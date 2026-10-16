// Production tool-call dispatch wiring: the deferred tool-registry factory and
// the turn.ToolDispatcher binding that routes the model's assembled tool calls to the
// landed dispatch backbone — bash to DispatchShell, every other structured name to
// DispatchTool — through the shared authorizer, real runner, and real registry.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/subagent"
	"codemeld.dev/codemeld/internal/subagenttool"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/vcs"
	"codemeld.dev/codemeld/internal/webresearch/exa"
)

// Synthetic target serializes production calls in model-call order.
const productionToolDispatchTarget = "production-tool-dispatch"

// The event schema pins these exact outcome strings.
const (
	structuredReadOutcomeSuccess         = "success"
	structuredReadOutcomeToolFailure     = "tool_failure"
	structuredReadOutcomeDenied          = "denied"
	structuredReadOutcomeCancelled       = "cancelled"
	structuredReadOutcomeInternalFailure = "internal_failure"

	structuredReadRefusalNotAllowlisted  = "not_allowlisted"
	structuredReadRefusalArgsInvalid     = "args_invalid"
	structuredReadRefusalPrepareFailed   = "prepare_failed"
	structuredReadRefusalScopeUnresolved = "scope_unresolved"
	structuredReadRefusalOutOfProject    = "out_of_project"
)

// ActiveVCS is the step-6 active-VCS detection result the registry factory consumes to
// register vcs_<action> tools: the selected template and the bound repo root. Both are
// required — vcs.RegisterActions resolves each action's cwd against the repo root — so the
// factory registers VCS tools only when both are present. DetectVCS returns nil when no
// template matched, which the factory treats as the degraded no-VCS path.
type ActiveVCS struct {
	Template               *vcs.Template
	RepoRoot               string
	TrustedExplicitClasses bool
}

type toolEventStore struct {
	mu    sync.Mutex
	store *sessions.Store
}

func (s *toolEventStore) Set(store *sessions.Store) {
	s.mu.Lock()
	s.store = store
	s.mu.Unlock()
}

func (s *toolEventStore) Active() *sessions.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store
}

// toolRegistryFactory defers tool-registry realization from step 6c — where the config
// cache and active session store do not yet exist (EnsureFreshSession runs after step 6c,
// and the cache is built in StartTUI) — to StartTUI. It captures the step-6 active-VCS data
// so vcs.RegisterActions can bind the run's output cap and turn-store event appender once
// those are available, without changing the persisted session schema.
type toolRegistryFactory struct {
	active any // the DetectVCS result: *ActiveVCS when a template matched, nil otherwise
}

// defaultBuildToolRegistry is the production step-6c BuildToolRegistry: it never fails and
// hands a non-nil factory carrying the active-VCS data forward to StartTUI, where the
// registry is realized with the cache and active-store accessor.
func defaultBuildToolRegistry(active any) (any, error) {
	return &toolRegistryFactory{active: active}, nil
}

// realize builds the production *tools.Registry. It always yields a non-nil registry carrying the
// built-in edit, create, delete, mkdir, read, glob, grep,
// list, tree, and file_count tools, bound to the run's home, process cwd, and project root so their
// target resolution matches the
// permission path-scope rules; read, glob, grep, list, tree, and file_count are also bound the tool-output
// byte cap their truncation metadata stays inside. When active VCS data (a non-nil
// template plus a repo root) is present it additionally registers the vcs_<action> tools with the
// production runner, an event appender bound to the *current* active session store (so it follows
// /clear and /resume swaps), and cache.MaxToolOutputBytes() as the tool_exec_end truncation cap.
// Missing VCS data, a nil template, or an empty repo root yields the edit-tool-only registry
// rather than a launch failure, because VCS detection can legitimately return no active template.
func (f *toolRegistryFactory) realize(cache *config.Cache, turnStore func() *sessions.Store, home, processCWD string, guard securitystate.Policy, delegate ...delegateBinding) (*tools.Registry, error) {
	reg := tools.NewRegistry()
	// the built-in edit tool is registered for every launch, independent of VCS detection. It
	// binds the run's ~ anchor, the default base for a relative target path, and the project root the
	// target must stay within — the same root the production authorizer overlays onto the mode-auth
	// context, so dispatch's pre-authorization containment check and Auto edits' in-scope check agree.
	if err := reg.Register(tools.BuiltinSource, filetools.NewEditTool(home, processCWD, cache.ProjectRoot())); err != nil {
		return nil, err
	}
	// The built-in create tool is registered for every launch alongside edit
	// independent of VCS detection, bound to the same home / process cwd / project root so its
	// create-only target resolution matches the permission path-scope rules.
	if err := reg.Register(tools.BuiltinSource, filetools.NewCreateTool(home, processCWD, cache.ProjectRoot())); err != nil {
		return nil, err
	}
	// The built-in delete tool is registered for every launch alongside edit/create,
	// bound to the same home / process cwd / project root so its target resolution matches the permission
	// path-scope rules. It is mutating but, unlike edit/create, is never auto-approved by any mode and
	// never folds under the write capability — every delete needs an explicit grant or approval.
	if err := reg.Register(tools.BuiltinSource, filetools.NewDeleteTool(home, processCWD, cache.ProjectRoot())); err != nil {
		return nil, err
	}
	// the built-in mkdir tool is registered for every launch alongside edit/create/delete, bound to the
	// same home / process cwd / project root so its deepest-existing-ancestor target resolution matches the
	// permission path-scope rules. It is mutating (read-only false) — Build advertises it and Plan filters it
	// out — and, like delete, never folds under the write capability: each directory create needs an explicit
	// mkdir grant or approval, so an existing write grant cannot silently authorize it.
	if err := reg.Register(tools.BuiltinSource, filetools.NewMkdirTool(home, processCWD, cache.ProjectRoot())); err != nil {
		return nil, err
	}
	// the built-in move tool is registered for every launch alongside edit/create/delete/mkdir, bound to
	// the same home / process cwd / project root so both endpoints' target resolution matches the
	// permission path-scope rules. It is mutating (read-only false) — Build advertises it and Plan filters
	// it out — and, like delete and mkdir, never folds under the write capability, so an existing write
	// grant cannot silently authorize it.
	if err := reg.Register(tools.BuiltinSource, filetools.NewMoveTool(home, processCWD, cache.ProjectRoot())); err != nil {
		return nil, err
	}
	// the built-in read-only read tool is registered for every launch alongside edit/create
	// independent of VCS detection. It binds the same home / process cwd / project root and also the
	// configured tool-output byte cap (cache.MaxToolOutputBytes()), which BoundedResult uses to
	// keep read's truncation indicator byte-cap-safe.
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadTool(home, processCWD, cache.ProjectRoot(), cache.MaxToolOutputBytes())); err != nil {
		return nil, err
	}
	// the built-in read-only glob tool is registered for every launch alongside
	// edit/create/read, independent of VCS detection. It binds the same home / process cwd / project root
	// and the configured tool-output byte cap (cache.MaxToolOutputBytes()), which BoundedResult uses
	// to keep glob's truncation indicator byte-cap-safe.
	glob := filetools.NewGlobTool(home, processCWD, cache.ProjectRoot(), cache.MaxToolOutputBytes())
	glob.SetBlockedPaths(guard.Blocked)
	if err := reg.Register(tools.BuiltinSource, glob); err != nil {
		return nil, err
	}
	// the built-in read-only grep tool is registered for every launch alongside
	// edit/create/read/glob, independent of VCS detection. It binds the same home / process cwd / project
	// root and the configured tool-output byte cap (cache.MaxToolOutputBytes()), which BoundedResult
	// uses to keep grep's truncation indicator byte-cap-safe.
	grep := filetools.NewGrepTool(home, processCWD, cache.ProjectRoot(), cache.MaxToolOutputBytes())
	grep.SetBlockedPaths(guard.Blocked)
	if err := reg.Register(tools.BuiltinSource, grep); err != nil {
		return nil, err
	}
	// the built-in read-only list tool is registered for every launch alongside
	// edit/create/read/glob/grep, independent of VCS detection. It binds the same home / process cwd /
	// project root and the configured tool-output byte cap (cache.MaxToolOutputBytes()), which
	// BoundedResult uses to keep list's truncation indicator byte-cap-safe.
	list := filetools.NewListTool(home, processCWD, cache.ProjectRoot(), cache.MaxToolOutputBytes())
	list.SetBlockedPaths(guard.Blocked)
	if err := reg.Register(tools.BuiltinSource, list); err != nil {
		return nil, err
	}
	// the built-in read-only tree tool is registered for every launch alongside
	// edit/create/read/glob/grep/list, independent of VCS detection. It binds the same home / process cwd /
	// project root and the configured tool-output byte cap (cache.MaxToolOutputBytes()), which
	// BoundedResult uses to keep tree's truncation indicator byte-cap-safe.
	tree := filetools.NewTreeTool(home, processCWD, cache.ProjectRoot(), cache.MaxToolOutputBytes())
	tree.SetBlockedPaths(guard.Blocked)
	if err := reg.Register(tools.BuiltinSource, tree); err != nil {
		return nil, err
	}
	// the built-in read-only file_count tool is registered for every launch alongside
	// edit/create/read/glob/grep/list/tree, independent of VCS detection. It binds the same home /
	// process cwd / project root and the configured tool-output byte cap (cache.MaxToolOutputBytes())
	// so its count output stays inside the byte cap. It advertises read-only, so it auto-allows in
	// every mode for in-project targets and is dispatchable by its exact registered name.
	fileCount := filetools.NewFileCountTool(home, processCWD, cache.ProjectRoot(), cache.MaxToolOutputBytes())
	fileCount.SetBlockedPaths(guard.Blocked)
	if err := reg.Register(tools.BuiltinSource, fileCount); err != nil {
		return nil, err
	}
	if err := reg.Register(tools.BuiltinSource, filetools.NewReadImageTool(home, processCWD, cache.ProjectRoot(), cache.MaxToolOutputBytes())); err != nil {
		return nil, err
	}
	// Without a parent to inherit from there is no child to start, so an unbound realization
	// registers no delegate at all.
	if len(delegate) > 0 {
		tool := subagenttool.New(delegate[0].deps(reg, cache, turnStore, home, processCWD, guard))
		if err := reg.Register(tools.BuiltinSource, tool); err != nil {
			return nil, err
		}
	}
	if settings := cache.WebResearch(); settings.Enabled {
		// The optional key reaches the adapter only here: it is deliberately absent from
		// WebResearchSettings so no formatted settings value can disclose it.
		backend := newSearchBackend(exa.Config{
			APIKey:         cache.WebResearchAPIKey(),
			MaxResults:     settings.MaxResults,
			Timeout:        time.Duration(settings.TimeoutSeconds) * time.Second,
			MaxOutputBytes: cache.MaxToolOutputBytes(),
			HTTPClient:     &http.Client{Timeout: time.Duration(settings.TimeoutSeconds) * time.Second},
		})
		for _, wt := range webResearchTools() {
			if wt.name == webSearchToolName {
				wt.search = backend
			}
			if err := reg.Register(tools.BuiltinSource, wt); err != nil {
				return nil, err
			}
		}
	}
	av, ok := f.active.(*ActiveVCS)
	if !ok || av == nil || av.Template == nil || av.RepoRoot == "" {
		return reg, nil
	}
	// The appender reads the turn-bound store per call, so execution events stay with the
	// submitted prompt's session; if a session switch closed that store, late appends are dropped.
	emit := func(p events.EventPayload) error {
		_, err := events.Append(turnStore(), p)
		return err
	}
	registerVCSActions := vcs.RegisterActions
	if av.TrustedExplicitClasses {
		registerVCSActions = vcs.RegisterActionsWithTrustedClasses
	}
	vcsRunner := newVCSActionRunner()
	if len(delegate) > 0 && delegate[0].confinement != nil {
		vcsRunner = &confinedRunner{inner: vcsRunner, conf: delegate[0].confinement, cap: cache.MaxToolOutputBytes()}
	}
	if err := registerVCSActions(reg, av.Template, av.RepoRoot, vcsRunner, emit, cache.MaxToolOutputBytes()); err != nil {
		return nil, err
	}
	return reg, nil
}

// newVCSActionRunner builds the command runner the registered vcs_<action> tools execute
// through. It is a package-level seam (like newTurnProviderClient) so an integration test can
// drive a genuinely product-authored VCS action — the only kind the read-only classification and
// the protected-state guard both accept — without launching a VCS subprocess; production never
// reassigns it.
var newVCSActionRunner = func() runner.Runner { return runner.DirectExecRunner{} }

var newChildToolRunner = func() runner.Runner { return runner.DirectExecRunner{} }

type parentTurnSnapshot struct {
	model        model.Selection
	modelSource  model.Source
	mode         string
	systemPrompt string
}

// parentTurnHolder carries one turn's model, mode, and assembled system prompt from the
// event-loop goroutine to the tool-dispatch goroutine a delegate call runs on. The run-scoped
// model and mode active states cannot be read there: they have no synchronization and pickers
// and slash commands mutate them on the event loop.
type parentTurnHolder struct {
	mu        sync.RWMutex
	published bool
	snapshot  parentTurnSnapshot
}

func (h *parentTurnHolder) publish(sel model.Selection, source model.Source, modeName, systemPrompt string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.snapshot = parentTurnSnapshot{model: sel, modelSource: source, mode: modeName, systemPrompt: systemPrompt}
	h.published = true
}

// current reports false until a turn has published, so a delegate call outside any turn is
// told there is no parent rather than handed zero values.
func (h *parentTurnHolder) current() (parentTurnSnapshot, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.snapshot, h.published
}

// delegateBinding reads the parent turn each child inherits from the run-scoped holder the
// turn publisher writes, so a model or mode change made while a turn is in flight reaches the
// next turn's children rather than this turn's.
type delegateBinding struct {
	parent      *parentTurnHolder
	notices     tui.NoticeRenderer
	confinement *confinement
}

// The live child-agent surface is discovered on the notice renderer the binding already
// holds, so the TUI site needs no extra wiring and the headless stderr renderer, which does
// not implement it, keeps a nil sink.
var _ subagent.ActivitySink = (*tui.App)(nil)

func (b delegateBinding) deps(reg *tools.Registry, cache *config.Cache, turnStore func() *sessions.Store, home, processCWD string, guard securitystate.Policy) subagenttool.Deps {
	deps := subagenttool.Deps{
		Home:        home,
		LaunchDir:   processCWD,
		ProjectRoot: cache.ProjectRoot(),
		Store:       turnStore,
		Snapshot: func() (subagenttool.Snapshot, bool) {
			parent, ok := b.parent.current()
			if !ok {
				return subagenttool.Snapshot{}, false
			}
			sel := parent.model
			catalog := cache.SelectableCatalog()
			entry, ok := catalog.Entry(sel.Provider)
			if !ok {
				return subagenttool.Snapshot{}, false
			}
			client, ok := buildTurnClient(sel.Provider, entry.AuthKind, cache, openaiauth.NewFlow(), SettingsPath(home))
			if !ok {
				return subagenttool.Snapshot{}, false
			}
			m := mode.Mode(parent.mode)
			return subagenttool.Snapshot{
				Mode:            parent.mode,
				Model:           sel,
				ModelSource:     parent.modelSource,
				SupportedEffort: catalog.SupportedEffort,
				SystemPrompt:    parent.systemPrompt,
				Client:          client,
				Tools:           advertisedTools(reg, m),
				Registered:      reg.List(),
			}, true
		},
		// A child gets no approver, so even an interactive run authorizes its calls through
		// the fail-closed headless authorizer.
		NewDispatcher: func(modeCtx permissions.ModeContext) turn.ToolDispatcher {
			auth := newHeadlessAuthorizer(cache, turnStore, mode.NewActiveState(mode.Mode(modeCtx.Mode), mode.SourceDefault), nil, b.notices)
			auth.declaredWrite = modeCtx.DeclaredWrite
			auth.declaredDelete = modeCtx.DeclaredDelete
			auth.childAgent = modeCtx.ChildAgent
			auth.childInvocationID = modeCtx.ChildInvocationID
			auth.delegateWrite = modeCtx.DelegateWrite
			auth.executionConstrained = b.confinement != nil && b.confinement.constrained
			auth.blocked = guard.Blocked
			child := newProductionToolDispatcher(reg, newChildToolRunner(), childMoveAuthorizer{Authorizer: auth, moves: modeCtx.DeclaredMoves},
				home, processCWD, turnStore, cache.MaxToolOutputBytes(), guard)
			child.childCeiling = modeCtx.ChildAgent
			child.childInvocationID = modeCtx.ChildInvocationID
			if b.confinement != nil {
				childMode := modeCtx.Mode
				conf := *b.confinement
				conf.mode = func() string { return childMode }
				child.confinement = &conf
				child.childMode = &childMode
			}
			return child
		},
	}
	if sink, ok := b.notices.(subagent.ActivitySink); ok {
		deps.Activity = sink
	}
	return deps
}

// headlessAuthorizer overlays a child's write and delete declarations but not its move pairs, which
// this overlays on every call instead.
type childMoveAuthorizer struct {
	dispatch.Authorizer
	moves map[permissions.MovePair]bool
}

func (a childMoveAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	modeCtx.DeclaredMoves = a.moves
	return a.Authorizer.Authorize(ctx, req, disp, modeCtx)
}

// realizeToolRegistry narrows the step-6c registry handoff into a concrete *tools.Registry
// in StartTUI. A bootstrap-produced *toolRegistryFactory is realized with the run's cache and
// turn-store accessor; any other handoff (nil from a degraded launch, or an unexpected
// type) degrades to a bare non-nil registry so the dispatcher always has a registry to look
// up against.
func realizeToolRegistry(handoff any, cache *config.Cache, turnStore func() *sessions.Store, home, processCWD string, guard securitystate.Policy, delegate ...delegateBinding) (*tools.Registry, error) {
	if f, ok := handoff.(*toolRegistryFactory); ok && f != nil {
		return f.realize(cache, turnStore, home, processCWD, guard, delegate...)
	}
	return tools.NewRegistry(), nil
}

// productionToolDispatcher is the production binding of turn.ToolDispatcher (the tool-call loop's
// seam). It routes each assembled tool call to the landed dispatch backbone: a `bash` call decodes its
// command argument and runs through DispatchShell; every other name decodes its JSON
// arguments and runs through DispatchTool against the real registry. Both paths authorize
// through the shared authorizer and resolve path scope against the run's home/process
// cwd, then adapt the dispatch outcome to model-facing turn.ToolResult content.
type productionToolDispatcher struct {
	registry   *tools.Registry
	runner     dispatch.Runner
	authorizer dispatch.Authorizer
	home       string
	processCWD string
	active     func() *sessions.Store
	outputCap  int
	// A nil fetchClient keeps web_fetch on its fail-closed branch, so an unwired dispatcher
	// never dials with an untimed default client.
	fetchClient *http.Client
	askUser     func(context.Context, tui.QuestionRequest) (tui.QuestionResult, error)
	guard       securitystate.Policy
	// childCeiling marks the dispatcher a child agent's own calls run through, where the parent's
	// declared write set is a ceiling every call is judged against — including a nested delegate whose
	// declaration did not resolve, which denies rather than correcting the model.
	childCeiling bool
	// childInvocationID attributes this dispatcher's tool, structured-read and permission
	// events to the child agent whose calls run through it; it is empty on the parent's own
	// dispatcher. The read tools a child is permitted are recorded as structured_read_* rather
	// than tool_exec_*, so that path carries the id too.
	childInvocationID string
	confinement       *confinement
	childMode         *string
}

var _ turn.ToolDispatcher = (*productionToolDispatcher)(nil)

// newProductionToolDispatcher binds the run-scoped dispatch collaborators to
// the tool-call loop.
func newProductionToolDispatcher(registry *tools.Registry, run dispatch.Runner, authorizer dispatch.Authorizer, home, processCWD string, activeStore func() *sessions.Store, outputCap int, guard securitystate.Policy) *productionToolDispatcher {
	return &productionToolDispatcher{registry: registry, runner: run, authorizer: authorizer, home: home, processCWD: processCWD, active: activeStore, outputCap: outputCap, guard: guard}
}

const vcsToolNamePrefix = "vcs_"

var phase1ReadToolNames = map[string]struct{}{
	filetools.ReadToolName:      {},
	filetools.GlobToolName:      {},
	filetools.GrepToolName:      {},
	filetools.ListToolName:      {},
	filetools.TreeToolName:      {},
	filetools.FileCountToolName: {},
}

func isPhase1ReadTool(name string) bool {
	_, ok := phase1ReadToolNames[name]
	return ok
}

// eligibleReadFailure retains the *lowest* model-call-index failure so the error a later barrier's
// guard surfaces does not depend on which concurrent read finished first. One is allocated per Plan
// call rather than on the dispatcher, which outlives the turn, so a failure cannot leak into the
// next one.
type eligibleReadFailure struct {
	mu    sync.Mutex
	err   error
	index int
	set   bool
}

func (f *eligibleReadFailure) record(index int, err error) {
	if err == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.set || index < f.index {
		f.err, f.index, f.set = err, index, true
	}
}

func (f *eligibleReadFailure) recorded() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// Plan partitions a response instead of collapsing it: each maximal contiguous run of prepared
// project-confined structured reads may overlap internally, a valid delegate call is its own
// segment ordered by the child's prepared write and delete targets, and every other call is a serial barrier
// that the run before it precedes and the run after it follows. Authorization grouping is
// assembled separately from that partition and changes neither: a group member keeps its serial
// target and its dependencies, and only gains a pre-run that waits for the group's one approval.
//
// A delegate carries the child's targets rather than the synthetic serial one, so two children that
// cannot reach the same path may overlap; everything it must not overlap becomes an explicit
// dependency instead. Reads report their failures outside the scheduler (ContinueOnError), so a
// dependency on a read does not stop a delegate and its pre-run repeats the barrier's guard on the
// recorded failure before authorizing or starting a child.
func (d *productionToolDispatcher) Plan(calls []turn.AssembledToolCall, maxConcurrency int) turn.ToolPlan {
	eligible := d.prepareStructuredReads(calls)
	delegates := d.prepareDelegates(calls)
	groups := d.assembleAuthGroups(calls)
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	failure := &eligibleReadFailure{}
	segments := &planSegments{}
	for i, call := range calls {
		group := groups[i]
		if prepared, ok := delegates[i]; ok {
			plan.Units[i] = turn.PlannedToolCall{
				Call:    call,
				Deps:    segments.enterDelegate(call.ID),
				Targets: prepared.DelegateSchedulerTargets(),
				PreRun:  func(context.Context) error { return failure.recorded() },
				Run: func(ctx context.Context) (turn.ToolResult, error) {
					return d.dispatchPreparedDelegate(ctx, prepared)
				},
			}
			continue
		}
		if !eligible[i] {
			plan.Units[i] = turn.PlannedToolCall{
				Call:    call,
				Deps:    segments.enterBarrier(call.ID),
				Targets: []string{productionToolDispatchTarget},
				PreRun: func(ctx context.Context) error {
					if err := failure.recorded(); err != nil {
						return err
					}
					return authorizeGroup(ctx, group)
				},
				Run: func(ctx context.Context) (turn.ToolResult, error) {
					if m := group.member(call.ID); m != nil {
						return d.dispatchDecided(ctx, m, false, maxConcurrency)
					}
					return d.Dispatch(ctx, call)
				},
			}
			continue
		}
		unit := turn.PlannedToolCall{
			Call:            call,
			ContinueOnError: true,
			Deps:            segments.enterRead(call.ID),
			Run: func(ctx context.Context) (turn.ToolResult, error) {
				res, err := d.runEligibleRead(ctx, group, call, maxConcurrency)
				failure.record(i, err)
				return res, err
			},
		}
		// An ungrouped read keeps no guard at all, so the plan an authorizer without the
		// independent seam produces is byte-for-byte the one it produced before.
		if group != nil {
			unit.PreRun = func(ctx context.Context) error { return authorizeGroup(ctx, group) }
		}
		plan.Units[i] = unit
	}
	return plan
}

type planKind int

const (
	planStart planKind = iota
	planReads
	planDelegates
	planBarrier
)

// planSegments hands each call the dependencies that fence it from the kinds of work it must not
// overlap. A run of reads and a run of delegates each accumulate until the other kind, or a barrier,
// starts, so every delegate waits for the whole read run before it rather than only for the reads a
// nearer delegate had not already claimed.
type planSegments struct {
	reads     []string
	delegates []string
	barrier   string
	kind      planKind
}

func (s *planSegments) fence(extra []string) []string {
	var deps []string
	if s.barrier != "" {
		deps = append(deps, s.barrier)
	}
	return append(deps, extra...)
}

func (s *planSegments) enterRead(id string) []string {
	if s.kind != planReads {
		s.reads, s.kind = nil, planReads
	}
	deps := s.fence(s.delegates)
	s.reads = append(s.reads, id)
	return deps
}

func (s *planSegments) enterDelegate(id string) []string {
	if s.kind != planDelegates {
		s.delegates, s.kind = nil, planDelegates
	}
	deps := s.fence(s.reads)
	s.delegates = append(s.delegates, id)
	return deps
}

func (s *planSegments) enterBarrier(id string) []string {
	deps := append(slices.Clone(s.reads), s.delegates...)
	s.reads, s.delegates, s.barrier, s.kind = nil, nil, id, planBarrier
	return deps
}

// prepareDelegates canonicalizes each delegate declaration once, at planning time, so the targets
// the scheduler orders on and the ceiling the child is built from are the same resolution. A
// declaration that does not resolve is absent here and stays an ordinary serial barrier, keeping its
// existing in-band validation result.
func (d *productionToolDispatcher) prepareDelegates(calls []turn.AssembledToolCall) map[int]dispatch.PreparedTool {
	var delegates map[int]dispatch.PreparedTool
	for i, call := range calls {
		if call.Name != subagenttool.ToolName {
			continue
		}
		args, err := decodeToolArgs(call.Arguments)
		if err != nil {
			continue
		}
		prepared, err := dispatch.PrepareTool(context.Background(), call.Name, args, d.home, d.processCWD, d.registry, d.guard)
		if err != nil || !prepared.DelegatePrepared() {
			continue
		}
		if delegates == nil {
			delegates = make(map[int]dispatch.PreparedTool, 1)
		}
		delegates[i] = prepared
	}
	return delegates
}

func (d *productionToolDispatcher) dispatchPreparedDelegate(ctx context.Context, prepared dispatch.PreparedTool) (turn.ToolResult, error) {
	res, derr := dispatch.DispatchPreparedTool(d.childCtx(ctx), prepared, d.authorizer)
	return d.adaptTool(subagenttool.ToolName, res, derr)
}

func (d *productionToolDispatcher) runEligibleRead(ctx context.Context, group *authGroup, call turn.AssembledToolCall, maxConcurrency int) (turn.ToolResult, error) {
	if m := group.member(call.ID); m != nil {
		return d.dispatchDecided(ctx, m, true, maxConcurrency)
	}
	return d.dispatchReclassified(ctx, call, maxConcurrency)
}

// assembleAuthGroups collects each maximal run of consecutive authorization-eligible calls into one
// group. Eligibility alone decides membership: a call keeps whatever dependencies and serial
// execution target Plan gives it, so an eligible read_image, read-only VCS action, or external read
// stays grouped for authorization while still executing as a barrier. A non-eligible call ends the
// run. A headless authorizer implements no independent seam, so headless forms no groups and keeps
// its per-call sequential authorization.
func (d *productionToolDispatcher) assembleAuthGroups(calls []turn.AssembledToolCall) []*authGroup {
	groups := make([]*authGroup, len(calls))
	authorizer, ok := d.authorizer.(dispatch.IndependentAuthorizer)
	if !ok {
		return groups
	}
	var current *authGroup
	for i, call := range calls {
		if _, eligible := d.prepareForAuthGroup(context.Background(), call); !eligible {
			current = nil
			continue
		}
		if current == nil {
			current = &authGroup{dispatcher: d, authorizer: authorizer}
		}
		current.calls = append(current.calls, call)
		groups[i] = current
	}
	return groups
}

// authGroup authorizes its consecutive eligible read-only calls on one prompt before any of them
// runs. Every member's pre-run waits here, so the group's approval completes before the first
// invocation. Preparation happens at that point rather than at Plan time, so each call is
// authorized against the target it will actually execute against, after every earlier barrier has
// run; no member can move another's target, because every member is read-only. A call whose
// preparation no longer resolves is left out and falls back to its ordinary per-call dispatch.
type authGroup struct {
	dispatcher *productionToolDispatcher
	authorizer dispatch.IndependentAuthorizer
	calls      []turn.AssembledToolCall
	once       sync.Once
	err        error
	members    map[string]*groupMember
}

// groupMember pairs a prepared call with the decision the group returned for it, so a member runs
// only for its own approval and a denied member carries only its own envelope.
type groupMember struct {
	prepared dispatch.PreparedTool
	decision permissions.Decision
	mode     string
	pinned   bool
}

func authorizeGroup(ctx context.Context, group *authGroup) error {
	if group == nil {
		return nil
	}
	group.once.Do(func() { group.members, group.err = group.resolve(ctx) })
	return group.err
}

func (g *authGroup) member(id string) *groupMember {
	if g == nil {
		return nil
	}
	return g.members[id]
}

// A call the group admitted at plan time can lose its eligibility by dispatch time, because an
// earlier barrier may have moved what it resolves to. Such a call is a runtime boundary exactly as a
// plan-time non-eligible call is: the members before it and the members after it are authorized as
// separate groups on separate prompts, and the call itself keeps only its ordinary per-call path.
func (g *authGroup) resolve(ctx context.Context) (map[string]*groupMember, error) {
	members := make(map[string]*groupMember, len(g.calls))
	var ids []string
	var prepared []dispatch.PreparedTool
	authorizeSegment := func() error {
		if len(ids) == 0 {
			return nil
		}
		reqs := make([]dispatch.IndependentAuthRequest, len(prepared))
		for i, p := range prepared {
			reqs[i] = p.IndependentRequest()
		}
		segCtx := g.dispatcher.pinMode(ctx)
		decisions, err := g.authorizer.AuthorizeIndependent(segCtx, reqs)
		if err != nil {
			return err
		}
		if len(decisions) != len(reqs) {
			return fmt.Errorf("bootstrap: authorization group returned %d decisions for %d calls", len(decisions), len(reqs))
		}
		segMode, pinned := vcs.ConfinementMode(segCtx)
		for i, id := range ids {
			members[id] = &groupMember{prepared: prepared[i], decision: decisions[i], mode: segMode, pinned: pinned}
		}
		ids, prepared = nil, nil
		return nil
	}
	for _, call := range g.calls {
		p, ok := g.dispatcher.prepareForAuthGroup(ctx, call)
		if !ok {
			if err := authorizeSegment(); err != nil {
				return nil, err
			}
			continue
		}
		ids = append(ids, call.ID)
		prepared = append(prepared, p)
	}
	if err := authorizeSegment(); err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return nil, nil
	}
	return members, nil
}

// prepareForAuthGroup proves a call may be authorized inside a group, without executing it. Every
// proof is required: the registry must hold the tool, its metadata must advertise read-only and
// non-credential-handling, its full arguments must validate with no I/O, and
// preparation must resolve a scope. An unknown name, an unclassified or credential-handling
// operation, a write, network egress, and a malformed call each fail one of them and stay outside
// every group.
func (d *productionToolDispatcher) prepareForAuthGroup(ctx context.Context, call turn.AssembledToolCall) (dispatch.PreparedTool, bool) {
	tool, ok := d.registry.Lookup(call.Name)
	if !ok {
		return dispatch.PreparedTool{}, false
	}
	if meta := tool.Advertise(); !meta.ReadOnly || !meta.Noncredential {
		return dispatch.PreparedTool{}, false
	}
	args, err := decodeToolArgs(call.Arguments)
	if err != nil {
		return dispatch.PreparedTool{}, false
	}
	if err := validateAuthGroupArgs(call.Name, args); err != nil {
		return dispatch.PreparedTool{}, false
	}
	prepared, err := dispatch.PrepareTool(ctx, call.Name, args, d.home, d.processCWD, d.registry, d.guard)
	if err != nil || prepared.Scope() == "" {
		return dispatch.PreparedTool{}, false
	}
	return prepared, true
}

// validateAuthGroupArgs is the complete non-executing argument check a call must pass before it is
// prepared: successful preparation resolves a path but does not prove optional arguments, patterns,
// or ranges well formed. A name with no validator has none, so it is refused.
func validateAuthGroupArgs(name string, args map[string]any) error {
	switch {
	case isPhase1ReadTool(name):
		return filetools.ValidatePhase1ReadArgs(name, args)
	case name == filetools.ReadImageToolName:
		return filetools.ValidateReadImageArgs(args)
	case strings.HasPrefix(name, vcsToolNamePrefix):
		// Every read-only vcs_<action> advertises an empty parameter schema, so any argument at
		// all is malformed here and one carrying a parameter is not an admitted read-only action.
		if len(args) > 0 {
			return fmt.Errorf("%s accepts no arguments", name)
		}
		return nil
	default:
		return fmt.Errorf("%s has no non-executing argument validator", name)
	}
}

// dispatchDecided runs one already-authorized group member. A member Plan also admitted to a
// concurrent structured-read segment keeps its structured_read_* events.
func (d *productionToolDispatcher) dispatchDecided(ctx context.Context, m *groupMember, structured bool, maxConcurrency int) (turn.ToolResult, error) {
	ctx = d.childCtx(ctx)
	if m.pinned {
		ctx = vcs.WithConfinementMode(ctx, m.mode)
	}
	if !structured {
		res, derr := dispatch.InvokeDecided(ctx, m.prepared, m.decision)
		return d.adaptTool(m.prepared.Name(), res, derr)
	}
	store := d.activeStore()
	invocationID := ids.NewV7()
	if err := events.EmitStructuredReadStart(store, invocationID, m.prepared.Name(), m.prepared.Scope(), int64(maxConcurrency), d.childInvocationID); err != nil {
		return turn.ToolResult{}, err
	}
	started := time.Now()
	res, derr := dispatch.InvokeDecided(ctx, m.prepared, m.decision)
	elapsed := time.Since(started)
	result, aerr := d.adaptTool(m.prepared.Name(), res, derr)
	if err := events.EmitStructuredReadEnd(store, invocationID, m.prepared.Name(), structuredReadOutcome(res, derr, aerr), elapsed.Milliseconds(), d.childInvocationID); err != nil {
		return turn.ToolResult{}, err
	}
	return result, aerr
}

// A barrier before this read may have changed what its path resolves to since Plan classified it,
// and PrepareTool captures the resolved target, so the plan-time preparation decides only the plan
// shape and execution resolves again against post-barrier state.
func (d *productionToolDispatcher) dispatchReclassified(ctx context.Context, call turn.AssembledToolCall, maxConcurrency int) (turn.ToolResult, error) {
	prepared, reason := d.classifyStructuredRead(call)
	if reason != "" {
		return turn.ToolResult{}, fmt.Errorf("bootstrap: structured read %q no longer qualifies at dispatch: %s", call.Name, reason)
	}
	return d.dispatchPrepared(ctx, prepared, maxConcurrency)
}

func (d *productionToolDispatcher) prepareStructuredReads(calls []turn.AssembledToolCall) []bool {
	eligible := make([]bool, len(calls))
	for i, call := range calls {
		_, reason := d.classifyStructuredRead(call)
		if reason != "" {
			// Best effort: Plan cannot report an append failure, and a lost refusal record
			// must not change how the call is classified, ordered, or executed.
			_ = events.EmitStructuredReadRefused(d.activeStore(), call.Name, reason, int64(len(calls)), d.childInvocationID)
			continue
		}
		eligible[i] = true
	}
	return eligible
}

func (d *productionToolDispatcher) classifyStructuredRead(call turn.AssembledToolCall) (dispatch.PreparedTool, string) {
	if _, ok := phase1ReadToolNames[call.Name]; !ok {
		return dispatch.PreparedTool{}, structuredReadRefusalNotAllowlisted
	}
	args, err := decodeToolArgs(call.Arguments)
	if err != nil {
		return dispatch.PreparedTool{}, structuredReadRefusalArgsInvalid
	}
	if err := filetools.ValidatePhase1ReadArgs(call.Name, args); err != nil {
		return dispatch.PreparedTool{}, structuredReadRefusalArgsInvalid
	}
	p, err := dispatch.PrepareTool(context.Background(), call.Name, args, d.home, d.processCWD, d.registry, d.guard)
	if err != nil {
		return dispatch.PreparedTool{}, structuredReadRefusalPrepareFailed
	}
	switch {
	case p.Scope() == "":
		return dispatch.PreparedTool{}, structuredReadRefusalScopeUnresolved
	case p.ExternalRead():
		return dispatch.PreparedTool{}, structuredReadRefusalOutOfProject
	}
	return p, ""
}

// Structured-read evidence failures fail closed.
func (d *productionToolDispatcher) dispatchPrepared(ctx context.Context, prepared dispatch.PreparedTool, maxConcurrency int) (turn.ToolResult, error) {
	store := d.activeStore()
	invocationID := ids.NewV7()
	if err := events.EmitStructuredReadStart(store, invocationID, prepared.Name(), prepared.Scope(), int64(maxConcurrency), d.childInvocationID); err != nil {
		return turn.ToolResult{}, err
	}
	started := time.Now()
	res, derr := dispatch.DispatchPreparedTool(ctx, prepared, d.authorizer)
	elapsed := time.Since(started)
	result, aerr := d.adapt(res, derr, prepared.Name() == filetools.ReadToolName)
	if err := events.EmitStructuredReadEnd(store, invocationID, prepared.Name(), structuredReadOutcome(res, derr, aerr), elapsed.Milliseconds(), d.childInvocationID); err != nil {
		return turn.ToolResult{}, err
	}
	return result, aerr
}

// childCtx carries this dispatcher's child invocation id to tool implementations that emit their
// own tool_exec_* records — the VCS action tools, whose event appender is bound once on the shared
// registry and so cannot know which agent is calling.
func (d *productionToolDispatcher) childCtx(ctx context.Context) context.Context {
	if d.childMode != nil {
		ctx = vcs.WithConfinementMode(ctx, *d.childMode)
	}
	if d.childInvocationID == "" {
		return ctx
	}
	return vcs.WithChildInvocationID(ctx, d.childInvocationID)
}

// pinMode fixes one call's mode before it is authorized, so a mode switch while the call is
// prompting or running cannot make its execution disagree with its authorization.
func (d *productionToolDispatcher) pinMode(ctx context.Context) context.Context {
	ctx = d.childCtx(ctx)
	if _, ok := vcs.ConfinementMode(ctx); !ok && d.confinement != nil && d.confinement.mode != nil {
		ctx = vcs.WithConfinementMode(ctx, d.confinement.mode())
	}
	return ctx
}

func (d *productionToolDispatcher) activeStore() *sessions.Store {
	if d.active == nil {
		return nil
	}
	return d.active()
}

// Classify cancellation before errors adapted as internal failures.
func structuredReadOutcome(res tools.Result, derr, aerr error) string {
	switch {
	case derr == nil:
		if res.ExitCode != 0 {
			return structuredReadOutcomeToolFailure
		}
		return structuredReadOutcomeSuccess
	case errors.Is(derr, context.Canceled) || errors.Is(derr, context.DeadlineExceeded):
		return structuredReadOutcomeCancelled
	case errors.As(derr, new(*dispatch.DeniedError)):
		return structuredReadOutcomeDenied
	case aerr == nil:
		return structuredReadOutcomeToolFailure
	default:
		return structuredReadOutcomeInternalFailure
	}
}

const EnvShellToolHint = "CODEMELD_SHELL_TOOL_HINT"

var shellToolHintTools = map[string]string{
	"grep":  filetools.GrepToolName,
	"egrep": filetools.GrepToolName,
	"fgrep": filetools.GrepToolName,
	"rg":    filetools.GrepToolName,
	"cat":   filetools.ReadToolName,
	"head":  filetools.ReadToolName,
	"tail":  filetools.ReadToolName,
	"find":  filetools.GlobToolName,
	"ls":    filetools.ListToolName,
}

func shellToolHint(command string) (string, bool) {
	advice, ok := shellToolAdvice(command)
	if !ok {
		return "", false
	}
	return "shell-tool hint: this command was not run; " + advice + ".", true
}

func shellToolAdvice(command string) (string, bool) {
	split, err := permissions.SplitCommand(command)
	if err != nil || !split.AllowedShell {
		return "", false
	}
	stages := split.Stages
	if split.LiteralRoute {
		canonical, err := permissions.CanonicalLiteralForm(split.LiteralInput)
		if err != nil {
			return "", false
		}
		stages = permissions.LiteralStages(canonical)
	}
	var programs []string
	for _, stage := range stages {
		if len(stage.Tokens) == 0 {
			continue
		}
		program := filepath.Base(stage.Tokens[0])
		if _, ok := shellToolHintTools[program]; ok && !slices.Contains(programs, program) {
			programs = append(programs, program)
		}
	}
	if len(programs) == 0 {
		return "", false
	}
	advice := make([]string, len(programs))
	for i, program := range programs {
		tool := shellToolHintTools[program]
		advice[i] = fmt.Sprintf("use the %s tool instead of %s", tool, program)
		if tool == filetools.ReadToolName {
			advice[i] += " (offset/limit for a range)"
		}
	}
	return strings.Join(advice, "; "), true
}

// Dispatch executes one assembled tool call and adapts the outcome to a turn.ToolResult.
// Malformed arguments (a `bash` call whose command cannot be decoded, or a structured call
// whose JSON arguments cannot be decoded) surface as an in-band tool result with a nil error
// — the loop records it and the model can correct itself — so a bad argument never crashes
// the turn or reaches a permission prompt.
func (d *productionToolDispatcher) Dispatch(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	ctx = d.pinMode(ctx)
	if call.Name == bashToolName {
		command, err := decodeBashCommand(call.Arguments)
		if err != nil {
			return inbandToolError(err), nil
		}
		if os.Getenv(EnvShellToolHint) == "1" {
			if hint, ok := shellToolHint(command); ok {
				return turn.ToolResult{Content: hint}, nil
			}
		}
		run := &confinedShellRunner{
			events: &shellEventRunner{inner: d.runner, active: d.active, cap: d.outputCap, childInvocationID: d.childInvocationID},
			conf:   d.confinement,
		}
		res, derr := dispatch.DispatchShell(ctx, command, d.home, d.processCWD, d.authorizer, run, d.guard)
		var refusal *securitystate.Refusal
		if errors.As(derr, &refusal) {
			return d.denyProtectedState(refusal)
		}
		if run.failureNoted {
			res.Stderr = keepConfinedFailureNote(res.Stderr, d.outputCap)
		}
		return d.adapt(res, derr, false)
	}
	if call.Name == provider.AskUserToolName && d.askUser != nil {
		return d.dispatchAskUser(ctx, call.Arguments)
	}
	args, err := decodeToolArgs(call.Arguments)
	if err != nil {
		return inbandToolError(err), nil
	}
	if tool, ok := d.registry.Lookup(call.Name); ok {
		if wt, ok := tool.(*webResearchTool); ok {
			if d.fetchClient != nil {
				switch {
				case call.Name == webFetchToolName:
					return d.dispatchWebFetch(ctx, args)
				case call.Name == webSearchToolName && wt.search != nil:
					return d.dispatchWebSearch(ctx, wt.search, args)
				}
			}
			return inbandToolError(errWebResearchUnavailable), nil
		}
	}
	if call.Name == filetools.EditToolName || call.Name == filetools.CreateToolName || call.Name == filetools.DeleteToolName || call.Name == filetools.MoveToolName {
		return d.dispatchWrite(ctx, call.Name, args)
	}
	if call.Name == subagenttool.ToolName {
		return d.dispatchDelegate(ctx, args)
	}
	res, derr := dispatch.DispatchTool(ctx, call.Name, args, d.home, d.processCWD, d.registry, d.authorizer, d.guard)
	return d.adaptTool(call.Name, res, derr)
}

// dispatchDelegate runs the two halves of DispatchTool separately so a delegate call whose
// declaration failed to resolve is answered by whoever owns the question. Under a child agent's
// ceiling it is a permission question whatever it declares: the ceiling denies an unresolvable nested
// declaration by declared scope before any grandchild starts, so the call still reaches
// authorization carrying an empty candidate the containment check refuses. A top-level call is under
// no such ceiling, so it must not reach authorization — its refusal is the tool's own corrective,
// returned with no prompt and no permission event.
func (d *productionToolDispatcher) dispatchDelegate(ctx context.Context, args map[string]any) (turn.ToolResult, error) {
	prepared, perr := dispatch.PrepareTool(ctx, subagenttool.ToolName, args, d.home, d.processCWD, d.registry, d.guard)
	if perr != nil {
		return d.adaptTool(subagenttool.ToolName, tools.Result{}, perr)
	}
	if refusal := prepared.DelegateRefusal(); refusal != nil && !d.childCeiling {
		return d.adaptTool(subagenttool.ToolName, tools.Result{}, refusal)
	}
	res, derr := dispatch.DispatchPreparedTool(ctx, prepared, d.authorizer)
	return d.adaptTool(subagenttool.ToolName, res, derr)
}

// dispatchWrite runs the two halves of DispatchTool separately so the reported target is the one
// authorization decided on, never a path re-derived from the arguments after the write.
func (d *productionToolDispatcher) dispatchWrite(ctx context.Context, name string, args map[string]any) (turn.ToolResult, error) {
	prepared, perr := dispatch.PrepareTool(ctx, name, args, d.home, d.processCWD, d.registry, d.guard)
	if perr != nil {
		return d.adaptTool(name, tools.Result{}, perr)
	}
	res, derr := dispatch.DispatchPreparedTool(ctx, prepared, d.authorizer)
	result, aerr := d.adaptTool(name, res, derr)
	if aerr != nil || derr != nil || res.ExitCode != 0 {
		return result, aerr
	}
	switch name {
	case filetools.DeleteToolName:
		result.DeleteTarget = prepared.PreparedTarget()
	case filetools.MoveToolName:
		source, destination := prepared.PreparedMove()
		result.MoveTarget = turn.MoveTarget{Source: source, Destination: destination}
	default:
		result.WriteTarget = prepared.PreparedTarget()
	}
	return result, nil
}

// adaptTool adapts one structured-tool outcome. The model-context image is carried straight off
// read_image's own result, so the notice the model reads and the pixels it sees come from the one
// capture that tool made against the authorized target; no other tool can put an image into the
// model context.
func (d *productionToolDispatcher) adaptTool(name string, res tools.Result, derr error) (turn.ToolResult, error) {
	var refusal *securitystate.Refusal
	if errors.As(derr, &refusal) {
		return d.denyProtectedState(refusal)
	}
	// A delegate call refused on its declaration never reached authorization, so it is a corrective
	// the model reads rather than a denial the loop routes.
	var prepRefusal *subagenttool.PreparationError
	if errors.As(derr, &prepRefusal) {
		return d.adapt(prepRefusal.Result(), nil, false)
	}
	// read delivers verbatim file content in stdout, so its trailing newline bytes must
	// survive to the model; every other tool's stdout is command output the formatter trims.
	result, aerr := d.adapt(res, derr, name == filetools.ReadToolName)
	if aerr != nil {
		return result, aerr
	}
	if name == filetools.ReadImageToolName && res.ModelContextImage != "" && derr == nil && res.ExitCode == 0 && !result.Denied {
		result.ModelContextImage = res.ModelContextImage
	}
	return result, nil
}

func (d *productionToolDispatcher) denyProtectedState(refusal *securitystate.Refusal) (turn.ToolResult, error) {
	if err := d.recordRefusal(refusal); err != nil {
		return turn.ToolResult{}, err
	}
	result, err := d.adapt(tools.Result{}, &dispatch.DeniedError{Envelope: refusal.Envelope}, false)
	if refusal.Source == "blocked_path" && refusal.EntrySource != "" {
		result.Notice = "Blocked by the blocked_paths entry " + fserrors.CollapseControls(refusal.Entry) +
			" in " + fserrors.CollapseControls(refusal.EntrySource)
	}
	return result, err
}

func (d *productionToolDispatcher) recordRefusal(refusal *securitystate.Refusal) error {
	_, err := events.Append(d.activeStore(), events.PermissionMatched{
		SubjectKind:          refusal.SubjectKind,
		Subject:              refusal.Subject,
		PathScope:            refusal.PathScope,
		Outcome:              "deny",
		OutcomeSource:        refusal.Source,
		ArgumentHash:         refusal.ArgumentHash,
		DirectRequestSubject: refusal.DirectRequestSubject,
		ChildInvocationID:    d.childInvocationID,
		BlockedEntry:         refusal.Entry,
		BlockedEntrySource:   refusal.EntrySource,
	})
	return err
}

// adapt converts a dispatch outcome to the model-facing turn.ToolResult. A successful
// tools.Result returns its captured output. A permission denial returns the permissions deny envelope
// as in-band content (nil error) with the Denied marker set, so the loop routes the refusal
// through permissions.DeliverDeny and persists it — the marker is the only way the loop can tell
// a deny envelope from ordinary output, which Content cannot. The dispatcher no longer decides
// the outcome: ToolLoop decodes the envelope's denied_by and halts the turn only for user or
// unclassifiable denials, while a mode-policy denial (denied_by:"mode") continues to a follow-up
// provider round. An unknown
// structured tool, a rejected/unsupported shell construct, a shell command codemeld cannot parse
// or whose `cd` hint will not resolve, and an out-of-scope edit target
// likewise surface in-band — DispatchTool/DispatchShell already refuse them without
// prompting — so the model sees the error and can adjust. Every other error is an internal
// dispatch failure (context cancellation, a prompt/event-emit error, hintless scope resolution, or
// runner invalid input) and is returned to abort the loop, per the turn.ToolDispatcher contract.
func (d *productionToolDispatcher) adapt(res tools.Result, err error, preserveStdoutNewlines bool) (turn.ToolResult, error) {
	if err == nil {
		return turn.ToolResult{
			Content:      formatToolResult(res, d.outputCap, preserveStdoutNewlines),
			DisplayPatch: res.DisplayPatch,
		}, nil
	}
	var denied *dispatch.DeniedError
	if errors.As(err, &denied) {
		return turn.ToolResult{Content: denied.Envelope, Denied: true, WrapUp: denied.WrapUp}, nil
	}
	var noSuch *dispatch.NoSuchToolError
	if errors.As(err, &noSuch) {
		return inbandToolError(noSuch), nil
	}
	var unsupported *dispatch.UnsupportedConstructError
	if errors.As(err, &unsupported) {
		return inbandToolError(unsupported), nil
	}
	var malformed *dispatch.MalformedCommandError
	if errors.As(err, &malformed) {
		return inbandToolError(malformed), nil
	}
	// an edit call whose target failed pre-authorization resolution (out of project, symlink
	// escape, directory, unresolvable parent) is refused before prompting. Surface it in-band so the
	// model can correct the path rather than aborting the turn.
	var badTarget *filetools.TargetError
	if errors.As(err, &badTarget) {
		return inbandToolError(badTarget), nil
	}
	var badAssignment *runner.EnvAssignmentError
	var notFound *runner.ExecutableNotFoundError
	if errors.As(err, &badAssignment) || errors.As(err, &notFound) {
		return inbandToolError(fmt.Errorf("the confined run refused this before starting any process: %w", err)), nil
	}
	return turn.ToolResult{}, err
}

// decodeToolArgs decodes a structured tool call's JSON arguments into the map DispatchTool
// passes to the tool. Empty or null arguments decode to an empty map (a tool may take no
// arguments); any other malformed JSON is an error surfaced in-band.
func decodeToolArgs(arguments string) (map[string]any, error) {
	if strings.TrimSpace(arguments) == "" {
		return map[string]any{}, nil
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return nil, fmt.Errorf("invalid tool arguments: %w", err)
	}
	if args == nil {
		return map[string]any{}, nil
	}
	return args, nil
}

// inbandToolError wraps a refusal or malformed-argument error as model-facing tool content
// the loop records and continues from (a non-nil error from Dispatch would instead abort).
func inbandToolError(err error) turn.ToolResult {
	return turn.ToolResult{Content: err.Error()}
}

// formatToolResult renders a successful dispatch tools.Result as the tool message content the
// model reads: stdout and stderr capped through the same helper as tool_exec_end (each labeled
// only when both are present), plus an exit-status line for a non-zero exit so the model sees a
// command failed without the loop aborting. It is the single renderer both shell and structured
// dispatch results pass through. preserveStdoutNewlines keeps the stdout segment's trailing
// newline bytes intact for read, whose stdout is verbatim file content the exact-text contract
// requires byte-for-byte; for every other tool stdout is command output whose trailing
// newline is cosmetic and trimmed. stderr is metadata in both cases, so it is always trimmed.
func formatToolResult(res tools.Result, cap int, preserveStdoutNewlines bool) string {
	modelStdout, modelStderr := events.BuildModelInputBytes(res.Stdout, res.Stderr, cap)
	stdout := string(modelStdout)
	if !preserveStdoutNewlines {
		stdout = strings.TrimRight(stdout, "\n")
	}
	stderr := strings.TrimRight(string(modelStderr), "\n")

	var parts []string
	if stdout != "" {
		parts = append(parts, stdout)
	}
	if stderr != "" {
		if stdout != "" {
			parts = append(parts, "stderr:\n"+stderr)
		} else {
			parts = append(parts, stderr)
		}
	}
	if res.ExitCode != 0 {
		parts = append(parts, fmt.Sprintf("exit status %d", res.ExitCode))
	}
	if len(parts) == 0 {
		return "(no output)"
	}
	return strings.Join(parts, "\n")
}
