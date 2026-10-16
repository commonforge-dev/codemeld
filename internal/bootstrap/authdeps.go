// Production permission-authorizer assembly: binds the landed permission seams — the
// in-memory grant table, the turn-scoped approval cache, the gated prompt,
// persistence-with-degradation, and the event emitters — into one dispatch.Authorizer
// that drives permissions.Authorize for every production tool/shell permission check. It carries
// the prompt display command text separately from the matching subject (so a structured tool
// matches on its registered name yet displays its full call with arguments) and serializes shared
// grant-table/cache access — per seam call for race safety (syncGrants) and per request identity
// so concurrent *identical* checks resolve from the first's recorded grant/cache instead of
// re-prompting (keyedMutex) — so scheduler-driven work units authorize safely in parallel
// behind one shared prompt gate.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissionpersist"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/vcs"
)

const (
	globalGrantKind  = "global"
	folderGrantKind  = "folder"
	projectGrantKind = "project"
)

// productionAuthorizer is the single production binding of dispatch.Authorizer over
// permissions.Authorize. For each tool/shell check it assembles a fresh permissions.AuthorizeDeps
// — the bundle is per-request because the persist target depends on the grant kind and the prompt
// display and global-degradation path depend on the request path scope — then drives the
// orchestrator. The grant table and turn cache are shared across calls and reached only through a
// mutex (syncGrants); concurrent authorizations of the *same* request additionally serialize on a
// per-identity in-flight lock (inflight) so the second observes the first's recorded grant/cache
// outcome rather than racing past the match/cache check and prompting again; and every prompt
// closure serializes through one shared prompt gate, so concurrent scheduler work units authorize
// with race-free shared state and never overlapping or duplicate prompts.
type productionAuthorizer struct {
	grants      *syncGrants
	inflight    *keyedMutex
	prompts     *PromptGateBuilder
	activeStore func() *sessions.Store
	// flush is the app's command-event flush hook, which owns the session-write-failure protocol.
	// RevokeGrant calls it from the tview event-loop goroutine, where that hook is safe.
	flush                func() error
	notices              tui.NoticeRenderer
	display              promptDisplayData
	modeActive           *mode.ActiveState
	declaredCommands     []permissions.DeclaredCommand
	executionConstrained bool
	blocked              *permissions.BlockedPaths
	localNotice          sync.Once
}

// promptDisplayData holds the permission-prompt display fields that are fixed for the run —
// everything PromptDisplay carries except the human-readable Action/Subject/Body (supplied
// per call by the dispatch producer) and FolderCoverage (derived per request from the path scope).
// They are resolved once at StartTUI from the bootstrap result and the config cache.
type promptDisplayData struct {
	projectRoot string
	launchDir   string
	boundary    string
	// folderSettingsPath is <project_root>/.codemeld/settings.yaml — the folder grant's write
	// target and the path the cross-mode marker notice names.
	folderSettingsPath string
	// globalSettingsPath is <home>/.codemeld/global/settings.yaml — the global grant's write target.
	globalSettingsPath string
	localSettingsPath  string
	// wouldCreateSettingsFile reports whether the folder settings file was absent at launch, gating
	// the launch-dir-only cross-mode marker notice.
	wouldCreateSettingsFile bool
	// projectUntrusted is !BootstrapResult.TrustDecision.Trusted, set by StartTUI. The
	// decision is not among this constructor's inputs and must never be inferred from them.
	projectUntrusted bool
	projectApproved  bool
}

// newProductionAuthorizer assembles the run's authorizer. cache is the grant table and composed
// config view; turn is the turn cache (its per-turn Reset boundary is the runtime's concern, not this
// assembly); gate is the one shared prompt gate created per run; app supplies the active-session
// accessor (so emitters and persistence follow a /clear or /resume swap) and the background-safe
// persist-failure notice sink; home and launchDir resolve the global settings path and the cross-mode
// display fields.
func newProductionAuthorizer(app *tui.App, cache *config.Cache, turn *permissions.TurnCache, gate *PromptGateBuilder, home, launchDir string, modeActive *mode.ActiveState) *productionAuthorizer {
	folderSettings := filepath.Join(cache.ProjectRoot(), ".codemeld", "settings.yaml")
	_, statErr := os.Stat(folderSettings)
	return &productionAuthorizer{
		grants: &syncGrants{
			cache: cache, turn: turn,
			localPath: config.LocalSettingsPath(cache.ProjectRoot()), globalPath: SettingsPath(home),
		},
		inflight:         newKeyedMutex(),
		prompts:          gate,
		activeStore:      app.ActiveStore,
		flush:            app.FlushActive,
		notices:          bgNoticeRenderer{app: app},
		modeActive:       modeActive,
		declaredCommands: cache.DeclaredCommands(),
		display: promptDisplayData{
			projectRoot:             cache.ProjectRoot(),
			launchDir:               launchDir,
			boundary:                cache.Discovery(),
			folderSettingsPath:      folderSettings,
			globalSettingsPath:      SettingsPath(home),
			localSettingsPath:       config.LocalSettingsPath(cache.ProjectRoot()),
			wouldCreateSettingsFile: errors.Is(statErr, fs.ErrNotExist),
		},
	}
}

// Authorize drives one production permission check through the orchestrator. It resolves
// the active session store once so all of this check's emitters and any persist-failure event append
// to the same session, builds the prompt closure with the full display command text while the
// matching subject stays req.Subject, and binds the persist and emitter seams. It first takes the
// per-identity in-flight lock so two concurrent identical requests serialize: the second re-runs
// matching only after the first has recorded its grant/cache outcome and short-circuits on it
// (real-grant match or turn-cache hit) instead of showing a duplicate prompt, while distinct
// requests stay fully parallel. permissions.Authorize owns the
// mode-posture→match→cache→prompt flow; this method only assembles its collaborators and
// completes the mode-authorization context.
//
// modeCtx arrives from the dispatch caller with the request-derived fields filled
// (operation class, tool name, pre-normalization shell stage data, resolved target path);
// this method overlays the run-scoped active mode and the project root before handing
// it to permissions.Authorize, so Plan/Build posture is decided centrally with a complete context.
func (a *productionAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	release, err := a.inflight.acquire(ctx, inflightKeyOf(req))
	if err != nil {
		return permissions.Decision{}, err
	}
	defer release()

	modeCtx.ProjectRoot = a.display.projectRoot
	modeCtx.DeclaredCommands = a.declaredCommands
	modeCtx.ExecutionConstrained = a.executionConstrained
	modeCtx.SettingsBroken = a.settingsBroken()

	store := a.activeStore()
	if m, ok := callMode(ctx, a.modeActive); ok {
		modeCtx.Mode = m
	}
	display := a.buildPromptDisplay(markExceptional(disp, req, modeCtx), req.PathScope)
	deps := permissions.AuthorizeDeps{
		Grants:       a.grants,
		Cache:        a.grants,
		Prompt:       a.prompts.Build(req, display),
		PersistGrant: a.persistGrant(store, req.PathScope),
		EmitPromptShown: func(subjectKind, subject, pathScope string, directTokens []string, id permissions.DirectIdentity) error {
			return events.EmitPromptShown(store, subjectKind, subject, pathScope, directTokens, id.CommandSubject, id.RequestSubject)
		},
		EmitDecision: func(subjectKind, subject, pathScope, outcome, grantKind, grantPathScope string, id permissions.DirectIdentity) error {
			return events.EmitDecision(store, subjectKind, subject, pathScope, outcome, grantKind, grantPathScope, id.CommandSubject, id.RequestSubject)
		},
		EmitDecisionGrant: func(subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject string, id permissions.DirectIdentity) error {
			return events.EmitDecisionGrant(store, subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject, id.CommandSubject, id.RequestSubject)
		},
		EmitMatched: func(subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject string) error {
			return events.EmitMatchedIdentity(store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject)
		},
	}
	return permissions.Authorize(ctx, req, modeCtx, deps)
}

// AuthorizeBatch drives one production authorization for a whole direct pipeline through the
// orchestrator's batched path: every stage resolves without prompting, and the stages that
// still need a decision are gathered into ONE command-level approval whose single outcome applies to
// them all. It mirrors Authorize's assembly — the same shared grant table, turn cache,
// persist and emitter seams, and per-request mode/project-root overlay — but binds PromptBatch instead
// of Prompt, so the batched prompt renders once. Like the single path it first takes the per-identity
// in-flight lock for *every* stage identity in the batch (acquireBatchInflight) before any resolution:
// the shared gate alone serializes only the prompt display, after grant/cache misses are already
// computed, so two concurrent identical/overlapping pipelines could both miss the grant and cache and
// prompt twice. Holding the stage locks across permissions.AuthorizeBatch makes a later overlapping
// batch re-run resolution only after the earlier batch records its grants/cache, so it observes them
// instead of showing a duplicate prompt; the syncGrants mutex still guards every table/cache access.
// All stages of a pipeline share the resolved path scope, so the persist target is bound from the first
// stage's scope.
func (a *productionAuthorizer) AuthorizeBatch(ctx context.Context, reqs []dispatch.BatchAuthRequest) ([]permissions.Decision, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	release, err := a.acquireBatchInflight(ctx, reqs)
	if err != nil {
		return nil, err
	}
	defer release()

	store := a.activeStore()
	activeMode, _ := callMode(ctx, a.modeActive)
	broken := a.settingsBroken()

	batch := make([]permissions.BatchRequest, len(reqs))
	displays := make([]PromptDisplay, len(reqs))
	modeCtxs := make([]permissions.ModeContext, len(reqs))
	for i, r := range reqs {
		modeCtx := r.ModeCtx
		modeCtx.ProjectRoot = a.display.projectRoot
		modeCtx.DeclaredCommands = a.declaredCommands
		modeCtx.ExecutionConstrained = a.executionConstrained
		modeCtx.SettingsBroken = broken
		modeCtx.Mode = activeMode
		batch[i] = permissions.BatchRequest{Req: r.Req, ModeCtx: modeCtx}
		modeCtxs[i] = modeCtx
		displays[i] = a.buildPromptDisplay(markExceptional(r.Display, r.Req, modeCtx), r.Req.PathScope)
	}

	deps := permissions.AuthorizeDeps{
		Grants:       a.grants,
		Cache:        a.grants,
		PromptBatch:  a.buildBatchPrompt(displays, modeCtxs),
		PersistGrant: a.persistGrant(store, reqs[0].Req.PathScope),
		EmitPromptShown: func(subjectKind, subject, pathScope string, directTokens []string, id permissions.DirectIdentity) error {
			return events.EmitPromptShown(store, subjectKind, subject, pathScope, directTokens, id.CommandSubject, id.RequestSubject)
		},
		EmitDecision: func(subjectKind, subject, pathScope, outcome, grantKind, grantPathScope string, id permissions.DirectIdentity) error {
			return events.EmitDecision(store, subjectKind, subject, pathScope, outcome, grantKind, grantPathScope, id.CommandSubject, id.RequestSubject)
		},
		EmitDecisionGrant: func(subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject string, id permissions.DirectIdentity) error {
			return events.EmitDecisionGrant(store, subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject, id.CommandSubject, id.RequestSubject)
		},
		EmitMatched: func(subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject string) error {
			return events.EmitMatchedIdentity(store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject)
		},
	}
	return permissions.AuthorizeBatch(ctx, batch, deps)
}

// AuthorizeIndependent drives one production authorization for a group of independently
// authorizable read-only calls. It mirrors AuthorizeBatch's assembly — the same shared grant table,
// turn cache, emitter seams, per-identity in-flight locks, and mode/project-root overlay — but binds
// PromptIndependent, so the group renders once and every call gets back its own decision. The calls
// do not share a path scope the way pipeline stages do, so persistence is bound per request
// (PersistGrantAt): a failed global persist degrades to the requesting call's own scope, never a
// sibling's.
func (a *productionAuthorizer) AuthorizeIndependent(ctx context.Context, reqs []dispatch.IndependentAuthRequest) ([]permissions.Decision, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	inflight := make([]dispatch.BatchAuthRequest, len(reqs))
	for i, r := range reqs {
		inflight[i] = dispatch.BatchAuthRequest{Req: r.Req, Display: r.Display, ModeCtx: r.ModeCtx}
	}
	release, err := a.acquireBatchInflight(ctx, inflight)
	if err != nil {
		return nil, err
	}
	defer release()

	store := a.activeStore()
	activeMode, _ := callMode(ctx, a.modeActive)
	broken := a.settingsBroken()

	batch := make([]permissions.BatchRequest, len(reqs))
	displays := make([]PromptDisplay, len(reqs))
	targets := make([]string, len(reqs))
	for i, r := range reqs {
		modeCtx := r.ModeCtx
		modeCtx.ProjectRoot = a.display.projectRoot
		modeCtx.Mode = activeMode
		modeCtx.ExecutionConstrained = a.executionConstrained
		modeCtx.SettingsBroken = broken
		batch[i] = permissions.BatchRequest{Req: r.Req, ModeCtx: modeCtx}
		displays[i] = a.buildPromptDisplay(markExceptional(r.Display, r.Req, modeCtx), r.Req.PathScope)
		targets[i] = r.PreparedTarget
	}

	deps := permissions.AuthorizeDeps{
		Grants:            a.grants,
		Cache:             a.grants,
		PromptIndependent: a.buildIndependentPrompt(displays, targets),
		PersistGrantAt: func(index int) func(permissions.PermissionEntry) (permissions.PermissionEntry, error) {
			return a.persistGrant(store, reqs[index].Req.PathScope)
		},
		EmitPromptShown: func(subjectKind, subject, pathScope string, directTokens []string, id permissions.DirectIdentity) error {
			return events.EmitPromptShown(store, subjectKind, subject, pathScope, directTokens, id.CommandSubject, id.RequestSubject)
		},
		EmitDecision: func(subjectKind, subject, pathScope, outcome, grantKind, grantPathScope string, id permissions.DirectIdentity) error {
			return events.EmitDecision(store, subjectKind, subject, pathScope, outcome, grantKind, grantPathScope, id.CommandSubject, id.RequestSubject)
		},
		EmitDecisionGrant: func(subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject string, id permissions.DirectIdentity) error {
			return events.EmitDecisionGrant(store, subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject, id.CommandSubject, id.RequestSubject)
		},
		EmitMatched: func(subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject string) error {
			return events.EmitMatchedIdentity(store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject)
		},
	}
	return permissions.AuthorizeIndependent(ctx, batch, deps)
}

func callMode(ctx context.Context, active *mode.ActiveState) (string, bool) {
	if m, ok := vcs.ConfinementMode(ctx); ok {
		return m, true
	}
	if active == nil {
		return "", false
	}
	m, _ := active.Current()
	return string(m), true
}

func (a *productionAuthorizer) settingsBroken() bool {
	return a.executionConstrained && a.blocked.Current().Degraded()
}

// buildIndependentPrompt returns the AuthorizeDeps.PromptIndependent closure for one authorization
// group. It holds the shared single-prompt gate for the whole group, so the group is one prompt
// owner and no other prompt interleaves. The surface is asked one question per distinct decision
// rather than one per call, but the orchestrator is still owed an outcome per call, so each
// question's decision is fanned back out to every member through that member's own display.
func (a *productionAuthorizer) buildIndependentPrompt(displays []PromptDisplay, targets []string) func(context.Context, []permissions.BatchPromptRequest) ([]permissions.PromptOutcome, error) {
	return func(ctx context.Context, prompts []permissions.BatchPromptRequest) ([]permissions.PromptOutcome, error) {
		questions := independentQuestions(prompts, displays)
		requests := make([]tui.PromptRequest, len(questions))
		for i, members := range questions {
			req, err := buildIndependentPromptRequest(prompts, displays, targets, members)
			if err != nil {
				return nil, err
			}
			if len(questions) > 1 {
				req.ApprovalIndex = i + 1
				req.ApprovalTotal = len(questions)
			}
			requests[i] = req
		}
		if err := a.prompts.gate.acquire(ctx); err != nil {
			return nil, err
		}
		defer a.prompts.gate.release()
		decisions, err := a.prompts.showIndependent(requests)
		if err != nil {
			return nil, err
		}
		if len(decisions) != len(questions) {
			return nil, fmt.Errorf("bootstrap: independent prompt returned %d decisions for %d approval questions", len(decisions), len(questions))
		}
		outcomes := make([]permissions.PromptOutcome, len(prompts))
		for i, members := range questions {
			if err := checkExceptionalChoice(requests[i], decisions[i]); err != nil {
				return nil, err
			}
			for _, m := range members {
				outcome, err := mapOutcomeFor(decisions[i], displayAt(displays, prompts[m].Index))
				if err != nil {
					return nil, err
				}
				outcomes[m] = outcome
			}
		}
		return outcomes, nil
	}
}

// independentQuestionKey holds every authorization and display effect a merged approval question
// states once on behalf of all its members, so no member's answer can stand for an effect its screen
// never showed.
type independentQuestionKey struct {
	kind                 string
	subject              string
	pathScope            string
	host                 string
	clearEnvironment     bool
	narrowerScope        string
	action               string
	grantStoredSubject   string
	outOfRootFileWrite   bool
	outOfRootReadScope   bool
	exceptionalAuthority string
}

// independentQuestions partitions one group's unresolved calls into approval questions, each the
// member indexes into prompts that are the same decision, in the calls' original relative order. A
// call carrying subject tokens or assignments is never merged: both are part of what its grant
// authorizes and the key does not compare them. Nor is a host call: the host prompt renders neither
// the merged member list nor a body, so a merge there would hide the differing request outright.
func independentQuestions(prompts []permissions.BatchPromptRequest, displays []PromptDisplay) [][]int {
	questions := make([][]int, 0, len(prompts))
	seen := make(map[independentQuestionKey]int, len(prompts))
	for i, p := range prompts {
		if p.Req.Kind == matchKindHost || len(p.Req.SubjectTokens) > 0 || len(p.Req.Assignments) > 0 {
			questions = append(questions, []int{i})
			continue
		}
		display := displayAt(displays, p.Index)
		key := independentQuestionKey{
			kind:                 p.Req.Kind,
			subject:              p.Req.Subject,
			pathScope:            p.Req.PathScope,
			host:                 p.Req.Host,
			clearEnvironment:     p.Req.ClearEnvironment,
			narrowerScope:        p.Escalation.NarrowerScope,
			action:               display.Action,
			grantStoredSubject:   display.GrantStoredSubject,
			outOfRootFileWrite:   display.OutOfRootFileWrite,
			outOfRootReadScope:   display.OutOfRootReadScope,
			exceptionalAuthority: display.ExceptionalAuthority,
		}
		if at, ok := seen[key]; ok {
			questions[at] = append(questions[at], i)
			continue
		}
		seen[key] = len(questions)
		questions = append(questions, []int{i})
	}
	return questions
}

// buildIndependentPromptRequest maps one approval question to the tui prompt's display contract.
// Every question, including a one-member one, lists the prepared targets its members were resolved
// against rather than the display's requested target, because that is what the authorization
// applies to. Members of a larger question are equal on every field the question states, so a
// representative supplies them all and only what merging would otherwise hide is added back: every
// member's structured call text. The representative Subject is cleared so its call is not shown
// twice.
func buildIndependentPromptRequest(prompts []permissions.BatchPromptRequest, displays []PromptDisplay, targets []string, members []int) (tui.PromptRequest, error) {
	if len(members) == 0 {
		return tui.PromptRequest{}, errors.New("bootstrap: independent approval question has no calls")
	}
	for _, m := range members {
		if m < 0 || m >= len(prompts) {
			return tui.PromptRequest{}, fmt.Errorf("bootstrap: independent prompt index %d out of range for %d calls", m, len(prompts))
		}
	}
	rep := prompts[members[0]]
	pr, err := buildPromptRequest(rep.Req, displayAt(displays, rep.Index), rep.Escalation)
	if err != nil {
		return tui.PromptRequest{}, err
	}
	bodies := make([]string, len(members))
	callTargets := make([]string, len(members))
	for i, m := range members {
		p := prompts[m]
		if p.Index < 0 || p.Index >= len(targets) {
			return tui.PromptRequest{}, fmt.Errorf("bootstrap: independent prompt call index %d out of range for %d prepared targets", p.Index, len(targets))
		}
		bodies[i] = displayAt(displays, p.Index).Body
		callTargets[i] = targets[p.Index]
	}
	// A host question's requested target is the host itself, not a path this group prepared.
	if rep.Req.Kind != matchKindHost {
		pr.Summary.Targets = callTargets
	}
	if len(members) == 1 {
		return pr, nil
	}
	pr.Subject = ""
	pr.Body = strings.Join(bodies, "\n")
	return pr, nil
}

// acquireBatchInflight takes the per-identity in-flight lock for every distinct stage identity in the
// batch and returns one release that frees them all. Keys are de-duplicated and acquired in a
// deterministic order (kind, subject, path scope) so two overlapping batches acquire any shared key in
// the same order and cannot deadlock. Holding all of them across permissions.AuthorizeBatch gives a
// batch the serialization the single Authorize path gets from its one inflight lock: a later
// identical/overlapping batch parks here until the earlier one has recorded its grants/cache, then
// re-resolves and observes them rather than showing a duplicate prompt. On a context error mid-acquire
// the already-held keys are released before returning.
func (a *productionAuthorizer) acquireBatchInflight(ctx context.Context, reqs []dispatch.BatchAuthRequest) (func(), error) {
	seen := make(map[inflightKey]struct{}, len(reqs))
	keys := make([]inflightKey, 0, len(reqs))
	for _, r := range reqs {
		k := inflightKeyOf(r.Req)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		if keys[i].subject != keys[j].subject {
			return keys[i].subject < keys[j].subject
		}
		return keys[i].pathScope < keys[j].pathScope
	})

	releases := make([]func(), 0, len(keys))
	release := func() {
		for i := len(releases) - 1; i >= 0; i-- { // LIFO, mirroring nested locks
			releases[i]()
		}
	}
	for _, k := range keys {
		rel, err := a.inflight.acquire(ctx, k)
		if err != nil {
			release()
			return nil, err
		}
		releases = append(releases, rel)
	}
	return release, nil
}

// buildBatchPrompt returns the AuthorizeDeps.PromptBatch closure for one batched authorization. It maps
// the unresolved stages to one tui.PromptRequest, shows it once behind the shared single-prompt gate
// (the same gate the single Prompt closure uses, so a pipeline prompt still never overlaps another
// work unit's prompt), and maps the returned decision to a permissions.PromptOutcome applied to every
// stage. A single unresolved stage renders as the ordinary single-stage prompt; two or more render as
// one command-level approval.
func (a *productionAuthorizer) buildBatchPrompt(displays []PromptDisplay, modeCtxs []permissions.ModeContext) func(context.Context, []permissions.BatchPromptRequest) (permissions.PromptOutcome, error) {
	return func(ctx context.Context, prompts []permissions.BatchPromptRequest) (permissions.PromptOutcome, error) {
		promptReq, err := buildBatchPromptRequest(prompts, displays, modeCtxs)
		if err != nil {
			return permissions.PromptOutcome{}, err
		}
		if err := a.prompts.gate.acquire(ctx); err != nil {
			return permissions.PromptOutcome{}, err
		}
		defer a.prompts.gate.release()
		decision, err := a.prompts.show(promptReq)
		if err != nil {
			return permissions.PromptOutcome{}, err
		}
		if err := checkExceptionalChoice(promptReq, decision); err != nil {
			return permissions.PromptOutcome{}, err
		}
		return mapOutcome(decision)
	}
}

// buildBatchPromptRequest maps the unresolved stages of a batched authorization to the tui prompt's
// display contract. A single unresolved stage builds the ordinary single-stage request through
// buildPromptRequest, so an N=1 batch renders byte-for-byte as today's per-stage prompt. Two or more
// stages build one command-level approval: the shared authorization facts (run folder, project root,
// grant anchors, pipeline text) come from a representative stage — every stage of a pipeline shares the
// resolved path scope and the pipeline text. Each stage's
// own scope-escalation warning is carried in the index-aligned BatchedEscalations so batching does not
// hide a broaden-of-an-already-approved-folder warning a per-stage prompt would show. The
// representative Subject line is cleared because the verbatim stage list replaces it.
func buildBatchPromptRequest(prompts []permissions.BatchPromptRequest, displays []PromptDisplay, modeCtxs []permissions.ModeContext) (tui.PromptRequest, error) {
	if len(prompts) == 1 {
		p := prompts[0]
		return buildPromptRequest(p.Req, displayAt(displays, p.Index), p.Escalation)
	}
	rep := prompts[0]
	pr, err := buildPromptRequest(rep.Req, displayAt(displays, rep.Index), permissions.ScopeEscalation{})
	if err != nil {
		return tui.PromptRequest{}, err
	}
	stages := make([]string, len(prompts))
	// Carry each stage's scope escalation alongside its subject so a batched prompt still warns
	// when a stage broadens an already-approved narrower folder. Dropping it here would hide
	// trust-scope information a per-stage prompt shows; batching is presentation-only.
	escalations := make([]string, len(prompts))
	var normalized []permissions.StageNormalization
	for i, p := range prompts {
		stages[i] = displayAt(displays, p.Index).Subject
		escalations[i] = p.Escalation.NarrowerScope
		normalized = append(normalized, modeCtxAt(modeCtxs, p.Index).Stages...)
	}
	whole := modeCtxAt(modeCtxs, rep.Index)
	whole.Stages = normalized
	if authority := exceptionalAuthority(rep.Req, whole); authority != "" {
		pr.Action = exceptionalAction(authority)
		pr.ExceptionalAuthority = authority
	}
	pr.BatchedStages = stages
	pr.BatchedEscalations = escalations
	pr.Subject = ""
	// One choice authorizes every stage, so the summary describes the whole batch rather than
	// the representative stage it borrows the shared facts from.
	pr.Summary = promptSummaryFor(rep.Req, displayAt(displays, rep.Index), stages)
	return pr, nil
}

func displayAt(displays []PromptDisplay, i int) PromptDisplay {
	if i < 0 || i >= len(displays) {
		return PromptDisplay{}
	}
	return displays[i]
}

func modeCtxAt(modeCtxs []permissions.ModeContext, i int) permissions.ModeContext {
	if i < 0 || i >= len(modeCtxs) {
		return permissions.ModeContext{}
	}
	return modeCtxs[i]
}

// buildPromptDisplay assembles the bootstrap prompt display for one authorization from the run-scoped
// display data, the per-call dispatch display, and the request path scope (for folder coverage). It is
// the single production seam that carries dispatch's display-only shell scope/pipeline context onto the
// bootstrap display, so a test can pin that carry without driving a full Authorize.
func (a *productionAuthorizer) buildPromptDisplay(disp dispatch.PromptDisplay, pathScope string) PromptDisplay {
	display := PromptDisplay{
		Action:             disp.Action,
		Subject:            disp.Subject,
		Body:               disp.Body,
		ProjectRoot:        a.display.projectRoot,
		LaunchDir:          a.display.launchDir,
		Boundary:           a.display.boundary,
		FolderSettingsPath: a.display.folderSettingsPath,
		// the folder grant covers the resolved request path scope and its descendants.
		FolderCoverage: pathScope + " and its descendants",
		// Carry the dispatch out-of-root edit/create signal through so the prompt offers the
		// folder option for that write (a folder grant whose path_scope is the out-of-root folder, while
		// its settings file stays in the project). False for every other request, so unrelated out-of-root
		// prompts keep hiding the folder option.
		OutOfRootFileWrite: disp.OutOfRootFileWrite,
		// Carry the dispatch external-read signal through so the prompt offers the folder option for
		// an explicit out-of-project read-only scope too (a read-only folder grant; its settings file stays
		// in the project). False for every other request.
		OutOfRootReadScope: disp.OutOfRootReadScope,
		// Carry the dispatch capability stored subject (write/read*) through so a grant-creating
		// choice stores the folded capability rather than the concrete tool name. Empty for every request
		// whose grant should store the concrete request subject.
		GrantStoredSubject:      disp.GrantStoredSubject,
		WouldCreateSettingsFile: a.display.wouldCreateSettingsFile,
		ProjectUntrusted:        a.display.projectUntrusted,
		RequestedTarget:         disp.RequestedTarget,
		HostRequest:             disp.HostRequest,
		DirectHTTPFallback:      disp.DirectHTTPFallback,
		ExceptionalAuthority:    disp.ExceptionalAuthority,
	}
	// carry dispatch's display-only shell scope/pipeline context (direct pipeline text, literal
	// whole-command marker) onto the bootstrap display. Display-only; empty for structured tools.
	return applyShellContext(display, disp)
}

func (a *productionAuthorizer) resetTurnCache() {
	a.grants.ResetTurnCache()
}

func (a *productionAuthorizer) persistGrant(store *sessions.Store, requestPath string) func(permissions.PermissionEntry) (permissions.PermissionEntry, error) {
	return func(entry permissions.PermissionEntry) (permissions.PermissionEntry, error) {
		target := a.display.folderSettingsPath
		switch entry.GrantKind {
		case globalGrantKind:
			target = a.display.globalSettingsPath
		case folderGrantKind, projectGrantKind:
			target = a.display.localSettingsPath
		}
		persisted, created, err := permissionpersist.PersistGrantReportingCreate(store, a.notices, target, requestPath, entry)
		if created && target == a.display.localSettingsPath {
			a.announceLocalSettings()
		}
		return persisted, err
	}
}

// announceLocalSettings gates on a run-local Once because the created report is derived from a
// stat taken outside the write lock, so two concurrent approvals can both report the creation.
func (a *productionAuthorizer) announceLocalSettings() {
	a.localNotice.Do(func() {
		a.notices.Notice(tui.RenderLocalSettingsIgnoreNotice(
			a.display.localSettingsPath, config.LocalSettingsLockPath(a.display.projectRoot)))
	})
}

// RevokeGrant removes one permission grant from disk and the live in-memory grant table,
// keeping the two in sync. It is the revoke seam the /permissions overlay revoke control
// calls; it owns the grant-kind→settings-file routing (mirroring persistGrant) so the call site
// does not duplicate it.
//
// The composed permission list keeps no per-entry source path, so a grant that matches in memory
// may live only in another (composed-only) layer this surface cannot write.
// permissionpersist.DeleteGrant treats an absent-on-target key as a silent no-op, which would
// otherwise let such a grant be dropped from memory while still set on disk. So RevokeGrant first
// verifies the selected writable file actually contains the entry: an absent-on-target grant is
// reported and skipped, not revoked. A target that cannot be inspected (unreadable, malformed, or
// schema-invalid) and a failed settings write are both reported as a revoke failure and leave the
// live grant in place.
//
// Skip/failure notices go through the caller-supplied notices sink, not the authorizer's own
// background renderer (a.notices). The /permissions confirm path calls RevokeGrant synchronously on
// the tview event-loop goroutine, where the background renderer would deadlock: its Notice marshals
// through QueueUpdateDraw, which blocks until the loop drains — but the loop is the very goroutine
// waiting on this call. The caller therefore passes an on-loop-safe sink (the *tui.App, whose Notice
// renders directly), while the off-loop persist path keeps using a.notices.
//
// A revoke that actually happened is also recorded as a permission_revoke_requested event, so a
// session distinguishes a deliberate revoke from an ordinary edit that removed the same YAML. The
// live grant is dropped before that recording is attempted: settings and session are separate files
// with no cross-file transaction, and a revoked grant that keeps authorizing is the worse failure
// than a revoke with no event.
func (a *productionAuthorizer) RevokeGrant(entry permissions.PermissionEntry, notices tui.NoticeRenderer) {
	target, persisted := revokeTarget(a.display, entry.GrantKind)
	if !persisted {
		// Session-only grant: it is memory-only, so removing it from the table is the whole revoke.
		if !a.grants.RemovePermission(tui.PermissionRow{Entry: entry}) {
			return
		}
		a.recordRevokeRequest(entry, notices)
		return
	}
	layer := permissions.LayerLocal
	if entry.GrantKind == globalGrantKind {
		layer = permissions.LayerGlobal
	}
	present, inspectErr := targetHasGrant(target, a.display.projectRoot, entry.DedupKey())
	if inspectErr != nil {
		// The writable target exists but could not be read, parsed, or validated, so we cannot tell
		// whether it holds the grant. Report a revoke failure with the real reason and keep the live
		// grant rather than dropping one that may still be set on disk.
		notices.Notice(tui.RenderRevokeFailedNotice(target, inspectErr.Error()))
		return
	}
	if !present {
		// The grant matches in memory but is absent from its writable target. Deleting there is a
		// no-op, so report and keep the live grant rather than dropping a grant that may still be set
		// on disk.
		notices.Notice(tui.RenderRevokeSkipNotice(target, a.grants.holdingRow(entry.DedupKey(), layer)))
		return
	}
	if err := permissionpersist.DeleteGrant(notices, a.display.localSettingsPath, a.display.globalSettingsPath, entry); err != nil {
		notices.Notice(tui.RenderRevokeFailedNotice(target, err.Error()))
		return
	}
	a.grants.RemovePermission(tui.PermissionRow{Entry: entry, Layer: layer, Path: target})
	a.recordRevokeRequest(entry, notices)
}

var beforeRevokeRowPersist func()

func (a *productionAuthorizer) RevokeRow(row tui.PermissionRow, notices tui.NoticeRenderer) {
	if row.Layer == "" {
		a.RevokeGrant(row.Entry, notices)
		return
	}
	if row.Layer != permissions.LayerLocal && row.Layer != permissions.LayerGlobal && row.Layer != permissions.LayerProject {
		return
	}
	row.Path = layerSettingsPath(a.display, row.Layer)
	key := row.Entry.DedupKey()
	present, inspectErr := targetHasGrant(row.Path, a.display.projectRoot, key)
	if inspectErr != nil {
		notices.Notice(tui.RenderRevokeFailedNotice(row.Path, inspectErr.Error()))
		return
	}
	if !present {
		notices.Notice(tui.RenderRevokeSkipNotice(row.Path, a.grants.holdingRow(key, row.Layer)))
		return
	}
	if beforeRevokeRowPersist != nil {
		beforeRevokeRowPersist()
	}
	op := &config.PermissionDeleteOp{Key: key}
	if _, _, err := config.Persist(row.Path, config.KeyPermissions, op); err != nil {
		notices.Notice(tui.RenderRevokeFailedNotice(row.Path, err.Error()))
		return
	}
	if !op.Removed {
		notices.Notice(tui.RenderRevokeSkipNotice(row.Path, a.grants.holdingRow(key, row.Layer)))
		return
	}
	a.grants.removeRow(row)
	a.recordRevokeRequest(row.Entry, notices)
}

// ShareGrant leaves the effective grant table alone: the grant authorizes the same before and after.
func (a *productionAuthorizer) ShareGrant(row tui.PermissionRow) tui.ShareResult {
	if row.Layer != permissions.LayerLocal || !a.display.projectApproved {
		return tui.ShareResult{Refused: true}
	}
	res := tui.ShareResult{
		SharedPath: layerSettingsPath(a.display, permissions.LayerProject),
		LocalPath:  layerSettingsPath(a.display, permissions.LayerLocal),
	}
	entry := row.Entry
	key := entry.DedupKey()
	present, err := targetHasGrant(res.SharedPath, a.display.projectRoot, key)
	if err != nil {
		res.SharedErr = err
		return res
	}
	if present {
		res.SharedSkipped = true
	} else {
		_, statErr := os.Stat(res.SharedPath)
		if _, _, err := config.Persist(res.SharedPath, config.KeyPermissions, entry); err != nil {
			res.SharedErr = err
			return res
		}
		if errors.Is(statErr, fs.ErrNotExist) {
			_, postErr := os.Stat(res.SharedPath)
			res.SharedCreated = postErr == nil
		}
	}
	a.grants.addRow(tui.PermissionRow{Entry: entry, Layer: permissions.LayerProject, Path: res.SharedPath})
	if _, _, err := config.Persist(res.LocalPath, config.KeyPermissions, config.PermissionDelete(key)); err != nil {
		res.LocalErr = err
		return res
	}
	a.grants.dropRow(tui.PermissionRow{Entry: entry, Layer: permissions.LayerLocal, Path: res.LocalPath})
	return res
}

func layerSettingsPath(d promptDisplayData, layer permissions.LayerKind) string {
	switch layer {
	case permissions.LayerLocal:
		return d.localSettingsPath
	case permissions.LayerProject:
		return d.folderSettingsPath
	case permissions.LayerGlobal:
		return d.globalSettingsPath
	default:
		return ""
	}
}

// recordRevokeRequest appends the revocation event for an already-removed grant and flushes it.
//
// The flush hook runs the session-write-failure notice/retry protocol itself and returns nil once
// it has handled such a failure, leaving the appended record queued for the next flush boundary
// with that protocol's notice as the only report. So only an append rejection (which queues
// nothing) or a flush error that protocol does not own reaches the notice here; reporting a handled
// write failure again would double-report one revoke.
func (a *productionAuthorizer) recordRevokeRequest(entry permissions.PermissionEntry, notices tui.NoticeRenderer) {
	err := events.EmitPermissionRevokeRequested(
		a.activeStore(), entry.Kind, entry.Subject, entry.PathScope, entry.HostScope, entry.GrantKind, entry.ArgumentHash)
	if err == nil {
		err = a.flush()
	}
	if err != nil {
		notices.Notice(renderRevokeNotRecordedNotice(err))
	}
}

// renderRevokeNotRecordedNotice must not read as a failed revoke: the grant is already gone from
// disk and memory by the time recording is attempted, so this reports only the missing record.
func renderRevokeNotRecordedNotice(err error) string {
	return "revoke not recorded — the grant was removed but the session record failed: " +
		fserrors.CollapseControls(err.Error())
}

func revokeTarget(d promptDisplayData, grantKind string) (path string, persisted bool) {
	switch grantKind {
	case globalGrantKind:
		return d.globalSettingsPath, true
	case folderGrantKind, projectGrantKind:
		return d.localSettingsPath, true
	default:
		return "", false
	}
}

// targetHasGrant reports whether the settings file at path currently contains a permission entry
// whose identity is key. It parses the file through the same config view that built the live grant
// table, so a DedupKey that matched in memory is compared against that file's own entries — closing
// the gap that the composed table keeps no source path.
//
// An absent file legitimately means the grant is set in another (composed-only) layer, so it
// returns (false, nil) and revoke skips it. But an unreadable, malformed, schema-invalid, or
// otherwise un-parseable file cannot be inspected at all: returning "absent" there would let the
// caller drop a grant that may still be on disk. So an inspection failure is surfaced as a non-nil
// inspectErr, which the caller turns into a revoke-failed notice that keeps the live grant.
func targetHasGrant(path, projectRoot string, key permissions.DedupKey) (present bool, inspectErr error) {
	_, raw, cat, err := config.LoadYAML(path)
	if err != nil || cat != config.LoadOK {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	cache, err := config.NewCache(raw, projectRoot, nil)
	if err != nil {
		return false, err
	}
	for _, e := range cache.Permissions() {
		if e.DedupKey() == key {
			return true, nil
		}
	}
	return false, nil
}

// syncGrants serializes access to the run's shared, otherwise non-concurrency-safe permission state:
// the in-memory grant table (*config.Cache) and the turn-scoped approval cache
// (*permissions.TurnCache). The scheduler runs work units on separate goroutines and each
// authorizes independently, so every read, append, lookup, and record the orchestrator makes passes
// through one mutex here — guaranteeing race-free shared access (a concurrent map write in the turn
// cache or slice append in the grant table would otherwise corrupt state). The mutex is held only for
// each individual seam call, never across the prompt, so a blocking prompt cannot stall an
// already-grantable authorization on another worker. This per-call locking buys race safety but not
// decision atomicity across calls: serializing concurrent *identical* requests, so the second does
// not prompt after the first's grant, is the in-flight keyedMutex's job (productionAuthorizer.Authorize).
// It implements both permissions.GrantTable and permissions.ApprovalCache.
type syncGrants struct {
	mu         sync.Mutex
	cache      *config.Cache
	turn       *permissions.TurnCache
	rows       []tui.PermissionRow
	localPath  string
	globalPath string
}

func (s *syncGrants) Permissions() []permissions.PermissionEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache.Permissions()
}

func (s *syncGrants) LayeredPermissions() []tui.PermissionRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.rows)
}

// AppendPermission relies on the authorizer handing it a session entry whenever the permanent
// write failed, so a permanent grant kind here means the file holds it.
func (s *syncGrants) AppendPermission(e permissions.PermissionEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache.AppendPermission(e)
	row := tui.PermissionRow{Entry: e}
	switch e.GrantKind {
	case globalGrantKind:
		row.Layer, row.Path = permissions.LayerGlobal, s.globalPath
	case folderGrantKind, projectGrantKind:
		row.Layer, row.Path = permissions.LayerLocal, s.localPath
	}
	s.putRow(row)
}

func (s *syncGrants) addRow(row tui.PermissionRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putRow(row)
}

func (s *syncGrants) dropRow(row tui.PermissionRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteRow(row)
}

func (s *syncGrants) removeRow(row tui.PermissionRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteRow(row)
	key := row.Entry.DedupKey()
	for _, r := range s.rows {
		if r.Entry.DedupKey() == key {
			return
		}
	}
	s.cache.RemovePermission(row.Entry)
}

func (s *syncGrants) holdingRow(key permissions.DedupKey, except permissions.LayerKind) tui.PermissionRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.Layer != "" && r.Layer != except && r.Entry.DedupKey() == key {
			return r
		}
	}
	return tui.PermissionRow{}
}

func (s *syncGrants) putRow(row tui.PermissionRow) {
	if s.rowIndex(row) < 0 {
		s.rows = append(s.rows, row)
	}
}

func (s *syncGrants) deleteRow(row tui.PermissionRow) {
	if i := s.rowIndex(row); i >= 0 {
		s.rows = slices.Delete(s.rows, i, i+1)
	}
}

func (s *syncGrants) rowIndex(row tui.PermissionRow) int {
	key := row.Entry.DedupKey()
	return slices.IndexFunc(s.rows, func(r tui.PermissionRow) bool {
		return r.Layer == row.Layer && r.Path == row.Path && r.Entry.DedupKey() == key
	})
}

// RemovePermission drops a grant from the in-memory table under the same mutex that
// guards AppendPermission, so a revoke (productionAuthorizer.RevokeGrant) cannot race a
// concurrent prompt-gate append, and reports whether the table actually held it. It is the
// in-memory half of a revoke; the disk half runs outside the lock, mirroring how the persist
// write is not held under it.
func (s *syncGrants) RemovePermission(row tui.PermissionRow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteRow(row)
	return s.cache.RemovePermission(row.Entry)
}

func (s *syncGrants) Lookup(req permissions.MatchRequest) (outcome string, hit bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.turn.Lookup(req)
}

func (s *syncGrants) Record(req permissions.MatchRequest, outcome string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.Record(req, outcome)
}

func (s *syncGrants) ResetTurnCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turn.Reset()
}

// bgNoticeRenderer renders the persist-failure notice from the background turn or
// scheduler goroutine an authorization runs on, marshaling it through the tview queue via
// NoticeFromBackground so it is safe off the event loop (mirroring turnNoticeRenderer). The persist
// seam calls Notice from inside permissions.Authorize, never on the tview goroutine.
type bgNoticeRenderer struct{ app *tui.App }

func (r bgNoticeRenderer) Notice(text string) { r.app.NoticeFromBackground(text) }

// inflightKey identifies a production authorization for serializing concurrent
// *identical* requests. It mirrors the turn cache's identity tuple
// (§Reserved Values "Turn-scoped approval cache": subject kind, canonical subject,
// resolved path scope); MatchRequest.SubjectTokens is deliberately excluded so two
// checks that share that tuple but differ only in their token slice serialize
// together, exactly as the cache collapses them onto one entry.
type inflightKey struct {
	kind      string
	subject   string
	pathScope string
}

func inflightKeyOf(req permissions.MatchRequest) inflightKey {
	return inflightKey{kind: req.Kind, subject: req.Subject, pathScope: req.PathScope}
}

// keyedMutex provides per-key mutual exclusion: callers holding different keys never
// block each other, while callers sharing a key serialize. It closes the stale-miss
// race that syncGrants' per-call locking leaves open: each individual grant-table or
// cache access is race-free, but the orchestrator's match → cache-miss → prompt →
// record sequence is not atomic, so two concurrent identical requests could both miss
// the grant and cache before either recorded its outcome and then each display a
// prompt for the same subject. Serializing the whole authorization per request
// identity makes the second identical request re-run matching only after the first
// has recorded its grant/cache outcome, so it short-circuits on that outcome (a
// real-grant match or a turn-cache hit) instead of prompting again — concurrent
// identical requests then behave exactly like sequential repeats.
// Distinct keys are untouched, so unrelated authorizations still run in parallel and
// a blocking prompt never stalls a different request.
type keyedMutex struct {
	mu    sync.Mutex
	slots map[inflightKey]*keyedSlot
}

// keyedSlot is one key's lock: a single-permit semaphore (a cap-1 channel) plus a
// reference count of the goroutines holding or waiting on it, so the map entry is
// dropped once nobody needs it and the map cannot grow without bound over a run.
type keyedSlot struct {
	sem  chan struct{}
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{slots: map[inflightKey]*keyedSlot{}}
}

// acquire takes the lock for key, blocking until any other holder of the same key
// releases, and returns a release func the caller must defer. It is context-aware,
// mirroring the prompt gate: an already-cancelled ctx returns its error without
// touching the lock, and a ctx cancelled while waiting returns its error without
// taking the lock — so a cancelled same-key worker drops out instead of waiting
// behind another worker's prompt.
func (k *keyedMutex) acquire(ctx context.Context, key inflightKey) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k.mu.Lock()
	slot := k.slots[key]
	if slot == nil {
		slot = &keyedSlot{sem: make(chan struct{}, 1)}
		k.slots[key] = slot
	}
	slot.refs++
	k.mu.Unlock()

	select {
	case slot.sem <- struct{}{}:
		return func() { k.release(key, slot, true) }, nil
	case <-ctx.Done():
		k.release(key, slot, false)
		return nil, ctx.Err()
	}
}

// release drops one reference to key's slot, frees the permit if this caller held it,
// and deletes the slot once no goroutine references it. While a slot has any
// reference it stays the canonical map entry for its key, so no concurrent acquire
// can resurrect a half-deleted slot.
func (k *keyedMutex) release(key inflightKey, slot *keyedSlot, held bool) {
	if held {
		<-slot.sem
	}
	k.mu.Lock()
	slot.refs--
	if slot.refs == 0 {
		delete(k.slots, key)
	}
	k.mu.Unlock()
}

// productionAuthorizer satisfies the dispatch seam shared by DispatchTool and DispatchShell, and
// the batched seam DispatchShell's direct-pipeline route drives.
var (
	_ dispatch.Authorizer            = (*productionAuthorizer)(nil)
	_ dispatch.BatchAuthorizer       = (*productionAuthorizer)(nil)
	_ dispatch.IndependentAuthorizer = (*productionAuthorizer)(nil)
)
