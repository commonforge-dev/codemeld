// Headless one-shot run: the `codemeld run` driver that reuses the shared fresh-launch
// bootstrap core and runs exactly one agentic turn with a fail-closed permission posture.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/permissionpersist"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/sessionturn"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
)

// ErrModelNotInCatalog reports that an explicit `--model` selection names a
// provider/model the run's resolved catalog does not offer (model.Validate failed).
// It is a usage error: the CLI maps it to exit 2, not a bootstrap/provider failure.
var ErrModelNotInCatalog = errors.New("bootstrap: --model selection is not in the run's model catalog")

// ErrModelPickerRequired reports that a headless run resolved no active model and
// no `--model` was given — the path-4 picker-required outcome. The
// interactive launch opens the model picker here; a headless run cannot, so the CLI
// maps this to a usage exit 2 telling the user to pass `--model` (Architecture Review).
var ErrModelPickerRequired = errors.New("bootstrap: no model determined for a headless run; pass --model")

const headlessDenyReason = "no approval available in non-interactive run mode; not authorized by an existing grant or read-only auto-allow"

const headlessReadOnlyHint = "If you intended only to read, use a structured read tool or a simpler read-only command instead."

const maxRefusalsPerCall = 5

// HeadlessFreshSteps builds the fresh-launch step set for a headless run. It starts
// from the production DefaultFreshSteps, always substitutes a non-prompting trust gate
// that can honor a record already made for the project root and a non-prompting journal
// recovery step (a headless run has no one to answer, so a path changed since the crash is
// reported and deferred rather than waited on from stdin) and, when given, substitutes
// a `--model` override (a DetermineModel step that builds and catalog-validates the explicit
// selection) and a `--mode` override (an InitMode step pinning the run's interaction
// mode). Every bootstrap-phase message — first-run notices, VCS warnings, and the
// path-4 model diagnostics — is routed to stderr so the run's stdout carries
// only the assistant reply (Done-when 2). StartTUI is never invoked on this path
// (RunHeadless runs the one-shot driver in place of step 8), so its bound writer is
// unused.
func HeadlessFreshSteps(stderr io.Writer, modelOverride *model.Selection, modeKey string) FreshSteps {
	steps := DefaultFreshSteps(stderr, stderr)
	steps.GateTrust = headlessTrustGate(stderr)
	steps.RecoverJournals = func(home, projectRoot string, global map[string]any, decision trust.Decision) {
		recoverChildJournals(home, projectRoot, global, decision, nil, stderr, false)
	}
	if modelOverride != nil {
		steps.DetermineModel = overrideDetermineModelStep(*modelOverride)
	}
	if modeKey != "" {
		steps.InitMode = overrideInitModeStep(modeKey, stderrNoticeRenderer{w: stderr})
	}
	return steps
}

// overrideDetermineModelStep returns a DetermineModel step that resolves the run's
// active model from an explicit `--model`/`--effort` selection instead of model.active.
// It validates the selection against the run's catalog (model.Validate) the same way
// the on-disk model.active path does; an uncatalogued provider/model surfaces
// ErrModelNotInCatalog (CLI exit 2) rather than a launch failure. The recorded source
// is SourceProject — an explicit, validated selection, like a per-project model.active.
func overrideDetermineModelStep(sel model.Selection) func(composed, global map[string]any, projectRoot string, layerPaths []string) (any, bool, error) {
	return func(composed, global map[string]any, projectRoot string, layerPaths []string) (any, bool, error) {
		if composed == nil {
			composed = map[string]any{}
		}
		cache, err := config.NewCache(composed, projectRoot, layerPaths)
		if err != nil {
			return nil, false, fmt.Errorf("bootstrap: headless model config cache: %w", err)
		}
		s := sel
		if verr := model.Validate(&s, cache); verr != nil {
			return nil, false, fmt.Errorf("%w: %s", ErrModelNotInCatalog, verr.Error())
		}
		return model.NewActiveState(&s, model.SourceProject), false, nil
	}
}

// overrideInitModeStep returns an InitMode step that pins the run's interaction mode
// to modeKey (the canonical "plan"/"build"/"auto_edits" key), overriding mode.default.
// It records the mode durably exactly as the production step records mode.default — a
// session-start interaction_mode{trigger:"launch"} through the shared emitInteractionMode
// — so /status and a later resume see the mode the run actually ran under. The user
// chose it explicitly via the flag, so the recorded source is user_command.
func overrideInitModeStep(modeKey string, ui tui.NoticeRenderer) func(ctx context.Context, store *sessions.Store, composed map[string]any, projectRoot string, layerPaths []string) (any, error) {
	return func(ctx context.Context, store *sessions.Store, composed map[string]any, projectRoot string, layerPaths []string) (any, error) {
		active := mode.NewActiveState(mode.Mode(modeKey), mode.SourceUserCommand)
		if err := emitInteractionMode(ctx, store, active, mode.TriggerLaunch, ui); err != nil {
			return nil, err
		}
		return active, nil
	}
}

type HeadlessDriver struct {
	prompt string
	stdout io.Writer
	stderr io.Writer

	// promptForApproval and stdin carry the interactive-escalation opt-in. When
	// promptForApproval is true, Run binds the terminal prompt (reading from stdin,
	// rendering to stderr) in place of the default-deny closure. They are unset by
	// NewHeadlessDriver and turned on only via EnablePromptForApproval, so a driver built
	// by NewHeadlessDriver alone stays fail-closed.
	promptForApproval bool
	stdin             io.Reader

	// devDebug carries the --dev-debug opt-in: when set, Run turns on the
	// suggest_followup development trace on the turn (ORed with CODEMELD_DEV_DEBUG). It is
	// off unless EnableDevDebug is called, so a normal headless run records no debug events.
	devDebug bool

	// sessionTitle holds the `codemeld run --title` name; the CLI owns its normalization,
	// so Run writes the value verbatim.
	sessionTitle string

	// declaredWrite and declaredDelete hold the run's raw --files-authorized /
	// --files-authorized-delete values. They stay raw here because the home and launch
	// directory they canonicalize against are produced by the bootstrap, not by the CLI.
	declaredWrite  []string
	declaredDelete []string

	experiment *HeadlessExperiment

	deadline  time.Time
	timeLimit time.Duration

	// authorizer is created in Run and retained so DeniedSubjects can report what the
	// turn refused. It is nil until Run executes.
	authorizer *headlessAuthorizer
}

// EnableDevDebug turns on the suggest_followup development trace for this run (the
// `codemeld run --dev-debug` opt-in). Run ORs it with CODEMELD_DEV_DEBUG, so either source
// enables the trace; without it the run stays byte-free of suggest_followup_debug events.
func (d *HeadlessDriver) EnableDevDebug() { d.devDebug = true }

// DevDebugRequested reports whether --dev-debug was bound onto this driver
// (EnableDevDebug). It is the observable form of that wiring for the CLI's run test, which
// confirms the flag reached the real driver. intentional: test-only seam (no production
// caller by design) — production reads d.devDebug directly in Run.
func (d *HeadlessDriver) DevDebugRequested() bool { return d.devDebug }

func NewHeadlessDriver(prompt string, stdout, stderr io.Writer) *HeadlessDriver {
	return &HeadlessDriver{prompt: prompt, stdout: stdout, stderr: stderr}
}

// EnablePromptForApproval switches the run from fail-closed default-deny to interactive
// terminal escalation: a tool call the active mode does not auto-allow and no grant
// authorizes pauses and asks on the terminal — the request renders to stderr, one choice is
// read from stdin — instead of being denied in-band. The caller (internal/cli/run.go) must gate
// this on stdin being a real terminal before enabling it.
func (d *HeadlessDriver) EnablePromptForApproval(stdin io.Reader) {
	d.promptForApproval = true
	d.stdin = stdin
}

// SetDeclaredFileScopes binds the run's declared write and delete path lists, the ceiling that
// becomes the sole authorization for every write tool in the run. Run canonicalizes them once the
// bootstrap has produced the home and launch directory they resolve against, and before the first
// turn. It follows EnablePromptForApproval's shape so NewHeadlessDriver keeps its signature.
func (d *HeadlessDriver) SetDeclaredFileScopes(write, remove []string) {
	d.declaredWrite = write
	d.declaredDelete = remove
}

// SetSessionTitle binds the name `codemeld run --title` gives this run's session, or "" to leave
// it unnamed. It follows EnablePromptForApproval's shape so NewHeadlessDriver keeps its signature.
func (d *HeadlessDriver) SetSessionTitle(title string) { d.sessionTitle = title }

func (d *HeadlessDriver) SessionTitle() string { return d.sessionTitle }

func (d *HeadlessDriver) SetTimeLimit(deadline time.Time, limit time.Duration) {
	d.deadline = deadline
	d.timeLimit = limit
}

func (d *HeadlessDriver) TimeLimit() (deadline time.Time, limit time.Duration) {
	return d.deadline, d.timeLimit
}

// DeclaredFileScopes returns the raw declarations bound onto this driver, in the order the flags
// supplied them. Run reads them through it, and the CLI's run test uses the same accessor to
// confirm each repeated flag value reached the real driver unsplit.
func (d *HeadlessDriver) DeclaredFileScopes() (write, remove []string) {
	return d.declaredWrite, d.declaredDelete
}

// PromptForApprovalEnabled reports whether interactive terminal escalation was enabled on this
// driver (EnablePromptForApproval). It is the observable form of that wiring, so the CLI's run
// test can confirm the --prompt-for-approval flag bound the terminal prompt onto the real driver
// (the production wiring this task owns). intentional: test-only seam (no production caller by
// design) — production reads d.promptForApproval directly in Run.
func (d *HeadlessDriver) PromptForApprovalEnabled() bool { return d.promptForApproval }

// DeniedCall is one refusal the run recorded: the subject label the caller sees, the reason the
// model was given, and the permission outcome source that decided it. Source is what lets the exit
// summary tell a declared-scope refusal from an ordinary fail-closed one without reading the reason
// text or checking which flags the run was started with.
type DeniedCall struct {
	Subject          string
	Reason           string
	Source           string
	Exceptional      bool
	TerminalApprover bool
}

// DeclaredScope reports whether the run's declared file scopes produced this denial — the one class
// no permission grant and no --prompt-for-approval can widen.
func (d DeniedCall) DeclaredScope() bool { return d.Source == permissions.OutcomeSourceDeclaredScope }

// DeniedSubjects returns the distinct denials the run's turn recorded, in first-seen order, with
// the subject label, reason, and classification the CLI's denial summary needs. It is empty before
// Run executes or when nothing was denied.
func (d *HeadlessDriver) DeniedSubjects() []DeniedCall {
	if d.authorizer == nil {
		return nil
	}
	return d.authorizer.deniedSubjects()
}

// RunHeadless runs the headless one-shot: it drives the shared bootstrap core
// (runFreshCore — every fresh-launch step except StartTUI) and then, in place of the
// TUI event loop, the driver's single turn. It returns the subjects the turn denied
// (for the CLI summary) and the run's terminal error.
//
// The first-run branch returns (nil, nil): generation ran and the caller exits 0
// without a turn. A path-4 picker-required outcome (no model determined, no
// --model) returns ErrModelPickerRequired, which the CLI maps to a usage exit 2 — a
// headless run cannot open the interactive picker. Otherwise it runs the driver and
// returns its denials and error.
// flushSessionTitle is runFreshCore's step 7b tail rather than part of Run, because every
// record runFreshCore appends after session creation — launch_began, the launch
// interaction_mode, the AGENTS.md loads — happens before Run is ever called. Writing the
// name here is what makes it survive an interrupt anywhere in the rest of the launch. It is
// detached from ctx so a cancel cannot beat it to disk, and a failure is reported through the
// metadata-write notice path and discarded: losing the name is not worth killing a batch run.
func (d *HeadlessDriver) flushSessionTitle(ctx context.Context, session *sessions.Store) {
	title := d.SessionTitle()
	if title == "" {
		return
	}
	if cat, reason, err := session.FlushTitle(context.WithoutCancel(ctx), title); err != nil && reason != sessions.ReasonNone {
		_ = sessionfailures.HandleWriteFailure(reason, cat, session.Path(), err, session, stderrNoticeRenderer{w: d.stderr})
	}
}

func RunHeadless(ctx context.Context, cwd string, steps FreshSteps, driver *HeadlessDriver) ([]DeniedCall, error) {
	steps.FlushSessionTitle = driver.flushSessionTitle
	res, firstRun, err := runFreshCore(ctx, cwd, steps)
	if err != nil {
		return nil, err
	}
	if firstRun {
		return nil, nil
	}
	if res.ResumeLockRelease != nil {
		defer res.ResumeLockRelease()
	}
	if res.ModelPickerRequired {
		return nil, ErrModelPickerRequired
	}
	runErr := driver.Run(ctx, res)
	return driver.DeniedSubjects(), runErr
}

// Run assembles the production turn collaborators over the bootstrap result —
// reusing StartTUI's assembly patterns (config cache, realized tool registry, system-
// prompt and advertised-tool assemblers, production tool dispatcher) — but binds the
// fail-closed headless authorizer instead of the interactive prompt gate, persists the
// prompt through the pre-turn durability boundary, and runs exactly one turn.NewToolLoop.
//
// A user interrupt (Ctrl-C, surfaced as context cancellation) or the turn deadline is
// not a failure *provided* the final WithoutCancel flush durably persists the partial
// work: only then does Run return nil. If that final flush fails, the run is not
// durably resumable, so the failure is surfaced (routed through the notice
// path for a real write reason) rather than masked as a clean interrupt. Any other turn
// error is returned for the CLI to map to a non-zero exit.
func (d *HeadlessDriver) Run(ctx context.Context, result *BootstrapResult) (retErr error) {
	if result == nil || result.Session == nil {
		return fmt.Errorf("bootstrap: RunHeadless requires an active session")
	}

	session := result.Session
	stderr := &headlessStderr{w: d.stderr}

	// Both lists resolve here, together, before any collaborator is built and before the
	// first turn: a failure ends the run with nothing partially resolved.
	rawWrite, rawDelete := d.DeclaredFileScopes()
	declaredWrite, declaredDelete, declErr := filetools.ResolveDeclaredScopes(result.Home, result.LaunchDir, rawWrite, rawDelete)
	if declErr != nil {
		return fmt.Errorf("bootstrap: headless declared file scope: %w", declErr)
	}

	// Narrow the loosely-typed bootstrap fields to the concrete landed state, exactly
	// as StartTUI does: an absent model yields a "no model selected" state and an absent
	// mode falls back to the launch default.
	active, ok := result.Model.(*model.ActiveState)
	if !ok || active == nil {
		active = model.NewActiveState(nil, "")
	}
	modeActive, isMode := result.Mode.(*mode.ActiveState)
	if !isMode || modeActive == nil {
		modeActive = mode.NewActiveState(mode.Build, mode.SourceDefault)
	}
	composed := result.Config
	if composed == nil {
		composed = map[string]any{}
	}
	cache, err := config.NewCache(composed, result.ProjectRoot, result.ConfigLayerPaths, result.Home)
	if err != nil {
		return fmt.Errorf("bootstrap: headless build config cache: %w", err)
	}
	execution := resolveExecutionCapability(enforce.ResolveInput{Home: result.Home})
	tmpDir, err := startExecutionCapability(execution, stderrNoticeRenderer{w: stderr})
	if err != nil {
		return fmt.Errorf("bootstrap: headless create confinement temp folder: %w", err)
	}
	if tmpDir != "" {
		defer func() { retErr = errors.Join(retErr, removeSessionTempDir(tmpDir)) }()
	}

	// The active store never swaps in a headless run (no /clear or /resume), so the
	// accessor every collaborator reads through is a constant.
	storeAccessor := func() *sessions.Store { return session }

	skillLines := loadSkills(result, cache.AgentInstructionsMaxFileBytes())
	assemblePrompt := newSystemPromptAssembler(result, modeActive, active)
	// One run-scoped holder for both the general_agent binding below and the turn runHeadlessTurn
	// publishes, exactly as StartTUI does: realization precedes the turn, so it has to exist
	// here for both sides to reference the same instance.
	generalAgentParent := &parentTurnHolder{}
	guard, err := protectedStatePolicy(result.Home, cache.ProjectRoot(), result.SettingsLayers)
	if err != nil {
		return fmt.Errorf("bootstrap: headless build blocked paths: %w", err)
	}
	guard.Blocked.SetNotice(stderrNoticeRenderer{w: stderr}.Notice)
	blockedEntries, err := blockedEntriesFromLayers(result.Home, result.SettingsLayers)
	if err != nil {
		return fmt.Errorf("bootstrap: headless build blocked paths: %w", err)
	}
	initial := (&capabilityRecorder{launch: execution, blocked: guard.Blocked}).current()
	_ = recordExecutionCapability(ctx, session, initial, stderrNoticeRenderer{w: stderr})
	launchMode, _ := modeActive.Current()
	stderr.line(initial.SandboxLabel(string(launchMode)))
	stopDelivery := func() {}
	if execution.Capability == enforce.Constrained {
		stopDelivery = deliverCapabilityChanges(guard.Blocked, func(degraded bool) {
			live := liveExecutionCapability(execution, degraded)
			_ = recordExecutionCapability(ctx, session, live, stderrNoticeRenderer{w: stderr})
			m, _ := modeActive.Current()
			stderr.line(live.SandboxLabel(string(m)))
		})
		defer stopDelivery()
	}
	for _, line := range bigBlockedEntryWarnings(result.Home, blockedEntries, guard.Blocked.FoldCase()) {
		_, _ = fmt.Fprintln(stderr, line)
	}
	for _, line := range skillLines {
		stderr.line(line)
	}
	inherited, _ := runner.InheritedEnvironment(os.Environ())
	conf := launchConfinement(execution, tmpDir, modeActive, cache, result.Home, guard, inherited)
	systemOne := newSystemOneCheck(cache, guard.Blocked)
	registry, err := realizeToolRegistry(result.ToolRegistry, cache, storeAccessor, result.Home, result.LaunchDir, guard,
		generalAgentBinding{parent: generalAgentParent, notices: stderrNoticeRenderer{w: stderr}, confinement: conf, systemOne: systemOne})
	if err != nil {
		return fmt.Errorf("bootstrap: headless build tool registry: %w", err)
	}

	// --prompt-for-approval: bind the terminal prompt so a call that would be
	// denied instead asks the user; without it the authorizer stays fail-closed.
	var terminal *terminalPrompter
	if d.promptForApproval {
		terminal = newTerminalPrompter(d.stdin, d.stderr)
		terminal.out = stderr
		terminal.disclosure = resolveTerminalDisclosure(cache, result.LaunchDir)
		terminal.projectUntrusted = !result.TrustDecision.Trusted
		terminal.home = result.Home
	}
	authorizer := newHeadlessAuthorizer(cache, storeAccessor, modeActive, terminal, stderrNoticeRenderer{w: stderr})
	authorizer.declaredWrite = declaredWrite
	authorizer.declaredDelete = declaredDelete
	authorizer.executionConstrained = execution.SelfTestPassed
	authorizer.blocked = guard.Blocked
	authorizer.systemOne = systemOne
	d.authorizer = authorizer

	dispatcher := newProductionToolDispatcher(registry, newShellRunner(), authorizer, result.Home, result.LaunchDir, storeAccessor, cache.MaxToolOutputBytes(), guard)
	dispatcher.confinement = conf
	dispatcher.setWebFetch(cache.WebResearch())
	assembleTools := newToolAdvertiser(registry, modeActive)
	var toolDispatcher turn.ToolDispatcher = dispatcher
	if d.experiment != nil {
		extended, expErr := headlessExperimentAdvertiser(assembleTools, d.experiment.ExtraTools)
		if expErr != nil {
			return expErr
		}
		assembleTools = extended
		toolDispatcher = newHeadlessExperimentDispatcher(dispatcher, *d.experiment)
	}
	// Gate last. headlessExperimentAdvertiser calls its base eagerly to build the
	// collision map, so gating first would have it check experiment names against a
	// possibly-nil shipped surface and accept a name that collides.
	assembleTools = newCapabilityGatedToolAdvertiser(assembleTools, cache, active)
	surface := newHeadlessSurface(d.stdout, stderr)
	var timeLimit time.Duration
	surface.deadline, timeLimit = d.TimeLimit()

	// Pre-turn durability: the user message is made durable before any provider
	// request, then the turn is dispatched on the successful flush.
	// Resolve the dev-debug gate (the --dev-debug flag ORed with CODEMELD_DEV_DEBUG)
	// and snapshot the active mode so the turn records its suggest_followup trace. The
	// headless surface has no ghost text, so only the turn-side stages are emitted here.
	devDebug := devDebugEnabled(d.devDebug)
	modeKey, _ := modeActive.Current()
	persister := sessionturn.New(session, turnNoticeRenderer{surface: surface})
	runErr := persister.PersistUserInputThenIssue(ctx, d.prompt, nil, func(submitStart time.Time) error {
		return runHeadlessTurn(ctx, session, cache, active, surface, toolDispatcher, assemblePrompt, assembleTools, result.Home, submitStart, devDebug, string(modeKey), generalAgentParent)
	})
	stopDelivery()

	// Final durability boundary (Step 7): a Ctrl-C cancel still persists the session so
	// the run is resumable. WithoutCancel detaches the flush from the (possibly
	// cancelled) run context so the durability write is not itself cancelled. This is the
	// last chance to persist a pre-turn user message the cancellation kept the pre-turn
	// boundary from flushing, so a failed final flush must surface — never be masked by
	// the cancel-to-clean conversion below — or the CLI would exit 0 on a run that is not
	// durably resumable.
	cat, reason, flushErr := session.Flush(context.WithoutCancel(ctx))
	if flushErr != nil && reason != sessions.ReasonNone {
		// A real atomic-write failure runs the protocol (records carry forward
		// the one-line notice renders to stderr); join the handler's own failure if it
		// too cannot persist.
		if herr := sessionfailures.HandleWriteFailure(reason, cat, session.Path(), flushErr, session, turnNoticeRenderer{surface: surface}); herr != nil {
			flushErr = errors.Join(flushErr, herr)
		}
	}

	if runErr == nil && flushErr == nil && surface.turnCompleted && !surface.timeLimitReached && ctx.Err() == nil && d.SessionTitle() == "" {
		storeHeadlessModelTitle(ctx, session, surface, cache.SelectableCatalog().SupportedEffort)
	}

	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			// A clean interrupt only when the final flush actually persisted; otherwise
			// the durability failure surfaces instead of a falsely-clean canceled run.
			return flushErr
		}
		return runErr
	}
	if flushErr == nil && surface.timeLimitReached {
		_, _ = fmt.Fprintf(stderr, "codemeld: time limit %s reached; the run ended with a final answer and no further tool use\n", timeLimit)
	}
	return flushErr
}

const headlessTitleTimeout = 20 * time.Second

func storeHeadlessModelTitle(ctx context.Context, session *sessions.Store, surface *headlessSurface, supportedEffort func(providerID, modelID string) []string) {
	firstUser, firstAssistant, ok := firstTurnTitleInputs(session)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, headlessTitleTimeout)
	defer cancel()
	title := turn.GenerateTitle(ctx, surface.turnClient, surface.turnSel, firstUser, firstAssistant, supportedEffort)
	if title == "" {
		return
	}
	_, _, _ = session.FlushGeneratedTitle(ctx, title)
}

// runHeadlessTurn builds and runs the single agentic tool-call loop for one accepted
// prompt: it snapshots the active model, resolves the provider's credential source
// from the selectable catalog, builds the provider client through the shared
// buildTurnClient, assembles the per-turn system prompt and advertised tools, and runs
// turn.NewToolLoop to a final answer. A run with no resolvable model issues no turn
// (the picker-required case is converted to exit 2 in RunHeadless before this runs).
//
// generalAgentParent, when bound, is the run-scoped holder the registry's general_agent binding reads
// a child's inherited parent from; RunHeadless passes the same instance it bound there.
func runHeadlessTurn(ctx context.Context, session *sessions.Store, cache *config.Cache, active *model.ActiveState, surface *headlessSurface, dispatcher turn.ToolDispatcher, assemblePrompt func() string, assembleTools func() []provider.ToolDefinition, home string, submitStart time.Time, devDebug bool, modeName string, generalAgentParent ...*parentTurnHolder) error {
	sel, source, ok := active.Current()
	if !ok {
		return nil
	}
	catalogEntry, ok := cache.SelectableCatalog().Entry(sel.Provider)
	if !ok {
		return nil
	}
	client, ok := buildTurnClient(sel.Provider, catalogEntry.AuthKind, cache, openaiauth.NewFlow(), SettingsPath(home))
	if !ok {
		return nil
	}

	// Per-turn snapshot so the turn reads a copy, not the run-scoped active state.
	snapshot := model.NewActiveState(&sel, source)
	systemPrompt := assemblePrompt()

	// Publish the very values this turn's Deps carry, before the loop can dispatch a general_agent
	// call, so the child's inherited parent cannot drift from the turn that emitted the call.
	if len(generalAgentParent) > 0 {
		generalAgentParent[0].publish(sel, source, modeName, systemPrompt)
	}

	flush := headlessFlushHook(ctx, session, surface)
	deps := turn.Deps{
		Active:               snapshot,
		Store:                session,
		Client:               client,
		SubmitStart:          submitStart,
		SystemPrompt:         systemPrompt,
		Tools:                assembleTools(),
		SuggestFollowupDebug: devDebug,
		Mode:                 modeName,
		Sink:                 surface.AppendStreamDelta,
		OnToolActivity:       surface.AppendToolActivity,
		SealPartial:          surface.sealToolRoundReply,
		SuggestFollowup:      surface.SuggestFollowup,
		Flush:                flush,
		FlushUnsupported:     flush,
		SupportedEffort:      cache.SelectableCatalog().SupportedEffort,
		Notice:               surface.CommitProviderError,
		ToolNotice:           surface.CommitProviderError,
		RenderNotice:         tui.RenderProviderRequestFailedNotice,
		RenderRetryNotice:    tui.RenderProviderRequestFailedAfterAttemptsNotice,
		Interrupt:            surface.MarkStreamInterrupted,
		Finalize:             surface.FinalizeStream,
		FinalizeErr:          surface.writeError,
		OnFailureWrite:       headlessOnFailureWrite(session, surface),
		Retry:                retryPolicy(cache.ProviderRetry()),
		RetryBackoff:         surface.ShowRetryBackoff,
		RetryResume:          surface.ResumeRetry,
		RetryRecovered:       surface.CommitRetryRecovered,
		RollbackPartial:      surface.RollbackPartial,

		IgnoredProviders:      &turn.IgnoredProviders{},
		ProviderIgnoredNotice: surface.CommitProviderError,
	}
	loop := newToolLoop(deps, dispatcher, cache.AgentMaxConcurrency())
	loop.SetDeadline(surface.deadline)
	recordsBefore := len(session.Records())
	err := loop.Run(ctx)
	surface.timeLimitReached = err == nil && loop.TimeLimitReached()
	surface.turnCompleted = err == nil && !loop.Denied() && lastTurnOutcome(session.Records()[recordsBefore:]) == events.TurnOutcomeCompleted
	surface.turnClient, surface.turnSel = client, sel
	return err
}

func lastTurnOutcome(records []sessions.Record) string {
	outcome := ""
	for _, r := range records {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindTurnTerminal {
			continue
		}
		var p events.TurnTerminal
		if json.Unmarshal(ev.Payload, &p) == nil {
			outcome = p.Outcome
		}
	}
	return outcome
}

// headlessFlushHook builds the turn's flush hook for a headless run, mirroring
// turnController.flushStore: an atomic-write failure routes the per-turn
// protocol through sessionfailures.HandleWriteFailure (records carry forward, the
// one-line notice renders to stderr) and the error is still returned so the runtime
// refuses to cross the durability boundary. A non-atomic flush failure (ReasonNone) is
// returned unrouted.
func headlessFlushHook(ctx context.Context, store *sessions.Store, surface turnSurface) turn.FlushHook {
	return func() error {
		cat, reason, err := store.Flush(ctx)
		if err == nil {
			return nil
		}
		if reason != sessions.ReasonNone {
			if herr := sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, turnNoticeRenderer{surface: surface}); herr != nil {
				return errors.Join(err, herr)
			}
		}
		return err
	}
}

// headlessOnFailureWrite builds the provider_request_failed write-failure handler for
// a headless run, mirroring turnController.onProviderFailureWrite: a real atomic-write
// failure on that event's own flush runs the protocol and surfaces the
// one-line notice to stderr.
func headlessOnFailureWrite(store *sessions.Store, surface turnSurface) events.WriteFailureHandler {
	return func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		_ = sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, turnNoticeRenderer{surface: surface})
	}
}

type headlessStderr struct {
	mu           sync.Mutex
	w            io.Writer
	unterminated bool
}

func (s *headlessStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(p)
}

func (s *headlessStderr) write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.unterminated = p[n-1] != '\n'
	}
	return n, err
}

// line starts on a fresh line because a terminal prompt leaves its "choose" question unterminated while it waits on stdin.
func (s *headlessStderr) line(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unterminated {
		text = "\n" + text
	}
	_, _ = s.write([]byte(text + "\n"))
}

func deliverCapabilityChanges(blocked *permissions.BlockedPaths, record func(degraded bool)) (stop func()) {
	var mu sync.Mutex
	var transitions []bool
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	finished := make(chan struct{})
	blocked.SetOnDegradedChange(func(degraded bool) {
		mu.Lock()
		transitions = append(transitions, degraded)
		mu.Unlock()
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	recordQueued := func() {
		mu.Lock()
		pending := transitions
		transitions = nil
		mu.Unlock()
		for _, degraded := range pending {
			record(degraded)
		}
	}
	go func() {
		defer close(finished)
		defer recordQueued()
		for {
			select {
			case <-done:
				return
			case <-wake:
				recordQueued()
			}
		}
	}()
	return sync.OnceFunc(func() {
		blocked.SetOnDegradedChange(nil)
		close(done)
		<-finished
	})
}

// Streamed text is held in reply until the round commits, so an auto-retried partial
// stream_drop can be discarded by RollbackPartial before any of it is written.
type headlessSurface struct {
	stdout   io.Writer
	stderr   io.Writer
	reply    []byte
	writeErr error

	deadline         time.Time
	timeLimitReached bool

	turnCompleted bool
	turnClient    provider.Client
	turnSel       model.Selection
}

func newHeadlessSurface(stdout, stderr io.Writer) *headlessSurface {
	return &headlessSurface{stdout: stdout, stderr: stderr}
}

func (s *headlessSurface) AppendStreamDelta(delta string) { s.reply = append(s.reply, delta...) }

func (s *headlessSurface) flushReply() {
	if len(s.reply) == 0 {
		return
	}
	s.write(s.reply)
	s.reply = s.reply[:0]
}

func (s *headlessSurface) sealToolRoundReply() {
	if len(s.reply) == 0 {
		return
	}
	if s.reply[len(s.reply)-1] != '\n' {
		s.reply = append(s.reply, '\n')
	}
	_, _ = s.stderr.Write(s.reply)
	s.reply = s.reply[:0]
}

func (s *headlessSurface) write(b []byte) {
	n, err := s.stdout.Write(b)
	if err == nil && n < len(b) {
		err = io.ErrShortWrite
	}
	if s.writeErr == nil && err != nil {
		s.writeErr = fmt.Errorf("bootstrap: write the reply to stdout: %w", err)
	}
}

func (s *headlessSurface) writeError() error { return s.writeErr }

func (s *headlessSurface) FinalizeStream() {
	s.flushReply()
	s.write([]byte("\n"))
}

func (s *headlessSurface) MarkStreamInterrupted() {
	s.flushReply()
	s.write([]byte("\n"))
}

func (s *headlessSurface) AppendToolActivity(lines []string) {
	if len(lines) == 0 {
		return
	}
	// Under a time limit the loop seals the preamble after dispatch instead, so a deadline
	// reached while the tools run can still discard it.
	if s.deadline.IsZero() {
		s.sealToolRoundReply()
	}
	for _, line := range lines {
		_, _ = fmt.Fprintln(s.stderr, line)
	}
}

func (s *headlessSurface) CommitProviderError(text string)          { _, _ = fmt.Fprintln(s.stderr, text) }
func (s *headlessSurface) NoticeFromBackground(text string)         { _, _ = fmt.Fprintln(s.stderr, text) }
func (s *headlessSurface) ShowIndicator(int64, int64)               {}
func (s *headlessSurface) SetIndicatorTokens(int64, int64)          {}
func (s *headlessSurface) ClearIndicator()                          {}
func (s *headlessSurface) TurnEnded(string)                         {}
func (s *headlessSurface) SeedNextIndicatorStart(time.Time)         {}
func (s *headlessSurface) AppendCompletionFooter([]sessions.Record) {}
func (s *headlessSurface) SuggestFollowup(string, string)           {}
func (s *headlessSurface) ShowRetryBackoff(int, int)                {}
func (s *headlessSurface) ResumeRetry()                             {}
func (s *headlessSurface) SetProviderIdle(string, time.Duration)    {}
func (s *headlessSurface) CommitRetryRecovered(int)                 {}

func (s *headlessSurface) RollbackPartial() { s.reply = s.reply[:0] }

var _ turnSurface = (*headlessSurface)(nil)

// headlessAuthorizer is the fail-closed dispatch.Authorizer for a headless run. It
// drives permissions.Authorize for every tool/shell check exactly as the production
// authorizer does — overlaying the run's active mode and project root so the mode
// posture (read-only auto-allow in every mode, Plan's mutating deny, Auto edits'
// in-scope edit allow) is honored, and emitting the permission events to the
// session — but binds a default-deny prompt: any call that reaches the prompt (no
// grant, no cache, no mode auto-allow) is refused in-band with the synthetic deny
// envelope, never executed. It records terminal user denials (the prompt-denied default)
// for the run's fail-closed summary, but not Plan/mode-posture denials — those are
// recoverable (the turn loop re-issues them) and grant instructions would not authorize
// them while the run stays in Plan, so surfacing them as no-approval denials would mislead.
type headlessAuthorizer struct {
	grants *syncGrants
	// inflight serializes concurrent *identical* authorizations by request identity, exactly as
	// productionAuthorizer does. The shared grant table/turn cache (syncGrants) is race-safe per
	// seam call, but the match → cache-miss → prompt → record sequence is not atomic, so two
	// identical concurrent checks could both miss the grant/cache and queue duplicate terminal
	// prompts before either recorded its outcome. With only one terminal answer available under
	// --prompt-for-approval, the second prompt would then read EOF and deny instead of observing
	// the first's recorded allow-for-this-session grant. Holding this per-identity lock across the
	// whole authorization makes the second request re-run matching only after the first records
	// its outcome, so it short-circuits on that grant/cache hit; distinct requests stay parallel.
	inflight           *keyedMutex
	activeStore        func() *sessions.Store
	projectRoot        string
	modeActive         *mode.ActiveState
	denyEnvelope       string
	terminal           *terminalPrompter
	folderSettingsPath string
	localSettingsPath  string
	notices            tui.NoticeRenderer
	declaredCommands   []permissions.DeclaredCommand
	declaredWrite      map[string]bool
	declaredDelete     map[string]bool
	childAgent         bool
	// childInvocationID attributes the permission events this authorizer emits to the child
	// agent whose calls it is judging; it is empty for the run's own top-level calls.
	childInvocationID    string
	generalAgentWrite    map[string]bool
	generalAgentResolved bool
	executionConstrained bool
	writable             *writableFoldersReader
	blocked              *permissions.BlockedPaths
	systemOne            *systemOneCheck
	localNotice          sync.Once

	mu       sync.Mutex
	seen     map[DeniedCall]bool
	denied   []DeniedCall
	refusals map[any]int
}

var _ dispatch.Authorizer = (*headlessAuthorizer)(nil)

var newShellRunner = func() runner.Runner { return runner.DirectExecRunner{} }

// wouldCreateSettingsFile is resolved here, at assembly, because the run itself can create
// the settings file later and the notice it gates describes the state before that write.
func resolveTerminalDisclosure(cache *config.Cache, launchDir string) terminalDisclosure {
	folderSettings := filepath.Join(cache.ProjectRoot(), ".codemeld", "settings.yaml")
	_, statErr := os.Stat(folderSettings)
	return terminalDisclosure{
		projectRoot:             cache.ProjectRoot(),
		launchDir:               launchDir,
		boundary:                cache.Discovery(),
		folderSettingsPath:      folderSettings,
		wouldCreateSettingsFile: errors.Is(statErr, fs.ErrNotExist),
	}
}

func newHeadlessAuthorizer(cache *config.Cache, activeStore func() *sessions.Store, modeActive *mode.ActiveState, terminal *terminalPrompter, notices tui.NoticeRenderer) *headlessAuthorizer {
	return &headlessAuthorizer{
		grants:             &syncGrants{cache: cache, turn: permissions.NewTurnCache()},
		inflight:           newKeyedMutex(),
		activeStore:        activeStore,
		projectRoot:        cache.ProjectRoot(),
		modeActive:         modeActive,
		denyEnvelope:       permissions.BuildDenyEnvelope(headlessDenyReason),
		terminal:           terminal,
		folderSettingsPath: filepath.Join(cache.ProjectRoot(), ".codemeld", "settings.yaml"),
		localSettingsPath:  config.LocalSettingsPath(cache.ProjectRoot()),
		notices:            notices,
		declaredCommands:   cache.DeclaredCommands(),
		writable:           newWritableFoldersReader(cache),
		seen:               map[DeniedCall]bool{},
		refusals:           map[any]int{},
	}
}

// Authorize drives one permission check through permissions.Authorize with the
// default-deny prompt. It first takes the per-identity in-flight lock so two concurrent
// identical requests serialize (the second re-runs matching only after the first records
// its grant/cache outcome, short-circuiting on it instead of queuing a duplicate terminal
// prompt — see the inflight field), then overlays the active mode and project root onto the
// mode-auth context (exactly as authdeps.go does), binds the session-bound event emitters and
// the shared grant table/turn cache, and after the decision records the denial for the run's
// summary (Architecture Review). Plan/mode-posture denials carry a "mode" deny envelope and are
// excluded: a grant would not have changed them, so the no-approval summary must not claim them
// or suggest a grant that Plan would still ignore.
func (a *headlessAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, disp dispatch.PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	release, err := a.inflight.acquire(ctx, inflightKeyOf(req))
	if err != nil {
		return permissions.Decision{}, err
	}
	defer release()
	identity := permissions.CacheIdentity(req)

	if m, ok := callMode(ctx, a.modeActive); ok {
		modeCtx.Mode = m
	}
	modeCtx.ProjectRoot = a.projectRoot
	modeCtx.DeclaredCommands = a.declaredCommands
	modeCtx.DeclaredWrite = a.declaredWrite
	modeCtx.DeclaredDelete = a.declaredDelete
	modeCtx.ChildAgent = a.childAgent
	modeCtx.ChildInvocationID = a.childInvocationID
	modeCtx.ExecutionConstrained = a.executionConstrained
	modeCtx.SettingsBroken = a.executionConstrained && a.blocked.Current().Degraded()
	modeCtx.WritableFolders = liveWritableFolders(a.executionConstrained, modeCtx.SettingsBroken, a.writable)
	// A prepared general_agent call already carries the exact candidate its child would be built from.
	if !modeCtx.GeneralAgentResolved && !modeCtx.GeneralAgentRefused && len(modeCtx.GeneralAgentWrite) == 0 {
		modeCtx.GeneralAgentWrite = a.generalAgentWrite
		modeCtx.GeneralAgentResolved = a.generalAgentResolved
	}
	texts := systemOneLiteralTexts{}
	texts.add(req, disp.Subject)
	disp = markExceptional(disp, req, modeCtx)
	noApprover := headlessDenyReason
	if disp.ExceptionalAuthority != "" {
		noApprover = "no approval available in non-interactive run mode for an exceptional action that adds " + disp.ExceptionalAuthority
	}

	store := a.activeStore()
	var note string
	prompt := a.promptFor(req, disp)
	if a.terminal == nil {
		prompt = func(ctx context.Context, esc permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
			note = esc.Note
			return a.denyPrompt(ctx, esc)
		}
	}
	deps := permissions.AuthorizeDeps{
		Grants:         a.grants,
		Cache:          a.grants,
		Prompt:         prompt,
		PersistGrant:   a.persistGrant(store, req.PathScope),
		PrePromptCheck: a.systemOne.bind(store, texts),
		EmitPromptShown: func(subjectKind, subject, pathScope string, directTokens []string, id permissions.DirectIdentity) error {
			return events.EmitPromptShownAttributed(store, subjectKind, subject, pathScope, directTokens, id.CommandSubject, id.RequestSubject, a.childInvocationID)
		},
		EmitDecision: func(subjectKind, subject, pathScope, outcome, grantKind, grantPathScope string, id permissions.DirectIdentity) error {
			return events.EmitDecisionAttributed(store, subjectKind, subject, pathScope, outcome, grantKind, grantPathScope, id.CommandSubject, id.RequestSubject, a.childInvocationID)
		},
		EmitDecisionGrant: func(subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject string, id permissions.DirectIdentity) error {
			return events.EmitDecisionGrantAttributed(store, subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject, id.CommandSubject, id.RequestSubject, a.childInvocationID)
		},
		EmitMatched: func(subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject string) error {
			return events.EmitMatchedIdentityAttributed(store, subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject, a.childInvocationID)
		},
	}
	if a.terminal != nil {
		deps.EmitPromptWait = promptWaitEmitter(store)
	}
	dec, err := permissions.Authorize(ctx, req, modeCtx, deps)
	if err != nil {
		return dec, err
	}
	if dec.DenyEnvelope == "" || permissions.IsModeDenyEnvelope(dec.DenyEnvelope) {
		return dec, nil
	}
	// Recorded before the conversion below, because IsModeDenyEnvelope accepts an unattended
	// envelope and the summary would then skip the denial it exists to report.
	a.recordDenied(DeniedCall{
		Subject:          deniedSubjectLabel(disp, req),
		Reason:           a.denialReason(dec, noApprover),
		Source:           dec.DenialSource,
		Exceptional:      disp.ExceptionalAuthority != "",
		TerminalApprover: a.terminal != nil,
	})
	if a.terminal != nil {
		return dec, nil
	}
	reason := a.unattendedReason(dec, noApprover)
	hint := reason == headlessDenyReason
	if note != "" {
		reason += "; " + note
	}
	if hint && (req.Kind == matchKindDirect || req.Kind == matchKindLiteral) {
		reason += " " + headlessReadOnlyHint
		if advice, ok := shellToolAdvice(disp.Subject); ok {
			reason += " " + advice + "."
		}
	}
	dec.DenyEnvelope = permissions.BuildUnattendedDenyEnvelope(reason)
	refusals := a.countRefusal(identity)
	dec.WrapUp = refusals >= maxRefusalsPerCall
	if refusals == maxRefusalsPerCall {
		a.notices.Notice(fmt.Sprintf("codemeld: %s was refused %d times; the run ended with a final answer and no further tool use",
			refusedCallLabel(disp, req), maxRefusalsPerCall))
	}
	return dec, nil
}

// countRefusal counts per turn-cache identity because an identical repeat is answered from that
// cache without reaching denyPrompt.
func (a *headlessAuthorizer) countRefusal(identity any) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refusals[identity]++
	return a.refusals[identity]
}

// unattendedReason keeps a policy reason that names the rule the call broke, and otherwise states
// the run's own no-approver refusal. dec.DenyReason is not usable directly: a turn-cache hit
// replays the permission layer's user-refusal default, which would contradict denied_by.
func (a *headlessAuthorizer) unattendedReason(dec permissions.Decision, noApprover string) string {
	if dec.DenialSource == permissions.OutcomeSourceDeclaredScope {
		return dec.DenyReason
	}
	return noApprover
}

// denialReason prefers the reason the permission layer decided, and falls back to the run's own
// fail-closed reason only when this authorizer's default-deny closure is the one that refused.
func (a *headlessAuthorizer) denialReason(dec permissions.Decision, noApprover string) string {
	if dec.DenyReason != "" {
		return dec.DenyReason
	}
	if a.terminal == nil {
		return noApprover
	}
	return ""
}

// promptFor builds the permissions.AuthorizeDeps.Prompt closure for one authorization. With
// --prompt-for-approval (terminal set) it returns the terminal prompt bound to this
// request and its display payload, so the call pauses and asks the user; otherwise it returns
// the default-deny closure. The selection is per-call so the run's posture (escalate vs
// fail-closed) is honored uniformly for every tool/shell check.
func (a *headlessAuthorizer) promptFor(req permissions.MatchRequest, disp dispatch.PromptDisplay) func(context.Context, permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
	if a.terminal != nil {
		return a.terminal.build(req, disp)
	}
	return a.denyPrompt
}

func (a *headlessAuthorizer) persistGrant(store *sessions.Store, requestPath string) func(permissions.PermissionEntry) (permissions.PermissionEntry, error) {
	return func(entry permissions.PermissionEntry) (permissions.PermissionEntry, error) {
		if entry.GrantKind != folderGrantKind && entry.GrantKind != projectGrantKind {
			return permissions.DegradeGrant(entry, requestPath),
				fmt.Errorf("bootstrap: a headless run cannot persist a %s grant", entry.GrantKind)
		}
		persisted, created, err := permissionpersist.PersistGrantReportingCreate(
			store, a.notices, a.localSettingsPath, requestPath, entry)
		if created {
			a.announceLocalSettings()
		}
		return persisted, err
	}
}

// announceLocalSettings gates on a run-local Once because the created report is derived from a
// stat taken outside the write lock, so two concurrent approvals can both report the creation.
func (a *headlessAuthorizer) announceLocalSettings() {
	a.localNotice.Do(func() {
		a.notices.Notice(tui.RenderLocalSettingsIgnoreNotice(
			a.localSettingsPath, config.LocalSettingsLockPath(a.projectRoot)))
	})
}

// denyPrompt is the default-deny prompt closure: with no interactive approver and no
// --prompt-for-approval, every call that reaches the prompt is refused with the run-mode deny
// envelope. It ignores the display-only scope-escalation signal (a fail-closed deny needs no
// warning) and never blocks or errors.
func (a *headlessAuthorizer) denyPrompt(context.Context, permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
	return permissions.PromptOutcome{Choice: permissions.PromptDeny, DenyEnvelope: a.denyEnvelope}, nil
}

// recordDenied keeps one entry per distinct denial, keyed on the whole record rather than the
// subject label: the summary's advice is chosen from the reason and source, so two denials sharing
// a label but differing in either are materially different refusals and both must survive.
func (a *headlessAuthorizer) recordDenied(call DeniedCall) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen[call] {
		return
	}
	a.seen[call] = true
	a.denied = append(a.denied, call)
}

func (a *headlessAuthorizer) deniedSubjects() []DeniedCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.denied)
}

var ErrHeadlessExperiment = errors.New("bootstrap: invalid headless experiment binding")

type HeadlessExtraTool struct {
	Definition provider.ToolDefinition
	Handle     func(ctx context.Context, arguments string) (turn.ToolResult, error)
}

type HeadlessExperiment struct {
	ExtraTools []HeadlessExtraTool
	DenyCall   func(call turn.AssembledToolCall) (reason string, deny bool)
}

// A shipped-surface name collision is only visible once the registry is realized, so Run
// checks for one and fails there rather than here. intentional: no production caller by design —
// the only caller is the local E2 harness, and `codemeld run` keeps the shipped advertised set.
func (d *HeadlessDriver) EnableExperiment(exp HeadlessExperiment) error {
	declared := map[string]bool{}
	for _, extra := range exp.ExtraTools {
		name := extra.Definition.Name
		if name == "" || extra.Handle == nil {
			return fmt.Errorf("%w: every extra tool needs a name and a handler", ErrHeadlessExperiment)
		}
		if declared[name] {
			return fmt.Errorf("%w: %q is declared twice", ErrHeadlessExperiment, name)
		}
		declared[name] = true
	}
	d.experiment = &exp
	return nil
}

func headlessExperimentAdvertiser(base func() []provider.ToolDefinition, extras []HeadlessExtraTool) (func() []provider.ToolDefinition, error) {
	shipped := map[string]bool{}
	for _, def := range base() {
		shipped[def.Name] = true
	}
	for _, extra := range extras {
		if shipped[extra.Definition.Name] {
			return nil, fmt.Errorf("%w: %q is already advertised by the shipped surface", ErrHeadlessExperiment, extra.Definition.Name)
		}
	}
	return func() []provider.ToolDefinition {
		defs := base()
		for _, extra := range extras {
			defs = append(defs, extra.Definition)
		}
		slices.SortFunc(defs, func(a, b provider.ToolDefinition) int {
			return strings.Compare(a.Name, b.Name)
		})
		return defs
	}, nil
}

type headlessExperimentDispatcher struct {
	inner    turn.ToolDispatcher
	extras   map[string]func(context.Context, string) (turn.ToolResult, error)
	denyCall func(turn.AssembledToolCall) (string, bool)
}

var _ turn.ToolDispatcher = (*headlessExperimentDispatcher)(nil)

func newHeadlessExperimentDispatcher(inner turn.ToolDispatcher, exp HeadlessExperiment) *headlessExperimentDispatcher {
	extras := make(map[string]func(context.Context, string) (turn.ToolResult, error), len(exp.ExtraTools))
	for _, extra := range exp.ExtraTools {
		extras[extra.Definition.Name] = extra.Handle
	}
	return &headlessExperimentDispatcher{inner: inner, extras: extras, denyCall: exp.DenyCall}
}

// Plan rewraps the production plan rather than replacing it, so the deny gate still sees a call the
// production dispatcher would otherwise run through a prepared closure. An experiment name has no
// registry entry, so the production planner already made a serial barrier of it; substituting only
// that unit's Run keeps its dependencies, target, continuation, and pre-run guard, and so keeps the
// eligible segments on either side of the barrier concurrent.
func (d *headlessExperimentDispatcher) Plan(calls []turn.AssembledToolCall, maxConcurrency int) turn.ToolPlan {
	plan := d.inner.Plan(calls, maxConcurrency)
	for i := range plan.Units {
		call, run := plan.Units[i].Call, plan.Units[i].Run
		if handle, isExtra := d.extras[call.Name]; isExtra {
			run = func(ctx context.Context) (turn.ToolResult, error) { return handle(ctx, call.Arguments) }
		}
		plan.Units[i].Run = func(ctx context.Context) (turn.ToolResult, error) {
			if denied, gated := d.gate(call); gated {
				return denied, nil
			}
			return run(ctx)
		}
	}
	return plan
}

func (d *headlessExperimentDispatcher) Dispatch(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	if denied, gated := d.gate(call); gated {
		return denied, nil
	}
	if handle, isExtra := d.extras[call.Name]; isExtra {
		return handle(ctx, call.Arguments)
	}
	return d.inner.Dispatch(ctx, call)
}

// gate carries a mode deny envelope rather than a user one: the refusal is a fixed posture of
// the experiment run, and the turn loop treats a user denial as terminal, which would end the
// run at the first refused call instead of letting the model carry on with its other work.
func (d *headlessExperimentDispatcher) gate(call turn.AssembledToolCall) (turn.ToolResult, bool) {
	if d.denyCall == nil {
		return turn.ToolResult{}, false
	}
	reason, deny := d.denyCall(call)
	if !deny {
		return turn.ToolResult{}, false
	}
	return turn.ToolResult{Content: permissions.BuildModeDenyEnvelope(reason), Denied: true}, true
}

func deniedSubjectLabel(disp dispatch.PromptDisplay, req permissions.MatchRequest) string {
	if disp.Subject != "" {
		return disp.Subject
	}
	return req.Subject
}

func refusedCallLabel(disp dispatch.PromptDisplay, req permissions.MatchRequest) string {
	label := deniedSubjectLabel(disp, req)
	if req.Kind == matchKindHost {
		label += " (host " + req.Host + ")"
	}
	return label
}
