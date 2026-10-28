// Production step-8 launch: build the runtime command registry over the
// bootstrap result's session + model/config state, wire the registry-backed
// submit adapter (the first non-test caller of DispatchSlashInput), and run
// the tview event loop (bootstrap step 8).
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/sessionturn"
	"codemeld.dev/codemeld/internal/subagenttool"
	"codemeld.dev/codemeld/internal/systemone"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
)

// runApp is a seam over tui.App.Run so StartTUI's assembly can be exercised in a
// test without a real terminal event loop; production runs App.Run unchanged.
var runApp = func(a *tui.App) error { return a.Run() }

// permissionsCacheLister is the production tui.PermissionLister for /settings: it
// reads the run's stored grants through the same syncGrants mutex the authorizer uses
// for appends/removes, so an open cannot race scheduler-driven authorization mutating
// the grant table. syncGrants.Permissions returns a defensive clone (via
// Cache.Permissions), so each open reflects grants added earlier in the run.
type permissionsCacheLister struct{ grants *syncGrants }

func (l permissionsCacheLister) List() []permissions.PermissionEntry {
	return l.grants.Permissions()
}

// codemeldVersion is the build version the /status overlay and the launch banner
// report (item 1). It is hard-coded and bumped by hand on each
// release; a single source so the banner and /status never drift.
var codemeldVersion = "Alpha 0.4.7"

// discoveryLaunchDirOnly is the discovery.boundary value under which the
// per-project model.active write lands in the launch directory, so the cross-mode
// marker disclosure applies. config has no exported constant for it; this mirrors
// the literal the config and vcs packages compare against.
const discoveryLaunchDirOnly = "launch-dir-only"

// StartTUI is the step-8 launch. It narrows the bootstrap result's active
// session + composed config + run-scoped model state, assembles the production
// command registry through the shared tui.BuildRegistry builder (binding the real
// handlers that make /clear, /status, /effort, /model, /exit, and /resume reachable
// at runtime), wires the dispatch-backed submit adapter, and runs the event loop. It
// owns the submit-path wiring for the first five commands and /resume, the
// adapter and the injection point, not the provider turn loop: a plain prompt is
// routed through the pre-turn persistence and an as-yet-empty dispatch seam
// later tasks fill in. stdout carries the clean-exit resume hint.
//
// Missing upstream state degrades rather than panics: the model-determination,
// config-composition, and AGENTS.md steps are still bootstrap stubs owned by other
// tasks, so an absent active model yields a "no model selected" state and an absent
// config yields an empty cache. The wiring is real; the inputs fill in as those
// steps land.
func StartTUI(ctx context.Context, result *BootstrapResult, stdout io.Writer) (retErr error) {
	if result == nil || result.Session == nil {
		return fmt.Errorf("bootstrap: StartTUI requires an active session")
	}

	// Narrow the loosely-typed bootstrap fields to the concrete landed state StartTUI
	// consumes (BootstrapResult.Model is still `any`; Config is the composed map).
	active, ok := result.Model.(*model.ActiveState)
	if !ok || active == nil {
		active = model.NewActiveState(nil, "")
	}
	// Narrow the run-scoped interaction-mode state (step 7b2). Like the model state
	// it degrades rather than panics: an absent mode (a bootstrap path that did not
	// run InitMode, e.g. a test harness) falls back to the launch default so
	// /clear still has a mode to carry forward.
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
		return fmt.Errorf("bootstrap: StartTUI build config cache: %w", err)
	}
	execution := resolveExecutionCapability(enforce.ResolveInput{Home: result.Home})
	app := tui.New(nil)
	tmpDir, err := startExecutionCapability(execution, app)
	if err != nil {
		return fmt.Errorf("bootstrap: StartTUI create confinement temp folder: %w", err)
	}
	var conf *confinement
	defer func() {
		switch {
		case conf != nil:
			retErr = errors.Join(retErr, conf.cleanupAll())
		case tmpDir != "":
			retErr = errors.Join(retErr, removeSessionTempDir(tmpDir))
		}
	}()

	app.SetActiveStore(result.Session)
	app.SetCommandFlush(newCommandFlush(ctx, app))
	guard, err := protectedStatePolicy(result.Home, cache.ProjectRoot(), result.SettingsLayers)
	if err != nil {
		return fmt.Errorf("bootstrap: StartTUI build blocked paths: %w", err)
	}
	recorder := &capabilityRecorder{launch: execution, blocked: guard.Blocked}
	initialExecution := recorder.current()
	var recordTransition func(degraded bool, notices tui.NoticeRenderer)
	if execution.Capability == enforce.Constrained {
		recordTransition = func(degraded bool, notices tui.NoticeRenderer) {
			recorder.deliver(ctx, app, degraded, notices)
		}
	}
	stopBlockedDelivery := queueBlockedNotices(app, guard.Blocked, recordTransition)
	defer stopBlockedDelivery()
	if err := recordExecutionCapability(ctx, result.Session, initialExecution, app); err != nil {
		return fmt.Errorf("bootstrap: StartTUI record execution capability: %w", err)
	}
	// Pass the resolved home so the '@' file-reference picker can honor the
	// global ~/.codemeld/global/codemeldignore file; the project root reaches it
	// through the StatusState installed by SetStatusLineState below.
	app.SetHome(result.Home)

	// only a fresh launch kicks off the background retention prune, now that
	// the active store is installed to receive the summary. Every resume path leaves
	// BackgroundPrune false — pruning is fresh-launch-only — so a
	// resumed run never prunes.
	if result.BackgroundPrune {
		startBackgroundPrune(ctx, app, result.Home, composed)
	}

	skillLines := loadSkills(result, cache.AgentInstructionsMaxFileBytes())

	// Realize the production tool registry now that the config cache and turn-store
	// accessor exist: the step-6c factory registers vcs_<action> tools (when active VCS data is
	// present) with the run's output cap and an event appender bound to the submitted turn's store,
	// and always yields a non-nil registry — a launch with no VCS data degrades to a bare registry, not a
	// failure.
	toolEvents := &toolEventStore{}
	assemblePrompt := newSystemPromptAssembler(result, modeActive, active)
	// One run-scoped holder for both the general_agent binding below and the turn controller built
	// after it: registry realization precedes controller construction, so it has to exist here
	// for both sides to reference the same instance.
	generalAgentParent := &parentTurnHolder{}
	blockedEntries, err := blockedEntriesFromLayers(result.Home, result.SettingsLayers)
	if err != nil {
		return fmt.Errorf("bootstrap: StartTUI build blocked paths: %w", err)
	}
	inherited, _ := runner.InheritedEnvironment(os.Environ())
	conf = launchConfinement(execution, tmpDir, modeActive, cache, result.Home, guard, inherited)
	systemOne := newSystemOneCheck(cache, guard.Blocked)
	registry, err := realizeToolRegistry(result.ToolRegistry, cache, toolEvents.Active, result.Home, result.LaunchDir, guard,
		generalAgentBinding{parent: generalAgentParent, notices: app, confinement: conf, systemOne: systemOne})
	if err != nil {
		return fmt.Errorf("bootstrap: StartTUI build tool registry: %w", err)
	}

	// Assemble the production permission authorizer: one shared prompt gate and one
	// run-scoped turn cache behind permissions.Authorize, so real tool/shell dispatch and
	// scheduler workers authorize through a single gated, concurrency-safe path. The turn
	// controller holds it for the tool-call loop; the per-turn turn-cache Reset boundary is that
	// runtime's concern, not this assembly's.
	launchRows, err := launchPermissionRows(result.SettingsLayers)
	if err != nil {
		return fmt.Errorf("bootstrap: StartTUI build permission rows: %w", err)
	}
	layered := make([]permissions.PermissionEntry, len(launchRows))
	for i, row := range launchRows {
		layered[i] = row.Entry
	}
	cache.SetLayeredPermissions(layered)
	authorizer := newInteractiveAuthorizer(app, cache, result, modeActive)
	authorizer.executionConstrained = execution.SelfTestPassed
	authorizer.blocked = guard.Blocked
	authorizer.systemOne = systemOne
	for _, row := range launchRows {
		authorizer.grants.addRow(row)
	}
	assembleTools := newCapabilityGatedToolAdvertiser(newInteractiveToolAdvertiser(newToolAdvertiser(registry, modeActive)), cache, active)
	turnCtl := newTurnController(ctx, app, cache, active, assemblePrompt, authorizer)
	turnCtl.setToolEventStore(toolEvents)
	turnCtl.setGeneralAgentParent(generalAgentParent)
	// Bind the OpenAI ChatGPT session resolver and global settings path so a submitted
	// openai-chatgpt turn loads, proactively refreshes, and one-shot reactively refreshes
	// the stored session; other providers ignore it.
	chatgptAuth := openaiauth.NewFlow()
	turnCtl.setChatGPTAuth(chatgptAuth, SettingsPath(result.Home))
	// Bind the advertised-tool assembler now that the registry is realized so each
	// dispatch advertises the mode-filtered registry tools plus `bash` to the provider.
	turnCtl.setToolAdvertiser(assembleTools)
	// Bind the production dispatcher onto the controller so the tool-call loop routes `bash`
	// to DispatchShell and other structured names to DispatchTool through the shared authorizer, the
	// real runner, the registry, the turn-bound execution-event store, and the run's home/process cwd
	// (the launch cwd codemeld never leaves).
	dispatcher := newProductionToolDispatcher(registry, runner.DirectExecRunner{}, authorizer, result.Home, result.LaunchDir, toolEvents.Active, cache.MaxToolOutputBytes(), guard)
	dispatcher.confinement = conf
	dispatcher.setWebFetch(cache.WebResearch())
	dispatcher.setAskUser(app.AskQuestions)
	turnCtl.setToolDispatcher(dispatcher)
	app.SetStreamCanceller(turnCtl)
	// Arm the development-only suggest_followup trace when CODEMELD_DEV_DEBUG=1. The
	// interactive launch has no flag, so the gate is env-only here; the controller threads
	// it onto each turn's Deps and arms the TUI surface with the turn's provider/model/mode.
	turnCtl.setDevDebug(devDebugEnabled(false), func() string {
		m, _ := modeActive.Current()
		return string(m)
	}, app.SetFollowupDebugContext)
	turnCtl.setTurnCompleteHook(newTitleOnComplete(app, func(providerID, modelID string) []string {
		return cache.SelectableCatalog().SupportedEffort(providerID, modelID)
	}))
	turnCtl.setResponseObserver(newContextWindowNotice(app, cache))
	turnCtl.setUnsentHook(func(store *sessions.Store, unsent []turn.PendingUserMessage, outcome string) func() {
		recorded := 0
		if outcome != "completed" {
			for _, m := range unsent {
				if _, err := events.Append(store, events.QueuedPromptDiscarded{
					Text:       m.Text,
					ImageCount: int64(len(m.Parts)),
					Reason:     outcome,
				}); err != nil {
					break
				}
				recorded++
			}
		}
		return app.UserMessagesUnsent(store, len(unsent), recorded, outcome)
	})

	resumeLock := &resumeLockHolder{}
	if result.ResumeLockRelease != nil {
		resumeLock.handoff(result.ResumeLockRelease)
	}
	defer func() {
		stopBlockedDelivery()
		resumeLock.releaseHeld()
	}()
	// One run-scoped resume-lock holder shared across the session-lifetime paths so
	// the at-most-one resume lock is released when the run leaves a resumed
	// session through /clear, a clean /exit, a later /resume, or final TUI return.
	clearDeps := newClearDeps(ctx, app, result, active, modeActive, resumeLock, recorder, conf)
	resumeDeps := newResumeDeps(ctx, app, result, resumeLock, cache, active, recorder, conf)
	effortDeps := newEffortDeps(ctx, app, cache, active, result.Home)
	modelDeps := newModelDeps(ctx, app, cache, active, result.Home)
	modeDeps := newModeDeps(ctx, app, modeActive)
	exit := newExitController(ctx, app, stdout, resumeLock, turnCtl, stopBlockedDelivery)
	status := newStatusState(app, cache, active, result, execution)
	status.live = recorder.current
	contextSt := newContextState(app, cache, active)

	// Wire /clear's transcript reset now that statusState exists: after the session
	// swap, /clear wipes the visible pane and re-renders the launch banner for the fresh
	// session from this same statusState. Set here rather than inside
	// newClearDeps because the banner source is built at this point, not when the rest
	// of the /clear capabilities are assembled above.
	clearDeps.Transcript = clearTranscriptResetter{app: app, status: status, conf: conf}

	// Install the same statusState on the app so the persistent status-line footer
	// renders from the single source /status and the launch banner read.
	// This seeds the initial footer before the event loop starts; the model/effort
	// apply paths refresh it live afterwards through the deps' Refresh callbacks.
	app.SetStatusLineState(status)

	// Render the launch banner as the transcript's first content, before the
	// path-4 picker can open or the event loop starts accepting prompts, so
	// the banner is always the first lines a user sees. It re-presents statusState's
	// version, selection, and launch dir — the same single source /status reads.
	skillCommands, skillCommandWarnings := tui.SkillCommands(result.Skills.Loaded, tui.SkillDeps{Submit: app.SubmitLiteral, ReplaceEcho: app.ReplaceNextEcho})
	app.AppendBanner(bannerLines(status)...)
	for _, line := range bigBlockedEntryWarnings(result.Home, blockedEntries, guard.Blocked.FoldCase()) {
		app.Append(line)
	}
	for _, line := range skillLines {
		app.Append(line)
	}
	for _, line := range skillCommandWarnings {
		app.Append(line)
	}

	// On a cold-start resume, re-render the loaded session's prior conversation
	// into the transcript right after the banner and before the event loop runs, so the
	// user resumes into their visible history rather than an empty-looking pane. The
	// banner stays the first block deliberately (Step 5): replay appends after it. Fresh
	// launches leave ResumeReplay false and are unaffected. Run is not yet active, so
	// ReplaySessionRecords mutates the pane directly.
	if result.ResumeReplay {
		app.ReplaySessionRecords(result.Session.Records())
	}

	// Install the same effort deps the /effort registry uses on the app itself so
	// the CTRL-E picker can read the active model, list supported efforts
	// and apply through the shared non-slash path; without this App.effortDeps stays
	// zero-valued and CTRL-E is inert in production.
	app.SetEffortDeps(effortDeps)

	// Install the same mode deps the /mode registry uses on the app itself so the
	// shift+tab cycle key switches the run-scoped interaction mode through the
	// shared seam and updates the same persistent mode-hint row; without this
	// App.modeDeps stays zero-valued and shift+tab is inert in production.
	app.SetModeDeps(modeDeps)
	// Seed the persistent mode-hint row from the active interaction mode so it
	// shows the current mode before any switch (persistent for all modes). Subsequent
	// switches through /mode or shift+tab update it via the shared ModeDeps.Notify seam
	// (RefreshModeHint), the same way SetStatusLineState seeds the footer above.
	app.RefreshModeHint(modeDeps.Switcher.Current())

	// Install the provider-aware deps the CTRL-M model picker needs to
	// enumerate the provider×model cross-product, snapshot the settings-write target,
	// and apply through the shared non-slash path (switching providers).
	// Without this App.modelPickerDeps stays zero-valued and CTRL-M is
	// inert in production. Distinct from newModelDeps above, which is the model-only
	// model path and is left untouched.
	app.SetModelPickerDeps(newModelPickerDeps(ctx, app, cache, active, chatgptAuth, result.Home, result.LaunchDir))

	systemOneDeps := newSystemOneDeps(cache, func() string { return systemOne.status(app.ActiveStore()) })
	systemOneDeps.OpenPicker = app.OpenSystemOnePicker
	app.SetSystemOneDeps(systemOneDeps)

	// path 4: a selectable model exists but none was determined at launch, so
	// open the provider-aware picker now that its deps are installed. Carried as
	// an explicit launch flag rather than implied by an empty active state, which alone
	// only means "no active selection".
	if result.ModelPickerRequired {
		app.OpenModelPicker()
	}

	projectBlockedDestinations := guard.Blocked.ProjectRoot() != "" && result.TrustDecision.Trusted
	renameHandler := tui.NewRenameHandler(tui.RenameDeps{SetTitle: newRenameTitleWrite(ctx, app)})
	compact := &compactLease{}
	defer func() { retErr = errors.Join(retErr, compact.end()) }()
	entry := newPromptEntrypoint(ctx, app, turnCtl)
	app.SetLiteralPrompt(func(input string, imageParts ...sessions.ContentPart) bool {
		if compact.held() {
			app.Notice("compaction is running; your input was kept")
			return false
		}
		return entry(input, imageParts...)
	})
	reg := tui.MustNewRegistry(append(tui.BuildRegistry(map[string]tui.HandlerFunc{
		"status":   tui.NewStatusHandler(status),
		"context":  tui.NewContextHandler(contextSt),
		"effort":   tui.NewEffortHandler(effortDeps),
		"model":    tui.NewModelHandler(modelDeps),
		"mode":     tui.NewModeHandler(modeDeps),
		"exit":     tui.NewExitHandler(exit),
		"clear":    tui.NewClearHandler(clearDeps),
		"resume":   tui.NewResumeHandler(resumeDeps),
		"rename":   renameHandler,
		"color":    tui.NewColorHandler(tui.ColorDeps{Apply: app.ApplyInputAccent}),
		"fork":     tui.NewForkHandler(newForkDeps(ctx, app, result.Home, resumeLock, turnCtl, status, recorder, conf)),
		"compact":  tui.NewCompactHandler(newCompactDeps(ctx, app, cache, active, result.Home, resumeLock, turnCtl, status, compact, recorder, conf)),
		"connect":  tui.NewConnectHandler(newConnectDeps(app, result.Home, cache)),
		"settings": tui.NewSettingsHandler(newSettingsDeps(app, cache, active, authorizer)),
		"blocked": tui.NewBlockedHandler(tui.BlockedDeps{
			Rows:   func() []tui.BlockedRow { return blockedRows(guard.Blocked, result.Home, SettingsPath(result.Home)) },
			Picker: tui.NewBlockedPicker(app),
			Remove: func(row tui.BlockedRow) string {
				return removeBlockedEntry(guard.Blocked, result.Home, row)
			},
			Add:    func(row tui.BlockedRow) string { return addRecommendedEntry(result.Home, row) },
			AddAll: func(rows []tui.BlockedRow) string { return addAllRecommended(result.Home, rows) },
			AddPath: func(raw string, dest tui.BlockedDestination) string {
				return addUserEntry(guard.Blocked, result.Home, raw, dest, projectBlockedDestinations, cache.Discovery())
			},
			ProjectDestinationsAllowed: projectBlockedDestinations,
			Destinations:               tui.NewBlockedDestinationPresenter(app),
		}),
		"systemone": tui.NewSystemOneHandler(systemOneDeps),
		"skills":    tui.NewSkillsHandler(skillsView(result)),
	}).Commands(), skillCommands...))
	// Install the same registry on the app so Tab name-completion matches
	// the live command set the submit adapter dispatches through; without this
	// App.registry stays nil and Tab is inert in production.
	app.SetRegistry(reg)
	submit := tui.NewSubmitFunc(reg, app, entry)
	app.SetSubmit(func(input string, imageParts ...sessions.ContentPart) bool {
		if compact.held() {
			app.Notice("compaction is running; your input was kept")
			return false
		}
		return submit(input, imageParts...)
	})

	if err := runApp(app); err != nil {
		return fmt.Errorf("bootstrap: TUI run failed: %w", err)
	}
	return nil
}

var deliverBlockedNotice = func(app *tui.App, line string) { app.NoticeFromBackground(line) }

var spawnBlockedDelivery = func(f func()) { go f() }

type queuedNotice func(string)

func (q queuedNotice) Notice(text string) { q(text) }

func liveExecutionCapability(launch enforce.Resolution, degraded bool) enforce.Resolution {
	if launch.Capability != enforce.Constrained || !degraded {
		return launch
	}
	launch.Capability, launch.Reason = enforce.Refused, "settings file is broken"
	return launch
}

// Holding mu must never acquire the blocked-list lock or wait on the event loop: a refresh holds that lock while it enqueues, and the delivery worker records under mu.
type capabilityRecorder struct {
	mu      sync.Mutex
	launch  enforce.Resolution
	blocked *permissions.BlockedPaths
}

func (r *capabilityRecorder) refresh() {
	if r.launch.Capability == enforce.Constrained {
		r.blocked.Current()
	}
}

func (r *capabilityRecorder) cached() enforce.Resolution {
	return liveExecutionCapability(r.launch, r.blocked.Degraded())
}

func (r *capabilityRecorder) current() enforce.Resolution {
	if r.launch.Capability != enforce.Constrained {
		return r.launch
	}
	return liveExecutionCapability(r.launch, r.blocked.Current().Degraded())
}

func (r *capabilityRecorder) deliver(ctx context.Context, app *tui.App, degraded bool, notices tui.NoticeRenderer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if store := app.ActiveStore(); store != nil {
		_ = recordExecutionCapability(ctx, store, liveExecutionCapability(r.launch, degraded), notices)
	}
}

func (r *capabilityRecorder) activate(ctx context.Context, app *tui.App, target *sessions.Store, notices tui.NoticeRenderer) error {
	r.refresh()
	var held heldNotices
	r.mu.Lock()
	err := recordExecutionCapability(ctx, target, r.cached(), &held)
	if err == nil {
		app.SetActiveStore(target)
	}
	r.mu.Unlock()
	held.replay(notices)
	return err
}

func (r *capabilityRecorder) reconcile(ctx context.Context, app *tui.App, target *sessions.Store, recorded enforce.Resolution) heldNotices {
	r.refresh()
	var held heldNotices
	r.mu.Lock()
	if live := r.cached(); live.Capability != recorded.Capability || live.Reason != recorded.Reason {
		if err := recordExecutionCapability(ctx, target, live, &held); err != nil && len(held) == 0 {
			held.Notice(fmt.Sprintf("can't record the execution capability in %s: %v", target.Path(), err))
		}
	}
	app.SetActiveStore(target)
	r.mu.Unlock()
	return held
}

type heldNotices []string

func (h *heldNotices) Notice(text string) { *h = append(*h, text) }

func (h heldNotices) replay(notices tui.NoticeRenderer) {
	for _, line := range h {
		notices.Notice(line)
	}
}

// record must not wait on the event loop: /exit calls stop from it and stop records every queued transition.
func queueBlockedNotices(app *tui.App, blocked *permissions.BlockedPaths, record func(degraded bool, notices tui.NoticeRenderer)) (stop func()) {
	deliverNotice, spawn := deliverBlockedNotice, spawnBlockedDelivery
	var mu sync.Mutex
	var queued []string
	var transitions []bool
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	finished := make(chan struct{})
	signal := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	notice := queuedNotice(func(line string) {
		mu.Lock()
		queued = append(queued, line)
		mu.Unlock()
		signal()
	})
	blocked.SetNotice(notice)
	if record != nil {
		blocked.SetOnDegradedChange(func(degraded bool) {
			mu.Lock()
			transitions = append(transitions, degraded)
			mu.Unlock()
			signal()
		})
	}
	recordQueued := func() bool {
		mu.Lock()
		pending := transitions
		transitions = nil
		mu.Unlock()
		for _, degraded := range pending {
			record(degraded, notice)
		}
		return len(pending) > 0
	}
	await := func(deliver func()) bool {
		delivered := make(chan struct{})
		select {
		case <-done:
			return false
		default:
			spawn(func() {
				defer close(delivered)
				select {
				case <-done:
					return
				default:
				}
				deliver()
			})
		}
		select {
		case <-done:
			return false
		case <-delivered:
			return true
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
			}
			if recordQueued() && !await(app.RefreshStatusLineFromBackground) {
				return
			}
			mu.Lock()
			lines := queued
			queued = nil
			mu.Unlock()
			for _, line := range lines {
				if !await(func() { deliverNotice(app, line) }) {
					return
				}
			}
		}
	}()
	return sync.OnceFunc(func() {
		blocked.SetNotice(nil)
		blocked.SetOnDegradedChange(nil)
		close(done)
		<-finished
	})
}

const systemOneParentDirReason = "parent_dir_error: the settings file may have changed; this session's selection is unchanged"

func newSystemOneDeps(cache *config.Cache, status func() string) tui.SystemOneDeps {
	choices := make([]tui.SystemOneChoice, len(systemone.Models))
	for i, m := range systemone.Models {
		choices[i] = tui.SystemOneChoice{Name: m.Name, Provider: m.Provider, ModelID: m.ModelID}
	}
	return tui.SystemOneDeps{
		Current: cache.SystemOne,
		Set: func(name string) error {
			reason, _, err := cache.SetSystemOne(name)
			switch {
			case reason == config.ReasonParentDirError:
				return errors.New(systemOneParentDirReason)
			case reason != config.ReasonNone:
				return errors.New(string(reason))
			case err != nil:
				return errors.New(string(config.ReasonWriteError))
			}
			return nil
		},
		Choices: choices,
		HasKey: func(name string) bool {
			entry, ok := cache.Provider(name)
			return ok && entry.APIKey != ""
		},
		Status: status,
	}
}

var newSettingsDeps = func(app *tui.App, cache *config.Cache, active *model.ActiveState, authorizer *productionAuthorizer) tui.SettingsDeps {
	return tui.SettingsDeps{
		Lister: permissionsCacheLister{grants: authorizer.grants},
		Picker: tui.NewSettingsPicker(app, tui.OpenRouterSettings{
			Attribution: cache.Attribution,
			SetAttribution: func(on bool) error {
				_, _, err := cache.SetAttribution(on)
				return err
			},
			DataCollection: cache.OpenRouterDataCollection,
			SetDataCollection: func(v string) error {
				_, _, err := cache.SetOpenRouterDataCollection(v)
				return err
			},
			Sort: cache.OpenRouterSort,
			SetSort: func(v string) error {
				_, _, err := cache.SetOpenRouterSort(v)
				return err
			},
			MaxPrice: cache.OpenRouterMaxPrice,
			SetMaxPrice: func(model string, p provider.MaxPrice) error {
				_, _, err := cache.SetOpenRouterMaxPrice(model, p)
				return err
			},
			ActiveModel: func() (string, string) { return activeModelIDs(active) },
			SortEstimate: func(model, sortMode string, fetched func()) (provider.OpenRouterEstimate, bool) {
				entry, ok := cache.Provider("openrouter")
				if !ok {
					return provider.OpenRouterEstimate{}, false
				}
				authName, authValue := entry.ResolveAuthHeader()
				return openRouterEndpoints.Estimate(entry, authName, authValue, model, sortMode, fetched)
			},
		}, tui.SessionSettings{
			RetentionDays: cache.RetentionDays,
			SetRetentionDays: func(days int) error {
				_, _, err := cache.SetRetentionDays(days)
				return err
			},
		}),
		Rows: authorizer.grants.LayeredPermissions,
		// The /settings confirm runs on the event-loop goroutine, so revoke notices must
		// use app.Notice (renders directly) — the authorizer's background renderer would
		// deadlock on QueueUpdateDraw from that goroutine.
		Revoke:   func(row tui.PermissionRow) { authorizer.RevokeRow(row, app) },
		Share:    authorizer.ShareGrant,
		Approved: authorizer.display.projectApproved,
		Boundary: cache.Discovery(),
	}
}

func launchPermissionRows(layers []securitystate.LayerSnapshot) ([]tui.PermissionRow, error) {
	var rows []tui.PermissionRow
	for _, layer := range layers {
		if layer.Ignored {
			continue
		}
		kind := permissions.LayerKind(layer.Kind)
		entries, err := config.LayerPermissions(layer.Raw, kind)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			rows = append(rows, tui.PermissionRow{Entry: e, Layer: kind, Path: layer.Path})
		}
	}
	return rows, nil
}

// newInteractiveAuthorizer is the one interactive assembly of the run's authorizer: a fresh
// launch and a resume both reach it through StartTUI, so both carry the same run-fixed trust
// decision to every prompt.
func newInteractiveAuthorizer(app *tui.App, cache *config.Cache, result *BootstrapResult, modeActive *mode.ActiveState) *productionAuthorizer {
	authorizer := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), NewPromptGateBuilder(app), result.Home, result.LaunchDir, modeActive)
	authorizer.display.projectUntrusted = !result.TrustDecision.Trusted
	authorizer.display.projectApproved = vcsTemplatesApproved(result.TrustDecision)
	return authorizer
}

// newSystemPromptAssembler returns the per-turn system-prompt source the turn
// controller calls at dispatch. Each call reads the current run-scoped
// interaction mode and active model and assembles the active mode's base
// prompt, that model's special instructions, the environment block (today's date,
// the launch directory, the project root, and the detected VCS), the launch-loaded skills
// list, and the launch-loaded AGENTS.md instructions into the single synthetic system message.
// Reading the mode and model per call is what lets a /mode or /model switch take effect
// on the next turn rather than being frozen at startup; the date is read from the
// system clock (host local timezone) so it stays current across a long-running session,
// while staying day-granular and therefore prompt-cache stable.
func newSystemPromptAssembler(result *BootstrapResult, modeActive *mode.ActiveState, active *model.ActiveState) func() string {
	return func() string {
		m, _ := modeActive.Current()
		providerID, modelID := activeModelIDs(active)
		return assembleSystemMessageFrom(result, m, providerID, modelID, turnEnvironmentInputs(result))
	}
}

// activeModelIDs reads the run-scoped active model and returns the provider id and
// model id used to look up per-model special instructions, or empty strings when
// no model is selected yet (Current ok=false) so no special-instructions section is
// added.
func activeModelIDs(active *model.ActiveState) (providerID, modelID string) {
	sel, _, ok := active.Current()
	if !ok {
		return "", ""
	}
	return sel.Provider, sel.ID
}

// assembleSystemMessageFrom builds the system message for mode m and the active
// model (providerID, modelID) from an already-captured environment-input snapshot. It is
// the per-turn system-prompt assembler's single assembly point (fresh env per dispatch),
// producing the exact system-message bytes BuildRequest sends.
func assembleSystemMessageFrom(result *BootstrapResult, m mode.Mode, providerID, modelID string, env agentinstr.EnvironmentInputs) string {
	return agentinstr.AssembleSystemMessage(m, providerID, modelID, env, result.Skills.Loaded, result.AgentInstructions)
}

// turnEnvironmentInputs builds the environment-block inputs for one assembly:
// the system clock (host local timezone, rendered day-granular so the block stays
// prompt-cache stable), the launch directory, the project root, and the detected VCS
// name. It feeds the per-turn system-prompt assembler so each dispatch renders
// a fresh environment block.
func turnEnvironmentInputs(result *BootstrapResult) agentinstr.EnvironmentInputs {
	return agentinstr.EnvironmentInputs{
		Now:         time.Now(),
		WorkingDir:  result.LaunchDir,
		ProjectRoot: result.ProjectRoot,
		RepoRoot:    activeVCSRepoRoot(result.VCSTemplate),
		VCSName:     activeVCSName(result.VCSTemplate),
	}
}

// contextState is the production tui.ContextState. It reads the active provider/model
// from the run-scoped model state and the session's token records live from the active
// store — the same live sources /status reads — so /context reports current usage, not
// a startup copy.
type contextState struct {
	app    *tui.App
	cache  *config.Cache
	active *model.ActiveState
}

func newContextState(app *tui.App, cache *config.Cache, active *model.ActiveState) contextState {
	return contextState{app: app, cache: cache, active: active}
}

func (s contextState) Selection() (provider, modelID string) {
	sel, _, ok := s.active.Current()
	if !ok {
		return "", ""
	}
	return sel.Provider, sel.ID
}

func (s contextState) Records() []sessions.Record {
	store := s.app.ActiveStore()
	if store == nil {
		return nil
	}
	return store.Records()
}

// ContextWindow reports the active model's context-window size in tokens, or 0 when
// codemeld does not know it.
func (s contextState) ContextWindow() int64 {
	return s.cache.ContextWindow(s.Selection())
}

// newToolAdvertiser returns the per-turn advertised-tool source the turn controller
// calls at dispatch. Each call reads the current run-scoped interaction mode
// and assembles the mode-filtered set from the realized registry plus the
// product-authored `bash` definition. Reading the mode per call is what lets a /mode
// switch take effect on the next turn rather than being frozen at startup.
func newToolAdvertiser(registry *tools.Registry, modeActive *mode.ActiveState) func() []provider.ToolDefinition {
	return func() []provider.ToolDefinition {
		m, _ := modeActive.Current()
		return advertisedTools(registry, m)
	}
}

// This must wrap an already-completed advertiser: anything composed outside it —
// interactive `ask_user`, headless experiment tools — would slip past the zero-tool
// result. The two reads stay inside the closure so a mid-session model switch or
// discovery refresh takes effect on the next turn.
func newCapabilityGatedToolAdvertiser(base func() []provider.ToolDefinition, cache *config.Cache, active *model.ActiveState) func() []provider.ToolDefinition {
	return func() []provider.ToolDefinition {
		providerID, modelID := activeModelIDs(active)
		if !cache.SelectableCatalog().SupportsTools(providerID, modelID) {
			return nil
		}
		return base()
	}
}

func newInteractiveToolAdvertiser(base func() []provider.ToolDefinition) func() []provider.ToolDefinition {
	return func() []provider.ToolDefinition {
		defs := append(base(), provider.AskUserToolDefinition())
		slices.SortFunc(defs, func(a, b provider.ToolDefinition) int {
			return strings.Compare(a.Name, b.Name)
		})
		return defs
	}
}

// advertisedTools builds the mode-filtered advertised tool set for one turn.
// It enumerates the registry's tools (deterministic List, already
// name-sorted) and the product-authored `bash` definition, then sorts the whole set by
// name so the provider request body is stable regardless of where `bash` falls relative
// to the registry names. `bash` is advertised in
// every mode — its read/write intent is per-invocation, so Plan's shell
// restriction is enforced by posture, not at advertise time — and it carries
// no registry entry, since dispatch routes the pinned name to the shell path.
func advertisedTools(registry *tools.Registry, m mode.Mode) []provider.ToolDefinition {
	var defs []provider.ToolDefinition
	for _, t := range registry.List() {
		meta := t.Advertise()
		if m == mode.Plan && !meta.ReadOnly && t.Name() != subagenttool.ToolName {
			continue
		}
		defs = append(defs, provider.ToolDefinition{
			Name:        t.Name(),
			Description: meta.Description,
			Parameters:  meta.Parameters,
		})
	}
	defs = append(defs, provider.BashToolDefinition())
	// suggest_followup is product-authored like bash and advertised in every mode (it is
	// never destructive — its only effect is an ephemeral UI suggestion the turn loop
	// intercepts — so Plan does not filter it).
	defs = append(defs, provider.SuggestFollowupToolDefinition())
	slices.SortFunc(defs, func(a, b provider.ToolDefinition) int {
		return strings.Compare(a.Name, b.Name)
	})
	return defs
}

// activeVCSName adapts the bootstrap step-6 active-VCS handoff (an *ActiveVCS, or nil
// when detection matched no template) into the plain template name the environment
// block renders: the block maps the built-in ids git/hg/jj to Git/Mercurial/Jujutsu, passes
// any other non-empty name through verbatim, and renders an empty name as "no version
// control detected". Keeping this adaptation in internal/bootstrap is what lets
// internal/agentinstr stay free of an internal/bootstrap import.
func activeVCSName(v any) string {
	av, ok := v.(*ActiveVCS)
	if !ok || av == nil || av.Template == nil {
		return ""
	}
	return av.Template.Name
}

func activeVCSRepoRoot(v any) string {
	av, ok := v.(*ActiveVCS)
	if !ok || av == nil || av.Template == nil {
		return ""
	}
	return av.RepoRoot
}

// newClearDeps builds the production /clear capabilities (cleardeps.go) bound to
// the running app + bootstrap result. The fresh same-folder session's folder is
// resolved by clearSessionSwapper.Fresh from the active store at /clear time (not
// captured here at startup), so the new session lands under whichever session is
// active when /clear runs even after a prior in-process swap. lock is the
// run-scoped resume-lock holder shared with the /resume switch and exit controller,
// so /clear releases the resume lock the run held on the session it is leaving.
func newClearDeps(ctx context.Context, app *tui.App, result *BootstrapResult, active *model.ActiveState, modeActive *mode.ActiveState, lock *resumeLockHolder, recorder *capabilityRecorder, conf *confinement) tui.ClearDeps {
	return tui.ClearDeps{
		Stream:           installedStreamCanceller(app),
		StreamTranscript: app,
		Session:          &clearSessionSwapper{app: app, ctx: ctx, home: result.Home, ui: app, holder: lock, recorder: recorder, conf: conf},
		Model:            clearModelState{active: active},
		Mode:             clearModeState{active: modeActive, ctx: ctx, ui: app},
		Agents:           clearAgentReplayer{entries: result.AgentInstructions},
		WriteFailure:     clearWriteFailureSink{ui: app},
		FlushCtx:         ctx,
	}
}

func newForkDeps(ctx context.Context, app *tui.App, home string, resumeLock *resumeLockHolder, turnCtl *turnController, status statusState, recorder *capabilityRecorder, conf *confinement) tui.ForkDeps {
	lifecycle := newChildLifecycle(ctx, app, home, resumeLock, status, recorder, conf)
	return tui.ForkDeps{
		TurnActive:        turnUnavailable(app, turnCtl),
		FlushParent:       newStrictParentFlush(ctx, app),
		CreateAndActivate: lifecycle.CreateAndActivate,
	}
}

func newChildLifecycle(ctx context.Context, app *tui.App, home string, resumeLock *resumeLockHolder, status statusState, recorder *capabilityRecorder, conf *confinement) preparedChildLifecycle {
	return preparedChildLifecycle{
		ctx:      ctx,
		home:     home,
		app:      app,
		holder:   resumeLock,
		banner:   func() []string { return bannerLines(status) },
		recorder: recorder,
		conf:     conf,
	}
}

func newStrictParentFlush(ctx context.Context, app *tui.App) func(*sessions.Store) error {
	return func(store *sessions.Store) error {
		cat, reason, err := store.Flush(ctx)
		if err == nil {
			return nil
		}
		if reason != sessions.ReasonNone {
			_ = sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, app)
		}
		return err
	}
}

var reportLateCompactDiscard = func(err error) {
	fmt.Fprintf(os.Stderr, "codemeld: compact cleanup after exit: %v\n", err)
}

type compactLease struct {
	inFlight atomic.Bool
	mu       sync.Mutex
	ended    bool
	prepared *preparedChild
}

func (l *compactLease) hold(prepared preparedChild) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ended {
		if err := prepared.discard(); err != nil {
			reportLateCompactDiscard(err)
		}
		return false
	}
	l.prepared = &prepared
	return true
}

// activate holds the lease lock through fn so end either waits for the activation
// or has already discarded the child; the completion can run on a worker after the
// event loop returns.
func (l *compactLease) activate(fn func(preparedChild)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.prepared == nil {
		return
	}
	prepared := *l.prepared
	l.prepared = nil
	fn(prepared)
}

func (l *compactLease) end() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ended = true
	if l.prepared == nil {
		return nil
	}
	err := l.prepared.discard()
	l.prepared = nil
	return err
}

func (l *compactLease) held() bool { return l.inFlight.Load() }

func (l *compactLease) acquire() (func(), bool) {
	if !l.inFlight.CompareAndSwap(false, true) {
		return nil, false
	}
	return func() { l.inFlight.Store(false) }, true
}

func newCompactDeps(ctx context.Context, app *tui.App, cache *config.Cache, active *model.ActiveState, home string, resumeLock *resumeLockHolder, turnCtl *turnController, status statusState, lease *compactLease, recorder *capabilityRecorder, conf *confinement) tui.CompactDeps {
	lifecycle := newChildLifecycle(ctx, app, home, resumeLock, status, recorder, conf)
	return tui.CompactDeps{
		Context:    ctx,
		TurnActive: turnUnavailable(app, turnCtl),
		SummaryRequest: func(records []sessions.Record) (provider.Request, string, string, bool) {
			sel, _, ok := active.Current()
			if !ok {
				return provider.Request{}, "", "", false
			}
			return turn.BuildCompactionSummaryRequest(sel, records), sel.Provider, sel.ID, true
		},
		Client: func(providerID, _ string) (provider.Client, bool) {
			entry, ok := cache.SelectableCatalog().Entry(providerID)
			if !ok {
				return nil, false
			}
			return turnCtl.buildClient(providerID, entry.AuthKind)
		},
		FlushParent:      newStrictParentFlush(ctx, app),
		AcquireExclusive: lease.acquire,
		RunBackground:    app.RunBackgroundAfterDraw,
		PrepareChild: func(parent *sessions.Store, title string, childRecords, finalParentRecords []sessions.Record) (func(), error) {
			prepared, err := lifecycle.Prepare(parent, title, childRecords, finalParentRecords, turnNoticeRenderer{surface: app})
			if err != nil {
				return nil, err
			}
			if !lease.hold(prepared) {
				return func() {}, nil
			}
			return func() {
				lease.activate(func(prepared preparedChild) {
					if warning := lifecycle.Activate(prepared); warning != "" {
						app.Notice(warning)
					}
				})
			}, nil
		},
	}
}

// newCommandFlush builds the app's command-event flush hook (installed
// via App.SetCommandFlush). It flushes whichever session is active when a command
// appended a slash_command record that has no other flush boundary (/status,
// /help, the placeholder commands), and on an atomic-write failure routes the
// per-turn protocol through sessionfailures.HandleWriteFailure — using
// the app as the one-line notice sink — so the records carry forward and retry on
// the next flush rather than aborting the command. Living in internal/bootstrap is
// what keeps this delegation off the sessionfailures→tui import cycle. A non-write
// flush error (cancelled context / marshal failure) yields reason ReasonNone and
// cannot be encoded as session_write_failed; it is returned so the command adapter
// treats the handler as failed and retains the input for a later retry rather than
// proceeding past the durability boundary, mirroring /clear's pre-switch flush gate.
func newCommandFlush(ctx context.Context, app *tui.App) func() error {
	return func() error {
		store := app.ActiveStore()
		if store == nil {
			return nil
		}
		cat, reason, err := store.Flush(ctx)
		if err == nil {
			return nil
		}
		if reason == sessions.ReasonNone {
			return err
		}
		return sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, app)
	}
}

// newRefreshRecordFlush makes the model picker record a forced-refresh result
// durable before it adds a matching scrollback line. It still delegates an
// atomic-write failure to the usual session-write failure protocol, preserving the
// record for retry and informing the user, but returns the original failure so this
// one caller does not present it as a recorded refresh.
func newRefreshRecordFlush(ctx context.Context, app *tui.App) func(*sessions.Store) error {
	return func(store *sessions.Store) error {
		if store == nil {
			return nil
		}
		cat, reason, err := store.Flush(ctx)
		if err == nil || reason == sessions.ReasonNone {
			return err
		}
		if herr := sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, app); herr != nil {
			return errors.Join(err, herr)
		}
		return err
	}
}

// newRenameTitleWrite builds the /rename persistence seam (tui.RenameDeps.SetTitle).
// It sets the new title on whichever session is active and atomic-writes it
// through that session's owning store via Store.FlushTitle — deliberately not the
// package-level sessions.SetTitle, which would take the sidecar lock the resumed
// session already holds and could self-contend. FlushTitle does not
// advance updated_at (a rename is metadata housekeeping, not session activity), and
// the same write flushes the handler's just-appended slash_command record.
func newRenameTitleWrite(ctx context.Context, app *tui.App) func(string) error {
	return func(title string) error {
		store := app.ActiveStore()
		if store == nil {
			return nil
		}
		cat, reason, err := store.FlushTitle(ctx, title)
		if err == nil {
			return nil
		}
		if reason == sessions.ReasonNone {
			return err
		}
		if herr := sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, app); herr != nil {
			return herr
		}
		return err
	}
}

// newTitleOnComplete builds the first-turn model-title hook. Generation runs off the
// event loop; the final checks and the write run on it, so a /clear or /resume swap
// cannot release the session between the active-store check and the write.
func newTitleOnComplete(app *tui.App, supportedEffort func(providerID, modelID string) []string) func(ctx context.Context, client provider.Client, sel model.Selection, store *sessions.Store, firstUser, firstAssistant string) {
	return func(ctx context.Context, client provider.Client, sel model.Selection, store *sessions.Store, firstUser, firstAssistant string) {
		writable := func() bool {
			return store.TitleSource() != sessions.TitleSourceUser && !store.IsChild() && app.ActiveStore() == store
		}
		if !writable() {
			return
		}
		var title string
		app.RunBackgroundAfterDraw(func() error {
			if !writable() {
				return nil
			}
			title = turn.GenerateTitle(ctx, client, sel, firstUser, firstAssistant, supportedEffort)
			return nil
		}, func(error) {
			if title == "" || ctx.Err() != nil || !writable() {
				return
			}
			if _, _, err := store.FlushGeneratedTitle(ctx, title); err != nil {
				return
			}
			app.RefreshSessionBadge(store)
		})
	}
}

func newContextWindowNotice(app *tui.App, cache *config.Cache) func(sessionID string, resp events.ModelResponse) {
	warned := map[string]bool{}
	return func(sessionID string, resp events.ModelResponse) {
		window := cache.ContextWindow(resp.Provider, resp.ModelID)
		threshold := window - window/10
		if window <= 0 || resp.InputTokens < threshold {
			return
		}
		amount := fmt.Sprint(resp.InputTokens)
		if slices.Contains(resp.Anomaly, "usage_missing") {
			amount = "at least " + amount
		}
		advice := "If individual requests approach the limit, check the server/model limit and match `context_windows`; the declaration does not raise capacity. For Ollama, check `OLLAMA_CONTEXT_LENGTH` or model `num_ctx`."
		if entry, ok := cache.SelectableCatalog().Entry(resp.Provider); ok && entry.AuthKind == provider.AuthKindChatGPTSession {
			advice = "If individual requests approach the limit, start a shorter or new session, or switch to a larger-window model."
		}
		text := fmt.Sprintf("%s/%s: %s recorded input tokens across rounds/retries; window %d, 90%% threshold %d. This is not one request's size. %s", resp.Provider, resp.ModelID, amount, window, threshold, advice)
		app.RunBackgroundAfterDraw(func() error { return nil }, func(error) {
			if active := app.ActiveStore(); active == nil || active.SessionID() != sessionID || warned[sessionID] {
				return
			}
			app.Notice(text)
			warned[sessionID] = true
		})
	}
}

// firstTurnTitleInputs reports ok only for a non-child session with exactly one user
// message (a tool-using first turn still has one: tool results are role "tool") whose
// content is non-empty plain text, returning it with the final plain assistant answer.
func firstTurnTitleInputs(store *sessions.Store) (firstUser, firstAssistant string, ok bool) {
	if store.IsChild() {
		return "", "", false
	}
	users := 0
	for _, r := range store.Records() {
		m, isMsg := r.(sessions.Message)
		if !isMsg {
			continue
		}
		switch m.Role {
		case "user":
			users++
			if !m.Content.IsList() {
				firstUser = m.Content.Text()
			}
		case "assistant":
			// The final plain assistant answer: a tool-call round or a content-part
			// list has no string projection, so the last non-tool, non-list assistant
			// message is the durable final reply.
			if len(m.ToolCalls) == 0 && !m.Content.IsList() {
				firstAssistant = m.Content.Text()
			}
		}
	}
	if users != 1 || strings.TrimSpace(firstUser) == "" {
		return "", "", false
	}
	return firstUser, firstAssistant, true
}

// newPickerApply builds the shared picker-apply transaction (effortdeps.go)
// over the app's active-session reference and the run's config/model roots. The
// cross-mode marker disclosure applies only under launch-dir-only discovery.
func newPickerApply(ctx context.Context, app *tui.App, cache *config.Cache, active *model.ActiveState, home string) pickerApply {
	return pickerApply{
		active:        active,
		ui:            app,
		store:         app.ActiveStore,
		ctx:           ctx,
		projectRoot:   cache.ProjectRoot(),
		home:          home,
		launchDirOnly: cache.Discovery() == discoveryLaunchDirOnly,
	}
}

// newEffortDeps builds the production tui.EffortDeps (effortdeps.go). Refresh
// re-renders the persistent status-line footer after a successful effort apply so
// /effort and the CTRL-E picker (which share this deps object) keep the footer in
// sync with the active selection. OpenPicker routes a bare /effort
// to the same effort picker CTRL-E opens.
func newEffortDeps(ctx context.Context, app *tui.App, cache *config.Cache, active *model.ActiveState, home string) tui.EffortDeps {
	return tui.EffortDeps{
		Model:      effortModel{active: active, cache: cache},
		Applier:    effortApplier{pickerApply: newPickerApply(ctx, app, cache, active, home)},
		OpenPicker: app.OpenEffortPicker,
		Refresh:    app.RefreshStatusLine,
	}
}

// newModelDeps builds the production tui.ModelDeps (modeldeps.go), sharing the
// same active state + transaction as the effort deps. OpenPicker routes a
// bare /model to the same model picker CTRL-M opens. ClearNotice drops any
// stale pinned notice on a successful model change so it cannot linger below the
// new selection's output.
func newModelDeps(ctx context.Context, app *tui.App, cache *config.Cache, active *model.ActiveState, home string) tui.ModelDeps {
	return tui.ModelDeps{
		Model:       modelCatalog{effortModel: effortModel{active: active, cache: cache}, cache: cache},
		Applier:     modelApplier{pickerApply: newPickerApply(ctx, app, cache, active, home)},
		OpenPicker:  app.OpenModelPicker,
		Refresh:     app.RefreshStatusLine,
		ClearNotice: app.ClearNotice,
		NoticeSeq:   app.NoticeSeq,
	}
}

// newModelPickerDeps builds the production tui.ModelPickerDeps (modeldeps.go) for
// the CTRL-M picker, sharing the same active state + transaction as the
// effort and /model deps but spanning the provider×model cross-product so the
// picker can switch providers. launchDir feeds the picker's
// settings-target path display.
func newModelPickerDeps(ctx context.Context, app *tui.App, cache *config.Cache, active *model.ActiveState, chatgptAuth chatGPTAuth, home, launchDir string) tui.ModelPickerDeps {
	fav := providerModelFavorites{cache: cache}
	return tui.ModelPickerDeps{
		Catalog:        providerModelCatalog{effortModel: effortModel{active: active, cache: cache}, cache: cache, launchDir: launchDir},
		Applier:        providerModelApplier{pickerApply: newPickerApply(ctx, app, cache, active, home)},
		Refresh:        app.RefreshStatusLine,
		RefreshCatalog: newProviderRefreshCallback(cache, chatgptAuth, SettingsPath(home)),
		FlushRefresh:   newRefreshRecordFlush(ctx, app),
		Favorites:      fav.Favorites,
		ToggleFavorite: fav.ToggleFavorite,
	}
}

// newExitController builds the production tui.ExitController (exitdeps.go) over
// the app's active-session reference and event-loop teardown. lock is the
// run-scoped resume-lock holder shared with the /resume switch and /clear swapper,
// so a clean /exit releases the resume lock the run held on the resumed session
// before the process boundary. turn is the run's turn controller, so a clean /exit
// cancels and drains an in-flight turn — and with it any child agent running under
// that turn's context — the way /clear and /resume already do before they switch.
func newExitController(ctx context.Context, app *tui.App, stdout io.Writer, lock *resumeLockHolder, turn turnStopper, stopDelivery func()) exitController {
	return exitController{activeStore: app.ActiveStore, beginShutdown: app.BeginShutdown, stop: app.Stop, ctx: ctx, stdout: stdout, holder: lock, turn: turn, stopDelivery: stopDelivery}
}

// statusState is the production tui.StatusState. Session id, start
// timestamp, and records are read live from the app's active store so a /clear or
// /resume swap is reflected at open time; the version, launch dir, config layer
// paths, and AGENTS.md load record are fixed for the run.
type statusState struct {
	app       *tui.App
	cache     *config.Cache
	active    *model.ActiveState
	launchDir string
	entries   []agentinstr.LoadEntry
	layers    []tui.StatusLayer
	approval  tui.ApprovalDisclosure
	execution enforce.Resolution
	live      func() enforce.Resolution
}

func newStatusState(app *tui.App, cache *config.Cache, active *model.ActiveState, result *BootstrapResult, execution enforce.Resolution) statusState {
	return statusState{
		app:       app,
		cache:     cache,
		active:    active,
		launchDir: result.LaunchDir,
		entries:   result.AgentInstructions,
		layers:    statusLayers(result.SettingsLayers),
		approval:  approvalDisclosure(result),
		execution: execution,
	}
}

func statusLayers(layers []securitystate.LayerSnapshot) []tui.StatusLayer {
	var rows []tui.StatusLayer
	for _, layer := range layers {
		if layer.Present && !layer.Ignored {
			rows = append(rows, tui.StatusLayer{Kind: string(layer.Kind), Path: layer.Path})
		}
	}
	return rows
}

// approvalDisclosure renders from the same WithheldInputs value and labels the launch
// notice uses, so /status and that notice cannot disagree about what the launch withheld.
func approvalDisclosure(result *BootstrapResult) tui.ApprovalDisclosure {
	disclosure := tui.ApprovalDisclosure{Approved: result.TrustDecision.Trusted, Reason: result.TrustDecision.Reason}
	for _, input := range result.WithheldInputs {
		disclosure.Withheld = append(disclosure.Withheld, withheldLabel(input.Category)+" "+input.Path)
	}
	return disclosure
}

// bannerLines builds the launch banner: the teal-filled name bar and, on a
// single line beneath it, the provider · model · effort · launch-dir metadata subtitle
// (LaunchBannerMeta, a cool-grey left→light ramp; a "no model selected"
// fallback when no model is determined yet, since Selection returns empty strings). It reads
// the same statusState the /status overlay renders, so the two never drift.
func bannerLines(status statusState) []string {
	provider, modelID, effort := status.Selection()
	return []string{
		// The name line is the teal-filled chrome bar (LaunchBannerBar): "◆ codemeld"
		// bold-white at the left, the dynamic version (status.Version(), never hardcoded)
		// dim/non-bold immediately after the wordmark, with the remaining width padded
		// by the teal fill to the terminal width at append time. The metadata line
		// (LaunchBannerMeta) carries the runtime values (provider/model/effort, launch path)
		// and tview.Escape's each segment internally — both lines mix intentional color
		// markup with escaped runtime text, since AppendBanner appends the joined block
		// through the raw AppendStyled seam, which would otherwise parse a path like
		// /tmp/[red]work as markup.
		tui.LaunchBannerBar(status.Version(), bannerWidth()),
		tui.LaunchBannerMeta(provider, modelID, effort, status.LaunchDir()),
	}
}

// bannerWidth reports the terminal width to fill the launch banner bar to, queried from
// os.Stdout at append time. Under `go test` and any non-terminal stdout the size
// query fails and it falls back to 80, so the bar is deterministic off a real terminal;
// in production the bar fills to the live terminal width. The bar is not re-filled on a
// later resize (Notes), so the append-time width is the one it keeps until it scrolls off.
func bannerWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

func (s statusState) Version() string           { return codemeldVersion }
func (s statusState) LaunchDir() string         { return s.launchDir }
func (s statusState) ProjectRoot() string       { return s.cache.ProjectRoot() }
func (s statusState) Layers() []tui.StatusLayer { return slices.Clone(s.layers) }

// Selection reports the active provider/model/effort; empty strings when no model
// is selected (the overlay then renders empty fields rather than refusing to open).
func (s statusState) Selection() (provider, modelID, effort string) {
	sel, _, ok := s.active.Current()
	if !ok {
		return "", "", ""
	}
	return sel.Provider, sel.ID, sel.Effort
}

func (s statusState) AgentInstructions() []agentinstr.LoadEntry { return s.entries }

func (s statusState) Approval() tui.ApprovalDisclosure {
	out := s.approval
	out.Withheld = slices.Clone(s.approval.Withheld)
	return out
}

func (s statusState) SessionID() string {
	store := s.app.ActiveStore()
	if store == nil {
		return ""
	}
	return store.MetadataSnapshot().ID
}

func (s statusState) SessionStartedAt() time.Time {
	store := s.app.ActiveStore()
	if store == nil {
		return time.Time{}
	}
	return store.MetadataSnapshot().StartedAt
}

func (s statusState) SandboxStatus() (state, reason, modeKey string) {
	execution := s.execution
	if s.live != nil {
		execution = s.live()
	}
	modeKey = s.app.StatusModeKey()
	return execution.SandboxState(modeKey), execution.Reason, modeKey
}

func (s statusState) WebResearch() bool {
	return s.cache.WebResearch().Enabled
}

func (s statusState) Records() []sessions.Record {
	store := s.app.ActiveStore()
	if store == nil {
		return nil
	}
	return store.Records()
}

// newPromptEntrypoint returns the production plain-prompt routing seam. It drives
// the pre-turn persistence contract (sessionturn.Persister) so the user message
// is durable before any provider request, then hands the already-persisted active
// store to the turn controller's dispatch, accepting the input (clearing the
// field) only when persistence succeeds. The persister is rebound when the active
// store changes (e.g. after a /clear swap) so its retry-idempotence guard stays
// scoped to one session.
func newPromptEntrypoint(ctx context.Context, app *tui.App, ctl *turnController) tui.PromptEntrypoint {
	var persister *sessionturn.Persister
	var bound *sessions.Store
	return func(input string, imageParts ...sessions.ContentPart) bool {
		store := app.ActiveStore()
		if store == nil {
			return false
		}
		if turnUnavailable(app, ctl)() {
			if !app.HasQueuedPrompt() && ctl.addUserMessage(input, imageParts) {
				app.SendingPrompt(input, imageParts...)
				return true
			}
			app.EnqueuePrompt(input, imageParts...)
			return true
		}
		if persister == nil || bound != store {
			persister = sessionturn.New(store, app)
			bound = store
		}
		return persister.PersistUserInputThenIssue(ctx, input, imageParts, func(submitStart time.Time) error { return ctl.dispatch(store, submitStart) }) == nil
	}
}

func turnUnavailable(app *tui.App, ctl *turnController) func() bool {
	return func() bool { return ctl.busy() || app.TurnEndPending() }
}

var resolveExecutionCapability = enforce.Resolve

func startExecutionCapability(resolution enforce.Resolution, notices tui.NoticeRenderer) (string, error) {
	if runtime.GOOS == "linux" {
		if err := removeStaleSessionTempDirs(); err != nil {
			notices.Notice(fmt.Sprintf("codemeld: could not remove a leftover confinement temp folder: %v", err))
		}
	}
	if !resolution.SelfTestPassed {
		return "", nil
	}
	return newSessionTempDir()
}

var recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
	var legs []events.ExecutionCapabilityLeg
	for _, leg := range resolution.Legs {
		legs = append(legs, events.ExecutionCapabilityLeg{Name: leg.Name, Observed: leg.Observed})
	}
	if _, err := events.Append(store, events.ExecutionCapability{Capability: string(resolution.Capability), Reason: resolution.Reason, Legs: legs}); err != nil {
		return err
	}
	cat, reason, err := store.Flush(context.WithoutCancel(ctx))
	if err != nil && reason != sessions.ReasonNone {
		_ = sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, notices)
	}
	return err
}

func launchConfinement(resolution enforce.Resolution, tmpDir string, modeActive *mode.ActiveState, cache *config.Cache, home string, guard securitystate.Policy, inherited []string) *confinement {
	lookupPath := os.Getenv("PATH")
	if cache.ProgramLookup() == "strict" {
		lookupPath = runner.FixedPATH
	}
	return &confinement{
		constrained: resolution.SelfTestPassed,
		mode: func() string {
			m, _ := modeActive.Current()
			return string(m)
		},
		home:        home,
		projectRoot: cache.ProjectRoot(),
		writable:    newWritableFoldersReader(cache),
		blocked:     guard.Blocked,
		lookupPath:  lookupPath,
		lookupSet:   true,
		tmpDir:      tmpDir,
		inherited:   inherited,
	}
}
