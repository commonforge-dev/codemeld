// Resume-launch bootstrap orchestration enforcing the resume sub-sequence
// for `--resume <id>` and the no-id `--resume` picker form.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
)

// ResumeSteps is the injected leaf-operation set for the resume-launch paths,
// the resume analogue of FreshSteps. RunResumeWithID / RunResumePicker own the
// ordering and short-circuiting; the steps own the work. Production wires
// DefaultResumeSteps; tests inject fakes that record invocation order and return
// controlled errors so the resume sub-sequence ordering can be asserted exactly
// the way orchestrate_test.go asserts the fresh path.
//
// The fields are grouped by the bootstrap phase they serve: the shared preamble
// (steps 0 and 1), the no-id listing phase, the resume sub-sequence (the
// load/lock/launch_began/refresh block placed between step 1 and step 2 on a
// resumed run), and the standard steps 2–8 that both launch paths share with the
// fresh path.
type ResumeSteps struct {
	// --- preamble (steps 0a, 0, 1) ---

	// ResolveHome resolves the user's home directory (step 0a), mirroring the fresh
	// path's first step. RunResumeWithID / RunResumePicker wrap a failure here in a
	// HomeResolveError so the CLI renders the step-0a stderr line.
	ResolveHome func() (home string, err error)
	// RunFirstRun reports ran=true when global settings were absent and first-run
	// generation ran (step 0); the resume entry points then exit before listing or
	// resolving, exactly as RunFresh exits before step 1.
	RunFirstRun func(home string) (ran bool, err error)
	// LoadGlobalSettings loads ~/.codemeld/global/settings.yaml and the keys the
	// resume paths need (discovery.boundary, sessions.retention_days) (step 1).
	LoadGlobalSettings func(home string) (global map[string]any, err error)

	// no-id listing phase ---

	// ListAndSelect renders the listing (after the tty/skipped-id
	// preflight) and reports the chosen session id. picked is false when the user
	// dismisses without selecting, in which case the caller exits normally without
	// entering the resume sub-sequence. No retention prune runs on this path: pruning
	// is fresh-launch-only.
	ListAndSelect func(home, cwd string, global map[string]any) (id string, picked bool, err error)

	// --- resume sub-sequence (between step 1 and step 2 on a resumed run) ---

	// ResolveResume resolves <id> to its session file and runs the
	// folder-file check and the CWD-match check. A failure
	// here fires before the record stream is available, so it is stderr-only and
	// emits no event (the returned error's text is the exact stderr line).
	ResolveResume func(id, cwd, home string) (sessionPath string, sess *sessions.Session, err error)
	// AcquireLock takes the per-session advisory lock on the session file's sidecar
	// (sub-step 1) and returns the release held for the lifetime of the
	// run. A failure here is also pre-stream and stderr-only.
	AcquireLock func(sessionPath, id string) (release func(), err error)
	// AppendLaunchBegan appends the launch_began (source: resume) event as the first
	// event of this launch (sub-step 2) and flushes. The record
	// stream is available at this point because resolve and lock have completed.
	AppendLaunchBegan func(ctx context.Context, store *sessions.Store) error
	// RefreshUpdatedAt refreshes the loaded session's updated_at and flushes
	// (sub-step 3). A write failure here fires after the record stream is
	// available, so the step routes it through the per-turn write-failure protocol
	// and the run continues; it returns a non-nil error only for a fatal
	// condition (e.g. context cancellation), which aborts the launch.
	RefreshUpdatedAt func(ctx context.Context, store *sessions.Store) error

	// --- standard steps 2–8 (shared with the fresh path) ---

	// ResolveProjectRoot walks for the project root from the launch cwd and returns
	// the project-side settings.yaml layer paths discovered there (step 2), mirroring
	// the fresh path's contract so a resumed launch shows the same global-first/
	// project-last /status config sources (item 10).
	ResolveProjectRoot func(cwd string, global map[string]any) (projectRoot string, projectLayers []string, err error)
	// GateTrust decides whether the repository at projectRoot may contribute its settings
	// layer (step 2b), mirroring the fresh path: it runs before the layer paths are
	// published and before composition.
	GateTrust func(home, projectRoot, launchDir string) trust.Decision
	// ScaffoldProjectIgnore scaffolds the commented <project-root>/.codemeld/codemeldignore
	// template, creating it only when absent. It runs immediately after project-root
	// resolution and before config/VCS/tool setup (step 2.5), mirroring the fresh path so a
	// cold-start resume scaffolds the project starter file too. The production step is
	// best-effort (it never aborts the launch).
	ScaffoldProjectIgnore func(projectRoot string) error
	// RecoverJournals puts back the writes of a child agent whose codemeld process was killed
	// before it could unwind them, for the project folder being opened (step 2.6), mirroring the
	// fresh path: a resumed launch is a launch for that folder too. It returns nothing because
	// recovery must never block a launch.
	RecoverJournals func(home, projectRoot string, global map[string]any, decision trust.Decision)
	// ComposeConfig composes the config layers (step 3), mirroring the fresh path.
	ComposeConfig func(global map[string]any, projectRoot string) (composition ConfigComposition, err error)
	// LoadVCSTemplates loads built-in and project VCS templates (step 4), mirroring the fresh
	// path: projectLayer is step 3's verified project settings map (nil when none was
	// composed) and approved is the launch's trust outcome.
	LoadVCSTemplates func(home, projectRoot string, projectLayer map[string]any, approved bool) (templates any, err error)
	// ValidatePreferredVCS cross-reference-validates vcs.preferred (step 5).
	ValidatePreferredVCS func(composed map[string]any, templates any) error
	// DetectVCS runs auto-detection, returning the active template or nil (step 6).
	DetectVCS func(cwd string, composed map[string]any, templates any) (active any, err error)
	// BuildToolRegistry builds the tool registry (step 6c).
	BuildToolRegistry func(active any) (registry any, err error)
	// DetermineModel determines the active model (steps 7/7a) through the same config→
	// model bridge as the fresh path, taking the composed config, the global layer
	// (to attribute path-4 provider diagnostics to their source settings file), the
	// project root, and the global-first/project-last layer paths. On a resumed run it
	// follows step 1 (recover from the loaded record stream) before the fresh
	// paths 2–4, so it also takes the loaded store. It returns the run-scoped
	// *model.ActiveState, reports pickerRequired=true for the path-4
	// selectable-model outcome, and returns the path-4 *NoSelectableModelError when no
	// model is installed.
	DetermineModel func(composed, global map[string]any, projectRoot string, layerPaths []string, store *sessions.Store) (selection any, pickerRequired bool, err error)
	// InitMode resolves mode.default from the composed config, durably appends the
	// session-start interaction_mode{trigger:"resume"}, and returns the run-scoped
	// *mode.ActiveState (step 7b2). A resumed session starts from mode.default, never
	// from the mode active when the prior session ended, so this mirrors
	// the fresh path's InitMode with a "resume" trigger. It runs after step 7's model
	// determination — so a path-4 no-selectable-model abort suppresses it —
	// and before AGENTS.md load, since the composed config (step 3) it reads is not
	// available until after the resume sub-sequence's launch_began.
	InitMode func(ctx context.Context, store *sessions.Store, composed map[string]any, projectRoot string, layerPaths []string) (modeState any, err error)
	// LoadAgentInstructions discovers AGENTS.md files, replays one
	// agent_instructions_loaded event per file into the resumed store, flushes so
	// the records are durable, and returns the in-memory load record for the live
	// system prompt, /status, and /clear replay (step 7c). The walk anchor is the launch CWD on a
	// resumed run, which the CWD-match check has already proven equal to
	// metadata.folder. composed/projectRoot/layerPaths feed the config.Cache the
	// per-file size cap is read from.
	LoadAgentInstructions      func(ctx context.Context, store *sessions.Store, home, launchDir string, composed map[string]any, projectRoot string, layerPaths []string, selection agentinstr.Selection) ([]agentinstr.LoadEntry, error)
	AgentInstructionsSelection agentinstr.Selection
	// StartTUI starts the TUI (step 8). It blocks for the lifetime of the run, so
	// the resume lock acquired above stays held until it returns.
	StartTUI func(ctx context.Context, result *BootstrapResult) error
}

// RunResumeWithID runs the cold-start `codemeld --resume <id>` launch. Mirroring
// RunFresh, it resolves home as step 0a (wrapping a failure in HomeResolveError),
// then runs step 0 (first-run check) and step 1 (load global settings) before
// entering the resume sub-sequence with no deferred prune summary. cwd is
// the launch directory and steps is the injected leaf-operation set (production
// wires DefaultResumeSteps). It never prints; it returns errors for the CLI layer
// to render and an exit code to apply.
//
// On the first-run branch it returns (nil, nil): first-run generation ran and the
// caller exits 0. On any failure it returns (nil, err). On a full launch it
// returns the populated result.
func RunResumeWithID(ctx context.Context, cwd, id string, steps ResumeSteps) (*BootstrapResult, error) {
	home, err := steps.ResolveHome()
	if err != nil {
		return nil, &HomeResolveError{Err: err}
	}
	return runResumeWithID(ctx, home, cwd, id, steps)
}

// RunResumePicker runs the no-id `codemeld --resume` launch. Mirroring RunFresh it
// resolves home as step 0a (wrapping a failure in HomeResolveError), then runs
// step 0, step 1, and the listing. When the user picks a session it
// transitions into the resume sub-sequence; when the user dismisses without picking
// it returns (nil, nil). No retention prune runs on this path — pruning is
// fresh-launch-only, so the listing may surface expired sessions that a
// later fresh launch has not yet pruned. cwd is the launch directory and steps is
// the injected leaf-operation set. It never prints; the listing's own IO lives in
// the ListAndSelect step.
func RunResumePicker(ctx context.Context, cwd string, steps ResumeSteps) (*BootstrapResult, error) {
	home, err := steps.ResolveHome()
	if err != nil {
		return nil, &HomeResolveError{Err: err}
	}
	return runResumePicker(ctx, home, cwd, steps)
}

// runResumeWithID is RunResumeWithID with the context and step set injected, so
// tests drive the ordering with recording fakes the way orchestrate_test.go
// drives RunFresh.
func runResumeWithID(ctx context.Context, home, cwd, id string, steps ResumeSteps) (*BootstrapResult, error) {
	global, ranFirstRun, err := runResumePreamble(home, steps)
	if err != nil || ranFirstRun {
		return nil, err
	}
	return runResumeSubsequence(ctx, home, cwd, id, global, steps)
}

// runResumePicker is RunResumePicker with the context and step set injected.
func runResumePicker(ctx context.Context, home, cwd string, steps ResumeSteps) (*BootstrapResult, error) {
	global, ranFirstRun, err := runResumePreamble(home, steps)
	if err != nil || ranFirstRun {
		return nil, err
	}

	// No retention prune runs before the listing: pruning is fresh-launch-only
	// so the listing may surface expired sessions a later fresh launch
	// has not yet pruned.
	id, picked, err := steps.ListAndSelect(home, cwd, global)
	if err != nil {
		return nil, err
	}
	if !picked {
		// No selection: exit normally without entering step 2.
		return nil, nil
	}
	return runResumeSubsequence(ctx, home, cwd, id, global, steps)
}

// runResumePreamble runs the two steps both resume forms share before they
// diverge: step 0 (first-run check) and step 1 (load global settings). It reports
// ranFirstRun=true when first-run generation ran, so the caller exits before any
// listing or resolution.
func runResumePreamble(home string, steps ResumeSteps) (global map[string]any, ranFirstRun bool, err error) {
	ran, err := steps.RunFirstRun(home)
	if err != nil {
		return nil, false, err
	}
	if ran {
		return nil, true, nil
	}
	global, err = steps.LoadGlobalSettings(home)
	if err != nil {
		return nil, false, err
	}
	return global, false, nil
}

// runResumeSubsequence runs the resume sub-sequence and the standard
// steps 2–8 that follow it. Each step runs only when every preceding step
// returned nil, matching the fresh path's strict ordering; the only nuance is
// that the post-stream write steps (AppendLaunchBegan, RefreshUpdatedAt) absorb
// per-turn write failures inside their own step and return nil so
// the run continues.
func runResumeSubsequence(ctx context.Context, home, cwd, id string, global map[string]any, steps ResumeSteps) (*BootstrapResult, error) {
	res := &BootstrapResult{Home: home, LaunchDir: cwd}
	// Every cold-start resume (both `--resume <id>` and the no-id picker form runs
	// through here) replays the loaded session's prior conversation into the transcript
	// in StartTUI, so the user does not resume into an empty-looking pane.
	res.ResumeReplay = true
	// no resume path initiates a retention prune — pruning is fresh-launch-only
	// so StartTUI must not kick off the background pruner for a resumed run. The sub-step-3
	// updated_at refresh below is a retention-safety measure, not a prune.
	res.BackgroundPrune = false

	// Resolve <id> + folder-file check + CWD-match. This
	// fires before the record stream is available; a failure is stderr-only and
	// emits no event (the typed error's text is the stderr line the CLI prints).
	sessionPath, sess, err := steps.ResolveResume(id, cwd, home)
	if err != nil {
		return nil, err
	}
	store := sessions.New(sessionPath, sess)
	res.Session = store

	// Sub-step 1 — acquire the per-session advisory lock. Also pre-stream
	// and stderr-only on failure. The release is held for the lifetime of the run:
	// step 8's StartTUI blocks until the run ends, and this deferred release fires
	// only after it returns (or after an abort below), matching the resume lock's
	// process-lifetime ownership without needing the kernel's process-exit fallback.
	release, err := steps.AcquireLock(sessionPath, id)
	if err != nil {
		return nil, err
	}
	releaseLock := release
	defer func() {
		if releaseLock != nil {
			releaseLock()
		}
	}()
	res.ResumeLockRelease = func() {
		if releaseLock == nil {
			return
		}
		releaseLock()
		releaseLock = nil
	}

	// Sub-step 2 — launch_began (source: resume) as the first event of this launch.
	// The record stream is available now (resolve and lock have completed), so this
	// and every later append/refresh is recordable (pre-session-start rule).
	if err := steps.AppendLaunchBegan(ctx, store); err != nil {
		return nil, err
	}

	// Sub-step 3 — refresh updated_at so the resumed session stays inside the
	// retention window. A write failure here is handled in-step by the
	// per-turn write-failure protocol and does not abort the launch. This is a
	// retention-safety measure against other pruners; the resume path starts none.
	if err := steps.RefreshUpdatedAt(ctx, store); err != nil {
		return nil, err
	}

	// Steps 2–6 run with the CWD as their anchor, identical to the fresh path; the
	// CWD-match check guarantees the CWD equals metadata.folder, so no resume-
	// specific anchor shift is needed.
	root, projectLayers, err := steps.ResolveProjectRoot(cwd, global)
	if err != nil {
		return nil, err
	}
	res.ProjectRoot = root

	// Step 2b — the same trust gate the fresh path runs, before the layer paths are
	// published and before composition.
	res.TrustDecision = steps.GateTrust(home, root, cwd)
	res.WithheldInputs = withheldInputs(root, res.TrustDecision.Trusted)
	composeRoot := root
	if !vcsTemplatesApproved(res.TrustDecision) {
		projectLayers = nil
		composeRoot = ""
	}

	// Same /status config sources as the fresh path (item 10): global
	// settings.yaml first, then the project-side layer(s) above — global-first,
	// project-last. With no project layer, only the global path remains.
	res.ConfigLayerPaths = append([]string{SettingsPath(home)}, projectLayers...)

	// Step 2.5 — scaffold the project codemeldignore template after project-root
	// resolution and before any config/VCS/tool setup, the same placement as the fresh
	// path (run on cold-start resume too).
	if err := steps.ScaffoldProjectIgnore(root); err != nil {
		return nil, err
	}

	// Step 2.6 — put back the child agent writes a killed launch left behind, before any later
	// step reads the project tree, the same placement as the fresh path.
	if steps.RecoverJournals != nil {
		steps.RecoverJournals(home, root, global, res.TrustDecision)
	}

	composition, err := steps.ComposeConfig(global, composeRoot)
	if err != nil {
		return nil, err
	}
	composed := composition.Config
	res.Config = composed
	res.SettingsLayers = settingsLayerSnapshots(home, root, global, res.TrustDecision.Trusted, composition)

	templates, err := steps.LoadVCSTemplates(home, root, composition.ProjectLayer, vcsTemplatesApproved(res.TrustDecision))
	if err != nil {
		return nil, err
	}

	if err := steps.ValidatePreferredVCS(composed, templates); err != nil {
		return nil, err
	}

	active, err := steps.DetectVCS(cwd, composed, templates)
	if err != nil {
		return nil, err
	}
	res.VCSTemplate = active

	registry, err := steps.BuildToolRegistry(active)
	if err != nil {
		return nil, err
	}
	res.ToolRegistry = registry

	// Steps 7/7a — model determination follows step 1 on resume, recovering
	// from the loaded record stream before the disk-config fallbacks. A
	// path-4 exit surfaces here, after the launch_began (resume) sub-step and before
	// step 7c, matching the resumed-run path-4 carve-out.
	activeModel, pickerRequired, err := steps.DetermineModel(composed, global, root, res.ConfigLayerPaths, store)
	if err != nil {
		var noSelectable *model.NoSelectableModelError
		if errors.As(err, &noSelectable) {
			if ferr := sessionfailures.CleanShutdownFlush(ctx, store); ferr != nil {
				return nil, ErrSessionWriteOnExit
			}
		}
		return nil, err
	}
	res.Model = activeModel
	res.ModelPickerRequired = pickerRequired

	// Step 7b2 — initialize the active mode from mode.default and durably append the
	// session-start interaction_mode{trigger:"resume"}. A resumed
	// session starts from mode.default, never from the prior session's last mode. It
	// runs after model determination (so a path-4 no-selectable-model abort above
	// suppresses it) and after ComposeConfig (the composed config it reads is not
	// available until here on the resume path), but before AGENTS.md load.
	modeState, err := steps.InitMode(ctx, store, composed, root, res.ConfigLayerPaths)
	if err != nil {
		return nil, err
	}
	res.Mode = modeState

	// Step 7c — AGENTS.md load; the resumed run re-emits a fresh
	// agent_instructions_loaded event per discovered file (step 7c). The walk
	// anchor is the launch CWD (cwd), already proven equal to metadata.folder by the
	// CWD-match check, not the resolved project root.
	entries, err := steps.LoadAgentInstructions(ctx, store, home, cwd, composed, root, res.ConfigLayerPaths, steps.AgentInstructionsSelection)
	if err != nil {
		return nil, err
	}
	res.AgentInstructions = entries

	// Step 8 — start the TUI.
	if err := steps.StartTUI(ctx, res); err != nil {
		return nil, err
	}

	return res, nil
}

// defaultResumeRetentionDays is the retention default applied when
// settings.yaml omits sessions.retention_days.
const defaultResumeRetentionDays = 30

// DefaultResumeSteps returns the production step set for the resume paths. As with
// DefaultFreshSteps, the steps owned by landed tasks are wired here: step 0a home
// resolution (paths.ResolveHome), step 0 first-run
// (defaultRunFirstRun), global-settings load, the id
// resolver, the per-session lock, project-root resolution, config
// composition, the step-4 through step-6 VCS detection chain (LoadVCSTemplates,
// ValidatePreferredVCS, DetectVCS) — wired to the same production functions the fresh
// path uses so a resumed run runs the same real steps 4-6 — the step-6c registry
// factory and step-7/7a model bridge, the step-7c AGENTS.md replay
// (wired to the same loadAgentInstructions adapter the fresh path uses), and the
// step-8 production launch, wired to the same StartTUI wrapper the fresh path
// uses so a resumed run follows the same registry/dispatcher path, and the
// session-stream append/refresh sub-steps with write-failure
// routing, and the no-id listing/selection step wired
// through resumeListAndSelect. No resume path prunes, so no prune
// step is wired here. stdout/stderr feed the first-run runner, resume write-failure
// notices, and the VCS detection step's stderr warnings; stdin drives the no-id
// listing's tty/keypress preflight and the cold-start selector.
func DefaultResumeSteps(stdin io.Reader, stdout, stderr io.Writer) ResumeSteps {
	notices := stderrNoticeRenderer{w: stderr}
	return ResumeSteps{
		ResolveHome: paths.ResolveHome,
		RunFirstRun: func(home string) (bool, error) {
			return defaultRunFirstRun(home, stdout, stderr)
		},
		LoadGlobalSettings: defaultLoadGlobalSettings,
		// No-id listing/selection: list the current folder's
		// resumable sessions, run the tty/skipped preflight, then render a
		// blocking cold-start selector. global is unused — the listing reads the current
		// folder directly. No prune runs first, so an expired-but-unpruned
		// session may still appear until a later fresh launch removes it.
		ListAndSelect: func(home, cwd string, _ map[string]any) (string, bool, error) {
			return resumeListAndSelect(home, cwd, stdin, stderr)
		},
		// The id resolver composes per-kind payload validation into the load
		// path; events.ValidatePayload is passed here because this
		// package can import internal/events while internal/sessions cannot.
		ResolveResume: func(id, cwd, home string) (string, *sessions.Session, error) {
			return sessions.ResolveResumeID(id, cwd, home, events.ValidatePayload)
		},
		AcquireLock: sessions.AcquireResumeLock,
		AppendLaunchBegan: func(ctx context.Context, store *sessions.Store) error {
			return appendLaunchBegan(ctx, store, "resume", notices)
		},
		RefreshUpdatedAt: func(ctx context.Context, store *sessions.Store) error {
			return refreshResumeUpdatedAt(ctx, store, notices)
		},
		ResolveProjectRoot: func(cwd string, global map[string]any) (string, []string, error) {
			return defaultResolveProjectRoot(cwd, global, stderr)
		},
		GateTrust: interactiveTrustGate(stdin, stderr),
		ScaffoldProjectIgnore: func(projectRoot string) error {
			return ScaffoldProjectCodemeldignore(projectRoot, stderr)
		},
		RecoverJournals: func(home, projectRoot string, global map[string]any, decision trust.Decision) {
			recoverChildJournals(home, projectRoot, global, decision, stdin, stderr, stdinIsTerminal(stdin))
		},
		ComposeConfig:        defaultComposeConfig,
		LoadVCSTemplates:     loadVCSTemplates,
		ValidatePreferredVCS: validatePreferredVCS,
		DetectVCS: func(cwd string, composed map[string]any, templates any) (any, error) {
			return detectVCS(cwd, composed, templates, stderr)
		},
		BuildToolRegistry: defaultBuildToolRegistry,
		DetermineModel: func(composed, global map[string]any, projectRoot string, layerPaths []string, store *sessions.Store) (any, bool, error) {
			return launchModelStep(composed, global, projectRoot, layerPaths, true, store, stderr)
		},
		InitMode: func(ctx context.Context, store *sessions.Store, composed map[string]any, projectRoot string, layerPaths []string) (any, error) {
			return initLaunchMode(ctx, store, composed, projectRoot, layerPaths, mode.TriggerResume, notices)
		},
		LoadAgentInstructions: loadAgentInstructions,
		// Step 8 — the same production launch the fresh path wires: realize the
		// tool registry factory, build the turn controller, and bind the production tool
		// dispatcher before running the event loop, so a resumed launch follows the same
		// registry/dispatcher path as a fresh one rather than skipping the assembly.
		StartTUI: func(ctx context.Context, result *BootstrapResult) error {
			return StartTUI(ctx, result, stdout)
		},
	}
}

type stderrNoticeRenderer struct {
	w io.Writer
}

func (r stderrNoticeRenderer) Notice(text string) {
	if r.w == nil {
		return
	}
	_, _ = fmt.Fprintln(r.w, text)
}

func appendLaunchBegan(ctx context.Context, store *sessions.Store, source string, ui tui.NoticeRenderer) error {
	handled := false
	var handleErr error
	onWriteFailure := func(cat fserrors.Category, reason sessions.WriteReason, ferr error) {
		handleErr = sessionfailures.HandleWriteFailure(reason, cat, store.Path(), ferr, store, ui)
		handled = handleErr == nil
	}
	if err := events.EmitLaunchBegan(ctx, store, source, onWriteFailure); err != nil {
		if handled {
			return nil
		}
		if handleErr != nil {
			return handleErr
		}
		return err
	}
	return nil
}

// emitInteractionMode durably appends the session-start / carry-forward
// interaction_mode event recording active's mode and source with the given trigger,
// routing an atomic-write failure through the sessionfailures write-failure protocol exactly like
// appendLaunchBegan. It is the single durable emitter shared by the fresh/resume
// step-7b2 init (initLaunchMode) and the /clear carry-forward (clearModeState), so
// the three emissions share one persistence policy.
func emitInteractionMode(ctx context.Context, store *sessions.Store, active *mode.ActiveState, trigger mode.Trigger, ui tui.NoticeRenderer) error {
	m, source := active.Current()
	handled := false
	var handleErr error
	onWriteFailure := func(cat fserrors.Category, reason sessions.WriteReason, ferr error) {
		handleErr = sessionfailures.HandleWriteFailure(reason, cat, store.Path(), ferr, store, ui)
		handled = handleErr == nil
	}
	if err := events.EmitInteractionMode(ctx, store, string(m), string(source), string(trigger), onWriteFailure); err != nil {
		if handled {
			return nil
		}
		if handleErr != nil {
			return handleErr
		}
		return err
	}
	return nil
}

func refreshResumeUpdatedAt(ctx context.Context, store *sessions.Store, ui tui.NoticeRenderer) error {
	cat, reason, err := sessions.RefreshUpdatedAt(ctx, store)
	if err == nil {
		return nil
	}
	if reason != sessions.ReasonNone {
		return sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, ui)
	}
	return err
}

// ErrResumeListPreflight signals that sessions.RunResumeListPreflight already wrote
// its exact terminal-failure line (non-tty stdin/stderr) and reported exit
// status 1. The no-id ListAndSelect step returns it so the CLI maps it to a quiet
// status-1 exit (mapBootstrapError) instead of printing a second wrapped error line.
var ErrResumeListPreflight = errors.New("resume list preflight failed")

// resumeListPreflight is a package seam over sessions.RunResumeListPreflight so the
// no-id picker's listing/selection path can be exercised without a real terminal:
// tests swap it to force the tty-gate outcome (0 to reach the selector, 1 to assert
// the quiet-exit mapping).
var resumeListPreflight = sessions.RunResumeListPreflight

var (
	resumeIsTerminal = term.IsTerminal
	resumeMakeRaw    = term.MakeRaw
	resumeRestore    = term.Restore
)

// resumeColdStartSelect renders the blocking cold-start session selector and reports
// the chosen id (picked=false on dismissal). It is a package seam — production wires
// the live tview selector (runResumeColdStartSelect), tests inject a selection/ESC
// result deterministically without owning a real terminal event loop.
var resumeColdStartSelect = runResumeColdStartSelect

// resumeListAndSelect is the production no-id ListAndSelect: it lists the current
// folder's resumable sessions (real sessions.ListResumable)
// runs the tty/skipped-id preflight, and renders the blocking cold-start
// selector for the survivors. A non-tty preflight failure becomes ErrResumeListPreflight
// (the helper already printed the exact line). A truly empty folder (no entries, no
// skipped ids) returns no selection before the preflight so a non-tty stream is not
// rejected; the all-skipped case still runs the preflight prompt, then returns no
// selection. Either way no session starts and the orchestrator drops the deferred
// prune summary.
func resumeListAndSelect(home, cwd string, stdin io.Reader, stderr io.Writer) (string, bool, error) {
	entries, skipped, err := sessions.ListResumable(home, cwd)
	if err != nil {
		return "", false, err
	}
	if len(entries) == 0 && len(skipped) == 0 {
		// Truly empty folder: nothing to list and no skipped-id lines to print, so there
		// is no prompt to run. Exit cleanly without the tty preflight — a non-tty stream
		// here must not be rejected as ErrResumeListPreflight (clean no-selection).
		return "", false, nil
	}
	if code := resumePreflight(stdin, streamFd(stdin), stderr, streamFd(stderr), skipped); code != 0 {
		return "", false, ErrResumeListPreflight
	}
	if len(entries) == 0 {
		// Empty folder or every candidate skipped: nothing to offer. The preflight has
		// already printed any skipped-id lines and consumed the press-any-key prompt.
		return "", false, nil
	}
	return resumeColdStartSelect(entries)
}

func resumePreflight(stdin io.Reader, stdinFd int, stderr io.Writer, stderrFd int, skipped []sessions.SkippedID) int {
	return resumeListPreflight(stdin, stdinFd, stderr, stderrFd, skipped, resumeIsTerminal, resumeWaitKey)
}

func resumeWaitKey(stdin io.Reader, stdinFd int) {
	if old, err := resumeMakeRaw(stdinFd); err == nil {
		defer func() { _ = resumeRestore(stdinFd, old) }()
	}
	var buf [1]byte
	_, _ = stdin.Read(buf[:])
}

// streamFd extracts the underlying file descriptor from a stdin/stderr stream that
// exposes one (an *os.File does); a stream without Fd() yields -1, which the tty
// checks treat as a non-terminal — the correct fallback for piped streams and the
// in-memory readers/writers tests pass.
func streamFd(s any) int {
	if f, ok := s.(interface{ Fd() uintptr }); ok {
		return int(f.Fd())
	}
	return -1
}

// resumeRowIDChars is the number of trailing session-id characters shown per
// selector row: the id's last 8 characters identify the row without the
// full handle's width.
const resumeRowIDChars = 8

// resumeRowTimeLayout formats the started_at / updated_at timestamps on each row.
const resumeRowTimeLayout = "2006-01-02 15:04"

// runResumeColdStartSelect is the production cold-start selector: a standalone,
// blocking tview application listing the surviving rows. ↑/↓ navigate, Enter returns
// the highlighted row's id (picked=true), ESC dismisses (picked=false). It is a
// cold-start selector, not the in-TUI continuation-based ResumePicker, because this
// CLI-flag entrypoint must return the selection before the resume sub-sequence runs.
func runResumeColdStartSelect(entries []sessions.ListEntry) (string, bool, error) {
	app := tview.NewApplication()
	list := tview.NewList()
	list.ShowSecondaryText(true)
	for _, e := range entries {
		list.AddItem(resumeRowPrimary(e), resumeRowSecondary(e), 0, nil)
	}

	var chosenID string
	var picked bool
	list.SetSelectedFunc(func(idx int, _, _ string, _ rune) {
		if idx >= 0 && idx < len(entries) {
			chosenID = entries[idx].ID
			picked = true
		}
		app.Stop()
	})
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			app.Stop()
			return nil
		}
		return ev
	})
	list.SetBorder(true)
	list.SetTitle(" resume session ")

	if err := app.SetRoot(list, true).Run(); err != nil {
		return "", false, fmt.Errorf("codemeld: session list: %w", err)
	}
	return chosenID, picked, nil
}

// resumeRowIDShort returns the last resumeRowIDChars characters of the entry's
// session id, or the whole id when shorter. Rune-based so a multibyte id is
// never split mid-character.
func resumeRowIDShort(e sessions.ListEntry) string {
	if r := []rune(e.ID); len(r) > resumeRowIDChars {
		return string(r[len(r)-resumeRowIDChars:])
	}
	return e.ID
}

// resumeRowPrimary renders a row's primary line from the same scanned entry the
// in-TUI picker uses, in the same order its resumeRowTitle applies: the scanned
// user title, else the first-user-message preview, both bounded to the cell
// budget, else the id's last 8 characters.
func resumeRowPrimary(e sessions.ListEntry) string {
	if title := truncatePreview(e.Title); title != "" {
		return title
	}
	if preview := truncatePreview(e.Preview); preview != "" {
		return preview
	}
	return resumeRowIDShort(e)
}

// resumeRowSecondary renders a row's secondary line with the metadata: the
// id's last 8 characters and both the started-at and updated-at timestamps.
func resumeRowSecondary(e sessions.ListEntry) string {
	return fmt.Sprintf("%s · started %s · updated %s",
		resumeRowIDShort(e),
		e.StartedAt.Local().Format(resumeRowTimeLayout),
		e.UpdatedAt.Local().Format(resumeRowTimeLayout))
}

// resumeRetentionDays reads sessions.retention_days from the composed global
// settings, falling back to the default when the key is absent or not an
// integer. The settings loader is still stubbed, so this also tolerates a nil map.
func resumeRetentionDays(global map[string]any) int {
	sessionsCfg, ok := global["sessions"].(map[string]any)
	if !ok {
		return defaultResumeRetentionDays
	}
	switch v := sessionsCfg["retention_days"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	default:
		return defaultResumeRetentionDays
	}
}
