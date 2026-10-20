// Fresh-launch bootstrap orchestration enforcing the step order (steps 0a-8).
package bootstrap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/subagent"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
)

// ErrFirstRunFailed reports that step 0 first-run generation failed. The failing
// runner has already written its OP_FAIL line to stderr, so the CLI maps this to
// a silent exit-1 rather than re-rendering it.
var ErrFirstRunFailed = errors.New("bootstrap: first-run generation failed")

// ErrSessionWriteOnExit reports that a pre-TUI clean-shutdown flush already wrote
// its OP_FAIL line and should map to a quiet status-1 exit.
var ErrSessionWriteOnExit = errors.New("bootstrap: session write on exit failed")

// HomeResolveError wraps a step-0a home-resolution failure so the CLI can render
// the stderr line (`codemeld: cannot resolve home directory: <reason>`)
// without inspecting which step failed.
type HomeResolveError struct{ Err error }

func (e *HomeResolveError) Error() string {
	return "cannot resolve home directory: " + paths.FormatHomeError(e.Err)
}

func (e *HomeResolveError) Unwrap() error { return e.Err }

// BootstrapResult carries the state a completed fresh launch produces, in the
// order fills it. Fields owned by pending leaf tasks (VCS template, tool
// registry, model selection) are typed as any until their owning task lands a
// concrete type.
type BootstrapResult struct {
	Home             string         // step 0a
	LaunchDir        string         // launch cwd (item 4 / status overlay)
	ProjectRoot      string         // step 2
	ConfigLayerPaths []string       // step 2 (ordered settings.yaml sources, global-first/project-last; item 10)
	Config           map[string]any // step 3 (composed config)
	VCSTemplate      any            // step 6 (active template; nil when none detected)
	ToolRegistry     any            // step 6c
	Model            any            // step 7 (active model selection; *model.ActiveState)
	Mode             any            // step 7b2 (active interaction mode; *mode.ActiveState)

	// ModelPickerRequired is the path-4 outcome (step 7): a selectable model
	// exists but none was determined, so StartTUI must open the provider-aware model
	// picker once the picker deps are installed. It is distinct from Model holding an empty
	// active state, which alone only means "no active selection".
	ModelPickerRequired bool

	Session           *sessions.Store        // step 7b (active session)
	AgentInstructions []agentinstr.LoadEntry // step 7c (in-memory AGENTS.md load record, for /status + /clear replay)

	// TrustDecision is the step-2b gate's run-fixed outcome, consumed by the interactive
	// project-grant prompt. A headless run retains it from its own non-prompting evaluator.
	TrustDecision trust.Decision

	// WithheldInputs is the structured record of the project inputs a degraded launch did
	// not load, including the reason when the gate could not inspect one.
	WithheldInputs []WithheldInput

	// SettingsLayers holds each admitted settings layer copied independently of Config, so
	// composition's merging and deduplication cannot erase what a layer itself held. A
	// configured project path the trust gate refused is carried as an ignored layer.
	SettingsLayers []securitystate.LayerSnapshot

	// BackgroundPrune marks a launch that must kick off the background
	// retention prune in StartTUI once the active session is installed. Only a fresh
	// launch sets it: pruning is fresh-launch-only. Every resume
	// path — `--resume <id>`, the no-id `--resume` picker, and in-TUI `/resume` —
	// leaves it false, so shared TUI assembly never prunes for a resumed run.
	BackgroundPrune bool

	ResumeLockRelease func()

	// ResumeReplay marks a cold-start resume launch (both `--resume <id>` and the no-id
	// picker form) so StartTUI re-renders the loaded session's prior conversation into
	// the transcript after the launch banner and before the event loop runs. It
	// stays false on a fresh launch, whose empty session has no prior conversation to
	// replay, so fresh-launch transcript behavior is unchanged.
	ResumeReplay bool
}

// ConfigComposition is the step-3 result. ProjectLayer is the parsed project settings map
// that actually contributed to Config, retained so vcs.preferred attribution reuses this
// launch's one verified read instead of reopening the file.
type ConfigComposition struct {
	Config       map[string]any
	ProjectLayer map[string]any
	// ProjectPresent distinguishes an admitted project layer that exists from one whose
	// file was absent, which ProjectLayer alone cannot: both leave it nil.
	ProjectPresent bool
	// LocalPresent distinguishes an admitted local layer that exists from one whose file was
	// absent, which LocalLayer alone cannot: both leave it nil.
	LocalLayer   map[string]any
	LocalPresent bool
}

// FreshSteps is the injected leaf-operation set for the fresh-launch path. Each
// field maps to one step (named in its comment). RunFresh owns the
// ordering and short-circuiting; the steps own the work. Production wires
// DefaultFreshSteps; tests inject fakes that record invocation order and return
// controlled errors so ordering can be asserted without real leaf packages.
type FreshSteps struct {
	// ResolveHome resolves the user's home directory (step 0a).
	ResolveHome func() (home string, err error)
	// RunFirstRun reports ran=true when global settings were absent and first-run
	// generation ran (step 0); RunFresh then exits before step 1.
	RunFirstRun func(home string) (ran bool, err error)
	// LoadGlobalSettings loads ~/.codemeld/global/settings.yaml (step 1).
	LoadGlobalSettings func(home string) (global map[string]any, err error)
	// ResolveProjectRoot walks for the project root from the launch cwd and returns
	// the project-side settings.yaml layer paths discovered there (at most one, per
	// config.LocateProjectRoot); RunFresh prepends the global path to build the
	// global-first/project-last /status source list (step 2).
	ResolveProjectRoot func(cwd string, global map[string]any) (projectRoot string, projectLayers []string, err error)
	// GateTrust decides whether the repository at projectRoot may contribute its settings
	// layer to this run (step 2b), prompting and recording the answer on an interactive
	// launch. It runs before the layer paths are published and before composition, so an
	// untrusted repository's settings reach neither.
	GateTrust func(home, projectRoot, launchDir string) trust.Decision
	// ScaffoldProjectIgnore scaffolds the commented <project-root>/.codemeld/codemeldignore
	// template, creating it only when absent. It runs immediately after
	// project-root resolution and before config/VCS/tool setup (step 2.5) so the project
	// .codemeld directory and starter file exist before any later step reads the project
	// tree. The production step is best-effort (it never aborts the launch).
	ScaffoldProjectIgnore func(projectRoot string) error
	// RecoverJournals puts back the writes of a child agent whose codemeld process was killed
	// before it could unwind them, for the project folder being opened (step 2.6). It returns
	// nothing because recovery must never block a launch: what it could not do is reported and the
	// launch continues.
	RecoverJournals func(home, projectRoot string)
	// ComposeConfig composes the config layers (step 3).
	ComposeConfig func(global map[string]any, projectRoot string) (composition ConfigComposition, err error)
	// LoadVCSTemplates loads built-in and project VCS templates (step 4). projectLayer is
	// step 3's verified project settings map (nil when none was composed), carried here so
	// vcs.preferred source attribution reuses it rather than reading the file again.
	// approved is the launch's trust outcome; the step derives no trust of its own.
	LoadVCSTemplates func(home, projectRoot string, projectLayer map[string]any, approved bool) (templates any, err error)
	// ValidatePreferredVCS cross-reference-validates vcs.preferred (step 5).
	ValidatePreferredVCS func(composed map[string]any, templates any) error
	// DetectVCS runs auto-detection, returning the active template or nil (step 6).
	DetectVCS func(cwd string, composed map[string]any, templates any) (active any, err error)
	// BuildToolRegistry builds the tool registry (step 6c).
	BuildToolRegistry func(active any) (registry any, err error)
	// DetermineModel determines the active model (steps 7/7a) through the config→
	// model bridge: it builds a config.Cache from the composed config, the project
	// root, and the global-first/project-last layer paths (using global to attribute
	// each path-4 provider diagnostic to its source settings file), calls
	// model.DetermineSelection, and returns the run-scoped *model.ActiveState. It also
	// reports pickerRequired=true for the path-4 selectable-model outcome (a
	// model picker must open) and returns the path-4 *NoSelectableModelError
	// when no model is installed.
	DetermineModel func(composed, global map[string]any, projectRoot string, layerPaths []string) (selection any, pickerRequired bool, err error)
	// EnsureFreshSession ensures the sessions dir, mints the id, and writes the
	// folder file (step 7b).
	EnsureFreshSession func(home, projectRoot string) (session *sessions.Store, err error)
	// FlushSessionTitle persists a caller-supplied session name (codemeld run --title)
	// as soon as the session exists and before any launch record is appended, so an
	// interrupt anywhere in the rest of the launch still leaves the session named on
	// disk. It returns nothing because losing the name must not kill the run: the
	// headless adapter routes a write failure through the metadata-notice path and
	// discards it. nil for launches that carry no title, which is every interactive one.
	FlushSessionTitle func(ctx context.Context, session *sessions.Store)
	AcquireLock       func(sessionPath, id string) (release func(), err error)
	// AppendLaunchBegan appends exactly one launch_began event, source: fresh
	// (step 7b1) — after session creation and before AGENTS.md load.
	AppendLaunchBegan func(ctx context.Context, session *sessions.Store) error
	// InitMode resolves mode.default from the composed config, appends the
	// session-start interaction_mode{trigger:"launch"} durably (same write-failure
	// policy as launch_began), and returns the run-scoped *mode.ActiveState (step
	// 7b2) — after launch_began and before AGENTS.md load. The active mode is never
	// inherited from a prior session: launch always starts from mode.default.
	// projectRoot/layerPaths feed the config.Cache mode.default is read
	// from, the same source the model and AGENTS.md steps use.
	InitMode func(ctx context.Context, session *sessions.Store, composed map[string]any, projectRoot string, layerPaths []string) (modeState any, err error)
	// LoadAgentInstructions discovers AGENTS.md files, replays one
	// agent_instructions_loaded event per file into the session stream, flushes so
	// the records are durable, and returns the in-memory load record (step 7c). The
	// walk anchor is launchDir (the launch CWD), not projectRoot: the AGENTS.md loader
	// always walks from the launch directory to the filesystem root, independent of
	// discovery.boundary, so the resolved project root must not be substituted here.
	// composed/projectRoot/layerPaths feed the config.Cache the per-file size cap is
	// read from. The returned record is surfaced on BootstrapResult so the /status
	// overlay and /clear replay reuse it without re-walking the disk.
	LoadAgentInstructions func(ctx context.Context, session *sessions.Store, home, launchDir string, composed map[string]any, projectRoot string, layerPaths []string) ([]agentinstr.LoadEntry, error)
	// StartTUI starts the TUI (step 8).
	StartTUI func(ctx context.Context, result *BootstrapResult) error
}

// RunFresh runs the fresh-launch bootstrap, invoking steps in the exact
// order (0a, 0, 1-8). Each step runs only when every preceding step returned
// nil. Step 0 short-circuits the whole sequence when first-run generation runs.
// RunFresh never prints; it returns errors for the CLI layer to render.
//
// On the first-run branch it returns (nil, nil): the launch is complete and the
// caller exits 0. On any step failure it returns (nil, err). On a full launch it
// returns the populated result.
//
// RunFresh is the interactive (TUI) launch: it runs the shared bootstrap core
// (steps 0a–7c) and then step 8, StartTUI. The headless run reuses the same
// runFreshCore and substitutes its own one-shot driver for StartTUI, so the two
// launch paths share identical bootstrap state assembly.
func RunFresh(ctx context.Context, cwd string, steps FreshSteps) (*BootstrapResult, error) {
	res, firstRun, err := runFreshCore(ctx, cwd, steps)
	if err != nil {
		return nil, err
	}
	if firstRun {
		// Step 0 ran first-run generation and short-circuited the sequence; the launch
		// is complete and the caller exits 0.
		return nil, nil
	}

	if res.ResumeLockRelease != nil {
		defer res.ResumeLockRelease()
	}

	// 8 — start the TUI.
	if err := steps.StartTUI(ctx, res); err != nil {
		return nil, err
	}
	return res, nil
}

// runFreshCore runs steps 0a–7c — every fresh-launch step except step 8's
// terminal launch (StartTUI) — and returns the assembled BootstrapResult. It is the
// shared bootstrap core both the interactive launch (RunFresh, which then runs
// StartTUI) and the headless run (RunHeadless, which then runs its one-shot driver)
// drive, so neither path can drift from the other's bootstrap state assembly.
//
// On the step-0 first-run branch it returns (nil, true, nil): first-run generation
// ran and the caller must exit 0 without launching. On any step failure it returns
// (nil, false, err). On a completed core it returns (res, false, nil).
func runFreshCore(ctx context.Context, cwd string, steps FreshSteps) (res *BootstrapResult, firstRun bool, err error) {
	res = &BootstrapResult{LaunchDir: cwd}

	// 0a — resolve home before any ~-bearing path is dereferenced.
	home, err := steps.ResolveHome()
	if err != nil {
		return nil, false, &HomeResolveError{Err: err}
	}
	res.Home = home

	// 0 — first-run generation when settings are absent; exit before step 1.
	ran, err := steps.RunFirstRun(home)
	if err != nil {
		return nil, false, err
	}
	if ran {
		return nil, true, nil
	}

	// 1 — load global settings.
	global, err := steps.LoadGlobalSettings(home)
	if err != nil {
		return nil, false, err
	}

	// 2 — walk for the project root and capture its settings.yaml layer(s).
	root, projectLayers, err := steps.ResolveProjectRoot(cwd, global)
	if err != nil {
		return nil, false, err
	}
	res.ProjectRoot = root

	// 2b — decide whether this repository is trusted before its settings can be published
	// as a source or composed.
	res.TrustDecision = steps.GateTrust(home, root, cwd)
	res.WithheldInputs = withheldInputs(root, res.TrustDecision.Trusted)
	composeRoot := root
	if !vcsTemplatesApproved(res.TrustDecision) {
		projectLayers = nil
		composeRoot = ""
	}

	// Preserve the ordered /status config sources (item 10): the global
	// settings.yaml first, then the project-side layer(s) above — global-first,
	// project-last (layer order). With no project layer, only global remains.
	res.ConfigLayerPaths = append([]string{SettingsPath(home)}, projectLayers...)

	// 2.5 — scaffold the project codemeldignore template after project-root resolution and
	// before any config/VCS/tool setup reads the project tree.
	if err := steps.ScaffoldProjectIgnore(root); err != nil {
		return nil, false, err
	}

	// 2.6 — put back the child agent writes a killed launch left behind, before any later step
	// reads the project tree.
	if steps.RecoverJournals != nil {
		steps.RecoverJournals(home, root)
	}

	// 3 — compose config layers.
	composition, err := steps.ComposeConfig(global, composeRoot)
	if err != nil {
		return nil, false, err
	}
	composed := composition.Config
	res.Config = composed
	res.SettingsLayers = settingsLayerSnapshots(home, root, global, res.TrustDecision.Trusted, composition)

	// 4 — load VCS templates.
	templates, err := steps.LoadVCSTemplates(home, root, composition.ProjectLayer, vcsTemplatesApproved(res.TrustDecision))
	if err != nil {
		return nil, false, err
	}

	// 5 — cross-reference-validate vcs.preferred.
	if err := steps.ValidatePreferredVCS(composed, templates); err != nil {
		return nil, false, err
	}

	// 6 — run VCS auto-detection.
	active, err := steps.DetectVCS(cwd, composed, templates)
	if err != nil {
		return nil, false, err
	}
	res.VCSTemplate = active

	// 6c — build the tool registry (only built-ins when no active template).
	registry, err := steps.BuildToolRegistry(active)
	if err != nil {
		return nil, false, err
	}
	res.ToolRegistry = registry

	// 7/7a — determine the active model through the config→model bridge; the path-4
	// no-selectable-model exit surfaces here as an error before any session work
	// begins, and a path-4 selectable outcome sets the picker-required launch flag.
	model, pickerRequired, err := steps.DetermineModel(composed, global, root, res.ConfigLayerPaths)
	if err != nil {
		return nil, false, err
	}
	res.Model = model
	res.ModelPickerRequired = pickerRequired

	// 7b — ensure sessions dir, mint id, write folder file.
	session, err := steps.EnsureFreshSession(home, root)
	if err != nil {
		return nil, false, err
	}
	res.Session = session
	// Before launch_began and every later record: the session file now exists, so a
	// cancellation or failure from here on must not be able to leave it unnamed.
	if steps.FlushSessionTitle != nil {
		steps.FlushSessionTitle(ctx, session)
	}
	// a normal interactive launch background-prunes once the active
	// session exists to receive the session_prune_summary; the fresh session's
	// updated_at is current, so the pass cannot prune it. StartTUI starts the pass
	// after installing the active store.
	res.BackgroundPrune = true

	release, err := steps.AcquireLock(session.Path(), session.SessionID())
	if err != nil {
		return nil, false, err
	}
	var releaseOnce sync.Once
	releaseFresh := func() { releaseOnce.Do(release) }
	res.ResumeLockRelease = releaseFresh
	defer func() {
		if err != nil {
			releaseFresh()
		}
	}()

	// 7b1 — append the single launch_began (source: fresh) after session
	// creation and before AGENTS.md load.
	if err := steps.AppendLaunchBegan(ctx, session); err != nil {
		return nil, false, err
	}

	// 7b2 — initialize the active mode from mode.default and durably append the
	// session-start interaction_mode{trigger:"launch"}. It runs after
	// launch_began so launch_began stays the session anchor.
	modeState, err := steps.InitMode(ctx, session, composed, root, res.ConfigLayerPaths)
	if err != nil {
		return nil, false, err
	}
	res.Mode = modeState

	// 7c — load AGENTS.md files into the session record stream and retain the
	// in-memory load record for the /status overlay and /clear replay. The walk
	// anchor is the launch CWD (cwd), not the resolved project root (root): the
	// loader walks from the launch directory independent of discovery.boundary.
	entries, err := steps.LoadAgentInstructions(ctx, session, home, cwd, composed, root, res.ConfigLayerPaths)
	if err != nil {
		return nil, false, err
	}
	res.AgentInstructions = entries

	return res, false, nil
}

// DefaultFreshSteps returns the production step set. The steps owned by landed
// tasks are wired: ResolveHome, step-0 first-run, global-settings load,
// project-root resolution, config composition, the step-4 through step-6 VCS
// detection chain (LoadVCSTemplates, ValidatePreferredVCS, DetectVCS), the
// step-6c registry factory, model determination, fresh-session
// creation, the step-7b1 launch_began event, the step-7c AGENTS.md load, and the
// step-8 production launch. stdout/stderr are threaded into the
// first-run runner (which prints its own first-run message and OP_FAIL lines) and
// into the VCS detection step (which prints skipped-directory and ambiguity
// warnings to stderr before the TUI starts), plus launch_began write-failure
// notices before the TUI exists.
func DefaultFreshSteps(stdout, stderr io.Writer) FreshSteps {
	notices := stderrNoticeRenderer{w: stderr}
	return FreshSteps{
		ResolveHome: paths.ResolveHome,
		RunFirstRun: func(home string) (bool, error) {
			return defaultRunFirstRun(home, stdout, stderr)
		},
		LoadGlobalSettings: defaultLoadGlobalSettings,
		ResolveProjectRoot: func(cwd string, global map[string]any) (string, []string, error) {
			return defaultResolveProjectRoot(cwd, global, stderr)
		},
		GateTrust: interactiveTrustGate(os.Stdin, stderr),
		ScaffoldProjectIgnore: func(projectRoot string) error {
			return ScaffoldProjectCodemeldignore(projectRoot, stderr)
		},
		RecoverJournals: func(home, projectRoot string) {
			recoverChildJournals(home, projectRoot, os.Stdin, stderr, stdinIsTerminal(os.Stdin))
		},
		ComposeConfig:        defaultComposeConfig,
		LoadVCSTemplates:     loadVCSTemplates,
		ValidatePreferredVCS: validatePreferredVCS,
		DetectVCS: func(cwd string, composed map[string]any, templates any) (any, error) {
			return detectVCS(cwd, composed, templates, stderr)
		},
		BuildToolRegistry: defaultBuildToolRegistry,
		DetermineModel: func(composed, global map[string]any, projectRoot string, layerPaths []string) (any, bool, error) {
			return launchModelStep(composed, global, projectRoot, layerPaths, false, nil, stderr)
		},
		EnsureFreshSession: func(home, projectRoot string) (*sessions.Store, error) {
			canonicalFolder, err := sessions.CanonicalizeFolder(projectRoot)
			if err != nil {
				return nil, err
			}
			return sessions.EnsureSession(home, canonicalFolder, time.Now().UTC(), nil)
		},
		AcquireLock: sessions.AcquireResumeLock,
		AppendLaunchBegan: func(ctx context.Context, store *sessions.Store) error {
			return appendLaunchBegan(ctx, store, "fresh", notices)
		},
		InitMode: func(ctx context.Context, store *sessions.Store, composed map[string]any, projectRoot string, layerPaths []string) (any, error) {
			return initLaunchMode(ctx, store, composed, projectRoot, layerPaths, mode.TriggerLaunch, notices)
		},
		LoadAgentInstructions: loadAgentInstructions,
		StartTUI: func(ctx context.Context, result *BootstrapResult) error {
			return StartTUI(ctx, result, stdout)
		},
	}
}

// loadAgentInstructions is the production step-7c adapter shared by the fresh and
// resume launch paths (step 7c). It discovers the AGENTS.md files — the
// global file then a farthest-first walk from launchDir to the filesystem root
// — replays one agent_instructions_loaded event per file into session, and
// flushes so those records are durable at the step-7c boundary. The walk anchor is
// launchDir (the launch CWD), not the resolved project root: the loader walks from the
// launch directory independent of discovery.boundary. The per-file size cap comes
// from the composed config via the shared config.Cache (default 65536), the
// same source the model step reads, so the cap is never re-derived from a duplicated
// default.
//
// A flush failure is fatal here. Step 7c runs before the TUI, so it uses the
// clean-shutdown write-failure protocol: retry once, write the OP_FAIL line on the
// second failure, then abort the launch with a quiet status-1 sentinel.
func loadAgentInstructions(ctx context.Context, session *sessions.Store, home, launchDir string, composed map[string]any, projectRoot string, layerPaths []string) ([]agentinstr.LoadEntry, error) {
	if composed == nil {
		composed = map[string]any{}
	}
	cache, err := config.NewCache(composed, projectRoot, layerPaths)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: agent-instructions config cache: %w", err)
	}
	entries, err := agentinstr.LoadAgentInstructions(home, launchDir, cache.AgentInstructionsMaxFileBytes())
	if err != nil {
		return nil, err
	}
	if err := agentinstr.Replay(session, entries); err != nil {
		return nil, err
	}
	if err := sessionfailures.CleanShutdownFlush(ctx, session); err != nil {
		return nil, ErrSessionWriteOnExit
	}
	return entries, nil
}

// initLaunchMode is the production step-7b2 adapter shared by the fresh and resume
// launch paths (step 7b2). It resolves mode.default
// from the composed config via the shared config.Cache — the same source the model
// and AGENTS.md steps read — seeds the run-scoped *mode.ActiveState from it (always
// from mode.default, never from a prior session), and durably appends the
// session-start interaction_mode event with the given trigger ("launch" on a fresh
// launch, "resume" on a cold-start resume). The recorded source is "config" when
// mode.default was present and "default" otherwise. Durability mirrors
// appendLaunchBegan: emitInteractionMode appends and flushes, routing an atomic-write
// failure through the sessionfailures write-failure protocol so a write failure carries forward like the
// adjacent launch_began rather than aborting the launch.
func initLaunchMode(ctx context.Context, store *sessions.Store, composed map[string]any, projectRoot string, layerPaths []string, trigger mode.Trigger, ui tui.NoticeRenderer) (any, error) {
	if composed == nil {
		composed = map[string]any{}
	}
	cache, err := config.NewCache(composed, projectRoot, layerPaths)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: mode config cache: %w", err)
	}
	modeValue, configured := cache.ModeDefault()
	source := mode.SourceDefault
	if configured {
		source = mode.SourceConfig
	}
	active := mode.NewActiveState(mode.Mode(modeValue), source)
	if err := emitInteractionMode(ctx, store, active, trigger, ui); err != nil {
		return nil, err
	}
	return active, nil
}

const journalRecoveryPrompt = `codemeld: %s changed after the child agent run that was interrupted, so codemeld will not put it back on its own.
  [k] keep the file as it is now
  [r] put back the version from before the child agent ran
  [d] decide later (default)
Keep, put back, or decide later? [k/r/d] `

// stdinIsTerminal is the tty seam the step-2.6 recovery prompt is gated on. It is a variable so a
// test can force it true and prove the headless step still never reads stdin.
var stdinIsTerminal = func(stdin io.Reader) bool { return term.IsTerminal(streamFd(stdin)) }

// recoverChildJournals runs the step-2.6 recovery pass and reports it on stderr, where the other
// pre-TUI launch notices go. A launch with no one to answer defers every changed path to a launch
// that can ask rather than deciding for the user.
func recoverChildJournals(home, projectRoot string, stdin io.Reader, stderr io.Writer, interactive bool) {
	if projectRoot == "" {
		return
	}
	var ask func(subagent.Unresolved) subagent.Choice
	if interactive {
		// One reader for the whole pass: a reader per question would drop the input the previous
		// question buffered past its own line.
		reader := bufio.NewReader(stdin)
		ask = func(u subagent.Unresolved) subagent.Choice { return askJournalChoice(reader, stderr, u) }
	}
	reportJournalRecovery(stderr, subagent.Recover(home, projectRoot, ask))
}

func askJournalChoice(reader *bufio.Reader, stderr io.Writer, u subagent.Unresolved) subagent.Choice {
	if len(u.Moves) > 0 {
		writeMoveGroupPrompt(stderr, u)
	} else {
		_, _ = fmt.Fprintf(stderr, journalRecoveryPrompt, shown(u.Path))
	}
	line, err := reader.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	if err != nil && (answer == "" || len(u.Moves) > 0) {
		return subagent.ChoiceDefer
	}
	switch answer {
	case "k", "keep":
		return subagent.ChoiceKeep
	case "r", "restore", "put back":
		return subagent.ChoiceRestore
	default:
		return subagent.ChoiceDefer
	}
}

func writeMoveGroupPrompt(stderr io.Writer, u subagent.Unresolved) {
	_, _ = fmt.Fprintln(stderr, "codemeld: these moves by an interrupted child agent run changed afterwards, so codemeld will not undo them on its own:")
	for _, move := range u.Moves {
		label := "move"
		if move.Pending {
			label = "attempted move, outcome unknown"
		}
		_, _ = fmt.Fprintf(stderr, "  %s: %s -> %s\n", label, shown(move.Source), shown(move.Destination))
	}
	_, _ = fmt.Fprintln(stderr, "  [k] keep every path named above as it is now")
	if slices.Contains(u.Choices, subagent.ChoiceRestore) {
		_, _ = fmt.Fprintln(stderr, "  [r] put every path named above back to how it was before the child agent ran")
		_, _ = fmt.Fprintln(stderr, "  [d] decide later (default)")
		_, _ = fmt.Fprint(stderr, "Keep, put back, or decide later? [k/r/d] ")
		return
	}
	_, _ = fmt.Fprintln(stderr, "  [d] decide later (default)")
	_, _ = fmt.Fprintf(stderr, "  put back is not available: %s\n", shown(u.RestoreRefusal))
	_, _ = fmt.Fprint(stderr, "Keep or decide later? [k/d] ")
}

func reportJournalRecovery(stderr io.Writer, report subagent.Report) {
	if report.Empty() {
		return
	}
	if len(report.LeftAlone) > 0 {
		_, _ = fmt.Fprintln(stderr, "codemeld: could not tell whether a child agent run recorded here has ended, so its files were left as they are.")
		for _, left := range report.LeftAlone {
			_, _ = fmt.Fprintf(stderr, "  left alone: %s (%s)\n", shown(left.Path), shown(left.Reason))
		}
	}
	if len(report.Restored) > 0 || len(report.Kept) > 0 || len(report.Retained) > 0 {
		_, _ = fmt.Fprintln(stderr, "codemeld: a previous session ended while a child agent was still writing files.")
		for _, path := range report.Restored {
			_, _ = fmt.Fprintf(stderr, "  put back: %s\n", shown(path))
		}
		for _, path := range report.Kept {
			_, _ = fmt.Fprintf(stderr, "  kept as it is now, as you asked: %s\n", shown(path))
		}
		for _, retained := range report.Retained {
			for _, note := range retained.Notes {
				_, _ = fmt.Fprintf(stderr, "  not put back: %s\n", shown(note))
			}
			for _, dir := range retained.Dirs {
				_, _ = fmt.Fprintf(stderr, "  left in place: %s (codemeld does not delete a directory a child agent created once it holds other entries or was replaced)\n", shown(dir))
			}
			if len(retained.Moves) == 0 && len(retained.Dirs) == 0 {
				_, _ = fmt.Fprintf(stderr, "  codemeld asks what to do with these files the next time you start it here; its record of the run is %s\n", shown(retained.Path))
				continue
			}
			if len(retained.Notes) > 0 {
				_, _ = fmt.Fprintln(stderr, "  codemeld asks what to do with these files the next time you start it here")
			}
			reportHeldMoves(stderr, retained.Moves, false, "  codemeld asks what to do with these moves the next time you start it here interactively")
			reportHeldMoves(stderr, retained.Moves, true, "  codemeld tries again to finish undoing these interrupted moves the next time you start it here; it does not ask about them")
			_, _ = fmt.Fprintf(stderr, "  its record of the run is %s\n", shown(retained.Path))
		}
	}
}

func reportHeldMoves(stderr io.Writer, moves []subagent.HeldMove, resumes bool, instruction string) {
	listed := false
	for _, move := range moves {
		if move.Resumes != resumes {
			continue
		}
		_, _ = fmt.Fprintf(stderr, "  move not undone: %s -> %s (%s)\n", shown(move.Source), shown(move.Destination), shown(move.Reason))
		listed = true
	}
	if listed {
		_, _ = fmt.Fprintln(stderr, instruction)
	}
}

func shown(s string) string {
	if utf8.ValidString(s) && !strings.ContainsAny(s, `"\`) && !strings.Contains(s, " -> ") && !strings.Contains(s, ": ") &&
		!strings.Contains(s, " (") && !strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsGraphic(r) }) {
		return s
	}
	return strconv.QuoteToGraphic(s)
}

// errUnsafeSettingsRead names no distinguishing detail on purpose: the refused path is
// attacker-influenced, so the reason must not report which check rejected it.
var errUnsafeSettingsRead = errors.New("settings file could not be read safely")

func defaultLoadGlobalSettings(home string) (map[string]any, error) {
	path := SettingsPath(home)
	config.WarnIfBroaderThan0600(path)
	data, found, ok := fsutil.ReadSettingsBytes(path)
	switch {
	case !ok:
		return nil, errors.New(config.FormatLoadError(path, config.UnreadableFile, errUnsafeSettingsRead, config.LaunchAborted))
	case !found:
		return nil, errors.New(config.FormatLoadError(path, config.UnreadableFile, fs.ErrNotExist, config.LaunchAborted))
	}
	raw, cat, err := config.ValidateGlobalSettingsBytes(data, path)
	if cat != config.LoadOK {
		return nil, errors.New(config.FormatLoadError(path, cat, err, config.LaunchAborted))
	}
	return raw, nil
}

func defaultResolveProjectRoot(cwd string, global map[string]any, stderr io.Writer) (string, []string, error) {
	root, layers, warnings, err := config.LocateProjectRoot(cwd, discoveryBoundary(global))
	for _, warning := range warnings {
		_, _ = fmt.Fprintln(stderr, warning)
	}
	if err != nil {
		var anchorErr *config.AnchorReadError
		if errors.As(err, &anchorErr) {
			return "", nil, errors.New(fserrors.FormatOpFail(anchorErr.Operation, anchorErr.Anchor, anchorErr.Category))
		}
		return "", nil, err
	}
	return root, layers, nil
}

func defaultComposeConfig(global map[string]any, projectRoot string) (ConfigComposition, error) {
	project, present, err := readAdmittedProjectSettingsLayer(projectRoot)
	if err != nil {
		return ConfigComposition{}, err
	}
	local, localPresent, err := readAdmittedLocalSettingsLayer(projectRoot)
	if err != nil {
		return ConfigComposition{}, err
	}
	composed, err := config.Compose(global, project, local)
	if err != nil {
		return ConfigComposition{}, err
	}
	return ConfigComposition{
		Config:         composed,
		ProjectLayer:   project,
		ProjectPresent: present,
		LocalLayer:     local,
		LocalPresent:   localPresent,
	}, nil
}

func readAdmittedLocalSettingsLayer(projectRoot string) (raw map[string]any, present bool, err error) {
	if projectRoot == "" {
		return nil, false, nil
	}
	localPath := config.LocalSettingsPath(projectRoot)
	data, found, ok := fsutil.ReadSettingsBytes(localPath)
	switch {
	case !ok:
		return nil, false, errors.New(config.FormatLoadError(localPath, config.UnreadableFile, errUnsafeSettingsRead, config.LaunchAborted))
	case !found:
		return nil, false, nil
	}
	raw, cat, lerr := config.ValidateLocalSettingsBytes(data, localPath)
	if cat != config.LoadOK {
		return nil, false, errors.New(config.FormatLoadError(localPath, cat, lerr, config.LaunchAborted))
	}
	return raw, true, nil
}

// settingsLayerSnapshots builds the monitor handoff from the layers this launch admitted.
func settingsLayerSnapshots(home, projectRoot string, global map[string]any, trusted bool, composition ConfigComposition) []securitystate.LayerSnapshot {
	layers := []securitystate.LayerSnapshot{{
		Kind:    securitystate.LayerGlobal,
		Path:    SettingsPath(home),
		Present: true,
		Raw:     config.CopyLayer(global),
	}}
	if projectRoot == "" {
		return layers
	}
	project := securitystate.LayerSnapshot{Kind: securitystate.LayerProject, Path: projectSettingsPath(projectRoot)}
	switch {
	case !trusted:
		project.Ignored = true
	case composition.ProjectPresent:
		project.Present = true
		project.Raw = config.CopyLayer(composition.ProjectLayer)
	}
	local := securitystate.LayerSnapshot{Kind: securitystate.LayerLocal, Path: config.LocalSettingsPath(projectRoot)}
	switch {
	case !trusted:
		local.Ignored = true
	case composition.LocalPresent:
		local.Present = true
		local.Raw = config.CopyLayer(composition.LocalLayer)
	}
	return append(layers, project, local)
}

// projectSettingsPath returns <project-root>/.codemeld/settings.yaml, the per-project settings layer.
func projectSettingsPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".codemeld", "settings.yaml")
}

// vcsTemplatesApproved reports whether the launch may open the project template folder. A root the
// gate found nothing to cover is trusted by vacuity and carries no record, so a .codemeld/vcs
// directory that appeared after the gate ran was never approved by anyone.
func vcsTemplatesApproved(d trust.Decision) bool {
	return d.Trusted && d.Reason != trust.ReasonNothingCovered
}

// projectVCSTemplateDir returns <project-root>/.codemeld/vcs, the per-project VCS template layer.
func projectVCSTemplateDir(projectRoot string) string {
	return filepath.Join(projectRoot, ".codemeld", "vcs")
}

func readAdmittedProjectSettingsLayer(projectRoot string) (raw map[string]any, present bool, err error) {
	if projectRoot == "" {
		return nil, false, nil
	}
	projectPath := projectSettingsPath(projectRoot)
	data, found, ok := fsutil.ReadSettingsBytes(projectPath)
	switch {
	case !ok:
		return nil, false, errors.New(config.FormatLoadError(projectPath, config.UnreadableFile, errUnsafeSettingsRead, config.LaunchAborted))
	case !found:
		return nil, false, nil
	}
	raw, cat, lerr := config.ValidateProjectSettingsBytes(data, projectPath)
	if cat != config.LoadOK {
		return nil, false, errors.New(config.FormatLoadError(projectPath, cat, lerr, config.LaunchAborted))
	}
	return raw, true, nil
}

func discoveryBoundary(global map[string]any) string {
	const fallback = "launch-dir-only"
	discovery, ok := global["discovery"].(map[string]any)
	if !ok {
		return fallback
	}
	boundary, ok := discovery["boundary"].(string)
	if !ok || boundary == "" {
		return fallback
	}
	return boundary
}

// defaultRunFirstRun implements step 0: when ~/.codemeld/global/settings.yaml is
// absent it runs first-run generation (dirs, then built-in VCS templates, then
// settings) and reports ran=true; when present it reports ran=false
// so bootstrap proceeds to step 1. The directory step runs first because
// WriteFirstRunSettings requires its parent directories to already exist.
func defaultRunFirstRun(home string, stdout, stderr io.Writer) (bool, error) {
	path := SettingsPath(home)
	// Lstat, not Stat: a dangling final symlink reports absence through Stat, and generation
	// would then write settings through the link into whatever it names.
	switch info, err := os.Lstat(path); {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return false, errors.New(config.FormatLoadError(path, config.UnreadableFile, errUnsafeSettingsRead, config.LaunchAborted))
	case err == nil:
		return false, nil // settings present; proceed to step 1
	case errors.Is(err, fs.ErrNotExist):
		// absent: fall through to first-run generation
	default:
		return false, err
	}

	if code := RunEnsureFirstRunDirs(home, stderr); code != 0 {
		return true, ErrFirstRunFailed
	}
	if code := RunMaterializeBuiltinTemplates(home, stderr); code != 0 {
		return true, ErrFirstRunFailed
	}
	if code := RunScaffoldGlobalCodemeldignore(home, stderr); code != 0 {
		return true, ErrFirstRunFailed
	}
	if code := RunWriteSettings(home, stdout, stderr); code != 0 {
		return true, ErrFirstRunFailed
	}
	return true, nil
}
