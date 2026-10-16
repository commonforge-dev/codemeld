// Tests for the production /clear capability implementations (cleardeps.go): each
// of the five /clear capability interfaces, plus the pre-switch flush-failure path that
// refuses the swap and leaves the active session unchanged.
package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

func TestClearStreamCanceller_ReportsNoInFlightStream(t *testing.T) {
	if retained, inFlight := (clearStreamCanceller{}).Cancel(); retained != 0 || inFlight {
		t.Fatalf("Cancel() = (%d, %v), want (0, false) for inert fallback", retained, inFlight)
	}
}

type inFlightStreamCanceller struct{ retainedChars int }

func (c inFlightStreamCanceller) Cancel() (int, bool) { return c.retainedChars, true }

func TestNewClearDeps_UsesInstalledAppStreamCanceller(t *testing.T) {
	app := tui.New(nil)
	app.SetStreamCanceller(inFlightStreamCanceller{retainedChars: 41})

	deps := newClearDeps(context.Background(), app, &BootstrapResult{Home: t.TempDir()}, selectedState(), selectedModeState(), &resumeLockHolder{}, fixedRecorder(injectedResolution), nil)
	retained, inFlight := deps.Stream.Cancel()
	if !inFlight || retained != 41 {
		t.Fatalf("ClearDeps.Stream.Cancel() = (%d, %v), want (41, true) from app's live canceller", retained, inFlight)
	}
}

func TestClearSessionSwapper_FreshSwapsActiveStoreAndEmitsLaunchBegan(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	folder := t.TempDir()
	app := tui.New(nil)
	app.SetActiveStore(storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior", folder))

	sw := &clearSessionSwapper{app: app, ctx: ctx, home: home, recorder: fixedRecorder(injectedResolution)}
	fresh, err := sw.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	if fresh == nil {
		t.Fatal("Fresh returned a nil store")
	}
	if app.ActiveStore() != fresh {
		t.Fatal("Fresh did not install the new store as the app's active session")
	}
	if got := fresh.MetadataSnapshot().Folder; got != folder {
		t.Fatalf("fresh session folder = %q, want the active store's folder %q", got, folder)
	}
	if got := len(kindEvents(t, fresh, events.KindLaunchBegan)); got != 1 {
		t.Fatalf("launch_began on the fresh store = %d, want 1", got)
	}
}

// TestClearSessionSwapper_FreshErrorsWithoutActiveStore pins that Fresh refuses to
// mint a session from stale state when the app has no active store, rather than
// silently falling back to a folder captured elsewhere.
func TestClearSessionSwapper_FreshErrorsWithoutActiveStore(t *testing.T) {
	sw := &clearSessionSwapper{app: tui.New(nil), ctx: context.Background(), home: t.TempDir()}
	if _, err := sw.Fresh(); err == nil {
		t.Fatal("Fresh with no active store = nil error, want a refusal")
	}
}

// TestClear_FreshFolderFollowsActiveStore pins that /clear must mint
// the fresh session under the folder of whichever session is active when it runs,
// not a folder snapshotted at TUI startup. It installs one active store, builds the
// production /clear deps over it, swaps App.ActiveStore() to a store in a different
// folder (the shape a later /resume produces), dispatches /new, and asserts the
// fresh session's metadata carries the second folder. It fails (fresh folder ==
// startup folder) if Fresh resolves the folder from anything but the active store.
func TestClear_FreshFolderFollowsActiveStore(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	startupFolder := t.TempDir()
	resumedFolder := t.TempDir()

	startup := storeAt(t, filepath.Join(t.TempDir(), "startup.json"), "startup", startupFolder)
	app := tui.New(nil)
	app.SetActiveStore(startup)

	result := &BootstrapResult{Home: home, Session: startup}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{
		"clear": tui.NewClearHandler(newClearDeps(ctx, app, result, selectedState(), selectedModeState(), &resumeLockHolder{}, fixedRecorder(injectedResolution), nil)),
	})
	submit := tui.NewSubmitFunc(reg, app, nil)

	// A later in-process swap (e.g. /resume) makes a different-folder session active.
	resumed := storeAt(t, filepath.Join(t.TempDir(), "resumed.json"), "resumed", resumedFolder)
	app.SetActiveStore(resumed)

	submit("/new")

	fresh := app.ActiveStore()
	if fresh == nil || fresh == startup || fresh == resumed {
		t.Fatalf("active store after /new = %p, want a freshly minted store (startup=%p resumed=%p)", fresh, startup, resumed)
	}
	if got := fresh.MetadataSnapshot().Folder; got != resumedFolder {
		t.Fatalf("fresh session folder = %q, want the active (resumed) folder %q, not the startup folder %q", got, resumedFolder, startupFolder)
	}
}

// TestClearSessionSwapper_FreshLaunchFlushFailure_RecordsAndContinues pins
// /clear's launch_began write: once the swap to the fresh store has
// happened, a launch_began flush failure records session_write_failed + renders
// the notice on the now-active fresh store and reports success, so the run
// continues on it rather than the error bubbling back to abort the switch and
// retain the typed /new input.
func TestClearSessionSwapper_FreshLaunchFlushFailure_RecordsAndContinues(t *testing.T) {
	ui := &recordingHost{}
	sw := &clearSessionSwapper{ctx: context.Background(), ui: ui}
	fresh := unwritableStore(t, "fresh-id", "/proj")

	if err := sw.emitFreshLaunch(fresh); err != nil {
		t.Fatalf("emitFreshLaunch should swallow a handled per-turn write failure, got %v", err)
	}
	if got := len(kindEvents(t, fresh, events.KindLaunchBegan)); got != 1 {
		t.Fatalf("launch_began on fresh = %d, want 1 (carried forward in memory)", got)
	}
	if got := len(kindEvents(t, fresh, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed on fresh = %d, want 1 (req 400a)", got)
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices rendered = %v, want exactly one (req 400a)", ui.notices)
	}
}

// TestClearSessionSwapper_FreshNonWriteLaunchFailureKeepsPriorActive pins that a
// non-write launch_began flush error must leave Fresh transactional. A cancelled
// context makes Store.Flush return ("", ReasonNone, context.Canceled) before any
// write — a non-write error cannot encode so emitFreshLaunch surfaces it instead
// of recording session_write_failed. Fresh
// must then return that error with the app still pointed at the prior store, so
// NewClearHandler's refusal does not strand the run on an uncommitted fresh
// session. It fails against the swap-before-flush ordering, where ActiveStore() is
// already the fresh store when the error returns.
func TestClearSessionSwapper_FreshNonWriteLaunchFailureKeepsPriorActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	home := t.TempDir()
	folder := t.TempDir()
	prior := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior", folder)
	app := tui.New(nil)
	app.SetActiveStore(prior)

	sw := &clearSessionSwapper{app: app, ctx: ctx, home: home, recorder: fixedRecorder(injectedResolution)}
	fresh, err := sw.Fresh()
	if err == nil {
		t.Fatal("Fresh = nil error on a cancelled launch flush, want the non-write error surfaced")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Fresh error = %v, want context.Canceled", err)
	}
	if fresh != nil {
		t.Fatalf("Fresh returned a store (%p) alongside the error; want nil", fresh)
	}
	if app.ActiveStore() != prior {
		t.Fatal("active store changed despite a non-write launch flush failure; Fresh must leave the prior store active")
	}
}

func TestClearSessionSwapper_FreshOwnsTargetBeforeInstallAndSourceRelease(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	folder := t.TempDir()
	prior := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior", folder)
	app := tui.New(nil)
	app.SetActiveStore(prior)

	priorRelease, err := sessions.AcquireResumeLock(prior.Path(), prior.SessionID())
	if err != nil {
		t.Fatalf("acquire prior lock: %v", err)
	}
	holder := &resumeLockHolder{}
	var order []string
	var activeAtSourceRelease *sessions.Store
	holder.handoff(func() {
		order = append(order, "source-release")
		activeAtSourceRelease = app.ActiveStore()
		priorRelease()
	})

	var acquiredActive *sessions.Store
	sw := &clearSessionSwapper{
		app: app, ctx: ctx, home: home, ui: &recordingHost{}, holder: holder, recorder: fixedRecorder(injectedResolution),
		acquire: func(path, id string) (func(), error) {
			order = append(order, "acquire")
			acquiredActive = app.ActiveStore()
			return sessions.AcquireResumeLock(path, id)
		},
	}
	sw.emit = func(fresh *sessions.Store) error {
		order = append(order, "launch")
		return sw.emitFreshLaunch(fresh)
	}

	fresh, err := sw.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	if len(order) != 3 || order[0] != "acquire" || order[1] != "launch" || order[2] != "source-release" {
		t.Fatalf("ownership order = %v, want [acquire launch source-release]", order)
	}
	if acquiredActive != prior {
		t.Errorf("active store at target acquisition = %p, want the source %p (acquire before install)", acquiredActive, prior)
	}
	if got := len(kindEvents(t, fresh, events.KindLaunchBegan)); got != 1 {
		t.Errorf("launch_began on the fresh target = %d, want 1 (initialize before install)", got)
	}
	if activeAtSourceRelease != fresh {
		t.Errorf("active store at source release = %p, want the fresh target %p (install before source release)", activeAtSourceRelease, fresh)
	}
	if app.ActiveStore() != fresh {
		t.Fatalf("active store after Fresh = %p, want the fresh target %p", app.ActiveStore(), fresh)
	}
	if resumeLockHeld(t, prior.Path()) {
		t.Error("source (prior) sidecar still held after the switch; the source token must be released")
	}
	if !resumeLockHeld(t, fresh.Path()) {
		t.Error("fresh target sidecar not held after the switch; the target token must be transferred into the holder")
	}
	holder.releaseHeld()
	if resumeLockHeld(t, fresh.Path()) {
		t.Error("fresh target sidecar still held after releasing the holder; the transferred token must be the current one")
	}
}

func TestClearSessionSwapper_FreshOwnershipFailuresRetainSource(t *testing.T) {
	t.Run("acquisition failure", func(t *testing.T) {
		home := t.TempDir()
		folder := t.TempDir()
		prior := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior", folder)
		app := tui.New(nil)
		app.SetActiveStore(prior)

		holder, released := clearHeldSource(t, prior)

		acqErr := errors.New("forced target acquisition failure")
		sw := &clearSessionSwapper{app: app, ctx: context.Background(), home: home, ui: &recordingHost{}, holder: holder,
			acquire: func(path, id string) (func(), error) { return nil, acqErr }}

		fresh, err := sw.Fresh()
		if !errors.Is(err, acqErr) {
			t.Fatalf("Fresh error = %v, want the acquisition failure", err)
		}
		if fresh != nil {
			t.Fatalf("Fresh returned a store %p alongside the acquisition error; want nil", fresh)
		}
		assertClearSourceRetained(t, app, prior, holder, released)
	})

	t.Run("fatal initialization failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		home := t.TempDir()
		folder := t.TempDir()
		prior := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior", folder)
		app := tui.New(nil)
		app.SetActiveStore(prior)

		holder, released := clearHeldSource(t, prior)

		var targetPath string
		sw := &clearSessionSwapper{app: app, ctx: ctx, home: home, ui: &recordingHost{}, holder: holder,
			acquire: func(path, id string) (func(), error) {
				targetPath = path
				return sessions.AcquireResumeLock(path, id)
			}}

		fresh, err := sw.Fresh()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Fresh error = %v, want the cancelled-initialization failure", err)
		}
		if fresh != nil {
			t.Fatalf("Fresh returned a store %p alongside the initialization error; want nil", fresh)
		}
		if targetPath == "" || resumeLockHeld(t, targetPath) {
			t.Errorf("tentative target sidecar still held after a fatal initialization failure (path %q)", targetPath)
		}
		assertClearSourceRetained(t, app, prior, holder, released)
	})

	t.Run("creation failure", func(t *testing.T) {
		badHome := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(badHome, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed unusable home: %v", err)
		}
		folder := t.TempDir()
		prior := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior", folder)
		app := tui.New(nil)
		app.SetActiveStore(prior)

		holder, released := clearHeldSource(t, prior)

		acquired := false
		sw := &clearSessionSwapper{app: app, ctx: context.Background(), home: badHome, ui: &recordingHost{}, holder: holder,
			acquire: func(path, id string) (func(), error) { acquired = true; return func() {}, nil }}

		fresh, err := sw.Fresh()
		if err == nil {
			t.Fatal("Fresh succeeded with an unusable home, want a creation failure")
		}
		if fresh != nil {
			t.Fatalf("Fresh returned a store %p alongside the creation error; want nil", fresh)
		}
		if acquired {
			t.Error("target token acquired despite a fresh-session creation failure; acquisition must follow creation")
		}
		assertClearSourceRetained(t, app, prior, holder, released)
	})
}

func clearHeldSource(t *testing.T, prior *sessions.Store) (*resumeLockHolder, *int) {
	t.Helper()
	release, err := sessions.AcquireResumeLock(prior.Path(), prior.SessionID())
	if err != nil {
		t.Fatalf("acquire source token: %v", err)
	}
	releases := 0
	return &resumeLockHolder{release: func() {
		releases++
		release()
	}}, &releases
}

func assertClearSourceRetained(t *testing.T, app *tui.App, prior *sessions.Store, holder *resumeLockHolder, sourceReleased *int) {
	t.Helper()
	if got := app.ActiveStore(); got != prior {
		t.Errorf("active store = %p, want the retained source %p", got, prior)
	}
	if *sourceReleased != 0 {
		t.Errorf("source token released %d times on failure, want 0", *sourceReleased)
	}
	if !resumeLockHeld(t, prior.Path()) {
		t.Error("source token was not current after the failed clear")
	}
	before := len(prior.Records())
	prior.Append(sessions.Message{ID: "clear-fail-append", Role: "user", Content: sessions.TextContent("still open"), Timestamp: testStart})
	if after := len(prior.Records()); after != before+1 {
		t.Errorf("source refused an append after failure: %d -> %d, want appendable", before, after)
	}
	holder.releaseHeld()
	if resumeLockHeld(t, prior.Path()) {
		t.Error("terminal cleanup did not release the retained source token")
	}
	holder.releaseHeld()
	if *sourceReleased != 1 {
		t.Errorf("source token released %d times after terminal cleanup, want 1", *sourceReleased)
	}
}

func TestClearSessionSwapper_CloseSealsPriorStore(t *testing.T) {
	prior := mkStore(t)
	if err := (&clearSessionSwapper{}).Close(prior); err != nil {
		t.Fatalf("Close: %v", err)
	}
	before := len(prior.Records())
	prior.Append(sessions.Message{ID: "late", Role: "user", Content: sessions.TextContent("late"), Timestamp: testStart})
	if len(prior.Records()) != before {
		t.Fatal("Close did not seal the prior store against further appends")
	}
}

func TestClearModelState_CarryForwardKeepsSelectionAndSource(t *testing.T) {
	active := selectedState() // openai/gpt-5.5/medium, source resume
	clearModelState{active: active}.CarryForward()
	sel, src, ok := active.Current()
	if !ok || sel.Provider != "openai" || sel.ID != "gpt-5.5" || sel.Effort != "medium" || src != model.SourceResume {
		t.Fatalf("after CarryForward Current() = (%+v, %q, %v), want openai/gpt-5.5/medium + resume", sel, src, ok)
	}
}

// TestClearModeState_CarryForwardEmitsClearEventWithCarriedSource pins
// for /clear: the production mode carry-forward keeps the active mode and its
// original source, and durably records interaction_mode{trigger:"clear"} into the
// fresh session with that carried source — so a mode a prior /mode switch selected
// (source user_command) carries forward rather than resetting to a launch default.
func TestClearModeState_CarryForwardEmitsClearEventWithCarriedSource(t *testing.T) {
	fresh := mkStore(t)
	state := mode.NewActiveState(mode.Plan, mode.SourceUserCommand)
	cms := clearModeState{active: state, ctx: context.Background(), ui: &recordingHost{}}

	if err := cms.CarryForward(fresh); err != nil {
		t.Fatalf("CarryForward: %v", err)
	}
	// Carry-forward keeps the mode and source unchanged on the run-scoped state.
	if m, src := state.Current(); m != mode.Plan || src != mode.SourceUserCommand {
		t.Fatalf("after CarryForward Current() = (%q, %q), want (plan, user_command)", m, src)
	}
	// The interaction_mode record is durable on disk with the carried-forward source.
	im := diskInteractionMode(t, readSessionFile(t, fresh.Path()))
	if len(im) != 1 || im[0].Mode != "plan" || im[0].Source != "user_command" || im[0].Trigger != "clear" {
		t.Fatalf("durable interaction_mode = %+v, want one {plan, user_command, clear}", im)
	}
}

// TestClearModeState_CarryForwardWriteFailureRecordsAndContinues pins for
// the /clear mode emission: once the swap has happened, an atomic-write failure on
// the interaction_mode flush records session_write_failed + renders the notice on
// the fresh store and reports success, so the completed switch stands rather than
// the error aborting it.
func TestClearModeState_CarryForwardWriteFailureRecordsAndContinues(t *testing.T) {
	ui := &recordingHost{}
	fresh := unwritableStore(t, "fresh-id", "/proj")
	cms := clearModeState{active: mode.NewActiveState(mode.Build, mode.SourceDefault), ctx: context.Background(), ui: ui}

	if err := cms.CarryForward(fresh); err != nil {
		t.Fatalf("CarryForward should swallow a handled per-turn write failure, got %v", err)
	}
	if got := len(kindEvents(t, fresh, events.KindInteractionMode)); got != 1 {
		t.Fatalf("interaction_mode on fresh = %d, want 1 (carried forward in memory)", got)
	}
	if got := len(kindEvents(t, fresh, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed on fresh = %d, want 1 (req 400a)", got)
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices rendered = %v, want exactly one (req 400a)", ui.notices)
	}
}

func TestClearAgentReplayer_ReplaysLoadRecord(t *testing.T) {
	target := mkStore(t)
	entries := []agentinstr.LoadEntry{
		{Path: "/g/AGENTS.md", Layer: agentinstr.LayerGlobal, LoadOrder: 1},
		{Path: "/w/AGENTS.md", Layer: agentinstr.LayerWalked, LoadOrder: 2},
	}
	if err := (clearAgentReplayer{entries: entries}).Replay(target); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := len(kindEvents(t, target, events.KindAgentInstructionsLoaded)); got != len(entries) {
		t.Fatalf("agent_instructions_loaded events = %d, want %d", got, len(entries))
	}
}

func TestClearWriteFailureSink_DelegatesToSessionfailures(t *testing.T) {
	store := mkStore(t)
	ui := &recordingHost{store: store}
	sink := clearWriteFailureSink{ui: ui}

	if err := sink.Handle(sessions.ReasonWriteError, fserrors.IOError, "/p/session.json", errors.New("disk full"), store); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (delegated to sessionfailures.HandleWriteFailure)", got)
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices rendered = %v, want exactly one", ui.notices)
	}
}

// TestClear_PreSwitchFlushFailure_LeavesActiveStoreUnchanged drives /new through
// the production registry against a prior store whose flush fails: the
// WriteFailureSink records session_write_failed, the swap is refused, and the
// active-session reference stays on the prior store.
func TestClear_PreSwitchFlushFailure_LeavesActiveStoreUnchanged(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	folder := t.TempDir()
	prior := unwritableStore(t, "prior", folder)
	app := tui.New(nil)
	app.SetActiveStore(prior)

	result := &BootstrapResult{Home: home, Session: prior}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{
		"clear": tui.NewClearHandler(newClearDeps(ctx, app, result, selectedState(), selectedModeState(), &resumeLockHolder{}, fixedRecorder(injectedResolution), nil)),
	})
	submit := tui.NewSubmitFunc(reg, app, nil)

	submit("/new")

	if app.ActiveStore() != prior {
		t.Fatal("active-session reference changed despite a pre-switch flush failure")
	}
	if got := len(kindEvents(t, prior, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed on prior = %d, want 1 (WriteFailureSink must run)", got)
	}
	if got := len(kindEvents(t, prior, events.KindLaunchBegan)); got != 0 {
		t.Fatalf("launch_began appeared (%d); the swap must be refused on flush failure", got)
	}
}

func injectedTempDir(t *testing.T) *confinement {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	old, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("create injected temp folder: %v", err)
	}
	return &confinement{tmpDir: old}
}

func stuckTempDir(t *testing.T) *confinement {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	t.Setenv("TMPDIR", t.TempDir())
	parent := t.TempDir()
	old := filepath.Join(parent, "old")
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	return &confinement{tmpDir: old}
}

func assertTempDirReplaced(t *testing.T, conf *confinement, old string) {
	t.Helper()
	if conf.tmpDir == "" || conf.tmpDir == old {
		t.Fatalf("tmpDir = %q, want a replacement for %q", conf.tmpDir, old)
	}
	info, err := os.Stat(conf.tmpDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("replacement %q: info %v, err %v; want an existing 0700 folder", conf.tmpDir, info, err)
	}
}

func assertTempDirKept(t *testing.T, conf *confinement, old string) {
	t.Helper()
	if conf.tmpDir != old {
		t.Fatalf("tmpDir = %q, want the old folder %q", conf.tmpDir, old)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("old folder: %v, want it kept", err)
	}
	if left, _ := filepath.Glob(filepath.Join(os.TempDir(), sessionTempDirPrefix+"*")); !slices.Equal(left, []string{old}) {
		t.Fatalf("temp folders = %v, want only the old %q", left, old)
	}
}

func clearSubmit(t *testing.T, app *tui.App, recorder *capabilityRecorder, conf *confinement) tui.SubmitFunc {
	t.Helper()
	result := &BootstrapResult{Home: t.TempDir(), Session: app.ActiveStore()}
	deps := newClearDeps(context.Background(), app, result, selectedState(), selectedModeState(), &resumeLockHolder{}, recorder, conf)
	status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})
	deps.Transcript = clearTranscriptResetter{app: app, status: status, conf: conf}
	return tui.NewSubmitFunc(tui.BuildRegistry(map[string]tui.HandlerFunc{"clear": tui.NewClearHandler(deps)}), app, nil)
}

func clearApp(t *testing.T) (*tui.App, *sessions.Store) {
	t.Helper()
	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "prior", t.TempDir())
	app.SetActiveStore(prior)
	return app, prior
}

func TestClear_RecordsTheLaunchCapabilityAfterLaunchBegan(t *testing.T) {
	app, prior := clearApp(t)
	if !clearSubmit(t, app, fixedRecorder(injectedResolution), nil)("/new") {
		t.Fatal("/new should be accepted")
	}
	fresh := app.ActiveStore()
	if fresh == prior {
		t.Fatal("active store not swapped after /new")
	}
	disk := readSessionFile(t, fresh.Path())
	kinds := eventKinds(disk.Records)
	began := slices.Index(kinds, events.KindLaunchBegan)
	if began < 0 || began+1 >= len(kinds) || kinds[began+1] != events.KindExecutionCapability {
		t.Fatalf("fresh kinds on disk = %v, want execution_capability right after launch_began", kinds)
	}
	caps := decodeDiskEvents[events.ExecutionCapability](t, disk, events.KindExecutionCapability)
	if len(caps) != 1 || !reflect.DeepEqual(caps[0], injectedCapability) {
		t.Fatalf("execution_capability on disk = %+v, want exactly %+v", caps, injectedCapability)
	}
}

func TestClearSessionSwapper_CapabilityRecordFailureKeepsThePriorSession(t *testing.T) {
	for _, tc := range []struct {
		name      string
		execution enforce.Resolution
		readOnly  bool
	}{
		{name: "append", execution: enforce.Resolution{}},
		{name: "flush", execution: injectedResolution, readOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.readOnly && os.Geteuid() == 0 {
				t.Skip("root can write a read-only file")
			}
			conf := injectedTempDir(t)
			old := conf.tmpDir
			app, prior := clearApp(t)
			holder, released := clearHeldSource(t, prior)
			var freshPath string
			sw := &clearSessionSwapper{app: app, ctx: context.Background(), home: t.TempDir(), ui: &recordingHost{}, holder: holder,
				recorder: fixedRecorder(tc.execution), conf: conf}
			sw.emit = func(fresh *sessions.Store) error {
				freshPath = fresh.Path()
				if err := sw.emitFreshLaunch(fresh); err != nil {
					return err
				}
				if tc.readOnly {
					return os.Chmod(fresh.Path(), 0o400)
				}
				return nil
			}

			fresh, err := sw.Fresh()
			if err == nil || fresh != nil {
				t.Fatalf("Fresh = (%p, %v), want a capability record error", fresh, err)
			}
			if freshPath == "" || resumeLockHeld(t, freshPath) {
				t.Errorf("fresh session lock still held after the failed record (path %q)", freshPath)
			}
			assertTempDirKept(t, conf, old)
			assertClearSourceRetained(t, app, prior, holder, released)
		})
	}
}

func TestClearSessionSwapper_ReplacesThePrivateTempFolder(t *testing.T) {
	newSwapper := func(t *testing.T, conf *confinement) (*clearSessionSwapper, *tui.App, *sessions.Store) {
		app, prior := clearApp(t)
		return &clearSessionSwapper{app: app, ctx: context.Background(), home: t.TempDir(), recorder: fixedRecorder(injectedResolution), conf: conf}, app, prior
	}

	t.Run("replaced", func(t *testing.T) {
		conf := injectedTempDir(t)
		old := conf.tmpDir
		sw, _, _ := newSwapper(t, conf)
		if _, err := sw.Fresh(); err != nil {
			t.Fatalf("Fresh: %v", err)
		}
		if _, err := os.Stat(old); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("old folder stat = %v, want it removed", err)
		}
		assertTempDirReplaced(t, conf, old)
		if len(conf.retryPaths) != 0 || conf.takeCleanupWarning() != "" {
			t.Fatalf("retry = %v, want none and no warning", conf.retryPaths)
		}
	})

	t.Run("replacement creation fails", func(t *testing.T) {
		conf := injectedTempDir(t)
		old := conf.tmpDir
		sw, app, prior := newSwapper(t, conf)
		t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
		if _, err := sw.Fresh(); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Fresh error = %v, want the temp folder error", err)
		}
		if app.ActiveStore() != prior || conf.tmpDir != old {
			t.Fatalf("active = %p tmpDir = %q, want prior %p and %q", app.ActiveStore(), conf.tmpDir, prior, old)
		}
		if _, err := os.Stat(old); err != nil {
			t.Fatalf("old folder: %v, want it kept", err)
		}
	})

	t.Run("old folder cleanup fails", func(t *testing.T) {
		conf := stuckTempDir(t)
		old := conf.tmpDir
		sw, app, prior := newSwapper(t, conf)
		fresh, err := sw.Fresh()
		if err != nil || app.ActiveStore() != fresh || fresh == prior {
			t.Fatalf("Fresh = (%p, %v), want the switch to stand", fresh, err)
		}
		assertTempDirReplaced(t, conf, old)
		if !slices.Equal(conf.retryPaths, []string{old}) {
			t.Fatalf("retry = %v, want [%s]", conf.retryPaths, old)
		}
		if w := conf.takeCleanupWarning(); !strings.HasPrefix(w, "can't remove private temp folder "+old+": ") || !strings.HasSuffix(w, "; codemeld retries when it exits") {
			t.Fatalf("warning = %q", w)
		}
	})

	t.Run("empty tmpDir", func(t *testing.T) {
		conf := &confinement{}
		sw, _, _ := newSwapper(t, conf)
		if _, err := sw.Fresh(); err != nil {
			t.Fatalf("Fresh: %v", err)
		}
		if conf.tmpDir != "" {
			t.Fatalf("tmpDir = %q, want it to stay empty", conf.tmpDir)
		}
	})
}

func TestClear_CleanupWarningStaysVisibleAfterTheReset(t *testing.T) {
	conf := stuckTempDir(t)
	old := conf.tmpDir
	app, prior := clearApp(t)
	if !clearSubmit(t, app, fixedRecorder(injectedResolution), conf)("/new") {
		t.Fatal("/new should be accepted")
	}
	if app.ActiveStore() == prior {
		t.Fatal("active store not swapped after /new")
	}
	if got := app.NoticeText(); !strings.HasPrefix(got, "can't remove private temp folder "+old+": ") {
		t.Fatalf("notice = %q, want the cleanup warning for %s", got, old)
	}
	if !strings.Contains(app.TranscriptText(), "codemeld") {
		t.Fatalf("transcript = %q, want the banner re-rendered", app.TranscriptText())
	}
}

var liveCapabilityCases = []struct {
	name   string
	launch enforce.Resolution
	broken bool
	want   events.ExecutionCapability
}{
	{name: "constrained, file broken", launch: constrainedLaunch, broken: true, want: brokenCapability},
	{name: "constrained, file valid", launch: constrainedLaunch, want: constrainedCapability},
	{name: "refused, file broken", launch: injectedResolution, broken: true, want: injectedCapability},
	{name: "refused, file valid", launch: injectedResolution, want: injectedCapability},
}

func TestClear_RecordsTheLiveCapabilityAfterASettingsChange(t *testing.T) {
	for _, tc := range liveCapabilityCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder, f := liveSettingsRecorder(t, tc.launch)
			setSettingsBroken(t, f, !tc.broken)
			recorder.blocked.Current()
			app, prior := clearApp(t)
			submit := clearSubmit(t, app, recorder, nil)

			setSettingsBroken(t, f, tc.broken)
			if !submit("/new") {
				t.Fatal("/new should be accepted")
			}
			fresh := app.ActiveStore()
			if fresh == prior {
				t.Fatal("active store not swapped after /new")
			}
			requireDiskCapabilities(t, fresh, tc.want)
		})
	}
}

func TestClear_TransitionQueuedDuringTheSwitchLandsInTheFreshSession(t *testing.T) {
	for _, recovers := range []bool{false, true} {
		t.Run(map[bool]string{false: "degrades", true: "recovers"}[recovers], func(t *testing.T) {
			recorder, f := liveSettingsRecorder(t, constrainedLaunch)
			setSettingsBroken(t, f, recovers)
			recorder.blocked.Current()
			app, prior := clearApp(t)
			hold := newRecordHold(t)
			records := watchCapabilityRecords(t, func(store *sessions.Store) {
				if store != prior {
					hold.block()
				}
			})
			runLiveDelivery(t, app, recorder)
			submit := clearSubmit(t, app, recorder, nil)
			accepted := make(chan bool, 1)
			go func() { accepted <- submit("/new") }()
			hold.waitEntered(t)
			fresh := nextCapabilityRecord(t, records, func(r storedCapability) bool { return r.store != prior }).store

			setSettingsBroken(t, f, !recovers)
			refreshWithin(t, recorder.blocked)
			waitForMutexWaitIn(t, "deliver")
			hold.open()

			if !receiveWithin(t, accepted, "/new") {
				t.Fatal("/new should be accepted")
			}
			if delivered := nextCapabilityRecord(t, records, func(storedCapability) bool { return true }); delivered.store != fresh {
				t.Fatalf("delivery recorded into %p, want the fresh session %p", delivered.store, fresh)
			}
			if app.ActiveStore() != fresh {
				t.Fatalf("active store = %p, want the fresh session %p", app.ActiveStore(), fresh)
			}
			requireDiskCapabilities(t, fresh, capabilityFor(recovers), capabilityFor(!recovers))
		})
	}
}
