// Tests for the production /resume capabilities (resumedeps.go): the
// refresh's write-failure routing, the loader's current-folder resolve +
// older classification, the lister's survivor projection + preview, the real
// step-1 model recovery, and the documented OlderSchemaForker no-op
// seam. The lock-state checks use locks.TryAcquire so "held vs released" is read
// non-blockingly off the same sidecar path the resume lock uses, with no real 2-second timeout.
package bootstrap

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"

	"github.com/rivo/uniseg"
)

// noticeSink is a tui.NoticeRenderer that records what was surfaced.
type noticeSink struct{ notices []string }

func (s *noticeSink) Notice(text string) { s.notices = append(s.notices, text) }

func TestNewResumeDeps_UsesInstalledAppStreamCanceller(t *testing.T) {
	app := tui.New(nil)
	app.SetStreamCanceller(inFlightStreamCanceller{retainedChars: 73})

	deps := newResumeDeps(context.Background(), app, &BootstrapResult{Home: t.TempDir()}, &resumeLockHolder{}, providerCache(t, t.TempDir()), selectedState(), fixedRecorder(injectedResolution), nil)
	retained, inFlight := deps.Stream.Cancel()
	if !inFlight || retained != 73 {
		t.Fatalf("ResumeDeps.Stream.Cancel() = (%d, %v), want (73, true) from app's live canceller", retained, inFlight)
	}
}

// resumeLockHeld reports, non-blockingly, whether the sidecar lock for
// sessionPath is currently held by another holder (the resumeSwitch under test).
// It probes the same sidecar path the resume lock uses via locks.TryAcquire: a contended
// result means held; a clean acquire means free, and the probe immediately releases
// the lock it just took so the check leaves the sidecar untouched.
func resumeLockHeld(t *testing.T, sessionPath string) bool {
	t.Helper()
	release, reason, err := locks.TryAcquire(sessions.ResumeLockPath(sessionPath))
	if err != nil {
		t.Fatalf("TryAcquire(%s): %v", sessionPath, err)
	}
	if reason == locks.ReasonLockContended {
		return true
	}
	if release != nil {
		release()
	}
	return false
}

func mustFlush(t *testing.T, s *sessions.Store) {
	t.Helper()
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush %s: %v", s.Path(), err)
	}
}

func TestResumeSwitch_TargetBeforeSourceAllowsBoundedOverlap(t *testing.T) {
	dir := t.TempDir()
	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(dir, "prior.json"), "01890000-0000-7000-8000-000000000001", "/proj")
	sessA := storeAt(t, filepath.Join(dir, "a.json"), "01890000-0000-7000-8000-000000000002", "/proj")
	sessB := storeAt(t, filepath.Join(dir, "b.json"), "01890000-0000-7000-8000-000000000003", "/proj")
	mustFlush(t, prior)
	mustFlush(t, sessA)
	mustFlush(t, sessB)
	app.SetActiveStore(prior)

	s := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: &resumeLockHolder{}}

	if err := s.Switch(sessA, prior); err != nil {
		t.Fatalf("switch prior->A: %v", err)
	}
	if _, err := os.Stat(sessions.ResumeLockPath(sessA.Path())); err != nil {
		t.Fatalf("A's sidecar lock not on disk: %v", err)
	}
	if !resumeLockHeld(t, sessA.Path()) {
		t.Error("A's resume lock is not held after switching to it")
	}
	if app.ActiveStore() != prior {
		t.Error("Switch installed the target as active before Activate; the switch window must expose no new active store")
	}
	if _, err := s.Activate(sessA); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if app.ActiveStore() != sessA {
		t.Error("active store not installed as A after Activate")
	}

	if err := s.Switch(sessB, sessA); err != nil {
		t.Fatalf("switch A->B: %v", err)
	}
	if !resumeLockHeld(t, sessB.Path()) {
		t.Error("B's resume lock is not held after acquiring it in Switch")
	}
	if !resumeLockHeld(t, sessA.Path()) {
		t.Error("A's resume lock was released before Activate; target-before-source must retain the source across the window")
	}
	if app.ActiveStore() != sessA {
		t.Error("Switch installed B before Activate; the window must still expose the source")
	}
	before := len(sessA.Records())
	sessA.Append(sessions.Message{ID: "during-switch", Role: "user", Content: sessions.TextContent("x")})
	if len(sessA.Records()) != before+1 {
		t.Error("Switch closed A before target activation")
	}

	if _, err := s.Activate(sessB); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if app.ActiveStore() != sessB {
		t.Error("active store not installed as B after Activate")
	}
	if !resumeLockHeld(t, sessB.Path()) {
		t.Error("B's resume lock is not held after Activate; the target token must remain the current one")
	}
	if resumeLockHeld(t, sessA.Path()) {
		t.Error("A's resume lock still held after Activate B — the source token must be released once the target is installed")
	}
	before = len(sessA.Records())
	sessA.Append(sessions.Message{ID: "after-switch", Role: "user", Content: sessions.TextContent("x")})
	if len(sessA.Records()) != before {
		t.Error("Activate left A appendable after installing B")
	}
}

func TestCurrentSessionOwnership_ReleasesExactlyOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	home := t.TempDir()
	folder := t.TempDir()

	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(dir, "prior.json"), "01890000-0000-7000-8000-000000000301", folder)
	resumed := storeAt(t, filepath.Join(dir, "resumed.json"), "01890000-0000-7000-8000-000000000302", folder)
	mustFlush(t, prior)
	mustFlush(t, resumed)
	app.SetActiveStore(prior)

	lock := &resumeLockHolder{}

	sw := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: lock}
	if err := sw.Switch(resumed, prior); err != nil {
		t.Fatalf("resume switch into resumed session: %v", err)
	}
	if _, err := sw.Activate(resumed); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !resumeLockHeld(t, resumed.Path()) {
		t.Fatal("resumed session's token not held after /resume")
	}

	result := &BootstrapResult{Home: home, Session: resumed}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{
		"clear": tui.NewClearHandler(newClearDeps(ctx, app, result, selectedState(), selectedModeState(), lock, fixedRecorder(injectedResolution), nil)),
	})
	submit := tui.NewSubmitFunc(reg, app, nil)
	if !submit("/new") {
		t.Fatal("/new should be accepted")
	}

	fresh := app.ActiveStore()
	if fresh == resumed {
		t.Fatal("active store not swapped to a fresh session after /new")
	}
	if resumeLockHeld(t, resumed.Path()) {
		t.Error("resumed token still held after /clear transferred ownership")
	}
	if !resumeLockHeld(t, fresh.Path()) {
		t.Error("fresh target token not held after /clear; the current token must be owned")
	}

	lock.releaseHeld()
	if resumeLockHeld(t, fresh.Path()) {
		t.Error("fresh token still held after the run's terminal release")
	}
	lock.releaseHeld()
	if resumeLockHeld(t, fresh.Path()) {
		t.Error("a second terminal release changed ownership; releaseHeld must be idempotent")
	}
}

func TestResumeSwitch_AbortReleasesTentativeTarget(t *testing.T) {
	dir := t.TempDir()
	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(dir, "prior.json"), "01890000-0000-7000-8000-000000000401", "/proj")
	sessA := storeAt(t, filepath.Join(dir, "a.json"), "01890000-0000-7000-8000-000000000402", "/proj")
	mustFlush(t, prior)
	mustFlush(t, sessA)
	app.SetActiveStore(prior)

	priorRelease, err := sessions.AcquireResumeLock(prior.Path(), prior.SessionID())
	if err != nil {
		t.Fatalf("acquire prior token: %v", err)
	}
	holder := &resumeLockHolder{release: priorRelease}
	s := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: holder}
	if err := s.Switch(sessA, prior); err != nil {
		t.Fatalf("switch prior->A: %v", err)
	}
	if !resumeLockHeld(t, sessA.Path()) {
		t.Fatal("A's token not held after Switch")
	}
	if app.ActiveStore() != prior {
		t.Fatal("an abandoned switch must leave the prior store installed")
	}

	s.Abort()
	if resumeLockHeld(t, sessA.Path()) {
		t.Error("the tentative target token is still held after Abort")
	}
	if !resumeLockHeld(t, prior.Path()) {
		t.Error("Abort released the source token")
	}
	before := len(prior.Records())
	prior.Append(sessions.Message{ID: "after-abort", Role: "user", Content: sessions.TextContent("x")})
	if len(prior.Records()) != before+1 {
		t.Error("Abort did not leave the source appendable")
	}
	holder.releaseHeld()
	if resumeLockHeld(t, prior.Path()) {
		t.Error("terminal cleanup did not release the retained source token")
	}
}

type resumeAbortLister struct{ entry tui.ResumeEntry }

func (l resumeAbortLister) List() ([]tui.ResumeEntry, []sessions.SkippedID, error) {
	return []tui.ResumeEntry{l.entry}, nil, nil
}

type resumeAbortPicker struct{}

func (resumeAbortPicker) Present(_ []tui.ResumeEntry, onResult func(tui.PickerResult), _ tui.ResumeActions) {
	onResult(tui.PickerResult{Selected: true})
}

func (resumeAbortPicker) PresentEmpty(string, func()) {}

type resumeAbortLoader struct{ target *sessions.Store }

func (l resumeAbortLoader) Load(tui.ResumeEntry) (*sessions.Store, bool, fserrors.Category, error) {
	return l.target, false, fserrors.Category(""), nil
}

type resumeAbortSwitch struct {
	aborts      int
	activations int
}

func (s *resumeAbortSwitch) Switch(*sessions.Store, *sessions.Store) error { return nil }

func (s *resumeAbortSwitch) Activate(*sessions.Store) (string, error) {
	s.activations++
	return "", nil
}

func (s *resumeAbortSwitch) Abort() { s.aborts++ }

type resumeAbortWriteFailure struct{ err error }

func (s resumeAbortWriteFailure) Handle(sessions.WriteReason, fserrors.Category, string, error, *sessions.Store) error {
	return s.err
}

func TestResumeHandler_LaunchFailureCallsAbort(t *testing.T) {
	prior := storeAt(t, filepath.Join(t.TempDir(), "prior.json"), "01890000-0000-7000-8000-000000000501", "/proj")
	mustFlush(t, prior)
	app := tui.New(nil)
	app.SetActiveStore(prior)
	target := sessions.New("", &sessions.Session{})
	switcher := &resumeAbortSwitch{}
	deps := tui.ResumeDeps{
		Lister:       resumeAbortLister{entry: tui.ResumeEntry{ID: "target"}},
		Picker:       resumeAbortPicker{},
		Stream:       clearStreamCanceller{},
		Loader:       resumeAbortLoader{target: target},
		Switch:       switcher,
		WriteFailure: resumeAbortWriteFailure{err: errors.New("launch sink failed")},
		FlushCtx:     context.Background(),
	}
	registry := tui.BuildRegistry(map[string]tui.HandlerFunc{"resume": tui.NewResumeHandler(deps)})
	tui.NewSubmitFunc(registry, app, nil)("/resume")

	if switcher.aborts != 1 {
		t.Errorf("Abort calls = %d, want 1 after a fatal launch failure", switcher.aborts)
	}
	if switcher.activations != 0 {
		t.Errorf("Activate calls = %d, want 0 after a fatal launch failure", switcher.activations)
	}
}

func TestResumeSwitch_BackgroundPruneSummaryStaysOnSourceBeforeActivate(t *testing.T) {
	dir := t.TempDir()
	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(dir, "prior.json"), "01890000-0000-7000-8000-0000000000c1", "/proj")
	target := storeAt(t, filepath.Join(dir, "target.json"), "01890000-0000-7000-8000-0000000000c2", "/proj")
	mustFlush(t, prior)
	mustFlush(t, target)
	app.SetActiveStore(prior)

	s := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: &resumeLockHolder{}}
	if err := s.Switch(target, prior); err != nil {
		t.Fatalf("switch prior->target: %v", err)
	}

	appendPruneSummary(context.Background(), app, sessions.PruneResult{FilesScanned: 2, FilesDeleted: 1})

	if got := len(kindEvents(t, prior, events.KindSessionPruneSummary)); got != 1 {
		t.Errorf("summary on the active source session = %d, want 1", got)
	}
	if got := len(kindEvents(t, target, events.KindSessionPruneSummary)); got != 0 {
		t.Errorf("summary forced into the target before its launch anchor = %d, want 0", got)
	}
	assertFileLacks(t, target.Path(), "session_prune_summary")
	assertFileContains(t, prior.Path(), "session_prune_summary")

	if _, err := s.Activate(target); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if app.ActiveStore() != target {
		t.Fatal("Activate did not install the target as the active store")
	}
	appendPruneSummary(context.Background(), app, sessions.PruneResult{FilesScanned: 3, FilesDeleted: 0})
	if got := len(kindEvents(t, target, events.KindSessionPruneSummary)); got != 1 {
		t.Errorf("post-Activate summary on the target = %d, want 1", got)
	}
	assertFileContains(t, target.Path(), "session_prune_summary")
}

// TestResumeSwitch_LockAcquireFailureRetainsPrior pins DW3: when the chosen
// session's lock cannot be acquired, the switch is refused — the prior session's
// lock is NOT released, the active store is unchanged, and the typed lock error
// surfaces (the handler renders it). The holder is seeded with a recording release
// standing in for the prior session's resume lock.
func TestResumeSwitch_LockAcquireFailureRetainsPrior(t *testing.T) {
	app := tui.New(nil)
	prior := mkStore(t)
	app.SetActiveStore(prior)

	released := false
	s := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: &resumeLockHolder{release: func() { released = true }}}

	// Chosen target whose sidecar lock cannot be created (parent dir missing), so
	// AcquireResumeLock fails fast with a lock_acquire_error rather than a timeout.
	bad := storeAt(t, filepath.Join(t.TempDir(), "missing", "x.json"), "01890000-0000-7000-8000-0000000000aa", "/proj")

	err := s.Switch(bad, prior)
	if err == nil {
		t.Fatal("Switch succeeded despite an unacquirable chosen lock")
	}
	var le *sessions.ResumeLockError
	if !errors.As(err, &le) {
		t.Errorf("error = %v, want a *sessions.ResumeLockError", err)
	}
	if released {
		t.Error("prior resume lock was released on a chosen-lock acquire failure (lock dropped)")
	}
	if app.ActiveStore() != prior {
		t.Error("active store changed after a refused lock handoff")
	}
	// The prior session is still appendable (not sealed by a refused switch).
	before := len(prior.Records())
	prior.Append(sessions.Message{ID: "after-fail", Role: "user", Content: sessions.TextContent("x")})
	if len(prior.Records()) != before+1 {
		t.Error("prior session was sealed by a refused switch (it must stay active)")
	}
}

// TestResumeThenClear_ReleasesResumedLock pins round 2 [r4]: the resume lock the
// run acquires on /resume must be released when the run later leaves that session
// through /clear|/new, not held until the next /resume or process teardown. It
// resumes into a real locked session through resumeSwitch, drives /new through the
// production clear handler sharing the same run-scoped holder, and proves the old
// session's sidecar lock is free afterward via locks.TryAcquire — so another
// codemeld instance can resume it. It fails against the prior code, where the held
// release was private to resumeSwitch and unreachable from /clear.
func TestResumeThenClear_ReleasesResumedLock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	home := t.TempDir()
	folder := t.TempDir()

	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(dir, "prior.json"), "01890000-0000-7000-8000-000000000201", folder)
	resumed := storeAt(t, filepath.Join(dir, "resumed.json"), "01890000-0000-7000-8000-000000000202", folder)
	mustFlush(t, prior)
	mustFlush(t, resumed)
	app.SetActiveStore(prior)

	// Shared run-scoped holder across the /resume switch and the /clear swapper.
	lock := &resumeLockHolder{}

	// /resume into the resumed session: its sidecar lock is acquired and held, and (after
	// the launch anchor, modelled here by the immediate Activate) it becomes the active
	// session the run records into.
	sw := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: lock}
	if err := sw.Switch(resumed, prior); err != nil {
		t.Fatalf("resume switch into resumed session: %v", err)
	}
	if _, err := sw.Activate(resumed); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !resumeLockHeld(t, resumed.Path()) {
		t.Fatal("resumed session's resume lock is not held after /resume")
	}

	// /new through the production clear handler sharing the same holder.
	result := &BootstrapResult{Home: home, Session: resumed}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{
		"clear": tui.NewClearHandler(newClearDeps(ctx, app, result, selectedState(), selectedModeState(), lock, fixedRecorder(injectedResolution), nil)),
	})
	submit := tui.NewSubmitFunc(reg, app, nil)

	if !submit("/new") {
		t.Fatal("/new should be accepted (handled, no retain)")
	}
	if app.ActiveStore() == resumed {
		t.Fatal("active store not swapped to a fresh session after /new")
	}
	if resumeLockHeld(t, resumed.Path()) {
		t.Error("resumed session's resume lock still held after /new left it — another instance cannot resume it")
	}
}

// TestResumeThenExit_ReleasesResumedLock pins round 2 [r4] for the exit path: a
// clean /exit must release the resume lock the run holds on the resumed session
// before the process boundary. It resumes into a real locked session, drives /exit
// through the production registry with an exitController sharing the same holder
// (os.Exit stubbed), and proves the sidecar lock is free afterward. The kernel
// would also drop the lock on real process death, but the explicit release makes
// the run-scoped lifetime observable in-process and uniform with /resume and /clear.
func TestResumeThenExit_ReleasesResumedLock(t *testing.T) {
	dir := t.TempDir()

	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(dir, "prior.json"), "01890000-0000-7000-8000-000000000211", "/proj")
	resumed := storeAt(t, filepath.Join(dir, "resumed.json"), "01890000-0000-7000-8000-000000000212", "/proj")
	mustFlush(t, prior)
	mustFlush(t, resumed)
	app.SetActiveStore(prior)

	lock := &resumeLockHolder{}
	sw := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: lock}
	if err := sw.Switch(resumed, prior); err != nil {
		t.Fatalf("resume switch into resumed session: %v", err)
	}
	if _, err := sw.Activate(resumed); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !resumeLockHeld(t, resumed.Path()) {
		t.Fatal("resumed session's resume lock is not held after /resume")
	}

	defer swapExitProcess(func(int) {})()
	ctrl := exitController{activeStore: app.ActiveStore, stop: func() {}, ctx: context.Background(), stdout: io.Discard, holder: lock}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"exit": tui.NewExitHandler(ctrl)})

	res := reg.DispatchSlashInput("/exit", &recordingHost{store: resumed})
	if res.Status != tui.StatusHandled || res.Err != nil {
		t.Fatalf("/exit dispatch = %+v, want handled with no error", res)
	}
	if resumeLockHeld(t, resumed.Path()) {
		t.Error("resumed session's resume lock still held after a clean /exit")
	}
}

// TestResumeRefresher_CleanRefreshReturnsNil pins the happy path: a writable
// session refreshes updated_at with no error and no notice.
func TestResumeRefresher_CleanRefreshReturnsNil(t *testing.T) {
	ui := &noticeSink{}
	if err := (resumeRefresher{ui: ui}).Refresh(context.Background(), mkStore(t)); err != nil {
		t.Fatalf("clean refresh returned %v, want nil", err)
	}
	if len(ui.notices) != 0 {
		t.Errorf("clean refresh rendered notices %v, want none", ui.notices)
	}
}

// TestResumeRefresher_WriteFailureRoutesToSink pins the refresh write-failure contract: a
// per-turn atomic-write failure on the refresh is absorbed by the write-failure
// sink (session_write_failed + notice) and Refresh returns nil so the post-switch
// sequence continues, rather than surfacing the write error.
func TestResumeRefresher_WriteFailureRoutesToSink(t *testing.T) {
	ui := &noticeSink{}
	store := unwritableStore(t, "01890000-0000-7000-8000-0000000000bb", "/proj")
	if err := (resumeRefresher{ui: ui}).Refresh(context.Background(), store); err != nil {
		t.Fatalf("write-failure refresh returned %v, want nil (absorbed by the sink)", err)
	}
	if len(ui.notices) == 0 {
		t.Error("no notice rendered for the per-turn refresh write failure (sink not invoked)")
	}
}

// TestResumeRefresher_CancelledContextSurfaces pins the fatal path: a cancelled run
// context yields a ReasonNone error that cannot be encoded as session_write_failed,
// so Refresh surfaces it to abort the post-switch sequence.
func TestResumeRefresher_CancelledContextSurfaces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ui := &noticeSink{}
	if err := (resumeRefresher{ui: ui}).Refresh(ctx, mkStore(t)); err == nil {
		t.Error("cancelled-context refresh returned nil, want the surfaced fatal error")
	}
	if len(ui.notices) != 0 {
		t.Errorf("cancelled-context refresh rendered notices %v, want none", ui.notices)
	}
}

// recovererFor builds a resumeModelRecoverer over a fresh app with the model
// picker deps installed (so the failure → picker route can mount), the providerCache
// allowlist (openai/gpt-5.5, gpt-5.5-pro), and the given active state.
func recovererFor(t *testing.T, active *model.ActiveState) (resumeModelRecoverer, *tui.App) {
	t.Helper()
	app := tui.New(nil)
	cache := providerCache(t, t.TempDir())
	app.SetModelPickerDeps(newModelPickerDeps(context.Background(), app, cache, active, nil, t.TempDir(), "/launch"))
	return resumeModelRecoverer{app: app, cache: cache, active: active}, app
}

// seedModelTurn appends a model_turn to store so a later recovery has it to restore.
func seedModelTurn(t *testing.T, store *sessions.Store, provider, modelID, effort string) {
	t.Helper()
	if _, err := events.Append(store, events.ModelTurn{
		Provider: provider, ModelID: modelID, Effort: effort, Source: "picker",
	}); err != nil {
		t.Fatalf("seed model_turn: %v", err)
	}
}

// TestResumeModelRecoverer_CleanRecoveryAdoptsSelection pins that a valid
// model_turn in the loaded stream is restored and adopted into the run-scoped active
// state as source "resume" — overriding the prior in-memory selection — with no
// model_recovery_failed appended and no picker opened.
func TestResumeModelRecoverer_CleanRecoveryAdoptsSelection(t *testing.T) {
	active := selectedState() // openai/gpt-5.5/medium, source resume
	rec, app := recovererFor(t, active)
	target := mkStore(t)
	seedModelTurn(t, target, "openai", "gpt-5.5-pro", "high")

	if err := rec.Recover(target); err != nil {
		t.Fatalf("Recover returned %v, want nil on clean recovery", err)
	}
	sel, src, ok := active.Current()
	if !ok || sel.Provider != "openai" || sel.ID != "gpt-5.5-pro" || sel.Effort != "high" || src != model.SourceResume {
		t.Fatalf("active selection = (%+v, %q, ok=%v), want openai/gpt-5.5-pro/high source resume", sel, src, ok)
	}
	if got := len(kindEvents(t, target, events.KindModelRecoveryFailed)); got != 0 {
		t.Errorf("model_recovery_failed events = %d, want 0 on clean recovery", got)
	}
	if app.ModelPickerOpen() {
		t.Error("model picker opened on a clean recovery; it must only open on failure")
	}
}

// TestResumeModelRecoverer_RecoveryFailureClearsAndOpensPicker pins the recovery-failure route: a
// model_turn that fails validation appends exactly one model_recovery_failed
// clears the active selection, and opens the model picker.
func TestResumeModelRecoverer_RecoveryFailureClearsAndOpensPicker(t *testing.T) {
	active := selectedState()
	rec, app := recovererFor(t, active)
	target := mkStore(t)
	// gpt-9 is not in the providerCache allowlist, so recovery validation fails.
	seedModelTurn(t, target, "openai", "gpt-9", "high")

	if err := rec.Recover(target); err != nil {
		t.Fatalf("Recover returned %v, want nil on recovery failure", err)
	}
	if _, _, ok := active.Current(); ok {
		t.Error("active selection not cleared after a recovery failure (orphaned selection)")
	}
	if got := len(kindEvents(t, target, events.KindModelRecoveryFailed)); got != 1 {
		t.Fatalf("model_recovery_failed events = %d, want exactly 1 (no double-append)", got)
	}
	if !app.ModelPickerOpen() {
		t.Error("model picker not opened after a recovery failure; the user cannot re-pick")
	}
}

// TestResumeModelRecoverer_NoModelTurnLeavesSelectionUnchanged pins that a target
// with no model_turn leaves the existing active selection in place and appends no
// model_recovery_failed and opens no picker.
func TestResumeModelRecoverer_NoModelTurnLeavesSelectionUnchanged(t *testing.T) {
	active := selectedState()
	before, srcBefore, _ := active.Current()
	rec, app := recovererFor(t, active)
	target := mkStore(t)
	// A non-model_turn record so step 1 finds nothing to recover.
	if _, err := events.Append(target, events.LaunchBegan{Source: "resume"}); err != nil {
		t.Fatalf("seed launch_began: %v", err)
	}

	if err := rec.Recover(target); err != nil {
		t.Fatalf("Recover returned %v, want nil with no model_turn", err)
	}
	sel, src, ok := active.Current()
	if !ok || sel != before || src != srcBefore {
		t.Fatalf("active selection changed: got (%+v, %q), want unchanged (%+v, %q)", sel, src, before, srcBefore)
	}
	if got := len(kindEvents(t, target, events.KindModelRecoveryFailed)); got != 0 {
		t.Errorf("model_recovery_failed events = %d, want 0 when no model_turn", got)
	}
	if app.ModelPickerOpen() {
		t.Error("model picker opened when there was no model_turn; the selection must be left unchanged")
	}
}

// TestResumeModelRecoverer_InternalErrorSurfaces pins that an internal recovery
// error (here a nil config cache, the same surface an append failure would take)
// surfaces from Recover so the /resume handler renders it, and leaves the active
// selection unchanged with no picker opened.
func TestResumeModelRecoverer_InternalErrorSurfaces(t *testing.T) {
	active := selectedState()
	before, srcBefore, _ := active.Current()
	app := tui.New(nil)
	rec := resumeModelRecoverer{app: app, cache: nil, active: active}
	target := mkStore(t)
	seedModelTurn(t, target, "openai", "gpt-5.5", "high")

	if err := rec.Recover(target); err == nil {
		t.Fatal("Recover returned nil on an internal error, want the surfaced error")
	}
	sel, src, ok := active.Current()
	if !ok || sel != before || src != srcBefore {
		t.Fatalf("active selection changed on an internal error: got (%+v, %q), want unchanged (%+v, %q)", sel, src, before, srcBefore)
	}
	if app.ModelPickerOpen() {
		t.Error("model picker opened on an internal error; the run must surface and leave state untouched")
	}
}

// TestResumeForker_IsNoOpSeam pins the unreachable older-schema branch: the
// production OlderSchemaForker is a documented no-op (older-fork-eligible is
// unreachable while ReaderSupportedVersion == 1) — it returns nil and mutates
// nothing.
func TestResumeForker_IsNoOpSeam(t *testing.T) {
	store := mkStore(t)
	before := len(store.Records())
	if err := (resumeForker{}).OfferFork(store); err != nil {
		t.Fatalf("OfferFork returned %v, want nil (no-op seam)", err)
	}
	if len(store.Records()) != before {
		t.Error("OlderSchemaForker seam mutated the session; it must do nothing")
	}
}

// TestResumeLoader_LoadsCurrentFolderSurvivor pins the loader happy path: a
// current-folder session resolves, loads, and classifies as not-older — no
// older-fork-eligible session is possible while ReaderSupportedVersion == 1.
func TestResumeLoader_LoadsCurrentFolderSurvivor(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)
	id := store.SessionID()

	loaded, older, cat, lerr := (resumeLoader{home: home, cwd: cwd}).Load(tui.ResumeEntry{ID: id})
	if lerr != nil {
		t.Fatalf("load returned err %v (cat %q), want success", lerr, cat)
	}
	if older {
		t.Error("survivor classified as older-schema (impossible while ReaderSupportedVersion == 1)")
	}
	if loaded == nil || loaded.SessionID() != id {
		t.Errorf("loaded store = %v, want a store for id %q", loaded, id)
	}
}

// TestResumeLoader_RejectsSchemaInvalidPayload is the payload-validation terminal test: it drives
// the real production load path (resumeLoader.Load → sessions.ResolveResumeID wired
// with the real events.ValidatePayload) against a session file whose record is
// spine-valid but whose stream_interrupted payload omits the required content_chars,
// and asserts the load is rejected with the exact payload wording. It writes
// the invalid file directly because events.Append would refuse to produce it.
func TestResumeLoader_RejectsSchemaInvalidPayload(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)
	id := store.SessionID()

	// Spine-valid stream_interrupted event missing the required content_chars: it
	// parses and passes, so only the per-kind validator can reject it.
	invalid := `{"type":"event","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02",` +
		`"kind":"stream_interrupted","timestamp":"2026-05-25T12:00:00.000Z","payload":{"source":"esc"}}`
	doc := `{"type":"metadata","metadata":{"id":"` + id + `","folder":` + strconv.Quote(canonical) +
		`,"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1}}` + "\n" +
		invalid + "\n"
	if err := os.WriteFile(store.Path(), []byte(doc), 0o600); err != nil {
		t.Fatalf("overwrite session file: %v", err)
	}

	loaded, older, _, lerr := (resumeLoader{home: home, cwd: cwd}).Load(tui.ResumeEntry{ID: id})
	if lerr == nil {
		t.Fatal("Load accepted a session with a schema-invalid event payload")
	}
	if loaded != nil || older {
		t.Errorf("rejection returned store=%v older=%v, want nil/false", loaded, older)
	}
	var le *sessions.ResumeLoadError
	if !errors.As(lerr, &le) {
		t.Fatalf("error %v is not a *sessions.ResumeLoadError", lerr)
	}
	want := "codemeld: session " + id + " cannot be loaded: " +
		"records[0].payload: stream_interrupted.content_chars: required field is absent\n" +
		"run codemeld --resume with no id to list resumable sessions for the current working directory."
	if lerr.Error() != want {
		t.Errorf("Error() = %q\nwant %q", lerr.Error(), want)
	}
}

// TestResumeLoader_AcceptsValidPayload pins the positive half of load-path payload validation through the
// real wiring: a session carrying a canonical (events.Append-written) event payload
// loads cleanly via resumeLoader.Load, proving the wired validator accepts valid
// payloads rather than rejecting everything.
func TestResumeLoader_AcceptsValidPayload(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	if _, err := events.Append(store, events.StreamInterrupted{Source: "esc", ContentChars: 3}); err != nil {
		t.Fatalf("append stream_interrupted: %v", err)
	}
	mustFlush(t, store)
	id := store.SessionID()

	loaded, older, cat, lerr := (resumeLoader{home: home, cwd: cwd}).Load(tui.ResumeEntry{ID: id})
	if lerr != nil {
		t.Fatalf("load returned err %v (cat %q), want success for a valid event payload", lerr, cat)
	}
	if older {
		t.Error("survivor classified as older-schema (impossible while ReaderSupportedVersion == 1)")
	}
	if loaded == nil || loaded.SessionID() != id {
		t.Errorf("loaded store = %v, want a store for id %q", loaded, id)
	}
}

// TestResumeLoader_VanishedFileReportsNotFound pins the step-8 case: a chosen id
// that no longer resolves (pruned between listing and selection) yields a nil
// store, a not_found category for the load-failure notice, and an error.
func TestResumeLoader_VanishedFileReportsNotFound(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()

	loaded, older, cat, err := (resumeLoader{home: home, cwd: cwd}).Load(
		tui.ResumeEntry{ID: "01890000-0000-7000-8000-0000000000ff"})
	if err == nil {
		t.Fatal("load of a vanished session returned nil error, want a load failure")
	}
	if loaded != nil || older {
		t.Errorf("load failure returned store=%v older=%v, want nil/false", loaded, older)
	}
	if cat != fserrors.NotFound {
		t.Errorf("failCat = %q, want %q for a vanished session", cat, fserrors.NotFound)
	}
}

// TestResumeLister_ProjectsSurvivorsWithPreview pins the lister projection: a
// current-folder survivor is surfaced as a tui.ResumeEntry carrying its id and the
// title and first-user-message preview the single listing scan produced.
func TestResumeLister_ProjectsSurvivorsWithPreview(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	userMsg := sessions.Message{
		ID:        ids.NewV7(),
		Role:      "user",
		Content:   sessions.TextContent("hello world"),
		Timestamp: testStart,
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, []sessions.Record{userMsg})
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)
	if _, terr := sessions.SetTitle(store.Path(), "chosen title"); terr != nil {
		t.Fatalf("set title: %v", terr)
	}

	entries, skipped, lerr := (resumeLister{home: home, cwd: cwd}).List()
	if lerr != nil {
		t.Fatalf("list: %v", lerr)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want none", skipped)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].ID != store.SessionID() {
		t.Errorf("entry id = %q, want %q", entries[0].ID, store.SessionID())
	}
	if entries[0].Preview != "hello world" {
		t.Errorf("entry preview = %q, want %q", entries[0].Preview, "hello world")
	}
	if entries[0].Title != "chosen title" {
		t.Errorf("entry title = %q, want %q", entries[0].Title, "chosen title")
	}
}

// TestResumeLister_ProjectsLongMessageWithDistinguishingTail pins the projection the
// picker depends on: a first user message far over the preview budget is projected
// through the production lister as a bounded, whitespace-normalized preview that keeps a
// head, exactly one ellipsis, and the trailing task id that distinguishes it from
// another session with the same prefix. Tail-cutting here would drop the id before any
// resume surface could render it.
func TestResumeLister_ProjectsLongMessageWithDistinguishingTail(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	long := "please refactor\tthe resume picker layout\n" + strings.Repeat("and tidy it up ", 12) + "for task i870"
	userMsg := sessions.Message{
		ID:        ids.NewV7(),
		Role:      "user",
		Content:   sessions.TextContent(long),
		Timestamp: testStart,
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, []sessions.Record{userMsg})
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)

	entries, _, lerr := (resumeLister{home: home, cwd: cwd}).List()
	if lerr != nil {
		t.Fatalf("list: %v", lerr)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	preview := entries[0].Preview

	if !strings.HasPrefix(preview, "please refactor the resume picker") {
		t.Errorf("preview %q lost its head or did not normalize the tab/newline", preview)
	}
	if strings.ContainsAny(preview, "\n\t") {
		t.Errorf("preview %q still carries raw whitespace", preview)
	}
	if n := strings.Count(preview, "…"); n != 1 {
		t.Errorf("preview %q has %d ellipses, want exactly 1", preview, n)
	}
	if !strings.Contains(preview, "for task i870") {
		t.Errorf("preview %q dropped the distinguishing tail %q", preview, "for task i870")
	}
	if w := uniseg.StringWidth(preview); w > resumePreviewMax {
		t.Errorf("preview %q = %d cells, want at most %d", preview, w, resumePreviewMax)
	}
	// The cold-start --resume list renders from the same scanned entry, so it must
	// show the same bounded preview the picker does.
	scanned, _, serr := sessions.ListResumable(home, cwd)
	if serr != nil {
		t.Fatalf("list resumable: %v", serr)
	}
	if got := resumeRowPrimary(scanned[0]); got != preview {
		t.Errorf("cold-start row = %q, want the lister's %q", got, preview)
	}
}

// TestTruncatePreview_BoundedAndGraphemeSafe pins the projection's boundary behavior:
// text at exactly the cell budget is untouched, one more grapheme forces a middle cut,
// and wide/emoji/combining text is cut on cluster boundaries measured in terminal cells
// rather than runes.
func TestTruncatePreview_BoundedAndGraphemeSafe(t *testing.T) {
	if got := truncatePreview(""); got != "" {
		t.Errorf("empty preview = %q, want %q", got, "")
	}
	exact := strings.Repeat("a", resumePreviewMax)
	if got := truncatePreview(exact); got != exact {
		t.Errorf("exact-budget preview = %q, want it unchanged", got)
	}
	if got := truncatePreview(exact + "b"); !strings.Contains(got, "…") {
		t.Errorf("over-budget-by-one preview = %q, want a middle ellipsis", got)
	}
	for name, text := range map[string]string{
		"cjk":       strings.Repeat("漢字", 60) + "for task i870",
		"emoji":     strings.Repeat("👨‍👩‍👧‍👦", 60) + "for task i870",
		"combining": strings.Repeat("e\u0301", 120) + "for task i870",
	} {
		got := truncatePreview(text)
		if w := uniseg.StringWidth(got); w > resumePreviewMax {
			t.Errorf("%s: preview %q = %d cells, want at most %d", name, got, w, resumePreviewMax)
		}
		head, tail, cut := strings.Cut(got, "…")
		if !cut {
			t.Fatalf("%s: preview %q was not truncated; the fixture is too short", name, got)
		}
		if !strings.Contains(tail, "for task i870") {
			t.Errorf("%s: preview %q dropped the tail", name, got)
		}
		if !strings.HasPrefix(text, head) || !strings.HasSuffix(text, tail) {
			t.Errorf("%s: preview %q is not a head+tail of the input", name, got)
		}
		if uniseg.GraphemeClusterCount(head)+uniseg.GraphemeClusterCount(tail) !=
			uniseg.GraphemeClusterCount(head+tail) {
			t.Errorf("%s: preview %q split a grapheme cluster at a cut", name, got)
		}
	}
}

// TestResumeLister_ProjectsTitleAndPath pins the title/path projection additions: a survivor's
// stored title and absolute file path are folded onto the tui.ResumeEntry (the title via
// the same single OpenSession the preview uses), so the picker can render the title over
// the preview and the rename/delete actions can target the file by path.
func TestResumeLister_ProjectsTitleAndPath(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	userMsg := sessions.Message{
		ID:        ids.NewV7(),
		Role:      "user",
		Content:   sessions.TextContent("preview text"),
		Timestamp: testStart,
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, []sessions.Record{userMsg})
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)
	if cat, serr := sessions.SetTitle(store.Path(), "Stored Title"); serr != nil {
		t.Fatalf("SetTitle: %v (cat %q)", serr, cat)
	}

	entries, _, lerr := (resumeLister{home: home, cwd: cwd}).List()
	if lerr != nil {
		t.Fatalf("list: %v", lerr)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Title != "Stored Title" {
		t.Errorf("entry title = %q, want %q", entries[0].Title, "Stored Title")
	}
	if entries[0].Preview != "preview text" {
		t.Errorf("entry preview = %q, want %q (preview still projected alongside the title)", entries[0].Preview, "preview text")
	}
	if entries[0].Path == "" {
		t.Error("entry path is empty, want the survivor's file path")
	}
	if _, serr := os.Stat(entries[0].Path); serr != nil {
		t.Errorf("entry path %q does not resolve to a file: %v", entries[0].Path, serr)
	}
	if base := filepath.Base(entries[0].Path); base != store.SessionID()+".json" {
		t.Errorf("entry path base = %q, want %q", base, store.SessionID()+".json")
	}
}

func TestResumeLister_ShowsStoredTitles(t *testing.T) {
	home := t.TempDir()

	newSurvivor := func(t *testing.T, preview string, apply func(*sessions.Store)) string {
		t.Helper()
		cwd := t.TempDir()
		canonical, err := sessions.CanonicalizeFolder(cwd)
		if err != nil {
			t.Fatalf("canonicalize: %v", err)
		}
		userMsg := sessions.Message{
			ID:        ids.NewV7(),
			Role:      "user",
			Content:   sessions.TextContent(preview),
			Timestamp: testStart,
		}
		store, err := sessions.EnsureSession(home, canonical, testStart, []sessions.Record{userMsg})
		if err != nil {
			t.Fatalf("ensure session: %v", err)
		}
		mustFlush(t, store)
		apply(store)
		return cwd
	}

	cases := []struct {
		name  string
		apply func(*sessions.Store)
		want  string
	}{
		{"generated", func(s *sessions.Store) {
			if _, _, err := s.FlushGeneratedTitle(context.Background(), "Auto Title"); err != nil {
				t.Fatalf("FlushGeneratedTitle: %v", err)
			}
		}, "Auto Title"},
		{"legacy_no_provenance", func(s *sessions.Store) {
			sess, _, err := sessions.OpenSession(s.Path())
			if err != nil {
				t.Fatalf("reopen to write a pre-provenance file: %v", err)
			}
			sess.Metadata.Title = "Legacy Name"
			data, merr := sessions.Marshal(sess)
			if merr != nil {
				t.Fatalf("marshal pre-provenance file: %v", merr)
			}
			if werr := os.WriteFile(s.Path(), data, 0o600); werr != nil {
				t.Fatalf("write pre-provenance file: %v", werr)
			}
		}, "Legacy Name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := newSurvivor(t, "preview text", tc.apply)

			entries, _, lerr := (resumeLister{home: home, cwd: cwd}).List()
			if lerr != nil {
				t.Fatalf("list: %v", lerr)
			}
			if len(entries) != 1 {
				t.Fatalf("entries = %d, want 1", len(entries))
			}
			if entries[0].Title != tc.want {
				t.Errorf("entry title = %q, want the stored title %q", entries[0].Title, tc.want)
			}
		})
	}
}

func TestResumeLoader_ReopenedSessionShowsItsStoredTitle(t *testing.T) {
	cases := []struct {
		name     string
		apply    func(*sessions.Store)
		wantSeen bool
	}{
		{"user_set", func(s *sessions.Store) {
			if cat, err := sessions.SetTitle(s.Path(), "My session"); err != nil {
				t.Fatalf("SetTitle: %v (cat %q)", err, cat)
			}
		}, true},
		{"generated", func(s *sessions.Store) {
			if _, _, err := s.FlushGeneratedTitle(context.Background(), "My session"); err != nil {
				t.Fatalf("FlushGeneratedTitle: %v", err)
			}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cwd := t.TempDir()
			canonical, err := sessions.CanonicalizeFolder(cwd)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			store, err := sessions.EnsureSession(home, canonical, testStart, nil)
			if err != nil {
				t.Fatalf("ensure session: %v", err)
			}
			mustFlush(t, store)
			tc.apply(store)

			target, _, _, lerr := (resumeLoader{home: home, cwd: cwd}).Load(tui.ResumeEntry{ID: store.SessionID()})
			if lerr != nil {
				t.Fatalf("Load: %v", lerr)
			}
			app := tui.New(nil)
			app.SetActiveStore(target)

			if got := strings.Contains(app.SessionBadgeText(), "My session"); got != tc.wantSeen {
				t.Errorf("badge = %q, shown = %v, want %v", app.SessionBadgeText(), got, tc.wantSeen)
			}
		})
	}
}

// TestResumeRenamer_PersistsTitle pins the production renamer wiring: it persists the
// typed title on the entry's file via sessions.SetTitle, readable back from disk.
func TestResumeRenamer_PersistsTitle(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)

	if rerr := (resumeRenamer{}).Rename(tui.ResumeEntry{ID: store.SessionID(), Path: store.Path()}, "My Title"); rerr != nil {
		t.Fatalf("Rename: %v", rerr)
	}
	sess, _, oerr := sessions.OpenSession(store.Path())
	if oerr != nil {
		t.Fatalf("reopen: %v", oerr)
	}
	if sess.Metadata.Title != "My Title" {
		t.Errorf("persisted title = %q, want %q", sess.Metadata.Title, "My Title")
	}
	if sess.Metadata.TitleSource != sessions.TitleSourceUser {
		t.Errorf("title_source = %q, want %q (the picker rename must record user provenance)", sess.Metadata.TitleSource, sessions.TitleSourceUser)
	}
}

// TestResumeDeleter_RemovesNonActiveSession pins the production deleter wiring: with no
// active session matching, it removes the file via sessions.DeleteSession.
func TestResumeDeleter_RemovesNonActiveSession(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)
	path := store.Path()

	app := tui.New(nil) // no active store, so the guard does not fire
	if derr := (resumeDeleter{app: app}).Delete(tui.ResumeEntry{ID: store.SessionID(), Path: path}); derr != nil {
		t.Fatalf("Delete: %v", derr)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Errorf("session file still present after delete (stat err %v)", serr)
	}
}

// TestResumeDeleter_RefusesActiveSession pins the deleter's defense-in-depth guard: it
// refuses to delete the run's active session (matched by id) and leaves the file intact,
// even though resumeLister already excludes it.
func TestResumeDeleter_RefusesActiveSession(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	store, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	mustFlush(t, store)
	path := store.Path()

	app := tui.New(nil)
	app.SetActiveStore(store)

	if derr := (resumeDeleter{app: app}).Delete(tui.ResumeEntry{ID: store.SessionID(), Path: path}); derr == nil {
		t.Fatal("Delete of the active session returned nil, want refusal")
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Errorf("active session file removed despite the guard: %v", serr)
	}
}

// TestResumeLister_ExcludesActiveSession pins the durability fix: the currently-active
// session must never be offered as a resume target. If it were, selecting it would make
// runResumeSwitch load a stale on-disk copy as the target and a later flush would
// overwrite the records the pre-switch flush just wrote (the /resume slash_command and
// any stream_interrupted) — dropping them. The non-active session in the same folder is
// still offered.
func TestResumeLister_ExcludesActiveSession(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	canonical, err := sessions.CanonicalizeFolder(cwd)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	active, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure active: %v", err)
	}
	mustFlush(t, active)
	other, err := sessions.EnsureSession(home, canonical, testStart, nil)
	if err != nil {
		t.Fatalf("ensure other: %v", err)
	}
	mustFlush(t, other)

	app := tui.New(nil)
	app.SetActiveStore(active)

	entries, _, lerr := (resumeLister{app: app, home: home, cwd: cwd}).List()
	if lerr != nil {
		t.Fatalf("list: %v", lerr)
	}
	for _, e := range entries {
		if e.ID == active.SessionID() {
			t.Fatalf("active session %s offered as a resume target; it must be excluded", active.SessionID())
		}
	}
	if len(entries) != 1 || entries[0].ID != other.SessionID() {
		t.Fatalf("entries = %+v, want only the non-active session %s", entries, other.SessionID())
	}
}

func resumeDepsInto(t *testing.T, app *tui.App, target *sessions.Store, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
	t.Helper()
	deps := newResumeDeps(context.Background(), app, &BootstrapResult{Home: t.TempDir()}, &resumeLockHolder{}, providerCache(t, t.TempDir()), selectedState(), recorder, conf)
	deps.Lister = resumeAbortLister{entry: tui.ResumeEntry{ID: target.SessionID()}}
	deps.Picker = resumeAbortPicker{}
	deps.Loader = resumeAbortLoader{target: target}
	return deps
}

func submitResume(app *tui.App, deps tui.ResumeDeps) {
	tui.NewSubmitFunc(tui.BuildRegistry(map[string]tui.HandlerFunc{"resume": tui.NewResumeHandler(deps)}), app, nil)("/resume")
}

func resumeStores(t *testing.T) (*tui.App, *sessions.Store, *sessions.Store) {
	t.Helper()
	dir := t.TempDir()
	app := tui.New(nil)
	prior := storeAt(t, filepath.Join(dir, "prior.json"), "01890000-0000-7000-8000-000000000601", "/proj")
	target := storeAt(t, filepath.Join(dir, "target.json"), "01890000-0000-7000-8000-000000000602", "/proj")
	mustFlush(t, prior)
	mustFlush(t, target)
	app.SetActiveStore(prior)
	return app, prior, target
}

type readOnlyTargetSwitch struct{ *resumeSwitch }

func (s readOnlyTargetSwitch) Activate(target *sessions.Store) (string, error) {
	if err := os.Chmod(target.Path(), 0o400); err != nil {
		return "", err
	}
	return s.resumeSwitch.Activate(target)
}

func TestResume_AppendsTheLaunchCapabilityToTheTarget(t *testing.T) {
	app, _, target := resumeStores(t)
	earlier := events.ExecutionCapability{Capability: "refused", Reason: "earlier launch"}
	if _, err := events.Append(target, earlier); err != nil {
		t.Fatal(err)
	}
	mustFlush(t, target)

	submitResume(app, resumeDepsInto(t, app, target, fixedRecorder(injectedResolution), nil))

	if app.ActiveStore() != target {
		t.Fatal("active store was not switched to the target")
	}
	caps := decodeDiskEvents[events.ExecutionCapability](t, readSessionFile(t, target.Path()), events.KindExecutionCapability)
	if len(caps) != 2 || !reflect.DeepEqual(caps[0], earlier) || !reflect.DeepEqual(caps[1], injectedCapability) {
		t.Fatalf("capabilities on disk = %+v, want %+v then the launch capability", caps, earlier)
	}
}

func TestResume_CapabilityRecordFailureKeepsThePriorSession(t *testing.T) {
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
			app, prior, target := resumeStores(t)
			deps := resumeDepsInto(t, app, target, fixedRecorder(tc.execution), conf)
			if tc.readOnly {
				deps.Switch = readOnlyTargetSwitch{deps.Switch.(*resumeSwitch)}
			}

			submitResume(app, deps)

			if app.ActiveStore() != prior {
				t.Fatal("active store changed despite the capability record failure")
			}
			if resumeLockHeld(t, target.Path()) {
				t.Error("target lock still held after the failed switch")
			}
			assertTempDirKept(t, conf, old)
		})
	}
}

func TestResumeSwitch_ReplacesThePrivateTempFolder(t *testing.T) {
	activate := func(t *testing.T, conf *confinement) (*resumeSwitch, *tui.App, *sessions.Store, *sessions.Store, string, error) {
		app, prior, target := resumeStores(t)
		s := &resumeSwitch{app: app, ctx: context.Background(), recorder: fixedRecorder(injectedResolution), holder: &resumeLockHolder{}, conf: conf}
		if err := s.Switch(target, prior); err != nil {
			t.Fatalf("Switch: %v", err)
		}
		warning, err := s.Activate(target)
		return s, app, prior, target, warning, err
	}

	t.Run("replaced", func(t *testing.T) {
		conf := injectedTempDir(t)
		old := conf.tmpDir
		if _, _, _, _, warning, err := activate(t, conf); err != nil || warning != "" {
			t.Fatalf("Activate = (%q, %v), want success without a warning", warning, err)
		}
		if _, err := os.Stat(old); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("old folder stat = %v, want it removed", err)
		}
		assertTempDirReplaced(t, conf, old)
	})

	t.Run("replacement creation fails", func(t *testing.T) {
		conf := injectedTempDir(t)
		old := conf.tmpDir
		t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
		s, app, prior, target, _, err := activate(t, conf)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Activate error = %v, want the temp folder error", err)
		}
		s.Abort()
		if app.ActiveStore() != prior || conf.tmpDir != old || resumeLockHeld(t, target.Path()) {
			t.Fatalf("active = %p tmpDir = %q; want prior %p, %q and the target lock released", app.ActiveStore(), conf.tmpDir, prior, old)
		}
		if _, err := os.Stat(old); err != nil {
			t.Fatalf("old folder: %v, want it kept", err)
		}
	})

	t.Run("old folder cleanup fails", func(t *testing.T) {
		conf := stuckTempDir(t)
		old := conf.tmpDir
		_, app, _, target, warning, err := activate(t, conf)
		if err != nil || app.ActiveStore() != target {
			t.Fatalf("Activate error = %v, want the switch to stand", err)
		}
		assertTempDirReplaced(t, conf, old)
		if !slices.Equal(conf.retryPaths, []string{old}) {
			t.Fatalf("retry = %v, want [%s]", conf.retryPaths, old)
		}
		if !strings.HasPrefix(warning, "can't remove private temp folder "+old+": ") {
			t.Fatalf("warning = %q, want the cleanup notice for %s", warning, old)
		}
	})

	t.Run("empty tmpDir", func(t *testing.T) {
		conf := &confinement{}
		if _, _, _, _, _, err := activate(t, conf); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		if conf.tmpDir != "" {
			t.Fatalf("tmpDir = %q, want it to stay empty", conf.tmpDir)
		}
	})
}

func TestResume_RecordsTheLiveCapabilityAfterASettingsChange(t *testing.T) {
	for _, tc := range liveCapabilityCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder, f := liveSettingsRecorder(t, tc.launch)
			setSettingsBroken(t, f, !tc.broken)
			recorder.blocked.Current()
			app, _, target := resumeStores(t)
			deps := resumeDepsInto(t, app, target, recorder, nil)

			setSettingsBroken(t, f, tc.broken)
			submitResume(app, deps)

			if app.ActiveStore() != target {
				t.Fatal("active store was not switched to the target")
			}
			requireDiskCapabilities(t, target, tc.want)
		})
	}
}

func TestResume_TransitionQueuedDuringTheSwitchLandsInTheTarget(t *testing.T) {
	for _, recovers := range []bool{false, true} {
		t.Run(map[bool]string{false: "degrades", true: "recovers"}[recovers], func(t *testing.T) {
			recorder, f := liveSettingsRecorder(t, constrainedLaunch)
			setSettingsBroken(t, f, recovers)
			recorder.blocked.Current()
			app, _, target := resumeStores(t)
			hold := newRecordHold(t)
			records := watchCapabilityRecords(t, func(store *sessions.Store) {
				if store == target {
					hold.block()
				}
			})
			runLiveDelivery(t, app, recorder)
			deps := resumeDepsInto(t, app, target, recorder, nil)
			switched := make(chan struct{})
			go func() {
				defer close(switched)
				submitResume(app, deps)
			}()
			hold.waitEntered(t)
			nextCapabilityRecord(t, records, func(r storedCapability) bool { return r.store == target })

			setSettingsBroken(t, f, !recovers)
			refreshWithin(t, recorder.blocked)
			waitForMutexWaitIn(t, "deliver")
			hold.open()

			receiveWithin(t, switched, "/resume")
			if delivered := nextCapabilityRecord(t, records, func(storedCapability) bool { return true }); delivered.store != target {
				t.Fatalf("delivery recorded into %p, want the resumed target %p", delivered.store, target)
			}
			if app.ActiveStore() != target {
				t.Fatalf("active store = %p, want the resumed target %p", app.ActiveStore(), target)
			}
			requireDiskCapabilities(t, target, capabilityFor(recovers), capabilityFor(!recovers))
		})
	}
}
