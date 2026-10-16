// Integration test for TR-TUI-9 (/resume picker), driving the production submit
// path StartTUI assembles: /resume goes through DispatchSlashInput and the
// wired production /resume handler, lists the current folder's resumable
// sessions through the real lister, and on selection runs the real in-process
// switch — load + CWD-match, the sidecar-lock handoff
// launch_began{resume}, and the updated_at refresh — with the prior and chosen
// session files read back from disk.
//
// This test's prep names internal/integration/resume_picker_test.go as the target file,
// but — exactly as tui_commands_test.go documents for TR-TUI-5/6/7 — the only
// way to drive the real production /resume wiring (StartTUI's registry-backed submit
// adapter, the production ResumeDeps from newResumeDeps, the command-event flush
// hook, the run-scoped resume-lock holder) is via internal/bootstrap's unexported
// builders. An internal/integration package could only re-implement those deps as
// fakes, so this black-box test lives in package bootstrap and reuses the
// startCaptured/swapRunApp driver and the readSessionFile/diskSlashCommands
// disk-readback helpers established there. The app is launched through the real
// StartTUI assembly — StartTUI builds the app, installs the command-event flush
// hook, builds the production registry with the /resume handler, and installs
// the submit adapter — so /resume is submitted through the app's own installed
// submit hook (app.SubmitInput) and a regression in that wiring fails the test. The
// one capability that cannot run headless is the picker overlay (a tview Pages
// overlay whose Enter/ESC handlers fire only off a live event loop,
// picker_resume.go); it is injected through the newResumeDeps seam with a
// synchronous-selection stand-in for the user's Enter (the ResumeDeps.Picker
// continuation contract, the same seam cmd_resume_test.go's fakePicker uses), while
// every other capability — lister, loader, lock handoff, refresh — is the
// production impl StartTUI built. The load -> sidecar-lock -> refresh order is
// pinned on those real deps via order-recording wrappers installed through the same
// seam and cross-checked against the cold-start --resume <id> sub-sequence (the
// runResumeWithID seam).
package bootstrap

import (
	"context"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// orderTicker hands out a strictly increasing sequence number so the resume
// capability wrappers below can record their relative invocation order.
type orderTicker struct{ n int }

func (o *orderTicker) tick() int { o.n++; return o.n }

// recordingResumeLoader, recordingResumeSwitch, and recordingResumeRefresher wrap
// the production /resume capabilities (the ResumeDeps seam): each records when it ran
// before delegating to the real impl, so the in-process switch order can be pinned
// on the genuine production deps rather than on fakes.
type recordingResumeLoader struct {
	inner tui.TargetLoader
	ord   *orderTicker
	at    int
}

func (l *recordingResumeLoader) Load(e tui.ResumeEntry) (*sessions.Store, bool, fserrors.Category, error) {
	l.at = l.ord.tick()
	return l.inner.Load(e)
}

type recordingResumeSwitch struct {
	inner      tui.ResumeSwitch
	ord        *orderTicker
	at         int
	activateAt int
}

func (s *recordingResumeSwitch) Switch(target, prior *sessions.Store) error {
	s.at = s.ord.tick()
	return s.inner.Switch(target, prior)
}

func (s *recordingResumeSwitch) Activate(target *sessions.Store) (string, error) {
	s.activateAt = s.ord.tick()
	return s.inner.Activate(target)
}

type recordingResumeRefresher struct {
	inner tui.UpdatedAtRefresher
	ord   *orderTicker
	at    int
}

func (r *recordingResumeRefresher) Refresh(ctx context.Context, target *sessions.Store) error {
	r.at = r.ord.tick()
	return r.inner.Refresh(ctx, target)
}

// selectingResumePicker stands in for the tview overlay (which cannot run without a
// live event loop): Present records the rows it was shown and synchronously selects
// the row whose id is selectID, modelling the user pressing Enter on it; with no
// matching row it dismisses (ESC). This is the ResumeDeps.Picker continuation
// contract — the same seam cmd_resume_test.go's fakePicker uses.
type selectingResumePicker struct {
	selectID  string
	presented [][]tui.ResumeEntry
	empties   []string
}

func (p *selectingResumePicker) Present(entries []tui.ResumeEntry, onResult func(tui.PickerResult), _ tui.ResumeActions) {
	p.presented = append(p.presented, entries)
	for i, e := range entries {
		if e.ID == p.selectID {
			onResult(tui.PickerResult{Selected: true, Index: i})
			return
		}
	}
	onResult(tui.PickerResult{Selected: false})
}

func (p *selectingResumePicker) PresentEmpty(message string, onDismiss func()) {
	p.empties = append(p.empties, message)
	onDismiss()
}

// swapNewResumeDeps overrides the newResumeDeps seam (resumedeps.go) and returns a
// restore function, mirroring swapRunApp. The TR-TUI-9 test uses it to wrap the
// headless-incompatible picker and the order-recording capabilities around the
// production deps while StartTUI still builds the app, installs the command-event
// flush hook, builds the production registry, and sets the submit adapter.
func swapNewResumeDeps(fn func(context.Context, *tui.App, *BootstrapResult, *resumeLockHolder, *config.Cache, *model.ActiveState, *capabilityRecorder, *confinement) tui.ResumeDeps) func() {
	prev := newResumeDeps
	newResumeDeps = fn
	return func() { newResumeDeps = prev }
}

// TestTRTUI9_ResumePicker_SwitchesCurrentFolderSessionDurablyOnDisk covers TR-TUI-9
// end to end. Two canonical folders each hold a resumable session, plus a second
// (target) session in folder A; folder A is launched through the production
// StartTUI assembly and /resume is submitted through the app's installed submit
// adapter (DW1). The picker is shown only folder A's
// non-active session — the sibling folder's session and the active session are both
// absent (DW2, a negative assertion by id, not only by count) — and selecting it
// runs the production switch. The prior session file holds the durable
// slash_command{resume, success} flushed before the picker opened plus the
// stream_interrupted{slash_resume_switch} the selection path records and flushes
// before the switch (pinning that pre-switch flush), and the chosen session file
// holds launch_began{resume} with an updated_at the post-lock refresh advanced (DW3,
// both files read back from disk). The load -> sidecar-lock ->
// refresh order is pinned on the real deps via the ResumeDeps seam (DW4).
func TestTRTUI9_ResumePicker_SwitchesCurrentFolderSessionDurablyOnDisk(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	folderA := t.TempDir()
	folderB := t.TempDir()

	canonA, err := sessions.CanonicalizeFolder(folderA)
	if err != nil {
		t.Fatalf("canonicalize folder A: %v", err)
	}
	canonB, err := sessions.CanonicalizeFolder(folderB)
	if err != nil {
		t.Fatalf("canonicalize folder B: %v", err)
	}

	// Folder A: the active (current) session plus the resume target; folder B: a
	// sibling session that must never appear in folder A's picker. Each is flushed so
	// its file exists for the real lister to enumerate.
	active, err := sessions.EnsureSession(home, canonA, testStart, nil)
	if err != nil {
		t.Fatalf("ensure active session: %v", err)
	}
	// Seed the target with a visible user+assistant exchange so the switch's transcript
	// replay (Transcript: app in newResumeDeps) has prior history to re-render; these
	// records reach disk through mustFlush and are reloaded by the production loader.
	const (
		targetQuestion = "TARGET-REPLAY-QUESTION"
		targetAnswer   = "TARGET-REPLAY-ANSWER"
	)
	target, err := sessions.EnsureSession(home, canonA, testStart, []sessions.Record{
		sessions.Message{ID: ids.NewV7(), Role: "user", Content: sessions.TextContent(targetQuestion), Timestamp: testStart},
		sessions.Message{ID: ids.NewV7(), Role: "assistant", Content: sessions.TextContent(targetAnswer), Timestamp: testStart},
	})
	if err != nil {
		t.Fatalf("ensure target session: %v", err)
	}
	sibling, err := sessions.EnsureSession(home, canonB, testStart, nil)
	if err != nil {
		t.Fatalf("ensure sibling session: %v", err)
	}
	mustFlush(t, active)
	mustFlush(t, target)
	mustFlush(t, sibling)
	targetID := target.SessionID()

	beforeUpdated := readSessionFile(t, target.Path()).Metadata.UpdatedAt

	// Wrap the production /resume deps where StartTUI builds them: only the
	// headless-incompatible picker is replaced (DW1's selection stand-in) and the
	// load/switch/refresh capabilities are wrapped to record order (DW4). Everything
	// else stays the production impl, and StartTUI remains responsible for building
	// the app, installing the command-event flush hook, building the production
	// registry with the /resume handler, and setting the submit adapter — so a
	// regression in that /resume wiring fails this test.
	ord := &orderTicker{}
	picker := &selectingResumePicker{selectID: targetID}
	const retainedStreamChars = 137 // distinctive count carried into the durable stream_interrupted
	var loader *recordingResumeLoader
	var sw *recordingResumeSwitch
	var ref *recordingResumeRefresher
	buildResumeDeps := newResumeDeps // the production builder, captured before the swap
	defer swapNewResumeDeps(func(c context.Context, app *tui.App, r *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, active *model.ActiveState, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
		deps := buildResumeDeps(c, app, r, lock, cache, active, recorder, conf)
		loader = &recordingResumeLoader{inner: deps.Loader, ord: ord}
		sw = &recordingResumeSwitch{inner: deps.Switch, ord: ord}
		ref = &recordingResumeRefresher{inner: deps.Refresh, ord: ord}
		deps.Loader = loader
		deps.Switch = sw
		deps.Refresh = ref
		deps.Picker = picker
		// Report an in-flight stream so the selection path records (and must flush) a
		// stream_interrupted on the prior session — pinning runResumeSwitch's pre-switch
		// flush, which the production no-op canceller would leave unwitnessed.
		deps.Stream = inFlightStreamCanceller{retainedChars: retainedStreamChars}
		return deps
	})()

	// Launch folder A through the real StartTUI assembly: it installs active, the
	// flush hook, the production registry (with the wrapped /resume deps), and the
	// submit adapter on the app it builds.
	result := &BootstrapResult{Home: home, LaunchDir: folderA, Session: active}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	// Seed a distinct visible marker into the active session's pane (on top of the
	// launch banner StartTUI rendered) so the post-switch assertion proves the chosen
	// session's history replaced it — not merely that the pane is non-empty.
	const activeMarker = "ACTIVE-SESSION-VISIBLE-MARKER"
	app.Append(activeMarker)
	if pre := app.TranscriptText(); !strings.Contains(pre, activeMarker) {
		t.Fatalf("precondition: active marker should be visible before /resume:\n%s", pre)
	}

	// DW1: /resume goes through the app's installed submit adapter, not a direct
	// handler call — a regression in StartTUI's registry/submit wiring fails here.
	if !app.SubmitInput("/resume") {
		t.Fatal("/resume should be accepted through the production submit adapter StartTUI installed")
	}

	// DW2: the picker was shown exactly folder A's non-active session; folder B's
	// session and the active session are both absent.
	if len(picker.presented) != 1 {
		t.Fatalf("picker presented %d times, want 1", len(picker.presented))
	}
	rows := picker.presented[0]
	if len(rows) != 1 || rows[0].ID != targetID {
		t.Fatalf("picker rows = %+v, want only the current-folder target %s", rows, targetID)
	}
	for _, r := range rows {
		if r.ID == sibling.SessionID() {
			t.Fatalf("sibling folder session %s appeared in the picker; rows must be scoped to the current folder", sibling.SessionID())
		}
		if r.ID == active.SessionID() {
			t.Fatalf("active session %s offered as a resume target; it must be excluded", active.SessionID())
		}
	}

	// The switch committed: the chosen session is now active, replacing the prior one,
	// and its sidecar resume lock is held.
	chosen := app.ActiveStore()
	if chosen == active {
		t.Fatal("active store was not switched to the chosen session")
	}
	if chosen.SessionID() != targetID {
		t.Fatalf("active session id = %q after switch, want the chosen target %q", chosen.SessionID(), targetID)
	}
	if !resumeLockHeld(t, chosen.Path()) {
		t.Error("chosen session's resume sidecar lock is not held after the switch")
	}

	// DW (transcript replay): the production newResumeDeps wires Transcript: app, so the
	// switch resets the visible pane and replays the chosen session's prior conversation.
	// Assert the rendered transcript holds the target's user+assistant exchange in live
	// form and no longer holds the active session's pre-switch marker. This pins the real
	// Transcript: app wiring — removing it from newResumeDeps leaves the active marker in
	// place and the target history un-replayed, failing both checks.
	transcript := app.TranscriptText()
	wantReplay := "▌ " + targetQuestion + "\n\n" + targetAnswer
	if !strings.Contains(transcript, wantReplay) {
		t.Fatalf("resumed transcript missing the chosen session's replayed history %q\n--- transcript ---\n%s", wantReplay, transcript)
	}
	if strings.Contains(transcript, activeMarker) {
		t.Fatalf("active session's pre-switch marker %q survived the switch; the pane was not reset for the chosen session\n--- transcript ---\n%s", activeMarker, transcript)
	}

	// DW3: the prior session file holds the durable slash_command{resume, success}
	// flushed before the picker opened (canonical name, empty args).
	priorDisk := readSessionFile(t, active.Path())
	cmds := diskSlashCommands(t, priorDisk)
	if len(cmds) != 1 || cmds[0].Name != "resume" || cmds[0].Outcome != "success" {
		t.Fatalf("prior disk slash_command = %+v, want one {resume, success}", cmds)
	}
	if len(cmds[0].Args) != 0 {
		t.Fatalf("resume slash_command args = %v, want empty", cmds[0].Args)
	}

	// DW3: the selection-time pre-switch flush is pinned. runResumeSwitch cancels the
	// in-flight stream the wrapped canceller reports and appends
	// stream_interrupted{slash_resume_switch} on the prior session immediately before
	// its pre-switch prior.Flush; reading that event back from disk proves the
	// selection path flushed the prior session (it would vanish if that flush were
	// removed, which the picker-open /resume slash_command flush cannot witness).
	interrupts := diskStreamInterrupted(t, priorDisk)
	if len(interrupts) != 1 || interrupts[0].Source != "slash_resume_switch" || interrupts[0].ContentChars != int64(retainedStreamChars) {
		t.Fatalf("prior disk stream_interrupted = %+v, want one {slash_resume_switch, %d chars}", interrupts, retainedStreamChars)
	}

	// DW3: the chosen session file holds launch_began{resume} as its anchor and a
	// durable updated_at advanced past started_at (it must not regress and must sit
	// past started_at). This pins durability of the chosen session, not the refresh
	// in isolation: runResumeSwitch flushes the chosen session again after the refresh
	// (the final target.Flush, cmd_resume.go), and every flush re-stamps updated_at, so
	// the disk value reflects that final flush regardless of the refresh. The refresh's
	// invocation and ordering are pinned separately by DW4 below (ref.at > sw.at).
	chosenDisk := readSessionFile(t, chosen.Path())
	if got := firstLaunchBeganSource(t, chosenDisk); got != "resume" {
		t.Fatalf("chosen session first launch_began source = %q, want %q", got, "resume")
	}
	if kinds := diskEventKinds(chosenDisk); len(kinds) == 0 || kinds[0] != events.KindLaunchBegan {
		t.Fatalf("chosen session disk kinds = %v, want to begin with launch_began", kinds)
	}
	afterUpdated := chosenDisk.Metadata.UpdatedAt
	if afterUpdated.Before(beforeUpdated) {
		t.Fatalf("chosen session updated_at regressed: before %s, after %s", beforeUpdated, afterUpdated)
	}
	if !afterUpdated.After(chosenDisk.Metadata.StartedAt) {
		t.Fatalf("chosen session updated_at %s not advanced past started_at %s (chosen session not durably re-flushed after the switch)", afterUpdated, chosenDisk.Metadata.StartedAt)
	}

	// DW4: on the real production deps the in-process switch ran load (+ CWD-match)
	// before the sidecar-lock handoff before the updated_at refresh.
	if loader.at <= 0 || sw.at <= loader.at || ref.at <= sw.at {
		t.Fatalf("in-process switch order load=%d switch=%d refresh=%d, want strictly increasing", loader.at, sw.at, ref.at)
	}
	// The active-store install (Activate) is the two-phase switch's second
	// step — it runs after the lock handoff (sw.at) and after the launch anchor, i.e.
	// before the refresh, so no fresh-launch background prune can target the chosen
	// session before its launch_began landed.
	if sw.activateAt <= sw.at || ref.at <= sw.activateAt {
		t.Fatalf("activate order switch=%d activate=%d refresh=%d, want switch<activate<refresh", sw.at, sw.activateAt, ref.at)
	}
}

// TestTRTUI9_ResumeRestoresModelFromTargetStream pins the in-TUI model restoration end
// to end: a /resume into a session whose record stream carries a valid model_turn
// restores that model as the run's active selection (source resume), observable
// through the /status overlay the run renders after the switch. It launches through
// the real StartTUI assembly (so the production resumeModelRecoverer and the config
// cache that allows the seeded provider/model are the ones under test) and injects
// only the headless-incompatible picker. It fails against a no-op recovery seam, where
// the switch left the active selection untouched and /status showed no model.
func TestTRTUI9_ResumeRestoresModelFromTargetStream(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	folder := t.TempDir()

	canon, err := sessions.CanonicalizeFolder(folder)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	active, err := sessions.EnsureSession(home, canon, testStart, nil)
	if err != nil {
		t.Fatalf("ensure active: %v", err)
	}
	target, err := sessions.EnsureSession(home, canon, testStart, nil)
	if err != nil {
		t.Fatalf("ensure target: %v", err)
	}
	// Seed the target's record stream with a valid model_turn so step-1
	// recovery has a selection to restore on the switch, then flush both so the real
	// lister/loader enumerate and reload them from disk.
	if _, err := events.Append(target, events.ModelTurn{
		Provider: "openai", ModelID: "gpt-5.5", Effort: "high", Source: "picker",
	}); err != nil {
		t.Fatalf("seed target model_turn: %v", err)
	}
	mustFlush(t, active)
	mustFlush(t, target)
	targetID := target.SessionID()

	// Inject only the headless-incompatible picker; the model recoverer and every other
	// capability stay the production impls StartTUI builds (with the config cache below
	// that allows the seeded provider/model so step-1 recovery validates).
	picker := &selectingResumePicker{selectID: targetID}
	buildResumeDeps := newResumeDeps
	defer swapNewResumeDeps(func(c context.Context, app *tui.App, r *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, act *model.ActiveState, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
		deps := buildResumeDeps(c, app, r, lock, cache, act, recorder, conf)
		deps.Picker = picker
		return deps
	})()

	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        folder,
		ProjectRoot:      folder,
		Session:          active,
		Config:           map[string]any{"provider": map[string]any{"openai": map[string]any{}}},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/resume") {
		t.Fatal("/resume should be accepted through the production submit adapter")
	}
	if got := app.ActiveStore().SessionID(); got != targetID {
		t.Fatalf("active session id = %q after switch, want target %q", got, targetID)
	}

	// The recovered model is now the run's active selection (source resume), observable
	// through the /status overlay the run renders after the switch.
	if !app.SubmitInput("/status") {
		t.Fatal("/status should be accepted after the resume switch")
	}
	overlay := app.StatusText()
	for _, want := range []string{"Provider: openai", "Model: gpt-5.5", "Effort: high"} {
		if !strings.Contains(overlay, want) {
			t.Errorf("status overlay missing %q after resume restoration\n--- overlay ---\n%s", want, overlay)
		}
	}
}

// TestTRTUI9_ResumeRecoveryFailureIsPersisted pins the recovery-failure
// durability boundary: the production /resume switch appends model_recovery_failed
// during model recovery, then the final target.Flush makes that event durable before
// control returns to the TUI. It reopens the chosen session from disk, so it fails if
// the append is only present in memory or the final target flush no longer covers the
// model-recovery record.
func TestTRTUI9_ResumeRecoveryFailureIsPersisted(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	folder := t.TempDir()

	canon, err := sessions.CanonicalizeFolder(folder)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	active, err := sessions.EnsureSession(home, canon, testStart, nil)
	if err != nil {
		t.Fatalf("ensure active: %v", err)
	}
	target, err := sessions.EnsureSession(home, canon, testStart, nil)
	if err != nil {
		t.Fatalf("ensure target: %v", err)
	}
	// gpt-9 is not in the run config allowlist below, so step-1 recovery
	// appends model_recovery_failed and opens the picker instead of adopting it.
	if _, err := events.Append(target, events.ModelTurn{
		Provider: "openai", ModelID: "gpt-9", Effort: "high", Source: "picker",
	}); err != nil {
		t.Fatalf("seed invalid target model_turn: %v", err)
	}
	mustFlush(t, active)
	mustFlush(t, target)
	targetID := target.SessionID()

	picker := &selectingResumePicker{selectID: targetID}
	buildResumeDeps := newResumeDeps
	defer swapNewResumeDeps(func(c context.Context, app *tui.App, r *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, act *model.ActiveState, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
		deps := buildResumeDeps(c, app, r, lock, cache, act, recorder, conf)
		deps.Picker = picker
		return deps
	})()

	seedOpenAIDiscovered(t, SettingsPath(home), "gpt-5.5")
	result := &BootstrapResult{
		Home:             home,
		LaunchDir:        folder,
		ProjectRoot:      folder,
		Session:          active,
		Config:           map[string]any{"provider": map[string]any{"openai": map[string]any{}}},
		ConfigLayerPaths: []string{SettingsPath(home)},
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("/resume") {
		t.Fatal("/resume should be accepted through the production submit adapter")
	}
	if got := app.ActiveStore().SessionID(); got != targetID {
		t.Fatalf("active session id = %q after switch, want target %q", got, targetID)
	}

	recoveryFailures := diskModelRecoveryFailed(t, readSessionFile(t, target.Path()))
	if len(recoveryFailures) != 1 {
		t.Fatalf("durable model_recovery_failed events = %d, want exactly 1", len(recoveryFailures))
	}
	if recoveryFailures[0].Reason != "validation_failed" || !strings.Contains(recoveryFailures[0].ErrorDetail, "gpt-9") {
		t.Fatalf("durable model_recovery_failed = %+v, want validation_failed mentioning gpt-9", recoveryFailures[0])
	}
}

// TestTRTUI9_ResumeSwitch_MirrorsColdStartSubsequence pins DW4's cold-start half:
// the in-process /resume switch follows the same load -> CWD-match -> sidecar-lock
// -> updated_at refresh order the cold-start `codemeld --resume <id>` path
// runs. It drives runResumeWithID with recording steps and asserts the resume
// sub-sequence places ResolveResume (resolve + CWD-match) before AcquireLock
// (the sidecar lock) before AppendLaunchBegan before RefreshUpdatedAt.
func TestTRTUI9_ResumeSwitch_MirrorsColdStartSubsequence(t *testing.T) {
	var order []string
	if _, err := runResumeWithID(context.Background(), "/home/u", "/cwd", "the-id", recordingResumeSteps(&order)); err != nil {
		t.Fatalf("runResumeWithID: %v", err)
	}
	seq := []string{"R1:ResolveResume", "R2:AcquireLock", "R3:AppendLaunchBegan", "R4:RefreshUpdatedAt"}
	for i := 1; i < len(seq); i++ {
		prev, cur := slices.Index(order, seq[i-1]), slices.Index(order, seq[i])
		if prev < 0 || cur < 0 || prev >= cur {
			t.Fatalf("cold-start resume sub-sequence %v not in order within %v", seq, order)
		}
	}
}

func TestTRTUI9_ResumeAppendsTheLaunchCapabilityToTheTarget(t *testing.T) {
	calls := swapResolveExecutionCapability(t, injectedResolution)
	home, folder := t.TempDir(), t.TempDir()
	canon, err := sessions.CanonicalizeFolder(folder)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	active, err := sessions.EnsureSession(home, canon, testStart, nil)
	if err != nil {
		t.Fatalf("ensure active: %v", err)
	}
	earlier := events.ExecutionCapability{Capability: "refused", Reason: "earlier launch"}
	target, err := sessions.EnsureSession(home, canon, testStart, nil)
	if err != nil {
		t.Fatalf("ensure target: %v", err)
	}
	if _, err := events.Append(target, earlier); err != nil {
		t.Fatal(err)
	}
	mustFlush(t, active)
	mustFlush(t, target)

	buildResumeDeps := newResumeDeps
	defer swapNewResumeDeps(func(c context.Context, app *tui.App, r *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, act *model.ActiveState, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
		deps := buildResumeDeps(c, app, r, lock, cache, act, recorder, conf)
		deps.Picker = &selectingResumePicker{selectID: target.SessionID()}
		return deps
	})()
	app, restore := startCaptured(t, context.Background(), &BootstrapResult{Home: home, LaunchDir: folder, Session: active}, io.Discard)
	defer restore()

	if !app.SubmitInput("/resume") {
		t.Fatal("/resume should be accepted")
	}
	if app.ActiveStore().SessionID() != target.SessionID() {
		t.Fatal("active store was not switched to the target")
	}
	disk := readSessionFile(t, target.Path())
	caps := decodeDiskEvents[events.ExecutionCapability](t, disk, events.KindExecutionCapability)
	if *calls != 1 || len(caps) != 2 || !reflect.DeepEqual(caps[0], earlier) || !reflect.DeepEqual(caps[1], injectedCapability) {
		t.Fatalf("Resolve calls = %d, capabilities = %+v, want one call and the launch capability appended after %+v", *calls, caps, earlier)
	}
}
