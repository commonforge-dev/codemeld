// Tests for the /resume handler: listing scope, the empty/enumeration-failure
// paths, skipped-id notices, navigation/dismissal, the on-selection switch event
// order, the older-schema fork handoff, and the lock/load failure paths — all
// driven through fakes for the ResumeDeps capabilities so no terminal driver,
// real filesystem (beyond t.TempDir for flush boundaries), or production app
// wiring is required.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/sessions"
)

type fakeLister struct {
	entries []ResumeEntry
	skipped []sessions.SkippedID
	err     error
}

func (l *fakeLister) List() ([]ResumeEntry, []sessions.SkippedID, error) {
	return l.entries, l.skipped, l.err
}

// fakePicker drives the continuation contract synchronously: Present records the
// entries it was shown and immediately invokes the result callback with the preset
// PickerResult (and PresentEmpty its dismiss callback), so a test can assert the
// post-selection effects right after dispatch returns. The production picker fires
// these callbacks asynchronously off the tview event loop instead (picker_resume.go).
// With deferCallback set, Present/PresentEmpty instead capture the callback without
// invoking it — modelling the production picker that returns to the event loop before
// the user acts, so a test can assert what is durable while the picker is still open.
type fakePicker struct {
	presented     [][]ResumeEntry
	emptyShown    []string
	result        PickerResult
	deferCallback bool
	pending       func(PickerResult)
	pendingEmpty  func()
	actions       ResumeActions
}

func (p *fakePicker) Present(entries []ResumeEntry, onResult func(PickerResult), actions ResumeActions) {
	p.presented = append(p.presented, entries)
	p.actions = actions
	if p.deferCallback {
		p.pending = onResult
		return
	}
	onResult(p.result)
}

func (p *fakePicker) PresentEmpty(message string, onDismiss func()) {
	p.emptyShown = append(p.emptyShown, message)
	if p.deferCallback {
		p.pendingEmpty = onDismiss
		return
	}
	onDismiss()
}

type callRecorder struct {
	order *callOrder
	at    int
	calls int
}

func (r *callRecorder) mark() {
	r.calls++
	r.at = r.tick()
}

func (r *callRecorder) tick() int {
	if r.order == nil {
		return 0
	}
	return r.order.tick()
}

type fakeLoader struct {
	callRecorder
	gotEntry ResumeEntry
	target   *sessions.Store
	older    bool
	failCat  fserrors.Category
	err      error
}

func (l *fakeLoader) Load(entry ResumeEntry) (*sessions.Store, bool, fserrors.Category, error) {
	l.mark()
	l.gotEntry = entry
	if l.err != nil {
		return nil, l.older, l.failCat, l.err
	}
	return l.target, l.older, l.failCat, l.err
}

type fakeSwitch struct {
	callRecorder
	gotTarget     *sessions.Store
	gotPrior      *sessions.Store
	err           error
	sealOnSuccess bool
	// activate phase: recorded separately so a test can prove Activate (the active-store
	// install) runs only after the launch anchor. activateAt is its call-order tick;
	// activateKinds snapshots the event kinds present on the target at the instant
	// Activate ran, so a test can assert launch_began was already emitted onto the target
	// before it became visible as the active session.
	activateCalls  int
	activateTarget *sessions.Store
	activateAt     int
	activateKinds  []string
	warning        string
	activateErr    error
}

func (s *fakeSwitch) Switch(target, prior *sessions.Store) error {
	s.mark()
	s.gotTarget = target
	s.gotPrior = prior
	if s.err != nil {
		return s.err
	}
	// Model the production swap, which seals the prior store against further appends
	// once the switch commits, so a test can prove the prior session stays usable
	// when the switch is refused.
	if s.sealOnSuccess && prior != nil {
		prior.Close()
	}
	return nil
}

func (s *fakeSwitch) Activate(target *sessions.Store) (string, error) {
	s.activateCalls++
	s.activateTarget = target
	s.activateAt = s.tick()
	s.activateKinds = eventKinds(target.Records())
	return s.warning, s.activateErr
}

type abortableSwitch struct {
	*fakeSwitch
	aborts  int
	abortAt int
}

func (s *abortableSwitch) Abort() {
	s.aborts++
	s.abortAt = s.tick()
}

func withAbortableSwitch(fx *resumeFixture) *abortableSwitch {
	sw := &abortableSwitch{fakeSwitch: fx.sw}
	fx.deps.Switch = sw
	return sw
}

type cancellingReplayer struct {
	cancel context.CancelFunc
	calls  int
	target *sessions.Store
}

func (r *cancellingReplayer) Replay(target *sessions.Store) error {
	r.calls++
	r.target = target
	r.cancel()
	return nil
}

type targetRecorder struct {
	callRecorder
	target *sessions.Store
	err    error
}

func (r *targetRecorder) record(target *sessions.Store) error {
	r.mark()
	r.target = target
	return r.err
}

func (r *targetRecorder) Refresh(_ context.Context, target *sessions.Store) error {
	return r.record(target)
}

func (r *targetRecorder) Recover(target *sessions.Store) error {
	return r.record(target)
}

type fakeForker struct {
	calls  int
	target *sessions.Store
	err    error
}

func (f *fakeForker) OfferFork(target *sessions.Store) error {
	f.calls++
	f.target = target
	return f.err
}

// fakeTranscriptReplayer records the reset-then-replay calls and their order so a
// test can prove the visible pane is reset and the target session's records replayed
// only after an equal-schema switch commits — and never on the load-failure/older-schema
// branches. resetAt/replayAt are call-order ticks; replayed captures the snapshot handed
// to ReplaySessionRecords so the test can assert it is the loaded session's stream.
type fakeTranscriptReplayer struct {
	callRecorder
	resets   int
	replays  int
	resetAt  int
	replayAt int
	replayed []sessions.Record
}

func (r *fakeTranscriptReplayer) ResetTranscript() {
	r.resets++
	r.resetAt = r.tick()
}

func (r *fakeTranscriptReplayer) ReplaySessionRecords(records []sessions.Record) {
	r.replays++
	r.replayed = records
	r.replayAt = r.tick()
}

// resumeFixture bundles the fakes a test inspects plus a writable target store so
// the post-switch launch_began emission and the post-replay flush actually
// succeed.
type resumeFixture struct {
	deps       ResumeDeps
	lister     *fakeLister
	picker     *fakePicker
	stream     *fakeStream
	marker     *fakeStreamTranscript
	loader     *fakeLoader
	sw         *fakeSwitch
	refresher  *targetRecorder
	model      *targetRecorder
	agents     *fakeReplayer
	fork       *fakeForker
	wf         *fakeWriteFailure
	transcript *fakeTranscriptReplayer
	order      *callOrder
}

func (fx *resumeFixture) target() *sessions.Store { return fx.loader.target }

func newResumeFixture(t *testing.T) *resumeFixture {
	t.Helper()
	order := &callOrder{}
	rec := func() callRecorder { return callRecorder{order: order} }
	target := sessions.New(filepath.Join(t.TempDir(), "target.json"), &sessions.Session{})
	fx := &resumeFixture{
		lister:     &fakeLister{},
		picker:     &fakePicker{},
		stream:     &fakeStream{},
		marker:     &fakeStreamTranscript{},
		loader:     &fakeLoader{callRecorder: rec(), target: target},
		sw:         &fakeSwitch{callRecorder: rec(), sealOnSuccess: true},
		refresher:  &targetRecorder{callRecorder: rec()},
		model:      &targetRecorder{callRecorder: rec()},
		agents:     &fakeReplayer{order: order},
		fork:       &fakeForker{},
		wf:         &fakeWriteFailure{},
		transcript: &fakeTranscriptReplayer{callRecorder: rec()},
		order:      order,
	}
	fx.deps = ResumeDeps{
		Lister:           fx.lister,
		Picker:           fx.picker,
		Stream:           fx.stream,
		StreamTranscript: fx.marker,
		Loader:           fx.loader,
		Switch:           fx.sw,
		Refresh:          fx.refresher,
		Model:            fx.model,
		Agents:           fx.agents,
		Fork:             fx.fork,
		WriteFailure:     fx.wf,
		Transcript:       fx.transcript,
	}
	return fx
}

// newResumeRegistry builds a Registry whose "resume" entry is bound to
// NewResumeHandler(deps), so dispatching "/resume" exercises the handler through
// the registry dispatch path.
func newResumeRegistry(t *testing.T, deps ResumeDeps) *Registry {
	t.Helper()
	r, err := NewRegistry([]Command{
		{
			Name:        "resume",
			Description: "Open the session picker to resume a session",
			ArgSig:      ArgNone,
			Phase:       PhaseOne,
			Handler:     NewResumeHandler(deps),
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func dispatchResume(t *testing.T, fx *resumeFixture, host CommandHost) DispatchResult {
	t.Helper()
	return newResumeRegistry(t, fx.deps).DispatchSlashInput("/resume", host)
}

func twoEntries() []ResumeEntry {
	return []ResumeEntry{
		{ID: "0190aaaa", Preview: "first prompt a"},
		{ID: "0190bbbb", Preview: "first prompt b"},
	}
}

// TestResumeHandler_FlushesSuccessBeforeOpeningPicker pins the FlushActive contract for
// the continuation reshape: the picker-open slash_command{success} must be durable on
// disk before the handler returns to dispatch. The production picker's Present returns
// immediately, so a deferred fake picker (callback not yet fired) stands in for "the
// picker is open and the user has not acted yet". If the success were only appended in
// memory, a crash while the picker is open would lose the accepted /resume audit event;
// flushing before opening prevents that and keeps a flush failure on the synchronous
// dispatch path.
func TestResumeHandler_FlushesSuccessBeforeOpeningPicker(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.deferCallback = true

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /resume = %+v, want Handled/nil-err", res)
	}
	if fx.picker.pending == nil {
		t.Fatal("picker callback fired synchronously; the deferred picker must hold it open")
	}

	// The accepted /resume audit event must already have been recorded and flushed before
	// the picker opened — not deferred into the (not-yet-fired) continuation. fakeHost's
	// FlushActive does not touch disk, so assert the call itself: exactly one flush has
	// happened, before the picker callback (which is where the pre-fix code flushed) ever
	// runs. The pre-fix handler would show zero flushes here.
	if evs := host.events(); len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Fatalf("slash_command events = %v, want one success recorded before the picker opened", evs)
	}
	if host.flushes != 1 {
		t.Errorf("FlushActive calls before the picker callback = %d, want 1 (success flushed before opening, not deferred)", host.flushes)
	}
}

// TestResumeHandler_WiresPickerActions pins the picker action seam: NewResumeHandler builds
// a ResumeActions bundle from the deps and hands it to Present. ReList re-enumerates via
// the lister (ignoring skipped ids), and Rename/Delete are wired from the deps' renamer /
// deleter. The mutation actions are side-effect-only and never resolve the continuation.
func TestResumeHandler_WiresPickerActions(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.lister.skipped = []sessions.SkippedID{{ID: "skip-me"}}
	fx.picker.deferCallback = true

	renamed, deleted := "", ""
	fx.deps.Rename = renamerFunc(func(_ ResumeEntry, title string) error { renamed = title; return nil })
	fx.deps.Delete = deleterFunc(func(e ResumeEntry) error { deleted = e.ID; return nil })

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /resume = %+v, want Handled/nil-err", res)
	}

	acts := fx.picker.actions
	if acts.ReList == nil || acts.Rename == nil || acts.Delete == nil {
		t.Fatalf("actions = %+v, want ReList/Rename/Delete all wired", acts)
	}
	// ReList re-enumerates via the lister and drops skipped ids.
	got, lerr := acts.ReList()
	if lerr != nil {
		t.Fatalf("ReList: %v", lerr)
	}
	if len(got) != len(fx.lister.entries) {
		t.Errorf("ReList returned %d entries, want %d (skipped ids ignored)", len(got), len(fx.lister.entries))
	}
	// Rename/Delete delegate to the wired deps without resolving the continuation.
	if err := acts.Rename(twoEntries()[0], "new title"); err != nil || renamed != "new title" {
		t.Errorf("Rename action: err=%v renamed=%q, want nil / %q", err, renamed, "new title")
	}
	if err := acts.Delete(twoEntries()[1]); err != nil || deleted != "0190bbbb" {
		t.Errorf("Delete action: err=%v deleted=%q, want nil / %q", err, deleted, "0190bbbb")
	}
	if fx.picker.pending == nil {
		t.Error("picker continuation fired during a mutation; only Enter/ESC may resolve it")
	}
}

// renamerFunc / deleterFunc adapt a plain func to the SessionRenamer / SessionDeleter
// interfaces so a test can wire the handler's rename/delete deps inline.
type renamerFunc func(entry ResumeEntry, title string) error

func (f renamerFunc) Rename(entry ResumeEntry, title string) error { return f(entry, title) }

type deleterFunc func(entry ResumeEntry) error

func (f deleterFunc) Delete(entry ResumeEntry) error { return f(entry) }

// TestResumeHandler_SelectionSwitchesAndOrdersEvents pins DW1/DW2: a selection
// records slash_command{success} on the current session before switching, cancels
// the in-flight stream, flushes the prior session, loads the target, and replays
// the launch/refresh/model/agent anchors on the loaded session in the required
// order.
func TestResumeHandler_SelectionSwitchesAndOrdersEvents(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 1}
	fx.stream.inFlight = true
	fx.stream.retained = 50
	fx.agents.replays = []events.AgentInstructionsLoaded{
		{Path: "/g/AGENTS.md", Layer: "global", LoadOrder: 1},
	}

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /resume = %+v, want Handled/nil-err", res)
	}

	// Prior session: slash_command{success} recorded before the switch, then
	// stream_interrupted{slash_resume_switch} from the pre-switch cancellation.
	priorKinds := eventKinds(host.store.Records())
	wantPrior := []string{events.KindSlashCommand, events.KindStreamInterrupted}
	if !equalStrings(priorKinds, wantPrior) {
		t.Fatalf("prior session event order = %v, want %v", priorKinds, wantPrior)
	}
	evs := host.events()
	if len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Fatalf("prior slash_command events = %v, want one success", evs)
	}
	var si events.StreamInterrupted
	decodeEventPayload(t, host.store.Records()[1], &si)
	if si.Source != "slash_resume_switch" || si.ContentChars != 50 {
		t.Errorf("stream_interrupted = %+v, want source slash_resume_switch / 50 chars", si)
	}
	if fx.marker.marks != 1 {
		t.Fatalf("transcript interruption marks = %d, want 1", fx.marker.marks)
	}

	// The current session was flushed before the switch (its records are on disk).
	priorData, err := os.ReadFile(host.store.Path())
	if err != nil {
		t.Fatalf("prior session not flushed to disk: %v", err)
	}
	if !strings.Contains(string(priorData), events.KindSlashCommand) {
		t.Errorf("flushed prior session missing slash_command:\n%s", priorData)
	}

	// The chosen entry was loaded and handed to the switch.
	if fx.loader.calls != 1 || fx.loader.gotEntry.ID != "0190bbbb" {
		t.Errorf("loader calls=%d gotID=%q, want 1 / 0190bbbb", fx.loader.calls, fx.loader.gotEntry.ID)
	}
	if fx.sw.calls != 1 || fx.sw.gotTarget != fx.target() || fx.sw.gotPrior != host.store {
		t.Errorf("switch calls=%d target=%p prior=%p, want 1 / target / prior", fx.sw.calls, fx.sw.gotTarget, fx.sw.gotPrior)
	}

	// Loaded session: launch_began{resume} is the first new event, then the replayed
	// agent_instructions_loaded.
	targetKinds := eventKinds(fx.target().Records())
	wantTarget := []string{events.KindLaunchBegan, events.KindAgentInstructionsLoaded}
	if !equalStrings(targetKinds, wantTarget) {
		t.Fatalf("loaded session event order = %v, want %v", targetKinds, wantTarget)
	}
	var lb events.LaunchBegan
	decodeEventPayload(t, fx.target().Records()[0], &lb)
	if lb.Source != "resume" {
		t.Errorf("launch_began source = %q, want resume", lb.Source)
	}

	// Call order: load -> switch -> refresh -> model recovery -> agent replay.
	seq := []int{fx.loader.at, fx.sw.at, fx.refresher.at, fx.model.at, fx.agents.at}
	for i := 1; i < len(seq); i++ {
		if seq[i-1] >= seq[i] {
			t.Errorf("call order load=%d switch=%d refresh=%d model=%d agents=%d, want strictly increasing",
				fx.loader.at, fx.sw.at, fx.refresher.at, fx.model.at, fx.agents.at)
			break
		}
	}
	if fx.refresher.target != fx.target() || fx.model.target != fx.target() || fx.agents.target != fx.target() {
		t.Error("refresh/model/agents did not all target the loaded session")
	}

	// The active-store install (Activate) is deferred until after the
	// launch anchor. It runs exactly once, on the loaded session, between the switch and
	// the refresh, and at the moment it runs launch_began is already on the target — so
	// the target never becomes the active session ahead of its own launch anchor (the
	// window a fresh-launch background prune could otherwise write into).
	if fx.sw.activateCalls != 1 || fx.sw.activateTarget != fx.target() {
		t.Fatalf("Activate calls=%d target=%p, want 1 on the loaded session %p", fx.sw.activateCalls, fx.sw.activateTarget, fx.target())
	}
	if fx.sw.activateAt <= fx.sw.at || fx.refresher.at <= fx.sw.activateAt {
		t.Errorf("activate order switch=%d activate=%d refresh=%d, want switch<activate<refresh", fx.sw.at, fx.sw.activateAt, fx.refresher.at)
	}
	if !slices.Contains(fx.sw.activateKinds, events.KindLaunchBegan) {
		t.Errorf("target event kinds at Activate = %v, want launch_began already emitted before the active-store install", fx.sw.activateKinds)
	}
}

func TestResumeHandler_EqualSchemaSwitchWaitsForCancelledTurn(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 1}
	stream := &drainingStream{order: fx.order, entered: make(chan struct{}), release: make(chan struct{})}
	stream.inFlight = true
	stream.retained = 21
	fx.deps.Stream = stream
	drainReg := newResumeRegistry(t, fx.deps)

	done := make(chan DispatchResult, 1)
	go func() { done <- drainReg.DispatchSlashInput("/resume", host) }()

	select {
	case <-stream.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the equal-schema switch never entered the turn drain after cancelling")
	}
	if _, err := os.Stat(host.store.Path()); !os.IsNotExist(err) {
		t.Fatalf("prior session file stat err = %v, want not-exist: the pre-switch flush ran while the cancelled turn was still draining", err)
	}
	if fx.sw.calls != 0 || fx.sw.activateCalls != 0 {
		t.Fatalf("Switch calls = %d, Activate calls = %d during the drain, want 0/0", fx.sw.calls, fx.sw.activateCalls)
	}

	close(stream.release)
	res := <-done
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /resume = %+v, want Handled/nil-err", res)
	}

	if stream.waits != 1 {
		t.Fatalf("WaitTurnDrained calls = %d, want 1", stream.waits)
	}
	if stream.waitAt == 0 || stream.waitAt >= fx.sw.at {
		t.Fatalf("drain tick = %d, Switch tick = %d: the wait must precede the switch", stream.waitAt, fx.sw.at)
	}
	priorData, err := os.ReadFile(host.store.Path())
	if err != nil {
		t.Fatalf("prior session not durable after the drain released: %v", err)
	}
	if !strings.Contains(string(priorData), events.KindStreamInterrupted) {
		t.Errorf("flushed prior session missing stream_interrupted:\n%s", priorData)
	}
	if fx.sw.activateCalls != 1 || fx.sw.activateTarget != fx.target() {
		t.Fatalf("Activate calls = %d target = %p after the drain, want 1 on the loaded session %p", fx.sw.activateCalls, fx.sw.activateTarget, fx.target())
	}
	if fx.marker.marks != 1 {
		t.Fatalf("transcript interruption marks = %d, want 1", fx.marker.marks)
	}
}

func TestResumeHandler_NonSwitchingBranchesDoNotCancelOrWait(t *testing.T) {
	cases := []struct {
		name  string
		setup func(fx *resumeFixture)
	}{
		{"older schema", func(fx *resumeFixture) {
			fx.picker.result = PickerResult{Selected: true, Index: 0}
			fx.loader.older = true
		}},
		{"load failure", func(fx *resumeFixture) {
			fx.picker.result = PickerResult{Selected: true, Index: 0}
			fx.loader.failCat = fserrors.NotFound
			fx.loader.err = errors.New("pruned between listing and selection")
		}},
		{"picker dismissed", func(fx *resumeFixture) {
			fx.picker.result = PickerResult{Selected: false}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := newWritableHost(t)
			fx := newResumeFixture(t)
			fx.lister.entries = twoEntries()
			stream := &drainingStream{order: fx.order}
			stream.inFlight = true
			fx.deps.Stream = stream
			tc.setup(fx)

			if res := dispatchResume(t, fx, host); res.Err != nil {
				t.Fatalf("dispatch err: %v", res.Err)
			}
			if stream.calls != 0 {
				t.Errorf("Cancel called %d times, want 0 (the active turn must be left running)", stream.calls)
			}
			if stream.waits != 0 {
				t.Errorf("WaitTurnDrained called %d times, want 0 (a non-switching branch must not block on the active turn)", stream.waits)
			}
			if fx.marker.marks != 0 {
				t.Errorf("transcript interruption marks = %d, want 0", fx.marker.marks)
			}
		})
	}
}

// TestResumeHandler_SwitchResetsAndReplaysTranscript pins the post-switch replay: after an
// equal-schema switch commits, the handler resets the visible pane and replays the
// loaded session's records, in that order, and only after the switch — never before it,
// and before the post-switch resume-time events are appended.
func TestResumeHandler_SwitchResetsAndReplaysTranscript(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 1}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if fx.transcript.resets != 1 || fx.transcript.replays != 1 {
		t.Fatalf("transcript resets=%d replays=%d, want 1/1", fx.transcript.resets, fx.transcript.replays)
	}
	// Reset then replay, both after the switch commits and before the post-switch
	// launch/refresh/model/agent events land.
	ordered := fx.sw.at < fx.transcript.resetAt &&
		fx.transcript.resetAt < fx.transcript.replayAt &&
		fx.transcript.replayAt < fx.refresher.at
	if !ordered {
		t.Errorf("order switch=%d reset=%d replay=%d refresh=%d, want switch<reset<replay<refresh",
			fx.sw.at, fx.transcript.resetAt, fx.transcript.replayAt, fx.refresher.at)
	}
}

// TestResumeHandler_NoReplayWhenSwitchDoesNotCommit pins the replay guard: the two
// branches that never switch away — an older-schema selection (fork affordance) and a
// chosen-session load failure — leave the prior session's transcript untouched, so the
// pane is neither reset nor replayed.
func TestResumeHandler_NoReplayWhenSwitchDoesNotCommit(t *testing.T) {
	t.Run("older schema", func(t *testing.T) {
		host := newWritableHost(t)
		fx := newResumeFixture(t)
		fx.lister.entries = twoEntries()
		fx.picker.result = PickerResult{Selected: true, Index: 0}
		fx.loader.older = true

		if res := dispatchResume(t, fx, host); res.Err != nil {
			t.Fatalf("dispatch err: %v", res.Err)
		}
		if fx.fork.calls != 1 {
			t.Fatalf("fork calls=%d, want 1 (older-schema path)", fx.fork.calls)
		}
		if fx.transcript.resets != 0 || fx.transcript.replays != 0 {
			t.Errorf("older-schema resets=%d replays=%d, want 0/0", fx.transcript.resets, fx.transcript.replays)
		}
	})

	t.Run("load failure", func(t *testing.T) {
		host := newWritableHost(t)
		fx := newResumeFixture(t)
		fx.lister.entries = twoEntries()
		fx.picker.result = PickerResult{Selected: true, Index: 0}
		fx.loader.err = errors.New("pruned between list and select")
		fx.loader.failCat = fserrors.NotFound

		if res := dispatchResume(t, fx, host); res.Err != nil {
			t.Fatalf("dispatch err: %v", res.Err)
		}
		if fx.sw.calls != 0 {
			t.Fatalf("switch calls=%d, want 0 (load-failure path)", fx.sw.calls)
		}
		if fx.transcript.resets != 0 || fx.transcript.replays != 0 {
			t.Errorf("load-failure resets=%d replays=%d, want 0/0", fx.transcript.resets, fx.transcript.replays)
		}
	})
}

// TestResumeHandler_LoadedSessionRecordsAreFlushed pins that
// after a successful switch the loaded session's launch_began{resume} anchor and the
// replayed agent_instructions_loaded records must be durable on disk, not only in
// memory — a crash right after /resume would otherwise lose the post-switch records.
// The fakes never flush the target themselves, so its on-disk file is written solely by
// the handler's launch emit + post-replay flush; reading it back fails if the final
// target.Flush(ctx) in runResumeSwitch is removed or misdirected. Mirrors
// TestClearHandler_ReplayedAgentEventsAreFlushed.
func TestResumeHandler_LoadedSessionRecordsAreFlushed(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 1}
	fx.agents.replays = []events.AgentInstructionsLoaded{
		{Path: "/g/AGENTS.md", Layer: "global", LoadOrder: 1},
	}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	data, err := os.ReadFile(fx.target().Path())
	if err != nil {
		t.Fatalf("loaded session file not on disk (post-switch flush missing?): %v", err)
	}
	for _, want := range []string{events.KindLaunchBegan, events.KindAgentInstructionsLoaded} {
		if !strings.Contains(string(data), want) {
			t.Errorf("loaded session file missing durable %q event\n--- file ---\n%s", want, data)
		}
	}
}

// TestResumeHandler_LockFailureRecordsErrorAndKeepsCurrent pins DW2/DW7 (step 7):
// a lock timeout/acquire failure renders the prescribed notice, records
// slash_command{outcome:error} carrying the same one-line text, leaves the current
// session active, and never reaches launch_began/refresh/model/replay.
func TestResumeHandler_LockFailureRecordsErrorAndKeepsCurrent(t *testing.T) {
	host := newWritableHost(t)
	priorRef := host.store
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	lockText := "session 0190aaaa is in use by another codemeld instance"
	fx.sw.err = errors.New(lockText)

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err (command-level failure is handled)", res)
	}

	// Two slash_command events: the picker-open success, then the lock-failure error.
	evs := host.events()
	if len(evs) != 2 {
		t.Fatalf("slash_command events = %d, want 2 (success then error)", len(evs))
	}
	if got := decodeSlash(t, evs[0]); got.Outcome != "success" {
		t.Errorf("first slash_command outcome = %q, want success", got.Outcome)
	}
	errEv := decodeSlash(t, evs[1])
	if errEv.Outcome != "error" || errEv.ErrorDetail != lockText {
		t.Errorf("error slash_command = %+v, want outcome error / error_detail %q", errEv, lockText)
	}
	if len(host.notices) == 0 || host.notices[len(host.notices)-1] != lockText {
		t.Errorf("notices = %v, want last to be the lock text %q", host.notices, lockText)
	}

	// No post-switch work ran, and the current session stays active and appendable.
	if fx.refresher.calls != 0 || fx.model.calls != 0 || fx.agents.calls != 0 {
		t.Errorf("post-switch steps ran on a refused lock: refresh=%d model=%d agents=%d",
			fx.refresher.calls, fx.model.calls, fx.agents.calls)
	}
	if len(eventKinds(fx.target().Records())) != 0 {
		t.Error("loaded session gained events despite the refused switch")
	}
	if host.Store() != priorRef {
		t.Error("active store changed after a refused lock handoff")
	}
	before := len(priorRef.Records())
	priorRef.Append(sessions.Message{ID: "after-lock-fail", Role: "user", Content: sessions.TextContent("x")})
	if len(priorRef.Records()) != before+1 {
		t.Error("current session dropped an append after a refused lock handoff (it was sealed)")
	}
}

// TestResumeHandler_LockFailureNoticeStripsCLIPrefix pins step 7's in-TUI
// wording for a production lock failure: the production switch returns a real
// *sessions.ResumeLockError whose Error() carries the cold-start `codemeld:` stderr
// prefix, but the TUI notice and the recorded slash_command error_detail must render
// the prefix-free form. Both the timeout and non-timeout acquire-error shapes
// are covered. The plain-string sibling test above does not exercise the typed-error
// translation, so this is the regression guard for the CLI-prefix leak.
func TestResumeHandler_LockFailureNoticeStripsCLIPrefix(t *testing.T) {
	cases := []struct {
		name    string
		lockErr *sessions.ResumeLockError
		want    string
	}{
		{
			name:    "timeout",
			lockErr: &sessions.ResumeLockError{ID: "0190aaaa", Reason: locks.ReasonLockTimeout},
			want:    "session 0190aaaa in use by another codemeld instance",
		},
		{
			name:    "acquire_error",
			lockErr: &sessions.ResumeLockError{ID: "0190aaaa", Reason: locks.ReasonLockAcquireError, Cat: fserrors.PermissionDenied},
			want:    "session 0190aaaa: lock acquisition failed: permission denied",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Guard the premise: the production error text really does carry the prefix
			// this fix strips, so the assertions below are meaningful.
			if !strings.Contains(tc.lockErr.Error(), "codemeld:") {
				t.Fatalf("setup: lock error %q should carry the codemeld: CLI prefix", tc.lockErr.Error())
			}

			host := newWritableHost(t)
			fx := newResumeFixture(t)
			fx.lister.entries = twoEntries()
			fx.picker.result = PickerResult{Selected: true, Index: 0}
			fx.sw.err = tc.lockErr

			res := dispatchResume(t, fx, host)
			if res.Status != StatusHandled || res.Err != nil {
				t.Fatalf("dispatch = %+v, want Handled/nil-err (command-level failure is handled)", res)
			}

			if len(host.notices) == 0 || host.notices[len(host.notices)-1] != tc.want {
				t.Errorf("notices = %v, want last to be the prefix-free notice %q", host.notices, tc.want)
			}
			evs := host.events()
			if len(evs) != 2 {
				t.Fatalf("slash_command events = %d, want 2 (success then error)", len(evs))
			}
			errEv := decodeSlash(t, evs[1])
			if errEv.Outcome != "error" || errEv.ErrorDetail != tc.want {
				t.Errorf("error slash_command = %+v, want outcome error / error_detail %q", errEv, tc.want)
			}
			if strings.Contains(errEv.ErrorDetail, "codemeld:") {
				t.Errorf("error_detail %q still carries the codemeld: CLI prefix", errEv.ErrorDetail)
			}
		})
	}
}

// TestResumeHandler_EmptyFolder pins DW3 (step 2): an empty folder shows the
// canonical message (dismissed on any keypress) and records slash_command success,
// without opening the navigable picker or reaching the switch.
func TestResumeHandler_EmptyFolder(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if len(fx.picker.emptyShown) != 1 || fx.picker.emptyShown[0] != noResumableSessionsMsg {
		t.Errorf("PresentEmpty calls = %v, want one %q", fx.picker.emptyShown, noResumableSessionsMsg)
	}
	if len(fx.picker.presented) != 0 {
		t.Error("the navigable picker was opened for an empty folder")
	}
	if fx.loader.calls != 0 || fx.sw.calls != 0 {
		t.Errorf("loader/switch ran for an empty folder: load=%d switch=%d", fx.loader.calls, fx.sw.calls)
	}
	evs := host.events()
	if len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Fatalf("slash_command events = %v, want one success", evs)
	}
}

// TestResumeHandler_EnumerationFailure pins DW4 (step 3): a non-ENOENT listing
// failure renders the cannot-enumerate notice and records slash_command{error}
// with the same text as error_detail, without opening the picker.
func TestResumeHandler_EnumerationFailure(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.err = &sessions.ResumeListEnumerateError{
		Subdir:   "/home/u/.codemeld/sessions/abcd",
		Category: fserrors.PermissionDenied,
	}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	wantText := "session list: cannot enumerate /home/u/.codemeld/sessions/abcd: permission denied"
	if len(fx.picker.presented) != 0 || len(fx.picker.emptyShown) != 0 {
		t.Error("picker was opened despite an enumeration failure")
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("slash_command events = %d, want 1 (error only)", len(evs))
	}
	got := decodeSlash(t, evs[0])
	if got.Outcome != "error" || got.ErrorDetail != wantText {
		t.Errorf("slash_command = %+v, want outcome error / error_detail %q", got, wantText)
	}
	if len(host.notices) != 1 || host.notices[0] != wantText {
		t.Errorf("notices = %v, want exactly [%q]", host.notices, wantText)
	}
}

func TestResumeHandler_SkippedIDsRenderOneNotice(t *testing.T) {
	many := make([]sessions.SkippedID, 413)
	for i := range many {
		many[i] = sessions.SkippedID{ID: fmt.Sprintf("bad-%d", i+1)}
	}
	tests := []struct {
		name    string
		skipped []sessions.SkippedID
		want    string
	}{
		{"one", many[:1], "1 session could not be listed (e.g. bad-1); run codemeld sessions doctor <id> to see why"},
		{"five", many[:5], "5 sessions could not be listed (e.g. bad-1, bad-2, bad-3, bad-4, bad-5); run codemeld sessions doctor <id> to see why"},
		{"many", many, "413 sessions could not be listed (e.g. bad-1, bad-2, bad-3, bad-4, bad-5, ... 408 more); run codemeld sessions doctor <id> to see why"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := newWritableHost(t)
			fx := newResumeFixture(t)
			fx.lister.entries = []ResumeEntry{{ID: "0190cccc"}}
			fx.lister.skipped = tt.skipped
			fx.picker.result = PickerResult{Selected: false}

			if res := dispatchResume(t, fx, host); res.Err != nil {
				t.Fatalf("dispatch err: %v", res.Err)
			}
			if !equalStrings(host.notices, []string{tt.want}) {
				t.Errorf("notices = %q, want exactly [%q]", host.notices, tt.want)
			}
			if len(fx.picker.presented) != 1 {
				t.Errorf("picker presented %d times, want 1", len(fx.picker.presented))
			}
			if fx.sw.calls != 0 {
				t.Error("switch ran after an ESC dismissal")
			}
			evs := host.events()
			if len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
				t.Fatalf("slash_command events = %v, want one success", evs)
			}
		})
	}
}

// TestResumeHandler_OlderSchemaOffersFork pins DW6 (step 6): an older-schema
// selection routes to the read-only + fork affordance, bypasses the lock handoff
// and refresh, and leaves the original session active and appendable.
func TestResumeHandler_OlderSchemaOffersFork(t *testing.T) {
	host := newWritableHost(t)
	priorRef := host.store
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	fx.loader.older = true

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if fx.fork.calls != 1 || fx.fork.target != fx.target() {
		t.Errorf("OfferFork calls=%d target=%p, want 1 / loaded target", fx.fork.calls, fx.fork.target)
	}
	if fx.sw.calls != 0 || fx.refresher.calls != 0 || fx.model.calls != 0 || fx.agents.calls != 0 {
		t.Errorf("equal-schema steps ran for an older-schema selection: switch=%d refresh=%d model=%d agents=%d",
			fx.sw.calls, fx.refresher.calls, fx.model.calls, fx.agents.calls)
	}
	if host.Store() != priorRef {
		t.Error("active store changed for an older-schema selection")
	}
	before := len(priorRef.Records())
	priorRef.Append(sessions.Message{ID: "after-fork-offer", Role: "user", Content: sessions.TextContent("x")})
	if len(priorRef.Records()) != before+1 {
		t.Error("original session was sealed on an older-schema selection (it must stay active)")
	}
}

// TestResumeHandler_OlderSchemaPreservesInFlightStream pins step 6:
// an older-schema selection made while a stream is in flight must not cancel that stream
// or append stream_interrupted to the active session before offering the fork. The
// handler classifies the target before touching the stream, so the originally-active
// session stays active in the background with its in-flight stream uninterrupted, and an
// ESC out of the fork affordance returns the user to it. With the pre-fix ordering
// (cancel/flush before the older-schema branch) Stream.Cancel ran and a
// stream_interrupted landed on the active session — this test fails in that case.
func TestResumeHandler_OlderSchemaPreservesInFlightStream(t *testing.T) {
	host := newWritableHost(t)
	priorRef := host.store
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	fx.loader.older = true
	fx.stream.inFlight = true
	fx.stream.retained = 99

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if fx.fork.calls != 1 || fx.fork.target != fx.target() {
		t.Errorf("OfferFork calls=%d target=%p, want 1 / loaded target", fx.fork.calls, fx.fork.target)
	}
	// The in-flight stream was never cancelled: the equal-schema switch sequence is not
	// entered for an older-schema selection, so Stream.Cancel is not used at all.
	if fx.stream.calls != 0 {
		t.Errorf("Stream.Cancel called %d times, want 0 (older-schema selection must not interrupt the active stream)", fx.stream.calls)
	}
	for _, k := range eventKinds(priorRef.Records()) {
		if k == events.KindStreamInterrupted {
			t.Error("stream_interrupted appended on an older-schema selection; the active stream must be left in flight")
		}
	}
	// The original session is still active and appendable in the background.
	if host.Store() != priorRef {
		t.Error("active store changed for an older-schema selection")
	}
	before := len(priorRef.Records())
	priorRef.Append(sessions.Message{ID: "after-older-inflight", Role: "user", Content: sessions.TextContent("x")})
	if len(priorRef.Records()) != before+1 {
		t.Error("original session was sealed on an older-schema selection (it must stay active)")
	}
}

// TestResumeHandler_OlderSchemaFlushesCommandEvent pins that
// an older-schema selection records slash_command{success} at picker-open
// but then hands off to the read-only/fork view without switching. Because the prior
// session stays active in the background, that success record must be made durable as
// a checkpoint before the fork view opens — otherwise a crash there loses the /resume
// audit event. The fakes never flush the prior store themselves, so reading
// host.store.Path() back from disk fails unless runResumeSwitch's older-schema branch
// flushes it. It must do so without entering the equal-schema switch sequence: none of
// Stream.Cancel, Switch, Refresh, Model, or Agents may run.
func TestResumeHandler_OlderSchemaFlushesCommandEvent(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	fx.loader.older = true

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	// The fork view was offered for the loaded target.
	if fx.fork.calls != 1 || fx.fork.target != fx.target() {
		t.Errorf("OfferFork calls=%d target=%p, want 1 / loaded target", fx.fork.calls, fx.fork.target)
	}
	// The picker-open slash_command{success} is durable on disk: the older-schema branch
	// checkpoint-flushed the still-active prior session before opening the fork view.
	data, err := os.ReadFile(host.store.Path())
	if err != nil {
		t.Fatalf("prior session not flushed before the fork view (older-schema checkpoint flush missing?): %v", err)
	}
	if !strings.Contains(string(data), events.KindSlashCommand) {
		t.Errorf("flushed prior session missing durable slash_command record\n--- file ---\n%s", data)
	}
	// The equal-schema switch sequence was not entered: the active stream stays in flight
	// and none of the switch/replay steps run.
	if fx.stream.calls != 0 {
		t.Errorf("Stream.Cancel called %d times, want 0 (older-schema selection must not interrupt the active stream)", fx.stream.calls)
	}
	if fx.sw.calls != 0 || fx.refresher.calls != 0 || fx.model.calls != 0 || fx.agents.calls != 0 {
		t.Errorf("equal-schema steps ran for an older-schema selection: switch=%d refresh=%d model=%d agents=%d",
			fx.sw.calls, fx.refresher.calls, fx.model.calls, fx.agents.calls)
	}
}

// TestResumeHandler_LoadFailureKeepsCurrent pins DW8 (step 8): a chosen-session
// load failure after the picker opened leaves the current session active, treats
// the pre-switch flush as a checkpoint only, and renders a one-line notice naming
// the chosen id and failure category without recording an error event.
func TestResumeHandler_LoadFailureKeepsCurrent(t *testing.T) {
	host := newWritableHost(t)
	priorRef := host.store
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	fx.loader.older = false
	fx.loader.failCat = fserrors.NotFound
	fx.loader.err = errors.New("session file vanished")

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	wantNotice := "session 0190aaaa: cannot load chosen session: not found"
	if len(host.notices) == 0 || host.notices[len(host.notices)-1] != wantNotice {
		t.Errorf("notices = %v, want last to be %q", host.notices, wantNotice)
	}
	if fx.sw.calls != 0 || fx.fork.calls != 0 || fx.refresher.calls != 0 {
		t.Errorf("steps ran after a load failure: switch=%d fork=%d refresh=%d", fx.sw.calls, fx.fork.calls, fx.refresher.calls)
	}
	// Only the picker-open success is recorded; the load failure adds a notice, not
	// an error event.
	evs := host.events()
	if len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Fatalf("slash_command events = %v, want one success (no error event for a load failure)", evs)
	}
	// The pre-switch flush ran as a checkpoint and the current session stays active.
	if _, err := os.ReadFile(priorRef.Path()); err != nil {
		t.Errorf("pre-switch checkpoint flush did not run: %v", err)
	}
	if host.Store() != priorRef {
		t.Error("active store changed after a chosen-session load failure")
	}
	before := len(priorRef.Records())
	priorRef.Append(sessions.Message{ID: "after-load-fail", Role: "user", Content: sessions.TextContent("x")})
	if len(priorRef.Records()) != before+1 {
		t.Error("current session was sealed after a load failure (it must stay active)")
	}
}

// TestResumeHandler_PreSwitchFlushFailureRefuses pins the pre-switch flush contract: for an
// equal-schema selection the target is classified first (a read-only load), but a
// pre-switch flush failure still refuses the switch — routing the write failure to the
// sink, never committing the handoff, and leaving the current session active.
func TestResumeHandler_PreSwitchFlushFailureRefuses(t *testing.T) {
	host := newFlushFailingHost() // store has an empty path, so Flush fails with a write reason
	fx := newResumeFixture(t)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err (write failure handled by the sink)", res)
	}
	if fx.wf.calls != 1 {
		t.Fatalf("WriteFailure.Handle calls = %d, want 1 (pre-switch flush failure routes to the sink)", fx.wf.calls)
	}
	if fx.wf.last.reason == sessions.ReasonNone || fx.wf.last.store != host.store {
		t.Errorf("WriteFailure.Handle last = %+v, want a real write reason on the prior store", fx.wf.last)
	}
	// The equal-schema path classifies the target before the pre-switch flush, but the
	// flush failure refuses the switch: the handoff (deps.Switch) never commits.
	if fx.loader.calls != 1 {
		t.Errorf("loader calls = %d, want 1 (the target is classified before the pre-switch flush)", fx.loader.calls)
	}
	if fx.sw.calls != 0 {
		t.Errorf("switch committed after a refused pre-switch flush: switch=%d", fx.sw.calls)
	}
}

// TestResumeHandler_LaunchWriteFailureSinkErrorAborts pins the issue-#1 contract: a
// launch_began atomic-write failure whose WriteFailureSink also fails (it could not
// append session_write_failed) aborts the post-switch sequence rather than being
// treated as handled and continuing into refresh/model/agent replay. The prior
// session's pre-switch flush still succeeds, so the switch commits; only the loaded
// session's launch flush hits the failing sink. Under the continuation contract the
// switch runs inside the picker callback after the handler has returned, so the
// residual sink error can no longer reach DispatchResult.Err — the handler returns
// Handled/nil and surfaceResumeErr renders the sink error as the last notice.
func TestResumeHandler_LaunchWriteFailureSinkErrorAborts(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	// Loaded session with an empty path: EmitLaunchBegan's post-append flush fails
	// with a real WriteReason, driving the write-failure callback.
	unwritable := sessions.New("", &sessions.Session{})
	fx.loader.target = unwritable
	sinkErr := errors.New("cannot append session_write_failed")
	fx.wf.result = sinkErr
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err (the switch runs in the picker continuation, not dispatch)", res)
	}
	// The residual sink error is surfaced as the last notice (the only channel left
	// once the switch runs after the handler returned).
	if len(host.notices) == 0 || host.notices[len(host.notices)-1] != sinkErr.Error() {
		t.Errorf("notices = %v, want last to be the surfaced sink error %q", host.notices, sinkErr.Error())
	}
	// The launch sink was invoked exactly once, on the loaded session.
	if fx.wf.calls != 1 || fx.wf.last.store != unwritable {
		t.Errorf("WriteFailure.Handle calls=%d store=%p, want 1 on the loaded session %p", fx.wf.calls, fx.wf.last.store, unwritable)
	}
	if fx.wf.last.reason == sessions.ReasonNone {
		t.Errorf("WriteFailure.Handle reason = %q, want a real write reason", fx.wf.last.reason)
	}
	// The switch committed (launch was attempted) but the post-switch sequence stopped
	// at the failed sink: refresh/model/agent replay never ran.
	if fx.sw.calls != 1 {
		t.Errorf("switch calls = %d, want 1 (the switch committed before the launch flush)", fx.sw.calls)
	}
	if fx.refresher.calls != 0 || fx.model.calls != 0 || fx.agents.calls != 0 {
		t.Errorf("post-switch steps ran after the launch sink failed: refresh=%d model=%d agents=%d",
			fx.refresher.calls, fx.model.calls, fx.agents.calls)
	}
}

func TestResumeHandler_LoadFailureFlushRoutesPriorToSink(t *testing.T) {
	host := newFlushFailingHost()
	priorRef := host.store
	fx := newResumeFixture(t)
	sw := withAbortableSwitch(fx)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	fx.loader.failCat = fserrors.NotFound
	fx.loader.err = errors.New("session file vanished")

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err (write failure handled by the sink)", res)
	}

	if fx.wf.calls != 1 || fx.wf.last.store != priorRef {
		t.Fatalf("WriteFailure.Handle calls=%d store=%p, want 1 on the prior store %p", fx.wf.calls, fx.wf.last.store, priorRef)
	}
	if fx.wf.last.reason == sessions.ReasonNone || fx.wf.last.path != priorRef.Path() {
		t.Errorf("WriteFailure.Handle last = %+v, want a real write reason on the prior path %q", fx.wf.last, priorRef.Path())
	}
	if fx.sw.calls != 0 || fx.sw.activateCalls != 0 || fx.fork.calls != 0 || sw.aborts != 0 {
		t.Errorf("switch=%d activate=%d fork=%d abort=%d after a load failure, want all 0",
			fx.sw.calls, fx.sw.activateCalls, fx.fork.calls, sw.aborts)
	}
	if len(eventKinds(fx.target().Records())) != 0 {
		t.Error("the loaded-session store gained events after a load failure")
	}
}

func TestResumeHandler_OlderSchemaFlushFailureRoutesPriorToSink(t *testing.T) {
	host := newFlushFailingHost()
	priorRef := host.store
	fx := newResumeFixture(t)
	sw := withAbortableSwitch(fx)
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	fx.loader.older = true
	fx.stream.inFlight = true

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err (write failure handled by the sink)", res)
	}

	if fx.wf.calls != 1 || fx.wf.last.store != priorRef {
		t.Fatalf("WriteFailure.Handle calls=%d store=%p, want 1 on the prior store %p", fx.wf.calls, fx.wf.last.store, priorRef)
	}
	if fx.wf.last.reason == sessions.ReasonNone {
		t.Errorf("WriteFailure.Handle reason = %q, want a real write reason", fx.wf.last.reason)
	}
	if fx.fork.calls != 0 {
		t.Errorf("OfferFork calls = %d, want 0 (the checkpoint flush failed, so the fork view is not offered)", fx.fork.calls)
	}
	if fx.stream.calls != 0 || fx.sw.calls != 0 || fx.sw.activateCalls != 0 || sw.aborts != 0 {
		t.Errorf("cancel=%d switch=%d activate=%d abort=%d for an older-schema selection, want all 0",
			fx.stream.calls, fx.sw.calls, fx.sw.activateCalls, sw.aborts)
	}
}

func TestResumeHandler_PreSwitchNonWriteFlushFailureBypassesSink(t *testing.T) {
	host := newWritableHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fx := newResumeFixture(t)
	fx.deps.FlushCtx = ctx
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if fx.wf.calls != 0 {
		t.Errorf("WriteFailure.Handle calls = %d, want 0 (a non-write flush failure bypasses the sink)", fx.wf.calls)
	}
	if len(host.notices) == 0 || host.notices[len(host.notices)-1] != context.Canceled.Error() {
		t.Errorf("notices = %v, want last to be the surfaced non-write flush error %q", host.notices, context.Canceled.Error())
	}
	if fx.sw.calls != 0 || fx.sw.activateCalls != 0 {
		t.Errorf("switch=%d activate=%d after a refused pre-switch flush, want 0/0", fx.sw.calls, fx.sw.activateCalls)
	}
}

func TestResumeHandler_FinalFlushWriteFailureRoutesTargetToSink(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	unwritable := sessions.New("", &sessions.Session{})
	fx.loader.target = unwritable
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}
	fx.agents.replays = []events.AgentInstructionsLoaded{
		{Path: "/g/AGENTS.md", Layer: "global", LoadOrder: 1},
	}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if fx.wf.calls != 2 {
		t.Fatalf("WriteFailure.Handle calls = %d, want 2 (launch anchor, then the post-replay final flush)", fx.wf.calls)
	}
	if fx.wf.last.store != unwritable || fx.wf.last.store == host.store {
		t.Errorf("final flush sink store = %p, want the loaded session %p (not the prior store %p)", fx.wf.last.store, unwritable, host.store)
	}
	if fx.wf.last.path != unwritable.Path() || fx.wf.last.reason == sessions.ReasonNone {
		t.Errorf("final flush sink call = %+v, want a real write reason on the loaded session's path", fx.wf.last)
	}
	if fx.sw.activateCalls != 1 || fx.refresher.calls != 1 || fx.model.calls != 1 || fx.agents.calls != 1 {
		t.Errorf("activate=%d refresh=%d model=%d agents=%d before the final flush, want all 1",
			fx.sw.activateCalls, fx.refresher.calls, fx.model.calls, fx.agents.calls)
	}
}

func TestResumeHandler_FinalFlushNonWriteFailureSurfaces(t *testing.T) {
	host := newWritableHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	fx := newResumeFixture(t)
	sw := withAbortableSwitch(fx)
	replayer := &cancellingReplayer{cancel: cancel}
	fx.deps.FlushCtx = ctx
	fx.deps.Agents = replayer
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if replayer.calls != 1 || replayer.target != fx.target() {
		t.Fatalf("agent replay calls=%d target=%p, want 1 on the loaded session %p", replayer.calls, replayer.target, fx.target())
	}
	if fx.wf.calls != 0 {
		t.Errorf("WriteFailure.Handle calls = %d, want 0 (a non-write final-flush failure bypasses the sink)", fx.wf.calls)
	}
	if len(host.notices) == 0 || host.notices[len(host.notices)-1] != context.Canceled.Error() {
		t.Errorf("notices = %v, want last to be the surfaced non-write flush error %q", host.notices, context.Canceled.Error())
	}
	if fx.sw.calls != 1 || fx.sw.activateCalls != 1 {
		t.Errorf("switch=%d activate=%d, want 1/1 (the switch committed before the final flush)", fx.sw.calls, fx.sw.activateCalls)
	}
	if sw.aborts != 0 {
		t.Errorf("Abort calls = %d, want 0: activation already happened, so a later failure must not roll back", sw.aborts)
	}
}

func TestResumeHandler_AbortRollsBackBeforeActivation(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	sw := withAbortableSwitch(fx)
	unwritable := sessions.New("", &sessions.Session{})
	fx.loader.target = unwritable
	fx.wf.result = errors.New("cannot append session_write_failed")
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 0}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if fx.sw.calls != 1 {
		t.Fatalf("switch calls = %d, want 1 (the rollback undoes a committed switch)", fx.sw.calls)
	}
	if sw.aborts != 1 {
		t.Fatalf("Abort calls = %d, want 1 (the post-switch sequence failed before activation)", sw.aborts)
	}
	if fx.sw.activateCalls != 0 {
		t.Errorf("Activate calls = %d, want 0 (the launch anchor failed before the active-store install)", fx.sw.activateCalls)
	}
	if sw.abortAt <= fx.sw.at {
		t.Errorf("switch tick = %d, abort tick = %d: the rollback must follow the switch it undoes", fx.sw.at, sw.abortAt)
	}
	if fx.refresher.calls != 0 || fx.model.calls != 0 || fx.agents.calls != 0 {
		t.Errorf("post-switch steps ran on a rolled-back switch: refresh=%d model=%d agents=%d",
			fx.refresher.calls, fx.model.calls, fx.agents.calls)
	}
}

func TestResumeHandler_ActivationSuppressesRollback(t *testing.T) {
	cases := []struct {
		name  string
		setup func(fx *resumeFixture)
	}{
		{"clean switch", func(fx *resumeFixture) {}},
		{"post-activation refresh failure", func(fx *resumeFixture) {
			fx.refresher.err = errors.New("refresh failed after activation")
		}},
		{"post-activation model failure", func(fx *resumeFixture) {
			fx.model.err = errors.New("model recovery failed after activation")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := newWritableHost(t)
			fx := newResumeFixture(t)
			sw := withAbortableSwitch(fx)
			fx.lister.entries = twoEntries()
			fx.picker.result = PickerResult{Selected: true, Index: 1}
			tc.setup(fx)

			if res := dispatchResume(t, fx, host); res.Err != nil {
				t.Fatalf("dispatch err: %v", res.Err)
			}

			if fx.sw.activateCalls != 1 {
				t.Fatalf("Activate calls = %d, want 1", fx.sw.activateCalls)
			}
			if sw.aborts != 0 {
				t.Errorf("Abort calls = %d, want 0 (rollback runs only when activation did not occur)", sw.aborts)
			}
		})
	}
}

func TestResumeHandler_SwitchWithoutAbortRemainsValid(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	if _, ok := ResumeSwitch(fx.sw).(resumeAborter); ok {
		t.Fatal("setup: fakeSwitch must not implement resumeAborter, so this test drives the no-rollback path")
	}
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 1}

	res := dispatchResume(t, fx, host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err", res)
	}
	if fx.sw.calls != 1 || fx.sw.activateCalls != 1 {
		t.Errorf("switch=%d activate=%d, want 1/1 for a switch without rollback support", fx.sw.calls, fx.sw.activateCalls)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none: a switch without the abort capability is valid", host.notices)
	}
}

func TestResumeHandler_ActivateErrorAbortsBeforeReplay(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	sw := withAbortableSwitch(fx)
	fx.sw.activateErr = errors.New("capability flush failed")
	fx.lister.entries = twoEntries()
	fx.picker.result = PickerResult{Selected: true, Index: 1}

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}
	if sw.aborts != 1 {
		t.Errorf("Abort calls = %d, want 1 after an Activate error", sw.aborts)
	}
	if fx.transcript.resets != 0 || fx.transcript.replays != 0 || fx.refresher.calls != 0 {
		t.Errorf("resets=%d replays=%d refresh=%d, want none after an Activate error",
			fx.transcript.resets, fx.transcript.replays, fx.refresher.calls)
	}
	if len(host.notices) == 0 || host.notices[len(host.notices)-1] != "capability flush failed" {
		t.Errorf("notices = %v, want the Activate error last", host.notices)
	}
}

func TestResumeHandler_ActivateWarningIsTheLastNotice(t *testing.T) {
	for _, warning := range []string{"can't remove private temp folder /x: busy; codemeld retries when it exits", ""} {
		host := newWritableHost(t)
		fx := newResumeFixture(t)
		fx.sw.warning = warning
		fx.lister.entries = twoEntries()
		fx.picker.result = PickerResult{Selected: true, Index: 1}

		if res := dispatchResume(t, fx, host); res.Err != nil {
			t.Fatalf("dispatch err: %v", res.Err)
		}
		if fx.transcript.resets != 1 || fx.transcript.replays != 1 {
			t.Fatalf("resets=%d replays=%d, want 1/1", fx.transcript.resets, fx.transcript.replays)
		}
		if warning == "" {
			if len(host.notices) != 0 {
				t.Errorf("notices = %v, want none for an empty warning", host.notices)
			}
			continue
		}
		if len(host.notices) == 0 || host.notices[len(host.notices)-1] != warning {
			t.Errorf("notices = %v, want %q last", host.notices, warning)
		}
	}
}

// folderScopedLister models the production lister, which is constructed bound
// to one canonical folder and returns only that folder's sessions —
// SessionLister.List takes no folder argument precisely because the binding is
// fixed at construction (production wiring binds the run's folder). It records the folder it was
// scoped to and filters a cross-folder candidate pool by it, so a test can prove
// the handler presents only the current-folder rows the bound lister yields and
// surfaces nothing from another folder.
type folderScopedLister struct {
	currentFolder string
	pool          []folderCandidate
	bound         string
}

type folderCandidate struct {
	folder string
	entry  ResumeEntry
}

func (l *folderScopedLister) List() ([]ResumeEntry, []sessions.SkippedID, error) {
	l.bound = l.currentFolder
	var out []ResumeEntry
	for _, c := range l.pool {
		if c.folder == l.currentFolder {
			out = append(out, c.entry)
		}
	}
	return out, nil, nil
}

// TestResumeHandler_PresentsCurrentFolderRowsOnly pins DW1's current-folder scope:
// driven by a folder-bound lister holding both in-folder and out-of-folder
// candidates, the handler presents to the picker exactly the current-folder rows
// and nothing from another folder. Folder filtering itself is owned by the
// production lister (bound by production wiring and exercised end-to-end by the /resume
// picker integration test); this asserts the handler faithfully surfaces only the bound
// lister's current-folder rows, neither dropping in-folder rows nor injecting others.
func TestResumeHandler_PresentsCurrentFolderRowsOnly(t *testing.T) {
	host := newWritableHost(t)
	fx := newResumeFixture(t)
	const here = "/home/u/.codemeld/sessions/folderHERE"
	const other = "/home/u/.codemeld/sessions/folderOTHER"
	lister := &folderScopedLister{
		currentFolder: here,
		pool: []folderCandidate{
			{folder: here, entry: ResumeEntry{ID: "0190here1", Preview: "in-folder one"}},
			{folder: other, entry: ResumeEntry{ID: "0190other", Preview: "OTHER folder"}},
			{folder: here, entry: ResumeEntry{ID: "0190here2", Preview: "in-folder two"}},
		},
	}
	fx.deps.Lister = lister
	fx.picker.result = PickerResult{Selected: false} // ESC: presentation-only, no switch

	if res := dispatchResume(t, fx, host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if lister.bound != here {
		t.Fatalf("lister scoped to %q, want current folder %q", lister.bound, here)
	}
	if len(fx.picker.presented) != 1 {
		t.Fatalf("picker presented %d times, want 1", len(fx.picker.presented))
	}
	got := fx.picker.presented[0]
	want := []ResumeEntry{
		{ID: "0190here1", Preview: "in-folder one"},
		{ID: "0190here2", Preview: "in-folder two"},
	}
	if len(got) != len(want) {
		t.Fatalf("picker rows = %v, want the %d current-folder rows %v", got, len(want), want)
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Preview != want[i].Preview {
			t.Errorf("picker row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for _, row := range got {
		if row.ID == "0190other" {
			t.Error("picker presented an out-of-folder row; rows must be scoped to the current folder")
		}
	}
}

// TestBuildRegistry_ResumeDispatchesToHandler pins DW1: the production registry
// binds /resume to the supplied handler, so dispatching "/resume" reaches the real
// handler (the capability the /resume picker integration test drives end-to-end) rather
// than the static recordHandler placeholder. Mirrors the clear/status/exit
// production-dispatch tests; the resume handler is a sentinel here so the binding is what's asserted.
func TestBuildRegistry_ResumeDispatchesToHandler(t *testing.T) {
	host := newWritableHost(t)
	ran := false
	resume := func(ctx CommandContext, _ []string) error {
		ran = true
		return nil
	}
	reg := BuildRegistry(map[string]HandlerFunc{"resume": resume})

	res := reg.DispatchSlashInput("/resume", host)
	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /resume = %+v, want Handled/nil-err", res)
	}
	if !ran {
		t.Error("/resume did not dispatch to the supplied production handler (still the recordHandler placeholder?)")
	}
}

// decodeEventPayload unmarshals an event record's payload into v, failing the test
// if the record is not an event or the payload does not decode.
func decodeEventPayload(t *testing.T, rec sessions.Record, v any) {
	t.Helper()
	ev, ok := rec.(sessions.Event)
	if !ok {
		t.Fatalf("record %T is not a sessions.Event", rec)
	}
	if err := json.Unmarshal(ev.Payload, v); err != nil {
		t.Fatalf("decode %s payload: %v", ev.Kind, err)
	}
}
