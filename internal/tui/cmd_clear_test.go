// Tests for the /clear (alias /new) handler: the (a)–(g) session-switch
// sequence is driven through fakes for all five capability interfaces so no
// terminal driver, real filesystem, or production app wiring is required.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

// newWritableHost is a fakeHost backed by a session store whose path lives in
// t.TempDir, so the handler's pre-switch Flush actually succeeds. Tests that
// only exercise dispatch/alias routing can use the empty-path newFakeHost,
// but anything reaching step (c) needs a writable path.
func newWritableHost(t *testing.T) *fakeHost {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.json")
	return &fakeHost{store: sessions.New(path, &sessions.Session{})}
}

// callOrder is a shared monotonic counter the fakes tick on each invocation,
// so a test can assert one call ran after another without depending on wall
// clocks or per-fake timestamps.
type callOrder struct{ n int }

func (c *callOrder) tick() int { c.n++; return c.n }

type fakeStream struct {
	calls    int
	retained int
	inFlight bool
}

func (s *fakeStream) Cancel() (int, bool) {
	s.calls++
	return s.retained, s.inFlight
}

type drainingStream struct {
	fakeStream
	order   *callOrder
	waits   int
	waitAt  int
	entered chan struct{}
	release chan struct{}
}

func (s *drainingStream) WaitTurnDrained() {
	s.waits++
	if s.order != nil {
		s.waitAt = s.order.tick()
	}
	if s.entered != nil {
		close(s.entered)
	}
	if s.release != nil {
		<-s.release
	}
}

type fakeStreamTranscript struct{ marks int }

func (m *fakeStreamTranscript) MarkStreamInterruptedFromCommand() { m.marks++ }

type fakeSwapper struct {
	order       *callOrder
	closed      int
	closedWith  *sessions.Store
	closeErr    error
	freshErr    error
	fresh       *sessions.Store
	freshCalls  int
	freshOrder  int
	sealOnClose bool
}

func (s *fakeSwapper) Close(prior *sessions.Store) error {
	s.closed++
	s.closedWith = prior
	// Model the production swapper, which seals the prior store against further
	// appends, so a test can prove the prior session stays usable when Close is
	// never reached.
	if s.sealOnClose && prior != nil {
		prior.Close()
	}
	return s.closeErr
}

func (s *fakeSwapper) Fresh() (*sessions.Store, error) {
	s.freshCalls++
	if s.order != nil {
		s.freshOrder = s.order.tick()
	}
	if s.freshErr != nil {
		return nil, s.freshErr
	}
	if s.fresh == nil {
		s.fresh = sessions.New("", &sessions.Session{})
	}
	// The production Fresh impl appends launch_began{source:"fresh"} as part
	// of the same call; the fake mirrors that so the new-session event order
	// the spec requires (launch_began first) is observable through the fakes.
	if _, err := events.Append(s.fresh, events.LaunchBegan{Source: "fresh"}); err != nil {
		return nil, err
	}
	return s.fresh, nil
}

type fakeModel struct {
	order   *callOrder
	carried int
	at      int
}

func (m *fakeModel) CarryForward() {
	m.carried++
	if m.order != nil {
		m.at = m.order.tick()
	}
}

// fakeMode records the /clear mode carry-forward without appending a record, so the
// handler's call ordering is observable while the fresh session's event list (asserted
// elsewhere) is unaffected. The production ModeCarrier (clearModeState) appends and
// flushes the interaction_mode event; that durable emission is covered in
// cleardeps_test.go, mirroring how the fake Model carry-forward is a pure no-op here.
type fakeMode struct {
	order  *callOrder
	calls  int
	target *sessions.Store
	at     int
	err    error
}

func (m *fakeMode) CarryForward(fresh *sessions.Store) error {
	m.calls++
	m.target = fresh
	if m.order != nil {
		m.at = m.order.tick()
	}
	return m.err
}

type fakeReplayer struct {
	order   *callOrder
	calls   int
	target  *sessions.Store
	at      int
	replays []events.AgentInstructionsLoaded
	err     error
}

func (r *fakeReplayer) Replay(target *sessions.Store) error {
	r.calls++
	r.target = target
	if r.order != nil {
		r.at = r.order.tick()
	}
	if r.err != nil {
		return r.err
	}
	for _, p := range r.replays {
		if _, err := events.Append(target, p); err != nil {
			return err
		}
	}
	return nil
}

type fakeWriteFailure struct {
	calls  int
	last   writeFailureCall
	result error
}

type writeFailureCall struct {
	reason sessions.WriteReason
	cat    fserrors.Category
	path   string
	detail error
	store  *sessions.Store
}

func (f *fakeWriteFailure) Handle(reason sessions.WriteReason, cat fserrors.Category, path string, detail error, store *sessions.Store) error {
	f.calls++
	f.last = writeFailureCall{reason: reason, cat: cat, path: path, detail: detail, store: store}
	return f.result
}

// clearFixture bundles the fakes a test typically inspects so they can be
// reached without re-extracting them from ClearDeps.
type clearFixture struct {
	deps     ClearDeps
	stream   *fakeStream
	marker   *fakeStreamTranscript
	swapper  *fakeSwapper
	model    *fakeModel
	mode     *fakeMode
	replayer *fakeReplayer
	wf       *fakeWriteFailure
	order    *callOrder
}

func newClearFixture(t *testing.T) *clearFixture {
	t.Helper()
	order := &callOrder{}
	// The fresh store carries a writable temp path so the handler's post-replay
	// flush succeeds; tests that want the fresh flush to fail swap in
	// their own unwritable store.
	fresh := sessions.New(filepath.Join(t.TempDir(), "fresh.json"), &sessions.Session{})
	f := &clearFixture{
		stream:   &fakeStream{},
		marker:   &fakeStreamTranscript{},
		swapper:  &fakeSwapper{order: order, fresh: fresh},
		model:    &fakeModel{order: order},
		mode:     &fakeMode{order: order},
		replayer: &fakeReplayer{order: order},
		wf:       &fakeWriteFailure{},
		order:    order,
	}
	f.deps = ClearDeps{
		Stream:           f.stream,
		StreamTranscript: f.marker,
		Session:          f.swapper,
		Model:            f.model,
		Mode:             f.mode,
		Agents:           f.replayer,
		WriteFailure:     f.wf,
	}
	return f
}

// newClearRegistry builds a Registry whose "clear" entry (with alias "new")
// is bound to NewClearHandler(deps), so dispatching "/new" exercises
// canonical-name routing end-to-end through the registry.
func newClearRegistry(t *testing.T, deps ClearDeps) *Registry {
	t.Helper()
	r, err := NewRegistry([]Command{
		{
			Name:        "clear",
			Aliases:     []string{"new"},
			Description: "End the current session and start a fresh one",
			ArgSig:      ArgNone,
			Phase:       PhaseOne,
			Handler:     NewClearHandler(deps),
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestClearHandler_AliasRoutesToCanonicalName(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/new", host)
	if res.Status != StatusHandled || res.Canonical != "clear" || res.Err != nil {
		t.Fatalf("dispatch /new = %+v, want Handled/clear/nil-err", res)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "clear" {
		t.Errorf("event name = %q, want canonical %q (not the alias)", p.Name, "clear")
	}
	if p.Outcome != "success" {
		t.Errorf("event outcome = %q, want success", p.Outcome)
	}
	if len(p.Args) != 0 {
		t.Errorf("event args = %v, want empty", p.Args)
	}
}

func TestClearHandler_InFlightStreamEmitsInterrupted(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	fx.stream.inFlight = true
	fx.stream.retained = 142
	reg := newClearRegistry(t, fx.deps)

	if res := reg.DispatchSlashInput("/clear", host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	priorRecs := host.store.Records()
	kinds := eventKinds(priorRecs)
	want := []string{events.KindStreamInterrupted, events.KindSlashCommand}
	if len(kinds) < 2 || kinds[0] != want[0] || kinds[1] != want[1] {
		t.Fatalf("prior session event order = %v, want prefix %v", kinds, want)
	}
	var p events.StreamInterrupted
	if err := json.Unmarshal(priorRecs[0].(sessions.Event).Payload, &p); err != nil {
		t.Fatalf("decode stream_interrupted: %v", err)
	}
	if p.Source != "slash_clear" {
		t.Errorf("stream_interrupted.source = %q, want slash_clear", p.Source)
	}
	if p.ContentChars != 142 {
		t.Errorf("stream_interrupted.content_chars = %d, want 142", p.ContentChars)
	}
	if fx.marker.marks != 1 {
		t.Fatalf("transcript interruption marks = %d, want 1", fx.marker.marks)
	}
	// The cancelled request must not surface as provider_request_failed on the
	// prior session, and no provider/stream event for it should leak into the
	// new session either.
	for _, k := range kinds {
		if k == events.KindProviderRequestFailed {
			t.Errorf("prior session unexpectedly carries provider_request_failed")
		}
	}
	for _, k := range eventKinds(fx.swapper.fresh.Records()) {
		if k == events.KindProviderRequestFailed || k == events.KindStreamInterrupted {
			t.Errorf("new session unexpectedly carries event %q for the cancelled request", k)
		}
	}
}

func TestClearHandler_WaitsForCancelledTurnBeforeFlushAndSeal(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	stream := &drainingStream{order: fx.order, entered: make(chan struct{}), release: make(chan struct{})}
	stream.inFlight = true
	stream.retained = 42
	fx.deps.Stream = stream
	fx.swapper.sealOnClose = true
	reg := newClearRegistry(t, fx.deps)

	done := make(chan DispatchResult, 1)
	go func() { done <- reg.DispatchSlashInput("/clear", host) }()

	select {
	case <-stream.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("/clear never entered the turn drain after cancelling")
	}
	if _, err := os.Stat(host.store.Path()); !os.IsNotExist(err) {
		t.Fatalf("prior session file stat err = %v, want not-exist: the pre-switch flush ran while the cancelled turn was still draining", err)
	}
	if fx.swapper.freshCalls != 0 || fx.swapper.closed != 0 {
		t.Fatalf("Fresh calls = %d, Close calls = %d during the drain, want 0/0", fx.swapper.freshCalls, fx.swapper.closed)
	}

	close(stream.release)
	res := <-done
	if res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	if stream.waits != 1 {
		t.Fatalf("WaitTurnDrained calls = %d, want 1", stream.waits)
	}
	if stream.waitAt == 0 || stream.waitAt >= fx.swapper.freshOrder {
		t.Fatalf("drain tick = %d, Fresh tick = %d: the wait must precede the swap", stream.waitAt, fx.swapper.freshOrder)
	}
	if _, err := os.Stat(host.store.Path()); err != nil {
		t.Fatalf("prior session not durable after the drain released: %v", err)
	}
	if fx.swapper.closed != 1 {
		t.Fatalf("Close calls = %d after the drain, want 1", fx.swapper.closed)
	}
	kinds := eventKinds(host.store.Records())
	if len(kinds) < 2 || kinds[0] != events.KindStreamInterrupted || kinds[1] != events.KindSlashCommand {
		t.Fatalf("prior session event order = %v, want stream_interrupted then slash_command", kinds)
	}
	if fx.marker.marks != 1 {
		t.Fatalf("transcript interruption marks = %d, want 1", fx.marker.marks)
	}
}

func TestClearHandler_NoStreamSkipsInterrupted(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	fx.stream.inFlight = false
	reg := newClearRegistry(t, fx.deps)

	if res := reg.DispatchSlashInput("/clear", host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}
	if fx.stream.calls != 1 {
		t.Errorf("Cancel called %d times, want 1", fx.stream.calls)
	}
	for _, k := range eventKinds(host.store.Records()) {
		if k == events.KindStreamInterrupted {
			t.Errorf("stream_interrupted appended even though no stream was in flight")
		}
	}
	if fx.marker.marks != 0 {
		t.Fatalf("transcript interruption marks = %d, want 0 with no in-flight stream", fx.marker.marks)
	}
}

// flushFailingHost backs CommandContext.Store with a store whose Flush always
// fails (the empty-string path makes the atomic write fail at the temp-file
// stage), so the pre-switch flush branch is exercised without touching a real
// filesystem.
type flushFailingHost struct {
	store    *sessions.Store
	notices  []string
	panels   []string
	statuses []string
}

func newFlushFailingHost() *flushFailingHost {
	return &flushFailingHost{store: sessions.New("", &sessions.Session{})}
}

func (h *flushFailingHost) Notice(text string)     { h.notices = append(h.notices, text) }
func (h *flushFailingHost) ShowPanel(text string)  { h.panels = append(h.panels, text) }
func (h *flushFailingHost) ShowStatus(text string) { h.statuses = append(h.statuses, text) }
func (h *flushFailingHost) Store() *sessions.Store { return h.store }
func (h *flushFailingHost) FlushActive() error     { return nil }

func TestClearHandler_FlushFailureRefusesSwitch(t *testing.T) {
	host := newFlushFailingHost()
	priorRef := host.store
	fx := newClearFixture(t)
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if res.Status != StatusHandled {
		t.Fatalf("status = %v, want Handled", res.Status)
	}

	if fx.wf.calls != 1 {
		t.Fatalf("WriteFailure.Handle called %d times, want 1", fx.wf.calls)
	}
	if fx.wf.last.store != priorRef {
		t.Error("WriteFailure.Handle received a different store than the prior one")
	}
	if fx.wf.last.reason == sessions.ReasonNone {
		t.Errorf("WriteFailure.Handle reason = %q, want a real failure reason", fx.wf.last.reason)
	}
	if fx.swapper.closed != 0 {
		t.Errorf("Session.Close called %d times, want 0", fx.swapper.closed)
	}
	if fx.swapper.freshCalls != 0 {
		t.Errorf("Session.Fresh called %d times, want 0", fx.swapper.freshCalls)
	}
	if fx.replayer.calls != 0 {
		t.Errorf("Agents.Replay called %d times, want 0", fx.replayer.calls)
	}
	if fx.model.carried != 0 {
		t.Errorf("Model.CarryForward called %d times, want 0", fx.model.carried)
	}
	// Prior store remains the active one: the handler never reaches into the
	// host to swap it.
	if host.Store() != priorRef {
		t.Error("prior store reference changed after refused switch")
	}
}

// TestClearHandler_CancelledFlushContextRefusesSwitch pins the cancelled-context refusal at
// the handler level: a non-write pre-switch flush error — an empty fserrors
// category with a non-nil error, which a cancelled run context produces — refuses
// the swap. The error surfaces directly without routing through WriteFailureSink
// (which is reserved for atomic-write failures), and no later step (Close, Fresh,
// Replay, CarryForward) runs, so the prior store stays the active one. The host is
// writable, so cancellation is the only reason the flush fails.
func TestClearHandler_CancelledFlushContextRefusesSwitch(t *testing.T) {
	host := newWritableHost(t)
	priorRef := host.store
	fx := newClearFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fx.deps.FlushCtx = ctx
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if res.Status != StatusHandled {
		t.Fatalf("status = %v, want Handled", res.Status)
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("res.Err = %v, want context.Canceled surfaced directly", res.Err)
	}
	if fx.wf.calls != 0 {
		t.Errorf("WriteFailure.Handle called %d times, want 0 (a non-write error must not route through the write-failure sink)", fx.wf.calls)
	}
	if fx.swapper.closed != 0 || fx.swapper.freshCalls != 0 || fx.replayer.calls != 0 || fx.model.carried != 0 || fx.mode.calls != 0 {
		t.Errorf("post-flush steps ran on a refused switch: close=%d fresh=%d replay=%d carry=%d mode=%d",
			fx.swapper.closed, fx.swapper.freshCalls, fx.replayer.calls, fx.model.carried, fx.mode.calls)
	}
	if host.Store() != priorRef {
		t.Error("prior store reference changed after a refused switch")
	}
}

// TestClearHandler_NonWriteFlushFailureDoesNotRouteToSink pins the non-write flush failure path:
// a pre-switch flush failure that cannot be encoded as session_write_failed
// (reason == sessions.ReasonNone) must surface directly, not route through the
// WriteFailureSink — even when it carries a non-empty fserrors category. A marshal
// failure is exactly that case (category IOError, reason ReasonNone): the store is
// writable, so the only reason its flush fails is the un-marshalable record seeded
// into the prior session. It fails against the prior `cat != ""` gate, which routed
// the marshal failure to the sink (where HandleWriteFailure rejects ReasonNone with
// a wrapped error) and never surfaced the real failure or refused cleanly.
func TestClearHandler_NonWriteFlushFailureDoesNotRouteToSink(t *testing.T) {
	host := newWritableHost(t)
	priorRef := host.store
	// An event whose payload is invalid JSON makes the prior session fail to marshal
	// at the step-(c) flush: Store.Flush returns (fserrors.IOError, ReasonNone, err).
	host.store.Append(sessions.Event{Kind: "bad", Payload: json.RawMessage("{")})
	fx := newClearFixture(t)
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if res.Status != StatusHandled {
		t.Fatalf("status = %v, want Handled", res.Status)
	}
	if res.Err == nil {
		t.Fatal("res.Err = nil, want the non-write flush failure surfaced directly (input retained)")
	}
	if fx.wf.calls != 0 {
		t.Errorf("WriteFailure.Handle called %d times, want 0 (a ReasonNone failure must not route through the sink even with a non-empty category)", fx.wf.calls)
	}
	if fx.swapper.closed != 0 || fx.swapper.freshCalls != 0 || fx.replayer.calls != 0 || fx.model.carried != 0 || fx.mode.calls != 0 {
		t.Errorf("post-flush steps ran on a refused switch: close=%d fresh=%d replay=%d carry=%d mode=%d",
			fx.swapper.closed, fx.swapper.freshCalls, fx.replayer.calls, fx.model.carried, fx.mode.calls)
	}
	if host.Store() != priorRef {
		t.Error("prior store reference changed after a refused switch")
	}
}

func TestClearHandler_FlushFailureSurfacesWriteFailureError(t *testing.T) {
	host := newFlushFailingHost()
	fx := newClearFixture(t)
	fx.wf.result = errors.New("could not record session_write_failed")
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if res.Err == nil || res.Err.Error() != "could not record session_write_failed" {
		t.Fatalf("res.Err = %v, want WriteFailure.Handle's error", res.Err)
	}
}

func TestClearHandler_SuccessOrdering(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	fx.replayer.replays = []events.AgentInstructionsLoaded{
		{Path: "/agents/global/AGENTS.md", Layer: "global", LoadOrder: 1},
		{Path: "/work/AGENTS.md", Layer: "walked", LoadOrder: 2},
	}
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	// New session: launch_began{fresh} from Fresh, then the two replayed
	// agent_instructions_loaded events, in that order.
	newRecs := fx.swapper.fresh.Records()
	gotKinds := eventKinds(newRecs)
	wantKinds := []string{
		events.KindLaunchBegan,
		events.KindAgentInstructionsLoaded,
		events.KindAgentInstructionsLoaded,
	}
	if !equalStrings(gotKinds, wantKinds) {
		t.Fatalf("new session event order = %v, want %v", gotKinds, wantKinds)
	}
	// The first new-session event must specifically be launch_began{source:"fresh"};
	// kind alone would still pass if Fresh recorded resume/fork by mistake.
	firstEv, ok := newRecs[0].(sessions.Event)
	if !ok {
		t.Fatalf("new session record 0 type = %T, want sessions.Event", newRecs[0])
	}
	var lb events.LaunchBegan
	if err := json.Unmarshal(firstEv.Payload, &lb); err != nil {
		t.Fatalf("unmarshal launch_began payload: %v", err)
	}
	if lb.Source != "fresh" {
		t.Fatalf("launch_began source = %q, want %q", lb.Source, "fresh")
	}

	if fx.swapper.closed != 1 || fx.swapper.closedWith != host.store {
		t.Errorf("Session.Close calls=%d with=%p, want 1 call with prior store %p", fx.swapper.closed, fx.swapper.closedWith, host.store)
	}
	if fx.replayer.calls != 1 || fx.replayer.target != fx.swapper.fresh {
		t.Errorf("Agents.Replay calls=%d target=%p, want 1 call targeting new store %p", fx.replayer.calls, fx.replayer.target, fx.swapper.fresh)
	}
	if fx.model.carried != 1 {
		t.Errorf("Model.CarryForward called %d times, want 1", fx.model.carried)
	}
	// CarryForward must run after Replay so the new session's first model_turn
	// can read the carried-forward selection without racing the replay.
	if fx.replayer.at == 0 || fx.model.at == 0 || fx.model.at <= fx.replayer.at {
		t.Errorf("call order: Replay=%d, CarryForward=%d, want CarryForward strictly after Replay", fx.replayer.at, fx.model.at)
	}
	// And Fresh must run before Replay so Replay's target is the new store.
	if fx.swapper.freshOrder == 0 || fx.swapper.freshOrder >= fx.replayer.at {
		t.Errorf("call order: Fresh=%d, Replay=%d, want Fresh strictly before Replay", fx.swapper.freshOrder, fx.replayer.at)
	}
}

// TestClearHandler_CarriesModeForwardAfterSwap pins: the handler carries
// the active interaction mode into the fresh session after the swap, after the agent
// replay, and after the model carry-forward, targeting the fresh store so the
// interaction_mode{trigger:"clear"} record lands in the new session.
func TestClearHandler_CarriesModeForwardAfterSwap(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	reg := newClearRegistry(t, fx.deps)

	if res := reg.DispatchSlashInput("/clear", host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}
	if fx.mode.calls != 1 {
		t.Fatalf("Mode.CarryForward called %d times, want 1", fx.mode.calls)
	}
	if fx.mode.target != fx.swapper.fresh {
		t.Errorf("Mode.CarryForward target = %p, want the fresh store %p", fx.mode.target, fx.swapper.fresh)
	}
	// Mode carry-forward runs strictly after both the agent replay and the model
	// carry-forward, so it records into the fully-swapped, replayed fresh session.
	if fx.replayer.at == 0 || fx.model.at == 0 || fx.mode.at == 0 {
		t.Fatalf("missing call timestamp: replay=%d model=%d mode=%d", fx.replayer.at, fx.model.at, fx.mode.at)
	}
	if fx.mode.at <= fx.model.at || fx.mode.at <= fx.replayer.at {
		t.Errorf("call order: replay=%d model=%d mode=%d, want mode strictly after replay and model", fx.replayer.at, fx.model.at, fx.mode.at)
	}
}

// TestClearHandler_ModeCarryForwardErrorSurfaces pins that a non-write error from the
// post-swap mode emission (the kind the production impl returns for a cancelled or
// marshal failure) surfaces from the handler so the input is retained rather than
// silently dropped.
func TestClearHandler_ModeCarryForwardErrorSurfaces(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	fx.mode.err = errors.New("mode emit boom")
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if !errors.Is(res.Err, fx.mode.err) {
		t.Fatalf("res.Err = %v, want the mode carry-forward error surfaced", res.Err)
	}
}

// TestClearHandler_ReplayedAgentEventsAreFlushed pins: after /clear
// replays the AGENTS.md record into the fresh session, those events must be
// durable on disk, not only in memory — a crash right after /clear would
// otherwise leave the new session with only its launch_began anchor. The fake
// Fresh never flushes, so the on-disk file is written solely by the handler's
// post-replay flush; reading it back fails if that flush is removed.
func TestClearHandler_ReplayedAgentEventsAreFlushed(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	fx.replayer.replays = []events.AgentInstructionsLoaded{
		{Path: "/g/AGENTS.md", Layer: "global", LoadOrder: 1},
	}
	reg := newClearRegistry(t, fx.deps)

	if res := reg.DispatchSlashInput("/clear", host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}

	data, err := os.ReadFile(fx.swapper.fresh.Path())
	if err != nil {
		t.Fatalf("fresh session file not on disk (post-replay flush missing?): %v", err)
	}
	for _, want := range []string{events.KindLaunchBegan, events.KindAgentInstructionsLoaded} {
		if !strings.Contains(string(data), want) {
			t.Errorf("fresh session file missing durable %q event\n--- file ---\n%s", want, data)
		}
	}
}

// TestClearHandler_FreshFlushFailureRecordsAndContinues pins for the
// post-replay flush: once the switch has happened, a fresh-store flush failure is
// a per-turn write failure, so the handler routes it through the same
// WriteFailureSink and carries forward (CarryForward runs, dispatch reports
// success) instead of aborting the completed swap.
func TestClearHandler_FreshFlushFailureRecordsAndContinues(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	// A fresh store whose path sits under a regular file fails every flush with a
	// real write reason.
	base := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(base, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	fx.swapper.fresh = sessions.New(filepath.Join(base, "fresh.json"), &sessions.Session{})
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil (handled per-turn failure continues)", res.Err)
	}
	if fx.wf.calls != 1 {
		t.Fatalf("WriteFailure.Handle calls = %d, want 1 (fresh flush failure routes through the sink)", fx.wf.calls)
	}
	if fx.wf.last.store != fx.swapper.fresh {
		t.Error("WriteFailure.Handle received a store other than the fresh one")
	}
	if fx.wf.last.reason == sessions.ReasonNone {
		t.Errorf("WriteFailure.Handle reason = %q, want a real write reason", fx.wf.last.reason)
	}
	if fx.model.carried != 1 {
		t.Errorf("CarryForward called %d times, want 1 (switch completes after a handled fresh flush failure)", fx.model.carried)
	}
}

// TestClearHandler_FreshFailureLeavesPriorStoreUsable pins the fresh-before-seal order: when
// fresh-session creation fails, the swap must not have sealed the prior session. The
// fake Fresh returns an error, and the fake Close seals its argument like the
// production swapper; because the fix creates the fresh session before sealing the
// prior one, a failed Fresh means Close never runs, so the prior store is still the
// active session and still accepts appends. With the prior close-before-fresh
// ordering, Close ran first (closed==1) and sealed the prior store, so the post-
// dispatch append was silently dropped — this test fails in that case.
func TestClearHandler_FreshFailureLeavesPriorStoreUsable(t *testing.T) {
	host := newWritableHost(t)
	priorRef := host.store
	fx := newClearFixture(t)
	fx.swapper.freshErr = errors.New("ensure session failed")
	fx.swapper.sealOnClose = true
	reg := newClearRegistry(t, fx.deps)

	res := reg.DispatchSlashInput("/clear", host)
	if res.Status != StatusHandled {
		t.Fatalf("status = %v, want Handled", res.Status)
	}
	if !errors.Is(res.Err, fx.swapper.freshErr) {
		t.Fatalf("res.Err = %v, want the Fresh error surfaced (input retained)", res.Err)
	}
	if fx.swapper.freshCalls != 1 {
		t.Fatalf("Session.Fresh called %d times, want 1", fx.swapper.freshCalls)
	}
	if fx.swapper.closed != 0 {
		t.Fatalf("Session.Close called %d times, want 0 — the prior store must not be sealed when Fresh fails", fx.swapper.closed)
	}
	if fx.replayer.calls != 0 || fx.model.carried != 0 || fx.mode.calls != 0 {
		t.Errorf("post-fresh steps ran after a failed swap: replay=%d carry=%d mode=%d", fx.replayer.calls, fx.model.carried, fx.mode.calls)
	}
	// The active session must still accept appends: a sealed store silently drops
	// every Append, so assert the record count grows after a failed /new.
	before := len(priorRef.Records())
	priorRef.Append(sessions.Message{ID: "after-failed-clear", Role: "user", Content: sessions.TextContent("still works")})
	if len(priorRef.Records()) != before+1 {
		t.Fatal("prior store dropped an append after a failed fresh-session swap — the active session was disabled")
	}
}

// eventKinds extracts the kind strings of every Event record in recs (in
// order), so per-session event orderings can be compared against a literal.
func eventKinds(recs []sessions.Record) []string {
	var out []string
	for _, r := range recs {
		if ev, ok := r.(sessions.Event); ok {
			out = append(out, ev.Kind)
		}
	}
	return out
}
