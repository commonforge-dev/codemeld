// Tests for the App streaming surface: transcript delta accumulation,
// finalize/interrupted closing of the in-progress message, the StreamCanceller
// install/accessor seam (default-inert with a fake canceller), App delegation to
// the transcript, background notices, and off-event-loop safety through the tview
// queue.
package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// fakeCanceller is a test StreamCanceller that records its Cancel calls and
// returns fixed retained-char/in-flight values.
type fakeCanceller struct {
	retained int
	inFlight bool
	calls    int
}

func (f *fakeCanceller) Cancel() (int, bool) {
	f.calls++
	return f.retained, f.inFlight
}

func TestTranscript_AppendDeltaAccumulates(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("a")
	tr.appendDelta("b")
	tr.appendDelta("c")

	if !tr.streaming {
		t.Fatal("appendDelta did not open the in-progress buffer")
	}
	if tr.streamBuf != "abc" {
		t.Fatalf("streamBuf = %q, want %q", tr.streamBuf, "abc")
	}
	if got := tr.view.GetText(false); got != "abc" {
		t.Fatalf("rendered in-progress line = %q, want %q", got, "abc")
	}
}

func TestTranscript_StreamingLineRendersAboveNotice(t *testing.T) {
	tr := newTranscript()
	tr.append("committed line")
	tr.appendDelta("streaming...")
	tr.setNotice("a notice")

	// Committed transcript, then the live in-progress line, then the notice last,
	// each separated from the block above by one blank line.
	want := "committed line\n\nstreaming...\n\na notice"
	if got := tr.view.GetText(false); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

func TestTranscript_FinalizeCommitsWithoutMarker(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("done reply")
	tr.finalize()

	if tr.streaming {
		t.Fatal("finalize left the in-progress buffer open")
	}
	if tr.streamBuf != "" {
		t.Fatalf("streamBuf = %q, want empty after finalize", tr.streamBuf)
	}
	if got, want := tr.view.GetText(false), "done reply"+rawResponseLine; got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}

	// The finalized message is a permanent line: a later append lands beneath it.
	tr.append("next")
	if got, want := tr.view.GetText(false), "done reply"+rawResponseLine+"\n\nnext"; got != want {
		t.Fatalf("rendered after append = %q, want %q", got, want)
	}
}

func TestTranscript_MarkInterruptedAppendsMarker(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("partial")
	tr.markInterrupted()

	if tr.streaming {
		t.Fatal("markInterrupted left the in-progress buffer open")
	}
	// The marker is stored escaped (dynamic colors); the visible text
	// (GetText(true)) resolves it back to the literal " [interrupted]".
	want := "partial" + streamInterruptedMarker + visibleResponseLine
	if got := tr.view.GetText(true); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

func TestTranscript_FinalizeAndInterruptNoopWhenIdle(t *testing.T) {
	tr := newTranscript()
	tr.append("only line")
	tr.finalize()
	tr.markInterrupted()

	if got := tr.view.GetText(false); got != "only line" {
		t.Fatalf("rendered = %q, want %q (no phantom line when nothing streams)", got, "only line")
	}
	if len(tr.lines) != 1 {
		t.Fatalf("lines = %v, want a single committed line", tr.lines)
	}
}

func TestTranscript_RollbackPartialDropsUnsealedStream(t *testing.T) {
	tr := newTranscript()
	tr.append("> prompt")
	tr.appendDelta("partial")
	tr.rollbackPartial()

	if tr.streaming {
		t.Fatal("rollbackPartial left the in-progress buffer open")
	}
	if tr.streamBuf != "" {
		t.Fatalf("streamBuf = %q, want empty after rollbackPartial", tr.streamBuf)
	}
	if got := tr.view.GetText(true); got != "> prompt" {
		t.Fatalf("rendered = %q, want only committed history after rollback", got)
	}

	tr.appendDelta("regenerated")
	tr.finalize()
	if got, want := tr.view.GetText(true), "> prompt\n\nregenerated"+visibleResponseLine; got != want {
		t.Fatalf("rendered after regenerated stream = %q, want discarded partial absent", got)
	}
}

func TestTranscript_RetryRecoveredBreadcrumb(t *testing.T) {
	tr := newTranscript()
	tr.append("answer")
	tr.commitRetryRecovered(2)

	if got := tr.view.GetText(true); got != "answer\n\n· recovered after 2 retries" {
		t.Fatalf("rendered breadcrumb = %q, want visible recovered text", got)
	}
	if raw := tr.view.GetText(false); !strings.Contains(raw, "[::d]· recovered after 2 retries[::-]") {
		t.Fatalf("raw breadcrumb = %q, want dim style tag plus visible text", raw)
	}
}

// TestTranscript_BlankLineBetweenBlocks proves a prompt → reply → activity-line
// sequence renders with exactly one blank line between consecutive blocks,
// while a multi-line reply committed as one block keeps its own lines adjacent
// (no separator injected inside a block) and there is no leading blank line.
func TestTranscript_BlankLineBetweenBlocks(t *testing.T) {
	tr := newTranscript()
	tr.append("> name the provinces")        // echoed prompt block
	tr.append("1. Alpha\n2. Beta\n3. Gamma") // multi-line reply, one block
	tr.append("• model set to opus")         // activity-line block

	want := "> name the provinces\n\n" +
		"1. Alpha\n2. Beta\n3. Gamma\n\n" +
		"• model set to opus"
	if got := tr.view.GetText(false); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

// TestTranscript_FollowsNewestLineOnAppendAndStream proves render() keeps the
// view following the newest line: when committed lines and a grown in-progress
// stream exceed the visible height, a draw scrolls to the bottom rather than
// staying pinned at the top. It is state-level — the transcript view is drawn
// onto a fixed-size SimulationScreen, not a live terminal — so the scroll offset
// is deterministic. Earlier lines are preserved (the view stays scrollable), so
// they scroll up but remain in the transcript.
func TestTranscript_FollowsNewestLineOnAppendAndStream(t *testing.T) {
	const height = 5
	tr := newTranscript()
	for i := 0; i < 40; i++ {
		tr.append(fmt.Sprintf("line %d", i))
	}

	// 40 committed entries separated by one blank line render as 79 rows
	// (40 lines + 39 blank separators); ScrollToEnd pins the bottom.
	const committedRows = 40 + 39
	if row := drawScrollRow(t, tr, height); row != committedRows-height {
		t.Fatalf("scroll row after append = %d, want %d (transcript not following the newest line)", row, committedRows-height)
	}

	// A grown streamed reply adds a blank-line separator plus the in-progress line
	// (79 + 1 + 1 = 81 rows) and also follows the end instead of pinning at the top.
	for i := 0; i < 10; i++ {
		tr.appendDelta("x")
	}
	const streamedRows = committedRows + 1 + 1
	if row := drawScrollRow(t, tr, height); row != streamedRows-height {
		t.Fatalf("scroll row after stream = %d, want %d (transcript not following the streamed line)", row, streamedRows-height)
	}

	// All earlier committed lines remain present — nothing was discarded by the
	// scroll, so prior turns are still in the transcript.
	if got := len(tr.lines); got != 40 {
		t.Fatalf("committed lines = %d, want 40 (earlier turns must remain)", got)
	}
}

// drawScrollRow draws the transcript view onto a fixed-size SimulationScreen and
// returns the resulting top-row scroll offset. With ScrollToEnd asserted by
// render(), a buffer taller than height yields a non-zero offset that pins the
// bottom (len(lines)-height); without it the offset would stay 0 (top).
func drawScrollRow(t *testing.T, tr *transcript, height int) int {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	const width = 40
	screen.SetSize(width, height)
	tr.view.SetRect(0, 0, width, height)
	tr.view.Draw(screen)
	row, _ := tr.view.GetScrollOffset()
	return row
}

func TestStreamCanceller_DefaultInert(t *testing.T) {
	a := New(nil)
	if a.StreamCanceller() != nil {
		t.Fatalf("StreamCanceller() = %v, want nil (inert with none installed)", a.StreamCanceller())
	}
}

func TestStreamCanceller_InstalledAccessorReturnsHandle(t *testing.T) {
	a := New(nil)
	fc := &fakeCanceller{retained: 7, inFlight: true}
	a.SetStreamCanceller(fc)

	got := a.StreamCanceller()
	if got == nil {
		t.Fatal("StreamCanceller() is nil after SetStreamCanceller")
	}
	// The ESC and CTRL-C handlers reach the handle through the accessor and call Cancel() on it.
	retained, inFlight := got.Cancel()
	if retained != 7 || !inFlight {
		t.Fatalf("Cancel() = (%d, %v), want (7, true)", retained, inFlight)
	}
	if fc.calls != 1 {
		t.Fatalf("Cancel called %d times, want 1", fc.calls)
	}
}

// TestAppStreamSurface_DelegatesToTranscript drives the exported App methods on a
// non-running app (the direct path) and asserts they delegate to the transcript:
// deltas accumulate onto the in-progress line and MarkStreamInterrupted seals it.
func TestAppStreamSurface_DelegatesToTranscript(t *testing.T) {
	a := New(nil)
	a.Append("user: hi")
	a.AppendStreamDelta("Wor")
	a.AppendStreamDelta("ld")

	if !a.transcript.streaming {
		t.Fatal("AppendStreamDelta did not open the in-progress buffer")
	}
	if a.transcript.streamBuf != "World" {
		t.Fatalf("streamBuf = %q, want %q", a.transcript.streamBuf, "World")
	}
	if got := a.transcript.view.GetText(false); got != "user: hi\n\nWorld" {
		t.Fatalf("rendered = %q, want %q", got, "user: hi\n\nWorld")
	}

	a.MarkStreamInterrupted()
	if a.transcript.streaming {
		t.Fatal("MarkStreamInterrupted left the buffer open")
	}
	// The sealed line is stored escaped (dynamic colors); read the visible
	// text so the marker resolves to its literal form.
	want := "user: hi\n\nWorld" + streamInterruptedMarker + visibleResponseLine
	if got := a.transcript.view.GetText(true); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

// TestAppStreamSurface_FinalizeClosesReplyForNextStream drives the production
// App surface — AppendStreamDelta, then FinalizeStream, then AppendStreamDelta —
// to prove a naturally completed streamed reply is closed through an exported App
// method and the next reply starts a fresh in-progress buffer instead of merging
// onto the committed one.
func TestAppStreamSurface_FinalizeClosesReplyForNextStream(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("first ")
	a.AppendStreamDelta("reply")
	a.FinalizeStream()

	if a.transcript.streaming {
		t.Fatal("FinalizeStream left the in-progress buffer open")
	}
	if a.transcript.streamBuf != "" {
		t.Fatalf("streamBuf = %q, want empty after FinalizeStream", a.transcript.streamBuf)
	}
	if got, want := a.transcript.view.GetText(false), "first reply"+rawResponseLine; got != want {
		t.Fatalf("rendered after finalize = %q, want %q", got, want)
	}

	// The next streamed reply opens a fresh buffer beneath the committed line
	// rather than appending onto the finalized "first reply".
	a.AppendStreamDelta("second")
	if !a.transcript.streaming {
		t.Fatal("AppendStreamDelta after finalize did not open a new in-progress buffer")
	}
	if a.transcript.streamBuf != "second" {
		t.Fatalf("streamBuf = %q, want %q (fresh buffer, not merged with first reply)", a.transcript.streamBuf, "second")
	}
	if got, want := a.transcript.view.GetText(false), "first reply"+rawResponseLine+"\n\nsecond"; got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

// TestAppStreamSurface_CompletionFooterAfterFinalize proves the live completion footer
// lands directly after the finalized reply as a teal metadata block: the visible
// text reads "answer\n\nprovider - model - duration - HH:MM" and the raw form carries the
// teal style tags rather than plain assistant prose.
func TestAppStreamSurface_CompletionFooterAfterFinalize(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("the answer")
	a.FinalizeStream()
	a.AppendCompletionFooter([]sessions.Record{
		modelTurnEvent("openai", "gpt-x"),
		assistantMsg("the answer"),
		turnLatencyEvent("openai", "gpt-x", 1000),
	})

	if got, want := a.TranscriptText(), "the answer"+visibleResponseLine+"\n\nopenai - gpt-x - 1s - "+footerClock(); got != want {
		t.Fatalf("transcript visible = %q, want %q", got, want)
	}
	if raw := a.transcript.view.GetText(false); !strings.Contains(raw, "["+accentTealHex+"]openai - gpt-x - 1s - "+footerClock()+"[-]") {
		t.Fatalf("transcript raw = %q, want the footer as a teal metadata block", raw)
	}
}

// TestAppStreamSurface_NoCompletionFooterWithoutTiming proves AppendCompletionFooter is a
// no-op for a turn whose records carry no final turn_latency (an interrupted or failed
// reply), so nothing trails the reply.
func TestAppStreamSurface_NoCompletionFooterWithoutTiming(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("the answer")
	a.FinalizeStream()
	a.AppendCompletionFooter([]sessions.Record{
		modelTurnEvent("openai", "gpt-x"),
		assistantMsg("the answer"),
	})

	if got, want := a.TranscriptText(), "the answer"+visibleResponseLine; got != want {
		t.Fatalf("transcript visible = %q, want %q (no footer without turn_latency)", got, want)
	}
}

// TestAppStreamSurface_NoFooterReuseOnFooterFreeLatestTurn proves a footer-free latest turn
// never reuses the previous turn's footer. One fully-successful turn is followed by
// a nil-error empty-response turn — its start-of-turn model_turn carries no visible reply
// and no final turn_latency (the zero-delta contract in internal/turn/failure_test.go) — so
// AppendCompletionFooter must attach nothing to it.
func TestAppStreamSurface_NoFooterReuseOnFooterFreeLatestTurn(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("the answer")
	a.FinalizeStream()
	a.AppendCompletionFooter([]sessions.Record{
		// Turn 1: a full success that earns a footer.
		modelTurnEvent("openai", "gpt-x"),
		assistantMsg("the answer"),
		turnLatencyEvent("openai", "gpt-x", 1000),
		// Turn 2: empty response — start-of-turn model_turn only, no reply, no turn_latency.
		modelTurnEvent("openai", "gpt-x"),
	})

	if got, want := a.TranscriptText(), "the answer"+visibleResponseLine; got != want {
		t.Fatalf("transcript visible = %q, want %q (footer-free latest turn must not reuse turn 1's footer)", got, want)
	}
}

// TestAppStreamSurface_MalformedModelTurnSupersedesFooter proves a malformed new-turn
// model_turn closes the previous turn's footer window on the live path too: turn 1 earns a
// footer, then a malformed model_turn opens turn 2, so a later valid turn_latency cannot
// pair turn 1's provider/model with turn 2's reply — AppendCompletionFooter attaches nothing.
func TestAppStreamSurface_MalformedModelTurnSupersedesFooter(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("the answer")
	a.FinalizeStream()
	a.AppendCompletionFooter([]sessions.Record{
		// Turn 1: full success earning a footer.
		modelTurnEvent("openai", "gpt-x"),
		assistantMsg("the answer"),
		turnLatencyEvent("openai", "gpt-x", 1000),
		// Turn 2: malformed model_turn boundary, a visible reply, then a valid turn_latency.
		rawEvent(events.KindModelTurn, `{"provider":""}`),
		assistantMsg("second reply"),
		turnLatencyEvent("openai", "gpt-x", 1000),
	})

	if got, want := a.TranscriptText(), "the answer"+visibleResponseLine; got != want {
		t.Fatalf("transcript visible = %q, want %q (malformed model_turn must not reuse turn 1's footer)", got, want)
	}
}

// TestAppIndicator_SeedsElapsedFromSubmitStart proves a seeded submit-start makes the
// in-flight indicator measure elapsed from that instant, so its final elapsed matches the
// turn_latency basis rather than the later ShowIndicator instant; the seed is consumed
// after one turn so the next falls back to now.
func TestAppIndicator_SeedsElapsedFromSubmitStart(t *testing.T) {
	a := New(nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base.Add(9 * time.Second) } // "now" is 9s after submit
	a.SeedNextIndicatorStart(base)
	a.ShowIndicator(0, 0)
	if got := a.indicator.GetText(false); !strings.Contains(got, "(9s ") {
		t.Fatalf("indicator = %q, want elapsed 9s measured from the seeded submit-start", got)
	}

	a.ClearIndicator()
	a.ShowIndicator(0, 0) // no seed: measure from now, so elapsed is 0s
	if got := a.indicator.GetText(false); !strings.Contains(got, "(0s ") {
		t.Fatalf("indicator = %q, want elapsed 0s from now once the seed is consumed", got)
	}
}

func TestAppStreamSurface_RetryRollbackAndBreadcrumb(t *testing.T) {
	a := New(nil)
	a.Append("> prompt")
	a.AppendStreamDelta("Partial")
	a.RollbackPartial()
	a.AppendStreamDelta("Recovered")
	a.FinalizeStream()
	a.CommitRetryRecovered(1)

	if a.transcript.streaming {
		t.Fatal("retry rollback/finalize left the in-progress buffer open")
	}
	want := "> prompt\n\nRecovered" + visibleResponseLine + "\n\n· recovered after 1 retry"
	if got := a.transcript.view.GetText(true); got != want {
		t.Fatalf("rendered retry transcript = %q, want %q", got, want)
	}
	if strings.Contains(a.transcript.view.GetText(true), "Partial") {
		t.Fatal("discarded partial text remained in transcript after rollback")
	}
}

// TestAppRetryUX_PreservesUserInput proves the auto-retry UX surface methods
// touch only transcript/indicator state and leave a user's unsent draft intact
// across the whole reconnect → rollback → resume → recovered sequence and the
// exhaustion path (preservation unchanged across retries).
func TestAppRetryUX_PreservesUserInput(t *testing.T) {
	a := New(nil)
	fixedNow(a, time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	const draft = "a half-typed next prompt"
	a.input.SetText(draft)

	// Recovered-retry sequence: stream a partial, reconnect, roll it back, resume,
	// re-stream, finalize, and drop the breadcrumb.
	a.Append("> prompt")
	a.ShowIndicator(0, 0)
	a.AppendStreamDelta("Partial")
	a.ShowRetryBackoff(2, 4)
	a.RollbackPartial()
	a.ResumeRetry()
	a.AppendStreamDelta("Recovered")
	a.FinalizeStream()
	a.CommitRetryRecovered(1)
	if got := a.InputText(); got != draft {
		t.Fatalf("input after recovered retry = %q, want unchanged %q", got, draft)
	}

	// Exhaustion path: the enriched permanent error still leaves the draft alone.
	a.CommitProviderError("failed after 4 attempts: provider … failed (stream_drop/stream_read_error)")
	if got := a.InputText(); got != draft {
		t.Fatalf("input after exhausted retry = %q, want unchanged %q", got, draft)
	}
}

// TestAppStreamSurface_OffLoopMarshalsThroughQueue proves the exported methods are
// safe for the provider-runtime sink to call off the tview event-loop goroutine:
// with Run active, deltas fed from a non-loop goroutine marshal through the queue
// in order and the interrupted finalizer seals the line — read back on the loop
// goroutine via a QueueUpdate barrier so the test never races the draw loop. The
// -race build (mise run test) would flag a direct off-loop mutation here.
func TestAppStreamSurface_OffLoopMarshalsThroughQueue(t *testing.T) {
	a, stop := newRunningApp(t)

	a.AppendStreamDelta("Hel")
	a.AppendStreamDelta("lo")
	a.MarkStreamInterrupted()

	got := transcriptText(t, a)
	want := "Hello" + streamInterruptedMarker + visibleResponseLine
	if got != want {
		a.app.Stop()
		t.Fatalf("rendered transcript = %q, want %q", got, want)
	}

	stop()
}

// TestAppStreamSurface_CoalescesRunningDeltas proves the running-loop delta path is
// buffer-only: several deltas change no visible text and request no draw, the single
// armed timer renders all of them at once, and a stream that then goes quiet arms
// nothing further.
func TestAppStreamSurface_CoalescesRunningDeltas(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()

	timers := captureStreamRenderTimer(t, a)
	draws := streamDrawCounter(t, a)
	base := draws()

	a.AppendStreamDelta("Hel")
	a.AppendStreamDelta("lo")

	armed := timers()
	if armed.arms != 1 || armed.delay != streamRenderInterval {
		t.Fatalf("armed %d timers at %v, want 1 at %v", armed.arms, armed.delay, streamRenderInterval)
	}
	if got := transcriptText(t, a); got != "" {
		t.Fatalf("visible text before the timer = %q, want empty", got)
	}
	if got := draws() - base; got != 0 {
		t.Fatalf("draws during accumulation = %d, want 0", got)
	}

	armed.fire()

	if got := transcriptText(t, a); got != "Hello" {
		t.Fatalf("visible text after the timer = %q, want %q", got, "Hello")
	}
	if got := draws() - base; got != 1 {
		t.Fatalf("draws through one coalesced render = %d, want 1", got)
	}
	quiet := timers()
	if quiet.arms != 1 {
		t.Fatalf("armed %d timers, want no re-arm without a new delta", quiet.arms)
	}
	if quiet.pending {
		t.Fatal("render stayed pending after the coalesced render")
	}
}

// TestAppStreamSurface_SupersededTimerCannotRenderNextStream proves finalization both
// shows the complete buffered reply and invalidates the pending render, so the timer
// armed by the closed stream cannot render — or consume the render armed for — the
// stream that replaces it.
func TestAppStreamSurface_SupersededTimerCannotRenderNextStream(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()

	timers := captureStreamRenderTimer(t, a)
	a.AppendStreamDelta("fir")
	a.AppendStreamDelta("st")
	stale := timers().fire
	a.FinalizeStream()

	if got, want := transcriptText(t, a), "first"+visibleResponseLine; got != want {
		t.Fatalf("finalized text = %q, want every buffered delta", got)
	}
	if timers().pending {
		t.Fatal("finalize left a pending stream render")
	}

	a.AppendStreamDelta("second")
	stale()

	if got, want := transcriptText(t, a), "first"+visibleResponseLine; got != want {
		t.Fatalf("visible text after the superseded timer = %q, want the finalized reply alone", got)
	}
	current := timers()
	if !current.pending {
		t.Fatal("the superseded timer consumed the pending render of the next stream")
	}

	current.fire()
	if got, want := transcriptText(t, a), "first"+visibleResponseLine+"\n\nsecond"; got != want {
		t.Fatalf("visible text after the current timer = %q, want both blocks", got)
	}
}

// TestAppStreamSurface_BoundariesShowBufferedReply proves every boundary that
// re-renders displays the deltas buffered since the last coalesced render — the timer
// they invalidate is never needed to show them — and that the timer they superseded
// cannot change the result afterwards.
func TestAppStreamSurface_BoundariesShowBufferedReply(t *testing.T) {
	const patch = "--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n-old\n+new\n"
	for _, tc := range []struct {
		name     string
		setup    func(*App)
		boundary func(*App)
		want     string
	}{
		{
			name:     "notice",
			boundary: func(a *App) { a.NoticeFromBackground("heads up") },
			want:     "buffered\n\nheads up",
		},
		{
			name:     "clear notice",
			setup:    func(a *App) { a.NoticeFromBackground("heads up") },
			boundary: func(a *App) { a.RunOnEventLoopForTest(a.ClearNotice) },
			want:     "buffered",
		},
		{
			name:     "tool activity",
			boundary: func(a *App) { a.AppendToolActivity([]string{"Run: go build"}) },
			want:     "buffered" + visibleResponseLine + "\n\nRun: go build",
		},
		{
			name:     "edit patch",
			boundary: func(a *App) { a.AppendEditPatch(patch) },
			want:     "buffered" + visibleResponseLine + "\n\n" + strings.TrimRight(patch, "\n"),
		},
		{
			name:     "off-loop interruption",
			boundary: func(a *App) { a.MarkStreamInterrupted() },
			want:     "buffered" + streamInterruptedMarker + visibleResponseLine,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, stop := newRunningApp(t)
			defer stop()
			if tc.setup != nil {
				tc.setup(a)
			}

			timers := captureStreamRenderTimer(t, a)
			draws := streamDrawCounter(t, a)
			a.AppendStreamDelta("buffered")
			stale := timers().fire

			tc.boundary(a)

			if got := transcriptText(t, a); got != tc.want {
				t.Fatalf("visible text at the boundary = %q, want %q", got, tc.want)
			}
			base := draws()
			stale()
			if got := transcriptText(t, a); got != tc.want {
				t.Fatalf("the superseded timer changed the transcript to %q, want %q", got, tc.want)
			}
			if got := draws() - base; got != 0 {
				t.Fatalf("draws requested by the superseded timer = %d, want 0", got)
			}
		})
	}
}

// TestAppStreamSurface_RollbackDropsBufferedReply proves a rollback before an
// auto-retry discards the buffered partial immediately, and that the timer armed for
// it cannot restore the discarded text or render the regenerated stream early.
func TestAppStreamSurface_RollbackDropsBufferedReply(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()

	timers := captureStreamRenderTimer(t, a)
	a.AppendStreamDelta("discarded partial")
	stale := timers().fire

	a.RollbackPartial()

	if got := transcriptText(t, a); got != "" {
		t.Fatalf("visible text after rollback = %q, want empty", got)
	}

	a.AppendStreamDelta("regenerated")
	stale()

	if got := transcriptText(t, a); got != "" {
		t.Fatalf("visible text after the stale timer = %q, want empty", got)
	}
}

func TestAppStop_DropsPendingStreamRender(t *testing.T) {
	a, stop := newRunningApp(t)
	timers := captureStreamRenderTimer(t, a)
	a.AppendStreamDelta("partial")
	stale := timers().fire

	a.Stop()
	// A queue attempt made after Stop never completes, so the callback returning at
	// all is what proves it made none.
	stale()
	stop()

	if got := a.transcript.view.GetText(true); got != "" {
		t.Fatalf("visible text after a post-stop timer = %q, want empty", got)
	}
}

func TestAppNoticeFromBackground_OffLoopMarshalsThroughQueue(t *testing.T) {
	a, stop := newRunningApp(t)

	a.NoticeFromBackground("write failed")

	got := transcriptText(t, a)
	if got != "write failed" {
		a.app.Stop()
		t.Fatalf("rendered transcript = %q, want %q", got, "write failed")
	}

	stop()
}

// TestTranscript_CommitErrorAppendsEscapedHistoryLine proves commitError commits an
// error as a permanent transcript line (part of scrollable history, escaped), one
// block-gap below the prior output, with a later append landing beneath it —
// i.e. it behaves like append/finalize, not like the bottom-pinned notice.
func TestTranscript_CommitErrorAppendsEscapedHistoryLine(t *testing.T) {
	tr := newTranscript()
	tr.append("> prompt")
	tr.commitError(`provider returned HTTP 429: [rate-limited]`)

	// The committed error is a permanent line one block below the prompt; its
	// tag-like "[rate-limited]" renders literally (GetText(true)) under dynamic colors.
	want := "> prompt\n\nprovider returned HTTP 429: [rate-limited]"
	if got := tr.view.GetText(true); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
	if len(tr.lines) != 2 {
		t.Fatalf("committed lines = %v, want the prompt and the error as two committed entries", tr.lines)
	}
	// A later reply lands beneath the committed error: it is history, not a pinned
	// bottom line that re-floats below new output.
	tr.append("later reply")
	if got := tr.view.GetText(true); got != want+"\n\nlater reply" {
		t.Fatalf("rendered after later append = %q, want the error to stay above the later reply", got)
	}
}

// TestAppCommitProviderError_OrdersAfterSealedTurnOutput proves the committed
// provider error lands after whatever seal already applied (step 2 ordering): a
// pre-stream failure directly after the submitted prompt (no forced finalize), a
// completed reply after FinalizeStream, and an interrupted reply after
// MarkStreamInterrupted — all through the exported App surface.
func TestAppCommitProviderError_OrdersAfterSealedTurnOutput(t *testing.T) {
	t.Run("pre-stream lands after the prompt", func(t *testing.T) {
		a := New(nil)
		a.Append("> prompt")          // echoed prompt
		a.CommitProviderError("boom") // failure before any stream opened
		if got := a.transcript.view.GetText(true); got != "> prompt\n\nboom" {
			t.Fatalf("rendered = %q, want the error directly after the prompt (no forced finalize)", got)
		}
	})
	t.Run("after a finalized reply", func(t *testing.T) {
		a := New(nil)
		a.Append("> prompt")
		a.AppendStreamDelta("done reply")
		a.FinalizeStream()
		a.CommitProviderError("boom")
		if got, want := a.transcript.view.GetText(true), "> prompt\n\ndone reply"+visibleResponseLine+"\n\nboom"; got != want {
			t.Fatalf("rendered = %q, want the error after the finalized reply", got)
		}
	})
	t.Run("after an interrupted reply", func(t *testing.T) {
		a := New(nil)
		a.Append("> prompt")
		a.AppendStreamDelta("partial")
		a.MarkStreamInterrupted()
		a.CommitProviderError("boom")
		want := "> prompt\n\npartial" + streamInterruptedMarker + visibleResponseLine + "\n\nboom"
		if got := a.transcript.view.GetText(true); got != want {
			t.Fatalf("rendered = %q, want %q", got, want)
		}
	})
}

// TestAppCommitProviderError_OffLoopMarshalsThroughQueue proves CommitProviderError
// is safe for the provider-runtime to call off the tview event-loop goroutine: with
// Run active, an error committed from a non-loop goroutine marshals through the queue
// and lands in committed history (read back on the loop via the barrier). The -race
// build (mise run test) would flag a direct off-loop mutation here.
func TestAppCommitProviderError_OffLoopMarshalsThroughQueue(t *testing.T) {
	a, stop := newRunningApp(t)

	a.CommitProviderError("provider returned HTTP 429: rate-limited")

	got := transcriptText(t, a)
	if got != "provider returned HTTP 429: rate-limited" {
		a.app.Stop()
		t.Fatalf("rendered transcript = %q, want the committed provider error", got)
	}
	stop()
}

// TestProviderError_CommittedOnceNotRepinnedAfterModelChange reproduces the reported
// bug: a turn fails with a provider error, the user switches the
// model, and a later prompt succeeds. The original error must appear exactly once —
// committed at its own turn in history — and must NOT re-render below the later
// turn's reply; committed history is preserved across the model-change notice clear
// (Done-when 5).
func TestProviderError_CommittedOnceNotRepinnedAfterModelChange(t *testing.T) {
	a := New(nil)
	const errLine = `provider openrouter returned HTTP 429: {"error":[gemma-4]} is temporarily rate-limited`

	// Failed turn: the prompt is echoed, then the provider error is committed in place
	// (the provider-error path routes the turn's Notice hook to CommitProviderError).
	a.Append("> gemma prompt")
	a.CommitProviderError(errLine)

	// The user switches to a working model; the model-change path clears any pinned
	// transient notice. The error is already committed history, so nothing is left
	// pinned to re-float — which is the whole point of the fix.
	a.ClearNotice()

	// A new prompt succeeds and streams a reply.
	a.Append("> granite prompt")
	a.AppendStreamDelta("granite reply")
	a.FinalizeStream()

	text := a.transcript.view.GetText(true)
	if n := strings.Count(text, errLine); n != 1 {
		t.Fatalf("original error appears %d times in the transcript, want exactly 1:\n%s", n, text)
	}
	// The error stays at its own turn above the later reply — it must not be the final
	// bottom line anymore (the old single-notice re-render symptom).
	if !strings.HasSuffix(text, "granite reply"+visibleResponseLine) {
		t.Fatalf("transcript does not end with the later reply; the error may have re-pinned at the bottom:\n%s", text)
	}
	if a.transcript.notice != "" {
		t.Fatalf("notice = %q, want empty (the error is committed history, never re-pinned)", a.transcript.notice)
	}
	// Full committed history preserved in order across the notice clear (Done-when 5).
	want := "> gemma prompt\n\n" + errLine + "\n\n> granite prompt\n\ngranite reply" + visibleResponseLine
	if text != want {
		t.Fatalf("transcript =\n%q\nwant\n%q", text, want)
	}
}

// TestAppAppendToolActivity_FinalizesThenAppendsEscapedBlock proves the tool-activity TUI
// contract through the exported surface: AppendToolActivity first commits any
// in-progress assistant reply (so the model's pre-tool text lands above the activity),
// then appends the round's lines as one escaped multi-line transcript entry — style-
// sensitive content like "[x]" renders literally, and parallel calls from one round
// stay one block, not separate blank-gapped entries.
func TestAppAppendToolActivity_FinalizesThenAppendsEscapedBlock(t *testing.T) {
	a := New(nil)
	a.Append("> prompt")
	a.AppendStreamDelta("about to edit")
	a.AppendToolActivity([]string{"Edit pkg/[x].go", "Run: go build ./..."})

	if a.transcript.streaming {
		t.Fatal("AppendToolActivity did not finalize the in-progress reply before appending")
	}
	// Pre-tool text commits above the activity; the two lines render as one block (one
	// blank-gap below the reply, none between the two lines); "[x]" stays literal.
	want := "> prompt\n\nabout to edit" + visibleResponseLine + "\n\nEdit pkg/[x].go\nRun: go build ./..."
	if got := a.transcript.view.GetText(true); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
	// One transcript entry for the whole round (prompt, finalized reply, activity block).
	if len(a.transcript.lines) != 3 {
		t.Fatalf("committed lines = %v, want 3 (prompt, reply, one activity block)", a.transcript.lines)
	}
}

// An activity round emitted with no in-progress reply commits directly after the
// prompt (no spurious finalize), and an empty round is a no-op.
func TestAppAppendToolActivity_NoReplyAndEmptyRound(t *testing.T) {
	a := New(nil)
	a.Append("> prompt")
	a.AppendToolActivity(nil) // empty round: nothing appended
	if len(a.transcript.lines) != 1 {
		t.Fatalf("committed lines = %v, want only the prompt (empty round appends nothing)", a.transcript.lines)
	}
	a.AppendToolActivity([]string{"Read server.go"})
	if got := a.transcript.view.GetText(true); got != "> prompt\n\nRead server.go" {
		t.Fatalf("rendered = %q, want the activity directly after the prompt", got)
	}
}

// TestAppAppendToolActivity_OffLoopMarshalsThroughQueue proves AppendToolActivity is
// safe for the provider runtime to call off the tview event-loop goroutine: with Run
// active, an activity round fed from a non-loop goroutine marshals through the queue
// and lands as one block (read back on the loop via the barrier). The -race build
// (mise run test) would flag a direct off-loop mutation here.
func TestAppAppendToolActivity_OffLoopMarshalsThroughQueue(t *testing.T) {
	a, stop := newRunningApp(t)

	a.AppendToolActivity([]string{"Run: go build ./...", "Edit pkg/[x].go"})

	got := transcriptText(t, a)
	want := "Run: go build ./...\nEdit pkg/[x].go"
	if got != want {
		a.app.Stop()
		t.Fatalf("rendered transcript = %q, want %q", got, want)
	}
	stop()
}

const editPatchFixture = "--- pkg/[x].go\n" +
	"+++ pkg/[x].go\n" +
	"@@ -1,3 +1,3 @@\n" +
	" context [dim]line\n" +
	"-old [red]line\n" +
	"+new [green]line\n"

func TestAppAppendEditPatch_FinalizesThenAppendsPatchBlock(t *testing.T) {
	a := New(nil)
	a.Append("> prompt")
	a.AppendStreamDelta("editing now")
	a.AppendEditPatch(editPatchFixture)

	if a.transcript.streaming {
		t.Fatal("AppendEditPatch did not finalize the in-progress reply before appending")
	}
	want := "> prompt\n\nediting now" + visibleResponseLine + "\n\n" + strings.TrimRight(editPatchFixture, "\n")
	if got := a.transcript.view.GetText(true); got != want {
		t.Fatalf("rendered = %q, want %q (the visible text is the raw patch, tags literal)", got, want)
	}
	if len(a.transcript.lines) != 3 {
		t.Fatalf("committed lines = %v, want 3 (prompt, reply, one patch block)", a.transcript.lines)
	}
}

func TestAppAppendEditPatch_ColorsOnlyRemovedAndAddedLines(t *testing.T) {
	a := New(nil)
	a.AppendEditPatch(editPatchFixture)

	raw := a.transcript.view.GetText(false)
	removed := patchRemovedColor + tview.Escape("-old [red]line") + defaultTag
	added := patchAddedColor + tview.Escape("+new [green]line") + defaultTag
	if !strings.Contains(raw, removed) {
		t.Fatalf("rendered = %q, want the removed line styled as %q", raw, removed)
	}
	if !strings.Contains(raw, added) {
		t.Fatalf("rendered = %q, want the added line styled as %q", raw, added)
	}
	neutral := tview.Escape("--- pkg/[x].go") + "\n" + tview.Escape("+++ pkg/[x].go") +
		"\n@@ -1,3 +1,3 @@\n" + tview.Escape(" context [dim]line") + "\n" + patchRemovedColor
	if !strings.Contains(raw, neutral) {
		t.Fatalf("rendered = %q, want unstyled headers/hunk/context before the first colored line (%q)", raw, neutral)
	}
	if n := strings.Count(raw, patchRemovedColor); n != 1 {
		t.Fatalf("red tags = %d, want exactly 1 (only the removed line)", n)
	}
	if n := strings.Count(raw, patchAddedColor); n != 1 {
		t.Fatalf("green tags = %d, want exactly 1 (only the added line)", n)
	}
}

func TestAppAppendEditPatch_EmptyPatchAndNoReply(t *testing.T) {
	a := New(nil)
	a.Append("> prompt")
	a.AppendEditPatch("")
	a.AppendEditPatch("\n")
	if len(a.transcript.lines) != 1 {
		t.Fatalf("committed lines = %v, want only the prompt (an empty patch appends nothing)", a.transcript.lines)
	}
	a.AppendEditPatch("--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n-old\n+new\n")
	want := "> prompt\n\n--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n-old\n+new"
	if got := a.transcript.view.GetText(true); got != want {
		t.Fatalf("rendered = %q, want %q", got, want)
	}
}

func TestAppAppendEditPatch_OffLoopMarshalsThroughQueue(t *testing.T) {
	a, stop := newRunningApp(t)

	a.AppendEditPatch(editPatchFixture)

	got := transcriptText(t, a)
	want := strings.TrimRight(editPatchFixture, "\n")
	if got != want {
		a.app.Stop()
		t.Fatalf("rendered transcript = %q, want %q", got, want)
	}
	stop()
}

// App.Run is required for off-loop surfaces to marshal through the queue.
func newRunningApp(t *testing.T) (*App, func()) {
	t.Helper()
	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }

	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)

	return a, func() {
		t.Helper()
		// App.Stop latches a.stopping, so a test that stopped the app itself must not
		// stop it a second time: tview's Run clears a.screen unlocked after its event
		// loop exits, which a concurrent Application.Stop would read (upstream race).
		if !a.stopping.Load() {
			a.app.Stop()
		}
		if err := <-errc; err != nil {
			t.Fatalf("app.Run returned error: %v", err)
		}
	}
}

// waitLoopRunning blocks until the event loop is draining the update queue. A
// QueueUpdate only completes once Run is processing updates, so a completed
// barrier proves the loop is live.
func waitLoopRunning(t *testing.T, a *App) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		a.app.QueueUpdate(func() {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("event loop did not start within 2s")
	}
}

// streamRenderTimer is one reading of the coalesced-render timer state: how many
// one-shot timers have been armed, the delay of the most recent one, whether a render
// is still pending, and the callback to fire in place of the real clock.
type streamRenderTimer struct {
	arms    int
	delay   time.Duration
	pending bool
	fire    func()
}

// captureStreamRenderTimer replaces the app's timer seam on the event-loop goroutine
// and returns a reader for the captured state, so a test drives the coalesced render
// on demand instead of waiting out streamRenderInterval. Both the capture and the read
// go through the tview queue, so they are ordered against the loop that writes them.
func captureStreamRenderTimer(t *testing.T, a *App) func() streamRenderTimer {
	t.Helper()
	var armed streamRenderTimer
	a.RunOnEventLoopForTest(func() {
		a.afterFunc = func(d time.Duration, f func()) {
			armed.arms++
			armed.delay = d
			armed.fire = f
		}
	})
	return func() streamRenderTimer {
		t.Helper()
		var got streamRenderTimer
		a.app.QueueUpdate(func() {
			got = armed
			got.pending = a.streamRenderPending
		})
		if got.fire == nil {
			t.Fatal("no stream render timer was armed")
		}
		return got
	}
}

// streamDrawCounter returns a reader for the number of full screen draws the app has
// performed, so a test can assert that buffered deltas request none. The read is queued
// without a draw and therefore runs after any draw the previous queued update triggered.
func streamDrawCounter(t *testing.T, a *App) func() int {
	t.Helper()
	var draws int
	a.RunOnEventLoopForTest(func() {
		a.app.SetAfterDrawFunc(func(tcell.Screen) { draws++ })
	})
	return func() int {
		t.Helper()
		var n int
		a.app.QueueUpdate(func() { n = draws })
		return n
	}
}

// transcriptText reads the visible rendered transcript text on the event-loop
// goroutine via QueueUpdate, so the read is serialized with the draws that mutate
// it. It strips style tags / resolves escapes (GetText(true)) so the interrupted
// marker reads as its literal form under the transcript's dynamic colors.
func transcriptText(t *testing.T, a *App) string {
	t.Helper()
	var s string
	a.app.QueueUpdate(func() { s = a.transcript.view.GetText(true) })
	return s
}
