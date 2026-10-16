// Tests for the transcript reset surface (/clear wiping the visible pane),
// the accepted-submit echo suppression that keeps "> /clear" off the fresh pane,
// and the handler-level ordering that resets only after a committed swap.
package tui

import (
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

// TestApp_ResetTranscript_ClearsRenderedState proves ResetTranscript wipes every
// rendered surface — committed lines, the in-progress streamed line, and the
// notice — not just the most recent one, so a fresh session opens on a blank pane.
func TestApp_ResetTranscript_ClearsRenderedState(t *testing.T) {
	a := New(nil)
	a.Append("prior conversation line")
	a.AppendStreamDelta("a partial assistant reply")
	a.Notice("a lingering notice")

	if got := a.TranscriptText(); got == "" {
		t.Fatal("precondition: transcript should hold seeded content before reset")
	}

	a.ResetTranscript()

	if got := a.TranscriptText(); got != "" {
		t.Fatalf("after ResetTranscript, transcript = %q, want empty", got)
	}
}

// TestApp_ResetTranscript_DropsPendingStreamRender proves /clear's reset discards the
// buffered reply and the render armed for it, so the timer captured before the reset
// cannot paint anything onto the freshly-wiped pane.
func TestApp_ResetTranscript_DropsPendingStreamRender(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()

	timers := captureStreamRenderTimer(t, a)
	a.AppendStreamDelta("a partial assistant reply")
	stale := timers().fire

	a.RunOnEventLoopForTest(a.ResetTranscript)

	if timers().pending {
		t.Fatal("ResetTranscript left a pending stream render")
	}

	a.AppendStreamDelta("post-reset delta")
	stale()

	if got := transcriptText(t, a); got != "" {
		t.Fatalf("visible text after the stale timer = %q, want empty", got)
	}
}

// TestApp_MarkStreamInterruptedFromCommand_DropsPendingStreamRender proves the direct
// event-loop seal /clear and /resume use shows every buffered delta and invalidates
// the pending render before it replaces the transcript state.
func TestApp_MarkStreamInterruptedFromCommand_DropsPendingStreamRender(t *testing.T) {
	a, stop := newRunningApp(t)
	defer stop()

	timers := captureStreamRenderTimer(t, a)
	a.AppendStreamDelta("par")
	a.AppendStreamDelta("tial")
	stale := timers().fire

	a.RunOnEventLoopForTest(a.MarkStreamInterruptedFromCommand)

	sealed := "partial" + streamInterruptedMarker + visibleResponseLine
	if got := transcriptText(t, a); got != sealed {
		t.Fatalf("sealed transcript = %q, want %q", got, sealed)
	}
	if timers().pending {
		t.Fatal("command interruption left a pending stream render")
	}

	a.AppendStreamDelta("next reply")
	stale()

	if got := transcriptText(t, a); got != sealed {
		t.Fatalf("visible text after the stale timer = %q, want %q", got, sealed)
	}
}

// TestApp_ResetTranscript_SuppressesAcceptedSubmitEcho proves that when an accepted
// command resets the transcript during dispatch, submitCurrent does not append the
// "> <command>" echo onto the freshly-cleared pane. The submit hook stands
// in for the /clear handler: it wipes the pane and accepts.
func TestApp_ResetTranscript_SuppressesAcceptedSubmitEcho(t *testing.T) {
	var a *App
	a = New(func(string, ...sessions.ContentPart) bool {
		a.ResetTranscript()
		return true
	})
	a.Append("prior conversation that /clear must wipe")

	if !a.SubmitInput("/clear") {
		t.Fatal("submit hook should accept /clear")
	}
	if got := a.TranscriptText(); got != "" {
		t.Fatalf("after a transcript-resetting accept, transcript = %q, want empty (no \"> /clear\" echo)", got)
	}
}

// TestApp_SubmitCurrent_EchoesWhenNoReset is the contrast: an ordinary accepted
// submission that does not reset the transcript still echoes "▌ <input>", so the
// suppression is scoped to the reset path and does not silence normal echoes.
func TestApp_SubmitCurrent_EchoesWhenNoReset(t *testing.T) {
	a := New(func(string, ...sessions.ContentPart) bool { return true })

	if !a.SubmitInput("hello there") {
		t.Fatal("submit hook should accept the input")
	}
	if got := a.TranscriptText(); got != "▌ hello there" {
		t.Fatalf("accepted submit transcript = %q, want %q", got, "▌ hello there")
	}
}

// TestApp_SubmitCurrent_SuppressionDoesNotLeakToNextSubmit proves the one-shot flag
// is consumed: a reset-and-accept submission suppresses its own echo, but the very
// next ordinary accepted submission echoes normally.
func TestApp_SubmitCurrent_SuppressionDoesNotLeakToNextSubmit(t *testing.T) {
	var a *App
	reset := true
	a = New(func(string, ...sessions.ContentPart) bool {
		if reset {
			a.ResetTranscript()
		}
		return true
	})

	if !a.SubmitInput("/clear") {
		t.Fatal("first submit should be accepted")
	}
	reset = false
	if !a.SubmitInput("a normal prompt") {
		t.Fatal("second submit should be accepted")
	}
	if got := a.TranscriptText(); got != "▌ a normal prompt" {
		t.Fatalf("after a suppressed echo then a normal one, transcript = %q, want %q", got, "▌ a normal prompt")
	}
}

// fakeResetter is a tui.TranscriptResetter that records how many times Reset ran and
// when, so the handler tests can assert it fires exactly once, after the swap.
type fakeResetter struct {
	order  *callOrder
	resets int
	at     int
}

func (r *fakeResetter) Reset() {
	r.resets++
	if r.order != nil {
		r.at = r.order.tick()
	}
}

// TestClearHandler_ResetsTranscriptAfterSuccessfulSwap pins the post-swap reset: a successful /clear
// resets the transcript exactly once, and strictly after CarryForward (the last
// pre-reset step), so the wipe happens only once the swap and all post-swap work have
// committed.
func TestClearHandler_ResetsTranscriptAfterSuccessfulSwap(t *testing.T) {
	host := newWritableHost(t)
	fx := newClearFixture(t)
	resetter := &fakeResetter{order: fx.order}
	fx.deps.Transcript = resetter
	reg := newClearRegistry(t, fx.deps)

	if res := reg.DispatchSlashInput("/clear", host); res.Err != nil {
		t.Fatalf("dispatch err: %v", res.Err)
	}
	if resetter.resets != 1 {
		t.Fatalf("transcript Reset called %d times, want 1 after a successful swap", resetter.resets)
	}
	if resetter.at == 0 || fx.model.at == 0 || resetter.at <= fx.model.at {
		t.Errorf("call order: CarryForward=%d, Reset=%d, want Reset strictly after CarryForward", fx.model.at, resetter.at)
	}
}

// TestClearHandler_NoTranscriptResetOnRefusedSwitch pins the inverse: when the
// pre-switch flush fails the swap is refused, so the transcript must NOT be reset —
// the prior session stays active and its visible pane must be left intact.
func TestClearHandler_NoTranscriptResetOnRefusedSwitch(t *testing.T) {
	host := newFlushFailingHost()
	fx := newClearFixture(t)
	resetter := &fakeResetter{order: fx.order}
	fx.deps.Transcript = resetter
	reg := newClearRegistry(t, fx.deps)

	if res := reg.DispatchSlashInput("/clear", host); res.Status != StatusHandled {
		t.Fatalf("status = %v, want Handled", res.Status)
	}
	if resetter.resets != 0 {
		t.Errorf("transcript Reset called %d times on a refused switch, want 0 (prior pane must stay)", resetter.resets)
	}
}
