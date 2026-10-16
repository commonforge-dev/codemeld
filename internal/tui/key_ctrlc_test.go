// Tests for the CTRL-C priority order: stream-first interruption, input
// clearing, the double-empty clean-exit within the 1500ms window, the outside-
// window fresh-press reset, hint clearing on a keystroke and on timeout (with a
// generation guard against a stale timer), and key consumption.
package tui

import (
	"errors"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// fakeClock is a manually-advanced clock for the CTRL-C window tests, so the
// 1500ms double-press window is exercised without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// installFakeCtrlCClock replaces the app's clock and timer seams with manual ones,
// returning the clock and a slice that collects every scheduled timeout callback so
// a test can fire them by hand (and assert the generation guard across re-arms).
func installFakeCtrlCClock(a *App) (*fakeClock, *[]func()) {
	clk := &fakeClock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	timers := &[]func(){}
	a.now = clk.now
	a.afterFunc = func(_ time.Duration, f func()) { *timers = append(*timers, f) }
	return clk, timers
}

// pressCtrlC drives the app-level global-key capture with a CTRL-C event, exactly
// as the live tview event loop would.
func pressCtrlC(a *App) {
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone))
}

// TestCtrlC_StreamFirst asserts a CTRL-C while a stream is in flight stops the
// stream with source "ctrl-c" and does not clear input or exit, even with typed
// input present (step 1).
func TestCtrlC_StreamFirst(t *testing.T) {
	a := New(nil)
	store := escTestStore()
	a.SetActiveStore(store)
	a.SetStreamCanceller(&fakeStreamCanceller{retained: 7, inFlight: true})
	a.SetCommandFlush(func() error { return nil })
	a.input.SetText("typed")
	a.AppendStreamDelta("partial")

	pressCtrlC(a)

	if got := a.input.GetText(); got != "typed" {
		t.Fatalf("input = %q, want preserved (stream priority must not clear input)", got)
	}
	if a.transcript.streaming || a.transcript.streamBuf != "" {
		t.Fatalf("stream buffer still open: streaming=%v buf=%q", a.transcript.streaming, a.transcript.streamBuf)
	}
	// The transcript stores the sealed line escaped (dynamic colors), so the
	// assertion reads the visible rendered text, where the interrupted marker shows
	// literally.
	if got, want := a.transcript.text(true), "partial [interrupted]"+visibleResponseLine; got != want {
		t.Fatalf("transcript = %q, want interrupted partial", got)
	}
	interrupt := onlyStreamInterrupted(t, store)
	if interrupt.Source != "ctrl-c" || interrupt.ContentChars != 7 {
		t.Fatalf("stream_interrupted = %+v, want ctrl-c/7", interrupt)
	}
}

// TestCtrlC_StreamFlushError_ShowsNotice asserts a flush failure while stopping the
// stream surfaces as a one-line notice and aborts the handler, mirroring HandleEsc.
func TestCtrlC_StreamFlushError_ShowsNotice(t *testing.T) {
	a := New(nil)
	store := escTestStore()
	a.SetActiveStore(store)
	a.SetStreamCanceller(&fakeStreamCanceller{retained: 4, inFlight: true})
	flushErr := errors.New("flush failed on interrupt")
	a.SetCommandFlush(func() error { return flushErr })
	a.AppendStreamDelta("partial")

	pressCtrlC(a)

	if a.transcript.notice != flushErr.Error() {
		t.Fatalf("notice = %q, want flush error %q", a.transcript.notice, flushErr.Error())
	}
}

// TestCtrlC_NonEmptyInput_ClearsBufferAndHint asserts a CTRL-C with typed input
// clears the buffer and any pending exit hint, and does not exit (step 2).
func TestCtrlC_NonEmptyInput_ClearsBufferAndHint(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-c"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	installFakeCtrlCClock(app)

	pressCtrlC(app) // empty buffer: arms the hint
	if !app.ctrlCArmed || app.transcript.notice != ctrlCHintText {
		t.Fatalf("after first CTRL-C: armed=%v notice=%q, want armed with hint", app.ctrlCArmed, app.transcript.notice)
	}

	app.input.SetText("draft")
	pressCtrlC(app)

	if got := app.input.GetText(); got != "" {
		t.Fatalf("input = %q, want cleared", got)
	}
	if app.ctrlCArmed || app.transcript.notice != "" {
		t.Fatalf("hint not cleared: armed=%v notice=%q", app.ctrlCArmed, app.transcript.notice)
	}
	if ctrl.finishCalled {
		t.Error("exit triggered on non-empty CTRL-C, want buffer clear only")
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events, want 0", len(evs))
	}
}

// TestCtrlC_DoubleEmptyWithinWindow_ExitsViaCleanShutdown asserts two empty-buffer
// CTRL-C presses within 1500ms exit through the /exit clean-shutdown path: the
// canonical slash_command{name:"exit"} event is recorded and Finish exits 0 with
// the resume hint (step 3).
func TestCtrlC_DoubleEmptyWithinWindow_ExitsViaCleanShutdown(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-c"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	clk, _ := installFakeCtrlCClock(app)

	pressCtrlC(app)
	clk.advance(1499 * time.Millisecond)
	pressCtrlC(app)

	if !ctrl.finishCalled || ctrl.finishCode != 0 {
		t.Fatalf("Finish(code=%d, called=%v), want code 0", ctrl.finishCode, ctrl.finishCalled)
	}
	if want := ResumeHint("sess-c"); ctrl.finishHint != want {
		t.Errorf("Finish hint = %q, want %q", ctrl.finishHint, want)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "exit" || p.Outcome != "success" || len(p.Args) != 0 {
		t.Errorf("event = %+v, want name=exit args=[] outcome=success", p)
	}
}

// TestCtrlC_DoubleEmpty_EventBeforeFlush asserts the exit reuses /exit's
// step-1-before-step-2 ordering: the slash_command event is in the stream before
// the clean-shutdown flush runs (step 3).
func TestCtrlC_DoubleEmpty_EventBeforeFlush(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-c"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	clk, _ := installFakeCtrlCClock(app)

	pressCtrlC(app)
	clk.advance(500 * time.Millisecond)
	pressCtrlC(app)

	if ctrl.flushCalls != 1 {
		t.Fatalf("FlushOnExit called %d times, want 1", ctrl.flushCalls)
	}
	if ctrl.slashEventsAtFlush != 1 {
		t.Errorf("slash_command events present at flush = %d, want 1 (event must precede the flush)", ctrl.slashEventsAtFlush)
	}
}

// TestCtrlC_DoubleEmpty_SecondFailureExitsOne asserts the second-failure exit path: when the
// clean-shutdown flush fails after retry, the double-CTRL-C exit takes exit 1 with
// no resume hint (step 3).
func TestCtrlC_DoubleEmpty_SecondFailureExitsOne(t *testing.T) {
	flushErr := errors.New("session write failed on exit after retry")
	ctrl := &fakeExitController{sessionID: "sess-c", flushErr: flushErr}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	clk, _ := installFakeCtrlCClock(app)

	pressCtrlC(app)
	clk.advance(100 * time.Millisecond)
	pressCtrlC(app)

	if !ctrl.finishCalled || ctrl.finishCode != 1 {
		t.Fatalf("Finish(code=%d, called=%v), want code 1", ctrl.finishCode, ctrl.finishCalled)
	}
	if ctrl.finishHint != "" {
		t.Errorf("Finish hint = %q, want empty on the second-failure path", ctrl.finishHint)
	}
}

// TestCtrlC_OutsideWindow_ShowsHintAgainNotExit asserts a second empty CTRL-C past
// the 1500ms window is treated as a fresh first press: it re-shows the hint and
// does not exit (step 4).
func TestCtrlC_OutsideWindow_ShowsHintAgainNotExit(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-c"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	clk, _ := installFakeCtrlCClock(app)

	pressCtrlC(app)
	clk.advance(1500*time.Millisecond + time.Nanosecond)
	pressCtrlC(app)

	if ctrl.finishCalled {
		t.Fatal("Finish called for a second CTRL-C outside the window, want hint re-shown")
	}
	if !app.ctrlCArmed || app.transcript.notice != ctrlCHintText {
		t.Fatalf("after outside-window CTRL-C: armed=%v notice=%q, want hint re-shown", app.ctrlCArmed, app.transcript.notice)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events, want 0", len(evs))
	}
}

// TestCtrlC_HintClearsOnNextKeystroke asserts any non-CTRL-C key clears a pending
// hint, and that a later CTRL-C within the original window no longer exits (the
// window was disarmed by the keystroke) (step 4).
func TestCtrlC_HintClearsOnNextKeystroke(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-c"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	clk, _ := installFakeCtrlCClock(app)

	pressCtrlC(app)
	if !app.ctrlCArmed {
		t.Fatal("hint not armed after first CTRL-C")
	}

	app.handleGlobalKey(tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone))
	if app.ctrlCArmed || app.transcript.notice != "" {
		t.Fatalf("keystroke did not clear hint: armed=%v notice=%q", app.ctrlCArmed, app.transcript.notice)
	}

	clk.advance(200 * time.Millisecond)
	pressCtrlC(app)
	if ctrl.finishCalled {
		t.Fatal("CTRL-C exited after the window was disarmed by a keystroke, want fresh first press")
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events, want 0", len(evs))
	}
}

// TestCtrlC_HintTimeoutClears asserts the scheduled timeout clears the hint when no
// further key arrives, and that a stale timer from a superseded hint is ignored by
// the generation guard (step 4).
func TestCtrlC_HintTimeoutClears(t *testing.T) {
	a := New(nil)
	_, timers := installFakeCtrlCClock(a)

	pressCtrlC(a) // arms hint, schedules timers[0] (gen 1)
	if len(*timers) != 1 {
		t.Fatalf("scheduled %d timers, want 1", len(*timers))
	}

	// Clear via keystroke, then re-arm: timers[1] belongs to the new generation.
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone))
	pressCtrlC(a)
	if len(*timers) != 2 {
		t.Fatalf("scheduled %d timers after re-arm, want 2", len(*timers))
	}

	// Fire the stale timer (timers[0]); the generation guard must ignore it.
	(*timers)[0]()
	if !a.ctrlCArmed || a.transcript.notice != ctrlCHintText {
		t.Fatalf("stale timer cleared a live hint: armed=%v notice=%q", a.ctrlCArmed, a.transcript.notice)
	}

	// Fire the live timer (timers[1]); it must clear the current hint.
	(*timers)[1]()
	if a.ctrlCArmed || a.transcript.notice != "" {
		t.Fatalf("live timer did not clear hint: armed=%v notice=%q", a.ctrlCArmed, a.transcript.notice)
	}
}

// TestCtrlC_Consumed asserts the global capture consumes CTRL-C (returns nil) in
// the streaming, input-clear, and hint branches, so it never reaches the focused
// input area as a stray keystroke.
func TestCtrlC_Consumed(t *testing.T) {
	a := New(nil)
	installFakeCtrlCClock(a)
	store := escTestStore()
	a.SetActiveStore(store)
	a.SetStreamCanceller(&fakeStreamCanceller{retained: 2, inFlight: true})
	a.SetCommandFlush(func() error { return nil })
	a.AppendStreamDelta("partial")

	if got := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)); got != nil {
		t.Errorf("streaming CTRL-C returned %v, want nil (consumed)", got)
	}
	a.input.SetText("draft")
	if got := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)); got != nil {
		t.Errorf("input-clear CTRL-C returned %v, want nil (consumed)", got)
	}
	if got := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)); got != nil {
		t.Errorf("hint CTRL-C returned %v, want nil (consumed)", got)
	}
}

// TestCtrlC_NoSubmitHook_Inert asserts the double-empty exit path is inert when no
// submit hook is installed (New(nil) / pre-SetSubmit), so CTRL-C cannot panic
// before the dispatch wiring lands.
func TestCtrlC_NoSubmitHook_Inert(t *testing.T) {
	a := New(nil)
	clk, _ := installFakeCtrlCClock(a)

	pressCtrlC(a)
	clk.advance(100 * time.Millisecond)
	pressCtrlC(a) // would dispatch "exit" if a hook were installed; must not panic
}
