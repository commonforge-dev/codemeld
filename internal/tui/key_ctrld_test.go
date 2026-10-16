// Tests for the CTRL-D exit shortcut: empty-buffer exit delegation
// through the /exit handler with event-before-flush ordering, the non-empty
// no-op, and the second-failure exit-code propagation.
package tui

import (
	"errors"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// ctrlDApp builds an App whose submit hook dispatches through a registry binding
// /exit (and its bare synonym) to ctrl, mirroring the production wiring
// (BuildRegistry + NewSubmitFunc). It returns the app and the fake host
// whose store the appended slash_command events are read back from. A nil prompt
// entrypoint is fine: CTRL-D only ever dispatches the bare `exit` synonym, never
// plain prompt text.
func ctrlDApp(t *testing.T, ctrl ExitController) (*App, *fakeHost) {
	t.Helper()
	host := newFakeHost()
	reg := exitRegistry(t, ctrl)
	app := New(nil)
	app.SetSubmit(NewSubmitFunc(reg, host, nil))
	return app, host
}

// pressCtrlD drives the app-level global-key capture with a CTRL-D event, exactly
// as the live tview event loop would.
func pressCtrlD(a *App) {
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlD, 0, tcell.ModNone))
}

// TestCtrlD_EmptyBuffer_ExitsViaCleanShutdown asserts CTRL-D on an empty buffer
// runs the /exit clean-exit sequence: the canonical slash_command{name:"exit"} event
// is recorded and Finish exits 0 with the resume hint.
func TestCtrlD_EmptyBuffer_ExitsViaCleanShutdown(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-d"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store

	pressCtrlD(app)

	if !ctrl.finishCalled || ctrl.finishCode != 0 {
		t.Fatalf("Finish(code=%d, called=%v), want code 0", ctrl.finishCode, ctrl.finishCalled)
	}
	if want := ResumeHint("sess-d"); ctrl.finishHint != want {
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

// TestCtrlD_EmptyBuffer_EventBeforeFlush asserts the slash_command event is in the
// in-memory stream before the clean-shutdown flush runs, i.e. CTRL-D reuses /exit's
// step-1-before-step-2 ordering rather than appending the event itself.
func TestCtrlD_EmptyBuffer_EventBeforeFlush(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-d"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store

	pressCtrlD(app)

	if ctrl.flushCalls != 1 {
		t.Fatalf("FlushOnExit called %d times, want 1", ctrl.flushCalls)
	}
	if ctrl.slashEventsAtFlush != 1 {
		t.Errorf("slash_command events present at flush = %d, want 1 (event must precede the flush)", ctrl.slashEventsAtFlush)
	}
}

// TestCtrlD_EmptyBuffer_SecondFailureExitsOne asserts the second-failure exit path: when the
// clean-shutdown flush fails after retry, CTRL-D exits 1 with no resume hint, with
// the event still recorded (lost only because the write never lands).
func TestCtrlD_EmptyBuffer_SecondFailureExitsOne(t *testing.T) {
	flushErr := errors.New("session write failed on exit after retry")
	ctrl := &fakeExitController{sessionID: "sess-d", flushErr: flushErr}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store

	pressCtrlD(app)

	if !ctrl.finishCalled || ctrl.finishCode != 1 {
		t.Fatalf("Finish(code=%d, called=%v), want code 1", ctrl.finishCode, ctrl.finishCalled)
	}
	if ctrl.finishHint != "" {
		t.Errorf("Finish hint = %q, want empty on the second-failure path (req 400a)", ctrl.finishHint)
	}
	if evs := host.events(); len(evs) != 1 {
		t.Errorf("appended %d slash_command events, want 1", len(evs))
	}
}

// TestCtrlD_NonEmptyBuffer_NoOp asserts CTRL-D with typed input is a no-op: the
// input is unchanged and no event, flush, notice, or shutdown request occurs.
func TestCtrlD_NonEmptyBuffer_NoOp(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-d"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	app.input.SetText("draft prompt")

	pressCtrlD(app)

	if got := app.input.GetText(); got != "draft prompt" {
		t.Errorf("input buffer = %q, want unchanged %q", got, "draft prompt")
	}
	if ctrl.finishCalled {
		t.Error("Finish called on non-empty buffer, want no shutdown request")
	}
	if ctrl.flushCalls != 0 {
		t.Errorf("FlushOnExit called %d times, want 0 on non-empty buffer", ctrl.flushCalls)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events, want 0 on non-empty buffer", len(evs))
	}
	if len(host.notices) != 0 {
		t.Errorf("rendered notices %v, want none on non-empty buffer", host.notices)
	}
}

func TestCtrlD_OverlayOpen_NoExit(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-d"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store
	app.ShowPanel("help")

	pressCtrlD(app)

	if ctrl.finishCalled {
		t.Fatal("Finish called while overlay was open, want CTRL-D consumed as no-op")
	}
	if !app.panelOpen {
		t.Fatal("panel closed after CTRL-D; overlay should stay open")
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("appended %d slash_command events, want 0 while overlay is open", len(evs))
	}
}

// TestCtrlD_NoSubmitHook_Inert asserts the empty-buffer path is inert when no
// submit hook is installed (New(nil) / pre-SetSubmit), so CTRL-D cannot panic or
// half-exit before the dispatch wiring lands.
func TestCtrlD_NoSubmitHook_Inert(t *testing.T) {
	app := New(nil)
	pressCtrlD(app) // must not panic
}

// TestCtrlD_Consumed asserts the global capture consumes CTRL-D (returns nil) in
// both the empty-exit and non-empty no-op cases, so it never reaches the focused
// input area as a stray keystroke.
func TestCtrlD_Consumed(t *testing.T) {
	ctrl := &fakeExitController{sessionID: "sess-d"}
	app, host := ctrlDApp(t, ctrl)
	ctrl.store = host.store

	if got := app.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlD, 0, tcell.ModNone)); got != nil {
		t.Errorf("empty-buffer CTRL-D returned %v, want nil (consumed)", got)
	}

	app.input.SetText("x")
	if got := app.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlD, 0, tcell.ModNone)); got != nil {
		t.Errorf("non-empty CTRL-D returned %v, want nil (consumed)", got)
	}
}
