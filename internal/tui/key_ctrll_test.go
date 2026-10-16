// Tests for CTRL-L screen repaint: the app-level key path
// requests exactly one repaint through the injected draw seam, mutates no input
// or transcript state, and leaves an open overlay open and focused — all driven
// through a fake draw seam so no live terminal is needed.
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
)

// pressCtrlL drives the app-level global-key capture as if CTRL-L were pressed and
// returns the event the dispatcher passed back (nil == consumed).
func pressCtrlL(a *App) *tcell.EventKey {
	return a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlL, 0, tcell.ModNone))
}

func TestCtrlL_RequestsRepaintThroughAppKeyPath(t *testing.T) {
	a := New(nil)
	draws := 0
	a.draw = func() { draws++ }

	if ev := pressCtrlL(a); ev != nil {
		t.Errorf("handleGlobalKey returned %v for CTRL-L, want nil (consumed)", ev)
	}
	if draws != 1 {
		t.Errorf("draw seam called %d times, want exactly 1", draws)
	}
}

func TestCtrlL_PreservesOpenOverlay(t *testing.T) {
	a := New(nil)
	draws := 0
	a.draw = func() { draws++ }

	// An overlay holds the screen: CTRL-L must repaint without dismissing it.
	a.statusOpen = true
	prevFocus := a.app.GetFocus()

	if ev := pressCtrlL(a); ev != nil {
		t.Errorf("handleGlobalKey returned %v for CTRL-L with overlay open, want nil", ev)
	}
	if draws != 1 {
		t.Errorf("draw seam called %d times, want exactly 1", draws)
	}
	if !a.statusOpen {
		t.Error("statusOpen = false after CTRL-L; overlay must stay open")
	}
	if !a.anyOverlayOpen() {
		t.Error("anyOverlayOpen() = false after CTRL-L; open overlay must be preserved")
	}
	if a.app.GetFocus() != prevFocus {
		t.Error("CTRL-L changed focus; it must not touch focus state")
	}
}

// TestCtrlL_PreservesArmedCtrlCHint asserts CTRL-L repaints without clearing a
// pending "press Ctrl-C again to exit" hint: the repaint must not run the generic
// hint-clearing hooks, so the armed window and its notice survive.
func TestCtrlL_PreservesArmedCtrlCHint(t *testing.T) {
	a := New(nil)
	installFakeCtrlCClock(a)
	pressCtrlC(a) // empty buffer: arms the exit hint and shows its notice
	if !a.ctrlCArmed || a.transcript.notice != ctrlCHintText {
		t.Fatalf("setup: armed=%v notice=%q, want armed with hint", a.ctrlCArmed, a.transcript.notice)
	}

	draws := 0
	a.draw = func() { draws++ }

	if ev := pressCtrlL(a); ev != nil {
		t.Errorf("handleGlobalKey returned %v for CTRL-L, want nil (consumed)", ev)
	}
	if draws != 1 {
		t.Errorf("draw seam called %d times, want exactly 1", draws)
	}
	if !a.ctrlCArmed || a.transcript.notice != ctrlCHintText {
		t.Errorf("CTRL-L cleared the armed CTRL-C hint: armed=%v notice=%q, want unchanged", a.ctrlCArmed, a.transcript.notice)
	}
}

// TestCtrlL_PreservesReverseSearchHint asserts CTRL-L repaints without clearing the
// empty-history CTRL-R hint: the repaint must not run clearReverseSearchHint, so the
// one-shot notice survives the repaint.
func TestCtrlL_PreservesReverseSearchHint(t *testing.T) {
	a := New(nil)
	a.showReverseSearchHint()
	if !a.reverseSearchHintShown || a.transcript.notice != reverseSearchEmptyHint {
		t.Fatalf("setup: shown=%v notice=%q, want hint shown", a.reverseSearchHintShown, a.transcript.notice)
	}

	draws := 0
	a.draw = func() { draws++ }

	if ev := pressCtrlL(a); ev != nil {
		t.Errorf("handleGlobalKey returned %v for CTRL-L, want nil (consumed)", ev)
	}
	if draws != 1 {
		t.Errorf("draw seam called %d times, want exactly 1", draws)
	}
	if !a.reverseSearchHintShown || a.transcript.notice != reverseSearchEmptyHint {
		t.Errorf("CTRL-L cleared the empty-history CTRL-R hint: shown=%v notice=%q, want unchanged", a.reverseSearchHintShown, a.transcript.notice)
	}
}

func TestCtrlL_DoesNotMutateInputOrTranscript(t *testing.T) {
	a := New(nil)
	a.draw = func() {}
	a.input.SetText("draft prompt")
	a.Append("line one")
	a.Notice("a notice")

	pressCtrlL(a)

	if got := a.input.GetText(); got != "draft prompt" {
		t.Errorf("input text = %q after CTRL-L, want unchanged %q", got, "draft prompt")
	}
	if a.transcript.notice != "a notice" {
		t.Errorf("notice = %q after CTRL-L, want unchanged %q", a.transcript.notice, "a notice")
	}
}
