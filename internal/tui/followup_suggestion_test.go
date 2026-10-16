// Tests for the follow-up suggestion ghost text: rendering it as dim, Tab-cued
// placeholder in the empty input, accepting it on Tab, and clearing it on any edit/submit.
// The SuggestFollowup surface seam exercised here is the real production method
// bootstrap binds onto turn.Deps (turndeps.go), so these drive the same entrypoint a real
// suggest_followup tool call reaches — paired with the mandatory real-terminal check noted
// in the withheld task notes.
package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// TestInputField_GhostTextRendersDimWithTabCue proves SuggestFollowup's ghost text renders
// in the empty input with the theme-independent "⇥ Tab:" cue (so the affordance reads even
// without dim support) and with the dim grey style. The input is drawn
// on a simulation screen and the rendered cells are read back, since the native placeholder
// only paints during Draw.
func TestInputField_GhostTextRendersDimWithTabCue(t *testing.T) {
	in := newInput()
	in.SetGhostText("write the tests")
	if got := in.ghost; got != "write the tests" {
		t.Fatalf("ghost = %q, want the raw (unprefixed) label", got)
	}

	screen := drawPrimitive(t, in, 40, 5)

	// The custom draw func returns the rows between the top/bottom rules as the inner rect,
	// so the prompt + placeholder land on row 1; the "> " label takes the first two columns.
	cells, width, _ := screen.GetContents()
	var row1 strings.Builder
	var cueFound bool
	var cueStyle tcell.Style
	for col := 0; col < width; col++ {
		c := cells[1*width+col]
		if len(c.Runes) == 0 {
			continue
		}
		row1.WriteString(string(c.Runes))
		if string(c.Runes) == "⇥" {
			cueFound = true
			cueStyle = c.Style
		}
	}
	if want := "⇥ Tab: write the tests"; !strings.Contains(row1.String(), want) {
		t.Fatalf("input row = %q, want it to contain the cued ghost text %q", row1.String(), want)
	}
	if !cueFound {
		t.Fatal("ghost text cue glyph ⇥ not rendered")
	}
	fg, _, attr := cueStyle.Decompose()
	if fg != ghostTextColor {
		t.Errorf("ghost text foreground = %v, want the dim accent %v", fg, ghostTextColor)
	}
	if attr&tcell.AttrDim == 0 {
		t.Error("ghost text is not drawn with the dim attribute")
	}
}

// TestInputField_GhostTextHiddenOnceBufferNonEmpty proves the ghost text never renders over
// real input: with text in the buffer the native placeholder is suppressed, so a draft
// always wins over a stale suggestion.
func TestInputField_GhostTextHiddenOnceBufferNonEmpty(t *testing.T) {
	in := newInput()
	in.SetGhostText("write the tests")
	// A direct buffer change goes through newInput's change wrapper, which clears the ghost.
	in.TextArea.SetText("hi", true)
	if got := in.ghost; got != "" {
		t.Fatalf("ghost = %q after a buffer change, want it cleared", got)
	}

	screen := drawPrimitive(t, in, 40, 5)
	if strings.Contains(screenText(screen), "Tab:") {
		t.Error("ghost text rendered while the buffer is non-empty; the draft must win")
	}
}

// TestApp_SuggestFollowup_TabAcceptsFillsPromptAndClears pins the accept path through the
// real surface seam and the real Tab key handler: SuggestFollowup stores the prompt and
// shows the label, then Tab fills the buffer with the prompt (ready to send) and clears both
// the ghost text and the pending state.
func TestApp_SuggestFollowup_TabAcceptsFillsPromptAndClears(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	if a.pendingFollowup != "Write unit tests for the parser" {
		t.Fatalf("pendingFollowup = %q, want the stored prompt", a.pendingFollowup)
	}
	if a.input.ghost != "write the tests" {
		t.Fatalf("ghost = %q, want the stored label", a.input.ghost)
	}

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "Write unit tests for the parser" {
		t.Fatalf("after Tab the buffer = %q, want the accepted prompt", got)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost text not cleared after acceptance: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup not cleared after acceptance: %q", a.pendingFollowup)
	}
}

// TestApp_SuggestFollowup_NoSuggestionTabStillCompletes proves the precedence rule's
// fallback: with no suggestion pending, Tab runs slash-name completion exactly as before
// (the new suggestion-first branch is skipped).
func TestApp_SuggestFollowup_NoSuggestionTabStillCompletes(t *testing.T) {
	a := New(nil)
	a.SetRegistry(tabTestRegistry(t))
	if a.pendingFollowup != "" {
		t.Fatalf("pendingFollowup = %q at construction, want empty", a.pendingFollowup)
	}

	a.input.SetText("/eff")
	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "/effort " {
		t.Fatalf("Tab with no suggestion = %q, want slash-name completion to %q", got, "/effort ")
	}
}

// TestApp_SuggestFollowup_ClearedByTyping proves any ordinary typed rune discards a pending
// suggestion (no stale ghost text), via the change-hook path the architecture review called
// out (typed runes reach onInputChanged, not handleInputKey).
func TestApp_SuggestFollowup_ClearedByTyping(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyRune, 'h', tcell.ModNone), func(tview.Primitive) {})

	if a.input.ghost != "" {
		t.Errorf("ghost text survived typing: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup survived typing: %q", a.pendingFollowup)
	}
	if got := a.input.GetText(); got != "h" {
		t.Fatalf("buffer after typing = %q, want %q", got, "h")
	}
}

// TestApp_SuggestFollowup_ClearedByEmptyEnter proves a submit keystroke discards a pending
// suggestion even when the buffer is empty: submitCurrent() returns false before any SetText
// fires the change hook, so without handleInputKey's explicit clear the ghost would survive a
// no-op Enter. Driven through the live input handler the production key path uses.
func TestApp_SuggestFollowup_ClearedByEmptyEnter(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if a.input.ghost != "" {
		t.Errorf("ghost text survived an empty Enter: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup survived an empty Enter: %q", a.pendingFollowup)
	}
}

// TestApp_SuggestFollowup_ClearedByDownNoHistory proves a consumed special key that changes
// no buffer still discards a pending suggestion: Down on the last line with no history
// navigation underway returns nil without a SetText, so the change hook never runs and only
// handleInputKey's explicit clear removes the stale ghost.
func TestApp_SuggestFollowup_ClearedByDownNoHistory(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")
	if a.history.navigating() {
		t.Fatal("history should not be navigating at construction")
	}

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "" {
		t.Fatalf("Down with no history changed the buffer to %q, want it untouched", got)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost text survived Down with no history: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup survived Down with no history: %q", a.pendingFollowup)
	}
}

// TestApp_SuggestFollowup_ClearedByEmptyKeyLeft proves a non-mutating input key discards a
// pending suggestion: KeyLeft on an empty buffer reaches handleInputKey's default path and
// changes nothing, so the onInputChanged change hook never fires and only the blanket clear
// for non-Tab keys removes the stale ghost. Driven through the live
// input handler the production key path uses.
func TestApp_SuggestFollowup_ClearedByEmptyKeyLeft(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyLeft, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "" {
		t.Fatalf("KeyLeft changed the empty buffer to %q, want it untouched", got)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost text survived an empty-buffer KeyLeft: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup survived an empty-buffer KeyLeft: %q", a.pendingFollowup)
	}
}

// TestApp_SuggestFollowup_ClearedByEmptyBackspace proves Backspace on an empty buffer — which
// mutates nothing, so the change hook never fires — still discards a pending suggestion via
// handleInputKey's blanket non-Tab clear.
func TestApp_SuggestFollowup_ClearedByEmptyBackspace(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyBackspace2, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "" {
		t.Fatalf("Backspace changed the empty buffer to %q, want it untouched", got)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost text survived an empty-buffer Backspace: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup survived an empty-buffer Backspace: %q", a.pendingFollowup)
	}
}

// TestApp_SuggestFollowup_ClearedByEmptyEscape proves a consumed global shortcut discards a
// pending suggestion: empty-buffer Escape reaches handleGlobalKey, which consumes it and runs
// HandleEsc (a no-op on an empty buffer with no stream/overlay), so without handleGlobalKey's
// blanket non-Tab clear the ghost would survive. Driven through the
// production app-level capture.
func TestApp_SuggestFollowup_ClearedByEmptyEscape(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)); ev != nil {
		t.Fatalf("Escape not consumed by handleGlobalKey: %v", ev)
	}

	if got := a.input.GetText(); got != "" {
		t.Fatalf("Escape changed the empty buffer to %q, want it untouched", got)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost text survived an empty-buffer Escape: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup survived an empty-buffer Escape: %q", a.pendingFollowup)
	}
}

// TestApp_SuggestFollowup_ClearedByEmptyCtrlC proves the empty-buffer Ctrl-C path — which arms
// the "press again to exit" hint without touching the input buffer — still discards a pending
// suggestion via handleGlobalKey's blanket non-Tab clear. The manual
// clock seam keeps the armed hint's timeout from scheduling against the test app.
func TestApp_SuggestFollowup_ClearedByEmptyCtrlC(t *testing.T) {
	a := New(nil)
	installFakeCtrlCClock(a)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)); ev != nil {
		t.Fatalf("Ctrl-C not consumed by handleGlobalKey: %v", ev)
	}

	if got := a.input.GetText(); got != "" {
		t.Fatalf("Ctrl-C changed the empty buffer to %q, want it untouched", got)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost text survived an empty-buffer Ctrl-C: %q", a.input.ghost)
	}
	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup survived an empty-buffer Ctrl-C: %q", a.pendingFollowup)
	}
}

// TestApp_SuggestFollowup_EmptyPromptShowsNoCue proves a schema-valid call with a blank
// prompt renders no acceptance cue at all: pendingFollowup == "" is handleInputKey's "nothing
// pending" sentinel, so a stored empty prompt would paint a ⇥ Tab ghost that Tab can never
// accept or clear, and Tab would fall through to slash completion leaving the ghost stranded.
// SuggestFollowup must reject the blank prompt and leave no pending/ghost state.
func TestApp_SuggestFollowup_EmptyPromptShowsNoCue(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "")

	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup set from a blank prompt: %q", a.pendingFollowup)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost cue rendered for a blank prompt: %q", a.input.ghost)
	}

	// Tab must not strand a cue: with nothing pending it falls through to slash completion,
	// which is a no-op on an empty buffer and leaves no ghost behind.
	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if a.input.ghost != "" {
		t.Errorf("Tab left a stale ghost cue after a blank-prompt suggestion: %q", a.input.ghost)
	}
	if got := a.input.GetText(); got != "" {
		t.Errorf("Tab filled the buffer from a blank-prompt suggestion: %q", got)
	}
}

// TestApp_SuggestFollowup_EmptyPromptClearsPriorPending proves a later blank-prompt call drops
// an already-pending valid suggestion rather than leaving the previous cue on screen:
// the guard routes through clearPendingFollowup before returning.
func TestApp_SuggestFollowup_EmptyPromptClearsPriorPending(t *testing.T) {
	a := New(nil)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")
	if a.pendingFollowup == "" {
		t.Fatal("precondition: a valid suggestion should be pending")
	}

	a.SuggestFollowup("write the tests", "")

	if a.pendingFollowup != "" {
		t.Errorf("a blank-prompt call left the prior pending prompt: %q", a.pendingFollowup)
	}
	if a.input.ghost != "" {
		t.Errorf("a blank-prompt call left the prior ghost cue: %q", a.input.ghost)
	}
}

// TestApp_SuggestFollowup_NonEmptyDraftDropsSuggestion proves a suggestion arriving while the
// user already has a draft is dropped rather than armed behind it: the ghost
// only paints over an empty buffer, but a stored pendingFollowup would let Tab replace the
// draft with the hidden prompt before slash completion (app.go:1154). With "/eff" in the
// buffer, SuggestFollowup must leave no pending/ghost state and Tab must still complete the
// slash name to "/effort ".
func TestApp_SuggestFollowup_NonEmptyDraftDropsSuggestion(t *testing.T) {
	a := New(nil)
	a.SetRegistry(tabTestRegistry(t))
	a.input.SetText("/eff")

	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	if a.pendingFollowup != "" {
		t.Errorf("pendingFollowup armed behind a non-empty draft: %q", a.pendingFollowup)
	}
	if a.input.ghost != "" {
		t.Errorf("ghost cue set behind a non-empty draft: %q", a.input.ghost)
	}

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "/effort " {
		t.Fatalf("Tab over a non-empty draft = %q, want slash-name completion to %q", got, "/effort ")
	}
}

// TestApp_SuggestFollowup_RendersAndAcceptsInRunningApp is the end-to-end check on the real
// event loop: the production SuggestFollowup seam renders the cued ghost text onto the
// screen, and Tab through the live input handler fills the buffer with the prompt and clears
// the ghost. SimulationScreen tests cannot replace the mandatory real-terminal confirmation
// (recorded in the withheld task notes), but this drives the running app rather than a bare widget.
func TestApp_SuggestFollowup_RendersAndAcceptsInRunningApp(t *testing.T) {
	h := newAppHarness(t, 60, 12)
	defer h.stop()

	h.runDraw(func() {
		h.a.SuggestFollowup("write the tests", "Write unit tests for the parser")
	})
	if screen := readScreenSync(t, h.a, h.screen); !strings.Contains(screen, "⇥ Tab: write the tests") {
		t.Fatalf("running app screen missing the cued ghost text; got:\n%s", screen)
	}

	var got, ghost, pending string
	h.runDraw(func() {
		handler := h.a.input.InputHandler()
		handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})
		got = h.a.input.GetText()
		ghost = h.a.input.ghost
		pending = h.a.pendingFollowup
	})
	if got != "Write unit tests for the parser" {
		t.Fatalf("after Tab the buffer = %q, want the accepted prompt", got)
	}
	if ghost != "" || pending != "" {
		t.Errorf("acceptance left stale state: ghost=%q pending=%q", ghost, pending)
	}
}
