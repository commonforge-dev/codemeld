// Tests for transcript scrollback: follow-mode state, the scroll
// primitives' offset preservation while scrolled up and auto-follow re-enable at
// the bottom, and the mouse-wheel / keyboard event routing that drives them.
package tui

import (
	"fmt"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// fillTranscript appends n short committed lines so the content is taller than a
// small viewport, the precondition for any scrollback behavior.
func fillTranscript(tr *transcript, n int) {
	for i := 0; i < n; i++ {
		tr.append(fmt.Sprintf("line %d", i))
	}
}

// TestTranscript_DefaultsToFollowing pins the initial contract: a fresh transcript
// auto-follows, so existing append/stream auto-scroll behavior is unchanged when
// the user has not scrolled up.
func TestTranscript_DefaultsToFollowing(t *testing.T) {
	tr := newTranscript()
	if !tr.following {
		t.Fatal("newTranscript should start in follow mode")
	}
}

// TestTranscript_ScrollUpDisablesFollowAndPreservesOffset proves Done-when 3: while
// scrolled up (following=false), an appended/streamed line does not jerk the view to
// the bottom — the saved scroll offset is preserved across the re-render.
func TestTranscript_ScrollUpDisablesFollowAndPreservesOffset(t *testing.T) {
	const height = 5
	tr := newTranscript()
	fillTranscript(tr, 40)

	drawScrollRow(t, tr, height) // establishes geometry; ScrollToEnd pins the bottom
	tr.scrollBy(-10)             // scroll up toward older output
	if tr.following {
		t.Fatal("scrolling up did not disable auto-follow")
	}
	rowBefore := drawScrollRow(t, tr, height)

	// New output arrives while the user is reading older content.
	tr.appendDelta("streamed delta")
	rowAfter := drawScrollRow(t, tr, height)

	if rowAfter != rowBefore {
		t.Fatalf("scroll offset moved on append while not following: before=%d after=%d", rowBefore, rowAfter)
	}
	if tr.following {
		t.Fatal("auto-follow re-enabled by a streamed delta while scrolled up")
	}
}

// TestTranscript_CoalescedRenderMatchesPerDeltaRender proves deferring the render
// changes only how often it runs: buffering two deltas and rendering once produces the
// same visible text and the same pinned row as rendering on each delta did.
func TestTranscript_CoalescedRenderMatchesPerDeltaRender(t *testing.T) {
	const height = 5
	coalesced := newTranscript()
	fillTranscript(coalesced, 40)
	drawScrollRow(t, coalesced, height)
	coalesced.bufferDelta("streamed ")
	coalesced.bufferDelta("delta")
	coalesced.render()

	perDelta := newTranscript()
	fillTranscript(perDelta, 40)
	drawScrollRow(t, perDelta, height)
	perDelta.appendDelta("streamed ")
	perDelta.appendDelta("delta")

	if got, want := coalesced.view.GetText(true), perDelta.view.GetText(true); got != want {
		t.Fatalf("coalesced render text = %q, want %q", got, want)
	}
	if got, want := drawScrollRow(t, coalesced, height), drawScrollRow(t, perDelta, height); got != want {
		t.Fatalf("coalesced render pinned row %d, want %d", got, want)
	}
	if !coalesced.following {
		t.Fatal("a coalesced render dropped auto-follow")
	}
}

// TestTranscript_CoalescedRenderHoldsScrolledUpOffset proves the scrolled-up hold
// survives coalescing: a render carrying several buffered deltas still restores the
// offset the reader left the view at instead of pulling it to the bottom.
func TestTranscript_CoalescedRenderHoldsScrolledUpOffset(t *testing.T) {
	const height = 5
	tr := newTranscript()
	fillTranscript(tr, 40)
	drawScrollRow(t, tr, height)
	tr.scrollBy(-10)
	if tr.following {
		t.Fatal("precondition: scrolling up did not disable auto-follow")
	}
	rowBefore := drawScrollRow(t, tr, height)

	tr.bufferDelta("streamed ")
	tr.bufferDelta("delta")
	tr.render()

	if rowAfter := drawScrollRow(t, tr, height); rowAfter != rowBefore {
		t.Fatalf("coalesced render moved a held offset: before=%d after=%d", rowBefore, rowAfter)
	}
	if tr.following {
		t.Fatal("a coalesced render re-enabled auto-follow while scrolled up")
	}
}

// TestTranscript_SelectionSurvivesBufferingAndClearsOnRender proves the coalesced path
// keeps renderLocked's selection invalidation exactly where it was — on the render that
// changes the displayed text — while an accumulated delta that changes nothing visible
// leaves a live selection alone.
func TestTranscript_SelectionSurvivesBufferingAndClearsOnRender(t *testing.T) {
	tr := newTranscript()
	fillTranscript(tr, 5)
	tr.selecting, tr.selAnchor, tr.selStart, tr.selEnd = true, 2, 2, 6

	tr.bufferDelta("streamed delta")

	if !tr.selecting || tr.selStart != 2 || tr.selEnd != 6 {
		t.Fatalf("buffering a delta cleared the selection: selecting=%v range=%d..%d", tr.selecting, tr.selStart, tr.selEnd)
	}

	tr.render()

	if tr.selecting || tr.selStart != 0 || tr.selEnd != 0 {
		t.Fatalf("coalesced render kept a stale selection: selecting=%v range=%d..%d", tr.selecting, tr.selStart, tr.selEnd)
	}
}

// TestTranscript_ScrollToBottomReEnablesFollow proves Done-when 4: scrolling back to
// the last row flips following true again and a subsequent append scrolls to end.
func TestTranscript_ScrollToBottomReEnablesFollow(t *testing.T) {
	const height = 5
	tr := newTranscript()
	fillTranscript(tr, 40)

	drawScrollRow(t, tr, height)
	tr.scrollBy(-10)
	drawScrollRow(t, tr, height)
	if tr.following {
		t.Fatal("precondition: should not be following after scrolling up")
	}

	// A large downward scroll lands at the bottom and resumes auto-follow.
	tr.scrollBy(1000)
	if !tr.following {
		t.Fatal("scrolling to the last row did not re-enable auto-follow")
	}

	// 41 committed lines render as 81 rows (41 lines + 40 blank separators); a fresh
	// append must pin the bottom again now that follow resumed.
	tr.append("newest")
	const totalRows = 41 + 40
	if row := drawScrollRow(t, tr, height); row != totalRows-height {
		t.Fatalf("append after re-follow scrolled to row %d, want %d (ScrollToEnd did not resume)", row, totalRows-height)
	}
}

// TestTranscript_ScrollPageUsesViewportHeight proves PageUp/PageDown move by about a
// viewport height (minus one row of context) and re-follow at the bottom.
func TestTranscript_ScrollPageUsesViewportHeight(t *testing.T) {
	const height = 5
	tr := newTranscript()
	fillTranscript(tr, 40)
	drawScrollRow(t, tr, height) // bottom = row 74 (79 rows - 5)

	tr.scrollPage(-1) // one page up: step = height-1 = 4
	if row, _ := tr.view.GetScrollOffset(); row != 74-(height-1) {
		t.Fatalf("page up offset = %d, want %d", row, 74-(height-1))
	}
	if tr.following {
		t.Fatal("page up did not disable auto-follow")
	}

	tr.scrollPage(1) // one page down returns to the bottom and re-follows
	if !tr.following {
		t.Fatal("page down to the bottom did not re-enable auto-follow")
	}
}

// drawAppTranscript draws the app's transcript view at a fixed size so the wheel /
// key routing tests have real geometry (offset clamping, bottom detection) and the
// InRect check has a populated rect.
func drawAppTranscript(t *testing.T, a *App, height int) {
	t.Helper()
	drawScrollRow(t, a.transcript, height)
}

// TestHandleTranscriptMouse_WheelScrollsWhenOverTranscript proves a wheel notch over
// the transcript scrolls it (up disables follow) and is consumed, while a wheel
// outside the transcript rect is passed through untouched.
func TestHandleTranscriptMouse_WheelScrollsWhenOverTranscript(t *testing.T) {
	const height = 5
	a := New(nil)
	fillTranscript(a.transcript, 40)
	drawAppTranscript(t, a, height)

	// Wheel up with the cursor inside the transcript rect (0,0,40,5).
	if a.app.GetFocus() != a.input {
		t.Fatalf("precondition: focus = %T, want the input", a.app.GetFocus())
	}
	over := tcell.NewEventMouse(1, 1, tcell.WheelUp, tcell.ModNone)
	action, event := a.handleTranscriptMouse(tview.MouseScrollUp, over)
	if action != tview.MouseConsumed || event != nil {
		t.Fatalf("wheel over transcript = (%v,%v), want (MouseConsumed,nil)", action, event)
	}
	if a.transcript.following {
		t.Fatal("wheel up over the transcript did not disable auto-follow")
	}
	// Scrolling must not steal keyboard focus from the input: keyboard input
	// has to keep working without a mouse re-click after a wheel scroll.
	if a.app.GetFocus() != a.input {
		t.Fatalf("after a wheel scroll, focus = %T, want the input to stay focused", a.app.GetFocus())
	}

	// Reset and verify a wheel outside the transcript rect is not consumed and does
	// not change follow state.
	a.transcript.scrollBy(1000) // back to bottom, following=true
	outside := tcell.NewEventMouse(1, 100, tcell.WheelUp, tcell.ModNone)
	action, event = a.handleTranscriptMouse(tview.MouseScrollUp, outside)
	if action != tview.MouseScrollUp || event != outside {
		t.Fatalf("wheel outside transcript = (%v,%v), want it passed through unchanged", action, event)
	}
	if !a.transcript.following {
		t.Fatal("a wheel outside the transcript changed follow state")
	}
}

// TestTranscriptMouseCapture_WiredThroughInstalledHandler proves the wheel reaches
// the transcript through the MouseHandler that New installs via SetMouseCapture, not
// only through a direct handleTranscriptMouse call. Removing the
// a.transcript.view.SetMouseCapture(a.handleTranscriptMouse) registration in New makes
// this fail: tview's default TextView wheel handler would not flip follow-mode off, so
// the follow state would not survive a live wheel notch.
func TestTranscriptMouseCapture_WiredThroughInstalledHandler(t *testing.T) {
	const height = 5
	a := New(nil)
	fillTranscript(a.transcript, 40)
	drawAppTranscript(t, a, height) // draws the transcript at rect (0,0,40,5)

	handler := a.transcript.view.MouseHandler()
	if handler == nil {
		t.Fatal("transcript view has no installed mouse handler")
	}

	// Wheel up inside the transcript rect, delivered through the installed handler.
	over := tcell.NewEventMouse(1, 1, tcell.WheelUp, tcell.ModNone)
	consumed, _ := handler(tview.MouseScrollUp, over, func(tview.Primitive) {})
	if !consumed {
		t.Fatal("installed transcript mouse handler did not consume a wheel-up over the transcript (SetMouseCapture not wired?)")
	}
	if a.transcript.following {
		t.Fatal("wheel-up through the installed handler did not disable auto-follow (SetMouseCapture not wired?)")
	}
}

// TestHandleAppMouse_AboveInputClickKeepsFocus proves the click shield: a plain left-click above
// the input row, while no overlay is open, is dropped (a nil event) by the app-level
// mouse capture and leaves the input focused. Without this capture tview routes the
// click to the clicked row's Box, whose default handler calls setFocus on it and
// drops the input cursor. The input rect is set explicitly so the above/inside-input
// boundary is deterministic without a full draw.
func TestHandleAppMouse_AboveInputClickKeepsFocus(t *testing.T) {
	a := New(nil)
	a.input.SetRect(0, 10, 40, 3) // input occupies rows 10..12

	if a.app.GetFocus() != a.input {
		t.Fatalf("precondition: focus = %T, want the input", a.app.GetFocus())
	}

	// Left-down on a chrome row above the input (e.g. the banner-gap spacer at row 9).
	above := tcell.NewEventMouse(5, 9, tcell.Button1, tcell.ModNone)
	event, action := a.handleAppMouse(above, tview.MouseLeftDown)
	if event != nil {
		t.Fatalf("above-input click returned event %v, want nil (dropped before routing)", event)
	}
	if action != tview.MouseLeftDown {
		t.Fatalf("above-input click returned action %v, want it unchanged", action)
	}
	if a.app.GetFocus() != a.input {
		t.Fatalf("after an above-input click, focus = %T, want the input to stay focused", a.app.GetFocus())
	}
}

// TestHandleAppMouse_FocusGuards proves the app capture's guards: a plain click on the
// input row is consumed by the app-owned input path, and while an overlay is open any
// click is passed through unchanged so the overlay's own focus rules are preserved.
func TestHandleAppMouse_FocusGuards(t *testing.T) {
	t.Run("plain click on the input row is handled", func(t *testing.T) {
		a := New(nil)
		a.input.SetRect(0, 10, 40, 3)
		inside := tcell.NewEventMouse(5, 11, tcell.Button1, tcell.ModNone)
		event, action := a.handleAppMouse(inside, tview.MouseLeftDown)
		if event != nil || action != tview.MouseLeftDown {
			t.Fatalf("input-row click = (%v,%v), want it consumed unchanged", event, action)
		}
	})

	t.Run("click passes through while an overlay is open", func(t *testing.T) {
		a := New(nil)
		a.input.SetRect(0, 10, 40, 3)
		a.panelOpen = true // simulate an open overlay
		above := tcell.NewEventMouse(5, 9, tcell.Button1, tcell.ModNone)
		event, action := a.handleAppMouse(above, tview.MouseLeftDown)
		if event != above || action != tview.MouseLeftDown {
			t.Fatalf("click while overlay open = (%v,%v), want it passed through unchanged", event, action)
		}
	})

	t.Run("wheel passes through to the transcript capture", func(t *testing.T) {
		a := New(nil)
		a.input.SetRect(0, 10, 40, 3)
		wheel := tcell.NewEventMouse(5, 1, tcell.WheelUp, tcell.ModNone)
		event, action := a.handleAppMouse(wheel, tview.MouseScrollUp)
		if event != wheel || action != tview.MouseScrollUp {
			t.Fatalf("wheel = (%v,%v), want it passed through unchanged for the transcript capture", event, action)
		}
	})
}

// TestAppMouse_SpacerRowClickKeepsFocus_ThroughRealLayout proves the click shield end to end: a
// left-click on the banner-gap spacer row directly above the input — a row the
// transcript's own mouse capture never sees — is routed through the real app/Flex
// mouse path and must leave the input focused. Without the installed app-level capture
// the spacer Box's default handler would setFocus the spacer and drop the input cursor,
// the exact regression the round-2 review flagged.
func TestAppMouse_SpacerRowClickKeepsFocus_ThroughRealLayout(t *testing.T) {
	h := newLayoutHarness(t, 80, 25)
	defer h.stop()

	var spacerY int
	var focusBefore tview.Primitive
	h.a.app.QueueUpdate(func() {
		_, iy, _, _ := h.a.input.GetRect()
		spacerY = iy - 1 // the one fixed banner-gap row immediately above the input
		focusBefore = h.a.app.GetFocus()
	})
	if focusBefore != h.a.input {
		t.Fatalf("precondition: focus = %T, want the input", focusBefore)
	}

	h.injectMouse(2, spacerY, tcell.Button1)

	var focusAfter tview.Primitive
	h.a.app.QueueUpdate(func() { focusAfter = h.a.app.GetFocus() })
	if focusAfter != h.a.input {
		t.Fatalf("after a click on the spacer row above the input, focus = %T, want the input to stay focused", focusAfter)
	}
}

// TestHandleGlobalKey_TranscriptScrollKeys proves the keyboard routing: PageUp and
// Shift+Up scroll the transcript (and are consumed), bare Up/Down pass through to
// input-history navigation, and the scroll keys pass through while an overlay is open.
func TestHandleGlobalKey_TranscriptScrollKeys(t *testing.T) {
	const height = 5

	// PageUp and Shift+Up are the two transcript-scroll chords: each scrolls the
	// transcript off the bottom, is consumed (returns nil), and leaves the input
	// focused so keyboard input keeps working without a mouse re-click.
	for _, tc := range []struct {
		name  string
		event *tcell.EventKey
	}{
		{"PageUp scrolls and is consumed", tcell.NewEventKey(tcell.KeyPgUp, 0, tcell.ModNone)},
		{"Shift+Up scrolls one line", tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModShift)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			fillTranscript(a.transcript, 40)
			drawAppTranscript(t, a, height)
			if a.app.GetFocus() != a.input {
				t.Fatalf("precondition: focus = %T, want the input", a.app.GetFocus())
			}
			if ev := a.handleGlobalKey(tc.event); ev != nil {
				t.Fatalf("%s returned %v, want nil (consumed)", tc.name, ev)
			}
			if a.transcript.following {
				t.Fatalf("%s did not scroll the transcript off the bottom", tc.name)
			}
			if a.app.GetFocus() != a.input {
				t.Fatalf("after %s, focus = %T, want the input to stay focused", tc.name, a.app.GetFocus())
			}
		})
	}

	t.Run("bare Up/Down pass through to input history", func(t *testing.T) {
		a := New(nil)
		fillTranscript(a.transcript, 40)
		drawAppTranscript(t, a, height)
		for _, k := range []tcell.Key{tcell.KeyUp, tcell.KeyDown} {
			if ev := a.handleGlobalKey(tcell.NewEventKey(k, 0, tcell.ModNone)); ev == nil {
				t.Fatalf("bare %v was consumed by handleGlobalKey, want it passed through to input history", k)
			}
		}
		if !a.transcript.following {
			t.Fatal("bare Up/Down scrolled the transcript; they must reach input history instead")
		}
	})

	t.Run("scroll keys pass through while an overlay is open", func(t *testing.T) {
		a := New(nil)
		fillTranscript(a.transcript, 40)
		drawAppTranscript(t, a, height)
		a.panelOpen = true // simulate an open overlay
		if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyPgUp, 0, tcell.ModNone)); ev == nil {
			t.Fatal("PageUp was consumed while an overlay is open; the overlay must keep the key")
		}
		if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModShift)); ev == nil {
			t.Fatal("Shift+Up was consumed while an overlay is open; the overlay must keep the key")
		}
		if !a.transcript.following {
			t.Fatal("transcript scrolled while an overlay is open")
		}
	})
}
