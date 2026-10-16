package tui

import (
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const inputDragScrollInterval = 75 * time.Millisecond

const codeCopyNotice = "Code block copied"

const responseCopyNotice = "Response copied"

// The terminal never acknowledges an OSC 52 write, so this notice reports only what
// codemeld detected while emitting — never that the terminal rejected the update.
const copyFailedNoticePrefix = "Could not copy: "

func (a *App) copyControlPayload(body string, response bool) {
	if err := a.input.copyToClipboard(body); err != nil {
		a.Notice(copyFailedNoticePrefix + err.Error())
		return
	}
	if response {
		a.Notice(responseCopyNotice)
		return
	}
	a.Notice(codeCopyNotice)
}

// clickRegion is one activatable control: the byte range it occupies in a view's
// stripped text, and the payload a completed click on it copies. The zero value means
// "no control" — a real region always spans at least one byte — so a view that has none
// armed, or a press that landed off every control, needs no separate flag. response
// marks a whole-reply copy control, which reports its own notice.
type clickRegion struct {
	start, end int
	payload    string
	response   bool
}

func (r clickRegion) armed() bool { return r.end > r.start }

// clickRegions holds one view's controls plus the press/release pair that gates
// activation: a control fires only when both ends of the click resolve to the same
// region, so a drag that starts or ends off it stays an ordinary selection. Regions are
// byte ranges rather than cell rects so a control wrapped across two rows still resolves.
type clickRegions struct {
	all         []clickRegion
	press, over clickRegion
}

// set installs the regions for the text now displayed and drops any press in flight, so
// a control can never fire against a payload from an earlier render.
func (c *clickRegions) set(all []clickRegion) {
	c.all = all
	c.press, c.over = clickRegion{}, clickRegion{}
}

// at resolves a byte offset to its region. onText is the view's verdict that the column
// landed on the row's own drawn text rather than the blank padding past its end, which
// wrapping puts one byte offset away from a control's first character.
func (c *clickRegions) at(off int, onText bool) clickRegion {
	if !onText {
		return clickRegion{}
	}
	for _, r := range c.all {
		if off >= r.start && off < r.end {
			return r
		}
	}
	return clickRegion{}
}

func (c *clickRegions) beginPress(r clickRegion) { c.press, c.over = r, r }

func (c *clickRegions) hover(r clickRegion) { c.over = r }

// pending reports the control a release would fire without consuming the press, so a
// caller can read which control it is alongside activate's payload.
func (c *clickRegions) pending() clickRegion {
	if !c.press.armed() || c.press != c.over {
		return clickRegion{}
	}
	return c.press
}

// activate consumes the press and reports the payload when press and release both
// resolved to the same control.
func (c *clickRegions) activate() (string, bool) {
	r := c.pending()
	c.press, c.over = clickRegion{}, clickRegion{}
	return r.payload, r.armed()
}

// transcriptWheelStep is how many wrapped rows one mouse-wheel notch scrolls the
// transcript, matching the few-lines-per-notch feel of a terminal pager.
const transcriptWheelStep = 3

// handleTranscriptMouse is the transcript view's mouse capture: a wheel notch over
// the transcript scrolls it (up toward older output, down toward newer) and is
// consumed so it does not also reach the default handler; every other action and
// any wheel outside the transcript rect is passed through unchanged so the
// input/chrome rows behave normally. Left-click focus preservation lives in
// the app-level handleAppMouse, which runs before tview routes the event
// here. It returns MouseConsumed with a nil event to signal a handled action that
// should trigger a redraw, per tview.Box.SetMouseCapture's contract.
func (a *App) handleTranscriptMouse(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
	if event == nil {
		return action, event
	}
	switch action {
	case tview.MouseScrollUp, tview.MouseScrollDown:
		if !a.transcript.view.InRect(event.Position()) {
			return action, event
		}
		if action == tview.MouseScrollUp {
			a.transcript.scrollBy(-transcriptWheelStep)
		} else {
			a.transcript.scrollBy(transcriptWheelStep)
		}
		return tview.MouseConsumed, nil
	}
	return action, event
}

func (a *App) handleAppMouse(event *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction) {
	if mouseDebugEnabled() {
		// Log every action (incl. hovers/moves) so a capture shows whether motion events
		// arrive and which pane the pointer is over — compare the press y to each rect
		// (CODEMELD_MOUSE_DEBUG; action 0=Move 1=LeftDown 2=LeftUp 3=LeftClick 13=WheelUp).
		x, y, btn := -1, -1, tcell.ButtonMask(0)
		if event != nil {
			x, y = event.Position()
			btn = event.Buttons()
		}
		ix, iy, iw, ih := a.input.GetRect()
		tx, ty, tw, th := a.transcript.view.GetRect()
		mouseDebugf("mouse action=%v x=%d y=%d btn=%d inputSel=%v transcriptSel=%v inputRect=(%d,%d,%d,%d) transcriptRect=(%d,%d,%d,%d)",
			action, x, y, btn, a.inputSelecting, a.transcript.isSelecting(), ix, iy, iw, ih, tx, ty, tw, th)
	}
	switch action {
	case tview.MouseMove:
		// Only the press is hit-tested against the question's options rect; once the
		// gesture is owned every move belongs to it wherever the pointer now is.
		if d := a.questionDrag(); d != nil && d.owned {
			if event != nil {
				x, y := event.Position()
				d.move(x, y)
			}
			return nil, action
		}
		if a.status.selecting {
			if event != nil {
				x, y := event.Position()
				a.statusRegions.hover(a.statusRegionAt(x, y))
				a.status.updateSelect(x, y)
			}
			return nil, action
		}
		// A move with the left button held while a transcript drag is active extends
		// the selection. fireMouseActions fires MouseMove before the button
		// up/down on the same event, so when the move consumes the event (nil) the
		// follow-up MouseLeftUp below sees a nil event and finalizes from the range
		// this move already set. A move with no drag in progress passes through.
		if a.transcript.isSelecting() {
			if event != nil {
				x, y := event.Position()
				// Resolve the control before the extension, which may scroll the pane and
				// move the text under the pointer.
				a.transcript.hoverControl(x, y)
				a.updateTranscriptSelection(x, y)
			}
			return nil, action
		}
		if a.inputSelecting {
			if event != nil {
				a.updateInputSelection(event.Position())
			}
			return nil, action
		}
		// Remember the last in-input position an active input drag passes through, so an
		// outside release can synthesize a valid inside-input release there. This
		// is only the Shift+drag native path; plain input drag is app-owned above.
		if a.inputDragging && event != nil {
			if x, y := event.Position(); a.inInputRect(x, y) {
				a.inputDragX, a.inputDragY = x, y
			}
		}
		return event, action
	case tview.MouseLeftDown:
		if event == nil {
			return event, action
		}
		if a.statusOpen {
			a.app.SetFocus(a.status)
			x, y := event.Position()
			// A press outside the panel takes no beginSelect, so it must still clear the
			// candidate — otherwise one left over from an earlier open fires on release.
			a.statusRegions.beginPress(a.statusRegionAt(x, y))
			if a.status.InRect(x, y) {
				a.status.beginSelect(x, y)
			}
			return nil, action
		}
		// Disarm here too: a drag whose release produced no click-class action at all would
		// otherwise leave the arming to swallow a later genuine click.
		if d := a.questionDrag(); d != nil {
			d.suppress = false
			qx, qy := event.Position()
			if event.Modifiers()&tcell.ModShift == 0 && d.begin(a.questionDragTarget(), qx, qy) {
				return nil, action
			}
		}
		if a.anyOverlayOpen() {
			return event, action
		}
		x, y := event.Position()
		if a.inInputRect(x, y) {
			if event.Modifiers()&tcell.ModShift != 0 {
				// Keep Shift+drag on TextArea's native path as the input escape hatch. The
				// app only tracks it enough to copy/collapse if release lands outside.
				a.inputDragging = true
				a.inputDragX, a.inputDragY = x, y
				return event, action
			}
			// Own plain input selection so it behaves like transcript selection even when
			// TextArea's native drag path only moves the cursor in a real terminal.
			a.beginInputSelection(x, y)
			return nil, action
		}
		// A Shift-modified left-press is left for the terminal's native selection
		// (Shift+drag stays the escape hatch where the terminal delivers it to
		// the app): pass it through unchanged so it is never captured into an app-owned
		// selection that would copy through OSC 52. With no beginSelect, isSelecting()
		// stays false, so the follow-up MouseMove/MouseLeftUp never finalize or copy.
		if event.Modifiers()&tcell.ModShift != 0 {
			return event, action
		}
		// Outside the transcript this clears any candidate left by an earlier press, the
		// same way the /status branch above does.
		a.transcript.pressControl(x, y)
		// A plain left-press inside the transcript starts an app-owned selection drag.
		// Focus stays on the input so keyboard entry keeps working without a
		// re-click, and the event is consumed so no primitive's
		// default handler runs.
		if a.transcript.view.InRect(x, y) {
			a.transcript.beginSelect(x, y)
			a.transcriptSelX, a.transcriptSelY = x, y
			a.transcriptScrollGen++
			a.transcriptScrollPending = false
		}
		a.app.SetFocus(a.input)
		return nil, action
	case tview.MouseLeftUp:
		// An owned release is answered before the nil-event guard below: a same-event move
		// consumes the event, so the release that ends a drag commonly carries no position
		// at all and the last move's range is what stands.
		if d := a.questionDrag(); d != nil && d.owned {
			if event != nil {
				x, y := event.Position()
				d.extend(x, y)
			}
			consumed, text := d.finish()
			if !consumed {
				// Pass the release on so tview still fires the click-class action, which is
				// what the option row acts on.
				return event, action
			}
			if text != "" {
				_ = a.input.copyToClipboard(text)
			}
			return nil, action
		}
		if a.status.selecting {
			// The same-event MouseMove above consumes the event, so a release commonly
			// arrives with a nil one and the last move's verdict is what stands.
			if event != nil {
				x, y := event.Position()
				a.statusRegions.hover(a.statusRegionAt(x, y))
				a.status.updateSelect(x, y)
			}
			if id, ok := a.statusRegions.activate(); ok {
				a.status.clearSelection()
				_ = a.input.copyToClipboard(id)
				a.Notice(statusCopyNotice)
				a.app.SetFocus(a.status)
				return nil, action
			}
			if text := a.status.endSelect(); text != "" {
				_ = a.input.copyToClipboard(text)
			}
			a.app.SetFocus(a.status)
			return nil, action
		}
		// Completing a transcript drag: extend to the release position (when the event
		// survived a same-event move), copy the selection through the input's OSC 52
		// clipboard path, and clear the range so the highlight does not linger past the
		// release (endSelect zeroes the offsets).
		if a.transcript.isSelecting() {
			if event != nil {
				x, y := event.Position()
				a.transcript.hoverControl(x, y)
				a.updateTranscriptSelection(x, y)
			}
			a.transcriptScrollGen++
			a.transcriptScrollPending = false
			control := a.transcript.pendingControl()
			if body, ok := a.transcript.activateControl(); ok {
				// The press and release both landed on the control, so whatever tiny range
				// the drag accumulated is discarded rather than copied over the body.
				_ = a.transcript.endSelect()
				a.copyControlPayload(body, control.response)
				a.app.SetFocus(a.input)
				return nil, action
			}
			if text := a.transcript.endSelect(); text != "" {
				a.copyTranscriptSelection(text)
			}
			a.app.SetFocus(a.input)
			return nil, action
		}
		if a.inputSelecting {
			if event != nil {
				a.updateInputSelection(event.Position())
			}
			a.finishInputSelection()
			a.copyInputSelection()
			a.app.SetFocus(a.input)
			return nil, action
		}
		if event == nil {
			return event, action
		}
		if a.statusOpen {
			// /status modal shield (see MouseLeftDown): keep focus on the panel, drop the event.
			a.app.SetFocus(a.status)
			return nil, action
		}
		if a.anyOverlayOpen() {
			return event, action
		}
		x, y := event.Position()
		if a.inInputRect(x, y) {
			// Shift+drag in the input uses TextArea's native path. Copy/collapse on release,
			// but pass the event through so TextArea resets its own drag state.
			a.inputDragging = false
			a.copyInputSelection()
			return event, action
		}
		// A native Shift+drag that releases outside the input rect must still copy/collapse,
		// and must hand the TextArea a release inside its own rect — otherwise the TextArea
		// (whose MouseHandler ignores out-of-rect events) is stranded mid-drag and a later
		// mouse move keeps extending the stale selection. Copy and collapse first,
		// then synthesize a release at the last in-input drag position: that is where the
		// TextArea's cursor already sits, so its MouseLeftUp moveCursor is a no-op that ends
		// the native drag without re-opening the collapsed selection.
		if a.inputDragging {
			a.inputDragging = false
			a.copyInputSelection()
			a.app.SetFocus(a.input)
			return tcell.NewEventMouse(a.inputDragX, a.inputDragY, event.Buttons(), event.Modifiers()), action
		}
		a.app.SetFocus(a.input)
		return nil, action
	case tview.MouseLeftClick, tview.MouseLeftDoubleClick:
		if d := a.questionDrag(); d != nil && d.suppress {
			d.suppress = false
			return nil, action
		}
		if event == nil {
			return event, action
		}
		if a.statusOpen {
			// /status modal shield (see MouseLeftDown): keep focus on the panel, drop the event.
			a.app.SetFocus(a.status)
			return nil, action
		}
		if a.anyOverlayOpen() {
			return event, action
		}
		x, y := event.Position()
		if a.inInputRect(x, y) {
			return event, action
		}
		a.app.SetFocus(a.input)
		return nil, action
	}
	return event, action
}

func (a *App) beginInputSelection(x, y int) {
	off := a.input.offsetAt(x, y)
	a.inputSelecting = true
	a.inputSelAnchor = off
	a.inputSelX, a.inputSelY = x, y
	a.inputScrollGen++
	a.inputScrollPending = false
	a.input.Select(off, off)
	a.app.SetFocus(a.input)
}

func (a *App) updateInputSelection(x, y int) {
	if !a.inputSelecting {
		return
	}
	a.inputSelX, a.inputSelY = x, y
	if a.input.scrollDrag(y) {
		a.scheduleInputDragScroll()
	}
	a.input.Select(a.inputSelAnchor, a.input.offsetAt(x, y))
}

func (a *App) finishInputSelection() {
	a.inputSelecting = false
	a.inputScrollGen++
	a.inputScrollPending = false
}

func (a *App) scheduleInputDragScroll() {
	if !a.inputSelecting || a.inputScrollPending {
		return
	}
	a.inputScrollPending = true
	gen := a.inputScrollGen
	a.afterFunc(inputDragScrollInterval, func() { a.inputDragScrollTick(gen) })
}

func (a *App) inputDragScrollTick(gen uint64) {
	mouseDebugf("inputDragScrollTick gen=%d curGen=%d selecting=%v selY=%d", gen, a.inputScrollGen, a.inputSelecting, a.inputSelY)
	a.streamUpdate(func() {
		if !a.inputSelecting || a.inputScrollGen != gen {
			return
		}
		a.inputScrollPending = false
		if a.input.scrollDrag(a.inputSelY) {
			a.input.Select(a.inputSelAnchor, a.input.offsetAt(a.inputSelX, a.inputSelY))
		}
		// Keep ticking for the whole drag, not only when this tick scrolled: a real mouse
		// held at the edge jitters by a fraction of a cell, and a single tick that lands one
		// row inside the edge (or momentarily at maxOffset) must not kill the auto-scroll —
		// it resumes the instant the held position is back on the edge. The gen/selecting
		// guard above ends the chain on release, so this cannot outlive the drag.
		a.scheduleInputDragScroll()
	})
}

// updateTranscriptSelection extends the conversation-pane selection to (x,y) and, when
// the drag is held on the top or bottom visible row, scrolls the pane and arms the
// edge-hold timer so the selection can reach conversation beyond the initial viewport
// (the transcript twin of updateInputSelection). The scroll runs before
// updateSelect so the extension re-projects through the new scroll offset.
func (a *App) updateTranscriptSelection(x, y int) {
	if !a.transcript.isSelecting() {
		return
	}
	a.transcriptSelX, a.transcriptSelY = x, y
	if a.transcript.scrollDragScroll(y) {
		a.scheduleTranscriptDragScroll()
	}
	a.transcript.updateSelect(x, y)
}

func (a *App) scheduleTranscriptDragScroll() {
	if !a.transcript.isSelecting() || a.transcriptScrollPending {
		return
	}
	a.transcriptScrollPending = true
	gen := a.transcriptScrollGen
	a.afterFunc(inputDragScrollInterval, func() { a.transcriptDragScrollTick(gen) })
}

func (a *App) transcriptDragScrollTick(gen uint64) {
	mouseDebugf("transcriptDragScrollTick gen=%d curGen=%d selecting=%v selY=%d", gen, a.transcriptScrollGen, a.transcript.isSelecting(), a.transcriptSelY)
	a.streamUpdate(func() {
		if !a.transcript.isSelecting() || a.transcriptScrollGen != gen {
			return
		}
		a.transcriptScrollPending = false
		if a.transcript.scrollDragScroll(a.transcriptSelY) {
			a.transcript.updateSelect(a.transcriptSelX, a.transcriptSelY)
		}
		// Reschedule for the whole drag (jitter-proof), exactly like the input timer: the
		// gen/selecting guard above ends the chain on release.
		a.scheduleTranscriptDragScroll()
	})
}

// copyInputSelection copies the input's current TextArea selection through the OSC 52
// clipboard path and collapses it, so a mouse-drag selection is auto-copied and its
// highlight clears on release. A no-op when nothing is selected.
func (a *App) copyInputSelection() {
	if a.input.HasSelection() {
		_, start, end := a.input.GetSelection()
		_ = a.input.copyToClipboard(a.input.GetText()[start:end])
		a.input.collapseSelection()
	}
}

// inInputRect reports whether (x,y) lands on the input area's drawn rectangle. The
// app-level mouse capture passes those clicks through so cursor placement and native
// input selection keep working, while clicks above the input are handled for focus
// preservation and transcript selection.
func (a *App) inInputRect(x, y int) bool {
	ix, iy, iw, ih := a.input.GetRect()
	return x >= ix && x < ix+iw && y >= iy && y < iy+ih
}

func (a *App) statusRegionAt(x, y int) clickRegion {
	if !a.status.InRect(x, y) {
		return clickRegion{}
	}
	off, onText := a.status.offsetRowAt(x, y)
	return a.statusRegions.at(off, onText)
}

// textSelection is the highlight half of a drag over a *tview.TextView: the anchor and
// range state, the column-to-byte-offset mapping over the view's displayed text, and the
// reverse-video pass the view's Draw overlays. rows supplies the view's display rows; a
// nil rows means the view wraps its text at the inner width, which is what a plain
// TextView does.
type textSelection struct {
	rows             func(text string, width int) []rowSpan
	selecting        bool
	selAnchor        int
	selStart, selEnd int
}

func (s *textSelection) rowsOf(text string, width int) []rowSpan {
	if s.rows != nil {
		return s.rows(text, width)
	}
	return wrapRows(text, width)
}

func (s *textSelection) paint(v *tview.TextView, screen tcell.Screen) {
	if s.selStart >= s.selEnd {
		return
	}
	ix, iy, iw, ih := v.GetInnerRect()
	if iw <= 0 || ih <= 0 {
		return
	}
	text := v.GetText(true)
	if s.selEnd > len(text) {
		return
	}
	rows := s.rowsOf(text, iw)
	scrollRow, scrollCol := v.GetScrollOffset()
	for ry := 0; ry < ih; ry++ {
		rowIdx := scrollRow + ry
		if rowIdx < 0 || rowIdx >= len(rows) {
			continue
		}
		row := rows[rowIdx]
		// Reverse wide cells right-to-left so tview paints each cluster last.
		for col := iw - 1; col >= 0; col-- {
			off := byteOffsetInRow(text, row, col+scrollCol)
			if off < s.selStart || off >= s.selEnd || off >= row.end {
				continue
			}
			str, style, _ := screen.Get(ix+col, iy+ry)
			screen.Put(ix+col, iy+ry, str, style.Reverse(true))
		}
	}
}

func (s *textSelection) offsetAt(v *tview.TextView, x, y int) int {
	off, _ := s.offsetRowAt(v, x, y)
	return off
}

// offsetRowAt returns the byte offset (x,y) addresses and whether the column landed on the
// row's own drawn text rather than the blank padding past its end. Selection wants the
// clamped offset either way; the copy control must not fire from a blank cell on the row
// above it, which wrapping puts one byte offset away from the control's first character.
func (s *textSelection) offsetRowAt(v *tview.TextView, x, y int) (int, bool) {
	ix, iy, iw, ih := v.GetInnerRect()
	if iw <= 0 {
		return 0, false
	}
	text := v.GetText(true)
	rows := s.rowsOf(text, iw)
	if len(rows) == 0 {
		return 0, false
	}
	scrollRow, scrollCol := v.GetScrollOffset()
	ry := y - iy
	if ry < 0 {
		ry = 0
	}
	// A pointer outside the view addresses the nearest row it drew: reaching a row the
	// reader has not scrolled into view would copy text that was never shown or highlighted.
	if ih > 0 && ry > ih-1 {
		ry = ih - 1
	}
	rowIdx := scrollRow + ry
	if rowIdx < 0 {
		rowIdx = 0
	}
	if rowIdx >= len(rows) {
		rowIdx = len(rows) - 1
	}
	if ih > 0 && y > iy+ih-1 {
		return rows[rowIdx].end, false
	}
	col := (x - ix) + scrollCol
	if col < 0 {
		col = 0
	}
	off := byteOffsetInRow(text, rows[rowIdx], col)
	return off, off < rows[rowIdx].end
}

func (s *textSelection) beginSelect(v *tview.TextView, x, y int) {
	off := s.offsetAt(v, x, y)
	s.selecting = true
	s.selAnchor, s.selStart, s.selEnd = off, off, off
}

func (s *textSelection) updateSelect(v *tview.TextView, x, y int) {
	if !s.selecting {
		return
	}
	off := s.offsetAt(v, x, y)
	if off < s.selAnchor {
		s.selStart, s.selEnd = off, s.selAnchor
	} else {
		s.selStart, s.selEnd = s.selAnchor, off
	}
}

func (s *textSelection) endSelect(v *tview.TextView) string {
	defer s.clearSelection()
	if s.selStart >= s.selEnd {
		return ""
	}
	text := v.GetText(true)
	if s.selEnd > len(text) {
		return ""
	}
	return text[s.selStart:s.selEnd]
}

func (s *textSelection) clearSelection() {
	s.selecting = false
	s.selAnchor, s.selStart, s.selEnd = 0, 0, 0
}

// statusView state is accessed on the tview event-loop goroutine.
type statusView struct {
	*tview.TextView
	textSelection
}

func (v *statusView) Draw(screen tcell.Screen) {
	v.TextView.Draw(screen)
	v.paint(v.TextView, screen)
}

func (v *statusView) offsetRowAt(x, y int) (int, bool) {
	return v.textSelection.offsetRowAt(v.TextView, x, y)
}

func (v *statusView) beginSelect(x, y int) { v.textSelection.beginSelect(v.TextView, x, y) }

func (v *statusView) updateSelect(x, y int) { v.textSelection.updateSelect(v.TextView, x, y) }

func (v *statusView) endSelect() string { return v.textSelection.endSelect(v.TextView) }

// copyTranscriptSelection copies selected transcript text to the system clipboard
// through the input area's existing OSC 52 path, so transcript and input copy
// share one mechanism: it emits the OSC 52 sequence and updates the in-app paste
// source (lastCopied) exactly like the input's Ctrl-Q copy. Selecting
// transcript text therefore needs no separate copy command.
func (a *App) copyTranscriptSelection(text string) {
	_ = a.input.copyToClipboard(text)
}
