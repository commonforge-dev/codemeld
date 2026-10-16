// App-owned transcript mouse selection: plain left-button drag selects
// transcript text, the range is highlighted with reverse video at draw time, and
// the selection is copied to the system clipboard on mouse-up — all while tcell's
// global mouse mode (needed for wheel scrolling) stays enabled.
package tui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"
)

type transcriptView struct {
	*tview.TextView
	owner      *transcript
	paint      *tview.TextView
	paintText  string
	paintWidth int
}

// Draw renders the TextView, then overlays the current selection highlight on top
// of the already-drawn glyphs. The highlight is a draw-time decoration only:
// it never mutates t.lines or the SetText'd text, so dynamic-color rendering of the
// committed transcript is untouched and the styling returns the instant the
// selection clears.
func (v *transcriptView) Draw(screen tcell.Screen) {
	_, _, width, _ := v.GetInnerRect()
	v.setPaintText(v.GetText(false), width)
	v.paint.SetRect(v.GetRect())
	v.paint.Draw(screen)
	v.owner.drawSelectionHighlight(screen)
}

func (v *transcriptView) setPaintText(text string, width int) {
	paintText := railWrapText(text, width)
	if v.paintText != paintText || v.paintWidth != width {
		row, col := v.paint.GetScrollOffset()
		v.paint.SetText(paintText)
		v.paint.SetSize(0, width)
		if v.owner.following {
			v.paint.ScrollToEnd()
		} else {
			v.paint.ScrollTo(row, col)
		}
		v.paintText = paintText
		v.paintWidth = width
	}
}

func (v *transcriptView) GetWrappedLineCount() int {
	v.setPaintText(v.GetText(false), v.paintWidth)
	return v.paint.GetWrappedLineCount()
}

func (v *transcriptView) GetScrollOffset() (int, int) {
	return v.paint.GetScrollOffset()
}

func (v *transcriptView) ScrollTo(row, column int) *transcriptView {
	v.TextView.ScrollTo(row, column)
	v.paint.ScrollTo(row, column)
	return v
}

func (v *transcriptView) ScrollToEnd() *transcriptView {
	v.TextView.ScrollToEnd()
	v.paint.ScrollToEnd()
	return v
}

// rowSpan is one wrapped display row, given as a byte range [start,end) into the
// stripped displayed text. end excludes any trailing hard-break newline, so the
// span covers exactly the visible cells of that row.
type rowSpan struct {
	start, end int
}

// tabCellWidth returns the cells a tab occupies starting at display column col,
// matching tview.TextView's left-aligned tab stops: a tab advances to the next
// multiple of tview.TabSize, so it spans tview.TabSize-col%tview.TabSize cells (a
// full tview.TabSize when col already sits on a stop). The transcript view is
// left-aligned (no SetTextAlign), so this mirrors how its tabs are drawn and
// indexed; a fixed tview.TabSize would mis-place every cell after a tab.
func tabCellWidth(col int) int {
	return tview.TabSize - col%tview.TabSize
}

// wrapRows splits literal displayed text into the wrapped rows a non-dynamic-color
// TextView draws at the given inner width, returning each row's byte range. It
// mirrors tview's wrap rules (mandatory breaks start a new row; an over-wide row
// breaks at the last word-break opportunity, or after the last grapheme for an
// unbreakable token), but treats bracketed text as visible cells rather than style
// tags. Transcript selection calls it with stripped text (GetText(true) semantics),
// so the row boundaries match what TextView draws while the offsets stay in the
// plain text the selection copies.
func wrapRows(text string, width int) []rowSpan {
	return wrapRowsAt(text, width, 0)
}

func wrapRowsAt(text string, width, startColumn int) []rowSpan {
	if width <= 0 {
		return nil
	}
	if text == "" {
		return []rowSpan{{0, 0}}
	}
	var rows []rowSpan
	for start := 0; start < len(text); {
		end, next := wrappedRowEnd(text, start, width, startColumn)
		rows = append(rows, rowSpan{start, end})
		start = next
	}
	if strings.HasSuffix(text, "\n") {
		rows = append(rows, rowSpan{len(text), len(text)})
	}
	return rows
}

func wrappedRowEnd(text string, start, width, startColumn int) (int, int) {
	lineWidth := startColumn
	lastBreak := -1
	pos := start
	state := -1
	for rest := text[start:]; len(rest) > 0; {
		cluster, next, boundaries, st := uniseg.StepString(rest, state)
		state = st
		end := pos + len(cluster)
		w := boundaries >> uniseg.ShiftWidth
		if cluster == "\t" {
			w = tabCellWidth(lineWidth)
		}
		if lineWidth+w > width {
			if lastBreak > start {
				return lastBreak, lastBreak
			}
			if pos > start {
				return pos, pos
			}
		}
		lineWidth += w
		if boundaries&uniseg.MaskLine == uniseg.LineMustBreak &&
			(len(next) > 0 || uniseg.HasTrailingLineBreakInString(cluster)) {
			return pos, end
		}
		if boundaries&uniseg.MaskLine == uniseg.LineCanBreak {
			lastBreak = end
		}
		pos = end
		rest = next
	}
	return len(text), len(text)
}

func transcriptRows(raw, text string, width int) []rowSpan {
	if text == "" {
		return []rowSpan{{0, 0}}
	}
	var rows []rowSpan
	start := 0
	lineNumber := 0
	rawLines := strings.Split(raw, "\n")
	for {
		end := strings.IndexByte(text[start:], '\n')
		if end < 0 {
			end = len(text)
		} else {
			end += start
		}
		line := text[start:end]
		if lineNumber < len(rawLines) && strings.HasPrefix(rawLines[lineNumber], userRailPrefix) {
			contentStart := start + len("▌ ")
			for i, row := range wrapRowsAt(text[contentStart:end], width, userRailWidth) {
				if i == 0 {
					rows = append(rows, rowSpan{start: start, end: contentStart + row.end})
				} else {
					rows = append(rows, rowSpan{start: contentStart + row.start, end: contentStart + row.end})
				}
			}
		} else {
			for _, row := range wrapRowsAt(line, width, 0) {
				rows = append(rows, rowSpan{start: start + row.start, end: start + row.end})
			}
		}
		if end == len(text) {
			break
		}
		start = end + 1
		lineNumber++
	}
	return rows
}

func hasSyntheticRail(raw, text string, row rowSpan) bool {
	lineStart := strings.LastIndexByte(text[:row.start], '\n') + 1
	lineNumber := strings.Count(text[:lineStart], "\n")
	rawLines := strings.Split(raw, "\n")
	return row.start != lineStart && lineNumber < len(rawLines) && strings.HasPrefix(rawLines[lineNumber], userRailPrefix)
}

// offsetAt maps a screen coordinate to a byte offset into the stripped displayed
// text, accounting for the transcript's inner rect, the current wrapped-row scroll
// offset, and word wrapping. A click above/left of the text clamps to the
// first visible row / row start; below/right clamps to the last row / row end, so a
// drag that leaves the rectangle still resolves to a sensible boundary. The caller
// holds t.mu.
func (t *transcript) offsetAt(x, y int) int {
	off, _ := t.offsetRowAt(x, y)
	return off
}

// offsetRowAt is offsetAt plus whether the column landed on the row's own drawn text
// rather than the blank padding past its end (the transcript twin of
// statusView.offsetRowAt). Selection wants the clamped offset either way; a copy control
// must not fire from a blank cell beside it, which wrapping puts one byte offset away
// from the control's first character.
func (t *transcript) offsetRowAt(x, y int) (int, bool) {
	ix, iy, iw, ih := t.view.GetInnerRect()
	if iw <= 0 {
		return 0, false
	}
	raw := t.view.GetText(false)
	text := t.view.GetText(true)
	rows := transcriptRows(raw, text, iw)
	if len(rows) == 0 {
		return 0, false
	}
	scrollRow, scrollCol := t.view.GetScrollOffset()
	ry := y - iy
	if ry < 0 {
		ry = 0
	}
	rowIdx := scrollRow + ry
	// A row index past the wrapped text is the blank pane below the conversation.
	// Selection still wants a clamped offset there, but nothing on it is drawn text, so
	// a control on the last row cannot be fired from the empty rows beneath it.
	blankPane := rowIdx >= len(rows)
	if rowIdx < 0 {
		rowIdx = 0
	}
	if blankPane {
		rowIdx = len(rows) - 1
		return rows[rowIdx].end, false
	}
	// A drag held below the last visible row puts the pointer past the content (over the
	// chrome/rule beneath it), which reads as "take the whole line", not up to the
	// pointer's column — to keep only part of the bottom line the user drags back up onto
	// it. So clamp the column to the row end there rather than tracking x.
	if ih > 0 && y > iy+ih-1 {
		return rows[rowIdx].end, false
	}
	targetCol := (x - ix) + scrollCol
	if targetCol < 0 {
		targetCol = 0
	}
	if hasSyntheticRail(raw, text, rows[rowIdx]) {
		targetCol -= userRailWidth
		if targetCol < 0 {
			// The pointer is on the synthetic rail gutter, which is drawn but is not the
			// row's own text.
			return rows[rowIdx].start, false
		}
	}
	off := byteOffsetInRow(text, rows[rowIdx], targetCol)
	return off, off < rows[rowIdx].end
}

// byteOffsetInRow returns the byte offset of the grapheme cluster occupying display
// column targetCol within row, or row.end when targetCol is at/past the row's
// visible width. Cluster cell widths drive the column math (a tab advances to the
// next tab stop, so its width depends on the current column), matching wrapRows and
// the TextView's own layout.
func byteOffsetInRow(text string, row rowSpan, targetCol int) int {
	seg := text[row.start:row.end]
	col := 0
	pos := row.start
	state := -1
	for len(seg) > 0 {
		cluster, rest, boundaries, st := uniseg.StepString(seg, state)
		state = st
		w := boundaries >> uniseg.ShiftWidth
		if cluster == "\t" {
			w = tabCellWidth(col)
		}
		if w > 0 && targetCol < col+w {
			return pos
		}
		col += w
		pos += len(cluster)
		seg = rest
	}
	return row.end
}

// beginSelect starts a drag selection, anchoring it at the text position under
// (x,y). Until updateSelect extends it the range is empty (no highlight). The
// caller runs on the tview event-loop goroutine.
func (t *transcript) beginSelect(x, y int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	off := t.offsetAt(x, y)
	t.selecting = true
	t.selAnchor = off
	t.selStart = off
	t.selEnd = off
}

// updateSelect extends the in-progress selection to the text position under (x,y),
// ordering the range against the drag anchor so dragging in either direction works.
// It is a no-op when no drag is active.
func (t *transcript) updateSelect(x, y int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.selecting {
		return
	}
	off := t.offsetAt(x, y)
	if off < t.selAnchor {
		t.selStart, t.selEnd = off, t.selAnchor
	} else {
		t.selStart, t.selEnd = t.selAnchor, off
	}
}

// endSelect finishes the drag and returns the selected stripped text, or "" when
// nothing was selected. It captures the text first, then zeroes the selection
// offsets — the same reset renderLocked performs on any text mutation — so the
// reverse-video highlight clears on the next draw instead of lingering after the
// mouse is released. The caller copies the returned text before the next
// draw, so auto-copy-on-release is unaffected by the clear.
func (t *transcript) endSelect() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.selecting = false
	defer func() { t.selAnchor, t.selStart, t.selEnd = 0, 0, 0 }()
	if t.selStart >= t.selEnd {
		return ""
	}
	text := t.view.GetText(true)
	if t.selEnd > len(text) {
		return ""
	}
	return text[t.selStart:t.selEnd]
}

// scrollDragScroll advances the transcript viewport by one wrapped row when an app-owned
// selection drag reaches the top or bottom visible row, so the selection can extend past
// the initially visible conversation (mirroring inputField.scrollDrag). It reports
// whether the view actually moved. It runs on the tview event-loop goroutine and must not
// be called while holding t.mu: it delegates the offset change (and the follow-flag
// update) to scrollBy, which takes t.mu itself. The visible-row check reads the drawn
// inner rect, which is touched only on this goroutine, so it needs no lock of its own.
func (t *transcript) scrollDragScroll(y int) bool {
	_, iy, _, ih := t.view.GetInnerRect()
	if ih <= 0 {
		return false
	}
	bottom := iy + ih - 1
	before, _ := t.view.GetScrollOffset()
	switch {
	case y >= bottom:
		t.scrollBy(1)
	case y <= iy:
		t.scrollBy(-1)
	default:
		mouseDebugf("  transcriptScrollDrag y=%d iy=%d ih=%d bottom=%d offset=%d (interior, no scroll)", y, iy, ih, bottom, before)
		return false
	}
	after, _ := t.view.GetScrollOffset()
	mouseDebugf("  transcriptScrollDrag y=%d iy=%d ih=%d bottom=%d offset=%d->%d scrolled=%v", y, iy, ih, bottom, before, after, after != before)
	return after != before
}

// pressControl records which code-block control, if any, a left-press landed on. It is
// called for every press the transcript could own, so a press elsewhere clears a
// candidate an earlier press left armed.
func (t *transcript) pressControl(x, y int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.controls.beginPress(t.regionAtLocked(x, y))
}

func (t *transcript) hoverControl(x, y int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.controls.hover(t.regionAtLocked(x, y))
}

// activateControl reports the fenced body to copy when the press and the release both
// landed on the same control, and consumes the press either way.
func (t *transcript) activateControl() (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.controls.activate()
}

func (t *transcript) regionAtLocked(x, y int) clickRegion {
	if !t.view.InRect(x, y) {
		return clickRegion{}
	}
	off, onText := t.offsetRowAt(x, y)
	return t.controls.at(off, onText)
}

// isSelecting reports whether a drag selection is currently in progress.
func (t *transcript) isSelecting() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.selecting
}

// drawSelectionHighlight paints reverse video over the cells of the selected range
// that are currently on screen, re-drawing each selected glyph in the inverted
// style. It re-projects the absolute selection offsets through the live inner
// rect and scroll offset, so the highlight tracks the text across scrolling. It runs
// from transcriptView.Draw on the event-loop goroutine after the text is drawn.
func (t *transcript) drawSelectionHighlight(screen tcell.Screen) {
	t.mu.Lock()
	selStart, selEnd := t.selStart, t.selEnd
	t.mu.Unlock()
	if selStart >= selEnd {
		return
	}
	ix, iy, iw, ih := t.view.GetInnerRect()
	if iw <= 0 || ih <= 0 {
		return
	}
	raw := t.view.GetText(false)
	text := t.view.GetText(true)
	if selEnd > len(text) {
		return
	}
	rows := transcriptRows(raw, text, iw)
	scrollRow, scrollCol := t.view.GetScrollOffset()
	style := tcell.StyleDefault.Reverse(true)
	for ry := 0; ry < ih; ry++ {
		rowIdx := scrollRow + ry
		if rowIdx < 0 || rowIdx >= len(rows) {
			continue
		}
		row := rows[rowIdx]
		seg := text[row.start:row.end]
		col := 0
		if hasSyntheticRail(raw, text, row) {
			col = userRailWidth
		}
		pos := row.start
		state := -1
		for len(seg) > 0 {
			cluster, rest, boundaries, st := uniseg.StepString(seg, state)
			state = st
			w := boundaries >> uniseg.ShiftWidth
			if cluster == "\t" {
				w = tabCellWidth(col)
			}
			if w > 0 && pos >= selStart && pos < selEnd {
				// A selected cluster of display width w covers w screen cells, so
				// paint every one — not just the first. This mirrors tview's own
				// cell rendering (textview.go:1265): the main rune (plus combining
				// marks) at offset 0, blank spaces for the continuation cells a tab
				// or wide rune occupies. Drawing high offset → low matches tview so
				// a wide rune's trailing continuation cell is written before the
				// wide rune reclaims it.
				runes := []rune(cluster)
				for offset := w - 1; offset >= 0; offset-- {
					screenX := ix + (col + offset - scrollCol)
					if screenX < ix || screenX >= ix+iw {
						continue
					}
					if offset == 0 {
						screen.SetContent(screenX, iy+ry, runes[0], runes[1:], style)
					} else {
						screen.SetContent(screenX, iy+ry, ' ', nil, style)
					}
				}
			}
			col += w
			pos += len(cluster)
			seg = rest
		}
	}
}
