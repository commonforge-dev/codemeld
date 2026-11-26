package tui

import (
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"
)

// wrappedRows reports how many screen rows the current buffer occupies inside an
// input area inputWidth columns wide, accounting for the "> " prompt label tview
// subtracts from every text row's width before laying text out. It is the
// height accessor tview.TextArea does not expose; App.inputRows uses it (capped at the
// height-aware App.inputTextRowCap) to size the input box and the matching
// transcript cap, so both reflow with the live terminal width.
func (in *inputField) wrappedRows(inputWidth int) int {
	textWidth := inputWidth - tview.TaggedStringWidth(promptLabel)
	return wrappedRowCount(in.GetText(), textWidth)
}

// adjustRowOffset aligns the TextArea's vertical scroll with the box height the
// before-draw hook just allocated, given cap (the visible text-row budget at
// inputWidth). When the whole wrapped buffer fits within cap it pins the row offset to
// 0 so the first wrapped row stays visible: a line wrapping to a second row makes tview
// scroll rowOffset to 1 against the stale one-row height, and the regrown box would
// otherwise hide row 0. When the buffer overflows cap it scrolls so the cursor's
// wrapped row is the last visible row — showing the tail of a long expanded paste at the
// bottom rather than tview's stale-height offset pinned to the head. Only the row
// offset is set; the column offset is preserved via SetOffset(row, column) so behavior is
// unchanged if wrapping is ever disabled.
func (in *inputField) adjustRowOffset(inputWidth, cap int) {
	_, column := in.GetOffset()
	if in.wrappedRows(inputWidth) <= cap {
		in.SetOffset(0, column)
		return
	}
	offset := in.cursorWrappedRow(inputWidth) - cap + 1
	if offset < 0 {
		offset = 0
	}
	in.SetOffset(offset, column)
}

// cursorWrappedRow reports the zero-based wrapped screen row the caret sits on inside an
// input area inputWidth columns wide, mirroring wrappedRows' label-aware text width. It
// wraps the buffer up to the caret's byte offset and takes the last of those rows, so
// after a paste (the caret lands at the end of the inserted text) it is the buffer's
// final wrapped row — the row adjustRowOffset pins to the bottom on overflow.
// Wrapping the prefix is exact when the caret is at the buffer end (the paste/tail case);
// for an interior caret a word straddling it could wrap a row differently, which only
// shifts the tail scroll by a row.
func (in *inputField) cursorWrappedRow(inputWidth int) int {
	text := in.GetText()
	_, _, end := in.GetSelection()
	if end > len(text) {
		end = len(text)
	}
	textWidth := inputWidth - tview.TaggedStringWidth(promptLabel)
	return wrappedRowCount(text[:end], textWidth) - 1
}

// wrappedRowCount reports how many screen rows text occupies when laid out at width
// columns with tview.TextArea's wrap + word-wrap rules. It mirrors TextArea.extendLines
// (tview v0.42.0): grapheme clusters are stepped with uniseg.StepString; a mandatory
// line break (LineMustBreak, e.g. a newline) starts a new row, a row grown past width
// breaks at the latest line-break opportunity (LineCanBreak — word wrap) or, lacking
// one, after the last grapheme so at least one cluster lands on each row. Cluster cell
// widths drive the math (tview.TabSize for tabs), not byte or rune counts. An empty
// buffer or a non-positive width is one row, preserving the single-line footprint.
//
// tview exposes no total-wrapped-row accessor (its post-draw row fields are
// unexported), so this duplicates the rule; a mismatch would mis-size the input box by
// a row, which is why input_test.go pins it against spaces, unbroken tokens, tabs, wide
// runes, newlines, and multiple widths.
func wrappedRowCount(text string, width int) int {
	if text == "" || width <= 0 {
		return 1
	}
	rows := 1
	state := -1
	var (
		lineWidth, widthSinceLineBreak int
		haveGrapheme, havePendingBreak bool
	)
	for len(text) > 0 {
		var (
			cluster    string
			boundaries int
		)
		cluster, text, boundaries, state = uniseg.StepString(text, state)
		clusterWidth := boundaries >> uniseg.ShiftWidth
		if cluster == "\t" {
			clusterWidth = tview.TabSize
		}
		lineWidth += clusterWidth
		widthSinceLineBreak += clusterWidth

		if lineWidth <= width {
			// Mandatory break (a newline): start a fresh row unless this is the final
			// cluster with no trailing line break, matching TextArea.extendLines.
			if boundaries&uniseg.MaskLine == uniseg.LineMustBreak &&
				(len(text) > 0 || uniseg.HasTrailingLineBreakInString(cluster)) {
				rows++
				lineWidth, widthSinceLineBreak = 0, 0
				haveGrapheme, havePendingBreak = false, false
				continue
			}
		} else { // row grew past width — wrap
			if havePendingBreak {
				// Break at the last word-wrap opportunity; the carried-over clusters
				// since it open the next row.
				rows++
				lineWidth = widthSinceLineBreak
				havePendingBreak = false
			} else if haveGrapheme {
				// No break opportunity yet: split the over-long token after the last
				// grapheme so the current cluster opens the next row.
				rows++
				lineWidth = clusterWidth
			}
		}

		if boundaries&uniseg.MaskLine == uniseg.LineCanBreak {
			havePendingBreak = true
			widthSinceLineBreak = 0
		}
		haveGrapheme = true
	}
	return rows
}
