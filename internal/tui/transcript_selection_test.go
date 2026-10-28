// Tests for app-owned transcript selection: the wrapped-text coordinate
// mapping, plain-drag select + OSC 52 copy through handleAppMouse, the reverse-video
// highlight, selection survival across scrolling, and preserved input behavior.
package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// reverseText returns the concatenation of every reverse-video cell's runes on the
// drawn screen, in row-major order — the visible highlight the selection paints.
func reverseText(t *testing.T, view tview.Primitive, w, h int) string {
	t.Helper()
	screen := drawPrimitive(t, view, w, h)
	cells, width, height := screen.GetContents()
	var rev string
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			c := cells[row*width+col]
			_, _, attr := c.Style.Decompose()
			if attr&tcell.AttrReverse != 0 && len(c.Runes) > 0 {
				rev += string(c.Runes)
			}
		}
	}
	return rev
}

// TestWrapRows_TracksByteSpans pins the coordinate mapper's wrapping: a hard newline
// closes a row before the newline and opens the next after it (so a "\n\n" block gap
// becomes an empty row between two text rows), and a word longer than the width wraps
// at the last break opportunity.
func TestWrapRows_TracksByteSpans(t *testing.T) {
	t.Run("block separator becomes an empty row", func(t *testing.T) {
		rows := wrapRows("hello\n\nworld", 40)
		want := []rowSpan{{start: 0, end: 5}, {start: 6, end: 6}, {start: 7, end: 12}}
		if len(rows) != len(want) {
			t.Fatalf("rows = %v, want %v", rows, want)
		}
		for i := range want {
			if rows[i] != want[i] {
				t.Fatalf("row %d = %v, want %v", i, rows[i], want[i])
			}
		}
	})

	t.Run("word wrap at the last break opportunity", func(t *testing.T) {
		// Width 5: "ab cd ef" wraps after each space that would overflow.
		rows := wrapRows("ab cd ef", 5)
		var got []string
		for _, r := range rows {
			got = append(got, "ab cd ef"[r.start:r.end])
		}
		want := []string{"ab ", "cd ef"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("wrapped rows = %q, want %q", got, want)
		}
	})
}

// TestTranscriptSelection_DragSelectsAndCopies proves Done-when 1 and 2: a plain
// left-drag (no Shift) over the transcript highlights the dragged text *while*
// dragging, then on mouse-up copies it through the input area's OSC 52 path and
// clears the highlight (no lingering selection on the next draw), with the input
// still focused.
func TestTranscriptSelection_DragSelectsAndCopies(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.append("hello")
	a.transcript.append("world")
	drawAppTranscript(t, a, 10)   // rows: "hello"@0, ""@1, "world"@2; no scroll
	a.input.SetRect(0, 20, 40, 3) // input below the transcript, as in the real layout

	a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(5, 0, tcell.Button1, tcell.ModNone), tview.MouseMove)
	// While the drag is in progress the range is highlighted (the highlight shows
	// only during the drag).
	if rev := reverseText(t, a.transcript.view, 40, 10); rev != "hello" {
		t.Fatalf("mid-drag highlight = %q, want %q", rev, "hello")
	}

	a.handleAppMouse(tcell.NewEventMouse(5, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)

	want := osc52Sequence("hello")
	if len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
	}
	if a.app.GetFocus() != a.input {
		t.Fatalf("focus = %T, want the input to stay focused during selection", a.app.GetFocus())
	}
	// On release the highlight clears: the next draw must show no reverse-video cells,
	// even though the text was still copied above.
	if rev := reverseText(t, a.transcript.view, 40, 10); rev != "" {
		t.Fatalf("post-release highlight = %q, want it cleared", rev)
	}
}

// TestTranscriptSelection_TabbedColumnsMapToRenderedCells proves the coordinate
// mapper uses tview's position-dependent tab stops, not a fixed tview.TabSize. For
// the transcript "a\tb", tview draws 'a' at column 0, the tab across columns 1-3,
// and 'b' at column 4. A plain drag from 'a' ending on the visible 'b' cell must map
// that release column back to b's byte offset, so the half-open selection copies the
// tabbed span "a\t". Reverting tab width to a fixed tview.TabSize maps the 'b' column
// onto the tab byte instead, truncating the copy to "a" — so this fails.
func TestTranscriptSelection_TabbedColumnsMapToRenderedCells(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.append("a\tb")
	drawAppTranscript(t, a, 10) // width 40: a single unwrapped row "a<tab>b"
	a.input.SetRect(0, 20, 40, 3)

	// Drag from 'a' (column 0) to the visible 'b' cell (column 4, past the 3-cell tab).
	a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(4, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)

	want := osc52Sequence("a\t")
	if len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q (the 'b' column must map past the tab)", captured, want)
	}
}

// TestTranscriptSelection_MultiCellSpanFullyHighlighted proves every screen cell a
// selected multi-cell cluster occupies carries reverse video, not just the first.
// tview paints a tab across all its cells (textview.go:1265), so for the transcript
// "a\tb" the tab spans columns 1-3 between 'a' at 0 and 'b' at 4. Selecting the whole
// row must reverse-video every one of columns 0-4; before the fix only the first cell
// of each cluster was painted, leaving the tab's continuation cells (2-3) unhighlighted
// so the range was not visibly highlighted as a range.
func TestTranscriptSelection_MultiCellSpanFullyHighlighted(t *testing.T) {
	a := New(nil)
	a.input.osc52 = func(string) error { return nil }
	a.transcript.append("a\tb")
	drawAppTranscript(t, a, 10) // width 40: a single unwrapped row "a<tab>b"
	a.input.SetRect(0, 20, 40, 3)

	// Drag across the whole row: 'a' (col 0) to past 'b' (col 10) selects "a\tb". The
	// highlight is asserted mid-drag (after the move, before release) because the app clears
	// it on mouse-up.
	a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(10, 0, tcell.Button1, tcell.ModNone), tview.MouseMove)

	screen := drawPrimitive(t, a.transcript.view, 40, 10)
	cells, width, _ := screen.GetContents()
	for col := 0; col <= 4; col++ { // 'a', the tab across 1-3, 'b'
		_, _, attr := cells[0*width+col].Style.Decompose()
		if attr&tcell.AttrReverse == 0 {
			t.Fatalf("selected \"a\\tb\" span: cell at col %d is not reverse-video; "+
				"every cell a multi-cell cluster occupies must be highlighted", col)
		}
	}
}

// TestTranscriptSelection_SpansBlockGap proves the mapping crosses the "\n\n" block
// separator: dragging from the first row into a later row copies the text between,
// the blank separator row included. Wrapped-row coverage is
// TestTranscriptSelection_SpansWrappedRow; scrolled-offset coverage is
// TestTranscriptSelection_SurvivesScrollButClearsOnNewOutput.
func TestTranscriptSelection_SpansBlockGap(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.append("hello")
	a.transcript.append("world")
	drawAppTranscript(t, a, 10)
	a.input.SetRect(0, 20, 40, 3)

	// (0,0) start of "hello" -> (2,2) the 'r' of "world" two display rows down.
	a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(2, 2, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)

	want := osc52Sequence("hello\n\nwo")
	if len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
	}
}

// TestTranscriptSelection_SpansWrappedRow is the end-to-end proof that the runtime
// selection path — drawn TextView geometry, offsetAt, the copy, and the highlight —
// maps a coordinate drag across a *wrapped* transcript row, the case
// TestWrapRows_TracksByteSpans only exercises on the helper in isolation. A single
// 20-rune block with no break opportunity is drawn at inner width 10, so tview hard-
// wraps it into display row 0 "0123456789" and row 1 "ABCDEFGHIJ" with no real
// newline between them. Dragging from row 0 col 2 into row 1 col 4 must copy the
// contiguous run that straddles the wrap boundary — "23456789ABCD", byte offsets
// [2,14) — and reverse-video exactly those cells on both rows. Ignoring the wrapped
// row index in offsetAt would map the release back onto row 0 and truncate the copy,
// so this fails.
func TestTranscriptSelection_SpansWrappedRow(t *testing.T) {
	const width, height = 10, 5
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.append("0123456789ABCDEFGHIJ")        // 20 runes, no break -> wraps at width 10
	drawPrimitive(t, a.transcript.view, width, height) // establish the narrow wrapped geometry
	a.input.SetRect(0, 20, 40, 3)

	// Drag from '2' (row 0, col 2) into the 'E' cell (row 1, col 4), across the wrap.
	a.handleAppMouse(tcell.NewEventMouse(2, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(4, 1, tcell.Button1, tcell.ModNone), tview.MouseMove)
	// Mid-drag the wrapped span is highlighted on both rows (it clears on release).
	if rev := reverseText(t, a.transcript.view, width, height); rev != "23456789ABCD" {
		t.Fatalf("mid-drag highlight = %q, want %q across both wrapped rows", rev, "23456789ABCD")
	}
	a.handleAppMouse(tcell.NewEventMouse(4, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)

	want := osc52Sequence("23456789ABCD")
	if len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q (the drag must map across the wrap boundary)", captured, want)
	}
	if rev := reverseText(t, a.transcript.view, width, height); rev != "" {
		t.Fatalf("post-release highlight = %q, want it cleared", rev)
	}
}

// TestTranscriptSelection_FinalizesWhenMoveConsumesUpEvent proves the mouse-up still
// finalizes when a same-event MouseMove already consumed the event (fireMouseActions
// fires MouseMove before MouseLeftUp, and a consumed move nils the event the up sees).
func TestTranscriptSelection_FinalizesWhenMoveConsumesUpEvent(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.append("hello")
	a.transcript.append("world")
	drawAppTranscript(t, a, 10)
	a.input.SetRect(0, 20, 40, 3)

	a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(5, 0, tcell.Button1, tcell.ModNone), tview.MouseMove)
	a.handleAppMouse(nil, tview.MouseLeftUp) // up after the move already consumed the event

	want := osc52Sequence("hello")
	if len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q (nil-event up must finalize)", captured, want)
	}
}

// TestTranscriptSelection_PlainClickDoesNotCopy proves a click with no drag selects
// nothing: the range stays empty, nothing is copied, and the input stays focused.
func TestTranscriptSelection_PlainClickDoesNotCopy(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.append("hello")
	drawAppTranscript(t, a, 10)
	a.input.SetRect(0, 20, 40, 3)

	a.handleAppMouse(tcell.NewEventMouse(2, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(2, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)

	if len(captured) != 0 {
		t.Fatalf("a plain click copied %q, want nothing", captured)
	}
	if a.transcript.isSelecting() {
		t.Fatal("selection still marked in-progress after a click")
	}
	if rev := reverseText(t, a.transcript.view, 40, 10); rev != "" {
		t.Fatalf("a plain click highlighted %q, want nothing", rev)
	}
}

// drawTranscriptPane draws the transcript at an explicit size, so a test can put the
// copy control on a wrapped row or scroll it into view the way a narrow terminal does.
func drawTranscriptPane(t *testing.T, a *App, width, height int) tcell.SimulationScreen {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(width, height)
	a.transcript.view.SetRect(0, 0, width, height)
	a.transcript.view.Draw(screen)
	screen.Show()
	a.input.SetRect(0, height+1, width, 3)
	return screen
}

// transcriptCopyHits clicks every cell of the drawn transcript and returns, per payload
// in want, the glyphs of the cells that copied it — so each activating region is pinned to
// exactly the drawn control rather than to a cell rectangle a wrapped or scrolled row
// would put elsewhere. want maps each payload a cell may copy to the notice that copy must
// report, so a cell copying anything else, or reporting the wrong notice, fails. Each click
// starts from a cleared notice and a fresh draw, because a successful copy adds the notice
// block and would otherwise shift every following row.
func transcriptCopyHits(t *testing.T, a *App, width, height int, want map[string]string) map[string]string {
	t.Helper()
	a.afterFunc = func(time.Duration, func()) {}
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	screen := drawTranscriptPane(t, a, width, height)
	cells, _, _ := screen.GetContents()

	sequences := make(map[string]string, len(want))
	for payload, notice := range want {
		sequences[osc52Sequence(payload)] = notice
	}
	hits := map[string]string{}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			captured = captured[:0]
			a.transcript.clearNotice()
			drawTranscriptPane(t, a, width, height)
			a.handleAppMouse(tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
			a.handleAppMouse(nil, tview.MouseLeftUp)
			if len(captured) == 0 {
				continue
			}
			notice, expected := sequences[captured[0]]
			if len(captured) != 1 || !expected {
				t.Fatalf("cell (%d,%d) emitted %q, want exactly one of %q", x, y, captured, want)
			}
			if got := a.NoticeText(); got != notice {
				t.Fatalf("cell (%d,%d) notice = %q, want %q", x, y, got, notice)
			}
			for payload := range want {
				if osc52Sequence(payload) == captured[0] {
					hits[payload] += string(cells[y*width+x].Runes)
				}
			}
		}
	}
	return hits
}

// TestTranscriptCodeCopy_ControlClickCopiesSourceBody sweeps every drawn cell: only the
// control's own cells copy, they copy the fence body exactly, and the blank cells beside
// the control — which wrapping puts one byte offset away from it — do not. The narrow
// width wraps the block and splits the control across rows, and the short height scrolls
// the earlier conversation out of view, both of which a cell-rect hit test addresses wrong.
func TestTranscriptCodeCopy_ControlClickCopiesSourceBody(t *testing.T) {
	const body = "cd /tmp\nmake build --flag=1"
	for _, size := range []struct{ width, height int }{{40, 8}, {12, 8}, {40, 5}} {
		t.Run(fmt.Sprintf("%dx%d", size.width, size.height), func(t *testing.T) {
			a := New(nil)
			a.transcript.append("earlier output")
			a.transcript.appendDelta("run this:\n\n```sh\n" + body + "\n```")
			a.transcript.finalize()

			const response = "run this:\n\ncd /tmp\nmake build --flag=1"
			hits := transcriptCopyHits(t, a, size.width, size.height, map[string]string{
				body + "\n": codeCopyNotice,
				response:    responseCopyNotice,
			})
			if got := hits[body+"\n"]; got != statusCopyControl {
				t.Errorf("the cells that copy the block spell %q, want exactly %q", got, statusCopyControl)
			}
			if got := hits[response]; got != responseCopyControl {
				t.Errorf("the cells that copy the response spell %q, want exactly %q", got, responseCopyControl)
			}
		})
	}
}

// TestTranscriptCodeCopy_PartialClicksStaySelection proves the control needs a press and a
// release on the same region: a press that leaves it, a release that arrives on it from
// elsewhere, and a drag that runs across it all copy the visible transcript text instead.
func TestTranscriptCodeCopy_PartialClicksStaySelection(t *testing.T) {
	// The finalized block renders as "cd /tmp" on row 0 and the two-space-indented
	// control on row 1, whose cells run from column 2 to column 16.
	open := func(t *testing.T) (*App, *[]string) {
		t.Helper()
		a := New(nil)
		captured := new([]string)
		a.input.osc52 = func(seq string) error { *captured = append(*captured, seq); return nil }
		a.transcript.appendDelta("```sh\ncd /tmp\n```")
		a.transcript.finalize()
		drawTranscriptPane(t, a, 40, 8)
		return a, captured
	}

	t.Run("a press on the control released elsewhere stays a selection", func(t *testing.T) {
		a, captured := open(t)
		a.handleAppMouse(tcell.NewEventMouse(2, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseMove)
		a.handleAppMouse(nil, tview.MouseLeftUp)

		if want := osc52Sequence("cd /tmp\n" + codeControlIndent); len(*captured) != 1 || (*captured)[0] != want {
			t.Fatalf("osc52 sink = %q, want exactly one %q (the dragged text, not the block body)", *captured, want)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q after a drag off the control, want none", got)
		}
	})

	t.Run("a press above the control released on it stays a selection", func(t *testing.T) {
		a, captured := open(t)
		a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(2, 1, tcell.Button1, tcell.ModNone), tview.MouseMove)
		a.handleAppMouse(nil, tview.MouseLeftUp)

		if want := osc52Sequence("cd /tmp\n" + codeControlIndent); len(*captured) != 1 || (*captured)[0] != want {
			t.Fatalf("osc52 sink = %q, want exactly one %q (the dragged text, not the block body)", *captured, want)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q after a drag onto the control, want none", got)
		}
	})

	t.Run("a drag across the control copies the visible text", func(t *testing.T) {
		a, captured := open(t)
		a.handleAppMouse(tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(tcell.NewEventMouse(30, 1, tcell.Button1, tcell.ModNone), tview.MouseMove)
		a.handleAppMouse(nil, tview.MouseLeftUp)

		if want := osc52Sequence("cd /tmp\n" + codeControlIndent + statusCopyControl); len(*captured) != 1 || (*captured)[0] != want {
			t.Fatalf("osc52 sink = %q, want exactly one %q (a selection that spans the control copies its visible text)", *captured, want)
		}
		if got := a.NoticeText(); got != "" {
			t.Errorf("notice = %q after a selection drag, want none", got)
		}
	})
}

// TestTranscriptCodeCopy_ReRenderDropsArmedControl proves a control cannot fire against a
// payload from an earlier render: streamed output between the press and the release
// rebuilds the view text, so the press is dropped along with the offsets it was taken at.
func TestTranscriptCodeCopy_ReRenderDropsArmedControl(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.appendDelta("```sh\ncd /tmp\n```")
	a.transcript.finalize()
	drawTranscriptPane(t, a, 40, 8)

	a.handleAppMouse(tcell.NewEventMouse(0, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.transcript.append("output that arrived mid-click")
	a.handleAppMouse(nil, tview.MouseLeftUp)

	if len(captured) != 0 {
		t.Fatalf("osc52 sink = %q after a re-render between press and release, want no copy", captured)
	}
	if got := a.NoticeText(); got != "" {
		t.Errorf("notice = %q, want none", got)
	}
}

// TestTranscriptCodeCopy_ReRenderRebuildsRegionsForTheNewText proves the regions follow
// the current render rather than the one that armed them: after a block is appended above,
// the control's offsets move and still address the same fence body.
func TestTranscriptCodeCopy_ReRenderRebuildsRegionsForTheNewText(t *testing.T) {
	a := New(nil)
	a.transcript.appendDelta("```sh\ncd /tmp\n```")
	a.transcript.finalize()
	before := codeRegions(a.transcript.controls.all)

	a.transcript.append("later output")
	after := codeRegions(a.transcript.controls.all)

	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("regions = %+v then %+v, want one each", before, after)
	}
	if after[0].payload != "cd /tmp\n" {
		t.Fatalf("region payload = %q, want the unchanged fence body", after[0].payload)
	}
	text := a.TranscriptText()
	if got := text[after[0].start:after[0].end]; got != statusCopyControl {
		t.Fatalf("region spans %q in the current text, want %q", got, statusCopyControl)
	}
}

// TestTranscriptCodeCopy_ControlsComeFromTheRenderer pins where a region may come from: a
// container prefix in front of a generated control is still addressed, while model content
// that reads exactly like a control — inside a fenced body or in the prose around it —
// neither becomes clickable itself nor costs the real control its region.
func TestTranscriptCodeCopy_ControlsComeFromTheRenderer(t *testing.T) {
	t.Run("a block inside a blockquote keeps its control", func(t *testing.T) {
		tr := newTranscript()
		tr.appendDelta("> ```sh\n> make build\n> ```")
		tr.finalize()

		regions := codeRegions(tr.controls.all)
		if len(regions) != 1 || regions[0].payload != "make build\n" {
			t.Fatalf("click regions = %+v, want one carrying the quoted block's body", regions)
		}
		text := tr.view.GetText(true)
		if got := text[regions[0].start:regions[0].end]; got != statusCopyControl {
			t.Fatalf("region spans %q in %q, want %q", got, text, statusCopyControl)
		}
	})

	t.Run("a fenced body that reads as a control copies only from the generated line", func(t *testing.T) {
		a := New(nil)
		a.transcript.appendDelta("note\n\n```\n" + statusCopyControl + "\n```")
		a.transcript.finalize()

		const response = "note\n\n" + statusCopyControl
		hits := transcriptCopyHits(t, a, 40, 8, map[string]string{
			statusCopyControl + "\n": codeCopyNotice,
			response:                 responseCopyNotice,
		})
		if got := hits[statusCopyControl+"\n"]; got != statusCopyControl {
			t.Errorf("the cells that copy spell %q, want only the generated control %q", got, statusCopyControl)
		}
		// The authored copy of the label is the response payload, unchanged: the generated
		// control is excluded by renderer identity, never by matching the label text.
		if got := hits[response]; got != responseCopyControl {
			t.Errorf("the cells that copy the response spell %q, want exactly %q", got, responseCopyControl)
		}
	})

	t.Run("a code-only reply copies the block body from its only control", func(t *testing.T) {
		a := New(nil)
		a.transcript.appendDelta("```sh\nmake build\n```")
		a.transcript.finalize()

		hits := transcriptCopyHits(t, a, 40, 8, map[string]string{
			"make build\n": codeCopyNotice,
		})
		if got := hits["make build\n"]; got != statusCopyControl {
			t.Errorf("the cells that copy spell %q, want only the generated control %q", got, statusCopyControl)
		}
	})

	t.Run("a prose line that reads as a control copies nothing", func(t *testing.T) {
		a := New(nil)
		a.transcript.appendDelta("```sh\nmake build\n```\n\n" + statusCopyControl)
		a.transcript.finalize()

		const response = "make build\n\n" + statusCopyControl
		hits := transcriptCopyHits(t, a, 40, 8, map[string]string{
			"make build\n": codeCopyNotice,
			response:       responseCopyNotice,
		})
		if got := hits["make build\n"]; got != statusCopyControl {
			t.Errorf("the cells that copy spell %q, want only the generated control %q", got, statusCopyControl)
		}
		if got := hits[response]; got != responseCopyControl {
			t.Errorf("the cells that copy the response spell %q, want exactly %q", got, responseCopyControl)
		}
	})
}

func TestTranscriptResponseCopy_EachResponseCopiesOnlyItself(t *testing.T) {
	a := New(nil)
	a.transcript.append("> first question")
	a.transcript.appendDelta("first answer")
	a.transcript.finalize()
	a.transcript.append("> second question")
	a.transcript.appendDelta("second answer")
	a.transcript.finalize()

	hits := transcriptCopyHits(t, a, 40, 12, map[string]string{
		"first answer":  responseCopyNotice,
		"second answer": responseCopyNotice,
	})
	if got := hits["first answer"]; got != responseCopyControl {
		t.Errorf("the cells that copy the first response spell %q, want exactly %q", got, responseCopyControl)
	}
	if got := hits["second answer"]; got != responseCopyControl {
		t.Errorf("the cells that copy the second response spell %q, want exactly %q", got, responseCopyControl)
	}
}

func TestTranscriptResponseCopy_ReportsOutcomeWithoutChangingTheResponse(t *testing.T) {
	// The sealed reply renders as "the answer" on row 0 and the two-space-indented
	// response control on row 1.
	open := func(t *testing.T, sink func(string) error) *App {
		t.Helper()
		a := New(nil)
		a.afterFunc = func(time.Duration, func()) {}
		a.input.osc52 = sink
		a.transcript.appendDelta("the answer")
		a.transcript.finalize()
		drawTranscriptPane(t, a, 40, 8)
		return a
	}
	click := func(a *App) {
		a.handleAppMouse(tcell.NewEventMouse(2, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(nil, tview.MouseLeftUp)
	}
	sealed := "the answer" + visibleResponseLine

	t.Run("emitted", func(t *testing.T) {
		var captured []string
		a := open(t, func(seq string) error { captured = append(captured, seq); return nil })
		click(a)

		if want := osc52Sequence("the answer"); len(captured) != 1 || captured[0] != want {
			t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
		}
		if got := a.NoticeText(); got != responseCopyNotice {
			t.Fatalf("notice = %q, want %q", got, responseCopyNotice)
		}
		if !strings.HasPrefix(a.TranscriptText(), sealed) {
			t.Fatalf("transcript = %q, want the response unchanged at %q", a.TranscriptText(), sealed)
		}
	})

	t.Run("emission failed", func(t *testing.T) {
		a := open(t, func(string) error { return errors.New("stdout is closed") })
		click(a)

		got := a.NoticeText()
		if !strings.HasPrefix(got, copyFailedNoticePrefix) || !strings.Contains(got, "stdout is closed") {
			t.Fatalf("notice = %q, want a %q error naming what failed", got, copyFailedNoticePrefix)
		}
		if got == responseCopyNotice {
			t.Fatalf("notice = %q, want no success report after a failed emission", got)
		}
		if !strings.HasPrefix(a.TranscriptText(), sealed) {
			t.Fatalf("transcript = %q, want the response unchanged at %q", a.TranscriptText(), sealed)
		}
	})
}

// TestTranscriptCodeCopy_WheelAndFollowSurviveControls proves the scroll contract is
// unchanged with regions present: a wheel notch up drops auto-follow and holds the offset
// across a later render, and scrolling back to the bottom resumes following.
func TestTranscriptCodeCopy_WheelAndFollowSurviveControls(t *testing.T) {
	a := New(nil)
	for i := 0; i < 20; i++ {
		a.transcript.appendDelta(fmt.Sprintf("```sh\nline%02d\n```", i))
		a.transcript.finalize()
	}
	drawAppTranscript(t, a, 6)

	a.handleTranscriptMouse(tview.MouseScrollUp, tcell.NewEventMouse(0, 0, tcell.ButtonNone, tcell.ModNone))
	if a.transcript.following {
		t.Fatal("a wheel notch up left auto-follow on")
	}
	held, _ := a.transcript.view.GetScrollOffset()
	a.transcript.append("streamed while scrolled up")
	if row, _ := a.transcript.view.GetScrollOffset(); row != held {
		t.Fatalf("scroll offset = %d after a render while scrolled up, want the held %d", row, held)
	}

	a.transcript.scrollBy(transcriptWheelStep * 20)
	if !a.transcript.following {
		t.Fatal("scrolling back to the bottom did not resume auto-follow")
	}
}

// TestTranscriptSelection_HighlightClearsOnReleaseAfterScroll proves Done-when 1 on a
// scrolled transcript: the highlight shows while dragging on a scrolled-into-view row,
// and the release both copies the text and clears the highlight so nothing lingers on
// the next draw. This supersedes the earlier "selection survives until new output" behavior
// — the range is now zeroed on release, so there is no post-release highlight to track
// across a scroll.
func TestTranscriptSelection_HighlightClearsOnReleaseAfterScroll(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	for i := 0; i < 40; i++ {
		a.transcript.append(fmt.Sprintf("line%02d", i))
	}
	drawAppTranscript(t, a, 6)
	a.input.SetRect(0, 20, 40, 3)

	// Select a few characters on a visible text row (row 0 is a blank block-gap row
	// once the view is scrolled to the bottom, so use y=1).
	a.handleAppMouse(tcell.NewEventMouse(0, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(3, 1, tcell.Button1, tcell.ModNone), tview.MouseMove)
	if rev := reverseText(t, a.transcript.view, 40, 6); rev == "" {
		t.Fatal("no highlight while dragging on a scrolled row")
	}

	a.handleAppMouse(tcell.NewEventMouse(3, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)
	if len(captured) != 1 || captured[0] == osc52Sequence("") {
		t.Fatalf("osc52 sink = %q, want one non-empty copy on release", captured)
	}
	if rev := reverseText(t, a.transcript.view, 40, 6); rev != "" {
		t.Fatalf("post-release highlight = %q, want it cleared", rev)
	}
}

// TestTranscriptSelection_WheelStillScrollsDuringNoSelection proves Done-when 3: with
// the selection capture in place, a wheel notch over the transcript still scrolls it
// and is consumed (the app capture passes the wheel through to handleTranscriptMouse).
func TestTranscriptSelection_WheelStillScrolls(t *testing.T) {
	a := New(nil)
	fillTranscript(a.transcript, 40)
	drawAppTranscript(t, a, 5)

	// The app-level capture must pass the wheel through unchanged.
	wheel := tcell.NewEventMouse(1, 1, tcell.WheelUp, tcell.ModNone)
	if ev, act := a.handleAppMouse(wheel, tview.MouseScrollUp); ev != wheel || act != tview.MouseScrollUp {
		t.Fatalf("app capture changed the wheel event = (%v,%v), want it passed through", ev, act)
	}
	// And the transcript capture still scrolls on it.
	action, event := a.handleTranscriptMouse(tview.MouseScrollUp, wheel)
	if action != tview.MouseConsumed || event != nil {
		t.Fatalf("wheel over transcript = (%v,%v), want (MouseConsumed,nil)", action, event)
	}
	if a.transcript.following {
		t.Fatal("wheel up over the transcript did not disable auto-follow")
	}
}

// TestTranscriptSelection_ShiftDragPassesThroughForNativeSelection proves the
// escape hatch: a Shift-modified transcript drag is never captured into the app-owned
// selection. The Shift+down is passed through unchanged (so the terminal's native
// selection can own it where the terminal delivers the event to the app), no selection
// starts, and the follow-up Shift+move/Shift+up copy nothing through OSC 52. Removing
// the ModShift guard in handleAppMouse makes the down start a selection and nils the
// passed-through event, so the first assertion fails.
func TestTranscriptSelection_ShiftDragPassesThroughForNativeSelection(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.transcript.append("hello")
	a.transcript.append("world")
	drawAppTranscript(t, a, 10) // rows: "hello"@0, ""@1, "world"@2; no scroll
	a.input.SetRect(0, 20, 40, 3)

	down := tcell.NewEventMouse(0, 0, tcell.Button1, tcell.ModShift)
	event, action := a.handleAppMouse(down, tview.MouseLeftDown)
	if event != down || action != tview.MouseLeftDown {
		t.Fatalf("Shift+down over transcript = (%v,%v), want it passed through for native terminal selection", event, action)
	}
	if a.transcript.isSelecting() {
		t.Fatal("Shift+down started an app-owned transcript selection; Shift must defer to native terminal selection")
	}

	a.handleAppMouse(tcell.NewEventMouse(5, 0, tcell.Button1, tcell.ModShift), tview.MouseMove)
	a.handleAppMouse(tcell.NewEventMouse(5, 0, tcell.Button1, tcell.ModShift), tview.MouseLeftUp)

	if len(captured) != 0 {
		t.Fatalf("a Shift+drag copied %q through OSC 52, want nothing (native selection owns it)", captured)
	}
	if rev := reverseText(t, a.transcript.view, 40, 10); rev != "" {
		t.Fatalf("a Shift+drag highlighted %q, want nothing", rev)
	}
}

// TestTranscriptSelection_InputClickUnaffected proves Done-when 4: a left-click on the
// input row is handled by the input selection path and does not start a transcript selection.
func TestTranscriptSelection_InputClickUnaffected(t *testing.T) {
	a := New(nil)
	a.input.SetText("hello world")
	drawPrimitive(t, a.input, 40, 3)

	inside := tcell.NewEventMouse(5, 1, tcell.Button1, tcell.ModNone)
	event, action := a.handleAppMouse(inside, tview.MouseLeftDown)
	if event != nil || action != tview.MouseLeftDown {
		t.Fatalf("input-row click = (%v,%v), want it consumed by input selection", event, action)
	}
	if a.transcript.isSelecting() {
		t.Fatal("an input-row click started a transcript selection")
	}
}

// TestTranscriptSelection_DragScrollsPastVisibleRows proves the transcript drag-scroll twin: a
// plain drag held on the bottom visible row of the conversation pane scrolls it on the
// timer so the selection extends past the initially visible rows, then copies the whole
// span on release. Mirrors TestInputSelection_AppOwnedDragScrollsPastVisibleRows.
func TestTranscriptSelection_DragScrollsPastVisibleRows(t *testing.T) {
	const height = 6
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	for i := 0; i < 40; i++ {
		a.transcript.append(fmt.Sprintf("L%02d", i))
	}
	var timers []func()
	a.afterFunc = func(_ time.Duration, f func()) { timers = append(timers, f) }
	drawAppTranscript(t, a, height)
	a.input.SetRect(0, 20, 40, 3)

	// Scroll to the top so there is conversation below the viewport to reveal.
	a.transcript.scrollBy(-1000)
	drawAppTranscript(t, a, height)
	if row, _ := a.transcript.view.GetScrollOffset(); row != 0 {
		t.Fatalf("precondition: transcript not scrolled to the top (offset=%d)", row)
	}
	_, iy, _, ih := a.transcript.view.GetInnerRect()
	top, below := iy, iy+ih+1 // below = past the last visible row (over the chrome beneath)

	// Press at the top visible row (column 0, anchoring at the first line), then a single
	// move BELOW the pane at column 1 (mid-line) and hold. Column 1 would otherwise stop
	// the copy mid-word on the last line ("L3"); dragging below the pane must take the whole
	// line ("L39").
	a.handleAppMouse(tcell.NewEventMouse(0, top, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(1, below, tcell.Button1, tcell.ModNone), tview.MouseMove)
	if first, _ := a.transcript.view.GetScrollOffset(); first <= 0 {
		t.Fatalf("transcript did not scroll on the below-pane move (offset=%d)", first)
	}

	// Hold: with no further mouse events the scheduled timer ticks must keep scrolling
	// until the pane reaches the bottom (scrollBy re-enables follow at the last row).
	for i := 0; i < len(timers) && i < 300; i++ {
		timers[i]()
		if a.transcript.following {
			break
		}
	}
	if !a.transcript.following {
		row, _ := a.transcript.view.GetScrollOffset()
		t.Fatalf("held transcript drag-scroll did not reach the bottom (offset=%d, following=%v)", row, a.transcript.following)
	}

	// Release: the selection — top of the conversation down to the last revealed line —
	// copies through OSC 52 and clears.
	a.handleAppMouse(tcell.NewEventMouse(1, below, tcell.ButtonNone, tcell.ModNone), tview.MouseLeftUp)
	if len(captured) != 1 {
		t.Fatalf("osc52 sink = %q, want exactly one copy on release", captured)
	}
	if !strings.Contains(a.input.lastCopied, "L00") || !strings.Contains(a.input.lastCopied, "L39") {
		t.Fatalf("copied transcript selection = %q, want it to span L00..L39 in full (scroll past the viewport + whole-line snap below the pane)", a.input.lastCopied)
	}
	if a.transcript.isSelecting() {
		t.Fatal("transcript selection still in progress after release")
	}
}

// TestInputSelection_AppOwnedDragSelectsAndCopies proves the plain input drag path
// without invoking TextArea.MouseHandler: handleAppMouse maps the coordinates, drives
// TextArea.Select itself, copies on release, and clears the highlight.
func TestInputSelection_AppOwnedDragSelectsAndCopies(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.input.SetText("hello world")
	drawPrimitive(t, a.input, 40, 3)

	down := tcell.NewEventMouse(2, 1, tcell.Button1, tcell.ModNone)
	if event, action := a.handleAppMouse(down, tview.MouseLeftDown); event != nil || action != tview.MouseLeftDown {
		t.Fatalf("plain input down = (%v,%v), want consumed MouseLeftDown", event, action)
	}
	move := tcell.NewEventMouse(7, 1, tcell.Button1, tcell.ModNone)
	if event, action := a.handleAppMouse(move, tview.MouseMove); event != nil || action != tview.MouseMove {
		t.Fatalf("plain input move = (%v,%v), want consumed MouseMove", event, action)
	}

	if !a.input.HasSelection() {
		t.Fatal("plain app-owned input drag did not leave a visible TextArea selection")
	}
	if _, start, end := a.input.GetSelection(); a.input.GetText()[start:end] != "hello" {
		t.Fatalf("mid-drag selection = %q, want %q", a.input.GetText()[start:end], "hello")
	}

	up := tcell.NewEventMouse(7, 1, tcell.ButtonNone, tcell.ModNone)
	if event, action := a.handleAppMouse(up, tview.MouseLeftUp); event != nil || action != tview.MouseLeftUp {
		t.Fatalf("plain input up = (%v,%v), want consumed MouseLeftUp", event, action)
	}

	if want := osc52Sequence("hello"); len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
	}
	if a.input.HasSelection() {
		t.Fatal("input selection not collapsed after app-owned release; the highlight would linger")
	}
}

// TestInputSelection_AppOwnedDragScrollsPastVisibleRows pins the real-input bug where
// a plain drag could select only to the bottom of the visible input box. Holding the
// drag on the bottom visible text row now advances TextArea's row offset on a timer and
// remaps the selection against the new viewport, so the range can reach prompt text below it.
func TestInputSelection_AppOwnedDragScrollsPastVisibleRows(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	var timers []func()
	a.afterFunc = func(_ time.Duration, f func()) { timers = append(timers, f) }
	a.input.SetText("zero\none\ntwo\nthree\nfour")
	drawPrimitive(t, a.input, 20, 3) // top/bottom rules + one visible text row.
	a.input.SetOffset(0, 0)

	down := tcell.NewEventMouse(2, 1, tcell.Button1, tcell.ModNone)
	if event, action := a.handleAppMouse(down, tview.MouseLeftDown); event != nil || action != tview.MouseLeftDown {
		t.Fatalf("plain input down = (%v,%v), want consumed MouseLeftDown", event, action)
	}
	bottom := tcell.NewEventMouse(6, 3, tcell.Button1, tcell.ModNone)
	if event, action := a.handleAppMouse(bottom, tview.MouseMove); event != nil || action != tview.MouseMove {
		t.Fatalf("plain input bottom move = (%v,%v), want consumed MouseMove", event, action)
	}
	if row, _ := a.input.GetOffset(); row != 1 {
		t.Fatalf("input row offset after first bottom move = %d, want 1", row)
	}
	for row, timerIdx := 1, 0; row < 4; row, timerIdx = row+1, timerIdx+1 {
		if len(timers) <= timerIdx {
			t.Fatalf("scheduled timers after row offset %d = %d, want at least %d", row, len(timers), timerIdx+1)
		}
		timers[timerIdx]()
	}

	if row, _ := a.input.GetOffset(); row != 4 {
		t.Fatalf("input row offset after timer-driven bottom scroll = %d, want 4", row)
	}
	_, start, end := a.input.GetSelection()
	if got := a.input.GetText()[start:end]; got != "zero\none\ntwo\nthree\nfour" {
		t.Fatalf("drag-scrolled selection = %q, want full input", got)
	}

	up := tcell.NewEventMouse(6, 3, tcell.ButtonNone, tcell.ModNone)
	if event, action := a.handleAppMouse(up, tview.MouseLeftUp); event != nil || action != tview.MouseLeftUp {
		t.Fatalf("plain input up = (%v,%v), want consumed MouseLeftUp", event, action)
	}
	if want := osc52Sequence("zero\none\ntwo\nthree\nfour"); len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
	}
	if a.input.HasSelection() {
		t.Fatal("drag-scrolled input selection not collapsed after release")
	}
}

// TestInputSelection_RunningAppDragScrollTimerContinuesWithoutMouseMove drives the
// running event loop: after one bottom-edge mouse move, timer ticks continue scrolling
// the input selection without additional mouse events. This is the terminal behavior a
// user sees when holding the mouse at the bottom of a scrollable input.
func TestInputSelection_RunningAppDragScrollTimerContinuesWithoutMouseMove(t *testing.T) {
	h := newLayoutHarness(t, 20, 12)
	defer h.stop()

	timers := make(chan func(), 8)
	var captured []string
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = fmt.Sprintf("line%02d", i)
	}
	inputText := strings.Join(lines, "\n")
	h.update(func() {
		h.screen.SetSize(20, 12)
		h.a.afterFunc = func(_ time.Duration, f func()) { timers <- f }
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		h.a.input.SetText(inputText)
		h.a.input.Select(0, 0)
		h.a.input.SetOffset(0, 0)
	})

	var ix, iy int
	var ih int
	h.a.app.QueueUpdate(func() { ix, iy, _, ih = h.a.input.GetRect() })
	_, screenH := h.screen.Size()
	textY := iy + 1
	startX, bottomX := ix+2, ix+19

	h.injectMouse(startX, textY, tcell.Button1)
	var selecting bool
	h.a.app.QueueUpdate(func() { selecting = h.a.inputSelecting })
	if !selecting {
		t.Fatal("inputSelecting is false after input mouse down")
	}
	h.injectMouse(bottomX, screenH-1, tcell.Button1)
	var firstRow int
	var innerY, innerH int
	h.a.app.QueueUpdate(func() {
		firstRow, _ = h.a.input.GetOffset()
		_, innerY, _, innerH = h.a.input.GetInnerRect()
	})
	visibleH := innerH
	if innerY+visibleH > screenH {
		visibleH = screenH - innerY
	}
	maxOffset := len(lines) - visibleH
	if maxOffset < 2 {
		t.Fatalf("test setup produced max input row offset %d, want at least 2 (inner h=%d visible h=%d)", maxOffset, innerH, visibleH)
	}
	if firstRow <= 0 {
		t.Fatalf("input row offset after bottom-edge move = %d, want forward scroll (outer y=%d h=%d, inner y=%d h=%d, event y=%d screen h=%d)", firstRow, iy, ih, innerY, innerH, screenH-1, screenH)
	}

	prevRow := firstRow
	for prevRow < maxOffset {
		select {
		case tick := <-timers:
			tick()
		case <-time.After(2 * time.Second):
			t.Fatal("input drag scroll timer was not scheduled")
		}
		var row int
		h.a.app.QueueUpdate(func() { row, _ = h.a.input.GetOffset() })
		if row <= prevRow {
			t.Fatalf("input row offset after timer tick = %d, want greater than %d", row, prevRow)
		}
		prevRow = row
	}

	// Release at the held bottom edge (not back up at the top text row) so the button-up
	// does not first re-extend the selection to the top visible line: with the input now
	// more than one text row tall (a chrome row was reclaimed), releasing at the top row
	// would shrink the captured selection, whereas the drag's intent is the full buffer.
	h.injectMouse(bottomX, screenH-1, tcell.ButtonNone)

	var got []string
	var finalRow int
	h.a.app.QueueUpdate(func() {
		finalRow, _ = h.a.input.GetOffset()
		got = append([]string(nil), captured...)
	})
	if want := osc52Sequence(inputText); len(got) != 1 || got[0] != want {
		t.Fatalf("final row offset = %d; osc52 sink = %q, want exactly one %q", finalRow, got, want)
	}
}

// inputSelText returns the input's currently selected substring, read on the
// event-loop goroutine so it never races the draw.
func inputSelText(h *layoutHarness) string {
	var s string
	h.a.app.QueueUpdate(func() {
		_, start, end := h.a.input.GetSelection()
		s = h.a.input.GetText()[start:end]
	})
	return s
}

// inputRowOffset returns the input's current vertical scroll row, read on the
// event-loop goroutine.
func inputRowOffset(h *layoutHarness) int {
	var row int
	h.a.app.QueueUpdate(func() { row, _ = h.a.input.GetOffset() })
	return row
}

// TestInputSelection_TailViewClickKeepsViewportAndDragGrows reproduces the
// regression the live terminal showed: a multi-line draft taller than the input box
// shows its TAIL (cursor parked at end, as a paste/type leaves it), and the before-draw
// realignment (adjustRowOffset) used to fight an app-owned drag. Clicking the top
// visible row to start a selection snapped the whole viewport to the cursor — jumping the
// view to the buffer head — so the anchor jumped to the box bottom and dragging "down"
// shrank the selection toward it instead of extending it. The drag now owns the row
// offset while it is active, so the click leaves the viewport put and the downward drag
// grows the selection monotonically from the clicked row. It drives the real running app
// so the before-draw hook (and adjustRowOffset) actually runs — the failure mode only
// appears through that hook, which the SetRect-only tests never exercise.
func TestInputSelection_TailViewClickKeepsViewportAndDragGrows(t *testing.T) {
	const W, H = 40, 24
	h := newLayoutHarness(t, W, H)
	defer h.stop()

	lines := make([]string, 25)
	for i := range lines {
		lines[i] = fmt.Sprintf("line%02d", i)
	}
	var captured []string
	h.update(func() {
		h.screen.SetSize(W, H)
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		// A filled transcript pushes the input box down to the bottom of the screen, just
		// above the status/mode-hint chrome — the everyday layout once a conversation runs.
		for i := 0; i < 60; i++ {
			h.a.transcript.append(fmt.Sprintf("transcript%02d", i))
		}
		h.a.input.SetText(strings.Join(lines, "\n"))
		// Cursor stays at end-of-buffer, so the input shows the tail (the realistic state).
	})

	var inX, inY, inH int
	h.a.app.QueueUpdate(func() { inX, inY, _, inH = h.a.input.GetInnerRect() })
	tailOffset := inputRowOffset(h)
	if tailOffset == 0 {
		t.Fatalf("precondition: input is not scrolled to its tail (offset=%d, inner h=%d); the regression needs a scrollable, tail-showing input", tailOffset, inH)
	}
	textTop, textBottom := inY, inY+inH-1
	startX := inX + 2 // column 0 of the text, past the "> " label
	dragX := inX + 20 // a column past the end of every short line, so the drag spans whole lines

	// Press on the top visible text row. The viewport must NOT move: before the fix the
	// before-draw realignment snapped it to the buffer head (offset 0).
	h.injectMouse(startX, textTop, tcell.Button1)
	if got := inputRowOffset(h); got != tailOffset {
		t.Fatalf("input row offset after click on the tail view = %d, want it unchanged at %d (adjustRowOffset must not snap the viewport during an app-owned drag)", got, tailOffset)
	}
	var anchor int
	h.a.app.QueueUpdate(func() { _, anchor, _ = h.a.input.GetSelection() })

	// Drag straight down through the visible rows. The selection must grow monotonically
	// and keep its anchor fixed (the press point), the opposite of the shrink-toward-a-
	// jumped-anchor the bug produced.
	prevLen := 0
	for y := textTop + 1; y <= textBottom; y++ {
		h.injectMouse(dragX, y, tcell.Button1)
		if got := inputRowOffset(h); got != tailOffset {
			t.Fatalf("input row offset during downward drag at y=%d = %d, want it held at %d", y, got, tailOffset)
		}
		var selStart int
		h.a.app.QueueUpdate(func() { _, selStart, _ = h.a.input.GetSelection() })
		if selStart != anchor {
			t.Fatalf("selection anchor moved during drag at y=%d: start=%d, want fixed at %d", y, selStart, anchor)
		}
		curLen := len(inputSelText(h))
		if curLen < prevLen {
			t.Fatalf("selection shrank during downward drag at y=%d: len=%d, want >= %d (the drag must extend, not collapse toward a jumped anchor)", y, curLen, prevLen)
		}
		prevLen = curLen
	}

	// Release on the bottom row: the selection — the visible tail from the clicked row to
	// the last line — copies through OSC 52 and the highlight clears.
	want := inputSelText(h)
	h.injectMouse(dragX, textBottom, tcell.ButtonNone)
	var endHasSel bool
	var got []string
	h.a.app.QueueUpdate(func() {
		endHasSel = h.a.input.HasSelection()
		got = append([]string(nil), captured...)
	})
	if len(got) != 1 || got[0] != osc52Sequence(want) {
		t.Fatalf("osc52 sink = %q, want exactly one copy of the dragged tail %q", got, want)
	}
	if endHasSel {
		t.Fatal("input selection not cleared on release; the highlight would linger")
	}
	if !strings.HasSuffix(want, "line24") {
		t.Fatalf("dragged tail selection = %q, want it to reach the last line", want)
	}
}

// TestInputSelection_HoldAtBoxBottomScrollsDown pins the headline drag auto-scroll behavior through
// the real event loop: with the input scrolled to its head, a plain drag held on the box's
// own bottom text row (not the screen edge) auto-scrolls the viewport downward on the timer
// — with no further mouse motion — until the selection reaches the last line, then copies
// it on release. The before-draw hook runs here, so it also guards that adjustRowOffset no
// longer caps the scroll short or jumps the viewport mid-drag.
func TestInputSelection_HoldAtBoxBottomScrollsDown(t *testing.T) {
	const W, H = 40, 24
	h := newLayoutHarness(t, W, H)
	defer h.stop()

	timers := make(chan func(), 64)
	lines := make([]string, 25)
	for i := range lines {
		lines[i] = fmt.Sprintf("line%02d", i)
	}
	var captured []string
	h.update(func() {
		h.screen.SetSize(W, H)
		h.a.afterFunc = func(_ time.Duration, f func()) { timers <- f }
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		for i := 0; i < 60; i++ {
			h.a.transcript.append(fmt.Sprintf("transcript%02d", i))
		}
		h.a.input.SetText(strings.Join(lines, "\n"))
		h.a.input.Select(0, 0) // park the cursor at the head so the view starts at the top
	})

	var inX, inY, inH int
	h.a.app.QueueUpdate(func() { inX, inY, _, inH = h.a.input.GetInnerRect() })
	if got := inputRowOffset(h); got != 0 {
		t.Fatalf("precondition: input row offset = %d, want it at the head (0)", got)
	}
	maxOffset := len(lines) - inH
	if maxOffset < 2 {
		t.Fatalf("test setup produced max offset %d, want >= 2 (inner h=%d)", maxOffset, inH)
	}
	textTop, textBottom := inY, inY+inH-1
	startX := inX + 2 // column 0 of the text, past the "> " label
	dragX := inX + 20 // a column past every short line's end, so the drag spans whole lines

	// Press at the head, then a single move onto the box's own bottom text row and hold.
	h.injectMouse(startX, textTop, tcell.Button1)
	h.injectMouse(dragX, textBottom, tcell.Button1)
	first := inputRowOffset(h)
	if first <= 0 {
		t.Fatalf("input row offset after the bottom-row move = %d, want a forward scroll", first)
	}

	// Hold: with no further mouse events the scheduled timer ticks must keep scrolling.
	prev := first
	for prev < maxOffset {
		select {
		case tick := <-timers:
			tick()
		case <-time.After(2 * time.Second):
			t.Fatalf("input drag-scroll timer stopped at offset %d before reaching max %d", prev, maxOffset)
		}
		row := inputRowOffset(h)
		if row <= prev {
			t.Fatalf("held drag-scroll did not advance: offset=%d, want > %d", row, prev)
		}
		prev = row
	}
	if got := inputSelText(h); !strings.HasSuffix(got, "line24") {
		t.Fatalf("held drag-scroll selection = %q, want it to reach the last line", got)
	}

	h.injectMouse(dragX, textBottom, tcell.ButtonNone)
	var endHasSel bool
	var got []string
	h.a.app.QueueUpdate(func() {
		endHasSel = h.a.input.HasSelection()
		got = append([]string(nil), captured...)
	})
	if want := osc52Sequence(strings.Join(lines, "\n")); len(got) != 1 || got[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one copy of the full buffer", got)
	}
	if endHasSel {
		t.Fatal("input selection not cleared on release after a held drag-scroll")
	}
}

// TestInputSelection_NativeShiftDragReleaseCopiesAndClears proves the preserved native
// release half: when a Shift-drag leaves a TextArea selection, handleAppMouse copies the
// selected text through OSC 52, collapses the highlight, and still passes the event
// through so TextArea resets its own drag state.
func TestInputSelection_NativeShiftDragReleaseCopiesAndClears(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.input.SetText("hello world")
	drawPrimitive(t, a.input, 40, 3) // lay out the buffer so Select resolves positions
	a.input.Select(0, 5)             // the selection a plain drag over "hello" leaves
	if !a.input.HasSelection() {
		t.Fatal("precondition: input has no selection after Select(0,5)")
	}

	a.inputDragging = true
	up := tcell.NewEventMouse(3, 1, tcell.Button1, tcell.ModShift) // inside the input rect
	event, action := a.handleAppMouse(up, tview.MouseLeftUp)
	if event != up || action != tview.MouseLeftUp {
		t.Fatalf("input-rect up = (%v,%v), want it passed through to the TextArea", event, action)
	}

	if want := osc52Sequence("hello"); len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
	}
	if a.input.lastCopied != "hello" {
		t.Fatalf("lastCopied = %q, want %q (the in-app paste source updates like Ctrl-Q)", a.input.lastCopied, "hello")
	}
	if a.input.HasSelection() {
		t.Fatal("input selection not collapsed after release; the highlight would linger")
	}
}

// TestInputSelection_PlainDragSelectsAndCopies proves the plain input drag
// end-to-end by driving a real tview.Application on a simulation screen: a plain (no-Shift) left
// drag inside the input is injected as actual queued mouse events, so it routes
// through the running event loop's fireMouseActions, the installed app-level capture
// (handleAppMouse), and Flex hit-testing. The drag is app-owned: handleAppMouse drives
// TextArea.Select directly, then copies the selection through OSC 52 and clears it on
// release.
func TestInputSelection_PlainDragSelectsAndCopies(t *testing.T) {
	h := newLayoutHarness(t, 80, 25)
	defer h.stop()

	// Seed the buffer and the OSC 52 capture on the event-loop goroutine so they are
	// in place before any injected event reaches the input, and so the slice is only
	// touched from that goroutine.
	var captured []string
	h.update(func() {
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		h.a.input.SetText("hello world")
	})

	// Read the input's drawn rect to address the real text row. The custom draw func
	// puts the top rule on row iy and the first text row on iy+1; the "> " label
	// occupies the first two columns, so 'h' sits at ix+2 and dragging to ix+7 spans
	// "hello".
	var ix, iy int
	h.a.app.QueueUpdate(func() { ix, iy, _, _ = h.a.input.GetRect() })
	textY := iy + 1
	hX, endX := ix+2, ix+7

	// Inject a real left-press, a drag move with the button still held, and a release —
	// the loop's fireMouseActions derives MouseLeftDown, then MouseMove (button held =
	// drag), then MouseLeftUp from these and routes each through the production path.
	h.injectMouse(hX, textY, tcell.Button1)
	h.injectMouse(endX, textY, tcell.Button1)

	var midHasSel bool
	var midSel string
	h.a.app.QueueUpdate(func() {
		midHasSel = h.a.input.HasSelection()
		if _, s, e := h.a.input.GetSelection(); midHasSel {
			midSel = h.a.input.GetText()[s:e]
		}
	})
	if !midHasSel {
		t.Fatal("plain drag through the running app did not engage the app-owned input selection")
	}
	if midSel != "hello" {
		t.Fatalf("mid-drag selection = %q, want %q", midSel, "hello")
	}

	h.injectMouse(endX, textY, tcell.ButtonNone)

	var endHasSel bool
	var got []string
	h.a.app.QueueUpdate(func() {
		endHasSel = h.a.input.HasSelection()
		got = append([]string(nil), captured...)
	})
	if want := osc52Sequence("hello"); len(got) != 1 || got[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q on release through the running app", got, want)
	}
	if endHasSel {
		t.Fatal("input selection not cleared on release; the highlight would linger")
	}
}

// TestInputSelection_DragReleaseOutsideInputCopiesAndClears proves the release-
// outside-the-input contract: a left drag that begins inside the input but releases
// outside its rect must still copy the selection through OSC 52, clear the highlight,
// and end the app-owned drag — so a later plain mouse move does not keep extending a
// stale selection. It drives the real running tview.Application through injected events.
func TestInputSelection_DragReleaseOutsideInputCopiesAndClears(t *testing.T) {
	h := newLayoutHarness(t, 80, 25)
	defer h.stop()

	var captured []string
	h.update(func() {
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		h.a.input.SetText("hello world")
	})

	var ix, iy int
	h.a.app.QueueUpdate(func() { ix, iy, _, _ = h.a.input.GetRect() })
	textY := iy + 1
	hX, endX := ix+2, ix+7
	// A row above the input's top rule is outside inInputRect (y < iy) but still inside
	// the screen, so the drag-out and release route through handleAppMouse, not off-screen.
	outsideY := iy - 1

	// Press inside the input and drag to the end of "hello" so the app-owned input
	// selection engages, exactly as the plain-drag test does.
	h.injectMouse(hX, textY, tcell.Button1)
	h.injectMouse(endX, textY, tcell.Button1)

	var midSel string
	h.a.app.QueueUpdate(func() {
		if _, s, e := h.a.input.GetSelection(); h.a.input.HasSelection() {
			midSel = h.a.input.GetText()[s:e]
		}
	})
	if midSel != "hello" {
		t.Fatalf("mid-drag selection = %q, want %q", midSel, "hello")
	}

	// Release outside the input rect: the loop derives a MouseMove out of the rect and
	// then the MouseLeftUp the fix must finish — copy and collapse.
	h.injectMouse(endX, outsideY, tcell.ButtonNone)

	var afterReleaseHasSel bool
	var got []string
	h.a.app.QueueUpdate(func() {
		afterReleaseHasSel = h.a.input.HasSelection()
		got = append([]string(nil), captured...)
	})
	if want := osc52Sequence("hello"); len(got) != 1 || got[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q on outside release through the running app", got, want)
	}
	if afterReleaseHasSel {
		t.Fatal("input selection not cleared on outside release; the highlight would linger")
	}

	// A later plain mouse move over the input must not re-open a selection: the fix ends
	// the app-owned drag on release, so without a held button the move is inert.
	// (Inert means unconsumed and so drawless — injectMouseQuiet forces the draw the
	// move itself would not, where the stranded-drag bug would consume it and redraw.)
	h.injectMouseQuiet(hX, textY, tcell.ButtonNone)

	var staleHasSel bool
	var afterMove []string
	h.a.app.QueueUpdate(func() {
		staleHasSel = h.a.input.HasSelection()
		afterMove = append([]string(nil), captured...)
	})
	if staleHasSel {
		t.Fatal("a later mouse move re-opened the selection; the app-owned input drag was left active after the outside release")
	}
	if len(afterMove) != 1 {
		t.Fatalf("osc52 sink = %q after a later move, want still exactly one copy", afterMove)
	}
}

// TestInputSelection_ShiftDragSelectsAndCopies pins the preserved-behaviour
// contract that Shift+drag in the input still selects, copies on release, and clears —
// the sibling of the plain-drag case above. It drives the same running tview.Application
// route (real injected events through fireMouseActions, handleAppMouse, Flex hit-testing,
// the TextArea's MouseHandler), but stamps tcell.ModShift on the down/move/up. The input
// rect is passed through on MouseLeftDown before handleAppMouse's Shift guard (which only
// diverts transcript presses to the terminal), so the Shift-modified drag must drive the
// TextArea's native selection and the app-level MouseLeftUp must copy through OSC 52 and
// collapse it exactly as the plain drag does. Injecting through the loop (not the widget
// handler directly) means the test fails if the real app stops delivering the Shift-
// modified MouseMove/MouseLeftUp to the input.
func TestInputSelection_ShiftDragSelectsAndCopies(t *testing.T) {
	h := newLayoutHarness(t, 80, 25)
	defer h.stop()

	var captured []string
	h.update(func() {
		h.a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
		h.a.input.SetText("hello world")
		// Anchor the cursor at the start: a TextArea Shift+drag extends from the existing
		// cursor (which SetText leaves at end-of-buffer), not from the click point, so
		// without this the Shift+drag would select toward the end instead of "hello".
		h.a.input.Select(0, 0)
	})

	var ix, iy int
	h.a.app.QueueUpdate(func() { ix, iy, _, _ = h.a.input.GetRect() })
	textY := iy + 1
	hX, endX := ix+2, ix+7

	h.injectMouseMod(hX, textY, tcell.Button1, tcell.ModShift)
	h.injectMouseMod(endX, textY, tcell.Button1, tcell.ModShift)

	var midHasSel bool
	var midSel string
	h.a.app.QueueUpdate(func() {
		midHasSel = h.a.input.HasSelection()
		if _, s, e := h.a.input.GetSelection(); midHasSel {
			midSel = h.a.input.GetText()[s:e]
		}
	})
	if !midHasSel {
		t.Fatal("Shift+drag through the running app did not engage the TextArea native selection")
	}
	if midSel != "hello" {
		t.Fatalf("mid-drag selection = %q, want %q", midSel, "hello")
	}

	h.injectMouseMod(endX, textY, tcell.ButtonNone, tcell.ModShift)

	var endHasSel bool
	var got []string
	h.a.app.QueueUpdate(func() {
		endHasSel = h.a.input.HasSelection()
		got = append([]string(nil), captured...)
	})
	if want := osc52Sequence("hello"); len(got) != 1 || got[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q on Shift+drag release through the running app", got, want)
	}
	if endHasSel {
		t.Fatal("input selection not cleared on Shift+drag release; the highlight would linger")
	}
}

// TestInputSelection_PlainClickLeavesNoSelection proves the click-without-drag rule: a plain
// single click in the input (down then up at the same point, no drag) places the cursor
// without leaving a selection and copies nothing — handleAppMouse must not treat a
// no-selection input release as a copy.
func TestInputSelection_PlainClickLeavesNoSelection(t *testing.T) {
	a := New(nil)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	a.input.SetText("hello world")
	drawPrimitive(t, a.input, 40, 3)

	route := func(action tview.MouseAction) {
		if ev, act := a.handleAppMouse(tcell.NewEventMouse(4, 1, tcell.Button1, tcell.ModNone), action); ev != nil || act != action {
			t.Fatalf("plain click %v = (%v,%v), want consumed action", action, ev, act)
		}
	}
	route(tview.MouseLeftDown)
	route(tview.MouseLeftUp)

	if len(captured) != 0 {
		t.Fatalf("a plain input click copied %q, want nothing", captured)
	}
	if a.input.HasSelection() {
		t.Fatal("a plain input click left a selection, want the cursor placed with no selection")
	}
}

func paneRows(t *testing.T, a *App, width, height int) []string {
	t.Helper()
	cells, w, h := drawTranscriptPane(t, a, width, height).GetContents()
	var rows []string
	for y := 0; y < h; y++ {
		var row strings.Builder
		for x := 0; x < w; x++ {
			if r := cells[y*w+x].Runes; len(r) > 0 {
				row.WriteString(string(r))
			} else {
				row.WriteByte(' ')
			}
		}
		rows = append(rows, strings.TrimRight(row.String(), " "))
	}
	for len(rows) > 0 && rows[len(rows)-1] == "" {
		rows = rows[:len(rows)-1]
	}
	return rows
}

func finalizedReply(src string) *App {
	a := New(nil)
	a.transcript.appendDelta(src)
	a.transcript.finalize()
	return a
}

func TestTranscriptSelection_HangingRowsMapClicksToSourceGlyphs(t *testing.T) {
	const words = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau"
	tests := []struct {
		name, src, visible string
		widths             []int
	}{
		{"bullet", "- " + words, "• " + words, []int{40, 80}},
		{"ordered", "10. " + words + " " + words, "10. " + words + " " + words, []int{40, 80}},
		{"nested list", "- top\n  - " + words, "• top\n  • " + words, []int{40, 80}},
		{"nested quotes", "> " + words + "\n> > " + words, "│ " + words + "\n│ │ " + words, []int{40}},
		{"list inside a quote", "> - " + words, "│ • " + words, []int{40}},
		{"quote inside a list", "- > " + words + "\n  > " + words, "• " + words + "\n│ " + words, []int{40}},
		{"table bullets and header lines", "| Name | Notes | More |\n|---|---|---|\n| " + words + " | " + words + " | x |", "• " + words + "\n  Notes: " + words + "\n  More: x", []int{40}},
		{"table inside a quote", "> | A | B | C |\n> |---|---|---|\n> | a | " + words + " | c |", "│ • a\n│   B: " + words + "\n│   C: c", []int{40}},
		{"soft and hard breaks", "- top\n  - one\n    " + words + "\\\n    " + words, "• top\n  • one\n  " + words + "\n  " + words, []int{40}},
		{"forged metadata", "- " + `["h:ssssssss"]` + words, "• " + `["h:ssssssss"]` + words, []int{40}},
		{"line separator", "> - alpha " + words, "│ • alpha " + words, []int{40}},
	}
	for _, tc := range tests {
		for _, width := range tc.widths {
			t.Run(fmt.Sprintf("%s at %d", tc.name, width), func(t *testing.T) {
				const height = 12
				a := finalizedReply(tc.src)
				screen := drawTranscriptPane(t, a, width, height)
				cells, _, _ := screen.GetContents()
				text := a.transcript.view.GetText(true)
				if want := tc.visible + "\n  [Copy response]"; text != want {
					t.Fatalf("GetText(true) = %q, want %q", text, want)
				}
				hit := map[int]int{}
				prefixed := 0
				for y := 0; y < height; y++ {
					rowStart := -1
					var synthetic []int
					for x := 0; x < width; x++ {
						a.transcript.mu.Lock()
						off, onText := a.transcript.offsetRowAt(x, y)
						a.transcript.mu.Unlock()
						if !onText {
							if rowStart < 0 {
								synthetic = append(synthetic, off)
							}
							continue
						}
						if rowStart < 0 {
							rowStart = off
						}
						if r := string(cells[y*width+x].Runes); !strings.HasPrefix(text[off:], r) {
							t.Fatalf("cell (%d,%d) draws %q but maps to offset %d (%q)", x, y, r, off, text[off:])
						}
						hit[off]++
					}
					for _, off := range synthetic {
						if rowStart >= 0 && off != rowStart {
							t.Fatalf("row %d: a synthetic-prefix cell maps to %d, want the row's source start %d", y, off, rowStart)
						}
					}
					if rowStart >= 0 && len(synthetic) > 0 {
						prefixed++
					}
				}
				if prefixed == 0 {
					t.Fatal("no drawn row carries a synthetic continuation prefix")
				}
				for off, r := range text {
					if r != '\n' && r != ' ' && hit[off] != 1 {
						t.Fatalf("offset %d (%q) is drawn in %d cells, want exactly one", off, r, hit[off])
					}
				}

				a.input.osc52 = func(string) error { return nil }
				a.transcript.beginSelect(0, 0)
				a.transcript.updateSelect(width, height-1)
				if got := a.transcript.endSelect(); got != text {
					t.Fatalf("drag copy = %q, want the logical text %q", got, text)
				}
			})
		}
	}
}

func TestTranscriptSelection_HangingHighlightSkipsSyntheticPrefix(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		press, move  [2]int
		copied       string
		reversedCols map[int][2]int
	}{
		{
			name:   "two-cell bullet indent",
			src:    "- alpha beta gamma delta epsilon zeta eta theta iota",
			press:  [2]int{13, 0},
			move:   [2]int{6, 1},
			copied: "gamma delta epsilon zeta eta ",
			reversedCols: map[int][2]int{
				0: {13, 37},
				1: {2, 5},
			},
		},
		{
			name:   "four-cell quoted bullet indent",
			src:    "> - alpha beta gamma delta epsilon zeta eta theta iota",
			press:  [2]int{15, 0},
			move:   [2]int{8, 1},
			copied: "gamma delta epsilon zeta eta ",
			reversedCols: map[int][2]int{
				0: {15, 39},
				1: {4, 7},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const width, height = 40, 6
			a := finalizedReply(tc.src)
			var captured []string
			a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
			drawTranscriptPane(t, a, width, height)
			a.handleAppMouse(tcell.NewEventMouse(tc.press[0], tc.press[1], tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
			a.handleAppMouse(tcell.NewEventMouse(tc.move[0], tc.move[1], tcell.Button1, tcell.ModNone), tview.MouseMove)

			cells, _, _ := drawTranscriptPane(t, a, width, height).GetContents()
			for y := 0; y < height; y++ {
				span, selected := tc.reversedCols[y]
				for x := 0; x < width; x++ {
					_, _, attr := cells[y*width+x].Style.Decompose()
					want := selected && x >= span[0] && x <= span[1]
					if got := attr&tcell.AttrReverse != 0; got != want {
						t.Fatalf("cell (%d,%d) %q reverse = %v, want %v", x, y, string(cells[y*width+x].Runes), got, want)
					}
				}
			}

			a.handleAppMouse(tcell.NewEventMouse(tc.move[0], tc.move[1], tcell.Button1, tcell.ModNone), tview.MouseLeftUp)
			if want := osc52Sequence(tc.copied); len(captured) != 1 || captured[0] != want {
				t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
			}
		})
	}
}

func TestTranscriptSelection_HangingTabMeasuredFromScreenColumn(t *testing.T) {
	const width, height = 40, 6
	for _, tc := range []struct {
		marker string
		prefix int
	}{
		{"- ", 2},
		{"> - ", 4},
		{"100. ", 5},
	} {
		t.Run(fmt.Sprintf("prefix %d", tc.prefix), func(t *testing.T) {
			a := finalizedReply(tc.marker + strings.Repeat("x", width-tc.prefix-1) + " a\tZ")
			var captured []string
			a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
			cells, _, _ := drawTranscriptPane(t, a, width, height).GetContents()
			text := a.transcript.view.GetText(true)
			aOff := strings.Index(text, "a\tZ")
			if aOff < 0 {
				t.Fatalf("GetText(true) = %q, want it to keep the literal tab", text)
			}
			y, xA, xZ := -1, -1, -1
			for row := 0; row < height && y < 0; row++ {
				for x := 0; x < width; x++ {
					switch string(cells[row*width+x].Runes) {
					case "a":
						xA = x
					case "Z":
						y, xZ = row, x
					}
				}
			}
			if y < 0 || xA != tc.prefix || xZ <= xA+1 {
				t.Fatalf("drawn a at column %d and Z at (%d,%d), want a at %d on a continuation row before the tab", xA, xZ, y, tc.prefix)
			}
			for x := 0; x <= xZ; x++ {
				want, wantOnText := aOff+1, true
				switch {
				case x < xA:
					want, wantOnText = aOff, false
				case x == xA:
					want = aOff
				case x == xZ:
					want = aOff + 2
				}
				a.transcript.mu.Lock()
				off, onText := a.transcript.offsetRowAt(x, y)
				a.transcript.mu.Unlock()
				if off != want || onText != wantOnText {
					t.Fatalf("cell (%d,%d) maps to (%d,%v), want (%d,%v)", x, y, off, onText, want, wantOnText)
				}
			}

			a.handleAppMouse(tcell.NewEventMouse(xA+1, y, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
			a.handleAppMouse(tcell.NewEventMouse(xZ+1, y, tcell.Button1, tcell.ModNone), tview.MouseMove)
			cells, _, _ = drawTranscriptPane(t, a, width, height).GetContents()
			for row := 0; row < height; row++ {
				for x := 0; x < width; x++ {
					_, _, attr := cells[row*width+x].Style.Decompose()
					want := row == y && x > xA && x <= xZ
					if got := attr&tcell.AttrReverse != 0; got != want {
						t.Fatalf("cell (%d,%d) %q reverse = %v, want %v", x, row, string(cells[row*width+x].Runes), got, want)
					}
				}
			}
			a.handleAppMouse(tcell.NewEventMouse(xZ+1, y, tcell.Button1, tcell.ModNone), tview.MouseLeftUp)
			if want := osc52Sequence("\tZ"); len(captured) != 1 || captured[0] != want {
				t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
			}
		})
	}
}

func TestTranscriptSelection_HangingNeedsWidthPastThePrefix(t *testing.T) {
	a := finalizedReply("> - ab cd ef")
	raw := a.transcript.view.GetText(false)
	text := a.transcript.view.GetText(true)
	line := strings.SplitN(raw, "\n", 2)[0]

	drawTranscriptPane(t, a, 4, 20)
	if got := strings.SplitN(a.transcript.view.paintText, "\n", 2)[0]; got != line {
		t.Fatalf("paint line at width 4 = %q, want it unchanged %q", got, line)
	}
	rows := transcriptRows(raw, text, 4)
	if fmt.Sprint(rows) != fmt.Sprint(wrapRows(text, 4)) {
		t.Fatalf("rows at width 4 = %v, want ordinary wrapping %v", rows, wrapRows(text, 4))
	}
	if got := a.transcript.view.paint.GetWrappedLineCount(); got != len(rows) {
		t.Fatalf("painted rows at width 4 = %d, selection rows = %d", got, len(rows))
	}

	drawTranscriptPane(t, a, 5, 20)
	rows = transcriptRows(raw, text, 5)
	if rows[0].prefixWidth != 0 || rows[1].prefixWidth != 4 {
		t.Fatalf("rows at width 5 = %v, want continuation rows behind a 4-cell prefix", rows)
	}
	if got := a.transcript.view.paint.GetWrappedLineCount(); got != len(rows) {
		t.Fatalf("painted rows at width 5 = %d, selection rows = %d", got, len(rows))
	}
}

func TestTranscriptSelection_HangingRowsKeepInlineStyles(t *testing.T) {
	const width = 40
	a := finalizedReply("- **alpha beta gamma delta epsilon zeta eta** tail `kappa lambda mu nu xi omicron pi rho` end")
	screen := drawTranscriptPane(t, a, width, 6)
	cells, _, _ := screen.GetContents()
	if got, want := paneRows(t, a, width, 6), []string{
		"• alpha beta gamma delta epsilon zeta",
		"  eta tail kappa lambda mu nu xi",
		"  omicron pi rho end",
		"  [Copy response]",
	}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	style := func(x, y int) (tcell.Color, bool) {
		fg, _, attr := cells[y*width+x].Style.Decompose()
		return fg, attr&tcell.AttrBold != 0
	}
	plainFg, _ := style(0, 0)
	codeFg := tcell.GetColor("#4e9a06")
	checks := []struct {
		x, y int
		fg   tcell.Color
		bold bool
	}{
		{2, 0, plainFg, true},
		{0, 1, plainFg, false},
		{1, 1, plainFg, false},
		{2, 1, plainFg, true},
		{4, 1, plainFg, true},
		{6, 1, plainFg, false},
		{11, 1, codeFg, false},
		{0, 2, plainFg, false},
		{1, 2, plainFg, false},
		{2, 2, codeFg, false},
		{16, 2, plainFg, false},
	}
	for _, c := range checks {
		if fg, bold := style(c.x, c.y); fg != c.fg || bold != c.bold {
			t.Errorf("cell (%d,%d) %q: fg %v bold %v, want fg %v bold %v", c.x, c.y, string(cells[c.y*width+c.x].Runes), fg, bold, c.fg, c.bold)
		}
	}
}

func TestTranscriptCodeCopy_ControlsInsideHangingListKeepTheirCells(t *testing.T) {
	const body = "make build --flag=1\n"
	a := finalizedReply("- alpha beta gamma delta epsilon zeta eta\n\n  ```sh\n  make build --flag=1\n  ```")
	const response = "• alpha beta gamma delta epsilon zeta eta\nmake build --flag=1"
	hits := transcriptCopyHits(t, a, 16, 20, map[string]string{
		body:     codeCopyNotice,
		response: responseCopyNotice,
	})
	if got := hits[body]; got != statusCopyControl {
		t.Errorf("the cells that copy the block spell %q, want exactly %q", got, statusCopyControl)
	}
	if got := hits[response]; got != responseCopyControl {
		t.Errorf("the cells that copy the response spell %q, want exactly %q", got, responseCopyControl)
	}
}

func TestTranscriptSelection_HangingFallsBackWhenTviewParsesEscapedText(t *testing.T) {
	a := finalizedReply("- [::b:x] alpha beta gamma delta epsilon zeta eta theta iota kappa")
	raw := a.transcript.view.GetText(false)
	text := a.transcript.view.GetText(true)
	if got, want := paneRows(t, a, 40, 6), []string{
		"•  alpha beta gamma delta epsilon zeta",
		"eta theta iota kappa",
		"  [Copy response]",
	}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if a.transcript.view.paintText != raw {
		t.Fatalf("paint text = %q, want it unchanged %q", a.transcript.view.paintText, raw)
	}
	if rows := transcriptRows(raw, text, 40); fmt.Sprint(rows) != fmt.Sprint(wrapRows(text, 40)) {
		t.Fatalf("rows = %v, want ordinary wrapping %v", rows, wrapRows(text, 40))
	}
}

func TestTranscriptSelection_HangingFallsBackWhenAGlyphOverflowsThePrefix(t *testing.T) {
	const width, height = 5, 12
	a := finalizedReply("> - 界界")
	raw := a.transcript.view.GetText(false)
	text := a.transcript.view.GetText(true)
	var captured []string
	a.input.osc52 = func(seq string) error { captured = append(captured, seq); return nil }
	cells, _, _ := drawTranscriptPane(t, a, width, height).GetContents()
	rows := transcriptRows(raw, text, width)
	if fmt.Sprint(rows) != fmt.Sprint(wrapRows(text, width)) {
		t.Fatalf("rows = %v, want ordinary wrapping %v", rows, wrapRows(text, width))
	}
	if got := a.transcript.view.paint.GetWrappedLineCount(); got != len(rows) {
		t.Fatalf("painted rows = %d, selection rows = %d", got, len(rows))
	}
	if got := paneRows(t, a, width, height)[:2]; strings.Join(got, "\n") != "│ •\n界 界" {
		t.Fatalf("rows = %q, want the glyphs wrapped together below the marker", got)
	}

	first := strings.Index(text, "界")
	var glyphs [][2]int
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if string(cells[y*width+x].Runes) != "界" {
				continue
			}
			want := first + len("界")*len(glyphs)
			glyphs = append(glyphs, [2]int{x, y})
			for _, cx := range []int{x, x + 1} {
				a.transcript.mu.Lock()
				off, onText := a.transcript.offsetRowAt(cx, y)
				a.transcript.mu.Unlock()
				if off != want || !onText {
					t.Fatalf("cell (%d,%d) maps to (%d,%v), want (%d,true)", cx, y, off, onText, want)
				}
			}
		}
	}
	if len(glyphs) != 2 {
		t.Fatalf("drawn glyphs at %v, want two", glyphs)
	}

	last := glyphs[1]
	a.handleAppMouse(tcell.NewEventMouse(glyphs[0][0], glyphs[0][1], tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(tcell.NewEventMouse(last[0]+2, last[1], tcell.Button1, tcell.ModNone), tview.MouseMove)
	cells, _, _ = drawTranscriptPane(t, a, width, height).GetContents()
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			_, _, attr := cells[y*width+x].Style.Decompose()
			want := y == last[1] && x < last[0]+2
			if want && len(cells[y*width+x].Runes) == 0 {
				continue
			}
			if got := attr&tcell.AttrReverse != 0; got != want {
				t.Fatalf("cell (%d,%d) %q reverse = %v, want %v", x, y, string(cells[y*width+x].Runes), got, want)
			}
		}
	}
	a.handleAppMouse(tcell.NewEventMouse(last[0]+2, last[1], tcell.Button1, tcell.ModNone), tview.MouseLeftUp)
	if want := osc52Sequence("界界"); len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink = %q, want exactly one %q", captured, want)
	}

	hits := transcriptCopyHits(t, a, width, height, map[string]string{"│ • 界界": responseCopyNotice})
	if got := hits["│ • 界界"]; got != responseCopyControl {
		t.Errorf("the cells that copy the response spell %q, want exactly %q", got, responseCopyControl)
	}
}

type copyTimer struct {
	delay time.Duration
	fire  func()
}

func captureTimers(a *App) *[]copyTimer {
	timers := new([]copyTimer)
	a.afterFunc = func(d time.Duration, f func()) { *timers = append(*timers, copyTimer{delay: d, fire: f}) }
	return timers
}

func copyFixtures() []struct {
	name, notice string
	open         func(t *testing.T) (*App, func())
} {
	clickAt := func(a *App, x, y int) {
		a.handleAppMouse(tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		a.handleAppMouse(nil, tview.MouseLeftUp)
	}
	return []struct {
		name, notice string
		open         func(t *testing.T) (*App, func())
	}{
		{"session id", "Session ID copied", func(t *testing.T) (*App, func()) {
			state := fixtureState()
			a := New(nil)
			a.input.osc52 = func(string) error { return nil }
			a.SetStatusLineState(state)
			a.ShowStatus(RenderStatus(BuildStatusSnapshot(state)))
			drawPrimitive(t, a.status, 80, 30)
			return a, func() { clickAt(a, len(statusSessionPrefix)+len(state.sessionID)+1, 2) }
		}},
		{"response", "Response copied", func(t *testing.T) (*App, func()) {
			a := finalizedReply("the answer")
			a.input.osc52 = func(string) error { return nil }
			drawTranscriptPane(t, a, 40, 8)
			return a, func() { clickAt(a, 2, 1) }
		}},
		{"code block", "Code block copied", func(t *testing.T) (*App, func()) {
			a := finalizedReply("```sh\ncd /tmp\n```")
			a.input.osc52 = func(string) error { return nil }
			drawTranscriptPane(t, a, 40, 8)
			return a, func() { clickAt(a, 2, 1) }
		}},
	}
}

func TestCopyNotice_ClearsWhenItsTimerFires(t *testing.T) {
	for _, fx := range copyFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			a, click := fx.open(t)
			timers := captureTimers(a)
			click()

			if got := a.NoticeText(); got != fx.notice {
				t.Fatalf("notice = %q, want %q", got, fx.notice)
			}
			if len(*timers) != 1 || (*timers)[0].delay != 4*time.Second {
				t.Fatalf("timers = %+v, want exactly one scheduled for 4s", *timers)
			}

			a.transcript.append("a committed tool line")
			a.transcript.appendDelta("a streamed delta")
			if got := a.NoticeText(); got != fx.notice {
				t.Fatalf("notice = %q after new output, want %q kept until the timer fires", got, fx.notice)
			}

			(*timers)[0].fire()
			if got := a.NoticeText(); got != "" {
				t.Fatalf("notice = %q after the timer fired, want it cleared", got)
			}
		})
	}
}

func TestCopyNotice_TimerLeavesANewerNotice(t *testing.T) {
	for _, fx := range copyFixtures() {
		t.Run(fx.name+" replaced by another notice", func(t *testing.T) {
			a, click := fx.open(t)
			timers := captureTimers(a)
			click()
			a.Notice("model apply failed")

			(*timers)[0].fire()
			if got := a.NoticeText(); got != "model apply failed" {
				t.Fatalf("notice = %q, want the newer notice left in place", got)
			}
		})
		t.Run(fx.name+" copied twice", func(t *testing.T) {
			a, click := fx.open(t)
			timers := captureTimers(a)
			click()
			click()
			if len(*timers) != 2 {
				t.Fatalf("timers = %d, want one per copy", len(*timers))
			}

			(*timers)[0].fire()
			if got := a.NoticeText(); got != fx.notice {
				t.Fatalf("notice = %q after the first copy's timer, want the second copy's %q kept", got, fx.notice)
			}
			(*timers)[1].fire()
			if got := a.NoticeText(); got != "" {
				t.Fatalf("notice = %q after the second copy's timer, want it cleared", got)
			}
		})
	}
}

func TestCopyNotice_PlainNoticesGetNoTimer(t *testing.T) {
	a := finalizedReply("the answer")
	a.input.osc52 = func(string) error { return errors.New("stdout is closed") }
	drawTranscriptPane(t, a, 40, 8)
	timers := captureTimers(a)

	a.handleAppMouse(tcell.NewEventMouse(2, 1, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
	a.handleAppMouse(nil, tview.MouseLeftUp)
	if got := a.NoticeText(); !strings.HasPrefix(got, "Could not copy: ") {
		t.Fatalf("notice = %q, want the copy failure", got)
	}
	a.Notice("model apply failed")

	if len(*timers) != 0 {
		t.Fatalf("timers = %+v, want none for plain notices", *timers)
	}
}
