// Drag selection over the ask_user question overlay. The SimulationScreen proves the
// routing and the source mapping; it cannot show the other half of a failure here —
// whether a real emulator delivers motion between the press and the release at all,
// where a real pointer lands, or how the reverse-video range looks on a theme. Those
// stay with the kitty gesture check in docs/tui-mouse-debugging.md.
package tui

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func qsOpen(t *testing.T, spec QuestionSpec, width, height int) (*App, *questionOptions, *[]string) {
	t.Helper()
	a := New(nil)
	captured := new([]string)
	a.input.osc52 = func(seq string) error { *captured = append(*captured, seq); return nil }
	openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{spec}})
	drawPrimitive(t, a.pages, width, height)
	return a, a.questionForm.blocks[0].options, captured
}

func qsAt(o *questionOptions, row, col int) (int, int) {
	ix, iy, _, _ := o.GetInnerRect()
	scroll, _ := o.GetScrollOffset()
	return ix + col, iy + row - scroll
}

// qsRowEnd addresses the blank cell past a row's last glyph, which the column mapper
// resolves to that row's end offset whatever the row's glyph widths are.
func qsRowEnd(o *questionOptions, row int) (int, int) {
	_, _, iw, _ := o.GetInnerRect()
	return qsAt(o, row, iw)
}

func qsPress(a *App, x, y int) {
	a.handleAppMouse(tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
}

func qsMove(a *App, x, y int) {
	a.handleAppMouse(tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone), tview.MouseMove)
}

func qsRelease(a *App, event *tcell.EventMouse) {
	a.handleAppMouse(event, tview.MouseLeftUp)
}

// qsClickAction runs one click-class action the way tview's fireMouseActions does: the
// app-level capture first, then the mounted page if the event survived it. It reports
// whether the event reached the page.
func qsClickAction(a *App, x, y int, action tview.MouseAction) bool {
	event, act := a.handleAppMouse(tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone), action)
	if event == nil {
		return false
	}
	a.pages.MouseHandler()(act, event, func(p tview.Primitive) { a.app.SetFocus(p) })
	return true
}

func qsFullClick(a *App, x, y int, action tview.MouseAction) bool {
	qsPress(a, x, y)
	qsRelease(a, tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone))
	return qsClickAction(a, x, y, action)
}

func qsDrag(a *App, x1, y1, x2, y2 int) {
	qsPress(a, x1, y1)
	qsMove(a, x2, y2)
	qsRelease(a, nil)
}

func qsCopied(t *testing.T, a *App, captured *[]string, want string) {
	t.Helper()
	if len(*captured) != 1 {
		t.Fatalf("osc52 sink = %d copies, want exactly 1", len(*captured))
	}
	if (*captured)[0] != osc52Sequence(want) {
		t.Fatalf("copied %q, want %q", a.input.lastCopied, want)
	}
}

// wrappedTagLabel is tag-shaped, longer than any narrow row, and unbreakable inside the
// brackets, so a wrap splits the "[" tview.Escape inserts away from its "]". The repeated
// run after the closing bracket is deliberate: it is what a row offset recovered by
// searching the source for the un-escaped fragment matches too early once the fragment
// carrying the orphan bracket is found nowhere at all.
const wrappedTagLabel = "[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa] aaaaaaaa tail"

func TestQuestionSelection_DragCopiesSourceTextNotDrawnRows(t *testing.T) {
	const prompt = "Where should sessions be stored?"

	t.Run("prompt row copies the prompt", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 120, 30)
		x1, y1 := qsAt(o, 0, 0)
		x2, y2 := qsRowEnd(o, 0)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, prompt)
	})

	t.Run("option row drops the mark and its padding", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 120, 30)
		row := o.starts[0]
		x1, y1 := qsAt(o, row, 0)
		x2, y2 := qsRowEnd(o, row)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, "Local disk")
		if a.questionForm.blocks[0].chosen[0] {
			t.Fatal("the drag chose the option it selected text from")
		}
	})

	t.Run("wrapped label rejoins as one source string", func(t *testing.T) {
		const label = "Store every session under the shared object store instead"
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{label}}, 34, 30)
		first, last := o.starts[0], o.lastLineOf(0)
		if last <= first {
			t.Fatalf("label rendered on %d row(s); the wrapped case is not covered", last-first+1)
		}
		x1, y1 := qsAt(o, first, 0)
		x2, y2 := qsRowEnd(o, last)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, label)
		if strings.Contains(a.input.lastCopied, "\n") {
			t.Fatalf("copied %q, want no wrap-inserted newline", a.input.lastCopied)
		}
	})

	t.Run("tag-shaped label copies byte for byte", func(t *testing.T) {
		const label = "[red]Keep local[-]"
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{label}}, 120, 30)
		row := o.starts[0]
		x1, y1 := qsAt(o, row, 0)
		x2, y2 := qsRowEnd(o, row)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, label)
	})

	// A tag-shaped label narrow enough to wrap puts the "[" tview.Escape inserted on one
	// rendered row and the "]" it belongs to on the next, which is the case a row offset
	// recovered by searching the source for the un-escaped fragment cannot resolve.
	t.Run("wrapped tag-shaped label copies byte for byte", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{wrappedTagLabel}}, 30, 40)
		first, last := o.starts[0], o.lastLineOf(0)
		if last-first < 2 {
			t.Fatalf("label rendered on %d row(s); the wrapped tag case is not covered", last-first+1)
		}
		x1, y1 := qsAt(o, first, 0)
		x2, y2 := qsRowEnd(o, last)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, wrappedTagLabel)
	})

	t.Run("partial rows of a wrapped tag-shaped label rejoin into it", func(t *testing.T) {
		a, o, _ := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{wrappedTagLabel}}, 30, 40)
		first, last := o.starts[0], o.lastLineOf(0)
		if last-first < 2 {
			t.Fatalf("label rendered on %d row(s); the wrapped tag case is not covered", last-first+1)
		}
		mid := first + 1
		hx, hy := qsAt(o, first, 0)
		hx2, hy2 := qsRowEnd(o, mid)
		qsDrag(a, hx, hy, hx2, hy2)
		head := a.input.lastCopied
		tx, ty := qsAt(o, mid+1, 0)
		tx2, ty2 := qsRowEnd(o, last)
		qsDrag(a, tx, ty, tx2, ty2)
		tail := a.input.lastCopied
		if !strings.HasPrefix(wrappedTagLabel, head) {
			t.Fatalf("the first rows copied %q, which is no prefix of %q", head, wrappedTagLabel)
		}
		if head+tail != wrappedTagLabel {
			t.Fatalf("partial selections copied %q then %q, want them to rejoin into %q", head, tail, wrappedTagLabel)
		}
	})

	t.Run("custom answer row is selectable", func(t *testing.T) {
		spec := QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}, AllowCustom: true}
		a, o, captured := qsOpen(t, spec, 120, 30)
		row := o.starts[len(spec.Options)]
		x1, y1 := qsAt(o, row, 0)
		x2, y2 := qsRowEnd(o, row)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, customAnswerRowLabel)
		if a.questionForm.blocks[0].customOn {
			t.Fatal("the drag opened the custom answer field")
		}
	})

	t.Run("prompt to option inserts exactly one newline", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 120, 30)
		row := o.starts[0]
		x1, y1 := qsAt(o, 0, 0)
		x2, y2 := qsRowEnd(o, row)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, prompt+"\n"+"Local disk")
		if got := strings.Count(a.input.lastCopied, "\n"); got != 1 {
			t.Fatalf("copied %q with %d newlines, want exactly 1", a.input.lastCopied, got)
		}
	})
}

// A newline the provider wrote is source text, so a drag that meets it at a row edge has
// to copy it. The break the renderer inserts to wrap a long line is not in the source and
// still must not appear, which is why the two edges are asserted separately.
func TestQuestionSelection_SourceNewlineAtARowEdgeIsCopied(t *testing.T) {
	const prompt = "First line\nSecond line"

	t.Run("a drag from the row end into the next row keeps it", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 120, 30)
		if o.starts[0] != 2 {
			t.Fatalf("prompt rendered on %d row(s); the hard-break case is not covered", o.starts[0])
		}
		x1, y1 := qsRowEnd(o, 0)
		x1--
		x2, y2 := qsRowEnd(o, 1)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, "\nSecond line")
	})

	t.Run("a drag ending at the next row's start keeps it", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 120, 30)
		x1, y1 := qsAt(o, 0, 0)
		x2, y2 := qsAt(o, 1, 0)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, "First line\n")
	})

	t.Run("a whole prompt with a hard break copies both lines", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 120, 30)
		x1, y1 := qsAt(o, 0, 0)
		x2, y2 := qsRowEnd(o, 1)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, prompt)
	})

	t.Run("an option label keeps its own newline", func(t *testing.T) {
		const label = "Local disk\nunder the cache dir"
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{label}}, 120, 30)
		first, last := o.starts[0], o.lastLineOf(0)
		if last != first+1 {
			t.Fatalf("label rendered on %d row(s); the hard-break case is not covered", last-first+1)
		}
		x1, y1 := qsRowEnd(o, first)
		x1--
		x2, y2 := qsRowEnd(o, last)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, "\nunder the cache dir")
	})

	t.Run("a row edge the renderer wrapped adds nothing", func(t *testing.T) {
		const label = "Store every session under the shared object store instead"
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{label}}, 34, 30)
		first, last := o.starts[0], o.lastLineOf(0)
		if last <= first {
			t.Fatalf("label rendered on %d row(s); the wrapped case is not covered", last-first+1)
		}
		x1, y1 := qsRowEnd(o, first)
		x1--
		x2, y2 := qsRowEnd(o, last)
		qsDrag(a, x1, y1, x2, y2)
		if len(*captured) != 1 {
			t.Fatalf("osc52 sink = %d copies, want exactly 1", len(*captured))
		}
		if strings.Contains(a.input.lastCopied, "\n") {
			t.Fatalf("copied %q, want no wrap-inserted newline", a.input.lastCopied)
		}
		if !strings.HasSuffix(label, a.input.lastCopied) {
			t.Fatalf("copied %q, want a suffix of %q", a.input.lastCopied, label)
		}
	})
}

// An ordinary soft wrap breaks at the offset past the breaking space, so the separator is
// drawn at the end of the row it broke and the row below begins at its own first drawn
// character. Comparing each copy against what the row draws is what excludes a separator
// leaking into the row below it; the partial range is asserted so a whole-row selection
// cannot mask a shifted start boundary.
func TestQuestionSelection_SoftWrappedRowStartsAtItsFirstDrawnCharacter(t *testing.T) {
	const prompt = "Where should the recorded sessions be stored on this machine"
	const label = "Store every session under the shared object store instead"

	drawnRow := func(t *testing.T, o *questionOptions, row int) string {
		t.Helper()
		text := o.GetText(true)
		rows := hardRows(text, 0)
		if row < 0 || row >= len(rows) {
			t.Fatalf("row %d does not exist among %d rendered rows", row, len(rows))
		}
		return text[rows[row].start:rows[row].end]
	}

	t.Run("a later prompt row copies exactly what it draws", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 34, 30)
		if o.starts[0] < 2 {
			t.Fatalf("prompt rendered on %d row(s); the soft-wrap case is not covered", o.starts[0])
		}
		want := drawnRow(t, o, 1)
		if strings.HasPrefix(want, " ") {
			t.Fatalf("row 1 draws %q; the wrap put the separator on the wrong row", want)
		}
		x1, y1 := qsAt(o, 1, 0)
		x2, y2 := qsRowEnd(o, 1)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, want)
	})

	t.Run("a partial range inside a later prompt row starts at its first character", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"Local disk"}}, 34, 30)
		if o.starts[0] < 2 {
			t.Fatalf("prompt rendered on %d row(s); the soft-wrap case is not covered", o.starts[0])
		}
		row := drawnRow(t, o, 1)
		if len(row) < 4 {
			t.Fatalf("row 1 draws %q, too short for a partial range", row)
		}
		x1, y1 := qsAt(o, 1, 0)
		x2, y2 := qsAt(o, 1, 4)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, row[:4])
	})

	t.Run("a later option row copies its label without the continuation padding", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{label}}, 34, 30)
		first, last := o.starts[0], o.lastLineOf(0)
		if last <= first {
			t.Fatalf("label rendered on %d row(s); the soft-wrap case is not covered", last-first+1)
		}
		want := drawnRow(t, o, first+1)[questionRowMarkWidth:]
		if strings.HasPrefix(want, " ") {
			t.Fatalf("row %d draws %q after its padding; the wrap put the separator on the wrong row", first+1, want)
		}
		x1, y1 := qsAt(o, first+1, 0)
		x2, y2 := qsRowEnd(o, first+1)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, want)
	})
}

// A selection that meets an owner only at a row edge crosses that owner boundary just as a
// selection that takes bytes from it does, so the copy still carries the one separator for
// the crossing. Both drag directions are asserted because the anchor is the pressed end.
func TestQuestionSelection_OwnerBoundaryEndpointKeepsItsSeparator(t *testing.T) {
	const prompt = "Where should sessions be stored?"
	options := []string{"Local disk", "Object store"}

	rowEndInside := func(o *questionOptions, row int) (int, int) {
		x, y := qsRowEnd(o, row)
		return x - 1, y
	}

	cases := []struct {
		name string
		ends func(o *questionOptions) (int, int, int, int)
		want string
	}{
		{"prompt row end into the option below it", func(o *questionOptions) (int, int, int, int) {
			x1, y1 := rowEndInside(o, 0)
			x2, y2 := rowEndInside(o, o.starts[0])
			return x1, y1, x2, y2
		}, "\n" + options[0]},
		{"prompt start to the option row start", func(o *questionOptions) (int, int, int, int) {
			x1, y1 := qsAt(o, 0, 0)
			x2, y2 := qsAt(o, o.starts[0], 0)
			return x1, y1, x2, y2
		}, prompt + "\n"},
		{"option row end into the adjacent option", func(o *questionOptions) (int, int, int, int) {
			x1, y1 := rowEndInside(o, o.starts[0])
			x2, y2 := rowEndInside(o, o.starts[1])
			return x1, y1, x2, y2
		}, "\n" + options[1]},
		{"option start to the adjacent option's row start", func(o *questionOptions) (int, int, int, int) {
			x1, y1 := qsAt(o, o.starts[0], 0)
			x2, y2 := qsAt(o, o.starts[1], 0)
			return x1, y1, x2, y2
		}, options[0] + "\n"},
	}

	for _, tc := range cases {
		for _, backwards := range []bool{false, true} {
			name := tc.name
			if backwards {
				name += ", dragged backwards"
			}
			t.Run(name, func(t *testing.T) {
				a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: prompt, Options: options}, 120, 30)
				if o.starts[0] != 1 || o.starts[1] != 2 {
					t.Fatalf("question rendered with option starts %v; the one-row-per-owner case is not covered", o.starts)
				}
				x1, y1, x2, y2 := tc.ends(o)
				if backwards {
					x1, y1, x2, y2 = x2, y2, x1, y1
				}
				qsDrag(a, x1, y1, x2, y2)
				qsCopied(t, a, captured, tc.want)
				if got := strings.Count(a.input.lastCopied, "\n"); got != 1 {
					t.Fatalf("copied %q with %d newlines, want exactly 1", a.input.lastCopied, got)
				}
			})
		}
	}
}

func TestQuestionSelection_MultibyteAndWideTextStaysOnByteBoundaries(t *testing.T) {
	const widePrompt = "保存先 naïve"

	t.Run("wide prompt stops on a UTF-8 boundary", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: widePrompt, Options: []string{"Local disk"}}, 120, 30)
		// Column 3 sits on the second wide cell of 保, and column 6 just past 先.
		x1, y1 := qsAt(o, 0, 3)
		x2, y2 := qsAt(o, 0, 6)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, "存先")
		if !utf8.ValidString(a.input.lastCopied) {
			t.Fatalf("copied %q is not valid UTF-8", a.input.lastCopied)
		}
	})

	t.Run("whole wide prompt copies byte for byte", func(t *testing.T) {
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: widePrompt, Options: []string{"Local disk"}}, 120, 30)
		x1, y1 := qsAt(o, 0, 0)
		x2, y2 := qsRowEnd(o, 0)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, widePrompt)
	})

	t.Run("wrapped wide label copies byte for byte", func(t *testing.T) {
		const label = "保存された すべての セッション を naïve café に置く"
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: widePrompt, Options: []string{label}}, 34, 30)
		first, last := o.starts[0], o.lastLineOf(0)
		if last <= first {
			t.Fatalf("label rendered on %d row(s); the wrapped case is not covered", last-first+1)
		}
		x1, y1 := qsAt(o, first, 0)
		x2, y2 := qsRowEnd(o, last)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, label)
		if strings.Contains(a.input.lastCopied, "\n") {
			t.Fatalf("copied %q, want no wrap-inserted newline", a.input.lastCopied)
		}
	})

	t.Run("cross owner drag with multibyte on both sides", func(t *testing.T) {
		const label = "オブジェクト café"
		a, o, captured := qsOpen(t, QuestionSpec{ID: "q", Prompt: widePrompt, Options: []string{label}}, 120, 30)
		row := o.starts[0]
		x1, y1 := qsAt(o, 0, 0)
		x2, y2 := qsRowEnd(o, row)
		qsDrag(a, x1, y1, x2, y2)
		qsCopied(t, a, captured, widePrompt+"\n"+label)
	})
}

func TestQuestionSelection_HighlightsTheDraggedRange(t *testing.T) {
	a, o, _ := qsOpen(t, QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{"Local disk"}}, 120, 30)
	x1, y1 := qsAt(o, 0, 0)
	x2, y2 := qsRowEnd(o, 0)
	qsPress(a, x1, y1)
	qsMove(a, x2, y2)
	if got := reverseText(t, a.pages, 120, 30); got != "Pick one" {
		t.Fatalf("mid-drag highlight = %q, want %q", got, "Pick one")
	}
	qsRelease(a, nil)
	if got := reverseText(t, a.pages, 120, 30); got != "" {
		t.Fatalf("highlight = %q after the release, want it cleared", got)
	}
}

func TestQuestionSelection_ZeroMovementPressStillChoosesItsRow(t *testing.T) {
	spec := QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{"Local disk", "Object store"}}

	t.Run("a click on an option row chooses it", func(t *testing.T) {
		a, o, captured := qsOpen(t, spec, 120, 30)
		x, y := qsAt(o, o.starts[1], 1)
		if !qsFullClick(a, x, y, tview.MouseLeftClick) {
			t.Fatal("the click-class action was consumed before the overlay saw it")
		}
		if !a.questionForm.blocks[0].chosen[1] {
			t.Fatal("a zero-movement click did not choose the row it landed on")
		}
		if len(*captured) != 0 {
			t.Fatalf("osc52 sink = %d copies after a click, want none", len(*captured))
		}
	})

	t.Run("a click on a wrapped continuation line chooses its row", func(t *testing.T) {
		const label = "Store every session under the shared object store instead"
		a, o, _ := qsOpen(t, QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{"Local disk", label}}, 34, 30)
		first, last := o.starts[1], o.lastLineOf(1)
		if last <= first {
			t.Fatalf("label rendered on %d row(s); the continuation case is not covered", last-first+1)
		}
		x, y := qsAt(o, last, 1)
		if !qsFullClick(a, x, y, tview.MouseLeftClick) {
			t.Fatal("the click-class action was consumed before the overlay saw it")
		}
		if !a.questionForm.blocks[0].chosen[1] {
			t.Fatal("a click on a continuation line did not choose its row")
		}
	})
}

// The second of two rapid clicks arrives as a double-click action wherever it lands, so
// the drag routing must leave actOnClick's verdict on it untouched.
func TestQuestionSelection_RapidClickPairKeepsRowSemantics(t *testing.T) {
	spec := QuestionSpec{ID: "q", Prompt: "Pick some", Options: []string{"Linux", "macOS"}, MultiSelect: true}

	t.Run("the second click acts on a different row", func(t *testing.T) {
		a, o, _ := qsOpen(t, spec, 120, 30)
		x, y := qsAt(o, o.starts[0], 1)
		qsFullClick(a, x, y, tview.MouseLeftClick)
		x, y = qsAt(o, o.starts[1], 1)
		qsFullClick(a, x, y, tview.MouseLeftDoubleClick)
		chosen := a.questionForm.blocks[0].chosen
		if !chosen[0] || !chosen[1] {
			t.Fatalf("chosen = %v, want both rows chosen", chosen)
		}
	})

	t.Run("the second click does not re-toggle the same row", func(t *testing.T) {
		a, o, _ := qsOpen(t, spec, 120, 30)
		x, y := qsAt(o, o.starts[0], 1)
		qsFullClick(a, x, y, tview.MouseLeftClick)
		qsFullClick(a, x, y, tview.MouseLeftDoubleClick)
		if !a.questionForm.blocks[0].chosen[0] {
			t.Fatal("the rapid second click on the same row turned it back off")
		}
	})
}

func TestQuestionSelection_DragOwnsItsReleaseAndClickAction(t *testing.T) {
	spec := QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{"Local disk", "Object store"}}

	t.Run("a release outside the options rect still copies", func(t *testing.T) {
		a, o, captured := qsOpen(t, spec, 120, 30)
		ix, iy, iw, ih := o.GetInnerRect()
		x1, y1 := qsAt(o, o.starts[0], 0)
		qsPress(a, x1, y1)
		qsMove(a, ix+iw+3, iy+ih+2)
		qsRelease(a, nil)
		qsCopied(t, a, captured, "Local disk\nObject store")
		if chosen := a.questionForm.blocks[0].chosen; chosen[0] || chosen[1] {
			t.Fatalf("chosen = %v, want the drag to leave every option alone", chosen)
		}
	})

	t.Run("a click action following a drag is suppressed", func(t *testing.T) {
		a, o, _ := qsOpen(t, spec, 120, 30)
		x1, y1 := qsAt(o, o.starts[0], 0)
		x2, y2 := qsRowEnd(o, o.starts[0])
		qsPress(a, x1, y1)
		qsMove(a, x2, y2)
		qsRelease(a, nil)
		if qsClickAction(a, x2, y2, tview.MouseLeftDoubleClick) {
			t.Fatal("the drag's click-class action reached the mounted form")
		}
		if a.questionForm.blocks[0].chosen[0] {
			t.Fatal("the drag's click-class action chose an option")
		}
	})

	t.Run("a press outside the options rect is left to the form", func(t *testing.T) {
		a, o, _ := qsOpen(t, spec, 120, 30)
		bx, by, _, _ := a.questionForm.cancel.GetRect()
		event, _ := a.handleAppMouse(tcell.NewEventMouse(bx+1, by, tcell.Button1, tcell.ModNone), tview.MouseLeftDown)
		if event == nil {
			t.Fatal("a press on Cancel was captured by the question selection")
		}
		if o.sel.selecting {
			t.Fatal("a press outside the options rect started a selection")
		}
		qsRelease(a, tcell.NewEventMouse(bx+1, by, tcell.Button1, tcell.ModNone))
		if !qsClickAction(a, bx+1, by, tview.MouseLeftClick) {
			t.Fatal("the click on Cancel was consumed before the form saw it")
		}
		if a.QuestionFormOpen() {
			t.Fatal("clicking Cancel no longer dismisses the form")
		}
	})

	t.Run("a later genuine click is not suppressed", func(t *testing.T) {
		a, o, _ := qsOpen(t, spec, 120, 30)
		x1, y1 := qsAt(o, o.starts[0], 0)
		x2, y2 := qsRowEnd(o, o.starts[0])
		qsPress(a, x1, y1)
		qsMove(a, x2, y2)
		qsRelease(a, nil)
		// The drag produced no click-class action at all, so the arming must fall away on
		// the next press rather than swallowing the click that follows it.
		cx, cy := qsAt(o, o.starts[1], 1)
		if !qsFullClick(a, cx, cy, tview.MouseLeftClick) {
			t.Fatal("a genuine click after a drag was suppressed")
		}
		if !a.questionForm.blocks[0].chosen[1] {
			t.Fatal("a genuine click after a drag did not choose its row")
		}
	})
}

// An over-tall question is the only shape where the outside-drag clamp shows: the rows
// below the view are in the text but were never drawn, so a pointer dragged past the
// bottom must stop at the last row the reader can see and copying them takes a scroll.
func TestQuestionSelection_OutsideDragStopsAtTheLastVisibleRow(t *testing.T) {
	const prompt = "Where should sessions be stored?"
	options := []string{
		"Local disk", "Object store", "Network share", "Tape archive",
		"Cold storage", "Memory only", "Remote replica", "Nowhere at all",
	}
	spec := QuestionSpec{ID: "q", Prompt: prompt, Options: options}
	const width, height = 60, 12

	setup := func(t *testing.T) (*App, *questionOptions, *[]string, int) {
		t.Helper()
		a, o, captured := qsOpen(t, spec, width, height)
		_, _, _, ih := o.GetInnerRect()
		if ih < 3 || o.contentHeight() <= ih {
			t.Fatalf("setup: %d content rows in a %d-row view, so nothing is hidden below it", o.contentHeight(), ih)
		}
		if len(o.owner) != len(options)+1 || o.owner[0] != -1 {
			t.Fatalf("setup: rows own %v, want one prompt row then one row per option", o.owner)
		}
		return a, o, captured, ih
	}

	t.Run("a move below the view ends at the last visible row", func(t *testing.T) {
		a, o, captured, ih := setup(t)
		ix, iy, _, _ := o.GetInnerRect()
		x1, y1 := qsAt(o, 0, 0)
		qsPress(a, x1, y1)
		qsMove(a, ix, iy+ih+3)
		qsRelease(a, nil)
		qsCopied(t, a, captured, strings.Join(append([]string{prompt}, options[:ih-1]...), "\n"))
	})

	t.Run("scrolling is what makes a row below the view selectable", func(t *testing.T) {
		a, o, captured, ih := setup(t)
		top := o.maxScroll()
		o.scrollToLine(top)
		drawPrimitive(t, a.pages, width, height)
		if row, _ := o.GetScrollOffset(); row != top {
			t.Fatalf("setup: the view sits at row %d after scrolling, want %d", row, top)
		}
		ix, iy, _, _ := o.GetInnerRect()
		x1, y1 := qsAt(o, top, 0)
		qsPress(a, x1, y1)
		qsMove(a, ix, iy+ih+3)
		qsRelease(a, nil)
		qsCopied(t, a, captured, strings.Join(options[top-1:], "\n"))
	})
}

func TestQuestionSelection_ReRenderDuringADragCopiesNothing(t *testing.T) {
	spec := QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{"Local disk", "Object store"}}
	a, o, captured := qsOpen(t, spec, 120, 30)

	x1, y1 := qsAt(o, o.starts[0], 0)
	x2, y2 := qsRowEnd(o, o.starts[0])
	qsPress(a, x1, y1)
	qsMove(a, x2, y2)
	// A resize re-places the stage, which rebuilds the row map the highlight was mapped
	// through while the button is still down.
	drawPrimitive(t, a.pages, 100, 30)
	if got := reverseText(t, a.pages, 100, 30); got != "" {
		t.Fatalf("highlight = %q after a mid-drag re-render, want it dropped", got)
	}
	qsRelease(a, nil)
	if len(*captured) != 0 {
		t.Fatalf("osc52 sink = %d copies after an interrupted drag, want none", len(*captured))
	}
	if chosen := a.questionForm.blocks[0].chosen; chosen[0] || chosen[1] {
		t.Fatalf("chosen = %v, want the interrupted drag to change nothing", chosen)
	}

	nx1, ny1 := qsAt(o, o.starts[1], 0)
	nx2, ny2 := qsRowEnd(o, o.starts[1])
	qsDrag(a, nx1, ny1, nx2, ny2)
	qsCopied(t, a, captured, "Object store")
}

// A re-render can land between the button-down and the first move, so the gesture that
// owes the terminal a release never moved. It still has to consume that release and the
// click-class action after it: the rows the press landed on are gone.
func TestQuestionSelection_ReRenderBeforeAnyMovementChoosesNothing(t *testing.T) {
	spec := QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{"Local disk", "Object store"}}
	a, o, captured := qsOpen(t, spec, 120, 30)

	x, y := qsAt(o, o.starts[0], 1)
	qsPress(a, x, y)
	drawPrimitive(t, a.pages, 100, 30)
	x, y = qsAt(o, o.starts[0], 1)

	if event, _ := a.handleAppMouse(tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone), tview.MouseLeftUp); event != nil {
		t.Fatal("the release of a press interrupted by a re-render was passed on instead of consumed")
	}
	if qsClickAction(a, x, y, tview.MouseLeftClick) {
		t.Fatal("the interrupted press's click-class action reached the page")
	}
	if chosen := a.questionForm.blocks[0].chosen; chosen[0] || chosen[1] {
		t.Fatalf("chosen = %v, want the interrupted press to change nothing", chosen)
	}
	if len(*captured) != 0 {
		t.Fatalf("osc52 sink = %d copies after an interrupted press, want none", len(*captured))
	}

	// The gesture is spent, so the press after it selects normally.
	nx1, ny1 := qsAt(o, o.starts[1], 0)
	nx2, ny2 := qsRowEnd(o, o.starts[1])
	qsDrag(a, nx1, ny1, nx2, ny2)
	qsCopied(t, a, captured, "Object store")
}

// Closing the form under a held button is the second stage of the drag's invalidation: the
// source map goes at once, but the physical gesture is still in progress, so the app owes
// the terminal a release and the click-class action tview fires after it.
func TestQuestionSelection_FormCloseDuringADragKeepsGestureOwnership(t *testing.T) {
	spec := QuestionSpec{ID: "q", Prompt: "Pick one", Options: []string{"Local disk", "Object store"}}
	a, o, captured := qsOpen(t, spec, 120, 30)
	block := a.questionForm.blocks[0]

	x1, y1 := qsAt(o, o.starts[0], 0)
	x2, y2 := qsRowEnd(o, o.starts[0])
	qsPress(a, x1, y1)
	qsMove(a, x2, y2)
	a.cancelQuestionForm()
	if a.QuestionFormOpen() {
		t.Fatal("setup: the form did not close")
	}
	if d := a.questionDrag(); d == nil || !d.owned {
		t.Fatal("closing the form dropped the gesture the app still owns")
	}
	if got := reverseText(t, a.pages, 120, 30); got != "" {
		t.Fatalf("highlight = %q after the form closed mid-drag, want it dropped", got)
	}

	if event, _ := a.handleAppMouse(nil, tview.MouseLeftUp); event != nil {
		t.Fatal("the release of an interrupted drag was passed on instead of consumed")
	}
	if len(*captured) != 0 {
		t.Fatalf("osc52 sink = %d copies after a form close mid-drag, want none", len(*captured))
	}
	if qsClickAction(a, x2, y2, tview.MouseLeftClick) {
		t.Fatal("the interrupted drag's click-class action reached the page")
	}
	if chosen := block.chosen; chosen[0] || chosen[1] {
		t.Fatalf("chosen = %v, want the interrupted drag to change nothing", chosen)
	}

	// The gesture is spent, so the app is out of the way of whatever the closed form
	// uncovered.
	if d := a.questionDrag(); d != nil {
		t.Fatal("the spent gesture is still held after its release and click were consumed")
	}
}

func TestHardRows_TracksOneRowPerRenderedLine(t *testing.T) {
	got := hardRows("mark a\n    b\n", 4)
	want := []rowSpan{{start: 0, end: 6}, {start: 7, end: 12}, {start: 13, end: 13}}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// wrapSource has to land in the original string's byte coordinates, which neither the
// escaped buffer's lengths nor a rune count reaches.
func TestWrapSource_LandsOnSourceByteBoundaries(t *testing.T) {
	t.Run("escape-inserted brackets do not shift the offset", func(t *testing.T) {
		const src = "[red]Keep local[-] tail"
		lines, offsets := wrapSource(src, 40)
		if len(lines) != 1 || len(offsets) != 1 {
			t.Fatalf("wrapped %q into %d lines, want 1", src, len(lines))
		}
		if offsets[0] != 0 || tview.Unescape(lines[0]) != src {
			t.Fatalf("line 0 = %q at source byte %d, want %q at 0", tview.Unescape(lines[0]), offsets[0], src)
		}
	})

	t.Run("a dropped hard-break newline still advances the offset", func(t *testing.T) {
		const src = "one\ntwo"
		lines, offsets := wrapSource(src, 40)
		if len(lines) != 2 {
			t.Fatalf("wrapped %q into %d lines, want 2", src, len(lines))
		}
		if offsets[0] != 0 || offsets[1] != 4 {
			t.Fatalf("offsets = %v, want [0 4] (the newline WordWrap dropped still occupies a byte)", offsets)
		}
	})

	t.Run("a wide rune counts its bytes", func(t *testing.T) {
		const src = "保存先 naïve tail"
		_, offsets := wrapSource(src, 8)
		for i, off := range offsets {
			if off == len(src) {
				continue
			}
			if !utf8.RuneStart(src[off]) {
				t.Fatalf("line %d starts at byte %d, which is not a rune boundary", i, off)
			}
		}
	})

	// A narrow width splits the "[" tview.Escape inserted away from the "]" it belongs to.
	// The fragment that carries the orphan bracket un-escapes to text that appears nowhere
	// in the source, so an offset derived by searching for that fragment is guesswork: the
	// search fails and the row silently keeps whatever offset the walk had reached.
	t.Run("a wrap through an escaped bracket keeps every row in step", func(t *testing.T) {
		for _, src := range []string{
			"[red] tag [red] tag rest",
			"[a] a [a] a a a",
			"[x]\n[x] x more text",
			"prefix [warn] body [warn] body",
			"保存先 [先] 保存 tail",
			wrappedTagLabel,
		} {
			for width := 2; width <= 12; width++ {
				lines, offsets := wrapSource(src, width)
				if len(lines) != len(offsets) {
					t.Fatalf("%q at width %d: %d lines but %d offsets", src, width, len(lines), len(offsets))
				}
				if offsets[0] != 0 {
					t.Fatalf("%q at width %d: first row starts at source byte %d, want 0", src, width, offsets[0])
				}
				for i, off := range offsets {
					if off < 0 || off > len(src) {
						t.Fatalf("%q at width %d: row %d offset %d out of range", src, width, i, off)
					}
					if off < len(src) && !utf8.RuneStart(src[off]) {
						t.Fatalf("%q at width %d: row %d offset %d is not a rune boundary", src, width, i, off)
					}
					if i > 0 && off < offsets[i-1] {
						t.Fatalf("%q at width %d: offsets %v run backwards", src, width, offsets)
					}
				}
				// Every source byte belongs to exactly one row, so the rows' own source
				// spans have to re-form the source with nothing dropped or repeated.
				var rebuilt strings.Builder
				for i, off := range offsets {
					end := len(src)
					if i+1 < len(offsets) {
						end = offsets[i+1]
					}
					rebuilt.WriteString(src[off:end])
				}
				if rebuilt.String() != src {
					t.Fatalf("%q at width %d: rows span %q, want the whole source", src, width, rebuilt.String())
				}
			}
		}
	})
}

// Changing the shown question under a held button interrupts the drag the same way closing
// the form does. The question being left is never re-rendered, so nothing invalidates its
// source map at the moment of the change, and the release still has to be answered: the
// gesture began on a question that is no longer the one drawn under the pointer.
func TestQuestionSelection_QuestionChangeDuringADragKeepsGestureOwnership(t *testing.T) {
	open := func(t *testing.T) (*App, *[]string, *questionBlock, *questionBlock) {
		t.Helper()
		a := New(nil)
		captured := new([]string)
		a.input.osc52 = func(seq string) error { *captured = append(*captured, seq); return nil }
		openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{
			{ID: "storage", Prompt: "Where should sessions be stored?", Options: []string{"Local disk", "Object store"}},
			{ID: "targets", Prompt: "Which platforms must ship first?", Options: []string{"Linux", "macOS"}},
		}})
		drawPrimitive(t, a.pages, 120, 30)
		return a, captured, a.questionForm.blocks[0], a.questionForm.blocks[1]
	}
	noneChosen := func(t *testing.T, blocks ...*questionBlock) {
		t.Helper()
		for i, b := range blocks {
			for j, on := range b.chosen {
				if on {
					t.Fatalf("question %d option %d was chosen, want the interrupted gesture to change nothing", i, j)
				}
			}
		}
	}

	// The release can arrive before the next draw, so the source map has to be gone at the
	// moment the question changes rather than when the newly shown question renders.
	t.Run("a moved drag copies nothing", func(t *testing.T) {
		a, captured, first, second := open(t)
		x1, y1 := qsAt(first.options, first.options.starts[0], 0)
		x2, y2 := qsRowEnd(first.options, first.options.starts[0])
		qsPress(a, x1, y1)
		qsMove(a, x2, y2)

		a.questionForm.showAdjacent(1)
		if d := a.questionDrag(); d == nil || !d.owned {
			t.Fatal("changing the shown question dropped the gesture the app still owns")
		}
		// Asserted without drawing: a draw would render the newly shown question, and that
		// render clears the highlight by itself, which is the masking the release beats.
		if sel := &first.options.sel; sel.selStart != sel.selEnd {
			t.Fatalf("highlight = [%d,%d) on the question that was left, want it dropped", sel.selStart, sel.selEnd)
		}

		qsRelease(a, nil)
		if len(*captured) != 0 {
			t.Fatalf("osc52 sink = %d copies after a question change mid-drag, want none", len(*captured))
		}
		noneChosen(t, first, second)
	})

	// A press that never moved would otherwise stay a click, and the row now under the
	// pointer belongs to the question the user has just left.
	t.Run("an unmoved press chooses nothing on the question it lands over", func(t *testing.T) {
		a, captured, first, second := open(t)
		x1, y1 := qsAt(first.options, first.options.starts[0], 0)
		qsPress(a, x1, y1)

		a.questionForm.showAdjacent(1)
		drawPrimitive(t, a.pages, 120, 30)
		if a.questionForm.stage.shown != second {
			t.Fatal("setup: the shown question did not change")
		}

		qsRelease(a, tcell.NewEventMouse(x1, y1, tcell.Button1, tcell.ModNone))
		cx, cy := qsAt(second.options, second.options.starts[0], 0)
		if qsClickAction(a, cx, cy, tview.MouseLeftClick) {
			t.Fatal("the interrupted gesture's click-class action reached the page")
		}
		if len(*captured) != 0 {
			t.Fatalf("osc52 sink = %d copies after a question change mid-press, want none", len(*captured))
		}
		noneChosen(t, first, second)
	})
}
