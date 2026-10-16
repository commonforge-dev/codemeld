package tui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/provider"
)

func maxRuneText(word string, runes int) string {
	w := []rune(word)
	out := make([]rune, 0, runes)
	for {
		need := len(w)
		if len(out) > 0 {
			need++
		}
		if len(out)+need > runes {
			break
		}
		if len(out) > 0 {
			out = append(out, ' ')
		}
		out = append(out, w...)
	}
	for len(out) < runes {
		out = append(out, w[0])
	}
	return string(out)
}

func questionFixture() QuestionRequest {
	return QuestionRequest{Questions: []QuestionSpec{
		{ID: "storage", Prompt: "Where should sessions be stored?", Options: []string{"Local disk", "Object store"}},
		{ID: "targets", Prompt: "Which platforms must ship first?", Options: []string{"Linux", "macOS", "Windows"}, MultiSelect: true},
		{ID: "name", Prompt: "What should the command be called?", Options: []string{"codemeld run", "codemeld go"}, AllowCustom: true},
	}}
}

func openQuestions(t *testing.T, a *App, req QuestionRequest) chan QuestionResult {
	t.Helper()
	ch := make(chan QuestionResult, 1)
	if !a.openQuestionForm(req, ch) {
		t.Fatal("setup: question form did not open")
	}
	return ch
}

func chooseByKeyboard(t *testing.T, l *questionOptions, index int) {
	t.Helper()
	l.SetCurrentItem(index)
	l.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
}

func pressList(l *questionOptions, key tcell.Key) {
	l.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
}

func clickRow(t *testing.T, a *App, l *questionOptions, index int) {
	t.Helper()
	showList(t, a, l)
	x, y, ok := optionPoint(l, index)
	if !ok {
		t.Fatalf("option %d is outside the %d rendered rows", index, len(l.starts))
	}
	clickAt(t, a, x, y)
}

// optionPoint is where an option's first line is drawn. Options wrap, so the screen row
// comes from the render map and the live scroll offset, not from the option's index. It
// takes no *testing.T on purpose: callers run it on the event-loop goroutine, where a
// t.Fatal would kill the loop and every later wait would time out instead of reporting.
func optionPoint(l *questionOptions, index int) (x, y int, ok bool) {
	if index < 0 || index >= len(l.starts) {
		return 0, 0, false
	}
	ix, iy, _, _ := l.GetInnerRect()
	offset, _ := l.GetScrollOffset()
	return ix + 1, iy + l.starts[index] - offset, true
}

// showList brings the question owning l on screen. The form renders one question at a
// time, so another question's last-drawn rect points at whatever replaced it.
func showList(t *testing.T, a *App, l *questionOptions) {
	t.Helper()
	a.questionForm.focus(l)
	drawPrimitive(t, a.pages, 120, 30)
}

func clickAt(t *testing.T, a *App, x, y int) {
	t.Helper()
	ev := tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone)
	consumed, _ := a.pages.MouseHandler()(tview.MouseLeftClick, ev, func(p tview.Primitive) { a.app.SetFocus(p) })
	if !consumed {
		t.Fatalf("click at (%d,%d) was not consumed; the mounted form did not receive the mouse event", x, y)
	}
}

func clickCancel(t *testing.T, a *App) {
	t.Helper()
	drawPrimitive(t, a.pages, 120, 30)
	x, y, _, _ := a.questionForm.cancel.GetRect()
	clickAt(t, a, x+1, y)
}

func tabToCancel(t *testing.T, a *App) {
	t.Helper()
	for step := 0; step < 2*len(a.questionForm.blocks)+4; step++ {
		if a.app.GetFocus() == tview.Primitive(a.questionForm.cancel) {
			return
		}
		tab := tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone)
		noFocus := func(tview.Primitive) {}
		switch p := a.app.GetFocus().(type) {
		case *questionOptions:
			p.InputHandler()(tab, noFocus)
		case *tview.Button:
			p.InputHandler()(tab, noFocus)
		case *tview.InputField:
			p.InputHandler()(tab, noFocus)
		default:
			t.Fatalf("focus = %T, which the form's Tab ring does not own", p)
		}
	}
	t.Fatalf("Tab never reached the Cancel button; focus = %T", a.app.GetFocus())
}

func waitResult(t *testing.T, ch chan QuestionResult) QuestionResult {
	t.Helper()
	select {
	case res := <-ch:
		return res
	default:
		t.Fatal("no result was delivered to the waiting caller")
		return QuestionResult{}
	}
}

func TestQuestionPrompt_ShowsOneQuestionAtATimeWithItsPosition(t *testing.T) {
	for _, size := range []struct {
		name          string
		width, height int
	}{
		{"wide", 120, 24},
		{"narrow", 44, 24},
	} {
		t.Run(size.name, func(t *testing.T) {
			a := New(nil)
			req := questionFixture()
			openQuestions(t, a, req)

			text := screenText(drawPrimitive(t, a.pages, size.width, size.height))

			if want := "Question 1 of 3"; !strings.Contains(text, want) {
				t.Errorf("the form does not say %q:\n%s", want, text)
			}
			shown := req.Questions[0]
			if !strings.Contains(text, shown.Prompt) {
				t.Errorf("the focused question's prompt is missing:\n%s", text)
			}
			for _, option := range shown.Options {
				if !strings.Contains(text, option) {
					t.Errorf("option %q of the shown question is missing:\n%s", option, text)
				}
			}
			for _, other := range req.Questions[1:] {
				if strings.Contains(text, other.Prompt) {
					t.Errorf("question %q is rendered alongside the focused one; the form shows one at a time:\n%s", other.ID, text)
				}
			}
			if !strings.Contains(text, "Submit") || !strings.Contains(text, "Cancel") {
				t.Errorf("the form controls are missing:\n%s", text)
			}
		})
	}
}

// TestQuestionPrompt_EveryControlIsDrawnAtTheSmallestTerminal is why the four buttons take
// two rows: on one row they need 35 columns, and a mouse-only user on a 20-column terminal
// would find Submit and Cancel off the right edge.
func TestQuestionPrompt_EveryControlIsDrawnAtTheSmallestTerminal(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())

	text := screenText(drawPrimitive(t, a.pages, 20, 24))

	for _, label := range []string{prevQuestionLabel, nextQuestionLabel, "Submit", "Cancel"} {
		if !strings.Contains(text, label) {
			t.Errorf("the %s control is not drawn at 20x24, so a mouse cannot reach it:\n%s", label, text)
		}
	}
}

// TestQuestionPrompt_QuestionNavigationSitsUnderTheQuestion pins where the mouse's route
// between questions is drawn: with the form's actions at the bottom of the box, a Prev/Next
// row parked beside them reads as a form action and stands between the last question and
// Submit. It belongs against the question it moves.
func TestQuestionPrompt_QuestionNavigationSitsUnderTheQuestion(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())
	drawPrimitive(t, a.pages, 44, 24)

	_, optionsY, _, optionsH := a.questionForm.blocks[0].options.GetRect()
	_, prevY, _, _ := a.questionForm.prev.GetRect()
	_, submitY, _, _ := a.questionForm.submit.GetRect()

	if prevY != optionsY+optionsH {
		t.Errorf("the Prev/Next row is drawn at y=%d, want %d — the row directly under the question", prevY, optionsY+optionsH)
	}
	if submitY <= prevY {
		t.Errorf("Submit is drawn at y=%d, at or above the navigation row at y=%d", submitY, prevY)
	}
}

func TestQuestionPrompt_NavigationShowsEachQuestionAndItsPosition(t *testing.T) {
	a := New(nil)
	req := questionFixture()
	openQuestions(t, a, req)

	for i, q := range req.Questions {
		text := screenText(drawPrimitive(t, a.pages, 44, 24))
		if want := fmt.Sprintf("Question %d of %d", i+1, len(req.Questions)); !strings.Contains(text, want) {
			t.Errorf("counter does not read %q at question %d:\n%s", want, i, text)
		}
		if !strings.Contains(text, q.Prompt) {
			t.Errorf("question %d is not the one shown:\n%s", i, text)
		}
		// The frame has to hold exactly this question. Checking only that the new one
		// arrived leaves a stage that never releases the old ones passing every step.
		for j, other := range req.Questions {
			if j == i {
				continue
			}
			if strings.Contains(text, other.Prompt) {
				t.Errorf("question %d's prompt is still drawn while question %d is shown:\n%s", j, i, text)
			}
			for _, option := range other.Options {
				if strings.Contains(text, option) {
					t.Errorf("option %q of question %d is still drawn while question %d is shown:\n%s", option, j, i, text)
				}
			}
		}
		if i < len(req.Questions)-1 {
			tabFromFocus(t, a)
		}
	}
}

func maximumQuestionRequest() QuestionRequest {
	req := QuestionRequest{}
	for q := 0; q < 5; q++ {
		spec := QuestionSpec{ID: fmt.Sprintf("q%d", q), Prompt: fmt.Sprintf("Question %d?", q)}
		for o := 0; o < 8; o++ {
			spec.Options = append(spec.Options, fmt.Sprintf("q%d option %d", q, o))
		}
		req.Questions = append(req.Questions, spec)
	}
	return req
}

func tabFromFocus(t *testing.T, a *App) {
	t.Helper()
	list, ok := a.app.GetFocus().(*questionOptions)
	if !ok {
		t.Fatalf("focus = %T, want a question list to move away from", a.app.GetFocus())
	}
	list.InputHandler()(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})
}

func TestQuestionPrompt_ShortTerminalScrollsToTheLastQuestion(t *testing.T) {
	a := New(nil)
	req := maximumQuestionRequest()
	results := openQuestions(t, a, req)
	last := req.Questions[len(req.Questions)-1]

	if text := screenText(drawPrimitive(t, a.pages, 44, 24)); strings.Contains(text, last.Options[0]) {
		t.Fatalf("setup: the maximum payload already fits at 44x24, so nothing is scrolled:\n%s", text)
	}
	for i := 0; i < len(req.Questions)-1; i++ {
		tabFromFocus(t, a)
	}
	text := screenText(drawPrimitive(t, a.pages, 44, 24))

	if !strings.Contains(text, last.Prompt) {
		t.Errorf("the last question stayed off screen after moving focus to it:\n%s", text)
	}
	for _, option := range last.Options {
		if !strings.Contains(text, option) {
			t.Errorf("option %q of the last question is not visible:\n%s", option, text)
		}
	}
	if !strings.Contains(text, "Submit") || !strings.Contains(text, "Cancel") {
		t.Error("the buttons scrolled away with the questions")
	}

	focused, ok := a.app.GetFocus().(*questionOptions)
	if !ok {
		t.Fatalf("focus = %T, want the last question's list", a.app.GetFocus())
	}
	chooseByKeyboard(t, focused, 7)
	a.submitQuestionForm()

	res := waitResult(t, results)
	if got := res.Answers[4].Selected; len(got) != 1 || got[0] != last.Options[7] {
		t.Errorf("the scrolled-to question answered %v, want %v", got, last.Options[7:])
	}
}

func oversizedQuestion() QuestionRequest {
	spec := QuestionSpec{
		ID:          "scope",
		Prompt:      maxRuneText("scope", provider.MaxAskUserTextRunes),
		AllowCustom: true,
	}
	for o := 0; o < 8; o++ {
		spec.Options = append(spec.Options, fmt.Sprintf("option-%d %s", o, strings.Repeat("detail ", 6)))
	}
	return QuestionRequest{Questions: []QuestionSpec{spec}}
}

func TestQuestionPrompt_OversizedQuestionScrollsWithinItsBlock(t *testing.T) {
	a := New(nil)
	req := oversizedQuestion()
	results := openQuestions(t, a, req)
	block := a.questionForm.blocks[0]

	text := screenText(drawPrimitive(t, a.pages, 20, 24))
	if strings.Contains(text, "option-7") {
		t.Fatalf("setup: a maximum-field single question already fits at 20x24:\n%s", text)
	}
	if !strings.Contains(text, "option-0") {
		t.Errorf("the first option is not on screen at 20x24:\n%s", text)
	}
	for i := 0; i < len(block.spec.Options); i++ {
		pressList(block.options, tcell.KeyDown)
	}
	text = screenText(drawPrimitive(t, a.pages, 20, 24))

	if !strings.Contains(text, "option-7") {
		t.Errorf("↑↓ could not bring the last option of an over-tall question on screen:\n%s", text)
	}
	if !strings.Contains(text, "Type your own") {
		t.Errorf("the custom-answer row of an over-tall question stayed off screen:\n%s", text)
	}

	chooseByKeyboard(t, block.options, len(block.spec.Options))
	if a.app.GetFocus() != tview.Primitive(block.field) {
		t.Fatalf("focus = %T after choosing the custom row, want that question's text field", a.app.GetFocus())
	}
	drawPrimitive(t, a.pages, 20, 24)
	_, fieldY, _, fieldHeight := block.field.GetRect()
	_, gridY, _, gridHeight := a.questionForm.stage.GetRect()
	if fieldHeight < 1 || fieldY < gridY || fieldY+fieldHeight > gridY+gridHeight {
		t.Errorf("the custom field is drawn at y=%d h=%d, outside the grid at y=%d h=%d", fieldY, fieldHeight, gridY, gridHeight)
	}

	block.field.SetText("something else entirely")
	a.submitQuestionForm()
	if got := waitResult(t, results).Answers[0].Custom; got != "something else entirely" {
		t.Errorf("custom answer = %q, want the text typed into the revealed field", got)
	}
}

func TestQuestionPrompt_ShrinkingTheTerminalKeepsTheFocusedQuestionVisible(t *testing.T) {
	a := New(nil)
	req := maximumQuestionRequest()
	openQuestions(t, a, req)
	drawPrimitive(t, a.pages, 120, 30)
	for i := 0; i < len(req.Questions)-1; i++ {
		tabFromFocus(t, a)
	}
	last := len(req.Questions) - 1

	text := screenText(drawPrimitive(t, a.pages, 44, 12))

	if !strings.Contains(text, req.Questions[last].Prompt) {
		t.Errorf("shrinking the terminal left the focused question off screen:\n%s", text)
	}
	if a.app.GetFocus() != tview.Primitive(a.questionForm.blocks[last].options) {
		t.Errorf("focus = %T after the resize, want the question it was on", a.app.GetFocus())
	}
}

// TestQuestionPrompt_LongOptionsAreShownInFull replaces a test that pinned two
// equal-prefix options staying distinguishable *after* truncation. Options are no longer
// truncated — each wraps across as many lines as it needs — so the property is now the
// stronger one: both labels are on screen in full, and no row carries an ellipsis.
func TestQuestionPrompt_LongOptionsAreShownInFull(t *testing.T) {
	prefix := strings.Repeat("migrate the ingestion stage ", 2)
	for _, tc := range []struct{ name, a, b string }{
		{"ascii", prefix + "then stop there", prefix + "then keep going"},
		{"wide", prefix + "停止", prefix + "続行"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			req := QuestionRequest{Questions: []QuestionSpec{{
				ID: "scope", Prompt: "Which scope?", Options: []string{tc.a, tc.b},
			}}}
			results := openQuestions(t, a, req)

			text := flattenScreen(screenText(drawPrimitive(t, a.pages, 44, 24)))
			for _, option := range req.Questions[0].Options {
				if !strings.Contains(text, flattenScreen(option)) {
					t.Errorf("option %q is not shown in full at 44 columns:\n%s", option, text)
				}
			}
			if strings.Contains(text, "…") {
				t.Errorf("a row was truncated; options wrap instead of fitting:\n%s", text)
			}

			chooseByKeyboard(t, a.questionForm.blocks[0].options, 1)
			a.submitQuestionForm()
			if got := waitResult(t, results).Answers[0].Selected; len(got) != 1 || got[0] != tc.b {
				t.Errorf("selected = %v, want the second option chosen by its own row", got)
			}
		})
	}
}

func TestQuestionPrompt_TagShapedTextRendersLiterally(t *testing.T) {
	a := New(nil)
	req := QuestionRequest{Questions: []QuestionSpec{{
		ID:      "conflict",
		Prompt:  "Which [side] wins?",
		Options: []string{"[red]Keep local[-]", "[yellow]Keep remote[-]"},
	}}}
	results := openQuestions(t, a, req)

	text := screenText(drawPrimitive(t, a.pages, 120, 24))

	for _, want := range append([]string{req.Questions[0].Prompt}, req.Questions[0].Options...) {
		if !strings.Contains(text, want) {
			t.Errorf("%q is not displayed literally; it was read as markup:\n%s", want, text)
		}
	}
	chooseByKeyboard(t, a.questionForm.blocks[0].options, 0)
	a.submitQuestionForm()
	if got := waitResult(t, results).Answers[0].Selected; len(got) != 1 || got[0] != req.Questions[0].Options[0] {
		t.Errorf("submitted %v, want the option's original bracketed text", got)
	}
}

// listCursorRows counts the rows the cursor accent is painted on. The cursor is a color,
// not reverse video: a reversed row is a solid bar that reads louder than the mark beside
// it, which is what hid a chosen row's `(*)` from a real terminal at the mark's own column.
func listCursorRows(t *testing.T, screen tcell.SimulationScreen, o *questionOptions) int {
	t.Helper()
	cells, width, _ := screen.GetContents()
	x, y, w, h := o.GetInnerRect()
	rows := 0
	for row := y; row < y+h; row++ {
		for col := x; col < x+w; col++ {
			fg, _, attrs := cells[row*width+col].Style.Decompose()
			if attrs&tcell.AttrReverse != 0 {
				t.Errorf("cell (%d,%d) is reverse video; the question cursor is drawn as an accent color", col, row)
			}
			if fg == accentTeal {
				rows++
				break
			}
		}
	}
	return rows
}

func TestQuestionPrompt_TheShownQuestionShowsACursorOnlyWhileItHasFocus(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())
	blocks := a.questionForm.blocks
	chooseByKeyboard(t, blocks[0].options, 0)
	a.questionForm.focus(blocks[0].options)

	screen := drawPrimitive(t, a.pages, 120, 24)
	if got := listCursorRows(t, screen, blocks[0].options); got != 1 {
		t.Errorf("the focused question shows %d cursor rows, want 1", got)
	}

	a.questionForm.focus(a.questionForm.submit)
	screen = drawPrimitive(t, a.pages, 120, 24)
	if got := listCursorRows(t, screen, blocks[0].options); got != 0 {
		t.Errorf("the question shows %d cursor rows while Submit holds focus, want 0", got)
	}
	if text := screenText(screen); !strings.Contains(text, singleChosenMark+" Local disk") {
		t.Errorf("moving focus off the question changed its answer marks:\n%s", text)
	}
}

func TestQuestionPrompt_NarrowLayoutWrapsPromptsAndOptions(t *testing.T) {
	a := New(nil)
	req := QuestionRequest{Questions: []QuestionSpec{
		{
			ID:      "scope",
			Prompt:  "Which parts of the pipeline should the migration cover before the freeze begins?",
			Options: []string{"Only the ingestion stage and nothing downstream of it for now", "Everything"},
		},
		{ID: "when", Prompt: "When should it run?", Options: []string{"Tonight", "Next week"}},
	}}
	openQuestions(t, a, req)

	text := screenText(drawPrimitive(t, a.pages, 44, 24))

	if !strings.Contains(text, "Which parts of the pipeline") {
		t.Error("the long prompt's opening text is missing")
	}
	if !strings.Contains(text, "freeze begins?") {
		t.Error("the long prompt did not wrap; its tail is missing")
	}
	if strings.Contains(text, "…") {
		t.Error("a row was truncated; the narrow layout wraps instead of fitting")
	}
	if !strings.Contains(flattenScreen(text), flattenScreen(req.Questions[0].Options[0])) {
		t.Errorf("the over-long option is not shown in full:\n%s", text)
	}
	if got := a.questionForm.blocks[0].answer().Selected; len(got) != 0 {
		t.Errorf("fitting the label changed the answer state: %v", got)
	}
}

func TestQuestionPrompt_SingleSelectKeepsOneOptionPerQuestion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		choose func(t *testing.T, a *App, l *questionOptions, index int)
	}{
		{"keyboard", func(t *testing.T, _ *App, l *questionOptions, index int) { chooseByKeyboard(t, l, index) }},
		{"mouse", func(t *testing.T, a *App, l *questionOptions, index int) { clickRow(t, a, l, index) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			results := openQuestions(t, a, questionFixture())
			first := a.questionForm.blocks[0]

			tc.choose(t, a, first.options, 0)
			tc.choose(t, a, first.options, 1)
			a.submitQuestionForm()

			res := waitResult(t, results)
			if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Object store" {
				t.Errorf("single-select answer = %v, want only the second choice", got)
			}
			if got := res.Answers[1].Selected; len(got) != 0 {
				t.Errorf("answering question 1 changed question 2's answer: %v", got)
			}
		})
	}
}

func TestQuestionPrompt_MultiSelectTogglesOnlyItsOwnOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		choose func(t *testing.T, a *App, l *questionOptions, index int)
	}{
		{"keyboard", func(t *testing.T, _ *App, l *questionOptions, index int) { chooseByKeyboard(t, l, index) }},
		{"mouse", func(t *testing.T, a *App, l *questionOptions, index int) { clickRow(t, a, l, index) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			results := openQuestions(t, a, questionFixture())
			multi := a.questionForm.blocks[1]

			tc.choose(t, a, multi.options, 0)
			tc.choose(t, a, multi.options, 2)
			tc.choose(t, a, multi.options, 1)
			tc.choose(t, a, multi.options, 1)
			tc.choose(t, a, a.questionForm.blocks[0].options, 0)
			a.submitQuestionForm()

			res := waitResult(t, results)
			want := []string{"Linux", "Windows"}
			if got := res.Answers[1].Selected; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
				t.Errorf("multi-select answer = %v, want %v in request option order", got, want)
			}
			if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Local disk" {
				t.Errorf("the single-select question collapsed to %v, want its one chosen option", got)
			}
		})
	}
}

func TestQuestionPrompt_CustomTextStaysScopedToItsQuestion(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())
	custom := a.questionForm.blocks[2]

	chooseByKeyboard(t, a.questionForm.blocks[0].options, 0)
	chooseByKeyboard(t, custom.options, len(custom.spec.Options))
	if a.app.GetFocus() != custom.field {
		t.Fatal("choosing the custom row did not focus that question's text field")
	}
	custom.field.SetText("codemeld ask")
	a.submitQuestionForm()

	res := waitResult(t, results)
	if res.Answers[2].Custom != "codemeld ask" {
		t.Errorf("custom answer = %q, want the typed text", res.Answers[2].Custom)
	}
	if got := res.Answers[2].Selected; len(got) != 0 {
		t.Errorf("the custom answer also selected options %v; want the typed text to replace them", got)
	}
	if res.Answers[0].Custom != "" || res.Answers[1].Custom != "" {
		t.Errorf("custom text leaked to another question: %q / %q", res.Answers[0].Custom, res.Answers[1].Custom)
	}
	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Local disk" {
		t.Errorf("typing a custom answer changed another question's selection: %v", got)
	}
}

// TestQuestionPrompt_MultiSelectKeepsItsOptionsAlongsideCustomText covers the one
// combination the two response modes make possible: a multi-select question is the only
// place where a listed set and typed text are both legitimate answers, so each of the two
// choose branches must leave the other alone.
func TestQuestionPrompt_MultiSelectKeepsItsOptionsAlongsideCustomText(t *testing.T) {
	a := New(nil)
	req := QuestionRequest{Questions: []QuestionSpec{
		{ID: "targets", Prompt: "Which platforms?", Options: []string{"Linux", "macOS", "Windows"}, MultiSelect: true, AllowCustom: true},
		{ID: "when", Prompt: "When should it run?", Options: []string{"Tonight", "Next week"}},
	}}
	results := openQuestions(t, a, req)
	both := a.questionForm.blocks[0]

	chooseByKeyboard(t, both.options, 0)
	chooseByKeyboard(t, both.options, 2)
	chooseByKeyboard(t, both.options, len(both.spec.Options))
	if !both.customOn {
		t.Fatal("setup: choosing the custom row of a multi-select question did not enable it")
	}
	both.field.SetText("plan9")
	chooseByKeyboard(t, both.options, 1)
	chooseByKeyboard(t, a.questionForm.blocks[1].options, 0)
	a.submitQuestionForm()

	encoded, err := waitResult(t, results).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"answers":[` +
		`{"id":"targets","prompt":"Which platforms?","selected":["Linux","macOS","Windows"],"custom":"plan9"},` +
		`{"id":"when","prompt":"When should it run?","selected":["Tonight"]}]}`
	if encoded != want {
		t.Errorf("combined-mode JSON =\n%s\nwant\n%s", encoded, want)
	}
}

func TestQuestionPrompt_CustomTextUnavailableWhenNotEnabled(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())

	plain := a.questionForm.blocks[0]
	if plain.field != nil {
		t.Error("a question without allow_custom built a text field")
	}
	if got := plain.options.GetItemCount(); got != len(plain.spec.Options) {
		t.Errorf("row count = %d, want %d (no custom row)", got, len(plain.spec.Options))
	}
	if text := screenText(drawPrimitive(t, a.pages, 120, 24)); strings.Contains(text, customAnswerRowLabel) {
		t.Errorf("%q is offered on a question without allow_custom:\n%s", customAnswerRowLabel, text)
	}
	custom := a.questionForm.blocks[2]
	a.questionForm.focus(custom.options)
	if text := screenText(drawPrimitive(t, a.pages, 120, 24)); !strings.Contains(text, customAnswerRowLabel) {
		t.Errorf("%q is missing from the custom-enabled question:\n%s", customAnswerRowLabel, text)
	}
}

func TestQuestionPrompt_SubmitEncodesDeterministicJSON(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())

	chooseByKeyboard(t, a.questionForm.blocks[0].options, 1)
	multi := a.questionForm.blocks[1]
	chooseByKeyboard(t, multi.options, 2)
	chooseByKeyboard(t, multi.options, 0)
	custom := a.questionForm.blocks[2]
	chooseByKeyboard(t, custom.options, len(custom.spec.Options))
	custom.field.SetText("  codemeld ask  ")
	a.submitQuestionForm()

	encoded, err := waitResult(t, results).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"answers":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","selected":["Object store"]},` +
		`{"id":"targets","prompt":"Which platforms must ship first?","selected":["Linux","Windows"]},` +
		`{"id":"name","prompt":"What should the command be called?","selected":[],"custom":"codemeld ask"}]}`
	if encoded != want {
		t.Errorf("submitted JSON =\n%s\nwant\n%s", encoded, want)
	}
}

func TestQuestionPrompt_UnansweredQuestionsEncodeEmptyNotInferred(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())

	a.submitQuestionForm()

	encoded, err := waitResult(t, results).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"answers":[` +
		`{"id":"storage","prompt":"Where should sessions be stored?","selected":[]},` +
		`{"id":"targets","prompt":"Which platforms must ship first?","selected":[]},` +
		`{"id":"name","prompt":"What should the command be called?","selected":[]}]}`
	if encoded != want {
		t.Errorf("unanswered JSON =\n%s\nwant\n%s", encoded, want)
	}
}

func TestQuestionPrompt_EscapeCancelsWithoutInterruptingTheWaitingTurn(t *testing.T) {
	a := New(nil)
	canceller := &fakeStreamCanceller{inFlight: true}
	a.SetStreamCanceller(canceller)
	a.input.SetText("half-written prompt")
	a.app.SetFocus(a.input)
	results := openQuestions(t, a, questionFixture())
	chooseByKeyboard(t, a.questionForm.blocks[0].options, 0)

	a.HandleEsc()

	res := waitResult(t, results)
	if !res.Cancelled {
		t.Error("ESC delivered an uncancelled result")
	}
	if len(res.Answers) != 0 {
		t.Errorf("ESC submitted %d answers; a dismissed form answers nothing", len(res.Answers))
	}
	if canceller.calls != 0 {
		t.Error("ESC interrupted the agent turn waiting on the form; it must only close the form")
	}
	if a.pages.HasPage(questionFormPage) || a.questionFormOpen {
		t.Error("the form page outlived its cancellation")
	}
	if a.app.GetFocus() != a.input {
		t.Errorf("focus = %T after cancellation, want the input area it was captured from", a.app.GetFocus())
	}
	if got := a.input.GetText(); got != "half-written prompt" {
		t.Errorf("input draft = %q, want it untouched by the form", got)
	}
}

func TestQuestionPrompt_CancelControlDismissesWithoutInterruptingTheWaitingTurn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		activate func(t *testing.T, a *App)
	}{
		{"keyboard", func(t *testing.T, a *App) {
			tabToCancel(t, a)
			a.questionForm.cancel.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
		}},
		{"mouse", func(t *testing.T, a *App) { clickCancel(t, a) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			canceller := &fakeStreamCanceller{inFlight: true}
			a.SetStreamCanceller(canceller)
			a.input.SetText("half-written prompt")
			a.app.SetFocus(a.input)
			results := openQuestions(t, a, questionFixture())
			chooseByKeyboard(t, a.questionForm.blocks[0].options, 0)

			tc.activate(t, a)

			res := waitResult(t, results)
			if !res.Cancelled {
				t.Error("the Cancel control delivered an uncancelled result")
			}
			if len(res.Answers) != 0 {
				t.Errorf("Cancel submitted %d answers; a dismissed form answers nothing", len(res.Answers))
			}
			if canceller.calls != 0 {
				t.Error("Cancel interrupted the agent turn waiting on the form; it must only close the form")
			}
			if a.pages.HasPage(questionFormPage) || a.questionFormOpen {
				t.Error("the form page outlived the Cancel control")
			}
			if a.app.GetFocus() != a.input {
				t.Errorf("focus = %T after Cancel, want the input area it was captured from", a.app.GetFocus())
			}
			if got := a.input.GetText(); got != "half-written prompt" {
				t.Errorf("input draft = %q, want it untouched by the form", got)
			}
		})
	}
}

func TestQuestionPrompt_CloseRestoresFocusAndIsIdempotent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(*App)
	}{
		{"submit", func(a *App) { a.submitQuestionForm() }},
		{"cancel", func(a *App) { a.cancelQuestionForm() }},
		{"escape", func(a *App) { a.HandleEsc() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.app.SetFocus(a.input)
			results := openQuestions(t, a, questionFixture())
			if a.app.GetFocus() == a.input {
				t.Fatal("the input kept focus while the form was open; typing would not reach the form")
			}

			tc.close(a)
			waitResult(t, results)

			if a.app.GetFocus() != a.input {
				t.Errorf("focus = %T after %s, want the input area", a.app.GetFocus(), tc.name)
			}
			a.submitQuestionForm()
			a.cancelQuestionForm()
			select {
			case res := <-results:
				t.Fatalf("a repeated close delivered a second result: %+v", res)
			default:
			}
		})
	}
}

func TestQuestionPrompt_CountsAsOverlayAndRefusesToStack(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())

	if !a.anyOverlayOpen() {
		t.Error("the question form does not register in the shared overlay guard")
	}
	if a.openQuestionForm(questionFixture(), make(chan QuestionResult, 1)) {
		t.Error("a second question form stacked over the open one")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := a.AskQuestions(ctx, questionFixture()); !errors.Is(err, errQuestionFormBusy) {
		t.Errorf("second AskQuestions error = %v, want %v", err, errQuestionFormBusy)
	}
	a.OpenSecretPrompt(SecretPromptRequest{Label: "API key:", OnSubmit: func(string) {}})
	if a.secretPromptOpen {
		t.Error("the secret prompt opened over the question form")
	}

	a.submitQuestionForm()
	waitResult(t, results)
	if a.anyOverlayOpen() {
		t.Error("the question form still counts as an overlay after it closed")
	}
}

func TestAskQuestions_RefusesAnEmptyRequest(t *testing.T) {
	a := New(nil)
	if _, err := a.AskQuestions(context.Background(), QuestionRequest{}); !errors.Is(err, errQuestionFormEmpty) {
		t.Errorf("error = %v, want %v", err, errQuestionFormEmpty)
	}
	if a.pages.HasPage(questionFormPage) {
		t.Error("an empty request mounted a form")
	}
}

func TestAskQuestions_CancelledContextNeverMountsTheForm(t *testing.T) {
	a := New(nil)
	a.app.SetFocus(a.input)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := a.AskQuestions(ctx, questionFixture())

	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if len(res.Answers) != 0 || res.Cancelled {
		t.Errorf("result = %+v, want the zero result for an aborted form", res)
	}
	if a.pages.HasPage(questionFormPage) || a.questionFormOpen || a.questionForm != nil {
		t.Error("an already-cancelled request mounted the form")
	}
	select {
	case <-a.questionFormMounts:
		t.Error("an already-cancelled request announced a mount")
	default:
	}
	if a.app.GetFocus() != a.input {
		t.Errorf("focus = %T after the abort, want the input area it never left", a.app.GetFocus())
	}
}

func TestQuestionPrompt_LiveKeyboardSubmitReturnsAnswersToTheBlockedCaller(t *testing.T) {
	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)
	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()
	a.running.Store(true)
	defer a.running.Store(false)

	resc := make(chan QuestionResult, 1)
	go func() {
		res, err := a.AskQuestions(context.Background(), questionFixture())
		if err != nil {
			resc <- QuestionResult{Cancelled: true}
			return
		}
		resc <- res
	}()
	waitOnLoop(t, a, "question form mount", func() bool { return a.pages.HasPage(questionFormPage) })

	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)

	var res QuestionResult
	select {
	case res = <-resc:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("AskQuestions did not return within 2s")
	}
	var focus tview.Primitive
	a.app.QueueUpdate(func() { focus = a.app.GetFocus() })
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}

	if res.Cancelled {
		t.Fatal("the live submit came back cancelled")
	}
	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Local disk" {
		t.Errorf("live answer = %v, want the option Enter chose", got)
	}
	if focus != a.input {
		t.Errorf("focus = %T after the live submit, want the input area", focus)
	}
}

func askLive(t *testing.T, a *App, req QuestionRequest) chan QuestionResult {
	t.Helper()
	resc := make(chan QuestionResult, 1)
	go func() {
		res, err := a.AskQuestions(context.Background(), req)
		if err != nil {
			resc <- QuestionResult{Cancelled: true}
			return
		}
		resc <- res
	}()
	waitOnLoop(t, a, "question form mount", func() bool { return a.pages.HasPage(questionFormPage) })
	return resc
}

func liveResult(t *testing.T, a *App, resc chan QuestionResult) QuestionResult {
	t.Helper()
	select {
	case res := <-resc:
		return res
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("the blocked AskQuestions caller did not return within 2s")
		return QuestionResult{}
	}
}

func liveScreenText(t *testing.T, h *appHarness) string {
	t.Helper()
	var text string
	h.a.app.QueueUpdate(func() { text = screenText(h.screen) })
	return text
}

func liveClickAt(t *testing.T, h *appHarness, x, y int) {
	t.Helper()
	h.dropStaleDraw()
	h.screen.InjectMouse(x, y, tcell.Button1, tcell.ModNone)
	h.screen.InjectMouse(x, y, tcell.ButtonNone, tcell.ModNone)
	h.waitDraw()
}

// liveClickRow clicks an option by its index in the question, translating through the
// list's scroll offset so a clipped list is clicked where the option is actually drawn.
// It then waits for the click's effect rather than for a draw: the two injected mouse
// events produce draws of their own, so a draw can arrive before the click is acted on.
func liveClickRow(t *testing.T, h *appHarness, question, option int) {
	t.Helper()
	liveShowQuestion(t, h, question)
	var x, y, wasCurrent int
	var wasChosen []bool
	var ok bool
	h.runDraw(func() {
		block := h.a.questionForm.blocks[question]
		x, y, ok = optionPoint(block.options, option)
		wasCurrent = block.options.GetCurrentItem()
		wasChosen = append([]bool(nil), block.chosen...)
	})
	if !ok {
		t.Fatalf("option %d of question %d was not rendered", option, question)
	}
	liveClickAt(t, h, x, y)
	waitOnLoop(t, h.a, fmt.Sprintf("the click on question %d option %d to land", question, option), func() bool {
		block := h.a.questionForm.blocks[question]
		return block.options.GetCurrentItem() != wasCurrent || !slices.Equal(block.chosen, wasChosen)
	})
}

// liveShowQuestion brings a question on screen the way a mouse-only user must: by clicking
// Next until the stage shows it. Focusing the block directly would be a state change no
// gesture can produce, which is what hid the missing mouse navigation for eight rounds.
func liveShowQuestion(t *testing.T, h *appHarness, question int) {
	t.Helper()
	var at, count int
	h.a.app.QueueUpdate(func() {
		at, count = h.a.questionForm.focusedIndex(), len(h.a.questionForm.blocks)
	})
	for step := 0; at != question; step++ {
		if step >= count {
			t.Fatalf("clicking Next %d times never showed question %d", step, question)
		}
		at = (at + 1) % count
		liveStepQuestion(t, h, nextControl, at)
	}
}

func liveClickButton(t *testing.T, h *appHarness, button func(*questionForm) *tview.Button) {
	t.Helper()
	var x, y int
	h.a.app.QueueUpdate(func() {
		bx, by, _, _ := button(h.a.questionForm).GetRect()
		x, y = bx+1, by
	})
	liveClickAt(t, h, x, y)
}

func liveClickSubmit(t *testing.T, h *appHarness) {
	t.Helper()
	liveClickButton(t, h, func(f *questionForm) *tview.Button { return f.submit })
}

func nextControl(f *questionForm) *tview.Button { return f.next }
func prevControl(f *questionForm) *tview.Button { return f.prev }

// liveStepQuestion moves the shown question by clicking Prev or Next — the only route a
// mouse has to a question that is not drawn — then forces the redraw that swaps the stage,
// so the caller's rect and screen reads see the question it asked for.
func liveStepQuestion(t *testing.T, h *appHarness, control func(*questionForm) *tview.Button, want int) {
	t.Helper()
	liveClickButton(t, h, control)
	waitOnLoop(t, h.a, fmt.Sprintf("the click to show question %d", want), func() bool {
		return h.a.questionForm.focusedIndex() == want
	})
	h.runDraw(func() {})
}

func liveWheel(t *testing.T, h *appHarness, x, y int, wheel tcell.ButtonMask) {
	t.Helper()
	h.dropStaleDraw()
	h.screen.InjectMouse(x, y, wheel, tcell.ModNone)
	h.waitDraw()
}

func TestQuestionPrompt_LiveMouseClicksReachTheMountedForm(t *testing.T) {
	defer func(interval time.Duration) { tview.DoubleClickInterval = interval }(tview.DoubleClickInterval)
	tview.DoubleClickInterval = time.Millisecond

	a := New(nil)
	h := newAppHarnessFor(t, a, 120, 30)
	a.running.Store(true)
	defer a.running.Store(false)

	resc := askLive(t, a, questionFixture())
	h.runDraw(func() {})

	liveClickRow(t, h, 0, 0)
	liveClickRow(t, h, 0, 1)
	liveClickRow(t, h, 1, 0)
	liveClickRow(t, h, 1, 2)
	liveClickRow(t, h, 1, 0)
	h.screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)

	res := liveResult(t, a, resc)
	h.stop()

	if res.Cancelled {
		t.Fatal("the live mouse submit came back cancelled")
	}
	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Object store" {
		t.Errorf("single-select answer = %v, want the second click to replace the first", got)
	}
	if got := res.Answers[1].Selected; len(got) != 1 || got[0] != "Windows" {
		t.Errorf("multi-select answer = %v, want the toggled-off option gone and Windows kept", got)
	}
}

// TestQuestionPrompt_MouseOnlyNavigationAnswersEveryQuestion is the property the form was
// missing: one question is drawn at a time, so without a clickable route to the others a
// pointer can only ever answer the first. Every step here is an injected click through the
// mounted App.Run — no test-only focus call — so a route the mouse does not have cannot
// make it pass.
func TestQuestionPrompt_MouseOnlyNavigationAnswersEveryQuestion(t *testing.T) {
	defer func(interval time.Duration) { tview.DoubleClickInterval = interval }(tview.DoubleClickInterval)
	tview.DoubleClickInterval = time.Millisecond

	a := New(nil)
	h := newAppHarnessFor(t, a, 120, 30)
	a.running.Store(true)
	defer a.running.Store(false)

	req := questionFixture()
	resc := askLive(t, a, req)
	h.runDraw(func() {})

	liveClickRow(t, h, 0, 0)
	liveStepQuestion(t, h, nextControl, 1)
	if text := liveScreenText(t, h); !strings.Contains(text, "Question 2 of 3") || !strings.Contains(text, req.Questions[1].Prompt) {
		t.Fatalf("clicking Next did not show question 2 and its counter:\n%s", text)
	}
	liveClickRow(t, h, 1, 0)
	liveClickRow(t, h, 1, 2)
	liveStepQuestion(t, h, nextControl, 2)
	liveClickRow(t, h, 2, 1)

	liveStepQuestion(t, h, prevControl, 1)
	if text := liveScreenText(t, h); !strings.Contains(text, "Question 2 of 3") {
		t.Fatalf("clicking Prev did not come back to question 2:\n%s", text)
	}
	liveClickRow(t, h, 1, 1)
	liveClickSubmit(t, h)

	res := liveResult(t, a, resc)
	h.stop()

	if res.Cancelled {
		t.Fatal("the mouse-only pass came back cancelled")
	}
	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Local disk" {
		t.Errorf("question 1 answer = %v, want the clicked option kept while the mouse moved on", got)
	}
	want := []string{"Linux", "macOS", "Windows"}
	if got := res.Answers[1].Selected; !slices.Equal(got, want) {
		t.Errorf("question 2 answer = %v, want %v — the options clicked before and after leaving it", got, want)
	}
	if got := res.Answers[2].Selected; len(got) != 1 || got[0] != "codemeld go" {
		t.Errorf("question 3 answer = %v, want the option only a mouse route could reach", got)
	}
}

// TestQuestionPrompt_PrevAndNextWrapAtBothBoundaries pins the wrap itself, which the
// interior steps of the mouse-only pass cannot: with endpoint clamping instead of the
// modulo, Prev on the first question and Next on the last would simply do nothing and every
// other mouse test would still pass. Neither wrap may cost an answer or a hand-scrolled
// position, since the pointer has no other route between the ends of the set.
func TestQuestionPrompt_PrevAndNextWrapAtBothBoundaries(t *testing.T) {
	a := New(nil)
	h := newAppHarnessFor(t, a, 20, 24)
	a.running.Store(true)
	defer a.running.Store(false)

	req := questionFixture()
	req.Questions = append(req.Questions, oversizedQuestion().Questions[0])
	last := len(req.Questions) - 1
	resc := askLive(t, a, req)
	h.runDraw(func() {})

	liveClickRow(t, h, 0, 0)
	liveStepQuestion(t, h, prevControl, last)
	if text := liveScreenText(t, h); !strings.Contains(text, fmt.Sprintf("Question %d of %d", last+1, len(req.Questions))) {
		t.Fatalf("Prev on the first question did not wrap to the last one:\n%s", text)
	}

	var x, y int
	h.a.app.QueueUpdate(func() {
		ox, oy, _, _ := a.questionForm.blocks[last].options.GetInnerRect()
		x, y = ox+1, oy+1
	})
	liveWheel(t, h, x, y, tcell.WheelDown)
	var scrolled int
	h.a.app.QueueUpdate(func() { scrolled, _ = a.questionForm.blocks[last].options.GetScrollOffset() })
	if scrolled == 0 {
		t.Fatal("setup: the wheel did not scroll the over-tall last question, so the wrap cannot undo it")
	}

	liveStepQuestion(t, h, nextControl, 0)
	if text := liveScreenText(t, h); !strings.Contains(text, "Question 1 of 4") ||
		!strings.Contains(flattenScreen(text), flattenScreen(req.Questions[0].Prompt)) {
		t.Fatalf("Next on the last question did not wrap to the first one:\n%s", text)
	}

	var offset int
	var kept []bool
	h.a.app.QueueUpdate(func() {
		offset, _ = a.questionForm.blocks[last].options.GetScrollOffset()
		kept = append([]bool(nil), a.questionForm.blocks[0].chosen...)
	})
	if offset != scrolled {
		t.Errorf("the wrapped-past question scrolled from row %d to %d; wrapping undid the reader's position", scrolled, offset)
	}
	if !kept[0] {
		t.Error("the first question's answer did not survive the two boundary wraps")
	}

	liveClickSubmit(t, h)
	res := liveResult(t, a, resc)
	h.stop()

	if got := res.Answers[0].Selected; !slices.Equal(got, []string{"Local disk"}) {
		t.Errorf("question 1 answer = %v, want [Local disk] carried across both wraps", got)
	}
}

// liveClickRepeat clicks the row that was just clicked, which tview reports as a double
// click. It deliberately waits for no state change — the point is that this click changes
// nothing — so the caller synchronizes on the next click that does act.
func liveClickRepeat(t *testing.T, h *appHarness, question, option int) {
	t.Helper()
	var x, y int
	var ok bool
	h.runDraw(func() {
		x, y, ok = optionPoint(h.a.questionForm.blocks[question].options, option)
	})
	if !ok {
		t.Fatalf("option %d of question %d was not rendered", option, question)
	}
	liveClickAt(t, h, x, y)
}

// TestQuestionPrompt_RapidClicksActWithoutUndoingEachOther holds both halves of the rule at
// once, with every click after the first classified as a double click: a quick click on a
// new row or on a button still acts, and a quick click on the row just chosen does not act
// again — one click selects the row and its option, and there is no second gesture that
// unselects it.
func TestQuestionPrompt_RapidClicksActWithoutUndoingEachOther(t *testing.T) {
	defer func(interval time.Duration) { tview.DoubleClickInterval = interval }(tview.DoubleClickInterval)
	tview.DoubleClickInterval = time.Hour

	a := New(nil)
	h := newAppHarnessFor(t, a, 120, 30)
	a.running.Store(true)
	defer a.running.Store(false)

	req := questionFixture()
	custom := len(req.Questions) - 1
	customRow := len(req.Questions[custom].Options)
	resc := askLive(t, a, req)
	h.runDraw(func() {})

	// tview alternates the classification: it resets its click clock after firing a double
	// click, so with the interval this wide every second click is the double and every other
	// one is plain. Each row below is therefore clicked at an odd position and repeated at
	// the even one that follows, which is the pair a real double click produces; the
	// `liveClickRow` calls that navigate first spend one click on `Next ›`, and that is what
	// keeps the pairs aligned.
	liveClickRow(t, h, 0, 1)              // 1: plain — chooses
	liveClickRepeat(t, h, 0, 1)           // 2: double on the same row — must not act
	liveClickRow(t, h, 1, 2)              // 3: Next, plain. 4: double on a new row — must act
	liveClickRow(t, h, 1, 0)              // 5: plain — checks Linux
	liveClickRepeat(t, h, 1, 0)           // 6: double on the same row — must not act
	liveClickRow(t, h, custom, 0)         // 7: Next, plain. 8: double on a new row — must act
	liveClickRow(t, h, custom, customRow) // 9: plain — opens the custom row
	waitOnLoop(t, a, "the custom field to take the click", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.questionForm.blocks[custom].field)
	})
	for _, r := range "BSD only" {
		h.screen.InjectKey(tcell.KeyRune, r, tcell.ModNone)
	}
	waitOnLoop(t, a, "the typed custom answer", func() bool {
		return a.questionForm.blocks[custom].field.GetText() == "BSD only"
	})
	liveClickRepeat(t, h, custom, customRow) // 10: double on the same row — must not act
	liveClickSubmit(t, h)                    // 11: plain

	res := liveResult(t, a, resc)
	h.stop()

	if res.Cancelled {
		t.Fatal("the rapid clicks cancelled instead of submitting")
	}
	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Object store" {
		t.Errorf("single-select answer = %v, want the clicked option to stay chosen through the repeat click", got)
	}
	if got := res.Answers[1].Selected; !slices.Equal(got, []string{"Linux", "Windows"}) {
		t.Errorf("multi-select answer = %v, want both: the repeat click must leave Linux checked and the quick click on Windows must still act", got)
	}
	if got := res.Answers[custom].Custom; got != "BSD only" {
		t.Errorf("custom answer = %q, want the repeat click to leave the custom row on and its text intact", got)
	}
}

// TestQuestionPrompt_AControlClickBetweenTwoRowClicksLeavesTheRowClickable is the other
// half of the repeat rule: a row is only repeated by the click *immediately* after it. tview
// keeps classifying by time alone, so a click on a form control between two clicks on one
// row still arrives as a double — and the second click on that row is then an ordinary
// click, which a multi-select user makes whenever they turn an option back off.
func TestQuestionPrompt_AControlClickBetweenTwoRowClicksLeavesTheRowClickable(t *testing.T) {
	defer func(interval time.Duration) { tview.DoubleClickInterval = interval }(tview.DoubleClickInterval)
	tview.DoubleClickInterval = time.Hour

	a := New(nil)
	h := newAppHarnessFor(t, a, 120, 30)
	a.running.Store(true)
	defer a.running.Store(false)

	req := QuestionRequest{Questions: []QuestionSpec{{
		ID: "targets", Prompt: "Which platforms must ship first?",
		Options: []string{"Linux", "macOS", "Windows"}, MultiSelect: true,
	}}}
	resc := askLive(t, a, req)
	h.runDraw(func() {})

	liveClickRow(t, h, 0, 0)           // 1: plain — checks Linux
	liveClickRow(t, h, 0, 1)           // 2: double on a new row — checks macOS
	liveClickButton(t, h, nextControl) // 3: plain — Next, which wraps back to this question
	liveClickRepeat(t, h, 0, 1)        // 4: double on macOS, but click 3 was not on that row
	liveClickSubmit(t, h)              // 5: plain

	res := liveResult(t, a, resc)
	h.stop()

	if res.Cancelled {
		t.Fatal("the click sequence cancelled instead of submitting")
	}
	if got := res.Answers[0].Selected; !slices.Equal(got, []string{"Linux"}) {
		t.Errorf("selected = %v, want [Linux]: the click after Next must toggle macOS back off", got)
	}
}

func TestQuestionPrompt_WheelReachesTheHiddenOptionsOfAnOverTallQuestion(t *testing.T) {
	a := New(nil)
	h := newAppHarnessFor(t, a, 20, 24)
	a.running.Store(true)
	defer a.running.Store(false)

	req := oversizedQuestion()
	resc := askLive(t, a, req)
	h.runDraw(func() {})
	last := req.Questions[0].Options[len(req.Questions[0].Options)-1]
	if text := liveScreenText(t, h); strings.Contains(flattenScreen(text), flattenScreen(last)) {
		t.Fatalf("setup: the over-tall question already shows %q at 20x24:\n%s", last, text)
	}

	var x, y int
	h.a.app.QueueUpdate(func() {
		lx, ly, _, _ := a.questionForm.blocks[0].options.GetInnerRect()
		x, y = lx+1, ly+1
	})
	// One notch at a time, each waiting for the draw it causes. Injecting them in a batch
	// and then observing the result races: injected events and QueueUpdate arrive on
	// different channels, so the observation can run while notches are still pending.
	var notches, target int
	h.a.app.QueueUpdate(func() {
		options := a.questionForm.blocks[0].options
		_, _, _, viewport := options.GetInnerRect()
		notches = options.contentHeight() - viewport
		target = options.lastLineOf(options.GetItemCount()-1) - viewport + 1
	})
	for i := 0; i < notches; i++ {
		var row int
		h.a.app.QueueUpdate(func() { row, _ = a.questionForm.blocks[0].options.GetScrollOffset() })
		if row >= target {
			break
		}
		liveWheel(t, h, x, y, tcell.WheelDown)
	}

	var offset int
	h.a.app.QueueUpdate(func() { offset, _ = a.questionForm.blocks[0].options.GetScrollOffset() })
	if offset == 0 {
		t.Fatal("the wheel over a clipped question never scrolled it; its hidden options stay out of mouse reach")
	}
	if !strings.Contains(flattenScreen(liveScreenText(t, h)), flattenScreen(last)) {
		t.Fatalf("wheeling over the clipped question did not reveal %q:\n%s", last, liveScreenText(t, h))
	}

	liveClickRow(t, h, 0, len(req.Questions[0].Options)-1)
	h.screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)

	res := liveResult(t, a, resc)
	h.stop()

	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != last {
		t.Errorf("answer = %v, want %q chosen by wheeling to it and clicking it", got, last)
	}
}

func TestQuestionPrompt_SubmitButtonDeliversFromEnterAndMouse(t *testing.T) {
	t.Run("enter", func(t *testing.T) {
		a := New(nil)
		a.app.SetFocus(a.input)
		results := openQuestions(t, a, questionFixture())
		chooseByKeyboard(t, a.questionForm.blocks[0].options, 1)
		submit := a.questionForm.submit
		a.questionForm.focus(submit)

		submit.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

		res := waitResult(t, results)
		if res.Cancelled {
			t.Error("Enter on Submit cancelled instead of submitting")
		}
		if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Object store" {
			t.Errorf("Enter on Submit delivered %v, want the chosen option", got)
		}
		if a.pages.HasPage(questionFormPage) || a.questionFormOpen {
			t.Error("the form page outlived Enter on Submit")
		}
		if a.app.GetFocus() != a.input {
			t.Errorf("focus = %T after Enter on Submit, want the input area it was captured from", a.app.GetFocus())
		}
	})
	t.Run("mouse", func(t *testing.T) {
		defer func(interval time.Duration) { tview.DoubleClickInterval = interval }(tview.DoubleClickInterval)
		tview.DoubleClickInterval = time.Millisecond

		a := New(nil)
		h := newAppHarnessFor(t, a, 120, 30)
		a.running.Store(true)
		defer a.running.Store(false)
		resc := askLive(t, a, questionFixture())
		h.runDraw(func() {})
		liveClickRow(t, h, 0, 1)

		liveClickSubmit(t, h)

		res := liveResult(t, a, resc)
		var focus tview.Primitive
		var mounted bool
		a.app.QueueUpdate(func() { focus, mounted = a.app.GetFocus(), a.pages.HasPage(questionFormPage) })
		h.stop()

		if res.Cancelled {
			t.Error("clicking Submit cancelled instead of submitting")
		}
		if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Object store" {
			t.Errorf("clicking Submit delivered %v, want the clicked option", got)
		}
		if mounted {
			t.Error("the form page outlived the Submit click")
		}
		if focus != tview.Primitive(a.input) {
			t.Errorf("focus = %T after the Submit click, want the input area", focus)
		}
	})
}

func staleFocusOnInput(t *testing.T, a *App) {
	t.Helper()
	a.app.QueueUpdate(func() { a.app.SetFocus(a.input) })
	waitOnLoop(t, a, "focus to go stale on the input area", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.input)
	})
}

func TestQuestionPrompt_TerminalFocusReturnRepairsTheForm(t *testing.T) {
	a := New(nil)
	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }
	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)
	a.app.QueueUpdate(func() { a.input.SetText("half-written prompt") })

	resc := make(chan QuestionResult, 1)
	go func() {
		res, err := a.AskQuestions(context.Background(), questionFixture())
		if err != nil {
			resc <- QuestionResult{Cancelled: true}
			return
		}
		resc <- res
	}()
	waitOnLoop(t, a, "question form mount", func() bool { return a.pages.HasPage(questionFormPage) })

	staleFocusOnInput(t, a)
	if err := screen.PostEvent(tcell.NewEventFocus(true)); err != nil {
		a.app.Stop()
		t.Fatalf("post focus-gained event: %v", err)
	}
	waitOnLoop(t, a, "the terminal focus-gained event to repair the form's focus", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.questionForm.blocks[0].options)
	})

	staleFocusOnInput(t, a)
	screen.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)

	var res QuestionResult
	select {
	case res = <-resc:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("AskQuestions did not return within 2s of the keys sent after the terminal returned")
	}
	var draft string
	a.app.QueueUpdate(func() { draft = a.input.GetText() })
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}

	if res.Cancelled {
		t.Fatal("the form came back cancelled")
	}
	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Object store" {
		t.Errorf("answer = %v, want the option the first key after the terminal returned moved to", got)
	}
	if draft != "half-written prompt" {
		t.Errorf("input draft = %q; the keys reached the input area instead of the form", draft)
	}
}

func TestQuestionPrompt_MouseFocusSurvivesTheTerminalFocusRepair(t *testing.T) {
	a := New(nil)
	req := questionFixture()
	last := len(req.Questions) - 1
	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }
	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)
	a.app.QueueUpdate(func() { a.input.SetText("half-written prompt") })

	resc := make(chan QuestionResult, 1)
	go func() {
		res, err := a.AskQuestions(context.Background(), req)
		if err != nil {
			resc <- QuestionResult{Cancelled: true}
			return
		}
		resc <- res
	}()
	waitOnLoop(t, a, "question form mount", func() bool { return a.pages.HasPage(questionFormPage) })

	// Navigate to the last question, then hand focus to Submit, so the click below is what
	// puts the keyboard back on that question's list. The repair has to follow the focus
	// the mouse established, not the last one the form drove itself.
	a.app.QueueUpdateDraw(func() {
		a.questionForm.focus(a.questionForm.blocks[last].options)
	})
	waitOnLoop(t, a, "the last question to be shown", func() bool {
		return a.questionForm.stage.shown == a.questionForm.blocks[last]
	})
	a.app.QueueUpdateDraw(func() { a.questionForm.focus(a.questionForm.submit) })
	waitOnLoop(t, a, "focus to leave the question list", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.questionForm.submit)
	})

	var x, y int
	waitOnLoop(t, a, "the mounted form to be drawn", func() bool {
		options := a.questionForm.blocks[last].options
		_, _, width, _ := options.GetInnerRect()
		if width <= 0 || len(options.starts) == 0 {
			return false
		}
		var ok bool
		x, y, ok = optionPoint(options, 0)
		return ok
	})
	screen.InjectMouse(x, y, tcell.Button1, tcell.ModNone)
	screen.InjectMouse(x, y, tcell.ButtonNone, tcell.ModNone)
	waitOnLoop(t, a, "the click to move focus onto the last question", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.questionForm.blocks[last].options)
	})

	staleFocusOnInput(t, a)
	if err := screen.PostEvent(tcell.NewEventFocus(true)); err != nil {
		a.app.Stop()
		t.Fatalf("post focus-gained event: %v", err)
	}
	waitOnLoop(t, a, "the terminal focus-gained event to restore the mouse-focused question", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.questionForm.blocks[last].options)
	})

	staleFocusOnInput(t, a)
	screen.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)

	var res QuestionResult
	select {
	case res = <-resc:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("AskQuestions did not return within 2s of the keys sent after the terminal returned")
	}
	var draft string
	a.app.QueueUpdate(func() { draft = a.input.GetText() })
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}

	if res.Cancelled {
		t.Fatal("the form came back cancelled")
	}
	want := req.Questions[last].Options[1]
	if got := res.Answers[last].Selected; len(got) != 1 || got[0] != want {
		t.Errorf("answer = %v, want %q — the keys after the repair reached the question the mouse focused", got, want)
	}
	for i, answer := range res.Answers[:last] {
		if len(answer.Selected) != 0 {
			t.Errorf("question %d answered %v; the repair routed the keys to the wrong question", i, answer.Selected)
		}
	}
	if draft != "half-written prompt" {
		t.Errorf("input draft = %q; the keys reached the input area instead of the form", draft)
	}
}

func TestQuestionPrompt_CtrlSSubmitsFromEitherButton(t *testing.T) {
	for _, tc := range []struct {
		name   string
		button func(*App) *tview.Button
	}{
		{"submit", func(a *App) *tview.Button { return a.questionForm.submit }},
		{"cancel", func(a *App) *tview.Button { return a.questionForm.cancel }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			results := openQuestions(t, a, questionFixture())
			chooseByKeyboard(t, a.questionForm.blocks[0].options, 1)
			button := tc.button(a)
			a.app.SetFocus(button)

			button.InputHandler()(tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModNone), func(tview.Primitive) {})

			res := waitResult(t, results)
			if res.Cancelled {
				t.Error("the advertised Ctrl-S cancelled instead of submitting")
			}
			if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Object store" {
				t.Errorf("Ctrl-S from the %s button submitted %v, want the chosen option", tc.name, got)
			}
		})
	}
}

func TestQuestionPrompt_CustomFieldLabelUsesNoFixedAccent(t *testing.T) {
	a := New(nil)
	req := questionFixture()
	custom := len(req.Questions) - 1
	openQuestions(t, a, req)
	block := a.questionForm.blocks[custom]
	a.questionForm.focus(block.options)
	block.choose(len(block.spec.Options))

	screen := drawPrimitive(t, a.pages, 120, 30)
	cells, width, height := screen.GetContents()
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			cell := cells[row*width+col]
			fg, bg, _ := cell.Style.Decompose()
			if isYellow(fg) || isYellow(bg) {
				t.Errorf("cell (%d,%d) %q uses fixed yellow; it is unreadable on a light background", col, row, string(cell.Runes))
			}
		}
	}
}

func TestQuestionPrompt_CtrlSSubmitsFromAnOpenCustomField(t *testing.T) {
	a := New(nil)
	h := newAppHarnessFor(t, a, 100, 30)
	a.running.Store(true)
	defer a.running.Store(false)
	h.runDraw(func() { a.input.SetText("half-written prompt") })

	req := questionFixture()
	custom := len(req.Questions) - 1
	resc := askLive(t, a, req)
	h.runDraw(func() {})

	for step := 0; step < custom; step++ {
		h.screen.InjectKey(tcell.KeyTab, 0, tcell.ModNone)
	}
	waitOnLoop(t, a, "Tab to reach the custom-text question", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.questionForm.blocks[custom].options)
	})
	for range req.Questions[custom].Options {
		h.screen.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
	}
	h.screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitOnLoop(t, a, "the custom row to open its field and take focus", func() bool {
		return a.app.GetFocus() == tview.Primitive(a.questionForm.blocks[custom].field)
	})
	for _, r := range "BSD only" {
		h.screen.InjectKey(tcell.KeyRune, r, tcell.ModNone)
	}
	waitOnLoop(t, a, "the typed answer to reach the still-focused custom field", func() bool {
		block := a.questionForm.blocks[custom]
		return block.field.GetText() == "BSD only" && a.app.GetFocus() == tview.Primitive(block.field)
	})

	h.screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)

	res := liveResult(t, a, resc)
	waitOnLoop(t, a, "the form teardown", func() bool {
		return !a.pages.HasPage(questionFormPage) && !a.questionFormOpen && a.questionForm == nil
	})
	var focus tview.Primitive
	var draft string
	a.app.QueueUpdate(func() { focus, draft = a.app.GetFocus(), a.input.GetText() })
	h.stop()

	if res.Cancelled {
		t.Fatal("Ctrl-S from the custom field cancelled instead of submitting")
	}
	if got := res.Answers[custom].Custom; got != "BSD only" {
		t.Errorf("custom answer = %q, want the text typed into the focused field", got)
	}
	if focus != tview.Primitive(a.input) {
		t.Errorf("focus = %T after the submit, want the input area", focus)
	}
	if draft != "half-written prompt" {
		t.Errorf("input draft = %q; the custom text was typed into the input area", draft)
	}
}

// TestQuestionPrompt_MountingTheFormEndsAnActiveDrag drives a real drag that is still held
// when the form mounts. The app-level mouse capture answers the move and the release from
// an active selection before its overlay guard and focuses the input from both release
// paths, so a surviving drag would take the keyboard out of a modal form.
func TestQuestionPrompt_MountingTheFormEndsAnActiveDrag(t *testing.T) {
	for _, tc := range []struct {
		name    string
		press   func(a *App) (x, y int)
		dragged func(a *App) bool
		gen     func(a *App) (uint64, bool)
	}{
		{
			name: "input drag",
			press: func(a *App) (int, int) {
				x, y, _, _ := a.input.GetRect()
				return x + 2, y + 1
			},
			dragged: func(a *App) bool { return a.inputSelecting },
			gen:     func(a *App) (uint64, bool) { return a.inputScrollGen, a.inputScrollPending },
		},
		{
			name: "transcript drag",
			press: func(a *App) (int, int) {
				x, y, _, _ := a.transcript.view.GetRect()
				return x + 1, y
			},
			dragged: func(a *App) bool { return a.transcript.isSelecting() },
			gen:     func(a *App) (uint64, bool) { return a.transcriptScrollGen, a.transcriptScrollPending },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLayoutHarness(t, 100, 30)
			a := h.a
			a.running.Store(true)
			defer a.running.Store(false)
			h.update(func() {
				// App.Run enables paste on the real screen; the harness runs the loop directly,
				// and without it tview delivers the pasted rune as a keystroke, which the
				// form's first-key focus repair would swallow instead of the draft taking it.
				a.app.EnablePaste(true)
				a.transcript.append("the transcript line a drag selects from")
				a.input.SetText("half-written prompt")
			})

			var x, y int
			var genBefore uint64
			a.app.QueueUpdate(func() { x, y = tc.press(a) })
			h.injectMouse(x, y, tcell.Button1)
			h.injectMouse(x+4, y, tcell.Button1)
			var dragging bool
			a.app.QueueUpdate(func() {
				dragging = tc.dragged(a)
				genBefore, _ = tc.gen(a)
			})
			if !dragging {
				t.Fatalf("setup: no %s is in progress at (%d,%d)", tc.name, x, y)
			}

			resc := askLive(t, a, questionFixture())

			var stillDragging, pending bool
			var genAfter uint64
			a.app.QueueUpdate(func() {
				stillDragging = tc.dragged(a)
				genAfter, pending = tc.gen(a)
			})
			if stillDragging {
				t.Error("the drag survived the mount; its release runs before the overlay guard")
			}
			if genAfter == genBefore || pending {
				t.Errorf("drag-scroll generation = %d (was %d), pending = %v; a queued tick can still scroll under the form", genAfter, genBefore, pending)
			}

			h.injectMouseQuiet(x+8, y, tcell.Button1)
			h.injectMouseQuiet(x+8, y, tcell.ButtonNone)

			var focus tview.Primitive
			var owned, open bool
			a.app.QueueUpdate(func() {
				focus, open = a.app.GetFocus(), a.questionFormOpen
				owned = a.questionForm != nil && a.questionForm.owns(focus)
			})
			if !open {
				t.Fatal("the release closed the question form")
			}
			if !owned {
				t.Errorf("focus = %T after the release, want a control of the mounted form", focus)
			}

			// One producer for the rest of the run: QueueEvent and the simulation screen's own
			// injections feed the loop through different queues, so posting the paste on one and
			// the keys on the other would leave their order undefined — and the draft can only
			// be read once the keys behind the paste have been answered.
			a.app.QueueEvent(tcell.NewEventPaste(true))
			a.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, 'z', tcell.ModNone))
			a.app.QueueEvent(tcell.NewEventPaste(false))
			a.app.QueueEvent(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
			a.app.QueueEvent(tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModNone))
			res := liveResult(t, a, resc)
			var draft string
			a.app.QueueUpdate(func() { draft = a.input.GetText() })
			h.stop()

			if draft != "half-written prompt" {
				t.Errorf("input draft = %q; the paste reached the input area under the form", draft)
			}
			if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Local disk" {
				t.Errorf("answer = %v, want the option the keys after the release chose", got)
			}
		})
	}
}

func TestAskQuestions_LiveCancelledContextTearsDownTheQueuedForm(t *testing.T) {
	a := New(nil)
	h := newAppHarnessFor(t, a, 100, 30)
	a.running.Store(true)
	defer a.running.Store(false)
	a.app.QueueUpdate(func() { a.app.SetFocus(a.input) })

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		res QuestionResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := a.AskQuestions(ctx, questionFixture())
		done <- outcome{res, err}
	}()
	waitOnLoop(t, a, "question form mount", func() bool { return a.pages.HasPage(questionFormPage) })

	cancel()

	var got outcome
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("AskQuestions did not return within 2s of its context being cancelled")
	}
	waitOnLoop(t, a, "the queued teardown of the question form", func() bool {
		return !a.pages.HasPage(questionFormPage) && !a.questionFormOpen && a.questionForm == nil
	})
	var focus tview.Primitive
	a.app.QueueUpdate(func() { focus = a.app.GetFocus() })
	h.stop()

	if !errors.Is(got.err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", got.err)
	}
	if len(got.res.Answers) != 0 || got.res.Cancelled {
		t.Errorf("result = %+v, want the zero result for an aborted form", got.res)
	}
	if focus != a.input {
		t.Errorf("focus = %T after the queued teardown, want the input area", focus)
	}
}

func TestQuestionPrompt_RowMarksFollowTheResponseMode(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())
	single, multi := a.questionForm.blocks[0], a.questionForm.blocks[1]

	chooseByKeyboard(t, single.options, 0)
	chooseByKeyboard(t, multi.options, 1)

	a.questionForm.focus(single.options)
	text := screenText(drawPrimitive(t, a.pages, 120, 24))
	if !strings.Contains(text, singleChosenMark+" Local disk") {
		t.Error("the chosen single-select option is not marked")
	}
	if !strings.Contains(text, singleOpenMark+" Object store") {
		t.Error("the unchosen single-select option is not marked as open")
	}

	a.questionForm.focus(multi.options)
	text = screenText(drawPrimitive(t, a.pages, 120, 24))
	if !strings.Contains(text, multiChosenMark+" macOS") {
		t.Error("the checked multi-select option is not marked")
	}
	// Both bracket forms have to survive the dynamic-colors parser, which would otherwise
	// read them as markup and drop them from the row.
	if !strings.Contains(text, multiOpenMark+" Windows") {
		t.Errorf("the unchecked multi-select option is not marked as open:\n%s", text)
	}
}

// boundaryTokens builds a value of exactly the largest text the dispatcher will ever hand
// the form, as distinct space-separated tokens of the named script, and returns them in the
// order they must be readable. No token contains a space, so wrapping never splits one and
// no drawn frame can show half of it; that is what lets a page-by-page sweep tell "every
// rune is reachable" from "the tail is reachable".
// sep is what joins the tokens: a space gives the renderer a break opportunity every few
// runes, and an empty separator gives it none at all, which is equally legal text and forces
// the break to fall inside a word.
func boundaryTokens(kind, sep string) (string, []string) {
	unit := map[string]string{
		"ascii":     "s",
		"wide":      string(rune(0x754C)),
		"combining": "e" + string(rune(0x0301)),
	}[kind]
	var tokens []string
	used := 0
	for i := 0; ; i++ {
		token := fmt.Sprintf("%02d", i) + strings.Repeat(unit, 3)
		need := len([]rune(token))
		if used > 0 {
			need += len([]rune(sep))
		}
		if used+need > provider.MaxAskUserTextRunes {
			break
		}
		used += need
		tokens = append(tokens, token)
	}
	if pad := provider.MaxAskUserTextRunes - used; pad > 0 {
		tokens[len(tokens)-1] += strings.Repeat("x", pad)
	}
	return strings.Join(tokens, sep), tokens
}

// assertReachableInOrder pages the question from the top and requires every token to turn
// up, in order, across the frames drawn along the way — the whole accepted text, not its
// suffix. Tokens are matched against the flattened frame because the text is wrapped and
// padded across screen rows that screenText joins border-to-border.
func assertReachableInOrder(t *testing.T, a *App, block *questionBlock, w, h int, tokens []string) {
	t.Helper()
	block.options.ScrollTo(0, 0)
	next := 0
	for page := 0; page < 4*len(tokens) && next < len(tokens); page++ {
		frame := flattenScreen(screenText(drawPrimitive(t, a.pages, w, h)))
		for next < len(tokens) && strings.Contains(frame, flattenScreen(tokens[next])) {
			next++
		}
		pressList(block.options, tcell.KeyPgDn)
	}
	if next < len(tokens) {
		t.Errorf("token %d of %d (%q) never became readable at %dx%d:\n%s",
			next+1, len(tokens), tokens[next], w, h, screenText(drawPrimitive(t, a.pages, w, h)))
	}
}

// revealsText scrolls the question looking for want, comparing with whitespace and the
// overlay's border glyphs removed: the text is wrapped and padded across screen rows that
// screenText joins border-to-border, so a contiguous match would test where the wrap
// happened to land rather than whether the text is readable at all.
func revealsText(t *testing.T, a *App, block *questionBlock, w, h int, want string) bool {
	t.Helper()
	for attempt := 0; attempt < 40; attempt++ {
		if strings.Contains(flattenScreen(screenText(drawPrimitive(t, a.pages, w, h))), flattenScreen(want)) {
			return true
		}
		pressList(block.options, tcell.KeyPgDn)
	}
	return false
}

func flattenScreen(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || (r >= 0x2500 && r <= 0x257F) {
			return -1
		}
		return r
	}, s)
}

// TestQuestionPrompt_MaximumTextIsReadableAtTheSmallestTerminal holds the property one
// element at a time: every accepted text must be readable in full on the smallest terminal,
// whichever element carries it and whichever script it is written in. Asserting it per
// element is what makes a fix for one of them a fix for all of them. It checks the whole
// rendered content, not the final frame: a renderer that dropped the middle of a label and
// kept its tail would still let the tail be reached.
func TestQuestionPrompt_MaximumTextIsReadableAtTheSmallestTerminal(t *testing.T) {
	for _, kind := range []string{"ascii", "wide", "combining"} {
		for _, place := range []string{"prompt", "option"} {
			t.Run(kind+"-"+place, func(t *testing.T) {
				text, tokens := boundaryTokens(kind, " ")
				spec := QuestionSpec{ID: "q", Prompt: "p", Options: []string{"x"}}
				if place == "prompt" {
					spec.Prompt = text
				} else {
					spec.Options = []string{text}
				}
				a := New(nil)
				openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{spec}})
				block := a.questionForm.blocks[0]
				drawPrimitive(t, a.pages, 20, 24)

				rendered := block.options.GetText(true)
				if !strings.Contains(flattenScreen(rendered), flattenScreen(text)) {
					t.Fatalf("the rendered question is missing part of a %d-rune %s %s:\n%s",
						provider.MaxAskUserTextRunes, kind, place, rendered)
				}
				if strings.Contains(rendered, "…") {
					t.Errorf("a %s %s was shortened; every label wraps in place:\n%s", kind, place, rendered)
				}
				assertReachableInOrder(t, a, block, 20, 24, tokens)
			})
		}
	}

	t.Run("custom-row", func(t *testing.T) {
		a := New(nil)
		openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{
			{ID: "q", Prompt: "p", Options: []string{"x"}, AllowCustom: true},
		}})
		block := a.questionForm.blocks[0]
		drawPrimitive(t, a.pages, 20, 24)
		block.options.SetCurrentItem(len(block.spec.Options))

		if !revealsText(t, a, block, 20, 24, customAnswerRowLabel) {
			t.Errorf("the custom row's complete label is unreachable at 20x24:\n%s", screenText(drawPrimitive(t, a.pages, 20, 24)))
		}
	})
}

// TestQuestionPrompt_ScrolledMaximumStillSubmits pins that scrolling does not cost the
// user the answer: after paging through a maximum prompt the options are still selectable
// and the result still carries the choice.
func TestQuestionPrompt_ScrolledMaximumStillSubmits(t *testing.T) {
	a := New(nil)
	prompt, tokens := boundaryTokens("wide", " ")
	spec := QuestionSpec{ID: "q", Prompt: prompt, Options: []string{"first", "second"}}
	results := openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{spec}})
	block := a.questionForm.blocks[0]

	if !revealsText(t, a, block, 20, 24, tokens[len(tokens)-1]) {
		t.Fatalf("setup: the maximum prompt never revealed its tail:\n%s", screenText(drawPrimitive(t, a.pages, 20, 24)))
	}
	chooseByKeyboard(t, block.options, 1)
	a.submitQuestionForm()

	if got := waitResult(t, results).Answers[0].Selected; len(got) != 1 || got[0] != "second" {
		t.Errorf("selected = %v, want [second] after revealing the prompt", got)
	}
}

// TestQuestionPrompt_ManualScrollSurvivesNavigationAndResize pins the reason
// questionBlock.layout deliberately omits ensureVisible: layout runs on every relayout, so
// calling it there would silently pull a question the user scrolled by hand back to
// wherever its option cursor sits. Only moving the cursor may scroll for the user.
func TestQuestionPrompt_ManualScrollSurvivesNavigationAndResize(t *testing.T) {
	a := New(nil)
	tall := oversizedQuestion().Questions[0]
	req := QuestionRequest{Questions: []QuestionSpec{
		tall,
		{ID: "when", Prompt: "When should it run?", Options: []string{"Tonight", "Next week"}},
	}}
	openQuestions(t, a, req)
	blocks := a.questionForm.blocks
	scrolled := blocks[0].options

	drawPrimitive(t, a.pages, 20, 24)
	pressList(scrolled, tcell.KeyPgDn)
	drawPrimitive(t, a.pages, 20, 24)

	offset, _ := scrolled.GetScrollOffset()
	if offset == 0 {
		t.Fatal("setup: paging the over-tall question did not scroll it")
	}
	if scrolled.GetCurrentItem() != 0 {
		t.Fatal("setup: scrolling moved the option cursor, so a later relayout may legitimately follow it")
	}
	top := -1
	for i, start := range scrolled.starts {
		if start >= offset {
			top = i
			break
		}
	}
	if top < 0 || top >= len(tall.Options) {
		t.Fatalf("setup: the scrolled view starts at row %d, which owns no option label to look for", offset)
	}
	reached := fmt.Sprintf("option-%d", top)

	for _, step := range []struct {
		name          string
		relayout      func()
		width, height int
	}{
		{"another question and back", func() {
			pressList(scrolled, tcell.KeyTab)
			drawPrimitive(t, a.pages, 20, 24)
			pressList(blocks[1].options, tcell.KeyLeft)
		}, 20, 24},
		{"a resize", func() {}, 20, 20},
	} {
		step.relayout()
		text := screenText(drawPrimitive(t, a.pages, step.width, step.height))

		if got, _ := scrolled.GetScrollOffset(); got != offset {
			t.Errorf("after %s the question scrolled from row %d to %d; the user's scroll was undone", step.name, offset, got)
		}
		if !strings.Contains(text, reached) {
			t.Errorf("after %s the scrolled-to %s is gone, so the reader restarts from the top:\n%s", step.name, reached, text)
		}
	}
}

func TestAskQuestions_AbandonedRequestCannotDismissAnotherRequestsForm(t *testing.T) {
	a := New(nil)
	mounted := openQuestions(t, a, questionFixture())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := a.abandonQuestionForm(ctx, make(chan QuestionResult, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("abandonQuestionForm error = %v, want context.Canceled", err)
	}
	if !a.QuestionFormOpen() {
		t.Error("a busy request's cancellation dismissed the form belonging to a different caller")
	}
	if len(mounted) != 0 {
		t.Error("a busy request's cancellation delivered a result to the mounted form's caller")
	}

	if _, err := a.abandonQuestionForm(ctx, mounted); !errors.Is(err, context.Canceled) {
		t.Fatalf("abandonQuestionForm error = %v, want context.Canceled", err)
	}
	if a.QuestionFormOpen() {
		t.Error("the owning request's cancellation left its own form mounted")
	}
}

func TestAskQuestions_StaleCleanupCannotDismissAReplacementForm(t *testing.T) {
	a := New(nil)
	first := openQuestions(t, a, questionFixture())
	a.cancelQuestionForm()
	if a.QuestionFormOpen() {
		t.Fatal("setup: the first form did not close")
	}
	second := openQuestions(t, a, questionFixture())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.abandonQuestionForm(ctx, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("abandonQuestionForm error = %v, want context.Canceled", err)
	}

	if !a.QuestionFormOpen() {
		t.Error("a stale cleanup from the already-closed request dismissed the replacement form")
	}
	if len(second) != 0 {
		t.Error("a stale cleanup delivered a result to the replacement form's caller")
	}
}

// controlName names a form control, because %T cannot tell Submit from Cancel.
func controlName(f *questionForm, p tview.Primitive) string {
	switch p {
	case tview.Primitive(f.prev):
		return "Prev"
	case tview.Primitive(f.next):
		return "Next"
	case tview.Primitive(f.submit):
		return "Submit"
	case tview.Primitive(f.cancel):
		return "Cancel"
	case tview.Primitive(f.clarify):
		return "Clarify"
	case tview.Primitive(f.clarifyField):
		return "clarification field"
	case tview.Primitive(f.context):
		return "context"
	}
	for i, b := range f.blocks {
		if p == tview.Primitive(b.options) {
			return fmt.Sprintf("question %d", i)
		}
		if b.field != nil && p == tview.Primitive(b.field) {
			return fmt.Sprintf("question %d custom field", i)
		}
	}
	return fmt.Sprintf("%T", p)
}

func pressKey(p tview.Primitive, key tcell.Key) {
	p.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
}

// TestQuestionPrompt_ArrowsWalkTheWholeFocusRing pins that every control the ring contains
// answers the arrow keys, not only Tab. Each control keeps the arrows it has another use
// for: a question list owns \u2191\u2193 for its option cursor and steps the ring with \u2190\u2192, an open
// custom field owns \u2190\u2192 for editing its text and steps the ring with \u2191\u2193, and a button has no
// other use for any of them, so all four step it. Buttons previously answered Tab alone,
// stranding an arrow-key user.
func TestQuestionPrompt_ArrowsWalkTheWholeFocusRing(t *testing.T) {
	a := New(nil)
	req := questionFixture()
	openQuestions(t, a, req)
	form := a.questionForm
	blocks := form.blocks
	last := blocks[len(blocks)-1]

	pressList(blocks[0].options, tcell.KeyLeft)
	if got := a.app.GetFocus(); got != tview.Primitive(form.cancel) {
		t.Errorf("Left on the first question focused %T, want the Cancel button (the ring wraps)", got)
	}

	form.focus(blocks[0].options)
	pressList(blocks[0].options, tcell.KeyRight)
	if got := a.app.GetFocus(); got != tview.Primitive(blocks[1].options) {
		t.Errorf("Right on the first question focused %T, want the next question", got)
	}

	for _, tc := range []struct {
		name string
		key  tcell.Key
		want tview.Primitive
	}{
		{"Right", tcell.KeyRight, form.cancel},
		{"Down", tcell.KeyDown, form.cancel},
		{"Left", tcell.KeyLeft, form.clarify},
		{"Up", tcell.KeyUp, form.clarify},
	} {
		t.Run("submit-"+tc.name, func(t *testing.T) {
			form.focus(form.submit)
			pressKey(form.submit, tc.key)
			if got := a.app.GetFocus(); got != tc.want {
				t.Errorf("%s on Submit focused %s, want %s", tc.name, controlName(form, got), controlName(form, tc.want))
			}
		})
	}

	form.focus(last.options)
	pressList(last.options, tcell.KeyRight)
	if got := a.app.GetFocus(); got != tview.Primitive(form.clarify) {
		t.Errorf("Right on the last question focused %s, want the clarification button", controlName(form, a.app.GetFocus()))
	}
	// Prev and Next are the mouse's route between questions and are deliberately outside the
	// ring: the keyboard steps the questions themselves, so stopping on them would only add
	// two stops between the last question and Submit.
	for _, p := range form.focusRing() {
		if p == tview.Primitive(form.prev) || p == tview.Primitive(form.next) {
			t.Errorf("the focus ring stops on %s; the keyboard reaches every question without it", controlName(form, p))
		}
	}

	form.focus(form.cancel)
	pressKey(form.cancel, tcell.KeyRight)
	if got := a.app.GetFocus(); got != tview.Primitive(blocks[0].options) {
		t.Errorf("Right on Cancel focused %T, want the first question (the ring wraps)", got)
	}

	chooseByKeyboard(t, last.options, len(last.spec.Options))
	if !last.customOn {
		t.Fatal("setup: choosing the custom row did not enable it")
	}
	form.focus(last.options)
	pressList(last.options, tcell.KeyRight)
	if got := a.app.GetFocus(); got != tview.Primitive(last.field) {
		t.Errorf("Right on a custom-enabled question focused %T, want that question's text field", got)
	}
	pressKey(last.field, tcell.KeyDown)
	if got := a.app.GetFocus(); got != tview.Primitive(form.clarify) {
		t.Errorf("Down in an open custom field focused %s, want the control after it", controlName(form, a.app.GetFocus()))
	}
	pressKey(form.clarify, tcell.KeyUp)
	if got := a.app.GetFocus(); got != tview.Primitive(last.field) {
		t.Errorf("Up on the clarification button focused %T, want the open custom field it came from", got)
	}
	pressKey(last.field, tcell.KeyUp)
	if got := a.app.GetFocus(); got != tview.Primitive(last.options) {
		t.Errorf("Up in an open custom field focused %s, want the question that owns it: it is the only way back that does not walk the whole ring",
			controlName(form, a.app.GetFocus()))
	}
	form.focus(last.field)
	for _, key := range []struct {
		name string
		key  tcell.Key
	}{{"Left", tcell.KeyLeft}, {"Right", tcell.KeyRight}} {
		pressKey(last.field, key.key)
		if got := a.app.GetFocus(); got != tview.Primitive(last.field) {
			t.Errorf("%s in an open custom field focused %s; ←→ move the cursor inside the text", key.name, controlName(form, got))
		}
	}
}

// topLineText reads the text drawn on the question's first visible row, which is what "where
// the reader is" means on screen: two widths wrap the same source into different lines, so
// only the text itself can say whether the position survived a rewrap.
func topLineText(t *testing.T, screen tcell.SimulationScreen, o *questionOptions) string {
	t.Helper()
	cells, width, _ := screen.GetContents()
	x, y, w, _ := o.GetInnerRect()
	var b strings.Builder
	for col := x; col < x+w; col++ {
		runes := cells[y*width+col].Runes
		if len(runes) == 0 {
			b.WriteRune(' ')
			continue
		}
		b.WriteString(string(runes))
	}
	return strings.TrimRight(b.String(), " ")
}

func widthChangeFixture(kind string) (QuestionRequest, []string) {
	prompt, tokens := boundaryTokens(kind, " ")
	spec := QuestionSpec{ID: "scope", Prompt: prompt}
	for i := 0; i < provider.MaxAskUserOptions; i++ {
		spec.Options = append(spec.Options, fmt.Sprintf("option-%d %s", i, strings.Repeat("detail ", 4)))
	}
	return QuestionRequest{Questions: []QuestionSpec{
		spec,
		{ID: "when", Prompt: "When should it run?", Options: []string{"Tonight", "Next week"}},
	}}, tokens
}

// TestQuestionPrompt_WidthChangesKeepTheReadersPlace pins the scroll position as a place in
// the question's text rather than a display-line number. A width change rewraps every line,
// so the same numbered line is different text afterwards; and a width that fits the whole
// question makes tview clamp its own offset to zero, so a number carried across it comes
// back as the beginning. Both are checked here, in each script class, because how far the
// text rewraps between the two widths is exactly what the script decides.
func TestQuestionPrompt_WidthChangesKeepTheReadersPlace(t *testing.T) {
	for _, kind := range []string{"ascii", "wide", "combining"} {
		t.Run(kind, func(t *testing.T) {
			req, tokens := widthChangeFixture(kind)
			a := New(nil)
			openQuestions(t, a, req)
			blocks := a.questionForm.blocks
			scrolled := blocks[0].options

			drawPrimitive(t, a.pages, 20, 24)
			scrolled.scrollBy(2)
			screen := drawPrimitive(t, a.pages, 20, 24)
			offset, _ := scrolled.GetScrollOffset()
			if offset == 0 {
				t.Fatal("setup: the question did not scroll at 20x24, so there is no position to lose")
			}
			reading := topLineText(t, screen, scrolled)
			if reading == "" {
				t.Fatal("setup: the row the reader is on is blank, so the assertion below would hold trivially")
			}

			drawPrimitive(t, a.pages, 72, 24)
			if wide, _ := scrolled.GetScrollOffset(); wide != 0 {
				t.Fatalf("setup: the whole question does not fit at 72 columns (offset %d), so tview never clamps and the numeric offset survives by luck", wide)
			}

			for _, step := range []struct {
				name string
				act  func()
			}{
				{"a resize back to the narrow terminal", func() {}},
				{"another question and back", func() {
					pressList(scrolled, tcell.KeyTab)
					drawPrimitive(t, a.pages, 20, 24)
					pressList(blocks[1].options, tcell.KeyLeft)
				}},
			} {
				step.act()
				back := drawPrimitive(t, a.pages, 20, 24)
				if got, _ := scrolled.GetScrollOffset(); got != offset {
					t.Errorf("after %s the question is at row %d, want the row %d it was being read at", step.name, got, offset)
				}
				if got := topLineText(t, back, scrolled); got != reading {
					t.Errorf("after %s the question reads %q at the top, want %q — the reader was moved", step.name, got, reading)
				}
			}
			assertReachableInOrder(t, a, blocks[0], 20, 24, tokens)
		})
	}
}

// buttonStyle reports how many of a button's cells are drawn in reverse video and whether any
// glyph carries a fixed foreground. The focus indicator has to be terminal-independent: with
// both theme backgrounds defaulted to the terminal's own, tview's fixed-blue focused
// foreground can equal the terminal's ordinary foreground and leave no visible change.
func buttonStyle(t *testing.T, screen tcell.SimulationScreen, b *tview.Button) (reversed int, fixed bool) {
	t.Helper()
	cells, width, _ := screen.GetContents()
	x, y, w, h := b.GetRect()
	for row := y; row < y+h; row++ {
		for col := x; col < x+w; col++ {
			cell := cells[row*width+col]
			fg, _, attrs := cell.Style.Decompose()
			if attrs&tcell.AttrReverse != 0 {
				reversed++
			}
			if len(cell.Runes) > 0 && cell.Runes[0] != ' ' && fg != tcell.ColorDefault {
				fixed = true
			}
		}
	}
	return reversed, fixed
}

func TestQuestionPrompt_OnlyTheFocusedButtonIsReversed(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())
	form := a.questionForm
	buttons := map[string]*tview.Button{
		"Submit":          form.submit,
		"Cancel":          form.cancel,
		prevQuestionLabel: form.prev,
		nextQuestionLabel: form.next,
	}

	for name, button := range buttons {
		t.Run(name, func(t *testing.T) {
			form.focus(button)
			screen := drawPrimitive(t, a.pages, 44, 24)

			reversed, fixed := buttonStyle(t, screen, button)
			if reversed == 0 {
				t.Errorf("the focused %s button has no reverse-video cell, so Enter has no visible target", name)
			}
			if fixed {
				t.Errorf("the focused %s button draws a fixed foreground, which can match the terminal's own", name)
			}
			for other, p := range buttons {
				if other == name {
					continue
				}
				if got, _ := buttonStyle(t, screen, p); got != 0 {
					t.Errorf("%s is reversed while %s holds focus", other, name)
				}
			}
		})
	}
}

// assertReachableByLine is assertReachableInOrder for text with no break opportunity in it: a
// token can straddle two rendered lines, so the frames have to overlap. Paging would leave
// such a token half on one frame and half on the next and report it as unreachable.
func assertReachableByLine(t *testing.T, a *App, block *questionBlock, w, h int, tokens []string) {
	t.Helper()
	block.options.scrollToLine(0)
	next := 0
	for row := 0; row <= block.options.contentHeight() && next < len(tokens); row++ {
		frame := flattenScreen(screenText(drawPrimitive(t, a.pages, w, h)))
		for next < len(tokens) && strings.Contains(frame, flattenScreen(tokens[next])) {
			next++
		}
		block.options.scrollBy(1)
	}
	if next < len(tokens) {
		t.Errorf("token %d of %d (%q) never became readable at %dx%d:\n%s",
			next+1, len(tokens), tokens[next], w, h, screenText(drawPrimitive(t, a.pages, w, h)))
	}
}

// TestQuestionPrompt_UnbrokenMaximumTextIsReadableAtTheSmallestTerminal is the case a
// space-separated fixture cannot make. Every other maximum-text fixture hands the renderer a
// break opportunity every few runes; a schema-valid value need not contain one anywhere, and
// then the break has to fall inside the word with nothing dropped at it.
func TestQuestionPrompt_UnbrokenMaximumTextIsReadableAtTheSmallestTerminal(t *testing.T) {
	for _, kind := range []string{"ascii", "wide", "combining"} {
		for _, place := range []string{"prompt", "option"} {
			t.Run(kind+"-"+place, func(t *testing.T) {
				text, tokens := boundaryTokens(kind, "")
				if strings.ContainsAny(text, " \t") {
					t.Fatalf("setup: the fixture carries a break opportunity: %q", text)
				}
				if !provider.AskUserTextRenderable(text) {
					t.Fatalf("setup: the fixture is not a value the dispatcher would accept: %q", text)
				}
				spec := QuestionSpec{ID: "q", Prompt: "p", Options: []string{"x"}}
				if place == "prompt" {
					spec.Prompt = text
				} else {
					spec.Options = []string{text}
				}
				a := New(nil)
				openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{spec}})
				block := a.questionForm.blocks[0]
				drawPrimitive(t, a.pages, 20, 24)

				rendered := block.options.GetText(true)
				if !strings.Contains(flattenScreen(rendered), flattenScreen(text)) {
					t.Fatalf("the rendered question is missing part of a %d-rune unbroken %s %s:\n%s",
						provider.MaxAskUserTextRunes, kind, place, rendered)
				}
				if strings.Contains(rendered, "…") {
					t.Errorf("an unbroken %s %s was shortened; every label wraps in place:\n%s", kind, place, rendered)
				}
				assertReachableByLine(t, a, block, 20, 24, tokens)
			})
		}
	}
}

func TestQuestionPrompt_OptionCursorAndPagingMoveBothWays(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, oversizedQuestion())
	block := a.questionForm.blocks[0]
	drawPrimitive(t, a.pages, 20, 24)

	pressList(block.options, tcell.KeyDown)
	pressList(block.options, tcell.KeyDown)
	if got := block.options.GetCurrentItem(); got != 2 {
		t.Fatalf("setup: two Downs left the cursor on option %d, want 2", got)
	}
	pressList(block.options, tcell.KeyUp)
	if got := block.options.GetCurrentItem(); got != 1 {
		t.Errorf("Up left the cursor on option %d, want 1", got)
	}

	// Each page is checked through a width round trip, because tview's own TextView answers
	// PgUp and PgDn too: what makes the form's branches the ones under test is that they move
	// the reader's recorded position, which is what a rewrap puts back.
	pressList(block.options, tcell.KeyPgDn)
	down := offsetAcrossAWidthRoundTrip(t, a, block.options)
	if down == 0 {
		t.Fatal("setup: PgDn did not scroll the over-tall question")
	}
	pressList(block.options, tcell.KeyPgUp)
	if up := offsetAcrossAWidthRoundTrip(t, a, block.options); up >= down {
		t.Errorf("PgUp left the question at row %d, want above the row %d PgDn reached", up, down)
	}
}

// offsetAcrossAWidthRoundTrip draws the question wide enough to fit — where tview clamps its
// own offset to zero — and then narrow again, and reports where the question sits afterwards.
// A move that did not record the reader's position comes back as the beginning.
func offsetAcrossAWidthRoundTrip(t *testing.T, a *App, o *questionOptions) int {
	t.Helper()
	drawPrimitive(t, a.pages, 20, 24)
	before, _ := o.GetScrollOffset()
	drawPrimitive(t, a.pages, 120, 40)
	drawPrimitive(t, a.pages, 20, 24)
	after, _ := o.GetScrollOffset()
	if after != before {
		t.Errorf("the question moved from row %d to row %d across a resize; the move did not record where the reader was", before, after)
	}
	return after
}

func TestQuestionPrompt_TabFromAnOpenCustomFieldReachesSubmit(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())
	form := a.questionForm
	last := form.blocks[len(form.blocks)-1]

	chooseByKeyboard(t, last.options, len(last.spec.Options))
	if a.app.GetFocus() != tview.Primitive(last.field) {
		t.Fatalf("setup: focus = %T after opening the custom row, want its text field", a.app.GetFocus())
	}
	pressKey(last.field, tcell.KeyTab)

	if got := a.app.GetFocus(); got != tview.Primitive(form.clarify) {
		t.Errorf("Tab in an open custom field focused %s, want the clarification button — it is the last question, so the ring goes there next", controlName(form, got))
	}
}

// TestQuestionPrompt_LiveEscapeCancelsThroughTheGlobalKeyRoute injects Escape into the
// running application instead of calling HandleEsc, so the app-level capture that routes it
// is part of what is under test: with only the direct call covered, the key could stop
// reaching HandleEsc while every cancellation assertion stayed green.
func TestQuestionPrompt_LiveEscapeCancelsThroughTheGlobalKeyRoute(t *testing.T) {
	a := New(nil)
	canceller := &fakeStreamCanceller{inFlight: true}
	a.SetStreamCanceller(canceller)
	h := newAppHarnessFor(t, a, 100, 30)
	a.running.Store(true)
	defer a.running.Store(false)
	h.runDraw(func() {
		a.input.SetText("half-written prompt")
		a.app.SetFocus(a.input)
	})

	resc := askLive(t, a, questionFixture())
	h.runDraw(func() {})
	h.screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)

	h.screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)

	res := liveResult(t, a, resc)
	waitOnLoop(t, a, "the form teardown", func() bool {
		return !a.pages.HasPage(questionFormPage) && !a.questionFormOpen && a.questionForm == nil
	})
	var focus tview.Primitive
	var draft string
	var interrupts int
	a.app.QueueUpdate(func() {
		focus, draft, interrupts = a.app.GetFocus(), a.input.GetText(), canceller.calls
	})
	h.stop()

	if !res.Cancelled || len(res.Answers) != 0 {
		t.Errorf("result = %+v, want a cancelled result with no answers", res)
	}
	if interrupts != 0 {
		t.Error("the injected Escape interrupted the agent turn waiting on the form")
	}
	if focus != tview.Primitive(a.input) {
		t.Errorf("focus = %T after the injected Escape, want the input area", focus)
	}
	if draft != "half-written prompt" {
		t.Errorf("input draft = %q, want it untouched by the form", draft)
	}
}

// TestQuestionPrompt_SingleSelectHoldsEitherAnOptionOrCustomText covers both replacement
// directions on one question. Asserting only that a custom answer comes back without
// selections proves nothing unless that question had a selection to lose first.
func TestQuestionPrompt_SingleSelectHoldsEitherAnOptionOrCustomText(t *testing.T) {
	a := New(nil)
	req := QuestionRequest{Questions: []QuestionSpec{
		{ID: "name", Prompt: "What should the command be called?", Options: []string{"codemeld run", "codemeld go"}, AllowCustom: true},
	}}
	results := openQuestions(t, a, req)
	block := a.questionForm.blocks[0]

	chooseByKeyboard(t, block.options, 0)
	if !block.chosen[0] {
		t.Fatal("setup: the listed option was not chosen")
	}
	chooseByKeyboard(t, block.options, len(block.spec.Options))
	block.field.SetText("codemeld ask")
	if got := block.answer().Selected; len(got) != 0 {
		t.Errorf("the custom answer left %v selected; a single-select question holds one answer or the other", got)
	}

	chooseByKeyboard(t, block.options, 1)
	if block.customOn {
		t.Error("choosing a listed option left the custom row on")
	}
	if got := block.field.GetText(); got != "" {
		t.Errorf("the replaced custom field still holds %q, which comes back the next time the row is opened", got)
	}
	a.submitQuestionForm()

	res := waitResult(t, results)
	if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "codemeld go" {
		t.Errorf("selected = %v, want the option that replaced the custom text", got)
	}
	if res.Answers[0].Custom != "" {
		t.Errorf("custom = %q, want it cleared by the listed option", res.Answers[0].Custom)
	}
}

func wrappedOptionQuestion() QuestionRequest {
	return QuestionRequest{Questions: []QuestionSpec{{
		ID:     "scope",
		Prompt: "Which scope?",
		Options: []string{
			"migrate the ingestion stage and then stop there for now",
			"migrate every stage and keep going right up to the freeze",
		},
		MultiSelect: true,
	}}}
}

// TestQuestionPrompt_ClickingAWrappedLineChoosesItsOption walks the one part of the click
// map every other mouse test misses: options wrap, and a click on a continuation line has to
// reach the option that owns it rather than the row above.
func TestQuestionPrompt_ClickingAWrappedLineChoosesItsOption(t *testing.T) {
	defer func(interval time.Duration) { tview.DoubleClickInterval = interval }(tview.DoubleClickInterval)
	tview.DoubleClickInterval = time.Millisecond

	a := New(nil)
	h := newAppHarnessFor(t, a, 44, 24)
	a.running.Store(true)
	defer a.running.Store(false)

	req := wrappedOptionQuestion()
	resc := askLive(t, a, req)
	h.runDraw(func() {})

	var x, y, owner int
	h.runDraw(func() {
		o := a.questionForm.blocks[0].options
		ix, iy, _, _ := o.GetInnerRect()
		offset, _ := o.GetScrollOffset()
		row := o.starts[1] + 1
		if row < len(o.owner) {
			owner = o.owner[row]
		} else {
			owner = -1
		}
		x, y = ix+1, iy+row-offset
	})
	if owner != 1 {
		t.Fatalf("setup: the second option's second rendered line belongs to option %d; the fixture must wrap at 44 columns", owner)
	}

	liveClickAt(t, h, x, y)
	waitOnLoop(t, a, "the click on the wrapped line to choose its option", func() bool {
		return a.questionForm.blocks[0].chosen[1]
	})
	liveClickSubmit(t, h)

	res := liveResult(t, a, resc)
	h.stop()

	if got := res.Answers[0].Selected; !slices.Equal(got, []string{req.Questions[0].Options[1]}) {
		t.Errorf("selected = %v, want only the option whose wrapped line was clicked", got)
	}
}

func TestQuestionPrompt_WheelUpMovesBackTheWayWheelDownCame(t *testing.T) {
	a := New(nil)
	h := newAppHarnessFor(t, a, 20, 24)
	a.running.Store(true)
	defer a.running.Store(false)

	resc := askLive(t, a, oversizedQuestion())
	h.runDraw(func() {})

	var x, y int
	h.a.app.QueueUpdate(func() {
		lx, ly, _, _ := a.questionForm.blocks[0].options.GetInnerRect()
		x, y = lx+1, ly+1
	})
	for i := 0; i < 3; i++ {
		liveWheel(t, h, x, y, tcell.WheelDown)
	}
	var down int
	h.a.app.QueueUpdate(func() { down, _ = a.questionForm.blocks[0].options.GetScrollOffset() })
	if down == 0 {
		t.Fatal("setup: three wheel notches did not scroll the over-tall question")
	}

	liveWheel(t, h, x, y, tcell.WheelUp)

	var up int
	h.a.app.QueueUpdate(func() { up, _ = a.questionForm.blocks[0].options.GetScrollOffset() })
	h.screen.InjectKey(tcell.KeyCtrlS, 0, tcell.ModNone)
	liveResult(t, a, resc)
	h.stop()

	if up != down-1 {
		t.Errorf("the wheel up left the question at row %d, want %d — one notch back from where the wheel down reached", up, down-1)
	}
}

// TestQuestionPrompt_ClickingBlankFormSpaceStaysInsideTheForm pins the overlay's own
// fallthrough guard: nothing in the form answers a click on its empty rows, so without the
// guard the event reaches the page underneath, which takes focus and the rest of the gesture.
func TestQuestionPrompt_ClickingBlankFormSpaceStaysInsideTheForm(t *testing.T) {
	a := New(nil)
	a.app.SetFocus(a.input)
	openQuestions(t, a, questionFixture())
	form := a.questionForm
	drawPrimitive(t, a.pages, 44, 24)

	sx, sy, _, sh := form.stage.GetRect()
	_, prevY, _, _ := form.prev.GetRect()
	y := sy + sh - 1
	if y <= prevY {
		t.Fatalf("setup: the stage has no blank row under the navigation row at y=%d", prevY)
	}

	clickAt(t, a, sx+3, y)

	if focus := a.app.GetFocus(); !form.owns(focus) {
		t.Errorf("focus = %T after a click on blank form space; the click fell through to the surface underneath", focus)
	}
	if !a.questionFormOpen {
		t.Error("a click on blank form space closed the form")
	}
}

// TestQuestionPrompt_PasteAfterLostTerminalFocusNeverReachesTheDraft drives the one input
// route that never passes through the key capture where modal-focus repair lives: tview
// collects a bracketed paste itself and hands the finished block to the root primitive. With
// terminal focus left stale on the input area, the paste would otherwise be typed into the
// draft under a mounted modal.
func TestQuestionPrompt_PasteAfterLostTerminalFocusNeverReachesTheDraft(t *testing.T) {
	const pasted = "pasted answer"
	for _, tc := range []struct {
		name  string
		focus func(*App) tview.Primitive
		lands bool
	}{
		{"open custom field", func(a *App) tview.Primitive {
			block := a.questionForm.blocks[2]
			a.questionForm.focus(block.options)
			block.choose(len(block.spec.Options))
			return block.field
		}, true},
		{"question list", func(a *App) tview.Primitive {
			block := a.questionForm.blocks[0]
			a.questionForm.focus(block.options)
			return block.options
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			h := newAppHarnessFor(t, a, 100, 30)
			a.running.Store(true)
			defer a.running.Store(false)
			h.runDraw(func() { a.input.SetText("half-written prompt") })

			resc := askLive(t, a, questionFixture())
			h.runDraw(func() {})
			var want tview.Primitive
			h.runDraw(func() { want = tc.focus(a) })
			waitOnLoop(t, a, "the form control to take focus", func() bool {
				return a.app.GetFocus() == want
			})

			staleFocusOnInput(t, a)
			a.app.QueueEvent(tcell.NewEventPaste(true))
			for _, r := range pasted {
				a.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone))
			}
			a.app.QueueEvent(tcell.NewEventPaste(false))
			a.app.QueueEvent(tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModNone))

			res := liveResult(t, a, resc)
			var draft string
			a.app.QueueUpdate(func() { draft = a.input.GetText() })
			h.stop()

			if draft != "half-written prompt" {
				t.Errorf("input draft = %q; the paste reached the draft under the mounted form", draft)
			}
			got := res.Answers[2].Custom
			switch {
			case tc.lands && got != pasted:
				t.Errorf("custom answer = %q, want the paste in the text field that had focus", got)
			case !tc.lands && got != "":
				t.Errorf("custom answer = %q, want nothing: no text control was focused to receive it", got)
			}
		})
	}
}

func contextQuestionFixture(context string) QuestionRequest {
	req := questionFixture()
	req.Context = context
	return req
}

func openClarification(t *testing.T, a *App, text string) {
	t.Helper()
	form := a.questionForm
	form.clarify.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})
	if !form.clarifyOn {
		t.Fatal("setup: the clarification button did not open its entry")
	}
	form.clarifyField.SetText(text)
}

func TestQuestionResult_ClarificationEncodesWithoutAnAnswersKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  QuestionResult
		want string
	}{
		{"clarification", QuestionResult{Clarification: `what is an "object store"?`}, `{"clarification":"what is an \"object store\"?"}`},
		{"clarification never carries the answers it replaces", QuestionResult{Answers: []QuestionAnswer{{ID: "a", Prompt: "p", Selected: []string{}}}, Clarification: "why?"}, `{"clarification":"why?"}`},
		{"no answers", QuestionResult{}, `{"answers":[]}`},
		{"cancelled", QuestionResult{Answers: []QuestionAnswer{}, Cancelled: true}, `{"answers":[],"cancelled":true}`},
		{"ordinary answer", QuestionResult{Answers: []QuestionAnswer{{ID: "a", Prompt: "p", Selected: []string{"x"}}}}, `{"answers":[{"id":"a","prompt":"p","selected":["x"]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.res.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if got != tc.want {
				t.Errorf("encoded = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestQuestionPrompt_ClarificationSubmitsInPlaceOfTheAnswers(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())
	chooseByKeyboard(t, a.questionForm.blocks[0].options, 1)

	openClarification(t, a, "  which store do you mean?  ")
	a.submitQuestionForm()

	res := waitResult(t, results)
	if res.Clarification != "which store do you mean?" {
		t.Errorf("clarification = %q, want the trimmed question the user typed", res.Clarification)
	}
	if len(res.Answers) != 0 {
		t.Errorf("answers = %+v, want none: a clarification answers no question", res.Answers)
	}
	if res.Cancelled {
		t.Error("the clarification came back cancelled; it is an ordinary result the model must answer")
	}
	encoded, err := res.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded != `{"clarification":"which store do you mean?"}` {
		t.Errorf("encoded = %s, want only the clarification even though an option was chosen first", encoded)
	}
}

func TestQuestionPrompt_ClarificationAndCustomAnswerCannotBecomeEachOther(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())
	custom := a.questionForm.blocks[2]
	chooseByKeyboard(t, custom.options, len(custom.spec.Options))
	custom.field.SetText("codemeld ask")

	a.submitQuestionForm()

	res := waitResult(t, results)
	if res.Clarification != "" {
		t.Errorf("clarification = %q, want none: a typed answer is not a question back", res.Clarification)
	}
	if got := res.Answers[2].Custom; got != "codemeld ask" {
		t.Errorf("custom answer = %q, want the typed answer preserved", got)
	}
}

func TestQuestionPrompt_AnEmptyClarificationSubmitsTheAnswersInstead(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"never typed", ""},
		{"whitespace only", "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			results := openQuestions(t, a, questionFixture())
			chooseByKeyboard(t, a.questionForm.blocks[0].options, 0)

			openClarification(t, a, tc.text)
			a.submitQuestionForm()

			res := waitResult(t, results)
			if res.Clarification != "" {
				t.Errorf("clarification = %q, want none: an empty entry must not ask the model nothing", res.Clarification)
			}
			if got := res.Answers[0].Selected; len(got) != 1 || got[0] != "Local disk" {
				t.Errorf("answers = %v, want the option that was chosen before the entry opened", got)
			}
		})
	}
}

func TestQuestionPrompt_ClosingTheClarificationEntryDiscardsItsText(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())
	form := a.questionForm
	openClarification(t, a, "why does this matter?")

	pressKey(form.clarify, tcell.KeyEnter)

	if form.clarifyOn {
		t.Fatal("the clarification button did not close its entry on a second press")
	}
	if got := form.clarifyField.GetText(); got != "" {
		t.Errorf("clarification text = %q, want it discarded with the entry", got)
	}
	if slices.Contains(form.focusRing(), tview.Primitive(form.clarifyField)) {
		t.Error("the focus ring still stops on the closed clarification entry")
	}
	a.submitQuestionForm()
	if res := waitResult(t, results); res.Clarification != "" {
		t.Errorf("clarification = %q, want none after the entry was closed", res.Clarification)
	}
}

func TestQuestionPrompt_ClarificationEntryStopsAtItsBound(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())
	field := a.questionForm.clarifyField
	openClarification(t, a, strings.Repeat("q", maxClarificationRunes))

	field.InputHandler()(tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone), func(tview.Primitive) {})

	if got := utf8.RuneCountInString(field.GetText()); got != maxClarificationRunes {
		t.Errorf("clarification length = %d after typing past the bound, want it held at %d", got, maxClarificationRunes)
	}
	if strings.HasSuffix(field.GetText(), "x") {
		t.Error("the rune past the bound was accepted")
	}
}

func TestQuestionPrompt_CancellingWhileClarifyingStaysCancelled(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, questionFixture())
	openClarification(t, a, "why does this matter?")

	a.cancelQuestionForm()

	res := waitResult(t, results)
	if !res.Cancelled {
		t.Error("dismissing the form while clarifying did not come back cancelled")
	}
	if res.Clarification != "" {
		t.Errorf("clarification = %q, want none: a dismissed form asks nothing", res.Clarification)
	}
	if got := a.TranscriptText(); got != "" {
		t.Errorf("transcript = %q, want nothing recorded for a dismissed form", got)
	}
}

func TestQuestionPrompt_ContextIsDrawnAboveTheQuestion(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, contextQuestionFixture("Sessions are replayed on /resume, so where they live decides what survives a restart."))

	text := flattenScreen(screenText(drawPrimitive(t, a.pages, 120, 30)))

	background := strings.Index(text, flattenScreen("Sessions are replayed on /resume"))
	prompt := strings.Index(text, flattenScreen("Where should sessions be stored?"))
	option := strings.Index(text, flattenScreen("Local disk"))
	if background < 0 {
		t.Fatalf("the supplied context was not drawn:\n%s", text)
	}
	if prompt < 0 || option < 0 {
		t.Fatalf("the question or its options went missing beside the context:\n%s", text)
	}
	if background > prompt || background > option {
		t.Error("the context was drawn after the question it is meant to explain")
	}
}

func TestQuestionPrompt_ContextRendersLiterally(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, contextQuestionFixture("[red]this is not a tag[-] and [::b] is not bold"))

	text := flattenScreen(screenText(drawPrimitive(t, a.pages, 120, 30)))

	for _, want := range []string{"[red]this is not a tag[-]", "[::b] is not bold"} {
		if !strings.Contains(text, flattenScreen(want)) {
			t.Errorf("drawn context did not carry %q literally:\n%s", want, text)
		}
	}
}

func TestQuestionPrompt_ContextScrollsWithoutMovingTheOptions(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, contextQuestionFixture(maxRuneText("background", provider.MaxAskUserContextRunes)))
	form := a.questionForm
	drawPrimitive(t, a.pages, 44, 24)
	optionsBefore, _ := form.blocks[0].options.GetScrollOffset()

	form.focus(form.context)
	for i := 0; i < 3; i++ {
		pressKey(form.context, tcell.KeyDown)
	}
	drawPrimitive(t, a.pages, 44, 24)

	if row, _ := form.context.GetScrollOffset(); row == 0 {
		t.Error("the context did not scroll; a context taller than its section would be unreadable")
	}
	if row, _ := form.blocks[0].options.GetScrollOffset(); row != optionsBefore {
		t.Errorf("options scrolled to row %d while the context was scrolled, want them left at %d", row, optionsBefore)
	}
}

func TestQuestionPrompt_ContextNeverCrowdsOutTheQuestion(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, contextQuestionFixture(maxRuneText("background", provider.MaxAskUserContextRunes)))

	for _, size := range []struct{ width, height int }{{20, 24}, {44, 24}, {120, 30}} {
		drawPrimitive(t, a.pages, size.width, size.height)
		_, _, _, rows := a.questionForm.context.GetRect()
		if rows < 1 {
			t.Errorf("at %dx%d the context section got %d rows, want at least one", size.width, size.height, rows)
		}
		if max := size.height / 3; rows > max {
			t.Errorf("at %dx%d the context took %d rows, want at most %d so the question stays on screen", size.width, size.height, rows, max)
		}
	}
}

func TestQuestionPrompt_NarrowLayoutKeepsEveryControlReachable(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, contextQuestionFixture(maxRuneText("background", provider.MaxAskUserContextRunes)))
	form := a.questionForm
	drawPrimitive(t, a.pages, 20, 24)

	ring := form.focusRing()
	for _, want := range []tview.Primitive{form.context, form.blocks[0].options, form.clarify, form.submit, form.cancel} {
		if !slices.Contains(ring, want) {
			t.Errorf("the focus ring cannot reach %s at the narrow supported layout", controlName(form, want))
		}
	}
	_, _, width, _ := form.clarify.GetRect()
	if width > 20 {
		t.Errorf("the clarification control is %d cells wide at a 20-column terminal", width)
	}
	if text := screenText(drawPrimitive(t, a.pages, 20, 24)); !strings.Contains(text, clarifyLabel) {
		t.Errorf("the clarification control's label is clipped at 20x24, so the action cannot be read:\n%s", text)
	}
}

func TestQuestionPrompt_NoContextMountsNoContextSurface(t *testing.T) {
	a := New(nil)
	openQuestions(t, a, questionFixture())

	if a.questionForm.context != nil {
		t.Error("a call with no context still mounted a context section")
	}
	if slices.Contains(a.questionForm.focusRing(), tview.Primitive(a.questionForm.context)) {
		t.Error("the focus ring stops on a context section that was never mounted")
	}
	drawPrimitive(t, a.pages, 120, 30)
}

func TestQuestionPrompt_SubmittedFormSealsThePreambleThenRecordsTheAnswer(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("I need to know where sessions go.")
	results := openQuestions(t, a, questionFixture())
	chooseByKeyboard(t, a.questionForm.blocks[0].options, 1)
	multi := a.questionForm.blocks[1]
	chooseByKeyboard(t, multi.options, 0)
	chooseByKeyboard(t, multi.options, 2)
	custom := a.questionForm.blocks[2]
	chooseByKeyboard(t, custom.options, len(custom.spec.Options))
	custom.field.SetText("codemeld ask")

	a.submitQuestionForm()
	waitResult(t, results)
	a.AppendStreamDelta("Object store it is.")

	want := "I need to know where sessions go." + visibleResponseLine + "\n\n" +
		"Answered:\n" +
		"  Where should sessions be stored? — Object store\n" +
		"  Which platforms must ship first? — Linux, Windows\n" +
		"  What should the command be called? — codemeld ask\n\n" +
		"Object store it is."
	if got := a.TranscriptText(); got != want {
		t.Fatalf("transcript =\n%q\nwant\n%q", got, want)
	}
}

func TestQuestionPrompt_ClarificationRecordIsDistinctAndKeepsTheLaterAnswerSeparate(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("Picking a store now.")
	results := openQuestions(t, a, questionFixture())
	openClarification(t, a, "what is an object store?")

	a.submitQuestionForm()
	waitResult(t, results)
	a.AppendStreamDelta("It is a remote blob service.")

	want := "Picking a store now." + visibleResponseLine + "\n\n" +
		"Asked for clarification:\n" +
		"  what is an object store?\n\n" +
		"It is a remote blob service."
	if got := a.TranscriptText(); got != want {
		t.Fatalf("transcript =\n%q\nwant\n%q", got, want)
	}
}

// Dismissing the form still hands a result back to the model, so the turn goes on: the prose
// that led up to the form has to be sealed even though the dismissal records no answer.
func TestQuestionPrompt_DismissedFormSealsThePreambleWithoutRecordingAnAnswer(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("I need to know where sessions go.")
	results := openQuestions(t, a, questionFixture())

	a.cancelQuestionForm()
	waitResult(t, results)
	a.AppendStreamDelta("Sticking with local disk then.")

	want := "I need to know where sessions go." + visibleResponseLine + "\n\nSticking with local disk then."
	if got := a.TranscriptText(); got != want {
		t.Fatalf("transcript =\n%q\nwant\n%q", got, want)
	}
}

func TestQuestionPrompt_RecordsNoAnswerForAnUntouchedQuestionAndNothingForACancelledForm(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{
		{ID: "storage", Prompt: "Where should sessions be stored?", Options: []string{"Local disk"}},
	}})

	a.submitQuestionForm()
	waitResult(t, results)
	submitted := a.TranscriptText()

	cancelled := openQuestions(t, a, questionFixture())
	a.cancelQuestionForm()
	waitResult(t, cancelled)

	want := "Answered:\n  Where should sessions be stored? — (no answer)"
	if submitted != want {
		t.Errorf("transcript =\n%q\nwant\n%q", submitted, want)
	}
	if got := a.TranscriptText(); got != want {
		t.Errorf("transcript = %q after a dismissed form, want the cancelled form to add nothing", got)
	}
}

func TestQuestionPrompt_RecordKeepsTagShapedTextLiteralAndHidesTheToolPlumbing(t *testing.T) {
	a := New(nil)
	results := openQuestions(t, a, QuestionRequest{Questions: []QuestionSpec{
		{ID: "call_1", Prompt: "[red]Which store?[-]", Options: []string{"[::b]Object store"}},
	}})
	chooseByKeyboard(t, a.questionForm.blocks[0].options, 0)

	a.submitQuestionForm()
	waitResult(t, results)

	got := a.TranscriptText()
	if !strings.Contains(got, "[red]Which store?[-] — [::b]Object store") {
		t.Errorf("transcript = %q, want the tag-shaped text drawn literally", got)
	}
	for _, leaked := range []string{"ask_user", `{"answers"`, "call_1"} {
		if strings.Contains(got, leaked) {
			t.Errorf("transcript = %q, leaked the tool plumbing %q", got, leaked)
		}
	}
	if raw := a.transcript.view.GetText(false); !strings.Contains(raw, "[red[]Which store?") {
		t.Errorf("committed block = %q, want the literal tag escaped rather than parsed as markup", raw)
	}
}

func TestAskQuestions_AnInterruptedFormRecordsNothingAndSealsNoStream(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("Picking a store now.")
	mounted := openQuestions(t, a, questionFixture())
	chooseByKeyboard(t, a.questionForm.blocks[0].options, 0)
	openClarification(t, a, "why does this matter?")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := a.abandonQuestionForm(ctx, mounted); !errors.Is(err, context.Canceled) {
		t.Fatalf("abandonQuestionForm error = %v, want context.Canceled", err)
	}

	if a.QuestionFormOpen() {
		t.Error("the interrupted form is still mounted")
	}
	if len(mounted) != 0 {
		t.Error("the interrupted form delivered a result to its caller")
	}
	a.AppendStreamDelta(" Interrupted.")
	if got := a.TranscriptText(); got != "Picking a store now. Interrupted." {
		t.Errorf("transcript = %q, want the open stream untouched and no answer record", got)
	}
}
