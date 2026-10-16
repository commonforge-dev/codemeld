package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const questionFormPage = "question-form"

const customAnswerRowLabel = "Type your own answer"

// Short enough to be drawn whole inside the form's border at the supported 20-column width.
const clarifyLabel = "Ask clarification"

// The clarification is never drawn as a form row, so it is not held to the displayed-text bound.
const maxClarificationRunes = 1000

const (
	prevQuestionLabel = "‹ Prev"
	nextQuestionLabel = "Next ›"
)

const (
	singleChosenMark = "(*)"
	singleOpenMark   = "( )"
	multiChosenMark  = "[x]"
	multiOpenMark    = "[ ]"
)

// questionRowMarkWidth is the mark and its space that refreshRows puts before every label,
// so a label fitted to this much less than the block width is what the row actually draws.
// Measuring the prompt or a label at any other width silently desynchronizes what layout
// budgets from what the terminal renders, which is how a fitted row and its full-text
// reveal can disagree about whether the text was truncated at all.
const questionRowMarkWidth = 4

var (
	errQuestionFormBusy  = errors.New("another overlay is already open")
	errQuestionFormEmpty = errors.New("no questions to ask")
)

type QuestionSpec struct {
	ID          string
	Prompt      string
	Options     []string
	MultiSelect bool
	AllowCustom bool
}

type QuestionRequest struct {
	Context   string
	Questions []QuestionSpec
}

type QuestionAnswer struct {
	ID       string   `json:"id"`
	Prompt   string   `json:"prompt"`
	Selected []string `json:"selected"`
	Custom   string   `json:"custom,omitempty"`
}

type QuestionResult struct {
	Answers       []QuestionAnswer `json:"answers"`
	Cancelled     bool             `json:"cancelled,omitempty"`
	Clarification string           `json:"clarification,omitempty"`
}

// A clarification marshals through its own shape because `answers` has no omitempty: this
// struct would pair it with an empty answer list the model reads as a question answered with
// nothing.
func (r QuestionResult) Encode() (string, error) {
	if r.Clarification != "" {
		return encodeQuestionJSON(struct {
			Clarification string `json:"clarification"`
		}{r.Clarification})
	}
	if r.Answers == nil {
		r.Answers = []QuestionAnswer{}
	}
	return encodeQuestionJSON(r)
}

func encodeQuestionJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

type questionBlock struct {
	spec    QuestionSpec
	form    *questionForm
	flex    *tview.Flex
	options *questionOptions
	field   *tview.InputField

	chosen     []bool
	customOn   bool
	customText string
}

type questionForm struct {
	app          *App
	req          QuestionRequest
	blocks       []*questionBlock
	focused      *questionBlock
	active       tview.Primitive
	stage        *questionStage
	body         *tview.Flex
	context      *tview.TextView
	prev         *tview.Button
	next         *tview.Button
	clarify      *tview.Button
	clarifyField *tview.InputField
	submit       *tview.Button
	cancel       *tview.Button
	resultCh     chan QuestionResult

	clarifyOn     bool
	contextWidth  int
	contextHeight int

	repeatClick bool
	lastClick   questionRow
	thisClick   questionRow
}

// questionRow names the option row a click chose. The zero value says the click was handled
// somewhere else in the form — a button, a custom field, blank space — which is why the
// identity is a value rather than a pair of fields: only a row that a click actually chose
// can be repeated by the click that follows it.
type questionRow struct {
	block *questionBlock
	index int
}

// actOnClick reports whether this click chooses the row, or is the second half of a double
// click on the row the first half already chose. There is no double-click gesture in the
// form — one click selects the row and its option — but tview classifies a click as a
// double by *time alone*, so two quick clicks on different rows arrive the same way as two
// on one row. The second must therefore still act on a different row, and must not act again
// on the same one, which would toggle a checkbox back off or close an open custom answer and
// discard its text.
func (f *questionForm) actOnClick(b *questionBlock, index int) bool {
	f.thisClick = questionRow{block: b, index: index}
	return !f.repeatClick || f.lastClick != f.thisClick
}

// questionStage is a column flex holding the position counter and the one question being
// shown.
//
// Only the focused question is placed. tview draws a child past its parent's rect rather
// than clipping it, so a question that is not being shown has to be out of the flex
// entirely rather than merely sized to zero.
type questionStage struct {
	*tview.Flex
	counter *tview.TextView
	slot    *tview.Flex
	form    *questionForm
	shown   *questionBlock
	width   int
	height  int
	placed  bool
}

func (c *questionStage) Draw(screen tcell.Screen) {
	_, _, width, height := c.GetRect()
	c.relayout(width, height)
	c.Flex.Draw(screen)
}

func (c *questionStage) relayout(width, height int) {
	if width <= 0 {
		return
	}
	if c.placed && width == c.width && height == c.height && c.shown == c.form.focused {
		return
	}
	c.place(width, height)
}

func (c *questionStage) place(width, height int) {
	c.width, c.height = width, height
	block := c.form.focused
	if block == nil {
		block = c.form.blocks[0]
	}
	used := block.layout(width, c.availableHeight(height))

	c.counter.SetText(c.form.position())
	c.ResizeItem(c.slot, used, 0)
	c.slot.Clear()
	c.slot.AddItem(block.flex, 0, 1, false)
	c.shown = block
	c.placed = true
}

// availableHeight is what the stage has left for the question: its own height less the
// counter above it and the Prev/Next row below it.
func (c *questionStage) availableHeight(height int) int {
	if avail := height - 2; avail > 2 {
		return avail
	}
	return 2
}

func (c *questionStage) invalidate() { c.placed = false }

// MouseHandler sends a wheel notch anywhere over the question to the shown question's
// scrollable region, so the pointer does not have to be inside it to scroll.
func (c *questionStage) MouseHandler() func(tview.MouseAction, *tcell.EventMouse, func(tview.Primitive)) (bool, tview.Primitive) {
	return func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(tview.Primitive)) (bool, tview.Primitive) {
		if !c.InRect(event.Position()) {
			return false, nil
		}
		switch action {
		case tview.MouseScrollUp, tview.MouseScrollDown:
			if c.shown != nil {
				delta := 1
				if action == tview.MouseScrollUp {
					delta = -1
				}
				c.shown.options.scrollBy(delta)
			}
			return true, nil
		}
		return c.Flex.MouseHandler()(action, event, setFocus)
	}
}

// questionOptions renders a question's prompt and every option row into one scrollable
// region, wrapping each label across as many lines as it needs. It stands in for
// tview.List, which prints an item with a single one-line write: fitting a label to the
// width meant truncating it, and a truncated label then needed a second surface to reveal
// its full text. Nothing is truncated here, so there is nothing to reveal.
type questionOptions struct {
	*tview.TextView
	block   *questionBlock
	current int
	// owner names the option each rendered line belongs to (-1 for the prompt's own
	// lines) and starts names each option's first line, so a click, the keyboard cursor
	// and the scroll position all agree with the wrapping that was actually drawn.
	owner  []int
	starts []int
	// offsets is the byte offset into its own prompt or option text where each rendered
	// line begins, taken at a UTF-8 boundary in the original unescaped string. With owner
	// it turns a display row into a position in the source, which is what survives a
	// rewrap and what a selection copies.
	offsets []int
	sel     textSelection
	anchor  questionAnchor
	width   int
	// focused mirrors tview's focus state. render cannot ask for it: TextView.Focus holds
	// the widget lock while it calls the focus callback, and both HasFocus and SetText
	// take that same lock, so rendering from inside the callback deadlocks.
	focused bool
}

// questionAnchor is where the reader is in a question's text: the prompt (-1) or the option
// the top visible line belongs to, and how far into that text it begins. A display line
// number cannot stand in for it. The same numbered line is different text once the width
// rewraps, and a width wide enough to fit the whole question makes TextView.Draw clamp its
// live offset to zero, so the position the reader chose has to be held apart from the
// offset tview is currently drawing at.
type questionAnchor struct {
	item   int
	offset int
}

func newQuestionOptions(b *questionBlock) *questionOptions {
	o := &questionOptions{TextView: tview.NewTextView(), block: b, anchor: questionAnchor{item: -1}}
	o.sel.rows = hardRows
	o.SetDynamicColors(true)
	o.SetWrap(false)
	o.SetScrollable(true)
	return o
}

func (o *questionOptions) GetItemCount() int {
	if o.block.spec.AllowCustom {
		return len(o.block.spec.Options) + 1
	}
	return len(o.block.spec.Options)
}

func (o *questionOptions) GetCurrentItem() int { return o.current }

func (o *questionOptions) SetCurrentItem(index int) {
	if index < 0 || index >= o.GetItemCount() || index == o.current {
		return
	}
	o.current = index
	o.render(o.width)
	o.ensureVisible()
}

func (o *questionOptions) label(index int) string {
	if index < len(o.block.spec.Options) {
		return o.block.spec.Options[index]
	}
	return customAnswerRowLabel
}

func (o *questionOptions) marked(index int) bool {
	if index < len(o.block.chosen) {
		return o.block.chosen[index]
	}
	return o.block.customOn
}

func (o *questionOptions) contentHeight() int { return len(o.owner) }

// render rebuilds the text at the given width. Provider text is escaped and the only
// style tags are the ones added here, so a label that looks like markup renders literally.
func (o *questionOptions) render(width int) {
	if width < 8 {
		width = 8
	}
	o.width = width
	body := width - questionRowMarkWidth
	if body < 1 {
		body = 1
	}
	highlight := o.focused

	var text strings.Builder
	o.owner = o.owner[:0]
	o.offsets = o.offsets[:0]
	o.starts = make([]int, o.GetItemCount())
	promptLines, promptOffsets := wrapSource(o.block.spec.Prompt, width)
	for i, line := range promptLines {
		text.WriteString(line + "\n")
		o.owner = append(o.owner, -1)
		o.offsets = append(o.offsets, promptOffsets[i])
	}
	for i := 0; i < o.GetItemCount(); i++ {
		o.starts[i] = len(o.owner)
		label := o.label(i)
		lines, lineOffsets := wrapSource(label, body)
		if len(lines) == 0 {
			lines, lineOffsets = []string{""}, []int{0}
		}
		for j, line := range lines {
			prefix := strings.Repeat(" ", questionRowMarkWidth)
			if j == 0 {
				// The marks are bracket-shaped, so they are escaped like any other text before
				// a dynamic-colors view parses the line as markup.
				prefix = tview.Escape(o.block.mark(o.marked(i))) + " "
			}
			row := prefix + line
			if highlight && i == o.current {
				row = "[" + accentTealHex + "]" + row + "[-]"
			}
			text.WriteString(row + "\n")
			o.owner = append(o.owner, i)
			o.offsets = append(o.offsets, lineOffsets[j])
		}
	}
	o.SetText(strings.TrimSuffix(text.String(), "\n"))
	o.invalidateSelection()
	// Put the view back where the reader left it, in the new wrapping. Deliberately not
	// through scrollToLine: this must not re-record the anchor, or a width that fits the
	// whole question — where tview clamps the offset to zero — would overwrite it.
	o.ScrollTo(o.anchorRow(), 0)
}

// anchorAt reads the position row starts at, and anchorRow finds that position again in the
// current wrapping: the last line of the same prompt or option that starts no further into
// its text than the anchor did, or that block's first line when the rewrap pushed every line
// past it.
func (o *questionOptions) anchorAt(row int) questionAnchor {
	if len(o.owner) == 0 {
		return questionAnchor{item: -1}
	}
	if row < 0 {
		row = 0
	}
	if row >= len(o.owner) {
		row = len(o.owner) - 1
	}
	return questionAnchor{item: o.owner[row], offset: o.offsets[row]}
}

func (o *questionOptions) anchorRow() int {
	row, found := 0, false
	for i, owner := range o.owner {
		if owner != o.anchor.item {
			if found {
				break
			}
			continue
		}
		if found && o.offsets[i] > o.anchor.offset {
			break
		}
		row, found = i, true
	}
	return row
}

func (o *questionOptions) lastLineOf(index int) int {
	last := o.starts[index]
	for last+1 < len(o.owner) && o.owner[last+1] == index {
		last++
	}
	return last
}

func (o *questionOptions) ensureVisible() {
	if o.current < 0 || o.current >= len(o.starts) {
		return
	}
	_, _, _, height := o.GetInnerRect()
	if height <= 0 {
		return
	}
	first, last := o.starts[o.current], o.lastLineOf(o.current)
	row, _ := o.GetScrollOffset()
	switch {
	case first < row:
		row = first
	case last >= row+height:
		// Prefer the option's first line when it is taller than the viewport: scrolling
		// to its last line would hide the mark that says whether it is chosen.
		if row = last - height + 1; row > first {
			row = first
		}
	default:
		return
	}
	o.scrollToLine(row)
}

// scrollToLine is every deliberate move of the view, and the only place the anchor is
// recorded: where the reader scrolled to is what a later rewrap has to reproduce.
func (o *questionOptions) scrollToLine(row int) {
	if max := o.maxScroll(); row > max {
		row = max
	}
	if row < 0 {
		row = 0
	}
	o.anchor = o.anchorAt(row)
	o.ScrollTo(row, 0)
}

func (o *questionOptions) maxScroll() int {
	_, _, _, height := o.GetInnerRect()
	if height < 1 {
		return 0
	}
	if max := o.contentHeight() - height; max > 0 {
		return max
	}
	return 0
}

// scrollPage moves by a viewport. Without it an option taller than the region would have
// its tail unreachable from the keyboard: ensureVisible pins such an option to its first
// line so its chosen/unchosen mark stays on screen.
func (o *questionOptions) scrollPage(dir int) {
	_, _, _, height := o.GetInnerRect()
	if height < 1 {
		height = 1
	}
	o.scrollBy(dir * height)
}

func (o *questionOptions) scrollBy(delta int) {
	row, _ := o.GetScrollOffset()
	o.scrollToLine(row + delta)
}

func (o *questionOptions) move(delta int) {
	next := o.current + delta
	if next < 0 || next >= o.GetItemCount() {
		return
	}
	o.SetCurrentItem(next)
}

func (o *questionOptions) optionAt(y int) int {
	_, top, _, height := o.GetInnerRect()
	if y < top || y >= top+height {
		return -1
	}
	row, _ := o.GetScrollOffset()
	line := y - top + row
	if line < 0 || line >= len(o.owner) {
		return -1
	}
	return o.owner[line]
}

func (o *questionOptions) MouseHandler() func(tview.MouseAction, *tcell.EventMouse, func(tview.Primitive)) (bool, tview.Primitive) {
	return func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(tview.Primitive)) (bool, tview.Primitive) {
		x, y := event.Position()
		if !o.InRect(x, y) {
			return false, nil
		}
		switch action {
		case tview.MouseLeftClick, tview.MouseLeftDoubleClick:
			if index := o.optionAt(y); index >= 0 {
				setFocus(o)
				o.SetCurrentItem(index)
				if o.block.form.actOnClick(o.block, index) {
					o.block.choose(index)
				}
			}
			return true, nil
		case tview.MouseScrollUp:
			o.scrollBy(-1)
			return true, nil
		case tview.MouseScrollDown:
			o.scrollBy(1)
			return true, nil
		}
		return true, nil
	}
}

type questionMount int

const (
	questionMountOpened questionMount = iota
	questionMountBusy
	questionMountCancelled
)

// Must not be called from a tview event-loop callback.
func (a *App) AskQuestions(ctx context.Context, req QuestionRequest) (QuestionResult, error) {
	if len(req.Questions) == 0 {
		return QuestionResult{}, errQuestionFormEmpty
	}
	if err := ctx.Err(); err != nil {
		return QuestionResult{}, err
	}
	resultCh := make(chan QuestionResult, 1)
	mounted := make(chan questionMount, 1)
	a.streamUpdate(func() {
		switch {
		case ctx.Err() != nil:
			mounted <- questionMountCancelled
		case !a.openQuestionForm(req, resultCh):
			mounted <- questionMountBusy
		default:
			mounted <- questionMountOpened
		}
	})
	select {
	case outcome := <-mounted:
		switch outcome {
		case questionMountBusy:
			return QuestionResult{}, errQuestionFormBusy
		case questionMountCancelled:
			return QuestionResult{}, ctx.Err()
		}
	case <-ctx.Done():
		return a.abandonQuestionForm(ctx, resultCh)
	}
	select {
	case res := <-resultCh:
		return res, nil
	case <-ctx.Done():
		return a.abandonQuestionForm(ctx, resultCh)
	}
}

// abandonQuestionForm queues the teardown behind the mount callback rather than assuming
// the form is up: giving up on the mount reply and the mount itself can race, and the
// queue's order is what makes the late one a no-op instead of a leaked overlay. The
// channel identifies the abandoning request, because by the time the callback runs the
// mounted form can belong to a different caller — one this request must not dismiss.
func (a *App) abandonQuestionForm(ctx context.Context, resultCh chan QuestionResult) (QuestionResult, error) {
	a.streamUpdate(func() {
		if a.questionForm == nil || a.questionForm.resultCh != resultCh {
			return
		}
		a.finishQuestionForm(QuestionResult{}, false)
	})
	return QuestionResult{}, ctx.Err()
}

func (a *App) openQuestionForm(req QuestionRequest, resultCh chan QuestionResult) bool {
	if a.anyOverlayOpen() || len(req.Questions) == 0 {
		return false
	}
	a.discardActiveDrags()
	form := &questionForm{app: a, req: req, resultCh: resultCh}
	overlay, focus := form.build()
	a.questionForm = form
	a.questionFormOpen = true
	a.questionFormPrev = a.app.GetFocus()
	a.pages.AddPage(questionFormPage, wrapOverlayPage(overlay), true, true)
	a.app.SetFocus(focus)
	select {
	case a.questionFormMounts <- struct{}{}:
	default:
	}
	return true
}

// discardActiveDrags ends any app-owned selection drag before the modal goes up. The
// app-level mouse capture answers a move or a release from an active input or transcript
// selection ahead of its overlay guard, and both release paths focus the input, so a drag
// that outlived the mount would take focus out of the form and let a paste reach the draft.
// The selections are discarded rather than finished: the user never released the button, so
// there is nothing to copy.
func (a *App) discardActiveDrags() {
	if a.transcript.isSelecting() {
		a.transcriptScrollGen++
		a.transcriptScrollPending = false
		a.transcript.endSelect()
	}
	if a.inputSelecting {
		a.finishInputSelection()
		a.input.collapseSelection()
	}
	a.inputDragging = false
}

func (f *questionForm) build() (tview.Primitive, tview.Primitive) {
	f.blocks = make([]*questionBlock, 0, len(f.req.Questions))
	for _, spec := range f.req.Questions {
		f.blocks = append(f.blocks, newQuestionBlock(f, spec))
	}

	counter := tview.NewTextView()
	counter.SetDynamicColors(false)

	f.stage = &questionStage{
		Flex:    tview.NewFlex().SetDirection(tview.FlexRow),
		counter: counter,
		slot:    tview.NewFlex().SetDirection(tview.FlexRow),
		form:    f,
	}
	f.prev = f.button(prevQuestionLabel, func() { f.showAdjacent(-1) })
	f.next = f.button(nextQuestionLabel, func() { f.showAdjacent(1) })
	f.clarify = f.button(clarifyLabel, func() { f.toggleClarify() })
	f.submit = f.button("Submit", func() { f.app.submitQuestionForm() })
	f.cancel = f.button("Cancel", func() { f.app.cancelQuestionForm() })
	f.clarifyField = f.buildClarifyField()

	f.stage.AddItem(f.stage.counter, 1, 0, false)
	f.stage.AddItem(f.stage.slot, 0, 0, false)
	// Prev/Next sit with the question they move, not with the form's actions, and they are
	// the mouse's only route to another question — the keyboard steps the questions
	// themselves through the focus ring, which is why focusRing leaves these two out.
	f.stage.AddItem(buttonRow(f.prev, prevQuestionLabel, f.next, nextQuestionLabel), 1, 0, false)
	// The filler absorbs the leftover height so the counter and the question stay at the
	// top of the terminal instead of the question stretching to fill it.
	f.stage.AddItem(nil, 0, 1, false)

	buttons := buttonRow(f.submit, "Submit", f.cancel, "Cancel")

	hint := tview.NewTextView()
	hint.SetDynamicColors(false)
	hint.SetText("↑↓ move · enter choose · tab or → next · ← prev · pgup/pgdn scroll · wheel scroll · ctrl-s submit · esc cancel")

	f.body = tview.NewFlex().SetDirection(tview.FlexRow)
	if f.req.Context != "" {
		f.context = f.buildContext()
		f.body.AddItem(f.context, 1, 0, false)
	}
	f.body.AddItem(f.stage, 0, 1, true)
	f.body.AddItem(f.clarify, 1, 0, false)
	f.body.AddItem(f.clarifyField, 0, 0, false)
	f.body.AddItem(buttons, 1, 0, false)
	f.body.AddItem(hint, 1, 0, false)
	f.body.SetBorder(true)
	f.body.SetTitle(" questions ")
	f.focused = f.blocks[0]
	f.active = f.blocks[0].options
	return &questionOverlay{Flex: f.body, form: f}, f.active
}

// Dynamic colors stay off so provider text renders literally without an escaping pass.
func (f *questionForm) buildContext() *tview.TextView {
	view := tview.NewTextView()
	view.SetDynamicColors(false)
	view.SetWrap(true)
	view.SetWordWrap(true)
	view.SetScrollable(true)
	view.SetText(f.req.Context)
	view.SetFocusFunc(func() { f.trackFocus(view) })
	view.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyTab, tcell.KeyRight:
			f.focusNext(view)
			return nil
		case tcell.KeyLeft:
			f.focusPrev(view)
			return nil
		case tcell.KeyCtrlS:
			f.app.submitQuestionForm()
			return nil
		}
		return ev
	})
	return view
}

// The third-of-the-form cap leaves the question and its options on screen; the section
// scrolls whatever does not fit.
func (f *questionForm) sizeContext(width, height int) {
	if f.context == nil || width <= 0 || (width == f.contextWidth && height == f.contextHeight) {
		return
	}
	f.contextWidth, f.contextHeight = width, height
	rows := len(tview.WordWrap(f.req.Context, width))
	if max := height / 3; rows > max {
		rows = max
	}
	if rows < 1 {
		rows = 1
	}
	f.body.ResizeItem(f.context, rows, 0)
}

func (f *questionForm) buildClarifyField() *tview.InputField {
	field := tview.NewInputField()
	field.SetLabel("› ")
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
	field.SetAcceptanceFunc(func(text string, _ rune) bool {
		return utf8.RuneCountInString(text) <= maxClarificationRunes
	})
	field.SetFocusFunc(func() { f.trackFocus(field) })
	field.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			f.app.submitQuestionForm()
		}
	})
	field.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyCtrlS:
			f.app.submitQuestionForm()
			return nil
		case tcell.KeyUp:
			f.focusPrev(field)
			return nil
		case tcell.KeyDown, tcell.KeyTab:
			f.focusNext(field)
			return nil
		}
		return ev
	})
	return field
}

func (f *questionForm) toggleClarify() {
	f.clarifyOn = !f.clarifyOn
	height := 0
	if f.clarifyOn {
		height = 1
	} else {
		f.clarifyField.SetText("")
	}
	f.body.ResizeItem(f.clarifyField, height, 0)
	if f.clarifyOn {
		f.focus(f.clarifyField)
	}
}

func (f *questionForm) clarification() string {
	if !f.clarifyOn {
		return ""
	}
	return strings.TrimSpace(f.clarifyField.GetText())
}

// questionOverlay makes the mounted form modal to the mouse. A list acts on the click
// action, not the button-down that precedes it, so an unconsumed down would fall through
// the overlay page to the input area underneath, which takes focus and captures the rest
// of the gesture — the click would then never reach the option row it landed on.
type questionOverlay struct {
	*tview.Flex
	form *questionForm
}

// The context/question split depends on the rect the form actually got, which build cannot see.
func (o *questionOverlay) Draw(screen tcell.Screen) {
	_, _, width, height := o.GetInnerRect()
	o.form.sizeContext(width, height)
	o.Flex.Draw(screen)
}

func (o *questionOverlay) MouseHandler() func(tview.MouseAction, *tcell.EventMouse, func(tview.Primitive)) (bool, tview.Primitive) {
	return func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(tview.Primitive)) (bool, tview.Primitive) {
		// tview reports the second of two quick clicks as a double click wherever it
		// lands, and lists and buttons act only on a plain click, so every click inside
		// the form has to arrive as one or a fast user's second choice is dropped. The flag
		// carries what the rewrite would otherwise erase: whether a row is being asked to
		// act twice within the double-click interval (see actOnClick).
		click := action == tview.MouseLeftClick || action == tview.MouseLeftDoubleClick
		if action == tview.MouseLeftDoubleClick {
			action = tview.MouseLeftClick
			o.form.repeatClick = true
		}
		if click {
			o.form.thisClick = questionRow{}
		}
		consumed, capture := o.Flex.MouseHandler()(action, event, setFocus)
		o.form.repeatClick = false
		if click {
			// Whatever this click chose — a row, or nothing, because it went to a button, a
			// custom field or blank space — is what the next click can repeat. Carrying a row
			// across an intervening click would suppress a later genuine click on it, since
			// tview keeps classifying by time no matter what was clicked in between.
			o.form.lastClick = o.form.thisClick
		}
		if consumed {
			return consumed, capture
		}
		return o.InRect(event.Position()), nil
	}
}

// buttonRow sizes each button to its label's terminal width, which a multi-byte label such
// as "‹ Prev" is not the byte length of.
func buttonRow(left *tview.Button, leftLabel string, right *tview.Button, rightLabel string) *tview.Flex {
	row := tview.NewFlex()
	row.AddItem(left, tview.TaggedStringWidth(leftLabel)+2, 0, false)
	row.AddItem(nil, 1, 0, false)
	row.AddItem(right, tview.TaggedStringWidth(rightLabel)+2, 0, false)
	row.AddItem(nil, 0, 1, false)
	return row
}

// showAdjacent moves the shown question, which is the mouse's only route to another
// question: the keyboard focus ring reaches them all, but a pointer can only act on what
// is currently drawn. It wraps, so neither control is ever a dead button.
func (f *questionForm) showAdjacent(delta int) {
	index := f.focusedIndex()
	if index < 0 {
		index = 0
	}
	f.focus(f.blocks[(index+delta+len(f.blocks))%len(f.blocks)].options)
}

func (f *questionForm) button(label string, activate func()) *tview.Button {
	b := tview.NewButton(label)
	// Reverse video rather than tview's snapshot of its own focus colors: applyTheme makes
	// both the primary and contrast backgrounds the terminal's own, while the button keeps a
	// fixed blue foreground for its focused state, so on a blue-foreground terminal the
	// focused button is indistinguishable from the others and Enter has no visible target.
	b.SetActivatedStyle(tcell.StyleDefault.Reverse(true))
	b.SetSelectedFunc(activate)
	b.SetFocusFunc(func() { f.trackFocus(b) })
	b.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyTab, tcell.KeyRight, tcell.KeyDown:
			f.focusNext(b)
			return nil
		case tcell.KeyLeft, tcell.KeyUp:
			f.focusPrev(b)
			return nil
		case tcell.KeyCtrlS:
			f.app.submitQuestionForm()
			return nil
		}
		return ev
	})
	return b
}

func newQuestionBlock(f *questionForm, spec QuestionSpec) *questionBlock {
	b := &questionBlock{spec: spec, form: f, chosen: make([]bool, len(spec.Options))}

	b.options = newQuestionOptions(b)
	b.options.SetFocusFunc(func() {
		b.options.focused = true
		f.trackFocus(b.options)
	})
	b.options.SetBlurFunc(func() {
		b.options.focused = false
		f.stage.invalidate()
	})
	b.options.SetInputCapture(b.handleListKey)

	b.flex = tview.NewFlex().SetDirection(tview.FlexRow)
	b.flex.AddItem(b.options, 0, 1, true)
	if spec.AllowCustom {
		b.field = tview.NewInputField()
		b.field.SetLabel("\u203a ")
		// No accent on the label — inherit the terminal default instead of tview's built-in
		// yellow, which is unreadable on a light terminal background.
		b.field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
		b.field.SetChangedFunc(func(text string) { b.customText = text })
		b.field.SetFocusFunc(func() { f.trackFocus(b.field) })
		b.field.SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter || key == tcell.KeyTab {
				f.focusNext(b.field)
			}
		})
		b.field.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			switch ev.Key() {
			case tcell.KeyCtrlS:
				f.app.submitQuestionForm()
				return nil
			case tcell.KeyUp:
				f.focusPrev(b.field)
				return nil
			case tcell.KeyDown:
				f.focusNext(b.field)
				return nil
			}
			return ev
		})
		b.flex.AddItem(b.field, 0, 0, false)
	}
	b.options.render(0)
	return b
}

func (b *questionBlock) handleListKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyTab, tcell.KeyRight:
		b.form.focusNext(b.options)
		return nil
	case tcell.KeyLeft:
		b.form.focusPrev(b.options)
		return nil
	case tcell.KeyCtrlS:
		b.form.app.submitQuestionForm()
		return nil
	case tcell.KeyUp:
		b.options.move(-1)
		return nil
	case tcell.KeyDown:
		b.options.move(1)
		return nil
	case tcell.KeyEnter:
		b.choose(b.options.current)
		return nil
	case tcell.KeyPgUp:
		b.options.scrollPage(-1)
		return nil
	case tcell.KeyPgDn:
		b.options.scrollPage(1)
		return nil
	}
	return ev
}

func (b *questionBlock) choose(index int) {
	b.form.focused = b
	custom := b.spec.AllowCustom && index == len(b.spec.Options)
	switch {
	case custom && b.customOn:
		b.customOn = false
		b.customText = ""
		if b.field != nil {
			b.field.SetText("")
		}
	case custom:
		b.customOn = true
		if !b.spec.MultiSelect {
			b.clearOptions()
		}
	case b.spec.MultiSelect:
		b.chosen[index] = !b.chosen[index]
	default:
		b.clearOptions()
		b.chosen[index] = true
		b.customOn = false
		b.customText = ""
		if b.field != nil {
			b.field.SetText("")
		}
	}
	b.options.render(b.options.width)
	if b.field != nil {
		height := 0
		if b.customOn {
			height = 1
		}
		b.flex.ResizeItem(b.field, height, 0)
		if b.form.stage != nil {
			b.form.stage.invalidate()
		}
		if b.customOn {
			b.form.focus(b.field)
		}
	}
}

func (b *questionBlock) clearOptions() {
	for i := range b.chosen {
		b.chosen[i] = false
	}
}

func (b *questionBlock) answer() QuestionAnswer {
	selected := []string{}
	for i, option := range b.spec.Options {
		if b.chosen[i] {
			selected = append(selected, option)
		}
	}
	custom := ""
	if b.customOn {
		custom = strings.TrimSpace(b.customText)
	}
	return QuestionAnswer{ID: b.spec.ID, Prompt: b.spec.Prompt, Selected: selected, Custom: custom}
}

func (b *questionBlock) mark(on bool) string {
	if b.spec.MultiSelect {
		if on {
			return multiChosenMark
		}
		return multiOpenMark
	}
	if on {
		return singleChosenMark
	}
	return singleOpenMark
}

// layout sizes the block for the given width, capped to max rows. Capping shortens the
// scrollable region rather than dropping content: every prompt line and option row stays
// reachable inside it, so a question too tall for the terminal loses nothing.
func (b *questionBlock) layout(width, max int) int {
	b.options.render(width)
	rows := b.options.contentHeight()
	fieldHeight := 0
	if b.field != nil && b.customOn {
		fieldHeight = 1
	}
	if max > 0 && rows+fieldHeight > max {
		if rows = max - fieldHeight; rows < 1 {
			rows = 1
		}
	}
	b.flex.ResizeItem(b.options, rows, 0)
	if b.field != nil {
		b.flex.ResizeItem(b.field, fieldHeight, 0)
	}
	// Deliberately not ensureVisible: layout runs on every relayout, including a focus
	// change or a resize, and pulling the view back to the current option there would
	// silently undo a scroll the user just made with the wheel. Moving the cursor is what
	// pulls the view, and that already calls it.
	return rows + fieldHeight
}

func (f *questionForm) focusRing() []tview.Primitive {
	ring := make([]tview.Primitive, 0, 2*len(f.blocks)+5)
	if f.context != nil {
		ring = append(ring, f.context)
	}
	for _, b := range f.blocks {
		ring = append(ring, b.options)
		if b.field != nil && b.customOn {
			ring = append(ring, b.field)
		}
	}
	ring = append(ring, f.clarify)
	if f.clarifyOn {
		ring = append(ring, f.clarifyField)
	}
	return append(ring, f.submit, f.cancel)
}

func (f *questionForm) focusNext(from tview.Primitive) { f.focusStep(from, 1) }
func (f *questionForm) focusPrev(from tview.Primitive) { f.focusStep(from, -1) }

func (f *questionForm) focusStep(from tview.Primitive, delta int) {
	ring := f.focusRing()
	for i, p := range ring {
		if p != from {
			continue
		}
		next := (i + delta + len(ring)) % len(ring)
		f.focus(ring[next])
		return
	}
	f.focus(ring[0])
}

func (f *questionForm) focus(p tview.Primitive) { f.app.app.SetFocus(p) }

// trackFocus records the primitive tview has just focused; the question that owns it
// becomes the one shown. It is registered as each control's focus callback rather than
// run from focus above, because a mouse click focuses a control through tview directly —
// the form would otherwise believe the first question still held the keyboard when
// terminal-focus repair asked it. It must never call SetFocus: tview invokes it from
// inside that call.
func (f *questionForm) trackFocus(p tview.Primitive) {
	f.active = p
	for _, b := range f.blocks {
		if p != tview.Primitive(b.options) && p != tview.Primitive(b.field) {
			continue
		}
		if b != f.focused {
			// The question being left is not re-rendered, so render's own invalidation never
			// runs for it and a held drag would keep copying from its source map.
			f.app.discardQuestionDrag()
		}
		f.focused = b
		f.stage.invalidate()
		return
	}
}

func (f *questionForm) focusedIndex() int {
	for i, b := range f.blocks {
		if b == f.focused {
			return i
		}
	}
	return -1
}

func (f *questionForm) position() string {
	index := f.focusedIndex()
	if index < 0 {
		index = 0
	}
	return fmt.Sprintf("Question %d of %d", index+1, len(f.blocks))
}

func (f *questionForm) owns(p tview.Primitive) bool {
	if p == nil {
		return false
	}
	for _, b := range f.blocks {
		if p == tview.Primitive(b.options) || (b.field != nil && p == tview.Primitive(b.field)) {
			return true
		}
	}
	if f.context != nil && p == tview.Primitive(f.context) {
		return true
	}
	return p == tview.Primitive(f.prev) || p == tview.Primitive(f.next) ||
		p == tview.Primitive(f.clarify) || p == tview.Primitive(f.clarifyField) ||
		p == tview.Primitive(f.submit) || p == tview.Primitive(f.cancel)
}

// restoreFocus pulls keyboard focus back onto the form after a terminal blur/return
// left it on a primitive underneath, where the mounted form would no longer be modal.
func (f *questionForm) restoreFocus() {
	if current := f.app.app.GetFocus(); f.owns(current) {
		f.active = current
		return
	}
	if !f.owns(f.active) {
		f.active = f.blocks[0].options
	}
	f.focus(f.active)
}

// An open but empty clarification entry deliberately falls through to the answers: submitting
// it must neither ask the model nothing nor leave Submit as a dead button.
func (f *questionForm) result() QuestionResult {
	if text := f.clarification(); text != "" {
		return QuestionResult{Clarification: text}
	}
	answers := make([]QuestionAnswer, 0, len(f.blocks))
	for _, b := range f.blocks {
		answers = append(answers, b.answer())
	}
	return QuestionResult{Answers: answers}
}

func (a *App) submitQuestionForm() {
	if !a.questionFormOpen || a.questionForm == nil {
		return
	}
	a.finishQuestionForm(a.questionForm.result(), true)
}

func (a *App) cancelQuestionForm() {
	if !a.questionFormOpen || a.questionForm == nil {
		return
	}
	a.finishQuestionForm(QuestionResult{Answers: []QuestionAnswer{}, Cancelled: true}, true)
}

func (a *App) finishQuestionForm(res QuestionResult, deliver bool) {
	form := a.questionForm
	if !a.questionFormOpen || form == nil {
		return
	}
	a.questionFormOpen = false
	a.questionForm = nil
	a.discardQuestionDrag()
	a.closeOverlayPage(questionFormPage, &a.questionFormPrev)
	if deliver {
		a.commitQuestionRecord(res)
		form.resultCh <- res
	}
}

// Every finishQuestionForm caller is already on the event-loop goroutine, so this cannot go
// through App.FinalizeStream, which marshals into that same loop and would deadlock; a
// separately queued finalize could not keep the seal and the append in one ordered step. The
// seal is required because ask_user no longer reaches AppendToolActivity, which used to
// commit the pre-call prose before the form ran, and it happens for every delivered result:
// a dismissed form still continues the model turn, so the pre-call prose must not absorb
// whatever the model says next even though the dismissal records no answer.
func (a *App) commitQuestionRecord(res QuestionResult) {
	a.invalidateStreamRender()
	a.transcript.finalize()
	if block := questionRecordBlock(res); block != "" {
		a.transcript.append(block)
	}
}

func (a *App) QuestionFormOpen() bool { return a.questionFormOpen }

func (a *App) AwaitQuestionFormForTest(timeout time.Duration) bool {
	select {
	case <-a.questionFormMounts:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (a *App) AnswerQuestionForTest(question, option int) bool {
	b, ok := a.questionBlockForTest(question)
	if !ok || option < 0 || option >= b.options.GetItemCount() {
		return false
	}
	b.choose(option)
	return true
}

func (a *App) AnswerQuestionCustomForTest(question int, text string) bool {
	b, ok := a.questionBlockForTest(question)
	if !ok || b.field == nil {
		return false
	}
	if !b.customOn {
		b.choose(len(b.spec.Options))
	}
	b.field.SetText(text)
	return true
}

func (a *App) QuestionContextForTest() string {
	if !a.questionFormOpen || a.questionForm == nil || a.questionForm.context == nil {
		return ""
	}
	return a.questionForm.context.GetText(true)
}

func (a *App) AskClarificationForTest(text string) bool {
	if !a.questionFormOpen || a.questionForm == nil {
		return false
	}
	form := a.questionForm
	if !form.clarifyOn {
		form.toggleClarify()
	}
	form.clarifyField.SetText(text)
	return true
}

func (a *App) SubmitQuestionFormForTest() { a.submitQuestionForm() }

func (a *App) questionBlockForTest(question int) (*questionBlock, bool) {
	if !a.questionFormOpen || a.questionForm == nil {
		return nil, false
	}
	if question < 0 || question >= len(a.questionForm.blocks) {
		return nil, false
	}
	return a.questionForm.blocks[question], true
}
