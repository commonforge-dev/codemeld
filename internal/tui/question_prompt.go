package tui

import (
	"context"
	"encoding/json"
	"errors"
	"time"

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
	ID                 string
	Prompt             string
	Context            string
	Options            []string
	OptionDescriptions []string
	MultiSelect        bool
	AllowCustom        bool
}

type QuestionRequest struct {
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
	contextRow   *tview.Flex
	buttons      *tview.Flex
	hint         *tview.TextView
	prev         *tview.Button
	next         *tview.Button
	clarify      *tview.Button
	clarifyField *tview.InputField
	submit       *tview.Button
	cancel       *tview.Button
	resultCh     chan QuestionResult

	clarifyOn     bool
	contextShown  bool
	contextText   string
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
	if !a.questionFormOpen || a.questionForm == nil || !a.questionForm.contextShown {
		return ""
	}
	return a.questionForm.focused.spec.Context
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
