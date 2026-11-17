package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/provider"
)

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

	f.buttons = buttonRow(f.submit, "Submit", f.cancel, "Cancel")

	f.hint = tview.NewTextView()
	f.hint.SetDynamicColors(false)
	f.hint.SetText("↑↓ move · enter choose · tab or → next · ← prev · pgup/pgdn scroll · wheel scroll · ctrl-s submit · esc cancel")

	f.body = tview.NewFlex().SetDirection(tview.FlexRow)
	for _, b := range f.blocks {
		if b.spec.Context != "" {
			f.context = f.buildContext()
			f.contextRow = tview.NewFlex().AddItem(nil, 1, 0, false).AddItem(f.context, 0, 1, false)
			break
		}
	}
	f.body.SetBorder(true)
	f.body.SetTitle(" questions ")
	f.focused = f.blocks[0]
	f.active = f.blocks[0].options
	f.showContext()
	return &questionOverlay{Flex: f.body, form: f}, f.active
}

// fillBody rebuilds the form's rows because a tview.Flex can only append, and the context
// section has to sit above the stage when it is shown and be out of the flex when it is not.
func (f *questionForm) fillBody() {
	f.body.Clear()
	if f.contextShown {
		f.body.AddItem(f.contextRow, 1, 0, false)
		f.body.AddItem(nil, 1, 0, false)
	}
	clarifyHeight := 0
	if f.clarifyOn {
		clarifyHeight = 1
	}
	f.body.AddItem(f.stage, 0, 1, true)
	f.body.AddItem(f.clarify, 1, 0, false)
	f.body.AddItem(f.clarifyField, clarifyHeight, 0, false)
	f.body.AddItem(f.buttons, 1, 0, false)
	f.body.AddItem(f.hint, 1, 0, false)
}

// showContext must not call SetFocus when reached from trackFocus, which tview runs inside
// SetFocus; there the newly focused primitive is never the context view, so the repair below
// cannot fire.
func (f *questionForm) showContext() {
	if f.context == nil {
		f.fillBody()
		return
	}
	f.contextText = contextParagraphs(f.focused.spec.Context)
	f.contextShown = f.contextText != ""
	f.context.SetText(f.contextText)
	f.context.ScrollToBeginning()
	f.contextWidth, f.contextHeight = 0, 0
	f.fillBody()
	if f.contextShown {
		return
	}
	if f.active == tview.Primitive(f.context) {
		f.active = f.focused.options
	}
	if f.app.app.GetFocus() == tview.Primitive(f.context) {
		f.focus(f.focused.options)
	}
}

func contextParagraphs(context string) string {
	var paragraphs []string
	for _, piece := range strings.Split(context, "\n") {
		if provider.AskUserTextRenderable(piece) {
			paragraphs = append(paragraphs, piece)
		}
	}
	return strings.Join(paragraphs, "\n\n")
}

// Dynamic colors stay off so provider text renders literally without an escaping pass.
func (f *questionForm) buildContext() *tview.TextView {
	view := tview.NewTextView()
	view.SetDynamicColors(false)
	view.SetWrap(true)
	view.SetWordWrap(true)
	view.SetScrollable(true)
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
	if !f.contextShown || width <= 0 || (width == f.contextWidth && height == f.contextHeight) {
		return
	}
	f.contextWidth, f.contextHeight = width, height
	viewWidth := max(min(width-1, 100), 1)
	rows := len(tview.WordWrap(f.contextText, viewWidth))
	if limit := height / 3; rows > limit {
		rows = limit
	}
	if rows < 1 {
		rows = 1
	}
	f.contextRow.ResizeItem(f.context, viewWidth, 0)
	f.body.ResizeItem(f.contextRow, rows, 0)
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

func (f *questionForm) focusRing() []tview.Primitive {
	ring := make([]tview.Primitive, 0, 2*len(f.blocks)+5)
	if f.contextShown {
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
			f.focused = b
			f.showContext()
		}
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
	if f.contextShown && p == tview.Primitive(f.context) {
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
