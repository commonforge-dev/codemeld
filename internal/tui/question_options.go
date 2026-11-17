package tui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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

func (o *questionOptions) description(index int) string {
	if index < len(o.block.spec.OptionDescriptions) {
		return o.block.spec.OptionDescriptions[index]
	}
	return ""
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
		text.WriteString("[::b]" + line + "[::-]\n")
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
		if description := o.description(i); description != "" {
			descLines, descOffsets := wrapSource(description, body)
			for j, line := range descLines {
				text.WriteString(strings.Repeat(" ", questionRowMarkWidth) + "[::d]" + line + "[::-]\n")
				o.owner = append(o.owner, i)
				o.offsets = append(o.offsets, len(label)+1+descOffsets[j])
			}
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
	if b.form.focused != b {
		b.form.focused = b
		b.form.showContext()
	}
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
