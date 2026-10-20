package tui

import (
	"strings"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// questionSelection is one physical left-drag over the shown question's options view. It
// lives on the app rather than on the view or the form because the app has to keep
// answering the gesture's move, release and click-class action after a re-render has
// dropped the row map the highlight was built from — or after the form itself has closed.
type questionSelection struct {
	options *questionOptions
	owned   bool
	moved   bool
	stale   bool
	// dropped says the surface the gesture started over went out from under it: the form
	// closed, the shown question changed, or a re-render replaced the rows the press landed
	// on. The gesture is still physically in progress, so its release and the click-class
	// action that follows are consumed rather than handed to whatever it uncovered.
	dropped  bool
	suppress bool
}

// questionDrag is the app's own drag slot rather than the form's: a form closed mid-gesture
// must still answer the move, the release and the click-class action that follow, so the
// gesture outlives the form it started over.
func (a *App) questionDrag() *questionSelection {
	if a.questionFormOpen && a.questionForm != nil {
		return &a.questionSel
	}
	if a.questionSel.owned || a.questionSel.suppress {
		return &a.questionSel
	}
	return nil
}

// discardQuestionDrag is the first half of the two-stage invalidation used when the form
// closes or the shown question changes: the source map the highlight was built from goes
// away at once, while the gesture keeps its ownership.
func (a *App) discardQuestionDrag() {
	d := &a.questionSel
	if d.options != nil {
		d.options.sel.clearSelection()
	}
	d.options = nil
	if d.owned {
		d.stale, d.dropped = true, true
	}
}

// questionDragTarget is the shown question's options view: the stage places one question
// at a time, so it is the only one a pointer can reach.
func (a *App) questionDragTarget() *questionOptions {
	f := a.questionForm
	if f == nil {
		return nil
	}
	block := f.focused
	if f.stage != nil && f.stage.shown != nil {
		block = f.stage.shown
	}
	if block == nil {
		return nil
	}
	return block.options
}

func (d *questionSelection) begin(o *questionOptions, x, y int) bool {
	if o == nil || !o.InRect(x, y) {
		return false
	}
	d.options, d.owned, d.moved, d.stale, d.dropped = o, true, false, false, false
	o.sel.beginSelect(o.TextView, x, y)
	return true
}

// move is a pointer motion during the gesture; extend is the same extension without that
// verdict, which the release takes so that a press and release on one cell stays a click.
func (d *questionSelection) move(x, y int) {
	d.moved = true
	d.extend(x, y)
}

func (d *questionSelection) extend(x, y int) {
	if d.stale || d.options == nil {
		return
	}
	d.options.sel.updateSelect(d.options.TextView, x, y)
}

// finish ends the gesture and reports whether it consumed the release — a pointer that
// moved made a selection rather than a row-choosing click, and a gesture whose surface went
// away under it has nothing left to click. The release position cannot separate them: a
// same-event move consumes the event, so the release often carries no position.
func (d *questionSelection) finish() (bool, string) {
	o, moved, stale, dropped := d.options, d.moved, d.stale, d.dropped
	d.options, d.owned, d.moved, d.stale, d.dropped = nil, false, false, false, false
	text := ""
	if moved || dropped {
		d.suppress = true
		if moved && o != nil && !stale {
			text = o.selectedSource()
		}
	}
	if o != nil {
		o.sel.clearSelection()
	}
	return moved || dropped, text
}

func (o *questionOptions) Draw(screen tcell.Screen) {
	o.TextView.Draw(screen)
	o.sel.paint(o.TextView, screen)
}

// invalidateSelection drops the highlight and drops a drag in flight, so a rebuild between
// the press and the release copies nothing and chooses nothing while the app still owns the
// rest of the gesture. Stale and dropped are set together on purpose: the rows the press
// landed on are gone either way, so a gesture that never moved must not fall through to the
// rebuilt rows as an ordinary click.
func (o *questionOptions) invalidateSelection() {
	o.sel.clearSelection()
	if o.block == nil || o.block.form == nil || o.block.form.app == nil {
		return
	}
	d := &o.block.form.app.questionSel
	if !d.owned {
		return
	}
	d.stale, d.dropped = true, true
	if d.options != nil {
		d.options.sel.clearSelection()
	}
}

// questionOptions turns tview's own wrapping off and writes the wrapped rows itself, so
// the rows a selection maps through are those lines rather than a second wrap at the
// view's width.
func hardRows(text string, _ int) []rowSpan {
	rows := make([]rowSpan, 0, strings.Count(text, "\n")+1)
	for start := 0; ; {
		i := strings.IndexByte(text[start:], '\n')
		if i < 0 {
			return append(rows, rowSpan{start: start, end: len(text)})
		}
		rows = append(rows, rowSpan{start: start, end: start + i})
		start += i + 1
	}
}

// wrapSource escapes src, wraps it the way the view draws it, and reports the byte offset
// in src at which each rendered line begins. The offsets are carried through the escaping
// rather than searched for: a wrap can put the "[" tview.Escape inserted on one line and
// its "]" on the next, and such a fragment un-escapes to something that is no substring of
// the source at all, so a search for it finds nothing and the row keeps a stale offset.
func wrapSource(src string, width int) ([]string, []int) {
	esc := tview.Escape(src)
	lines := tview.WordWrap(esc, width)
	srcAt := escapedToSource(src, esc)
	offsets := make([]int, len(lines))
	pos := 0
	for i, line := range lines {
		if pos > len(esc) {
			pos = len(esc)
		}
		offsets[i] = snapToRune(src, srcAt[pos])
		pos += len(line)
		// WordWrap drops the line break at a hard split; the escaped text still holds it,
		// and a break is at most one "\r\n" pair because either byte ends the line itself.
		if pos < len(esc) && esc[pos] == '\r' {
			pos++
		}
		if pos < len(esc) && esc[pos] == '\n' {
			pos++
		}
	}
	return lines, offsets
}

// escapedToSource maps every byte offset in tview.Escape(src) back onto src. Escape only
// ever inserts a "[" ahead of a "]" and never deletes or reorders, so a left-to-right walk
// that advances in src only on a byte match is exact: an inserted "[" can never be mistaken
// for a source byte, because the source byte it stands before is always "]".
func escapedToSource(src, esc string) []int {
	at := make([]int, len(esc)+1)
	i := 0
	for j := 0; j < len(esc); j++ {
		at[j] = i
		if i < len(src) && esc[j] == src[i] {
			i++
		}
	}
	at[len(esc)] = i
	return at
}

func (o *questionOptions) sourceOf(item int) string {
	if item < 0 {
		return o.block.spec.Prompt
	}
	if description := o.description(item); description != "" {
		return o.label(item) + "\n" + description
	}
	return o.label(item)
}

type sourceSpan struct {
	item       int
	start, end int
}

// selectedSource projects the highlighted display range back through owner/offsets onto
// the prompt and label strings the question was built from. Slicing the view's own text
// instead would copy the row marks, the continuation padding and every wrap-inserted
// newline.
func (o *questionOptions) selectedSource() string {
	start, end := o.sel.selStart, o.sel.selEnd
	if start >= end {
		return ""
	}
	text := o.GetText(true)
	if end > len(text) {
		return ""
	}
	rows := hardRows(text, 0)
	if len(rows) != len(o.owner) || len(rows) != len(o.offsets) {
		return ""
	}

	var spans []sourceSpan
	for i, row := range rows {
		lo, hi := start, end
		if lo < row.start {
			lo = row.start
		}
		if hi > row.end {
			hi = row.end
		}
		if lo > hi {
			continue
		}
		item := o.owner[i]
		body := row.start
		if item >= 0 {
			body += questionRowMarkWidth
		}
		src := o.sourceOf(item)
		s := snapToRune(src, clampLen(o.offsets[i]+pastPrefix(lo, body), len(src)))
		e := snapToRune(src, clampLen(o.offsets[i]+pastPrefix(hi, body), len(src)))
		if e < s {
			e = s
		}
		// Rows of one item extend a single span rather than joining as text: the source
		// slice between the first and last row already carries whatever newline of its own
		// sits at the break, and carries nothing at all where the break was wrap-inserted.
		if n := len(spans); n > 0 && spans[n-1].item == item {
			if e > spans[n-1].end {
				spans[n-1].end = e
			}
			continue
		}
		spans = append(spans, sourceSpan{item: item, start: s, end: e})
	}

	// Every span is joined, including an empty one: a row the range meets at exactly one
	// edge contributes no source bytes, but its owner is still inside the selection and the
	// join is what turns each owner boundary into its single separator.
	parts := make([]string, 0, len(spans))
	for _, span := range spans {
		parts = append(parts, o.sourceOf(span.item)[span.start:span.end])
	}
	return strings.Join(parts, "\n")
}

// snapToRune is the last guarantee that a copied slice is valid UTF-8: a display column
// resolves to a rune boundary in the *drawn* row, and a row whose escaped tag was split
// across a wrap is one byte away from that boundary in the source.
func snapToRune(src string, off int) int {
	for off > 0 && off < len(src) && !utf8.RuneStart(src[off]) {
		off--
	}
	return off
}

func pastPrefix(off, body int) int {
	if off <= body {
		return 0
	}
	return off - body
}

func clampLen(off, length int) int {
	if off > length {
		return length
	}
	if off < 0 {
		return 0
	}
	return off
}
