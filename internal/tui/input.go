// Input area: the multi-line prompt (a tview.TextArea), its "› " label and
// borderless top/bottom-rule chrome, and a cursor accessor Tab slash-name
// completion reads as a rune offset into the buffer.
package tui

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

// promptLabel is the input's "› " prompt label (U+203A). tview draws it on the
// first text row only but subtracts its width from every text row before laying text out,
// so wrappedRows reduces the text width by it for continuation rows too. The
// glyph is two cells wide ("› " = the chevron plus a space), unchanged from the prior
// "> ", so the wrapped-row width math is unaffected by the restyle.
const promptLabel = "› "

// inputField wraps tview.TextArea as the multi-line prompt input, adapting only the API the
// rest of the app calls: a single-argument SetText, a rune-offset Cursor accessor for Tab
// slash-name completion, a newline insert, and a logical-line edge test for ↑/↓ history.
type inputField struct {
	*tview.TextArea
	// pasting is true only while a bracketed paste is being applied to the buffer, so the
	// '@' file-reference trigger (App.onInputChanged) can skip a paste-originated change. A
	// pasted lone '@' inserts the same one byte as a typed '@', so the buffer delta alone
	// cannot tell them apart; this flag marks the paste so the picker never opens on a paste,
	// which the file-reference contract forbids. PasteHandler sets it across exactly the paste insert.
	pasting bool

	// osc52 is the sink the Ctrl-Q/Ctrl-X copy path writes the OSC 52
	// system-clipboard escape sequence to. newInput installs a TTY-gated os.Stdout
	// writer (so the sequence reaches the terminal — and over SSH the local
	// clipboard — only when stdout is a real terminal); tests inject a fake to
	// capture the emitted bytes. Caveat: this write happens from the input widget's
	// copy callback rather than through the normal tview draw path, so the escape
	// sequence is emitted mid-frame; terminals tolerate an interleaved OSC 52 and it
	// carries no on-screen cells, so it does not corrupt the rendered frame. The
	// returned error covers only what emitting can detect; whether the terminal then
	// accepted the sequence is unobservable, because OSC 52 has no acknowledgement.
	osc52 func(string) error
	// lastCopied holds the text of the most recent Ctrl-Q/Ctrl-X copy. It backs
	// tview's clipboard paste callback (pasteFromClipboard) because OSC 52 read-back is
	// unreliable across terminals/SSH: the copy contract is intentionally asymmetric —
	// write the system clipboard via OSC 52, but read back the last copy from memory.
	// Note this last-copy text is no longer reachable via Ctrl-V in production:
	// app-level Ctrl-V is captured by handleGlobalKey for image paste, so the
	// buffer is retained only for tview's clipboard callback/legacy copy internals.
	lastCopied string

	// pastes holds collapsed bracketed-paste segments: each pins the exact buffer byte
	// range of one "[Pasted N lines]" placeholder token to the full text it stands in
	// for. A long bracketed paste inserts only its placeholder into the buffer (so the
	// input box does not grow or scroll the draft off-screen) while the real text is
	// retained here and substituted back at submission (expandedText). Only the specific
	// occurrence PasteHandler inserts is tracked — by range, not by string — so a
	// user-typed literal "[Pasted N lines]" elsewhere in the buffer is never treated as
	// hidden paste text. reconcilePasteRanges keeps each range pinned to its placeholder
	// across ordinary edits and drops a segment whose placeholder is edited or deleted, so
	// stale hidden text is never submitted.
	pastes []pasteSegment
	// prevText is the buffer as of the last change reconcilePasteRanges processed; the
	// next change diffs against it to shift or drop tracked paste ranges.
	prevText string
	// onChanged is the app-installed change handler (App.onInputChanged). newInput wires
	// the TextArea's single change callback to an internal wrapper that reconciles paste
	// ranges first and then invokes this, so range tracking runs even in tests that never
	// install an app handler.
	onChanged func()

	// images holds the prompt's pending image attachments as editable buffer tokens:
	// each pins the exact byte range of one "[Image N]" / "[<basename>]"
	// placeholder to the imageAttachment it stands for, exactly as pastes pins a collapsed
	// paste. An attachment is added by the '@' picker, a pasted image path, or a CTRL-V
	// clipboard read — all through addAttachment, which inserts the token and appends the
	// segment. The shared change-hook pass (reconcileSegments) keeps each range pinned and
	// drops a segment — and thus its attachment — when its token is edited or deleted, so
	// backspacing the token removes the image. At submit each surviving token is stripped
	// from the prompt text and yields one image_url content part (submitText). Like paste
	// segments, they are cleared on every whole-buffer replace (SetText: accepted submit,
	// ESC/CTRL-C clear, history recall) because the draft they belonged to is gone; a
	// rejected submit and a failed pre-turn flush do not call SetText, so they survive a
	// retry. Typed (Enter-validated) paths are ordinary text and never tokenized.
	images []imageSegment
	// clipboardCounter is the per-prompt monotonic source of the N in a clipboard image's
	// "[Image N]" token. It increments on each clipboard attachment and never
	// renumbers survivors when an earlier token is deleted, so the labels a user sees stay
	// stable; SetText resets it to 0 alongside clearing images, so each fresh draft counts
	// from 1.
	clipboardCounter int
	// onPaste observes the visible range inserted by a short bracketed paste so the app
	// can promote pasted image paths to pending attachments immediately. Long collapsed
	// pastes keep their placeholder behavior and are not image-reference input.
	onPaste func(text string, start, end int)

	// accent is the run-scoped input color override: when accented is true, the
	// prompt "› " glyph and both horizontal rules draw in this tcell color instead of their
	// defaults (teal glyph, terminal-default rules); when false the field renders the fresh
	// terminal appearance. It is set only through applyAccent, is not persisted, and is not
	// carried across --resume — a fresh inputField starts unaccented. accented is a separate
	// flag because tcell.Color's zero value is itself a real color, so it cannot double as
	// "no accent".
	accent   tcell.Color
	accented bool

	// ghost is the raw follow-up suggestion label currently offered as dim ghost text in
	// the empty input, or "" when none is pending. It is rendered through
	// tview.TextArea's native placeholder (drawn only while the buffer is empty, after the
	// "› " label) with a "⇥ Tab: " prefix and a dim style; the field retains the unprefixed
	// label so ghostText() can report it without re-parsing the placeholder. Any buffer
	// change clears it (newInput's change wrapper), so a typed/accepted/cleared buffer never
	// leaves stale ghost text.
	ghost     string
	queueHint string

	// sessionMu guards sessionTitle because App.refreshSessionBadge writes it while the
	// draw func reads it on the tview goroutine.
	sessionMu    sync.RWMutex
	sessionTitle string
}

type inputDraft struct {
	text             string
	pastes           []pasteSegment
	images           []imageSegment
	clipboardCounter int
}

// newInput uses custom drawing because tview.Box can only draw a four-sided border, while
// this input needs top and bottom rules with its text between them. Its wrapped-row height
// grows with each visual line so App.inputRows reflows the input with the terminal width.
func newInput() *inputField {
	in := tview.NewTextArea()
	field := &inputField{TextArea: in}
	in.SetLabel(promptLabel)
	in.SetLabelStyle(tcell.StyleDefault.Foreground(promptLabelColor).Background(tcell.ColorDefault))
	in.SetBorder(false)
	// Word wrap is tview's default, but set both flags explicitly so the height math
	// (App.inputRows, which counts wrapped rows) cannot silently disagree with the
	// widget if a future tview default changes. SetWrap breaks long lines
	// onto continuation rows; SetWordWrap prefers space/line-break opportunities.
	in.SetWrap(true)
	in.SetWordWrap(true)
	in.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		if width < 1 || height < 2 {
			return x, y, width, height
		}
		rule := field.ruleStyle()
		for col := x; col < x+width; col++ {
			screen.SetContent(col, y, tcell.RuneHLine, nil, rule)
			screen.SetContent(col, y+height-1, tcell.RuneHLine, nil, rule)
		}
		if badge := fitSessionBadge(field.sessionName(), width); badge != "" {
			tview.Print(screen, tview.Escape(badge), x, y, width-sessionBadgeRightMargin, tview.AlignRight, field.labelColor())
		}
		// Inner rect is the rows between the two rules, so the prompt + text land
		// between them rather than under the top one.
		return x, y + 1, width, height - 2
	})
	// Style the follow-up suggestion ghost text: a dim grey foreground over
	// the terminal-default background. SetPlaceholder (set per-suggestion in SetGhostText)
	// supplies the text; this fixes its style once. drawPlaceholder renders it only while
	// the buffer is empty, after the "› " label, so user text always wins over it.
	in.SetPlaceholderStyle(tcell.StyleDefault.Foreground(ghostTextColor).Background(tcell.ColorDefault).Dim(true))
	// TextArea exposes a single change callback. Wire it to an internal wrapper that pins
	// the collapsed-paste and image-token ranges (reconcileSegments) before invoking the
	// app-installed handler, so range tracking runs on every buffer change — including in
	// tests that drive the widget directly and never call SetChangedFunc. A
	// buffer change also clears any pending follow-up ghost text here, so range tracking and
	// ghost clearing both run on every change even when no app handler is installed (no
	// stale ghost after typing).
	in.SetChangedFunc(func() {
		field.reconcileSegments(field.GetText())
		field.clearGhostText()
		if field.onChanged != nil {
			field.onChanged()
		}
	})
	// Default OSC 52 sink: write the escape sequence to os.Stdout only when it is a
	// real terminal (golang.org/x/term is already a dependency), so a redirected or
	// piped stdout never receives the control bytes. Tests replace this with a fake.
	field.osc52 = func(seq string) error {
		if !term.IsTerminal(int(os.Stdout.Fd())) {
			return errClipboardOutputUnavailable
		}
		_, err := io.WriteString(os.Stdout, seq)
		return err
	}
	// Replace tview's default per-widget clipboard (a dead internal buffer that never
	// reaches the OS/terminal) so Ctrl-Q/Ctrl-X copy to the system clipboard via OSC 52.
	// The paste callback is retained for tview's clipboard internals, but it is no longer
	// exercised by Ctrl-V in production: handleGlobalKey captures
	// app-level Ctrl-V for image paste before it reaches this widget.
	in.SetClipboard(func(text string) { _ = field.copyToClipboard(text) }, field.pasteFromClipboard)
	return field
}

func (in *inputField) setSessionName(name string) {
	in.sessionMu.Lock()
	defer in.sessionMu.Unlock()
	in.sessionTitle = name
}

func (in *inputField) sessionName() string {
	in.sessionMu.RLock()
	defer in.sessionMu.RUnlock()
	return in.sessionTitle
}

// ruleStyle is the tcell style the top/bottom input rules draw in: the run-scoped accent
// color when one is set, else the terminal default. The draw func reads it every frame, so
// ruleStyle recolors both rules on the next draw without re-touching the draw func.
func (in *inputField) ruleStyle() tcell.Style {
	fg := tcell.ColorDefault
	if in.accented {
		fg = in.accent
	}
	return tcell.StyleDefault.Foreground(fg).Background(tcell.ColorDefault)
}

// labelColor is the prompt "› " glyph foreground: the run-scoped accent when set, else the
// teal brand default (promptLabelColor), so a fresh input keeps the default glyph until an
// accent is applied.
func (in *inputField) labelColor() tcell.Color {
	if in.accented {
		return in.accent
	}
	return promptLabelColor
}

// applyAccent sets the run-scoped input accent so the prompt glyph and both horizontal rules
// share one color: it restyles the label immediately via SetLabelStyle and marks the field
// accented so the next draw picks up the matching rule style (ruleStyle). The accent is not
// persisted and is scoped to the input chrome only — it never touches global tview.Styles or
// any other surface. App.ApplyInputAccent drives it from the resolved palette color.
func (in *inputField) applyAccent(color tcell.Color) {
	in.accent = color
	in.accented = true
	in.SetLabelStyle(tcell.StyleDefault.Foreground(in.labelColor()).Background(tcell.ColorDefault))
}

// SetText replaces the buffer and parks the cursor at the end, matching the old
// tview.InputField wrapper so history recall and the test seams that set the buffer
// leave the caret after the text. TextArea.SetText takes an explicit "cursor at end"
// flag; this adapts it to the single-argument call the rest of the app makes.
func (in *inputField) SetText(text string) *inputField {
	// A whole-buffer replace (history recall, clear, accepted-submit clear) invalidates
	// any collapsed-paste placeholders and image tokens that were in the old buffer, so drop
	// those segments rather than let them match coincidental text later. Pending image
	// attachments belong to the draft being replaced, so they are dropped here too, and the
	// per-prompt clipboard counter resets so the next draft's "[Image N]" starts at 1;
	// a rejected submit retains all of this because it never reaches SetText.
	in.pastes = nil
	in.images = nil
	in.clipboardCounter = 0
	in.prevText = text
	in.TextArea.SetText(text, true)
	return in
}

// ghostPrefix is the theme-independent cue prepended to a follow-up suggestion label so
// the affordance reads even where the terminal renders the dim placeholder style
// indistinctly from normal text (accessibility). "⇥" is the Tab glyph.
const ghostPrefix = "⇥ Tab: "

// SetGhostText offers label as a dim follow-up suggestion in the empty input: it is
// shown via TextArea's native placeholder, drawn only while the buffer is
// empty and after the "> " label, with the ghostPrefix cue and the dim style newInput
// installed. A later buffer change clears it (the change wrapper calls clearGhostText), so
// the suggestion never survives typing, acceptance, or submit. An empty label clears it.
func (in *inputField) SetGhostText(label string) {
	in.ghost = label
	in.renderPlaceholder()
}

// clearGhostText removes any pending follow-up ghost text. It is idempotent and cheap, so
// the change wrapper can call it on every buffer change.
func (in *inputField) clearGhostText() {
	if in.ghost == "" {
		return
	}
	in.ghost = ""
	in.renderPlaceholder()
}

func (in *inputField) setQueueHint(hint string) {
	in.queueHint = hint
	in.renderPlaceholder()
}

func (in *inputField) renderPlaceholder() {
	if in.ghost != "" {
		in.SetPlaceholder(ghostPrefix + in.ghost)
		return
	}
	in.SetPlaceholder(in.queueHint)
}

func (in *inputField) snapshotDraft() inputDraft {
	text := in.GetText()
	d := inputDraft{text: text, clipboardCounter: in.clipboardCounter}
	for _, seg := range in.pastes {
		if rangeText(text, seg.start, seg.end) == seg.placeholder {
			d.pastes = append(d.pastes, seg)
		}
	}
	d.images = in.liveImageSegments(text)
	return d
}

func (in *inputField) restoreDraft(d inputDraft) {
	in.SetText(d.text)
	in.pastes = append([]pasteSegment(nil), d.pastes...)
	in.images = append([]imageSegment(nil), d.images...)
	in.clipboardCounter = d.clipboardCounter
}

// addAttachment inserts a removable "[label]" token for att at the caret and pins an image
// segment to it. label is the display name shown in the token and the transcript
// placeholder: "Image N" for a clipboard image (see nextClipboardLabel) or the file's
// basename for an '@'-picker / pasted-path reference. The placeholder is inserted through the
// embedded TextArea so the change hook (reconcileSegments) fires and pins any existing
// segments before this new one is appended at its known range — the same append-after-insert
// PasteHandler uses, so a token inserted between earlier tokens cannot be double-shifted. The
// label is recorded on the attachment (displayName) so the transcript echo and /resume replay
// render the same name without re-deriving it from the path. Every immediate attachment
// source funnels through here so they share one token/pin path; typed paths stay plain text.
func (in *inputField) addAttachment(att imageAttachment, label string) {
	att.name = label
	placeholder := imageTokenLabel(label)
	_, start, end := in.GetSelection()
	in.Replace(start, end, placeholder)
	in.images = append(in.images, imageSegment{
		placeholder: placeholder,
		att:         att,
		start:       start,
		end:         start + len(placeholder),
	})
}

// nextClipboardLabel returns the "Image N" label for the next clipboard image and advances
// the per-prompt counter. N is monotonic within a draft and never renumbers when an
// earlier token is deleted, so the labels the user sees stay stable; SetText resets it.
func (in *inputField) nextClipboardLabel() string {
	in.clipboardCounter++
	return fmt.Sprintf("Image %d", in.clipboardCounter)
}

// liveImageSegments returns the image segments whose pinned range still holds its exact token
// in buf, ordered by buffer position — the surviving attachments in the order they appear in
// the prompt. A segment whose token was edited or deleted is omitted (its attachment is
// dropped), the same liveness test expandedText applies to paste segments.
func (in *inputField) liveImageSegments(buf string) []imageSegment {
	live := make([]imageSegment, 0, len(in.images))
	for _, seg := range in.images {
		if rangeText(buf, seg.start, seg.end) == seg.placeholder {
			live = append(live, seg)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].start < live[j].start })
	return live
}

// imageAttachments returns the pending image attachments of the surviving tokens in buffer
// order, so callers (the PressCtrlV/SubmitCurrent test seams and the submit path) can read
// the staged set without exposing the live segment slice.
func (in *inputField) imageAttachments() []imageAttachment {
	live := in.liveImageSegments(in.GetText())
	out := make([]imageAttachment, len(live))
	for i, seg := range live {
		out[i] = seg.att
	}
	return out
}

// submitText returns the value submitCurrent sends: the visible buffer with every tracked
// collapsed-paste placeholder expanded back to its full text and every surviving image token
// stripped, plus those tokens' attachments in buffer order. It is the unified analogue
// of expandedText — paste segments are spliced to their full text, image segments to the
// empty string — applied back-to-front by start offset so each splice leaves the earlier
// ranges' offsets intact. Only a segment whose pinned range still holds its exact placeholder
// contributes, so an edited/deleted token strips nothing and stages no attachment, and a
// user-typed literal "[Image 1]" (tracked by no segment) is left untouched.
func (in *inputField) submitText() (string, []imageAttachment) {
	text := in.GetText()
	type splice struct {
		start, end int
		repl       string
	}
	var edits []splice
	for _, seg := range in.pastes {
		if rangeText(text, seg.start, seg.end) == seg.placeholder {
			edits = append(edits, splice{seg.start, seg.end, seg.full})
		}
	}
	live := in.liveImageSegments(text)
	atts := make([]imageAttachment, len(live))
	for i, seg := range live {
		atts[i] = seg.att
		edits = append(edits, splice{seg.start, seg.end, ""})
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, e := range edits {
		text = text[:e.start] + e.repl + text[e.end:]
	}
	return text, atts
}

// SetChangedFunc registers the app's prompt-change handler. The TextArea's own change
// callback is held by newInput's wrapper (which reconciles paste ranges first), so this only
// records the handler for that wrapper to invoke rather than replacing it.
func (in *inputField) SetChangedFunc(handler func()) *inputField {
	in.onChanged = handler
	return in
}

// SetPasteFunc registers the app's short-paste observer without replacing the
// TextArea paste handler. It is separate from SetChangedFunc because paste-originated
// changes intentionally suppress the '@' picker while still allowing pasted image paths
// to become pending attachments.
func (in *inputField) SetPasteFunc(handler func(text string, start, end int)) *inputField {
	in.onPaste = handler
	return in
}

// Cursor returns the caret as a rune offset into the buffer, the position Tab
// slash-name completion (completeSlashName) expects. tview.TextArea reports
// the cursor/selection as byte indices into the text (GetSelection); this converts
// the caret's byte index to a rune count. When text is selected the caret is the
// selection end. The offset spans the whole buffer including newlines, so a caret
// past the first line lands beyond any leading slash-name token and completion
// no-ops there — the first-line name token still completes.
func (in *inputField) Cursor() int {
	text := in.GetText()
	_, _, end := in.GetSelection()
	if end > len(text) {
		end = len(text)
	}
	return len([]rune(text[:end]))
}

// collapseSelection clears any active text selection by collapsing it to the
// caret at the selection end, so the TextArea's own selection highlight clears
// after the app auto-copies a mouse-drag selection on release. It leaves
// the caret where the drag ended (GetSelection's end), so a following keystroke
// continues from there; with no selection it is a no-op that re-pins the caret to
// itself. Select takes byte indices, which GetSelection already reports.
func (in *inputField) collapseSelection() {
	_, _, end := in.GetSelection()
	in.Select(end, end)
}

// offsetAt maps a screen coordinate in or near the input text area to a byte offset
// in the buffer. It mirrors the TextArea mouse coordinate rules for the app-owned
// plain-drag selection path: the prompt label takes the first two columns on
// every wrapped row, row offset is honored, and off-rect drags clamp to the nearest
// visible row boundary.
func (in *inputField) offsetAt(x, y int) int {
	ix, iy, iw, ih := in.GetInnerRect()
	labelWidth := tview.TaggedStringWidth(promptLabel)
	textWidth := iw - labelWidth
	text := in.GetText()
	rows := wrapRows(text, textWidth)
	if len(rows) == 0 {
		return 0
	}
	rowOffset, colOffset := in.GetOffset()
	rowIdx := rowOffset + y - iy
	if rowIdx < 0 {
		rowIdx = 0
	}
	if rowIdx >= len(rows) {
		rowIdx = len(rows) - 1
	}
	// Below the last visible text row the pointer is past the content (on the bottom rule
	// or beyond), which means "take the whole line" rather than up to the pointer column —
	// matching the transcript and the drag-below-the-bar intent.
	if ih > 0 && y > iy+ih-1 {
		return rows[rowIdx].end
	}
	targetCol := x - ix - labelWidth + colOffset
	if targetCol < 0 {
		targetCol = 0
	}
	return byteOffsetInRow(text, rows[rowIdx], targetCol)
}

// scrollDrag advances the input viewport by one wrapped row when an app-owned drag
// reaches the top or bottom visible text row. It reports whether the viewport moved.
// Without this, a selection could only extend to the edge of the current input viewport
// even when more prompt text exists above or below it. The input box's inner rect
// is always fully on screen — the adaptive cap reserves rows for the status line and mode
// hint below it (inputTextRowCap), so its bottom row never reaches the terminal edge — so
// the box's own inner rect is the visible viewport with no screen-height clipping needed.
func (in *inputField) scrollDrag(y int) bool {
	_, iy, iw, ih := in.GetInnerRect()
	if ih <= 0 {
		return false
	}
	bottom := iy + ih - 1
	textWidth := iw - tview.TaggedStringWidth(promptLabel)
	rows := wrapRows(in.GetText(), textWidth)
	maxOffset := len(rows) - ih
	if maxOffset < 0 {
		maxOffset = 0
	}
	rowOffset, colOffset := in.GetOffset()
	next := rowOffset
	switch {
	case y >= bottom:
		next++
	case y <= iy:
		next--
	}
	if next < 0 {
		next = 0
	}
	if next > maxOffset {
		next = maxOffset
	}
	mouseDebugf("  inputScrollDrag y=%d iy=%d ih=%d bottom=%d offset=%d->%d maxOffset=%d scrolled=%v",
		y, iy, ih, bottom, rowOffset, next, maxOffset, next != rowOffset)
	if next != rowOffset {
		in.SetOffset(next, colOffset)
		return true
	}
	return false
}

// insertNewline inserts a newline at the caret without submitting — the action the
// Ctrl+Enter / Ctrl+J chord drives. It replaces any active selection, the
// way typing a character would, and leaves the caret after the inserted newline.
// TextArea.Replace takes byte indices, which GetSelection already reports.
func (in *inputField) insertNewline() {
	_, start, end := in.GetSelection()
	in.Replace(start, end, "\n")
}

// cursorLineEdges reports whether the caret sits on the first and/or last logical
// (newline-separated) line of the buffer. handleInputKey uses it to keep ↑/↓ bound
// to input-history navigation only at the buffer's top and bottom edges, letting the
// arrows move the caret between lines of a multi-line draft otherwise.
// Logical lines are counted from the text and the caret's byte offset, not
// TextArea's rendered rows, so word-wrap cannot shift the edge test. A single-line
// buffer is both first and last, so ↑/↓ stay history navigation exactly as before.
func (in *inputField) cursorLineEdges() (first, last bool) {
	text := in.GetText()
	_, _, end := in.GetSelection()
	if end > len(text) {
		end = len(text)
	}
	lineIdx := strings.Count(text[:end], "\n")
	total := strings.Count(text, "\n")
	return lineIdx == 0, lineIdx == total
}
