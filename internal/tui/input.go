// Input area: the multi-line prompt (a tview.TextArea), its "› " label and
// borderless top/bottom-rule chrome, and a cursor accessor Tab slash-name
// completion reads as a rune offset into the buffer.
package tui

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"
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

// pasteCollapseLineThreshold is the logical line count at or above which a bracketed
// paste collapses to a one-line "[Pasted N lines …]" placeholder instead of inserting
// inline. The exact value is an implementation choice: a collapsed paste is
// always the single placeholder row, while a shorter paste inserts inline exactly as
// before — and below this threshold an inline paste stays within the input's adaptive
// text-row cap (App.inputTextRowCap) on any normally sized terminal.
const pasteCollapseLineThreshold = 6

// pasteSegment maps one collapsed paste to the full pasted text it stands in for, pinned
// to the exact [start,end) byte range its placeholder token occupies in the visible buffer
// so the right occurrence is expanded even when an identical placeholder string appears
// elsewhere.
type pasteSegment struct {
	placeholder string
	full        string
	start, end  int
}

// imageSegment maps one pending image attachment to the "[Image N]" / "[<basename>]" token
// that stands in for it in the visible buffer, pinned to the exact [start,end) byte range
// the token occupies so the right occurrence is stripped even when an identical token string
// appears elsewhere — the image analogue of pasteSegment. The one behavioral difference is
// at submit: a paste placeholder is expanded back to its full text, an image token is
// stripped and yields a content part instead.
type imageSegment struct {
	placeholder string
	att         imageAttachment
	start, end  int
}

// imageTokenLabel wraps a display label as the bracketed token shown in the input for a
// pending image, e.g. "Image 1" → "[Image 1]" and "diagram.png" → "[diagram.png]".
func imageTokenLabel(label string) string { return "[" + label + "]" }

// pastedLineCount reports the logical line count of a (newline-normalized) paste, the
// N shown in "[Pasted N lines]". A single trailing newline does not add a phantom empty
// line, so "a\nb" and "a\nb\n" both count as 2.
func pastedLineCount(text string) int {
	return strings.Count(strings.TrimSuffix(text, "\n"), "\n") + 1
}

// pastePlaceholder is the one-line token a collapsed paste of n logical lines shows in
// the input while its full text is retained off-screen. The "— paste again to
// expand" suffix is the inline affordance hinting that re-pasting the same block
// expands it back to the full text; pasteSegment ranges follow its byte length
// via len(placeholder), so the wording is the only thing that changes.
func pastePlaceholder(n int) string {
	return fmt.Sprintf("[Pasted %d lines — paste again to expand]", n)
}

var errClipboardOutputUnavailable = errors.New("terminal output is not available")

// osc52Sequence builds the OSC 52 "set clipboard" escape sequence for text:
// ESC ] 52 ; c ; <base64(text)> BEL. The payload is base64-encoded so clipboard
// content can never inject raw terminal control bytes into the sequence.
func osc52Sequence(text string) string {
	return "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(text)) + "\x07"
}

// copyToClipboard records text as the in-app paste source and emits it to the system
// clipboard via OSC 52 through the injected sink. The paste source is set even when the
// sink reports a failure: only the trip to the terminal failed.
func (in *inputField) copyToClipboard(text string) error {
	in.lastCopied = text
	return in.osc52(osc52Sequence(text))
}

// pasteFromClipboard is the tview clipboard paste callback (SetClipboard): it
// returns the last copied text (OSC 52 read-back is unreliable, so it reads back the
// last copy from memory rather than the live system clipboard). This
// is no longer reached via Ctrl-V in production — handleGlobalKey captures app-level
// Ctrl-V for image paste before it reaches the input widget — so it remains only as
// tview's legacy clipboard callback.
func (in *inputField) pasteFromClipboard() string {
	return in.lastCopied
}

// PasteHandler marks the buffer change a bracketed paste produces as paste-originated for the
// duration of the insert, so App.onInputChanged can tell a pasted '@' (which must not open the
// file-reference picker) from a typed one. tview routes a paste to the focused
// primitive's PasteHandler and applies the whole block through TextArea.replace, which fires
// the change hook synchronously via its deferred callback — so the flag is set across exactly
// the change the paste causes and cleared once the insert returns. The insertion itself is
// delegated unchanged to the embedded TextArea.
func (in *inputField) PasteHandler() func(string, func(tview.Primitive)) {
	inner := in.TextArea.PasteHandler()
	return func(text string, setFocus func(tview.Primitive)) {
		in.pasting = true
		defer func() { in.pasting = false }()
		if pastedLineCount(text) < pasteCollapseLineThreshold {
			_, start, _ := in.GetSelection()
			inner(text, setFocus) // short paste: insert inline exactly as before.
			if in.onPaste != nil {
				in.onPaste(text, start, start+len(text))
			}
			return
		}
		if in.expandCollapsedPaste(text) {
			return // re-paste of an already-collapsed block: expand it in place.
		}
		placeholder := pastePlaceholder(pastedLineCount(text))
		_, start, _ := in.GetSelection() // paste replaces the selection, so the placeholder lands at its start.
		inner(placeholder, setFocus)     // insert the short placeholder; full text is retained.
		// Pin the segment to the occurrence just inserted. The insert fired the change hook
		// (reconcilePasteRanges) synchronously, shifting any earlier segments past start; this
		// new occurrence is appended afterward at its known range so it is not double-counted.
		in.pastes = append(in.pastes, pasteSegment{
			placeholder: placeholder,
			full:        text,
			start:       start,
			end:         start + len(placeholder),
		})
	}
}

// expandCollapsedPaste handles a re-paste of a block that is already collapsed: if text
// equals a tracked segment whose placeholder range still holds that placeholder, it
// replaces that range with the full text in place, so the re-paste expands the existing
// occurrence rather than inserting a second one. It reports whether it handled the
// paste. The replace goes through the embedded TextArea (not SetText), so its change hook
// runs reconcilePasteRanges, which shifts the other tracked segments and drops this one (its
// range now holds full text, not the placeholder); the paste-suppressed change keeps the '@'
// picker from opening.
func (in *inputField) expandCollapsedPaste(text string) bool {
	buf := in.GetText()
	for _, seg := range in.pastes {
		if seg.full != text || segmentText(buf, seg) != seg.placeholder {
			continue
		}
		in.Replace(seg.start, seg.end, seg.full)
		return true
	}
	return false
}

// reconcileSegments keeps every tracked placeholder — collapsed-paste and image-token alike
// — pinned to its occurrence as the buffer changes, in one pass so the two segment kinds'
// ranges can never desynchronize under an edit. It diffs the new buffer against the
// previously observed one as a single replaced span (the common prefix/suffix bound the
// edit) and applies shiftPinnedRange to each segment: a segment wholly after the edit shifts
// by the length delta, a segment wholly before is untouched, and a segment the edit overlaps
// is dropped — dropping an image segment removes its pending attachment. newInput
// wires this ahead of the app's change handler.
func (in *inputField) reconcileSegments(cur string) {
	prev := in.prevText
	in.prevText = cur
	if len(in.pastes) == 0 && len(in.images) == 0 {
		return
	}
	prefix := commonPrefixLen(prev, cur)
	suffix := commonSuffixLen(prev, cur, prefix)
	editStart := prefix
	editEnd := len(prev) - suffix
	delta := len(cur) - len(prev)
	_, _, cursor := in.GetSelection()

	keptPastes := in.pastes[:0]
	for _, seg := range in.pastes {
		if start, end, ok := shiftPinnedRange(prev, cur, seg.placeholder, seg.start, seg.end, editStart, editEnd, delta, cursor); ok {
			seg.start, seg.end = start, end
			keptPastes = append(keptPastes, seg)
		}
	}
	in.pastes = keptPastes

	keptImages := in.images[:0]
	for _, seg := range in.images {
		if start, end, ok := shiftPinnedRange(prev, cur, seg.placeholder, seg.start, seg.end, editStart, editEnd, delta, cursor); ok {
			seg.start, seg.end = start, end
			keptImages = append(keptImages, seg)
		}
	}
	in.images = keptImages
}

// shiftPinnedRange recomputes one pinned [start,end) placeholder range against a single
// replaced-span buffer edit (prev→cur, described by editStart/editEnd/delta and the caret),
// shared by the paste and image reconcilers so both pin identically. It returns the adjusted
// range and whether the segment survives: an edit wholly before it slides it by delta, an
// edit wholly after leaves it, an edit that overlaps it drops it (keep=false); a duplicate
// placeholder freshly inserted at the segment's start is disambiguated by the caret (the new
// occurrence keeps the range pinned only when the caret sits at its end). A final exact-text
// check drops any range no longer holding its placeholder, so an ambiguous diff can never
// expand/strip the wrong text.
func shiftPinnedRange(prev, cur, placeholder string, start, end, editStart, editEnd, delta, cursor int) (int, int, bool) {
	adjusted := false
	if delta > 0 && editStart >= end {
		shiftedStart, shiftedEnd := start+delta, end+delta
		insertedAtSegmentStart := start+delta <= len(cur) &&
			rangeText(cur, shiftedStart, shiftedEnd) == placeholder &&
			cur[:start]+cur[start+delta:] == prev
		if insertedAtSegmentStart {
			switch cursor {
			case start + delta:
				start, end = shiftedStart, shiftedEnd
				adjusted = true
			case end + delta:
				// The duplicate text was inserted after this segment, so the range stays put.
			default:
				return 0, 0, false // Ambiguous duplicate placeholder edit: drop rather than keep.
			}
		}
	}
	if !adjusted {
		switch {
		case editEnd <= start: // edit entirely before the placeholder: it slides by delta.
			start += delta
			end += delta
		case editStart >= end: // edit entirely after the placeholder: range unchanged.
		default: // edit touched the placeholder: drop the segment.
			return 0, 0, false
		}
	}
	if rangeText(cur, start, end) != placeholder {
		return 0, 0, false // range no longer holds the exact placeholder: drop it.
	}
	return start, end, true
}

// segmentText returns the buffer slice a paste segment's range covers, or "" if the range is
// out of bounds for buf — so a stale range never panics and, since a placeholder is never
// empty, compares unequal to it.
func segmentText(buf string, seg pasteSegment) string {
	return rangeText(buf, seg.start, seg.end)
}

// rangeText returns buf[start:end], or "" if the range is out of bounds — the shared
// bounds-safe accessor both paste and image segments use to confirm their pinned range
// still holds the exact placeholder before expanding/stripping it.
func rangeText(buf string, start, end int) string {
	if start < 0 || end > len(buf) || start > end {
		return ""
	}
	return buf[start:end]
}

// commonPrefixLen returns the number of leading bytes a and b share.
func commonPrefixLen(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// commonSuffixLen returns the number of trailing bytes a and b share, capped so the suffix
// does not overlap the already-counted prefix (keeping the diffed edit span non-negative).
func commonSuffixLen(a, b string, prefix int) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	limit -= prefix
	i := 0
	for i < limit && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	return i
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

// detectAtTrigger reports whether cur is prev with exactly one '@' rune inserted at a word
// boundary — the file-reference picker trigger — and returns the byte offset of the
// inserted '@' in cur. A word boundary is the start of the buffer or a position whose
// preceding rune is whitespace, so a '@' typed inside a word (an email local part, say)
// never triggers. Because '@' is a single byte, a one-character insertion makes
// len(cur) == len(prev)+1; any larger delta — a multi-rune bracketed paste, including one
// that contains '@' — fails the length test and never triggers. A deletion, a
// replacement, or a multi-rune programmatic SetText fail the same test. The trailing-bytes
// equality check rejects a same-length coincidental edit that is not a clean single insert.
// A bracketed paste of exactly one '@' has the same one-byte delta as a typed '@' and is not
// separable here; App.onInputChanged suppresses that case upstream via inputField.pasting.
func detectAtTrigger(prev, cur string) (int, bool) {
	if len(cur) != len(prev)+1 { // '@' is one byte: only a single-char insertion can match
		return 0, false
	}
	i := 0
	for i < len(prev) && prev[i] == cur[i] {
		i++
	}
	if cur[i] != '@' {
		return 0, false
	}
	if cur[i+1:] != prev[i:] {
		return 0, false // the rest must be unchanged, so the edit is exactly one inserted '@'
	}
	if i == 0 {
		return i, true // start of buffer is a word boundary
	}
	r, _ := utf8.DecodeLastRuneInString(cur[:i])
	if unicode.IsSpace(r) {
		return i, true
	}
	return 0, false
}

// detectSlashTrigger reports whether cur is prev with exactly one '/' rune inserted as the
// first non-whitespace character of the buffer — the live slash-command picker trigger — and
// returns the byte offset of the inserted '/' in cur. A slash command is only valid as the
// whole line, so the '/' fires only when every byte before it is space or tab: a '/' after any
// non-whitespace text, after a newline, or inside a word never triggers. Like detectAtTrigger,
// '/' is a single byte so a one-character insertion makes len(cur) == len(prev)+1; a multi-rune
// bracketed paste fails the length test, and a paste of exactly '/' is suppressed upstream by
// App.onInputChanged via inputField.pasting.
func detectSlashTrigger(prev, cur string) (int, bool) {
	if len(cur) != len(prev)+1 { // '/' is one byte: only a single-char insertion can match
		return 0, false
	}
	i := 0
	for i < len(prev) && prev[i] == cur[i] {
		i++
	}
	if cur[i] != '/' {
		return 0, false
	}
	if cur[i+1:] != prev[i:] {
		return 0, false // the rest must be unchanged, so the edit is exactly one inserted '/'
	}
	for _, r := range cur[:i] { // everything before the '/' must be leading space/tab, no newline
		if r != ' ' && r != '\t' {
			return 0, false
		}
	}
	return i, true
}

// fileRefTokenEnd returns the byte offset at which the file-reference token beginning with
// the '@' at atByte ends: the first whitespace byte at or after atByte+1, or the end of
// text. The token is "@" plus the run of non-whitespace runes after it, so selecting a
// candidate replaces the whole run (any query text following '@') as a unit. atByte
// must index the '@'; an out-of-range offset is returned unchanged.
func fileRefTokenEnd(text string, atByte int) int {
	if atByte < 0 || atByte >= len(text) {
		return atByte
	}
	for i := atByte + 1; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if unicode.IsSpace(r) {
			return i
		}
		i += size
	}
	return len(text)
}

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
