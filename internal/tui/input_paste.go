package tui

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/rivo/tview"
)

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
