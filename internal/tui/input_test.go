// Tests for the wrapped-row count that drives the input area's
// width-aware height. wrappedRowCount mirrors tview.TextArea's wrap algorithm, so
// the suite both pins hand-computed cases and cross-checks the count against a real
// tview.TextArea's rendered rows (the fidelity net for the duplicated algorithm).
package tui

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestWrappedRowCount(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		width int
		want  int
	}{
		{"empty buffer is one row", "", 10, 1},
		{"zero width floors to one row", "abc", 0, 1},
		{"negative width floors to one row", "abc", -5, 1},
		{"short line fits", "hello", 10, 1},
		{"exact width fits", "hello", 5, 1},
		{"one past width wraps", "hello", 4, 2},
		{"unbroken token width 3", "aaaaaaaa", 3, 3},
		{"unbroken token width 4", "aaaaaaaa", 4, 2},
		{"unbroken token width 7", "aaaaaaaa", 7, 2},
		{"unbroken token width 8", "aaaaaaaa", 8, 1},
		{"two logical lines", "a\nb", 10, 2},
		{"trailing newline adds a row", "a\n", 10, 2},
		{"blank interior line", "a\n\nb", 10, 3},
		{"newline then wrap", "aaaa\nbbbb", 3, 4},
		{"tab fits one row", "\tx", 10, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wrappedRowCount(tc.text, tc.width); got != tc.want {
				t.Fatalf("wrappedRowCount(%q, %d) = %d, want %d", tc.text, tc.width, got, tc.want)
			}
		})
	}
}

// TestWrappedRowCount_MatchesTextAreaRender is the fidelity net: for each case it
// renders a real tview.TextArea (the same widget the input uses) at a known width
// and counts the rows that actually received content, then asserts wrappedRowCount
// predicts exactly that many. Because tview's wrap algorithm is duplicated in
// wrappedRowCount (tview exposes no total-row accessor), a divergence — including a
// future tview change — fails here rather than silently mis-sizing the input by a
// row. Label cases also prove the "> " width is subtracted from every text row.
func TestWrappedRowCount_MatchesTextAreaRender(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		label    string
		boxWidth int
	}{
		{"token width 5", strings.Repeat("a", 23), "", 5},
		{"token width 7", strings.Repeat("a", 23), "", 7},
		{"token width 1", strings.Repeat("a", 6), "", 1},
		{"token with label width 80", strings.Repeat("a", 200), "> ", 80},
		{"token with label width 40", strings.Repeat("a", 200), "> ", 40},
		{"label boundary 79 chars", strings.Repeat("a", 79), "> ", 80},
		{"words width 8", "alpha beta gamma delta epsilon", "", 8},
		{"words width 12", "alpha beta gamma delta epsilon", "", 12},
		{"words with label width 20", "the quick brown fox jumps over", "> ", 20},
		{"long single word width 10", "supercalifragilisticexpialidocious", "", 10},
		{"cjk width 5", "日本語のテキスト", "", 5},
		{"cjk width 4", "日本語のテキスト", "", 4},
		{"cjk with label width 9", "日本語のテキスト表示", "> ", 9},
		{"tabs width 8", "\tabc\tdefg", "", 8},
		{"tabs width 12", "\tabcdef\tghijkl", "", 12},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			textWidth := tc.boxWidth - tview.TaggedStringWidth(tc.label)
			want := textAreaRenderedRows(t, tc.text, tc.label, tc.boxWidth)
			if got := wrappedRowCount(tc.text, textWidth); got != want {
				t.Fatalf("wrappedRowCount(%q, %d) = %d, but tview rendered %d rows (boxWidth %d, label %q)",
					tc.text, textWidth, got, want, tc.boxWidth, tc.label)
			}
		})
	}
}

// textAreaRenderedRows draws a real tview.TextArea (wrap + word-wrap on, matching
// the input) holding text with the given prompt label into a boxWidth-wide region of
// a simulation screen, then reports how many rows tview wrapped the text into as the
// highest row that received visible content, plus one. The TextArea's default text
// style shares the box background, so Draw does not pre-clear the rect — untouched
// cells keep the screen's initial blanks. Wrapping fills rows contiguously from the
// top, so the last content row's index + 1 is the row count even when an interior row
// is visually blank (a leading tab renders as spaces, not a "\t" glyph). Cases are
// chosen to end on a content row (no trailing newline / lone-tab final row).
func textAreaRenderedRows(t *testing.T, text, label string, boxWidth int) int {
	t.Helper()
	const height = 64
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(boxWidth, height)
	ta := tview.NewTextArea()
	if label != "" {
		ta.SetLabel(label)
	}
	ta.SetWrap(true)
	ta.SetWordWrap(true)
	ta.SetText(text, false)
	ta.SetRect(0, 0, boxWidth, height)
	ta.Draw(screen)

	last := -1
	for y := 0; y < height; y++ {
		for x := 0; x < boxWidth; x++ {
			str, _, _ := screen.Get(x, y)
			if str != " " && str != "" {
				last = y
				break
			}
		}
	}
	return last + 1
}

// TestInputField_CtrlQCopiesSelectionViaOSC52 pins the Ctrl-Q copy: with a real
// clipboard wired by newInput, selecting input text and pressing Ctrl-Q emits the
// selection to the system clipboard as an OSC 52 sequence through the injected sink,
// and the in-app paste source (GetClipboardText) returns that selection. The
// TextArea is drawn on a simulation screen before Select so tview lays out the rows
// selection positions are computed from (Notes).
func TestInputField_CtrlQCopiesSelectionViaOSC52(t *testing.T) {
	in := newInput()
	var captured []string
	in.osc52 = func(seq string) error { captured = append(captured, seq); return nil }

	const text = "hello world"
	in.SetText(text)

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(40, 5)
	in.SetRect(0, 0, 40, 5)
	in.Draw(screen)

	// Select "hello" (the first five characters), then draw so the selection is laid out.
	in.Select(0, 5)
	in.Draw(screen)

	ev := tcell.NewEventKey(tcell.KeyCtrlQ, 0, tcell.ModNone)
	in.InputHandler()(ev, func(tview.Primitive) {})

	want := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte("hello")) + "\x07"
	if len(captured) != 1 || captured[0] != want {
		t.Fatalf("osc52 sink received %q, want exactly one %q", captured, want)
	}
	if got := in.GetClipboardText(); got != "hello" {
		t.Errorf("GetClipboardText() = %q, want %q (in-app paste source)", got, "hello")
	}
}

// TestInputField_CopyToClipboardReportsSinkOutcome pins what the copy seam can and cannot
// tell a caller. OSC 52 carries no acknowledgement, so terminal-side acceptance is outside
// what any of this observes; only the emission attempt is.
func TestInputField_CopyToClipboardReportsSinkOutcome(t *testing.T) {
	t.Run("emitted", func(t *testing.T) {
		in := newInput()
		var captured []string
		in.osc52 = func(seq string) error { captured = append(captured, seq); return nil }

		if err := in.copyToClipboard("hello"); err != nil {
			t.Fatalf("copyToClipboard = %v, want no error from an emitting sink", err)
		}
		if want := osc52Sequence("hello"); len(captured) != 1 || captured[0] != want {
			t.Fatalf("osc52 sink received %q, want exactly one %q", captured, want)
		}
		if got := in.GetClipboardText(); got != "hello" {
			t.Errorf("GetClipboardText() = %q, want %q", got, "hello")
		}
	})

	t.Run("emission failed", func(t *testing.T) {
		in := newInput()
		sinkErr := errors.New("stdout is closed")
		in.osc52 = func(string) error { return sinkErr }

		if err := in.copyToClipboard("hello"); !errors.Is(err, sinkErr) {
			t.Fatalf("copyToClipboard = %v, want the sink's %v", err, sinkErr)
		}
		if got := in.GetClipboardText(); got != "hello" {
			t.Errorf("GetClipboardText() = %q, want %q even when emission failed", got, "hello")
		}
	})

	t.Run("output unavailable", func(t *testing.T) {
		in := newInput()
		if err := in.osc52(osc52Sequence("hello")); !errors.Is(err, errClipboardOutputUnavailable) {
			t.Fatalf("default sink under a non-terminal stdout = %v, want %v", err, errClipboardOutputUnavailable)
		}
	})
}

// TestInputField_WrappedRowsSubtractsLabel proves the wrappedRows method reduces the
// input width by the rendered "> " label width before counting: 79 'a's fit in 80 raw
// columns (one row) but wrap to two rows once the 2-cell label leaves 78 for text.
func TestInputField_WrappedRowsSubtractsLabel(t *testing.T) {
	in := newInput()
	in.SetText(strings.Repeat("a", 79))
	if got := wrappedRowCount(in.GetText(), 80); got != 1 {
		t.Fatalf("sanity: 79 chars at raw width 80 = %d rows, want 1", got)
	}
	if got := in.wrappedRows(80); got != 2 {
		t.Fatalf("wrappedRows(80) = %d, want 2 (the \"> \" label reduces text width to 78)", got)
	}
}

// noFocus is the setFocus argument the paste/key handlers take; tests never move focus.
func noFocus(tview.Primitive) {}

// pasteInto drives a bracketed paste through the production PasteHandler closure the
// way tview routes a real paste to the focused primitive, so collapse, expansion, and
// the change hook run exactly as at runtime.
func pasteInto(in *inputField, text string) {
	in.PasteHandler()(text, noFocus)
}

// submitTextOf returns just the derived prompt text — collapsed pastes expanded back to their
// full text and image tokens stripped — from submitText, for the paste-expansion tests that
// predate image tokens (the production submit path reads both returns).
func submitTextOf(in *inputField) string {
	text, _ := in.submitText()
	return text
}

// TestPastedLineCount pins the N in "[Pasted N lines]": logical lines after newline
// normalization, with a single trailing newline not adding a phantom empty line (Notes).
func TestPastedLineCount(t *testing.T) {
	for _, tc := range []struct {
		text string
		want int
	}{
		{"", 1},
		{"one line", 1},
		{"a\nb", 2},
		{"a\nb\n", 2},
		{"a\nb\nc", 3},
		{"a\n\nc", 3}, // an interior blank line is a real line
	} {
		if got := pastedLineCount(tc.text); got != tc.want {
			t.Errorf("pastedLineCount(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
}

// TestInputField_LongPasteCollapsesToPlaceholder proves a paste at/above the threshold
// shows the one-line placeholder in the visible buffer while expandedText recovers the
// full pasted content.
func TestInputField_LongPasteCollapsesToPlaceholder(t *testing.T) {
	in := newInput()
	full := "l1\nl2\nl3\nl4\nl5\nl6"
	pasteInto(in, full)

	if got, want := in.GetText(), "[Pasted 6 lines — paste again to expand]"; got != want {
		t.Fatalf("visible buffer after long paste = %q, want placeholder %q", got, want)
	}
	if got := submitTextOf(in); got != full {
		t.Fatalf("expandedText() = %q, want full pasted content %q", got, full)
	}
}

// TestInputField_SmallPasteInsertsInline proves a paste below the threshold inserts
// verbatim and tracks no hidden segment, so the prior small-paste behavior is unchanged.
func TestInputField_SmallPasteInsertsInline(t *testing.T) {
	in := newInput()
	small := "a\nb\nc" // 3 lines, below pasteCollapseLineThreshold
	pasteInto(in, small)

	if got := in.GetText(); got != small {
		t.Fatalf("visible buffer after small paste = %q, want inline %q", got, small)
	}
	if len(in.pastes) != 0 {
		t.Fatalf("small paste tracked %d hidden segments, want 0", len(in.pastes))
	}
	if got := submitTextOf(in); got != small {
		t.Fatalf("expandedText() = %q, want %q", got, small)
	}
}

// TestInputField_RepasteExpandsPlaceholder proves re-pasting the same long block while
// its placeholder is present expands the placeholder back to the full text in place
// instead of inserting a second placeholder.
func TestInputField_RepasteExpandsPlaceholder(t *testing.T) {
	in := newInput()
	full := "x1\nx2\nx3\nx4\nx5\nx6"
	pasteInto(in, full)
	if got := in.GetText(); got != "[Pasted 6 lines — paste again to expand]" {
		t.Fatalf("first paste visible = %q, want placeholder", got)
	}

	pasteInto(in, full) // re-paste the identical block
	if got := in.GetText(); got != full {
		t.Fatalf("visible buffer after re-paste = %q, want expanded full text %q", got, full)
	}
	if len(in.pastes) != 0 {
		t.Fatalf("re-paste left %d hidden segments, want 0 (placeholder expanded)", len(in.pastes))
	}
}

// TestInputField_TypedPlaceholderNotExpanded proves a user-typed literal "[Pasted N
// lines]" is never treated as hidden paste text: with no tracked segment, expandedText
// returns it unchanged.
func TestInputField_TypedPlaceholderNotExpanded(t *testing.T) {
	in := newInput()
	in.SetText("[Pasted 6 lines — paste again to expand]")
	if got := submitTextOf(in); got != "[Pasted 6 lines — paste again to expand]" {
		t.Fatalf("expandedText() of a typed placeholder = %q, want it unchanged", got)
	}
}

// TestInputField_EditedPlaceholderDropsHiddenText proves editing the placeholder token
// drops its hidden segment at expansion rather than submitting stale content: a mangled
// placeholder no longer matches, so expandedText returns the visible (mangled) text with
// no full content spliced in.
func TestInputField_EditedPlaceholderDropsHiddenText(t *testing.T) {
	in := newInput()
	full := "s1\ns2\ns3\ns4\ns5\ns6"
	pasteInto(in, full)

	// Delete the trailing ']' so the tracked placeholder no longer matches.
	buf := in.GetText()
	in.Replace(len(buf)-1, len(buf), "")

	got := submitTextOf(in)
	if strings.Contains(got, full) {
		t.Fatalf("expandedText() = %q, must not splice in dropped hidden content %q", got, full)
	}
	if got != "[Pasted 6 lines — paste again to expand" {
		t.Fatalf("expandedText() = %q, want the mangled visible text %q", got, "[Pasted 6 lines — paste again to expand")
	}
}

// TestInputField_EditAroundPlaceholderPreservesHiddenText proves editing the buffer
// around an intact placeholder keeps the segment, so expansion still recovers the full
// content alongside the edit.
func TestInputField_EditAroundPlaceholderPreservesHiddenText(t *testing.T) {
	in := newInput()
	full := "p1\np2\np3\np4\np5\np6"
	pasteInto(in, full)

	buf := in.GetText()
	in.Replace(len(buf), len(buf), " go") // append after the intact placeholder

	if got, want := submitTextOf(in), full+" go"; got != want {
		t.Fatalf("expandedText() = %q, want %q (placeholder expanded plus the edit)", got, want)
	}
}

// TestInputField_TypedLiteralBeforeCollapsedPaste proves a user-typed literal "[Pasted N
// lines]" sitting before a real collapsed paste is left literal while only the pasted
// occurrence expands: segments are pinned to their byte range, not matched by string, so the
// earlier identical token is never mistaken for hidden paste text.
func TestInputField_TypedLiteralBeforeCollapsedPaste(t *testing.T) {
	in := newInput()
	typed := "[Pasted 6 lines — paste again to expand]"
	in.Replace(0, 0, typed) // user types a literal that happens to match a placeholder
	full := "n1\nn2\nn3\nn4\nn5\nn6"
	pasteInto(in, full)

	if got, want := in.GetText(), typed+typed; got != want {
		t.Fatalf("visible buffer = %q, want typed literal then placeholder %q", got, want)
	}
	if got, want := submitTextOf(in), typed+full; got != want {
		t.Fatalf("expandedText() = %q, want %q (typed literal kept, pasted occurrence expanded)", got, want)
	}
}

// TestInputField_TypedLiteralInsertedBeforeCollapsedPaste proves the same literal remains
// literal even when it is inserted before an already-tracked collapsed paste. This is the
// ambiguous edit direction: the visible buffer is identical to appending the literal after
// the placeholder, so range tracking must not leave the hidden segment pinned to the newly
// typed occurrence.
func TestInputField_TypedLiteralInsertedBeforeCollapsedPaste(t *testing.T) {
	in := newInput()
	full := "m1\nm2\nm3\nm4\nm5\nm6"
	pasteInto(in, full)

	typed := "[Pasted 6 lines — paste again to expand]"
	in.Replace(0, 0, typed) // user inserts the literal before the tracked placeholder

	if got, want := in.GetText(), typed+typed; got != want {
		t.Fatalf("visible buffer = %q, want typed literal then placeholder %q", got, want)
	}
	if got, want := submitTextOf(in), typed+full; got != want {
		t.Fatalf("expandedText() = %q, want %q (typed literal kept, pasted occurrence expanded)", got, want)
	}
}

// TestInputField_TwoCollapsedPastesExpandToOwnContent proves two collapsed pastes with the
// same line count (so identical placeholder strings) but different content each expand to
// their own text, because each segment tracks its own occurrence's range rather than the
// first matching placeholder string.
func TestInputField_TwoCollapsedPastesExpandToOwnContent(t *testing.T) {
	in := newInput()
	first := "a1\na2\na3\na4\na5\na6"
	second := "b1\nb2\nb3\nb4\nb5\nb6"
	pasteInto(in, first)
	pasteInto(in, second)

	if got, want := in.GetText(), "[Pasted 6 lines — paste again to expand][Pasted 6 lines — paste again to expand]"; got != want {
		t.Fatalf("visible buffer = %q, want two placeholders %q", got, want)
	}
	if got, want := submitTextOf(in), first+second; got != want {
		t.Fatalf("expandedText() = %q, want each placeholder expanded to its own paste %q", got, want)
	}
}

// TestInputField_SetTextClearsHiddenPasteState proves a whole-buffer SetText drops any
// tracked segments, so a later coincidental placeholder string is not expanded.
func TestInputField_SetTextClearsHiddenPasteState(t *testing.T) {
	in := newInput()
	pasteInto(in, "c1\nc2\nc3\nc4\nc5\nc6")
	if len(in.pastes) == 0 {
		t.Fatal("sanity: long paste should have tracked a segment")
	}
	in.SetText("[Pasted 6 lines — paste again to expand]")
	if got := submitTextOf(in); got != "[Pasted 6 lines — paste again to expand]" {
		t.Fatalf("expandedText() after SetText = %q, want the literal text (segments cleared)", got)
	}
}

// TestInputField_AdjustRowOffsetScrollsToTailOnOverflow pins tail-scroll on overflow:
// when the wrapped buffer exceeds the visible cap, adjustRowOffset scrolls so the
// caret's wrapped row (after a paste the caret is at the end, i.e. the tail) is the
// last visible row, instead of leaving the viewport pinned to the head.
func TestInputField_AdjustRowOffsetScrollsToTailOnOverflow(t *testing.T) {
	in := newInput()
	in.SetText(strings.Repeat("x\n", 19) + "x") // 20 single-row logical lines, caret at end
	const width, cap = 80, 8
	if got := in.wrappedRows(width); got != 20 {
		t.Fatalf("sanity: wrappedRows(%d) = %d, want 20", width, got)
	}

	in.adjustRowOffset(width, cap)

	// Caret on wrapped row 19 (0-based); to make it the last of cap visible rows the
	// offset is 19 - cap + 1 = 20 - cap, so rows 12..19 (the tail) show.
	row, _ := in.GetOffset()
	if want := 20 - cap; row != want {
		t.Fatalf("row offset on overflow = %d, want %d (tail visible at the bottom)", row, want)
	}
}

// TestInputField_AdjustRowOffsetPinsTopWhenFits preserves the first-row fix under the new signature:
// when the whole buffer fits the cap, adjustRowOffset resets the row offset to 0 so the
// first wrapped row stays visible even if tview left a stale non-zero offset.
func TestInputField_AdjustRowOffsetPinsTopWhenFits(t *testing.T) {
	in := newInput()
	in.SetText("a\nb\nc") // 3 wrapped rows, well within the cap
	const width, cap = 80, 8
	in.SetOffset(2, 0) // simulate tview's stale rowOffset after a wrap

	in.adjustRowOffset(width, cap)

	if row, _ := in.GetOffset(); row != 0 {
		t.Fatalf("row offset when content fits = %d, want 0 (first row pinned)", row)
	}
}

// testImg builds a minimal image attachment for the input-token tests.
func testImg(path string) imageAttachment {
	return imageAttachment{path: path, mime: "image/png", dataURI: "data:image/png;base64,AA=="}
}

// TestInputField_AttachmentsClearedOnSetText proves a whole-buffer SetText replace
// drops pending image tokens and their attachments alongside the text/paste state:
// they belong to the draft being replaced. A rejected submit never reaches SetText,
// so attachments survive there for a retry — covered by the app-level submit tests.
func TestInputField_AttachmentsClearedOnSetText(t *testing.T) {
	in := newInput()
	in.addAttachment(testImg("a.png"), "a.png")
	if len(in.imageAttachments()) != 1 {
		t.Fatal("precondition: attachment not added")
	}

	in.SetText("a new draft")

	if n := len(in.imageAttachments()); n != 0 {
		t.Errorf("attachments after SetText = %d, want 0 (cleared on a whole-buffer replace)", n)
	}
}

// TestInputField_AddAttachmentInsertsToken proves addAttachment inserts a "[<label>]" token
// at the caret and pins the attachment to it, so the visible buffer carries an editable
// token rather than the attachment living in a hidden slice.
func TestInputField_AddAttachmentInsertsToken(t *testing.T) {
	in := newInput()
	in.SetText("see ")
	in.Select(len("see "), len("see ")) // caret at end
	in.addAttachment(testImg("docs/diagram.png"), "diagram.png")

	if got, want := in.GetText(), "see [diagram.png]"; got != want {
		t.Errorf("buffer = %q, want %q (token inserted at caret)", got, want)
	}
	if n := len(in.imageAttachments()); n != 1 {
		t.Fatalf("attachments = %d, want 1", n)
	}
	text, atts := in.submitText()
	if got, want := strings.TrimSpace(text), "see"; got != want {
		t.Errorf("submit text = %q, want %q (token stripped)", got, want)
	}
	if len(atts) != 1 || atts[0].path != "docs/diagram.png" {
		t.Errorf("submit attachments = %+v, want the one diagram attachment", atts)
	}
}

// TestInputField_ClipboardTokenCounterMonotonic covers the per-prompt "[Image N]" counter:
// successive clipboard attachments are Image 1, 2, …; deleting an earlier token drops only
// its attachment and does not renumber survivors; the next attachment continues the count
// without reusing a number.
func TestInputField_ClipboardTokenCounterMonotonic(t *testing.T) {
	in := newInput()
	in.addAttachment(testImg("clip"), in.nextClipboardLabel()) // [Image 1]
	// Type a separator between attachments, as a user would between two pastes.
	in.Select(len(in.GetText()), len(in.GetText()))
	in.Replace(len(in.GetText()), len(in.GetText()), " and ")
	in.addAttachment(testImg("clip"), in.nextClipboardLabel()) // [Image 2]
	if got, want := in.GetText(), "[Image 1] and [Image 2]"; got != want {
		t.Fatalf("buffer = %q, want %q", got, want)
	}

	// Backspace the first token (delete its byte range): only its attachment drops.
	in.Replace(0, len("[Image 1]"), "")
	if got, want := in.GetText(), " and [Image 2]"; got != want {
		t.Fatalf("buffer after deleting [Image 1] = %q, want %q", got, want)
	}
	atts := in.imageAttachments()
	if len(atts) != 1 || atts[0].displayName() != "Image 2" {
		t.Fatalf("surviving attachments = %+v, want only Image 2 (no renumber)", atts)
	}

	// The next clipboard attachment is Image 3 — monotonic, no reuse of the freed 1.
	in.Select(len(in.GetText()), len(in.GetText()))
	in.addAttachment(testImg("clip"), in.nextClipboardLabel())
	if got, want := in.GetText(), " and [Image 2][Image 3]"; got != want {
		t.Errorf("buffer after third attachment = %q, want %q (monotonic counter)", got, want)
	}
}

// TestInputField_EditingTokenDropsAttachment proves editing a token's text (not deleting the
// whole range) drops the segment and its attachment, the same liveness rule paste segments
// follow — a token whose pinned range no longer holds its exact placeholder contributes
// nothing at submit.
func TestInputField_EditingTokenDropsAttachment(t *testing.T) {
	in := newInput()
	in.addAttachment(testImg("a.png"), "a.png")
	if len(in.imageAttachments()) != 1 {
		t.Fatal("precondition: token not added")
	}
	// Delete one byte inside the token so its range no longer matches "[a.png]".
	in.Replace(1, 2, "") // drop the 'a'
	if n := len(in.imageAttachments()); n != 0 {
		t.Errorf("attachments after editing the token = %d, want 0 (edited token drops its image)", n)
	}
	if _, atts := in.submitText(); len(atts) != 0 {
		t.Errorf("submit attachments after edit = %d, want 0", len(atts))
	}
}

// TestInputField_SetTextResetsClipboardCounter proves a whole-buffer replace resets the
// per-prompt counter so the next draft's first clipboard image is "[Image 1]" again.
func TestInputField_SetTextResetsClipboardCounter(t *testing.T) {
	in := newInput()
	in.addAttachment(testImg("clip"), in.nextClipboardLabel()) // Image 1
	in.SetText("")                                             // accepted-submit / clear
	in.addAttachment(testImg("clip"), in.nextClipboardLabel())
	if got, want := in.GetText(), "[Image 1]"; got != want {
		t.Errorf("buffer = %q, want %q (counter reset by SetText)", got, want)
	}
}

// TestInputField_TokensAndPasteCoexist proves the shared reconcile pass keeps an image token
// and a collapsed-paste placeholder pinned together: submitText expands the paste and strips
// the image token in one back-to-front pass, returning the attachment.
func TestInputField_TokensAndPasteCoexist(t *testing.T) {
	in := newInput()
	full := "p1\np2\np3\np4\np5\np6"
	pasteInto(in, full) // collapses to a placeholder at offset 0
	in.Select(len(in.GetText()), len(in.GetText()))
	in.addAttachment(testImg("a.png"), "a.png")

	text, atts := in.submitText()
	if text != full {
		t.Errorf("submit text = %q, want the expanded paste with the image token stripped (%q)", text, full)
	}
	if len(atts) != 1 || atts[0].path != "a.png" {
		t.Errorf("submit attachments = %+v, want the one image attachment", atts)
	}
}

func TestInputField_MultiByteEditRepinsBothSegmentKinds(t *testing.T) {
	in := newInput()
	full := "q1\nq2\nq3\nq4\nq5\nq6"
	pasteInto(in, full)
	in.Select(len(in.GetText()), len(in.GetText()))
	in.addAttachment(testImg("a.png"), "a.png")

	ph := pastePlaceholder(6)
	token := imageTokenLabel("a.png")
	if got, want := in.GetText(), ph+token; got != want {
		t.Fatalf("precondition: buffer = %q, want %q", got, want)
	}

	const prefix = "日本語 "
	in.Replace(0, 0, prefix)

	if len(in.pastes) != 1 || len(in.images) != 1 {
		t.Fatalf("after the edit: %d paste / %d image segments, want 1 each", len(in.pastes), len(in.images))
	}
	if got, want := [2]int{in.pastes[0].start, in.pastes[0].end}, [2]int{10, 10 + len(ph)}; got != want {
		t.Errorf("paste range = %v, want %v (shifted by 10 bytes, not 4 runes)", got, want)
	}
	if got, want := [2]int{in.images[0].start, in.images[0].end}, [2]int{10 + len(ph), 10 + len(ph) + len(token)}; got != want {
		t.Errorf("image range = %v, want %v (shifted by 10 bytes, not 4 runes)", got, want)
	}

	text, atts := in.submitText()
	if want := prefix + full; text != want {
		t.Errorf("submit text = %q, want %q (paste expanded, token stripped)", text, want)
	}
	if len(atts) != 1 || atts[0].path != "a.png" {
		t.Errorf("submit attachments = %+v, want the one image attachment", atts)
	}
}

func TestInputField_EditingOneSegmentKeepsTheOther(t *testing.T) {
	full := "r1\nr2\nr3\nr4\nr5\nr6"
	ph := pastePlaceholder(6)

	setup := func(t *testing.T) *inputField {
		t.Helper()
		in := newInput()
		pasteInto(in, full)
		in.Select(len(in.GetText()), len(in.GetText()))
		in.addAttachment(testImg("a.png"), "a.png")
		if len(in.pastes) != 1 || len(in.images) != 1 {
			t.Fatalf("precondition: %d paste / %d image segments, want 1 each", len(in.pastes), len(in.images))
		}
		return in
	}

	t.Run("edited token keeps the paste", func(t *testing.T) {
		in := setup(t)
		in.Replace(len(ph)+1, len(ph)+2, "")

		text, atts := in.submitText()
		if len(atts) != 0 {
			t.Errorf("submit attachments = %+v, want none (the edited token drops its image)", atts)
		}
		if want := full + "[.png]"; text != want {
			t.Errorf("submit text = %q, want %q (paste still expands beside the mangled token)", text, want)
		}
	})

	t.Run("edited placeholder keeps the attachment", func(t *testing.T) {
		in := setup(t)
		in.Replace(len(ph)-1, len(ph), "")

		text, atts := in.submitText()
		if strings.Contains(text, full) {
			t.Errorf("submit text = %q, must not splice in the dropped paste %q", text, full)
		}
		if want := ph[:len(ph)-1]; text != want {
			t.Errorf("submit text = %q, want the mangled placeholder %q with the token stripped", text, want)
		}
		if len(atts) != 1 || atts[0].path != "a.png" {
			t.Errorf("submit attachments = %+v, want the untouched image attachment", atts)
		}
	})
}

// The identical insertion is ambiguous, so the prior segment is dropped.
func TestInputField_AmbiguousDuplicatePlaceholderDropsSegment(t *testing.T) {
	in := newInput()
	first := "a1\na2\na3\na4\na5\na6"
	second := "b1\nb2\nb3\nb4\nb5\nb6"
	third := "c1\nc2\nc3\nc4\nc5\nc6"
	pasteInto(in, first)
	pasteInto(in, second)
	if len(in.pastes) != 2 {
		t.Fatalf("precondition: %d tracked segments, want 2", len(in.pastes))
	}

	pasteInto(in, third)

	ph := pastePlaceholder(6)
	if got, want := in.GetText(), ph+ph+ph; got != want {
		t.Fatalf("buffer = %q, want three identical placeholders", got)
	}
	if len(in.pastes) != 2 {
		t.Fatalf("tracked segments = %d, want 2 (the ambiguous first segment is dropped)", len(in.pastes))
	}
	if got, want := submitTextOf(in), ph+second+third; got != want {
		t.Errorf("expandedText() = %q, want %q (first placeholder left literal, the provable two expanded)", got, want)
	}
}

// cellFg draws the input on a fresh simulation screen and returns the foreground colors of
// the top rule, bottom rule, and the "› " prompt glyph, so the accent tests can assert all
// three are styled together. The rules span the top and bottom rows; the label glyph
// sits at the inner rect's first row, column 0.
func inputChromeColors(t *testing.T, in *inputField) (topRule, bottomRule, label tcell.Color) {
	t.Helper()
	const w, h = 20, 4
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	screen.SetSize(w, h)
	in.SetRect(0, 0, w, h)
	in.Draw(screen)
	fg := func(x, y int) tcell.Color {
		_, style, _ := screen.Get(x, y)
		c, _, _ := style.Decompose()
		return c
	}
	// Rules are drawn across the top (row 0) and bottom (row h-1) rows; the inner rect
	// starts at row 1, where tview draws the "› " label at column 0.
	return fg(2, 0), fg(2, h-1), fg(0, 1)
}

// TestInputField_ColorAccentStylesPromptAndRules pins the accent styling: applying each of the six palette
// accents styles the input's top rule, bottom rule, and prompt glyph together on a simulation
// screen.
func TestInputField_ColorAccentStylesPromptAndRules(t *testing.T) {
	// Independent oracle: the six required names pinned to their exact tcell constants, so a
	// dropped name, an added seventh name, or a remapped color fails rather than being
	// silently absorbed by ranging over the production map.
	cases := map[string]tcell.Color{
		"red":     tcell.ColorRed,
		"green":   tcell.ColorGreen,
		"yellow":  tcell.ColorYellow,
		"blue":    tcell.ColorBlue,
		"magenta": tcell.ColorFuchsia,
		"cyan":    tcell.ColorAqua,
	}
	if len(inputAccentPalette) != len(cases) {
		t.Fatalf("inputAccentPalette has %d names, want %d", len(inputAccentPalette), len(cases))
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := inputAccentPalette[name]
			if !ok {
				t.Fatalf("inputAccentPalette missing required name %q", name)
			}
			if got != want {
				t.Fatalf("inputAccentPalette[%q] = %v, want %v", name, got, want)
			}
			in := newInput()
			in.applyAccent(got)
			top, bottom, label := inputChromeColors(t, in)
			if top != want {
				t.Errorf("top rule = %v, want %v", top, want)
			}
			if bottom != want {
				t.Errorf("bottom rule = %v, want %v", bottom, want)
			}
			if label != want {
				t.Errorf("prompt glyph = %v, want %v", label, want)
			}
		})
	}
}

// TestInputField_FreshDefaultAppearance pins the default appearance: a freshly constructed input renders the
// terminal-default rules and the teal brand prompt glyph until an accent is applied.
func TestInputField_FreshDefaultAppearance(t *testing.T) {
	in := newInput()
	if in.accented {
		t.Fatal("fresh input should start unaccented")
	}
	top, bottom, label := inputChromeColors(t, in)
	if top != tcell.ColorDefault || bottom != tcell.ColorDefault {
		t.Errorf("fresh rules = %v/%v, want terminal default", top, bottom)
	}
	if label != promptLabelColor {
		t.Errorf("fresh prompt glyph = %v, want teal default %v", label, promptLabelColor)
	}
}

// TestInputField_SessionBadgeDrawsOnTheTopRule is the rendered oracle the badge's text seam
// cannot be: only drawn cells show which row the name lands on and that the rule survives it.
func TestInputField_SessionBadgeDrawsOnTheTopRule(t *testing.T) {
	const w, h = 40, 4
	topRow := func(in *inputField) string {
		t.Helper()
		return string([]rune(screenText(drawPrimitive(t, in, w, h)))[:w])
	}

	in := newInput()
	if got, want := topRow(in), strings.Repeat("─", w); got != want {
		t.Errorf("unnamed session top rule = %q, want the bare rule %q", got, want)
	}

	in.setSessionName("My session")
	badge := " My session "
	want := strings.Repeat("─", w-len([]rune(badge))-sessionBadgeRightMargin) + badge + strings.Repeat("─", sessionBadgeRightMargin)
	if got := topRow(in); got != want {
		t.Errorf("top rule = %q, want the badge right-aligned inside the margin: %q", got, want)
	}

	in.applyAccent(tcell.ColorFuchsia)
	screen := drawPrimitive(t, in, w, h)
	if got := string([]rune(screenText(screen))[:w]); got != want {
		t.Errorf("accented top rule = %q, want the badge placed as before: %q", got, want)
	}
	str, style, _ := screen.Get(w-sessionBadgeRightMargin-2, 0)
	if str != "n" {
		t.Fatalf("cell %d of the top rule = %q, want the last rune of the drawn name", w-sessionBadgeRightMargin-2, str)
	}
	if fg, _, _ := style.Decompose(); fg != tcell.ColorFuchsia {
		t.Errorf("badge foreground = %v, want the applied accent %v", fg, tcell.ColorFuchsia)
	}

	in.setSessionName("work [red]zone")
	if got := topRow(in); !strings.Contains(got, "work [red]zone") {
		t.Errorf("top rule = %q, want a bracketed name drawn literally rather than read as a color tag", got)
	}
}

// TestNewApp_InputAccentNotPersisted pins the run-scoped accent: a fresh App's input carries no accent, and
// ApplyInputAccent sets the run-scoped accent and requests a redraw.
func TestNewApp_InputAccentNotPersisted(t *testing.T) {
	a := New(nil)
	if a.input.accented {
		t.Fatal("fresh App input should start unaccented")
	}
	drew := false
	a.draw = func() { drew = true }
	a.ApplyInputAccent(inputAccentPalette["red"])
	if !a.input.accented || a.input.accent != tcell.ColorRed {
		t.Fatalf("ApplyInputAccent did not set the red accent (accented=%v color=%v)", a.input.accented, a.input.accent)
	}
	if !drew {
		t.Error("ApplyInputAccent did not request a redraw")
	}
}
