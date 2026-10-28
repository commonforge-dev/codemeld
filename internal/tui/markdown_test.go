// Tests for the inline-markdown renderer and its transcript finalize wiring.
package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rivo/tview"
)

var (
	rawCopyLine         = "\n" + codeControlIndent + statusCopyControlTag + tview.Escape(statusCopyControl) + defaultTag + underlineOffTag
	visibleCopyLine     = "\n" + codeControlIndent + statusCopyControl
	rawResponseLine     = "\n" + codeControlIndent + statusCopyControlTag + tview.Escape(responseCopyControl) + defaultTag + underlineOffTag
	visibleResponseLine = "\n" + codeControlIndent + responseCopyControl
)

// codeRegions drops the response-level control every sealed block ends with, leaving the
// fenced-block regions under test.
func codeRegions(regions []clickRegion) []clickRegion {
	var out []clickRegion
	for _, r := range regions {
		if !r.response {
			out = append(out, r)
		}
	}
	return out
}

func responseRegions(regions []clickRegion) []clickRegion {
	var out []clickRegion
	for _, r := range regions {
		if r.response {
			out = append(out, r)
		}
	}
	return out
}

func controlBodies(controls []codeControl) []string {
	var bodies []string
	for _, c := range controls {
		bodies = append(bodies, c.body)
	}
	return bodies
}

func TestRenderMarkdown_InlineElements(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "bold and inline code",
			src:  "**bold** and `code`",
			want: "[::b]bold[-:-:-] and [#4e9a06]code[-:-:-]",
		},
		{
			name: "italic",
			src:  "*italic*",
			want: "[::i]italic[-:-:-]",
		},
		{
			name: "bold italic",
			src:  "***both***",
			want: "[::bi]both[-:-:-]",
		},
		{
			name: "code inside bold is one combined absolute tag",
			src:  "**`code`**",
			want: "[#4e9a06::b]code[-:-:-]",
		},
		{
			name: "plain text carries no tags",
			src:  "just words",
			want: "just words",
		},
		{
			name: "bold then adjacent code resets between styled runs",
			src:  "**b**`c`",
			want: "[::b]b[-:-:-][#4e9a06]c[-:-:-]",
		},
		{
			name: "code then text inside bold returns to plain bold",
			src:  "**a `b` c**",
			want: "[::b]a [-:-:-][#4e9a06::b]b[-:-:-][::b] c[-:-:-]",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _, _ := renderMarkdown(tc.src); got != tc.want {
				t.Errorf("renderMarkdown(%q) = %q, want %q", tc.src, got, tc.want)
			}
		})
	}
}

// TestRenderMarkdown_InjectionSafety proves that bracket sequences and asterisks
// that are not inline-markdown styling render literally: the result carries no
// live style tag, so the visible text equals the input verbatim. goldmark
// fragments the failed link "[red]" into separate text nodes, so this also guards
// the regression where per-fragment escaping let the brackets reassemble into a
// live tview color tag.
//
// NB: the original Done-when wrote this input as "see [red] and 2*3*4", but goldmark
// (a CommonMark parser, as the task mandates) parses the intraword "*3*" as
// emphasis — see TestRenderMarkdown_IntrawordAsterisksAreEmphasis — so the
// asterisks there cannot render literally without abandoning the parser. The
// spaced "2 * 3 * 4" is the faithful representative of "asterisks in non-markdown
// positions": the delimiters are not flanking, so no emphasis is produced.
func TestRenderMarkdown_InjectionSafety(t *testing.T) {
	src := "see [red] and 2 * 3 * 4"
	got, _, _ := renderMarkdown(src)
	if strings.Contains(got, defaultTag) || strings.Contains(got, codeColor) || strings.Contains(got, "[::") {
		t.Fatalf("renderMarkdown(%q) = %q, want no live style tag", src, got)
	}
	// The [red] bracket is escaped (tview.Escape inserts the opening-bracket guard),
	// so it is inert under dynamic colors but resolves back to the literal text.
	if want := "see [red[] and 2 * 3 * 4"; got != want {
		t.Fatalf("renderMarkdown(%q) = %q, want %q", src, got, want)
	}

	// A lone (unpaired) backtick opens no code span, so it renders literally with no
	// foreground accent (Done-when 3 covers backticks in non-markdown positions too).
	const tick = "use the ` key"
	if gotTick, _, _ := renderMarkdown(tick); gotTick != tick {
		t.Fatalf("renderMarkdown(%q) = %q, want the literal backtick unchanged", tick, gotTick)
	}
}

// TestTranscript_FinalizeRendersInjectionInputLiterally proves the injection-safety
// Done-when at the real rendering surface, not just renderMarkdown's string: a finalized
// reply whose text carries a failed link "[red]", spaced non-markdown asterisks, and a lone
// backtick renders literally through the dynamic-color TextView. GetText(true) (tags
// stripped, escapes resolved) returns the input verbatim — so the escaped "[red]" stays
// inert yet resolves back to literal brackets — and GetText(false) carries no intentional
// markdown style tag, so nothing in the input was parsed as styling. This readback is what
// the string-level TestRenderMarkdown_InjectionSafety cannot give: only the TextView proves
// a bad escape would surface (dropping "[red]" from the visible text). Removing the
// tview.Escape call in renderMarkdown's flush path makes the GetText(true) assertion fail.
func TestTranscript_FinalizeRendersInjectionInputLiterally(t *testing.T) {
	const src = "see [red] and 2 * 3 * 4 and use the ` key"
	tr := newTranscript()
	tr.appendDelta(src)
	tr.finalize()

	if got, want := tr.view.GetText(true), src+visibleResponseLine; got != want {
		t.Fatalf("GetText(true) = %q, want the literal input %q", got, want)
	}
	raw := tr.view.GetText(false)
	if body := strings.TrimSuffix(raw, rawResponseLine); strings.Contains(body, defaultTag) || strings.Contains(body, codeColor) || strings.Contains(body, "[::") {
		t.Fatalf("GetText(false) = %q, want no live style tag for non-markdown input", raw)
	}
}

// TestRenderMarkdown_IntrawordAsterisksAreEmphasis documents the goldmark/CommonMark
// behavior that drove the injection-test input change: "2*3*4" (no surrounding
// spaces) is left- and right-flanking, so "*3*" opens and closes emphasis and the
// "3" renders italic. The bracket is still escaped; only the asterisks are consumed.
func TestRenderMarkdown_IntrawordAsterisksAreEmphasis(t *testing.T) {
	got, _, _ := renderMarkdown("see [red] and 2*3*4")
	if want := "see [red[] and 2[::i]3[-:-:-]4"; got != want {
		t.Fatalf("renderMarkdown(%q) = %q, want %q", "see [red] and 2*3*4", got, want)
	}
}

func TestRenderMarkdown_FencedCodeBlockStyled(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "literal markdown inside is not re-parsed",
			src:  "```\n*not* `code`\n```",
			want: codeBlockTag + "*not* `code`" + defaultTag + rawCopyLine,
		},
		{
			name: "each content line is its own filled run",
			src:  "```go\nline1\nline2\n```",
			want: codeBlockTag + "line1" + defaultTag + "\n" + codeBlockTag + "line2" + defaultTag + rawCopyLine,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := renderMarkdown(tc.src)
			if got != tc.want {
				t.Fatalf("renderMarkdown(%q) = %q, want %q", tc.src, got, tc.want)
			}
			if !strings.Contains(got, codeBlockFill) {
				t.Fatalf("renderMarkdown(%q) = %q, want code lines painted with the block fill %s", tc.src, got, codeBlockFill)
			}
			if body := strings.TrimSuffix(got, rawCopyLine); strings.Contains(body, "[::") {
				t.Fatalf("renderMarkdown(%q) = %q, want no emphasis tags inside the code block", tc.src, got)
			}
		})
	}
}

func TestRenderMarkdown_FencedCodeBlockTagIsForegroundAndBackground(t *testing.T) {
	if want := "[" + codeBlockText + ":" + codeBlockFill + "]"; codeBlockTag != want {
		t.Fatalf("codeBlockTag = %q, want a foreground:background tag %q", codeBlockTag, want)
	}
	if codeBlockFill == "" || codeBlockText == codeBlockFill {
		t.Fatalf("codeBlockText/codeBlockFill = %q/%q, want a distinct non-empty pair", codeBlockText, codeBlockFill)
	}
	got, _, _ := renderMarkdown("`inline`")
	if want := "[" + codeColor + "]inline" + defaultTag; got != want {
		t.Fatalf("renderMarkdown(\"`inline`\") = %q, want the unchanged foreground-only inline accent %q", got, want)
	}
}

func TestRenderMarkdown_FencedCodeBlockResetsPrecedingInlineStyle(t *testing.T) {
	src := "**bold**\n\n```go\ncode\n```\n\nafter *it*"
	got, _, _ := renderMarkdown(src)
	want := "[::b]bold" + defaultTag + "\n\n" + codeBlockTag + "code" + defaultTag + rawCopyLine + "\n\nafter [::i]it" + defaultTag
	if got != want {
		t.Fatalf("renderMarkdown(%q) = %q, want %q", src, got, want)
	}
	if strings.Contains(got, "["+codeBlockText+":"+codeBlockFill+":") {
		t.Fatalf("renderMarkdown(%q) = %q, want the code body in the block style only, not carrying the preceding bold flag", src, got)
	}
}

func TestRenderMarkdown_EmptyFencedCodeBlockStaysVisible(t *testing.T) {
	t.Run("wholly empty block", func(t *testing.T) {
		got, _, _ := renderMarkdown("```\n```")
		want := codeBlockTag + codeBlockBlankLine + defaultTag + rawCopyLine
		if got != want {
			t.Fatalf("renderMarkdown(\"```\\n```\") = %q, want a filled blank line %q", got, want)
		}
	})
	t.Run("blank-only block", func(t *testing.T) {
		got, _, _ := renderMarkdown("```\n\n\n```")
		want := codeBlockTag + codeBlockBlankLine + defaultTag +
			"\n" + codeBlockTag + codeBlockBlankLine + defaultTag + rawCopyLine
		if got != want {
			t.Fatalf("renderMarkdown = %q, want every line of a blank-only block filled: %q", got, want)
		}
	})
	t.Run("blank line inside a block stays literal", func(t *testing.T) {
		got, _, _ := renderMarkdown("```\na\n\nb\n```")
		want := codeBlockTag + "a" + defaultTag +
			"\n" + codeBlockTag + defaultTag +
			"\n" + codeBlockTag + "b" + defaultTag + rawCopyLine
		if got != want {
			t.Fatalf("renderMarkdown = %q, want the interior blank line left empty: %q", got, want)
		}
	})
}

func TestTranscript_FinalizeRendersEmptyFencedBlockAsBoundedLine(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```\n```")
	tr.finalize()

	if raw := tr.view.GetText(false); !strings.Contains(raw, codeBlockFill) {
		t.Fatalf("GetText(false) = %q, want the empty block painted with the block fill", raw)
	}
	if got, want := tr.view.GetText(true), codeBlockBlankLine+visibleCopyLine+visibleResponseLine; got != want {
		t.Fatalf("GetText(true) = %q, want the bounded blank line %q", got, want)
	}
}

func TestTranscript_FinalizeRendersBlockWithBlankLineVerbatim(t *testing.T) {
	const body = "func a() {}\n\nfunc b() {}"
	tr := newTranscript()
	tr.appendDelta("```go\n" + body + "\n```")
	tr.finalize()

	if got, want := tr.view.GetText(true), body+visibleCopyLine; got != want {
		t.Fatalf("GetText(true) = %q, want the blank line copied as-is %q", got, want)
	}
}

func TestTranscript_FinalizeRendersMultilineFencedBlockVerbatim(t *testing.T) {
	const body = "cd /tmp\nmake build\n./out --flag=1"
	tr := newTranscript()
	tr.appendDelta("```sh\n" + body + "\n```")
	tr.finalize()

	if got, want := tr.view.GetText(true), body+visibleCopyLine; got != want {
		t.Fatalf("GetText(true) = %q, want the copyable body verbatim %q", got, want)
	}
	raw := tr.view.GetText(false)
	if n := strings.Count(raw, codeBlockTag); n != 3 {
		t.Fatalf("GetText(false) = %q, want one %s per body line (3), got %d", raw, codeBlockTag, n)
	}
}

// TestTranscript_CopyControlUnderlineStopsAtTheControl draws the finalized transcript
// and reads applied cell styles, which is the only way to see the clear: raw markup
// cannot distinguish an underline that ended from one tview never turned off.
func TestTranscript_CopyControlUnderlineStopsAtTheControl(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```sh\nmake build\n```\n\nafter the block")
	tr.finalize()

	screen := drawPrimitive(t, tr.view, 80, 30)
	if got, want := underlinedText(screen), statusCopyControl+responseCopyControl; got != want {
		t.Errorf("underlined cells spell %q, want exactly the two controls %q", got, want)
	}
}

func TestTranscript_FinalizeRendersTviewLikeBlockContentLiterally(t *testing.T) {
	const body = "[red]alert[-] **bold** `tick` [#ffffff:#000000]"
	tr := newTranscript()
	tr.appendDelta("```\n" + body + "\n```")
	tr.finalize()

	if got, want := tr.view.GetText(true), body+visibleCopyLine; got != want {
		t.Fatalf("GetText(true) = %q, want the markup-like body literally %q", got, want)
	}
	raw := tr.view.GetText(false)
	stripped := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSuffix(raw, rawCopyLine), codeBlockTag, ""), defaultTag, "")
	if strings.Contains(stripped, "[::") || strings.Contains(stripped, "["+codeColor+"]") {
		t.Fatalf("GetText(false) = %q, want no styling parsed out of the block body", raw)
	}
}

// TestRenderMarkdown_BlockElements covers the block nodes at the string level:
// headings render bold with the '#' markers dropped; bullet/ordered/nested lists get
// their "• "/"N. " prefixes preserving order and nesting; blockquotes prefix every
// line with "│ "; and inline styling still applies inside each block.
func TestRenderMarkdown_BlockElements(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "heading renders bold without markers",
			src:  "# Title",
			want: "[::b]Title[-:-:-]",
		},
		{
			name: "inline bold inside heading stays bold",
			src:  "## Section **two**",
			want: "[::b]Section two[-:-:-]",
		},
		{
			name: "bullet list",
			src:  "- one\n- two",
			want: `["h:ss"]• one` + "\n" + `["h:ss"]• two`,
		},
		{
			name: "ordered list numbers from one",
			src:  "1. a\n2. b",
			want: `["h:sss"]1. a` + "\n" + `["h:sss"]2. b`,
		},
		{
			name: "ordered list honors start offset",
			src:  "3. a\n4. b",
			want: `["h:sss"]3. a` + "\n" + `["h:sss"]4. b`,
		},
		{
			name: "nested list is indented",
			src:  "- a\n  - b",
			want: `["h:ss"]• a` + "\n" + `["h:ssss"]  • b`,
		},
		{
			name: "inline bold inside bullet item",
			src:  "- **x** y",
			want: `["h:ss"]• [::b]x[-:-:-] y`,
		},
		{
			name: "blockquote prefixes every line",
			src:  "> alpha\n> beta",
			want: `["h:bs"]│ alpha` + "\n" + `["h:bs"]│ beta`,
		},
		{
			name: "inline bold inside blockquote",
			src:  "> **q**",
			want: `["h:bs"]│ [::b]q[-:-:-]`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _, _ := renderMarkdown(tc.src); got != tc.want {
				t.Errorf("renderMarkdown(%q) = %q, want %q", tc.src, got, tc.want)
			}
		})
	}
}

// TestRenderMarkdown_IndentedCodeBlockRendersAsPlainText proves an indented (4-space)
// code block — a CommonMark block node out of scope for inline styling — renders its body
// as escaped plain text rather than being dropped. Like a fenced block, its body lives in
// source line segments, not child text nodes, so the generic block path would otherwise
// emit only a separator. No style tags are added: only fenced code blocks are styled.
func TestRenderMarkdown_IndentedCodeBlockRendersAsPlainText(t *testing.T) {
	src := "    fmt.Println(\"hi\")\n"
	got, _, _ := renderMarkdown(src)
	if !strings.Contains(got, `fmt.Println("hi")`) {
		t.Fatalf("renderMarkdown(%q) = %q, want the code body as plain text", src, got)
	}
	if strings.Contains(got, codeColor) || strings.Contains(got, "[::") || strings.Contains(got, codeBlockFill) {
		t.Fatalf("renderMarkdown(%q) = %q, want no style tags on an indented code block (only fenced blocks carry the copyable-block boundary)", src, got)
	}
}

// TestRenderMarkdown_IndentedCodeBlockResetsPrecedingInlineStyle proves an indented code
// block following a styled inline run renders plain: the styled run is closed back to the
// default tag before the body, so the body cannot inherit the preceding bold/code style.
// The body is written raw (not through flush), so without the reset the bold run would
// bleed into the code block.
func TestRenderMarkdown_IndentedCodeBlockResetsPrecedingInlineStyle(t *testing.T) {
	src := "**bold**\n\n    fmt.Println(\"hi\")\n"
	got, _, _ := renderMarkdown(src)

	bodyIdx := strings.Index(got, `fmt.Println("hi")`)
	if bodyIdx < 0 {
		t.Fatalf("renderMarkdown(%q) = %q, want the code body as plain text", src, got)
	}
	// The bold run must be closed back to default before the body is written.
	resetIdx := strings.LastIndex(got[:bodyIdx], defaultTag)
	if resetIdx < 0 {
		t.Fatalf("renderMarkdown(%q) = %q, want a %s reset before the indented body", src, got, defaultTag)
	}
	// Nothing between the reset and the body may re-open a style, or the body would
	// render bold/light-green instead of plain text.
	if between := got[resetIdx+len(defaultTag) : bodyIdx]; strings.Contains(between, "[::") || strings.Contains(between, codeColor) {
		t.Fatalf("renderMarkdown(%q) = %q, want no style tag between the reset and the indented body, got %q", src, got, between)
	}
}

// TestTranscript_FinalizeRendersIndentedCodeBlockAsPlainText proves a finalized reply
// containing an indented code block commits the code body through renderMarkdown as plain
// text: the tags-stripped view text includes the body, and the raw view text carries no
// code-block style tags (block styling is out of scope for inline markdown).
func TestTranscript_FinalizeRendersIndentedCodeBlockAsPlainText(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("    fmt.Println(\"hi\")\n")
	tr.finalize()

	if got := tr.view.GetText(true); !strings.Contains(got, `fmt.Println("hi")`) {
		t.Fatalf("GetText(true) = %q, want the indented code body as plain text", got)
	}
	raw := tr.view.GetText(false)
	if body := strings.TrimSuffix(raw, rawResponseLine); strings.Contains(body, codeColor) || strings.Contains(body, "[::") || strings.Contains(body, codeBlockFill) {
		t.Fatalf("GetText(false) = %q, want no code-block style tags on an indented block", raw)
	}
}

func TestTranscript_FinalizeRendersFencedCodeBlockStyled(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```go\nfmt.Println(\"hi\")\n```")
	tr.finalize()

	if got := tr.view.GetText(true); !strings.Contains(got, `fmt.Println("hi")`) {
		t.Fatalf("GetText(true) = %q, want the fenced code body verbatim", got)
	}
	raw := tr.view.GetText(false)
	if !strings.Contains(raw, codeBlockTag) {
		t.Fatalf("GetText(false) = %q, want the code body wrapped in %s", raw, codeBlockTag)
	}
	if strings.Contains(raw, "["+codeColor+"]") {
		t.Fatalf("GetText(false) = %q, want the block treatment, not the inline-code foreground", raw)
	}
}

func TestTranscript_FinalizeSeparatesBlockFromSurroundingProse(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("run this:\n\n```sh\nmake build\n```\n\nthen check the output")
	tr.finalize()

	raw := tr.view.GetText(false)
	styled := codeBlockTag + "make build" + defaultTag
	start := strings.Index(raw, styled)
	if start < 0 {
		t.Fatalf("GetText(false) = %q, want the block styled and closed as %q", raw, styled)
	}
	if before := raw[:start]; strings.Contains(before, codeBlockTag) || !strings.Contains(before, "run this:") {
		t.Fatalf("prose before the block = %q, want the unstyled leading paragraph", before)
	}
	after := raw[start+len(styled):]
	if strings.Contains(after, codeBlockTag) || !strings.Contains(after, "then check the output") {
		t.Fatalf("prose after the block = %q, want the unstyled trailing paragraph", after)
	}
	if got, want := tr.view.GetText(true), "run this:\n\nmake build"+visibleCopyLine+"\n\nthen check the output"+visibleResponseLine; got != want {
		t.Fatalf("GetText(true) = %q, want %q", got, want)
	}
}

func TestTranscript_MarkInterruptedRendersFencedBlockWithLiteralMarker(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```sh\nmake build\n```")
	tr.markInterrupted()

	if got, want := tr.view.GetText(true), "make build"+visibleCopyLine+streamInterruptedMarker; got != want {
		t.Fatalf("GetText(true) = %q, want %q (literal marker suffix)", got, want)
	}
	raw := tr.view.GetText(false)
	if !strings.Contains(raw, codeBlockTag) {
		t.Fatalf("GetText(false) = %q, want the interrupted reply's block styled the same way", raw)
	}
	markerIdx := strings.Index(raw, "interrupted")
	if markerIdx < 0 {
		t.Fatalf("GetText(false) = %q, want the interrupted marker present", raw)
	}
	if !strings.Contains(raw[:markerIdx], defaultTag) {
		t.Fatalf("GetText(false) = %q, want the block closed back to %s before the marker", raw, defaultTag)
	}
}

func TestTranscript_FinalizeResponseControlOnlyWhenPayloadDiffersFromLoneBlock(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		wantResponse bool
	}{
		{"lone fenced block", "```sh\nmake build\n```", false},
		{"lone multiline block", "```\na\nb\n```", false},
		{"prose before the block", "run:\n\n```sh\nmake build\n```", true},
		{"prose after the block", "```sh\nmake build\n```\n\ndone", true},
		{"two fenced blocks", "```\na\n```\n\n```\nb\n```", true},
		{"extra trailing blank line in the body", "```\nline\n\n```", true},
		{"two extra trailing blank lines in the body", "```\nline\n\n\n```", true},
		{"empty block", "```\n```", true},
		{"blank-only block", "```\n\n```", true},
		{"whitespace-only block", "```\n   \n```", true},
		{"trailing whitespace-only blank line in the body", "```\nline\n  \n```", true},
		{"block in a list item", "- ```sh\n  make build\n  ```", true},
		{"block in a blockquote", "> ```sh\n> make build\n> ```", true},
		{"no fenced block", "plain prose", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTranscript()
			tr.appendDelta(tc.src)
			tr.finalize()

			controls := tr.codeControls[len(tr.codeControls)-1]
			var response []codeControl
			for _, c := range controls {
				if c.response {
					response = append(response, c)
				}
			}
			if !tc.wantResponse {
				if len(response) != 0 || strings.Contains(tr.view.GetText(true), responseCopyControl) {
					t.Fatalf("GetText(true) = %q, want no %s on a lone block", tr.view.GetText(true), responseCopyControl)
				}
				return
			}
			_, _, payload := renderMarkdown(tc.src)
			if len(response) != 1 || response[0].body != payload {
				t.Fatalf("response controls = %+v, want one carrying the projection %q", response, payload)
			}
			if got := tr.view.GetText(true); !strings.HasSuffix(got, visibleResponseLine) {
				t.Fatalf("GetText(true) = %q, want it to end with %q", got, visibleResponseLine)
			}
		})
	}
}

func TestTranscript_InterruptedWhitespaceBlockKeepsResponseControl(t *testing.T) {
	for _, src := range []string{"```\n   \n```", "```\nline\n  \n```"} {
		tr := newTranscript()
		tr.appendDelta(src)
		tr.markInterrupted()

		_, _, payload := renderMarkdown(src)
		controls := tr.codeControls[len(tr.codeControls)-1]
		if len(controls) != 2 || !controls[1].response || controls[1].body != payload {
			t.Fatalf("%q: controls = %+v, want the block control and a response control carrying %q", src, controls, payload)
		}
	}
}

func TestTranscript_FinalizeBlankReplyShowsNoResponseControl(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("  \n")
	tr.finalize()

	if got := tr.view.GetText(true); strings.Contains(got, responseCopyControl) {
		t.Fatalf("GetText(true) = %q, want no %s on a blank reply", got, responseCopyControl)
	}
}

// TestRenderMarkdown_FencedBlockCarriesSourceBody proves the click payload comes from
// the source, not the display cells: the bodies come back in document order, one per
// closed fenced block, and every control reaches the output escaped so the dynamic-color
// view draws it instead of swallowing it as a style tag.
func TestRenderMarkdown_FencedBlockCarriesSourceBody(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "markdown-like body stays source-faithful",
			src:  "```\n*not* `code`\n[red]\n```",
			want: []string{"*not* `code`\n[red]\n"},
		},
		{
			name: "the newline before the closing fence belongs to the body",
			src:  "```\nline\n```",
			want: []string{"line\n"},
		},
		{
			name: "a trailing blank line before the closing fence is kept",
			src:  "```\nline\n\n```",
			want: []string{"line\n\n"},
		},
		{
			name: "an interior blank line is not display-padded",
			src:  "```\na\n\nb\n```",
			want: []string{"a\n\nb\n"},
		},
		{
			name: "a blank-only body keeps its own lines",
			src:  "```\n\n\n```",
			want: []string{"\n\n"},
		},
		{
			name: "two blocks come back in document order",
			src:  "```\nfirst\n```\n\ntext\n\n```sh\nsecond\n```",
			want: []string{"first\n", "second\n"},
		},
		{
			name: "an indented code block gets no control",
			src:  "    indented\n",
			want: nil,
		},
		{
			name: "an inline code span gets no control",
			src:  "an `inline` span",
			want: nil,
		},
		{
			name: "a fence that never closes gets no control",
			src:  "```sh\nmake build",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, controls, _ := renderMarkdown(tc.src)
			if bodies := controlBodies(controls); fmt.Sprint(bodies) != fmt.Sprint(tc.want) {
				t.Fatalf("renderMarkdown(%q) bodies = %q, want %q", tc.src, bodies, tc.want)
			}
			if n := strings.Count(got, tview.Escape(statusCopyControl)); n != len(tc.want) {
				t.Fatalf("renderMarkdown(%q) = %q, want %d escaped controls", tc.src, got, len(tc.want))
			}
			if strings.Contains(got, statusCopyControl) {
				t.Fatalf("renderMarkdown(%q) = %q, want no unescaped control (the view would swallow it)", tc.src, got)
			}
		})
	}
}

// TestRenderMarkdown_CopyControlSitsTwoColumnsPastContainerPrefix pins the placement as a
// fixed offset from the container prefix rather than an absolute column: the prefix widens
// with nesting, and the list marker — which shares the block's opening row but never enters
// the prefix — must not move the control.
func TestRenderMarkdown_CopyControlSitsTwoColumnsPastContainerPrefix(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"top-level block", "```sh\na\nb\n```"},
		{"blockquoted block", "> ```sh\n> a\n> b\n> ```"},
		{"unordered list item", "- ```sh\n  a\n  b\n  ```"},
		{"multi-digit ordered item", "10. ```sh\n    a\n    b\n    ```"},
		{"list nested in a blockquote", "> - ```sh\n>   a\n>   b\n>   ```"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTranscript()
			tr.appendDelta(tc.src)
			tr.finalize()

			text := strings.TrimSuffix(tr.view.GetText(true), visibleResponseLine)
			lines := strings.Split(text, "\n")
			if len(lines) < 2 {
				t.Fatalf("GetText(true) = %q, want a body line above the control line", text)
			}
			// The block's second body line carries curPrefix() and nothing else, so the
			// renderer supplies the prefix the control is measured against.
			prefix, ok := strings.CutSuffix(lines[len(lines)-2], "b")
			if !ok {
				t.Fatalf("GetText(true) = %q, want %q to be the block's second body line", text, lines[len(lines)-2])
			}
			if got, want := lines[len(lines)-1], prefix+codeControlIndent+statusCopyControl; got != want {
				t.Errorf("control line = %q, want %q", got, want)
			}
		})
	}
}

// TestRenderMarkdown_ResponseProjection pins the payload a whole-reply copy emits. Text
// the model itself wrote that reads like a control is ordinary content and stays, so the
// exclusion of generated controls cannot be label matching.
func TestRenderMarkdown_ResponseProjection(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "prose around a fenced block",
			src:  "run this:\n\n```sh\nmake build\n```\n\nthen check it",
			want: "run this:\n\nmake build\n\nthen check it",
		},
		{
			name: "inline markdown copies as its display text",
			src:  "# Title\n\n**bold** and `code`",
			want: "Title\n\nbold and code",
		},
		{
			name: "authored control labels are ordinary content",
			src:  statusCopyControl + " and " + responseCopyControl,
			want: statusCopyControl + " and " + responseCopyControl,
		},
		{
			name: "a body that reads as a control keeps its own text",
			src:  "```\n" + statusCopyControl + "\n```",
			want: statusCopyControl,
		},
		{
			name: "an unclosed final fence keeps the body it did receive",
			src:  "```sh\nmake bu",
			want: "make bu",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rendered, controls, projection := renderMarkdown(tc.src)
			if projection != tc.want {
				t.Fatalf("renderMarkdown(%q) projection = %q, want %q", tc.src, projection, tc.want)
			}
			if strings.Contains(rendered, rawResponseLine) {
				t.Fatalf("renderMarkdown(%q) = %q, want no response control drawn by the renderer", tc.src, rendered)
			}
			for _, c := range controls {
				if c.response {
					t.Fatalf("renderMarkdown(%q) controls = %+v, want no response control armed by the renderer", tc.src, controls)
				}
			}
		})
	}
}

// TestTranscript_StreamingResponseArmsNoResponseControl covers both live renders,
// including the fully arrived fence opener that sends the whole unsealed buffer through
// renderMarkdown — the path that would otherwise arm the control early.
func TestTranscript_StreamingResponseArmsNoResponseControl(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"a closed fence and more prose arriving", "```sh\nmake build\n```\n\nstill go"},
		{"a fence opener that has fully arrived", "```sh\nmake bu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTranscript()
			tr.appendDelta(tc.src)

			if got := tr.view.GetText(true); strings.Contains(got, responseCopyControl) {
				t.Fatalf("GetText(true) = %q, want no response control while the reply streams", got)
			}
			if got := responseRegions(tr.controls.all); len(got) != 0 {
				t.Fatalf("response regions = %+v, want none while the reply streams", got)
			}

			tr.finalize()
			if got := responseRegions(tr.controls.all); len(got) != 1 {
				t.Fatalf("response regions after finalize = %+v, want exactly one", got)
			}
		})
	}
}

func TestTranscript_StreamingClosedFenceKeepsItsCodeControl(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```sh\nmake build\n```\n\nstill go")

	if got := codeRegions(tr.controls.all); len(got) != 1 || got[0].payload != "make build\n" {
		t.Fatalf("code regions = %+v, want one carrying the closed fence body", got)
	}
}

// TestTranscript_MarkInterruptedOpenFenceExposesNoControl proves a reply cut off inside a
// fence exposes nothing to click: goldmark closes the block at end of source, but the
// snippet is truncated, so neither the control nor a payload survives.
func TestTranscript_MarkInterruptedOpenFenceExposesNoControl(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```sh\nmake bu")
	tr.markInterrupted()

	if got := tr.view.GetText(true); strings.Contains(got, statusCopyControl) {
		t.Fatalf("GetText(true) = %q, want no control below a fence that never closed", got)
	}
	if got := codeRegions(tr.controls.all); len(got) != 0 {
		t.Fatalf("click regions = %+v, want none for a truncated block", got)
	}
	// The interruption is still a sealed response, so the whole-reply control is armed
	// even though the fence under it never closed.
	if got := responseRegions(tr.controls.all); len(got) != 1 || got[0].payload != "make bu" {
		t.Fatalf("response regions = %+v, want one carrying the truncated reply", got)
	}
}

// TestTranscript_TerminalStreamPathsArmClosedFenceControl proves both paths that seal a
// stream leave the completed block clickable, and that the region covers the control
// alone — markInterrupted writes its marker onto the same line.
func TestTranscript_TerminalStreamPathsArmClosedFenceControl(t *testing.T) {
	seals := map[string]func(*transcript){
		"finalize":        (*transcript).finalize,
		"markInterrupted": (*transcript).markInterrupted,
	}
	for name, seal := range seals {
		t.Run(name, func(t *testing.T) {
			tr := newTranscript()
			tr.appendDelta("```sh\nmake build\n```")
			seal(tr)

			regions := codeRegions(tr.controls.all)
			if len(regions) != 1 || regions[0].payload != "make build\n" {
				t.Fatalf("click regions = %+v, want one carrying the fence body", regions)
			}
			text := tr.view.GetText(true)
			if got := text[regions[0].start:regions[0].end]; got != statusCopyControl {
				t.Fatalf("region spans %q in %q, want %q", got, text, statusCopyControl)
			}
		})
	}
}

// TestRenderStreamMarkdown_ControlOnlyForClosedFence proves the live renderer exposes a
// control for a fence that has closed while the still-growing tail carries none.
func TestRenderStreamMarkdown_ControlOnlyForClosedFence(t *testing.T) {
	got, controls := renderStreamMarkdown("```sh\nmake build\n```\n\n```go\nfunc main() {")

	if bodies := controlBodies(controls); len(bodies) != 1 || bodies[0] != "make build\n" {
		t.Fatalf("bodies = %q, want only the completed fence's body", bodies)
	}
	if n := strings.Count(got, tview.Escape(statusCopyControl)); n != 1 {
		t.Fatalf("renderStreamMarkdown = %q, want exactly one escaped control", got)
	}
	if !strings.Contains(got, codeBlockTag+"func main() {"+defaultTag) {
		t.Fatalf("renderStreamMarkdown = %q, want the still-open fence styled but uncontrolled", got)
	}
}

// TestTranscript_LiveStreamArmsControlOnlyForClosedFence proves the same at the pane: the
// completed block's payload is armed while the reply is still arriving, and the open
// fence that follows arms nothing.
func TestTranscript_LiveStreamArmsControlOnlyForClosedFence(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```sh\nmake build\n```\n\n")
	tr.appendDelta("```go\nfunc main() {")

	if len(tr.controls.all) != 1 || tr.controls.all[0].payload != "make build\n" {
		t.Fatalf("click regions = %+v, want one carrying the completed fence's body", tr.controls.all)
	}
	if text := tr.view.GetText(true); strings.Count(text, statusCopyControl) != 1 {
		t.Fatalf("GetText(true) = %q, want exactly one control", text)
	}
}

// TestRenderStreamMarkdown_ClosedFenceNeedsNoTrailingBlankLine proves the closing fence is
// itself the block boundary: a stream that stops on it, or continues straight into prose,
// exposes the control and its source body without waiting for a blank-line delta.
func TestRenderStreamMarkdown_ClosedFenceNeedsNoTrailingBlankLine(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantRaw string
	}{
		{name: "stream ends on the closing fence", src: "```sh\nmake build\n```"},
		{name: "closing fence followed by prose", src: "```sh\nmake build\n```\nthen check", wantRaw: "then check"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, controls := renderStreamMarkdown(tc.src)

			if bodies := controlBodies(controls); len(bodies) != 1 || bodies[0] != "make build\n" {
				t.Fatalf("bodies = %q, want the closed fence's source body", bodies)
			}
			if n := strings.Count(got, tview.Escape(statusCopyControl)); n != 1 {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want exactly one escaped control", tc.src, got)
			}
			if !strings.Contains(got, codeBlockTag+"make build"+defaultTag) {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want the closed fence styled", tc.src, got)
			}
			if tc.wantRaw != "" && !strings.Contains(got, tc.wantRaw) {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want the trailing prose held raw", tc.src, got)
			}
		})
	}
}

// TestTranscript_LiveStreamArmsControlWhenFenceCloses proves the same at the pane, before
// any terminal path runs: the block is clickable as soon as its closing fence arrives, and
// prose streamed after it neither disturbs the region nor adds one.
func TestTranscript_LiveStreamArmsControlWhenFenceCloses(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```sh\nmake build\n```")

	armed := func(t *testing.T) {
		t.Helper()
		regions := tr.controls.all
		if len(regions) != 1 || regions[0].payload != "make build\n" {
			t.Fatalf("click regions = %+v, want one carrying the closed fence's body", regions)
		}
		text := tr.view.GetText(true)
		if got := text[regions[0].start:regions[0].end]; got != statusCopyControl {
			t.Fatalf("region spans %q in %q, want %q", got, text, statusCopyControl)
		}
	}
	armed(t)

	tr.appendDelta("\nthen check")
	armed(t)
	if got, want := tr.view.GetText(true), "make build"+visibleCopyLine+"\n\nthen check"; got != want {
		t.Fatalf("GetText(true) = %q, want %q", got, want)
	}
}

// TestTranscript_ContainerFenceControls proves fence completeness is judged through the
// blockquote and list prefixes a block is written under, on every path that arms a control:
// a closed container fence is copyable while the reply is still streaming, and one cut off
// before its closing fence exposes nothing on any of them.
func TestTranscript_ContainerFenceControls(t *testing.T) {
	seals := []struct {
		name string
		seal func(*transcript)
	}{
		{name: "streaming", seal: func(*transcript) {}},
		{name: "finalize", seal: (*transcript).finalize},
		{name: "markInterrupted", seal: (*transcript).markInterrupted},
	}
	// A dedented closer ends the list item, so goldmark closes the item's fence and reads
	// the same line as a second, empty top-level fence — hence two controls, the second
	// carrying an empty payload.
	tests := []struct {
		name  string
		src   string
		wants []string // the payload each block must arm, in order; none for no control at all
	}{
		{name: "closed blockquote fence", src: "> ```sh\n> make build\n> ```", wants: []string{"make build\n"}},
		{name: "unclosed blockquote fence", src: "> ```sh\n> make bu"},
		{name: "closed list fence", src: "- ```sh\n  make build\n  ```", wants: []string{"make build\n"}},
		{name: "unclosed list fence", src: "- ```sh\n  make bu"},
		{name: "closed multi-digit list fence", src: "10. ```sh\n    make build\n    ```", wants: []string{"make build\n"}},
		{name: "closed nested list fence", src: "- outer\n  - ```sh\n    make build\n    ```", wants: []string{"make build\n"}},
		{name: "closed list fence with dedented closer", src: "- ```sh\n  make build\n```", wants: []string{"make build\n", ""}},
		{name: "closed multi-digit list fence with dedented closer", src: "10. ```sh\n    make build\n```", wants: []string{"make build\n", ""}},
	}
	for _, tc := range tests {
		for _, s := range seals {
			t.Run(tc.name+"/"+s.name, func(t *testing.T) {
				tr := newTranscript()
				tr.appendDelta(tc.src)
				s.seal(tr)

				regions := codeRegions(tr.controls.all)
				if len(tc.wants) == 0 {
					if len(regions) != 0 {
						t.Fatalf("click regions = %+v, want none for a fence that never closed", regions)
					}
					if got := tr.view.GetText(true); strings.Contains(got, statusCopyControl) {
						t.Fatalf("GetText(true) = %q, want no control drawn either", got)
					}
					return
				}
				if len(regions) != len(tc.wants) {
					t.Fatalf("click regions = %+v, want %d carrying %q", regions, len(tc.wants), tc.wants)
				}
				text := tr.view.GetText(true)
				for i, want := range tc.wants {
					if regions[i].payload != want {
						t.Fatalf("click region %d = %+v, want payload %q", i, regions[i], want)
					}
					if got := text[regions[i].start:regions[i].end]; got != statusCopyControl {
						t.Fatalf("region %d spans %q in %q, want %q", i, got, text, statusCopyControl)
					}
				}
			})
		}
	}
}

func TestRenderStreamMarkdown_OpenFenceStyledFromFirstBodyLine(t *testing.T) {
	got, controls := renderStreamMarkdown("```sh\nmake build\n```\n\n```go\nfunc main() {")

	if !strings.Contains(got, codeBlockTag+"make build"+defaultTag) {
		t.Fatalf("renderStreamMarkdown = %q, want the completed fence carrying the block boundary", got)
	}
	if !strings.Contains(got, codeBlockTag+"func main() {"+defaultTag) {
		t.Fatalf("renderStreamMarkdown = %q, want the open fence's first body line styled", got)
	}
	if strings.Contains(got, "```go") {
		t.Fatalf("renderStreamMarkdown = %q, want the open fence's opener line not drawn", got)
	}
	if bodies := controlBodies(controls); len(bodies) != 1 || bodies[0] != "make build\n" {
		t.Fatalf("bodies = %q, want only the closed fence's body", bodies)
	}
}

func TestRenderStreamMarkdown_OpenFenceInterruptsProse(t *testing.T) {
	const src = "run this:\n```sh\nmake bu"
	got, controls := renderStreamMarkdown(src)

	if len(controls) != 0 {
		t.Fatalf("controls = %+v, want none until the closer arrives", controls)
	}
	closed, _, _ := renderMarkdown(src + "ild\n```")
	wantPrefix := closed[:strings.Index(closed, "ild")]
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("renderStreamMarkdown(%q) = %q, want it to open with the closed form's %q", src, got, wantPrefix)
	}
}

func TestRenderStreamMarkdown_OpenFenceInContainers(t *testing.T) {
	tests := []struct {
		name string
		open string
		rest string
	}{
		{name: "blockquote", open: "> ```sh\n> make bu", rest: "ild\n> ```"},
		{name: "list item", open: "- ```sh\n  make bu", rest: "ild\n  ```"},
		{name: "nested list item", open: "- outer\n  - ```sh\n    make bu", rest: "ild\n    ```"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, controls := renderStreamMarkdown(tc.open)

			if len(controls) != 0 {
				t.Fatalf("controls = %+v, want none while the fence is open", controls)
			}
			closed, _, _ := renderMarkdown(tc.open + tc.rest)
			wantPrefix := closed[:strings.Index(closed, "ild")]
			if !strings.HasPrefix(got, wantPrefix) {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want it to open with the closed form's %q", tc.open, got, wantPrefix)
			}
		})
	}
}

func TestRenderStreamMarkdown_OpenFenceBodyMatchesClosedBody(t *testing.T) {
	const body = "echo \"[red]hi[-:-:-]\"\n\necho done\n"
	open, openControls := renderStreamMarkdown("```sh\n" + body)
	closed, closedControls := renderStreamMarkdown("```sh\n" + body + "```")

	if len(openControls) != 0 {
		t.Fatalf("open-fence controls = %+v, want none", openControls)
	}
	if bodies := controlBodies(closedControls); len(bodies) != 1 || bodies[0] != body {
		t.Fatalf("closed-fence bodies = %q, want the source body", bodies)
	}
	closedBody := strings.TrimSuffix(closed, rawCopyLine)
	if open != closedBody {
		t.Fatalf("open body = %q, closed body = %q, want them identical", open, closedBody)
	}
	if !strings.Contains(open, codeBlockTag+tview.Escape("echo \"[red]hi[-:-:-]\"")+defaultTag) {
		t.Fatalf("open body = %q, want the tview-like line escaped inside the block", open)
	}
}

func TestRenderStreamMarkdown_TailAfterFenceEndsStaysRaw(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "closing fence", src: "```sh\nmake build\n```\nthen **bold** more"},
		{name: "line leaving the blockquote", src: "> ```sh\n> make bu\n\nthen **bold** more"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := renderStreamMarkdown(tc.src)

			if !strings.HasSuffix(got, "then **bold** more") {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want the trailing prose held raw", tc.src, got)
			}
			if strings.Contains(got, "[::b]bold") {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want the trailing prose NOT styled", tc.src, got)
			}
		})
	}
}

func TestTranscript_LiveStreamStylesOpenFence(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("run this:\n```sh\n")
	tr.appendDelta("make bu")

	if raw := tr.view.GetText(false); !strings.Contains(raw, codeBlockTag+"make bu"+defaultTag) {
		t.Fatalf("GetText(false) = %q, want the open fence styled live", raw)
	}
	if got, want := tr.view.GetText(true), "run this:\n\nmake bu"; got != want {
		t.Fatalf("GetText(true) = %q, want %q", got, want)
	}
	if len(tr.controls.all) != 0 {
		t.Fatalf("click regions = %+v, want none while the fence is open", tr.controls.all)
	}

	tr.appendDelta("ild\n```")

	if got, want := tr.view.GetText(true), "run this:\n\nmake build"+visibleCopyLine; got != want {
		t.Fatalf("GetText(true) = %q, want %q once the closer arrives", got, want)
	}
}

func TestTranscript_LiveStreamStylesContainerOpenFence(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "blockquote", src: "> ```sh\n> make bu", want: "│ make bu"},
		{name: "list item", src: "- ```sh\n  make bu", want: "• make bu"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTranscript()
			tr.appendDelta(tc.src)

			if got := tr.view.GetText(true); got != tc.want {
				t.Fatalf("GetText(true) = %q, want %q", got, tc.want)
			}
			if raw := tr.view.GetText(false); !strings.Contains(raw, codeBlockTag+"make bu"+defaultTag) {
				t.Fatalf("GetText(false) = %q, want the container fence body styled live", raw)
			}
		})
	}
}

func TestTranscript_LiveStreamRendersCompletedFencedBlock(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("```sh\nmake build\n```\n\n")
	tr.appendDelta("now the **expl")

	if raw := tr.view.GetText(false); !strings.Contains(raw, codeBlockTag+"make build"+defaultTag) {
		t.Fatalf("GetText(false) = %q, want the completed block styled live", raw)
	}
	if got, want := tr.view.GetText(true), "make build"+visibleCopyLine+"\n\nnow the **expl"; got != want {
		t.Fatalf("GetText(true) = %q, want %q", got, want)
	}
}

// TestTranscript_FinalizeRendersBlockMarkdown proves block markdown commits
// through the real rendering surface: a heading shows its text bold with no '#', an
// ordered list shows its markers in order, and a blockquote shows its "│ " prefix on
// each line — all via GetText(true) (tags stripped) — while GetText(false) carries the
// bold style tag for the heading.
func TestTranscript_FinalizeRendersBlockMarkdown(t *testing.T) {
	t.Run("heading", func(t *testing.T) {
		tr := newTranscript()
		tr.appendDelta("# Heading **bold**")
		tr.finalize()
		if got, want := tr.view.GetText(true), "Heading bold"+visibleResponseLine; got != want {
			t.Fatalf("GetText(true) = %q, want %q (no '#' markers)", got, want)
		}
		if raw := tr.view.GetText(false); !strings.Contains(raw, "[::b]") {
			t.Fatalf("GetText(false) = %q, want the bold heading style tag", raw)
		}
	})
	t.Run("ordered list keeps order", func(t *testing.T) {
		tr := newTranscript()
		tr.appendDelta("1. first\n2. second")
		tr.finalize()
		if got, want := tr.view.GetText(true), "1. first\n2. second"+visibleResponseLine; got != want {
			t.Fatalf("GetText(true) = %q, want %q", got, want)
		}
	})
	t.Run("blockquote prefix is visible", func(t *testing.T) {
		tr := newTranscript()
		tr.appendDelta("> quoted\n> lines")
		tr.finalize()
		if got, want := tr.view.GetText(true), "│ quoted\n│ lines"+visibleResponseLine; got != want {
			t.Fatalf("GetText(true) = %q, want %q (quote prefix on each line)", got, want)
		}
	})
}

// TestTranscript_FinalizeRendersMarkdown proves a finalized streamed reply is
// committed through renderMarkdown: the tags-stripped view text is the plain
// unstyled reply, while the raw view text carries the style tags (Done-when 4).
func TestTranscript_FinalizeRendersMarkdown(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("**bold** and `code`")
	tr.finalize()

	if got, want := tr.view.GetText(true), "bold and code"+visibleResponseLine; got != want {
		t.Fatalf("GetText(true) = %q, want the plain unstyled reply %q", got, want)
	}
	raw := tr.view.GetText(false)
	if !strings.Contains(raw, "[::b]") || !strings.Contains(raw, codeColor) {
		t.Fatalf("GetText(false) = %q, want the bold and code style tags", raw)
	}
}

// TestTranscript_MarkInterruptedRendersMarkdownWithLiteralMarker proves the
// interrupted reply renders its body through renderMarkdown (style tags present)
// while the " [interrupted]" marker stays a literal suffix with no broken tag
// (Done-when 5).
func TestTranscript_MarkInterruptedRendersMarkdownWithLiteralMarker(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("**done**")
	tr.markInterrupted()

	if got, want := tr.view.GetText(true), "done"+streamInterruptedMarker+visibleResponseLine; got != want {
		t.Fatalf("GetText(true) = %q, want %q (literal marker suffix)", got, want)
	}
	if raw := tr.view.GetText(false); !strings.Contains(raw, "[::b]") {
		t.Fatalf("GetText(false) = %q, want the bold body style tag", raw)
	}
}

// TestRenderStreamMarkdown_RendersCompletedBlocksHoldsTrailingRaw proves the live
// render: a completed block renders through renderMarkdown (styled) while the still-growing
// trailing block is held escaped/raw, so formatting appears as the reply streams instead of
// snapping in at finalize. The trailing paragraph's ** markers stay literal.
func TestRenderStreamMarkdown_RendersCompletedBlocksHoldsTrailingRaw(t *testing.T) {
	got, _ := renderStreamMarkdown("# Title\n\nthe **next** part")
	if !strings.Contains(got, "[::b]Title[-:-:-]") {
		t.Fatalf("renderStreamMarkdown(%q) = %q, want the completed heading rendered bold", "# Title…", got)
	}
	if !strings.HasSuffix(got, "the **next** part") {
		t.Fatalf("renderStreamMarkdown = %q, want the trailing in-progress block held raw", got)
	}
	if strings.Contains(got, "[::b]next") {
		t.Fatalf("renderStreamMarkdown = %q, want the in-progress block NOT styled", got)
	}
}

// TestRenderStreamMarkdown_PartialSyntaxStaysLiteral covers the trailing in-progress
// fragment held conservatively. The open-fence styling exception begins only once the
// opener line is newline-terminated, so nothing here reaches it.
func TestRenderStreamMarkdown_PartialSyntaxStaysLiteral(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantHas string // a substring that must survive in the visible output
	}{
		{"unclosed bold", "this is **bol", "**bol"},
		{"split tag across deltas", "[re" + "d]hi", "[red"},
		{"partial list marker", "- ", "- "},
		{"unterminated fence opener", "```g", "```g"},
		{"too-short fence opener", "``\n", "``"},
		{"unterminated fence opener after prose", "intro\n```go", "```go"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := renderStreamMarkdown(tc.src)
			if strings.Contains(got, defaultTag) || strings.Contains(got, codeColor) || strings.Contains(got, "[::") || strings.Contains(got, codeBlockFill) {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want no live style tag for partial syntax", tc.src, got)
			}
			if !strings.Contains(got, tc.wantHas) {
				t.Fatalf("renderStreamMarkdown(%q) = %q, want it to contain %q literally", tc.src, got, tc.wantHas)
			}
		})
	}
}

// TestTranscript_LiveStreamRendersCompletedBlocks replaces the old "stays plain"
// expectation: while streaming, a completed block already shows its markdown styling
// through the dynamic-color view (no raw-then-reformat flip for finished content), while
// the trailing in-progress block stays literal.
func TestTranscript_LiveStreamRendersCompletedBlocks(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("# Heading\n\n")
	tr.appendDelta("body **mid")

	if raw := tr.view.GetText(false); !strings.Contains(raw, "[::b]Heading[-:-:-]") {
		t.Fatalf("GetText(false) = %q, want the completed heading rendered live", raw)
	}
	if got, want := tr.view.GetText(true), "Heading\n\nbody **mid"; got != want {
		t.Fatalf("GetText(true) = %q, want %q (heading styled, trailing block raw)", got, want)
	}
}

// TestTranscript_LiveStreamHoldsLoneBlockRaw proves a single still-growing block (no
// completed block boundary yet) stays escaped/raw mid-stream, so partial inline markdown
// shows literally and no style tag goes live until a block completes or the reply
// finalizes (conservative trailing-fragment handling).
func TestTranscript_LiveStreamHoldsLoneBlockRaw(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("**bold**")

	if got, want := tr.view.GetText(false), "**bold**"; got != want {
		t.Fatalf("lone in-progress block = %q, want raw %q", got, want)
	}
}

// TestTranscript_LiveStreamHoldsUnterminatedOpenerRaw is the same conservative hold at the
// pane: a delta may still extend the info string, so nothing is styled yet.
func TestTranscript_LiveStreamHoldsUnterminatedOpenerRaw(t *testing.T) {
	tr := newTranscript()
	tr.appendDelta("intro\n\n```go")

	if raw := tr.view.GetText(false); strings.Contains(raw, codeColor) || strings.Contains(raw, codeBlockFill) {
		t.Fatalf("GetText(false) = %q, want no styling before the opener line ends", raw)
	}
	if vis := tr.view.GetText(true); !strings.Contains(vis, "```go") {
		t.Fatalf("GetText(true) = %q, want the partial opener held literally", vis)
	}
}

// TestTranscript_LiveStreamLongMultiBlockStream is the long-stream regression guard:
// feeding many completed blocks plus a trailing in-progress block keeps an
// early completed block styled and the trailing block raw, with the full reply
// reconstructable — exercising the live path repeatedly so a corrupted reflow or a
// pathological reparse surfaces here rather than in a terminal.
func TestTranscript_LiveStreamLongMultiBlockStream(t *testing.T) {
	tr := newTranscript()
	const blocks = 200
	for i := 0; i < blocks; i++ {
		tr.appendDelta(fmt.Sprintf("## Section %d\n\nbody %d\n\n", i, i))
	}
	tr.appendDelta("trailing **in progress")

	if raw := tr.view.GetText(false); !strings.Contains(raw, "[::b]Section 0[-:-:-]") {
		t.Fatalf("GetText(false) missing an early completed heading styled live in a long stream")
	}
	if vis := tr.view.GetText(true); !strings.HasSuffix(vis, "trailing **in progress") {
		t.Fatalf("GetText(true) = %q…, want the trailing in-progress block held raw at end of stream", vis[max(0, len(vis)-40):])
	}
}

// BenchmarkRenderStreamMarkdown documents the live-render cost on a multi-block buffer so
// a future regression in the streaming render path is measurable.
func BenchmarkRenderStreamMarkdown(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, "## Section %d\n\nbody **%d** with `code`\n\n", i, i)
	}
	sb.WriteString("trailing **in progress")
	src := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = renderStreamMarkdown(src)
	}
}

func TestRenderMarkdown_Tables(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		want     string
		wantProj string
	}{
		{
			name:     "one column",
			src:      "| Name |\n|---|\n| alpha |\n| beta |",
			want:     `["h:ss"]• [::b]alpha[-:-:-]` + "\n" + `["h:ss"]• [::b]beta[-:-:-]`,
			wantProj: "• alpha\n• beta",
		},
		{
			name:     "two columns",
			src:      "| Term | Meaning |\n|---|---|\n| foo | a thing |\n| bar | `x` |",
			want:     `["h:ss"]• [::b]foo[-:-:-]. a thing` + "\n" + `["h:ss"]• [::b]bar[-:-:-]. [#4e9a06]x[-:-:-]`,
			wantProj: "• foo. a thing\n• bar. x",
		},
		{
			name: "two columns with trailing punctuation on the visible lead",
			src:  "| A | B |\n|---|---|\n| end. | v |\n| key: | v |\n| why? | v |\n| wow! | v |\n| **bold.** | v |",
			want: `["h:ss"]• [::b]end.[-:-:-] v` + "\n" + `["h:ss"]• [::b]key:[-:-:-] v` + "\n" +
				`["h:ss"]• [::b]why?[-:-:-] v` + "\n" + `["h:ss"]• [::b]wow![-:-:-] v` + "\n" + `["h:ss"]• [::b]bold.[-:-:-] v`,
			wantProj: "• end. v\n• key: v\n• why? v\n• wow! v\n• bold. v",
		},
		{
			name:     "two columns with an empty first or second cell",
			src:      "| A | B |\n|---|---|\n|  | second |\n| first |  |",
			want:     `["h:ss"]• second` + "\n" + `["h:ss"]• [::b]first[-:-:-]`,
			wantProj: "• second\n• first",
		},
		{
			name: "three columns with alignment markers and empty cells",
			src:  "| Name | Type | Notes |\n|:---|:---:|---:|\n| id | int | primary |\n| x |  | n |\n|  | t |  |",
			want: `["h:ss"]• [::b]id[-:-:-]` + "\n" + `["h:ss"]  Type: int` + "\n" + `["h:ss"]  Notes: primary` + "\n" +
				`["h:ss"]• [::b]x[-:-:-]` + "\n" + `["h:ss"]  Notes: n` + "\n" + `["h:ss"]• ` + "\n" + `["h:ss"]  Type: t`,
			wantProj: "• id\n  Type: int\n  Notes: primary\n• x\n  Notes: n\n• \n  Type: t",
		},
		{
			name:     "three columns with an empty header",
			src:      "| Name |  | Notes |\n|---|---|---|\n| id | int | primary |",
			want:     `["h:ss"]• [::b]id[-:-:-]` + "\n" + `["h:ss"]  int` + "\n" + `["h:ss"]  Notes: primary`,
			wantProj: "• id\n  int\n  Notes: primary",
		},
		{
			name:     "short body rows",
			src:      "| A | B | C |\n|---|---|---|\n| a | b |\n\n| D | E |\n|---|---|\n| d |",
			want:     `["h:ss"]• [::b]a[-:-:-]` + "\n" + `["h:ss"]  B: b` + "\n\n" + `["h:ss"]• [::b]d[-:-:-]`,
			wantProj: "• a\n  B: b\n\n• d",
		},
		{
			name:     "excess body cells are ignored",
			src:      "| A | B |\n|---|---|\n| a | b | c | d |",
			want:     `["h:ss"]• [::b]a[-:-:-]. b`,
			wantProj: "• a. b",
		},
		{
			name:     "header-only table keeps its styled header cells",
			src:      "| Alpha | **Beta** |\n|---|---|",
			want:     `["h:ss"]• Alpha — [::b]Beta[-:-:-]`,
			wantProj: "• Alpha — Beta",
		},
		{
			name:     "header-only table skips empty header cells",
			src:      "| A |  | C |\n|---|---|---|",
			want:     `["h:ss"]• A — C`,
			wantProj: "• A — C",
		},
		{
			name:     "header-only table with all headers empty writes no bullet",
			src:      "| |\n|---|\n\nnext",
			want:     "next",
			wantProj: "next",
		},
		{
			name:     "table directly under prose",
			src:      "Intro:\n| A | B |\n|---|---|\n| a | b |",
			want:     "Intro:\n\n" + `["h:ss"]• [::b]a[-:-:-]. b`,
			wantProj: "Intro:\n\n• a. b",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, proj := renderMarkdown(tc.src)
			if got != tc.want {
				t.Errorf("renderMarkdown(%q) = %q, want %q", tc.src, got, tc.want)
			}
			if proj != tc.wantProj {
				t.Errorf("renderMarkdown(%q) projection = %q, want %q", tc.src, proj, tc.wantProj)
			}
		})
	}
}

func TestRenderMarkdown_TablesInContainers(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		want     string
		wantProj string
	}{
		{
			name:     "blockquote two columns",
			src:      "> | A | B |\n> |---|---|\n> | 1 | 2 |\n> | 3 | 4 |",
			want:     `["h:bsss"]│ • [::b]1[-:-:-]. 2` + "\n" + `["h:bsss"]│ • [::b]3[-:-:-]. 4`,
			wantProj: "│ • 1. 2\n│ • 3. 4",
		},
		{
			name:     "blockquote three columns",
			src:      "> | A | B | C |\n> |---|---|---|\n> | 1 | 2 | 3 |",
			want:     `["h:bsss"]│ • [::b]1[-:-:-]` + "\n" + `["h:bsss"]│   B: 2` + "\n" + `["h:bsss"]│   C: 3`,
			wantProj: "│ • 1\n│   B: 2\n│   C: 3",
		},
		{
			name:     "blockquote header-only",
			src:      "> | A | B |\n> |---|---|",
			want:     `["h:bsss"]│ • A — B`,
			wantProj: "│ • A — B",
		},
		{
			name:     "unordered list item reuses its marker",
			src:      "- | A | B |\n  |---|---|\n  | 1 | 2 |\n  | 3 | 4 |",
			want:     `["h:ss"]• [::b]1[-:-:-]. 2` + "\n" + `["h:ss"]• [::b]3[-:-:-]. 4`,
			wantProj: "• 1. 2\n• 3. 4",
		},
		{
			name:     "ordered list item reuses its marker for the first row only",
			src:      "1. | A | B |\n   |---|---|\n   | 1 | 2 |\n   | 3 | 4 |",
			want:     `["h:sss"]1. [::b]1[-:-:-]. 2` + "\n" + `["h:ss"]• [::b]3[-:-:-]. 4`,
			wantProj: "1. 1. 2\n• 3. 4",
		},
		{
			name:     "ordered list item three columns",
			src:      "1. | A | B | C |\n   |---|---|---|\n   | 1 | 2 | 3 |",
			want:     `["h:sss"]1. [::b]1[-:-:-]` + "\n" + `["h:ss"]  B: 2` + "\n" + `["h:ss"]  C: 3`,
			wantProj: "1. 1\n  B: 2\n  C: 3",
		},
		{
			name:     "list item inside blockquote",
			src:      "> - | A | B |\n>   |---|---|\n>   | 1 | 2 |\n>   | 3 | 4 |",
			want:     `["h:bsss"]│ • [::b]1[-:-:-]. 2` + "\n" + `["h:bsss"]│ • [::b]3[-:-:-]. 4`,
			wantProj: "│ • 1. 2\n│ • 3. 4",
		},
		{
			name:     "list item header-only",
			src:      "- | A | B |\n  |---|---|",
			want:     `["h:ss"]• A — B`,
			wantProj: "• A — B",
		},
		{
			name:     "list item with an all-empty header-only table",
			src:      "- | |\n  |---|\n- next",
			want:     `["h:ss"]• ` + "\n" + `["h:ss"]• next`,
			wantProj: "• \n• next",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, proj := renderMarkdown(tc.src)
			if got != tc.want {
				t.Errorf("renderMarkdown(%q) = %q, want %q", tc.src, got, tc.want)
			}
			if proj != tc.wantProj {
				t.Errorf("renderMarkdown(%q) projection = %q, want %q", tc.src, proj, tc.wantProj)
			}
		})
	}
}

func TestTranscript_HeaderOnlyTableSurvivesSealing(t *testing.T) {
	const src = "| Alpha | **Beta** |\n|---|---|"
	const visible = "• Alpha — Beta"
	for name, seal := range map[string]func(*transcript){
		"finalize":        (*transcript).finalize,
		"markInterrupted": (*transcript).markInterrupted,
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTranscript()
			tr.appendDelta(src)
			seal(tr)

			if got := tr.view.GetText(true); !strings.HasPrefix(got, visible) {
				t.Fatalf("GetText(true) = %q, want it to start with %q", got, visible)
			}
			if got := responseRegions(tr.controls.all); len(got) != 1 || got[0].payload != visible {
				t.Fatalf("response regions = %+v, want one carrying %q", got, visible)
			}
		})
	}
}

func TestTranscript_TableRendersWithoutSyntaxDelimiters(t *testing.T) {
	const src = "| Cmd | Effect |\n|:---|---:|\n| `a \\| b` | x-y |\n| c | --- |"
	const visible = "• a | b. x-y\n• c. ---"

	if got, _, proj := renderMarkdown(src); got != `["h:ss"]• [#4e9a06::b]a | b[-:-:-]. x-y`+"\n"+`["h:ss"]• [::b]c[-:-:-]. ---` || proj != visible {
		t.Fatalf("renderMarkdown(%q) = %q, projection %q", src, got, proj)
	}

	t.Run("sealed", func(t *testing.T) {
		tr := newTranscript()
		tr.appendDelta(src)
		tr.finalize()
		if got, want := tr.view.GetText(true), visible+visibleResponseLine; got != want {
			t.Fatalf("GetText(true) = %q, want %q", got, want)
		}
		if got := responseRegions(tr.controls.all); len(got) != 1 || got[0].payload != visible {
			t.Fatalf("response regions = %+v, want one carrying %q", got, visible)
		}
	})
	t.Run("completed streaming block", func(t *testing.T) {
		tr := newTranscript()
		tr.appendDelta(src + "\n\nmore")
		if got, want := tr.view.GetText(true), visible+"\n\nmore"; got != want {
			t.Fatalf("GetText(true) = %q, want %q", got, want)
		}
	})
}

func TestTranscript_TableCellsAndLabelsRenderLiterally(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		want    string
		visible string
	}{
		{
			name:    "cells carrying a tview tag and a split link",
			src:     "| Name | Value |\n|---|---|\n| [red] | see [blue](x and [red] |",
			want:    `["h:ss"]• [::b]` + tview.Escape("[red]") + "[-:-:-]. " + tview.Escape("see [blue](x and [red]"),
			visible: "• [red]. see [blue](x and [red]",
		},
		{
			name: "header labels with a tview tag, inline code and bold",
			src:  "| Name | [red] | `code` | **bold** |\n|---|---|---|---|\n| n | v1 | v2 | v3 |",
			want: `["h:ss"]• [::b]n[-:-:-]` + "\n" + `["h:ss"]  ` + tview.Escape("[red]: v1") + "\n" +
				`["h:ss"]  code: v2` + "\n" + `["h:ss"]  bold: v3`,
			visible: "• n\n  [red]: v1\n  code: v2\n  bold: v3",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _, proj := renderMarkdown(tc.src); got != tc.want || proj != tc.visible {
				t.Fatalf("renderMarkdown(%q) = %q, projection %q; want %q, %q", tc.src, got, proj, tc.want, tc.visible)
			}
			tr := newTranscript()
			tr.appendDelta(tc.src)
			tr.finalize()
			if got, want := tr.view.GetText(true), tc.visible+visibleResponseLine; got != want {
				t.Fatalf("GetText(true) = %q, want %q", got, want)
			}
			if got := responseRegions(tr.controls.all); len(got) != 1 || got[0].payload != tc.visible {
				t.Fatalf("response regions = %+v, want one carrying %q", got, tc.visible)
			}
		})
	}
}

func TestTranscript_StreamedTable(t *testing.T) {
	deltas := []string{"Intro\n\n", "| Name | Value |\n", "|---|---|\n", "| [re", "d] | [x](", "y |\n", "| b | c |"}
	full := strings.Join(deltas, "")
	stream := func(t *testing.T) *transcript {
		t.Helper()
		tr := newTranscript()
		for i, d := range deltas {
			tr.appendDelta(d)
			if i < 2 {
				continue
			}
			if got, want := tr.view.GetText(true), strings.Join(deltas[:i+1], ""); got != want {
				t.Fatalf("after delta %d GetText(true) = %q, want the raw tail literal %q", i, got, want)
			}
		}
		return tr
	}

	t.Run("finalize without a trailing blank line", func(t *testing.T) {
		tr := stream(t)
		tr.finalize()
		rendered, _, _ := renderMarkdown(full)
		if got, want := tr.view.GetText(false), rendered+rawResponseLine; got != want {
			t.Fatalf("GetText(false) = %q, want %q", got, want)
		}
		if got, want := tr.view.GetText(true), "Intro\n\n• [red]. [x](y\n• b. c"+visibleResponseLine; got != want {
			t.Fatalf("GetText(true) = %q, want %q", got, want)
		}
	})
	t.Run("block boundary then markInterrupted", func(t *testing.T) {
		tr := stream(t)
		tr.appendDelta("\n\nmore")
		if got, want := tr.view.GetText(true), "Intro\n\n• [red]. [x](y\n• b. c\n\nmore"; got != want {
			t.Fatalf("GetText(true) = %q, want %q", got, want)
		}
		tr.markInterrupted()
		rendered, _, _ := renderMarkdown(full + "\n\nmore")
		if got, want := tr.view.GetText(false), rendered+tview.Escape(streamInterruptedMarker)+rawResponseLine; got != want {
			t.Fatalf("GetText(false) = %q, want %q", got, want)
		}
	})
}

func TestRenderMarkdown_PipeProseIsNotATable(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		want     string
		wantProj string
	}{
		{name: "inline pipe", src: "a | b", want: "a | b", wantProj: "a | b"},
		{name: "pipe lines without a delimiter row", src: "a | b\nc | d", want: "a | b\nc | d", wantProj: "a | b\nc | d"},
		{name: "pipe line above a setext underline", src: "x | y\n---", want: "[::b]x | y[-:-:-]", wantProj: "x | y"},
		{name: "inline code holding a pipe", src: "use `a | b` here", want: "use [#4e9a06]a | b[-:-:-] here", wantProj: "use a | b here"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, proj := renderMarkdown(tc.src)
			if got != tc.want || proj != tc.wantProj {
				t.Fatalf("renderMarkdown(%q) = %q, projection %q; want %q, %q", tc.src, got, proj, tc.want, tc.wantProj)
			}
		})
	}
}

const hangWords = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau"

func TestRenderMarkdown_HangTagFollowsTheEmittedPrefix(t *testing.T) {
	tests := []struct {
		name, src, want, wantProj string
	}{
		{"ordered marker width", "10. x", `["h:ssss"]10. x`, "10. x"},
		{"nested quotes", "> > a\n> > b", `["h:bs"]│ a` + "\n" + `["h:bsbs"]│ │ b`, "│ a\n│ │ b"},
		{"list inside a quote", "> - a\n>   b", `["h:bsss"]│ • a` + "\n" + `["h:bs"]│ b`, "│ • a\n│ b"},
		{"quote inside a list keeps the first row barless", "- > q\n  > r", `["h:ss"]• q` + "\n" + `["h:bs"]│ r`, "• q\n│ r"},
		{"unprefixed soft break gets no tag", "- a\n  b", `["h:ss"]• a` + "\nb", "• a\nb"},
		{"hard break in a nested item", "- x\n  - a\\\n    b", `["h:ss"]• x` + "\n" + `["h:ssss"]  • a` + "\n" + `["h:ss"]  b`, "• x\n  • a\n  b"},
		{"table inside a quoted list", "> - | A | B | C |\n>   |---|---|---|\n>   | 1 | 2 | 3 |",
			`["h:bsss"]│ • [::b]1[-:-:-]` + "\n" + `["h:bsss"]│   B: 2` + "\n" + `["h:bsss"]│   C: 3`, "│ • 1\n│   B: 2\n│   C: 3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, _, proj := renderMarkdown(tc.src); got != tc.want || proj != tc.wantProj {
				t.Fatalf("renderMarkdown(%q) = %q, projection %q; want %q, %q", tc.src, got, proj, tc.want, tc.wantProj)
			}
		})
	}
}

func TestRenderMarkdown_HangTagSkipsHeadingsCodeAndControls(t *testing.T) {
	for _, src := range []string{
		"- # Title " + hangWords,
		"> # Title " + hangWords,
		"- ```sh\n  " + hangWords + "\n  ```",
		"> ```\n> " + hangWords + "\n> ```",
		">     " + hangWords,
		"plain " + hangWords + "\nsoft " + hangWords,
	} {
		if got, _, _ := renderMarkdown(src); strings.Contains(got, `["h:`) {
			t.Errorf("renderMarkdown(%q) = %q, want no hanging-indent tag", src, got)
		}
	}
}

func TestTranscript_WrappedReplyLinesHangUnderTheirText(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		width int
		want  []string
	}{
		{"bullet at 40", "- " + hangWords, 40, []string{
			"• alpha beta gamma delta epsilon zeta",
			"  eta theta iota kappa lambda mu nu xi",
			"  omicron pi rho sigma tau",
		}},
		{"bullet at 80", "- " + hangWords + " " + hangWords, 80, []string{
			"• alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi",
			"  omicron pi rho sigma tau alpha beta gamma delta epsilon zeta eta theta iota",
			"  kappa lambda mu nu xi omicron pi rho sigma tau",
		}},
		{"ordered at 40", "10. " + hangWords, 40, []string{
			"10. alpha beta gamma delta epsilon zeta",
			"    eta theta iota kappa lambda mu nu",
			"    xi omicron pi rho sigma tau",
		}},
		{"ordered at 80", "10. " + hangWords + " " + hangWords, 80, []string{
			"10. alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi",
			"    omicron pi rho sigma tau alpha beta gamma delta epsilon zeta eta theta iota",
			"    kappa lambda mu nu xi omicron pi rho sigma tau",
		}},
		{"nested at 40", "- top\n  - " + hangWords, 40, []string{
			"• top",
			"  • alpha beta gamma delta epsilon zeta",
			"    eta theta iota kappa lambda mu nu",
			"    xi omicron pi rho sigma tau",
		}},
		{"nested at 80", "- top\n  - " + hangWords + " " + hangWords, 80, []string{
			"• top",
			"  • alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi",
			"    omicron pi rho sigma tau alpha beta gamma delta epsilon zeta eta theta iota",
			"    kappa lambda mu nu xi omicron pi rho sigma tau",
		}},
		{"nested quotes", "> " + hangWords + "\n> > " + hangWords, 40, []string{
			"│ alpha beta gamma delta epsilon zeta",
			"│ eta theta iota kappa lambda mu nu xi",
			"│ omicron pi rho sigma tau",
			"│ │ alpha beta gamma delta epsilon zeta",
			"│ │ eta theta iota kappa lambda mu nu",
			"│ │ xi omicron pi rho sigma tau",
		}},
		{"list inside a quote", "> - " + hangWords, 40, []string{
			"│ • alpha beta gamma delta epsilon zeta",
			"│   eta theta iota kappa lambda mu nu",
			"│   xi omicron pi rho sigma tau",
		}},
		{"quote inside a list", "- > " + hangWords + "\n  > " + hangWords, 40, []string{
			"• alpha beta gamma delta epsilon zeta",
			"  eta theta iota kappa lambda mu nu xi",
			"  omicron pi rho sigma tau",
			"│ alpha beta gamma delta epsilon zeta",
			"│ eta theta iota kappa lambda mu nu xi",
			"│ omicron pi rho sigma tau",
		}},
		{"table bullets and header lines", "| Name | Notes | More |\n|---|---|---|\n| " + hangWords + " | " + hangWords + " | x |", 40, []string{
			"• alpha beta gamma delta epsilon zeta",
			"  eta theta iota kappa lambda mu nu xi",
			"  omicron pi rho sigma tau",
			"  Notes: alpha beta gamma delta epsilon",
			"  zeta eta theta iota kappa lambda mu",
			"  nu xi omicron pi rho sigma tau",
			"  More: x",
		}},
		{"two-column table inside a list", "- | A | B |\n  |---|---|\n  | a | " + hangWords + " |", 40, []string{
			"• a. alpha beta gamma delta epsilon",
			"  zeta eta theta iota kappa lambda mu",
			"  nu xi omicron pi rho sigma tau",
		}},
		{"header line inside a quote", "> | A | B | C |\n> |---|---|---|\n> | a | " + hangWords + " | c |", 40, []string{
			"│ • a",
			"│   B: alpha beta gamma delta epsilon",
			"│   zeta eta theta iota kappa lambda mu",
			"│   nu xi omicron pi rho sigma tau",
			"│   C: c",
		}},
		{"soft and hard breaks", "- top\n  - one\n    " + hangWords + "\\\n    " + hangWords, 40, []string{
			"• top",
			"  • one",
			"  alpha beta gamma delta epsilon zeta",
			"  eta theta iota kappa lambda mu nu xi",
			"  omicron pi rho sigma tau",
			"  alpha beta gamma delta epsilon zeta",
			"  eta theta iota kappa lambda mu nu xi",
			"  omicron pi rho sigma tau",
		}},
		{"unprefixed soft break wraps flush left", "- one\n  " + hangWords, 40, []string{
			"• one",
			"alpha beta gamma delta epsilon zeta eta",
			"theta iota kappa lambda mu nu xi",
			"omicron pi rho sigma tau",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := paneRows(t, finalizedReply(tc.src), tc.width, 30)
			want := append(tc.want, "  [Copy response]")
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("rows at width %d:\n%s\nwant:\n%s", tc.width, strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

func TestTranscript_HangMetadataStaysOutOfVisibleText(t *testing.T) {
	const src = "- " + hangWords + "\n  - nested " + hangWords + "\n\n> quoted " + hangWords + "\n\n| A | B |\n|---|---|\n| a | " + hangWords + " |"
	const visible = "• " + hangWords + "\n  • nested " + hangWords + "\n\n│ quoted " + hangWords + "\n\n• a. " + hangWords
	a := finalizedReply(src)
	for _, width := range []int{20, 40, 80} {
		drawTranscriptPane(t, a, width, 30)
		if got := a.transcript.view.GetText(true); got != visible+visibleResponseLine {
			t.Fatalf("GetText(true) at width %d = %q, want %q", width, got, visible+visibleResponseLine)
		}
	}
	if _, _, proj := renderMarkdown(src); proj != visible {
		t.Fatalf("projection = %q, want %q", proj, visible)
	}
	if got := responseRegions(a.transcript.controls.all); len(got) != 1 || got[0].payload != visible {
		t.Fatalf("response regions = %+v, want one carrying %q", got, visible)
	}
}

func TestTranscript_ForgedHangMetadataStaysLiteral(t *testing.T) {
	const forged = `["h:ssssssss"]`
	tests := []struct {
		name, src, visible string
		want               []string
	}{
		{"paragraph", forged + hangWords, forged + hangWords, []string{
			`["h:ssssssss"]alpha beta gamma delta`,
			"epsilon zeta eta theta iota kappa",
			"lambda mu nu xi omicron pi rho sigma tau",
		}},
		{"list item", "- " + forged + hangWords, "• " + forged + hangWords, []string{
			`• ["h:ssssssss"]alpha beta gamma delta`,
			"  epsilon zeta eta theta iota kappa",
			"  lambda mu nu xi omicron pi rho sigma",
			"  tau",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := finalizedReply(tc.src)
			got := paneRows(t, a, 40, 20)
			want := append(tc.want, "  [Copy response]")
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if got := a.transcript.view.GetText(true); got != tc.visible+visibleResponseLine {
				t.Fatalf("GetText(true) = %q, want %q", got, tc.visible+visibleResponseLine)
			}
		})
	}
}

func TestTranscript_HangingWrapLeavesOtherBlocksUnchanged(t *testing.T) {
	const code = "go test -run TestSomethingLong ./internal/..."
	tests := []struct {
		name, src string
		bodies    []string
	}{
		{"paragraph and heading", "# Heading " + hangWords + "\n\n" + hangWords + "\nsoft " + hangWords, nil},
		{"heading in a list and a quote", "- # " + hangWords + "\n\n> ## " + hangWords, nil},
		{"fence sharing the list-marker row", "- ```sh\n  " + code + "\n  ```", []string{code + "\n"}},
		{"fence inside a quote", "> ```\n> " + code + "\n> " + code + "\n> ```", []string{code + "\n" + code + "\n"}},
		{"fence inside a quoted list", "> - x\n>\n>   ```\n>   " + code + "\n>   ```", []string{code + "\n"}},
		{"indented code inside a quote", ">     " + code, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := finalizedReply(tc.src)
			for _, width := range []int{12, 40} {
				drawTranscriptPane(t, a, width, 30)
				if raw := a.transcript.view.GetText(false); a.transcript.view.paintText != raw {
					t.Fatalf("paint text at width %d = %q, want the unwrapped text %q", width, a.transcript.view.paintText, raw)
				}
			}
			var bodies []string
			for _, r := range codeRegions(a.transcript.controls.all) {
				bodies = append(bodies, r.payload)
			}
			if fmt.Sprint(bodies) != fmt.Sprint(tc.bodies) {
				t.Fatalf("copy payloads = %q, want %q", bodies, tc.bodies)
			}
		})
	}
}
