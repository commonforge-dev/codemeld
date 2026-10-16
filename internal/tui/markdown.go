// Markdown renderer: parses assistant-reply markdown and emits absolute tview style tags.
package tui

import (
	"strconv"
	"strings"

	"github.com/rivo/tview"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// codeColor (the inline-code/fenced-block accent) is defined in colors.go alongside the
// other intentional theme overrides.

// defaultTag is the absolute reset tag for the empty style stack: foreground,
// background, and flags all return to the terminal default. Every styled run is
// closed back to it so a tag cannot leak past the run that opened it.
const defaultTag = "[-:-:-]"

// underlineOffTag follows defaultTag after every underlined run: the pinned tview
// version's absolute reset restores colors and ordinary attributes but leaves the
// underline flag set, so the underline would otherwise leak into following output.
const underlineOffTag = "[::U]"

const codeControlIndent = "  "

const codeBlockTag = "[" + codeBlockText + ":" + codeBlockFill + "]"

// A fenced block whose body is entirely blank paints no cell, so its lines carry a
// space to stay visible. Blank lines inside a block that has content are left
// literal: the tags-stripped text a terminal selection copies must equal the block
// body the model wrote.
const codeBlockBlankLine = " "

// codeControl is one generated copy control: the zero-based line of the rendered text
// the control occupies, and the exact source body a click on it copies. The line comes
// from the renderer because once the text is stripped a model-written line reading like
// the copy control is indistinguishable from a generated one. response marks the
// whole-reply control the sealing paths append, which carries a different label.
type codeControl struct {
	line     int
	body     string
	response bool
}

// renderMarkdown parses src as markdown and returns a single string in which
// literal text is tview.Escape'd and styled runs are wrapped in absolute tview
// style tags, one codeControl per closed fenced code block in document order, and the
// reply's copyable display projection: the visible text with the style tags, the
// escaping, and the generated control lines gone. The projection is built here rather
// than recovered from the rendered string because only the renderer can tell a generated
// control line from model text that reads like one.
// The returned string already contains intentional tags, so callers
// append it WITHOUT a further tview.Escape (that would neuter the tags); literal
// segments are escaped internally here.
//
// No response-level control is appended: renderStreamMarkdown renders a still-growing
// reply through here, so arming one would expose it before the reply is sealed. The
// sealing paths append it from the returned projection.
//
// Each fenced block is followed by its own escaped statusCopyControl line — the payload
// comes from the source, byte for byte including the newline before the closing fence,
// so a click copies what the model wrote rather than the display cells.
//
// Inline runs (bold, italic, inline code) emit absolute tags computed from the
// current style stack: code-inside-bold emits one combined tag like
// "[#4e9a06::b]" and returning to the empty stack emits defaultTag. Block
// elements are layered on top of that inline machinery:
//   - Headings: the text renders bold (the heading pushes the bold depth and the
//     inline walker styles the text); the leading '#' markers are not shown.
//   - Lists: bullet items get a "• " prefix and ordered items an "N. " prefix
//     (numbered from the list's Start); nested lists are indented; item text
//     flows through the inline walker.
//   - Blockquotes: every produced line is prefixed with "│ "; inner text flows
//     through the inline walker.
//
// Indented (4-space) code blocks stay plain escaped text — block styling for them
// is out of scope (a potential follow-up). The finalize/markInterrupted seam is
// unchanged.
func renderMarkdown(src string) (string, []codeControl, string) {
	source := []byte(src)
	doc := goldmark.DefaultParser().Parse(text.NewReader(source))

	var b strings.Builder
	// projection mirrors every write to b except the style tags, the escaping, and the
	// generated control lines.
	var projection strings.Builder
	var controls []codeControl
	lastControlStart := 0
	// Style stack depths. tview tags are absolute, so each run emits the effective
	// tag for the current depths rather than relying on nesting.
	var bold, italic, code int
	// prevTag tracks the style currently active in the output. The view enters this
	// block at the terminal default (the prior block reset on its way out), so it
	// starts at defaultTag; a run only writes a tag when its effective style differs.
	prevTag := defaultTag
	// pending accumulates the raw (unescaped) literal text of the current style run.
	// goldmark fragments a failed link like "[red]" into several *ast.Text nodes, so
	// escaping each fragment alone would never see the complete "[...]" and the
	// brackets would reassemble into a live tview color tag in the view. Buffering
	// all same-style fragments and escaping the concatenation closes that injection
	// path; the buffer is flushed before any style change, line break, or block
	// boundary (where the run ends) so a fragment is never escaped in isolation.
	var pending strings.Builder

	// prefixStack holds the per-line prefixes contributed by enclosing block
	// containers — "│ " for each blockquote level and "  " for each nested-list
	// level. curPrefix joins them; it is written at the start of every content line
	// so blockquote bars and list indentation repeat on continued lines, not just
	// the first.
	var prefixStack []string
	curPrefix := func() string { return strings.Join(prefixStack, "") }

	// List bookkeeping: listDepth counts open lists (drives nested indentation) and
	// listStack carries each open list's ordered flag and running counter so ordered
	// items number from the list's Start.
	type listState struct {
		ordered bool
		next    int
	}
	var listDepth int
	var listStack []*listState

	// suppressNextLineStart is set by a container (blockquote, list item) that has
	// already opened the current line; the inner paragraph/text-block that follows
	// then renders onto that line instead of starting another.
	var suppressNextLineStart bool

	flush := func() {
		if pending.Len() == 0 {
			return
		}
		eff := effectiveStyleTag(bold, italic, code)
		if eff != prevTag {
			// The partial tags ([::b], [#4e9a06]) leave the unspecified attribute
			// unchanged in tview, so a direct styled→styled transition would carry the
			// other attribute over (e.g. code's green leaking into a following bold
			// run). Reset to default first whenever both sides are styled; sibling runs
			// already pass through defaultTag and need no extra reset.
			if eff != defaultTag && prevTag != defaultTag {
				b.WriteString(defaultTag)
			}
			b.WriteString(eff)
			prevTag = eff
		}
		b.WriteString(tview.Escape(pending.String()))
		projection.WriteString(pending.String())
		pending.Reset()
	}

	isTopLevel := func(n ast.Node) bool {
		p := n.Parent()
		return p != nil && p.Kind() == ast.KindDocument
	}

	// resetStyle closes any open inline style so the next raw write (a prefix,
	// marker, or code-block body) renders plain rather than inheriting the run.
	resetStyle := func() {
		if prevTag != defaultTag {
			b.WriteString(defaultTag)
			prevTag = defaultTag
		}
	}

	// startBlockLine begins a block on a fresh line carrying the current line
	// prefix, inserting a blank line first when gap is true (a top-level block
	// break). It is a no-op beyond clearing the flag when a container already opened
	// the line (suppressNextLineStart).
	startBlockLine := func(gap bool) {
		if suppressNextLineStart {
			suppressNextLineStart = false
			return
		}
		flush()
		resetStyle()
		if b.Len() > 0 {
			b.WriteString("\n")
			projection.WriteString("\n")
			if gap {
				b.WriteString("\n")
				projection.WriteString("\n")
			}
		}
		b.WriteString(curPrefix())
		projection.WriteString(curPrefix())
	}

	// newlineWithPrefix ends the current line inside a block and starts the next
	// one with the line prefix, so blockquote bars and list indentation repeat on
	// every soft/hard break.
	newlineWithPrefix := func() {
		flush()
		resetStyle()
		b.WriteString("\n")
		b.WriteString(curPrefix())
		projection.WriteString("\n")
		projection.WriteString(curPrefix())
	}

	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		switch node := n.(type) {
		case *ast.Document:
			// The root carries no text and needs no separator.
		case *ast.Emphasis:
			// Level 2 is bold (**…**), level 1 italic (*…*); nesting the two yields
			// bold-italic via the accumulated depths. Flush before the depth changes so
			// the just-collected text is escaped under its own (still-current) style.
			flush()
			delta := -1
			if entering {
				delta = 1
			}
			if node.Level == 2 {
				bold += delta
			} else {
				italic += delta
			}
		case *ast.CodeSpan:
			// CodeSpan holds its content in child *ast.Text nodes, which the walk
			// visits with code active; only the depth is tracked here.
			flush()
			if entering {
				code++
			} else {
				code--
			}
		case *ast.Text:
			if entering {
				pending.WriteString(string(node.Value(source)))
				// A soft or hard line break preserves the model's line structure; the
				// newline carries no glyph, so it ends the run and stays outside the tag.
				// The continued line re-emits the current prefix (blockquote bar, list
				// indent) so multi-line inner content stays aligned.
				if node.SoftLineBreak() || node.HardLineBreak() {
					newlineWithPrefix()
				}
			}
		case *ast.String:
			if entering {
				pending.WriteString(string(node.Value))
			}
		case *ast.Heading:
			// The heading text reuses the inline walker; pushing the bold depth renders
			// it bold, and goldmark already drops the leading '#' markers. Flush on the
			// way out so the buffered text is emitted while bold is still active.
			if entering {
				startBlockLine(isTopLevel(n))
				bold++
			} else {
				flush()
				bold--
			}
		case *ast.Blockquote:
			// Push the quote bar before opening the line so the first content line —
			// and, via newlineWithPrefix, every continued line — carries it. The inner
			// paragraph renders onto the line this opened, not a fresh one.
			if entering {
				prefixStack = append(prefixStack, "│ ")
				startBlockLine(isTopLevel(n))
				suppressNextLineStart = true
			} else {
				flush()
				prefixStack = prefixStack[:len(prefixStack)-1]
			}
		case *ast.List:
			if entering {
				nested := listDepth > 0
				listDepth++
				if nested {
					prefixStack = append(prefixStack, "  ")
				}
				listStack = append(listStack, &listState{ordered: node.IsOrdered(), next: node.Start})
				// A top-level list opens with a blank-line gap from the prior block; the
				// first item supplies the line break itself, so only the extra blank line
				// is added here. Nested lists flow directly under their parent item.
				if isTopLevel(n) && !suppressNextLineStart && b.Len() > 0 {
					flush()
					resetStyle()
					b.WriteString("\n")
					projection.WriteString("\n")
				}
			} else {
				flush()
				listDepth--
				if listDepth > 0 {
					prefixStack = prefixStack[:len(prefixStack)-1]
				}
				listStack = listStack[:len(listStack)-1]
			}
		case *ast.ListItem:
			// Each item opens its own line (single break between items) carrying the
			// list indent, then its marker; the item's inner text-block renders onto
			// that same line.
			if entering {
				ls := listStack[len(listStack)-1]
				marker := "• "
				if ls.ordered {
					marker = strconv.Itoa(ls.next) + ". "
					ls.next++
				}
				startBlockLine(false)
				b.WriteString(marker)
				projection.WriteString(marker)
				suppressNextLineStart = true
			}
		case *ast.FencedCodeBlock:
			if entering {
				startBlockLine(isTopLevel(n))
				// The payload keeps the body exactly as written; only the drawn lines drop
				// the newline that belongs to the last one, which has no cell of its own.
				body := string(node.Lines().Value(source))
				padBlank := strings.TrimSpace(body) == ""
				for i, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
					if i > 0 {
						b.WriteString("\n")
						b.WriteString(curPrefix())
						projection.WriteString("\n")
						projection.WriteString(curPrefix())
					}
					if padBlank && line == "" {
						line = codeBlockBlankLine
					}
					b.WriteString(codeBlockTag)
					b.WriteString(tview.Escape(line))
					b.WriteString(defaultTag)
					projection.WriteString(line)
				}
				// The control goes below the block: a tall block has already scrolled its top
				// out of view, and a streaming reply auto-follows the bottom.
				lastControlStart = b.Len()
				controlLine := strings.Count(b.String(), "\n") + 1
				b.WriteString("\n")
				b.WriteString(curPrefix())
				// The offset is from curPrefix(), never from the block's first line: that
				// line shares its row with the list marker, whose width would drag the
				// control along with it.
				b.WriteString(codeControlIndent)
				b.WriteString(statusCopyControlTag)
				b.WriteString(tview.Escape(statusCopyControl))
				b.WriteString(defaultTag)
				b.WriteString(underlineOffTag)
				prevTag = defaultTag
				controls = append(controls, codeControl{line: controlLine, body: body})
				return ast.WalkSkipChildren, nil
			}
		case *ast.CodeBlock:
			// Indented (4-space) code blocks are out of scope for block styling: render
			// the body as escaped plain text, still resetting any preceding style via
			// startBlockLine. Escaping the whole body at once keeps the same
			// injection-safety guarantee as the inline pending buffer.
			if entering {
				startBlockLine(isTopLevel(n))
				b.WriteString(tview.Escape(string(node.Lines().Value(source))))
				projection.WriteString(string(node.Lines().Value(source)))
				return ast.WalkSkipChildren, nil
			}
		case *ast.Paragraph, *ast.TextBlock:
			// Paragraph / list-item text-block content flows through the inline walker;
			// they only open a line, unless a container already did (suppressNextLineStart).
			if entering {
				startBlockLine(isTopLevel(n))
			}
		default:
			// Any other block node (e.g. a thematic break) gets only structural
			// separation so its inline text content stays readable; inline nodes fall
			// through here and their child text renders via the *ast.Text case.
			if entering && n.Type() == ast.TypeBlock {
				startBlockLine(isTopLevel(n))
			}
		}
		return ast.WalkContinue, nil
	})

	flush()
	// Close any open styling so the accent cannot bleed into the block separator
	// renderLocked adds after this block, or into the next (escaped, untagged) block.
	if prevTag != defaultTag {
		b.WriteString(defaultTag)
	}
	out := b.String()
	// A reply cut off mid-fence still parses as a fenced block — goldmark closes it at
	// end of source — but it has no closing fence, so the block is incomplete and gets no
	// control. Only the final fence can be unclosed, and it swallows the rest of the
	// source, so its control is the last thing written.
	if len(controls) > 0 && endsInsideFence(src) {
		out = out[:lastControlStart]
		controls = controls[:len(controls)-1]
	}
	return out, controls, projection.String()
}

func endsInsideFence(src string) bool {
	_, open, _ := scanBlocks(src)
	return open
}

// renderStreamMarkdown renders the still-growing streamed reply src for live display:
// the completed-block prefix is rendered through renderMarkdown — so styling
// appears as the reply streams instead of snapping in at finalize — while the trailing
// in-progress block is appended tview.Escape'd (raw). Splitting on the last hard block
// boundary keeps incomplete syntax conservative: an unclosed **, a partial list marker,
// a partially arrived fence opener, or a tview tag split across deltas ("[re"+"d]") sits
// in the escaped tail, so it renders literally and cannot leak a style tag, restyle
// following text, or drop a literal bracket. renderMarkdown's output is NOT re-escaped
// (that would neuter its intentional tags); only the raw tail is. finalize/markInterrupted
// remain the authoritative full-buffer render at commit.
//
// A fence whose opener line has fully arrived is the one exception: in CommonMark an
// unclosed fence runs to the end of the block, so the opener both terminates the paragraph
// it interrupted and claims everything after it as body — no later delta can reinterpret
// either side. The whole buffer therefore already renders as it will once the closer
// lands, so it goes through renderMarkdown whole, which still escapes the body per line
// and (via endsInsideFence) withholds the copy control until that closer arrives.
func renderStreamMarkdown(src string) (string, []codeControl) {
	if _, _, openerComplete := scanBlocks(src); openerComplete {
		rendered, controls, _ := renderMarkdown(src)
		return rendered, controls
	}
	head, tail := splitCompletedBlocks(src)
	var out string
	var controls []codeControl
	if strings.TrimSpace(head) != "" {
		out, controls, _ = renderMarkdown(head)
	}
	if strings.TrimSpace(tail) == "" {
		return out, controls
	}
	escaped := tview.Escape(tail)
	if out == "" {
		return escaped, controls
	}
	// One blank line separates the last completed block from the in-progress block,
	// matching renderMarkdown's own top-level block separation and the transcript's
	// block-gap assembly.
	return out + "\n\n" + escaped, controls
}

// splitCompletedBlocks divides a still-growing markdown buffer into a completed-block
// prefix (head) and the trailing in-progress block (tail). The split is the byte after the
// most recent hard block boundary: a blank line outside an open code fence, or a closing
// code fence. In CommonMark both end a block outright, so everything before them is final
// and cannot be reinterpreted by later deltas — a closing fence needs no blank line after
// it, which is what makes a just-closed block copyable mid-stream. A blank line inside an
// open fence is fence content (not a boundary), so a half-open fenced block stays whole in
// the tail. With no such boundary yet head is empty and the whole buffer is the tail.
func splitCompletedBlocks(buf string) (head, tail string) {
	boundary, _, _ := scanBlocks(buf)
	return buf[:boundary], buf[boundary:]
}

// scanBlocks walks buf a line at a time and reports the hard-boundary facts the render
// paths need: the offset just past the most recent boundary, whether the buffer ends
// inside a fence that never closed, and whether that fence's opener line arrived whole
// (its terminating newline included). Fences are tracked through their container, so an
// opener carrying a blockquote or list-item prefix is seen and its closer — which repeats
// the blockquote markers but replaces the list marker with indentation — matches it. A
// close must sit at the blockquote depth its opener did, so a ``` written inside a quoted
// fence body cannot end it, and a line that leaves the blockquote ends the fence with the
// container that held it.
func scanBlocks(buf string) (boundary int, openFence, openerComplete bool) {
	var (
		fenceChar   byte
		fenceLen    int
		fenceDepth  int
		fenceIndent int
		offset      int
	)
	for offset < len(buf) {
		line := buf[offset:]
		next := len(buf)
		terminated := false
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line, next, terminated = line[:nl], offset+nl+1, true
		}
		trimmed := strings.TrimRight(line, " \t\r")
		rest, depth := stripQuotePrefix(trimmed)
		switch {
		case openFence && depth == fenceDepth && isFenceClose(rest, fenceChar, fenceLen, fenceIndent):
			openFence, openerComplete = false, false
			boundary = next
		case openFence && depth >= fenceDepth:
			// Fence content: a blank line inside a fence is not a block boundary.
		case trimmed == "":
			openFence, openerComplete = false, false
			boundary = next
		default:
			openFence, openerComplete = false, false
			fenceContent, containerIndent := stripListMarker(rest)
			if ch, n, ok := fenceOpen(fenceContent); ok {
				openFence, fenceChar, fenceLen, fenceDepth, fenceIndent = true, ch, n, depth, containerIndent
				openerComplete = terminated
			}
		}
		offset = next
	}
	return boundary, openFence, openerComplete
}

// stripQuotePrefix removes the blockquote markers content opens with, returning the rest
// of the line and the quote depth it was written at.
func stripQuotePrefix(content string) (string, int) {
	depth := 0
	for {
		indent := 0
		for indent < len(content) && content[indent] == ' ' {
			indent++
		}
		if indent > 3 || indent == len(content) || content[indent] != '>' {
			return content, depth
		}
		content = strings.TrimPrefix(content[indent+1:], " ")
		depth++
	}
}

// stripListMarker removes a leading list-item marker so a fence opened on the marker's
// own line ("- ```sh") is seen, and returns the item's content indent for matching its
// indented closing fence.
func stripListMarker(content string) (string, int) {
	indent := 0
	for indent < len(content) && content[indent] == ' ' {
		indent++
	}
	if indent > 3 {
		return content, 0
	}
	end := indent
	if end < len(content) && (content[end] == '-' || content[end] == '*' || content[end] == '+') {
		end++
	} else {
		for end < len(content) && content[end] >= '0' && content[end] <= '9' {
			end++
		}
		if end == indent || end == len(content) || (content[end] != '.' && content[end] != ')') {
			return content, 0
		}
		end++
	}
	if end == len(content) || content[end] != ' ' {
		return content, 0
	}
	for end < len(content) && content[end] == ' ' {
		end++
	}
	return content[end:], end
}

// fenceOpen reports whether content (a line without its newline) opens a markdown code
// fence, returning the fence char ('`' or '~') and its run length. A fence is up to three
// leading spaces of indent then three or more of the same char; a backtick fence's info
// string may not contain a backtick (that would be an inline code span instead).
func fenceOpen(content string) (byte, int, bool) {
	indent := 0
	for indent < len(content) && content[indent] == ' ' {
		indent++
	}
	if indent > 3 {
		return 0, 0, false
	}
	rest := content[indent:]
	if len(rest) < 3 || (rest[0] != '`' && rest[0] != '~') {
		return 0, 0, false
	}
	ch := rest[0]
	n := 0
	for n < len(rest) && rest[n] == ch {
		n++
	}
	if n < 3 {
		return 0, 0, false
	}
	if ch == '`' && strings.Contains(rest[n:], "`") {
		return 0, 0, false
	}
	return ch, n, true
}

// isFenceClose reports whether content closes a fence opened with openChar/openLen: no
// more than three spaces past its container indent, the same fence char, a run at least
// as long as the opener, and only trailing whitespace after it. There is no lower bound:
// a closer written left of the container ends that container, which closes the fence it
// held just the same.
func isFenceClose(content string, openChar byte, openLen, containerIndent int) bool {
	indent := 0
	for indent < len(content) && content[indent] == ' ' {
		indent++
	}
	if indent > containerIndent+3 {
		return false
	}
	rest := content[indent:]
	n := 0
	for n < len(rest) && rest[n] == openChar {
		n++
	}
	if n < openLen {
		return false
	}
	return strings.TrimRight(rest[n:], " \t") == ""
}

// effectiveStyleTag returns the absolute tview tag for the given style-stack
// depths. The empty stack is defaultTag; otherwise the foreground is codeColor
// when a code span is open (else left unchanged) and the flags field carries the
// bold/italic combination. The forms ([::b], [#4e9a06], [#4e9a06::b]) are safe
// because renderMarkdown guarantees the run starts from the default style.
func effectiveStyleTag(bold, italic, code int) string {
	if bold == 0 && italic == 0 && code == 0 {
		return defaultTag
	}
	fg := ""
	if code > 0 {
		fg = codeColor
	}
	flags := ""
	if bold > 0 {
		flags += "b"
	}
	if italic > 0 {
		flags += "i"
	}
	if flags == "" {
		// Foreground-only (a bare code span): [#4e9a06].
		return "[" + fg + "]"
	}
	return "[" + fg + "::" + flags + "]"
}
