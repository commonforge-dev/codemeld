package tui

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/sessions"
)

// userRailPrefix marks every line of a user-submission block with a teal "▌ " left rail:
// the U+258C half-block in the accentTeal brand color, then a space, then the
// line's escaped content. Unlike the chrome bars it paints no background — it is a
// foreground accent only, so the transcript/session area stays within the
// terminal-default theme. The rail repeats on every line of the block (the blockquote
// per-line-prefix model from markdown.go), so a multi-line user message reads as one
// continuous marked block rather than only its first line. The "▌ " glyph is two cells
// wide, matching the prior "> " prefix, so nothing downstream shifts.
const userRailPrefix = "[" + accentTealHex + "]▌[-] "

const userRailWidth = 2

func userBlockLines(text string, imageParts []sessions.ContentPart) string {
	var lines []string
	if text != "" {
		lines = append(lines, userRailLines(text))
	}
	for _, p := range imageParts {
		if p.Type == "image_url" {
			lines = append(lines, userRailPrefix+tview.Escape(imagePlaceholder(p)))
		}
	}
	return strings.Join(lines, "\n")
}

func userRailLines(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = userRailPrefix + tview.Escape(line)
	}
	return strings.Join(lines, "\n")
}

// A reply line's continuation prefix travels as a region tag because tview keeps region
// tags in GetText(false) yet strips them from GetText(true), and tview.Escape neuters any
// copy in model text.
const (
	hangTagOpen  = `["h:`
	hangTagClose = `"]`
)

var styleTagPattern = regexp.MustCompile(`\[[a-zA-Z0-9#:-]+\]`)

func hangTag(prefix string) string {
	var code strings.Builder
	for _, r := range prefix {
		if r == '│' {
			code.WriteByte('b')
		} else {
			code.WriteByte('s')
		}
	}
	return hangTagOpen + code.String() + hangTagClose
}

func hangLine(raw, plain string) (cont string, prefixBytes int, content string, ok bool) {
	after, found := strings.CutPrefix(raw, hangTagOpen)
	if !found {
		return "", 0, "", false
	}
	n := 0
	for n < len(after) && (after[n] == 'b' || after[n] == 's') {
		n++
	}
	rest, found := strings.CutPrefix(after[n:], hangTagClose)
	if !found || n == 0 {
		return "", 0, "", false
	}
	for range n {
		_, size := utf8.DecodeRuneInString(rest[prefixBytes:])
		if size == 0 {
			return "", 0, "", false
		}
		prefixBytes += size
	}
	content = rest[prefixBytes:]
	if stripStyleTags(content) != plain[min(prefixBytes, len(plain)):] {
		return "", 0, "", false
	}
	return strings.NewReplacer("b", "│", "s", " ").Replace(after[:n]), prefixBytes, content, true
}

func stripStyleTags(s string) string {
	var out strings.Builder
	last := 0
	for _, loc := range styleTagPattern.FindAllStringIndex(s, -1) {
		out.WriteString(tview.Unescape(s[last:loc[0]]))
		last = loc[1]
	}
	out.WriteString(tview.Unescape(s[last:]))
	return out.String()
}

func lineRows(raw, plain string, width int) []rowSpan {
	prefixBytes, indent, hang := 0, 0, false
	if strings.HasPrefix(raw, userRailPrefix) {
		prefixBytes, indent = len("▌ "), userRailWidth
	} else if cont, n, _, ok := hangLine(raw, plain); ok && width > utf8.RuneCountInString(cont) {
		prefixBytes, indent, hang = n, utf8.RuneCountInString(cont), true
	}
	if indent == 0 {
		return wrapRowsAt(plain, width, 0)
	}
	rows := wrapRowsAt(plain[prefixBytes:], width, indent)
	for i := range rows {
		rows[i].start += prefixBytes
		rows[i].end += prefixBytes
		if i > 0 {
			rows[i].prefixWidth = indent
		}
	}
	rows[0].start = 0
	for _, row := range rows {
		if hang && byteOffsetInRow(plain, row, width) < row.end {
			return wrapRowsAt(plain, width, 0)
		}
	}
	return rows
}

func hangWrapLine(line string, width int, strip *tview.TextView) string {
	plain := strip.SetText(line).GetText(true)
	cont, pos, content, ok := hangLine(line, plain)
	if !ok {
		return line
	}
	rows := lineRows(line, plain, width)
	if len(rows) < 2 || rows[1].prefixWidth == 0 {
		return line
	}
	var out strings.Builder
	out.WriteString(plain[:pos])
	active := ""
	k := 0
	write := func(s string) {
		for s != "" {
			switch {
			case k+1 < len(rows) && pos >= rows[k+1].start:
				if active != "" {
					out.WriteString(defaultTag)
				}
				out.WriteString("\n" + cont + active)
				k++
			case k+1 < len(rows) && pos >= rows[k].end:
				n := min(len(s), rows[k+1].start-pos)
				s, pos = s[n:], pos+n
			default:
				n := len(s)
				if k+1 < len(rows) {
					n = min(n, rows[k].end-pos)
				}
				out.WriteString(tview.Escape(s[:n]))
				s, pos = s[n:], pos+n
			}
		}
	}
	last := 0
	for _, loc := range styleTagPattern.FindAllStringIndex(content, -1) {
		write(tview.Unescape(content[last:loc[0]]))
		tag := content[loc[0]:loc[1]]
		out.WriteString(tag)
		if tag == defaultTag {
			active = ""
		} else {
			active += tag
		}
		last = loc[1]
	}
	write(tview.Unescape(content[last:]))
	return out.String()
}

func railWrapText(text string, width int) string {
	lines := strings.Split(text, "\n")
	var strip *tview.TextView
	for i, line := range lines {
		if strings.HasPrefix(line, hangTagOpen) {
			if strip == nil {
				strip = tview.NewTextView().SetDynamicColors(true)
			}
			lines[i] = hangWrapLine(line, width, strip)
			continue
		}
		raw, ok := strings.CutPrefix(line, userRailPrefix)
		if !ok || width <= userRailWidth {
			continue
		}
		plain := tview.NewTextView().SetDynamicColors(true).SetText(raw).GetText(true)
		rows := wrapRowsAt(plain, width, userRailWidth)
		wrapped := make([]string, len(rows))
		for j, row := range rows {
			wrapped[j] = userRailPrefix + tview.Escape(plain[row.start:row.end])
		}
		lines[i] = strings.Join(wrapped, "\n")
	}
	return strings.Join(lines, "\n")
}

const (
	answeredRecordHeading      = "Answered (ask_user):"
	clarificationRecordHeading = "Asked for clarification (ask_user):"
	unansweredRecordText       = "(no answer)"
)

func questionRecordBlock(res QuestionResult) string {
	var heading string
	var body []string
	switch {
	case res.Cancelled:
		return ""
	case res.Clarification != "":
		heading, body = clarificationRecordHeading, []string{res.Clarification}
	case len(res.Answers) > 0:
		heading = answeredRecordHeading
		for _, a := range res.Answers {
			body = append(body, a.Prompt+" — "+questionAnswerText(a))
		}
	default:
		return ""
	}
	lines := []string{"[" + accentTealHex + "]" + tview.Escape(heading) + "[-]"}
	for _, line := range body {
		lines = append(lines, tview.Escape("  "+line))
	}
	return strings.Join(lines, "\n")
}

func questionAnswerText(a QuestionAnswer) string {
	parts := a.Selected
	if a.Custom != "" {
		parts = append(append([]string{}, parts...), a.Custom)
	}
	if len(parts) == 0 {
		return unansweredRecordText
	}
	return strings.Join(parts, ", ")
}

// contentPartBlock renders a content-part user message (sessions.PartsContent) into
// its transcript block for the /resume replay path: the text part becomes the
// "> text" line and each image_url part a "[image: name (size)]" placeholder, via
// the same userBlockLines renderer the live echo uses. A message with no text and no
// image parts (only unknown part types) yields "", so replay skips it exactly as the
// live pane shows nothing for it (phase-1 scope).
func contentPartBlock(parts []sessions.ContentPart) string {
	var text string
	var images []sessions.ContentPart
	for _, p := range parts {
		switch p.Type {
		case "text":
			if s := textPartContent(p); s != "" {
				text = s
			}
		case "image_url":
			images = append(images, p)
		}
	}
	return userBlockLines(text, images)
}

// textPartContent reads the text of a "text" content part, or "" when the raw part
// is malformed or carries no text — the inverse of the {"type":"text","text":…}
// shape the pre-turn boundary persists.
func textPartContent(p sessions.ContentPart) string {
	var w struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(p.Raw, &w); err != nil {
		return ""
	}
	return w.Text
}

// imagePlaceholder renders the "[image: name (size)]" placeholder for an image_url
// content part. The name is the codemeld-private "name" sibling imageURLContentPart
// persisted (falling back to "image" when absent), and the size is derived from the
// data: URI's base64 length, so replay needs no separately stored size.
func imagePlaceholder(p sessions.ContentPart) string {
	var w struct {
		Name     string `json:"name"`
		ImageURL struct {
			URL string `json:"url"`
		} `json:"image_url"`
	}
	_ = json.Unmarshal(p.Raw, &w)
	name := w.Name
	if name == "" {
		name = "image"
	}
	return fmt.Sprintf("[image: %s (%s)]", name, humanBytes(dataURIByteLen(w.ImageURL.URL)))
}

// dataURIByteLen returns the decoded byte length of a data:…;base64,… URI's payload
// without decoding it, so the placeholder size can be computed cheaply. A URI that
// is not base64-form yields 0.
func dataURIByteLen(uri string) int64 {
	const marker = ";base64,"
	i := strings.Index(uri, marker)
	if i < 0 {
		return 0
	}
	return base64ByteLen(uri[i+len(marker):])
}

// base64ByteLen returns the number of bytes a canonical (padded) standard-base64
// string decodes to, computed from its length and trailing '=' padding so no decode
// is performed.
func base64ByteLen(s string) int64 {
	if len(s) == 0 {
		return 0
	}
	pad := 0
	for i := len(s) - 1; i >= 0 && s[i] == '='; i-- {
		pad++
	}
	return int64(len(s)/4*3 - pad)
}

// humanBytes renders a byte count compactly for the image placeholder: bytes under
// 1 KiB print whole ("823 B"), then KiB and MiB with one decimal place (trailing
// ".0" trimmed, reusing trimDecimal) and a "KB"/"MB" label.
func humanBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return trimDecimal(float64(n)/1024) + " KB"
	default:
		return trimDecimal(float64(n)/(1024*1024)) + " MB"
	}
}
