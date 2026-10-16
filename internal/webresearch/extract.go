package webresearch

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

var errExtraction = errors.New("webresearch: extraction failed")

var omittedHTML = map[string]bool{
	"noscript": true,
	"script":   true,
	"style":    true,
	"template": true,
}

var blockHTML = map[string]bool{
	"article": true, "blockquote": true, "br": true, "div": true, "dl": true, "dt": true,
	"dd": true, "fieldset": true, "figcaption": true, "figure": true, "footer": true, "form": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "header": true,
	"hr": true, "li": true, "main": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "table": true, "td": true, "th": true, "tr": true, "ul": true,
}

func extractText(mediaType string, body []byte, cap int) (string, error) {
	switch mediaType {
	case "text/html", "application/xhtml+xml":
		return extractHTML(body, cap)
	case "application/json":
		if !json.Valid(body) {
			return "", errExtraction
		}
	case "application/xml", "text/xml":
		if _, err := extractXML(body); err != nil {
			return "", errExtraction
		}
	}
	return normalizeText(string(body), cap, false), nil
}

func extractHTML(body []byte, cap int) (string, error) {
	node, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", errExtraction
	}
	var text strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			text.WriteString(strings.Map(newlineToSpace, n.Data))
			return
		}
		if n.Type == html.ElementNode {
			if omittedHTML[n.Data] || hasHiddenAttribute(n) {
				return
			}
			if blockHTML[n.Data] {
				text.WriteString("\n\n")
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if n.Type == html.ElementNode && blockHTML[n.Data] {
			text.WriteString("\n\n")
		}
	}
	walk(node)
	return normalizeText(text.String(), cap, true), nil
}

// newlineToSpace keeps a source line break inside a text node from reaching
// normalizeText, which reads a newline as the paragraph boundary that only
// extractHTML's block-element writes are allowed to mean.
func newlineToSpace(r rune) rune {
	if r == '\n' || r == '\r' {
		return ' '
	}
	return r
}

func hasHiddenAttribute(n *html.Node) bool {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, "hidden") {
			return true
		}
	}
	return false
}

func extractXML(body []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return text.String(), nil
		}
		if err != nil {
			return "", err
		}
		if chars, ok := token.(xml.CharData); ok {
			text.Write(chars)
		}
	}
}

func normalizeText(value string, cap int, paragraphs bool) string {
	if cap <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	var normalized strings.Builder
	newlines := 0
	space := false
	for _, r := range value {
		switch {
		case r == '\n' || r == '\r':
			if paragraphs && normalized.Len() > 0 && newlines < 2 {
				normalized.WriteByte('\n')
				newlines++
			}
			space = normalized.Len() > 0
		case unicode.IsSpace(r):
			if normalized.Len() > 0 {
				space = true
			}
		case unicode.IsControl(r):
		case space:
			if normalized.Len() > 0 && newlines == 0 {
				normalized.WriteByte(' ')
			}
			normalized.WriteRune(r)
			space = false
			newlines = 0
		default:
			normalized.WriteRune(r)
			newlines = 0
		}
	}
	return truncateUTF8(strings.TrimSpace(normalized.String()), cap)
}

func truncateUTF8(value string, cap int) string {
	if cap <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= cap {
		return value
	}
	end := cap
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}
