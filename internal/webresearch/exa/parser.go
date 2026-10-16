package exa

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/webresearch"
)

const (
	maxTitleBytes     = 512
	maxPublishedBytes = 512
	maxSnippetBytes   = 4096
)

// recordSeparator is the provider's full record boundary; a bare dash line is
// ordinary excerpt text and must not split a record.
const recordSeparator = "\n\n---\n\n"

// errNoCandidates carries no input text: the labelled block is untrusted
// provider data and must not reach an error message.
var errNoCandidates = errors.New("exa: the search response held no usable result")

var dateLayouts = []string{time.RFC3339, "2006-01-02"}

func parseResults(text string) ([]webresearch.Candidate, error) {
	var out []webresearch.Candidate
	for _, block := range strings.Split(text, recordSeparator) {
		out = parseRecord(block).appendTo(out)
	}
	if len(out) == 0 {
		return nil, errNoCandidates
	}
	return out, nil
}

type record struct {
	title     string
	url       string
	published string
	snippet   string
	inSnippet bool
}

// Only pre-snippet labels may set candidate fields.
func parseRecord(block string) record {
	var r record
	for _, line := range strings.Split(block, "\n") {
		if r.inSnippet {
			r.snippet += "\n" + line
			continue
		}
		label, value, ok := splitLabel(line)
		if !ok {
			continue
		}
		switch label {
		case "Title":
			setOnce(&r.title, value)
		case "URL":
			setOnce(&r.url, value)
		case "Published Date", "Published":
			setOnce(&r.published, value)
		case "Highlights", "Text":
			r.snippet = value
			r.inSnippet = true
		}
	}
	return r
}

// The URL alone carries no length cap: a cut names a different fetch target, so an over-long
// result must reach the capability layer whole for it to omit and count.
func (r record) appendTo(out []webresearch.Candidate) []webresearch.Candidate {
	url := validUTF8(r.url)
	if url == "" {
		return out
	}
	return append(out, webresearch.Candidate{
		Title:         capUTF8(r.title, maxTitleBytes),
		URL:           url,
		Snippet:       capUTF8(r.snippet, maxSnippetBytes),
		PublishedDate: publishedDate(r.published),
	})
}

func setOnce(field *string, value string) {
	if *field == "" {
		*field = value
	}
}

func splitLabel(line string) (label, value string, ok bool) {
	colon := strings.Index(line, ":")
	if colon < 0 {
		return "", "", false
	}
	label = strings.TrimSpace(line[:colon])
	switch label {
	case "Title", "URL", "Published Date", "Published", "Highlights", "Text", "Author":
		return label, strings.TrimSpace(line[colon+1:]), true
	}
	return "", "", false
}

func publishedDate(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maxPublishedBytes {
		return ""
	}
	for _, layout := range dateLayouts {
		if _, err := time.Parse(layout, value); err == nil {
			return value
		}
	}
	return ""
}

func validUTF8(s string) string {
	return strings.ToValidUTF8(strings.TrimSpace(s), "�")
}

// capUTF8 coerces invalid bytes before applying the cap, so the kept prefix is
// valid UTF-8 and never longer than max even when a replacement rune grows the
// input.
func capUTF8(s string, max int) string {
	s = validUTF8(s)
	if len(s) <= max {
		return s
	}
	b := max
	for b > 0 && !utf8.RuneStart(s[b]) {
		b--
	}
	return s[:b]
}
