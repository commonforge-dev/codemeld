package exa

import (
	"strings"
	"testing"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/webresearch"
)

const orderedResponse = `Title: First Result
URL: https://example.com/first
Published Date: 2026-01-02T03:04:05Z
Author: Ada Lovelace
Highlights: first highlight
continued highlight line

---

Title: Second Result
URL: https://example.org/second
Author: Grace Hopper
Text: second body

---

Title: Third Result
URL: https://example.net/third
`

func TestParseResults_OrderedNeutralCandidates(t *testing.T) {
	got, err := parseResults(orderedResponse)
	if err != nil {
		t.Fatalf("parseResults() error = %v, want nil", err)
	}
	want := []webresearch.Candidate{
		{
			Title:         "First Result",
			URL:           "https://example.com/first",
			Snippet:       "first highlight\ncontinued highlight line",
			PublishedDate: "2026-01-02T03:04:05Z",
		},
		{
			Title:   "Second Result",
			URL:     "https://example.org/second",
			Snippet: "second body",
		},
		{
			Title: "Third Result",
			URL:   "https://example.net/third",
		},
	}
	if len(got) != len(want) {
		t.Fatalf("parseResults() returned %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for i, c := range got {
		for _, author := range []string{"Ada Lovelace", "Grace Hopper"} {
			if strings.Contains(c.Title+c.URL+c.Snippet+c.PublishedDate, author) {
				t.Errorf("candidate %d carries the ignored Author %q: %+v", i, author, c)
			}
		}
	}
}

const capturedResponse = "Title: Venice AI Token | VVV - Venice Uncensored AI\n" +
	"URL: https://venice.ai/token\n" +
	"Published: N/A\n" +
	"Author: N/A\n" +
	"Highlights:\n" +
	"---\n" +
	"description: The Venice token (VVV) is an access key for AI agents\n" +
	"title: Venice AI Token | VVV - Venice Uncensored AI\n" +
	"image: https://venice.ai/images/landing-social-preview.png\n" +
	"\n---\n\n" +
	"Title: What is the Venice token (VVV)? - Venice.ai\n" +
	"URL: https://venice.ai/blog/what-is-vvv\n" +
	"Published: 2026-01-02\n" +
	"Author: Damien Neil and Jonathan Amsterdam\n" +
	"      17 October 2019\n" +
	"Text: VVV is: a staking asset\n"

func TestParseResults_CapturedProviderResponse(t *testing.T) {
	got, err := parseResults(capturedResponse)
	if err != nil {
		t.Fatalf("parseResults() error = %v, want nil", err)
	}
	want := []webresearch.Candidate{
		{
			Title: "Venice AI Token | VVV - Venice Uncensored AI",
			URL:   "https://venice.ai/token",
			Snippet: "---\ndescription: The Venice token (VVV) is an access key for AI agents\n" +
				"title: Venice AI Token | VVV - Venice Uncensored AI\n" +
				"image: https://venice.ai/images/landing-social-preview.png",
		},
		{
			Title:         "What is the Venice token (VVV)? - Venice.ai",
			URL:           "https://venice.ai/blog/what-is-vvv",
			Snippet:       "VVV is: a staking asset",
			PublishedDate: "2026-01-02",
		},
	}
	if len(got) != len(want) {
		t.Fatalf("parseResults() returned %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for i, c := range got {
		for _, ignored := range []string{"Damien Neil", "17 October 2019", "N/A"} {
			if strings.Contains(c.Title+c.URL+c.PublishedDate, ignored) {
				t.Errorf("candidate %d carries the ignored value %q: %+v", i, ignored, c)
			}
		}
	}
}

func TestParseResults_SnippetTextCannotSetMetadata(t *testing.T) {
	const hostile = "hostile-secret-marker"
	tests := []struct {
		name     string
		response string
		want     webresearch.Candidate
	}{
		{
			name: "labels after highlights",
			response: "Title: Real\nURL: https://example.com/real\nPublished Date: 2026-01-02\nHighlights: body\n" +
				"Title: " + hostile + "\nURL: https://" + hostile + "/evil\nPublished Date: 2020-02-03\n",
			want: webresearch.Candidate{
				Title:         "Real",
				URL:           "https://example.com/real",
				PublishedDate: "2026-01-02",
				Snippet: "body\nTitle: " + hostile + "\nURL: https://" + hostile +
					"/evil\nPublished Date: 2020-02-03",
			},
		},
		{
			name: "labels after text",
			response: "Title: Real\nURL: https://example.com/real\nText: body\n" +
				"URL: https://" + hostile + "/evil\nPublished: 2020-02-03\n",
			want: webresearch.Candidate{
				Title:   "Real",
				URL:     "https://example.com/real",
				Snippet: "body\nURL: https://" + hostile + "/evil\nPublished: 2020-02-03",
			},
		},
		{
			name:     "unknown labels beside a usable URL",
			response: "URL: https://example.com/result\nSnippet: " + hostile + "\nLink: https://" + hostile + "/evil\n",
			want:     webresearch.Candidate{URL: "https://example.com/result"},
		},
		{
			name:     "colonless lines beside a usable URL",
			response: "URL: https://example.com/result\nTitle " + hostile + "\n",
			want:     webresearch.Candidate{URL: "https://example.com/result"},
		},
		{
			name:     "repeated header labels",
			response: "Title: Real\nURL: https://example.com/real\nTitle: " + hostile + "\nURL: https://" + hostile + "/evil\n",
			want:     webresearch.Candidate{Title: "Real", URL: "https://example.com/real"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseResults(tc.response)
			if err != nil {
				t.Fatalf("parseResults() error = %v, want nil", err)
			}
			if len(got) != 1 {
				t.Fatalf("parseResults() = %+v, want one candidate", got)
			}
			if got[0] != tc.want {
				t.Errorf("candidate = %+v, want %+v", got[0], tc.want)
			}
			if strings.Contains(got[0].Title+got[0].URL+got[0].PublishedDate, hostile) {
				t.Errorf("hostile text reached candidate metadata: %+v", got[0])
			}
		})
	}
}

func TestParseResults_UnusableRecordDropped(t *testing.T) {
	response := "Title: No URL here\nHighlights: body\n\n---\n\nTitle: Usable\nURL: https://example.com/ok\n"
	got, err := parseResults(response)
	if err != nil {
		t.Fatalf("parseResults() error = %v, want nil", err)
	}
	if len(got) != 1 || got[0].URL != "https://example.com/ok" {
		t.Fatalf("parseResults() = %+v, want only the record carrying a URL", got)
	}
}

func TestParseResults_FieldCaps(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		value   string
		field   func(webresearch.Candidate) string
		wantLen int
	}{
		{"title at cap", "Title", strings.Repeat("t", maxTitleBytes), titleOf, maxTitleBytes},
		{"title over cap", "Title", strings.Repeat("t", maxTitleBytes+1), titleOf, maxTitleBytes},
		{"title multibyte boundary", "Title", strings.Repeat("t", maxTitleBytes-1) + "é", titleOf, maxTitleBytes - 1},
		{"snippet at cap", "Highlights", strings.Repeat("s", maxSnippetBytes), snippetOf, maxSnippetBytes},
		{"snippet over cap", "Highlights", strings.Repeat("s", maxSnippetBytes+1), snippetOf, maxSnippetBytes},
		{"snippet multibyte boundary", "Highlights", strings.Repeat("s", maxSnippetBytes-2) + "☃", snippetOf, maxSnippetBytes - 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := "URL: https://example.com/capped\n" + tc.label + ": " + tc.value + "\n"
			got, err := parseResults(response)
			if err != nil {
				t.Fatalf("parseResults() error = %v, want nil", err)
			}
			value := tc.field(got[0])
			if len(value) != tc.wantLen {
				t.Errorf("%s length = %d bytes, want %d", tc.label, len(value), tc.wantLen)
			}
			if !utf8.ValidString(value) {
				t.Errorf("%s is not valid UTF-8: %q", tc.label, value)
			}
			if !strings.HasPrefix(tc.value, value) {
				t.Errorf("%s = %q, want a prefix of the source value", tc.label, value)
			}
		})
	}
}

// candidateURLFieldBytes mirrors the capability layer's candidate url limit; the adapter must not
// pre-cut at it, because a shortened URL names a different fetch target than the one Exa ranked.
const candidateURLFieldBytes = 2048

func TestParseResults_URLNeverShortened(t *testing.T) {
	base := "https://example.com/"
	for _, tc := range []struct {
		name  string
		extra int
	}{{"at the capability field limit", 0}, {"one byte over", 1}, {"far over", 4096}} {
		t.Run(tc.name, func(t *testing.T) {
			url := base + strings.Repeat("u", candidateURLFieldBytes-len(base)+tc.extra)
			got, err := parseResults("URL: " + url + "\n")
			if err != nil {
				t.Fatalf("parseResults() error = %v, want nil", err)
			}
			if got[0].URL != url {
				t.Errorf("URL = %d bytes, want the complete %d-byte source URL", len(got[0].URL), len(url))
			}
		})
	}
}

func TestParseResults_URLCoercedToValidUTF8(t *testing.T) {
	got, err := parseResults("URL: https://example.com/bad\xff\xfetail\n")
	if err != nil {
		t.Fatalf("parseResults() error = %v, want nil", err)
	}
	if !utf8.ValidString(got[0].URL) {
		t.Errorf("URL is not valid UTF-8: %q", got[0].URL)
	}
	if got[0].URL != "https://example.com/bad�tail" {
		t.Errorf("URL = %q, want the invalid run coerced to one replacement rune", got[0].URL)
	}
}

func TestParseResults_InvalidUTF8Coerced(t *testing.T) {
	got, err := parseResults("URL: https://example.com/bad\nTitle: broken\xff\xfetail\n")
	if err != nil {
		t.Fatalf("parseResults() error = %v, want nil", err)
	}
	if !utf8.ValidString(got[0].Title) {
		t.Errorf("Title is not valid UTF-8: %q", got[0].Title)
	}
	if got[0].Title != "broken�tail" {
		t.Errorf("Title = %q, want the invalid run coerced to one replacement rune", got[0].Title)
	}
}

func TestParseResults_PublishedDate(t *testing.T) {
	tests := []struct {
		name  string
		lines string
		want  string
	}{
		{"missing", "", ""},
		{"empty value", "Published Date:\n", ""},
		{"malformed", "Published Date: yesterday afternoon\n", ""},
		{"overlong", "Published Date: " + strings.Repeat("2", maxPublishedBytes+1) + "\n", ""},
		{"rfc3339", "Published Date: 2026-01-02T03:04:05Z\n", "2026-01-02T03:04:05Z"},
		{"date only", "Published: 2026-01-02\n", "2026-01-02"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseResults("Title: Dated\nURL: https://example.com/dated\n" + tc.lines)
			if err != nil {
				t.Fatalf("parseResults() error = %v, want nil", err)
			}
			if len(got) != 1 {
				t.Fatalf("parseResults() = %+v, want one usable candidate", got)
			}
			if got[0].PublishedDate != tc.want {
				t.Errorf("PublishedDate = %q, want %q", got[0].PublishedDate, tc.want)
			}
			if len(got[0].PublishedDate) > maxPublishedBytes {
				t.Errorf("PublishedDate = %d bytes, want at most %d", len(got[0].PublishedDate), maxPublishedBytes)
			}
			if got[0].Title != "Dated" || got[0].URL != "https://example.com/dated" {
				t.Errorf("candidate = %+v, want the other fields intact", got[0])
			}
		})
	}
}

func TestParseResults_MalformedProducesNoCandidate(t *testing.T) {
	hostile := "hostile-secret-marker"
	tests := []struct {
		name     string
		response string
	}{
		{"empty", ""},
		{"blank records", "\n\n---\n\n   \n\n---\n\n"},
		{"unknown labels", "Snippet: " + hostile + "\nLink: https://example.com/" + hostile + "\n"},
		{"labels without a colon", "URL https://example.com/" + hostile + "\nTitle " + hostile + "\n"},
		{"author only", "Author: " + hostile + "\n"},
		{"url only inside a snippet", "Title: Fine\nHighlights: body\nURL: https://example.com/" + hostile + "\n"},
		{"no record carries a url", "Title: Fine\n\n---\n\nAuthor: " + hostile + "\n\n---\n\nText: " + hostile + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseResults(tc.response)
			if got != nil {
				t.Errorf("parseResults() = %+v, want no candidate", got)
			}
			if err == nil {
				t.Fatal("parseResults() error = nil, want a generic failure")
			}
			if strings.Contains(err.Error(), hostile) {
				t.Errorf("error echoes provider text: %q", err.Error())
			}
			if len(err.Error()) > 256 {
				t.Errorf("error is %d bytes, want a bounded message", len(err.Error()))
			}
		})
	}
}

func titleOf(c webresearch.Candidate) string { return c.Title }

func snippetOf(c webresearch.Candidate) string { return c.Snippet }
