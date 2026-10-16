package webresearch

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestExtractTextHTMLVisibleText(t *testing.T) {
	body := []byte(`<html><body><h1>  Heading </h1><p>First <b>paragraph</b>.</p><script>ignore()</script><style>.x{}</style><noscript>fallback</noscript><template>template</template><div hidden>secret</div><p>Second	paragraph.</p></body></html>`)
	want := "Heading\n\nFirst paragraph.\n\nSecond paragraph."
	for _, mediaType := range []string{"text/html", "application/xhtml+xml"} {
		got, err := extractText(mediaType, body, 256)
		if err != nil {
			t.Fatalf("extractText(%s) = %v", mediaType, err)
		}
		if got != want {
			t.Fatalf("extractText(%s) = %q, want %q", mediaType, got, want)
		}
	}
}

func TestExtractTextPreservesSafetyAndBounds(t *testing.T) {
	got, err := extractText("text/plain", []byte("one\x1b\x07\x7f"+string(rune(0x9b))+"two\xffthree"), 12)
	if err != nil {
		t.Fatalf("extractText = %v", err)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("extractText returned invalid UTF-8: %q", got)
	}
	if len(got) > 12 {
		t.Fatalf("extractText = %q, want text within the cap", got)
	}
	for _, r := range got {
		if unicode.IsControl(r) {
			t.Fatalf("extractText = %q, want no control rune %U", got, r)
		}
	}
	if !strings.Contains(got, "\uFFFD") {
		t.Fatalf("extractText = %q, want invalid bytes normalized", got)
	}
}

func TestExtractTextCollapsesLineBreaksIntoSpaces(t *testing.T) {
	plain, err := extractText("text/plain", []byte("line one\nline two"), 64)
	if err != nil {
		t.Fatalf("extractText = %v", err)
	}
	if plain != "line one line two" {
		t.Fatalf("extractText = %q, want the line break collapsed to a space", plain)
	}

	markup, err := extractText("text/html", []byte("<p>first\nsecond</p><p>third</p>"), 64)
	if err != nil {
		t.Fatalf("extractText = %v", err)
	}
	if markup != "first second\n\nthird" {
		t.Fatalf("extractText = %q, want a source line break collapsed inside its paragraph", markup)
	}
}

func TestExtractTextTruncatesAtARuneBoundary(t *testing.T) {
	got, err := extractText("text/plain", []byte("ααα"), 5)
	if err != nil {
		t.Fatalf("extractText = %v", err)
	}
	if got != "αα" || !utf8.ValidString(got) {
		t.Fatalf("extractText = %q, want %q cut before the third two-byte rune", got, "αα")
	}
}

func TestExtractTextHTMLRecoversMalformedMarkupWithoutLeaking(t *testing.T) {
	body := []byte(`<div><p>visible<script>leak()</script><span hidden>secret</span></b><p>tail`)
	got, err := extractText("text/html", body, 256)
	if err != nil {
		t.Fatalf("extractText = %v", err)
	}
	for _, unwanted := range []string{"leak()", "secret", "<", ">"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("extractText = %q, want recovered markup to expose no %q", got, unwanted)
		}
	}
	if !strings.Contains(got, "visible") || !strings.Contains(got, "tail") {
		t.Fatalf("extractText = %q, want the visible text of both paragraphs", got)
	}
}

func TestExtractTextRejectsMalformedStructuredDocuments(t *testing.T) {
	for mediaType, body := range map[string][]byte{
		"application/json": []byte(`{"unterminated":`),
		"application/xml":  []byte(`<document>`),
	} {
		t.Run(mediaType, func(t *testing.T) {
			got, err := extractText(mediaType, body, 128)
			if err == nil || got != "" {
				t.Fatalf("extractText = (%q, %v), want an empty generic failure", got, err)
			}
		})
	}
}
