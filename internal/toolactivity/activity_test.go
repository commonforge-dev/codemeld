package toolactivity

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestPackageImportsOnlyStdlib(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	parsed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquote import %s: %v", name, spec.Path.Value, err)
			}
			if strings.HasPrefix(path, "codemeld.dev/") {
				t.Fatalf("%s imports %q; internal/toolactivity must import only the standard library", name, path)
			}
		}
	}
	if parsed == 0 {
		t.Fatal("parsed no package sources")
	}
}

func TestFormat(t *testing.T) {
	longCmd := strings.Repeat("a", 200)
	longQuery := strings.Repeat("q", 200)
	longURL := "https://example.test/" + strings.Repeat("p", 200)
	cases := []struct {
		name string
		tool string
		args string
		want string
	}{
		{"bash command", "bash", `{"command":"go build ./..."}`, "Run: go build ./..."},
		{"read path", "read", `{"path":"server.go"}`, "Read server.go"},
		{"edit path", "edit", `{"path":"pkg/utils.go"}`, "Edit pkg/utils.go"},
		{"create path", "create", `{"path":"new.txt"}`, "Create new.txt"},
		{"list path", "list", `{"path":"internal"}`, "List internal"},
		{"tree path", "tree", `{"path":"."}`, "Tree ."},
		{"grep pattern", "grep", `{"pattern":"func main"}`, "Grep func main"},
		{"glob pattern", "glob", `{"pattern":"**/*.go"}`, "Glob **/*.go"},
		{"move source and destination", "move", `{"source":"old.go","destination":"new.go"}`, "Move old.go -> new.go"},

		{"web search query", "web_search", `{"query":"golang tview escape"}`, "WebSearch golang tview escape"},
		{"web search keeps operators", "web_search", `{"query":"site:go.dev \"context cancel\" -tutorial"}`, `WebSearch site:go.dev "context cancel" -tutorial`},
		{"web fetch url", "web_fetch", `{"url":"https://go.dev/doc/effective_go"}`, "WebFetch https://go.dev/doc/effective_go"},
		{"web fetch keeps query and fragment", "web_fetch", `{"url":"https://example.test/a?b=c&d=e#frag"}`, "WebFetch https://example.test/a?b=c&d=e#frag"},
		{"web search ignores unrelated keys", "web_search", `{"query":"gopher","max_results":5}`, "WebSearch gopher"},

		{"move missing destination", "move", `{"source":"old.go"}`, "move"},
		{"move missing source", "move", `{"destination":"new.go"}`, "move"},
		{"move empty source", "move", `{"source":"","destination":"new.go"}`, "move"},
		{"move empty destination", "move", `{"source":"old.go","destination":""}`, "move"},
		{"move non-string destination", "move", `{"source":"old.go","destination":42}`, "move"},
		{"move malformed json", "move", `{not json`, "move"},

		{"vcs falls back to name", "vcs_commit", `{"message":"x"}`, "vcs_commit"},
		{"unknown falls back to name", "mystery", `{"path":"a"}`, "mystery"},

		{"bash malformed json", "bash", `{not json`, "bash"},
		{"bash missing key", "bash", `{"foo":"bar"}`, "bash"},
		{"bash empty command", "bash", `{"command":""}`, "bash"},
		{"read non-string path", "read", `{"path":42}`, "read"},
		{"read empty args", "read", ``, "read"},
		{"grep missing pattern", "grep", `{}`, "grep"},

		{"web search malformed json", "web_search", `{not json`, "web_search"},
		{"web search missing key", "web_search", `{"q":"gopher"}`, "web_search"},
		{"web search empty query", "web_search", `{"query":""}`, "web_search"},
		{"web search non-string query", "web_search", `{"query":42}`, "web_search"},
		{"web search empty args", "web_search", ``, "web_search"},
		{"web search array args", "web_search", `["query"]`, "web_search"},
		{"web fetch malformed json", "web_fetch", `{not json`, "web_fetch"},
		{"web fetch missing key", "web_fetch", `{"href":"https://example.test"}`, "web_fetch"},
		{"web fetch empty url", "web_fetch", `{"url":""}`, "web_fetch"},
		{"web fetch non-string url", "web_fetch", `{"url":["https://example.test"]}`, "web_fetch"},
		{"web fetch empty args", "web_fetch", ``, "web_fetch"},

		{"bash truncated", "bash", `{"command":"` + longCmd + `"}`, "Run: " + strings.Repeat("a", maxBashActivityRunes) + "…"},
		{"web search truncated", "web_search", `{"query":"` + longQuery + `"}`, "WebSearch " + strings.Repeat("q", maxWebActivityRunes) + "…"},
		{"web fetch truncated", "web_fetch", `{"url":"` + longURL + `"}`, "WebFetch " + string([]rune(longURL)[:maxWebActivityRunes]) + "…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Format(tc.tool, tc.args); got != tc.want {
				t.Fatalf("Format(%q, %q) = %q, want %q", tc.tool, tc.args, got, tc.want)
			}
		})
	}
}

func TestFormatWebDisplayBound(t *testing.T) {
	atLimit := strings.Repeat("x", maxWebActivityRunes)
	if got, want := Format("web_search", `{"query":"`+atLimit+`"}`), "WebSearch "+atLimit; got != want {
		t.Fatalf("web search at limit = %q, want %q", got, want)
	}
	if got, want := Format("web_fetch", `{"url":"`+atLimit+`"}`), "WebFetch "+atLimit; got != want {
		t.Fatalf("web fetch at limit = %q, want %q", got, want)
	}
	over := strings.Repeat("x", maxWebActivityRunes+1)
	if got, want := Format("web_search", `{"query":"`+over+`"}`), "WebSearch "+atLimit+"…"; got != want {
		t.Fatalf("web search over limit = %q, want %q", got, want)
	}
	multi := strings.Repeat("é", maxWebActivityRunes+5)
	if got, want := Format("web_fetch", `{"url":"`+multi+`"}`), "WebFetch "+strings.Repeat("é", maxWebActivityRunes)+"…"; got != want {
		t.Fatalf("web fetch multibyte = %q, want %q", got, want)
	}
}

func TestTruncateRunesBoundary(t *testing.T) {
	atLimit := strings.Repeat("x", maxBashActivityRunes)
	if got := truncateRunes(atLimit, maxBashActivityRunes); got != atLimit {
		t.Fatalf("truncateRunes at limit = %q, want unchanged", got)
	}
	over := strings.Repeat("x", maxBashActivityRunes+1)
	want := strings.Repeat("x", maxBashActivityRunes) + "…"
	if got := truncateRunes(over, maxBashActivityRunes); got != want {
		t.Fatalf("truncateRunes over limit = %q, want %q", got, want)
	}
	multi := strings.Repeat("é", maxBashActivityRunes+5)
	if got := truncateRunes(multi, maxBashActivityRunes); got != strings.Repeat("é", maxBashActivityRunes)+"…" {
		t.Fatalf("truncateRunes multibyte = %q, want %d é + ellipsis", got, maxBashActivityRunes)
	}
}

func TestWebLine(t *testing.T) {
	cases := []struct {
		name   string
		tool   string
		args   string
		want   string
		wantOK bool
	}{
		{"search", "web_search", `{"query":"gopher"}`, "WebSearch gopher", true},
		{"fetch", "web_fetch", `{"url":"https://go.dev"}`, "WebFetch https://go.dev", true},
		{"search malformed keeps bare name", "web_search", `{not json`, "web_search", true},
		{"fetch malformed keeps bare name", "web_fetch", `{"url":7}`, "web_fetch", true},
		{"bash rejected", "bash", `{"command":"rm -rf /"}`, "", false},
		{"read rejected", "read", `{"path":"secret.txt"}`, "", false},
		{"unknown rejected", "mystery", `{}`, "", false},
		{"empty name rejected", "", ``, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := WebLine(tc.tool, tc.args)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("WebLine(%q, %q) = (%q, %v), want (%q, %v)", tc.tool, tc.args, got, ok, tc.want, tc.wantOK)
			}
			if tc.wantOK && got != Format(tc.tool, tc.args) {
				t.Fatalf("WebLine(%q) = %q, want Format's %q (live and replay must not drift)", tc.tool, got, Format(tc.tool, tc.args))
			}
		})
	}
}
