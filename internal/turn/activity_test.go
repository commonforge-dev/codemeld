package turn

import (
	"testing"

	"codemeld.dev/codemeld/internal/toolactivity"
)

func TestToolActivityLinesDelegatesToSharedFormatter(t *testing.T) {
	cases := []struct {
		name string
		call AssembledToolCall
		want string
	}{
		{"bash command", AssembledToolCall{Name: "bash", Arguments: `{"command":"go build ./..."}`}, "Run: go build ./..."},
		{"read path", AssembledToolCall{Name: "read", Arguments: `{"path":"server.go"}`}, "Read server.go"},
		{"edit path", AssembledToolCall{Name: "edit", Arguments: `{"path":"pkg/utils.go"}`}, "Edit pkg/utils.go"},
		{"create path", AssembledToolCall{Name: "create", Arguments: `{"path":"new.txt"}`}, "Create new.txt"},
		{"list path", AssembledToolCall{Name: "list", Arguments: `{"path":"internal"}`}, "List internal"},
		{"tree path", AssembledToolCall{Name: "tree", Arguments: `{"path":"."}`}, "Tree ."},
		{"grep pattern", AssembledToolCall{Name: "grep", Arguments: `{"pattern":"func main"}`}, "Grep func main"},
		{"glob pattern", AssembledToolCall{Name: "glob", Arguments: `{"pattern":"**/*.go"}`}, "Glob **/*.go"},
		{"move endpoints", AssembledToolCall{Name: "move", Arguments: `{"source":"old.go","destination":"new.go"}`}, "Move old.go -> new.go"},
		{"web search query", AssembledToolCall{Name: "web_search", Arguments: `{"query":"golang tview escape"}`}, "WebSearch golang tview escape"},
		{"web fetch url", AssembledToolCall{Name: "web_fetch", Arguments: `{"url":"https://go.dev/doc/effective_go"}`}, "WebFetch https://go.dev/doc/effective_go"},
		{"unknown tool", AssembledToolCall{Name: "vcs_commit", Arguments: `{"message":"x"}`}, "vcs_commit"},
		{"malformed arguments", AssembledToolCall{Name: "bash", Arguments: `{not json`}, "bash"},
		{"malformed web arguments", AssembledToolCall{Name: "web_fetch", Arguments: `{not json`}, "web_fetch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ToolActivityLines([]AssembledToolCall{tc.call})
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("ToolActivityLines(%+v) = %v, want [%q]", tc.call, got, tc.want)
			}
			if shared := toolactivity.Format(tc.call.Name, tc.call.Arguments); got[0] != shared {
				t.Fatalf("line = %q, want the shared formatter's %q", got[0], shared)
			}
		})
	}
}

func TestToolActivityLinesPreservesOrder(t *testing.T) {
	calls := []AssembledToolCall{
		{ID: "a", Name: "read", Arguments: `{"path":"a.go"}`},
		{ID: "b", Name: "web_search", Arguments: `{"query":"tview escape"}`},
		{ID: "c", Name: "bash", Arguments: `{"command":"go test"}`},
		{ID: "d", Name: "web_fetch", Arguments: `{"url":"https://go.dev"}`},
		{ID: "e", Name: "grep", Arguments: `{"pattern":"TODO"}`},
	}
	got := ToolActivityLines(calls)
	want := []string{"Read a.go", "WebSearch tview escape", "Run: go test", "WebFetch https://go.dev", "Grep TODO"}
	if len(got) != len(want) {
		t.Fatalf("ToolActivityLines len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// An empty round yields an empty (non-nil-required) slice, so the surface appends nothing.
func TestToolActivityLinesEmpty(t *testing.T) {
	if got := ToolActivityLines(nil); len(got) != 0 {
		t.Fatalf("ToolActivityLines(nil) = %v, want empty", got)
	}
}

func TestEmitDenialNoticeText(t *testing.T) {
	cases := []struct {
		name string
		call AssembledToolCall
		want string
	}{
		{"bash", AssembledToolCall{Name: "bash", Arguments: `{"command":"rm -rf /"}`}, "Denied Run: rm -rf /: out of repo scope"},
		{"edit", AssembledToolCall{Name: "edit", Arguments: `{"path":"pkg/utils.go"}`}, "Denied Edit pkg/utils.go: out of repo scope"},
		{"web fetch", AssembledToolCall{Name: "web_fetch", Arguments: `{"url":"https://go.dev"}`}, "Denied WebFetch https://go.dev: out of repo scope"},
		{"malformed arguments", AssembledToolCall{Name: "web_search", Arguments: `{not json`}, "Denied web_search: out of repo scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var notices []string
			loop := NewToolLoop(Deps{ToolNotice: func(text string) { notices = append(notices, text) }}, nil, 1)
			loop.emitDenialNotice(tc.call, denyEnvelopeInfo{deniedBy: deniedByUser, reason: "out of repo scope"}, true)
			if len(notices) != 1 || notices[0] != tc.want {
				t.Fatalf("denial notices = %v, want [%q]", notices, tc.want)
			}
		})
	}
}
