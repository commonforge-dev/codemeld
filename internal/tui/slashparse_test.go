// Table-driven coverage for the slash-command parser: TR-TUI-1 cases plus
// near-miss and TR-TUI-12 non-slash inputs.
package tui

import (
	"slices"
	"testing"
)

func TestParseSlashInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKind SlashParseKind
		wantName string   // checked only when wantKind == KindSlashInvocation
		wantArgs []string // checked only when wantKind == KindSlashInvocation
	}{
		// --- slash invocations ---
		{"valid name no args", "/help", KindSlashInvocation, "help", nil},
		{"leading whitespace before slash", "   /help", KindSlashInvocation, "help", nil},
		{"name with single arg", "/model gpt-4", KindSlashInvocation, "model", []string{"gpt-4"}},
		{"name with multiple args", "/effort high now", KindSlashInvocation, "effort", []string{"high", "now"}},
		{"whitespace-collapsed args", "/cmd   a    b\tc", KindSlashInvocation, "cmd", []string{"a", "b", "c"}},
		{"trailing whitespace after args", "/status   ", KindSlashInvocation, "status", nil},
		{"hyphenated name", "/foo-bar", KindSlashInvocation, "foo-bar", nil},
		{"name with digits", "/cmd2", KindSlashInvocation, "cmd2", nil},
		{"unknown but valid name parses", "/definitelynotacommand", KindSlashInvocation, "definitelynotacommand", nil},

		// bare exit / quit ---
		{"bare exit", "exit", KindBareExit, "", nil},
		{"bare quit", "quit", KindBareExit, "", nil},
		{"exit uppercase", "EXIT", KindBareExit, "", nil},
		{"quit mixed case", "QuIt", KindBareExit, "", nil},
		{"exit with surrounding whitespace", "   exit   ", KindBareExit, "", nil},
		{"quit with tabs", "\tquit\t", KindBareExit, "", nil},

		// --- non-slash text and near-misses (TR-TUI-12) ---
		{"empty input", "", KindNotASlashCommand, "", nil},
		{"whitespace only", "   ", KindNotASlashCommand, "", nil},
		{"bare slash", "/", KindNotASlashCommand, "", nil},
		{"slash space", "/ ", KindNotASlashCommand, "", nil},
		{"slash then args no name", "/ help", KindNotASlashCommand, "", nil},
		{"uppercase name rejected", "/Help", KindNotASlashCommand, "", nil},
		{"name starting with digit rejected", "/1cmd", KindNotASlashCommand, "", nil},
		{"name starting with hyphen rejected", "/-cmd", KindNotASlashCommand, "", nil},
		{"name with dot rejected", "/foo.bar", KindNotASlashCommand, "", nil},
		{"underscore name rejected", "/foo_bar", KindNotASlashCommand, "", nil},
		{"exit with trailing word", "exit now", KindNotASlashCommand, "", nil},
		{"please exit", "please exit", KindNotASlashCommand, "", nil},
		{"quit substring", "quitter", KindNotASlashCommand, "", nil},
		{"ordinary prompt", "summarize this file", KindNotASlashCommand, "", nil},
		{"slash not first char", "use /help to begin", KindNotASlashCommand, "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSlashInput(tt.input)
			if got.Kind != tt.wantKind {
				t.Fatalf("ParseSlashInput(%q).Kind = %v, want %v", tt.input, got.Kind, tt.wantKind)
			}
			if tt.wantKind != KindSlashInvocation {
				// Invocation must be the zero value for non-invocation kinds.
				if got.Invocation.Name != "" || got.Invocation.Args != nil {
					t.Fatalf("ParseSlashInput(%q).Invocation = %+v, want zero value", tt.input, got.Invocation)
				}
				return
			}
			if got.Invocation.Name != tt.wantName {
				t.Fatalf("ParseSlashInput(%q).Name = %q, want %q", tt.input, got.Invocation.Name, tt.wantName)
			}
			if !slices.Equal(got.Invocation.Args, tt.wantArgs) {
				t.Fatalf("ParseSlashInput(%q).Args = %#v, want %#v", tt.input, got.Invocation.Args, tt.wantArgs)
			}
		})
	}
}
