// Tests for Tab slash-name completion: single-match completion and its
// trailing-space rule, longest-common-prefix extension, the non-extendable
// candidate list, alias-to-canonical completion with per-canonical dedupe, and the
// no-op cases (no match, not a slash, cursor outside the name token).
package tui

import (
	"reflect"
	"testing"
)

// tabNoHandler is a do-nothing handler so the completion-test registry passes
// NewRegistry's nil-handler validation without pulling in command behavior.
func tabNoHandler(CommandContext, []string) error { return nil }

// tabTestRegistry is a focused command set covering every completion rule:
// no-arg and arg-taking commands, an alias (new -> clear), two commands sharing a
// one-char prefix (effort/exit -> list), and two sharing a longer prefix
// (model/models -> extend).
func tabTestRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry([]Command{
		{Name: "help", Description: "h", ArgSig: ArgNone, Phase: PhaseOne, Handler: tabNoHandler},
		{Name: "clear", Aliases: []string{"new"}, Description: "c", ArgSig: ArgNone, Phase: PhaseOne, Handler: tabNoHandler},
		{Name: "status", Description: "s", ArgSig: ArgNone, Phase: PhaseOne, Handler: tabNoHandler},
		{Name: "effort", Description: "e", ArgSig: ArgOneRequired, Phase: PhaseOne, Handler: tabNoHandler},
		{Name: "exit", Aliases: []string{"quit"}, Description: "x", ArgSig: ArgNone, Phase: PhaseOne, Handler: tabNoHandler},
		{Name: "model", Description: "m", ArgSig: ArgOneRequired, Phase: PhaseOne, Handler: tabNoHandler},
		{Name: "models", Description: "ms", ArgSig: ArgNone, Phase: PhaseOne, Handler: tabNoHandler},
	})
	if err != nil {
		t.Fatalf("build test registry: %v", err)
	}
	return reg
}

func TestCompleteSlashName(t *testing.T) {
	reg := tabTestRegistry(t)

	tests := []struct {
		name   string
		text   string
		cursor int
		want   tabResult
	}{
		{
			name:   "single match no-arg command gets no trailing space",
			text:   "/hel",
			cursor: 4,
			want:   tabResult{Action: tabReplace, Text: "/help"},
		},
		{
			name:   "single match arg-required command gets trailing space",
			text:   "/eff",
			cursor: 4,
			want:   tabResult{Action: tabReplace, Text: "/effort "},
		},
		{
			name:   "single match completes whole name unchanged but adds its space",
			text:   "/status",
			cursor: 7,
			want:   tabResult{Action: tabReplace, Text: "/status"},
		},
		{
			name:   "alias prefix completes to canonical name",
			text:   "/ne",
			cursor: 3,
			want:   tabResult{Action: tabReplace, Text: "/clear"},
		},
		{
			name:   "full alias completes to canonical name",
			text:   "/new",
			cursor: 4,
			want:   tabResult{Action: tabReplace, Text: "/clear"},
		},
		{
			name:   "multiple matches extend to longest common prefix",
			text:   "/mod",
			cursor: 4,
			want:   tabResult{Action: tabReplace, Text: "/model"},
		},
		{
			name:   "no further extension lists candidates in registry order",
			text:   "/e",
			cursor: 2,
			want:   tabResult{Action: tabList, Matches: []string{"/effort", "/exit"}},
		},
		{
			name:   "exhausted common prefix lists the two model commands",
			text:   "/model",
			cursor: 6,
			want:   tabResult{Action: tabList, Matches: []string{"/model", "/models"}},
		},
		{
			name:   "no matching command is a no-op",
			text:   "/zzz",
			cursor: 4,
			want:   tabResult{Action: tabNoop},
		},
		{
			name:   "non-slash input is a no-op",
			text:   "hello",
			cursor: 5,
			want:   tabResult{Action: tabNoop},
		},
		{
			name:   "empty buffer is a no-op",
			text:   "",
			cursor: 0,
			want:   tabResult{Action: tabNoop},
		},
		{
			name:   "cursor in the argument region is a no-op (no arg completion)",
			text:   "/effort high",
			cursor: 12,
			want:   tabResult{Action: tabNoop},
		},
		{
			name:   "cursor just past the name onto the separating space is still a no-op",
			text:   "/effort high",
			cursor: 8,
			want:   tabResult{Action: tabNoop},
		},
		{
			name:   "leading whitespace before slash still completes",
			text:   "  /hel",
			cursor: 6,
			want:   tabResult{Action: tabReplace, Text: "  /help"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := completeSlashName(tc.text, tc.cursor, reg)
			if got.Action != tc.want.Action || got.Text != tc.want.Text || !reflect.DeepEqual(got.Matches, tc.want.Matches) {
				t.Errorf("completeSlashName(%q, %d) = %+v, want %+v", tc.text, tc.cursor, got, tc.want)
			}
		})
	}
}

// TestCompleteSlashNameAliasDedupe proves an alias and its own canonical name
// count as a single canonical match: "/" matches every command, and clear (which
// also owns the alias "new") appears exactly once rather than twice.
func TestCompleteSlashNameAliasDedupe(t *testing.T) {
	reg := tabTestRegistry(t)
	got := completeSlashName("/", 1, reg)
	if got.Action != tabList {
		t.Fatalf("completeSlashName(%q) action = %v, want tabList", "/", got.Action)
	}
	want := []string{"/help", "/clear", "/status", "/effort", "/exit", "/model", "/models"}
	if !reflect.DeepEqual(got.Matches, want) {
		t.Fatalf("matches = %v, want %v", got.Matches, want)
	}
	clears := 0
	for _, m := range got.Matches {
		if m == "/clear" {
			clears++
		}
	}
	if clears != 1 {
		t.Errorf("/clear appears %d times in %v, want exactly 1 (alias+canonical dedupe)", clears, got.Matches)
	}
}

// TestCompleteSlashNameIncludesSettings ties Tab completion to the real
// builtinCommands set (not the focused tabTestRegistry fixture): "/" over the
// production registry must offer "/settings", so this fails if the command is
// dropped from builtinCommands or its production wiring.
func TestCompleteSlashNameIncludesSettings(t *testing.T) {
	got := completeSlashName("/", 1, BuildRegistry(nil))
	if got.Action != tabList {
		t.Fatalf("completeSlashName(%q) action = %v, want tabList", "/", got.Action)
	}
	found := false
	for _, m := range got.Matches {
		if m == "/settings" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("/settings missing from completion candidates %v", got.Matches)
	}
}

// TestCompleteSlashNameNilRegistry confirms the helper is inert with no registry,
// matching the app wiring that leaves Tab a no-op before SetRegistry is called.
func TestCompleteSlashNameNilRegistry(t *testing.T) {
	if got := completeSlashName("/hel", 4, nil); got.Action != tabNoop {
		t.Errorf("nil registry: got %+v, want no-op", got)
	}
}
