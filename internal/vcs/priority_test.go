package vcs

import (
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/vcs/builtin"
)

// builtinSet builds the builtinNames lookup callers pass to Rank/TieBreak from the canonical names.
func builtinSet() map[string]bool {
	set := map[string]bool{}
	for _, n := range builtin.BuiltinNames() {
		set[n] = true
	}
	return set
}

func TestTieBreak(t *testing.T) {
	builtins := builtinSet()
	tests := []struct {
		name     string
		matches  []string
		priority []string
		want     string
	}{
		{
			name:     "default priority picks git over hg",
			matches:  []string{"hg", "git"},
			priority: []string{"git", "hg", "jj"},
			want:     "git",
		},
		{
			name:     "user-set priority picks hg over git",
			matches:  []string{"git", "hg"},
			priority: []string{"hg", "git", "jj"},
			want:     "hg",
		},
		{
			name:     "listed beats unlisted regardless of name",
			matches:  []string{"git", "aardvark"},
			priority: []string{"git"},
			want:     "git",
		},
		{
			name:     "tie on unlisted: builtin before user-defined",
			matches:  []string{"fossil", "hg"},
			priority: []string{},
			want:     "hg",
		},
		{
			name:     "tie on unlisted builtins: alphabetical",
			matches:  []string{"jj", "hg", "git"},
			priority: []string{},
			want:     "git",
		},
		{
			name:     "tie on unlisted user-defined: alphabetical",
			matches:  []string{"zebra", "fossil"},
			priority: []string{},
			want:     "fossil",
		},
		{
			name:     "single match returned directly",
			matches:  []string{"jj"},
			priority: []string{"git", "hg", "jj"},
			want:     "jj",
		},
		{
			name:     "no matches yields empty string",
			matches:  nil,
			priority: []string{"git", "hg", "jj"},
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TieBreak(tt.matches, tt.priority, builtins); got != tt.want {
				t.Errorf("TieBreak(%v, %v) = %q, want %q", tt.matches, tt.priority, got, tt.want)
			}
		})
	}
}

func TestRankBuckets(t *testing.T) {
	builtins := builtinSet()
	priority := []string{"git", "hg"}

	// Listed entries rank at their position; lower wins.
	if r := Rank("git", priority, builtins); r != 0 {
		t.Errorf("Rank(git) = %d, want 0", r)
	}
	if r := Rank("hg", priority, builtins); r != 1 {
		t.Errorf("Rank(hg) = %d, want 1", r)
	}
	// Unlisted built-in ranks after all listed entries.
	if r := Rank("jj", priority, builtins); r != len(priority) {
		t.Errorf("Rank(jj) = %d, want %d", r, len(priority))
	}
	// Unlisted user-defined ranks after unlisted built-ins.
	if r := Rank("fossil", priority, builtins); r != len(priority)+1 {
		t.Errorf("Rank(fossil) = %d, want %d", r, len(priority)+1)
	}
	// Ordering invariant: listed < unlisted-builtin < unlisted-user.
	if Rank("git", priority, builtins) >= Rank("jj", priority, builtins) ||
		Rank("jj", priority, builtins) >= Rank("fossil", priority, builtins) {
		t.Error("rank ordering listed < unlisted-builtin < unlisted-user violated")
	}
}

func TestAmbiguityWarning(t *testing.T) {
	// Emitted only when more than one detector matched and no preferred override applied.
	if w := AmbiguityWarning([]string{"git", "hg"}, "git", false); w == "" {
		t.Fatal("expected warning for ambiguous detection, got empty")
	} else {
		if !strings.Contains(w, "using \"git\" via vcs.priority") || !strings.Contains(w, "vcs.preferred") {
			t.Errorf("warning %q missing selected-winner phrase or config-key references", w)
		}
		if strings.Contains(w, "\n") {
			t.Errorf("warning is not single-line: %q", w)
		}
	}

	// Single match: no ambiguity.
	if w := AmbiguityWarning([]string{"git"}, "git", false); w != "" {
		t.Errorf("expected no warning for single match, got %q", w)
	}
	// No matches: no ambiguity.
	if w := AmbiguityWarning(nil, "", false); w != "" {
		t.Errorf("expected no warning for no matches, got %q", w)
	}
	// preferred applied bypasses tie-breaking, so no ambiguity warning.
	if w := AmbiguityWarning([]string{"git", "hg"}, "hg", true); w != "" {
		t.Errorf("expected no warning when vcs.preferred applied, got %q", w)
	}
}
