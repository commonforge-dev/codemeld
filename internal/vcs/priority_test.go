package vcs

import (
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/config"
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
	wantGit := "codemeld: multiple VCS detected (git, hg); using \"git\". Set vcs.force in the .codemeld/settings.yaml file to force a choice.\n" +
		"Example:\n" +
		"  vcs:\n" +
		"    force: hg"
	if w := AmbiguityWarning([]string{"git", "hg"}, "git", false); w != wantGit {
		t.Errorf("git winner warning:\n got %q\nwant %q", w, wantGit)
	}

	wantHg := "codemeld: multiple VCS detected (git, hg); using \"hg\". Set vcs.force in the .codemeld/settings.yaml file to force a choice.\n" +
		"Example:\n" +
		"  vcs:\n" +
		"    force: git"
	if w := AmbiguityWarning([]string{"git", "hg"}, "hg", false); w != wantHg {
		t.Errorf("hg winner warning:\n got %q\nwant %q", w, wantHg)
	}

	for _, winner := range []string{"git", "hg"} {
		w := AmbiguityWarning([]string{"git", "hg"}, winner, false)
		if strings.Contains(w, "vcs.priority") || strings.Contains(w, "vcs.preferred") {
			t.Errorf("warning names an old setting: %q", w)
		}
	}

	w := AmbiguityWarning([]string{"git", "evil\nname"}, "git", false)
	if got := strings.Count(w, "\n"); got != 3 {
		t.Errorf("newline in a matched name changed the line count to %d: %q", got+1, w)
	}
	if !strings.Contains(w, "(git, evil name)") || !strings.HasSuffix(w, "force: evil name") {
		t.Errorf("collapsed name missing from warning: %q", w)
	}

	for _, name := range []string{"true", "false", "null", "yes", "no", "on", "off", "y", "n"} {
		if !filenameRe.MatchString(name + ".yaml") {
			t.Fatalf("%q is not a valid custom template name", name)
		}
		w := AmbiguityWarning([]string{"git", name}, "git", false)
		_, example, ok := strings.Cut(w, "\nExample:\n")
		if !ok {
			t.Fatalf("warning has no example block: %q", w)
		}
		raw, _, err := config.ValidateProjectSettingsBytes([]byte(example+"\n"), "project/.codemeld/settings.yaml")
		if err != nil {
			t.Fatalf("example for %q does not load: %v\n%s", name, err, example)
		}
		vcsMap, _ := raw["vcs"].(map[string]any)
		got, isString := vcsMap["force"].(string)
		if !isString || got != name {
			t.Fatalf("example for %q loads vcs.force as %#v", name, vcsMap["force"])
		}
		if err := ValidateForce(got, builtin.BuiltinNames(), []string{name}, "project/.codemeld/settings.yaml"); err != nil {
			t.Fatalf("example for %q does not resolve its template: %v", name, err)
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
	// force applied bypasses tie-breaking, so no ambiguity warning.
	if w := AmbiguityWarning([]string{"git", "hg"}, "hg", true); w != "" {
		t.Errorf("expected no warning when vcs.force applied, got %q", w)
	}
}
