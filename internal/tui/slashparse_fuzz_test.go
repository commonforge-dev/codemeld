// Fuzz target for the slash-command parser (TR-TUI-2): random byte slices
// must never panic ParseSlashInput, and any returned slash invocation must carry
// a name satisfying the grammar.
package tui

import (
	"regexp"
	"strings"
	"testing"
)

// fuzzNamePattern re-states the name grammar independently of the
// parser's own namePattern, so a regression in the parser is caught rather than
// masked by reusing the same compiled regex it validates against.
var fuzzNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func FuzzSlashParse(f *testing.F) {
	seeds := []string{
		"/",                           // bare slash → not a command
		"/help",                       // valid invocation, no args
		"/exit foo bar",               // valid invocation with args
		"exit",                        // bare exit synonym
		"/  /  /",                     // whitespace-heavy malformed slash forms
		"/café résumé",                // unicode after the slash
		"/日本語",                        // non-latin name (must be rejected, not panic)
		strings.Repeat("/a b ", 4000), // very long input
		"/ab\x00cd",                   // NUL byte inside the name
		"\x00\x00\x00",                // bare NUL bytes
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		got := ParseSlashInput(input) // must not panic for any input

		if got.Kind != KindSlashInvocation {
			return
		}
		if !fuzzNamePattern.MatchString(got.Invocation.Name) {
			t.Fatalf("ParseSlashInput(%q) returned slash invocation with invalid name %q (must match %s)",
				input, got.Invocation.Name, fuzzNamePattern)
		}
	})
}
