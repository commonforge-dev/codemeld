package permissions

import (
	"sort"
	"testing"
)

// TestDestructiveProgramSetIsExact pins the curated set to an exact product set, mirroring
// TestPlanReadOnlyAllowlistIsExactProductSet: adding or dropping an entry is a deliberate
// table+test change, not an accidental drift.
func TestDestructiveProgramSetIsExact(t *testing.T) {
	want := []string{"git", "hg", "rm", "rmdir"}

	got := make([]string, 0, len(destructivePrograms))
	for name := range destructivePrograms {
		got = append(got, name)
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("destructive set = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("destructive set = %v, want exactly %v", got, want)
		}
	}
}

func TestIsDestructiveProgramPositives(t *testing.T) {
	for _, program := range []string{"rm", "rmdir", "hg", "git"} {
		if !IsDestructiveProgram(program) {
			t.Fatalf("IsDestructiveProgram(%q) = false, want true (curated destructive program)", program)
		}
	}
}

func TestIsDestructiveProgramNegatives(t *testing.T) {
	cases := []struct {
		name    string
		program string
	}{
		{"read-only ls", "ls"},
		{"read-only rg", "rg"},
		{"read-only cat", "cat"},
		{"unknown program", "frobnicate"},
		{"empty token", ""},
		// Canonical-token contract: a path-like, non-canonical token must not match by basename.
		{"path-like rm", "/tmp/rm"},
		{"relative path rm", "./rm"},
		{"path-like git", "/usr/bin/git"},
		// Exact-match contract: no prefix/substring or argument-bearing token matches.
		{"program with arguments", "rm -rf x"},
		{"subcommand-bearing token", "git push"},
		{"substring of a listed program", "rmx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsDestructiveProgram(tc.program) {
				t.Fatalf("IsDestructiveProgram(%q) = true, want false", tc.program)
			}
		})
	}
}
