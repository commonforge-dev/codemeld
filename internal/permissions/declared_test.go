package permissions

import "testing"

func TestParseDeclaredCommands_Accepted(t *testing.T) {
	entries, notices, err := ParseDeclaredCommands([]any{
		"prep-open-tasks.sh --only",
		"sed -n",
		"ls",
	})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v, want nil", err)
	}
	if len(notices) != 0 {
		t.Fatalf("notices = %v, want none", notices)
	}
	want := []string{"prep-open-tasks.sh --only :*", "sed -n :*", "ls :*"}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v, want %d entries", entries, len(want))
	}
	for i, w := range want {
		if entries[i].Subject != w {
			t.Fatalf("entries[%d].Subject = %q, want %q", i, entries[i].Subject, w)
		}
	}
}

func TestParseDeclaredCommands_Absent(t *testing.T) {
	entries, notices, err := ParseDeclaredCommands(nil)
	if err != nil {
		t.Fatalf("ParseDeclaredCommands(nil) error = %v, want nil", err)
	}
	if len(notices) != 0 || len(entries) != 0 {
		t.Fatalf("entries=%v notices=%v, want both empty", entries, notices)
	}
}

func TestParseDeclaredCommands_RejectionTable(t *testing.T) {
	cases := []struct {
		name  string
		entry string
	}{
		{"bare hg", "hg"},
		{"bare git", "git"},
		{"bare rm", "rm"},
		{"bare rmdir", "rmdir"},
		{"absolute path spelling of a destructive program", "/tmp/probe/bin/hg"},
		{"relative path spelling of a destructive program", "./rm"},
		{"program wildcard spelling", "make :*"},
		{"empty entry", ""},
		{"whitespace-only entry", "   "},
		{"does not tokenize: unterminated quote", "sed 'unterminated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, notices, err := ParseDeclaredCommands([]any{tc.entry})
			if err != nil {
				t.Fatalf("ParseDeclaredCommands(%q) error = %v, want nil (rejection is a notice, not an error)", tc.entry, err)
			}
			if len(entries) != 0 {
				t.Fatalf("entries = %v, want none for a rejected entry", entries)
			}
			if len(notices) != 1 {
				t.Fatalf("notices = %v, want exactly one", notices)
			}
		})
	}
}

func TestParseDeclaredCommands_BareNonDestructiveProgramAccepted(t *testing.T) {
	// Risk-regression case: the destructive classifier is advisory and incomplete, so a
	// bare program absent from it is still accepted — this is not a safety verdict.
	entries, notices, err := ParseDeclaredCommands([]any{"bash"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v, want nil", err)
	}
	if len(notices) != 0 {
		t.Fatalf("notices = %v, want none", notices)
	}
	if len(entries) != 1 || entries[0].Subject != "bash :*" {
		t.Fatalf("entries = %v, want one entry with subject %q", entries, "bash :*")
	}
}

func TestParseDeclaredCommands_BarePathSpelledProgramAccepted(t *testing.T) {
	// Only the base name is classified, so a path-spelled project script the classifier does not
	// flag stays accepted — that spelling is the declared list's main use.
	entries, notices, err := ParseDeclaredCommands([]any{"scripts/work.sh"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v, want nil", err)
	}
	if len(notices) != 0 {
		t.Fatalf("notices = %v, want none", notices)
	}
	if len(entries) != 1 || entries[0].Subject != "scripts/work.sh :*" {
		t.Fatalf("entries = %v, want one entry with subject %q", entries, "scripts/work.sh :*")
	}
}

func TestParseDeclaredCommands_DestructiveProgramWithFlagsAccepted(t *testing.T) {
	// The restriction is on the bare (flagless) form only: pinned flags are the user's judgment
	// call the ADR defers to.
	entries, notices, err := ParseDeclaredCommands([]any{"rm -rf ./build"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v, want nil", err)
	}
	if len(notices) != 0 {
		t.Fatalf("notices = %v, want none", notices)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want exactly one accepted entry", entries)
	}
}

func TestParseDeclaredCommands_OneInvalidEntryDoesNotBlockOthers(t *testing.T) {
	entries, notices, err := ParseDeclaredCommands([]any{"rm", "ls", "hg"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v, want nil", err)
	}
	if len(entries) != 1 || entries[0].Subject != "ls :*" {
		t.Fatalf("entries = %v, want only the accepted ls entry", entries)
	}
	if len(notices) != 2 {
		t.Fatalf("notices = %v, want exactly two (rm, hg)", notices)
	}
}

func TestParseDeclaredCommands_MalformedShape(t *testing.T) {
	if _, _, err := ParseDeclaredCommands("not-a-list"); err == nil {
		t.Fatalf("ParseDeclaredCommands(non-list) error = nil, want an error")
	}
	if _, _, err := ParseDeclaredCommands([]any{42}); err == nil {
		t.Fatalf("ParseDeclaredCommands(non-string entry) error = nil, want an error")
	}
}

func TestMatchesDeclaredCommand_PrefixCoversChangingArgument(t *testing.T) {
	entries, _, err := ParseDeclaredCommands([]any{"prep-open-tasks.sh --only"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v", err)
	}

	if !MatchesDeclaredCommand([]string{"prep-open-tasks.sh", "--only", "i425"}, nil, false, entries) {
		t.Fatalf("expected a match for --only i425")
	}
	if !MatchesDeclaredCommand([]string{"prep-open-tasks.sh", "--only", "i425", "--force"}, nil, false, entries) {
		t.Fatalf("expected a match for --only i425 --force")
	}
	if MatchesDeclaredCommand([]string{"prep-open-tasks.sh"}, nil, false, entries) {
		t.Fatalf("expected no match: the invocation is shorter than the declared prefix")
	}
}

func TestMatchesDeclaredCommand_FlagNotCoveredByDifferentFlag(t *testing.T) {
	entries, _, err := ParseDeclaredCommands([]any{"sed -n"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v", err)
	}

	if !MatchesDeclaredCommand([]string{"sed", "-n", "1p", "file"}, nil, false, entries) {
		t.Fatalf("expected sed -n to match")
	}
	if MatchesDeclaredCommand([]string{"sed", "-i", "s/a/b/", "file"}, nil, false, entries) {
		t.Fatalf("expected sed -i to NOT match a declared sed -n entry")
	}
}

func TestMatchesDeclaredCommand_TokenBoundaryNearMiss(t *testing.T) {
	entries, _, err := ParseDeclaredCommands([]any{"prep-open-tasks.sh --only"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v", err)
	}

	if MatchesDeclaredCommand([]string{"prep-open-tasks.shx", "--only", "i425"}, nil, false, entries) {
		t.Fatalf("expected no match: program name differs at the token boundary")
	}
}

func TestMatchesDeclaredCommand_AssignmentPrefixedRequestDoesNotMatch(t *testing.T) {
	entries, _, err := ParseDeclaredCommands([]any{"scripts/work.sh"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v", err)
	}

	norm, err := NormalizeDirectStage("TERM=xterm scripts/work.sh", StageSolo)
	if err != nil {
		t.Fatalf("NormalizeDirectStage() error = %v", err)
	}
	if norm.Route != RouteDirect {
		t.Fatalf("Route = %v, want RouteDirect", norm.Route)
	}
	if len(norm.Assignments) != 1 || norm.Assignments[0] != "TERM=xterm" {
		t.Fatalf("Assignments = %v, want the stripped TERM assignment carried through", norm.Assignments)
	}
	if MatchesDeclaredCommand(norm.Tokens, norm.Assignments, norm.ClearEnvironment, entries) {
		t.Fatalf("expected no match: a declaration spells no environment, so it covers only the environment-inheriting invocation")
	}
	if !MatchesDeclaredCommand(norm.Tokens, nil, false, entries) {
		t.Fatalf("expected the same tokens with no assignment to match the declaration")
	}
}

// The dispatcher applies a cleared environment's own PATH to the child and resolves the program
// name against it, so a declaration matched on tokens alone would authorize a different executable.
func TestMatchesDeclaredCommand_ClearedEnvironmentRequestDoesNotMatch(t *testing.T) {
	entries, _, err := ParseDeclaredCommands([]any{"hg status"})
	if err != nil {
		t.Fatalf("ParseDeclaredCommands() error = %v", err)
	}

	norm, err := NormalizeDirectStage("env -i PATH=/tmp/probe/bin hg status", StageSolo)
	if err != nil {
		t.Fatalf("NormalizeDirectStage() error = %v", err)
	}
	if norm.Route != RouteDirect || !norm.ClearEnvironment {
		t.Fatalf("Route = %v, ClearEnvironment = %v, want a direct env -i stage", norm.Route, norm.ClearEnvironment)
	}
	if len(norm.Tokens) != 2 || norm.Tokens[0] != "hg" || norm.Tokens[1] != "status" {
		t.Fatalf("Tokens = %v, want the inner hg status command", norm.Tokens)
	}
	if MatchesDeclaredCommand(norm.Tokens, norm.Assignments, norm.ClearEnvironment, entries) {
		t.Fatalf("expected no match: a declared prefix must not authorize the same tokens under a stripped, PATH-shadowing environment")
	}
}

func TestMatchesDeclaredCommand_NoEntriesNeverMatches(t *testing.T) {
	if MatchesDeclaredCommand([]string{"ls"}, nil, false, nil) {
		t.Fatalf("expected no match with an empty declared list")
	}
}

func TestMatchesDeclaredCommand_PinnedHomeFormRefusesBothSpellings(t *testing.T) {
	tests := []struct {
		declaration string
		stages      []string
	}{
		{"cat ~/x", []string{`cat ~/x`, `cat '~/x'`, `cat ~/x -n`, `cat \~/x -n`}},
		{"cat '~/x'", []string{`cat ~/x`, `cat '~/x'`}},
		{"ls $HOME", []string{`ls $HOME`, `ls "$HOME"`, `ls $HOME -l`}},
		{"ls -l ~", []string{`ls -l ~`, `ls -l '~'`}},
		{"cp $HOME/a", []string{`cp $HOME/a b`, `cp '$HOME/a' b`}},
	}
	for _, tt := range tests {
		t.Run(tt.declaration, func(t *testing.T) {
			entries, _, err := ParseDeclaredCommands([]any{tt.declaration})
			if err != nil || len(entries) != 1 {
				t.Fatalf("ParseDeclaredCommands(%q) = %v, %v; want one entry", tt.declaration, entries, err)
			}
			for _, stage := range tt.stages {
				norm, err := NormalizeDirectStage(stage, StageSolo)
				if err != nil || norm.Route != RouteDirect {
					t.Fatalf("NormalizeDirectStage(%q) = route %v, error %v; want a direct stage", stage, norm.Route, err)
				}
				if MatchesDeclaredCommand(norm.Tokens, norm.Assignments, norm.ClearEnvironment, entries) {
					t.Fatalf("declaration %q authorized %q, want a pinned home form refused", tt.declaration, stage)
				}
			}
		})
	}
}

func TestMatchesDeclaredCommand_UnpinnedHomeFormsKeepMatching(t *testing.T) {
	tests := []struct {
		declaration string
		stages      []string
	}{
		{"cat -n", []string{`cat -n ~/x`, `cat -n '~/x'`, `cat -n $HOME`, `cat -n "$HOME"/x`, `cat -n ~`}},
		{"cat ~alice/x", []string{`cat ~alice/x`, `cat '~alice/x' -n`}},
		{"echo $HOMEDIR", []string{`echo '$HOMEDIR'`, `echo '$HOMEDIR' ~`}},
	}
	for _, tt := range tests {
		t.Run(tt.declaration, func(t *testing.T) {
			entries, _, err := ParseDeclaredCommands([]any{tt.declaration})
			if err != nil || len(entries) != 1 {
				t.Fatalf("ParseDeclaredCommands(%q) = %v, %v; want one entry", tt.declaration, entries, err)
			}
			for _, stage := range tt.stages {
				norm, err := NormalizeDirectStage(stage, StageSolo)
				if err != nil || norm.Route != RouteDirect {
					t.Fatalf("NormalizeDirectStage(%q) = route %v, error %v; want a direct stage", stage, norm.Route, err)
				}
				if !MatchesDeclaredCommand(norm.Tokens, norm.Assignments, norm.ClearEnvironment, entries) {
					t.Fatalf("declaration %q stopped authorizing %q", tt.declaration, stage)
				}
			}
		})
	}
}
