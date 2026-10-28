package permissions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type systemOneFixture struct {
	home, root, bin, links, rootBin string
	blocked                         *BlockedPaths
}

func newSystemOneFixture(t *testing.T) systemOneFixture {
	t.Helper()
	f := systemOneFixture{home: t.TempDir(), root: t.TempDir(), bin: t.TempDir(), links: t.TempDir()}
	f.rootBin = filepath.Join(f.root, "bin")
	if err := os.Mkdir(f.rootBin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := func(path string) {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"grep", "ls", "head", "hg", "awk", "git", "cat", "echo", "diff", "tee", "test", "sh", "bash"} {
		exe(filepath.Join(f.bin, name))
	}
	for _, name := range []string{"inproj", "grep"} {
		exe(filepath.Join(f.rootBin, name))
	}
	if err := os.Symlink(filepath.Join(f.rootBin, "inproj"), filepath.Join(f.links, "linked")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", strings.Join([]string{f.bin, f.links, f.rootBin}, string(os.PathListSeparator)))
	f.blocked = NewBlockedPaths(f.home, []BlockedEntry{{Path: filepath.Join(f.home, "secret"), Source: "s"}})
	return f
}

func (f systemOneFixture) request(t *testing.T, command string) MatchRequest {
	t.Helper()
	split, err := SplitCommand(command)
	if err == nil && split.AllowedShell && !split.LiteralRoute && len(split.Stages) == 1 {
		return MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(split.Stages[0].Tokens, " "), SubjectTokens: split.Stages[0].Tokens, PathScope: f.root}
	}
	return MatchRequest{Kind: subjectKindLiteral, Subject: command, PathScope: f.root}
}

func (f systemOneFixture) mode() ModeContext {
	return ModeContext{Mode: modeAutoEdits, ProjectRoot: f.root}
}

func TestSystemOneEligible_RefusesAdversarialCommands(t *testing.T) {
	f := newSystemOneFixture(t)
	r := func(s string) string { return strings.NewReplacer("<home>", f.home, "<root>", f.root, "<bin>", f.bin).Replace(s) }
	tests := []struct {
		name    string
		command string
		edit    func(*MatchRequest, *ModeContext)
	}{
		{"plain substitution", "echo $(id)", nil},
		{"single-quoted substitution", "echo '$(id)'", nil},
		{"double-quoted substitution", `echo "$(id)"`, nil},
		{"ANSI-C quoted substitution", `echo $'$(id)'`, nil},
		{"ANSI-C escaped dollar", `echo $'\x24(id)'`, nil},
		{"escaped substitution", `echo \$\(id\)`, nil},
		{"backticks", "echo `id`", nil},
		{"input process substitution", "diff <(ls) <(ls)", nil},
		{"output process substitution", "ls | tee >(cat)", nil},
		{"test -v subscript", `bash -c 'declare -a x; test -v '"'"'x[$(printf INJECTED >&2)]'"'"''`, nil},
		{"arithmetic subscript", "echo $(( a[$(id)] ))", nil},
		{"write redirect", "ls > out", nil},
		{"append redirect", "ls >> out", nil},
		{"stderr file redirect", "ls 2> err", nil},
		{"both streams redirect", "ls &> out", nil},
		{"clobber redirect", "ls >| out", nil},
		{"input redirect", "cat < f", nil},
		{"heredoc", "cat << EOF", nil},
		{"here-string", "cat <<< x", nil},
		{"here-string in a compound", "ls; jq . <<< 'a'", nil},
		{"shell reading a script", "bash < x.sh", nil},
		{"unsupported descriptor", "ls 3>/dev/null", nil},
		{"unsupported duplication", "ls 2>&3", nil},
		{"dot-slash program", "./x.sh", nil},
		{"relative path program", "bin/tool", nil},
		{"absolute path program", "/abs/tool", nil},
		{"absolute path normalized to bare name", "<bin>/grep x f", nil},
		{"path program after ;", "ls; ./x.sh", nil},
		{"path program after &&", "ls && ./x.sh", nil},
		{"path program after ||", "ls || ./x.sh", nil},
		{"path program after |", "ls | ./x.sh", nil},
		{"project program after ;", "ls; inproj", nil},
		{"project program after &&", "ls && inproj", nil},
		{"project program after ||", "ls || inproj", nil},
		{"project program after |", "ls | inproj", nil},
		{"bare name inside project", "inproj", nil},
		{"symlink into project from an outside PATH entry", "linked", nil},
		{"request-assigned PATH", "PATH=<root>/bin grep x f", nil},
		{"env-assigned PATH", "env PATH=<root>/bin grep x f", nil},
		{"env with an absolute program", "env /abs/tool", nil},
		{"assignment before a path program", "FOO=1 ./x.sh", nil},
		{"empty project root", "ls", func(_ *MatchRequest, mc *ModeContext) { mc.ProjectRoot = "" }},
		{"unresolvable program", "nosuchprogram x", nil},
		{"global settings", "cat ~/.codemeld/global/settings.yaml", nil},
		{"blocked path in ~ form", "cat ~/secret/a", nil},
		{"blocked path expanded", "cat <home>/secret/a", nil},
		{"blocked path as option value", "grep --file=~/secret/a x f", nil},
		{"blocked path as expanded option value", "grep --file=<home>/secret/a x f", nil},
		{"blocked path in a quoted inner command", "grep -e 'cat <home>/secret/a' f", nil},
		{"recursive read of home", "grep -r x ~", nil},
		{"path-uncertain absolute glob", "ls /etc/*", shellPathAsk},
		{"path-uncertain home glob", "ls ~/*", shellPathAsk},
		{"path-uncertain other user", "ls ~user/*", shellPathAsk},
		{"path-uncertain $HOME", "ls $HOME/*", shellPathAsk},
		{"path-uncertain ${HOME}", "ls ${HOME}/*", shellPathAsk},
		{"path-uncertain ${HOME:-}", "ls ${HOME:-/elsewhere}/*", shellPathAsk},
		{"path-uncertain parent", "ls ../*", shellPathAsk},
		{"build mode", "ls", func(_ *MatchRequest, mc *ModeContext) { mc.Mode = "build" }},
		{"unknown mode", "ls", func(_ *MatchRequest, mc *ModeContext) { mc.Mode = "" }},
		{"network egress", "ls", func(_ *MatchRequest, mc *ModeContext) { mc.NetworkEgress = true }},
		{"external read", "ls", func(_ *MatchRequest, mc *ModeContext) { mc.ExternalRead = true }},
		{"tool subject", "ls", func(req *MatchRequest, _ *ModeContext) { req.Kind = subjectKindTool }},
		{"empty source", "", nil},
		{"blank source", "  ", nil},
		{"newline then project program", "ls\ninproj", nil},
		{"newline then path program", "ls\n./x.sh", nil},
		{"carriage return then project program", "ls\rinproj", nil},
		{"newline before a null redirect then project program", "ls\n2>/dev/null inproj", nil},
		{"newline before a null redirect then path program", "ls\n2>/dev/null ./x.sh", nil},
		{"newline before a stdout null redirect then project program", "ls\n>/dev/null inproj", nil},
		{"carriage return before a null redirect then project program", "ls\r2>/dev/null inproj", nil},
		{"newline before a descriptor duplication then project program", "ls\n2>&1 inproj", nil},
		{"newline before a descriptor duplication then path program", "ls\n2>&1 ./x.sh", nil},
		{"background", "ls & ls", nil},
		{"subshell", "(ls)", nil},
		{"group", "{ ls; }", nil},
		{"if", "if ls; then ls; fi", nil},
		{"for", "for i in a; do ls; done", nil},
		{"unterminated quote", "ls 'a", nil},
		{"continuation splitting a blocked path", "cat <home>/sec\\\nret/a >/dev/null", nil},
		{"double-quoted continuation splitting a blocked path", "cat \"<home>/sec\\\nret/a\" >/dev/null", nil},
		{"continuation splitting the global settings spelling", "cat ~/.codemeld/glo\\\nbal/settings.yaml >/dev/null", nil},
		{"double-quoted continuation splitting the global settings spelling", "cat ~/\".codemeld/glo\\\nbal/settings.yaml\" >/dev/null", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := r(tt.command)
			req, mc := f.request(t, command), f.mode()
			if tt.edit != nil {
				tt.edit(&req, &mc)
			}
			if SystemOneEligible(req, mc, f.blocked, command) == "" {
				t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
			}
		})
	}

	t.Run("nil blocked paths", func(t *testing.T) {
		if SystemOneEligible(f.request(t, "ls"), f.mode(), nil, "ls") == "" {
			t.Error("eligible with a nil *BlockedPaths")
		}
	})
	t.Run("snapshot with an empty home", func(t *testing.T) {
		if SystemOneEligible(f.request(t, "ls"), f.mode(), NewBlockedPaths("", nil), "ls") == "" {
			t.Error("eligible with an empty home")
		}
	})
}

func shellPathAsk(_ *MatchRequest, mc *ModeContext) { mc.ShellPathAsk = true }

func TestSystemOneEligible_DirectRouteChecksSourceText(t *testing.T) {
	f := newSystemOneFixture(t)
	for _, command := range []string{"echo '$(id)'", `echo \$\(id\)`, "<bin>/grep x f"} {
		command = strings.ReplaceAll(command, "<bin>", f.bin)
		split, err := SplitCommand(command)
		if err != nil || split.LiteralRoute || len(split.Stages) != 1 {
			t.Fatalf("SplitCommand(%q) = %+v, %v; want one direct stage", command, split, err)
		}
		stage := split.Stages[0]
		if stage.Source == strings.Join(stage.Tokens, " ") {
			t.Fatalf("%q: source and canonical text are the same: %q", command, stage.Source)
		}
		req := MatchRequest{Kind: subjectKindDirect, SubjectTokens: stage.Tokens, PathScope: f.root}
		if SystemOneEligible(req, f.mode(), f.blocked, stage.Source) == "" {
			t.Errorf("%q: eligible on the direct route", command)
		}
	}
}

func TestSystemOneEligible_QuotedGlobCharactersBesideActiveGlob(t *testing.T) {
	f := newSystemOneFixture(t)
	dir := filepath.Join(f.root, "[x]")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := NewBlockedPaths(f.home, []BlockedEntry{{Path: secret, Source: "s"}})
	for _, command := range []string{
		"cat '[x]'/* 2>/dev/null",
		`cat "[x]"/* 2>/dev/null`,
		`cat \[x]/* 2>/dev/null`,
		`cat \[x\]/* 2>/dev/null`,
		`cat '[x]'/*`,
	} {
		if SystemOneEligible(f.request(t, command), f.mode(), blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
	command := "ls logs/2026*/ 2>/dev/null | head -80"
	req, mc := f.request(t, command), f.mode()
	shellPathAsk(&req, &mc)
	if SystemOneEligible(req, mc, blocked, command) != "" {
		t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
	}
}

func TestSystemOneEligible_SkipsPathCandidateTheUserCannotExecute(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may execute a file with any execute bit set")
	}
	f := newSystemOneFixture(t)
	early := t.TempDir()
	probe := filepath.Join(early, "probe")
	if err := os.WriteFile(probe, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(probe, 0o611); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.rootBin, "probe"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := early + string(os.PathListSeparator) + f.rootBin
	t.Run("inherited PATH", func(t *testing.T) {
		t.Setenv("PATH", path)
		if SystemOneEligible(f.request(t, "probe --version"), f.mode(), f.blocked, "probe --version") == "" {
			t.Error("eligible although execution resolves the project-local probe")
		}
	})
	t.Run("requested PATH", func(t *testing.T) {
		command := "PATH=" + path + " probe --version"
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	})
	t.Run("external program after the inaccessible candidate", func(t *testing.T) {
		command := "PATH=" + early + string(os.PathListSeparator) + f.bin + " grep x f"
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) != "" {
			t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
		}
	})
}

func TestSystemOneEligible_RefusesExpandingProgramWord(t *testing.T) {
	f := newSystemOneFixture(t)
	external := t.TempDir()
	for _, path := range []string{filepath.Join(external, "probe*"), filepath.Join(f.rootBin, "probe-local")} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", strings.Join([]string{external, f.bin, f.rootBin}, string(os.PathListSeparator)))
	for _, command := range []string{
		"probe* 2>/dev/null",
		"probe*",
		"FOO=1 probe* x",
		"env probe* x",
		"env -i PATH=" + external + " probe* x",
		"grep x f | probe*",
		"grep x f && probe* x",
	} {
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
	for _, command := range []string{"'probe*' x", `probe\* x`} {
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) != "" {
			t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
		}
	}
}

func TestSystemOneEligible_RefusesParentTraversal(t *testing.T) {
	f := newSystemOneFixture(t)
	external := t.TempDir()
	for _, dir := range []string{"public", "secret"} {
		if err := os.Mkdir(filepath.Join(external, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(external, "secret", "a"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(external, "public"), filepath.Join(f.root, "hop")); err != nil {
		t.Fatal(err)
	}
	blocked := NewBlockedPaths(f.home, []BlockedEntry{{Path: filepath.Join(external, "secret"), Source: "s"}})

	command := "cat hop/../secret/a >/dev/null"
	req := MatchRequest{Kind: subjectKindLiteral, Subject: command, PathScope: f.root}
	if SystemOneEligible(req, f.mode(), blocked, command) == "" {
		t.Errorf("literal route: SystemOneEligible(%q) = \"\", want a reason", command)
	}
	for _, command := range []string{
		"cat hop/../secret/a",
		"grep x -f../secret/a f",
		"grep -fhop/../secret/a x f",
		"grep --file=hop/../secret/a x f",
		"cat ~/../secret/a",
		"cat hop/.*/secret/a 2>/dev/null",
		"cat hop/.?/secret/a",
		"cat hop/.[.]/secret/a",
		"ls hop/..",
	} {
		if SystemOneEligible(f.request(t, command), f.mode(), blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
	if command := "grep a..b f"; SystemOneEligible(f.request(t, command), f.mode(), blocked, command) != "" {
		t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
	}
}

func TestSystemOneEligible_RefusesBracketGlobs(t *testing.T) {
	f := newSystemOneFixture(t)
	data := filepath.Join(f.root, "data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(data, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := NewBlockedPaths(f.home, []BlockedEntry{{Path: secret, Source: "s"}})

	command := "cat data/[!x]* 2>/dev/null"
	req := MatchRequest{Kind: subjectKindLiteral, Subject: command, PathScope: f.root}
	if SystemOneEligible(req, f.mode(), blocked, command) == "" {
		t.Errorf("literal route: SystemOneEligible(%q) = \"\", want a reason", command)
	}
	for _, command := range []string{
		"cat data/[!x]*",
		"grep --file=data/[!x]* x f",
		"grep -fdata/[!x]* x f",
		"cat data/[[:alnum:]]*",
	} {
		if SystemOneEligible(f.request(t, command), f.mode(), blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
	command = "ls logs/2026*/ 2>/dev/null | head -80"
	req, mc := f.request(t, command), f.mode()
	shellPathAsk(&req, &mc)
	if SystemOneEligible(req, mc, blocked, command) != "" {
		t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
	}
}

func TestSystemOneEligible_ChecksAttachedOptionValues(t *testing.T) {
	f := newSystemOneFixture(t)
	data := filepath.Join(f.root, "data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(data, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(f.root, "alias")); err != nil {
		t.Fatal(err)
	}
	blocked := NewBlockedPaths(f.home, []BlockedEntry{{Path: secret, Source: "s"}})

	command := "grep -fdata/secret x f 2>/dev/null"
	req := MatchRequest{Kind: subjectKindLiteral, Subject: command, PathScope: f.root}
	if SystemOneEligible(req, f.mode(), blocked, command) == "" {
		t.Errorf("literal route: SystemOneEligible(%q) = \"\", want a reason", command)
	}
	for _, command := range []string{
		"grep -fdata/secret x f",
		"grep -rfdata/secret x f",
		"grep -fdata/s* x f",
		"grep -falias x f",
	} {
		if SystemOneEligible(f.request(t, command), f.mode(), blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
	for _, command := range []string{"grep -rn foo internal/", "hg log -l 3 2>&1"} {
		if SystemOneEligible(f.request(t, command), f.mode(), blocked, command) != "" {
			t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
		}
	}
}

func TestSystemOneEligible_AllowsReadOnlyShapes(t *testing.T) {
	f := newSystemOneFixture(t)
	tests := []struct {
		command string
		edit    func(*MatchRequest, *ModeContext)
	}{
		{"grep -rn foo internal/", nil},
		{"ls logs/2026*/ 2>/dev/null | head -80", shellPathAsk},
		{"hg log -l 3 2>&1", nil},
		{"awk '{print $1}' f", nil},
		{"git check-ignore -v x", nil},
		{"grep 'a\nb' f 2>/dev/null", nil},
		{"grep -rn foo internal/", func(_ *MatchRequest, mc *ModeContext) { mc.Mode = modePlan }},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			req, mc := f.request(t, tt.command), f.mode()
			if tt.edit != nil {
				tt.edit(&req, &mc)
			}
			if SystemOneEligible(req, mc, f.blocked, tt.command) != "" {
				t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", tt.command)
			}
		})
	}
}

func TestSystemOneEligible_AllowsLookups(t *testing.T) {
	f := newSystemOneFixture(t)
	for _, mode := range []string{"auto_edits", "plan"} {
		for _, command := range []string{
			"command -v jq",
			"type jq",
			"command -v git",
			"type git",
			"command -v python3 git diff patch",
			"type jq bats shellcheck",
			"type jq bats 2>&1 | head -5",
			"command -v inproj",
			"type inproj",
		} {
			mc := f.mode()
			mc.Mode = mode
			if SystemOneEligible(f.request(t, command), mc, f.blocked, command) != "" {
				t.Errorf("%s: SystemOneEligible(%q) = a reason, want \"\"", mode, command)
			}
		}
	}
}

func TestSystemOneEligible_LookupRoutes(t *testing.T) {
	f := newSystemOneFixture(t)
	for _, command := range []string{"command -v git", "type git"} {
		split, err := SplitCommand(command)
		if err != nil || split.LiteralRoute || len(split.Stages) != 1 {
			t.Fatalf("SplitCommand(%q) = %+v, %v; want one direct stage", command, split, err)
		}
		if st := split.Stages[0]; st.Route != RouteDirect || len(st.Tokens) == 0 || st.LookupPath == "" {
			t.Errorf("SplitCommand(%q) stage = %+v; want direct with tokens and a lookup path", command, st)
		}
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) != "" {
			t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
		}
	}
	for _, command := range []string{"command -v jq", "type jq", "command -v git diff", "type git diff"} {
		split, err := SplitCommand(command)
		if err != nil || !split.LiteralRoute {
			t.Fatalf("SplitCommand(%q) = %+v, %v; want the literal route", command, split, err)
		}
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) != "" {
			t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
		}
	}
}

func TestSystemOneEligible_RefusesNonLookupShapes(t *testing.T) {
	f := newSystemOneFixture(t)
	for _, command := range []string{
		"command jq",
		"command -p jq",
		"command -V jq",
		"command -V git",
		"command -v",
		"type",
		"type -p jq",
		"type -a jq",
		"command -v -- jq",
		"command -v jq -x",
		`"command" -v jq`,
		`\type jq`,
		"command -v 'jq'",
		`command "-v" jq`,
		"PATH=/x command -v jq",
		"env command -v jq",
		"command -v ./jq",
		"command -v /usr/bin/jq",
		"command -v ../jq",
		"type 'jq;id'",
		`type "$(id)"`,
		"type $X",
		"type j*",
		"type ~/.ssh/id",
	} {
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
	for _, command := range []string{"command -v jq", "type jq", "command -v git", "type git", "command -v python3 git diff patch", "type jq bats shellcheck", "command -v inproj"} {
		mc := f.mode()
		mc.Mode = "build"
		if SystemOneEligible(f.request(t, command), mc, f.blocked, command) == "" {
			t.Errorf("build mode: SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
}

func TestSystemOneEligible_LookupInCompound(t *testing.T) {
	f := newSystemOneFixture(t)
	if command := "command -v jq; hg status"; SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) != "" {
		t.Errorf("SystemOneEligible(%q) = a reason, want \"\"", command)
	}
	for _, command := range []string{"command -v jq; inproj", "type jq && ./x.sh", "type jq | nosuchprogram"} {
		if SystemOneEligible(f.request(t, command), f.mode(), f.blocked, command) == "" {
			t.Errorf("SystemOneEligible(%q) = \"\", want a reason", command)
		}
	}
}

func TestSystemOneEligible_LookupGrammarWiderThanRouting(t *testing.T) {
	f := newSystemOneFixture(t)
	tests := []struct {
		command           string
		routing, eligible bool
		route             StageRoute
	}{
		{"command -v git", true, true, RouteDirect},
		{"type git", true, true, RouteDirect},
		{"command -v git diff", false, true, RouteLiteral},
		{"type git diff", false, true, RouteLiteral},
		{"command -p git", false, false, RouteLiteral},
		{"command -V git", false, false, RouteLiteral},
		{"type -p git", false, false, RouteLiteral},
		{"type -a git", false, false, RouteLiteral},
	}
	for _, tt := range tests {
		fields := strings.Fields(tt.command)
		if got := commandLookupTokens(fields) || typeLookupTokens(fields); got != tt.routing {
			t.Errorf("routing grammar accepts %q = %v, want %v", tt.command, got, tt.routing)
		}
		if got := SystemOneEligible(f.request(t, tt.command), f.mode(), f.blocked, tt.command); (got == "") != tt.eligible {
			t.Errorf("SystemOneEligible(%q) = %q, want eligible %v", tt.command, got, tt.eligible)
		}
		norm, err := NormalizeDirectStage(tt.command, StageSolo)
		if err != nil || norm.Route != tt.route {
			t.Errorf("NormalizeDirectStage(%q) route = %v, %v; want %v", tt.command, norm.Route, err, tt.route)
		}
	}
}

func TestSystemOneEligible_ReasonPerCategory(t *testing.T) {
	f := newSystemOneFixture(t)
	r := strings.NewReplacer("<home>", f.home, "<root>", f.root, "<bin>", f.bin).Replace
	literal := func(req *MatchRequest, _ *ModeContext) { req.Kind, req.SubjectTokens = subjectKindLiteral, nil }
	tests := []struct {
		name, command, want string
		edit                func(*MatchRequest, *ModeContext)
	}{
		{"empty text", "", "text", nil},
		{"blank text", "  ", "text", nil},
		{"line continuation", "ls \\\nx", "text", nil},
		{"bare newline", "ls\nls", "text", nil},
		{"bare carriage return", "ls\rls", "text", nil},
		{"empty path scope", "ls", "text", func(req *MatchRequest, _ *ModeContext) { req.PathScope = "" }},
		{"empty project root", "ls", "text", func(_ *MatchRequest, mc *ModeContext) { mc.ProjectRoot = "" }},
		{"build mode", "ls", "text", func(_ *MatchRequest, mc *ModeContext) { mc.Mode = "build" }},
		{"network egress", "ls", "text", func(_ *MatchRequest, mc *ModeContext) { mc.NetworkEgress = true }},
		{"tool subject", "ls", "text", func(req *MatchRequest, _ *ModeContext) { req.Kind = subjectKindTool }},
		{"command substitution", "echo $(id)", "substitution", nil},
		{"backticks", "echo `id`", "substitution", nil},
		{"process substitution", "diff <(ls) <(ls)", "substitution", nil},
		{"dollar outside single quotes", "grep $X f", "substitution", nil},
		{"blocked path in the text", "cat ~/secret/a", "blocked_path", nil},
		{"global settings in the text", "cat ~/.codemeld/global/settings.yaml", "blocked_path", nil},
		{"blocked path scope", "ls", "blocked_path", func(req *MatchRequest, _ *ModeContext) { req.PathScope = filepath.Join(f.home, "secret") }},
		{"resolved home holds a blocked path", "grep -r x ~", "blocked_path", nil},
		{"wrapper program", "bash --version | head -1", "wrapper", nil},
		{"shell -c wrapper", "bash -c 'ls'", "wrapper", nil},
		{"reserved word", "in x", "wrapper", nil},
		{"unresolvable program", "nosuchprogram x", "program_location", nil},
		{"program inside the project", "inproj", "program_location", nil},
		{"symlink into the project", "linked", "program_location", nil},
		{"path program", "./x.sh", "program_location", nil},
		{"path program on the literal route", "./x.sh", "program_location", literal},
		{"absolute program normalized to a bare name", "<bin>/grep x f", "program_location", nil},
		{"glob program word", "gre* x f", "program_location", nil},
		{"request-assigned PATH into the project", "PATH=<root>/bin grep x f", "program_location", nil},
		{"write redirect", "ls > out", "shell_shape", nil},
		{"unterminated quote", "ls 'a", "shell_shape", nil},
		{"background", "ls & ls", "shell_shape", nil},
		{"brace", "echo {a,b}", "shell_shape", nil},
		{"path-uncertain spelling", "ls /etc/*", "shell_shape", shellPathAsk},
		{"assignment without a program", "FOO=1", "shell_shape", nil},
		{"empty direct subject tokens", "ls", "shell_shape", func(req *MatchRequest, _ *ModeContext) { req.Kind, req.SubjectTokens = subjectKindDirect, nil }},
		{"parent traversal", "cat a/../b", "shell_shape", nil},
		{"bracket glob", "cat data/[!x]*", "shell_shape", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := r(tt.command)
			req, mc := f.request(t, command), f.mode()
			if tt.edit != nil {
				tt.edit(&req, &mc)
			}
			if got := SystemOneEligible(req, mc, f.blocked, command); got != tt.want {
				t.Errorf("SystemOneEligible(%q) = %q, want %q", command, got, tt.want)
			}
		})
	}

	degraded := NewLiveBlockedPaths(f.home, f.root, nil, func() BlockedReload {
		return BlockedReload{Problems: map[string]string{"/g/settings.yaml": "is missing"}}
	})
	for name, blocked := range map[string]*BlockedPaths{"nil": nil, "empty home": NewBlockedPaths("", nil), "degraded": degraded} {
		if got := SystemOneEligible(f.request(t, "ls"), f.mode(), blocked, "ls"); got != "blocked_paths_unavailable" {
			t.Errorf("%s blocked paths: SystemOneEligible(ls) = %q, want blocked_paths_unavailable", name, got)
		}
	}
}

func TestSystemOneEligible_FirstFailingCheckSuppliesTheReason(t *testing.T) {
	f := newSystemOneFixture(t)
	r := strings.NewReplacer("<home>", f.home).Replace
	tests := []struct {
		name, command, want string
		blocked             *BlockedPaths
	}{
		{"continuation before substitution", "echo $(id) \\\nx", "text", f.blocked},
		{"missing snapshot before substitution", "echo $(id)", "blocked_paths_unavailable", nil},
		{"substitution before a blocked mention", "cat ~/secret/$(id)", "substitution", f.blocked},
		{"substitution before a bare newline", "echo $(id)\nls", "substitution", f.blocked},
		{"blocked mention before a path program", "./x.sh ~/secret", "blocked_path", f.blocked},
		{"blocked mention before a bare newline", "cat ~/secret\nls", "blocked_path", f.blocked},
		{"first failing stage: program location", "nosuchprogram; bash -c x", "program_location", f.blocked},
		{"first failing stage: wrapper", "bash -c x; nosuchprogram", "wrapper", f.blocked},
		{"route before token checks", "bash -c $X", "wrapper", f.blocked},
		{"token checks before program location", "nosuchprogram $X", "substitution", f.blocked},
		{"token dollar before a token blocked mention", `cat "<home>"/secret$X`, "substitution", f.blocked},
		{"token blocked mention before a brace", `cat "<home>"/secret{a,b}`, "blocked_path", f.blocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := r(tt.command)
			req := MatchRequest{Kind: subjectKindLiteral, Subject: command, PathScope: f.root}
			if got := SystemOneEligible(req, f.mode(), tt.blocked, command); got != tt.want {
				t.Errorf("SystemOneEligible(%q) = %q, want %q", command, got, tt.want)
			}
		})
	}
}

func TestSystemOneEligible_TokenPathReasons(t *testing.T) {
	f := newSystemOneFixture(t)
	data := filepath.Join(f.root, "data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(data, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(f.root, "alias")); err != nil {
		t.Fatal(err)
	}
	blocked := NewBlockedPaths(f.home, []BlockedEntry{{Path: secret, Source: "s"}})
	for _, tt := range []struct{ command, want string }{
		{"cat alias", "blocked_path"},
		{"grep -falias x f", "blocked_path"},
		{"cat data/s*", "blocked_path"},
		{"grep --file=data/s?cret x f", "blocked_path"},
		{"ls data", "blocked_path"},
		{"cat data/../data/secret", "shell_shape"},
		{"ls data/..", "shell_shape"},
		{"cat data/[!x]*", "shell_shape"},
		{"cat '[x]'/*", "shell_shape"},
		{"cat data/.*", "shell_shape"},
		{"cat data/notsecret", ""},
	} {
		req := MatchRequest{Kind: subjectKindLiteral, Subject: tt.command, PathScope: f.root}
		if got := SystemOneEligible(req, f.mode(), blocked, tt.command); got != tt.want {
			t.Errorf("SystemOneEligible(%q) = %q, want %q", tt.command, got, tt.want)
		}
	}
}

func TestSystemOneEligible_StageReasons(t *testing.T) {
	f := newSystemOneFixture(t)
	snap := f.blocked.Current()
	mentions := blockedMentions(snap)
	for _, tt := range []struct{ stage, want string }{
		{"ls 'a", "shell_shape"},
		{"", "shell_shape"},
		{"   ", "shell_shape"},
		{"FOO=1", "shell_shape"},
		{"bash -c x", "wrapper"},
		{"command -V git", "wrapper"},
		{"type -a git", "wrapper"},
		{"command -v git diff", ""},
		{"type jq", ""},
	} {
		if got := systemOneStageEligible(tt.stage, StageSolo, f.root, f.mode(), snap, mentions); got != tt.want {
			t.Errorf("systemOneStageEligible(%q) = %q, want %q", tt.stage, got, tt.want)
		}
	}
	for _, command := range []string{"command -v", "type", "command jq", `"command" -v jq`, "command -v 'jq'", "PATH=/x command -v jq", "type j*"} {
		req := MatchRequest{Kind: subjectKindLiteral, Subject: command, PathScope: f.root}
		if got := SystemOneEligible(req, f.mode(), f.blocked, command); got != "wrapper" {
			t.Errorf("SystemOneEligible(%q) = %q, want wrapper", command, got)
		}
	}
}
