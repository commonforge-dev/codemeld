package permissions

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestShellPathCandidates(t *testing.T) {
	const folder, home = "/run", "/home/u"
	for _, tc := range []struct {
		name string
		argv []string
		want []string
	}{
		{"absolute operand", []string{"cat", "/home/u/.ssh/k"}, []string{"/home/u/.ssh/k"}},
		{"relative operands keep their dot-dot", []string{"cat", "notes", "sub/../k"}, []string{"/run/notes", "/run/sub/../k"}},
		{"flags skipped, lone dash and everything after -- kept", []string{"cat", "-n", "-", "--", "-k", "--x=/y"}, []string{"/run/-", "/run/-k", "/run/--x=/y"}},
		{"equals values", []string{"grep", "--x=/home/u/.ssh/k", "--y=~/.ssh/k", "--z=rel"}, []string{"/home/u/.ssh/k", "/run/~/.ssh/k", "/home/u/.ssh/k", "/run/rel"}},
		{"no candidate", []string{"grep", "--x=", "-/home/u/.ssh/k", "-n~/.ssh/k"}, nil},
		{"program only", []string{"ls"}, nil},
		{"empty argv", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShellPathCandidates(tc.argv, folder, home); !slices.Equal(got, tc.want) {
				t.Fatalf("ShellPathCandidates(%q) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
	if got, want := ShellPathCandidates([]string{"grep", "--y=~/.ssh/k"}, folder, ""), []string{"/run/~/.ssh/k"}; !slices.Equal(got, want) {
		t.Fatalf("without a home = %q, want %q", got, want)
	}
}

func TestShellPathCandidates_LetterCase(t *testing.T) {
	home := blockedTempDir(t)
	ssh := filepath.Join(home, ".ssh")
	mkdirs(t, ssh)
	entries := []BlockedEntry{{Path: ssh, Source: "s"}}
	candidates := ShellPathCandidates([]string{"cat", filepath.Join(home, ".SSH", "k")}, home, home)
	blocked := func(b *BlockedPaths) bool {
		return slices.ContainsFunc(candidates, func(c string) bool { _, ok := b.Blocking(c); return ok })
	}
	if !blocked(newBlockedPaths(home, entries, true)) {
		t.Fatal("~/.SSH/k was not refused under case-insensitive matching")
	}
	if blocked(newBlockedPaths(home, entries, false)) {
		t.Fatal("~/.SSH/k was refused under exact matching")
	}
}

func TestShellPathAsks_DegradedListAsksOutsideTheProject(t *testing.T) {
	home := blockedTempDir(t)
	project := blockedTempDir(t)
	outside := blockedTempDir(t)
	mkdirs(t, filepath.Join(project, "inside"))
	if err := os.Symlink(outside, filepath.Join(project, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	relativeOutside, err := filepath.Rel(project, filepath.Join(outside, "file"))
	if err != nil {
		t.Fatalf("Rel: %v", err)
	}
	list := func(root string, degraded bool) *BlockedPaths {
		return NewLiveBlockedPaths(home, root, nil, func() BlockedReload {
			if !degraded {
				return BlockedReload{}
			}
			return BlockedReload{Problems: map[string]string{"/g/settings.yaml": "is not valid YAML"}}
		}).Current()
	}

	for _, tc := range []struct {
		name   string
		root   string
		folder string
		argv   []string
		asks   bool
	}{
		{"an absolute path outside", project, project, []string{"cat", filepath.Join(outside, "file")}, true},
		{"a relative path that resolves outside", project, project, []string{"cat", relativeOutside}, true},
		{"a folder outside", project, outside, []string{"ls"}, true},
		{"a dot-dot sibling", project, project, []string{"grep", "x", "../sibling"}, true},
		{"a symlink inside that points outside", project, project, []string{"cat", "link/secret"}, true},
		{"an empty project root", "", project, []string{"cat", "inside/file"}, true},
		{"a file inside", project, project, []string{"cat", "inside/file"}, false},
		{"ls in the project folder", project, project, []string{"ls"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidates := ShellPathCandidates(tc.argv, tc.folder, home)
			if got := ShellPathAsks(list(tc.root, true), tc.folder, tc.argv, candidates); got != tc.asks {
				t.Fatalf("degraded ask for %q in %q = %v, want %v", tc.argv, tc.folder, got, tc.asks)
			}
			today := ShellPathAsks(NewBlockedPaths(home, nil), tc.folder, tc.argv, candidates)
			if got := ShellPathAsks(list(tc.root, false), tc.folder, tc.argv, candidates); got != today {
				t.Fatalf("ask for %q in %q without a problem = %v, want today's %v", tc.argv, tc.folder, got, today)
			}
		})
	}
}

func testExecArgv(stage StageNormalization, home string) []string {
	argv := slices.Clone(stage.Tokens)
	for i := range argv {
		if i < len(stage.ExecForms) && stage.ExecForms[i].Expand {
			argv[i] = home + stage.ExecForms[i].Suffix
		}
	}
	return argv
}

func TestShellPathAsks(t *testing.T) {
	home := blockedTempDir(t)
	project := blockedTempDir(t)
	child := filepath.Join(home, "proj")
	ssh := filepath.Join(home, ".ssh")
	mkdirs(t, ssh, child, filepath.Join(home, "sub"))
	if err := os.Symlink(home, filepath.Join(project, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	blocked := NewBlockedPaths(home, []BlockedEntry{{Path: ssh, Source: "s"}})
	stagesOf := func(t *testing.T, route, input string) []StageNormalization {
		t.Helper()
		var stages []StageNormalization
		if route == "literal" {
			canonical, err := CanonicalLiteralForm(input)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q): %v", input, err)
			}
			stages = LiteralStages(canonical)
		} else {
			split, err := SplitCommand(input)
			if err != nil || split.LiteralRoute {
				t.Fatalf("SplitCommand(%q) literal = %v, err = %v; want the direct route", input, split.LiteralRoute, err)
			}
			stages = split.Stages
		}
		if len(stages) == 0 {
			t.Fatalf("%s %q has no stages", route, input)
		}
		return stages
	}
	asks := func(t *testing.T, b *BlockedPaths, route, folder, input string) bool {
		t.Helper()
		for _, stage := range stagesOf(t, route, input) {
			argv := testExecArgv(stage, home)
			if (route == "literal" && LiteralRewriteAsks(stage, folder)) || ShellPathAsks(b, folder, argv, ShellPathCandidates(argv, folder, home)) {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		route, folder, input string
		want                 bool
	}{
		{"direct", project, "ls ~", true},
		{"direct", project, "ls " + home, true},
		{"direct", project, "ls " + home + "/", true},
		{"direct", project, "ls " + home + "/.", true},
		{"direct", project, "ls " + home + "/sub/..", true},
		{"direct", project, "ls ~/.ssh/..", true},
		{"direct", project, "rg token /", true},
		{"direct", project, "ls -- ~", true},
		{"direct", project, "cat notes ~", true},
		{"direct", child, "ls ..", true},
		{"direct", home, "cd ~ && ls", true},
		{"direct", "/", "cd / && cat notes", true},
		{"direct", project, "ls link", true},
		{"direct", project, "grep -f~/.ssh/k notes", true},
		{"direct", project, "grep -f/etc/p notes", true},
		{"direct", project, "ls -I~", true},
		{"literal", project, "ls * 2>/dev/null", true},
		{"literal", project, "cat $F 2>/dev/null", true},
		{"literal", project, "ls {a,b} 2>/dev/null", true},
		{"literal", project, "ls ~root 2>/dev/null", true},
		{"literal", project, `cat "$HOME/.ssh/k" 2>/dev/null`, true},
		{"literal", project, "cat ~/.ss?/k 2>/dev/null", true},
		{"literal", project, "env ls 2>/dev/null", true},
		{"direct", project, "ls", false},
		{"direct", project, "rg -n token src", false},
		{"direct", project, "cat ~/.sshx/k", false},
		{"direct", project, "ls ~/.ss", false},
		{"direct", project, "ls --color=auto", false},
		{"direct", project, "ls -la", false},
		{"direct", project, "cat -", false},
		{"direct", project, "cat '~/.ssh/k'", false},
		{"direct", project, "cat 'notes*'", false},
		{"direct", project, "cat ~/notes", false},
		{"literal", project, "ls ~/notes 2>/dev/null", false},
	} {
		t.Run(tc.route+" "+tc.input, func(t *testing.T) {
			if got := asks(t, blocked, tc.route, tc.folder, tc.input); got != tc.want {
				t.Fatalf("ask for %q in %q = %v, want %v", tc.input, tc.folder, got, tc.want)
			}
		})
	}

	t.Run("a raw token count that differs from the tokens", func(t *testing.T) {
		stage := stagesOf(t, "literal", "env ls 2>/dev/null")[0]
		if len(stage.Tokens) != 1 || stage.Source != "env ls" {
			t.Fatalf("stage = %+v, want the env prefix stripped from one token", stage)
		}
	})

	t.Run("double-quoted $HOME is asked, not refused", func(t *testing.T) {
		for _, stage := range stagesOf(t, "literal", `cat "$HOME/.ssh/k" 2>/dev/null`) {
			for _, candidate := range ShellPathCandidates(testExecArgv(stage, home), project, home) {
				if _, ok := blocked.Blocking(candidate); ok {
					t.Fatalf("candidate %q is refused, want only the ask", candidate)
				}
			}
		}
	})

	t.Run("letter case", func(t *testing.T) {
		input := "ls " + strings.ToUpper(home)
		if !asks(t, newBlockedPaths(home, nil, true), "direct", project, input) {
			t.Fatal("a differently cased home did not ask under case-insensitive matching")
		}
		if asks(t, newBlockedPaths(home, nil, false), "direct", project, input) {
			t.Fatal("a differently cased home asked under exact matching")
		}
	})
}

func TestLiteralRewriteAsks_OptionGlob(t *testing.T) {
	runDir := t.TempDir()
	matched := t.TempDir()
	if err := os.WriteFile(filepath.Join(matched, "--include=x.md"), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	const optionGlobs = `grep -rln "b09\|b08" . --include=*.md --include=*.txt 2>/dev/null | head -30`
	asks := func(t *testing.T, dir, input string) bool {
		t.Helper()
		canonical, err := CanonicalLiteralForm(input)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q): %v", input, err)
		}
		stages := LiteralStages(canonical)
		if len(stages) == 0 {
			t.Fatalf("%q has no literal stages", input)
		}
		for _, stage := range stages {
			if LiteralRewriteAsks(stage, dir) {
				return true
			}
		}
		return false
	}
	if asks(t, runDir, optionGlobs) {
		t.Fatalf("%q asked in a directory with no matching entry", optionGlobs)
	}
	if !asks(t, matched, optionGlobs) {
		t.Fatalf("%q did not ask in a directory holding --include=x.md", optionGlobs)
	}
	metaDir := filepath.Join(t.TempDir(), "[x]")
	if err := os.Mkdir(metaDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "--include=x.md"), nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !asks(t, metaDir, optionGlobs) {
		t.Fatalf("%q did not ask in %s holding --include=x.md", optionGlobs, metaDir)
	}
	stage := func(source string) StageNormalization {
		return StageNormalization{Source: source, Tokens: make([]string, 5)}
	}
	if LiteralRewriteAsks(stage("grep -r x . --include=id*.md"), runDir) || !LiteralRewriteAsks(stage("grep -r x . --include=`id`*.md"), runDir) {
		t.Fatal("want a backtick, and only the backtick, to make the option glob ask")
	}
	for _, input := range []string{
		"ls reviews" + "/*.md 2>/dev/null",
		"cat batch-b0*/log.md 2>/dev/null",
		"grep x -- -*.md 2>/dev/null",
		`grep x "--" -*.md 2>/dev/null`,
		"grep -r x . --include=[ab].md 2>/dev/null",
		"grep -r x . --include={a,b}.md 2>/dev/null",
		"grep -r x . --include=src/*.go 2>/dev/null",
		"grep -r x . --include=$X*.md 2>/dev/null",
		"grep -r x . --include=~*.md 2>/dev/null",
		"grep -r x . --include=!*.md 2>/dev/null",
		`grep -r x . --include=*\ .md 2>/dev/null`,
		`grep -r x . "--include="*.md 2>/dev/null`,
		`cat "reviews"/*.md 2>/dev/null`,
		"gr*p -r x . 2>/dev/null",
		"-gr*p -r x . 2>/dev/null",
	} {
		t.Run(input, func(t *testing.T) {
			if !asks(t, runDir, input) {
				t.Fatalf("%q did not ask", input)
			}
		})
	}
}
