package permissions

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestClassifyDirectTokens(t *testing.T) {
	cases := []struct {
		name        string
		tokens      []string
		wantOffered bool
		wantAnchor  int
	}{
		{"plain positional", []string{"log"}, true, 0},
		{"long flag then positional", []string{"--oneline", "log"}, true, 1},
		{"positional then long flag", []string{"log", "--oneline"}, true, 0},
		{"key=value flag then positional", []string{"--color=always", "build"}, true, 1},
		{"bundled short flags then positional", []string{"-abc", "test"}, true, 1},
		{"single short flag then positional", []string{"-l", "status"}, true, 1},
		{"only flags", []string{"-l", "-a"}, false, -1},
		{"bare dash is a flag (cat -)", []string{"-"}, false, -1},
		{"double-dash terminator then positional", []string{"--", "foo"}, true, 1},
		{"double-dash makes leading-dash token positional", []string{"--", "-x"}, true, 1},
		{"flag path value is skipped, later token anchors", []string{"--git-dir", "/path", "log"}, true, 2},
		{"flag path value skipped, no later token", []string{"-v", "src/main.go"}, false, -1},
		{"flag path value skipped, later path does not anchor", []string{"-v", "/a", "/b", "bar"}, false, -1},
		{"path after terminator is not a flag value", []string{"-v", "--", "/tmp/x"}, false, -1},
		{"first positional is a path", []string{"/tmp/x"}, false, -1},
		{"first positional starts with tilde", []string{"~/foo"}, false, -1},
		{"tilde after flag is skipped", []string{"-C", "~/repo", "status"}, true, 2},
		{"bare tilde positional", []string{"~"}, false, -1},
		{"no args", nil, false, -1},
		{"flag value anchors when it is not a path", []string{"--only", "t200", "--force"}, true, 1},
		{"short flag value anchors when it is not a path", []string{"-n", "1,28p"}, true, 1},
		{"flag path value skipped before subcommand", []string{"--cwd", "/home/u/proj", "status", "--rev", "tip"}, true, 2},
		{"empty flag value anchors", []string{"--only", ""}, true, 1},
		{"whitespace path after flag is skipped", []string{"--file", "/a b/c", "pat"}, true, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			offered, anchor := ClassifyDirectTokens(c.tokens)
			if offered != c.wantOffered {
				t.Errorf("offered = %v, want %v", offered, c.wantOffered)
			}
			if anchor != c.wantAnchor {
				t.Errorf("anchorIdx = %d, want %d", anchor, c.wantAnchor)
			}
		})
	}
}

func TestDirectScopeSubjectStrings(t *testing.T) {
	if got := ExactSubject("ls", []string{"-la", "/tmp"}); got != "ls -la /tmp" {
		t.Errorf("ExactSubject = %q, want %q", got, "ls -la /tmp")
	}
	if got := ExactSubject("make", nil); got != "make" {
		t.Errorf("ExactSubject (no args) = %q, want %q", got, "make")
	}
	if got := PrefixSubject("git", []string{"log"}); got != "git log :*" {
		t.Errorf("PrefixSubject = %q, want %q", got, "git log :*")
	}
	if got := PrefixSubject("hg", []string{"--cwd", "/repo", "status"}); got != "hg --cwd /repo status :*" {
		t.Errorf("PrefixSubject (prefix) = %q, want %q", got, "hg --cwd /repo status :*")
	}
	if got := ProgramSubject("make"); got != "make :*" {
		t.Errorf("ProgramSubject = %q, want %q", got, "make :*")
	}
	if got := ExactSubject("foo", []string{"--only", ""}); got != "foo --only ''" {
		t.Errorf("ExactSubject (empty value) = %q, want %q", got, "foo --only ''")
	}
	if got := ExactSubject("foo", []string{"a b", "c"}); got != "foo 'a b' c" {
		t.Errorf("ExactSubject (whitespace token) = %q, want %q", got, "foo 'a b' c")
	}
	if got := PrefixSubject("rg", []string{"--file", "/a b/c", "pat"}); got != "rg --file '/a b/c' pat :*" {
		t.Errorf("PrefixSubject (whitespace path) = %q, want %q", got, "rg --file '/a b/c' pat :*")
	}
	if got := ProgramSubject("my prog"); got != "'my prog' :*" {
		t.Errorf("ProgramSubject (whitespace program) = %q, want %q", got, "'my prog' :*")
	}
}

func TestNewDirectScopeModel_LadderOrderAndRecommendation(t *testing.T) {
	model, ok := NewDirectScopeModel([]string{"prep-open-tasks.sh", "--only", "c175", "--force"}, "")
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok for a well-formed direct request")
	}

	wantSubjects := []string{
		"prep-open-tasks.sh --only c175 --force",
		"prep-open-tasks.sh --only c175 --force :*",
		"prep-open-tasks.sh --only c175 :*",
		"prep-open-tasks.sh --only :*",
		"prep-open-tasks.sh :*",
	}
	wantKinds := []DirectScopeKind{DirectScopeExact, DirectScopePrefix, DirectScopePrefix, DirectScopePrefix, DirectScopeProgram}
	if len(model.Choices) != len(wantSubjects) {
		t.Fatalf("len(Choices) = %d, want %d (%+v)", len(model.Choices), len(wantSubjects), model.Choices)
	}
	for i, want := range wantSubjects {
		if model.Choices[i].Subject != want {
			t.Errorf("Choices[%d].Subject = %q, want %q", i, model.Choices[i].Subject, want)
		}
		if model.Choices[i].Kind != wantKinds[i] {
			t.Errorf("Choices[%d].Kind = %d, want %d", i, model.Choices[i].Kind, wantKinds[i])
		}
	}
	if model.Recommended != 2 {
		t.Errorf("Recommended = %d (%q), want the inferred prefix row", model.Recommended, model.Choices[model.Recommended].Subject)
	}
}

// The chooser takes no declared-list input and must never grow one: a declaration changes Auto
// posture, never what the prompt recommends.
func TestNewDirectScopeModel_UnaffectedByDeclaredCommandList(t *testing.T) {
	model, ok := NewDirectScopeModel([]string{"prep-open-tasks.sh", "--only", "i425"}, "")
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok for a well-formed direct request")
	}
	got := model.Choices[model.Recommended]
	if want := "prep-open-tasks.sh --only i425 :*"; got.Subject != want {
		t.Errorf("recommended subject = %q, want %q", got.Subject, want)
	}
	if got.RequiresConfirmation() {
		t.Errorf("recommended choice is the confirm-gated Program row: %+v", got)
	}
}

func TestNewDirectScopeModel_RecommendationNeverBroaderThanInferredPrefix(t *testing.T) {
	cases := []struct {
		name   string
		tokens []string
		want   string
	}{
		{"anchor is first arg", []string{"git", "log", "--oneline"}, "git log :*"},
		{"flag value anchor", []string{"prep-open-tasks.sh", "--only", "c175", "--force"}, "prep-open-tasks.sh --only c175 :*"},
		{"path flag then subcommand", []string{"hg", "--cwd", "/repo", "status", "--rev", "tip"}, "hg --cwd /repo status :*"},
		{"no anchor: flags only", []string{"ls", "-la"}, "ls -la"},
		{"no anchor: bare path operand", []string{"ls", "-la", "/tmp"}, "ls -la /tmp"},
		{"no args", []string{"make"}, "make"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			model, ok := NewDirectScopeModel(c.tokens, "")
			if !ok {
				t.Fatalf("NewDirectScopeModel(%v) = !ok", c.tokens)
			}
			got := model.Choices[model.Recommended]
			if got.Subject != c.want {
				t.Errorf("recommended subject = %q, want %q", got.Subject, c.want)
			}
			if got.RequiresConfirmation() {
				t.Errorf("recommended choice is the confirm-gated Program row: %+v", got)
			}
		})
	}
}

func TestNewDirectScopeModel_PrefixSubjectsMatchOnlyAtTokenBoundaries(t *testing.T) {
	commands := [][]string{
		{"prep-open-tasks.sh", "--only", "c175", "--force"},
		{"hg", "--cwd", "/home/u/proj", "status", "--rev", "tip"},
		{"sed", "-n", "1,28p"},
		{"rg", "--file", "/a b/c", "pat"},
		{"foo", "--only", ""},
	}
	for _, command := range commands {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			model, ok := NewDirectScopeModel(command, "")
			if !ok {
				t.Fatalf("NewDirectScopeModel(%v) = !ok", command)
			}
			var prefixRows []DirectScopeChoice
			for _, c := range model.Choices {
				if c.Kind == DirectScopePrefix {
					prefixRows = append(prefixRows, c)
				}
			}
			if len(prefixRows) != len(command)-1 {
				t.Fatalf("%d Prefix rows, want %d", len(prefixRows), len(command)-1)
			}
			for row, c := range prefixRows {
				if !MatchesDirectSubject(command, nil, false, c.Subject) {
					t.Fatalf("prefix subject %q does not match the command it was offered for %v", c.Subject, command)
				}
				pinned := len(command) - row

				for i := 0; i < pinned; i++ {
					mutated := append([]string(nil), command...)
					mutated[i] += "X"
					if MatchesDirectSubject(mutated, nil, false, c.Subject) {
						t.Errorf("subject %q matched %v after changing pinned token %d", c.Subject, mutated, i)
					}
					truncated := append([]string(nil), command...)
					if tok := truncated[i]; tok != "" {
						truncated[i] = tok[:len(tok)-1]
						if MatchesDirectSubject(truncated, nil, false, c.Subject) {
							t.Errorf("subject %q matched %v after truncating pinned token %d", c.Subject, truncated, i)
						}
					}
				}

				varied := append(append([]string(nil), command[:pinned]...), "anything", "else")
				if !MatchesDirectSubject(varied, nil, false, c.Subject) {
					t.Errorf("subject %q did not authorize later tokens %v", c.Subject, varied)
				}
				if pinned > 1 && MatchesDirectSubject(command[:pinned-1], nil, false, c.Subject) {
					t.Errorf("subject %q matched a command missing a pinned token: %v", c.Subject, command[:pinned-1])
				}
				for _, spelling := range []string{`":*"`, `:\*`, `':*'`} {
					literal := strings.TrimSuffix(c.Subject, ":*") + spelling
					if MatchesDirectSubject(varied, nil, false, literal) {
						t.Errorf("quoted wildcard subject %q wildcarded %v", literal, varied)
					}
				}
			}
		})
	}
}

func TestNewDirectScopeModel_ExactAndProgramLimits(t *testing.T) {
	model, ok := NewDirectScopeModel([]string{"make"}, "")
	if !ok {
		t.Fatal("NewDirectScopeModel([make]) = !ok")
	}
	if len(model.Choices) != 2 {
		t.Fatalf("len(Choices) = %d, want 2 (%+v)", len(model.Choices), model.Choices)
	}
	if model.Choices[0].Kind != DirectScopeExact || model.Choices[0].Subject != "make" {
		t.Errorf("Choices[0] = %+v, want exact subject %q", model.Choices[0], "make")
	}
	if model.Choices[1].Kind != DirectScopeProgram || model.Choices[1].Subject != "make :*" {
		t.Errorf("Choices[1] = %+v, want program subject %q", model.Choices[1], "make :*")
	}
	if model.Recommended != 0 {
		t.Errorf("Recommended = %d, want 0 (Exact)", model.Recommended)
	}

	if _, ok := NewDirectScopeModel(nil, ""); ok {
		t.Error("NewDirectScopeModel(nil) = ok; an empty token sequence has no subject to scope")
	}
}

func TestDirectScopeChoice_OnlyProgramRequiresConfirmation(t *testing.T) {
	model, ok := NewDirectScopeModel([]string{"git", "log", "--oneline"}, "")
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok")
	}
	for i, c := range model.Choices {
		want := c.Kind == DirectScopeProgram
		if got := c.RequiresConfirmation(); got != want {
			t.Errorf("Choices[%d] (%+v) RequiresConfirmation = %v, want %v", i, c, got, want)
		}
	}
	last := model.Choices[len(model.Choices)-1]
	if !last.RequiresConfirmation() || last.Subject != "git :*" {
		t.Errorf("widest choice = %+v, want confirm-gated %q", last, "git :*")
	}
}

func TestNewDirectScopeModel_ExactPreservesEveryCanonicalToken(t *testing.T) {
	command := []string{"rg", "--file", "/a b/c", "", "pat"}
	model, ok := NewDirectScopeModel(command, "")
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok")
	}
	exact := model.Choices[0]
	if exact.Kind != DirectScopeExact {
		t.Fatalf("Choices[0] = %+v, want the Exact row", exact)
	}
	if want := "rg --file '/a b/c' '' pat"; exact.Subject != want {
		t.Fatalf("exact subject = %q, want %q", exact.Subject, want)
	}
	if !MatchesDirectSubject(command, nil, false, exact.Subject) {
		t.Fatalf("exact subject %q does not match %v", exact.Subject, command)
	}
	collapsed := []string{"rg", "--file", "/a b/c", "pat"}
	if MatchesDirectSubject(collapsed, nil, false, exact.Subject) {
		t.Fatalf("exact subject %q matched %v after the empty token collapsed", exact.Subject, collapsed)
	}
}

// containmentFixture lays out a machine-shaped tree: a home directory and a scratch
// directory as siblings, so home's ancestors are exactly the floor the chooser must stop at.
type containmentFixture struct {
	root  string
	home  string
	tmp   string
	run   string
	entry string
}

func newContainmentFixture(t *testing.T) containmentFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	f := containmentFixture{
		root: root,
		home: filepath.Join(root, "home", "user"),
		tmp:  filepath.Join(root, "tmp"),
	}
	f.run = filepath.Join(f.tmp, "codemeld-g2430-audit.RtAY58")
	f.entry = filepath.Join(f.run, "id-ssh")
	if err := os.MkdirAll(f.home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(f.run, 0o755); err != nil {
		t.Fatalf("mkdir run: %v", err)
	}
	if err := os.WriteFile(f.entry, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	return f
}

func TestNewDirectScopeModel_PathRungLadderPlacementAndFloor(t *testing.T) {
	f := newContainmentFixture(t)
	model, ok := NewDirectScopeModel([]string{"chmod", "+x", f.entry}, f.home)
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok")
	}

	row := model.PathRow()
	if row != 2 {
		t.Fatalf("PathRow = %d, want the row between the Prefix that pins the path and the one that wildcards it", row)
	}
	if model.Recommended != row {
		t.Fatalf("Recommended = %d, want the path row %d", model.Recommended, row)
	}
	wantKinds := []DirectScopeKind{DirectScopeExact, DirectScopePrefix, DirectScopePath, DirectScopePrefix, DirectScopeProgram}
	if len(model.Choices) != len(wantKinds) {
		t.Fatalf("len(Choices) = %d, want %d (%+v)", len(model.Choices), len(wantKinds), model.Choices)
	}
	for i, want := range wantKinds {
		if model.Choices[i].Kind != want {
			t.Errorf("Choices[%d].Kind = %d, want %d", i, model.Choices[i].Kind, want)
		}
	}
	if got := model.Choices[1].Subject; got != ExactSubject("chmod", []string{"+x", f.entry})+" :*" {
		t.Errorf("row above the path row = %q, want the Prefix that still pins the path", got)
	}
	if got := model.Choices[3].Subject; got != "chmod +x :*" {
		t.Errorf("row below the path row = %q, want the Prefix that wildcards the path", got)
	}

	path := model.Choices[row]
	if want := []string{f.run, f.tmp}; !slices.Equal(path.Boundaries, want) {
		t.Fatalf("Boundaries = %v, want %v (parent first, stopping below home's ancestors)", path.Boundaries, want)
	}
	if path.Boundary != 0 {
		t.Errorf("Boundary = %d, want the immediate parent", path.Boundary)
	}
	if path.TailWildcard {
		t.Error("TailWildcard = true for a command whose path argument is last")
	}
	if want := "chmod +x :under=" + f.run; path.Readable != want {
		t.Errorf("Readable = %q, want %q", path.Readable, want)
	}
	if !strings.HasPrefix(path.Subject, "'direct-under/v1 ") {
		t.Errorf("Subject = %q, want the opaque versioned envelope", path.Subject)
	}
	for _, b := range path.Boundaries {
		if b == "/" || IsDescendantOrEqual(f.home, b) {
			t.Errorf("boundary %q is at or above the floor", b)
		}
	}
}

func TestNewDirectScopeModel_PathRungAdjustsToEveryBoundary(t *testing.T) {
	f := newContainmentFixture(t)
	model, ok := NewDirectScopeModel([]string{"chmod", "+x", f.entry}, f.home)
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok")
	}
	boundaries := model.Choices[model.PathRow()].Boundaries
	for i, boundary := range boundaries {
		choice, ok := model.PathChoiceAt(i)
		if !ok {
			t.Fatalf("PathChoiceAt(%d) = !ok", i)
		}
		if choice.Boundary != i || choice.Boundaries[choice.Boundary] != boundary {
			t.Fatalf("PathChoiceAt(%d) = %+v, want the choice at %q", i, choice, boundary)
		}
		if want := "chmod +x :under=" + boundary; choice.Readable != want {
			t.Errorf("Readable at %d = %q, want %q", i, choice.Readable, want)
		}
		if !MatchesDirectSubject([]string{"chmod", "+x", f.entry}, nil, false, choice.Subject) {
			t.Errorf("subject at boundary %q does not authorize the approved command", boundary)
		}
	}
	if _, ok := model.PathChoiceAt(len(boundaries)); ok {
		t.Error("PathChoiceAt walked past the widest boundary")
	}
	if _, ok := model.PathChoiceAt(-1); ok {
		t.Error("PathChoiceAt walked below the immediate parent")
	}
}

func TestNewDirectScopeModel_PathRungTailWildcardWhenTokensFollow(t *testing.T) {
	f := newContainmentFixture(t)
	repo := filepath.Join(f.run, "subprobe", "sub")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	model, ok := NewDirectScopeModel([]string{"git", "-C", repo, "add", "a"}, f.home)
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok")
	}
	row := model.PathRow()
	if row != 4 {
		t.Fatalf("PathRow = %d, want the row above the Prefix that wildcards the path", row)
	}
	if got := model.Choices[row+1].Subject; got != "git -C :*" {
		t.Fatalf("row below the path row = %q, want the Prefix that wildcards the path", got)
	}
	path := model.Choices[row]
	if !path.TailWildcard {
		t.Fatal("TailWildcard = false for a command with tokens after its path argument")
	}
	want := []string{filepath.Join(f.run, "subprobe"), f.run, f.tmp}
	if !slices.Equal(path.Boundaries, want) {
		t.Fatalf("Boundaries = %v, want %v", path.Boundaries, want)
	}
	widest, ok := model.PathChoiceAt(len(want) - 1)
	if !ok {
		t.Fatal("PathChoiceAt(widest) = !ok")
	}
	if want := "git -C :under=" + f.tmp + " :*"; widest.Readable != want {
		t.Errorf("Readable = %q, want %q", widest.Readable, want)
	}
	if !MatchesDirectSubject([]string{"git", "-C", repo, "commit", "-m", "init"}, nil, false, widest.Subject) {
		t.Error("the widest boundary does not authorize the same command with a different tail")
	}
}

func TestNewDirectScopeModel_PathRungSuppressedAndLadderUnchanged(t *testing.T) {
	f := newContainmentFixture(t)
	second := filepath.Join(f.run, "id-rsa")
	if err := os.WriteFile(second, nil, 0o644); err != nil {
		t.Fatalf("write second path: %v", err)
	}
	directChild := filepath.Join(f.home, "notes.txt")
	if err := os.WriteFile(directChild, nil, 0o644); err != nil {
		t.Fatalf("write home child: %v", err)
	}
	relHome := filepath.Join(f.home, "..", "user")
	linkedHome := filepath.Join(f.root, "home-link")
	if err := os.Symlink(f.home, linkedHome); err != nil {
		t.Fatalf("symlink home: %v", err)
	}
	dangling := filepath.Join(f.root, "dangling-home")
	if err := os.Symlink(filepath.Join(f.root, "absent"), dangling); err != nil {
		t.Fatalf("dangling symlink: %v", err)
	}
	loopA := filepath.Join(f.root, "loop-a")
	loopB := filepath.Join(f.root, "loop-b")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatalf("loop a: %v", err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatalf("loop b: %v", err)
	}

	cases := []struct {
		name   string
		tokens []string
		home   string
	}{
		{"two path arguments", []string{"cp", f.entry, second}, f.home},
		{"relative argument", []string{"chmod", "+x", "id-ssh"}, f.home},
		{"slash-bearing relative argument", []string{"chmod", "+x", "bin/id-ssh"}, f.home},
		{"tilde argument", []string{"chmod", "+x", "~/id-ssh"}, f.home},
		{"missing target", []string{"chmod", "+x", filepath.Join(f.run, "absent")}, f.home},
		{"no path argument", []string{"chmod", "+x", "id"}, f.home},
		{"empty argument token", []string{"chmod", "", f.entry}, f.home},
		{"terminal wildcard sentinel argument", []string{"chmod", f.entry, ":*"}, f.home},
		{"non-terminal wildcard sentinel argument", []string{"chmod", ":*", f.entry}, f.home},
		{"terminal under sentinel argument", []string{"chmod", f.entry, ":under=" + f.tmp}, f.home},
		{"non-terminal under sentinel argument", []string{"chmod", ":under=" + f.tmp, f.entry}, f.home},
		{"path directly inside home", []string{"chmod", "+x", directChild}, f.home},
		{"empty home", []string{"chmod", "+x", f.entry}, ""},
		{"relative home", []string{"chmod", "+x", f.entry}, "home/user"},
		{"missing home", []string{"chmod", "+x", f.entry}, filepath.Join(f.root, "absent")},
		{"non-directory home", []string{"chmod", "+x", f.entry}, f.entry},
		{"dangling symlink home", []string{"chmod", "+x", f.entry}, dangling},
		{"symlink loop home", []string{"chmod", "+x", f.entry}, loopA},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			model, ok := NewDirectScopeModel(c.tokens, c.home)
			if !ok {
				t.Fatalf("NewDirectScopeModel(%v) = !ok", c.tokens)
			}
			if model.PathRow() != -1 {
				t.Fatalf("PathRow = %d, want no containment row (%+v)", model.PathRow(), model.Choices)
			}
			if _, ok := model.PathChoiceAt(0); ok {
				t.Error("PathChoiceAt(0) = ok without a containment row")
			}
			bare, _ := NewDirectScopeModel(c.tokens, "")
			if len(model.Choices) != len(bare.Choices) || model.Recommended != bare.Recommended {
				t.Fatalf("ladder = %+v (recommended %d), want the unchanged ladder %+v (recommended %d)",
					model.Choices, model.Recommended, bare.Choices, bare.Recommended)
			}
			for i, c := range model.Choices {
				if c.Subject != bare.Choices[i].Subject || c.Kind != bare.Choices[i].Kind {
					t.Errorf("Choices[%d] = %+v, want %+v", i, c, bare.Choices[i])
				}
			}
		})
	}
	if _, err := os.Stat(relHome); err != nil {
		t.Fatalf("dot-segment home spelling is not usable: %v", err)
	}
	if _, err := os.Stat(linkedHome); err != nil {
		t.Fatalf("symlinked home spelling is not usable: %v", err)
	}
}

func TestNewDirectScopeModel_PathRungCanonicalizesHomeSpellings(t *testing.T) {
	f := newContainmentFixture(t)
	linked := filepath.Join(f.root, "home-link")
	if err := os.Symlink(f.home, linked); err != nil {
		t.Fatalf("symlink home: %v", err)
	}
	below := filepath.Join(f.home, "work", "sub")
	if err := os.MkdirAll(below, 0o755); err != nil {
		t.Fatalf("mkdir below home: %v", err)
	}
	entry := filepath.Join(below, "run.sh")
	if err := os.WriteFile(entry, nil, 0o644); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	want := []string{below, filepath.Join(f.home, "work")}
	for _, home := range []string{f.home, linked, filepath.Join(f.home, "work", "..")} {
		model, ok := NewDirectScopeModel([]string{"chmod", "+x", entry}, home)
		if !ok {
			t.Fatalf("NewDirectScopeModel with home %q = !ok", home)
		}
		row := model.PathRow()
		if row < 0 {
			t.Fatalf("home %q produced no containment row", home)
		}
		got := model.Choices[row].Boundaries
		if !slices.Equal(got, want) {
			t.Fatalf("home %q boundaries = %v, want %v", home, got, want)
		}
		for _, b := range got {
			if IsDescendantOrEqual(f.home, b) {
				t.Errorf("home %q offered %q, which is at or above canonical home", home, b)
			}
		}
	}
}

func TestNewDirectScopeModel_PathRungNeverOffersRootForATopLevelPath(t *testing.T) {
	f := newContainmentFixture(t)
	model, ok := NewDirectScopeModel([]string{"chmod", "+x", f.entry}, f.home)
	if !ok {
		t.Fatal("NewDirectScopeModel = !ok")
	}
	for i := 0; ; i++ {
		choice, ok := model.PathChoiceAt(i)
		if !ok {
			break
		}
		if choice.Boundaries[choice.Boundary] == string(filepath.Separator) {
			t.Fatalf("boundary %d is the filesystem root", i)
		}
	}
	if got := containmentBoundaries("/", f.home); len(got) != 0 {
		t.Errorf("containmentBoundaries at the root = %v, want none", got)
	}
	if got := containmentBoundaries(f.home, f.home); len(got) != 0 {
		t.Errorf("containmentBoundaries at canonical home = %v, want none", got)
	}
	if got := containmentBoundaries(filepath.Dir(f.home), f.home); len(got) != 0 {
		t.Errorf("containmentBoundaries at home's parent = %v, want none", got)
	}
}

func TestResolveExistingEntry(t *testing.T) {
	f := newContainmentFixture(t)
	link := filepath.Join(f.tmp, "id-link")
	if err := os.Symlink(f.entry, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if got, err := resolveExistingEntry(link); err != nil || got != f.entry {
		t.Errorf("resolveExistingEntry(symlink) = %q, %v; want %q", got, err, f.entry)
	}
	if got, err := resolveExistingEntry(filepath.Join(f.run, "..", "codemeld-g2430-audit.RtAY58", "id-ssh")); err != nil || got != f.entry {
		t.Errorf("resolveExistingEntry(dot segments) = %q, %v; want %q", got, err, f.entry)
	}
	if got, err := resolveExistingEntry(f.run); err != nil || got != f.run {
		t.Errorf("resolveExistingEntry(directory) = %q, %v; want %q", got, err, f.run)
	}
	for _, bad := range []string{"", "relative/path", filepath.Join(f.run, "absent")} {
		if _, err := resolveExistingEntry(bad); err == nil {
			t.Errorf("resolveExistingEntry(%q) = nil error", bad)
		}
	}
	if _, err := resolveExistingDir(f.entry); err == nil {
		t.Error("resolveExistingDir accepted a regular file")
	}
	if got, err := resolveExistingDir(f.run); err != nil || got != f.run {
		t.Errorf("resolveExistingDir = %q, %v; want %q", got, err, f.run)
	}
}
