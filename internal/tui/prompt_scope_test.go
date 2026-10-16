// Package tui provides the terminal user interface.
package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/permissions"
)

func TestScopeOptionRows_SubcommandSubjectPinsDisplayedPrefix(t *testing.T) {
	cases := []struct {
		name    string
		command []string
		want    string
	}{
		{"flag value anchor", []string{"prep-open-tasks.sh", "--only", "t200", "--force"}, "prep-open-tasks.sh --only t200 :*"},
		{"short flag value anchor", []string{"sed", "-n", "1,28p"}, "sed -n 1,28p :*"},
		{"path flag then subcommand", []string{"hg", "--cwd", "/home/u/proj", "status", "--rev", "tip"}, "hg --cwd /home/u/proj status :*"},
		{"anchor is first arg", []string{"git", "log", "--oneline"}, "git log :*"},
		{"anchor is first arg, no flags", []string{"mise", "run", "check"}, "mise run :*"},
		{"path pinned, not wildcarded", []string{"foo", "--verbose", "/data/x", "bar"}, "foo --verbose /data/x bar :*"},
		{"key=value flag pinned", []string{"foo", "--key=value", "bar"}, "foo --key=value bar :*"},
		{"terminator pinned", []string{"foo", "--", "--weird"}, "foo -- --weird :*"},
		{"empty flag value anchor", []string{"foo", "--only", ""}, "foo --only '' :*"},
		{"whitespace path flag value pinned", []string{"rg", "--file", "/a b/c", "pat"}, "rg --file '/a b/c' pat :*"},
		{"no anchor after skipped path", []string{"foo", "-v", "src/main.go"}, ""},
		{"path value only", []string{"cat", "-n", "/etc/passwd"}, ""},
		{"unassociated path", []string{"ls", "/tmp/x"}, ""},
		{"only flags", []string{"prdtasks", "--help"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got string
			for _, row := range scopeOptionRows(c.command[0], c.command[1:]) {
				if row.Kind == ScopeSubcommand {
					got = row.Subject
				}
			}
			if got != c.want {
				t.Fatalf("subcommand subject = %q, want %q", got, c.want)
			}
			if c.want == "" {
				return
			}

			if !permissions.MatchesDirectSubject(c.command, nil, false, got) {
				t.Errorf("MatchesDirectSubject(%v, nil, %q) = false, want true", c.command, got)
			}

			_, anchor := permissions.ClassifyDirectTokens(c.command[1:])
			pinned := anchor + 2
			if pinned > len(c.command) {
				t.Fatalf("subject prefix of %d tokens is longer than the command %v", pinned, c.command)
			}

			for i := 0; i < pinned; i++ {
				mutated := append([]string(nil), c.command...)
				mutated[i] += "X"
				if permissions.MatchesDirectSubject(mutated, nil, false, got) {
					t.Errorf("subject %q matched %v after changing pinned token %d", got, mutated, i)
				}
			}

			extended := append(append([]string(nil), c.command...), "trailing")
			if !permissions.MatchesDirectSubject(extended, nil, false, got) {
				t.Errorf("subject %q did not wildcard a trailing token: %v", got, extended)
			}
		})
	}
}

func TestBuildScopeOptions_PrefixRowAtEveryBoundary(t *testing.T) {
	opts, defaultIdx := scopeOptionsFor(t, "prep-open-tasks.sh", []string{"--only", "c175", "--force"}, "")

	wantSubjects := []string{
		"prep-open-tasks.sh --only c175 --force",
		"prep-open-tasks.sh --only c175 --force :*",
		"prep-open-tasks.sh --only c175 :*",
		"prep-open-tasks.sh --only :*",
		"prep-open-tasks.sh :*",
	}
	wantKinds := []ScopeKind{ScopeExact, ScopePrefix, ScopePrefix, ScopePrefix, ScopeProgram}
	if len(opts) != len(wantSubjects) {
		t.Fatalf("len(opts) = %d, want %d (%+v)", len(opts), len(wantSubjects), opts)
	}
	for i, want := range wantSubjects {
		if opts[i].Subject != want {
			t.Errorf("opts[%d].Subject = %q, want %q", i, opts[i].Subject, want)
		}
		if opts[i].Kind != wantKinds[i] {
			t.Errorf("opts[%d].Kind = %d, want %d", i, opts[i].Kind, wantKinds[i])
		}
	}
	if defaultIdx != 2 || opts[defaultIdx].Subject != "prep-open-tasks.sh --only c175 :*" {
		t.Errorf("defaultIdx = %d (%q), want the inferred prefix row", defaultIdx, opts[defaultIdx].Subject)
	}
	for _, so := range opts {
		if so.Kind == ScopeSubcommand {
			t.Errorf("direct chooser offered an inferred Subcommand row: %+v", so)
		}
	}
}

// The TUI chooser takes no declared-list input and must never grow one: a declaration changes Auto
// posture, never what the prompt recommends.
func TestBuildScopeOptions_UnaffectedByDeclaredCommandList(t *testing.T) {
	opts, defaultIdx := scopeOptionsFor(t, "prep-open-tasks.sh", []string{"--only", "i425"}, "")
	if want := "prep-open-tasks.sh --only i425 :*"; opts[defaultIdx].Subject != want {
		t.Errorf("defaultIdx = %d (%q), want %q", defaultIdx, opts[defaultIdx].Subject, want)
	}
	if opts[defaultIdx].Kind != ScopePrefix {
		t.Errorf("default kind = %d, want ScopePrefix", opts[defaultIdx].Kind)
	}
}

func TestBuildScopeOptions_PrefixRowsNarrowToBroad(t *testing.T) {
	for _, args := range [][]string{
		{"log", "--oneline"},
		{"--only", "c175", "--force"},
		{"-la", "/tmp"},
		{"status"},
	} {
		opts, _ := scopeOptionsFor(t, "git", args, "")
		if opts[0].Kind != ScopeExact {
			t.Fatalf("%v: first row kind = %d, want Exact", args, opts[0].Kind)
		}
		if last := opts[len(opts)-1]; last.Kind != ScopeProgram {
			t.Fatalf("%v: last row = %+v, want Program", args, last)
		}
		middle := opts[1 : len(opts)-1]
		if len(middle) != len(args) {
			t.Fatalf("%v: %d Prefix rows, want %d (one per token boundary)", args, len(middle), len(args))
		}
		for i, so := range middle {
			if so.Kind != ScopePrefix {
				t.Fatalf("%v: middle row %+v is not a Prefix row", args, so)
			}
			pinnedArgs := len(args) - i
			if pinnedArgs < 1 {
				t.Fatalf("%v: row %d is a program-only prefix; that is the Program row", args, i)
			}
			if want := permissions.PrefixSubject("git", args[:pinnedArgs]); so.Subject != want {
				t.Errorf("%v: row %d subject = %q, want %q", args, i, so.Subject, want)
			}
		}
	}
}

func TestBuildScopeOptions_DefaultNeverBroaderThanInferredPrefix(t *testing.T) {
	cases := []struct {
		name    string
		program string
		args    []string
		want    string
	}{
		{"anchor is first arg", "git", []string{"log", "--oneline"}, "git log :*"},
		{"flag value anchor", "prep-open-tasks.sh", []string{"--only", "c175", "--force"}, "prep-open-tasks.sh --only c175 :*"},
		{"path flag then subcommand", "hg", []string{"--cwd", "/repo", "status", "--rev", "tip"}, "hg --cwd /repo status :*"},
		{"no anchor: flags only", "ls", []string{"-la"}, "ls -la"},
		{"no anchor: bare path operand", "ls", []string{"-la", "/tmp"}, "ls -la /tmp"},
		{"no args", "make", nil, "make"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts, defaultIdx := scopeOptionsFor(t, c.program, c.args, "")
			if opts[defaultIdx].Subject != c.want {
				t.Errorf("default subject = %q, want %q", opts[defaultIdx].Subject, c.want)
			}
			if opts[defaultIdx].Kind == ScopeProgram {
				t.Errorf("default row is the confirm-gated Program row: %+v", opts[defaultIdx])
			}
			marked := 0
			for i, so := range opts {
				if strings.HasSuffix(so.Label, scopeRecommendedSuffix) {
					marked++
					if i != defaultIdx {
						t.Errorf("row %d carries the recommended marker but the default is %d", i, defaultIdx)
					}
				}
			}
			if marked != 1 {
				t.Errorf("%d rows carry the recommended marker, want exactly 1 (%+v)", marked, opts)
			}
		})
	}
}

func TestBuildScopeOptions_ExactAndProgramUnchanged(t *testing.T) {
	opts, _ := scopeOptionsFor(t, "git", []string{"log", "--oneline"}, "")

	if opts[0].Subject != "git log --oneline" {
		t.Errorf("exact subject = %q, want %q", opts[0].Subject, "git log --oneline")
	}
	if opts[0].Label != "exact: git log --oneline — only this exact command" {
		t.Errorf("exact label = %q, want the unchanged breadth phrase", opts[0].Label)
	}
	last := opts[len(opts)-1]
	if last.Kind != ScopeProgram || last.Subject != "git :*" {
		t.Errorf("program row = %+v, want subject %q", last, "git :*")
	}
	if last.Label != "program (advanced): git :* — ANY invocation of git (widest)" {
		t.Errorf("program label = %q, want the unchanged breadth phrase", last.Label)
	}
	for _, so := range opts {
		for _, leak := range []string{"—", scopeRecommendedSuffix, "exact:", "prefix:", "advanced", "invocation", "fixed:"} {
			if strings.Contains(so.Subject, leak) {
				t.Errorf("subject %q leaked display copy %q", so.Subject, leak)
			}
		}
	}
}

func TestScopeChooserHelp_StatesPrefixContractOnlyWhenOffered(t *testing.T) {
	withPrefix, _ := scopeOptionsFor(t, "git", []string{"log", "--oneline"}, "")
	help := scopeChooserHelp(withPrefix)
	if !strings.Contains(help, scopePrefixNotice) {
		t.Errorf("help omits the prefix contract when Prefix rows are offered:\n%q", help)
	}
	if !strings.Contains(help, scopeProgramWarning) {
		t.Errorf("help dropped the Program breadth warning:\n%q", help)
	}

	noPrefix, _ := scopeOptionsFor(t, "make", nil, "")
	bare := scopeChooserHelp(noPrefix)
	if strings.Contains(bare, scopePrefixNotice) {
		t.Errorf("help claims a prefix contract with no Prefix row offered:\n%q", bare)
	}
	if !strings.Contains(bare, scopeProgramWarning) {
		t.Errorf("help dropped the Program breadth warning:\n%q", bare)
	}
}

// TestProgramConfirmWarning_DestructivePrependsAdvisory proves the destructive-program confirm
// copy: a destructive program shows the stronger destructive advisory above the
// standard breadth warning (both present), while a benign program shows only the
// standard breadth warning and no destructive copy.
func TestProgramConfirmWarning_DestructivePrependsAdvisory(t *testing.T) {
	destructive := programConfirmWarning(true)
	if !strings.Contains(destructive, scopeDestructiveProgramWarning) {
		t.Errorf("destructive confirm copy missing the stronger destructive advisory:\n%q", destructive)
	}
	if !strings.Contains(destructive, scopeProgramWarning) {
		t.Errorf("destructive confirm copy dropped the standard breadth warning:\n%q", destructive)
	}

	benign := programConfirmWarning(false)
	if benign != scopeProgramWarning {
		t.Errorf("benign confirm copy = %q, want only the standard breadth warning %q", benign, scopeProgramWarning)
	}
	if strings.Contains(benign, "DESTRUCTIVE") {
		t.Errorf("benign confirm copy leaked destructive advisory:\n%q", benign)
	}
}

// TestBuildCompoundStageScopeOptions_TwoStageCompound proves a two-stage simple
// compound of non-destructive programs yields one ordered entry per stage, each
// with Exact/Subcommand/Program rows in narrow → wide order, each defaulting to
// Exact (not Subcommand as the direct-command chooser does), with the recommended
// marker on the Exact row only and the canonical per-stage stored subjects.
func TestBuildCompoundStageScopeOptions_TwoStageCompound(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build"}, {"npm", "test"}},
		Operators: []string{"&&"},
	}
	stages := buildCompoundStageScopeOptions(sc)
	wantCommands := []string{"go build", "npm test"}
	wantKinds := []ScopeKind{ScopeExact, ScopeSubcommand, ScopeProgram}
	if len(stages) != len(wantCommands) {
		t.Fatalf("len(stages) = %d, want %d (%+v)", len(stages), len(wantCommands), stages)
	}
	for si, st := range stages {
		if st.Command != wantCommands[si] {
			t.Errorf("stage %d Command = %q, want %q", si, st.Command, wantCommands[si])
		}
		if st.NoWiden {
			t.Errorf("stage %d NoWiden = true, want false for non-destructive program", si)
		}
		if st.DefaultIdx != 0 {
			t.Errorf("stage %d DefaultIdx = %d, want 0 (Exact)", si, st.DefaultIdx)
		}
		if len(st.Options) != len(wantKinds) {
			t.Fatalf("stage %d: %d rows, want %d (%+v)", si, len(st.Options), len(wantKinds), st.Options)
		}
		for ri, k := range wantKinds {
			if st.Options[ri].Kind != k {
				t.Errorf("stage %d row %d Kind = %d, want %d", si, ri, st.Options[ri].Kind, k)
			}
		}
		// The recommended marker is on the Exact default only; the wider rows lack it.
		if !strings.HasSuffix(st.Options[0].Label, scopeRecommendedSuffix) {
			t.Errorf("stage %d Exact label missing recommended marker: %q", si, st.Options[0].Label)
		}
		if strings.Contains(st.Options[1].Label, scopeRecommendedSuffix) ||
			strings.Contains(st.Options[2].Label, scopeRecommendedSuffix) {
			t.Errorf("stage %d a wider row carries the recommended marker: %+v", si, st.Options)
		}
	}

	if stages[0].Options[0].Subject != "go build" ||
		stages[0].Options[1].Subject != "go build :*" ||
		stages[0].Options[2].Subject != "go :*" {
		t.Errorf("stage 0 subjects = %+v", stages[0].Options)
	}
	if stages[1].Options[0].Subject != "npm test" ||
		stages[1].Options[1].Subject != "npm test :*" ||
		stages[1].Options[2].Subject != "npm :*" {
		t.Errorf("stage 1 subjects = %+v", stages[1].Options)
	}
}

func TestBuildCompoundStageScopeOptions_PrefixSubjectKeepsExactDefault(t *testing.T) {
	stages := buildCompoundStageScopeOptions(permissions.SimpleCompound{
		Stages:    [][]string{{"sed", "-n", "1,28p", "notes.txt"}, {"echo", "done"}},
		Operators: []string{"&&"},
	})
	if len(stages) != 2 {
		t.Fatalf("len(stages) = %d, want 2", len(stages))
	}

	st := stages[0]
	if len(st.Options) < 2 || st.DefaultIdx >= len(st.Options) {
		t.Fatalf("stage 0 rows = %+v (default %d), want at least an Exact and a Subcommand row", st.Options, st.DefaultIdx)
	}
	if st.DefaultIdx != 0 || st.Options[st.DefaultIdx].Kind != ScopeExact {
		t.Errorf("stage 0 default row = %+v, want the Exact row", st.Options[st.DefaultIdx])
	}
	if st.Options[1].Kind != ScopeSubcommand || st.Options[1].Subject != "sed -n 1,28p :*" {
		t.Errorf("stage 0 subcommand row = %+v, want subject %q", st.Options[1], "sed -n 1,28p :*")
	}
	if strings.Contains(st.Options[1].Label, scopeRecommendedSuffix) {
		t.Errorf("stage 0 subcommand row carries the recommended marker: %q", st.Options[1].Label)
	}
}

// TestBuildCompoundStageScopeOptions_DestructiveStageExactOnly proves a destructive
// stage is exact-only with NoWiden set and never exposes a Subcommand or Program
// widening row, while a benign sibling stage in the same compound still widens.
func TestBuildCompoundStageScopeOptions_DestructiveStageExactOnly(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"rm", "-rf", "build"}, {"echo", "done"}},
		Operators: []string{"&&"},
	}
	stages := buildCompoundStageScopeOptions(sc)
	if len(stages) != 2 {
		t.Fatalf("len(stages) = %d, want 2 (%+v)", len(stages), stages)
	}

	destructive := stages[0]
	if !destructive.NoWiden {
		t.Errorf("destructive stage NoWiden = false, want true")
	}
	if len(destructive.Options) != 1 {
		t.Fatalf("destructive stage offered %d rows, want exact-only: %+v", len(destructive.Options), destructive.Options)
	}
	if destructive.Options[0].Kind != ScopeExact {
		t.Errorf("destructive stage row kind = %d, want Exact", destructive.Options[0].Kind)
	}
	if destructive.Options[0].Subject != "rm -rf build" {
		t.Errorf("destructive stage exact subject = %q, want %q", destructive.Options[0].Subject, "rm -rf build")
	}
	for _, o := range destructive.Options {
		if o.Kind == ScopeSubcommand || o.Kind == ScopeProgram {
			t.Errorf("destructive stage exposed a widening row: %+v", o)
		}
	}

	benign := stages[1]
	if benign.NoWiden {
		t.Errorf("benign stage NoWiden = true, want false")
	}
	hasProgram := false
	for _, o := range benign.Options {
		if o.Kind == ScopeProgram {
			hasProgram = true
		}
	}
	if !hasProgram {
		t.Errorf("benign stage missing its Program widening row: %+v", benign.Options)
	}

	// Every program the backend classifies destructive is exact-only/no-widen.
	for _, prog := range []string{"rm", "rmdir", "hg", "git"} {
		st := buildCompoundStageScopeOptions(permissions.SimpleCompound{
			Stages:    [][]string{{prog, "x"}, {"echo", "ok"}},
			Operators: []string{"&&"},
		})
		if len(st) == 0 {
			t.Fatalf("%s compound produced no stages", prog)
		}
		if !st[0].NoWiden || len(st[0].Options) != 1 || st[0].Options[0].Kind != ScopeExact {
			t.Errorf("%s stage not exact-only/no-widen: %+v", prog, st[0])
		}
	}
}

// TestBuildCompoundStageScopeOptions_NoStages proves a nil/empty (non-simple) or
// malformed compound yields no stage options, leaving byte-exact literal prompting
// to the later production flow.
func TestBuildCompoundStageScopeOptions_NoStages(t *testing.T) {
	cases := []struct {
		name string
		sc   permissions.SimpleCompound
	}{
		{"zero value", permissions.SimpleCompound{}},
		{"nil stages", permissions.SimpleCompound{Stages: nil}},
		{"empty stages", permissions.SimpleCompound{Stages: [][]string{}}},
		{"empty stage token list", permissions.SimpleCompound{Stages: [][]string{{"go", "build"}, {}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildCompoundStageScopeOptions(c.sc); got != nil {
				t.Errorf("got %d stage options, want nil", len(got))
			}
		})
	}
}

func TestBuildCompoundStageScopeOptions_NoDirectPrefixRows(t *testing.T) {
	stages := buildCompoundStageScopeOptions(permissions.SimpleCompound{
		Stages:    [][]string{{"prep-open-tasks.sh", "--only", "c175", "--force"}, {"rm", "-rf", "build"}},
		Operators: []string{"&&"},
	})
	if len(stages) != 2 {
		t.Fatalf("len(stages) = %d, want 2", len(stages))
	}

	widenable := stages[0]
	wantKinds := []ScopeKind{ScopeExact, ScopeSubcommand, ScopeProgram}
	if len(widenable.Options) != len(wantKinds) {
		t.Fatalf("stage 0 offered %d rows, want the unchanged %d-rung ladder: %+v", len(widenable.Options), len(wantKinds), widenable.Options)
	}
	for i, k := range wantKinds {
		if widenable.Options[i].Kind != k {
			t.Errorf("stage 0 row %d Kind = %d, want %d", i, widenable.Options[i].Kind, k)
		}
	}
	if widenable.DefaultIdx != 0 {
		t.Errorf("stage 0 DefaultIdx = %d, want 0 (Exact)", widenable.DefaultIdx)
	}

	destructive := stages[1]
	if !destructive.NoWiden || len(destructive.Options) != 1 || destructive.Options[0].Kind != ScopeExact {
		t.Errorf("destructive stage lost its exact-only no-widen rule: %+v", destructive)
	}

	for si, st := range stages {
		for ri, so := range st.Options {
			if so.Kind == ScopePrefix {
				t.Errorf("stage %d row %d is a direct-only Prefix row: %+v", si, ri, so)
			}
			if strings.Contains(so.Label, "prefix:") {
				t.Errorf("stage %d row %d carries direct-only Prefix copy: %q", si, ri, so.Label)
			}
		}
	}
}

// TestBuildCompoundStageScopeOptions_LabelSubjectSeparation proves the per-stage
// rows keep display copy out of the stored subject: Subject is always a canonical
// direct-command subject string, while the breadth phrase and recommended marker
// live only in Label.
func TestBuildCompoundStageScopeOptions_LabelSubjectSeparation(t *testing.T) {
	sc := permissions.SimpleCompound{
		Stages:    [][]string{{"go", "build"}, {"npm", "test"}},
		Operators: []string{"&&"},
	}
	stages := buildCompoundStageScopeOptions(sc)
	wantSubjects := [][]string{
		{"go build", "go build :*", "go :*"},
		{"npm test", "npm test :*", "npm :*"},
	}
	if len(stages) != len(wantSubjects) {
		t.Fatalf("len(stages) = %d, want %d", len(stages), len(wantSubjects))
	}
	for si, st := range stages {
		if len(st.Options) != len(wantSubjects[si]) {
			t.Fatalf("stage %d: %d rows, want %d", si, len(st.Options), len(wantSubjects[si]))
		}
		for ri, o := range st.Options {
			if o.Subject != wantSubjects[si][ri] {
				t.Errorf("stage %d row %d Subject = %q, want %q", si, ri, o.Subject, wantSubjects[si][ri])
			}
			// Display copy (breadth phrase, row prefix, recommended marker) must
			// never appear in a stored subject string.
			for _, leak := range []string{"—", scopeRecommendedSuffix, "exact:", "subcommand:", "advanced", "invocation"} {
				if strings.Contains(o.Subject, leak) {
					t.Errorf("stage %d row %d Subject = %q leaked display copy %q", si, ri, o.Subject, leak)
				}
			}
		}
		def := st.Options[st.DefaultIdx]
		if !strings.Contains(def.Label, scopeRecommendedSuffix) {
			t.Errorf("stage %d default label missing recommended marker: %q", si, def.Label)
		}
		if strings.Contains(def.Subject, scopeRecommendedSuffix) {
			t.Errorf("stage %d default subject leaked recommended marker: %q", si, def.Subject)
		}
	}
}

// containmentTree lays home and a scratch directory out as siblings, so the walk up from a
// path under the scratch directory stops at home's parent.
type containmentTree struct {
	home  string
	tmp   string
	run   string
	entry string
}

func newContainmentTree(t *testing.T) containmentTree {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	tree := containmentTree{home: filepath.Join(root, "home", "user"), tmp: filepath.Join(root, "tmp")}
	tree.run = filepath.Join(tree.tmp, "codemeld-g2430-audit.RtAY58")
	tree.entry = filepath.Join(tree.run, "id-ssh")
	if err := os.MkdirAll(tree.home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(tree.run, 0o755); err != nil {
		t.Fatalf("mkdir run: %v", err)
	}
	if err := os.WriteFile(tree.entry, nil, 0o644); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	return tree
}

func TestBuildScopeOptions_PathRowLabelPlacementAndRecommendation(t *testing.T) {
	tree := newContainmentTree(t)
	opts, defaultIdx := scopeOptionsFor(t, "chmod", []string{"+x", tree.entry}, tree.home)

	wantKinds := []ScopeKind{ScopeExact, ScopePrefix, ScopePath, ScopePrefix, ScopeProgram}
	if len(opts) != len(wantKinds) {
		t.Fatalf("len(opts) = %d, want %d (%+v)", len(opts), len(wantKinds), opts)
	}
	for i, want := range wantKinds {
		if opts[i].Kind != want {
			t.Errorf("opts[%d].Kind = %d, want %d", i, opts[i].Kind, want)
		}
	}
	if defaultIdx != 2 {
		t.Fatalf("defaultIdx = %d, want the path row", defaultIdx)
	}
	if opts[1].Subject != "chmod +x "+tree.entry+" :*" {
		t.Errorf("row above the path row = %q, want the Prefix that still pins the path", opts[1].Subject)
	}
	if opts[3].Subject != "chmod +x :*" {
		t.Errorf("row below the path row = %q, want the Prefix that wildcards the path", opts[3].Subject)
	}

	want := "path: chmod +x :under=" + tree.run + " — chmod +x against any path resolving under " + tree.run +
		", checked when permission is decided (← → adjust)" + scopeRecommendedSuffix
	if opts[2].Label != want {
		t.Errorf("path label = %q, want %q", opts[2].Label, want)
	}
	if !strings.HasPrefix(opts[2].Subject, "'direct-under/v1 ") {
		t.Errorf("path subject = %q, want the opaque versioned envelope", opts[2].Subject)
	}
	if strings.Contains(opts[2].Label, "'direct-under/v1 ") {
		t.Errorf("path label %q rendered the stored envelope", opts[2].Label)
	}
	for _, leak := range []string{"—", scopeRecommendedSuffix, "path:", "adjust", "checked when"} {
		if strings.Contains(opts[2].Subject, leak) {
			t.Errorf("path subject %q leaked display copy %q", opts[2].Subject, leak)
		}
	}
	marked := 0
	for i, so := range opts {
		if strings.HasSuffix(so.Label, scopeRecommendedSuffix) {
			marked++
			if i != defaultIdx {
				t.Errorf("row %d carries the recommended marker but the default is %d", i, defaultIdx)
			}
		}
	}
	if marked != 1 {
		t.Errorf("%d rows carry the recommended marker, want exactly 1", marked)
	}
}

func TestBuildScopeOptions_PathRowWildcardsATailAndKeepsOtherRows(t *testing.T) {
	tree := newContainmentTree(t)
	repo := filepath.Join(tree.run, "subprobe", "sub")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	args := []string{"-C", repo, "add", "a"}
	opts, defaultIdx := scopeOptionsFor(t, "git", args, tree.home)
	if defaultIdx != 4 || opts[4].Kind != ScopePath {
		t.Fatalf("defaultIdx = %d (kind %d), want the path row at 4", defaultIdx, opts[defaultIdx].Kind)
	}
	if !strings.Contains(opts[4].Label, "any later arguments may vary") {
		t.Errorf("path label = %q, want the tail-wildcard phrase", opts[4].Label)
	}
	if !strings.Contains(opts[4].Label, ":under="+filepath.Join(tree.run, "subprobe")+" :*") {
		t.Errorf("path label = %q, want the readable sentinel with its terminal wildcard", opts[4].Label)
	}

	plain, plainDefault := scopeOptionsFor(t, "git", args, "")
	if len(plain) != len(opts)-1 {
		t.Fatalf("ladder without a path row has %d rows, want %d", len(plain), len(opts)-1)
	}
	for i, so := range plain {
		other := i
		if i >= 4 {
			other = i + 1
		}
		if so.Kind != opts[other].Kind || so.Subject != opts[other].Subject {
			t.Errorf("row %d = %+v, want the unchanged %+v", i, opts[other], so)
		}
	}
	if plainDefault != 2 || plain[plainDefault].Kind != ScopePrefix {
		t.Errorf("default without a path row = %d (kind %d), want the previously recommended prefix", plainDefault, plain[plainDefault].Kind)
	}
}

func TestScopeChooserHelp_DescribesTheBoundaryAsAnAuthorizationCheck(t *testing.T) {
	tree := newContainmentTree(t)
	withPath, _ := scopeOptionsFor(t, "chmod", []string{"+x", tree.entry}, tree.home)
	help := scopeChooserHelp(withPath)
	for _, want := range []string{scopePathNotice, scopePrefixNotice, scopeProgramWarning} {
		if !strings.Contains(help, want) {
			t.Errorf("help missing %q:\n%s", want, help)
		}
	}
	if !strings.Contains(help, "checked against that boundary at the moment permission is decided") {
		t.Errorf("help does not say when the path is checked:\n%s", help)
	}
	if !strings.Contains(help, "not an execution-time sandbox") {
		t.Errorf("help does not disclaim execution-time confinement:\n%s", help)
	}
	for _, banned := range []string{"confines what", "cannot escape", "prevents the program", "restricted to"} {
		if strings.Contains(strings.ToLower(help), banned) {
			t.Errorf("help promises execution-time confinement (%q):\n%s", banned, help)
		}
	}

	withoutPath, _ := scopeOptionsFor(t, "chmod", []string{"+x", tree.entry}, "")
	if got := scopeChooserHelp(withoutPath); strings.Contains(got, scopePathNotice) {
		t.Errorf("help states the path notice with no path row:\n%s", got)
	}
}

func TestScopeChooser_AdjustWalksTheBoundaryAndKeepsTheMarker(t *testing.T) {
	tree := newContainmentTree(t)
	sc, ok := buildScopeChooserRows("chmod", []string{"+x", tree.entry}, tree.home)
	if !ok {
		t.Fatal("buildScopeChooserRows = !ok")
	}
	if sc.pathRow != 2 {
		t.Fatalf("pathRow = %d, want 2", sc.pathRow)
	}
	if _, ok := sc.adjust(-1); ok {
		t.Error("adjust walked below the immediate parent")
	}
	label, ok := sc.adjust(1)
	if !ok {
		t.Fatal("adjust(1) = !ok")
	}
	if !strings.Contains(label, ":under="+tree.tmp+" ") {
		t.Errorf("adjusted label = %q, want the widened boundary %q", label, tree.tmp)
	}
	if !strings.HasSuffix(label, scopeRecommendedSuffix) {
		t.Errorf("adjusted label = %q, want the recommended marker kept", label)
	}
	if sc.options[sc.pathRow].Label != label {
		t.Errorf("row not re-rendered in place: %q", sc.options[sc.pathRow].Label)
	}
	sibling := filepath.Join(tree.tmp, "other", "id")
	if err := os.MkdirAll(filepath.Dir(sibling), 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	if err := os.WriteFile(sibling, nil, 0o644); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	if !permissions.MatchesDirectSubject([]string{"chmod", "+x", sibling}, nil, false, sc.options[sc.pathRow].Subject) {
		t.Error("the widened subject does not authorize a sibling path under the boundary")
	}
	if _, ok := sc.adjust(1); ok {
		t.Error("adjust walked past the widest selectable boundary")
	}

	none, ok := buildScopeChooserRows("git", []string{"log"}, tree.home)
	if !ok {
		t.Fatal("buildScopeChooserRows = !ok")
	}
	if none.pathRow != -1 {
		t.Fatalf("pathRow = %d for a command with no path argument", none.pathRow)
	}
	if _, ok := none.adjust(1); ok {
		t.Error("adjust reported a change with no path row")
	}
}

func scopeOptionsFor(t *testing.T, program string, args []string, home string) (opts []scopeOption, defaultIdx int) {
	t.Helper()
	sc, ok := buildScopeChooserRows(program, args, home)
	if !ok {
		return nil, 0
	}
	return sc.options, sc.defaultIdx
}
