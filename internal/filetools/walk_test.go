// Unit tests for the shared directory walker: deterministic depth-first ordering, file/dir/symlink
// classification with directory-symlink no-follow, hidden-entry filtering and the include_hidden override,
// the pluggable ignore-filter seam (skip, subtree pruning, include_ignored disable, project-relative
// matcher input), limit/truncation, depth capping, and read-error propagation.
package filetools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

func TestWalk_BlockedEntriesLeftOut(t *testing.T) {
	root := eval(t, t.TempDir())
	mkdir(t, filepath.Join(root, "secrets"))
	writeFile(t, filepath.Join(root, "secrets", "token.txt"), "TOKEN")
	mkdir(t, filepath.Join(root, "a"))
	writeFile(t, filepath.Join(root, "a", "key.pem"), "x")
	writeFile(t, filepath.Join(root, "a", "notes.txt"), "x")
	writeFile(t, filepath.Join(root, "b.txt"), "x")
	mkdir(t, filepath.Join(root, ".vault"))
	blocked := permissions.NewBlockedPaths(eval(t, t.TempDir()), []permissions.BlockedEntry{
		{Path: filepath.Join(root, "secrets"), Source: "test"},
		{Path: filepath.Join(root, "a", "key.pem"), Source: "test"},
		{Path: filepath.Join(root, ".vault"), Source: "test"},
	})

	walk := func(opts WalkOptions) ([]string, []string) {
		t.Helper()
		var reported []string
		opts.Blocked = blocked
		opts.OnBlocked = func(p string) { reported = append(reported, p) }
		entries, _, err := Walk(opts)
		if err != nil {
			t.Fatalf("Walk error = %v, want nil", err)
		}
		return relPaths(entries), reported
	}

	t.Run("left out whatever include_ignored and include_hidden say", func(t *testing.T) {
		got, reported := walk(WalkOptions{Root: root, ProjectRoot: root, IncludeIgnored: true, IncludeHidden: true})
		if want := []string{"a", "a/notes.txt", "b.txt"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("entries = %v, want %v", got, want)
		}
		want := []string{filepath.Join(root, ".vault"), filepath.Join(root, "a", "key.pem"), filepath.Join(root, "secrets")}
		if !reflect.DeepEqual(reported, want) {
			t.Fatalf("OnBlocked = %v, want %v", reported, want)
		}
	})

	t.Run("a hidden entry the hidden rule drops is not reported", func(t *testing.T) {
		_, reported := walk(WalkOptions{Root: root, ProjectRoot: root})
		want := []string{filepath.Join(root, "a", "key.pem"), filepath.Join(root, "secrets")}
		if !reflect.DeepEqual(reported, want) {
			t.Fatalf("OnBlocked = %v, want %v", reported, want)
		}
	})

	t.Run("a blocked root emits nothing and is reported", func(t *testing.T) {
		secrets := filepath.Join(root, "secrets")
		got, reported := walk(WalkOptions{Root: secrets, ProjectRoot: root, IncludeIgnored: true})
		if len(got) != 0 {
			t.Fatalf("entries = %v, want none", got)
		}
		if want := []string{secrets}; !reflect.DeepEqual(reported, want) {
			t.Fatalf("OnBlocked = %v, want %v", reported, want)
		}
	})
}

func TestWalk_OneBlockedListPerWalk(t *testing.T) {
	root := eval(t, t.TempDir())
	writeFile(t, filepath.Join(root, "a.txt"), "x")
	mkdir(t, filepath.Join(root, "b"))
	writeFile(t, filepath.Join(root, "b", "c.txt"), "x")
	calls := 0
	blocked := permissions.NewLiveBlockedPaths(eval(t, t.TempDir()), "", nil, func() permissions.BlockedReload {
		calls++
		if calls == 1 {
			return permissions.BlockedReload{}
		}
		return permissions.BlockedReload{Changed: true, Entries: []permissions.BlockedEntry{{Path: filepath.Join(root, "b"), Source: "test"}}}
	})

	for i, want := range [][]string{{"a.txt", "b", "b/c.txt"}, {"a.txt"}} {
		entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, Blocked: blocked})
		if err != nil {
			t.Fatalf("walk %d: Walk error = %v", i+1, err)
		}
		if got := relPaths(entries); !reflect.DeepEqual(got, want) {
			t.Fatalf("walk %d: entries = %v, want %v", i+1, got, want)
		}
		if calls != i+1 {
			t.Fatalf("walk %d: reload calls = %d, want %d", i+1, calls, i+1)
		}
	}
}

func TestWithLeftOut(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	outside := filepath.Join(filepath.Dir(home), "elsewhere")

	if res := withLeftOut(tools.Result{}, nil, project, home, false, 1<<20); res.Stderr != nil {
		t.Fatalf("Stderr = %q, want nil when nothing was left out", res.Stderr)
	}

	leftOut := []string{filepath.Join(project, "secrets"), filepath.Join(home, ".ssh"), outside}
	for i := 0; i < 20; i++ {
		leftOut = append(leftOut, filepath.Join(project, "f", strconv.Itoa(i)))
	}
	wantNames := []string{"secrets", "~/.ssh", outside}
	for i := 0; i < 17; i++ {
		wantNames = append(wantNames, "f/"+strconv.Itoa(i))
	}
	want := "meta\nleft out (blocked): " + strings.Join(wantNames, ", ") + " and 3 more\n"

	res := withLeftOut(tools.Result{Stderr: []byte("meta\n")}, leftOut, project, home, false, 1<<20)
	if string(res.Stderr) != want {
		t.Fatalf("Stderr =\n%q\nwant\n%q", res.Stderr, want)
	}

	upperProject, upperHome := strings.ToUpper(project), strings.ToUpper(home)
	variants := []string{upperProject, filepath.Join(upperProject, "secrets"), upperHome, filepath.Join(upperHome, ".ssh", "id_rsa")}
	folded := withLeftOut(tools.Result{}, variants, project, home, true, 1<<20)
	if want := "left out (blocked): ., secrets, ~, ~/.ssh/id_rsa\n"; string(folded.Stderr) != want {
		t.Fatalf("folded Stderr = %q, want %q", folded.Stderr, want)
	}
	exact := withLeftOut(tools.Result{}, variants[1:2], project, home, false, 1<<20)
	if want := "left out (blocked): " + variants[1] + "\n"; string(exact.Stderr) != want {
		t.Fatalf("case-sensitive Stderr = %q, want %q", exact.Stderr, want)
	}

	physicalHome := eval(t, t.TempDir())
	linkedHome := filepath.Join(eval(t, t.TempDir()), "home")
	symlink(t, physicalHome, linkedHome)
	linked := withLeftOut(tools.Result{}, []string{filepath.Join(physicalHome, ".ssh")}, project, linkedHome, false, 1<<20)
	if want := "left out (blocked): ~/.ssh\n"; string(linked.Stderr) != want {
		t.Fatalf("symlinked home Stderr = %q, want %q", linked.Stderr, want)
	}

	newline := withLeftOut(tools.Result{}, []string{filepath.Join(project, "a\nb")}, project, home, false, 1<<20)
	if want := "left out (blocked): \"a\\nb\"\n"; string(newline.Stderr) != want {
		t.Fatalf("newline path Stderr = %q, want %q", newline.Stderr, want)
	}
}

func TestWithLeftOut_OutputCap(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	const outputCap = 256

	failed := failResult("glob target rejected: cannot traverse the search path: open " + strings.Repeat("x", 400) + ": permission denied")
	res := withLeftOut(failed, []string{filepath.Join(project, "secrets")}, project, home, false, outputCap)
	_, stderr := events.BuildModelInputBytes(res.Stdout, res.Stderr, outputCap)
	if got := string(stderr); !strings.HasPrefix(got, "glob target rejected: ") || !strings.HasSuffix(got, "\nleft out (blocked): secrets\n") {
		t.Fatalf("model stderr = %q, want the traversal error followed by the complete left-out line", got)
	}

	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, filepath.Join(project, strings.Repeat("d", 40), strconv.Itoa(i)))
	}
	res = withLeftOut(tools.Result{Stderr: []byte("meta\n")}, many, project, home, false, outputCap)
	_, stderr = events.BuildModelInputBytes(nil, res.Stderr, outputCap)
	if got := string(stderr); got != string(res.Stderr) || !strings.HasPrefix(got, "meta\nleft out (blocked): ") || !strings.HasSuffix(got, " more\n") {
		t.Fatalf("model stderr = %q from %q, want meta and a complete shortened left-out line", got, res.Stderr)
	}

	long := filepath.Join(filepath.Dir(home), strings.Repeat("y", 300))
	res = withLeftOut(tools.Result{}, []string{long}, project, home, false, outputCap)
	if want := "left out (blocked): 1 (paths too long to show)\n"; string(res.Stderr) != want {
		t.Fatalf("Stderr = %q, want %q", res.Stderr, want)
	}
}

func TestWalkTools_TraversalErrorKeepsLeftOut(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the test user cannot read")
	}
	root := eval(t, t.TempDir())
	mkdir(t, filepath.Join(root, "a-secrets"))
	writeFile(t, filepath.Join(root, "a-secrets", "token.txt"), "TOKEN")
	locked := filepath.Join(root, "b-locked")
	mkdir(t, filepath.Join(locked, "inner"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	blocked := permissions.NewBlockedPaths(eval(t, t.TempDir()), []permissions.BlockedEntry{{Path: filepath.Join(root, "a-secrets"), Source: "test"}})
	home := eval(t, t.TempDir())

	glob, grep := NewGlobTool(home, root, root, 1<<20), NewGrepTool(home, root, root, 1<<20)
	tree, count := NewTreeTool(home, root, root, 1<<20), NewFileCountTool(home, root, root, 1<<20)
	glob.SetBlockedPaths(blocked)
	grep.SetBlockedPaths(blocked)
	tree.SetBlockedPaths(blocked)
	count.SetBlockedPaths(blocked)

	for name, c := range map[string]struct {
		tool tools.Tool
		args map[string]any
	}{
		GlobToolName:      {glob, map[string]any{"pattern": "**", "include_ignored": true}},
		GrepToolName:      {grep, map[string]any{"pattern": "TOKEN", "include_ignored": true}},
		TreeToolName:      {tree, map[string]any{"include_ignored": true}},
		FileCountToolName: {count, map[string]any{"include_ignored": true}},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := c.tool.Invoke(context.Background(), c.args)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			stderr := string(res.Stderr)
			if res.ExitCode == 0 || !strings.Contains(stderr, "b-locked") {
				t.Fatalf("result = exit %d, stderr %q; want the traversal error for b-locked", res.ExitCode, stderr)
			}
			if !strings.HasSuffix(stderr, "\nleft out (blocked): a-secrets\n") {
				t.Fatalf("stderr = %q, want the left-out line after the traversal error", stderr)
			}
		})
	}
}

func collectContext(t *testing.T, ctx context.Context, opts WalkOptions) []WalkEntry {
	t.Helper()
	var got []WalkEntry
	if err := WalkContext(ctx, opts, func(e WalkEntry) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("WalkContext error = %v, want nil", err)
	}
	return got
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", path, err)
	}
}

// triple is the observable shape of an emitted entry the ordering/classification tests assert on.
type triple struct {
	rel   string
	kind  EntryKind
	depth int
}

func triples(es []WalkEntry) []triple {
	out := make([]triple, len(es))
	for i, e := range es {
		out[i] = triple{e.RelPath, e.Kind, e.Depth}
	}
	return out
}

func relPaths(es []WalkEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.RelPath
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// recordingMatcher skips the relPaths flagged in skip and records every relPath it is consulted with, so a
// test can prove a pruned directory's children were never enumerated (the matcher ran before descent).
type recordingMatcher struct {
	skip map[string]bool
	seen []string
}

func (m *recordingMatcher) ShouldSkip(rel string, kind EntryKind) bool {
	m.seen = append(m.seen, rel)
	return m.skip[rel]
}

// kindMatcher skips every entry of a given kind, exercising that the walker passes the entry type into a
// matcher.
type kindMatcher struct{ skipKind EntryKind }

func (m kindMatcher) ShouldSkip(_ string, kind EntryKind) bool { return kind == m.skipKind }

type cancellingMatcher struct {
	cancel context.CancelFunc
	calls  int
	skip   bool
}

func (m *cancellingMatcher) ShouldSkip(string, EntryKind) bool {
	m.calls++
	if m.calls == 1 {
		m.cancel()
	}
	return m.skip
}

// buildMainTree lays out the fixture the ordering/hidden/symlink/limit tests share:
//
//	.dotfile            (hidden file)
//	.hidden/secret.txt  (hidden dir + child)
//	a.txt
//	b/{b1.txt,b2.txt}
//	c.txt
//	realdir/{.deep.txt, inner.txt}
//	linkdir -> realdir  (directory symlink)
func buildMainTree(t *testing.T) string {
	t.Helper()
	root := eval(t, t.TempDir())
	writeFile(t, filepath.Join(root, ".dotfile"), "x")
	mkdir(t, filepath.Join(root, ".hidden"))
	writeFile(t, filepath.Join(root, ".hidden", "secret.txt"), "x")
	writeFile(t, filepath.Join(root, "a.txt"), "x")
	mkdir(t, filepath.Join(root, "b"))
	writeFile(t, filepath.Join(root, "b", "b1.txt"), "x")
	writeFile(t, filepath.Join(root, "b", "b2.txt"), "x")
	writeFile(t, filepath.Join(root, "c.txt"), "x")
	mkdir(t, filepath.Join(root, "realdir"))
	writeFile(t, filepath.Join(root, "realdir", ".deep.txt"), "x")
	writeFile(t, filepath.Join(root, "realdir", "inner.txt"), "x")
	symlink(t, filepath.Join(root, "realdir"), filepath.Join(root, "linkdir"))
	return root
}

// TestWalk_OrderClassificationHiddenDefault pins Done-when 1, 2, and 4 together: depth-first ascending
// order, file/dir/symlink classification, a directory symlink reported as a symlink and never descended
// (no linkdir/* descendants), and hidden dot-entries skipped by default (no .dotfile/.hidden subtree).
func TestWalk_OrderClassificationHiddenDefault(t *testing.T) {
	root := buildMainTree(t)

	entries, truncated, err := Walk(WalkOptions{Root: root, ProjectRoot: root})
	if err != nil {
		t.Fatalf("Walk error = %v, want nil", err)
	}
	if truncated {
		t.Fatalf("truncated = true, want false (no limit set)")
	}
	want := []triple{
		{"a.txt", EntryFile, 1},
		{"b", EntryDir, 1},
		{"b/b1.txt", EntryFile, 2},
		{"b/b2.txt", EntryFile, 2},
		{"c.txt", EntryFile, 1},
		{"linkdir", EntrySymlink, 1},
		{"realdir", EntryDir, 1},
		{"realdir/inner.txt", EntryFile, 2},
	}
	if got := triples(entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries =\n%v\nwant\n%v", got, want)
	}
}

// TestWalk_DirectorySymlinkNotFollowed pins Done-when 1 directly, including the architecture
// review's fixture: even with hidden filtering disabled — which would otherwise surface realdir/.deep.txt
// through the link — the walker never descends linkdir, so no linkdir/* entry appears.
func TestWalk_DirectorySymlinkNotFollowed(t *testing.T) {
	root := buildMainTree(t)

	entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, IncludeHidden: true})
	if err != nil {
		t.Fatalf("Walk error = %v, want nil", err)
	}

	var linkKind EntryKind
	for _, e := range entries {
		if e.RelPath == "linkdir" {
			linkKind = e.Kind
		}
		if strings.HasPrefix(e.RelPath, "linkdir/") {
			t.Fatalf("walked into directory symlink: found descendant %q (req 35)", e.RelPath)
		}
	}
	if linkKind != EntrySymlink {
		t.Fatalf("linkdir kind = %q, want %q (a directory symlink is classified as a symlink, req 35)", linkKind, EntrySymlink)
	}
}

// TestWalk_IncludeHidden pins Done-when 2: include_hidden surfaces dot-prefixed files and descends hidden
// directories, while the symlink is still not followed.
func TestWalk_IncludeHidden(t *testing.T) {
	root := buildMainTree(t)

	entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, IncludeHidden: true})
	if err != nil {
		t.Fatalf("Walk error = %v, want nil", err)
	}
	want := []triple{
		{".dotfile", EntryFile, 1},
		{".hidden", EntryDir, 1},
		{".hidden/secret.txt", EntryFile, 2},
		{"a.txt", EntryFile, 1},
		{"b", EntryDir, 1},
		{"b/b1.txt", EntryFile, 2},
		{"b/b2.txt", EntryFile, 2},
		{"c.txt", EntryFile, 1},
		{"linkdir", EntrySymlink, 1},
		{"realdir", EntryDir, 1},
		{"realdir/.deep.txt", EntryFile, 2},
		{"realdir/inner.txt", EntryFile, 2},
	}
	if got := triples(entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries =\n%v\nwant\n%v", got, want)
	}
}

// TestWalk_OrderIsComponentwise pins Done-when 4's ordering semantics precisely: the order is depth-first
// pre-order with siblings ascending by name, NOT a byte-sort of the slash-joined paths. A byte-sort would
// place "b.txt" before "b/a.txt" because '.' (0x2e) < '/' (0x2f); the hierarchical order the tree tool
// needs places the whole "b" subtree first.
func TestWalk_OrderIsComponentwise(t *testing.T) {
	root := eval(t, t.TempDir())
	mkdir(t, filepath.Join(root, "b"))
	writeFile(t, filepath.Join(root, "b", "a.txt"), "x")
	writeFile(t, filepath.Join(root, "b.txt"), "x")

	entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root})
	if err != nil {
		t.Fatalf("Walk error = %v, want nil", err)
	}
	want := []string{"b", "b/a.txt", "b.txt"}
	if got := relPaths(entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v (depth-first, not byte-lexicographic)", got, want)
	}
}

// TestWalk_LimitTruncation pins Done-when 4's bound: at most Limit entries are emitted, in order, with
// truncated=true only when at least one more entry was withheld. Limit==total and Limit>total
// and Limit<=0 (unbounded) report truncated=false.
func TestWalk_LimitTruncation(t *testing.T) {
	root := buildMainTree(t)
	const total = 8 // entries emitted by the default (hidden-off) walk of buildMainTree

	t.Run("limit below total truncates", func(t *testing.T) {
		entries, truncated, err := Walk(WalkOptions{Root: root, ProjectRoot: root, Limit: 3})
		if err != nil {
			t.Fatalf("Walk error = %v, want nil", err)
		}
		if !truncated {
			t.Fatalf("truncated = false, want true (limit 3 < %d entries)", total)
		}
		want := []triple{
			{"a.txt", EntryFile, 1},
			{"b", EntryDir, 1},
			{"b/b1.txt", EntryFile, 2},
		}
		if got := triples(entries); !reflect.DeepEqual(got, want) {
			t.Fatalf("entries =\n%v\nwant\n%v", got, want)
		}
	})

	for _, tc := range []struct {
		name  string
		limit int
	}{
		{"limit equals total", total},
		{"limit above total", total + 12},
		{"limit zero is unbounded", 0},
		{"limit negative is unbounded", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, truncated, err := Walk(WalkOptions{Root: root, ProjectRoot: root, Limit: tc.limit})
			if err != nil {
				t.Fatalf("Walk error = %v, want nil", err)
			}
			if truncated {
				t.Fatalf("truncated = true, want false (limit %d, %d entries)", tc.limit, total)
			}
			if len(entries) != total {
				t.Fatalf("len(entries) = %d, want %d", len(entries), total)
			}
		})
	}
}

// TestWalk_MaxDepth checks the depth cap that lets the non-recursive list tool share the walker: MaxDepth 1
// emits only immediate children (directories included but not descended).
func TestWalk_MaxDepth(t *testing.T) {
	root := buildMainTree(t)

	entries, truncated, err := Walk(WalkOptions{Root: root, ProjectRoot: root, MaxDepth: 1})
	if err != nil {
		t.Fatalf("Walk error = %v, want nil", err)
	}
	if truncated {
		t.Fatalf("truncated = true, want false")
	}
	want := []triple{
		{"a.txt", EntryFile, 1},
		{"b", EntryDir, 1},
		{"c.txt", EntryFile, 1},
		{"linkdir", EntrySymlink, 1},
		{"realdir", EntryDir, 1},
	}
	if got := triples(entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries =\n%v\nwant\n%v", got, want)
	}
}

// TestWalk_IgnoreSeam pins Done-when 3: the ordered matcher set is empty (a no-op) by default, sees each
// entry's project-relative path and type before emit/descent, can drop an entry, can prune a directory
// subtree (so its children are never enumerated), and is disabled entirely by include_ignored.
func TestWalk_IgnoreSeam(t *testing.T) {
	root := buildMainTree(t)

	t.Run("empty set is a no-op even with include_ignored", func(t *testing.T) {
		entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, IncludeIgnored: true})
		if err != nil {
			t.Fatalf("Walk error = %v, want nil", err)
		}
		if len(entries) != 8 {
			t.Fatalf("len(entries) = %d, want 8 (no matchers registered: include_ignored is a no-op)", len(entries))
		}
	})

	t.Run("matcher drops a single file", func(t *testing.T) {
		m := &recordingMatcher{skip: map[string]bool{"c.txt": true}}
		entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, Ignore: []IgnoreMatcher{m}})
		if err != nil {
			t.Fatalf("Walk error = %v, want nil", err)
		}
		got := relPaths(entries)
		if contains(got, "c.txt") {
			t.Fatalf("c.txt present, want it dropped by the matcher; got %v", got)
		}
		if !contains(got, "a.txt") || !contains(got, "b/b1.txt") {
			t.Fatalf("matcher dropped more than c.txt; got %v", got)
		}
		if !contains(m.seen, "c.txt") {
			t.Fatalf("matcher was not consulted for c.txt; seen %v", m.seen)
		}
	})

	t.Run("matcher prunes a directory subtree before descent", func(t *testing.T) {
		m := &recordingMatcher{skip: map[string]bool{"b": true}}
		entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, Ignore: []IgnoreMatcher{m}})
		if err != nil {
			t.Fatalf("Walk error = %v, want nil", err)
		}
		for _, rel := range relPaths(entries) {
			if rel == "b" || strings.HasPrefix(rel, "b/") {
				t.Fatalf("pruned directory subtree leaked entry %q", rel)
			}
		}
		if !contains(m.seen, "b") {
			t.Fatalf("matcher was not consulted for directory b; seen %v", m.seen)
		}
		if contains(m.seen, "b/b1.txt") {
			t.Fatalf("matcher saw b/b1.txt, so the walker descended a pruned directory; seen %v", m.seen)
		}
	})

	t.Run("include_ignored disables the matchers", func(t *testing.T) {
		m := &recordingMatcher{skip: map[string]bool{"b": true}}
		entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, IncludeIgnored: true, Ignore: []IgnoreMatcher{m}})
		if err != nil {
			t.Fatalf("Walk error = %v, want nil", err)
		}
		got := relPaths(entries)
		if !contains(got, "b") || !contains(got, "b/b1.txt") {
			t.Fatalf("include_ignored did not re-include the skipped subtree; got %v", got)
		}
		if len(m.seen) != 0 {
			t.Fatalf("matcher consulted despite include_ignored; seen %v", m.seen)
		}
	})

	t.Run("matcher receives the entry kind", func(t *testing.T) {
		entries, _, err := Walk(WalkOptions{Root: root, ProjectRoot: root, Ignore: []IgnoreMatcher{kindMatcher{skipKind: EntrySymlink}}})
		if err != nil {
			t.Fatalf("Walk error = %v, want nil", err)
		}
		if got := relPaths(entries); contains(got, "linkdir") {
			t.Fatalf("symlink not dropped by a kind-keyed matcher; got %v", got)
		}
	})
}

// TestWalk_ProjectRelativePaths checks that RelPath (and therefore matcher input) is relative to
// ProjectRoot, not to a deeper traversal Root, so a future .gitignore matcher sees repo-root-relative
// paths regardless of which subdirectory a tool was invoked on. Depth, by contrast, is measured from Root.
func TestWalk_ProjectRelativePaths(t *testing.T) {
	proj := eval(t, t.TempDir())
	mkdir(t, filepath.Join(proj, "sub", "nested"))
	writeFile(t, filepath.Join(proj, "sub", "x.txt"), "x")
	writeFile(t, filepath.Join(proj, "sub", "nested", "y.txt"), "x")

	rec := &recordingMatcher{skip: map[string]bool{}}
	entries, _, err := Walk(WalkOptions{Root: filepath.Join(proj, "sub"), ProjectRoot: proj, Ignore: []IgnoreMatcher{rec}})
	if err != nil {
		t.Fatalf("Walk error = %v, want nil", err)
	}
	want := []triple{
		{"sub/nested", EntryDir, 1},
		{"sub/nested/y.txt", EntryFile, 2},
		{"sub/x.txt", EntryFile, 1},
	}
	if got := triples(entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries =\n%v\nwant\n%v", got, want)
	}
	if !contains(rec.seen, "sub/x.txt") {
		t.Fatalf("matcher did not receive project-relative path; seen %v", rec.seen)
	}
}

// TestWalk_ReadErrorPropagates checks that an unreadable root — non-existent or not a directory — is
// returned as an error value (model-correctable in-band by the caller) rather than panicking or hiding it.
func TestWalk_ReadErrorPropagates(t *testing.T) {
	root := buildMainTree(t)

	t.Run("non-existent root", func(t *testing.T) {
		_, _, err := Walk(WalkOptions{Root: filepath.Join(root, "does-not-exist"), ProjectRoot: root})
		if err == nil {
			t.Fatalf("Walk error = nil, want a read error for a non-existent root")
		}
	})

	t.Run("root is a file", func(t *testing.T) {
		_, _, err := Walk(WalkOptions{Root: filepath.Join(root, "a.txt"), ProjectRoot: root})
		if err == nil {
			t.Fatalf("Walk error = nil, want a read error for a non-directory root")
		}
	})
}

func TestWalkContext_OrderClassificationHiddenDefault(t *testing.T) {
	root := buildMainTree(t)

	for _, tc := range []struct {
		name string
		opts WalkOptions
	}{
		{"default hidden filtering", WalkOptions{Root: root, ProjectRoot: root}},
		{"include hidden", WalkOptions{Root: root, ProjectRoot: root, IncludeHidden: true}},
		{"max depth 1", WalkOptions{Root: root, ProjectRoot: root, MaxDepth: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, truncated, err := Walk(tc.opts)
			if err != nil {
				t.Fatalf("Walk error = %v, want nil", err)
			}
			if truncated {
				t.Fatalf("truncated = true, want false (no limit set)")
			}
			if got := collectContext(t, context.Background(), tc.opts); !reflect.DeepEqual(got, want) {
				t.Fatalf("WalkContext entries =\n%v\nwant (same as Walk)\n%v", triples(got), triples(want))
			}
		})
	}
}

func TestWalkContext_CancelStopsEmission(t *testing.T) {
	root := buildMainTree(t)

	t.Run("cancel from the visitor stops later siblings", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var seen []string
		err := WalkContext(ctx, WalkOptions{Root: root, ProjectRoot: root}, func(e WalkEntry) error {
			seen = append(seen, e.RelPath)
			if e.RelPath == "a.txt" {
				cancel()
			}
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WalkContext error = %v, want context.Canceled", err)
		}
		if !reflect.DeepEqual(seen, []string{"a.txt"}) {
			t.Fatalf("visited %v, want only [a.txt] before cancellation", seen)
		}
	})

	t.Run("cancel on a directory stops its descent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var seen []string
		err := WalkContext(ctx, WalkOptions{Root: root, ProjectRoot: root}, func(e WalkEntry) error {
			seen = append(seen, e.RelPath)
			if e.RelPath == "b" {
				cancel()
			}
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WalkContext error = %v, want context.Canceled", err)
		}
		for _, rel := range seen {
			if strings.HasPrefix(rel, "b/") {
				t.Fatalf("descended into b after cancellation: visited %v", seen)
			}
		}
	})

	t.Run("already-cancelled context emits nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		visited := 0
		err := WalkContext(ctx, WalkOptions{Root: root, ProjectRoot: root}, func(WalkEntry) error {
			visited++
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WalkContext error = %v, want context.Canceled", err)
		}
		if visited != 0 {
			t.Fatalf("visited %d entries, want 0 for an already-cancelled context", visited)
		}
	})

	t.Run("cancel during ignore matching stops the entry from being emitted", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := &cancellingMatcher{cancel: cancel}
		visited := 0
		err := WalkContext(ctx, WalkOptions{Root: root, ProjectRoot: root, Ignore: []IgnoreMatcher{m}}, func(WalkEntry) error {
			visited++
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WalkContext error = %v, want context.Canceled", err)
		}
		if m.calls == 0 {
			t.Fatalf("matcher never consulted, want at least one ShouldSkip call")
		}
		if visited != 0 {
			t.Fatalf("visited %d entries, want 0 after cancellation during ignore matching", visited)
		}
	})

	t.Run("cancel while skipping the traversal root returns cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := &cancellingMatcher{cancel: cancel, skip: true}
		visited := 0
		err := WalkContext(ctx, WalkOptions{Root: filepath.Join(root, "b"), ProjectRoot: root, Ignore: []IgnoreMatcher{m}}, func(WalkEntry) error {
			visited++
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WalkContext error = %v, want context.Canceled", err)
		}
		if visited != 0 {
			t.Fatalf("visited %d entries, want 0 when cancellation skips the root", visited)
		}
	})

	t.Run("cancel while skipping the final entry returns cancellation", func(t *testing.T) {
		projectRoot := eval(t, t.TempDir())
		writeFile(t, filepath.Join(projectRoot, "only.txt"), "x")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := &cancellingMatcher{cancel: cancel, skip: true}
		visited := 0
		err := WalkContext(ctx, WalkOptions{Root: projectRoot, ProjectRoot: projectRoot, Ignore: []IgnoreMatcher{m}}, func(WalkEntry) error {
			visited++
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WalkContext error = %v, want context.Canceled", err)
		}
		if visited != 0 {
			t.Fatalf("visited %d entries, want 0 when cancellation skips the final entry", visited)
		}
	})
}

func TestWalkContext_ErrorsStayDistinguishable(t *testing.T) {
	root := buildMainTree(t)

	t.Run("visitor error propagates", func(t *testing.T) {
		sentinel := errors.New("visitor stop")
		err := WalkContext(context.Background(), WalkOptions{Root: root, ProjectRoot: root}, func(WalkEntry) error {
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("WalkContext error = %v, want the visitor's error", err)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, errWalkLimit) {
			t.Fatalf("visitor error conflated with cancellation or the limit sentinel: %v", err)
		}
	})

	t.Run("read error propagates", func(t *testing.T) {
		err := WalkContext(context.Background(), WalkOptions{Root: filepath.Join(root, "does-not-exist"), ProjectRoot: root}, func(WalkEntry) error {
			t.Fatalf("visitor called for an unreadable root")
			return nil
		})
		if err == nil {
			t.Fatalf("WalkContext error = nil, want a read error for a non-existent root")
		}
		if errors.Is(err, context.Canceled) {
			t.Fatalf("read error conflated with cancellation: %v", err)
		}
	})
}

func TestWalkContext_IgnoreAndSymlinkRules(t *testing.T) {
	root := buildMainTree(t)

	t.Run("matcher prunes a directory subtree before descent", func(t *testing.T) {
		m := &recordingMatcher{skip: map[string]bool{"b": true}}
		got := relPaths(collectContext(t, context.Background(), WalkOptions{Root: root, ProjectRoot: root, Ignore: []IgnoreMatcher{m}}))
		for _, rel := range got {
			if rel == "b" || strings.HasPrefix(rel, "b/") {
				t.Fatalf("pruned directory subtree leaked entry %q", rel)
			}
		}
		if contains(m.seen, "b/b1.txt") {
			t.Fatalf("matcher saw b/b1.txt, so the visitor walk descended a pruned directory; seen %v", m.seen)
		}
	})

	t.Run("include_ignored disables the matchers", func(t *testing.T) {
		m := &recordingMatcher{skip: map[string]bool{"b": true}}
		got := relPaths(collectContext(t, context.Background(), WalkOptions{Root: root, ProjectRoot: root, IncludeIgnored: true, Ignore: []IgnoreMatcher{m}}))
		if !contains(got, "b") || !contains(got, "b/b1.txt") {
			t.Fatalf("include_ignored did not re-include the skipped subtree; got %v", got)
		}
	})

	t.Run("ignored traversal root emits nothing", func(t *testing.T) {
		m := &recordingMatcher{skip: map[string]bool{"b": true}}
		got := collectContext(t, context.Background(), WalkOptions{Root: filepath.Join(root, "b"), ProjectRoot: root, Ignore: []IgnoreMatcher{m}})
		if len(got) != 0 {
			t.Fatalf("entries = %v, want none for an ignored traversal root", relPaths(got))
		}
	})

	t.Run("directory symlink is reported but not followed", func(t *testing.T) {
		got := collectContext(t, context.Background(), WalkOptions{Root: root, ProjectRoot: root, IncludeHidden: true})
		var linkKind EntryKind
		for _, e := range got {
			if e.RelPath == "linkdir" {
				linkKind = e.Kind
			}
			if strings.HasPrefix(e.RelPath, "linkdir/") {
				t.Fatalf("visitor walk descended a directory symlink: found %q", e.RelPath)
			}
		}
		if linkKind != EntrySymlink {
			t.Fatalf("linkdir kind = %q, want %q", linkKind, EntrySymlink)
		}
	})
}

// fakeFileInfo is a minimal os.FileInfo whose only meaningful field is its mode, used to drive
// classifyDirEntry's Info() fallback for an entry the directory read left untyped.
type fakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// fakeDirEntry is an os.DirEntry whose Type() reports no type bits — the shape a filesystem that does not
// supply d_type produces — while Info() reports the entry's true mode, exercising classifyDirEntry's
// metadata fallback path.
type fakeDirEntry struct {
	name string
	typ  os.FileMode
	info os.FileInfo
	err  error
}

func (d fakeDirEntry) Name() string               { return d.name }
func (d fakeDirEntry) IsDir() bool                { return d.typ.IsDir() }
func (d fakeDirEntry) Type() os.FileMode          { return d.typ }
func (d fakeDirEntry) Info() (os.FileInfo, error) { return d.info, d.err }

// TestClassifyDirEntry_UnknownTypeUsesInfo pins the review fix (r1): an os.DirEntry whose Type() carries no
// type bits (an unknown d_type) is classified through its Info() mode rather than defaulting to a regular
// file, so a real directory the directory read left untyped becomes EntryDir — and is therefore descended
// by Walk — instead of being silently emitted as a file and skipped. The directory case fails
// against the pre-fix implementation (which returned EntryFile for any zero type) and passes after it.
func TestClassifyDirEntry_UnknownTypeUsesInfo(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode
		want EntryKind
	}{
		{"directory", os.ModeDir | 0o755, EntryDir},
		{"regular", 0o644, EntryFile},
		{"symlink", os.ModeSymlink | 0o777, EntrySymlink},
		{"socket", os.ModeSocket | 0o644, EntryOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			de := fakeDirEntry{name: tc.name, typ: 0, info: fakeFileInfo{name: tc.name, mode: tc.mode}}
			got, err := classifyDirEntry(de)
			if err != nil {
				t.Fatalf("classifyDirEntry error = %v, want nil", err)
			}
			if got != tc.want {
				t.Fatalf("classifyDirEntry(unknown-type %s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}

	t.Run("info error propagates", func(t *testing.T) {
		de := fakeDirEntry{name: "x", typ: 0, err: errors.New("lstat failed")}
		if _, err := classifyDirEntry(de); err == nil {
			t.Fatalf("classifyDirEntry error = nil, want the Info() error to propagate")
		}
	})
}
