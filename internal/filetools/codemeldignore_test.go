// Tests for codemeldignore loading/parsing, the literal match + directory-prune semantics, and the
// terminal cross-tool filtering proof: glob/grep/list/tree skip matched paths by default and include them
// under include_ignored.
package filetools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/tools"
)

const ciTestCap = 65536

// writeCI writes content to path, creating parent directories, failing the test on error.
func writeCI(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func TestLoadCodemeldignore_MissingFilesIsNotAnError(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	m, err := LoadCodemeldignoreMatcher(root, home)
	if err != nil {
		t.Fatalf("LoadCodemeldignoreMatcher with no files: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil matcher when neither file exists, got %+v", m)
	}
}

func TestLoadCodemeldignore_SkipsBlankAndCommentsAndUnions(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	writeCI(t, ProjectCodemeldignorePath(root), "# project ignores\n\nbuild\n  node_modules  \n")
	writeCI(t, GlobalCodemeldignorePath(home), "\n# global\n**/*.tmp\n")

	m, err := LoadCodemeldignoreMatcher(root, home)
	if err != nil {
		t.Fatalf("LoadCodemeldignoreMatcher: %v", err)
	}
	if m == nil {
		t.Fatal("expected a matcher, got nil")
	}
	want := []string{"build", "node_modules", "**/*.tmp"}
	if len(m.patterns) != len(want) {
		t.Fatalf("patterns = %v, want %v", m.patterns, want)
	}
	for i := range want {
		if m.patterns[i] != want[i] {
			t.Fatalf("patterns = %v, want %v (project first, global second)", m.patterns, want)
		}
	}
}

func TestLoadCodemeldignore_InvalidPatternRejected(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	// An unterminated character class is an invalid doublestar pattern.
	writeCI(t, ProjectCodemeldignorePath(root), "good\n[unterminated\n")

	_, err := LoadCodemeldignoreMatcher(root, home)
	if err == nil {
		t.Fatal("expected an error for an invalid pattern, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid pattern") || !strings.Contains(msg, ":2:") {
		t.Fatalf("error %q should name the invalid pattern and its 1-based line (2)", msg)
	}
}

func TestCodemeldignoreMatcher_LiteralSemantics(t *testing.T) {
	m := &CodemeldignoreMatcher{patterns: []string{
		"build/output.log", // exact file at root
		"node_modules",     // slash-less: root-only
		"**/somedir_name",  // any depth
	}}
	cases := []struct {
		rel  string
		want bool
	}{
		{"build/output.log", true},
		{"build/output.log2", false},
		{"node_modules", true},        // root-level dir
		{"d1/node_modules", false},    // slash-less is root-only
		{"somedir_name", true},        // **/ matches zero leading segments
		{"d1/somedir_name", true},     // one segment
		{"a/b/c/somedir_name", true},  // many segments
		{"somedir_name_v2", false},    // literal, not a prefix
		{"d1/somedir_name_v2", false}, // same at depth
		{"src/app.go", false},         // unrelated
	}
	for _, tc := range cases {
		if got := m.ShouldSkip(tc.rel, EntryFile); got != tc.want {
			t.Errorf("ShouldSkip(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}

// --- Terminal cross-tool test ---------------------------------------------------------------------------

// ciFixture builds a project tree with a .codemeld/codemeldignore and returns (root, home). home is a
// separate empty dir, so only the project file contributes patterns. Files tagged with the FINDME token
// let grep prove content filtering.
func ciFixture(t *testing.T) (root, home string) {
	t.Helper()
	root = t.TempDir()
	home = t.TempDir()

	writeCI(t, ProjectCodemeldignorePath(root), "# ignore some things\nbuild\n**/node_modules\nsecret.txt\n")

	writeCI(t, filepath.Join(root, "build", "output.log"), "FINDME in build")
	writeCI(t, filepath.Join(root, "build", "keep.go"), "FINDME in build keep")
	writeCI(t, filepath.Join(root, "src", "app.go"), "FINDME in app")
	writeCI(t, filepath.Join(root, "src", "node_modules", "pkg.go"), "FINDME in nested node_modules")
	writeCI(t, filepath.Join(root, "node_modules", "top.go"), "FINDME in top node_modules")
	writeCI(t, filepath.Join(root, "node_modules_v2", "x.go"), "FINDME in v2") // must NOT be pruned
	writeCI(t, filepath.Join(root, "secret.txt"), "FINDME secret")
	writeCI(t, filepath.Join(root, "keep.txt"), "FINDME keep")
	return root, home
}

func mustContain(t *testing.T, label, out, want string) {
	t.Helper()
	if !strings.Contains(out, want) {
		t.Errorf("%s: expected output to contain %q\n--- output ---\n%s", label, want, out)
	}
}

func mustNotContain(t *testing.T, label, out, want string) {
	t.Helper()
	if strings.Contains(out, want) {
		t.Errorf("%s: expected output NOT to contain %q\n--- output ---\n%s", label, want, out)
	}
}

func runTool(t *testing.T, tool tools.Tool, args map[string]any) string {
	t.Helper()
	res, err := tool.Invoke(context.Background(), args)
	if err != nil {
		t.Fatalf("Invoke(%v): %v", args, err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("Invoke(%v) ExitCode = %d, stderr=%q", args, res.ExitCode, res.Stderr)
	}
	return string(res.Stdout)
}

// ciFilterCase parameterizes the terminal cross-tool filtering proof over the four tools that honor
// codemeldignore: each runs over the same ciFixture, asserting ignored paths are absent and non-ignored
// paths present by default, and ignored paths reappear under include_ignored. The expected tokens differ per
// tool because their output forms differ (glob/grep emit project-relative paths; list/tree emit
// entries/basenames).
type ciFilterCase struct {
	name               string
	newTool            func(home, root string) tools.Tool
	defaultArgs        map[string]any
	includeArgs        map[string]any
	absentByDefault    []string
	presentByDefault   []string
	presentWithInclude []string
}

var ciFilterCases = []ciFilterCase{
	{
		name:               "glob",
		newTool:            func(home, root string) tools.Tool { return NewGlobTool(home, root, root, ciTestCap) },
		defaultArgs:        map[string]any{"pattern": "**"},
		includeArgs:        map[string]any{"pattern": "**", "include_ignored": true},
		absentByDefault:    []string{"secret.txt", "build/output.log", "node_modules/top.go", "src/node_modules/pkg.go"},
		presentByDefault:   []string{"src/app.go", "node_modules_v2/x.go", "keep.txt"}, // literal **/node_modules must not match node_modules_v2
		presentWithInclude: []string{"secret.txt", "build/output.log", "node_modules/top.go", "src/node_modules/pkg.go"},
	},
	{
		name:               "grep",
		newTool:            func(home, root string) tools.Tool { return NewGrepTool(home, root, root, ciTestCap) },
		defaultArgs:        map[string]any{"pattern": "FINDME"},
		includeArgs:        map[string]any{"pattern": "FINDME", "include_ignored": true},
		absentByDefault:    []string{"secret.txt", "build/output.log", "node_modules/top.go", "src/node_modules/pkg.go"},
		presentByDefault:   []string{"src/app.go", "node_modules_v2/x.go"},
		presentWithInclude: []string{"secret.txt", "build/output.log", "node_modules/top.go"},
	},
	{
		name:               "list",
		newTool:            func(home, root string) tools.Tool { return NewListTool(home, root, root, ciTestCap) },
		defaultArgs:        map[string]any{},
		includeArgs:        map[string]any{"include_ignored": true},
		absentByDefault:    []string{"secret.txt", "build", "node_modules\n"}, // node_modules\n = the root dir, not node_modules_v2
		presentByDefault:   []string{"src", "node_modules_v2", "keep.txt"},
		presentWithInclude: []string{"secret.txt", "build"},
	},
	{
		name:               "tree",
		newTool:            func(home, root string) tools.Tool { return NewTreeTool(home, root, root, ciTestCap) },
		defaultArgs:        map[string]any{},
		includeArgs:        map[string]any{"include_ignored": true},
		absentByDefault:    []string{"secret.txt", "output.log", "top.go", "pkg.go"},
		presentByDefault:   []string{"app.go", "node_modules_v2"},
		presentWithInclude: []string{"secret.txt", "output.log"},
	},
}

func TestCodemeldignore_ToolsFilterByDefault(t *testing.T) {
	for _, tc := range ciFilterCases {
		t.Run(tc.name, func(t *testing.T) {
			root, home := ciFixture(t)
			tool := tc.newTool(home, root)

			def := runTool(t, tool, tc.defaultArgs)
			for _, s := range tc.absentByDefault {
				mustNotContain(t, tc.name+" default", def, s)
			}
			for _, s := range tc.presentByDefault {
				mustContain(t, tc.name+" default", def, s)
			}

			all := runTool(t, tool, tc.includeArgs)
			for _, s := range tc.presentWithInclude {
				mustContain(t, tc.name+" include_ignored", all, s)
			}
		})
	}
}

// TestCodemeldignore_IgnoredDirAsPathPruned proves that naming an ignored directory directly as the tool
// `path` still prunes it: the walker checks the traversal root itself against the ignore set, so glob,
// grep, list, and tree all return no content for `path: "build"` by default (build is ignored) and surface
// it under include_ignored. Without the root pre-walk ignore check in Walk, the matched directory would be
// descended before its project-relative path was ever matched, leaking its children.
func TestCodemeldignore_IgnoredDirAsPathPruned(t *testing.T) {
	cases := []struct {
		name        string
		newTool     func(home, root string) tools.Tool
		defaultArgs map[string]any
		includeArgs map[string]any
		wantPresent string // the include_ignored output token (project-relative for glob/grep, basename for list/tree)
	}{
		{"glob", func(home, root string) tools.Tool { return NewGlobTool(home, root, root, ciTestCap) },
			map[string]any{"pattern": "**", "path": "build"}, map[string]any{"pattern": "**", "path": "build", "include_ignored": true}, "build/output.log"},
		{"grep", func(home, root string) tools.Tool { return NewGrepTool(home, root, root, ciTestCap) },
			map[string]any{"pattern": "FINDME", "path": "build"}, map[string]any{"pattern": "FINDME", "path": "build", "include_ignored": true}, "build/output.log"},
		{"list", func(home, root string) tools.Tool { return NewListTool(home, root, root, ciTestCap) },
			map[string]any{"path": "build"}, map[string]any{"path": "build", "include_ignored": true}, "output.log"},
		{"tree", func(home, root string) tools.Tool { return NewTreeTool(home, root, root, ciTestCap) },
			map[string]any{"path": "build"}, map[string]any{"path": "build", "include_ignored": true}, "output.log"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, home := ciFixture(t)
			tool := tc.newTool(home, root)
			def := runTool(t, tool, tc.defaultArgs)
			mustNotContain(t, tc.name+" path=build default", def, "output.log")
			mustNotContain(t, tc.name+" path=build default", def, "keep.go")
			all := runTool(t, tool, tc.includeArgs)
			mustContain(t, tc.name+" path=build include_ignored", all, tc.wantPresent)
		})
	}
}

// TestCodemeldignore_HiddenFilteringIndependent proves include_hidden controls dot-entry filtering
// independently of the codemeldignore filter: a non-ignored dot file is hidden by default and
// surfaced by include_hidden, with the codemeldignore filter still excluding an ignored path in both cases.
func TestCodemeldignore_HiddenFilteringIndependent(t *testing.T) {
	root, home := ciFixture(t)
	writeCI(t, filepath.Join(root, ".env"), "FINDME dotfile")
	tool := NewListTool(home, root, root, ciTestCap)

	def := runTool(t, tool, map[string]any{})
	mustNotContain(t, "list default", def, ".env")       // hidden by default
	mustNotContain(t, "list default", def, "secret.txt") // ignored by default

	hidden := runTool(t, tool, map[string]any{"include_hidden": true})
	mustContain(t, "list include_hidden", hidden, ".env")          // hidden filter lifted
	mustNotContain(t, "list include_hidden", hidden, "secret.txt") // codemeldignore still applies
}
