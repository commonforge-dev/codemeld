// Cross-tool adversarial negative tests for the five read-only navigation tools (read, grep, glob, list,
// tree): path-containment escapes, directory-symlink no-follow, and per-tool numeric validation, each driven
// through the tool's real Invoke path and asserted in-band.
package filetools

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/tools"
)

// negTestCap is a generous tool-output byte cap for these negative tests: rejections produce no stdout and
// the symlink-no-follow traversals stay tiny, so the cap never trips and so cannot itself mask a canary leak.
const negTestCap = 1 << 20

// Canary tokens marking out-of-root fixtures. canaryContent only ever appears inside an out-of-root file's
// bytes (never in a path or a rejection message), so its presence in any output proves an outside file was
// read. canaryName is an out-of-root file's basename, so its presence in stdout proves an outside entry was
// traversed and listed.
const (
	canaryContent = "CANARYSECRETxyz789"
	canaryName    = "CANARYFILE.txt"
)

// roTool pairs a read-only tool with its dispatch name for table labelling.
type roTool struct {
	name string
	tool tools.Tool
}

// buildReadOnlyTools constructs all five read-only tools bound to the same ~ anchor (home) and project root
// so one adversarial table can drive each tool's real Invoke path. home is deliberately outside root so a
// ~-rooted path escapes the project.
func buildReadOnlyTools(home, root string) []roTool {
	return []roTool{
		{"read", NewReadTool(home, root, root, negTestCap)},
		{"grep", NewGrepTool(home, root, root, negTestCap)},
		{"glob", NewGlobTool(home, root, root, negTestCap)},
		{"list", NewListTool(home, root, root, negTestCap)},
		{"tree", NewTreeTool(home, root, root, negTestCap)},
	}
}

// dirTool reports whether tool name is one of the directory-oriented read-only tools (grep, glob, list,
// tree), whose path argument names a directory; read instead names a regular file. The escape fixtures point
// a directory tool at an out-of-root directory and read at an out-of-root file.
func dirTool(name string) bool { return name != "read" }

// recursiveTool reports whether tool name is one of the recursive tools (grep, glob, tree) subject to the
// directory-symlink no-follow rule; list is non-recursive and read is single-file.
func recursiveTool(name string) bool { return name == "grep" || name == "glob" || name == "tree" }

// pathCase is one adversarial path argument and a label for it.
type pathCase struct {
	caseName string
	path     string
}

// argsWithPath builds the minimal arguments that drive tool `name` against pathVal through its real
// resolution path. grep and glob require a `pattern`; it is set so that a followed escape would surface the
// canary in the result (grep matches the canary file's contents, glob matches its name), making a containment
// failure observable rather than silently empty. read/list/tree need only the path.
func argsWithPath(name, pathVal string) map[string]any {
	args := map[string]any{"path": pathVal}
	switch name {
	case "grep":
		args["pattern"] = canaryContent
	case "glob":
		args["pattern"] = "**/" + canaryName
	}
	return args
}

// negFixture is the shared adversarial filesystem for the containment table: a project root holding two
// in-root symlinks that escape it, an out-of-root directory holding a canary file (a sibling of root so a
// "../<base>" reaches it), and a home directory outside root holding its own canary file so a ~-rooted path
// escapes too.
type negFixture struct {
	root        string
	home        string
	outsideDir  string
	outsideFile string
}

func newNegFixture(t *testing.T) negFixture {
	t.Helper()
	root := t.TempDir()
	outsideDir := t.TempDir() // a sibling of root under the same per-test temp parent
	home := t.TempDir()       // outside root, so "~" / "~/<sub>" escape the project

	outsideFile := filepath.Join(outsideDir, canaryName)
	writeFile(t, outsideFile, canaryContent+"\n")
	writeFile(t, filepath.Join(home, canaryName), canaryContent+"\n")

	// In-root symlinks that escape the root: one to the outside file (read's target), one to the outside
	// directory (the directory tools' target). Resolution must reject both before any read.
	symlink(t, outsideFile, filepath.Join(root, "escape_file"))
	symlink(t, outsideDir, filepath.Join(root, "escape_dir"))

	return negFixture{root: root, home: home, outsideDir: outsideDir, outsideFile: outsideFile}
}

// boundaryEscapeCases returns the ../ traversal, absolute-outside, and in-root-symlink-escape variants for
// tool `name`, each pointing at the out-of-root file (read) or directory (the directory tools).
func boundaryEscapeCases(name string, f negFixture) []pathCase {
	outBase := filepath.Base(f.outsideDir)
	if dirTool(name) {
		return []pathCase{
			{"dotdot-traversal", "../" + outBase},
			{"absolute-outside", f.outsideDir},
			{"symlink-escape", "escape_dir"},
		}
	}
	return []pathCase{
		{"dotdot-traversal", "../" + outBase + "/" + canaryName},
		{"absolute-outside", f.outsideFile},
		{"symlink-escape", "escape_file"},
	}
}

// tildeCases returns the ~user and out-of-root ~ variants for tool `name`. ~user is unsupported and rejected
// outright; the bare ~ (or ~/<canary>) resolves to the home directory, which the fixture places outside root.
func tildeCases(name string) []pathCase {
	if dirTool(name) {
		return []pathCase{
			{"tilde-user", "~canaryuser"},
			{"tilde-home", "~"},
		}
	}
	return []pathCase{
		{"tilde-user", "~canaryuser/" + canaryName},
		{"tilde-home", "~/" + canaryName},
	}
}

// assertInBandRejection pins Done-when 5: a rejection is a non-zero-exit tool result carrying a
// stderr reason and a nil Go error, never an error that would abort the turn.
func assertInBandRejection(t *testing.T, label string, res tools.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: Invoke returned Go error %v, want nil (rejection must be in-band)", label, err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("%s: ExitCode = 0, want a non-zero in-band rejection (stdout=%q)", label, res.Stdout)
	}
	if len(res.Stderr) == 0 {
		t.Fatalf("%s: Stderr empty, want an in-band reason", label)
	}
}

// assertNoCanaryLeak proves no out-of-root file was read or traversed: the canary content must appear in
// neither stdout nor stderr, and the out-of-root filename must not appear in stdout (the success channel).
func assertNoCanaryLeak(t *testing.T, label string, res tools.Result) {
	t.Helper()
	if strings.Contains(string(res.Stdout), canaryContent) || strings.Contains(string(res.Stderr), canaryContent) {
		t.Fatalf("%s: canary content leaked — an out-of-root file was read (stdout=%q stderr=%q)", label, res.Stdout, res.Stderr)
	}
	if strings.Contains(string(res.Stdout), canaryName) {
		t.Fatalf("%s: out-of-root filename leaked into stdout — an outside entry was traversed (stdout=%q)", label, res.Stdout)
	}
}

// TestReadOnlyTools_PathContainmentRejectsEscapes drives the boundary-escape table through each read-only
// tool's real Invoke path: ../ traversal, absolute-outside, and in-root-symlink-escape all reject fail-closed
// before any read, and no out-of-root canary is read or traversed (Done-when 1, 5).
func TestReadOnlyTools_PathContainmentRejectsEscapes(t *testing.T) {
	f := newNegFixture(t)
	for _, rt := range buildReadOnlyTools(f.home, f.root) {
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			for _, pc := range boundaryEscapeCases(rt.name, f) {
				t.Run(pc.caseName, func(t *testing.T) {
					label := rt.name + "/" + pc.caseName
					res, err := rt.tool.Invoke(context.Background(), argsWithPath(rt.name, pc.path))
					assertInBandRejection(t, label, res, err)
					assertNoCanaryLeak(t, label, res)
				})
			}
		})
	}
}

// TestReadOnlyTools_StandaloneInvokeRefusesExplicitExternalTarget pins the standalone-path guard: the
// non-dispatch Invoke has no authorizer, so an EXPLICIT out-of-project target it now resolves (instead of
// rejecting at the resolver) is refused in-band with the dispatch-approval message rather than read — only
// the dispatch path, which prompts, can read outside the project root. The out-of-root canary never leaks.
func TestReadOnlyTools_StandaloneInvokeRefusesExplicitExternalTarget(t *testing.T) {
	f := newNegFixture(t)
	for _, rt := range buildReadOnlyTools(f.home, f.root) {
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			pathVal := f.outsideFile
			if dirTool(rt.name) {
				pathVal = f.outsideDir
			}
			res, err := rt.tool.Invoke(context.Background(), argsWithPath(rt.name, pathVal))
			assertInBandRejection(t, rt.name, res, err)
			if !strings.Contains(string(res.Stderr), "requires permission approval through dispatch") {
				t.Fatalf("%s: stderr = %q, want the dispatch-approval guard message (g815)", rt.name, res.Stderr)
			}
			assertNoCanaryLeak(t, rt.name, res)
		})
	}
}

// TestReadOnlyTools_ExternalReadAnchorsOutputAtExternalRoot pins the external post-authorization read: once
// dispatch has resolved and authorized an explicit external target, InvokeWithResolvedTarget reads / lists
// / walks it (the standalone guard does not apply on this path), and the recursive/listing tools anchor
// their emitted paths at the approved external root so results stay clean — no ".."-prefixed paths leaking
// the project-root-relative spelling.
func TestReadOnlyTools_ExternalReadAnchorsOutputAtExternalRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	home := t.TempDir()
	ext := eval(t, t.TempDir())
	writeFile(t, filepath.Join(ext, "a.txt"), canaryContent+"\n")
	if err := os.MkdirAll(filepath.Join(ext, "sub"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, filepath.Join(ext, "sub", "b.txt"), "bbb\n")
	ctx := context.Background()

	// resolvedInvoker is the post-authorization invocation seam the five read tools share (the dispatch
	// resolvedTargetInvoker), mirrored locally so this test can drive it without importing internal/dispatch.
	type resolvedInvoker interface {
		InvokeWithResolvedTarget(context.Context, map[string]any, string) (tools.Result, error)
	}

	assertClean := func(t *testing.T, name, out string) {
		t.Helper()
		if strings.Contains(out, "..") {
			t.Fatalf("%s external output = %q, want external-root-relative paths with no .. prefix", name, out)
		}
	}

	t.Run("glob anchors matches at the external root", func(t *testing.T) {
		var tool resolvedInvoker = NewGlobTool(home, root, root, negTestCap)
		res, err := tool.InvokeWithResolvedTarget(ctx, map[string]any{"pattern": "**/*.txt"}, ext)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("glob err=%v exit=%d stderr=%q", err, res.ExitCode, res.Stderr)
		}
		out := string(res.Stdout)
		if !strings.Contains(out, "a.txt") || !strings.Contains(out, "sub/b.txt") {
			t.Fatalf("glob output = %q, want external-root-relative matches a.txt and sub/b.txt", out)
		}
		assertClean(t, "glob", out)
	})

	t.Run("grep reads the external file and anchors paths at the external root", func(t *testing.T) {
		var tool resolvedInvoker = NewGrepTool(home, root, root, negTestCap)
		res, err := tool.InvokeWithResolvedTarget(ctx, map[string]any{"pattern": canaryContent}, ext)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("grep err=%v exit=%d stderr=%q", err, res.ExitCode, res.Stderr)
		}
		out := string(res.Stdout)
		if !strings.Contains(out, "a.txt:") || !strings.Contains(out, canaryContent) {
			t.Fatalf("grep output = %q, want the external match in a.txt", out)
		}
		assertClean(t, "grep", out)
	})

	t.Run("tree anchors the listing at the external root", func(t *testing.T) {
		var tool resolvedInvoker = NewTreeTool(home, root, root, negTestCap)
		res, err := tool.InvokeWithResolvedTarget(ctx, map[string]any{}, ext)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("tree err=%v exit=%d stderr=%q", err, res.ExitCode, res.Stderr)
		}
		out := string(res.Stdout)
		if !strings.Contains(out, "a.txt") || !strings.Contains(out, "sub/b.txt") {
			t.Fatalf("tree output = %q, want external-root-relative entries", out)
		}
		assertClean(t, "tree", out)
	})

	t.Run("list emits the external directory's basenames", func(t *testing.T) {
		var tool resolvedInvoker = NewListTool(home, root, root, negTestCap)
		res, err := tool.InvokeWithResolvedTarget(ctx, map[string]any{}, ext)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("list err=%v exit=%d stderr=%q", err, res.ExitCode, res.Stderr)
		}
		out := string(res.Stdout)
		if !strings.Contains(out, "a.txt") || !strings.Contains(out, "sub") {
			t.Fatalf("list output = %q, want the external directory entries", out)
		}
		assertClean(t, "list", out)
	})

	t.Run("read returns the external file's verbatim content", func(t *testing.T) {
		var tool resolvedInvoker = NewReadTool(home, root, root, negTestCap)
		extFile := filepath.Join(ext, "a.txt")
		res, err := tool.InvokeWithResolvedTarget(ctx, map[string]any{"path": extFile}, extFile)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("read err=%v exit=%d stderr=%q", err, res.ExitCode, res.Stderr)
		}
		if !strings.Contains(string(res.Stdout), canaryContent) {
			t.Fatalf("read output = %q, want the external file content", res.Stdout)
		}
	})
}

// TestReadOnlyTools_TildeFormsRejected pins Done-when 3: the ~user form and an out-of-root ~ form are
// rejected in-band for every tool, before any read, with no out-of-root canary leaking.
func TestReadOnlyTools_TildeFormsRejected(t *testing.T) {
	f := newNegFixture(t)
	for _, rt := range buildReadOnlyTools(f.home, f.root) {
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			for _, pc := range tildeCases(rt.name) {
				t.Run(pc.caseName, func(t *testing.T) {
					label := rt.name + "/" + pc.caseName
					res, err := rt.tool.Invoke(context.Background(), argsWithPath(rt.name, pc.path))
					assertInBandRejection(t, label, res, err)
					assertNoCanaryLeak(t, label, res)
				})
			}
		})
	}
}

// TestReadOnlyTools_RecursiveToolsDoNotFollowDirSymlinks pins Done-when 2: an in-root directory
// symlink pointing at an out-of-root directory of canary files is not descended by the recursive tools, so a
// recursive walk of the project root succeeds yet never reads or lists the out-of-root canaries.
func TestReadOnlyTools_RecursiveToolsDoNotFollowDirSymlinks(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	home := t.TempDir()

	// The out-of-root directory the in-root symlink points at, holding a canary whose name and contents would
	// surface if the walk followed the link.
	writeFile(t, filepath.Join(outsideDir, canaryName), canaryContent+"\n")
	symlink(t, outsideDir, filepath.Join(root, "symdir"))
	// A real in-root file so the traversal is non-trivial and clearly succeeds.
	writeFile(t, filepath.Join(root, "keep.txt"), "in root\n")

	for _, rt := range buildReadOnlyTools(home, root) {
		if !recursiveTool(rt.name) {
			continue // covers the recursive tools (grep, glob, tree)
		}
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			args := map[string]any{} // default path = project root; the walk encounters symdir
			switch rt.name {
			case "grep":
				args["pattern"] = canaryContent
			case "glob":
				args["pattern"] = "**/" + canaryName
			}
			res, err := rt.tool.Invoke(context.Background(), args)
			if err != nil {
				t.Fatalf("%s: Invoke error = %v, want nil", rt.name, err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("%s: ExitCode = %d (stderr=%q), want 0 (walking the root succeeds; the symlink is just not followed)", rt.name, res.ExitCode, res.Stderr)
			}
			assertNoCanaryLeak(t, rt.name, res)
		})
	}
}

// TestReadOnlyTools_NumericValidation pins Done-when 4: each tool rejects its out-of-range numeric
// arguments in-band, naming the violated bound, with no silent change of behavior. The path argument is
// always valid (a real file for read, the default project root for the rest) so the numeric value is the sole
// rejection cause.
func TestReadOnlyTools_NumericValidation(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	writeFile(t, filepath.Join(root, "num.txt"), "a\nb\nc\n")

	rd := NewReadTool(home, root, root, negTestCap)
	gr := NewGrepTool(home, root, root, negTestCap)
	gl := NewGlobTool(home, root, root, negTestCap)
	li := NewListTool(home, root, root, negTestCap)
	tr := NewTreeTool(home, root, root, negTestCap)

	cases := []struct {
		name    string
		tool    tools.Tool
		args    map[string]any
		wantMsg string
	}{
		// read covers offset and limit.
		{"read/offset-zero", rd, map[string]any{"path": "num.txt", "offset": 0}, "offset must be >= 1"},
		{"read/offset-negative", rd, map[string]any{"path": "num.txt", "offset": -2}, "offset must be >= 1"},
		{"read/limit-zero", rd, map[string]any{"path": "num.txt", "limit": 0}, "limit must be >= 1"},
		{"read/limit-over-max", rd, map[string]any{"path": "num.txt", "limit": ReadMaxLimit + 1}, "exceeds the maximum of " + strconv.Itoa(ReadMaxLimit)},
		// grep covers context and limit.
		{"grep/context-negative", gr, map[string]any{"pattern": "x", "context": -1}, "context must be >= 0"},
		{"grep/limit-zero", gr, map[string]any{"pattern": "x", "limit": 0}, "limit must be >= 1"},
		{"grep/limit-over-max", gr, map[string]any{"pattern": "x", "limit": GrepMaxLimit + 1}, "exceeds the maximum of " + strconv.Itoa(GrepMaxLimit)},
		// glob covers limit.
		{"glob/limit-zero", gl, map[string]any{"pattern": "*", "limit": 0}, "limit must be >= 1"},
		{"glob/limit-over-max", gl, map[string]any{"pattern": "*", "limit": GlobMaxLimit + 1}, "exceeds the maximum of " + strconv.Itoa(GlobMaxLimit)},
		// list covers limit.
		{"list/limit-zero", li, map[string]any{"limit": 0}, "limit must be >= 1"},
		{"list/limit-over-max", li, map[string]any{"limit": ListMaxLimit + 1}, "exceeds the maximum of " + strconv.Itoa(ListMaxLimit)},
		// tree covers depth and limit.
		{"tree/depth-negative", tr, map[string]any{"depth": -1}, "depth must be >= 0"},
		{"tree/limit-zero", tr, map[string]any{"limit": 0}, "limit must be >= 1"},
		{"tree/limit-over-max", tr, map[string]any{"limit": TreeMaxLimit + 1}, "exceeds the maximum of " + strconv.Itoa(TreeMaxLimit)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.tool.Invoke(context.Background(), tc.args)
			assertInBandRejection(t, tc.name, res, err)
			if !strings.Contains(string(res.Stderr), tc.wantMsg) {
				t.Fatalf("%s: Stderr = %q, want it to contain %q", tc.name, res.Stderr, tc.wantMsg)
			}
		})
	}
}
