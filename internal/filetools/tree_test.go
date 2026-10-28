// Unit tests for the built-in tree tool: metadata/classification, the default `ai` project-relative
// path-list output and the `human` indented basename output, recursive pre-order listing, deterministic
// ascending order, depth-limited and depth-0 output, depth-before-limit accounting with the truncation
// metadata, empty-directory success, directory-symlink no-follow (both as an in-walk entry and as a rejected
// path argument), hidden-skip + include_hidden, include_ignored acceptance, default-path-is-root, argument
// validation (including an unrecognized `format`), and the path-containment + reuse-at-invoke symlink
// rejections.
package filetools

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/tools"
)

const treeTestCap = 65536

// newTreeToolIn builds a tree tool whose project root and relative-path base are root, with a separate home
// anchor, mirroring list_test's newListToolIn.
func newTreeToolIn(t *testing.T, root string) *TreeTool {
	t.Helper()
	return NewTreeTool(t.TempDir(), root, root, treeTestCap)
}

// invokeTree runs the tree tool's full standalone path (ResolveTarget then tree) and returns the result.
func invokeTree(t *testing.T, tool *TreeTool, args map[string]any) (tools.Result, error) {
	t.Helper()
	return tool.Invoke(context.Background(), args)
}

// treeLines splits a successful tree result's stdout into its entry lines (trailing newline dropped, any
// leading indentation preserved), asserting a zero exit so a rejection is not silently read as "empty tree".
// It is layout-agnostic: each line is one `ai` project-relative path or one `human` indented basename.
func treeLines(t *testing.T, res tools.Result) []string {
	t.Helper()
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d (stderr=%q), want 0", res.ExitCode, res.Stderr)
	}
	out := strings.TrimSuffix(string(res.Stdout), "\n")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func TestTreeTool_AdvertiseMetadata(t *testing.T) {
	tool := newTreeToolIn(t, t.TempDir())

	if tool.Name() != "tree" {
		t.Fatalf("Name() = %q, want tree", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if !md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = false, want true (tree is read-only, req 20)")
	}
	if strings.TrimSpace(md.Description) == "" {
		t.Fatal("Advertise().Description is empty, want a one-line description")
	}
	if md.Parameters["type"] != "object" {
		t.Fatalf("Parameters.type = %v, want object", md.Parameters["type"])
	}
	if md.Parameters["additionalProperties"] != false {
		t.Fatalf("Parameters.additionalProperties = %v, want false", md.Parameters["additionalProperties"])
	}
	// Every tree argument is optional: required must be present and empty (path defaults to the root).
	if req, ok := md.Parameters["required"].([]string); !ok || len(req) != 0 {
		t.Fatalf("Parameters.required = %v, want an empty list (all args optional)", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties = %v, want a map", md.Parameters["properties"])
	}
	for _, key := range []string{"path", "depth", "limit", "format", "include_ignored", "include_hidden"} {
		if _, ok := props[key]; !ok {
			t.Fatalf("Parameters.properties missing %q", key)
		}
	}
	// format is a closed enum of exactly {ai, human}.
	formatProp, ok := props["format"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties[format] = %v, want a map", props["format"])
	}
	if got := formatProp["enum"]; !reflect.DeepEqual(got, []string{"ai", "human"}) {
		t.Fatalf("format enum = %#v, want [ai human]", got)
	}
	assertOutsideScanAdvertise(t, md, "directory outside the project is walked without asking", "such a walk asks first")
}

// mkTreeFixture builds a small nested tree under root and returns it:
//
//	README.md
//	src/main.go
//	src/util/helper.go
func mkTreeFixture(t *testing.T, root string) {
	t.Helper()
	mkdirAll(t, filepath.Join(root, "src", "util"))
	writeFile(t, filepath.Join(root, "README.md"), "# readme\n")
	writeFile(t, filepath.Join(root, "src", "main.go"), "package main\n")
	writeFile(t, filepath.Join(root, "src", "util", "helper.go"), "package util\n")
}

// TestTreeTool_DefaultAIRecursiveOrder pins Done-when 1: with no format argument tree defaults to `ai` and
// emits one project-relative, slash-normalized path per line in deterministic depth-first pre-order
// (directory before its descendants, siblings ascending by name), with a trailing "/" on directories and no
// indentation.
func TestTreeTool_DefaultAIRecursiveOrder(t *testing.T) {
	root := t.TempDir()
	mkTreeFixture(t, root)
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, nil)
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := treeLines(t, res)
	want := []string{
		"README.md",          // depth 1, ascending: 'R' < 's'
		"src/",               // depth 1 directory
		"src/main.go",        // depth 2, ascending: 'm' < 'u'
		"src/util/",          // depth 2 directory
		"src/util/helper.go", // depth 3
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree = %#v, want %#v (default ai project-relative pre-order)", got, want)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated {
		t.Fatalf("meta.Truncated = true, want false (the whole small tree fits)")
	}
}

// TestTreeTool_HumanFormat pins Done-when 1: format "human" emits the same pre-order/depth/order entries as
// the indented basename tree — two spaces of indent per level below the resolved root, basenames only, with
// a trailing "/" on directories — over the same fixture the default ai layout renders as project-relative
// paths.
func TestTreeTool_HumanFormat(t *testing.T) {
	root := t.TempDir()
	mkTreeFixture(t, root)
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, map[string]any{"format": "human"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := treeLines(t, res)
	want := []string{
		"README.md",     // depth 1, ascending: 'R' < 's'
		"src/",          // depth 1 directory
		"  main.go",     // depth 2, ascending: 'm' < 'u'
		"  util/",       // depth 2 directory
		"    helper.go", // depth 3
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree(format:human) = %#v, want %#v (indented basename pre-order)", got, want)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated {
		t.Fatalf("meta.Truncated = true, want false (the whole small tree fits)")
	}
}

// TestTreeTool_DepthLimited pins Done-when 1: depth caps the descendant levels shown. depth 1 shows only the
// immediate children; depth 2 shows two levels (the depth-2 directory is emitted but not descended).
func TestTreeTool_DepthLimited(t *testing.T) {
	root := t.TempDir()
	mkTreeFixture(t, root)
	tool := newTreeToolIn(t, root)

	t.Run("depth 1 = immediate children only", func(t *testing.T) {
		res, err := invokeTree(t, tool, map[string]any{"depth": 1})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := treeLines(t, res)
		want := []string{"README.md", "src/"} // src is at the cap: emitted, not descended
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("tree(depth:1) = %#v, want %#v", got, want)
		}
	})

	t.Run("depth 2 = two levels", func(t *testing.T) {
		res, err := invokeTree(t, tool, map[string]any{"depth": 2})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := treeLines(t, res)
		// util/ is at the depth-2 cap: emitted but not descended, so helper.go (depth 3) is absent.
		want := []string{"README.md", "src/", "src/main.go", "src/util/"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("tree(depth:2) = %#v, want %#v", got, want)
		}
	})
}

// TestTreeTool_DepthZeroEmpty pins Done-when 2 (edge): depth 0 emits no descendant entries — an
// empty success with a not-truncated indicator, not an error — distinct from the walker's MaxDepth 0
// (unlimited) meaning.
func TestTreeTool_DepthZeroEmpty(t *testing.T) {
	root := t.TempDir()
	mkTreeFixture(t, root)
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, map[string]any{"depth": 0})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	assertEmptySuccess(t, res)
}

// TestTreeTool_EmptyDirectoryEmptyNotError pins Done-when 2 (edge): an existing but empty directory
// returns a success with empty output and a not-truncated indicator, not an error.
func TestTreeTool_EmptyDirectoryEmptyNotError(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "empty"))
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, map[string]any{"path": "empty"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	assertEmptySuccess(t, res)
}

// TestTreeTool_LimitAndTruncation pins Done-when 3: total entries are bounded by limit in pre-order, and the
// metadata signals truncation with reason "limit" when more entries remain.
func TestTreeTool_LimitAndTruncation(t *testing.T) {
	assertLimitTruncation(t, func(root string) readNavTool { return newTreeToolIn(t, root) }, treeLines, nil,
		[]string{"a.go", "b.go"}) // first 2 in ascending order
}

// TestTreeTool_DepthAppliedBeforeLimit pins the task note that depth filtering precedes limit accounting:
// descendants below the depth cap are never counted toward the total-entry budget, so a limit equal to the
// in-depth entry count is not truncated even though the tree holds far more files below that depth.
func TestTreeTool_DepthAppliedBeforeLimit(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "packed"))
	for _, n := range []string{"x1.go", "x2.go", "x3.go", "x4.go", "x5.go"} {
		writeFile(t, filepath.Join(root, "packed", n), "package packed\n")
	}
	writeFile(t, filepath.Join(root, "top.go"), "package top\n")
	tool := newTreeToolIn(t, root)

	// Two depth-1 entries (packed/, top.go); the five files under packed/ are at depth 2, beyond the depth-1
	// cap, so they must not be emitted or counted. limit:2 fits both depth-1 entries exactly → not truncated.
	res, err := invokeTree(t, tool, map[string]any{"depth": 1, "limit": 2})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := treeLines(t, res)
	want := []string{"packed/", "top.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree(depth:1,limit:2) = %#v, want %#v (deeper descendants do not count)", got, want)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated {
		t.Fatalf("meta.Truncated = true, want false (only 2 in-depth entries; deeper files excluded)")
	}
}

// TestTreeTool_DirectorySymlinkEntryNotFollowed pins Done-when 3 +: a directory symlink encountered
// within the walk is shown as a leaf (no trailing "/", no children) and never descended, so its target's
// contents are not listed through it.
func TestTreeTool_DirectorySymlinkEntryNotFollowed(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "realdir"))
	writeFile(t, filepath.Join(root, "realdir", "inside.go"), "package realdir\n")
	if err := os.Symlink(filepath.Join(root, "realdir"), filepath.Join(root, "linkdir")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, nil)
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := treeLines(t, res)
	// linkdir (ascending: 'l' < 'r') is a bare leaf — no "/", no child path under it. inside.go appears
	// exactly once, under realdir, proving the symlink target was not walked through the link.
	want := []string{"linkdir", "realdir/", "realdir/inside.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree = %#v, want %#v (directory symlink not followed)", got, want)
	}
}

// TestTreeTool_HiddenSkippedByDefaultAndOverride pins Done-when 4: dot-prefixed entries are
// skipped by default and surfaced (with their descendants) under include_hidden.
func TestTreeTool_HiddenSkippedByDefaultAndOverride(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, ".git"))
	writeFile(t, filepath.Join(root, ".git", "config"), "data\n")
	writeFile(t, filepath.Join(root, "visible.go"), "package v\n")
	writeFile(t, filepath.Join(root, ".dotfile"), "secret\n")
	tool := newTreeToolIn(t, root)

	t.Run("hidden skipped by default", func(t *testing.T) {
		res, err := invokeTree(t, tool, nil)
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := treeLines(t, res)
		want := []string{"visible.go"} // .git (and its config) and .dotfile filtered, not descended
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("tree default = %#v, want %#v (hidden skipped)", got, want)
		}
	})

	t.Run("include_hidden surfaces dot entries and their descendants", func(t *testing.T) {
		res, err := invokeTree(t, tool, map[string]any{"include_hidden": true})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := treeLines(t, res)
		// Ascending at root: ".dotfile" < ".git" < "visible.go"; .git is now descended into.
		want := []string{".dotfile", ".git/", ".git/config", "visible.go"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("tree include_hidden = %#v, want %#v", got, want)
		}
	})
}

// TestTreeTool_IncludeIgnoredAccepted pins Done-when 4 for include_ignored: the flag is accepted and the
// walk runs with it set. The fixture has no project or global codemeldignore file, so the walker's
// Ignore set is empty and include_ignored changes nothing here — this confirms the flag plumbs without error.
func TestTreeTool_IncludeIgnoredAccepted(t *testing.T) {
	assertIncludeIgnoredAccepted(t, func(root string) readNavTool { return newTreeToolIn(t, root) }, treeLines,
		nil, "package k\n", []string{"keep.go"})
}

// TestTreeTool_DefaultPathIsProjectRoot pins: an omitted path walks the project root.
func TestTreeTool_DefaultPathIsProjectRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "rootfile.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "rootdir"))
	writeFile(t, filepath.Join(root, "rootdir", "child.go"), "package rootdir\n")
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, nil)
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := treeLines(t, res)
	want := []string{"rootdir/", "rootdir/child.go", "rootfile.go"} // 'rootd' < 'rootf'
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree with default path = %#v, want %#v", got, want)
	}
}

// TestTreeTool_ExplicitRootEqualsDefault is the explicit-root regression: an explicit path equal to the
// project root (absolute, ".", "./", and trailing-slash forms) walks the same tree as omitting path.
func TestTreeTool_ExplicitRootEqualsDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "rootfile.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "rootdir"))
	writeFile(t, filepath.Join(root, "rootdir", "child.go"), "package rootdir\n")
	tool := newTreeToolIn(t, root)

	assertExplicitRootEqualsDefault(t, func(a map[string]any) (tools.Result, error) { return invokeTree(t, tool, a) },
		treeLines, root, nil)
}

// TestTreeTool_ArgumentValidation pins Done-when 2/3: unknown args, a wrong-type/out-of-range limit, a
// negative/wrong-type depth, and a non-boolean flag are each rejected in-band.
func TestTreeTool_ArgumentValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	tool := newTreeToolIn(t, root)

	assertArgRejections(t, func(a map[string]any) (tools.Result, error) { return invokeTree(t, tool, a) }, []argRejectionCase{
		{"unknown arg", map[string]any{"bogus": 1}, "unexpected argument"},
		{"path wrong type", map[string]any{"path": 5}, "must be a string"},
		{"limit zero", map[string]any{"limit": 0}, "limit must be >= 1"},
		{"limit over max", map[string]any{"limit": TreeMaxLimit + 1}, "maximum of " + strconv.Itoa(TreeMaxLimit)},
		{"limit wrong type", map[string]any{"limit": "ten"}, "must be an integer"},
		{"limit fractional", map[string]any{"limit": 1.5}, "must be an integer"},
		{"depth negative", map[string]any{"depth": -1}, "depth must be >= 0"},
		{"depth wrong type", map[string]any{"depth": "deep"}, "must be an integer"},
		{"depth fractional", map[string]any{"depth": 2.5}, "must be an integer"},
		{"format unrecognized", map[string]any{"format": "fancy"}, `"format" must be "ai" or "human"`},
		{"format wrong type", map[string]any{"format": 7}, "must be a string"},
		{"include_hidden wrong type", map[string]any{"include_hidden": "yes"}, "must be a boolean"},
		{"include_ignored wrong type", map[string]any{"include_ignored": 1}, "must be a boolean"},
	})
}

// TestTreeTool_NonDirectoryPathRejected pins the directory precondition: a `path` naming a regular file is
// rejected in-band rather than walked.
func TestTreeTool_NonDirectoryPathRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "file.go"), "package x\n")
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, map[string]any{"path": "file.go"})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil (in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want a rejection for a non-directory path (stdout=%q)", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "not a directory") {
		t.Fatalf("Stderr = %q, want it to mention not a directory", res.Stderr)
	}
}

// TestTreeTool_DirectorySymlinkPathRejected pins at the path argument: as a recursive tool, tree
// refuses a directory-symlink `path` fail-closed before any walk (so a recursive walk cannot be redirected
// through it), mirroring grep — unlike the non-recursive list, which resolves and lists it.
func TestTreeTool_DirectorySymlinkPathRejected(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "realdir"))
	writeFile(t, filepath.Join(root, "realdir", "a.go"), "package realdir\n")
	if err := os.Symlink(filepath.Join(root, "realdir"), filepath.Join(root, "linkdir")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newTreeToolIn(t, root)

	res, err := invokeTree(t, tool, map[string]any{"path": "linkdir"})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil (in-band rejection)", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want a fail-closed rejection of a directory-symlink path (stdout=%q)", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "symlink") {
		t.Fatalf("Stderr = %q, want it to name the symlink rejection", res.Stderr)
	}
}

// TestTreeTool_ContainmentRejections pins: a `path` escaping the root (symlink to outside
// absolute outside, ../ traversal) is rejected fail-closed before any walk, with no out-of-root content
// leaked.
func TestTreeTool_ContainmentRejections(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "secret.go"), "package secret\n")
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newTreeToolIn(t, root)

	assertContainmentRejections(t, func(p string) (tools.Result, error) { return invokeTree(t, tool, map[string]any{"path": p}) },
		"secret", []pathCase{
			{"symlink escape dir", "escape"},
			{"absolute outside", outsideDir},
			{"dotdot traversal", "../" + filepath.Base(outsideDir)},
		})
}

// TestTreeTool_ResolveTargetScopeAndResolvedInvoke pins the target-scoped dispatch contract: ResolveTarget
// returns the resolved directory as both target and path scope, and InvokeWithResolvedTarget over that
// resolved target matches the standalone Invoke.
func TestTreeTool_ResolveTargetScopeAndResolvedInvoke(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "a.go"), "package sub\n")
	tool := newTreeToolIn(t, root)

	target, scope, err := tool.ResolveTarget(map[string]any{"path": "sub"})
	if err != nil {
		t.Fatalf("ResolveTarget error = %v", err)
	}
	wantDir := eval(t, filepath.Join(root, "sub"))
	if target != wantDir {
		t.Fatalf("ResolveTarget target = %q, want resolved %q", target, wantDir)
	}
	if scope != wantDir {
		t.Fatalf("ResolveTarget scope = %q, want the directory itself %q", scope, wantDir)
	}

	resolvedRes, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "sub"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v", err)
	}
	directRes, err := invokeTree(t, tool, map[string]any{"path": "sub"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	// Default ai layout emits project-relative paths, so a file under the walked subdir is "sub/a.go".
	if string(resolvedRes.Stdout) != string(directRes.Stdout) || string(resolvedRes.Stdout) != "sub/a.go\n" {
		t.Fatalf("resolved-target tree = %q, direct tree = %q, want %q", resolvedRes.Stdout, directRes.Stdout, "sub/a.go\n")
	}
}

// TestTreeTool_ResolvedRootSwappedToSymlinkRejected pins the reuse-at-invoke revalidation: if the
// authorized directory is replaced by a symlink to an outside directory between target resolution and
// invocation, tree must reject the now-symlink root in-band rather than let Walk's os.ReadDir follow it out
// of the project.
func TestTreeTool_ResolvedRootSwappedToSymlinkRejected(t *testing.T) {
	assertResolvedRootSwapRejected(t, func(root string) readNavTool { return newTreeToolIn(t, root) }, nil, "package secret\n")
}
