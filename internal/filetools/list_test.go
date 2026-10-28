// Unit tests for the built-in list tool: metadata/classification, non-recursive single-level listing with
// name+type output, deterministic ascending order, only-immediate-entries-count-toward-limit with the
// truncation metadata, symlink-entry classification without descent, hidden-skip + include_hidden,
// include_ignored acceptance, empty-directory success, default-path-is-root, argument validation, and the
// path-containment + reuse-at-invoke symlink rejections.
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

const listTestCap = 65536

// newListToolIn builds a list tool whose project root and relative-path base are root, with a separate home
// anchor, mirroring glob_test's newGlobToolIn.
func newListToolIn(t *testing.T, root string) *ListTool {
	t.Helper()
	return NewListTool(t.TempDir(), root, root, listTestCap)
}

// invokeList runs the list tool's full standalone path (ResolveTarget then list) and returns the result.
func invokeList(t *testing.T, tool *ListTool, args map[string]any) (tools.Result, error) {
	t.Helper()
	return tool.Invoke(context.Background(), args)
}

// listLines splits a successful list result's stdout into its "<type>\t<name>" lines (trailing newline
// dropped), asserting a zero exit so a rejection is not silently read as "empty directory".
func listLines(t *testing.T, res tools.Result) []string {
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

func TestListTool_AdvertiseMetadata(t *testing.T) {
	tool := newListToolIn(t, t.TempDir())

	if tool.Name() != "list" {
		t.Fatalf("Name() = %q, want list", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if !md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = false, want true (list is read-only, req 20)")
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
	// Every list argument is optional: required must be present and empty (path defaults to the root).
	if req, ok := md.Parameters["required"].([]string); !ok || len(req) != 0 {
		t.Fatalf("Parameters.required = %v, want an empty list (all args optional)", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties = %v, want a map", md.Parameters["properties"])
	}
	for _, key := range []string{"path", "limit", "include_ignored", "include_hidden"} {
		if _, ok := props[key]; !ok {
			t.Fatalf("Parameters.properties missing %q", key)
		}
	}
	assertOutsideScanAdvertise(t, md, "directory outside the project is listed without asking", "such a listing asks first")
}

// TestListTool_ImmediateEntriesWithType pins Done-when 1+2: list returns the directory's immediate entries
// only — name + type (file / dir / symlink) — in ascending name order, never descending into subdirectories
// (a file deep under a subdir does not appear).
func TestListTool_ImmediateEntriesWithType(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "deep.go"), "package sub\n")
	writeFile(t, filepath.Join(root, "b.go"), "package x\n")
	writeFile(t, filepath.Join(root, "a.txt"), "x\n")
	if err := os.Symlink(filepath.Join(root, "b.go"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newListToolIn(t, root)

	res, err := invokeList(t, tool, nil)
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := listLines(t, res)
	// Immediate entries only, ascending by name; each line is "<type>\t<name>". sub/deep.go is NOT listed —
	// list is non-recursive.
	want := []string{"file\ta.txt", "file\tb.go", "symlink\tlink", "dir\tsub"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list = %v, want %v (immediate entries, ascending, name+type)", got, want)
	}
}

// TestListTool_OnlyImmediateEntriesCountTowardLimit pins Done-when 2: a subdirectory holding many files
// counts as exactly one entry — its descendants are never traversed or counted — so a limit equal to the
// immediate-entry count is not truncated even though the tree holds far more files than the limit.
func TestListTool_OnlyImmediateEntriesCountTowardLimit(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "packed"))
	for _, n := range []string{"x1.go", "x2.go", "x3.go", "x4.go", "x5.go"} {
		writeFile(t, filepath.Join(root, "packed", n), "package packed\n")
	}
	writeFile(t, filepath.Join(root, "top.go"), "package top\n")
	tool := newListToolIn(t, root)

	// Two immediate entries (packed/, top.go); the five files under packed/ must not count. limit:2 fits
	// both immediate entries exactly, so the result is not truncated.
	res, err := invokeList(t, tool, map[string]any{"limit": 2})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := listLines(t, res)
	want := []string{"dir\tpacked", "file\ttop.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list(limit:2) = %v, want %v (descendants do not count)", got, want)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated {
		t.Fatalf("meta.Truncated = true, want false (only 2 immediate entries; descendants excluded)")
	}
}

// TestListTool_LimitAndTruncation pins Done-when 2: immediate entries are bounded by limit in ascending
// order, and the metadata signals truncation with reason "limit" when more immediate entries remain.
func TestListTool_LimitAndTruncation(t *testing.T) {
	assertLimitTruncation(t, func(root string) readNavTool { return newListToolIn(t, root) }, listLines, nil,
		[]string{"file\ta.go", "file\tb.go"}) // first 2 in ascending order
}

// TestListTool_SymlinkEntryNotFollowed pins Done-when 1 +: a symlink to a directory is reported as an
// entry of type symlink, and its target's contents are never listed (no descendant of the symlink target
// appears).
func TestListTool_SymlinkEntryNotFollowed(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "realdir"))
	writeFile(t, filepath.Join(root, "realdir", "inside.go"), "package realdir\n")
	if err := os.Symlink(filepath.Join(root, "realdir"), filepath.Join(root, "linkdir")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newListToolIn(t, root)

	res, err := invokeList(t, tool, nil)
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := listLines(t, res)
	// linkdir is classified as a symlink (not dir), and inside.go (a descendant of the symlink target) is
	// absent because list neither follows the symlink nor recurses.
	want := []string{"symlink\tlinkdir", "dir\trealdir"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list = %v, want %v (symlink entry typed symlink, target not followed)", got, want)
	}
}

// TestListTool_HiddenSkippedByDefaultAndOverride pins Done-when 3: dot-prefixed immediate
// entries are skipped by default and surfaced with include_hidden.
func TestListTool_HiddenSkippedByDefaultAndOverride(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, ".git"))
	writeFile(t, filepath.Join(root, "visible.go"), "package v\n")
	writeFile(t, filepath.Join(root, ".dotfile"), "secret\n")
	tool := newListToolIn(t, root)

	t.Run("hidden skipped by default", func(t *testing.T) {
		res, err := invokeList(t, tool, nil)
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := listLines(t, res)
		want := []string{"file\tvisible.go"} // .git and .dotfile filtered
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("list default = %v, want %v (hidden skipped)", got, want)
		}
	})

	t.Run("include_hidden surfaces dot entries", func(t *testing.T) {
		res, err := invokeList(t, tool, map[string]any{"include_hidden": true})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := listLines(t, res)
		want := []string{"file\t.dotfile", "dir\t.git", "file\tvisible.go"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("list include_hidden = %v, want %v", got, want)
		}
	})
}

// TestListTool_IncludeIgnoredAccepted pins Done-when 3 for include_ignored: the flag is accepted and the
// walk runs with it set. The fixture has no project or global codemeldignore file, so the walker's
// Ignore set is empty and include_ignored changes nothing here — this confirms the flag plumbs without
// error rather than asserting a filter is disabled.
func TestListTool_IncludeIgnoredAccepted(t *testing.T) {
	assertIncludeIgnoredAccepted(t, func(root string) readNavTool { return newListToolIn(t, root) }, listLines,
		nil, "package k\n", []string{"file\tkeep.go"})
}

// TestListTool_EmptyDirectoryEmptyNotError pins Done-when 4 (edge): an existing but empty directory
// returns a success with empty output and a not-truncated indicator, not an error.
func TestListTool_EmptyDirectoryEmptyNotError(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "empty"))
	tool := newListToolIn(t, root)

	res, err := invokeList(t, tool, map[string]any{"path": "empty"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	assertEmptySuccess(t, res)
}

// TestListTool_DefaultPathIsProjectRoot pins: an omitted path lists the project root's entries.
func TestListTool_DefaultPathIsProjectRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "rootfile.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "rootdir"))
	tool := newListToolIn(t, root)

	res, err := invokeList(t, tool, nil)
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := listLines(t, res)
	want := []string{"dir\trootdir", "file\trootfile.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list with default path = %v, want %v", got, want)
	}
}

// TestListTool_ExplicitRootEqualsDefault is the explicit-root regression: an explicit path equal to the
// project root (absolute, ".", "./", and trailing-slash forms) lists the same entries as omitting path.
func TestListTool_ExplicitRootEqualsDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "rootfile.go"), "package x\n")
	mkdirAll(t, filepath.Join(root, "rootdir"))
	tool := newListToolIn(t, root)

	assertExplicitRootEqualsDefault(t, func(a map[string]any) (tools.Result, error) { return invokeList(t, tool, a) },
		listLines, root, nil)
}

// TestListTool_SymlinkedDirectoryPathListed confirms list's non-recursive symlink policy at the path
// argument: unlike the recursive tools (which refuse a directory-symlink path), list resolves a symlinked
// directory `path` to its real in-root target and lists that directory's immediate entries.
func TestListTool_SymlinkedDirectoryPathListed(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "realdir"))
	writeFile(t, filepath.Join(root, "realdir", "a.go"), "package realdir\n")
	if err := os.Symlink(filepath.Join(root, "realdir"), filepath.Join(root, "linkdir")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newListToolIn(t, root)

	res, err := invokeList(t, tool, map[string]any{"path": "linkdir"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := listLines(t, res)
	if !reflect.DeepEqual(got, []string{"file\ta.go"}) {
		t.Fatalf("list(path:linkdir) = %v, want [file\\ta.go] (symlinked dir path is resolved and listed)", got)
	}
}

// TestListTool_ArgumentValidation pins Done-when 4: unknown args, a wrong-type/out-of-range limit, and a
// non-boolean flag are each rejected in-band.
func TestListTool_ArgumentValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	tool := newListToolIn(t, root)

	assertArgRejections(t, func(a map[string]any) (tools.Result, error) { return invokeList(t, tool, a) }, []argRejectionCase{
		{"unknown arg", map[string]any{"bogus": 1}, "unexpected argument"},
		{"path wrong type", map[string]any{"path": 5}, "must be a string"},
		{"limit zero", map[string]any{"limit": 0}, "limit must be >= 1"},
		{"limit over max", map[string]any{"limit": ListMaxLimit + 1}, "maximum of " + strconv.Itoa(ListMaxLimit)},
		{"limit wrong type", map[string]any{"limit": "ten"}, "must be an integer"},
		{"limit fractional", map[string]any{"limit": 1.5}, "must be an integer"},
		{"include_hidden wrong type", map[string]any{"include_hidden": "yes"}, "must be a boolean"},
		{"include_ignored wrong type", map[string]any{"include_ignored": 1}, "must be a boolean"},
	})
}

// TestListTool_NonDirectoryPathRejected pins the directory precondition: a `path` naming a regular file is
// rejected in-band rather than listed.
func TestListTool_NonDirectoryPathRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "file.go"), "package x\n")
	tool := newListToolIn(t, root)

	res, err := invokeList(t, tool, map[string]any{"path": "file.go"})
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

// TestListTool_ContainmentRejections pins: a `path` escaping the root (symlink to outside
// absolute outside, ../ traversal) is rejected fail-closed before any listing, with no out-of-root entry
// name leaked.
func TestListTool_ContainmentRejections(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "secret.go"), "package secret\n")
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newListToolIn(t, root)

	assertContainmentRejections(t, func(p string) (tools.Result, error) { return invokeList(t, tool, map[string]any{"path": p}) },
		"secret", []pathCase{
			{"symlink escape dir", "escape"},
			{"absolute outside", outsideDir},
			{"dotdot traversal", "../" + filepath.Base(outsideDir)},
		})
}

// TestListTool_ResolveTargetScopeAndResolvedInvoke pins the target-scoped dispatch contract: ResolveTarget
// returns the resolved directory as both target and path scope, and InvokeWithResolvedTarget over that
// resolved target matches the standalone Invoke.
func TestListTool_ResolveTargetScopeAndResolvedInvoke(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "a.go"), "package sub\n")
	tool := newListToolIn(t, root)

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
	directRes, err := invokeList(t, tool, map[string]any{"path": "sub"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if string(resolvedRes.Stdout) != string(directRes.Stdout) || string(resolvedRes.Stdout) != "file\ta.go\n" {
		t.Fatalf("resolved-target list = %q, direct list = %q, want %q", resolvedRes.Stdout, directRes.Stdout, "file\ta.go\n")
	}
}

// TestListTool_ResolvedRootSwappedToSymlinkRejected pins the reuse-at-invoke revalidation: if the
// authorized directory is replaced by a symlink to an outside directory between target resolution and
// invocation, list must reject the now-symlink root in-band rather than let Walk's os.ReadDir follow it out
// of the project.
func TestListTool_ResolvedRootSwappedToSymlinkRejected(t *testing.T) {
	assertResolvedRootSwapRejected(t, func(root string) readNavTool { return newListToolIn(t, root) }, nil, "package secret\n")
}
