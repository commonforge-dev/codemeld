// Unit tests for the built-in glob tool: metadata/classification, doublestar `**` recursive matching,
// search-root-relative matching with project-relative output, hidden-skip + include_hidden, include_ignored
// acceptance, limit/truncation metadata, malformed-pattern and argument rejections, no-match empty result,
// and the symlink/containment rejections.
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

const globTestCap = 65536

// newGlobToolIn builds a glob tool whose project root and relative-path base are root, with a separate home
// anchor, mirroring read_test's newReadToolIn.
func newGlobToolIn(t *testing.T, root string) *GlobTool {
	t.Helper()
	return NewGlobTool(t.TempDir(), root, root, globTestCap)
}

// invokeGlob runs the glob tool's full standalone path (ResolveTarget then glob) and returns the result.
func invokeGlob(t *testing.T, tool *GlobTool, args map[string]any) (tools.Result, error) {
	t.Helper()
	return tool.Invoke(context.Background(), args)
}

// globLines splits a successful glob result's stdout into its project-relative path lines (trailing newline
// dropped), asserting a zero exit so a hidden rejection is not silently read as "no matches".
func globLines(t *testing.T, res tools.Result) []string {
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

// mkdirAll creates a directory tree under the test root, failing the test on error.
func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", path, err)
	}
}

func TestGlobTool_AdvertiseMetadata(t *testing.T) {
	tool := newGlobToolIn(t, t.TempDir())

	if tool.Name() != "glob" {
		t.Fatalf("Name() = %q, want glob", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if !md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = false, want true (glob is read-only, req 20)")
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
	if req, ok := md.Parameters["required"].([]string); !ok || !reflect.DeepEqual(req, []string{"pattern"}) {
		t.Fatalf("Parameters.required = %v, want [pattern] only", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties = %v, want a map", md.Parameters["properties"])
	}
	for _, key := range []string{"pattern", "path", "limit", "include_ignored", "include_hidden"} {
		if _, ok := props[key]; !ok {
			t.Fatalf("Parameters.properties missing %q", key)
		}
	}
}

// TestGlobTool_RecursiveDoublestar pins Done-when 1: `**` matches across directories at any depth, a
// single `*` does not cross a path separator, and results are project-relative and ascending.
func TestGlobTool_RecursiveDoublestar(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "a", "b"))
	writeFile(t, filepath.Join(root, "top.go"), "package top\n")
	writeFile(t, filepath.Join(root, "a", "mid.go"), "package a\n")
	writeFile(t, filepath.Join(root, "a", "b", "deep.go"), "package b\n")
	writeFile(t, filepath.Join(root, "a", "notes.txt"), "x\n")
	tool := newGlobToolIn(t, root)

	t.Run("doublestar matches every depth", func(t *testing.T) {
		res, err := invokeGlob(t, tool, map[string]any{"pattern": "**/*.go"})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := globLines(t, res)
		want := []string{"a/b/deep.go", "a/mid.go", "top.go"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("glob(**/*.go) = %v, want %v (project-relative, ascending)", got, want)
		}
	})

	t.Run("single star does not cross a separator", func(t *testing.T) {
		res, err := invokeGlob(t, tool, map[string]any{"pattern": "*.go"})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := globLines(t, res)
		want := []string{"top.go"} // a/mid.go and a/b/deep.go are below the root, not matched by *.go
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("glob(*.go) = %v, want %v", got, want)
		}
	})
}

// TestGlobTool_SearchRootRelativeMatchProjectRelativeOutput pins Done-when 1 + the architecture-review
// matching basis: a pattern is matched against names relative to the search `path`, while the output stays
// project-relative.
func TestGlobTool_SearchRootRelativeMatchProjectRelativeOutput(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "internal", "filetools"))
	writeFile(t, filepath.Join(root, "internal", "filetools", "glob.go"), "package filetools\n")
	writeFile(t, filepath.Join(root, "internal", "filetools", "read.go"), "package filetools\n")
	writeFile(t, filepath.Join(root, "internal", "other.go"), "package internal\n")
	tool := newGlobToolIn(t, root)

	// "*.go" is matched relative to path=internal/filetools, so it matches files directly under it; output
	// is project-relative.
	res, err := invokeGlob(t, tool, map[string]any{"pattern": "*.go", "path": "internal/filetools"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := globLines(t, res)
	want := []string{"internal/filetools/glob.go", "internal/filetools/read.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("glob(*.go, path:internal/filetools) = %v, want %v", got, want)
	}
}

// TestGlobTool_HiddenSkippedByDefaultAndOverride pins Done-when 3: dot-prefixed entries are
// skipped by default and surfaced with include_hidden.
func TestGlobTool_HiddenSkippedByDefaultAndOverride(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, ".hidden"))
	writeFile(t, filepath.Join(root, "visible.go"), "package v\n")
	writeFile(t, filepath.Join(root, ".dotfile.go"), "package d\n")
	writeFile(t, filepath.Join(root, ".hidden", "inside.go"), "package h\n")
	tool := newGlobToolIn(t, root)

	t.Run("hidden skipped by default", func(t *testing.T) {
		res, err := invokeGlob(t, tool, map[string]any{"pattern": "**/*.go"})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := globLines(t, res)
		want := []string{"visible.go"} // .dotfile.go and the .hidden/ subtree are filtered
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("glob default = %v, want %v (hidden skipped)", got, want)
		}
	})

	t.Run("include_hidden surfaces dot entries", func(t *testing.T) {
		res, err := invokeGlob(t, tool, map[string]any{"pattern": "**/*.go", "include_hidden": true})
		if err != nil {
			t.Fatalf("Invoke error = %v", err)
		}
		got := globLines(t, res)
		want := []string{".dotfile.go", ".hidden/inside.go", "visible.go"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("glob include_hidden = %v, want %v", got, want)
		}
	})
}

// TestGlobTool_IncludeIgnoredAccepted pins Done-when 3 for include_ignored: the flag is accepted and the
// walk runs with it set. The fixture has no project or global codemeldignore file, so the walker's
// Ignore set is empty and include_ignored changes nothing here — this confirms the flag plumbs without
// error rather than asserting a filter is disabled.
func TestGlobTool_IncludeIgnoredAccepted(t *testing.T) {
	assertIncludeIgnoredAccepted(t, func(root string) readNavTool { return newGlobToolIn(t, root) }, globLines,
		map[string]any{"pattern": "**/*.go"}, "package k\n", []string{"keep.go"})
}

// TestGlobTool_MatchesDirectoriesAndSymlinks confirms the standard-glob decision: a pattern names a path
// regardless of its entry type, so directories and symlink entries can match (the symlink is reported, not
// followed).
func TestGlobTool_MatchesDirectoriesAndSymlinks(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "pkg"))
	writeFile(t, filepath.Join(root, "pkg", "a.go"), "package pkg\n")
	if err := os.Symlink(filepath.Join(root, "pkg"), filepath.Join(root, "linkpkg")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newGlobToolIn(t, root)

	res, err := invokeGlob(t, tool, map[string]any{"pattern": "*"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := globLines(t, res)
	// `*` matches the immediate entries: the dir pkg and the symlink linkpkg. The walker does not descend
	// the symlink, so pkg/a.go (which needs a separator) is absent under `*`.
	want := []string{"linkpkg", "pkg"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("glob(*) = %v, want %v (dir + symlink entries match; symlink not followed)", got, want)
	}
}

// TestGlobTool_LimitAndTruncation pins Done-when 1+4: results are bounded by limit (ascending), and the
// metadata signals truncation with reason "limit" when more matched.
func TestGlobTool_LimitAndTruncation(t *testing.T) {
	assertLimitTruncation(t, func(root string) readNavTool { return newGlobToolIn(t, root) }, globLines,
		map[string]any{"pattern": "*.go"}, []string{"a.go", "b.go"}) // first 2 in ascending order
}

// TestGlobTool_NoMatchEmptyNotError pins Done-when 4: no match is a success with empty output and a
// not-truncated indicator, not an error.
func TestGlobTool_NoMatchEmptyNotError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "x\n")
	tool := newGlobToolIn(t, root)

	res, err := invokeGlob(t, tool, map[string]any{"pattern": "**/*.go"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	assertEmptySuccess(t, res)
}

// TestGlobTool_MalformedPatternRejected pins Done-when 4: a malformed glob pattern is rejected in-band
// (non-zero exit, stderr reason), not crashed.
func TestGlobTool_MalformedPatternRejected(t *testing.T) {
	tool := newGlobToolIn(t, t.TempDir())

	for _, tc := range []struct{ name, pattern string }{
		{"unterminated class", "[abc"},
		{"unterminated alternation", "{a,b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := invokeGlob(t, tool, map[string]any{"pattern": tc.pattern})
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil (in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0 for %s, want a rejection (stdout=%q)", tc.name, res.Stdout)
			}
			if !strings.Contains(string(res.Stderr), "pattern") {
				t.Fatalf("Stderr = %q, want it to mention the pattern", res.Stderr)
			}
		})
	}
}

// TestGlobTool_ArgumentValidation pins Done-when 4: missing/empty pattern, unknown args, a non-boolean
// flag, and out-of-range/wrong-type limit are each rejected in-band.
func TestGlobTool_ArgumentValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package x\n")
	tool := newGlobToolIn(t, root)

	assertArgRejections(t, func(a map[string]any) (tools.Result, error) { return invokeGlob(t, tool, a) }, []argRejectionCase{
		{"missing pattern", map[string]any{}, "pattern"},
		{"empty pattern", map[string]any{"pattern": ""}, "non-empty"},
		{"unknown arg", map[string]any{"pattern": "*", "bogus": 1}, "unexpected argument"},
		{"pattern wrong type", map[string]any{"pattern": 5}, "must be a string"},
		{"limit zero", map[string]any{"pattern": "*", "limit": 0}, "limit must be >= 1"},
		{"limit over max", map[string]any{"pattern": "*", "limit": GlobMaxLimit + 1}, "maximum of " + strconv.Itoa(GlobMaxLimit)},
		{"limit wrong type", map[string]any{"pattern": "*", "limit": "ten"}, "must be an integer"},
		{"include_hidden wrong type", map[string]any{"pattern": "*", "include_hidden": "yes"}, "must be a boolean"},
		{"include_ignored wrong type", map[string]any{"pattern": "*", "include_ignored": 1}, "must be a boolean"},
	})
}

// TestGlobTool_ContainmentRejections pins: a `path` escaping the root (symlink, absolute
// outside, ../ traversal) and a directory-symlink `path` argument are all rejected fail-closed before any
// traversal, with no out-of-root content leaked.
func TestGlobTool_ContainmentRejections(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "secret.go"), "package secret\n")
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// An in-root directory symlink that points back inside the root: still refused as a path argument
	// because recursive tools must not be redirected through any directory symlink.
	mkdirAll(t, filepath.Join(root, "realdir"))
	if err := os.Symlink(filepath.Join(root, "realdir"), filepath.Join(root, "indirlink")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newGlobToolIn(t, root)

	assertContainmentRejections(t, func(p string) (tools.Result, error) {
		return invokeGlob(t, tool, map[string]any{"pattern": "**/*.go", "path": p})
	}, "secret", []pathCase{
		{"symlink escape dir", "escape"},
		{"absolute outside", outsideDir},
		{"dotdot traversal", "../" + filepath.Base(outsideDir)},
		{"in-root directory symlink", "indirlink"},
	})
}

// TestGlobTool_ResolveTargetScopeAndResolvedInvoke pins the target-scoped dispatch contract: ResolveTarget
// returns the resolved search directory as both target and path scope, and InvokeWithResolvedTarget over
// that resolved target matches the standalone Invoke.
func TestGlobTool_ResolveTargetScopeAndResolvedInvoke(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "a.go"), "package sub\n")
	tool := newGlobToolIn(t, root)

	target, scope, err := tool.ResolveTarget(map[string]any{"pattern": "**/*.go", "path": "sub"})
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

	resolvedRes, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"pattern": "**/*.go", "path": "sub"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v", err)
	}
	directRes, err := invokeGlob(t, tool, map[string]any{"pattern": "**/*.go", "path": "sub"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if string(resolvedRes.Stdout) != string(directRes.Stdout) || string(resolvedRes.Stdout) != "sub/a.go\n" {
		t.Fatalf("resolved-target glob = %q, direct glob = %q, want %q", resolvedRes.Stdout, directRes.Stdout, "sub/a.go\n")
	}
}

// TestGlobTool_ResolvedRootSwappedToSymlinkRejected pins the reuse-at-invoke revalidation: if the
// authorized search directory is replaced by a symlink to an outside directory between target resolution
// and invocation, glob must reject the now-symlink root in-band rather than let Walk's os.ReadDir follow it
// out of the project. On the pre-guard implementation this leaked the outside secret.go; the in-band guard
// makes it a fail-closed rejection.
func TestGlobTool_ResolvedRootSwappedToSymlinkRejected(t *testing.T) {
	assertResolvedRootSwapRejected(t, func(root string) readNavTool { return newGlobToolIn(t, root) },
		map[string]any{"pattern": "**/*.go"}, "package secret\n")
}

// TestGlobTool_DefaultPathIsProjectRoot pins: an omitted path defaults to the project root.
func TestGlobTool_DefaultPathIsProjectRoot(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "x"))
	writeFile(t, filepath.Join(root, "x", "a.go"), "package x\n")
	tool := newGlobToolIn(t, root)

	res, err := invokeGlob(t, tool, map[string]any{"pattern": "**/*.go"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	got := globLines(t, res)
	if !reflect.DeepEqual(got, []string{"x/a.go"}) {
		t.Fatalf("glob with default path = %v, want [x/a.go]", got)
	}
}

// TestGlobTool_ExplicitRootEqualsDefault is the explicit-root regression: an explicit path equal to the
// project root (absolute, ".", "./", and trailing-slash forms) returns the same matches as omitting path.
func TestGlobTool_ExplicitRootEqualsDefault(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "x"))
	writeFile(t, filepath.Join(root, "x", "a.go"), "package x\n")
	tool := newGlobToolIn(t, root)

	assertExplicitRootEqualsDefault(t, func(a map[string]any) (tools.Result, error) { return invokeGlob(t, tool, a) },
		globLines, root, map[string]any{"pattern": "**/*.go"})
}
