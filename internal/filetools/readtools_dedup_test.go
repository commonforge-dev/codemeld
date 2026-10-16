// Shared test-only helpers for the read-only navigation tools (list, tree, glob, grep, read). They fold the
// argument-validation, containment-rejection, explicit-root-equals-default, limit/truncation,
// include-ignored, empty-result, and reuse-at-invoke symlink-swap patterns that were repeated near-verbatim
// across the per-tool *_test.go files into one parameterized place, each keyed by the tool's constructor,
// invocation, and output-parsing seam so every call site stays explicit about that tool's behavior.
package filetools

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/tools"
)

// readNavTool is the seam the five read-only navigation tools share: the standalone Invoke, the resolved-target
// reuse path, and pre-authorization target resolution. *ListTool, *TreeTool, *GlobTool, *GrepTool, and
// *ReadTool all satisfy it, so one helper can drive any of them.
type readNavTool interface {
	Invoke(ctx context.Context, args map[string]any) (tools.Result, error)
	InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error)
	ResolveTarget(args map[string]any) (target string, scope string, err error)
}

// linesFn parses a successful tool result's stdout into its output lines (listLines, treeLines, globLines,
// grepLines).
type linesFn func(t *testing.T, res tools.Result) []string

// mergeArgs returns base with extra overlaid, leaving both inputs untouched so a shared baseArgs map can be
// reused across cases.
func mergeArgs(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// argRejectionCase is one malformed-argument call and the stderr substring its in-band rejection must carry.
// An empty wantInMsg asserts only that the call is rejected (used by read's required-path/unknown-arg table,
// which checks the exit code but not a specific message).
type argRejectionCase struct {
	name      string
	args      map[string]any
	wantInMsg string
}

// assertArgRejections runs each malformed-argument case through invoke and asserts an in-band rejection (nil
// Go error, non-zero exit) whose stderr contains wantInMsg. Shared by the per-tool argument-validation and
// numeric-boundary tables.
func assertArgRejections(t *testing.T, invoke func(map[string]any) (tools.Result, error), cases []argRejectionCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := invoke(tc.args)
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil (in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0 for %s, want a rejection (stdout=%q)", tc.name, res.Stdout)
			}
			if !strings.Contains(string(res.Stderr), tc.wantInMsg) {
				t.Fatalf("Stderr = %q, want it to contain %q", res.Stderr, tc.wantInMsg)
			}
		})
	}
}

// assertContainmentRejections runs each out-of-root path case through invokePath and asserts a fail-closed
// in-band rejection (nil Go error, non-zero exit) that leaks no out-of-root content — the canary token must
// not appear in stdout. invokePath builds the tool's arguments for a path and invokes it.
func assertContainmentRejections(t *testing.T, invokePath func(path string) (tools.Result, error), canary string, cases []pathCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.caseName, func(t *testing.T) {
			res, err := invokePath(tc.path)
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil (in-band rejection)", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0 for %s, want a fail-closed rejection (stdout=%q)", tc.caseName, res.Stdout)
			}
			if strings.Contains(string(res.Stdout), canary) {
				t.Fatalf("Stdout leaked out-of-root content for %s: %q", tc.caseName, res.Stdout)
			}
		})
	}
}

// assertExplicitRootEqualsDefault pins that every rootPathForms spelling of the project root returns the
// same output lines as an omitted path. baseArgs carry the tool's non-path arguments (e.g. the glob/grep
// pattern); a nil baseArgs means the tool has none.
func assertExplicitRootEqualsDefault(t *testing.T, invoke func(map[string]any) (tools.Result, error), lines linesFn, root string, baseArgs map[string]any) {
	t.Helper()
	base, err := invoke(mergeArgs(baseArgs, nil))
	if err != nil {
		t.Fatalf("Invoke (default path) error = %v", err)
	}
	want := lines(t, base)
	if len(want) == 0 {
		t.Fatal("default-path result returned no entries; fixture is wrong")
	}
	for _, f := range rootPathForms(root) {
		t.Run(f.name, func(t *testing.T) {
			res, err := invoke(mergeArgs(baseArgs, map[string]any{"path": f.path}))
			if err != nil {
				t.Fatalf("Invoke(path=%q) error = %v", f.path, err)
			}
			if got := lines(t, res); !reflect.DeepEqual(got, want) {
				t.Fatalf("result(path=%q) = %v, want %v (same as omitted path)", f.path, got, want)
			}
		})
	}
}

// assertLimitTruncation writes five sibling .go files, runs the tool with limit:2, and asserts the first two
// entries (in the tool's output form, ascending) plus truncated/reason=limit metadata. baseArgs carry any
// required pattern.
func assertLimitTruncation(t *testing.T, newTool func(root string) readNavTool, lines linesFn, baseArgs map[string]any, wantFirstTwo []string) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.go", "d.go", "e.go"} {
		writeFile(t, filepath.Join(root, name), "package x\n")
	}
	tool := newTool(root)

	res, err := tool.Invoke(context.Background(), mergeArgs(baseArgs, map[string]any{"limit": 2}))
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if got := lines(t, res); !reflect.DeepEqual(got, wantFirstTwo) {
		t.Fatalf("limit:2 = %v, want %v (first 2 ascending)", got, wantFirstTwo)
	}
	meta := parseMeta(t, res.Stderr)
	if !meta.Truncated || meta.TruncationReason != TruncationReasonLimit {
		t.Fatalf("meta = %+v, want truncated with reason limit", meta)
	}
}

// assertIncludeIgnoredAccepted pins that include_ignored is accepted (and a no-op here, as the fixture has no
// project or global codemeldignore file): a single keep.go is returned unchanged for both false and true.
// fileContent is the tool-appropriate file body; want is the expected single output line.
func assertIncludeIgnoredAccepted(t *testing.T, newTool func(root string) readNavTool, lines linesFn, baseArgs map[string]any, fileContent string, want []string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.go"), fileContent)
	tool := newTool(root)

	for _, val := range []bool{false, true} {
		res, err := tool.Invoke(context.Background(), mergeArgs(baseArgs, map[string]any{"include_ignored": val}))
		if err != nil {
			t.Fatalf("Invoke(include_ignored=%v) error = %v", val, err)
		}
		if got := lines(t, res); !reflect.DeepEqual(got, want) {
			t.Fatalf("include_ignored=%v = %v, want %v", val, got, want)
		}
	}
}

// assertEmptySuccess asserts a result is a zero-exit success with empty stdout and not-truncated metadata —
// the shared shape of the empty-directory, depth-0, and no-match cases.
func assertEmptySuccess(t *testing.T, res tools.Result) {
	t.Helper()
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d (stderr=%q), want 0 (an empty result is empty, not an error)", res.ExitCode, res.Stderr)
	}
	if len(res.Stdout) != 0 {
		t.Fatalf("Stdout = %q, want empty", res.Stdout)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated {
		t.Fatalf("meta.Truncated = true for an empty result, want false")
	}
}

// assertResolvedRootSwapRejected pins the reuse-at-invoke revalidation: after a target is resolved
// swapping the authorized in-root directory for a symlink to an outside directory must yield a fail-closed
// in-band rejection at InvokeWithResolvedTarget, with no out-of-root content leaked. baseArgs carry any
// required pattern; secretContent is the outside file's body (it must match a grep pattern when one is given,
// so a followed swap would be observable).
func assertResolvedRootSwapRejected(t *testing.T, newTool func(root string) readNavTool, baseArgs map[string]any, secretContent string) {
	t.Helper()
	root := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "secret.go"), secretContent)
	realDir := filepath.Join(root, "data")
	mkdirAll(t, realDir)
	writeFile(t, filepath.Join(realDir, "in.go"), "package data\n")
	tool := newTool(root)

	args := mergeArgs(baseArgs, map[string]any{"path": "data"})
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v", err)
	}

	// Swap the authorized real directory for a symlink to the outside directory after authorization.
	if err := os.RemoveAll(realDir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.Symlink(outsideDir, realDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil (in-band rejection)", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want a fail-closed rejection (stdout=%q)", res.Stdout)
	}
	if strings.Contains(string(res.Stdout), "secret") {
		t.Fatalf("Stdout leaked out-of-root content: %q", res.Stdout)
	}
}
