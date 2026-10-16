// Unit tests for the built-in grep tool: metadata/classification, path-then-line ordering, match/context
// distinction with merged context windows, files_only, match-count limit + truncation (context excluded),
// RE2 compile-error rejection (with/without case-insensitivity), include basename filtering, case
// insensitivity, binary-file skip + notice, hidden-skip + include_hidden, include_ignored acceptance,
// long-line search, no-match empty result, the symlink/containment rejections, and the resolved-target
// dispatch contract.
package filetools

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

const grepTestCap = 65536

// newGrepToolIn builds a grep tool whose project root and relative-path base are root, with a separate
// home anchor, mirroring glob_test's newGlobToolIn.
func newGrepToolIn(t *testing.T, root string) *GrepTool {
	t.Helper()
	return NewGrepTool(t.TempDir(), root, root, grepTestCap)
}

// invokeGrep runs the grep tool's full standalone path (ResolveTarget then grep) and returns the result.
func invokeGrep(t *testing.T, tool *GrepTool, args map[string]any) (tools.Result, error) {
	t.Helper()
	res, err := tool.Invoke(context.Background(), args)
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil (in-band)", err)
	}
	return res, nil
}

// grepLines splits a successful grep result's stdout into its output lines (trailing newline dropped),
// asserting a zero exit so a rejection is not silently read as "no matches".
func grepLines(t *testing.T, res tools.Result) []string {
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

func TestGrepTool_AdvertiseMetadata(t *testing.T) {
	tool := newGrepToolIn(t, t.TempDir())

	if tool.Name() != "grep" {
		t.Fatalf("Name() = %q, want grep", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if !md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = false, want true (grep is read-only, req 20)")
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
	// the exact parameter set, no more, no less.
	want := []string{"pattern", "path", "include", "case_insensitive", "context", "limit", "files_only", "include_ignored", "include_hidden"}
	for _, key := range want {
		if _, ok := props[key]; !ok {
			t.Fatalf("Parameters.properties missing %q", key)
		}
	}
	if len(props) != len(want) {
		t.Fatalf("Parameters.properties has %d keys, want exactly %d (%v)", len(props), len(want), want)
	}
}

// TestGrepTool_OrderingPathThenLine pins Done-when 1: matches are emitted by ascending
// project-relative path then ascending line, formatted path:line:match:text.
func TestGrepTool_OrderingPathThenLine(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "a.go"), "foo\nbar\nfoo\n")
	writeFile(t, filepath.Join(root, "m.txt"), "foo\n")
	writeFile(t, filepath.Join(root, "sub", "b.go"), "x\nfoo\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo"})
	got := grepLines(t, res)
	want := []string{
		"a.go:1:match:foo",
		"a.go:3:match:foo",
		"m.txt:1:match:foo",
		"sub/b.go:2:match:foo",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grep(foo) = %v\nwant %v (ascending path then line)", got, want)
	}
}

// TestGrepTool_MatchAndContextDistinguished pins Done-when 2: match lines are marked match and the
// `context` lines before/after are marked context, with clamping at file edges.
func TestGrepTool_MatchAndContextDistinguished(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.go"), "line1\nMATCH\nline3\nline4\n")
	tool := newGrepToolIn(t, root)

	t.Run("context 1 around an interior match", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "MATCH", "context": 1})
		got := grepLines(t, res)
		want := []string{
			"f.go:1:context:line1",
			"f.go:2:match:MATCH",
			"f.go:3:context:line3",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("grep(MATCH, context:1) = %v\nwant %v", got, want)
		}
	})

	t.Run("context clamps at the first line", func(t *testing.T) {
		writeFile(t, filepath.Join(root, "top.go"), "HIT\nb\n")
		res, _ := invokeGrep(t, newGrepToolIn(t, root), map[string]any{"pattern": "HIT", "context": 2})
		got := grepLines(t, res)
		want := []string{"top.go:1:match:HIT", "top.go:2:context:b"} // no line 0
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("grep(HIT, context:2) = %v\nwant %v (clamped at line 1)", got, want)
		}
	})
}

// TestGrepTool_ContextWindowsMerged pins the architecture-review decision: overlapping/adjacent context
// windows merge so a line between two near matches is emitted once, not duplicated.
func TestGrepTool_ContextWindowsMerged(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.go"), "a\nM\nb\nM\nc\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "M", "context": 1})
	got := grepLines(t, res)
	want := []string{
		"f.go:1:context:a",
		"f.go:2:match:M",
		"f.go:3:context:b", // shared by both windows, emitted once as context
		"f.go:4:match:M",
		"f.go:5:context:c",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged context = %v\nwant %v (line 3 once, as context)", got, want)
	}
}

// TestGrepTool_FilesOnly pins Done-when 2: files_only returns only matching file paths, ascending
// with no match/context line markers.
func TestGrepTool_FilesOnly(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "a.go"), "foo\nfoo\n") // two matches, one path
	writeFile(t, filepath.Join(root, "sub", "b.go"), "foo\n")
	writeFile(t, filepath.Join(root, "none.go"), "bar\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo", "files_only": true})
	got := grepLines(t, res)
	want := []string{"a.go", "sub/b.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grep(files_only) = %v, want %v", got, want)
	}
	if strings.Contains(string(res.Stdout), ":match:") {
		t.Fatalf("files_only output %q contains match markers, want bare paths", res.Stdout)
	}
}

// TestGrepTool_LimitBoundsMatchesNotContext pins Done-when 3: limit caps the match count
// (not context lines) and the result signals truncation when more match.
func TestGrepTool_LimitBoundsMatchesNotContext(t *testing.T) {
	t.Run("limit caps matches across files with truncation", func(t *testing.T) {
		root := t.TempDir()
		for _, n := range []string{"a.go", "b.go", "c.go", "d.go"} {
			writeFile(t, filepath.Join(root, n), "M\n")
		}
		tool := newGrepToolIn(t, root)

		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "M", "limit": 2})
		got := grepLines(t, res)
		want := []string{"a.go:1:match:M", "b.go:1:match:M"} // first 2 in path order
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("grep(limit:2) = %v, want %v", got, want)
		}
		meta := parseMeta(t, res.Stderr)
		if !meta.Truncated || meta.TruncationReason != TruncationReasonLimit {
			t.Fatalf("meta = %+v, want truncated with reason limit", meta)
		}
	})

	t.Run("context lines do not count toward the limit", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "f.go"), "a\nM\nb\n")
		tool := newGrepToolIn(t, root)

		// One match, limit 1, context 1: three lines are emitted (a, M, b) but only the single match counts,
		// so the limit is not exceeded and the result is not truncated.
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "M", "limit": 1, "context": 1})
		got := grepLines(t, res)
		want := []string{"f.go:1:context:a", "f.go:2:match:M", "f.go:3:context:b"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("grep(limit:1, context:1) = %v, want %v", got, want)
		}
		if meta := parseMeta(t, res.Stderr); meta.Truncated {
			t.Fatalf("meta.Truncated = true, want false (1 match <= limit 1; context not counted)")
		}
	})

	t.Run("files_only limit bounds matching files", func(t *testing.T) {
		root := t.TempDir()
		for _, n := range []string{"a.go", "b.go", "c.go"} {
			writeFile(t, filepath.Join(root, n), "M\n")
		}
		tool := newGrepToolIn(t, root)

		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "M", "files_only": true, "limit": 2})
		got := grepLines(t, res)
		if !reflect.DeepEqual(got, []string{"a.go", "b.go"}) {
			t.Fatalf("grep(files_only, limit:2) = %v, want [a.go b.go]", got)
		}
		if meta := parseMeta(t, res.Stderr); !meta.Truncated || meta.TruncationReason != TruncationReasonLimit {
			t.Fatalf("meta = %+v, want truncated with reason limit", meta)
		}
	})
}

// TestGrepTool_RE2CompileErrorRejected pins Done-when 4: a pattern RE2 cannot compile is rejected
// in-band with the RE2 compile error, both with and without case_insensitive (task note).
func TestGrepTool_RE2CompileErrorRejected(t *testing.T) {
	tool := newGrepToolIn(t, t.TempDir())

	patterns := []struct{ name, pattern string }{
		{"backreference", `(a)\1`},
		{"lookahead", `(?=foo)`},
	}
	for _, p := range patterns {
		for _, ci := range []bool{false, true} {
			name := p.name
			if ci {
				name += "/case_insensitive"
			}
			t.Run(name, func(t *testing.T) {
				res, _ := invokeGrep(t, tool, map[string]any{"pattern": p.pattern, "case_insensitive": ci})
				if res.ExitCode == 0 {
					t.Fatalf("ExitCode = 0 for %q, want a rejection (stdout=%q)", p.pattern, res.Stdout)
				}
				// the in-band error must include the RE2 compile error text.
				if !strings.Contains(string(res.Stderr), "error parsing regexp") {
					t.Fatalf("Stderr = %q, want it to include the RE2 compile error", res.Stderr)
				}
				if !strings.Contains(string(res.Stderr), "cannot compile pattern") {
					t.Fatalf("Stderr = %q, want it to name the compile failure", res.Stderr)
				}
			})
		}
	}
}

// TestGrepTool_CaseInsensitive pins the case_insensitive flag: it matches regardless of letter case, and
// the default (false) does not.
func TestGrepTool_CaseInsensitive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.go"), "FOO\n")
	tool := newGrepToolIn(t, root)

	t.Run("case-sensitive default misses", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo"})
		if got := grepLines(t, res); len(got) != 0 {
			t.Fatalf("grep(foo) = %v, want no match (case-sensitive)", got)
		}
	})
	t.Run("case_insensitive matches", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo", "case_insensitive": true})
		got := grepLines(t, res)
		if !reflect.DeepEqual(got, []string{"f.go:1:match:FOO"}) {
			t.Fatalf("grep(foo, case_insensitive) = %v, want [f.go:1:match:FOO]", got)
		}
	})
}

// TestGrepTool_IncludeBasenameFilter pins Done-when 1: include is a glob on the file *name*
// (basename), independent of the path, selecting which files are searched.
func TestGrepTool_IncludeBasenameFilter(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "keep.go"), "needle\n")
	writeFile(t, filepath.Join(root, "skip.txt"), "needle\n")
	writeFile(t, filepath.Join(root, "sub", "deep.go"), "needle\n") // basename deep.go matches *.go
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "needle", "include": "*.go"})
	got := grepLines(t, res)
	want := []string{"keep.go:1:match:needle", "sub/deep.go:1:match:needle"} // skip.txt excluded
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grep(include:*.go) = %v, want %v", got, want)
	}
}

// TestGrepTool_BinarySkipped pins Done-when 5: a binary file is not searched and its bytes never
// reach the output; a short notice records the skip.
func TestGrepTool_BinarySkipped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "text.go"), "hello\n")
	writeFile(t, filepath.Join(root, "bin.dat"), "hello\x00world\n") // contains the pattern but is binary
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "hello"})
	got := grepLines(t, res)
	if !reflect.DeepEqual(got, []string{"text.go:1:match:hello"}) {
		t.Fatalf("grep over text+binary = %v, want only the text-file match", got)
	}
	if strings.Contains(string(res.Stdout), "bin.dat") || strings.Contains(string(res.Stdout), "world") {
		t.Fatalf("Stdout leaked binary-file content: %q", res.Stdout)
	}
	if strings.IndexByte(string(res.Stdout), 0) >= 0 {
		t.Fatal("Stdout contains a NUL byte from the binary file")
	}
	if !strings.Contains(string(res.Stderr), "binary") {
		t.Fatalf("Stderr = %q, want a binary-skip notice", res.Stderr)
	}
}

// TestGrepTool_HiddenSkippedByDefaultAndOverride pins Done-when 5: dot-prefixed entries are
// skipped by default and surfaced with include_hidden.
func TestGrepTool_HiddenSkippedByDefaultAndOverride(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, ".hidden"))
	writeFile(t, filepath.Join(root, "visible.go"), "foo\n")
	writeFile(t, filepath.Join(root, ".dotfile.go"), "foo\n")
	writeFile(t, filepath.Join(root, ".hidden", "inside.go"), "foo\n")
	tool := newGrepToolIn(t, root)

	t.Run("hidden skipped by default", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo"})
		got := grepLines(t, res)
		if !reflect.DeepEqual(got, []string{"visible.go:1:match:foo"}) {
			t.Fatalf("grep default = %v, want only visible.go (hidden skipped)", got)
		}
	})
	t.Run("include_hidden surfaces dot entries", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo", "include_hidden": true})
		got := grepLines(t, res)
		want := []string{
			".dotfile.go:1:match:foo",
			".hidden/inside.go:1:match:foo",
			"visible.go:1:match:foo",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("grep include_hidden = %v, want %v", got, want)
		}
	})
}

// TestGrepTool_IncludeIgnoredAccepted pins Done-when 5 for include_ignored: the flag is accepted and the
// walk runs with it set. The fixture has no project or global codemeldignore file, so the walker's
// Ignore set is empty and include_ignored changes nothing here — this confirms the flag plumbs without error.
func TestGrepTool_IncludeIgnoredAccepted(t *testing.T) {
	assertIncludeIgnoredAccepted(t, func(root string) readNavTool { return newGrepToolIn(t, root) }, grepLines,
		map[string]any{"pattern": "foo"}, "foo\n", []string{"keep.go:1:match:foo"})
}

// TestGrepTool_SymlinkFileNotSearched pins: grep searches only regular files, so a symlink (even to
// a regular file outside the root) is never read through, and its target's content cannot leak.
func TestGrepTool_SymlinkFileNotSearched(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "needle\n")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	writeFile(t, filepath.Join(root, "real.go"), "needle\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "needle"})
	got := grepLines(t, res)
	if !reflect.DeepEqual(got, []string{"real.go:1:match:needle"}) {
		t.Fatalf("grep over real+symlink = %v, want only the real file (symlink not searched)", got)
	}
	if strings.Contains(string(res.Stdout), "link.txt") {
		t.Fatalf("Stdout searched through a symlink: %q", res.Stdout)
	}
}

// TestGrepTool_LongLineSearched pins the task note: a line longer than bufio.Scanner's default token limit
// is searched without a silent failure (the implementation splits by byte slice, not Scanner).
func TestGrepTool_LongLineSearched(t *testing.T) {
	root := t.TempDir()
	longLine := strings.Repeat("a", 200000) + "needle"
	writeFile(t, filepath.Join(root, "big.go"), longLine+"\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "needle"})
	got := grepLines(t, res)
	if len(got) != 1 || !strings.HasPrefix(got[0], "big.go:1:match:") || !strings.HasSuffix(got[0], "needle") {
		t.Fatalf("grep over a very long line returned %d lines (first=%.40q...), want one match on line 1", len(got), got)
	}
}

// TestGrepTool_NoMatchEmptyNotError pins Done-when output semantics: no match is a success with empty output
// and a not-truncated indicator, not an error.
func TestGrepTool_NoMatchEmptyNotError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "bar\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo"})
	assertEmptySuccess(t, res)
}

// TestGrepTool_DefaultPathIsProjectRoot pins: an omitted path defaults to the project root.
func TestGrepTool_DefaultPathIsProjectRoot(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "x"))
	writeFile(t, filepath.Join(root, "x", "a.go"), "foo\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo"})
	if got := grepLines(t, res); !reflect.DeepEqual(got, []string{"x/a.go:1:match:foo"}) {
		t.Fatalf("grep with default path = %v, want [x/a.go:1:match:foo]", got)
	}
}

// TestGrepTool_ExplicitRootEqualsDefault is the explicit-root regression: an explicit path equal to the
// project root (absolute, ".", "./", and trailing-slash forms) returns the same matches as omitting path.
func TestGrepTool_ExplicitRootEqualsDefault(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "x"))
	writeFile(t, filepath.Join(root, "x", "a.go"), "foo\n")
	tool := newGrepToolIn(t, root)

	assertExplicitRootEqualsDefault(t, func(a map[string]any) (tools.Result, error) { return invokeGrep(t, tool, a) },
		grepLines, root, map[string]any{"pattern": "foo"})
}

// TestGrepTool_PathScopesSearch pins: a `path` argument confines the search to that subtree, while
// output stays project-relative.
func TestGrepTool_PathScopesSearch(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "in"))
	mkdirAll(t, filepath.Join(root, "out"))
	writeFile(t, filepath.Join(root, "in", "a.go"), "foo\n")
	writeFile(t, filepath.Join(root, "out", "b.go"), "foo\n")
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo", "path": "in"})
	if got := grepLines(t, res); !reflect.DeepEqual(got, []string{"in/a.go:1:match:foo"}) {
		t.Fatalf("grep(path:in) = %v, want only in/a.go", got)
	}
}

// TestGrepTool_ArgumentValidation pins Done-when 4: each malformed argument is
// rejected in-band (non-zero exit, stderr reason), not crashed.
func TestGrepTool_ArgumentValidation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "foo\n")
	tool := newGrepToolIn(t, root)

	assertArgRejections(t, func(a map[string]any) (tools.Result, error) { return invokeGrep(t, tool, a) }, []argRejectionCase{
		{"missing pattern", map[string]any{}, "pattern"},
		{"empty pattern", map[string]any{"pattern": ""}, "non-empty"},
		{"unknown arg", map[string]any{"pattern": "x", "bogus": 1}, "unexpected argument"},
		{"pattern wrong type", map[string]any{"pattern": 5}, "must be a string"},
		{"include wrong type", map[string]any{"pattern": "x", "include": 5}, "must be a string"},
		{"malformed include glob", map[string]any{"pattern": "x", "include": "[abc"}, "malformed include glob"},
		{"limit zero", map[string]any{"pattern": "x", "limit": 0}, "limit must be >= 1"},
		{"limit over max", map[string]any{"pattern": "x", "limit": GrepMaxLimit + 1}, "maximum of " + strconv.Itoa(GrepMaxLimit)},
		{"limit wrong type", map[string]any{"pattern": "x", "limit": "ten"}, "must be an integer"},
		{"context negative", map[string]any{"pattern": "x", "context": -1}, "context must be >= 0"},
		{"context wrong type", map[string]any{"pattern": "x", "context": "one"}, "must be an integer"},
		{"case_insensitive wrong type", map[string]any{"pattern": "x", "case_insensitive": "yes"}, "must be a boolean"},
		{"files_only wrong type", map[string]any{"pattern": "x", "files_only": 1}, "must be a boolean"},
		{"include_hidden wrong type", map[string]any{"pattern": "x", "include_hidden": "yes"}, "must be a boolean"},
		{"include_ignored wrong type", map[string]any{"pattern": "x", "include_ignored": 1}, "must be a boolean"},
	})
}

// TestGrepTool_ContainmentRejections pins: a `path` escaping the root (symlink, absolute
// outside, ../ traversal) and a directory-symlink `path` argument are all rejected fail-closed before any
// traversal, with no out-of-root content leaked.
func TestGrepTool_ContainmentRejections(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "secret.go"), "needle\n")
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	mkdirAll(t, filepath.Join(root, "realdir"))
	if err := os.Symlink(filepath.Join(root, "realdir"), filepath.Join(root, "indirlink")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newGrepToolIn(t, root)

	assertContainmentRejections(t, func(p string) (tools.Result, error) {
		return invokeGrep(t, tool, map[string]any{"pattern": "needle", "path": p})
	}, "needle", []pathCase{
		{"symlink escape dir", "escape"},
		{"absolute outside", outsideDir},
		{"dotdot traversal", "../" + filepath.Base(outsideDir)},
		{"in-root directory symlink", "indirlink"},
	})
}

// TestGrepTool_ResolveTargetScopeAndResolvedInvoke pins the target-scoped dispatch contract: ResolveTarget
// returns the resolved search directory as both target and path scope, and InvokeWithResolvedTarget over
// that resolved target matches the standalone Invoke.
func TestGrepTool_ResolveTargetScopeAndResolvedInvoke(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "a.go"), "foo\n")
	tool := newGrepToolIn(t, root)

	target, scope, err := tool.ResolveTarget(map[string]any{"pattern": "foo", "path": "sub"})
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

	resolvedRes, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"pattern": "foo", "path": "sub"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v", err)
	}
	directRes, _ := invokeGrep(t, tool, map[string]any{"pattern": "foo", "path": "sub"})
	if string(resolvedRes.Stdout) != string(directRes.Stdout) || string(resolvedRes.Stdout) != "sub/a.go:1:match:foo\n" {
		t.Fatalf("resolved-target grep = %q, direct grep = %q, want %q", resolvedRes.Stdout, directRes.Stdout, "sub/a.go:1:match:foo\n")
	}
}

// TestGrepTool_ResolvedRootSwappedToSymlinkRejected pins the reuse-at-invoke revalidation: if the
// authorized search directory is replaced by a symlink to an outside directory between target resolution
// and invocation, grep must reject the now-symlink root in-band rather than let Walk's os.ReadDir follow it
// out of the project.
func TestGrepTool_ResolvedRootSwappedToSymlinkRejected(t *testing.T) {
	assertResolvedRootSwapRejected(t, func(root string) readNavTool { return newGrepToolIn(t, root) },
		map[string]any{"pattern": "needle"}, "needle\n")
}

func TestGrepTool_NamedFileSearched(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "sub", "f.go"), "a\nM\nb\nc\nM\n")
	writeFile(t, filepath.Join(root, "sub", "other.go"), "M\n")
	tool := newGrepToolIn(t, root)

	t.Run("context", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "M", "path": "sub/f.go", "context": 1})
		want := []string{"sub/f.go:1:context:a", "sub/f.go:2:match:M", "sub/f.go:3:context:b", "sub/f.go:4:context:c", "sub/f.go:5:match:M"}
		if got := grepLines(t, res); !reflect.DeepEqual(got, want) {
			t.Fatalf("grep(named file, context:1) = %v\nwant %v", got, want)
		}
	})
	t.Run("limit", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "M", "path": "sub/f.go", "limit": 1})
		if got := grepLines(t, res); !reflect.DeepEqual(got, []string{"sub/f.go:2:match:M"}) {
			t.Fatalf("grep(named file, limit:1) = %v, want [sub/f.go:2:match:M]", got)
		}
		if meta := parseMeta(t, res.Stderr); !meta.Truncated || meta.TruncationReason != TruncationReasonLimit {
			t.Fatalf("meta = %+v, want truncated with reason limit", meta)
		}
	})
	t.Run("files_only", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "M", "path": "sub/f.go", "files_only": true})
		if got := grepLines(t, res); !reflect.DeepEqual(got, []string{"sub/f.go"}) {
			t.Fatalf("grep(named file, files_only) = %v, want [sub/f.go]", got)
		}
	})
}

func TestGrepTool_NamedFileNotFiltered(t *testing.T) {
	root, home := ciFixture(t)
	writeFile(t, filepath.Join(root, ".hidden.go"), "FINDME hidden\n")
	tool := NewGrepTool(home, root, root, grepTestCap)

	for _, tc := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"hidden", map[string]any{"path": ".hidden.go"}, ".hidden.go:1:match:FINDME hidden"},
		{"codemeldignore", map[string]any{"path": "secret.txt"}, "secret.txt:1:match:FINDME secret"},
		{"include not matching", map[string]any{"path": "keep.txt", "include": "*.go"}, "keep.txt:1:match:FINDME keep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := invokeGrep(t, tool, mergeArgs(map[string]any{"pattern": "FINDME"}, tc.args))
			if got := grepLines(t, res); !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("grep(%v) = %v, want [%s]", tc.args, got, tc.want)
			}
		})
	}
}

func TestGrepTool_NamedBinaryFileSkipped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "bin.dat"), "hello\x00world\n")
	tool := newGrepToolIn(t, root)

	for _, filesOnly := range []bool{false, true} {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "hello", "path": "bin.dat", "files_only": filesOnly})
		if got := grepLines(t, res); len(got) != 0 {
			t.Fatalf("grep(binary named file, files_only=%v) = %v, want no matches", filesOnly, got)
		}
		if !strings.Contains(string(res.Stderr), grepNoticePrefix+"skipped 1 binary file(s)") {
			t.Fatalf("Stderr = %q, want the binary-skip notice", res.Stderr)
		}
	}
}

func TestGrepTool_NamedFileRefused(t *testing.T) {
	root := eval(t, t.TempDir())
	outside := eval(t, t.TempDir())
	writeFile(t, filepath.Join(outside, "secret.txt"), "needle\n")
	writeFile(t, filepath.Join(root, "blocked.txt"), "needle\n")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newGrepToolIn(t, root)
	tool.SetBlockedPaths(permissions.NewBlockedPaths(eval(t, t.TempDir()), []permissions.BlockedEntry{{Path: filepath.Join(root, "blocked.txt"), Source: "test"}}))

	t.Run("blocked", func(t *testing.T) {
		res, _ := invokeGrep(t, tool, map[string]any{"pattern": "needle", "path": "blocked.txt"})
		if len(res.Stdout) != 0 {
			t.Fatalf("Stdout = %q, want nothing read from a blocked file", res.Stdout)
		}
		if !strings.HasSuffix(string(res.Stderr), "\nleft out (blocked): blocked.txt\n") {
			t.Fatalf("Stderr = %q, want the blocked left-out line", res.Stderr)
		}
	})

	for _, tc := range []struct {
		name, path, wantErr string
	}{
		{"outside project without approval", filepath.Join(outside, "secret.txt"), "grep target outside the project root requires permission approval through dispatch"},
		{"dotdot traversal", "../" + filepath.Base(outside) + "/secret.txt", "grep target rejected: target's parent directory is outside the project root"},
		{"symlink escaping root", "link.txt", "grep target rejected: target resolves through a symlink to outside the project root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := invokeGrep(t, tool, map[string]any{"pattern": "needle", "path": tc.path})
			if res.ExitCode == 0 || strings.Contains(string(res.Stdout), "needle") {
				t.Fatalf("result = exit %d, stdout %q; want a refusal with nothing read", res.ExitCode, res.Stdout)
			}
			if !strings.Contains(string(res.Stderr), tc.wantErr) {
				t.Fatalf("Stderr = %q, want it to contain %q", res.Stderr, tc.wantErr)
			}
		})
	}
}

func TestGrepTool_ApprovedExternalNamedFileAnchored(t *testing.T) {
	root := t.TempDir()
	ext := eval(t, t.TempDir())
	writeFile(t, filepath.Join(ext, "ext.txt"), "needle\n")
	tool := newGrepToolIn(t, root)
	args := map[string]any{"pattern": "needle", "path": filepath.Join(ext, "ext.txt")}

	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v", err)
	}
	res, _ := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if got := grepLines(t, res); !reflect.DeepEqual(got, []string{"ext.txt:1:match:needle"}) {
		t.Fatalf("grep(external named file) = %v, want [ext.txt:1:match:needle]", got)
	}
}

func TestGrepTool_NamedFIFORejected(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o644); err != nil {
		t.Skipf("Mkfifo unsupported on this platform: %v", err)
	}
	tool := newGrepToolIn(t, root)

	res, _ := invokeGrep(t, tool, map[string]any{"pattern": "x", "path": "pipe"})
	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "grep target rejected: search path is not a directory") {
		t.Fatalf("result = exit %d, stderr %q; want the not-a-directory rejection", res.ExitCode, res.Stderr)
	}
}
