// Unit tests for the built-in read tool: metadata/classification, pre-authorization target resolution,
// numeric boundary validation, verbatim line-paginated content with separate metadata, binary-file
// notice, hidden-path exemption, and the symlink/containment rejections.
package filetools

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/tools"
)

const readTestCap = 65536

// newReadToolIn builds a read tool whose project root and relative-path base are root, with a separate
// home anchor, mirroring edit_test's newToolIn.
func newReadToolIn(t *testing.T, root string) *ReadTool {
	t.Helper()
	return NewReadTool(t.TempDir(), root, root, readTestCap)
}

// invokeRead runs the read tool's full standalone path (ResolveTarget then read) and returns the result.
func invokeRead(t *testing.T, tool *ReadTool, args map[string]any) (tools.Result, error) {
	t.Helper()
	return tool.Invoke(context.Background(), args)
}

func TestReadTool_AdvertiseMetadata(t *testing.T) {
	tool := newReadToolIn(t, t.TempDir())

	if tool.Name() != "read" {
		t.Fatalf("Name() = %q, want read", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if !md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = false, want true (read is read-only, req 20)")
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
	if req, ok := md.Parameters["required"].([]string); !ok || !reflect.DeepEqual(req, []string{"path"}) {
		t.Fatalf("Parameters.required = %v, want [path] only", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties = %v, want a map", md.Parameters["properties"])
	}
	for _, key := range []string{"path", "offset", "limit"} {
		if _, ok := props[key]; !ok {
			t.Fatalf("Parameters.properties missing %q", key)
		}
	}
}

func TestReadTool_AdvertisePathContract(t *testing.T) {
	assertReadPathContract(t, newReadToolIn(t, t.TempDir()).Advertise())
}

func pathDescription(t *testing.T, md tools.Metadata) string {
	t.Helper()
	props, _ := md.Parameters["properties"].(map[string]any)
	path, _ := props["path"].(map[string]any)
	desc, _ := path["description"].(string)
	if desc == "" {
		t.Fatal("path parameter has no description")
	}
	return desc
}

func assertReadPathContract(t *testing.T, md tools.Metadata) {
	t.Helper()
	desc := pathDescription(t, md)
	for _, want := range []string{
		"absolute or ~",
		"outside the project",
		"without asking unless it is blocked, in which case it is refused",
		"settings file is broken",
		"blocked-path list is unknown",
		"asks first",
		"leaves the project through `..` or through a symlink inside the project is refused",
		"~user forms",
		"malformed paths",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("path description missing %q; got %q", want, desc)
		}
	}
	for _, stale := range []string{"approve it at the permission prompt", "only after you approve"} {
		if strings.Contains(desc, stale) {
			t.Errorf("path description still says %q; got %q", stale, desc)
		}
	}
	for _, confined := range []string{"project file", "within the project", "in-project", "project-confined"} {
		if strings.Contains(md.Description, confined) {
			t.Errorf("tool description claims project-only confinement with %q; got %q", confined, md.Description)
		}
	}
}

// TestReadTool_VerbatimContent_NoLineNumbers pins Done-when 1: a whole-file read returns the file bytes
// byte-for-byte with no injected line numbers, and the truncation metadata lives in stderr, not stdout.
func TestReadTool_VerbatimContent_NoLineNumbers(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"trailing newline", "alpha\nbeta\ngamma\n"},
		{"no trailing newline", "alpha\nbeta\ngamma"},
		{"single line", "only line, no newline"},
		{"empty file", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "f.txt"), tc.content)
			tool := newReadToolIn(t, root)

			res, err := invokeRead(t, tool, map[string]any{"path": "f.txt"})
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil", err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("ExitCode = %d (stderr=%q), want 0", res.ExitCode, res.Stderr)
			}
			if string(res.Stdout) != tc.content {
				t.Fatalf("Stdout = %q, want verbatim %q", res.Stdout, tc.content)
			}
			if bytes.Contains(res.Stdout, []byte(MetadataPrefix)) {
				t.Fatalf("Stdout contains the metadata prefix %q; metadata must be out-of-band", MetadataPrefix)
			}
			if meta := parseMeta(t, res.Stderr); meta.Truncated {
				t.Fatalf("meta.Truncated = true for a whole-file read, want false")
			}
		})
	}
}

// TestReadTool_RejectsNonexistentDirectoryNonRegular pins Done-when 2: a nonexistent path, a directory,
// and a non-regular file are each rejected in-band (non-zero exit), not crashed or read.
func TestReadTool_RejectsNonexistentDirectoryNonRegular(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "adir"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	fifo := filepath.Join(root, "afifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	tool := newReadToolIn(t, root)

	for _, tc := range []struct{ name, path string }{
		{"nonexistent", "missing.txt"},
		{"directory", "adir"},
		{"non-regular fifo", "afifo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := invokeRead(t, tool, map[string]any{"path": tc.path})
			if err != nil {
				t.Fatalf("Invoke error = %v, want nil (rejection is in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0 for %s, want a non-zero in-band rejection (stdout=%q)", tc.name, res.Stdout)
			}
			if len(res.Stderr) == 0 {
				t.Fatalf("Stderr empty for %s, want a reason", tc.name)
			}
		})
	}
}

// TestReadTool_BinaryFileNotice pins Done-when 2: a binary file returns the short notice rather than its
// raw bytes, and none of the raw NUL bytes leak into stdout.
func TestReadTool_BinaryFileNotice(t *testing.T) {
	root := t.TempDir()
	content := "PNG\x00\x01\x02binary\x00data"
	writeFile(t, filepath.Join(root, "img.bin"), content)
	tool := newReadToolIn(t, root)

	res, err := invokeRead(t, tool, map[string]any{"path": "img.bin"})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (the notice is a success result)", res.ExitCode)
	}
	want := "binary file, " + strconv.Itoa(len(content)) + " bytes — not shown"
	if string(res.Stdout) != want {
		t.Fatalf("Stdout = %q, want the notice %q", res.Stdout, want)
	}
	if bytes.IndexByte(res.Stdout, 0) >= 0 {
		t.Fatal("Stdout contains a raw NUL byte; binary content must never be emitted")
	}
}

// TestReadTool_NumericBoundaries pins Done-when 3: out-of-range offset/limit are rejected in-band, and an
// over-maximum limit names the maximum.
func TestReadTool_NumericBoundaries(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.txt"), "a\nb\nc\n")
	tool := newReadToolIn(t, root)

	assertArgRejections(t, func(a map[string]any) (tools.Result, error) { return invokeRead(t, tool, a) }, []argRejectionCase{
		{"offset zero", map[string]any{"path": "f.txt", "offset": 0}, "offset must be >= 1"},
		{"offset negative", map[string]any{"path": "f.txt", "offset": -3}, "offset must be >= 1"},
		{"limit zero", map[string]any{"path": "f.txt", "limit": 0}, "limit must be >= 1"},
		{"limit over max", map[string]any{"path": "f.txt", "limit": ReadMaxLimit + 1}, "maximum of " + strconv.Itoa(ReadMaxLimit)},
		{"offset non-integer", map[string]any{"path": "f.txt", "offset": 1.5}, "must be an integer"},
		{"limit wrong type", map[string]any{"path": "f.txt", "limit": "ten"}, "must be an integer"},
	})
}

// TestReadTool_PaginationMoreRemains pins Done-when 3+4: offset/limit select a verbatim line window, and
// when more lines remain the metadata carries truncated/reason plus the next offset to request.
func TestReadTool_PaginationMoreRemains(t *testing.T) {
	for _, trailing := range []struct {
		name    string
		content string
	}{
		{"trailing newline", "L1\nL2\nL3\nL4\nL5\n"},
		{"no trailing newline", "L1\nL2\nL3\nL4\nL5"},
	} {
		t.Run(trailing.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "f.txt"), trailing.content)
			tool := newReadToolIn(t, root)

			// First page: lines 1-2, more remains, next offset 3.
			res, err := invokeRead(t, tool, map[string]any{"path": "f.txt", "offset": 1, "limit": 2})
			if err != nil {
				t.Fatalf("Invoke error = %v", err)
			}
			if string(res.Stdout) != "L1\nL2\n" {
				t.Fatalf("page1 Stdout = %q, want %q", res.Stdout, "L1\nL2\n")
			}
			meta := parseMeta(t, res.Stderr)
			if !meta.Truncated || meta.TruncationReason != TruncationReasonLimit {
				t.Fatalf("page1 meta = %+v, want truncated with reason limit", meta)
			}
			if meta.NextOffset != 3 {
				t.Fatalf("page1 NextOffset = %d, want 3", meta.NextOffset)
			}

			// Middle page from the reported next offset: lines 3-4, still more, next offset 5.
			res, err = invokeRead(t, tool, map[string]any{"path": "f.txt", "offset": 3, "limit": 2})
			if err != nil {
				t.Fatalf("Invoke error = %v", err)
			}
			if string(res.Stdout) != "L3\nL4\n" {
				t.Fatalf("page2 Stdout = %q, want %q", res.Stdout, "L3\nL4\n")
			}
			if meta := parseMeta(t, res.Stderr); meta.NextOffset != 5 {
				t.Fatalf("page2 NextOffset = %d, want 5", meta.NextOffset)
			}

			// Final page: last line, no more content, no next offset.
			res, err = invokeRead(t, tool, map[string]any{"path": "f.txt", "offset": 5, "limit": 2})
			if err != nil {
				t.Fatalf("Invoke error = %v", err)
			}
			wantLast := "L5\n"
			if trailing.name == "no trailing newline" {
				wantLast = "L5"
			}
			if string(res.Stdout) != wantLast {
				t.Fatalf("page3 Stdout = %q, want %q", res.Stdout, wantLast)
			}
			if meta := parseMeta(t, res.Stderr); meta.Truncated || meta.NextOffset != 0 {
				t.Fatalf("page3 meta = %+v, want not-truncated with no next offset", meta)
			}
		})
	}
}

// TestReadTool_OffsetBeyondEOF: an offset past the last line is not an error — it returns empty content
// with no continuation.
func TestReadTool_OffsetBeyondEOF(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.txt"), "a\nb\nc\n")
	tool := newReadToolIn(t, root)

	res, err := invokeRead(t, tool, map[string]any{"path": "f.txt", "offset": 100})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (past-EOF offset is empty, not an error)", res.ExitCode)
	}
	if len(res.Stdout) != 0 {
		t.Fatalf("Stdout = %q, want empty", res.Stdout)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated || meta.NextOffset != 0 {
		t.Fatalf("meta = %+v, want not-truncated with no next offset", meta)
	}
}

// TestReadTool_HiddenFileExempt pins: an explicit hidden (dot-prefixed) path is read, unlike the
// recursive tools that filter hidden entries.
func TestReadTool_HiddenFileExempt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".secret"), "token=abc\n")
	tool := newReadToolIn(t, root)

	res, err := invokeRead(t, tool, map[string]any{"path": ".secret"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "token=abc\n" {
		t.Fatalf("read of hidden file = (exit %d, %q), want (0, %q)", res.ExitCode, res.Stdout, "token=abc\n")
	}
}

// TestReadTool_SymlinkToInRootFileFollowed: read follows a symlink that resolves to a regular file inside
// the project root.
func TestReadTool_SymlinkToInRootFileFollowed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "real.txt"), "via symlink\n")
	if err := os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newReadToolIn(t, root)

	res, err := invokeRead(t, tool, map[string]any{"path": "link.txt"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != "via symlink\n" {
		t.Fatalf("read via symlink = (exit %d, %q), want (0, %q)", res.ExitCode, res.Stdout, "via symlink\n")
	}
}

// TestReadTool_ContainmentRejections pins the adversarial containment table: a symlink escaping the root,
// an absolute path outside the root, and a ../ traversal are all rejected fail-closed before any read.
func TestReadTool_ContainmentRejections(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret.txt")
	writeFile(t, outside, "secret\n")
	if err := os.Symlink(outside, filepath.Join(root, "escape.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	tool := newReadToolIn(t, root)

	assertContainmentRejections(t, func(p string) (tools.Result, error) { return invokeRead(t, tool, map[string]any{"path": p}) },
		"secret", []pathCase{
			{"symlink escape", "escape.txt"},
			{"absolute outside", outside},
			{"dotdot traversal", "../" + filepath.Base(outsideDir) + "/secret.txt"},
		})
}

// TestReadTool_RequirePathAndUnknownArgs: a missing/empty path and an unknown argument are rejected
// in-band before any read.
func TestReadTool_RequirePathAndUnknownArgs(t *testing.T) {
	tool := newReadToolIn(t, t.TempDir())

	// wantInMsg is empty: these cases assert only the in-band rejection (non-zero exit), not a specific reason.
	assertArgRejections(t, func(a map[string]any) (tools.Result, error) { return invokeRead(t, tool, a) }, []argRejectionCase{
		{"missing path", map[string]any{}, ""},
		{"empty path", map[string]any{"path": ""}, ""},
		{"unknown arg", map[string]any{"path": "f.txt", "bogus": 1}, ""},
	})
}

// TestReadTool_ResolveTargetScopeAndResolvedInvoke pins the target-scoped dispatch contract: ResolveTarget
// returns the resolved real file as the mode-auth target and its parent directory as the path scope, and
// InvokeWithResolvedTarget reading that resolved target matches the standalone Invoke (style
// resolve-once / reuse-at-invoke).
func TestReadTool_ResolveTargetScopeAndResolvedInvoke(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "main.go")
	writeFile(t, file, "package main\n")
	tool := newReadToolIn(t, root)

	target, scope, err := tool.ResolveTarget(map[string]any{"path": "main.go"})
	if err != nil {
		t.Fatalf("ResolveTarget error = %v", err)
	}
	if target != eval(t, file) {
		t.Fatalf("ResolveTarget target = %q, want resolved %q", target, eval(t, file))
	}
	if scope != filepath.Dir(eval(t, file)) {
		t.Fatalf("ResolveTarget scope = %q, want the parent dir %q", scope, filepath.Dir(eval(t, file)))
	}

	resolvedRes, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "main.go"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v", err)
	}
	directRes, err := invokeRead(t, tool, map[string]any{"path": "main.go"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if string(resolvedRes.Stdout) != string(directRes.Stdout) || string(resolvedRes.Stdout) != "package main\n" {
		t.Fatalf("resolved-target read = %q, direct read = %q, want %q", resolvedRes.Stdout, directRes.Stdout, "package main\n")
	}
}

// TestReadTool_DefaultsReadWholeSmallFile: with no offset/limit, read starts at line 1 and the default
// limit (2000) covers a small file in one page with no continuation.
func TestReadTool_DefaultsReadWholeSmallFile(t *testing.T) {
	root := t.TempDir()
	content := "one\ntwo\nthree\n"
	writeFile(t, filepath.Join(root, "f.txt"), content)
	tool := newReadToolIn(t, root)

	res, err := invokeRead(t, tool, map[string]any{"path": "f.txt"})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if string(res.Stdout) != content {
		t.Fatalf("Stdout = %q, want %q", res.Stdout, content)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated || meta.NextOffset != 0 {
		t.Fatalf("meta = %+v, want a single non-truncated page", meta)
	}
}

// TestReadTool_LimitExactlyLineCountNoContinuation: a limit equal to the total line count returns the
// whole file with no spurious "more remains" continuation.
func TestReadTool_LimitExactlyLineCountNoContinuation(t *testing.T) {
	root := t.TempDir()
	content := "a\nb\nc\n"
	writeFile(t, filepath.Join(root, "f.txt"), content)
	tool := newReadToolIn(t, root)

	res, err := invokeRead(t, tool, map[string]any{"path": "f.txt", "offset": 1, "limit": 3})
	if err != nil {
		t.Fatalf("Invoke error = %v", err)
	}
	if string(res.Stdout) != content {
		t.Fatalf("Stdout = %q, want the whole file %q", res.Stdout, content)
	}
	if meta := parseMeta(t, res.Stderr); meta.Truncated || meta.NextOffset != 0 {
		t.Fatalf("meta = %+v, want no continuation when limit equals the line count", meta)
	}
}

// TestReadTool_BinaryDetection covers the isBinaryContent classifier directly so the NUL heuristic is
// pinned independent of the read path.
func TestReadTool_BinaryDetection(t *testing.T) {
	cases := []struct {
		name    string
		content string
		binary  bool
	}{
		{"plain text", "hello\nworld\n", false},
		{"empty", "", false},
		{"utf8 multibyte no nul", "héllo — über\n", false},
		{"leading nul", "\x00abc", true},
		{"interior nul", "abc\x00def", true},
		{"trailing nul", "abc\x00", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBinaryContent([]byte(tc.content)); got != tc.binary {
				t.Fatalf("isBinaryContent(%q) = %v, want %v", tc.content, got, tc.binary)
			}
		})
	}
}
