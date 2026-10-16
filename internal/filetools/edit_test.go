// Unit tests for the built-in edit tool: metadata/classification, pre-authorization target resolution
// (in-scope, escape, symlink-escape, directory, missing-parent, non-regular), and atomic exact-once
// apply with byte-identical files on every precondition or mid-write failure.
package filetools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/fsutil"
)

func eval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return r
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return string(b)
}

// newToolIn builds an edit tool whose project root and relative-path base are root, with a separate
// home anchor, so a relative target lands inside the project and ~ expansion is exercised independently.
func newToolIn(t *testing.T, root string) *EditTool {
	t.Helper()
	return NewEditTool(t.TempDir(), root, root)
}

func TestEditTool_AdvertiseMetadata(t *testing.T) {
	tool := newToolIn(t, t.TempDir())

	if tool.Name() != "edit" {
		t.Fatalf("Name() = %q, want edit", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = true, want false (the edit tool is mutating)")
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
	required, ok := md.Parameters["required"].([]string)
	if !ok || !reflect.DeepEqual(required, []string{"path", "old_text", "new_text"}) {
		t.Fatalf("Parameters.required = %v, want [path old_text new_text]", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties type = %T, want map[string]any", md.Parameters["properties"])
	}
	for _, key := range []string{"path", "old_text", "new_text"} {
		if _, ok := props[key]; !ok {
			t.Fatalf("Parameters.properties missing %q", key)
		}
	}

	// The advertised path contract must match runtime behavior: in-project paths edit
	// normally, but an out-of-root target is permitted via the permission prompt. Guard against the
	// contract regressing back to a flat "within the project" requirement, which would contradict
	// dispatch now prompting (instead of hard-denying) for an out-of-root edit.
	pathProp, ok := props["path"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties[path] type = %T, want map[string]any", props["path"])
	}
	pathDesc, _ := pathProp["description"].(string)
	if strings.Contains(pathDesc, "within the project") {
		t.Fatalf("path description still claims targets are %q; out-of-root edits are prompt-gated, not forbidden: %q", "within the project", pathDesc)
	}
	for _, want := range []string{"outside the project", "permission prompt"} {
		if !strings.Contains(pathDesc, want) {
			t.Fatalf("path description = %q, want it to mention %q (out-of-root prompt approval)", pathDesc, want)
		}
	}
	if strings.Contains(md.Description, "within the project") {
		t.Fatalf("tool description still claims targets are %q: %q", "within the project", md.Description)
	}
}

// TestEditTool_ResolveTargetRejectsRoot pins the explicit-root case: the read-only resolver now accepts an
// explicit project-root path, but the mutating edit tool must still reject it (the root is a directory,
// not an editable regular file), for the absolute, "." and trailing-slash root forms.
func TestEditTool_ResolveTargetRejectsRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	for _, p := range []string{root, ".", root + string(filepath.Separator)} {
		_, _, err := tool.ResolveTarget(map[string]any{"path": p})
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("ResolveTarget(path=%q) error = %v, want *TargetError (root must not be editable)", p, err)
		}
	}
}

func TestEditTool_ResolveTargetInScope(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	abs := filepath.Join(root, "main.go")
	writeFile(t, abs, "package main\n")

	for _, path := range []string{"main.go", abs} {
		target, scope, err := tool.ResolveTarget(map[string]any{"path": path})
		if err != nil {
			t.Fatalf("ResolveTarget(%q) error = %v, want nil", path, err)
		}
		if target != abs {
			t.Fatalf("ResolveTarget(%q) target = %q, want %q", path, target, abs)
		}
		if scope != root {
			t.Fatalf("ResolveTarget(%q) scope = %q, want %q (the parent directory)", path, scope, root)
		}
	}
}

// TestEditTool_ResolveTargetFollowsInProjectSymlink proves a symlinked target inside the project is
// followed to the real file (so the write lands on the real file) and stays in scope.
func TestEditTool_ResolveTargetFollowsInProjectSymlink(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	realFile := filepath.Join(root, "real.txt")
	writeFile(t, realFile, "hello\n")
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	target, scope, err := tool.ResolveTarget(map[string]any{"path": "link.txt"})
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil", err)
	}
	if target != realFile {
		t.Fatalf("target = %q, want the followed real file %q", target, realFile)
	}
	if scope != filepath.Dir(realFile) {
		t.Fatalf("scope = %q, want %q", scope, filepath.Dir(realFile))
	}
}

// TestEditTool_ResolveTargetStructuralRejections pins the structural failures that remain a *TargetError
// before authorization: a directory/missing/non-regular target, an unresolvable parent, and
// malformed args. Out-of-root is no longer one of these — it is promptable (see
// TestEditTool_ResolveTargetOutOfRoot).
func TestEditTool_ResolveTargetStructuralRejections(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	// A directory target inside the project.
	dir := filepath.Join(root, "subdir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	cases := []struct {
		name string
		path any
	}{
		{"names a directory", "subdir"},
		{"missing target file", "does-not-exist.txt"},
		{"unresolvable parent directory", "no/such/parent/file.txt"},
		{"empty path", ""},
		{"missing path argument", nil},
		{"non-string path argument", 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{}
			if tc.path != nil {
				args["path"] = tc.path
			}
			_, _, err := tool.ResolveTarget(args)
			var te *TargetError
			if !errors.As(err, &te) {
				t.Fatalf("ResolveTarget error = %v, want *TargetError", err)
			}
		})
	}
}

// TestEditTool_ResolveTargetOutOfRoot pins that an out-of-root edit target is no longer a hard
// *TargetError; it resolves to its real out-of-root file with the real out-of-root folder as the path
// scope (promptable). This includes an in-root lexical path that symlink-resolves outside the root, which
// resolves to the real out-of-root file/folder rather than the lexical parent. Distinct out-of-root
// folders are distinct scopes, so they do not share one grant.
func TestEditTool_ResolveTargetOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	outsideDir := eval(t, t.TempDir())
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	writeFile(t, outsideFile, "data\n")

	// Direct absolute out-of-root path resolves, anchored on the real out-of-root folder.
	target, scope, err := tool.ResolveTarget(map[string]any{"path": outsideFile})
	if err != nil {
		t.Fatalf("ResolveTarget(out-of-root absolute) error = %v, want nil (promptable)", err)
	}
	if target != outsideFile {
		t.Fatalf("target = %q, want the real out-of-root file %q", target, outsideFile)
	}
	if scope != outsideDir {
		t.Fatalf("scope = %q, want the real out-of-root folder %q", scope, outsideDir)
	}
	if !tool.OutOfRootScope(scope) {
		t.Fatalf("OutOfRootScope(%q) = false, want true", scope)
	}

	// An in-root lexical path that symlink-resolves outside the root resolves to the same real file and
	// folder, never the in-root lexical parent.
	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	target, scope, err = tool.ResolveTarget(map[string]any{"path": "escape.txt"})
	if err != nil {
		t.Fatalf("ResolveTarget(symlink escape) error = %v, want nil (promptable)", err)
	}
	if target != outsideFile || scope != outsideDir {
		t.Fatalf("symlink escape target/scope = %q/%q, want real %q/%q", target, scope, outsideFile, outsideDir)
	}
	if !tool.OutOfRootScope(scope) {
		t.Fatalf("OutOfRootScope on symlink escape = false, want true")
	}

	// A sibling out-of-root folder is a distinct scope (so a grant for the first folder does not cover it).
	otherDir := eval(t, t.TempDir())
	otherFile := filepath.Join(otherDir, "other.txt")
	writeFile(t, otherFile, "x\n")
	_, scope2, err := tool.ResolveTarget(map[string]any{"path": otherFile})
	if err != nil {
		t.Fatalf("ResolveTarget(sibling out-of-root) error = %v, want nil", err)
	}
	if scope2 == scope {
		t.Fatalf("sibling out-of-root folder shares scope %q; want a distinct scope", scope2)
	}
}

func TestEditTool_ResolveTargetNonRegular(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("Mkfifo unsupported on this platform: %v", err)
	}

	_, _, err := tool.ResolveTarget(map[string]any{"path": "pipe"})
	var te *TargetError
	if !errors.As(err, &te) {
		t.Fatalf("ResolveTarget(fifo) error = %v, want *TargetError (non-regular target)", err)
	}
}

// TestEditTool_ApplyExactOnce pins the exact-once apply on the resolved-target seam: a unique match is
// replaced (an empty new_text deletes the snippet) with a zero exit and the rest of the file byte-for-byte
// preserved.
func TestEditTool_ApplyExactOnce(t *testing.T) {
	cases := []struct {
		name     string
		original string
		oldText  string
		newText  string
		want     string
	}{
		{"replaces the unique match", "alpha BETA gamma\n", "BETA", "DELTA", "alpha DELTA gamma\n"},
		{"empty new_text deletes the snippet", "keep[remove]end\n", "[remove]", "", "keepend\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := eval(t, t.TempDir())
			tool := newToolIn(t, root)
			file := filepath.Join(root, "doc.txt")
			writeFile(t, file, tc.original)

			args := map[string]any{"path": "doc.txt", "old_text": tc.oldText, "new_text": tc.newText}
			wantPatch, refusal := tool.Preview(file, args)
			if refusal != nil {
				t.Fatalf("Preview refusal = %+v, want nil for a valid edit", *refusal)
			}

			res, err := tool.InvokeWithResolvedTarget(context.Background(), args, file)
			if err != nil {
				t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
			}
			if got := readFile(t, file); got != tc.want {
				t.Fatalf("file = %q, want %q", got, tc.want)
			}
			if res.DisplayPatch != wantPatch {
				t.Fatalf("DisplayPatch =\n%s\n--- want the pre-authorization patch ---\n%s", res.DisplayPatch, wantPatch)
			}
			if want := "edited " + file + " (replaced 1 occurrence)\n"; string(res.Stdout) != want {
				t.Fatalf("stdout = %q, want %q (the patch stays out of model-facing output)", res.Stdout, want)
			}
		})
	}
}

// TestEditTool_PreconditionFailuresLeaveFileByteIdentical pins: a stale, ambiguous
// unchanged, or malformed edit fails with a non-zero exit and never modifies the file.
func TestEditTool_PreconditionFailuresLeaveFileByteIdentical(t *testing.T) {
	const original = "x marks x the x spot\n"
	cases := []struct {
		name string
		args map[string]any
	}{
		{"zero matches (stale)", map[string]any{"old_text": "ZZZ", "new_text": "q"}},
		{"multiple matches (ambiguous)", map[string]any{"old_text": "x", "new_text": "y"}},
		{"unchanged replacement", map[string]any{"old_text": "marks", "new_text": "marks"}},
		{"empty old_text", map[string]any{"old_text": "", "new_text": "q"}},
		{"missing old_text", map[string]any{"new_text": "q"}},
		{"missing new_text", map[string]any{"old_text": "marks"}},
		{"non-string old_text", map[string]any{"old_text": 1, "new_text": "q"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := eval(t, t.TempDir())
			tool := newToolIn(t, root)
			file := filepath.Join(root, "doc.txt")
			writeFile(t, file, original)

			args := map[string]any{"path": "doc.txt"}
			for k, v := range tc.args {
				args[k] = v
			}
			res, err := tool.InvokeWithResolvedTarget(context.Background(), args, file)
			if err != nil {
				t.Fatalf("error = %v, want nil (precondition failures surface in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0, want non-zero for a failed precondition")
			}
			if got := readFile(t, file); got != original {
				t.Fatalf("file = %q, want byte-identical %q (no modification on failure)", got, original)
			}
			if res.DisplayPatch != "" {
				t.Fatalf("DisplayPatch = %q, want empty for a refused edit", res.DisplayPatch)
			}
		})
	}
}

// TestEditTool_OverlappingMatchIsAmbiguous pins the exact-once criterion against overlapping matches:
// "aa" can start at offset 0 or 1 within "aaa", so the edit is ambiguous and must fail with a non-zero
// exit and leave the file byte-identical. strings.Count counts only non-overlapping matches (1 here),
// which would have let an ambiguous edit through; the overlapping scan rejects it.
func TestEditTool_OverlappingMatchIsAmbiguous(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	const original = "aaa"
	writeFile(t, file, original)

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "doc.txt", "old_text": "aa", "new_text": "b",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (an ambiguous edit surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for an overlapping (ambiguous) match")
	}
	if got := readFile(t, file); got != original {
		t.Fatalf("file = %q, want byte-identical %q (no modification on an ambiguous edit)", got, original)
	}
}

// TestEditTool_RejectsUnknownArgs pins the closed advertised schema (additionalProperties:false):
// a call carrying an extra key is rejected before authorization or modification on every entry
// — ResolveTarget (dispatch resolution), apply via InvokeWithResolvedTarget (direct/production), and
// the standalone Invoke — and leaves the file byte-identical.
func TestEditTool_RejectsUnknownArgs(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	const original = "alpha BETA gamma\n"

	extraArgs := map[string]any{"path": "doc.txt", "old_text": "BETA", "new_text": "DELTA", "unexpected": true}

	t.Run("ResolveTarget rejects before authorization", func(t *testing.T) {
		_, _, err := tool.ResolveTarget(extraArgs)
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("ResolveTarget error = %v, want *TargetError for an extra property", err)
		}
	})

	t.Run("InvokeWithResolvedTarget rejects at apply", func(t *testing.T) {
		file := filepath.Join(root, "doc.txt")
		writeFile(t, file, original)
		res, err := tool.InvokeWithResolvedTarget(context.Background(), extraArgs, file)
		if err != nil {
			t.Fatalf("error = %v, want nil (an extra property surfaces in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an extra property")
		}
		if got := readFile(t, file); got != original {
			t.Fatalf("file = %q, want byte-identical %q (no modification on a rejected extra property)", got, original)
		}
	})

	t.Run("Invoke rejects and leaves the file untouched", func(t *testing.T) {
		file := filepath.Join(root, "doc.txt")
		writeFile(t, file, original)
		res, err := tool.Invoke(context.Background(), extraArgs)
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (an extra property is in-band, not a Go error)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an extra property")
		}
		if got := readFile(t, file); got != original {
			t.Fatalf("file = %q, want byte-identical %q", got, original)
		}
	})
}

// TestEditTool_ResolvedTargetRequiresPath pins the advertised required `path` on the resolved-target
// invocation seam: InvokeWithResolvedTarget reaches apply with the target already resolved, so a call
// omitting `path` (otherwise a valid exact-once edit) must still fail non-zero and leave the file
// byte-identical — the runtime contract stays no broader than the advertised schema on the production
// invocation path, not only on the dispatch ResolveTarget path.
func TestEditTool_ResolvedTargetRequiresPath(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	const original = "alpha BETA gamma\n"
	writeFile(t, file, original)

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"old_text": "BETA", "new_text": "DELTA",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (a missing required argument surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a missing required path argument")
	}
	if got := readFile(t, file); got != original {
		t.Fatalf("file = %q, want byte-identical %q (no modification when path is omitted)", got, original)
	}
}

func TestEditTool_PreservesFileMode(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "script.sh")
	if err := os.WriteFile(file, []byte("echo OLD\n"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "script.sh", "old_text": "OLD", "new_text": "NEW",
	}, file); err != nil {
		t.Fatalf("error = %v", err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640 (the original mode is preserved)", info.Mode().Perm())
	}
}

// TestEditTool_AtomicWriteFailureLeavesFileByteIdentical pins: a failure during the write
// leaves no partial contents and no leftover temp file — the original is untouched.
func TestEditTool_AtomicWriteFailureLeavesFileByteIdentical(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	const original = "before EDIT after\n"
	writeFile(t, file, original)

	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced sync failure") })
	defer restore()

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "doc.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (a write failure surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after a forced write failure")
	}
	if got := readFile(t, file); got != original {
		t.Fatalf("file = %q, want byte-identical %q after a failed write", got, original)
	}
	if res.DisplayPatch != "" {
		t.Fatalf("DisplayPatch = %q, want empty; the patch is attached only after the atomic write succeeds", res.DisplayPatch)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %q after a failed write", e.Name())
		}
	}
}

// TestEditTool_InvokeStandalone exercises the non-dispatch Invoke entry: it resolves and applies in one
// call, and surfaces a structural resolution failure as the same in-band failure the dispatcher would
// render. Out-of-root is no longer a resolution failure, so standalone Invoke — which has no
// authorizer — must refuse an out-of-root resolved target itself (see the out-of-root subtests); only
// dispatch can authorize an out-of-root write.
func TestEditTool_InvokeStandalone(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	t.Run("resolves and applies", func(t *testing.T) {
		file := filepath.Join(root, "doc.txt")
		writeFile(t, file, "one TWO three\n")
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": "doc.txt", "old_text": "TWO", "new_text": "2",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
		}
		if got := readFile(t, file); got != "one 2 three\n" {
			t.Fatalf("file = %q, want %q", got, "one 2 three\n")
		}
		if !strings.Contains(res.DisplayPatch, "-one TWO three\n") || !strings.Contains(res.DisplayPatch, "+one 2 three\n") {
			t.Fatalf("DisplayPatch =\n%s\nwant the applied replacement", res.DisplayPatch)
		}
	})

	t.Run("missing target is an in-band failure", func(t *testing.T) {
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": "does-not-exist.txt", "old_text": "a", "new_text": "b",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (a resolution failure is in-band, not a Go error)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for a missing target")
		}
		if !strings.Contains(string(res.Stderr), "edit target rejected") {
			t.Fatalf("stderr = %q, want it to name the rejected target", res.Stderr)
		}
		if res.DisplayPatch != "" {
			t.Fatalf("DisplayPatch = %q, want empty for a rejected target", res.DisplayPatch)
		}
	})
}

func TestEditTool_PreviewUnifiedPatch(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	target := filepath.Join(root, "notes.txt")
	const original = "one\ntwo\nalpha\nfour\nfive\nsix\nseven\neight\nnine\nten\nomega\ntwelve\nthirteen\n"
	writeFile(t, target, original)

	patch, refusal := tool.Preview(target, map[string]any{
		"path":     "notes.txt",
		"old_text": "alpha\nfour\nfive\nsix\nseven\neight\nnine\nten\nomega",
		"new_text": "ALPHA\nfour\nfive\nsix\nseven\neight\nnine\nten\nOMEGA",
	})
	if refusal != nil {
		t.Fatalf("Preview refusal = %+v, want nil for a valid edit", *refusal)
	}
	want := "--- " + target + "\n" +
		"+++ " + target + "\n" +
		"@@ -1,5 +1,5 @@\n" +
		" one\n two\n-alpha\n+ALPHA\n four\n five\n" +
		"@@ -9,5 +9,5 @@\n" +
		" nine\n ten\n-omega\n+OMEGA\n twelve\n thirteen\n"
	if patch != want {
		t.Fatalf("Preview patch =\n%s\n--- want ---\n%s", patch, want)
	}
	if got := readFile(t, target); got != original {
		t.Fatalf("target = %q, want byte-identical %q (preview must not write)", got, original)
	}
}

func TestEditTool_PreviewBoundaryContext(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	target := filepath.Join(root, "edges.txt")
	const original = "first\nsecond\nthird\n"

	cases := []struct {
		name     string
		old, new string
		want     string
	}{
		{"first line has no leading context", "first", "FIRST", "@@ -1,3 +1,3 @@\n-first\n+FIRST\n second\n third\n"},
		{"last line has no trailing context", "third", "THIRD", "@@ -1,3 +1,3 @@\n first\n second\n-third\n+THIRD\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, target, original)
			patch, refusal := tool.Preview(target, map[string]any{"path": "edges.txt", "old_text": tc.old, "new_text": tc.new})
			if refusal != nil {
				t.Fatalf("Preview refusal = %+v, want nil", *refusal)
			}
			want := "--- " + target + "\n+++ " + target + "\n" + tc.want
			if patch != want {
				t.Fatalf("Preview patch =\n%s\n--- want ---\n%s", patch, want)
			}
			if got := readFile(t, target); got != original {
				t.Fatalf("target = %q, want byte-identical %q (preview must not write)", got, original)
			}
		})
	}
}

func TestEditTool_PreviewMarksMissingTrailingNewline(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	target := filepath.Join(root, "tail.txt")
	const original = "first\nlast"
	writeFile(t, target, original)

	patch, refusal := tool.Preview(target, map[string]any{"path": "tail.txt", "old_text": "last", "new_text": "LAST"})
	if refusal != nil {
		t.Fatalf("Preview refusal = %+v, want nil", *refusal)
	}
	want := "--- " + target + "\n+++ " + target + "\n" +
		"@@ -1,2 +1,2 @@\n first\n-last\n\\ No newline at end of file\n+LAST\n\\ No newline at end of file\n"
	if patch != want {
		t.Fatalf("Preview patch =\n%s\n--- want ---\n%s", patch, want)
	}
	if got := readFile(t, target); got != original {
		t.Fatalf("target = %q, want byte-identical %q (preview must not write)", got, original)
	}
}

func TestEditTool_PreviewRefusesWithoutWriting(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	target := filepath.Join(root, "dup.txt")
	const original = "alpha\nbeta\nalpha\n"

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"ambiguous", map[string]any{"path": "dup.txt", "old_text": "alpha", "new_text": "gamma"}, "matches 2 times"},
		{"stale", map[string]any{"path": "dup.txt", "old_text": "absent", "new_text": "gamma"}, "was not found in the file"},
		{"unchanged", map[string]any{"path": "dup.txt", "old_text": "beta", "new_text": "beta"}, "there is no change to apply"},
		{"empty old_text", map[string]any{"path": "dup.txt", "old_text": "", "new_text": "gamma"}, "old_text must be non-empty"},
		{"missing path", map[string]any{"old_text": "beta", "new_text": "gamma"}, "path"},
		{"non-string new_text", map[string]any{"path": "dup.txt", "old_text": "beta", "new_text": 7}, "new_text"},
		{"unknown argument", map[string]any{"path": "dup.txt", "old_text": "beta", "new_text": "gamma", "extra": true}, "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, target, original)
			patch, refusal := tool.Preview(target, tc.args)
			if refusal == nil {
				t.Fatalf("Preview refusal = nil, want the in-band refusal (patch %q)", patch)
			}
			if patch != "" {
				t.Fatalf("Preview patch = %q, want empty on a refusal", patch)
			}
			if refusal.ExitCode == 0 {
				t.Fatalf("refusal ExitCode = 0, want non-zero")
			}
			if !strings.Contains(string(refusal.Stderr), tc.want) {
				t.Fatalf("refusal stderr = %q, want it to mention %q", refusal.Stderr, tc.want)
			}
			if got := readFile(t, target); got != original {
				t.Fatalf("target = %q, want byte-identical %q (a refused preview must not write)", got, original)
			}
		})
	}

	t.Run("unreadable target", func(t *testing.T) {
		missing := filepath.Join(root, "gone.txt")
		patch, refusal := tool.Preview(missing, map[string]any{"path": "gone.txt", "old_text": "beta", "new_text": "gamma"})
		if refusal == nil || patch != "" {
			t.Fatalf("Preview(%q) = (%q, %v), want an in-band refusal and no patch", missing, patch, refusal)
		}
		if !strings.Contains(string(refusal.Stderr), "cannot read the target file") {
			t.Fatalf("refusal stderr = %q, want the existing unreadable-target refusal", refusal.Stderr)
		}
	})
}

func TestEditTool_PreviewMatchesApplyResult(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	target := filepath.Join(root, "main.go")
	writeFile(t, target, "package main\n\nfunc main() {\n\tfoo()\n}\n")
	args := map[string]any{"path": "main.go", "old_text": "foo()", "new_text": "bar()"}

	patch, refusal := tool.Preview(target, args)
	if refusal != nil {
		t.Fatalf("Preview refusal = %+v, want nil", *refusal)
	}
	if !strings.Contains(patch, "-\tfoo()\n") || !strings.Contains(patch, "+\tbar()\n") {
		t.Fatalf("patch does not describe the replacement\n%s", patch)
	}
	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("InvokeWithResolvedTarget = (%+v, %v), want a successful apply", res, err)
	}
	if got, want := readFile(t, target), "package main\n\nfunc main() {\n\tbar()\n}\n"; got != want {
		t.Fatalf("target after apply = %q, want %q", got, want)
	}
	if res.DisplayPatch != patch {
		t.Fatalf("DisplayPatch =\n%s\n--- want the previewed patch ---\n%s", res.DisplayPatch, patch)
	}
}

// TestEditTool_InvokeStandaloneRejectsOutOfRoot pins the out-of-root boundary on the standalone Invoke path:
// it has no authorizer, so an out-of-root resolved target — whether a direct absolute path or an in-root
// lexical path that symlink-resolves outside the root — must fail in-band and leave the outside file
// byte-identical. Only dispatch can authorize an out-of-root write through the approval prompt; if this
// guard were removed the asserts below would fail (the outside file would be modified).
func TestEditTool_InvokeStandaloneRejectsOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)

	outsideDir := eval(t, t.TempDir())
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	const original = "data\n"

	t.Run("direct out-of-root absolute path", func(t *testing.T) {
		writeFile(t, outsideFile, original)
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": outsideFile, "old_text": "data", "new_text": "edited",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an out-of-root edit")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if got := readFile(t, outsideFile); got != original {
			t.Fatalf("outside file = %q, want byte-identical %q", got, original)
		}
		if res.DisplayPatch != "" {
			t.Fatalf("DisplayPatch = %q, want empty for a refused out-of-root edit", res.DisplayPatch)
		}
	})

	t.Run("in-root lexical path that symlink-escapes the root", func(t *testing.T) {
		writeFile(t, outsideFile, original)
		link := filepath.Join(root, "escape.txt")
		if err := os.Symlink(outsideFile, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": "escape.txt", "old_text": "data", "new_text": "edited",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for a symlink-escaped edit")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if got := readFile(t, outsideFile); got != original {
			t.Fatalf("outside file = %q, want byte-identical %q after a symlink-escaped edit", got, original)
		}
	})
}

// withUmask installs a restrictive process umask for the duration of one test. Nothing in this package
// runs in parallel, so the process-wide setting cannot leak into a concurrent test.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	prev := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(prev) })
}

// TestEditTool_PreservesExactModeUnderRestrictiveUmask is the terminal check on the publish path: a real
// edit of a group-writable file republishes it group-writable. The temp file's create mode alone is
// trimmed by the umask, so before the explicit chmod this edit silently downgraded 0664 to 0644.
func TestEditTool_PreservesExactModeUnderRestrictiveUmask(t *testing.T) {
	withUmask(t, 0o022)
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "shared.txt")
	writeFile(t, file, "before EDIT after\n")
	if err := os.Chmod(file, 0o664); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "shared.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0: %s", res.ExitCode, res.Stdout)
	}
	if got := readFile(t, file); got != "before WROTE after\n" {
		t.Fatalf("contents = %q", got)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o664 {
		t.Fatalf("mode = %v, want 0664 despite the 022 umask", info.Mode().Perm())
	}
}

// TestEditTool_PublishesThroughHeldParentDescriptor pins that the write follows the directory the edit
// bound, not the path name: with the authorized parent renamed aside and a decoy left at the old path,
// the decoy is never written through and the edit reports the move as a failure. The move lands before
// publication, so the pre-publish guard aborts the rename outright — the held directory keeps its
// original bytes and carries no staged temporary entry.
func TestEditTool_PublishesThroughHeldParentDescriptor(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(authorized, "doc.txt")
	const original = "before EDIT after\n"
	writeFile(t, file, original)

	moved := filepath.Join(root, "moved")
	origHook := beforeEditPublish
	t.Cleanup(func() { beforeEditPublish = origHook })
	beforeEditPublish = func() {
		if err := os.Rename(authorized, moved); err != nil {
			t.Fatalf("rename the held directory: %v", err)
		}
		if err := os.Mkdir(authorized, 0o755); err != nil {
			t.Fatalf("drop the decoy at the old path: %v", err)
		}
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after the authorized parent moved")
	}
	if got := readFile(t, filepath.Join(moved, "doc.txt")); got != original {
		t.Fatalf("file under the held directory = %q, want the original %q", got, original)
	}
	entries, err := os.ReadDir(authorized)
	if err != nil {
		t.Fatalf("ReadDir the decoy: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("the decoy at the old path received %d entries; the publish followed the path name", len(entries))
	}
	held, err := os.ReadDir(moved)
	if err != nil {
		t.Fatalf("ReadDir the held directory: %v", err)
	}
	if len(held) != 1 || held[0].Name() != "doc.txt" {
		t.Fatalf("held directory entries = %v, want only doc.txt; the aborted publish left residue", held)
	}
}

// TestEditTool_ParentReplacedAfterPlanningLeavesReplacementUntouched pins the read-to-publish window: a
// directory swapped in at the authorized path after the plan was read cannot receive bytes planned from
// the file that was actually read.
func TestEditTool_ParentReplacedAfterPlanningLeavesReplacementUntouched(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(authorized, "doc.txt")
	const original = "before EDIT after\n"
	writeFile(t, file, original)

	stash := filepath.Join(root, "stash")
	const replacement = "unrelated REPLACEMENT contents\n"
	origHook := beforeEditPublish
	t.Cleanup(func() { beforeEditPublish = origHook })
	beforeEditPublish = func() {
		if err := os.Rename(authorized, stash); err != nil {
			t.Fatalf("move the held directory aside: %v", err)
		}
		if err := os.Mkdir(authorized, 0o755); err != nil {
			t.Fatalf("drop the replacement directory: %v", err)
		}
		writeFile(t, filepath.Join(authorized, "doc.txt"), replacement)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after the authorized parent was replaced")
	}
	if got := readFile(t, filepath.Join(authorized, "doc.txt")); got != replacement {
		t.Fatalf("replacement file = %q, want the untouched %q", got, replacement)
	}
	if got := readFile(t, filepath.Join(stash, "doc.txt")); got != original {
		t.Fatalf("the edited file = %q, want the original %q restored", got, original)
	}
}

// TestEditTool_TargetReplacedAfterPlanning pins the entry inside the held directory, not just the
// directory: the descriptor keeps naming leaf, so a target renamed away and replaced under the same name
// after the plan was read would otherwise be overwritten with a change computed from the file that was
// read. Both files must come out untouched and the refusal must name the changed target.
func TestEditTool_TargetReplacedAfterPlanning(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(authorized, "doc.txt")
	stash := filepath.Join(authorized, "stashed.txt")
	const original = "before EDIT after\n"
	const replacement = "unrelated REPLACEMENT contents\n"
	writeFile(t, file, original)

	origHook := beforeEditPublish
	t.Cleanup(func() { beforeEditPublish = origHook })
	beforeEditPublish = func() {
		if err := os.Rename(file, stash); err != nil {
			t.Fatalf("move the planned target aside: %v", err)
		}
		writeFile(t, file, replacement)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after the planned target was replaced")
	}
	if got := string(res.Stderr); !strings.Contains(got, "changed during the edit") {
		t.Fatalf("Stderr = %q, want it to name the changed target", got)
	}
	if got := readFile(t, file); got != replacement {
		t.Fatalf("replacement file = %q, want the untouched %q", got, replacement)
	}
	if got := readFile(t, stash); got != original {
		t.Fatalf("the planned target = %q, want the original %q", got, original)
	}
	entries, rerr := os.ReadDir(authorized)
	if rerr != nil {
		t.Fatalf("ReadDir the held directory: %v", rerr)
	}
	if len(entries) != 2 {
		t.Fatalf("held directory entries = %v, want only doc.txt and stashed.txt; the aborted publish left residue", entries)
	}
}

// TestEditTool_ParentMovedAfterPublish drives the window the pre-publish guard cannot cover: the parent
// moves only after the rename has already made the changed bytes visible. fsutil's parent-sync seam runs
// between that rename and the identity check, so a move performed there lands exactly in that window.
// When the compensating write succeeds the held file is byte-identical to the original and the edit is an
// ordinary refusal; when it cannot even stage, the changed bytes really are published and the result must
// say so rather than claim a no-write refusal.
func TestEditTool_ParentMovedAfterPublish(t *testing.T) {
	const original = "before EDIT after\n"
	const updated = "before WROTE after\n"

	cases := []struct {
		name         string
		failRestore  bool
		wantContents string
		wantReason   string
	}{
		{
			name:         "restore succeeds",
			wantContents: original,
			wantReason:   "moved during the edit",
		},
		{
			name:         "restore fails",
			failRestore:  true,
			wantContents: updated,
			wantReason:   "still published in that directory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := eval(t, t.TempDir())
			tool := newToolIn(t, root)
			authorized := filepath.Join(root, "sub")
			if err := os.Mkdir(authorized, 0o755); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			file := filepath.Join(authorized, "doc.txt")
			writeFile(t, file, original)
			moved := filepath.Join(root, "moved")

			dirSyncs := 0
			t.Cleanup(fsutil.SetSyncDirForTest(func(f *os.File) error {
				dirSyncs++
				if dirSyncs == 1 {
					if err := os.Rename(authorized, moved); err != nil {
						t.Fatalf("move the held directory after publication: %v", err)
					}
					return nil
				}
				return f.Sync()
			}))
			if tc.failRestore {
				fileSyncs := 0
				t.Cleanup(fsutil.SetSyncFileForTest(func(f *os.File) error {
					fileSyncs++
					if fileSyncs >= 2 {
						return errors.New("forced restore staging failure")
					}
					return f.Sync()
				}))
			}

			res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
				"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
			}, file)
			if err != nil {
				t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatal("ExitCode = 0, want non-zero after the authorized parent moved")
			}
			if dirSyncs == 0 {
				t.Fatal("the parent-sync seam never fired; the move did not land after publication")
			}
			if got := string(res.Stderr); !strings.Contains(got, tc.wantReason) {
				t.Fatalf("stderr = %q, want it to name %q", got, tc.wantReason)
			}
			if got := readFile(t, filepath.Join(moved, "doc.txt")); got != tc.wantContents {
				t.Fatalf("file under the held directory = %q, want %q", got, tc.wantContents)
			}
			held, err := os.ReadDir(moved)
			if err != nil {
				t.Fatalf("ReadDir the held directory: %v", err)
			}
			if len(held) != 1 || held[0].Name() != "doc.txt" {
				t.Fatalf("held directory entries = %v, want only doc.txt", held)
			}
		})
	}
}

// TestEditTool_ParentSyncFailsAfterMovedPublish covers the parent-sync failure that lands after the
// rename has already made the new bytes visible. The write reports an error, but the changed bytes are
// published in a directory that has meanwhile moved, so treating that error as "nothing was written"
// would skip the recovery the moved-parent case exists for.
func TestEditTool_ParentSyncFailsAfterMovedPublish(t *testing.T) {
	const original = "before EDIT after\n"

	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(authorized, "doc.txt")
	writeFile(t, file, original)
	moved := filepath.Join(root, "moved")

	dirSyncs := 0
	t.Cleanup(fsutil.SetSyncDirForTest(func(f *os.File) error {
		dirSyncs++
		if dirSyncs == 1 {
			if err := os.Rename(authorized, moved); err != nil {
				t.Fatalf("move the held directory after publication: %v", err)
			}
			return errors.New("forced parent sync failure after publication")
		}
		return f.Sync()
	}))

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after the authorized parent moved")
	}
	if got := string(res.Stderr); !strings.Contains(got, "moved during the edit") {
		t.Fatalf("stderr = %q, want the moved-parent refusal rather than a generic write failure", got)
	}
	if got := readFile(t, filepath.Join(moved, "doc.txt")); got != original {
		t.Fatalf("file under the held directory = %q, want the original %q restored", got, original)
	}
	held, err := os.ReadDir(moved)
	if err != nil {
		t.Fatalf("ReadDir the held directory: %v", err)
	}
	if len(held) != 1 || held[0].Name() != "doc.txt" {
		t.Fatalf("held directory entries = %v, want only doc.txt", held)
	}
}

// TestEditTool_TargetReplacedBeforeMovedParentRestore covers the window inside the moved-parent
// recovery itself: between the check that the parent moved and the restore that puts the original
// bytes back, another writer can take over the target name. The restore must not overwrite that file,
// because the original bytes were never planned from it.
func TestEditTool_TargetReplacedBeforeMovedParentRestore(t *testing.T) {
	const original = "before EDIT after\n"
	const intruder = "someone else's file\n"

	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(authorized, "doc.txt")
	writeFile(t, file, original)
	moved := filepath.Join(root, "moved")
	outsider := filepath.Join(root, "outsider.txt")
	writeFile(t, outsider, intruder)

	dirSyncs := 0
	t.Cleanup(fsutil.SetSyncDirForTest(func(f *os.File) error {
		dirSyncs++
		if dirSyncs == 1 {
			if err := os.Rename(authorized, moved); err != nil {
				t.Fatalf("move the held directory after publication: %v", err)
			}
			return nil
		}
		return f.Sync()
	}))

	publishes := 0
	t.Cleanup(fsutil.SetBeforePublishRenameForTest(func() {
		publishes++
		if publishes == 2 {
			if err := os.Rename(outsider, filepath.Join(moved, "doc.txt")); err != nil {
				t.Fatalf("take over the target name before the restore publishes: %v", err)
			}
		}
	}))

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after the authorized parent moved")
	}
	if publishes < 2 {
		t.Fatalf("publish seam fired %d times; the restore never reached publication", publishes)
	}
	if got := readFile(t, filepath.Join(moved, "doc.txt")); got != intruder {
		t.Fatalf("file at the target name = %q, want the other writer's %q left alone", got, intruder)
	}
	if got := string(res.Stderr); !strings.Contains(got, "another writer replaced that file first") {
		t.Fatalf("stderr = %q, want it to say the original contents were not put back", got)
	}
	held, err := os.ReadDir(moved)
	if err != nil {
		t.Fatalf("ReadDir the held directory: %v", err)
	}
	if len(held) != 1 || held[0].Name() != "doc.txt" {
		t.Fatalf("held directory entries = %v, want only doc.txt", held)
	}
}

// TestEditTool_RefusesParentChangedBeforeApply pins the descriptor binding itself: a parent that no
// longer resolves to the authorized directory, or that no longer holds the target, fails the edit
// without writing anything.
func TestEditTool_RefusesParentChangedBeforeApply(t *testing.T) {
	const original = "before EDIT after\n"

	cases := []struct {
		name    string
		replace func(t *testing.T, root, authorized string)
	}{
		{
			name: "symlinked away",
			replace: func(t *testing.T, root, authorized string) {
				elsewhere := filepath.Join(root, "elsewhere")
				if err := os.Mkdir(elsewhere, 0o755); err != nil {
					t.Fatalf("Mkdir elsewhere: %v", err)
				}
				if err := os.Symlink(elsewhere, authorized); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
			},
		},
		{
			name: "replaced by a fresh directory",
			replace: func(t *testing.T, _, authorized string) {
				if err := os.Mkdir(authorized, 0o755); err != nil {
					t.Fatalf("Mkdir replacement: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := eval(t, t.TempDir())
			tool := newToolIn(t, root)
			authorized := filepath.Join(root, "sub")
			if err := os.Mkdir(authorized, 0o755); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			file := filepath.Join(authorized, "doc.txt")
			writeFile(t, file, original)

			stash := filepath.Join(root, "stash")
			if err := os.Rename(authorized, stash); err != nil {
				t.Fatalf("move the authorized directory aside: %v", err)
			}
			tc.replace(t, root, authorized)

			res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
				"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
			}, file)
			if err != nil {
				t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatal("ExitCode = 0, want non-zero when the authorized parent no longer matches")
			}
			if got := readFile(t, filepath.Join(stash, "doc.txt")); got != original {
				t.Fatalf("the original file = %q, want byte-identical %q", got, original)
			}
			entries, err := os.ReadDir(authorized)
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("the swapped-in directory received %d entries, want none", len(entries))
			}
		})
	}
}

// TestEditTool_RefusesNonRegularTargetThroughHeldParent pins the fd-relative read: a symlink or FIFO
// swapped in at the target name after resolution is refused rather than followed or read.
func TestEditTool_RefusesNonRegularTargetThroughHeldParent(t *testing.T) {
	cases := []struct {
		name    string
		install func(t *testing.T, root, path string)
	}{
		{
			name: "symlink",
			install: func(t *testing.T, root, path string) {
				outside := filepath.Join(root, "outside.txt")
				writeFile(t, outside, "before EDIT after\n")
				if err := os.Symlink(outside, path); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
			},
		},
		{
			name: "fifo",
			install: func(t *testing.T, _, path string) {
				if err := syscall.Mkfifo(path, 0o644); err != nil {
					t.Skipf("Mkfifo unsupported on this platform: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := eval(t, t.TempDir())
			tool := newToolIn(t, root)
			file := filepath.Join(root, "doc.txt")
			writeFile(t, file, "before EDIT after\n")
			if err := os.Remove(file); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			tc.install(t, root, file)

			res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
				"path": "doc.txt", "old_text": "EDIT", "new_text": "WROTE",
			}, file)
			if err != nil {
				t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatal("ExitCode = 0, want non-zero for a non-regular target")
			}
			for _, e := range readDirNames(t, root) {
				if strings.Contains(e, ".tmp-") {
					t.Fatalf("leftover temp file %q after a refused edit", e)
				}
			}
		})
	}
}

func readDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestEditTool_TargetReplacedAfterPrePublishCheck(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(authorized, "doc.txt")
	stash := filepath.Join(authorized, "stashed.txt")
	const original = "before EDIT after\n"
	const replacement = "unrelated REPLACEMENT contents\n"
	writeFile(t, file, original)

	t.Cleanup(fsutil.SetBeforePublishRenameForTest(func() {
		if err := os.Rename(file, stash); err != nil {
			t.Fatalf("move the planned target aside: %v", err)
		}
		writeFile(t, file, replacement)
	}))

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "sub/doc.txt", "old_text": "EDIT", "new_text": "WROTE",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after the target was replaced before publication")
	}
	if got := string(res.Stderr); !strings.Contains(got, "changed during the edit") {
		t.Fatalf("Stderr = %q, want it to name the changed target", got)
	}
	if got := readFile(t, file); got != replacement {
		t.Fatalf("replacement file = %q, want the untouched %q", got, replacement)
	}
	if got := readFile(t, stash); got != original {
		t.Fatalf("the planned target = %q, want the original %q", got, original)
	}
	entries, rerr := os.ReadDir(authorized)
	if rerr != nil {
		t.Fatalf("ReadDir the held directory: %v", rerr)
	}
	if len(entries) != 2 {
		t.Fatalf("held directory entries = %v, want only doc.txt and stashed.txt; the refused publish left residue", entries)
	}
}

func TestEditTool_JournalsTheOriginalAndPendingStateAroundThePublish(t *testing.T) {
	const original = "before EDIT after\n"
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	writeFile(t, file, original)
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	journal := newFakeJournal(file)

	var contentAtBegin string
	journal.onBegin = func() { contentAtBegin = readFile(t, file) }

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": file, "old_text": "EDIT", "new_text": "WROTE"}, file)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("edit failed: %s", res.Stderr)
	}
	if contentAtBegin != original {
		t.Fatalf("file at the pending record = %q, want the publish still unmade", contentAtBegin)
	}
	want := []string{"begin:" + file, "resolve:" + file}
	if !reflect.DeepEqual(journal.events, want) {
		t.Fatalf("journal events = %v, want %v", journal.events, want)
	}
	observed := journal.observed[0]
	if string(observed.Data) != original || observed.Mode.Perm() != 0o640 || observed.Ino == 0 {
		t.Fatalf("observed state = %+v, want the descriptor-read original bytes, mode, and identity", observed)
	}
	if got := string(journal.next[0].Data); got != "before WROTE after\n" {
		t.Fatalf("pending state = %q, want the exact bytes publication makes visible", got)
	}
	if journal.next[0].Mode.Perm() != 0o640 {
		t.Fatalf("pending mode = %v, want the mode publication makes visible", journal.next[0].Mode.Perm())
	}
}

func TestEditTool_JournalRefusalLeavesTheFileUnchanged(t *testing.T) {
	const original = "before EDIT after\n"
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	writeFile(t, file, original)
	journal := newFakeJournal(file)
	journal.beginErr = errors.New("that file changed outside the child agent")

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": file, "old_text": "EDIT", "new_text": "WROTE"}, file)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("edit published despite the journal refusing to record it")
	}
	if !strings.Contains(string(res.Stderr), "changed outside the child agent") {
		t.Fatalf("stderr = %q, want it to carry the journal's refusal", res.Stderr)
	}
	if got := readFile(t, file); got != original {
		t.Fatalf("file = %q, want it unchanged", got)
	}
}

// TestEditTool_JournalReconcilesOnlyAfterMovedParentCompensation pins the ordering the journal's
// prior/pending contract depends on: a compensated edit must be compared against the directory the
// compensation leaves behind, or the restored original reads as an external conflict.
func TestEditTool_JournalReconcilesOnlyAfterMovedParentCompensation(t *testing.T) {
	const original = "before EDIT after\n"
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	file := filepath.Join(authorized, "doc.txt")
	writeFile(t, file, original)
	moved := filepath.Join(root, "moved")
	journal := newFakeJournal(file)

	dirSyncs := 0
	t.Cleanup(fsutil.SetSyncDirForTest(func(f *os.File) error {
		dirSyncs++
		if dirSyncs == 1 {
			if err := os.Rename(authorized, moved); err != nil {
				t.Fatalf("move the held directory after publication: %v", err)
			}
			return nil
		}
		return f.Sync()
	}))

	var contentAtResolve string
	journal.onResolve = func() { contentAtResolve = readFile(t, filepath.Join(moved, "doc.txt")) }

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": file, "old_text": "EDIT", "new_text": "WROTE"}, file)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("edit reported success after its authorized parent moved")
	}
	if len(journal.resolved) != 1 {
		t.Fatalf("journal resolutions = %v, want exactly one after compensation", journal.events)
	}
	if contentAtResolve != original {
		t.Fatalf("file at reconciliation = %q, want the compensation to have finished first", contentAtResolve)
	}
}

// The replacement holds a byte-identical target, so every existing precondition would be satisfied and
// only the captured identity can refuse the edit.
func TestEditTool_AuthorizedScopeReplacedWhilePendingEditsNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "doc.txt")
	const original = "alpha BETA gamma\n"
	writeFile(t, target, original)
	identity := mustCaptureScope(t, scope)

	replaceDirectory(t, scope)
	writeFile(t, target, original)

	args := map[string]any{"path": "pkg/doc.txt", "old_text": "BETA", "new_text": "DELTA"}
	res, err := tool.InvokeWithAuthorizedScope(context.Background(), args, target, scope, identity)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a scope replaced while the request was pending")
	}
	if got := string(res.Stderr); !strings.Contains(got, authorizedScopeReplaced) {
		t.Fatalf("stderr = %q, want the pending-replacement refusal", got)
	}
	if got := readFile(t, target); got != original {
		t.Fatalf("file = %q, want byte-identical %q", got, original)
	}
}

func TestEditTool_ScopeReplacedAfterConfirmationEditsNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "doc.txt")
	const original = "alpha BETA gamma\n"
	writeFile(t, target, original)
	identity := mustCaptureScope(t, scope)

	var aside string
	afterScopeConfirmedOnce(t, func() {
		aside = swapAuthorizedScope(t, scope)
		// Byte-identical, so ordinary planning against the replacement would succeed and only the
		// identity binding can be what refuses.
		writeFile(t, target, original)
	})

	args := map[string]any{"path": "pkg/doc.txt", "old_text": "BETA", "new_text": "DELTA"}
	res, err := tool.InvokeWithAuthorizedScope(context.Background(), args, target, scope, identity)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a scope replaced after the confirmation")
	}
	if got := string(res.Stderr); !strings.Contains(got, authorizedScopeReplaced) {
		t.Fatalf("stderr = %q, want the pending-replacement refusal", got)
	}
	if got := readFile(t, target); got != original {
		t.Fatalf("replacement file = %q, want byte-identical %q", got, original)
	}
	if got := readFile(t, filepath.Join(aside, "doc.txt")); got != original {
		t.Fatalf("authorized file = %q, want byte-identical %q", got, original)
	}
}

func TestEditTool_AbsentScopeIdentityEditsNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	const original = "alpha BETA gamma\n"
	writeFile(t, file, original)

	args := map[string]any{"path": "doc.txt", "old_text": "BETA", "new_text": "DELTA"}
	res, err := tool.InvokeWithAuthorizedScope(context.Background(), args, file, root, ScopeIdentity{})
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero; an uncaptured identity must never be read as permission to skip the check")
	}
	if got := readFile(t, file); got != original {
		t.Fatalf("file = %q, want byte-identical %q", got, original)
	}
}

func TestEditTool_UnchangedAuthorizedScopeStillApplies(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	writeFile(t, file, "alpha BETA gamma\n")

	args := map[string]any{"path": "doc.txt", "old_text": "BETA", "new_text": "DELTA"}
	res, err := tool.InvokeWithAuthorizedScope(context.Background(), args, file, root, mustCaptureScope(t, root))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result = %+v, stderr = %q, want a successful edit", res, res.Stderr)
	}
	if got, want := readFile(t, file), "alpha DELTA gamma\n"; got != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
}
