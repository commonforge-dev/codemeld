package filetools

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/fsutil"
)

// newCreateToolIn builds a create tool whose project root and relative-path base are root, with a
// separate home anchor, so a relative target lands inside the project and ~ expansion is exercised
// independently — mirroring newToolIn for the edit tool.
func newCreateToolIn(t *testing.T, root string) *CreateTool {
	t.Helper()
	return NewCreateTool(t.TempDir(), root, root)
}

func TestCreateTool_AdvertiseMetadata(t *testing.T) {
	tool := newCreateToolIn(t, t.TempDir())

	if tool.Name() != "create" {
		t.Fatalf("Name() = %q, want create", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = true, want false (the create tool is mutating)")
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
	if !ok || !reflect.DeepEqual(required, []string{"path", "content"}) {
		t.Fatalf("Parameters.required = %v, want [path content]", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties type = %T, want map[string]any", md.Parameters["properties"])
	}
	for _, key := range []string{"path", "content"} {
		if _, ok := props[key]; !ok {
			t.Fatalf("Parameters.properties missing %q", key)
		}
	}

	// The advertised path contract must match runtime behavior: in-project paths create
	// normally, but an out-of-root target is permitted via the permission prompt. Guard against the
	// contract regressing back to a flat "within the project" requirement, which would contradict
	// dispatch now prompting (instead of hard-denying) for an out-of-root create.
	pathProp, ok := props["path"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties[path] type = %T, want map[string]any", props["path"])
	}
	pathDesc, _ := pathProp["description"].(string)
	if strings.Contains(pathDesc, "within the project") {
		t.Fatalf("path description still claims targets are %q; out-of-root creates are prompt-gated, not forbidden: %q", "within the project", pathDesc)
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

// TestCreateTool_ResolveTargetRejectsRoot pins the explicit-root case: the read-only resolver now accepts
// an explicit project-root path, but the mutating create tool must still reject it (the root exists and
// is a directory — you cannot create it), for the absolute, "." and trailing-slash root forms.
func TestCreateTool_ResolveTargetRejectsRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	for _, p := range []string{root, ".", root + string(filepath.Separator)} {
		_, _, err := tool.ResolveTarget(map[string]any{"path": p, "content": "X"})
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("ResolveTarget(path=%q) error = %v, want *TargetError (root must not be creatable)", p, err)
		}
	}
}

func TestCreateTool_ResolveTargetInScope(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	abs := filepath.Join(root, "new.go")
	for _, path := range []string{"new.go", abs} {
		target, scope, err := tool.ResolveTarget(map[string]any{"path": path, "content": "x"})
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

// TestCreateTool_ResolveTargetNestedChild proves the resolver still accepts a new file under an existing
// subdirectory ("subdir/new.txt") after the trailing-slash fix: the parent resolves to the existing
// directory and the child is created there. This is the boundary-valid counterpart to the "subdir/"
// rejection in TestCreateTool_NegativeResolutionTable.
func TestCreateTool_ResolveTargetNestedChild(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	if err := os.Mkdir(filepath.Join(root, "subdir"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	want := filepath.Join(root, "subdir", "new.txt")

	target, scope, err := tool.ResolveTarget(map[string]any{"path": "subdir/new.txt", "content": "NEW"})
	if err != nil {
		t.Fatalf("ResolveTarget(subdir/new.txt) error = %v, want nil", err)
	}
	if target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
	if wantScope := filepath.Join(root, "subdir"); scope != wantScope {
		t.Fatalf("scope = %q, want %q (the existing parent directory)", scope, wantScope)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "subdir/new.txt", "content": "NEW",
	}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readFile(t, want); got != "NEW" {
		t.Fatalf("file = %q, want %q", got, "NEW")
	}
}

func TestCreateTool_ResolveTargetNestedMissingParents(t *testing.T) {
	root := eval(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(root, "existing"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	tool := newCreateToolIn(t, root)

	cases := []struct {
		name       string
		path       string
		wantTarget string
		wantScope  string
	}{
		{"immediate parent missing", "docs/guide.md", filepath.Join(root, "docs", "guide.md"), root},
		{"several parents missing", "a/b/c/file.txt", filepath.Join(root, "a", "b", "c", "file.txt"), root},
		{"deepest ancestor is an existing subdir", "existing/missing/file.txt", filepath.Join(root, "existing", "missing", "file.txt"), filepath.Join(root, "existing")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, scope, err := tool.ResolveTarget(map[string]any{"path": tc.path, "content": "X"})
			if err != nil {
				t.Fatalf("ResolveTarget(%q) error = %v, want nil (missing parents resolve to the deepest existing ancestor)", tc.path, err)
			}
			if target != tc.wantTarget {
				t.Fatalf("target = %q, want the full resolved target %q", target, tc.wantTarget)
			}
			if scope != tc.wantScope {
				t.Fatalf("scope = %q, want the deepest existing ancestor %q", scope, tc.wantScope)
			}
			if tool.OutOfRootScope(scope) {
				t.Fatalf("OutOfRootScope(%q) = true, want false (an in-project ancestor)", scope)
			}
			for _, p := range []string{tc.wantTarget, filepath.Dir(tc.wantTarget)} {
				if _, statErr := os.Lstat(p); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("ResolveTarget created %q on disk: %v", p, statErr)
				}
			}
		})
	}
}

func TestCreateTool_CreatesNestedFile(t *testing.T) {
	root := eval(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(root, "existing"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	cases := []struct {
		name     string
		path     string
		wantDirs []string
	}{
		{"immediate parent missing", "docs/guide.md", []string{"docs"}},
		{"several parents missing", "a/b/c/file.txt", []string{"a", "a/b", "a/b/c"}},
		{"deepest ancestor is an existing subdir", "existing/missing/file.txt", []string{"existing/missing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool := newCreateToolIn(t, root)
			want := filepath.Join(root, filepath.FromSlash(tc.path))
			args := map[string]any{"path": tc.path, "content": "NESTED"}

			target, _, err := tool.ResolveTarget(args)
			if err != nil {
				t.Fatalf("ResolveTarget(%q) error = %v, want nil", tc.path, err)
			}
			res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
			if err != nil {
				t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("ExitCode = %d, want 0 (missing parents are created); stderr=%q", res.ExitCode, res.Stderr)
			}
			if got := readFile(t, want); got != "NESTED" {
				t.Fatalf("leaf file = %q, want %q at %q", got, "NESTED", want)
			}
			for _, d := range tc.wantDirs {
				info, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(d)))
				if statErr != nil {
					t.Fatalf("expected created parent %q missing: %v", d, statErr)
				}
				if !info.IsDir() {
					t.Fatalf("expected parent %q is not a directory: mode=%v", d, info.Mode())
				}
			}
			assertNoTemp(t, filepath.Dir(want))
		})
	}
}

func TestCreateTool_NestedCreateRejectsSymlinkOrNonDirectoryComponent(t *testing.T) {
	t.Run("missing parent replaced by a symlink to an outside directory", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newCreateToolIn(t, root)

		args := map[string]any{"path": "docs/guide.md", "content": "NEW"}
		target, scope, err := tool.ResolveTarget(args)
		if err != nil {
			t.Fatalf("ResolveTarget error = %v, want nil (docs absent ⇒ resolves to the root ancestor)", err)
		}
		if scope != root {
			t.Fatalf("scope = %q, want the deepest existing ancestor %q", scope, root)
		}

		outside := eval(t, t.TempDir())
		if err := os.Symlink(outside, filepath.Join(root, "docs")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
		if err != nil {
			t.Fatalf("InvokeWithResolvedTarget error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero when the missing parent resolved through a symlink")
		}
		if _, statErr := os.Stat(filepath.Join(outside, "guide.md")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("create followed the parent symlink and wrote outside the project: %v", statErr)
		}
		assertNoTemp(t, outside)
	})

	t.Run("missing parent replaced by a regular file", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newCreateToolIn(t, root)

		args := map[string]any{"path": "blocked/guide.md", "content": "NEW"}
		target, _, err := tool.ResolveTarget(args)
		if err != nil {
			t.Fatalf("ResolveTarget error = %v, want nil", err)
		}

		writeFile(t, filepath.Join(root, "blocked"), "NOT A DIR\n")

		res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
		if err != nil {
			t.Fatalf("InvokeWithResolvedTarget error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero when a path component is not a directory")
		}
		if got := readFile(t, filepath.Join(root, "blocked")); got != "NOT A DIR\n" {
			t.Fatalf("blocking file changed = %q, want it untouched", got)
		}
		if _, statErr := os.Lstat(target); statErr == nil {
			t.Fatal("create produced a leaf under a non-directory component")
		}
	})
}

func TestCreateTool_NestedCreateFailureCleanup(t *testing.T) {
	t.Run("leaf publish failure leaves the created parents in place with no leaf or temp", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newCreateToolIn(t, root)
		target := filepath.Join(root, "a", "b", "doc.txt")

		restore := fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced file-sync failure") })
		defer restore()

		res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
			"path": "a/b/doc.txt", "content": "data",
		}, target)
		if err != nil {
			t.Fatalf("error = %v, want nil (a publish failure surfaces in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero after a forced leaf publish failure")
		}
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("leaf unexpectedly exists after a failed nested create: %v", statErr)
		}
		for _, dir := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
			info, statErr := os.Lstat(dir)
			if statErr != nil || !info.IsDir() {
				t.Fatalf("invocation-created parent %q should remain after a failed create: info=%v err=%v", dir, info, statErr)
			}
		}
		assertNoTemp(t, filepath.Join(root, "a", "b"))
		assertNoTemp(t, root)
	})

	t.Run("parent-directory creation failure leaves the created segments in place with no leaf or temp", func(t *testing.T) {
		root := eval(t, t.TempDir())
		tool := newCreateToolIn(t, root)
		target := filepath.Join(root, "a", "b", "doc.txt")

		calls := 0
		restore := fsutil.SetSyncDirForTest(func(f *os.File) error {
			calls++
			if calls >= 2 {
				return errors.New("forced dir-sync failure")
			}
			return f.Sync()
		})
		defer restore()

		res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
			"path": "a/b/doc.txt", "content": "data",
		}, target)
		if err != nil {
			t.Fatalf("error = %v, want nil (a parent-creation failure surfaces in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero after a forced parent-creation failure")
		}
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("leaf unexpectedly exists after a failed nested create: %v", statErr)
		}
		for _, dir := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
			info, statErr := os.Lstat(dir)
			if statErr != nil || !info.IsDir() {
				t.Fatalf("documented residue %q missing after the failed create: info=%v err=%v", dir, info, statErr)
			}
		}
		assertNoTemp(t, filepath.Join(root, "a"))
		assertNoTemp(t, filepath.Join(root, "a", "b"))
	})
}

// TestCreateTool_ResolveTargetOutOfRoot pins that an out-of-root create target is no longer a hard
// *TargetError; it resolves (promptable) to its real out-of-root parent folder as the path scope,
// including a parent reached through an in-project symlink to an out-of-root directory. The create then
// publishes there through InvokeWithResolvedTarget, proving the invoke-time guards now bound the write to
// the *authorized* parent rather than the project root.
func TestCreateTool_ResolveTargetOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	outsideDir := eval(t, t.TempDir())
	target := filepath.Join(outsideDir, "new.txt")

	got, scope, err := tool.ResolveTarget(map[string]any{"path": target, "content": "OUT"})
	if err != nil {
		t.Fatalf("ResolveTarget(out-of-root absolute) error = %v, want nil (promptable)", err)
	}
	if got != target {
		t.Fatalf("target = %q, want %q", got, target)
	}
	if scope != outsideDir {
		t.Fatalf("scope = %q, want the real out-of-root folder %q", scope, outsideDir)
	}
	if !tool.OutOfRootScope(scope) {
		t.Fatalf("OutOfRootScope(%q) = false, want true", scope)
	}

	// The create publishes into the authorized out-of-root parent (the post-auth guards bound the write
	// to that parent, not the project root).
	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": target, "content": "OUT"}, got)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget(out-of-root) error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if content := readFile(t, target); content != "OUT" {
		t.Fatalf("out-of-root file = %q, want %q", content, "OUT")
	}

	// A parent reached through an in-project symlink to an out-of-root directory resolves to the real
	// out-of-root folder, never the in-root lexical parent.
	escapeLink := filepath.Join(root, "escape")
	if err := os.Symlink(outsideDir, escapeLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	wantChild := filepath.Join(outsideDir, "child.txt")
	gotChild, scope2, err := tool.ResolveTarget(map[string]any{"path": "escape/child.txt", "content": "x"})
	if err != nil {
		t.Fatalf("ResolveTarget(escape/child.txt) error = %v, want nil (promptable)", err)
	}
	if gotChild != wantChild {
		t.Fatalf("symlink-parent target = %q, want the real path %q", gotChild, wantChild)
	}
	if scope2 != outsideDir {
		t.Fatalf("symlink-parent scope = %q, want the real out-of-root folder %q", scope2, outsideDir)
	}
	if !tool.OutOfRootScope(scope2) {
		t.Fatalf("OutOfRootScope on symlink parent = false, want true")
	}
}

// TestCreateTool_TildeTargetResolution pins the permission-path-scope tilde contract for the create
// target. The valid subpath form "~/new.txt" expands against the configured home and creates there; the
// invalid forms must not be cleaned into project-local basenames before tilde handling runs.
func TestCreateTool_TildeTargetResolution(t *testing.T) {
	root := eval(t, t.TempDir())
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatalf("Mkdir home: %v", err)
	}
	tool := NewCreateTool(home, root, root)

	// Valid tilde-subpath form: ~/new.txt expands to <home>/new.txt and creates the file there.
	want := filepath.Join(home, "new.txt")
	res, err := tool.Invoke(context.Background(), map[string]any{"path": "~/new.txt", "content": "HI"})
	if err != nil {
		t.Fatalf("Invoke(~/new.txt) error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("Invoke(~/new.txt) ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readFile(t, want); got != "HI" {
		t.Fatalf("~/new.txt created %q, want %q at %q", got, "HI", want)
	}

	// Whole-target tilde forms must be rejected, never anchored as a project-local "~"/"~user" basename.
	for _, p := range []string{"~", "~/", "~user"} {
		res, err := tool.Invoke(context.Background(), map[string]any{"path": p, "content": "X"})
		if err != nil {
			t.Fatalf("Invoke(%q) error = %v, want nil (rejection surfaces in-band)", p, err)
		}
		if res.ExitCode == 0 {
			t.Fatalf("Invoke(%q) ExitCode = 0, want non-zero (whole-target tilde must not create a file)", p)
		}
	}
	for _, name := range []string{"~", "~user"} {
		if _, statErr := os.Lstat(filepath.Join(root, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("whole-target tilde created a project-local %q file: %v", name, statErr)
		}
	}

	// Traversal after a tilde must be interpreted relative to home, not cleaned into a project-local file
	// before expansion. Place home outside the project so "~/../created.txt" expands to a path under
	// home's parent, proving it was not collapsed to a project-local "created.txt".
	outsideHomeRoot := eval(t, t.TempDir())
	outsideHome := filepath.Join(outsideHomeRoot, "home")
	if err := os.Mkdir(outsideHome, 0o755); err != nil {
		t.Fatalf("Mkdir outside home: %v", err)
	}
	outsideHomeTool := NewCreateTool(outsideHome, root, root)

	// "~/../created.txt" expands relative to home to <outsideHomeRoot>/created.txt. An
	// out-of-root target is promptable, not a *TargetError: it resolves to that real out-of-root location
	// with the out-of-root folder as the scope, never a project-local basename. ResolveTarget creates
	// nothing, so no file appears.
	wantOut := filepath.Join(outsideHomeRoot, "created.txt")
	target, scope, err := outsideHomeTool.ResolveTarget(map[string]any{"path": "~/../created.txt", "content": "X"})
	if err != nil {
		t.Fatalf("ResolveTarget(~/../created.txt) error = %v, want nil (out-of-root promptable)", err)
	}
	if target != wantOut {
		t.Fatalf("ResolveTarget(~/../created.txt) target = %q, want %q (expanded relative to home, not project-local)", target, wantOut)
	}
	if scope != outsideHomeRoot {
		t.Fatalf("ResolveTarget(~/../created.txt) scope = %q, want %q", scope, outsideHomeRoot)
	}
	if !outsideHomeTool.OutOfRootScope(scope) {
		t.Fatalf("OutOfRootScope(%q) = false, want true", scope)
	}

	// "~user/../created.txt" is the unsupported ~user form: still a structural *TargetError, never
	// anchored as a project-local basename.
	_, _, uerr := outsideHomeTool.ResolveTarget(map[string]any{"path": "~user/../created.txt", "content": "X"})
	var ute *TargetError
	if !errors.As(uerr, &ute) {
		t.Fatalf("ResolveTarget(~user/../created.txt) error = %v, want *TargetError", uerr)
	}
	for _, path := range []string{filepath.Join(root, "created.txt"), wantOut} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("tilde traversal created %q: %v", path, statErr)
		}
	}
}

func TestCreateTool_CreatesNewFile(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	file := filepath.Join(root, "main.go")

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "main.go", "content": "package main\n",
	}, file)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readFile(t, file); got != "package main\n" {
		t.Fatalf("file = %q, want %q", got, "package main\n")
	}
}

// TestCreateTool_NewFileHonorsProcessUmask is the terminal check on create's publish path: the
// fsutil create publish now fchmods the staged file to exactly the mode it is handed, so a plain
// 0644 request would land 0644 under a 077 umask and widen a new file past what the user's umask
// allows. The mask is re-captured here because the package-level capture ran at init, before
// withUmask changed it.
func TestCreateTool_NewFileHonorsProcessUmask(t *testing.T) {
	withUmask(t, 0o077)
	prev := processUmask
	processUmask = captureUmask()
	t.Cleanup(func() { processUmask = prev })

	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	file := filepath.Join(root, "private.txt")

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "private.txt", "content": "secret\n",
	}, file)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	info, statErr := os.Stat(file)
	if statErr != nil {
		t.Fatalf("Stat: %v", statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600 under the 077 umask", info.Mode().Perm())
	}
}

func TestCreateTool_EmptyContentCreatesEmptyFile(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	file := filepath.Join(root, "empty.txt")

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "empty.txt", "content": "",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readFile(t, file); got != "" {
		t.Fatalf("file = %q, want empty", got)
	}
}

// TestCreateTool_NegativeResolutionTable is the adversarial negative table:
// every out-of-scope or malformed create target is rejected with a *TargetError before authorization,
// and no new file is created. Existing-target cases assert the pre-existing target is left unchanged.
func TestCreateTool_NegativeResolutionTable(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	// Existing regular file.
	existingFile := filepath.Join(root, "exists.txt")
	writeFile(t, existingFile, "ORIGINAL\n")
	// Existing directory.
	existingDir := filepath.Join(root, "subdir")
	if err := os.Mkdir(existingDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	// Existing symlink (dangling): exists as a symlink even though its destination does not.
	danglingLink := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "nowhere"), danglingLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// Out-of-root targets are no longer in this table: they are promptable, not a hard
	// *TargetError (see TestCreateTool_ResolveTargetOutOfRoot). What remains are the structural rejections.
	cases := []struct {
		name string
		path any
	}{
		{"existing regular file", "exists.txt"},
		{"existing directory", "subdir"},
		{"existing directory with trailing slash", "subdir/"},
		{"existing dangling symlink", "dangling"},
		{"empty path", ""},
		{"missing path argument", nil},
		{"non-string path argument", 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{"content": "NEW"}
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

	// Existing targets must be byte/-kind identical after the rejection.
	if got := readFile(t, existingFile); got != "ORIGINAL\n" {
		t.Fatalf("existing file = %q, want unchanged ORIGINAL", got)
	}
	if info, err := os.Stat(existingDir); err != nil || !info.IsDir() {
		t.Fatalf("existing dir changed: info=%v err=%v", info, err)
	}
	// A trailing-slash directory target ("subdir/") must not anchor a phantom child: rejecting it must
	// leave no "<existingDir>/subdir" file behind (the desync the resolver fix closes).
	phantom := filepath.Join(existingDir, "subdir")
	if _, err := os.Lstat(phantom); err == nil {
		t.Fatalf("trailing-slash directory target created a phantom child at %q", phantom)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected stat error for phantom child %q: %v", phantom, err)
	}
	if fi, err := os.Lstat(danglingLink); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("existing symlink changed: mode=%v err=%v", fi.Mode(), err)
	}
}

// TestCreateTool_RejectsExistingTargetThroughInvoke proves the create-only contract on the Invoke path,
// not only at ResolveTarget: creating over an existing file fails in-band with a non-zero exit and the
// original bytes survive.
func TestCreateTool_RejectsExistingTargetThroughInvoke(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	file := filepath.Join(root, "exists.txt")
	const original = "KEEP ME\n"
	writeFile(t, file, original)

	res, err := tool.Invoke(context.Background(), map[string]any{
		"path": "exists.txt", "content": "CLOBBER",
	})
	if err != nil {
		t.Fatalf("Invoke error = %v, want nil (an existing target surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for an existing target")
	}
	if !strings.Contains(string(res.Stderr), "create target rejected") {
		t.Fatalf("stderr = %q, want it to name the rejected target", res.Stderr)
	}
	if got := readFile(t, file); got != original {
		t.Fatalf("file = %q, want byte-identical %q", got, original)
	}
}

// TestCreateTool_PublishTimeMaterializationDoesNotOverwrite pins Done-when 4: a target that materializes
// after pre-authorization resolution but before publish is never overwritten. ResolveTarget sees no
// target; a file then appears at the resolved path; InvokeWithResolvedTarget (using the already-resolved
// target) must fail without overwriting the pre-existing bytes and leave no temp residue.
func TestCreateTool_PublishTimeMaterializationDoesNotOverwrite(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	target, _, err := tool.ResolveTarget(map[string]any{"path": "raced.txt", "content": "NEW"})
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (target absent at resolution)", err)
	}

	// The target materializes between authorization and publish.
	const raced = "MATERIALIZED ELSEWHERE\n"
	writeFile(t, target, raced)

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "raced.txt", "content": "NEW",
	}, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (a publish-time collision surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the target materialized before publish")
	}
	if got := readFile(t, target); got != raced {
		t.Fatalf("file = %q, want the materialized bytes %q preserved (no overwrite)", got, raced)
	}
	assertNoTemp(t, root)
}

// TestCreateTool_ParentSymlinkSwapAfterAuthorizationDoesNotEscape pins the authorization/invocation
// target binding under a post-authorization parent symlink swap. ResolveTarget binds an in-project parent
// (<root>/safe); that parent is then replaced with a symlink to an outside directory before invocation.
// WriteAtomicCreate opens the parent by path at publish time, so without the invocation-time parent
// revalidation the temp file and link publish would follow the new symlink and create the file outside
// the project. The create must instead fail in-band, write no outside file, and leave no temp residue.
func TestCreateTool_ParentSymlinkSwapAfterAuthorizationDoesNotEscape(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	args := map[string]any{"path": "safe/new.txt", "content": "NEW"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (parent in project at resolution)", err)
	}
	if want := filepath.Join(safe, "new.txt"); target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}

	// After authorization, swap the authorized parent for a symlink to an outside directory.
	outside := eval(t, t.TempDir())
	if err := os.Remove(safe); err != nil {
		t.Fatalf("Remove(safe): %v", err)
	}
	if err := os.Symlink(outside, safe); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (a parent swap surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the authorized parent changed to an outside symlink")
	}
	outsideFile := filepath.Join(outside, "new.txt")
	if _, statErr := os.Stat(outsideFile); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("create followed the swapped parent symlink and wrote outside the project: %v", statErr)
	}
	assertNoTemp(t, outside)
}

// TestCreateTool_ParentMoveAfterRevalidationFailsAndLeavesNoFile pins the publish-window rename variant:
// the held parent descriptor follows the directory inode, so if that directory is renamed out of the
// project after invocation-time revalidation but before the publish, the fd-relative publish writes into
// the moved inode. A create reported as success for the authorized in-project path while the file actually
// lives outside the project would violate the target-binding/containment contract, so the create must fail
// and leave no file at the original path, the moved (outside) directory, or any replacement put in place.
func TestCreateTool_ParentMoveAfterRevalidationFailsAndLeavesNoFile(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	args := map[string]any{"path": "safe/new.txt", "content": "NEW"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (parent in project at resolution)", err)
	}

	origBeforeCreatePublish := beforeCreatePublish
	t.Cleanup(func() { beforeCreatePublish = origBeforeCreatePublish })
	outsideParent := eval(t, t.TempDir())
	movedSafe := filepath.Join(outsideParent, "safe-moved")
	replacement := eval(t, t.TempDir())
	beforeCreatePublish = func() {
		// Move the authorized directory entirely outside the project (the held fd follows it there), then
		// drop a symlink to a different outside directory in its place so the authorized path still appears
		// to exist but no longer names the held inode.
		if err := os.Rename(safe, movedSafe); err != nil {
			t.Fatalf("Rename(safe): %v", err)
		}
		if err := os.Symlink(replacement, safe); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (a parent move surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the authorized parent was moved out of the project before publish")
	}
	for _, loc := range []struct {
		what string
		file string
	}{
		{"original authorized path", filepath.Join(root, "safe", "new.txt")},
		{"moved (outside) directory", filepath.Join(movedSafe, "new.txt")},
		{"replacement directory", filepath.Join(replacement, "new.txt")},
	} {
		if _, statErr := os.Stat(loc.file); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("file unexpectedly present at the %s (%s): %v", loc.what, loc.file, statErr)
		}
	}
	assertNoTemp(t, movedSafe)
	assertNoTemp(t, replacement)
	assertNoTemp(t, root)
}

func TestCreateTool_NestedParentMoveAfterPublishFailsAndLeavesNoFile(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	args := map[string]any{"path": "docs/guide.md", "content": "NEW"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (docs absent ⇒ resolves to the root ancestor)", err)
	}

	origBeforeCreatePublish := beforeCreatePublish
	t.Cleanup(func() { beforeCreatePublish = origBeforeCreatePublish })
	outsideParent := eval(t, t.TempDir())
	movedDocs := filepath.Join(outsideParent, "docs-moved")
	replacement := eval(t, t.TempDir())
	beforeCreatePublish = func() {
		docs := filepath.Join(root, "docs")
		if err := os.Rename(docs, movedDocs); err != nil {
			t.Fatalf("Rename(docs): %v", err)
		}
		if err := os.Symlink(replacement, docs); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (a nested parent move surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when a just-created nested parent was moved out of the project before publish")
	}
	for _, loc := range []struct {
		what string
		file string
	}{
		{"original authorized path", filepath.Join(root, "docs", "guide.md")},
		{"moved (outside) directory", filepath.Join(movedDocs, "guide.md")},
		{"replacement directory", filepath.Join(replacement, "guide.md")},
	} {
		if _, statErr := os.Stat(loc.file); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("file unexpectedly present at the %s (%s): %v", loc.what, loc.file, statErr)
		}
	}
	assertNoTemp(t, movedDocs)
	assertNoTemp(t, replacement)
	assertNoTemp(t, root)
}

func TestCreateTool_ConcurrentReplacementDirsSurviveFailedCreate(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	args := map[string]any{"path": "a/b/doc.txt", "content": "NEW"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (a absent ⇒ resolves to the root ancestor)", err)
	}

	origBeforeCreatePublish := beforeCreatePublish
	t.Cleanup(func() { beforeCreatePublish = origBeforeCreatePublish })
	outsideParent := eval(t, t.TempDir())
	movedAB := filepath.Join(outsideParent, "ab-moved")
	beforeCreatePublish = func() {
		ab := filepath.Join(root, "a", "b")
		if err := os.Rename(ab, movedAB); err != nil {
			t.Fatalf("Rename(a/b): %v", err)
		}
		if err := os.Mkdir(ab, 0o755); err != nil {
			t.Fatalf("Mkdir(replacement a/b): %v", err)
		}
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (a moved nested parent surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the invocation-created nested parent was replaced before publish")
	}

	for _, dir := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
		info, statErr := os.Lstat(dir)
		if statErr != nil || !info.IsDir() {
			t.Fatalf("concurrent replacement %q must survive a failed create, not be unlinked by name: info=%v err=%v", dir, info, statErr)
		}
	}
	for _, loc := range []struct {
		what string
		file string
	}{
		{"replacement path", filepath.Join(root, "a", "b", "doc.txt")},
		{"moved (outside) directory", filepath.Join(movedAB, "doc.txt")},
	} {
		if _, statErr := os.Stat(loc.file); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("file unexpectedly present at the %s (%s): %v", loc.what, loc.file, statErr)
		}
	}
	assertNoTemp(t, filepath.Join(root, "a", "b"))
	assertNoTemp(t, movedAB)
	assertNoTemp(t, root)
}

// TestCreateTool_NoTempResidueOnWriteFailure pins Done-when 4: a failure during the write leaves no
// target file and no leftover temp file.
func TestCreateTool_NoTempResidueOnWriteFailure(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	file := filepath.Join(root, "doc.txt")

	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return errors.New("forced sync failure") })
	defer restore()

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{
		"path": "doc.txt", "content": "data",
	}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (a write failure surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after a forced write failure")
	}
	if _, statErr := os.Stat(file); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("target unexpectedly exists after a failed create: %v", statErr)
	}
	assertNoTemp(t, root)
}

// TestCreateTool_RejectsUnknownArgs pins the closed advertised schema (additionalProperties:false):
// a call carrying an extra key is rejected before authorization or creation on every entry —
// ResolveTarget, create via InvokeWithResolvedTarget, and the standalone Invoke — and creates no file.
func TestCreateTool_RejectsUnknownArgs(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	extraArgs := map[string]any{"path": "doc.txt", "content": "data", "unexpected": true}
	file := filepath.Join(root, "doc.txt")

	t.Run("ResolveTarget rejects before authorization", func(t *testing.T) {
		_, _, err := tool.ResolveTarget(extraArgs)
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("ResolveTarget error = %v, want *TargetError for an extra property", err)
		}
	})

	t.Run("InvokeWithResolvedTarget rejects at create", func(t *testing.T) {
		res, err := tool.InvokeWithResolvedTarget(context.Background(), extraArgs, file)
		if err != nil {
			t.Fatalf("error = %v, want nil (an extra property surfaces in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an extra property")
		}
		if _, statErr := os.Stat(file); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("file created despite a rejected extra property: %v", statErr)
		}
	})

	t.Run("Invoke rejects and creates nothing", func(t *testing.T) {
		res, err := tool.Invoke(context.Background(), extraArgs)
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (an extra property is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an extra property")
		}
		if _, statErr := os.Stat(file); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("file created despite a rejected extra property: %v", statErr)
		}
	})
}

// TestCreateTool_ResolvedTargetRequiresRequiredArgs pins the advertised required args on the resolved-target
// invocation seam: InvokeWithResolvedTarget reaches create with the target already resolved, so a call
// omitting `path` or `content` must still fail non-zero and create no file — the runtime contract stays no
// broader than the advertised schema on the production invocation path.
func TestCreateTool_ResolvedTargetRequiresRequiredArgs(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
	}{
		{"missing path", map[string]any{"content": "data"}},
		{"missing content", map[string]any{"path": "doc.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := eval(t, t.TempDir())
			tool := newCreateToolIn(t, root)
			file := filepath.Join(root, "doc.txt")

			res, err := tool.InvokeWithResolvedTarget(context.Background(), tc.args, file)
			if err != nil {
				t.Fatalf("error = %v, want nil (a missing required argument surfaces in-band)", err)
			}
			if res.ExitCode == 0 {
				t.Fatalf("ExitCode = 0, want non-zero for %s", tc.name)
			}
			if _, statErr := os.Stat(file); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("file created despite %s: %v", tc.name, statErr)
			}
		})
	}
}

// TestCreateTool_InvokeStandalone exercises the non-dispatch Invoke entry: it resolves and creates in one
// call, and surfaces a structural resolution failure as the same in-band failure the dispatcher would
// render. Out-of-root is no longer a resolution failure, so standalone Invoke — which has no
// authorizer — must refuse an out-of-root resolved target itself (see the out-of-root subtests); only
// dispatch can authorize an out-of-root write.
func TestCreateTool_InvokeStandalone(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	t.Run("resolves and creates", func(t *testing.T) {
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": "new.txt", "content": "hello\n",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
		}
		if got := readFile(t, filepath.Join(root, "new.txt")); got != "hello\n" {
			t.Fatalf("file = %q, want %q", got, "hello\n")
		}
	})

	t.Run("missing parents are created for a nested in-project target", func(t *testing.T) {
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": "no/such/parent/x.txt", "content": "data",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("ExitCode = %d, want 0 (missing in-project parents are created); stderr=%q", res.ExitCode, res.Stderr)
		}
		if got := readFile(t, filepath.Join(root, "no", "such", "parent", "x.txt")); got != "data" {
			t.Fatalf("nested file = %q, want %q", got, "data")
		}
		if info, statErr := os.Stat(filepath.Join(root, "no", "such", "parent")); statErr != nil || !info.IsDir() {
			t.Fatalf("nested parent directories not created: info=%v err=%v", info, statErr)
		}
	})
}

// TestCreateTool_InvokeStandaloneRejectsOutOfRoot pins the out-of-root boundary on the standalone Invoke path:
// it has no authorizer, so an out-of-root resolved target — whether a direct absolute path or an in-root
// lexical path whose parent symlink-resolves outside the root — must fail in-band and create nothing
// outside the project. Only dispatch can authorize an out-of-root write through the approval prompt; if
// this guard were removed the asserts below would fail (a file would appear outside the root).
func TestCreateTool_InvokeStandaloneRejectsOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)

	outsideDir := eval(t, t.TempDir())

	t.Run("direct out-of-root absolute path", func(t *testing.T) {
		outsideFile := filepath.Join(outsideDir, "new.txt")
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": outsideFile, "content": "x",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an out-of-root create")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if _, statErr := os.Stat(outsideFile); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("file created outside the project root: %v", statErr)
		}
	})

	t.Run("in-root lexical path whose parent symlink-escapes the root", func(t *testing.T) {
		escapeLink := filepath.Join(root, "escape")
		if err := os.Symlink(outsideDir, escapeLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		res, err := tool.Invoke(context.Background(), map[string]any{
			"path": "escape/sneaky.txt", "content": "x",
		})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for a symlink-escaped create")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if _, statErr := os.Stat(filepath.Join(outsideDir, "sneaky.txt")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("file created outside the project root via symlink escape: %v", statErr)
		}
	})
}

// assertNoTemp fails if any sibling temp file is left in dir after a create attempt.
func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %q after a failed create", e.Name())
		}
	}
}

// fakeJournal records the seam calls a mutating tool makes so their order and payloads can be pinned
// without a real durable journal.
type fakeJournal struct {
	covered      map[string]bool
	maxState     int64
	beginErr     error
	events       []string
	observed     []JournalState
	next         []JournalState
	removed      []JournalState
	resolved     []string
	abandoned    []string
	resolvedWith []JournalState
	dirIntent    []string
	dirDone      []fsutil.DirSegment
	onBegin      func()
	onResolve    func()

	beginDeleteErr error
	onBeginDelete  func()

	beginMoveErr error
}

func newFakeJournal(covered ...string) *fakeJournal {
	j := &fakeJournal{covered: map[string]bool{}, maxState: 10 << 20}
	for _, target := range covered {
		j.covered[target] = true
	}
	return j
}

func (j *fakeJournal) Covers(target string) bool { return j.covered[target] }

func (j *fakeJournal) MaxStateBytes() int64 { return j.maxState }

func (j *fakeJournal) BeginMutation(target string, observed, next JournalState) error {
	j.events = append(j.events, "begin:"+target)
	j.observed = append(j.observed, observed)
	j.next = append(j.next, next)
	if j.onBegin != nil {
		j.onBegin()
	}
	return j.beginErr
}

func (j *fakeJournal) BeginDelete(target string, _ *os.File) error {
	j.events = append(j.events, "begin_delete:"+target)
	if j.onBeginDelete != nil {
		j.onBeginDelete()
	}
	return j.beginDeleteErr
}

func (j *fakeJournal) ResolveMutation(target string, _ *os.File, published JournalState) {
	j.events = append(j.events, "resolve:"+target)
	j.resolved = append(j.resolved, target)
	j.resolvedWith = append(j.resolvedWith, published)
	if j.onResolve != nil {
		j.onResolve()
	}
}

func (j *fakeJournal) AbandonMutation(target string, _ *os.File) {
	j.events = append(j.events, "abandon:"+target)
	j.abandoned = append(j.abandoned, target)
}

func (j *fakeJournal) RemovePublished(target string, _ *os.File, published JournalState) {
	j.events = append(j.events, "remove:"+target)
	j.removed = append(j.removed, published)
}

func (j *fakeJournal) MoveLifecycle(source, destination string) fsutil.MoveLifecycle {
	return fsutil.MoveLifecycle{
		BeforeRename: func(*os.File, *os.File) error {
			j.events = append(j.events, "begin_move:"+source+">"+destination)
			return j.beginMoveErr
		},
		AfterRename: func(*os.File, *os.File) {
			j.events = append(j.events, "resolve_move:"+source+">"+destination)
		},
	}
}

func (j *fakeJournal) DirLifecycle(string, string) fsutil.DirLifecycle {
	return fsutil.DirLifecycle{
		Intent: func(rel string) error {
			j.dirIntent = append(j.dirIntent, rel)
			return nil
		},
		Confirm: func(seg fsutil.DirSegment) error {
			j.dirDone = append(j.dirDone, seg)
			return nil
		},
	}
}

func TestCreateTool_JournalsThePendingStateAroundThePublish(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	target := filepath.Join(root, "made", "deep", "new.txt")
	journal := newFakeJournal(target)

	var visibleAtBegin bool
	journal.onBegin = func() {
		_, err := os.Lstat(target)
		visibleAtBegin = err == nil
	}

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": target, "content": "CHILD\n"}, target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("create failed: %s", res.Stderr)
	}
	if visibleAtBegin {
		t.Fatal("the pending state was recorded after publication, not before it")
	}
	want := []string{"begin:" + target, "resolve:" + target}
	if !reflect.DeepEqual(journal.events, want) {
		t.Fatalf("journal events = %v, want %v", journal.events, want)
	}
	if journal.observed[0].Exists {
		t.Fatalf("observed state = %+v, want an absence for a create", journal.observed[0])
	}
	if got := string(journal.next[0].Data); got != "CHILD\n" || journal.next[0].Mode.Perm() == 0 {
		t.Fatalf("pending state = %+v, want the exact bytes and mode publication makes visible", journal.next[0])
	}
	if !reflect.DeepEqual(journal.dirIntent, []string{"made", "made/deep"}) {
		t.Fatalf("directory intents = %v, want one per created segment", journal.dirIntent)
	}
	if len(journal.dirDone) != 2 {
		t.Fatalf("directory confirmations = %v, want one per intent", journal.dirDone)
	}
	for _, seg := range journal.dirDone {
		if !seg.Created || seg.Ino == 0 {
			t.Fatalf("confirmed segment %+v, want it recorded as created with an identity", seg)
		}
	}
}

func TestCreateTool_JournalRefusalKeepsTheCreateInvisible(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	target := filepath.Join(root, "new.txt")
	journal := newFakeJournal(target)
	journal.beginErr = errors.New("journal is full")

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": target, "content": "CHILD\n"}, target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("create published despite the journal refusing to record it")
	}
	if _, serr := os.Lstat(target); !os.IsNotExist(serr) {
		t.Fatalf("target exists (err=%v), want nothing published", serr)
	}
}

func TestCreateTool_OverCapContentIsRefusedBeforeAnyParentDirectory(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	target := filepath.Join(root, "made", "new.txt")
	journal := newFakeJournal(target)
	journal.maxState = 8

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": target, "content": "123456789"}, target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("create accepted content over the journal's per-path limit")
	}
	if _, serr := os.Lstat(filepath.Join(root, "made")); !os.IsNotExist(serr) {
		t.Fatalf("parent directory exists (err=%v), want the refusal to precede EnsureDirAt", serr)
	}
	if len(journal.events) != 0 {
		t.Fatalf("journal events = %v, want the refusal to precede any record", journal.events)
	}

	atCap, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": target, "content": "12345678"}, target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if atCap.ExitCode != 0 {
		t.Fatalf("create refused content at exactly the limit: %s", atCap.Stderr)
	}
}

// TestCreateTool_ParentMovedAfterPublishHandsTheJournalItsPublishedIdentity pins that create's
// post-publication cleanup names the inode the publish reported rather than whatever the leaf holds,
// which is the only thing that keeps a swapped-in file from being unlinked.
func TestCreateTool_ParentMovedAfterPublishHandsTheJournalItsPublishedIdentity(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	authorized := filepath.Join(root, "sub")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(authorized, "new.txt")
	journal := newFakeJournal(target)
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

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal),
		map[string]any{"path": target, "content": "CHILD\n"}, target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("create reported success after its authorized parent moved")
	}
	if len(journal.removed) != 1 {
		t.Fatalf("journal removals = %v, want the cleanup routed through the journal", journal.events)
	}
	published := journal.removed[0]
	if published.Ino == 0 || string(published.Data) != "CHILD\n" {
		t.Fatalf("published identity = %+v, want the inode the publish reported", published)
	}
	if _, serr := os.Lstat(filepath.Join(moved, "new.txt")); serr != nil {
		t.Fatalf("the journal, not the tool, owns the removal; leaf stat = %v", serr)
	}
}

func mustCaptureScope(t *testing.T, scope string) ScopeIdentity {
	t.Helper()
	identity, err := CaptureScopeIdentity(scope)
	if err != nil {
		t.Fatalf("CaptureScopeIdentity(%q): %v", scope, err)
	}
	return identity
}

// The swap the captured identity exists to catch: every path-based check still sees a directory where
// one is expected.
func replaceDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("RemoveAll(%q): %v", path, err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", path, err)
	}
}

// swapAuthorizedScope moves the directory at path aside and puts a fresh, empty one in its place,
// returning where the original now lives. Renaming rather than deleting keeps the original directory
// reachable through the descriptor the confirmation holds, so a test can tell a refusal apart from an
// operation that simply hit an unlinked directory, and can assert neither directory was mutated.
func swapAuthorizedScope(t *testing.T, path string) string {
	t.Helper()
	aside := path + ".aside"
	if err := os.Rename(path, aside); err != nil {
		t.Fatalf("Rename(%q): %v", path, err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(%q): %v", path, err)
	}
	return aside
}

// afterScopeConfirmedOnce runs fn in the window between the scope-identity confirmation and the
// operation helper's first directory open — the interval a confirmation that released its descriptor
// left unguarded.
func afterScopeConfirmedOnce(t *testing.T, fn func()) {
	t.Helper()
	orig := afterScopeConfirmed
	t.Cleanup(func() { afterScopeConfirmed = orig })
	done := false
	afterScopeConfirmed = func() {
		if done {
			return
		}
		done = true
		fn()
	}
}

func TestCreateTool_ScopeReplacedAfterConfirmationCreatesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "new.go")
	identity := mustCaptureScope(t, scope)

	var aside string
	afterScopeConfirmedOnce(t, func() { aside = swapAuthorizedScope(t, scope) })

	args := map[string]any{"path": "pkg/new.go", "content": "package pkg\n"}
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
	if _, serr := os.Lstat(target); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Lstat(replacement target) = %v, want nothing created in the replacement directory", serr)
	}
	if _, serr := os.Lstat(filepath.Join(aside, "new.go")); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Lstat(original target) = %v, want nothing created in the authorized directory either", serr)
	}
}

func TestCaptureScopeIdentity_RefusesWhatIsNotTheDirectoryItself(t *testing.T) {
	root := eval(t, t.TempDir())
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if _, err := CaptureScopeIdentity(link); err == nil {
		t.Fatal("CaptureScopeIdentity(symlink) = nil error, want a refusal to capture what the link points at")
	}
	if _, err := CaptureScopeIdentity(filepath.Join(root, "absent")); err == nil {
		t.Fatal("CaptureScopeIdentity(missing) = nil error, want a capture failure")
	}
	if _, err := CaptureScopeIdentity(filepath.Join(root, "real")); err != nil {
		t.Fatalf("CaptureScopeIdentity(directory) = %v, want a successful capture", err)
	}
}

func TestCreateTool_AuthorizedScopeReplacedWhilePendingCreatesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "new.go")
	identity := mustCaptureScope(t, scope)

	replaceDirectory(t, scope)

	args := map[string]any{"path": "pkg/new.go", "content": "package pkg\n"}
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
	if _, serr := os.Lstat(target); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Lstat(target) = %v, want the file never created", serr)
	}
}

func TestCreateTool_AbsentScopeIdentityCreatesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	target := filepath.Join(root, "new.go")

	args := map[string]any{"path": "new.go", "content": "package main\n"}
	res, err := tool.InvokeWithAuthorizedScope(context.Background(), args, target, root, ScopeIdentity{})
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero; an uncaptured identity must never be read as permission to skip the check")
	}
	if _, serr := os.Lstat(target); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Lstat(target) = %v, want the file never created", serr)
	}
}

// The comparison is against the authorized scope, never the deepest ancestor existing at invocation.
func TestCreateTool_IntermediateDirectoryAppearingWhilePendingStillCreates(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newCreateToolIn(t, root)
	target := filepath.Join(root, "a", "b", "new.go")
	identity := mustCaptureScope(t, root)

	if err := os.Mkdir(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	args := map[string]any{"path": "a/b/new.go", "content": "package b\n"}
	res, err := tool.InvokeWithAuthorizedScope(context.Background(), args, target, root, identity)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result = %+v, stderr = %q, want a successful create", res, res.Stderr)
	}
	if got := readFile(t, target); got != "package b\n" {
		t.Fatalf("file = %q, want the created content", got)
	}
}
