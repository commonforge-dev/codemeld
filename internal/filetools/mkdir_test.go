// Unit tests for the built-in mkdir tool: metadata/classification, pre-authorization mkdir -p target
// resolution (in-scope, nested missing parents, existing directory idempotence, tilde, `..` normalization,
// existing non-directory component, symlink escape, out-of-root prompt, bad args), fd-relative nested
// creation, and post-authorization symlink-swap / rename rejection with no residue.
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

// newMkdirToolIn builds a mkdir tool whose project root and relative-path base are root, with a separate
// home anchor, so a relative target lands inside the project and ~ expansion is exercised independently —
// mirroring newCreateToolIn for the create tool.
func newMkdirToolIn(t *testing.T, root string) *MkdirTool {
	t.Helper()
	return NewMkdirTool(t.TempDir(), root, root)
}

func TestMkdirTool_AdvertiseMetadata(t *testing.T) {
	tool := newMkdirToolIn(t, t.TempDir())

	if tool.Name() != "mkdir" {
		t.Fatalf("Name() = %q, want mkdir", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = true, want false (the mkdir tool is mutating)")
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
	if !ok || !reflect.DeepEqual(required, []string{"path"}) {
		t.Fatalf("Parameters.required = %v, want [path]", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties type = %T, want map[string]any", md.Parameters["properties"])
	}
	if _, ok := props["path"]; !ok {
		t.Fatal("Parameters.properties missing \"path\"")
	}
	// The closed schema must carry no key beyond path (the runtime arg-set check enforces the same).
	if len(props) != 1 {
		t.Fatalf("Parameters.properties = %v, want exactly {path}", props)
	}

	// The advertised path contract must match runtime behavior: in-project paths create normally,
	// but an out-of-root target is permitted via the permission prompt, not hard-denied.
	pathProp, ok := props["path"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties[path] type = %T, want map[string]any", props["path"])
	}
	pathDesc, _ := pathProp["description"].(string)
	for _, want := range []string{"outside the project", "permission prompt"} {
		if !strings.Contains(pathDesc, want) {
			t.Fatalf("path description = %q, want it to mention %q (out-of-root prompt approval)", pathDesc, want)
		}
	}
}

func TestMkdirTool_ResolveTargetInScope(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	abs := filepath.Join(root, "newdir")
	for _, path := range []string{"newdir", abs} {
		target, scope, err := tool.ResolveTarget(map[string]any{"path": path})
		if err != nil {
			t.Fatalf("ResolveTarget(%q) error = %v, want nil", path, err)
		}
		if target != abs {
			t.Fatalf("ResolveTarget(%q) target = %q, want %q", path, target, abs)
		}
		// The deepest existing ancestor (the project root) is the authorized scope the new dir lands under.
		if scope != root {
			t.Fatalf("ResolveTarget(%q) scope = %q, want %q (the deepest existing ancestor)", path, scope, root)
		}
		if tool.OutOfRootScope(scope) {
			t.Fatalf("OutOfRootScope(%q) = true, want false for an in-project target", scope)
		}
	}
}

// TestMkdirTool_ResolveTargetNestedMissingParents pins the mkdir -p resolver contract: with several missing
// parents, the resolver authorizes the deepest existing ancestor (here the project root) as the scope and
// the full nested path as the target, then InvokeWithResolvedTarget creates the whole tree fd-relative.
func TestMkdirTool_ResolveTargetNestedMissingParents(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	want := filepath.Join(root, "a", "b", "c")
	target, scope, err := tool.ResolveTarget(map[string]any{"path": "a/b/c"})
	if err != nil {
		t.Fatalf("ResolveTarget(a/b/c) error = %v, want nil", err)
	}
	if target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
	if scope != root {
		t.Fatalf("scope = %q, want %q (the deepest existing ancestor)", scope, root)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "a/b/c"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	for _, dir := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b"), want} {
		if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
			t.Fatalf("nested dir %q not created: info=%v err=%v", dir, info, statErr)
		}
	}
}

// TestMkdirTool_NestedUnderExistingSubdir authorizes the deepest existing ancestor when it is a subdirectory
// rather than the root: the scope is the existing subdirectory, not the root.
func TestMkdirTool_NestedUnderExistingSubdir(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	want := filepath.Join(sub, "x", "y")
	target, scope, err := tool.ResolveTarget(map[string]any{"path": "sub/x/y"})
	if err != nil {
		t.Fatalf("ResolveTarget(sub/x/y) error = %v, want nil", err)
	}
	if target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
	if scope != sub {
		t.Fatalf("scope = %q, want %q (the existing subdirectory)", scope, sub)
	}
}

// TestMkdirTool_ExistingDirectoryIdempotent pins mkdir -p idempotence: resolving an already-existing
// directory is not an error, and creating it again succeeds without changing it.
func TestMkdirTool_ExistingDirectoryIdempotent(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	sub := filepath.Join(root, "exists")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeFile(t, filepath.Join(sub, "keep.txt"), "KEEP\n")

	target, scope, err := tool.ResolveTarget(map[string]any{"path": "exists"})
	if err != nil {
		t.Fatalf("ResolveTarget(exists) error = %v, want nil (idempotent)", err)
	}
	if target != sub || scope != sub {
		t.Fatalf("target=%q scope=%q, want both %q", target, scope, sub)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "exists"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (idempotent existing dir); stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readFile(t, filepath.Join(sub, "keep.txt")); got != "KEEP\n" {
		t.Fatalf("idempotent mkdir disturbed existing contents: %q", got)
	}
}

// TestMkdirTool_ResolveTargetNormalizesDotDot proves a `..` segment is normalized before resolution, so an
// in-project path with traversal still resolves to its cleaned in-root target rather than being rejected.
func TestMkdirTool_ResolveTargetNormalizesDotDot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	want := filepath.Join(root, "newdir")
	target, scope, err := tool.ResolveTarget(map[string]any{"path": "sub/../newdir"})
	if err != nil {
		t.Fatalf("ResolveTarget(sub/../newdir) error = %v, want nil", err)
	}
	if target != want {
		t.Fatalf("target = %q, want %q (the `..` must normalize to an in-root path)", target, want)
	}
	if scope != root {
		t.Fatalf("scope = %q, want %q", scope, root)
	}
}

// TestMkdirTool_TildeTargetResolution pins the tilde contract. The valid subpath form "~/newdir" expands
// against the configured home (placed inside the project so it stays in-root) and creates there; the
// unsupported ~user form is a structural *TargetError, never anchored as a project-local basename.
func TestMkdirTool_TildeTargetResolution(t *testing.T) {
	root := eval(t, t.TempDir())
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatalf("Mkdir home: %v", err)
	}
	tool := NewMkdirTool(home, root, root)

	want := filepath.Join(home, "newdir")
	res, err := tool.Invoke(context.Background(), map[string]any{"path": "~/newdir"})
	if err != nil {
		t.Fatalf("Invoke(~/newdir) error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("Invoke(~/newdir) ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if info, statErr := os.Stat(want); statErr != nil || !info.IsDir() {
		t.Fatalf("~/newdir not created at %q: info=%v err=%v", want, info, statErr)
	}

	for _, p := range []string{"~user", "~user/sub"} {
		_, _, terr := tool.ResolveTarget(map[string]any{"path": p})
		var te *TargetError
		if !errors.As(terr, &te) {
			t.Fatalf("ResolveTarget(%q) error = %v, want *TargetError (unsupported ~user form)", p, terr)
		}
		if _, statErr := os.Lstat(filepath.Join(root, "~user")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("~user resolution created a project-local basename: %v", statErr)
		}
	}
}

// TestMkdirTool_ResolveTargetOutOfRoot pins that an out-of-root mkdir target is not a hard
// *TargetError; it resolves (promptable) to its real out-of-root ancestor as the scope, including an
// ancestor reached through an in-project symlink to an out-of-root directory (the symlink-escape case).
// The create then lands there through InvokeWithResolvedTarget, proving the invoke-time guards bound the
// create to the authorized ancestor rather than the project root.
func TestMkdirTool_ResolveTargetOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	outsideDir := eval(t, t.TempDir())
	target := filepath.Join(outsideDir, "newsub")

	got, scope, err := tool.ResolveTarget(map[string]any{"path": target})
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

	// The mkdir lands in the authorized out-of-root ancestor (the post-auth guards bound it to that
	// ancestor, not the project root).
	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": target}, got)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget(out-of-root) error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		t.Fatalf("out-of-root dir not created: info=%v err=%v", info, statErr)
	}

	// An ancestor reached through an in-project symlink to an out-of-root directory resolves to the real
	// out-of-root folder, never the in-root lexical ancestor (boundary-bypass guard).
	escapeLink := filepath.Join(root, "escape")
	if err := os.Symlink(outsideDir, escapeLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	wantChild := filepath.Join(outsideDir, "child")
	gotChild, scope2, err := tool.ResolveTarget(map[string]any{"path": "escape/child"})
	if err != nil {
		t.Fatalf("ResolveTarget(escape/child) error = %v, want nil (promptable)", err)
	}
	if gotChild != wantChild {
		t.Fatalf("symlink-ancestor target = %q, want the real path %q", gotChild, wantChild)
	}
	if scope2 != outsideDir {
		t.Fatalf("symlink-ancestor scope = %q, want the real out-of-root folder %q", scope2, outsideDir)
	}
	if !tool.OutOfRootScope(scope2) {
		t.Fatalf("OutOfRootScope on symlink ancestor = false, want true")
	}
}

// TestMkdirTool_NegativeResolutionTable is the adversarial negative table: every malformed or structurally
// invalid mkdir target is rejected with a *TargetError before authorization, and nothing is created.
// (An existing *directory* target is not here — it is idempotent success, covered separately.)
func TestMkdirTool_NegativeResolutionTable(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	existingFile := filepath.Join(root, "file.txt")
	writeFile(t, existingFile, "DATA\n")
	danglingLink := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "nowhere"), danglingLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	cases := []struct {
		name string
		path any
	}{
		{"target is an existing regular file", "file.txt"},
		{"existing non-directory component", "file.txt/sub"},
		{"target is a dangling symlink", "dangling"},
		{"unsupported ~user form", "~user"},
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

	// The existing entries must survive the rejections unchanged.
	if got := readFile(t, existingFile); got != "DATA\n" {
		t.Fatalf("existing file = %q, want unchanged DATA", got)
	}
	if fi, err := os.Lstat(danglingLink); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("existing symlink changed: mode=%v err=%v", fi.Mode(), err)
	}
}

// TestMkdirTool_RejectsUnknownArgs pins the closed advertised schema (additionalProperties:false): a call
// carrying an extra key is rejected before authorization or creation on every entry — ResolveTarget,
// InvokeWithResolvedTarget, and the standalone Invoke — and creates no directory.
func TestMkdirTool_RejectsUnknownArgs(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	extraArgs := map[string]any{"path": "newdir", "unexpected": true}
	dir := filepath.Join(root, "newdir")

	t.Run("ResolveTarget rejects before authorization", func(t *testing.T) {
		_, _, err := tool.ResolveTarget(extraArgs)
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("ResolveTarget error = %v, want *TargetError for an extra property", err)
		}
	})

	t.Run("InvokeWithResolvedTarget rejects at create", func(t *testing.T) {
		res, err := tool.InvokeWithResolvedTarget(context.Background(), extraArgs, dir)
		if err != nil {
			t.Fatalf("error = %v, want nil (an extra property surfaces in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an extra property")
		}
		if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("directory created despite a rejected extra property: %v", statErr)
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
		if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("directory created despite a rejected extra property: %v", statErr)
		}
	})
}

// TestMkdirTool_ResolvedTargetRequiresPath pins the advertised required arg on the resolved-target
// invocation seam: a call omitting `path` must still fail non-zero and create no directory.
func TestMkdirTool_ResolvedTargetRequiresPath(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	dir := filepath.Join(root, "newdir")

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{}, dir)
	if err != nil {
		t.Fatalf("error = %v, want nil (a missing required argument surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a missing path argument")
	}
	if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("directory created despite a missing path argument: %v", statErr)
	}
}

// TestMkdirTool_InvokeStandaloneRejectsOutOfRoot pins the out-of-root boundary on the standalone Invoke path:
// it has no authorizer, so an out-of-root resolved target — a direct absolute path or an in-root lexical
// path whose ancestor symlink-resolves outside the root — must fail in-band and create nothing outside the
// project. Only dispatch can authorize an out-of-root write through the approval prompt.
func TestMkdirTool_InvokeStandaloneRejectsOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	outsideDir := eval(t, t.TempDir())

	t.Run("direct out-of-root absolute path", func(t *testing.T) {
		outsideSub := filepath.Join(outsideDir, "newsub")
		res, err := tool.Invoke(context.Background(), map[string]any{"path": outsideSub})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an out-of-root mkdir")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if _, statErr := os.Stat(outsideSub); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("directory created outside the project root: %v", statErr)
		}
	})

	t.Run("in-root lexical path whose ancestor symlink-escapes the root", func(t *testing.T) {
		escapeLink := filepath.Join(root, "escape")
		if err := os.Symlink(outsideDir, escapeLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		res, err := tool.Invoke(context.Background(), map[string]any{"path": "escape/sneaky"})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for a symlink-escaped mkdir")
		}
		if _, statErr := os.Stat(filepath.Join(outsideDir, "sneaky")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("directory created outside the project root via symlink escape: %v", statErr)
		}
	})
}

// TestMkdirTool_ParentSymlinkSwapAfterAuthorizationDoesNotEscape pins the authorization/invocation binding
// under a post-authorization ancestor symlink swap. ResolveTarget binds an in-project ancestor
// (<root>/safe); that ancestor is then replaced with a symlink to an outside directory before invocation.
// The fd-relative create must refuse rather than follow the swapped symlink and create outside the project.
func TestMkdirTool_ParentSymlinkSwapAfterAuthorizationDoesNotEscape(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	args := map[string]any{"path": "safe/newdir"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (ancestor in project at resolution)", err)
	}
	if want := filepath.Join(safe, "newdir"); target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}

	outside := eval(t, t.TempDir())
	if err := os.Remove(safe); err != nil {
		t.Fatalf("Remove(safe): %v", err)
	}
	if err := os.Symlink(outside, safe); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (an ancestor swap surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the authorized ancestor changed to an outside symlink")
	}
	if _, statErr := os.Stat(filepath.Join(outside, "newdir")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("mkdir followed the swapped ancestor symlink and created outside the project: %v", statErr)
	}
}

// TestMkdirTool_ParentMoveDuringCreateFailsAndLeavesNoDir pins the create-window rename variant via the
// beforeMkdirCreate seam: the held ancestor descriptor follows the directory inode, so if that directory is
// renamed out of the project after the descriptor is opened but before the fd-relative create, the create
// lands in the moved inode. Reporting that as a success at the authorized in-project path would violate the
// target binding, so the create must fail and leave no directory at the original path, the moved (outside)
// directory, or any replacement put in place.
func TestMkdirTool_ParentMoveDuringCreateFailsAndLeavesNoDir(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	args := map[string]any{"path": "safe/newdir"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (ancestor in project at resolution)", err)
	}

	origBeforeMkdirCreate := beforeMkdirCreate
	t.Cleanup(func() { beforeMkdirCreate = origBeforeMkdirCreate })
	outsideParent := eval(t, t.TempDir())
	movedSafe := filepath.Join(outsideParent, "safe-moved")
	replacement := eval(t, t.TempDir())
	beforeMkdirCreate = func() {
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
		t.Fatalf("error = %v, want nil (an ancestor move surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the authorized ancestor was moved out of the project before the create")
	}
	for _, loc := range []struct {
		what string
		dir  string
	}{
		{"original authorized path", filepath.Join(root, "safe", "newdir")},
		{"moved (outside) directory", filepath.Join(movedSafe, "newdir")},
		{"replacement directory", filepath.Join(replacement, "newdir")},
	} {
		if _, statErr := os.Stat(loc.dir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("directory unexpectedly present at the %s (%s): %v", loc.what, loc.dir, statErr)
		}
	}
}

// TestMkdirTool_NestedParentMoveDuringCreateLeavesNoResidue pins the rename-race rollback for a nested
// missing suffix (more than one segment). The single-segment rollback only removed the topmost created
// segment, which AT_REMOVEDIR cannot delete while it still holds the deeper segment — so a rename race on a
// nested target like safe/a/b left a/ and a/b/ behind in the moved directory. The whole created suffix must
// be rolled back, deepest child first, leaving no directory at the original path, the moved (outside)
// directory, or the replacement.
func TestMkdirTool_NestedParentMoveDuringCreateLeavesNoResidue(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	args := map[string]any{"path": "safe/a/b"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (ancestor in project at resolution)", err)
	}

	origBeforeMkdirCreate := beforeMkdirCreate
	t.Cleanup(func() { beforeMkdirCreate = origBeforeMkdirCreate })
	outsideParent := eval(t, t.TempDir())
	movedSafe := filepath.Join(outsideParent, "safe-moved")
	replacement := eval(t, t.TempDir())
	beforeMkdirCreate = func() {
		// Move the authorized directory outside the project (the held fd follows it there) and drop a
		// symlink to a different outside directory in its place, so the nested suffix a/b is created under
		// the moved inode and must be fully rolled back there.
		if err := os.Rename(safe, movedSafe); err != nil {
			t.Fatalf("Rename(safe): %v", err)
		}
		if err := os.Symlink(replacement, safe); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (an ancestor move surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the authorized ancestor was moved out of the project before the create")
	}
	for _, loc := range []struct {
		what string
		dir  string
	}{
		{"original authorized intermediate", filepath.Join(root, "safe", "a")},
		{"original authorized leaf", filepath.Join(root, "safe", "a", "b")},
		{"moved (outside) intermediate", filepath.Join(movedSafe, "a")},
		{"moved (outside) leaf", filepath.Join(movedSafe, "a", "b")},
		{"replacement intermediate", filepath.Join(replacement, "a")},
		{"replacement leaf", filepath.Join(replacement, "a", "b")},
	} {
		if _, statErr := os.Stat(loc.dir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("directory unexpectedly present at the %s (%s): %v", loc.what, loc.dir, statErr)
		}
	}
}

// TestMkdirTool_ParentMoveRollbackKeepsConcurrentlyCreatedDir pins that the rename-race rollback removes
// only the directories this mkdir created, never one a concurrent process slipped in. With target safe/a/b,
// the seam creates safe/a (as a racer would) before renaming safe out of the project: EnsureDirAt finds a
// already present and creates only b, so the move-detected rollback must unlink b alone and leave the
// pre-existing a in the moved location intact. The old blanket rollback derived its set from the full
// missing suffix and deleted a too, turning a mkdir failure into an unintended delete of a directory it did
// not create.
func TestMkdirTool_ParentMoveRollbackKeepsConcurrentlyCreatedDir(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	args := map[string]any{"path": "safe/a/b"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (ancestor in project at resolution)", err)
	}

	origBeforeMkdirCreate := beforeMkdirCreate
	t.Cleanup(func() { beforeMkdirCreate = origBeforeMkdirCreate })
	outsideParent := eval(t, t.TempDir())
	movedSafe := filepath.Join(outsideParent, "safe-moved")
	replacement := eval(t, t.TempDir())
	beforeMkdirCreate = func() {
		// A concurrent process creates the first missing suffix segment, then the authorized directory is
		// renamed out of the project (the held fd follows it) and a symlink to a different outside directory
		// is dropped in its place. EnsureDirAt finds safe/a already present and creates only safe/a/b, so the
		// rollback must touch b alone and leave the racer's a behind.
		if err := os.Mkdir(filepath.Join(safe, "a"), 0o755); err != nil {
			t.Fatalf("Mkdir(safe/a): %v", err)
		}
		if err := os.Rename(safe, movedSafe); err != nil {
			t.Fatalf("Rename(safe): %v", err)
		}
		if err := os.Symlink(replacement, safe); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (an ancestor move surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the authorized ancestor was moved out of the project before the create")
	}

	// The directory the concurrent process created must survive the rollback in the moved location.
	if info, statErr := os.Stat(filepath.Join(movedSafe, "a")); statErr != nil {
		t.Fatalf("pre-existing directory safe/a was removed by the rollback: %v", statErr)
	} else if !info.IsDir() {
		t.Fatalf("pre-existing safe/a is no longer a directory: %v", info.Mode())
	}

	// Only the segment this call created (b) is rolled back; it must be gone everywhere it could have landed.
	for _, loc := range []struct {
		what string
		dir  string
	}{
		{"original authorized leaf", filepath.Join(root, "safe", "a", "b")},
		{"moved (outside) leaf", filepath.Join(movedSafe, "a", "b")},
		{"replacement leaf", filepath.Join(replacement, "a", "b")},
	} {
		if _, statErr := os.Stat(loc.dir); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("created leaf unexpectedly present at the %s (%s): %v", loc.what, loc.dir, statErr)
		}
	}
}

func TestMkdirTool_CreateFailureLeavesResidue(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	dir := filepath.Join(root, "newdir")

	restore := fsutil.SetSyncDirForTest(func(*os.File) error { return errors.New("forced sync failure") })
	defer restore()

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "newdir"}, dir)
	if err != nil {
		t.Fatalf("error = %v, want nil (a create failure surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero after a forced create failure")
	}
	info, statErr := os.Stat(dir)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("just-created segment not left as residue after the failed create: info=%v err=%v", info, statErr)
	}
}

func TestMkdirTool_AuthorizedScopeReplacedWhilePendingCreatesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "sub")
	identity := mustCaptureScope(t, scope)

	replaceDirectory(t, scope)

	res, err := tool.InvokeWithAuthorizedScope(context.Background(), map[string]any{"path": "pkg/sub"}, target, scope, identity)
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
		t.Fatalf("Lstat(target) = %v, want the directory never created", serr)
	}
}

func TestMkdirTool_ScopeReplacedAfterConfirmationCreatesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "sub")
	identity := mustCaptureScope(t, scope)

	var aside string
	afterScopeConfirmedOnce(t, func() { aside = swapAuthorizedScope(t, scope) })

	res, err := tool.InvokeWithAuthorizedScope(context.Background(), map[string]any{"path": "pkg/sub"}, target, scope, identity)
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
	if _, serr := os.Lstat(filepath.Join(aside, "sub")); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Lstat(original target) = %v, want nothing created in the authorized directory either", serr)
	}
}

func TestMkdirTool_AbsentScopeIdentityCreatesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	target := filepath.Join(root, "sub")

	res, err := tool.InvokeWithAuthorizedScope(context.Background(), map[string]any{"path": "sub"}, target, root, ScopeIdentity{})
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero; an uncaptured identity must never be read as permission to skip the check")
	}
	if _, serr := os.Lstat(target); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("Lstat(target) = %v, want the directory never created", serr)
	}
}

// The comparison is against the authorized scope, never the deepest ancestor existing at invocation.
func TestMkdirTool_IntermediateDirectoryAppearingWhilePendingStillCreates(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newMkdirToolIn(t, root)
	target := filepath.Join(root, "a", "b")
	identity := mustCaptureScope(t, root)

	if err := os.Mkdir(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	res, err := tool.InvokeWithAuthorizedScope(context.Background(), map[string]any{"path": "a/b"}, target, root, identity)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result = %+v, stderr = %q, want a successful create", res, res.Stderr)
	}
	info, serr := os.Stat(target)
	if serr != nil || !info.IsDir() {
		t.Fatalf("Stat(target) = (%v, %v), want the created directory", info, serr)
	}
}
