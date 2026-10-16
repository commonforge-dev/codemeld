// Unit tests for the built-in delete tool: metadata/classification, pre-authorization must-exist target
// resolution (in-scope file/symlink/empty-dir, missing target, traversal, out-of-root, bad args),
// fd-relative removal of a regular file / final symlink (link, not target) / empty directory, in-band
// refusal of a non-empty directory (never a recursive wipe), the standalone out-of-root guard, and the
// post-authorization parent symlink-swap / move (TOCTOU) guards.
package filetools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/tools"
)

// newDeleteToolIn builds a delete tool whose project root and relative-path base are root, with a
// separate home anchor, so a relative target lands inside the project and ~ expansion is exercised
// independently — mirroring newCreateToolIn for the create tool.
func newDeleteToolIn(t *testing.T, root string) *DeleteTool {
	t.Helper()
	return NewDeleteTool(t.TempDir(), root, root)
}

func TestDeleteTool_AdvertiseMetadata(t *testing.T) {
	tool := newDeleteToolIn(t, t.TempDir())

	if tool.Name() != "delete" {
		t.Fatalf("Name() = %q, want delete", tool.Name())
	}
	if tool.SubjectKind() != "tool" {
		t.Fatalf("SubjectKind() = %q, want tool", tool.SubjectKind())
	}

	md := tool.Advertise()
	if md.ReadOnly {
		t.Fatal("Advertise().ReadOnly = true, want false (the delete tool is mutating)")
	}
	if strings.TrimSpace(md.Description) == "" {
		t.Fatal("Advertise().Description is empty, want a one-line description")
	}
	if md.Parameters["type"] != "object" {
		t.Fatalf("Parameters.type = %v, want object", md.Parameters["type"])
	}
	if md.Parameters["additionalProperties"] != false {
		t.Fatalf("Parameters.additionalProperties = %v, want false (closed schema)", md.Parameters["additionalProperties"])
	}
	required, ok := md.Parameters["required"].([]string)
	if !ok || !reflect.DeepEqual(required, []string{"path"}) {
		t.Fatalf("Parameters.required = %v, want [path] (path is the only argument)", md.Parameters["required"])
	}
	props, ok := md.Parameters["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Parameters.properties type = %T, want map[string]any", md.Parameters["properties"])
	}
	if _, ok := props["path"]; !ok {
		t.Fatal("Parameters.properties missing \"path\"")
	}
	// delete carries no content/old_text/new_text — only path.
	for _, forbidden := range []string{"content", "old_text", "new_text"} {
		if _, ok := props[forbidden]; ok {
			t.Fatalf("Parameters.properties unexpectedly carries %q; delete takes only path", forbidden)
		}
	}
}

func TestDeleteTool_ResolveTargetInScope(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)

	file := filepath.Join(root, "doomed.txt")
	writeFile(t, file, "X")
	emptyDir := filepath.Join(root, "emptydir")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	linkTarget := filepath.Join(root, "real.txt")
	writeFile(t, linkTarget, "REAL")
	link := filepath.Join(root, "link")
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	cases := []struct {
		name string
		path string
		want string
	}{
		{"regular file", "doomed.txt", file},
		{"empty directory", "emptydir", emptyDir},
		{"final symlink", "link", link}, // the link entry, not its real target
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, scope, err := tool.ResolveTarget(map[string]any{"path": tc.path})
			if err != nil {
				t.Fatalf("ResolveTarget(%q) error = %v, want nil", tc.path, err)
			}
			if target != tc.want {
				t.Fatalf("ResolveTarget(%q) target = %q, want %q", tc.path, target, tc.want)
			}
			if scope != root {
				t.Fatalf("ResolveTarget(%q) scope = %q, want the parent directory %q", tc.path, scope, root)
			}
			if tool.OutOfRootScope(scope) {
				t.Fatalf("OutOfRootScope(%q) = true for an in-root target, want false", scope)
			}
		})
	}
}

func TestDeleteTool_DeletesRegularFile(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	file := filepath.Join(root, "gone.txt")
	writeFile(t, file, "bye\n")

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "gone.txt"}, file)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if _, statErr := os.Lstat(file); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("file still present after delete: %v", statErr)
	}
}

// TestDeleteTool_DeletesSymlinkNotTarget pins the final-symlink contract: deleting a symlink removes the
// link entry and never follows it to delete the file it points at.
func TestDeleteTool_DeletesSymlinkNotTarget(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)

	realTarget := filepath.Join(root, "keep.txt")
	writeFile(t, realTarget, "KEEP\n")
	link := filepath.Join(root, "link")
	if err := os.Symlink(realTarget, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	target, _, err := tool.ResolveTarget(map[string]any{"path": "link"})
	if err != nil {
		t.Fatalf("ResolveTarget(link) error = %v, want nil", err)
	}
	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "link"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if _, statErr := os.Lstat(link); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("symlink entry still present after delete: %v", statErr)
	}
	if got := readFile(t, realTarget); got != "KEEP\n" {
		t.Fatalf("symlink delete followed the link and removed/altered the target: file = %q, want %q", got, "KEEP\n")
	}
}

func TestDeleteTool_DeletesEmptyDirectory(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	dir := filepath.Join(root, "emptydir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "emptydir"}, dir)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if _, statErr := os.Lstat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("empty directory still present after delete: %v", statErr)
	}
}

func TestDeleteTool_JournalsExpectedAbsenceBeforeTheUnlink(t *testing.T) {
	for _, entry := range []string{"resolved target", "authorized scope"} {
		t.Run(entry, func(t *testing.T) {
			root := eval(t, t.TempDir())
			tool := newDeleteToolIn(t, root)
			target := filepath.Join(root, "doomed.txt")
			writeFile(t, target, "bye\n")
			journal := newFakeJournal(target)

			var presentAtBegin, goneAtResolve bool
			journal.onBeginDelete = func() {
				_, err := os.Lstat(target)
				presentAtBegin = err == nil
			}
			journal.onResolve = func() {
				_, err := os.Lstat(target)
				goneAtResolve = errors.Is(err, os.ErrNotExist)
			}

			ctx := WithWriteJournal(context.Background(), journal)
			args := map[string]any{"path": "doomed.txt"}
			var res tools.Result
			var err error
			if entry == "resolved target" {
				res, err = tool.InvokeWithResolvedTarget(ctx, args, target)
			} else {
				identity, cerr := CaptureScopeIdentity(root)
				if cerr != nil {
					t.Fatalf("CaptureScopeIdentity: %v", cerr)
				}
				res, err = tool.InvokeWithAuthorizedScope(ctx, args, target, root, identity)
			}
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("delete = %+v, %v; want success", res, err)
			}
			if !presentAtBegin {
				t.Fatal("the journal was told of the delete after the entry was already gone")
			}
			if !goneAtResolve {
				t.Fatal("the journal resolved the delete before the unlink happened")
			}
			if want := []string{"begin_delete:" + target, "resolve:" + target}; !reflect.DeepEqual(journal.events, want) {
				t.Fatalf("journal events = %v, want %v", journal.events, want)
			}
			if !reflect.DeepEqual(journal.resolvedWith, []JournalState{{}}) {
				t.Fatalf("resolved with %+v, want the absent state", journal.resolvedWith)
			}
		})
	}
}

func TestDeleteTool_ARefusedJournalIntentDeletesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	target := filepath.Join(root, "kept.txt")
	writeFile(t, target, "KEEP\n")
	journal := newFakeJournal(target)
	journal.beginDeleteErr = errors.New("kept.txt changed outside the child agent")

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal), map[string]any{"path": "kept.txt"}, target)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "changed outside the child agent") {
		t.Fatalf("result = %+v, want the journal's refusal in band", res)
	}
	if got := readFile(t, target); got != "KEEP\n" {
		t.Fatalf("%s = %q, want it untouched after a refused intent", target, got)
	}
	if want := []string{"begin_delete:" + target}; !reflect.DeepEqual(journal.events, want) {
		t.Fatalf("journal events = %v, want only the refused intent %v", journal.events, want)
	}
}

func TestDeleteTool_AFailedUnlinkAbandonsTheJournalledIntent(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	dir := filepath.Join(root, "full")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	inside := filepath.Join(dir, "inside.txt")
	writeFile(t, inside, "STILL HERE\n")
	journal := newFakeJournal(dir)

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal), map[string]any{"path": "full"}, dir)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil", err)
	}
	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "non-empty directory") {
		t.Fatalf("result = %+v, want the kernel's non-empty refusal in band", res)
	}
	if want := []string{"begin_delete:" + dir, "abandon:" + dir}; !reflect.DeepEqual(journal.events, want) {
		t.Fatalf("journal events = %v, want %v", journal.events, want)
	}
	if got := readFile(t, inside); got != "STILL HERE\n" {
		t.Fatalf("%s = %q, want the directory's contents intact", inside, got)
	}
}

func TestDeleteTool_AnUncoveredTargetTakesTheUnjournalledRoute(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	target := filepath.Join(root, "plain.txt")
	writeFile(t, target, "x")
	journal := newFakeJournal(filepath.Join(root, "other.txt"))

	res, err := tool.InvokeWithResolvedTarget(WithWriteJournal(context.Background(), journal), map[string]any{"path": "plain.txt"}, target)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("delete = %+v, %v; want success", res, err)
	}
	if len(journal.events) != 0 {
		t.Fatalf("journal events = %v, want none for a path the journal does not cover", journal.events)
	}
	if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("file still present after delete: %v", statErr)
	}
}

// TestDeleteTool_RefusesNonEmptyDirectory pins the load-bearing v1 guardrail: a non-empty directory is
// refused in-band and never recursively wiped — the AT_REMOVEDIR unlink the kernel guarantees is
// non-recursive, so the directory and its contents are left intact.
func TestDeleteTool_RefusesNonEmptyDirectory(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	dir := filepath.Join(root, "full")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	inside := filepath.Join(dir, "inside.txt")
	writeFile(t, inside, "STILL HERE\n")

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": "full"}, dir)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget error = %v, want nil (a refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a non-empty directory")
	}
	if !strings.Contains(string(res.Stderr), "non-empty directory") {
		t.Fatalf("stderr = %q, want it to name the non-empty-directory refusal", res.Stderr)
	}
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		t.Fatalf("directory removed despite being non-empty: info=%v err=%v", info, statErr)
	}
	if got := readFile(t, inside); got != "STILL HERE\n" {
		t.Fatalf("directory contents changed: %q, want them preserved", got)
	}
}

// TestDeleteTool_NegativeResolutionTable is the adversarial negative table: every malformed or absent
// delete target is rejected with a *TargetError before authorization (out-of-root is excluded — it is
// promptable, see TestDeleteTool_ResolveTargetOutOfRoot).
func TestDeleteTool_NegativeResolutionTable(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)

	cases := []struct {
		name string
		path any
	}{
		{"missing target", "ghost.txt"},
		{"missing parent directory", "no/such/parent/file.txt"},
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

// TestDeleteTool_ResolveTargetOutOfRoot pins that an out-of-root delete target is not a hard
// *TargetError; it resolves (promptable) to its real out-of-root parent folder as the path scope —
// including a parent reached through an in-project symlink to an out-of-root directory — and the delete
// then removes the entry there through InvokeWithResolvedTarget, proving the invoke-time guards bound the
// removal to the *authorized* parent rather than the project root.
func TestDeleteTool_ResolveTargetOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)

	outsideDir := eval(t, t.TempDir())
	victim := filepath.Join(outsideDir, "victim.txt")
	writeFile(t, victim, "V")

	got, scope, err := tool.ResolveTarget(map[string]any{"path": victim})
	if err != nil {
		t.Fatalf("ResolveTarget(out-of-root absolute) error = %v, want nil (promptable)", err)
	}
	if got != victim {
		t.Fatalf("target = %q, want %q", got, victim)
	}
	if scope != outsideDir {
		t.Fatalf("scope = %q, want the real out-of-root folder %q", scope, outsideDir)
	}
	if !tool.OutOfRootScope(scope) {
		t.Fatalf("OutOfRootScope(%q) = false, want true", scope)
	}

	// The delete removes the entry from the authorized out-of-root parent (the post-auth guards bound the
	// removal to that parent, not the project root).
	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{"path": victim}, got)
	if err != nil {
		t.Fatalf("InvokeWithResolvedTarget(out-of-root) error = %v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if _, statErr := os.Lstat(victim); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("out-of-root target still present after an approved delete: %v", statErr)
	}

	// A parent reached through an in-project symlink to an out-of-root directory resolves to the real
	// out-of-root folder, never the in-root lexical parent.
	escapeLink := filepath.Join(root, "escape")
	if err := os.Symlink(outsideDir, escapeLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	child := filepath.Join(outsideDir, "child.txt")
	writeFile(t, child, "C")
	gotChild, scope2, err := tool.ResolveTarget(map[string]any{"path": "escape/child.txt"})
	if err != nil {
		t.Fatalf("ResolveTarget(escape/child.txt) error = %v, want nil (promptable)", err)
	}
	if gotChild != child {
		t.Fatalf("symlink-parent target = %q, want the real path %q", gotChild, child)
	}
	if scope2 != outsideDir {
		t.Fatalf("symlink-parent scope = %q, want the real out-of-root folder %q", scope2, outsideDir)
	}
	if !tool.OutOfRootScope(scope2) {
		t.Fatalf("OutOfRootScope on symlink parent = false, want true")
	}
}

// TestDeleteTool_InvokeStandaloneRejectsOutOfRoot pins the out-of-root boundary on the standalone Invoke
// path: it has no authorizer, so an out-of-root resolved target — whether a direct absolute path or an
// in-root lexical path whose parent symlink-resolves outside the root — must fail in-band and remove
// nothing outside the project. Only dispatch can authorize an out-of-root delete through the approval
// prompt; if this guard were removed the asserts below would fail (the outside file would be deleted).
func TestDeleteTool_InvokeStandaloneRejectsOutOfRoot(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)

	outsideDir := eval(t, t.TempDir())

	t.Run("direct out-of-root absolute path", func(t *testing.T) {
		victim := filepath.Join(outsideDir, "victim.txt")
		writeFile(t, victim, "V")
		res, err := tool.Invoke(context.Background(), map[string]any{"path": victim})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an out-of-root delete")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if _, statErr := os.Lstat(victim); statErr != nil {
			t.Fatalf("out-of-root file removed by standalone Invoke: %v", statErr)
		}
	})

	t.Run("in-root lexical path whose parent symlink-escapes the root", func(t *testing.T) {
		escapeLink := filepath.Join(root, "escape")
		if err := os.Symlink(outsideDir, escapeLink); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		victim := filepath.Join(outsideDir, "sneaky.txt")
		writeFile(t, victim, "V")
		res, err := tool.Invoke(context.Background(), map[string]any{"path": "escape/sneaky.txt"})
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (the refusal is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for a symlink-escaped delete")
		}
		if !strings.Contains(string(res.Stderr), "outside the project root") {
			t.Fatalf("stderr = %q, want it to name the out-of-root refusal", res.Stderr)
		}
		if _, statErr := os.Lstat(victim); statErr != nil {
			t.Fatalf("out-of-root file removed via symlink escape: %v", statErr)
		}
	})
}

// TestDeleteTool_RejectsUnknownArgs pins the closed advertised schema (additionalProperties:false): a
// call carrying an extra key is rejected before authorization or removal on every entry — ResolveTarget,
// remove via InvokeWithResolvedTarget, and the standalone Invoke — and removes nothing.
func TestDeleteTool_RejectsUnknownArgs(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	extraArgs := map[string]any{"path": "doc.txt", "unexpected": true}

	t.Run("ResolveTarget rejects before authorization", func(t *testing.T) {
		_, _, err := tool.ResolveTarget(extraArgs)
		var te *TargetError
		if !errors.As(err, &te) {
			t.Fatalf("ResolveTarget error = %v, want *TargetError for an extra property", err)
		}
	})

	t.Run("InvokeWithResolvedTarget rejects at remove", func(t *testing.T) {
		writeFile(t, file, "KEEP")
		res, err := tool.InvokeWithResolvedTarget(context.Background(), extraArgs, file)
		if err != nil {
			t.Fatalf("error = %v, want nil (an extra property surfaces in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an extra property")
		}
		if _, statErr := os.Lstat(file); statErr != nil {
			t.Fatalf("file removed despite a rejected extra property: %v", statErr)
		}
	})

	t.Run("Invoke rejects and removes nothing", func(t *testing.T) {
		res, err := tool.Invoke(context.Background(), extraArgs)
		if err != nil {
			t.Fatalf("Invoke error = %v, want nil (an extra property is in-band)", err)
		}
		if res.ExitCode == 0 {
			t.Fatal("ExitCode = 0, want non-zero for an extra property")
		}
		if _, statErr := os.Lstat(file); statErr != nil {
			t.Fatalf("file removed despite a rejected extra property: %v", statErr)
		}
	})
}

// TestDeleteTool_ResolvedTargetRequiresPath pins the advertised required arg on the resolved-target
// invocation seam: InvokeWithResolvedTarget reaches remove with the target already resolved, so a call
// omitting `path` must still fail non-zero and remove no file — the runtime contract stays no broader
// than the advertised schema on the production invocation path.
func TestDeleteTool_ResolvedTargetRequiresPath(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	file := filepath.Join(root, "doc.txt")
	writeFile(t, file, "KEEP")

	res, err := tool.InvokeWithResolvedTarget(context.Background(), map[string]any{}, file)
	if err != nil {
		t.Fatalf("error = %v, want nil (a missing required argument surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a missing path argument")
	}
	if _, statErr := os.Lstat(file); statErr != nil {
		t.Fatalf("file removed despite a missing path argument: %v", statErr)
	}
}

// TestDeleteTool_ParentSymlinkSwapAfterAuthorizationDoesNotEscape pins the authorization/invocation
// target binding under a post-authorization parent symlink swap. ResolveTarget binds an in-project parent
// (<root>/safe); that parent is then moved aside and replaced with a symlink to a different outside
// directory before invocation. openAuthorizedParent re-resolves the parent and finds it no longer the
// authorized directory, so the delete fails in-band, the moved-aside victim survives, and the decoy in
// the swapped-in directory is never touched (the delete is not redirected).
func TestDeleteTool_ParentSymlinkSwapAfterAuthorizationDoesNotEscape(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	victim := filepath.Join(safe, "victim.txt")
	writeFile(t, victim, "VICTIM\n")

	args := map[string]any{"path": "safe/victim.txt"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (parent in project at resolution)", err)
	}

	// After authorization, move the authorized parent aside and replace it with a symlink to a different
	// outside directory holding a decoy of the same basename.
	outsideParent := eval(t, t.TempDir())
	movedSafe := filepath.Join(outsideParent, "safe-moved")
	if err := os.Rename(safe, movedSafe); err != nil {
		t.Fatalf("Rename(safe): %v", err)
	}
	otherOutside := eval(t, t.TempDir())
	decoy := filepath.Join(otherOutside, "victim.txt")
	writeFile(t, decoy, "DECOY\n")
	if err := os.Symlink(otherOutside, safe); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	res, err := tool.InvokeWithResolvedTarget(context.Background(), args, target)
	if err != nil {
		t.Fatalf("error = %v, want nil (a parent swap surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero when the authorized parent changed to an outside symlink")
	}
	if got := readFile(t, filepath.Join(movedSafe, "victim.txt")); got != "VICTIM\n" {
		t.Fatalf("moved-aside victim = %q, want it untouched", got)
	}
	if got := readFile(t, decoy); got != "DECOY\n" {
		t.Fatalf("delete followed the swapped parent symlink and removed the decoy: %q", got)
	}
}

// TestDeleteTool_ParentMoveBeforeUnlinkRefuses pins the publish-window rename variant (TOCTOU): the held
// parent descriptor follows the directory inode, so if that directory is renamed out of the project after
// the handle is opened but before the unlink, the held handle still names the original inode. The
// destructive verify-then-act guard (confirmParentStillAuthorized, run via the beforeDeleteUnlink seam)
// detects the held inode is no longer at the authorized path and refuses, so the delete neither proceeds
// against the moved inode nor is redirected to whatever now sits at the authorized path.
func TestDeleteTool_ParentMoveBeforeUnlinkRefuses(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)

	safe := filepath.Join(root, "safe")
	if err := os.Mkdir(safe, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	victim := filepath.Join(safe, "victim.txt")
	writeFile(t, victim, "VICTIM\n")

	args := map[string]any{"path": "safe/victim.txt"}
	target, _, err := tool.ResolveTarget(args)
	if err != nil {
		t.Fatalf("ResolveTarget error = %v, want nil (parent in project at resolution)", err)
	}

	origBeforeDeleteUnlink := beforeDeleteUnlink
	t.Cleanup(func() { beforeDeleteUnlink = origBeforeDeleteUnlink })
	outsideParent := eval(t, t.TempDir())
	movedSafe := filepath.Join(outsideParent, "safe-moved")
	replacement := eval(t, t.TempDir())
	decoy := filepath.Join(replacement, "victim.txt")
	writeFile(t, decoy, "DECOY\n")
	beforeDeleteUnlink = func() {
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
		t.Fatal("ExitCode = 0, want non-zero when the authorized parent was moved before the unlink")
	}
	if got := readFile(t, filepath.Join(movedSafe, "victim.txt")); got != "VICTIM\n" {
		t.Fatalf("victim in the moved directory = %q, want it untouched (the move was refused, not followed)", got)
	}
	if got := readFile(t, decoy); got != "DECOY\n" {
		t.Fatalf("delete was redirected into the swapped-in directory: decoy = %q", got)
	}
}

func TestDeleteTool_AuthorizedScopeReplacedWhilePendingDeletesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "gone.txt")
	writeFile(t, target, "bye\n")
	identity := mustCaptureScope(t, scope)

	replaceDirectory(t, scope)
	writeFile(t, target, "bye\n")

	res, err := tool.InvokeWithAuthorizedScope(context.Background(), map[string]any{"path": "pkg/gone.txt"}, target, scope, identity)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a scope replaced while the request was pending")
	}
	if got := string(res.Stderr); !strings.Contains(got, authorizedScopeReplaced) {
		t.Fatalf("stderr = %q, want the pending-replacement refusal", got)
	}
	if got := readFile(t, target); got != "bye\n" {
		t.Fatalf("file = %q, want the entry left in place", got)
	}
}

func TestDeleteTool_ScopeReplacedAfterConfirmationDeletesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	scope := filepath.Join(root, "pkg")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	target := filepath.Join(scope, "gone.txt")
	writeFile(t, target, "bye\n")
	identity := mustCaptureScope(t, scope)

	var aside string
	afterScopeConfirmedOnce(t, func() {
		aside = swapAuthorizedScope(t, scope)
		// Same name in the replacement, so a missing entry cannot be what refuses.
		writeFile(t, target, "bye\n")
	})

	res, err := tool.InvokeWithAuthorizedScope(context.Background(), map[string]any{"path": "pkg/gone.txt"}, target, scope, identity)
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero for a scope replaced after the confirmation")
	}
	if got := string(res.Stderr); !strings.Contains(got, authorizedScopeReplaced) {
		t.Fatalf("stderr = %q, want the pending-replacement refusal", got)
	}
	if got := readFile(t, target); got != "bye\n" {
		t.Fatalf("replacement file = %q, want the entry left in place", got)
	}
	if got := readFile(t, filepath.Join(aside, "gone.txt")); got != "bye\n" {
		t.Fatalf("authorized file = %q, want the entry left in place", got)
	}
}

func TestDeleteTool_AbsentScopeIdentityDeletesNothing(t *testing.T) {
	root := eval(t, t.TempDir())
	tool := newDeleteToolIn(t, root)
	target := filepath.Join(root, "gone.txt")
	writeFile(t, target, "bye\n")

	res, err := tool.InvokeWithAuthorizedScope(context.Background(), map[string]any{"path": "gone.txt"}, target, root, ScopeIdentity{})
	if err != nil {
		t.Fatalf("error = %v, want nil (the refusal surfaces in-band)", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("ExitCode = 0, want non-zero; an uncaptured identity must never be read as permission to skip the check")
	}
	if got := readFile(t, target); got != "bye\n" {
		t.Fatalf("file = %q, want the entry left in place", got)
	}
}
