package filetools

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func declRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return root
}

func writeDecl(t *testing.T, home, launchDir, decl string) (string, error) {
	t.Helper()
	write, remove, err := ResolveDeclaredScopes(home, launchDir, []string{decl}, nil)
	if err != nil {
		return "", err
	}
	if remove != nil {
		t.Fatalf("delete set = %v, want nil for a write-only declaration", remove)
	}
	return onlyKey(t, write), nil
}

func deleteDecl(t *testing.T, home, launchDir, decl string) (string, error) {
	t.Helper()
	write, remove, err := ResolveDeclaredScopes(home, launchDir, nil, []string{decl})
	if err != nil {
		return "", err
	}
	if write != nil {
		t.Fatalf("write set = %v, want nil for a delete-only declaration", write)
	}
	return onlyKey(t, remove), nil
}

func onlyKey(t *testing.T, set map[string]bool) string {
	t.Helper()
	if len(set) != 1 {
		t.Fatalf("resolved set = %v, want exactly one entry", set)
	}
	for k := range set {
		return k
	}
	return ""
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestResolveDeclaredScopes_WriteMatchesEditTarget proves a declaration for an existing path
// resolves to exactly what the edit tool later resolves that path to, including through a final
// symlink — so the runtime membership test is a comparison of canonical paths.
func TestResolveDeclaredScopes_WriteMatchesEditTarget(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)
	real := filepath.Join(root, "real.txt")
	mustWriteFile(t, real, "body\n")
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	for _, decl := range []string{"real.txt", "link.txt"} {
		t.Run(decl, func(t *testing.T) {
			got, err := writeDecl(t, home, root, decl)
			if err != nil {
				t.Fatalf("ResolveDeclaredScopes(%q) error = %v", decl, err)
			}
			want, _, terr := NewEditTool(home, root, root).ResolveTarget(map[string]any{
				"path": decl, "old_text": "body", "new_text": "other",
			})
			if terr != nil {
				t.Fatalf("EditTool.ResolveTarget(%q) error = %v", decl, terr)
			}
			if got != want {
				t.Fatalf("write declaration %q = %q, want the edit tool's target %q", decl, got, want)
			}
		})
	}
}

// TestResolveDeclaredScopes_WriteMatchesCreateTarget proves a declaration made before its file
// exists resolves to the value the later create of that file resolves to, for a target whose
// parent exists and for one whose parents do not.
func TestResolveDeclaredScopes_WriteMatchesCreateTarget(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)

	for _, decl := range []string{"new.txt", "dir/sub/deep.txt"} {
		t.Run(decl, func(t *testing.T) {
			got, err := writeDecl(t, home, root, decl)
			if err != nil {
				t.Fatalf("ResolveDeclaredScopes(%q) error = %v", decl, err)
			}
			want, _, terr := NewCreateTool(home, root, root).ResolveTarget(map[string]any{
				"path": decl, "content": "x",
			})
			if terr != nil {
				t.Fatalf("CreateTool.ResolveTarget(%q) error = %v", decl, terr)
			}
			if got != want {
				t.Fatalf("write declaration %q = %q, want the create tool's target %q", decl, got, want)
			}
		})
	}
}

// TestResolveDeclaredScopes_DeleteKeepsTheLinkEntry proves a delete declaration resolves its
// parent but never the final component, so declaring a symlink authorizes removing the link and
// never the file it points at.
func TestResolveDeclaredScopes_DeleteKeepsTheLinkEntry(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)
	real := filepath.Join(root, "real.txt")
	mustWriteFile(t, real, "body\n")
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got, err := deleteDecl(t, home, root, "link.txt")
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}
	want, _, terr := NewDeleteTool(home, root, root).ResolveTarget(map[string]any{"path": "link.txt"})
	if terr != nil {
		t.Fatalf("DeleteTool.ResolveTarget error = %v", terr)
	}
	if got != want {
		t.Fatalf("delete declaration = %q, want the delete tool's target %q", got, want)
	}
	if got != link {
		t.Fatalf("delete declaration = %q, want the link entry %q", got, link)
	}
	if got == real {
		t.Fatalf("delete declaration followed the final symlink to %q", real)
	}
}

// TestResolveDeclaredScopes_DeleteMissingParentAnchorsOnDeepestAncestor proves the
// create-then-delete case: a delete declaration is valid before its parent directory exists, and
// resolves to what the delete tool resolves once the file is created.
func TestResolveDeclaredScopes_DeleteMissingParentAnchorsOnDeepestAncestor(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)

	got, err := deleteDecl(t, home, root, "dir/sub/doomed.txt")
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}
	if want := filepath.Join(root, "dir", "sub", "doomed.txt"); got != want {
		t.Fatalf("delete declaration = %q, want %q", got, want)
	}

	if err := os.MkdirAll(filepath.Join(root, "dir", "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mustWriteFile(t, filepath.Join(root, "dir", "sub", "doomed.txt"), "x\n")
	want, _, terr := NewDeleteTool(home, root, root).ResolveTarget(map[string]any{"path": "dir/sub/doomed.txt"})
	if terr != nil {
		t.Fatalf("DeleteTool.ResolveTarget error = %v", terr)
	}
	if got != want {
		t.Fatalf("delete declaration = %q, want the delete tool's later target %q", got, want)
	}
}

// TestResolveDeclaredScopes_IntermediateSymlinkResolvesElsewhere proves the fail-closed guarantee
// for a segment created as a symlink after the declaration resolved: the tool's runtime target no
// longer equals the stored declaration, so membership fails.
func TestResolveDeclaredScopes_IntermediateSymlinkResolvesElsewhere(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)
	elsewhere := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	declared, err := deleteDecl(t, home, root, "dir/doomed.txt")
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}

	if err := os.Symlink(elsewhere, filepath.Join(root, "dir")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	mustWriteFile(t, filepath.Join(elsewhere, "doomed.txt"), "x\n")

	runtime, _, terr := NewDeleteTool(home, root, root).ResolveTarget(map[string]any{"path": "dir/doomed.txt"})
	if terr != nil {
		t.Fatalf("DeleteTool.ResolveTarget error = %v", terr)
	}
	if runtime == declared {
		t.Fatalf("runtime target %q still equals the declaration; the swap must resolve elsewhere", runtime)
	}
}

// TestResolveDeclaredScopes_WriteSwapToSymlinkResolvesElsewhere proves the same guarantee for the
// write list: a declared path replaced by a symlink resolves to the link's target, which is not
// the stored declaration.
func TestResolveDeclaredScopes_WriteSwapToSymlinkResolvesElsewhere(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)
	outside := declRoot(t)
	target := filepath.Join(outside, "outside.txt")
	mustWriteFile(t, target, "outside\n")

	declared, err := writeDecl(t, home, root, "swapped.txt")
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "swapped.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	runtime, _, terr := NewEditTool(home, root, root).ResolveTarget(map[string]any{
		"path": "swapped.txt", "old_text": "outside", "new_text": "changed",
	})
	if terr != nil {
		t.Fatalf("EditTool.ResolveTarget error = %v", terr)
	}
	if runtime == declared {
		t.Fatalf("runtime target %q still equals the declaration; the swap must resolve to %q", runtime, target)
	}
}

// TestResolveDeclaredScopes_RejectsUnresolvableDeclarations proves each structurally invalid
// declaration is rejected — before any expansion or anchoring for the empty forms, so none can
// canonicalize to the launch directory — and that the error names the offending path.
func TestResolveDeclaredScopes_RejectsUnresolvableDeclarations(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)
	mustWriteFile(t, filepath.Join(root, "file.txt"), "x\n")
	if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "dangling")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cases := []struct {
		name string
		decl string
	}{
		{"empty", ""},
		{"whitespace only", "   \t "},
		{"unsupported ~user form", "~someone/notes.txt"},
		{"existing non-directory mid component", "file.txt/child.txt"},
		{"dangling symlink component", "dangling/child.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := writeDecl(t, home, root, tc.decl); err == nil {
				t.Fatalf("write declaration %q was accepted, want a rejection", tc.decl)
			} else if !strings.Contains(err.Error(), strconv.Quote(tc.decl)) {
				t.Fatalf("write rejection %q does not name the declared path %q", err, tc.decl)
			}
			if _, err := deleteDecl(t, home, root, tc.decl); err == nil {
				t.Fatalf("delete declaration %q was accepted, want a rejection", tc.decl)
			} else if !strings.Contains(err.Error(), strconv.Quote(tc.decl)) {
				t.Fatalf("delete rejection %q does not name the declared path %q", err, tc.decl)
			}
		})
	}
}

// TestResolveDeclaredScopes_OneBadEntryLeavesBothListsUnresolved proves resolution is atomic: a
// rejection anywhere in either list returns no partially-resolved set.
func TestResolveDeclaredScopes_OneBadEntryLeavesBothListsUnresolved(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)
	mustWriteFile(t, filepath.Join(root, "ok.txt"), "x\n")

	cases := []struct {
		name           string
		write, deletes []string
	}{
		{"bad write entry", []string{"ok.txt", "~someone/bad.txt"}, []string{"ok.txt"}},
		{"bad delete entry", []string{"ok.txt"}, []string{"ok.txt", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			write, remove, err := ResolveDeclaredScopes(home, root, tc.write, tc.deletes)
			if err == nil {
				t.Fatal("ResolveDeclaredScopes accepted a list containing an invalid declaration")
			}
			if write != nil || remove != nil {
				t.Fatalf("write = %v, delete = %v, want both unresolved", write, remove)
			}
		})
	}
}

// TestResolveDeclaredScopes_AnchorsRelativeAndHomePaths proves a relative declaration anchors to
// the launch directory and a leading ~ expands against the run's resolved home.
func TestResolveDeclaredScopes_AnchorsRelativeAndHomePaths(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)
	mustWriteFile(t, filepath.Join(home, "in-home.txt"), "x\n")

	got, err := writeDecl(t, home, root, "relative.txt")
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}
	if want := filepath.Join(root, "relative.txt"); got != want {
		t.Fatalf("relative declaration = %q, want %q", got, want)
	}

	got, err = writeDecl(t, home, root, "~/in-home.txt")
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}
	if want := filepath.Join(home, "in-home.txt"); got != want {
		t.Fatalf("~ declaration = %q, want %q", got, want)
	}
}

// TestResolveDeclaredScopes_KeepsACommaInsideAFilename proves a declared value is one path even
// when it contains a comma, so the resolver never splits what the flag did not split.
func TestResolveDeclaredScopes_KeepsACommaInsideAFilename(t *testing.T) {
	root := declRoot(t)
	home := declRoot(t)

	got, err := writeDecl(t, home, root, "a,b.txt")
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}
	if want := filepath.Join(root, "a,b.txt"); got != want {
		t.Fatalf("comma declaration = %q, want the single file %q", got, want)
	}
}

// TestResolveDeclaredScopes_EmptyListsProduceNoCeiling proves the absence of both flags resolves
// to two empty sets, which is what leaves ordinary authorization untouched.
func TestResolveDeclaredScopes_EmptyListsProduceNoCeiling(t *testing.T) {
	write, remove, err := ResolveDeclaredScopes(declRoot(t), declRoot(t), nil, nil)
	if err != nil {
		t.Fatalf("ResolveDeclaredScopes error = %v", err)
	}
	if len(write) != 0 || len(remove) != 0 {
		t.Fatalf("write = %v, delete = %v, want both empty", write, remove)
	}
}
