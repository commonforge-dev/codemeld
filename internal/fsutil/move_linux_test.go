//go:build linux

// Linux-only tests for MoveNoReplace that exercise the real renameat2(RENAME_NOREPLACE)
// primitive: file/directory moves, no-overwrite refusal, missing source, and the parent-identity
// guard. These rely on the kernel rename behaviour, so they are tagged off the unsupported
// platforms whose default seam fails closed with ErrNoReplaceUnsupported (see
// move_unsupported_test.go for the fail-closed contract on those platforms).
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
)

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", path, err)
	}
}

func TestMoveNoReplace_FileMove(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "dst.txt")
	const payload = "move me\n"
	seedFile(t, src, payload)

	step, cat, err := MoveNoReplace(src, dst)
	if err != nil {
		t.Fatalf("MoveNoReplace error: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want empty on success", step, cat)
	}
	if got := readBack(t, dst); string(got) != payload {
		t.Fatalf("dst contents = %q, want %q", got, payload)
	}
	if _, statErr := os.Stat(src); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("src still present after move or stat err: %v", statErr)
	}
}

func TestMoveNoReplace_DirectoryMove(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "srcdir")
	dst := filepath.Join(root, "dstdir")
	mustMkdir(t, src)
	seedFile(t, filepath.Join(src, "child.txt"), "inside")

	step, cat, err := MoveNoReplace(src, dst)
	if err != nil {
		t.Fatalf("MoveNoReplace error: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want empty on success", step, cat)
	}
	info, statErr := os.Stat(dst)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("dst is not the moved directory: info=%v err=%v", info, statErr)
	}
	if got := readBack(t, filepath.Join(dst, "child.txt")); string(got) != "inside" {
		t.Fatalf("moved child contents = %q, want %q", got, "inside")
	}
	if _, statErr := os.Stat(src); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("src dir still present after move or stat err: %v", statErr)
	}
}

// TestMoveNoReplace_RefusesExistingDestination pins the no-overwrite contract: a destination that is
// already a file, directory, or symlink is never clobbered. The call fails with err wrapping
// fs.ErrExist at RenameStep, the destination is byte/type identical, and the source survives.
func TestMoveNoReplace_RefusesExistingDestination(t *testing.T) {
	cases := []struct {
		name string
		seed func(t *testing.T, dst string)
		want func(t *testing.T, dst string)
	}{
		{
			name: "file",
			seed: func(t *testing.T, dst string) { seedFile(t, dst, "ORIGINAL DEST") },
			want: func(t *testing.T, dst string) {
				if got := readBack(t, dst); string(got) != "ORIGINAL DEST" {
					t.Fatalf("dst contents = %q, want preserved %q", got, "ORIGINAL DEST")
				}
			},
		},
		{
			name: "directory",
			seed: func(t *testing.T, dst string) { mustMkdir(t, dst) },
			want: func(t *testing.T, dst string) {
				if info, err := os.Stat(dst); err != nil || !info.IsDir() {
					t.Fatalf("dst is no longer the original directory: info=%v err=%v", info, err)
				}
			},
		},
		{
			name: "symlink",
			seed: func(t *testing.T, dst string) {
				if err := os.Symlink(filepath.Join(filepath.Dir(dst), "nowhere"), dst); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
			want: func(t *testing.T, dst string) {
				if fi, err := os.Lstat(dst); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
					t.Fatalf("dst is no longer the original symlink: mode=%v err=%v", fi.Mode(), err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "src.txt")
			dst := filepath.Join(root, "dst")
			seedFile(t, src, "SOURCE BYTES")
			tc.seed(t, dst)

			step, _, err := MoveNoReplace(src, dst)
			if err == nil {
				t.Fatal("MoveNoReplace over an existing destination succeeded, want a no-overwrite failure")
			}
			if step != RenameStep {
				t.Fatalf("step = %q, want %q", step, RenameStep)
			}
			if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("err does not wrap fs.ErrExist: %v", err)
			}
			tc.want(t, dst)
			if got := readBack(t, src); string(got) != "SOURCE BYTES" {
				t.Fatalf("src contents = %q, want it preserved on refusal %q", got, "SOURCE BYTES")
			}
		})
	}
}

func TestMoveNoReplace_SourceMissing(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "absent.txt")
	dst := filepath.Join(root, "dst.txt")

	step, cat, err := MoveNoReplace(src, dst)
	if err == nil {
		t.Fatal("MoveNoReplace of a missing source succeeded, want error")
	}
	if step != RenameStep {
		t.Fatalf("step = %q, want %q", step, RenameStep)
	}
	if cat != fserrors.NotFound {
		t.Fatalf("cat = %q, want %q", cat, fserrors.NotFound)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err does not wrap fs.ErrNotExist: %v", err)
	}
}

// TestMoveNoReplace_ParentSwapDetected pins the parent guard: when a source or destination parent is
// renamed/replaced after its descriptor is held but before the rename, the helper detects the drift
// and fails closed (ErrParentMoved at ParentSyncStep) instead of reporting a move at the wrong path.
func TestMoveNoReplace_ParentSwapDetected(t *testing.T) {
	cases := []string{"src", "dst"}
	for _, which := range cases {
		t.Run(which, func(t *testing.T) {
			root := t.TempDir()
			srcDir := filepath.Join(root, "srcdir")
			dstDir := filepath.Join(root, "dstdir")
			mustMkdir(t, srcDir)
			mustMkdir(t, dstDir)
			src := filepath.Join(srcDir, "f.txt")
			dst := filepath.Join(dstDir, "f.txt")
			seedFile(t, src, "payload")

			swapDir := srcDir
			if which == "dst" {
				swapDir = dstDir
			}
			defer SetBeforeMoveRenameForTest(func() {
				if err := os.Rename(swapDir, swapDir+"-moved"); err != nil {
					t.Fatalf("swap rename: %v", err)
				}
				mustMkdir(t, swapDir) // a fresh inode now sits at the held parent's path
			})()

			step, _, err := MoveNoReplace(src, dst)
			if err == nil {
				t.Fatal("MoveNoReplace with a swapped parent succeeded, want a parent-guard failure")
			}
			if step != ParentSyncStep {
				t.Fatalf("step = %q, want %q", step, ParentSyncStep)
			}
			if !errors.Is(err, ErrParentMoved) {
				t.Fatalf("err does not wrap ErrParentMoved: %v", err)
			}
		})
	}
}
