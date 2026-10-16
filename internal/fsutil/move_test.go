// Cross-platform tests for MoveNoReplace and the shared test helpers. The seam-driven tests here run
// on every GOOS because they install a fake renameNoReplaceAt rather than exercising the platform
// primitive. The real-kernel behaviour tests live in move_linux_test.go; the unsupported fail-closed
// contract lives in move_unsupported_test.go.
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func seedFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed %q: %v", path, err)
	}
}

// TestMoveNoReplace_UnsupportedPrimitive forces the unsupported-platform seam and asserts the helper
// fails closed in-band — and does not emulate the move with copy+unlink (source intact, dst absent).
func TestMoveNoReplace_UnsupportedPrimitive(t *testing.T) {
	defer SetRenameNoReplaceAtForTest(func(int, string, int, string) error { return ErrNoReplaceUnsupported })()

	root := t.TempDir()
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "dst.txt")
	seedFile(t, src, "SOURCE BYTES")

	step, _, err := MoveNoReplace(src, dst)
	if err == nil {
		t.Fatal("MoveNoReplace on an unsupported platform succeeded, want failure")
	}
	if step != RenameStep {
		t.Fatalf("step = %q, want %q", step, RenameStep)
	}
	if !errors.Is(err, ErrNoReplaceUnsupported) {
		t.Fatalf("err does not wrap ErrNoReplaceUnsupported: %v", err)
	}
	assertSourcePreservedDestAbsent(t, src, dst)
}

// TestMoveNoReplace_CrossDeviceNoFallback forces the seam to return EXDEV and asserts the cross-device
// error is surfaced (errors.Is reachable) with no copy+unlink fallback.
func TestMoveNoReplace_CrossDeviceNoFallback(t *testing.T) {
	defer SetRenameNoReplaceAtForTest(func(int, string, int, string) error { return syscall.EXDEV })()

	root := t.TempDir()
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "dst.txt")
	seedFile(t, src, "SOURCE BYTES")

	step, cat, err := MoveNoReplace(src, dst)
	if err == nil {
		t.Fatal("MoveNoReplace across devices succeeded, want failure")
	}
	if step != RenameStep {
		t.Fatalf("step = %q, want %q", step, RenameStep)
	}
	if cat == "" {
		t.Fatal("cat is empty on cross-device failure, want a category")
	}
	if !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("err does not wrap syscall.EXDEV: %v", err)
	}
	assertSourcePreservedDestAbsent(t, src, dst)
}

// assertSourcePreservedDestAbsent confirms a failed move left the source in place and never created
// the destination — the observable signature that no copy+unlink fallback ran.
func assertSourcePreservedDestAbsent(t *testing.T, src, dst string) {
	t.Helper()
	if got := readBack(t, src); string(got) != "SOURCE BYTES" {
		t.Fatalf("src contents = %q, want preserved %q (no fallback may consume the source)", got, "SOURCE BYTES")
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("dst exists after a failed move or stat err: %v (no fallback may create it)", statErr)
	}
}

func TestMoveNoReplace_ABeforeRenameRefusalPreventsTheRename(t *testing.T) {
	renamed := false
	defer SetRenameNoReplaceAtForTest(func(int, string, int, string) error {
		renamed = true
		return nil
	})()

	root := t.TempDir()
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "dst.txt")
	seedFile(t, src, "SOURCE BYTES")
	refusal := errors.New("journal refused")
	afterRan := false

	step, _, err := MoveNoReplace(src, dst, MoveLifecycle{
		BeforeRename: func(*os.File, *os.File) error { return refusal },
		AfterRename:  func(*os.File, *os.File) { afterRan = true },
	})

	if !errors.Is(err, refusal) || step != RenameStep {
		t.Fatalf("step, err = %q, %v; want the BeforeRename refusal at %q", step, err, RenameStep)
	}
	if renamed || afterRan {
		t.Fatalf("rename ran=%v, AfterRename ran=%v; want neither after a refused BeforeRename", renamed, afterRan)
	}
	assertSourcePreservedDestAbsent(t, src, dst)
}

func TestMoveNoReplace_BracketsAFailedRenameWithTheHeldParents(t *testing.T) {
	var order []string
	defer SetRenameNoReplaceAtForTest(func(int, string, int, string) error {
		order = append(order, "rename")
		return syscall.EXDEV
	})()

	root := t.TempDir()
	dstDir := filepath.Join(root, "dst")
	if err := os.Mkdir(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(dstDir, "dst.txt")
	seedFile(t, src, "SOURCE BYTES")
	var before, after [2]string

	_, _, err := MoveNoReplace(src, dst, MoveLifecycle{
		BeforeRename: func(srcParent, dstParent *os.File) error {
			order = append(order, "before")
			before = [2]string{srcParent.Name(), dstParent.Name()}
			return nil
		},
		AfterRename: func(srcParent, dstParent *os.File) {
			order = append(order, "after")
			after = [2]string{srcParent.Name(), dstParent.Name()}
		},
	})

	if !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("err = %v, want the rename's own failure", err)
	}
	if len(order) != 3 || order[0] != "before" || order[1] != "rename" || order[2] != "after" {
		t.Fatalf("order = %v, want before, rename, after: AfterRename must run when the rename fails", order)
	}
	if want := [2]string{root, dstDir}; before != want || after != want {
		t.Fatalf("parents before=%v after=%v, want both hooks handed the held parents %v", before, after, want)
	}
	assertSourcePreservedDestAbsent(t, src, dst)
}
