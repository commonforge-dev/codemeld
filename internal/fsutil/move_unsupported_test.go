//go:build !linux

// Unsupported-platform test for MoveNoReplace. Platforms without an atomic no-overwrite rename
// primitive have no kernel rename to test, so instead of running the Linux behaviour expectations
// (see move_linux_test.go) this asserts the fail-closed contract: MoveNoReplace returns
// ErrNoReplaceUnsupported at RenameStep and never emulates the move (source intact, destination
// absent).
package fsutil

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestMoveNoReplace_UnsupportedPlatform exercises the real (un-seamed) default helper on a platform
// whose renameNoReplaceAtSyscall fails closed, proving MoveNoReplace surfaces ErrNoReplaceUnsupported
// in-band rather than falling back to a race-prone preflight-plus-rename.
func TestMoveNoReplace_UnsupportedPlatform(t *testing.T) {
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
