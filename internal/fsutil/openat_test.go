// Unit tests for SnapshotFileAt: absence, regular-file state and identity, non-regular refusals, and
// the byte cap on both the pre-read size and the bytes actually read.
package fsutil

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func snapshotDir(t *testing.T, path string) *os.File {
	t.Helper()
	d, err := os.Open(path)
	if err != nil {
		t.Fatalf("open dir %q: %v", path, err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestSnapshotFileAt_Absent(t *testing.T) {
	root := t.TempDir()
	parent := snapshotDir(t, root)

	snap, err := SnapshotFileAt(parent, "missing.txt", 1<<20)
	if err != nil {
		t.Fatalf("SnapshotFileAt on an absent entry: %v", err)
	}
	if snap.Exists {
		t.Fatalf("Exists = true for an absent entry")
	}
	if snap.Data != nil || snap.Mode != 0 || snap.Dev != 0 || snap.Ino != 0 {
		t.Fatalf("absent snapshot carries state: %+v", snap)
	}
}

func TestSnapshotFileAt_RegularFileStateAndIdentity(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "doc.txt")
	const payload = "snapshot me\n"
	if err := os.WriteFile(target, []byte(payload), 0o640); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatalf("chmod target: %v", err)
	}
	parent := snapshotDir(t, root)

	snap, err := SnapshotFileAt(parent, "doc.txt", 1<<20)
	if err != nil {
		t.Fatalf("SnapshotFileAt: %v", err)
	}
	if !snap.Exists {
		t.Fatal("Exists = false for a present regular file")
	}
	if string(snap.Data) != payload {
		t.Fatalf("Data = %q, want %q", snap.Data, payload)
	}
	if snap.Mode != 0o640 {
		t.Fatalf("Mode = %v, want 0640", snap.Mode)
	}

	var st syscall.Stat_t
	if err := syscall.Stat(target, &st); err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if snap.Dev != uint64(st.Dev) || snap.Ino != uint64(st.Ino) {
		t.Fatalf("identity = (%d,%d), want (%d,%d)", snap.Dev, snap.Ino, uint64(st.Dev), uint64(st.Ino))
	}
}

func TestSnapshotFileAt_EmptyFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "empty"), nil, 0o600); err != nil {
		t.Fatalf("seed empty target: %v", err)
	}
	parent := snapshotDir(t, root)

	snap, err := SnapshotFileAt(parent, "empty", 0)
	if err != nil {
		t.Fatalf("SnapshotFileAt on an empty file with a zero cap: %v", err)
	}
	if !snap.Exists || len(snap.Data) != 0 {
		t.Fatalf("snapshot = %+v, want an existing empty file", snap)
	}
}

// TestSnapshotFileAt_RefusesNonRegular pins that every non-regular kind is refused rather than read: a
// directory and a symlink are refused by kind, and a FIFO is refused instead of blocking the open — the
// case that would otherwise hang a caller indefinitely.
func TestSnapshotFileAt_RefusesNonRegular(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "adir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "real.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed link destination: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o644); err != nil {
		t.Skipf("Mkfifo unsupported on this platform: %v", err)
	}
	parent := snapshotDir(t, root)

	for _, name := range []string{"adir", "link", "pipe"} {
		t.Run(name, func(t *testing.T) {
			snap, err := SnapshotFileAt(parent, name, 1<<20)
			if err == nil {
				t.Fatalf("SnapshotFileAt(%q) succeeded, want a refusal", name)
			}
			if !errors.Is(err, ErrSnapshotNotRegular) {
				t.Fatalf("err = %v, want ErrSnapshotNotRegular", err)
			}
			if snap.Exists {
				t.Fatalf("snapshot reports Exists on a refusal: %+v", snap)
			}
		})
	}
}

// TestSnapshotFileAt_ByteCapBoundary pins the cap as inclusive: exactly cap bytes is accepted and one
// byte more is refused before the read.
func TestSnapshotFileAt_ByteCapBoundary(t *testing.T) {
	root := t.TempDir()
	parent := snapshotDir(t, root)
	const cap64 = 8

	if err := os.WriteFile(filepath.Join(root, "atcap"), make([]byte, cap64), 0o644); err != nil {
		t.Fatalf("seed at-cap file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "overcap"), make([]byte, cap64+1), 0o644); err != nil {
		t.Fatalf("seed over-cap file: %v", err)
	}

	snap, err := SnapshotFileAt(parent, "atcap", cap64)
	if err != nil {
		t.Fatalf("SnapshotFileAt at exactly the cap: %v", err)
	}
	if len(snap.Data) != cap64 {
		t.Fatalf("Data length = %d, want %d", len(snap.Data), cap64)
	}

	if _, err := SnapshotFileAt(parent, "overcap", cap64); !errors.Is(err, ErrSnapshotTooLarge) {
		t.Fatalf("err = %v, want ErrSnapshotTooLarge one byte over the cap", err)
	}
}

// TestSnapshotFileAt_RefusesFileGrownAfterTheSizeCheck pins that the cap bounds the bytes actually read,
// not just the size fstat reported: a file that grows between the size check and the read is refused
// rather than returning a snapshot larger than the caller allowed.
func TestSnapshotFileAt_RefusesFileGrownAfterTheSizeCheck(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "growing")
	if err := os.WriteFile(target, []byte("small"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	parent := snapshotDir(t, root)

	orig := beforeSnapshotRead
	t.Cleanup(func() { beforeSnapshotRead = orig })
	beforeSnapshotRead = func() {
		if err := os.WriteFile(target, make([]byte, 64), 0o644); err != nil {
			t.Fatalf("grow the target: %v", err)
		}
	}

	snap, err := SnapshotFileAt(parent, "growing", 8)
	if !errors.Is(err, ErrSnapshotTooLarge) {
		t.Fatalf("err = %v, want ErrSnapshotTooLarge after the target grew past the cap", err)
	}
	if snap.Exists {
		t.Fatalf("snapshot reports Exists on a refusal: %+v", snap)
	}
}

// TestSnapshotFileAt_MaximumCapReturnsFullContents pins the largest accepted cap as an ordinary cap: it
// must return the file's bytes rather than an empty snapshot from a read limit that wrapped negative.
func TestSnapshotFileAt_MaximumCapReturnsFullContents(t *testing.T) {
	root := t.TempDir()
	want := []byte("bytes that must survive the maximum cap")
	if err := os.WriteFile(filepath.Join(root, "big"), want, 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	parent := snapshotDir(t, root)

	snap, err := SnapshotFileAt(parent, "big", math.MaxInt64)
	if err != nil {
		t.Fatalf("SnapshotFileAt at the maximum cap: %v", err)
	}
	if !snap.Exists {
		t.Fatalf("Exists = false for an existing regular file")
	}
	if !bytes.Equal(snap.Data, want) {
		t.Fatalf("Data = %q, want %q", snap.Data, want)
	}
}

func TestSnapshotFileAt_RejectsNonSingleComponentName(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed nested file: %v", err)
	}
	parent := snapshotDir(t, root)

	for _, name := range []string{"", ".", "..", "sub/f.txt", "/abs"} {
		t.Run("name="+name, func(t *testing.T) {
			if _, err := SnapshotFileAt(parent, name, 1<<20); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("err = %v, want EINVAL for %q", err, name)
			}
		})
	}
}

func TestSnapshotFileAt_RejectsNegativeCap(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	parent := snapshotDir(t, root)

	if _, err := SnapshotFileAt(parent, "f", -1); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("err = %v, want EINVAL for a negative cap", err)
	}
}
