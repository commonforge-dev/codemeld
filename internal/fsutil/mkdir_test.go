// Unit tests for the shared EnsureDir and EnsureDirAt helpers.
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
	"golang.org/x/sys/unix"
)

func TestEnsureDir_CleanCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "newdir")

	created, cat, err := EnsureDir(dir)
	if err != nil {
		t.Fatalf("EnsureDir(%q) error: %v", dir, err)
	}
	if !created {
		t.Fatalf("created = false, want true for absent target")
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}
	info, statErr := os.Stat(dir)
	if statErr != nil {
		t.Fatalf("stat after EnsureDir: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("created path is not a directory: %v", info.Mode())
	}
}

func TestEnsureDir_NestedParents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")

	created, cat, err := EnsureDir(dir)
	if err != nil {
		t.Fatalf("EnsureDir(%q) error: %v", dir, err)
	}
	if !created {
		t.Fatalf("created = false, want true for nested absent target")
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("stat after EnsureDir: %v", statErr)
	}
}

func TestEnsureDir_AlreadyExists(t *testing.T) {
	dir := t.TempDir()

	created, cat, err := EnsureDir(dir)
	if err != nil {
		t.Fatalf("EnsureDir(%q) error: %v", dir, err)
	}
	if created {
		t.Fatalf("created = true, want false for pre-existing directory")
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}
}

func TestEnsureDir_FileAtTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(target, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write occupying file: %v", err)
	}

	created, cat, err := EnsureDir(target)
	if err == nil {
		t.Fatalf("EnsureDir on file-target succeeded, want error")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q (ENOTDIR maps to io_error)", cat, fserrors.IOError)
	}
	var pe *os.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("err is not *os.PathError: %T (%v)", err, err)
	}
	if pe.Path != target {
		t.Fatalf("PathError.Path = %q, want %q", pe.Path, target)
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("err does not wrap ENOTDIR: %v", err)
	}
}

func TestEnsureDir_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; permission failure is unobservable")
	}
	parent := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir locked parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	target := filepath.Join(parent, "child")
	created, cat, err := EnsureDir(target)
	if err == nil {
		t.Fatalf("EnsureDir in unwritable parent succeeded, want error")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err does not wrap a permission error: %v", err)
	}
}

func TestEnsureDir_CategoryPropagation(t *testing.T) {
	// A child of a regular file makes os.Stat return ENOTDIR, which maps to IOError (no dedicated non-directory category).
	tmp := t.TempDir()
	parentFile := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(parentFile, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write parentFile: %v", err)
	}
	target := filepath.Join(parentFile, "child")

	created, cat, err := EnsureDir(target)
	if err == nil {
		t.Fatalf("EnsureDir under file-parent succeeded, want error")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q (ENOTDIR maps to io_error)", cat, fserrors.IOError)
	}
}

// openDir opens path as a directory descriptor with the same O_DIRECTORY|O_NOFOLLOW posture the production
// consumer (a held authorized parent) uses, and closes it at test end.
func openDir(t *testing.T, path string) *os.File {
	t.Helper()
	d, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open dir %q: %v", path, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestEnsureDirAt_SingleCreate(t *testing.T) {
	root := t.TempDir()
	parent := openDir(t, root)

	created, _, cat, err := EnsureDirAt(parent, "newdir")
	if err != nil {
		t.Fatalf("EnsureDirAt error: %v", err)
	}
	if !created {
		t.Fatalf("created = false, want true for absent target")
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}
	info, statErr := os.Stat(filepath.Join(root, "newdir"))
	if statErr != nil {
		t.Fatalf("stat after EnsureDirAt: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("created path is not a directory: %v", info.Mode())
	}
}

func TestEnsureDirAt_NestedCreate(t *testing.T) {
	root := t.TempDir()
	parent := openDir(t, root)

	created, _, cat, err := EnsureDirAt(parent, filepath.Join("a", "b", "c"))
	if err != nil {
		t.Fatalf("EnsureDirAt error: %v", err)
	}
	if !created {
		t.Fatalf("created = false, want true for nested absent target")
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}
	info, statErr := os.Stat(filepath.Join(root, "a", "b", "c"))
	if statErr != nil {
		t.Fatalf("stat nested target: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("nested target is not a directory: %v", info.Mode())
	}
}

func TestEnsureDirAt_Idempotent(t *testing.T) {
	root := t.TempDir()
	parent := openDir(t, root)

	rel := filepath.Join("a", "b")
	if _, _, _, err := EnsureDirAt(parent, rel); err != nil {
		t.Fatalf("first EnsureDirAt: %v", err)
	}

	created, _, cat, err := EnsureDirAt(parent, rel)
	if err != nil {
		t.Fatalf("second EnsureDirAt: %v", err)
	}
	if created {
		t.Fatalf("created = true on pre-existing target, want false (idempotent)")
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on idempotent success", cat)
	}
}

func TestEnsureDirAt_FileAtTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write occupying file: %v", err)
	}
	parent := openDir(t, root)

	created, _, cat, err := EnsureDirAt(parent, "f")
	if err == nil {
		t.Fatalf("EnsureDirAt over a file succeeded, want error")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("err does not wrap ENOTDIR: %v", err)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	info, statErr := os.Stat(filepath.Join(root, "f"))
	if statErr != nil {
		t.Fatalf("stat occupying file: %v", statErr)
	}
	if info.IsDir() {
		t.Fatalf("occupying file was replaced by a directory")
	}
}

func TestEnsureDirAt_NonDirectoryIntermediate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write intermediate file: %v", err)
	}
	parent := openDir(t, root)

	created, _, cat, err := EnsureDirAt(parent, filepath.Join("f", "child"))
	if err == nil {
		t.Fatalf("EnsureDirAt through a file component succeeded, want error")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("err does not wrap ENOTDIR: %v", err)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	info, statErr := os.Stat(filepath.Join(root, "f"))
	if statErr != nil {
		t.Fatalf("stat intermediate file: %v", statErr)
	}
	if info.IsDir() {
		t.Fatalf("intermediate file was replaced by a directory")
	}
}

func TestEnsureDirAt_SymlinkComponentRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	parent := openDir(t, root)

	created, _, _, err := EnsureDirAt(parent, "link")
	if err == nil {
		t.Fatalf("EnsureDirAt on a symlink component succeeded, want rejection")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	// O_NOFOLLOW does not follow the symlink, so opening it as a directory fails: ENOTDIR (the link
	// itself is not a directory) or ELOOP. Following it would have succeeded — it points at a real dir —
	// so this rejection proves the link was not traversed.
	if !errors.Is(err, syscall.ENOTDIR) && !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("err = %v, want ENOTDIR or ELOOP from refusing to follow the symlink", err)
	}
	li, lerr := os.Lstat(filepath.Join(root, "link"))
	if lerr != nil {
		t.Fatalf("lstat link: %v", lerr)
	}
	if li.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("link was replaced (mode %v); the symlink should be left untouched", li.Mode())
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("symlink was followed: outside dir gained entries %v", entries)
	}
}

func TestEnsureDirAt_SymlinkIntermediateNoRedirection(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	parent := openDir(t, root)

	_, _, _, err := EnsureDirAt(parent, filepath.Join("link", "child"))
	if err == nil {
		t.Fatalf("EnsureDirAt descending through a symlink succeeded, want rejection")
	}
	if !errors.Is(err, syscall.ENOTDIR) && !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("err = %v, want ENOTDIR or ELOOP from refusing to traverse the symlink", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "child")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("child was created through the symlink into the outside dir; redirection not blocked")
	}
}

func TestEnsureDirAt_HeldDescriptorNotRedirectedByRename(t *testing.T) {
	root := t.TempDir()
	orig := filepath.Join(root, "orig")
	if err := os.Mkdir(orig, 0o755); err != nil {
		t.Fatalf("mkdir orig: %v", err)
	}
	parent := openDir(t, orig)

	// Swap the path out from under the held descriptor: move the authorized dir aside, drop a decoy at the old path.
	moved := filepath.Join(root, "moved")
	if err := os.Rename(orig, moved); err != nil {
		t.Fatalf("rename orig: %v", err)
	}
	if err := os.Mkdir(orig, 0o755); err != nil {
		t.Fatalf("mkdir decoy: %v", err)
	}

	created, _, _, err := EnsureDirAt(parent, "child")
	if err != nil {
		t.Fatalf("EnsureDirAt: %v", err)
	}
	if !created {
		t.Fatalf("created = false, want true")
	}
	if _, statErr := os.Stat(filepath.Join(moved, "child")); statErr != nil {
		t.Fatalf("child not created under the held inode (now at moved/): %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(orig, "child")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("child created under the decoy path; held descriptor was redirected by the rename")
	}
}

func TestEnsureDirAt_BadPathRejected(t *testing.T) {
	cases := []string{"", "/abs", "..", "../escape", "a/../b", ".", "a/./b", "a//b", "a/", "good/\x00bad"}
	for _, rel := range cases {
		root := t.TempDir()
		parent := openDir(t, root)

		created, _, cat, err := EnsureDirAt(parent, rel)
		if err == nil {
			t.Fatalf("rel=%q accepted, want EINVAL", rel)
		}
		if created {
			t.Fatalf("rel=%q created = true on rejection", rel)
		}
		if !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("rel=%q err = %v, want EINVAL", rel, err)
		}
		if cat != fserrors.IOError {
			t.Fatalf("rel=%q cat = %q, want %q", rel, cat, fserrors.IOError)
		}
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			t.Fatalf("rel=%q read root: %v", rel, readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("rel=%q left stray entries: %v", rel, entries)
		}
	}
}

func TestEnsureDirAt_NonDirectoryParent(t *testing.T) {
	root := t.TempDir()
	fpath := filepath.Join(root, "file")
	if err := os.WriteFile(fpath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	f, err := os.OpenFile(fpath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer f.Close() //nolint:errcheck // read-only fd in a test

	created, _, cat, err := EnsureDirAt(f, "child")
	if err == nil {
		t.Fatalf("EnsureDirAt with a non-directory parent succeeded, want error")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("err does not wrap ENOTDIR: %v", err)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
}

func TestEnsureDirAt_ParentSyncFailureLeavesResidue(t *testing.T) {
	restore := SetSyncDirForTest(func(*os.File) error { return syscall.EIO })
	defer restore()

	root := t.TempDir()
	parent := openDir(t, root)

	created, _, cat, err := EnsureDirAt(parent, "newdir")
	if err == nil {
		t.Fatalf("EnsureDirAt succeeded despite forced parent-sync failure")
	}
	if created {
		t.Fatalf("created = true on sync failure, want false")
	}
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("err does not wrap the forced EIO: %v", err)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	info, statErr := os.Stat(filepath.Join(root, "newdir"))
	if statErr != nil {
		t.Fatalf("just-created segment not left as residue after the sync failure: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("residue at newdir is not a directory: %v", info.Mode())
	}
}

func TestEnsureDirAt_NestedFirstParentSyncFailureLeavesResidue(t *testing.T) {
	var calls int
	restore := SetSyncDirForTest(func(*os.File) error {
		calls++
		if calls == 1 {
			return syscall.EIO
		}
		return nil
	})
	defer restore()

	root := t.TempDir()
	parent := openDir(t, root)

	created, _, cat, err := EnsureDirAt(parent, filepath.Join("a", "b", "c"))
	if err == nil {
		t.Fatalf("EnsureDirAt succeeded despite forced first-parent-sync failure")
	}
	if created {
		t.Fatalf("created = true on sync failure, want false")
	}
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("err does not wrap the forced EIO: %v", err)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	info, statErr := os.Stat(filepath.Join(root, "a"))
	if statErr != nil || !info.IsDir() {
		t.Fatalf("first segment not left as residue after the sync failure: info=%v err=%v", info, statErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "a", "b")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("descent continued past the failed segment: a/b exists (%v)", statErr)
	}
}

func TestEnsureDirAt_SyncFailureDoesNotUnlinkConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	stash := t.TempDir()

	var replacement os.FileInfo
	var swapped bool
	restore := SetSyncDirForTest(func(*os.File) error {
		if swapped {
			return nil
		}
		swapped = true
		if err := os.Rename(filepath.Join(root, "seg"), filepath.Join(stash, "seg")); err != nil {
			t.Fatalf("move the invocation-created segment aside: %v", err)
		}
		if err := os.Mkdir(filepath.Join(root, "seg"), 0o755); err != nil {
			t.Fatalf("drop the concurrent replacement: %v", err)
		}
		info, err := os.Stat(filepath.Join(root, "seg"))
		if err != nil {
			t.Fatalf("stat the concurrent replacement: %v", err)
		}
		replacement = info
		return syscall.EIO
	})
	defer restore()

	parent := openDir(t, root)
	if _, _, _, err := EnsureDirAt(parent, "seg"); err == nil {
		t.Fatalf("EnsureDirAt succeeded despite forced sync failure")
	}

	got, statErr := os.Stat(filepath.Join(root, "seg"))
	if statErr != nil {
		t.Fatalf("concurrent replacement was removed by the failed-sync cleanup: %v", statErr)
	}
	if !os.SameFile(got, replacement) {
		t.Fatalf("directory at the created name is no longer the concurrent replacement")
	}
}

func TestEnsureDirAt_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; permission failure is unobservable")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	parent := openDir(t, locked)

	created, _, cat, err := EnsureDirAt(parent, "child")
	if err == nil {
		t.Fatalf("EnsureDirAt into an unwritable directory succeeded, want error")
	}
	if created {
		t.Fatalf("created = true on failure, want false")
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err does not wrap a permission error: %v", err)
	}
}

func dirIdentity(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return uint64(st.Dev), uint64(st.Ino)
}

func recordLifecycle(log *[]string, segs *[]DirSegment) DirLifecycle {
	return DirLifecycle{
		Intent: func(relPath string) error {
			*log = append(*log, "intent:"+relPath)
			return nil
		},
		Confirm: func(seg DirSegment) error {
			*log = append(*log, "confirm:"+seg.Path)
			*segs = append(*segs, seg)
			return nil
		},
	}
}

// TestEnsureDirAt_LifecycleReportsEveryCreatedSegment pins the per-segment lifecycle on a fresh nested
// descent: each segment's intent is reported before its Mkdirat (proved by the segment still being
// absent when the intent fires) and its confirmation carries the device and inode of the directory that
// was then re-opened.
func TestEnsureDirAt_LifecycleReportsEveryCreatedSegment(t *testing.T) {
	root := t.TempDir()
	parent := openDir(t, root)

	var log []string
	var segs []DirSegment
	hooks := recordLifecycle(&log, &segs)
	intent := hooks.Intent
	hooks.Intent = func(relPath string) error {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relPath))); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("intent for %q fired after the directory already existed (stat err = %v)", relPath, err)
		}
		return intent(relPath)
	}

	if _, createdDirs, _, err := EnsureDirAt(parent, filepath.Join("a", "b", "c"), hooks); err != nil {
		t.Fatalf("EnsureDirAt: %v", err)
	} else if len(createdDirs) != 3 {
		t.Fatalf("createdDirs = %v, want all three segments", createdDirs)
	}

	wantLog := []string{"intent:a", "confirm:a", "intent:a/b", "confirm:a/b", "intent:a/b/c", "confirm:a/b/c"}
	if !slicesEqual(log, wantLog) {
		t.Fatalf("hook order = %v, want %v", log, wantLog)
	}
	for _, seg := range segs {
		if !seg.Created {
			t.Fatalf("segment %q reported Created=false on a fresh descent", seg.Path)
		}
		dev, ino := dirIdentity(t, filepath.Join(root, filepath.FromSlash(seg.Path)))
		if seg.Dev != dev || seg.Ino != ino {
			t.Fatalf("segment %q identity = (%d,%d), want (%d,%d)", seg.Path, seg.Dev, seg.Ino, dev, ino)
		}
	}
}

// TestEnsureDirAt_ExistingSegmentConfirmsNoCreate pins the outcome a journal consumer needs to tell an
// ordinary descent through a pre-existing directory apart from a crash after a create: the pre-existing
// segment is confirmed with Created=false, so its intent is resolved rather than left unrecovered.
func TestEnsureDirAt_ExistingSegmentConfirmsNoCreate(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatalf("seed the pre-existing segment: %v", err)
	}
	parent := openDir(t, root)

	var log []string
	var segs []DirSegment
	if _, createdDirs, _, err := EnsureDirAt(parent, filepath.Join("a", "b"), recordLifecycle(&log, &segs)); err != nil {
		t.Fatalf("EnsureDirAt: %v", err)
	} else if len(createdDirs) != 1 || createdDirs[0] != "a/b" {
		t.Fatalf("createdDirs = %v, want only a/b", createdDirs)
	}

	if len(segs) != 2 {
		t.Fatalf("confirmations = %v, want one per attempted segment", segs)
	}
	if segs[0].Path != "a" || segs[0].Created {
		t.Fatalf("segment a = %+v, want Created=false", segs[0])
	}
	dev, ino := dirIdentity(t, filepath.Join(root, "a"))
	if segs[0].Dev != dev || segs[0].Ino != ino {
		t.Fatalf("pre-existing segment identity = (%d,%d), want the directory on disk (%d,%d)", segs[0].Dev, segs[0].Ino, dev, ino)
	}
	if segs[1].Path != "a/b" || !segs[1].Created {
		t.Fatalf("segment a/b = %+v, want Created=true", segs[1])
	}
}

// TestEnsureDirAt_FailedMkdiratConfirmsNothingCreated pins the other no-create outcome: a Mkdirat that
// fails outright made nothing, so its intent is resolved with a zero identity rather than looking like a
// crash between a successful create and its confirmation.
func TestEnsureDirAt_FailedMkdiratConfirmsNothingCreated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unwritable directory would still be writable")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatalf("mkdir unwritable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	parent := openDir(t, locked)

	var log []string
	var segs []DirSegment
	hooks := recordLifecycle(&log, &segs)
	confirm := hooks.Confirm
	hooks.Confirm = func(seg DirSegment) error {
		_ = confirm(seg)
		return errors.New("journalling problem")
	}

	_, _, _, err := EnsureDirAt(parent, filepath.Join("a", "b"), hooks)
	if err == nil {
		t.Fatal("EnsureDirAt into an unwritable directory succeeded, want a failure")
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("err = %v, want the filesystem EACCES rather than the confirm hook's error", err)
	}

	wantLog := []string{"intent:a", "confirm:a"}
	if !slicesEqual(log, wantLog) {
		t.Fatalf("hook order = %v, want %v (descent must stop at the failed segment)", log, wantLog)
	}
	if segs[0].Created || segs[0].Dev != 0 || segs[0].Ino != 0 {
		t.Fatalf("segment a = %+v, want a no-create outcome with a zero identity", segs[0])
	}
}

// TestEnsureDirAt_HookErrorStopsDescent pins that either hook's error aborts the call the way any other
// failure does: the later segments are never attempted, and a segment already created before the
// failure is left in place rather than removed.
func TestEnsureDirAt_HookErrorStopsDescent(t *testing.T) {
	sentinel := errors.New("hook refused")

	t.Run("intent", func(t *testing.T) {
		root := t.TempDir()
		parent := openDir(t, root)

		_, _, cat, err := EnsureDirAt(parent, filepath.Join("a", "b"), DirLifecycle{
			Intent: func(relPath string) error {
				if relPath == "a/b" {
					return sentinel
				}
				return nil
			},
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want the hook's sentinel", err)
		}
		if cat != fserrors.IOError {
			t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
		}
		if info, statErr := os.Stat(filepath.Join(root, "a")); statErr != nil || !info.IsDir() {
			t.Fatalf("the already-created segment was removed: info=%v err=%v", info, statErr)
		}
		if _, statErr := os.Stat(filepath.Join(root, "a", "b")); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("descent continued past the refused intent (stat err = %v)", statErr)
		}
	})

	t.Run("confirm", func(t *testing.T) {
		root := t.TempDir()
		parent := openDir(t, root)

		_, _, _, err := EnsureDirAt(parent, filepath.Join("a", "b"), DirLifecycle{
			Confirm: func(DirSegment) error { return sentinel },
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want the hook's sentinel", err)
		}
		if info, statErr := os.Stat(filepath.Join(root, "a")); statErr != nil || !info.IsDir() {
			t.Fatalf("the already-created segment was removed: info=%v err=%v", info, statErr)
		}
		if _, statErr := os.Stat(filepath.Join(root, "a", "b")); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("descent continued past the refused confirmation (stat err = %v)", statErr)
		}
	})
}

// TestEnsureDirAt_UnconfirmedIntentIsRetained pins the crash boundary child-agent rollback and
// orphaned-journal recovery must carry: a failure after Mkdirat but before the confirmation leaves an
// intent with no identity and a directory still on disk. Nothing removes it here — with no confirmed
// identity it is unrecovered state, not a rollback candidate, because the name alone cannot prove
// this call made what is there now.
func TestEnsureDirAt_UnconfirmedIntentIsRetained(t *testing.T) {
	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	syncDir = func(*os.File) error { return syscall.EIO }

	root := t.TempDir()
	parent := openDir(t, root)

	var log []string
	var segs []DirSegment
	_, createdDirs, _, err := EnsureDirAt(parent, "a", recordLifecycle(&log, &segs))
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("err = %v, want the forced EIO", err)
	}
	if !slicesEqual(log, []string{"intent:a"}) {
		t.Fatalf("hook order = %v, want the intent alone with no confirmation", log)
	}
	if len(createdDirs) != 0 {
		t.Fatalf("createdDirs = %v, want none reported on failure", createdDirs)
	}
	if info, statErr := os.Stat(filepath.Join(root, "a")); statErr != nil || !info.IsDir() {
		t.Fatalf("the unconfirmed directory was removed: info=%v err=%v", info, statErr)
	}
}

func slicesEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
