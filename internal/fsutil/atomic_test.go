// Unit tests for WriteAtomic, the descriptor-relative replace/create publishes, and tempName.
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
	"golang.org/x/sys/unix"
)

func TestWriteAtomic_CleanWrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.bin")
	payload := []byte("hello world\n")

	step, cat, err := WriteAtomic(target, payload, 0o644)
	if err != nil {
		t.Fatalf("WriteAtomic error: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" {
		t.Fatalf("step = %q, want empty on success", step)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}

	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(got) != string(payload) {
		t.Fatalf("contents = %q, want %q", got, payload)
	}

	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("stat target: %v", statErr)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}

	// No temp orphans left behind.
	entries, readDirErr := os.ReadDir(dir)
	if readDirErr != nil {
		t.Fatalf("readdir: %v", readDirErr)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp orphan remains: %q", e.Name())
		}
	}
}

func TestTempName_NeverYamlOrJson(t *testing.T) {
	bases := []string{
		"config.yaml",
		"state.json",
		"plain",
		"no-ext",
		"multi.part.json",
		"",
		"file.YAML", // case-sensitivity check: lowercase suffix list, uppercase target
	}
	for _, base := range bases {
		t.Run("base="+base, func(t *testing.T) {
			name, err := tempName(base)
			if err != nil {
				t.Fatalf("tempName(%q) error: %v", base, err)
			}
			if !strings.Contains(name, ".tmp-") {
				t.Fatalf("tempName(%q) = %q; missing .tmp- marker", base, name)
			}
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".json") {
				t.Fatalf("tempName(%q) = %q; ends in forbidden discovery suffix", base, name)
			}
			// Suffix after ".tmp-" must be exactly 16 lowercase hex chars.
			idx := strings.LastIndex(name, ".tmp-")
			suffix := name[idx+len(".tmp-"):]
			if len(suffix) != 16 {
				t.Fatalf("tempName(%q) suffix length = %d, want 16: %q", base, len(suffix), suffix)
			}
			for _, r := range suffix {
				if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
					t.Fatalf("tempName(%q) suffix has non-hex char %q in %q", base, r, suffix)
				}
			}
		})
	}
}

func TestTempName_Randomness(t *testing.T) {
	const n = 64
	seen := make(map[string]struct{}, n)
	for i := range n {
		name, err := tempName("x")
		if err != nil {
			t.Fatalf("tempName error: %v", err)
		}
		if _, dup := seen[name]; dup {
			t.Fatalf("duplicate tempName after %d iterations: %q", i, name)
		}
		seen[name] = struct{}{}
	}
}

func TestWriteAtomic_ParentDirMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "no-such-subdir", "out.bin")

	step, cat, err := WriteAtomic(target, []byte("x"), 0o644)
	if err == nil {
		t.Fatalf("WriteAtomic with missing parent dir succeeded, want error")
	}
	if step != ParentSyncStep {
		t.Fatalf("step = %q, want %q", step, ParentSyncStep)
	}
	if cat != fserrors.NotFound {
		t.Fatalf("cat = %q, want %q", cat, fserrors.NotFound)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err does not wrap fs.ErrNotExist: %v", err)
	}
}

func TestWriteAtomic_ParentIsRegularFile(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent-file")
	if err := os.WriteFile(parent, []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("seed regular-file parent: %v", err)
	}
	target := filepath.Join(parent, "out.bin")

	step, cat, err := WriteAtomic(target, []byte("x"), 0o644)
	if err == nil {
		t.Fatalf("WriteAtomic with regular-file parent succeeded, want error")
	}
	if step != ParentSyncStep {
		t.Fatalf("step = %q, want %q", step, ParentSyncStep)
	}
	if cat == "" {
		t.Fatalf("cat is empty on non-directory parent, want a category")
	}
}

func TestWriteAtomic_WriteFailure_ReadOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir read-only parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	target := filepath.Join(parent, "out.bin")
	step, cat, err := WriteAtomic(target, []byte("x"), 0o644)
	if err == nil {
		t.Fatalf("WriteAtomic into read-only parent succeeded, want error")
	}
	if step != WriteStep {
		t.Fatalf("step = %q, want %q", step, WriteStep)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}

	// Owner still has read+execute under 0500, so the parent is listable.
	entries, readErr := os.ReadDir(parent)
	if readErr != nil {
		t.Fatalf("readdir: %v", readErr)
	}
	for _, e := range entries {
		t.Fatalf("unexpected entry left in read-only parent: %q", e.Name())
	}
}

func TestWriteAtomic_RenameFailure_TargetIsDirectory(t *testing.T) {
	// The sibling temp file makes the rename same-device, so EXDEV is unreachable via the public API; use a directory target to force os.Rename to fail instead.
	dir := t.TempDir()
	target := filepath.Join(dir, "out.bin")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}

	step, cat, err := WriteAtomic(target, []byte("x"), 0o644)
	if err == nil {
		t.Fatalf("WriteAtomic with directory target succeeded, want error")
	}
	if step != RenameStep {
		t.Fatalf("step = %q, want %q", step, RenameStep)
	}
	if cat == "" {
		t.Fatalf("cat is empty on rename failure, want a category")
	}

	// No temp orphan left behind alongside the target directory.
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("readdir: %v", readErr)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp orphan remains: %q", e.Name())
		}
	}
}

func TestWriteAtomic_TempSyncFailure(t *testing.T) {
	orig := syncFile
	t.Cleanup(func() { syncFile = orig })
	sentinel := errors.New("forced temp sync failure")
	syncFile = func(*os.File) error { return sentinel }

	dir := t.TempDir()
	target := filepath.Join(dir, "out.bin")
	step, _, err := WriteAtomic(target, []byte("x"), 0o644)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if step != WriteStep {
		t.Fatalf("step = %q, want %q", step, WriteStep)
	}

	if _, statErr := os.Stat(target); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("target unexpectedly exists or stat err: %v", statErr)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("readdir: %v", readErr)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp orphan remains: %q", e.Name())
		}
	}
}

func TestWriteAtomic_ParentSyncFailure(t *testing.T) {
	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	sentinel := errors.New("forced parent sync failure")
	syncDir = func(*os.File) error { return sentinel }

	dir := t.TempDir()
	target := filepath.Join(dir, "out.bin")
	step, _, err := WriteAtomic(target, []byte("x"), 0o644)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if step != ParentSyncStep {
		t.Fatalf("step = %q, want %q", step, ParentSyncStep)
	}
}

// assertNoTempOrphan fails if any sibling temp file is left in dir.
func assertNoTempOrphan(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp orphan remains: %q", e.Name())
		}
	}
}

func writeAtomicCreate(t *testing.T, targetPath string, data []byte, mode os.FileMode) (AtomicWriteStep, fserrors.Category, error) {
	t.Helper()
	parentDir := filepath.Dir(targetPath)
	dirFD, openErr := os.Open(parentDir)
	if openErr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(openErr), openErr
	}
	defer dirFD.Close() //nolint:errcheck // read-only descriptor opened only to fsync the parent dir
	step, cat, _, err := WriteAtomicCreateAt(dirFD, filepath.Base(targetPath), data, mode)
	return step, cat, err
}

func TestWriteAtomicCreate_CleanCreate(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "new.txt")
	payload := []byte("fresh contents\n")

	step, cat, err := writeAtomicCreate(t, target, payload, 0o644)
	if err != nil {
		t.Fatalf("WriteAtomicCreate error: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want empty on success", step, cat)
	}
	if got := readBack(t, target); string(got) != string(payload) {
		t.Fatalf("contents = %q, want %q", got, payload)
	}
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("stat target: %v", statErr)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
	assertNoTempOrphan(t, dir)
}

func TestWriteAtomicCreate_EmptyContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.txt")

	if step, cat, err := writeAtomicCreate(t, target, []byte{}, 0o644); err != nil {
		t.Fatalf("WriteAtomicCreate error: %v (step=%q cat=%q)", err, step, cat)
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if len(got) != 0 {
		t.Fatalf("contents = %q, want empty", got)
	}
	assertNoTempOrphan(t, dir)
}

// TestWriteAtomicCreate_RefusesExistingFilePreservesBytes pins the no-overwrite publish: a
// target present at publish time (the publish-time materialization case) is never clobbered — the call
// fails with err wrapping fs.ErrExist at LinkStep and the pre-existing bytes are byte-identical.
func TestWriteAtomicCreate_RefusesExistingFilePreservesBytes(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "exists.txt")
	const original = "ORIGINAL DO NOT CLOBBER\n"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatalf("seed existing target: %v", err)
	}

	step, _, err := writeAtomicCreate(t, target, []byte("OVERWRITE ATTEMPT"), 0o644)
	if err == nil {
		t.Fatal("WriteAtomicCreate over an existing file succeeded, want a no-overwrite failure")
	}
	if step != LinkStep {
		t.Fatalf("step = %q, want %q", step, LinkStep)
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err does not wrap fs.ErrExist: %v", err)
	}
	if got := readBack(t, target); string(got) != original {
		t.Fatalf("contents = %q, want byte-identical %q (existing bytes must survive)", got, original)
	}
	assertNoTempOrphan(t, dir)
}

func TestWriteAtomicCreate_RefusesExistingDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "adir")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}

	step, _, err := writeAtomicCreate(t, target, []byte("x"), 0o644)
	if err == nil {
		t.Fatal("WriteAtomicCreate over an existing directory succeeded, want failure")
	}
	if step != LinkStep {
		t.Fatalf("step = %q, want %q", step, LinkStep)
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		t.Fatalf("target is no longer the original directory: info=%v err=%v", info, statErr)
	}
	assertNoTempOrphan(t, dir)
}

func TestWriteAtomicCreate_RefusesExistingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "link")
	// A dangling symlink: it exists as a symlink even though its destination does not.
	if err := os.Symlink(filepath.Join(dir, "nowhere"), target); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	step, _, err := writeAtomicCreate(t, target, []byte("x"), 0o644)
	if err == nil {
		t.Fatal("WriteAtomicCreate over an existing symlink succeeded, want failure")
	}
	if step != LinkStep {
		t.Fatalf("step = %q, want %q", step, LinkStep)
	}
	if fi, lerr := os.Lstat(target); lerr != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("target is no longer the original symlink: mode=%v err=%v", fi.Mode(), lerr)
	}
	assertNoTempOrphan(t, dir)
}

func TestWriteAtomicCreate_ParentDirMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "no-such-subdir", "new.txt")

	step, cat, err := writeAtomicCreate(t, target, []byte("x"), 0o644)
	if err == nil {
		t.Fatal("WriteAtomicCreate with missing parent succeeded, want error")
	}
	if step != ParentSyncStep {
		t.Fatalf("step = %q, want %q", step, ParentSyncStep)
	}
	if cat != fserrors.NotFound {
		t.Fatalf("cat = %q, want %q", cat, fserrors.NotFound)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err does not wrap fs.ErrNotExist: %v", err)
	}
}

// TestWriteAtomicCreate_SyncFailures pins create's atomicity contract at both fsync points:
// a forced fsync failure — whether on the temp file before publish (aborts at WriteStep, target never
// appears) or on the parent directory after os.Link has already published the target (ParentSyncStep) —
// is a returned failure, so the target must not survive on disk and no temp residue may remain. This
// guards the observable filesystem contract, not just the returned step: if the post-publish cleanup is
// removed the orphaned target makes the parent-sync case fail.
func TestWriteAtomicCreate_SyncFailures(t *testing.T) {
	cases := []struct {
		name     string
		seam     *func(*os.File) error
		wantStep AtomicWriteStep
	}{
		{"temp sync", &syncFile, WriteStep},
		{"parent sync", &syncDir, ParentSyncStep},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := *tc.seam
			t.Cleanup(func() { *tc.seam = orig })
			sentinel := errors.New("forced sync failure")
			*tc.seam = func(*os.File) error { return sentinel }

			dir := t.TempDir()
			target := filepath.Join(dir, "new.txt")
			step, _, err := writeAtomicCreate(t, target, []byte("x"), 0o644)
			if !errors.Is(err, sentinel) {
				t.Fatalf("err = %v, want sentinel %v", err, sentinel)
			}
			if step != tc.wantStep {
				t.Fatalf("step = %q, want %q", step, tc.wantStep)
			}
			if _, statErr := os.Stat(target); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("target survived a failed create or stat err: %v", statErr)
			}
			assertNoTempOrphan(t, dir)
		})
	}
}

func readBack(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return b
}

func TestWriteAtomic_OverwritesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rolling.bin")
	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed existing target: %v", err)
	}

	step, cat, err := WriteAtomic(target, []byte("fresh"), 0o644)
	if err != nil {
		t.Fatalf("WriteAtomic overwrite error: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q, want empty on success", step, cat)
	}

	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(got) != "fresh" {
		t.Fatalf("contents = %q, want %q", got, "fresh")
	}
}

func openTestDir(t *testing.T, path string) *os.File {
	t.Helper()
	d, err := os.Open(path)
	if err != nil {
		t.Fatalf("open dir %q: %v", path, err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// withUmask installs a restrictive process umask for the duration of one test. Nothing in this package
// runs in parallel, so the process-wide setting cannot leak into a concurrent test.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	prev := unix.Umask(mask)
	t.Cleanup(func() { unix.Umask(prev) })
}

// TestWriteAtomicReplaceAt_FollowsHeldDirectoryThroughRename pins the containment contract: the publish
// lands in the directory the caller opened even after that directory is renamed, and never in a decoy
// swapped in at the old path.
func TestWriteAtomicReplaceAt_FollowsHeldDirectoryThroughRename(t *testing.T) {
	root := t.TempDir()
	authorized := filepath.Join(root, "authorized")
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("mkdir authorized: %v", err)
	}
	parent := openTestDir(t, authorized)

	moved := filepath.Join(root, "moved")
	if err := os.Rename(authorized, moved); err != nil {
		t.Fatalf("rename the held directory: %v", err)
	}
	if err := os.Mkdir(authorized, 0o755); err != nil {
		t.Fatalf("drop the decoy at the old path: %v", err)
	}

	if step, cat, _, err := WriteAtomicReplaceAt(parent, "out.txt", []byte("payload"), 0o644, nil, nil); err != nil {
		t.Fatalf("WriteAtomicReplaceAt error: %v (step=%q cat=%q)", err, step, cat)
	}

	if got := readBack(t, filepath.Join(moved, "out.txt")); string(got) != "payload" {
		t.Fatalf("contents under the held directory = %q, want %q", got, "payload")
	}
	if _, err := os.Stat(filepath.Join(authorized, "out.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the decoy at the old path received the write (stat err = %v)", err)
	}
	assertNoTempOrphan(t, moved)
}

func TestWriteAtomicReplaceAt_OverwritesExistingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "rolling.txt")
	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed existing target: %v", err)
	}
	parent := openTestDir(t, root)

	if step, cat, _, err := WriteAtomicReplaceAt(parent, "rolling.txt", []byte("fresh"), 0o644, nil, nil); err != nil {
		t.Fatalf("WriteAtomicReplaceAt error: %v (step=%q cat=%q)", err, step, cat)
	}
	if got := readBack(t, target); string(got) != "fresh" {
		t.Fatalf("contents = %q, want %q", got, "fresh")
	}
	assertNoTempOrphan(t, root)
}

// TestWriteAtomicPublish_ExactModeUnderUmask pins that both descriptor-relative publishes land the mode
// the caller asked for. The O_CREAT mode alone is trimmed by the umask, so under 022 a 0664 request
// would silently publish 0644 without the explicit chmod.
func TestWriteAtomicPublish_ExactModeUnderUmask(t *testing.T) {
	cases := []struct {
		name    string
		publish func(parent *os.File, name string, data []byte, mode os.FileMode) (AtomicWriteStep, fserrors.Category, error)
	}{
		{"replace", func(parent *os.File, name string, data []byte, mode os.FileMode) (AtomicWriteStep, fserrors.Category, error) {
			step, cat, _, err := WriteAtomicReplaceAt(parent, name, data, mode, nil, nil)
			return step, cat, err
		}},
		{"create", func(parent *os.File, name string, data []byte, mode os.FileMode) (AtomicWriteStep, fserrors.Category, error) {
			step, cat, _, err := WriteAtomicCreateAt(parent, name, data, mode)
			return step, cat, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withUmask(t, 0o022)
			root := t.TempDir()
			parent := openTestDir(t, root)

			if step, cat, err := tc.publish(parent, "out.txt", []byte("x"), 0o664); err != nil {
				t.Fatalf("publish error: %v (step=%q cat=%q)", err, step, cat)
			}
			info, err := os.Stat(filepath.Join(root, "out.txt"))
			if err != nil {
				t.Fatalf("stat target: %v", err)
			}
			if info.Mode().Perm() != 0o664 {
				t.Fatalf("mode = %v, want 0664 despite the 022 umask", info.Mode().Perm())
			}
		})
	}
}

// TestWriteAtomicPublish_UnreadableModeLeavesNoResidue pins cleanup against the exact mode the publish
// now lands: the staged entry is fchmod-ed to the caller's mode before it is published, so a mode
// without read permission — a create under a restrictive umask, an edit preserving a write-only file —
// used to make cleanup's own O_RDONLY identity check fail with EACCES. Cleanup then read this call's
// temporary entry as another writer's file and left it beside a successfully published target. The
// replace case publishes over an unreadable planned original, so the displaced entry is unreadable too.
func TestWriteAtomicPublish_UnreadableModeLeavesNoResidue(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; the unreadable-entry case is unobservable")
	}
	cases := []struct {
		name       string
		seedTarget bool
		publish    func(parent *os.File, name string, data []byte, mode os.FileMode, planned os.FileInfo) (AtomicWriteStep, fserrors.Category, error)
	}{
		{
			name: "create",
			publish: func(parent *os.File, name string, data []byte, mode os.FileMode, _ os.FileInfo) (AtomicWriteStep, fserrors.Category, error) {
				step, cat, _, err := WriteAtomicCreateAt(parent, name, data, mode)
				return step, cat, err
			},
		},
		{
			name:       "replace",
			seedTarget: true,
			publish: func(parent *os.File, name string, data []byte, mode os.FileMode, planned os.FileInfo) (AtomicWriteStep, fserrors.Category, error) {
				step, cat, _, err := WriteAtomicReplaceAt(parent, name, data, mode, planned, nil)
				return step, cat, err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "out.txt")
			var planned os.FileInfo
			if tc.seedTarget {
				if err := os.WriteFile(target, []byte("original"), 0o200); err != nil {
					t.Fatalf("seed the unreadable target: %v", err)
				}
				info, serr := os.Stat(target)
				if serr != nil {
					t.Fatalf("stat the planned target: %v", serr)
				}
				planned = info
			}
			parent := openTestDir(t, root)

			if step, cat, err := tc.publish(parent, "out.txt", []byte("published"), 0o200, planned); err != nil {
				t.Fatalf("publish error: %v (step=%q cat=%q)", err, step, cat)
			}
			info, serr := os.Stat(target)
			if serr != nil {
				t.Fatalf("stat the published target: %v", serr)
			}
			if info.Mode().Perm() != 0o200 {
				t.Fatalf("mode = %v, want 0200", info.Mode().Perm())
			}
			assertNoTempOrphan(t, root)
		})
	}
}

// TestWriteAtomicPublish_HookSeesDurableStateBeforeVisibility pins the pre-publish contract for both
// publishes at once: the hook is handed the target name, the exact bytes, and the exact mode that
// publication will make visible; the file fsync has already run against a descriptor whose chmod and
// fstat came first (so the mode the hook records is durable); and nothing is visible at the target name
// yet.
func TestWriteAtomicPublish_HookSeesDurableStateBeforeVisibility(t *testing.T) {
	cases := []struct {
		name       string
		seedTarget string
		wantAtHook string
		publish    func(parent *os.File, name string, data []byte, mode os.FileMode, hook PrePublish) (AtomicWriteStep, fserrors.Category, error)
	}{
		{
			name:       "replace",
			seedTarget: "original bytes",
			wantAtHook: "original bytes",
			publish: func(parent *os.File, name string, data []byte, mode os.FileMode, hook PrePublish) (AtomicWriteStep, fserrors.Category, error) {
				step, cat, _, err := WriteAtomicReplaceAt(parent, name, data, mode, nil, hook)
				return step, cat, err
			},
		},
		{
			name: "create",
			publish: func(parent *os.File, name string, data []byte, mode os.FileMode, hook PrePublish) (AtomicWriteStep, fserrors.Category, error) {
				step, cat, _, err := WriteAtomicCreateAt(parent, name, data, mode, hook)
				return step, cat, err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withUmask(t, 0o022)
			root := t.TempDir()
			target := filepath.Join(root, "out.txt")
			if tc.seedTarget != "" {
				if err := os.WriteFile(target, []byte(tc.seedTarget), 0o600); err != nil {
					t.Fatalf("seed target: %v", err)
				}
			}
			parent := openTestDir(t, root)

			var order []string
			var syncedMode os.FileMode
			origSync := syncFile
			t.Cleanup(func() { syncFile = origSync })
			syncFile = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					t.Fatalf("stat the staged descriptor inside the sync seam: %v", err)
				}
				syncedMode = info.Mode().Perm()
				order = append(order, "sync")
				return origSync(f)
			}

			payload := []byte("published bytes")
			var gotName string
			var gotData []byte
			var gotMode os.FileMode
			hook := func(name string, data []byte, mode os.FileMode) error {
				order = append(order, "hook")
				gotName, gotData, gotMode = name, append([]byte(nil), data...), mode
				if tc.wantAtHook == "" {
					if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("target visible before publication (stat err = %v)", err)
					}
				} else if got := readBack(t, target); string(got) != tc.wantAtHook {
					t.Fatalf("target already changed at hook time: %q, want %q", got, tc.wantAtHook)
				}
				return nil
			}

			if step, cat, err := tc.publish(parent, "out.txt", payload, 0o664, hook); err != nil {
				t.Fatalf("publish error: %v (step=%q cat=%q)", err, step, cat)
			}

			if !reflect.DeepEqual(order, []string{"sync", "hook"}) {
				t.Fatalf("order = %v, want the file fsync to complete before the hook", order)
			}
			if syncedMode != 0o664 {
				t.Fatalf("mode at fsync = %v, want 0664; the chmod must precede the fsync for the recorded mode to be durable", syncedMode)
			}
			if gotName != "out.txt" {
				t.Fatalf("hook name = %q, want out.txt", gotName)
			}
			if string(gotData) != string(payload) {
				t.Fatalf("hook bytes = %q, want %q", gotData, payload)
			}
			if gotMode != 0o664 {
				t.Fatalf("hook mode = %v, want the exact published 0664", gotMode)
			}
			if got := readBack(t, target); string(got) != string(payload) {
				t.Fatalf("published contents = %q, want %q", got, payload)
			}
		})
	}
}

// TestWriteAtomicPublish_HookErrorAbortsWithoutResidue pins that a refusing hook leaves the filesystem
// exactly as it was — the replace target keeps its original bytes and mode, the create target stays
// absent — and that the staged temp entry is removed either way.
func TestWriteAtomicPublish_HookErrorAbortsWithoutResidue(t *testing.T) {
	sentinel := errors.New("hook refused the publish")

	t.Run("replace", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "out.txt")
		const original = "ORIGINAL\n"
		if err := os.WriteFile(target, []byte(original), 0o640); err != nil {
			t.Fatalf("seed target: %v", err)
		}
		parent := openTestDir(t, root)

		step, _, _, err := WriteAtomicReplaceAt(parent, "out.txt", []byte("REPLACEMENT"), 0o644, nil, func(string, []byte, os.FileMode) error {
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want the hook's sentinel", err)
		}
		if step != WriteStep {
			t.Fatalf("step = %q, want %q", step, WriteStep)
		}
		if got := readBack(t, target); string(got) != original {
			t.Fatalf("contents = %q, want byte-identical %q", got, original)
		}
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("stat target: %v", statErr)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("mode = %v, want the untouched 0640", info.Mode().Perm())
		}
		assertNoTempOrphan(t, root)
	})

	t.Run("create", func(t *testing.T) {
		root := t.TempDir()
		parent := openTestDir(t, root)

		step, _, _, err := WriteAtomicCreateAt(parent, "out.txt", []byte("x"), 0o644, func(string, []byte, os.FileMode) error {
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want the hook's sentinel", err)
		}
		if step != WriteStep {
			t.Fatalf("step = %q, want %q", step, WriteStep)
		}
		if _, statErr := os.Stat(filepath.Join(root, "out.txt")); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("target exists after a refused create (stat err = %v)", statErr)
		}
		assertNoTempOrphan(t, root)
	})
}

// TestWriteAtomicReplaceAt_SyncFailureLeavesOriginal pins that a failure at either fsync point aborts
// before the rename (temp sync) or is reported after it (parent sync), and never leaves temp residue.
func TestWriteAtomicReplaceAt_SyncFailureLeavesOriginal(t *testing.T) {
	cases := []struct {
		name       string
		seam       *func(*os.File) error
		wantStep   AtomicWriteStep
		wantOnDisk string
	}{
		{"temp sync", &syncFile, WriteStep, "ORIGINAL"},
		{"parent sync", &syncDir, ParentSyncStep, "REPLACEMENT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := *tc.seam
			t.Cleanup(func() { *tc.seam = orig })
			sentinel := errors.New("forced sync failure")
			*tc.seam = func(*os.File) error { return sentinel }

			root := t.TempDir()
			target := filepath.Join(root, "out.txt")
			if err := os.WriteFile(target, []byte("ORIGINAL"), 0o644); err != nil {
				t.Fatalf("seed target: %v", err)
			}
			parent := openTestDir(t, root)

			step, _, _, err := WriteAtomicReplaceAt(parent, "out.txt", []byte("REPLACEMENT"), 0o644, nil, nil)
			if !errors.Is(err, sentinel) {
				t.Fatalf("err = %v, want the forced sentinel", err)
			}
			if step != tc.wantStep {
				t.Fatalf("step = %q, want %q", step, tc.wantStep)
			}
			if got := readBack(t, target); string(got) != tc.wantOnDisk {
				t.Fatalf("contents = %q, want %q", got, tc.wantOnDisk)
			}
			assertNoTempOrphan(t, root)
		})
	}
}

// TestWriteAtomicReplaceAt_HookNotCalledWhenStagingFails pins that the hook only ever observes a staged
// entry that is already durable: a write that fails before the fsync never reaches it.
func TestWriteAtomicReplaceAt_HookNotCalledWhenStagingFails(t *testing.T) {
	orig := syncFile
	t.Cleanup(func() { syncFile = orig })
	syncFile = func(*os.File) error { return syscall.EIO }

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "out.txt"), []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	parent := openTestDir(t, root)

	called := false
	_, _, _, err := WriteAtomicReplaceAt(parent, "out.txt", []byte("x"), 0o644, nil, func(string, []byte, os.FileMode) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("WriteAtomicReplaceAt succeeded despite a forced sync failure")
	}
	if called {
		t.Fatal("the pre-publish hook ran even though the staged entry was never made durable")
	}
	assertNoTempOrphan(t, root)
}

func TestWriteAtomicReplaceAt_RejectsNonSingleComponentName(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	parent := openTestDir(t, root)

	for _, name := range []string{"", ".", "..", "sub/out.txt", "/abs"} {
		t.Run("name="+name, func(t *testing.T) {
			step, _, _, err := WriteAtomicReplaceAt(parent, name, []byte("x"), 0o644, nil, nil)
			if !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("err = %v, want EINVAL for %q", err, name)
			}
			if step != WriteStep {
				t.Fatalf("step = %q, want %q", step, WriteStep)
			}
		})
	}
}

func TestWriteAtomicReplaceAt_NonDirectoryParent(t *testing.T) {
	root := t.TempDir()
	fpath := filepath.Join(root, "f")
	if err := os.WriteFile(fpath, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	f, err := os.Open(fpath)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer f.Close()

	step, _, _, err := WriteAtomicReplaceAt(f, "out.txt", []byte("x"), 0o644, nil, nil)
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("err = %v, want ENOTDIR", err)
	}
	if step != ParentSyncStep {
		t.Fatalf("step = %q, want %q", step, ParentSyncStep)
	}
}

func TestWriteAtomicReplaceAt_RefusesTargetReplacedBeforePublish(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "doc.txt")
	stash := filepath.Join(root, "stashed.txt")
	if err := os.WriteFile(target, []byte("planned original"), 0o644); err != nil {
		t.Fatalf("seed the planned target: %v", err)
	}
	planned, serr := os.Stat(target)
	if serr != nil {
		t.Fatalf("stat the planned target: %v", serr)
	}
	parent := openTestDir(t, root)

	t.Cleanup(SetBeforePublishRenameForTest(func() {
		if err := os.Rename(target, stash); err != nil {
			t.Fatalf("move the planned target aside: %v", err)
		}
		if err := os.WriteFile(target, []byte("someone else's file"), 0o644); err != nil {
			t.Fatalf("drop the replacement at the target name: %v", err)
		}
	}))

	step, _, _, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o644, planned, nil)
	if !errors.Is(err, ErrTargetIdentityChanged) {
		t.Fatalf("err = %v, want ErrTargetIdentityChanged", err)
	}
	if step != RenameStep {
		t.Fatalf("step = %q, want %q", step, RenameStep)
	}
	if got := readBack(t, target); string(got) != "someone else's file" {
		t.Fatalf("the replacement = %q, want it untouched", got)
	}
	if got := readBack(t, stash); string(got) != "planned original" {
		t.Fatalf("the planned original = %q, want it untouched", got)
	}
	assertNoTempOrphan(t, root)
}

func TestWriteAtomicReplaceAt_PublishesWhenTargetIdentityMatches(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "doc.txt")
	if err := os.WriteFile(target, []byte("planned original"), 0o600); err != nil {
		t.Fatalf("seed the planned target: %v", err)
	}
	planned, serr := os.Stat(target)
	if serr != nil {
		t.Fatalf("stat the planned target: %v", serr)
	}
	parent := openTestDir(t, root)

	if step, cat, _, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o600, planned, nil); err != nil {
		t.Fatalf("WriteAtomicReplaceAt error: %v (step=%q cat=%q)", err, step, cat)
	}
	if got := readBack(t, target); string(got) != "planned replacement" {
		t.Fatalf("contents = %q, want %q", got, "planned replacement")
	}
	info, ierr := os.Stat(target)
	if ierr != nil {
		t.Fatalf("stat the published target: %v", ierr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("published mode = %v, want 0600", info.Mode().Perm())
	}
	assertNoTempOrphan(t, root)
}

func TestWriteAtomicReplaceAt_RefusesTargetRemovedBeforePublish(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "doc.txt")
	if err := os.WriteFile(target, []byte("planned original"), 0o644); err != nil {
		t.Fatalf("seed the planned target: %v", err)
	}
	planned, serr := os.Stat(target)
	if serr != nil {
		t.Fatalf("stat the planned target: %v", serr)
	}
	parent := openTestDir(t, root)

	t.Cleanup(SetBeforePublishRenameForTest(func() {
		if err := os.Remove(target); err != nil {
			t.Fatalf("remove the planned target: %v", err)
		}
	}))

	_, _, _, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o644, planned, nil)
	if !errors.Is(err, ErrTargetIdentityChanged) {
		t.Fatalf("err = %v, want ErrTargetIdentityChanged", err)
	}
	if _, serr := os.Stat(target); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("the removed target came back (stat err = %v); the refused publish wrote it", serr)
	}
	assertNoTempOrphan(t, root)
}

// TestWriteAtomicReplaceAt_ReportsPublishedIdentity pins what a caller needs in order to undo its own
// publish safely: the reported identity is the inode now answering to the target name, and it is
// reported even when the parent fsync fails, because that failure lands after the bytes are already
// visible and so is not a reason for the caller to believe nothing was published.
func TestWriteAtomicReplaceAt_ReportsPublishedIdentity(t *testing.T) {
	cases := []struct {
		name     string
		failSync bool
	}{
		{name: "clean publish"},
		{name: "parent sync fails after publication", failSync: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "doc.txt")
			if err := os.WriteFile(target, []byte("planned original"), 0o644); err != nil {
				t.Fatalf("seed the planned target: %v", err)
			}
			planned, serr := os.Stat(target)
			if serr != nil {
				t.Fatalf("stat the planned target: %v", serr)
			}
			parent := openTestDir(t, root)

			if tc.failSync {
				t.Cleanup(SetSyncDirForTest(func(*os.File) error { return errors.New("forced parent sync failure") }))
			}

			_, _, published, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o644, planned, nil)
			if (err != nil) != tc.failSync {
				t.Fatalf("err = %v with failSync = %v", err, tc.failSync)
			}
			if published == nil {
				t.Fatal("published = nil, want the identity of the inode publication made visible")
			}
			info, ierr := os.Stat(target)
			if ierr != nil {
				t.Fatalf("stat the published target: %v", ierr)
			}
			if !os.SameFile(published, info) {
				t.Fatal("the reported identity is not the file now at the target name")
			}
			if got := readBack(t, target); string(got) != "planned replacement" {
				t.Fatalf("contents = %q, want %q", got, "planned replacement")
			}
			assertNoTempOrphan(t, root)
		})
	}
}

// tempEntries lists the sibling temporary entries left in dir, so a test can distinguish an entry a
// publish retained from one it should have cleaned up.
func tempEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			names = append(names, e.Name())
		}
	}
	return names
}

// otherTempEntry names the temporary entry in dir that is not known, so a test running inside a publish
// can address the staged name without the publish exposing it: only the recovery name is pinnable.
func otherTempEntry(t *testing.T, dir, known string) string {
	t.Helper()
	for _, name := range tempEntries(t, dir) {
		if name != known {
			return name
		}
	}
	t.Fatalf("no temporary entry beside %q", known)
	return ""
}

func TestWriteAtomicReplaceAt_PreservesOccupiedRecoveryName(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "doc.txt")
	stash := filepath.Join(root, "stashed.txt")
	occupiedName := "doc.txt.tmp-00000000cafebabe"
	occupied := filepath.Join(root, occupiedName)
	if err := os.WriteFile(target, []byte("planned original"), 0o644); err != nil {
		t.Fatalf("seed the planned target: %v", err)
	}
	if err := os.WriteFile(occupied, []byte("an unrelated writer's file"), 0o644); err != nil {
		t.Fatalf("occupy the recovery name: %v", err)
	}
	planned, serr := os.Stat(target)
	if serr != nil {
		t.Fatalf("stat the planned target: %v", serr)
	}
	parent := openTestDir(t, root)

	choices := 0
	t.Cleanup(SetRecoveryNameForTest(func(basename string) (string, error) {
		choices++
		if choices == 1 {
			return occupiedName, nil
		}
		return tempName(basename)
	}))
	t.Cleanup(SetBeforePublishRenameForTest(func() {
		if err := os.Rename(target, stash); err != nil {
			t.Fatalf("move the planned target aside: %v", err)
		}
		if err := os.WriteFile(target, []byte("someone else's file"), 0o644); err != nil {
			t.Fatalf("drop the replacement at the target name: %v", err)
		}
	}))

	step, _, published, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o644, planned, nil)
	if !errors.Is(err, ErrTargetIdentityChanged) {
		t.Fatalf("err = %v, want ErrTargetIdentityChanged", err)
	}
	if step != RenameStep {
		t.Fatalf("step = %q, want %q", step, RenameStep)
	}
	if published != nil {
		t.Fatal("published is non-nil, but the changed target refused the publish")
	}
	if choices < 2 {
		t.Fatalf("recovery-name choices = %d, want the occupied name to have been rejected", choices)
	}
	if got := readBack(t, occupied); string(got) != "an unrelated writer's file" {
		t.Fatalf("the occupied recovery entry = %q, want the unrelated writer's file intact", got)
	}
	if got := readBack(t, target); string(got) != "someone else's file" {
		t.Fatalf("the replacement = %q, want it restored", got)
	}
	if got := readBack(t, stash); string(got) != "planned original" {
		t.Fatalf("the planned original = %q, want it untouched", got)
	}
	if names := tempEntries(t, root); !reflect.DeepEqual(names, []string{occupiedName}) {
		t.Fatalf("temporary entries = %v, want only the unrelated writer's %q", names, occupiedName)
	}
}

func TestWriteAtomicReplaceAt_RefusesWhenNoRecoveryNameIsFree(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "doc.txt")
	occupiedName := "doc.txt.tmp-00000000cafebabe"
	occupied := filepath.Join(root, occupiedName)
	if err := os.WriteFile(target, []byte("planned original"), 0o644); err != nil {
		t.Fatalf("seed the planned target: %v", err)
	}
	if err := os.WriteFile(occupied, []byte("an unrelated writer's file"), 0o644); err != nil {
		t.Fatalf("occupy the recovery name: %v", err)
	}
	planned, serr := os.Stat(target)
	if serr != nil {
		t.Fatalf("stat the planned target: %v", serr)
	}
	parent := openTestDir(t, root)

	t.Cleanup(SetRecoveryNameForTest(func(string) (string, error) { return occupiedName, nil }))

	step, _, published, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o644, planned, nil)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err = %v, want a refusal wrapping fs.ErrExist", err)
	}
	if step != RenameStep {
		t.Fatalf("step = %q, want %q", step, RenameStep)
	}
	if published != nil {
		t.Fatal("published is non-nil, but no recovery name could be reserved")
	}
	if got := readBack(t, occupied); string(got) != "an unrelated writer's file" {
		t.Fatalf("the occupied recovery entry = %q, want the unrelated writer's file intact", got)
	}
	if got := readBack(t, target); string(got) != "planned original" {
		t.Fatalf("the target = %q, want it untouched", got)
	}
	if names := tempEntries(t, root); !reflect.DeepEqual(names, []string{occupiedName}) {
		t.Fatalf("temporary entries = %v, want only the unrelated writer's %q", names, occupiedName)
	}
}

// TestWriteAtomicReplaceAt_RetainsScratchEntryTakenAfterPublication pins that a successful publish
// never removes one of its scratch names on the strength of the name alone: a writer who takes either
// name after the bytes are visible keeps their file, and the publish still reports success, because
// reporting a completed publish as a failure is the worse error.
func TestWriteAtomicReplaceAt_RetainsScratchEntryTakenAfterPublication(t *testing.T) {
	cases := []struct {
		name         string
		takeTheAside bool
	}{
		{name: "staged name taken"},
		{name: "aside name taken", takeTheAside: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "doc.txt")
			asideName := "doc.txt.tmp-00000000cafebabe"
			if err := os.WriteFile(target, []byte("planned original"), 0o644); err != nil {
				t.Fatalf("seed the planned target: %v", err)
			}
			planned, serr := os.Stat(target)
			if serr != nil {
				t.Fatalf("stat the planned target: %v", serr)
			}
			parent := openTestDir(t, root)

			t.Cleanup(SetRecoveryNameForTest(func(string) (string, error) { return asideName, nil }))

			var taken string
			t.Cleanup(SetBeforeCleanupForTest(func() {
				taken = asideName
				if !tc.takeTheAside {
					taken = otherTempEntry(t, root, asideName)
				}
				intruder := filepath.Join(root, "intruder.txt")
				if err := os.WriteFile(intruder, []byte("an unrelated writer's file"), 0o644); err != nil {
					t.Fatalf("seed the unrelated writer's file: %v", err)
				}
				if err := os.Rename(intruder, filepath.Join(root, taken)); err != nil {
					t.Fatalf("take the scratch name %q: %v", taken, err)
				}
			}))

			step, _, published, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o644, planned, nil)
			if err != nil {
				t.Fatalf("err = %v, want the publish to succeed", err)
			}
			if step != "" {
				t.Fatalf("step = %q, want no failed step", step)
			}
			if published == nil {
				t.Fatal("published is nil, but the staged bytes were made visible")
			}
			if got := readBack(t, target); string(got) != "planned replacement" {
				t.Fatalf("the target = %q, want the published bytes", got)
			}
			if got := readBack(t, filepath.Join(root, taken)); string(got) != "an unrelated writer's file" {
				t.Fatalf("the taken scratch entry = %q, want the unrelated writer's file intact", got)
			}
			if names := tempEntries(t, root); !reflect.DeepEqual(names, []string{taken}) {
				t.Fatalf("temporary entries = %v, want only the taken %q", names, taken)
			}
		})
	}
}

// TestWriteAtomicReplaceAt_RetainsScratchEntryTakenBeforeRestoreCleanup pins the same rule on the
// refused path, where the publish is putting the displaced entry back: the taken name is retained and
// the refusal reports an unreconciled publish naming it, instead of deleting the other writer's file.
func TestWriteAtomicReplaceAt_RetainsScratchEntryTakenBeforeRestoreCleanup(t *testing.T) {
	cases := []struct {
		name         string
		takeTheAside bool
	}{
		{name: "staged name taken"},
		{name: "aside name taken", takeTheAside: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "doc.txt")
			stash := filepath.Join(root, "stashed.txt")
			asideName := "doc.txt.tmp-00000000cafebabe"
			if err := os.WriteFile(target, []byte("planned original"), 0o644); err != nil {
				t.Fatalf("seed the planned target: %v", err)
			}
			planned, serr := os.Stat(target)
			if serr != nil {
				t.Fatalf("stat the planned target: %v", serr)
			}
			parent := openTestDir(t, root)

			t.Cleanup(SetRecoveryNameForTest(func(string) (string, error) { return asideName, nil }))
			t.Cleanup(SetBeforePublishRenameForTest(func() {
				if err := os.Rename(target, stash); err != nil {
					t.Fatalf("move the planned target aside: %v", err)
				}
				if err := os.WriteFile(target, []byte("someone else's file"), 0o644); err != nil {
					t.Fatalf("drop the replacement at the target name: %v", err)
				}
			}))

			var taken string
			t.Cleanup(SetBeforeCleanupForTest(func() {
				taken = asideName
				if !tc.takeTheAside {
					taken = otherTempEntry(t, root, asideName)
				}
				intruder := filepath.Join(root, "intruder.txt")
				if err := os.WriteFile(intruder, []byte("an unrelated writer's file"), 0o644); err != nil {
					t.Fatalf("seed the unrelated writer's file: %v", err)
				}
				if err := os.Rename(intruder, filepath.Join(root, taken)); err != nil {
					t.Fatalf("take the scratch name %q: %v", taken, err)
				}
			}))

			step, _, published, err := WriteAtomicReplaceAt(parent, "doc.txt", []byte("planned replacement"), 0o644, planned, nil)
			if !errors.Is(err, ErrPublishUnreconciled) {
				t.Fatalf("err = %v, want ErrPublishUnreconciled", err)
			}
			if !strings.Contains(err.Error(), taken) {
				t.Fatalf("err = %v, want it to name the retained entry %q", err, taken)
			}
			if step != RenameStep {
				t.Fatalf("step = %q, want %q", step, RenameStep)
			}
			if published != nil {
				t.Fatal("published is non-nil, but the changed target refused the publish")
			}
			if got := readBack(t, filepath.Join(root, taken)); string(got) != "an unrelated writer's file" {
				t.Fatalf("the taken scratch entry = %q, want the unrelated writer's file intact", got)
			}
			if got := readBack(t, stash); string(got) != "planned original" {
				t.Fatalf("the planned original = %q, want it untouched", got)
			}
			if names := tempEntries(t, root); !reflect.DeepEqual(names, []string{taken}) {
				t.Fatalf("temporary entries = %v, want only the taken %q", names, taken)
			}
			if tc.takeTheAside {
				if _, statErr := os.Lstat(target); !errors.Is(statErr, fs.ErrNotExist) {
					t.Fatalf("lstat the target = %v, want it absent: the entry moved aside was destroyed by the other writer, so there was nothing to put back", statErr)
				}
				return
			}
			if got := readBack(t, target); string(got) != "someone else's file" {
				t.Fatalf("the target = %q, want the displaced entry put back", got)
			}
		})
	}
}

// replaceEntry destroys whatever answers to name in dir and puts an unrelated writer's file there, so a
// test can stand in for another process taking a scratch or target name inside a cleanup window.
func replaceEntry(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %q: %v", name, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %q: %v", name, err)
	}
}

// TestWriteAtomicReplaceAt_StagingFailureRetainsReplacedTempEntry drives the failure the staging
// cleanup exists for — the fsync of the temporary entry fails — while another writer takes that
// temporary name from inside the seam. The cleanup must not delete their file.
func TestWriteAtomicReplaceAt_StagingFailureRetainsReplacedTempEntry(t *testing.T) {
	const foreign = "ANOTHER WRITER'S FILE"

	root := t.TempDir()
	target := filepath.Join(root, "out.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	parent := openTestDir(t, root)

	sentinel := errors.New("forced temp sync failure")
	var staged string
	t.Cleanup(SetSyncFileForTest(func(f *os.File) error {
		staged = filepath.Base(f.Name())
		replaceEntry(t, root, staged, []byte(foreign))
		return sentinel
	}))

	step, _, published, err := WriteAtomicReplaceAt(parent, "out.txt", []byte("REPLACEMENT"), 0o644, nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the forced sentinel", err)
	}
	if !errors.Is(err, ErrPublishUnreconciled) {
		t.Fatalf("err = %v, want it to also report ErrPublishUnreconciled", err)
	}
	if !strings.Contains(err.Error(), staged) {
		t.Fatalf("err = %v, want it to name the retained entry %q", err, staged)
	}
	if step != WriteStep {
		t.Fatalf("step = %q, want %q", step, WriteStep)
	}
	if published != nil {
		t.Fatalf("published = %v, want nil for a staging failure", published)
	}
	if got := readBack(t, target); string(got) != "ORIGINAL" {
		t.Fatalf("target = %q, want the original bytes untouched", got)
	}
	if got := readBack(t, filepath.Join(root, staged)); string(got) != foreign {
		t.Fatalf("retained entry = %q, want the other writer's bytes %q", got, foreign)
	}
	if names := tempEntries(t, root); len(names) != 1 || names[0] != staged {
		t.Fatalf("temp entries = %v, want only the retained %q", names, staged)
	}
}

// TestWriteAtomicCreateAt_ParentSyncFailureRetainsReplacedTarget drives create's parent-directory sync
// failure, whose cleanup unpublishes the target, while another writer replaces that target from inside
// the seam. Create still reports failure, but the replacement survives.
func TestWriteAtomicCreateAt_ParentSyncFailureRetainsReplacedTarget(t *testing.T) {
	const foreign = "ANOTHER WRITER'S FILE"

	root := t.TempDir()
	parent := openTestDir(t, root)

	sentinel := errors.New("forced parent sync failure")
	t.Cleanup(SetSyncDirForTest(func(*os.File) error {
		replaceEntry(t, root, "new.txt", []byte(foreign))
		return sentinel
	}))

	step, _, _, err := WriteAtomicCreateAt(parent, "new.txt", []byte("CREATED"), 0o644)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the forced sentinel", err)
	}
	if !errors.Is(err, ErrPublishUnreconciled) {
		t.Fatalf("err = %v, want it to also report ErrPublishUnreconciled", err)
	}
	if !strings.Contains(err.Error(), "new.txt") {
		t.Fatalf("err = %v, want it to name the retained target", err)
	}
	if step != ParentSyncStep {
		t.Fatalf("step = %q, want %q", step, ParentSyncStep)
	}
	if got := readBack(t, filepath.Join(root, "new.txt")); string(got) != foreign {
		t.Fatalf("target = %q, want the other writer's bytes %q", got, foreign)
	}
	assertNoTempOrphan(t, root)
}

// TestWriteAtomicCreateAt_ReportsThePublishedIdentityOnEveryVisibleOutcome pins the return a caller
// needs to reconcile or take back its own create: the inode it published, not the name, which another
// writer can occupy the instant the call returns.
func TestWriteAtomicCreateAt_ReportsThePublishedIdentityOnEveryVisibleOutcome(t *testing.T) {
	t.Run("successful publish", func(t *testing.T) {
		root := t.TempDir()
		parent := openTestDir(t, root)

		_, _, published, err := WriteAtomicCreateAt(parent, "new.txt", []byte("CREATED"), 0o644)
		if err != nil {
			t.Fatalf("WriteAtomicCreateAt: %v", err)
		}
		info, serr := os.Stat(filepath.Join(root, "new.txt"))
		if serr != nil {
			t.Fatalf("stat published target: %v", serr)
		}
		if !os.SameFile(published, info) {
			t.Fatal("published identity does not name the inode now at the target")
		}
	})

	t.Run("visible parent-sync failure", func(t *testing.T) {
		root := t.TempDir()
		parent := openTestDir(t, root)

		var seen os.FileInfo
		sentinel := errors.New("forced parent sync failure")
		t.Cleanup(SetSyncDirForTest(func(*os.File) error {
			info, serr := os.Stat(filepath.Join(root, "new.txt"))
			if serr != nil {
				t.Errorf("stat inside the sync seam: %v", serr)
			}
			seen = info
			return sentinel
		}))

		step, _, published, err := WriteAtomicCreateAt(parent, "new.txt", []byte("CREATED"), 0o644)
		if !errors.Is(err, sentinel) || step != ParentSyncStep {
			t.Fatalf("err = %v step = %q, want the forced parent-sync failure", err, step)
		}
		if published == nil {
			t.Fatal("published identity is nil, but the bytes were visible before the compensating removal")
		}
		if !os.SameFile(published, seen) {
			t.Fatal("published identity does not name the inode that was visible at the target")
		}
	})

	t.Run("refused publish", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("EXISTING"), 0o644); err != nil {
			t.Fatalf("seed target: %v", err)
		}
		parent := openTestDir(t, root)

		step, _, published, err := WriteAtomicCreateAt(parent, "new.txt", []byte("CREATED"), 0o644)
		if err == nil || step != LinkStep {
			t.Fatalf("err = %v step = %q, want the no-replace publish to refuse", err, step)
		}
		if published != nil {
			t.Fatalf("published = %v, want nil when nothing became visible", published)
		}
	})
}
