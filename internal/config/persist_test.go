// Unit tests for Persist: the shared lock/re-read/merge/write chokepoint for permission and model settings writes.
package config

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/trust"
)

// folderEntry builds a direct folder-grant permission entry for persistence tests.
func folderEntry(subject, pathScope string) permissions.PermissionEntry {
	return permissions.PermissionEntry{Kind: "direct", Subject: subject, PathScope: pathScope, GrantKind: "folder"}
}

func setAcquireLockAt(t *testing.T, fn func(*os.File, string, time.Duration) (func(), locks.LockReason, error)) {
	t.Helper()
	orig := acquireLock
	t.Cleanup(func() { acquireLock = orig })
	acquireLock = fn
}

func setAcquireLock(t *testing.T, fn func(string, time.Duration) (func(), locks.LockReason, error)) {
	t.Helper()
	setAcquireLockAt(t, func(parent *os.File, name string, timeout time.Duration) (func(), locks.LockReason, error) {
		return fn(filepath.Join(parent.Name(), name), timeout)
	})
}

func setRereadSettings(t *testing.T, fn func(*os.File, string) (fsutil.FileSnapshot, map[string]any, LoadFailure, error)) {
	t.Helper()
	orig := rereadSettings
	t.Cleanup(func() { rereadSettings = orig })
	rereadSettings = fn
}

func setMergeWrite(t *testing.T, fn func(*os.File, string, fsutil.FileSnapshot, string, any) (fsutil.AtomicWriteStep, fserrors.Category, error)) {
	t.Helper()
	orig := mergeWrite
	t.Cleanup(func() { mergeWrite = orig })
	mergeWrite = fn
}

func setBeforeParentSegment(t *testing.T, fn func(string)) {
	t.Helper()
	orig := beforeParentSegment
	t.Cleanup(func() { beforeParentSegment = orig })
	beforeParentSegment = fn
}

// failIfMergeCalled installs a mergeWrite seam that records whether it ran, so a
// skip-write branch can assert the merge never happened. The returned pointer is
// checked after Persist returns.
func failIfMergeCalled(t *testing.T) *bool {
	t.Helper()
	called := false
	setMergeWrite(t, func(*os.File, string, fsutil.FileSnapshot, string, any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		called = true
		return "", "", nil
	})
	return &called
}

func TestPersist_WritesLandUnchangedAndNeverTouchTheTrustStore(t *testing.T) {
	home, root, target := trustedProjectSettings(t)
	store := trust.StorePath(home)
	beforeContent := readAt(t, store)
	beforeStat, err := os.Stat(store)
	if err != nil {
		t.Fatalf("stat trust store: %v", err)
	}

	reference := filepath.Join(t.TempDir(), "settings.yaml")
	writeAt(t, reference, readAt(t, target))

	for _, step := range []struct {
		name  string
		key   string
		value any
	}{
		{"grant", KeyPermissions, folderEntry("ls", "/work")},
		{"blocked path", blockedPathsKey, BlockedPathAdd(home, filepath.Join(root, "secret"), "")},
		{"model.active", KeyModelActive, "sonnet"},
	} {
		reason, cat, perr := Persist(target, step.key, step.value)
		if reason != ReasonNone || cat != "" || perr != nil {
			t.Fatalf("%s: Persist = (%q, %q, %v), want a clean write", step.name, reason, cat, perr)
		}
		if _, _, rerr := RewriteKey(reference, step.key, step.value); rerr != nil {
			t.Fatalf("%s: reference RewriteKey: %v", step.name, rerr)
		}
		if got, want := readAt(t, target), readAt(t, reference); got != want {
			t.Fatalf("%s: settings on disk = %q, want the bytes a plain write produces: %q", step.name, got, want)
		}
	}

	afterStat, err := os.Stat(store)
	if err != nil {
		t.Fatalf("stat trust store after the writes: %v", err)
	}
	if after := readAt(t, store); after != beforeContent {
		t.Fatalf("trust store content changed:\n got=%q\nwant=%q", after, beforeContent)
	}
	if !afterStat.ModTime().Equal(beforeStat.ModTime()) {
		t.Fatalf("trust store mtime = %v, want it untouched at %v", afterStat.ModTime(), beforeStat.ModTime())
	}
}

func trustedProjectSettings(t *testing.T) (home, root, target string) {
	t.Helper()
	home = t.TempDir()
	root, err := sessions.CanonicalizeFolder(t.TempDir())
	if err != nil {
		t.Fatalf("canonicalize project root: %v", err)
	}
	vcsDir := filepath.Join(root, ".codemeld", "vcs")
	if err := os.MkdirAll(vcsDir, 0o755); err != nil {
		t.Fatalf("mkdir vcs templates: %v", err)
	}
	writeAt(t, filepath.Join(vcsDir, "git.yaml"), "name: git\n")
	target = filepath.Join(root, ".codemeld", "settings.yaml")
	writeAt(t, target, "model: {}\n")
	if err := trust.Record(home, root); err != nil {
		t.Fatalf("record trust: %v", err)
	}
	return home, root, target
}

// TestPersist_AbsentFile_CreatesAndAppendsPermission exercises the full
// sub-sequence end to end with real helpers: parent-dir ensure, sidecar-lock
// acquisition, locked re-read (which treats the absent settings file as an empty
// document), merge, and the atomic write that creates the settings file
// at mode 0600.
func TestPersist_AbsentFile_CreatesAndAppendsPermission(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "settings.yaml")

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if err != nil {
		t.Fatalf("Persist error: %v (reason=%q cat=%q)", err, reason, cat)
	}
	if reason != ReasonNone {
		t.Fatalf("reason = %q, want %q", reason, ReasonNone)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty on success", cat)
	}

	content := readAt(t, target)
	if !strings.Contains(content, "subject: ls") {
		t.Fatalf("file does not contain the appended entry:\n%s", content)
	}

	if os.Geteuid() != 0 {
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("stat created file: %v", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("created file mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

// TestPersist_AbsentFile_CreatesModelActive confirms the same chokepoint handles
// model.active create-from-absent writes (create-file-if-absent).
func TestPersist_AbsentFile_CreatesModelActive(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	reason, _, err := Persist(target, KeyModelActive, modelSelection("openai", "gpt-x", "medium"))
	if err != nil || reason != ReasonNone {
		t.Fatalf("Persist model.active = (%q, %v), want (none, nil)", reason, err)
	}
	content := readAt(t, target)
	if !strings.Contains(content, "active:") || !strings.Contains(content, "gpt-x") {
		t.Fatalf("model.active not written:\n%s", content)
	}
}

// TestPersist_MalformedFile_SkipsWriteUnmodified is the special branch:
// a malformed on-disk file makes the locked re-read fail, so the merge is skipped
// and the file is left byte-for-byte untouched.
func TestPersist_MalformedFile_SkipsWriteUnmodified(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	const malformed = "permissions: [unterminated\n"
	writeAt(t, target, malformed)

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonRereadParseError {
		t.Fatalf("reason = %q, want %q", reason, ReasonRereadParseError)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty for reread_parse_error", cat)
	}
	if err == nil {
		t.Fatalf("err is nil, want the parse error")
	}
	if got := readAt(t, target); got != malformed {
		t.Fatalf("file was modified by a skipped write:\ngot:  %q\nwant: %q", got, malformed)
	}
	// No temp orphan must be left behind by the skipped write.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("skipped write left a temp orphan: %s", e.Name())
		}
	}
}

// TestPersist_RewriteStepMapping covers the RewriteKey (step, cat, err) → reason
// mapping for every step the merge can report, plus category handling: write
// family steps propagate the category unchanged (Done-when: category propagated
// by RewriteKey), the I/O-shaped LoadStep maps to reread_io_error keeping its
// category, and the parse-shaped LoadStep maps to reread_parse_error with no
// category.
func TestPersist_RewriteStepMapping(t *testing.T) {
	sentinel := errors.New("forced merge failure")
	ioErr := &os.PathError{Op: "read", Path: "x", Err: syscall.EIO}

	cases := []struct {
		name       string
		step       fsutil.AtomicWriteStep
		cat        fserrors.Category
		err        error
		wantReason PersistReason
		wantCat    fserrors.Category
	}{
		{"write", fsutil.WriteStep, fserrors.NoSpace, sentinel, ReasonWriteError, fserrors.NoSpace},
		{"rename", fsutil.RenameStep, fserrors.ReadOnlyFS, sentinel, ReasonRenameError, fserrors.ReadOnlyFS},
		{"parent_sync", fsutil.ParentSyncStep, fserrors.IOError, sentinel, ReasonParentDirError, fserrors.IOError},
		{"load_io", fsutil.LoadStep, fserrors.IOError, ioErr, ReasonRereadIOError, fserrors.IOError},
		{"load_parse", fsutil.LoadStep, fserrors.IOError, sentinel, ReasonRereadParseError, ""},
		{"success", "", "", nil, ReasonNone, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "settings.yaml")
			writeAt(t, target, "") // existing, empty, schema-valid: re-read passes

			setMergeWrite(t, func(*os.File, string, fsutil.FileSnapshot, string, any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
				return tc.step, tc.cat, tc.err
			})

			reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
			if cat != tc.wantCat {
				t.Fatalf("cat = %q, want %q", cat, tc.wantCat)
			}
			if tc.err == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			} else if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want wrap of %v", err, tc.err)
			}
		})
	}
}

// TestPersist_LockTimeout_SkipsWrite asserts a lock timeout returns lock_timeout
// with no category, never reaches the merge, and leaves the file untouched.
func TestPersist_LockTimeout_SkipsWrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	const seed = "model:\n  active:\n    provider: openai\n    id: gpt-x\n    effort: medium\n"
	writeAt(t, target, seed)

	setAcquireLock(t, func(string, time.Duration) (func(), locks.LockReason, error) {
		return nil, locks.ReasonLockTimeout, context.DeadlineExceeded
	})
	merged := failIfMergeCalled(t)

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonLockTimeout {
		t.Fatalf("reason = %q, want %q", reason, ReasonLockTimeout)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty for lock_timeout", cat)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if *merged {
		t.Fatalf("merge ran despite lock timeout")
	}
	if got := readAt(t, target); got != seed {
		t.Fatalf("file modified on lock timeout:\n%s", got)
	}
}

// TestPersist_LockAcquireError maps a non-timeout lock-syscall failure to
// lock_acquire_error and derives the category from the underlying errno.
func TestPersist_LockAcquireError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, "")

	lockErr := &os.PathError{Op: "flock", Path: target, Err: syscall.EACCES}
	setAcquireLock(t, func(string, time.Duration) (func(), locks.LockReason, error) {
		return nil, locks.ReasonLockAcquireError, lockErr
	})
	merged := failIfMergeCalled(t)

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonLockAcquireError {
		t.Fatalf("reason = %q, want %q", reason, ReasonLockAcquireError)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
	if !errors.Is(err, lockErr) {
		t.Fatalf("err = %v, want wrap of %v", err, lockErr)
	}
	if *merged {
		t.Fatalf("merge ran despite lock acquire failure")
	}
}

// TestPersist_AbsentFile_LockAcquireError asserts that when the target is absent and
// the sidecar lock fails to acquire, the failure surfaces as lock_acquire_error, not
// write_error/rename_error. Per sub-sequence 1b, a create-and-lock failure on
// the sidecar maps to the lock-acquisition path; the settings file is created later by
// RewriteKey, so the merge never runs and no write step can fail here.
func TestPersist_AbsentFile_LockAcquireError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml") // absent: no seed file

	lockErr := &os.PathError{Op: "flock", Path: target, Err: syscall.EACCES}
	setAcquireLock(t, func(string, time.Duration) (func(), locks.LockReason, error) {
		return nil, locks.ReasonLockAcquireError, lockErr
	})
	merged := failIfMergeCalled(t)

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonLockAcquireError {
		t.Fatalf("reason = %q, want %q", reason, ReasonLockAcquireError)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
	if !errors.Is(err, lockErr) {
		t.Fatalf("err = %v, want wrap of %v", err, lockErr)
	}
	if *merged {
		t.Fatalf("merge ran despite lock acquire failure on absent target")
	}
}

// TestPersist_RereadIOError_SkipsWrite covers an OS-level re-read failure under
// the lock: reread_io_error with the categorized errno, and the merge skipped.
func TestPersist_RereadIOError_SkipsWrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	const seed = "permissions: []\n"
	writeAt(t, target, seed)

	ioErr := &os.PathError{Op: "open", Path: target, Err: syscall.EACCES}
	setRereadSettings(t, func(*os.File, string) (fsutil.FileSnapshot, map[string]any, LoadFailure, error) {
		return fsutil.FileSnapshot{}, nil, UnreadableFile, ioErr
	})
	merged := failIfMergeCalled(t)

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonRereadIOError {
		t.Fatalf("reason = %q, want %q", reason, ReasonRereadIOError)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
	if !errors.Is(err, ioErr) {
		t.Fatalf("err = %v, want wrap of %v", err, ioErr)
	}
	if *merged {
		t.Fatalf("merge ran despite re-read I/O failure")
	}
	if got := readAt(t, target); got != seed {
		t.Fatalf("file modified on re-read I/O failure:\n%s", got)
	}
}

// TestPersist_RereadSchemaValidation_MapsToParseError confirms a schema-validation
// re-read failure is classified as reread_parse_error and skips the write.
func TestPersist_RereadSchemaValidation_MapsToParseError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, "")

	schemaErr := errors.New("schema violation")
	setRereadSettings(t, func(*os.File, string) (fsutil.FileSnapshot, map[string]any, LoadFailure, error) {
		return fsutil.FileSnapshot{}, nil, SchemaValidationError, schemaErr
	})
	merged := failIfMergeCalled(t)

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonRereadParseError {
		t.Fatalf("reason = %q, want %q", reason, ReasonRereadParseError)
	}
	if cat != "" {
		t.Fatalf("cat = %q, want empty for reread_parse_error", cat)
	}
	if !errors.Is(err, schemaErr) {
		t.Fatalf("err = %v, want wrap of %v", err, schemaErr)
	}
	if *merged {
		t.Fatalf("merge ran despite schema-validation failure")
	}
}

// TestPersist_ParentDirError maps a parent path that is a regular file, not a
// directory, to parent_dir_error before any lock or write is attempted.
func TestPersist_ParentDirError(t *testing.T) {
	dir := t.TempDir()
	fileAsParent := filepath.Join(dir, "notadir")
	writeAt(t, fileAsParent, "x")
	target := filepath.Join(fileAsParent, "settings.yaml")

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonParentDirError {
		t.Fatalf("reason = %q, want %q", reason, ReasonParentDirError)
	}
	if cat == "" {
		t.Fatalf("cat is empty, want a categorized errno for parent_dir_error")
	}
	if err == nil {
		t.Fatalf("err is nil, want the ENOTDIR error")
	}
}

// TestPersist_AbsentFileWriteError covers a write failure on the create-from-absent
// path: the sidecar lock is taken, the locked re-read treats the missing settings
// file as empty, then RewriteKey's atomic write (step 4) fails on a
// forced fsync error before any rename. Because the lock never materializes the
// settings file — only a successful RewriteKey rename does — the settings file is left
// absent and no temp orphan remains.
func TestPersist_AbsentFileWriteError(t *testing.T) {
	sentinel := errors.New("forced merge sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonWriteError {
		t.Fatalf("reason = %q, want %q", reason, ReasonWriteError)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrap of %v", err, sentinel)
	}
	// The lock never materializes the settings file; the failed atomic write
	// renamed nothing, so the settings file stays absent.
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("settings file should be absent after a failed create, stat err = %v", statErr)
	}
	// The failed atomic write must clean up its sibling temp file.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("failed write left a temp orphan: %s", e.Name())
		}
	}
}

// TestPersist_UnlocksOnWriteFailure proves Persist releases the sidecar lock when
// the merge fails. It asserts two things, because either alone is insufficient:
//
//   - The release function Persist was handed for targetPath+".lock" is actually
//     invoked. The acquireLock seam wraps the real locks.AcquireAt (so a genuine
//     flock is still taken on the sidecar) but records whether release ran.
//   - The exact sidecar path is re-acquirable afterward, confirming the lock Persist
//     holds is the sidecar (targetPath+".lock"), not targetPath itself.
func TestPersist_UnlocksOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, "")

	released := false
	setAcquireLockAt(t, func(parent *os.File, name string, d time.Duration) (func(), locks.LockReason, error) {
		rel, reason, err := locks.AcquireAt(parent, name, d)
		if reason != locks.ReasonNone {
			return rel, reason, err
		}
		return func() { released = true; rel() }, reason, nil
	})

	sentinel := errors.New("forced merge failure")
	setMergeWrite(t, func(*os.File, string, fsutil.FileSnapshot, string, any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		return fsutil.WriteStep, fserrors.NoSpace, sentinel
	})

	reason, _, _ := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonWriteError {
		t.Fatalf("reason = %q, want %q", reason, ReasonWriteError)
	}
	if !released {
		t.Fatalf("Persist did not release the sidecar lock after a write failure")
	}

	release, lr, err := locks.Acquire(target+".lock", 500*time.Millisecond)
	if err != nil || lr != locks.ReasonNone {
		t.Fatalf("sidecar lock not re-acquirable after write failure: (%q, %v)", lr, err)
	}
	release()
}

// TestPersist_ConcurrentWriters_BothSucceed runs two real Persist calls against
// the same file concurrently. The advisory lock must serialize their
// read-modify-write cycles so neither append clobbers the other (Done-when:
// exactly one holds the lock at a time; both writes survive).
func TestPersist_ConcurrentWriters_BothSucceed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, "") // pre-existing empty file: both writers exercise the locked merge path

	entries := []permissions.PermissionEntry{
		folderEntry("ls", "/work"),
		folderEntry("cat", "/work"),
	}

	var wg sync.WaitGroup
	results := make([]PersistReason, len(entries))
	errs := make([]error, len(entries))
	for i, e := range entries {
		wg.Add(1)
		go func(i int, e permissions.PermissionEntry) {
			defer wg.Done()
			results[i], _, errs[i] = Persist(target, KeyPermissions, e)
		}(i, e)
	}
	wg.Wait()

	for i := range entries {
		if errs[i] != nil || results[i] != ReasonNone {
			t.Fatalf("writer %d = (%q, %v), want (none, nil)", i, results[i], errs[i])
		}
	}

	content := readAt(t, target)
	for _, want := range []string{"subject: ls", "subject: cat"} {
		if !strings.Contains(content, want) {
			t.Fatalf("concurrent append lost an entry (missing %q):\n%s", want, content)
		}
	}
}

// TestPersist_ConcurrentWriters_AbsentFile_BothSucceed runs two real Persist calls
// against a target that does not exist before either goroutine starts. The sidecar
// lock serializes both cycles, so the first writer's RewriteKey creates the settings
// file and the second appends to it; neither append clobbers the other and the
// created file keeps mode 0600.
func TestPersist_ConcurrentWriters_AbsentFile_BothSucceed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml") // absent before either writer starts

	entries := []permissions.PermissionEntry{
		folderEntry("ls", "/work"),
		folderEntry("cat", "/work"),
	}

	var wg sync.WaitGroup
	results := make([]PersistReason, len(entries))
	errs := make([]error, len(entries))
	for i, e := range entries {
		wg.Add(1)
		go func(i int, e permissions.PermissionEntry) {
			defer wg.Done()
			results[i], _, errs[i] = Persist(target, KeyPermissions, e)
		}(i, e)
	}
	wg.Wait()

	for i := range entries {
		if errs[i] != nil || results[i] != ReasonNone {
			t.Fatalf("writer %d = (%q, %v), want (none, nil)", i, results[i], errs[i])
		}
	}

	content := readAt(t, target)
	for _, want := range []string{"subject: ls", "subject: cat"} {
		if !strings.Contains(content, want) {
			t.Fatalf("concurrent absent-file append lost an entry (missing %q):\n%s", want, content)
		}
	}

	if os.Geteuid() != 0 {
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("stat created file: %v", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("created file mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

// TestPersist_LocksSidecarNotSettingsFile is the sidecar-lock contract assertion
// (Done-when: lock acquired on targetPath+".lock", never on targetPath; the
// settings file is created by RewriteKey, not by the lock). The lock seam records
// the held directory and name it is handed and creates nothing, so a successful
// run proves both: the captured name is the sidecar in the target's parent, and
// the settings file that appears afterward came from RewriteKey's atomic write —
// not from lock acquisition.
func TestPersist_LocksSidecarNotSettingsFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml") // absent before the call

	var gotLockDir, gotLockName string
	setAcquireLockAt(t, func(parent *os.File, name string, _ time.Duration) (func(), locks.LockReason, error) {
		gotLockDir, gotLockName = parent.Name(), name
		return func() {}, locks.ReasonNone, nil
	})

	reason, _, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if err != nil || reason != ReasonNone {
		t.Fatalf("Persist = (%q, %v), want (none, nil)", reason, err)
	}
	if gotLockDir != dir || gotLockName != "settings.yaml.lock" {
		t.Fatalf("lock = (%q, %q), want sidecar settings.yaml.lock in %q", gotLockDir, gotLockName, dir)
	}
	// The settings file was created by RewriteKey under the lock.
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("settings file not created by RewriteKey: %v", statErr)
	}
	// The mocked lock created no sidecar, so its existence cannot explain the
	// settings file — proving lock acquisition does not materialize it.
	if _, statErr := os.Stat(target + ".lock"); !os.IsNotExist(statErr) {
		t.Fatalf("sidecar should not exist (mock lock created nothing), stat err = %v", statErr)
	}
}

// TestPersist_RereadAbsent_TreatedAsEmpty asserts the rule that an absent
// settings file under the held lock is an empty document, not a re-read failure:
// the locked re-read reports it as a non-existing snapshot with LoadOK, and the
// merge proceeds to create the file (step (2)). Contrast
// TestPersist_RereadIOError_SkipsWrite, where UnreadableFile maps to
// reread_io_error and skips.
func TestPersist_RereadAbsent_TreatedAsEmpty(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml") // absent

	var got fsutil.FileSnapshot
	var gotCat LoadFailure
	setRereadSettings(t, func(parent *os.File, path string) (fsutil.FileSnapshot, map[string]any, LoadFailure, error) {
		snap, raw, cat, err := readSettings(parent, path)
		got, gotCat = snap, cat
		return snap, raw, cat, err
	})

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonNone || cat != "" || err != nil {
		t.Fatalf("absent re-read = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}
	if got.Exists || gotCat != LoadOK {
		t.Fatalf("absent re-read = (exists=%v, %v), want (false, LoadOK)", got.Exists, gotCat)
	}
	content := readAt(t, target)
	if !strings.Contains(content, "subject: ls") {
		t.Fatalf("merge did not proceed for absent settings file:\n%s", content)
	}
}

// TestPersist_ConcurrentWriters_ThreePlus_NoLostUpdate is the sidecar-lock regression
// guard, made deterministic. It forces the exact interleaving the sidecar lock
// fixes rather than hoping the scheduler produces it:
//
//  1. A seed writer (bravo) completes a full create+rename with the real helpers,
//     so the settings file exists and its inode has been rename-replaced once.
//  2. The holder (alpha) acquires the sidecar lock and, via the mergeWrite seam,
//     completes its own atomic rename — replacing the settings inode again — then
//     stays inside the critical section still holding the lock (Persist's deferred
//     release has not run).
//  3. A late arrival (charlie) starts only after the holder's rename. While the
//     holder holds the lock, charlie must NOT reach its merge.
//
// Under the superseded lock-the-data-file contract, alpha's rename orphans the
// inode alpha locked, so charlie opens the fresh inode and takes an uncontended
// lock — entering its critical section and proving mutual exclusion broken (this
// test would then fail on the negative assertion). Because the lock lives on the
// stable sidecar inode, charlie blocks until alpha releases, and every entry
// survives. A two-writer test cannot reach this three-inode interleaving. Broader
// cross-process coverage lives in internal/integration/concurrent_persist_test.go.
func TestPersist_ConcurrentWriters_ThreePlus_NoLostUpdate(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	// (1) Seed writer completes a full create+rename with the real helpers, before
	// the seam is installed, so the settings inode is materialized and replaced.
	if reason, _, err := Persist(target, KeyPermissions, folderEntry("bravo", "/work")); err != nil || reason != ReasonNone {
		t.Fatalf("seed writer bravo = (%q, %v), want (none, nil)", reason, err)
	}

	holderRenamed := make(chan struct{}) // alpha finished its rename and still holds the lock
	releaseHolder := make(chan struct{}) // test lets alpha leave the critical section
	lateEnteredCS := make(chan struct{}) // charlie reached its merge (i.e. it acquired the lock)

	realMerge := mergeWrite
	setMergeWrite(t, func(dir *os.File, path string, src fsutil.FileSnapshot, key string, val any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		subject := ""
		if e, ok := val.(permissions.PermissionEntry); ok {
			subject = e.Subject
		}
		switch subject {
		case "alpha":
			// Complete the rename first (replacing the settings inode), then block
			// while still holding the sidecar lock — Persist's defer release() runs
			// only after this seam returns.
			step, cat, err := realMerge(dir, path, src, key, val)
			close(holderRenamed)
			<-releaseHolder
			return step, cat, err
		case "charlie":
			// Reaching here means charlie acquired the lock and entered its merge.
			close(lateEnteredCS)
			return realMerge(dir, path, src, key, val)
		default:
			return realMerge(dir, path, src, key, val)
		}
	})

	var wg sync.WaitGroup
	var holderReason, lateReason PersistReason
	var holderErr, lateErr error

	// (2) Holder acquires the sidecar lock and stays inside the critical section.
	wg.Add(1)
	go func() {
		defer wg.Done()
		holderReason, _, holderErr = Persist(target, KeyPermissions, folderEntry("alpha", "/work"))
	}()
	<-holderRenamed

	// (3) Late arrival starts after the holder's rename replaced the settings inode.
	wg.Add(1)
	go func() {
		defer wg.Done()
		lateReason, _, lateErr = Persist(target, KeyPermissions, folderEntry("charlie", "/work"))
	}()

	// Ordering assertion: while the holder still holds the sidecar lock, the late
	// arrival must stay blocked at lock acquisition and never reach its merge. If
	// the lock had been taken on the renamed settings inode instead of the stable
	// sidecar, charlie would acquire an uncontended lock here and this would fire.
	select {
	case <-lateEnteredCS:
		close(releaseHolder)
		t.Fatalf("late writer entered its critical section while the holder still held the sidecar lock: mutual exclusion broken")
	case <-time.After(150 * time.Millisecond):
	}

	// Releasing the holder must let the late arrival proceed.
	close(releaseHolder)
	select {
	case <-lateEnteredCS:
	case <-time.After(2 * time.Second):
		t.Fatalf("late writer never entered its critical section after the holder released the lock")
	}

	wg.Wait()

	if holderErr != nil || holderReason != ReasonNone {
		t.Fatalf("holder alpha = (%q, %v), want (none, nil)", holderReason, holderErr)
	}
	if lateErr != nil || lateReason != ReasonNone {
		t.Fatalf("late charlie = (%q, %v), want (none, nil)", lateReason, lateErr)
	}

	content := readAt(t, target)
	for _, s := range []string{"alpha", "bravo", "charlie"} {
		if !strings.Contains(content, "subject: "+s) {
			t.Fatalf("concurrent write lost entry %q (no lost update expected):\n%s", s, content)
		}
	}
}

// TestPersist_AbsentFile_CreatesAuthChatGPT confirms the shared chokepoint creates
// an absent settings file at mode 0600 for an auth.openai-chatgpt set.
func TestPersist_AbsentFile_CreatesAuthChatGPT(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "settings.yaml")

	reason, cat, err := Persist(target, KeyAuthOpenAIChatGPT, authValue("at", "rt", "2099-01-02T03:04:05Z", "acct"))
	if err != nil || reason != ReasonNone || cat != "" {
		t.Fatalf("Persist auth set = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}

	content := readAt(t, target)
	if !strings.Contains(content, "openai-chatgpt:") || !strings.Contains(content, "account_id: acct") {
		t.Fatalf("auth session not written:\n%s", content)
	}
	if os.Geteuid() != 0 {
		info, statErr := os.Stat(target)
		if statErr != nil {
			t.Fatalf("stat created file: %v", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("created file mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

// TestPersist_AuthChatGPT_DeletePreservesSiblings deletes the session through the
// chokepoint and asserts the unrelated permissions/model keys survive.
func TestPersist_AuthChatGPT_DeletePreservesSiblings(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	seed := "model:\n  active:\n    provider: openai\n    id: gpt-5.5\n    effort: medium\n\n" +
		"auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: acct\n\n" +
		"permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: global\n"
	writeAt(t, target, seed)

	reason, cat, err := Persist(target, KeyAuthOpenAIChatGPT, AuthDelete)
	if err != nil || reason != ReasonNone || cat != "" {
		t.Fatalf("Persist auth delete = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}

	content := readAt(t, target)
	if strings.Contains(content, "openai-chatgpt") {
		t.Fatalf("auth still present after delete:\n%s", content)
	}
	for _, want := range []string{"active:", "id: gpt-5.5", "subject: ls"} {
		if !strings.Contains(content, want) {
			t.Fatalf("delete dropped unrelated key (missing %q):\n%s", want, content)
		}
	}
}

// TestPersist_AuthChatGPT_DeleteWriteFailure_LeavesPriorState forces a temp-file
// fsync failure during the delete's atomic write and asserts prior auth state and
// unrelated settings are left byte-for-byte unchanged (Done-when: failed delete
// leaves prior state unchanged).
func TestPersist_AuthChatGPT_DeleteWriteFailure_LeavesPriorState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	seed := "auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: acct\n\n" +
		"permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: global\n"
	writeAt(t, target, seed)

	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	reason, cat, err := Persist(target, KeyAuthOpenAIChatGPT, AuthDelete)
	if reason != ReasonWriteError {
		t.Fatalf("reason = %q, want %q", reason, ReasonWriteError)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if got := readAt(t, target); got != seed {
		t.Fatalf("failed delete modified the file:\n--- got ---\n%s\n--- want ---\n%s", got, seed)
	}
}

// permDeleteSeed is a two-entry folder permissions list plus an unrelated model
// block, used by the permission-delete Persist tests to prove a delete removes the
// target entry and preserves siblings, or leaves everything untouched on no-op /
// write failure.
const permDeleteSeed = "model:\n  active:\n    provider: openai\n    id: gpt-5.5\n    effort: medium\n\n" +
	"permissions:\n  - kind: direct\n    subject: ls\n    path_scope: /work\n    grant_kind: folder\n" +
	"  - kind: direct\n    subject: pwd\n    path_scope: /work\n    grant_kind: folder\n"

// TestPersist_PermissionDelete_RemovesEntryPreservesSiblings routes a permission
// delete through Persist and reads the file back from disk to confirm the matched
// entry is gone while the other permission entry and the unrelated model block
// survive (Done-when: delete goes through the shared lock/re-read/atomic path).
func TestPersist_PermissionDelete_RemovesEntryPreservesSiblings(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, permDeleteSeed)

	reason, cat, err := Persist(target, KeyPermissions, PermissionDelete(folderEntry("ls", "/work").DedupKey()))
	if err != nil || reason != ReasonNone || cat != "" {
		t.Fatalf("Persist permission delete = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}

	content := readAt(t, target)
	if strings.Contains(content, "subject: ls") {
		t.Fatalf("deleted entry still present:\n%s", content)
	}
	for _, want := range []string{"subject: pwd", "active:", "id: gpt-5.5"} {
		if !strings.Contains(content, want) {
			t.Fatalf("delete dropped unrelated content (missing %q):\n%s", want, content)
		}
	}
}

// TestPersist_PermissionDelete_LocksSidecar asserts a permission delete acquires
// the dedicated sidecar lock (targetPath+".lock"), the same chokepoint as a write.
func TestPersist_PermissionDelete_LocksSidecar(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, permDeleteSeed)

	var gotLockPath string
	setAcquireLock(t, func(path string, _ time.Duration) (func(), locks.LockReason, error) {
		gotLockPath = path
		return func() {}, locks.ReasonNone, nil
	})

	reason, _, err := Persist(target, KeyPermissions, PermissionDelete(folderEntry("ls", "/work").DedupKey()))
	if err != nil || reason != ReasonNone {
		t.Fatalf("Persist = (%q, %v), want (none, nil)", reason, err)
	}
	if want := target + ".lock"; gotLockPath != want {
		t.Fatalf("lock path = %q, want sidecar %q", gotLockPath, want)
	}
	if got := readAt(t, target); strings.Contains(got, "subject: ls") {
		t.Fatalf("delete did not run under the mocked lock:\n%s", got)
	}
}

func TestPersist_BlockedPathRemove_WaitsForSidecarLockAndSkipsAnItemAlreadyRemoved(t *testing.T) {
	target := filepath.Join(t.TempDir(), "settings.yaml")
	writeAt(t, target, "blocked_paths:\n  - \"~/.ssh\"\n  - \"~/.aws\"\n")

	release, lockReason, lockErr := locks.Acquire(target+lockSuffix, time.Second)
	if lockErr != nil || lockReason != locks.ReasonNone {
		t.Fatalf("hold sidecar lock = (%q, %v)", lockReason, lockErr)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			release()
		}
	})

	done := make(chan struct{})
	var reason PersistReason
	var err error
	go func() {
		defer close(done)
		reason, _, err = Persist(target, "blocked_paths", BlockedPathRemove("/home/u", "/home/u/.ssh", 0))
	}()

	select {
	case <-done:
		t.Fatalf("blocked_paths write finished while another writer held the sidecar lock: (%q, %v)", reason, err)
	case <-time.After(150 * time.Millisecond):
	}

	other := "blocked_paths:\n  - \"~/.aws\"\n"
	writeAt(t, target, other)
	old := time.Now().Add(-time.Hour)
	if chErr := os.Chtimes(target, old, old); chErr != nil {
		t.Fatal(chErr)
	}
	before, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	released = true
	release()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("blocked_paths write never finished after the lock was released")
	}
	if err != nil || reason != ReasonNone {
		t.Fatalf("Persist = (%q, %v), want (none, nil)", reason, err)
	}
	if got := readAt(t, target); got != other {
		t.Fatalf("removal of an already removed item wrote the file:\n%s", got)
	}
	after, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("modification time changed: %v -> %v", before.ModTime(), after.ModTime())
	}
}

// TestPersist_PermissionDelete_WriteFailureLeavesPriorState forces a temp-file
// fsync failure during the delete's atomic write and asserts the file is left
// byte-for-byte unchanged (Done-when: failed delete leaves prior state unchanged).
func TestPersist_PermissionDelete_WriteFailureLeavesPriorState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, permDeleteSeed)

	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	reason, cat, err := Persist(target, KeyPermissions, PermissionDelete(folderEntry("ls", "/work").DedupKey()))
	if reason != ReasonWriteError {
		t.Fatalf("reason = %q, want %q", reason, ReasonWriteError)
	}
	if cat != fserrors.IOError {
		t.Fatalf("cat = %q, want %q", cat, fserrors.IOError)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
	if got := readAt(t, target); got != permDeleteSeed {
		t.Fatalf("failed delete modified the file:\n--- got ---\n%s\n--- want ---\n%s", got, permDeleteSeed)
	}
}

// TestPersist_PermissionDelete_AbsentKeyNoOp asserts that deleting an entry not in
// the file is a clean success that leaves the file byte-for-byte unchanged.
func TestPersist_PermissionDelete_AbsentKeyNoOp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, permDeleteSeed)

	reason, cat, err := Persist(target, KeyPermissions, PermissionDelete(folderEntry("missing", "/work").DedupKey()))
	if err != nil || reason != ReasonNone || cat != "" {
		t.Fatalf("Persist absent-key delete = (%q, %q, %v), want (none, '', nil)", reason, cat, err)
	}
	if got := readAt(t, target); got != permDeleteSeed {
		t.Fatalf("absent-key delete modified the file:\n--- got ---\n%s\n--- want ---\n%s", got, permDeleteSeed)
	}
}

// TestPersist_ConcurrentAuthModelPermissionWriters runs concurrent auth, model,
// and permission writers against the same file. The sidecar lock must serialize
// their read-modify-write cycles so all three land without clobbering each other
// (Research: serializes concurrent auth/model/permission writers).
func TestPersist_ConcurrentAuthModelPermissionWriters(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, "")

	type job struct {
		key string
		val any
	}
	jobs := []job{
		{KeyAuthOpenAIChatGPT, authValue("at", "rt", "2099-01-02T03:04:05Z", "acct")},
		{KeyModelActive, modelSelection("openai", "gpt-5.5", "medium")},
		{KeyPermissions, folderEntry("ls", "/work")},
	}

	var wg sync.WaitGroup
	reasons := make([]PersistReason, len(jobs))
	errs := make([]error, len(jobs))
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			reasons[i], _, errs[i] = Persist(target, j.key, j.val)
		}(i, j)
	}
	wg.Wait()

	for i := range jobs {
		if errs[i] != nil || reasons[i] != ReasonNone {
			t.Fatalf("writer %d = (%q, %v), want (none, nil)", i, reasons[i], errs[i])
		}
	}

	content := readAt(t, target)
	for _, want := range []string{"openai-chatgpt:", "active:", "subject: ls"} {
		if !strings.Contains(content, want) {
			t.Fatalf("concurrent write lost key %q:\n%s", want, content)
		}
	}
}

// TestPersist_ConcurrentWriters_Stochastic_NoLostUpdate is complementary stress
// coverage, not the deterministic regression guard above: six real Persist calls
// race against the same settings file with no forced interleaving. It exercises the
// lock/re-read/merge/rename cycle under scheduler-driven contention (run under
// -race) and asserts every append survives. It does NOT guarantee the
// inode-replacement interleaving — that property is pinned by
// TestPersist_ConcurrentWriters_ThreePlus_NoLostUpdate.
func TestPersist_ConcurrentWriters_Stochastic_NoLostUpdate(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, "") // pre-existing empty file: every writer exercises the locked merge path

	subjects := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}
	var wg sync.WaitGroup
	results := make([]PersistReason, len(subjects))
	errs := make([]error, len(subjects))
	for i, s := range subjects {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			results[i], _, errs[i] = Persist(target, KeyPermissions, folderEntry(s, "/work"))
		}(i, s)
	}
	wg.Wait()

	for i, s := range subjects {
		if errs[i] != nil || results[i] != ReasonNone {
			t.Fatalf("writer %q = (%q, %v), want (none, nil)", s, results[i], errs[i])
		}
	}

	content := readAt(t, target)
	for _, s := range subjects {
		if !strings.Contains(content, "subject: "+s) {
			t.Fatalf("concurrent write lost entry %q (no lost update expected):\n%s", s, content)
		}
	}
}

// forcedAuthInterleave drives one deterministic auth-vs-unrelated-writer race and
// returns the post-release file content. It forces the exact interleaving the
// sidecar lock must defend rather than hoping the scheduler produces it (the same
// mechanism as TestPersist_ConcurrentWriters_ThreePlus_NoLostUpdate):
//
//  1. An auth writer (holderVal — a session write for login/refresh, or AuthDelete
//     for logout, both through KeyAuthOpenAIChatGPT) enters its merge, completes the
//     real atomic rename (replacing the settings inode), then stays inside the
//     critical section still holding the sidecar lock.
//  2. An unrelated writer (lateKey/lateVal — a model.last_used or permission write)
//     starts only after the auth writer's rename. While the auth writer holds the
//     lock it must NOT reach its own merge.
//
// Under a lock-the-data-file contract the auth rename orphans the locked inode, so
// the unrelated writer opens the fresh inode and takes an uncontended lock — the
// negative assertion below would then fire. Because the lock lives on the stable
// sidecar inode, the unrelated writer blocks until the auth writer releases, and the
// pre-existing settings plus the concurrent update all survive. A final sequential
// append proves the post-race file is still coherent (its locked re-read passes).
func forcedAuthInterleave(t *testing.T, seed string, holderVal any, lateKey string, lateVal any) string {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	writeAt(t, target, seed)

	holderRenamed := make(chan struct{}) // auth writer finished its rename and still holds the lock
	releaseHolder := make(chan struct{}) // test lets the auth writer leave the critical section
	lateEnteredCS := make(chan struct{}) // unrelated writer reached its merge (i.e. it acquired the lock)

	realMerge := mergeWrite
	setMergeWrite(t, func(dir *os.File, path string, src fsutil.FileSnapshot, key string, val any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		switch key {
		case KeyAuthOpenAIChatGPT:
			// Auth holder: complete the real rename (replacing the settings inode),
			// then block while still holding the sidecar lock — Persist's deferred
			// release runs only after this seam returns.
			step, cat, err := realMerge(dir, path, src, key, val)
			close(holderRenamed)
			<-releaseHolder
			return step, cat, err
		case lateKey:
			// Reaching here means the unrelated writer acquired the lock and entered
			// its merge.
			close(lateEnteredCS)
			return realMerge(dir, path, src, key, val)
		default:
			return realMerge(dir, path, src, key, val)
		}
	})

	var wg sync.WaitGroup
	var holderReason, lateReason PersistReason
	var holderErr, lateErr error

	// (1) Auth writer acquires the sidecar lock and stays inside the critical section.
	wg.Add(1)
	go func() {
		defer wg.Done()
		holderReason, _, holderErr = Persist(target, KeyAuthOpenAIChatGPT, holderVal)
	}()
	<-holderRenamed

	// (2) Unrelated writer starts after the auth writer's rename replaced the inode.
	wg.Add(1)
	go func() {
		defer wg.Done()
		lateReason, _, lateErr = Persist(target, lateKey, lateVal)
	}()

	// Ordering assertion: while the auth writer still holds the sidecar lock, the
	// unrelated writer must stay blocked at lock acquisition and never reach its
	// merge. If the lock had been taken on the renamed settings inode instead of the
	// stable sidecar, the unrelated writer would acquire an uncontended lock here.
	select {
	case <-lateEnteredCS:
		close(releaseHolder)
		t.Fatalf("unrelated %s writer entered its critical section while the auth writer still held the sidecar lock: mutual exclusion broken", lateKey)
	case <-time.After(150 * time.Millisecond):
	}

	// Releasing the auth writer must let the unrelated writer proceed.
	close(releaseHolder)
	select {
	case <-lateEnteredCS:
	case <-time.After(2 * time.Second):
		t.Fatalf("unrelated %s writer never entered its critical section after the auth writer released the lock", lateKey)
	}

	wg.Wait()

	if holderErr != nil || holderReason != ReasonNone {
		t.Fatalf("auth writer = (%q, %v), want (none, nil)", holderReason, holderErr)
	}
	if lateErr != nil || lateReason != ReasonNone {
		t.Fatalf("unrelated %s writer = (%q, %v), want (none, nil)", lateKey, lateReason, lateErr)
	}

	// Drop the seam before the coherence append: it shares KeyPermissions with the
	// permission late-writer case, so leaving it installed would re-close lateEnteredCS.
	mergeWrite = realMerge

	// The post-race file is coherent: a fresh locked re-read + append succeeds, so no
	// writer left a partial or schema-invalid document behind.
	if reason, _, err := Persist(target, KeyPermissions, folderEntry("final", "/work")); err != nil || reason != ReasonNone {
		t.Fatalf("post-race append = (%q, %v), want (none, nil): the concurrent writers left the file incoherent", reason, err)
	}
	content := readAt(t, target)
	if !strings.Contains(content, "subject: final") {
		t.Fatalf("post-race append did not land:\n%s", content)
	}
	return content
}

// TestPersist_ConcurrentAuthWriteDeleteRefreshPreserveUnrelated is the
// cross-cutting concurrency guard for (Done-when 2, Step 6).
// It deterministically forces an auth writer to hold the sidecar lock through its
// real atomic rename while an unrelated global-settings writer is blocked at lock
// acquisition, then proves the unrelated writer only proceeds after release and that
// every pre-existing and concurrent setting survives. The two subtests pin both auth
// holder shapes names — a session write (login/refresh) and a delete (logout)
// — each against one of the unrelated writers (model.last_used and a permission
// append). The seed carries unrelated content that must survive: a leading comment,
// an OpenAI Platform api_key, a pre-existing model.active, a pre-existing permission,
// and a stored session. Every fragment is a schema-valid shape reused from the
// existing persistence tests, so the seeded file passes each writer's locked re-read.
func TestPersist_ConcurrentAuthWriteDeleteRefreshPreserveUnrelated(t *testing.T) {
	const seed = "# managed settings — do not hand-edit blindly\n" +
		"provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-KEEP\n" +
		"model:\n  active:\n    provider: openai\n    id: gpt-5.5\n    effort: medium\n" +
		"auth:\n  openai-chatgpt:\n    access_token: at\n    refresh_token: rt\n    expires_at: \"2099-01-02T03:04:05Z\"\n    account_id: acct\n" +
		"permissions:\n  - kind: direct\n    subject: ls\n    path_scope: \"*\"\n    grant_kind: global\n"

	// Pre-existing unrelated content that must survive any auth churn.
	preExisting := []string{"# managed settings", "api_key: sk-KEEP", "active:", "id: gpt-5.5", "effort: medium", "subject: ls"}

	// Auth set (login/refresh) holds the sidecar lock; a model.last_used writer must
	// serialize behind it and still land, and the unrelated settings must survive.
	t.Run("auth set vs model.last_used", func(t *testing.T) {
		content := forcedAuthInterleave(t, seed,
			authValue("new-access", "new-refresh", "2099-02-02T03:04:05Z", "acct"),
			KeyModelLastUsed, modelSelection("openai", "gpt-5.5", "high"))
		if !strings.Contains(content, "new-access") {
			t.Fatalf("auth set (login/refresh) did not land:\n%s", content)
		}
		for _, keep := range preExisting {
			if !strings.Contains(content, keep) {
				t.Fatalf("auth set dropped unrelated content %q:\n%s", keep, content)
			}
		}
		// The concurrent model.last_used update (effort: high) survived behind the auth write.
		for _, want := range []string{"last_used:", "effort: high"} {
			if !strings.Contains(content, want) {
				t.Fatalf("concurrent model.last_used update lost (missing %q):\n%s", want, content)
			}
		}
	})

	// Auth delete (logout) holds the sidecar lock; a permission writer must serialize
	// behind it and still land, and the unrelated settings must survive the deletion.
	t.Run("auth delete vs permission", func(t *testing.T) {
		content := forcedAuthInterleave(t, seed, AuthDelete,
			KeyPermissions, folderEntry("newperm", "/work"))
		if strings.Contains(content, "openai-chatgpt") {
			t.Fatalf("auth delete (logout) did not remove the session:\n%s", content)
		}
		for _, keep := range preExisting {
			if !strings.Contains(content, keep) {
				t.Fatalf("auth delete dropped unrelated content %q:\n%s", keep, content)
			}
		}
		// The concurrent permission append survived behind the auth delete.
		if !strings.Contains(content, "subject: newperm") {
			t.Fatalf("concurrent permission update lost:\n%s", content)
		}
	})
}

func TestPersistFavorite_UsesLockedLatestState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	got, reason, cat, err := persistFavorite(target, Favorite{Provider: "openai", ID: "gpt-5"}, true)
	if reason != ReasonNone || err != nil {
		t.Fatalf("first add = (%q, %q, %v), want success", reason, cat, err)
	}
	if want := []Favorite{{Provider: "openai", ID: "gpt-5"}}; !slices.Equal(got, want) {
		t.Fatalf("first add returned %v, want %v", got, want)
	}

	writeAt(t, target, "model:\n  favorites: [{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}]  # mine\n")

	got, reason, cat, err = persistFavorite(target, Favorite{Provider: "google", ID: "gemini"}, true)
	if reason != ReasonNone || err != nil {
		t.Fatalf("second add = (%q, %q, %v), want success", reason, cat, err)
	}
	want := []Favorite{
		{Provider: "openai", ID: "gpt-5"},
		{Provider: "anthropic", ID: "opus"},
		{Provider: "google", ID: "gemini"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("second add returned %v, want %v", got, want)
	}
	if durable := favoritesOnDisk(t, target); !slices.Equal(durable, want) {
		t.Fatalf("durable favorites = %v, want %v", durable, want)
	}

	got[0] = Favorite{Provider: "tampered", ID: "tampered"}
	if durable := favoritesOnDisk(t, target); !slices.Equal(durable, want) {
		t.Fatalf("mutating the returned list changed durable favorites: %v, want %v", durable, want)
	}

	writeAt(t, target, "model:\n  favorites: [{provider: openai, id: gpt-5}, {provider: anthropic, id: opus}, {provider: google, id: gemini}]  # mine\n")
	before := readAt(t, target)
	got, reason, _, err = persistFavorite(target, Favorite{Provider: "anthropic", ID: "opus"}, true)
	if reason != ReasonNone || err != nil {
		t.Fatalf("duplicate add = (%q, %v), want success", reason, err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("duplicate add returned %v, want %v", got, want)
	}
	if after := readAt(t, target); after != before {
		t.Fatalf("duplicate add rewrote bytes:\n%q\nwant\n%q", after, before)
	}
}

func TestPersistFavorite_FailuresReturnNoResult(t *testing.T) {
	before := "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n"
	target := Favorite{Provider: "anthropic", ID: "opus"}

	t.Run("empty target is refused before any lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, path, before)
		blocked := failIfMergeCalled(t)
		got, reason, cat, err := persistFavorite(path, Favorite{Provider: "openai"}, true)
		if got != nil || reason != ReasonRereadParseError || cat != "" || err == nil {
			t.Fatalf("= (%v, %q, %q, %v), want (nil, reread_parse_error, \"\", error)", got, reason, cat, err)
		}
		if *blocked {
			t.Fatalf("merge ran for an invalid target")
		}
		if after := readAt(t, path); after != before {
			t.Fatalf("invalid target changed bytes:\n%q", after)
		}
	})

	t.Run("typed-nil payload is refused under the lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, path, before)
		blocked := failIfMergeCalled(t)
		reason, cat, err := Persist(path, keyModelFavorites, (*favoriteToggleValue)(nil))
		if reason != ReasonRereadParseError || cat != "" || err == nil {
			t.Fatalf("= (%q, %q, %v), want (reread_parse_error, \"\", error)", reason, cat, err)
		}
		if *blocked {
			t.Fatalf("merge ran for a nil favorite payload")
		}
		if after := readAt(t, path); after != before {
			t.Fatalf("nil favorite payload changed bytes:\n%q", after)
		}
	})

	t.Run("schema-invalid reread skips the write", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.yaml")
		bad := "model:\n  favorites:\n    - provider: openai\n"
		writeAt(t, path, bad)
		got, reason, cat, err := persistFavorite(path, target, true)
		if got != nil || reason != ReasonRereadParseError || cat != "" || err == nil {
			t.Fatalf("= (%v, %q, %q, %v), want (nil, reread_parse_error, \"\", error)", got, reason, cat, err)
		}
		if after := readAt(t, path); after != bad {
			t.Fatalf("pre-publish failure changed bytes:\n%q\nwant\n%q", after, bad)
		}
	})

	t.Run("pre-publish write failure leaves prior bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, path, before)
		sentinel := errors.New("forced temp-file sync failure")
		restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
		t.Cleanup(restore)

		got, reason, cat, err := persistFavorite(path, target, true)
		if got != nil || reason != ReasonWriteError || !errors.Is(err, sentinel) {
			t.Fatalf("= (%v, %q, %q, %v), want (nil, write_error, wrap of sentinel)", got, reason, cat, err)
		}
		if after := readAt(t, path); after != before {
			t.Fatalf("failed pre-publish write changed bytes:\n%q\nwant\n%q", after, before)
		}
	})

	t.Run("parent-sync failure returns no result after publication", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.yaml")
		writeAt(t, path, before)
		sentinel := errors.New("forced parent dir sync failure")
		restore := fsutil.SetSyncDirForTest(func(*os.File) error { return sentinel })
		t.Cleanup(restore)

		got, reason, cat, err := persistFavorite(path, target, true)
		if got != nil {
			t.Fatalf("result = %v, want nil on a reported failure", got)
		}
		if reason != ReasonParentDirError || !errors.Is(err, sentinel) {
			t.Fatalf("= (%q, %q, %v), want (parent_dir_error, wrap of sentinel)", reason, cat, err)
		}
		restore()
		want := []Favorite{{Provider: "openai", ID: "gpt-5"}, target}
		if durable := favoritesOnDisk(t, path); !slices.Equal(durable, want) {
			t.Fatalf("durable favorites = %v, want the published %v", durable, want)
		}
	})
}

func TestPersistFavorite_ConcurrentDifferentAddsBothSurvive(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")
	seeded := Favorite{Provider: "openai", ID: "gpt-5"}
	holderAdd := Favorite{Provider: "anthropic", ID: "opus"}
	lateAdd := Favorite{Provider: "google", ID: "gemini"}
	writeAt(t, target, "model:\n  favorites:\n    - provider: openai\n      id: gpt-5\n")

	holderEnteredCS := make(chan struct{})
	releaseHolder := make(chan struct{})
	lateEnteredCS := make(chan struct{})

	realMerge := mergeWrite
	setMergeWrite(t, func(dir *os.File, path string, src fsutil.FileSnapshot, key string, val any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		op, ok := val.(*favoriteToggleValue)
		if !ok {
			return realMerge(dir, path, src, key, val)
		}
		switch op.target {
		case holderAdd:
			close(holderEnteredCS)
			<-releaseHolder
			return realMerge(dir, path, src, key, val)
		case lateAdd:
			close(lateEnteredCS)
			return realMerge(dir, path, src, key, val)
		default:
			return realMerge(dir, path, src, key, val)
		}
	})

	var wg sync.WaitGroup
	var holderReason, lateReason PersistReason
	var holderErr, lateErr error
	var lateResult []Favorite

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, holderReason, _, holderErr = persistFavorite(target, holderAdd, true)
	}()
	<-holderEnteredCS

	wg.Add(1)
	go func() {
		defer wg.Done()
		lateResult, lateReason, _, lateErr = persistFavorite(target, lateAdd, true)
	}()

	select {
	case <-lateEnteredCS:
		close(releaseHolder)
		t.Fatalf("second favorite writer merged while the first still held the sidecar lock: its transition could be derived from a stale snapshot")
	case <-time.After(150 * time.Millisecond):
	}

	close(releaseHolder)
	select {
	case <-lateEnteredCS:
	case <-time.After(2 * time.Second):
		t.Fatalf("second favorite writer never merged after the first released the lock")
	}

	wg.Wait()

	if holderErr != nil || holderReason != ReasonNone {
		t.Fatalf("first writer = (%q, %v), want (none, nil)", holderReason, holderErr)
	}
	if lateErr != nil || lateReason != ReasonNone {
		t.Fatalf("second writer = (%q, %v), want (none, nil)", lateReason, lateErr)
	}

	want := []Favorite{seeded, holderAdd, lateAdd}
	if !slices.Equal(lateResult, want) {
		t.Fatalf("second writer returned %v, want %v: it did not derive its transition from the first writer's durable state", lateResult, want)
	}
	if durable := favoritesOnDisk(t, target); !slices.Equal(durable, want) {
		t.Fatalf("durable favorites = %v, want %v", durable, want)
	}
}

func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatalf("symlink %s -> %s: %v", newname, oldname, err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	state := make(map[string]string, len(entries))
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		switch {
		case e.Type()&os.ModeSymlink != 0:
			dst, lerr := os.Readlink(p)
			if lerr != nil {
				t.Fatalf("readlink %s: %v", p, lerr)
			}
			state[e.Name()] = "link:" + dst
		case e.Type().IsRegular():
			state[e.Name()] = "file:" + readAt(t, p)
		default:
			state[e.Name()] = "type:" + e.Type().String()
		}
	}
	return state
}

func assertDirUnchanged(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	if after := dirState(t, dir); !maps.Equal(after, before) {
		t.Fatalf("%s changed:\n got=%v\nwant=%v", dir, after, before)
	}
}

func assertParentRefused(t *testing.T, reason PersistReason, cat fserrors.Category, err error, parent string) {
	t.Helper()
	if reason != ReasonParentDirError || cat == "" || err == nil || !strings.Contains(err.Error(), parent) {
		t.Fatalf("Persist = (%q, %q, %v), want (parent_dir_error, a category, an error naming %q)", reason, cat, err, parent)
	}
}

func TestPersist_SymlinkedParentRefused(t *testing.T) {
	cases := []struct {
		name  string
		seed  string
		key   string
		value any
	}{
		{"new file", "", KeyPermissions, folderEntry("ls", "/work")},
		{"existing file", permDeleteSeed, KeyPermissions, folderEntry("ls", "/elsewhere")},
		{"blocked_paths removal", "blocked_paths:\n  - \"~/.ssh\"\n", blockedPathsKey, BlockedPathRemove("/home/u", "/home/u/.ssh", 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, foreign := t.TempDir(), t.TempDir()
			writeAt(t, filepath.Join(foreign, "keep.txt"), "keep\n")
			if tc.seed != "" {
				writeAt(t, filepath.Join(foreign, "settings.yaml"), tc.seed)
			}
			link := filepath.Join(root, ".codemeld")
			mustSymlink(t, foreign, link)
			before := dirState(t, foreign)

			reason, cat, err := Persist(filepath.Join(link, "settings.yaml"), tc.key, tc.value)
			assertParentRefused(t, reason, cat, err, link)
			assertDirUnchanged(t, foreign, before)
		})
	}
}

func TestPersist_RealAndAbsentParentsWrite(t *testing.T) {
	cases := []struct {
		name      string
		rel       string
		precreate bool
	}{
		{"real parent", "real", true},
		{"absent parent with missing ancestors", filepath.Join("a", "b", "c"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), tc.rel)
			if tc.precreate {
				mustMkdir(t, parent)
			}
			target := filepath.Join(parent, "settings.yaml")
			reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
			if reason != ReasonNone || cat != "" || err != nil {
				t.Fatalf("Persist = (%q, %q, %v), want a clean write", reason, cat, err)
			}
			if content := readAt(t, target); !strings.Contains(content, "subject: ls") {
				t.Fatalf("entry not written:\n%s", content)
			}
		})
	}
}

func TestPersist_ImmediateParentAdversarial(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, root, outside, parent string)
	}{
		{"link to dot", func(t *testing.T, _, _, parent string) { mustSymlink(t, ".", parent) }},
		{"link to outside dir", func(t *testing.T, _, outside, parent string) { mustSymlink(t, outside, parent) }},
		{"dangling link", func(t *testing.T, root, _, parent string) {
			mustSymlink(t, filepath.Join(root, "missing"), parent)
		}},
		{"link to a link", func(t *testing.T, root, outside, parent string) {
			hop := filepath.Join(root, "hop")
			mustSymlink(t, outside, hop)
			mustSymlink(t, hop, parent)
		}},
		{"regular file", func(t *testing.T, _, _, parent string) { writeAt(t, parent, "not a directory\n") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			writeAt(t, filepath.Join(outside, "settings.yaml"), permDeleteSeed)
			parent := filepath.Join(root, "parent")
			tc.setup(t, root, outside, parent)
			beforeRoot, beforeOutside := dirState(t, root), dirState(t, outside)

			reason, cat, err := Persist(filepath.Join(parent, "settings.yaml"), KeyPermissions, folderEntry("ls", "/elsewhere"))
			assertParentRefused(t, reason, cat, err, parent)
			assertDirUnchanged(t, root, beforeRoot)
			assertDirUnchanged(t, outside, beforeOutside)
		})
	}
}

func TestPersist_ParentSwappedBeforeOpenRefused(t *testing.T) {
	removeIfPresent := func(t *testing.T, path string) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", path, err)
		}
	}
	toLink := func(t *testing.T, path, outside string) {
		removeIfPresent(t, path)
		mustSymlink(t, outside, path)
	}
	toFile := func(t *testing.T, path, _ string) {
		removeIfPresent(t, path)
		writeAt(t, path, "not a directory\n")
	}
	cases := []struct {
		name     string
		existing string
		target   string
		swapAt   string
		swap     func(t *testing.T, path, outside string)
	}{
		{"existing parent to symlink", "p", filepath.Join("p", "settings.yaml"), "p", toLink},
		{"existing parent to file", "p", filepath.Join("p", "settings.yaml"), "p", toFile},
		{"missing intermediate to symlink", "", filepath.Join("a", "b", "settings.yaml"), "a", toLink},
		{"missing intermediate to file", "", filepath.Join("a", "b", "settings.yaml"), "a", toFile},
		{"missing parent to symlink", "", filepath.Join("a", "b", "settings.yaml"), filepath.Join("a", "b"), toLink},
		{"missing parent to file", "", filepath.Join("a", "b", "settings.yaml"), filepath.Join("a", "b"), toFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			writeAt(t, filepath.Join(outside, "keep.txt"), "keep\n")
			if tc.existing != "" {
				mustMkdir(t, filepath.Join(root, tc.existing))
			}
			beforeOutside := dirState(t, outside)
			swapPath := filepath.Join(root, tc.swapAt)
			var afterSwap map[string]string
			setBeforeParentSegment(t, func(p string) {
				if p == swapPath {
					tc.swap(t, p, outside)
					afterSwap = dirState(t, filepath.Dir(p))
				}
			})

			reason, cat, err := Persist(filepath.Join(root, tc.target), KeyPermissions, folderEntry("ls", "/work"))
			if afterSwap == nil {
				t.Fatalf("swap hook never ran for %s", swapPath)
			}
			assertParentRefused(t, reason, cat, err, swapPath)
			assertDirUnchanged(t, filepath.Dir(swapPath), afterSwap)
			assertDirUnchanged(t, outside, beforeOutside)
		})
	}
}

func TestPersist_HeldParentSurvivesSwapToRealDir(t *testing.T) {
	wrapAcquire := func(t *testing.T, swap func()) {
		orig := acquireLock
		setAcquireLockAt(t, func(d *os.File, name string, to time.Duration) (func(), locks.LockReason, error) {
			swap()
			return orig(d, name, to)
		})
	}
	wrapReread := func(t *testing.T, swap func()) {
		orig := rereadSettings
		setRereadSettings(t, func(d *os.File, path string) (fsutil.FileSnapshot, map[string]any, LoadFailure, error) {
			swap()
			return orig(d, path)
		})
	}
	wrapMerge := func(t *testing.T, swap func()) {
		orig := mergeWrite
		setMergeWrite(t, func(d *os.File, path string, src fsutil.FileSnapshot, key string, val any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
			swap()
			return orig(d, path, src, key, val)
		})
	}
	cases := []struct {
		name    string
		missing bool
		install func(t *testing.T, swap func())
	}{
		{"before sidecar creation", false, wrapAcquire},
		{"created parent before sidecar creation", true, wrapAcquire},
		{"before re-read", false, wrapReread},
		{"before publication", false, wrapMerge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "p")
			if tc.missing {
				parent = filepath.Join(root, "a", "b")
			} else {
				mustMkdir(t, parent)
				writeAt(t, filepath.Join(parent, "settings.yaml"), "model: {}\n")
			}
			pinned := parent + "-pinned"
			swapped := false
			tc.install(t, func() {
				swapped = true
				if err := os.Rename(parent, pinned); err != nil {
					t.Fatalf("move held parent aside: %v", err)
				}
				mustMkdir(t, parent)
			})

			reason, cat, err := Persist(filepath.Join(parent, "settings.yaml"), KeyPermissions, folderEntry("ls", "/work"))
			if !swapped {
				t.Fatalf("swap seam never ran")
			}
			if reason != ReasonNone || cat != "" || err != nil {
				t.Fatalf("Persist = (%q, %q, %v), want the write to finish in the held directory", reason, cat, err)
			}
			if got := dirState(t, parent); len(got) != 0 {
				t.Fatalf("replacement directory was touched: %v", got)
			}
			if content := readAt(t, filepath.Join(pinned, "settings.yaml")); !strings.Contains(content, "subject: ls") {
				t.Fatalf("held directory did not receive the write:\n%s", content)
			}
			if _, lerr := os.Lstat(filepath.Join(pinned, "settings.yaml"+lockSuffix)); lerr != nil {
				t.Fatalf("sidecar not in the held directory: %v", lerr)
			}
		})
	}
}

func TestPersist_ConcurrentParentCreatorStillWrites(t *testing.T) {
	root := t.TempDir()
	var created []string
	setBeforeParentSegment(t, func(p string) {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatalf("competing mkdir %s: %v", p, err)
		}
		created = append(created, p)
	})
	target := filepath.Join(root, "a", "b", "settings.yaml")

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonNone || cat != "" || err != nil {
		t.Fatalf("Persist = (%q, %q, %v), want a clean write", reason, cat, err)
	}
	if want := []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")}; !slices.Equal(created, want) {
		t.Fatalf("competitor created %v, want %v", created, want)
	}
	if content := readAt(t, target); !strings.Contains(content, "subject: ls") {
		t.Fatalf("entry not written:\n%s", content)
	}
}

func TestPersist_FinalComponentRefused(t *testing.T) {
	const lockLeaf = "settings.yaml" + lockSuffix
	link := func(t *testing.T, path, outside string) { mustSymlink(t, filepath.Join(outside, "referent"), path) }
	dangling := func(t *testing.T, path, outside string) { mustSymlink(t, filepath.Join(outside, "missing"), path) }
	dir := func(t *testing.T, path, _ string) { mustMkdir(t, path) }
	fifo := func(t *testing.T, path, _ string) {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("mkfifo %s: %v", path, err)
		}
	}
	cases := []struct {
		name  string
		leaf  string
		setup func(t *testing.T, path, outside string)
		want  PersistReason
	}{
		{"lock symlink to file", lockLeaf, link, ReasonLockAcquireError},
		{"lock dangling symlink", lockLeaf, dangling, ReasonLockAcquireError},
		{"lock directory", lockLeaf, dir, ReasonLockAcquireError},
		{"lock fifo", lockLeaf, fifo, ReasonLockAcquireError},
		{"settings symlink to file", "settings.yaml", link, ReasonRereadIOError},
		{"settings dangling symlink", "settings.yaml", dangling, ReasonRereadIOError},
		{"settings fifo", "settings.yaml", fifo, ReasonRereadIOError},
		{"settings directory", "settings.yaml", dir, ReasonRereadIOError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent, outside := t.TempDir(), t.TempDir()
			writeAt(t, filepath.Join(outside, "referent"), "model: {}\n")
			if tc.leaf == lockLeaf {
				writeAt(t, filepath.Join(parent, "settings.yaml"), "model: {}\n")
			} else {
				writeAt(t, filepath.Join(parent, lockLeaf), "")
			}
			tc.setup(t, filepath.Join(parent, tc.leaf), outside)
			beforeParent, beforeOutside := dirState(t, parent), dirState(t, outside)

			reason, cat, err := Persist(filepath.Join(parent, "settings.yaml"), KeyPermissions, folderEntry("ls", "/work"))
			if reason != tc.want || cat != fserrors.IOError || err == nil {
				t.Fatalf("Persist = (%q, %q, %v), want (%q, %q, an error)", reason, cat, err, tc.want, fserrors.IOError)
			}
			assertDirUnchanged(t, parent, beforeParent)
			assertDirUnchanged(t, outside, beforeOutside)
		})
	}
}

func TestPersist_EmptyExistingSettingsIsNotAbsent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "settings.yaml")
	writeAt(t, target, "")

	var source fsutil.FileSnapshot
	orig := mergeWrite
	setMergeWrite(t, func(d *os.File, path string, src fsutil.FileSnapshot, key string, val any) (fsutil.AtomicWriteStep, fserrors.Category, error) {
		source = src
		return orig(d, path, src, key, val)
	})

	reason, cat, err := Persist(target, KeyPermissions, folderEntry("ls", "/work"))
	if reason != ReasonNone || cat != "" || err != nil {
		t.Fatalf("Persist = (%q, %q, %v), want a clean write", reason, cat, err)
	}
	if !source.Exists || len(source.Data) != 0 {
		t.Fatalf("merge source = (exists=%v, %q), want an existing empty file", source.Exists, source.Data)
	}
	if content := readAt(t, target); !strings.Contains(content, "subject: ls") {
		t.Fatalf("entry not written:\n%s", content)
	}
}

func TestPersist_GlobalSaveThroughSymlinkedAncestor(t *testing.T) {
	cases := []struct {
		name      string
		precreate bool
	}{
		{"existing global dir", true},
		{"absent global dir", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			realDir := filepath.Join(tmp, "real")
			mustMkdir(t, realDir)
			if tc.precreate {
				mustMkdir(t, filepath.Join(realDir, "global"))
			}
			mustSymlink(t, realDir, filepath.Join(tmp, "link"))

			reason, cat, err := Persist(filepath.Join(tmp, "link", "global", "settings.yaml"), KeyModelActive, modelSelection("openai", "gpt-x", "medium"))
			if reason != ReasonNone || cat != "" || err != nil {
				t.Fatalf("Persist = (%q, %q, %v), want a clean write", reason, cat, err)
			}
			if content := readAt(t, filepath.Join(realDir, "global", "settings.yaml")); !strings.Contains(content, "gpt-x") {
				t.Fatalf("global settings not written:\n%s", content)
			}
		})
	}
}
