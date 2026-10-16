// Atomic file write via a sibling temp file plus rename, fsyncing the temp file and parent directory.
package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"codemeld.dev/codemeld/internal/fserrors"
	"golang.org/x/sys/unix"
)

// ErrTargetIdentityChanged reports that the entry occupying the publish target name was not the file
// the caller planned its bytes from, so the publish was refused and nothing at that name was
// overwritten. Consumers detect it with errors.Is.
var ErrTargetIdentityChanged = errors.New("fsutil: the publish target is not the file the write was planned from")

// ErrPublishUnreconciled reports that a write neither published nor put the directory back as it
// found it: a file the call did not stage survives under the scratch or target name given in the
// wrapping error, because removing it or displacing it would have destroyed data this call does not
// own — the planned original, which could not be linked back under its own name, or a file another
// writer left under a name this call was about to clean up. Nothing is lost, but the directory needs
// reconciling by hand. Consumers detect it with errors.Is.
var ErrPublishUnreconciled = errors.New("fsutil: the write was refused and a file it did not stage is retained under the name given in the wrapping error")

// AtomicWriteStep identifies which step of WriteAtomic failed so callers can map it to their own reason tokens without parsing error strings. The zero value means success.
type AtomicWriteStep string

const (
	WriteStep      AtomicWriteStep = "write"
	RenameStep     AtomicWriteStep = "rename"
	ParentSyncStep AtomicWriteStep = "parent_sync"
	// LinkStep marks a failure of WriteAtomicCreate's no-replace link publish — most importantly the
	// publish-time existing-target case (err wraps fs.ErrExist), where the target appeared after
	// resolution and create must not overwrite it.
	LinkStep AtomicWriteStep = "link"
	// LoadStep marks a pre-write failure surfaced by callers that compose load/parse/marshal steps in front of WriteAtomic; WriteAtomic itself never returns it. Defined here so the shared enum stays the single source of truth for step tokens.
	LoadStep AtomicWriteStep = "load"
)

// Test seams so tests can force temp-file and parent-dir sync failures; production callers see plain f.Sync().
var (
	syncFile = (*os.File).Sync
	syncDir  = (*os.File).Sync
)

// SetSyncFileForTest replaces the temp-file fsync seam used by WriteAtomic
// with fn and returns a restorer the caller MUST run to put the production
// seam back. Test-only; production code must not call this.
// intentional: test-only seam (no production caller by design).
func SetSyncFileForTest(fn func(*os.File) error) func() {
	orig := syncFile
	syncFile = fn
	return func() { syncFile = orig }
}

// SetSyncDirForTest replaces the parent-dir fsync seam used by WriteAtomic
// with fn and returns a restorer the caller MUST run to put the production
// seam back. Test-only; production code must not call this.
// intentional: test-only seam (no production caller by design).
func SetSyncDirForTest(fn func(*os.File) error) func() {
	orig := syncDir
	syncDir = fn
	return func() { syncDir = orig }
}

// beforePublishRename is a test-only seam fired after the staged entry is durable and the pre-publish
// hook has run, but before publication, so a test can replace the target inside the one window a
// pre-publish check cannot cover. Production runs the no-op default.
// intentional: test-only seam (no production caller by design).
var beforePublishRename = func() {}

// recoveryName is the package-local seam for choosing the temporary name a publish moves the target
// aside to. Tests swap it via SetRecoveryNameForTest so a chosen name can be occupied on purpose;
// production generates a fresh random name.
var recoveryName = tempName

// SetRecoveryNameForTest replaces the recovery-name generator with fn and returns a restorer the
// caller MUST run to put the production generator back. Test-only; production must not call it.
// intentional: test-only seam (no production caller by design).
func SetRecoveryNameForTest(fn func(basename string) (string, error)) func() {
	orig := recoveryName
	recoveryName = fn
	return func() { recoveryName = orig }
}

// SetBeforePublishRenameForTest replaces the pre-publication hook with fn and returns a restorer the
// caller MUST run to put the no-op default back. Test-only; production must not call it.
// intentional: test-only seam (no production caller by design).
func SetBeforePublishRenameForTest(fn func()) func() {
	orig := beforePublishRename
	beforePublishRename = fn
	return func() { beforePublishRename = orig }
}

// beforeCleanup is a test-only seam fired once the publish has decided its outcome — the staged bytes
// are linked at the target, or the displaced original has been put back — and before either scratch
// name is removed, which is the only window in which a replacement of those names could make the
// cleanup destroy another writer's file. Production runs the no-op default.
// intentional: test-only seam (no production caller by design).
var beforeCleanup = func() {}

// SetBeforeCleanupForTest replaces the pre-cleanup hook with fn and returns a restorer the caller MUST
// run to put the no-op default back. Test-only; production must not call it.
// intentional: test-only seam (no production caller by design).
func SetBeforeCleanupForTest(fn func()) func() {
	orig := beforeCleanup
	beforeCleanup = fn
	return func() { beforeCleanup = orig }
}

// PrePublish observes a staged temporary entry that already holds the final bytes, the exact
// requested permission bits, and a completed file fsync — immediately before the rename or link makes
// anything visible. mode is the permission mode read back from the staged descriptor, not the mode the
// caller asked for, so a recorded mode is the one publication will make durable. Returning an error
// aborts the publish, removes the temporary entry, and surfaces as a WriteStep failure.
type PrePublish func(targetName string, data []byte, mode os.FileMode) error

// singleComponent reports whether name is one ordinary path component, so a publish relative to a held
// directory descriptor can never be steered into another directory by the name alone.
func singleComponent(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name
}

func requireDir(parentDir *os.File) (AtomicWriteStep, fserrors.Category, error) {
	info, statErr := parentDir.Stat()
	if statErr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(statErr), statErr
	}
	if !info.IsDir() {
		e := &os.PathError{Op: "open", Path: parentDir.Name(), Err: syscall.ENOTDIR}
		return ParentSyncStep, fserrors.CategorizeErrno(e), e
	}
	return "", "", nil
}

// stageTempAt creates a sibling temporary entry for targetName relative to dirfd and leaves it holding
// data at exactly mode's permission bits. The order is fixed — write, fchmod, fstat, fsync — because
// the O_CREAT mode is trimmed by the process umask (so the chmod is what makes the mode exact) and the
// fsync must follow the chmod for the read-back mode to be durable rather than a pending metadata
// change. info is read back from the staged descriptor, so its mode is the one the filesystem stored
// and its identity is the inode publication will move to the target name. Every failure removes the
// temporary entry it created, and only that entry: the name is an ordinary sibling any other writer of
// the directory can take, so a replacement is retained and named in the returned error instead.
func stageTempAt(dirfd int, targetName string, data []byte, mode os.FileMode) (staged string, info os.FileInfo, step AtomicWriteStep, cat fserrors.Category, err error) {
	name, nameErr := tempName(targetName)
	if nameErr != nil {
		return "", nil, WriteStep, fserrors.IOError, nameErr
	}

	fd, createErr := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, uint32(mode.Perm()))
	if createErr != nil {
		e := &os.PathError{Op: "openat", Path: name, Err: createErr}
		return "", nil, WriteStep, fserrors.CategorizeErrno(e), e
	}
	f := os.NewFile(uintptr(fd), name)

	abort := func(e error) (string, os.FileInfo, AtomicWriteStep, fserrors.Category, error) {
		own, _ := f.Stat()
		_ = f.Close()
		if removeIfSame(dirfd, name, infoID(own)) {
			e = retainedForeignError(name, e)
		}
		return "", nil, WriteStep, fserrors.CategorizeErrno(e), e
	}

	if _, writeErr := f.Write(data); writeErr != nil {
		return abort(writeErr)
	}
	if chmodErr := f.Chmod(mode.Perm()); chmodErr != nil {
		return abort(chmodErr)
	}
	stagedInfo, statErr := f.Stat()
	if statErr != nil {
		return abort(statErr)
	}
	if syncErr := syncFile(f); syncErr != nil {
		return abort(syncErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		reported := error(closeErr)
		if removeIfSame(dirfd, name, infoID(stagedInfo)) {
			reported = retainedForeignError(name, reported)
		}
		return "", nil, WriteStep, fserrors.CategorizeErrno(reported), reported
	}
	return name, stagedInfo, "", "", nil
}

// tempName returns basename + ".tmp-" + 16 hex chars. The hex-only suffix can never end in ".yaml" or ".json"; the trailing assertion is defense-in-depth against future changes.
func tempName(basename string) (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("tempName: random read: %w", err)
	}
	name := basename + ".tmp-" + hex.EncodeToString(buf[:])
	if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".json") {
		return "", fmt.Errorf("tempName: generated name ends in forbidden discovery suffix: %q", name)
	}
	return name, nil
}

// WriteAtomic writes data to targetPath via a sibling temp file plus rename, fsyncing the temp file and parent directory. The parent directory must already exist. On failure it returns the step that failed and the error category.
func WriteAtomic(targetPath string, data []byte, mode os.FileMode) (step AtomicWriteStep, cat fserrors.Category, err error) {
	parentDir := filepath.Dir(targetPath)
	dirFD, openErr := os.Open(parentDir)
	if openErr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(openErr), openErr
	}
	defer dirFD.Close() //nolint:errcheck // read-only descriptor opened only to fsync the parent dir; nothing to recover from on close

	info, statErr := dirFD.Stat()
	if statErr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(statErr), statErr
	}
	if !info.IsDir() {
		notDirErr := &os.PathError{Op: "open", Path: parentDir, Err: syscall.ENOTDIR}
		return ParentSyncStep, fserrors.CategorizeErrno(notDirErr), notDirErr
	}

	name, nameErr := tempName(filepath.Base(targetPath))
	if nameErr != nil {
		return WriteStep, fserrors.IOError, nameErr
	}
	tempPath := filepath.Join(parentDir, name)

	f, createErr := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if createErr != nil {
		return WriteStep, fserrors.CategorizeErrno(createErr), createErr
	}

	if _, writeErr := f.Write(data); writeErr != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return WriteStep, fserrors.CategorizeErrno(writeErr), writeErr
	}
	if syncErr := syncFile(f); syncErr != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return WriteStep, fserrors.CategorizeErrno(syncErr), syncErr
	}
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(tempPath)
		return WriteStep, fserrors.CategorizeErrno(closeErr), closeErr
	}

	if renameErr := os.Rename(tempPath, targetPath); renameErr != nil {
		_ = os.Remove(tempPath)
		return RenameStep, fserrors.CategorizeErrno(renameErr), renameErr
	}

	if syncErr := syncDir(dirFD); syncErr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(syncErr), syncErr
	}

	return "", "", nil
}

// WriteAtomicReplaceAt writes data to targetName inside the already open parent directory, replacing
// whatever is there, and never resolves the parent by path: temp creation, the rename publish, cleanup,
// and the parent sync all run relative to parentDir. It is the descriptor-relative counterpart of
// WriteAtomic — a parent renamed or replaced after the caller opened it cannot redirect the write to a
// directory swapped in at the old path, because the held descriptor pins the inode. The published file
// carries exactly mode's permission bits regardless of the process umask. beforePublish is optional and,
// when non-nil, runs after the staged entry is durable and before anything becomes visible; its error
// aborts the publish leaving the target unchanged and no temp residue. The caller owns parentDir and
// must close it after this call. targetName must be a single path component, not a relative path.
//
// planned is the identity of the file the caller computed data from, and is what closes the gap the
// descriptor cannot: the held descriptor pins the directory, not the entry inside it, so a plain
// rename replaces whatever answers to targetName at the instant the kernel resolves it — after any
// check the caller could have made. When planned is non-nil the publish refuses, wrapping
// ErrTargetIdentityChanged and leaving both files untouched, unless the entry it displaces is that
// exact file. Pass nil only when the caller has no expectation about what occupies the name.
//
// published is the identity of the inode now answering to targetName, and it is non-nil exactly when
// publication happened — including alongside an error, because the parent fsync runs after the bytes
// are already visible and its failure does not take them back. A caller that may have to undo its own
// publish keeps it and passes it back as planned for that undo: the file it published is the only
// thing that undo may overwrite, and by then anything can occupy the name.
func WriteAtomicReplaceAt(parentDir *os.File, targetName string, data []byte, mode os.FileMode, planned os.FileInfo, beforePublish PrePublish) (step AtomicWriteStep, cat fserrors.Category, published os.FileInfo, err error) {
	if !singleComponent(targetName) {
		e := &os.PathError{Op: "rename", Path: targetName, Err: syscall.EINVAL}
		return WriteStep, fserrors.CategorizeErrno(e), nil, e
	}
	if step, cat, err := requireDir(parentDir); err != nil {
		return step, cat, nil, err
	}

	dirfd := int(parentDir.Fd())
	name, stagedInfo, step, cat, err := stageTempAt(dirfd, targetName, data, mode)
	if err != nil {
		return step, cat, nil, err
	}

	if beforePublish != nil {
		if hookErr := beforePublish(targetName, data, stagedInfo.Mode().Perm()); hookErr != nil {
			removeIfSame(dirfd, name, infoID(stagedInfo))
			return WriteStep, fserrors.CategorizeErrno(hookErr), nil, hookErr
		}
	}

	beforePublishRename()

	if step, cat, pubErr := publishReplace(dirfd, name, stagedInfo, targetName, planned); pubErr != nil {
		return step, cat, nil, pubErr
	}

	if syncErr := syncDir(parentDir); syncErr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(syncErr), stagedInfo, syncErr
	}

	return "", "", stagedInfo, nil
}

// recoverySlot is a temporary name this publish owns because it created the entry there exclusively,
// plus the identity of that entry, so a later move into the name can be confirmed to be replacing the
// publish's own placeholder rather than a file some other writer put there.
type recoverySlot struct {
	name string
	info os.FileInfo
}

// held reports whether the slot still holds the placeholder this publish created. A move into a name
// it no longer holds would destroy an unrelated file, so every use of the slot is gated on it.
func (r recoverySlot) held(dirfd int) bool {
	return sameEntryAt(dirfd, r.name, infoID(r.info))
}

func (r recoverySlot) release(dirfd int) {
	if r.held(dirfd) {
		_ = unix.Unlinkat(dirfd, r.name, 0)
	}
}

// recoveryReserveAttempts bounds the search for a free recovery name. A 64-bit random suffix makes one
// collision already improbable; several in a row means the directory is hostile or exhausted, and the
// publish must refuse rather than move the target onto a name it does not own.
const recoveryReserveAttempts = 8

// reserveRecoveryAt claims a sibling temporary name for targetName by creating an empty entry there
// with O_EXCL, retrying on a name that is already taken. The claim is what makes the later
// replace-style move safe: without it the publish would rename the target onto an unverified name and
// silently unlink whatever occupied it.
func reserveRecoveryAt(dirfd int, targetName string) (recoverySlot, error) {
	var lastErr error
	for range recoveryReserveAttempts {
		name, nameErr := recoveryName(targetName)
		if nameErr != nil {
			return recoverySlot{}, nameErr
		}
		fd, createErr := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
		if createErr != nil {
			lastErr = &os.PathError{Op: "openat", Path: name, Err: createErr}
			if errors.Is(createErr, unix.EEXIST) {
				continue
			}
			return recoverySlot{}, lastErr
		}
		f := os.NewFile(uintptr(fd), name)
		info, statErr := f.Stat()
		closeErr := f.Close()
		if statErr != nil || closeErr != nil {
			reported := closeErr
			if statErr != nil {
				reported = &os.PathError{Op: "fstat", Path: name, Err: statErr}
			}
			if removeIfSame(dirfd, name, infoID(info)) {
				reported = retainedForeignError(name, reported)
			}
			return recoverySlot{}, reported
		}
		return recoverySlot{name: name, info: info}, nil
	}
	return recoverySlot{}, lastErr
}

// publishReplace makes the staged entry visible as targetName. Without a planned identity it renames
// over the target. With one it uses the same identity-verified displace-and-link route on every
// platform.
func publishReplace(dirfd int, staged string, stagedInfo os.FileInfo, targetName string, planned os.FileInfo) (AtomicWriteStep, fserrors.Category, error) {
	if planned == nil {
		if renameErr := unix.Renameat(dirfd, staged, dirfd, targetName); renameErr != nil {
			removeIfSame(dirfd, staged, infoID(stagedInfo))
			e := &os.LinkError{Op: "renameat", Old: staged, New: targetName, Err: renameErr}
			return RenameStep, fserrors.CategorizeErrno(e), e
		}
		return "", "", nil
	}

	recovery, nameErr := reserveRecoveryAt(dirfd, targetName)
	if nameErr != nil {
		removeIfSame(dirfd, staged, infoID(stagedInfo))
		return RenameStep, fserrors.CategorizeErrno(nameErr), nameErr
	}
	return publishReplaceDisplacing(dirfd, staged, stagedInfo, targetName, recovery, planned)
}

// publishReplaceDisplacing renames the target aside first, so the identity comparison runs on an entry nothing
// can reach by the target name, then publishes with a no-replace link, which fails rather than
// overwrite anything that appeared in the interval where the target name was unoccupied. That
// interval is the accepted cost of using one publish route on every platform.
//
// slot is the recovery name the caller already reserved, so the move aside replaces this publish's own
// placeholder rather than an entry another writer happens to occupy.
//
// stagedInfo is the identity of the entry the caller staged. Both scratch names are sibling entries in
// a directory any other writer of it can see, so neither is removed on the strength of the name alone:
// every removal is gated on the entry still being the inode this call put there.
func publishReplaceDisplacing(dirfd int, staged string, stagedInfo os.FileInfo, targetName string, slot recoverySlot, planned os.FileInfo) (AtomicWriteStep, fserrors.Category, error) {
	if !slot.held(dirfd) {
		fresh, reserveErr := reserveRecoveryAt(dirfd, targetName)
		if reserveErr != nil {
			removeIfSame(dirfd, staged, infoID(stagedInfo))
			return RenameStep, fserrors.CategorizeErrno(reserveErr), reserveErr
		}
		slot = fresh
	}
	aside := slot.name

	if renameErr := unix.Renameat(dirfd, targetName, dirfd, aside); renameErr != nil {
		slot.release(dirfd)
		removeIfSame(dirfd, staged, infoID(stagedInfo))
		reported := renameErr
		if errors.Is(renameErr, unix.ENOENT) {
			reported = ErrTargetIdentityChanged
		}
		e := &os.LinkError{Op: "renameat", Old: targetName, New: aside, Err: reported}
		return RenameStep, fserrors.CategorizeErrno(e), e
	}

	// The entry now answering to aside is the one this call moved off the target name; asideID is what
	// every later removal of that name is checked against. An unread identity is never treated as a
	// match, so the entry is retained rather than removed.
	asideID, _ := entryIDAt(dirfd, aside)

	unreconciled := func(retained string) (AtomicWriteStep, fserrors.Category, error) {
		e := &os.LinkError{Op: "linkat", Old: retained, New: targetName, Err: ErrPublishUnreconciled}
		return RenameStep, fserrors.CategorizeErrno(e), e
	}

	// Putting the displaced entry back has to use the same no-replace link as the publish: a rename
	// would silently destroy whatever occupies the name now, which is the outcome this whole path
	// exists to prevent. When even that is impossible the original is left under aside and named in
	// the error, because retaining it somewhere reconcilable beats deleting it.
	restore := func() (AtomicWriteStep, fserrors.Category, error) {
		beforeCleanup()
		stagedRetained := removeIfSame(dirfd, staged, infoID(stagedInfo))
		if asideID.known && !sameEntryAt(dirfd, aside, asideID) {
			return unreconciled(aside)
		}
		if linkErr := unix.Linkat(dirfd, aside, dirfd, targetName, 0); linkErr != nil {
			return unreconciled(aside)
		}
		if removeIfSame(dirfd, aside, asideID) {
			return unreconciled(aside)
		}
		if stagedRetained {
			return unreconciled(staged)
		}
		e := &os.LinkError{Op: "linkat", Old: staged, New: targetName, Err: ErrTargetIdentityChanged}
		return RenameStep, fserrors.CategorizeErrno(e), e
	}

	if !infoID(planned).matches(asideID) {
		return restore()
	}
	if linkErr := unix.Linkat(dirfd, staged, dirfd, targetName, 0); linkErr != nil {
		return restore()
	}

	// The bytes are visible at the target name, so this publish has succeeded and must not report
	// otherwise. A scratch name another writer took in the meantime is left alone; the leftover is
	// theirs to own, and calling a completed publish a failure is the worse error.
	beforeCleanup()
	removeIfSame(dirfd, staged, infoID(stagedInfo))
	removeIfSame(dirfd, aside, asideID)
	return "", "", nil
}

// fileID identifies a directory entry by the device and inode numbers of the inode behind it. The zero
// value identifies nothing and never compares equal to anything, so an identity that could not be read
// is never mistaken for a match.
type fileID struct {
	dev   uint64
	ino   uint64
	known bool
}

// matches reports whether both identities were read and describe the same inode.
func (id fileID) matches(other fileID) bool {
	return id.known && other.known && id == other
}

// infoID reads the identity out of a FileInfo obtained by stat-ing the file itself (os.Stat, or Stat on
// an open descriptor). An unknown Sys() yields the zero identity rather than a wrong match.
func infoID(info os.FileInfo) fileID {
	if info == nil {
		return fileID{}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino), known: true}
}

// entryIDAt reads the identity of name under dirfd. It stats the name rather than opening it because a
// staged entry carries exactly the permission bits the caller asked for: a mode without read permission
// — a create under a restrictive umask, an edit preserving a 0200 file — makes an O_RDONLY open of this
// call's own temporary entry fail with EACCES, which cleanup would then have to read as another
// writer's file and leave behind on an otherwise successful publish. AT_SYMLINK_NOFOLLOW keeps what
// O_NOFOLLOW gave the open: a symlink dropped in place is described by its own identity, never the one
// it points at, so it can never compare equal to the regular file this call staged. The error is
// returned so callers can tell an absent name from one they could not inspect.
func entryIDAt(dirfd int, name string) (fileID, error) {
	var st unix.Stat_t
	if serr := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
		return fileID{}, &os.PathError{Op: "fstatat", Path: name, Err: serr}
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino), known: true}, nil
}

// sameEntryAt reports whether name under dirfd is the exact file planned identifies. It answers no for
// anything it cannot stat, so an entry it cannot inspect is never accepted as the planned one.
func sameEntryAt(dirfd int, name string, planned fileID) bool {
	id, err := entryIDAt(dirfd, name)
	if err != nil {
		return false
	}
	return planned.matches(id)
}

// removeIfSame unlinks name under dirfd only while it still holds the inode expected identifies, and
// reports whether an entry this call did not put there was left in place instead. That answer is what
// a caller surfaces as an unreconciled publish: a scratch name is an ordinary sibling entry, so a
// writer who takes it between the last check and this one must not have their file deleted. A name
// that no longer exists is neither removed nor reported, because nothing is retained there.
func removeIfSame(dirfd int, name string, expected fileID) (retainedForeign bool) {
	id, err := entryIDAt(dirfd, name)
	if err != nil {
		return !errors.Is(err, unix.ENOENT)
	}
	if expected.matches(id) {
		_ = unix.Unlinkat(dirfd, name, 0)
		return false
	}
	return true
}

// retainedForeignError wraps a failure whose cleanup kept name in place because it could not prove the
// entry there was the one this call staged. Both the cause and ErrPublishUnreconciled stay reachable
// with errors.Is, so a caller can tell a plain failure from one that left something behind.
func retainedForeignError(name string, cause error) error {
	return fmt.Errorf("%w: %s: %w", ErrPublishUnreconciled, name, cause)
}

// WriteAtomicCreateAt writes data to targetName only when nothing already exists there, using an already
// open parent directory. It never resolves the parent by path: temp creation, no-replace publish, cleanup,
// and parent sync all operate relative to parentDir. It is the create-only counterpart of WriteAtomic:
// where WriteAtomic publishes with os.Rename (which silently overwrites an existing target), this
// publishes with a hard link, which fails if targetName already exists — so a target that materialized
// between a caller's pre-authorization check and the publish is never clobbered. The published file
// carries exactly mode's permission bits regardless of the process umask. Every returned failure
// leaves no target and no temp residue. The caller owns parentDir and must close it after this call.
// targetName must be a single path component, not a relative path.
//
// beforePublish is at most one optional pre-publish hook; passing none is the plain publish. It is
// variadic so the path-free create callers that predate the hook keep compiling unchanged.
//
// published is the identity of the inode this call linked at targetName, and it is non-nil exactly
// when those bytes became visible under that name — including alongside a parent-sync failure, whose
// compensating removal happens after the entry was already reachable. A caller that has to reconcile
// or undo the create identifies it by that inode and never by the name, because another writer can
// replace the name between publication and the reconciliation.
func WriteAtomicCreateAt(parentDir *os.File, targetName string, data []byte, mode os.FileMode, beforePublish ...PrePublish) (step AtomicWriteStep, cat fserrors.Category, published os.FileInfo, err error) {
	var hook PrePublish
	if len(beforePublish) > 0 {
		hook = beforePublish[0]
	}
	return writeAtomicCreateInDir(parentDir, targetName, data, mode, hook)
}

func writeAtomicCreateInDir(parentDir *os.File, targetName string, data []byte, mode os.FileMode, beforePublish PrePublish) (step AtomicWriteStep, cat fserrors.Category, published os.FileInfo, err error) {
	if !singleComponent(targetName) {
		err := &os.PathError{Op: "create", Path: targetName, Err: syscall.EINVAL}
		return WriteStep, fserrors.CategorizeErrno(err), nil, err
	}

	if step, cat, err := requireDir(parentDir); err != nil {
		return step, cat, nil, err
	}

	dirfd := int(parentDir.Fd())
	name, stagedInfo, step, cat, err := stageTempAt(dirfd, targetName, data, mode)
	if err != nil {
		return step, cat, nil, err
	}

	if beforePublish != nil {
		if hookErr := beforePublish(targetName, data, stagedInfo.Mode().Perm()); hookErr != nil {
			removeIfSame(dirfd, name, infoID(stagedInfo))
			return WriteStep, fserrors.CategorizeErrno(hookErr), nil, hookErr
		}
	}

	// No-replace publish: linkat fails with EEXIST if targetName already exists, so create never overwrites
	// — unlike rename, which would replace it. The temp name is then unlinked; the target keeps the inode.
	if linkErr := unix.Linkat(dirfd, name, dirfd, targetName, 0); linkErr != nil {
		removeIfSame(dirfd, name, infoID(stagedInfo))
		err := &os.LinkError{Op: "linkat", Old: name, New: targetName, Err: linkErr}
		return LinkStep, fserrors.CategorizeErrno(err), nil, err
	}
	removeIfSame(dirfd, name, infoID(stagedInfo))

	if syncErr := syncDir(parentDir); syncErr != nil {
		// The file data was fsynced and published, but the parent-directory entry is not durable.
		// Unlike WriteAtomic — which overwrote prior bytes and has nothing to roll back — create's
		// contract is that a failed create leaves no target, so the published name is removed
		// before the failure is reported. It is removed only while it still holds the inode this call
		// published: another writer can replace that name in the sync window, and deleting their file
		// would destroy data this call never staged.
		reported := error(syncErr)
		if removeIfSame(dirfd, targetName, infoID(stagedInfo)) {
			reported = retainedForeignError(targetName, reported)
		}
		return ParentSyncStep, fserrors.CategorizeErrno(reported), stagedInfo, reported
	}

	return "", "", stagedInfo, nil
}
