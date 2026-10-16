package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"codemeld.dev/codemeld/internal/fserrors"
	"golang.org/x/sys/unix"
)

// ErrNoReplaceUnsupported reports that the running platform has no atomic no-overwrite rename
// primitive, so MoveNoReplace cannot move safely. The helper fails closed with this rather than
// emulating no-overwrite as a preflight stat plus a plain rename, which would clobber a destination
// that materializes after the check. Consumers detect it with errors.Is.
var ErrNoReplaceUnsupported = errors.New("fsutil: atomic no-overwrite rename is unsupported on this platform")

// ErrParentMoved reports that a source or destination parent directory was renamed or replaced
// while MoveNoReplace ran, so the helper cannot confirm the entry landed at the authorized path.
// Consumers detect it with errors.Is. The helper rolls the rename back (best effort) before
// returning this, so a move reported as failed did not silently relocate the entry.
var ErrParentMoved = errors.New("fsutil: a parent directory was renamed or replaced during the move")

// renameNoReplaceAt is the package-local seam for the platform no-overwrite rename primitive.
// move_linux.go and move_unsupported.go provide the build-tagged renameNoReplaceAtSyscall; tests
// swap this var via SetRenameNoReplaceAtForTest to force the unsupported and cross-device paths
// without a real second filesystem.
var renameNoReplaceAt = renameNoReplaceAtSyscall

// beforeMoveRename is a test-only seam fired after both parent descriptors are held but before the
// rename, so a test can rename or replace a parent mid-operation and exercise the parent guard.
// Production runs the no-op default.
// intentional: test-only seam (no production caller by design).
var beforeMoveRename = func() {}

// SetRenameNoReplaceAtForTest replaces the platform no-overwrite rename seam with fn and returns a
// restorer the caller MUST run to put the production seam back. Test-only; production must not call it.
// intentional: test-only seam (no production caller by design).
func SetRenameNoReplaceAtForTest(fn func(oldDirFd int, oldName string, newDirFd int, newName string) error) func() {
	orig := renameNoReplaceAt
	renameNoReplaceAt = fn
	return func() { renameNoReplaceAt = orig }
}

// SetBeforeMoveRenameForTest replaces the pre-rename hook with fn and returns a restorer the caller
// MUST run to put the no-op default back. Test-only; production must not call it.
// intentional: test-only seam (no production caller by design).
func SetBeforeMoveRenameForTest(fn func()) func() {
	orig := beforeMoveRename
	beforeMoveRename = fn
	return func() { beforeMoveRename = orig }
}

// MoveNoReplace renames src to dst on the same filesystem and never overwrites an existing
// destination. It opens both parent directories without following a final symlink and performs the
// rename relative to those held descriptors using an atomic no-replace primitive, so the operation
// cannot be redirected by a symlink swap and a destination that materializes after a caller's
// preflight is never clobbered. It is same-filesystem only: a cross-device attempt fails with the
// kernel's EXDEV and the helper never falls back to copy+unlink. After the rename it revalidates
// that each held parent is still the directory reachable at its path (os.SameFile), rolling the
// rename back and failing closed if a parent moved mid-operation. The caller owns no descriptors;
// MoveNoReplace opens and closes everything it uses.
//
// On failure it returns the step that failed and the error category. The underlying error is
// returned alongside so a consumer can branch without parsing strings: an existing destination wraps
// fs.ErrExist (RenameStep), a missing source wraps fs.ErrNotExist (RenameStep), a cross-device
// attempt wraps syscall.EXDEV (RenameStep), an unsupported platform wraps ErrNoReplaceUnsupported
// (RenameStep), and a parent that moved wraps ErrParentMoved (ParentSyncStep). The zero step and
// empty category mean success.
func MoveNoReplace(src, dst string, observe ...MoveLifecycle) (step AtomicWriteStep, cat fserrors.Category, err error) {
	var lifecycle MoveLifecycle
	if len(observe) > 0 {
		lifecycle = observe[0]
	}
	srcParent, srcName, verr := splitMoveEndpoint(src)
	if verr != nil {
		return RenameStep, fserrors.CategorizeErrno(verr), verr
	}
	dstParent, dstName, verr := splitMoveEndpoint(dst)
	if verr != nil {
		return RenameStep, fserrors.CategorizeErrno(verr), verr
	}

	srcParentFD, oerr := os.OpenFile(srcParent, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(oerr), oerr
	}
	defer srcParentFD.Close() //nolint:errcheck // read-only descriptor held only to rename relative to / re-identify the parent

	dstParentFD, oerr := os.OpenFile(dstParent, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return ParentSyncStep, fserrors.CategorizeErrno(oerr), oerr
	}
	defer dstParentFD.Close() //nolint:errcheck // read-only descriptor held only to rename relative to / re-identify the parent

	beforeMoveRename()

	if lifecycle.BeforeRename != nil {
		if berr := lifecycle.BeforeRename(srcParentFD, dstParentFD); berr != nil {
			return RenameStep, fserrors.CategorizeErrno(berr), berr
		}
	}
	if lifecycle.AfterRename != nil {
		defer lifecycle.AfterRename(srcParentFD, dstParentFD)
	}

	if rerr := renameNoReplaceAt(int(srcParentFD.Fd()), srcName, int(dstParentFD.Fd()), dstName); rerr != nil {
		le := &os.LinkError{Op: "renameat2", Old: src, New: dst, Err: rerr}
		return RenameStep, fserrors.CategorizeErrno(le), le
	}

	if !sameDir(srcParentFD, srcParent) || !sameDir(dstParentFD, dstParent) {
		// The rename ran relative to the held parent inodes, so a parent renamed or replaced
		// mid-operation would land the entry under an inode no longer reachable at the authorized
		// path. Roll the rename back through the held descriptors (best effort) and fail closed
		// rather than report a move at a path the entry is not located at.
		_ = renameNoReplaceAt(int(dstParentFD.Fd()), dstName, int(srcParentFD.Fd()), srcName)
		le := &os.LinkError{Op: "renameat2", Old: src, New: dst, Err: ErrParentMoved}
		return ParentSyncStep, fserrors.CategorizeErrno(le), le
	}

	return "", "", nil
}

// AfterRename runs once the rename and any rollback of it have finished, whether or not the move
// succeeded.
type MoveLifecycle struct {
	BeforeRename func(srcParent, dstParent *os.File) error
	AfterRename  func(srcParent, dstParent *os.File)
}

func RenameNoReplaceAt(oldDir *os.File, oldName string, newDir *os.File, newName string) error {
	return renameNoReplaceAt(int(oldDir.Fd()), oldName, int(newDir.Fd()), newName)
}

// splitMoveEndpoint validates an absolute move endpoint and splits it into its parent directory and
// single final component. It rejects relative paths and degenerate names (".", "..", the path
// separator) so the rename can run as a single-component operation relative to a held parent fd.
func splitMoveEndpoint(path string) (parent, name string, err error) {
	if !filepath.IsAbs(path) {
		return "", "", &os.PathError{Op: "rename", Path: path, Err: syscall.EINVAL}
	}
	parent = filepath.Dir(path)
	name = filepath.Base(path)
	if name == "" || name == "." || name == ".." || name == string(os.PathSeparator) {
		return "", "", &os.PathError{Op: "rename", Path: path, Err: syscall.EINVAL}
	}
	return parent, name, nil
}

// sameDir reports whether parentPath still resolves to the directory held by the descriptor. A held
// fd pins an inode regardless of path renames, so comparing the held inode with a fresh O_NOFOLLOW
// open of the path (os.SameFile) detects a parent that was renamed or replaced during the move.
func sameDir(held *os.File, parentPath string) bool {
	fresh, oerr := os.OpenFile(parentPath, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return false
	}
	defer fresh.Close() //nolint:errcheck // read-only descriptor opened only to compare directory identity
	heldInfo, herr := held.Stat()
	freshInfo, ferr := fresh.Stat()
	if herr != nil || ferr != nil {
		return false
	}
	return os.SameFile(heldInfo, freshInfo)
}
