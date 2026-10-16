package config

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
)

// PersistReason classifies the outcome of a Persist call in the
// vocabulary shared with the permission/model persist-failure events. ReasonNone
// covers a successful write; every other value is a distinct failure path.
type PersistReason string

const (
	ReasonNone             PersistReason = "none"
	ReasonLockTimeout      PersistReason = "lock_timeout"
	ReasonLockAcquireError PersistReason = "lock_acquire_error"
	ReasonRereadParseError PersistReason = "reread_parse_error"
	ReasonRereadIOError    PersistReason = "reread_io_error"
	ReasonWriteError       PersistReason = "write_error"
	ReasonRenameError      PersistReason = "rename_error"
	ReasonParentDirError   PersistReason = "parent_dir_error"
)

// lockTimeout is the step (1) lock-acquisition timeout. Production
// always uses 2 seconds; tests force lock outcomes through the acquireLock seam
// rather than waiting on a real timeout.
const lockTimeout = 2 * time.Second

// lockSuffix is appended to targetPath to form the dedicated sidecar lock file
// per step (1). The advisory lock is bound to this sidecar's
// inode, which is never the target of an atomic rename, so all writers serialize
// over the whole read-modify-write window regardless of how often the settings
// file's inode is replaced.
const lockSuffix = ".lock"

// Test seams for the dependencies whose failure modes Persist cannot
// force deterministically through plain filesystem setup: the cross-process
// lock acquire, the locked re-read/validate, and the merge+atomic-write.
// beforeParentSegment runs before each directory component Persist opens or
// creates on the way to the target's parent, so a test can swap that component.
// Production code uses the real functions; tests must restore the seam.
var (
	acquireLock         = locks.AcquireAt
	rereadSettings      = readSettings
	mergeWrite          = rewriteKeyAt
	beforeParentSegment = func(string) {}
)

func readSettings(dir *os.File, path string) (fsutil.FileSnapshot, map[string]any, LoadFailure, error) {
	snap, err := fsutil.SnapshotFileAt(dir, filepath.Base(path), math.MaxInt64)
	if err != nil {
		return fsutil.FileSnapshot{}, nil, UnreadableFile, err
	}
	if !snap.Exists {
		return snap, nil, LoadOK, nil
	}
	_, raw, cat, err := LoadYAMLBytes(snap.Data, path)
	return snap, raw, cat, err
}

// dir itself and every component created under it are opened without following
// a symlink; the existing ancestor they hang from may still be reached through one.
func openParentDir(dir string) (*os.File, fserrors.Category, error) {
	dir = filepath.Clean(dir)
	segs := []string{filepath.Base(dir)}
	anc := filepath.Dir(dir)
	var fd int
	for {
		var err error
		fd, err = unix.Open(anc, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.ENOENT) || filepath.Dir(anc) == anc {
			e := &os.PathError{Op: "open", Path: anc, Err: err}
			return nil, fserrors.CategorizeErrno(e), e
		}
		segs = append([]string{filepath.Base(anc)}, segs...)
		anc = filepath.Dir(anc)
	}

	cur := os.NewFile(uintptr(fd), anc)
	for _, seg := range segs {
		path := filepath.Join(cur.Name(), seg)
		beforeParentSegment(path)
		if err := unix.Mkdirat(int(cur.Fd()), seg, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = cur.Close()
			e := &os.PathError{Op: "mkdirat", Path: path, Err: err}
			return nil, fserrors.CategorizeErrno(e), e
		}
		next, err := unix.Openat(int(cur.Fd()), seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = cur.Close()
		if err != nil {
			e := &os.PathError{Op: "openat", Path: path, Err: err}
			return nil, fserrors.CategorizeErrno(e), e
		}
		cur = os.NewFile(uintptr(next), path)
	}
	return cur, "", nil
}

// Persist is the single internal chokepoint for every folder/global permission
// write and every model.active/model.last_used write, implementing the
// protocol: ensure the parent directory, take a
// 2-second advisory lock on the dedicated sidecar lock file (targetPath+".lock"),
// re-read and validate the latest contents, byte-preservingly merge newValue into
// key, write atomically, and release the lock. newValue is the matching payload
// RewriteKey expects for key. For KeyPermissions that is either a permissions.PermissionEntry to
// append an entry or a PermissionDelete(dedupKey) sentinel to remove one — both
// take this same sidecar-lock + re-read-validate + atomic-replace path. The model
// keys take a yaml-marshalable value.
//
// The lock is held on the sidecar — never on targetPath itself — because every
// write replaces the settings file's inode via atomic rename,
// which would orphan a lock taken on that inode and break mutual exclusion for
// three or more concurrent writers. The lock does NOT create the
// settings file; an absent settings file is created by RewriteKey's atomic write
// under the held lock ("Create-file-if-absent").
//
// On success it returns (ReasonNone, "", nil). On failure it returns the
// reason, the error category, and the underlying error. lock_timeout and
// reread_parse_error carry no category (the failure did not originate in an OS
// file syscall); every other failure carries the category observed by the helper
// that hit the OS error. For reason reread_parse_error, reread_io_error,
// lock_timeout, or lock_acquire_error the merge/write is skipped entirely and the
// existing file is left untouched (special branch).
//
// targetPath is treated as final: callers snapshot the project-root path when the
// triggering prompt is raised ("write-target snapshot") and pass it in
// Persist does not re-resolve project root. The TUI notice and the
// persist-failure event are the caller's responsibility, so Persist
// performs no logging or event emission of its own.
func Persist(targetPath, key string, newValue any) (reason PersistReason, errCat fserrors.Category, err error) {
	// (1a) Hold the parent directory, creating it if absent; every later step runs
	// relative to this descriptor so a parent swapped after the open is never touched.
	parent, dirCat, derr := openParentDir(filepath.Dir(targetPath))
	if derr != nil {
		return ReasonParentDirError, dirCat, derr
	}
	defer parent.Close() //nolint:errcheck // read-only directory descriptor

	// (1b) Acquire the advisory lock on the sidecar lock file (step (1)).
	// acquireLock O_CREATEs the absent sidecar at mode
	// 0600 before locking; a create-and-lock failure surfaces through the lock
	// path as lock_acquire_error / lock_timeout, never write_error / rename_error.
	// On either lock failure the merge cannot proceed and the lock was never
	// held, so the write is skipped.
	release, lockReason, lockErr := acquireLock(parent, filepath.Base(targetPath)+lockSuffix, lockTimeout)
	switch lockReason {
	case locks.ReasonLockTimeout:
		return ReasonLockTimeout, "", lockErr
	case locks.ReasonLockAcquireError:
		return ReasonLockAcquireError, fserrors.CategorizeErrno(lockErr), lockErr
	}
	defer release()

	// (2) Re-read and validate the latest contents under the lock. Holding the
	// sidecar lock does not imply the settings file exists: an absent
	// settings file is an empty document, so the merge/write below creates it
	// while the lock is held. A symlinked or non-regular settings file and a
	// genuine OS read failure are reread_io_error; a parse or schema failure is
	// reread_parse_error. Both skip the write so the file is left untouched.
	source, raw, cat, rerr := rereadSettings(parent, targetPath)
	if cat != LoadOK {
		switch cat {
		case UnreadableFile:
			return ReasonRereadIOError, fserrors.CategorizeErrno(rerr), rerr
		default:
			// YAMLParseError or SchemaValidationError (malformed,
			// truncated, or schema-invalid contents).
			return ReasonRereadParseError, "", rerr
		}
	}

	if op, isFavorite := newValue.(*favoriteToggleValue); isFavorite {
		if op == nil {
			return ReasonRereadParseError, "", errors.New("config.Persist: model.favorites payload is nil")
		}
		if perr := op.prepare(raw); perr != nil {
			return ReasonRereadParseError, "", perr
		}
	}

	// (3)-(4) Merge newValue into key and write atomically, creating an absent file,
	// all under the held lock; the locked re-read above is the validation gate that
	// decides whether the merge may run at all.
	step, writeCat, werr := mergeWrite(parent, targetPath, source, key, newValue)
	if werr != nil {
		r, c := mapWriteStep(step, writeCat, werr)
		return r, c, werr
	}
	return ReasonNone, "", nil
}

// mapWriteStep maps a failed atomic-write/rewrite step to its reason and
// the error category to surface. The three write-family steps propagate the
// helper's category unchanged (sources error_category from the
// atomic-write helper, never from re-derived error strings). A LoadStep — which
// RewriteKey may return defensively for a pre-write failure the locked re-read
// should already have caught — is split by error shape: an error wrapping a
// syscall.Errno is I/O-shaped and keeps its category (reread_io_error); anything
// else is parse-shaped and carries no category (reread_parse_error).
func mapWriteStep(step fsutil.AtomicWriteStep, cat fserrors.Category, err error) (PersistReason, fserrors.Category) {
	switch step {
	case fsutil.WriteStep:
		return ReasonWriteError, cat
	case fsutil.RenameStep:
		return ReasonRenameError, cat
	case fsutil.ParentSyncStep:
		return ReasonParentDirError, cat
	case fsutil.LoadStep:
		if ioShaped(err) {
			return ReasonRereadIOError, cat
		}
		return ReasonRereadParseError, ""
	default:
		// WriteAtomic and RewriteKey always return a non-empty step alongside a
		// non-nil error, so this is unreachable; treat any unexpected step as a
		// write error so no failure is silently dropped.
		return ReasonWriteError, cat
	}
}

// ioShaped reports whether err wraps a syscall.Errno, marking it as an OS-level
// I/O failure rather than a YAML parse/structure failure.
func ioShaped(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno)
}
