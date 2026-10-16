// Per-session advisory lock taken on --resume before the updated_at refresh.
package sessions

import (
	"fmt"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
)

// resumeLockTimeout is the lock-acquisition timeout. Production always
// uses two seconds; tests force lock outcomes through the acquireLock seam rather
// than waiting on a real timeout.
const resumeLockTimeout = 2 * time.Second

// lockSuffix forms the dedicated sidecar lock-file path from a session file path.
// The lock binds to this sidecar's inode, which
// no atomic rename ever replaces, so resumers and the retention pruner serialize
// even though per-turn writes and the updated_at refresh swap the session file's
// inode via temp+rename.
const lockSuffix = ".lock"

// acquireLock is the test seam for the cross-process lock acquire; production uses
// locks.Acquire. Tests swap it to force a lock_acquire_error without
// platform-specific filesystem tricks, then restore it.
var acquireLock = locks.Acquire

// ResumeLockPath returns the dedicated sidecar lock-file path (<session-file>.lock)
// for sessionPath. The --resume advisory lock and the retention
// pruner's non-blocking pre-unlink lock MUST both derive their
// target through this one helper: the lock cannot bind to the session file itself
// because per-turn writes and the updated_at refresh replace that inode via atomic
// temp+rename, which would orphan the lock and break cross-instance
// mutual exclusion.
func ResumeLockPath(sessionPath string) string {
	return sessionPath + lockSuffix
}

// ResumeLockError is the typed failure returned by AcquireResumeLock when the
// per-session lock cannot be taken. Its Error renders the exact stderr
// line for the failure reason, which the CLI prints before exiting with code 1.
// Reason is locks.ReasonLockTimeout or locks.ReasonLockAcquireError;
// Cat carries the error category for the acquire-error line and is empty
// for a timeout; Err is the underlying lock error, exposed via Unwrap.
type ResumeLockError struct {
	ID     string
	Reason locks.LockReason
	Cat    fserrors.Category
	Err    error
}

func (e *ResumeLockError) Error() string {
	if e.Reason == locks.ReasonLockTimeout {
		return fmt.Sprintf("codemeld: session %s in use by another codemeld instance", e.ID)
	}
	return fmt.Sprintf("codemeld: session %s: lock acquisition failed: %s", e.ID, e.Cat)
}

func (e *ResumeLockError) Unwrap() error { return e.Err }

// AcquireResumeLock takes the exclusive per-session advisory lock required on
// resume before the updated_at refresh. It
// locks the session file's dedicated sidecar — ResumeLockPath(sessionPath) — for
// up to two seconds via the same kernel mechanism as; id names the session
// for the failure line only. On success it returns a non-nil release and a nil
// error: the caller holds release for the lifetime of the run and calls it on exit
// (the kernel also releases the lock if the process dies, so no per-turn re-lock is
// needed). A contended lock returns a *ResumeLockError with ReasonLockTimeout; any
// other lock-syscall failure returns one with ReasonLockAcquireError and the
// observed error category. Per-turn session writes (Store.Flush) never re-acquire
// this lock, so lock_timeout / lock_acquire_error cannot surface on a
// session_write_failed event.
func AcquireResumeLock(sessionPath, id string) (release func(), err error) {
	release, reason, lockErr := acquireLock(ResumeLockPath(sessionPath), resumeLockTimeout)
	switch reason {
	case locks.ReasonLockTimeout:
		return nil, &ResumeLockError{ID: id, Reason: reason, Err: lockErr}
	case locks.ReasonLockAcquireError:
		return nil, &ResumeLockError{ID: id, Reason: reason, Cat: fserrors.CategorizeErrno(lockErr), Err: lockErr}
	}
	return release, nil
}
