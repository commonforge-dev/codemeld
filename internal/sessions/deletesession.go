// Explicit session deletion plus the shared lock-and-unlink core the retention pruner reuses.
package sessions

import (
	"fmt"
	"os"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
)

// deleteSessionUnderLock takes the session's dedicated sidecar lock non-blockingly
// and, with it held, unlinks the session file and then the sidecar lock file (the
// lock ordering). It is the shared core of prune's tryDeleteExpired and the
// explicit DeleteSession, so the two can never drift on lock probing or sidecar
// handling.
//
// reason reports the lock outcome. locks.ReasonNone means the lock was taken and the
// unlink attempted — cat/err then carry the unlink result (("", nil) on success, the
// category plus the error on a session-file unlink failure). A non-None reason
// means the file was left untouched: locks.ReasonLockContended for a lock held by
// another instance (err nil), or locks.ReasonLockAcquireError for a lock-syscall
// failure (err carries it). The sidecar unlink, once the session file is gone, is
// best-effort and untracked — the candidate is already deleted, so no new failure is
// invented.
func deleteSessionUnderLock(sessionPath string) (reason locks.LockReason, cat fserrors.Category, err error) {
	lockPath := ResumeLockPath(sessionPath)
	release, lockReason, lockErr := locks.TryAcquire(lockPath)
	if lockReason != locks.ReasonNone {
		return lockReason, "", lockErr
	}
	defer release()

	if rmErr := os.Remove(sessionPath); rmErr != nil {
		return locks.ReasonNone, fserrors.CategorizeErrno(rmErr), rmErr
	}
	// Unlink the sidecar while the lock is still held: this orphans only
	// that inode, and because the session file is gone no live session loses its lock.
	// The deferred release runs immediately after.
	_ = os.Remove(lockPath)
	return locks.ReasonNone, "", nil
}

// lockContentionCategory maps a non-None TryAcquire outcome on a session sidecar lock
// to the category and error surfaced by the SetTitle / DeleteSession picker
// actions: a lock held by another codemeld instance is fserrors.InUse, and any other
// acquire failure carries its syscall category. Call only when reason != ReasonNone.
func lockContentionCategory(sessionPath string, reason locks.LockReason, lockErr error) (fserrors.Category, error) {
	if reason == locks.ReasonLockContended {
		return fserrors.InUse, fmt.Errorf("session %s in use by another codemeld instance", sessionPath)
	}
	return fserrors.CategorizeErrno(lockErr), fmt.Errorf("session %s: lock acquisition failed: %w", sessionPath, lockErr)
}

// DeleteSession removes the session file at path and its dedicated sidecar lock behind
// the same non-blocking sidecar lock the retention pruner uses, so an
// explicit delete and a concurrent prune or resume cannot drift on lock or sidecar
// handling. It is the persistence behind the /resume picker's delete action.
//
// It returns the error category and a non-nil error on failure, or ("", nil)
// on success. A lock already held by another codemeld instance (the session is being
// resumed elsewhere) is refused with fserrors.InUse and the file is left intact; any
// other lock-acquire failure returns its categorized error; a session-file unlink
// failure returns the unlink's category.
func DeleteSession(path string) (fserrors.Category, error) {
	reason, cat, err := deleteSessionUnderLock(path)
	if reason != locks.ReasonNone {
		return lockContentionCategory(path, reason, err)
	}
	if err != nil {
		return cat, fmt.Errorf("delete session %s: %w", path, err)
	}
	return "", nil
}
