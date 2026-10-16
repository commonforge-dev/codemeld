// Package locks wraps gofrs/flock with typed-reason acquire helpers for the kernel-managed advisory locks required by and 440b, plus a non-blocking single-attempt try (TryAcquire) for the retention pruner.
package locks

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/sys/unix"
)

// LockReason classifies the outcome of an acquire attempt, in the vocabulary shares with. ReasonNone covers a successful acquire.
type LockReason string

const (
	ReasonNone             LockReason = "none"
	ReasonLockTimeout      LockReason = "lock_timeout"
	ReasonLockContended    LockReason = "lock_contended"
	ReasonLockAcquireError LockReason = "lock_acquire_error"
)

// lockFileMode is the permission mode applied when Acquire materializes a missing lock target. The lock file is a dedicated sidecar (e.g. settings.yaml.lock, <session>.json.lock) that guards owner-only data, so it is owner-only too — never group/world-readable.
const lockFileMode = 0o600

// retryDelay is the TryLockContext retry interval. Short enough that the 2-second production timeout is observed promptly; long enough to avoid busy-looping under contention.
const retryDelay = 25 * time.Millisecond

// lockHandle abstracts gofrs/flock's *Flock so tests can force lock-syscall failures without platform-specific filesystem tricks. TryLock is the single-attempt, no-wait primitive TryAcquire builds on; TryLockContext is the retrying primitive Acquire builds on.
type lockHandle interface {
	TryLock() (bool, error)
	TryLockContext(ctx context.Context, retryDelay time.Duration) (bool, error)
	Close() error
}

// newLock is the test seam that builds the lock handle for path. Production code wraps gofrs/flock; tests can substitute a stub that returns a configured error.
var newLock = func(path string) lockHandle {
	return flock.New(path, flock.SetPermissions(lockFileMode))
}

// Acquire takes an exclusive advisory lock on path with the given acquisition timeout. Production callers (step (1) and 440b) pass 2*time.Second; tests may pass a shorter duration.
//
// On success, release closes the underlying lock object — which unlocks the file and closes the file descriptor — and reason is ReasonNone. On timeout, reason is ReasonLockTimeout and err is the context deadline error. On any other lock-syscall failure, reason is ReasonLockAcquireError and err is the underlying error so callers can map it to the error-category vocabulary.
//
// This helper locks exactly the path it is given and does not own the data file. Callers pass a dedicated sidecar lock path (`<settings>.lock`, `<session>.json.lock`) that is never the target of an atomic rename, per step (1) — locking the renamed-over data file would not provide cross-process mutual exclusion. If the lock file does not exist, gofrs/flock creates it at mode 0600 before attempting the lock.
func Acquire(path string, timeout time.Duration) (release func(), reason LockReason, err error) {
	lock := newLock(path)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ok, lockErr := lock.TryLockContext(ctx, retryDelay)
	if ok {
		return func() { _ = lock.Close() }, ReasonNone, nil
	}

	if errors.Is(lockErr, context.DeadlineExceeded) {
		return nil, ReasonLockTimeout, lockErr
	}
	return nil, ReasonLockAcquireError, lockErr
}

// TryAcquire makes exactly one non-blocking attempt to take an exclusive advisory lock on path and returns immediately — there is no wait, retry, or timeout. The retention pruner uses it to probe a session's resume lock before deleting the file: a single try with "no wait timeout applies."
//
// On success, release closes the underlying lock object (unlock + close fd) and reason is ReasonNone. When another holder currently owns the lock, release is nil, reason is ReasonLockContended, and err is nil — a non-error skip path the pruner must distinguish from a real failure so it can leave the live session alone silently. On a lock-syscall/construction failure, release is nil, reason is ReasonLockAcquireError, and err is the underlying error.
//
// Unlike Acquire(path, 0), this actually attempts the lock: Acquire with a zero timeout hands gofrs/flock an already-expired context, so TryLockContext reports a timeout without ever calling the lock syscall. TryAcquire calls the single-attempt TryLock directly instead. The same sidecar-path contract as Acquire applies: callers pass a dedicated lock path, never an atomically renamed-over data file.
func TryAcquire(path string) (release func(), reason LockReason, err error) {
	lock := newLock(path)

	ok, lockErr := lock.TryLock()
	if ok {
		return func() { _ = lock.Close() }, ReasonNone, nil
	}
	// gofrs/flock distinguishes ordinary contention (false, nil) from a syscall/open failure (false, err): only the latter is an error the pruner should surface.
	if lockErr != nil {
		return nil, ReasonLockAcquireError, lockErr
	}
	return nil, ReasonLockContended, nil
}

// AcquireAt takes the same kernel flock as Acquire, so the two exclude each other on one sidecar.
func AcquireAt(dir *os.File, name string, timeout time.Duration) (release func(), reason LockReason, err error) {
	fd, openErr := unix.Openat(int(dir.Fd()), name, unix.O_CREAT|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, lockFileMode)
	if openErr != nil {
		return nil, ReasonLockAcquireError, &os.PathError{Op: "openat", Path: name, Err: openErr}
	}

	var st unix.Stat_t
	if statErr := unix.Fstat(fd, &st); statErr != nil {
		_ = unix.Close(fd)
		return nil, ReasonLockAcquireError, &os.PathError{Op: "fstat", Path: name, Err: statErr}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, ReasonLockAcquireError, &os.PathError{Op: "fstat", Path: name, Err: syscall.EINVAL}
	}

	deadline := time.Now().Add(timeout)
	for {
		lockErr := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if lockErr == nil {
			return func() { _ = unix.Close(fd) }, ReasonNone, nil
		}
		if !errors.Is(lockErr, unix.EWOULDBLOCK) && !errors.Is(lockErr, unix.EINTR) {
			_ = unix.Close(fd)
			return nil, ReasonLockAcquireError, &os.PathError{Op: "flock", Path: name, Err: lockErr}
		}
		if !time.Now().Before(deadline) {
			_ = unix.Close(fd)
			return nil, ReasonLockTimeout, context.DeadlineExceeded
		}
		time.Sleep(retryDelay)
	}
}
