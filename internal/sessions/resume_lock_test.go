// Tests for the per-session resume lock: sidecar path, clean acquire/release,
// contended timeout, injected acquire-error, and process-exit auto-release.
package sessions

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
)

// tempSessionPath returns a session-file path inside a fresh temp dir. The file is
// never created; only its sidecar (path+".lock") is materialized by the lock.
func tempSessionPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "session.json")
}

// holdSidecarLock takes the real advisory lock on path's sidecar and registers its
// release for cleanup, so a subsequent acquire on the same sidecar contends.
func holdSidecarLock(t *testing.T, path string) {
	t.Helper()
	release, reason, err := locks.Acquire(ResumeLockPath(path), time.Second)
	if err != nil {
		t.Fatalf("hold sidecar lock: %v (reason=%q)", err, reason)
	}
	t.Cleanup(release)
}

// shortenAcquireTimeout points the acquireLock seam at the real locks.Acquire but
// with a short timeout, so a contended acquire exercises a real flock contention
// yet times out in milliseconds instead of the production two seconds.
func shortenAcquireTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := acquireLock
	t.Cleanup(func() { acquireLock = orig })
	acquireLock = func(path string, _ time.Duration) (func(), locks.LockReason, error) {
		return locks.Acquire(path, d)
	}
}

// injectAcquireError points the acquireLock seam at a stub that returns a
// non-timeout lock-syscall failure, so the lock_acquire_error path is tested
// without platform-specific filesystem tricks.
func injectAcquireError(t *testing.T, err error) {
	t.Helper()
	orig := acquireLock
	t.Cleanup(func() { acquireLock = orig })
	acquireLock = func(string, time.Duration) (func(), locks.LockReason, error) {
		return nil, locks.ReasonLockAcquireError, err
	}
}

func TestResumeLockPath_AppendsSidecarSuffix(t *testing.T) {
	const session = "/home/u/.codemeld/sessions/ab/0190.json"
	got := ResumeLockPath(session)
	if want := session + ".lock"; got != want {
		t.Fatalf("ResumeLockPath = %q, want %q", got, want)
	}
}

func TestAcquireResumeLock_CleanAcquireAndRelease(t *testing.T) {
	path := tempSessionPath(t)

	release, err := AcquireResumeLock(path, testMetaID)
	if err != nil {
		t.Fatalf("AcquireResumeLock error: %v", err)
	}
	if release == nil {
		t.Fatal("release is nil on success")
	}

	// The lock binds to the sidecar, not the session file itself.
	if _, statErr := os.Stat(ResumeLockPath(path)); statErr != nil {
		t.Fatalf("sidecar lock file not materialized: %v", statErr)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("session file should not be created by the lock; stat err = %v", statErr)
	}
	release()

	// After release a second acquire on the same sidecar must succeed promptly.
	release2, err2 := AcquireResumeLock(path, testMetaID)
	if err2 != nil {
		t.Fatalf("re-acquire after release error: %v", err2)
	}
	release2()
}

func TestAcquireResumeLock_ContendedTimeoutClassifiesAndUnwraps(t *testing.T) {
	path := tempSessionPath(t)
	holdSidecarLock(t, path)
	shortenAcquireTimeout(t, 150*time.Millisecond)

	release, err := AcquireResumeLock(path, testMetaID)
	if release != nil {
		release()
		t.Fatal("release non-nil on contended timeout")
	}
	var rle *ResumeLockError
	if !errors.As(err, &rle) {
		t.Fatalf("err = %v, want *ResumeLockError", err)
	}
	if rle.Reason != locks.ReasonLockTimeout {
		t.Fatalf("reason = %q, want %q", rle.Reason, locks.ReasonLockTimeout)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err does not unwrap to context.DeadlineExceeded: %v", err)
	}
	want := "codemeld: session " + testMetaID + " in use by another codemeld instance"
	if rle.Error() != want {
		t.Fatalf("Error() = %q, want %q", rle.Error(), want)
	}
}

func TestAcquireResumeLock_AcquireErrorClassifiesCategory(t *testing.T) {
	injectAcquireError(t, syscall.EACCES)

	release, err := AcquireResumeLock(tempSessionPath(t), testMetaID)
	if release != nil {
		release()
		t.Fatal("release non-nil on acquire error")
	}
	var rle *ResumeLockError
	if !errors.As(err, &rle) {
		t.Fatalf("err = %v, want *ResumeLockError", err)
	}
	if rle.Reason != locks.ReasonLockAcquireError {
		t.Fatalf("reason = %q, want %q", rle.Reason, locks.ReasonLockAcquireError)
	}
	if rle.Cat != fserrors.PermissionDenied {
		t.Fatalf("category = %q, want %q", rle.Cat, fserrors.PermissionDenied)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("err does not unwrap to syscall.EACCES: %v", err)
	}
}

// Subprocess wiring for the auto-release test: a child process acquires the resume
// lock via the real helper and exits without releasing, so the kernel must release
// it on process exit.
const (
	holdLockEnv = "CODEMELD_SESSIONS_RESUME_HOLD_PATH"
	holdLockID  = "CODEMELD_SESSIONS_RESUME_HOLD_ID"
)

func TestMain(m *testing.M) {
	if path := os.Getenv(holdLockEnv); path != "" {
		// Subprocess mode: acquire the resume lock, signal readiness by closing
		// stdout, block until the parent closes stdin, then exit WITHOUT calling
		// release so the fd-close-on-exit auto-release path is what frees the lock.
		release, err := AcquireResumeLock(path, os.Getenv(holdLockID))
		if err != nil {
			_, _ = os.Stderr.WriteString("subprocess AcquireResumeLock failed: " + err.Error() + "\n")
			os.Exit(2)
		}
		_ = release // intentionally not called; process exit must release the lock
		_ = os.Stdout.Close()
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestAcquireResumeLock_AutoReleaseOnProcessExit(t *testing.T) {
	path := tempSessionPath(t)

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=ResumeLockSubprocessNoop")
	cmd.Env = append(os.Environ(),
		holdLockEnv+"="+path,
		holdLockID+"="+testMetaID,
	)
	stdout, pipeErr := cmd.StdoutPipe()
	if pipeErr != nil {
		t.Fatalf("StdoutPipe: %v", pipeErr)
	}
	// Give the child a stdin we control so it blocks after signaling readiness and
	// exits only once we close this pipe; without the gate the contention assertion
	// below would race the child's exit.
	stdin, stdinErr := cmd.StdinPipe()
	if stdinErr != nil {
		t.Fatalf("StdinPipe: %v", stdinErr)
	}
	cmd.Stderr = os.Stderr
	if startErr := cmd.Start(); startErr != nil {
		t.Fatalf("subprocess start: %v", startErr)
	}

	// Readiness: the child closes stdout once it holds the lock.
	buf := make([]byte, 16)
	_, _ = stdout.Read(buf)

	// While the child holds the lock, a contending acquire on the same sidecar must
	// time out. Use locks.Acquire with a short timeout directly so the assertion
	// does not wait the production two seconds.
	contend, reason, contendErr := locks.Acquire(ResumeLockPath(path), 200*time.Millisecond)
	if contendErr == nil {
		contend()
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatal("acquire succeeded while subprocess held the resume lock; want timeout")
	}
	if reason != locks.ReasonLockTimeout {
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("contend reason = %q, want %q", reason, locks.ReasonLockTimeout)
	}

	// Release the gate: closing stdin returns EOF to the child's io.Copy, after
	// which it exits without calling release().
	if closeErr := stdin.Close(); closeErr != nil {
		t.Fatalf("close subprocess stdin: %v", closeErr)
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		t.Fatalf("subprocess wait: %v", waitErr)
	}

	// After the child has exited without releasing, the kernel must have released
	// the lock, so acquire now succeeds promptly.
	release, reason2, acquireErr := locks.Acquire(ResumeLockPath(path), time.Second)
	if acquireErr != nil {
		t.Fatalf("post-exit acquire failed: %v (reason=%q)", acquireErr, reason2)
	}
	release()
}
