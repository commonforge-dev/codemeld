// Unit tests for Acquire: clean acquire/release, timeout, mocked syscall failure, file materialization, and process-exit auto-release.
package locks

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
)

func TestAcquire_CleanAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	release, reason, err := Acquire(target, time.Second)
	if err != nil {
		t.Fatalf("Acquire error: %v (reason=%q)", err, reason)
	}
	if reason != ReasonNone {
		t.Fatalf("reason = %q, want %q", reason, ReasonNone)
	}
	if release == nil {
		t.Fatalf("release is nil on success")
	}
	release()

	// After release, a second Acquire must succeed quickly.
	release2, reason2, err2 := Acquire(target, time.Second)
	if err2 != nil {
		t.Fatalf("second Acquire after release error: %v (reason=%q)", err2, reason2)
	}
	if reason2 != ReasonNone {
		t.Fatalf("second reason = %q, want %q", reason2, ReasonNone)
	}
	release2()
}

func TestAcquire_MaterializesMissingFileAt0600(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root masks mode-bit assertions on fresh files")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	if _, statErr := os.Stat(target); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("precondition: target unexpectedly exists or stat err: %v", statErr)
	}

	release, reason, err := Acquire(target, time.Second)
	if err != nil {
		t.Fatalf("Acquire error: %v (reason=%q)", err, reason)
	}
	t.Cleanup(release)

	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("stat materialized lock file: %v", statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestAcquire_SecondAcquirerTimesOut(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	release, reason, err := Acquire(target, time.Second)
	if err != nil {
		t.Fatalf("first Acquire error: %v (reason=%q)", err, reason)
	}
	t.Cleanup(release)

	const wait = 150 * time.Millisecond
	start := time.Now()
	release2, reason2, err2 := Acquire(target, wait)
	elapsed := time.Since(start)

	if err2 == nil {
		release2()
		t.Fatalf("second Acquire unexpectedly succeeded while first lock held")
	}
	if reason2 != ReasonLockTimeout {
		t.Fatalf("reason = %q, want %q", reason2, ReasonLockTimeout)
	}
	if !errors.Is(err2, context.DeadlineExceeded) {
		t.Fatalf("err does not wrap context.DeadlineExceeded: %v", err2)
	}
	if elapsed < wait {
		t.Fatalf("returned after %v, want >= %v (configured timeout)", elapsed, wait)
	}
}

// stubLock is a lockHandle that always reports the configured error from both lock primitives, simulating a non-timeout lock-syscall failure without platform-specific filesystem tricks.
type stubLock struct {
	err      error
	closeErr error
}

func (s *stubLock) TryLock() (bool, error) { return false, s.err }

func (s *stubLock) TryLockContext(ctx context.Context, retryDelay time.Duration) (bool, error) {
	return false, s.err
}

func (s *stubLock) Close() error { return s.closeErr }

func TestAcquire_LockSyscallFailureMapsToAcquireError(t *testing.T) {
	orig := newLock
	t.Cleanup(func() { newLock = orig })
	sentinel := errors.New("forced lock syscall failure")
	newLock = func(path string) lockHandle { return &stubLock{err: sentinel} }

	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	release, reason, err := Acquire(target, time.Second)
	if release != nil {
		release()
		t.Fatalf("release non-nil on failure")
	}
	if reason != ReasonLockAcquireError {
		t.Fatalf("reason = %q, want %q", reason, ReasonLockAcquireError)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
}

func TestTryAcquire_CleanAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "session.json.lock")

	// An uncontended try on a free path must actually attempt and succeed — the behavior Acquire(path, 0) lacks because its already-expired context returns before the lock syscall runs.
	release, reason, err := TryAcquire(target)
	if err != nil {
		t.Fatalf("TryAcquire error: %v (reason=%q)", err, reason)
	}
	if reason != ReasonNone {
		t.Fatalf("reason = %q, want %q", reason, ReasonNone)
	}
	if release == nil {
		t.Fatalf("release is nil on success")
	}
	release()

	// After release, a second try must succeed, proving release actually unlocked.
	release2, reason2, err2 := TryAcquire(target)
	if err2 != nil {
		t.Fatalf("second TryAcquire after release error: %v (reason=%q)", err2, reason2)
	}
	if reason2 != ReasonNone {
		t.Fatalf("second reason = %q, want %q", reason2, ReasonNone)
	}
	release2()
}

func TestTryAcquire_ContendedReturnsImmediately(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "session.json.lock")

	release, reason, err := TryAcquire(target)
	if err != nil {
		t.Fatalf("first TryAcquire error: %v (reason=%q)", err, reason)
	}
	t.Cleanup(release)

	// A second try while the lock is held must return at once with a non-error contended reason and no release — never ReasonLockTimeout, since a no-wait try has no timeout.
	start := time.Now()
	release2, reason2, err2 := TryAcquire(target)
	elapsed := time.Since(start)

	if release2 != nil {
		release2()
		t.Fatalf("release non-nil while lock held; want nil on contention")
	}
	if err2 != nil {
		t.Fatalf("err = %v, want nil on contended (non-error skip path)", err2)
	}
	if reason2 != ReasonLockContended {
		t.Fatalf("reason = %q, want %q", reason2, ReasonLockContended)
	}
	// Generous upper bound: a single flock syscall is sub-millisecond; this only fails if the implementation waits or retries (e.g. via TryLockContext) instead of trying once.
	if elapsed > 100*time.Millisecond {
		t.Fatalf("contended TryAcquire took %v; want immediate return (no wait)", elapsed)
	}
}

func TestTryAcquire_LockSyscallFailureMapsToAcquireError(t *testing.T) {
	orig := newLock
	t.Cleanup(func() { newLock = orig })
	sentinel := errors.New("forced lock syscall failure")
	newLock = func(path string) lockHandle { return &stubLock{err: sentinel} }

	dir := t.TempDir()
	target := filepath.Join(dir, "session.json.lock")

	release, reason, err := TryAcquire(target)
	if release != nil {
		release()
		t.Fatalf("release non-nil on failure")
	}
	if reason != ReasonLockAcquireError {
		t.Fatalf("reason = %q, want %q", reason, ReasonLockAcquireError)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel %v", err, sentinel)
	}
}

// holdLockEnv selects the subprocess "hold the lock then exit" mode in TestMain. The path to lock is read from the environment so the parent and child agree on the target.
const (
	holdLockEnv  = "CODEMELD_LOCKS_TEST_HOLD_PATH"
	holdLockMode = "CODEMELD_LOCKS_TEST_HOLD_MODE"
	holdLockVia  = "CODEMELD_LOCKS_TEST_HOLD_VIA"
)

func TestMain(m *testing.M) {
	if path := os.Getenv(holdLockEnv); path != "" {
		// Subprocess mode: acquire the lock, signal readiness by closing stdout, then exit per the requested mode. The kernel must release the lock on exit.
		var release func()
		var reason LockReason
		var err error
		if os.Getenv(holdLockVia) == "at" {
			var dir *os.File
			if dir, err = os.Open(filepath.Dir(path)); err == nil {
				release, reason, err = AcquireAt(dir, filepath.Base(path), 5*time.Second)
			}
		} else {
			release, reason, err = Acquire(path, 5*time.Second)
		}
		if err != nil {
			// Exit nonzero so the parent test fails with a clear signal rather than a mysterious timeout.
			_, _ = os.Stderr.WriteString("subprocess Acquire failed: " + string(reason) + ": " + err.Error() + "\n")
			os.Exit(2)
		}
		// Signal the parent that the lock is held: close stdout so the parent's Read() returns EOF.
		_ = os.Stdout.Close()

		// Block until the parent closes stdin so the lock is provably still held during the parent's contention assertion. Without this, the child could exit before the parent checks contention and the test would observe scheduling, not the locked state.
		_, _ = io.Copy(io.Discard, os.Stdin)

		switch os.Getenv(holdLockMode) {
		case "release":
			release()
			os.Exit(0)
		default:
			// "exit-without-release" — the kernel auto-release path. Do NOT call release(); just exit. The fd close on process exit must release the lock.
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestAcquire_AutoReleaseOnProcessExit(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "settings.yaml")

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=TestMain_noop_subprocess_only")
	cmd.Env = append(os.Environ(),
		holdLockEnv+"="+target,
		holdLockMode+"=exit-without-release",
	)
	stdout, pipeErr := cmd.StdoutPipe()
	if pipeErr != nil {
		t.Fatalf("StdoutPipe: %v", pipeErr)
	}
	// Give the child a stdin we control so it blocks after signaling readiness and only exits once we close this pipe. Without this gate, the contention assertion below would race the child's exit.
	stdin, stdinErr := cmd.StdinPipe()
	if stdinErr != nil {
		t.Fatalf("StdinPipe: %v", stdinErr)
	}
	cmd.Stderr = os.Stderr
	if startErr := cmd.Start(); startErr != nil {
		t.Fatalf("subprocess start: %v", startErr)
	}

	// Wait for the subprocess to signal it holds the lock by closing stdout.
	buf := make([]byte, 16)
	_, _ = stdout.Read(buf)

	// While the subprocess is running with the lock held (blocked reading stdin), the parent must time out trying to acquire.
	contendRelease, contendReason, contendErr := Acquire(target, 200*time.Millisecond)
	if contendErr == nil {
		contendRelease()
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("parent Acquire succeeded while subprocess held lock; want timeout")
	}
	if contendReason != ReasonLockTimeout {
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("contend reason = %q, want %q", contendReason, ReasonLockTimeout)
	}

	// Release the gate: closing stdin causes the child's io.Copy to return EOF, after which it exits without calling release().
	if closeErr := stdin.Close(); closeErr != nil {
		t.Fatalf("close subprocess stdin: %v", closeErr)
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		t.Fatalf("subprocess wait: %v", waitErr)
	}

	// After the subprocess has exited without calling release, the kernel must have released the lock. The parent Acquire should now succeed promptly.
	release, reason, acquireErr := Acquire(target, time.Second)
	if acquireErr != nil {
		t.Fatalf("post-exit Acquire failed: %v (reason=%q)", acquireErr, reason)
	}
	if reason != ReasonNone {
		t.Fatalf("post-exit reason = %q, want %q", reason, ReasonNone)
	}
	release()
}

func openDir(t *testing.T, path string) *os.File {
	t.Helper()
	dir, err := os.Open(path)
	if err != nil {
		t.Fatalf("open dir: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir
}

func startHolder(t *testing.T, path, via, mode string) (io.WriteCloser, *exec.Cmd) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestMain_noop_subprocess_only")
	cmd.Env = append(os.Environ(), holdLockEnv+"="+path, holdLockMode+"="+mode, holdLockVia+"="+via)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("subprocess start: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	_, _ = io.Copy(io.Discard, stdout)
	return stdin, cmd
}

func TestAcquireAt_CrossProcessWithAcquire(t *testing.T) {
	for _, via := range []string{"acquire", "at"} {
		for _, mode := range []string{"release", "exit-without-release"} {
			t.Run(via+"/"+mode, func(t *testing.T) {
				dirPath := t.TempDir()
				target := filepath.Join(dirPath, "settings.yaml.lock")
				dir := openDir(t, dirPath)

				parentAcquire := func(timeout time.Duration) (func(), LockReason, error) {
					if via == "at" {
						return Acquire(target, timeout)
					}
					return AcquireAt(dir, filepath.Base(target), timeout)
				}

				stdin, cmd := startHolder(t, target, via, mode)

				release, reason, err := parentAcquire(150 * time.Millisecond)
				if err == nil {
					release()
					t.Fatalf("parent acquired while child held the lock via %s", via)
				}
				if reason != ReasonLockTimeout || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("contended acquire = (%q, %v), want (%q, DeadlineExceeded)", reason, err, ReasonLockTimeout)
				}

				_ = stdin.Close()
				if err := cmd.Wait(); err != nil {
					t.Fatalf("subprocess wait: %v", err)
				}

				release, reason, err = parentAcquire(time.Second)
				if err != nil || reason != ReasonNone {
					t.Fatalf("acquire after child %s = (%q, %v), want success", mode, reason, err)
				}
				release()
			})
		}
	}
}

func TestAcquireAt_TimeoutThenReleaseThenExplicitRelease(t *testing.T) {
	dirPath := t.TempDir()
	target := filepath.Join(dirPath, "settings.yaml.lock")
	dir := openDir(t, dirPath)

	holdRelease, _, err := Acquire(target, time.Second)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	const wait = 150 * time.Millisecond
	start := time.Now()
	release, reason, err := AcquireAt(dir, "settings.yaml.lock", wait)
	elapsed := time.Since(start)
	if release != nil {
		release()
		t.Fatalf("release non-nil on timeout")
	}
	if reason != ReasonLockTimeout {
		t.Fatalf("reason = %q, want %q", reason, ReasonLockTimeout)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed < wait {
		t.Fatalf("returned after %v, want >= %v", elapsed, wait)
	}

	holdRelease()
	release, reason, err = AcquireAt(dir, "settings.yaml.lock", time.Second)
	if err != nil || reason != ReasonNone {
		t.Fatalf("AcquireAt after holder release = (%q, %v), want success", reason, err)
	}

	contend, reason, err := Acquire(target, 100*time.Millisecond)
	if err == nil {
		contend()
		t.Fatalf("Acquire succeeded while AcquireAt held the lock")
	}
	if reason != ReasonLockTimeout {
		t.Fatalf("contended Acquire reason = %q, want %q", reason, ReasonLockTimeout)
	}

	release()
	after, reason, err := Acquire(target, time.Second)
	if err != nil || reason != ReasonNone {
		t.Fatalf("Acquire after AcquireAt release = (%q, %v), want success", reason, err)
	}
	after()
}

func TestAcquireAt_CreatesAbsentSidecarAt0600(t *testing.T) {
	dirPath := t.TempDir()
	dir := openDir(t, dirPath)

	release, reason, err := AcquireAt(dir, "s.lock", time.Second)
	if err != nil || reason != ReasonNone {
		t.Fatalf("AcquireAt = (%q, %v), want success", reason, err)
	}
	t.Cleanup(release)

	info, err := os.Lstat(filepath.Join(dirPath, "s.lock"))
	if err != nil {
		t.Fatalf("stat sidecar: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar mode = %v, want regular 0600", info.Mode())
	}
}

func TestAcquireAt_DoesNotTruncateExistingSidecar(t *testing.T) {
	dirPath := t.TempDir()
	dir := openDir(t, dirPath)
	path := filepath.Join(dirPath, "s.lock")
	content := []byte("existing sidecar bytes")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	release, reason, err := AcquireAt(dir, "s.lock", time.Second)
	if err != nil || reason != ReasonNone {
		t.Fatalf("AcquireAt = (%q, %v), want success", reason, err)
	}
	release()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("sidecar content = %q, want %q", got, content)
	}
}

func TestAcquireAt_RefusesNonRegularSidecar(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dirPath, sidecar string)
		wantErr error
		check   func(t *testing.T, dirPath string)
	}{
		{
			name: "symlink to regular file",
			setup: func(t *testing.T, dirPath, sidecar string) {
				if err := os.WriteFile(filepath.Join(dirPath, "real"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("real", sidecar); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: syscall.ELOOP,
			check: func(t *testing.T, dirPath string) {
				got, err := os.ReadFile(filepath.Join(dirPath, "real"))
				if err != nil || string(got) != "keep" {
					t.Fatalf("referent = (%q, %v), want unchanged %q", got, err, "keep")
				}
			},
		},
		{
			name: "dangling symlink",
			setup: func(t *testing.T, dirPath, sidecar string) {
				if err := os.Symlink("missing", sidecar); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: syscall.ELOOP,
			check: func(t *testing.T, dirPath string) {
				if _, err := os.Lstat(filepath.Join(dirPath, "missing")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("dangling referent was created (lstat err %v)", err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, dirPath, sidecar string) {
				if err := os.Mkdir(sidecar, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: syscall.EISDIR,
		},
		{
			name: "fifo",
			setup: func(t *testing.T, dirPath, sidecar string) {
				if err := syscall.Mkfifo(sidecar, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: syscall.EINVAL,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dirPath := t.TempDir()
			dir := openDir(t, dirPath)
			tc.setup(t, dirPath, filepath.Join(dirPath, "s.lock"))

			type result struct {
				release func()
				reason  LockReason
				err     error
			}
			const timeout = 200 * time.Millisecond
			done := make(chan result, 1)
			start := time.Now()
			go func() {
				release, reason, err := AcquireAt(dir, "s.lock", timeout)
				done <- result{release, reason, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("AcquireAt hung on a %s sidecar", tc.name)
			}
			if elapsed := time.Since(start); elapsed >= timeout {
				t.Fatalf("AcquireAt took %v, want prompt refusal under %v", elapsed, timeout)
			}
			if r.release != nil {
				r.release()
				t.Fatalf("release non-nil on refusal")
			}
			if r.reason != ReasonLockAcquireError {
				t.Fatalf("reason = %q, want %q", r.reason, ReasonLockAcquireError)
			}
			if !errors.Is(r.err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", r.err, tc.wantErr)
			}
			if tc.check != nil {
				tc.check(t, dirPath)
			}
		})
	}
}
