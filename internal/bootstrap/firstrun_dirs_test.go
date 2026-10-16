// Unit tests for first-run directory creation.
package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
)

func TestFirstRunDirs_OrderAndPaths(t *testing.T) {
	home := "/some/home"
	got := FirstRunDirs(home)
	want := []string{
		filepath.Join(home, ".codemeld"),
		filepath.Join(home, ".codemeld", "global"),
		filepath.Join(home, ".codemeld", "global", "vcs"),
	}
	if len(got) != len(want) {
		t.Fatalf("FirstRunDirs returned %d paths, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FirstRunDirs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestEnsureFirstRunDirs_FreshHome_CreatesAllThree(t *testing.T) {
	home := t.TempDir()

	path, cat, err := EnsureFirstRunDirs(home)
	if err != nil {
		t.Fatalf("EnsureFirstRunDirs: %v (path=%q cat=%q)", err, path, cat)
	}
	if path != "" || cat != "" {
		t.Fatalf("path=%q cat=%q on success, want both empty", path, cat)
	}

	for _, dir := range FirstRunDirs(home) {
		info, statErr := os.Stat(dir)
		if statErr != nil {
			t.Fatalf("expected dir %q to exist: %v", dir, statErr)
		}
		if !info.IsDir() {
			t.Fatalf("%q is not a directory: %v", dir, info.Mode())
		}
	}
}

func TestEnsureFirstRunDirs_SecondInvocation_NoError(t *testing.T) {
	home := t.TempDir()

	if path, cat, err := EnsureFirstRunDirs(home); err != nil {
		t.Fatalf("first EnsureFirstRunDirs: %v (path=%q cat=%q)", err, path, cat)
	}
	if path, cat, err := EnsureFirstRunDirs(home); err != nil {
		t.Fatalf("second EnsureFirstRunDirs: %v (path=%q cat=%q)", err, path, cat)
	}
}

func TestEnsureFirstRunDirs_PermissionDenied_ReportsRootTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; permission failure is unobservable")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatalf("chmod home read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o755) })

	path, cat, err := EnsureFirstRunDirs(home)
	if err == nil {
		t.Fatalf("EnsureFirstRunDirs in read-only home succeeded, want failure")
	}
	if want := filepath.Join(home, ".codemeld"); path != want {
		t.Fatalf("failed path = %q, want %q (first dir in order)", path, want)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}
}

func TestRunEnsureFirstRunDirs_Success_NoOutputExit0(t *testing.T) {
	home := t.TempDir()

	var stderr bytes.Buffer
	code := RunEnsureFirstRunDirs(home, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on success", stderr.String())
	}
}

func TestRunEnsureFirstRunDirs_Failure_EmitsExactOpFailExit1(t *testing.T) {
	home := t.TempDir()
	// Occupy ~/.codemeld with a regular file so EnsureDir hits ENOTDIR (io_error)
	// deterministically, independent of the test process's uid.
	if err := os.WriteFile(filepath.Join(home, ".codemeld"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed file at .codemeld: %v", err)
	}

	var stderr bytes.Buffer
	code := RunEnsureFirstRunDirs(home, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	wantLine := "codemeld: create-dir failed: " + filepath.Join(home, ".codemeld") + ": " + string(fserrors.IOError) + "\n"
	if stderr.String() != wantLine {
		t.Fatalf("stderr mismatch\n--- got ---\n%q\n--- want ---\n%q", stderr.String(), wantLine)
	}
	if strings.Count(stderr.String(), "\n") != 1 {
		t.Errorf("stderr must be exactly one line, got: %q", stderr.String())
	}
}
