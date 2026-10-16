package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestNewSessionTempDir_CreatesPrivateFolderNamedForThisProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("session temp folders are created only where the confinement runs")
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	first, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("newSessionTempDir: %v", err)
	}
	if got := filepath.Dir(first); got != tmp {
		t.Fatalf("folder %q is in %q, want %q", first, got, tmp)
	}
	wantPrefix := fmt.Sprintf("codemeld-confine-%d-", os.Getpid())
	if name := filepath.Base(first); !strings.HasPrefix(name, wantPrefix) || name == wantPrefix {
		t.Fatalf("folder name %q, want %q followed by a suffix", name, wantPrefix)
	}
	info, err := os.Stat(first)
	if err != nil {
		t.Fatalf("stat %q: %v", first, err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("folder %q has mode %v, want a directory with 0700", first, info.Mode())
	}

	second, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("second newSessionTempDir: %v", err)
	}
	if second == first {
		t.Fatalf("two calls both returned %q", first)
	}
}

func TestRemoveStaleSessionTempDirs_RemovesOnlyFinishedProcessFolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("probing a process with signal 0 is not supported on windows")
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	finished := exec.Command(os.Args[0], "-test.run=^$")
	if err := finished.Run(); err != nil {
		t.Fatalf("run a short-lived process: %v", err)
	}
	deadPID := finished.ProcessState.Pid()

	running := exec.Command("sleep", "60")
	if err := running.Start(); err != nil {
		t.Fatalf("start a long-running process: %v", err)
	}
	t.Cleanup(func() {
		_ = running.Process.Kill()
		_ = running.Wait()
	})

	mkdir := func(name string) string {
		path := filepath.Join(tmp, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatalf("mkdir %q: %v", path, err)
		}
		return path
	}

	staleName := fmt.Sprintf("codemeld-confine-%d-stale", deadPID)
	stale := filepath.Join(tmp, staleName)
	cache := mkdir(filepath.Join(staleName, "gocache"))
	if err := os.WriteFile(filepath.Join(cache, "entry"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write into stale folder: %v", err)
	}
	if err := os.Chmod(cache, 0); err != nil {
		t.Fatal(err)
	}

	kept := []string{
		mkdir(fmt.Sprintf("codemeld-confine-%d-self", os.Getpid())),
		mkdir(fmt.Sprintf("codemeld-confine-%d-live", running.Process.Pid)),
		mkdir("codemeld-confine-abc-x"),
		mkdir("codemeld-confine-007-x"),
		mkdir("codemeld-confine-"),
		mkdir("unrelated"),
		mkdir(fmt.Sprintf("codemeld-confine-0%d-x", deadPID)),
		mkdir(fmt.Sprintf("codemeld-confine-+%d-x", deadPID)),
		mkdir(fmt.Sprintf("codemeld-confine-%d-", deadPID)),
		mkdir(fmt.Sprintf("codemeld-confine-%d-x", int64(deadPID)+1<<32)),
	}

	regularFile := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-file", deadPID))
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	target := t.TempDir()
	targetFile := filepath.Join(target, "keep")
	if err := os.WriteFile(targetFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write symlink target file: %v", err)
	}
	link := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-link", deadPID))
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	kept = append(kept, regularFile, link, target, targetFile)

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}

	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("finished process folder %q still present (err %v)", stale, err)
	}
	for _, path := range kept {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%q was removed: %v", path, err)
		}
	}
}

func TestSignalMeansGone(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"process done", os.ErrProcessDone, true},
		{"wrapped process done", fmt.Errorf("signal: %w", os.ErrProcessDone), true},
		{"nil", nil, false},
		{"permission denied", syscall.EPERM, false},
		{"unrelated", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := signalMeansGone(tc.err); got != tc.want {
			t.Errorf("%s: signalMeansGone(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestSessionTempDirPID(t *testing.T) {
	cases := []struct {
		name    string
		wantPID int
		wantOK  bool
	}{
		{"codemeld-confine-1234-x", 1234, true},
		{"codemeld-confine-0-x", 0, false},
		{"codemeld-confine-+1234-x", 0, false},
		{"codemeld-confine--1234-x", 0, false},
		{"codemeld-confine-01234-x", 0, false},
		{"codemeld-confine-1234-", 0, false},
		{"codemeld-confine-4294968530-x", 0, false},
	}
	for _, tc := range cases {
		pid, ok := sessionTempDirPID(tc.name)
		if ok != tc.wantOK || (ok && pid != tc.wantPID) {
			t.Errorf("sessionTempDirPID(%q) = (%d, %v), want (%d, %v)", tc.name, pid, ok, tc.wantPID, tc.wantOK)
		}
	}
}

func TestNewSessionTempDir_IsPrivateUnderOwnerMaskingUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("session temp folders are created only where the confinement runs")
	}
	t.Setenv("TMPDIR", t.TempDir())
	prev := syscall.Umask(0o277)
	t.Cleanup(func() { syscall.Umask(prev) })

	dir, err := newSessionTempDir()
	syscall.Umask(prev)
	if err != nil {
		t.Fatalf("newSessionTempDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %q: %v", dir, err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("folder %q has mode %v, want 0700", dir, info.Mode().Perm())
	}
}
