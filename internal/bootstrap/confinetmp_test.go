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
	tmp := canonicalTempDir(t)
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

func TestNewSessionTempDir_StoresTheResolvedFolderUnderASymlinkedTMPDIR(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("session temp folders are created only where the confinement runs")
	}
	target := canonicalTempDir(t)
	alias := filepath.Join(canonicalTempDir(t), "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)

	first, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("newSessionTempDir: %v", err)
	}
	conf := &confinement{tmpDir: first}
	replacement, rollback, err := conf.prepareReplacement()
	if err != nil {
		t.Fatalf("prepareReplacement: %v", err)
	}
	t.Cleanup(func() { _ = rollback() })
	for _, dir := range []string{first, replacement} {
		if got := filepath.Dir(dir); got != target {
			t.Fatalf("folder %q is in %q, want the resolved %q", dir, got, target)
		}
		if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write into %q: %v", dir, err)
		}
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

func TestNewSessionTempDir_UnderOwnerReadMaskingUmaskEndsPrivate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the no-follow mode correction is exercised only on linux")
	}
	t.Setenv("TMPDIR", t.TempDir())
	prev := syscall.Umask(0o477)
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

func TestNewSessionTempDir_RelativeTMPDIRYieldsAnAbsolutePathInTheResolvedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("session temp folders are created only where the confinement runs")
	}
	base := canonicalTempDir(t)
	if err := os.Mkdir(filepath.Join(base, "rel"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	t.Setenv("TMPDIR", "rel")

	dir, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("newSessionTempDir: %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("folder %q is not absolute", dir)
	}
	if got, want := filepath.Dir(dir), filepath.Join(base, "rel"); got != want {
		t.Fatalf("folder %q is in %q, want %q", dir, got, want)
	}
}

func TestNewSessionTempDir_UnresolvableParentFailsBeforeCreation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("session temp folders are created only where the confinement runs")
	}
	base := canonicalTempDir(t)
	missing := filepath.Join(base, "missing")
	t.Setenv("TMPDIR", missing)

	dir, err := newSessionTempDir()
	if err == nil {
		t.Fatalf("newSessionTempDir = %q, want an error", dir)
	}
	if dir != "" {
		t.Fatalf("newSessionTempDir returned %q with its error", dir)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%q holds %d entries after the failure, want none", base, len(entries))
	}
}

type swappedTempDir struct {
	created   string
	original  string
	outside   string
	keep      string
	parentDir string
}

func swapSessionTempDirAt(t *testing.T, seam *func(string)) *swappedTempDir {
	t.Helper()
	s := &swappedTempDir{parentDir: canonicalTempDir(t), outside: canonicalTempDir(t)}
	t.Setenv("TMPDIR", s.parentDir)
	s.keep = filepath.Join(s.outside, "keep")
	if err := os.WriteFile(s.keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.outside, 0o750); err != nil {
		t.Fatal(err)
	}
	prev := *seam
	*seam = func(created string) {
		s.created = created
		s.original = created + ".original"
		if err := os.Rename(created, s.original); err != nil {
			t.Errorf("rename %q: %v", created, err)
			return
		}
		if err := os.Symlink(s.outside, created); err != nil {
			t.Errorf("symlink %q: %v", created, err)
		}
	}
	t.Cleanup(func() {
		*seam = prev
		if s.original != "" {
			_ = removeSessionTempDir(s.original)
		}
	})
	return s
}

func (s *swappedTempDir) requireOutsideUnchanged(t *testing.T) {
	t.Helper()
	info, err := os.Stat(s.outside)
	if err != nil {
		t.Fatalf("stat outside folder: %v", err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("outside folder mode %v, want 0750", info.Mode().Perm())
	}
	data, err := os.ReadFile(s.keep)
	if err != nil || string(data) != "keep" {
		t.Fatalf("outside file = %q, %v; want it unchanged", data, err)
	}
}

func (s *swappedTempDir) requireLinkGone(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat(s.created); !os.IsNotExist(err) {
		t.Fatalf("substituted link %q still present (err %v)", s.created, err)
	}
}

func TestNewSessionTempDir_SwapBeforeTheModeOpenFailsSafely(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the no-follow mode correction is exercised only on linux")
	}
	s := swapSessionTempDirAt(t, &beforeSessionTempDirChmod)

	dir, err := newSessionTempDir()
	if err == nil {
		t.Fatalf("newSessionTempDir = %q, want an error after the swap", dir)
	}
	if dir != "" {
		t.Fatalf("newSessionTempDir returned %q with its error", dir)
	}
	if s.created == "" {
		t.Fatal("the seam before the mode open was not called")
	}
	s.requireOutsideUnchanged(t)
	s.requireLinkGone(t)
}

func TestNewSessionTempDir_SwapAfterModeCorrectionReturnsTheCreatedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("session temp folders are created only where the confinement runs")
	}
	s := swapSessionTempDirAt(t, &afterSessionTempDirChmod)

	dir, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("newSessionTempDir: %v", err)
	}
	if dir != s.created {
		t.Fatalf("newSessionTempDir = %q, want the created path %q", dir, s.created)
	}
	if got := filepath.Dir(dir); got != s.parentDir {
		t.Fatalf("folder %q is in %q, want %q", dir, got, s.parentDir)
	}
	s.requireOutsideUnchanged(t)

	if err := removeSessionTempDir(dir); err != nil {
		t.Fatalf("removeSessionTempDir: %v", err)
	}
	s.requireLinkGone(t)
	s.requireOutsideUnchanged(t)
}
