package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"codemeld.dev/codemeld/internal/enforce"
)

func skipUnlessLinuxTempDirs(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("session temp folders are created only on linux")
	}
}

func newOwnedTempDir(t *testing.T) *sessionTempDir {
	t.Helper()
	dir, err := newSessionTempDir()
	if err != nil {
		t.Fatalf("newSessionTempDir: %v", err)
	}
	t.Cleanup(dir.close)
	return dir
}

func setHook(t *testing.T, hook *func(string), fn func(string)) {
	t.Helper()
	prev := *hook
	*hook = fn
	t.Cleanup(func() { *hook = prev })
}

func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type keptTarget struct {
	dir, file string
}

func newKeptTarget(t *testing.T, dir string) keptTarget {
	t.Helper()
	mkdirMode(t, dir, 0o700)
	k := keptTarget{dir: dir, file: filepath.Join(dir, "keep")}
	mustWrite(t, k.file, "keep")
	mkdirMode(t, filepath.Join(dir, "sub"), 0o500)
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.Chmod(filepath.Join(dir, "sub"), 0o700)
	})
	return k
}

func (k keptTarget) requireUnchanged(t *testing.T) {
	t.Helper()
	for path, want := range map[string]os.FileMode{k.dir: 0o750, filepath.Join(k.dir, "sub"): 0o500} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != want {
			t.Fatalf("%s: info %v, err %v; want a folder with mode %v", path, info, err, want)
		}
	}
	if data, err := os.ReadFile(k.file); err != nil || string(data) != "keep" {
		t.Fatalf("%s = %q, %v; want it unchanged", k.file, data, err)
	}
}

func requireGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s still present (err %v), want it removed", path, err)
	}
}

func TestNewSessionTempDir_CreatesPrivateFolderNamedForThisProcess(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	tmp := canonicalTempDir(t)
	t.Setenv("TMPDIR", tmp)

	first := newOwnedTempDir(t)
	if got := filepath.Dir(first.path); got != tmp {
		t.Fatalf("folder %q is in %q, want %q", first.path, got, tmp)
	}
	wantPrefix := fmt.Sprintf("codemeld-confine-%d-", os.Getpid())
	if name := filepath.Base(first.path); !strings.HasPrefix(name, wantPrefix) || name == wantPrefix {
		t.Fatalf("folder name %q, want %q followed by a suffix", name, wantPrefix)
	}
	info, err := os.Stat(first.path)
	if err != nil {
		t.Fatalf("stat %q: %v", first.path, err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("folder %q has mode %v, want a directory with 0700", first.path, info.Mode())
	}

	if second := newOwnedTempDir(t); second.path == first.path {
		t.Fatalf("two calls both returned %q", first.path)
	}
}

func TestNewSessionTempDir_StoresTheResolvedFolderUnderASymlinkedTMPDIR(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	target := canonicalTempDir(t)
	alias := filepath.Join(canonicalTempDir(t), "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)

	first := newOwnedTempDir(t)
	conf := &confinement{tmpDir: first.path}
	conf.own(first)
	replacement, rollback, err := conf.prepareReplacement()
	if err != nil {
		t.Fatalf("prepareReplacement: %v", err)
	}
	for _, dir := range []string{first.path, replacement} {
		if got := filepath.Dir(dir); got != target {
			t.Fatalf("folder %q is in %q, want the resolved %q", dir, got, target)
		}
		mustWrite(t, filepath.Join(dir, "f"), "x")
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := conf.cleanupAll(); err != nil {
		t.Fatalf("cleanupAll: %v", err)
	}
	requireGone(t, first.path)
	requireGone(t, replacement)
}

func finishedProcessPID(t *testing.T) int {
	t.Helper()
	finished := exec.Command(os.Args[0], "-test.run=^$")
	if err := finished.Run(); err != nil {
		t.Fatalf("run a short-lived process: %v", err)
	}
	return finished.ProcessState.Pid()
}

func TestRemoveStaleSessionTempDirs_RemovesOnlyFinishedProcessFolders(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	deadPID := finishedProcessPID(t)

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
	mustWrite(t, filepath.Join(cache, "entry"), "x")
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
	mustWrite(t, regularFile, "x")
	target := t.TempDir()
	targetFile := filepath.Join(target, "keep")
	mustWrite(t, targetFile, "x")
	link := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-link", deadPID))
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	kept = append(kept, regularFile, link, target, targetFile)

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}

	requireGone(t, stale)
	for _, path := range kept {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%q was removed: %v", path, err)
		}
	}
}

func TestRemoveStaleSessionTempDirs_AParentSwapAfterTheScanOpensCannotRedirectIt(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base, outside := canonicalTempDir(t), canonicalTempDir(t)
	tmp := filepath.Join(base, "tmp")
	t.Setenv("TMPDIR", tmp)
	name := fmt.Sprintf("codemeld-confine-%d-stale", finishedProcessPID(t))
	mkdirMode(t, filepath.Join(tmp, name, "cache"), 0)
	kept := newKeptTarget(t, filepath.Join(outside, name))
	setHook(t, &afterStaleScanParentOpen, func(string) {
		if err := os.Rename(tmp, tmp+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Symlink(outside, tmp); err != nil {
			t.Errorf("symlink: %v", err)
		}
	})

	if err := removeStaleSessionTempDirs(); err != nil {
		t.Fatalf("removeStaleSessionTempDirs: %v", err)
	}
	requireGone(t, filepath.Join(tmp+".moved", name))
	kept.requireUnchanged(t)
}

func TestRemoveStaleSessionTempDirs_ASwappedCandidateIsLeftAndReportedAtStartup(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	tmp, outside := canonicalTempDir(t), canonicalTempDir(t)
	t.Setenv("TMPDIR", tmp)
	stale := filepath.Join(tmp, fmt.Sprintf("codemeld-confine-%d-stale", finishedProcessPID(t)))
	sub := filepath.Join(stale, "sub")
	mkdirMode(t, sub, 0)
	kept := newKeptTarget(t, filepath.Join(outside, "target"))
	setHook(t, &duringSessionTempDirCleanup, func(dir string) {
		if dir != sub {
			return
		}
		if err := os.Rename(sub, sub+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Symlink(kept.dir, sub); err != nil {
			t.Errorf("symlink: %v", err)
		}
	})

	var notices bytes.Buffer
	if _, err := startExecutionCapability(enforce.Resolution{}, stderrNoticeRenderer{w: &notices}); err != nil {
		t.Fatalf("startExecutionCapability: %v", err)
	}
	if got := notices.String(); !strings.HasPrefix(got, "codemeld: could not remove a leftover confinement temp folder: ") || !strings.Contains(got, sub) {
		t.Fatalf("notice = %q, want the leftover-folder warning naming %s", got, sub)
	}
	if target, err := os.Readlink(sub); err != nil || target != kept.dir {
		t.Fatalf("readlink %s = %q, %v; want the substituted link left in place", sub, target, err)
	}
	kept.requireUnchanged(t)
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

func TestNewSessionTempDir_IsPrivateUnderOwnerMaskingUmasks(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	for _, umask := range []int{0o277, 0o477, 0o777} {
		t.Run(fmt.Sprintf("%04o", umask), func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			prev := syscall.Umask(umask)
			t.Cleanup(func() { syscall.Umask(prev) })

			dir, err := newSessionTempDir()
			syscall.Umask(prev)
			if err != nil {
				t.Fatalf("newSessionTempDir: %v", err)
			}
			t.Cleanup(dir.close)
			info, err := os.Stat(dir.path)
			if err != nil {
				t.Fatalf("stat %q: %v", dir.path, err)
			}
			if info.Mode().Perm() != 0o700 {
				t.Fatalf("folder %q has mode %v, want 0700", dir.path, info.Mode().Perm())
			}
		})
	}
}

func TestNewSessionTempDir_RelativeTMPDIRYieldsAnAbsolutePathInTheResolvedParent(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base := canonicalTempDir(t)
	mkdirMode(t, filepath.Join(base, "rel"), 0o700)
	t.Chdir(base)
	t.Setenv("TMPDIR", "rel")

	dir := newOwnedTempDir(t)
	if !filepath.IsAbs(dir.path) {
		t.Fatalf("folder %q is not absolute", dir.path)
	}
	if got, want := filepath.Dir(dir.path), filepath.Join(base, "rel"); got != want {
		t.Fatalf("folder %q is in %q, want %q", dir.path, got, want)
	}
}

func TestSessionTempDir_RelativeTMPDIRThenAWorkingDirectoryChangeCannotRedirectCleanup(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	launch, later, outside := canonicalTempDir(t), canonicalTempDir(t), canonicalTempDir(t)
	mkdirMode(t, filepath.Join(launch, "rel"), 0o700)
	t.Chdir(launch)
	t.Setenv("TMPDIR", "rel")
	dir := newOwnedTempDir(t)
	name := filepath.Base(dir.path)
	if err := os.Rename(filepath.Join(launch, "rel"), filepath.Join(launch, "rel.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(launch, "rel")); err != nil {
		t.Fatal(err)
	}
	kept := newKeptTarget(t, filepath.Join(outside, name))
	mkdirMode(t, filepath.Join(later, "rel", name), 0o700)
	decoy := newKeptTarget(t, filepath.Join(later, "rel", name, "decoy"))
	t.Chdir(later)

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("removeAndRelease: %v", err)
	}
	requireGone(t, filepath.Join(launch, "rel.moved", name))
	kept.requireUnchanged(t)
	decoy.requireUnchanged(t)
}

func TestNewSessionTempDir_UnresolvableParentFailsBeforeCreation(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base := canonicalTempDir(t)
	t.Setenv("TMPDIR", filepath.Join(base, "missing"))

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error", dir, err)
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
	kept      keptTarget
	parentDir string
}

func swapSessionTempDirAt(t *testing.T, seam *func(string), replaceWith func(created string, s *swappedTempDir) error) *swappedTempDir {
	t.Helper()
	s := &swappedTempDir{parentDir: canonicalTempDir(t)}
	t.Setenv("TMPDIR", s.parentDir)
	s.kept = newKeptTarget(t, filepath.Join(canonicalTempDir(t), "outside"))
	setHook(t, seam, func(created string) {
		s.created = created
		s.original = created + ".original"
		if err := os.Rename(created, s.original); err != nil {
			t.Errorf("rename %q: %v", created, err)
			return
		}
		if err := replaceWith(created, s); err != nil {
			t.Errorf("replace %q: %v", created, err)
		}
	})
	t.Cleanup(func() {
		if s.original != "" {
			_ = os.Chmod(s.original, 0o700)
			_ = os.RemoveAll(s.original)
		}
	})
	return s
}

func symlinkToOutside(created string, s *swappedTempDir) error {
	return os.Symlink(s.kept.dir, created)
}

func (s *swappedTempDir) requireLinkKept(t *testing.T) {
	t.Helper()
	if target, err := os.Readlink(s.created); err != nil || target != s.kept.dir {
		t.Fatalf("readlink %s = %q, %v; want the substituted link left in place", s.created, target, err)
	}
}

func TestNewSessionTempDir_SwapBeforeTheModeOpenFailsSafely(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	s := swapSessionTempDirAt(t, &beforeSessionTempDirChmod, symlinkToOutside)

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error after the swap", dir, err)
	}
	if s.created == "" {
		t.Fatal("the seam before the mode open was not called")
	}
	s.kept.requireUnchanged(t)
	s.requireLinkKept(t)
}

func TestNewSessionTempDir_RealDirectorySwapBeforeTheFirstOpenIsLeftUntouched(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	s := swapSessionTempDirAt(t, &beforeSessionTempDirChmod, func(created string, _ *swappedTempDir) error {
		if err := os.Mkdir(created, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(created, "planted"), []byte("planted"), 0o600); err != nil {
			return err
		}
		return os.Chmod(created, 0o550)
	})
	t.Cleanup(func() { _ = os.Chmod(s.created, 0o700) })

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error after the swap", dir, err)
	}
	info, err := os.Lstat(s.created)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o550 {
		t.Fatalf("replacement %s: info %v, err %v; want the planted folder with its mode 0550", s.created, info, err)
	}
	if data, err := os.ReadFile(filepath.Join(s.created, "planted")); err != nil || string(data) != "planted" {
		t.Fatalf("planted file = %q, %v; want it unchanged", data, err)
	}
}

func TestNewSessionTempDir_AParentSwapDuringCreationFailsAndRollsBackThroughTheHandles(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base, outside := canonicalTempDir(t), canonicalTempDir(t)
	tmp := filepath.Join(base, "tmp")
	mkdirMode(t, tmp, 0o700)
	t.Setenv("TMPDIR", tmp)
	var kept keptTarget
	var created string
	setHook(t, &beforeSessionTempDirChmod, func(path string) {
		created = path
		if err := os.Rename(tmp, tmp+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Symlink(outside, tmp); err != nil {
			t.Errorf("symlink: %v", err)
		}
		kept = newKeptTarget(t, filepath.Join(outside, filepath.Base(path)))
	})

	dir, err := newSessionTempDir()
	if err == nil || dir != nil {
		t.Fatalf("newSessionTempDir = (%v, %v), want only an error", dir, err)
	}
	requireGone(t, filepath.Join(tmp+".moved", filepath.Base(created)))
	kept.requireUnchanged(t)
}

func TestNewSessionTempDir_SwapAfterCreationLeavesTheLinkAndReportsTheCleanupFailure(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	s := swapSessionTempDirAt(t, &afterSessionTempDirChmod, symlinkToOutside)

	dir := newOwnedTempDir(t)
	if dir.path != s.created || filepath.Dir(dir.path) != s.parentDir {
		t.Fatalf("newSessionTempDir = %q, want the created path %q in %q", dir.path, s.created, s.parentDir)
	}
	s.kept.requireUnchanged(t)

	if err := dir.removeAndRelease(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("removeAndRelease = %v, want the replacement reported", err)
	}
	s.requireLinkKept(t)
	s.kept.requireUnchanged(t)
}

func TestSessionTempDir_AnAncestorSwapBeforeCleanupCannotRedirectIt(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	base, outside := canonicalTempDir(t), canonicalTempDir(t)
	ancestor := filepath.Join(base, "a")
	t.Setenv("TMPDIR", filepath.Join(ancestor, "tmp"))
	mkdirMode(t, filepath.Join(ancestor, "tmp"), 0o700)
	dir := newOwnedTempDir(t)
	mkdirMode(t, filepath.Join(dir.path, "cache"), 0)
	name := filepath.Base(dir.path)
	if err := os.Rename(ancestor, ancestor+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, ancestor); err != nil {
		t.Fatal(err)
	}
	kept := newKeptTarget(t, filepath.Join(outside, "tmp", name))

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("removeAndRelease: %v", err)
	}
	requireGone(t, filepath.Join(ancestor+".moved", "tmp", name))
	kept.requireUnchanged(t)
}

func TestSessionTempDir_UnreadableDescendantsAreRemoved(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	dir := newOwnedTempDir(t)
	deep := filepath.Join(dir.path, "a", "b")
	mkdirMode(t, deep, 0o700)
	mustWrite(t, filepath.Join(deep, "f"), "x")
	if err := os.Symlink("/", filepath.Join(deep, "root")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{deep, filepath.Dir(deep), dir.path} {
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
	}

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("removeAndRelease: %v", err)
	}
	requireGone(t, dir.path)
}

func TestSessionTempDir_ASwapDuringPermissionRecoveryIsNeitherFollowedNorChanged(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	for _, replacement := range []string{"symlink", "real directory"} {
		t.Run(replacement, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			dir := newOwnedTempDir(t)
			sub := filepath.Join(dir.path, "sub")
			mkdirMode(t, sub, 0o700)
			mustWrite(t, filepath.Join(sub, "f"), "x")
			if err := os.Chmod(sub, 0); err != nil {
				t.Fatal(err)
			}
			kept := newKeptTarget(t, filepath.Join(canonicalTempDir(t), "outside"))
			swapped := 0
			setHook(t, &duringSessionTempDirCleanup, func(path string) {
				if path != sub || swapped > 0 {
					return
				}
				swapped++
				if err := os.Rename(sub, sub+".moved"); err != nil {
					t.Errorf("rename: %v", err)
				}
				if replacement == "symlink" {
					if err := os.Symlink(kept.dir, sub); err != nil {
						t.Errorf("symlink: %v", err)
					}
					return
				}
				if err := os.Rename(kept.dir, sub); err != nil {
					t.Errorf("move the outside folder in: %v", err)
				}
				kept.dir, kept.file = sub, filepath.Join(sub, "keep")
			})

			err := dir.remove()
			if err == nil || !strings.Contains(err.Error(), sub) {
				t.Fatalf("remove = %v, want an error naming %s", err, sub)
			}
			if swapped != 1 {
				t.Fatalf("swaps = %d, want the hook to fire once", swapped)
			}
			kept.requireUnchanged(t)
		})
	}
}

func TestSessionTempDir_AnEmptyRealDirectorySwappedInBeforeTheFinalUnlinkIsKept(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	t.Setenv("TMPDIR", t.TempDir())
	dir := newOwnedTempDir(t)
	setHook(t, &beforeSessionTempDirUnlink, func(path string) {
		if path != dir.path {
			return
		}
		if err := os.Rename(dir.path, dir.path+".moved"); err != nil {
			t.Errorf("rename: %v", err)
		}
		if err := os.Mkdir(dir.path, 0o750); err != nil {
			t.Errorf("mkdir: %v", err)
		}
	})

	if err := dir.remove(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("remove = %v, want the replacement reported", err)
	}
	if info, err := os.Lstat(dir.path); err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
		t.Fatalf("replacement %s: info %v, err %v; want it kept with mode 0750", dir.path, info, err)
	}
}

func openFDsAt(t *testing.T, paths ...string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var fds []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && slices.Contains(paths, strings.TrimSuffix(target, " (deleted)")) {
			fds = append(fds, e.Name())
		}
	}
	return fds
}

func TestSessionTempDir_HandlesAreCloseOnExecAndReleasedAfterAFailedThenRetriedCleanup(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	parent := canonicalTempDir(t)
	t.Setenv("TMPDIR", parent)
	dir := newOwnedTempDir(t)
	fds := openFDsAt(t, parent, dir.path)
	if len(fds) != 2 {
		t.Fatalf("open handles on %s and its folder = %v, want two", parent, fds)
	}
	for _, fd := range fds {
		info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", fd))
		if err != nil {
			t.Fatal(err)
		}
		var flags int
		for line := range strings.Lines(string(info)) {
			if rest, ok := strings.CutPrefix(line, "flags:"); ok {
				_, _ = fmt.Sscanf(strings.TrimSpace(rest), "%o", &flags)
			}
		}
		if flags&syscall.O_CLOEXEC == 0 {
			t.Fatalf("handle %s flags %o, want close-on-exec", fd, flags)
		}
	}

	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	err := dir.remove()
	_ = os.Chmod(parent, 0o700)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("remove from a read-only parent = %v, want a permission error", err)
	}
	if got := openFDsAt(t, parent, dir.path); !slices.Equal(got, fds) {
		t.Fatalf("handles after the failed cleanup = %v, want %v kept for the retry", got, fds)
	}

	if err := dir.remove(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	requireGone(t, dir.path)
	if got := openFDsAt(t, parent, dir.path); len(got) != 0 {
		t.Fatalf("handles after the retry = %v, want none", got)
	}
}

type failedRollback struct {
	*ancestorSwap
	parent, created string
	cleanups        int
}

func failCreationRollback(t *testing.T) *failedRollback {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	f := &failedRollback{ancestorSwap: newAncestorSwap(t)}
	f.parent = filepath.Join(f.ancestor+".moved", "tmp")
	t.Cleanup(func() { _ = os.Chmod(f.parent, 0o700) })
	setHook(t, &beforeSessionTempDirChmod, func(path string) {
		f.created = path
		f.swap(t)
		if err := os.Chmod(f.parent, 0o500); err != nil {
			t.Errorf("chmod: %v", err)
		}
	})
	setHook(t, &duringSessionTempDirCleanup, func(path string) {
		if path != f.created {
			return
		}
		if f.cleanups++; f.cleanups == 2 {
			if err := os.Chmod(f.parent, 0o700); err != nil {
				t.Errorf("chmod: %v", err)
			}
		}
	})
	return f
}

func (f *failedRollback) held() string {
	return filepath.Join(f.parent, filepath.Base(f.created))
}

func (f *failedRollback) requireCreationAndRollbackErrors(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "does not resolve to the folder codemeld created") || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want both the creation mismatch and the failed rollback", err)
	}
}

func (f *failedRollback) requireRetriedAndReleased(t *testing.T) {
	t.Helper()
	if f.cleanups != 2 {
		t.Fatalf("cleanup attempts on %s = %d, want the rollback and one exit retry", f.created, f.cleanups)
	}
	f.requireHeld(t, []string{f.created}, nil)
	if got := openFDsAt(t, f.parent, f.held()); len(got) != 0 {
		t.Fatalf("handles after the exit retry = %v, want none", got)
	}
}

func TestNewSessionTempDir_AFailedCreationRollbackHandsBackTheHeldOwner(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	f := failCreationRollback(t)

	dir, err := newSessionTempDir()
	f.requireCreationAndRollbackErrors(t, err)
	if dir == nil || dir.path != f.created {
		t.Fatalf("owner = %v, want the held folder %s returned for the exit retry", dir, f.created)
	}
	if got := openFDsAt(t, f.parent, f.held()); len(got) != 2 {
		t.Fatalf("handles after the failed rollback = %v, want the parent and folder kept", got)
	}

	if err := dir.removeAndRelease(); err != nil {
		t.Fatalf("exit retry: %v", err)
	}
	f.requireRetriedAndReleased(t)
}

func TestConfinement_AFailedReplacementRollbackIsRetriedAtExit(t *testing.T) {
	skipUnlessLinuxTempDirs(t)
	conf := injectedTempDir(t)
	launch := conf.tmpDir
	f := failCreationRollback(t)

	folder, rollback, err := conf.prepareReplacement()
	f.requireCreationAndRollbackErrors(t, err)
	if folder != "" || rollback() != nil || conf.tmpDir != launch {
		t.Fatalf("prepareReplacement folder = %q, tmpDir = %q; want no replacement and %q kept", folder, conf.tmpDir, launch)
	}
	if got := retainedTempDirs(conf); !slices.Equal(got, []string{f.created}) {
		t.Fatalf("retained = %v, want the failed replacement %s kept for the exit retry", got, f.created)
	}

	if err := conf.cleanupAll(); err != nil {
		t.Fatalf("cleanupAll: %v", err)
	}
	f.requireRetriedAndReleased(t)
	requireGone(t, launch)
}
