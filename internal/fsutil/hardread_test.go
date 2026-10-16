// Unit tests for ReadSettingsBytes: absence, symlink and non-regular refusals, the byte cap, and the
// descriptor checks that catch a file changing under the open.
package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct {
	os.FileInfo
	mode os.FileMode
	size int64
}

func (f fakeInfo) Mode() os.FileMode { return f.mode }
func (f fakeInfo) Size() int64       { return f.size }

func swapStatOpened(t *testing.T, info fakeInfo) {
	t.Helper()
	restore := statOpened
	t.Cleanup(func() { statOpened = restore })
	statOpened = func(*os.File) (os.FileInfo, error) { return info, nil }
}

func settingsFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.yaml")
	seedFile(t, path, content)
	return path
}

func TestReadSettingsBytes_ReturnsCoveredBytesAndDistinguishesAbsence(t *testing.T) {
	const content = "model: {}\n"
	path := settingsFixture(t, content)

	data, found, ok := ReadSettingsBytes(path)
	if !ok || !found || string(data) != content {
		t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (%q, true, true)", data, found, ok, content)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove fixture: %v", err)
	}
	data, found, ok = ReadSettingsBytes(path)
	if !ok || found || data != nil {
		t.Fatalf("absent ReadSettingsBytes = (%q, %v, %v), want (nil, false, true)", data, found, ok)
	}
}

func TestReadSettingsBytes_NonRegularAndOversizedTargetsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"target is a directory", func(t *testing.T, path string) {
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}},
		{"target is a fifo", func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatalf("mkfifo: %v", err)
			}
		}},
		{"symlink resolves to a non-regular source", func(t *testing.T, path string) {
			if err := os.Symlink(t.TempDir(), path); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"larger than the covered limit", func(t *testing.T, path string) {
			seedFile(t, path, strings.Repeat("x", maxCoveredBytes+1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.yaml")
			tc.setup(t, path)
			data, found, ok := ReadSettingsBytes(path)
			if ok || found || data != nil {
				t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (nil, false, false)", data, found, ok)
			}
		})
	}
}

func TestReadSettingsBytes_SettingsReplacedWithAFifoBeforeOpenFailsWithoutBlocking(t *testing.T) {
	path := settingsFixture(t, "model: {}\n")

	realOpen := openCovered
	t.Cleanup(func() { openCovered = realOpen })
	openCovered = func(p string) (*os.File, error) {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Errorf("mkfifo: %v", err)
		}
		return realOpen(p)
	}

	done := make(chan bool, 1)
	go func() {
		_, _, ok := ReadSettingsBytes(path)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("ReadSettingsBytes accepted a fifo swapped in after the pre-open check")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadSettingsBytes blocked in open on the replaced path instead of failing")
	}
}

// A settings path that is a symbolic link is refused rather than followed, so a path admitted
// as settings cannot later redirect a read to another file. A dangling link is refused too:
// reporting it as absence is what would let first-run generation write through it.
func TestReadSettingsBytes_RejectsFinalComponentSymlink(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"live link", "seeded"},
		{"dangling link", "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "settings.yaml")
			target := filepath.Join(root, tc.target)
			if tc.target == "seeded" {
				seedFile(t, target, "model: {}\n")
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatalf("symlink: %v", err)
			}

			data, found, ok := ReadSettingsBytes(path)
			if ok || found || data != nil {
				t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (nil, false, false)", data, found, ok)
			}
		})
	}
}

// A replacement of the same length leaves the declared length and the read itself consistent,
// so only re-resolving the path without following it can reject it.
func TestReadSettingsBytes_SameLengthPathReplacementAtTheReadSeamFailsClosed(t *testing.T) {
	path := settingsFixture(t, "model: {a: 1}\n")
	replacement := filepath.Join(filepath.Dir(path), "replacement.yaml")
	seedFile(t, replacement, "model: {b: 2}\n")

	realRead := readCoveredBytes
	t.Cleanup(func() { readCoveredBytes = realRead })
	readCoveredBytes = func(f *os.File, limit int64) ([]byte, error) {
		data, err := realRead(f, limit)
		if rerr := os.Rename(replacement, path); rerr != nil {
			t.Errorf("rename over settings: %v", rerr)
		}
		return data, err
	}

	data, found, ok := ReadSettingsBytes(path)
	if ok || found || data != nil {
		t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (nil, false, false)", data, found, ok)
	}
}

// An in-place rewrite of the same length keeps both the inode and the declared length, so
// neither the length check nor the path-identity check can see it; only the descriptor's own
// mutation metadata distinguishes it from a stable read.
func TestReadSettingsBytes_SameInodeSameLengthRewriteAtTheReadSeamFailsClosed(t *testing.T) {
	path := settingsFixture(t, "model: {a: 1}\n")

	realRead := readCoveredBytes
	t.Cleanup(func() { readCoveredBytes = realRead })
	readCoveredBytes = func(f *os.File, limit int64) ([]byte, error) {
		data, err := realRead(f, limit)
		if werr := os.WriteFile(path, []byte("model: {b: 2}\n"), 0o600); werr != nil {
			t.Errorf("rewrite settings in place: %v", werr)
		}
		bumped := time.Now().Add(time.Second)
		if cerr := os.Chtimes(path, bumped, bumped); cerr != nil {
			t.Errorf("bump settings mtime: %v", cerr)
		}
		return data, err
	}

	data, found, ok := ReadSettingsBytes(path)
	if ok || found || data != nil {
		t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (nil, false, false)", data, found, ok)
	}
}

func TestReadSettingsBytes_OpenedTargetPastTheLimitFailsClosed(t *testing.T) {
	path := settingsFixture(t, "model: {}\n")
	swapStatOpened(t, fakeInfo{mode: 0o600, size: maxCoveredBytes + 1})

	data, found, ok := ReadSettingsBytes(path)
	if ok || found || data != nil {
		t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (nil, false, false)", data, found, ok)
	}
}

func TestReadSettingsBytes_OpenedFileChecksAndUnstableLengthFailClosed(t *testing.T) {
	// Each fixture keeps the read consistent with the reported size, so only the opened-file
	// check under test can reject it.
	t.Run("opened target is no longer regular", func(t *testing.T) {
		path := settingsFixture(t, "model: {}\n")
		real, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat fixture: %v", err)
		}
		swapStatOpened(t, fakeInfo{mode: os.ModeDir | 0o755, size: real.Size()})
		if data, found, ok := ReadSettingsBytes(path); ok || found || data != nil {
			t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (nil, false, false)", data, found, ok)
		}
	})

	for _, tc := range []struct {
		name string
		read func(*os.File, int64) ([]byte, error)
	}{
		{"short read", func(*os.File, int64) ([]byte, error) { return []byte("x"), nil }},
		{"overlong read", func(_ *os.File, limit int64) ([]byte, error) {
			return make([]byte, limit), nil
		}},
		{"read error", func(*os.File, int64) ([]byte, error) { return nil, errors.New("boom") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := settingsFixture(t, "model: {}\n")
			restore := readCoveredBytes
			t.Cleanup(func() { readCoveredBytes = restore })
			readCoveredBytes = tc.read
			if data, found, ok := ReadSettingsBytes(path); ok || found || data != nil {
				t.Fatalf("ReadSettingsBytes = (%q, %v, %v), want (nil, false, false)", data, found, ok)
			}
		})
	}
}

func vcsFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vcs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir vcs dir: %v", err)
	}
	return dir
}

func TestCollectVCSCandidates_AbsentAndSymlinkedFolders(t *testing.T) {
	t.Run("absent folder contributes nothing", func(t *testing.T) {
		files, present, failure := CollectVCSCandidates(filepath.Join(t.TempDir(), "vcs"))
		if files != nil || present || failure != VCSFailureNone {
			t.Fatalf("CollectVCSCandidates = (%v, %v, %q), want the absent state", files, present, failure)
		}
	})

	t.Run("folder that is a symlink is refused", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "vcs")
		target := vcsFixture(t)
		seedFile(t, filepath.Join(target, "git.yaml"), "status:\n  argv: [git, status]\n")
		if err := os.Symlink(target, dir); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		files, present, failure := CollectVCSCandidates(dir)
		if files != nil || present || failure != VCSFailureUnreadable {
			t.Fatalf("CollectVCSCandidates = (%v, %v, %q), want a symlinked folder refused", files, present, failure)
		}
	})

	t.Run("folder that is a regular file is refused", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "vcs")
		seedFile(t, dir, "not a folder\n")
		if _, _, failure := CollectVCSCandidates(dir); failure != VCSFailureUnreadable {
			t.Fatalf("failure = %q, want a non-directory refused", failure)
		}
	})
}

func TestCollectVCSCandidates_UnsafeOrOversizedCandidateFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		stage func(t *testing.T, dir string)
	}{
		{"symlink to a directory", func(t *testing.T, dir string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "git.yaml")); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"dangling symlink", func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "git.yaml")); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"fifo", func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "git.yaml"), 0o600); err != nil {
				t.Fatalf("mkfifo: %v", err)
			}
		}},
		{"unreadable mode", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "git.yaml"), []byte("x"), 0o000); err != nil {
				t.Fatalf("write: %v", err)
			}
		}},
		{"one byte over the per-file limit", func(t *testing.T, dir string) {
			seedFile(t, filepath.Join(dir, "git.yaml"), strings.Repeat("x", maxCoveredBytes+1))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "unreadable mode" && os.Geteuid() == 0 {
				t.Skip("root reads a 0000-mode file")
			}
			dir := vcsFixture(t)
			tc.stage(t, dir)

			// A fifo without O_NONBLOCK parks in open(2), so reaching this assertion at
			// all is what proves such an entry cannot hang a launch.
			files, present, failure := CollectVCSCandidates(dir)
			if files != nil || present || failure != VCSFailureUnsafeEntry {
				t.Fatalf("CollectVCSCandidates = (%v, %v, %q), want an unsafe-entry refusal", files, present, failure)
			}
		})
	}
}

func TestCollectVCSCandidates_AggregateBoundsFailClosed(t *testing.T) {
	fill := func(t *testing.T, dir string, entries int, dirs bool) {
		t.Helper()
		for i := 0; i < entries; i++ {
			name := filepath.Join(dir, "e"+strconv.Itoa(i))
			var err error
			if dirs {
				err = os.Mkdir(name, 0o755)
			} else {
				err = os.WriteFile(name, []byte("x"), 0o600)
			}
			if err != nil {
				t.Fatalf("create entry %d: %v", i, err)
			}
		}
	}

	t.Run("exactly at the entry bound succeeds", func(t *testing.T) {
		dir := vcsFixture(t)
		fill(t, dir, MaxVCSEntries, false)
		files, present, failure := CollectVCSCandidates(dir)
		if !present || failure != VCSFailureNone || len(files) != MaxVCSEntries {
			t.Fatalf("CollectVCSCandidates = (%d files, %v, %q), want a full but admissible folder", len(files), present, failure)
		}
	})

	t.Run("one entry over the bound fails closed", func(t *testing.T) {
		dir := vcsFixture(t)
		fill(t, dir, MaxVCSEntries+1, false)
		if _, _, failure := CollectVCSCandidates(dir); failure != VCSFailureEntryLimit {
			t.Fatalf("failure = %q, want the entry bound to fail closed", failure)
		}
	})

	t.Run("subdirectories alone can exceed the bound", func(t *testing.T) {
		dir := vcsFixture(t)
		fill(t, dir, MaxVCSEntries+1, true)
		if _, _, failure := CollectVCSCandidates(dir); failure != VCSFailureEntryLimit {
			t.Fatalf("failure = %q, want directory entries counted against the bound", failure)
		}
	})

	t.Run("one byte over the aggregate bound fails closed", func(t *testing.T) {
		dir := vcsFixture(t)
		blob := strings.Repeat("x", maxCoveredBytes)
		for i := 0; i < MaxVCSBytes/maxCoveredBytes; i++ {
			seedFile(t, filepath.Join(dir, "f"+strconv.Itoa(i)+".yaml"), blob)
		}
		seedFile(t, filepath.Join(dir, "over.yaml"), "x")
		if _, _, failure := CollectVCSCandidates(dir); failure != VCSFailureByteLimit {
			t.Fatalf("failure = %q, want the aggregate bound to fail closed", failure)
		}
	})
}

func TestCollectVCSCandidates_EnumerationFailureFailsClosed(t *testing.T) {
	restore := openCoveredDir
	t.Cleanup(func() { openCoveredDir = restore })
	openCoveredDir = func(string) (*os.File, error) { return nil, errors.New("forced enumeration failure") }

	dir := vcsFixture(t)
	files, present, failure := CollectVCSCandidates(dir)
	if files != nil || present || failure != VCSFailureUnreadable {
		t.Fatalf("CollectVCSCandidates = (%v, %v, %q), want an unreadable folder to fail closed", files, present, failure)
	}
}

// The directory descriptor, not the pathname, resolves every entry, so replacing the folder with
// a symlink after enumeration opened it cannot redirect the reads.
func TestCollectVCSCandidates_FolderSwappedForSymlinkAfterOpenIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vcs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir vcs dir: %v", err)
	}
	seedFile(t, filepath.Join(dir, "git.yaml"), "COLLECTED")

	decoy := filepath.Join(root, "decoy")
	if err := os.MkdirAll(decoy, 0o755); err != nil {
		t.Fatalf("mkdir decoy dir: %v", err)
	}
	seedFile(t, filepath.Join(decoy, "git.yaml"), "SWAPPEDIN")

	restore := openCoveredDir
	t.Cleanup(func() { openCoveredDir = restore })
	openCoveredDir = func(path string) (*os.File, error) {
		d, err := restore(path)
		if err != nil {
			return nil, err
		}
		if err := os.Rename(dir, filepath.Join(root, "moved")); err != nil {
			t.Fatalf("rename vcs dir: %v", err)
		}
		if err := os.Symlink(decoy, dir); err != nil {
			t.Fatalf("symlink over vcs dir: %v", err)
		}
		return d, nil
	}

	files, present, failure := CollectVCSCandidates(dir)
	if !present || failure != VCSFailureNone {
		t.Fatalf("CollectVCSCandidates = (present %v, failure %q), want a clean collection through the descriptor", present, failure)
	}
	if len(files) != 1 || string(files[0].Bytes) != "COLLECTED" {
		t.Fatalf("collected = %v, want the bytes of the folder the descriptor names", files)
	}
}

func TestCollectVCSCandidates_NamesAreSorted(t *testing.T) {
	dir := vcsFixture(t)
	for _, name := range []string{"zz.yaml", "aa.yaml", "mm.yaml", "bb.yaml"} {
		seedFile(t, filepath.Join(dir, name), "status:\n  argv: [x, status]\n")
	}
	files, _, failure := CollectVCSCandidates(dir)
	if failure != VCSFailureNone {
		t.Fatalf("failure = %q, want a clean collection", failure)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	if want := strings.Join([]string{"aa.yaml", "bb.yaml", "mm.yaml", "zz.yaml"}, ","); strings.Join(names, ",") != want {
		t.Fatalf("collected names = %v, want %s", names, want)
	}
}
