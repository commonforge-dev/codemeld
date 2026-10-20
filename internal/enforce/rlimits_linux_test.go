package enforce

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyRlimitsSetsOnlyFsizeAndNproc(t *testing.T) {
	oldSet, oldCount := setrlimit, countUserThreads
	t.Cleanup(func() { setrlimit, countUserThreads = oldSet, oldCount })
	countUserThreads = func() (uint64, error) { return 300, nil }
	got := map[int]unix.Rlimit{}
	setrlimit = func(resource int, l *unix.Rlimit) error { got[resource] = *l; return nil }
	nproc, err := applyRlimits()
	if err != nil || nproc != 4396 {
		t.Fatalf("applyRlimits() = %d, %v", nproc, err)
	}
	want := map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 8 << 30, Max: 8 << 30}, unix.RLIMIT_NPROC: {Cur: 4396, Max: 4396}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("set %v, want %v", got, want)
	}
}

func TestApplyRlimitsReportsFailures(t *testing.T) {
	oldSet, oldCount := setrlimit, countUserThreads
	t.Cleanup(func() { setrlimit, countUserThreads = oldSet, oldCount })
	setrlimit = func(int, *unix.Rlimit) error { return nil }
	countUserThreads = func() (uint64, error) { return 0, syscall.EACCES }
	if _, err := applyRlimits(); !errors.Is(err, syscall.EACCES) {
		t.Errorf("count failure: err = %v", err)
	}
	countUserThreads = func() (uint64, error) { return 1, nil }
	setrlimit = func(int, *unix.Rlimit) error { return syscall.EPERM }
	if _, err := applyRlimits(); !errors.Is(err, syscall.EPERM) {
		t.Errorf("setrlimit failure: err = %v", err)
	}
}

func dirEntries(t *testing.T, names ...string) []os.DirEntry {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func stubProcScan(t *testing.T, dirs map[string][]os.DirEntry, dirErr map[string]error, owners map[string]uint32, ownerErr map[string]error) {
	t.Helper()
	oldRead, oldOwner := procReadDir, procOwner
	t.Cleanup(func() { procReadDir, procOwner = oldRead, oldOwner })
	procReadDir = func(p string) ([]os.DirEntry, error) {
		if err := dirErr[p]; err != nil {
			return nil, err
		}
		return dirs[p], nil
	}
	procOwner = func(p string) (uint32, error) {
		if err := ownerErr[p]; err != nil {
			return 0, err
		}
		return owners[p], nil
	}
}

func TestUserThreadCountScan(t *testing.T) {
	uid := uint32(os.Getuid())
	vanished := &fs.PathError{Op: "open", Path: "x", Err: fs.ErrNotExist}
	denied := &fs.PathError{Op: "open", Path: "x", Err: syscall.EACCES}
	exited := &fs.PathError{Op: "open", Path: "/proc/6/task", Err: syscall.ESRCH}
	dirs := map[string][]os.DirEntry{
		"/proc":        dirEntries(t, "1", "2", "3", "4", "5", "6", "self"),
		"/proc/1/task": dirEntries(t, "1", "10", "11"),
		"/proc/2/task": dirEntries(t, "2"),
		"/proc/5/task": dirEntries(t, "5", "50"),
		"/proc/6/task": dirEntries(t, "6", "60"),
	}
	owners := map[string]uint32{"/proc/1": uid, "/proc/2": uid + 1, "/proc/4": uid, "/proc/5": uid, "/proc/6": uid}
	stubProcScan(t, dirs, map[string]error{"/proc/4/task": vanished, "/proc/6/task": exited}, owners, map[string]error{"/proc/3": vanished})
	if n, err := userThreadCount(); err != nil || n != 5 {
		t.Errorf("userThreadCount() = %d, %v, want 5", n, err)
	}
	for name, tc := range map[string]struct{ dirErr, ownerErr map[string]error }{
		"proc enumeration": {dirErr: map[string]error{"/proc": vanished}},
		"ownership read":   {ownerErr: map[string]error{"/proc/1": denied}},
		"task directory":   {dirErr: map[string]error{"/proc/1/task": denied}},
	} {
		stubProcScan(t, dirs, tc.dirErr, owners, tc.ownerErr)
		if _, err := userThreadCount(); err == nil {
			t.Errorf("%s failure: no error", name)
		}
	}
}

func TestUserThreadCountCountsOwnThreads(t *testing.T) {
	own, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	n, err := userThreadCount()
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 || n < uint64(len(own)) {
		t.Errorf("userThreadCount() = %d, want at least this process's %d threads", n, len(own))
	}
}
