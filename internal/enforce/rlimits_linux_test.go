package enforce

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func stubRlimits(t *testing.T, threads uint64, inherited map[int]unix.Rlimit) map[int]unix.Rlimit {
	t.Helper()
	oldSet, oldGet, oldCount := setrlimit, getrlimit, countUserThreads
	t.Cleanup(func() { setrlimit, getrlimit, countUserThreads = oldSet, oldGet, oldCount })
	countUserThreads = func() (uint64, error) { return threads, nil }
	getrlimit = func(resource int, l *unix.Rlimit) error { *l = inherited[resource]; return nil }
	set := map[int]unix.Rlimit{}
	setrlimit = func(resource int, l *unix.Rlimit) error { set[resource] = *l; return nil }
	return set
}

func TestApplyRlimitsSetsOnlyFsizeAndNproc(t *testing.T) {
	inf := uint64(unix.RLIM_INFINITY)
	set := stubRlimits(t, 300, map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: inf, Max: inf}, unix.RLIMIT_NPROC: {Cur: 100000, Max: inf}})
	fsize, nproc, err := applyRlimits()
	wantFsize, wantNproc := unix.Rlimit{Cur: 8 << 30, Max: 8 << 30}, unix.Rlimit{Cur: 4396, Max: 4396}
	if err != nil || fsize != wantFsize || nproc != wantNproc {
		t.Fatalf("applyRlimits() = %v, %v, %v", fsize, nproc, err)
	}
	want := map[int]unix.Rlimit{unix.RLIMIT_FSIZE: wantFsize, unix.RLIMIT_NPROC: wantNproc}
	if !reflect.DeepEqual(set, want) {
		t.Errorf("set %v, want %v", set, want)
	}
}

func TestApplyRlimitsNeverRaisesInheritedLimits(t *testing.T) {
	inf := uint64(unix.RLIM_INFINITY)
	for name, tc := range map[string]struct{ inherited, want map[int]unix.Rlimit }{
		"both below requested": {
			inherited: map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 1 << 20, Max: 1 << 30}, unix.RLIMIT_NPROC: {Cur: 500, Max: 1000}},
			want:      map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 1 << 20, Max: 1 << 30}, unix.RLIMIT_NPROC: {Cur: 500, Max: 1000}},
		},
		"only soft below requested": {
			inherited: map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 1 << 30, Max: inf}, unix.RLIMIT_NPROC: {Cur: 1000, Max: inf}},
			want:      map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 1 << 30, Max: 8 << 30}, unix.RLIMIT_NPROC: {Cur: 1000, Max: 4396}},
		},
		"hard equal to requested": {
			inherited: map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 8 << 30, Max: 8 << 30}, unix.RLIMIT_NPROC: {Cur: 4396, Max: 4396}},
			want:      map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 8 << 30, Max: 8 << 30}, unix.RLIMIT_NPROC: {Cur: 4396, Max: 4396}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			set := stubRlimits(t, 300, tc.inherited)
			fsize, nproc, err := applyRlimits()
			if err != nil {
				t.Fatal(err)
			}
			got := map[int]unix.Rlimit{unix.RLIMIT_FSIZE: fsize, unix.RLIMIT_NPROC: nproc}
			if !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(set, tc.want) {
				t.Errorf("returned %v, set %v, want %v", got, set, tc.want)
			}
			for r, l := range set {
				if l.Cur > tc.inherited[r].Cur || l.Max > tc.inherited[r].Max || l.Cur > l.Max {
					t.Errorf("resource %d: set %v above inherited %v", r, l, tc.inherited[r])
				}
			}
		})
	}
}

func TestApplyRlimitsReportsFailures(t *testing.T) {
	oldSet, oldGet, oldCount := setrlimit, getrlimit, countUserThreads
	t.Cleanup(func() { setrlimit, getrlimit, countUserThreads = oldSet, oldGet, oldCount })
	setrlimit = func(int, *unix.Rlimit) error { return nil }
	getrlimit = func(_ int, l *unix.Rlimit) error { *l = unix.Rlimit{Cur: 1, Max: 1}; return nil }
	countUserThreads = func() (uint64, error) { return 0, syscall.EACCES }
	if _, _, err := applyRlimits(); !errors.Is(err, syscall.EACCES) {
		t.Errorf("count failure: err = %v", err)
	}
	countUserThreads = func() (uint64, error) { return 1, nil }
	setrlimit = func(int, *unix.Rlimit) error { return syscall.EPERM }
	if _, _, err := applyRlimits(); !errors.Is(err, syscall.EPERM) {
		t.Errorf("setrlimit failure: err = %v", err)
	}
	setrlimit = func(int, *unix.Rlimit) error { return nil }
	for resource, name := range map[int]string{unix.RLIMIT_FSIZE: "RLIMIT_FSIZE", unix.RLIMIT_NPROC: "RLIMIT_NPROC"} {
		getrlimit = func(r int, l *unix.Rlimit) error {
			if r == resource {
				return syscall.EFAULT
			}
			*l = unix.Rlimit{Cur: 1, Max: 1}
			return nil
		}
		if _, _, err := applyRlimits(); !errors.Is(err, syscall.EFAULT) || !strings.HasPrefix(err.Error(), name+": ") {
			t.Errorf("%s getrlimit failure: err = %v", name, err)
		}
	}
}

func TestRlimitsProbeChecksRecordedValues(t *testing.T) {
	old := getrlimit
	t.Cleanup(func() { getrlimit = old })
	installed := map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 1 << 20, Max: 1 << 30}, unix.RLIMIT_NPROC: {Cur: 500, Max: 1000}}
	getrlimit = func(r int, l *unix.Rlimit) error { *l = installed[r]; return nil }
	fsize, nproc := installed[unix.RLIMIT_FSIZE], installed[unix.RLIMIT_NPROC]
	if got := rlimitsProbe(fsize, nproc); got != probeAllowed {
		t.Errorf("clamped values: probe = %d, want %d", got, probeAllowed)
	}
	for name, tc := range map[string]struct{ fsize, nproc unix.Rlimit }{
		"fsize soft":   {unix.Rlimit{Cur: 1 << 30, Max: 1 << 30}, nproc},
		"fsize hard":   {unix.Rlimit{Cur: 1 << 20, Max: 8 << 30}, nproc},
		"nproc soft":   {fsize, unix.Rlimit{Cur: 1000, Max: 1000}},
		"nproc hard":   {fsize, unix.Rlimit{Cur: 500, Max: 4396}},
		"nproc zero":   {fsize, unix.Rlimit{}},
	} {
		if got := rlimitsProbe(tc.fsize, tc.nproc); got != probeFailed {
			t.Errorf("%s differs: probe = %d, want %d", name, got, probeFailed)
		}
	}
}

func TestRlimitsProbeAcceptsRecordedZeroLimits(t *testing.T) {
	stubRlimits(t, 300, map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 1 << 20, Max: 1 << 30}, unix.RLIMIT_NPROC: {}})
	s := &helperState{}
	if err := realStep(t, "rlimits")(s); err != nil {
		t.Fatal(err)
	}
	if s.nproc != (unix.Rlimit{}) {
		t.Fatalf("recorded nproc %v, want zero", s.nproc)
	}
	if got := runProbe(s, []string{"rlimits"}); got != probeAllowed {
		t.Errorf("recorded zero NPROC: probe = %d, want %d", got, probeAllowed)
	}
}

func TestRlimitsProbeFailsWhenNotRecorded(t *testing.T) {
	stubRlimits(t, 300, map[int]unix.Rlimit{})
	if got := runProbe(&helperState{}, []string{"rlimits"}); got != probeFailed {
		t.Errorf("unrecorded state with zero limits: probe = %d, want %d", got, probeFailed)
	}
	setrlimit = func(int, *unix.Rlimit) error { return syscall.EPERM }
	s := &helperState{}
	if err := realStep(t, "rlimits")(s); err == nil {
		t.Fatal("setup succeeded with setrlimit failing")
	}
	if got := runProbe(s, []string{"rlimits"}); got != probeFailed {
		t.Errorf("after failed setup: probe = %d, want %d", got, probeFailed)
	}
}

const rlimitChildEnv = "CODEMELD_TEST_RLIMIT_CHILD"

func TestRunHelperKeepsLowerInheritedRlimits(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRlimitClampChild$", "-test.v")
	cmd.Env = append(os.Environ(), rlimitChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "rlimit child ran") {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func TestRlimitClampChild(t *testing.T) {
	if os.Getenv(rlimitChildEnv) == "" {
		t.Skip("runs only as the child of TestRunHelperKeepsLowerInheritedRlimits")
	}
	n, err := userThreadCount()
	if err != nil {
		t.Fatal(err)
	}
	lowered := map[int]unix.Rlimit{}
	for r, l := range map[int]unix.Rlimit{unix.RLIMIT_FSIZE: {Cur: 512 << 20, Max: 1 << 30}, unix.RLIMIT_NPROC: {Cur: n + 500, Max: n + 1000}} {
		var cur unix.Rlimit
		if err := unix.Getrlimit(r, &cur); err != nil {
			t.Fatal(err)
		}
		l = unix.Rlimit{Cur: min(l.Cur, cur.Cur), Max: min(l.Max, cur.Max)}
		if err := unix.Setrlimit(r, &l); err != nil {
			t.Fatal(err)
		}
		lowered[r] = l
	}
	steps := helperSteps
	t.Cleanup(func() { helperSteps = steps })
	helperSteps = slices.DeleteFunc(slices.Clone(steps), func(s helperStep) bool { return s.name != "rlimits" })
	if code := RunHelper([]string{ProbeArg, "rlimits"}); code != probeAllowed {
		t.Fatalf("RunHelper = %d, want %d", code, probeAllowed)
	}
	for r, want := range lowered {
		var got unix.Rlimit
		if err := unix.Getrlimit(r, &got); err != nil || got != want {
			t.Errorf("resource %d after setup = %v, %v, want inherited %v", r, got, err, want)
		}
	}
	fmt.Println("rlimit child ran")
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
