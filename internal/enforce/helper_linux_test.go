package enforce

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	return func() string {
		os.Stderr = old
		_ = w.Close()
		out, _ := io.ReadAll(r)
		_ = r.Close()
		return string(out)
	}
}

func recordSteps(t *testing.T, failing string, override map[string]func(*helperState) error) *[]string {
	t.Helper()
	t.Setenv("TERM", os.Getenv("TERM"))
	var calls []string
	oldSteps, oldExec := helperSteps, execStep
	t.Cleanup(func() { helperSteps, execStep = oldSteps, oldExec })
	record := func(name string) helperStep {
		return helperStep{name, func(st *helperState) error {
			calls = append(calls, name)
			if name == failing {
				return errors.New("boom")
			}
			if run := override[name]; run != nil {
				return run(st)
			}
			return nil
		}}
	}
	helperSteps = nil
	for _, s := range oldSteps {
		helperSteps = append(helperSteps, record(s.name))
	}
	execStep = record("exec")
	return &calls
}

func realStep(t *testing.T, name string) func(*helperState) error {
	t.Helper()
	for _, s := range helperSteps {
		if s.name == name {
			return s.run
		}
	}
	t.Fatalf("no step %q", name)
	return nil
}

func withStdin(t *testing.T, data []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old; _ = f.Close() })
}

func encodedFrame(t *testing.T, p Policy) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := WritePolicyFrame(&b, p); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRunHelperRunsStepsInOrder(t *testing.T) {
	var execArgs []string
	calls := recordSteps(t, "", map[string]func(*helperState) error{"exec": func(s *helperState) error { execArgs = s.args; return nil }})
	RunHelper([]string{"/bin/true", "-h"})
	want := []string{"lock thread", "policy frame", "rlimits", "no_new_privs", "landlock", "seccomp", "exec"}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("steps = %v, want %v", *calls, want)
	}
	if !reflect.DeepEqual(execArgs, []string{"/bin/true", "-h"}) {
		t.Errorf("exec args = %v", execArgs)
	}
}

func TestRunHelperRestoresTERMBeforeStepsProbesAndExec(t *testing.T) {
	for _, args := range [][]string{
		{"/bin/true"},
		{ProbeArg, "write-tmp", filepath.Join(t.TempDir(), "probe")},
		{ControlArg, "write-tmp", filepath.Join(t.TempDir(), "control")},
	} {
		t.Setenv("TERM", "")
		seen := map[string][]string{}
		override := map[string]func(*helperState) error{}
		for _, name := range []string{"lock thread", "policy frame", "rlimits", "no_new_privs", "landlock", "seccomp", "exec"} {
			override[name] = func(*helperState) error {
				for _, e := range os.Environ() {
					if strings.HasPrefix(e, "TERM=") {
						seen[name] = append(seen[name], e)
					}
				}
				return nil
			}
		}
		calls := recordSteps(t, "", override)
		if code := RunHelper(args); code != 0 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if len(*calls) == 0 {
			t.Fatalf("%v: no step ran", args)
		}
		for _, name := range *calls {
			if !slices.Equal(seen[name], []string{"TERM=dumb"}) {
				t.Errorf("%v: TERM entries at %s = %q, want exactly TERM=dumb", args, name, seen[name])
			}
		}
	}
}

func TestRunHelperStepFailureNeverExecs(t *testing.T) {
	for _, step := range []string{"policy frame", "rlimits", "no_new_privs", "landlock", "seccomp"} {
		for _, args := range [][]string{{"/bin/true"}, {ProbeArg, "write-tmp", filepath.Join(t.TempDir(), "new")}} {
			calls := recordSteps(t, step, nil)
			stderr := captureStderr(t)
			code := RunHelper(args)
			out := stderr()
			if code != SetupFailureExitCode {
				t.Errorf("%s %v: exit %d", step, args, code)
			}
			if out != "codemeld confinement: "+step+": boom\n" {
				t.Errorf("%s %v: stderr %q", step, args, out)
			}
			if slices.Contains(*calls, "exec") {
				t.Errorf("%s %v: exec ran", step, args)
			}
			if _, err := os.Stat(args[len(args)-1]); args[0] == ProbeArg && err == nil {
				t.Errorf("%s: probe ran", step)
			}
		}
	}
}

func TestRunHelperProbeRunsRestrictionsThenProbe(t *testing.T) {
	calls := recordSteps(t, "", nil)
	path := filepath.Join(t.TempDir(), "new")
	if code := RunHelper([]string{ProbeArg, "write-tmp", path}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := []string{"lock thread", "policy frame", "rlimits", "no_new_privs", "landlock", "seccomp"}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("steps = %v, want %v", *calls, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("probe did not run: %v", err)
	}
}

func TestRunHelperControlRunsOnlyThePolicyFrame(t *testing.T) {
	calls := recordSteps(t, "", nil)
	path := filepath.Join(t.TempDir(), "new")
	if code := RunHelper([]string{ControlArg, "write-tmp", path}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !reflect.DeepEqual(*calls, []string{"policy frame"}) {
		t.Errorf("steps = %v, want only policy frame", *calls)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("probe did not run: %v", err)
	}
}

func TestRunHelperControlRejectsMalformedFrame(t *testing.T) {
	frame := realStep(t, "policy frame")
	calls := recordSteps(t, "", map[string]func(*helperState) error{"policy frame": frame})
	withStdin(t, []byte{0, 0, 0, 2, '{', '{'})
	path := filepath.Join(t.TempDir(), "new")
	stderr := captureStderr(t)
	code := RunHelper([]string{ControlArg, "write-tmp", path})
	out := stderr()
	if code != SetupFailureExitCode || !strings.HasPrefix(out, "codemeld confinement: policy frame: ") {
		t.Errorf("exit %d, stderr %q", code, out)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("probe ran after a malformed frame")
	}
	if !reflect.DeepEqual(*calls, []string{"policy frame"}) {
		t.Errorf("steps = %v", *calls)
	}
}

func TestRunHelperProbeArgumentErrorsAfterSetup(t *testing.T) {
	for _, args := range [][]string{{ProbeArg, "bogus", "/tmp"}, {ProbeArg}, {ControlArg}} {
		frame := realStep(t, "policy frame")
		recordSteps(t, "", map[string]func(*helperState) error{"policy frame": frame})
		withStdin(t, encodedFrame(t, Policy{Mode: ModePlan, BlockedPaths: []string{"/home/u/.codemeld"}}))
		if code := RunHelper(args); code != probeFailed {
			t.Errorf("%v: exit %d, want %d", args, code, probeFailed)
		}
	}
}

func TestRunHelperSeccompReceivesDecodedPolicy(t *testing.T) {
	want := Policy{Mode: ModeAutoEdits, ExceptionalAuthority: NetworkAccessAuthority, BlockedPaths: []string{"/home/u/.codemeld"}, TmpDir: "/tmp/t"}
	var got Policy
	recordSteps(t, "", map[string]func(*helperState) error{
		"policy frame": realStep(t, "policy frame"),
		"seccomp":      func(s *helperState) error { got = s.policy; return nil },
	})
	withStdin(t, encodedFrame(t, want))
	if code := RunHelper([]string{"/bin/true"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("seccomp policy = %+v, want %+v", got, want)
	}
}

func TestRunHelperFailingThreadCountNeverExecs(t *testing.T) {
	old := countUserThreads
	t.Cleanup(func() { countUserThreads = old })
	countUserThreads = func() (uint64, error) { return 0, syscall.EACCES }
	calls := recordSteps(t, "", map[string]func(*helperState) error{"rlimits": realStep(t, "rlimits")})
	stderr := captureStderr(t)
	code := RunHelper([]string{"/bin/true"})
	out := stderr()
	if code != SetupFailureExitCode || !strings.HasPrefix(out, "codemeld confinement: rlimits: ") || slices.Contains(*calls, "exec") {
		t.Errorf("exit %d, stderr %q, steps %v", code, out, *calls)
	}
}

func TestRunHelperRefusesEmptyArgs(t *testing.T) {
	calls := recordSteps(t, "", nil)
	stderr := captureStderr(t)
	code := RunHelper(nil)
	out := stderr()
	if code != SetupFailureExitCode || len(*calls) != 0 || !strings.HasPrefix(out, "codemeld confinement: ") {
		t.Errorf("exit %d, steps %v, stderr %q", code, *calls, out)
	}
}

func TestRunHelperLocksThreadFirst(t *testing.T) {
	steps := helperSteps
	calls := recordSteps(t, "", nil)
	for i, s := range steps {
		if s.name == "lock thread" {
			helperSteps[i] = s
		}
	}
	oldLock := lockOSThread
	t.Cleanup(func() { lockOSThread = oldLock })
	lockOSThread = func() { *calls = append(*calls, "LockOSThread") }
	RunHelper([]string{"/bin/true"})
	if len(*calls) < 2 || (*calls)[0] != "LockOSThread" || (*calls)[1] != "policy frame" {
		t.Errorf("calls = %v, want LockOSThread then policy frame", *calls)
	}
}

func TestNoNewPrivsUsesAllThreadsCall(t *testing.T) {
	t.Setenv("TERM", os.Getenv("TERM"))
	old := allThreadsSyscall
	t.Cleanup(func() { allThreadsSyscall = old })
	var got []uintptr
	allThreadsSyscall = func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
		got = []uintptr{trap, a1, a2, a3}
		return 0, 0, syscall.ENOTSUP
	}
	var execRan bool
	steps, exec := helperSteps, execStep
	t.Cleanup(func() { helperSteps, execStep = steps, exec })
	helperSteps = nil
	for _, s := range steps {
		if s.name == "no_new_privs" {
			helperSteps = append(helperSteps, s)
		}
	}
	execStep = helperStep{exec.name, func(*helperState) error { execRan = true; return nil }}
	stderr := captureStderr(t)
	code := RunHelper([]string{"/bin/true"})
	out := stderr()
	if code != SetupFailureExitCode || execRan || !strings.Contains(out, "no_new_privs") {
		t.Errorf("exit %d, exec %v, stderr %q", code, execRan, out)
	}
	if !reflect.DeepEqual(got, []uintptr{unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0}) {
		t.Errorf("syscall args = %v", got)
	}
}

func TestRunHelperLeavesNoInheritableDescriptor(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "enforce.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cgo-free test binary: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		name, leak string
		wantLeak   bool
	}{{"setup as shipped", "", false}, {"setup leaks a descriptor", "1", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, d := range []string{"work/.codemeld", "tmp"} {
				if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// Blocking the whole shared temp tree keeps the read walk from listing other tests' temp dirs, which can vanish before Landlock opens them.
			sharedTmp, err := filepath.EvalSymlinks(os.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var frame bytes.Buffer
			if err := WritePolicyFrame(&frame, Policy{
				Mode:         ModeAutoEdits,
				BlockedPaths: []string{sharedTmp},
				WriteRoots:   []string{filepath.Join(dir, "work")},
				NoWritePaths: []string{filepath.Join(dir, "work/.codemeld")},
				TmpDir:       filepath.Join(dir, "tmp"),
			}); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(bin, "-test.run=^TestHelperDescriptorChild$")
			child.Env = append(os.Environ(), "CODEMELD_TEST_FD_CHILD=1", "CODEMELD_TEST_FD_LEAK="+tc.leak)
			child.Stdin = &frame
			raw, err := child.CombinedOutput()
			out := string(raw)
			if i := strings.Index(out, "fdcheck skip: "); i >= 0 {
				t.Skip(strings.SplitN(out[i:], "\n", 2)[0])
			}
			if i := strings.Index(out, "codemeld confinement: no_new_privs: "); i >= 0 {
				t.Skip("no_new_privs unavailable: " + strings.SplitN(out[i:], "\n", 2)[0])
			}
			if err != nil || !strings.Contains(out, "fdcheck exit=0\n") {
				t.Fatalf("child did not reach the exec seam after setup: %v\n%s", err, out)
			}
			leaked := strings.Contains(out, "fdcheck leaked=") && !strings.Contains(out, "fdcheck leaked=[]\n")
			if leaked != tc.wantLeak {
				t.Errorf("leak reported = %v, want %v\n%s", leaked, tc.wantLeak, out)
			}
		})
	}
}

func TestHelperDescriptorChild(t *testing.T) {
	if os.Getenv("CODEMELD_TEST_FD_CHILD") == "" {
		t.Skip("runs only as the cgo-free child of TestRunHelperLeavesNoInheritableDescriptor")
	}
	if abi, err := landlockABI(); err != nil || abi < 3 {
		fmt.Printf("fdcheck skip: landlock ABI 3 unavailable (abi %d, err %v)\n", abi, err)
		return
	}
	for i, s := range helperSteps {
		if s.name == "seccomp" && os.Getenv("CODEMELD_TEST_FD_LEAK") != "" {
			run := s.run
			helperSteps[i].run = func(st *helperState) error {
				if err := run(st); err != nil {
					return err
				}
				_, err := unix.Dup(2)
				return err
			}
		}
	}
	execStep.run = func(*helperState) error {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return err
		}
		leaked := []string{}
		for _, e := range entries {
			fd, err := strconv.Atoi(e.Name())
			if err != nil || fd <= 2 {
				continue
			}
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if err == nil && flags&unix.FD_CLOEXEC == 0 {
				leaked = append(leaked, e.Name())
			}
		}
		fmt.Printf("fdcheck leaked=%v\n", leaked)
		return nil
	}
	fmt.Printf("fdcheck exit=%d\n", RunHelper([]string{"/bin/true"}))
}
