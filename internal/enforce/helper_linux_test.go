package enforce

import (
	"bytes"
	"context"
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
	"time"

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

const handoffFDsEnv = "CODEMELD_TEST_HANDOFF_FDS"

func init() {
	probes["h-fds"] = probe{1, func(a []string) int {
		if writeFDLinks(a[0]) != nil {
			return probeFailed
		}
		return probeAllowed
	}}
}

func writeFDLinks(path string) error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	var links []string
	for _, e := range entries {
		if link, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil {
			links = append(links, link)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(links, "\n")), 0o600)
}

func TestHandoffTargetChild(t *testing.T) {
	path := os.Getenv(handoffFDsEnv)
	if path == "" {
		t.Skip("runs only as the exec target of the broker handoff tests")
	}
	if err := writeFDLinks(path); err != nil {
		t.Fatal(err)
	}
}

type handoffFx struct {
	bin, work, out string
	policy         Policy
	env            []string
}

var unavailableErrnos = []unix.Errno{unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP}

func handoffSetup(t *testing.T) handoffFx {
	t.Helper()
	abi, err := landlockABI()
	for _, e := range unavailableErrnos {
		if errors.Is(err, e) {
			t.Skipf("unverified: the kernel lacks landlock: %v", err)
		}
	}
	if err != nil {
		t.Fatalf("landlock ABI: %v", err)
	}
	if abi < 3 {
		t.Skipf("unverified: landlock ABI %d, want 3", abi)
	}
	bin := mxBinary(t)
	f := mxSetup(t)
	work, tmp := f.mkdir(t, "work"), f.mkdir(t, "tmp")
	out := filepath.Join(work, "fds")
	return handoffFx{
		bin: bin, work: work, out: out,
		policy: Policy{Mode: ModeAutoEdits, Broker: BrokerSlice, BlockedPaths: f.blocked(), WriteRoots: []string{work}, TmpDir: tmp},
		env:    append(f.env(t, work, tmp), handoffFDsEnv+"="+out),
	}
}

func (x handoffFx) args(mode string) []string {
	if mode == ProbeArg {
		return []string{ProbeArg, "h-fds", x.out}
	}
	return []string{x.bin, "-test.run=^TestHandoffTargetChild$"}
}

func (x handoffFx) targetRan() bool {
	_, err := os.Stat(x.out)
	return !errors.Is(err, os.ErrNotExist)
}

type handoffRun struct {
	cmd    *exec.Cmd
	parent *os.File
	ino    uint64
	done   chan struct{}
	stderr bytes.Buffer
	err    error
}

func startHandoff(t *testing.T, x handoffFx, p Policy, channel bool, args ...string) *handoffRun {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := &handoffRun{parent: os.NewFile(uintptr(fds[0]), "channel"), done: make(chan struct{})}
	child := os.NewFile(uintptr(fds[1]), "helper channel")
	var st unix.Stat_t
	if err := unix.Fstat(fds[1], &st); err != nil {
		t.Fatal(err)
	}
	h.ino = st.Ino
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	h.cmd = exec.CommandContext(ctx, x.bin, append([]string{HelperCommand}, args...)...)
	h.cmd.Env, h.cmd.Dir, h.cmd.Stdin, h.cmd.Stderr = x.env, x.work, bytes.NewReader(encodedFrame(t, p)), &h.stderr
	if channel {
		h.cmd.ExtraFiles = []*os.File{child}
	}
	h.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	h.cmd.Cancel = func() error { return syscall.Kill(-h.cmd.Process.Pid, syscall.SIGKILL) }
	h.cmd.WaitDelay = time.Second
	err = h.cmd.Start()
	child.Close()
	if err != nil {
		h.parent.Close()
		cancel()
		t.Fatal(err)
	}
	go func() { h.err = h.cmd.Wait(); close(h.done) }()
	t.Cleanup(func() { cancel(); <-h.done; h.parent.Close() })
	return h
}

func (h *handoffRun) exit(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(within):
		t.Fatalf("helper still running after %v", within)
	}
	var ee *exec.ExitError
	if errors.As(h.err, &ee) {
		return ee.ExitCode()
	}
	if h.err != nil {
		t.Fatal(h.err)
	}
	return 0
}

func (h *handoffRun) receive(t *testing.T) *os.File {
	t.Helper()
	l, err := ReceiveListener(h.parent, 5*time.Second)
	if err == nil {
		t.Cleanup(func() { l.Close() })
		return l
	}
	h.exit(t, 15*time.Second)
	out := h.stderr.String()
	for _, e := range unavailableErrnos {
		if strings.Contains(out, "install seccomp listener filter: "+e.Error()) {
			t.Skipf("unverified: the kernel refused the seccomp listener filter: %s", out)
		}
	}
	t.Fatalf("receive listener: %v\nhelper: %s", err, out)
	return nil
}

func TestRunHelperBrokerHandoff(t *testing.T) {
	for _, mode := range []string{"exec", ProbeArg} {
		t.Run(mode, func(t *testing.T) {
			x := handoffSetup(t)
			h := startHandoff(t, x, x.policy, true, x.args(mode)...)
			l := h.receive(t)
			if flags, err := unix.FcntlInt(l.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Errorf("received listener flags %#x, %v: want FD_CLOEXEC", flags, err)
			}
			if link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", l.Fd())); err != nil || !strings.Contains(link, "seccomp notify") {
				t.Fatalf("received %q, %v: want a seccomp notify descriptor", link, err)
			}
			if n := notifyListeners(t, strconv.Itoa(h.cmd.Process.Pid)); n != 0 {
				t.Errorf("helper holds %d listener descriptors after its acknowledgement", n)
			}
			child := exec.Command("/bin/sleep", "30")
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			inherited := notifyListeners(t, strconv.Itoa(child.Process.Pid))
			_ = child.Process.Kill()
			_ = child.Wait()
			if inherited != 0 {
				t.Errorf("a codemeld child inherited %d listener descriptors", inherited)
			}
			time.Sleep(200 * time.Millisecond)
			if x.targetRan() {
				t.Fatal("the target ran before release")
			}
			select {
			case <-h.done:
				t.Fatalf("helper exited before release: %v\n%s", h.err, h.stderr.String())
			default:
			}
			if err := ReleaseHelper(h.parent); err != nil {
				t.Fatal(err)
			}
			if code := h.exit(t, 15*time.Second); code != 0 {
				t.Fatalf("exit %d\n%s", code, h.stderr.String())
			}
			raw, err := os.ReadFile(x.out)
			if err != nil || len(raw) == 0 {
				t.Fatalf("target descriptor list %q: %v", raw, err)
			}
			for _, link := range strings.Split(string(raw), "\n") {
				if link == fmt.Sprintf("socket:[%d]", h.ino) || strings.Contains(link, "seccomp notify") {
					t.Errorf("target holds %s", link)
				}
			}
		})
	}
}

func TestRunHelperBrokerHandoffFailuresNeverRunTarget(t *testing.T) {
	missing := []string{"/nonexistent/codemeld-target"}
	for _, c := range []struct {
		name, mode string
		channel    bool
		args       []string
		parent     func(t *testing.T, h *handoffRun)
		wait       time.Duration
		stderr     string
	}{
		{"parent closes the channel/exec", "exec", true, nil, func(_ *testing.T, h *handoffRun) { h.parent.Close() }, 15 * time.Second, "seccomp: "},
		{"parent closes the channel/probe", ProbeArg, true, nil, func(_ *testing.T, h *handoffRun) { h.parent.Close() }, 15 * time.Second, "seccomp: "},
		{"missing release/exec", "exec", true, nil, func(t *testing.T, h *handoffRun) { h.receive(t).Close(); h.parent.Close() }, 15 * time.Second, "seccomp: await release: "},
		{"missing release/probe", ProbeArg, true, nil, func(t *testing.T, h *handoffRun) { h.receive(t).Close(); h.parent.Close() }, 15 * time.Second, "seccomp: await release: "},
		{"no setup channel/exec", "exec", false, nil, nil, 15 * time.Second, "seccomp: send listener: "},
		{"no setup channel/probe", ProbeArg, false, nil, nil, 15 * time.Second, "seccomp: send listener: "},
		{"withheld release", "exec", true, nil, func(t *testing.T, h *handoffRun) { h.receive(t).Close() }, 20 * time.Second, "seccomp: await release: " + os.ErrDeadlineExceeded.Error()},
		{"exec failure", "exec", true, missing, func(t *testing.T, h *handoffRun) {
			h.receive(t).Close()
			if err := ReleaseHelper(h.parent); err != nil {
				t.Fatal(err)
			}
		}, 15 * time.Second, "exec: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := handoffSetup(t)
			args := c.args
			if args == nil {
				args = x.args(c.mode)
			}
			before := notifyListeners(t, "self")
			h := startHandoff(t, x, x.policy, c.channel, args...)
			if c.parent != nil {
				c.parent(t, h)
			}
			code := h.exit(t, c.wait)
			out := h.stderr.String()
			if code != SetupFailureExitCode || !strings.HasPrefix(out, "codemeld confinement: "+c.stderr) {
				t.Errorf("exit %d, stderr %q", code, out)
			}
			if x.targetRan() {
				t.Error("the target ran")
			}
			if after := notifyListeners(t, "self"); after != before {
				t.Errorf("%d listener descriptors open after the failed handoff, %d before", after, before)
			}
		})
	}
}

func TestRunHelperHandoffOnlyForBrokerPolicies(t *testing.T) {
	x := handoffSetup(t)
	nonBroker := x.policy
	nonBroker.Broker = BrokerNone
	for _, c := range []struct {
		name, mode string
		policy     Policy
	}{
		{"non-broker probe", ProbeArg, nonBroker},
		{"control with a broker policy", ControlArg, x.policy},
	} {
		t.Run(c.name, func(t *testing.T) {
			_ = os.Remove(x.out)
			h := startHandoff(t, x, c.policy, true, c.mode, "h-fds", x.out)
			if code := h.exit(t, 15*time.Second); code != probeAllowed {
				t.Fatalf("exit %d\n%s", code, h.stderr.String())
			}
			if !x.targetRan() {
				t.Error("the probe did not run")
			}
			b := make([]byte, 1)
			if n, _, err := unix.Recvfrom(int(h.parent.Fd()), b, unix.MSG_DONTWAIT); n != 0 || err != nil {
				t.Errorf("the helper used the channel: %q, %v", b[:n], err)
			}
		})
	}
}
