package enforce

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"codemeld.dev/codemeld/internal/runner"
	"golang.org/x/sys/unix"
)

const (
	nnpChildEnv     = "CODEMELD_TEST_PROBE_NNP"
	ptraceTargetEnv = "CODEMELD_TEST_PTRACE_TARGET"
	capSysChroot    = 18
	capSysPtrace    = 19
	capSysAdmin     = 21
)

func init() {
	if os.Getenv(nnpChildEnv) != "" {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			panic(err)
		}
	}
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperCommand {
		os.Exit(RunHelper(os.Args[2:]))
	}
	if os.Getenv(ptraceTargetEnv) != "" {
		_ = unix.Prctl(unix.PR_SET_PTRACER, unix.PR_SET_PTRACER_ANY, 0, 0, 0)
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestProbeChild(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 {
		t.Skip("runs only as the disposable child of the probe tests")
	}
	fmt.Printf("probe exit=%d\n", runProbe(&helperState{}, args))
}

func hostIA32EmulationGap() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	path := "/boot/config-" + unix.ByteSliceToString(uts.Release[:])
	config, _ := os.ReadFile(path)
	cmdline, _ := os.ReadFile("/proc/cmdline")
	return ia32EmulationGap(path, config, cmdline)
}

func ia32EmulationGap(configPath string, config, cmdline []byte) string {
	defaultDisabled := false
	for line := range strings.Lines(string(config)) {
		switch strings.TrimSpace(line) {
		case "# CONFIG_IA32_EMULATION is not set":
			return configPath + ": CONFIG_IA32_EMULATION is not set"
		case "CONFIG_IA32_EMULATION_DEFAULT_DISABLED=y":
			defaultDisabled = true
		}
	}
	for _, field := range strings.Fields(string(cmdline)) {
		if v, ok := strings.CutPrefix(field, "ia32_emulation="); ok {
			if on, err := strconv.ParseBool(v); err == nil {
				if on {
					return ""
				}
				return "/proc/cmdline sets " + field
			}
		}
	}
	if defaultDisabled {
		return configPath + ": CONFIG_IA32_EMULATION_DEFAULT_DISABLED=y and /proc/cmdline does not enable ia32_emulation"
	}
	return ""
}

func TestIA32EmulationGap(t *testing.T) {
	for _, tc := range []struct {
		config, cmdline string
		gap             bool
	}{
		{"CONFIG_IA32_EMULATION=y\n", "quiet", false},
		{"", "quiet", false},
		{"# CONFIG_IA32_EMULATION is not set\n", "ia32_emulation=1", true},
		{"CONFIG_IA32_EMULATION=y\n", "quiet ia32_emulation=0", true},
		{"CONFIG_IA32_EMULATION=y\nCONFIG_IA32_EMULATION_DEFAULT_DISABLED=y\n", "quiet", true},
		{"CONFIG_IA32_EMULATION=y\nCONFIG_IA32_EMULATION_DEFAULT_DISABLED=y\n", "ia32_emulation=true", false},
	} {
		if gap := ia32EmulationGap("config", []byte(tc.config), []byte(tc.cmdline)); (gap != "") != tc.gap {
			t.Errorf("config %q, cmdline %q: gap %q", tc.config, tc.cmdline, gap)
		}
	}
}

func probeInChild(t *testing.T, env []string, args ...string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestProbeChild$", "--"}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	_, after, ok := strings.Cut(string(out), "probe exit=")
	if !ok {
		t.Fatalf("%v: child reported no exit (%v):\n%s", args, err, out)
	}
	code, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(after, "\n", 2)[0]))
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return code
}

func statusField(t *testing.T, pid, field string) string {
	t.Helper()
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(data)) {
		if v, ok := strings.CutPrefix(line, field+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no %s in /proc/%s/status", field, pid)
	return ""
}

func hasCap(t *testing.T, bit uint) bool {
	t.Helper()
	eff, err := strconv.ParseUint(statusField(t, "self", "CapEff"), 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	return eff&(1<<bit) != 0
}

func sysctl(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func deniedUnless(allowed bool) int {
	if allowed {
		return probeAllowed
	}
	return probeDenied
}

func TestProbeExitMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{&fs.PathError{Op: "open", Path: "/x", Err: unix.EACCES}, 10},
		{&fs.PathError{Op: "open", Path: "/x", Err: unix.EPERM}, 10},
		{&fs.PathError{Op: "open", Path: "/x", Err: unix.ENOENT}, 11},
		{errors.New("other"), 11},
	}
	for _, tc := range cases {
		if got := probeExit(tc.err); got != tc.want {
			t.Errorf("probeExit(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

func TestRunProbeArgumentErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus", t.TempDir()}, {"write-tmp"}, {"write-tmp", "a", "b"}} {
		if got := runProbe(&helperState{}, args); got != probeFailed {
			t.Errorf("runProbe(%q) = %d, want %d", args, got, probeFailed)
		}
	}
}

func TestRunProbeRejectsWrongArgumentCounts(t *testing.T) {
	for name, p := range probes {
		for _, n := range []int{p.n - 1, p.n + 1} {
			if n < 0 {
				continue
			}
			args := append([]string{name}, slices.Repeat([]string{"/nonexistent-probe-arg"}, n)...)
			if got := runProbe(&helperState{nproc: 1}, args); got != probeFailed {
				t.Errorf("runProbe(%q) = %d, want %d", args, got, probeFailed)
			}
		}
	}
	for _, args := range [][]string{{"socket-unix", "x"}, {"chmod"}, {"environment", "/h", "/r"}, {"environment", "/h", "/r", "", "x"}, {"rlimits", "x"}} {
		if got := runProbe(&helperState{nproc: 1}, args); got != probeFailed {
			t.Errorf("runProbe(%q) = %d, want %d", args, got, probeFailed)
		}
	}
	wantCounts := map[string]int{"socket-unix": 0, "chmod": 1, "mount": 1, "environment": 3, "no-new-privs": 0, "clone-newuser": 0}
	for name, n := range wantCounts {
		if probes[name].n != n {
			t.Errorf("%s takes %d arguments, want %d", name, probes[name].n, n)
		}
	}
}

func TestFilesystemProbesSucceedUnrestricted(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "r")
	if err := os.WriteFile(file, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"read-protected":     file,
		"truncate-read-root": file,
		"read-read-root":     file,
		"write-outside":      filepath.Join(dir, "outside-new"),
		"write-tmp":          filepath.Join(dir, "tmp-new"),
	}
	for leg, path := range cases {
		if got := runProbe(&helperState{}, []string{leg, path}); got != probeAllowed {
			t.Errorf("%s: exit %d, want 0", leg, got)
		}
	}
	for _, created := range []string{"outside-new", "tmp-new"} {
		if _, err := os.Stat(filepath.Join(dir, created)); err != nil {
			t.Errorf("%s not created: %v", created, err)
		}
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "content" {
		t.Errorf("truncate changed the file: %q, %v", data, err)
	}
	if got := runProbe(&helperState{}, []string{"write-tmp", filepath.Join(dir, "tmp-new")}); got != probeFailed {
		t.Errorf("write-tmp on an existing file: exit %d, want 11 (O_EXCL)", got)
	}
	if got := runProbe(&helperState{}, []string{"read-protected", filepath.Join(dir, "missing")}); got != probeFailed {
		t.Errorf("read-protected on a missing file: exit %d, want 11", got)
	}
}

func sysvIPCIDs(t *testing.T) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, kind := range []string{"shm", "msg", "sem"} {
		data, err := os.ReadFile("/proc/sysvipc/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if f := strings.Fields(line); i > 0 && len(f) > 1 {
				ids[kind+" "+f[1]] = true
			}
		}
	}
	return ids
}

func mqExists(t *testing.T, name string) bool {
	t.Helper()
	p, err := unix.BytePtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	fd, _, errno := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(p)), unix.O_RDONLY|unix.O_CLOEXEC, 0, 0, 0, 0)
	if errno == 0 {
		_ = unix.Close(int(fd))
		return true
	}
	if errno != unix.ENOENT {
		t.Fatalf("mq_open %s: %v", name, errno)
	}
	return false
}

func TestDeputyProbesSucceedUnrestricted(t *testing.T) {
	if _, err := os.Stat("/proc/sys/fs/mqueue"); err != nil {
		t.Skipf("POSIX message queues unavailable: %v", err)
	}
	if info, err := os.Stat("/dev/shm"); err != nil || !info.IsDir() {
		t.Skipf("/dev/shm unavailable: %v", err)
	}
	name := fmt.Sprintf("codemeld-probe-test-%d", os.Getpid())
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	before := sysvIPCIDs(t)
	for _, args := range [][]string{
		{"socket-unix"}, {"socket-inet"}, {"socketpair"}, {"shmget"}, {"msgget"}, {"semget"},
		{"mq-open", name}, {"shm-open", name}, {"environ-parent", strconv.Itoa(os.Getpid())}, {"chmod", file},
	} {
		if got := runProbe(&helperState{}, args); got != probeAllowed {
			t.Errorf("%v: exit %d, want 0", args, got)
		}
	}
	for id := range sysvIPCIDs(t) {
		if !before[id] {
			t.Errorf("System V IPC object %s left behind", id)
		}
	}
	if mqExists(t, name) {
		t.Errorf("message queue %s left behind", name)
	}
	if _, err := os.Stat(filepath.Join("/dev/shm", name)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("/dev/shm/%s left behind: %v", name, err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("chmod: %v, %v", info, err)
	}
	if got := runProbe(&helperState{}, []string{"environ-parent", "self"}); got != probeFailed {
		t.Errorf("environ-parent with a non-numeric pid: exit %d, want 11", got)
	}
	if got := runProbe(&helperState{}, []string{"shm-open", name}); got != probeAllowed {
		t.Errorf("shm-open after cleanup: exit %d, want 0", got)
	}
}

func TestIoUringSetupProbe(t *testing.T) {
	want := probeAllowed
	switch disabled := sysctl("/proc/sys/kernel/io_uring_disabled"); disabled {
	case "", "0":
	case "1":
		want = deniedUnless(hasCap(t, capSysAdmin))
	default:
		want = probeDenied
	}
	if got := runProbe(&helperState{}, []string{"io-uring-setup"}); got != want {
		t.Errorf("io-uring-setup: exit %d, want %d", got, want)
	}
}

func TestSetflagsProbeRestoresFlags(t *testing.T) {
	dir := t.TempDir()
	preflight := filepath.Join(dir, "preflight")
	file := filepath.Join(dir, "fixture")
	for _, p := range []string{preflight, file} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	flagsOf := func(path string) (uint32, error) {
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		defer func() { _ = f.Close() }()
		return unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	}
	f, err := os.Open(preflight)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err == nil {
		err = unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(flags))
	}
	_ = f.Close()
	if err != nil {
		t.Skipf("FS_IOC_GETFLAGS/FS_IOC_SETFLAGS unsupported on %s: %v", dir, err)
	}
	before, err := flagsOf(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := runProbe(&helperState{}, []string{"ioctl-setflags", file}); got != probeAllowed {
		t.Fatalf("ioctl-setflags: exit %d, want 0", got)
	}
	if after, err := flagsOf(file); err != nil || after != before {
		t.Errorf("flags after probe = %#x, %v; want %#x", after, err, before)
	}
	if got := runProbe(&helperState{}, []string{"ioctl-setflags", filepath.Join(dir, "missing")}); got != probeFailed {
		t.Errorf("ioctl-setflags on a missing file: exit %d, want 11", got)
	}
}

func mounted(t *testing.T, dir string) bool {
	t.Helper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) > 4 && f[4] == dir {
			return true
		}
	}
	return false
}

func TestPrivilegedProbesInDisposableChild(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := probeInChild(t, nil, "chroot", dir), deniedUnless(hasCap(t, capSysChroot)); got != want {
		t.Errorf("chroot: exit %d, want %d", got, want)
	}
	if got, want := probeInChild(t, nil, "mount", dir), deniedUnless(hasCap(t, capSysAdmin)); got != want {
		t.Errorf("mount: exit %d, want %d", got, want)
	}
	if mounted(t, dir) {
		t.Errorf("mount left %s mounted", dir)
	}
	if n := sysctl("/proc/sys/user/max_user_namespaces"); n == "0" {
		t.Skip("user namespaces unavailable: /proc/sys/user/max_user_namespaces is 0")
	}
	want := deniedUnless(sysctl("/proc/sys/kernel/unprivileged_userns_clone") != "0" || hasCap(t, capSysAdmin))
	if got := probeInChild(t, nil, "clone-newuser"); got != want {
		t.Errorf("clone-newuser: exit %d, want %d", got, want)
	}
}

func TestPtraceProbeDetachesTestOwnedTarget(t *testing.T) {
	target := exec.Command(os.Args[0])
	target.Env = append(os.Environ(), ptraceTargetEnv+"=1")
	stdin, err := target.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := target.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = target.Process.Kill()
		_ = target.Wait()
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("target not ready: %q, %v", line, err)
	}
	pid := strconv.Itoa(target.Process.Pid)
	want := probeAllowed
	switch sysctl("/proc/sys/kernel/yama/ptrace_scope") {
	case "2":
		want = deniedUnless(hasCap(t, capSysPtrace))
	case "3":
		want = probeDenied
	}
	if got := probeInChild(t, nil, "ptrace-parent", pid); got != want {
		t.Errorf("ptrace-parent: exit %d, want %d", got, want)
	}
	if tracer := statusField(t, pid, "TracerPid"); tracer != "0" {
		t.Errorf("target still traced by %s", tracer)
	}
	if state := statusField(t, pid, "State"); strings.HasPrefix(state, "T") || strings.HasPrefix(state, "t") {
		t.Errorf("target left stopped: %s", state)
	}
	if got := runProbe(&helperState{}, []string{"ptrace-parent", "x"}); got != probeFailed {
		t.Errorf("ptrace-parent with a non-numeric pid: exit %d, want 11", got)
	}
}

func TestNoNewPrivsProbe(t *testing.T) {
	if got := probeInChild(t, append(os.Environ(), nnpChildEnv+"=1"), "no-new-privs"); got != probeAllowed {
		t.Errorf("with no_new_privs: exit %d, want 0", got)
	}
	want := probeFailed
	if statusField(t, "self", "NoNewPrivs") == "1" {
		want = probeAllowed
	}
	if got := probeInChild(t, nil, "no-new-privs"); got != want {
		t.Errorf("inherited no_new_privs state: exit %d, want %d", got, want)
	}
}

func TestEnvironmentProbe(t *testing.T) {
	home, root, tmp := "/home/u", "/tmp/fixture", "/tmp/fixture/tmp"
	for _, tmpDir := range []string{"", tmp} {
		env, err := runner.FixedEnvironment(home, root, tmpDir, runner.FixedPATH, nil)
		if err != nil {
			t.Fatal(err)
		}
		reordered := slices.Clone(env)
		slices.Reverse(reordered)
		for _, tc := range []struct {
			name string
			env  []string
			want int
		}{
			{"exact", env, probeAllowed},
			{"reordered", reordered, probeAllowed},
			{"extra variable", append(slices.Clone(env), "EXTRA=1"), probeFailed},
			{"missing entry", env[1:], probeFailed},
			{"wrong value", append(slices.Clone(env[:len(env)-1]), "LC_ALL=C"), probeFailed},
		} {
			if got := probeInChild(t, tc.env, "environment", home, root, tmpDir); got != tc.want {
				t.Errorf("tmp %q, %s: exit %d, want %d", tmpDir, tc.name, got, tc.want)
			}
		}
	}
}
