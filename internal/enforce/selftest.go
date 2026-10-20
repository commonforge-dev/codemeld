package enforce

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"codemeld.dev/codemeld/internal/runner"
)

const (
	observedAllowed    = "allowed"
	observedDenied     = "denied"
	observedFailed     = "failed"
	observedHeldByHost = "held_by_host"
	observedNotRun     = "not_run"

	probeAllowed     = 0
	probeDenied      = 10
	probeFailed      = 11
	probeUnsupported = 12
)

type selfTestLegResult struct {
	Name        string
	Expected    string
	Observed    string
	Required    bool
	SetupStderr string
	Diagnostic  string
}

type selfTestLeg struct {
	name       string
	probe      string
	expected   string
	auto       bool
	writeRoots []string
	fresh      bool
	arch       string
	args       func(fixture) []string
}

type fixture struct {
	root, home, name, exe string
	pid                   int
}

func (f fixture) tmp() string { return filepath.Join(f.root, "tmp") }

func (f fixture) remove() { _ = os.RemoveAll(f.root) }

func at(parts ...string) func(fixture) []string {
	return func(f fixture) []string { return []string{filepath.Join(append([]string{f.root}, parts...)...)} }
}

func privateName(f fixture) []string { return []string{f.name} }

func ownPid(f fixture) []string { return []string{strconv.Itoa(f.pid)} }

var selfTestLegs = []selfTestLeg{
	{name: "write-outside", expected: observedDenied, fresh: true, args: at("outside", "new")},
	{name: "truncate-read-root", expected: observedDenied, fresh: true, args: at("read", "r")},
	{name: "read-protected", expected: observedDenied, fresh: true, args: func(f fixture) []string {
		return []string{filepath.Join(f.home, ".codemeld", "global", "settings.yaml")}
	}},
	{name: "read-read-root", expected: observedAllowed, args: at("read", "r")},
	{name: "write-tmp", expected: observedAllowed, auto: true, args: at("tmp", "new")},
	{name: "rlimits", expected: observedAllowed},
	{name: "socket-unix", expected: observedDenied},
	{name: "socket-inet", expected: observedDenied},
	{name: "socketpair", expected: observedAllowed},
	{name: "io-uring-setup", expected: observedDenied},
	{name: "shmget", expected: observedDenied},
	{name: "msgget", expected: observedDenied},
	{name: "semget", expected: observedDenied},
	{name: "mq-open", expected: observedDenied, args: privateName},
	{name: "shm-open", expected: observedDenied, auto: true, writeRoots: []string{"/dev/shm"}, args: privateName},
	{name: "ptrace-parent", expected: observedDenied, args: ownPid},
	{name: "environ-parent", expected: observedDenied, args: ownPid},
	{name: "clone-newuser", expected: observedDenied},
	{name: "mount", expected: observedDenied, args: at("outside")},
	{name: "chroot", expected: observedDenied, args: at()},
	{name: "chmod", expected: observedDenied, args: at("read", "r")},
	{name: "ioctl-setflags", expected: observedDenied, args: at("read", "r")},
	{name: "no-new-privs", expected: observedAllowed},
	{name: "environment", expected: observedAllowed, args: func(f fixture) []string { return []string{f.home, f.root, ""} }},
	{name: "environment-auto", probe: "environment", expected: observedAllowed, auto: true, args: func(f fixture) []string {
		return []string{f.home, f.root, f.tmp()}
	}},
	{name: "chmod-auto", probe: "chmod", expected: observedAllowed, auto: true, args: at("tmp", "m")},
	{name: "ioctl-setflags-auto", probe: "ioctl-setflags", expected: observedAllowed, auto: true, args: at("tmp", "m")},
	{name: "x32-syscall", expected: observedDenied, arch: "amd64"},
	{name: "i386-syscall", expected: observedDenied, arch: "amd64"},
	{name: "arm32-syscall", expected: observedDenied, arch: "arm64", args: func(f fixture) []string { return []string{f.exe} }},
}

type helperExit struct {
	code     int
	signal   syscall.Signal
	timedOut bool
	stderr   string
}

var (
	helperExecutable  = "/proc/self/exe"
	selfTestTimeout   = 5 * time.Second
	startHelper       = startHelperProcess
	writeArm32Fixture func(root string) (string, error)
)

func runSelfTestLegs(home, exe string) []selfTestLegResult {
	out := make([]selfTestLegResult, 0, len(selfTestLegs))
	for _, leg := range selfTestLegs {
		out = append(out, runSelfTestLeg(home, exe, leg))
	}
	return out
}

func runSelfTestLeg(home, exe string, leg selfTestLeg) selfTestLegResult {
	r := selfTestLegResult{Name: leg.name, Expected: leg.expected, Required: true}
	if leg.arch != "" && leg.arch != goarch {
		r.Expected, r.Observed, r.Required = observedNotRun, observedNotRun, false
		return r
	}
	var shared *fixture
	if !leg.fresh {
		f, err := newFixture(home, leg)
		if err != nil {
			r.Observed, r.Diagnostic = observedFailed, err.Error()
			return r
		}
		defer f.remove()
		shared = &f
	}
	attempt := func(mode string) helperExit {
		if shared != nil {
			return runLeg(*shared, leg, mode, exe)
		}
		f, err := newFixture(home, leg)
		if err != nil {
			return helperExit{code: -1, stderr: err.Error()}
		}
		defer f.remove()
		return runLeg(f, leg, mode, exe)
	}
	if leg.expected != observedDenied {
		r.Observed, r.SetupStderr, r.Diagnostic = observe(leg, attempt(ProbeArg))
		return r
	}
	control := attempt(ControlArg)
	if leg.name == "arm32-syscall" && !control.timedOut && control.signal == 0 && control.code == probeUnsupported {
		r.Expected, r.Observed, r.Required = observedNotRun, observedNotRun, false
		r.Diagnostic = "linux/arm64: 32-bit ARM executables unsupported (ENOEXEC)"
		return r
	}
	r.Observed, r.SetupStderr, r.Diagnostic = observe(leg, attempt(ProbeArg))
	switch controlObserved, controlSetup, controlDiagnostic := observe(leg, control); {
	case controlObserved == observedAllowed:
	case controlObserved == observedDenied && r.Observed == observedDenied:
		r.Observed = observedHeldByHost
	case controlObserved == observedFailed:
		r.Observed = observedFailed
		r.SetupStderr = strings.Join(slices.DeleteFunc([]string{controlSetup, r.SetupStderr}, func(s string) bool { return s == "" }), "\n")
		r.Diagnostic = strings.Join(slices.DeleteFunc([]string{controlDiagnostic, r.Diagnostic}, func(s string) bool { return s == "" }), "; ")
	default:
		r.Observed = observedFailed
	}
	return r
}

func observe(leg selfTestLeg, e helperExit) (observed, setupStderr, diagnostic string) {
	switch {
	case e.timedOut:
		return observedFailed, "", ""
	case e.signal == syscall.SIGSYS && leg.name == "i386-syscall":
		return observedDenied, "", ""
	case e.signal != 0:
		return observedFailed, "", "killed by " + e.signal.String()
	case e.code == probeAllowed:
		return observedAllowed, "", ""
	case e.code == probeDenied:
		return observedDenied, "", ""
	case e.code == SetupFailureExitCode:
		return observedFailed, e.stderr, ""
	default:
		return observedFailed, "", e.stderr
	}
}

func newFixture(home string, leg selfTestLeg) (fixture, error) {
	root, err := os.MkdirTemp("", "codemeld-selftest-")
	if err != nil {
		return fixture{}, err
	}
	f := fixture{root: filepath.Clean(root), home: home, pid: os.Getpid()}
	f.name = filepath.Base(f.root)
	if err := f.populate(leg); err != nil {
		f.remove()
		return fixture{}, err
	}
	return f, nil
}

func (f *fixture) populate(leg selfTestLeg) error {
	for _, d := range []string{"read", "outside", "tmp"} {
		if err := os.Mkdir(filepath.Join(f.root, d), 0o700); err != nil {
			return err
		}
	}
	for _, file := range []string{"read/r", "tmp/m"} {
		if err := os.WriteFile(filepath.Join(f.root, file), []byte("r"), 0o600); err != nil {
			return err
		}
	}
	if leg.name != "arm32-syscall" || writeArm32Fixture == nil {
		return nil
	}
	var err error
	f.exe, err = writeArm32Fixture(f.root)
	return err
}

func runLeg(f fixture, leg selfTestLeg, mode, exe string) helperExit {
	policy := Policy{Mode: ModePlan, BlockedPaths: []string{filepath.Join(f.home, ".codemeld")}}
	tmp := ""
	if leg.auto {
		tmp = f.tmp()
		policy.Mode, policy.TmpDir, policy.WriteRoots = ModeAutoEdits, tmp, leg.writeRoots
	}
	var frame bytes.Buffer
	if err := WritePolicyFrame(&frame, policy); err != nil {
		return helperExit{code: -1}
	}
	env, err := runner.FixedEnvironment(f.home, f.root, tmp, runner.FixedPATH, nil)
	if err != nil {
		return helperExit{code: -1}
	}
	argv := []string{exe, HelperCommand, mode, cmp.Or(leg.probe, leg.name)}
	if leg.args != nil {
		argv = append(argv, leg.args(f)...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), selfTestTimeout)
	defer cancel()
	return startHelper(ctx, argv, env, f.root, frame.Bytes())
}

func startHelperProcess(ctx context.Context, argv, env []string, dir string, frame []byte) helperExit {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env, cmd.Dir, cmd.Stdin = env, dir, bytes.NewReader(frame)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	line, _, _ := strings.Cut(stderr.String(), "\n")
	e := helperExit{code: -1, stderr: line}
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		e.timedOut = true
	case err == nil:
		e.code = 0
	case errors.As(err, &exitErr):
		e.code = exitErr.ExitCode()
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			e.signal = ws.Signal()
		}
	}
	return e
}
