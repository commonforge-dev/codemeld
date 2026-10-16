//go:build linux

package enforce

import (
	"bytes"
	"context"
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

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/sys/unix"
)

func TestResolveNamesTheFirstMismatchedLeg(t *testing.T) {
	withArch(t, "amd64")
	for _, flip := range []struct {
		leg      string
		exit     int
		observed string
	}{
		{"write-outside", probeAllowed, "allowed"},
		{"truncate-read-root", probeAllowed, "allowed"},
		{"read-protected", probeFailed, "failed"},
		{"read-read-root", probeDenied, "denied"},
		{"write-tmp", probeDenied, "denied"},
		{"rlimits", probeFailed, "failed"},
	} {
		stubStarter(t, func(mode, leg string) helperExit {
			if mode == ProbeArg && leg == flip.leg {
				return helperExit{code: flip.exit}
			}
			return expectedExit(mode, leg)
		})
		got := Resolve(ResolveInput{Home: homeWithCodemeld(t)})
		want := "linux: self-test leg " + flip.leg + " observed " + flip.observed
		if got.Capability != Refused || got.Reason != want {
			t.Errorf("%s flipped: Resolve() = %+v, want reason %q", flip.leg, got, want)
		}
	}
}

func TestResolveKeepsSetupFailureStderr(t *testing.T) {
	const line = "codemeld confinement: landlock: landlock ABI 2 < 3"
	stubStarter(t, func(mode, leg string) helperExit {
		if mode == ProbeArg {
			return helperExit{code: SetupFailureExitCode, stderr: line}
		}
		return helperExit{code: probeAllowed}
	})
	got := Resolve(ResolveInput{Home: homeWithCodemeld(t)})
	if got.Capability != Refused || got.Reason != "linux: self-test leg write-outside observed failed: "+line {
		t.Errorf("Resolve() = %+v", got)
	}
}

func TestResolveTimedOutLegFails(t *testing.T) {
	withArch(t, "amd64")
	script := filepath.Join(t.TempDir(), "slow-helper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldExe, oldTimeout := helperExecutable, selfTestTimeout
	t.Cleanup(func() { helperExecutable, selfTestTimeout = oldExe, oldTimeout })
	helperExecutable, selfTestTimeout = script, 50*time.Millisecond
	start := time.Now()
	got := Resolve(ResolveInput{Home: homeWithCodemeld(t)})
	if got.Capability != Refused || got.Reason != "linux: self-test leg write-outside observed failed" {
		t.Errorf("Resolve() = %+v", got)
	}
	for _, l := range got.Legs {
		if l.Observed != observedFailed && l.Name != "arm32-syscall" {
			t.Errorf("leg %s observed %s, want failed", l.Name, l.Observed)
		}
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("Resolve took %v; the timeout did not stop the helpers", elapsed)
	}
}

func TestResolveFrames(t *testing.T) {
	withArch(t, "amd64")
	calls := stubStarter(t, expectedExit)
	home := homeWithCodemeld(t)
	Resolve(ResolveInput{Home: home})
	if len(*calls) == 0 {
		t.Fatal("no helper started")
	}
	auto := []string{"write-tmp", "shm-open", "environment-auto", "chmod-auto", "ioctl-setflags-auto"}
	for _, c := range *calls {
		want := Policy{Mode: ModePlan, BlockedPaths: []string{filepath.Join(home, ".codemeld")}}
		if slices.Contains(auto, c.leg) {
			want.Mode, want.TmpDir = ModeAutoEdits, filepath.Join(c.dir, "tmp")
		}
		if c.leg == "shm-open" {
			want.WriteRoots = []string{"/dev/shm"}
		}
		if !reflect.DeepEqual(c.policy, want) {
			t.Errorf("%s %s frame = %+v, want %+v", c.mode, c.leg, c.policy, want)
		}
		if c.argv[0] != "/proc/self/exe" || c.argv[1] != HelperCommand {
			t.Errorf("argv = %q", c.argv)
		}
		switch c.leg {
		case "chmod-auto", "ioctl-setflags-auto":
			if c.argv[4] != filepath.Join(c.dir, "tmp", "m") {
				t.Errorf("%s targets %s, want a file in the leg's temp folder", c.leg, c.argv[4])
			}
		case "chmod", "ioctl-setflags":
			if c.argv[4] != filepath.Join(c.dir, "read", "r") {
				t.Errorf("%s targets %s, want the owned read-root file", c.leg, c.argv[4])
			}
		case "ptrace-parent", "environ-parent":
			if c.argv[4] != strconv.Itoa(os.Getpid()) {
				t.Errorf("%s targets pid %s, want the runner's own pid", c.leg, c.argv[4])
			}
		}
	}
}

func TestResolveEnvironmentLegsPassExpectedInputs(t *testing.T) {
	withArch(t, "amd64")
	calls := stubStarter(t, expectedExit)
	home := homeWithCodemeld(t)
	Resolve(ResolveInput{Home: home})
	seen := 0
	for _, c := range *calls {
		var want []string
		switch c.leg {
		case "environment":
			want = []string{home, c.dir, ""}
		case "environment-auto":
			want = []string{home, c.dir, filepath.Join(c.dir, "tmp")}
		default:
			continue
		}
		seen++
		if c.argv[3] != "environment" || !reflect.DeepEqual(c.argv[4:], want) {
			t.Errorf("%s argv = %q, want probe environment with %q", c.leg, c.argv, want)
		}
		if c.policy.TmpDir != want[2] || slices.ContainsFunc(c.env, func(e string) bool { return strings.HasPrefix(e, "CODEMELD") }) {
			t.Errorf("%s tmp %q env %v", c.leg, c.policy.TmpDir, c.env)
		}
	}
	if seen != 2 {
		t.Errorf("environment legs run %d times, want 2", seen)
	}
	for _, leg := range []string{"environment", "environment-auto"} {
		stubStarter(t, func(mode, name string) helperExit {
			if name == leg {
				return helperExit{code: probeFailed}
			}
			return expectedExit(mode, name)
		})
		if got := Resolve(ResolveInput{Home: homeWithCodemeld(t)}); got.Capability != Refused || got.Reason != "linux: self-test leg "+leg+" observed failed" {
			t.Errorf("%s mismatch: Resolve() = %+v", leg, got)
		}
	}
}

func TestResolveDeputyAttemptsShareTheirFixture(t *testing.T) {
	withArch(t, "amd64")
	calls := stubStarter(t, expectedExit)
	Resolve(ResolveInput{Home: homeWithCodemeld(t)})
	control := map[string]helperCall{}
	for _, c := range *calls {
		if c.mode == ControlArg {
			control[c.leg] = c
			continue
		}
		ctl, ok := control[c.leg]
		if !ok {
			continue
		}
		same := ctl.dir == c.dir && reflect.DeepEqual(ctl.argv[3:], c.argv[3:])
		fresh := slices.Contains([]string{"write-outside", "truncate-read-root", "read-protected"}, c.leg)
		if fresh == same || fresh && ctl.dir == c.dir {
			t.Errorf("%s: control %s %q, confined %s %q (fresh fixtures %v)", c.leg, ctl.dir, ctl.argv, c.dir, c.argv, fresh)
		}
	}
	for _, leg := range []string{"mq-open", "shm-open"} {
		if c := control[leg]; c.argv[4] != filepath.Base(c.dir) {
			t.Errorf("%s private name %q, want the fixture's own name", leg, c.argv[4])
		}
	}
	var denied []string
	for _, l := range selfTestLegs {
		if l.expected == observedDenied && l.arch != "arm64" {
			denied = append(denied, l.name)
		}
	}
	for _, name := range denied {
		if _, ok := control[name]; !ok {
			t.Errorf("expected-denied leg %s ran no control", name)
		}
	}
}

func TestResolveControlAttribution(t *testing.T) {
	withArch(t, "amd64")
	const abiStderr = "codemeld confinement: landlock: landlock ABI 2 < 3"
	cases := []struct {
		name              string
		control, confined helperExit
		want, reason      string
	}{
		{"held by host", helperExit{code: probeDenied}, helperExit{code: probeDenied}, observedHeldByHost, ""},
		{"control failed", helperExit{code: probeFailed}, helperExit{code: probeDenied}, observedFailed, "observed failed"},
		{"control timed out", helperExit{code: -1, timedOut: true}, helperExit{code: probeDenied}, observedFailed, "observed failed"},
		{"control setup failure", helperExit{code: SetupFailureExitCode, stderr: abiStderr}, helperExit{code: probeDenied}, observedFailed, "observed failed: " + abiStderr},
		{"control failed, confined setup failure", helperExit{code: probeFailed}, helperExit{code: SetupFailureExitCode, stderr: abiStderr}, observedFailed, "observed failed: " + abiStderr},
		{"control diagnostic, confined setup failure", helperExit{code: probeFailed, stderr: "ctl diag"}, helperExit{code: SetupFailureExitCode, stderr: abiStderr}, observedFailed, "observed failed: " + abiStderr + ": ctl diag"},
		{"both setup failures", helperExit{code: SetupFailureExitCode, stderr: "ctl setup"}, helperExit{code: SetupFailureExitCode, stderr: abiStderr}, observedFailed, "observed failed: ctl setup\n" + abiStderr},
		{"denied control, allowed confined", helperExit{code: probeDenied}, helperExit{code: probeAllowed}, observedFailed, "observed failed"},
		{"denied control, failed confined", helperExit{code: probeDenied}, helperExit{code: SetupFailureExitCode, stderr: abiStderr}, observedFailed, "observed failed: " + abiStderr},
	}
	for _, leg := range []string{"write-outside", "socket-inet", "shm-open", "x32-syscall"} {
		for _, tc := range cases {
			calls := stubStarter(t, func(mode, name string) helperExit {
				switch {
				case name == leg && mode == ControlArg:
					return tc.control
				case name == leg:
					return tc.confined
				}
				return expectedExit(mode, name)
			})
			got := Resolve(ResolveInput{Home: homeWithCodemeld(t)})
			i := slices.IndexFunc(got.Legs, func(l Leg) bool { return l.Name == leg })
			if got.Legs[i].Observed != tc.want {
				t.Errorf("%s %s: leg = %+v, want %s", leg, tc.name, got.Legs[i], tc.want)
			}
			wantCap, wantReason := Refused, "linux: self-test leg "+leg+" "+tc.reason
			if tc.want == observedHeldByHost {
				wantCap, wantReason = Constrained, ""
			}
			if got.Capability != wantCap || got.Reason != wantReason {
				t.Errorf("%s %s: Resolve() = %+v, want %s %q", leg, tc.name, got, wantCap, wantReason)
			}
			var order []string
			for _, c := range *calls {
				if c.leg == leg {
					order = append(order, c.mode)
				}
			}
			if !reflect.DeepEqual(order, []string{ControlArg, ProbeArg}) {
				t.Errorf("%s %s: attempts %v, want control then probe", leg, tc.name, order)
			}
		}
	}
}

func TestResolveKeepsFailedControlDiagnostic(t *testing.T) {
	const diag = "ioctl-setflags: FS_IOC_SETFLAGS: operation not supported"
	stubStarter(t, func(mode, leg string) helperExit {
		switch {
		case leg == "ioctl-setflags" && mode == ControlArg:
			return helperExit{code: probeFailed, stderr: diag}
		case leg == "ioctl-setflags":
			return helperExit{code: probeDenied}
		}
		return expectedExit(mode, leg)
	})
	got := Resolve(ResolveInput{Home: homeWithCodemeld(t)})
	i := slices.IndexFunc(got.Legs, func(l Leg) bool { return l.Name == "ioctl-setflags" })
	if got.Capability != Refused || got.Legs[i].Observed != observedFailed || got.Legs[i].Diagnostic != diag ||
		got.Reason != "linux: self-test leg ioctl-setflags observed failed: "+diag {
		t.Errorf("Resolve() = %+v", got)
	}
}

func TestResolveI386Outcomes(t *testing.T) {
	withArch(t, "amd64")
	cases := []struct {
		name              string
		control, confined helperExit
		want              string
	}{
		{"control allowed, confined SIGSYS", helperExit{code: probeAllowed}, helperExit{code: -1, signal: syscall.SIGSYS}, observedDenied},
		{"host SIGSYS on both", helperExit{code: -1, signal: syscall.SIGSYS}, helperExit{code: -1, signal: syscall.SIGSYS}, observedHeldByHost},
		{"control SIGSEGV", helperExit{code: -1, signal: syscall.SIGSEGV}, helperExit{code: -1, signal: syscall.SIGSYS}, observedFailed},
		{"control undefined exit", helperExit{code: probeUnsupported}, helperExit{code: -1, signal: syscall.SIGSYS}, observedFailed},
		{"control failed", helperExit{code: probeFailed}, helperExit{code: -1, signal: syscall.SIGSYS}, observedFailed},
		{"confined SIGTERM", helperExit{code: probeAllowed}, helperExit{code: -1, signal: syscall.SIGTERM}, observedFailed},
		{"confined timed out", helperExit{code: probeAllowed}, helperExit{code: -1, timedOut: true}, observedFailed},
	}
	for _, tc := range cases {
		stubStarter(t, func(mode, leg string) helperExit {
			switch {
			case leg == "i386-syscall" && mode == ControlArg:
				return tc.control
			case leg == "i386-syscall":
				return tc.confined
			}
			return expectedExit(mode, leg)
		})
		got := Resolve(ResolveInput{Home: homeWithCodemeld(t)})
		i := slices.IndexFunc(got.Legs, func(l Leg) bool { return l.Name == "i386-syscall" })
		if got.Legs[i].Observed != tc.want {
			t.Errorf("%s: i386 leg = %+v, want %s", tc.name, got.Legs[i], tc.want)
		}
		if refused := tc.want == observedFailed; refused != (got.Capability == Refused) {
			t.Errorf("%s: Resolve() = %+v", tc.name, got)
		}
	}
	stubStarter(t, func(mode, leg string) helperExit {
		if leg == "socket-unix" && mode == ProbeArg {
			return helperExit{code: -1, signal: syscall.SIGSYS}
		}
		return expectedExit(mode, leg)
	})
	if got := Resolve(ResolveInput{Home: homeWithCodemeld(t)}); got.Reason != "linux: self-test leg socket-unix observed failed: killed by bad system call" {
		t.Errorf("SIGSYS outside the i386 leg: Resolve() = %+v", got)
	}
}

func TestResolveArm32FixturePreparedByParent(t *testing.T) {
	withArch(t, "arm64")
	old := writeArm32Fixture
	t.Cleanup(func() { writeArm32Fixture = old })
	var written []string
	writeArm32Fixture = func(root string) (string, error) {
		path := filepath.Join(root, "read", "arm32")
		written = append(written, path)
		return path, os.WriteFile(path, []byte("elf"), 0o700)
	}
	var seen []string
	calls := stubStarter(t, func(mode, leg string) helperExit {
		if leg == "arm32-syscall" {
			seen = append(seen, mode)
		}
		return expectedExit(mode, leg)
	})
	if got := Resolve(ResolveInput{Home: homeWithCodemeld(t)}); got.Capability != Constrained {
		t.Fatalf("Resolve() = %+v", got)
	}
	if len(written) != 1 || !reflect.DeepEqual(seen, []string{ControlArg, ProbeArg}) {
		t.Fatalf("fixture written %v, attempts %v", written, seen)
	}
	for _, c := range *calls {
		if c.leg != "arm32-syscall" {
			continue
		}
		if c.argv[4] != written[0] || c.policy.Mode != ModePlan || len(c.policy.WriteRoots) != 0 {
			t.Errorf("%s: argv %q, policy %+v", c.mode, c.argv, c.policy)
		}
	}
	if _, err := os.Stat(written[0]); err == nil {
		t.Error("arm32 fixture left behind")
	}
	for _, tc := range []struct {
		name              string
		control, confined helperExit
		want              string
	}{
		{"confined unsupported", helperExit{code: probeAllowed}, helperExit{code: probeUnsupported}, observedFailed},
		{"control timed out", helperExit{code: -1, timedOut: true}, helperExit{code: probeDenied}, observedFailed},
		{"control killed", helperExit{code: -1, signal: syscall.SIGSYS}, helperExit{code: probeDenied}, observedFailed},
		{"control exec error", helperExit{code: probeFailed}, helperExit{code: probeDenied}, observedFailed},
	} {
		stubStarter(t, func(mode, leg string) helperExit {
			switch {
			case leg == "arm32-syscall" && mode == ControlArg:
				return tc.control
			case leg == "arm32-syscall":
				return tc.confined
			}
			return expectedExit(mode, leg)
		})
		got := Resolve(ResolveInput{Home: homeWithCodemeld(t)})
		i := slices.IndexFunc(got.Legs, func(l Leg) bool { return l.Name == "arm32-syscall" })
		if got.Legs[i].Observed != tc.want || got.Capability != Refused {
			t.Errorf("%s: Resolve() = %+v", tc.name, got)
		}
	}
}

func TestStartHelperProcessReportsSignalsSeparately(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(path string, timeout time.Duration) helperExit {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return startHelperProcess(ctx, []string{path}, nil, dir, nil)
	}
	cases := []struct {
		name string
		got  helperExit
		want helperExit
	}{
		{"SIGSYS", run(script("sys", "kill -SYS $$"), 5*time.Second), helperExit{code: -1, signal: syscall.SIGSYS}},
		{"SIGTERM", run(script("term", "kill -TERM $$"), 5*time.Second), helperExit{code: -1, signal: syscall.SIGTERM}},
		{"exit", run(script("exit", "echo diag >&2; exit 10"), 5*time.Second), helperExit{code: 10, stderr: "diag"}},
		{"timeout", run(script("slow", "exec sleep 10"), 50*time.Millisecond), helperExit{code: -1, timedOut: true}},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, tc.got, tc.want)
		}
	}
}

func TestResolveHomeValidation(t *testing.T) {
	withArch(t, "amd64")
	for _, home := range []string{"", "relative/home"} {
		calls := stubStarter(t, expectedExit)
		got := Resolve(ResolveInput{Home: home})
		if got.Capability != Refused || got.Reason != "linux: invalid home: path must be absolute" || got.Legs != nil {
			t.Errorf("home %q: Resolve() = %+v", home, got)
		}
		if len(*calls) != 0 {
			t.Errorf("home %q: started %d helpers", home, len(*calls))
		}
		if entries, _ := os.ReadDir(os.TempDir()); len(entries) != 0 {
			t.Errorf("home %q: fixtures created: %v", home, entries)
		}
	}
	home := homeWithCodemeld(t)
	for _, written := range []string{home + "/", home + "/."} {
		calls := stubStarter(t, expectedExit)
		if got := Resolve(ResolveInput{Home: written}); got.Capability != Constrained {
			t.Errorf("home %q: Resolve() = %+v", written, got)
		}
		for _, c := range *calls {
			if c.policy.BlockedPaths[0] != filepath.Join(home, ".codemeld") || !slices.Contains(c.env, "HOME="+home) {
				t.Errorf("home %q: blocked %v, env %v", written, c.policy.BlockedPaths, c.env)
			}
		}
	}
}

func TestResolveRemovesFixtures(t *testing.T) {
	calls := stubStarter(t, expectedExit)
	Resolve(ResolveInput{Home: homeWithCodemeld(t)})
	for _, c := range *calls {
		if !strings.HasPrefix(c.dir, os.TempDir()) {
			t.Errorf("fixture %s outside %s", c.dir, os.TempDir())
		}
	}
	if entries, err := os.ReadDir(os.TempDir()); err != nil || len(entries) != 0 {
		t.Errorf("fixtures left behind: %v, %v", entries, err)
	}
}

func TestSetflagsProbeReportsTheFilesystemError(t *testing.T) {
	stderr := captureStderr(t)
	code := runProbe(&helperState{}, []string{"ioctl-setflags", "/dev/null"})
	out := stderr()
	if code != probeFailed || !strings.Contains(out, "FS_IOC_SETFLAGS") || !strings.Contains(out, unix.ENOTTY.Error()) {
		t.Errorf("exit %d, stderr %q", code, out)
	}
}

func TestResolveThroughRealHelper(t *testing.T) {
	if abi, err := landlockABI(); err != nil || abi < 3 {
		t.Skipf("landlock ABI 3 unavailable (abi %d, err %v)", abi, err)
	}
	if !seccomp.Supported() {
		t.Skip("seccomp unavailable")
	}
	if _, err := os.Stat("/proc/sys/fs/mqueue"); err != nil {
		t.Skipf("POSIX message queues unavailable: %v", err)
	}
	if info, err := os.Stat("/dev/shm"); err != nil || !info.IsDir() {
		t.Skipf("/dev/shm unavailable: %v", err)
	}
	probe, err := os.CreateTemp("", "codemeld-ioctl-preflight-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(probe.Name()) })
	flags, err := unix.IoctlGetUint32(int(probe.Fd()), unix.FS_IOC_GETFLAGS)
	if err == nil {
		err = unix.IoctlSetPointerInt(int(probe.Fd()), unix.FS_IOC_SETFLAGS, int(flags^fsNodumpFl))
	}
	if err == nil {
		err = unix.IoctlSetPointerInt(int(probe.Fd()), unix.FS_IOC_SETFLAGS, int(flags))
	}
	_ = probe.Close()
	if err != nil {
		t.Skipf("FS_IOC_SETFLAGS unsupported under %s: %v", os.TempDir(), err)
	}
	bin := filepath.Join(t.TempDir(), "codemeld")
	build := exec.Command("go", "build", "-o", bin, "codemeld.dev/codemeld/cmd/codemeld")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cgo-free codemeld: %v\n%s", err, out)
	}
	if goarch == "amd64" {
		if gap := hostIA32EmulationGap(); gap != "" {
			t.Skipf("ia32 emulation unavailable: %s", gap)
		}
		var frame bytes.Buffer
		if err := WritePolicyFrame(&frame, Policy{Mode: ModePlan, BlockedPaths: []string{"/nonexistent/.codemeld"}}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		control := startHelperProcess(ctx, []string{bin, HelperCommand, ControlArg, "i386-syscall"}, nil, t.TempDir(), frame.Bytes())
		cancel()
		if !i386ControlUsable(control) {
			t.Fatalf("i386 control: %+v", control)
		}
	}
	// The helper's read walk lists every directory above the blocked home; /var/tmp churns far less
	// than the shared test temp directory, whose vanishing entries would fail Landlock setup.
	base, err := os.MkdirTemp("/var/tmp", "codemeld-selftest-home-")
	if err != nil {
		base = t.TempDir()
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(base) })
	}
	if err := os.MkdirAll(filepath.Join(base, ".codemeld", "global"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, ".codemeld", "global", "settings.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := Resolve(ResolveInput{Home: base, HelperExecutable: bin})
	if got.Capability != Constrained || got.Reason != "" || !got.SelfTestPassed {
		t.Errorf("Resolve() = %+v, want Constrained", got)
	}
	if helperExecutable != "/proc/self/exe" {
		t.Errorf("helperExecutable = %q after an explicit-path resolve", helperExecutable)
	}
	for i, l := range selfTestLegs {
		if !realHelperLegMatches(l, got.Legs[i]) {
			t.Errorf("leg %s observed %+v through the real helper, want %s", l.name, got.Legs[i], l.expected)
		}
	}
}

func i386ControlUsable(e helperExit) bool {
	return !e.timedOut && e.signal == 0 && (e.code == probeAllowed || e.code == probeDenied)
}

func realHelperLegMatches(l selfTestLeg, got Leg) bool {
	want := l.expected
	if l.arch != "" && l.arch != goarch {
		want = observedNotRun
	}
	switch {
	case got.Observed == want, got.Observed == observedHeldByHost && want == observedDenied:
		return true
	case l.name == "arm32-syscall" && got.Observed == observedNotRun:
		return strings.Contains(got.Diagnostic, "unsupported")
	}
	return false
}

func TestI386ControlPreflight(t *testing.T) {
	for _, tc := range []struct {
		e    helperExit
		want bool
	}{
		{helperExit{code: probeAllowed}, true},
		{helperExit{code: probeDenied}, true},
		{helperExit{code: SetupFailureExitCode, stderr: "setup"}, false},
		{helperExit{code: probeFailed}, false},
		{helperExit{code: -1, signal: syscall.SIGTERM}, false},
		{helperExit{code: -1, timedOut: true}, false},
	} {
		if got := i386ControlUsable(tc.e); got != tc.want {
			t.Errorf("%+v: usable %v, want %v", tc.e, got, tc.want)
		}
	}
}

func TestRealHelperLegExpectations(t *testing.T) {
	withArch(t, "arm64")
	leg := func(name string) selfTestLeg {
		return selfTestLegs[slices.IndexFunc(selfTestLegs, func(l selfTestLeg) bool { return l.name == name })]
	}
	stubStarter(t, func(mode, name string) helperExit {
		if name == "arm32-syscall" && mode == ControlArg {
			return helperExit{code: probeUnsupported}
		}
		return expectedExit(mode, name)
	})
	r := runSelfTestLeg(homeWithCodemeld(t), helperExecutable, leg("arm32-syscall"))
	unsupported := Leg{Name: r.Name, Observed: r.Observed, Diagnostic: r.Diagnostic}
	if r.Required || r.Expected != observedNotRun || r.Diagnostic == "" {
		t.Errorf("arm32 without compat: %+v", r)
	}
	for _, tc := range []struct {
		leg  string
		got  Leg
		want bool
	}{
		{"arm32-syscall", Leg{Observed: observedDenied}, true},
		{"arm32-syscall", Leg{Observed: observedHeldByHost}, true},
		{"arm32-syscall", unsupported, true},
		{"arm32-syscall", Leg{Observed: observedNotRun}, false},
		{"arm32-syscall", Leg{Observed: observedFailed}, false},
		{"socket-unix", Leg{Observed: observedNotRun, Diagnostic: "unsupported"}, false},
		{"x32-syscall", Leg{Observed: observedNotRun}, true},
	} {
		if got := realHelperLegMatches(leg(tc.leg), tc.got); got != tc.want {
			t.Errorf("%s %+v: matches %v, want %v", tc.leg, tc.got, got, tc.want)
		}
	}
}
