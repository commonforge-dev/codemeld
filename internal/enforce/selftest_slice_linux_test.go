package enforce

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	probes["s-exit"] = probe{1, func(a []string) int {
		code, err := strconv.Atoi(a[0])
		if err != nil {
			return probeFailed
		}
		return code
	}}
	probes["s-kill"] = probe{0, func([]string) int {
		_ = unix.Kill(unix.Getpid(), unix.SIGKILL)
		time.Sleep(time.Minute)
		return probeFailed
	}}
	probes["s-socket-errno"] = probe{1, func(a []string) int {
		n, err := strconv.Atoi(a[0])
		if err != nil {
			return probeFailed
		}
		return targetFdProbe(-1, unix.Errno(n))
	}}
	probes["s-hang"] = probe{0, func([]string) int { time.Sleep(time.Minute); return probeFailed }}
	probes["s-identity"] = probe{1, func(a []string) int {
		runtime.LockOSThread()
		if unix.Gettid() != unix.Getpid() {
			fmt.Println("identity unverified")
			return probeUnsupported
		}
		worker := make(chan int)
		go func() {
			runtime.LockOSThread()
			worker <- connectAs(tcpSocket, true, []string{a[0], "x"})
		}()
		fmt.Printf("identity main-as-worker=%d worker-as-main=%d\n", connectAs(tcpSocket, false, []string{a[0], "x"}), <-worker)
		return probeAllowed
	}}
}

func sliceHome(t *testing.T) (home, bin string) {
	t.Helper()
	mxRequire(t)
	bin = mxBinary(t)
	return mxSetup(t).home, bin
}

func sliceUnverified(t *testing.T, reason string) {
	t.Helper()
	for _, e := range []unix.Errno{unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP} {
		if strings.Contains(reason, "install seccomp listener filter: "+e.Error()) {
			t.Skipf("unverified: the kernel refused the seccomp listener filter: %s", reason)
		}
	}
}

func childPIDs(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		t.Fatal(err)
	}
	var pids []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		pids = append(pids, strings.Fields(string(data))...)
	}
	return pids
}

func withoutLeaks(t *testing.T, run func()) {
	t.Helper()
	warm, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = warm.Close()
	fds, goroutines, children := fdCount(t), runtime.NumGoroutine(), childPIDs(t)
	defer func() {
		if after := fdCount(t); after != fds {
			t.Errorf("descriptors %d after the check, %d before", after, fds)
		}
		for _, pid := range childPIDs(t) {
			if !slices.Contains(children, pid) {
				t.Errorf("helper process %s left running", pid)
			}
		}
		for deadline := time.Now().Add(2 * time.Second); runtime.NumGoroutine() > goroutines; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Errorf("goroutines %d after the check, %d before", runtime.NumGoroutine(), goroutines)
				break
			}
		}
	}()
	run()
}

func setVar[T any](t *testing.T, v *T, value T) {
	t.Helper()
	old := *v
	*v = value
	t.Cleanup(func() { *v = old })
}

func TestSliceSelfTestPassesInRealHelper(t *testing.T) {
	home, bin := sliceHome(t)
	withoutLeaks(t, func() {
		passed, reason := runSliceSelfTest(home, bin)
		sliceUnverified(t, reason)
		if !passed || reason != "" {
			t.Fatalf("slice check = %v, %q", passed, reason)
		}
	})
	var got []string
	for _, s := range sliceSteps {
		got = append(got, fmt.Sprintf("%s=%d", s.probe, s.want))
	}
	want := []string{"tcp-connect-main=0", "tcp-connect-thread=0", "tcp-bind=10", "tcp-listen=10", "socket-unix=10", "tcp-fastopen=10"}
	if !slices.Equal(got, want) {
		t.Errorf("steps %v, want %v", got, want)
	}
	for _, s := range sliceSteps[:2] {
		if !s.payload {
			t.Errorf("%s passes without an accepted payload", s.probe)
		}
	}
}

func TestSliceSelfTestPolicyFrame(t *testing.T) {
	home := mxSetup(t).home
	dir := t.TempDir()
	out := filepath.Join(dir, "frame")
	script := filepath.Join(dir, "helper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat > "+out+"\nls /proc/self/fd >> "+out+".fds\necho \"$@\" > "+out+".args\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	passed, reason := runSliceSelfTest(home, script)
	if passed || !strings.HasPrefix(reason, "slice self-test: tcp-connect-main: listener handoff: ") {
		t.Fatalf("slice check = %v, %q", passed, reason)
	}
	raw, err := os.ReadFile(out)
	if err != nil || len(raw) < 4 {
		t.Fatalf("frame %q: %v", raw, err)
	}
	var p Policy
	if err := json.Unmarshal(raw[4:4+binary.BigEndian.Uint32(raw)], &p); err != nil {
		t.Fatal(err)
	}
	if p.Mode != "auto_edits" || p.Broker != "slice" || p.ExceptionalAuthority != "" || p.TmpDir == "" {
		t.Errorf("policy %+v: want auto_edits, slice broker, no exceptional authority, a tmp dir", p)
	}
	if !slices.Equal(p.BlockedPaths, []string{filepath.Join(home, ".codemeld")}) {
		t.Errorf("blocked paths %v", p.BlockedPaths)
	}
	if fds, _ := os.ReadFile(out + ".fds"); !strings.Contains(string(fds), "\n3\n") {
		t.Errorf("helper descriptors %q: want the setup channel at 3", fds)
	}
	args, _ := os.ReadFile(out + ".args")
	if f := strings.Fields(string(args)); len(f) != 5 || f[0] != "__codemeld_confine" || f[1] != "--probe" || f[2] != "tcp-connect-main" {
		t.Errorf("helper arguments %q", args)
	}
}

func TestSliceSelfTestThreadIdentityChecks(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	helper := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{HelperCommand, ControlArg}, args...)...)
		cmd.Stdin = strings.NewReader(string(encodedFrame(t, Policy{Mode: ModePlan, BlockedPaths: []string{"/nonexistent"}})))
		cmd.WaitDelay = time.Second
		return cmd.CombinedOutput()
	}
	out, err := helper("s-identity", ln.Addr().String())
	if strings.Contains(string(out), "identity unverified") {
		t.Skip("unverified: the helper's main goroutine was not on the leader thread")
	}
	if err != nil || !strings.Contains(string(out), "identity main-as-worker=11 worker-as-main=11\n") {
		t.Fatalf("identity probe: %v\n%s", err, out)
	}
	for _, p := range []string{"tcp-connect-main", "tcp-connect-thread"} {
		if err := ln.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		accepted := make(chan string, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				accepted <- err.Error()
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			b, _ := io.ReadAll(c)
			_ = c.Close()
			accepted <- string(b)
		}()
		out, err := helper(p, ln.Addr().String(), "payload-"+p)
		if err != nil {
			_ = ln.SetDeadline(time.Now())
			<-accepted
			t.Fatalf("%s unconfined: %v\n%s", p, err, out)
		}
		if got := <-accepted; got != "payload-"+p {
			t.Errorf("%s: accepted %q", p, got)
		}
	}
}

func TestSliceSelfTestFailuresAreUnavailable(t *testing.T) {
	home, bin := sliceHome(t)
	closedPort := func() netip.AddrPort {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ap := netip.MustParseAddrPort(l.Addr().String())
		_ = l.Close()
		return ap
	}()
	connects := slices.Clone(sliceSteps[:2])
	exitStep := func(code string) sliceStep {
		return sliceStep{probe: "s-exit", want: probeDenied, args: func(stepTargets, string) []string { return []string{code} }}
	}
	injected := errors.New("injected")
	unrecordedBroker := func(t *testing.T) {
		setVar(t, &sliceStartBroker, func(l *os.File, _ ConnectDecider) (*Broker, error) {
			return StartBroker(l, func(d netip.AddrPort) bool { return d.Addr().IsLoopback() })
		})
	}
	directPayload := func(to stepTargets, token string) []string {
		if c, err := net.Dial("tcp4", to.tcp.String()); err == nil {
			_, _ = c.Write([]byte(token))
			_ = c.Close()
		}
		return []string{"0"}
	}
	setVar(t, &selfTestTimeout, 2*time.Second)
	for _, c := range []struct {
		name   string
		exe    string
		steps  []sliceStep
		setup  func(t *testing.T)
		reason string
	}{
		{name: "helper never hands off", exe: "/bin/true", reason: "tcp-connect-main: listener handoff: "},
		{name: "receive", setup: func(t *testing.T) {
			setVar(t, &sliceReceive, func(ch *os.File, d time.Duration) (*os.File, error) {
				l, err := ReceiveListener(ch, d)
				if err == nil {
					_ = l.Close()
				}
				return nil, injected
			})
		}, reason: "tcp-connect-main: listener handoff: injected"},
		{name: "broker start", setup: func(t *testing.T) {
			setVar(t, &sliceStartBroker, func(l *os.File, _ ConnectDecider) (*Broker, error) { _ = l.Close(); return nil, injected })
		}, reason: "tcp-connect-main: broker start: injected"},
		{name: "release", setup: func(t *testing.T) {
			setVar(t, &sliceRelease, func(*os.File) error { return injected })
		}, reason: "tcp-connect-main: release: injected"},
		{name: "connect refused by the decider", steps: []sliceStep{{probe: "tcp-connect-main", want: probeAllowed, payload: true, args: func(_ stepTargets, token string) []string {
			return []string{closedPort.String(), token}
		}}}, reason: "tcp-connect-main: helper exit 10, want 0"},
		{name: "nothing accepted", steps: []sliceStep{{probe: "s-exit", want: probeAllowed, payload: true, args: func(stepTargets, string) []string { return []string{"0"} }}},
			reason: "s-exit: no accepted connection carried the helper's payload"},
		{name: "wrong payload", steps: []sliceStep{{probe: "tcp-connect-thread", want: probeAllowed, payload: true, args: func(to stepTargets, token string) []string {
			return []string{to.tcp.String(), "other-" + token}
		}}}, reason: "tcp-connect-thread: no accepted connection carried the helper's payload"},
		{name: "unexpected peer", steps: []sliceStep{{probe: "s-exit", want: probeAllowed, payload: true, args: func(to stepTargets, _ string) []string {
			if c, err := net.Dial("tcp4", to.tcp.String()); err == nil {
				_, _ = c.Write([]byte("intruder"))
				_ = c.Close()
			}
			return []string{"0"}
		}}}, reason: "s-exit: no accepted connection carried the helper's payload"},
		{name: "main-thread connect admitted without this attempt's broker", steps: connects[:1], setup: unrecordedBroker,
			reason: "tcp-connect-main: the broker never handled a connect to the expected endpoint"},
		{name: "worker-thread connect admitted without this attempt's broker", steps: connects[1:], setup: unrecordedBroker,
			reason: "tcp-connect-thread: the broker never handled a connect to the expected endpoint"},
		{name: "direct connect with the payload", steps: []sliceStep{{probe: "s-exit", want: probeAllowed, payload: true, args: directPayload}},
			reason: "s-exit: the broker never handled a connect to the expected endpoint"},
		{name: "denial EACCES from the socket call", steps: append(slices.Clone(connects), sliceStep{probe: "s-socket-errno", want: probeDenied, args: func(stepTargets, string) []string {
			return []string{strconv.Itoa(int(unix.EACCES))}
		}}), reason: "s-socket-errno: helper exit 11, want 10"},
		{name: "denial allowed", steps: append(slices.Clone(connects), exitStep("0")), reason: "s-exit: helper exit 0, want 10"},
		{name: "denial failed", steps: append(slices.Clone(connects), exitStep("11")), reason: "s-exit: helper exit 11, want 10"},
		{name: "denial unsupported", steps: append(slices.Clone(connects), exitStep("12")), reason: "s-exit: helper exit 12, want 10"},
		{name: "denial setup failure", steps: append(slices.Clone(connects), exitStep("125")), reason: "s-exit: helper exit 125, want 10"},
		{name: "denial signal", steps: append(slices.Clone(connects), sliceStep{probe: "s-kill", want: probeDenied}), reason: "s-kill: helper killed by signal 9"},
		{name: "denial timeout", steps: []sliceStep{{probe: "s-hang", want: probeDenied}}, reason: "s-hang: helper timed out"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.steps != nil {
				setVar(t, &sliceSteps, c.steps)
			}
			if c.setup != nil {
				c.setup(t)
			}
			exe := bin
			if c.exe != "" {
				exe = c.exe
			}
			withoutLeaks(t, func() {
				passed, reason := runSliceSelfTest(home, exe)
				sliceUnverified(t, reason)
				if passed || !strings.HasPrefix(reason, "slice self-test: "+c.reason) {
					t.Errorf("slice check = %v, %q; want unavailable with %q", passed, reason, c.reason)
				}
			})
		})
	}
}

func TestSliceSelfTestConcurrentChecksStayIsolated(t *testing.T) {
	home, bin := sliceHome(t)
	exes := []string{bin, bin, "/nonexistent/codemeld-helper", bin}
	type result struct {
		passed bool
		reason string
	}
	results := make([]result, len(exes))
	withoutLeaks(t, func() {
		var wg sync.WaitGroup
		for i, exe := range exes {
			wg.Go(func() {
				passed, reason := runSliceSelfTest(home, exe)
				results[i] = result{passed, reason}
			})
		}
		wg.Wait()
	})
	for i, r := range results {
		sliceUnverified(t, r.reason)
		wantPass := exes[i] == bin
		if r.passed != wantPass || (wantPass && r.reason != "") || (!wantPass && !strings.HasPrefix(r.reason, "slice self-test: tcp-connect-main: start helper: ")) {
			t.Errorf("check %d (%s) = %v, %q", i, exes[i], r.passed, r.reason)
		}
	}
}

func TestConnectSelfTestPassesInRealHelper(t *testing.T) {
	home, bin := sliceHome(t)
	withoutLeaks(t, func() {
		passed, reason := connectSelfTest(home, bin)
		sliceUnverified(t, reason)
		if !passed || reason != "" {
			t.Fatalf("connect check = %v, %q", passed, reason)
		}
	})
	var got []string
	for _, s := range connectSteps {
		var args []string
		if s.args != nil {
			args = s.args(stepTargets{tcp: netip.MustParseAddrPort("127.0.0.1:9"), granted: "/g", ungranted: "/u"}, "tok")
		}
		got = append(got, fmt.Sprintf("%s=%d %v payload=%v", s.probe, s.want, args, s.payload))
	}
	want := []string{
		"tcp-connect-main=0 [127.0.0.1:9 tok] payload=true",
		"tcp-connect-thread=0 [127.0.0.1:9 tok] payload=true",
		"tcp-bind=10 [127.0.0.1:0] payload=false",
		"tcp-listen=10 [] payload=false",
		"socket-unix=0 [] payload=false",
		"tcp-fastopen=10 [127.0.0.1:9] payload=false",
		"unix-connect-main=0 [/g tok] payload=true",
		"unix-connect-thread=0 [/g tok] payload=true",
		"unix-connect-main=10 [@codemeld-connect-self-test tok] payload=false",
		"unix-connect-thread=10 [@codemeld-connect-self-test tok] payload=false",
		"unix-connect-main=10 [/u tok] payload=false",
		"unix-connect-thread=10 [/u tok] payload=false",
	}
	if !slices.Equal(got, want) {
		t.Errorf("steps\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestConnectSelfTestFailuresAreUnavailable(t *testing.T) {
	home, bin := sliceHome(t)
	setVar(t, &selfTestTimeout, 2*time.Second)
	for _, c := range []struct {
		name   string
		steps  []sliceStep
		reason string
	}{
		{name: "unix socket expected denied", steps: []sliceStep{{probe: "socket-unix", want: probeDenied}},
			reason: "socket-unix: helper exit 0, want 10"},
		{name: "ungranted unix connect expected allowed", steps: []sliceStep{{probe: "unix-connect-main", want: probeAllowed, payload: true, unix: true, args: ungrantedAndToken}},
			reason: "unix-connect-main: helper exit 10, want 0"},
		{name: "abstract unix connect expected allowed", steps: []sliceStep{{probe: "unix-connect-thread", want: probeAllowed, payload: true, unix: true, args: abstractAndToken}},
			reason: "unix-connect-thread: helper exit 10, want 0"},
		{name: "wrong unix payload", steps: []sliceStep{{probe: "unix-connect-main", want: probeAllowed, payload: true, unix: true, args: func(to stepTargets, token string) []string {
			return []string{to.granted, "other-" + token}
		}}}, reason: "unix-connect-main: no accepted connection carried the helper's payload"},
		{name: "nothing accepted on the unix listener", steps: []sliceStep{{probe: "s-exit", want: probeAllowed, payload: true, unix: true, args: func(stepTargets, string) []string { return []string{"0"} }}},
			reason: "s-exit: no accepted connection carried the helper's payload"},
	} {
		t.Run(c.name, func(t *testing.T) {
			setVar(t, &connectSteps, c.steps)
			withoutLeaks(t, func() {
				passed, reason := runConnectSelfTest(home, bin)
				sliceUnverified(t, reason)
				if passed || !strings.HasPrefix(reason, "connect self-test: "+c.reason) {
					t.Errorf("connect check = %v, %q; want unavailable with %q", passed, reason, c.reason)
				}
			})
		})
	}
}

func TestFullSelfTestPassesInRealHelper(t *testing.T) {
	home, bin := sliceHome(t)
	withoutLeaks(t, func() {
		passed, reason := fullSelfTest(home, bin)
		sliceUnverified(t, reason)
		if !passed || reason != "" {
			t.Fatalf("full check = %v, %q", passed, reason)
		}
	})
	var got []string
	for _, s := range fullSteps {
		var args []string
		if s.args != nil {
			args = s.args(stepTargets{tcp: netip.MustParseAddrPort("127.0.0.1:9"), granted: "/g", ungranted: "/u", tmp: "/w/tmp", root: "/w"}, "tok")
		}
		got = append(got, fmt.Sprintf("%s=%d %v payload=%v", s.probe, s.want, args, s.payload))
	}
	want := []string{
		"tcp-connect-main=0 [127.0.0.1:9 tok] payload=true",
		"tcp-connect-thread=0 [127.0.0.1:9 tok] payload=true",
		"socket-unix=0 [] payload=false",
		"tcp-fastopen=10 [127.0.0.1:9] payload=false",
		"unix-connect-main=0 [/g tok] payload=true",
		"unix-connect-thread=0 [/g tok] payload=true",
		"unix-connect-main=10 [@codemeld-connect-self-test tok] payload=false",
		"unix-connect-thread=10 [@codemeld-connect-self-test tok] payload=false",
		"unix-connect-main=10 [/u tok] payload=false",
		"unix-connect-thread=10 [/u tok] payload=false",
		"tcp-bind-listen-connect-main=0 [] payload=false",
		"tcp-bind-listen-connect-thread=0 [] payload=false",
		"unix-bind-main=0 [/w/tmp/s] payload=false",
		"unix-bind-thread=0 [/w/tmp/s] payload=false",
		"unix-bind-main=10 [/w/s] payload=false",
		"setsockopt-reuseport=10 [] payload=false",
		"setsockopt-reuseaddr=0 [] payload=false",
	}
	if !slices.Equal(got, want) {
		t.Errorf("steps\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFullSelfTestFailuresAreUnavailable(t *testing.T) {
	home, bin := sliceHome(t)
	setVar(t, &selfTestTimeout, 2*time.Second)
	for _, c := range []struct {
		name   string
		steps  []sliceStep
		reason string
	}{
		{name: "bind and listen expected denied", steps: []sliceStep{{probe: "tcp-bind-listen-connect-thread", want: probeDenied}},
			reason: "tcp-bind-listen-connect-thread: helper exit 0, want 10"},
		{name: "unix bind outside the write root expected allowed", steps: []sliceStep{{probe: "unix-bind-main", want: probeAllowed, args: socketInRoot}},
			reason: "unix-bind-main: helper exit 10, want 0"},
		{name: "unix bind inside the write root expected denied", steps: []sliceStep{{probe: "unix-bind-thread", want: probeDenied, args: socketInTmp}},
			reason: "unix-bind-thread: helper exit 0, want 10"},
		{name: "SO_REUSEPORT expected allowed", steps: []sliceStep{{probe: "setsockopt-reuseport", want: probeAllowed}},
			reason: "setsockopt-reuseport: helper exit 10, want 0"},
		{name: "SO_REUSEADDR expected denied", steps: []sliceStep{{probe: "setsockopt-reuseaddr", want: probeDenied}},
			reason: "setsockopt-reuseaddr: helper exit 0, want 10"},
	} {
		t.Run(c.name, func(t *testing.T) {
			setVar(t, &fullSteps, c.steps)
			withoutLeaks(t, func() {
				passed, reason := runFullSelfTest(home, bin)
				sliceUnverified(t, reason)
				if passed || !strings.HasPrefix(reason, "full self-test: "+c.reason) {
					t.Errorf("full check = %v, %q; want unavailable with %q", passed, reason, c.reason)
				}
			})
		})
	}
}
