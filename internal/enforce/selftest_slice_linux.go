package enforce

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"codemeld.dev/codemeld/internal/runner"
	"golang.org/x/sys/unix"
)

type stepTargets struct {
	tcp                netip.AddrPort
	granted, ungranted string
	tmp, root          string
}

type sliceStep struct {
	probe   string
	want    int
	payload bool
	unix    bool
	args    func(to stepTargets, token string) []string
}

func endpointAndToken(to stepTargets, token string) []string {
	return []string{to.tcp.String(), token}
}

func grantedAndToken(to stepTargets, token string) []string {
	return []string{to.granted, token}
}

func ungrantedAndToken(to stepTargets, token string) []string {
	return []string{to.ungranted, token}
}

func abstractAndToken(_ stepTargets, token string) []string {
	return []string{"@codemeld-connect-self-test", token}
}

func endpoint(to stepTargets, _ string) []string {
	return []string{to.tcp.String()}
}

func loopbackAnyPort(stepTargets, string) []string {
	return []string{"127.0.0.1:0"}
}

func socketInTmp(to stepTargets, _ string) []string {
	return []string{filepath.Join(to.tmp, "s")}
}

func socketInRoot(to stepTargets, _ string) []string {
	return []string{filepath.Join(to.root, "s")}
}

var sliceSteps = []sliceStep{
	{probe: "tcp-connect-main", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "tcp-connect-thread", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "tcp-bind", want: probeDenied, args: loopbackAnyPort},
	{probe: "tcp-listen", want: probeDenied},
	{probe: "socket-unix", want: probeDenied},
	{probe: "tcp-fastopen", want: probeDenied, args: endpoint},
}

var connectSteps = []sliceStep{
	{probe: "tcp-connect-main", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "tcp-connect-thread", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "tcp-bind", want: probeDenied, args: loopbackAnyPort},
	{probe: "tcp-listen", want: probeDenied},
	{probe: "socket-unix", want: probeAllowed},
	{probe: "tcp-fastopen", want: probeDenied, args: endpoint},
	{probe: "unix-connect-main", want: probeAllowed, payload: true, unix: true, args: grantedAndToken},
	{probe: "unix-connect-thread", want: probeAllowed, payload: true, unix: true, args: grantedAndToken},
	{probe: "unix-connect-main", want: probeDenied, args: abstractAndToken},
	{probe: "unix-connect-thread", want: probeDenied, args: abstractAndToken},
	{probe: "unix-connect-main", want: probeDenied, args: ungrantedAndToken},
	{probe: "unix-connect-thread", want: probeDenied, args: ungrantedAndToken},
}

var fullSteps = []sliceStep{
	{probe: "tcp-connect-main", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "tcp-connect-thread", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "socket-unix", want: probeAllowed},
	{probe: "tcp-fastopen", want: probeDenied, args: endpoint},
	{probe: "unix-connect-main", want: probeAllowed, payload: true, unix: true, args: grantedAndToken},
	{probe: "unix-connect-thread", want: probeAllowed, payload: true, unix: true, args: grantedAndToken},
	{probe: "unix-connect-main", want: probeDenied, args: abstractAndToken},
	{probe: "unix-connect-thread", want: probeDenied, args: abstractAndToken},
	{probe: "unix-connect-main", want: probeDenied, args: ungrantedAndToken},
	{probe: "unix-connect-thread", want: probeDenied, args: ungrantedAndToken},
	{probe: "tcp-bind-listen-connect-main", want: probeAllowed},
	{probe: "tcp-bind-listen-connect-thread", want: probeAllowed},
	{probe: "unix-bind-main", want: probeAllowed, args: socketInTmp},
	{probe: "unix-bind-thread", want: probeAllowed, args: socketInTmp},
	{probe: "unix-bind-main", want: probeDenied, args: socketInRoot},
	{probe: "setsockopt-reuseport", want: probeDenied},
	{probe: "setsockopt-reuseaddr", want: probeAllowed},
}

var (
	sliceReceive     = ReceiveListener
	sliceStartBroker = StartBroker
	sliceRelease     = ReleaseHelper
)

func init() { connectSelfTest, fullSelfTest = runConnectSelfTest, runFullSelfTest }

func runSliceSelfTest(home, exe string) (passed bool, reason string) {
	return runBrokerSelfTest(home, exe, BrokerSlice, sliceSteps)
}

func runConnectSelfTest(home, exe string) (passed bool, reason string) {
	return runBrokerSelfTest(home, exe, BrokerConnect, connectSteps)
}

func runFullSelfTest(home, exe string) (passed bool, reason string) {
	return runBrokerSelfTest(home, exe, BrokerFull, fullSteps)
}

type brokerSelfTest struct {
	home, exe, broker string
	tcp               *net.TCPListener
	unix              *net.UnixListener
	to                stepTargets
}

func runBrokerSelfTest(home, exe, broker string, steps []sliceStep) (passed bool, reason string) {
	prefix := broker + " self-test: "
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return false, prefix + "loopback listener: " + err.Error()
	}
	defer func() { _ = ln.Close() }()
	dest, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		return false, prefix + "loopback listener: " + err.Error()
	}
	s := brokerSelfTest{home: home, exe: exe, broker: broker, tcp: ln, to: stepTargets{tcp: dest}}
	if broker != BrokerSlice {
		dir, err := os.MkdirTemp("", "codemeld-connect-")
		if err != nil {
			return false, prefix + "socket folder: " + err.Error()
		}
		defer func() { _ = os.RemoveAll(dir) }()
		s.to.granted, s.to.ungranted = filepath.Join(dir, "granted"), filepath.Join(dir, "ungranted")
		if s.unix, err = net.ListenUnix("unix", &net.UnixAddr{Name: s.to.granted, Net: "unix"}); err != nil {
			return false, prefix + "unix listener: " + err.Error()
		}
		defer func() { _ = s.unix.Close() }()
		other, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.to.ungranted, Net: "unix"})
		if err != nil {
			return false, prefix + "unix listener: " + err.Error()
		}
		defer func() { _ = other.Close() }()
	}
	for _, step := range steps {
		if reason := s.attempt(step); reason != "" {
			return false, prefix + step.probe + ": " + reason
		}
	}
	return true, ""
}

func (s brokerSelfTest) attempt(step sliceStep) string {
	f, err := newFixture(s.home, selfTestLeg{})
	if err != nil {
		return "fixture: " + err.Error()
	}
	defer f.remove()
	var frame bytes.Buffer
	policy := Policy{Mode: ModeAutoEdits, Broker: s.broker, BlockedPaths: []string{filepath.Join(s.home, ".codemeld")}, TmpDir: f.tmp()}
	if err := WritePolicyFrame(&frame, policy); err != nil {
		return "policy frame: " + err.Error()
	}
	env, err := runner.FixedEnvironment(s.home, f.root, f.tmp(), runner.FixedPATH, nil)
	if err != nil {
		return "environment: " + err.Error()
	}
	token := rand.Text()
	argv := []string{HelperCommand, ProbeArg, step.probe}
	if step.args != nil {
		to := s.to
		to.tmp, to.root = f.tmp(), f.root
		argv = append(argv, step.args(to, token)...)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "setup channel: " + err.Error()
	}
	parent, child := os.NewFile(uintptr(fds[0]), "setup channel"), os.NewFile(uintptr(fds[1]), "helper setup channel")
	defer func() { _ = parent.Close() }()
	var stderr bytes.Buffer
	cmd := exec.Command(s.exe, argv...)
	cmd.Env, cmd.Dir, cmd.Stdin, cmd.Stderr = env, f.root, &frame, &stderr
	cmd.ExtraFiles = []*os.File{child}
	cmd.WaitDelay = time.Second
	err = cmd.Start()
	_ = child.Close()
	if err != nil {
		return "start helper: " + err.Error()
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	fail := func(stage string, err error) string {
		_ = parent.Close()
		_ = cmd.Process.Kill()
		<-exited
		return withStderr(stage+": "+err.Error(), &stderr)
	}
	listener, err := sliceReceive(parent, selfTestTimeout)
	if err != nil {
		return fail("listener handoff", err)
	}
	var brokered atomic.Bool
	decide := func(d netip.AddrPort) bool {
		if d != s.to.tcp {
			return false
		}
		brokered.Store(true)
		return true
	}
	var broker *Broker
	if s.broker != BrokerSlice {
		deny := NewDenyList()
		defer deny.Close()
		broker, err = StartConnectBroker(listener, ConnectRules{Grants: []string{s.to.granted}, Deny: deny, Proxy: decide, TmpDir: f.tmp(), Policy: policy}, nil)
	} else {
		broker, err = sliceStartBroker(listener, decide)
	}
	if err != nil {
		return fail("broker start", err)
	}
	defer broker.Stop()
	if err := sliceRelease(parent); err != nil {
		return fail("release", err)
	}
	_ = parent.Close()
	deadline := time.Now().Add(selfTestTimeout)
	paired := make(chan bool, 1)
	var ln deadlineListener = s.tcp
	if step.unix {
		ln = s.unix
	}
	if step.payload {
		_ = ln.SetDeadline(deadline)
		go func() { paired <- acceptToken(ln, token, deadline) }()
	} else {
		paired <- false
	}
	var e helperExit
	select {
	case err := <-exited:
		e = exitOf(err)
	case <-time.After(time.Until(deadline)):
		_ = cmd.Process.Kill()
		<-exited
		e = helperExit{code: -1, timedOut: true}
	}
	if step.payload && (e.timedOut || e.code != probeAllowed) {
		_ = ln.SetDeadline(time.Now())
	}
	if reason := sliceOutcome(step, e, <-paired, brokered.Load()); reason != "" {
		return withStderr(reason, &stderr)
	}
	return ""
}

type deadlineListener interface {
	net.Listener
	SetDeadline(time.Time) error
}

func acceptToken(ln deadlineListener, token string, deadline time.Time) bool {
	for {
		c, err := ln.Accept()
		if err != nil {
			return false
		}
		_ = c.SetReadDeadline(deadline)
		got, _ := io.ReadAll(io.LimitReader(c, int64(len(token))+1))
		_ = c.Close()
		if string(got) == token {
			return true
		}
	}
}

func exitOf(err error) helperExit {
	e := helperExit{code: -1}
	var exitErr *exec.ExitError
	switch {
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

func sliceOutcome(step sliceStep, e helperExit, paired, brokered bool) string {
	switch {
	case e.timedOut:
		return "helper timed out"
	case e.signal != 0:
		return "helper killed by signal " + strconv.Itoa(int(e.signal))
	case e.code != step.want:
		return fmt.Sprintf("helper exit %d, want %d", e.code, step.want)
	case step.payload && !paired:
		return "no accepted connection carried the helper's payload"
	case step.payload && !step.unix && !brokered:
		return "the broker never handled a connect to the expected endpoint"
	}
	return ""
}

func withStderr(reason string, stderr *bytes.Buffer) string {
	if line, _, _ := strings.Cut(stderr.String(), "\n"); line != "" {
		return reason + ": " + line
	}
	return reason
}
