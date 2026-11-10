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

type sliceStep struct {
	probe   string
	want    int
	payload bool
	args    func(dest netip.AddrPort, token string) []string
}

func endpointAndToken(dest netip.AddrPort, token string) []string {
	return []string{dest.String(), token}
}

var sliceSteps = []sliceStep{
	{probe: "tcp-connect-main", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "tcp-connect-thread", want: probeAllowed, payload: true, args: endpointAndToken},
	{probe: "tcp-bind", want: probeDenied, args: func(netip.AddrPort, string) []string { return []string{"127.0.0.1:0"} }},
	{probe: "tcp-listen", want: probeDenied},
	{probe: "socket-unix", want: probeDenied},
	{probe: "tcp-fastopen", want: probeDenied, args: func(dest netip.AddrPort, _ string) []string { return []string{dest.String()} }},
}

var (
	sliceReceive     = ReceiveListener
	sliceStartBroker = StartBroker
	sliceRelease     = ReleaseHelper
)

func runSliceSelfTest(home, exe string) (passed bool, reason string) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return false, "slice self-test: loopback listener: " + err.Error()
	}
	defer func() { _ = ln.Close() }()
	dest, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		return false, "slice self-test: loopback listener: " + err.Error()
	}
	for _, step := range sliceSteps {
		if reason := runSliceAttempt(home, exe, ln, dest, step); reason != "" {
			return false, "slice self-test: " + step.probe + ": " + reason
		}
	}
	return true, ""
}

func runSliceAttempt(home, exe string, ln *net.TCPListener, dest netip.AddrPort, step sliceStep) string {
	f, err := newFixture(home, selfTestLeg{})
	if err != nil {
		return "fixture: " + err.Error()
	}
	defer f.remove()
	var frame bytes.Buffer
	policy := Policy{Mode: ModeAutoEdits, Broker: BrokerSlice, BlockedPaths: []string{filepath.Join(home, ".codemeld")}, TmpDir: f.tmp()}
	if err := WritePolicyFrame(&frame, policy); err != nil {
		return "policy frame: " + err.Error()
	}
	env, err := runner.FixedEnvironment(home, f.root, f.tmp(), runner.FixedPATH, nil)
	if err != nil {
		return "environment: " + err.Error()
	}
	token := rand.Text()
	argv := []string{HelperCommand, ProbeArg, step.probe}
	if step.args != nil {
		argv = append(argv, step.args(dest, token)...)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "setup channel: " + err.Error()
	}
	parent, child := os.NewFile(uintptr(fds[0]), "setup channel"), os.NewFile(uintptr(fds[1]), "helper setup channel")
	defer func() { _ = parent.Close() }()
	var stderr bytes.Buffer
	cmd := exec.Command(exe, argv...)
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
	broker, err := sliceStartBroker(listener, func(d netip.AddrPort) bool {
		if d != dest {
			return false
		}
		brokered.Store(true)
		return true
	})
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

func acceptToken(ln *net.TCPListener, token string, deadline time.Time) bool {
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
	case step.payload && !brokered:
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
