package bootstrap

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/netproxy"
	"codemeld.dev/codemeld/internal/runner"
)

const helperReceiveWait = 5 * time.Second

var (
	receiveListener = enforce.ReceiveListener
	releaseHelper   = enforce.ReleaseHelper
)

type sessionDenyList = enforce.DenyList

func newSessionDenyList() *sessionDenyList { return enforce.NewDenyList() }

type brokerLaunch struct {
	decide  enforce.ConnectDecider
	rules   *enforce.ConnectRules
	owner   *netproxy.Owner
	proxy   *sessionProxy
	mu      sync.Mutex
	own     *os.File
	helper  *os.File
	broker  *enforce.Broker
	stopped bool
}

func (c *confinement) attachBroker(spec *runner.RunSpec, policy enforce.Policy) error {
	var server *netproxy.Server
	if policy.Broker != enforce.BrokerNone {
		if c.proxy != nil {
			server = c.proxy.running()
		}
		if server == nil {
			return errors.New("codemeld confinement: the session network proxy is not running")
		}
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("codemeld confinement: helper channel: %w", err)
	}
	l := &brokerLaunch{
		decide: c.decide,
		proxy:  c.proxy,
		own:    os.NewFile(uintptr(fds[0]), "helper channel"),
		helper: os.NewFile(uintptr(fds[1]), "helper channel"),
	}
	if policy.Broker == enforce.BrokerConnect || policy.Broker == enforce.BrokerFull {
		l.rules = &enforce.ConnectRules{Grants: c.connectGrants, Deny: c.deny, Proxy: c.decide, WriteRoots: policy.WriteRoots, TmpDir: policy.TmpDir, Ask: c.askConnect, Policy: policy}
	}
	if l.proxy != nil {
		if err := l.proxy.track(l); err != nil {
			_ = l.own.Close()
			_ = l.helper.Close()
			return err
		}
	}
	if server != nil {
		l.owner = server.NewOwner(c.proxyAsker)
	}
	spec.Helper = l
	return nil
}

type fileID struct{ dev, ino uint64 }

func (c *confinement) askConnect(ctx context.Context, live func() bool, tcp netip.AddrPort, unixFD int) (string, string) {
	if unixFD < 0 {
		return c.answerConnect(ctx, live, tcp, tcp.String(), nil)
	}
	var st unix.Stat_t
	if err := unix.Fstat(unixFD, &st); err != nil {
		return "", ""
	}
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(unixFD))
	if err != nil {
		return "", ""
	}
	return c.answerConnect(ctx, live, fileID{st.Dev, st.Ino}, path, func() (*os.File, error) {
		fd, err := unix.FcntlInt(uintptr(unixFD), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	})
}

func (l *brokerLaunch) HelperChannel() *os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.helper
}

func (l *brokerLaunch) Started() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeHelper()
	if l.stopped {
		return errSessionProxyStopped
	}
	listener, err := receiveListener(l.own, helperReceiveWait)
	if err == nil && l.rules != nil {
		l.broker, err = enforce.StartConnectBroker(listener, *l.rules, l.owner.Register)
	} else if err == nil && l.owner != nil {
		l.broker, err = enforce.StartRegisteringBroker(listener, l.decide, l.owner.Register)
	} else if err == nil {
		l.broker, err = enforce.StartBroker(listener, l.decide)
	}
	if err == nil {
		err = releaseHelper(l.own)
	}
	if err != nil {
		return err
	}
	_ = l.own.Close()
	l.own = nil
	return nil
}

func (l *brokerLaunch) stopBroker() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped = true
	if l.broker != nil {
		l.broker.Stop()
	}
}

func (l *brokerLaunch) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeHelper()
	if l.own != nil {
		_ = l.own.Close()
		l.own = nil
	}
	if l.broker != nil {
		l.broker.Stop()
	}
	if l.owner != nil {
		l.owner.Close()
	}
	if l.proxy != nil {
		l.proxy.untrack(l)
	}
}

func (l *brokerLaunch) refusals() []refusal {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []refusal
	if l.owner != nil {
		for _, r := range l.owner.Refusals() {
			out = append(out, refusal{Host: r.Host, Port: r.Port, Reason: r.Reason})
		}
	}
	if l.broker != nil {
		for _, r := range l.broker.Refusals() {
			out = append(out, refusal{Host: r.Host, Port: r.Port, Path: r.Path, Reason: r.Reason})
		}
	}
	return out
}

var connectAnswers = map[string]string{connectPromptOnce: "once", connectPromptSession: "session", connectDenied: "deny"}

func (l *brokerLaunch) connectDecisions() []events.ConnectDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broker == nil {
		return nil
	}
	var out []events.ConnectDecision
	for _, d := range l.broker.Decisions() {
		decision := "denied"
		if d.Allowed {
			decision = "allowed"
		}
		out = append(out, events.ConnectDecision{Destination: cmp.Or(d.Destination, events.UnknownDestination), Decision: decision, Step: d.Step, Reason: d.Reason,
			Answer: connectAnswers[cmp.Or(d.Step, d.Reason)], Count: d.Count})
	}
	return out
}

func (l *brokerLaunch) closeHelper() {
	if l.helper != nil {
		_ = l.helper.Close()
		l.helper = nil
	}
}
