package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/netproxy"
	"codemeld.dev/codemeld/internal/runner"
)

const helperReceiveWait = 5 * time.Second

var (
	receiveListener = enforce.ReceiveListener
	releaseHelper   = enforce.ReleaseHelper
)

type brokerLaunch struct {
	decide  enforce.ConnectDecider
	owner   *netproxy.Owner
	proxy   *sessionProxy
	mu      sync.Mutex
	own     *os.File
	helper  *os.File
	broker  *enforce.Broker
	stopped bool
}

func (c *confinement) attachBroker(spec *runner.RunSpec, broker string) error {
	var server *netproxy.Server
	if broker == enforce.BrokerSlice {
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
	if err == nil && l.owner != nil {
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

func (l *brokerLaunch) refusals() []netproxy.Refusal {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []netproxy.Refusal
	if l.owner != nil {
		out = l.owner.Refusals()
	}
	if l.broker != nil {
		for _, r := range l.broker.Refusals() {
			out = append(out, netproxy.Refusal{Host: r.Host, Port: r.Port, Reason: r.Reason})
		}
	}
	return out
}

func (l *brokerLaunch) closeHelper() {
	if l.helper != nil {
		_ = l.helper.Close()
		l.helper = nil
	}
}
