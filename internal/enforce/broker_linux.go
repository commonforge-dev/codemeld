package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	kcmpFiles       = 2
	maxSockaddrLen  = 128
	stopShutdownGap = 10 * time.Millisecond

	refusedDirect = "direct connection not allowed (use the proxy)"
	refusedNotTCP = "not a TCP connect"
	refusedOpaque = "connect not inspectable"
)

var pidfdGetfd = unix.PidfdGetfd

type ConnectDecider func(dest netip.AddrPort) bool

type ConnectRegistrar func(local netip.AddrPort) error

type Refusal struct {
	Host, Port, Reason string
}

type Broker struct {
	listener *os.File
	fd       int
	wake     int
	decide   ConnectDecider
	register ConnectRegistrar

	mu         sync.Mutex
	stopping   chan struct{}
	sockets    map[uint64]*brokerSocket
	connecting map[int]struct{}
	registered map[uint64]bool
	refusals   []Refusal

	handlers sync.WaitGroup
	loopDone chan struct{}
	stopOnce sync.Once
}

type brokerSocket struct {
	users int
	turn  chan struct{}
}

func StartBroker(listener *os.File, decide ConnectDecider) (*Broker, error) {
	return StartRegisteringBroker(listener, decide, nil)
}

func StartRegisteringBroker(listener *os.File, decide ConnectDecider, register ConnectRegistrar) (*Broker, error) {
	if listener == nil {
		return nil, errors.New("broker: no listener")
	}
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("broker: eventfd: %w", err)
	}
	b := newBroker(int(listener.Fd()), decide)
	b.listener, b.wake, b.register = listener, wake, register
	go b.receive()
	return b, nil
}

func newBroker(fd int, decide ConnectDecider) *Broker {
	return &Broker{
		fd:         fd,
		wake:       -1,
		decide:     decide,
		stopping:   make(chan struct{}),
		sockets:    map[uint64]*brokerSocket{},
		connecting: map[int]struct{}{},
		registered: map[uint64]bool{},
		loopDone:   make(chan struct{}),
	}
}

func (b *Broker) Stop() {
	b.stopOnce.Do(func() {
		b.mu.Lock()
		close(b.stopping)
		b.mu.Unlock()
		var one [8]byte
		binary.NativeEndian.PutUint64(one[:], 1)
		_, _ = unix.Write(b.wake, one[:])
		<-b.loopDone
		done := make(chan struct{})
		go func() { b.handlers.Wait(); close(done) }()
		tick := time.NewTicker(stopShutdownGap)
		defer tick.Stop()
		// A shutdown that lands before the handler enters connect() does not stop it, so repeat until joined.
		for finished := false; !finished; {
			b.mu.Lock()
			for sock := range b.connecting {
				_ = unix.Shutdown(sock, unix.SHUT_RDWR)
			}
			b.mu.Unlock()
			select {
			case <-done:
				finished = true
			case <-tick.C:
			}
		}
		_ = b.listener.Close()
		_ = unix.Close(b.wake)
	})
}

func (b *Broker) receive() {
	defer close(b.loopDone)
	for {
		fds := []unix.PollFd{{Fd: int32(b.fd), Events: unix.POLLIN}, {Fd: int32(b.wake), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, -1); err == unix.EINTR {
			continue
		} else if err != nil {
			go b.Stop()
			return
		}
		if fds[1].Revents != 0 {
			return
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			go b.Stop()
			return
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := recvNotification(b.fd)
		if err == unix.EINTR || err == unix.ENOENT {
			continue
		}
		if err != nil {
			go b.Stop()
			return
		}
		b.mu.Lock()
		select {
		case <-b.stopping:
			b.mu.Unlock()
			_ = sendNotificationResponse(b.fd, denial(n.ID))
			continue
		default:
		}
		b.handlers.Add(1)
		b.mu.Unlock()
		go func() {
			defer b.handlers.Done()
			b.handle(n)
		}()
	}
}

func (b *Broker) handle(n seccompNotification) {
	resp, why, ok := b.answer(n)
	if !ok {
		return
	}
	if why == nil {
		_ = sendNotificationResponse(b.fd, resp)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.stopping:
		_ = sendNotificationResponse(b.fd, resp)
	default:
		if sendNotificationResponse(b.fd, resp) == nil {
			b.refusals = append(b.refusals, *why)
		}
	}
}

func (b *Broker) Refusals() []Refusal {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.refusals)
}

func denial(id uint64) seccompNotificationResponse {
	return seccompNotificationResponse{ID: id, Error: -int32(unix.EPERM)}
}

func (b *Broker) answer(n seccompNotification) (seccompNotificationResponse, *Refusal, bool) {
	deny := denial(n.ID)
	refuse := func(reason string) (seccompNotificationResponse, *Refusal, bool) {
		return deny, &Refusal{Reason: reason}, true
	}
	if n.Nr != unix.SYS_CONNECT {
		return refuse(refusedNotTCP)
	}
	if err := notificationIDValid(b.fd, n.ID); err != nil {
		return deny, nil, err != unix.ENOENT
	}
	tgid, err := threadGroup(n.Pid)
	if err != nil {
		return refuse(refusedOpaque)
	}
	pidfd, err := unix.PidfdOpen(tgid, 0)
	if err != nil {
		return refuse(refusedOpaque)
	}
	defer func() { _ = unix.Close(pidfd) }()
	sharesFiles := func() bool {
		if tgid == int(n.Pid) {
			return true
		}
		differ, _, e := unix.Syscall6(unix.SYS_KCMP, uintptr(n.Pid), uintptr(tgid), kcmpFiles, 0, 0, 0)
		return e == 0 && differ == 0
	}
	if !sharesFiles() {
		return refuse(refusedOpaque)
	}
	if err := notificationIDValid(b.fd, n.ID); err != nil {
		return deny, nil, err != unix.ENOENT
	}
	addr, failed := readSockaddr(n)
	if failed != "" {
		return refuse(failed)
	}
	sock, err := pidfdGetfd(pidfd, int(n.Args[0]), 0)
	if err != nil {
		return refuse(refusedOpaque)
	}
	defer func() { _ = unix.Close(sock) }()
	if !sharesFiles() {
		return refuse(refusedOpaque)
	}
	dest, ok := tcpDestination(sock, addr)
	if !ok {
		return refuse(refusedNotTCP)
	}
	if b.decide == nil || !b.decide(dest) {
		return deny, &Refusal{Host: dest.Addr().String(), Port: strconv.Itoa(int(dest.Port())), Reason: refusedDirect}, true
	}
	resp, ok := b.connect(n.ID, sock, addr)
	return resp, nil, ok
}

func threadGroup(tid uint32) (int, error) {
	status, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(tid), 10) + "/status")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, errors.New("no Tgid line")
}

func readSockaddr(n seccompNotification) ([]byte, string) {
	if n.Args[2] < 2 || n.Args[2] > maxSockaddrLen {
		return nil, refusedNotTCP
	}
	addr := make([]byte, n.Args[2])
	local := []unix.Iovec{{Base: &addr[0]}}
	local[0].SetLen(len(addr))
	got, err := unix.ProcessVMReadv(int(n.Pid), local, []unix.RemoteIovec{{Base: uintptr(n.Args[1]), Len: len(addr)}}, 0)
	if err != nil || got != len(addr) {
		return nil, refusedOpaque
	}
	return addr, ""
}

func tcpDestination(sock int, addr []byte) (netip.AddrPort, bool) {
	domain, err := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil || domain != unix.AF_INET && domain != unix.AF_INET6 {
		return netip.AddrPort{}, false
	}
	if proto, err := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_PROTOCOL); err != nil || proto != unix.IPPROTO_TCP {
		return netip.AddrPort{}, false
	}
	switch binary.NativeEndian.Uint16(addr) {
	case unix.AF_INET:
		if len(addr) >= unix.SizeofSockaddrInet4 {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(addr[4:8])), binary.BigEndian.Uint16(addr[2:4])), true
		}
	case unix.AF_INET6:
		if len(addr) >= unix.SizeofSockaddrInet6 {
			return netip.AddrPortFrom(netip.AddrFrom16([16]byte(addr[8:24])).Unmap(), binary.BigEndian.Uint16(addr[2:4])), true
		}
	}
	return netip.AddrPort{}, false
}

func (b *Broker) connect(id uint64, sock int, addr []byte) (seccompNotificationResponse, bool) {
	deny := denial(id)
	cookie, err := unix.GetsockoptUint64(sock, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return deny, true
	}
	rec := b.holdSocket(cookie)
	defer b.releaseSocket(cookie, rec)
	rec.turn <- struct{}{}
	defer func() { <-rec.turn }()
	if err := notificationIDValid(b.fd, id); err != nil {
		return deny, err != unix.ENOENT
	}
	b.mu.Lock()
	select {
	case <-b.stopping:
		b.mu.Unlock()
		return deny, true
	default:
	}
	b.connecting[sock] = struct{}{}
	b.mu.Unlock()
	_, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(sock), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
	b.mu.Lock()
	delete(b.connecting, sock)
	again := b.registered[cookie]
	b.mu.Unlock()
	if b.register != nil && (e == 0 || e == unix.EINPROGRESS) && !again {
		if b.publish(sock) != nil {
			return deny, true
		}
		b.mu.Lock()
		b.registered[cookie] = true
		b.mu.Unlock()
	}
	return seccompNotificationResponse{ID: id, Error: -int32(e)}, true
}

func (b *Broker) publish(sock int) error {
	sa, err := unix.Getsockname(sock)
	if err != nil {
		return err
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return b.register(netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)))
	case *unix.SockaddrInet6:
		return b.register(netip.AddrPortFrom(netip.AddrFrom16(a.Addr).Unmap(), uint16(a.Port)))
	}
	return errors.New("broker: the connected socket has no TCP address")
}

func (b *Broker) holdSocket(cookie uint64) *brokerSocket {
	b.mu.Lock()
	defer b.mu.Unlock()
	rec := b.sockets[cookie]
	if rec == nil {
		rec = &brokerSocket{turn: make(chan struct{}, 1)}
		b.sockets[cookie] = rec
	}
	rec.users++
	return rec
}

func (b *Broker) releaseSocket(cookie uint64, rec *brokerSocket) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if rec.users--; rec.users == 0 {
		delete(b.sockets, cookie)
	}
}
