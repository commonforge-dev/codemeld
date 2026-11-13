package enforce

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
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
	sin6LenRFC2133  = 24
	stopShutdownGap = 10 * time.Millisecond
	askLiveGap      = 50 * time.Millisecond

	refusedDirect = "direct connection not allowed (use the proxy)"
	refusedNotTCP = "not a TCP connect"
	refusedOpaque = "connect not inspectable"
	refusedBind   = "bind not allowed (only 127.0.0.1 or ::1)"
	refusedListen = "listen not allowed (bind to 127.0.0.1 or ::1 first)"

	refusedAlways     = "always denied: "
	refusedAbstract   = refusedAlways + "abstract Unix address"
	refusedUnresolved = "Unix socket path not checkable"
	refusedUngranted  = "Unix socket connect not granted"
	refusedUnixBind   = "Unix bind failed: "
	maxSymlinks       = 40

	stepProxy       = "proxy"
	stepOwnListener = "own listener"
	stepGrant       = "grant"
)

var (
	pidfdGetfd        = unix.PidfdGetfd
	bindOrListenPause = func(nr int32, afterSyscall bool) {}
	afterConfinedBind = func() {}
)

type ConnectDecider func(dest netip.AddrPort) bool

type ConnectRegistrar func(local netip.AddrPort) error

type ConnectAsker func(ctx context.Context, live func() bool, tcp netip.AddrPort, unixFD int) (step, reason string)

type Refusal struct {
	Host, Port, Path, Reason string
}

type ConnectDecision struct {
	Destination string
	Allowed     bool
	Step        string
	Reason      string
	Count       int64
}

type ConnectRules struct {
	Grants     []string
	Deny       *DenyList
	Proxy      ConnectDecider
	WriteRoots []string
	TmpDir     string
	Ask        ConnectAsker
	Policy     Policy
}

type Broker struct {
	listener *os.File
	fd       int
	wake     int
	decide   ConnectDecider
	register ConnectRegistrar
	rules    *ConnectRules

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	stopping   chan struct{}
	sockets    map[uint64]*brokerSocket
	connecting map[int]struct{}
	registered map[uint64]bool
	bound      map[uint64]bool
	own        map[netip.AddrPort]bool
	refusals   []Refusal
	decisions  []ConnectDecision

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
	return startBroker(listener, decide, register, nil)
}

func StartConnectBroker(listener *os.File, rules ConnectRules, register ConnectRegistrar) (*Broker, error) {
	if rules.Deny == nil {
		if listener != nil {
			_ = listener.Close()
		}
		return nil, errors.New("broker: no deny list")
	}
	return startBroker(listener, rules.Proxy, register, &rules)
}

func startBroker(listener *os.File, decide ConnectDecider, register ConnectRegistrar, rules *ConnectRules) (*Broker, error) {
	if listener == nil {
		return nil, errors.New("broker: no listener")
	}
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("broker: eventfd: %w", err)
	}
	b := newBroker(int(listener.Fd()), decide)
	b.listener, b.wake, b.register, b.rules = listener, wake, register, rules
	go b.receive()
	return b, nil
}

func newBroker(fd int, decide ConnectDecider) *Broker {
	ctx, cancel := context.WithCancel(context.Background())
	return &Broker{
		ctx:        ctx,
		cancel:     cancel,
		fd:         fd,
		wake:       -1,
		decide:     decide,
		stopping:   make(chan struct{}),
		sockets:    map[uint64]*brokerSocket{},
		connecting: map[int]struct{}{},
		registered: map[uint64]bool{},
		bound:      map[uint64]bool{},
		own:        map[netip.AddrPort]bool{},
		loopDone:   make(chan struct{}),
	}
}

func (b *Broker) Stop() {
	b.stopOnce.Do(func() {
		b.mu.Lock()
		close(b.stopping)
		b.mu.Unlock()
		b.cancel()
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
	resp, why, dec, ok := b.answer(n)
	if !ok {
		return
	}
	if why == nil && dec == nil {
		_ = sendNotificationResponse(b.fd, resp)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.stopping:
		_ = sendNotificationResponse(b.fd, resp)
	default:
		if sendNotificationResponse(b.fd, resp) != nil {
			return
		}
		if why != nil {
			b.refusals = append(b.refusals, *why)
		}
		if dec != nil {
			b.record(*dec)
		}
	}
}

func (b *Broker) Refusals() []Refusal {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.refusals)
}

func (b *Broker) record(dec ConnectDecision) {
	dec.Count = 1
	if i := slices.IndexFunc(b.decisions, func(d ConnectDecision) bool { d.Count = 1; return d == dec }); i >= 0 {
		b.decisions[i].Count++
		return
	}
	b.decisions = append(b.decisions, dec)
}

func (b *Broker) Decisions() []ConnectDecision {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.decisions)
}

func denial(id uint64) seccompNotificationResponse {
	return seccompNotificationResponse{ID: id, Error: -int32(unix.EPERM)}
}

func (b *Broker) answer(n seccompNotification) (seccompNotificationResponse, *Refusal, *ConnectDecision, bool) {
	deny := denial(n.ID)
	refuse := func(reason string) (seccompNotificationResponse, *Refusal, *ConnectDecision, bool) {
		switch n.Nr {
		case unix.SYS_BIND:
			reason = refusedBind
		case unix.SYS_LISTEN:
			reason = refusedListen
		}
		var dec *ConnectDecision
		if b.rules != nil && n.Nr == unix.SYS_CONNECT {
			dec = &ConnectDecision{Reason: reason}
		}
		return deny, &Refusal{Reason: reason}, dec, true
	}
	if n.Nr != unix.SYS_CONNECT && n.Nr != unix.SYS_BIND && n.Nr != unix.SYS_LISTEN {
		return refuse(refusedNotTCP)
	}
	if err := notificationIDValid(b.fd, n.ID); err != nil {
		return deny, nil, nil, err != unix.ENOENT
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
		return deny, nil, nil, err != unix.ENOENT
	}
	var addr []byte
	if n.Nr != unix.SYS_LISTEN {
		var failed string
		if addr, failed = readSockaddr(n); failed != "" {
			return refuse(failed)
		}
	}
	sock, err := pidfdGetfd(pidfd, int(n.Args[0]), 0)
	if err != nil {
		return refuse(refusedOpaque)
	}
	defer func() { _ = unix.Close(sock) }()
	if !sharesFiles() {
		return refuse(refusedOpaque)
	}
	if n.Nr == unix.SYS_LISTEN {
		resp, why, ok := b.bindOrListen(n, sock, nil, nil)
		return resp, why, nil, ok
	}
	if domain, err := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_DOMAIN); err == nil && domain == unix.AF_UNIX {
		if n.Nr == unix.SYS_BIND {
			resp, why, ok := b.bindUnix(n, sock, addr)
			return resp, why, nil, ok
		}
		if b.rules != nil {
			return b.connectUnix(n.ID, n.Pid, sock, addr)
		}
	}
	dest, ok := tcpDestination(sock, addr)
	if !ok {
		return refuse(refusedNotTCP)
	}
	if n.Nr == unix.SYS_BIND {
		if dest.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) && dest.Addr() != netip.IPv6Loopback() {
			return refuse(refusedBind)
		}
		resp, why, ok := b.bindOrListen(n, sock, addr, nil)
		return resp, why, nil, ok
	}
	b.mu.Lock()
	own := b.own[dest]
	b.mu.Unlock()
	var step, reason string
	switch {
	case own:
		step = stepOwnListener
	case b.decide != nil && b.decide(dest):
		step = stepProxy
	case b.rules.grantsTCP(dest):
		step = stepGrant
	default:
		step, reason = b.ask(n.ID, dest, -1, refusedDirect)
	}
	var dec *ConnectDecision
	if b.rules != nil {
		dec = &ConnectDecision{Destination: dest.String(), Allowed: step != "", Step: step, Reason: reason}
	}
	if step == "" {
		return deny, &Refusal{Host: dest.Addr().String(), Port: strconv.Itoa(int(dest.Port())), Reason: reason}, dec, true
	}
	resp, ok := b.connect(n.ID, sock, addr)
	return resp, nil, dec, ok
}

func (b *Broker) connectUnix(id uint64, tid uint32, sock int, addr []byte) (seccompNotificationResponse, *Refusal, *ConnectDecision, bool) {
	deny := denial(id)
	refuse := func(path, dest, reason string) (seccompNotificationResponse, *Refusal, *ConnectDecision, bool) {
		return deny, &Refusal{Path: path, Reason: reason}, &ConnectDecision{Destination: dest, Reason: reason}, true
	}
	if binary.NativeEndian.Uint16(addr) == unix.AF_UNIX && len(addr) > 2 && addr[2] == 0 {
		path := "@" + string(addr[3:])
		return refuse(path, path, refusedAbstract)
	}
	path, _, _ := strings.Cut(string(addr[2:]), "\x00")
	fd, sa, err := resolveUnixDest(tid, addr)
	if err != nil {
		return refuse(path, path, refusedUnresolved)
	}
	defer func() { _ = unix.Close(fd) }()
	dest := path
	if real, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil {
		dest = real
	}
	var step string
	ok, reason := b.rules.decideUnix(fd)
	if ok {
		step = stepGrant
	} else if reason != refusedOpaque && !strings.HasPrefix(reason, refusedAlways) {
		step, reason = b.ask(id, netip.AddrPort{}, fd, reason)
	}
	if step == "" {
		return refuse(path, dest, reason)
	}
	resp, ok := b.connect(id, sock, append(binary.NativeEndian.AppendUint16(nil, unix.AF_UNIX), sa.Name...))
	return resp, nil, &ConnectDecision{Destination: dest, Allowed: true, Step: step}, ok
}

func (r *ConnectRules) grantsTCP(dest netip.AddrPort) bool {
	if r == nil {
		return false
	}
	for _, g := range r.Grants {
		if ap, err := netip.ParseAddrPort(g); err == nil && tcpEndpoint(ap.Addr(), ap.Port()) == dest {
			return true
		}
	}
	return false
}

func (b *Broker) ask(id uint64, tcp netip.AddrPort, unixFD int, reason string) (step, why string) {
	if b.rules == nil || b.rules.Ask == nil {
		return "", reason
	}
	live := func() bool { return notificationIDValid(b.fd, id) == nil }
	ctx, cancel := context.WithCancel(b.ctx)
	watched := make(chan struct{})
	defer func() { cancel(); <-watched }()
	go func() {
		defer close(watched)
		tick := time.NewTicker(askLiveGap)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if !live() {
					cancel()
					return
				}
			}
		}
	}()
	if step, why = b.rules.Ask(ctx, live, tcp, unixFD); step != "" {
		return step, ""
	}
	return "", cmp.Or(why, reason)
}

func (r *ConnectRules) decideUnix(fd int) (bool, string) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, refusedOpaque
	}
	if entry, denied := r.Deny.denies(&st); denied {
		return false, refusedAlways + entry
	}
	reason := refusedUngranted
	for _, g := range r.Grants {
		if !filepath.IsAbs(g) {
			continue
		}
		match, why := r.pathGrant(g, &st)
		if match {
			return true, ""
		}
		if why != "" {
			reason = why
		}
	}
	return false, reason
}

func (r *ConnectRules) pathGrant(grant string, dest *unix.Stat_t) (bool, string) {
	st, traversed, err := walkPath(grant)
	if err != nil || st.Dev != dest.Dev || st.Ino != dest.Ino {
		return false, ""
	}
	roots := slices.Clone(r.WriteRoots)
	if r.TmpDir != "" {
		roots = append(roots, r.TmpDir)
	}
	for _, root := range roots {
		if resolved, err := filepath.EvalSymlinks(root); err == nil {
			root = resolved
		}
		for _, p := range traversed {
			if rel, err := filepath.Rel(root, p); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
				return false, fmt.Sprintf("grant %s resolves through %s, inside the write root or temp folder %s", grant, p, root)
			}
		}
	}
	return true, ""
}

func walkPath(path string) (unix.Stat_t, []string, error) {
	var st unix.Stat_t
	var traversed []string
	rest := strings.Split(path, "/")
	cur, links := "/", 0
	if err := unix.Lstat(cur, &st); err != nil {
		return st, nil, err
	}
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return st, nil, unix.ENOTDIR
		}
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			if err := unix.Lstat(cur, &st); err != nil {
				return st, nil, err
			}
			continue
		}
		next := filepath.Join(cur, c)
		if err := unix.Lstat(next, &st); err != nil {
			return st, nil, err
		}
		traversed = append(traversed, next)
		if st.Mode&unix.S_IFMT != unix.S_IFLNK {
			cur = next
			continue
		}
		if links++; links > maxSymlinks {
			return st, nil, unix.ELOOP
		}
		target, err := os.Readlink(next)
		if err != nil {
			return st, nil, err
		}
		if filepath.IsAbs(target) {
			cur = "/"
		}
		if err := unix.Lstat(cur, &st); err != nil {
			return st, nil, err
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return st, traversed, nil
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
			return tcpEndpoint(netip.AddrFrom4([4]byte(addr[4:8])), binary.BigEndian.Uint16(addr[2:4])), true
		}
	case unix.AF_INET6:
		if len(addr) >= sin6LenRFC2133 {
			return tcpEndpoint(netip.AddrFrom16([16]byte(addr[8:24])), binary.BigEndian.Uint16(addr[2:4])), true
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
	stopped := b.stopped()
	b.mu.Unlock()
	if b.register != nil && binary.NativeEndian.Uint16(addr) != unix.AF_UNIX && (e == 0 || e == unix.EINPROGRESS) && !again {
		if stopped {
			return deny, true
		}
		if b.publish(sock) != nil {
			return deny, true
		}
		b.mu.Lock()
		b.registered[cookie] = true
		b.mu.Unlock()
	}
	return seccompNotificationResponse{ID: id, Error: -int32(e)}, true
}

func (b *Broker) stopped() bool {
	select {
	case <-b.stopping:
		return true
	default:
		return false
	}
}

func (b *Broker) bindOrListen(n seccompNotification, sock int, addr []byte, confined func() (unix.Errno, *Refusal)) (seccompNotificationResponse, *Refusal, bool) {
	deny := denial(n.ID)
	cookie, err := unix.GetsockoptUint64(sock, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return deny, nil, true
	}
	domain, err := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return deny, nil, true
	}
	rec := b.holdSocket(cookie)
	defer b.releaseSocket(cookie, rec)
	rec.turn <- struct{}{}
	defer func() { <-rec.turn }()
	bindOrListenPause(n.Nr, false)
	if err := notificationIDValid(b.fd, n.ID); err != nil {
		return deny, nil, err != unix.ENOENT
	}
	b.mu.Lock()
	bound, stopped := b.bound[cookie], b.stopped()
	b.mu.Unlock()
	if stopped {
		return deny, nil, true
	}
	var e unix.Errno
	switch {
	case n.Nr == unix.SYS_LISTEN:
		if !bound {
			return deny, &Refusal{Reason: refusedListen}, true
		}
		_, _, e = unix.Syscall(unix.SYS_LISTEN, uintptr(sock), uintptr(n.Args[1]), 0)
	case confined != nil:
		var why *Refusal
		if e, why = confined(); why != nil {
			return deny, why, true
		}
	default:
		_, _, e = unix.Syscall(unix.SYS_BIND, uintptr(sock), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
	}
	if e != 0 {
		return seccompNotificationResponse{ID: n.ID, Error: -int32(e)}, nil, true
	}
	bindOrListenPause(n.Nr, true)
	var local netip.AddrPort
	if domain != unix.AF_UNIX {
		if local, err = socketEndpoint(sock); err != nil {
			return deny, nil, true
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped() {
		return deny, nil, true
	}
	b.bound[cookie] = true
	if local.Port() != 0 {
		b.own[local] = true
	}
	return seccompNotificationResponse{ID: n.ID}, nil, true
}

func (b *Broker) bindUnix(n seccompNotification, sock int, addr []byte) (seccompNotificationResponse, *Refusal, bool) {
	deny := denial(n.ID)
	if binary.NativeEndian.Uint16(addr) == unix.AF_UNIX && (len(addr) == 2 || addr[2] == 0) {
		return deny, &Refusal{Path: "@" + string(addr[min(3, len(addr)):]), Reason: refusedAbstract}, true
	}
	path, _, _ := strings.Cut(string(addr[2:]), "\x00")
	failed := func(err error) *Refusal { return &Refusal{Path: path, Reason: refusedUnixBind + err.Error()} }
	var policy Policy
	if b.rules != nil {
		policy = b.rules.Policy
	}
	if err := policy.validate(); err != nil {
		return deny, failed(err), true
	}
	rules, err := landlockRules(policy, osFS{}, heldTmp{})
	if err != nil {
		return deny, failed(err), true
	}
	umask, err := threadUmask(n.Pid)
	if err != nil {
		return deny, failed(err), true
	}
	cwd, err := unix.Open(fmt.Sprintf("/proc/%d/cwd", n.Pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return deny, failed(fmt.Errorf("open the caller's working folder: %w", err)), true
	}
	defer func() { _ = unix.Close(cwd) }()
	return b.bindOrListen(n, sock, addr, func() (unix.Errno, *Refusal) {
		e, err := bindOnConfinedThread(rules, umask, cwd, sock, addr)
		if err != nil {
			return 0, failed(err)
		}
		return e, nil
	})
}

// A locked goroutine that returns ends its thread, except on the main thread, which it wedges instead.
func bindOnConfinedThread(rules []pathRule, umask, cwd, sock int, addr []byte) (unix.Errno, error) {
	type result struct {
		e   unix.Errno
		err error
	}
	done := make(chan result, 1)
	var run func()
	run = func() {
		runtime.LockOSThread()
		if unix.Gettid() == unix.Getpid() {
			inner := make(chan struct{})
			go func() { run(); close(inner) }()
			<-inner
			runtime.UnlockOSThread()
			return
		}
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			done <- result{err: fmt.Errorf("unshare(CLONE_FS): %w", err)}
			return
		}
		unix.Umask(umask)
		if err := restrictThreadMakeSock(rules); err != nil {
			done <- result{err: err}
			return
		}
		if err := unix.Fchdir(cwd); err != nil {
			done <- result{err: fmt.Errorf("fchdir: %w", err)}
			return
		}
		_, _, e := unix.Syscall(unix.SYS_BIND, uintptr(sock), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
		afterConfinedBind()
		done <- result{e: e}
	}
	go run()
	r := <-done
	return r.e, r.err
}

func threadUmask(tid uint32) (int, error) {
	status, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(tid), 10) + "/status")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Umask:"); ok {
			mask, err := strconv.ParseUint(strings.TrimSpace(v), 8, 32)
			return int(mask), err
		}
	}
	return 0, errors.New("no Umask line")
}

func (b *Broker) publish(sock int) error {
	local, err := socketEndpoint(sock)
	if err != nil {
		return err
	}
	return b.register(local)
}

func socketEndpoint(sock int) (netip.AddrPort, error) {
	sa, err := unix.Getsockname(sock)
	if err != nil {
		return netip.AddrPort{}, err
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return tcpEndpoint(netip.AddrFrom4(a.Addr), uint16(a.Port)), nil
	case *unix.SockaddrInet6:
		return tcpEndpoint(netip.AddrFrom16(a.Addr), uint16(a.Port)), nil
	}
	return netip.AddrPort{}, errors.New("broker: the socket has no TCP address")
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
