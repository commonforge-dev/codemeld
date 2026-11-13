package enforce

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	brkChildEnv    = "CODEMELD_TEST_BROKER_KERNEL_CHILD"
	brkPeerAddrEnv = "CODEMELD_TEST_BROKER_PEER_ADDR"
	brkBound       = 10 * time.Second
	brkBadFD       = 9999
)

func brkSockaddr(ap netip.AddrPort) []byte {
	if ap.Addr().Is4() {
		b := make([]byte, unix.SizeofSockaddrInet4)
		binary.NativeEndian.PutUint16(b, unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:], ap.Port())
		a := ap.Addr().As4()
		copy(b[4:], a[:])
		return b
	}
	b := make([]byte, unix.SizeofSockaddrInet6)
	binary.NativeEndian.PutUint16(b, unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	a := ap.Addr().As16()
	copy(b[8:], a[:])
	return b
}

type brkChildState struct {
	mu              sync.Mutex
	fds             map[string]int
	bufs            map[string][]byte
	other, separate func(func())
}

func (s *brkChildState) fd(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fds[name]
}

func (s *brkChildState) keep(name string, fd int, err error) string {
	if err == nil {
		s.mu.Lock()
		s.fds[name] = fd
		s.mu.Unlock()
	}
	return errName(err)
}

func (s *brkChildState) run(f []string) string {
	switch f[0] {
	case "socket":
		typ := unix.SOCK_STREAM | unix.SOCK_CLOEXEC
		if len(f) > 3 {
			typ |= unix.SOCK_NONBLOCK
		}
		fd, err := unix.Socket(map[string]int{"inet": unix.AF_INET, "inet6": unix.AF_INET6, "unix": unix.AF_UNIX}[f[2]], typ, 0)
		return s.keep(f[1], fd, err)
	case "pair":
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		return s.keep(f[1], fds[0], err)
	case "dup":
		fd, err := unix.FcntlInt(uintptr(s.fd(f[1])), unix.F_DUPFD_CLOEXEC, 0)
		return s.keep(f[2], fd, err)
	case "fdnum":
		return strconv.Itoa(s.fd(f[1]))
	case "connect":
		addr := brkSockaddr(netip.MustParseAddrPort(f[2]))
		s.mu.Lock()
		s.bufs[f[1]] = addr
		fd := s.fds[f[1]]
		s.mu.Unlock()
		var err error
		call := func() { err = rawSockaddrCall(unix.SYS_CONNECT, fd, addr) }
		if len(f) > 3 {
			s.other(call)
		} else {
			call()
		}
		return errName(err)
	case "separate":
		var err error
		s.separate(func() {
			fd, serr := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if serr != nil {
				err = errors.New("fixture socket: " + errName(serr))
				return
			}
			defer func() { _ = unix.Close(fd) }()
			err = rawSockaddrCall(unix.SYS_CONNECT, fd, brkSockaddr(netip.MustParseAddrPort(f[1])))
		})
		return errName(err)
	case "raw":
		addr, err := hex.DecodeString(f[2])
		if err != nil {
			return err.Error()
		}
		nr := uintptr(unix.SYS_CONNECT)
		if len(f) > 3 {
			nr = unix.SYS_BIND
		}
		return errName(rawSockaddrCall(nr, s.fd(f[1]), addr))
	case "noport":
		return errName(unix.SetsockoptInt(s.fd(f[1]), unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT, 1))
	case "badptr":
		_, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(s.fd(f[1])), 1, unix.SizeofSockaddrInet4)
		return errName(errnoErr(e))
	case "edge":
		page := os.Getpagesize()
		mem, err := unix.Mmap(-1, 0, 2*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
		if err != nil {
			return errName(err)
		}
		if err := unix.Mprotect(mem[page:], unix.PROT_NONE); err != nil {
			return errName(err)
		}
		half := unix.SizeofSockaddrInet4 / 2
		copy(mem[page-half:page], brkSockaddr(netip.MustParseAddrPort(f[2])))
		_, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(s.fd(f[1])), uintptr(unsafe.Pointer(&mem[page-half])), unix.SizeofSockaddrInet4)
		return errName(errnoErr(e))
	case "badfd":
		return errName(rawSockaddrCall(unix.SYS_CONNECT, brkBadFD, brkSockaddr(netip.MustParseAddrPort(f[1]))))
	case "bind":
		addr := "127.0.0.1:0"
		if len(f) > 2 {
			addr = f[2]
		}
		return errName(rawSockaddrCall(unix.SYS_BIND, s.fd(f[1]), brkSockaddr(netip.MustParseAddrPort(addr))))
	case "listen":
		return errName(unix.Listen(s.fd(f[1]), 1))
	case "soerror":
		fd := s.fd(f[1])
		if _, err := pollFD(fd, unix.POLLOUT, brkBound); err != nil {
			return errName(err)
		}
		v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return errName(err)
		}
		return errName(errnoErr(unix.Errno(v)))
	case "peer", "local":
		name := unix.Getpeername
		if f[0] == "local" {
			name = unix.Getsockname
		}
		sa, err := name(s.fd(f[1]))
		switch a := sa.(type) {
		case *unix.SockaddrInet4:
			return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)).String()
		case *unix.SockaddrInet6:
			return netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port)).String()
		case *unix.SockaddrUnix:
			return strconv.Quote(a.Name)
		}
		return errName(err)
	case "chdir":
		return errName(unix.Chdir(f[1]))
	case "umask":
		mask, err := strconv.ParseUint(f[1], 8, 32)
		if err != nil {
			return err.Error()
		}
		unix.Umask(int(mask))
		return "0"
	case "rewrite":
		s.mu.Lock()
		copy(s.bufs[f[1]], brkSockaddr(netip.MustParseAddrPort(f[2])))
		s.mu.Unlock()
		return "0"
	case "reuse":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return errName(err)
		}
		defer func() { _ = unix.Close(fd) }()
		return errName(unix.Dup3(fd, s.fd(f[1]), unix.O_CLOEXEC))
	case "spawn":
		fd, err := unix.FcntlInt(uintptr(s.fd(f[1])), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return errName(err)
		}
		sock := os.NewFile(uintptr(fd), "peer-socket")
		cmd := exec.Command(os.Args[0], "-test.run=^TestBrokerKernelChild$")
		cmd.Env = append(os.Environ(), brkChildEnv+"=peer", brkPeerAddrEnv+"="+f[2])
		cmd.ExtraFiles = []*os.File{sock}
		out, err := cmd.Output()
		_ = sock.Close()
		for line := range strings.SplitSeq(string(out), "\n") {
			if v, ok := strings.CutPrefix(line, "result="); ok {
				return v
			}
		}
		return "peer failed: " + errName(err)
	}
	return "unknown " + f[0]
}

func (s *brkChildState) split(name string) string {
	if unix.Gettid() != unix.Getpid() {
		return "unverified"
	}
	if err := unix.CloseRange(uint(^uint32(0)), uint(^uint32(0)), unix.CLOSE_RANGE_UNSHARE); err != nil {
		return errName(err)
	}
	return s.run([]string{"reuse", name})
}

func TestBrokerKernelChild(t *testing.T) {
	mode := os.Getenv(brkChildEnv)
	switch mode {
	case "":
		t.Skip("runs only as the disposable child of the broker tests")
	case "peer":
		if os.Getenv(brkPeerAddrEnv) == "listen" {
			_, _ = os.Stdout.WriteString("result=" + errName(unix.Listen(3, 1)) + "\n")
			return
		}
		addr := brkSockaddr(netip.MustParseAddrPort(os.Getenv(brkPeerAddrEnv)))
		_, _ = os.Stdout.WriteString("result=" + errName(rawSockaddrCall(unix.SYS_CONNECT, 3, addr)) + "\n")
		return
	}
	reply := func(msg string, oob []byte) { _ = unix.Sendmsg(3, []byte(msg), oob, nil, 0) }
	runtime.LockOSThread()
	st := &brkChildState{fds: map[string]int{}, bufs: map[string][]byte{}}
	var err error
	if st.other, err = proxyThread(false); err != nil {
		t.Fatal(err)
	}
	if st.separate, err = proxyThread(true); err != nil {
		t.Fatal(err)
	}
	for name, spec := range map[string][3]int{"udp": {unix.AF_INET, unix.SOCK_DGRAM, 0}, "xfrm": {unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_XFRM}} {
		fd, err := unix.Socket(spec[0], spec[1]|unix.SOCK_CLOEXEC, spec[2])
		if err != nil {
			t.Fatal(err)
		}
		st.fds[name] = fd
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	listener, err := installSeccompListener(map[string]Policy{"slice": seccompSlice, "full": seccompFull, "connect": seccompConnect}[mode])
	if err != nil {
		var e unix.Errno
		errors.As(err, &e)
		reply("install="+unix.ErrnoName(e), nil)
		return
	}
	reply("listener", unix.UnixRights(listener))
	if err := unix.Close(listener); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	for {
		n, err := unix.Read(3, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return
		}
		f := strings.Fields(string(buf[:n]))
		if f[1] == "split" {
			reply(f[0]+" "+st.split(f[2]), nil)
			continue
		}
		go func() { reply(f[0]+" "+st.run(f[1:]), nil) }()
	}
}

type brkChild struct {
	cmd      *exec.Cmd
	ctl      *net.UnixConn
	listener *os.File
	done     chan struct{}
	waitErr  error
	out      bytes.Buffer

	mu      sync.Mutex
	seq     int
	replies map[string]chan string
}

func brkStart(t *testing.T, mode string) *brkChild {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentEnd, childEnd := os.NewFile(uintptr(fds[0]), "broker-ctl"), os.NewFile(uintptr(fds[1]), "broker-child-ctl")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	c := &brkChild{done: make(chan struct{}), replies: map[string]chan string{}}
	c.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBrokerKernelChild$")
	c.cmd.Env = append(os.Environ(), brkChildEnv+"="+mode)
	c.cmd.ExtraFiles = []*os.File{childEnd}
	c.cmd.Stdout, c.cmd.Stderr = &c.out, &c.out
	err = c.cmd.Start()
	closed(t, "the child's control end", childEnd.Close())
	if err != nil {
		closed(t, "the control end", parentEnd.Close())
		cancel()
		t.Fatal(err)
	}
	go func() { c.waitErr = c.cmd.Wait(); close(c.done) }()
	t.Cleanup(func() {
		cancel()
		<-c.done
		if c.listener != nil {
			closed(t, "the listener", c.listener.Close())
		}
		if c.ctl != nil {
			closed(t, "the control connection", c.ctl.Close())
		}
	})
	conn, err := net.FileConn(parentEnd)
	closed(t, "the control end", parentEnd.Close())
	if err != nil {
		t.Fatal(err)
	}
	c.ctl = conn.(*net.UnixConn)
	if err := c.ctl.SetReadDeadline(time.Now().Add(brkBound)); err != nil {
		t.Fatal(err)
	}
	b, oob := make([]byte, 64), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := c.ctl.ReadMsgUnix(b, oob)
	if err != nil {
		c.fatalf(t, "no listener message: %v", err)
	}
	if msg := string(b[:n]); msg != "listener" {
		if msg == "install=EINVAL" || msg == "install=ENOSYS" {
			t.Skipf("unverified: the kernel refused the listener filter (%s)", msg)
		}
		c.fatalf(t, "child: %s", msg)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		c.fatalf(t, "listener message: %v", err)
	}
	rights, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(rights) != 1 {
		c.fatalf(t, "listener rights %v: %v", rights, err)
	}
	c.listener = os.NewFile(uintptr(rights[0]), "listener")
	if err := c.ctl.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(c.cmd.Process.Pid, 0)
	if err == nil {
		var probe int
		if probe, err = unix.PidfdGetfd(pidfd, 3, 0); err == nil {
			closed(t, "the probe copy", unix.Close(probe))
		}
		closed(t, "the probe pidfd", unix.Close(pidfd))
	}
	if err != nil {
		t.Skipf("inconclusive at kernel.yama.ptrace_scope=%s: taking a copy of the child's descriptor failed: %v", sysctl("/proc/sys/kernel/yama/ptrace_scope"), err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, _, _, _, err := c.ctl.ReadMsgUnix(buf, nil)
			if err != nil {
				return
			}
			tag, res, _ := strings.Cut(string(buf[:n]), " ")
			c.mu.Lock()
			ch := c.replies[tag]
			c.mu.Unlock()
			if ch != nil {
				ch <- res
			}
		}
	}()
	return c
}

func (c *brkChild) take() *os.File {
	l := c.listener
	c.listener = nil
	return l
}

func (c *brkChild) start(t *testing.T, cmd string) <-chan string {
	t.Helper()
	c.mu.Lock()
	c.seq++
	tag := strconv.Itoa(c.seq)
	ch := make(chan string, 1)
	c.replies[tag] = ch
	c.mu.Unlock()
	if _, err := c.ctl.Write([]byte(tag + " " + cmd)); err != nil {
		c.fatalf(t, "send %q: %v", cmd, err)
	}
	return ch
}

func (c *brkChild) await(t *testing.T, ch <-chan string, what string) string {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(brkBound):
		c.fatalf(t, "%s: no reply within %v", what, brkBound)
	}
	return ""
}

func (c *brkChild) silent(ch <-chan string, d time.Duration) bool {
	select {
	case <-ch:
		return false
	case <-time.After(d):
		return true
	}
}

func (c *brkChild) do(t *testing.T, cmd string) string {
	t.Helper()
	return c.await(t, c.start(t, cmd), cmd)
}

func (c *brkChild) expect(t *testing.T, cmd, want string) {
	t.Helper()
	if got := c.do(t, cmd); got != want {
		t.Errorf("%s: got %s, want %s", cmd, got, want)
	}
}

func (c *brkChild) fatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	_ = c.cmd.Process.Kill()
	<-c.done
	t.Fatalf(format+"\nchild (%v) output:\n%s", append(args, c.waitErr, c.out.String())...)
}

func (c *brkChild) until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(brkBound)
	for !cond() {
		if time.Now().After(deadline) {
			c.fatalf(t, "timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type brkDecisions struct {
	mu    sync.Mutex
	seen  []netip.AddrPort
	allow map[netip.AddrPort]bool
}

func (d *brkDecisions) decide(dest netip.AddrPort) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, dest)
	return d.allow[dest]
}

func (d *brkDecisions) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

func brkStartBroker(t *testing.T, c *brkChild, decide ConnectDecider) *Broker {
	t.Helper()
	b, err := StartBroker(c.take(), decide)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	return b
}

func brkListen(t *testing.T) (*net.TCPListener, netip.AddrPort) {
	t.Helper()
	ln, port := listenTCP(t)
	return ln, netip.MustParseAddrPort("127.0.0.1:" + port)
}

func brkAccepts(t *testing.T, ln *net.TCPListener, d time.Duration) int {
	t.Helper()
	if err := ln.SetDeadline(time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		conn, err := ln.Accept()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return n
		}
		if err != nil {
			t.Fatal(err)
		}
		closed(t, "an accepted connection", conn.Close())
		n++
	}
}

func brkFreePort(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed(t, "the probe listener", ln.Close())
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func brkFullListener(t *testing.T) (netip.AddrPort, func() int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fillers []net.Conn
	t.Cleanup(func() {
		for _, c := range fillers {
			closed(t, "a filler connection", c.Close())
		}
		closed(t, "the full listener", unix.Close(fd))
	})
	if err := unix.Bind(fd, loopback4(0)); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(sa.(*unix.SockaddrInet4).Port))
	for len(fillers) < 8 {
		conn, err := net.DialTimeout("tcp4", ap.String(), 300*time.Millisecond)
		if err != nil {
			break
		}
		fillers = append(fillers, conn)
	}
	if len(fillers) == 8 {
		t.Fatal("fixture: the accept queue never filled")
	}
	return ap, func() int {
		n := 0
		for {
			nfd, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
			if err != nil {
				return n
			}
			closed(t, "a drained connection", unix.Close(nfd))
			n++
		}
	}
}

func brkStop(t *testing.T, b *Broker, bound time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { b.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(bound):
		t.Fatalf("Stop did not return within %v", bound)
	}
}

func brkLinks(t *testing.T, pid, target string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/" + pid + "/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if link, err := os.Readlink("/proc/" + pid + "/fd/" + e.Name()); err == nil && link == target {
			n++
		}
	}
	return n
}

func brkNative(t *testing.T, nonblock bool, dest netip.AddrPort, steps ...string) []string {
	t.Helper()
	typ := unix.SOCK_STREAM | unix.SOCK_CLOEXEC
	if nonblock {
		typ |= unix.SOCK_NONBLOCK
	}
	fd, err := unix.Socket(unix.AF_INET, typ, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closed(t, "the native socket", unix.Close(fd)) }()
	var got []string
	for _, step := range steps {
		switch step {
		case "connect":
			got = append(got, errName(rawSockaddrCall(unix.SYS_CONNECT, fd, brkSockaddr(dest))))
		case "soerror":
			if _, err := pollFD(fd, unix.POLLOUT, brkBound); err != nil {
				t.Fatal(err)
			}
			v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, errName(errnoErr(unix.Errno(v))))
		}
	}
	return got
}

func TestBrokerConnectChecks(t *testing.T) {
	c := brkStart(t, "slice")
	lnA, a := brkListen(t)
	lnB, other := brkListen(t)
	refused := brkFreePort(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{a: true, refused: true}}
	brkStartBroker(t, c, d.decide)

	c.expect(t, "socket s inet", "0")
	c.expect(t, "connect s "+a.String(), "0")
	c.expect(t, "socket t inet", "0")
	c.expect(t, "connect t "+a.String()+" other", "0")
	if n := brkAccepts(t, lnA, 500*time.Millisecond); n != 2 {
		t.Errorf("admitted endpoint accepted %d connections, want 2", n)
	}
	c.expect(t, "socket u inet", "0")
	c.expect(t, "connect u "+other.String(), "EPERM")
	if n := brkAccepts(t, lnB, 200*time.Millisecond); n != 0 {
		t.Errorf("denied endpoint accepted %d connections", n)
	}
	want := []netip.AddrPort{a, a, other}
	d.mu.Lock()
	seen := append([]netip.AddrPort(nil), d.seen...)
	d.mu.Unlock()
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] || seen[2] != want[2] {
		t.Errorf("decider saw %v, want %v", seen, want)
	}

	short := brkSockaddr(a)[:8]
	unsupported := brkSockaddr(a)
	binary.NativeEndian.PutUint16(unsupported, unix.AF_APPLETALK)
	before := d.count()
	c.expect(t, "socket v inet", "0")
	c.expect(t, "pair p", "0")
	for _, cmd := range []string{
		"separate " + a.String(),
		"badptr v",
		"edge v " + a.String(),
		"badfd " + a.String(),
		"raw v " + hex.EncodeToString(brkSockaddr(a)[:1]),
		"raw v " + hex.EncodeToString(brkSockaddr(a)[:3]),
		"raw v " + hex.EncodeToString(short),
		"raw v " + hex.EncodeToString(append(brkSockaddr(a), make([]byte, 113)...)),
		"raw v " + hex.EncodeToString(unsupported),
		"connect p " + a.String(),
		"connect udp " + a.String(),
		"connect xfrm " + a.String(),
	} {
		c.expect(t, cmd, "EPERM")
	}
	if n := d.count() - before; n != 0 {
		t.Errorf("decider called %d times for calls that fail before it", n)
	}
	if n := brkAccepts(t, lnA, 200*time.Millisecond); n != 0 {
		t.Errorf("admitted endpoint accepted %d connections from failed calls", n)
	}
	c.expect(t, "bind v", "EPERM")
	c.expect(t, "listen v", "EPERM")

	c.expect(t, "socket r inet", "0")
	if got, want := c.do(t, "connect r "+refused.String()), brkNative(t, false, refused, "connect")[0]; got != want {
		t.Errorf("blocking connect to a closed port: got %s, want the kernel's %s", got, want)
	}
	c.expect(t, "socket n inet nonblock", "0")
	steps := []string{"connect", "soerror", "connect", "connect"}
	want2 := brkNative(t, true, a, steps...)
	var got2 []string
	for _, step := range steps {
		cmd := "connect n " + a.String()
		if step == "soerror" {
			cmd = "soerror n"
		}
		got2 = append(got2, c.do(t, cmd))
	}
	if strings.Join(got2, " ") != strings.Join(want2, " ") {
		t.Errorf("non-blocking connect sequence: got %v, want the kernel's %v", got2, want2)
	}

	if c.do(t, "socket six inet6") != "0" {
		t.Log("IPv6 sockets unavailable; mapped-address check skipped")
		return
	}
	mapped := netip.AddrPortFrom(netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}), a.Port())
	before = d.count()
	c.expect(t, "connect six "+mapped.String(), "0")
	c.expect(t, "peer six", mapped.String())
	d.mu.Lock()
	if len(d.seen) != before+1 || d.seen[before] != a {
		t.Errorf("decider saw %v for the mapped address, want %v", d.seen[before:], a)
	}
	d.mu.Unlock()
}

func TestBrokerFullModeBindListenAndOwnListener(t *testing.T) {
	c := brkStart(t, "full")
	lnB, other := brkListen(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{}}
	b := brkStartBroker(t, c, d.decide)

	c.expect(t, "socket u unix", "0")
	c.expect(t, "connect u "+other.String(), "EPERM")
	c.expect(t, "socket x inet", "0")
	for _, addr := range []string{"0.0.0.0:0", "127.0.0.2:0", "192.0.2.1:0"} {
		c.expect(t, "bind x "+addr, "EPERM")
	}
	c.expect(t, "listen x", "EPERM")
	c.expect(t, "local x", "0.0.0.0:0")

	c.expect(t, "socket s inet", "0")
	c.expect(t, "bind s 127.0.0.1:0", "0")
	own := netip.MustParseAddrPort(c.do(t, "local s"))
	if own.Port() == 0 {
		t.Fatalf("the port-0 bind left local endpoint %v", own)
	}
	b.mu.Lock()
	recorded := b.own[own]
	b.mu.Unlock()
	if !recorded {
		t.Errorf("the kernel-picked endpoint %v was not recorded", own)
	}
	c.expect(t, "listen s", "0")
	c.expect(t, "socket c inet", "0")
	c.expect(t, "connect c "+own.String(), "0")
	c.expect(t, "peer c", own.String())
	c.expect(t, "socket o inet", "0")
	c.expect(t, "connect o "+other.String(), "EPERM")
	if n := brkAccepts(t, lnB, 200*time.Millisecond); n != 0 {
		t.Errorf("another loopback port accepted %d connections", n)
	}
	d.mu.Lock()
	seen := slices.Clone(d.seen)
	d.mu.Unlock()
	if len(seen) != 1 || seen[0] != other {
		t.Errorf("decider saw %v, want only %v", seen, other)
	}

	if c.do(t, "socket six inet6") != "0" {
		t.Log("IPv6 sockets unavailable; IPv6 checks skipped")
		return
	}
	mapped := netip.AddrPortFrom(netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}), own.Port())
	c.expect(t, "connect six "+mapped.String(), "0")
	c.expect(t, "socket v6 inet6", "0")
	c.expect(t, "connect v6 "+netip.AddrPortFrom(netip.IPv6Loopback(), own.Port()).String(), "EPERM")
	c.expect(t, "socket any6 inet6", "0")
	c.expect(t, "bind any6 [::]:0", "EPERM")
	c.expect(t, "socket m inet6", "0")
	c.expect(t, "bind m "+netip.AddrPortFrom(mapped.Addr(), 0).String(), "0")
	c.expect(t, "socket l6 inet6", "0")
	if got := c.do(t, "bind l6 [::1]:0"); got != "0" && got != "EADDRNOTAVAIL" {
		t.Errorf("bind to ::1: got %s, want 0 or the kernel's EADDRNOTAVAIL", got)
	}
}

func TestBrokerFullModeRecordsTheEndpointListenAllocates(t *testing.T) {
	c := brkStart(t, "full")
	lnB, other := brkListen(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{}}
	brkStartBroker(t, c, d.decide)

	c.expect(t, "socket s inet", "0")
	c.expect(t, "noport s", "0")
	c.expect(t, "bind s 127.0.0.1:0", "0")
	c.expect(t, "local s", "127.0.0.1:0")
	c.expect(t, "listen s", "0")
	own := netip.MustParseAddrPort(c.do(t, "local s"))
	if own.Port() == 0 {
		t.Fatalf("listen left local endpoint %v", own)
	}
	c.expect(t, "socket c inet", "0")
	c.expect(t, "connect c "+own.String(), "0")
	c.expect(t, "peer c", own.String())
	c.expect(t, "socket o inet", "0")
	c.expect(t, "connect o "+other.String(), "EPERM")
	if n := brkAccepts(t, lnB, 200*time.Millisecond); n != 0 {
		t.Errorf("another loopback port accepted %d connections", n)
	}
}

func TestBrokerFullModeBindTakesTheShortIPv6Sockaddr(t *testing.T) {
	c := brkStart(t, "full")
	brkStartBroker(t, c, (&brkDecisions{allow: map[netip.AddrPort]bool{}}).decide)
	if c.do(t, "socket six inet6") != "0" {
		t.Skip("IPv6 sockets unavailable")
	}
	short := hex.EncodeToString(brkSockaddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0))[:24])
	c.expect(t, "socket cut inet6", "0")
	c.expect(t, "raw cut "+short[:46]+" bind", "EPERM")
	got := c.do(t, "raw six "+short+" bind")
	if got == "EADDRNOTAVAIL" {
		t.Skip("::1 is not configured")
	}
	if got != "0" {
		t.Fatalf("24-byte bind to [::1]:0: got %s, want 0", got)
	}
	if local := netip.MustParseAddrPort(c.do(t, "local six")); local.Addr() != netip.IPv6Loopback() || local.Port() == 0 {
		t.Errorf("24-byte bind left local endpoint %v", local)
	}
}

func TestBrokerNilDeciderDenies(t *testing.T) {
	c := brkStart(t, "slice")
	ln, a := brkListen(t)
	b := brkStartBroker(t, c, nil)
	c.expect(t, "socket s inet", "0")
	c.expect(t, "connect s "+a.String(), "EPERM")
	if n := brkAccepts(t, ln, 200*time.Millisecond); n != 0 {
		t.Errorf("accepted %d connections", n)
	}
	brkStop(t, b, brkBound)
	want := []Refusal{{Host: "127.0.0.1", Port: strconv.Itoa(int(a.Port())), Reason: "direct connection not allowed (use the proxy)"}}
	if got := b.Refusals(); !slices.Equal(got, want) {
		t.Errorf("refusals %+v, want %+v", got, want)
	}
}

func TestBrokerRecordsRefusals(t *testing.T) {
	c := brkStart(t, "slice")
	_, a := brkListen(t)
	_, other := brkListen(t)
	closedPort := brkFreePort(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{a: true, closedPort: true}}
	b := brkStartBroker(t, c, d.decide)

	c.expect(t, "socket s inet", "0")
	c.expect(t, "connect s "+a.String(), "0")
	c.expect(t, "socket r inet", "0")
	if got := c.do(t, "connect r "+closedPort.String()); got == "0" || got == "EPERM" {
		t.Fatalf("fixture: connect to a closed port returned %s, want a kernel connect error", got)
	}
	c.expect(t, "socket u inet", "0")
	c.expect(t, "connect u "+other.String(), "EPERM")
	want := []Refusal{{Host: "127.0.0.1", Port: strconv.Itoa(int(other.Port())), Reason: "direct connection not allowed (use the proxy)"}}

	unsupported := brkSockaddr(a)
	binary.NativeEndian.PutUint16(unsupported, unix.AF_APPLETALK)
	c.expect(t, "socket v inet", "0")
	c.expect(t, "pair p", "0")
	for _, tc := range []struct{ cmd, reason string }{
		{"connect p " + a.String(), "not a TCP connect"},
		{"connect udp " + a.String(), "not a TCP connect"},
		{"raw v " + hex.EncodeToString(brkSockaddr(a)[:1]), "not a TCP connect"},
		{"raw v " + hex.EncodeToString(append(brkSockaddr(a), make([]byte, 113)...)), "not a TCP connect"},
		{"raw v " + hex.EncodeToString(brkSockaddr(a)[:3]), "not a TCP connect"},
		{"raw v " + hex.EncodeToString(brkSockaddr(a)[:8]), "not a TCP connect"},
		{"raw v " + hex.EncodeToString(unsupported), "not a TCP connect"},
		{"badptr v", "connect not inspectable"},
		{"edge v " + a.String(), "connect not inspectable"},
		{"badfd " + a.String(), "connect not inspectable"},
		{"separate " + a.String(), "connect not inspectable"},
	} {
		c.expect(t, tc.cmd, "EPERM")
		want = append(want, Refusal{Reason: tc.reason})
	}

	brkStop(t, b, brkBound)
	got := b.Refusals()
	if !slices.Equal(got, want) {
		t.Fatalf("refusals:\n got %+v\nwant %+v", got, want)
	}
	got[0].Host = "changed"
	if again := b.Refusals(); !slices.Equal(again, want) {
		t.Errorf("a second read after changing the first copy: %+v, want %+v", again, want)
	}
}

func TestBrokerStopBeforeDenialResponseRecordsNothing(t *testing.T) {
	c := brkStart(t, "slice")
	_, a := brkListen(t)
	entered, release := make(chan struct{}), make(chan struct{})
	b := brkStartBroker(t, c, func(netip.AddrPort) bool {
		close(entered)
		<-release
		return false
	})
	c.expect(t, "socket s inet", "0")
	res := c.start(t, "connect s "+a.String())
	select {
	case <-entered:
	case <-time.After(brkBound):
		c.fatalf(t, "decider never asked")
	}
	stopped := make(chan struct{})
	go func() { b.Stop(); close(stopped) }()
	select {
	case <-b.stopping:
	case <-time.After(brkBound):
		c.fatalf(t, "Stop never began")
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(brkBound):
		c.fatalf(t, "Stop did not return")
	}
	if got := c.await(t, res, "connect"); got != "EPERM" {
		t.Errorf("connect denied during stop: got %s, want EPERM", got)
	}
	if got := b.Refusals(); len(got) != 0 {
		t.Errorf("a denial answered after Stop began was recorded: %+v", got)
	}
}

func TestBrokerFailedDenialResponseRecordsNothing(t *testing.T) {
	c := brkStart(t, "slice")
	listener := c.take()
	t.Cleanup(func() { closed(t, "the listener", listener.Close()) })
	_, a := brkListen(t)
	b := newBroker(int(listener.Fd()), (&brkDecisions{}).decide)
	pidfdGetfd = func(pidfd, fd, flags int) (int, error) {
		sock, err := unix.PidfdGetfd(pidfd, fd, flags)
		_ = c.cmd.Process.Kill()
		<-c.done
		return sock, err
	}
	t.Cleanup(func() { pidfdGetfd = unix.PidfdGetfd })
	c.expect(t, "socket s inet", "0")
	c.start(t, "connect s "+a.String())
	if revents, err := pollFD(b.fd, unix.POLLIN, brkBound); err != nil || revents&unix.POLLIN == 0 {
		c.fatalf(t, "no notification (revents %#x): %v", revents, err)
	}
	n, err := recvNotification(b.fd)
	if err != nil {
		c.fatalf(t, "recvNotification: %v", err)
	}
	b.handle(n)
	if got := b.Refusals(); len(got) != 0 {
		t.Errorf("a denial whose caller exited before the response was recorded: %+v", got)
	}
}

func TestBrokerFailedLookupAndStaleNotification(t *testing.T) {
	c := brkStart(t, "slice")
	listener := c.take()
	t.Cleanup(func() { closed(t, "the listener", listener.Close()) })
	_, a := brkListen(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{a: true}}
	b := newBroker(int(listener.Fd()), d.decide)
	c.expect(t, "socket s inet", "0")
	res := c.start(t, "connect s "+a.String())
	if revents, err := pollFD(b.fd, unix.POLLIN, brkBound); err != nil || revents&unix.POLLIN == 0 {
		c.fatalf(t, "no notification (revents %#x): %v", revents, err)
	}
	n, err := recvNotification(b.fd)
	if err != nil {
		c.fatalf(t, "recvNotification: %v", err)
	}
	unbound := n
	unbound.Nr = unix.SYS_LISTEN
	if _, why, _, ok := b.answer(unbound); !ok || why == nil || *why != (Refusal{Reason: "listen not allowed (bind to 127.0.0.1 or ::1 first)"}) {
		t.Errorf("a listen on an unbound socket: refusal %+v sent=%v, want a listen refusal with no destination", why, ok)
	}
	forged := n
	forged.Pid = 1 << 30
	resp, why, _, ok := b.answer(forged)
	if !ok || resp.ID != n.ID || resp.Error != -int32(unix.EPERM) || d.count() != 0 {
		t.Errorf("failed lookup: answer %+v sent=%v after %d decisions, want EPERM sent without deciding", resp, ok, d.count())
	}
	if why == nil || *why != (Refusal{Reason: "connect not inspectable"}) {
		t.Errorf("failed lookup: refusal %+v, want an uninspectable connect with no destination", why)
	}
	if err := sendNotificationResponse(b.fd, resp); err != nil {
		c.fatalf(t, "send: %v", err)
	}
	if got := c.await(t, res, "connect"); got != "EPERM" {
		t.Errorf("connect: got %s, want EPERM", got)
	}
	if resp, why, _, ok := b.answer(n); ok || why != nil {
		t.Errorf("stale notification answered with %+v and refusal %+v, want it dropped", resp, why)
	}
}

func TestBrokerUsesSnapshotAndRetainedSocket(t *testing.T) {
	c := brkStart(t, "slice")
	lnA, a := brkListen(t)
	lnB, other := brkListen(t)
	asked := make(chan netip.AddrPort, 1)
	proceed := make(chan struct{})
	brkStartBroker(t, c, func(dest netip.AddrPort) bool {
		asked <- dest
		<-proceed
		return dest == a
	})
	c.expect(t, "socket s inet", "0")
	res := c.start(t, "connect s "+a.String())
	select {
	case got := <-asked:
		if got != a {
			t.Errorf("decider asked about %v, want %v", got, a)
		}
	case <-time.After(brkBound):
		c.fatalf(t, "decider never asked")
	}
	c.expect(t, "rewrite s "+other.String(), "0")
	c.expect(t, "reuse s", "0")
	close(proceed)
	if got := c.await(t, res, "connect"); got != "0" {
		t.Errorf("connect: got %s, want 0", got)
	}
	if n := brkAccepts(t, lnA, 500*time.Millisecond); n != 1 {
		t.Errorf("checked endpoint accepted %d connections, want 1", n)
	}
	if n := brkAccepts(t, lnB, 200*time.Millisecond); n != 0 {
		t.Errorf("rewritten endpoint accepted %d connections", n)
	}
	c.expect(t, "peer s", "ENOTCONN")
}

func TestBrokerDeniesCopyFromSplitTable(t *testing.T) {
	c := brkStart(t, "slice")
	ln, a := brkListen(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{a: true}}
	paused, resume := make(chan struct{}), make(chan struct{})
	pidfdGetfd = func(pidfd, fd, flags int) (int, error) {
		close(paused)
		<-resume
		return unix.PidfdGetfd(pidfd, fd, flags)
	}
	t.Cleanup(func() { pidfdGetfd = unix.PidfdGetfd })
	brkStartBroker(t, c, d.decide)
	release := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(release)
	c.expect(t, "socket s inet", "0")
	res := c.start(t, "connect s "+a.String()+" other")
	select {
	case <-paused:
	case <-time.After(brkBound):
		c.fatalf(t, "the broker never reached the copy")
	}
	switch got := c.do(t, "split s"); got {
	case "0":
	case "unverified":
		t.Skip("unverified: the child's control loop is not on the thread-group leader")
	default:
		c.fatalf(t, "split: %s", got)
	}
	release()
	if got := c.await(t, res, "connect"); got != "EPERM" {
		t.Errorf("connect after the leader split its table: got %s, want EPERM", got)
	}
	if n := d.count(); n != 0 {
		t.Errorf("decider called %d times for a copy from the split table", n)
	}
	if n := brkAccepts(t, ln, 300*time.Millisecond); n != 0 {
		t.Errorf("endpoint accepted %d connections", n)
	}
	c.expect(t, "peer s", "ENOTCONN")
}

func TestBrokerCoordinatesBySocket(t *testing.T) {
	c := brkStart(t, "slice")
	full, drain := brkFullListener(t)
	_, a := brkListen(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{a: true, full: true}}
	b := brkStartBroker(t, c, d.decide)
	c.expect(t, "socket s inet", "0")
	c.expect(t, "dup s s2", "0")
	c.expect(t, "socket u inet", "0")
	first := c.start(t, "connect s "+full.String())
	c.until(t, "the first connect to start", func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.connecting) == 1 })
	second := c.start(t, "connect s2 "+full.String())
	third := c.start(t, "spawn s "+full.String())
	c.until(t, "three handlers on one socket", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, rec := range b.sockets {
			if rec.users == 3 {
				return true
			}
		}
		return false
	})
	c.expect(t, "connect u "+a.String(), "0")
	if !c.silent(first, 0) || !c.silent(second, 0) || !c.silent(third, 0) {
		t.Fatal("a connect on the blocked socket returned before the queue drained")
	}
	drain()
	for _, r := range []struct {
		ch   <-chan string
		what string
		want string
	}{{first, "first connect", "0"}, {second, "duplicated descriptor", "EISCONN"}, {third, "other process", "EISCONN"}} {
		if got := c.await(t, r.ch, r.what); got != r.want {
			t.Errorf("%s: got %s, want %s", r.what, got, r.want)
		}
	}
}

func TestBrokerStopIdle(t *testing.T) {
	for _, mode := range []string{"slice", "full"} {
		t.Run(mode, func(t *testing.T) {
			c := brkStart(t, mode)
			_, a := brkListen(t)
			b := brkStartBroker(t, c, func(netip.AddrPort) bool { return true })
			before := notifyListeners(t, "self")
			brkStop(t, b, 2*time.Second)
			if got := notifyListeners(t, "self"); got != before-1 {
				t.Errorf("listener descriptors %d after stop, want %d", got, before-1)
			}
			brkStop(t, b, time.Second)
			filtered := map[string]string{"slice": "EPERM", "full": "ENOSYS"}[mode]
			c.expect(t, "socket s inet", "0")
			c.expect(t, "connect s "+a.String(), "ENOSYS")
			c.expect(t, "bind s", filtered)
			c.expect(t, "listen s", filtered)
		})
	}
}

func TestBrokerStopsWhenCommandExits(t *testing.T) {
	c := brkStart(t, "slice")
	b := brkStartBroker(t, c, nil)
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.stopping:
	case <-time.After(brkBound):
		t.Fatal("broker kept running after the listener hung up")
	}
}

func TestBrokerStopCancelsBlockedConnect(t *testing.T) {
	c := brkStart(t, "slice")
	full, _ := brkFullListener(t)
	pidfds := brkLinks(t, "self", "anon_inode:[pidfd]")
	d := &brkDecisions{allow: map[netip.AddrPort]bool{full: true}}
	b := brkStartBroker(t, c, d.decide)
	c.expect(t, "socket s inet", "0")
	c.expect(t, "dup s s2", "0")
	sockLink, err := os.Readlink("/proc/" + strconv.Itoa(c.cmd.Process.Pid) + "/fd/" + c.do(t, "fdnum s"))
	if err != nil {
		t.Fatal(err)
	}
	first := c.start(t, "connect s "+full.String())
	c.until(t, "the connect to block", func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.connecting) == 1 })
	second := c.start(t, "connect s2 "+full.String())
	c.until(t, "a second handler waiting on the socket", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, rec := range b.sockets {
			if rec.users == 2 {
				return true
			}
		}
		return false
	})
	if brkLinks(t, "self", sockLink) == 0 {
		t.Fatal("fixture: the broker holds no copy of the socket while connecting")
	}
	listeners := notifyListeners(t, "self")
	brkStop(t, b, 3*time.Second)
	if got := c.await(t, first, "blocked connect"); got == "0" {
		t.Errorf("blocked connect succeeded across stop")
	}
	if got := c.await(t, second, "waiting connect"); got != "EPERM" {
		t.Errorf("waiting connect: got %s, want EPERM", got)
	}
	if n := brkLinks(t, "self", sockLink); n != 0 {
		t.Errorf("broker still holds %d copies of the socket", n)
	}
	if n := brkLinks(t, "self", "anon_inode:[pidfd]"); n != pidfds {
		t.Errorf("%d pidfds after stop, want %d", n, pidfds)
	}
	if n := notifyListeners(t, "self"); n != listeners-1 {
		t.Errorf("listener descriptors %d after stop, want %d", n, listeners-1)
	}
	if len(b.connecting) != 0 || len(b.sockets) != 0 {
		t.Errorf("records left after stop: %d connecting, %d sockets", len(b.connecting), len(b.sockets))
	}
	c.expect(t, "peer s", "ENOTCONN")
}

func TestBrokerStopDuringDecision(t *testing.T) {
	c := brkStart(t, "full")
	ln, a := brkListen(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	b := brkStartBroker(t, c, func(netip.AddrPort) bool {
		once.Do(func() { close(entered) })
		<-release
		return true
	})
	c.expect(t, "socket s inet", "0")
	c.expect(t, "socket u inet", "0")
	first := c.start(t, "connect s "+a.String())
	select {
	case <-entered:
	case <-time.After(brkBound):
		c.fatalf(t, "decider never asked")
	}
	stopped := make(chan struct{})
	go func() { b.Stop(); close(stopped) }()
	select {
	case <-b.loopDone:
	case <-time.After(brkBound):
		c.fatalf(t, "receive loop did not stop")
	}
	second := c.start(t, "connect u "+a.String())
	if !c.silent(second, 300*time.Millisecond) {
		t.Fatal("a call made after the receive loop stopped returned before the listener closed")
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(brkBound):
		c.fatalf(t, "Stop did not return")
	}
	if got := c.await(t, first, "connect during stop"); got != "EPERM" {
		t.Errorf("connect decided during stop: got %s, want EPERM", got)
	}
	if got := c.await(t, second, "paused connect"); got != "ENOSYS" {
		t.Errorf("connect paused at listener close: got %s, want ENOSYS", got)
	}
	if n := brkAccepts(t, ln, 200*time.Millisecond); n != 0 {
		t.Errorf("accepted %d connections", n)
	}
	c.expect(t, "connect s "+a.String(), "ENOSYS")
	c.expect(t, "bind s", "ENOSYS")
	c.expect(t, "listen s", "ENOSYS")
	if got := b.Refusals(); len(got) != 0 {
		t.Errorf("an admitted connect denied by stop was recorded: %+v", got)
	}
}

type brkRegistry struct {
	entered chan netip.AddrPort
	release chan struct{}
	fail    error

	mu  sync.Mutex
	got []netip.AddrPort
}

func (r *brkRegistry) register(local netip.AddrPort) error {
	if r.entered != nil {
		r.entered <- local
		<-r.release
	}
	if r.fail != nil {
		return r.fail
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, local)
	return nil
}

func (r *brkRegistry) published() []netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]netip.AddrPort(nil), r.got...)
}

func brkStartRegistering(t *testing.T, c *brkChild, decide ConnectDecider, r *brkRegistry) *Broker {
	t.Helper()
	b, err := StartRegisteringBroker(c.take(), decide, r.register)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	return b
}

func brkUnmapped(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("child endpoint %q: %v", s, err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func TestBrokerRegistersBeforeWakingTheChild(t *testing.T) {
	c := brkStart(t, "slice")
	_, a := brkListen(t)
	r := &brkRegistry{entered: make(chan netip.AddrPort, 1), release: make(chan struct{})}
	brkStartRegistering(t, c, (&brkDecisions{allow: map[netip.AddrPort]bool{a: true}}).decide, r)
	c.expect(t, "socket s inet", "0")
	res := c.start(t, "connect s "+a.String())
	var local netip.AddrPort
	select {
	case local = <-r.entered:
	case <-time.After(brkBound):
		c.fatalf(t, "the broker never registered the connection")
	}
	if !c.silent(res, 300*time.Millisecond) {
		t.Fatal("the child was woken before the registration callback returned")
	}
	close(r.release)
	if got := c.await(t, res, "connect"); got != "0" {
		t.Errorf("connect: got %s, want 0", got)
	}
	if got := brkUnmapped(t, c.do(t, "local s")); got != local {
		t.Errorf("registered %v, want the socket's local endpoint %v", local, got)
	}
}

func TestBrokerRegistrationFailureDenies(t *testing.T) {
	c := brkStart(t, "slice")
	_, a := brkListen(t)
	r := &brkRegistry{fail: errors.New("refused")}
	b := brkStartRegistering(t, c, (&brkDecisions{allow: map[netip.AddrPort]bool{a: true}}).decide, r)
	c.expect(t, "socket s inet", "0")
	c.expect(t, "connect s "+a.String(), "EPERM")
	if got := r.published(); len(got) != 0 {
		t.Errorf("published %v after a failed registration", got)
	}
	brkStop(t, b, brkBound)
	if got := b.Refusals(); len(got) != 0 {
		t.Errorf("an admitted connect whose registration failed was recorded: %+v", got)
	}
}

func TestBrokerRegistersNonblockingConnectBeforeTheHandshake(t *testing.T) {
	c := brkStart(t, "slice")
	full, _ := brkFullListener(t)
	r := &brkRegistry{}
	brkStartRegistering(t, c, (&brkDecisions{allow: map[netip.AddrPort]bool{full: true}}).decide, r)
	c.expect(t, "socket n inet nonblock", "0")
	c.expect(t, "connect n "+full.String(), "EINPROGRESS")
	got := r.published()
	if want := brkUnmapped(t, c.do(t, "local n")); len(got) != 1 || got[0] != want {
		t.Errorf("published %v, want exactly the connecting socket's %v", got, want)
	}
}

func TestBrokerRegistersMappedEndpointsUnmapped(t *testing.T) {
	c := brkStart(t, "slice")
	_, a := brkListen(t)
	r := &brkRegistry{}
	brkStartRegistering(t, c, (&brkDecisions{allow: map[netip.AddrPort]bool{a: true}}).decide, r)
	if c.do(t, "socket six inet6") != "0" {
		t.Skip("unverified: IPv6 sockets unavailable")
	}
	mapped := netip.AddrPortFrom(netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}), a.Port())
	c.expect(t, "connect six "+mapped.String(), "0")
	raw := netip.MustParseAddrPort(c.do(t, "local six"))
	got := r.published()
	if !raw.Addr().Is4In6() || len(got) != 1 || got[0] != netip.AddrPortFrom(netip.AddrFrom4(raw.Addr().As4()), raw.Port()) {
		t.Errorf("published %v for the mapped local endpoint %v, want its IPv4 form", got, raw)
	}
}

func TestBrokerRepeatedConnectsOnOneSocketRegisterOnce(t *testing.T) {
	c := brkStart(t, "slice")
	_, a := brkListen(t)
	refused := brkFreePort(t)
	r := &brkRegistry{}
	brkStartRegistering(t, c, (&brkDecisions{allow: map[netip.AddrPort]bool{a: true, refused: true}}).decide, r)
	c.expect(t, "socket n inet nonblock", "0")
	if got := c.do(t, "connect n "+refused.String()); got != "EINPROGRESS" {
		t.Skipf("unverified: a non-blocking loopback connect to a closed port returned %s, not EINPROGRESS", got)
	}
	c.expect(t, "soerror n", "ECONNREFUSED")
	got := c.do(t, "connect n "+a.String())
	if got == "ECONNABORTED" {
		got = c.do(t, "connect n "+a.String())
	}
	if got != "0" && got != "EINPROGRESS" {
		t.Fatalf("reconnect after the failed attempt: got %s", got)
	}
	if published := r.published(); len(published) != 1 {
		t.Errorf("published %v, want one registration for the socket", published)
	}
}

func TestBrokerStopDuringRegistrationWaitsOnlyForTheCallback(t *testing.T) {
	c := brkStart(t, "slice")
	_, a := brkListen(t)
	r := &brkRegistry{entered: make(chan netip.AddrPort, 1), release: make(chan struct{})}
	b := brkStartRegistering(t, c, (&brkDecisions{allow: map[netip.AddrPort]bool{a: true}}).decide, r)
	c.expect(t, "socket s inet", "0")
	res := c.start(t, "connect s "+a.String())
	select {
	case <-r.entered:
	case <-time.After(brkBound):
		c.fatalf(t, "the broker never registered the connection")
	}
	stopped := make(chan struct{})
	go func() { b.Stop(); close(stopped) }()
	select {
	case <-b.loopDone:
	case <-time.After(brkBound):
		c.fatalf(t, "receive loop did not stop")
	}
	close(r.release)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		c.fatalf(t, "Stop did not return after the callback returned, with the connection never accepted")
	}
	if got := c.await(t, res, "connect"); got != "0" {
		t.Errorf("connect registered during stop: got %s, want 0", got)
	}
}

func brkUnixAddr(path string) string {
	return hex.EncodeToString(unixDestAddr(unix.AF_UNIX, path))
}

func brkRealDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func brkHeld(t *testing.T, path string) int {
	t.Helper()
	fd, _, err := resolveUnixDest(uint32(os.Getpid()), unixDestAddr(unix.AF_UNIX, path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func TestBrokerConnectModeDecidesInRuleSixOrder(t *testing.T) {
	c := brkStart(t, "connect")
	dir := brkRealDir(t)
	granted, ungranted, denied := filepath.Join(dir, "granted.sock"), filepath.Join(dir, "other.sock"), filepath.Join(dir, "denied.sock")
	grantedLn, otherLn, deniedLn := unixDestListen(t, granted), unixDestListen(t, ungranted), unixDestListen(t, denied)
	grantedTCPLn, grantedTCP := brkListen(t)
	proxyLn, proxy := brkListen(t)
	_, otherTCP := brkListen(t)
	deny := newDenyList([]string{denied}, nil)
	t.Cleanup(deny.Close)
	r := &brkRegistry{}
	b, err := StartConnectBroker(c.take(), ConnectRules{
		Grants:     []string{granted, denied, grantedTCP.String()},
		Deny:       deny,
		Proxy:      (&brkDecisions{allow: map[netip.AddrPort]bool{proxy: true}}).decide,
		WriteRoots: []string{filepath.Join(dir, "work")},
		TmpDir:     filepath.Join(dir, "tmp"),
	}, r.register)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)

	for _, tc := range []struct{ name, family, addr, cmd, want string }{
		{"g", "unix", brkUnixAddr(granted), "raw", "0"},
		{"o", "unix", brkUnixAddr(ungranted), "raw", "EPERM"},
		{"d", "unix", brkUnixAddr(denied), "raw", "EPERM"},
		{"a", "unix", brkUnixAddr("\x00codemeld-test"), "raw", "EPERM"},
		{"t", "inet", grantedTCP.String(), "connect", "0"},
		{"p", "inet", proxy.String(), "connect", "0"},
		{"u", "inet", otherTCP.String(), "connect", "EPERM"},
	} {
		c.expect(t, "socket "+tc.name+" "+tc.family, "0")
		c.expect(t, tc.cmd+" "+tc.name+" "+tc.addr, tc.want)
	}
	if !unixDestAccepted(t, grantedLn, brkBound) {
		t.Error("the granted socket accepted no connection")
	}
	if unixDestAccepted(t, otherLn, 200*time.Millisecond) || unixDestAccepted(t, deniedLn, 200*time.Millisecond) {
		t.Error("a refused Unix socket accepted a connection")
	}
	if n := brkAccepts(t, grantedTCPLn, 200*time.Millisecond) + brkAccepts(t, proxyLn, 200*time.Millisecond); n != 2 {
		t.Errorf("the granted and proxy endpoints accepted %d connections, want 2", n)
	}
	brkStop(t, b, brkBound)
	want := []Refusal{
		{Path: ungranted, Reason: "Unix socket connect not granted"},
		{Path: denied, Reason: "always denied: " + denied},
		{Path: "@codemeld-test", Reason: "always denied: abstract Unix address"},
		{Host: "127.0.0.1", Port: strconv.Itoa(int(otherTCP.Port())), Reason: "direct connection not allowed (use the proxy)"},
	}
	if got := b.Refusals(); !slices.Equal(got, want) {
		t.Errorf("refusals:\n got %+v\nwant %+v", got, want)
	}
	if got := r.published(); len(got) != 2 {
		t.Errorf("published %v, want only the two TCP connections", got)
	}
}

func TestStartConnectBrokerRequiresADenyList(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wr.Close() }()
	if b, err := StartConnectBroker(rd, ConnectRules{}, nil); err == nil {
		b.Stop()
		t.Fatal("started with no deny list")
	}
}

func TestConnectRulesPathGrantMatchesTheHeldFile(t *testing.T) {
	dir := brkRealDir(t)
	a, b := filepath.Join(dir, "a.sock"), filepath.Join(dir, "b.sock")
	lnA, lnB := unixDestListen(t, a), unixDestListen(t, b)
	grant := filepath.Join(dir, "grant")
	if err := os.Symlink(a, grant); err != nil {
		t.Fatal(err)
	}
	deny := newDenyList(nil, nil)
	rules := &ConnectRules{Grants: []string{grant}, Deny: deny}
	held := brkHeld(t, a)
	if ok, why := rules.decideUnix(held); !ok {
		t.Fatalf("a destination that is the grant's file: refused (%s)", why)
	}
	next := filepath.Join(dir, "grant.next")
	if err := os.Symlink(b, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, grant); err != nil {
		t.Fatal(err)
	}
	unixDestDial(t, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(held)})
	if !unixDestAccepted(t, lnA, brkBound) || unixDestAccepted(t, lnB, 200*time.Millisecond) {
		t.Error("replacing the grant path after the check redirected the connect")
	}
	if ok, _ := rules.decideUnix(held); ok {
		t.Error("the grant, now leading to another socket, still admits the held destination")
	}
	if ok, why := rules.decideUnix(brkHeld(t, b)); !ok {
		t.Errorf("a replacement present before the check: refused (%s)", why)
	}
}

func TestConnectRulesPathGrantPastTheSocketDoesNotAdmit(t *testing.T) {
	dir := brkRealDir(t)
	sock := filepath.Join(dir, "s.sock")
	unixDestListen(t, sock)
	held := brkHeld(t, sock)
	deny := newDenyList(nil, nil)
	if ok, why := (&ConnectRules{Grants: []string{sock}, Deny: deny}).decideUnix(held); !ok {
		t.Fatalf("the socket's own path: refused (%s)", why)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	dotLink := filepath.Join(dir, "dot-link")
	if err := os.Symlink("s.sock/.", dotLink); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{sock + "/", sock + "/.", sock + "/..", link + "/", link + "/..", dotLink} {
		if ok, _ := (&ConnectRules{Grants: []string{grant}, Deny: deny}).decideUnix(held); ok {
			t.Errorf("grant %s admitted the socket", grant)
		}
	}
}

func TestConnectRulesPathGrantThroughWriteRootOrTempFolderDoesNotAdmit(t *testing.T) {
	base := brkRealDir(t)
	work, tmp, out := filepath.Join(base, "work"), filepath.Join(base, "tmp"), filepath.Join(base, "out")
	for _, d := range []string{work, tmp, out} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, path string) string {
		t.Helper()
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	outside, inWork, inTmp := filepath.Join(out, "s.sock"), filepath.Join(work, "s.sock"), filepath.Join(tmp, "s.sock")
	for _, p := range []string{outside, inWork, inTmp} {
		unixDestListen(t, p)
	}
	workLink := link(work, filepath.Join(base, "work-link"))
	deny := newDenyList(nil, nil)
	if ok, why := (&ConnectRules{Grants: []string{outside}, Deny: deny, WriteRoots: []string{work}, TmpDir: tmp}).decideUnix(brkHeld(t, outside)); !ok {
		t.Fatalf("a grant outside every write root: refused (%s)", why)
	}
	for _, tc := range []struct {
		name, grant, dest, folder string
		roots                     []string
	}{
		{"socket in a write root", inWork, inWork, work, nil},
		{"socket in the temp folder", inTmp, inTmp, tmp, nil},
		{"symlink in a write root to a socket outside", link(outside, filepath.Join(work, "to-out")), outside, work, nil},
		{"symlink in the temp folder to a socket outside", link(outside, filepath.Join(tmp, "to-out")), outside, tmp, nil},
		{"symlink outside into a write root", link(inWork, filepath.Join(out, "to-work")), inWork, work, nil},
		{"write root named through a symlink", inWork, inWork, work, []string{workLink}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := &ConnectRules{Grants: []string{tc.grant}, Deny: deny, WriteRoots: []string{work}, TmpDir: tmp}
			if tc.roots != nil {
				rules.WriteRoots, rules.TmpDir = tc.roots, ""
			}
			ok, why := rules.decideUnix(brkHeld(t, tc.dest))
			want := "grant " + tc.grant + " resolves through " + tc.folder + ", inside the write root or temp folder " + tc.folder
			if ok || why != want {
				t.Errorf("admitted %v, reason %q, want refused with %q", ok, why, want)
			}
		})
	}
}

func TestBrokerConnectModeAsksOnlyAfterRuleSixChecksFail(t *testing.T) {
	c := brkStart(t, "connect")
	dir := brkRealDir(t)
	sock := func(name string) (string, *net.UnixListener) {
		p := filepath.Join(dir, name)
		return p, unixDestListen(t, p)
	}
	granted, _ := sock("granted.sock")
	once, onceLn := sock("once.sock")
	refused, refusedLn := sock("refused.sock")
	silent, _ := sock("silent.sock")
	denied, _ := sock("denied.sock")
	_, proxy := brkListen(t)
	sessionLn, session := brkListen(t)
	_, refusedTCP := brkListen(t)
	_, silentTCP := brkListen(t)
	deny := newDenyList([]string{denied}, nil)
	t.Cleanup(deny.Close)
	answers := map[string][2]string{
		once:                {"prompt once", ""},
		refused:             {"", "not approved (denied)"},
		session.String():    {"prompt session", ""},
		refusedTCP.String(): {"", "not approved (denied)"},
	}
	var mu sync.Mutex
	var asked []string
	b, err := StartConnectBroker(c.take(), ConnectRules{
		Grants: []string{granted},
		Deny:   deny,
		Proxy:  (&brkDecisions{allow: map[netip.AddrPort]bool{proxy: true}}).decide,
		Ask: func(_ context.Context, _ func() bool, tcp netip.AddrPort, fd int) (string, string) {
			dest := tcp.String()
			if fd >= 0 {
				dest, _ = os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			}
			mu.Lock()
			asked = append(asked, dest)
			mu.Unlock()
			return answers[dest][0], answers[dest][1]
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)

	for _, tc := range []struct{ name, family, addr, cmd, want string }{
		{"g", "unix", brkUnixAddr(granted), "raw", "0"},
		{"o", "unix", brkUnixAddr(once), "raw", "0"},
		{"r", "unix", brkUnixAddr(refused), "raw", "EPERM"},
		{"s", "unix", brkUnixAddr(silent), "raw", "EPERM"},
		{"d", "unix", brkUnixAddr(denied), "raw", "EPERM"},
		{"p", "inet", proxy.String(), "connect", "0"},
		{"t", "inet", session.String(), "connect", "0"},
		{"u", "inet", refusedTCP.String(), "connect", "EPERM"},
		{"v", "inet", silentTCP.String(), "connect", "EPERM"},
	} {
		c.expect(t, "socket "+tc.name+" "+tc.family, "0")
		c.expect(t, tc.cmd+" "+tc.name+" "+tc.addr, tc.want)
	}
	if !unixDestAccepted(t, onceLn, brkBound) || unixDestAccepted(t, refusedLn, 200*time.Millisecond) {
		t.Error("the admitted Unix socket accepted nothing, or the refused one accepted a connection")
	}
	if n := brkAccepts(t, sessionLn, 200*time.Millisecond); n != 1 {
		t.Errorf("the admitted TCP endpoint accepted %d connections, want 1", n)
	}
	brkStop(t, b, brkBound)
	mu.Lock()
	defer mu.Unlock()
	if want := []string{once, refused, silent, session.String(), refusedTCP.String(), silentTCP.String()}; !slices.Equal(asked, want) {
		t.Errorf("asked for %q, want only the ungranted destinations %q", asked, want)
	}
	port := func(ap netip.AddrPort) string { return strconv.Itoa(int(ap.Port())) }
	want := []Refusal{
		{Path: refused, Reason: "not approved (denied)"},
		{Path: silent, Reason: "Unix socket connect not granted"},
		{Path: denied, Reason: "always denied: " + denied},
		{Host: "127.0.0.1", Port: port(refusedTCP), Reason: "not approved (denied)"},
		{Host: "127.0.0.1", Port: port(silentTCP), Reason: "direct connection not allowed (use the proxy)"},
	}
	if got := b.Refusals(); !slices.Equal(got, want) {
		t.Errorf("refusals:\n got %+v\nwant %+v", got, want)
	}
}

func TestBrokerConnectModeRecordsEachDecisionOncePerOutcome(t *testing.T) {
	c := brkStart(t, "connect")
	dir := brkRealDir(t)
	sock := func(name string) string {
		p := filepath.Join(dir, name)
		unixDestListen(t, p)
		return p
	}
	granted, once, approved, refused, silent, denied := sock("granted.sock"), sock("once.sock"), sock("approved.sock"), sock("refused.sock"), sock("silent.sock"), sock("denied.sock")
	link, missing := filepath.Join(dir, "link.sock"), filepath.Join(dir, "missing.sock")
	if err := os.Symlink(granted, link); err != nil {
		t.Fatal(err)
	}
	_, proxy := brkListen(t)
	_, grantedTCP := brkListen(t)
	_, session := brkListen(t)
	_, refusedTCP := brkListen(t)
	_, silentTCP := brkListen(t)
	_, own := brkListen(t)
	deny := newDenyList([]string{denied}, nil)
	t.Cleanup(deny.Close)
	answers := map[string][2]string{
		once:                {"prompt once", ""},
		approved:            {"session approval", ""},
		refused:             {"", "not approved (denied)"},
		session.String():    {"prompt session", ""},
		refusedTCP.String(): {"", "not approved (denied)"},
	}
	b, err := StartConnectBroker(c.take(), ConnectRules{
		Grants: []string{granted, grantedTCP.String()},
		Deny:   deny,
		Proxy:  (&brkDecisions{allow: map[netip.AddrPort]bool{proxy: true}}).decide,
		Ask: func(_ context.Context, _ func() bool, tcp netip.AddrPort, fd int) (string, string) {
			dest := tcp.String()
			if fd >= 0 {
				dest, _ = os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			}
			return answers[dest][0], answers[dest][1]
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	b.mu.Lock()
	b.own[own] = true
	b.mu.Unlock()

	for i, tc := range []struct{ family, addr, cmd, want string }{
		{"unix", brkUnixAddr(granted), "raw", "0"},
		{"unix", brkUnixAddr(link), "raw", "0"},
		{"unix", brkUnixAddr(once), "raw", "0"},
		{"unix", brkUnixAddr(approved), "raw", "0"},
		{"unix", brkUnixAddr(refused), "raw", "EPERM"},
		{"unix", brkUnixAddr(silent), "raw", "EPERM"},
		{"unix", brkUnixAddr(denied), "raw", "EPERM"},
		{"unix", brkUnixAddr("\x00codemeld-test"), "raw", "EPERM"},
		{"unix", brkUnixAddr(missing), "raw", "EPERM"},
		{"inet", proxy.String(), "connect", "0"},
		{"inet", proxy.String(), "connect", "0"},
		{"inet", grantedTCP.String(), "connect", "0"},
		{"inet", own.String(), "connect", "0"},
		{"inet", session.String(), "connect", "0"},
		{"inet", refusedTCP.String(), "connect", "EPERM"},
		{"inet", silentTCP.String(), "connect", "EPERM"},
		{"unix", hex.EncodeToString(binary.NativeEndian.AppendUint16(nil, unix.AF_UNIX)), "raw", "EPERM"},
		{"inet", "01", "raw", "EPERM"},
		{"inet", "", "badptr", "EPERM"},
	} {
		name := "s" + strconv.Itoa(i)
		c.expect(t, "socket "+name+" "+tc.family, "0")
		c.expect(t, tc.cmd+" "+name+" "+tc.addr, tc.want)
	}
	c.expect(t, "connect udp "+proxy.String(), "EPERM")
	brkStop(t, b, brkBound)
	want := []ConnectDecision{
		{Destination: granted, Allowed: true, Step: "grant", Count: 2},
		{Destination: once, Allowed: true, Step: "prompt once", Count: 1},
		{Destination: approved, Allowed: true, Step: "session approval", Count: 1},
		{Destination: refused, Reason: "not approved (denied)", Count: 1},
		{Destination: silent, Reason: "Unix socket connect not granted", Count: 1},
		{Destination: denied, Reason: "always denied: " + denied, Count: 1},
		{Destination: "@codemeld-test", Reason: "always denied: abstract Unix address", Count: 1},
		{Destination: missing, Reason: "Unix socket path not checkable", Count: 1},
		{Destination: proxy.String(), Allowed: true, Step: "proxy", Count: 2},
		{Destination: grantedTCP.String(), Allowed: true, Step: "grant", Count: 1},
		{Destination: own.String(), Allowed: true, Step: "own listener", Count: 1},
		{Destination: session.String(), Allowed: true, Step: "prompt session", Count: 1},
		{Destination: refusedTCP.String(), Reason: "not approved (denied)", Count: 1},
		{Destination: silentTCP.String(), Reason: "direct connection not allowed (use the proxy)", Count: 1},
		{Reason: "Unix socket path not checkable", Count: 1},
		{Reason: "not a TCP connect", Count: 2},
		{Reason: "connect not inspectable", Count: 1},
	}
	if got := b.Decisions(); !slices.Equal(got, want) {
		t.Errorf("decisions:\n got %+v\nwant %+v", got, want)
	}
}

func TestBrokerStopWithdrawsAPendingAsk(t *testing.T) {
	c := brkStart(t, "connect")
	_, dest := brkListen(t)
	deny := newDenyList(nil, nil)
	t.Cleanup(deny.Close)
	entered, withdrawn := make(chan struct{}), make(chan error, 1)
	b, err := StartConnectBroker(c.take(), ConnectRules{Deny: deny, Ask: func(ctx context.Context, _ func() bool, _ netip.AddrPort, _ int) (string, string) {
		close(entered)
		<-ctx.Done()
		withdrawn <- ctx.Err()
		return "", "not approved (command ended)"
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.expect(t, "socket s inet", "0")
	res := c.start(t, "connect s "+dest.String())
	select {
	case <-entered:
	case <-time.After(brkBound):
		c.fatalf(t, "the broker never asked")
	}
	brkStop(t, b, brkBound)
	if err := <-withdrawn; err == nil {
		t.Error("the pending ask's context was not cancelled")
	}
	if got := c.await(t, res, "connect"); got != "EPERM" {
		t.Errorf("withdrawn connect: got %s, want EPERM", got)
	}
	if got := b.Decisions(); len(got) != 0 {
		t.Errorf("decisions after a withdrawn ask = %+v, want none recorded while stopping", got)
	}
}

func TestBrokerWithdrawsAnAskWhenItsCallerExits(t *testing.T) {
	c := brkStart(t, "connect")
	deadLn, dead := brkListen(t)
	queuedLn, queued := brkListen(t)
	deny := newDenyList(nil, nil)
	t.Cleanup(deny.Close)
	type withdrawal struct {
		err  error
		live bool
	}
	slot, entered, withdrawn := make(chan struct{}, 1), make(chan struct{}), make(chan withdrawal, 1)
	var mu sync.Mutex
	var asked []string
	b, err := StartConnectBroker(c.take(), ConnectRules{Deny: deny, Ask: func(ctx context.Context, live func() bool, tcp netip.AddrPort, _ int) (string, string) {
		mu.Lock()
		asked = append(asked, tcp.String())
		first := len(asked) == 1
		mu.Unlock()
		select {
		case slot <- struct{}{}:
		case <-ctx.Done():
			return "", "not approved (command ended)"
		}
		defer func() { <-slot }()
		switch {
		case first:
			close(entered)
			<-ctx.Done()
			withdrawn <- withdrawal{ctx.Err(), live()}
			return "prompt session", ""
		case tcp == queued:
			return "prompt once", ""
		}
		return "", "not approved (denied)"
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)

	c.expect(t, "socket p inet", "0")
	spawned := c.start(t, "spawn p "+dead.String())
	select {
	case <-entered:
	case <-time.After(brkBound):
		c.fatalf(t, "the broker never asked for the spawned connect")
	}
	c.expect(t, "socket q inet", "0")
	waiting := c.start(t, "connect q "+queued.String())
	if !c.silent(waiting, 200*time.Millisecond) {
		t.Fatal("the queued connect finished while the first ask held the slot")
	}
	brkKillSpawned(t, c)
	select {
	case w := <-withdrawn:
		if w.err == nil || w.live {
			t.Errorf("after the caller exited: ask context error %v, live %v; want cancelled and not live", w.err, w.live)
		}
	case <-time.After(brkBound):
		c.fatalf(t, "the ask was not withdrawn after its caller exited")
	}
	c.await(t, spawned, "spawn")
	if got := c.await(t, waiting, "queued connect"); got != "0" {
		t.Errorf("queued connect: got %s, want 0", got)
	}
	if n := brkAccepts(t, queuedLn, 200*time.Millisecond); n != 1 {
		t.Errorf("the queued endpoint accepted %d connections, want 1", n)
	}
	c.expect(t, "socket r inet", "0")
	c.expect(t, "connect r "+dead.String(), "EPERM")
	if n := brkAccepts(t, deadLn, 200*time.Millisecond); n != 0 {
		t.Errorf("the withdrawn destination accepted %d connections, want 0", n)
	}
	brkStop(t, b, brkBound)
	mu.Lock()
	defer mu.Unlock()
	if want := []string{dead.String(), queued.String(), dead.String()}; !slices.Equal(asked, want) {
		t.Errorf("asked for %q, want %q (the late session answer must not admit the next connect)", asked, want)
	}
	want := []ConnectDecision{
		{Destination: queued.String(), Allowed: true, Step: "prompt once", Count: 1},
		{Destination: dead.String(), Reason: "not approved (denied)", Count: 1},
	}
	if got := b.Decisions(); !slices.Equal(got, want) {
		t.Errorf("decisions:\n got %+v\nwant %+v", got, want)
	}
}

func brkKillSpawned(t *testing.T, c *brkChild) {
	t.Helper()
	pid := c.cmd.Process.Pid
	tasks, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
	if err != nil {
		c.fatalf(t, "list the child's threads: %v", err)
	}
	killed := 0
	for _, task := range tasks {
		children, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/task/" + task.Name() + "/children")
		if err != nil {
			c.fatalf(t, "read the child's processes: %v", err)
		}
		for _, f := range strings.Fields(string(children)) {
			if p, err := strconv.Atoi(f); err == nil && unix.Kill(p, unix.SIGKILL) == nil {
				killed++
			}
		}
	}
	if killed == 0 {
		c.fatalf(t, "no spawned process to kill")
	}
}

func brkMkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func brkExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func brkFullPolicy(t *testing.T, base, root string, noWrite ...string) Policy {
	t.Helper()
	tmp := filepath.Join(base, "tmp")
	brkMkdirs(t, tmp)
	return Policy{Mode: ModeAutoEdits, Broker: BrokerFull, BlockedPaths: []string{filepath.Join(base, "blocked")}, WriteRoots: []string{root}, NoWritePaths: noWrite, TmpDir: tmp}
}

func TestBrokerFullModeUnixBindWithoutAPolicyIsRefused(t *testing.T) {
	dir := brkRealDir(t)
	c := brkStart(t, "full")
	b := brkStartBroker(t, c, (&brkDecisions{}).decide)
	c.expect(t, "chdir "+dir, "0")
	c.expect(t, "socket s unix", "0")
	c.expect(t, "raw s "+brkUnixAddr("s.sock")+" bind", "EPERM")
	brkStop(t, b, brkBound)
	want := []Refusal{{Path: "s.sock", Reason: `Unix bind failed: policy: unknown mode ""`}}
	if got := b.Refusals(); !slices.Equal(got, want) {
		t.Errorf("refusals:\n got %+v\nwant %+v", got, want)
	}
}

func TestBrokerFullModeUnixBindRunsUnderTheCommandsWriteRules(t *testing.T) {
	if abi, err := landlockABI(); err != nil || abi < 1 {
		t.Skipf("unverified: Landlock unavailable (ABI %d, %v)", abi, err)
	}
	if statusField(t, "self", "NoNewPrivs") != "0" {
		t.Skip("inconclusive: the test process already runs with no_new_privs")
	}
	base := brkRealDir(t)
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "out")
	work, locked := filepath.Join(root, "work"), filepath.Join(root, "locked")
	brkMkdirs(t, root, outside, work, locked)
	cwdBefore, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	type during struct {
		otherBind                   error
		mainNNP, threadNNP, workDir string
	}
	seen := make(chan during, 8)
	var binds atomic.Int32
	afterConfinedBind = func() {
		other := filepath.Join(outside, "other-"+strconv.Itoa(int(binds.Add(1)))+".sock")
		done := make(chan error, 1)
		go func() {
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				done <- err
				return
			}
			defer func() { _ = unix.Close(fd) }()
			done <- unix.Bind(fd, &unix.SockaddrUnix{Name: other})
		}()
		field := func(path string) string {
			data, _ := os.ReadFile(path)
			for line := range strings.Lines(string(data)) {
				if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok {
					return strings.TrimSpace(v)
				}
			}
			return "missing"
		}
		wd, _ := os.Readlink("/proc/thread-self/cwd")
		seen <- during{<-done, field("/proc/self/status"), field("/proc/thread-self/status"), wd}
	}
	t.Cleanup(func() { afterConfinedBind = func() {} })
	c := brkStart(t, "full")
	deny := newDenyList(nil, nil)
	t.Cleanup(deny.Close)
	b, err := StartConnectBroker(c.take(), ConnectRules{Deny: deny, Policy: brkFullPolicy(t, base, root, locked)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)

	var childMask, hostMask uint32 = 0o077, uint32(unix.Umask(0o022))
	unix.Umask(int(hostMask))
	if childMask == hostMask {
		childMask = 0o027
	}
	c.expect(t, "umask "+strconv.FormatUint(uint64(childMask), 8), "0")
	c.expect(t, "chdir "+work, "0")
	for _, tc := range []struct {
		name, addr, file, want string
	}{
		{"rel", "rel.sock", filepath.Join(work, "rel.sock"), "0"},
		{"abs", filepath.Join(work, "abs.sock"), filepath.Join(work, "abs.sock"), "0"},
		{"out", filepath.Join(outside, "out.sock"), filepath.Join(outside, "out.sock"), "EACCES"},
		{"nowrite", filepath.Join(locked, "x.sock"), filepath.Join(locked, "x.sock"), "EACCES"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.expect(t, "socket "+tc.name+" unix", "0")
			c.expect(t, "raw "+tc.name+" "+brkUnixAddr(tc.addr)+" bind", tc.want)
			if got := brkExists(t, tc.file); got != (tc.want == "0") {
				t.Errorf("socket file %s exists=%v after bind %s", tc.file, got, tc.want)
			}
			if tc.want == "0" {
				c.expect(t, "local "+tc.name, strconv.Quote(tc.addr))
				info, err := os.Lstat(tc.file)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := uint32(info.Mode().Perm()), 0o777&^childMask; got != want {
					t.Errorf("socket file mode %o, want %o from the command's umask %o", got, want, childMask)
				}
			}
			select {
			case d := <-seen:
				if d.otherBind != nil {
					t.Errorf("another codemeld thread binding outside the write root while the confined thread was alive: %v", d.otherBind)
				}
				if d.mainNNP != "0" || d.threadNNP != "1" {
					t.Errorf("NoNewPrivs main thread %s, confined thread %s; want 0 and 1", d.mainNNP, d.threadNNP)
				}
				if d.workDir != work {
					t.Errorf("confined thread bound from %s, want the command's folder %s", d.workDir, work)
				}
			default:
				t.Error("the bind did not run on the confined thread")
			}
		})
	}
	if got := statusField(t, "self", "NoNewPrivs"); got != "0" {
		t.Errorf("main thread NoNewPrivs %s after the binds, want 0", got)
	}
	if cwd, err := os.Getwd(); err != nil || cwd != cwdBefore {
		t.Errorf("codemeld's working folder %s (%v) after the binds, want %s", cwd, err, cwdBefore)
	}

	c.expect(t, "socket a unix", "0")
	c.expect(t, "raw a "+brkUnixAddr("\x00codemeld-test")+" bind", "EPERM")
	c.expect(t, "raw a "+hex.EncodeToString(binary.NativeEndian.AppendUint16(nil, unix.AF_UNIX))+" bind", "EPERM")
	c.expect(t, "socket n unix", "0")
	c.expect(t, "local a", c.do(t, "local n"))
	brkStop(t, b, brkBound)
	want := []Refusal{
		{Path: "@codemeld-test", Reason: "always denied: abstract Unix address"},
		{Path: "@", Reason: "always denied: abstract Unix address"},
	}
	if got := b.Refusals(); !slices.Equal(got, want) {
		t.Errorf("refusals:\n got %+v\nwant %+v", got, want)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.own) != 0 {
		t.Errorf("Unix binds published own-endpoint records %v", b.own)
	}
}

func TestBrokerFullModeUnixListenAfterAConfinedBind(t *testing.T) {
	if abi, err := landlockABI(); err != nil || abi < 1 {
		t.Skipf("unverified: Landlock unavailable (ABI %d, %v)", abi, err)
	}
	base := brkRealDir(t)
	root := filepath.Join(base, "root")
	brkMkdirs(t, root)
	c := brkStart(t, "full")
	deny := newDenyList(nil, nil)
	t.Cleanup(deny.Close)
	b, err := StartConnectBroker(c.take(), ConnectRules{Deny: deny, Policy: brkFullPolicy(t, base, root)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	path := filepath.Join(root, "l.sock")
	c.expect(t, "socket l unix", "0")
	c.expect(t, "listen l", "EPERM")
	c.expect(t, "raw l "+brkUnixAddr(path)+" bind", "0")
	c.expect(t, "listen l", "0")
	unixDestDial(t, &unix.SockaddrUnix{Name: path})
}

func brkPauseBoundedCaseOtherInterleavingsAreADocumentedLimit(t *testing.T, nr int32, afterSyscall bool) (<-chan struct{}, func()) {
	t.Helper()
	paused, resume := make(chan struct{}), make(chan struct{})
	ctx := t.Context()
	var once sync.Once
	bindOrListenPause = func(got int32, after bool) {
		if got != nr || after != afterSyscall {
			return
		}
		first := false
		once.Do(func() { first = true })
		if !first {
			return
		}
		close(paused)
		select {
		case <-resume:
		case <-ctx.Done():
		}
	}
	t.Cleanup(func() { bindOrListenPause = func(int32, bool) {} })
	return paused, sync.OnceFunc(func() { close(resume) })
}

func brkAwaitPause(t *testing.T, c *brkChild, paused <-chan struct{}) {
	t.Helper()
	select {
	case <-paused:
	case <-time.After(brkBound):
		c.fatalf(t, "the handler never reached the pause")
	}
}

func TestBrokerSameSocketHandlersWaitForAPausedBind(t *testing.T) {
	paused, release := brkPauseBoundedCaseOtherInterleavingsAreADocumentedLimit(t, unix.SYS_BIND, true)
	c := brkStart(t, "full")
	lnA, a := brkListen(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{a: true}}
	b := brkStartBroker(t, c, d.decide)

	c.expect(t, "socket t inet", "0")
	c.expect(t, "dup t t2", "0")
	c.expect(t, "listen t2", "EPERM")

	c.expect(t, "socket s inet", "0")
	c.expect(t, "dup s s2", "0")
	bind := c.start(t, "bind s 127.0.0.1:0")
	brkAwaitPause(t, c, paused)
	own := netip.MustParseAddrPort(c.do(t, "local s"))
	if own.Port() == 0 {
		c.fatalf(t, "the paused bind left local endpoint %v", own)
	}
	listen := c.start(t, "listen s2")

	c.expect(t, "socket u inet", "0")
	c.expect(t, "connect u "+a.String(), "0")
	if n := brkAccepts(t, lnA, 200*time.Millisecond); n != 1 {
		t.Errorf("another socket's connect while the bind was paused: %d accepted, want 1", n)
	}
	c.expect(t, "socket c inet", "0")
	c.expect(t, "connect c "+own.String(), "EPERM")
	if !c.silent(bind, 0) || !c.silent(listen, 300*time.Millisecond) {
		t.Fatal("the bind or the listen on its duplicate returned while the bind was paused before publishing")
	}
	release()
	if got := c.await(t, bind, "bind"); got != "0" {
		t.Errorf("paused bind: got %s, want 0", got)
	}
	if got := c.await(t, listen, "listen on the duplicate"); got != "0" {
		t.Errorf("listen on the duplicate after the bind published: got %s, want 0", got)
	}
	c.expect(t, "socket c2 inet", "0")
	c.expect(t, "connect c2 "+own.String(), "0")
	brkStop(t, b, brkBound)
	port := strconv.Itoa(int(own.Port()))
	want := []Refusal{
		{Reason: "listen not allowed (bind to 127.0.0.1 or ::1 first)"},
		{Host: "127.0.0.1", Port: port, Reason: "direct connection not allowed (use the proxy)"},
	}
	if got := b.Refusals(); !slices.Equal(got, want) {
		t.Errorf("refusals:\n got %+v\nwant %+v", got, want)
	}
}

func TestBrokerListenFromAnotherProcessWaitsForAPausedBind(t *testing.T) {
	paused, release := brkPauseBoundedCaseOtherInterleavingsAreADocumentedLimit(t, unix.SYS_BIND, true)
	c := brkStart(t, "full")
	brkStartBroker(t, c, (&brkDecisions{}).decide)
	c.expect(t, "socket s inet", "0")
	bind := c.start(t, "bind s 127.0.0.1:0")
	brkAwaitPause(t, c, paused)
	listen := c.start(t, "spawn s listen")
	if !c.silent(listen, 300*time.Millisecond) {
		t.Fatal("the other process's listen returned while the bind was paused before publishing")
	}
	release()
	if got := c.await(t, bind, "bind"); got != "0" {
		t.Errorf("paused bind: got %s, want 0", got)
	}
	if got := c.await(t, listen, "listen from the other process"); got != "0" {
		t.Errorf("listen through the descriptor shared across fork: got %s, want 0", got)
	}
}

func TestBrokerStopBeforeAPausedBindsSyscall(t *testing.T) {
	if abi, err := landlockABI(); err != nil || abi < 1 {
		t.Skipf("unverified: Landlock unavailable (ABI %d, %v)", abi, err)
	}
	paused, release := brkPauseBoundedCaseOtherInterleavingsAreADocumentedLimit(t, unix.SYS_BIND, false)
	base := brkRealDir(t)
	root := filepath.Join(base, "root")
	brkMkdirs(t, root)
	c := brkStart(t, "full")
	deny := newDenyList(nil, nil)
	t.Cleanup(deny.Close)
	b, err := StartConnectBroker(c.take(), ConnectRules{Deny: deny, Policy: brkFullPolicy(t, base, root)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	path := filepath.Join(root, "s.sock")
	c.expect(t, "socket s unix", "0")
	c.expect(t, "socket n unix", "0")
	unbound := c.do(t, "local n")
	bind := c.start(t, "raw s "+brkUnixAddr(path)+" bind")
	brkAwaitPause(t, c, paused)
	stopped := make(chan struct{})
	go func() { b.Stop(); close(stopped) }()
	select {
	case <-b.stopping:
	case <-time.After(brkBound):
		c.fatalf(t, "Stop never began")
	}
	release()
	select {
	case <-stopped:
	case <-time.After(brkBound):
		c.fatalf(t, "Stop did not return")
	}
	if got := c.await(t, bind, "bind"); got != "EPERM" {
		t.Errorf("bind paused across stop: got %s, want EPERM", got)
	}
	if brkExists(t, path) {
		t.Errorf("the bind created %s after stop", path)
	}
	c.expect(t, "local s", unbound)
	if len(b.bound) != 0 || len(b.own) != 0 {
		t.Errorf("records after stop: bound %v, own %v", b.bound, b.own)
	}
}

func TestBrokerStopAfterAPausedBindsSyscall(t *testing.T) {
	paused, release := brkPauseBoundedCaseOtherInterleavingsAreADocumentedLimit(t, unix.SYS_BIND, true)
	c := brkStart(t, "full")
	b := brkStartBroker(t, c, (&brkDecisions{}).decide)
	c.expect(t, "socket s inet", "0")
	bind := c.start(t, "bind s 127.0.0.1:0")
	brkAwaitPause(t, c, paused)
	stopped := make(chan struct{})
	go func() { b.Stop(); close(stopped) }()
	select {
	case <-b.stopping:
	case <-time.After(brkBound):
		c.fatalf(t, "Stop never began")
	}
	release()
	select {
	case <-stopped:
	case <-time.After(brkBound):
		c.fatalf(t, "Stop did not return")
	}
	c.await(t, bind, "bind")
	if len(b.bound) != 0 || len(b.own) != 0 {
		t.Errorf("records after stop: bound %v, own %v", b.bound, b.own)
	}
}
