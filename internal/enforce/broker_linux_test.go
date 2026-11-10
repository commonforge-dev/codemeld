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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
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
		return errName(rawSockaddrCall(unix.SYS_CONNECT, s.fd(f[1]), addr))
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
		return errName(unix.Bind(s.fd(f[1]), loopback4(0)))
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
		}
		return errName(err)
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
	listener, err := installSeccompListener(map[string]Policy{"slice": seccompSlice, "full": seccompFull}[mode])
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

func TestBrokerFullModeDenials(t *testing.T) {
	c := brkStart(t, "full")
	_, a := brkListen(t)
	d := &brkDecisions{allow: map[netip.AddrPort]bool{a: true}}
	brkStartBroker(t, c, d.decide)
	c.expect(t, "socket s inet", "0")
	c.expect(t, "bind s", "EPERM")
	c.expect(t, "listen s", "EPERM")
	c.expect(t, "socket u unix", "0")
	c.expect(t, "connect u "+a.String(), "EPERM")
	if n := d.count(); n != 0 {
		t.Errorf("decider called %d times", n)
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
	notConnect := n
	notConnect.Nr = unix.SYS_BIND
	if _, why, ok := b.answer(notConnect); !ok || why == nil || *why != (Refusal{Reason: "not a TCP connect"}) {
		t.Errorf("a non-connect call: refusal %+v sent=%v, want a non-TCP-connect refusal with no destination", why, ok)
	}
	forged := n
	forged.Pid = 1 << 30
	resp, why, ok := b.answer(forged)
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
	if resp, why, ok := b.answer(n); ok || why != nil {
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
