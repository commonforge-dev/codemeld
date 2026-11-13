package enforce

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const brokerChildEnv = "CODEMELD_TEST_BROKER_CHILD"

var brokerMarker = [8]byte{'b', 'r', 'o', 'k', 'e', 'r', 'o', 'k'}

type seccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Nr    int32
	Arch  uint32
	IP    uint64
	Args  [6]uint64
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

type brokerChild struct {
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	done     chan struct{}
	waitErr  error
	out      bytes.Buffer
	ctl      *net.UnixConn
	lines    *bufio.Reader
	listener int
	pidfd    int

	notifyRefused string
	copyRefused   string
	readRefused   string
}

const (
	needNotify = 1 << iota
	needCopy
	needRead
)

func claim(t *testing.T, held bool, format string, args ...any) {
	t.Helper()
	result := "REFUTED"
	if held {
		result = "CONFIRMED"
	}
	t.Logf("%s: "+format, append([]any{result}, args...)...)
}

func errName(err error) string {
	if err == nil {
		return "0"
	}
	if e, ok := err.(unix.Errno); ok {
		return unix.ErrnoName(e)
	}
	return err.Error()
}

func sockaddrString(sa unix.Sockaddr) string {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)).String()
	case *unix.SockaddrUnix:
		return strconv.Quote(a.Name)
	}
	return fmt.Sprintf("%T", sa)
}

func peerName(t *testing.T, fd int) string {
	t.Helper()
	sa, err := unix.Getpeername(fd)
	if err == unix.ENOTCONN {
		return errName(err)
	}
	if err != nil {
		t.Fatalf("fixture: getpeername: %v", err)
	}
	return sockaddrString(sa)
}

func unixName(t *testing.T, fd int) string {
	t.Helper()
	var sa unix.RawSockaddrUnix
	n := uint32(unsafe.Sizeof(sa))
	_, _, e := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&n)))
	if e != 0 {
		t.Fatalf("fixture: getsockname: %v", e)
	}
	if n <= 2 {
		return "unnamed"
	}
	path := unsafe.Slice((*byte)(unsafe.Pointer(&sa.Path[0])), n-2)
	return strconv.Quote(string(bytes.TrimSuffix(path, []byte{0})))
}

func rawSockaddrCall(nr uintptr, fd int, addr []byte) error {
	_, _, e := unix.Syscall(nr, uintptr(fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
	return errnoErr(e)
}

func ioctlPtr(fd int, req uintptr, p unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(p))
	return errnoErr(e)
}

func pollFD(fd int, events int16, timeout time.Duration) (int16, error) {
	deadline := time.Now().Add(timeout)
	for {
		p := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(p, int(max(time.Until(deadline), 0).Milliseconds()))
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return 0, err
		}
		return p[0].Revents, nil
	}
}

func setRawPort(sa *unix.RawSockaddrInet4, port int) {
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], uint16(port))
}

func loopback4(port int) *unix.SockaddrInet4 {
	return &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
}

func closed(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("fixture: closing %s: %v", what, err)
	}
}

func notifyListeners(t *testing.T, pid string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/" + pid + "/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		link, err := os.Readlink("/proc/" + pid + "/fd/" + e.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("fixture: inspecting descriptor %s of %s: %v", e.Name(), pid, err)
		}
		if strings.Contains(link, "seccomp notify") {
			n++
		}
	}
	return n
}

func listenTCP(t *testing.T) (*net.TCPListener, string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closed(t, "TCP listener", ln.Close()) })
	return ln.(*net.TCPListener), strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

func (c *brokerChild) accepted(t *testing.T, ln *net.TCPListener, d time.Duration) net.Conn {
	t.Helper()
	if err := ln.SetDeadline(time.Now().Add(d)); err != nil {
		c.fatalf(t, "listener deadline: %v", err)
	}
	conn, err := ln.Accept()
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil
	}
	if err != nil {
		c.fatalf(t, "accept: %v", err)
	}
	return conn
}

func unixListener(t *testing.T, typ int, path string) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closed(t, "Unix listener", unix.Close(fd)) })
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		t.Fatal(err)
	}
	return fd
}

func pendingConn(t *testing.T, fd int) bool {
	t.Helper()
	nfd, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
	if err == unix.EAGAIN {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	closed(t, "accepted connection", unix.Close(nfd))
	return true
}

func startBrokerChild(t *testing.T, needs int, mode, dir string, args ...string) *brokerChild {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentEnd := os.NewFile(uintptr(fds[0]), "broker-ctl")
	childEnd := os.NewFile(uintptr(fds[1]), "child-ctl")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	c := &brokerChild{cancel: cancel, done: make(chan struct{}), listener: -1, pidfd: -1}
	c.cmd = exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestBrokerProtoChild$", "--"}, args...)...)
	c.cmd.Env = append(os.Environ(), brokerChildEnv+"="+mode)
	c.cmd.Dir = dir
	c.cmd.ExtraFiles = []*os.File{childEnd}
	c.cmd.Stdout = &c.out
	c.cmd.Stderr = &c.out
	err = c.cmd.Start()
	closed(t, "the child's control end", childEnd.Close())
	if err != nil {
		closed(t, "the broker's control end", parentEnd.Close())
		cancel()
		t.Fatal(err)
	}
	go func() {
		c.waitErr = c.cmd.Wait()
		close(c.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-c.done
		closed(t, "the listener", c.closeListener())
		if c.pidfd >= 0 {
			closed(t, "the pidfd", unix.Close(c.pidfd))
		}
		if c.ctl != nil {
			closed(t, "the control connection", c.ctl.Close())
		}
	})
	conn, err := net.FileConn(parentEnd)
	if err == nil {
		c.ctl = conn.(*net.UnixConn)
	}
	if cerr := parentEnd.Close(); cerr != nil {
		c.fatalf(t, "fixture: closing the broker's control end: %v", cerr)
	}
	if err != nil {
		c.fatalf(t, "control socket: %v", err)
	}
	c.lines = bufio.NewReader(c.ctl)

	if err := c.ctl.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.fatalf(t, "%v", err)
	}
	b, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := c.ctl.ReadMsgUnix(b, oob)
	if err != nil || n != 1 {
		c.fatalf(t, "no listener message from child: %v", err)
	}
	if b[0] == 'E' {
		c.notifyRefused = "NEW_LISTENER filter refused: " + c.expect(t, "filter")
	} else {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(msgs) != 1 {
			c.fatalf(t, "listener message: %v", err)
		}
		rights, err := unix.ParseUnixRights(&msgs[0])
		if err != nil || len(rights) != 1 {
			c.fatalf(t, "listener rights: %v", err)
		}
		c.listener = rights[0]
		c.expect(t, "closed")
		if notifyListeners(t, "self") < 1 {
			c.fatalf(t, "the received listener is not visible as a seccomp notify descriptor")
		}
		if got := notifyListeners(t, strconv.Itoa(c.cmd.Process.Pid)); got != 0 {
			c.fatalf(t, "child still holds %d listener descriptors", got)
		}
	}

	if pidfd, err := unix.PidfdOpen(c.cmd.Process.Pid, 0); err != nil {
		c.copyRefused = "pidfd_open refused: " + errName(err)
	} else {
		c.pidfd = pidfd
		if probe, err := unix.PidfdGetfd(c.pidfd, 3, 0); err != nil {
			c.copyRefused = "pidfd_getfd refused: " + errName(err)
		} else if err := unix.Close(probe); err != nil {
			c.fatalf(t, "fixture: closing the pidfd_getfd probe: %v", err)
		}
	}
	addr, err := strconv.ParseUint(c.expect(t, "marker"), 0, 64)
	if err != nil {
		c.fatalf(t, "marker: %v", err)
	}
	got := make([]byte, len(brokerMarker))
	var errno unix.Errno
	if err := c.readMem(c.cmd.Process.Pid, addr, got); errors.As(err, &errno) {
		c.readRefused = "process_vm_readv refused: " + errName(errno)
	} else if err != nil {
		c.fatalf(t, "process_vm_readv: %v", err)
	} else if !bytes.Equal(got, brokerMarker[:]) {
		c.fatalf(t, "process_vm_readv read %q, want %q", got, brokerMarker[:])
	}
	var missing []string
	if needs&needNotify != 0 && c.notifyRefused != "" {
		missing = append(missing, c.notifyRefused)
	}
	if needs&needCopy != 0 && c.copyRefused != "" {
		missing = append(missing, c.copyRefused)
	}
	if needs&needRead != 0 && c.readRefused != "" {
		missing = append(missing, c.readRefused)
	}
	if len(missing) > 0 {
		t.Skipf("inconclusive at kernel.yama.ptrace_scope=%s: %s", sysctl("/proc/sys/kernel/yama/ptrace_scope"), strings.Join(missing, "; "))
	}
	c.send(t, "go")
	return c
}

func (c *brokerChild) fatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	c.cancel()
	<-c.done
	t.Fatalf(format+"\nchild (%v) output:\n%s", append(args, c.waitErr, c.out.String())...)
}

func (c *brokerChild) closeListener() error {
	if c.listener < 0 {
		return nil
	}
	err := unix.Close(c.listener)
	c.listener = -1
	return err
}

func (c *brokerChild) send(t *testing.T, line string) {
	t.Helper()
	if _, err := c.ctl.Write([]byte(line + "\n")); err != nil {
		c.fatalf(t, "send %q: %v", line, err)
	}
}

func (c *brokerChild) expect(t *testing.T, key string) string {
	t.Helper()
	v, ok := c.expectWithin(t, key, 10*time.Second)
	if !ok {
		c.fatalf(t, "waiting for %s: timed out with the child still running", key)
	}
	return v
}

func (c *brokerChild) expectWithin(t *testing.T, key string, d time.Duration) (string, bool) {
	t.Helper()
	if err := c.ctl.SetReadDeadline(time.Now().Add(d)); err != nil {
		c.fatalf(t, "%v", err)
	}
	line, err := c.lines.ReadString('\n')
	if errors.Is(err, os.ErrDeadlineExceeded) && line == "" {
		select {
		case <-c.done:
			c.fatalf(t, "waiting for %s: the child exited", key)
		default:
			return "", false
		}
	}
	if err != nil {
		c.fatalf(t, "waiting for %s: %v", key, err)
	}
	v, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), key+"=")
	if !ok {
		c.fatalf(t, "want %s=, got %q", key, line)
	}
	return v, true
}

func (c *brokerChild) wait(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(20 * time.Second):
		c.fatalf(t, "child did not exit")
	}
	if c.waitErr != nil {
		c.fatalf(t, "child failed")
	}
}

func (c *brokerChild) readMem(pid int, addr uint64, buf []byte) error {
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(len(buf))
	n, err := unix.ProcessVMReadv(pid, local, []unix.RemoteIovec{{Base: uintptr(addr), Len: len(buf)}}, 0)
	if err == nil && n != len(buf) {
		return fmt.Errorf("short read %d of %d", n, len(buf))
	}
	return err
}

func (c *brokerChild) next(t *testing.T, nr int) seccompNotif {
	t.Helper()
	revents, err := pollFD(c.listener, unix.POLLIN, 10*time.Second)
	if err != nil || revents&unix.POLLIN == 0 {
		c.fatalf(t, "no notification (revents %#x): %v", revents, err)
	}
	var n seccompNotif
	if err := ioctlPtr(c.listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n)); err != nil {
		c.fatalf(t, "SECCOMP_IOCTL_NOTIF_RECV: %v", err)
	}
	if int(n.Nr) != nr {
		c.fatalf(t, "notification for syscall %d, want %d", n.Nr, nr)
	}
	c.live(t, n)
	return n
}

func (c *brokerChild) live(t *testing.T, n seccompNotif) {
	t.Helper()
	if err := ioctlPtr(c.listener, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&n.ID)); err != nil {
		c.fatalf(t, "SECCOMP_IOCTL_NOTIF_ID_VALID: %v", err)
	}
}

func (c *brokerChild) readAddr(t *testing.T, n seccompNotif) []byte {
	t.Helper()
	if n.Args[2] == 0 || n.Args[2] > unix.SizeofSockaddrAny {
		c.fatalf(t, "address length %d", n.Args[2])
	}
	addr := make([]byte, n.Args[2])
	if err := c.readMem(int(n.Pid), n.Args[1], addr); err != nil {
		c.fatalf(t, "process_vm_readv: %v", err)
	}
	return addr
}

func (c *brokerChild) reply(t *testing.T, id uint64, result error) {
	t.Helper()
	resp := seccompNotifResp{ID: id}
	if result != nil {
		var e unix.Errno
		if !errors.As(result, &e) {
			c.fatalf(t, "broker result %v is not an errno", result)
		}
		resp.Error = -int32(e)
	}
	if err := ioctlPtr(c.listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp)); err != nil {
		c.fatalf(t, "SECCOMP_IOCTL_NOTIF_SEND: %v", err)
	}
}

func (c *brokerChild) handle(t *testing.T, nr int, act func(n seccompNotif, sock int, addr []byte) error) seccompNotif {
	t.Helper()
	n := c.next(t, nr)
	sock, err := unix.PidfdGetfd(c.pidfd, int(n.Args[0]), 0)
	if err != nil {
		c.fatalf(t, "pidfd_getfd: %v", err)
	}
	defer func() { closed(t, "the broker's socket copy", unix.Close(sock)) }()
	var addr []byte
	if nr != unix.SYS_LISTEN {
		addr = c.readAddr(t, n)
	}
	c.live(t, n)
	result := act(n, sock, addr)
	c.reply(t, n.ID, result)
	return n
}

func installBrokerFilter(denyFastOpen bool) (int, error) {
	info, err := nativeSeccompArch()
	if err != nil {
		return -1, err
	}
	loadNr := bpf.LoadAbsolute{Off: seccompNrOffset, Size: 4}
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompArchOffset, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(info.ID), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_KILL_PROCESS},
		loadNr,
	}
	for _, nr := range []uint32{unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN} {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: nr, SkipTrue: 1}, bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF})
	}
	if denyFastOpen {
		for _, call := range [][2]uint32{{unix.SYS_SENDTO, 3}, {unix.SYS_SENDMSG, 2}, {unix.SYS_SENDMMSG, 3}} {
			prog = append(prog,
				bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: call[0], SkipTrue: 3},
				loadArg(call[1]),
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: unix.MSG_FASTOPEN, SkipFalse: 1},
				bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
				loadNr)
		}
	}
	raw, err := bpf.Assemble(append(prog, bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}))
	if err != nil {
		return -1, err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, err
	}
	fd, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER|unix.SECCOMP_FILTER_FLAG_TSYNC|unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
		uintptr(unsafe.Pointer(&fprog)))
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

func TestBrokerProtoChild(t *testing.T) {
	mode := os.Getenv(brokerChildEnv)
	if mode == "" {
		t.Skip("runs only as the disposable child of the broker prototype tests")
	}
	args := flag.Args()
	ctl := os.NewFile(3, "ctl")
	lines := bufio.NewReader(ctl)
	report := func(key, val string) {
		if _, err := fmt.Fprintf(ctl, "%s=%s\n", key, val); err != nil {
			panic(fmt.Sprintf("fixture: reporting %s: %v", key, err))
		}
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	socket := func(domain, typ int) int {
		fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC, 0)
		must(err)
		return fd
	}
	acceptConn := func(fd int) string {
		v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
		must(err)
		return strconv.Itoa(v)
	}

	runtime.LockOSThread()
	listener, filterErr := installBrokerFilter(mode == "fastopen" && args[1] == "deny")
	if filterErr != nil {
		_, err := ctl.Write([]byte("E"))
		must(err)
		report("filter", errName(filterErr))
	} else {
		must(unix.Sendmsg(3, []byte("L"), unix.UnixRights(listener), nil, 0))
		// The kernel fails paused calls when the broker stops only if the broker holds the last listener reference.
		must(unix.Close(listener))
		report("closed", "1")
	}
	report("marker", fmt.Sprintf("%#x", uintptr(unsafe.Pointer(&brokerMarker[0]))))
	if line, err := lines.ReadString('\n'); err != nil || line != "go\n" {
		t.Fatalf("waiting for go: %q %v", line, err)
	}
	if filterErr != nil {
		return
	}

	switch mode {
	case "connect":
		port, err := strconv.Atoi(args[0])
		must(err)
		for _, nonblock := range []int{0, unix.SOCK_NONBLOCK} {
			fd := socket(unix.AF_INET, unix.SOCK_STREAM|nonblock)
			report("connect", errName(unix.Connect(fd, loopback4(port))))
			if nonblock != 0 {
				revents, err := pollFD(fd, unix.POLLOUT, 10*time.Second)
				must(err)
				soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				must(err)
				report("poll", fmt.Sprintf("revents=%#x so_error=%s", revents, errName(errnoErr(unix.Errno(soErr)))))
				must(unix.SetNonblock(fd, false))
			}
			peer := peerName(t, fd)
			report("peer", peer)
			if peer == "ENOTCONN" {
				must(unix.Close(fd))
				continue
			}
			must(unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}))
			conn := os.NewFile(uintptr(fd), "conn")
			buf := make([]byte, 4)
			_, err = io.ReadFull(conn, buf)
			must(err)
			report("read", string(buf))
			_, err = conn.Write([]byte("pong"))
			must(err)
			must(conn.Close())
		}
	case "changed":
		port, err := strconv.Atoi(args[0])
		must(err)
		sa := &unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: [4]byte{127, 0, 0, 1}}
		setRawPort(sa, port)
		go func() {
			line, err := lines.ReadString('\n')
			v, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "mutate=")
			p, perr := strconv.Atoi(v)
			if err != nil || !ok || perr != nil {
				report("mutated", "bad request "+strconv.Quote(line))
				return
			}
			setRawPort(sa, p)
			report("mutated", "1")
		}()
		fd := socket(unix.AF_INET, unix.SOCK_STREAM)
		_, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(sa)), unsafe.Sizeof(*sa))
		report("connect", errName(errnoErr(e)))
		report("peer", peerName(t, fd))
	case "tcp-listen":
		fd := socket(unix.AF_INET, unix.SOCK_STREAM)
		report("listen", errName(unix.Listen(fd, 8)))
		sa, err := unix.Getsockname(fd)
		must(err)
		report("name", sockaddrString(sa))
		report("acceptconn", acceptConn(fd))
	case "unix-listen":
		for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
			fd := socket(unix.AF_UNIX, typ)
			report("listen", errName(unix.Listen(fd, 8)))
			report("name", unixName(t, fd))
			report("acceptconn", acceptConn(fd))
		}
	case "fastopen":
		port, err := strconv.Atoi(args[0])
		must(err)
		payload := []byte("x")
		rsa := unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: [4]byte{127, 0, 0, 1}}
		setRawPort(&rsa, port)
		calls := []func(fd int) error{
			func(fd int) error { return unix.Sendto(fd, payload, unix.MSG_FASTOPEN, loopback4(port)) },
			func(fd int) error {
				_, err := unix.SendmsgN(fd, payload, nil, loopback4(port), unix.MSG_FASTOPEN)
				return err
			},
			func(fd int) error {
				iov := unix.Iovec{Base: &payload[0]}
				iov.SetLen(len(payload))
				var m unix.Mmsghdr
				m.Hdr.Name = (*byte)(unsafe.Pointer(&rsa))
				m.Hdr.Namelen = uint32(unsafe.Sizeof(rsa))
				m.Hdr.Iov = &iov
				m.Hdr.SetIovlen(1)
				_, _, e := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&m)), 1, unix.MSG_FASTOPEN, 0, 0)
				return errnoErr(e)
			},
		}
		for _, call := range calls {
			fd := socket(unix.AF_INET, unix.SOCK_STREAM)
			report("send", errName(call(fd))+" peer="+peerName(t, fd))
			must(unix.Close(fd))
		}
	case "bind":
		for _, path := range args {
			fd := socket(unix.AF_UNIX, unix.SOCK_STREAM)
			report("bind", errName(unix.Bind(fd, &unix.SockaddrUnix{Name: path})))
			report("name", unixName(t, fd))
		}
	case "stops":
		port, err := strconv.Atoi(args[0])
		must(err)
		report("connect", errName(unix.Connect(socket(unix.AF_INET, unix.SOCK_STREAM), loopback4(port))))
		report("bind", errName(unix.Bind(socket(unix.AF_INET, unix.SOCK_STREAM), loopback4(0))))
		report("listen", errName(unix.Listen(socket(unix.AF_INET, unix.SOCK_STREAM), 8)))
		report("connect-again", errName(unix.Connect(socket(unix.AF_INET, unix.SOCK_STREAM), loopback4(port))))
	}
}

func TestBrokerProtoHostPrerequisites(t *testing.T) {
	if unsafe.Sizeof(seccompNotif{}) != 0x50 || unsafe.Sizeof(seccompNotifResp{}) != 0x18 {
		t.Fatalf("seccomp_notif %#x, seccomp_notif_resp %#x", unsafe.Sizeof(seccompNotif{}), unsafe.Sizeof(seccompNotifResp{}))
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	abi, abiErr := landlockABI()
	scope := sysctl("/proc/sys/kernel/yama/ptrace_scope")
	t.Logf("kernel %s; kernel.yama.ptrace_scope=%q; net.ipv4.tcp_fastopen=%q; Landlock ABI %d (%v)",
		unix.ByteSliceToString(uts.Release[:]), scope, sysctl("/proc/sys/net/ipv4/tcp_fastopen"), abi, abiErr)
	c := startBrokerChild(t, 0, "idle", "")
	works := func(refused string) string {
		if refused == "" {
			return "works"
		}
		return refused
	}
	t.Logf("at kernel.yama.ptrace_scope=%s: seccomp user notification: %s; pidfd_getfd: %s; process_vm_readv: %s",
		scope, works(c.notifyRefused), works(c.copyRefused), works(c.readRefused))
	c.wait(t)
}

func TestBrokerProtoConnect(t *testing.T) {
	ln, port := listenTCP(t)
	c := startBrokerChild(t, needNotify|needCopy|needRead, "connect", "", port)
	for _, wantConnect := range []string{"0", "EINPROGRESS"} {
		var brokerErr error
		n := c.handle(t, unix.SYS_CONNECT, func(_ seccompNotif, sock int, addr []byte) error {
			brokerErr = rawSockaddrCall(unix.SYS_CONNECT, sock, addr)
			return brokerErr
		})
		got, poll := c.expect(t, "connect"), "not polled"
		if wantConnect == "EINPROGRESS" {
			poll = c.expect(t, "poll")
		}
		peer := c.expect(t, "peer")
		var read, pong string
		if _, err := netip.ParseAddrPort(peer); err == nil {
			conn := c.accepted(t, ln, 5*time.Second)
			if conn == nil {
				c.fatalf(t, "the child is connected to %s but the listener accepted nothing", peer)
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				c.fatalf(t, "write: %v", err)
			}
			if read = c.expect(t, "read"); read != "ping" {
				c.fatalf(t, "fixture: child read %q, want \"ping\"", read)
			}
			buf := make([]byte, 4)
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				c.fatalf(t, "%v", err)
			}
			if _, err := io.ReadFull(conn, buf); err != nil {
				c.fatalf(t, "fixture: reading the child's reply: %v", err)
			}
			if pong = string(buf); pong != "pong" {
				c.fatalf(t, "fixture: broker read %q from the child, want \"pong\"", pong)
			}
			if err := conn.Close(); err != nil {
				c.fatalf(t, "fixture: closing the accepted connection: %v", err)
			}
		}
		held := got == wantConnect && errName(brokerErr) == wantConnect && (wantConnect == "0" || poll == "revents=0x4 so_error=0") &&
			peer == "127.0.0.1:"+port && read == "ping"
		claim(t, held, "R1/R2 connect wanting %s: broker connect=%s, child connect=%s poll=%s peer=%s read=%q, broker read %q; notification pid %d, child pid %d",
			wantConnect, errName(brokerErr), got, poll, peer, read, pong, n.Pid, c.cmd.Process.Pid)
	}
	c.wait(t)
}

func TestBrokerProtoChangedAddress(t *testing.T) {
	lnA, portA := listenTCP(t)
	lnB, portB := listenTCP(t)
	c := startBrokerChild(t, needNotify|needCopy|needRead, "changed", "", portA)
	var readPort, afterPort string
	c.handle(t, unix.SYS_CONNECT, func(n seccompNotif, sock int, addr []byte) error {
		readPort = strconv.Itoa(int(binary.BigEndian.Uint16(addr[2:4])))
		c.send(t, "mutate="+portB)
		if got := c.expect(t, "mutated"); got != "1" {
			c.fatalf(t, "child mutation: %s", got)
		}
		afterPort = strconv.Itoa(int(binary.BigEndian.Uint16(c.readAddr(t, n)[2:4])))
		return rawSockaddrCall(unix.SYS_CONNECT, sock, addr)
	})
	if readPort != portA || afterPort != portB {
		c.fatalf(t, "fixture: broker read port %s, child memory then held %s; want %s then %s", readPort, afterPort, portA, portB)
	}
	connect, peer := c.expect(t, "connect"), c.expect(t, "peer")
	connA, connB := c.accepted(t, lnA, 5*time.Second), c.accepted(t, lnB, 300*time.Millisecond)
	for _, conn := range []net.Conn{connA, connB} {
		if conn != nil {
			if err := conn.Close(); err != nil {
				c.fatalf(t, "fixture: closing an accepted connection: %v", err)
			}
		}
	}
	claim(t, connect == "0" && peer == "127.0.0.1:"+portA && connA != nil && connB == nil,
		"R2 changed address: broker read port %s, child memory then held %s; child connect=%s peer=%s; listener A (read address) accepted=%v, listener B (changed address) accepted=%v",
		portA, portB, connect, peer, connA != nil, connB != nil)
	c.wait(t)
}

func TestBrokerProtoTCPListenUnbound(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closed(t, "the direct listen socket", unix.Close(fd)) }()
	listenErr := unix.Listen(fd, 8)
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	direct, ok := sa.(*unix.SockaddrInet4)
	claim(t, listenErr == nil && ok && direct.Addr == [4]byte{} && direct.Port != 0,
		"R1 direct listen() on an unbound TCP socket: listen=%s, getsockname=%s", errName(listenErr), sockaddrString(sa))

	c := startBrokerChild(t, needNotify|needCopy, "tcp-listen", "")
	var seen string
	c.handle(t, unix.SYS_LISTEN, func(_ seccompNotif, sock int, _ []byte) error {
		sa, err := unix.Getsockname(sock)
		if err != nil {
			c.fatalf(t, "fixture: broker getsockname: %v", err)
		}
		seen = sockaddrString(sa)
		if a, ok := sa.(*unix.SockaddrInet4); !ok || a.Addr != [4]byte{127, 0, 0, 1} {
			return unix.EPERM
		}
		return unix.Listen(sock, 8)
	})
	listen, name, acceptConn := c.expect(t, "listen"), c.expect(t, "name"), c.expect(t, "acceptconn")
	claim(t, seen == "0.0.0.0:0" && listen == "EPERM" && name == "0.0.0.0:0" && acceptConn == "0",
		"R1 brokered listen() on an unbound TCP socket: broker saw %s on its copy; child listen=%s name=%s SO_ACCEPTCONN=%s",
		seen, listen, name, acceptConn)
	c.wait(t)
}

func TestBrokerProtoUnixListenUnbound(t *testing.T) {
	types := []struct {
		name string
		typ  int
	}{{"stream", unix.SOCK_STREAM}, {"seqpacket", unix.SOCK_SEQPACKET}}
	for _, ty := range types {
		fd, err := unix.Socket(unix.AF_UNIX, ty.typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		err = unix.Listen(fd, 8)
		claim(t, err != nil, "R7 direct %s listen() on an unbound Unix socket: listen=%s name=%s", ty.name, errName(err), unixName(t, fd))
		closed(t, "the direct listen socket", unix.Close(fd))
	}

	c := startBrokerChild(t, needNotify|needCopy, "unix-listen", "")
	for _, ty := range types {
		var seen string
		var brokerErr error
		c.handle(t, unix.SYS_LISTEN, func(n seccompNotif, sock int, _ []byte) error {
			seen = unixName(t, sock)
			brokerErr = unix.Listen(sock, int(n.Args[1]))
			return brokerErr
		})
		listen, name, acceptConn := c.expect(t, "listen"), c.expect(t, "name"), c.expect(t, "acceptconn")
		claim(t, seen == "unnamed" && brokerErr != nil && listen == errName(brokerErr) && acceptConn == "0",
			"R7 brokered %s listen() on an unbound Unix socket: broker saw name %s, broker listen=%s; child listen=%s name=%s SO_ACCEPTCONN=%s",
			ty.name, seen, errName(brokerErr), listen, name, acceptConn)
	}
	c.wait(t)
}

func TestBrokerProtoFastOpen(t *testing.T) {
	fastOpen := sysctl("/proc/sys/net/ipv4/tcp_fastopen")
	if v, err := strconv.Atoi(fastOpen); err != nil || v&1 == 0 {
		t.Skipf("inconclusive: net.ipv4.tcp_fastopen=%q does not enable the client side", fastOpen)
	}
	for _, variant := range []string{"allow", "deny"} {
		t.Run(variant, func(t *testing.T) {
			ln, port := listenTCP(t)
			c := startBrokerChild(t, needNotify, "fastopen", "", port, variant)
			for _, call := range []string{"sendto", "sendmsg", "sendmmsg"} {
				got := c.expect(t, "send")
				wait := 2 * time.Second
				if variant == "deny" {
					wait = 300 * time.Millisecond
				}
				conn := c.accepted(t, ln, wait)
				var data []byte
				if conn != nil {
					if variant == "allow" {
						data = make([]byte, 1)
						if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
							c.fatalf(t, "%v", err)
						}
						if _, err := io.ReadFull(conn, data); err != nil {
							c.fatalf(t, "fixture: reading the %s payload: %v", call, err)
						}
						if string(data) != "x" {
							c.fatalf(t, "fixture: %s payload %q, want \"x\"", call, data)
						}
					}
					if err := conn.Close(); err != nil {
						c.fatalf(t, "fixture: closing the %s connection: %v", call, err)
					}
				}
				want, wantConn := "0 peer=127.0.0.1:"+port, true
				if variant == "deny" {
					want, wantConn = "EPERM peer=ENOTCONN", false
				}
				claim(t, got == want && (conn != nil) == wantConn,
					"R1 %s %s with MSG_FASTOPEN: child %s; listener accepted=%v data=%q", variant, call, got, conn != nil, data)
			}
			revents, err := pollFD(c.listener, unix.POLLIN, 0)
			if err != nil {
				c.fatalf(t, "poll listener: %v", err)
			}
			claim(t, revents&unix.POLLIN == 0, "R1 %s: no notification for MSG_FASTOPEN sends (listener revents %#x)", variant, revents)
			c.wait(t)
		})
	}
}

func TestBrokerProtoUnixSendToAddress(t *testing.T) {
	for _, ty := range []struct {
		name string
		typ  int
	}{{"stream", unix.SOCK_STREAM}, {"seqpacket", unix.SOCK_SEQPACKET}} {
		path := filepath.Join(t.TempDir(), "l.sock")
		ln := unixListener(t, ty.typ, path)
		fd, err := unix.Socket(unix.AF_UNIX, ty.typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		to := &unix.SockaddrUnix{Name: path}
		sendtoErr := unix.Sendto(fd, []byte("x"), 0, to)
		_, sendmsgErr := unix.SendmsgN(fd, []byte("x"), nil, to, 0)
		peer := peerName(t, fd)
		pending := pendingConn(t, ln)
		closed(t, "the sending socket", unix.Close(fd))
		claim(t, peer == "ENOTCONN" && !pending,
			"R1 Unix %s send to an address: sendto=%s sendmsg=%s getpeername=%s listener has a pending connection=%v",
			ty.name, errName(sendtoErr), errName(sendmsgErr), peer, pending)
	}
}

func TestBrokerProtoUnixConnectThroughHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.sock")
	orig := unixListener(t, unix.SOCK_STREAM, path)
	h, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closed(t, "the O_PATH handle", unix.Close(h)) }()
	via := "/proc/self/fd/" + strconv.Itoa(h)
	connectVia := func() error {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { closed(t, "the connecting socket", unix.Close(fd)) }()
		return unix.Connect(fd, &unix.SockaddrUnix{Name: via})
	}
	err = connectVia()
	reached := pendingConn(t, orig)
	claim(t, err == nil && reached, "R5 connect through %s: connect=%s, listener reached=%v", via, errName(err), reached)
	if err := os.Rename(path, filepath.Join(dir, "b.sock")); err != nil {
		t.Fatal(err)
	}
	repl := unixListener(t, unix.SOCK_STREAM, path)
	err = connectVia()
	origGot, replGot := pendingConn(t, orig), pendingConn(t, repl)
	claim(t, err == nil && origGot && !replGot, "R5 after rename and replacement: connect=%s original listener=%v replacement=%v", errName(err), origGot, replGot)
	t.Run("openat2", func(t *testing.T) {
		magic := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), h)
		how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC}
		fd, err := unix.Openat2(unix.AT_FDCWD, magic, &how)
		if err != nil {
			t.Skipf("inconclusive: openat2(%s) without RESOLVE_NO_MAGICLINKS = %s, so the flag cannot be evaluated", magic, errName(err))
		}
		closed(t, "the baseline openat2 handle", unix.Close(fd))
		how.Resolve = unix.RESOLVE_NO_MAGICLINKS
		fd, err = unix.Openat2(unix.AT_FDCWD, magic, &how)
		if err == nil {
			closed(t, "the openat2 handle", unix.Close(fd))
		}
		claim(t, err != nil, "R5 openat2(%s, RESOLVE_NO_MAGICLINKS) = %s (without the flag it opened)", magic, errName(err))
	})
}

func confinedBind(t *testing.T, root string, pid uint32, sock int, addr []byte, otherThread func() error) (bindErr, otherErr error) {
	t.Helper()
	cwd, err := os.Open(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closed(t, "the child's cwd", cwd.Close()) }()
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closed(t, "the write root", unix.Close(rootFD)) }()
	cwdFD := int(cwd.Fd())
	refused := errors.New("refused by the host")
	enforce := func(step string, err error) error {
		if e, ok := err.(unix.Errno); ok && e != unix.EINVAL && e != unix.EBADF && e != unix.EFAULT {
			return fmt.Errorf("%s %w: %w", step, refused, err)
		}
		return fmt.Errorf("%s: %w", step, err)
	}
	type result struct{ setup, bind error }
	results, release := make(chan result, 1), make(chan struct{})
	defer close(release)
	var confine func()
	confine = func() {
		runtime.LockOSThread()
		// A locked goroutine that exits on the main thread wedges it instead of ending it, so the restriction must land elsewhere.
		if unix.Gettid() == unix.Getpid() {
			done := make(chan struct{})
			go func() {
				confine()
				close(done)
			}()
			<-done
			runtime.UnlockOSThread()
			return
		}
		setup := func() error {
			if err := unix.Unshare(unix.CLONE_FS); err != nil {
				return enforce("unshare(CLONE_FS)", err)
			}
			if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
				return enforce("no_new_privs", err)
			}
			attr := unix.LandlockRulesetAttr{Handled_access_fs: unix.LANDLOCK_ACCESS_FS_MAKE_SOCK}
			rs, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Offsetof(attr.Handled_access_net), 0)
			if e != 0 {
				return enforce("landlock_create_ruleset", e)
			}
			defer func() { closed(t, "the Landlock ruleset", unix.Close(int(rs))) }()
			rule := unix.LandlockPathBeneathAttr{Allowed_access: unix.LANDLOCK_ACCESS_FS_MAKE_SOCK, Parent_fd: int32(rootFD)}
			if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, rs, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); e != 0 {
				return fmt.Errorf("landlock_add_rule: %w", e)
			}
			if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rs, 0, 0); e != 0 {
				return enforce("landlock_restrict_self", e)
			}
			return unix.Fchdir(cwdFD)
		}()
		if setup != nil {
			results <- result{setup: setup}
			return
		}
		results <- result{bind: rawSockaddrCall(unix.SYS_BIND, sock, addr)}
		<-release
	}
	go confine()
	r := <-results
	if errors.Is(r.setup, refused) {
		t.Skipf("inconclusive: confined bind thread setup %v", r.setup)
	}
	if r.setup != nil {
		t.Fatalf("confined thread setup: %v", r.setup)
	}
	return r.bind, otherThread()
}

func TestBrokerProtoConfinedUnixBind(t *testing.T) {
	if abi, err := landlockABI(); err != nil || abi < 3 {
		t.Skipf("Landlock ABI 3 unavailable: ABI %d, %v", abi, err)
	}
	root, outside := t.TempDir(), t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		addr, file string
		inside     bool
	}{
		{"rel.sock", filepath.Join(work, "rel.sock"), true},
		{filepath.Join(root, "abs.sock"), filepath.Join(root, "abs.sock"), true},
		{filepath.Join(outside, "out.sock"), filepath.Join(outside, "out.sock"), false},
	}
	args := make([]string, len(cases))
	for i, tc := range cases {
		args[i] = tc.addr
	}
	c := startBrokerChild(t, needNotify|needCopy|needRead, "bind", work, args...)
	for i, tc := range cases {
		var bindErr, otherErr error
		other := filepath.Join(outside, fmt.Sprintf("other-%d.sock", i))
		c.handle(t, unix.SYS_BIND, func(n seccompNotif, sock int, addr []byte) error {
			bindErr, otherErr = confinedBind(t, root, n.Pid, sock, addr, func() error {
				fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					c.fatalf(t, "fixture: other thread socket: %v", err)
				}
				defer func() { closed(t, "the other thread's socket", unix.Close(fd)) }()
				return unix.Bind(fd, &unix.SockaddrUnix{Name: other})
			})
			return bindErr
		})
		bind, name := c.expect(t, "bind"), c.expect(t, "name")
		_, statErr := os.Stat(tc.file)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			c.fatalf(t, "stat %s: %v", tc.file, statErr)
		}
		exists := statErr == nil
		held := bind == "0" && bindErr == nil && name == strconv.Quote(tc.addr) && exists
		if !tc.inside {
			held = bindErr != nil && bind == errName(bindErr) && !exists
		}
		claim(t, held, "R7 confined bind %q (inside write root=%v): broker %s, child bind=%s name=%s, file exists=%v",
			tc.addr, tc.inside, errName(bindErr), bind, name, exists)
		claim(t, otherErr == nil, "R7 another test-process thread binding outside the write root meanwhile: %s", errName(otherErr))
	}
	c.wait(t)
}

func TestBrokerProtoBrokerStops(t *testing.T) {
	ln, port := listenTCP(t)
	c := startBrokerChild(t, needNotify, "stops", "", port)
	c.next(t, unix.SYS_CONNECT)
	if got := notifyListeners(t, "self"); got != 1 {
		c.fatalf(t, "test process holds %d listener descriptors, want only the broker's", got)
	}
	if got := notifyListeners(t, strconv.Itoa(c.cmd.Process.Pid)); got != 0 {
		c.fatalf(t, "child holds %d listener descriptors", got)
	}
	if err := c.closeListener(); err != nil {
		c.fatalf(t, "fixture: closing the broker's listener: %v", err)
	}
	var results []string
	held := true
	for _, key := range []string{"connect", "bind", "listen", "connect-again"} {
		got, ok := c.expectWithin(t, key, 10*time.Second)
		if !ok {
			claim(t, false, "R9 after the broker closed the last listener reference, %s was still blocked after 10s with the child alive (earlier: %s); killing the child",
				key, strings.Join(results, " "))
			c.cancel()
			<-c.done
			return
		}
		results = append(results, key+"="+got)
		held = held && got != "0"
	}
	conn := c.accepted(t, ln, 300*time.Millisecond)
	if conn != nil {
		if err := conn.Close(); err != nil {
			c.fatalf(t, "fixture: closing the accepted connection: %v", err)
		}
	}
	claim(t, held && conn == nil, "R9 after the broker closed the last listener reference: %s; listener accepted=%v",
		strings.Join(results, " "), conn != nil)
	c.wait(t)
}

func TestBrokerProtoPassRights(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closed(t, "the socket pair", unix.Close(fds[0])) }()
	defer func() { closed(t, "the socket pair", unix.Close(fds[1])) }()
	if err := unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_PASSRIGHTS, 0); err != nil {
		t.Skipf("setsockopt(SO_PASSRIGHTS=%#x, 0) refused by this kernel: %s", unix.SO_PASSRIGHTS, errName(err))
	}
	sendErr := unix.Sendmsg(fds[0], []byte("L"), unix.UnixRights(fds[0]), nil, 0)
	b, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, recvErr := unix.Recvmsg(fds[1], b, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	var rights []int
	if recvErr == nil && oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			t.Fatalf("parsing control messages: %v", err)
		}
		for i := range msgs {
			got, err := unix.ParseUnixRights(&msgs[i])
			if err == nil {
				rights = append(rights, got...)
			}
		}
	}
	for _, fd := range rights {
		closed(t, "a received descriptor", unix.Close(fd))
	}
	claim(t, len(rights) == 0, "R10 with SO_PASSRIGHTS=0 on the receiver, SCM_RIGHTS is refused: sendmsg=%s recvmsg=%s bytes=%d rights=%d ctrunc=%v",
		errName(sendErr), errName(recvErr), n, len(rights), flags&unix.MSG_CTRUNC != 0)
}
