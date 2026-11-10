package enforce

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const notifyChildEnv = "CODEMELD_TEST_NOTIFY_CHILD"

const notifyChildBacklog = 7

func TestNotificationLayout(t *testing.T) {
	var n seccompNotification
	var r seccompNotificationResponse
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"notification ID", unsafe.Offsetof(n.ID), 0},
		{"notification Pid", unsafe.Offsetof(n.Pid), 8},
		{"notification Flags", unsafe.Offsetof(n.Flags), 12},
		{"notification Nr", unsafe.Offsetof(n.Nr), 16},
		{"notification Arch", unsafe.Offsetof(n.Arch), 20},
		{"notification IP", unsafe.Offsetof(n.IP), 24},
		{"notification Args", unsafe.Offsetof(n.Args), 32},
		{"notification size", unsafe.Sizeof(n), 0x50},
		{"response ID", unsafe.Offsetof(r.ID), 0},
		{"response Val", unsafe.Offsetof(r.Val), 8},
		{"response Error", unsafe.Offsetof(r.Error), 16},
		{"response Flags", unsafe.Offsetof(r.Flags), 20},
		{"response size", unsafe.Sizeof(r), 0x18},
	} {
		if c.got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, c.got, c.want)
		}
	}
}

func TestNotificationWrappersBadDescriptor(t *testing.T) {
	if _, err := recvNotification(-1); err != unix.EBADF {
		t.Errorf("recvNotification: got %v, want raw EBADF", err)
	}
	if err := sendNotificationResponse(-1, seccompNotificationResponse{ID: 1}); err != unix.EBADF {
		t.Errorf("sendNotificationResponse: got %v, want raw EBADF", err)
	}
	if err := notificationIDValid(-1, 1); err != unix.EBADF {
		t.Errorf("notificationIDValid: got %v, want raw EBADF", err)
	}
}

func TestNotifyChild(t *testing.T) {
	if os.Getenv(notifyChildEnv) == "" {
		t.Skip("runs only as the disposable child of TestNotificationRoundTrip")
	}
	runtime.LockOSThread()
	ctl := os.NewFile(3, "ctl")
	listener, err := installBrokerFilter(false)
	if err != nil {
		if _, werr := fmt.Fprintf(ctl, "E%s\n", errName(err)); werr != nil {
			t.Fatal(werr)
		}
		return
	}
	if err := unix.Sendmsg(3, []byte("L"), unix.UnixRights(listener), nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(listener); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(ctl, "listen=%s\n", errName(unix.Listen(fd, notifyChildBacklog))); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationRoundTrip(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentEnd := os.NewFile(uintptr(fds[0]), "notify-ctl")
	childEnd := os.NewFile(uintptr(fds[1]), "notify-child-ctl")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNotifyChild$")
	cmd.Env = append(os.Environ(), notifyChildEnv+"=1")
	cmd.ExtraFiles = []*os.File{childEnd}
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Start()
	closed(t, "the child's control end", childEnd.Close())
	if err != nil {
		closed(t, "the parent's control end", parentEnd.Close())
		cancel()
		t.Fatal(err)
	}
	var waitErr error
	exited := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()
	listener := -1
	var ctl *net.UnixConn
	t.Cleanup(func() {
		cancel()
		<-exited
		if listener >= 0 {
			closed(t, "the listener", unix.Close(listener))
		}
		if ctl != nil {
			closed(t, "the control connection", ctl.Close())
		}
	})
	fail := func(format string, args ...any) {
		t.Helper()
		cancel()
		<-exited
		t.Fatalf(format+"\nchild (%v) output:\n%s", append(args, waitErr, out.String())...)
	}

	conn, err := net.FileConn(parentEnd)
	closed(t, "the parent's control end", parentEnd.Close())
	if err != nil {
		fail("control socket: %v", err)
	}
	ctl = conn.(*net.UnixConn)
	lines := bufio.NewReader(ctl)
	readLine := func(what string) string {
		t.Helper()
		if err := ctl.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			fail("%v", err)
		}
		line, err := lines.ReadString('\n')
		if err != nil {
			fail("waiting for %s: %v", what, err)
		}
		return strings.TrimSuffix(line, "\n")
	}

	if err := ctl.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		fail("%v", err)
	}
	b, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := ctl.ReadMsgUnix(b, oob)
	if err != nil || n != 1 {
		fail("no listener message from child: %v", err)
	}
	if b[0] == 'E' {
		t.Skipf("unverified: the kernel refused a seccomp filter with a notification listener: %s", readLine("filter error"))
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		fail("listener message: %v", err)
	}
	rights, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(rights) != 1 {
		for _, fd := range rights {
			closed(t, "a received descriptor", unix.Close(fd))
		}
		fail("listener rights %v: %v", rights, err)
	}
	listener = rights[0]

	revents, err := pollFD(listener, unix.POLLIN, 10*time.Second)
	if err != nil || revents&unix.POLLIN == 0 {
		fail("no notification (revents %#x): %v", revents, err)
	}
	notif, err := recvNotification(listener)
	if err != nil {
		fail("recvNotification: %v", err)
	}
	if notif.Nr != unix.SYS_LISTEN || notif.Args[1] != notifyChildBacklog {
		fail("notification for syscall %d backlog %d, want %d backlog %d", notif.Nr, notif.Args[1], unix.SYS_LISTEN, notifyChildBacklog)
	}
	if want, ok := map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}[runtime.GOARCH]; ok && notif.Arch != want {
		fail("notification arch %#x, want %#x", notif.Arch, want)
	}
	if err := notificationIDValid(listener, notif.ID); err != nil {
		fail("notificationIDValid on a pending notification: %v", err)
	}
	resp := seccompNotificationResponse{ID: notif.ID, Error: -int32(unix.ETXTBSY)}
	if err := sendNotificationResponse(listener, resp); err != nil {
		fail("sendNotificationResponse: %v", err)
	}
	if got := readLine("the child's listen result"); got != "listen=ETXTBSY" {
		fail("child saw %q, want listen=ETXTBSY", got)
	}
	if err := notificationIDValid(listener, notif.ID); !errors.Is(err, unix.ENOENT) {
		fail("notificationIDValid on an answered notification: got %v, want ENOENT", err)
	}
	if err := sendNotificationResponse(listener, resp); !errors.Is(err, unix.ENOENT) {
		fail("second sendNotificationResponse: got %v, want ENOENT", err)
	}
	select {
	case <-exited:
	case <-time.After(20 * time.Second):
		fail("child did not exit")
	}
	if waitErr != nil {
		fail("child failed")
	}
}
