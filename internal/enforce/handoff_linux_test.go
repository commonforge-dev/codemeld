package enforce

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fdCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func handoffPair(t *testing.T) (parent, helper *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, helper = os.NewFile(uintptr(fds[0]), "channel"), os.NewFile(uintptr(fds[1]), "helper channel")
	t.Cleanup(func() { parent.Close(); helper.Close() })
	return parent, helper
}

func rawPipe(t *testing.T) (r, w int) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	return p[0], p[1]
}

func sendRaw(t *testing.T, fd *os.File, data string, rights ...int) {
	t.Helper()
	var oob []byte
	if len(rights) > 0 {
		oob = unix.UnixRights(rights...)
	}
	if err := unix.Sendmsg(int(fd.Fd()), []byte(data), oob, nil, 0); err != nil {
		t.Fatalf("fixture: sending %q: %v", data, err)
	}
}

func channelOpen(t *testing.T, f *os.File) {
	t.Helper()
	if _, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err != nil {
		t.Errorf("the channel was closed: %v", err)
	}
}

func TestListenerHandoffRoundTrip(t *testing.T) {
	before := fdCount(t)
	parent, helper := handoffPair(t)
	r, w := rawPipe(t)
	if err := sendListener(int(helper.Fd()), w); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(w), unix.F_GETFD, 0); err != unix.EBADF {
		t.Errorf("the sender kept its listener copy: F_GETFD = %v", err)
	}
	l, err := ReceiveListener(parent, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if flags, err := unix.FcntlInt(l.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("received listener flags %#x, %v: want FD_CLOEXEC", flags, err)
	}
	if _, err := l.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if n, err := unix.Read(r, b); n != 1 || err != nil || b[0] != 'x' {
		t.Errorf("the received descriptor is not the sent one: %q %v", b[:n], err)
	}
	if err := ReleaseHelper(parent); err != nil {
		t.Fatal(err)
	}
	if err := awaitRelease(int(helper.Fd()), time.Now().Add(5*time.Second)); err != nil {
		t.Errorf("helper did not see the release: %v", err)
	}
	channelOpen(t, parent)
	l.Close()
	parent.Close()
	helper.Close()
	_ = unix.Close(r)
	if after := fdCount(t); after != before {
		t.Errorf("descriptors %d after the handoff, %d before", after, before)
	}
}

func TestReceiveListenerRejectsMalformedHandoffs(t *testing.T) {
	copies := func(w, n int) []int {
		s := make([]int, n)
		for i := range s {
			s[i] = w
		}
		return s
	}
	for _, c := range []struct {
		name    string
		timeout time.Duration
		send    func(t *testing.T, helper *os.File, w int)
	}{
		{"nothing sent", 300 * time.Millisecond, func(*testing.T, *os.File, int) {}},
		{"acknowledgement without listener", 0, func(t *testing.T, h *os.File, _ int) { sendRaw(t, h, "A") }},
		{"listener then channel closed", 0, func(t *testing.T, h *os.File, w int) { sendRaw(t, h, "L", w); h.Close() }},
		{"listener without acknowledgement", 300 * time.Millisecond, func(t *testing.T, h *os.File, w int) { sendRaw(t, h, "L", w) }},
		{"listener byte without descriptor", 0, func(t *testing.T, h *os.File, _ int) { sendRaw(t, h, "L"); sendRaw(t, h, "A") }},
		{"two descriptors", 0, func(t *testing.T, h *os.File, w int) { sendRaw(t, h, "L", w, w); sendRaw(t, h, "A") }},
		{"descriptor on the acknowledgement", 0, func(t *testing.T, h *os.File, w int) { sendRaw(t, h, "L", w); sendRaw(t, h, "A", w) }},
		{"wrong first byte with listener queued", 0, func(t *testing.T, h *os.File, w int) { sendRaw(t, h, "X"); sendRaw(t, h, "L", w); sendRaw(t, h, "A") }},
		{"extra byte before acknowledgement", 0, func(t *testing.T, h *os.File, w int) { sendRaw(t, h, "L", w); sendRaw(t, h, "BA") }},
		{"more descriptors than the receive buffer", 0, func(t *testing.T, h *os.File, w int) { sendRaw(t, h, "L", copies(w, 20)...); sendRaw(t, h, "A") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := fdCount(t)
			parent, helper := handoffPair(t)
			r, w := rawPipe(t)
			c.send(t, helper, w)
			_ = unix.Close(w)
			timeout := c.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			start := time.Now()
			l, err := ReceiveListener(parent, timeout)
			if elapsed := time.Since(start); elapsed > timeout+2*time.Second {
				t.Errorf("rejection took %v with a %v budget", elapsed, timeout)
			}
			if err == nil || l != nil {
				t.Fatalf("accepted: %v, %v", l, err)
			}
			if timedOut := errors.Is(err, os.ErrDeadlineExceeded); timedOut != (c.timeout != 0) {
				t.Errorf("err = %v, want a deadline error only for a %v budget", err, c.timeout)
			}
			channelOpen(t, parent)
			parent.Close()
			helper.Close()
			if revents, err := pollFD(r, unix.POLLIN, 0); err != nil || revents&unix.POLLHUP == 0 {
				t.Errorf("a sent descriptor copy is still open (revents %#x, %v)", revents, err)
			}
			_ = unix.Close(r)
			if after := fdCount(t); after != before {
				t.Errorf("descriptors %d after the rejection, %d before", after, before)
			}
		})
	}
}

func TestReceiveListenerBudgetCoversWholeHandoff(t *testing.T) {
	parent, helper := handoffPair(t)
	r, w := rawPipe(t)
	defer func() { _ = unix.Close(r) }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(300 * time.Millisecond)
		_ = unix.Sendmsg(int(helper.Fd()), []byte("L"), unix.UnixRights(w), nil, 0)
		_ = unix.Close(w)
		time.Sleep(400 * time.Millisecond)
		_ = unix.Sendmsg(int(helper.Fd()), []byte("A"), nil, nil, 0)
	}()
	l, err := ReceiveListener(parent, 500*time.Millisecond)
	<-done
	if err == nil {
		l.Close()
		t.Fatal("an acknowledgement after the budget was accepted")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("err = %v, want a deadline error", err)
	}
}

func TestSendReleaseIsBounded(t *testing.T) {
	parent, _ := handoffPair(t)
	fd := int(parent.Fd())
	chunk := make([]byte, 1<<16)
	for {
		if err := unix.Sendmsg(fd, chunk, nil, nil, unix.MSG_DONTWAIT); err == unix.EAGAIN {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	got := make(chan error, 1)
	go func() { got <- sendRelease(fd, time.Now().Add(300*time.Millisecond)) }()
	select {
	case err := <-got:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("err = %v, want a deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the release write was not bounded")
	}
}

func TestAwaitRelease(t *testing.T) {
	for _, c := range []struct {
		name string
		send func(t *testing.T, parent *os.File)
		ok   bool
	}{
		{"release", func(t *testing.T, p *os.File) { sendRaw(t, p, "R") }, true},
		{"wrong byte", func(t *testing.T, p *os.File) { sendRaw(t, p, "X") }, false},
		{"extra byte", func(t *testing.T, p *os.File) { sendRaw(t, p, "RR") }, false},
		{"channel closed", func(_ *testing.T, p *os.File) { p.Close() }, false},
		{"withheld", func(*testing.T, *os.File) {}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			parent, helper := handoffPair(t)
			c.send(t, parent)
			start := time.Now()
			err := awaitRelease(int(helper.Fd()), time.Now().Add(300*time.Millisecond))
			if (err == nil) != c.ok {
				t.Errorf("err = %v, want ok=%v", err, c.ok)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("waited %v", elapsed)
			}
		})
	}
}
