package enforce

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const HelperChannelFD = 3

var ErrBrokerUnsupported = errors.New("enforce: broker mode is not supported on this platform")

const (
	handoffListener   = 'L'
	handoffAck        = 'A'
	handoffRelease    = 'R'
	helperReleaseWait = 10 * time.Second
	releaseWriteWait  = 5 * time.Second
)

func handOffListener(p Policy) error {
	fd, err := installSeccompListener(p)
	if err == nil {
		err = sendListener(HelperChannelFD, fd)
	}
	if err == nil {
		err = awaitRelease(HelperChannelFD, time.Now().Add(helperReleaseWait))
	}
	return errors.Join(err, unix.Close(HelperChannelFD))
}

func sendListener(channel, listener int) error {
	err := unix.Sendmsg(channel, []byte{handoffListener}, unix.UnixRights(listener), nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
	if cerr := unix.Close(listener); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("send listener: %w", err)
	}
	if err := unix.Sendmsg(channel, []byte{handoffAck}, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
		return fmt.Errorf("send acknowledgement: %w", err)
	}
	return nil
}

func awaitRelease(channel int, deadline time.Time) error {
	b := make([]byte, 2)
	for {
		if err := waitChannel(channel, unix.POLLIN, deadline); err != nil {
			return fmt.Errorf("await release: %w", err)
		}
		n, _, err := unix.Recvfrom(channel, b, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("await release: %w", err)
		}
		if n != 1 || b[0] != handoffRelease {
			return fmt.Errorf("await release: got %q", b[:n])
		}
		return nil
	}
}

func ReceiveListener(channel *os.File, timeout time.Duration) (*os.File, error) {
	deadline := time.Now().Add(timeout)
	listener := -1
	err := onChannel(channel, func(fd int) (err error) {
		listener, err = receiveListener(fd, deadline)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("enforce: receive listener: %w", err)
	}
	return os.NewFile(uintptr(listener), "seccomp listener"), nil
}

func receiveListener(channel int, deadline time.Time) (int, error) {
	want := string([]byte{handoffListener, handoffAck})
	var got []byte
	var received []int
	fail := func(err error) (int, error) {
		for _, fd := range received {
			_ = unix.Close(fd)
		}
		return -1, err
	}
	buf, oob := make([]byte, 4), make([]byte, unix.CmsgSpace(4*4))
	for string(got) != want {
		if err := waitChannel(channel, unix.POLLIN, deadline); err != nil {
			return fail(err)
		}
		n, oobn, flags, _, err := unix.Recvmsg(channel, buf, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return fail(err)
		}
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return fail(err)
		}
		for i := range msgs {
			fds, err := unix.ParseUnixRights(&msgs[i])
			received = append(received, fds...)
			if err != nil {
				return fail(err)
			}
		}
		switch {
		case flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0:
			return fail(errors.New("truncated message"))
		case n == 0:
			return fail(errors.New("channel closed before the acknowledgement"))
		}
		got = append(got, buf[:n]...)
		if !strings.HasPrefix(want, string(got)) {
			return fail(fmt.Errorf("unexpected handoff bytes %q", got))
		}
	}
	if len(received) != 1 {
		return fail(fmt.Errorf("%d listener descriptors", len(received)))
	}
	return received[0], nil
}

func ReleaseHelper(channel *os.File) error {
	deadline := time.Now().Add(releaseWriteWait)
	if err := onChannel(channel, func(fd int) error { return sendRelease(fd, deadline) }); err != nil {
		return fmt.Errorf("enforce: release helper: %w", err)
	}
	return nil
}

func sendRelease(channel int, deadline time.Time) error {
	for {
		if err := waitChannel(channel, unix.POLLOUT, deadline); err != nil {
			return err
		}
		err := unix.Sendmsg(channel, []byte{handoffRelease}, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
		if err != unix.EAGAIN && err != unix.EINTR {
			return err
		}
	}
}

func onChannel(channel *os.File, f func(int) error) error {
	rc, err := channel.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

func waitChannel(fd int, events int16, deadline time.Time) error {
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return os.ErrDeadlineExceeded
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: events}}, int(left.Milliseconds())+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n > 0 {
			return err
		}
	}
}
