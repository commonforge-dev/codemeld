package enforce

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func unixDestCaller(t *testing.T, dir string) uint32 {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "30")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return uint32(cmd.Process.Pid)
}

func unixDestAddr(family uint16, path string) []byte {
	return append(binary.NativeEndian.AppendUint16(nil, family), path...)
}

func unixDestListen(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func unixDestDial(t *testing.T, sa *unix.SockaddrUnix) {
	t.Helper()
	s, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(s) }()
	if err := unix.Connect(s, sa); err != nil {
		t.Fatalf("connect through %s: %v", sa.Name, err)
	}
}

func unixDestAccepted(t *testing.T, ln *net.UnixListener, wait time.Duration) bool {
	t.Helper()
	if err := ln.SetDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	c, err := ln.Accept()
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func TestResolveUnixDestRelativeToCallerCwd(t *testing.T) {
	dir := t.TempDir()
	ln := unixDestListen(t, filepath.Join(dir, "s.sock"))
	tid := unixDestCaller(t, dir)
	full := "s.sock\x00" + strings.Repeat("x", unix.SizeofSockaddrUnix-2-len("s.sock\x00"))
	for _, path := range []string{"s.sock", "s.sock\x00", "s.sock\x00junk", full} {
		t.Run(fmt.Sprintf("%q", path), func(t *testing.T) {
			fd, sa, err := resolveUnixDest(tid, unixDestAddr(unix.AF_UNIX, path))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(fd) }()
			unixDestDial(t, sa)
			if !unixDestAccepted(t, ln, 2*time.Second) {
				t.Fatal("the socket in the caller's working folder got no connection")
			}
		})
	}
}

func TestResolveUnixDestRefusals(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	unixDestListen(t, sock)
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unixDestListen(t, filepath.Join(dir, "linked.sock"))
	if err := os.Link(filepath.Join(dir, "linked.sock"), filepath.Join(dir, "second.sock")); err != nil {
		t.Fatal(err)
	}
	held, err := unix.Open(sock, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(held) }()
	tid := unixDestCaller(t, dir)

	for _, c := range []struct {
		name string
		addr []byte
	}{
		{"magic link", unixDestAddr(unix.AF_UNIX, fmt.Sprintf("/proc/self/fd/%d", held))},
		{"regular file", unixDestAddr(unix.AF_UNIX, "file")},
		{"socket with two links", unixDestAddr(unix.AF_UNIX, "linked.sock")},
		{"not a Unix family", unixDestAddr(unix.AF_INET, "s.sock")},
		{"longer than sockaddr_un", unixDestAddr(unix.AF_UNIX, strings.Repeat("./", 55)+"s.sock")},
		{"unnamed", unixDestAddr(unix.AF_UNIX, "")},
		{"abstract", unixDestAddr(unix.AF_UNIX, "\x00s.sock")},
	} {
		t.Run(c.name, func(t *testing.T) {
			fd, _, err := resolveUnixDest(tid, c.addr)
			if err == nil {
				_ = unix.Close(fd)
				t.Fatalf("resolveUnixDest(%q) succeeded", c.addr[2:])
			}
		})
	}
}

func TestResolveUnixDestConnectsTheCheckedSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	checked := unixDestListen(t, sock)
	tid := unixDestCaller(t, dir)
	fd, sa, err := resolveUnixDest(tid, unixDestAddr(unix.AF_UNIX, "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := os.Rename(sock, filepath.Join(dir, "moved.sock")); err != nil {
		t.Fatal(err)
	}
	replacement := unixDestListen(t, sock)

	unixDestDial(t, sa)
	if !unixDestAccepted(t, checked, 2*time.Second) {
		t.Fatal("the checked socket got no connection")
	}
	if unixDestAccepted(t, replacement, 100*time.Millisecond) {
		t.Fatal("the replacement socket got the connection")
	}
}
