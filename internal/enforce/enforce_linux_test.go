//go:build linux

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
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"codemeld.dev/codemeld/internal/runner"
	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/sys/unix"
)

const (
	forceABI2Env = "CODEMELD_TEST_FORCE_LANDLOCK_ABI2"
	mxBadFD      = uintptr(0x7ffffffe)
	mxBadKey     = uintptr(0x6d61747a)
)

func init() {
	if os.Getenv(forceABI2Env) != "" {
		landlockABI = func() (int, error) { return 2, nil }
	}
	probes["m-core"] = probe{0, mxCoreProbe}
	probes["m-sockets"] = probe{0, mxSocketsProbe}
	probes["m-pair-isolation"] = probe{6, mxPairIsolationProbe}
	probes["m-clone"] = probe{0, mxCloneProbe}
	probes["m-meta"] = probe{1, mxMetaProbe}
	probes["m-x32"] = probe{0, mxX32Probe}
	probes["m-open-write"] = probe{1, mxProbe(func(p string) error {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_ = f.Close()
		}
		return err
	})}
	probes["m-write-existing"] = probe{1, mxProbe(func(p string) error {
		f, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err == nil {
			_ = f.Close()
		}
		return err
	})}
	probes["m-truncate"] = probe{1, mxProbe(func(p string) error { return os.Truncate(p, 0) })}
	probes["m-read"] = probe{1, mxProbe(func(p string) error {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = f.Read(make([]byte, 1))
		return err
	})}
	probes["m-readdir"] = probe{1, mxProbe(func(p string) error { _, err := os.ReadDir(p); return err })}
	probes["m-chmod-ok"] = probe{1, mxProbe(func(p string) error { return os.Chmod(p, 0o600) })}
	probes["m-hardlink"] = probe{2, func(a []string) int { return mxEmit("result", mxErrno(unix.Link(a[0], a[1]))) }}
	probes["m-reopen-fd"] = probe{1, mxReopenFDProbe}
	probes["m-snapshot"] = probe{1, mxSnapshotProbe}
	probes["m-all-threads"] = probe{1, mxAllThreadsProbe}
	probes["m-proc-access"] = probe{3, mxProcAccessProbe}
}

func mxEmit(key string, errno unix.Errno) int {
	fmt.Printf("%s=%d\n", key, int(errno))
	return probeAllowed
}

func mxErrno(err error) unix.Errno {
	if err == nil {
		return 0
	}
	var e unix.Errno
	if errors.As(err, &e) {
		return e
	}
	return unix.Errno(0xffff)
}

func mxProbe(f func(string) error) func([]string) int {
	return func(a []string) int { return mxEmit("result", mxErrno(f(a[0]))) }
}

func mxSyscall(nr uintptr, args ...uintptr) unix.Errno {
	var a [6]uintptr
	copy(a[:], args)
	_, _, e := unix.Syscall6(nr, a[0], a[1], a[2], a[3], a[4], a[5])
	return e
}

type mxCall struct {
	name string
	fn   func(nr uintptr) unix.Errno
}

// Arguments must fail benignly when unconfined so an unrestricted control run touches no shared kernel object.
func mxCoreCalls() []mxCall {
	return []mxCall{
		{"io_uring_setup", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0, 0) }},
		{"io_uring_enter", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0, 0, 0, 0) }},
		{"io_uring_register", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0, 0) }},
		{"shmget", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadKey, 0, 0) }},
		{"shmat", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0) }},
		{"shmctl", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 2, 0) }},
		{"msgget", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadKey, 0) }},
		{"msgsnd", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0, 0) }},
		{"msgrcv", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0, 0, 0) }},
		{"msgctl", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 2, 0) }},
		{"semget", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadKey, 0, 0) }},
		{"semop", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0) }},
		{"semtimedop", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0, 0) }},
		{"semctl", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 2, 0) }},
		{"mq_open", func(nr uintptr) unix.Errno {
			name, _ := unix.BytePtrFromString("/codemeld-matrix-absent")
			e := mxSyscall(nr, uintptr(unsafe.Pointer(name)), uintptr(unix.O_RDONLY), 0)
			runtime.KeepAlive(name)
			return e
		}},
		{"unshare", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0) }},
		{"setns", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0) }},
		{"mount", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0, 0, 0, 0, 0) }},
		{"umount2", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0, 0) }},
		{"pivot_root", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0, 0) }},
		{"fsopen", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0, 0) }},
		{"fsconfig", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0, 0, 0) }},
		{"fsmount", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0) }},
		{"fspick", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0) }},
		{"move_mount", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, mxBadFD, 0, 0) }},
		{"open_tree", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0) }},
		{"mount_setattr", func(nr uintptr) unix.Errno { return mxSyscall(nr, mxBadFD, 0, 0, 0, 0) }},
		{"chroot", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0) }},
		{"bpf", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0, 0, 0) }},
		{"clone3", func(nr uintptr) unix.Errno { return mxSyscall(nr, 0, 0) }},
	}
}

func mxCoreProbe([]string) int {
	info, err := arch.GetInfo("")
	if err != nil {
		fmt.Printf("arch=-1\n")
		return probeFailed
	}
	for _, c := range mxCoreCalls() {
		nr, ok := info.SyscallNames[c.name]
		if !ok {
			fmt.Printf("%s=-2\n", c.name)
			continue
		}
		mxEmit(c.name, c.fn(uintptr(nr)))
	}
	return probeAllowed
}

type mxSocketCase struct {
	name        string
	domain, typ int
}

func mxSocketCases() []mxSocketCase {
	return []mxSocketCase{
		{"unix", unix.AF_UNIX, unix.SOCK_STREAM},
		{"inet", unix.AF_INET, unix.SOCK_STREAM},
		{"inet6", unix.AF_INET6, unix.SOCK_STREAM},
		{"netlink", unix.AF_NETLINK, unix.SOCK_RAW},
		{"packet", unix.AF_PACKET, unix.SOCK_RAW},
		{"inet-raw", unix.AF_INET, unix.SOCK_RAW},
		{"inet6-raw", unix.AF_INET6, unix.SOCK_RAW},
	}
}

func mxSocketsProbe([]string) int {
	for _, c := range mxSocketCases() {
		fd, err := unix.Socket(c.domain, c.typ|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		mxEmit(c.name, mxErrno(err))
	}
	for _, c := range []mxSocketCase{{"socketpair", unix.AF_UNIX, unix.SOCK_STREAM}, {"socketpair-seqpacket", unix.AF_UNIX, unix.SOCK_SEQPACKET}} {
		fds, err := unix.Socketpair(c.domain, c.typ|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		mxEmit(c.name, mxErrno(err))
		if err == nil {
			mxEmit(c.name+"-exchange", mxErrno(mxExchange(fds[0], fds[1])))
			_ = unix.Close(fds[0])
			_ = unix.Close(fds[1])
		}
	}
	for _, c := range mxPairTypeCases() {
		fds, err := unix.Socketpair(c.domain, c.typ|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fds[0])
			_ = unix.Close(fds[1])
		}
		mxEmit(c.name, mxErrno(err))
	}
	return probeAllowed
}

func mxPairTypeCases() []mxSocketCase {
	return []mxSocketCase{
		{"socketpair-dgram", unix.AF_UNIX, unix.SOCK_DGRAM},
	}
}

func mxExchange(a, b int) error {
	for _, dir := range [][2]int{{a, b}, {b, a}} {
		if _, err := unix.Write(dir[0], []byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 8)
		n, err := unix.Read(dir[1], buf)
		if err != nil {
			return err
		}
		if string(buf[:n]) != "ping" {
			return unix.EIO
		}
	}
	return nil
}

type mxPairType struct {
	name, network string
	sotype        int
}

func mxPairTypes() []mxPairType {
	return []mxPairType{{"stream", "unix", unix.SOCK_STREAM}, {"seqpacket", "unixpacket", unix.SOCK_SEQPACKET}}
}

type mxPairCase struct {
	typ         mxPairType
	end         int
	state, kind string
}

func (c mxPairCase) label() string {
	return fmt.Sprintf("%s-e%d-%s-%s", c.typ.name, c.end, c.state, c.kind)
}

func mxPairCases() []mxPairCase {
	var out []mxPairCase
	for _, typ := range mxPairTypes() {
		for end := range 2 {
			for _, state := range []string{"open", "shutdown", "closed"} {
				for _, kind := range []string{"path", "abstract"} {
					out = append(out, mxPairCase{typ, end, state, kind})
				}
			}
		}
	}
	return out
}

func mxPairIsolationProbe(a []string) int {
	outsides := map[string][]string{}
	for i, typ := range mxPairTypes() {
		outsides[typ.name] = a[2*i : 2*i+2]
	}
	bindDir, abstractPrefix := a[4], a[5]
	for _, c := range mxPairCases() {
		label := c.label()
		outsidePath, outsideAbstract := outsides[c.typ.name][0], outsides[c.typ.name][1]
		fds, err := unix.Socketpair(unix.AF_UNIX, c.typ.sotype|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			mxEmit(label+"-pair", mxErrno(err))
			continue
		}
		e, peer := fds[c.end], fds[1-c.end]
		switch c.state {
		case "shutdown":
			_ = unix.Shutdown(peer, unix.SHUT_RDWR)
		case "closed":
			_ = unix.Close(peer)
		}
		var unspec [16]byte
		_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(e), uintptr(unsafe.Pointer(&unspec)), uintptr(len(unspec)))
		mxEmit(label+"-unspec", errno)
		mxEmit(label+"-connect-path", mxErrno(unix.Connect(e, &unix.SockaddrUnix{Name: outsidePath})))
		mxEmit(label+"-connect-abstract", mxErrno(unix.Connect(e, &unix.SockaddrUnix{Name: "@" + outsideAbstract})))
		name := filepath.Join(bindDir, label)
		if c.kind == "abstract" {
			name = "@" + abstractPrefix + label
		}
		err = unix.Bind(e, &unix.SockaddrUnix{Name: name})
		mxEmit(label+"-bind", mxErrno(err))
		mxEmit(label+"-listen", mxErrno(unix.Listen(e, 1)))
		if err == nil {
			fmt.Printf("await=%s %s\n", label, name)
			if _, err := os.Stdin.Read(make([]byte, 1)); err != nil {
				return probeFailed
			}
		}
		nfd, _, err := unix.Accept4(e, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err == nil {
			_ = unix.Close(nfd)
		}
		mxEmit(label+"-accept", mxErrno(err))
		_ = unix.Close(e)
		if c.state != "closed" {
			_ = unix.Close(peer)
		}
	}
	return probeAllowed
}

func mxCloneFlags() []struct {
	name string
	flag uintptr
} {
	return []struct {
		name string
		flag uintptr
	}{
		{"newns", unix.CLONE_NEWNS},
		{"newcgroup", unix.CLONE_NEWCGROUP},
		{"newuts", unix.CLONE_NEWUTS},
		{"newipc", unix.CLONE_NEWIPC},
		{"newuser", unix.CLONE_NEWUSER},
		{"newpid", unix.CLONE_NEWPID},
		{"newnet", unix.CLONE_NEWNET},
		{"newtime", unix.CLONE_NEWTIME},
	}
}

func mxCloneProbe([]string) int {
	for _, c := range mxCloneFlags() {
		pid, err := syscall.ForkExec("/bin/true", []string{"/bin/true"}, &syscall.ProcAttr{
			Sys: &syscall.SysProcAttr{Cloneflags: c.flag},
		})
		if err == nil {
			_, _ = waitBounded(pid, selfTestTimeout)
		}
		mxEmit(c.name, mxErrno(err))
	}
	return probeAllowed
}

func mxMetaProbe(a []string) int {
	info, err := arch.GetInfo("")
	if err != nil {
		fmt.Printf("arch=-1\n")
		return probeFailed
	}
	fd, err := unix.Open(a[0], unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Printf("open=-1\n")
		return probeFailed
	}
	defer func() { _ = unix.Close(fd) }()
	pp, _ := unix.BytePtrFromString(a[0])
	attr, _ := unix.BytePtrFromString("user.codemeld")
	var val [4]byte
	var fsx [28]byte
	var flagBuf int32
	p := func(b *byte) uintptr { return uintptr(unsafe.Pointer(b)) }
	atfdcwd := unix.AT_FDCWD
	cwd := uintptr(atfdcwd)
	m1 := ^uintptr(0)
	entries := []struct {
		name string
		args []uintptr
	}{
		{"chmod", []uintptr{p(pp), 0o600}},
		{"fchmod", []uintptr{uintptr(fd), 0o600}},
		{"fchmodat", []uintptr{cwd, p(pp), 0o600}},
		{"fchmodat2", []uintptr{cwd, p(pp), 0o600, 0}},
		{"chown", []uintptr{p(pp), m1, m1}},
		{"fchown", []uintptr{uintptr(fd), m1, m1}},
		{"lchown", []uintptr{p(pp), m1, m1}},
		{"fchownat", []uintptr{cwd, p(pp), m1, m1, 0}},
		{"setxattr", []uintptr{p(pp), p(attr), p(&val[0]), uintptr(len(val)), 0}},
		{"lsetxattr", []uintptr{p(pp), p(attr), p(&val[0]), uintptr(len(val)), 0}},
		{"fsetxattr", []uintptr{uintptr(fd), p(attr), p(&val[0]), uintptr(len(val)), 0}},
		{"removexattr", []uintptr{p(pp), p(attr)}},
		{"lremovexattr", []uintptr{p(pp), p(attr)}},
		{"fremovexattr", []uintptr{uintptr(fd), p(attr)}},
		{"utime", []uintptr{p(pp), 0}},
		{"utimes", []uintptr{p(pp), 0}},
		{"futimesat", []uintptr{cwd, p(pp), 0}},
		{"utimensat", []uintptr{cwd, p(pp), 0, 0}},
	}
	for _, e := range entries {
		nr, ok := info.SyscallNames[e.name]
		if !ok {
			fmt.Printf("%s=-2\n", e.name)
			continue
		}
		mxEmit(e.name, mxSyscall(uintptr(nr), e.args...))
	}
	ioctlNr, ok := info.SyscallNames["ioctl"]
	if ok {
		mxEmit("ioctl-setflags", mxSyscall(uintptr(ioctlNr), uintptr(fd), uintptr(unix.FS_IOC_SETFLAGS), p((*byte)(unsafe.Pointer(&flagBuf)))))
		mxEmit("ioctl-fssetxattr", mxSyscall(uintptr(ioctlNr), uintptr(fd), uintptr(fsIocFssetxattr), p(&fsx[0])))
	}
	runtime.KeepAlive(pp)
	runtime.KeepAlive(attr)
	return probeAllowed
}

func mxX32Probe([]string) int {
	_, _, errno := unix.RawSyscall(unix.SYS_GETPID|x32SyscallBit, 0, 0, 0)
	return mxEmit("x32", errno)
}

func mxReopenFDProbe(a []string) int {
	f, err := os.Open(a[0])
	if err != nil {
		fmt.Printf("open=-1\n")
		return probeFailed
	}
	defer func() { _ = f.Close() }()
	g, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), os.O_WRONLY, 0)
	if err == nil {
		_ = g.Close()
	}
	return mxEmit("result", mxErrno(err))
}

func mxSnapshotProbe(a []string) int {
	fmt.Println("ready")
	if _, err := os.Stdin.Read(make([]byte, 1)); err != nil {
		fmt.Printf("setup=-1\n")
		return probeFailed
	}
	f, err := os.Open(a[0])
	if err == nil {
		_ = f.Close()
	}
	return mxEmit("result", mxErrno(err))
}

func mxAllThreadsProbe(a []string) int {
	runtime.GOMAXPROCS(max(4, runtime.NumCPU()))
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		fmt.Printf("tasks=-1\n")
		return probeFailed
	}
	for _, e := range tasks {
		data, err := os.ReadFile("/proc/self/task/" + e.Name() + "/status")
		if err != nil {
			continue
		}
		if !strings.Contains(string(data), "NoNewPrivs:\t1") {
			fmt.Printf("nnp=0\n")
			return probeFailed
		}
	}
	bp, _ := unix.BytePtrFromString(a[0])
	atfdcwd := unix.AT_FDCWD
	_, _, errno := syscall.AllThreadsSyscall6(unix.SYS_OPENAT, uintptr(atfdcwd), uintptr(unsafe.Pointer(bp)), uintptr(os.O_WRONLY), 0, 0, 0)
	runtime.KeepAlive(bp)
	if errno != unix.EACCES && errno != unix.EPERM {
		fmt.Printf("allthreads-open=%d\n", int(errno))
		return probeFailed
	}
	var bad int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			for j := 0; j < 400; j++ {
				f, err := os.OpenFile(a[0], os.O_WRONLY, 0)
				if err == nil {
					_ = f.Close()
					atomic.AddInt32(&bad, 1)
					return
				}
				if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
					atomic.AddInt32(&bad, 1)
					return
				}
			}
		}()
	}
	wg.Wait()
	if atomic.LoadInt32(&bad) != 0 {
		fmt.Printf("worker=bad\n")
		return probeFailed
	}
	fmt.Printf("allthreads=ok\n")
	return probeAllowed
}

// The write-back bytes equal the target's current environment bytes, so a successful unconfined control leaves it unchanged.
func mxProcAccessProbe(a []string) int {
	pid, err := strconv.Atoi(a[0])
	if err != nil {
		return probeFailed
	}
	addr, err := strconv.ParseUint(a[1], 0, 64)
	if err != nil || a[2] == "" {
		return probeFailed
	}
	fmt.Printf("target=%d\n", pid)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err = unix.PtraceAttach(pid)
	if err == nil {
		_, _ = unix.Wait4(pid, nil, unix.WALL, nil)
		_ = unix.PtraceDetach(pid)
	}
	mxEmit("ptrace", mxErrno(err))
	content := []byte(a[2])
	buf := make([]byte, len(content))
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(content)}}
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(len(buf))
	_, err = unix.ProcessVMReadv(pid, local, remote, 0)
	mxEmit("process_vm_readv", mxErrno(err))
	local[0].Base = &content[0]
	_, err = unix.ProcessVMWritev(pid, local, remote, 0)
	mxEmit("process_vm_writev", mxErrno(err))
	f, err := os.Open(fmt.Sprintf("/proc/%d/environ", pid))
	if err == nil {
		_, err = f.Read(make([]byte, 1))
		_ = f.Close()
	}
	mxEmit("environ", mxErrno(err))
	return probeAllowed
}

var (
	mxBinOnce  sync.Once
	mxBinBytes []byte
	mxBinErr   error
)

func mxBinary(t *testing.T) string {
	t.Helper()
	mxBinOnce.Do(func() { mxBinBytes, mxBinErr = mxBuildBinary() })
	if mxBinErr != nil {
		t.Fatalf("helper test binary: %v", mxBinErr)
	}
	dir, err := os.MkdirTemp("/var/tmp", "codemeld-matrix-bin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "enforce.test")
	if err := os.WriteFile(bin, mxBinBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func mxBuildBinary() ([]byte, error) {
	dir, err := os.MkdirTemp("/var/tmp", "codemeld-matrix-bin-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	bin := filepath.Join(dir, "enforce.test")
	cmd := exec.CommandContext(ctx, "go", "test", "-c", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build cgo-free helper test binary: %v\n%s", err, out)
	}
	return os.ReadFile(bin)
}

func mxRequire(t *testing.T) {
	t.Helper()
	abi, err := landlockABI()
	if err != nil || abi < 3 {
		t.Skipf("real-kernel matrix skipped: landlock ABI 3 unavailable (abi %d, err %v)", abi, err)
	}
	if !seccomp.Supported() {
		t.Skip("real-kernel matrix skipped: seccomp unavailable")
	}
}

type mxFx struct {
	base, home, sharedTmp string
}

func mxSetup(t *testing.T) mxFx {
	t.Helper()
	base, err := os.MkdirTemp("/var/tmp", "codemeld-matrix-")
	if err != nil {
		t.Fatal(err)
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(filepath.Join(home, ".codemeld", "global"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codemeld", "global", "settings.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return mxFx{base: base, home: home, sharedTmp: st}
}

func (f mxFx) blocked(extra ...string) []string {
	return append([]string{filepath.Join(f.home, ".codemeld"), f.sharedTmp}, extra...)
}

func (f mxFx) env(t *testing.T, dir, tmp string) []string {
	t.Helper()
	e, err := runner.FixedEnvironment(f.home, dir, tmp, runner.FixedPATH, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (f mxFx) mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{f.base}, parts...)...)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f mxFx) writeFile(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{f.base}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type mxResult struct {
	code     int
	signal   syscall.Signal
	timedOut bool
	lines    map[string]int
	stdout   string
	stderr   string
}

func mxRun(t *testing.T, bin, mode string, p Policy, dir string, env []string, args ...string) mxResult {
	t.Helper()
	var frame bytes.Buffer
	if err := WritePolicyFrame(&frame, p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	argv := []string{HelperCommand}
	if mode != "" {
		argv = append(argv, mode)
	}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, bin, argv...)
	cmd.Env, cmd.Dir, cmd.Stdin = env, dir, bytes.NewReader(frame.Bytes())
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	res := mxResult{code: -1, stdout: out.String(), stderr: errb.String(), lines: map[string]int{}}
	for _, ln := range strings.Split(res.stdout, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(ln), "="); ok {
			if n, e := strconv.Atoi(v); e == nil {
				res.lines[k] = n
			}
		}
	}
	switch {
	case ctx.Err() != nil:
		res.timedOut = true
	case err == nil:
		res.code = 0
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.code = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				res.signal = ws.Signal()
			}
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return res
}

func mxWant(t *testing.T, label string, res mxResult, key string, want unix.Errno) {
	t.Helper()
	got, ok := res.lines[key]
	if !ok {
		t.Errorf("%s: %s: no result line (code %d sig %v stdout %q stderr %q)", label, key, res.code, res.signal, res.stdout, res.stderr)
		return
	}
	if got != int(want) {
		t.Errorf("%s: %s: errno %d, want %d", label, key, got, int(want))
	}
}

func mxWantOneOf(t *testing.T, label string, res mxResult, key string, want ...unix.Errno) {
	t.Helper()
	got, ok := res.lines[key]
	if !ok {
		t.Errorf("%s: %s: no result line (code %d sig %v stdout %q stderr %q)", label, key, res.code, res.signal, res.stdout, res.stderr)
		return
	}
	if !slices.ContainsFunc(want, func(e unix.Errno) bool { return int(e) == got }) {
		t.Errorf("%s: %s: errno %d, want one of %v", label, key, got, want)
	}
}

func mxComplete(t *testing.T, label string, res mxResult, keys ...string) {
	t.Helper()
	if res.timedOut || res.signal != 0 || res.code != probeAllowed {
		t.Fatalf("%s: run did not complete: code %d sig %v timed out %v (stdout %q stderr %q)", label, res.code, res.signal, res.timedOut, res.stdout, res.stderr)
	}
	for _, k := range keys {
		if _, ok := res.lines[k]; !ok {
			t.Fatalf("%s: no %s report (stdout %q stderr %q)", label, k, res.stdout, res.stderr)
		}
	}
}

type mxVariant struct {
	name, authority string
	auto            bool
}

var (
	mxPlanAutoNet = []mxVariant{{"plan", "", false}, {"auto", "", true}, {"net", NetworkAccessAuthority, true}}
	mxAutoNet     = mxPlanAutoNet[1:]
)

func (f mxFx) policy(v mxVariant, writeRoots, noWrite []string, tmp string, extra ...string) Policy {
	if !v.auto {
		return mxPlan(f, extra...)
	}
	return mxAuto(f, writeRoots, noWrite, tmp, v.authority, extra...)
}

func (f mxFx) tmpFor(t *testing.T, v mxVariant) string {
	t.Helper()
	if !v.auto {
		return ""
	}
	return f.mkdir(t, "tmp")
}

func mxTarget(t *testing.T, bin string) (pid int, envStart uint64, content string) {
	t.Helper()
	content = ptraceTargetEnv + "=1"
	cmd := exec.Command(bin)
	cmd.Env = []string{content}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if err := stdout.(*os.File).SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("process-access target not ready: %q, %v", line, err)
	}
	pid = cmd.Process.Pid
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	if len(fields) < 48 {
		t.Fatalf("short /proc/%d/stat: %q", pid, stat)
	}
	envStart, err = strconv.ParseUint(fields[47], 10, 64)
	if err != nil || envStart == 0 {
		t.Fatalf("target env_start %q: %v", fields[47], err)
	}
	environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || string(environ) != content+"\x00" {
		t.Fatalf("target environment %q, %v; want %q", environ, err, content)
	}
	return pid, envStart, content
}

func mxPlan(f mxFx, extra ...string) Policy {
	return Policy{Mode: ModePlan, BlockedPaths: f.blocked(extra...)}
}

func mxAuto(f mxFx, writeRoots, noWrite []string, tmp, authority string, extra ...string) Policy {
	return Policy{
		Mode:                 ModeAutoEdits,
		ExceptionalAuthority: authority,
		BlockedPaths:         f.blocked(extra...),
		WriteRoots:           writeRoots,
		NoWritePaths:         noWrite,
		TmpDir:               tmp,
	}
}

func TestEnforceHostInfo(t *testing.T) {
	abi, err := landlockABI()
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	t.Logf("arch=%s kernel=%s landlockABI=%d (err %v) seccompSupported=%v", runtime.GOARCH,
		unix.ByteSliceToString(uts.Release[:]), abi, err, seccomp.Supported())
}

func TestEnforceEnvironment(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	tmp := f.mkdir(t, "tmp")
	plan := mxRun(t, bin, ProbeArg, mxPlan(f), f.base, f.env(t, f.base, ""), "environment", f.home, f.base, "")
	if plan.code != probeAllowed {
		t.Errorf("plan environment: code %d, want %d (stderr %q)", plan.code, probeAllowed, plan.stderr)
	}
	auto := mxRun(t, bin, ProbeArg, mxAuto(f, []string{tmp}, nil, tmp, ""), f.base, f.env(t, f.base, tmp), "environment", f.home, f.base, tmp)
	if auto.code != probeAllowed {
		t.Errorf("auto environment: code %d, want %d (stderr %q)", auto.code, probeAllowed, auto.stderr)
	}
}

func TestEnforceRlimits(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	res := mxRun(t, bin, ProbeArg, mxPlan(f), f.base, f.env(t, f.base, ""), "rlimits")
	if res.code != probeAllowed {
		t.Errorf("rlimits: code %d, want %d (the probe validates 8 GiB RLIMIT_FSIZE and command-start RLIMIT_NPROC); stderr %q", res.code, probeAllowed, res.stderr)
	}
}

func TestEnforceAllThreadsRestricted(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	readFile := f.writeFile(t, "fx", "r")
	for i := 0; i < 5; i++ {
		res := mxRun(t, bin, ProbeArg, mxPlan(f), f.base, f.env(t, f.base, ""), "m-all-threads", readFile)
		if res.code != probeAllowed || res.lines == nil {
			t.Fatalf("run %d: all-threads restriction not uniform: code %d stdout %q stderr %q", i, res.code, res.stdout, res.stderr)
		}
	}
}

func TestEnforcePlanFilesystemDenials(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	readFile := f.writeFile(t, "fx", "r")
	outside := f.writeFile(t, "outside", "target")
	link := filepath.Join(f.base, "fx", "link-outside")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	env := f.env(t, f.base, "")
	plan := mxPlan(f)

	cases := []struct {
		name string
		args []string
		want unix.Errno
	}{
		{"write-outside", []string{"m-open-write", filepath.Join(f.base, "outside", "new")}, unix.EACCES},
		{"write-through-symlink", []string{"m-write-existing", link}, unix.EACCES},
		{"read-home-codemeld", []string{"m-read", filepath.Join(f.home, ".codemeld", "global", "settings.yaml")}, unix.EACCES},
		{"read-read-root", []string{"m-read", readFile}, 0},
	}
	for _, c := range cases {
		res := mxRun(t, bin, ProbeArg, plan, f.base, env, c.args...)
		mxWant(t, "plan/"+c.name, res, "result", c.want)
	}
	if _, err := os.Stat(filepath.Join(f.base, "outside", "new")); err == nil {
		t.Error("write-outside created a file despite denial")
	}

	if res := mxRun(t, bin, ProbeArg, plan, f.base, env, "no-new-privs"); res.code != probeAllowed {
		t.Errorf("no-new-privs: code %d, want %d", res.code, probeAllowed)
	}
}

func TestEnforceNonWritableFileDenials(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxPlanAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			readFile := f.writeFile(t, "fx", "r")
			wr := f.mkdir(t, "wr")
			wrFile := f.writeFile(t, "wr", "neighbor")
			hard := filepath.Join(wr, "hard")
			tmp := f.tmpFor(t, v)
			env := f.env(t, f.base, tmp)
			p := f.policy(v, []string{wr}, nil, tmp)
			for _, c := range []struct {
				name string
				args []string
				want []unix.Errno
			}{
				{"hardlink-into-root", []string{"m-hardlink", readFile, hard}, []unix.Errno{unix.EACCES, unix.EXDEV}},
				{"reopen-for-write", []string{"m-reopen-fd", readFile}, []unix.Errno{unix.EACCES}},
				{"truncate", []string{"m-truncate", readFile}, []unix.Errno{unix.EACCES}},
			} {
				label := v.name + "/" + c.name
				res := mxRun(t, bin, ProbeArg, p, f.base, env, c.args...)
				mxComplete(t, label, res, "result")
				mxWantOneOf(t, label, res, "result", c.want...)
			}
			if got, err := os.ReadFile(readFile); err != nil || string(got) != "content" {
				t.Errorf("%s: non-writable source changed: %q, %v", v.name, got, err)
			}
			if _, err := os.Lstat(hard); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: denied hardlink left %s behind (%v)", v.name, hard, err)
			}
			if !v.auto {
				return
			}
			for _, c := range []struct {
				name string
				args []string
			}{
				{"hardlink-within-root", []string{"m-hardlink", wrFile, filepath.Join(wr, "hard-ok")}},
				{"reopen-for-write-in-root", []string{"m-reopen-fd", wrFile}},
				{"truncate-in-root", []string{"m-truncate", wrFile}},
			} {
				label := v.name + "/" + c.name
				res := mxRun(t, bin, ProbeArg, p, f.base, env, c.args...)
				mxComplete(t, label, res, "result")
				mxWant(t, label, res, "result", 0)
			}
		})
	}
}

func TestEnforcePlanGrandchildDeniedThroughShell(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	outside := filepath.Join(f.base, "outside", "child-target")
	if err := os.MkdirAll(filepath.Dir(outside), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(f.base, "fx", "grandchild.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("sh -c 'if echo x > %q 2>/dev/null; then echo RES=0; else echo RES=1; fi'\n", outside)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	res := mxRun(t, bin, "", mxPlan(f), f.base, f.env(t, f.base, ""), "/bin/sh", script)
	mxComplete(t, "grandchild", res, "RES")
	if res.lines["RES"] != 1 {
		t.Errorf("grandchild write: RES=%d want 1 (code %d stdout %q stderr %q)", res.lines["RES"], res.code, res.stdout, res.stderr)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Error("grandchild created the outside file despite denial")
	}
}

func TestEnforceBlockedPaths(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxPlanAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			bp := f.mkdir(t, "bp")
			blockedFile := f.writeFile(t, "bp", "blocked")
			neighbor := f.writeFile(t, "bp", "neighbor")
			blockedDir := f.mkdir(t, "bp", "blockeddir")
			blockedDirFile := filepath.Join(blockedDir, "inside")
			if err := os.WriteFile(blockedDirFile, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			okDirFile := filepath.Join(f.mkdir(t, "bp", "okdir"), "inside")
			if err := os.WriteFile(okDirFile, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			wr := f.mkdir(t, "wr")
			wrBlocked := f.writeFile(t, "wr", "blocked")
			wrNeighbor := f.writeFile(t, "wr", "neighbor")
			tmp := f.tmpFor(t, v)
			env := f.env(t, f.base, tmp)
			p := f.policy(v, []string{wr}, nil, tmp, blockedFile, blockedDir, wrBlocked)
			for _, c := range []struct {
				name string
				args []string
				want unix.Errno
			}{
				{"read-blocked-file", []string{"m-read", blockedFile}, unix.EACCES},
				{"read-file-in-blocked-folder", []string{"m-read", blockedDirFile}, unix.EACCES},
				{"read-home-codemeld", []string{"m-read", filepath.Join(f.home, ".codemeld", "global", "settings.yaml")}, unix.EACCES},
				{"read-neighbor", []string{"m-read", neighbor}, 0},
				{"read-neighbor-folder-file", []string{"m-read", okDirFile}, 0},
				{"list-parent", []string{"m-readdir", bp}, 0},
			} {
				res := mxRun(t, bin, ProbeArg, p, f.base, env, c.args...)
				mxWant(t, v.name+"/blocked/"+c.name, res, "result", c.want)
			}
			if !v.auto {
				return
			}
			res := mxRun(t, bin, ProbeArg, p, f.base, env, "m-write-existing", wrBlocked)
			mxWant(t, v.name+"/blocked/write-blocked-in-root", res, "result", unix.EACCES)
			res = mxRun(t, bin, ProbeArg, p, f.base, env, "m-write-existing", wrNeighbor)
			mxWant(t, v.name+"/blocked/write-neighbor-in-root", res, "result", 0)
		})
	}
}

func TestEnforceSnapshotCommandStart(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxPlanAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			snapDir := f.mkdir(t, "snap")
			blocked := filepath.Join(snapDir, "blocked")
			if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			newFile := filepath.Join(snapDir, "created-after-setup")
			tmp := f.tmpFor(t, v)
			got := mxRunSnapshot(t, bin, f.policy(v, nil, nil, tmp, blocked), f.base, f.env(t, f.base, tmp), newFile)
			if got != unix.EACCES {
				t.Errorf("%s command-start snapshot: read of a file created next to a blocked file after setup = errno %d, want EACCES", v.name, int(got))
			}
		})
	}
}

func mxRunSnapshot(t *testing.T, bin string, p Policy, dir string, env []string, newfile string) unix.Errno {
	t.Helper()
	var frame bytes.Buffer
	if err := WritePolicyFrame(&frame, p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, HelperCommand, ProbeArg, "m-snapshot", newfile)
	cmd.Env, cmd.Dir = env, dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }()
	if _, err := stdin.Write(frame.Bytes()); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	ready := make([]byte, len("ready\n"))
	if _, err := readLine(stdout, ready); err != nil || strings.TrimSpace(string(ready)) != "ready" {
		t.Fatalf("probe not ready: %q %v (stderr %q)", ready, err, errb.String())
	}
	if err := os.WriteFile(newfile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("a")); err != nil {
		t.Fatalf("ack: %v", err)
	}
	buf := make([]byte, 64)
	n, _ := stdout.Read(buf)
	_, v, ok := strings.Cut(strings.TrimSpace(string(buf[:n])), "=")
	if !ok {
		t.Fatalf("bad result line %q (stderr %q)", buf[:n], errb.String())
	}
	code, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("parse result %q: %v", v, err)
	}
	return unix.Errno(code)
}

func readLine(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total : total+1])
		total += n
		if err != nil {
			return total, err
		}
		if buf[total-1] == '\n' {
			return total, nil
		}
	}
	return total, nil
}

func TestEnforceAutoEdits(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			wr := f.mkdir(t, "wr")
			proj := f.mkdir(t, "proj")
			projCodemeld := f.mkdir(t, "proj", ".codemeld")
			granted := f.mkdir(t, "proj", "granted")
			tmp := f.mkdir(t, "tmp")
			tmpFile := f.writeFile(t, "tmp", "m")
			f.mkdir(t, "wr-sibling")
			outsideDir := f.mkdir(t, "outside-target")
			linkOutside := filepath.Join(proj, "link-outside")
			if err := os.Symlink(outsideDir, linkOutside); err != nil {
				t.Fatal(err)
			}
			linkCodemeld := filepath.Join(proj, "link-codemeld")
			if err := os.Symlink(projCodemeld, linkCodemeld); err != nil {
				t.Fatal(err)
			}
			env := f.env(t, f.base, tmp)

			auto := f.policy(v, []string{wr, proj}, []string{projCodemeld}, tmp)
			for _, c := range []struct {
				name string
				args []string
				want unix.Errno
			}{
				{"write-in-root", []string{"m-open-write", filepath.Join(wr, "new")}, 0},
				{"write-sibling-of-root", []string{"m-open-write", filepath.Join(f.base, "wr-sibling", "new")}, unix.EACCES},
				{"write-project-codemeld", []string{"m-open-write", filepath.Join(projCodemeld, "x")}, unix.EACCES},
				{"write-tmp", []string{"m-open-write", filepath.Join(tmp, "new")}, 0},
				{"chmod-tmp", []string{"m-chmod-ok", tmpFile}, 0},
				{"write-granted-ordinary", []string{"m-open-write", filepath.Join(granted, "new")}, 0},
				{"write-through-link-to-outside", []string{"m-open-write", filepath.Join(linkOutside, "new")}, unix.EACCES},
				{"write-through-link-to-project-codemeld", []string{"m-open-write", filepath.Join(linkCodemeld, "via-link")}, unix.EACCES},
			} {
				res := mxRun(t, bin, ProbeArg, auto, f.base, env, c.args...)
				mxWant(t, v.name+"/"+c.name, res, "result", c.want)
			}
			for _, p := range []string{
				filepath.Join(f.base, "wr-sibling", "new"),
				filepath.Join(projCodemeld, "x"),
				filepath.Join(outsideDir, "new"),
				filepath.Join(projCodemeld, "via-link"),
			} {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s: denied write left %s behind (%v)", v.name, p, err)
				}
			}
			if v.authority == "" {
				sock := mxRun(t, bin, ProbeArg, auto, f.base, env, "m-sockets")
				mxWant(t, "auto/socket-inet", sock, "inet", unix.EPERM)
			}
		})
	}
}

func TestEnforceAutoEditsWritableFolders(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			above := f.mkdir(t, "above")
			proj := f.mkdir(t, "above", "proj")
			projCodemeld := f.mkdir(t, "above", "proj", ".codemeld")
			codemeldFile := f.writeFile(t, "above", "proj", ".codemeld", "settings.yaml")
			src := f.mkdir(t, "above", "proj", "src")
			neighborFile := f.writeFile(t, "above", "proj", "file.txt")
			outside := f.mkdir(t, "outside")
			link := filepath.Join(proj, "link-outside")
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			tmp := f.mkdir(t, "tmp")
			env := f.env(t, f.base, tmp)
			projectRoots := []string{neighborFile, src}
			noWrite := []string{projCodemeld}

			for _, c := range []struct {
				name     string
				writable []string
				args     []string
				want     unix.Errno
			}{
				{"link-to-writable-folder", []string{outside}, []string{"m-open-write", filepath.Join(link, "granted")}, 0},
				{"link-to-undeclared-folder", nil, []string{"m-open-write", filepath.Join(link, "denied")}, unix.EACCES},
				{"above-project-codemeld-new", []string{above}, []string{"m-open-write", filepath.Join(projCodemeld, "x")}, unix.EACCES},
				{"above-project-codemeld-existing", []string{above}, []string{"m-write-existing", codemeldFile}, unix.EACCES},
				{"above-project-neighbor-dir", []string{above}, []string{"m-open-write", filepath.Join(src, "new")}, 0},
				{"above-project-neighbor-file", []string{above}, []string{"m-write-existing", neighborFile}, 0},
			} {
				auto := f.policy(v, append(slices.Clone(projectRoots), c.writable...), noWrite, tmp)
				res := mxRun(t, bin, ProbeArg, auto, f.base, env, c.args...)
				mxWant(t, v.name+"/"+c.name, res, "result", c.want)
			}
			for _, p := range []string{filepath.Join(outside, "denied"), filepath.Join(projCodemeld, "x")} {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s: denied write left %s behind (%v)", v.name, p, err)
				}
			}
			if b, err := os.ReadFile(codemeldFile); err != nil || string(b) != "content" {
				t.Errorf("%s: %s = %q, %v; want it unchanged", v.name, codemeldFile, b, err)
			}
		})
	}
}

func TestEnforceAutoEditsProjectInsideOuterWriteRoot(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			outer := f.mkdir(t, "outer")
			other := f.mkdir(t, "outer", "other")
			projCodemeld := f.mkdir(t, "outer", "proj", ".codemeld")
			codemeldFile := f.writeFile(t, "outer", "proj", ".codemeld", "settings.yaml")
			src := f.mkdir(t, "outer", "proj", "src")
			neighborFile := f.writeFile(t, "outer", "proj", "file.txt")
			secret := f.writeFile(t, "outer", "proj", "secret")
			tmp := f.mkdir(t, "tmp")
			env := f.env(t, f.base, tmp)
			auto := Policy{
				Mode:                 ModeAutoEdits,
				ExceptionalAuthority: v.authority,
				BlockedPaths:         []string{filepath.Join(f.home, ".codemeld"), secret},
				NoWritePaths:         []string{projCodemeld},
				TmpDir:               tmp,
				WriteRoots:           []string{outer},
			}

			for _, c := range []struct {
				name string
				args []string
				want unix.Errno
			}{
				{"project-codemeld-new", []string{"m-open-write", filepath.Join(projCodemeld, "x")}, unix.EACCES},
				{"project-codemeld-existing", []string{"m-write-existing", codemeldFile}, unix.EACCES},
				{"blocked-neighbor", []string{"m-write-existing", secret}, unix.EACCES},
				{"neighbor-dir", []string{"m-open-write", filepath.Join(src, "new")}, 0},
				{"neighbor-file", []string{"m-write-existing", neighborFile}, 0},
				{"outer-root-neighbor-of-project", []string{"m-open-write", filepath.Join(other, "new")}, 0},
				{"outer-root-holding-the-project", []string{"m-open-write", filepath.Join(outer, "new")}, unix.EACCES},
			} {
				res := mxRun(t, bin, ProbeArg, auto, f.base, env, c.args...)
				mxWant(t, v.name+"/"+c.name, res, "result", c.want)
			}
			for _, p := range []string{filepath.Join(projCodemeld, "x"), filepath.Join(outer, "new")} {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s: denied write left %s behind (%v)", v.name, p, err)
				}
			}
			for _, p := range []string{codemeldFile, secret} {
				if b, err := os.ReadFile(p); err != nil || string(b) != "content" {
					t.Errorf("%s: %s = %q, %v; want it unchanged", v.name, p, b, err)
				}
			}
		})
	}
}

func TestEnforceDevShm(t *testing.T) {
	mxRequire(t)
	if info, err := os.Stat("/dev/shm"); err != nil || !info.IsDir() {
		t.Skipf("/dev/shm unavailable: %v", err)
	}
	bin := mxBinary(t)
	for _, v := range mxAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			tmp := f.mkdir(t, "tmp")
			auto := f.policy(v, []string{"/dev/shm"}, nil, tmp)
			name := fmt.Sprintf("codemeld-matrix-%d-%s", os.Getpid(), v.name)
			res := mxRun(t, bin, ProbeArg, auto, f.base, f.env(t, f.base, tmp), "shm-open", name)
			if res.code != probeDenied {
				t.Errorf("%s: shm_open under a /dev/shm write root: code %d, want %d (denied)", v.name, res.code, probeDenied)
			}
			if _, err := os.Stat(filepath.Join("/dev/shm", name)); err == nil {
				t.Errorf("%s: shm object %s left behind", v.name, name)
				_ = os.Remove(filepath.Join("/dev/shm", name))
			}
		})
	}
}

func TestEnforceProcessAccess(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	keys := []string{"ptrace", "process_vm_readv", "process_vm_writev", "environ"}
	want := map[string]unix.Errno{"ptrace": unix.EPERM, "process_vm_readv": unix.EPERM, "process_vm_writev": unix.EPERM, "environ": unix.EACCES}
	run := func(t *testing.T, mode string, v mxVariant) mxResult {
		t.Helper()
		f := mxSetup(t)
		pid, envStart, content := mxTarget(t, bin)
		tmp := f.tmpFor(t, v)
		label := mode + "/" + v.name
		res := mxRun(t, bin, mode, f.policy(v, []string{f.mkdir(t, "wr")}, nil, tmp), f.base, f.env(t, f.base, tmp),
			"m-proc-access", strconv.Itoa(pid), strconv.FormatUint(envStart, 10), content)
		mxComplete(t, label, res, append([]string{"target"}, keys...)...)
		if res.lines["target"] != pid {
			t.Errorf("%s: probe reported target %d, want the live test-owned target %d", label, res.lines["target"], pid)
		}
		if tracer := statusField(t, strconv.Itoa(pid), "TracerPid"); tracer != "0" {
			t.Errorf("%s: target still traced by %s", label, tracer)
		}
		if state := statusField(t, strconv.Itoa(pid), "State"); strings.HasPrefix(state, "T") || strings.HasPrefix(state, "t") {
			t.Errorf("%s: target left stopped: %s", label, state)
		}
		if environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err != nil || string(environ) != content+"\x00" {
			t.Errorf("%s: target environment changed: %q, %v", label, environ, err)
		}
		return res
	}
	control := run(t, ControlArg, mxPlanAutoNet[0])
	for _, v := range mxPlanAutoNet {
		res := run(t, ProbeArg, v)
		for _, k := range keys {
			mxWant(t, v.name+"/"+k, res, k, want[k])
		}
	}
	var demonstrated, hostHeld, hostErr []string
	for _, k := range keys {
		switch cv := control.lines[k]; {
		case cv == 0:
			demonstrated = append(demonstrated, k)
		case cv == int(want[k]):
			hostHeld = append(hostHeld, k)
		default:
			hostErr = append(hostErr, fmt.Sprintf("%s(errno %d)", k, cv))
		}
	}
	t.Logf("process access demonstrated (unconfined control succeeds against the live target): %v", demonstrated)
	t.Logf("process access host-held (unconfined control gets the same errno): %v", hostHeld)
	t.Logf("process access host errors (unconfined control fails otherwise): %v", hostErr)
}

func TestEnforceCoreSyscalls(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	wr := f.mkdir(t, "wr")
	tmp := f.mkdir(t, "tmp")
	env := f.env(t, f.base, "")
	autoEnv := f.env(t, f.base, tmp)

	var names []string
	for _, c := range mxCoreCalls() {
		names = append(names, c.name)
	}
	control := mxRun(t, bin, ControlArg, mxPlan(f), f.base, env, "m-core")
	mxComplete(t, "control", control, names...)

	modes := []struct {
		name string
		p    Policy
		env  []string
	}{
		{"plan", mxPlan(f), env},
		{"auto", mxAuto(f, []string{wr}, nil, tmp, ""), autoEnv},
		{"net", mxAuto(f, []string{wr}, nil, tmp, NetworkAccessAuthority), autoEnv},
	}
	var hostHeld, demonstrated, archSkipped []string
	for _, m := range modes {
		res := mxRun(t, bin, ProbeArg, m.p, f.base, m.env, "m-core")
		mxComplete(t, m.name, res, names...)
		for _, c := range mxCoreCalls() {
			v := res.lines[c.name]
			if v == -2 {
				if m.name == "plan" {
					archSkipped = append(archSkipped, c.name)
				}
				continue
			}
			want := unix.EPERM
			if c.name == "clone3" {
				want = unix.ENOSYS
			}
			if v != int(want) {
				t.Errorf("%s: %s: errno %d, want %d", m.name, c.name, v, int(want))
			}
			if m.name == "plan" {
				if control.lines[c.name] == int(want) {
					hostHeld = append(hostHeld, c.name)
				} else {
					demonstrated = append(demonstrated, c.name)
				}
			}
		}
	}
	t.Logf("core syscalls demonstrated (control errno differs from the boundary errno): %v", demonstrated)
	t.Logf("core syscalls host-held (control returns the boundary errno too): %v", hostHeld)
	if len(archSkipped) > 0 {
		t.Logf("core syscalls absent from native table (architecture-specific skip): %v", archSkipped)
	}
}

func TestEnforceCloneNamespaceFlags(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	tmp := f.mkdir(t, "tmp")
	wr := f.mkdir(t, "wr")
	var names []string
	for _, c := range mxCloneFlags() {
		names = append(names, c.name)
	}
	control := mxRun(t, bin, ControlArg, mxPlan(f), f.base, f.env(t, f.base, ""), "m-clone")
	mxComplete(t, "control", control, names...)
	modes := []struct {
		name string
		p    Policy
		env  []string
	}{
		{"plan", mxPlan(f), f.env(t, f.base, "")},
		{"auto", mxAuto(f, []string{wr}, nil, tmp, ""), f.env(t, f.base, tmp)},
		{"net", mxAuto(f, []string{wr}, nil, tmp, NetworkAccessAuthority), f.env(t, f.base, tmp)},
	}
	for _, m := range modes {
		res := mxRun(t, bin, ProbeArg, m.p, f.base, m.env, "m-clone")
		mxComplete(t, m.name, res, names...)
		for _, c := range mxCloneFlags() {
			// A new-namespace clone is refused either by the clone bitmask rule (EPERM) or, when the
			// Go runtime routes the flag through clone3, by the clone3 rule (ENOSYS).
			mxWantOneOf(t, m.name+"/clone-"+c.name, res, c.name, unix.EPERM, unix.ENOSYS)
		}
	}
	var hostHeld, demonstrated, hostErr []string
	for _, c := range mxCloneFlags() {
		switch cv := control.lines[c.name]; cv {
		case 0:
			demonstrated = append(demonstrated, c.name)
		case int(unix.EPERM), int(unix.ENOSYS):
			hostHeld = append(hostHeld, fmt.Sprintf("%s(errno %d)", c.name, cv))
		default:
			hostErr = append(hostErr, fmt.Sprintf("%s(errno %d)", c.name, cv))
		}
	}
	t.Logf("clone flags demonstrated (clone succeeds unconfined): %v", demonstrated)
	t.Logf("clone flags host-held (unconfined clone also EPERM or ENOSYS): %v", hostHeld)
	t.Logf("clone flags host errors (unconfined clone fails otherwise): %v", hostErr)
}

func TestEnforcePlanMetadataSyscalls(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	readFile := f.writeFile(t, "fx", "r")
	res := mxRun(t, bin, ProbeArg, mxPlan(f), f.base, f.env(t, f.base, ""), "m-meta", readFile)
	names := []string{
		"chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat",
		"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",
		"utime", "utimes", "futimesat", "utimensat", "ioctl-setflags", "ioctl-fssetxattr",
	}
	var archSkipped []string
	for _, n := range names {
		v, ok := res.lines[n]
		if !ok {
			t.Errorf("meta %s: no result (stderr %q)", n, res.stderr)
			continue
		}
		if v == -2 {
			archSkipped = append(archSkipped, n)
			continue
		}
		if v != int(unix.EPERM) {
			t.Errorf("meta %s: errno %d, want EPERM", n, v)
		}
	}
	if len(archSkipped) > 0 {
		t.Logf("metadata syscalls absent from native table (architecture-specific skip): %v", archSkipped)
	}
}

func TestEnforceSockets(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	wr := f.mkdir(t, "wr")
	tmp := f.mkdir(t, "tmp")
	var names []string
	for _, c := range mxSocketCases() {
		names = append(names, c.name)
	}
	denied := slices.Clone(names)
	for _, c := range mxPairTypeCases() {
		denied = append(denied, c.name)
	}
	allowedPairs := []string{"socketpair", "socketpair-exchange", "socketpair-seqpacket", "socketpair-seqpacket-exchange"}
	names = append(slices.Clone(denied), allowedPairs...)

	control := mxRun(t, bin, ControlArg, mxPlan(f), f.base, f.env(t, f.base, ""), "m-sockets")
	mxComplete(t, "control", control, names...)

	pairsAllowed := func(label string, res mxResult) {
		for _, n := range allowedPairs {
			mxWant(t, label+"/"+n, res, n, 0)
		}
		for _, c := range mxPairTypeCases() {
			mxWant(t, label+"/"+c.name, res, c.name, unix.EPERM)
		}
	}
	plan := mxRun(t, bin, ProbeArg, mxPlan(f), f.base, f.env(t, f.base, ""), "m-sockets")
	mxComplete(t, "plan", plan, names...)
	auto := mxRun(t, bin, ProbeArg, mxAuto(f, []string{wr}, nil, tmp, ""), f.base, f.env(t, f.base, tmp), "m-sockets")
	mxComplete(t, "auto", auto, names...)
	for label, res := range map[string]mxResult{"plan": plan, "auto": auto} {
		for _, n := range denied {
			mxWant(t, label+"/"+n, res, n, unix.EPERM)
		}
		pairsAllowed(label, res)
	}

	net := mxRun(t, bin, ProbeArg, mxAuto(f, []string{wr}, nil, tmp, NetworkAccessAuthority), f.base, f.env(t, f.base, tmp), "m-sockets")
	mxComplete(t, "net", net, names...)
	mxWant(t, "net/inet", net, "inet", 0)
	mxWant(t, "net/inet6", net, "inet6", 0)
	pairsAllowed("net", net)
	for _, name := range []string{"unix", "netlink", "packet", "inet-raw", "inet6-raw"} {
		mxWant(t, "net/"+name, net, name, unix.EPERM)
	}

	var demonstrated, hostHeld, hostErr []string
	for _, n := range names {
		switch cv := control.lines[n]; cv {
		case 0:
			demonstrated = append(demonstrated, n)
		case int(unix.EPERM):
			hostHeld = append(hostHeld, n)
		default:
			hostErr = append(hostErr, fmt.Sprintf("%s(errno %d)", n, cv))
		}
	}
	t.Logf("sockets demonstrated (socket succeeds unconfined): %v", demonstrated)
	t.Logf("sockets host-held (unconfined socket also EPERM): %v", hostHeld)
	t.Logf("sockets host errors (unconfined socket fails otherwise): %v", hostErr)
}

type mxOutsidePeer struct {
	ln            *net.UnixListener
	network, addr string
}

func mxListenOutside(t *testing.T, network, addr string) mxOutsidePeer {
	t.Helper()
	ln, err := net.ListenUnix(network, &net.UnixAddr{Name: addr, Net: network})
	if err != nil {
		t.Fatalf("outside %s listener %s: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := mxOutsidePeer{ln, network, addr}
	if foreign := p.drain(t); len(foreign) != 0 {
		t.Fatalf("outside listener %s: unexpected connections from pids %v", addr, foreign)
	}
	return p
}

func (p mxOutsidePeer) drain(t *testing.T) (foreign []int32) {
	t.Helper()
	c, err := net.DialTimeout(p.network, p.addr, 2*time.Second)
	if err != nil {
		t.Fatalf("outside listener %s not live: %v", p.addr, err)
	}
	defer func() { _ = c.Close() }()
	if err := p.ln.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		conn, err := p.ln.AcceptUnix()
		if err != nil {
			t.Fatalf("outside listener %s: accept: %v", p.addr, err)
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var cred *unix.Ucred
		var credErr error
		if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || credErr != nil {
			t.Fatalf("outside listener %s: peer credentials: %v %v", p.addr, err, credErr)
		}
		_ = conn.Close()
		if cred.Pid == int32(os.Getpid()) {
			return foreign
		}
		foreign = append(foreign, cred.Pid)
	}
}

func mxRunAwaiting(t *testing.T, bin string, p Policy, dir string, env []string, onAwait func(label, name string), args ...string) mxResult {
	t.Helper()
	var frame bytes.Buffer
	if err := WritePolicyFrame(&frame, p); err != nil {
		t.Fatal(err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inW.Close(); _ = outR.Close() }()
	cmd := exec.Command(bin, append([]string{HelperCommand, ProbeArg}, args...)...)
	var errb bytes.Buffer
	cmd.Env, cmd.Dir, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, dir, inR, outW, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	err = cmd.Start()
	_ = inR.Close()
	_ = outW.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	if _, err := inW.Write(frame.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := outR.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	res := mxResult{code: -1, lines: map[string]int{}}
	var stdout strings.Builder
	sc := bufio.NewScanner(outR)
	for sc.Scan() {
		ln := sc.Text()
		stdout.WriteString(ln + "\n")
		if rest, ok := strings.CutPrefix(ln, "await="); ok {
			label, name, _ := strings.Cut(rest, " ")
			onAwait(label, name)
			if _, err := inW.Write([]byte{'\n'}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if k, v, ok := strings.Cut(ln, "="); ok {
			if n, e := strconv.Atoi(v); e == nil {
				res.lines[k] = n
			}
		}
	}
	if res.timedOut = errors.Is(sc.Err(), os.ErrDeadlineExceeded); res.timedOut {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	err = cmd.Wait()
	res.stdout, res.stderr = stdout.String(), errb.String()
	var ee *exec.ExitError
	switch {
	case res.timedOut:
	case err == nil:
		res.code = 0
	case errors.As(err, &ee):
		res.code = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.signal = ws.Signal()
		}
	default:
		t.Fatalf("run %v: %v", args, err)
	}
	return res
}

func TestEnforceSocketpairIsolation(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	abstract := filepath.Base(f.base)
	outsideDir := f.mkdir(t, "outside")
	var outsides []mxOutsidePeer
	outsideArgs := []string{"m-pair-isolation"}
	networks := map[string]string{}
	for _, typ := range mxPairTypes() {
		path, name := filepath.Join(outsideDir, typ.name+".sock"), abstract+"-"+typ.name+"-listener"
		outsides = append(outsides, mxListenOutside(t, typ.network, path), mxListenOutside(t, typ.network, "@"+name))
		outsideArgs = append(outsideArgs, path, name)
	}
	for _, c := range mxPairCases() {
		networks[c.label()] = c.typ.network
	}
	wr := f.mkdir(t, "wr")
	for _, v := range mxPlanAutoNet {
		tmp := f.tmpFor(t, v)
		bindDir := f.mkdir(t, "wr", v.name)
		var bound []string
		res := mxRunAwaiting(t, bin, f.policy(v, []string{wr}, nil, tmp), f.base, f.env(t, f.base, tmp), func(label, name string) {
			bound = append(bound, label)
			c, err := net.DialTimeout(networks[label], name, 2*time.Second)
			if err == nil {
				_ = c.Close()
				t.Errorf("%s/%s: outside client connected to the confined endpoint bound at %q", v.name, label, name)
				return
			}
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Errorf("%s/%s: outside client dial %q: %v, want ECONNREFUSED from a bound endpoint that is not listening", v.name, label, name, err)
			}
		}, append(slices.Clone(outsideArgs), bindDir, abstract+"-"+v.name+"-")...)
		var keys, wantBound []string
		for _, c := range mxPairCases() {
			for _, op := range []string{"unspec", "connect-path", "connect-abstract", "bind", "listen", "accept"} {
				keys = append(keys, c.label()+"-"+op)
			}
		}
		mxComplete(t, v.name, res, keys...)
		for _, c := range mxPairCases() {
			for op, want := range map[string]unix.Errno{"connect-path": unix.EISCONN, "connect-abstract": unix.EISCONN, "listen": unix.EINVAL, "accept": unix.EINVAL} {
				mxWant(t, v.name, res, c.label()+"-"+op, want)
			}
			if !v.auto && c.kind == "path" {
				mxWant(t, v.name, res, c.label()+"-bind", unix.EACCES)
				continue
			}
			mxWant(t, v.name, res, c.label()+"-bind", 0)
			wantBound = append(wantBound, c.label())
		}
		if !slices.Equal(bound, wantBound) {
			t.Errorf("%s: outside-client checks ran for %v, want exactly %v", v.name, bound, wantBound)
		}
		for _, o := range outsides {
			if foreign := o.drain(t); len(foreign) != 0 {
				t.Errorf("%s: outside listener %s accepted connections from pids %v", v.name, o.addr, foreign)
			}
		}
		t.Logf("%s: endpoints bound and refused to an outside client: %v", v.name, bound)
	}
}

func TestEnforceNonNativeArchitecture(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	f := mxSetup(t)
	env := f.env(t, f.base, "")
	plan := mxPlan(f)

	switch goarch {
	case "amd64":
		x32 := mxRun(t, bin, ProbeArg, plan, f.base, env, "m-x32")
		mxWant(t, "amd64/x32", x32, "x32", unix.EPERM)

		if gap := hostIA32EmulationGap(); gap != "" {
			t.Logf("i386 int 0x80 kill skipped (architecture-specific): ia32 emulation unavailable: %s", gap)
			return
		}
		i386 := mxRun(t, bin, ProbeArg, plan, f.base, env, "i386-syscall")
		if i386.signal != syscall.SIGSYS {
			t.Errorf("i386 int 0x80: signal %v code %d, want SIGSYS kill (stderr %q)", i386.signal, i386.code, i386.stderr)
		}
	case "arm64":
		if writeArm32Fixture == nil {
			t.Skip("arm32 kill skipped (architecture-specific): no 32-bit ARM fixture writer")
		}
		f.mkdir(t, "read")
		path, err := writeArm32Fixture(f.base)
		if err != nil {
			t.Fatal(err)
		}
		control := mxRun(t, bin, ControlArg, plan, f.base, env, "arm32-syscall", path)
		switch {
		case !control.timedOut && control.signal == 0 && control.code == probeUnsupported:
			t.Skip("arm32 kill skipped (architecture-specific): linux/arm64 host cannot execute 32-bit ARM executables (ENOEXEC from the unconfined control)")
		case control.timedOut || control.signal != 0 || control.code != probeAllowed:
			t.Fatalf("arm32 control: code %d sig %v timed out %v, want the unconfined 32-bit child to exit 0 (stderr %q)", control.code, control.signal, control.timedOut, control.stderr)
		}
		res := mxRun(t, bin, ProbeArg, plan, f.base, env, "arm32-syscall", path)
		if res.signal != syscall.SIGSYS && res.code != probeDenied {
			t.Errorf("arm32 syscall: signal %v code %d, want the 32-bit child killed by SIGSYS (probe exit %d)", res.signal, res.code, probeDenied)
		}
	default:
		t.Skipf("non-native architecture kill skipped: unsupported goarch %s", goarch)
	}
}

func TestEnforceSetuidUnchanged(t *testing.T) {
	mxRequire(t)
	if os.Getuid() == 0 {
		t.Skip("setuid check skipped (safe-setuid): invoking uid is root, so an unchanged effective uid proves nothing")
	}
	t.Skip("setuid check skipped (safe-setuid): no standard setuid-root binary reports its effective uid, so no such target exists on a stock host, and a non-root user cannot build a root-owned setuid helper; passwd --help alone is not proof")
}

func TestEnforceForcedABIRefusal(t *testing.T) {
	bin := mxBinary(t)
	f := mxSetup(t)
	old := startHelper
	t.Cleanup(func() { startHelper = old })
	startHelper = func(ctx context.Context, argv, env []string, dir string, frame []byte) helperExit {
		return startHelperProcess(ctx, argv, append(slices.Clone(env), forceABI2Env+"=1"), dir, frame)
	}
	got := Resolve(ResolveInput{Home: f.home, HelperExecutable: bin})
	if got.Capability != Refused || !strings.Contains(got.Reason, "landlock ABI 2 < 3") {
		t.Errorf("forced ABI 2: Resolve() = %+v, want Refused with reason containing %q", got, "landlock ABI 2 < 3")
	}
}

func mxSkillsTree(t *testing.T, f mxFx, dir string) (script, leak string) {
	t.Helper()
	script = filepath.Join(dir, "x", "run.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho RAN=7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	leak = filepath.Join(dir, "x", "leak")
	if err := os.Symlink(filepath.Join(f.home, ".codemeld", "global", "settings.yaml"), leak); err != nil {
		t.Fatal(err)
	}
	return script, leak
}

func TestEnforceSkillsReadRoot(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxPlanAutoNet {
		t.Run(v.name, func(t *testing.T) {
			f := mxSetup(t)
			skills := filepath.Join(f.home, ".codemeld", "skills")
			script, leak := mxSkillsTree(t, f, skills)
			tmp := f.tmpFor(t, v)
			env := f.env(t, f.base, tmp)
			p := f.policy(v, nil, nil, tmp)
			p.ReadRoots = []string{skills}

			run := mxRun(t, bin, "", p, f.base, env, script)
			mxComplete(t, v.name+"/run-skill-script", run, "RAN")
			if run.lines["RAN"] != 7 {
				t.Errorf("%s: skill script printed RAN=%d, want 7", v.name, run.lines["RAN"])
			}
			for _, c := range []struct {
				name string
				args []string
				want unix.Errno
			}{
				{"read-skill-file", []string{"m-read", script}, 0},
				{"read-home-codemeld", []string{"m-read", filepath.Join(f.home, ".codemeld", "global", "settings.yaml")}, unix.EACCES},
				{"read-through-skills-symlink", []string{"m-read", leak}, unix.EACCES},
			} {
				res := mxRun(t, bin, ProbeArg, p, f.base, env, c.args...)
				mxWant(t, v.name+"/skills/"+c.name, res, "result", c.want)
			}
			if !v.auto {
				return
			}
			for _, c := range []struct {
				name string
				args []string
			}{
				{"create-in-skills", []string{"m-open-write", filepath.Join(skills, "x", "new")}},
				{"change-skill-file", []string{"m-write-existing", script}},
			} {
				res := mxRun(t, bin, ProbeArg, p, f.base, env, c.args...)
				mxWant(t, v.name+"/skills/"+c.name, res, "result", unix.EACCES)
			}
			if _, err := os.Lstat(filepath.Join(skills, "x", "new")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: denied create left a file in skills (%v)", v.name, err)
			}
		})
	}
}

func TestEnforceRedirectedSkillsRootStaysUnwritable(t *testing.T) {
	mxRequire(t)
	bin := mxBinary(t)
	for _, v := range mxAutoNet {
		for _, rootName := range []string{"project", "declared"} {
			t.Run(v.name+"/"+rootName, func(t *testing.T) {
				f := mxSetup(t)
				project := f.mkdir(t, "proj")
				real := f.mkdir(t, "proj", "shared", "skills")
				script, _ := mxSkillsTree(t, f, real)
				neighbor := f.writeFile(t, "proj", "shared", "neighbor")
				neighborDir := f.mkdir(t, "proj", "shared", "other")
				alias := filepath.Join(f.home, ".codemeld", "skills")
				if err := os.Symlink(real, alias); err != nil {
					t.Fatal(err)
				}
				root := project
				if rootName == "declared" {
					root = filepath.Dir(real)
				}
				tmp := f.tmpFor(t, v)
				env := f.env(t, f.base, tmp)
				p := f.policy(v, []string{root}, []string{filepath.Join(project, ".codemeld"), real}, tmp)
				p.ReadRoots = []string{real}
				for _, c := range []struct {
					name string
					args []string
					want unix.Errno
				}{
					{"read-through-alias", []string{"m-read", filepath.Join(alias, "x", "run.sh")}, 0},
					{"change-through-alias", []string{"m-write-existing", filepath.Join(alias, "x", "run.sh")}, unix.EACCES},
					{"create-through-alias", []string{"m-open-write", filepath.Join(alias, "x", "new-alias")}, unix.EACCES},
					{"change-resolved", []string{"m-write-existing", script}, unix.EACCES},
					{"create-resolved", []string{"m-open-write", filepath.Join(real, "x", "new-real")}, unix.EACCES},
					{"change-neighbor", []string{"m-write-existing", neighbor}, 0},
					{"create-in-neighbor-folder", []string{"m-open-write", filepath.Join(neighborDir, "new")}, 0},
				} {
					res := mxRun(t, bin, ProbeArg, p, f.base, env, c.args...)
					mxWant(t, v.name+"/"+rootName+"/"+c.name, res, "result", c.want)
				}
				for _, name := range []string{"new-alias", "new-real"} {
					if _, err := os.Lstat(filepath.Join(real, "x", name)); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("denied create left %s in the skills folder (%v)", name, err)
					}
				}
			})
		}
	}
}
