package enforce

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/runner"
	"golang.org/x/sys/unix"
)

const fsNodumpFl = 0x40

type probe struct {
	n   int
	run func([]string) int
}

var probes = map[string]probe{
	"write-outside": pathProbe(createExclusive),
	"truncate-read-root": pathProbe(func(path string) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		return os.Truncate(path, info.Size())
	}),
	"read-protected": pathProbe(func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		return f.Close()
	}),
	"read-read-root": pathProbe(func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = f.Read(make([]byte, 1))
		return err
	}),
	"write-tmp": pathProbe(createExclusive),
	"socket-unix": {0, func([]string) int {
		return fdProbe(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	}},
	"socket-inet": {0, func([]string) int {
		return fdProbe(unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	}},
	"socketpair": {0, func([]string) int {
		for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
			fds, err := unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return probeExit(err)
			}
			_ = unix.Close(fds[0])
			_ = unix.Close(fds[1])
		}
		return probeAllowed
	}},
	"io-uring-setup": {0, func([]string) int {
		var params [120]byte
		fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0)
		return fdProbe(int(fd), errnoErr(errno))
	}},
	"shmget": {0, func([]string) int {
		id, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|0o600)
		return undo(err, func() error { _, err := unix.SysvShmCtl(id, unix.IPC_RMID, nil); return err })
	}},
	"msgget": {0, func([]string) int {
		id, _, errno := unix.Syscall(unix.SYS_MSGGET, unix.IPC_PRIVATE, unix.IPC_CREAT|0o600, 0)
		return undo(errnoErr(errno), func() error {
			_, _, errno := unix.Syscall(unix.SYS_MSGCTL, id, unix.IPC_RMID, 0)
			return errnoErr(errno)
		})
	}},
	"semget": {0, func([]string) int {
		id, _, errno := unix.Syscall(unix.SYS_SEMGET, unix.IPC_PRIVATE, 1, unix.IPC_CREAT|0o600)
		return undo(errnoErr(errno), func() error {
			_, _, errno := unix.Syscall6(unix.SYS_SEMCTL, id, 0, unix.IPC_RMID, 0, 0, 0)
			return errnoErr(errno)
		})
	}},
	"mq-open":        {1, mqOpenProbe},
	"shm-open":       {1, shmOpenProbe},
	"ptrace-parent":  {1, ptraceProbe},
	"environ-parent": {1, environProbe},
	"clone-newuser":  {0, cloneNewuserProbe},
	"mount":          {1, mountProbe},
	"chroot":         pathProbe(unix.Chroot),
	"chmod":          pathProbe(func(path string) error { return os.Chmod(path, 0o600) }),
	"ioctl-setflags": {1, setflagsProbe},
	"environment":    {3, environmentProbe},
	"no-new-privs":   {0, noNewPrivsProbe},
}

func pathProbe(f func(string) error) probe {
	return probe{1, func(a []string) int { return probeExit(f(a[0])) }}
}

func errnoErr(errno unix.Errno) error {
	if errno == 0 {
		return nil
	}
	return errno
}

func fdProbe(fd int, err error) int {
	return undo(err, func() error { return unix.Close(fd) })
}

func undo(err error, cleanup func() error) int {
	if err != nil {
		return probeExit(err)
	}
	if cleanup() != nil {
		return probeFailed
	}
	return probeAllowed
}

func createExclusive(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func mqOpenProbe(a []string) int {
	name, err := unix.BytePtrFromString(a[0])
	if err != nil {
		return probeFailed
	}
	fd, _, errno := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(name)), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600, 0, 0, 0)
	return undo(errnoErr(errno), func() error {
		_ = unix.Close(int(fd))
		_, _, errno := unix.Syscall(unix.SYS_MQ_UNLINK, uintptr(unsafe.Pointer(name)), 0, 0)
		return errnoErr(errno)
	})
}

func shmOpenProbe(a []string) int {
	path := filepath.Join("/dev/shm", a[0])
	return undo(createExclusive(path), func() error { return os.Remove(path) })
}

func ptraceProbe(a []string) int {
	pid, err := strconv.Atoi(a[0])
	if err != nil {
		return probeFailed
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return undo(unix.PtraceAttach(pid), func() error {
		if _, err := unix.Wait4(pid, nil, unix.WALL, nil); err != nil {
			return err
		}
		return unix.PtraceDetach(pid)
	})
}

func environProbe(a []string) int {
	if _, err := strconv.Atoi(a[0]); err != nil {
		return probeFailed
	}
	f, err := os.Open("/proc/" + a[0] + "/environ")
	if err != nil {
		return probeExit(err)
	}
	_ = f.Close()
	return probeAllowed
}

func cloneNewuserProbe([]string) int {
	exe := "/proc/self/exe"
	pid, err := syscall.ForkExec(exe, []string{exe, HelperCommand}, &syscall.ProcAttr{Sys: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}})
	if err != nil {
		return probeExit(err)
	}
	_, _ = waitBounded(pid, selfTestTimeout)
	return probeAllowed
}

var errChildTimeout = errors.New("child did not exit in time")

func waitBounded(pid int, limit time.Duration) (unix.WaitStatus, error) {
	var ws unix.WaitStatus
	deadline := time.Now().Add(limit)
	for {
		wpid, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
		switch {
		case errors.Is(err, unix.EINTR):
		case err != nil:
			return ws, err
		case wpid == pid:
			return ws, nil
		}
		if time.Now().After(deadline) {
			_ = unix.Kill(pid, unix.SIGKILL)
			_, _ = unix.Wait4(pid, &ws, 0, nil)
			return ws, errChildTimeout
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func mountProbe(a []string) int {
	return undo(unix.Mount("tmpfs", a[0], "tmpfs", 0, ""), func() error { return unix.Unmount(a[0], 0) })
}

func setflagsProbe(a []string) int {
	f, err := os.Open(a[0])
	if err != nil {
		return probeExit(err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd())
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FS_IOC_SETFLAGS: reading flags of %s: %v\n", a[0], err)
		return probeExit(err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags^fsNodumpFl)); err != nil {
		fmt.Fprintf(os.Stderr, "FS_IOC_SETFLAGS on %s: %v\n", a[0], err)
		return probeExit(err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags)); err != nil {
		fmt.Fprintf(os.Stderr, "FS_IOC_SETFLAGS: restoring flags of %s: %v\n", a[0], err)
		return probeFailed
	}
	return probeAllowed
}

func environmentProbe(a []string) int {
	want, err := runner.FixedEnvironment(a[0], a[1], a[2], runner.FixedPATH, nil)
	if err != nil || !fixedEnvironmentSeen(os.Environ(), want) {
		return probeFailed
	}
	return probeAllowed
}

// fixedEnvironmentSeen accepts the fixed table alone, as a startup helper launch passes it, or the
// table plus exactly one well-formed run marker, as the production runner adds it.
func fixedEnvironmentSeen(got, want []string) bool {
	got = slices.Clone(got)
	if i := slices.IndexFunc(got, func(e string) bool {
		id, ok := strings.CutPrefix(e, runner.RunMarkerEnv+"=")
		return ok && ids.IsValidV7(id)
	}); i >= 0 {
		got = slices.Delete(got, i, i+1)
	}
	want = slices.Clone(want)
	slices.Sort(want)
	slices.Sort(got)
	return slices.Equal(got, want)
}

func noNewPrivsProbe([]string) int {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return probeFailed
	}
	for line := range strings.Lines(string(data)) {
		if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok && strings.TrimSpace(v) == "1" {
			return probeAllowed
		}
	}
	return probeFailed
}

func runProbe(s *helperState, args []string) int {
	if len(args) == 0 {
		return probeFailed
	}
	if args[0] == "rlimits" {
		if len(args) != 1 {
			return probeFailed
		}
		return rlimitsProbe(s.nproc)
	}
	p, ok := probes[args[0]]
	if !ok || len(args)-1 != p.n {
		return probeFailed
	}
	return p.run(args[1:])
}

func probeExit(err error) int {
	switch {
	case err == nil:
		return probeAllowed
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return probeDenied
	default:
		return probeFailed
	}
}

func rlimitsProbe(nproc uint64) int {
	if nproc == 0 {
		return probeFailed
	}
	for resource, want := range map[int]uint64{unix.RLIMIT_FSIZE: fsizeLimit, unix.RLIMIT_NPROC: nproc} {
		var got unix.Rlimit
		if err := getrlimit(resource, &got); err != nil || got.Cur != want || got.Max != want {
			return probeFailed
		}
	}
	return probeAllowed
}
