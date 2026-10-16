package enforce

import "golang.org/x/sys/unix"

func i386Getpid() int32

func init() {
	probes["x32-syscall"] = probe{0, func([]string) int {
		_, _, errno := unix.RawSyscall(unix.SYS_GETPID|x32SyscallBit, 0, 0, 0)
		if errno == unix.ENOSYS {
			return probeDenied
		}
		return probeExit(errnoErr(errno))
	}}
	probes["i386-syscall"] = probe{0, func([]string) int {
		if i386Getpid() < 0 {
			return probeFailed
		}
		return probeAllowed
	}}
}
