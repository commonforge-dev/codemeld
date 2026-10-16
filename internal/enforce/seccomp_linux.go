package enforce

import (
	"fmt"
	"slices"
	"unsafe"

	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	fsIocFssetxattr = 0x401c5820
	x32SyscallBit   = 0x40000000
	cloneNewFlags   = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
		unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWTIME
	seccompNrOffset   = 0
	seccompArchOffset = 4
	seccompArgsOffset = 16
)

var seccompDenyAll = []string{
	"socket", "socketpair", "ptrace", "process_vm_readv", "process_vm_writev",
	"shmget", "shmat", "shmctl", "msgget", "msgsnd", "msgrcv", "msgctl",
	"semget", "semop", "semtimedop", "semctl", "mq_open",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	"unshare", "setns", "mount", "umount2", "pivot_root", "chroot",
	"fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree", "mount_setattr", "bpf",
}

var seccompDenyPlan = []string{
	"chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat",
	"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",
	"utime", "utimes", "utimensat", "futimesat",
}

var seccompAbsent = map[string][]string{
	"aarch64": {"chmod", "chown", "lchown", "utime", "utimes", "futimesat"},
}

var (
	nativeSeccompArch = func() (*arch.Info, error) { return arch.GetInfo("") }
	loadSeccomp       = func(flags uintptr, prog *unix.SockFprog) error {
		tid, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(prog)))
		if errno != 0 {
			return errno
		}
		if tid != 0 {
			return fmt.Errorf("thread %d could not synchronize", tid)
		}
		return nil
	}
)

func installSeccomp(p Policy) error {
	insts, err := seccompFilter(p)
	if err != nil {
		return err
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		return err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return loadSeccomp(unix.SECCOMP_FILTER_FLAG_TSYNC, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]})
}

func seccompFilter(p Policy) ([]bpf.Instruction, error) {
	info, err := nativeSeccompArch()
	if err != nil {
		return nil, err
	}
	return seccompFilterFor(p, info)
}

func seccompFilterFor(p Policy, info *arch.Info) ([]bpf.Instruction, error) {
	if info.Name != arch.X86_64.Name && info.Name != arch.AARCH64.Name {
		return nil, fmt.Errorf("unsupported architecture %s", info.Name)
	}
	eperm := bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}
	loadNr := bpf.LoadAbsolute{Off: seccompNrOffset, Size: 4}
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompArchOffset, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(info.ID), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_KILL_PROCESS},
		loadNr,
	}
	if info.Name == arch.X86_64.Name {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: x32SyscallBit, SkipFalse: 1}, eperm)
	}
	network := p.ExceptionalAuthority == NetworkAccessAuthority
	blocks := map[string][]bpf.Instruction{
		"clone":  {loadArg(0), bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: cloneNewFlags, SkipFalse: 1}, eperm, loadNr},
		"clone3": {bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)}},
	}
	names := append(slices.Clone(seccompDenyAll), "clone", "clone3")
	if p.Mode == ModePlan {
		names = append(append(names, seccompDenyPlan...), "ioctl")
		blocks["ioctl"] = []bpf.Instruction{
			loadArg(1),
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.FS_IOC_SETFLAGS, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: fsIocFssetxattr, SkipTrue: 1},
			eperm,
			loadNr,
		}
	}
	if network {
		names = slices.DeleteFunc(names, func(n string) bool { return n == "socketpair" })
		blocks["socket"] = []bpf.Instruction{
			loadArg(1),
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: ^uint32(unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC)},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SOCK_RAW, SkipTrue: 3},
			loadArg(0),
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_INET, SkipTrue: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_INET6, SkipTrue: 1},
			eperm,
			bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW},
		}
	}
	for _, name := range names {
		nr, ok := info.SyscallNames[name]
		if !ok {
			if slices.Contains(seccompAbsent[info.Name], name) {
				continue
			}
			return nil, fmt.Errorf("no %s syscall number for %s", info.Name, name)
		}
		block, ok := blocks[name]
		if !ok {
			block = []bpf.Instruction{eperm}
		}
		prog = append(append(prog, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(nr), SkipTrue: uint8(len(block))}), block...)
	}
	return append(prog, bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}), nil
}

// The kernel reads these arguments as 32-bit ints, so only the low word is compared; both supported
// architectures are little-endian, which puts the low word first.
func loadArg(i uint32) bpf.Instruction {
	return bpf.LoadAbsolute{Off: seccompArgsOffset + 8*i, Size: 4}
}
