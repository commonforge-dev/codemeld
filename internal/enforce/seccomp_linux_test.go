package enforce

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var (
	wantDenyAll = []string{
		"socket", "ptrace", "process_vm_readv", "process_vm_writev", "shmget", "shmat",
		"shmctl", "msgget", "msgsnd", "msgrcv", "msgctl", "semget", "semop", "semtimedop", "semctl",
		"mq_open", "io_uring_setup", "io_uring_enter", "io_uring_register", "unshare", "setns", "mount",
		"umount2", "pivot_root", "chroot", "fsopen", "fsconfig", "fsmount", "fspick", "move_mount",
		"open_tree", "mount_setattr", "bpf",
	}
	wantDenyPlan = []string{
		"chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat", "setxattr",
		"lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "utime", "utimes",
		"utimensat", "futimesat",
	}
	seccompArches   = []*arch.Info{arch.X86_64, arch.AARCH64}
	seccompPlan     = Policy{Mode: ModePlan, BlockedPaths: []string{"/home/u/.codemeld"}}
	seccompAuto     = Policy{Mode: ModeAutoEdits, BlockedPaths: []string{"/home/u/.codemeld"}, TmpDir: "/tmp/t"}
	seccompNetwork  = Policy{Mode: ModeAutoEdits, BlockedPaths: []string{"/home/u/.codemeld"}, TmpDir: "/tmp/t", ExceptionalAuthority: NetworkAccessAuthority}
	retAllow        = uint32(unix.SECCOMP_RET_ALLOW)
	retEPERM        = uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	retENOSYS       = uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.ENOSYS)
	retKillProcess  = uint32(unix.SECCOMP_RET_KILL_PROCESS)
	threadCloneFlag = uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM)
)

type seccompVM struct {
	t    *testing.T
	vm   *bpf.VM
	info *arch.Info
}

func newSeccompVM(t *testing.T, p Policy, info *arch.Info) seccompVM {
	t.Helper()
	insts, err := seccompFilterFor(p, info)
	if err != nil {
		t.Fatalf("%s: %v", info.Name, err)
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatal(err)
	}
	return seccompVM{t, vm, info}
}

func (v seccompVM) runRaw(auditArch, nr uint32, args ...uint64) uint32 {
	v.t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:], nr)
	binary.LittleEndian.PutUint32(data[4:], auditArch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], a)
	}
	// The kernel loads seccomp_data words in native (little-endian) order; the VM loads big-endian.
	for i := 0; i < len(data); i += 4 {
		data[i], data[i+1], data[i+2], data[i+3] = data[i+3], data[i+2], data[i+1], data[i]
	}
	ret, err := v.vm.Run(data)
	if err != nil {
		v.t.Fatal(err)
	}
	return uint32(ret)
}

func (v seccompVM) run(name string, args ...uint64) uint32 {
	v.t.Helper()
	nr, ok := v.info.SyscallNames[name]
	if !ok {
		v.t.Fatalf("%s: no syscall %s", v.info.Name, name)
	}
	return v.runRaw(uint32(v.info.ID), uint32(nr), args...)
}

func deniedNames(v seccompVM) map[string]uint32 {
	out := map[string]uint32{}
	for nr, name := range v.info.SyscallNumbers {
		if ret := v.runRaw(uint32(v.info.ID), uint32(nr)); ret != retAllow {
			out[name] = ret
		}
	}
	return out
}

func present(info *arch.Info, names ...string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool { _, ok := info.SyscallNames[n]; return !ok })
}

func TestSeccompFilterDeniesExactlyTheLists(t *testing.T) {
	for _, info := range seccompArches {
		for _, tc := range []struct {
			name   string
			policy Policy
			want   []string
		}{
			{"plan", seccompPlan, append(slices.Clone(wantDenyAll), wantDenyPlan...)},
			{"auto_edits", seccompAuto, wantDenyAll},
			{"auto_edits network", seccompNetwork, wantDenyAll},
		} {
			got := deniedNames(newSeccompVM(t, tc.policy, info))
			want := map[string]uint32{"clone3": retENOSYS, "socketpair": retEPERM}
			for _, n := range present(info, tc.want...) {
				want[n] = retEPERM
			}
			if !maps.Equal(got, want) {
				t.Errorf("%s %s: denied %v, want %v", info.Name, tc.name, slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
			}
			if _, ok := got["kill"]; ok {
				t.Errorf("%s %s: kill denied", info.Name, tc.name)
			}
		}
	}
}

func TestSeccompFilterGuardsArchitecture(t *testing.T) {
	for _, info := range seccompArches {
		v := newSeccompVM(t, seccompAuto, info)
		for _, foreign := range []*arch.Info{arch.I386, arch.ARM, arch.X86_64, arch.AARCH64} {
			if foreign.ID == info.ID {
				continue
			}
			if got := v.runRaw(uint32(foreign.ID), 0); got != retKillProcess {
				t.Errorf("%s filter, %s audit arch: ret %#x, want kill", info.Name, foreign.Name, got)
			}
		}
	}
	v := newSeccompVM(t, seccompAuto, arch.X86_64)
	for _, nr := range []uint32{0, uint32(arch.X86_64.SyscallNames["getpid"])} {
		if got := v.runRaw(uint32(arch.X86_64.ID), nr|x32SyscallBit); got != retEPERM {
			t.Errorf("x32 syscall %d: ret %#x, want EPERM", nr, got)
		}
		if got := v.runRaw(uint32(arch.X86_64.ID), nr); got != retAllow {
			t.Errorf("native syscall %d: ret %#x, want allow", nr, got)
		}
	}
}

func TestSeccompArchitectureAbsentSyscalls(t *testing.T) {
	all := append(slices.Clone(wantDenyAll), wantDenyPlan...)
	all = append(all, "clone", "clone3", "ioctl", "socketpair")
	if missing := slices.DeleteFunc(slices.Clone(all), func(n string) bool { return slices.Contains(present(arch.X86_64, n), n) }); len(missing) != 0 {
		t.Errorf("x86_64 missing %v", missing)
	}
	wantAbsent := []string{"chmod", "chown", "lchown", "utime", "utimes", "futimesat"}
	missing := slices.DeleteFunc(slices.Clone(all), func(n string) bool { return slices.Contains(present(arch.AARCH64, n), n) })
	if !reflect.DeepEqual(missing, wantAbsent) || !reflect.DeepEqual(seccompAbsent["aarch64"], wantAbsent) {
		t.Errorf("aarch64 absent %v, skip list %v, want %v", missing, seccompAbsent["aarch64"], wantAbsent)
	}
	if len(seccompAbsent) != 1 {
		t.Errorf("skip lists %v, want only aarch64", seccompAbsent)
	}
}

func TestSeccompUnresolvedSyscallFailsConstruction(t *testing.T) {
	broken := &arch.Info{Name: arch.X86_64.Name, ID: arch.X86_64.ID, SyscallNames: maps.Clone(arch.X86_64.SyscallNames)}
	delete(broken.SyscallNames, "bpf")
	if _, err := seccompFilterFor(seccompAuto, broken); err == nil {
		t.Error("construction succeeded without a bpf number")
	}
	oldArch, oldLoad := nativeSeccompArch, loadSeccomp
	t.Cleanup(func() { nativeSeccompArch, loadSeccomp = oldArch, oldLoad })
	nativeSeccompArch = func() (*arch.Info, error) { return broken, nil }
	loaded := false
	loadSeccomp = func(uintptr, *unix.SockFprog) error { loaded = true; return nil }
	if err := installSeccomp(seccompAuto); err == nil || loaded {
		t.Errorf("installSeccomp err = %v, loaded = %v; want an error and no filter", err, loaded)
	}
	if _, err := seccompFilterFor(seccompAuto, arch.I386); err == nil {
		t.Error("constructed a filter for i386")
	}
}

func TestSeccompClone(t *testing.T) {
	policies := map[string]Policy{"plan": seccompPlan, "auto_edits": seccompAuto, "auto_edits network": seccompNetwork}
	for _, info := range seccompArches {
		for name, p := range policies {
			v := newSeccompVM(t, p, info)
			for _, flags := range []uint64{threadCloneFlag, uint64(unix.SIGCHLD), 0} {
				if got := v.run("clone", flags); got != retAllow {
					t.Errorf("%s %s clone %#x: ret %#x, want allow", info.Name, name, flags, got)
				}
			}
			for _, flag := range []uint64{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWPID, unix.CLONE_NEWNET, unix.CLONE_NEWIPC, unix.CLONE_NEWUTS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWTIME} {
				if got := v.run("clone", uint64(unix.SIGCHLD)|flag); got != retEPERM {
					t.Errorf("%s %s clone %#x: ret %#x, want EPERM", info.Name, name, flag, got)
				}
			}
			if got := v.run("clone3"); got != retENOSYS {
				t.Errorf("%s %s clone3: ret %#x, want ENOSYS", info.Name, name, got)
			}
		}
	}
}

func TestSeccompIoctl(t *testing.T) {
	for _, info := range seccompArches {
		plan, auto := newSeccompVM(t, seccompPlan, info), newSeccompVM(t, seccompAuto, info)
		for _, req := range []uint64{unix.FS_IOC_SETFLAGS, fsIocFssetxattr, 1<<32 | unix.FS_IOC_SETFLAGS} {
			if got := plan.run("ioctl", 3, req); got != retEPERM {
				t.Errorf("%s plan ioctl %#x: ret %#x, want EPERM", info.Name, req, got)
			}
			if got := auto.run("ioctl", 3, req); got != retAllow {
				t.Errorf("%s auto_edits ioctl %#x: ret %#x, want allow", info.Name, req, got)
			}
		}
		if got := plan.run("ioctl", 3, unix.TCGETS); got != retAllow {
			t.Errorf("%s plan ioctl TCGETS: ret %#x, want allow", info.Name, got)
		}
	}
}

func TestSeccompNetworkVariant(t *testing.T) {
	flagSets := []uint64{0, unix.SOCK_NONBLOCK, unix.SOCK_CLOEXEC, unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC}
	for _, info := range seccompArches {
		net, auto := newSeccompVM(t, seccompNetwork, info), newSeccompVM(t, seccompAuto, info)
		for _, family := range []uint64{unix.AF_INET, unix.AF_INET6} {
			for _, flags := range flagSets {
				for _, typ := range []uint64{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
					if got := net.run("socket", family, typ|flags); got != retAllow {
						t.Errorf("%s network socket(%d, %#x): ret %#x, want allow", info.Name, family, typ|flags, got)
					}
					if got := auto.run("socket", family, typ|flags); got != retEPERM {
						t.Errorf("%s auto_edits socket(%d, %#x): ret %#x, want EPERM", info.Name, family, typ|flags, got)
					}
				}
				if got := net.run("socket", family, unix.SOCK_RAW|flags); got != retEPERM {
					t.Errorf("%s network raw socket(%d, %#x): ret %#x, want EPERM", info.Name, family, flags, got)
				}
			}
		}
		for _, family := range []uint64{unix.AF_UNIX, unix.AF_NETLINK, unix.AF_PACKET, 1<<32 | unix.AF_UNIX} {
			if got := net.run("socket", family, unix.SOCK_STREAM); got != retEPERM {
				t.Errorf("%s network socket family %#x: ret %#x, want EPERM", info.Name, family, got)
			}
		}
		for _, flags := range flagSets {
			for _, typ := range []uint64{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
				if got := net.run("socketpair", unix.AF_UNIX, typ|flags); got != retAllow {
					t.Errorf("%s network socketpair(AF_UNIX, %#x): ret %#x, want allow", info.Name, typ|flags, got)
				}
			}
		}
	}
}

func TestSeccompSocketpair(t *testing.T) {
	policies := map[string]Policy{"plan": seccompPlan, "auto_edits": seccompAuto, "auto_edits network": seccompNetwork}
	for _, info := range seccompArches {
		for name, p := range policies {
			v := newSeccompVM(t, p, info)
			for _, flags := range []uint64{0, unix.SOCK_NONBLOCK, unix.SOCK_CLOEXEC, unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC} {
				for _, typ := range []uint64{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
					if got := v.run("socketpair", unix.AF_UNIX, typ|flags); got != retAllow {
						t.Errorf("%s %s socketpair(AF_UNIX, %#x): ret %#x, want allow", info.Name, name, typ|flags, got)
					}
				}
			}
			for _, family := range []uint64{unix.AF_UNSPEC, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK, unix.AF_TIPC, 1000} {
				for _, typ := range []uint64{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
					if got := v.run("socketpair", family, typ); got != retEPERM {
						t.Errorf("%s %s socketpair(%d, %#x): ret %#x, want EPERM", info.Name, name, family, typ, got)
					}
				}
			}
			for _, typ := range []uint64{unix.SOCK_DGRAM, unix.SOCK_RAW, unix.SOCK_STREAM | 0x100, unix.SOCK_SEQPACKET | 0x100} {
				if got := v.run("socketpair", unix.AF_UNIX, typ); got != retEPERM {
					t.Errorf("%s %s socketpair(AF_UNIX, %#x): ret %#x, want EPERM", info.Name, name, typ, got)
				}
			}
		}
	}
}

func TestInstallSeccompPassesTSYNC(t *testing.T) {
	old := loadSeccomp
	t.Cleanup(func() { loadSeccomp = old })
	var flags uintptr
	var length uint16
	loadSeccomp = func(f uintptr, prog *unix.SockFprog) error { flags, length = f, prog.Len; return nil }
	if err := installSeccomp(seccompPlan); err != nil {
		t.Fatal(err)
	}
	if flags != unix.SECCOMP_FILTER_FLAG_TSYNC || length == 0 {
		t.Errorf("flags %#x, length %d; want TSYNC and a program", flags, length)
	}
	loadSeccomp = func(uintptr, *unix.SockFprog) error { return unix.EINVAL }
	if err := installSeccomp(seccompPlan); !errors.Is(err, unix.EINVAL) {
		t.Errorf("install error = %v, want EINVAL", err)
	}
}

var (
	seccompSlice   = Policy{Mode: ModeAutoEdits, BlockedPaths: []string{"/home/u/.codemeld"}, TmpDir: "/tmp/t", Broker: "slice"}
	seccompFull    = Policy{Mode: ModeAutoEdits, BlockedPaths: []string{"/home/u/.codemeld"}, TmpDir: "/tmp/t", Broker: "full"}
	seccompConnect = Policy{Mode: ModeAutoEdits, BlockedPaths: []string{"/home/u/.codemeld"}, TmpDir: "/tmp/t", Broker: "connect"}
	seccompBrokers = map[string]Policy{"slice": seccompSlice, "full": seccompFull, "connect": seccompConnect}
	retNotify      = uint32(unix.SECCOMP_RET_USER_NOTIF)
)

func brokerSocketAllowed(mode string, family, typ, proto uint64) bool {
	base := uint32(typ) &^ (unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC)
	switch uint32(family) {
	case unix.AF_INET, unix.AF_INET6:
		return base == unix.SOCK_STREAM && (uint32(proto) == 0 || uint32(proto) == unix.IPPROTO_TCP)
	case unix.AF_UNIX:
		return mode != "slice" && (base == unix.SOCK_STREAM || base == unix.SOCK_SEQPACKET) && uint32(proto) == 0
	}
	return false
}

func TestSeccompBrokerSocketMatrix(t *testing.T) {
	families := []uint64{unix.AF_UNSPEC, unix.AF_INET, unix.AF_INET6, unix.AF_UNIX, unix.AF_NETLINK, unix.AF_PACKET, 1<<32 | unix.AF_INET, 1<<32 | unix.AF_UNIX}
	types := []uint64{unix.SOCK_STREAM, unix.SOCK_SEQPACKET, unix.SOCK_DGRAM, unix.SOCK_RAW, unix.SOCK_STREAM | 0x100, 1<<32 | unix.SOCK_STREAM}
	protos := []uint64{0, unix.IPPROTO_TCP, unix.IPPROTO_SCTP, unix.IPPROTO_MPTCP, unix.IPPROTO_UDP, 1<<32 | unix.IPPROTO_TCP}
	for _, info := range seccompArches {
		for name, p := range seccompBrokers {
			v := newSeccompVM(t, p, info)
			for _, family := range families {
				for _, typ := range types {
					for _, flags := range []uint64{0, unix.SOCK_NONBLOCK, unix.SOCK_CLOEXEC, unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC} {
						for _, proto := range protos {
							want := retEPERM
							if brokerSocketAllowed(name, family, typ|flags, proto) {
								want = retAllow
							}
							if got := v.run("socket", family, typ|flags, proto); got != want {
								t.Errorf("%s %s socket(%#x, %#x, %#x): ret %#x, want %#x", info.Name, name, family, typ|flags, proto, got, want)
							}
						}
					}
				}
			}
		}
	}
}

func TestSeccompBrokerCallsAndPreservedDenials(t *testing.T) {
	for _, info := range seccompArches {
		for name, p := range seccompBrokers {
			v := newSeccompVM(t, p, info)
			bindListen := retEPERM
			if name == "full" {
				bindListen = retNotify
			}
			want := map[string]uint32{"clone3": retENOSYS, "socketpair": retEPERM, "connect": retNotify, "bind": bindListen, "listen": bindListen}
			for _, n := range present(info, wantDenyAll...) {
				want[n] = retEPERM
			}
			if got := deniedNames(v); !maps.Equal(got, want) {
				t.Errorf("%s %s: denied %v, want %v", info.Name, name, got, want)
			}
			for _, call := range []string{"connect", "bind", "listen"} {
				if got, w := v.run(call, 3, 1<<40, 16), want[call]; got != w {
					t.Errorf("%s %s %s: ret %#x, want %#x", info.Name, name, call, got, w)
				}
			}
			for _, flags := range []uint64{threadCloneFlag, uint64(unix.SIGCHLD)} {
				if got := v.run("clone", flags); got != retAllow {
					t.Errorf("%s %s clone %#x: ret %#x, want allow", info.Name, name, flags, got)
				}
			}
			for _, flag := range []uint64{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWPID, unix.CLONE_NEWNET, unix.CLONE_NEWIPC, unix.CLONE_NEWUTS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWTIME} {
				if got := v.run("clone", uint64(unix.SIGCHLD)|flag); got != retEPERM {
					t.Errorf("%s %s clone %#x: ret %#x, want EPERM", info.Name, name, flag, got)
				}
			}
			for _, foreign := range []*arch.Info{arch.I386, arch.ARM, arch.X86_64, arch.AARCH64} {
				if foreign.ID != info.ID {
					if got := v.runRaw(uint32(foreign.ID), 0); got != retKillProcess {
						t.Errorf("%s %s, %s audit arch: ret %#x, want kill", info.Name, name, foreign.Name, got)
					}
				}
			}
			if info == arch.X86_64 {
				for _, call := range []string{"getpid", "connect", "socket"} {
					if got := v.runRaw(uint32(info.ID), uint32(info.SyscallNames[call])|x32SyscallBit, unix.AF_INET, unix.SOCK_STREAM); got != retEPERM {
						t.Errorf("%s x32 %s: ret %#x, want EPERM", name, call, got)
					}
				}
			}
			for _, flags := range []uint64{0, unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC} {
				for _, typ := range []uint64{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
					if got := v.run("socketpair", unix.AF_UNIX, typ|flags); got != retAllow {
						t.Errorf("%s %s socketpair(AF_UNIX, %#x): ret %#x, want allow", info.Name, name, typ|flags, got)
					}
				}
			}
			for _, args := range [][2]uint64{{unix.AF_UNIX, unix.SOCK_DGRAM}, {unix.AF_UNIX, unix.SOCK_RAW}, {unix.AF_INET, unix.SOCK_STREAM}, {unix.AF_UNIX, unix.SOCK_STREAM | 0x100}} {
				if got := v.run("socketpair", args[0], args[1]); got != retEPERM {
					t.Errorf("%s %s socketpair(%d, %#x): ret %#x, want EPERM", info.Name, name, args[0], args[1], got)
				}
			}
		}
	}
}

func TestSeccompPlanSliceKeepsPlanDenials(t *testing.T) {
	p := Policy{Mode: ModePlan, BlockedPaths: []string{"/home/u/.codemeld"}, Broker: "slice"}
	for _, info := range seccompArches {
		v := newSeccompVM(t, p, info)
		want := map[string]uint32{"clone3": retENOSYS, "socketpair": retEPERM, "connect": retNotify, "bind": retEPERM, "listen": retEPERM}
		for _, n := range present(info, append(slices.Clone(wantDenyAll), wantDenyPlan...)...) {
			want[n] = retEPERM
		}
		if got := deniedNames(v); !maps.Equal(got, want) {
			t.Errorf("%s: denied %v, want %v", info.Name, got, want)
		}
		if got := v.run("connect", 3, 1<<40, 16); got != retNotify {
			t.Errorf("%s connect: ret %#x, want notify", info.Name, got)
		}
		for _, req := range []uint64{unix.FS_IOC_SETFLAGS, fsIocFssetxattr} {
			if got := v.run("ioctl", 3, req); got != retEPERM {
				t.Errorf("%s ioctl %#x: ret %#x, want EPERM", info.Name, req, got)
			}
		}
		if got := v.run("socket", unix.AF_INET, unix.SOCK_STREAM, 0); got != retAllow {
			t.Errorf("%s socket(AF_INET, SOCK_STREAM): ret %#x, want allow", info.Name, got)
		}
	}
}

func TestSeccompBrokerFastOpen(t *testing.T) {
	for _, info := range seccompArches {
		for name, p := range seccompBrokers {
			v := newSeccompVM(t, p, info)
			for call, flagsArg := range map[string]int{"sendto": 3, "sendmsg": 2, "sendmmsg": 3} {
				for flags, want := range map[uint64]uint32{
					unix.MSG_FASTOPEN:                     retEPERM,
					unix.MSG_FASTOPEN | unix.MSG_DONTWAIT: retEPERM,
					1<<32 | unix.MSG_FASTOPEN:             retEPERM,
					unix.MSG_FASTOPEN << 32:               retAllow,
					unix.MSG_DONTWAIT | unix.MSG_NOSIGNAL: retAllow,
					0:                                     retAllow,
				} {
					args := make([]uint64, 6)
					args[flagsArg] = flags
					if got := v.run(call, args...); got != want {
						t.Errorf("%s %s %s flags %#x in arg %d: ret %#x, want %#x", info.Name, name, call, flags, flagsArg, got, want)
					}
				}
				for i := range 6 {
					if i == flagsArg {
						continue
					}
					args := make([]uint64, 6)
					args[i] = unix.MSG_FASTOPEN
					if got := v.run(call, args...); got != retAllow {
						t.Errorf("%s %s %s MSG_FASTOPEN in arg %d: ret %#x, want allow", info.Name, name, call, i, got)
					}
				}
			}
		}
	}
}

func TestSeccompBrokerSetsockopt(t *testing.T) {
	const solSocket, soReuseaddr, soReuseport, ipprotoTCP = 1, 2, 15, 6
	policies := map[string]Policy{"auto": seccompAuto, "network": seccompNetwork}
	maps.Copy(policies, seccompBrokers)
	for _, info := range seccompArches {
		for name, p := range policies {
			v := newSeccompVM(t, p, info)
			reuseport := retAllow
			if name == "full" {
				reuseport = retEPERM
			}
			for _, tc := range []struct {
				level, opt uint64
				want       uint32
			}{
				{solSocket, soReuseport, reuseport},
				{1<<32 | solSocket, 1<<32 | soReuseport, reuseport},
				{solSocket, soReuseaddr, retAllow},
				{ipprotoTCP, soReuseport, retAllow},
				{soReuseport, solSocket, retAllow},
			} {
				if got := v.run("setsockopt", 3, tc.level, tc.opt, 0, 4); got != tc.want {
					t.Errorf("%s %s setsockopt(3, %#x, %#x): ret %#x, want %#x", info.Name, name, tc.level, tc.opt, got, tc.want)
				}
			}
		}
	}
}

func TestSeccompBrokerRejectsBadPolicies(t *testing.T) {
	network, plan, unknown := seccompFull, seccompFull, seccompSlice
	network.ExceptionalAuthority = NetworkAccessAuthority
	plan.Mode, plan.TmpDir = ModePlan, ""
	unknown.Broker = "bind"
	connectNetwork, connectPlan := network, plan
	connectNetwork.Broker, connectPlan.Broker = "connect", "connect"
	oldLoad, oldListener := loadSeccomp, loadSeccompListener
	t.Cleanup(func() { loadSeccomp, loadSeccompListener = oldLoad, oldListener })
	loads := 0
	loadSeccomp = func(uintptr, *unix.SockFprog) error { loads++; return nil }
	loadSeccompListener = func(uintptr, *unix.SockFprog) (int, error) { loads++; return 7, nil }
	for name, p := range map[string]Policy{"network": network, "plan": plan, "unknown": unknown, "connect network": connectNetwork, "connect plan": connectPlan} {
		for _, info := range seccompArches {
			if _, err := seccompFilterFor(p, info); err == nil {
				t.Errorf("%s: %s filter constructed", name, info.Name)
			}
		}
		if fd, err := installSeccompListener(p); err == nil || fd != -1 {
			t.Errorf("%s: installSeccompListener = %d, %v; want -1 and an error", name, fd, err)
		}
		if err := installSeccomp(p); err == nil {
			t.Errorf("%s: installSeccomp accepted", name)
		}
	}
	for name, p := range seccompBrokers {
		if err := installSeccomp(p); err == nil {
			t.Errorf("installSeccomp accepted %s", name)
		}
	}
	if fd, err := installSeccompListener(seccompAuto); err == nil || fd != -1 {
		t.Errorf("installSeccompListener(non-broker) = %d, %v; want -1 and an error", fd, err)
	}
	if loads != 0 {
		t.Errorf("%d load seam calls, want 0", loads)
	}
}

func TestInstallSeccompListenerFlagsAndErrors(t *testing.T) {
	oldLoad, oldListener := loadSeccomp, loadSeccompListener
	t.Cleanup(func() { loadSeccomp, loadSeccompListener = oldLoad, oldListener })
	loadSeccomp = func(uintptr, *unix.SockFprog) error { t.Error("installSeccompListener used loadSeccomp"); return nil }
	var calls []uintptr
	var length uint16
	result := func(fd int, err error) func(uintptr, *unix.SockFprog) (int, error) {
		calls = nil
		return func(f uintptr, prog *unix.SockFprog) (int, error) {
			calls, length = append(calls, f), prog.Len
			return fd, err
		}
	}
	wantFlags := []uintptr{unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH}
	for _, p := range seccompBrokers {
		loadSeccompListener = result(0, nil)
		if fd, err := installSeccompListener(p); fd != 0 || err != nil {
			t.Errorf("%s: install = %d, %v; want descriptor 0", p.Broker, fd, err)
		}
		if !slices.Equal(calls, wantFlags) || length == 0 {
			t.Errorf("%s: flags %#x, length %d; want one load with %#x and a program", p.Broker, calls, length, wantFlags)
		}
	}
	for _, errno := range []unix.Errno{unix.ESRCH, unix.EINVAL} {
		loadSeccompListener = result(-1, errno)
		fd, err := installSeccompListener(seccompSlice)
		if fd != -1 || !errors.Is(err, errno) || len(calls) != 1 {
			t.Errorf("%v: install = %d, %v after %d loads; want -1, the errno and one load", errno, fd, err, len(calls))
		}
		if synced := err != nil && strings.Contains(err.Error(), "synchronize"); synced != (errno == unix.ESRCH) {
			t.Errorf("%v: error %q reports a sync failure: %v", errno, err, synced)
		}
	}
}

const seccompChildEnv = "CODEMELD_TEST_SECCOMP_LISTENER_CHILD"

const pausedErrno = unix.ENOTRECOVERABLE

type seccompKernelCase struct {
	name string
	want string
	nr   int
	call func() error
}

func seccompKernelCases(mode string) []seccompKernelCase {
	verdict := map[bool]string{true: "allow", false: "deny"}
	var cases []seccompKernelCase
	for _, family := range []int{unix.AF_INET, unix.AF_INET6, unix.AF_UNIX, unix.AF_NETLINK, unix.AF_PACKET} {
		for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_STREAM | unix.SOCK_NONBLOCK, unix.SOCK_STREAM | unix.SOCK_CLOEXEC,
			unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC, unix.SOCK_SEQPACKET, unix.SOCK_SEQPACKET | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC,
			unix.SOCK_DGRAM, unix.SOCK_RAW} {
			for _, proto := range []int{0, unix.IPPROTO_TCP, unix.IPPROTO_SCTP} {
				cases = append(cases, seccompKernelCase{
					fmt.Sprintf("socket(%d,%#x,%d)", family, typ, proto),
					verdict[brokerSocketAllowed(mode, uint64(family), uint64(typ), uint64(proto))], 0,
					func() error {
						fd, err := unix.Socket(family, typ, proto)
						if err == nil {
							_ = unix.Close(fd)
						}
						return err
					},
				})
			}
		}
	}
	for _, sp := range []struct {
		family, typ int
		allowed     bool
	}{
		{unix.AF_UNIX, unix.SOCK_STREAM, true}, {unix.AF_UNIX, unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC, true},
		{unix.AF_UNIX, unix.SOCK_SEQPACKET, true}, {unix.AF_UNIX, unix.SOCK_SEQPACKET | unix.SOCK_NONBLOCK, true},
		{unix.AF_UNIX, unix.SOCK_DGRAM, false}, {unix.AF_INET, unix.SOCK_STREAM, false},
	} {
		cases = append(cases, seccompKernelCase{fmt.Sprintf("socketpair(%d,%#x)", sp.family, sp.typ), verdict[sp.allowed], 0, func() error {
			fds, err := unix.Socketpair(sp.family, sp.typ, 0)
			if err == nil {
				_, _ = unix.Close(fds[0]), unix.Close(fds[1])
			}
			return err
		}})
	}
	with := func(domain int, f func(fd int) error) func() error {
		return func() error {
			fds, err := [2]int{-1, -1}, error(nil)
			if domain == unix.AF_UNIX {
				fds, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			} else {
				fds[0], err = unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			}
			if err != nil {
				return fmt.Errorf("%w socket: %w", errSeccompFixture, err)
			}
			defer func() { _, _ = unix.Close(fds[0]), unix.Close(fds[1]) }()
			return f(fds[0])
		}
	}
	payload := []byte("x")
	dst := unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: [4]byte{127, 0, 0, 1}}
	setRawPort(&dst, 9)
	sendmmsg := func(fd int, name *unix.RawSockaddrInet4, flags int) error {
		iov := unix.Iovec{Base: &payload[0]}
		iov.SetLen(len(payload))
		var m unix.Mmsghdr
		if name != nil {
			m.Hdr.Name, m.Hdr.Namelen = (*byte)(unsafe.Pointer(name)), uint32(unsafe.Sizeof(*name))
		}
		m.Hdr.Iov = &iov
		m.Hdr.SetIovlen(1)
		_, _, e := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&m)), 1, uintptr(flags), 0, 0)
		return errnoErr(e)
	}
	abstract := &unix.SockaddrUnix{Name: "@codemeld-seccomp-listener-test"}
	bindListen, bindNr, listenNr := "deny", 0, 0
	if mode == "full" {
		bindListen, bindNr, listenNr = "pause", unix.SYS_BIND, unix.SYS_LISTEN
	}
	cases = append(cases,
		seccompKernelCase{"connect tcp", "pause", unix.SYS_CONNECT, with(unix.AF_INET, func(fd int) error { return unix.Connect(fd, loopback4(9)) })},
		seccompKernelCase{"connect socketpair", "pause", unix.SYS_CONNECT, with(unix.AF_UNIX, func(fd int) error { return unix.Connect(fd, abstract) })},
		seccompKernelCase{"bind tcp", bindListen, bindNr, with(unix.AF_INET, func(fd int) error { return unix.Bind(fd, loopback4(0)) })},
		seccompKernelCase{"listen tcp", bindListen, listenNr, with(unix.AF_INET, func(fd int) error { return unix.Listen(fd, 1) })},
		seccompKernelCase{"sendto fastopen", "deny", 0, with(unix.AF_INET, func(fd int) error { return unix.Sendto(fd, payload, unix.MSG_FASTOPEN, loopback4(9)) })},
		seccompKernelCase{"sendmsg fastopen", "deny", 0, with(unix.AF_INET, func(fd int) error {
			_, err := unix.SendmsgN(fd, payload, nil, loopback4(9), unix.MSG_FASTOPEN)
			return err
		})},
		seccompKernelCase{"sendmmsg fastopen", "deny", 0, with(unix.AF_INET, func(fd int) error { return sendmmsg(fd, &dst, unix.MSG_FASTOPEN) })},
		seccompKernelCase{"sendto plain", "allow", 0, with(unix.AF_UNIX, func(fd int) error { return unix.Sendto(fd, payload, 0, nil) })},
		seccompKernelCase{"sendmsg plain", "allow", 0, with(unix.AF_UNIX, func(fd int) error {
			_, err := unix.SendmsgN(fd, payload, nil, nil, 0)
			return err
		})},
		seccompKernelCase{"sendmmsg plain", "allow", 0, with(unix.AF_UNIX, func(fd int) error { return sendmmsg(fd, nil, 0) })},
	)
	if mode != "slice" {
		cases = append(cases, seccompKernelCase{"connect unix socket", "pause", unix.SYS_CONNECT, func() error {
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("%w socket: %w", errSeccompFixture, err)
			}
			defer func() { _ = unix.Close(fd) }()
			return unix.Connect(fd, abstract)
		}})
	}
	return cases
}

func TestSeccompListenerChild(t *testing.T) {
	mode := os.Getenv(seccompChildEnv)
	if mode == "" {
		t.Skip("runs only as the disposable child of the seccomp listener tests")
	}
	send := func(msg string, oob []byte) {
		if err := unix.Sendmsg(3, []byte(msg), oob, nil, 0); err != nil {
			t.Fatalf("fixture: sending %q: %v", msg, err)
		}
	}
	errno := func(err error) string {
		var e unix.Errno
		if errors.As(err, &e) {
			return unix.ErrnoName(e)
		}
		return fmt.Sprint(err)
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if mode == "tsync" {
		allow, err := bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}})
		if err != nil {
			t.Fatal(err)
		}
		filter := []unix.SockFilter{{Code: allow[0].Op, K: allow[0].K}}
		ready := make(chan error)
		go func() {
			runtime.LockOSThread()
			err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
			if err == nil {
				err = loadSeccomp(0, &unix.SockFprog{Len: 1, Filter: &filter[0]})
			}
			ready <- err
			select {}
		}()
		if err := <-ready; err != nil {
			t.Fatal(err)
		}
		fd, err := installSeccompListener(seccompSlice)
		send(fmt.Sprintf("tsync=%s fd=%d sync=%v", errno(err), fd, err != nil && strings.Contains(err.Error(), "synchronize")), nil)
		return
	}
	fd, err := installSeccompListener(seccompBrokers[mode])
	if err != nil {
		send("install="+errno(err), nil)
		return
	}
	send("listener", unix.UnixRights(fd))
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	send("closed", nil)
	buf := make([]byte, 16)
	if n, err := unix.Read(3, buf); err != nil || string(buf[:n]) != "go" {
		t.Fatalf("waiting for go: %q %v", buf[:n], err)
	}
	for _, c := range seccompKernelCases(mode) {
		send(seccompVerdict(c.call())+" "+c.name, nil)
	}
	send("done", nil)
}

var errSeccompFixture = errors.New("fixture")

func seccompVerdict(err error) string {
	var e unix.Errno
	switch {
	case err == nil:
		return "allow"
	case errors.Is(err, errSeccompFixture):
		if errors.As(err, &e) {
			return "fixture=" + unix.ErrnoName(e)
		}
		return "fixture"
	case errors.Is(err, unix.EPERM):
		return "deny"
	case errors.Is(err, pausedErrno):
		return "pause"
	case errors.As(err, &e):
		return "errno=" + unix.ErrnoName(e)
	}
	return "error"
}

func TestSeccompVerdict(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, "allow"},
		{unix.EPERM, "deny"},
		{pausedErrno, "pause"},
		{unix.EAFNOSUPPORT, "errno=EAFNOSUPPORT"},
		{fmt.Errorf("%w socket: %w", errSeccompFixture, unix.EPERM), "fixture=EPERM"},
		{fmt.Errorf("%w socket: %w", errSeccompFixture, unix.EMFILE), "fixture=EMFILE"},
		{errors.New("other"), "error"},
	} {
		if got := seccompVerdict(c.err); got != c.want {
			t.Errorf("seccompVerdict(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

type seccompListenerChild struct {
	cmd  *exec.Cmd
	ctl  *net.UnixConn
	done chan struct{}
	out  strings.Builder
	err  error
}

func startSeccompListenerChild(t *testing.T, mode string) (*seccompListenerChild, string, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentEnd, childEnd := os.NewFile(uintptr(fds[0]), "ctl"), os.NewFile(uintptr(fds[1]), "child-ctl")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	c := &seccompListenerChild{done: make(chan struct{})}
	c.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSeccompListenerChild$")
	c.cmd.Env = append(os.Environ(), seccompChildEnv+"="+mode)
	c.cmd.ExtraFiles = []*os.File{childEnd}
	c.cmd.Stdout, c.cmd.Stderr = &c.out, &c.out
	err = c.cmd.Start()
	closed(t, "the child's control end", childEnd.Close())
	if err != nil {
		closed(t, "the control end", parentEnd.Close())
		cancel()
		t.Fatal(err)
	}
	go func() { c.err = c.cmd.Wait(); close(c.done) }()
	listener := -1
	t.Cleanup(func() {
		cancel()
		<-c.done
		if listener >= 0 {
			closed(t, "the listener", unix.Close(listener))
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
	msg, oob := c.read(t, unix.CmsgSpace(4))
	if msg == "listener" {
		msgs, err := unix.ParseSocketControlMessage(oob)
		if err != nil || len(msgs) != 1 {
			c.fatalf(t, "listener message: %v", err)
		}
		rights, err := unix.ParseUnixRights(&msgs[0])
		if err != nil || len(rights) != 1 {
			c.fatalf(t, "listener rights: %v", err)
		}
		listener = rights[0]
	}
	return c, msg, listener
}

func (c *seccompListenerChild) read(t *testing.T, oobLen int) (string, []byte) {
	t.Helper()
	if err := c.ctl.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.fatalf(t, "%v", err)
	}
	b, oob := make([]byte, 128), make([]byte, oobLen)
	n, oobn, _, _, err := c.ctl.ReadMsgUnix(b, oob)
	if err != nil {
		c.fatalf(t, "reading from the child: %v", err)
	}
	return string(b[:n]), oob[:oobn]
}

func (c *seccompListenerChild) fatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	_ = c.cmd.Process.Kill()
	<-c.done
	t.Fatalf(format+"\nchild (%v) output:\n%s", append(args, c.err, c.out.String())...)
}

func TestSeccompListenerKernelVariants(t *testing.T) {
	for _, mode := range []string{"slice", "full", "connect"} {
		t.Run(mode, func(t *testing.T) {
			c, msg, listener := startSeccompListenerChild(t, mode)
			if listener < 0 {
				if msg == "install=EINVAL" || msg == "install=ENOSYS" {
					t.Skipf("unverified: the kernel refused NEW_LISTENER|TSYNC|TSYNC_ESRCH (%s)", msg)
				}
				c.fatalf(t, "child: %s", msg)
			}
			if got, _ := c.read(t, 0); got != "closed" {
				c.fatalf(t, "want closed, got %q", got)
			}
			if n := notifyListeners(t, strconv.Itoa(c.cmd.Process.Pid)); n != 0 {
				c.fatalf(t, "child still holds %d listener descriptors", n)
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var paused []int
			var notifyErr error
			wg.Add(1)
			shutdown := sync.OnceFunc(func() { close(stop); wg.Wait() })
			t.Cleanup(shutdown)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					revents, err := pollFD(listener, unix.POLLIN, 100*time.Millisecond)
					if err != nil {
						notifyErr = err
						return
					}
					if revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
						notifyErr = fmt.Errorf("listener poll events %#x", revents)
						return
					}
					if revents&unix.POLLIN == 0 {
						if revents&unix.POLLHUP != 0 {
							return
						}
						continue
					}
					var n seccompNotif
					if err := ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n)); err != nil {
						notifyErr = fmt.Errorf("SECCOMP_IOCTL_NOTIF_RECV: %w", err)
						return
					}
					paused = append(paused, int(n.Nr))
					resp := seccompNotifResp{ID: n.ID, Error: -int32(pausedErrno)}
					if err := ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp)); err != nil {
						notifyErr = fmt.Errorf("SECCOMP_IOCTL_NOTIF_SEND: %w", err)
						return
					}
				}
			}()
			if _, err := c.ctl.Write([]byte("go")); err != nil {
				c.fatalf(t, "send go: %v", err)
			}
			got := map[string]string{}
			for {
				msg, _ := c.read(t, 0)
				if msg == "done" {
					break
				}
				verdict, name, _ := strings.Cut(msg, " ")
				got[name] = verdict
			}
			shutdown()
			if notifyErr != nil {
				c.fatalf(t, "broker: %v", notifyErr)
			}
			cases, wantPaused := seccompKernelCases(mode), []int{}
			for _, kc := range cases {
				if kc.want == "pause" {
					wantPaused = append(wantPaused, kc.nr)
				}
				t.Run(kc.name, func(t *testing.T) {
					switch g := got[kc.name]; {
					case g == kc.want:
					case kc.want == "allow" && strings.HasPrefix(g, "errno="):
						t.Skipf("unverified: the kernel refused the allowed call with %s", strings.TrimPrefix(g, "errno="))
					default:
						t.Errorf("%s, want %s", g, kc.want)
					}
				})
			}
			if len(got) != len(cases) || !slices.Equal(paused, wantPaused) {
				t.Errorf("%d results for %d cases; paused syscalls %v, want %v", len(got), len(cases), paused, wantPaused)
			}
		})
	}
}

func TestSeccompListenerKernelSyncFailure(t *testing.T) {
	c, msg, listener := startSeccompListenerChild(t, "tsync")
	if listener >= 0 {
		c.fatalf(t, "child sent a listener")
	}
	if strings.HasPrefix(msg, "tsync=EINVAL") {
		t.Skipf("unverified: the kernel refused NEW_LISTENER|TSYNC|TSYNC_ESRCH (%s)", msg)
	}
	if msg != "tsync=ESRCH fd=-1 sync=true" {
		c.fatalf(t, "child: %s, want a reported ESRCH sync failure", msg)
	}
}
