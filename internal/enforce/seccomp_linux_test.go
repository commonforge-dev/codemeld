package enforce

import (
	"encoding/binary"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var (
	wantDenyAll = []string{
		"socket", "socketpair", "ptrace", "process_vm_readv", "process_vm_writev", "shmget", "shmat",
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
			{"auto_edits network", seccompNetwork, slices.DeleteFunc(slices.Clone(wantDenyAll), func(n string) bool { return n == "socketpair" })},
		} {
			got := deniedNames(newSeccompVM(t, tc.policy, info))
			want := map[string]uint32{"clone3": retENOSYS}
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
	all = append(all, "clone", "clone3", "ioctl")
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
		if got := net.run("socketpair", unix.AF_UNIX, unix.SOCK_STREAM); got != retAllow {
			t.Errorf("%s network socketpair: ret %#x, want allow", info.Name, got)
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
