package enforce

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestX32SyscallProbeMapsENOSYSToDenied(t *testing.T) {
	if _, _, errno := unix.RawSyscall(unix.SYS_GETPID|x32SyscallBit, 0, 0, 0); errno != unix.ENOSYS {
		t.Skipf("x32 ABI enabled on this kernel (x32 getpid errno %d), so its ENOSYS refusal is not observable", errno)
	}
	if got := runProbe(&helperState{}, []string{"x32-syscall"}); got != probeDenied {
		t.Errorf("x32-syscall: exit %d, want %d", got, probeDenied)
	}
}

func TestI386SyscallProbeRunsCgoFree(t *testing.T) {
	if gap := hostIA32EmulationGap(); gap != "" {
		t.Skipf("ia32 emulation unavailable: %s", gap)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "enforce.test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cgo-free test binary: %v\n%s", err, out)
	}
	runCtx, runCancel := context.WithTimeout(ctx, 30*time.Second)
	defer runCancel()
	out, err := exec.CommandContext(runCtx, bin, "-test.run=^TestProbeChild$", "--", "i386-syscall").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "probe exit=0\n") {
		t.Errorf("i386-syscall: %v\n%s", err, out)
	}
}
