package enforce

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// A static 32-bit ARM EABI executable whose code is getpid followed by exit(0).
var arm32Executable = func() []byte {
	le := binary.LittleEndian
	b := []byte{0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b = le.AppendUint16(b, 2)
	b = le.AppendUint16(b, 40)
	for _, v := range []uint32{1, 0x10054, 52, 0, 0x05000000} {
		b = le.AppendUint32(b, v)
	}
	for _, v := range []uint16{52, 32, 1, 0, 0, 0} {
		b = le.AppendUint16(b, v)
	}
	for _, v := range []uint32{
		1, 0, 0x10000, 0x10000, 104, 104, 5, 0x1000,
		0xe3a07014, 0xef000000, 0xe3a00000, 0xe3a07001, 0xef000000,
	} {
		b = le.AppendUint32(b, v)
	}
	return b
}()

func init() {
	writeArm32Fixture = func(root string) (string, error) {
		path := filepath.Join(root, "read", "arm32")
		return path, os.WriteFile(path, arm32Executable, 0o700)
	}
	probes["arm32-syscall"] = probe{1, arm32Probe}
}

func arm32Probe(a []string) int {
	pid, err := syscall.ForkExec(a[0], []string{a[0]}, &syscall.ProcAttr{})
	switch {
	case errors.Is(err, unix.ENOEXEC):
		return probeUnsupported
	case err != nil:
		return probeFailed
	}
	ws, err := waitBounded(pid, selfTestTimeout/2)
	switch {
	case err != nil:
		return probeFailed
	case ws.Signaled() && ws.Signal() == unix.SIGSYS:
		return probeDenied
	case ws.Exited() && ws.ExitStatus() == 0:
		return probeAllowed
	default:
		return probeFailed
	}
}
