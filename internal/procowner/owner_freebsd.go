//go:build freebsd

package procowner

import (
	"errors"

	"golang.org/x/sys/unix"
)

func probeStartTimeSyscall(pid int) (string, error) {
	raw, err := unix.SysctlRaw("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return "", errProcessAbsent
		}
		return "", err
	}
	return decodeFreeBSDStartTime(raw)
}
