//go:build darwin

package procowner

import (
	"errors"

	"golang.org/x/sys/unix"
)

func probeStartTimeSyscall(pid int) (string, error) {
	proc, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return "", errProcessAbsent
		}
		return "", err
	}
	start := proc.Proc.P_starttime
	return formatTimeval(int64(start.Sec), int64(start.Usec)), nil
}
