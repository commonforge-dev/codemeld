package bootstrap

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const sessionTempDirPrefix = "codemeld-confine-"

var (
	beforeSessionTempDirChmod   func(created string)
	afterSessionTempDirChmod    func(created string)
	duringSessionTempDirCleanup func(dir string)
	beforeSessionTempDirUnlink  func(dir string)
	afterStaleScanParentOpen    func(parent string)
)

func (d *sessionTempDir) folder() string {
	if d == nil {
		return ""
	}
	return d.path
}

func (d *sessionTempDir) recordFailure() error {
	if d == nil {
		return nil
	}
	return d.recordErr
}

func (d *sessionTempDir) removeAndRelease() error {
	err := d.remove()
	d.close()
	return err
}

func sessionTempDirPID(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, sessionTempDirPrefix)
	if !ok {
		return 0, false
	}
	digits, suffix, ok := strings.Cut(rest, "-")
	if !ok || suffix == "" {
		return 0, false
	}
	pid, err := strconv.ParseInt(digits, 10, 32)
	if err != nil || pid <= 0 || strconv.FormatInt(pid, 10) != digits {
		return 0, false
	}
	return int(pid), true
}

func processGone(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	defer func() { _ = proc.Release() }()
	return signalMeansGone(proc.Signal(syscall.Signal(0)))
}

func signalMeansGone(err error) bool {
	return errors.Is(err, os.ErrProcessDone)
}
