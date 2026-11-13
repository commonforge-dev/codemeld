package enforce

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	fsizeLimit    = 8 << 30
	nprocHeadroom = 4096
)

var (
	setrlimit        = unix.Setrlimit
	getrlimit        = unix.Getrlimit
	countUserThreads = userThreadCount
	procReadDir      = os.ReadDir
	procOwner        = func(path string) (uint32, error) {
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
		}
		return info.Sys().(*syscall.Stat_t).Uid, nil
	}
)

func applyRlimits() (fsize, nproc unix.Rlimit, err error) {
	n, err := countUserThreads()
	if err != nil {
		return fsize, nproc, fmt.Errorf("count threads: %w", err)
	}
	if fsize, err = lowerRlimit(unix.RLIMIT_FSIZE, fsizeLimit); err != nil {
		return fsize, nproc, fmt.Errorf("RLIMIT_FSIZE: %w", err)
	}
	if nproc, err = lowerRlimit(unix.RLIMIT_NPROC, n+nprocHeadroom); err != nil {
		return fsize, nproc, fmt.Errorf("RLIMIT_NPROC: %w", err)
	}
	return fsize, nproc, nil
}

func lowerRlimit(resource int, want uint64) (unix.Rlimit, error) {
	var l unix.Rlimit
	if err := getrlimit(resource, &l); err != nil {
		return unix.Rlimit{}, err
	}
	l = unix.Rlimit{Cur: min(want, l.Cur), Max: min(want, l.Max)}
	if err := setrlimit(resource, &l); err != nil {
		return unix.Rlimit{}, err
	}
	return l, nil
}

func userThreadCount() (uint64, error) {
	uid := uint32(os.Getuid())
	entries, err := procReadDir("/proc")
	if err != nil {
		return 0, err
	}
	var n uint64
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join("/proc", e.Name())
		owner, err := procOwner(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if owner != uid {
			continue
		}
		tasks, err := procReadDir(filepath.Join(dir, "task"))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return 0, err
		}
		n += uint64(len(tasks))
	}
	return n, nil
}
