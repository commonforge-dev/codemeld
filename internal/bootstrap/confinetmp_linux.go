//go:build linux

package bootstrap

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func chmodPrivateNoFollow(created string) error {
	fd, err := unix.Open(created, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: created, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Chmod("/proc/self/fd/"+strconv.Itoa(fd), 0o700); err != nil {
		return &os.PathError{Op: "chmod", Path: created, Err: err}
	}
	return nil
}
