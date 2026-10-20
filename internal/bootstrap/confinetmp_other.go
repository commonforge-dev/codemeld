//go:build !linux

package bootstrap

import (
	"os"

	"golang.org/x/sys/unix"
)

func chmodPrivateNoFollow(created string) error {
	if err := unix.Fchmodat(unix.AT_FDCWD, created, 0o700, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chmod", Path: created, Err: err}
	}
	return nil
}
