// Package fserrors maps filesystem errnos to codemeld's canonical error-category vocabulary.
package fserrors

import (
	"errors"
	"syscall"
)

type Category string

const (
	PermissionDenied Category = "permission_denied"
	NoSpace          Category = "no_space"
	ReadOnlyFS       Category = "read_only_fs"
	IOError          Category = "io_error"
	NotFound         Category = "not_found"
	InUse            Category = "in_use"
)

// CategorizeErrno extracts a wrapped syscall.Errno from err and maps it to a Category. Unknown errnos and nil-wrapped errors return IOError.
func CategorizeErrno(err error) Category {
	if err == nil {
		return IOError
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return IOError
	}
	switch errno {
	case syscall.EACCES, syscall.EPERM:
		return PermissionDenied
	case syscall.ENOSPC:
		return NoSpace
	case syscall.EROFS:
		return ReadOnlyFS
	case syscall.ENOENT:
		return NotFound
	case syscall.EBUSY, syscall.ETXTBSY:
		return InUse
	default:
		return IOError
	}
}
