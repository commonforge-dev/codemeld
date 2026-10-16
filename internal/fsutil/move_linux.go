//go:build linux

package fsutil

import "golang.org/x/sys/unix"

// renameNoReplaceAtSyscall renames oldName under oldDirFd to newName under newDirFd using the
// kernel's atomic no-overwrite primitive (renameat2 with RENAME_NOREPLACE): the rename fails with
// EEXIST if newName already exists, so the destination is never clobbered even when it materializes
// after a caller's preflight. A cross-device attempt surfaces the kernel's EXDEV unchanged; the
// helper never falls back to copy+unlink.
func renameNoReplaceAtSyscall(oldDirFd int, oldName string, newDirFd int, newName string) error {
	return unix.Renameat2(oldDirFd, oldName, newDirFd, newName, unix.RENAME_NOREPLACE)
}
