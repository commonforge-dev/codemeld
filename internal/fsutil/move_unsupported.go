//go:build !linux

package fsutil

// renameNoReplaceAtSyscall fails closed on platforms without an atomic no-overwrite rename
// primitive. Emulating no-overwrite as a preflight stat plus a plain rename would clobber a
// destination that appears after the check, so unsupported platforms return ErrNoReplaceUnsupported
// instead of moving.
func renameNoReplaceAtSyscall(_ int, _ string, _ int, _ string) error {
	return ErrNoReplaceUnsupported
}
