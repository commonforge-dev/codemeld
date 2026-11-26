//go:build linux

package bootstrap

import (
	"io/fs"
	"syscall"
)

func settingsCtime(info fs.FileInfo) (syscall.Timespec, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return syscall.Timespec{}, false
	}
	return st.Ctim, true
}
