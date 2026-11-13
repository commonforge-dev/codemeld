package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func resolveUnixDest(tid uint32, addr []byte) (int, *unix.SockaddrUnix, error) {
	if len(addr) < 2 || len(addr) > unix.SizeofSockaddrUnix || binary.NativeEndian.Uint16(addr) != unix.AF_UNIX {
		return -1, nil, errors.New("not a Unix socket address")
	}
	path, _, _ := strings.Cut(string(addr[2:]), "\x00")
	cwd, err := unix.Open(fmt.Sprintf("/proc/%d/cwd", tid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, fmt.Errorf("open the caller's working folder: %w", err)
	}
	fd, err := unix.Openat2(cwd, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_MAGICLINKS})
	_ = unix.Close(cwd)
	if err != nil {
		return -1, nil, fmt.Errorf("open %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Nlink != 1 {
		_ = unix.Close(fd)
		return -1, nil, fmt.Errorf("%s is not a socket with one link", path)
	}
	return fd, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(fd)}, nil
}
