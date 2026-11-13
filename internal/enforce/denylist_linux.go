package enforce

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type DenyList struct {
	paths []string
	globs []string
	held  []heldSocket
}

type heldSocket struct {
	path     string
	fd       int
	dev, ino uint64
}

func NewDenyList() *DenyList {
	paths, globs := denyListPaths("/", os.Getuid(), os.Getenv("SSH_AUTH_SOCK"), os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
	return newDenyList(paths, globs)
}

func denyListPaths(root string, uid int, sshAuthSock, dbusAddress string) (paths, globs []string) {
	run := filepath.Join(root, "run")
	user := filepath.Join(run, "user", strconv.Itoa(uid))
	paths = []string{
		filepath.Join(user, "systemd", "private"),
		filepath.Join(user, "bus"),
		filepath.Join(run, "dbus", "system_bus_socket"),
		filepath.Join(run, "docker.sock"),
		filepath.Join(user, "docker.sock"),
	}
	paths = append(paths, dbusUnixPaths(dbusAddress)...)
	if sshAuthSock != "" {
		paths = append(paths, sshAuthSock)
	}
	return paths, []string{filepath.Join(user, "gnupg", "S.*")}
}

func dbusUnixPaths(address string) []string {
	var paths []string
	for addr := range strings.SplitSeq(address, ";") {
		params, ok := strings.CutPrefix(addr, "unix:")
		if !ok {
			continue
		}
		for kv := range strings.SplitSeq(params, ",") {
			if v, ok := strings.CutPrefix(kv, "path="); ok && v != "" {
				if unescaped, err := url.PathUnescape(v); err == nil {
					v = unescaped
				}
				paths = append(paths, v)
			}
		}
	}
	return paths
}

func newDenyList(paths, globs []string) *DenyList {
	d := &DenyList{paths: paths, globs: globs}
	for _, p := range d.current() {
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			_ = unix.Close(fd)
			continue
		}
		d.held = append(d.held, heldSocket{path: p, fd: fd, dev: st.Dev, ino: st.Ino})
	}
	return d
}

func (d *DenyList) current() []string {
	out := slices.Clone(d.paths)
	for _, g := range d.globs {
		matches, _ := filepath.Glob(g)
		out = append(out, matches...)
	}
	return out
}

func (d *DenyList) denies(st *unix.Stat_t) (string, bool) {
	for _, h := range d.held {
		if h.dev == st.Dev && h.ino == st.Ino {
			return h.path, true
		}
	}
	for _, p := range d.current() {
		var now unix.Stat_t
		if unix.Stat(p, &now) == nil && now.Dev == st.Dev && now.Ino == st.Ino {
			return p, true
		}
	}
	return "", false
}

func (d *DenyList) Close() {
	for _, h := range d.held {
		_ = unix.Close(h.fd)
	}
	d.held = nil
}
