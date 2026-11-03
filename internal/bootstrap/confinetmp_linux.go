//go:build linux

package bootstrap

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

type sessionTempDir struct {
	path   string
	name   string
	parent int
	fd     int
}

const (
	openDirPath = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	openDirRead = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
)

func newSessionTempDir() (*sessionTempDir, error) {
	parentPath, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, err
	}
	if parentPath, err = filepath.EvalSymlinks(parentPath); err != nil {
		return nil, err
	}
	parent, err := unix.Open(parentPath, openDirRead, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: parentPath, Err: err}
	}
	name, err := mkdirSessionTempDir(parent)
	if err != nil {
		_ = unix.Close(parent)
		return nil, &os.PathError{Op: "mkdir", Path: parentPath, Err: err}
	}
	d := &sessionTempDir{path: filepath.Join(parentPath, name), name: name, parent: parent, fd: -1}
	if beforeSessionTempDirChmod != nil {
		beforeSessionTempDirChmod(d.path)
	}
	if err := d.claim(); err != nil {
		return d.rollback(err)
	}
	if err := d.claimedAtPath(); err != nil {
		return d.rollback(err)
	}
	if afterSessionTempDirChmod != nil {
		afterSessionTempDirChmod(d.path)
	}
	return d, nil
}

func mkdirSessionTempDir(parent int) (string, error) {
	prefix := fmt.Sprintf("%s%d-", sessionTempDirPrefix, os.Getpid())
	for range 10000 {
		name := prefix + strconv.FormatUint(uint64(rand.Uint32()), 10)
		err := unix.Mkdirat(parent, name, 0)
		if !errors.Is(err, unix.EEXIST) {
			return name, err
		}
	}
	return "", unix.EEXIST
}

// btrfs reports nlink 1 for every directory, so only a count above 2 shows a subfolder.
func (d *sessionTempDir) claim() error {
	fd, err := unix.Openat(d.parent, d.name, openDirPath, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: d.path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return &os.PathError{Op: "stat", Path: d.path, Err: err}
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0 || st.Nlink > 2 {
		_ = unix.Close(fd)
		return fmt.Errorf("bootstrap: private temp folder %s was replaced before codemeld opened it; left untouched", d.path)
	}
	d.fd = fd
	if err := unix.Chmod(procFD(fd), 0o700); err != nil {
		return &os.PathError{Op: "chmod", Path: d.path, Err: err}
	}
	return nil
}

func (d *sessionTempDir) rollback(err error) (*sessionTempDir, error) {
	if d.fd >= 0 {
		if err = errors.Join(err, d.remove()); d.fd >= 0 {
			return d, err
		}
	}
	d.close()
	return nil, err
}

func (d *sessionTempDir) claimedAtPath() error {
	var held, named unix.Stat_t
	if err := unix.Fstat(d.fd, &held); err != nil {
		return &os.PathError{Op: "stat", Path: d.path, Err: err}
	}
	if err := unix.Stat(d.path, &named); err != nil {
		return &os.PathError{Op: "stat", Path: d.path, Err: err}
	}
	if held.Dev != named.Dev || held.Ino != named.Ino {
		return fmt.Errorf("bootstrap: private temp folder %s does not resolve to the folder codemeld created", d.path)
	}
	return nil
}

func (d *sessionTempDir) identity() (dev, ino uint64, err error) {
	if d.fd < 0 {
		return 0, 0, fmt.Errorf("bootstrap: private temp folder %s: handle already released", d.path)
	}
	var st unix.Stat_t
	if err := unix.Fstat(d.fd, &st); err != nil {
		return 0, 0, &os.PathError{Op: "stat", Path: d.path, Err: err}
	}
	return uint64(st.Dev), st.Ino, nil
}

func (d *sessionTempDir) remove() error {
	if d.fd < 0 {
		return fmt.Errorf("bootstrap: private temp folder %s: cleanup handle already released", d.path)
	}
	if err := removeHeldDir(d.parent, d.name, d.fd, d.path); err != nil {
		return err
	}
	d.close()
	return nil
}

func (d *sessionTempDir) close() {
	if d.fd >= 0 {
		_ = unix.Close(d.fd)
		d.fd = -1
	}
	if d.parent >= 0 {
		_ = unix.Close(d.parent)
		d.parent = -1
	}
}

func removeHeldDir(parent int, name string, fd int, label string) error {
	if duringSessionTempDirCleanup != nil {
		duringSessionTempDirCleanup(label)
	}
	if err := emptyHeldDir(fd, label); err != nil {
		return err
	}
	if beforeSessionTempDirUnlink != nil {
		beforeSessionTempDirUnlink(label)
	}
	var held, named unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return &os.PathError{Op: "stat", Path: label, Err: err}
	}
	if err := unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "stat", Path: label, Err: err}
	}
	if held.Dev != named.Dev || held.Ino != named.Ino {
		return fmt.Errorf("bootstrap: %s was replaced during cleanup; left untouched", label)
	}
	if err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); err != nil {
		return &os.PathError{Op: "remove", Path: label, Err: err}
	}
	return nil
}

func emptyHeldDir(fd int, label string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: label, Err: err}
	}
	if st.Mode&0o700 != 0o700 {
		if err := unix.Chmod(procFD(fd), st.Mode&0o7777|0o700); err != nil {
			return &os.PathError{Op: "chmod", Path: label, Err: err}
		}
	}
	names, err := heldDirNames(fd, label)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		path := filepath.Join(label, name)
		err := unix.Unlinkat(fd, name, 0)
		switch {
		case err == nil || errors.Is(err, unix.ENOENT):
		case errors.Is(err, unix.EISDIR):
			errs = append(errs, removeChildDir(fd, name, path))
		default:
			errs = append(errs, &os.PathError{Op: "remove", Path: path, Err: err})
		}
	}
	return errors.Join(errs...)
}

func removeChildDir(parent int, name, label string) error {
	fd, err := unix.Openat(parent, name, openDirPath, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: label, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	return removeHeldDir(parent, name, fd, label)
}

func heldDirNames(fd int, label string) ([]string, error) {
	dir, err := unix.Openat(fd, ".", openDirRead, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: label, Err: err}
	}
	f := os.NewFile(uintptr(dir), label)
	defer func() { _ = f.Close() }()
	return f.Readdirnames(-1)
}

func procFD(fd int) string {
	return "/proc/self/fd/" + strconv.Itoa(fd)
}

func removeStaleSessionTempDirs() error {
	parentPath := os.TempDir()
	parent, err := unix.Open(parentPath, openDirRead, 0)
	if err != nil {
		return nil
	}
	defer func() { _ = unix.Close(parent) }()
	if afterStaleScanParentOpen != nil {
		afterStaleScanParentOpen(parentPath)
	}
	names, err := heldDirNames(parent, parentPath)
	if err != nil {
		return nil
	}
	var errs []error
	for _, name := range names {
		pid, ok := sessionTempDirPID(name)
		if !ok || pid == os.Getpid() || !processGone(pid) {
			continue
		}
		label := filepath.Join(parentPath, name)
		fd, err := unix.Openat(parent, name, openDirPath, 0)
		if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			errs = append(errs, &os.PathError{Op: "open", Path: label, Err: err})
			continue
		}
		errs = append(errs, removeHeldDir(parent, name, fd, label))
		_ = unix.Close(fd)
	}
	return errors.Join(errs...)
}
