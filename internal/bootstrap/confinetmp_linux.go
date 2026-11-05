//go:build linux

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/paths"
)

type sessionTempDir struct {
	path      string
	name      string
	parent    int
	fd        int
	recorded  bool
	recordErr error
}

type sessionTempRecord struct {
	Path    string `json:"path"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	BtimeNs *int64 `json:"btime_ns,omitempty"`
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
	d.recordErr = d.publishRecord()
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
	if d.recorded {
		// A record left behind here is dropped by the next launch's cleanup, which finds its folder gone.
		_ = dropSessionTempRecord(d.name)
		d.recorded = false
	}
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

func (d *sessionTempDir) publishRecord() error {
	dev, ino, err := d.identity()
	if err != nil {
		return err
	}
	rec := sessionTempRecord{Path: d.path, Dev: dev, Ino: ino}
	btime, ok, err := heldBirthTime(d.fd, d.path)
	if err != nil {
		return err
	}
	if ok {
		rec.BtimeNs = &btime
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	records, err := openSessionTempRecords(true)
	if err != nil {
		return err
	}
	defer func() { _ = records.Close() }()
	if _, _, _, err := fsutil.WriteAtomicCreateAt(records, d.name, data, 0o600); err != nil {
		return err
	}
	d.recorded = true
	return nil
}

func heldBirthTime(fd int, label string) (int64, bool, error) {
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BTIME, &stx); err != nil {
		return 0, false, &os.PathError{Op: "statx", Path: label, Err: err}
	}
	if stx.Mask&unix.STATX_BTIME == 0 {
		return 0, false, nil
	}
	return stx.Btime.Sec*1e9 + int64(stx.Btime.Nsec), true, nil
}

func openSessionTempRecords(create bool) (*os.File, error) {
	home, err := paths.ResolveHome()
	if err != nil {
		return nil, err
	}
	base := filepath.Join(home, ".codemeld")
	dir := filepath.Join(base, "confine-tmp")
	if create {
		for _, path := range []string{base, dir} {
			if err := unix.Mkdir(path, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, &os.PathError{Op: "mkdir", Path: path, Err: err}
			}
		}
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "stat", Path: dir, Err: err}
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o7777 != 0o700 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bootstrap: %s must be a folder owned by you with mode 0700", dir)
	}
	return os.NewFile(uintptr(fd), dir), nil
}

func dropSessionTempRecord(name string) error {
	records, err := openSessionTempRecords(false)
	if err != nil {
		return err
	}
	defer func() { _ = records.Close() }()
	return dropRecordAt(records, name)
}

func dropRecordAt(records *os.File, name string) error {
	if err := unix.Unlinkat(int(records.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "remove", Path: filepath.Join(records.Name(), name), Err: err}
	}
	return nil
}

func removeStaleSessionTempDirs() error {
	records, err := openSessionTempRecords(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = records.Close() }()
	names, err := records.Readdirnames(-1)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		pid, ok := sessionTempDirPID(name)
		if !ok || pid == os.Getpid() || !processGone(pid) {
			continue
		}
		errs = append(errs, removeRecordedSessionTempDir(records, name))
	}
	return errors.Join(errs...)
}

func removeRecordedSessionTempDir(records *os.File, name string) error {
	recordPath := filepath.Join(records.Name(), name)
	rec, err := readSessionTempRecord(records, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	parentPath := filepath.Dir(rec.Path)
	parent, err := unix.Open(parentPath, openDirRead, 0)
	if errors.Is(err, unix.ENOENT) {
		return dropRecordAt(records, name)
	}
	if err != nil {
		return &os.PathError{Op: "open", Path: parentPath, Err: err}
	}
	defer func() { _ = unix.Close(parent) }()
	if afterStaleScanParentOpen != nil {
		afterStaleScanParentOpen(parentPath)
	}
	fd, err := unix.Openat(parent, name, openDirPath, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return dropRecordAt(records, name)
	case errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP):
		return errors.Join(fmt.Errorf("bootstrap: %s is no longer a folder; left untouched", rec.Path), dropRecordAt(records, name))
	case err != nil:
		return &os.PathError{Op: "open", Path: rec.Path, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: rec.Path, Err: err}
	}
	btime, ok, err := heldBirthTime(fd, rec.Path)
	if err != nil {
		return err
	}
	if rec.BtimeNs == nil || !ok {
		return errors.Join(fmt.Errorf("bootstrap: %s has no birth time to prove codemeld created it; left untouched (record %s dropped)", rec.Path, recordPath), dropRecordAt(records, name))
	}
	if uint64(st.Dev) != rec.Dev || st.Ino != rec.Ino || btime != *rec.BtimeNs {
		return errors.Join(fmt.Errorf("bootstrap: %s is not the folder codemeld recorded; left untouched", rec.Path), dropRecordAt(records, name))
	}
	if err := removeHeldDir(parent, name, fd, rec.Path); err != nil && !onlyNotExist(err) {
		return err
	}
	return dropRecordAt(records, name)
}

func readSessionTempRecord(records *os.File, name string) (sessionTempRecord, error) {
	recordPath := filepath.Join(records.Name(), name)
	fd, err := unix.Openat(int(records.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return sessionTempRecord{}, &os.PathError{Op: "open", Path: recordPath, Err: err}
	}
	f := os.NewFile(uintptr(fd), recordPath)
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil {
		return sessionTempRecord{}, err
	} else if !info.Mode().IsRegular() {
		return sessionTempRecord{}, fmt.Errorf("bootstrap: record %s is not a regular file", recordPath)
	}
	var raw struct {
		Path    string  `json:"path"`
		Dev     *uint64 `json:"dev"`
		Ino     *uint64 `json:"ino"`
		BtimeNs *int64  `json:"btime_ns"`
	}
	dec := json.NewDecoder(f)
	if err := dec.Decode(&raw); err != nil {
		return sessionTempRecord{}, fmt.Errorf("bootstrap: unreadable record %s: %w", recordPath, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return sessionTempRecord{}, fmt.Errorf("bootstrap: record %s has data after its JSON object", recordPath)
	}
	if raw.Dev == nil || raw.Ino == nil {
		return sessionTempRecord{}, fmt.Errorf("bootstrap: record %s lacks the folder's dev or ino", recordPath)
	}
	rec := sessionTempRecord{Path: raw.Path, Dev: *raw.Dev, Ino: *raw.Ino, BtimeNs: raw.BtimeNs}
	if !filepath.IsAbs(rec.Path) || filepath.Clean(rec.Path) != rec.Path || filepath.Base(rec.Path) != name {
		return sessionTempRecord{}, fmt.Errorf("bootstrap: record %s names %q, not a folder called %s", recordPath, rec.Path, name)
	}
	return rec, nil
}

func onlyNotExist(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			if !onlyNotExist(e) {
				return false
			}
		}
		return true
	}
	return errors.Is(err, unix.ENOENT)
}
