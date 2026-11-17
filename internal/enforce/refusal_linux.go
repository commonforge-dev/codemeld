package enforce

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

const modelledOpenFlags = unix.O_ACCMODE | unix.O_CREAT | unix.O_EXCL | unix.O_NOCTTY | unix.O_TRUNC | unix.O_APPEND |
	unix.O_NONBLOCK | unix.O_SYNC | unix.O_DSYNC | unix.O_NOFOLLOW | unix.O_CLOEXEC

type FileRefusal struct {
	Path, Process, Candidate, Reason string
}

type RefusalCollector struct {
	policy  Policy
	plan    bool
	rules   []pathRule
	blocked []string
	noWrite []string
	shm     []string

	mu       sync.Mutex
	grants   map[string][]pathRule
	seen     map[string]bool
	refused  []FileRefusal
	unjudged int
}

type fileOp struct {
	path string
	at   string
	need landlock.AccessFSSet
}

func NewRefusalCollector(p Policy) (*RefusalCollector, error) {
	c := &RefusalCollector{policy: p, plan: p.Mode == ModePlan, grants: map[string][]pathRule{}, seen: map[string]bool{}}
	var held heldTmp
	if c.plan && p.TmpDir != "" {
		if fd, h, err := openHeldTmp(p); err == nil {
			defer func() { _ = unix.Close(fd) }()
			held = h
		}
	}
	var err error
	if c.rules, err = landlockRules(p, osFS{}, held); err != nil {
		return nil, err
	}
	for i, r := range c.rules {
		if held.fdPath != "" && within(r.Path, held.fdPath) {
			c.rules[i].Path = held.name + strings.TrimPrefix(r.Path, held.fdPath)
		}
	}
	b := &ruleBuilder{fs: osFS{}}
	if c.blocked, err = b.withResolved(p.BlockedPaths); err != nil {
		return nil, err
	}
	if c.noWrite, err = b.withResolved(p.NoWritePaths); err != nil {
		return nil, err
	}
	if c.shm, err = b.withResolved([]string{devShm}); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *RefusalCollector) Watch(call WatchedCall) {
	ops, err := fileOperands(call)
	var missing []fileOp
	for _, op := range ops {
		if ruleAccess(c.rules, op.at)&op.need != op.need {
			missing = append(missing, op)
		}
	}
	if err == nil && len(missing) > 0 {
		err = kernelFailsFirst(call, ops)
	}
	var found []FileRefusal
	for _, op := range missing {
		if err != nil {
			break
		}
		r := FileRefusal{Path: op.path, Process: call.Process}
		if !c.plan {
			r.Candidate, r.Reason, err = c.verdict(op)
		}
		found = append(found, r)
	}
	if err == nil && len(found) == 0 {
		return
	}
	call.Record(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if err != nil {
			c.unjudged++
			return
		}
		for _, r := range found {
			if !c.seen[r.Path] {
				c.seen[r.Path] = true
				c.refused = append(c.refused, r)
			}
		}
	})
}

func (c *RefusalCollector) Report() ([]FileRefusal, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.refused), c.unjudged
}

func (c *RefusalCollector) verdict(op fileOp) (string, string, error) {
	dir := op.at
	if op.at == op.path {
		dir = filepath.Dir(op.path)
	}
	rules, err := c.grantRules(dir)
	if err != nil {
		return "", "", err
	}
	if ruleAccess(rules, op.at)&op.need == op.need {
		if filepath.Dir(dir) == dir {
			return "", "the filesystem root cannot be a writable folder", nil
		}
		return dir, "", nil
	}
	switch {
	case coveredBy(op.at, c.blocked) || coveredBy(op.path, c.blocked):
		return "", "blocked path", nil
	case coveredBy(op.at, c.noWrite) || coveredBy(op.path, c.noWrite):
		return "", "no-write path", nil
	case slices.Contains(c.shm, op.at):
		return "", "/dev/shm itself", nil
	case containsAny(dir, c.blocked) || containsAny(dir, c.noWrite):
		return "", dir + " holds a blocked or no-write path", nil
	}
	return "", "no folder grant gives this right", nil
}

func (c *RefusalCollector) grantRules(dir string) ([]pathRule, error) {
	c.mu.Lock()
	rules, ok := c.grants[dir]
	c.mu.Unlock()
	if ok {
		return rules, nil
	}
	p := c.policy
	p.WriteRoots = append(slices.Clone(p.WriteRoots), dir)
	rules, err := landlockRules(p, osFS{}, heldTmp{})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.grants[dir] = rules
	c.mu.Unlock()
	return rules, nil
}

func fileOperands(c WatchedCall) ([]fileOp, error) {
	var flags uint64
	switch c.Syscall {
	case "open", "openat":
		flags = uint64(c.Flags)
	case "creat":
		flags = unix.O_CREAT | unix.O_WRONLY | unix.O_TRUNC
	case "openat2":
		h := c.OpenHow
		if h == nil {
			return nil, errors.New("openat2 without open_how")
		}
		if h.Err != nil {
			return nil, h.Err
		}
		how := h.How
		create := how.Flags&unix.O_CREAT != 0 || how.Flags&unix.O_TMPFILE == unix.O_TMPFILE
		switch {
		case h.ExtensionNonzero:
			return nil, errors.New("open_how extension fields are not modelled")
		case how.Flags&watchWriteFlags == 0:
			return nil, nil
		case how.Resolve != 0:
			return nil, fmt.Errorf("open_how resolve %#x is not modelled", how.Resolve)
		case how.Flags>>32 != 0 || how.Mode&^0o7777 != 0 || (how.Mode != 0 && !create):
			return nil, fmt.Errorf("the kernel rejects open_how flags %#x mode %#o", how.Flags, how.Mode)
		}
		flags = how.Flags
	case "truncate":
		if c.Length < 0 {
			return nil, fmt.Errorf("negative truncate length %d", c.Length)
		}
		flags = unix.O_TRUNC
	case "symlink", "symlinkat":
		if c.TargetErr != nil {
			return nil, fmt.Errorf("symlink target: %w", c.TargetErr)
		}
		if c.Target == "" {
			return nil, errors.New("empty symlink target")
		}
	}
	want := 1
	switch c.Syscall {
	case "link", "linkat", "rename", "renameat", "renameat2":
		want = 2
	}
	if len(c.Paths) != want {
		return nil, fmt.Errorf("%s with %d paths is not modelled", c.Syscall, len(c.Paths))
	}
	noParent := false
	for _, p := range c.Paths {
		switch {
		case errors.Is(p.Err, ErrWatchNoParent):
			noParent = true
		case p.Err != nil:
			return nil, p.Err
		}
	}
	var mknodNeed landlock.AccessFSSet
	switch c.Syscall {
	case "open", "openat", "openat2", "creat", "truncate":
		switch {
		case flags&unix.O_PATH != 0:
			return nil, nil
		case flags&unix.O_TMPFILE == unix.O_TMPFILE:
			return nil, errors.New("O_TMPFILE is not modelled")
		case flags&watchWriteFlags == 0:
			return nil, nil
		case flags&^modelledOpenFlags != 0 || flags&unix.O_ACCMODE == unix.O_ACCMODE:
			return nil, fmt.Errorf("open flags %#x are not modelled", flags)
		}
	case "mknod", "mknodat":
		var err error
		if mknodNeed, err = fileMknodAccess(c.Mode); err != nil {
			return nil, err
		}
	case "unlinkat":
		if c.Flags&^unix.AT_REMOVEDIR != 0 {
			return nil, fmt.Errorf("unlinkat flags %#x are not modelled", c.Flags)
		}
	case "linkat":
		if c.Flags&^unix.AT_SYMLINK_FOLLOW != 0 {
			return nil, fmt.Errorf("linkat flags %#x are not modelled", c.Flags)
		}
	case "renameat2":
		if c.Flags&^unix.RENAME_NOREPLACE != 0 {
			return nil, fmt.Errorf("renameat2 flags %#x are not modelled", c.Flags)
		}
	}
	if noParent {
		return nil, nil
	}
	p := c.Paths[0].Path
	switch c.Syscall {
	case "open", "openat", "openat2", "creat", "truncate":
		return fileOpen(p, flags)
	case "mkdir", "mkdirat":
		return fileCreate(p, llsys.AccessFSMakeDir)
	case "mknod", "mknodat":
		return fileCreate(p, mknodNeed)
	case "symlink", "symlinkat":
		return fileCreate(p, llsys.AccessFSMakeSym)
	case "unlink":
		return fileRemove(p, llsys.AccessFSRemoveFile)
	case "rmdir":
		return fileRemove(p, llsys.AccessFSRemoveDir)
	case "unlinkat":
		if c.Flags&unix.AT_REMOVEDIR != 0 {
			return fileRemove(p, llsys.AccessFSRemoveDir)
		}
		return fileRemove(p, llsys.AccessFSRemoveFile)
	}
	q := c.Paths[1].Path
	switch c.Syscall {
	case "link":
		return filePair(p, q, false, 0)
	case "linkat":
		if c.Flags&unix.AT_SYMLINK_FOLLOW != 0 {
			var err error
			if p, err = filepath.EvalSymlinks(p); errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			} else if err != nil {
				return nil, err
			}
		}
		return filePair(p, q, false, 0)
	case "rename", "renameat":
		return filePair(p, q, true, 0)
	case "renameat2":
		return filePair(p, q, true, c.Flags)
	}
	return nil, fmt.Errorf("%s is not modelled", c.Syscall)
}

func fileOpen(p string, flags uint64) ([]fileOp, error) {
	info, err := os.Lstat(p)
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		if flags&unix.O_NOFOLLOW != 0 {
			return nil, nil
		}
		if p, err = filepath.EvalSymlinks(p); err != nil {
			return nil, fmt.Errorf("final symlink: %w", err)
		}
		info, err = os.Stat(p)
	}
	if errors.Is(err, fs.ErrNotExist) {
		if flags&unix.O_CREAT == 0 {
			return nil, nil
		}
		return []fileOp{{p, filepath.Dir(p), llsys.AccessFSMakeReg}}, nil
	}
	if err != nil {
		return nil, err
	}
	if flags&(unix.O_CREAT|unix.O_EXCL) == unix.O_CREAT|unix.O_EXCL || info.IsDir() {
		return nil, nil
	}
	var need landlock.AccessFSSet
	if flags&(unix.O_WRONLY|unix.O_RDWR) != 0 {
		need |= llsys.AccessFSWriteFile
	}
	if flags&unix.O_TRUNC != 0 && info.Mode().IsRegular() {
		need |= llsys.AccessFSTruncate
	}
	if need == 0 {
		return nil, nil
	}
	return []fileOp{{p, p, need}}, nil
}

func fileCreate(p string, need landlock.AccessFSSet) ([]fileOp, error) {
	_, err := os.Lstat(p)
	switch {
	case err == nil:
		return nil, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return []fileOp{{p, filepath.Dir(p), need}}, nil
}

func fileRemove(p string, need landlock.AccessFSSet) ([]fileOp, error) {
	_, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return []fileOp{{p, filepath.Dir(p), need}}, nil
}

func fileMknodAccess(mode uint32) (landlock.AccessFSSet, error) {
	switch mode & unix.S_IFMT {
	case 0, unix.S_IFREG:
		return llsys.AccessFSMakeReg, nil
	case unix.S_IFIFO:
		return llsys.AccessFSMakeFifo, nil
	case unix.S_IFSOCK:
		return llsys.AccessFSMakeSock, nil
	case unix.S_IFCHR:
		return llsys.AccessFSMakeChar, nil
	case unix.S_IFBLK:
		return llsys.AccessFSMakeBlock, nil
	}
	return 0, fmt.Errorf("mknod file type %#o is not modelled", mode&unix.S_IFMT)
}

func filePair(src, dst string, rename bool, flags uint32) ([]fileOp, error) {
	si, err := os.Lstat(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var srcNeed landlock.AccessFSSet
	if rename {
		srcNeed = fileTypeAccess(si, true)
	}
	dstNeed := fileTypeAccess(si, false)
	if di, err := os.Lstat(dst); err == nil {
		if !rename || flags&unix.RENAME_NOREPLACE != 0 {
			return nil, nil
		}
		dstNeed |= fileTypeAccess(di, true)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if filepath.Dir(src) != filepath.Dir(dst) {
		srcNeed |= llsys.AccessFSRefer
		dstNeed |= llsys.AccessFSRefer
	}
	return []fileOp{{src, filepath.Dir(src), srcNeed}, {dst, filepath.Dir(dst), dstNeed}}, nil
}

func fileTypeAccess(info fs.FileInfo, remove bool) landlock.AccessFSSet {
	switch t := info.Mode().Type(); {
	case t == fs.ModeDir && remove:
		return llsys.AccessFSRemoveDir
	case t == fs.ModeDir:
		return llsys.AccessFSMakeDir
	case remove:
		return llsys.AccessFSRemoveFile
	case t == fs.ModeSymlink:
		return llsys.AccessFSMakeSym
	case t == fs.ModeNamedPipe:
		return llsys.AccessFSMakeFifo
	case t == fs.ModeSocket:
		return llsys.AccessFSMakeSock
	case t == fs.ModeDevice|fs.ModeCharDevice:
		return llsys.AccessFSMakeChar
	case t == fs.ModeDevice:
		return llsys.AccessFSMakeBlock
	}
	return llsys.AccessFSMakeReg
}

func ruleAccess(rules []pathRule, path string) landlock.AccessFSSet {
	var a landlock.AccessFSSet
	for _, r := range rules {
		if within(path, r.Path) {
			a |= r.Access
		}
	}
	return a
}

// These kernel errors come before Landlock's check, so a refusal predicted for such a call may never happen.
func kernelFailsFirst(c WatchedCall, ops []fileOp) error {
	switch c.Syscall {
	case "unlink", "unlinkat":
		if c.Flags&unix.AT_REMOVEDIR == 0 {
			if info, err := os.Lstat(ops[0].path); err == nil && info.IsDir() {
				return errors.New("unlink of a folder")
			}
		}
	case "rename", "renameat", "renameat2":
		if ops[1].path != ops[0].path && within(ops[1].path, ops[0].path) {
			return errors.New("rename into its own descendant")
		}
	}
	if len(ops) == 2 {
		src, err := mountID(ops[0].at)
		if err != nil {
			return err
		}
		dst, err := mountID(ops[1].at)
		if err != nil {
			return err
		}
		if src != dst {
			return errors.New("source and destination on different mounts")
		}
	}
	for _, op := range ops {
		var st unix.Statfs_t
		if err := unix.Statfs(op.at, &st); err != nil {
			return err
		}
		if st.Flags&unix.ST_RDONLY != 0 {
			return errors.New("read-only mount")
		}
	}
	return nil
}

func mountID(dir string) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, dir, 0, unix.STATX_MNT_ID, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("no mount id")
	}
	return st.Mnt_id, nil
}
