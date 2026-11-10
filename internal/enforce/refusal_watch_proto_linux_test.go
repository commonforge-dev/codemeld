package enforce

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"
	"unsafe"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/runner"
)

const (
	refusalWatchChildEnv     = "CODEMELD_TEST_REFUSAL_WATCH_CHILD"
	refusalWatchPolicyEnv    = "CODEMELD_TEST_REFUSAL_WATCH_POLICY"
	refusalWatchWorkloadsEnv = "CODEMELD_TEST_REFUSAL_WATCH_WORKLOADS"
	refusalWatchWriteFlags   = unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC
	refusalWatchOpenFlags    = unix.O_ACCMODE | unix.O_CREAT | unix.O_EXCL | unix.O_NOCTTY | unix.O_TRUNC | unix.O_APPEND |
		unix.O_NONBLOCK | unix.O_SYNC | unix.O_DSYNC | unix.O_NOFOLLOW | unix.O_CLOEXEC
)

var refusalWatchAlways = []string{
	"mkdirat", "unlinkat", "renameat2", "linkat", "symlinkat", "mknodat", "truncate", "openat2",
	"mkdir", "rmdir", "unlink", "rename", "renameat", "link", "symlink", "mknod", "creat",
}

var errRefusalWatchNoParent = errors.New("parent folder missing")

func refusalWatchInstall(connect bool) (int, error) {
	info, err := nativeSeccompArch()
	if err != nil {
		return -1, err
	}
	notify := bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF}
	loadNr := bpf.LoadAbsolute{Off: seccompNrOffset, Size: 4}
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompArchOffset, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(info.ID), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_KILL_PROCESS},
		loadNr,
	}
	names := refusalWatchAlways
	if connect {
		names = append(slices.Clone(names), "connect")
	}
	for _, name := range names {
		if nr, ok := info.SyscallNames[name]; ok {
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(nr), SkipTrue: 1}, notify)
		}
	}
	for _, call := range []struct {
		name string
		arg  uint32
	}{{"openat", 2}, {"open", 1}} {
		if nr, ok := info.SyscallNames[call.name]; ok {
			prog = append(prog,
				bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(nr), SkipTrue: 3},
				loadArg(call.arg),
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: refusalWatchWriteFlags, SkipFalse: 1},
				notify,
				loadNr)
		}
	}
	raw, err := bpf.Assemble(append(prog, bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}))
	if err != nil {
		return -1, err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	fd, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER|unix.SECCOMP_FILTER_FLAG_TSYNC|unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
		uintptr(unsafe.Pointer(&fprog)))
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

type refusalWatchOp struct {
	path string
	at   string
	need landlock.AccessFSSet
}

type refusalWatchReport struct {
	call, path, verdict, comm string
	pid                       uint32
}

type refusalWatcher struct {
	policy  Policy
	names   map[int32]string
	rules   []pathRule
	blocked []string
	noWrite []string
	shm     []string
	grants  map[string][]pathRule
	hook    func(n seccompNotif, name string)

	mu      sync.Mutex
	counts  map[string]int
	reports []refusalWatchReport
	notes   []string
}

func refusalWatchNew(p Policy) (*refusalWatcher, error) {
	info, err := nativeSeccompArch()
	if err != nil {
		return nil, err
	}
	w := &refusalWatcher{policy: p, names: map[int32]string{}, grants: map[string][]pathRule{}, counts: map[string]int{}}
	for name, nr := range info.SyscallNames {
		w.names[int32(nr)] = name
	}
	if w.rules, err = landlockRules(p, osFS{}, heldTmp{}); err != nil {
		return nil, err
	}
	b := &ruleBuilder{fs: osFS{}}
	if w.blocked, err = b.withResolved(p.BlockedPaths); err != nil {
		return nil, err
	}
	if w.noWrite, err = b.withResolved(p.NoWritePaths); err != nil {
		return nil, err
	}
	if w.shm, err = b.withResolved([]string{devShm}); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *refusalWatcher) run(listener int, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		revents, err := pollFD(listener, unix.POLLIN, 100*time.Millisecond)
		if err != nil {
			w.note("poll: " + errName(err))
			return
		}
		if revents&unix.POLLHUP != 0 {
			return
		}
		if revents&unix.POLLIN == 0 {
			continue
		}
		var n seccompNotif
		if err := ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&n)); err != nil {
			if err == unix.ENOENT {
				continue
			}
			w.note("recv: " + errName(err))
			return
		}
		w.handle(listener, n)
	}
}

func (w *refusalWatcher) note(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.notes = append(w.notes, s)
}

func (w *refusalWatcher) total() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.counts["notified"]
}

func (w *refusalWatcher) handle(listener int, n seccompNotif) {
	name := w.names[n.Nr]
	resp := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	var reports []refusalWatchReport
	var kinds []string
	var note string
	if name == "connect" {
		resp = seccompNotifResp{ID: n.ID, Error: -int32(unix.EPERM)}
		kinds = []string{"connect denied"}
	} else {
		var ops []refusalWatchOp
		var err error
		ops, kinds, err = w.operands(n, name)
		if err == nil && ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&n.ID)) != nil {
			err = errors.New("the call ended while its arguments were read")
		}
		if err != nil {
			note, ops = name+": "+err.Error(), nil
		}
		if w.hook != nil {
			w.hook(n, name)
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", n.Pid))
		for _, op := range ops {
			if refusalWatchAccess(w.rules, op.at)&op.need != op.need {
				reports = append(reports, refusalWatchReport{name, op.path, w.verdict(op), strings.TrimSpace(string(comm)), n.Pid})
			}
		}
	}
	sendErr := ioctlPtr(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp))
	w.mu.Lock()
	defer w.mu.Unlock()
	w.counts["notified"]++
	w.counts[name]++
	for _, k := range kinds {
		w.counts[k]++
	}
	if note != "" {
		w.counts["inconclusive"]++
		w.notes = append(w.notes, note)
	}
	if sendErr != nil && sendErr != unix.ENOENT {
		w.notes = append(w.notes, "reply: "+errName(sendErr))
	}
	w.reports = append(w.reports, reports...)
}

func (w *refusalWatcher) operands(n seccompNotif, name string) ([]refusalWatchOp, []string, error) {
	a := n.Args
	var flags uint64
	var kinds []string
	if name == "openat2" {
		how, ext, err := refusalWatchOpenHow(n)
		if err != nil {
			return nil, []string{"openat2 unreadable"}, err
		}
		create := how.Flags&unix.O_CREAT != 0 || how.Flags&unix.O_TMPFILE == unix.O_TMPFILE
		switch {
		case slices.ContainsFunc(ext, func(b byte) bool { return b != 0 }):
			err = errors.New("open_how extension fields are not modelled")
		case how.Flags&refusalWatchWriteFlags == 0:
			return nil, []string{"openat2 read-only"}, nil
		case how.Resolve != 0:
			err = fmt.Errorf("open_how resolve %#x is not modelled", how.Resolve)
		case how.Flags>>32 != 0 || how.Mode&^0o7777 != 0 || (how.Mode != 0 && !create):
			err = fmt.Errorf("the kernel rejects open_how flags %#x mode %#o", how.Flags, how.Mode)
		}
		if err != nil {
			return nil, []string{"openat2 unsupported"}, err
		}
		flags = how.Flags
		kinds = append(kinds, "openat2 write-intent")
	}
	path := func(dirfd int32, ptr uint64) (string, error) {
		s, err := refusalWatchString(n.Pid, ptr)
		if err != nil {
			return "", err
		}
		return refusalWatchResolve(n.Pid, dirfd, s)
	}
	var p, q string
	var err error
	switch name {
	case "open", "creat", "mkdir", "mknod", "unlink", "rmdir":
		p, err = path(unix.AT_FDCWD, a[0])
	case "truncate":
		if int64(a[1]) < 0 {
			return nil, kinds, fmt.Errorf("negative truncate length %d", int64(a[1]))
		}
		p, err = path(unix.AT_FDCWD, a[0])
	case "openat", "openat2", "mkdirat", "mknodat", "unlinkat":
		p, err = path(int32(a[0]), a[1])
	case "symlink", "symlinkat":
		var target string
		if target, err = refusalWatchString(n.Pid, a[0]); err != nil {
			return nil, kinds, fmt.Errorf("symlink target: %w", err)
		}
		if target == "" {
			return nil, kinds, errors.New("empty symlink target")
		}
		if name == "symlink" {
			p, err = path(unix.AT_FDCWD, a[1])
		} else {
			p, err = path(int32(a[1]), a[2])
		}
	case "link", "rename":
		if p, err = path(unix.AT_FDCWD, a[0]); err == nil {
			q, err = path(unix.AT_FDCWD, a[1])
		}
	case "linkat", "renameat", "renameat2":
		if p, err = path(int32(a[0]), a[1]); err == nil {
			q, err = path(int32(a[2]), a[3])
		}
	default:
		return nil, kinds, fmt.Errorf("syscall %d is not modelled", n.Nr)
	}
	if errors.Is(err, errRefusalWatchNoParent) {
		return nil, append(kinds, "missing parent"), nil
	}
	if err != nil {
		return nil, kinds, err
	}
	var ops []refusalWatchOp
	var kind string
	switch name {
	case "open":
		ops, kind, err = refusalWatchOpen(p, a[1])
	case "openat":
		ops, kind, err = refusalWatchOpen(p, a[2])
	case "openat2":
		ops, kind, err = refusalWatchOpen(p, flags)
	case "creat":
		ops, kind, err = refusalWatchOpen(p, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC)
	case "mkdir", "mkdirat":
		ops, kind, err = refusalWatchCreate(p, llsys.AccessFSMakeDir)
	case "mknod", "mknodat":
		mode := a[1]
		if name == "mknodat" {
			mode = a[2]
		}
		need, merr := refusalWatchMknod(mode)
		if merr != nil {
			return nil, kinds, merr
		}
		ops, kind, err = refusalWatchCreate(p, need)
	case "symlink", "symlinkat":
		ops, kind, err = refusalWatchCreate(p, llsys.AccessFSMakeSym)
	case "unlink":
		ops = refusalWatchRemove(p, llsys.AccessFSRemoveFile)
	case "rmdir":
		ops = refusalWatchRemove(p, llsys.AccessFSRemoveDir)
	case "unlinkat":
		if a[2]&^unix.AT_REMOVEDIR != 0 {
			return nil, kinds, fmt.Errorf("unlinkat flags %#x are not modelled", a[2])
		}
		need := landlock.AccessFSSet(llsys.AccessFSRemoveFile)
		if a[2]&unix.AT_REMOVEDIR != 0 {
			need = llsys.AccessFSRemoveDir
		}
		ops = refusalWatchRemove(p, need)
	case "truncate":
		ops, kind, err = refusalWatchOpen(p, unix.O_TRUNC)
	case "link":
		ops, kind, err = refusalWatchPair(p, q, false, 0)
	case "linkat":
		if a[4]&^unix.AT_SYMLINK_FOLLOW != 0 {
			return nil, kinds, fmt.Errorf("linkat flags %#x are not modelled", a[4])
		}
		if a[4]&unix.AT_SYMLINK_FOLLOW != 0 {
			if p, err = filepath.EvalSymlinks(p); errors.Is(err, fs.ErrNotExist) {
				return nil, kinds, nil
			} else if err != nil {
				return nil, kinds, err
			}
		}
		ops, kind, err = refusalWatchPair(p, q, false, 0)
	case "rename", "renameat":
		ops, kind, err = refusalWatchPair(p, q, true, 0)
	case "renameat2":
		ops, kind, err = refusalWatchPair(p, q, true, a[4])
	}
	if kind != "" {
		kinds = append(kinds, kind)
	}
	return ops, kinds, err
}

func refusalWatchOpen(p string, flags uint64) ([]refusalWatchOp, string, error) {
	if flags&unix.O_PATH != 0 {
		return nil, "O_PATH", nil
	}
	if flags&unix.O_TMPFILE == unix.O_TMPFILE {
		return nil, "", errors.New("O_TMPFILE is not modelled")
	}
	if flags&refusalWatchWriteFlags == 0 {
		return nil, "", nil
	}
	if flags&^refusalWatchOpenFlags != 0 || flags&unix.O_ACCMODE == unix.O_ACCMODE {
		return nil, "", fmt.Errorf("open flags %#x are not modelled", flags)
	}
	info, err := os.Lstat(p)
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		if flags&unix.O_NOFOLLOW != 0 {
			return nil, "final symlink not followed", nil
		}
		if p, err = filepath.EvalSymlinks(p); err != nil {
			return nil, "", fmt.Errorf("final symlink: %w", err)
		}
		info, err = os.Stat(p)
	}
	if errors.Is(err, fs.ErrNotExist) {
		if flags&unix.O_CREAT == 0 {
			return nil, "", nil
		}
		return []refusalWatchOp{{p, filepath.Dir(p), llsys.AccessFSMakeReg}}, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if flags&(unix.O_CREAT|unix.O_EXCL) == unix.O_CREAT|unix.O_EXCL {
		return nil, "exists", nil
	}
	if info.IsDir() {
		return nil, "directory", nil
	}
	var need landlock.AccessFSSet
	if flags&(unix.O_WRONLY|unix.O_RDWR) != 0 {
		need |= llsys.AccessFSWriteFile
	}
	if flags&unix.O_TRUNC != 0 && info.Mode().IsRegular() {
		need |= llsys.AccessFSTruncate
	}
	if need == 0 {
		return nil, "", nil
	}
	return []refusalWatchOp{{p, p, need}}, "", nil
}

func refusalWatchCreate(p string, need landlock.AccessFSSet) ([]refusalWatchOp, string, error) {
	_, err := os.Lstat(p)
	switch {
	case err == nil:
		return nil, "exists", nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, "", err
	}
	return []refusalWatchOp{{p, filepath.Dir(p), need}}, "", nil
}

func refusalWatchRemove(p string, need landlock.AccessFSSet) []refusalWatchOp {
	if _, err := os.Lstat(p); err != nil {
		return nil
	}
	return []refusalWatchOp{{p, filepath.Dir(p), need}}
}

func refusalWatchMknod(mode uint64) (landlock.AccessFSSet, error) {
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

func refusalWatchPair(src, dst string, rename bool, flags uint64) ([]refusalWatchOp, string, error) {
	if flags&^unix.RENAME_NOREPLACE != 0 {
		return nil, "", fmt.Errorf("renameat2 flags %#x are not modelled", flags)
	}
	si, err := os.Lstat(src)
	if err != nil {
		return nil, "", nil
	}
	var srcNeed landlock.AccessFSSet
	if rename {
		srcNeed = refusalWatchTypeAccess(si, true)
	}
	dstNeed := refusalWatchTypeAccess(si, false)
	if di, err := os.Lstat(dst); err == nil {
		if !rename || flags&unix.RENAME_NOREPLACE != 0 {
			return nil, "exists", nil
		}
		dstNeed |= refusalWatchTypeAccess(di, true)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, "", err
	}
	if filepath.Dir(src) != filepath.Dir(dst) {
		srcNeed |= llsys.AccessFSRefer
		dstNeed |= llsys.AccessFSRefer
	}
	return []refusalWatchOp{{src, filepath.Dir(src), srcNeed}, {dst, filepath.Dir(dst), dstNeed}}, "", nil
}

func refusalWatchTypeAccess(info fs.FileInfo, remove bool) landlock.AccessFSSet {
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

func refusalWatchAccess(rules []pathRule, path string) landlock.AccessFSSet {
	var a landlock.AccessFSSet
	for _, r := range rules {
		if within(path, r.Path) {
			a |= r.Access
		}
	}
	return a
}

func (w *refusalWatcher) verdict(op refusalWatchOp) string {
	dir := op.at
	if op.at == op.path {
		dir = filepath.Dir(op.path)
	}
	rules, ok := w.grants[dir]
	if !ok {
		p := w.policy
		p.WriteRoots = append(slices.Clone(p.WriteRoots), dir)
		var err error
		if rules, err = landlockRules(p, osFS{}, heldTmp{}); err != nil {
			return "inconclusive: " + err.Error()
		}
		w.grants[dir] = rules
	}
	if refusalWatchAccess(rules, op.at)&op.need == op.need {
		return "grant candidate " + dir
	}
	switch {
	case coveredBy(op.at, w.blocked) || coveredBy(op.path, w.blocked):
		return "not grantable: blocked path"
	case coveredBy(op.at, w.noWrite) || coveredBy(op.path, w.noWrite):
		return "not grantable: no-write path"
	case slices.Contains(w.shm, op.at):
		return "not grantable: /dev/shm itself"
	case containsAny(dir, w.blocked) || containsAny(dir, w.noWrite):
		return "not grantable: " + dir + " holds a blocked or no-write path"
	}
	return "not grantable"
}

func refusalWatchRead(pid uint32, addr uint64, buf []byte) error {
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(len(buf))
	n, err := unix.ProcessVMReadv(int(pid), local, []unix.RemoteIovec{{Base: uintptr(addr), Len: len(buf)}}, 0)
	if err == nil && n != len(buf) {
		return fmt.Errorf("short read %d of %d", n, len(buf))
	}
	return err
}

func refusalWatchWrite(pid uint32, addr uint64, buf []byte) error {
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(len(buf))
	_, err := unix.ProcessVMWritev(int(pid), local, []unix.RemoteIovec{{Base: uintptr(addr), Len: len(buf)}}, 0)
	return err
}

func refusalWatchString(pid uint32, addr uint64) (string, error) {
	const page = 4096
	var out []byte
	for len(out) < unix.PathMax {
		chunk := make([]byte, page-int(addr%page))
		if err := refusalWatchRead(pid, addr, chunk); err != nil {
			return "", err
		}
		if i := bytes.IndexByte(chunk, 0); i >= 0 {
			return string(append(out, chunk[:i]...)), nil
		}
		out = append(out, chunk...)
		addr += uint64(len(chunk))
	}
	return "", errors.New("path longer than PATH_MAX")
}

func refusalWatchOpenHow(n seccompNotif) (unix.OpenHow, []byte, error) {
	var how unix.OpenHow
	if n.Args[3] < unix.SizeofOpenHow || n.Args[3] > 4096 {
		return how, nil, fmt.Errorf("open_how size %d", n.Args[3])
	}
	buf := make([]byte, n.Args[3])
	if err := refusalWatchRead(n.Pid, n.Args[2], buf); err != nil {
		return how, nil, err
	}
	how.Flags = binary.NativeEndian.Uint64(buf)
	how.Mode = binary.NativeEndian.Uint64(buf[8:])
	how.Resolve = binary.NativeEndian.Uint64(buf[16:])
	return how, buf[unix.SizeofOpenHow:], nil
}

func refusalWatchResolve(tid uint32, dirfd int32, s string) (string, error) {
	if s == "" {
		return "", errors.New("empty path; AT_EMPTY_PATH is not modelled")
	}
	raw := s
	if !filepath.IsAbs(s) {
		link := fmt.Sprintf("/proc/%d/cwd", tid)
		if dirfd != unix.AT_FDCWD {
			link = fmt.Sprintf("/proc/%d/fd/%d", tid, dirfd)
		}
		base, err := os.Readlink(link)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(base) || strings.HasSuffix(base, " (deleted)") {
			return "", fmt.Errorf("%s names %q, not a folder path", link, base)
		}
		raw = base + "/" + s
	}
	if raw == "/proc" || strings.HasPrefix(raw, "/proc/") {
		return "", errors.New("procfs paths are not modelled")
	}
	if strings.HasSuffix(raw, "/") {
		return "", errors.New("a trailing slash is not modelled")
	}
	i := strings.LastIndexByte(raw, '/')
	dir, last := raw[:i], raw[i+1:]
	if last == "." || last == ".." {
		return "", fmt.Errorf("final component %q is not modelled", last)
	}
	if dir == "" {
		dir = "/"
	}
	parent, err := filepath.EvalSymlinks(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", errRefusalWatchNoParent
	}
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(parent); err != nil {
		return "", err
	} else if !info.IsDir() {
		return "", fmt.Errorf("lookup parent %s is not a folder", parent)
	}
	return filepath.Join(parent, last), nil
}

func refusalWatchAction(a string) error {
	op, arg, _ := strings.Cut(a, ":")
	src, dst, _ := strings.Cut(arg, ":")
	create := func(p string) error {
		fd, err := unix.Open(p, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	}
	open := func(flags int) error {
		fd, err := unix.Open(arg, flags|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	}
	openat2 := func(how *unix.OpenHow) error {
		fd, err := unix.Openat2(unix.AT_FDCWD, arg, how)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	}
	switch op {
	case "mkdir":
		return unix.Mkdir(arg, 0o700)
	case "create":
		return create(arg)
	case "write-trunc":
		fd, err := unix.Open(arg, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	case "read":
		fd, err := unix.Open(arg, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	case "open-path-write":
		return open(unix.O_PATH | unix.O_WRONLY)
	case "open-path-create":
		return open(unix.O_PATH | unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC)
	case "open-nofollow-write":
		return open(unix.O_WRONLY | unix.O_NOFOLLOW)
	case "unlink":
		return unix.Unlinkat(unix.AT_FDCWD, arg, 0)
	case "openat2-path-write":
		return openat2(&unix.OpenHow{Flags: unix.O_PATH | unix.O_WRONLY | unix.O_CLOEXEC})
	case "openat2-unknown-flag":
		return openat2(&unix.OpenHow{Flags: unix.O_WRONLY | 1<<31})
	case "mkdirat-fd":
		dir, err := unix.Open(src, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(dir) }()
		return unix.Mkdirat(dir, dst, 0o700)
	case "openat2-read":
		return openat2(&unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC})
	case "openat2-write":
		return openat2(&unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_CLOEXEC, Mode: 0o600})
	case "openat2-unreadable":
		p, err := unix.BytePtrFromString(arg)
		if err != nil {
			return err
		}
		cwd := unix.AT_FDCWD
		_, _, e := unix.Syscall6(unix.SYS_OPENAT2, uintptr(cwd), uintptr(unsafe.Pointer(p)), 1, unix.SizeofOpenHow, 0, 0)
		return errnoErr(e)
	case "openat2-ext":
		p, err := unix.BytePtrFromString(arg)
		if err != nil {
			return err
		}
		var how [unix.SizeofOpenHow + 8]byte
		binary.NativeEndian.PutUint64(how[:], unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC)
		binary.NativeEndian.PutUint64(how[8:], 0o600)
		how[unix.SizeofOpenHow] = 1
		cwd := unix.AT_FDCWD
		fd, _, e := unix.Syscall6(unix.SYS_OPENAT2, uintptr(cwd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how[0])), uintptr(len(how)), 0, 0)
		if e == 0 {
			return unix.Close(int(fd))
		}
		return errnoErr(e)
	case "openat2-inroot":
		dir, err := unix.Open(src, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(dir) }()
		fd, err := unix.Openat2(dir, dst, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_CLOEXEC, Mode: 0o600, Resolve: unix.RESOLVE_IN_ROOT})
		if err != nil {
			return err
		}
		return unix.Close(fd)
	case "link-follow":
		return unix.Linkat(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.AT_SYMLINK_FOLLOW)
	case "rename":
		return unix.Rename(src, dst)
	case "rename-unknown-flag":
		return unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, 1<<31)
	case "rename-whiteout":
		return unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_WHITEOUT)
	case "unlink-unknown-flag":
		return unix.Unlinkat(unix.AT_FDCWD, arg, 1<<31)
	case "rmdir-at":
		return unix.Unlinkat(unix.AT_FDCWD, arg, unix.AT_REMOVEDIR)
	case "mknod-dir":
		return unix.Mknod(arg, unix.S_IFDIR|0o700, 0)
	case "symlink":
		return unix.Symlinkat(src, unix.AT_FDCWD, dst)
	case "symlink-unreadable":
		p, err := unix.BytePtrFromString(arg)
		if err != nil {
			return err
		}
		cwd := unix.AT_FDCWD
		_, _, e := unix.Syscall(unix.SYS_SYMLINKAT, 1, uintptr(cwd), uintptr(unsafe.Pointer(p)))
		return errnoErr(e)
	case "truncate":
		return unix.Truncate(arg, 0)
	case "truncate-negative":
		return unix.Truncate(arg, -1)
	case "link":
		return unix.Link(src, dst)
	case "fallback":
		if err := create(src); err != nil {
			return create(dst)
		}
		return nil
	case "connect":
		port, err := strconv.Atoi(arg)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		return unix.Connect(fd, loopback4(port))
	}
	return fmt.Errorf("unknown action %q", a)
}

func TestRefusalWatchProtoChild(t *testing.T) {
	mode := os.Getenv(refusalWatchChildEnv)
	if mode == "" {
		t.Skip("runs only as the disposable child of the refusal-watch prototype tests")
	}
	args := flag.Args()
	ctl := os.NewFile(3, "ctl")
	report := func(key, val string) {
		if _, err := fmt.Fprintf(ctl, "%s=%s\n", key, strings.ReplaceAll(val, "\n", " ")); err != nil {
			panic(fmt.Sprintf("fixture: reporting %s: %v", key, err))
		}
	}
	fail := func(step string, err error) {
		if _, werr := ctl.Write([]byte("E")); werr != nil {
			t.Fatal(werr)
		}
		report(step, errName(err))
	}
	var p Policy
	if err := json.Unmarshal([]byte(os.Getenv(refusalWatchPolicyEnv)), &p); err != nil {
		t.Fatal(err)
	}
	if err := applyLandlock(p); err != nil {
		fail("landlock", err)
		return
	}
	if err := installSeccomp(p); err != nil {
		fail("seccomp", err)
		return
	}
	if mode == "plain" {
		if _, err := ctl.Write([]byte("N")); err != nil {
			t.Fatal(err)
		}
	} else {
		fd, err := refusalWatchInstall(mode == "merged")
		if err != nil {
			fail("listener filter", err)
			return
		}
		if err := unix.Sendmsg(3, []byte("L"), unix.UnixRights(fd), nil, 0); err != nil {
			t.Fatal(err)
		}
		// The kernel fails paused calls when the watcher stops only if the watcher holds the last listener reference.
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		report("closed", "1")
	}
	if line, err := bufio.NewReader(ctl).ReadString('\n'); err != nil || line != "go\n" {
		t.Fatalf("waiting for go: %q %v", line, err)
	}
	if args[0] == "exec" {
		if _, err := unix.FcntlInt(3, unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		t.Fatal(syscall.Exec(args[1], args[1:], os.Environ()))
	}
	for i, a := range args {
		report(strconv.Itoa(i), errName(refusalWatchAction(a)))
	}
}

type refusalWatchSetup struct {
	policy   Policy
	mode     string
	env      []string
	dir      string
	timeout  time.Duration
	stopped  bool
	hook     func(n seccompNotif, name string)
	progress string
	args     []string
}

type refusalWatchResult struct {
	results map[string]string
	w       *refusalWatcher
	pid     int
	out     string
	err     error
	elapsed time.Duration
}

func refusalWatchRun(t *testing.T, s refusalWatchSetup) refusalWatchResult {
	t.Helper()
	if abi, err := landlockABI(); err != nil || abi < 3 {
		t.Skipf("Landlock ABI 3 unavailable: ABI %d, %v", abi, err)
	}
	if scope := sysctl("/proc/sys/kernel/yama/ptrace_scope"); scope == "2" || scope == "3" {
		t.Skipf("inconclusive at kernel.yama.ptrace_scope=%s: the watcher cannot read the child's memory", scope)
	}
	if s.timeout == 0 {
		s.timeout = 30 * time.Second
	}
	if s.env == nil {
		s.env = os.Environ()
	}
	policy, err := json.Marshal(s.policy)
	if err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentEnd, childEnd := os.NewFile(uintptr(fds[0]), "watch-ctl"), os.NewFile(uintptr(fds[1]), "watch-child-ctl")
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestRefusalWatchProtoChild$", "--"}, s.args...)...)
	cmd.Env = append(slices.Clone(s.env), refusalWatchChildEnv+"="+s.mode, refusalWatchPolicyEnv+"="+string(policy))
	cmd.Dir = s.dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.ExtraFiles = []*os.File{childEnd}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	err = cmd.Start()
	closed(t, "the child's control end", childEnd.Close())
	if err != nil {
		closed(t, "the parent's control end", parentEnd.Close())
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	fail := func(format string, a ...any) {
		cancel()
		<-done
		t.Fatalf(format+"\nchild (%v) output:\n%s", append(a, waitErr, out.String())...)
	}
	conn, err := net.FileConn(parentEnd)
	closed(t, "the parent's control end", parentEnd.Close())
	if err != nil {
		fail("control socket: %v", err)
	}
	ctl := conn.(*net.UnixConn)
	defer func() { closed(t, "the control connection", ctl.Close()) }()
	if err := ctl.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		fail("%v", err)
	}
	b, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := ctl.ReadMsgUnix(b, oob)
	if err != nil || n != 1 {
		fail("no confinement message from the child: %v", err)
	}
	lines := bufio.NewReader(ctl)
	res := refusalWatchResult{results: map[string]string{}, pid: cmd.Process.Pid}
	listener := -1
	switch b[0] {
	case 'E':
		line, _ := lines.ReadString('\n')
		if strings.HasPrefix(line, "listener filter=") {
			t.Skipf("inconclusive: seccomp user notification refused: %s", line)
		}
		fail("child confinement failed: %s", line)
	case 'L':
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(msgs) != 1 {
			fail("listener message: %v", err)
		}
		rights, err := unix.ParseUnixRights(&msgs[0])
		if err != nil || len(rights) != 1 {
			fail("listener rights: %v", err)
		}
		listener = rights[0]
		if line, err := lines.ReadString('\n'); err != nil || line != "closed=1\n" {
			fail("child did not close its listener: %q %v", line, err)
		}
	}
	stop, watched := make(chan struct{}), make(chan struct{})
	close(watched)
	stopWatch := sync.OnceFunc(func() {
		close(stop)
		<-watched
	})
	defer stopWatch()
	if listener >= 0 {
		if got := notifyListeners(t, strconv.Itoa(cmd.Process.Pid)); got != 0 {
			fail("child still holds %d listener descriptors", got)
		}
		if res.w, err = refusalWatchNew(s.policy); err != nil {
			fail("watcher: %v", err)
		}
		res.w.hook = s.hook
		if s.stopped {
			closed(t, "the listener", unix.Close(listener))
		} else {
			watched = make(chan struct{})
			go func() {
				defer close(watched)
				defer func() { closed(t, "the listener", unix.Close(listener)) }()
				res.w.run(listener, stop)
			}()
		}
	}
	start := time.Now()
	if s.progress != "" {
		go func() {
			tick := time.NewTicker(30 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					notified := "unwatched"
					if res.w != nil {
						notified = strconv.Itoa(res.w.total()) + " notifications"
					}
					fmt.Fprintf(os.Stderr, "refusal watch: %s: %s elapsed, %s\n", s.progress, time.Since(start).Round(time.Second), notified)
				}
			}
		}()
	}
	if _, err := ctl.Write([]byte("go\n")); err != nil {
		fail("send go: %v", err)
	}
	if err := ctl.SetReadDeadline(time.Time{}); err != nil {
		fail("%v", err)
	}
	for {
		line, err := lines.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fail("reading child results: %v", err)
			}
			break
		}
		k, v, _ := strings.Cut(strings.TrimSuffix(line, "\n"), "=")
		res.results[k] = v
	}
	select {
	case <-done:
	case <-ctx.Done():
		fail("child did not exit")
	}
	res.elapsed = time.Since(start)
	stopWatch()
	res.out, res.err = out.String(), waitErr
	if s.args[0] != "exec" && waitErr != nil {
		fail("child failed")
	}
	return res
}

type refusalWatchFx struct {
	blocked, root, sub, tmp, outside string
	policy                           Policy
}

// The rule builder lists every entry beside a blocked path, so the fixture lives outside the busy
// shared temp folder.
func refusalWatchFixture(t *testing.T) refusalWatchFx {
	t.Helper()
	base, err := os.MkdirTemp("/var/tmp", "codemeld-refusal-watch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("fixture: removing %s: %v", base, err)
		}
	})
	if base, err = filepath.EvalSymlinks(base); err != nil {
		t.Fatal(err)
	}
	fx := refusalWatchFx{
		blocked: filepath.Join(base, "blocked"), root: filepath.Join(base, "root"),
		tmp: filepath.Join(base, "tmp"), outside: filepath.Join(base, "outside"),
	}
	fx.sub = filepath.Join(fx.root, "sub")
	for _, d := range []string{fx.blocked, fx.sub, filepath.Join(fx.root, ".codemeld"), filepath.Join(fx.root, ".hg"), fx.tmp, fx.outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"src", "r"} {
		if err := os.WriteFile(filepath.Join(fx.outside, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fx.policy = Policy{
		Mode: ModeAutoEdits, BlockedPaths: []string{fx.blocked}, WriteRoots: []string{fx.root},
		NoWritePaths: []string{filepath.Join(fx.root, ".codemeld"), filepath.Join(fx.root, ".hg")}, TmpDir: fx.tmp,
	}
	if err := fx.policy.validate(); err != nil {
		t.Fatal(err)
	}
	return fx
}

func refusalWatchCheck(t *testing.T, r refusalWatchResult, wantResults []string, wantReports map[string]string) {
	t.Helper()
	for i, want := range wantResults {
		if got := r.results[strconv.Itoa(i)]; got != want {
			t.Errorf("action %d: child result %q, want %q", i, got, want)
		}
	}
	got := map[string]string{}
	for _, rep := range r.w.reports {
		got[rep.path] = rep.verdict
	}
	if len(r.w.reports) != len(wantReports) || !maps.Equal(got, wantReports) {
		t.Errorf("watcher reports %+v, want %v (notes %q)", r.w.reports, wantReports, r.w.notes)
	}
}

func TestRefusalWatchProtoMkdir(t *testing.T) {
	fx := refusalWatchFixture(t)
	refused, inTmp := filepath.Join(fx.outside, "new"), filepath.Join(fx.tmp, "new")
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{"mkdir:" + refused, "mkdir:" + inTmp}})
	refusalWatchCheck(t, r, []string{"EACCES", "0"}, map[string]string{refused: "grant candidate " + fx.outside})
}

func TestRefusalWatchProtoOpenat2(t *testing.T) {
	fx := refusalWatchFixture(t)
	refused := filepath.Join(fx.outside, "w")
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{
		"openat2-read:" + filepath.Join(fx.outside, "r"),
		"openat2-write:" + refused,
		"openat2-write:" + filepath.Join(fx.tmp, "w"),
		"openat2-unreadable:" + filepath.Join(fx.tmp, "u"),
		"openat2-inroot:" + fx.outside + ":/w",
		"openat2-ext:" + filepath.Join(fx.tmp, "e"),
	}})
	refusalWatchCheck(t, r, []string{"0", "EACCES", "0", "EFAULT", "EACCES", "E2BIG"}, map[string]string{refused: "grant candidate " + fx.outside})
	for key, want := range map[string]int{"openat2": 6, "openat2 read-only": 1, "openat2 write-intent": 2, "openat2 unreadable": 1, "openat2 unsupported": 2, "inconclusive": 3} {
		if got := r.w.counts[key]; got != want {
			t.Errorf("%s notifications: %d, want %d (counts %v)", key, got, want, r.w.counts)
		}
	}
}

func TestRefusalWatchProtoProtections(t *testing.T) {
	fx := refusalWatchFixture(t)
	src := filepath.Join(fx.outside, "src")
	args := []string{
		"create:" + filepath.Join(fx.root, ".codemeld", "x"),
		"create:" + filepath.Join(fx.root, ".hg", "x"),
		"create:" + filepath.Join(fx.blocked, "x"),
		"create:" + filepath.Join(fx.outside, "x"),
		"create:" + filepath.Join(fx.sub, "ok"),
		"link:" + src + ":" + filepath.Join(fx.sub, "linked"),
		"rename:" + src + ":" + filepath.Join(fx.sub, "moved"),
	}
	wantResults := []string{"EACCES", "EACCES", "EACCES", "EACCES", "0", "EXDEV", "EACCES"}
	wantReports := map[string]string{
		filepath.Join(fx.root, ".codemeld", "x"): "not grantable: no-write path",
		filepath.Join(fx.root, ".hg", "x"):       "not grantable: no-write path",
		filepath.Join(fx.blocked, "x"):           "not grantable: blocked path",
		filepath.Join(fx.outside, "x"):           "grant candidate " + fx.outside,
	}
	shmReports := 0
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		shm, err := os.MkdirTemp("/dev/shm", "codemeld-refusal-watch-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(shm); err != nil {
				t.Errorf("fixture: removing %s: %v", shm, err)
			}
		})
		inShm, atShm := filepath.Join(shm, "x"), shm+"-direct"
		t.Cleanup(func() { _ = os.Remove(atShm) })
		args = append(args, "create:"+inShm, "create:"+atShm)
		wantResults = append(wantResults, "EACCES", "EACCES")
		wantReports[inShm] = "grant candidate " + shm
		wantReports[atShm] = "not grantable: /dev/shm itself"
		shmReports = 2
	}
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: args})
	got := map[string]string{}
	pairSources := 0
	for _, rep := range r.w.reports {
		if rep.path == src {
			pairSources++
			if rep.verdict != "grant candidate "+fx.outside {
				t.Errorf("%s of refused source %s: verdict %q, want a grant candidate for %s", rep.call, src, rep.verdict, fx.outside)
			}
			continue
		}
		got[rep.path] = rep.verdict
	}
	if pairSources != 2 {
		t.Errorf("refused link and rename source reported %d times, want 2: %+v", pairSources, r.w.reports)
	}
	if !maps.Equal(got, wantReports) || len(r.w.reports) != len(wantReports)+pairSources {
		t.Errorf("watcher reports %+v, want %v plus the pair sources (notes %q)", r.w.reports, wantReports, r.w.notes)
	}
	for i, want := range wantResults {
		if got := r.results[strconv.Itoa(i)]; got != want {
			t.Errorf("%s: child result %q, want %q", args[i], got, want)
		}
	}
	t.Logf("child results %v; %d /dev/shm cases", r.results, shmReports)
}

func TestRefusalWatchProtoLinkFollow(t *testing.T) {
	fx := refusalWatchFixture(t)
	target, sym := filepath.Join(fx.outside, "src"), filepath.Join(fx.sub, "sym")
	if err := os.Symlink(target, sym); err != nil {
		t.Fatal(err)
	}
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{
		"link-follow:" + sym + ":" + filepath.Join(fx.sub, "linked"),
	}})
	refusalWatchCheck(t, r, []string{"EXDEV"}, map[string]string{target: "grant candidate " + fx.outside})
}

func TestRefusalWatchProtoLookupSemantics(t *testing.T) {
	fx := refusalWatchFixture(t)
	file, sym, absent := filepath.Join(fx.outside, "r"), filepath.Join(fx.outside, "sym"), filepath.Join(fx.outside, "new")
	if err := os.Symlink(file, sym); err != nil {
		t.Fatal(err)
	}
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{
		"open-path-write:" + file,
		"open-path-create:" + absent,
		"openat2-path-write:" + file,
		"open-nofollow-write:" + sym,
		"unlink:" + file + "/",
		"write-trunc:" + fx.outside,
		"mkdirat-fd:" + file + ":new",
		"mkdir:" + file + "/new",
		"openat2-unknown-flag:" + file,
	}})
	refusalWatchCheck(t, r, []string{"0", "ENOENT", "EINVAL", "ELOOP", "ENOTDIR", "EISDIR", "ENOTDIR", "ENOTDIR", "EINVAL"}, map[string]string{})
	for key, want := range map[string]int{"notified": 9, "O_PATH": 3, "final symlink not followed": 1, "directory": 1, "inconclusive": 4} {
		if got := r.w.counts[key]; got != want {
			t.Errorf("%s notifications: %d, want %d (counts %v)", key, got, want, r.w.counts)
		}
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "x" {
		t.Errorf("%s: %q %v, want it unchanged", file, b, err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s: %v, want it absent", absent, err)
	}
}

func TestRefusalWatchProtoMutationFlags(t *testing.T) {
	fx := refusalWatchFixture(t)
	src, dir, moved := filepath.Join(fx.outside, "src"), filepath.Join(fx.outside, "dir"), filepath.Join(fx.outside, "moved")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{
		"unlink-unknown-flag:" + src,
		"rename-unknown-flag:" + src + ":" + moved,
		"rename-whiteout:" + src + ":" + moved,
		"mknod-dir:" + filepath.Join(fx.outside, "new"),
		"rmdir-at:" + dir,
	}})
	refusalWatchCheck(t, r, []string{"EINVAL", "EINVAL", "EACCES", "EPERM", "EACCES"}, map[string]string{dir: "grant candidate " + fx.outside})
	for key, want := range map[string]int{"notified": 5, "inconclusive": 4} {
		if got := r.w.counts[key]; got != want {
			t.Errorf("%s notifications: %d, want %d (counts %v, notes %q)", key, got, want, r.w.counts, r.w.notes)
		}
	}
	if _, err := os.Lstat(src); err != nil {
		t.Errorf("%s: %v, want it unchanged", src, err)
	}
}

func TestRefusalWatchProtoArgumentChecks(t *testing.T) {
	fx := refusalWatchFixture(t)
	file, link := filepath.Join(fx.outside, "r"), filepath.Join(fx.outside, "link")
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{
		"symlink-unreadable:" + filepath.Join(fx.outside, "bad"),
		"symlink::" + filepath.Join(fx.outside, "empty"),
		"truncate-negative:" + file,
		"symlink:x:" + link,
		"truncate:" + file,
	}})
	refusalWatchCheck(t, r, []string{"EFAULT", "ENOENT", "EINVAL", "EACCES", "EACCES"}, map[string]string{
		link: "grant candidate " + fx.outside, file: "grant candidate " + fx.outside,
	})
	for key, want := range map[string]int{"notified": 5, "inconclusive": 3} {
		if got := r.w.counts[key]; got != want {
			t.Errorf("%s notifications: %d, want %d (counts %v, notes %q)", key, got, want, r.w.counts, r.w.notes)
		}
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "x" {
		t.Errorf("%s: %q %v, want it unchanged", file, b, err)
	}
}

func TestRefusalWatchProtoDeviceRights(t *testing.T) {
	devs := fstest.MapFS{"char": {Mode: fs.ModeDevice | fs.ModeCharDevice}, "block": {Mode: fs.ModeDevice}}
	fx := refusalWatchFixture(t)
	w, err := refusalWatchNew(fx.policy)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]landlock.AccessFSSet{"char": llsys.AccessFSMakeChar, "block": llsys.AccessFSMakeBlock} {
		info, err := fs.Stat(devs, name)
		if err != nil {
			t.Fatal(err)
		}
		if got := refusalWatchTypeAccess(info, false); got != want {
			t.Errorf("%s device destination right %v, want %v", name, got, want)
		}
		op := refusalWatchOp{filepath.Join(fx.outside, name), fx.outside, want}
		if got := w.verdict(op); got != "not grantable" {
			t.Errorf("%s device in %s: verdict %q, want not grantable", name, fx.outside, got)
		}
	}
	// A 0:0 character device is an overlayfs whiteout, the one device node an unprivileged process may create.
	dev := filepath.Join(fx.sub, "dev")
	if err := unix.Mknod(dev, unix.S_IFCHR|0o600, 0); err != nil {
		t.Skipf("inconclusive: cannot create a whiteout device node: %v", err)
	}
	linked, moved := filepath.Join(fx.outside, "linked"), filepath.Join(fx.outside, "moved")
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{
		"link:" + dev + ":" + linked, "rename:" + dev + ":" + moved,
	}})
	refusalWatchCheck(t, r, []string{"EACCES", "EACCES"}, map[string]string{linked: "not grantable", moved: "not grantable"})
}

func TestRefusalWatchProtoFalseReports(t *testing.T) {
	fx := refusalWatchFixture(t)
	tolerated := filepath.Join(fx.outside, "f")
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", args: []string{
		"fallback:" + tolerated + ":" + filepath.Join(fx.tmp, "f"),
		"mkdir:" + fx.outside,
		"write-trunc:/dev/null",
	}})
	refusalWatchCheck(t, r, []string{"0", "EEXIST", "0"}, map[string]string{tolerated: "grant candidate " + fx.outside})
	if r.w.counts["exists"] != 1 {
		t.Errorf("existing-target notifications: %d, want 1 (counts %v)", r.w.counts["exists"], r.w.counts)
	}
}

func TestRefusalWatchProtoChangedArguments(t *testing.T) {
	fx := refusalWatchFixture(t)
	seen := filepath.Join(fx.tmp, strings.Repeat("a", 40))
	used := filepath.Join(fx.outside, "b")
	raced := filepath.Join(fx.outside, "race")
	hook := func(n seccompNotif, name string) {
		var err error
		switch name {
		case "mkdirat":
			err = refusalWatchWrite(n.Pid, n.Args[1], append([]byte(used), 0))
		case "openat2":
			flags := make([]byte, 8)
			binary.NativeEndian.PutUint64(flags, unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC)
			err = refusalWatchWrite(n.Pid, n.Args[2], flags)
		}
		if err != nil {
			t.Errorf("fixture: changing the child's arguments: %v", err)
		}
	}
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", hook: hook, args: []string{
		"mkdir:" + seen, "openat2-read:" + raced,
	}})
	refusalWatchCheck(t, r, []string{"EACCES", "EACCES"}, map[string]string{})
	if r.w.counts["openat2 read-only"] != 1 {
		t.Errorf("openat2 counted %v, want one read-only call", r.w.counts)
	}
	for _, p := range []string{seen, used, raced} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v, want it absent", p, err)
		}
	}
}

func TestRefusalWatchProtoWatcherStops(t *testing.T) {
	fx := refusalWatchFixture(t)
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", stopped: true, args: []string{
		"mkdir:" + filepath.Join(fx.tmp, "x"), "read:" + filepath.Join(fx.outside, "r"),
	}})
	refusalWatchCheck(t, r, []string{"ENOSYS", "0"}, map[string]string{})
}

func TestRefusalWatchProtoMergedListener(t *testing.T) {
	fx := refusalWatchFixture(t)
	p := fx.policy
	p.ExceptionalAuthority = NetworkAccessAuthority
	ln, port := listenTCP(t)
	refused := filepath.Join(fx.outside, "m")
	r := refusalWatchRun(t, refusalWatchSetup{policy: p, mode: "merged", args: []string{"connect:" + port, "mkdir:" + refused}})
	refusalWatchCheck(t, r, []string{"EPERM", "EACCES"}, map[string]string{refused: "grant candidate " + fx.outside})
	if r.w.counts["connect denied"] != 1 {
		t.Errorf("connect decisions %v, want one denial", r.w.counts)
	}
	if err := ln.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := ln.Accept(); err == nil {
		closed(t, "the accepted connection", conn.Close())
		t.Errorf("the listener accepted a connection the watcher denied")
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestRefusalWatchProtoCommandChildren(t *testing.T) {
	fx := refusalWatchFixture(t)
	refused := filepath.Join(fx.outside, "viash")
	r := refusalWatchRun(t, refusalWatchSetup{policy: fx.policy, mode: "watch", dir: fx.sub,
		args: []string{"exec", "/bin/sh", "-c", "mkdir " + refused + "; mkdir rel; true"}})
	if len(r.w.reports) != 1 || r.w.reports[0].path != refused || r.w.reports[0].pid == uint32(r.pid) {
		t.Errorf("reports %+v, want only %s from a process other than the shell %d (notes %q)", r.w.reports, refused, r.pid, r.w.notes)
	}
	if _, err := os.Stat(filepath.Join(fx.sub, "rel")); err != nil {
		t.Errorf("relative mkdir inside the write root: %v", err)
	}
}

func refusalWatchRepoPolicy(t *testing.T, root, home, tmp string) Policy {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{
		Mode: ModeAutoEdits, BlockedPaths: []string{filepath.Join(home, ".codemeld")},
		NoWritePaths: []string{filepath.Join(root, ".codemeld")}, TmpDir: tmp,
	}
	for _, e := range entries {
		target, err := filepath.EvalSymlinks(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, target)
		first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
		if err != nil || first == "." || first == ".." || first == ".codemeld" || slices.Contains(p.WriteRoots, target) {
			continue
		}
		p.WriteRoots = append(p.WriteRoots, target)
	}
	for _, store := range []string{".hg", ".git"} {
		if _, err := os.Lstat(filepath.Join(root, store)); err == nil {
			p.NoWritePaths = append(p.NoWritePaths, filepath.Join(root, store))
		}
	}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func refusalWatchSummary(r refusalWatchResult) string {
	exit := "ok"
	if r.err != nil {
		exit = r.err.Error()
	}
	s := fmt.Sprintf("exit %s, %.1fs", exit, r.elapsed.Seconds())
	if r.err != nil {
		s += fmt.Sprintf(", output ends %q", r.out[max(0, len(r.out)-400):])
	}
	if r.w == nil {
		return s + ", unwatched"
	}
	keys := slices.Sorted(maps.Keys(r.w.counts))
	counts := make([]string, len(keys))
	for i, k := range keys {
		counts[i] = fmt.Sprintf("%s=%d", k, r.w.counts[k])
	}
	seen := map[string]int{}
	for _, rep := range r.w.reports {
		seen[rep.comm+": "+rep.call+" "+rep.path+" -> "+rep.verdict]++
	}
	reports := make([]string, 0, len(seen))
	for k, n := range seen {
		reports = append(reports, fmt.Sprintf("%s (x%d)", k, n))
	}
	sort.Strings(reports)
	notes := r.w.notes
	if len(notes) > 10 {
		notes = append(slices.Clone(notes[:10]), fmt.Sprintf("... %d more", len(r.w.notes)-10))
	}
	return fmt.Sprintf("%s; counts %s; %d reports, %d distinct:\n  %s\n  notes %q", s, strings.Join(counts, " "), len(r.w.reports), len(seen), strings.Join(reports, "\n  "), notes)
}

func TestRefusalWatchProtoWorkloads(t *testing.T) {
	pkgs := strings.Fields(os.Getenv(refusalWatchWorkloadsEnv))
	if len(pkgs) == 0 {
		t.Skipf("set %s to a package list such as ./... to measure the build workloads by hand", refusalWatchWorkloadsEnv)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	type workload struct {
		name string
		argv []string
	}
	workloads := []workload{
		{"go build", append([]string{goBin, "build"}, pkgs...)},
		{"go test", append([]string{goBin, "test"}, pkgs...)},
	}
	if lint, err := exec.LookPath("golangci-lint"); err == nil {
		workloads = append(workloads, workload{"golangci-lint", append([]string{lint, "run"}, pkgs...)})
	} else {
		t.Logf("golangci-lint not measured: %v", err)
	}
	newTmp := func() string {
		tmp, err := os.MkdirTemp("", "codemeld-refusal-watch-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(tmp); err != nil {
				t.Errorf("fixture: removing %s: %v", tmp, err)
			}
		})
		if tmp, err = filepath.EvalSymlinks(tmp); err != nil {
			t.Fatal(err)
		}
		return tmp
	}
	envFor := func(tmp string) []string {
		env, err := runner.FixedEnvironment(home, root, tmp, filepath.Dir(goBin)+":"+runner.FixedPATH, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"GOPATH", "GOMODCACHE"} {
			if v, ok := os.LookupEnv(name); ok {
				env = append(env, name+"="+v)
			}
		}
		return append(env, "GOLANGCI_LINT_CACHE="+filepath.Join(tmp, "golangci-lint"))
	}
	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "refusal watch: "+format+"\n", a...)
		t.Logf(format, a...)
	}
	runs := len(workloads) * 5
	logf("start: %d runs over %v in %s; kernel.yama.ptrace_scope=%s", runs, pkgs, root, sysctl("/proc/sys/kernel/yama/ptrace_scope"))
	i := 0
	measure := func(label, mode, tmp string, env []string, argv []string) refusalWatchResult {
		i++
		logf("run %d/%d: %s", i, runs, label)
		r := refusalWatchRun(t, refusalWatchSetup{
			policy: refusalWatchRepoPolicy(t, root, home, tmp), mode: mode, env: env, dir: root,
			timeout: 30 * time.Minute, progress: label, args: append([]string{"exec"}, argv...),
		})
		logf("run %d/%d: %s: %s", i, runs, label, refusalWatchSummary(r))
		return r
	}
	watched := 0
	for _, wl := range workloads {
		for _, mode := range []string{"plain", "watch"} {
			tmp := newTmp()
			for _, phase := range []string{"cold", "warm"} {
				r := measure(fmt.Sprintf("%s, %s cache, %s", wl.name, phase, mode), mode, tmp, envFor(tmp), wl.argv)
				if r.w != nil {
					watched += r.w.total()
				}
			}
		}
	}
	for _, wl := range workloads {
		tmp := newTmp()
		env := slices.DeleteFunc(envFor(tmp), func(e string) bool {
			return strings.HasPrefix(e, "GOCACHE=") || strings.HasPrefix(e, "GOLANGCI_LINT_CACHE=")
		})
		for _, name := range []string{"GOCACHE", "GOTMPDIR", "GOLANGCI_LINT_CACHE"} {
			if v, ok := os.LookupEnv(name); ok {
				env = append(env, name+"="+v)
			}
		}
		measure(wl.name+", real caches, watch", "watch", tmp, env, wl.argv)
	}
	if watched == 0 {
		t.Errorf("the watched workload runs produced no notifications")
	}
}
