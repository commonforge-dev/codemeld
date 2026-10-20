package enforce

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

const (
	accessReadDir = landlock.AccessFSSet(llsys.AccessFSReadDir)
	accessRead    = landlock.AccessFSSet(llsys.AccessFSReadFile|llsys.AccessFSExecute) | accessReadDir
	accessWrite   = landlock.AccessFSSet(llsys.AccessFSWriteFile | llsys.AccessFSTruncate |
		llsys.AccessFSMakeReg | llsys.AccessFSMakeDir | llsys.AccessFSMakeSym | llsys.AccessFSMakeFifo |
		llsys.AccessFSMakeSock | llsys.AccessFSRemoveFile | llsys.AccessFSRemoveDir | llsys.AccessFSRefer)
	accessDevNull  = landlock.AccessFSSet(llsys.AccessFSWriteFile)
	accessFileOnly = landlock.AccessFSSet(llsys.AccessFSReadFile | llsys.AccessFSExecute |
		llsys.AccessFSWriteFile | llsys.AccessFSTruncate)
	devShm = "/dev/shm"
)

var (
	landlockABI   = llsys.LandlockGetABIVersion
	restrictPaths = landlock.V3.RestrictPaths
)

type pathRule struct {
	Path   string
	Access landlock.AccessFSSet
}

type fsView interface {
	ReadDir(string) ([]fs.DirEntry, error)
	Stat(string) (fs.FileInfo, error)
	EvalSymlinks(string) (string, error)
	Lstat(string) (fs.FileInfo, error)
	Readlink(string) (string, error)
}

type osFS struct{}

func (osFS) ReadDir(p string) ([]fs.DirEntry, error) { return os.ReadDir(p) }
func (osFS) Stat(p string) (fs.FileInfo, error)      { return os.Stat(p) }
func (osFS) EvalSymlinks(p string) (string, error)   { return filepath.EvalSymlinks(p) }
func (osFS) Lstat(p string) (fs.FileInfo, error)     { return os.Lstat(p) }
func (osFS) Readlink(p string) (string, error)       { return os.Readlink(p) }

func applyLandlock(p Policy) error {
	abi, err := landlockABI()
	if err != nil {
		return fmt.Errorf("landlock ABI probe: %w", err)
	}
	if abi < 3 {
		return fmt.Errorf("landlock ABI %d < 3; sandbox needs Landlock ABI 3 or newer, first shipped in Linux 6.2", abi)
	}
	rules, err := landlockRules(p, osFS{})
	if err != nil {
		return err
	}
	opts := make([]landlock.Rule, len(rules))
	for i, r := range rules {
		opts[i] = landlock.PathAccess(r.Access, r.Path)
	}
	return restrictPaths(opts...)
}

type ruleBuilder struct {
	fs      fsView
	blocked []string
	noWrite []string
	shm     []string
	rules   []pathRule
	index   map[string]int
	seen    map[string]bool
}

func landlockRules(p Policy, view fsView) ([]pathRule, error) {
	b := &ruleBuilder{fs: view, index: map[string]int{}, seen: map[string]bool{}}
	var err error
	if b.blocked, err = b.withResolved(p.BlockedPaths); err != nil {
		return nil, err
	}
	if !coveredBy("/", b.blocked) {
		if err := b.walkRead("/"); err != nil {
			return nil, err
		}
	}
	if t, isDir, ok, err := b.resolve("/dev/null"); err != nil {
		return nil, err
	} else if ok && !coveredBy(t, b.blocked) {
		b.add(t, accessDevNull, isDir)
	}
	if p.Mode != ModeAutoEdits {
		return b.rules, nil
	}
	if b.noWrite, err = b.withResolved(p.NoWritePaths); err != nil {
		return nil, err
	}
	if b.shm, err = b.withResolved([]string{devShm}); err != nil {
		return nil, err
	}
	for _, root := range b.outerRoots(append(append([]string{}, p.WriteRoots...), p.TmpDir)) {
		t, isDir, ok, err := b.resolve(root)
		if err != nil {
			return nil, err
		}
		if !ok || b.noWriteGrant(t) {
			continue
		}
		if err := b.walkWrite(t, t, isDir, map[string]bool{}); err != nil {
			return nil, err
		}
	}
	return b.rules, nil
}

func (b *ruleBuilder) outerRoots(roots []string) []string {
	var unique []string
	for _, r := range roots {
		if !slices.Contains(unique, r) {
			unique = append(unique, r)
		}
	}
	var out []string
	for _, r := range unique {
		if !slices.ContainsFunc(unique, func(o string) bool { return o != r && b.covers(o, r) }) {
			out = append(out, r)
		}
	}
	return out
}

func (b *ruleBuilder) covers(outer, inner string) bool {
	if !within(inner, outer) {
		return false
	}
	if !coveredBy(inner, b.shm) {
		return true
	}
	return slices.ContainsFunc(b.shm, func(s string) bool { return outer != s && within(outer, s) })
}

func (b *ruleBuilder) walkRead(dir string) error {
	if b.seen[dir] {
		return nil
	}
	b.seen[dir] = true
	entries, err := b.fs.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	b.add(dir, accessReadDir, true)
	for _, e := range entries {
		t, isDir, ok, err := b.entryTarget(dir, e)
		if err != nil {
			return err
		}
		if !ok || coveredBy(t, b.blocked) {
			continue
		}
		if containsAny(t, b.blocked) {
			if isDir {
				if err := b.walkRead(t); err != nil {
					return err
				}
			}
			continue
		}
		b.add(t, accessRead, isDir)
	}
	return nil
}

func (b *ruleBuilder) walkWrite(t, root string, isDir bool, seen map[string]bool) error {
	carve := append(append(append([]string{}, b.blocked...), b.noWrite...), b.shm...)
	if !isDir || !containsAny(t, carve) {
		b.add(t, accessRead|accessWrite, isDir)
		return nil
	}
	if seen[t] {
		return nil
	}
	seen[t] = true
	entries, err := b.fs.ReadDir(t)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		child, childDir, ok, err := b.entryTarget(t, e)
		if err != nil {
			return err
		}
		if !ok || !within(child, root) || b.noWriteGrant(child) {
			continue
		}
		if err := b.walkWrite(child, root, childDir, seen); err != nil {
			return err
		}
	}
	return nil
}

func (b *ruleBuilder) noWriteGrant(t string) bool {
	if coveredBy(t, b.blocked) || coveredBy(t, b.noWrite) {
		return true
	}
	for _, s := range b.shm {
		if t == s {
			return true
		}
	}
	return false
}

func (b *ruleBuilder) entryTarget(dir string, e fs.DirEntry) (string, bool, bool, error) {
	path := filepath.Join(dir, e.Name())
	if e.Type()&fs.ModeSymlink == 0 {
		return path, e.IsDir(), true, nil
	}
	return b.resolve(path)
}

func (b *ruleBuilder) resolve(path string) (string, bool, bool, error) {
	t, err := b.fs.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	info, err := b.fs.Stat(t)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	return t, info.IsDir(), true, nil
}

func (b *ruleBuilder) withResolved(paths []string) ([]string, error) {
	out := append([]string{}, paths...)
	for _, p := range paths {
		t, err := b.canonical(p)
		if err != nil {
			return nil, err
		}
		if t != p {
			out = append(out, t)
		}
	}
	return out, nil
}

func (b *ruleBuilder) canonical(p string) (string, error) {
	cur, rest, hops := "/", strings.Split(p, "/"), 0
	for len(rest) > 0 {
		part := rest[0]
		rest = rest[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, part)
		info, err := b.fs.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) {
			return filepath.Join(append([]string{next}, rest...)...), nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if hops++; hops > 40 {
			return "", &fs.PathError{Op: "readlink", Path: p, Err: syscall.ELOOP}
		}
		target, err := b.fs.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return cur, nil
}

func (b *ruleBuilder) add(path string, access landlock.AccessFSSet, isDir bool) {
	if !isDir {
		access &= accessFileOnly
	}
	if i, ok := b.index[path]; ok {
		b.rules[i].Access |= access
		return
	}
	b.index[path] = len(b.rules)
	b.rules = append(b.rules, pathRule{Path: path, Access: access})
}

func within(path, base string) bool {
	return base == "/" || path == base || strings.HasPrefix(path, base+"/")
}

func coveredBy(path string, set []string) bool {
	for _, s := range set {
		if within(path, s) {
			return true
		}
	}
	return false
}

func containsAny(path string, set []string) bool {
	for _, s := range set {
		if s != path && within(s, path) {
			return true
		}
	}
	return false
}
