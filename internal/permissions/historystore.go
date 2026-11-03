package permissions

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func HistoryStores(root string) ([]string, error) {
	git, err := gitStores(filepath.Join(root, ".git"))
	if err != nil {
		return nil, err
	}
	hg, err := hgStores(filepath.Join(root, ".hg"))
	if err != nil {
		return nil, err
	}
	return append(git, hg...), nil
}

func gitStores(marker string) ([]string, error) {
	out, resolved, info, err := lstatMarker(marker)
	if err != nil || info == nil {
		return nil, err
	}
	if info.IsDir() {
		return optionalStore(append(out, resolved), resolved, "commondir")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("permissions: %s is neither a file nor a folder", marker)
	}
	out = append(out, resolved)
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("permissions: read %s: %w", marker, err)
	}
	target, ok := strings.CutPrefix(strings.TrimRight(string(b), "\r\n"), "gitdir: ")
	if !ok || target == "" {
		return nil, fmt.Errorf("permissions: %s does not name a gitdir", marker)
	}
	gitdir, err := storeDir(filepath.Dir(marker), target, marker)
	if err != nil {
		return nil, err
	}
	out = append(out, gitdir...)
	return optionalStore(out, gitdir[len(gitdir)-1], "commondir")
}

func hgStores(marker string) ([]string, error) {
	out, resolved, info, err := lstatMarker(marker)
	if err != nil || info == nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("permissions: %s is not a folder", marker)
	}
	return optionalStore(append(out, resolved), resolved, "sharedpath")
}

func optionalStore(out []string, dir, name string) ([]string, error) {
	pointer := filepath.Join(dir, name)
	marker, resolved, info, err := lstatMarker(pointer)
	if err != nil || info == nil {
		return out, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("permissions: %s is not a regular file", pointer)
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("permissions: read %s: %w", pointer, err)
	}
	store, err := storeDir(dir, strings.TrimRight(string(b), "\r\n"), pointer)
	if err != nil {
		return nil, err
	}
	if len(marker) > 0 {
		out = append(append(out, marker...), resolved)
	}
	return append(out, store...), nil
}

func lstatMarker(marker string) (links []string, resolved string, info fs.FileInfo, err error) {
	if _, err := os.Lstat(marker); errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil, nil
	} else if err != nil {
		return nil, "", nil, fmt.Errorf("permissions: inspect %s: %w", marker, err)
	}
	if resolved, links, err = resolveSelectors(marker); err != nil {
		return nil, "", nil, fmt.Errorf("permissions: resolve %s: %w", marker, err)
	}
	if info, err = os.Stat(resolved); err != nil {
		return nil, "", nil, fmt.Errorf("permissions: inspect %s: %w", marker, err)
	}
	return links, resolved, info, nil
}

// storeDir returns every symlink followed on the way to the store, then the store: replacing any
// of those links would select a different store.
func storeDir(base, target, source string) ([]string, error) {
	if target == "" {
		return nil, fmt.Errorf("permissions: %s is empty", source)
	}
	if !filepath.IsAbs(target) {
		target = base + "/" + target
	}
	resolved, links, err := resolveSelectors(target)
	if err != nil {
		return nil, fmt.Errorf("permissions: %s names %s: %w", source, target, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("permissions: %s names %s: %w", source, target, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("permissions: %s names %s, which is not a folder", source, target)
	}
	return append(links, resolved), nil
}

// resolveSelectors walks path in filesystem order: a ".." after a symlink leaves the link's target,
// not the link's lexical parent.
func resolveSelectors(path string) (string, []string, error) {
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", nil, err
		}
		path = wd + "/" + path
	}
	cur, rest, hops := "/", strings.Split(path, "/"), 0
	var links []string
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
		info, err := os.Lstat(next)
		if err != nil {
			return "", nil, err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			if !info.IsDir() && len(rest) > 0 {
				return "", nil, &fs.PathError{Op: "lstat", Path: next, Err: syscall.ENOTDIR}
			}
			cur = next
			continue
		}
		if hops++; hops > 40 {
			return "", nil, &fs.PathError{Op: "readlink", Path: path, Err: syscall.ELOOP}
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", nil, err
		}
		links = append(links, next)
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return cur, links, nil
}
