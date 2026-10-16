package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const sessionTempDirPrefix = "codemeld-confine-"

func newSessionTempDir() (string, error) {
	dir, err := os.MkdirTemp("", fmt.Sprintf("%s%d-*", sessionTempDirPrefix, os.Getpid()))
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func removeSessionTempDir(path string) error {
	if os.RemoveAll(path) == nil {
		return nil
	}
	if info, err := os.Lstat(path); err != nil || !info.IsDir() {
		return os.RemoveAll(path)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	restoreOwnerAccess(root, ".")
	_ = root.Close()
	return os.RemoveAll(path)
}

func restoreOwnerAccess(root *os.Root, name string) {
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() {
		return
	}
	_ = root.Chmod(name, info.Mode().Perm()|0o700)
	dir, err := root.Open(name)
	if err != nil {
		return
	}
	names, _ := dir.Readdirnames(-1)
	_ = dir.Close()
	for _, child := range names {
		restoreOwnerAccess(root, filepath.Join(name, child))
	}
}

func removeStaleSessionTempDirs() error {
	dir := os.TempDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var errs []error
	for _, entry := range entries {
		pid, ok := sessionTempDirPID(entry.Name())
		if !ok || pid == os.Getpid() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			continue
		}
		if processGone(pid) {
			errs = append(errs, removeSessionTempDir(path))
		}
	}
	return errors.Join(errs...)
}

func sessionTempDirPID(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, sessionTempDirPrefix)
	if !ok {
		return 0, false
	}
	digits, suffix, ok := strings.Cut(rest, "-")
	if !ok || suffix == "" {
		return 0, false
	}
	pid, err := strconv.ParseInt(digits, 10, 32)
	if err != nil || pid <= 0 || strconv.FormatInt(pid, 10) != digits {
		return 0, false
	}
	return int(pid), true
}

func processGone(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	defer func() { _ = proc.Release() }()
	return signalMeansGone(proc.Signal(syscall.Signal(0)))
}

func signalMeansGone(err error) bool {
	return errors.Is(err, os.ErrProcessDone)
}
