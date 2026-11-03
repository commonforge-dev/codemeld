//go:build !linux

package bootstrap

import "errors"

type sessionTempDir struct {
	path string
}

var errSessionTempDirUnsupported = errors.New("bootstrap: private temp folders are created only on linux")

func newSessionTempDir() (*sessionTempDir, error) {
	return nil, errSessionTempDirUnsupported
}

func (d *sessionTempDir) identity() (dev, ino uint64, err error) {
	return 0, 0, errSessionTempDirUnsupported
}

func (d *sessionTempDir) remove() error {
	return errSessionTempDirUnsupported
}

func (d *sessionTempDir) close() {}

func removeStaleSessionTempDirs() error {
	return errSessionTempDirUnsupported
}
