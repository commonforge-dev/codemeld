// Package paths resolves the user's home directory and expands ~-prefixed paths against it.
package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
)

var (
	errHomeUnset   = errors.New("$HOME unset")
	errHomeMissing = errors.New("$HOME points to a path that does not exist")
)

// currentUser is the package-local seam tests use to force os/user.Current outcomes.
var currentUser = user.Current

// ResolveHome returns the user's home directory, preferring $HOME and falling back to os/user.
func ResolveHome() (string, error) {
	home, ok := os.LookupEnv("HOME")
	if ok && home != "" {
		if _, err := os.Stat(home); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", errHomeMissing
			}
			return "", err
		}
		return home, nil
	}

	u, err := currentUser()
	if err != nil {
		return "", fmt.Errorf("os/user lookup failed: %w", err)
	}
	if u.HomeDir == "" {
		return "", errHomeUnset
	}
	return u.HomeDir, nil
}

// FormatHomeError maps ResolveHome's errors to their user-facing reason strings.
func FormatHomeError(err error) string {
	switch {
	case errors.Is(err, errHomeUnset):
		return "$HOME unset"
	case errors.Is(err, errHomeMissing):
		return "$HOME points to a path that does not exist"
	}
	return err.Error()
}

// Expand joins ~-prefixed paths against home and rejects ~user forms.
func Expand(home, path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}
	if path == "~" {
		return home, nil
	}
	if path[1] == '/' {
		rest := path[2:]
		if rest == "" {
			return home, nil
		}
		return filepath.Join(home, rest), nil
	}
	return "", fmt.Errorf("paths: ~user form not supported: %q", path)
}
