// First-run creation of the ~/.codemeld directory tree.
package bootstrap

import (
	"fmt"
	"io"
	"path/filepath"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

// FirstRunDirs returns the three first-run target directories in creation
// order. Order is load-bearing: each entry is the parent of the next.
func FirstRunDirs(home string) []string {
	root := filepath.Join(home, ".codemeld")
	global := filepath.Join(root, "global")
	vcs := filepath.Join(global, "vcs")
	return []string{root, global, vcs}
}

// EnsureFirstRunDirs creates each FirstRunDirs target in order, stopping at the
// first failure and returning its path, category, and error. Directories
// created before a failure are left in place.
func EnsureFirstRunDirs(home string) (failedPath string, cat fserrors.Category, err error) {
	for _, dir := range FirstRunDirs(home) {
		if _, c, e := fsutil.EnsureDir(dir); e != nil {
			return dir, c, e
		}
	}
	return "", "", nil
}

// RunEnsureFirstRunDirs creates the first-run directories, mapping any failure
// to the OP_FAIL stderr line with operation "create-dir" and exit code 1.
func RunEnsureFirstRunDirs(home string, stderr io.Writer) int {
	path, cat, err := EnsureFirstRunDirs(home)
	if err != nil {
		fmt.Fprintln(stderr, fserrors.FormatOpFail("create-dir", path, cat))
		return 1
	}
	return 0
}
