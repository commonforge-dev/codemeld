// First-run materialization of the built-in VCS templates into ~/.codemeld/global/vcs/.
package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/vcs/builtin"
)

// VCSTemplateDir returns ~/.codemeld/global/vcs, the directory built-in VCS
// templates are materialized into.
func VCSTemplateDir(home string) string {
	return filepath.Join(home, ".codemeld", "global", "vcs")
}

// VCSTemplatePath returns the on-disk path for the built-in template named name
// (e.g. "git" -> ~/.codemeld/global/vcs/git.yaml).
func VCSTemplatePath(home, name string) string {
	return filepath.Join(VCSTemplateDir(home), name+".yaml")
}

var (
	isEarlierBuiltin = builtin.IsEarlierVersion
	writeAtomic      = fsutil.WriteAtomic
)

// MaterializeBuiltinTemplates writes each built-in template that is not already
// present under ~/.codemeld/global/vcs/, at mode 0644, and replaces an existing
// regular file that is byte-identical to an earlier release of that template.
// Every other existing file is preserved; since WriteAtomic overwrites,
// existence is checked first. On the first failure it returns the target path,
// category, and error and stops; templates written before the failure are left
// in place.
func MaterializeBuiltinTemplates(home string) (failedPath string, cat fserrors.Category, err error) {
	return syncBuiltinTemplates(home, true)
}

func syncBuiltinTemplates(home string, create bool) (failedPath string, cat fserrors.Category, err error) {
	for _, name := range builtin.BuiltinNames() {
		target := VCSTemplatePath(home, name)

		switch _, statErr := os.Stat(target); {
		case statErr == nil:
			info, lerr := os.Lstat(target)
			if lerr != nil {
				return target, fserrors.CategorizeErrno(lerr), lerr
			}
			if !info.Mode().IsRegular() {
				continue
			}
			existing, rerr := os.ReadFile(target)
			if rerr != nil {
				return target, fserrors.CategorizeErrno(rerr), rerr
			}
			if !isEarlierBuiltin(name, existing) {
				continue
			}
		case errors.Is(statErr, fs.ErrNotExist):
			if !create {
				continue
			}
		default:
			return target, fserrors.CategorizeErrno(statErr), statErr
		}

		data, ok := builtin.BuiltinTemplate(name)
		if !ok {
			e := fmt.Errorf("builtin template %q not found", name)
			return target, fserrors.IOError, e
		}
		if _, c, e := writeAtomic(target, data, 0o644); e != nil {
			return target, c, e
		}
	}
	return "", "", nil
}

// RunMaterializeBuiltinTemplates materializes the built-in templates, mapping
// any failure to the OP_FAIL stderr line with operation "write-vcs-template"
// and exit code 1.
func RunMaterializeBuiltinTemplates(home string, stderr io.Writer) int {
	path, cat, err := MaterializeBuiltinTemplates(home)
	if err != nil {
		fmt.Fprintln(stderr, fserrors.FormatOpFail("write-vcs-template", path, cat))
		return 1
	}
	return 0
}
