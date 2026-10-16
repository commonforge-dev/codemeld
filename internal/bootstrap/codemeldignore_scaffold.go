// First-run (global) and project-open scaffolding of the commented codemeldignore starter templates:
// both writes create the file only when absent and never overwrite an existing one.
package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

// codemeldignoreScaffoldOp is the operation token for the OP_FAIL line a scaffold-write failure prints.
const codemeldignoreScaffoldOp = "write-codemeldignore"

// codemeldignoreTemplate is the commented starter written to both the global and project codemeldignore
// files. Every line is a comment, so the scaffolded file matches nothing until a user uncomments a pattern;
// the examples show the file / root-only / `**/`-anywhere forms.
const codemeldignoreTemplate = `# codemeld ignore file. Patterns here exclude paths from the read-only navigation
# tools (glob, grep, list, tree) by default. Pass include_ignored to a tool to
# bypass this filter for a single call.
#
# Syntax: one doublestar glob per line. Blank lines and lines starting with # are
# ignored. There is no negation, and the project and global files apply as a union.
#
# Matching is literal against each entry's project-root-relative, slash-separated
# path:
#   - a slash-less name matches only at the project root;
#   - use a leading **/ to match a name at any depth;
#   - a matched directory and its whole subtree are skipped.
#
# Examples (uncomment and edit to use):
# build/output.log     # that exact file at the project root
# node_modules         # only the root-level node_modules directory
# **/__pycache__       # a __pycache__ directory at any depth (its subtree skipped)
# **/*.log             # every .log file at any depth
`

// scaffoldCodemeldignore writes the commented template to path at mode 0644 only when path is absent,
// preserving any existing file so the operation is idempotent and never clobbers a user's patterns. The
// parent directory must already exist. It returns the failing category and error on a stat or write failure.
func scaffoldCodemeldignore(path string) (fserrors.Category, error) {
	switch _, statErr := os.Stat(path); {
	case statErr == nil:
		return "", nil // preserve existing file
	case errors.Is(statErr, fs.ErrNotExist):
		// absent: fall through to write
	default:
		return fserrors.CategorizeErrno(statErr), statErr
	}
	if _, cat, err := fsutil.WriteAtomic(path, []byte(codemeldignoreTemplate), 0o644); err != nil {
		return cat, err
	}
	return "", nil
}

// RunScaffoldGlobalCodemeldignore writes the commented ~/.codemeld/global/codemeldignore on first run,
// alongside the other first-run files. The parent ~/.codemeld/global directory is created by
// EnsureFirstRunDirs earlier in first-run generation. A failure maps to the OP_FAIL stderr line and exit
// code 1, mirroring the other first-run write runners.
func RunScaffoldGlobalCodemeldignore(home string, stderr io.Writer) int {
	path := filetools.GlobalCodemeldignorePath(home)
	if cat, err := scaffoldCodemeldignore(path); err != nil {
		_, _ = fmt.Fprintln(stderr, fserrors.FormatOpFail(codemeldignoreScaffoldOp, path, cat))
		return 1
	}
	return 0
}

// ScaffoldProjectCodemeldignore ensures <project-root>/.codemeld exists and writes a commented
// <project-root>/.codemeld/codemeldignore when absent, never overwriting an existing file. It is the
// project bootstrap step that runs after project-root resolution and before config/VCS/tool setup, on both
// fresh and cold-start resume launches. It is best-effort: an empty projectRoot is a no-op, and a directory
// or write failure is reported to stderr and swallowed so an optional template can never block a launch in a
// read-only project. The returned error is therefore always nil; the type matches the injected bootstrap
// step contract so the step can be faked in tests.
func ScaffoldProjectCodemeldignore(projectRoot string, stderr io.Writer) error {
	if projectRoot == "" {
		return nil
	}
	path := filetools.ProjectCodemeldignorePath(projectRoot)
	if _, cat, err := fsutil.EnsureDir(filepath.Dir(path)); err != nil {
		noticeCodemeldignoreScaffoldFailure(stderr, filepath.Dir(path), cat)
		return nil
	}
	if cat, err := scaffoldCodemeldignore(path); err != nil {
		noticeCodemeldignoreScaffoldFailure(stderr, path, cat)
	}
	return nil
}

// noticeCodemeldignoreScaffoldFailure prints the OP_FAIL line for a best-effort project-scaffold failure
// without aborting the launch.
func noticeCodemeldignoreScaffoldFailure(stderr io.Writer, path string, cat fserrors.Category) {
	if stderr == nil {
		return
	}
	_, _ = fmt.Fprintln(stderr, fserrors.FormatOpFail(codemeldignoreScaffoldOp, path, cat))
}
