// Locates the project root by walking upward for the innermost .codemeld/settings.yaml marker.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"codemeld.dev/codemeld/internal/fserrors"
)

// readWalkAnchorOp is the OP_FAIL operation token used when the walk anchor itself cannot be listed.
const readWalkAnchorOp = "read-walk-anchor"

// markerRelPath is the per-project settings marker relative to a candidate directory.
var markerRelPath = filepath.Join(".codemeld", "settings.yaml")

// readDir is a package-local seam so tests can force unreadable-directory behavior deterministically.
var readDir = os.ReadDir

// statMarker is a package-local seam so tests can force unreadable-marker behavior deterministically.
var statMarker = os.Stat

// userHomeDir is a package-local seam so the home-directory carve-out can be tested independently of the real home.
var userHomeDir = os.UserHomeDir

// AnchorReadError reports that the walk anchor (the launch CWD) could not be listed, so the upward walk never started.
type AnchorReadError struct {
	Operation string
	Anchor    string
	Category  fserrors.Category
	Err       error
}

func (e *AnchorReadError) Error() string {
	return fmt.Sprintf("%s: %s: %s: %v", e.Operation, e.Anchor, e.Category, e.Err)
}

func (e *AnchorReadError) Unwrap() error { return e.Err }

// LocateProjectRoot resolves the project root for the given discovery boundary
// mode. cwd is the launch directory (the walk anchor), normalized to an absolute
// cleaned path; layers holds the discovered .codemeld/settings.yaml path (at most
// one). In project-root mode the walk skips non-anchor unreadable directories with
// a warning and stops at the innermost ancestor with a marker, falling back to the
// anchor if none match; an unreadable anchor yields a *AnchorReadError. Discovery
// is read-only.
func LocateProjectRoot(cwd string, mode string) (root string, layers []string, warnings []string, err error) {
	anchor, aerr := filepath.Abs(cwd)
	if aerr != nil {
		anchor = filepath.Clean(cwd)
	}
	anchor = canonicalPath(anchor)

	switch mode {
	case "launch-dir-only":
		marker := filepath.Join(anchor, markerRelPath)
		if isMarkerFile(marker) {
			return anchor, []string{marker}, nil, nil
		}
		return anchor, nil, nil, nil
	case "project-root":
	default:
		return anchor, nil, nil, fmt.Errorf("unsupported discovery boundary mode %q", mode)
	}

	// project-root: walk upward from the anchor to the filesystem root.
	home := ""
	if h, herr := userHomeDir(); herr == nil {
		home = canonicalPath(filepath.Clean(h))
	}

	dir := anchor
	for {
		if _, rerr := readDir(dir); rerr != nil {
			if dir == anchor {
				return anchor, nil, nil, &AnchorReadError{
					Operation: readWalkAnchorOp,
					Anchor:    anchor,
					Category:  fserrors.CategorizeErrno(rerr),
					Err:       rerr,
				}
			}
			warnings = append(warnings, walkWarning(dir, rerr))
		} else if home == "" || dir != home {
			// Never match the home directory: ~/.codemeld/ holds global state, not a
			// project marker, even if a stray ~/.codemeld/settings.yaml exists.
			marker := filepath.Join(dir, markerRelPath)
			if isMarkerFile(marker) {
				return dir, []string{marker}, warnings, nil
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return anchor, nil, warnings, nil
}

func canonicalPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// isMarkerFile reports whether path is a candidate marker. Only an absent one is skipped: a
// candidate that cannot be statted, or whose resolved target is not a regular file, still
// stops the walk. Skipping it would hand back some other project root, and the trust gate
// would then inspect that unrelated root's covered content — reporting no settings to
// withhold — instead of failing closed on the candidate it could not classify.
func isMarkerFile(path string) bool {
	_, err := statMarker(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// walkWarning builds the one-line stderr warning naming a skipped unreadable directory and its OS error code; the caller prints it.
func walkWarning(dir string, err error) string {
	code := err.Error()
	var errno syscall.Errno
	if errors.As(err, &errno) {
		code = fmt.Sprintf("errno %d (%s)", int(errno), errno.Error())
	}
	return fserrors.CollapseControls(
		fmt.Sprintf("codemeld: skipping unreadable directory %s: %s", dir, code))
}
