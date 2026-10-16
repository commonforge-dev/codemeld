// Boundary-aware upward VCS auto-detection: innermost-match selection across built-in and user detectors.
package vcs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/vcs/builtin"
)

// readDir is a package-local seam so tests can force unreadable-directory behavior deterministically.
var readDir = os.ReadDir

// readWalkAnchorOp is the OP_FAIL operation token used when the walk anchor itself cannot be listed.
const readWalkAnchorOp = "read-walk-anchor"

// AnchorReadError reports that the VCS auto-detection walk anchor (the launch CWD) could not be listed, so the
// walk never started. The caller renders it with the OP_FAIL template (operation read-walk-anchor) and exits
// before the TUI starts, rather than treating the anchor as a skippable unreadable directory.
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

// anchorReadError wraps a walk-anchor read failure with the OP_FAIL operation token and error category.
func anchorReadError(anchor string, err error) *AnchorReadError {
	return &AnchorReadError{
		Operation: readWalkAnchorOp,
		Anchor:    anchor,
		Category:  fserrors.CategorizeErrno(err),
		Err:       err,
	}
}

// detector pairs an eligible VCS name with the marker probed during auto-detection.
type detector struct {
	name   string
	marker string
}

// AutoDetect walks upward from cwd, bounded by boundary, and returns the VCS names whose markers
// succeed at the innermost level. matches holds every name that matched at that level so
// the caller can tie-break; depth is 0 for cwd and increases by one per parent level, and is
// -1 when no marker is found anywhere within the boundary. warnings carries one collapsed line per
// skipped unreadable non-anchor directory for the caller to print; AutoDetect never writes to
// stderr. An unreadable walk anchor (the cwd itself) is not a skippable directory: AutoDetect returns a
// *AnchorReadError before probing for matches or walking to parents, so the caller can render the
// OP_FAIL walk-anchor failure and exit before the TUI starts.
//
// boundary is "launch-dir-only" (probe cwd only, projectRoot ignored) or "project-root" (walk from
// cwd up through projectRoot inclusive). Any other boundary value, or a cwd that is not within
// projectRoot in project-root mode, returns an error without reporting a match. Detection is a pure
// filesystem marker probe and never shells out, so a matched VCS's binary need not be installed; a
// missing binary surfaces only on first action invocation.
func AutoDetect(cwd string, boundary string, projectRoot string, templates map[string]*Template) (matches []string, depth int, warnings []string, err error) {
	anchor := absClean(cwd)
	detectors := eligibleDetectors(templates)

	switch boundary {
	case "launch-dir-only":
		names, readErr := probeLevel(anchor, detectors)
		if readErr != nil {
			// The sole probed level is the walk anchor; an unreadable anchor fails before the walk.
			return nil, -1, nil, anchorReadError(anchor, readErr)
		}
		if len(names) > 0 {
			return names, 0, nil, nil
		}
		return nil, -1, nil, nil
	case "project-root":
		// fall through to the upward walk below.
	default:
		return nil, -1, nil, fmt.Errorf("unsupported VCS auto-detect boundary %q", boundary)
	}

	root := absClean(projectRoot)
	if !withinOrEqual(root, anchor) {
		// Outside the project root: error rather than walking to the filesystem root.
		return nil, -1, nil, fmt.Errorf("cwd %q is not within project root %q", anchor, root)
	}

	dir := anchor
	for level := 0; ; level++ {
		names, readErr := probeLevel(dir, detectors)
		if readErr != nil {
			if level == 0 {
				// Walk anchor unreadable: do not start the upward walk and do not select an ancestor
				// marker; surface an OP_FAIL-style failure so the caller can exit before the TUI.
				return nil, -1, nil, anchorReadError(dir, readErr)
			}
			warnings = append(warnings, walkWarning(dir, readErr))
		} else if len(names) > 0 {
			return names, level, warnings, nil
		}
		if dir == root {
			// Probed the project root inclusively with no match; stop without walking higher.
			return nil, -1, warnings, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Defensive: containment was checked above, so the walk should always reach root first.
			return nil, -1, warnings, nil
		}
		dir = parent
	}
}

// withinOrEqual reports whether target is root itself or a descendant of root; both must be absolute,
// cleaned paths. It uses filepath.Rel so the check is lexical and never touches the filesystem.
func withinOrEqual(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// eligibleDetectors builds the ordered detector set for one walk: every built-in (in canonical order,
// using the built-in marker) followed by user-defined templates whose name is not a built-in, sorted
// by name. A user template named after a built-in is an override: the built-in detect marker
// is used during auto-detection, so the override adds no second detector and the name is returned once.
func eligibleDetectors(templates map[string]*Template) []detector {
	builtinNames := builtin.BuiltinNames()
	dets := make([]detector, 0, len(builtinNames)+len(templates))
	for _, name := range builtinNames {
		dets = append(dets, detector{name: name, marker: builtinMarkers[name]})
	}

	custom := make([]string, 0, len(templates))
	for name, tmpl := range templates {
		if slices.Contains(builtinNames, name) {
			continue // built-in-name override: built-in detect is authoritative.
		}
		if tmpl == nil || tmpl.Detect == nil {
			continue // no marker to probe (a non-built-in template without detect cannot participate).
		}
		custom = append(custom, name)
	}
	sort.Strings(custom)
	for _, name := range custom {
		dets = append(dets, detector{name: name, marker: templates[name].Detect.Marker})
	}
	return dets
}

// probeLevel runs every detector against a single directory and returns the names that matched, in
// detector order. An unreadable directory yields no matches and the underlying read error; the
// caller decides whether that is a skippable non-anchor directory (warn and continue) or a fatal
// walk-anchor failure. A readable directory returns a nil error.
func probeLevel(dir string, detectors []detector) (names []string, readErr error) {
	if _, err := readDir(dir); err != nil {
		return nil, err
	}
	for _, d := range detectors {
		// Markers come from validated templates and the built-in table, so DetectInDir's only
		// failure here is an unexpected filesystem error on a specific entry; treat it as no match.
		if ok, derr := DetectInDir(dir, d.marker); derr == nil && ok {
			names = append(names, d.name)
		}
	}
	return names, nil
}

// absClean normalizes a path to an absolute, cleaned form, falling back to a plain clean if the
// working directory cannot be resolved, mirroring config.LocateProjectRoot's anchor handling.
func absClean(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// walkWarning builds the one-line warning naming a skipped unreadable directory and its OS error code;
// the caller prints it. It mirrors the discovery walk's warning shape so both walks read alike.
func walkWarning(dir string, err error) string {
	code := err.Error()
	var errno syscall.Errno
	if errors.As(err, &errno) {
		code = fmt.Sprintf("errno %d (%s)", int(errno), errno.Error())
	}
	return fserrors.CollapseControls(
		fmt.Sprintf("codemeld: skipping unreadable directory %s: %s", dir, code))
}
