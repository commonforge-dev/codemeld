// Hard override vcs.preferred: cross-reference validation and single-detector upward walk.
package vcs

import (
	"fmt"
	"path/filepath"
	"slices"
)

// ValidatePreferred cross-reference-checks an effective vcs.preferred value against the loaded-template
// name set. An unset or empty value disables the override and returns nil. The accepted set is
// the union of the built-in names (always, regardless of filesystem-resident reference copies) and the
// user-defined template names that loaded successfully. An unrecognized value yields a
// schema-validation-shaped load-time error naming sourceFile, the vcs.preferred key, and the offending
// value, so the caller renders it the same way it renders settings schema-validation failures and exits
// before the TUI.
func ValidatePreferred(name string, builtins []string, userTemplates []string, sourceFile string) error {
	if name == "" {
		return nil
	}
	if slices.Contains(builtins, name) || slices.Contains(userTemplates, name) {
		return nil
	}
	return fmt.Errorf("%s: schema validation failed at vcs.preferred: unknown VCS template name %q", sourceFile, name)
}

// RunPreferred performs the hard-override detection walk for an effective vcs.preferred value:
// only the named VCS's detect marker is probed up the tree, skipping vcs.priority tie-breaking entirely.
// It mirrors AutoDetect's boundary semantics — "launch-dir-only" probes only cwd; "project-root" walks
// from cwd through projectRoot inclusive and rejects a cwd outside projectRoot; any other boundary errors
// before walking; an unreadable walk anchor is fatal (returns *AnchorReadError) while unreadable
// non-anchor directories are skipped. The innermost directory whose marker matches is returned as the
// active VCS template's repo root. When the marker matches nowhere on the walk, it returns the prescribed
// detect-fails-everywhere error naming sourceFile so the caller can exit.
//
// Built-in names probe builtinDetect[name] even when templates carries a built-in-name override, matching
// the auto-detect contract; non-built-in names probe templates[name].Detect.Marker.
func RunPreferred(name string, cwd string, boundary string, projectRoot string, sourceFile string, builtinDetect map[string]string, templates map[string]*Template) (matchedDir string, err error) {
	marker, err := preferredMarker(name, builtinDetect, templates)
	if err != nil {
		return "", err
	}
	det := []detector{{name: name, marker: marker}}
	anchor := absClean(cwd)

	switch boundary {
	case "launch-dir-only":
		names, readErr := probeLevel(anchor, det)
		if readErr != nil {
			// The sole probed level is the walk anchor; an unreadable anchor is fatal.
			return "", anchorReadError(anchor, readErr)
		}
		if len(names) > 0 {
			return anchor, nil
		}
		return "", noPreferredMatchError(name, sourceFile)
	case "project-root":
		// fall through to the upward walk below.
	default:
		return "", fmt.Errorf("unsupported VCS auto-detect boundary %q", boundary)
	}

	root := absClean(projectRoot)
	if !withinOrEqual(root, anchor) {
		// Outside the project root: error rather than walking to the filesystem root.
		return "", fmt.Errorf("cwd %q is not within project root %q", anchor, root)
	}

	dir := anchor
	for level := 0; ; level++ {
		names, readErr := probeLevel(dir, det)
		if readErr != nil {
			if level == 0 {
				// Walk anchor unreadable: do not start the upward walk.
				return "", anchorReadError(dir, readErr)
			}
			// Skip an unreadable non-anchor directory and keep walking, as AutoDetect does.
		} else if len(names) > 0 {
			return dir, nil
		}
		if dir == root {
			// Probed the project root inclusively with no match; stop without walking higher.
			return "", noPreferredMatchError(name, sourceFile)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Defensive: containment was checked above, so the walk should always reach root first.
			return "", noPreferredMatchError(name, sourceFile)
		}
		dir = parent
	}
}

// preferredMarker resolves the single marker to probe for name. Built-in names take the built-in detect
// marker even when a user template overrides the action set; a non-built-in name takes its
// loaded template's detect marker. A name that is neither is a caller contract violation (ValidatePreferred
// should run first), reported as an error rather than silently probing nothing.
func preferredMarker(name string, builtinDetect map[string]string, templates map[string]*Template) (string, error) {
	if marker, ok := builtinDetect[name]; ok {
		return marker, nil
	}
	if tmpl, ok := templates[name]; ok && tmpl != nil && tmpl.Detect != nil {
		return tmpl.Detect.Marker, nil
	}
	return "", fmt.Errorf("vcs.preferred %q has no detect marker (not a built-in and no loaded template detect)", name)
}

// noPreferredMatchError builds the detect-fails-everywhere error: it names the override value and
// the settings file that set it, and lists the three remedies the user has.
func noPreferredMatchError(name, sourceFile string) error {
	return fmt.Errorf("codemeld: vcs.preferred '%s' (from %s): no matching repo found; remove the override, change it, or launch in a directory where the named VCS is present", name, sourceFile)
}
