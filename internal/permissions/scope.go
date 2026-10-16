// Path-scope cleaning/resolution, descendant matching, and request path-scope derivation.
package permissions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/paths"
)

// subjectKindTool is the discriminator for structured-tool subjects.
// Kept as a local literal until a shared subject-kind constant exists.
const subjectKindTool = "tool"

// allPathsScope is the distinguished all-paths value carried only by stored
// global grants. A request's resolved path is always concrete, so it
// must never take this value ('s permission_* payload note).
const allPathsScope = "*"

// CleanAbsResolve normalizes path into a cleaned, absolute, symlink-resolved
// directory path. It expands a leading ~ against home, resolves a
// relative path against baseDir, follows symlinks via filepath.EvalSymlinks,
// and requires the resolved target to be an existing directory. EvalSymlinks
// requires the path to exist, so a missing target is an error here — correct
// for a folder-grant anchor, which must name a real directory.
func CleanAbsResolve(home, baseDir, path string) (string, error) {
	expanded, err := paths.Expand(home, path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(baseDir, expanded)
	}
	resolved, err := filepath.EvalSymlinks(expanded)
	if err != nil {
		return "", fmt.Errorf("permissions: resolve path scope %q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("permissions: stat path scope %q: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("permissions: path scope %q is not a directory", resolved)
	}
	return filepath.Clean(resolved), nil
}

// IsDescendantOrEqual reports whether path equals scope or lies strictly within
// it. A grant authorizes its scope and every descendant, never an
// ancestor or a sibling. Both arguments are expected to be cleaned absolute
// paths; the relative-path computation makes the check boundary-safe so that
// scope "/a/foo" does not match the sibling "/a/foobar".
func IsDescendantOrEqual(path, scope string) bool {
	cleanPath := filepath.Clean(path)
	cleanScope := filepath.Clean(scope)
	if cleanPath == cleanScope {
		return true
	}
	rel, err := filepath.Rel(cleanScope, cleanPath)
	if err != nil {
		return false
	}
	// A rel of ".." (the ancestor) or one starting with "../" (a sibling or any
	// path that escapes scope) means path is not contained by scope.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// ScopeEscalation is a display-only signal computed on the prompt path. When
// NarrowerScope is non-empty, the request's path scope is strictly broader than (an
// ancestor of) a folder the user already approved for this same subject, and
// NarrowerScope names that narrowest already-approved folder. The prompt uses it to
// warn that the request broadens an existing grant; it changes nothing about
// matching, caching, or persistence. The zero value (empty NarrowerScope) means the
// request is not a scope escalation.
type ScopeEscalation struct {
	NarrowerScope string
}

// FindScopeEscalation reports whether req's path scope is a strict ancestor of an
// already-approved, same-subject grant — i.e. the request is broader than, and
// contains, a folder the user already allowed for the same kind and subject. It scans
// grants for a non-global grant whose kind and subject match req by the same rules
// Match uses (so a stored direct ":*" program scope or a tool capability still
// matches, not just a raw-string-equal subject), and whose path scope is a strict
// descendant of req's path scope. NarrowerScope is the narrowest (deepest) such
// already-approved scope, or empty when req broadens no same-subject grant.
//
// It is display-only: the caller passes the result to the prompt purely to make the
// broadening salient — it reads grants but changes no matching, cache, or persistence.
// Global grants are skipped: a global grant would have matched req outright (so the
// prompt is never reached), and "*" is not a narrower folder.
func FindScopeEscalation(req MatchRequest, grants []PermissionEntry) ScopeEscalation {
	narrowest := ""
	for i := range grants {
		grant := grants[i]
		if grant.GrantKind == grantKindGlobal {
			continue
		}
		if grant.Kind != req.Kind || !subjectMatches(req, grant) {
			continue
		}
		// The request must be a STRICT ancestor of the grant scope: the grant scope is
		// contained by the request scope and the two differ. An equal or descendant
		// request scope is not an escalation — it would have matched the grant outright
		// and never reached the prompt.
		if grant.PathScope == req.PathScope || !IsDescendantOrEqual(grant.PathScope, req.PathScope) {
			continue
		}
		if narrowest == "" || IsDeeperScope(grant.PathScope, narrowest) {
			narrowest = grant.PathScope
		}
	}
	return ScopeEscalation{NarrowerScope: narrowest}
}

func IsDeeperScope(candidate, current string) bool {
	if cd, cur := scopeDepth(candidate), scopeDepth(current); cd != cur {
		return cd > cur
	}
	if len(candidate) != len(current) {
		return len(candidate) > len(current)
	}
	return candidate < current
}

// scopeDepth counts the path separators in a cleaned scope, a proxy for how deep the
// folder sits so a descendant scope outranks its ancestor.
func scopeDepth(scope string) int {
	return strings.Count(filepath.Clean(scope), string(filepath.Separator))
}

// DerivePathScope resolves the path scope of a request being approved, by this
// precedence: a non-empty cdHint (the cd <path> && prefix) wins, otherwise a
// structured-tool subject anchors on toolCwd, and otherwise the codemeld process
// CWD is used. The selected raw path is resolved; relative cd hints and a
// relative toolCwd resolve against
// processCWD. The result is always a concrete directory and never the all-paths
// sentinel "*", which is reserved for stored global grants.
func DerivePathScope(home, cdHint, processCWD, toolCwd, subjectKind string) (string, error) {
	var raw string
	switch {
	case cdHint != "":
		raw = cdHint
	case subjectKind == subjectKindTool:
		raw = toolCwd
	default:
		raw = processCWD
	}
	if raw == allPathsScope {
		return "", fmt.Errorf("permissions: path scope %q is reserved for global grants and cannot be a request scope", allPathsScope)
	}
	return CleanAbsResolve(home, processCWD, raw)
}
