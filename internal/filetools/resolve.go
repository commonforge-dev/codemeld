// Shared file-target resolution and argument helpers for the structured file tools: parent resolution
// via the permission path-scope rules, basename anchoring, and project-root containment. The edit and
// create tools parameterize it by their target precondition; the read-only navigation
// tools share the same parent-resolution/containment step through ResolveReadTarget in readresolve.go.
package filetools

import (
	"fmt"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// TargetError reports that a file tool's target path could not be resolved to a safe target.
// It is the fail-closed result of the structural conditions — no safe parent directory, the unsupported
// ~user form — plus each tool's own precondition (edit: missing/directory/non-regular target; create: an
// already-existing target or a basename that escapes its resolved parent; the read-only tools: an
// out-of-root path, a symlink escape, or an unresolvable type). For the mutating edit/create tools an
// out-of-root resolved *real* target is no longer a TargetError: it is a promptable case routed
// to the approval prompt, not a pre-authorization rejection, so only the structural failures above abort
// before authorization — and such a structural call is never authorized or executed (so never
// auto-approved). The read-only tools keep their unconditional root-confinement, so an out-of-root
// read target is still a TargetError before any content read (invariant unchanged). The production
// dispatcher surfaces it to the model in-band so the model can correct the path rather than aborting the
// turn. Kind names the rejecting tool ("edit", "create", "read", "grep", "glob", "list", "tree") so the
// model-facing message points at the right tool.
type TargetError struct {
	Kind   string
	Reason string
}

func (e *TargetError) Error() string {
	kind := e.Kind
	if kind == "" {
		kind = "file"
	}
	return kind + " target rejected: " + e.Reason
}

// targetPrecondition is the tool-specific check resolveFileTarget applies to the anchored candidate
// after the shared parent resolution pass: must-exist-regular for edit, must-not-exist for create. It
// receives the resolved (symlink-followed) parent directory and the candidate target anchored under it,
// and returns the final target path to authorize/invoke against, the path scope to authorize (the
// directory the write lands in), and a non-empty reason describing a *structural* rejection on failure.
// It deliberately does not receive the project root: out-of-root is no longer a precondition rejection
// for the mutating tools, so the in-root/out-of-root verdict is computed downstream from the
// returned scope (the tool's OutOfRootScope), never here.
type targetPrecondition func(parent string, candidate string) (target string, scope string, reason string)

// resolveFileTarget performs the pre-authorization target resolution shared by the edit and create
// tools. It validates a non-empty string `path`, resolves the parent directory with the
// permission path-scope rules (~ expansion, relative resolution against processCWD, symlink resolution,
// and an existing-directory requirement via permissions.CleanAbsResolve), and anchors the basename under
// that resolved parent. The tool's precondition then validates the candidate and returns the resolved
// target plus the path scope to authorize. A *structural* failure (no safe parent, ~user, or a
// precondition rejection) returns a *TargetError before authorization. An out-of-root resolved real
// target is NOT a structural failure: resolveAnchoredTarget no longer rejects an out-of-root
// parent for the mutating tools (it reports it via parentInRoot, which this helper ignores), so an
// out-of-root edit/create flows on to be authorized via the approval prompt rather than aborting.
// Argument-set validation (additionalProperties) is the caller's responsibility and runs before this
// helper.
func resolveFileTarget(kind string, home string, processCWD string, projectRoot string, args map[string]any, precond targetPrecondition) (target string, scope string, err error) {
	rawPath, perr := requireStringArg(args, "path")
	if perr != nil {
		return "", "", &TargetError{Kind: kind, Reason: perr.Error()}
	}
	if strings.TrimSpace(rawPath) == "" {
		return "", "", &TargetError{Kind: kind, Reason: "path must be non-empty"}
	}

	// Resolve relative paths against the process cwd for edit/create (the read tools pass projectRoot
	// instead; see ResolveReadTarget). The parentInRoot verdict is consumed only by the read-only caller,
	// which keeps its root-confinement; the mutating tools classify on the precondition's real path scope.
	parent, candidate, _, reason := resolveAnchoredTarget(home, processCWD, projectRoot, rawPath)
	if reason != "" {
		return "", "", &TargetError{Kind: kind, Reason: reason}
	}

	resolved, targetScope, reason := precond(parent, candidate)
	if reason != "" {
		return "", "", &TargetError{Kind: kind, Reason: reason}
	}
	return resolved, targetScope, nil
}

// normalizeRoot returns projectRoot in the cleaned, symlink-resolved form used as the containment scope
// by every file tool (edit, create, and the read-only resolvers). The bootstrap project root is absolute
// and cleaned but not symlink-resolved, while candidate parents are symlink-resolved before the
// containment check; resolving the root here puts both on the same footing, so a root path that itself
// contains a symlink does not reject valid in-project targets. EvalSymlinks requires the path to exist; if
// it fails (a missing or unreadable root), the cleaned-but-unresolved root is used as a fail-closed
// fallback that still compares boundary-safely.
func normalizeRoot(projectRoot string) string {
	resolved := filepath.Clean(projectRoot)
	if r, err := filepath.EvalSymlinks(projectRoot); err == nil {
		resolved = r
	}
	return resolved
}

// resolveAnchoredTarget performs the parent-resolution and basename-anchoring step shared by the
// edit/create resolver (resolveFileTarget) and the read-only resolver (ResolveReadTarget). It expands a
// leading ~ (rejecting ~user), cleans the path once, resolves the parent directory against baseDir with
// the permission path-scope rules (permissions.CleanAbsResolve: ~ expansion, relative resolution against
// baseDir, symlink resolution, and an existing-directory requirement), and anchors the cleaned basename
// under that resolved parent. baseDir is the process cwd for edit/create and the project root for the
// read-only tools. It returns the resolved parent directory, the anchored candidate, and
// parentInRoot — whether the resolved parent is inside projectRoot (permissions.IsDescendantOrEqual).
//
// parentInRoot is reported rather than enforced here so the two callers can diverge on it without a
// behavior flag: the read-only resolver still rejects an out-of-root parent fail-closed (its
// root-confinement invariant is unchanged), while the mutating edit/create resolver lets it through as a
// promptable out-of-root target and computes the real-path verdict in its precondition. A
// non-empty reason is a fail-closed *structural* rejection (~user or no resolvable parent) the caller
// wraps in a *TargetError before any authorization or read; out-of-root is not such a reason.
func resolveAnchoredTarget(home string, baseDir string, projectRoot string, rawPath string) (parent string, candidate string, parentInRoot bool, reason string) {
	// Expand a leading ~ before cleaning can collapse it with traversal segments. Cleaning first turns
	// "~/../created.txt" into "created.txt" and "~user/../created.txt" into "created.txt", bypassing
	// both home expansion and the unsupported-~user rejection before the permission-scope resolver sees
	// the path.
	expandedPath, eerr := paths.Expand(home, rawPath)
	if eerr != nil {
		return "", "", false, "unsupported ~user path form; only ~ and ~/<subpath> are supported"
	}

	// Clean the expanded path once and derive both the parent and the basename from that same normalized
	// value. Splitting the raw path instead lets a trailing separator desync the two: for a directory
	// target written as "subdir/", filepath.Dir is "subdir" but filepath.Base is also "subdir", so the
	// candidate would anchor a phantom "<parent>/subdir/subdir" child that create sees as absent — letting
	// it write inside the existing directory instead of rejecting the directory target. Cleaning
	// collapses "subdir/" to "subdir" so it is rejected, while "subdir/new.txt" still resolves to a new
	// child under the existing parent.
	cleanPath := filepath.Clean(expandedPath)

	parent, rerr := permissions.CleanAbsResolve(home, baseDir, filepath.Dir(cleanPath))
	if rerr != nil {
		return "", "", false, "cannot resolve a safe parent directory for the target"
	}
	parentInRoot = permissions.IsDescendantOrEqual(parent, projectRoot)
	return parent, filepath.Join(parent, filepath.Base(cleanPath)), parentInRoot, ""
}

// requireStringArg pulls a required string argument out of the decoded tool arguments. A missing key
// or a non-string value is an error; the provider-facing JSON-Schema (additionalProperties:false,
// required) should prevent both, so this is defense-in-depth against a malformed tool call. Shared by
// the edit and create tools.
func requireStringArg(args map[string]any, key string) (string, error) {
	raw, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", key)
	}
	return s, nil
}

// failResult renders a file-tool precondition or resolution failure as a non-zero-exit tool result whose
// stderr names the reason, so the dispatcher's result formatter surfaces it to the model in-band (no file
// was created, modified, or read). Shared by the mutating edit/create tools and the read-only navigation
// tools, which convert a *TargetError from ResolveReadTarget into this in-band form.
func failResult(msg string) tools.Result {
	return tools.Result{ExitCode: 1, Stderr: []byte(msg + "\n")}
}

// ResolveDeclaredScopes canonicalizes one run's caller-declared write and delete paths into the
// exact target forms the create/edit and delete tools resolve their own targets to, so the
// runtime membership test is a path comparison and never a comparison of the raw argument. A
// write declaration follows a final symlink when the path exists and otherwise anchors the
// missing segments under the deepest existing ancestor; a delete declaration resolves the parent
// and keeps the literal basename, so declaring a symlink authorizes removing the link rather than
// its target. Either list failing leaves both unresolved.
func ResolveDeclaredScopes(home, launchDir string, writeDecls, deleteDecls []string) (write, remove map[string]bool, err error) {
	write, err = resolveDeclarations(home, launchDir, writeDecls, resolveWriteDeclaration)
	if err != nil {
		return nil, nil, err
	}
	remove, err = resolveDeclarations(home, launchDir, deleteDecls, resolveDeleteDeclaration)
	if err != nil {
		return nil, nil, err
	}
	return write, remove, nil
}

func resolveDeclarations(home, launchDir string, decls []string, resolve func(home, launchDir, raw string) (string, string)) (map[string]bool, error) {
	if len(decls) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(decls))
	for _, raw := range decls {
		if strings.TrimSpace(raw) == "" {
			return nil, fmt.Errorf("declared path %q is empty or whitespace only", raw)
		}
		target, reason := resolve(home, launchDir, raw)
		if reason != "" {
			return nil, fmt.Errorf("declared path %q: %s", raw, reason)
		}
		out[target] = true
	}
	return out, nil
}

func resolveWriteDeclaration(home, launchDir, raw string) (string, string) {
	abs, reason := absDeclaration(home, launchDir, raw)
	if reason != "" {
		return "", reason
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, ""
	}
	return anchorUnderExistingAncestor(home, launchDir, abs, "")
}

func resolveDeleteDeclaration(home, launchDir, raw string) (string, string) {
	abs, reason := absDeclaration(home, launchDir, raw)
	if reason != "" {
		return "", reason
	}
	parent, leaf := filepath.Dir(abs), filepath.Base(abs)
	if resolvedParent, err := permissions.CleanAbsResolve(home, launchDir, parent); err == nil {
		return anchorDeclaration(resolvedParent, nil, leaf)
	}
	return anchorUnderExistingAncestor(home, launchDir, parent, leaf)
}

func absDeclaration(home, launchDir, raw string) (string, string) {
	expanded, err := paths.Expand(home, raw)
	if err != nil {
		return "", "unsupported ~user path form; only ~ and ~/<subpath> are supported"
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(launchDir, expanded)
	}
	return filepath.Clean(expanded), ""
}

func anchorUnderExistingAncestor(home, launchDir, path, leaf string) (string, string) {
	ancestor, segs, _, reason := splitExistingPrefix(path)
	if reason != "" {
		return "", reason
	}
	resolved, err := permissions.CleanAbsResolve(home, launchDir, ancestor)
	if err != nil {
		return "", "cannot resolve a safe existing parent directory for the declared path"
	}
	return anchorDeclaration(resolved, segs, leaf)
}

func anchorDeclaration(ancestor string, segs []string, leaf string) (string, string) {
	parts := append([]string{ancestor}, segs...)
	if leaf != "" {
		parts = append(parts, leaf)
	}
	target := filepath.Join(parts...)
	if !permissions.IsDescendantOrEqual(target, ancestor) {
		return "", "declared path escapes its resolved parent directory"
	}
	return target, ""
}
