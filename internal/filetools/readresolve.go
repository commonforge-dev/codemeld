// Shared read-target path resolution and symlink-policy predicates for the five read-only navigation
// tools (read, grep, glob, list, tree): project-root-relative resolution, required vs optional `path`
// modes, fail-closed project-root containment, and the per-caller symlink rules.
package filetools

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// ReadTargetOptions configures ResolveReadTarget's argument handling for a specific read-only tool.
type ReadTargetOptions struct {
	// RequirePath selects the argument mode: read sets it true, so a missing or empty `path` is
	// an in-band rejection; grep, glob, list, and tree leave it false, so an omitted (or empty) `path`
	// defaults to the project root.
	RequirePath bool
	// Kind names the calling tool ("read", "grep", "glob", "list", "tree") for the *TargetError message;
	// an empty Kind falls back to the generic "file" label in TargetError.Error.
	Kind string
	// RejectDirectorySymlink makes a final-component symlink that resolves to a directory an in-band
	// rejection: the recursive tools (grep, glob, tree) set it true so a directory-symlink path
	// argument is refused fail-closed *before* the resolver collapses it to the real directory, instead of
	// being handed back as an ordinary directory target they would then walk. read and list leave it false:
	// read targets regular files (a directory target is rejected downstream), and list reports a symlink as
	// type symlink without descending. Symlinks encountered *within* a recursive walk are handled separately
	// by IsDirectorySymlink; this option governs only the top-level path argument.
	RejectDirectorySymlink bool
	// AllowExternal opts the caller into promptable out-of-project read resolution: when set, an
	// EXPLICIT absolute or ~ path whose parent resolves outside the project root is resolved to a concrete
	// out-of-root target and scope instead of being rejected, so dispatch can route it to a permission
	// prompt. It is the five dispatch read tools' mode; every other structural rejection (a relative ".."
	// escape, a ~user form, an in-root path whose final symlink escapes the root, a directory-symlink root
	// for the recursive tools, an unresolvable parent) stays fail-closed regardless. Left false by callers
	// that must keep the unconditional root-confinement — notably the image-attachment resolver, which has
	// no permission prompt to gate an out-of-root read — so their behavior is unchanged.
	AllowExternal bool
}

// ResolveReadTarget resolves a read-only tool's path argument to a safe, in-project absolute target
// before any content read. It is the shared security boundary for read, grep, glob
// list, and tree, and differs from resolveFileTarget in three ways: (1) a relative path resolves against
// projectRoot, not the process cwd, so resolution is stable however codemeld was launched
// (2) it imposes no existence-shape precondition, so the target may be a regular file or a directory;
// and (3) an omitted path defaults to projectRoot for the directory-oriented tools (grep/glob/list/tree).
//
// It expands a leading ~ (rejecting ~user), resolves and contains the parent directory, anchors the
// basename, then follows a final-component symlink and re-checks that the real target — including one
// reached through a symlink — stays inside projectRoot, failing closed with a *TargetError before any
// read. When opts.RejectDirectorySymlink is set (the recursive grep/glob/tree tools), a final-component
// symlink that resolves to a directory is refused fail-closed before it is collapsed to the real
// directory, so a recursive walk cannot be redirected through a directory symlink. It returns
// the resolved target and the path scope to authorize: the target itself when it is a directory, or the
// target's enclosing directory when it is a file. A non-existent target is returned as the anchored
// (already-contained) path so the calling tool reports a normal not-found.
//
// By default the target must be in-project: an out-of-root parent is a fail-closed rejection. When
// opts.AllowExternal is set (the five dispatch read tools) the one exception is an EXPLICIT absolute
// or ~ path whose parent resolves outside the root: it is resolved to a concrete out-of-root target/scope
// (via resolveExternalReadTarget) rather than rejected, so DispatchTool can route it to a permission
// prompt. Every other escape stays fail-closed even with AllowExternal — a relative ".." traversal, a
// ~user form, an in-root path whose final symlink escapes the root, a directory-symlink root for the
// recursive tools, and an unresolvable parent — so the only widening is an explicitly named external path
// the user can be prompted to approve.
//
// processCWD is accepted for signature symmetry with resolveFileTarget but is deliberately not the base
// for relative resolution; read targets resolve against projectRoot.
func ResolveReadTarget(home string, processCWD string, projectRoot string, args map[string]any, opts ReadTargetOptions) (target string, scope string, err error) {
	// Normalize the project root to its cleaned, symlink-resolved form so the containment scope and the
	// symlink-resolved candidate parents compare on the same footing — mirroring NewEditTool/NewCreateTool.
	// Without this, a launch through a symlinked project directory would reject valid in-root reads.
	root := normalizeRoot(projectRoot)

	var rawPath string
	raw, present := args["path"]
	if present {
		s, ok := raw.(string)
		if !ok {
			return "", "", &TargetError{Kind: opts.Kind, Reason: `argument "path" must be a string`}
		}
		rawPath = s
	}
	if !present || strings.TrimSpace(rawPath) == "" {
		if opts.RequirePath {
			reason := "path is required"
			if present {
				reason = "path must be non-empty"
			}
			return "", "", &TargetError{Kind: opts.Kind, Reason: reason}
		}
		// Optional path omitted or blank: the whole project root is the target. Return the
		// normalized root so later traversal and authorization use the same root shape.
		return root, root, nil
	}

	// A present, non-blank path that denotes the project root itself is accepted as the whole-root target,
	// returning the same (root, root) the omitted-path branch returns above. resolveAnchoredTarget
	// would otherwise reject the root: it anchors via the parent (filepath.Dir(root)), which lies outside the
	// root and fails the parent-containment check. Every other path still flows through resolveAnchoredTarget
	// and keeps its rejections (out-of-root, ~user, symlink escape, and the recursive directory-symlink rule).
	if pathDenotesRoot(home, projectRoot, root, rawPath) {
		return root, root, nil
	}

	// Resolve relative paths against the project root (not processCWD) so resolution is stable however
	// codemeld was launched.
	_, candidate, parentInRoot, reason := resolveAnchoredTarget(home, root, root, rawPath)
	if reason != "" {
		return "", "", &TargetError{Kind: opts.Kind, Reason: reason}
	}
	// An out-of-root parent is fail-closed by default. The exception is narrow: when the caller opted
	// in (AllowExternal) AND the user named an EXPLICIT absolute or ~ path, the out-of-root target is
	// resolved to a concrete external target/scope so dispatch can route it to a permission prompt. A
	// relative path that merely climbs out via ".." is a traversal escape, not an explicit external
	// request, so it stays rejected here — only an absolute/~ path the caller wrote directly is promptable.
	if !parentInRoot {
		if opts.AllowExternal && isExplicitPath(home, rawPath) {
			return resolveExternalReadTarget(opts, candidate)
		}
		return "", "", &TargetError{Kind: opts.Kind, Reason: "target's parent directory is outside the project root"}
	}

	// Re-check the anchored candidate's containment — a ".." basename can point above the resolved
	// parent — then follow a final-component symlink and re-check that the real target stays in-root, so
	// a symlink escape is rejected before any read.
	clean := filepath.Clean(candidate)
	if !permissions.IsDescendantOrEqual(clean, root) {
		return "", "", &TargetError{Kind: opts.Kind, Reason: "target is outside the project root"}
	}
	info, lerr := os.Lstat(clean)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			// Nothing to follow and already contained; the tool reports the not-found itself. The
			// enclosing directory is the path scope.
			return clean, filepath.Dir(clean), nil
		}
		return "", "", &TargetError{Kind: opts.Kind, Reason: "cannot determine the target's type"}
	}
	target = clean
	if info.Mode()&os.ModeSymlink != 0 {
		real, rerr := filepath.EvalSymlinks(clean)
		if rerr != nil {
			return "", "", &TargetError{Kind: opts.Kind, Reason: "target symlink cannot be resolved"}
		}
		if !permissions.IsDescendantOrEqual(real, root) {
			return "", "", &TargetError{Kind: opts.Kind, Reason: "target resolves through a symlink to outside the project root"}
		}
		ri, serr := os.Stat(real)
		if serr != nil {
			return "", "", &TargetError{Kind: opts.Kind, Reason: "cannot determine the target's type"}
		}
		// Recursive callers refuse a directory-symlink path argument fail-closed here, before the real
		// directory is returned and they would otherwise walk it.
		if opts.RejectDirectorySymlink && ri.IsDir() {
			return "", "", &TargetError{Kind: opts.Kind, Reason: "recursive tools do not follow a symlink to a directory"}
		}
		target, info = real, ri
	}
	if info.IsDir() {
		return target, target, nil
	}
	return target, filepath.Dir(target), nil
}

// isExplicitPath reports whether rawPath is an explicit absolute or ~ path — the only forms that may
// become a promptable out-of-project read. It expands a leading ~ (so "~"/"~/sub" count as
// explicit, mirroring the dispatch read tools' resolution) and treats the result as explicit only when it
// is absolute; a relative path (including one that climbs out via "..") is never explicit, so a traversal
// escape stays a fail-closed rejection. A ~user form (paths.Expand error) is likewise not explicit, so it
// keeps its canonical rejection through resolveAnchoredTarget.
func isExplicitPath(home, rawPath string) bool {
	expanded, err := paths.Expand(home, rawPath)
	if err != nil {
		return false
	}
	return filepath.IsAbs(expanded)
}

// resolveExternalReadTarget completes resolution for an explicit absolute/~ path whose parent already
// resolved outside the project root. candidate is the anchored target resolveAnchoredTarget
// produced — its parent directory is real (symlink-resolved) and contained nothing; only the final
// component may still be a symlink. This mirrors the in-root tail of ResolveReadTarget — following a
// final-component symlink, refusing a directory-symlink root for the recursive tools fail-closed
// and rejecting an unresolvable type — but deliberately omits the project-root containment recheck,
// because the target is outside the root by construction and is gated by the permission prompt instead.
// The returned scope is the resolved real directory (a directory target) or the real file's enclosing
// directory (a file target), so the prompt and any grant anchor on the target's real location, never a
// symlink alias. A non-existent target is returned as the anchored path so the calling tool reports a
// normal not-found.
func resolveExternalReadTarget(opts ReadTargetOptions, candidate string) (target string, scope string, err error) {
	clean := filepath.Clean(candidate)
	info, lerr := os.Lstat(clean)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			return clean, filepath.Dir(clean), nil
		}
		return "", "", &TargetError{Kind: opts.Kind, Reason: "cannot determine the target's type"}
	}
	target = clean
	if info.Mode()&os.ModeSymlink != 0 {
		real, rerr := filepath.EvalSymlinks(clean)
		if rerr != nil {
			return "", "", &TargetError{Kind: opts.Kind, Reason: "target symlink cannot be resolved"}
		}
		ri, serr := os.Stat(real)
		if serr != nil {
			return "", "", &TargetError{Kind: opts.Kind, Reason: "cannot determine the target's type"}
		}
		if opts.RejectDirectorySymlink && ri.IsDir() {
			return "", "", &TargetError{Kind: opts.Kind, Reason: "recursive tools do not follow a symlink to a directory"}
		}
		target, info = real, ri
	}
	if info.IsDir() {
		return target, target, nil
	}
	return target, filepath.Dir(target), nil
}

// isExternalReadScope reports whether scope (a path scope ResolveReadTarget returned) lies outside
// projectRoot — the promptable out-of-project read verdict the dispatch read tools surface to
// DispatchTool (mirroring the mutating tools' OutOfRootScope). projectRoot is normalized to its
// symlink-resolved form so the comparison uses the same containment footing ResolveReadTarget does.
func isExternalReadScope(scope, projectRoot string) bool {
	return !permissions.IsDescendantOrEqual(scope, normalizeRoot(projectRoot))
}

// readAnchor returns the base a read-only tool's emitted relative paths (and its ignore-matcher inputs)
// are computed against: the project root for an in-project target, or the resolved out-of-project target
// itself for an approved external read, so external results stay clean (no ".."-prefixed paths)
// and the output and ignore matchers anchor on the same base.
func readAnchor(searchRoot, projectRoot string) string {
	if isExternalReadScope(searchRoot, projectRoot) {
		return searchRoot
	}
	return projectRoot
}

// externalReadDispatchOnly is the in-band result the standalone Invoke path returns for an explicit
// out-of-project read target. Like the mutating tools' standalone out-of-root guard, the
// non-dispatch entry has no authorizer and so cannot obtain the required approval; it refuses in-band
// rather than reading, so only the dispatch path (which prompts) can ever read outside the project root.
func externalReadDispatchOnly(kind string) tools.Result {
	return failResult(kind + " target outside the project root requires permission approval through dispatch")
}

// pathDenotesRoot reports whether a present, non-blank path argument names the project root itself. root
// is the already-normalized (cleaned, symlink-resolved) project root, and projectRoot is the raw configured
// spelling root was normalized from (see normalizeRoot). It expands a leading ~, resolves a relative path
// against root, and cleans the candidate, then accepts it when it equals the normalized root directly —
// covering the absolute root, "."/"./", and trailing-separator forms. A launch through a symlinked project
// root is also accepted, but only via the configured spelling itself: the cleaned candidate must equal the
// cleaned configured projectRoot before its EvalSymlinks resolution is allowed to match root. This
// deliberately does NOT accept an arbitrary out-of-root symlink alias whose target happens to be the root
// (e.g. /outside/link-to-root); such a path keeps flowing through resolveAnchoredTarget, whose
// parent-containment check rejects it fail-closed, so an explicit out-of-root path can never alias the root.
// A ~user form (paths.Expand error) returns false so resolveAnchoredTarget produces the
// canonical rejection; a genuine in-root directory symlink canonicalizes elsewhere and so is not
// short-circuited, staying subject to the recursive directory-symlink rule. A path with any ".." segment
// is likewise never short-circuited — even one that cleans back to root, such as "../<root-basename>" —
// so resolveAnchoredTarget applies the parent-containment check rather than a normalization collapse
// re-aliasing the root.
func pathDenotesRoot(home string, projectRoot string, root string, rawPath string) bool {
	expanded, err := paths.Expand(home, rawPath)
	if err != nil {
		return false
	}
	// A traversal form (any ".." segment) must not be short-circuited even when it cleans back to the
	// root — e.g. "../<root-basename>", which filepath.Clean collapses to root. Only direct root spellings
	// use this shortcut; a ".." alias falls through to resolveAnchoredTarget, whose parent-containment check
	// resolves the ".." to the root's parent and rejects it fail-closed as outside the project root, so a
	// normalization bypass cannot smuggle the root past that check.
	for _, seg := range strings.Split(filepath.ToSlash(expanded), "/") {
		if seg == ".." {
			return false
		}
	}
	candidate := expanded
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate = filepath.Clean(candidate)
	if candidate == root {
		return true
	}
	// A launch through a symlinked root: accept the configured root spelling whose EvalSymlinks form is the
	// normalized root, mirroring normalizeRoot. Gate this on the candidate being exactly the configured
	// spelling so an out-of-root symlink alias to the root (whose cleaned form is some other path) is not
	// short-circuited here and instead fails parent containment in resolveAnchoredTarget.
	if candidate == filepath.Clean(projectRoot) {
		if real, rerr := filepath.EvalSymlinks(candidate); rerr == nil && real == root {
			return true
		}
	}
	return false
}

// IsDirectorySymlink reports whether path is itself a symlink whose target is a directory. The recursive
// read tools (grep, tree, and glob's recursive matching) use it to refuse to descend through a directory
// symlink, so a symlink under the tree cannot redirect a recursive walk outside it. A real
// directory, a non-symlink, a dangling symlink, or a symlink to a non-directory all return false; a
// stat/lstat error other than non-existence is returned to the caller.
func IsDirectorySymlink(path string) (bool, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if li.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}
	ti, err := os.Stat(path) // follows the link to classify its destination
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // a dangling symlink is not a directory to descend into
		}
		return false, err
	}
	return ti.IsDir(), nil
}

// EntryKind is the type the list tool displays for a directory entry, classified without following
// symlinks.
type EntryKind string

const (
	// EntryFile is a regular file.
	EntryFile EntryKind = "file"
	// EntryDir is a directory.
	EntryDir EntryKind = "dir"
	// EntrySymlink is a symbolic link, classified by its own type rather than its target's.
	EntrySymlink EntryKind = "symlink"
	// EntryOther is any other node (socket, device, named pipe).
	EntryOther EntryKind = "other"
)

// ClassifyEntry returns path's type for the list tool using a non-following lstat, so a symlink entry is
// reported as EntrySymlink rather than as whatever it points to: list classifies entries by
// their own type, and following here would let a symlink masquerade as a regular file or directory in
// the listing. A regular file is EntryFile, a directory EntryDir, and anything else EntryOther.
func ClassifyEntry(path string) (EntryKind, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	switch {
	case li.Mode()&os.ModeSymlink != 0:
		return EntrySymlink, nil
	case li.IsDir():
		return EntryDir, nil
	case li.Mode().IsRegular():
		return EntryFile, nil
	default:
		return EntryOther, nil
	}
}

// ResolveReadFile applies the read tool's symlink policy to a candidate target: it follows a symlink only
// when the link resolves to a regular file that is still inside projectRoot. It returns the
// resolved real file path when the target — after following any symlink — is a regular file in-root;
// otherwise ok is false with a reason naming why (a directory, a special file, a symlink that escapes the
// root, or a missing target), so read never follows a symlink to a directory or out of the project. The
// target argument is normally the path ResolveReadTarget returned. The project root is normalized to its
// symlink-resolved form before the containment check so a launch through a symlinked project directory does
// not reject valid in-root files (matching ResolveReadTarget).
func ResolveReadFile(target string, projectRoot string) (real string, ok bool, reason string) {
	root := normalizeRoot(projectRoot)
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", false, "target file does not exist or cannot be resolved"
	}
	if !permissions.IsDescendantOrEqual(resolved, root) {
		return "", false, "target resolves through a symlink to outside the project root"
	}
	info, serr := os.Stat(resolved)
	if serr != nil {
		return "", false, "cannot read the target file's metadata"
	}
	if info.IsDir() {
		return "", false, "target names a directory, not a file"
	}
	if !info.Mode().IsRegular() {
		return "", false, "target is not a regular file"
	}
	return resolved, true, ""
}
