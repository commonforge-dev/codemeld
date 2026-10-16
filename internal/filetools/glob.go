// Built-in structured glob tool: project-root-confined filename globbing with `**` recursive matching
// via the pure-Go doublestar matcher, run over the shared hidden/ignore/symlink-safe walker, returning
// project-relative paths in ascending order bounded by a per-tool limit.
package filetools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// GlobToolName is the exact dispatch name the structured glob tool registers under. Like
// `read`/`edit`/`create`/`bash` it is a fixed built-in name carrying no template namespace.
const GlobToolName = "glob"

// GlobTool is the built-in read-only glob tool. It returns the project-relative paths
// of filesystem entries whose path matches a glob `pattern` — including `**` recursive segments — under an
// optional `path` (default project root), in ascending order, bounded by a per-tool `limit` with the
// truncation indicator. It is read-only (Advertise().ReadOnly == true), so it auto-allows without
// prompting in every mode. Matching uses doublestar.Match over entries produced by the shared
// walker (hidden-skip by default, the ignore seam, directory-symlink no-follow); it never invokes
// doublestar's own filesystem traversal, so the walker stays the single source of traversal policy. The
// run-scoped home, process cwd, project root, and the configured tool-output byte cap are bound at
// construction so target resolution matches the permission path-scope rules and the truncation indicator
// survives the same byte cap as every other tool output.
type GlobTool struct {
	home        string
	processCWD  string
	projectRoot string
	outputCap   int
	blocked     *permissions.BlockedPaths
}

var _ tools.Tool = (*GlobTool)(nil)

func (t *GlobTool) SetBlockedPaths(blocked *permissions.BlockedPaths) { t.blocked = blocked }

// NewGlobTool builds the glob tool bound to the run's ~ anchor (home), the process cwd accepted for
// signature symmetry with the other file tools, the project root the search is confined to (via
// ResolveReadTarget), and the tool-output byte cap (cache.MaxToolOutputBytes()) BoundedResult uses to
// predict byte-cap truncation. The project root is symlink-resolved once here — mirroring
// NewReadTool — so a launch through a symlinked project directory does not reject valid in-project paths;
// ResolveReadTarget normalizes again, so the double normalization is idempotent.
func NewGlobTool(home, processCWD, projectRoot string, outputCap int) *GlobTool {
	return &GlobTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot), outputCap: outputCap}
}

func (t *GlobTool) Name() string { return GlobToolName }

func (t *GlobTool) SubjectKind() string { return "tool" }

// Advertise returns the glob tool's advertising metadata and read-only classification.
// The parameter JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so the
// advertised contract matches the decoder exactly: `pattern` is the only required argument; `path`,
// `limit`, `include_ignored`, and `include_hidden` are optional. ReadOnly is true: glob never mutates, so
// it is advertised in Plan and auto-allowed in every mode.
func (t *GlobTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "List project files whose path matches a glob pattern, including ** for recursive " +
			"matching across directories. pattern is required (e.g. \"**/*.go\"); path is the directory to " +
			"search under (default project root); limit caps the paths returned (default " +
			fmt.Sprintf("%d, max %d", GlobDefaultLimit, GlobMaxLimit) + "). Hidden (dot-prefixed) entries are " +
			"skipped unless include_hidden is set. Results are project-relative, in ascending order; when more " +
			"match than the limit, the result signals truncation. Use to find files by name pattern.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pattern": map[string]any{
					"type": "string",
					"description": "Glob pattern, matched against entry paths relative to the search path. Supports " +
						"* (within one path segment), ?, character classes [...], {alt,alt} alternatives, and ** to " +
						"match across directories. Example: \"**/*.go\" finds every Go file in the tree.",
				},
				"path": map[string]any{
					"type":        "string",
					"description": "Directory to search under. Relative paths resolve against the project root and search normally; an explicitly named directory whose real location is outside the project is searched only after you approve it at the permission prompt. Defaults to the project root when omitted.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Maximum number of paths to return. Default %d; must be between 1 and %d.", GlobDefaultLimit, GlobMaxLimit),
				},
				"include_ignored": map[string]any{
					"type":        "boolean",
					"description": "Include entries normally excluded by codemeldignore rules from .codemeld/codemeldignore and ~/.codemeld/global/codemeldignore. Default false.",
				},
				"include_hidden": map[string]any{
					"type":        "boolean",
					"description": "Include hidden (dot-prefixed) files and directories. Default false.",
				},
			},
			"required":             []string{"pattern"},
			"additionalProperties": false,
		},
		ReadOnly:      true,
		Noncredential: true,
	}
}

// ResolveTarget resolves the search root from args before authorization and returns it as both the
// resolved target and the path scope to authorize, mirroring read's target-scoped contract so
// authorization and the directory actually walked cannot drift. It rejects unknown arguments, then
// delegates to ResolveReadTarget in optional-path mode (an omitted/blank `path` defaults to the
// project root) with RejectDirectorySymlink set so a directory-symlink `path` argument is refused
// fail-closed before a recursive walk could be redirected through it. Pattern and numeric/boolean
// validation are deferred to invocation, as read defers its offset/limit checks.
func (t *GlobTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownPhase1ReadArgs(GlobToolName, args); verr != nil {
		return "", "", &TargetError{Kind: GlobToolName, Reason: verr.Error()}
	}
	return ResolveReadTarget(t.home, t.processCWD, t.projectRoot, args, ReadTargetOptions{
		RequirePath:            false,
		Kind:                   GlobToolName,
		RejectDirectorySymlink: true,
		AllowExternal:          true,
	})
}

// ExternalReadScope reports whether scope (the search root ResolveTarget returned) is an explicit
// out-of-project read target — the promptable case DispatchTool routes to a permission prompt while
// bypassing the read-only mode auto-allow. False for an in-project search root, keeping in-project globs
// on their existing no-prompt auto-allow.
func (t *GlobTool) ExternalReadScope(scope string) bool {
	return isExternalReadScope(scope, t.projectRoot)
}

// InvokeWithResolvedTarget runs glob over the search root dispatch already resolved before authorization,
// so the authorized directory and the directory actually walked cannot diverge if a symlink changes in
// between — the same reuse-at-invoke contract read/edit/create follow. It is the production invocation
// path; the registered tool implements it so DispatchTool reuses the authorized target.
func (t *GlobTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.glob(resolvedTarget, args), nil
}

// Invoke resolves the search root and globs it in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveTarget then InvokeWithResolvedTarget; this keeps the tool a complete unit
// for direct callers and tests. A target-resolution failure surfaces as the same in-band error result the
// dispatcher would render, so the observable outcome matches either entry.
// Standalone Invoke has no authorizer, so it refuses an explicit out-of-project search root
// in-band: only the dispatch path can obtain the required approval. The in-project path is unchanged.
func (t *GlobTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.ExternalReadScope(scope) {
		return externalReadDispatchOnly(GlobToolName), nil
	}
	return t.glob(target, args), nil
}

func (t *GlobTool) glob(searchRoot string, args map[string]any) tools.Result {
	if verr := ValidatePhase1ReadArgs(GlobToolName, args); verr != nil {
		return failResult(verr.Error())
	}

	pattern, _ := requireStringArg(args, "pattern")
	limitPtr, _ := optionalIntArg(args, "limit")
	limit := GlobDefaultLimit
	if limitPtr != nil {
		limit = *limitPtr
	}
	includeHidden, _ := optionalBoolArg(args, "include_hidden")
	includeIgnored, _ := optionalBoolArg(args, "include_ignored")

	// Re-validate the traversal root immediately before walking. ResolveTarget refused a directory-symlink
	// `path` before authorization, but the authorized directory could be swapped for a symlink between
	// resolution and this invocation; Walk begins with os.ReadDir(searchRoot), which follows a symlink root,
	// so without this guard a swapped root would redirect the recursive walk outside the authorized tree.
	// This mirrors read's reuse-at-invoke revalidation of its resolved target before opening it.
	rootInfo, lerr := os.Lstat(searchRoot)
	if lerr != nil {
		return failResult("glob target rejected: cannot traverse the search path: " + lerr.Error())
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return failResult("glob target rejected: recursive tools do not follow a symlink to a directory")
	}
	if !rootInfo.IsDir() {
		return failResult("glob target rejected: search path is not a directory")
	}

	// Anchor emitted paths and the ignore matchers at the project root for an in-project search, or at the
	// approved external search root for an out-of-project read, so external matches stay clean
	// (project-root-relative paths would otherwise carry a ".." prefix) and the matchers see the same base.
	anchor := readAnchor(searchRoot, t.projectRoot)

	// Load the default codemeldignore filter set unless include_ignored disables it. A
	// malformed codemeldignore pattern surfaces in-band so the model can correct the file rather than the
	// turn aborting; when include_ignored is set the file is not even read, so a bad file never blocks a
	// bypassing call.
	var ignore []IgnoreMatcher
	if !includeIgnored {
		matchers, ierr := defaultIgnoreMatchers(anchor, t.home)
		if ierr != nil {
			return failResult("glob target rejected: " + ierr.Error())
		}
		ignore = matchers
	}

	// Walk the whole subtree unbounded and bound the *matches* below, not the walked entries: the walker's
	// Limit caps how many entries it emits, but glob must consider every entry to find matches anywhere in
	// the tree, so capping the walk would silently drop matches deeper than the cap. MaxDepth is 0
	// (recursive) so a `**` segment can match at any depth.
	var leftOut []string
	entries, _, werr := Walk(WalkOptions{
		Root:           searchRoot,
		ProjectRoot:    anchor,
		Limit:          0,
		MaxDepth:       0,
		IncludeHidden:  includeHidden,
		IncludeIgnored: includeIgnored,
		Ignore:         ignore,
		Blocked:        t.blocked,
		OnBlocked:      func(p string) { leftOut = append(leftOut, p) },
	})
	if werr != nil {
		return withLeftOut(failResult("glob target rejected: cannot traverse the search path: "+werr.Error()), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
	}

	matches, merr := matchEntries(pattern, searchRoot, entries)
	if merr != nil {
		return failResult(merr.Error())
	}

	// results are project-relative in ascending path order. Sort the matched project-relative
	// paths lexically so ordering is a stable byte-order of the output paths, independent of the walker's
	// hierarchical emit order, then bound the set by limit and signal truncation when more matched.
	sort.Strings(matches)
	truncated := len(matches) > limit
	if truncated {
		matches = matches[:limit]
	}

	var buf strings.Builder
	for _, m := range matches {
		buf.WriteString(m)
		buf.WriteByte('\n')
	}
	// nextOffset is 0: glob is an entry-listing tool, so it carries no read-style line continuation.
	return withLeftOut(BoundedResult([]byte(buf.String()), truncated, 0, t.outputCap), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
}

// matchEntries returns the project-relative paths of the walker entries whose path — taken relative to the
// search root, slash-normalized — matches pattern. Matching against the search-root-relative name (not the
// project-relative one) makes glob("*.go", path:"internal/x") match files directly under that path, while
// the returned paths stay project-relative for stable, root-anchored output (architecture review). All
// entry kinds are matched (file, dir, symlink), matching standard glob semantics where a pattern names a
// path regardless of its type. A doublestar.Match error is unexpected after ValidatePattern but is
// surfaced in-band defensively.
func matchEntries(pattern, searchRoot string, entries []WalkEntry) ([]string, error) {
	var matches []string
	for _, e := range entries {
		rel, rerr := filepath.Rel(searchRoot, e.AbsPath)
		if rerr != nil {
			return nil, fmt.Errorf("glob target rejected: cannot relativize %q: %v", e.AbsPath, rerr)
		}
		ok, merr := doublestar.Match(pattern, filepath.ToSlash(rel))
		if merr != nil {
			return nil, fmt.Errorf("glob target rejected: malformed glob pattern %q: %v", pattern, merr)
		}
		if ok {
			matches = append(matches, e.RelPath)
		}
	}
	return matches, nil
}

// optionalBoolArg pulls an optional boolean argument out of the decoded tool arguments, returning false
// when the key is absent (so the caller applies its default) and an error for a present-but-non-boolean
// value so a malformed flag surfaces in-band rather than being silently coerced. Shared by the
// read-only navigation tools' include_hidden / include_ignored flags.
func optionalBoolArg(args map[string]any, key string) (bool, error) {
	raw, ok := args[key]
	if !ok {
		return false, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("argument %q must be a boolean", key)
	}
	return b, nil
}
