// Built-in structured tree tool: project-confined, recursive listing of the directory structure under an
// optional `path` (default project root) to an optional maximum descendant `depth`, in deterministic
// ascending project-relative (pre-order) path order, bounded by a total-entry `limit` with the
// truncation signal, over the shared walker (directory symlinks not followed, hidden/ignore
// filtering). Display is selected by `format`: `ai` (the default) emits one project-relative,
// slash-normalized path per line; `human` emits the indented basename tree. The two layouts differ only in
// the per-line body — resolution, walk order, depth, limit, filtering, symlink handling, and truncation are
// shared.
package filetools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// TreeToolName is the exact dispatch name the structured tree tool registers under. Like
// `read`/`glob`/`grep`/`list`/`edit`/`create`/`bash` it is a fixed built-in name carrying no template
// namespace.
const TreeToolName = "tree"

// treeIndentUnit is the per-level indentation prepended to each emitted entry in `format: "human"`: a child
// one level below the resolved root carries no indent, its own children carry one unit, and so on (indent
// count == Depth-1). Two spaces is a compact, deterministic, OS-stable prefix that keeps the hierarchical
// shape legible without consuming much of the byte cap.
const treeIndentUnit = "  "

// treeFormatAI and treeFormatHuman are the two display layouts the `format` argument selects.
// treeFormatAI is the default: each entry is its project-relative, slash-normalized path on its own line —
// the canonical form Codemeld itself consumes. treeFormatHuman is the indented basename tree for human
// reading. They share path resolution, walk order, depth, limit, hidden/ignore filtering, symlink handling,
// and truncation; only the per-line body differs.
const (
	treeFormatAI    = "ai"
	treeFormatHuman = "human"
)

// TreeTool is the built-in read-only tree tool. It returns a recursive listing of the
// directory structure under an optional `path` (default project root), in deterministic ascending
// project-relative (pre-order) path order, to an optional maximum descendant `depth`, bounded by a
// total-entry `limit` with the truncation indicator. Display is selected by `format`: `ai` (the
// default) emits one project-relative, slash-normalized path per line; `human` emits the indented basename
// tree. It is read-only (Advertise().ReadOnly == true), so it auto-allows without prompting in every mode.
// Traversal runs through the shared walker (hidden-skip by default, the ignore seam
// directory-symlink no-follow), consuming the walker's pre-order entries directly so the human-format
// indentation matches the hierarchy; `depth` and the total-entry `limit` are both applied by the walker, so
// deeper-than-depth descendants never consume the visible entry budget and exactly `limit` entries are
// emitted before truncation is signalled. The run-scoped home, process cwd,
// project root, and the configured tool-output byte cap are bound at construction so target resolution
// matches the permission path-scope rules and the truncation indicator survives the same byte cap as every
// other tool output.
type TreeTool struct {
	home        string
	processCWD  string
	projectRoot string
	outputCap   int
	blocked     *permissions.BlockedPaths
}

var _ tools.Tool = (*TreeTool)(nil)

func (t *TreeTool) SetBlockedPaths(blocked *permissions.BlockedPaths) { t.blocked = blocked }

// NewTreeTool builds the tree tool bound to the run's ~ anchor (home), the process cwd accepted for
// signature symmetry with the other file tools, the project root the listing is confined to (via
// ResolveReadTarget), and the tool-output byte cap (cache.MaxToolOutputBytes()) BoundedResult uses to
// predict byte-cap truncation. The project root is symlink-resolved once here — mirroring
// NewListTool/NewGrepTool — so a launch through a symlinked project directory does not reject valid
// in-project paths; ResolveReadTarget normalizes again, so the double normalization is idempotent.
func NewTreeTool(home, processCWD, projectRoot string, outputCap int) *TreeTool {
	return &TreeTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot), outputCap: outputCap}
}

func (t *TreeTool) Name() string { return TreeToolName }

func (t *TreeTool) SubjectKind() string { return "tool" }

// Advertise returns the tree tool's advertising metadata and read-only classification.
// The parameter JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so the
// advertised contract matches the decoder exactly: every argument is optional — `path`, `depth`, `limit`,
// `format`, `include_ignored`, and `include_hidden`. `format` is a closed enum (`ai`, `human`) defaulting
// to `ai`. ReadOnly is true: tree never mutates, so it is advertised in Plan and auto-allowed in
// every mode.
func (t *TreeTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "List the directory structure under a path within the project. path is the directory to " +
			"walk (default project root); depth caps how many levels below path are shown (omit for the whole " +
			"subtree, 1 for immediate children only, 0 for nothing); limit caps the total number of entries " +
			"(default " + fmt.Sprintf("%d, max %d", TreeDefaultLimit, TreeMaxLimit) + "). format selects the " +
			"layout: \"ai\" (the default) lists each entry as its project-relative, slash-normalized path, one " +
			"per line; \"human\" shows an indented basename tree, two spaces per level below path. A trailing " +
			"\"/\" marks directories in both. Hidden (dot-prefixed) entries are skipped unless include_hidden is " +
			"set; a symlink is shown as a leaf and never followed. Entries are in depth-first order, siblings " +
			"ascending by name; when more entries exist than the limit, the result signals truncation. Use to " +
			"get an overview of how a directory is laid out.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Directory to walk. Relative paths resolve against the project root and walk normally; an explicitly named directory whose real location is outside the project is walked only after you approve it at the permission prompt. Defaults to the project root when omitted.",
				},
				"depth": map[string]any{
					"type":        "integer",
					"description": "Maximum number of levels below path to show. Omit for the full subtree; 1 shows only the immediate children; 0 shows nothing. Must be >= 0.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Maximum total number of entries to return. Default %d; must be between 1 and %d.", TreeDefaultLimit, TreeMaxLimit),
				},
				"format": map[string]any{
					"type":        "string",
					"enum":        []string{treeFormatAI, treeFormatHuman},
					"description": "Output layout. \"ai\" (default) lists each entry as its project-relative, slash-normalized path, one per line; \"human\" shows an indented basename tree, two spaces per level below path. Directories carry a trailing \"/\" in both.",
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
			"required":             []string{},
			"additionalProperties": false,
		},
		ReadOnly:      true,
		Noncredential: true,
	}
}

// ResolveTarget resolves the directory to walk from args before authorization and returns it as both the
// resolved target and the path scope to authorize, mirroring grep/list's target-scoped contract so
// authorization and the directory actually walked cannot drift. It rejects unknown arguments, then
// delegates to ResolveReadTarget in optional-path mode (an omitted/blank `path` defaults to the
// project root) with RejectDirectorySymlink set so a directory-symlink `path` argument is refused
// fail-closed before a recursive walk could be redirected through it. Numeric/boolean validation
// is deferred to invocation, as grep/list defer theirs.
func (t *TreeTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownPhase1ReadArgs(TreeToolName, args); verr != nil {
		return "", "", &TargetError{Kind: TreeToolName, Reason: verr.Error()}
	}
	return ResolveReadTarget(t.home, t.processCWD, t.projectRoot, args, ReadTargetOptions{
		RequirePath:            false,
		Kind:                   TreeToolName,
		RejectDirectorySymlink: true,
		AllowExternal:          true,
	})
}

// ExternalReadScope reports whether scope (the directory ResolveTarget returned) is an explicit
// out-of-project read target — the promptable case DispatchTool routes to a permission prompt while
// bypassing the read-only mode auto-allow. False for an in-project directory, keeping in-project trees on
// their existing no-prompt auto-allow.
func (t *TreeTool) ExternalReadScope(scope string) bool {
	return isExternalReadScope(scope, t.projectRoot)
}

// InvokeWithResolvedTarget walks the directory dispatch already resolved before authorization, so the
// authorized directory and the directory actually walked cannot diverge if a symlink changes in between —
// the same reuse-at-invoke contract grep/list/read/glob/edit/create follow. It is the production invocation
// path; the registered tool implements it so DispatchTool reuses the authorized target.
func (t *TreeTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.tree(resolvedTarget, args), nil
}

// Invoke resolves the directory and walks it in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveTarget then InvokeWithResolvedTarget; this keeps the tool a complete unit
// for direct callers and tests. A target-resolution failure surfaces as the same in-band error result the
// dispatcher would render, so the observable outcome matches either entry.
// Standalone Invoke has no authorizer, so it refuses an explicit out-of-project directory in-band:
// only the dispatch path can obtain the required approval. The in-project path is unchanged.
func (t *TreeTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.ExternalReadScope(scope) {
		return externalReadDispatchOnly(TreeToolName), nil
	}
	return t.tree(target, args), nil
}

// tree walks dir via the shared walker and returns its entries as a recursive listing in the walker's
// pre-order (directory before its descendants, siblings ascending by name) bounded by `depth` and the
// total-entry `limit`, rendered in the `format` layout (`ai` project-relative paths by default, `human`
// indented basenames). Every precondition failure — an unknown argument, an out-of-range/wrong-type depth
// or limit, an unrecognized format, a non-boolean flag, a swapped-to-symlink root, a non-directory path, or
// a traversal error — returns a non-zero-exit result so the model can correct itself in-band rather than
// aborting the turn. An empty directory (or depth 0) is a success with empty output, not an error
func (t *TreeTool) tree(dir string, args map[string]any) tools.Result {
	if verr := ValidatePhase1ReadArgs(TreeToolName, args); verr != nil {
		return failResult(verr.Error())
	}

	depthPtr, _ := optionalIntArg(args, "depth")
	limitPtr, _ := optionalIntArg(args, "limit")
	limit := TreeDefaultLimit
	if limitPtr != nil {
		limit = *limitPtr
	}

	includeHidden, _ := optionalBoolArg(args, "include_hidden")
	includeIgnored, _ := optionalBoolArg(args, "include_ignored")

	format, _ := optionalStringArg(args, "format")
	if format == "" {
		format = treeFormatAI
	}

	// Re-validate the resolved directory immediately before walking, mirroring grep/list: ResolveTarget
	// refused a directory-symlink `path` before authorization, but the authorized directory could be swapped
	// for a symlink between resolution and this invocation, and Walk begins with os.ReadDir(dir), which
	// follows a symlink root — so without this guard a swapped root would redirect the walk outside the
	// authorized tree. A non-existent path surfaces as the lstat error (a normal not-found), and a
	// non-directory path — a regular file named as `path` — is rejected in-band.
	info, lstatErr := os.Lstat(dir)
	if lstatErr != nil {
		return failResult("tree target rejected: cannot walk the path: " + lstatErr.Error())
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return failResult("tree target rejected: recursive tools do not follow a symlink to a directory")
	}
	if !info.IsDir() {
		return failResult("tree target rejected: path is not a directory")
	}

	// depth 0 means no descendants under the resolved root: an empty success, distinct from the
	// walker's MaxDepth 0 which means *unlimited*. Short-circuit before walking so the two zero meanings do
	// not collide; the root guard above still ran, so a non-directory/swapped-symlink path is rejected even
	// at depth 0.
	if depthPtr != nil && *depthPtr == 0 {
		return BoundedResult(nil, false, 0, t.outputCap)
	}

	// Map the tool's `depth` onto the walker's MaxDepth: an omitted depth is the full subtree (MaxDepth 0 =
	// unlimited), and depth N (>= 1) caps descent at N levels (the walker's MaxDepth semantics match for N >=
	// 1). The walker applies the depth cap during descent and counts only emitted entries toward `limit`, so
	// deeper-than-depth descendants never consume the visible entry budget and truncation is reported when
	// more entries exist than the limit admits (task note).
	maxDepth := 0
	if depthPtr != nil {
		maxDepth = *depthPtr
	}

	// Anchor emitted paths and the ignore matchers at the project root for an in-project walk, or at the
	// approved external directory for an out-of-project read, so external "ai"-format paths stay
	// clean (project-root-relative paths would otherwise carry a ".." prefix) and the matchers see the
	// same base.
	anchor := readAnchor(dir, t.projectRoot)

	// Load the default codemeldignore filter set unless include_ignored disables it. A
	// malformed pattern surfaces in-band; include_ignored skips reading the file entirely.
	var ignore []IgnoreMatcher
	if !includeIgnored {
		matchers, ierr := defaultIgnoreMatchers(anchor, t.home)
		if ierr != nil {
			return failResult("tree target rejected: " + ierr.Error())
		}
		ignore = matchers
	}

	var leftOut []string
	entries, truncated, werr := Walk(WalkOptions{
		Root:           dir,
		ProjectRoot:    anchor,
		Limit:          limit,
		MaxDepth:       maxDepth,
		IncludeHidden:  includeHidden,
		IncludeIgnored: includeIgnored,
		Ignore:         ignore,
		Blocked:        t.blocked,
		OnBlocked:      func(p string) { leftOut = append(leftOut, p) },
	})
	if werr != nil {
		return withLeftOut(failResult("tree target rejected: cannot walk the path: "+werr.Error()), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
	}

	var buf strings.Builder
	for _, e := range entries {
		// Both layouts share the walker's pre-order entries, the trailing "/" on real directories, and the
		// per-newline framing; they differ only in the line body. "ai" writes the entry's project-relative,
		// slash-normalized path verbatim (the walker's RelPath). "human" writes the basename indented one unit
		// per level below the resolved root — immediate children (Depth 1) carry none — and because the walker
		// emits entries in pre-order a directory always precedes its more-indented descendants.
		if format == treeFormatHuman {
			for i := 1; i < e.Depth; i++ {
				buf.WriteString(treeIndentUnit)
			}
			buf.WriteString(filepath.Base(e.AbsPath))
		} else {
			buf.WriteString(e.RelPath)
		}
		if e.Kind == EntryDir {
			buf.WriteByte('/') // mark real directories; a symlink (even to a directory) is a non-descended leaf
		}
		buf.WriteByte('\n')
	}
	// nextOffset is 0: tree is an entry-listing tool, so it carries no read-style line continuation.
	return withLeftOut(BoundedResult([]byte(buf.String()), truncated, 0, t.outputCap), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
}
