// Built-in list tool: lists a directory's immediate entries.
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

// ListToolName is the exact dispatch name the structured list tool registers under. Like
// `read`/`glob`/`grep`/`edit`/`create`/`bash` it is a fixed built-in name carrying no template namespace.
const ListToolName = "list"

// listEntrySeparator joins each entry's type and name on its output line. A tab keeps the two columns
// unambiguous even for a name containing spaces: the type token (file/dir/symlink/other) never contains a
// tab, so a consumer recovers the name as everything after the first tab.
const listEntrySeparator = "\t"

// ListTool is the built-in read-only list tool. It returns the immediate (non-recursive)
// entries of a directory under an optional `path` (default project root): each entry's name and type
// (file / dir / symlink), in deterministic ascending name order, bounded by a per-tool `limit` with the
// truncation indicator. It is read-only (Advertise().ReadOnly == true), so it auto-allows without
// prompting in every mode. It drives the shared walker in single-level mode (MaxDepth 1), so
// descendants are never traversed, filtered, or counted against the limit — keeping list's output,
// hidden/ignore filtering, and limit accounting strictly to the directory's own entries. The
// run-scoped home, process cwd, project root, and the configured tool-output byte cap are bound at
// construction so target resolution matches the permission path-scope rules and the truncation indicator
// survives the same byte cap as every other tool output.
type ListTool struct {
	home        string
	processCWD  string
	projectRoot string
	outputCap   int
	blocked     *permissions.BlockedPaths
}

var _ tools.Tool = (*ListTool)(nil)

func (t *ListTool) SetBlockedPaths(blocked *permissions.BlockedPaths) { t.blocked = blocked }

func NewListTool(home, processCWD, projectRoot string, outputCap int) *ListTool {
	return &ListTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot), outputCap: outputCap}
}

func (t *ListTool) Name() string { return ListToolName }

func (t *ListTool) SubjectKind() string { return "tool" }

// Advertise returns the list tool's advertising metadata and read-only classification.
// The parameter JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so the
// advertised contract matches the decoder exactly: every argument is optional — `path`, `limit`,
// `include_ignored`, and `include_hidden`. ReadOnly is true: list never mutates, so it is advertised in
// Plan and auto-allowed in every mode.
func (t *ListTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "List the immediate (non-recursive) entries of a directory inside or outside the project. path is " +
			"the directory to list (default project root); limit caps the entries returned (default " +
			fmt.Sprintf("%d, max %d", ListDefaultLimit, ListMaxLimit) + "). Hidden (dot-prefixed) entries are " +
			"skipped unless include_hidden is set. Each line is the entry type and name separated by a tab, as " +
			"\"<type>\\t<name>\", where type is dir, file, symlink, or other (special files); a symlink is " +
			"reported as symlink and never followed. Entries are in ascending name order; when more entries " +
			"exist than the limit, the result signals truncation. Use to see what a directory contains.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Directory to list. Defaults to the project root when omitted. Relative paths resolve against the project root. An explicitly named absolute or ~ directory outside the project is listed without asking unless it is blocked, in which case it is refused; while a settings file is broken, so that the blocked-path list is unknown, such a listing asks first. A relative path that leaves the project through `..` or through a symlink inside the project is refused, as are ~user forms and malformed paths.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Maximum number of entries to return. Default %d; must be between 1 and %d.", ListDefaultLimit, ListMaxLimit),
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

// ResolveTarget resolves the directory to list from args before authorization and returns it as both the
// resolved target and the path scope to authorize, mirroring read/glob's target-scoped contract so
// authorization and the directory actually listed cannot drift. It rejects unknown arguments, then
// delegates to ResolveReadTarget in optional-path mode (an omitted/blank `path` defaults to the
// project root). RejectDirectorySymlink is left false: list is non-recursive, so a symlinked
// directory `path` is resolved to its real target and listed (the resolver still rejects a symlink
// that escapes the root), while a symlink *entry inside* the listed directory is reported as type symlink
// and never descended. Numeric/boolean validation is deferred to invocation, as read/glob defer theirs.
func (t *ListTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownPhase1ReadArgs(ListToolName, args); verr != nil {
		return "", "", &TargetError{Kind: ListToolName, Reason: verr.Error()}
	}
	return ResolveReadTarget(t.home, t.processCWD, t.projectRoot, args, ReadTargetOptions{
		RequirePath:            false,
		Kind:                   ListToolName,
		RejectDirectorySymlink: false,
		AllowExternal:          true,
	})
}

func (t *ListTool) ExternalReadScope(scope string) bool {
	return isExternalReadScope(scope, t.projectRoot)
}

// InvokeWithResolvedTarget lists the directory dispatch already resolved before authorization, so the
// authorized directory and the directory actually listed cannot diverge if a symlink changes in between —
// the same reuse-at-invoke contract read/glob/edit/create follow. It is the production invocation path; the
// registered tool implements it so DispatchTool reuses the authorized target.
func (t *ListTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.list(resolvedTarget, args), nil
}

// Invoke resolves the directory and lists it in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveTarget then InvokeWithResolvedTarget; this keeps the tool a complete unit
// for direct callers and tests. A target-resolution failure surfaces as the same in-band error result the
// dispatcher would render, so the observable outcome matches either entry.
func (t *ListTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.ExternalReadScope(scope) {
		return externalReadDispatchOnly(ListToolName), nil
	}
	return t.list(target, args), nil
}

// list lists dir's immediate entries via the shared walker in single-level mode and returns each
// entry's "<type>\t<name>" line in ascending name order bounded by `limit`. Every precondition failure — an
// unknown argument, an out-of-range/wrong-type limit, a non-boolean flag, a path that is not a directory,
// or a traversal error — returns a non-zero-exit result so the model can correct itself in-band rather than
// aborting the turn. An empty directory is a success with empty output, not an error.
func (t *ListTool) list(dir string, args map[string]any) tools.Result {
	if verr := ValidatePhase1ReadArgs(ListToolName, args); verr != nil {
		return failResult(verr.Error())
	}

	limitPtr, _ := optionalIntArg(args, "limit")
	limit := ListDefaultLimit
	if limitPtr != nil {
		limit = *limitPtr
	}

	includeHidden, _ := optionalBoolArg(args, "include_hidden")
	includeIgnored, _ := optionalBoolArg(args, "include_ignored")

	// Re-validate the resolved directory immediately before walking. ResolveReadTarget already followed any
	// legitimate symlink `path` and returned the real directory, so a symlink here can only be a
	// post-authorization swap; Walk begins with os.ReadDir(dir), which follows a symlink root, so without
	// this guard a swapped root would redirect the listing outside the authorized directory. A
	// non-existent path surfaces as the lstat error (a normal not-found), and a non-directory path — a
	// regular file named as `path` — is rejected in-band. This mirrors glob's pre-walk root guard.
	info, lstatErr := os.Lstat(dir)
	if lstatErr != nil {
		return failResult("list target rejected: cannot list the path: " + lstatErr.Error())
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return failResult("list target rejected: the path changed to a symlink after authorization")
	}
	if !info.IsDir() {
		return failResult("list target rejected: path is not a directory")
	}

	anchor := readAnchor(dir, t.projectRoot)

	// Load the default codemeldignore filter set unless include_ignored disables it. A
	// malformed pattern surfaces in-band; include_ignored skips reading the file entirely.
	var ignore []IgnoreMatcher
	if !includeIgnored {
		matchers, ierr := defaultIgnoreMatchers(anchor, t.home)
		if ierr != nil {
			return failResult("list target rejected: " + ierr.Error())
		}
		ignore = matchers
	}

	// Drive the walker in single-level mode (MaxDepth 1): only the directory's immediate children are
	// emitted, so descendants are never traversed, filtered, or counted against the limit. The
	// walker's hidden-skip and ignore seam apply before an entry is counted, and its
	// os.ReadDir-sourced ordering yields ascending name order at a single level. Limit is the per-tool limit:
	// the walker emits at most that many entries and reports truncation when more immediate entries remain.
	var leftOut []string
	entries, truncated, werr := Walk(WalkOptions{
		Root:           dir,
		ProjectRoot:    anchor,
		Limit:          limit,
		MaxDepth:       1,
		IncludeHidden:  includeHidden,
		IncludeIgnored: includeIgnored,
		Ignore:         ignore,
		Blocked:        t.blocked,
		OnBlocked:      func(p string) { leftOut = append(leftOut, p) },
	})
	if werr != nil {
		return withLeftOut(failResult("list target rejected: cannot list the path: "+werr.Error()), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
	}

	var buf strings.Builder
	for _, e := range entries {
		buf.WriteString(string(e.Kind))
		buf.WriteString(listEntrySeparator)
		buf.WriteString(filepath.Base(e.AbsPath))
		buf.WriteByte('\n')
	}
	// nextOffset is 0: list is an entry-listing tool, so it carries no read-style line continuation.
	return withLeftOut(BoundedResult([]byte(buf.String()), truncated, 0, t.outputCap), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
}
