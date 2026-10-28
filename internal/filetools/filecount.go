// Built-in file_count tool: counts the entries under a directory, optionally filtered and grouped.
package filetools

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// FileCountToolName is the exact dispatch name the structured file_count tool registers under. Like
// `read`/`glob`/`grep`/`tree` it is a fixed built-in name carrying no template namespace.
const FileCountToolName = "file_count"

// FileCountDefaultLimit and FileCountMaxLimit bound the `limit` argument, which caps how many groups the
// grouped output shows (the remainder is folded into `other`). They mirror the grep/glob/tree entry-limit
// constants; the whole subtree is always walked and counted regardless of `limit` — only the number of
// visible groups is bounded.
const (
	FileCountDefaultLimit = 250
	FileCountMaxLimit     = 5000
)

// group_by modes. Each selects how a counted entry is keyed in the aggregated breakdown.
const (
	groupByExtension = "extension" // file extension (e.g. ".go"); a directory is "(dir)", a no-extension file "(none)"
	groupByTopDir    = "top_dir"   // first path segment below the counted directory; a direct child is "(root)"
	groupByParentDir = "dir"       // immediate parent directory; a direct child is "(root)"
	groupByDepth     = "depth"     // 1-based depth below the counted directory
	groupByStem      = "stem"      // file basename with only the final extension removed (cat.png, cat.webp -> cat)
)

// Sentinel group keys for entries with no natural key in a given mode.
const (
	groupKeyRoot      = "(root)" // direct child of the counted directory (top_dir / dir)
	groupKeyNoneExt   = "(none)" // file with no extension (extension)
	groupKeyDirMarker = "(dir)"  // a directory entry (extension)
	groupKeyOther     = "other"  // folded remainder once `limit` truncates the visible groups
)

type FileCountTool struct {
	home        string
	processCWD  string
	projectRoot string
	outputCap   int
	blocked     *permissions.BlockedPaths
}

var _ tools.Tool = (*FileCountTool)(nil)

func (t *FileCountTool) SetBlockedPaths(blocked *permissions.BlockedPaths) { t.blocked = blocked }

func NewFileCountTool(home, processCWD, projectRoot string, outputCap int) *FileCountTool {
	return &FileCountTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot), outputCap: outputCap}
}

func (t *FileCountTool) Name() string { return FileCountToolName }

func (t *FileCountTool) SubjectKind() string { return "tool" }

func (t *FileCountTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Count filesystem entries under a directory inside or outside the project. Prefer this over shell or Python " +
			"(ls|wc, find, os.walk, glob) for any file-counting task its filters can express — path, kinds, " +
			"include_globs, and exclude_globs cover most \"how many X files\" questions in one read-only call; reach " +
			"for shell/Python only when the filter genuinely cannot be expressed here, or after a correctable " +
			"file_count error. path is the directory to walk (default project root). kinds selects which entry types " +
			"to count (any of file, dir, symlink, other; default file only). include_globs/exclude_globs keep only " +
			"entries whose path (relative to path, with ** for recursive matching) matches an include and no exclude. " +
			"kinds, include_globs, and exclude_globs are JSON arrays, not comma- or newline-delimited strings: pass " +
			"kinds [\"file\"] not \"file\", include_globs [\"**/*.png\"] not \"*.png\", and exclude_globs " +
			"[\"**/*_thumb.*\"] not \"*_thumb.*\". Example — count images under prefix folders while " +
			"skipping thumbnails: include_globs [\"g_*/**\",\"v_*/**\"], exclude_globs [\"th_*/**\",\"**/*_thumb.*\"], " +
			"kinds [\"file\"]. group_by breaks the count down by \"extension\", \"top_dir\" (top-level directory), " +
			"\"dir\" (parent directory), \"depth\", or \"stem\" (file basename across formats, e.g. cat.png/cat.webp/cat.json " +
			"-> cat); groups are sorted by descending count then key, and limit caps " +
			"how many groups are shown with the remainder folded into \"other\" so the visible counts plus other " +
			"equal the total. Hidden (dot-prefixed) entries are skipped unless include_dotfiles is set; codemeldignore " +
			"entries are skipped unless include_ignored is set; a symlink is counted as a leaf and never followed. " +
			"Use to size a tree or see how files are distributed.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Directory to walk. Defaults to the project root when omitted. Relative paths resolve against the project root. An explicitly named absolute or ~ directory outside the project is walked without asking unless it is blocked, in which case it is refused; while a settings file is broken, so that the blocked-path list is unknown, such a walk asks first. Blocked entries beneath an allowed directory do not refuse the walk: they are left out of the count and reported as left out (blocked). A relative path that leaves the project through `..` or through a symlink inside the project is refused, as are ~user forms, malformed paths, and a path that is a symlink to a directory, even one named explicitly outside the project.",
				},
				"kinds": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string", "enum": []string{string(EntryFile), string(EntryDir), string(EntrySymlink), string(EntryOther)}},
					"description": "Entry kinds to count: any of \"file\", \"dir\", \"symlink\", \"other\". Defaults to [\"file\"] when omitted; must list at least one kind when given.",
				},
				"include_globs": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "JSON array of globs (e.g. [\"g_*/**\",\"**/*.png\"]), not a comma- or newline-delimited string. Keep only entries whose path (relative to path, slash-separated, ** allowed) matches at least one of these globs. Omit to keep every entry.",
				},
				"exclude_globs": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "JSON array of globs (e.g. [\"th_*/**\",\"**/*_thumb.*\"]), not a comma- or newline-delimited string. Drop entries whose path (relative to path, slash-separated, ** allowed) matches any of these globs — useful to exclude thumbnails from an image count. Applied after include_globs.",
				},
				"group_by": map[string]any{
					"type":        "string",
					"enum":        []string{groupByExtension, groupByTopDir, groupByParentDir, groupByDepth, groupByStem},
					"description": "Break the count down by \"extension\" (\"(dir)\" for directories, \"(none)\" for no-extension files), \"top_dir\" (top-level directory, \"(root)\" for direct children), \"dir\" (parent directory, \"(root)\" for direct children), \"depth\", or \"stem\" (file basename with the final extension removed, so cat.png/cat.webp/cat.json group under cat). Omit for a flat total only.",
				},
				"include_dotfiles": map[string]any{
					"type":        "boolean",
					"description": "Include hidden (dot-prefixed) files and directories. Default false.",
				},
				"include_ignored": map[string]any{
					"type":        "boolean",
					"description": "Include entries normally excluded by codemeldignore rules from .codemeld/codemeldignore and ~/.codemeld/global/codemeldignore. Default false.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Maximum number of groups to show when group_by is set; the rest are folded into \"other\". Default %d; must be between 1 and %d.", FileCountDefaultLimit, FileCountMaxLimit),
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
// resolved target and the path scope to authorize, mirroring grep/glob/tree's target-scoped contract so
// authorization and the directory actually walked cannot drift. It rejects unknown arguments, then delegates
// to ResolveReadTarget in optional-path mode (an omitted/blank `path` defaults to the project root)
// with RejectDirectorySymlink set so a directory-symlink `path` argument is refused fail-closed before a
// recursive walk could be redirected through it. Remaining argument validation is deferred to invocation.
func (t *FileCountTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownPhase1ReadArgs(FileCountToolName, args); verr != nil {
		return "", "", &TargetError{Kind: FileCountToolName, Reason: verr.Error()}
	}
	return ResolveReadTarget(t.home, t.processCWD, t.projectRoot, args, ReadTargetOptions{
		RequirePath:            false,
		Kind:                   FileCountToolName,
		RejectDirectorySymlink: true,
		AllowExternal:          true,
	})
}

func (t *FileCountTool) ExternalReadScope(scope string) bool {
	return isExternalReadScope(scope, t.projectRoot)
}

// InvokeWithResolvedTarget counts the directory dispatch already resolved before authorization, so the
// authorized directory and the directory actually walked cannot diverge if a symlink changes in between —
// the same reuse-at-invoke contract grep/glob/tree follow. It is the production invocation path; the
// registered tool implements it so DispatchTool reuses the authorized target.
func (t *FileCountTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.count(resolvedTarget, args), nil
}

// Invoke resolves the directory and counts it in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveTarget then InvokeWithResolvedTarget; this keeps the tool a complete unit
// for direct callers and tests. A target-resolution failure surfaces as the same in-band error result the
// dispatcher would render, so the observable outcome matches either entry.
func (t *FileCountTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.ExternalReadScope(scope) {
		return externalReadDispatchOnly(FileCountToolName), nil
	}
	return t.count(target, args), nil
}

// count walks dir via the shared walker, keeps the entries matching `kinds` and the
// include/exclude globs, and returns either a flat total or — when `group_by` is set — a deterministic
// breakdown bounded by `limit` with an `other:` remainder. Every precondition failure — an unknown argument,
// a wrong-type/out-of-range limit, a malformed/wrong-type kinds or glob list, an unrecognized group_by, a
// swapped-to-symlink root, a non-directory path, or a traversal error — returns a non-zero-exit result so
// the model can correct itself in-band rather than aborting the turn. An empty directory is a success
// reporting total 0, not an error.
func (t *FileCountTool) count(dir string, args map[string]any) tools.Result {
	if verr := ValidatePhase1ReadArgs(FileCountToolName, args); verr != nil {
		return failResult(verr.Error())
	}

	limitPtr, _ := optionalIntArg(args, "limit")
	limit := FileCountDefaultLimit
	if limitPtr != nil {
		limit = *limitPtr
	}

	includeDotfiles, _ := optionalBoolArg(args, "include_dotfiles")
	includeIgnored, _ := optionalBoolArg(args, "include_ignored")
	kinds, _ := resolveFileCountKinds(args)
	groupBy, _ := optionalStringArg(args, "group_by")
	includeGlobs, _ := optionalStringSliceArg(args, "include_globs")
	excludeGlobs, _ := optionalStringSliceArg(args, "exclude_globs")

	// Re-validate the resolved directory immediately before walking, mirroring grep/glob/tree: ResolveTarget
	// refused a directory-symlink `path` before authorization, but the authorized directory could be swapped
	// for a symlink between resolution and this invocation, and Walk begins with os.ReadDir(dir), which
	// follows a symlink root — so without this guard a swapped root would redirect the walk outside the
	// authorized tree.
	info, lstatErr := os.Lstat(dir)
	if lstatErr != nil {
		return failResult(FileCountToolName + " target rejected: cannot walk the path: " + lstatErr.Error())
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return failResult(FileCountToolName + " target rejected: recursive tools do not follow a symlink to a directory")
	}
	if !info.IsDir() {
		return failResult(FileCountToolName + " target rejected: path is not a directory")
	}

	anchor := readAnchor(dir, t.projectRoot)

	var ignore []IgnoreMatcher
	if !includeIgnored {
		matchers, ierr := defaultIgnoreMatchers(anchor, t.home)
		if ierr != nil {
			return failResult(FileCountToolName + " target rejected: " + ierr.Error())
		}
		ignore = matchers
	}

	// Walk the whole subtree unbounded and bound the visible *groups* below, not the walked entries: a count
	// must consider every entry, so capping the walk would silently undercount. MaxDepth 0 is recursive.
	var leftOut []string
	entries, _, werr := Walk(WalkOptions{
		Root:           dir,
		ProjectRoot:    anchor,
		Limit:          0,
		MaxDepth:       0,
		IncludeHidden:  includeDotfiles,
		IncludeIgnored: includeIgnored,
		Ignore:         ignore,
		Blocked:        t.blocked,
		OnBlocked:      func(p string) { leftOut = append(leftOut, p) },
	})
	if werr != nil {
		return withLeftOut(failResult(FileCountToolName+" target rejected: cannot walk the path: "+werr.Error()), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
	}

	groups, total, aerr := aggregateFileCount(dir, entries, kinds, includeGlobs, excludeGlobs, groupBy)
	if aerr != nil {
		return failResult(aerr.Error())
	}

	out, truncated := renderFileCount(total, groupBy, groups, limit)
	// nextOffset is 0: file_count is not a read-style line-paginated tool.
	return withLeftOut(BoundedResult([]byte(out), truncated, 0, t.outputCap), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
}

// groupCount is one aggregated group: its key and the number of counted entries that map to it.
type groupCount struct {
	key   string
	count int
}

// aggregateFileCount filters the walker entries by kind and the include/exclude globs, counts the survivors
// into total, and — when groupBy is set — tallies them into groups sorted by descending count then ascending
// key. Glob matching is against each entry's path relative to dir (slash-normalized), so the patterns are
// anchored at the counted directory regardless of where it sits in the project. Patterns are pre-validated,
// so a doublestar.Match error is unexpected but surfaced in-band defensively.
func aggregateFileCount(dir string, entries []WalkEntry, kinds map[EntryKind]bool, includeGlobs, excludeGlobs []string, groupBy string) (groups []groupCount, total int, err error) {
	tally := map[string]int{}
	for _, e := range entries {
		if !kinds[e.Kind] {
			continue
		}
		rel, rerr := filepath.Rel(dir, e.AbsPath)
		if rerr != nil {
			return nil, 0, fmt.Errorf("%s target rejected: cannot relativize %q: %v", FileCountToolName, e.AbsPath, rerr)
		}
		relSlash := filepath.ToSlash(rel)
		ok, merr := globsAllow(relSlash, includeGlobs, excludeGlobs)
		if merr != nil {
			return nil, 0, merr
		}
		if !ok {
			continue
		}
		total++
		if groupBy == "" {
			continue
		}
		tally[fileCountGroupKey(groupBy, relSlash, e)]++
	}
	for k, c := range tally {
		groups = append(groups, groupCount{key: k, count: c})
	}
	// Descending count, then ascending key, so ordering is fully deterministic across runs and platforms.
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].count != groups[j].count {
			return groups[i].count > groups[j].count
		}
		return groups[i].key < groups[j].key
	})
	return groups, total, nil
}

// fileCountGroupKey maps one entry (relSlash is its dir-relative, slash-separated path) to its group key for
// the given mode. depth uses the walker's Depth (entries directly under the counted directory are depth 1).
func fileCountGroupKey(mode, relSlash string, e WalkEntry) string {
	switch mode {
	case groupByExtension:
		if e.Kind == EntryDir {
			return groupKeyDirMarker
		}
		ext := path.Ext(relSlash)
		if ext == "" {
			return groupKeyNoneExt
		}
		return ext
	case groupByTopDir:
		if i := strings.IndexByte(relSlash, '/'); i >= 0 {
			return relSlash[:i]
		}
		return groupKeyRoot
	case groupByParentDir:
		parent := path.Dir(relSlash)
		if parent == "." {
			return groupKeyRoot
		}
		return parent
	case groupByDepth:
		return strconv.Itoa(e.Depth)
	case groupByStem:
		base := path.Base(relSlash)
		if e.Kind != EntryFile {
			return base
		}
		// Drop only the final extension; an all-extension basename like ".env" would trim to "" so keep the base.
		if stem := strings.TrimSuffix(base, path.Ext(base)); stem != "" {
			return stem
		}
		return base
	}
	return ""
}

// renderFileCount formats the result: a leading "total: N" line, then (when groupBy is set) one "key: count"
// line per group in sorted order, bounded by limit with the folded remainder on a trailing "other: M" line.
// The returned bool reports whether grouping truncation withheld groups, driving BoundedResult's indicator.
// Because every counted entry maps to exactly one group, the visible counts plus other always equal total.
func renderFileCount(total int, groupBy string, groups []groupCount, limit int) (string, bool) {
	var buf strings.Builder
	fmt.Fprintf(&buf, "total: %d\n", total)
	if groupBy == "" {
		return buf.String(), false
	}
	truncated := len(groups) > limit
	other := 0
	if truncated {
		for _, g := range groups[limit:] {
			other += g.count
		}
		groups = groups[:limit]
	}
	for _, g := range groups {
		fmt.Fprintf(&buf, "%s: %d\n", g.key, g.count)
	}
	if truncated {
		fmt.Fprintf(&buf, "%s: %d\n", groupKeyOther, other)
	}
	return buf.String(), truncated
}

// resolveFileCountKinds reads the optional `kinds` argument into the set of entry kinds to count. An omitted
// `kinds` defaults to files only; a present value must be a non-empty array of strings, each one of file,
// dir, symlink, or other. A wrong type, an empty list, a non-string member, or an unrecognized kind is an
// in-band rejection.
func resolveFileCountKinds(args map[string]any) (map[EntryKind]bool, error) {
	raw, ok := args["kinds"]
	if !ok {
		return map[EntryKind]bool{EntryFile: true}, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("argument %q must be an array of strings", "kinds")
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("argument %q must list at least one kind", "kinds")
	}
	set := make(map[EntryKind]bool, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("argument %q[%d] must be a string", "kinds", i)
		}
		switch k := EntryKind(s); k {
		case EntryFile, EntryDir, EntrySymlink, EntryOther:
			set[k] = true
		default:
			return nil, fmt.Errorf("argument %q[%d] %q must be one of %q, %q, %q, or %q", "kinds", i, s, EntryFile, EntryDir, EntrySymlink, EntryOther)
		}
	}
	return set, nil
}

// optionalStringSliceArg pulls an optional list-of-strings argument out of the decoded tool arguments,
// returning nil when the key is absent. A present-but-non-array value, or a non-string member, is an error
// so a malformed list surfaces in-band rather than being silently coerced.
func optionalStringSliceArg(args map[string]any, key string) ([]string, error) {
	raw, ok := args[key]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("argument %q must be an array of strings", key)
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("argument %q[%d] must be a string", key, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// validateGlobPatterns rejects an empty or malformed doublestar pattern in the named list before walking, so
// a bad pattern is a deterministic in-band rejection independent of whether any entry would exercise it.
func validateGlobPatterns(arg string, patterns []string) error {
	for _, p := range patterns {
		if p == "" {
			return fmt.Errorf("%s target rejected: %s contains an empty pattern", FileCountToolName, arg)
		}
		if !doublestar.ValidatePattern(p) {
			return fmt.Errorf("%s target rejected: malformed glob pattern %q in %s", FileCountToolName, p, arg)
		}
	}
	return nil
}

// globsAllow reports whether relSlash (a dir-relative, slash-separated path) passes the include/exclude
// filters: it must match at least one include glob (or there are none) and must not match any exclude glob.
// Patterns are pre-validated, so a doublestar.Match error is unexpected but surfaced in-band defensively.
func globsAllow(relSlash string, includeGlobs, excludeGlobs []string) (bool, error) {
	if len(includeGlobs) > 0 {
		matched := false
		for _, p := range includeGlobs {
			ok, err := doublestar.Match(p, relSlash)
			if err != nil {
				return false, fmt.Errorf("%s target rejected: malformed glob pattern %q: %v", FileCountToolName, p, err)
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	for _, p := range excludeGlobs {
		ok, err := doublestar.Match(p, relSlash)
		if err != nil {
			return false, fmt.Errorf("%s target rejected: malformed glob pattern %q: %v", FileCountToolName, p, err)
		}
		if ok {
			return false, nil
		}
	}
	return true, nil
}

// validGroupBy reports whether mode is one of the recognized group_by values.
func validGroupBy(mode string) bool {
	switch mode {
	case groupByExtension, groupByTopDir, groupByParentDir, groupByDepth, groupByStem:
		return true
	}
	return false
}
