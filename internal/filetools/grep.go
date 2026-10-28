// Built-in grep tool: searches file contents for an RE2 regular expression.
package filetools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// GrepToolName is the exact dispatch name the structured grep tool registers under. Like
// `read`/`glob`/`edit`/`create`/`bash` it is a fixed built-in name carrying no template namespace.
const GrepToolName = "grep"

// grepNoticePrefix marks the binary-file-skip notice grep appends to stderr *after* the truncation metadata
// line. It is kept off stdout so the match output stays a clean, parseable stream of
// path:line:match/context lines, and after the metadata line so the truncation indicator still wins the
// byte-cap prefix.
const grepNoticePrefix = "codemeld-grep: "

// GrepTool is the built-in read-only grep tool. It searches the contents of regular
// files under an optional `path` (default project root) for an RE2 regular expression `pattern`, emitting
// matches deterministically by ascending project-relative path then ascending line number. It is read-only
// (Advertise.ReadOnly == true), so it auto-allows without prompting in every mode. Traversal
// runs through the shared walker (hidden-skip by default, the ignore seam, directory-symlink
// no-follow); the walker is run unbounded so every eligible file is searched and only the *match* count is
// bounded by `limit` — searching a capped set of files could miss matches in later files. The
// run-scoped home, process cwd, project root, and the configured tool-output byte cap are bound at
// construction so target resolution matches the permission path-scope rules and the truncation indicator
// survives the same byte cap as every other tool output.
type GrepTool struct {
	home        string
	processCWD  string
	projectRoot string
	outputCap   int
	blocked     *permissions.BlockedPaths
}

var _ tools.Tool = (*GrepTool)(nil)

func (t *GrepTool) SetBlockedPaths(blocked *permissions.BlockedPaths) { t.blocked = blocked }

func NewGrepTool(home, processCWD, projectRoot string, outputCap int) *GrepTool {
	return &GrepTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot), outputCap: outputCap}
}

func (t *GrepTool) Name() string { return GrepToolName }

func (t *GrepTool) SubjectKind() string { return "tool" }

// Advertise returns the grep tool's advertising metadata and read-only classification.
// The parameter JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so the
// advertised contract matches the decoder exactly: `pattern` is the only required argument.
// ReadOnly is true: grep never mutates, so it is advertised in Plan and auto-allowed in every
// mode.
func (t *GrepTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Search the contents of files inside or outside the project for a regular-expression pattern (Go RE2 syntax). " +
			"pattern is required; path is the directory to search under (default project root) or a single file " +
			"to search; include is a glob on file names (e.g. \"*.go\"); case_insensitive matches without case; context is the number " +
			"of lines shown before and after each match; limit caps the number of matches (default " +
			fmt.Sprintf("%d, max %d", GrepDefaultLimit, GrepMaxLimit) + "); files_only returns just the matching " +
			"file paths. Hidden (dot-prefixed) entries are skipped unless include_hidden is set. Output is " +
			"ordered by ascending project-relative path then line number, with match and context lines " +
			"distinguished; when more match than the limit, the result signals truncation. Binary files are " +
			"skipped. Use to find where text or code appears.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pattern": map[string]any{
					"type": "string",
					"description": "Regular expression to search for, using Go's RE2 syntax. PCRE-only features " +
						"(backreferences, lookaround) are not supported and are rejected with the compile error.",
				},
				"path": map[string]any{
					"type":        "string",
					"description": "Directory to search under, or a single file to search. include, include_hidden and include_ignored do not filter out a named file. Defaults to the project root when omitted. Relative paths resolve against the project root. An explicitly named absolute or ~ directory or file outside the project is searched without asking unless it is blocked, in which case it is refused; while a settings file is broken, so that the blocked-path list is unknown, such a search asks first. A relative path that leaves the project through `..` or through a symlink inside the project is refused, as are ~user forms and malformed paths.",
				},
				"include": map[string]any{
					"type":        "string",
					"description": "Glob matched against each file's name (the basename, not its path), e.g. \"*.go\". Only matching files are searched. Omit to search every file.",
				},
				"case_insensitive": map[string]any{
					"type":        "boolean",
					"description": "Match without regard to letter case. Default false.",
				},
				"context": map[string]any{
					"type":        "integer",
					"description": "Number of lines to show before and after each match. Default 0; must be >= 0.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": fmt.Sprintf("Maximum number of matches (matching files in files_only mode) to return. Default %d; must be between 1 and %d. Context lines do not count toward this limit.", GrepDefaultLimit, GrepMaxLimit),
				},
				"files_only": map[string]any{
					"type":        "boolean",
					"description": "Return only the paths of files that contain a match, not the matching lines. Default false.",
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
// resolved target and the path scope to authorize, mirroring glob's target-scoped contract so
// authorization and the directory actually walked cannot drift. It rejects unknown arguments, then
// delegates to ResolveReadTarget in optional-path mode (an omitted/blank `path` defaults to the
// project root) with RejectDirectorySymlink set so a directory-symlink `path` argument is refused
// fail-closed before a recursive walk could be redirected through it. Pattern, include, and
// numeric/boolean validation are deferred to invocation, as glob defers its pattern/limit checks.
func (t *GrepTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownPhase1ReadArgs(GrepToolName, args); verr != nil {
		return "", "", &TargetError{Kind: GrepToolName, Reason: verr.Error()}
	}
	return ResolveReadTarget(t.home, t.processCWD, t.projectRoot, args, ReadTargetOptions{
		RequirePath:            false,
		Kind:                   GrepToolName,
		RejectDirectorySymlink: true,
		AllowExternal:          true,
	})
}

func (t *GrepTool) ExternalReadScope(scope string) bool {
	return isExternalReadScope(scope, t.projectRoot)
}

// InvokeWithResolvedTarget runs grep over the search root dispatch already resolved before authorization,
// so the authorized directory and the directory actually walked cannot diverge if a symlink changes in
// between — the same reuse-at-invoke contract read/glob/edit/create follow. It is the production
// invocation path; the registered tool implements it so DispatchTool reuses the authorized target.
func (t *GrepTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.grep(resolvedTarget, args), nil
}

// Invoke resolves the search root and greps it in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveTarget then InvokeWithResolvedTarget; this keeps the tool a complete unit
// for direct callers and tests. A target-resolution failure surfaces as the same in-band error result the
// dispatcher would render, so the observable outcome matches either entry.
func (t *GrepTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.ExternalReadScope(scope) {
		return externalReadDispatchOnly(GrepToolName), nil
	}
	return t.grep(target, args), nil
}

// grep walks searchRoot via the shared walker, searches each eligible regular file for the RE2
// `pattern`, and returns the matches in deterministic ascending project-relative path then line order,
// bounded by the match `limit`. Every precondition failure — an unknown argument, a missing/empty pattern,
// an uncompilable pattern, a malformed include glob, an out-of-range numeric, a non-boolean flag
// a swapped-to-symlink root, or a traversal error — returns a non-zero-exit result so the model can correct
// itself in-band rather than aborting the turn. No match is a success with empty output, not an
// error.
func (t *GrepTool) grep(searchRoot string, args map[string]any) tools.Result {
	if verr := ValidatePhase1ReadArgs(GrepToolName, args); verr != nil {
		return failResult(verr.Error())
	}

	filesOnly, _ := optionalBoolArg(args, "files_only")
	includeHidden, _ := optionalBoolArg(args, "include_hidden")
	includeIgnored, _ := optionalBoolArg(args, "include_ignored")
	limitPtr, _ := optionalIntArg(args, "limit")
	contextPtr, _ := optionalIntArg(args, "context")
	re, _ := compileGrepPattern(args)
	includeGlob, _ := grepIncludeGlob(args)
	limit := GrepDefaultLimit
	if limitPtr != nil {
		limit = *limitPtr
	}
	contextN := 0
	if contextPtr != nil {
		contextN = *contextPtr
	}

	// Re-validate the traversal root immediately before walking, mirroring glob: ResolveTarget refused a
	// directory-symlink `path` before authorization, but the authorized directory could be swapped for a
	// symlink between resolution and this invocation, and Walk begins with os.ReadDir(searchRoot), which
	// follows a symlink root — so without this guard a swapped root would redirect the walk outside the
	// authorized tree.
	rootInfo, lstatErr := os.Lstat(searchRoot)
	if lstatErr != nil {
		return failResult("grep target rejected: cannot traverse the search path: " + lstatErr.Error())
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return failResult("grep target rejected: recursive tools do not follow a symlink to a directory")
	}
	if rootInfo.Mode().IsRegular() {
		var files []grepCandidate
		var leftOut []string
		if _, blocked := t.blocked.Blocking(searchRoot); blocked {
			leftOut = []string{searchRoot}
		} else {
			rel, _ := filepath.Rel(readAnchor(filepath.Dir(searchRoot), t.projectRoot), searchRoot)
			files = []grepCandidate{{rel: filepath.ToSlash(rel), abs: searchRoot}}
		}
		var res tools.Result
		if filesOnly {
			res = t.searchFilesOnly(files, re, limit)
		} else {
			res = t.searchMatches(files, re, limit, contextN)
		}
		return withLeftOut(res, leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
	}
	if !rootInfo.IsDir() {
		return failResult("grep target rejected: search path is not a directory")
	}

	anchor := readAnchor(searchRoot, t.projectRoot)

	// Load the default codemeldignore filter set unless include_ignored disables it. A
	// malformed pattern surfaces in-band; include_ignored skips reading the file entirely.
	var ignore []IgnoreMatcher
	if !includeIgnored {
		matchers, ierr := defaultIgnoreMatchers(anchor, t.home)
		if ierr != nil {
			return failResult("grep target rejected: " + ierr.Error())
		}
		ignore = matchers
	}

	// Walk unbounded (Limit 0, recursive): grep must search every eligible file to bound *matches*, not
	// candidate files, so capping the walk could silently drop matches in files past the cap.
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
		return withLeftOut(failResult("grep target rejected: cannot traverse the search path: "+werr.Error()), leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
	}

	files := grepCandidates(entries, includeGlob)
	var res tools.Result
	if filesOnly {
		res = t.searchFilesOnly(files, re, limit)
	} else {
		res = t.searchMatches(files, re, limit, contextN)
	}
	return withLeftOut(res, leftOut, t.projectRoot, t.home, t.blocked.FoldCase(), t.outputCap)
}

// grepCandidate is one regular file selected for content search, carrying its project-relative path (the
// ordering/output key) and absolute path (the read target).
type grepCandidate struct {
	rel string
	abs string
}

// grepCandidates selects the regular files to search from the walker entries: only EntryFile entries are
// kept, so a symlink is never read through (the no-follow posture of — a symlink to a file outside
// the root must not be searched), and directories are skipped. When includeGlob is non-empty each file's
// basename must match it (filepath.Match). The result is sorted by ascending project-relative path
// so the search emits matches in the deterministic order requires (a pure path sort, not the
// walker's hierarchical emit order, so "a.go" precedes "a/b.go").
func grepCandidates(entries []WalkEntry, includeGlob string) []grepCandidate {
	var files []grepCandidate
	for _, e := range entries {
		if e.Kind != EntryFile {
			continue
		}
		if includeGlob != "" {
			base := e.RelPath
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			// The pattern was validated up front, so a match error here is not expected; treat a
			// non-match (including any defensive error) as "not included" rather than surfacing it.
			if ok, _ := filepath.Match(includeGlob, base); !ok {
				continue
			}
		}
		files = append(files, grepCandidate{rel: e.RelPath, abs: e.AbsPath})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return files
}

// grepFileMatch holds one file's accepted matches: its lines (so context windows can be rendered) and the
// 1-based line numbers that matched within the global limit.
type grepFileMatch struct {
	rel        string
	lines      []string
	matchLines []int
}

// searchMatches searches each candidate file line by line, accumulating up to `limit` matches across all
// files in path-then-line order, and renders them with merged context windows. The match limit bounds only
// match lines, never context lines: once the (limit+1)th match is found the search stops and the
// result is marked truncated. Binary files are skipped without reading their bytes into the
// output and counted for a trailing notice.
func (t *GrepTool) searchMatches(files []grepCandidate, re *regexp.Regexp, limit, contextN int) tools.Result {
	var results []grepFileMatch
	matchCount := 0
	truncated := false
	binarySkipped := 0

	for _, f := range files {
		content, rerr := os.ReadFile(f.abs)
		if rerr != nil {
			continue // an unreadable file is skipped rather than aborting the whole search
		}
		if isBinaryContent(content) {
			binarySkipped++
			continue // never read binary bytes into the output
		}
		lines := grepFileLines(content)

		var matched []int
		hitLimit := false
		for idx, line := range lines {
			if !re.MatchString(line) {
				continue
			}
			if matchCount >= limit {
				truncated, hitLimit = true, true
				break
			}
			matched = append(matched, idx+1) // 1-based line number
			matchCount++
		}
		if len(matched) > 0 {
			results = append(results, grepFileMatch{rel: f.rel, lines: lines, matchLines: matched})
		}
		if hitLimit {
			break
		}
	}

	var buf strings.Builder
	for _, fr := range results {
		matchSet := make(map[int]bool, len(fr.matchLines))
		for _, m := range fr.matchLines {
			matchSet[m] = true
		}
		// architecture review: merge overlapping or adjacent context windows so a line near two
		// matches is emitted once, and emit each line as match or context.
		for _, rg := range mergeGrepRanges(fr.matchLines, len(fr.lines), contextN) {
			for ln := rg.start; ln <= rg.end; ln++ {
				kind := "context"
				if matchSet[ln] {
					kind = "match"
				}
				fmt.Fprintf(&buf, "%s:%d:%s:%s\n", fr.rel, ln, kind, fr.lines[ln-1])
			}
		}
	}
	return t.boundedWithBinaryNotice(buf.String(), truncated, binarySkipped)
}

// searchFilesOnly returns just the project-relative paths of files that contain at least one match, in
// ascending order, bounded by `limit` matching files. Searching short-circuits at the first
// match in a file. Binary files are skipped and counted for the trailing notice.
func (t *GrepTool) searchFilesOnly(files []grepCandidate, re *regexp.Regexp, limit int) tools.Result {
	var matchedFiles []string
	truncated := false
	binarySkipped := 0

	for _, f := range files {
		content, rerr := os.ReadFile(f.abs)
		if rerr != nil {
			continue
		}
		if isBinaryContent(content) {
			binarySkipped++
			continue
		}
		found := false
		for _, line := range grepFileLines(content) {
			if re.MatchString(line) {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		if len(matchedFiles) >= limit {
			truncated = true // a matching file past the limit: report none past it, signal truncation
			break
		}
		matchedFiles = append(matchedFiles, f.rel)
	}

	var buf strings.Builder
	for _, rel := range matchedFiles { // already ascending: files is path-sorted
		buf.WriteString(rel)
		buf.WriteByte('\n')
	}
	return t.boundedWithBinaryNotice(buf.String(), truncated, binarySkipped)
}

// boundedWithBinaryNotice wraps stdout in the BoundedResult (truncation indicator as the first stderr
// line, byte-cap-safe) and, when binary files were skipped, appends a short notice after that metadata line.
// The notice goes after the metadata so the truncation indicator still wins the byte-cap prefix
// and in stderr rather than stdout so the match stream stays a clean parseable sequence. nextOffset is 0:
// grep is not a line-paginated tool.
func (t *GrepTool) boundedWithBinaryNotice(stdout string, truncated bool, binarySkipped int) tools.Result {
	res := BoundedResult([]byte(stdout), truncated, 0, t.outputCap)
	if binarySkipped > 0 {
		res.Stderr = append(res.Stderr, fmt.Sprintf("%sskipped %d binary file(s)\n", grepNoticePrefix, binarySkipped)...)
	}
	return res
}

// grepRange is a 1-based inclusive line range covering a match and its context window.
type grepRange struct {
	start int
	end   int
}

// mergeGrepRanges turns the ascending match line numbers into the minimal set of 1-based inclusive ranges
// covering each match plus contextN lines on either side, clamped to [1, total], merging overlapping or
// adjacent windows so no line is emitted twice and no spurious gap appears between near matches
// (architecture review). matchLines is assumed ascending (the search collects them in line order).
func mergeGrepRanges(matchLines []int, total, contextN int) []grepRange {
	var out []grepRange
	for _, m := range matchLines {
		s := m - contextN
		if s < 1 {
			s = 1
		}
		e := m + contextN
		if e > total {
			e = total
		}
		if n := len(out); n > 0 && s <= out[n-1].end+1 {
			if e > out[n-1].end {
				out[n-1].end = e
			}
			continue
		}
		out = append(out, grepRange{start: s, end: e})
	}
	return out
}

// grepFileLines splits file content into its lines without the trailing newline, reusing read's
// lineStartOffsets so the line count and numbering match the read tool exactly: "a\nb\n" is two lines, a
// trailing newline does not create a phantom final empty line, and an empty file has no lines. Splitting by
// byte slice (not bufio.Scanner) avoids the scanner's default token-size limit, so a very long source line
// never turns into a silent search failure (task note).
func grepFileLines(content []byte) []string {
	starts := lineStartOffsets(content)
	if len(starts) == 0 {
		return nil
	}
	lines := make([]string, len(starts))
	for i, s := range starts {
		end := len(content)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		seg := content[s:end]
		if n := len(seg); n > 0 && seg[n-1] == '\n' {
			seg = seg[:n-1] // drop the line's own terminator; anchors match per-line via MatchString
		}
		lines[i] = string(seg)
	}
	return lines
}

// optionalStringArg pulls an optional string argument out of the decoded tool arguments, returning "" when
// the key is absent (so the caller applies its default) and an error for a present-but-non-string value so
// a malformed argument surfaces in-band rather than being silently coerced. Used for grep's
// `include` filter.
func optionalStringArg(args map[string]any, key string) (string, error) {
	raw, ok := args[key]
	if !ok {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", key)
	}
	return s, nil
}
