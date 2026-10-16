package filetools

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

type phase1ReadSchema struct {
	allowed  map[string]struct{}
	accepted string
	validate func(args map[string]any) error
}

var phase1ReadSchemas = map[string]phase1ReadSchema{
	ReadToolName: {
		allowed:  map[string]struct{}{"path": {}, "offset": {}, "limit": {}},
		accepted: "path, offset, and limit",
		validate: validateReadArgs,
	},
	GlobToolName: {
		allowed: map[string]struct{}{
			"pattern": {}, "path": {}, "limit": {}, "include_ignored": {}, "include_hidden": {},
		},
		accepted: "pattern, path, limit, include_ignored, and include_hidden",
		validate: validateGlobArgs,
	},
	GrepToolName: {
		allowed: map[string]struct{}{
			"pattern": {}, "path": {}, "include": {}, "case_insensitive": {}, "context": {},
			"limit": {}, "files_only": {}, "include_ignored": {}, "include_hidden": {},
		},
		accepted: "pattern, path, include, case_insensitive, context, limit, files_only, include_ignored, and include_hidden",
		validate: validateGrepArgs,
	},
	ListToolName: {
		allowed: map[string]struct{}{
			"path": {}, "limit": {}, "include_ignored": {}, "include_hidden": {},
		},
		accepted: "path, limit, include_ignored, and include_hidden",
		validate: validateListArgs,
	},
	TreeToolName: {
		allowed: map[string]struct{}{
			"path": {}, "depth": {}, "limit": {}, "format": {}, "include_ignored": {}, "include_hidden": {},
		},
		accepted: "path, depth, limit, format, include_ignored, and include_hidden",
		validate: validateTreeArgs,
	},
	FileCountToolName: {
		allowed: map[string]struct{}{
			"path": {}, "kinds": {}, "include_globs": {}, "exclude_globs": {},
			"group_by": {}, "include_dotfiles": {}, "include_ignored": {}, "limit": {},
		},
		accepted: "path, kinds, include_globs, exclude_globs, group_by, include_dotfiles, include_ignored, and limit",
		validate: validateFileCountArgs,
	},
}

func ValidatePhase1ReadArgs(name string, args map[string]any) error {
	schema, ok := phase1ReadSchemas[name]
	if !ok {
		return fmt.Errorf("tool %q has no Phase-1 read argument schema", name)
	}
	if err := rejectUnknownPhase1ReadArgs(name, args); err != nil {
		return err
	}
	return schema.validate(args)
}

func rejectUnknownPhase1ReadArgs(name string, args map[string]any) error {
	schema, ok := phase1ReadSchemas[name]
	if !ok {
		return fmt.Errorf("tool %q has no Phase-1 read argument schema", name)
	}
	for key := range args {
		if _, ok := schema.allowed[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only %s are accepted", key, schema.accepted)
		}
	}
	return nil
}

func validateReadArgs(args map[string]any) error {
	path, err := requireStringArg(args, "path")
	if err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return &TargetError{Kind: ReadToolName, Reason: "path must be non-empty"}
	}
	offsetPtr, oerr := optionalIntArg(args, "offset")
	if oerr != nil {
		return oerr
	}
	limitPtr, lerr := optionalIntArg(args, "limit")
	if lerr != nil {
		return lerr
	}
	if verr := ValidateNumericArgs(ReadToolName, NumericArgs{Offset: offsetPtr, Limit: limitPtr, Max: ReadMaxLimit}); verr != nil {
		return verr
	}
	return nil
}

func validateGlobArgs(args map[string]any) error {
	pattern, perr := requireStringArg(args, "pattern")
	if perr != nil {
		return perr
	}
	// An empty pattern is rejected, but the value is not trimmed: a filename glob may legitimately contain
	// leading/trailing spaces, so only the literal empty string is refused.
	if pattern == "" {
		return &TargetError{Kind: GlobToolName, Reason: "pattern must be non-empty"}
	}
	if !doublestar.ValidatePattern(pattern) {
		return &TargetError{Kind: GlobToolName, Reason: fmt.Sprintf("malformed glob pattern %q", pattern)}
	}
	if _, pterr := optionalStringArg(args, "path"); pterr != nil {
		return pterr
	}
	limitPtr, lerr := optionalIntArg(args, "limit")
	if lerr != nil {
		return lerr
	}
	if verr := ValidateNumericArgs(GlobToolName, NumericArgs{Limit: limitPtr, Max: GlobMaxLimit}); verr != nil {
		return verr
	}
	if _, herr := optionalBoolArg(args, "include_hidden"); herr != nil {
		return herr
	}
	if _, ierr := optionalBoolArg(args, "include_ignored"); ierr != nil {
		return ierr
	}
	return nil
}

func validateGrepArgs(args map[string]any) error {
	pattern, perr := requireStringArg(args, "pattern")
	if perr != nil {
		return perr
	}
	// An empty pattern matches every line.
	if pattern == "" {
		return &TargetError{Kind: GrepToolName, Reason: "pattern must be non-empty"}
	}
	if _, pterr := optionalStringArg(args, "path"); pterr != nil {
		return pterr
	}
	if _, cerr := optionalBoolArg(args, "case_insensitive"); cerr != nil {
		return cerr
	}
	if _, ferr := optionalBoolArg(args, "files_only"); ferr != nil {
		return ferr
	}
	if _, herr := optionalBoolArg(args, "include_hidden"); herr != nil {
		return herr
	}
	if _, ierr := optionalBoolArg(args, "include_ignored"); ierr != nil {
		return ierr
	}
	limitPtr, lerr := optionalIntArg(args, "limit")
	if lerr != nil {
		return lerr
	}
	contextPtr, xerr := optionalIntArg(args, "context")
	if xerr != nil {
		return xerr
	}
	if verr := ValidateNumericArgs(GrepToolName, NumericArgs{Limit: limitPtr, Context: contextPtr, Max: GrepMaxLimit}); verr != nil {
		return verr
	}
	if _, rerr := compileGrepPattern(args); rerr != nil {
		return rerr
	}
	if _, igerr := grepIncludeGlob(args); igerr != nil {
		return igerr
	}
	return nil
}

func validateListArgs(args map[string]any) error {
	if _, pterr := optionalStringArg(args, "path"); pterr != nil {
		return pterr
	}
	limitPtr, lerr := optionalIntArg(args, "limit")
	if lerr != nil {
		return lerr
	}
	if verr := ValidateNumericArgs(ListToolName, NumericArgs{Limit: limitPtr, Max: ListMaxLimit}); verr != nil {
		return verr
	}
	if _, herr := optionalBoolArg(args, "include_hidden"); herr != nil {
		return herr
	}
	if _, ierr := optionalBoolArg(args, "include_ignored"); ierr != nil {
		return ierr
	}
	return nil
}

func validateTreeArgs(args map[string]any) error {
	if _, pterr := optionalStringArg(args, "path"); pterr != nil {
		return pterr
	}
	depthPtr, derr := optionalIntArg(args, "depth")
	if derr != nil {
		return derr
	}
	limitPtr, lerr := optionalIntArg(args, "limit")
	if lerr != nil {
		return lerr
	}
	if verr := ValidateNumericArgs(TreeToolName, NumericArgs{Limit: limitPtr, Depth: depthPtr, Max: TreeMaxLimit}); verr != nil {
		return verr
	}
	if _, herr := optionalBoolArg(args, "include_hidden"); herr != nil {
		return herr
	}
	if _, ierr := optionalBoolArg(args, "include_ignored"); ierr != nil {
		return ierr
	}
	format, ferr := optionalStringArg(args, "format")
	if ferr != nil {
		return ferr
	}
	if format != "" && format != treeFormatAI && format != treeFormatHuman {
		return fmt.Errorf("argument %q must be %q or %q", "format", treeFormatAI, treeFormatHuman)
	}
	return nil
}

func validateFileCountArgs(args map[string]any) error {
	if _, pterr := optionalStringArg(args, "path"); pterr != nil {
		return pterr
	}
	limitPtr, lerr := optionalIntArg(args, "limit")
	if lerr != nil {
		return lerr
	}
	if verr := ValidateNumericArgs(FileCountToolName, NumericArgs{Limit: limitPtr, Max: FileCountMaxLimit}); verr != nil {
		return verr
	}
	if _, derr := optionalBoolArg(args, "include_dotfiles"); derr != nil {
		return derr
	}
	if _, ierr := optionalBoolArg(args, "include_ignored"); ierr != nil {
		return ierr
	}
	if _, kerr := resolveFileCountKinds(args); kerr != nil {
		return kerr
	}
	groupBy, gerr := optionalStringArg(args, "group_by")
	if gerr != nil {
		return gerr
	}
	if groupBy != "" && !validGroupBy(groupBy) {
		return fmt.Errorf("argument %q must be one of %q, %q, %q, %q, or %q", "group_by", groupByExtension, groupByTopDir, groupByParentDir, groupByDepth, groupByStem)
	}
	includeGlobs, igErr := optionalStringSliceArg(args, "include_globs")
	if igErr != nil {
		return igErr
	}
	excludeGlobs, egErr := optionalStringSliceArg(args, "exclude_globs")
	if egErr != nil {
		return egErr
	}
	if verr := validateGlobPatterns("include_globs", includeGlobs); verr != nil {
		return verr
	}
	return validateGlobPatterns("exclude_globs", excludeGlobs)
}

func compileGrepPattern(args map[string]any) (*regexp.Regexp, error) {
	pattern, _ := requireStringArg(args, "pattern")
	caseInsensitive, _ := optionalBoolArg(args, "case_insensitive")
	expr := pattern
	if caseInsensitive {
		expr = "(?i)" + pattern
	}
	re, cerr := regexp.Compile(expr)
	if cerr != nil {
		return nil, &TargetError{Kind: GrepToolName, Reason: "cannot compile pattern: " + cerr.Error()}
	}
	return re, nil
}

func grepIncludeGlob(args map[string]any) (string, error) {
	includeGlob, igerr := optionalStringArg(args, "include")
	if igerr != nil {
		return "", igerr
	}
	if includeGlob != "" {
		if _, merr := filepath.Match(includeGlob, "probe"); merr != nil {
			return "", &TargetError{Kind: GrepToolName, Reason: fmt.Sprintf("malformed include glob %q: %v", includeGlob, merr)}
		}
	}
	return includeGlob, nil
}
