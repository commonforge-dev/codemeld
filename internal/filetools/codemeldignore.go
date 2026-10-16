// codemeld-owned ignore filtering: a single-format `codemeldignore` matcher plugged into the walker's
// traversal seam, honored by glob/grep/list/tree by default in place of native .gitignore/.hgignore parsing.
package filetools

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// CodemeldignoreMatcher is the IgnoreMatcher over the union of patterns loaded from the project and global
// codemeldignore files. Each pattern is a single doublestar glob matched literally against an
// entry's project-root-relative, slash-separated path: a slash-less pattern is root-only, "match a name at
// any depth" needs an explicit leading `**/`, and there is no negation, so the two files' patterns are an
// order-independent union. A matched directory prunes its whole subtree because the shared walker consults the
// matcher before it descends.
type CodemeldignoreMatcher struct {
	// patterns is the validated union of project + global patterns. An empty slice never matches.
	patterns []string
}

var _ IgnoreMatcher = (*CodemeldignoreMatcher)(nil)

// ShouldSkip reports whether relPath matches any loaded pattern. Patterns are pre-validated at load via
// doublestar.ValidatePattern, so doublestar.Match cannot return a pattern error here; a defensive error is
// treated as no-match so a single odd pattern can never wrongly exclude an entry. The entry kind is
// irrelevant to matching — directory-subtree pruning is the walker's job once a directory is skipped.
func (m *CodemeldignoreMatcher) ShouldSkip(relPath string, _ EntryKind) bool {
	for _, p := range m.patterns {
		if ok, err := doublestar.Match(p, relPath); err == nil && ok {
			return true
		}
	}
	return false
}

// ProjectCodemeldignorePath returns <project-root>/.codemeld/codemeldignore, the per-project ignore file.
func ProjectCodemeldignorePath(projectRoot string) string {
	return filepath.Join(projectRoot, ".codemeld", "codemeldignore")
}

// GlobalCodemeldignorePath returns ~/.codemeld/global/codemeldignore, the global ignore file.
func GlobalCodemeldignorePath(home string) string {
	return filepath.Join(home, ".codemeld", "global", "codemeldignore")
}

// LoadCodemeldignoreMatcher reads the project and global codemeldignore files (each optional — a missing
// file is not an error), unions their patterns, and returns a matcher. It returns a nil matcher when neither
// file contributes a pattern, so a caller can skip registering an empty filter. An invalid pattern in either
// file is a hard error (the file path and 1-based line number are named), surfaced in-band by the consuming
// tool rather than silently dropped. Order is irrelevant: there is no negation, so the union is the same set
// regardless of which file is read first.
func LoadCodemeldignoreMatcher(projectRoot, home string) (*CodemeldignoreMatcher, error) {
	projectPatterns, err := parseCodemeldignoreFile(ProjectCodemeldignorePath(projectRoot))
	if err != nil {
		return nil, err
	}
	globalPatterns, err := parseCodemeldignoreFile(GlobalCodemeldignorePath(home))
	if err != nil {
		return nil, err
	}
	if len(projectPatterns) == 0 && len(globalPatterns) == 0 {
		return nil, nil
	}
	patterns := make([]string, 0, len(projectPatterns)+len(globalPatterns))
	patterns = append(patterns, projectPatterns...)
	patterns = append(patterns, globalPatterns...)
	return &CodemeldignoreMatcher{patterns: patterns}, nil
}

// parseCodemeldignoreFile reads one codemeldignore file into its list of patterns: one doublestar glob per
// line, with blank lines and `#`-prefixed comment lines skipped and each surviving line trimmed of
// surrounding whitespace. A missing file yields no patterns and no error (req: missing = not an error); any
// other read error is returned. Each pattern is validated with doublestar.ValidatePattern up front so a
// malformed glob is a deterministic rejection naming the offending file and line.
func parseCodemeldignoreFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("codemeldignore: cannot read %s: %w", path, err)
	}
	var patterns []string
	for i, line := range strings.Split(string(data), "\n") {
		pattern := strings.TrimSpace(line)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		if !doublestar.ValidatePattern(pattern) {
			return nil, fmt.Errorf("codemeldignore: %s:%d: invalid pattern %q", path, i+1, pattern)
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

// defaultIgnoreMatchers builds the default walker ignore-filter set for a walk anchored at projectRoot, using
// home for the global file. It is the single seam the read-only navigation tools register into so
// codemeldignore filtering applies to glob/grep/list/tree by default. It returns nil (no
// matchers) when neither codemeldignore file contributes a pattern, and an error when either file holds an
// invalid pattern, which the calling tool surfaces in-band.
func defaultIgnoreMatchers(projectRoot, home string) ([]IgnoreMatcher, error) {
	matcher, err := LoadCodemeldignoreMatcher(projectRoot, home)
	if err != nil {
		return nil, err
	}
	if matcher == nil {
		return nil, nil
	}
	return []IgnoreMatcher{matcher}, nil
}
