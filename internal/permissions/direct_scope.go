package permissions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type DirectScopeKind int

const (
	DirectScopeExact DirectScopeKind = iota
	DirectScopePrefix
	DirectScopeProgram
	DirectScopePath
)

// DirectScopeChoice is one selectable stored subject for a direct-command grant.
// Pinned holds the argument tokens the subject stores verbatim (all of them for
// Exact, the wildcard's prefix for Prefix, none for Program), so a surface can
// render what a choice fixes without re-deriving it.
//
// A DirectScopePath choice carries an opaque versioned envelope in Subject, so a surface
// renders Readable instead. Boundaries runs from the path argument's immediate parent
// outward and Boundary indexes the one this choice stores.
type DirectScopeChoice struct {
	Kind         DirectScopeKind
	Subject      string
	Pinned       []string
	Readable     string
	Boundaries   []string
	Boundary     int
	TailWildcard bool
}

func (c DirectScopeChoice) RequiresConfirmation() bool { return c.Kind == DirectScopeProgram }

// DirectScopeModel is the direct-command grant-scope policy. It must stay
// presentation-neutral: no labels, warnings, or input handling, so every prompt surface
// renders its own copy over one policy.
type DirectScopeModel struct {
	Program     string
	Args        []string
	Choices     []DirectScopeChoice
	Recommended int

	path    pathScope
	pathRow int
}

// NewDirectScopeModel derives the scope ladder from a request's canonical tokens: Exact,
// then one Prefix choice per visible token boundary from the longest pinned prefix to the
// shortest, then Program. The zero-length prefix is deliberately absent — that subject is
// the Program choice, which is the only one requiring a confirmation.
//
// home is the bootstrap-resolved home directory, canonicalized here and used only as the
// containment floor; callers must not resolve it themselves.
func NewDirectScopeModel(tokens []string, home string) (DirectScopeModel, bool) {
	if len(tokens) == 0 {
		return DirectScopeModel{}, false
	}
	program, args := tokens[0], tokens[1:]

	choices := make([]DirectScopeChoice, 0, len(args)+3)
	choices = append(choices, DirectScopeChoice{
		Kind:    DirectScopeExact,
		Subject: ExactSubject(program, args),
		Pinned:  args,
	})
	for n := len(args); n >= 1; n-- {
		pinned := args[:n]
		choices = append(choices, DirectScopeChoice{
			Kind:    DirectScopePrefix,
			Subject: PrefixSubject(program, pinned),
			Pinned:  pinned,
		})
	}
	choices = append(choices, DirectScopeChoice{
		Kind:    DirectScopeProgram,
		Subject: ProgramSubject(program),
	})

	recommended := 0
	if offered, anchor := ClassifyDirectTokens(args); offered {
		recommended = 1 + len(args) - (anchor + 1)
	}

	model := DirectScopeModel{Program: program, Args: args, Choices: choices, Recommended: recommended, pathRow: -1}
	path, ok := newPathScope(tokens, home)
	if !ok {
		return model, true
	}
	choice, ok := path.choiceAt(0)
	if !ok {
		return model, true
	}
	// The row below is the Prefix pinning the tokens before the path, the first one that
	// wildcards the path token.
	row := 1 + len(args) - (path.pathIndex - 1)
	model.Choices = append(choices[:row:row], append([]DirectScopeChoice{choice}, choices[row:]...)...)
	model.path = path
	model.pathRow = row
	model.Recommended = row
	return model, true
}

// PathRow is the index of the containment choice in Choices, or -1 when none is offered.
func (m DirectScopeModel) PathRow() int { return m.pathRow }

func (m DirectScopeModel) PathChoiceAt(boundary int) (DirectScopeChoice, bool) {
	if m.pathRow < 0 {
		return DirectScopeChoice{}, false
	}
	return m.path.choiceAt(boundary)
}

type pathScope struct {
	tokens       []string
	pathIndex    int
	boundaries   []string
	tailWildcard bool
}

func newPathScope(tokens []string, home string) (pathScope, bool) {
	if len(tokens) < 2 || home == "" {
		return pathScope{}, false
	}
	canonicalHome, err := resolveExistingDir(home)
	if err != nil {
		return pathScope{}, false
	}
	pathIndex := -1
	for i, tok := range tokens {
		if tok == directWildcardToken || strings.HasPrefix(tok, directUnderSentinel) {
			return pathScope{}, false
		}
		if i == 0 {
			continue
		}
		if tok == "" {
			return pathScope{}, false
		}
		if !isPathLikeToken(tok) {
			continue
		}
		if pathIndex >= 0 {
			return pathScope{}, false
		}
		pathIndex = i
	}
	if pathIndex < 0 {
		return pathScope{}, false
	}
	resolved, err := resolveExistingEntry(tokens[pathIndex])
	if err != nil {
		return pathScope{}, false
	}
	boundaries := containmentBoundaries(filepath.Dir(resolved), canonicalHome)
	if len(boundaries) == 0 {
		return pathScope{}, false
	}
	return pathScope{
		tokens:       tokens,
		pathIndex:    pathIndex,
		boundaries:   boundaries,
		tailWildcard: pathIndex < len(tokens)-1,
	}, true
}

func (s pathScope) choiceAt(boundary int) (DirectScopeChoice, bool) {
	if boundary < 0 || boundary >= len(s.boundaries) {
		return DirectScopeChoice{}, false
	}
	subject, err := EncodeDirectUnderSubject(s.tokens, s.pathIndex, s.boundaries[boundary], s.tailWildcard)
	if err != nil {
		return DirectScopeChoice{}, false
	}
	return DirectScopeChoice{
		Kind:         DirectScopePath,
		Subject:      subject,
		Pinned:       s.tokens[1:s.pathIndex],
		Readable:     DirectUnderReadable(s.tokens[:s.pathIndex], s.boundaries[boundary], s.tailWildcard),
		Boundaries:   s.boundaries,
		Boundary:     boundary,
		TailWildcard: s.tailWildcard,
	}, true
}

func containmentBoundaries(start, home string) []string {
	var out []string
	for dir := start; !isContainmentFloor(dir, home); {
		out = append(out, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

// The floor is the filesystem root and every directory at or above canonical home, so no
// boundary can cover home.
func isContainmentFloor(dir, home string) bool {
	return dir == string(filepath.Separator) || IsDescendantOrEqual(home, dir)
}

// resolveExistingEntry is the one resolver behind both boundary construction and
// containment matching, so a spelling cannot mean one thing while choosing and another
// while replaying. Unlike CleanAbsResolve it neither expands nor accepts a relative
// spelling and does not require a directory.
func resolveExistingEntry(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("permissions: %q is not an absolute path", path)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("permissions: resolve %q: %w", path, err)
	}
	return filepath.Clean(resolved), nil
}

func resolveExistingDir(path string) (string, error) {
	resolved, err := resolveExistingEntry(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("permissions: stat %q: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("permissions: %q is not a directory", resolved)
	}
	return resolved, nil
}

// ClassifyDirectTokens applies the flag/positional rules to the canonical argument
// tokens that follow the program token. The anchor index is -1 when no safe anchor
// exists.
//
// A token is a flag when its first byte is '-' — this covers long flags
// (`--verbose`), `--key=value` forms, bundled short flags (`-abc`), and a bare
// '-'. The literal '--' token terminates flag parsing and is itself not a
// positional, so every token after it is positional regardless of a leading '-'.
// A path-looking token after a flag is skipped; a path-looking token elsewhere
// suppresses the inferred anchor.
func ClassifyDirectTokens(tokens []string) (offered bool, anchorIdx int) {
	afterTerminator := false
	afterFlag := false
	for i, tok := range tokens {
		if !afterTerminator {
			if tok == "--" {
				afterTerminator = true
				afterFlag = false
				continue
			}
			if strings.HasPrefix(tok, "-") {
				afterFlag = true
				continue
			}
		}
		if isPathLikeToken(tok) {
			if afterFlag {
				afterFlag = false
				continue
			}
			return false, -1
		}
		return true, i
	}
	return false, -1
}

func isPathLikeToken(tok string) bool {
	return strings.Contains(tok, "/") || strings.HasPrefix(tok, "~")
}

// ExactSubject returns the Exact stored subject: the full canonical token sequence
// (program followed by its argument tokens) with no `:*` suffix. Each value is
// serialized as exactly one shell word, so an empty or whitespace-bearing token
// survives re-tokenization instead of collapsing and letting a later token be
// wildcarded.
func ExactSubject(program string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, ShellQuote(program))
	for _, a := range args {
		parts = append(parts, ShellQuote(a))
	}
	return strings.Join(parts, " ")
}

func PrefixSubject(program string, prefix []string) string {
	return ExactSubject(program, prefix) + " " + directWildcardToken
}

// ProgramSubject returns the Program stored subject: the shell-quoted program
// token, a space, then `:*` (e.g. `make :*`), authorizing any invocation of the
// program within the scope. A whitespace-bearing program is quoted first, so the
// wildcard stays its own token.
func ProgramSubject(program string) string {
	return ShellQuote(program) + " " + directWildcardToken
}

// DirectUnderReadable is display only; the stored value is the versioned envelope and
// this spelling is never parsed back.
func DirectUnderReadable(fixed []string, boundary string, tailWildcard bool) string {
	parts := make([]string, 0, len(fixed)+2)
	for _, tok := range fixed {
		parts = append(parts, ShellQuote(tok))
	}
	parts = append(parts, directUnderSentinel+ShellQuote(boundary))
	if tailWildcard {
		parts = append(parts, directWildcardToken)
	}
	return strings.Join(parts, " ")
}
