package permissions

import (
	"os"
	"path/filepath"
	"strings"
)

func ReadOnlyShell(req MatchRequest, mc ModeContext) bool {
	return classifyReadOnlyShell(req, mc) == ClassReadOnly
}

func LiteralStages(canonical string) []StageNormalization {
	literal, ok := breakDownLiteral(canonical)
	if !ok {
		return nil
	}
	return literal.stages
}

// A relative candidate is joined without cleaning: `link/../x` names a different file than `x` when
// `link` is a symlink, and the blocked-path matcher compares both the cleaned and resolved forms.
func ShellPathCandidates(argv []string, folder, home string) []string {
	if len(argv) == 0 {
		return nil
	}
	var candidates []string
	add := func(token string) {
		if filepath.IsAbs(token) {
			candidates = append(candidates, token)
			return
		}
		candidates = append(candidates, folder+string(filepath.Separator)+token)
	}
	operands := false
	for _, token := range argv[1:] {
		switch {
		case operands:
			add(token)
		case token == "--":
			operands = true
		case token == "-" || !strings.HasPrefix(token, "-"):
			add(token)
		default:
			_, value, ok := strings.Cut(token, "=")
			if !ok || value == "" {
				continue
			}
			add(value)
			if home != "" && strings.HasPrefix(value, "~/") {
				add(home + value[1:])
			}
		}
	}
	return candidates
}

func ShellPathAsks(b *BlockedPaths, folder string, argv, candidates []string) bool {
	for _, target := range append([]string{folder}, candidates...) {
		if _, ok := b.BlockedWithin(target); ok {
			return true
		}
		if b.Degraded() && b.OutsideProject(target) {
			return true
		}
	}
	for _, token := range argv {
		if token == "--" {
			return false
		}
		if strings.HasPrefix(token, "-") && !strings.Contains(token, "=") && strings.ContainsAny(token, "/~") {
			return true
		}
	}
	return false
}

func LiteralRewriteAsks(stage StageNormalization, runDir string) bool {
	raw, err := tokenizeShell(stage.Source)
	if err != nil || len(raw) != len(stage.Tokens) {
		return true
	}
	options := true
	for i, token := range raw {
		text := token.Raw
		if i < len(stage.ExecForms) && stage.ExecForms[i].Expand {
			text = strings.TrimPrefix(strings.TrimPrefix(text, "$HOME"), "~")
		}
		if !tokenExpansionFree(text) && (i == 0 || !options || !unexpandedOptionGlob(token, runDir)) {
			return true
		}
		if token.Value == "--" {
			options = false
		}
	}
	return false
}

func unexpandedOptionGlob(token ShellToken, runDir string) bool {
	if token.Quoted || !strings.HasPrefix(token.Raw, "-") || strings.Contains(token.Raw, "/") ||
		strings.ContainsFunc(token.Raw, func(r rune) bool { return r != '*' && r != '?' && runeNeedsQuote(r) }) {
		return false
	}
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if matched, err := filepath.Match(token.Value, entry.Name()); err != nil || matched {
			return false
		}
	}
	return true
}
