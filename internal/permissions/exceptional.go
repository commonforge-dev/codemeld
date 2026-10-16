package permissions

import (
	"slices"
	"strings"

	"codemeld.dev/codemeld/internal/enforce"
)

const (
	authorityNetwork        = enforce.NetworkAccessAuthority
	authorityFileDeletion   = "file deletion"
	authorityHistoryRewrite = "VCS history rewrite"
)

var authorityPrecedence = []string{authorityNetwork, authorityFileDeletion, authorityHistoryRewrite}

var programAuthorities = map[string]string{
	"curl":   authorityNetwork,
	"wget":   authorityNetwork,
	"ssh":    authorityNetwork,
	"scp":    authorityNetwork,
	"rm":     authorityFileDeletion,
	"rmdir":  authorityFileDeletion,
	"unlink": authorityFileDeletion,
	"shred":  authorityFileDeletion,
}

var subcommandAuthorities = map[string]map[string]string{
	"hg": {
		"pull":     authorityNetwork,
		"push":     authorityNetwork,
		"clone":    authorityNetwork,
		"strip":    authorityHistoryRewrite,
		"rollback": authorityHistoryRewrite,
		"histedit": authorityHistoryRewrite,
		"rebase":   authorityHistoryRewrite,
		"uncommit": authorityHistoryRewrite,
		"amend":    authorityHistoryRewrite,
	},
	"git": {
		"fetch":         authorityNetwork,
		"push":          authorityNetwork,
		"pull":          authorityNetwork,
		"clone":         authorityNetwork,
		"clean":         authorityFileDeletion,
		"rebase":        authorityHistoryRewrite,
		"filter-branch": authorityHistoryRewrite,
		"filter-repo":   authorityHistoryRewrite,
	},
	"pip":  {"install": authorityNetwork},
	"pip3": {"install": authorityNetwork},
}

var findExecActions = []string{"-exec", "-execdir", "-ok", "-okdir"}

func isShellReservedWord(tok string) bool {
	return isReservedWord(tok) || tok == "{" || tok == "}" || tok == "!"
}

func ExceptionalAuthority(tokens []string) (authority string, ok bool) {
	if len(tokens) == 0 {
		return "", false
	}
	if a, found := programAuthorities[tokens[0]]; found {
		return a, true
	}
	subs := subcommandAuthorities[tokens[0]]
	for i, tok := range tokens[1:] {
		a := subs[tok]
		rest := tokens[i+2:]
		switch {
		case tokens[0] == "git" && tok == "reset" && slices.Contains(rest, "--hard"),
			(tokens[0] == "git" || tokens[0] == "hg") && tok == "commit" && slices.Contains(rest, "--amend"):
			a = authorityHistoryRewrite
		case tokens[0] == "find" && (tok == "-delete" ||
			slices.Contains(findExecActions, tok) && len(rest) > 0 && programAuthorities[rest[0]] == authorityFileDeletion):
			a = authorityFileDeletion
		}
		authority = higherAuthority(authority, a)
	}
	return authority, authority != ""
}

func ClassifyExceptional(req MatchRequest, mc ModeContext) (authority string, classifiable bool) {
	var stages []StageNormalization
	switch req.Kind {
	case subjectKindDirect:
		if len(mc.Stages) == 0 {
			return "", false
		}
		stages = mc.Stages
	case subjectKindLiteral:
		_, split, _, ok := SimpleCompoundStages(req.Subject)
		if !ok {
			return "", false
		}
		for _, s := range split {
			if len(s.Tokens) > 0 && isShellReservedWord(s.Tokens[0]) {
				return "", false
			}
			if slices.ContainsFunc(s.Tokens, func(tok string) bool { return strings.Contains(tok, "\n") }) {
				return "", false
			}
		}
		stages = split
	default:
		return "", true
	}
	for _, s := range stages {
		a, _ := ExceptionalAuthority(s.Tokens)
		authority = higherAuthority(authority, a)
	}
	return authority, true
}

func higherAuthority(a, b string) string {
	if a == "" {
		return b
	}
	if b != "" && slices.Index(authorityPrecedence, b) < slices.Index(authorityPrecedence, a) {
		return b
	}
	return a
}
