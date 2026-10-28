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

var shellCommandRunningBuiltins = []string{"exec", "eval", ".", "source", "builtin"}

func isAmendOption(tok string) bool {
	return len(tok) >= len("--am") && strings.HasPrefix("--amend", tok)
}

func isShellReservedWord(tok string) bool {
	return isReservedWord(tok) || tok == "{" || tok == "}" || tok == "!"
}

func ExceptionalAuthority(tokens []string) (authority string, ok bool) {
	authority = stageAuthority(tokens, "")
	return authority, authority != ""
}

func stageAuthority(tokens []string, dropped string) (authority string) {
	if len(tokens) == 0 {
		return ""
	}
	if a, found := programAuthorities[tokens[0]]; found && a != dropped {
		return a
	}
	subs := subcommandAuthorities[tokens[0]]
	for i, tok := range tokens[1:] {
		a := subs[tok]
		rest := tokens[i+2:]
		switch {
		case tokens[0] == "git" && tok == "reset" && slices.Contains(rest, "--hard"),
			(tokens[0] == "git" && tok == "commit" || tokens[0] == "hg" && (tok == "commit" || tok == "ci")) && slices.ContainsFunc(rest, isAmendOption):
			a = authorityHistoryRewrite
		case tokens[0] == "find" && (tok == "-delete" ||
			slices.Contains(findExecActions, tok) && len(rest) > 0 && programAuthorities[canonicalProgram(rest[0])] == authorityFileDeletion):
			a = authorityFileDeletion
		}
		if a != dropped {
			authority = higherAuthority(authority, a)
		}
	}
	return authority
}

func ClassifyExceptional(req MatchRequest, mc ModeContext) (authority string, classifiable bool) {
	stages, ok := exceptionalStages(req, mc)
	if !ok {
		return "", false
	}
	return stagesAuthority(stages, ""), true
}

// File deletion is dropped from each token before any reduction, because deletion outranks history
// rewrite and dropping it afterwards would hide a rewrite in the same command.
func SandboxedAutoEditsAuthority(req MatchRequest, mc ModeContext) string {
	stages, _ := exceptionalStages(req, mc)
	return stagesAuthority(stages, authorityFileDeletion)
}

func stagesAuthority(stages []StageNormalization, dropped string) (authority string) {
	for _, s := range stages {
		authority = higherAuthority(authority, stageAuthority(s.Tokens, dropped))
	}
	return authority
}

func exceptionalStages(req MatchRequest, mc ModeContext) ([]StageNormalization, bool) {
	switch req.Kind {
	case subjectKindDirect:
		return mc.Stages, len(mc.Stages) > 0
	case subjectKindLiteral:
		split, ok := literalClassifierStages(req.Subject)
		if !ok {
			return nil, false
		}
		for _, s := range split {
			if len(s.Tokens) > 0 && isShellReservedWord(s.Tokens[0]) {
				return nil, false
			}
			if len(s.Tokens) > 0 && slices.Contains(shellCommandRunningBuiltins, s.Tokens[0]) {
				return nil, false
			}
			if slices.ContainsFunc(s.Tokens, func(tok string) bool { return strings.Contains(tok, "\n") }) {
				return nil, false
			}
		}
		return split, true
	}
	return nil, true
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

const maxWrapperDepth = 3

// A stripped here-string and a shell reading standard input may sit in different stages or `-c`
// bodies, so both facts are gathered over the whole walk before either can refuse.
type classifierFacts struct {
	hereString bool
	stdinShell bool
}

func literalClassifierStages(command string) ([]StageNormalization, bool) {
	var facts classifierFacts
	stages, ok := classifierStages(command, false, &facts)
	if !ok || facts.hereString && facts.stdinShell {
		return nil, false
	}
	return stages, true
}

func classifierStages(command string, inBody bool, facts *classifierFacts) ([]StageNormalization, bool) {
	remainder, ok := stripClassifierHereStrings(command)
	if !ok {
		return nil, false
	}
	facts.hereString = facts.hereString || remainder != command
	stripped, ok := stripClassifierRedirects(remainder)
	if !ok {
		return nil, false
	}
	mask, err := bareMask(stripped)
	if err != nil || compoundBodyHasDisallowed(stripped, mask) {
		return nil, false
	}
	raws, _ := splitCompound(stripped, mask)
	stages := make([]StageNormalization, 0, len(raws))
	for _, raw := range raws {
		toks, err := tokenizeShell(raw)
		if err != nil || len(toks) == 0 {
			return nil, false
		}
		if _, operator := literalOperatorReason(toks); operator {
			return nil, false
		}
		if v := toks[0].Value; v != "bash" && v != "sh" || !tokenExpansionFree(toks[0].Raw) {
			stage, ok := wrappedClassifierStage(toks, 0)
			if !ok {
				return nil, false
			}
			stages = append(stages, stage)
			continue
		}
		body, command, ok := shellInvocation(toks)
		if !ok || command && inBody {
			return nil, false
		}
		if !command {
			facts.stdinShell = true
			stages = append(stages, StageNormalization{Route: RouteLiteral, Tokens: tokenValues(toks)})
			continue
		}
		inner, ok := classifierStages(body, true, facts)
		if !ok {
			return nil, false
		}
		stages = append(stages, inner...)
	}
	return stages, true
}

func shellInvocation(toks []ShellToken) (body string, command, ok bool) {
	i := 1
	for i < len(toks) {
		v := toks[i].Value
		if v == "" || v[0] != '-' && v[0] != '+' {
			break
		}
		if !tokenExpansionFree(toks[i].Raw) {
			return "", false, false
		}
		i++
		switch {
		case v == "--":
		case v == "--rcfile", v == "--init-file", v == "-o", v == "+o", v == "-O", v == "+O":
			if i == len(toks) || !tokenExpansionFree(toks[i].Raw) {
				return "", false, false
			}
			i++
			continue
		case strings.HasPrefix(v, "--"):
			continue
		default:
			flags := v[1:]
			if flags == "" || strings.ContainsAny(flags, "oO") || strings.ContainsFunc(flags, func(r rune) bool { return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') }) {
				return "", false, false
			}
			if strings.Contains(flags, "c") {
				if v[0] == '+' {
					return "", false, false
				}
				command = true
			}
			continue
		}
		break
	}
	operands := toks[i:]
	if !command {
		return "", false, len(operands) == 0 || tokenExpansionFree(operands[0].Raw)
	}
	if len(operands) == 0 || !tokensExpansionFree(operands) {
		return "", false, false
	}
	return operands[0].Value, true, true
}

func wrappedClassifierStage(toks []ShellToken, depth int) (StageNormalization, bool) {
	name := toks[0].Value
	switch {
	case depth > 0 && (name == "bash" || name == "sh" || name == "env" || isEnvAssignment(toks[0])):
		return StageNormalization{}, false
	case name == "env" || !wrapperPrograms[name] || !tokenExpansionFree(toks[0].Raw):
		raws := make([]string, len(toks))
		for i, t := range toks {
			raws[i] = t.Raw
		}
		return classifierStage(strings.Join(raws, " "))
	case depth == maxWrapperDepth:
		return StageNormalization{}, false
	case lookupWrapperStage(toks):
		return StageNormalization{Route: RouteLiteral, Tokens: tokenValues(toks)}, true
	case name == "type":
		return StageNormalization{}, false
	}
	rest, ok := wrappedCommand(toks)
	switch {
	case !ok:
		return StageNormalization{}, false
	case len(rest) == 0:
		return StageNormalization{Route: RouteLiteral, Tokens: tokenValues(toks)}, name == "xargs"
	}
	return wrappedClassifierStage(rest, depth+1)
}

func lookupWrapperStage(toks []ShellToken) bool {
	names := toks[1:]
	switch {
	case toks[0].Value == "command" && len(names) > 0 && (names[0].Value == "-v" || names[0].Value == "-V"),
		toks[0].Value == "type" && len(names) > 0 && slices.Contains([]string{"-a", "-f", "-p", "-P", "-t"}, names[0].Value):
		names = names[1:]
	case toks[0].Value != "type":
		return false
	}
	return len(names) > 0 && tokensExpansionFree(toks[1:]) && !slices.ContainsFunc(names, func(t ShellToken) bool { return strings.HasPrefix(t.Value, "-") })
}

func wrappedCommand(toks []ShellToken) ([]ShellToken, bool) {
	i := 1
	for i < len(toks) && strings.HasPrefix(toks[i].Value, "-") {
		v := toks[i].Value
		if !tokenExpansionFree(toks[i].Raw) {
			return nil, false
		}
		i++
		if v == "--" {
			break
		}
		next, ok := wrapperOptionArgs(toks[0].Value, v)
		if !ok {
			return nil, false
		}
		if next {
			if i == len(toks) || !tokenExpansionFree(toks[i].Raw) {
				return nil, false
			}
			i++
		}
	}
	return toks[i:], true
}

func wrapperOptionArgs(wrapper, opt string) (next, ok bool) {
	switch wrapper {
	case "command", "time":
		return false, opt == "-p"
	case "nice":
		if opt == "-n" {
			return true, true
		}
		return false, len(opt) > 1 && strings.Trim(opt[1:], "0123456789") == ""
	case "xargs":
		return xargsOptionArgs(opt)
	}
	return false, false
}

func xargsOptionArgs(opt string) (next, ok bool) {
	if name, _, hasValue := strings.Cut(opt, "="); strings.HasPrefix(opt, "--") {
		switch name {
		case "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var":
			return !hasValue, true
		case "--eof", "--replace", "--max-lines":
			return false, true
		case "--null", "--open-tty", "--interactive", "--no-run-if-empty", "--verbose", "--exit":
			return false, !hasValue
		}
		return false, false
	}
	for j := 1; j < len(opt); j++ {
		switch c := opt[j]; {
		case strings.IndexByte("0oprtx", c) >= 0:
		case strings.IndexByte("adEILnPs", c) >= 0:
			return j == len(opt)-1, true
		case strings.IndexByte("eil", c) >= 0:
			return false, true
		default:
			return false, false
		}
	}
	return false, len(opt) > 1
}

func tokensExpansionFree(toks []ShellToken) bool {
	return !slices.ContainsFunc(toks, func(t ShellToken) bool { return !tokenExpansionFree(t.Raw) })
}

func tokenValues(toks []ShellToken) []string {
	values := make([]string, len(toks))
	for i, t := range toks {
		values[i] = t.Value
	}
	return values
}

func classifierStage(raw string) (StageNormalization, bool) {
	toks, err := tokenizeShell(raw)
	if err != nil {
		return StageNormalization{}, false
	}
	norm, err := NormalizeDirectStage(raw, StageInCompound)
	if err != nil {
		return StageNormalization{}, false
	}
	if norm.Route != RouteDirect {
		return StageNormalization{}, false
	}
	for _, t := range toks[:len(norm.Assignments)] {
		if !isEnvAssignment(t) || !tokenExpansionFree(t.Raw) {
			return StageNormalization{}, false
		}
	}
	if !tokenExpansionFree(toks[len(toks)-len(norm.Tokens)].Raw) {
		return StageNormalization{}, false
	}
	return norm, true
}

func stripClassifierRedirects(body string) (string, bool) {
	mask, err := bareMask(body)
	if err != nil || hasExecutableSubstitution(body) {
		return "", false
	}
	toks, err := tokenizeShell(body)
	if err != nil || slices.ContainsFunc(toks, func(t ShellToken) bool { return strings.Contains(t.Value, "\n") }) {
		return "", false
	}
	for i := range len(body) {
		if mask[i] && (body[i] == '\n' || body[i] == '\r') {
			return "", false
		}
	}
	var b strings.Builder
	kept := 0
	for i := 0; i < len(body); i++ {
		if !mask[i] || (body[i] != '<' && body[i] != '>') {
			continue
		}
		start, end, ok := classifierRedirectSpan(body, mask, kept, i)
		if !ok {
			return "", false
		}
		b.WriteString(body[kept:start])
		b.WriteByte(' ')
		kept = end
		i = end - 1
	}
	b.WriteString(body[kept:])
	return b.String(), true
}

func hasExecutableSubstitution(s string) bool {
	mask, err := bareMask(s)
	if err != nil || hasDoubleQuotedSubstitution(s) {
		return true
	}
	for i := range len(s) {
		if mask[i] && (s[i] == '`' || s[i] == '$' && i+1 < len(s) && mask[i+1] && s[i+1] == '(') {
			return true
		}
	}
	return false
}

func classifierRedirectSpan(s string, mask []bool, kept, i int) (start, end int, ok bool) {
	bareAt := func(k int, c byte) bool { return k < len(s) && mask[k] && s[k] == c }
	wordEnd := func(k int) bool { return mask[k] && strings.IndexByte(" \t;&|<>()", s[k]) >= 0 }
	start = i
	for start > kept && mask[start-1] && s[start-1] >= '0' && s[start-1] <= '9' {
		start--
	}
	descriptor := ""
	if start < i {
		if start > 0 && !wordEnd(start-1) {
			start = i
		} else if i-start > 1 {
			return 0, 0, false
		} else {
			descriptor = s[start:i]
		}
	}
	if start > 0 && (bareAt(start-1, '&') || bareAt(start-1, '}')) {
		return 0, 0, false
	}
	j := i + 1
	switch {
	case bareAt(j, '('), s[i] == '<' && bareAt(j, '<'):
		return 0, 0, false
	case bareAt(j, '&'):
		j++
		digit := j < len(s) && mask[j] && s[j] >= '0' && s[j] <= '9'
		closeFD := bareAt(j, '-') && s[i] == '>'
		if descriptor == "" && (s[i] == '<' || closeFD) || !digit && !closeFD {
			return 0, 0, false
		}
		end = j + 1
		if end < len(s) && !wordEnd(end) {
			return 0, 0, false
		}
		return start, end, true
	case s[i] == '>' && (bareAt(j, '>') || bareAt(j, '|')), s[i] == '<' && bareAt(j, '>'):
		j++
	}
	for j < len(s) && mask[j] && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	end = j
	for end < len(s) && !wordEnd(end) {
		end++
	}
	if end == j || !tokenExpansionFree(s[j:end]) {
		return 0, 0, false
	}
	return start, end, true
}
