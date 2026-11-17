// Direct-command stage normalization and direct-subject matching for the permission system.
package permissions

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StageRoute classifies how a normalized pipeline stage must be matched.
type StageRoute int

const (
	// RouteDirect means the stage is a plain exec-style command whose canonical
	// token sequence (StageNormalization.Tokens) is matched against
	// direct-command grants.
	RouteDirect StageRoute = iota
	// RouteLiteral means the stage is a wrapper or indirect form that
	// must not be treated as a direct command; the caller routes it to
	// literal-command matching instead. No direct tokens are produced.
	RouteLiteral
)

// LiteralReason names why a stage was routed to literal matching. It is
// informational (for events and prompts); routing is the same for every value.
type LiteralReason string

const (
	// ReasonWrapperCommand: the leading program is a wrapper/indirect
	// launcher (sh, bash, env, command, nice, nohup, time, xargs).
	ReasonWrapperCommand LiteralReason = "wrapper-command"
	// ReasonBackgrounding: the stage contains an unquoted backgrounding `&`.
	ReasonBackgrounding LiteralReason = "backgrounding"
	// ReasonSubshell: the stage contains an unquoted subshell `(...)`.
	ReasonSubshell LiteralReason = "subshell"
	// ReasonProcessSubstitution: the stage contains an unquoted process
	// substitution `<(...)` or `>(...)`.
	ReasonProcessSubstitution LiteralReason = "process-substitution"
)

// HomeExpansion is the execution-only home-directory expansion for one direct
// token, carried parallel to StageNormalization.Tokens so runner argv can expand
// a bare leading `~` or `$HOME` while the canonical Tokens used for authorization
// subjects stay literal and unexpanded. It is deliberately kept off Tokens so a
// stored grant never holds the resolved home path.
type HomeExpansion struct {
	// Expand is true only when the token began with a bare (unquoted, unescaped)
	// leading `~` or `$HOME` followed by `/` or end-of-token — the sole forms
	// this slice expands. `~user` and general `$VAR` substitution stay false.
	Expand bool
	// Suffix is the token text after the stripped `~` / `$HOME` prefix (e.g.
	// "/srht/codemeld/que" for `~/srht/codemeld/que`, "" for a bare `~`). The
	// runner argv token is the resolved home directory followed by Suffix.
	Suffix string
}

// StageNormalization is the result of normalizing one pipeline stage. When
// Route is RouteDirect, Tokens holds the canonical token sequence (bare program
// name followed by its arguments in original order) and Reason is empty. When
// Route is RouteLiteral, Tokens is nil and Reason explains the routing.
type StageNormalization struct {
	Route  StageRoute
	Tokens []string
	// ExecForms is the per-token home-directory expansion for execution, index-
	// aligned with Tokens. It carries the minimal source-form detail dispatch
	// needs to expand a bare leading `~` / `$HOME` in runner argv only, without
	// changing the canonical Tokens used for matching. nil on a RouteLiteral
	// stage; on a RouteDirect stage every entry is present (Expand false for a
	// token that is not a bare leading HOME form, including the program token).
	ExecForms []HomeExpansion
	// Assignments holds the leading KEY=VALUE environment assignments stripped
	// from a RouteDirect stage (step 3), in original order, each as the
	// shell-resolved `KEY=VALUE` string (name and separator unquoted, value
	// already unescaped — `FOO="a b"` yields `FOO=a b`). They are deliberately
	// kept out of Tokens so direct-subject matching authorizes on the program and
	// its arguments alone, but preserved here so an authorized stage executes with
	// the environment the agent's command requested rather than the parent
	// environment only. nil when the stage had no leading assignments or routes to
	// literal matching.
	Assignments []string
	// ClearEnvironment is true for an accepted `env -i` stage: the child receives Assignments alone
	// rather than the inherited environment. It is also part of the stage's authorization identity,
	// so a cleared stage never matches, caches, or persists as its otherwise identical inheriting
	// form.
	ClearEnvironment bool
	// LookupPath is the $PATH resolution captured for an accepted `command -v <name>` or
	// `type <name>` stage (commandLookupStage, typeLookupStage). Both are shell builtins with no
	// executable to launch, so dispatch answers such a stage from this value instead of building runner
	// argv; resolving it a second time at execution would authorize one lookup and perform another.
	// Empty on every other stage.
	LookupPath string
	// ProgramUnescapedSeparator is true when the program word's source spelling has a `/` that was
	// bare or quoted rather than backslash-escaped.
	ProgramUnescapedSeparator bool
	// ExecProgram, when set, replaces Tokens[0] in runner argv, because the runner may look a bare
	// Tokens[0] up on a PATH other than the one that collapsed it.
	ExecProgram string
	// Source is prompt-only stage text.
	Source string
	Reason LiteralReason
}

// wrapperPrograms are the leading programs whose presence takes a stage
// out of the direct-command normalization boundary. Matched on the base name so
// `/usr/bin/env` is recognized too. The argument-sensitive exceptions are the
// bare `bash`/`sh` no-exec syntax-check grammar (noExecShellStage), the bare
// `command -v <name>` and `type <name>` lookups (commandLookupStage,
// typeLookupStage), the solo-only bare `bash`/`sh` script invocation
// (scriptInvocationStage), and an argument-free bare `env`, which stay on the
// direct route so dispatch answers the exact invocation the classifier validated.
var wrapperPrograms = map[string]bool{
	"sh":      true,
	"bash":    true,
	"env":     true,
	"command": true,
	"type":    true,
	"nice":    true,
	"nohup":   true,
	"time":    true,
	"xargs":   true,
}

// StageContext exists for the flagless script-invocation grammar alone (scriptInvocationStage),
// which is admitted only for a standalone command so a script pipeline stays one literal subject
// executing through the outer `sh -c`. StageInCompound is the zero value so a caller that omits the
// context fails closed.
type StageContext int

const (
	StageInCompound StageContext = iota
	StageSolo
)

// NormalizeDirectStage normalizes one already-isolated pipeline stage:
// it strips leading KEY=VALUE environment assignments, rewrites the
// leading executable to its bare program name, and returns the canonical token
// sequence for direct-command matching. Wrapper and indirect forms
// are tagged for literal routing rather than returned as direct tokens.
//
// Preconditions owned by the caller: the pipeline has already
// been split on `|`, any `cd <path> && ` prefix has been stripped, rejected
// constructs (`;`, `&&` outside the allowed form, `||`, `$(...)`, backticks)
// have already been refused, and I/O redirection has already been routed to
// literal matching. This function does not re-detect those.
func NormalizeDirectStage(stage string, ctx StageContext) (StageNormalization, error) {
	tokens, err := tokenizeShell(stage)
	if err != nil {
		return StageNormalization{}, err
	}
	if len(tokens) == 0 {
		return StageNormalization{}, errors.New("normalize direct: empty command stage")
	}

	// an unquoted backgrounding, subshell, or process-substitution
	// metacharacter takes the whole stage out of the direct boundary. Checked
	// before env stripping so a metacharacter anywhere in the stage routes to
	// literal rather than ever yielding direct tokens.
	if reason, ok := literalOperatorReason(tokens); ok {
		return StageNormalization{Route: RouteLiteral, Reason: reason}, nil
	}

	// step 3: strip leading KEY=VALUE environment assignments from the
	// matched subject, but keep them as resolved KEY=VALUE strings so an
	// authorized direct stage still executes with the requested environment.
	first := 0
	for first < len(tokens) && isEnvAssignment(tokens[first]) {
		first++
	}
	if first == len(tokens) {
		return StageNormalization{}, errors.New("normalize direct: no program after environment assignments")
	}
	var assignments []string
	if first > 0 {
		assignments = make([]string, first)
		for i := range first {
			assignments[i] = tokens[i].Value
		}
	}
	rest := tokens[first:]

	// Quoting the program word (`"sh" -c ...`, `"env" FOO=bar ...`) does not
	// change which executable the shell invokes, so classify by the parsed
	// program value's base name regardless of quote metadata; a quoted wrapper
	// must still route to literal matching and never yield direct tokens.
	prog := rest[0]
	var lookupPath string
	var clearEnvironment bool
	if wrapperPrograms[filepath.Base(prog.Value)] {
		if len(assignments) > 0 {
			return StageNormalization{Route: RouteLiteral, Reason: ReasonWrapperCommand}, nil
		}
		if inner, envAssignments, clear, isEnv := envStage(rest); isEnv {
			rest = inner
			prog = rest[0]
			assignments = envAssignments
			clearEnvironment = clear
		} else {
			path, isLookup := commandLookupStage(rest)
			if !isLookup {
				path, isLookup = typeLookupStage(rest)
			}
			soloScript := ctx == StageSolo && scriptInvocationStage(rest)
			bareEnv := len(rest) == 1 && rest[0].Raw == "env"
			if !isLookup && !noExecShellStage(rest) && !soloScript && !bareEnv {
				return StageNormalization{Route: RouteLiteral, Reason: ReasonWrapperCommand}, nil
			}
			lookupPath = path
		}
	}

	out := make([]string, 0, len(rest))
	forms := make([]HomeExpansion, 0, len(rest))
	// The program token is canonicalized (bare-name rewrite) and never home-expanded;
	// expansion is for path arguments only.
	out = append(out, canonicalProgram(prog.Value))
	forms = append(forms, HomeExpansion{})
	for _, t := range rest[1:] {
		out = append(out, t.Value)
		forms = append(forms, homeExpansionFor(t))
	}
	return StageNormalization{
		Route:                     RouteDirect,
		Tokens:                    out,
		ExecForms:                 forms,
		Assignments:               assignments,
		ClearEnvironment:          clearEnvironment,
		LookupPath:                lookupPath,
		ProgramUnescapedSeparator: unescapedSeparator(prog.Raw),
		Source:                    strings.TrimSpace(stage),
	}, nil
}

func unescapedSeparator(raw string) bool {
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case '\'':
			end := i + 1 + strings.IndexByte(raw[i+1:], '\'')
			if strings.Contains(raw[i+1:end], "/") {
				return true
			}
			i = end
		case '"':
			for i++; i < len(raw) && raw[i] != '"'; i++ {
				if raw[i] == '\\' && i+1 < len(raw) && isDoubleQuoteEscape(raw[i+1]) {
					i++
					continue
				}
				if raw[i] == '/' {
					return true
				}
			}
		case '/':
			return true
		}
	}
	return false
}

// envStage reports the inner command of an accepted `env` stage, its ordered assignments, and
// whether `-i` clears the environment. Every unrecognized shape keeps the wrapper's literal route.
//
// An inner program carrying a path separator is refused because canonicalProgram resolves a path
// form against codemeld's $PATH while the stage runs with the child's, and a relative spelling names
// a different file at every descendant of a folder grant's scope. A PATH assignment carrying an
// empty or non-absolute entry is refused for the same reason one level down, and `-i` without an
// explicit PATH is refused rather than given an invented default search path. Requiring `env`, `-i`,
// and the inner program to be spelled bare — raw source span equal to parsed value — keeps one
// canonical spelling as the only text that reaches the exception.
func envStage(tokens []ShellToken) (rest []ShellToken, assignments []string, clearEnvironment, ok bool) {
	if tokens[0].Raw != tokens[0].Value || tokens[0].Value != "env" {
		return nil, nil, false, false
	}
	i := 1
	if i < len(tokens) && tokens[i].Raw == "-i" && tokens[i].Value == "-i" {
		clearEnvironment = true
		i++
	}
	assignsPath := false
	for ; i < len(tokens); i++ {
		t := tokens[i]
		if !isEnvAssignment(t) {
			break
		}
		if name, value, _ := strings.Cut(t.Value, "="); name == "PATH" {
			if !absolutePathEntries(value) {
				return nil, nil, false, false
			}
			assignsPath = true
		}
		assignments = append(assignments, t.Value)
	}
	if clearEnvironment && !assignsPath {
		return nil, nil, false, false
	}
	rest = tokens[i:]
	if len(rest) == 0 || rest[0].Raw != rest[0].Value || !bareInnerProgram(rest[0].Value) {
		return nil, nil, false, false
	}
	return rest, assignments, clearEnvironment, true
}

func bareInnerProgram(prog string) bool {
	return prog != "" && prog[0] != '-' && filepath.Base(prog) == prog && !wrapperPrograms[prog]
}

// absolutePathEntries reports whether every entry of a PATH assignment's value is absolute. An empty
// or relative entry is resolved against the directory the stage runs in, so one grant would
// authorize a different executable at every descendant of its path scope.
func absolutePathEntries(value string) bool {
	for _, entry := range strings.Split(value, ":") {
		if !filepath.IsAbs(entry) {
			return false
		}
	}
	return true
}

// commandLookupStage reports the $PATH resolution for an assignment-free `command -v <name>` stage,
// the only `command` grammar that leaves the wrapper's literal route. Requiring every token's raw
// span to equal its parsed value keeps a quoted or escaped spelling out of the lookup, so one
// canonical direct subject is the only text that reaches it. A name that does not resolve is not
// accepted: telling an absent program apart from a shell builtin such as `cd` would mean running a
// shell, so the stage keeps its literal route and prompts instead.
func commandLookupStage(tokens []ShellToken) (string, bool) {
	values := make([]string, len(tokens))
	for i, t := range tokens {
		if t.Raw != t.Value {
			return "", false
		}
		values[i] = t.Value
	}
	if !commandLookupTokens(values) {
		return "", false
	}
	path, err := exec.LookPath(values[len(values)-1])
	if err != nil {
		return "", false
	}
	return path, true
}

func typeLookupStage(tokens []ShellToken) (string, bool) {
	if len(tokens) != 2 {
		return "", false
	}
	values := make([]string, len(tokens))
	for i, t := range tokens {
		if t.Raw != t.Value {
			return "", false
		}
		values[i] = t.Value
	}
	if !typeLookupTokens(values) {
		return "", false
	}
	path, err := exec.LookPath(values[1])
	if err != nil {
		return "", false
	}
	return path, true
}

// noExecShellStage reports whether an assignment-free stage is one of the accepted no-exec
// syntax-check invocations (noExecShellTokens). The program word must be the bare, unquoted,
// unescaped name — its raw source span equal to its parsed value — so a path form (`/bin/bash -n`)
// or a quoted spelling (`"bash" -n`) keeps the wrapper's literal route and one canonical direct
// subject stays the only spelling that reaches the exception.
func noExecShellStage(tokens []ShellToken) bool {
	if tokens[0].Raw != tokens[0].Value {
		return false
	}
	values := make([]string, len(tokens))
	for i, t := range tokens {
		values[i] = t.Value
	}
	return noExecShellTokens(values)
}

// scriptInvocationStage reports whether an assignment-free stage is a flagless `bash`/`sh` script
// invocation. The program word must be the bare, unquoted, unescaped name so one canonical
// spelling is the only text that reaches the exception. The first operand must begin with neither `-`
// nor `+`: both shells parse `+`-leading invocation options and keep parsing, so
// `bash +O extglob -c '<code>'` would otherwise put interpreted code on the direct route. That operand
// becomes `$0`, so the tokens after it are the script's argv and are not inspected; a script named
// with a leading `+` stays reachable as `bash ./+name`.
func scriptInvocationStage(tokens []ShellToken) bool {
	if len(tokens) < 2 || tokens[0].Raw != tokens[0].Value {
		return false
	}
	if tokens[0].Value != "bash" && tokens[0].Value != "sh" {
		return false
	}
	operand := tokens[1].Value
	return operand != "" && operand[0] != '-' && operand[0] != '+'
}

// homeExpansionFor computes the execution-only home expansion for one direct
// argument token. Only a bare leading `~` or `$HOME` — where the prefix bytes
// appear unquoted and unescaped in the source and are followed by `/` or the end
// of the token — expands. A quoted (`'~/x'`, `"$HOME"/x`), escaped (`\~/x`), or
// embedded (`x=$HOME`, `$HOMEDIR`) form yields Expand false so the canonical
// literal token runs verbatim. Detection keys on Raw (the verbatim source span):
// a leading quote or backslash makes Raw[0] a quote/backslash byte, so a bare
// prefix is present only when Raw itself starts with it.
func homeExpansionFor(t ShellToken) HomeExpansion {
	switch {
	case t.Raw == "~" || strings.HasPrefix(t.Raw, "~/"):
		return HomeExpansion{Expand: true, Suffix: t.Value[len("~"):]}
	case t.Raw == "$HOME" || strings.HasPrefix(t.Raw, "$HOME/"):
		return HomeExpansion{Expand: true, Suffix: t.Value[len("$HOME"):]}
	}
	return HomeExpansion{}
}

// isBareWildcardToken reports the trailing `:*` scope wildcard. A quoted (`":*"`) or escaped
// (`:\*`) form parses to the same value but is a literal argument token, never the wildcard.
func isBareWildcardToken(t ShellToken) bool {
	return t.Raw == ":*" && t.Value == ":*" && !t.Quoted
}

// literalOperatorReason reports the first syntactic form found among the
// tokens' unquoted characters, giving process substitution precedence over a
// bare subshell parenthesis since `<(` and `>(` also contain `(`.
func literalOperatorReason(tokens []ShellToken) (LiteralReason, bool) {
	for _, t := range tokens {
		if strings.Contains(t.unquoted, "<(") || strings.Contains(t.unquoted, ">(") {
			return ReasonProcessSubstitution, true
		}
	}
	for _, t := range tokens {
		if strings.ContainsAny(t.unquoted, "()") {
			return ReasonSubshell, true
		}
	}
	for _, t := range tokens {
		if strings.IndexByte(t.unquoted, '&') >= 0 {
			return ReasonBackgrounding, true
		}
	}
	return "", false
}

// isEnvAssignment reports whether a token is a leading KEY=VALUE environment
// assignment. Per POSIX the NAME and the `=` separator must be unquoted, so the
// test scans the token's raw span up to the first unquoted `=`: any quote or
// backslash before that separator means the shell treats the word as a command
// word, not an assignment. The collapsed `unquoted` run cannot be used here
// because it drops quoted and escaped bytes, which would let `F\OO=bar` and
// `F"OO"=bar` masquerade as the valid name `FOO`. `FOO="a b"` is still an
// assignment because the name and separator are unquoted and only the value is
// quoted; a fully quoted `"FOO=bar"` is a command word.
func isEnvAssignment(t ShellToken) bool {
	for i := range len(t.Raw) {
		switch t.Raw[i] {
		case '=':
			// First unquoted `=` is the separator. Every byte before it is plain
			// (a quote or backslash would have returned false above), so the raw
			// name span is exactly the shell name to validate.
			return isValidShellName(t.Raw[:i])
		case '\'', '"', '\\':
			return false
		}
	}
	return false
}

// isValidShellName reports whether name is a valid POSIX shell variable name: a
// non-empty run of ASCII letters, digits, and underscores that does not begin
// with a digit.
func isValidShellName(name string) bool {
	for i := range len(name) {
		c := name[i]
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
			// valid name character
		case i > 0 && c >= '0' && c <= '9':
			// digits allowed after the first character
		default:
			return false
		}
	}
	return name != ""
}

// canonicalProgram reduces an absolute path to its bare name only when that name resolves through
// the current $PATH to the very same file, so an out-of-PATH executable cannot match a bare-name
// grant. A relative path is kept as written: it runs from the stage folder, which is not known here.
func canonicalProgram(arg0 string) string {
	base := filepath.Base(arg0)
	if base == arg0 || !filepath.IsAbs(arg0) {
		return arg0
	}
	resolved, err := exec.LookPath(base)
	if err != nil {
		return arg0
	}
	if sameExecutable(arg0, resolved) {
		return base
	}
	return arg0
}

// ResolveRelativeProgram never cleans the folder part before EvalSymlinks, so `link/..` names the
// physical parent the shell would run from, and it leaves the final name unresolved so names linked
// to one multi-call binary keep separate grants.
func ResolveRelativeProgram(program, folder string, keepAbsolute bool) string {
	sep := strings.LastIndexByte(program, '/')
	if folder == "" || sep < 0 || filepath.IsAbs(program) {
		return program
	}
	base := strings.TrimSuffix(folder, "/")
	dir, err := filepath.EvalSymlinks(base + "/" + program[:sep])
	if err != nil {
		return base + "/" + program
	}
	abs := strings.TrimSuffix(dir, "/") + "/" + program[sep+1:]
	if keepAbsolute {
		return abs
	}
	return canonicalProgram(abs)
}

// sameExecutable reports whether two paths name the same file, following
// symlinks via the OS (handles a PATH entry that is a symlink to the absolute
// path the agent typed).
func sameExecutable(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}
