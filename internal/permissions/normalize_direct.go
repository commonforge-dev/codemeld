// Direct-command stage normalization and direct-subject matching for the permission system.
package permissions

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
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
	// Source is prompt-only stage text.
	Source string
	Reason LiteralReason
}

// wrapperPrograms are the leading programs whose presence takes a stage
// out of the direct-command normalization boundary. Matched on the base name so
// `/usr/bin/env` is recognized too. The argument-sensitive exceptions are the
// bare `bash`/`sh` no-exec syntax-check grammar (noExecShellStage), the bare
// `command -v <name>` and `type <name>` lookups (commandLookupStage,
// typeLookupStage), and the solo-only bare `bash`/`sh` script invocation
// (scriptInvocationStage), which stay on the direct route so dispatch answers
// the exact invocation the classifier validated.
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
			if !isLookup && !noExecShellStage(rest) && !soloScript {
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
	if len(tokens) != 3 {
		return "", false
	}
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
	path, err := exec.LookPath(values[2])
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

// directEnvSubjectPrefix marks a stored direct subject as the versioned
// assignment-bearing form, and directEnvSubjectPrefixV2 the disjoint
// clear-environment form. The leading unmatched single quote makes the whole
// value unparseable as a shell subject, so no unversioned reader can mistake it
// for a command.
const (
	directEnvSubjectPrefix   = "'direct-env/v1 "
	directEnvSubjectPrefixV2 = "'direct-env/v2 "
)

type directEnvSubject struct {
	Assignments []string `json:"assignments"`
	Subject     string   `json:"subject"`
}

// directEnvSubjectV2 is both the v2 wire payload and the decoder's result type; a decoded v1
// subject reports ClearEnvironment false.
type directEnvSubjectV2 struct {
	Assignments      []string `json:"assignments"`
	ClearEnvironment bool     `json:"clear_environment"`
	Subject          string   `json:"subject"`
}

func isDirectEnvSubject(subject string) bool {
	return strings.HasPrefix(subject, directEnvSubjectPrefix) || strings.HasPrefix(subject, directEnvSubjectPrefixV2)
}

// directUnderSubjectPrefix marks the versioned path-containment form, under the same
// unmatched-leading-quote rule as the direct-env forms. directWildcardToken and
// directUnderSentinel are readable spellings only: a stored subject spelling either of them
// literally stays an ordinary token, so no grant written before this form gains containment.
const (
	directUnderSubjectPrefix = "'direct-under/v1 "
	directWildcardToken      = ":*"
	directUnderSentinel      = ":under="
)

// directUnderSubject's Tokens carries the fixed leading tokens with the path position as an
// empty slot at PathIndex; the request's token there must resolve under Boundary instead of
// matching by equality.
type directUnderSubject struct {
	Tokens       []string `json:"tokens"`
	PathIndex    int      `json:"path_index"`
	Boundary     string   `json:"boundary"`
	TailWildcard bool     `json:"tail_wildcard"`
}

func isDirectUnderSubject(subject string) bool {
	return strings.HasPrefix(subject, directUnderSubjectPrefix)
}

// EncodeDirectUnderSubject builds the stored containment subject from a request's canonical
// tokens. Tokens after pathIndex are dropped, so they may vary only when tailWildcard says so.
func EncodeDirectUnderSubject(tokens []string, pathIndex int, boundary string, tailWildcard bool) (string, error) {
	if pathIndex < 1 || pathIndex >= len(tokens) {
		return "", fmt.Errorf("permissions: direct-under path index %d is outside the command tokens", pathIndex)
	}
	if !tailWildcard && pathIndex != len(tokens)-1 {
		return "", errors.New("permissions: a direct-under subject without a tail wildcard cannot drop trailing tokens")
	}
	fixed := make([]string, pathIndex+1)
	copy(fixed, tokens[:pathIndex])
	p := directUnderSubject{Tokens: fixed, PathIndex: pathIndex, Boundary: boundary, TailWildcard: tailWildcard}
	encoded, err := encodeDirectUnderPayload(p)
	if err != nil {
		return "", err
	}
	if _, err := decodeDirectUnderSubject(encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

func encodeDirectUnderPayload(p directUnderSubject) (string, error) {
	if err := checkDirectUnderPayload(p); err != nil {
		return "", err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return directUnderSubjectPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// decodeDirectUnderSubject is the sole parser of the containment form. Requiring the payload to
// re-encode to the exact stored bytes keeps a merely equivalent shape — reordered fields, padded
// base64 — from authorizing anything.
func decodeDirectUnderSubject(encoded string) (directUnderSubject, error) {
	rest, ok := strings.CutPrefix(encoded, directUnderSubjectPrefix)
	if !ok {
		return directUnderSubject{}, errors.New("permissions: missing direct-under subject prefix")
	}
	var p directUnderSubject
	if err := decodeVersionedSubjectPayload(rest, &p); err != nil {
		return directUnderSubject{}, err
	}
	canonical, err := encodeDirectUnderPayload(p)
	if err != nil {
		return directUnderSubject{}, err
	}
	if canonical != encoded {
		return directUnderSubject{}, errors.New("permissions: direct-under subject is not canonical")
	}
	return p, nil
}

func checkDirectUnderPayload(p directUnderSubject) error {
	if len(p.Tokens) < 2 {
		return errors.New("permissions: a direct-under subject needs a program and a path position")
	}
	if p.PathIndex < 1 || p.PathIndex != len(p.Tokens)-1 {
		return fmt.Errorf("permissions: direct-under path index %d is not the last fixed token", p.PathIndex)
	}
	slots := 0
	for i, tok := range p.Tokens {
		if tok == "" {
			slots++
			continue
		}
		if i == p.PathIndex {
			return errors.New("permissions: direct-under path index does not name a path position")
		}
		if tok == directWildcardToken {
			return errors.New("permissions: direct-under fixed tokens carry a wildcard")
		}
		if !utf8.ValidString(tok) {
			return fmt.Errorf("permissions: direct-under token %q is not valid UTF-8", tok)
		}
	}
	if slots != 1 {
		return fmt.Errorf("permissions: direct-under subject has %d path positions, want exactly 1", slots)
	}
	if !filepath.IsAbs(p.Boundary) || filepath.Clean(p.Boundary) != p.Boundary || p.Boundary == string(filepath.Separator) {
		return fmt.Errorf("permissions: %q is not a containment boundary", p.Boundary)
	}
	if !utf8.ValidString(p.Boundary) {
		return fmt.Errorf("permissions: containment boundary %q is not valid UTF-8", p.Boundary)
	}
	return nil
}

// matchesDirectUnderSubject decides from the filesystem as it stands when permission is
// evaluated. Dispatch still passes the request's original lexical argument, so a replacement of
// that path or an ancestor after this decision is outside what the grant checks.
func matchesDirectUnderSubject(commandTokens []string, storedSubject string) bool {
	p, err := decodeDirectUnderSubject(storedSubject)
	if err != nil {
		return false
	}
	if len(commandTokens) < len(p.Tokens) {
		return false
	}
	if !p.TailWildcard && len(commandTokens) != len(p.Tokens) {
		return false
	}
	for i := range p.PathIndex {
		if commandTokens[i] != p.Tokens[i] {
			return false
		}
	}
	boundary, err := resolveExistingEntry(p.Boundary)
	if err != nil || boundary != p.Boundary {
		return false
	}
	resolved, err := resolveExistingEntry(commandTokens[p.PathIndex])
	if err != nil {
		return false
	}
	return IsDescendantOrEqual(resolved, boundary)
}

// EncodeDirectEnvSubject wraps a canonical direct scope subject and the request's
// ordered assignments into the versioned stored form. subject is the chooser-produced
// scope subject, so a bare trailing `:*` wildcard is preserved rather than quoted.
// clearEnvironment selects the disjoint v2 form, so a cleared stage can never be stored
// as its otherwise identical inherited-environment form.
func EncodeDirectEnvSubject(assignments []string, clearEnvironment bool, subject string) (string, error) {
	if len(assignments) == 0 {
		return "", errors.New("permissions: a direct-env subject needs at least one assignment")
	}
	if err := checkDirectEnvPayload(assignments, subject); err != nil {
		return "", err
	}
	prefix := directEnvSubjectPrefix
	var value any = directEnvSubject{Assignments: assignments, Subject: subject}
	if clearEnvironment {
		prefix = directEnvSubjectPrefixV2
		value = directEnvSubjectV2{Assignments: assignments, ClearEnvironment: true, Subject: subject}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encoded := prefix + base64.RawURLEncoding.EncodeToString(payload)
	if _, err := decodeDirectEnvSubject(encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

// decodeDirectEnvSubject is the sole parser of both versioned forms. Every malformation
// fails closed, so a near-miss stored value never authorizes anything. A v2 payload that
// does not carry a true clear_environment is rejected rather than read as v1, and a v1
// payload carrying the field at all is rejected as an unknown field.
func decodeDirectEnvSubject(encoded string) (directEnvSubjectV2, error) {
	if rest, ok := strings.CutPrefix(encoded, directEnvSubjectPrefixV2); ok {
		var p directEnvSubjectV2
		if err := decodeVersionedSubjectPayload(rest, &p); err != nil {
			return directEnvSubjectV2{}, err
		}
		if !p.ClearEnvironment {
			return directEnvSubjectV2{}, errors.New("permissions: direct-env v2 subject does not clear the environment")
		}
		if err := checkDecodedDirectEnv(p.Assignments, p.Subject); err != nil {
			return directEnvSubjectV2{}, err
		}
		return p, nil
	}
	rest, ok := strings.CutPrefix(encoded, directEnvSubjectPrefix)
	if !ok {
		return directEnvSubjectV2{}, errors.New("permissions: missing direct-env subject prefix")
	}
	var p directEnvSubject
	if err := decodeVersionedSubjectPayload(rest, &p); err != nil {
		return directEnvSubjectV2{}, err
	}
	if err := checkDecodedDirectEnv(p.Assignments, p.Subject); err != nil {
		return directEnvSubjectV2{}, err
	}
	return directEnvSubjectV2{Assignments: p.Assignments, Subject: p.Subject}, nil
}

func decodeVersionedSubjectPayload(rest string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return fmt.Errorf("permissions: versioned subject payload: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("permissions: versioned subject payload: %w", err)
	}
	// dec.More reports another element of an enclosing array or object, so at the top
	// level it stays false for a trailing `}` or `]`; only a second decode reaching EOF
	// proves the payload held exactly one value.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("permissions: versioned subject payload has trailing data")
	}
	return nil
}

func checkDecodedDirectEnv(assignments []string, subject string) error {
	if len(assignments) == 0 {
		return errors.New("permissions: direct-env subject has no assignments")
	}
	return checkDirectEnvPayload(assignments, subject)
}

// checkDirectEnvPayload also refuses an assignment holding invalid UTF-8, because JSON encoding
// would replace those bytes with U+FFFD and let two different values share one identity.
func checkDirectEnvPayload(assignments []string, subject string) error {
	for _, a := range assignments {
		name, _, ok := strings.Cut(a, "=")
		if !ok || !isValidShellName(name) {
			return fmt.Errorf("permissions: %q is not a NAME=VALUE assignment", a)
		}
		if !utf8.ValidString(a) {
			return fmt.Errorf("permissions: assignment %q is not valid UTF-8", a)
		}
	}
	if isDirectUnderSubject(subject) {
		_, err := decodeDirectUnderSubject(subject)
		return err
	}
	if canon, ok := canonicalStageSubject(subject); !ok || canon != subject {
		return fmt.Errorf("permissions: %q is not a canonical direct scope subject", subject)
	}
	return nil
}

// DirectRequestSubject returns the request identity for one direct stage. Command
// tokens are serialized one shell word each and the assignments and clear-environment
// state are carried inside the versioned form, so no two distinct requests share an
// identity.
func DirectRequestSubject(commandTokens, assignments []string, clearEnvironment bool) (string, error) {
	if len(commandTokens) == 0 {
		return "", errors.New("permissions: a direct request needs at least one command token")
	}
	subject := ExactSubject(commandTokens[0], commandTokens[1:])
	if len(assignments) == 0 && !clearEnvironment {
		return subject, nil
	}
	return EncodeDirectEnvSubject(assignments, clearEnvironment, subject)
}

// DecodeDirectRequestSubject validates a recorded direct request identity against its
// exact command identity and reports the request's ordered assignments and whether it
// cleared the environment. ok is false unless the pair proves that state, so an
// assignment-free inherited environment is never inferred from command-only text.
func DecodeDirectRequestSubject(requestSubject, commandSubject string) (assignments []string, clearEnvironment, ok bool) {
	if !isExactDirectSubject(commandSubject) {
		return nil, false, false
	}
	if requestSubject == commandSubject {
		return nil, false, true
	}
	p, err := decodeDirectEnvSubject(requestSubject)
	if err != nil || p.Subject != commandSubject {
		return nil, false, false
	}
	return p.Assignments, p.ClearEnvironment, true
}

func isExactDirectSubject(subject string) bool {
	canon, ok := canonicalStageSubject(subject)
	if !ok || canon != subject {
		return false
	}
	toks, err := tokenizeShell(subject)
	if err != nil || len(toks) == 0 {
		return false
	}
	return !isBareWildcardToken(toks[len(toks)-1])
}

// isBareWildcardToken reports the trailing `:*` scope wildcard. A quoted (`":*"`) or escaped
// (`:\*`) form parses to the same value but is a literal argument token, never the wildcard.
func isBareWildcardToken(t ShellToken) bool {
	return t.Raw == ":*" && t.Value == ":*" && !t.Quoted
}

// MatchesDirectSubject reports whether a direct request — its canonical command
// token sequence plus the ordered environment assignments stripped from it and
// whether it clears the environment — matches the stored direct-command grant
// subject. A versioned subject authorizes only its exact ordered assignments and
// clear state and applies its decoded scope subject to the command tokens; every
// unversioned subject keeps its legacy assignment-free, environment-inheriting
// reading, so neither an assignment-bearing nor a clearing request ever matches one.
func MatchesDirectSubject(commandTokens, assignments []string, clearEnvironment bool, storedSubject string) bool {
	if isDirectEnvSubject(storedSubject) {
		p, err := decodeDirectEnvSubject(storedSubject)
		if err != nil || p.ClearEnvironment != clearEnvironment || !slices.Equal(p.Assignments, assignments) {
			return false
		}
		return matchesDirectCommandSubject(commandTokens, p.Subject)
	}
	if len(assignments) > 0 || clearEnvironment {
		return false
	}
	return matchesDirectCommandSubject(commandTokens, storedSubject)
}

func matchesDirectCommandSubject(commandTokens []string, subject string) bool {
	if isDirectUnderSubject(subject) {
		return matchesDirectUnderSubject(commandTokens, subject)
	}
	return matchesDirectScope(commandTokens, subject)
}

// matchesDirectScope applies the command-only scope rule: exact token-for-token
// equality, or — when the subject ends in the literal unescaped `:*` token —
// token-boundary prefix equality on the preceding tokens. Token equality is
// byte-for-byte. The wildcard suffix is recognized only when its raw source bytes
// are exactly `:*`: a quoted (`":*"`) or escaped (`:\*`) form has the same parsed
// value but is a literal argument token, not a wildcard, so it must not broaden
// the subject. A malformed or empty subject never matches.
func matchesDirectScope(commandTokens []string, storedSubject string) bool {
	subjTokens, err := tokenizeShell(storedSubject)
	if err != nil || len(subjTokens) == 0 {
		return false
	}

	if isBareWildcardToken(subjTokens[len(subjTokens)-1]) {
		prefix := subjTokens[:len(subjTokens)-1]
		if len(prefix) == 0 {
			// A bare ":*" is not a valid one-or-more-token subject.
			return false
		}
		if len(commandTokens) < len(prefix) {
			return false
		}
		for i, p := range prefix {
			if commandTokens[i] != p.Value {
				return false
			}
		}
		return true
	}

	if len(commandTokens) != len(subjTokens) {
		return false
	}
	for i, s := range subjTokens {
		if commandTokens[i] != s.Value {
			return false
		}
	}
	return true
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
