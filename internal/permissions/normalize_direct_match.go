package permissions

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const directHomeSubjectPrefix = "'direct-home/v1 "

type directHomeSubject struct {
	Subject   string `json:"subject"`
	Expanding []int  `json:"expanding"`
	Literal   []int  `json:"literal"`
}

func isDirectHomeSubject(subject string) bool {
	return strings.HasPrefix(subject, directHomeSubjectPrefix)
}

func isHomeFormArg(value string) bool {
	return value == "~" || strings.HasPrefix(value, "~/") || value == "$HOME" || strings.HasPrefix(value, "$HOME/")
}

func scopePinnedTokens(scope string) []string {
	if isDirectUnderSubject(scope) {
		p, err := decodeDirectUnderSubject(scope)
		if err != nil {
			return nil
		}
		return p.Tokens[:p.PathIndex]
	}
	toks, err := tokenizeShell(scope)
	if err != nil || len(toks) == 0 {
		return nil
	}
	if isBareWildcardToken(toks[len(toks)-1]) {
		toks = toks[:len(toks)-1]
	}
	values := make([]string, len(toks))
	for i, t := range toks {
		values[i] = t.Value
	}
	return values
}

func homePositions(pinned []string) []int {
	var positions []int
	for i := 1; i < len(pinned); i++ {
		if isHomeFormArg(pinned[i]) {
			positions = append(positions, i)
		}
	}
	return positions
}

func wrapHomeState(scope string, commandTokens []string, expands []bool) (string, error) {
	if isDirectEnvSubject(scope) || isDirectHomeSubject(scope) {
		return "", errors.New("permissions: home state wraps only a command scope")
	}
	pinned := scopePinnedTokens(scope)
	positions := homePositions(pinned)
	if len(positions) == 0 {
		return scope, nil
	}
	p := directHomeSubject{Subject: scope, Expanding: []int{}, Literal: []int{}}
	for _, i := range positions {
		if i >= len(commandTokens) || i >= len(expands) || commandTokens[i] != pinned[i] {
			return "", fmt.Errorf("permissions: scope token %d does not match the request", i)
		}
		if expands[i] {
			p.Expanding = append(p.Expanding, i)
		} else {
			p.Literal = append(p.Literal, i)
		}
	}
	encoded, err := encodeDirectHomePayload(p)
	if err != nil {
		return "", err
	}
	if _, err := decodeDirectHomeSubject(encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

func encodeDirectHomePayload(p directHomeSubject) (string, error) {
	if err := checkDirectHomePayload(p); err != nil {
		return "", err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return directHomeSubjectPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// decodeDirectHomeSubject requires the payload to re-encode to the stored bytes, so a duplicate,
// missing or null field, reordered fields or padded base64 match nothing.
func decodeDirectHomeSubject(encoded string) (directHomeSubject, error) {
	rest, ok := strings.CutPrefix(encoded, directHomeSubjectPrefix)
	if !ok {
		return directHomeSubject{}, errors.New("permissions: missing direct-home subject prefix")
	}
	var p directHomeSubject
	if err := decodeVersionedSubjectPayload(rest, &p); err != nil {
		return directHomeSubject{}, err
	}
	if p.Expanding == nil || p.Literal == nil {
		return directHomeSubject{}, errors.New("permissions: direct-home subject is missing its state")
	}
	canonical, err := encodeDirectHomePayload(p)
	if err != nil {
		return directHomeSubject{}, err
	}
	if canonical != encoded {
		return directHomeSubject{}, errors.New("permissions: direct-home subject is not canonical")
	}
	return p, nil
}

func checkDirectHomePayload(p directHomeSubject) error {
	if isDirectEnvSubject(p.Subject) || isDirectHomeSubject(p.Subject) {
		return errors.New("permissions: direct-home subject wraps another envelope")
	}
	if err := checkDirectScope(p.Subject); err != nil {
		return err
	}
	positions := homePositions(scopePinnedTokens(p.Subject))
	if len(positions) == 0 {
		return errors.New("permissions: direct-home subject pins no home-form argument")
	}
	want := make(map[int]bool, len(positions))
	for _, i := range positions {
		want[i] = true
	}
	seen := 0
	for _, list := range [][]int{p.Expanding, p.Literal} {
		for j, i := range list {
			if !want[i] || (j > 0 && list[j-1] >= i) {
				return fmt.Errorf("permissions: direct-home position %d is not a distinct pinned home-form argument", i)
			}
			delete(want, i)
			seen++
		}
	}
	if seen != len(positions) {
		return errors.New("permissions: direct-home state does not cover every pinned home-form argument")
	}
	return nil
}

// DirectRequestSubject is the token-only request identity: it carries no home expansion state, so for
// a command with a `~` or `$HOME` argument it names both the expanding and the literal request and
// matches no grant pinning that argument. Dispatch builds identities with DirectStageRequestSubject.
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

// expands[i] must report whether token i actually runs as the home folder, not whether its spelling
// could expand.
func DirectStageRequestSubject(commandTokens, assignments []string, clearEnvironment bool, expands []bool) (string, error) {
	if len(commandTokens) == 0 {
		return "", errors.New("permissions: a direct request needs at least one command token")
	}
	if len(expands) != len(commandTokens) {
		return "", errors.New("permissions: home expansion state does not align with the command tokens")
	}
	for i, e := range expands {
		if e && (i == 0 || !isHomeFormArg(commandTokens[i])) {
			return "", fmt.Errorf("permissions: token %d cannot expand to the home folder", i)
		}
	}
	if len(homePositions(commandTokens)) == 0 {
		return DirectRequestSubject(commandTokens, assignments, clearEnvironment)
	}
	subject, err := wrapHomeState(ExactSubject(commandTokens[0], commandTokens[1:]), commandTokens, expands)
	if err != nil {
		return "", err
	}
	if len(assignments) == 0 && !clearEnvironment {
		return subject, nil
	}
	return EncodeDirectEnvSubject(assignments, clearEnvironment, subject)
}

type directRequestIdentity struct {
	assignments      []string
	clearEnvironment bool
	home             *directHomeSubject
	command          string
}

func decodeDirectRequestIdentity(subject string) (directRequestIdentity, error) {
	var id directRequestIdentity
	inner := subject
	if isDirectEnvSubject(subject) {
		p, err := decodeDirectEnvSubject(subject)
		if err != nil {
			return directRequestIdentity{}, err
		}
		id.assignments, id.clearEnvironment, inner = p.Assignments, p.ClearEnvironment, p.Subject
	}
	if isDirectHomeSubject(inner) {
		h, err := decodeDirectHomeSubject(inner)
		if err != nil {
			return directRequestIdentity{}, err
		}
		id.home = &h
		inner = h.Subject
	}
	if !isExactDirectSubject(inner) {
		return directRequestIdentity{}, errors.New("permissions: direct request identity does not name an exact command")
	}
	id.command = inner
	return id, nil
}

func isVersionedDirectSubject(subject string) bool {
	return strings.HasPrefix(subject, "'direct-")
}

func checkDirectRequestIdentity(subject string, commandTokens, assignments []string, clearEnvironment bool) error {
	if !isVersionedDirectSubject(subject) {
		return nil
	}
	id, err := decodeDirectRequestIdentity(subject)
	if err != nil {
		return err
	}
	if len(commandTokens) == 0 || id.command != ExactSubject(commandTokens[0], commandTokens[1:]) {
		return errors.New("permissions: direct request identity names other command tokens")
	}
	if !slices.Equal(id.assignments, assignments) || id.clearEnvironment != clearEnvironment {
		return errors.New("permissions: direct request identity names another environment")
	}
	return nil
}

func requestHomeExpansion(subject string, commandTokens, assignments []string, clearEnvironment bool) (expands []bool, ok bool) {
	if checkDirectRequestIdentity(subject, commandTokens, assignments, clearEnvironment) != nil {
		return nil, false
	}
	expands = make([]bool, len(commandTokens))
	if len(homePositions(commandTokens)) == 0 {
		return expands, true
	}
	id, err := decodeDirectRequestIdentity(subject)
	if err != nil || id.home == nil {
		return nil, false
	}
	for _, i := range id.home.Expanding {
		expands[i] = true
	}
	return expands, true
}

// DecodeDirectRequestSubject validates a recorded direct request identity against its
// exact command identity and reports the request's ordered assignments and whether it
// cleared the environment. ok is false unless the pair proves that state, so an
// assignment-free inherited environment is never inferred from command-only text. It
// reports nothing about home expansion.
func DecodeDirectRequestSubject(requestSubject, commandSubject string) (assignments []string, clearEnvironment, ok bool) {
	if !isExactDirectSubject(commandSubject) {
		return nil, false, false
	}
	id, err := decodeDirectRequestIdentity(requestSubject)
	if err != nil || id.command != commandSubject {
		return nil, false, false
	}
	return id.assignments, id.clearEnvironment, true
}

func DirectHomeSubjectReadable(subject string) (string, bool) {
	var parts []string
	inner := subject
	if isDirectEnvSubject(subject) {
		p, err := decodeDirectEnvSubject(subject)
		if err != nil {
			return "", false
		}
		if p.ClearEnvironment {
			parts = append(parts, "env", "-i")
		}
		for _, a := range p.Assignments {
			name, value, _ := strings.Cut(a, "=")
			parts = append(parts, name+"="+ShellQuote(value))
		}
		inner = p.Subject
	}
	if !isDirectHomeSubject(inner) {
		return "", false
	}
	h, err := decodeDirectHomeSubject(inner)
	if err != nil {
		return "", false
	}
	expanding := make(map[int]bool, len(h.Expanding))
	for _, i := range h.Expanding {
		expanding[i] = true
	}
	render := func(fixed []string) {
		for i, tok := range fixed {
			if expanding[i] {
				parts = append(parts, readableExpandingHome(tok))
			} else {
				parts = append(parts, ShellQuote(tok))
			}
		}
	}
	if isDirectUnderSubject(h.Subject) {
		u, err := decodeDirectUnderSubject(h.Subject)
		if err != nil {
			return "", false
		}
		render(u.Tokens[:u.PathIndex])
		parts = append(parts, DirectUnderReadable(nil, u.Boundary, u.TailWildcard))
		return strings.Join(parts, " "), true
	}
	toks, err := tokenizeShell(h.Subject)
	if err != nil || len(toks) == 0 {
		return "", false
	}
	wildcard := isBareWildcardToken(toks[len(toks)-1])
	render(scopePinnedTokens(h.Subject))
	if wildcard {
		parts = append(parts, directWildcardToken)
	}
	return strings.Join(parts, " "), true
}

func readableExpandingHome(tok string) string {
	prefix := "~"
	if strings.HasPrefix(tok, "$HOME") {
		prefix = "$HOME"
	}
	rest := strings.TrimPrefix(tok[len(prefix):], "/")
	switch {
	case tok == prefix:
		return prefix
	case rest == "":
		return prefix + "/"
	}
	return prefix + "/" + ShellQuote(rest)
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

// MatchesDirectSubject reports whether a direct request — its canonical command
// token sequence plus the ordered environment assignments stripped from it and
// whether it clears the environment — matches the stored direct-command grant
// subject. A versioned subject authorizes only its exact ordered assignments and
// clear state and applies its decoded scope subject to the command tokens; every
// unversioned subject keeps its legacy assignment-free, environment-inheriting
// reading, so neither an assignment-bearing nor a clearing request ever matches one.
// The caller cannot prove home expansion, so a subject pinning a `~` or `$HOME` argument
// never matches.
func MatchesDirectSubject(commandTokens, assignments []string, clearEnvironment bool, storedSubject string) bool {
	return matchesDirectSubject(commandTokens, assignments, clearEnvironment, nil, storedSubject)
}

// expands nil means the request's home expansion is unknown.
func matchesDirectSubject(commandTokens, assignments []string, clearEnvironment bool, expands []bool, storedSubject string) bool {
	if isDirectEnvSubject(storedSubject) {
		p, err := decodeDirectEnvSubject(storedSubject)
		if err != nil || p.ClearEnvironment != clearEnvironment || !slices.Equal(p.Assignments, assignments) {
			return false
		}
		return matchesHomeScope(commandTokens, expands, p.Subject)
	}
	if len(assignments) > 0 || clearEnvironment {
		return false
	}
	return matchesHomeScope(commandTokens, expands, storedSubject)
}

// matchesHomeScope refuses a scope pinning a home-form argument without recorded state: it cannot
// say whether the approved command ran in the home folder or in a folder named `~`.
func matchesHomeScope(commandTokens []string, expands []bool, subject string) bool {
	if !isDirectHomeSubject(subject) {
		if len(homePositions(scopePinnedTokens(subject))) > 0 {
			return false
		}
		return matchesDirectCommandSubject(commandTokens, subject)
	}
	h, err := decodeDirectHomeSubject(subject)
	if err != nil || expands == nil {
		return false
	}
	for _, i := range h.Expanding {
		if i >= len(expands) || !expands[i] {
			return false
		}
	}
	for _, i := range h.Literal {
		if i >= len(expands) || expands[i] {
			return false
		}
	}
	return matchesDirectCommandSubject(commandTokens, h.Subject)
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
