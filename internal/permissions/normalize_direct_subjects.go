package permissions

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

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
	encoded, err := encodeDirectEnvPayload(assignments, clearEnvironment, subject)
	if err != nil {
		return "", err
	}
	if _, err := decodeDirectEnvSubject(encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

func encodeDirectEnvPayload(assignments []string, clearEnvironment bool, subject string) (string, error) {
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
	return prefix + base64.RawURLEncoding.EncodeToString(payload), nil
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
		if err := checkCanonicalHomeEnv(encoded, p); err != nil {
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
	v2 := directEnvSubjectV2{Assignments: p.Assignments, Subject: p.Subject}
	if err := checkCanonicalHomeEnv(encoded, v2); err != nil {
		return directEnvSubjectV2{}, err
	}
	return v2, nil
}

// checkCanonicalHomeEnv applies the home envelope's re-encoding rule to the env wrapper around it;
// env wrappers around other scopes keep their older, non-canonical acceptance.
func checkCanonicalHomeEnv(encoded string, p directEnvSubjectV2) error {
	if !isDirectHomeSubject(p.Subject) {
		return nil
	}
	canonical, err := encodeDirectEnvPayload(p.Assignments, p.ClearEnvironment, p.Subject)
	if err != nil {
		return err
	}
	if canonical != encoded {
		return errors.New("permissions: direct-env subject around home state is not canonical")
	}
	return nil
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
	if isDirectHomeSubject(subject) {
		_, err := decodeDirectHomeSubject(subject)
		return err
	}
	return checkDirectScope(subject)
}

func checkDirectScope(subject string) error {
	if isDirectUnderSubject(subject) {
		_, err := decodeDirectUnderSubject(subject)
		return err
	}
	if canon, ok := canonicalStageSubject(subject); !ok || canon != subject {
		return fmt.Errorf("permissions: %q is not a canonical direct scope subject", subject)
	}
	return nil
}
