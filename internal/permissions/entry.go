// Parses, validates, and serializes on-disk permission entries.
package permissions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
	"golang.org/x/net/idna"
)

// LayerKind names the settings layer an entry was read from. It is in-memory provenance: no
// settings file may carry it, and it takes no part in authorization or deduplication.
type LayerKind string

const (
	LayerLocal   LayerKind = "local"
	LayerProject LayerKind = "project"
	LayerGlobal  LayerKind = "global"
)

// PermissionEntry is the in-memory form of one on-disk permission entry.
// PathScope is "*" for a global grant or a cleaned absolute path for a folder
// grant. ArgumentHash is set only when Kind == "literal". Layer is stamped by the loader
// that read the entry, never by the entry's own bytes.
type PermissionEntry struct {
	Kind         string
	Subject      string
	PathScope    string
	HostScope    string
	GrantKind    string
	ArgumentHash string
	Layer        LayerKind
}

type DedupKey struct {
	Kind      string
	Subject   string
	PathScope string
	HostScope string
	GrantKind string
}

var allowedKeys = map[string]bool{
	"kind":          true,
	"subject":       true,
	"path_scope":    true,
	"host_scope":    true,
	"grant_kind":    true,
	"argument_hash": true,
}

var validKinds = map[string]bool{"direct": true, "literal": true, "tool": true}

var validGrantKinds = map[string]bool{"folder": true, "global": true}

const grantKindProject = "project"

var hostSubjects = map[string]bool{"web_search": true, "web_fetch": true}

// ParseEntry validates one decoded YAML mapping from the permissions list and
// returns the typed entry. index is the entry's position in the permissions
// array; it and filePath are woven into every error so load-time callers can
// surface -compatible failures (offending file, entry index, and the
// path_scope/grant_kind field pair) without re-parsing the entry.
func ParseEntry(raw map[string]any, filePath string, index int) (PermissionEntry, error) {
	loc := fmt.Sprintf("%s: permissions.%d", filePath, index)

	if err := rejectUnknownKeys(raw, loc); err != nil {
		return PermissionEntry{}, err
	}

	kind, err := requiredString(raw, "kind", loc)
	if err != nil {
		return PermissionEntry{}, err
	}
	subject, err := requiredString(raw, "subject", loc)
	if err != nil {
		return PermissionEntry{}, err
	}
	hostScope, hasHostScope, err := optionalString(raw, "host_scope", loc)
	if err != nil {
		return PermissionEntry{}, err
	}
	if hasHostScope || hostSubjects[subject] {
		return parseHostEntry(raw, loc, kind, subject, hostScope, hasHostScope)
	}

	pathScope, err := requiredString(raw, "path_scope", loc)
	if err != nil {
		return PermissionEntry{}, err
	}
	grantKind, err := requiredString(raw, "grant_kind", loc)
	if err != nil {
		return PermissionEntry{}, err
	}

	if !validKinds[kind] {
		return PermissionEntry{}, fmt.Errorf("%s: kind %q is not one of direct, literal, tool", loc, kind)
	}
	if !validGrantKinds[grantKind] {
		return PermissionEntry{}, fmt.Errorf("%s: grant_kind %q is not one of folder, global", loc, grantKind)
	}
	if !validPathScope(pathScope) {
		return PermissionEntry{}, fmt.Errorf("%s: path_scope %q must be \"*\" or a cleaned absolute path", loc, pathScope)
	}
	if IsCapabilitySubject(subject) && kind != subjectKindTool {
		return PermissionEntry{}, fmt.Errorf("%s: subject %q is a reserved capability subject valid only for kind %q, got %q", loc, subject, subjectKindTool, kind)
	}

	argHash, hasArgHash, err := optionalString(raw, "argument_hash", loc)
	if err != nil {
		return PermissionEntry{}, err
	}
	if kind == "literal" {
		if !hasArgHash {
			return PermissionEntry{}, fmt.Errorf("%s: literal entry requires argument_hash", loc)
		}
		if want := ComputeArgumentHash(subject); argHash != want {
			return PermissionEntry{}, fmt.Errorf("%s: argument_hash does not match SHA-256 of subject", loc)
		}
		if isCompoundSubject(subject) {
			// A generalized compound subject pins programs, operators, and the
			// non-widened arguments; its argument_hash already hashes that pinned encoding (checked
			// above). It must decode cleanly — a malformed or destructive-program generalized subject
			// is rejected at load rather than ever matching (fail closed) — and it must NOT be run
			// through literal canonicalization, which would mangle the encoding's operators and `:*`
			// wildcards.
			if _, dErr := decodeCompoundSubject(subject); dErr != nil {
				return PermissionEntry{}, fmt.Errorf("%s: invalid generalized compound subject: %w", loc, dErr)
			}
		} else if canon, cErr := CanonicalLiteralForm(subject); cErr == nil && canon != subject {
			// A byte-exact grant persisted under an older canonical literal spelling must keep
			// matching after the canonical form changes: requests are canonicalized before
			// authorization, so re-canonicalize the stored subject here and recompute its hash. The
			// hash check above already rejected tampered subjects; a subject that no longer tokenizes
			// is left unchanged rather than broadened.
			subject = canon
			argHash = ComputeArgumentHash(canon)
		}
	} else if hasArgHash {
		return PermissionEntry{}, fmt.Errorf("%s: argument_hash is only allowed for literal entries", loc)
	}

	// Cross-field pairing: path_scope == "*" iff grant_kind == "global".
	if pathScope == "*" && grantKind != "global" {
		return PermissionEntry{}, fmt.Errorf("%s: path_scope \"*\" requires grant_kind global, got %q", loc, grantKind)
	}
	if pathScope != "*" && grantKind == "global" {
		return PermissionEntry{}, fmt.Errorf("%s: grant_kind global requires path_scope \"*\", got %q", loc, pathScope)
	}

	return PermissionEntry{
		Kind:         kind,
		Subject:      subject,
		PathScope:    pathScope,
		GrantKind:    grantKind,
		ArgumentHash: argHash,
	}, nil
}

func parseHostEntry(raw map[string]any, loc, kind, subject, hostScope string, hasHostScope bool) (PermissionEntry, error) {
	if !hostSubjects[subject] {
		return PermissionEntry{}, fmt.Errorf("%s: host_scope is valid only for subject web_search or web_fetch, got %q", loc, subject)
	}
	if kind != subjectKindTool {
		return PermissionEntry{}, fmt.Errorf("%s: subject %q is a network subject valid only for kind %q, got %q", loc, subject, subjectKindTool, kind)
	}
	if _, ok := raw["path_scope"]; ok {
		return PermissionEntry{}, fmt.Errorf("%s: subject %q is scoped by host_scope and must not set path_scope", loc, subject)
	}
	if !hasHostScope {
		return PermissionEntry{}, fmt.Errorf("%s: subject %q requires host_scope", loc, subject)
	}
	if _, ok := raw["argument_hash"]; ok {
		return PermissionEntry{}, fmt.Errorf("%s: argument_hash is only allowed for literal entries", loc)
	}
	grantKind, err := requiredString(raw, "grant_kind", loc)
	if err != nil {
		return PermissionEntry{}, err
	}
	if grantKind != grantKindProject {
		return PermissionEntry{}, fmt.Errorf("%s: grant_kind %q is not valid for a host grant, which requires grant_kind %q", loc, grantKind, grantKindProject)
	}
	canonical, err := CanonicalHost(hostScope)
	if err != nil {
		return PermissionEntry{}, fmt.Errorf("%s: host_scope %q is not a valid host: %w", loc, hostScope, err)
	}
	return PermissionEntry{Kind: kind, Subject: subject, HostScope: canonical, GrantKind: grantKind}, nil
}

var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

func CanonicalHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("host is empty")
	}
	if host == "*" {
		return "", fmt.Errorf(`wildcard host "*" is not allowed; grant one exact host`)
	}
	trimmed := strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String(), nil
	}
	ascii, err := hostProfile.ToASCII(trimmed)
	if err != nil {
		return "", err
	}
	return ascii, nil
}

// DedupKey returns the comparable identity used to merge or dedup entries.
func (e PermissionEntry) DedupKey() DedupKey {
	return DedupKey{Kind: e.Kind, Subject: e.Subject, PathScope: e.PathScope, HostScope: e.HostScope, GrantKind: e.GrantKind}
}

// ComputeArgumentHash returns the lowercase hex SHA-256 (64 chars) of the
// canonical literal subject, per the argument-hash algorithm.
func ComputeArgumentHash(canonicalLiteralSubject string) string {
	sum := sha256.Sum256([]byte(canonicalLiteralSubject))
	return hex.EncodeToString(sum[:])
}

// MarshalEntry serializes one entry to YAML for persistence callers, emitting
// keys in on-disk order and guaranteeing path_scope == "*" is a quoted scalar
// rather than a bare "*" (which YAML would read as an alias).
func MarshalEntry(e PermissionEntry) ([]byte, error) {
	scopeKey, scopeValue := "path_scope", e.PathScope
	if e.HostScope != "" {
		scopeKey, scopeValue = "host_scope", e.HostScope
	}
	ms := yaml.MapSlice{
		{Key: "kind", Value: e.Kind},
		{Key: "subject", Value: e.Subject},
		{Key: scopeKey, Value: scopeValue},
		{Key: "grant_kind", Value: e.GrantKind},
	}
	if e.Kind == "literal" {
		ms = append(ms, yaml.MapItem{Key: "argument_hash", Value: e.ArgumentHash})
	}
	return yaml.Marshal(ms)
}

func validPathScope(p string) bool {
	if p == "*" {
		return true
	}
	return filepath.IsAbs(p) && filepath.Clean(p) == p
}

func rejectUnknownKeys(raw map[string]any, loc string) error {
	var unknown []string
	for k := range raw {
		if !allowedKeys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s: unknown key %q", loc, unknown[0])
}

func requiredString(raw map[string]any, key, loc string) (string, error) {
	v, ok := raw[key]
	if !ok {
		return "", fmt.Errorf("%s: missing required key %q", loc, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s: key %q must be a string, got %T", loc, key, v)
	}
	return s, nil
}

func optionalString(raw map[string]any, key, loc string) (value string, present bool, err error) {
	v, ok := raw[key]
	if !ok {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", true, fmt.Errorf("%s: key %q must be a string, got %T", loc, key, v)
	}
	return s, true, nil
}
