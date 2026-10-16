// Reader-side schema-version classification and the future-version open refusal.
package sessions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// ReaderSupportedVersion is the maximum session schema_version this build can
// open. It is the reader-side contract, kept distinct from the
// writer-side CurrentSchemaVersion in schema.go because the two may legitimately
// diverge during a schema transition (a reader that supports v1 and v2 while the
// writer still emits v1). The invariant ReaderSupportedVersion >= CurrentSchemaVersion
// must always hold so a writer never emits a version its own reader cannot open;
// version_test.go asserts it.
const ReaderSupportedVersion = 1

// VersionStatus is the outcome of classifying a session file's schema_version.
type VersionStatus string

const (
	// StatusUnparseable is a schema_version that is missing, not a JSON integer,
	// or less than 1. Such a file is treated as unparseable.
	StatusUnparseable VersionStatus = "unparseable"
	// StatusOlderForkEligible is a parseable integer version >= 1 and less than
	// ReaderSupportedVersion. Phase 1 has no plain "older" status: every readable
	// older file gets the read-only display plus one-shot fork affordance.
	StatusOlderForkEligible VersionStatus = "older-fork-eligible"
	// StatusEqual is a version equal to ReaderSupportedVersion; the file loads
	// normally.
	StatusEqual VersionStatus = "equal"
	// StatusNewer is a version greater than ReaderSupportedVersion; the reader
	// refuses to open the file.
	StatusNewer VersionStatus = "newer"
)

// VersionError is the typed refusal returned by OpenSession when a session file
// cannot be opened on version grounds: a future (newer) version or an
// unparseable schema_version. It supports errors.As so callers can distinguish a
// version refusal from an ordinary I/O or JSON parse failure. Its message names
// the file and the version mismatch.
type VersionError struct {
	Path      string        // the refused session file
	Status    VersionStatus // StatusNewer or StatusUnparseable
	Found     *big.Int      // the file's schema_version; meaningful only when Status is StatusNewer. Arbitrary magnitude so a future version beyond int64 range is still named exactly.
	Supported int           // the reader's supported version (ReaderSupportedVersion)
}

func (e *VersionError) Error() string {
	if e.Status == StatusNewer {
		return fmt.Sprintf(
			"codemeld: session %s has schema_version %d, which is newer than this build supports (max %d)",
			e.Path, e.Found, e.Supported)
	}
	return fmt.Sprintf(
		"codemeld: session %s has an unparseable schema_version (must be a JSON integer >= 1); this build supports up to version %d",
		e.Path, e.Supported)
}

// ClassifyVersion maps a recovered metadata.schema_version value to a
// VersionStatus. The argument is the value as recovered from the
// file: a raw JSON token (json.RawMessage/[]byte, decoded here with integer
// precision preserved so no float64 rounding occurs), an already-decoded
// json.Number, a Go integer, or nil for an absent field. Missing, non-integer,
// and < 1 values all classify as StatusUnparseable; a value equal to, less than,
// or greater than ReaderSupportedVersion classifies as StatusEqual,
// StatusOlderForkEligible, or StatusNewer respectively. It returns a non-nil
// error only when a raw JSON token argument is itself malformed.
func ClassifyVersion(v any) (VersionStatus, error) {
	return classifyVersion(v, ReaderSupportedVersion)
}

// classifyVersion is ClassifyVersion with the supported version injected, so the
// older-fork-eligible branch (unreachable while ReaderSupportedVersion == 1) is
// exercisable in tests.
func classifyVersion(v any, supported int) (VersionStatus, error) {
	n, ok, err := schemaVersionValue(v)
	if err != nil {
		return StatusUnparseable, err
	}
	if !ok || n.Cmp(big.NewInt(1)) < 0 {
		return StatusUnparseable, nil
	}
	switch n.Cmp(big.NewInt(int64(supported))) {
	case 1:
		return StatusNewer, nil
	case -1:
		return StatusOlderForkEligible, nil
	default:
		return StatusEqual, nil
	}
}

// OpenSession reads the JSONL session file at path, pre-scans metadata.schema_version
// from the first line before any full parse, and classifies it. It
// refuses a newer or unparseable version with a *VersionError, without parsing
// records — a future breaking schema may carry fields the current record parser
// cannot understand, so refusal must not depend on a successful full Unmarshal.
// For an equal or older-fork-eligible version it delegates to Unmarshal and
// returns the parsed session with its status, so callers load equal files
// normally and present the read-only + fork UI for older files.
//
// A read failure or a genuine JSONL parse failure is returned as an ordinary error with an empty status,
// distinct from a version refusal; callers surface those via the
// "cannot be parsed" path.
func OpenSession(path string) (*Session, VersionStatus, error) {
	return openSession(path, ReaderSupportedVersion)
}

// openSession is OpenSession with the supported version injected, so the
// older-fork-eligible load path is exercisable in tests.
func openSession(path string, supported int) (*Session, VersionStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	raw, err := rawSchemaVersion(data)
	if err != nil {
		return nil, "", err
	}
	status, err := classifyVersion(raw, supported)
	if err != nil {
		return nil, "", err
	}
	switch status {
	case StatusNewer:
		found, _, _ := schemaVersionValue(raw)
		return nil, status, &VersionError{Path: path, Status: status, Found: found, Supported: supported}
	case StatusUnparseable:
		return nil, status, &VersionError{Path: path, Status: status, Supported: supported}
	default: // StatusEqual, StatusOlderForkEligible
		sess, uerr := Unmarshal(data)
		if uerr != nil {
			return nil, status, uerr
		}
		return sess, status, nil
	}
}

// rawSchemaVersion returns the raw JSON token for metadata.schema_version from the
// first JSONL line, or nil when the metadata object or the field is absent (the
// "missing" case, which classifies as unparseable). It errors only when
// the metadata line itself is malformed JSON.
func rawSchemaVersion(data []byte) (json.RawMessage, error) {
	lines := completeJSONLLines(data)
	if len(lines) == 0 {
		return nil, fmt.Errorf("session must start with a metadata line")
	}
	if !isJSONObject(lines[0]) {
		return nil, fmt.Errorf("metadata line: must be a JSON object")
	}
	var top struct {
		Type     *string         `json:"type"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(lines[0], &top); err != nil {
		return nil, fmt.Errorf("parse session metadata line: %w", err)
	}
	if top.Type == nil || *top.Type != "metadata" {
		return nil, fmt.Errorf("metadata line: type must be %q", "metadata")
	}
	if !isJSONObject(top.Metadata) {
		return nil, nil
	}
	var meta struct {
		SchemaVersion json.RawMessage `json:"schema_version"`
	}
	if err := json.Unmarshal(top.Metadata, &meta); err != nil {
		return nil, fmt.Errorf("parse session metadata: %w", err)
	}
	if len(bytes.TrimSpace(meta.SchemaVersion)) == 0 {
		return nil, nil
	}
	return meta.SchemaVersion, nil
}

// schemaVersionValue interprets a recovered schema_version value as an integer of
// arbitrary magnitude. ok is false for any non-integer value (the
// non-integer case), including JSON numbers with a fraction or exponent; err is
// non-nil only when a raw JSON token argument is itself malformed. A JSON integer
// outside int64 range is still a JSON integer and is returned exactly, so a future
// version larger than int64 classifies as StatusNewer rather than being folded
// into the unparseable bucket.
func schemaVersionValue(v any) (n *big.Int, ok bool, err error) {
	switch t := v.(type) {
	case nil:
		return nil, false, nil
	case json.RawMessage:
		return decodeSchemaToken(t)
	case []byte:
		return decodeSchemaToken(t)
	case json.Number:
		return numberBig(t)
	case int:
		return big.NewInt(int64(t)), true, nil
	case int64:
		return big.NewInt(t), true, nil
	default:
		return nil, false, nil
	}
}

func decodeSchemaToken(raw []byte) (*big.Int, bool, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if derr := dec.Decode(&v); derr != nil {
		return nil, false, fmt.Errorf("parse schema_version: %w", derr)
	}
	if dec.More() {
		return nil, false, fmt.Errorf("parse schema_version: unexpected trailing data")
	}
	num, ok := v.(json.Number)
	if !ok {
		return nil, false, nil
	}
	return numberBig(num)
}

// numberBig parses a JSON number as an exact integer of arbitrary magnitude. ok is
// false for a number carrying a fraction or exponent (the "not a JSON
// integer" case), since base-10 SetString rejects the '.'/'e' those introduce; a
// plain integer token of any size parses exactly.
func numberBig(num json.Number) (*big.Int, bool, error) {
	n, ok := new(big.Int).SetString(num.String(), 10)
	if !ok {
		return nil, false, nil
	}
	return n, true, nil
}
