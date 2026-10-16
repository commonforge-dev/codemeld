// Tests for reader-side schema-version classification, the future-version open
// refusal, and the reader/writer version-coordination invariant.
package sessions

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReaderSupportsCurrentSchema is the cross-file coordination invariant from
// the reader must be able to open every version the writer emits, so a
// freshly minted file (stamped CurrentSchemaVersion by EnsureSession) is never refused by
// this build's own reader.
func TestReaderSupportsCurrentSchema(t *testing.T) {
	if ReaderSupportedVersion < CurrentSchemaVersion {
		t.Fatalf("ReaderSupportedVersion (%d) < CurrentSchemaVersion (%d): the writer would emit files its own reader refuses",
			ReaderSupportedVersion, CurrentSchemaVersion)
	}
}

func TestClassifyVersion(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want VersionStatus
	}{
		{"missing nil", nil, StatusUnparseable},
		{"token equal", json.RawMessage("1"), StatusEqual},
		{"token newer", json.RawMessage("2"), StatusNewer},
		{"token newer beyond int64", json.RawMessage("9223372036854775808"), StatusNewer},
		{"token zero", json.RawMessage("0"), StatusUnparseable},
		{"token negative", json.RawMessage("-1"), StatusUnparseable},
		{"token negative beyond int64", json.RawMessage("-9223372036854775809"), StatusUnparseable},
		{"token fractional", json.RawMessage("1.5"), StatusUnparseable},
		{"token exponent", json.RawMessage("1e2"), StatusUnparseable},
		{"token string", json.RawMessage(`"1"`), StatusUnparseable},
		{"token bool", json.RawMessage("true"), StatusUnparseable},
		{"token null", json.RawMessage("null"), StatusUnparseable},
		{"number equal", json.Number("1"), StatusEqual},
		{"number newer", json.Number("2"), StatusNewer},
		{"number fractional", json.Number("1.5"), StatusUnparseable},
		{"go int equal", 1, StatusEqual},
		{"go int newer", 2, StatusNewer},
		{"go int zero", 0, StatusUnparseable},
		{"go int64 equal", int64(1), StatusEqual},
		{"go string", "hello", StatusUnparseable},
		{"go float", 1.5, StatusUnparseable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ClassifyVersion(tt.in)
			if err != nil {
				t.Fatalf("ClassifyVersion(%#v) error = %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ClassifyVersion(%#v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The older-fork-eligible branch is unreachable while ReaderSupportedVersion == 1
// (no integer is both >= 1 and < 1), so it is exercised through the injectable
// helper with a higher supported version.
func TestClassifyVersion_OlderForkEligible(t *testing.T) {
	tests := []struct {
		name      string
		in        any
		supported int
		want      VersionStatus
	}{
		{"v1 under v2 is older", json.RawMessage("1"), 2, StatusOlderForkEligible},
		{"v1 under v3 is older (number)", json.Number("1"), 3, StatusOlderForkEligible},
		{"v4 under v5 is older", json.RawMessage("4"), 5, StatusOlderForkEligible},
		{"v5 under v5 is equal", json.RawMessage("5"), 5, StatusEqual},
		{"v6 over v5 is newer", json.RawMessage("6"), 5, StatusNewer},
		{"zero still unparseable", json.RawMessage("0"), 5, StatusUnparseable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyVersion(tt.in, tt.supported)
			if err != nil {
				t.Fatalf("classifyVersion(%#v, %d) error = %v", tt.in, tt.supported, err)
			}
			if got != tt.want {
				t.Fatalf("classifyVersion(%#v, %d) = %q, want %q", tt.in, tt.supported, got, tt.want)
			}
		})
	}
}

func TestClassifyVersion_MalformedToken(t *testing.T) {
	for _, raw := range []string{"{", "1 2", "[1"} {
		got, err := ClassifyVersion(json.RawMessage(raw))
		if err == nil {
			t.Fatalf("ClassifyVersion(%q) = nil error, want malformed-token error", raw)
		}
		if got != StatusUnparseable {
			t.Fatalf("ClassifyVersion(%q) status = %q, want %q", raw, got, StatusUnparseable)
		}
	}
}

// sessionJSONWithVersion builds a structurally valid JSONL session whose
// metadata.schema_version is the literal token raw; an empty raw omits the field.
func sessionJSONWithVersion(raw string) string {
	meta := `"id":"` + testMetaID + `","folder":"/p",` +
		`"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z"`
	if raw != "" {
		meta += `,"schema_version":` + raw
	}
	return `{"type":"metadata","metadata":{` + meta + `}}` + "\n"
}

func writeSessionFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestOpenSession_EqualLoadsNormally(t *testing.T) {
	path := writeSessionFile(t, sessionJSONWithVersion("1"))
	sess, status, err := OpenSession(path)
	if err != nil {
		t.Fatalf("OpenSession() error = %v", err)
	}
	if status != StatusEqual {
		t.Fatalf("status = %q, want %q", status, StatusEqual)
	}
	if sess == nil || sess.Metadata.SchemaVersion != 1 {
		t.Fatalf("session = %+v, want parsed session at schema_version 1", sess)
	}
}

func TestOpenSession_RejectsLegacyWholeObject(t *testing.T) {
	legacy := `{"metadata":{"id":"` + testMetaID + `","folder":"/p",` +
		`"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z",` +
		`"schema_version":1},"records":[]}`
	path := writeSessionFile(t, legacy)
	sess, status, err := OpenSession(path)
	if err == nil {
		t.Fatal("OpenSession() accepted legacy whole-object session, want rejection")
	}
	if sess != nil || status != "" {
		t.Fatalf("session=%+v status=%q, want nil session and empty status", sess, status)
	}
	var ve *VersionError
	if errors.As(err, &ve) {
		t.Fatalf("legacy whole-object rejection surfaced as *VersionError: %v", err)
	}
}

func TestOpenSession_IgnoresTruncatedFinalLine(t *testing.T) {
	complete := `{"type":"message","id":"` + testRecID1 + `","role":"user","content":"ok","timestamp":"2026-05-25T12:00:00.000Z"}`
	truncated := `{"type":"message","id":"` + testRecID2 + `","role":"user"`
	path := writeSessionFile(t, sessionJSONWithVersion("1")+complete+"\n"+truncated)
	sess, status, err := OpenSession(path)
	if err != nil {
		t.Fatalf("OpenSession() error = %v", err)
	}
	if status != StatusEqual {
		t.Fatalf("status = %q, want %q", status, StatusEqual)
	}
	if len(sess.Records) != 1 {
		t.Fatalf("records = %d, want only the last complete record", len(sess.Records))
	}
}

func TestOpenSession_NewerRefused(t *testing.T) {
	path := writeSessionFile(t, sessionJSONWithVersion("2"))
	sess, status, err := OpenSession(path)
	if sess != nil {
		t.Fatalf("session = %+v, want nil on refusal", sess)
	}
	if status != StatusNewer {
		t.Fatalf("status = %q, want %q", status, StatusNewer)
	}
	var ve *VersionError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *VersionError", err)
	}
	if ve.Status != StatusNewer || ve.Found == nil || ve.Found.Cmp(big.NewInt(2)) != 0 || ve.Supported != ReaderSupportedVersion {
		t.Fatalf("VersionError = %+v, want Status=newer Found=2 Supported=%d", ve, ReaderSupportedVersion)
	}
}

// A future schema_version too large for int64 is still a JSON integer greater
// than the supported version, so it must be refused as StatusNewer (not folded
// into the unparseable bucket) and the refusal must name the exact value.
func TestOpenSession_NewerBeyondInt64Refused(t *testing.T) {
	const raw = "9223372036854775808" // math.MaxInt64 + 1
	path := writeSessionFile(t, sessionJSONWithVersion(raw))
	sess, status, err := OpenSession(path)
	if sess != nil {
		t.Fatalf("session = %+v, want nil on refusal", sess)
	}
	if status != StatusNewer {
		t.Fatalf("status = %q, want %q", status, StatusNewer)
	}
	var ve *VersionError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *VersionError", err)
	}
	want, _ := new(big.Int).SetString(raw, 10)
	if ve.Status != StatusNewer || ve.Found == nil || ve.Found.Cmp(want) != 0 {
		t.Fatalf("VersionError = %+v, want Status=newer Found=%s", ve, raw)
	}
	if !strings.Contains(err.Error(), raw) {
		t.Fatalf("refusal message %q does not name the found version %q", err.Error(), raw)
	}
}

// A future-version file (schema_version 2) whose body the current record parser
// cannot accept — here, a malformed record line — must still be refused as StatusNewer
// with a *VersionError. This pins the ordering: OpenSession pre-scans
// metadata.schema_version and refuses a newer version before the full Unmarshal,
// so future-version refusal never depends on the body matching the current
// schema (a future breaking schema may carry a shape this parser rejects). The
// test fails if OpenSession is changed to Unmarshal first: Unmarshal reports the
// malformed record as an ordinary error, not a *VersionError, and the
// status would not be StatusNewer.
func TestOpenSession_NewerRefusedBeforeUnmarshal(t *testing.T) {
	body := `{"type":"metadata","metadata":{"id":"` + testMetaID + `","folder":"/p",` +
		`"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z",` +
		`"schema_version":2}}` + "\n" + `not-json` + "\n" // schema_version 2, malformed body
	// Guard the test's premise: the fixture must be one the full parser rejects,
	// otherwise it could not distinguish pre-parse refusal from post-parse refusal.
	if _, uerr := Unmarshal([]byte(body)); uerr == nil {
		t.Fatal("fixture must be rejected by Unmarshal, else it cannot prove pre-parse refusal")
	}
	path := writeSessionFile(t, body)
	sess, status, err := OpenSession(path)
	if sess != nil {
		t.Fatalf("session = %+v, want nil on refusal", sess)
	}
	if status != StatusNewer {
		t.Fatalf("status = %q, want %q", status, StatusNewer)
	}
	var ve *VersionError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *VersionError", err)
	}
	if ve.Status != StatusNewer || ve.Found == nil || ve.Found.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("VersionError = %+v, want Status=newer Found=2", ve)
	}
}

func TestOpenSession_UnparseableVersions(t *testing.T) {
	tests := []struct {
		name string
		raw  string // schema_version token; "" omits the field
	}{
		{"missing", ""},
		{"non-integer fractional", "1.5"},
		{"non-integer string", `"x"`},
		{"non-integer bool", "true"},
		{"zero", "0"},
		{"negative", "-3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSessionFile(t, sessionJSONWithVersion(tt.raw))
			sess, status, err := OpenSession(path)
			if sess != nil {
				t.Fatalf("session = %+v, want nil on refusal", sess)
			}
			if status != StatusUnparseable {
				t.Fatalf("status = %q, want %q", status, StatusUnparseable)
			}
			var ve *VersionError
			if !errors.As(err, &ve) {
				t.Fatalf("error %v is not a *VersionError", err)
			}
			if ve.Status != StatusUnparseable {
				t.Fatalf("VersionError.Status = %q, want %q", ve.Status, StatusUnparseable)
			}
		})
	}
}

// An older-version file is unreachable in phase 1 (ReaderSupportedVersion == 1),
// so the read-only-load path is exercised through the injectable helper: a v1
// file under a hypothetical v2 reader loads and reports older-fork-eligible.
func TestOpenSession_OlderForkEligibleLoads(t *testing.T) {
	path := writeSessionFile(t, sessionJSONWithVersion("1"))
	sess, status, err := openSession(path, 2)
	if err != nil {
		t.Fatalf("openSession(path, 2) error = %v", err)
	}
	if status != StatusOlderForkEligible {
		t.Fatalf("status = %q, want %q", status, StatusOlderForkEligible)
	}
	if sess == nil || sess.Metadata.SchemaVersion != 1 {
		t.Fatalf("session = %+v, want parsed older session", sess)
	}
}

// A genuine parse failure (not valid JSON, or not a session object) is an
// ordinary error with an empty status, never a *VersionError — surfaces
// it via the "cannot be parsed" path, separate from a version refusal.
func TestOpenSession_ParseFailureIsNotVersionError(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"not json", "this is not json"},
		{"json array not object", "[]"},
		{"truncated object", `{"metadata":`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSessionFile(t, tt.body)
			sess, status, err := OpenSession(path)
			if err == nil {
				t.Fatalf("OpenSession() = nil error, want parse failure")
			}
			if sess != nil || status != "" {
				t.Fatalf("session=%+v status=%q, want nil session and empty status", sess, status)
			}
			var ve *VersionError
			if errors.As(err, &ve) {
				t.Fatalf("parse failure surfaced as *VersionError: %v", err)
			}
		})
	}
}

func TestOpenSession_ReadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	_, status, err := OpenSession(path)
	if err == nil {
		t.Fatalf("OpenSession(missing) = nil error, want read error")
	}
	if status != "" {
		t.Fatalf("status = %q, want empty on read error", status)
	}
	var ve *VersionError
	if errors.As(err, &ve) {
		t.Fatalf("read error surfaced as *VersionError: %v", err)
	}
}

// The refusal message must name the file and both sides of the version mismatch
// so the operator can see what was found versus what the build supports.
func TestVersionError_NamesFileAndMismatch(t *testing.T) {
	path := writeSessionFile(t, sessionJSONWithVersion("2"))
	_, _, err := OpenSession(path)
	if err == nil {
		t.Fatalf("OpenSession() = nil error, want refusal")
	}
	msg := err.Error()
	for _, want := range []string{path, "2", "1"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal message %q does not contain %q", msg, want)
		}
	}
}
