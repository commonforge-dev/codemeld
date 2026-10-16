// Tests for the synthetic deny-reason envelope builder and its delivery seam.
package permissions

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

// parseEnvelope decodes a built envelope and asserts it is clean JSON with
// denied_by == "user", returning the reason field for further checks.
func parseEnvelope(t *testing.T, envelope string) string {
	t.Helper()
	var got struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(envelope), &got); err != nil {
		t.Fatalf("envelope is not clean JSON: %v (envelope=%q)", err, envelope)
	}
	if got.DeniedBy != "user" {
		t.Fatalf("denied_by = %q, want %q", got.DeniedBy, "user")
	}
	return got.Reason
}

func TestBuildDenyEnvelope_WorkedExample(t *testing.T) {
	got := BuildDenyEnvelope("path is outside the repo")
	want := `{"denied_by":"user","reason":"path is outside the repo"}`
	if got != want {
		t.Fatalf("envelope = %q, want %q", got, want)
	}
}

func TestBuildModeDenyEnvelope_WorkedExample(t *testing.T) {
	// a mode-posture denial carries denied_by "mode" (not "user") and the reason
	// the caller supplies, in the same pinned field order as the user envelope.
	got := BuildModeDenyEnvelope("plan mode is read-only; this command is classified as mutating")
	want := `{"denied_by":"mode","reason":"plan mode is read-only; this command is classified as mutating"}`
	if got != want {
		t.Fatalf("mode envelope = %q, want %q", got, want)
	}
}

func TestBuildGuardDenyEnvelope_WorkedExample(t *testing.T) {
	got := BuildGuardDenyEnvelope()
	want := `{"denied_by":"guard","reason":"codemeld settings files are protected; manage grants with /settings"}`
	if got != want {
		t.Fatalf("guard envelope = %q, want %q", got, want)
	}
	if got != BuildGuardDenyEnvelope() {
		t.Fatal("guard envelope is not stable across calls")
	}
}

func TestBuildUnattendedDenyEnvelope_WorkedExample(t *testing.T) {
	got := BuildUnattendedDenyEnvelope("no approval available in non-interactive run mode")
	want := `{"denied_by":"unattended","reason":"no approval available in non-interactive run mode"}`
	if got != want {
		t.Fatalf("unattended envelope = %q, want %q", got, want)
	}
	if !IsModeDenyEnvelope(got) {
		t.Fatalf("IsModeDenyEnvelope(%q) = false; a run with no approver would still halt on its own refusal", got)
	}
}

func TestBuildBlockedPathDenyEnvelope(t *testing.T) {
	cases := []struct {
		target, entry string
		floor         bool
		want          string
	}{
		{"~/.ssh/id_rsa", "~/.ssh", false, `{"denied_by":"guard","reason":"~/.ssh/id_rsa is blocked by your blocked_paths entry ~/.ssh"}`},
		{"~/.codemeld/global/settings.yaml", "~/.codemeld", true, `{"denied_by":"guard","reason":"~/.codemeld/global/settings.yaml is inside codemeld's protected folder ~/.codemeld"}`},
	}
	for _, c := range cases {
		got := BuildBlockedPathDenyEnvelope(c.target, c.entry, c.floor)
		if got != c.want {
			t.Fatalf("envelope = %q, want %q", got, c.want)
		}
		if !IsModeDenyEnvelope(got) {
			t.Fatalf("IsModeDenyEnvelope(%q) = false, want a recoverable guard denial", got)
		}
	}
}

func TestBuildBlockedPathDenyEnvelope_LongTargetKeepsEntry(t *testing.T) {
	target := "~/" + strings.Repeat("dir/", 200) + "key"
	for _, c := range []struct {
		entry  string
		floor  bool
		suffix string
	}{
		{"~/.ssh", false, " is blocked by your blocked_paths entry ~/.ssh"},
		{"~/.codemeld", true, " is inside codemeld's protected folder ~/.codemeld"},
	} {
		var got denyEnvelope
		if err := json.Unmarshal([]byte(BuildBlockedPathDenyEnvelope(target, c.entry, c.floor)), &got); err != nil {
			t.Fatalf("envelope is not clean JSON: %v", err)
		}
		if len(got.Reason) > maxDenyReasonBytes || !utf8.ValidString(got.Reason) {
			t.Fatalf("reason is %d bytes (valid UTF-8 %v), want at most %d", len(got.Reason), utf8.ValidString(got.Reason), maxDenyReasonBytes)
		}
		if !strings.HasPrefix(got.Reason, "~/dir/") || !strings.HasSuffix(got.Reason, "…"+c.suffix) {
			t.Fatalf("reason = %q, want the shortened target followed by %q", got.Reason, c.suffix)
		}
	}
}

func TestIsRecoverableDeniedBy(t *testing.T) {
	cases := []struct {
		deniedBy string
		want     bool
	}{
		{"mode", true},
		{"guard", true},
		{"unattended", true},
		{"user", false},
		{"sideways", false},
		{"", false},
		{"Guard", false},
		{"Unattended", false},
	}
	for _, c := range cases {
		if got := IsRecoverableDeniedBy(c.deniedBy); got != c.want {
			t.Fatalf("IsRecoverableDeniedBy(%q) = %v, want %v", c.deniedBy, got, c.want)
		}
	}
}

// TestIsModeDenyEnvelope covers the recoverable-denial classifier: a well-formed envelope with
// a reason and a recoverable denied_by ("mode", "guard" or "unattended") is recoverable; a user
// envelope, malformed JSON, a reasonless envelope of any recoverable kind, an unknown kind, and
// empty input all fail closed to false so an unclassifiable denial stays terminal.
func TestIsModeDenyEnvelope(t *testing.T) {
	cases := []struct {
		name     string
		envelope string
		want     bool
	}{
		{"mode", BuildModeDenyEnvelope("plan is read-only"), true},
		{"guard", BuildGuardDenyEnvelope(), true},
		{"user", BuildDenyEnvelope("no"), false},
		{"malformed", `{"denied_by":`, false},
		{"empty", "", false},
		{"unknown kind", `{"denied_by":"other","reason":"x"}`, false},
		{"missing reason", `{"denied_by":"mode"}`, false},
		{"empty reason", `{"denied_by":"mode","reason":""}`, false},
		{"blank reason", `{"denied_by":"mode","reason":" \t"}`, false},
		{"guard missing reason", `{"denied_by":"guard"}`, false},
		{"guard blank reason", `{"denied_by":"guard","reason":" \t"}`, false},
		{"unattended", BuildUnattendedDenyEnvelope("no approver"), true},
		{"unattended missing reason", `{"denied_by":"unattended"}`, false},
		{"unattended blank reason", `{"denied_by":"unattended","reason":" \t"}`, false},
	}
	for _, c := range cases {
		if got := IsModeDenyEnvelope(c.envelope); got != c.want {
			t.Fatalf("%s: IsModeDenyEnvelope(%q) = %v, want %v", c.name, c.envelope, got, c.want)
		}
	}
}

// TestDenyEnvelope_ClosedEnum asserts the only denied_by values the builders produce are the
// closed enum "user" | "mode" | "guard" | "unattended" — one builder per value — with
// byte-identical reason normalization between the builders that take caller text.
func TestDenyEnvelope_ClosedEnum(t *testing.T) {
	const reason = "spaced reason"
	user := BuildDenyEnvelope("  " + reason + "  ")
	modeEnv := BuildModeDenyEnvelope("  " + reason + "  ")
	guardEnv := BuildGuardDenyEnvelope()
	unattendedEnv := BuildUnattendedDenyEnvelope("  " + reason + "  ")
	if user != `{"denied_by":"user","reason":"spaced reason"}` {
		t.Fatalf("user envelope = %q", user)
	}
	if modeEnv != `{"denied_by":"mode","reason":"spaced reason"}` {
		t.Fatalf("mode envelope = %q", modeEnv)
	}
	if unattendedEnv != `{"denied_by":"unattended","reason":"spaced reason"}` {
		t.Fatalf("unattended envelope = %q", unattendedEnv)
	}
	for _, e := range []string{user, modeEnv, guardEnv, unattendedEnv} {
		var got struct {
			DeniedBy string `json:"denied_by"`
			Reason   string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(e), &got); err != nil {
			t.Fatalf("envelope is not clean JSON: %v (%q)", err, e)
		}
		switch got.DeniedBy {
		case "user", "mode", "guard", "unattended":
		default:
			t.Fatalf("denied_by = %q, want one of the closed enum user|mode|guard|unattended", got.DeniedBy)
		}
		if got.Reason == "" {
			t.Fatalf("envelope %q carries no reason", e)
		}
	}
}

func TestBuildDenyEnvelope_ReasonNormalization(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantReason string
	}{
		{"non-empty plain", "do not touch this", "do not touch this"},
		{"trims ASCII whitespace", "  \t\r\n\v\f spaced \f\v\n\r\t  ", "spaced"},
		{"empty becomes default", "", defaultDenyReason},
		{"whitespace-only becomes default", " \t\n\r\v\f ", defaultDenyReason},
		{"unicode whitespace is not trimmed", " keep ", " keep "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := parseEnvelope(t, BuildDenyEnvelope(tt.input))
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestBuildDenyEnvelope_MultiByteReasonPreserved(t *testing.T) {
	in := "café ☕ 日本語 — naïve"
	reason := parseEnvelope(t, BuildDenyEnvelope(in))
	if reason != in {
		t.Fatalf("reason = %q, want %q", reason, in)
	}
	if !utf8.ValidString(reason) {
		t.Fatalf("reason is not valid UTF-8: %q", reason)
	}
}

func TestBuildDenyEnvelope_OversizeCappedOnRuneBoundary(t *testing.T) {
	// "€" is 3 bytes; 171 runes = 513 bytes overflows the 512-byte cap by one
	// rune's worth, so the cut at 512 falls inside the 171st rune and must back
	// off to 170 whole runes (510 bytes).
	const euro = "€"
	in := strings.Repeat(euro, 171)
	reason := parseEnvelope(t, BuildDenyEnvelope(in))

	if !utf8.ValidString(reason) {
		t.Fatalf("capped reason is not valid UTF-8")
	}
	if len(reason) > maxDenyReasonBytes {
		t.Fatalf("capped reason is %d bytes, want <= %d", len(reason), maxDenyReasonBytes)
	}
	if got := utf8.RuneCountInString(reason); got != 170 {
		t.Fatalf("capped reason has %d runes, want 170", got)
	}
	if reason != strings.Repeat(euro, 170) {
		t.Fatalf("capped reason dropped or corrupted codepoints")
	}
}

func TestBuildDenyEnvelope_CapAtExactBoundary(t *testing.T) {
	// 256 two-byte runes = exactly 512 bytes: nothing is dropped.
	const eacute = "é" // é, 2 bytes
	in := strings.Repeat(eacute, 256)
	reason := parseEnvelope(t, BuildDenyEnvelope(in))
	if len(reason) != maxDenyReasonBytes {
		t.Fatalf("reason = %d bytes, want exactly %d", len(reason), maxDenyReasonBytes)
	}
	if reason != in {
		t.Fatalf("exactly-512-byte reason was altered")
	}
}

// stubAppender captures appended records without touching the filesystem.
type stubAppender struct{ records []sessions.Record }

func (s *stubAppender) Append(r sessions.Record) { s.records = append(s.records, r) }

func TestDeliverDeny_AppendsToolResultMessage(t *testing.T) {
	const toolCallID = "call_abc123"
	envelope := BuildDenyEnvelope("path is outside the repo")

	before := time.Now().UTC().Truncate(time.Millisecond)
	stub := &stubAppender{}
	DeliverDeny(toolCallID, envelope, stub)
	after := time.Now().UTC()

	if len(stub.records) != 1 {
		t.Fatalf("appended %d records, want 1", len(stub.records))
	}
	msg, ok := stub.records[0].(sessions.Message)
	if !ok {
		t.Fatalf("record type = %T, want sessions.Message", stub.records[0])
	}
	if !ids.IsValidV7(msg.ID) {
		t.Fatalf("id %q is not a valid UUIDv7", msg.ID)
	}
	if msg.Role != "tool" {
		t.Fatalf("role = %q, want %q", msg.Role, "tool")
	}
	if msg.ToolCallID != toolCallID {
		t.Fatalf("tool_call_id = %q, want %q", msg.ToolCallID, toolCallID)
	}
	if msg.Content.IsList() {
		t.Fatalf("content is a list, want string content")
	}
	if msg.Content.Text() != envelope {
		t.Fatalf("content = %q, want %q", msg.Content.Text(), envelope)
	}
	if msg.Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp location = %v, want UTC", msg.Timestamp.Location())
	}
	if !msg.Timestamp.Equal(msg.Timestamp.Truncate(time.Millisecond)) {
		t.Fatalf("timestamp %v is not millisecond-truncated", msg.Timestamp)
	}
	if msg.Timestamp.Before(before) || msg.Timestamp.After(after) {
		t.Fatalf("timestamp %v outside [%v, %v]", msg.Timestamp, before, after)
	}

	// The appended record must round-trip through the session codec as a valid
	// tool-result message under the existing schema.
	doc := &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            ids.NewV7(),
			Folder:        "/repo",
			StartedAt:     before,
			UpdatedAt:     before,
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
		Records: stub.records,
	}
	data, err := sessions.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	round, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	got, ok := round.Records[0].(sessions.Message)
	if !ok {
		t.Fatalf("round-tripped record type = %T, want sessions.Message", round.Records[0])
	}
	if got.ToolCallID != toolCallID || got.Content.Text() != envelope || got.Role != "tool" {
		t.Fatalf("round-trip altered the tool-result message: %+v", got)
	}
}
