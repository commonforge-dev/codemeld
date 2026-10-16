// Tests for session JSON marshal/unmarshal, canonical snapshot, spine
// validation rejections, and timestamp codec behavior.
package sessions

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const canonicalJSON = "{" + validMetaHome + "}\n" +
	`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":"hello","timestamp":"2026-05-25T12:00:00.000Z"}` + "\n" +
	`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02","role":"assistant","content":[{"type":"text","text":"hi"}],"timestamp":"2026-05-25T12:00:01.000Z","tool_calls":[{"id":"call_1","type":"function","function":{"name":"ls","arguments":"{}"}}]}` + "\n" +
	`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a03","role":"tool","content":"result","timestamp":"2026-05-25T12:00:02.000Z","tool_call_id":"call_1"}` + "\n" +
	`{"type":"event","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a04","kind":"launch_began","timestamp":"2026-05-25T12:00:03.000Z","payload":{"source":"fresh"}}` + "\n"

func canonicalSession() *Session {
	return &Session{
		Metadata: Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 5, 30, 250_000_000, time.UTC),
			SchemaVersion: 1,
		},
		Records: []Record{
			Message{
				ID:        "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01",
				Role:      "user",
				Content:   TextContent("hello"),
				Timestamp: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			},
			Message{
				ID:               "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02",
				Role:             "assistant",
				Content:          PartsContent([]ContentPart{{Type: "text", Raw: json.RawMessage(`{"type":"text","text":"hi"}`)}}),
				Timestamp:        time.Date(2026, 5, 25, 12, 0, 1, 0, time.UTC),
				ToolCalls:        []ToolCall{{ID: "call_1", Type: "function", Raw: json.RawMessage(`{"id":"call_1","type":"function","function":{"name":"ls","arguments":"{}"}}`)}},
				toolCallsPresent: true,
			},
			Message{
				ID:                "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a03",
				Role:              "tool",
				Content:           TextContent("result"),
				Timestamp:         time.Date(2026, 5, 25, 12, 0, 2, 0, time.UTC),
				ToolCallID:        "call_1",
				toolCallIDPresent: true,
			},
			Event{
				ID:        "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a04",
				Kind:      "launch_began",
				Timestamp: time.Date(2026, 5, 25, 12, 0, 3, 0, time.UTC),
				Payload:   json.RawMessage(`{"source":"fresh"}`),
			},
		},
	}
}

func TestMarshal_CanonicalSnapshot(t *testing.T) {
	got, err := Marshal(canonicalSession())
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(got) != canonicalJSON {
		t.Fatalf("Marshal() mismatch:\n got: %s\nwant: %s", got, canonicalJSON)
	}
}

func TestUnmarshal_Canonical(t *testing.T) {
	s, err := Unmarshal([]byte(canonicalJSON))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if s.Metadata.ID != "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b" {
		t.Errorf("metadata.id = %q", s.Metadata.ID)
	}
	if s.Metadata.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", s.Metadata.SchemaVersion)
	}
	if len(s.Records) != 4 {
		t.Fatalf("len(records) = %d, want 4", len(s.Records))
	}
	// Re-marshal must reproduce the canonical bytes exactly.
	got, err := Marshal(s)
	if err != nil {
		t.Fatalf("re-Marshal() error = %v", err)
	}
	if string(got) != canonicalJSON {
		t.Fatalf("re-Marshal() mismatch:\n got: %s\nwant: %s", got, canonicalJSON)
	}
}

// TestTitle_RoundTrip covers the optional metadata.title additive field
// (DW): a v1 file with no title key loads with Title:"" and re-marshals with no title key
// (the additive field stays non-breaking), a titled file round-trips with the "title"
// key, and CurrentSchemaVersion never bumps for the field.
func TestTitle_RoundTrip(t *testing.T) {
	const noTitleJSON = "{" + validMeta + "}\n"

	s, err := Unmarshal([]byte(noTitleJSON))
	if err != nil {
		t.Fatalf("Unmarshal(no title) error = %v", err)
	}
	if s.Metadata.Title != "" {
		t.Errorf("no-title load: Title = %q, want empty", s.Metadata.Title)
	}
	got, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal(no title) error = %v", err)
	}
	if strings.Contains(string(got), "title") {
		t.Errorf("untitled session re-marshaled with a title key: %s", got)
	}
	if string(got) != noTitleJSON {
		t.Errorf("untitled round-trip mismatch:\n got: %s\nwant: %s", got, noTitleJSON)
	}

	// A titled session marshals with the "title" key after schema_version and loads back.
	const titledJSON = `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1,"title":"my session"}}` + "\n"
	s.Metadata.Title = "my session"
	got, err = Marshal(s)
	if err != nil {
		t.Fatalf("Marshal(titled) error = %v", err)
	}
	if string(got) != titledJSON {
		t.Errorf("titled marshal mismatch:\n got: %s\nwant: %s", got, titledJSON)
	}
	back, err := Unmarshal([]byte(titledJSON))
	if err != nil {
		t.Fatalf("Unmarshal(titled) error = %v", err)
	}
	if back.Metadata.Title != "my session" {
		t.Errorf("titled load: Title = %q, want %q", back.Metadata.Title, "my session")
	}

	if CurrentSchemaVersion != 1 {
		t.Errorf("CurrentSchemaVersion = %d, want 1 (the title field must not bump it)", CurrentSchemaVersion)
	}
}

func TestTitleSource_RoundTrip(t *testing.T) {
	const userJSON = `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1,"title":"my session","title_source":"user"}}` + "\n"
	const generatedJSON = `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1,"title":"auto title","title_source":"generated"}}` + "\n"

	base, err := Unmarshal([]byte("{" + validMeta + "}\n"))
	if err != nil {
		t.Fatalf("Unmarshal(base) error = %v", err)
	}

	base.Metadata.Title = "my session"
	base.Metadata.TitleSource = TitleSourceUser
	got, err := Marshal(base)
	if err != nil {
		t.Fatalf("Marshal(user-set) error = %v", err)
	}
	if string(got) != userJSON {
		t.Errorf("user-set marshal mismatch:\n got: %s\nwant: %s", got, userJSON)
	}
	back, err := Unmarshal([]byte(userJSON))
	if err != nil {
		t.Fatalf("Unmarshal(user-set) error = %v", err)
	}
	if back.Metadata.TitleSource != TitleSourceUser {
		t.Errorf("user-set load: TitleSource = %q, want %q", back.Metadata.TitleSource, TitleSourceUser)
	}
	if back.Metadata.Title != "my session" {
		t.Errorf("user-set load: Title = %q, want %q", back.Metadata.Title, "my session")
	}

	base.Metadata.Title = "auto title"
	base.Metadata.TitleSource = TitleSourceGenerated
	got, err = Marshal(base)
	if err != nil {
		t.Fatalf("Marshal(generated) error = %v", err)
	}
	if string(got) != generatedJSON {
		t.Errorf("generated marshal mismatch:\n got: %s\nwant: %s", got, generatedJSON)
	}
	back, err = Unmarshal([]byte(generatedJSON))
	if err != nil {
		t.Fatalf("Unmarshal(generated) error = %v", err)
	}
	if back.Metadata.Title != "auto title" {
		t.Errorf("generated load: Title = %q, want %q", back.Metadata.Title, "auto title")
	}
	if back.Metadata.TitleSource != TitleSourceGenerated {
		t.Errorf("generated load: TitleSource = %q, want %q", back.Metadata.TitleSource, TitleSourceGenerated)
	}

	if CurrentSchemaVersion != 1 {
		t.Errorf("CurrentSchemaVersion = %d, want 1 (the title_source field must not bump it)", CurrentSchemaVersion)
	}
}

func TestTitleSource_AbsentAndUnknownAreNotUserSet(t *testing.T) {
	const legacyTitledJSON = `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1,"title":"legacy name"}}` + "\n"

	legacy, err := Unmarshal([]byte(legacyTitledJSON))
	if err != nil {
		t.Fatalf("Unmarshal(legacy titled) error = %v", err)
	}
	if legacy.Metadata.Title != "legacy name" {
		t.Errorf("legacy load: Title = %q, want %q (the raw title still loads)", legacy.Metadata.Title, "legacy name")
	}
	if legacy.Metadata.TitleSource != "" {
		t.Errorf("legacy load: TitleSource = %q, want empty for an absent key", legacy.Metadata.TitleSource)
	}
	roundTripped, err := Marshal(legacy)
	if err != nil {
		t.Fatalf("Marshal(legacy titled) error = %v", err)
	}
	if string(roundTripped) != legacyTitledJSON {
		t.Errorf("legacy round-trip mismatch:\n got: %s\nwant: %s", roundTripped, legacyTitledJSON)
	}

	const unknownSourceJSON = `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1,"title":"odd","title_source":"imported"}}` + "\n"
	unknown, err := Unmarshal([]byte(unknownSourceJSON))
	if err != nil {
		t.Fatalf("Unmarshal(unknown source) error = %v", err)
	}
	if unknown.Metadata.Title != "odd" || unknown.Metadata.TitleSource != "imported" {
		t.Errorf("unknown source: (Title, TitleSource) = (%q, %q), want (%q, %q)", unknown.Metadata.Title, unknown.Metadata.TitleSource, "odd", "imported")
	}
	roundTripped, err = Marshal(unknown)
	if err != nil {
		t.Fatalf("Marshal(unknown source) error = %v", err)
	}
	if string(roundTripped) != unknownSourceJSON {
		t.Errorf("unknown-source round-trip mismatch:\n got: %s\nwant: %s", roundTripped, unknownSourceJSON)
	}

	untitled, err := Unmarshal([]byte("{" + validMeta + "}\n"))
	if err != nil {
		t.Fatalf("Unmarshal(untitled) error = %v", err)
	}
	got, err := Marshal(untitled)
	if err != nil {
		t.Fatalf("Marshal(untitled) error = %v", err)
	}
	if strings.Contains(string(got), "title") {
		t.Errorf("untitled session re-marshaled with a title/title_source key: %s", got)
	}
}

const (
	parentSessionID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b01"
	parentRecordID  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b02"
	childRec0ID     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b03"
	childRec1ID     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b04"
)

func childMeta(forkedFrom string) string {
	meta := `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1`
	if forkedFrom != "" {
		meta += `,"forked_from":` + forkedFrom
	}
	return meta + "}}\n"
}

func childRecord(id, parentID string) string {
	rec := `{"type":"message","id":"` + id + `","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z"`
	if parentID != "" {
		rec += `,"parent_id":"` + parentID + `"`
	}
	return rec + "}\n"
}

func rawParentIDRecord(id, rawParentID string) string {
	return `{"type":"message","id":"` + id + `","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z","parent_id":` + rawParentID + "}\n"
}

func compactionRecord(id, parentID string) string {
	rec := `{"type":"compaction","id":"` + id + `","timestamp":"2026-05-25T12:00:00.000Z","summary":"prior context","provider":"anthropic","model_id":"claude-opus-4-8"`
	if parentID != "" {
		rec += `,"parent_id":"` + parentID + `"`
	}
	return rec + "}\n"
}

func compactionChildSession() *Session {
	return &Session{
		Metadata: Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/p",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
			ForkedFrom:    &ForkOrigin{SessionID: parentSessionID, RecordID: parentRecordID},
		},
		Records: []Record{
			Compaction{
				ID:        childRec0ID,
				Summary:   "prior context",
				Timestamp: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
				Provider:  "anthropic",
				ModelID:   "claude-opus-4-8",
				ParentID:  parentRecordID,
			},
			Event{
				ID:        childRec1ID,
				Kind:      "launch_began",
				Timestamp: time.Date(2026, 5, 25, 12, 0, 1, 0, time.UTC),
				Payload:   json.RawMessage(`{"source":"fork"}`),
			},
		},
	}
}

func TestForkProvenance_RoundTrip(t *testing.T) {
	doc := childMeta(`{"session_id":"`+parentSessionID+`","record_id":"`+parentRecordID+`"}`) +
		childRecord(childRec0ID, parentRecordID) +
		childRecord(childRec1ID, "")

	s, err := Unmarshal([]byte(doc))
	if err != nil {
		t.Fatalf("Unmarshal(child) error = %v", err)
	}
	if s.Metadata.ForkedFrom == nil {
		t.Fatalf("ForkedFrom = nil, want the parent provenance")
	}
	if s.Metadata.ForkedFrom.SessionID != parentSessionID || s.Metadata.ForkedFrom.RecordID != parentRecordID {
		t.Errorf("ForkedFrom = %+v, want {%s %s}", *s.Metadata.ForkedFrom, parentSessionID, parentRecordID)
	}
	if got := s.Records[0].(Message).ParentID; got != parentRecordID {
		t.Errorf("records[0].ParentID = %q, want %q", got, parentRecordID)
	}
	if got := s.Records[1].(Message).ParentID; got != "" {
		t.Errorf("records[1].ParentID = %q, want empty (only record zero is linked)", got)
	}

	got, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal(child) error = %v", err)
	}
	if string(got) != doc {
		t.Fatalf("child round-trip mismatch:\n got: %s\nwant: %s", got, doc)
	}
	if CurrentSchemaVersion != 1 {
		t.Errorf("CurrentSchemaVersion = %d, want 1 (the provenance fields must not bump it)", CurrentSchemaVersion)
	}

	plain, err := Marshal(canonicalSession())
	if err != nil {
		t.Fatalf("Marshal(non-forked) error = %v", err)
	}
	for _, key := range []string{"forked_from", "parent_id"} {
		if strings.Contains(string(plain), key) {
			t.Errorf("non-forked session marshaled with a %q key: %s", key, plain)
		}
	}
}

func TestForkProvenance_RejectedShapes(t *testing.T) {
	validOrigin := `{"session_id":"` + parentSessionID + `","record_id":"` + parentRecordID + `"}`
	tests := []struct {
		name    string
		json    string
		wantSub string
	}{
		{
			"forked_from not an object",
			childMeta(`5`) + childRecord(childRec0ID, parentRecordID),
			"metadata.forked_from: must be a JSON object",
		},
		{
			"forked_from missing session_id",
			childMeta(`{"record_id":"`+parentRecordID+`"}`) + childRecord(childRec0ID, parentRecordID),
			"metadata.forked_from.session_id: required field is missing",
		},
		{
			"forked_from missing record_id",
			childMeta(`{"session_id":"`+parentSessionID+`"}`) + childRecord(childRec0ID, parentRecordID),
			"metadata.forked_from.record_id: required field is missing",
		},
		{
			"non-UUIDv7 source session",
			childMeta(`{"session_id":"nope","record_id":"`+parentRecordID+`"}`) + childRecord(childRec0ID, parentRecordID),
			`metadata.forked_from.session_id: "nope" is not a valid UUIDv7`,
		},
		{
			"non-UUIDv7 source record",
			childMeta(`{"session_id":"`+parentSessionID+`","record_id":"nope"}`) + childRecord(childRec0ID, "nope"),
			`metadata.forked_from.record_id: "nope" is not a valid UUIDv7`,
		},
		{
			"missing child first record",
			childMeta(validOrigin),
			"forked session has no first record to carry parent_id",
		},
		{
			"mismatched parent_id",
			childMeta(validOrigin) + childRecord(childRec0ID, childRec1ID),
			"does not match metadata.forked_from.record_id",
		},
		{
			"unlinked first record",
			childMeta(validOrigin) + childRecord(childRec0ID, ""),
			`records[0].parent_id: "" does not match`,
		},
		{
			"parent_id on a later message record",
			childMeta(validOrigin) + childRecord(childRec0ID, parentRecordID) + childRecord(childRec1ID, parentRecordID),
			"records[1].parent_id: parent_id is only permitted on the first record",
		},
		{
			"parent_id on a later event record",
			childMeta(validOrigin) + childRecord(childRec0ID, parentRecordID) +
				`{"type":"event","id":"` + childRec1ID + `","kind":"launch_began","timestamp":"2026-05-25T12:00:00.000Z","payload":{"source":"fork"},"parent_id":"` + parentRecordID + `"}` + "\n",
			"records[1].parent_id: parent_id is only permitted on the first record",
		},
		{
			"parent_id without forked_from",
			childMeta("") + childRecord(childRec0ID, parentRecordID),
			"parent_id is present without metadata.forked_from",
		},
		{
			"non-UUIDv7 parent_id",
			childMeta(validOrigin) + childRecord(childRec0ID, "nope"),
			`records[0].parent_id: "nope" is not a valid UUIDv7`,
		},
		{
			"null parent_id on record zero",
			childMeta(validOrigin) + rawParentIDRecord(childRec0ID, `null`),
			"records[0].parent_id: must be a non-empty string",
		},
		{
			"empty parent_id on record zero",
			childMeta(validOrigin) + rawParentIDRecord(childRec0ID, `""`),
			"records[0].parent_id: must be a non-empty string",
		},
		{
			"non-string parent_id on record zero",
			childMeta(validOrigin) + rawParentIDRecord(childRec0ID, `5`),
			"records[0].parent_id: must be a non-empty string",
		},
		{
			"null parent_id on a later record",
			childMeta(validOrigin) + childRecord(childRec0ID, parentRecordID) + rawParentIDRecord(childRec1ID, `null`),
			"records[1].parent_id: must be a non-empty string",
		},
		{
			"empty parent_id on a later record of a non-forked session",
			childMeta("") + childRecord(childRec0ID, "") + rawParentIDRecord(childRec1ID, `""`),
			"records[1].parent_id: must be a non-empty string",
		},
		{
			"null parent_id on a later event record",
			childMeta(validOrigin) + childRecord(childRec0ID, parentRecordID) +
				`{"type":"event","id":"` + childRec1ID + `","kind":"launch_began","timestamp":"2026-05-25T12:00:00.000Z","payload":{"source":"fork"},"parent_id":null}` + "\n",
			"records[1].parent_id: must be a non-empty string",
		},
		{
			"null forked_from",
			childMeta(`null`) + childRecord(childRec0ID, parentRecordID),
			"metadata.forked_from: must be a JSON object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(tt.json))
			if err == nil {
				t.Fatalf("Unmarshal() = nil error, want rejection")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestMarshal_RejectsUnlinkableProvenance(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Session)
		wantSub string
	}{
		{
			"forked_from with no records",
			func(s *Session) {
				s.Records = nil
				s.Metadata.ForkedFrom = &ForkOrigin{SessionID: parentSessionID, RecordID: parentRecordID}
			},
			"forked session has no first record to carry parent_id",
		},
		{
			"first record not linked",
			func(s *Session) {
				s.Metadata.ForkedFrom = &ForkOrigin{SessionID: parentSessionID, RecordID: parentRecordID}
			},
			"does not match metadata.forked_from.record_id",
		},
		{
			"parent_id on a later record",
			func(s *Session) {
				s.Metadata.ForkedFrom = &ForkOrigin{SessionID: parentSessionID, RecordID: parentRecordID}
				s.Records[0] = withParentID(s.Records[0], parentRecordID)
				s.Records[1] = withParentID(s.Records[1], parentRecordID)
			},
			"records[1].parent_id: parent_id is only permitted on the first record",
		},
		{
			"non-UUIDv7 source",
			func(s *Session) {
				s.Metadata.ForkedFrom = &ForkOrigin{SessionID: "nope", RecordID: parentRecordID}
				s.Records[0] = withParentID(s.Records[0], parentRecordID)
			},
			`metadata.forked_from.session_id: "nope" is not a valid UUIDv7`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := canonicalSession()
			tt.mutate(s)
			_, err := Marshal(s)
			if err == nil {
				t.Fatalf("Marshal() = nil error, want rejection")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestRoundTrip_InMemory(t *testing.T) {
	want := canonicalSession()
	b, err := Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\nwant: %#v\n got: %#v", want, got)
	}
}

// Unmarshal must preserve the load-time facts the validator depends on:
// each tool-call entry's id, and whether the tool_calls / tool_call_id sibling
// fields were present (distinct from being present but empty).
func TestUnmarshal_PreservesSiblingPresence(t *testing.T) {
	recs := `{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":"hi","timestamp":"2026-05-25T12:00:00.000Z"},` +
		`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02","role":"assistant","content":"","timestamp":"2026-05-25T12:00:01.000Z","tool_calls":[{"id":"call_9","type":"function","function":{"name":"ls","arguments":"{}"}}]},` +
		`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a03","role":"tool","content":"r","timestamp":"2026-05-25T12:00:02.000Z","tool_call_id":""},` +
		`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a04","role":"assistant","content":"","timestamp":"2026-05-25T12:00:03.000Z","tool_calls":[]}`
	s, err := Unmarshal([]byte(withRecords(recs)))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(s.Records) != 4 {
		t.Fatalf("len(records) = %d, want 4", len(s.Records))
	}
	user := s.Records[0].(Message)
	if user.toolCallsPresent || user.toolCallIDPresent {
		t.Errorf("user message: presence flags = (%v,%v), want both false", user.toolCallsPresent, user.toolCallIDPresent)
	}
	asst := s.Records[1].(Message)
	if !asst.toolCallsPresent || asst.toolCallIDPresent {
		t.Errorf("assistant message: presence flags = (%v,%v), want (true,false)", asst.toolCallsPresent, asst.toolCallIDPresent)
	}
	if len(asst.ToolCalls) != 1 || asst.ToolCalls[0].ID != "call_9" {
		t.Errorf("assistant tool-call id = %+v, want one entry with id call_9", asst.ToolCalls)
	}
	tool := s.Records[2].(Message)
	if !tool.toolCallIDPresent || tool.toolCallsPresent {
		t.Errorf("tool message: presence flags = (%v,%v), want (false tool_calls, true tool_call_id)", tool.toolCallsPresent, tool.toolCallIDPresent)
	}
	if tool.ToolCallID != "" {
		t.Errorf("tool message tool_call_id = %q, want empty", tool.ToolCallID)
	}
	emptyCalls := s.Records[3].(Message)
	if !emptyCalls.toolCallsPresent || len(emptyCalls.ToolCalls) != 0 {
		t.Errorf("assistant with empty tool_calls: present=%v len=%d, want present=true len=0", emptyCalls.toolCallsPresent, len(emptyCalls.ToolCalls))
	}
}

const validMeta = `"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1}`
const validMetaHome = `"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/home/u/proj","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:05:30.250Z","schema_version":1}`

// withRecords wraps a comma-separated record body in a JSONL stream with valid metadata.
func withRecords(records string) string {
	doc := "{" + validMeta + "}\n"
	if strings.TrimSpace(records) == "" {
		return doc
	}
	var elems []json.RawMessage
	if err := json.Unmarshal([]byte("["+records+"]"), &elems); err != nil {
		panic(err)
	}
	for _, elem := range elems {
		doc += string(elem) + "\n"
	}
	return doc
}

func TestUnmarshal_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantSub string
	}{
		{
			"missing metadata id",
			`{"type":"metadata","metadata":{"folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1}}` + "\n",
			"metadata.id",
		},
		{
			"malformed metadata uuid",
			`{"type":"metadata","metadata":{"id":"not-a-uuid","folder":"/p","started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":1}}` + "\n",
			"is not a valid UUIDv7",
		},
		{
			"missing metadata object",
			`{"type":"metadata"}` + "\n",
			"metadata",
		},
		{
			"message missing id",
			withRecords(`{"type":"message","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z"}`),
			"records[0].id",
		},
		{
			"event missing id",
			withRecords(`{"type":"event","kind":"launch_began","timestamp":"2026-05-25T12:00:00.000Z","payload":{"source":"fresh"}}`),
			"records[0].id",
		},
		{
			"message malformed id",
			withRecords(`{"type":"message","id":"XYZ","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z"}`),
			"is not a valid UUIDv7",
		},
		{
			"missing record type",
			withRecords(`{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z"}`),
			"missing required field",
		},
		{
			"unknown record type",
			withRecords(`{"type":"bogus","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"}`),
			"unknown record type",
		},
		{
			"invalid message role",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"robot","content":"x","timestamp":"2026-05-25T12:00:00.000Z"}`),
			"role",
		},
		{
			"non-object event payload",
			withRecords(`{"type":"event","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","kind":"launch_began","timestamp":"2026-05-25T12:00:00.000Z","payload":"oops"}`),
			"payload: must be a JSON object",
		},
		{
			"content list non-object element",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":[123],"timestamp":"2026-05-25T12:00:00.000Z"}`),
			"content part must be a JSON object",
		},
		{
			"content part missing string type",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":[{"text":"hi"}],"timestamp":"2026-05-25T12:00:00.000Z"}`),
			"missing a string",
		},
		{
			"content part non-string type",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":[{"type":5}],"timestamp":"2026-05-25T12:00:00.000Z"}`),
			"content[0].type",
		},
		{
			"content neither string nor list",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":{"a":1},"timestamp":"2026-05-25T12:00:00.000Z"}`),
			"must be a string or a list",
		},
		{
			"tool call entry not object",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02","role":"assistant","content":"","timestamp":"2026-05-25T12:00:00.000Z","tool_calls":[42]}`),
			"tool_calls[0]: must be a JSON object",
		},
		{
			"message missing content",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","timestamp":"2026-05-25T12:00:00.000Z"}`),
			"content: required field is missing",
		},
		{
			"bad timestamp",
			withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":"x","timestamp":"yesterday"}`),
			"timestamp",
		},
		{
			"not a JSON object",
			`[]`,
			"must be a JSON object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(tt.json))
			if err == nil {
				t.Fatalf("Unmarshal() = nil error, want rejection")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

// A blank complete line inside the stream is malformed: after the metadata line
// every complete line must be one record entry, and only a truncated final line may
// be discarded. The allowed boundary "metadata\nmessage\n" loads;
// the invalid boundary "metadata\n\nmessage\n" must fail at the blank record line
// rather than being silently stitched over.
func TestUnmarshal_RejectsInteriorBlankLine(t *testing.T) {
	meta := "{" + validMeta + "}"
	msg := `{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z"}`

	allowed := meta + "\n" + msg + "\n"
	s, err := Unmarshal([]byte(allowed))
	if err != nil {
		t.Fatalf("Unmarshal(metadata\\nmessage\\n) error = %v, want nil", err)
	}
	if len(s.Records) != 1 {
		t.Fatalf("Unmarshal(metadata\\nmessage\\n) records = %d, want 1", len(s.Records))
	}

	invalid := meta + "\n\n" + msg + "\n"
	_, err = Unmarshal([]byte(invalid))
	if err == nil {
		t.Fatalf("Unmarshal(metadata\\n\\nmessage\\n) = nil error, want rejection of the blank record line")
	}
	for _, sub := range []string{"records[0]", "must be a JSON object"} {
		if !strings.Contains(err.Error(), sub) {
			t.Fatalf("error %q does not contain %q", err.Error(), sub)
		}
	}
}

// A non-function tool-call type is accepted by Unmarshal and rejected only by
// ValidateRecordStream with the exact wording, so the production load
// path (parse then validate) reports the type violation at its record index.
func TestUnmarshalThenValidate_NonFunctionToolCallType(t *testing.T) {
	in := withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02","role":"assistant","content":"","timestamp":"2026-05-25T12:00:00.000Z","tool_calls":[{"id":"call_1","type":"web"}]}`)
	s, err := Unmarshal([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil (type rule deferred to ValidateRecordStream)", err)
	}
	err = ValidateRecordStream(s.Records)
	want := `records[0]: assistant message has tool_call id "call_1" with type "web" (only "function" is permitted in phase 1)`
	if err == nil {
		t.Fatalf("ValidateRecordStream() = nil error, want %q", want)
	}
	if err.Error() != want {
		t.Fatalf("ValidateRecordStream() error =\n  %q\nwant\n  %q", err.Error(), want)
	}
}

// A present tool_call_id:null on a non-tool message must be tracked as present
// (not treated as an absent field) so the full load path reports the
// sibling-field violation rather than silently accepting it.
func TestUnmarshalThenValidate_NullToolCallIDOnNonToolRole(t *testing.T) {
	in := withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z","tool_call_id":null}`)
	s, err := Unmarshal([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil (sibling-field rule deferred to ValidateRecordStream)", err)
	}
	if msg := s.Records[0].(Message); !msg.toolCallIDPresent {
		t.Fatalf("toolCallIDPresent = false for present tool_call_id:null, want true")
	}
	err = ValidateRecordStream(s.Records)
	want := "records[0]: tool_call_id is only permitted on role: tool messages"
	if err == nil {
		t.Fatalf("ValidateRecordStream() = nil error, want %q", want)
	}
	if err.Error() != want {
		t.Fatalf("ValidateRecordStream() error =\n  %q\nwant\n  %q", err.Error(), want)
	}
}

// A present-but-malformed sibling field on a role not permitted to carry it must
// be accepted by Unmarshal and rejected by ValidateRecordStream with the exact
// sibling-field error. parseMessage must defer value interpretation to
// the permitted role so a wrong-shape value (null tool_calls, non-list
// tool_calls, non-string tool_call_id) on a disallowed role surfaces the
// placement error rather than a parser shape/type error.
func TestUnmarshalThenValidate_DisallowedRoleMalformedSiblingFields(t *testing.T) {
	const id = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a03"
	tests := []struct {
		name string
		rec  string
		want string
	}{
		{
			"null tool_calls on user role",
			`{"type":"message","id":"` + id + `","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z","tool_calls":null}`,
			"records[0]: tool_calls is only permitted on role: assistant messages",
		},
		{
			"non-list tool_calls on user role",
			`{"type":"message","id":"` + id + `","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z","tool_calls":123}`,
			"records[0]: tool_calls is only permitted on role: assistant messages",
		},
		{
			"non-string tool_call_id on user role",
			`{"type":"message","id":"` + id + `","role":"user","content":"x","timestamp":"2026-05-25T12:00:00.000Z","tool_call_id":123}`,
			"records[0]: tool_call_id is only permitted on role: tool messages",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Unmarshal([]byte(withRecords(tt.rec)))
			if err != nil {
				t.Fatalf("Unmarshal() error = %v, want nil (sibling-field rule deferred to ValidateRecordStream)", err)
			}
			err = ValidateRecordStream(s.Records)
			if err == nil {
				t.Fatalf("ValidateRecordStream() = nil error, want %q", tt.want)
			}
			if err.Error() != tt.want {
				t.Fatalf("ValidateRecordStream() error =\n  %q\nwant\n  %q", err.Error(), tt.want)
			}
		})
	}
}

func TestModelContext_RoundTrip(t *testing.T) {
	const rec = `{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a05","role":"model_context","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}],"timestamp":"2026-05-25T12:00:00.000Z"}`
	doc := withRecords(rec)

	s, err := Unmarshal([]byte(doc))
	if err != nil {
		t.Fatalf("Unmarshal(model_context) error = %v", err)
	}
	if len(s.Records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(s.Records))
	}
	msg, ok := s.Records[0].(Message)
	if !ok || msg.Role != "model_context" {
		t.Fatalf("record[0] = %+v, want a Message with role model_context", s.Records[0])
	}
	if !msg.Content.IsList() || len(msg.Content.Parts()) != 1 {
		t.Fatalf("content = %+v, want a one-part list", msg.Content)
	}
	if p := msg.Content.Parts()[0]; p.Type != "image_url" || string(p.Raw) != `{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}` {
		t.Fatalf("part = %+v, want the image_url part preserved verbatim", p)
	}
	if s.Metadata.SchemaVersion != 1 || CurrentSchemaVersion != 1 {
		t.Fatalf("schema version = %d / current = %d, want 1 (no bump)", s.Metadata.SchemaVersion, CurrentSchemaVersion)
	}
	got, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(got) != doc {
		t.Fatalf("re-Marshal mismatch:\n got: %s\nwant: %s", got, doc)
	}
}

func TestUnmarshal_RejectsNonImageModelContext(t *testing.T) {
	const id = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a05"
	tests := []struct {
		name string
		rec  string
	}{
		{"string content", `{"type":"message","id":"` + id + `","role":"model_context","content":"hi","timestamp":"2026-05-25T12:00:00.000Z"}`},
		{"empty list", `{"type":"message","id":"` + id + `","role":"model_context","content":[],"timestamp":"2026-05-25T12:00:00.000Z"}`},
		{"text part", `{"type":"message","id":"` + id + `","role":"model_context","content":[{"type":"text","text":"hi"}],"timestamp":"2026-05-25T12:00:00.000Z"}`},
		{"unknown part", `{"type":"message","id":"` + id + `","role":"model_context","content":[{"type":"audio"}],"timestamp":"2026-05-25T12:00:00.000Z"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(withRecords(tt.rec)))
			if err == nil {
				t.Fatalf("Unmarshal() = nil error, want rejection")
			}
			if !strings.Contains(err.Error(), "model_context") {
				t.Fatalf("error %q does not mention model_context", err.Error())
			}
		})
	}
}

func TestFormatTimestamp(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		want string
	}{
		{
			"truncates to millisecond",
			time.Date(2026, 5, 25, 12, 0, 0, 123_456_789, time.UTC),
			"2026-05-25T12:00:00.123Z",
		},
		{
			"converts to UTC",
			time.Date(2026, 5, 25, 14, 0, 0, 0, time.FixedZone("east", 2*3600)),
			"2026-05-25T12:00:00.000Z",
		},
		{
			"pads sub-millisecond zeros",
			time.Date(2026, 5, 25, 12, 0, 0, 5_000_000, time.UTC),
			"2026-05-25T12:00:00.005Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTimestamp(tt.in); got != tt.want {
				t.Fatalf("formatTimestamp() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseTimestamp_RelaxedRFC3339(t *testing.T) {
	for _, in := range []string{
		"2026-05-25T12:00:00.000Z",
		"2026-05-25T12:00:00Z",
		"2026-05-25T14:00:00.5+02:00",
		"2026-05-25T12:00:00.123456789Z",
	} {
		if _, err := parseTimestamp(in); err != nil {
			t.Errorf("parseTimestamp(%q) error = %v", in, err)
		}
	}
}

// On read, a timestamp without milliseconds is accepted; on re-write it is
// normalized to the canonical millisecond Z form.
func TestUnmarshal_RelaxedTimestampNormalizedOnWrite(t *testing.T) {
	in := `{"type":"metadata","metadata":{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","folder":"/p","started_at":"2026-05-25T12:00:00Z","updated_at":"2026-05-25T12:00:00+00:00","schema_version":1}}` + "\n"
	s, err := Unmarshal([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	got, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(got), `"started_at":"2026-05-25T12:00:00.000Z"`) {
		t.Fatalf("started_at not normalized: %s", got)
	}
	if !strings.Contains(string(got), `"updated_at":"2026-05-25T12:00:00.000Z"`) {
		t.Fatalf("updated_at not normalized: %s", got)
	}
}

func TestCompaction_RoundTrip(t *testing.T) {
	eventLine := `{"type":"event","id":"` + childRec1ID + `","kind":"launch_began","timestamp":"2026-05-25T12:00:01.000Z","payload":{"source":"fork"}}` + "\n"
	doc := childMeta(`{"session_id":"`+parentSessionID+`","record_id":"`+parentRecordID+`"}`) +
		compactionRecord(childRec0ID, parentRecordID) +
		eventLine

	got, err := Marshal(compactionChildSession())
	if err != nil {
		t.Fatalf("Marshal(compaction child) error = %v", err)
	}
	if string(got) != doc {
		t.Fatalf("compaction marshal mismatch:\n got: %s\nwant: %s", got, doc)
	}

	s, err := Unmarshal([]byte(doc))
	if err != nil {
		t.Fatalf("Unmarshal(compaction child) error = %v", err)
	}
	if s.Metadata.ForkedFrom == nil ||
		s.Metadata.ForkedFrom.SessionID != parentSessionID ||
		s.Metadata.ForkedFrom.RecordID != parentRecordID {
		t.Fatalf("ForkedFrom = %+v, want {%s %s}", s.Metadata.ForkedFrom, parentSessionID, parentRecordID)
	}
	c, ok := s.Records[0].(Compaction)
	if !ok {
		t.Fatalf("records[0] = %T, want Compaction", s.Records[0])
	}
	if c.ID != childRec0ID || c.Summary != "prior context" ||
		c.Provider != "anthropic" || c.ModelID != "claude-opus-4-8" ||
		c.ParentID != parentRecordID {
		t.Fatalf("compaction = %+v, want id/summary/provider/model_id/parent_id preserved", c)
	}
	if !c.Timestamp.Equal(time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("compaction timestamp = %v, want 2026-05-25T12:00:00Z", c.Timestamp)
	}
	if _, ok := s.Records[1].(Event); !ok {
		t.Fatalf("records[1] = %T, want Event (a completed child may carry a later launch_began)", s.Records[1])
	}

	if !reflect.DeepEqual(compactionChildSession(), s) {
		t.Fatalf("round-trip mismatch:\nwant: %#v\n got: %#v", compactionChildSession(), s)
	}
	if CurrentSchemaVersion != 1 {
		t.Errorf("CurrentSchemaVersion = %d, want 1 (the compaction record must not bump it)", CurrentSchemaVersion)
	}
}

func TestCompaction_Rejects(t *testing.T) {
	validOrigin := `{"session_id":"` + parentSessionID + `","record_id":"` + parentRecordID + `"}`
	linked := childMeta(validOrigin)
	unlinked := childMeta("")
	ts := `"timestamp":"2026-05-25T12:00:00.000Z"`
	pid := `"parent_id":"` + parentRecordID + `"`
	tests := []struct {
		name    string
		json    string
		wantSub string
	}{
		{
			"missing id",
			linked + `{"type":"compaction",` + ts + `,"summary":"s","provider":"p","model_id":"m",` + pid + "}\n",
			"records[0].id: required field is missing",
		},
		{
			"malformed id",
			linked + `{"type":"compaction","id":"XYZ",` + ts + `,"summary":"s","provider":"p","model_id":"m",` + pid + "}\n",
			"is not a valid UUIDv7",
		},
		{
			"missing timestamp",
			linked + `{"type":"compaction","id":"` + childRec0ID + `","summary":"s","provider":"p","model_id":"m",` + pid + "}\n",
			"records[0].timestamp: required field is missing",
		},
		{
			"malformed timestamp",
			linked + `{"type":"compaction","id":"` + childRec0ID + `","timestamp":"nope","summary":"s","provider":"p","model_id":"m",` + pid + "}\n",
			"records[0].timestamp",
		},
		{
			"missing summary",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"provider":"p","model_id":"m",` + pid + "}\n",
			"records[0].summary: required field is missing",
		},
		{
			"blank summary",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":"","provider":"p","model_id":"m",` + pid + "}\n",
			"records[0].summary: must be a non-empty string",
		},
		{
			"whitespace summary",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":" ","provider":"p","model_id":"m",` + pid + "}\n",
			"records[0].summary: must be a non-empty string",
		},
		{
			"missing provider",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":"s","model_id":"m",` + pid + "}\n",
			"records[0].provider: required field is missing",
		},
		{
			"blank provider",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":"s","provider":"","model_id":"m",` + pid + "}\n",
			"records[0].provider: must be a non-empty string",
		},
		{
			"whitespace provider",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":"s","provider":" ","model_id":"m",` + pid + "}\n",
			"records[0].provider: must be a non-empty string",
		},
		{
			"missing model_id",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":"s","provider":"p",` + pid + "}\n",
			"records[0].model_id: required field is missing",
		},
		{
			"blank model_id",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":"s","provider":"p","model_id":"",` + pid + "}\n",
			"records[0].model_id: must be a non-empty string",
		},
		{
			"whitespace model_id",
			linked + `{"type":"compaction","id":"` + childRec0ID + `",` + ts + `,"summary":"s","provider":"p","model_id":" ",` + pid + "}\n",
			"records[0].model_id: must be a non-empty string",
		},
		{
			"unlinked compaction",
			linked + compactionRecord(childRec0ID, ""),
			`records[0].parent_id: "" does not match`,
		},
		{
			"mismatched parent_id",
			linked + compactionRecord(childRec0ID, childRec1ID),
			"does not match metadata.forked_from.record_id",
		},
		{
			"compaction without forked_from",
			unlinked + compactionRecord(childRec0ID, ""),
			"a compaction is only valid as record zero of a linked child",
		},
		{
			"parent_id without forked_from",
			unlinked + compactionRecord(childRec0ID, parentRecordID),
			"parent_id is present without metadata.forked_from",
		},
		{
			"second compaction is not record zero",
			linked + compactionRecord(childRec0ID, parentRecordID) + compactionRecord(childRec1ID, ""),
			"records[1]: a compaction is only permitted as the first record",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(tt.json))
			if err == nil {
				t.Fatalf("Unmarshal() = nil error, want rejection")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestCompaction_HelperClosure(t *testing.T) {
	base := Compaction{
		ID:        childRec0ID,
		Summary:   "s",
		Timestamp: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
		Provider:  "p",
		ModelID:   "m",
	}
	if got := recordParentID(base); got != "" {
		t.Errorf("recordParentID(unstamped) = %q, want empty", got)
	}
	stamped := withParentID(base, parentRecordID)
	if got := recordParentID(stamped); got != parentRecordID {
		t.Errorf("recordParentID(stamped) = %q, want %q", got, parentRecordID)
	}
	if recordParentID(base) != "" {
		t.Errorf("withParentID mutated the source record's parent_id")
	}
}

func TestCompaction_PointerRecord(t *testing.T) {
	newComp := func(parentID string) *Compaction {
		return &Compaction{
			ID:        childRec0ID,
			Summary:   "s",
			Timestamp: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			Provider:  "p",
			ModelID:   "m",
			ParentID:  parentID,
		}
	}

	unlinked := &Session{
		Metadata: Metadata{
			ID:            parentSessionID,
			Folder:        "/p",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
		Records: []Record{newComp("")},
	}
	if _, err := Marshal(unlinked); err == nil {
		t.Fatalf("Marshal(unlinked *Compaction) = nil error, want rejection")
	} else if !strings.Contains(err.Error(), "a compaction is only valid as record zero of a linked child") {
		t.Fatalf("error %q does not name the linked-child rule", err.Error())
	}
	var nilCompaction *Compaction
	unlinked.Records = []Record{nilCompaction}
	if _, err := Marshal(unlinked); err == nil {
		t.Fatalf("Marshal(nil *Compaction) = nil error, want rejection")
	} else if !strings.Contains(err.Error(), "records[0]: compaction must not be nil") {
		t.Fatalf("error %q does not reject a nil compaction", err.Error())
	}
	if _, err := marshalRecordLines([]Record{nilCompaction}, 3); err == nil {
		t.Fatalf("marshalRecordLines(nil *Compaction) = nil error, want rejection")
	} else if !strings.Contains(err.Error(), "records[3]: compaction must not be nil") {
		t.Fatalf("append-path error %q does not reject a nil compaction at its record index", err.Error())
	}

	base := newComp("")
	if got := recordParentID(base); got != "" {
		t.Errorf("recordParentID(*Compaction unstamped) = %q, want empty", got)
	}
	stamped := withParentID(base, parentRecordID)
	if got := recordParentID(stamped); got != parentRecordID {
		t.Errorf("recordParentID(stamped *Compaction) = %q, want %q", got, parentRecordID)
	}
	if base.ParentID != "" {
		t.Errorf("withParentID mutated the caller's *Compaction: ParentID = %q", base.ParentID)
	}
}

func TestCompaction_ExistingV1Unaffected(t *testing.T) {
	s, err := Unmarshal([]byte(canonicalJSON))
	if err != nil {
		t.Fatalf("Unmarshal(existing v1) error = %v", err)
	}
	got, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal(existing v1) error = %v", err)
	}
	if strings.Contains(string(got), "compaction") {
		t.Errorf("existing message/event session marshaled with a compaction key: %s", got)
	}
	if s.Metadata.SchemaVersion != 1 || CurrentSchemaVersion != 1 {
		t.Errorf("schema version = %d / current = %d, want 1", s.Metadata.SchemaVersion, CurrentSchemaVersion)
	}

	unknown := childMeta(`{"session_id":"`+parentSessionID+`","record_id":"`+parentRecordID+`"}`) +
		`{"type":"compaction_from_the_future","id":"` + childRec0ID + `"}` + "\n"
	if _, err := Unmarshal([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown record type") {
		t.Fatalf("Unmarshal(unknown discriminator) error = %v, want an unknown record type rejection", err)
	}
}
