// Package sessions defines the on-disk session JSONL schema, its marshal/unmarshal
// codec, and the per-record spine validation applied at load time.
package sessions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/ids"
)

// tsLayout is the canonical session timestamp form: UTC, millisecond precision,
// with a literal trailing Z. Writers always emit this; readers accept
// the broader RFC 3339 grammar.
const tsLayout = "2006-01-02T15:04:05.000Z"

// CurrentSchemaVersion is the schema_version stamped into freshly minted session
// metadata. It is the writer-side source of truth; the reader-side
// support is asserted against it via ReaderSupportedVersion >= CurrentSchemaVersion.
// JSONL is the pre-ship v1 baseline, so no legacy whole-object version is kept.
const CurrentSchemaVersion = 1

type Session struct {
	Metadata Metadata
	Records  []Record
}

// Metadata is the top-level session header. ID and the timestamps use
// the formats fixed in §Reserved Values; SchemaVersion is parsed as an integer
// here, with version classification deferred to ClassifyVersion.
type Metadata struct {
	ID            string
	Folder        string
	StartedAt     time.Time
	UpdatedAt     time.Time
	SchemaVersion int
	Title         string
	TitleSource   string
	ForkedFrom    *ForkOrigin
}

const (
	TitleSourceUser      = "user"
	TitleSourceGenerated = "generated"
)

func userTitleSource(title string) string {
	if title == "" {
		return ""
	}
	return TitleSourceUser
}

type ForkOrigin struct {
	SessionID string
	RecordID  string
}

type Record interface {
	isRecord()
}

// Message is a message record: a role-tagged turn whose content is
// either a plain string or a list of content-part objects.
type Message struct {
	ID         string
	Role       string
	Content    Content
	Timestamp  time.Time
	ToolCalls  []ToolCall // present only on assistant tool-call turns
	ToolCallID string     // present only on tool-result turns
	ParentID   string

	// toolCallsPresent and toolCallIDPresent record whether the JSON carried the
	// corresponding sibling field at load time, independent of its value. The
	// cross-record validator needs to tell an absent field from a
	// present-but-empty one (a missing tool_call_id versus an empty string; an
	// absent tool_calls versus a present empty list) — a distinction the value
	// fields alone cannot preserve. They are not marshaled.
	toolCallsPresent  bool
	toolCallIDPresent bool
}

func (Message) isRecord() {}

// Event is an event record: a kind-tagged entry with an opaque payload
// object. Per-kind payload shape is validated by the events package, not here.
type Event struct {
	ID        string
	Kind      string
	Timestamp time.Time
	Payload   json.RawMessage
	ParentID  string
}

func (Event) isRecord() {}

type Compaction struct {
	ID        string
	Summary   string
	Timestamp time.Time
	Provider  string
	ModelID   string
	ParentID  string
}

func (Compaction) isRecord() {}

// Content is a message's content: either a plain string or a list of content
// parts. Exactly one form is active; use IsList to discriminate.
type Content struct {
	isList bool
	text   string
	parts  []ContentPart
}

// TextContent builds string-valued message content.
func TextContent(s string) Content { return Content{text: s} }

// PartsContent builds list-valued message content from preserved content parts.
func PartsContent(parts []ContentPart) Content { return Content{isList: true, parts: parts} }

// IsList reports whether the content is a list of parts rather than a string.
func (c Content) IsList() bool { return c.isList }

// Text returns the string content (meaningful only when IsList is false).
func (c Content) Text() string { return c.text }

// Parts returns the content parts (meaningful only when IsList is true).
func (c Content) Parts() []ContentPart { return c.parts }

// ContentPart is one element of list-valued content. Type is the validated
// string discriminator; Raw is the whole part object preserved verbatim so
// unknown provider block types round-trip without interpretation.
type ContentPart struct {
	Type string
	Raw  json.RawMessage
}

// ToolCall is one entry of an assistant message's tool_calls list. ID is the
// entry's id, captured so the correlation validator can match it
// against following tool messages' tool_call_id; Type is the parsed type
// discriminator, whose must-be-"function" rule is enforced by
// ValidateRecordStream rather than at parse time; Raw is the whole entry object
// preserved verbatim.
type ToolCall struct {
	ID   string
	Type string
	Raw  json.RawMessage
}

// Marshal serializes a Session to its canonical JSONL byte form: the first line
// is a tagged metadata record, followed by one message/event record per line.
// Lines are compact JSON with stable field order and canonical UTC millisecond
// timestamps.
func Marshal(s *Session) ([]byte, error) {
	if err := validateProvenance(s.Metadata, s.Records); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	line, err := marshalMetadataLine(s.Metadata)
	if err != nil {
		return nil, err
	}
	out.Write(line)
	out.WriteByte('\n')
	for i, rec := range s.Records {
		line, err := marshalRecordLine(rec)
		if err != nil {
			return nil, fmt.Errorf("records[%d]: %w", i, err)
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func marshalMetadataLine(meta Metadata) ([]byte, error) {
	w := struct {
		Type     string       `json:"type"`
		Metadata wireMetadata `json:"metadata"`
	}{
		Type: "metadata",
		Metadata: wireMetadata{
			ID:            meta.ID,
			Folder:        meta.Folder,
			StartedAt:     formatTimestamp(meta.StartedAt),
			UpdatedAt:     formatTimestamp(meta.UpdatedAt),
			SchemaVersion: meta.SchemaVersion,
			Title:         meta.Title,
			TitleSource:   meta.TitleSource,
			ForkedFrom:    forkOriginWire(meta.ForkedFrom),
		},
	}
	return json.Marshal(w)
}

func forkOriginWire(o *ForkOrigin) *wireForkOrigin {
	if o == nil {
		return nil
	}
	return &wireForkOrigin{SessionID: o.SessionID, RecordID: o.RecordID}
}

func marshalRecordLine(rec Record) ([]byte, error) {
	if compaction, ok := rec.(*Compaction); ok && compaction == nil {
		return nil, fmt.Errorf("compaction must not be nil")
	}
	return json.Marshal(rec)
}

type wireMetadata struct {
	ID            string          `json:"id"`
	Folder        string          `json:"folder"`
	StartedAt     string          `json:"started_at"`
	UpdatedAt     string          `json:"updated_at"`
	SchemaVersion int             `json:"schema_version"`
	Title         string          `json:"title,omitempty"`
	TitleSource   string          `json:"title_source,omitempty"`
	ForkedFrom    *wireForkOrigin `json:"forked_from,omitempty"`
}

type wireForkOrigin struct {
	SessionID string `json:"session_id"`
	RecordID  string `json:"record_id"`
}

// MarshalJSON emits a message record with the type discriminator and the
// canonical field order; absent sibling fields are omitted.
func (m Message) MarshalJSON() ([]byte, error) {
	content, err := marshalContent(m.Content)
	if err != nil {
		return nil, err
	}
	w := struct {
		Type       string            `json:"type"`
		ID         string            `json:"id"`
		Role       string            `json:"role"`
		Content    json.RawMessage   `json:"content"`
		Timestamp  string            `json:"timestamp"`
		ToolCalls  []json.RawMessage `json:"tool_calls,omitempty"`
		ToolCallID string            `json:"tool_call_id,omitempty"`
		ParentID   string            `json:"parent_id,omitempty"`
	}{
		Type:       "message",
		ID:         m.ID,
		Role:       m.Role,
		Content:    content,
		Timestamp:  formatTimestamp(m.Timestamp),
		ToolCallID: m.ToolCallID,
		ParentID:   m.ParentID,
	}
	if len(m.ToolCalls) > 0 {
		w.ToolCalls = make([]json.RawMessage, len(m.ToolCalls))
		for i, tc := range m.ToolCalls {
			w.ToolCalls[i] = tc.Raw
		}
	}
	return json.Marshal(w)
}

// MarshalJSON emits an event record with the type discriminator and the
// canonical field order.
func (e Event) MarshalJSON() ([]byte, error) {
	w := struct {
		Type      string          `json:"type"`
		ID        string          `json:"id"`
		Kind      string          `json:"kind"`
		Timestamp string          `json:"timestamp"`
		Payload   json.RawMessage `json:"payload"`
		ParentID  string          `json:"parent_id,omitempty"`
	}{
		Type:      "event",
		ID:        e.ID,
		Kind:      e.Kind,
		Timestamp: formatTimestamp(e.Timestamp),
		Payload:   e.Payload,
		ParentID:  e.ParentID,
	}
	return json.Marshal(w)
}

func (c Compaction) MarshalJSON() ([]byte, error) {
	w := struct {
		Type      string `json:"type"`
		ID        string `json:"id"`
		Timestamp string `json:"timestamp"`
		Summary   string `json:"summary"`
		Provider  string `json:"provider"`
		ModelID   string `json:"model_id"`
		ParentID  string `json:"parent_id,omitempty"`
	}{
		Type:      "compaction",
		ID:        c.ID,
		Timestamp: formatTimestamp(c.Timestamp),
		Summary:   c.Summary,
		Provider:  c.Provider,
		ModelID:   c.ModelID,
		ParentID:  c.ParentID,
	}
	return json.Marshal(w)
}

func marshalContent(c Content) (json.RawMessage, error) {
	if c.isList {
		arr := make([]json.RawMessage, len(c.parts))
		for i, p := range c.parts {
			arr[i] = p.Raw
		}
		return json.Marshal(arr)
	}
	return json.Marshal(c.text)
}

func formatTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format(tsLayout)
}

func parseTimestamp(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func asCompaction(rec Record) (Compaction, bool) {
	switch r := rec.(type) {
	case Compaction:
		return r, true
	case *Compaction:
		if r == nil {
			return Compaction{}, false
		}
		return *r, true
	default:
		return Compaction{}, false
	}
}

// Unmarshal parses and validates a session JSONL stream, returning the in-memory
// Session. Validation covers the spine (required metadata and
// record fields, message role enum, event payload object, UUIDv7 ids) and the
// per-record content-part and tool-call entry shapes (each entry is a
// JSON object with string id/type). Cross-record correlation including the
// tool-call type-must-be-"function" rule, per-kind event
// payloads, and schema-version classification are intentionally
// out of scope here. Returned errors
// locate the offending field; callers add file context.
func Unmarshal(data []byte) (*Session, error) {
	lines := completeJSONLLines(data)
	if len(lines) == 0 {
		return nil, fmt.Errorf("session must start with a metadata line")
	}
	meta, err := parseMetadataLine(lines[0])
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(lines)-1)
	for i, line := range lines[1:] {
		rec, err := parseRecord(i, line)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	if err := validateProvenance(meta, records); err != nil {
		return nil, err
	}
	return &Session{Metadata: meta, Records: records}, nil
}

func validateProvenance(meta Metadata, records []Record) error {
	if ff := meta.ForkedFrom; ff != nil {
		if !ids.IsValidV7(ff.SessionID) {
			return fmt.Errorf("metadata.forked_from.session_id: %q is not a valid UUIDv7", ff.SessionID)
		}
		if !ids.IsValidV7(ff.RecordID) {
			return fmt.Errorf("metadata.forked_from.record_id: %q is not a valid UUIDv7", ff.RecordID)
		}
	}
	for i, rec := range records {
		if compaction, ok := rec.(*Compaction); ok && compaction == nil {
			return fmt.Errorf("records[%d]: compaction must not be nil", i)
		}
		if _, ok := asCompaction(rec); ok && i != 0 {
			return fmt.Errorf("records[%d]: a compaction is only permitted as the first record", i)
		}
		parentID := recordParentID(rec)
		if parentID == "" {
			continue
		}
		if i != 0 {
			return fmt.Errorf("records[%d].parent_id: parent_id is only permitted on the first record of a forked session", i)
		}
		if !ids.IsValidV7(parentID) {
			return fmt.Errorf("records[0].parent_id: %q is not a valid UUIDv7", parentID)
		}
		if meta.ForkedFrom == nil {
			return fmt.Errorf("records[0].parent_id: parent_id is present without metadata.forked_from")
		}
	}
	if meta.ForkedFrom == nil {
		if len(records) > 0 {
			if _, ok := asCompaction(records[0]); ok {
				return fmt.Errorf("records[0]: a compaction is only valid as record zero of a linked child (metadata.forked_from is missing)")
			}
		}
		return nil
	}
	if len(records) == 0 {
		return fmt.Errorf("records[0].parent_id: forked session has no first record to carry parent_id")
	}
	if got := recordParentID(records[0]); got != meta.ForkedFrom.RecordID {
		return fmt.Errorf("records[0].parent_id: %q does not match metadata.forked_from.record_id %q", got, meta.ForkedFrom.RecordID)
	}
	return nil
}

func parseParentID(i int, raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil || s == "" {
		return "", fmt.Errorf("records[%d].parent_id: must be a non-empty string", i)
	}
	return s, nil
}

func recordParentID(rec Record) string {
	switch r := rec.(type) {
	case Message:
		return r.ParentID
	case Event:
		return r.ParentID
	case Compaction:
		return r.ParentID
	case *Compaction:
		if r == nil {
			return ""
		}
		return r.ParentID
	default:
		return ""
	}
}

func withParentID(rec Record, parentID string) Record {
	switch r := rec.(type) {
	case Message:
		r.ParentID = parentID
		return r
	case Event:
		r.ParentID = parentID
		return r
	case Compaction:
		r.ParentID = parentID
		return r
	case *Compaction:
		if r == nil {
			return rec
		}
		cp := *r
		cp.ParentID = parentID
		return cp
	default:
		return rec
	}
}

func completeJSONLLines(data []byte) [][]byte {
	data = bytes.TrimRight(data, "\r")
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	// Complete lines are everything up to the final newline; the bytes after it are
	// an incomplete tail — the empty remainder of a terminating newline, or a torn
	// (partially written) final record — and are dropped. A buffer with no newline at
	// all is a single complete line (e.g. a bare metadata line) and is kept.
	//
	// Blank complete lines are deliberately NOT filtered out: after the metadata line
	// every complete line must be exactly one record entry, so an interior blank line
	// stays in the stream for parseRecord to reject. Filtering it would silently
	// stitch the surrounding records together and accept malformed input such as
	// "metadata\n\nmessage\n", where only a truncated final line may be discarded.
	complete := data
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		complete = data[:i]
	}
	return bytes.Split(complete, []byte("\n"))
}

// completeLineBoundary returns the byte offset immediately after the final
// newline in data — the end of the last complete JSONL line. Any bytes past it
// are a torn (incomplete) final line that completeJSONLLines drops on load, so an
// append-only writer must resume at this offset rather than physical EOF: starting
// at EOF would concatenate the new record onto the half-written tail and leave the
// file unparseable on the next load. Data with no newline yields 0.
func completeLineBoundary(data []byte) int64 {
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		return int64(i + 1)
	}
	return 0
}

func parseMetadataLine(raw json.RawMessage) (Metadata, error) {
	if !isJSONObject(raw) {
		return Metadata{}, fmt.Errorf("metadata line: must be a JSON object")
	}
	var line struct {
		Type     *string         `json:"type"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &line); err != nil {
		return Metadata{}, fmt.Errorf("metadata line: %w", err)
	}
	if line.Type == nil || *line.Type != "metadata" {
		return Metadata{}, fmt.Errorf("metadata line: type must be %q", "metadata")
	}
	if len(line.Metadata) == 0 {
		return Metadata{}, fmt.Errorf("metadata: required object is missing")
	}
	return parseMetadata(line.Metadata)
}

func parseMetadata(raw json.RawMessage) (Metadata, error) {
	if !isJSONObject(raw) {
		return Metadata{}, fmt.Errorf("metadata: must be a JSON object")
	}
	var rm struct {
		ID            *string         `json:"id"`
		Folder        *string         `json:"folder"`
		StartedAt     *string         `json:"started_at"`
		UpdatedAt     *string         `json:"updated_at"`
		SchemaVersion *int            `json:"schema_version"`
		Title         *string         `json:"title"`
		TitleSource   *string         `json:"title_source"`
		ForkedFrom    json.RawMessage `json:"forked_from"`
	}
	if err := json.Unmarshal(raw, &rm); err != nil {
		return Metadata{}, fmt.Errorf("metadata: %w", err)
	}
	if rm.ID == nil {
		return Metadata{}, fmt.Errorf("metadata.id: required field is missing")
	}
	if !ids.IsValidV7(*rm.ID) {
		return Metadata{}, fmt.Errorf("metadata.id: %q is not a valid UUIDv7", *rm.ID)
	}
	if rm.Folder == nil {
		return Metadata{}, fmt.Errorf("metadata.folder: required field is missing")
	}
	if rm.StartedAt == nil {
		return Metadata{}, fmt.Errorf("metadata.started_at: required field is missing")
	}
	started, err := parseTimestamp(*rm.StartedAt)
	if err != nil {
		return Metadata{}, fmt.Errorf("metadata.started_at: %w", err)
	}
	if rm.UpdatedAt == nil {
		return Metadata{}, fmt.Errorf("metadata.updated_at: required field is missing")
	}
	updated, err := parseTimestamp(*rm.UpdatedAt)
	if err != nil {
		return Metadata{}, fmt.Errorf("metadata.updated_at: %w", err)
	}
	if rm.SchemaVersion == nil {
		return Metadata{}, fmt.Errorf("metadata.schema_version: required field is missing")
	}
	title := ""
	if rm.Title != nil {
		title = *rm.Title
	}
	titleSource := ""
	if rm.TitleSource != nil {
		titleSource = *rm.TitleSource
	}
	forkedFrom, err := parseForkOrigin(rm.ForkedFrom)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{
		ID:            *rm.ID,
		Folder:        *rm.Folder,
		StartedAt:     started,
		UpdatedAt:     updated,
		SchemaVersion: *rm.SchemaVersion,
		Title:         title,
		TitleSource:   titleSource,
		ForkedFrom:    forkedFrom,
	}, nil
}

func parseForkOrigin(raw json.RawMessage) (*ForkOrigin, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if !isJSONObject(trimmed) {
		return nil, fmt.Errorf("metadata.forked_from: must be a JSON object")
	}
	var wf struct {
		SessionID *string `json:"session_id"`
		RecordID  *string `json:"record_id"`
	}
	if err := json.Unmarshal(trimmed, &wf); err != nil {
		return nil, fmt.Errorf("metadata.forked_from: %w", err)
	}
	if wf.SessionID == nil {
		return nil, fmt.Errorf("metadata.forked_from.session_id: required field is missing")
	}
	if wf.RecordID == nil {
		return nil, fmt.Errorf("metadata.forked_from.record_id: required field is missing")
	}
	return &ForkOrigin{SessionID: *wf.SessionID, RecordID: *wf.RecordID}, nil
}

func parseRecord(i int, raw json.RawMessage) (Record, error) {
	if !isJSONObject(raw) {
		return nil, fmt.Errorf("records[%d]: must be a JSON object", i)
	}
	var disc struct {
		Type *string `json:"type"`
	}
	if err := json.Unmarshal(raw, &disc); err != nil {
		return nil, fmt.Errorf("records[%d].type: %w", i, err)
	}
	if disc.Type == nil {
		return nil, fmt.Errorf("records[%d]: missing required field \"type\"", i)
	}
	switch *disc.Type {
	case "message":
		return parseMessage(i, raw)
	case "event":
		return parseEvent(i, raw)
	case "compaction":
		return parseCompaction(i, raw)
	default:
		return nil, fmt.Errorf("records[%d]: unknown record type %q", i, *disc.Type)
	}
}

var validRoles = map[string]struct{}{
	"user":          {},
	"assistant":     {},
	"system":        {},
	"tool":          {},
	"model_context": {},
}

func parseMessage(i int, raw json.RawMessage) (Record, error) {
	var rm struct {
		ID         *string         `json:"id"`
		Role       *string         `json:"role"`
		Content    json.RawMessage `json:"content"`
		Timestamp  *string         `json:"timestamp"`
		ToolCalls  json.RawMessage `json:"tool_calls"`
		ToolCallID json.RawMessage `json:"tool_call_id"`
		ParentID   json.RawMessage `json:"parent_id"`
	}
	if err := json.Unmarshal(raw, &rm); err != nil {
		return nil, fmt.Errorf("records[%d]: %w", i, err)
	}
	if rm.ID == nil {
		return nil, fmt.Errorf("records[%d].id: required field is missing", i)
	}
	if !ids.IsValidV7(*rm.ID) {
		return nil, fmt.Errorf("records[%d].id: %q is not a valid UUIDv7", i, *rm.ID)
	}
	if rm.Role == nil {
		return nil, fmt.Errorf("records[%d].role: required field is missing", i)
	}
	if _, ok := validRoles[*rm.Role]; !ok {
		return nil, fmt.Errorf("records[%d].role: %q is not one of user/assistant/system/tool/model_context", i, *rm.Role)
	}
	if rm.Timestamp == nil {
		return nil, fmt.Errorf("records[%d].timestamp: required field is missing", i)
	}
	ts, err := parseTimestamp(*rm.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("records[%d].timestamp: %w", i, err)
	}
	if len(bytes.TrimSpace(rm.Content)) == 0 {
		return nil, fmt.Errorf("records[%d].content: required field is missing", i)
	}
	content, err := parseContent(i, rm.Content)
	if err != nil {
		return nil, err
	}
	if *rm.Role == "model_context" {
		if err := validateModelContextContent(i, content); err != nil {
			return nil, err
		}
	}
	parentID, err := parseParentID(i, rm.ParentID)
	if err != nil {
		return nil, err
	}
	msg := Message{ID: *rm.ID, Role: *rm.Role, Content: content, Timestamp: ts, ParentID: parentID}
	// Record sibling-field presence by JSON-key presence (an absent key leaves the
	// RawMessage empty; a present null still counts), but interpret the value only
	// on the role permitted to carry it. Parsing a disallowed-role value
	// here would surface a shape error (e.g. "tool_calls: must be a list" for a
	// present null, or a tool_call_id JSON type error) before ValidateRecordStream
	// could emit the exact "is only permitted on role: ..." sibling-field error;
	// deferring the parse lets the role-placement rule win.
	if len(bytes.TrimSpace(rm.ToolCalls)) != 0 {
		msg.toolCallsPresent = true
		if msg.Role == "assistant" {
			calls, err := parseToolCalls(i, rm.ToolCalls)
			if err != nil {
				return nil, err
			}
			msg.ToolCalls = calls
		}
	}
	// tool_call_id mirrors the tool_calls handling above: presence is tracked for
	// every role, but a present non-null value is decoded only on role: tool. A
	// present null leaves ToolCallID empty (which trips the tool-message empty
	// check); a present value on a non-tool role stays unparsed so the sibling-field
	// rule reports it.
	if trimmed := bytes.TrimSpace(rm.ToolCallID); len(trimmed) != 0 {
		msg.toolCallIDPresent = true
		if msg.Role == "tool" && !bytes.Equal(trimmed, []byte("null")) {
			if err := json.Unmarshal(trimmed, &msg.ToolCallID); err != nil {
				return nil, fmt.Errorf("records[%d].tool_call_id: %w", i, err)
			}
		}
	}
	return msg, nil
}

func validateModelContextContent(i int, c Content) error {
	if !c.IsList() || len(c.Parts()) == 0 {
		return fmt.Errorf("records[%d].content: model_context message must be a non-empty list of image_url parts", i)
	}
	for j, p := range c.Parts() {
		if p.Type != "image_url" {
			return fmt.Errorf("records[%d].content[%d]: model_context parts must be image_url, got %q", i, j, p.Type)
		}
	}
	return nil
}

func parseContent(i int, raw json.RawMessage) (Content, error) {
	t := bytes.TrimSpace(raw)
	switch t[0] {
	case '"':
		var s string
		if err := json.Unmarshal(t, &s); err != nil {
			return Content{}, fmt.Errorf("records[%d].content: %w", i, err)
		}
		return TextContent(s), nil
	case '[':
		var elems []json.RawMessage
		if err := json.Unmarshal(t, &elems); err != nil {
			return Content{}, fmt.Errorf("records[%d].content: %w", i, err)
		}
		parts := make([]ContentPart, 0, len(elems))
		for j, e := range elems {
			et := bytes.TrimSpace(e)
			if len(et) == 0 || et[0] != '{' {
				return Content{}, fmt.Errorf("records[%d].content[%d]: content part must be a JSON object", i, j)
			}
			var probe struct {
				Type *string `json:"type"`
			}
			if err := json.Unmarshal(e, &probe); err != nil {
				return Content{}, fmt.Errorf("records[%d].content[%d].type: %w", i, j, err)
			}
			if probe.Type == nil {
				return Content{}, fmt.Errorf("records[%d].content[%d]: content part is missing a string \"type\"", i, j)
			}
			parts = append(parts, ContentPart{Type: *probe.Type, Raw: e})
		}
		return PartsContent(parts), nil
	default:
		return Content{}, fmt.Errorf("records[%d].content: must be a string or a list of content-part objects", i)
	}
}

func parseToolCalls(i int, raw json.RawMessage) ([]ToolCall, error) {
	t := bytes.TrimSpace(raw)
	if t[0] != '[' {
		return nil, fmt.Errorf("records[%d].tool_calls: must be a list", i)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(t, &elems); err != nil {
		return nil, fmt.Errorf("records[%d].tool_calls: %w", i, err)
	}
	calls := make([]ToolCall, 0, len(elems))
	for j, e := range elems {
		et := bytes.TrimSpace(e)
		if len(et) == 0 || et[0] != '{' {
			return nil, fmt.Errorf("records[%d].tool_calls[%d]: must be a JSON object", i, j)
		}
		var probe struct {
			ID   *string `json:"id"`
			Type *string `json:"type"`
		}
		if err := json.Unmarshal(e, &probe); err != nil {
			return nil, fmt.Errorf("records[%d].tool_calls[%d].type: %w", i, j, err)
		}
		// The type-must-be-"function" rule is enforced by
		// ValidateRecordStream, not here, so the production load path returns the
		// exact error with its record index. Parsing only preserves the
		// id and type for that validator and keeps the entry's raw JSON verbatim.
		id := ""
		if probe.ID != nil {
			id = *probe.ID
		}
		typ := ""
		if probe.Type != nil {
			typ = *probe.Type
		}
		calls = append(calls, ToolCall{ID: id, Type: typ, Raw: e})
	}
	return calls, nil
}

func parseEvent(i int, raw json.RawMessage) (Record, error) {
	var re struct {
		ID        *string         `json:"id"`
		Kind      *string         `json:"kind"`
		Timestamp *string         `json:"timestamp"`
		Payload   json.RawMessage `json:"payload"`
		ParentID  json.RawMessage `json:"parent_id"`
	}
	if err := json.Unmarshal(raw, &re); err != nil {
		return nil, fmt.Errorf("records[%d]: %w", i, err)
	}
	if re.ID == nil {
		return nil, fmt.Errorf("records[%d].id: required field is missing", i)
	}
	if !ids.IsValidV7(*re.ID) {
		return nil, fmt.Errorf("records[%d].id: %q is not a valid UUIDv7", i, *re.ID)
	}
	if re.Kind == nil {
		return nil, fmt.Errorf("records[%d].kind: required field is missing", i)
	}
	if *re.Kind == "" {
		return nil, fmt.Errorf("records[%d].kind: must be a non-empty string", i)
	}
	if re.Timestamp == nil {
		return nil, fmt.Errorf("records[%d].timestamp: required field is missing", i)
	}
	ts, err := parseTimestamp(*re.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("records[%d].timestamp: %w", i, err)
	}
	if len(bytes.TrimSpace(re.Payload)) == 0 {
		return nil, fmt.Errorf("records[%d].payload: required field is missing", i)
	}
	if !isJSONObject(re.Payload) {
		return nil, fmt.Errorf("records[%d].payload: must be a JSON object", i)
	}
	parentID, err := parseParentID(i, re.ParentID)
	if err != nil {
		return nil, err
	}
	return Event{ID: *re.ID, Kind: *re.Kind, Timestamp: ts, Payload: re.Payload, ParentID: parentID}, nil
}

func parseCompaction(i int, raw json.RawMessage) (Record, error) {
	var rc struct {
		ID        *string         `json:"id"`
		Timestamp *string         `json:"timestamp"`
		Summary   *string         `json:"summary"`
		Provider  *string         `json:"provider"`
		ModelID   *string         `json:"model_id"`
		ParentID  json.RawMessage `json:"parent_id"`
	}
	if err := json.Unmarshal(raw, &rc); err != nil {
		return nil, fmt.Errorf("records[%d]: %w", i, err)
	}
	if rc.ID == nil {
		return nil, fmt.Errorf("records[%d].id: required field is missing", i)
	}
	if !ids.IsValidV7(*rc.ID) {
		return nil, fmt.Errorf("records[%d].id: %q is not a valid UUIDv7", i, *rc.ID)
	}
	if rc.Timestamp == nil {
		return nil, fmt.Errorf("records[%d].timestamp: required field is missing", i)
	}
	ts, err := parseTimestamp(*rc.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("records[%d].timestamp: %w", i, err)
	}
	if rc.Summary == nil {
		return nil, fmt.Errorf("records[%d].summary: required field is missing", i)
	}
	if strings.TrimSpace(*rc.Summary) == "" {
		return nil, fmt.Errorf("records[%d].summary: must be a non-empty string", i)
	}
	if rc.Provider == nil {
		return nil, fmt.Errorf("records[%d].provider: required field is missing", i)
	}
	if strings.TrimSpace(*rc.Provider) == "" {
		return nil, fmt.Errorf("records[%d].provider: must be a non-empty string", i)
	}
	if rc.ModelID == nil {
		return nil, fmt.Errorf("records[%d].model_id: required field is missing", i)
	}
	if strings.TrimSpace(*rc.ModelID) == "" {
		return nil, fmt.Errorf("records[%d].model_id: must be a non-empty string", i)
	}
	parentID, err := parseParentID(i, rc.ParentID)
	if err != nil {
		return nil, err
	}
	return Compaction{ID: *rc.ID, Timestamp: ts, Summary: *rc.Summary, Provider: *rc.Provider, ModelID: *rc.ModelID, ParentID: parentID}, nil
}

func isJSONObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{'
}
