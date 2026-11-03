// Tests for the cross-record correlation, sibling-field, and
// launch_began source validation in ValidateRecordStream.
package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// --- record builders (set the load-time presence flags directly, mirroring
// what parseMessage records, so the validator sees the same facts it would on a
// loaded stream). ---

func tcEntry(id, typ string) ToolCall { return ToolCall{ID: id, Type: typ} }

func asstWithCalls(calls ...ToolCall) Message {
	return Message{Role: "assistant", ToolCalls: calls, toolCallsPresent: true}
}

func toolResp(toolCallID string) Message {
	return Message{Role: "tool", ToolCallID: toolCallID, toolCallIDPresent: true}
}

func plainUser() Message { return Message{Role: "user", Content: TextContent("hi")} }

func launchEvent(payload string) Event {
	return Event{Kind: "launch_began", Payload: json.RawMessage(payload)}
}

func TestValidateRecordStream_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		records []Record
		wantErr string
	}{
		{
			"tool message missing tool_call_id",
			[]Record{Message{Role: "tool"}},
			"records[0]: tool message is missing tool_call_id",
		},
		{
			"tool message empty tool_call_id",
			[]Record{toolResp("")},
			"records[0]: tool message has empty tool_call_id",
		},
		{
			"tool with no preceding record at all",
			[]Record{toolResp("call_1")},
			"records[0]: tool message has no preceding assistant message with tool_calls",
		},
		{
			"tool whose first non-tool record is not an assistant-with-tool_calls",
			[]Record{plainUser(), toolResp("call_1")},
			"records[1]: tool message has no preceding assistant message with tool_calls",
		},
		{
			"tool_call_id matches no id in the preceding assistant",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), toolResp("call_1"), toolResp("call_X")},
			`records[2]: tool_call_id "call_X" does not match any id in the preceding assistant message's tool_calls`,
		},
		// The next three guard the validation ordering: a bad tool record that
		// answers an assistant with a still-pending call must surface its own
		// tool-record error at records[1], not the assistant's "no matching tool
		// response" completeness error at records[0].
		{
			"pending assistant call followed by tool missing tool_call_id",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), Message{Role: "tool"}},
			"records[1]: tool message is missing tool_call_id",
		},
		{
			"pending assistant call followed by tool with empty tool_call_id",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), toolResp("")},
			"records[1]: tool message has empty tool_call_id",
		},
		{
			"pending assistant call followed by mismatched tool response",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), toolResp("call_X")},
			`records[1]: tool_call_id "call_X" does not match any id in the preceding assistant message's tool_calls`,
		},
		{
			"assistant id with no matching tool response",
			[]Record{asstWithCalls(tcEntry("call_1", "function"), tcEntry("call_2", "function")), toolResp("call_1")},
			`records[0]: assistant message has tool_call id "call_2" with no matching tool response`,
		},
		{
			"assistant id matched by more than one tool response",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), toolResp("call_1"), toolResp("call_1")},
			`records[0]: assistant message has tool_call id "call_1" matched by more than one tool response`,
		},
		{
			"tool-call type other than function",
			[]Record{asstWithCalls(tcEntry("call_1", "web"))},
			`records[0]: assistant message has tool_call id "call_1" with type "web" (only "function" is permitted in phase 1)`,
		},
		{
			"tool_call_id on a non-tool role",
			[]Record{Message{Role: "user", ToolCallID: "call_1", toolCallIDPresent: true}},
			"records[0]: tool_call_id is only permitted on role: tool messages",
		},
		{
			"tool_calls on a non-assistant role (present empty list)",
			[]Record{Message{Role: "user", toolCallsPresent: true}},
			"records[0]: tool_calls is only permitted on role: assistant messages",
		},
		{
			"launch_began with an out-of-set source",
			[]Record{launchEvent(`{"source":"bogus"}`)},
			`records[0]: launch_began payload.source missing or not one of "fresh"/"resume"/"fork"`,
		},
		{
			"launch_began with a missing source",
			[]Record{launchEvent(`{}`)},
			`records[0]: launch_began payload.source missing or not one of "fresh"/"resume"/"fork"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordStream(tt.records)
			if err == nil {
				t.Fatalf("ValidateRecordStream() = nil error, want %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("ValidateRecordStream() error =\n  %q\nwant\n  %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateRecordStream_Valid(t *testing.T) {
	valid := []struct {
		name    string
		records []Record
	}{
		{
			"single assistant tool call answered",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), toolResp("call_1")},
		},
		{
			"multiple tool calls answered by adjacent tool messages",
			[]Record{asstWithCalls(tcEntry("call_1", "function"), tcEntry("call_2", "function")), toolResp("call_1"), toolResp("call_2")},
		},
		{
			"non-tool record ends the response group",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), toolResp("call_1"), plainUser()},
		},
		{
			"two separate assistant/tool groups",
			[]Record{asstWithCalls(tcEntry("call_1", "function")), toolResp("call_1"), asstWithCalls(tcEntry("call_2", "function")), toolResp("call_2")},
		},
		{
			"assistant without tool_calls plus unrelated records",
			[]Record{plainUser(), Message{Role: "assistant", Content: TextContent("hi")}, Event{Kind: "model_turn", Payload: json.RawMessage(`{"x":1}`)}},
		},
		{
			"assistant with present empty tool_calls",
			[]Record{Message{Role: "assistant", toolCallsPresent: true}},
		},
		{"valid launch_began fresh", []Record{launchEvent(`{"source":"fresh"}`)}},
		{"valid launch_began resume", []Record{launchEvent(`{"source":"resume"}`)}},
		{"valid launch_began fork", []Record{launchEvent(`{"source":"fork"}`)}},
		{"full canonical session record stream", canonicalSession().Records},
		{"empty record stream", []Record{}},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateRecordStream(tt.records); err != nil {
				t.Fatalf("ValidateRecordStream() = %v, want nil", err)
			}
		})
	}
}

const unknownEventLine = ` { "type": "event",  "kind":"from_newer_build","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a09", ` +
	`"timestamp":"2026-05-25T12:00:04.000Z", "payload": {"b": 2,  "a":"<x>"}, "extra_field": [1, 2] } `

func unknownKindValidator(kind string, payload json.RawMessage) error {
	switch kind {
	case "launch_began":
		return nil
	case "stream_interrupted":
		var p map[string]any
		if err := json.Unmarshal(payload, &p); err != nil || p["content_chars"] == nil {
			return errors.New("stream_interrupted.content_chars: required field is absent")
		}
		return nil
	}
	return fmt.Errorf("%w %q", ErrUnknownEventKind, kind)
}

func eventOf(kind string) Event {
	return Event{Kind: kind, Payload: json.RawMessage(`{}`)}
}

func skippedFlags(records []Record) []bool {
	var out []bool
	for _, rec := range records {
		if ev, ok := rec.(Event); ok {
			out = append(out, ev.skipped)
		}
	}
	return out
}

func TestValidateEventPayloads_SkipsAndMarksUnknownKinds(t *testing.T) {
	records := []Record{eventOf("from_newer_build"), plainUser(), eventOf("launch_began")}
	if err := ValidateEventPayloads(records, unknownKindValidator); err != nil {
		t.Fatalf("ValidateEventPayloads() = %v, want nil", err)
	}
	if got, want := skippedFlags(records), []bool{true, false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("skipped flags = %v, want %v", got, want)
	}
	if err := ValidateEventPayloads(records, unknownKindValidator); err != nil {
		t.Fatalf("second ValidateEventPayloads() = %v, want nil", err)
	}
	if got, want := SkippedEventKinds(records), []SkippedKind{{Kind: "from_newer_build", Count: 1}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after revalidation SkippedEventKinds = %v, want %v", got, want)
	}
}

func TestValidateEventPayloads_SuccessfulRevalidationClearsMarker(t *testing.T) {
	records := []Record{eventOf("from_newer_build")}
	if err := ValidateEventPayloads(records, unknownKindValidator); err != nil {
		t.Fatalf("ValidateEventPayloads() = %v", err)
	}
	if err := ValidateEventPayloads(records, nil); err != nil {
		t.Fatalf("nil validator = %v", err)
	}
	if got := skippedFlags(records); !reflect.DeepEqual(got, []bool{true}) {
		t.Fatalf("after nil validator skipped flags = %v, want [true]", got)
	}
	if err := ValidateEventPayloads(records, func(string, json.RawMessage) error { return nil }); err != nil {
		t.Fatalf("accepting validator = %v", err)
	}
	if got := skippedFlags(records); !reflect.DeepEqual(got, []bool{false}) {
		t.Fatalf("after successful revalidation skipped flags = %v, want [false]", got)
	}
	if got := SkippedEventKinds(records); got != nil {
		t.Fatalf("SkippedEventKinds = %v, want nil", got)
	}
}

func TestValidateEventPayloads_InvalidKnownPayloadKeepsItsIndex(t *testing.T) {
	records := []Record{
		eventOf("from_newer_build"),
		eventOf("also_unknown"),
		Event{Kind: "stream_interrupted", Payload: json.RawMessage(`{"source":"esc"}`)},
	}
	err := ValidateEventPayloads(records, unknownKindValidator)
	want := "records[2].payload: stream_interrupted.content_chars: required field is absent"
	if err == nil || err.Error() != want {
		t.Fatalf("ValidateEventPayloads() = %v, want %q", err, want)
	}
}

func TestSkippedEventKinds_SortedCounts(t *testing.T) {
	records := []Record{eventOf("zeta"), eventOf("launch_began"), eventOf("alpha"), plainUser(), eventOf("zeta")}
	if err := ValidateEventPayloads(records, unknownKindValidator); err != nil {
		t.Fatalf("ValidateEventPayloads() = %v", err)
	}
	want := []SkippedKind{{Kind: "alpha", Count: 1}, {Kind: "zeta", Count: 2}}
	if got := SkippedEventKinds(records); !reflect.DeepEqual(got, want) {
		t.Fatalf("SkippedEventKinds = %v, want %v", got, want)
	}
	if got := SkippedEventKinds([]Record{eventOf("never_validated"), plainUser()}); got != nil {
		t.Fatalf("SkippedEventKinds without marked events = %v, want nil", got)
	}
}

func TestSkippedEventsNotice(t *testing.T) {
	got := SkippedEventsNotice("S1", []SkippedKind{{Kind: "alpha", Count: 1}, {Kind: "bad\nkind", Count: 2}})
	want := `codemeld: session S1: skipped 3 event records of unknown kinds ("alpha"=1, "bad\nkind"=2); ` +
		`a newer codemeld wrote them; inspect with: codemeld sessions show S1`
	if got != want {
		t.Fatalf("notice =\n%q\nwant\n%q", got, want)
	}
	if got := SkippedEventsNotice("S1", nil); got != "" {
		t.Fatalf("empty report notice = %q, want empty", got)
	}
}
