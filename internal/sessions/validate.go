// Cross-record tool-call correlation, sibling-field placement, and launch_began
// source validation over a parsed record stream.
package sessions

import (
	"encoding/json"
	"fmt"
)

// launchBeganSources is the closed set of launch_began.source values.
// It is duplicated from internal/events (LaunchBegan / launchSources) on
// purpose: internal/events already imports internal/sessions, so importing it
// back to reach the canonical enum would create an import cycle. The
// record-stream validator owns only this one event-payload check; the broader
// per-kind event validation stays in internal/events.ValidatePayload.
var launchBeganSources = map[string]bool{"fresh": true, "resume": true, "fork": true}

// ValidateRecordStream enforces the load-time rules over an
// already-parsed record slice (as returned by Unmarshal): cross-record
// tool-call correlation between assistant tool_calls entries and the tool
// messages that answer them, the sibling-field placement restrictions
// (tool_call_id only on tool messages, tool_calls only on assistant messages),
// and the launch_began payload.source enum. It is the validator surface later
// load/resume orchestration composes with OpenSession and the per-kind event
// payload validation in internal/events; it does not wire those callers itself.
//
// Errors locate the offending record by its zero-based index in the slice using
// the form records[<N>] and use the exact wording.
//
// Validation runs in two passes so a malformed tool record receives its own
// required error rather than being masked by its assistant's completeness check.
// The first pass validates, in record order, per-record facts: sibling-field
// placement, each tool message's missing/empty/predecessor/mismatch checks, and
// launch_began payloads. Only after every tool record has passed its own checks
// does the second pass validate assistant tool-call type and response-group
// completeness. Within each pass the first violation in record order is returned.
func ValidateRecordStream(records []Record) error {
	for i, rec := range records {
		switch r := rec.(type) {
		case Message:
			if err := validateSiblingFields(i, r); err != nil {
				return err
			}
			if r.Role == "tool" {
				if err := validateToolMessage(i, records); err != nil {
					return err
				}
			}
		case Event:
			if r.Kind == "launch_began" {
				if err := validateLaunchBegan(i, r); err != nil {
					return err
				}
			}
		}
	}
	for i, rec := range records {
		if r, ok := rec.(Message); ok && r.Role == "assistant" && len(r.ToolCalls) > 0 {
			if err := validateAssistantToolCalls(i, records); err != nil {
				return err
			}
		}
	}
	return nil
}

// PayloadValidator validates a single event record's per-kind payload — the
// internal/events.ValidatePayload surface. Production wiring that
// can import internal/events supplies it; internal/sessions takes it as a
// callback because internal/events already imports internal/sessions, so a
// direct import here would be a cycle.
type PayloadValidator func(kind string, payload json.RawMessage) error

// ValidateEventPayloads runs validate over every Event record's per-kind
// payload, returning the first failure located by record index as
// records[<N>].payload: <detail>. It is the load-path composition point for the
// per-kind event validation beside ValidateRecordStream's
// spine checks; message records carry no event payload and are skipped. A nil
// validate is a no-op, so a caller that has not wired a payload validator runs
// the rest of the load path unchanged.
func ValidateEventPayloads(records []Record, validate PayloadValidator) error {
	if validate == nil {
		return nil
	}
	for i, rec := range records {
		ev, ok := rec.(Event)
		if !ok {
			continue
		}
		if err := validate(ev.Kind, ev.Payload); err != nil {
			return fmt.Errorf("records[%d].payload: %w", i, err)
		}
	}
	return nil
}

// validateSiblingFields rejects the correlation sibling fields appearing on a
// role that may not carry them: tool_call_id only on tool messages
// tool_calls only on assistant messages. Presence — not value — is what the
// rule restricts, so an empty present tool_calls on a non-assistant role is
// still a violation.
func validateSiblingFields(i int, m Message) error {
	if m.toolCallIDPresent && m.Role != "tool" {
		return fmt.Errorf("records[%d]: tool_call_id is only permitted on role: tool messages", i)
	}
	if m.toolCallsPresent && m.Role != "assistant" {
		return fmt.Errorf("records[%d]: tool_calls is only permitted on role: assistant messages", i)
	}
	return nil
}

// validateToolMessage checks the per-tool-message rules of: the
// message must carry a non-empty tool_call_id, the first non-tool record found
// walking backward must be an assistant message with a non-empty tool_calls
// list, and the tool_call_id must equal one of that assistant's tool-call ids.
func validateToolMessage(i int, records []Record) error {
	m := records[i].(Message)
	if !m.toolCallIDPresent {
		return fmt.Errorf("records[%d]: tool message is missing tool_call_id", i)
	}
	if m.ToolCallID == "" {
		return fmt.Errorf("records[%d]: tool message has empty tool_call_id", i)
	}
	asst, ok := precedingAssistant(i, records)
	if !ok {
		return fmt.Errorf("records[%d]: tool message has no preceding assistant message with tool_calls", i)
	}
	for _, tc := range asst.ToolCalls {
		if tc.ID == m.ToolCallID {
			return nil
		}
	}
	return fmt.Errorf("records[%d]: tool_call_id %q does not match any id in the preceding assistant message's tool_calls", i, m.ToolCallID)
}

// precedingAssistant walks backward from index i over the contiguous run of
// preceding tool messages and returns the first non-tool record. The bool is
// true only when that record is an assistant message carrying a non-empty
// tool_calls list; any other first non-tool record — a user/system
// message, an assistant without tool_calls, an event, or the start of the
// stream — yields false.
func precedingAssistant(i int, records []Record) (Message, bool) {
	for j := i - 1; j >= 0; j-- {
		msg, isMsg := records[j].(Message)
		if isMsg && msg.Role == "tool" {
			continue
		}
		if isMsg && msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			return msg, true
		}
		return Message{}, false
	}
	return Message{}, false
}

// validateAssistantToolCalls checks the per-assistant-message rules of
// for a message carrying a non-empty tool_calls list: every entry must be type
// "function", and every entry id must be answered by exactly one tool message
// in the contiguous response group (the tool messages immediately following,
// up to the next non-tool record).
func validateAssistantToolCalls(i int, records []Record) error {
	m := records[i].(Message)
	for _, tc := range m.ToolCalls {
		if tc.Type != "function" {
			return fmt.Errorf("records[%d]: assistant message has tool_call id %q with type %q (only \"function\" is permitted in phase 1)", i, tc.ID, tc.Type)
		}
	}
	responses := responseGroupIDs(i, records)
	for _, tc := range m.ToolCalls {
		count := 0
		for _, rid := range responses {
			if rid == tc.ID {
				count++
			}
		}
		switch {
		case count == 0:
			return fmt.Errorf("records[%d]: assistant message has tool_call id %q with no matching tool response", i, tc.ID)
		case count > 1:
			return fmt.Errorf("records[%d]: assistant message has tool_call id %q matched by more than one tool response", i, tc.ID)
		}
	}
	return nil
}

// responseGroupIDs returns the tool_call_id values of the tool messages that
// immediately follow the assistant message at index i, stopping at the first
// record that is not a tool message ('s "before the next non-tool
// record").
func responseGroupIDs(i int, records []Record) []string {
	var ids []string
	for j := i + 1; j < len(records); j++ {
		msg, isMsg := records[j].(Message)
		if !isMsg || msg.Role != "tool" {
			break
		}
		ids = append(ids, msg.ToolCallID)
	}
	return ids
}

// validateLaunchBegan checks that a launch_began event's payload.source is
// present and one of fresh/resume/fork. The spine parser has
// already guaranteed payload is a JSON object; this decodes only the source
// field, treating an absent, null, non-string, or out-of-set value uniformly as
// the single violation.
func validateLaunchBegan(i int, e Event) error {
	var p struct {
		Source *string `json:"source"`
	}
	if err := json.Unmarshal(e.Payload, &p); err != nil || p.Source == nil || !launchBeganSources[*p.Source] {
		return fmt.Errorf("records[%d]: launch_began payload.source missing or not one of \"fresh\"/\"resume\"/\"fork\"", i)
	}
	return nil
}
