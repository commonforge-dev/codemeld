package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

const readScope = "/home/u/proj/internal/events/payloads.go"

func TestEmitStructuredReadPair_DurableRoundTrip(t *testing.T) {
	tick := fixedTime
	restore := now
	now = func() time.Time {
		tick = tick.Add(7 * time.Millisecond)
		return tick
	}
	t.Cleanup(func() { now = restore })

	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())
	invocationID := ids.NewV7()

	if err := EmitStructuredReadStart(store, invocationID, "read", readScope, 4, ""); err != nil {
		t.Fatalf("EmitStructuredReadStart() error = %v", err)
	}
	if err := EmitStructuredReadEnd(store, invocationID, "read", "success", 12, ""); err != nil {
		t.Fatalf("EmitStructuredReadEnd() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Store.Flush() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("session file not written (flush did not run): %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if len(loaded.Records) != 2 {
		t.Fatalf("persisted records = %d, want 2", len(loaded.Records))
	}
	startEv, ok := loaded.Records[0].(sessions.Event)
	if !ok || startEv.Kind != KindStructuredReadStart {
		t.Fatalf("record 0 = %T kind %q, want sessions.Event %q", loaded.Records[0], startEv.Kind, KindStructuredReadStart)
	}
	endEv, ok := loaded.Records[1].(sessions.Event)
	if !ok || endEv.Kind != KindStructuredReadEnd {
		t.Fatalf("record 1 = %T kind %q, want sessions.Event %q", loaded.Records[1], endEv.Kind, KindStructuredReadEnd)
	}
	for i, ev := range []sessions.Event{startEv, endEv} {
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload(%q) rejected persisted record %d: %v", ev.Kind, i, err)
		}
	}

	var start StructuredReadStart
	if err := json.Unmarshal(startEv.Payload, &start); err != nil {
		t.Fatalf("unmarshal structured_read_start payload: %v", err)
	}
	var end StructuredReadEnd
	if err := json.Unmarshal(endEv.Payload, &end); err != nil {
		t.Fatalf("unmarshal structured_read_end payload: %v", err)
	}

	if start.InvocationID != invocationID || end.InvocationID != invocationID {
		t.Errorf("invocation_id pair = (%q, %q), want both %q", start.InvocationID, end.InvocationID, invocationID)
	}
	if start.ToolName != "read" || end.ToolName != "read" {
		t.Errorf("tool_name pair = (%q, %q), want both %q", start.ToolName, end.ToolName, "read")
	}
	if start.PathScope != readScope {
		t.Errorf("path_scope = %q, want %q", start.PathScope, readScope)
	}
	if start.ConfiguredConcurrency != 4 {
		t.Errorf("configured_concurrency = %d, want 4", start.ConfiguredConcurrency)
	}
	if end.Outcome != "success" {
		t.Errorf("outcome = %q, want success", end.Outcome)
	}
	if end.DurationMs != 12 {
		t.Errorf("duration_ms = %d, want 12", end.DurationMs)
	}
	if !endEv.Timestamp.After(startEv.Timestamp) {
		t.Errorf("record timestamps = (start %v, end %v), want the end strictly later so the interval is reconstructable", startEv.Timestamp, endEv.Timestamp)
	}
	for _, forbidden := range []string{"configured_concurrency", "stdout", "stderr", "exit_code", "truncated"} {
		if _, present := rawFields(t, endEv.Payload)[forbidden]; present {
			t.Errorf("structured_read_end carries %q: %s", forbidden, endEv.Payload)
		}
	}
	for _, forbidden := range []string{"stdout", "stderr", "exit_code", "truncated", "duration_ms", "outcome"} {
		if _, present := rawFields(t, startEv.Payload)[forbidden]; present {
			t.Errorf("structured_read_start carries %q: %s", forbidden, startEv.Payload)
		}
	}
}

func rawFields(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal payload object: %v", err)
	}
	return fields
}

func TestEmitStructuredReadEnd_EveryOutcome(t *testing.T) {
	for _, outcome := range []string{"success", "tool_failure", "denied", "cancelled", "internal_failure"} {
		t.Run(outcome, func(t *testing.T) {
			sess := newSession()
			store := sessions.New("unused-in-tests", sess)
			id := ids.NewV7()
			if err := EmitStructuredReadEnd(store, id, "grep", outcome, 0, ""); err != nil {
				t.Fatalf("EmitStructuredReadEnd(%q) error = %v", outcome, err)
			}
			evs := reloadAll(t, sess)
			if len(evs) != 1 {
				t.Fatalf("persisted records = %d, want 1", len(evs))
			}
			var got StructuredReadEnd
			if err := json.Unmarshal(evs[0].Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if got.Outcome != outcome {
				t.Errorf("outcome = %q, want %q", got.Outcome, outcome)
			}
		})
	}
}

func TestEmitStructuredReadRefused_DurableRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitStructuredReadRefused(store, "read_image", "not_allowlisted", 6, ""); err != nil {
		t.Fatalf("EmitStructuredReadRefused() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Store.Flush() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("session file not written (flush did not run): %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if len(loaded.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(loaded.Records))
	}
	ev, ok := loaded.Records[0].(sessions.Event)
	if !ok || ev.Kind != KindStructuredReadRefused {
		t.Fatalf("record 0 = %T kind %q, want sessions.Event %q", loaded.Records[0], ev.Kind, KindStructuredReadRefused)
	}
	if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
		t.Fatalf("ValidatePayload(%q) rejected the persisted record: %v", ev.Kind, err)
	}

	var refused StructuredReadRefused
	if err := json.Unmarshal(ev.Payload, &refused); err != nil {
		t.Fatalf("unmarshal structured_read_refused payload: %v", err)
	}
	if refused.ToolName != "read_image" {
		t.Errorf("tool_name = %q, want the exact call name %q even though it is not an allowlisted read", refused.ToolName, "read_image")
	}
	if refused.Reason != "not_allowlisted" {
		t.Errorf("reason = %q, want not_allowlisted", refused.Reason)
	}
	if refused.BatchSize != 6 {
		t.Errorf("batch_size = %d, want 6", refused.BatchSize)
	}
	for _, forbidden := range []string{"invocation_id", "duration_ms", "outcome", "path_scope", "configured_concurrency"} {
		if _, present := rawFields(t, ev.Payload)[forbidden]; present {
			t.Errorf("structured_read_refused carries %q: %s", forbidden, ev.Payload)
		}
	}
}

func TestEmitStructuredReadRefused_EveryReason(t *testing.T) {
	for _, reason := range []string{"not_allowlisted", "args_invalid", "prepare_failed", "scope_unresolved", "out_of_project"} {
		t.Run(reason, func(t *testing.T) {
			sess := newSession()
			store := sessions.New("unused-in-tests", sess)
			if err := EmitStructuredReadRefused(store, "read", reason, 1, ""); err != nil {
				t.Fatalf("EmitStructuredReadRefused(%q) error = %v", reason, err)
			}
			evs := reloadAll(t, sess)
			if len(evs) != 1 {
				t.Fatalf("persisted records = %d, want 1", len(evs))
			}
			var got StructuredReadRefused
			if err := json.Unmarshal(evs[0].Payload, &got); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if got.Reason != reason {
				t.Errorf("reason = %q, want %q", got.Reason, reason)
			}
		})
	}
}

func TestEmitStructuredRead_RejectionsAppendNothing(t *testing.T) {
	good := ids.NewV7()
	starts := map[string]func(*sessions.Store) error{
		"empty tool_name": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "", readScope, 1, "")
		},
		"unknown tool_name": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "read_image", readScope, 1, "")
		},
		"relative path_scope": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "read", "internal/events/payloads.go", 1, "")
		},
		"unnormalized path_scope": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "read", "/home/u/../u/proj/a.go", 1, "")
		},
		"star path_scope": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "read", "*", 1, "")
		},
		"non-v7 invocation_id": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, "not-a-v7", "read", readScope, 1, "")
		},
		"zero concurrency": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "read", readScope, 0, "")
		},
		"negative concurrency": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "read", readScope, -1, "")
		},
		"non-v7 child_invocation_id": func(s *sessions.Store) error {
			return EmitStructuredReadStart(s, good, "read", readScope, 1, "not-a-v7")
		},
	}
	ends := map[string]func(*sessions.Store) error{
		"empty tool_name": func(s *sessions.Store) error {
			return EmitStructuredReadEnd(s, good, "", "success", 1, "")
		},
		"unknown tool_name": func(s *sessions.Store) error {
			return EmitStructuredReadEnd(s, good, "read_image", "success", 1, "")
		},
		"non-v7 invocation_id": func(s *sessions.Store) error {
			return EmitStructuredReadEnd(s, "not-a-v7", "read", "success", 1, "")
		},
		"unknown outcome": func(s *sessions.Store) error {
			return EmitStructuredReadEnd(s, good, "read", "ok", 1, "")
		},
		"empty outcome": func(s *sessions.Store) error {
			return EmitStructuredReadEnd(s, good, "read", "", 1, "")
		},
		"negative duration": func(s *sessions.Store) error {
			return EmitStructuredReadEnd(s, good, "read", "success", -1, "")
		},
		"non-v7 child_invocation_id": func(s *sessions.Store) error {
			return EmitStructuredReadEnd(s, good, "read", "success", 1, "not-a-v7")
		},
	}
	refusals := map[string]func(*sessions.Store) error{
		"empty tool_name": func(s *sessions.Store) error {
			return EmitStructuredReadRefused(s, "", "out_of_project", 1, "")
		},
		"unknown reason": func(s *sessions.Store) error {
			return EmitStructuredReadRefused(s, "read", "ineligible", 1, "")
		},
		"empty reason": func(s *sessions.Store) error {
			return EmitStructuredReadRefused(s, "read", "", 1, "")
		},
		"zero batch_size": func(s *sessions.Store) error {
			return EmitStructuredReadRefused(s, "read", "out_of_project", 0, "")
		},
		"negative batch_size": func(s *sessions.Store) error {
			return EmitStructuredReadRefused(s, "read", "out_of_project", -1, "")
		},
		"non-v7 child_invocation_id": func(s *sessions.Store) error {
			return EmitStructuredReadRefused(s, "read", "out_of_project", 1, "not-a-v7")
		},
	}
	for label, cases := range map[string]map[string]func(*sessions.Store) error{"start": starts, "end": ends, "refused": refusals} {
		for name, emit := range cases {
			t.Run(label+"/"+name, func(t *testing.T) {
				store := newStore()
				if err := emit(store); err == nil {
					t.Errorf("emitter accepted %s", name)
				}
				if got := len(store.Records()); got != 0 {
					t.Errorf("rejected emission appended %d record(s), want 0", got)
				}
			})
		}
	}
}

func TestEmitStructuredReadStart_MinimumConcurrency(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	if err := EmitStructuredReadStart(store, ids.NewV7(), "glob", readScope, 1, ""); err != nil {
		t.Fatalf("EmitStructuredReadStart() rejected configured_concurrency 1: %v", err)
	}
	evs := reloadAll(t, sess)
	if len(evs) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(evs))
	}
	var got StructuredReadStart
	if err := json.Unmarshal(evs[0].Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.ConfiguredConcurrency != 1 {
		t.Errorf("configured_concurrency = %d, want 1", got.ConfiguredConcurrency)
	}
}

func TestEmitStructuredRead_NilStore(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("emitter panicked on a nil store: %v", r)
		}
	}()
	if err := EmitStructuredReadStart(nil, ids.NewV7(), "read", readScope, 1, ""); err == nil {
		t.Error("EmitStructuredReadStart(nil store) did not error")
	}
	if err := EmitStructuredReadEnd(nil, ids.NewV7(), "read", "success", 1, ""); err == nil {
		t.Error("EmitStructuredReadEnd(nil store) did not error")
	}
	if err := EmitStructuredReadRefused(nil, "read", "out_of_project", 1, ""); err == nil {
		t.Error("EmitStructuredReadRefused(nil store) did not error")
	}
}

func TestStructuredRead_ChildAttributionRoundTrip(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	invocation, child := ids.NewV7(), ids.NewV7()

	if err := EmitStructuredReadStart(store, invocation, "read", readScope, 4, child); err != nil {
		t.Fatalf("EmitStructuredReadStart() error = %v", err)
	}
	if err := EmitStructuredReadEnd(store, invocation, "read", "success", 12, child); err != nil {
		t.Fatalf("EmitStructuredReadEnd() error = %v", err)
	}
	if err := EmitStructuredReadRefused(store, "read_image", "not_allowlisted", 2, child); err != nil {
		t.Fatalf("EmitStructuredReadRefused() error = %v", err)
	}
	evs := reloadAll(t, sess)
	if len(evs) != 3 {
		t.Fatalf("persisted records = %d, want 3", len(evs))
	}
	var start StructuredReadStart
	if err := json.Unmarshal(evs[0].Payload, &start); err != nil {
		t.Fatalf("unmarshal structured_read_start: %v", err)
	}
	var end StructuredReadEnd
	if err := json.Unmarshal(evs[1].Payload, &end); err != nil {
		t.Fatalf("unmarshal structured_read_end: %v", err)
	}
	var refused StructuredReadRefused
	if err := json.Unmarshal(evs[2].Payload, &refused); err != nil {
		t.Fatalf("unmarshal structured_read_refused: %v", err)
	}
	if start.ChildInvocationID != child {
		t.Errorf("start child_invocation_id = %q, want %q", start.ChildInvocationID, child)
	}
	if end.ChildInvocationID != child {
		t.Errorf("end child_invocation_id = %q, want %q", end.ChildInvocationID, child)
	}
	if refused.ChildInvocationID != child {
		t.Errorf("refused child_invocation_id = %q, want %q", refused.ChildInvocationID, child)
	}
}

func TestStructuredRead_ParentOmitsTheChildAttribution(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	invocation := ids.NewV7()

	if err := EmitStructuredReadStart(store, invocation, "read", readScope, 1, ""); err != nil {
		t.Fatalf("EmitStructuredReadStart() error = %v", err)
	}
	if err := EmitStructuredReadEnd(store, invocation, "read", "success", 1, ""); err != nil {
		t.Fatalf("EmitStructuredReadEnd() error = %v", err)
	}
	if err := EmitStructuredReadRefused(store, "read_image", "not_allowlisted", 1, ""); err != nil {
		t.Fatalf("EmitStructuredReadRefused() error = %v", err)
	}
	for i, ev := range reloadAll(t, sess) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(ev.Payload, &fields); err != nil {
			t.Fatalf("unmarshal payload %d: %v", i, err)
		}
		if _, present := fields["child_invocation_id"]; present {
			t.Errorf("record %d (%s) carries child_invocation_id: %s", i, ev.Kind, ev.Payload)
		}
	}
}
