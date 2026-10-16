// Tests for EmitInteractionMode: source/trigger combinations persisted and read
// back through the session codec, invalid-value rejection before any append, and
// the flush-failure handler handoff (mirroring launchbegan_test.go).
package events

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

// TestEmitInteractionMode_PersistsAndReadsBack covers the source/trigger
// combinations end to end against a real store: each appends a single
// interaction_mode event and flushes a parseable file whose reloaded record carries
// the matching mode, source, and trigger.
func TestEmitInteractionMode_PersistsAndReadsBack(t *testing.T) {
	cases := []struct {
		name                  string
		mode, source, trigger string
	}{
		{"launch-default", "build", "default", "launch"},
		{"launch-config", "plan", "config", "launch"},
		{"resume-default", "build", "default", "resume"},
		{"clear-config", "auto_edits", "config", "clear"},
		{"clear-user-command", "plan", "user_command", "clear"},
		{"user-command", "auto_edits", "user_command", "user_command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session.json")
			store := sessions.New(path, newSession())

			if err := EmitInteractionMode(context.Background(), store, tc.mode, tc.source, tc.trigger, failOnWriteFailure(t)); err != nil {
				t.Fatalf("EmitInteractionMode error = %v", err)
			}

			recs := store.Records()
			if len(recs) != 1 || recs[0].(sessions.Event).Kind != KindInteractionMode {
				t.Fatalf("store records = %v, want one interaction_mode", recs)
			}

			// The append must have been flushed: the file round-trips back to an
			// interaction_mode event carrying the requested fields.
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
			got := loaded.Records[0].(sessions.Event)
			if err := ValidatePayload(got.Kind, got.Payload); err != nil {
				t.Fatalf("persisted interaction_mode failed load-time validation: %v", err)
			}
			var p InteractionMode
			if err := json.Unmarshal(got.Payload, &p); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if p.Mode != tc.mode || p.Source != tc.source || p.Trigger != tc.trigger {
				t.Errorf("persisted = %+v, want mode=%q source=%q trigger=%q", p, tc.mode, tc.source, tc.trigger)
			}
		})
	}
}

// TestEmitInteractionMode_InvalidValueRejected verifies an out-of-enum mode, source,
// or trigger is rejected by the append's payload validation before any flush, and
// nothing is appended.
func TestEmitInteractionMode_InvalidValueRejected(t *testing.T) {
	cases := []struct {
		name                  string
		mode, source, trigger string
	}{
		{"bad-mode", "turbo", "default", "launch"},
		{"source-is-trigger", "build", "resume", "launch"},
		{"bad-trigger", "build", "default", "boot"},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var flushed bool
			restoreFlush := flushStore
			flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
				flushed = true
				return s.Flush(ctx)
			}
			t.Cleanup(func() { flushStore = restoreFlush })

			store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
			if err := EmitInteractionMode(context.Background(), store, tc.mode, tc.source, tc.trigger, failOnWriteFailure(t)); err == nil {
				t.Fatal("EmitInteractionMode accepted an invalid value")
			}
			if flushed {
				t.Error("invalid value still triggered a flush")
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("invalid value appended %d record(s), want 0", got)
			}
		})
	}
}

// TestEmitInteractionMode_LeavesPriorRecordsUntouched pins: emitting a mode
// event — the record a launch, a /mode switch, or a /clear produces — is purely
// additive. It appends exactly one interaction_mode record and does not rewrite,
// reorder, or remove any already-emitted record, including a prior permission_matched
// (the audit-trail record of a grant). The mode state and this emitter have no
// coupling to the permission/grant system, so an existing grant cannot be mutated
// either; this exercises the record side of that invariant.
func TestEmitInteractionMode_LeavesPriorRecordsUntouched(t *testing.T) {
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	prior, err := Append(store, PermissionMatched{
		SubjectKind: "tool", Subject: "Read", PathScope: "/home/u/proj",
		GrantKind: "global", GrantPathScope: "*", Outcome: "global_grant", OutcomeSource: "grant",
	})
	if err != nil {
		t.Fatalf("seed prior record: %v", err)
	}
	priorEv := prior.(sessions.Event)
	priorCount := len(store.Records())

	// trigger "user_command" stands in for a /mode switch's emission.
	if err := EmitInteractionMode(context.Background(), store, "plan", "user_command", "user_command", failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitInteractionMode: %v", err)
	}

	after := store.Records()
	if len(after) != priorCount+1 {
		t.Fatalf("record count = %d, want %d (exactly one appended)", len(after), priorCount+1)
	}
	gotPrior := after[0].(sessions.Event)
	if gotPrior.ID != priorEv.ID || gotPrior.Kind != KindPermissionMatched || string(gotPrior.Payload) != string(priorEv.Payload) {
		t.Errorf("prior grant record mutated:\n got: %+v\nwant: %+v", gotPrior, priorEv)
	}
	if after[1].(sessions.Event).Kind != KindInteractionMode {
		t.Errorf("appended record kind = %q, want interaction_mode", after[1].(sessions.Event).Kind)
	}
}

// TestEmitInteractionMode_FlushFailureInvokesHandler verifies an atomic-write flush
// failure hands the exact Flush return tuple to the write-failure handler and
// surfaces the error.
func TestEmitInteractionMode_FlushFailureInvokesHandler(t *testing.T) {
	wantErr := errors.New("flush boom")
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		return fserrors.NoSpace, sessions.ReasonWriteError, wantErr
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	var calls int
	var gotReason sessions.WriteReason
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		calls++
		gotReason = reason
	}
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	if err := EmitInteractionMode(context.Background(), store, "build", "default", "launch", handler); !errors.Is(err, wantErr) {
		t.Fatalf("returned error = %v, want %v", err, wantErr)
	}
	if calls != 1 || gotReason != sessions.ReasonWriteError {
		t.Fatalf("handler calls=%d reason=%q, want 1 / write_error", calls, gotReason)
	}
}

// TestEmitInteractionMode_CanceledContextSkipsHandler verifies a non-write flush
// failure (a canceled context, reported with sessions.ReasonNone) surfaces the
// error but does not invoke the write-failure handler.
func TestEmitInteractionMode_CanceledContextSkipsHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())

	var calls int
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) { calls++ }
	if err := EmitInteractionMode(ctx, store, "build", "default", "launch", handler); err == nil {
		t.Fatal("EmitInteractionMode with canceled context succeeded, want error")
	}
	if calls != 0 {
		t.Fatalf("handler called %d times for a non-write flush failure, want 0", calls)
	}
}
