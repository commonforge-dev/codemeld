// External-package tests for the session_prune_summary handoff: a PruneResult
// converts field-for-field into a valid events.SessionPruneSummary that the
// caller can append to an active session, and the no-active-session case drops
// the deferred result silently. This lives in the external test package so it can
// import internal/events (which imports internal/sessions) without a cycle.
package sessions_test

import (
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

// sampleResult is a PruneResult carrying one accumulated failure, as a foreground
// or background prune would hand to the caller.
func sampleResult() sessions.PruneResult {
	return sessions.PruneResult{
		FilesScanned: 5,
		FilesDeleted: 2,
		FilesFailed:  1,
		Failures: []sessions.PruneFailure{{
			Path:   "/home/u/.codemeld/sessions/abc-proj/0190a1b2.json",
			Reason: fserrors.IOError,
			Kind:   sessions.FailureFileDelete,
		}},
		ElapsedMs: 7,
	}
}

// toSummary mirrors the conversion the summary callback / resume sub-sequence
// performs: a verbatim field copy from the internal PruneResult into the event
// payload, since internal/sessions cannot import internal/events.
func toSummary(r sessions.PruneResult) events.SessionPruneSummary {
	p := events.SessionPruneSummary{
		FilesScanned: r.FilesScanned,
		FilesDeleted: r.FilesDeleted,
		FilesFailed:  r.FilesFailed,
		ElapsedMs:    r.ElapsedMs,
	}
	for _, f := range r.Failures {
		p.Failures = append(p.Failures, events.PruneFailure{
			Path:   f.Path,
			Reason: string(f.Reason),
			Kind:   string(f.Kind),
		})
	}
	return p
}

func TestPruneResult_AppendableToActiveSession(t *testing.T) {
	session := &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC),
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
	}
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), session)

	rec, err := events.Append(store, toSummary(sampleResult()))
	if err != nil {
		t.Fatalf("events.Append rejected the converted summary: %v", err)
	}
	ev, ok := rec.(sessions.Event)
	if !ok {
		t.Fatalf("appended record is %T, want sessions.Event", rec)
	}
	if ev.Kind != events.KindSessionPruneSummary {
		t.Fatalf("event kind = %q, want %q", ev.Kind, events.KindSessionPruneSummary)
	}

	var summaries int
	for _, r := range store.Records() {
		if e, ok := r.(sessions.Event); ok && e.Kind == events.KindSessionPruneSummary {
			summaries++
		}
	}
	if summaries != 1 {
		t.Fatalf("session_prune_summary events in stream = %d, want 1", summaries)
	}
}

// TestPruneResult_DroppedWhenNoActiveSession models the callback contract for the
// shutdown / pre-`--resume`-no-selection case: with no active session the caller
// drops the deferred result without appending anything and without a stderr
// surface.
func TestPruneResult_DroppedWhenNoActiveSession(t *testing.T) {
	appended := dropOrAppend(nil, sampleResult())
	if appended {
		t.Fatalf("result was appended despite no active session; want dropped")
	}
}

// dropOrAppend is the caller-side rule the summary callback applies: append the
// converted event when a session is active, otherwise drop it silently.
func dropOrAppend(store *sessions.Store, r sessions.PruneResult) (appended bool) {
	if store == nil {
		return false
	}
	_, err := events.Append(store, toSummary(r))
	return err == nil
}
