// Tests for the resume-time updated_at refresh: clean timestamp
// advancement with an on-disk byte assertion, write-failure return behavior with
// the refreshed timestamp retained in memory for the next flush, and the resume
// orchestration follow-up that routes a failed refresh through the
// write-failure protocol. This is an external test package so it can import
// internal/sessionfailures (which imports internal/sessions) without a cycle.
package sessions_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	testMetaID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	testRecID1 = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"
	// tsLayout mirrors the session codec's canonical timestamp form so the on-disk
	// byte assertion can compare against the exact persisted string.
	tsLayout = "2006-01-02T15:04:05.000Z"
)

// staleBaseline is the resumed session's pre-refresh updated_at: far enough in
// the past that the wall-clock refresh is unambiguously newer, so these tests
// need no clock seam (the internal store_test owns the seam-driven cases).
var staleBaseline = time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)

// resumedSession returns a loaded session whose updated_at sits at the stale
// baseline, as if just read from disk on --resume.
func resumedSession() *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            testMetaID,
			Folder:        "/home/u/proj",
			StartedAt:     staleBaseline,
			UpdatedAt:     staleBaseline,
			SchemaVersion: 1,
		},
	}
}

func userMessage(id, text string) sessions.Message {
	return sessions.Message{
		ID:        id,
		Role:      "user",
		Content:   sessions.TextContent(text),
		Timestamp: staleBaseline,
	}
}

// captureNotice is a NoticeRenderer that records the rendered notice text so the
// follow-up routing test can assert the session_write_failed notice surfaced.
type captureNotice struct{ notices []string }

func (c *captureNotice) Notice(text string) { c.notices = append(c.notices, text) }

func TestRefreshUpdatedAt_CleanRefresh_AdvancesAndPersistsBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	sess := resumedSession()
	store := sessions.New(path, sess)
	store.Append(userMessage(testRecID1, "resumed turn"))

	before := time.Now().UTC()
	cat, reason, err := sessions.RefreshUpdatedAt(context.Background(), store)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("RefreshUpdatedAt error: %v (cat=%q reason=%q)", err, cat, reason)
	}
	if cat != "" || reason != sessions.ReasonNone {
		t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone on a clean refresh", cat, reason)
	}

	// In-memory: the refresh advanced updated_at off the stale baseline and into
	// the wall-clock window around the call.
	mem := sess.Metadata.UpdatedAt
	if !mem.After(staleBaseline) {
		t.Fatalf("in-memory updated_at = %s, want after stale baseline %s", mem, staleBaseline)
	}
	if mem.Before(before.Truncate(time.Millisecond)) || mem.After(after) {
		t.Fatalf("in-memory updated_at = %s, want within [%s, %s]", mem, before, after)
	}

	// On disk: read the file back and assert the rewritten updated_at bytes, not
	// just the in-memory object. The codec persists compact JSON at millisecond
	// precision.
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read session file: %v", rerr)
	}
	wantField := `"updated_at":"` + mem.UTC().Truncate(time.Millisecond).Format(tsLayout) + `"`
	if !strings.Contains(string(raw), wantField) {
		t.Fatalf("persisted bytes missing %s\nfile: %s", wantField, raw)
	}
	// Parsing the persisted bytes back confirms the on-disk timestamp round-trips
	// to the refreshed in-memory value and the records survived the rewrite.
	got, perr := sessions.Unmarshal(raw)
	if perr != nil {
		t.Fatalf("parse persisted session: %v", perr)
	}
	if !got.Metadata.UpdatedAt.Equal(mem.UTC().Truncate(time.Millisecond)) {
		t.Fatalf("persisted updated_at = %s, want %s", got.Metadata.UpdatedAt, mem.UTC().Truncate(time.Millisecond))
	}
	if len(got.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(got.Records))
	}
}

func TestRefreshUpdatedAt_FailedRefresh_ReturnsReasonAndRetainsTimestamp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir read-only parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	path := filepath.Join(parent, "session.json")
	sess := resumedSession()
	store := sessions.New(path, sess)
	store.Append(userMessage(testRecID1, "resumed turn"))

	cat, reason, err := sessions.RefreshUpdatedAt(context.Background(), store)
	if err == nil {
		t.Fatalf("RefreshUpdatedAt into read-only parent succeeded, want error")
	}
	// The helper returns Store.Flush's category/reason/error verbatim.
	if reason != sessions.ReasonWriteError {
		t.Fatalf("reason = %q, want %q", reason, sessions.ReasonWriteError)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}

	// the refreshed timestamp is left in the in-memory
	// session even though the write failed, and the records are retained.
	refreshed := sess.Metadata.UpdatedAt
	if !refreshed.After(staleBaseline) {
		t.Fatalf("in-memory updated_at = %s, want refreshed past stale baseline %s after failed flush", refreshed, staleBaseline)
	}
	if got := len(store.Records()); got != 1 {
		t.Fatalf("in-memory records after failed refresh = %d, want 1 (retained)", got)
	}

	// The next successful flush persists that retained (re-)refreshed timestamp.
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatalf("chmod parent writable: %v", err)
	}
	cat, reason, err = sessions.RefreshUpdatedAt(context.Background(), store)
	if err != nil {
		t.Fatalf("second RefreshUpdatedAt error: %v (cat=%q reason=%q)", err, cat, reason)
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read session file: %v", rerr)
	}
	persisted, perr := sessions.Unmarshal(got)
	if perr != nil {
		t.Fatalf("parse persisted session: %v", perr)
	}
	if !persisted.Metadata.UpdatedAt.After(staleBaseline) {
		t.Fatalf("persisted updated_at = %s, want after stale baseline %s", persisted.Metadata.UpdatedAt, staleBaseline)
	}
	if !persisted.Metadata.UpdatedAt.Equal(sess.Metadata.UpdatedAt.UTC().Truncate(time.Millisecond)) {
		t.Fatalf("persisted updated_at = %s, want in-memory refreshed %s", persisted.Metadata.UpdatedAt, sess.Metadata.UpdatedAt.UTC().Truncate(time.Millisecond))
	}
}

// TestRefreshUpdatedAt_FailureRoutedThroughWriteFailureProtocol covers the
// resume orchestration follow-up: a non-ReasonNone refresh result is handed to
// sessionfailures.HandleWriteFailure, which appends session_write_failed and
// renders the notice while the run continues (the in-memory session is intact).
// Production wiring of this sequence belongs to the resume orchestrator;
// internal/sessions never imports internal/sessionfailures.
func TestRefreshUpdatedAt_FailureRoutedThroughWriteFailureProtocol(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir read-only parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	path := filepath.Join(parent, "session.json")
	sess := resumedSession()
	store := sessions.New(path, sess)
	store.Append(userMessage(testRecID1, "resumed turn"))

	cat, reason, err := sessions.RefreshUpdatedAt(context.Background(), store)
	if reason == sessions.ReasonNone {
		t.Fatalf("forced refresh returned ReasonNone, want a write-failure reason (err=%v)", err)
	}

	ui := &captureNotice{}
	if herr := sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, ui); herr != nil {
		t.Fatalf("HandleWriteFailure error: %v", herr)
	}

	// The notice surfaced to the user.
	if len(ui.notices) != 1 || ui.notices[0] == "" {
		t.Fatalf("notices = %v, want exactly one non-empty notice", ui.notices)
	}

	// A session_write_failed event was appended to the retained in-memory stream
	// so the next successful flush carries both the records and the failure event.
	var failedCount int
	for _, rec := range store.Records() {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == events.KindSessionWriteFailed {
			failedCount++
		}
	}
	if failedCount != 1 {
		t.Fatalf("session_write_failed events in stream = %d, want 1", failedCount)
	}

	// The run continues: the refreshed timestamp and the user record are still in
	// memory, untouched by the failure handling.
	if !sess.Metadata.UpdatedAt.After(staleBaseline) {
		t.Fatalf("in-memory updated_at = %s, want refreshed past stale baseline %s", sess.Metadata.UpdatedAt, staleBaseline)
	}
}
