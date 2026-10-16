// Tests for the session write-failure protocol: per-turn event append with
// record retention and no synchronous retry, next-boundary re-flush, and the
// clean-shutdown retry/OP_FAIL/exit-1 ordering.
package sessionfailures

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	testMetaID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	testRecID  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"
)

// validSession returns a round-trippable session carrying a single user message,
// so a test can prove the message survives a failed flush and persists alongside
// the failure event on the next flush.
func validSession() *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            testMetaID,
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
		Records: []sessions.Record{
			sessions.Message{
				ID:        testRecID,
				Role:      "user",
				Content:   sessions.TextContent("hello"),
				Timestamp: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			},
		},
	}
}

// fakeNotice captures the one-line notices the handler renders.
type fakeNotice struct{ lines []string }

func (f *fakeNotice) Notice(text string) { f.lines = append(f.lines, text) }

// writeFailedEvents returns the session_write_failed events in a record stream.
func writeFailedEvents(recs []sessions.Record) []sessions.Event {
	var out []sessions.Event
	for _, r := range recs {
		if e, ok := r.(sessions.Event); ok && e.Kind == events.KindSessionWriteFailed {
			out = append(out, e)
		}
	}
	return out
}

func TestHandleWriteFailure_RetainsRecords_EmitsEvent_NoSyncRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "session.json") // missing parent dir
	store := sessions.New(path, validSession())

	// A real flush into the missing parent yields the parent_dir_error reason.
	cat, reason, ferr := store.Flush(context.Background())
	if ferr == nil {
		t.Fatalf("flush into missing parent succeeded, want failure")
	}
	if reason != sessions.ReasonParentDirError {
		t.Fatalf("reason = %q, want %q", reason, sessions.ReasonParentDirError)
	}
	if cat != fserrors.NotFound {
		t.Fatalf("cat = %q, want %q", cat, fserrors.NotFound)
	}

	ui := &fakeNotice{}
	if err := HandleWriteFailure(reason, cat, path, ferr, store, ui); err != nil {
		t.Fatalf("HandleWriteFailure error: %v", err)
	}

	// The original message is retained and the failure event is appended after it.
	recs := store.Records()
	if len(recs) != 2 {
		t.Fatalf("in-memory records = %d, want 2 (message retained + failure event)", len(recs))
	}
	if msg, ok := recs[0].(sessions.Message); !ok || msg.ID != testRecID {
		t.Fatalf("record 0 = %+v, want the retained user message %q", recs[0], testRecID)
	}
	evs := writeFailedEvents(recs)
	if len(evs) != 1 {
		t.Fatalf("session_write_failed events = %d, want 1", len(evs))
	}
	var payload events.SessionWriteFailed
	if err := json.Unmarshal(evs[0].Payload, &payload); err != nil {
		t.Fatalf("decode session_write_failed payload: %v", err)
	}
	if payload.TargetPath != path || payload.Reason != string(sessions.ReasonParentDirError) || payload.ErrorCategory != string(fserrors.NotFound) {
		t.Fatalf("payload = %+v, want target_path=%q reason=parent_dir_error error_category=not_found", payload, path)
	}
	if payload.ErrorDetail == "" {
		t.Fatalf("payload.error_detail is empty, want the underlying OS error text")
	}

	// One notice rendered, naming the path and reason.
	if len(ui.lines) != 1 {
		t.Fatalf("notices rendered = %d, want 1", len(ui.lines))
	}
	if got := ui.lines[0]; !strings.HasPrefix(got, "session log unwritable") || !strings.Contains(got, path) || !strings.Contains(got, "parent_dir_error") {
		t.Fatalf("notice = %q, want the session-write-failed line naming the path and reason", got)
	}

	// No synchronous retry: HandleWriteFailure must not have written the file.
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("session file exists after HandleWriteFailure, want no synchronous write (stat err=%v)", statErr)
	}

	// Next turn-boundary flush, now that the parent exists, persists the retained
	// stream and the failure event together.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create parent dir: %v", err)
	}
	if _, reason2, err := store.Flush(context.Background()); err != nil || reason2 != sessions.ReasonNone {
		t.Fatalf("re-flush after parent created: err=%v reason=%q, want success", err, reason2)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted session: %v", err)
	}
	persisted, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse persisted session: %v", err)
	}
	if len(persisted.Records) != 2 {
		t.Fatalf("persisted records = %d, want 2", len(persisted.Records))
	}
	if len(writeFailedEvents(persisted.Records)) != 1 {
		t.Fatalf("persisted session_write_failed events = %d, want 1", len(writeFailedEvents(persisted.Records)))
	}
}

func TestHandleWriteFailure_ReasonNone_Rejected(t *testing.T) {
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), validSession())
	ui := &fakeNotice{}

	err := HandleWriteFailure(sessions.ReasonNone, fserrors.IOError, "/abs/session.json", errors.New("boom"), store, ui)
	if err == nil {
		t.Fatalf("HandleWriteFailure with ReasonNone succeeded, want error")
	}
	if got := len(writeFailedEvents(store.Records())); got != 0 {
		t.Fatalf("session_write_failed events = %d, want 0 (ReasonNone cannot be encoded)", got)
	}
	if len(ui.lines) != 0 {
		t.Fatalf("notices rendered = %d, want 0 on a rejected reason", len(ui.lines))
	}
}

func TestHandleWriteFailure_AppendRejection_NoNotice(t *testing.T) {
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), validSession())
	before := len(store.Records())
	ui := &fakeNotice{}

	// A nil detail yields an empty error_detail, which the session_write_failed
	// payload validator rejects; the handler must surface that and render nothing.
	err := HandleWriteFailure(sessions.ReasonWriteError, fserrors.IOError, "/abs/session.json", nil, store, ui)
	if err == nil {
		t.Fatalf("HandleWriteFailure with empty error_detail succeeded, want Append rejection")
	}
	if got := len(store.Records()); got != before {
		t.Fatalf("records = %d, want %d (rejected payload must not be appended)", got, before)
	}
	if len(ui.lines) != 0 {
		t.Fatalf("notices rendered = %d, want 0 when the event is rejected", len(ui.lines))
	}
}

func TestCleanShutdownFlush_FirstFailureRetries_ThenSucceeds(t *testing.T) {
	orig := flushStore
	t.Cleanup(func() { flushStore = orig })

	calls := 0
	flushStore = func(_ context.Context, _ *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		calls++
		if calls == 1 {
			return fserrors.IOError, sessions.ReasonWriteError, errors.New("transient")
		}
		return "", sessions.ReasonNone, nil
	}

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), validSession())
	if err := CleanShutdownFlush(context.Background(), store); err != nil {
		t.Fatalf("CleanShutdownFlush after a single transient failure: %v, want nil", err)
	}
	if calls != 2 {
		t.Fatalf("flush attempts = %d, want 2 (one failure then one success)", calls)
	}
}

func TestCleanShutdownFlush_SecondFailure_OpFail_Exit1_NoEvent(t *testing.T) {
	orig := flushStore
	t.Cleanup(func() { flushStore = orig })

	calls := 0
	flushStore = func(_ context.Context, _ *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		calls++
		return fserrors.IOError, sessions.ReasonWriteError, errors.New("disk\tgone")
	}

	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, validSession())

	// Capture stderr to assert the OP_FAIL line on the second failure.
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	flushErr := CleanShutdownFlush(context.Background(), store)

	_ = w.Close()
	os.Stderr = oldStderr
	captured, _ := io.ReadAll(r)

	if flushErr == nil {
		t.Fatalf("CleanShutdownFlush after two failures returned nil, want a non-nil error for exit-1 mapping")
	}
	if calls != 2 {
		t.Fatalf("flush attempts = %d, want exactly 2 (attempt + one retry)", calls)
	}

	out := string(captured)
	wantOpFail := fserrors.FormatOpFail("session-write-on-exit", path, fserrors.IOError)
	if !strings.Contains(out, wantOpFail) {
		t.Fatalf("stderr = %q, want OP_FAIL line %q", out, wantOpFail)
	}
	// The tab in the detail is collapsed to a space by WriteToStderr.
	if !strings.Contains(out, "detail: disk gone") {
		t.Fatalf("stderr = %q, want collapsed detail %q", out, "detail: disk gone")
	}

	// the clean-shutdown second-failure path emits no session_write_failed
	// event, since there is no later flush to carry it.
	if got := len(writeFailedEvents(store.Records())); got != 0 {
		t.Fatalf("session_write_failed events = %d, want 0 on the clean-shutdown failure path", got)
	}
}
