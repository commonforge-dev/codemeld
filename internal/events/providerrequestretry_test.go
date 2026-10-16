// Tests for EmitProviderRequestRetry: append-before-flush ordering,
// invalid-payload skipping the flush, write-failure handler routing, and a
// real-store success path that reloads the flushed session and asserts the
// provider_request_retry event persisted with its fields intact.
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

func TestEmitProviderRequestRetry_AppendBeforeFlush(t *testing.T) {
	var order []string
	restoreAppend, restoreFlush := appendEvent, flushStore
	appendEvent = func(s *sessions.Store, p EventPayload) (sessions.Record, error) {
		order = append(order, "append")
		return sessions.Event{}, nil
	}
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		order = append(order, "flush")
		return "", sessions.ReasonNone, nil
	}
	t.Cleanup(func() { appendEvent, flushStore = restoreAppend, restoreFlush })

	store := sessions.New("unused", newSession())
	err := EmitProviderRequestRetry(context.Background(), store, "openai", "gpt-4o",
		"stream_drop", "stream_eof", 1, 500, 12, failOnWriteFailure(t))
	if err != nil {
		t.Fatalf("EmitProviderRequestRetry error = %v", err)
	}
	if len(order) != 2 || order[0] != "append" || order[1] != "flush" {
		t.Fatalf("operation order = %v, want [append flush] (durable before the backoff wait)", order)
	}
}

// An invalid payload (partial_chars_discarded on a non-stream_drop phase) is
// rejected at append, before any flush, so a malformed retry never reaches disk.
func TestEmitProviderRequestRetry_InvalidPayloadSkipsFlush(t *testing.T) {
	var flushed bool
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		flushed = true
		return s.Flush(ctx)
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderRequestRetry(context.Background(), store, "openai", "gpt-4o",
		"dial", "dns_error", 1, 500, 7, failOnWriteFailure(t))
	if err == nil {
		t.Fatal("accepted partial_chars_discarded on a non-stream_drop phase")
	}
	if flushed {
		t.Error("flush ran after a rejected append")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("invalid payload appended %d record(s), want 0", got)
	}
}

// attempt < 1 is rejected: the failed-attempt number is always 1-based.
func TestEmitProviderRequestRetry_AttemptBelowOneRejected(t *testing.T) {
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	if err := EmitProviderRequestRetry(context.Background(), store, "openai", "gpt-4o",
		"dial", "dns_error", 0, 500, 0, failOnWriteFailure(t)); err == nil {
		t.Fatal("accepted attempt 0, want rejection")
	}
}

func TestEmitProviderRequestRetry_FlushFailureInvokesHandler(t *testing.T) {
	wantErr := errors.New("flush boom")
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		return fserrors.NoSpace, sessions.ReasonWriteError, wantErr
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	var (
		calls     int
		gotReason sessions.WriteReason
	)
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		calls++
		gotReason = reason
	}
	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderRequestRetry(context.Background(), store, "openai", "gpt-4o",
		"http", "http_error", 2, 1000, 0, handler)
	if !errors.Is(err, wantErr) {
		t.Fatalf("returned error = %v, want %v", err, wantErr)
	}
	if calls != 1 || gotReason != sessions.ReasonWriteError {
		t.Fatalf("handler calls=%d reason=%q, want 1 write_error", calls, gotReason)
	}
}

// A real flush to a session file, reloaded through the codec, proves the
// provider_request_retry record persisted with its fields intact.
func TestEmitProviderRequestRetry_RealStoreSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitProviderRequestRetry(context.Background(), store, "openrouter", "openai/gpt-4o",
		"stream_drop", "stream_read_error", 3, 2000, 256, failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitProviderRequestRetry error = %v", err)
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
	if !ok || ev.Kind != KindProviderRequestRetry {
		t.Fatalf("record = %T kind %q, want sessions.Event %q", loaded.Records[0], ev.Kind, KindProviderRequestRetry)
	}
	var got ProviderRequestRetry
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.Provider != "openrouter" || got.ModelID != "openai/gpt-4o" {
		t.Errorf("provider/model = (%q, %q), want (openrouter, openai/gpt-4o)", got.Provider, got.ModelID)
	}
	if got.Attempt != 3 || got.DelayMs != 2000 {
		t.Errorf("(attempt, delay_ms) = (%d, %d), want (3, 2000)", got.Attempt, got.DelayMs)
	}
	if got.Phase != "stream_drop" || got.Reason != "stream_read_error" {
		t.Errorf("(phase, reason) = (%q, %q), want (stream_drop, stream_read_error)", got.Phase, got.Reason)
	}
	if got.PartialCharsDiscarded != 256 {
		t.Errorf("partial_chars_discarded = %d, want 256", got.PartialCharsDiscarded)
	}
}
