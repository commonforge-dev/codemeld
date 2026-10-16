// Tests for EmitProviderRequestFailed: append-before-flush ordering, invalid
// payload skipping the flush, write-failure handler routing (only real
// WriteReasons), ReasonNone bypass, and a real-store success path that reloads
// the flushed session and asserts the provider_request_failed event persisted.
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

func TestEmitProviderRequestFailed_AppendBeforeFlush(t *testing.T) {
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
	err := EmitProviderRequestFailed(context.Background(), store, "openai", "gpt-4o",
		"dial", "dns_error", "no such host", nil, 0, failOnWriteFailure(t))
	if err != nil {
		t.Fatalf("EmitProviderRequestFailed error = %v", err)
	}
	if len(order) != 2 || order[0] != "append" || order[1] != "flush" {
		t.Fatalf("operation order = %v, want [append flush]", order)
	}
}

// TestEmitProviderRequestFailed_InvalidPayloadSkipsFlush feeds a phase outside
// the closed set so the real Append rejects it; the flush must never run
// and the store must gain no record.
func TestEmitProviderRequestFailed_InvalidPayloadSkipsFlush(t *testing.T) {
	var flushed bool
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		flushed = true
		return s.Flush(ctx)
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderRequestFailed(context.Background(), store, "openai", "gpt-4o",
		"bogus_phase", "dns_error", "detail", nil, 0, failOnWriteFailure(t))
	if err == nil {
		t.Fatal("EmitProviderRequestFailed accepted an invalid phase")
	}
	if flushed {
		t.Error("flush ran after a rejected append")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("invalid payload appended %d record(s), want 0", got)
	}
}

// TestEmitProviderRequestFailed_FieldConstraintRejected confirms a field-level
// schema rule (partial_response_chars set on a non-stream_drop phase) is
// rejected at append, before any flush — the validation seam provider failure handling relies on.
func TestEmitProviderRequestFailed_FieldConstraintRejected(t *testing.T) {
	var flushed bool
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		flushed = true
		return s.Flush(ctx)
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderRequestFailed(context.Background(), store, "openai", "gpt-4o",
		"decode", "decode_error", "bad json", nil, 17, failOnWriteFailure(t))
	if err == nil {
		t.Fatal("accepted partial_response_chars on a non-stream_drop phase")
	}
	if flushed {
		t.Error("flush ran after a rejected append")
	}
}

func TestEmitProviderRequestFailed_FlushFailureInvokesHandler(t *testing.T) {
	wantErr := errors.New("flush boom")
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		return fserrors.NoSpace, sessions.ReasonWriteError, wantErr
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	var (
		calls     int
		gotCat    fserrors.Category
		gotReason sessions.WriteReason
		gotErr    error
	)
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		calls++
		gotCat, gotReason, gotErr = cat, reason, err
	}

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderRequestFailed(context.Background(), store, "openrouter", "anthropic/claude",
		"stream_drop", "stream_eof", "unexpected EOF", nil, 12, handler)
	if !errors.Is(err, wantErr) {
		t.Fatalf("returned error = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("handler called %d times, want 1", calls)
	}
	if gotCat != fserrors.NoSpace || gotReason != sessions.ReasonWriteError || !errors.Is(gotErr, wantErr) {
		t.Errorf("handler got (cat=%q reason=%q err=%v), want (%q %q %v)",
			gotCat, gotReason, gotErr, fserrors.NoSpace, sessions.ReasonWriteError, wantErr)
	}
}

// TestEmitProviderRequestFailed_CanceledContextSkipsHandler verifies a
// ReasonNone flush failure (an already-canceled context, no write attempted)
// surfaces the error but does NOT invoke the write-failure handler.
func TestEmitProviderRequestFailed_CanceledContextSkipsHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	var calls int
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) { calls++ }

	err := EmitProviderRequestFailed(ctx, store, "openai", "gpt-4o",
		"tls", "tls_cert_expired", "certificate expired", nil, 0, handler)
	if err == nil {
		t.Fatal("canceled context succeeded, want error")
	}
	if calls != 0 {
		t.Fatalf("handler called %d times for a ReasonNone flush failure, want 0", calls)
	}
}

func TestEmitProviderRequestFailed_NilHandlerOnFlushFailure(t *testing.T) {
	wantErr := errors.New("flush boom")
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		return fserrors.IOError, sessions.ReasonRenameError, wantErr
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New("unused", newSession())
	if err := EmitProviderRequestFailed(context.Background(), store, "openai", "gpt-4o",
		"empty_response", "no_choices", "no choices", nil, 0, nil); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

// TestEmitProviderRequestFailed_RealStoreSuccess flushes a provider_request_failed
// event to an actual session file and reloads it through the session
// reader/decoder, asserting the persisted record carries the event with its
// fields intact — so durability cannot be satisfied by an in-memory-only mock.
func TestEmitProviderRequestFailed_RealStoreSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	status := int64(503)
	err := EmitProviderRequestFailed(context.Background(), store, "openrouter", "openai/gpt-4o",
		"http", "http_no_body", "empty body", &status, 0, failOnWriteFailure(t))
	if err != nil {
		t.Fatalf("EmitProviderRequestFailed error = %v", err)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("session file not written (flush did not run): %v", readErr)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if len(loaded.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(loaded.Records))
	}
	ev, ok := loaded.Records[0].(sessions.Event)
	if !ok {
		t.Fatalf("record 0 type = %T, want sessions.Event", loaded.Records[0])
	}
	if ev.Kind != KindProviderRequestFailed {
		t.Fatalf("kind = %q, want %q", ev.Kind, KindProviderRequestFailed)
	}
	var got ProviderRequestFailed
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.Provider != "openrouter" || got.ModelID != "openai/gpt-4o" {
		t.Errorf("provider/model = (%q, %q), want (openrouter, openai/gpt-4o)", got.Provider, got.ModelID)
	}
	if got.Phase != "http" || got.Reason != "http_no_body" {
		t.Errorf("(phase, reason) = (%q, %q), want (http, http_no_body)", got.Phase, got.Reason)
	}
	if got.HTTPStatus == nil || *got.HTTPStatus != 503 {
		t.Errorf("http_status = %v, want 503", got.HTTPStatus)
	}
	if got.ErrorDetail != "empty body" {
		t.Errorf("error_detail = %q, want %q", got.ErrorDetail, "empty body")
	}
}

// TestEmitProviderRequestFailed_RealStoreStreamDrop persists a stream_drop event
// and confirms partial_response_chars round-trips through the real codec.
func TestEmitProviderRequestFailed_RealStoreStreamDrop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitProviderRequestFailed(context.Background(), store, "openai", "gpt-4o",
		"stream_drop", "stream_read_error", "connection reset", nil, 256, failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitProviderRequestFailed error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}
	var got ProviderRequestFailed
	if err := json.Unmarshal(loaded.Records[0].(sessions.Event).Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.PartialResponseChars != 256 {
		t.Errorf("partial_response_chars = %d, want 256", got.PartialResponseChars)
	}
	if got.HTTPStatus != nil {
		t.Errorf("http_status = %v, want nil for stream_drop", *got.HTTPStatus)
	}
}
