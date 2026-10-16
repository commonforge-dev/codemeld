// Tests for EmitProviderRequestRetrySkipped: append-before-flush ordering,
// invalid-payload skipping the flush, write-failure handler routing, and a real-store
// success path that reloads the flushed session and asserts the
// provider_request_retry_skipped event persisted with its fields intact. Also covers
// the payload validator's closed skip-reason set, provider (phase, reason) taxonomy,
// attempt >= 1, and stream_drop-only partial chars.
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

func TestEmitProviderRequestRetrySkipped_AppendBeforeFlush(t *testing.T) {
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
	err := EmitProviderRequestRetrySkipped(context.Background(), store, "openai", "gpt-4o",
		"stream_drop", "stream_eof", "max_attempts_reached", 3, 12, failOnWriteFailure(t))
	if err != nil {
		t.Fatalf("EmitProviderRequestRetrySkipped error = %v", err)
	}
	if len(order) != 2 || order[0] != "append" || order[1] != "flush" {
		t.Fatalf("operation order = %v, want [append flush] (durable before terminal failure)", order)
	}
}

// An invalid payload (partial_chars_discarded on a non-stream_drop phase) is rejected
// at append, before any flush, so a malformed skip never reaches disk.
func TestEmitProviderRequestRetrySkipped_InvalidPayloadSkipsFlush(t *testing.T) {
	var flushed bool
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		flushed = true
		return s.Flush(ctx)
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderRequestRetrySkipped(context.Background(), store, "openai", "gpt-4o",
		"dial", "dns_error", "retry_disabled", 1, 7, failOnWriteFailure(t))
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

func TestEmitProviderRequestRetrySkipped_FlushFailureInvokesHandler(t *testing.T) {
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
	err := EmitProviderRequestRetrySkipped(context.Background(), store, "openai", "gpt-4o",
		"http", "http_error", "budget_exhausted", 2, 0, handler)
	if !errors.Is(err, wantErr) {
		t.Fatalf("returned error = %v, want %v", err, wantErr)
	}
	if calls != 1 || gotReason != sessions.ReasonWriteError {
		t.Fatalf("handler calls=%d reason=%q, want 1 write_error", calls, gotReason)
	}
}

// The validator rejects an unknown skip reason, a (phase, reason) tuple outside the
// provider taxonomy, and attempt < 1 — all before the store is touched.
func TestProviderRequestRetrySkipped_ValidatorRejections(t *testing.T) {
	base := ProviderRequestRetrySkipped{
		Provider: "openai", ModelID: "gpt-4o", Attempt: 1,
		Phase: "dial", Reason: "dns_error", SkipReason: "retry_disabled",
	}
	cases := map[string]func(*ProviderRequestRetrySkipped){
		"unknown skip_reason": func(p *ProviderRequestRetrySkipped) { p.SkipReason = "gave_up" },
		"phase not in taxonomy": func(p *ProviderRequestRetrySkipped) {
			p.Phase, p.Reason = "auth", "forbidden"
		},
		"reason invalid for phase": func(p *ProviderRequestRetrySkipped) { p.Reason = "tls_handshake" },
		"attempt below one":        func(p *ProviderRequestRetrySkipped) { p.Attempt = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if err := p.validate(); err == nil {
				t.Fatalf("validate accepted %s, want rejection", name)
			}
		})
	}
	if err := base.validate(); err != nil {
		t.Fatalf("base payload should validate, got %v", err)
	}
}

// A real flush to a session file, reloaded through the codec, proves the
// provider_request_retry_skipped record persisted with its fields intact.
func TestEmitProviderRequestRetrySkipped_RealStoreSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitProviderRequestRetrySkipped(context.Background(), store, "openrouter", "openai/gpt-4o",
		"stream_drop", "stream_read_error", "budget_exhausted", 3, 256, failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitProviderRequestRetrySkipped error = %v", err)
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
	if !ok || ev.Kind != KindProviderRequestRetrySkipped {
		t.Fatalf("record = %T kind %q, want sessions.Event %q", loaded.Records[0], ev.Kind, KindProviderRequestRetrySkipped)
	}
	// Exercise the load-time decoder registration: fails if the
	// KindProviderRequestRetrySkipped case is removed or miswired in unmarshalPayload.
	if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
		t.Fatalf("ValidatePayload(%q): %v", ev.Kind, err)
	}
	var got ProviderRequestRetrySkipped
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.Provider != "openrouter" || got.ModelID != "openai/gpt-4o" {
		t.Errorf("provider/model = (%q, %q), want (openrouter, openai/gpt-4o)", got.Provider, got.ModelID)
	}
	if got.Attempt != 3 || got.SkipReason != "budget_exhausted" {
		t.Errorf("(attempt, skip_reason) = (%d, %q), want (3, budget_exhausted)", got.Attempt, got.SkipReason)
	}
	if got.Phase != "stream_drop" || got.Reason != "stream_read_error" {
		t.Errorf("(phase, reason) = (%q, %q), want (stream_drop, stream_read_error)", got.Phase, got.Reason)
	}
	if got.PartialCharsDiscarded != 256 {
		t.Errorf("partial_chars_discarded = %d, want 256", got.PartialCharsDiscarded)
	}
}
