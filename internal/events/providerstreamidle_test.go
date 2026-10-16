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

func TestEmitProviderStreamIdle_AppendBeforeFlush(t *testing.T) {
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
	err := EmitProviderStreamIdle(context.Background(), store, "openai", "gpt-4o",
		30000, 15000, 128, failOnWriteFailure(t))
	if err != nil {
		t.Fatalf("EmitProviderStreamIdle error = %v", err)
	}
	if len(order) != 2 || order[0] != "append" || order[1] != "flush" {
		t.Fatalf("operation order = %v, want [append flush] (durable at detection)", order)
	}
}

func TestEmitProviderStreamIdle_InvalidPayloadSkipsFlush(t *testing.T) {
	var flushed bool
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		flushed = true
		return s.Flush(ctx)
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderStreamIdle(context.Background(), store, "openai", "gpt-4o",
		30000, -1, 0, failOnWriteFailure(t))
	if err == nil {
		t.Fatal("accepted a negative idle_ms")
	}
	if flushed {
		t.Error("flush ran after a rejected append")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("invalid payload appended %d record(s), want 0", got)
	}
}

func TestEmitProviderStreamIdle_FlushFailureInvokesHandler(t *testing.T) {
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
	err := EmitProviderStreamIdle(context.Background(), store, "openai", "gpt-4o",
		30000, 15000, 0, handler)
	if !errors.Is(err, wantErr) {
		t.Fatalf("returned error = %v, want %v", err, wantErr)
	}
	if calls != 1 || gotCat != fserrors.NoSpace || gotReason != sessions.ReasonWriteError || !errors.Is(gotErr, wantErr) {
		t.Fatalf("handler calls=%d cat=%q reason=%q err=%v, want 1 %q write_error %v",
			calls, gotCat, gotReason, gotErr, fserrors.NoSpace, wantErr)
	}
}

func TestEmitProviderStreamIdle_ReasonNoneFlushFailureBypassesHandler(t *testing.T) {
	wantErr := errors.New("ctx cancelled")
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		return "", sessions.ReasonNone, wantErr
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	err := EmitProviderStreamIdle(context.Background(), store, "openai", "gpt-4o",
		30000, 15000, 0, failOnWriteFailure(t))
	if !errors.Is(err, wantErr) {
		t.Fatalf("returned error = %v, want %v", err, wantErr)
	}
}

func TestEmitProviderStreamIdle_RealStoreSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())

	if err := EmitProviderStreamIdle(context.Background(), store, "openrouter", "openai/gpt-4o",
		45000, 20000, 256, failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitProviderStreamIdle error = %v", err)
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
	if !ok || ev.Kind != KindProviderStreamIdle {
		t.Fatalf("record = %T kind %q, want sessions.Event %q", loaded.Records[0], ev.Kind, KindProviderStreamIdle)
	}
	var got ProviderStreamIdle
	if err := json.Unmarshal(ev.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.Provider != "openrouter" || got.ModelID != "openai/gpt-4o" {
		t.Errorf("provider/model = (%q, %q), want (openrouter, openai/gpt-4o)", got.Provider, got.ModelID)
	}
	if got.RoundElapsedMs != 45000 || got.IdleMs != 20000 {
		t.Errorf("(round_elapsed_ms, idle_ms) = (%d, %d), want (45000, 20000)", got.RoundElapsedMs, got.IdleMs)
	}
	if got.PartialChars != 256 {
		t.Errorf("partial_chars = %d, want 256", got.PartialChars)
	}
}
