// Tests for EmitLaunchBegan: every source value, invalid-source rejection,
// append-before-flush ordering, and flush-failure handler handoff.
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

// TestEmitLaunchBegan_AllSources covers the three source values end to
// end against a real store: each appends a single launch_began event and flushes
// a parseable file whose reloaded record carries the matching source.
func TestEmitLaunchBegan_AllSources(t *testing.T) {
	for _, source := range []string{"fresh", "resume", "fork"} {
		t.Run(source, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "session.json")
			store := sessions.New(path, newSession())

			if err := EmitLaunchBegan(context.Background(), store, source, failOnWriteFailure(t)); err != nil {
				t.Fatalf("EmitLaunchBegan(%q) error = %v", source, err)
			}

			recs := store.Records()
			if len(recs) != 1 {
				t.Fatalf("store has %d records, want 1", len(recs))
			}
			ev, ok := recs[0].(sessions.Event)
			if !ok {
				t.Fatalf("record 0 type = %T, want sessions.Event", recs[0])
			}
			if ev.Kind != KindLaunchBegan {
				t.Errorf("kind = %q, want %q", ev.Kind, KindLaunchBegan)
			}

			// The append must have been flushed: the file exists and round-trips
			// back to a launch_began event with the requested source.
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
			var lb LaunchBegan
			if err := json.Unmarshal(got.Payload, &lb); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if lb.Source != source {
				t.Errorf("persisted source = %q, want %q", lb.Source, source)
			}
		})
	}
}

// TestEmitLaunchBegan_InvalidSourceRejected verifies a source outside the closed
// set is rejected before any append or flush is attempted.
func TestEmitLaunchBegan_InvalidSourceRejected(t *testing.T) {
	var appended, flushed bool
	restoreAppend, restoreFlush := appendEvent, flushStore
	appendEvent = func(s *sessions.Store, p EventPayload) (sessions.Record, error) {
		appended = true
		return Append(s, p)
	}
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		flushed = true
		return s.Flush(ctx)
	}
	t.Cleanup(func() { appendEvent, flushStore = restoreAppend, restoreFlush })

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())
	if err := EmitLaunchBegan(context.Background(), store, "boot", failOnWriteFailure(t)); err == nil {
		t.Fatal("EmitLaunchBegan accepted an invalid source")
	}
	if appended {
		t.Error("invalid source still triggered an append")
	}
	if flushed {
		t.Error("invalid source still triggered a flush")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("invalid source appended %d record(s), want 0", got)
	}
}

// TestEmitLaunchBegan_AppendBeforeFlush asserts the helper appends the event
// before flushing, so a flush can never persist a session missing the event it
// is meant to durably record.
func TestEmitLaunchBegan_AppendBeforeFlush(t *testing.T) {
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
	if err := EmitLaunchBegan(context.Background(), store, "fresh", failOnWriteFailure(t)); err != nil {
		t.Fatalf("EmitLaunchBegan error = %v", err)
	}
	if len(order) != 2 || order[0] != "append" || order[1] != "flush" {
		t.Fatalf("operation order = %v, want [append flush]", order)
	}
}

// TestEmitLaunchBegan_AppendFailureSkipsFlush verifies an append failure short-
// circuits before the flush and surfaces the append error.
func TestEmitLaunchBegan_AppendFailureSkipsFlush(t *testing.T) {
	wantErr := errors.New("append boom")
	var flushed bool
	restoreAppend, restoreFlush := appendEvent, flushStore
	appendEvent = func(s *sessions.Store, p EventPayload) (sessions.Record, error) {
		return nil, wantErr
	}
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		flushed = true
		return "", sessions.ReasonNone, nil
	}
	t.Cleanup(func() { appendEvent, flushStore = restoreAppend, restoreFlush })

	store := sessions.New("unused", newSession())
	if err := EmitLaunchBegan(context.Background(), store, "fresh", failOnWriteFailure(t)); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if flushed {
		t.Error("flush ran after an append failure")
	}
}

// TestEmitLaunchBegan_FlushFailureInvokesHandler verifies a flush failure hands
// the exact Flush return tuple to the write-failure handler and surfaces the
// error, using the seam to make the failure deterministic.
func TestEmitLaunchBegan_FlushFailureInvokesHandler(t *testing.T) {
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
	err := EmitLaunchBegan(context.Background(), store, "resume", handler)
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

// TestEmitLaunchBegan_FlushFailureNilHandler verifies a flush failure with a nil
// handler returns the error without panicking — the handler is optional.
func TestEmitLaunchBegan_FlushFailureNilHandler(t *testing.T) {
	wantErr := errors.New("flush boom")
	restoreFlush := flushStore
	flushStore = func(ctx context.Context, s *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		return fserrors.IOError, sessions.ReasonRenameError, wantErr
	}
	t.Cleanup(func() { flushStore = restoreFlush })

	store := sessions.New("unused", newSession())
	if err := EmitLaunchBegan(context.Background(), store, "fork", nil); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

// TestEmitLaunchBegan_FlushFailureRealStore exercises the real Store.Flush
// failure path (no seam): flushing into a read-only parent invokes the handler
// with the mapped write reason and category from the actual filesystem error.
func TestEmitLaunchBegan_FlushFailureRealStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir read-only parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	store := sessions.New(filepath.Join(parent, "session.json"), newSession())

	var calls int
	var gotReason sessions.WriteReason
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		calls++
		gotReason = reason
	}
	if err := EmitLaunchBegan(context.Background(), store, "fresh", handler); err == nil {
		t.Fatal("EmitLaunchBegan into read-only parent succeeded, want error")
	}
	if calls != 1 {
		t.Fatalf("handler called %d times, want 1", calls)
	}
	if gotReason != sessions.ReasonWriteError {
		t.Errorf("reason = %q, want %q", gotReason, sessions.ReasonWriteError)
	}
}

// TestEmitLaunchBegan_CanceledContextSkipsHandler verifies a non-write flush
// failure — an already-canceled context, which Store.Flush reports with
// sessions.ReasonNone and no write attempt — surfaces the error but does NOT
// invoke the write-failure handler, since ReasonNone cannot be encoded in
// the session_write_failed contract.
func TestEmitLaunchBegan_CanceledContextSkipsHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := sessions.New(filepath.Join(t.TempDir(), "session.json"), newSession())

	var calls int
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		calls++
	}
	if err := EmitLaunchBegan(ctx, store, "fresh", handler); err == nil {
		t.Fatal("EmitLaunchBegan with canceled context succeeded, want error")
	}
	if calls != 0 {
		t.Fatalf("handler called %d times for a non-write flush failure, want 0", calls)
	}
}

// failOnWriteFailure returns a handler that fails the test if a flush failure is
// reported, for the success-path cases where none is expected.
func failOnWriteFailure(t *testing.T) WriteFailureHandler {
	t.Helper()
	return func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		t.Errorf("unexpected write failure: cat=%q reason=%q err=%v", cat, reason, err)
	}
}
