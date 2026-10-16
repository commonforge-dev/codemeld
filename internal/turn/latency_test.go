// Tests for the timing events: the per-turn end-to-end turn_latency emitted
// only on a completed final answer, and the per-round provider_round_trip emitted
// on every terminal provider outcome (success and failure), with durability read
// back from the session store.
package turn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

// storeFlush makes the turn's flush hook write the real store to disk so a
// test can read the persisted records back (not just the in-memory snapshot).
func storeFlush(store *sessions.Store) FlushHook {
	return func() error {
		_, _, err := store.Flush(context.Background())
		return err
	}
}

// eventsOf decodes every Event record of the given kind into T, failing the test on a
// payload that does not unmarshal. label names the kind in that failure message.
func eventsOf[T any](t *testing.T, recs []sessions.Record, kind, label string) []T {
	t.Helper()
	var out []T
	for _, r := range recs {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != kind {
			continue
		}
		var p T
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode %s: %v", label, err)
		}
		out = append(out, p)
	}
	return out
}

// turnLatencyEvents keeps its name because latency and tool-loop tests call it directly.
func turnLatencyEvents(t *testing.T, recs []sessions.Record) []events.TurnLatency {
	t.Helper()
	return eventsOf[events.TurnLatency](t, recs, events.KindTurnLatency, "turn_latency")
}

// providerRoundTripEvents keeps its name because latency, failure, and tool-loop tests
// call it directly.
func providerRoundTripEvents(t *testing.T, recs []sessions.Record) []events.ProviderRoundTrip {
	t.Helper()
	return eventsOf[events.ProviderRoundTrip](t, recs, events.KindProviderRoundTrip, "provider_round_trip")
}

// A completed turn persists exactly one provider_round_trip (timing the model
// call) and one turn_latency (the end-to-end submit→answer time), both read back
// from disk with the durations the seam-driven clock produces: the round runs from
// the just-before-call instant to the terminal answer, and turn_latency from the
// threaded submit-start.
func TestRun_RecordsTurnLatencyAndProviderRoundTrip(t *testing.T) {
	restore := now
	base := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	now = func() time.Time {
		calls++
		if calls == 1 {
			return base // round start, captured just before the provider call
		}
		return base.Add(40 * time.Millisecond) // round end and turn end
	}
	t.Cleanup(func() { now = restore })

	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active:      selectedState("openai", "gpt-x", model.EffortDefault),
		Store:       store,
		Client:      streamClient(contentChunk("hi"), finishChunk("stop")),
		SubmitStart: base.Add(-60 * time.Millisecond),
		Flush:       storeFlush(store),
	})
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	recs := diskRecords(t, store)
	rounds := providerRoundTripEvents(t, recs)
	if len(rounds) != 1 {
		t.Fatalf("provider_round_trip events = %d, want 1; kinds = %v", len(rounds), eventKinds(recs))
	}
	if rounds[0].DurationMs != 40 {
		t.Fatalf("provider_round_trip duration_ms = %d, want 40", rounds[0].DurationMs)
	}
	if rounds[0].Provider != "openai" || rounds[0].ModelID != "gpt-x" {
		t.Fatalf("provider_round_trip identity = %+v, want provider openai model gpt-x", rounds[0])
	}
	turns := turnLatencyEvents(t, recs)
	if len(turns) != 1 {
		t.Fatalf("turn_latency events = %d, want 1; kinds = %v", len(turns), eventKinds(recs))
	}
	if turns[0].DurationMs != 100 {
		t.Fatalf("turn_latency duration_ms = %d, want 100 (end base+40ms minus submit base-60ms)", turns[0].DurationMs)
	}
	if turns[0].Provider != "openai" || turns[0].ModelID != "gpt-x" {
		t.Fatalf("turn_latency identity = %+v, want provider openai model gpt-x", turns[0])
	}
}

// With no submit-start threaded in (a standalone Runner or a non-production path),
// a completed turn records the provider round but no turn_latency, so the
// end-to-end metric is never invented from a zero start.
func TestRun_NoTurnLatencyWithoutSubmitStart(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("hi"), finishChunk("stop")),
		// SubmitStart left zero.
	})
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	recs := store.Records()
	if hasKind(recs, events.KindTurnLatency) {
		t.Fatalf("turn_latency recorded for a turn with no submit start; kinds = %v", eventKinds(recs))
	}
	if !hasKind(recs, events.KindProviderRoundTrip) {
		t.Fatalf("provider_round_trip missing; kinds = %v", eventKinds(recs))
	}
}

// A failed provider round (here a clean zero-delta empty_response) still persists a
// provider_round_trip alongside the provider_request_failed event, so a slow
// failure is visible; it records no turn_latency even when a submit-start is
// present, because the turn produced no completed answer.
func TestRun_FailedRoundRecordsProviderRoundTripNotTurnLatency(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active:      selectedState("openai", "gpt-x", model.EffortDefault),
		Store:       store,
		Client:      streamClient(finishChunk("stop")), // zero content deltas -> empty_response
		SubmitStart: time.Now().Add(-50 * time.Millisecond),
		Flush:       storeFlush(store),
	})
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil (empty_response is a recorded failure, not a returned error)", err)
	}

	recs := diskRecords(t, store)
	if !hasKind(recs, events.KindProviderRequestFailed) {
		t.Fatalf("provider_request_failed missing; kinds = %v", eventKinds(recs))
	}
	rounds := providerRoundTripEvents(t, recs)
	if len(rounds) != 1 {
		t.Fatalf("provider_round_trip events = %d, want 1 (recorded for a failed round); kinds = %v", len(rounds), eventKinds(recs))
	}
	if rounds[0].DurationMs < 0 {
		t.Fatalf("provider_round_trip duration_ms = %d, want >= 0", rounds[0].DurationMs)
	}
	if hasKind(recs, events.KindTurnLatency) {
		t.Fatalf("turn_latency recorded for a failed turn; kinds = %v", eventKinds(recs))
	}
}

func roundTripPayloads(recs []sessions.Record) []string {
	var out []string
	for _, r := range recs {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == events.KindProviderRoundTrip {
			out = append(out, string(ev.Payload))
		}
	}
	return out
}

func TestToolLoop_OpenRouterRecordsPerRoundUpstreamProvider(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))
	client := &scriptedClient{rounds: [][][]byte{
		{withUpstream(toolCallChunk(), `"Groq"`)},
		{withUpstream(contentChunk("all done"), `"Google AI Studio"`), withUpstream(finishChunk("stop"), `"Google AI Studio"`)},
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openrouter", "meta/llama", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, &fakeDispatcher{}, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	recs := diskRecords(t, store)
	rounds := providerRoundTripEvents(t, recs)
	if len(rounds) != 2 {
		t.Fatalf("provider_round_trip events = %d, want 2; kinds = %v", len(rounds), eventKinds(recs))
	}
	if rounds[0].UpstreamProvider != "Groq" || rounds[1].UpstreamProvider != "Google AI Studio" {
		t.Fatalf("upstream_provider per round = [%q %q], want [Groq, Google AI Studio]", rounds[0].UpstreamProvider, rounds[1].UpstreamProvider)
	}
	if got := decodeModelResponse(t, recs).UpstreamProvider; got != "Google AI Studio" {
		t.Fatalf("model_response upstream_provider = %q, want the final round's Google AI Studio", got)
	}
}

func TestRun_OpenRouterStreamDropRecordsUpstreamProvider(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		dec := &dropDecoder{first: withUpstream(contentChunk("partial"), `"Together"`), err: io.ErrUnexpectedEOF}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}}
	runner := New(Deps{
		Active: selectedState("openrouter", "meta/llama", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the mid-stream drop error")
	}
	rounds := providerRoundTripEvents(t, diskRecords(t, store))
	if len(rounds) != 1 || rounds[0].UpstreamProvider != "Together" {
		t.Fatalf("provider_round_trip = %+v, want one with upstream_provider Together", rounds)
	}
}

func TestRun_OpenRouterPreStreamFailureOmitsUpstreamProvider(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	httpErr := &provider.HTTPError{Status: 400, Body: "bad request", Surface: "provider openrouter returned HTTP 400: bad request"}
	runner := New(Deps{
		Active: selectedState("openrouter", "meta/llama", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, httpErr
		}},
		Flush: storeFlush(store),
	})

	if err := runner.Run(context.Background()); !errors.Is(err, httpErr) {
		t.Fatalf("Run() error = %v, want the HTTPError", err)
	}
	payloads := roundTripPayloads(diskRecords(t, store))
	if len(payloads) != 1 || strings.Contains(payloads[0], "upstream_provider") {
		t.Fatalf("provider_round_trip payloads = %v, want one without upstream_provider", payloads)
	}
}

func TestRun_UpstreamProviderOmittedWhenUnattributed(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		chunks   [][]byte
	}{
		{"non-openrouter", "openai", [][]byte{withUpstream(contentChunk("hi"), `"Groq"`), withUpstream(finishChunk("stop"), `"Groq"`)}},
		{"absent", "openrouter", [][]byte{contentChunk("hi"), finishChunk("stop")}},
		{"null", "openrouter", [][]byte{withUpstream(contentChunk("hi"), `null`), finishChunk("stop")}},
		{"empty", "openrouter", [][]byte{withUpstream(contentChunk("hi"), `""`), finishChunk("stop")}},
		{"non-string", "openrouter", [][]byte{withUpstream(contentChunk("hi"), `42`), finishChunk("stop")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			runner := New(Deps{
				Active: selectedState(tc.provider, "m", model.EffortDefault),
				Store:  store,
				Client: streamClient(tc.chunks...),
				Flush:  storeFlush(store),
			})
			if err := runner.Run(context.Background()); err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}
			payloads := roundTripPayloads(diskRecords(t, store))
			if len(payloads) != 1 || strings.Contains(payloads[0], "upstream_provider") {
				t.Fatalf("provider_round_trip payloads = %v, want one without upstream_provider", payloads)
			}
		})
	}
}
