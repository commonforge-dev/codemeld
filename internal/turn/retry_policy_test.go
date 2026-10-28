// Tests for the auto-retry engine: the pure backoff/Retry-After
// policy helpers and the Runner/ToolLoop retry behavior driven by the no-network
// fakeClient harness — success-after-retry, partial-drop discard-and-restart,
// interruptible backoff, exhaustion, the no-tool-replay invariant, and that a
// non-retryable classification (and a disabled policy) surface in one pass.
package turn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
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

// retryOn is the standard enabled policy for these tests: 4 total attempts, 500ms
// base, 8s cap. The per-turn budget defaults in New.
func retryOn() RetryPolicy {
	return RetryPolicy{Enabled: true, MaxAttempts: 4, BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second}
}

// noSleep replaces the package backoff seam with a recorder that never waits, so a
// test exercises the retry loop without wall-clock sleeps. It returns a pointer to
// the recorded delays. randFloat is pinned so any computed backoff is deterministic.
func noSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	restoreSleep, restoreRand := sleep, randFloat
	var slept []time.Duration
	sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	randFloat = func() float64 { return 0.5 }
	t.Cleanup(func() { sleep, randFloat = restoreSleep, restoreRand })
	return &slept
}

// steppedClient calls step(callIndex) (1-based) for each ChatCompletion, so a test
// can fail early attempts and succeed later ones.
func steppedClient(step func(call int) (provider.Response, error)) *fakeClient {
	c := &fakeClient{}
	c.fn = func(context.Context, provider.Request) (provider.Response, error) {
		return step(c.callCount())
	}
	return c
}

func dropStream(content string, err error) provider.Response {
	dec := &dropDecoder{first: contentChunk(content), err: err}
	return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}
}

func findProviderRequestRetry(t *testing.T, recs []sessions.Record) []events.ProviderRequestRetry {
	t.Helper()
	var out []events.ProviderRequestRetry
	for _, r := range recs {
		e, ok := r.(sessions.Event)
		if !ok || e.Kind != events.KindProviderRequestRetry {
			continue
		}
		var p events.ProviderRequestRetry
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatalf("unmarshal provider_request_retry: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func findProviderRequestRetrySkipped(t *testing.T, recs []sessions.Record) []events.ProviderRequestRetrySkipped {
	t.Helper()
	var out []events.ProviderRequestRetrySkipped
	for _, r := range recs {
		e, ok := r.(sessions.Event)
		if !ok || e.Kind != events.KindProviderRequestRetrySkipped {
			continue
		}
		var p events.ProviderRequestRetrySkipped
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatalf("unmarshal provider_request_retry_skipped: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// kindIndex returns the append-order index of the first record of kind, or -1. Used
// to prove the durable skipped event is recorded before the terminal
// provider_request_failed on the retry-skipped paths.
func kindIndex(recs []sessions.Record, kind string) int {
	for i, r := range recs {
		if e, ok := r.(sessions.Event); ok && e.Kind == kind {
			return i
		}
	}
	return -1
}

// --- pure policy helpers ----------------------------------------------------

func TestBackoffDelay_FullJitterBounds(t *testing.T) {
	restore := randFloat
	t.Cleanup(func() { randFloat = restore })
	p := RetryPolicy{BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second}
	caps := map[int]time.Duration{1: 500 * time.Millisecond, 2: time.Second, 3: 2 * time.Second, 4: 4 * time.Second, 5: 8 * time.Second, 6: 8 * time.Second}
	for attempt, wantCap := range caps {
		randFloat = func() float64 { return 0 }
		if got := backoffDelay(p, attempt); got != 0 {
			t.Fatalf("attempt %d zero-jitter = %v, want 0", attempt, got)
		}
		randFloat = func() float64 { return 0.999 }
		got := backoffDelay(p, attempt)
		if got < 0 || got > wantCap {
			t.Fatalf("attempt %d delay = %v, want within [0, %v]", attempt, got, wantCap)
		}
		if got < wantCap/2 {
			t.Fatalf("attempt %d near-max jitter = %v, want close to cap %v", attempt, got, wantCap)
		}
	}
}

func TestRetryDelay_RetryAfterOverridesAndCaps(t *testing.T) {
	restore := randFloat
	t.Cleanup(func() { randFloat = restore })
	p := RetryPolicy{BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second}
	if got := retryDelay(p, 1, 3*time.Second, true); got != 3*time.Second {
		t.Fatalf("Retry-After 3s = %v, want 3s honored", got)
	}
	if got := retryDelay(p, 1, 20*time.Second, true); got != 8*time.Second {
		t.Fatalf("Retry-After 20s = %v, want capped at MaxDelay 8s", got)
	}
	// A present, parsed Retry-After of 0 (e.g. `Retry-After: 0` or a past HTTP-date)
	// overrides backoff with an immediate retry rather than falling back to jitter.
	randFloat = func() float64 { return 0.999 }
	if got := retryDelay(p, 1, 0, true); got != 0 {
		t.Fatalf("present zero Retry-After = %v, want 0 (immediate retry, not jitter)", got)
	}
	// With no Retry-After present, the same attempt uses computed backoff (non-zero
	// under near-max jitter), confirming the boolean — not the duration — gates the override.
	if got := retryDelay(p, 1, 0, false); got == 0 {
		t.Fatalf("absent Retry-After with near-max jitter = 0, want computed backoff")
	}
}

func TestParseRetryAfter(t *testing.T) {
	ref := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		in     string
		want   time.Duration
		wantOK bool
	}{
		{"seconds", "5", 5 * time.Second, true},
		{"seconds padded", "  10 ", 10 * time.Second, true},
		{"negative seconds clamps", "-3", 0, true},
		{"http-date future", ref.Add(7 * time.Second).Format(http.TimeFormat), 7 * time.Second, true},
		{"http-date past clamps", ref.Add(-time.Hour).Format(http.TimeFormat), 0, true},
		{"empty", "", 0, false},
		{"garbage", "soon", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.in, ref)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// --- Runner retry behavior --------------------------------------------------

// A transient stream drop at 0 chars is auto-retried and the second attempt
// succeeds: the store holds exactly one coherent assistant message, one
// provider_request_retry (read back from disk), one provider_round_trip per
// attempt, no model interrupt/seal for the recovered blip, and the partial
// rollback hook is NOT fired (nothing was streamed to roll back).
func TestRun_RetrySucceedsAfterZeroCharDrop(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	var interrupts, rollbacks, resumes, recovered int
	var backoffs [][2]int
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return dropStream("", io.ErrUnexpectedEOF), nil
		}
		return provider.Response{Stream: newStream(contentChunk("Hello world"), finishChunk("stop"))}, nil
	})
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           retryOn(),
		Interrupt:       func() { interrupts++ },
		RollbackPartial: func() { rollbacks++ },
		RetryBackoff: func(nextAttempt, totalAttempts int) {
			backoffs = append(backoffs, [2]int{nextAttempt, totalAttempts})
		},
		RetryResume:    func() { resumes++ },
		RetryRecovered: func(retries int) { recovered = retries },
		Flush:          storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil (recovered after one retry)", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (one drop, one success)", client.callCount())
	}
	msgs := assistantMessages(store.Records())
	if len(msgs) != 1 || msgs[0].Content.Text() != "Hello world" {
		t.Fatalf("assistant messages = %+v, want one coherent %q", msgs, "Hello world")
	}
	if interrupts != 0 {
		t.Fatalf("Interrupt fired %d times, want 0 for a recovered blip (no seal between attempts)", interrupts)
	}
	if rollbacks != 0 {
		t.Fatalf("RollbackPartial fired %d times, want 0 for a 0-char drop", rollbacks)
	}
	if len(backoffs) != 1 || backoffs[0] != [2]int{2, 4} {
		t.Fatalf("RetryBackoff calls = %+v, want next attempt 2 of 4", backoffs)
	}
	if resumes != 1 {
		t.Fatalf("RetryResume calls = %d, want 1 before re-issue", resumes)
	}
	if recovered != 1 {
		t.Fatalf("RetryRecovered retries = %d, want 1", recovered)
	}
	recs := diskRecords(t, store)
	retries := findProviderRequestRetry(t, recs)
	if len(retries) != 1 || retries[0].Attempt != 1 || retries[0].Phase != "stream_drop" {
		t.Fatalf("provider_request_retry = %+v, want one attempt-1 stream_drop", retries)
	}
	if retries[0].PartialCharsDiscarded != 0 {
		t.Fatalf("partial_chars_discarded = %d, want 0 for a 0-char drop", retries[0].PartialCharsDiscarded)
	}
	if rounds := providerRoundTripEvents(t, recs); len(rounds) != 2 {
		t.Fatalf("provider_round_trip events = %d, want 2 (one per attempt)", len(rounds))
	}
	if hasKind(recs, "provider_request_failed") {
		t.Fatalf("provider_request_failed emitted for a recovered turn; kinds = %v", eventKinds(recs))
	}
}

// A stream drop after partial content discards and restarts: the rollback hook is
// fired once, the retry records the discarded char count, and the final store
// holds a single coherent assistant message (the regenerated answer only).
func TestRun_RetryRollsBackPartialDrop(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	var rollbacks int
	var sunk []string
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return dropStream("Partial", io.ErrUnexpectedEOF), nil
		}
		return provider.Response{Stream: newStream(contentChunk("Hello world"), finishChunk("stop"))}, nil
	})
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           retryOn(),
		Sink:            func(d string) { sunk = append(sunk, d) },
		RollbackPartial: func() { rollbacks++ },
		Flush:           storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if rollbacks != 1 {
		t.Fatalf("RollbackPartial fired %d times, want 1 for a partial drop", rollbacks)
	}
	msgs := assistantMessages(store.Records())
	if len(msgs) != 1 || msgs[0].Content.Text() != "Hello world" {
		t.Fatalf("assistant messages = %+v, want one coherent %q (partial discarded)", msgs, "Hello world")
	}
	retries := findProviderRequestRetry(t, diskRecords(t, store))
	if len(retries) != 1 || retries[0].PartialCharsDiscarded != int64(len("Partial")) {
		t.Fatalf("provider_request_retry = %+v, want one with partial_chars_discarded %d", retries, len("Partial"))
	}
}

// A 429 carrying Retry-After overrides the computed backoff (capped at MaxDelay):
// the recorded wait equals the honored Retry-After, proving HTTPError.RetryAfter
// flows from the provider client through the retry engine. The second attempt
// succeeds.
func TestRun_RetryAfterHonoredOn429(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return provider.Response{}, &provider.HTTPError{
				Status: 429, Body: "rate limited", Surface: "provider openai returned HTTP 429: rate limited", RetryAfter: "2",
			}
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  retryOn(),
		Flush:  storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if len(*slept) != 1 || (*slept)[0] != 2*time.Second {
		t.Fatalf("backoff waits = %v, want exactly [2s] honored from Retry-After", *slept)
	}
	retries := findProviderRequestRetry(t, diskRecords(t, store))
	if len(retries) != 1 || retries[0].Phase != "http" || retries[0].DelayMs != 2000 {
		t.Fatalf("provider_request_retry = %+v, want one http retry with delay_ms 2000", retries)
	}
}

// A valid `Retry-After: 0` (a provider asking for an immediate retry; a past
// HTTP-date parses the same way) is honored as a zero-delay override rather than
// discarded as absent and replaced with jittered backoff. randFloat is pinned to
// near-max so any fallback to computed backoff would record a clearly non-zero wait,
// making the assertion that the recorded sleep and delay_ms are both 0 a real
// regression guard for the hasRetryAfter signal.
func TestRun_RetryAfterZeroHonoredAsImmediate(t *testing.T) {
	slept := noSleep(t)
	randFloat = func() float64 { return 0.999 }
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return provider.Response{}, &provider.HTTPError{
				Status: 503, Body: "unavailable", Surface: "provider openai returned HTTP 503: unavailable", RetryAfter: "0",
			}
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  retryOn(),
		Flush:  storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if len(*slept) != 1 || (*slept)[0] != 0 {
		t.Fatalf("backoff waits = %v, want exactly [0] honored from Retry-After: 0 (not jittered backoff)", *slept)
	}
	retries := findProviderRequestRetry(t, diskRecords(t, store))
	if len(retries) != 1 || retries[0].Phase != "http" || retries[0].DelayMs != 0 {
		t.Fatalf("provider_request_retry = %+v, want one http retry with delay_ms 0", retries)
	}
}

// A non-retryable classification (HTTP 400) surfaces immediately even with retry
// enabled: one provider call, no backoff wait, a committed provider_request_failed,
// and no provider_request_retry.
func TestRun_NonRetryableSurfacesWithoutRetry(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	httpErr := &provider.HTTPError{Status: 400, Body: "bad request", Surface: "provider openai returned HTTP 400: bad request"}
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{}, httpErr
	}}
	var notices int
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  retryOn(),
		Notice: func(string) { notices++ },
	})

	if err := runner.Run(context.Background()); !errors.Is(err, httpErr) {
		t.Fatalf("Run() error = %v, want the HTTP 400 error", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (no retry for a 4xx)", client.callCount())
	}
	if len(*slept) != 0 {
		t.Fatalf("backoff waits = %v, want none for a non-retryable failure", *slept)
	}
	recs := store.Records()
	if !hasKind(recs, "provider_request_failed") {
		t.Fatalf("missing provider_request_failed; kinds = %v", eventKinds(recs))
	}
	if hasKind(recs, "provider_request_retry") {
		t.Fatalf("provider_request_retry emitted for a non-retryable failure; kinds = %v", eventKinds(recs))
	}
	if hasKind(recs, "provider_request_retry_skipped") {
		t.Fatalf("provider_request_retry_skipped emitted for a non-retryable failure; kinds = %v", eventKinds(recs))
	}
	if notices != 1 {
		t.Fatalf("notices = %d, want 1 surfaced in one pass", notices)
	}
}

// A disabled policy restores the no-retry behavior exactly: a stream drop
// surfaces once with no wait and no retry event.
func TestRun_RetryDisabledRestoresNoRetry(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("Hi", io.ErrUnexpectedEOF), nil
	})
	var interrupts int
	runner := New(Deps{
		Active:    selectedState("openai", "gpt-x", model.EffortDefault),
		Store:     store,
		Client:    client,
		Retry:     RetryPolicy{Enabled: false},
		Interrupt: func() { interrupts++ },
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error")
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 with retry disabled", client.callCount())
	}
	if len(*slept) != 0 {
		t.Fatalf("backoff waits = %v, want none with retry disabled", *slept)
	}
	recs := store.Records()
	if !hasKind(recs, "provider_request_failed") || hasKind(recs, "provider_request_retry") {
		t.Fatalf("kinds = %v, want provider_request_failed and no retry event", eventKinds(recs))
	}
	if interrupts != 1 {
		t.Fatalf("Interrupt = %d, want 1 (sealed exactly as before g790)", interrupts)
	}
}

// A backoff wait interrupted by a context cancel (ESC) ends the turn promptly and
// is not itself retried: the cancel is returned, no further provider call is made,
// and no terminal provider_request_failed is committed.
func TestRun_BackoffWaitInterruptibleByCancel(t *testing.T) {
	restoreSleep := sleep
	sleep = func(context.Context, time.Duration) error { return context.Canceled }
	t.Cleanup(func() { sleep = restoreSleep })

	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("", io.ErrUnexpectedEOF), nil
	})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  retryOn(),
	})

	if err := runner.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled from the interrupted wait", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (the wait was cancelled before re-issue)", client.callCount())
	}
	recs := store.Records()
	if hasKind(recs, "provider_request_failed") {
		t.Fatalf("provider_request_failed committed for a cancelled backoff; kinds = %v", eventKinds(recs))
	}
	if rs := findProviderRequestRetry(t, recs); len(rs) != 1 {
		t.Fatalf("provider_request_retry = %d, want 1 (the scheduled retry was recorded before the cancel)", len(rs))
	}
}

// When every attempt fails, the failure surfaces after the attempt cap: the last
// attempt commits provider_request_failed and seals once, each attempt records its
// own provider_round_trip, and the attempt count is reconstructable from the
// MaxAttempts-1 retry events.
func TestRun_RetryExhaustionSurfacesFailure(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("x", io.ErrUnexpectedEOF), nil
	})
	var interrupts int
	var notices []string
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           RetryPolicy{Enabled: true, MaxAttempts: 3, BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second},
		Interrupt:       func() { interrupts++ },
		Notice:          func(text string) { notices = append(notices, text) },
		RollbackPartial: func() {},
		Flush:           storeFlush(store),
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error after exhausting retries")
	}
	if client.callCount() != 3 {
		t.Fatalf("provider calls = %d, want 3 (MaxAttempts)", client.callCount())
	}
	if interrupts != 1 {
		t.Fatalf("Interrupt = %d, want 1 (sealed only on the final exhausted attempt)", interrupts)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "failed after 3 attempts") {
		t.Fatalf("notices = %+v, want terminal failure enriched with attempt count", notices)
	}
	recs := diskRecords(t, store)
	if rs := findProviderRequestRetry(t, recs); len(rs) != 2 {
		t.Fatalf("provider_request_retry = %d, want 2 (MaxAttempts-1)", len(rs))
	}
	if !hasKind(recs, "provider_request_failed") {
		t.Fatalf("missing terminal provider_request_failed; kinds = %v", eventKinds(recs))
	}
	if rounds := providerRoundTripEvents(t, recs); len(rounds) != 3 {
		t.Fatalf("provider_round_trip events = %d, want 3 (one per attempt)", len(rounds))
	}
}

// The per-turn wall-clock budget stops the retry loop before it sleeps or re-issues,
// independently of the MaxAttempts cap (req: retry-policy tests include budget
// exhaustion). now is pinned constant so elapsed time is
// zero and only the computed next delay is weighed; randFloat is pinned high so that
// delay is a clearly-positive backoff that exceeds the tiny Budget. With MaxAttempts
// well above one, the only thing that can stop the loop on the first failure is the
// budget check at retry.go:108-112: the runner makes a single provider call, records
// no sleep, commits the terminal provider_request_failed, and emits no
// provider_request_retry for the budget-blocked attempt.
func TestRun_RetryBudgetExhaustionStopsBeforeRetry(t *testing.T) {
	slept := noSleep(t)
	randFloat = func() float64 { return 0.999 } // a clearly non-zero backoff (~500ms)
	restoreNow := now
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return base } // zero elapsed: budget is spent purely by the next delay
	t.Cleanup(func() { now = restoreNow })

	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("", io.ErrUnexpectedEOF), nil
	})
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           RetryPolicy{Enabled: true, MaxAttempts: 5, BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second, Budget: time.Millisecond},
		RollbackPartial: func() {},
		Flush:           storeFlush(store),
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error after the budget is exhausted")
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (budget blocks the retry before re-issue)", client.callCount())
	}
	if len(*slept) != 0 {
		t.Fatalf("backoff waits = %v, want none (budget blocks before the sleep)", *slept)
	}
	recs := diskRecords(t, store)
	if !hasKind(recs, "provider_request_failed") {
		t.Fatalf("missing terminal provider_request_failed; kinds = %v", eventKinds(recs))
	}
	if rs := findProviderRequestRetry(t, recs); len(rs) != 0 {
		t.Fatalf("provider_request_retry = %d, want 0 (no retry scheduled once budget is spent)", len(rs))
	}
}

// The no-tool-replay invariant: a stream drop is retried inside one provider round,
// so a completed tool dispatch is never replayed. The drop precedes the tool-call
// response, the round is re-issued, the tool dispatches exactly once, and the turn
// reaches a final answer.
func TestToolLoop_RetryDoesNotReplayTool(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(call int) (provider.Response, error) {
		switch call {
		case 1:
			return dropStream("", io.ErrUnexpectedEOF), nil // transient blip before any tool call
		case 2:
			return provider.Response{Stream: newStream(toolCallChunk())}, nil // tool-call round
		default:
			return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
		}
	})
	disp := &fakeDispatcher{}
	loop := NewToolLoop(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           retryOn(),
		RollbackPartial: func() {},
		Flush:           storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("ToolLoop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 3 {
		t.Fatalf("provider calls = %d, want 3 (drop, tool-call, final answer)", client.callCount())
	}
	if len(disp.order) != 1 {
		t.Fatalf("tool dispatches = %d (%v), want exactly 1 — a retry must not replay a tool", len(disp.order), disp.order)
	}
	recs := store.Records()
	if rs := findProviderRequestRetry(t, recs); len(rs) != 1 {
		t.Fatalf("provider_request_retry = %d, want 1 for the pre-tool drop", len(rs))
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response for the completed turn; kinds = %v", eventKinds(recs))
	}
}

// --- retry-skipped invariant ----------------------------------

// The reported bug shape — a clean zero-delta empty_response with retry enabled and
// more than one allowed attempt — now schedules a retry instead of surfacing as a
// silent one-attempt final failure: exactly one provider_request_retry (phase
// empty_response), no provider_request_retry_skipped, and no terminal
// provider_request_failed. The second attempt recovers.
func TestRun_ZeroDeltaStreamSchedulesRetryBeforeFailure(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return provider.Response{Stream: newStream(finishChunk("stop"))}, nil // zero content deltas -> empty_response
		}
		return provider.Response{Stream: newStream(contentChunk("Hello world"), finishChunk("stop"))}, nil
	})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  retryOn(),
		Flush:  storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil (recovered after one retry)", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (one empty_response, one success)", client.callCount())
	}
	recs := diskRecords(t, store)
	retries := findProviderRequestRetry(t, recs)
	if len(retries) != 1 || retries[0].Attempt != 1 || retries[0].Phase != "empty_response" {
		t.Fatalf("provider_request_retry = %+v, want one attempt-1 empty_response retry", retries)
	}
	if skipped := findProviderRequestRetrySkipped(t, recs); len(skipped) != 0 {
		t.Fatalf("provider_request_retry_skipped = %+v, want none when a retry was scheduled", skipped)
	}
	if hasKind(recs, "provider_request_failed") {
		t.Fatalf("provider_request_failed emitted for a recovered zero-delta turn; kinds = %v", eventKinds(recs))
	}
}

// Retry disabled: a retryable stream drop records provider_request_retry_skipped with
// skip_reason retry_disabled, appended before the terminal provider_request_failed, and
// no provider_request_retry.
func TestRun_RetryDisabledEmitsSkippedReason(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("", io.ErrUnexpectedEOF), nil
	})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  RetryPolicy{Enabled: false},
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error with retry disabled")
	}
	recs := store.Records()
	skipped := findProviderRequestRetrySkipped(t, recs)
	if len(skipped) != 1 || skipped[0].SkipReason != "retry_disabled" {
		t.Fatalf("provider_request_retry_skipped = %+v, want one with skip_reason retry_disabled", skipped)
	}
	if skipped[0].Phase != "stream_drop" || skipped[0].PartialCharsDiscarded != 0 {
		t.Fatalf("skipped payload = %+v, want stream_drop phase with 0 partial chars", skipped[0])
	}
	if hasKind(recs, "provider_request_retry") {
		t.Fatalf("provider_request_retry emitted with retry disabled; kinds = %v", eventKinds(recs))
	}
	si, fi := kindIndex(recs, "provider_request_retry_skipped"), kindIndex(recs, "provider_request_failed")
	if si < 0 || fi < 0 || si > fi {
		t.Fatalf("skipped index %d / failed index %d, want the skip recorded before the terminal failure", si, fi)
	}
}

// Effective single attempt: an enabled policy with MaxAttempts 1 hits the attempt cap
// on the first retryable failure and records skip_reason max_attempts_reached (not
// retry_disabled, since the policy is enabled) before the terminal failure, with no
// retry scheduled.
func TestRun_RetryMaxAttemptsEmitsSkippedReason(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("", io.ErrUnexpectedEOF), nil
	})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  RetryPolicy{Enabled: true, MaxAttempts: 1, BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second},
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error at the single-attempt cap")
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (cap reached on the first failure)", client.callCount())
	}
	if len(*slept) != 0 {
		t.Fatalf("backoff waits = %v, want none at the attempt cap", *slept)
	}
	recs := store.Records()
	skipped := findProviderRequestRetrySkipped(t, recs)
	if len(skipped) != 1 || skipped[0].SkipReason != "max_attempts_reached" || skipped[0].Attempt != 1 {
		t.Fatalf("provider_request_retry_skipped = %+v, want one attempt-1 max_attempts_reached", skipped)
	}
	if hasKind(recs, "provider_request_retry") {
		t.Fatalf("provider_request_retry emitted at the single-attempt cap; kinds = %v", eventKinds(recs))
	}
	si, fi := kindIndex(recs, "provider_request_retry_skipped"), kindIndex(recs, "provider_request_failed")
	if si < 0 || fi < 0 || si > fi {
		t.Fatalf("skipped index %d / failed index %d, want the skip recorded before the terminal failure", si, fi)
	}
}

// Budget blocked: a retryable failure whose next backoff exceeds the remaining budget
// stops before sleeping or re-issuing and records skip_reason budget_exhausted (the
// attempt cap is well above one, so only the budget can terminate the first failure).
// now is pinned so elapsed is zero and only the computed delay is weighed; randFloat is
// pinned high so that delay clearly exceeds the tiny Budget.
func TestRun_RetryBudgetExhaustionEmitsSkippedReason(t *testing.T) {
	slept := noSleep(t)
	randFloat = func() float64 { return 0.999 }
	restoreNow := now
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return base }
	t.Cleanup(func() { now = restoreNow })

	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("", io.ErrUnexpectedEOF), nil
	})
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           RetryPolicy{Enabled: true, MaxAttempts: 5, BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second, Budget: time.Millisecond},
		RollbackPartial: func() {},
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error after the budget is exhausted")
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (budget blocks before re-issue)", client.callCount())
	}
	if len(*slept) != 0 {
		t.Fatalf("backoff waits = %v, want none (budget blocks before the sleep)", *slept)
	}
	recs := store.Records()
	skipped := findProviderRequestRetrySkipped(t, recs)
	if len(skipped) != 1 || skipped[0].SkipReason != "budget_exhausted" {
		t.Fatalf("provider_request_retry_skipped = %+v, want one with skip_reason budget_exhausted", skipped)
	}
	if hasKind(recs, "provider_request_retry") {
		t.Fatalf("provider_request_retry emitted for a budget-blocked attempt; kinds = %v", eventKinds(recs))
	}
	si, fi := kindIndex(recs, "provider_request_retry_skipped"), kindIndex(recs, "provider_request_failed")
	if si < 0 || fi < 0 || si > fi {
		t.Fatalf("skipped index %d / failed index %d, want the skip recorded before the terminal failure", si, fi)
	}
}

// A backoff wait cancelled by ESC already recorded a scheduled provider_request_retry
// and never reaches a terminal commit, so it must not emit a skipped event.
func TestRun_CancelledBackoffNoSkippedEvent(t *testing.T) {
	restoreSleep := sleep
	sleep = func(context.Context, time.Duration) error { return context.Canceled }
	t.Cleanup(func() { sleep = restoreSleep })

	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("", io.ErrUnexpectedEOF), nil
	})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  retryOn(),
	})

	if err := runner.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled from the interrupted wait", err)
	}
	recs := store.Records()
	if skipped := findProviderRequestRetrySkipped(t, recs); len(skipped) != 0 {
		t.Fatalf("provider_request_retry_skipped = %+v, want none for a cancelled backoff", skipped)
	}
	if rs := findProviderRequestRetry(t, recs); len(rs) != 1 {
		t.Fatalf("provider_request_retry = %d, want 1 (scheduled before the cancel)", len(rs))
	}
}

// The no-tool-replay invariant on the continuation round: the producer-reachable
// risk is a transient drop in the post-tool provider round, after a tool result has
// already been dispatched and persisted. Here call 1 is the tool-call round (one
// dispatch), call 2 is the continuation round that drops mid-stream, and call 3 is
// the in-round retry that lands the final answer. The retry re-issues only the
// continuation request — re-entering the tool loop or re-running OnToolCalls would
// show up as a second dispatch, which this test rejects.
func TestToolLoop_RetryAfterToolDispatchDoesNotReplayTool(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(call int) (provider.Response, error) {
		switch call {
		case 1:
			return provider.Response{Stream: newStream(toolCallChunk())}, nil // tool-call round: dispatches once
		case 2:
			return dropStream("", io.ErrUnexpectedEOF), nil // continuation drop, after the completed dispatch
		default:
			return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
		}
	})
	disp := &fakeDispatcher{}
	loop := NewToolLoop(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           retryOn(),
		RollbackPartial: func() {},
		Flush:           storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("ToolLoop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 3 {
		t.Fatalf("provider calls = %d, want 3 (tool-call, continuation drop, final answer)", client.callCount())
	}
	if len(disp.order) != 1 {
		t.Fatalf("tool dispatches = %d (%v), want exactly 1 — a continuation retry must not replay the dispatched tool", len(disp.order), disp.order)
	}
	recs := store.Records()
	if rs := findProviderRequestRetry(t, recs); len(rs) != 1 {
		t.Fatalf("provider_request_retry = %d, want 1 for the continuation drop", len(rs))
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response for the completed turn; kinds = %v", eventKinds(recs))
	}
}

func TestToolLoop_AssemblyFailureRetriesBeforeAnyDispatch(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return provider.Response{Stream: newStream(contentChunk("thinking"), toolCallsChunk(toolFrag(0, "", "do", "{}")))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	})
	disp := &fakeDispatcher{}
	var backoffs [][2]int
	var rollbacks int
	loop := NewToolLoop(Deps{
		Active:       selectedState("openai", "gpt-x", model.EffortDefault),
		Store:        store,
		Client:       client,
		Retry:        retryOn(),
		RetryBackoff: func(next, total int) { backoffs = append(backoffs, [2]int{next, total}) },
		RollbackPartial: func() {
			rollbacks++
		},
		Flush: storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("ToolLoop.Run() error = %v, want nil (the re-issued round answered)", err)
	}

	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (failed handoff + one re-issue)", client.callCount())
	}
	if len(disp.order) != 0 {
		t.Fatalf("tool dispatches = %v, want none: the round failed before the scheduler", disp.order)
	}
	if rollbacks != 1 {
		t.Fatalf("RollbackPartial calls = %d, want 1 for the discarded handoff prose", rollbacks)
	}
	recs := diskRecords(t, store)
	retries := findProviderRequestRetry(t, recs)
	if len(retries) != 1 {
		t.Fatalf("provider_request_retry = %d, want 1", len(retries))
	}
	if retries[0].Phase != events.RetryPhaseToolHandoff || retries[0].Reason != events.RetryReasonAssemblyFailed {
		t.Fatalf("(phase, reason) = (%q, %q), want (%q, %q)", retries[0].Phase, retries[0].Reason,
			events.RetryPhaseToolHandoff, events.RetryReasonAssemblyFailed)
	}
	if retries[0].Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", retries[0].Attempt)
	}
	if len(*slept) != 1 || (*slept)[0] != 250*time.Millisecond {
		t.Fatalf("backoff waits = %v, want one 250ms wait (500ms base at 0.5 jitter)", *slept)
	}
	if len(backoffs) != 1 || backoffs[0] != [2]int{2, 4} {
		t.Fatalf("retry UI backoffs = %v, want [[2 4]]", backoffs)
	}
	terminals := turnTerminalEvents(t, recs)
	if len(terminals) != 2 {
		t.Fatalf("turn_terminal events = %d, want one per attempt; kinds = %v", len(terminals), eventKinds(recs))
	}
	if terminals[0].Outcome != events.TurnOutcomeToolAssemblyFailed || terminals[0].DispatchStarted {
		t.Fatalf("abandoned round = (%q, %t), want (%q, false)", terminals[0].Outcome, terminals[0].DispatchStarted,
			events.TurnOutcomeToolAssemblyFailed)
	}
	if terminals[1].Outcome != events.TurnOutcomeCompleted {
		t.Fatalf("re-issued round outcome = %q, want %q", terminals[1].Outcome, events.TurnOutcomeCompleted)
	}
	if terminals[0].TurnID != terminals[1].TurnID {
		t.Fatalf("turn ids = (%q, %q), want the re-issue under the same turn", terminals[0].TurnID, terminals[1].TurnID)
	}
	if kindIndex(recs, events.KindTurnTerminal) > kindIndex(recs, events.KindProviderRequestRetry) {
		t.Fatal("the abandoned round's terminal record must be written before the retry that replaces it")
	}
}

func TestToolLoop_InvalidPlanRetriesBeforeAnyDispatch(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return provider.Response{Stream: newStream(toolCallChunk())}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	})
	disp := &planMutatingDispatcher{mutate: func(u []PlannedToolCall) []PlannedToolCall {
		u[0].Run = nil
		return u
	}}
	var activities int
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  retryOn(),
		Flush:  storeFlush(store),
		OnToolActivity: func([]string) {
			activities++
		},
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("ToolLoop.Run() error = %v, want nil (the re-issued round answered)", err)
	}

	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (rejected plan + one re-issue)", client.callCount())
	}
	if n := disp.dispatchCount(); n != 0 {
		t.Fatalf("tool dispatches = %d, want 0: a rejected plan never reaches the scheduler", n)
	}
	if activities != 0 {
		t.Fatalf("tool activity calls = %d, want 0 for plans rejected before dispatch", activities)
	}
	recs := diskRecords(t, store)
	retries := findProviderRequestRetry(t, recs)
	if len(retries) != 1 || retries[0].Phase != events.RetryPhaseToolHandoff || retries[0].Reason != events.RetryReasonInvalidPlan {
		t.Fatalf("provider_request_retry = %+v, want one (%q, %q)", retries,
			events.RetryPhaseToolHandoff, events.RetryReasonInvalidPlan)
	}
	terminals := turnTerminalEvents(t, recs)
	if len(terminals) != 2 || terminals[0].Outcome != events.TurnOutcomeToolPlanInvalid || terminals[0].DispatchStarted {
		t.Fatalf("terminal records = %+v, want the abandoned round recorded as a pre-dispatch %q", terminals,
			events.TurnOutcomeToolPlanInvalid)
	}
}

func TestToolLoop_StartedDispatchIsNeverRetried(t *testing.T) {
	cases := []struct {
		name   string
		result func(AssembledToolCall) (ToolResult, error)
		want   string
	}{
		{
			name:   "failed edit",
			result: func(AssembledToolCall) (ToolResult, error) { return ToolResult{}, errors.New("edit failed") },
			want:   events.TurnOutcomeDispatchFailed,
		},
		{
			name: "denied edit",
			result: func(AssembledToolCall) (ToolResult, error) {
				return ToolResult{Content: `{"denied_by":"user","reason":"no"}`, Denied: true}, nil
			},
			want: events.TurnOutcomeCompleted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			noSleep(t)
			store := storeAt(t.TempDir() + "/session.json")
			client := steppedClient(func(int) (provider.Response, error) {
				return provider.Response{Stream: newStream(toolCallChunk())}, nil
			})
			disp := &fakeDispatcher{resultFn: tc.result}
			loop := NewToolLoop(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  store,
				Client: client,
				Retry:  retryOn(),
				Flush:  storeFlush(store),
			}, disp, 3)

			_ = loop.Run(context.Background())

			if len(disp.order) != 1 {
				t.Fatalf("tool dispatches = %v, want exactly 1 (a started dispatch is never replayed)", disp.order)
			}
			if client.callCount() != 1 {
				t.Fatalf("provider calls = %d, want 1 (the round is not re-issued)", client.callCount())
			}
			recs := diskRecords(t, store)
			if rs := findProviderRequestRetry(t, recs); len(rs) != 0 {
				t.Fatalf("provider_request_retry = %+v, want none once dispatch began", rs)
			}
			terminals := turnTerminalEvents(t, recs)
			if len(terminals) != 1 {
				t.Fatalf("turn_terminal events = %d, want 1; kinds = %v", len(terminals), eventKinds(recs))
			}
			if terminals[0].Outcome != tc.want || !terminals[0].DispatchStarted {
				t.Fatalf("terminal = (%q, %t), want (%q, true)", terminals[0].Outcome, terminals[0].DispatchStarted, tc.want)
			}
		})
	}
}

func TestToolLoop_ExhaustedHandoffRetriesRecordSkipReason(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "", "do", "{}")))}, nil
	})
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Retry:  RetryPolicy{Enabled: true, MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Second},
		Flush:  storeFlush(store),
	}, &fakeDispatcher{}, 3)

	if err := loop.Run(context.Background()); err == nil {
		t.Fatal("ToolLoop.Run() error = nil, want the exhausted handoff failure surfaced")
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (the configured attempt cap)", client.callCount())
	}
	recs := diskRecords(t, store)
	skipped := findProviderRequestRetrySkipped(t, recs)
	if len(skipped) != 1 {
		t.Fatalf("provider_request_retry_skipped = %d, want 1", len(skipped))
	}
	if skipped[0].Phase != events.RetryPhaseToolHandoff || skipped[0].SkipReason != "max_attempts_reached" {
		t.Fatalf("(phase, skip_reason) = (%q, %q), want (%q, max_attempts_reached)",
			skipped[0].Phase, skipped[0].SkipReason, events.RetryPhaseToolHandoff)
	}
	if terminals := turnTerminalEvents(t, recs); len(terminals) != 2 {
		t.Fatalf("turn_terminal events = %d, want one per attempt; kinds = %v", len(terminals), eventKinds(recs))
	}
}

func unavailableUpstream(name, errorType string) error {
	body := `{"error":{"code":502,"message":"Upstream error from ` + name + `: service unavailable","metadata":{"error_type":"` + errorType + `"}}}`
	return &ssestream.StreamError{Event: ssestream.Event{Data: []byte(body)}}
}

func ignoreRecordingClient(step func(call int) (provider.Response, error)) (*fakeClient, *[][]string) {
	seen := &[][]string{}
	c := &fakeClient{}
	c.fn = func(_ context.Context, req provider.Request) (provider.Response, error) {
		*seen = append(*seen, req.IgnoredProviders)
		return step(c.callCount())
	}
	return c, seen
}

func okStream(text string) provider.Response {
	return provider.Response{Stream: newStream(contentChunk(text), finishChunk("stop"))}
}

const togetherNotice = "Provider together failing to respond. Removing for rest of this session"

func TestRun_UnavailableUpstreamRetriesImmediatelyWithIgnoreList(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client, seen := ignoreRecordingClient(func(call int) (provider.Response, error) {
		if call == 1 {
			return dropStream("Partial", unavailableUpstream("Together", "provider_unavailable")), nil
		}
		return okStream("Hello world"), nil
	})
	ignored := &IgnoredProviders{}
	var notices []string
	var rollbacks int
	var backoffs [][2]int
	runner := New(Deps{
		Active:                selectedState("openrouter", "m", model.EffortDefault),
		Store:                 store,
		Client:                client,
		Retry:                 retryOn(),
		IgnoredProviders:      ignored,
		ProviderIgnoredNotice: func(text string) { notices = append(notices, text) },
		RollbackPartial:       func() { rollbacks++ },
		RetryBackoff:          func(next, total int) { backoffs = append(backoffs, [2]int{next, total}) },
		Flush:                 storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if len(*seen) != 2 || len((*seen)[0]) != 0 || !slices.Equal((*seen)[1], []string{"together"}) {
		t.Fatalf("request ignore lists = %v, want [[] [together]]", *seen)
	}
	if !slices.Equal(notices, []string{togetherNotice}) {
		t.Fatalf("notices = %q, want exactly %q", notices, togetherNotice)
	}
	if !slices.Equal(*slept, []time.Duration{0}) {
		t.Fatalf("backoff waits = %v, want [0]", *slept)
	}
	if rollbacks != 1 {
		t.Fatalf("RollbackPartial = %d, want 1", rollbacks)
	}
	if len(backoffs) != 1 || backoffs[0] != [2]int{2, 4} {
		t.Fatalf("RetryBackoff = %v, want [[2 4]]", backoffs)
	}
	retries := findProviderRequestRetry(t, diskRecords(t, store))
	if len(retries) != 1 || retries[0].Phase != "stream_drop" || retries[0].DelayMs != 0 {
		t.Fatalf("provider_request_retry = %+v, want one stream_drop retry with delay_ms 0", retries)
	}
	if !slices.Equal(ignored.List(), []string{"together"}) {
		t.Fatalf("ignored = %v, want [together]", ignored.List())
	}
}

func TestRun_AlreadyIgnoredUpstreamTakesNormalBackoff(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client, seen := ignoreRecordingClient(func(call int) (provider.Response, error) {
		if call <= 2 {
			return dropStream("", unavailableUpstream("Together", "provider_unavailable")), nil
		}
		return okStream("ok"), nil
	})
	var notices []string
	runner := New(Deps{
		Active:                selectedState("openrouter", "m", model.EffortDefault),
		Store:                 store,
		Client:                client,
		Retry:                 retryOn(),
		IgnoredProviders:      &IgnoredProviders{},
		ProviderIgnoredNotice: func(text string) { notices = append(notices, text) },
		Flush:                 storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %q, want one for the first exclusion only", notices)
	}
	if !slices.Equal(*slept, []time.Duration{0, 500 * time.Millisecond}) {
		t.Fatalf("backoff waits = %v, want [0 500ms] (immediate, then normal backoff)", *slept)
	}
	if len(*seen) != 3 || !slices.Equal((*seen)[1], []string{"together"}) || !slices.Equal((*seen)[2], []string{"together"}) {
		t.Fatalf("request ignore lists = %v, want together on calls 2 and 3", *seen)
	}
}

func TestToolLoop_IgnoredUpstreamKeptOnLaterRoundsAndTurns(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client, seen := ignoreRecordingClient(func(call int) (provider.Response, error) {
		switch call {
		case 1:
			return dropStream("", unavailableUpstream("Together", "provider_unavailable")), nil
		case 2:
			return provider.Response{Stream: newStream(toolCallChunk())}, nil
		default:
			return okStream("done"), nil
		}
	})
	deps := Deps{
		Active:           selectedState("openrouter", "m", model.EffortDefault),
		Store:            store,
		Client:           client,
		Retry:            retryOn(),
		IgnoredProviders: &IgnoredProviders{},
		RollbackPartial:  func() {},
		Flush:            storeFlush(store),
	}

	if err := NewToolLoop(deps, &fakeDispatcher{}, 3).Run(context.Background()); err != nil {
		t.Fatalf("ToolLoop.Run() error = %v, want nil", err)
	}
	if err := New(deps).Run(context.Background()); err != nil {
		t.Fatalf("later Run() error = %v, want nil", err)
	}
	if len(*seen) != 4 || len((*seen)[0]) != 0 {
		t.Fatalf("request ignore lists = %v, want 4 calls starting empty", *seen)
	}
	for i, list := range (*seen)[1:] {
		if !slices.Equal(list, []string{"together"}) {
			t.Fatalf("call %d ignore list = %v, want [together]", i+2, list)
		}
	}
}

func TestRun_UnrecognizedFailuresKeepNormalRetry(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		err      error
	}{
		{"non-openrouter provider", "openai", unavailableUpstream("Together", "provider_unavailable")},
		{"other openrouter error type", "openrouter", unavailableUpstream("Together", "provider_error")},
		{"multi-word upstream name", "openrouter", unavailableUpstream("Google AI Studio", "provider_unavailable")},
		{"plain stream drop", "openrouter", io.ErrUnexpectedEOF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slept := noSleep(t)
			store := storeAt(t.TempDir() + "/session.json")
			client, seen := ignoreRecordingClient(func(call int) (provider.Response, error) {
				if call == 1 {
					return dropStream("", tc.err), nil
				}
				return okStream("ok"), nil
			})
			ignored := &IgnoredProviders{}
			var notices int
			runner := New(Deps{
				Active:                selectedState(tc.provider, "m", model.EffortDefault),
				Store:                 store,
				Client:                client,
				Retry:                 retryOn(),
				IgnoredProviders:      ignored,
				ProviderIgnoredNotice: func(string) { notices++ },
				Flush:                 storeFlush(store),
			})

			if err := runner.Run(context.Background()); err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}
			if notices != 0 || len(ignored.List()) != 0 {
				t.Fatalf("notices = %d, ignored = %v, want none", notices, ignored.List())
			}
			if !slices.Equal(*slept, []time.Duration{250 * time.Millisecond}) {
				t.Fatalf("backoff waits = %v, want [250ms] normal backoff", *slept)
			}
			if len(*seen) != 2 || len((*seen)[0]) != 0 || len((*seen)[1]) != 0 {
				t.Fatalf("request ignore lists = %v, want all empty", *seen)
			}
		})
	}
}

func TestRun_RetryDisabledStillIgnoresUpstreamBeforeFailure(t *testing.T) {
	noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	client := steppedClient(func(int) (provider.Response, error) {
		return dropStream("", unavailableUpstream("Together", "provider_unavailable")), nil
	})
	ignored := &IgnoredProviders{}
	var order []string
	runner := New(Deps{
		Active:                selectedState("openrouter", "m", model.EffortDefault),
		Store:                 store,
		Client:                client,
		Retry:                 RetryPolicy{Enabled: false},
		IgnoredProviders:      ignored,
		ProviderIgnoredNotice: func(text string) { order = append(order, text) },
		Notice:                func(text string) { order = append(order, "failure: "+text) },
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error with retry disabled")
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1", client.callCount())
	}
	if !slices.Equal(ignored.List(), []string{"together"}) {
		t.Fatalf("ignored = %v, want [together]", ignored.List())
	}
	if len(order) != 2 || order[0] != togetherNotice || !strings.HasPrefix(order[1], "failure: ") {
		t.Fatalf("notice order = %q, want the exclusion notice before the failure notice", order)
	}
	skipped := findProviderRequestRetrySkipped(t, store.Records())
	if len(skipped) != 1 || skipped[0].SkipReason != "retry_disabled" {
		t.Fatalf("provider_request_retry_skipped = %+v, want one retry_disabled", skipped)
	}
}

func TestRun_NewlyIgnoredUpstreamRetriesCountTowardMaxAttempts(t *testing.T) {
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	names := []string{"Together", "DeepInfra"}
	client, seen := ignoreRecordingClient(func(call int) (provider.Response, error) {
		return dropStream("", unavailableUpstream(names[call-1], "provider_unavailable")), nil
	})
	ignored := &IgnoredProviders{}
	var notices int
	runner := New(Deps{
		Active:                selectedState("openrouter", "m", model.EffortDefault),
		Store:                 store,
		Client:                client,
		Retry:                 RetryPolicy{Enabled: true, MaxAttempts: 2, BaseDelay: 500 * time.Millisecond, MaxDelay: 8 * time.Second},
		IgnoredProviders:      ignored,
		ProviderIgnoredNotice: func(string) { notices++ },
		Flush:                 storeFlush(store),
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the drop error at the attempt cap")
	}
	if client.callCount() != 2 || notices != 2 {
		t.Fatalf("provider calls = %d, notices = %d, want 2 and 2", client.callCount(), notices)
	}
	if !slices.Equal(*slept, []time.Duration{0}) {
		t.Fatalf("backoff waits = %v, want [0]", *slept)
	}
	if !slices.Equal((*seen)[1], []string{"together"}) {
		t.Fatalf("second request ignore list = %v, want [together]", (*seen)[1])
	}
	if !slices.Equal(ignored.List(), []string{"together", "deepinfra"}) {
		t.Fatalf("ignored = %v, want [together deepinfra]", ignored.List())
	}
	skipped := findProviderRequestRetrySkipped(t, store.Records())
	if len(skipped) != 1 || skipped[0].SkipReason != "max_attempts_reached" {
		t.Fatalf("provider_request_retry_skipped = %+v, want one max_attempts_reached", skipped)
	}
}

func TestRun_RoutingExhaustionSurfacesOnceWithFilters(t *testing.T) {
	const body = `{"error":{"message":"No endpoints found that satisfy the max price for this request","code":404,"metadata":{"routing_funnel":[{"step":"Initial Endpoints","endpoint_count":1}],"failed_routing_step":"Filter by Max Price"}}}`
	const want = "provider openrouter returned HTTP 404: No endpoints found that satisfy the max price for this request (model inception/mercury-2.5; filters sent: max_price prompt 0.02 completion 0.075). Change provider.openrouter.routing to let a provider through."
	slept := noSleep(t)
	store := storeAt(t.TempDir() + "/session.json")
	httpErr := &provider.HTTPError{Status: 404, Body: body, Surface: "provider openrouter returned HTTP 404: " + body}
	routingErr := &provider.RoutingExhaustionError{
		Model:    "inception/mercury-2.5",
		MaxPrice: provider.MaxPrice{Prompt: 0.02, Completion: 0.075, HasPrompt: true, HasCompletion: true},
		HTTP:     httpErr,
	}
	client, seen := ignoreRecordingClient(func(int) (provider.Response, error) {
		return provider.Response{}, routingErr
	})
	ignored := &IgnoredProviders{}
	var notices []string
	var backoffs int
	runner := New(Deps{
		Active:                selectedState("openrouter", "inception/mercury-2.5", model.EffortDefault),
		Store:                 store,
		Client:                client,
		Retry:                 retryOn(),
		IgnoredProviders:      ignored,
		Notice:                func(text string) { notices = append(notices, text) },
		ProviderIgnoredNotice: func(text string) { notices = append(notices, text) },
		RetryBackoff:          func(int, int) { backoffs++ },
		Flush:                 storeFlush(store),
	})

	if err := runner.Run(context.Background()); !errors.Is(err, httpErr) {
		t.Fatalf("Run() error = %v, want the routing-exhaustion HTTP 404", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("provider calls = %d, want 1", len(*seen))
	}
	if len(*slept) != 0 || backoffs != 0 {
		t.Fatalf("backoff waits = %v, RetryBackoff calls = %d, want none", *slept, backoffs)
	}
	if len(ignored.List()) != 0 {
		t.Fatalf("ignored = %v, want empty", ignored.List())
	}
	if !slices.Equal(notices, []string{want}) {
		t.Fatalf("notices = %q, want exactly %q", notices, want)
	}
	recs := diskRecords(t, store)
	if hasKind(recs, "provider_request_retry") || hasKind(recs, "provider_request_retry_skipped") {
		t.Fatalf("retry event emitted for routing exhaustion; kinds = %v", eventKinds(recs))
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "http" || prf.Reason != "http_error" || prf.ErrorDetail != body || prf.HTTPStatus == nil || *prf.HTTPStatus != 404 {
		t.Fatalf("provider_request_failed = %+v, want http/http_error with the raw body and status 404", prf)
	}
}

func kindCount(recs []sessions.Record, kind string) int {
	n := 0
	for _, k := range eventKinds(recs) {
		if k == kind {
			n++
		}
	}
	return n
}

func assertBlankAttemptRecords(t *testing.T, recs []sessions.Record, attempts int, recovered bool, retryKind string) {
	t.Helper()
	if rounds := providerRoundTripEvents(t, recs); len(rounds) != attempts {
		t.Fatalf("provider_round_trip = %d, want %d (one per attempt); kinds = %v", len(rounds), attempts, eventKinds(recs))
	}
	terminals := turnTerminalEvents(t, recs)
	if len(terminals) != attempts {
		t.Fatalf("turn_terminal = %d, want %d (one per attempt); kinds = %v", len(terminals), attempts, eventKinds(recs))
	}
	failed := terminals
	if recovered {
		failed = terminals[:attempts-1]
		if last := terminals[attempts-1]; last.Outcome != events.TurnOutcomeCompleted {
			t.Fatalf("recovered attempt terminal = %+v, want completed", last)
		}
	}
	for i, term := range failed {
		if term.Outcome != events.TurnOutcomeProviderFailed || term.FailurePhase != "empty_response" || term.DispatchStarted {
			t.Fatalf("terminal[%d] = %+v, want provider_failed/empty_response with no dispatch", i, term)
		}
	}
	round, terminal, retry := kindIndex(recs, events.KindProviderRoundTrip), kindIndex(recs, events.KindTurnTerminal), kindIndex(recs, retryKind)
	if round < 0 || terminal < round || retry < terminal {
		t.Fatalf("record order (round=%d, terminal=%d, %s=%d), want timing, then terminal, then %s; kinds = %v",
			round, terminal, retryKind, retry, retryKind, eventKinds(recs))
	}
}

func TestToolLoop_BlankSuggestOnlyRoundRetriesBeforeFailure(t *testing.T) {
	textCall := `{"name":"suggest_followup","arguments":` + suggestArgs + `}`
	for _, tc := range []struct {
		name      string
		round     [][]byte
		rollbacks int
	}{
		{"structured empty", [][]byte{toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), usageChunk(100, 10)}, 0},
		{"structured whitespace", [][]byte{contentChunk(" \n\t"), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), usageChunk(100, 10)}, 1},
		{"parsed text", [][]byte{contentChunk(textCall), finishChunk("stop"), usageChunk(100, 10)}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noSleep(t)
			store := storeAt(t.TempDir() + "/session.json")
			store.Append(textMsg("user", "summarize"))
			client := &scriptedClient{rounds: [][][]byte{tc.round, {contentChunk("done"), finishChunk("stop"), usageChunk(200, 20)}}}
			var suggests, rollbacks int
			var notices []string
			loop := NewToolLoop(Deps{
				Active:          selectedState("openai", "gpt-x", model.EffortDefault),
				Store:           store,
				Client:          client,
				Retry:           retryOn(),
				SuggestFollowup: func(string, string) { suggests++ },
				Notice:          func(text string) { notices = append(notices, text) },
				RollbackPartial: func() { rollbacks++ },
				Flush:           storeFlush(store),
			}, &fakeDispatcher{}, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("ToolLoop.Run() error = %v, want nil (the re-issued round answered)", err)
			}
			if client.callCount() != 2 {
				t.Fatalf("provider calls = %d, want 2", client.callCount())
			}
			if suggests != 0 || len(notices) != 0 {
				t.Fatalf("suggestions = %d, notices = %q, want none from the rejected round", suggests, notices)
			}
			if rollbacks != tc.rollbacks {
				t.Fatalf("RollbackPartial calls = %d, want %d", rollbacks, tc.rollbacks)
			}
			recs := diskRecords(t, store)
			retries := findProviderRequestRetry(t, recs)
			if len(retries) != 1 || retries[0].Phase != "empty_response" || retries[0].Reason != "zero_delta_stream" ||
				retries[0].Attempt != 1 || retries[0].PartialCharsDiscarded != 0 {
				t.Fatalf("provider_request_retry = %+v, want one attempt-1 empty_response/zero_delta_stream with 0 discarded", retries)
			}
			if skipped := findProviderRequestRetrySkipped(t, recs); len(skipped) != 0 {
				t.Fatalf("provider_request_retry_skipped = %+v, want none", skipped)
			}
			if hasKind(recs, "provider_request_failed") {
				t.Fatalf("provider_request_failed recorded for a recovered turn; kinds = %v", eventKinds(recs))
			}
			assertBlankAttemptRecords(t, recs, 2, true, events.KindProviderRequestRetry)
			if n := kindCount(recs, "model_response"); n != 1 {
				t.Fatalf("model_response = %d, want 1", n)
			}
			if mr := decodeModelResponse(t, recs); mr.InputTokens != 300 || mr.OutputTokens != 30 {
				t.Fatalf("model_response tokens = (%d, %d), want both attempts' (300, 30)", mr.InputTokens, mr.OutputTokens)
			}
			if final := lastAssistantText(recs); final != "done" {
				t.Fatalf("assistant text = %q, want the re-issued answer", final)
			}
		})
	}
}

func TestToolLoop_BlankSuggestOnlyRoundExhaustedRecordsSkipBeforeFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		retry  RetryPolicy
		calls  int
		skip   string
		notice string
	}{
		{"max attempts", RetryPolicy{Enabled: true, MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Second}, 2, "max_attempts_reached", "retry 2: "},
		{"disabled", RetryPolicy{}, 1, "retry_disabled", "plain: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noSleep(t)
			store := storeAt(t.TempDir() + "/session.json")
			store.Append(textMsg("user", "summarize"))
			client := &scriptedClient{rounds: [][][]byte{{contentChunk("\n"), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), usageChunk(100, 10)}}}
			var suggests int
			var notices []string
			loop := NewToolLoop(Deps{
				Active:          selectedState("openai", "gpt-x", model.EffortDefault),
				Store:           store,
				Client:          client,
				Retry:           tc.retry,
				SuggestFollowup: func(string, string) { suggests++ },
				Notice:          func(text string) { notices = append(notices, text) },
				RenderNotice:    func(verbatim, _, _ string, _ int) string { return "plain: " + verbatim },
				RenderRetryNotice: func(verbatim, _, _ string, _, attempts int) string {
					return fmt.Sprintf("retry %d: %s", attempts, verbatim)
				},
				RollbackPartial: func() {},
				Flush:           storeFlush(store),
			}, &fakeDispatcher{}, 3)

			if err := loop.Run(context.Background()); err == nil {
				t.Fatal("ToolLoop.Run() error = nil, want the blank-round failure")
			}
			if client.callCount() != tc.calls {
				t.Fatalf("provider calls = %d, want %d", client.callCount(), tc.calls)
			}
			if suggests != 0 {
				t.Fatalf("suggestions = %d, want 0", suggests)
			}
			if len(notices) != 1 || !strings.HasPrefix(notices[0], tc.notice) {
				t.Fatalf("notices = %q, want one starting %q", notices, tc.notice)
			}
			recs := diskRecords(t, store)
			skipped := findProviderRequestRetrySkipped(t, recs)
			if len(skipped) != 1 || skipped[0].Phase != "empty_response" || skipped[0].SkipReason != tc.skip || skipped[0].PartialCharsDiscarded != 0 {
				t.Fatalf("provider_request_retry_skipped = %+v, want one empty_response %s", skipped, tc.skip)
			}
			if n := kindCount(recs, "provider_request_failed"); n != 1 {
				t.Fatalf("provider_request_failed = %d, want 1; kinds = %v", n, eventKinds(recs))
			}
			if prf := findProviderRequestFailed(t, recs); prf.Phase != "empty_response" || prf.Reason != "zero_delta_stream" {
				t.Fatalf("provider_request_failed = %+v, want empty_response/zero_delta_stream", prf)
			}
			if kindIndex(recs, events.KindProviderRequestRetrySkipped) > kindIndex(recs, "provider_request_failed") {
				t.Fatal("provider_request_retry_skipped must precede provider_request_failed")
			}
			assertBlankAttemptRecords(t, recs, tc.calls, false, events.KindProviderRequestRetrySkipped)
			if n := kindCount(recs, "model_response"); n != 1 {
				t.Fatalf("model_response = %d, want 1 accounting record", n)
			}
			if mr := decodeModelResponse(t, recs); mr.InputTokens != int64(100*tc.calls) || mr.OutputTokens != int64(10*tc.calls) {
				t.Fatalf("model_response tokens = (%d, %d), want every attempt's billed usage", mr.InputTokens, mr.OutputTokens)
			}
			if final := lastAssistantText(recs); final != "" {
				t.Fatalf("assistant text = %q, want none", final)
			}
		})
	}
}

func TestToolLoop_BlankFinalReplyRetriesAndKeepsUsage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		first     [][]byte
		rollbacks int
		retained  int
	}{
		{"whitespace", [][]byte{contentChunk("\n"), contentChunk(" \n"), finishChunk("stop"), usageChunk(100, 10)}, 1, 3},
		{"empty", [][]byte{finishChunk("stop"), usageChunk(100, 10)}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noSleep(t)
			store := storeAt(t.TempDir() + "/session.json")
			store.Append(textMsg("user", "hi"))
			client := &scriptedClient{rounds: [][][]byte{tc.first, {contentChunk("Hello"), finishChunk("stop"), usageChunk(200, 20)}}}
			var progress, rollbacks, retainedAtRollback, callsAtRollback, finalizes int
			loop := NewToolLoop(Deps{
				Active:   selectedState("openai", "gpt-x", model.EffortDefault),
				Store:    store,
				Client:   client,
				Retry:    retryOn(),
				Progress: func(n int) { progress = n },
				RollbackPartial: func() {
					rollbacks++
					retainedAtRollback, callsAtRollback = progress, client.callCount()
				},
				Finalize: func() { finalizes++ },
				Flush:    storeFlush(store),
			}, &fakeDispatcher{}, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("ToolLoop.Run() error = %v, want nil", err)
			}
			if client.callCount() != 2 {
				t.Fatalf("provider calls = %d, want 2", client.callCount())
			}
			if rollbacks != tc.rollbacks {
				t.Fatalf("RollbackPartial calls = %d, want %d", rollbacks, tc.rollbacks)
			}
			if tc.rollbacks > 0 && (retainedAtRollback != tc.retained || callsAtRollback != 1) {
				t.Fatalf("rollback saw retained=%d after %d calls, want %d before the re-issue", retainedAtRollback, callsAtRollback, tc.retained)
			}
			if finalizes != 1 {
				t.Fatalf("Finalize calls = %d, want 1 (only the recovered answer)", finalizes)
			}
			recs := diskRecords(t, store)
			retries := findProviderRequestRetry(t, recs)
			if len(retries) != 1 || retries[0].Phase != "empty_response" || retries[0].PartialCharsDiscarded != 0 {
				t.Fatalf("provider_request_retry = %+v, want one empty_response with 0 discarded", retries)
			}
			if hasKind(recs, "provider_request_failed") {
				t.Fatalf("provider_request_failed recorded for a recovered turn; kinds = %v", eventKinds(recs))
			}
			assertBlankAttemptRecords(t, recs, 2, true, events.KindProviderRequestRetry)
			var answers []string
			for _, rec := range recs {
				if msg, ok := rec.(sessions.Message); ok && msg.Role == "assistant" {
					answers = append(answers, msg.Content.Text())
				}
			}
			if !slices.Equal(answers, []string{"Hello"}) {
				t.Fatalf("assistant messages = %q, want only the recovered answer", answers)
			}
			if n := kindCount(recs, "model_response"); n != 1 {
				t.Fatalf("model_response = %d, want 1", n)
			}
			if mr := decodeModelResponse(t, recs); mr.InputTokens != 300 || mr.OutputTokens != 30 {
				t.Fatalf("model_response tokens = (%d, %d), want both attempts' (300, 30)", mr.InputTokens, mr.OutputTokens)
			}
		})
	}
}
