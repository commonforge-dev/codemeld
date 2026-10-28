// Bounded, classification-driven auto-retry of transient provider-round failures:
// the per-turn retry loop around a single provider round, the
// full-jitter exponential backoff and Retry-After honoring, and the injectable
// clock/sleep seams that keep backoff, budget, and cancellation testable without
// wall-clock sleeps. Handoff retries stop before dispatch begins, so completed
// tool dispatch is never replayed.
package turn

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
)

// defaultRetryBudget bounds the total wall-clock one turn may spend waiting out
// retry backoffs, so a continuously-flapping provider cannot hang the turn even
// within the attempt cap. It is applied in New when an enabled policy
// leaves Budget unset.
const defaultRetryBudget = 60 * time.Second

// RetryPolicy is the resolved auto-retry configuration for one turn. The
// zero value is disabled, so a Runner built without a policy behaves exactly as
// a no-retry runner. Production wiring fills it from the
// provider.retry settings block (config.Cache.ProviderRetry); MaxAttempts is the
// total number of attempts including the first.
type RetryPolicy struct {
	Enabled     bool
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Budget      time.Duration
}

type IgnoredProviders struct {
	mu    sync.Mutex
	slugs []string
}

func (s *IgnoredProviders) Add(slug string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.slugs, slug) {
		return false
	}
	s.slugs = append(s.slugs, slug)
	return true
}

func (s *IgnoredProviders) List() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.slugs)
}

// sleep waits d, returning early with ctx.Err() if the context is cancelled
// first, so an ESC/interrupt during backoff ends the turn promptly. It
// is a package seam (like now) so tests drive cancellation without wall-clock
// sleeps. A non-positive d still honors an already-cancelled context.
var sleep = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// randFloat returns a uniform value in [0,1) for full-jitter backoff. It is a
// seam so a test can pin the jitter to an extreme (0 or near 1) and assert the
// backoff bounds deterministically.
var randFloat = rand.Float64

// retrySignal is runAttempt's report of a classified provider-round failure whose
// terminal handling was deferred so Run's retry loop can choose between retrying
// and surfacing it. commit performs the deferred terminal handling — the same
// durable provider_request_failed emit, failure notice, and (for a stream_drop)
// partial seal the non-retry path runs inline — and is invoked when retries are
// exhausted, the budget is spent, or retry is disabled. err is the value Run
// returns for this failure.
type retrySignal struct {
	phase         string
	reason        string
	retryAfter    time.Duration // honored 429/503 Retry-After delay; meaningful only when hasRetryAfter
	hasRetryAfter bool          // a 429/503 Retry-After was present and parsed (overrides backoff even at 0)
	partialChars  int           // assistant runes retained before the failure, including held deltas
	isStreamDrop  bool
	err           error
	commit        func(attempts int)
}

// runWithRetry drives one provider turn under the retry policy. It runs an
// attempt and, on a classified retryable failure with attempts and budget
// remaining, records a durable provider_request_retry, rolls back any visible partial
// stream, waits an interruptible backoff, and re-issues the identical request. A
// terminal outcome (success, a tool-call handoff, a cancellation, or a
// non-retryable failure) returns immediately. On exhaustion, budget-out, or with
// retry disabled it commits the deferred failure surface and returns. Start-of-turn
// events were emitted once by Run before this loop, so they are not repeated per
// attempt.
func (r *Runner) runWithRetry(ctx context.Context, req provider.Request, sel model.Selection) error {
	p := r.deps.Retry
	// retryStart is captured lazily on the first retryable failure, not before the
	// loop, so a turn that succeeds (or fails non-retryably) on its first attempt
	// consumes no extra clock tick — keeping the provider_round_trip/turn_latency
	// timing seam unperturbed for the common no-retry case.
	var retryStart time.Time
	retries := 0
	for attempt := 1; ; attempt++ {
		req.IgnoredProviders = r.deps.IgnoredProviders.List()
		sig, err := r.runAttempt(ctx, req, sel)
		if sig == nil {
			// Terminal: success, tool-call handoff, cancellation, or a non-retryable
			// failure already surfaced inline by runAttempt.
			if err == nil && retries > 0 {
				r.deps.RetryRecovered(retries)
			}
			return err
		}
		newlyIgnored := false
		if slug, ok := provider.UnavailableUpstreamProvider(sel.Provider, sig.err); ok && r.deps.IgnoredProviders.Add(slug) {
			newlyIgnored = true
			r.deps.ProviderIgnoredNotice(fmt.Sprintf("Provider %s failing to respond. Removing for rest of this session", slug))
		}
		if retryStart.IsZero() {
			retryStart = now()
		}
		delay := retryDelay(p, attempt, sig.retryAfter, sig.hasRetryAfter)
		if newlyIgnored {
			delay = 0
		}
		budgetSpent := p.Budget > 0 && now().Sub(retryStart)+delay > p.Budget
		if !p.Enabled {
			// Retryable failure, but the policy is off: record why no retry followed
			// before committing the final provider_request_failed, so that event is never
			// the only trace of a retryable round.
			r.emitRetrySkipped(ctx, sel, attempt, "retry_disabled", sig)
			sig.commit(0)
			return err
		}
		if attempt >= p.MaxAttempts || budgetSpent {
			// This one branch is both the attempt cap and budget exhaustion. Prefer
			// max_attempts_reached when the cap is hit (the definitive terminal state),
			// so budget_exhausted only names a budget block that stopped a retry the
			// cap would still have allowed.
			skipReason := "max_attempts_reached"
			if budgetSpent && attempt < p.MaxAttempts {
				skipReason = "budget_exhausted"
			}
			r.emitRetrySkipped(ctx, sel, attempt, skipReason, sig)
			sig.commit(attempt)
			return err
		}
		// Durably record the scheduled retry before waiting, so a failed attempt is
		// recoverable even if the process exits during the backoff.
		r.emitRetry(ctx, sel, attempt, delay, sig)
		// Discard-and-restart: have the UI roll back the un-sealed partial before
		// re-issue (the UI owns the visible rollback; the seam is a no-op by default).
		if (sig.isStreamDrop || sig.phase == events.RetryPhaseToolHandoff || sig.phase == provider.EmptyStreamClassification().Phase) && sig.partialChars > 0 {
			r.deps.RollbackPartial()
		}
		nextAttempt := attempt + 1
		r.deps.RetryBackoff(nextAttempt, p.MaxAttempts)
		retries++
		if werr := sleep(ctx, delay); werr != nil {
			// ESC/interrupt during the wait ends the turn promptly and is not itself
			// retried; the cancellation, not the provider failure, is surfaced.
			return werr
		}
		r.deps.RetryResume()
	}
}

// emitRetry appends and flushes the provider_request_retry for one scheduled
// retry, routing a write failure through the same OnFailureWrite protocol the
// failure event uses. The write/flush error is ignored (like recordProviderRound):
// a missing observability event must not fail the turn, and the protocol already
// ran via OnFailureWrite.
func (r *Runner) emitRetry(ctx context.Context, sel model.Selection, attempt int, delay time.Duration, sig *retrySignal) {
	partial := int64(0)
	if sig.isStreamDrop {
		partial = int64(sig.partialChars)
	}
	_ = events.EmitProviderRequestRetry(ctx, r.deps.Store, sel.Provider, sel.ID,
		sig.phase, sig.reason, int64(attempt), delay.Milliseconds(), partial, r.deps.OnFailureWrite)
}

// emitRetrySkipped durably records why a classified retryable failure went terminal
// without a retry (retry_disabled / max_attempts_reached / budget_exhausted), so a
// final provider_request_failed is never the only trace of a retryable round. Like
// emitRetry it appends-then-flushes and ignores the write/flush error (a missing
// diagnostic must not fail the turn) and uses the stream_drop-only partial-char count.
// Provider failures leave their handler nil because sig.commit immediately emits
// provider_request_failed; handoff failures route the write failure because they have
// no following provider failure emit.
func (r *Runner) emitRetrySkipped(ctx context.Context, sel model.Selection, attempt int, skipReason string, sig *retrySignal) {
	partial := int64(0)
	if sig.isStreamDrop {
		partial = int64(sig.partialChars)
	}
	onWriteFailure := events.WriteFailureHandler(nil)
	if sig.phase == events.RetryPhaseToolHandoff {
		onWriteFailure = r.deps.OnFailureWrite
	}
	_ = events.EmitProviderRequestRetrySkipped(ctx, r.deps.Store, sel.Provider, sel.ID,
		sig.phase, sig.reason, skipReason, int64(attempt), partial, onWriteFailure)
}

// retryDelay picks the wait before re-issuing: a present Retry-After value (parsed
// onto the signal for a 429/503) overrides the computed backoff, capped at MaxDelay,
// and is honored even when it is 0 (an immediate retry that a provider can legitimately
// request via `Retry-After: 0` or a past HTTP-date); otherwise full-jitter exponential
// backoff for this 1-based attempt.
func retryDelay(p RetryPolicy, attempt int, retryAfter time.Duration, hasRetryAfter bool) time.Duration {
	if hasRetryAfter {
		if retryAfter > p.MaxDelay {
			return p.MaxDelay
		}
		if retryAfter < 0 {
			return 0
		}
		return retryAfter
	}
	return backoffDelay(p, attempt)
}

// backoffDelay returns the full-jitter exponential backoff for a 1-based attempt:
// a uniform random duration in [0, capDelay) where capDelay = min(base *
// 2^(attempt-1), maxDelay). Full jitter (rather than equal jitter) spreads
// concurrent retries widest, which matters when many turns retry a shared
// provider at once.
func backoffDelay(p RetryPolicy, attempt int) time.Duration {
	capDelay := p.BaseDelay
	for i := 1; i < attempt; i++ {
		capDelay *= 2
		if capDelay <= 0 || capDelay >= p.MaxDelay {
			capDelay = p.MaxDelay
			break
		}
	}
	if capDelay > p.MaxDelay {
		capDelay = p.MaxDelay
	}
	if capDelay <= 0 {
		return 0
	}
	return time.Duration(randFloat() * float64(capDelay))
}

// parseRetryAfter parses a Retry-After header value as either delta-seconds or an
// HTTP-date, returning the wait from refTime and whether it was understood. A
// negative or already-past value clamps to 0 (retry without extra delay); an
// unparseable value reports false so the caller falls back to computed backoff.
func parseRetryAfter(v string, refTime time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, true
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(refTime)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}
