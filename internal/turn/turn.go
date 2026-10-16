// Package turn runs a single cancellable streamed provider turn: it turns a
// submitted prompt into a streamed model reply, emits the turn
// events, records the assistant message, and exposes a cancel handle. Its
// collaborators (provider client, delta sink, flush hooks, tool-call hook)
// are injected so the package stays free of internal/tui and
// internal/bootstrap (no import cycle); bootstrap wires the production bindings.
package turn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

// ErrNoModelSelected is returned by Run when no model is selected: the turn is
// refused before any provider request or turn event is issued.
var ErrNoModelSelected = errors.New("turn: no model selected; refuse the turn")

// now is a test seam for the latency clock so a test can drive turn_latency /
// provider_round_trip durations deterministically; production reads the wall
// clock. It is deliberately separate from the millisecond-truncated UTC stamp
// events.Append mints for each record — this measures elapsed time, not record
// order.
var now = func() time.Time { return time.Now() }

// streamIdleThreshold is how long a provider round waits for the next stream chunk
// before recording one provider_stream_idle diagnostic for the round.
var streamIdleThreshold = 30 * time.Second

// idleTimer is a package seam for the idle-crossing signal: production waits
// streamIdleThreshold on a real timer; a test replaces it to fire the crossing the
// moment a read is known blocked, with no wall-clock wait.
var idleTimer = func() (<-chan time.Time, func()) {
	t := time.NewTimer(streamIdleThreshold)
	return t.C, func() { t.Stop() }
}

// beforeIdleEmit is a test seam invoked in the idle branch immediately before the
// synchronized cancellation recheck, so a test can inject a Runner.Cancel at the last
// moment and prove the recheck still suppresses the diagnostic. No-op in production.
var beforeIdleEmit = func() {}

// duringIdleEmit is a test seam invoked while r.mu is still held, immediately after the
// durable idle event has been appended and flushed, so a test can prove Runner.Cancel
// cannot complete before that committed emit releases the lock. No-op in production.
var duringIdleEmit = func() {}

// StreamIdleInfo is the live idle-crossing payload delivered to OnProviderStreamIdle.
// It mirrors the durable provider_stream_idle event but is handed over in-process so a
// consumer can react without reading events back.
type StreamIdleInfo struct {
	Provider       string
	ModelID        string
	RoundElapsedMs int64
	IdleMs         int64
	PartialChars   int64
}

// FinalFlushError wraps a flush failure after the provider stream already
// completed and model_response was appended. Callers can distinguish it from
// provider/stream errors when deciding whether the visible stream should be sealed.
type FinalFlushError struct{ Err error }

func (e *FinalFlushError) Error() string { return "turn: final response flush: " + e.Err.Error() }

func (e *FinalFlushError) Unwrap() error { return e.Err }

// Sink receives each assistant content delta as it streams in, in arrival order.
// The production binding pipes it to the transcript via App.AppendStreamDelta.
type Sink func(delta string)

// FlushHook makes turn records durable at boundaries. The production
// binding flushes the real session store and routes atomic-write failures through
// the per-turn write-failure protocol.
type FlushHook func() error

// ToolCallHandoff carries the completed-turn data a tool-call hook needs to take
// over agentic iteration. AssistantText is the streamed assistant content
// so far; ToolCallDeltas are the raw per-chunk tool_call fragments collected in
// arrival order. Assembling and executing them is the tool-call hook's job.
type ToolCallHandoff struct {
	AssistantText    string
	ToolCallDeltas   [][]openai.ChatCompletionChunkChoiceDeltaToolCall
	Report           *RoundReport
	UpstreamProvider string
}

type RoundReport struct {
	Outcome         string
	FailurePhase    string
	FailedTool      string
	FailureReason   string
	DispatchStarted bool
}

func (h ToolCallHandoff) report() *RoundReport {
	if h.Report == nil {
		return &RoundReport{}
	}
	return h.Report
}

// ToolCallHook intercepts a completed turn whose response requested tool calls so
// the agentic loop can iterate without rewriting the stream loop. The default is a no-op.
type ToolCallHook func(ctx context.Context, h ToolCallHandoff) error

// Deps gathers the injected collaborators for one provider turn. Active, Store,
// and Client are required; the remaining hooks default to no-ops when nil
// (RenderNotice to an identity renderer), so a test opts in only to the behavior
// it asserts. Sink, Flush, FlushUnsupported, and OnToolCalls are the
// runtime hooks; Notice, RenderNotice, RenderRetryNotice, Interrupt, Finalize,
// OnFailureWrite, and the retry UX hooks are failure/status hooks that keep the
// package free of internal/tui and internal/bootstrap.
type Deps struct {
	Active           *model.ActiveState
	Store            *sessions.Store
	Client           provider.Client
	Sink             Sink
	Flush            FlushHook
	FlushUnsupported FlushHook
	OnToolCalls      ToolCallHook

	TurnID string

	// A nil SupportedEffort lookup exposes only no-reasoning.
	SupportedEffort func(providerID, modelID string) []string

	// SuggestFollowup routes an intercepted suggest_followup tool call to the
	// TUI: label is the short imperative shown as Tab-to-accept ghost text and prompt is
	// the text prefilled when the user accepts. The agentic loop fires it instead of
	// dispatching or persisting that call, so the suggestion is purely ephemeral UI state
	// and never reaches the session record or transcript. Optional and nil-safe: a
	// standalone Runner or a test that does not wire it simply drops the suggestion (the
	// call is still omitted from the records).
	SuggestFollowup func(label, prompt string)

	// OnToolActivity surfaces a tool-call round's about-to-run calls as live, inline
	// transcript lines, one formatted line per call in assembled order (see
	// ToolActivityLines). The agentic loop fires it once per tool-call round, after the
	// calls are assembled and before they are scheduled/dispatched, so the user sees what
	// is about to run — and a denied call still shows its line. It is derived purely from
	// the already-assembled calls, so it costs no extra provider tokens. Optional and
	// nil-safe: a standalone Runner or a test that does not wire it simply emits nothing.
	OnToolActivity func(lines []string)
	// SealPartial commits a buffered pre-tool reply that OnToolActivity left unsealed. The loop
	// calls it after dispatch unless the time limit cancelled the round, which rolls it back.
	SealPartial func()

	OnEditPatch func(patch string)

	// Progress reports the cumulative retained assistant-content rune count as the
	// reply streams — an approximate in-flight progress signal, not exact tokens
	// (stream usage only arrives in the final chunk). It remains a retained-rune
	// callback for tests and any other consumer, but production no longer feeds it to
	// the token indicator: that indicator is wired to exact per-round Usage only,
	// because retained runes routinely exceed the round's exact output tokens and feeding
	// them in would make the ↓ figure climb then drop (see Usage / UsageAcc). May be nil.
	// It is called in arrival order on the single stream goroutine, like Sink. In an
	// agentic turn ToolLoop wraps this so the reported count is cumulative across provider
	// rounds (prior rounds' retained chars plus the current round's), keeping the live
	// signal from shrinking when a fresh per-round Runner resets its own count to zero.
	Progress func(retainedChars int)
	// Usage reports the exact provider token usage as cumulative input/output totals,
	// feeding the in-flight indicator's exact figure. It fires once per
	// successful round under a ToolLoop and once total for a bare Runner: under a
	// ToolLoop (UsageAcc != nil) the loop owns emission and fires it after every round
	// with the running turn total, so the ↑ input figure reaches each completed round's
	// real prompt cost immediately rather than only at turn end; a bare Runner
	// (UsageAcc == nil) fires it once on the natural non-tool completion that records
	// model_response. May be nil; it is not called when no usage chunk arrived in any
	// round (an interrupted or usage-missing turn). The count it reports is the summed
	// turn total (see UsageAcc), so it stays consistent with /status.
	Usage func(inputTokens, outputTokens int64)

	// UsageAcc accumulates the exact stream usage of every provider round in one
	// agentic turn so the final model_response and the Usage indicator report the
	// summed turn total rather than only the last round. ToolLoop owns one
	// per turn and threads the same pointer through every round's Deps; a standalone
	// Runner (no tool-call iteration) leaves it nil and records only its own round.
	UsageAcc *model.UsageAccumulator

	// SubmitStart is the wall-clock instant the user's input for this turn was
	// accepted at the pre-turn boundary (sessionturn.Persister), threaded through
	// bootstrap so the final provider round can record one end-to-end turn_latency
	// event (user submit → final answer) for the whole agentic turn. The same
	// value is carried onto every round's Deps, but only the final no-tool answer
	// records it, so a multi-round turn yields exactly one turn_latency. The zero
	// value means "not wired" (a standalone Runner or a test that does not exercise
	// turn latency), in which case no turn_latency is recorded.
	SubmitStart time.Time

	// SystemPrompt is the assembled system message — the active mode's base prompt,
	// the environment block, and the loaded AGENTS.md instructions. The bootstrap turn
	// wiring assembles it per dispatch and passes a stable snapshot here, so every
	// provider round in one turn uses the same prompt while a later /mode switch is
	// reflected on the next turn. When non-empty it leads each provider request as a
	// single synthetic system message before the conversation history; empty adds no
	// message.
	SystemPrompt string

	// Tools is the turn's mode-filtered advertised tool set, assembled once by
	// the bootstrap turn wiring per dispatch from the snapshotted active mode and the
	// realized registry plus the product-authored `bash` definition. It is threaded
	// onto every provider round's request through BuildRequest, so the tool-call
	// continuation rounds advertise the same set as the initial round and a /mode switch
	// only affects the next user turn. Empty (the default) advertises no tools, so the
	// request omits the `tools`/`tool_choice` fields.
	Tools []provider.ToolDefinition

	// SuggestFollowupDebug gates the development-only suggest_followup trace: when
	// true the turn loop appends ordered suggest_followup_debug events (advertised /
	// no-call / tool-call-seen / intercepted) to Store so a developer can see how far a
	// suggestion got. Off by default (false), so a normal turn records none of them. It
	// is append-only and best-effort — a missing diagnostic never affects the turn.
	SuggestFollowupDebug bool
	// Mode is the active interaction-mode key (plan/build/auto_edits) for this turn,
	// stamped onto the suggest_followup debug events alongside the provider/model from Active. It is
	// captured by bootstrap at dispatch (the turn package has no mode concept) and is only
	// read when SuggestFollowupDebug is on; empty otherwise.
	Mode string

	// Notice reports a provider/turn request failure as user-facing text (the rendered
	// failure line — for an HTTP error the friendly message, optionally with
	// the remediation hint line). It is called only
	// from the provider-failure paths of Run. The production binding commits it
	// as an in-place transcript line tied to the turn (App.CommitProviderError,
	// marshaled through the tview queue so it is safe from the background turn
	// goroutine) rather than a bottom-pinned notice, so a stale provider error can no
	// longer re-render below a later turn. Session-write failures take the
	// OnFailureWrite path instead and stay on the transient notice surface.
	Notice     func(text string)
	ToolNotice func(text string)
	// RenderNotice renders a provider-failure notice: line 1 is the caller-supplied
	// message (for an HTTP error, the friendly line from FriendlyHTTPMessage;
	// for transport/body failures, the synthetic surface), with the remediation hint
	// appended as line 2 when the (phase, reason, httpStatus) tuple matches the hint
	// table. The production binding is tui.RenderProviderRequestFailedNotice; injecting
	// it keeps this package free of internal/tui while still using the TUI's hint logic.
	RenderNotice func(verbatim, phase, reason string, httpStatus int) string
	// RenderRetryNotice renders the terminal provider-failure notice after auto-retry
	// gives up, enriching the normal notice with the number of attempts that were made
	// while preserving the provider-specific hint behavior. The production binding is
	// tui.RenderProviderRequestFailedAfterAttemptsNotice. Nil defaults to the normal
	// renderer with a generic "failed after N attempts" prefix on line 1.
	RenderRetryNotice func(verbatim, phase, reason string, httpStatus, attempts int) string
	// Interrupt seals the in-progress transcript reply as interrupted. It is
	// called on a real mid-stream transport drop, and on a user interrupt only
	// when the reply was still a held text-tool-call candidate that never reached the
	// Sink — so the ESC/CTRL-C path's own seal found no open stream to close. On an
	// ordinary user interrupt whose content already streamed, that path seals the reply
	// itself and this hook is not called.
	Interrupt func()
	// Finalize commits a naturally completed reply into the transcript so the
	// next turn starts a fresh buffer. It is called only on a successful non-tool
	// stream, after the assistant message and model_response are recorded.
	Finalize func()
	// FinalizeErr reports a failure to deliver what Finalize committed.
	FinalizeErr func() error
	// OnFailureWrite routes a real atomic-write failure from the
	// provider_request_failed flush through the per-turn write-failure
	// protocol (sessionfailures.HandleWriteFailure). It may be nil.
	OnFailureWrite events.WriteFailureHandler

	// Retry is the auto-retry policy for the turn's provider rounds. The
	// zero value (Enabled false) is the no-retry behavior: every provider
	// failure surfaces once, exactly as before. New applies the per-turn budget
	// default when an enabled policy leaves it unset. Production threads it from the
	// provider.retry settings block via bootstrap.
	Retry RetryPolicy
	// RetryBackoff reports that the next retry attempt has been scheduled and the
	// retry loop is entering backoff. nextAttempt is 1-based and names the provider
	// attempt that will run after the wait; totalAttempts is Retry.MaxAttempts. The
	// TUI uses it for the transient "Reconnecting..." indicator. Optional and nil-safe.
	RetryBackoff func(nextAttempt, totalAttempts int)
	// RetryResume reports that backoff completed and the provider round is about to be
	// re-issued, so the TUI can return the activity indicator to its normal working
	// state. Optional and nil-safe.
	RetryResume func()
	// RetryRecovered reports that a provider round completed successfully after one or
	// more scheduled retries. retries is the number of retries that were actually
	// issued, not the total attempt count. Optional and nil-safe.
	RetryRecovered func(retries int)
	// RollbackPartial removes the un-sealed in-progress reply line before a
	// discard-and-restart retry of a partial provider round, so the
	// regenerated answer does not stack on the discarded partial. The backend calls
	// it; the UI owns the visible transcript rollback against this seam. Optional and
	// nil-safe: New defaults it to a no-op, so a standalone Runner or a turn whose
	// stream never partially drops is unaffected.
	RollbackPartial func()

	IgnoredProviders      *IgnoredProviders
	ProviderIgnoredNotice func(text string)

	// OnProviderStreamIdle reports that the active provider round's stream has gone
	// quiet — no chunk for streamIdleThreshold. It fires at most once per provider round,
	// on the turn goroutine, after the durable provider_stream_idle event has been
	// flushed. Optional and nil-safe: New defaults it to a no-op.
	OnProviderStreamIdle func(StreamIdleInfo)
	// OnProviderStreamActivity reports that a chunk arrived after an idle crossing. It
	// fires at most once per round and only after OnProviderStreamIdle. Optional and
	// nil-safe: New defaults it to a no-op.
	OnProviderStreamActivity func()

	OnUserMessageAdded func(text string, parts []sessions.ContentPart)

	finalAnswer func(ctx context.Context, text string) (intercepted bool, err error)
	acct        *turnAccounting
}

type turnAccounting struct {
	attempts int
	recorded bool
	upstream string
}

// Runner runs one streamed provider turn and exposes the cancel handle the
// landed tui.StreamCanceller needs. A Runner is single-use: create one per turn.
type Runner struct {
	deps Deps

	// mu guards the cancel handle's observable state so Cancel can race the
	// stream goroutine: cancel cancels the in-flight request context, inFlight is
	// true only while the stream is being consumed, and retained tracks the
	// assistant characters streamed so far.
	mu        sync.Mutex
	cancel    context.CancelFunc
	inFlight  bool
	retained  int
	cancelled bool
}

// New builds a Runner from deps, defaulting the optional hooks to no-ops.
func New(deps Deps) *Runner {
	if deps.TurnID == "" {
		deps.TurnID = ids.NewV7()
	}
	if deps.Sink == nil {
		deps.Sink = func(string) {}
	}
	if deps.Flush == nil {
		deps.Flush = func() error { return nil }
	}
	if deps.FlushUnsupported == nil {
		deps.FlushUnsupported = deps.Flush
	}
	if deps.SupportedEffort == nil {
		deps.SupportedEffort = provider.SupportedEffort
	}
	if deps.OnToolCalls == nil {
		deps.OnToolCalls = func(context.Context, ToolCallHandoff) error { return nil }
	}
	if deps.SuggestFollowup == nil {
		deps.SuggestFollowup = func(string, string) {}
	}
	if deps.Progress == nil {
		deps.Progress = func(int) {}
	}
	if deps.Usage == nil {
		deps.Usage = func(int64, int64) {}
	}
	if deps.Notice == nil {
		deps.Notice = func(string) {}
	}
	if deps.ToolNotice == nil {
		deps.ToolNotice = deps.Notice
	}
	if deps.RenderNotice == nil {
		deps.RenderNotice = func(verbatim, _, _ string, _ int) string { return verbatim }
	}
	if deps.RenderRetryNotice == nil {
		deps.RenderRetryNotice = func(verbatim, phase, reason string, httpStatus, attempts int) string {
			return deps.RenderNotice(failureAfterAttempts(verbatim, attempts), phase, reason, httpStatus)
		}
	}
	if deps.Interrupt == nil {
		deps.Interrupt = func() {}
	}
	if deps.Finalize == nil {
		deps.Finalize = func() {}
	}
	if deps.FinalizeErr == nil {
		deps.FinalizeErr = func() error { return nil }
	}
	if deps.RetryBackoff == nil {
		deps.RetryBackoff = func(int, int) {}
	}
	if deps.RetryResume == nil {
		deps.RetryResume = func() {}
	}
	if deps.RetryRecovered == nil {
		deps.RetryRecovered = func(int) {}
	}
	if deps.RollbackPartial == nil {
		deps.RollbackPartial = func() {}
	}
	if deps.ProviderIgnoredNotice == nil {
		deps.ProviderIgnoredNotice = func(string) {}
	}
	if deps.OnProviderStreamIdle == nil {
		deps.OnProviderStreamIdle = func(StreamIdleInfo) {}
	}
	if deps.OnProviderStreamActivity == nil {
		deps.OnProviderStreamActivity = func() {}
	}
	if deps.acct == nil {
		deps.acct = &turnAccounting{}
	}
	// An enabled retry policy with no explicit per-turn budget gets the default
	// ceiling, and a non-positive attempt cap is clamped to a single attempt so a
	// misconfigured policy never loops; a disabled policy is left untouched (it is
	// never consulted).
	if deps.Retry.Enabled {
		if deps.Retry.Budget <= 0 {
			deps.Retry.Budget = defaultRetryBudget
		}
		if deps.Retry.MaxAttempts < 1 {
			deps.Retry.MaxAttempts = 1
		}
	}
	return &Runner{deps: deps}
}

// Cancel cancels the in-flight provider request and reports the characters
// retained for the response so far plus whether a stream was actually in flight,
// matching the landed tui.StreamCanceller shape (the production wiring adapts it). It is safe to
// call from another goroutine and is idempotent: once the loop has observed
// cancellation or completion it returns inFlight=false and cancels nothing.
func (r *Runner) Cancel() (retainedChars int, inFlight bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	retainedChars, inFlight = r.retained, r.inFlight
	if r.inFlight && r.cancel != nil {
		r.cancelled = true
		r.cancel()
	}
	return retainedChars, inFlight
}

func (r *Runner) InFlight() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inFlight
}

func (r *Runner) retainedChars() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.retained
}

// Run executes the plain send→reply turn synchronously: build the request, emit
// the start-of-turn events once (filtering unsupported effort), and
// then drive one or more provider-round attempts under the retry policy
// (runWithRetry → runAttempt). A transient provider-round failure with attempts
// and budget remaining is auto-retried with bounded jittered backoff; a
// deterministic, user-actionable failure surfaces in one pass with no retry. The
// per-attempt failure routing and the natural-completion/tool-call paths
// are documented on runAttempt. It returns ErrNoModelSelected when no model is
// selected (no provider call), the flush-hook error when the post-unsupported flush
// fails (no provider call), and the provider/stream error (or nil) of the final
// attempt. No failure path emits model_response, and tool-call turns hand off to
// OnToolCalls.
func (r *Runner) Run(ctx context.Context) error {
	req, sel, source, ok := BuildRequest(r.deps.Active, r.deps.Store, r.deps.SystemPrompt, r.deps.Tools)
	if !ok {
		return ErrNoModelSelected
	}

	// Record whether this round's request advertised suggest_followup, the first
	// stage of the dev-debug trace. Off unless the gate is set (a no-op otherwise).
	suggestAdvertised := toolsAdvertiseSuggestFollowup(r.deps.Tools)
	appendSuggestFollowupDebug(r.deps, events.SuggestFollowupStageRequestBuilt, &suggestAdvertised, "", "")

	supported := r.deps.SupportedEffort(sel.Provider, sel.ID)
	effortToSend, dropped, err := model.EmitTurnStart(r.deps.Store, sel, source, supported)
	if err != nil {
		return err
	}
	req.Effort = effortToSend

	if dropped {
		// model_effort_unsupported must be durable before the provider
		// call. An unhandled flush failure aborts the turn so no request is sent
		// for an effort drop that was not made durable.
		err = r.deps.FlushUnsupported()
	} else {
		err = r.deps.Flush()
	}
	if err != nil {
		return err
	}

	// The start-of-turn events above (model_turn, model_effort_unsupported) are
	// emitted once per user turn; the retry loop re-issues only the provider round
	// itself, so they are not repeated per attempt.
	return r.runWithRetry(ctx, req, sel)
}

// deferOrCommit builds the retry signal for a classified provider-round failure
// when the retry taxonomy deems it retryable, leaving its terminal handling (commit) deferred
// to the retry loop; for a non-retryable classification it runs commit inline and
// returns a nil signal so the failure is surfaced in one pass with no
// retry. recordProviderRound must already have been called for this attempt by the
// caller (so every attempt records its own timing), and commit must not call it
// again.
func (r *Runner) deferOrCommit(class provider.Classification, retryAfter time.Duration, hasRetryAfter bool, partialChars int, isStreamDrop bool, err error, commit func(attempts int)) *retrySignal {
	if provider.Retryable(class) {
		return &retrySignal{
			phase:         class.Phase,
			reason:        class.Reason,
			retryAfter:    retryAfter,
			hasRetryAfter: hasRetryAfter,
			partialChars:  partialChars,
			isStreamDrop:  isStreamDrop,
			err:           err,
			commit:        commit,
		}
	}
	commit(0)
	return nil
}

func (r *Runner) renderFailureNotice(verbatim, phase, reason string, httpStatus, attempts int) string {
	if attempts > 0 {
		return r.deps.RenderRetryNotice(verbatim, phase, reason, httpStatus, attempts)
	}
	return r.deps.RenderNotice(verbatim, phase, reason, httpStatus)
}

func failureAfterAttempts(verbatim string, attempts int) string {
	word := "attempts"
	if attempts == 1 {
		word = "attempt"
	}
	return fmt.Sprintf("failed after %d %s: %s", attempts, word, verbatim)
}

// runAttempt issues and consumes one provider round and reports its outcome to
// runWithRetry. It returns (nil, err) for a terminal outcome — a natural
// completion, a tool-call handoff, a user cancellation, or a non-retryable failure
// already surfaced inline — and (signal, err) for a classified retryable-candidate
// failure whose durable emit/notice/seal it has deferred so the loop can choose to
// retry. Its streamed reply, held-buffer, tool-call, and usage state are all
// attempt-local, so a re-issue starts from a clean slate; the start-of-turn events
// were already emitted once by Run. The failure routing mirrors the no-retry Run:
//   - a non-2xx *provider.HTTPError surfaces the friendly notice and emits
//     provider_request_failed{http, http_error}; a 429/5xx is a retry candidate
//     (honoring any Retry-After), a 4xx surfaces immediately;
//   - a 2xx *provider.HTTPBodyError emits http_no_body/http_truncated and surfaces
//     immediately (never retried: its status is the 2xx that arrived);
//   - a pre-stream transport/TLS/decode failure emits provider_request_failed{dial|
//     tls|decode} and is a retry candidate per the retry taxonomy;
//   - a mid-stream transport drop emits provider_request_failed{stream_drop}, and
//     on retry discards the partial via RollbackPartial rather than sealing it;
//   - a clean zero-delta or non-streamed empty completion emits
//     provider_request_failed{empty_response} and is a retry candidate;
//   - natural completion records the assistant message and model_response; tool-call
//     turns hand off to OnToolCalls.
//
// A context.Canceled/DeadlineExceeded is never a retry candidate.
func (r *Runner) runAttempt(ctx context.Context, req provider.Request, sel model.Selection) (*retrySignal, error) {
	roundID := ids.NewV7()
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r.mu.Lock()
	r.cancel = cancel
	r.inFlight = true
	r.retained = 0
	r.cancelled = false
	r.mu.Unlock()
	streamActive := true
	clearStreamActive := func() {
		if !streamActive {
			return
		}
		r.mu.Lock()
		r.inFlight = false
		r.mu.Unlock()
		streamActive = false
	}
	defer clearStreamActive()

	var usage openai.CompletionUsage
	var usageValid bool
	var upstream string
	completed := false
	completeRound := func() {
		completed = true
		if r.deps.UsageAcc != nil {
			r.deps.UsageAcc.Add(usage, usageValid)
		}
		r.deps.acct.upstream = upstream
	}
	// Every issued attempt was billed, so a failed one still folds whatever usage it received.
	defer func() {
		if !completed && r.deps.UsageAcc != nil {
			r.deps.UsageAcc.Add(usage, usageValid)
		}
	}()
	r.deps.acct.attempts++
	// Start the provider-round clock just before the model call so
	// provider_round_trip covers the whole round — including full stream
	// consumption — to whichever terminal outcome it reaches.
	roundStart := now()
	resp, err := r.deps.Client.ChatCompletion(streamCtx, req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.Join(err, r.recordTerminal(ctx, roundID, events.TurnOutcomeCancelled, "", false))
		}
		// A non-2xx provider response is surfaced as a TUI notice
		// whose line 1 is the friendly message extracted from the body (not the raw
		// JSON). For a 4xx/5xx response whose body declares quota exhaustion, the
		// quota remediation hint is added; any other HTTP body adds no hint. Overriding the
		// earlier no-event rule for HTTP errors, body text is also persisted as
		// provider_request_failed{http, http_error} so it has a durable home once the
		// notice scrolls off. events.Append applies
		// the system-wide UTF-8 normalization before storage. The render path's
		// quota_exceeded hint reason stays separate from the event's http_error reason.
		// No model_response is emitted either way.
		var credErr *provider.CredentialUnavailableError
		var httpErr *provider.HTTPError
		var bodyErr *provider.HTTPBodyError
		if errors.As(err, &credErr) {
			// The selected provider has no usable credential (a missing/invalid/
			// expired OpenAI ChatGPT session or a failed token refresh). Surface the safe,
			// provider-named remediation as the failure notice and fail the turn without
			// switching providers. No provider_request_failed event: the reason set
			// has no auth phase and no request reached the network, so there is no transport
			// outcome to record (mirroring the ErrNoModelSelected no-event refusal). The hint
			// table is bypassed (empty phase/reason), so RenderNotice returns the message
			// verbatim. Never retried — there is no Classification.
			r.deps.Notice(r.deps.RenderNotice(credErr.Surface, "", "", 0))
			return nil, errors.Join(err, r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, "", false))
		}
		if errors.As(err, &httpErr) {
			phase, reason := "", ""
			if httpErr.Status >= 400 && httpErr.Status <= 599 && bodyDeclaresQuotaExhausted(httpErr.Body) {
				phase, reason = "http", "quota_exceeded"
			}
			// Line 1 of the notice is the friendly message extracted from the
			// body (error.metadata.raw / error.message), not httpErr.Surface's raw JSON.
			// The persisted error_detail receives the unaltered Body.
			friendly := provider.FriendlyHTTPMessage(sel.Provider, httpErr.Status, httpErr.Body)
			var routingErr *provider.RoutingExhaustionError
			if errors.As(err, &routingErr) {
				friendly = provider.FriendlyRoutingExhaustionMessage(sel.Provider, routingErr)
			}
			httpStatus := int64(httpErr.Status)
			// Pre-stream HTTP-error round: record its timing before the failure event so
			// both ride the EmitProviderRequestFailed flush, making the slow failure durable.
			r.recordProviderRound(sel, roundID, roundStart, "")
			emit := func(onWriteFailure events.WriteFailureHandler, attempts int) {
				r.deps.Notice(r.renderFailureNotice(friendly, phase, reason, httpErr.Status, attempts))
				// error_detail receives Body, not Surface, so codemeld's synthetic prefix is
				// not persisted. Append normalizes invalid UTF-8 before writing the event.
				// The flush routes write failures through OnFailureWrite.
				_ = events.EmitProviderRequestFailed(ctx, r.deps.Store, sel.Provider, sel.ID,
					"http", "http_error", httpErr.Body, &httpStatus, 0, onWriteFailure)
			}
			if terminalErr := r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, "http", false); terminalErr != nil {
				emit(nil, 0)
				return nil, errors.Join(err, terminalErr)
			}
			commit := func(attempts int) { emit(r.deps.OnFailureWrite, attempts) }
			// A 429/5xx is a transient retry candidate (honoring a 429/503's
			// Retry-After); a 4xx is deterministic and surfaces immediately. The event
			// reason stays http_error regardless of the render-path quota hint.
			class := provider.Classification{Phase: "http", Reason: "http_error", HTTPStatus: &httpStatus}
			var retryAfter time.Duration
			var hasRetryAfter bool
			if (httpErr.Status == 429 || httpErr.Status == 503) && httpErr.RetryAfter != "" {
				if d, ok := parseRetryAfter(httpErr.RetryAfter, now()); ok {
					retryAfter, hasRetryAfter = d, true
				}
			}
			return r.deferOrCommit(class, retryAfter, hasRetryAfter, 0, false, err, commit), err
		}
		if errors.As(err, &bodyErr) {
			// a 2xx response whose body is missing or truncated (distinct from
			// a non-2xx error status). On the non-streaming path the provider
			// client returns this directly; the streaming path surfaces the same shape
			// from the stream-error branch below. Never retried: the status is the 2xx
			// that arrived, outside the retry-status set.
			r.recordProviderRound(sel, roundID, roundStart, "")
			phase := r.emitHTTPBodyFailure(ctx, sel, bodyErr)
			return nil, errors.Join(err, r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, phase, false))
		}
		if class, ok := provider.ClassifyRequestError(err); ok {
			// a pre-stream transport/TLS/decode failure (dial, tls, or decode
			// phase per ClassifyRequestError) emits a durable provider_request_failed and
			// surfaces a provider-error-style notice with a synthetic reason.
			// ClassifyRequestError returns false for a context cancel/deadline (a user interrupt or the turn deadline,
			// which owns its own sealing) and for *HTTPError (handled above), so those
			// fall through unchanged. The event's flush routes write failures through
			// OnFailureWrite; no model_response is emitted. Dial and recoverable
			// TLS failures are retry candidates; a bad cert or decode error is not.
			r.recordProviderRound(sel, roundID, roundStart, "")
			httpStatus := 0
			if class.HTTPStatus != nil {
				httpStatus = int(*class.HTTPStatus)
			}
			surface := fmt.Sprintf("provider %s request to model %s failed (%s/%s): %s",
				sel.Provider, sel.ID, class.Phase, class.Reason, class.ErrorDetail)
			emit := func(onWriteFailure events.WriteFailureHandler, attempts int) {
				_ = events.EmitProviderRequestFailed(ctx, r.deps.Store, sel.Provider, sel.ID,
					class.Phase, class.Reason, class.ErrorDetail, class.HTTPStatus, class.PartialResponseChars, onWriteFailure)
				r.deps.Notice(r.renderFailureNotice(surface, class.Phase, class.Reason, httpStatus, attempts))
			}
			if terminalErr := r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, class.Phase, false); terminalErr != nil {
				emit(nil, 0)
				return nil, errors.Join(err, terminalErr)
			}
			commit := func(attempts int) { emit(r.deps.OnFailureWrite, attempts) }
			return r.deferOrCommit(class, 0, false, 0, false, err, commit), err
		}
		return nil, errors.Join(err, r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, "", false))
	}
	stream := resp.Stream
	if stream == nil {
		// BuildRequest always streams, so a non-nil Completion here is a
		// non-streamed response the streaming turn never asks for. Defensively
		// classify an empty one (no_choices/null_content) and emit the durable event
		// — making ClassifyEmptyCompletion reachable — while a completion that
		// does carry content is an invalid streaming-provider response. Neither path
		// emits a model_response.
		if resp.Completion != nil {
			if class, ok := provider.ClassifyEmptyCompletion(resp.Completion); ok {
				r.recordProviderRound(sel, roundID, roundStart, "")
				// Surface the one-line notice, like the streamed
				// empty_response branch below; empty_response carries no hint.
				surface := fmt.Sprintf("provider %s request to model %s failed (%s/%s): %s",
					sel.Provider, sel.ID, class.Phase, class.Reason, class.ErrorDetail)
				emit := func(onWriteFailure events.WriteFailureHandler, attempts int) {
					_ = events.EmitProviderRequestFailed(ctx, r.deps.Store, sel.Provider, sel.ID,
						class.Phase, class.Reason, class.ErrorDetail, class.HTTPStatus, class.PartialResponseChars, onWriteFailure)
					r.deps.Notice(r.renderFailureNotice(surface, class.Phase, class.Reason, 0, attempts))
				}
				if terminalErr := r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, class.Phase, false); terminalErr != nil {
					emit(nil, 0)
					return nil, terminalErr
				}
				commit := func(attempts int) { emit(r.deps.OnFailureWrite, attempts) }
				// An empty response is a transient retry candidate; the returned
				// error is nil (this path completes the turn without an error today).
				return r.deferOrCommit(class, 0, false, 0, false, nil, commit), nil
			}
			r.recordProviderRound(sel, roundID, roundStart, "")
			return nil, errors.Join(errors.New("turn: provider returned a non-streamed completion for a streaming request"), r.recordTerminal(ctx, roundID, events.TurnOutcomeInvalidResponse, "", false))
		}
		r.recordProviderRound(sel, roundID, roundStart, "")
		return nil, errors.Join(errors.New("turn: provider returned no stream for a streaming request"), r.recordTerminal(ctx, roundID, events.TurnOutcomeInvalidResponse, "", false))
	}

	var reply strings.Builder
	var finishReason string
	var toolCallDeltas [][]openai.ChatCompletionChunkChoiceDeltaToolCall

	// A small/open model can emit its whole reply as a text tool call — a bare JSON
	// object or one fenced block — instead of a structured call. Hold streamed content back
	// from the sink while the reply could still be such a call so its raw JSON is never
	// shown; flush the held deltas the instant the reply is proven ordinary prose, and on
	// every completion path that is not a parsed text tool call. heldFlushed marks that we
	// have committed to live streaming (the normal path): every later delta then goes
	// straight to the sink and flushHeld is a no-op.
	var held strings.Builder
	heldFlushed := false
	flushHeld := func() {
		if held.Len() > 0 {
			r.deps.Sink(held.String())
			held.Reset()
		}
		heldFlushed = true
	}

	// Detect a provider stream that goes quiet mid-round. The blocking stream.Next()
	// read runs on a helper goroutine so the idle timer can fire while the read is still
	// blocked; the diagnostic is emitted at most once per attempt. All store access stays
	// on this goroutine — the helper only reports the read result — so the durable emit
	// needs no cross-goroutine store synchronization, and stream.Current()/Err() are read
	// only after the helper's Next() returns.
	lastActivity := now()
	idleEmitted := false
	idlePending := false
	nextChunk := func() bool {
		ch := make(chan bool, 1)
		go func() { ch <- stream.Next() }()
		idleC, stopIdle := idleTimer()
		defer stopIdle()
		awaitRead := func() bool {
			ok := <-ch
			if idlePending && ok {
				idlePending = false
				r.deps.OnProviderStreamActivity()
			}
			return ok
		}
		for {
			select {
			case ok := <-ch:
				if idlePending && ok {
					idlePending = false
					r.deps.OnProviderStreamActivity()
				}
				return ok
			case <-streamCtx.Done():
				// Runner.Cancel raced the read: take the in-flight result via the
				// normal cancellation path, never emit a false idle diagnostic.
				return awaitRead()
			case <-idleC:
				if idleEmitted {
					continue
				}
				beforeIdleEmit()
				// select picks randomly among ready cases, so a read result or a
				// cancellation that is already ready could lose to the idle timer in the
				// outer select; take either first so a stream that is not actually quiet
				// never records a diagnostic.
				select {
				case ok := <-ch:
					if idlePending && ok {
						idlePending = false
						r.deps.OnProviderStreamActivity()
					}
					return ok
				case <-streamCtx.Done():
					return awaitRead()
				default:
				}
				// Recheck cancellation and perform the durable emit under the same lock
				// Runner.Cancel takes. Cancel marks r.cancelled before cancelling, so a
				// cancel that won the race sends us down the cancel path; otherwise the
				// event is appended and flushed here, inside the critical section, so Cancel
				// cannot complete before the diagnostic is persisted. The live hook fires
				// after the unlock so a consumer that re-enters Runner.Cancel cannot deadlock.
				r.mu.Lock()
				cancelled := r.cancelled
				var idleInfo StreamIdleInfo
				if !cancelled {
					idleEmitted = true
					idlePending = true
					idleInfo = r.emitStreamIdleDurable(ctx, sel, roundStart, lastActivity, utf8.RuneCountInString(reply.String()))
					duringIdleEmit()
				}
				r.mu.Unlock()
				if cancelled {
					return awaitRead()
				}
				r.deps.OnProviderStreamIdle(idleInfo)
			}
		}
	}

	for nextChunk() {
		lastActivity = now()
		chunk := stream.Current()
		// include_usage streams the totals on a final chunk whose choices array is
		// empty and whose usage object is populated; capture it independently of the
		// content choices below.
		if chunk.JSON.Usage.Valid() {
			usage = chunk.Usage
			usageValid = true
		}
		if upstream == "" && sel.Provider == "openrouter" {
			upstream = upstreamProvider(chunk)
		}
		for _, choice := range chunk.Choices {
			if delta := choice.Delta.Content; delta != "" {
				reply.WriteString(delta)
				r.mu.Lock()
				r.retained += utf8.RuneCountInString(delta)
				retained := r.retained
				r.mu.Unlock()
				// Stream live once flushed; until then hold the delta and flush the
				// moment the accumulated reply can no longer be a whole-message text tool call.
				if heldFlushed {
					r.deps.Sink(delta)
				} else {
					held.WriteString(delta)
					if !stillTextToolCallCandidate(reply.String()) {
						flushHeld()
					}
				}
				r.deps.Progress(retained)
			}
			if len(choice.Delta.ToolCalls) > 0 {
				toolCallDeltas = append(toolCallDeltas, choice.Delta.ToolCalls)
			}
			if choice.FinishReason != "" {
				finishReason = choice.FinishReason
			}
		}
	}
	if serr := stream.Err(); serr != nil {
		if errors.Is(serr, context.Canceled) || errors.Is(serr, context.DeadlineExceeded) {
			// A user interrupt (ESC/CTRL-C) or the turn deadline — not a
			// provider failure. The ESC path already sealed the transcript and
			// recorded stream_interrupted, so emit no provider_request_failed.
			//
			// When the cancel lands while the reply is still a held text-tool-call
			// candidate, none of it ever reached the Sink, so the ESC path's own
			// markInterrupted found no open stream and sealed nothing — leaving a
			// stream_interrupted record with content chars but no visible interrupted
			// content. Surface the held partial here and seal it as interrupted, on this
			// background goroutine (the flush/seal must not run on Cancel()'s key-handler
			// path). The already-streamed path (heldFlushed) is left untouched: its content
			// reached the Sink and the ESC path already sealed it.
			if !heldFlushed && held.Len() > 0 {
				flushHeld()
				r.deps.Interrupt()
			}
			// A cancellation is never a retry candidate: surface it as a
			// terminal outcome so the loop ends the turn.
			return nil, errors.Join(serr, r.recordTerminal(ctx, roundID, events.TurnOutcomeCancelled, "", false))
		}
		var bodyErr *provider.HTTPBodyError
		if errors.As(serr, &bodyErr) && reply.Len() == 0 {
			// the streaming 2xx body was absent or cut off before any
			// assistant-content delta. The provider client preserved the status line;
			// emit http_no_body/http_truncated, the same as the non-streaming path. A
			// cut-off *after* partial content falls through to stream_drop below so the
			// streamed characters are still counted. No model_response is emitted. Never
			// retried (2xx status, outside the retry set).
			r.recordProviderRound(sel, roundID, roundStart, upstream)
			phase := r.emitHTTPBodyFailure(ctx, sel, bodyErr)
			return nil, errors.Join(serr, r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, phase, false))
		}
		// a real mid-stream transport drop after partial assistant content.
		// Count the assistant characters streamed so far, classify via ClassifyStreamDrop, emit the
		// durable provider_request_failed{stream_drop}, and seal the partial reply as
		// interrupted. The event's own flush routes write failures through
		// OnFailureWrite; the drop error stays the turn's returned failure and no
		// model_response is emitted. When the drop arrived wrapped as an *HTTPBodyError
		// (a truncation that followed partial content), classify the original transport
		// error so its stream_eof/stream_read_error fidelity and detail are preserved.
		dropErr := serr
		if bodyErr != nil && bodyErr.Err != nil {
			dropErr = bodyErr.Err
		}
		partialChars := utf8.RuneCountInString(reply.String())
		class := provider.ClassifyStreamDrop(dropErr, int64(partialChars))
		r.recordProviderRound(sel, roundID, roundStart, upstream)
		httpStatus := 0
		if class.HTTPStatus != nil {
			httpStatus = int(*class.HTTPStatus)
		}
		surface := fmt.Sprintf("provider %s request to model %s failed (%s/%s): %s",
			sel.Provider, sel.ID, class.Phase, class.Reason, class.ErrorDetail)
		// On exhaustion (or with retry disabled) seal the partial and surface the
		// failure. On a retry this commit is NOT run: the loop
		// rolls back the partial via RollbackPartial and re-issues instead, so the
		// reply is never sealed-as-interrupted between attempts.
		emit := func(onWriteFailure events.WriteFailureHandler, attempts int) {
			_ = events.EmitProviderRequestFailed(ctx, r.deps.Store, sel.Provider, sel.ID,
				class.Phase, class.Reason, class.ErrorDetail, class.HTTPStatus, class.PartialResponseChars, onWriteFailure)
			// Surface whatever partial content streamed before the drop — it may have
			// been held as a text-tool-call candidate — so the sealed interrupted reply
			// reflects what the model produced, matching the pre-buffering behavior.
			flushHeld()
			r.deps.Interrupt()
			// Commit the failure as an in-place transcript line, the same synthetic
			// surface the pre-stream branches render. It is committed *after* Interrupt so
			// the error line lands after the sealed interrupted block, satisfying the
			// post-MarkStreamInterrupted ordering case.
			r.deps.Notice(r.renderFailureNotice(surface, class.Phase, class.Reason, httpStatus, attempts))
		}
		if terminalErr := r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, class.Phase, false); terminalErr != nil {
			emit(nil, 0)
			return nil, errors.Join(serr, terminalErr)
		}
		commit := func(attempts int) { emit(r.deps.OnFailureWrite, attempts) }
		// stream_drop is always a retry candidate (including a partial drop).
		return r.deferOrCommit(class, 0, false, partialChars, true, serr, commit), serr
	}
	clearStreamActive()

	// A stream can finish cleanly after the time limit cancelled its context; ToolLoop wraps
	// up instead of accepting its reply or dispatching its tool calls.
	if errors.Is(context.Cause(ctx), errTimeLimit) {
		return nil, errors.Join(context.Cause(ctx), r.recordTerminal(ctx, roundID, events.TurnOutcomeCancelled, "", false))
	}

	if finishReason == "tool_calls" || len(toolCallDeltas) > 0 {
		// Tool-call turns hand off to OnToolCalls; the default hook is a no-op, so this
		// runner records nothing for them and leaves the iteration to the hook. The
		// round's own exact usage is folded into the turn accumulator first, so the
		// final round's model_response sums every round and is not undercounted by the
		// tokens this intermediate round spent.
		// A structured tool-call round's assistant text is real content shown live
		// (and recorded below as AssistantText), so flush any held candidate before handoff.
		flushHeld()
		completeRound()
		// The round's terminal outcome is a tool-call handoff. Record its timing
		// and flush it durable now, before handing off — OnToolCalls can fail (tool
		// assembly, scheduling, or dispatch) and return before the next round's start
		// flush would have persisted the event, which would strand the timing of an
		// already-completed provider round in memory. This flush only persists the
		// observability event (the assistant tool-call record is appended later, inside
		// OnToolCalls), so a flush failure must not fail the turn: the error is ignored,
		// matching recordProviderRound. An agentic turn still records exactly one
		// provider_round_trip per provider round.
		r.recordProviderRound(sel, roundID, roundStart, upstream)
		_ = r.deps.Flush()
		return r.handOffToolCalls(ctx, roundID, ToolCallHandoff{
			AssistantText:    reply.String(),
			ToolCallDeltas:   toolCallDeltas,
			UpstreamProvider: upstream,
		})
	}

	// A small/open model can emit its tool call as assistant text — a JSON object,
	// optionally inside one code fence — instead of a structured tool call (see
	// docs/ibm-model-issues.md). When this turn produced no structured tool-call deltas
	// and did not finish as "tool_calls", try to parse the whole reply as such a call. On
	// success route it through the SAME OnToolCalls handoff the structured branch uses, so
	// it goes through assembleToolCalls → scheduler → dispatcher → the authorizer /
	// deny path with identical permission behavior, and the raw JSON is not also
	// committed as assistant text (AssistantText is left empty). Fold this round's usage
	// into the accumulator first, mirroring the structured branch. An empty reply
	// never parses as a call, so it still falls through to the empty_response branch below.
	// The candidate content was held back from the sink during streaming and is deliberately
	// NOT flushed here, so the raw JSON is never shown.
	if deltas, ok := parseTextToolCall(reply.String(), finishReason); ok {
		completeRound()
		// A whole-message text tool call is also a tool-call-handoff terminal
		// outcome — time the round and flush it durable before handing off, like the
		// structured branch, so a failing continuation cannot strand the timing event in
		// memory. The flush error is ignored for the same reason (see that branch).
		r.recordProviderRound(sel, roundID, roundStart, upstream)
		_ = r.deps.Flush()
		return r.handOffToolCalls(ctx, roundID, ToolCallHandoff{
			AssistantText:    "",
			ToolCallDeltas:   deltas,
			UpstreamProvider: upstream,
		})
	}

	// Not a structured or text tool call: any content held as a candidate is ordinary prose,
	// so flush it to the sink now — before the empty-response check and the normal commit —
	// so the transcript renders it and Finalize seals it. An empty reply held nothing,
	// so this is a no-op for the empty_response path below.
	flushHeld()

	if reply.Len() == 0 {
		// a stream that closed cleanly with zero assistant-content
		// deltas and no tool-call handoff is an empty_response failure. Emit the
		// durable event and surface the one-line failure notice (like the
		// sibling transport branches), but append no assistant message, emit no
		// model_response, and neither finalize nor interrupt the transcript — no
		// in-progress reply line was ever opened. RenderNotice yields line 1 only for
		// empty_response (no hint match). The event's flush routes write
		// failures through OnFailureWrite.
		class := provider.EmptyStreamClassification()
		r.recordProviderRound(sel, roundID, roundStart, upstream)
		// empty_response is never an HTTP phase, so httpStatus is irrelevant here
		// (ProviderHint returns no hint for empty_response regardless) — pass 0.
		surface := fmt.Sprintf("provider %s request to model %s failed (%s/%s): %s",
			sel.Provider, sel.ID, class.Phase, class.Reason, class.ErrorDetail)
		emit := func(onWriteFailure events.WriteFailureHandler, attempts int) {
			_ = events.EmitProviderRequestFailed(ctx, r.deps.Store, sel.Provider, sel.ID,
				class.Phase, class.Reason, class.ErrorDetail, class.HTTPStatus, class.PartialResponseChars, onWriteFailure)
			r.deps.Notice(r.renderFailureNotice(surface, class.Phase, class.Reason, 0, attempts))
		}
		if terminalErr := r.recordTerminal(ctx, roundID, events.TurnOutcomeProviderFailed, class.Phase, false); terminalErr != nil {
			emit(nil, 0)
			return nil, terminalErr
		}
		commit := func(attempts int) { emit(r.deps.OnFailureWrite, attempts) }
		// A zero-delta empty response is a transient retry candidate; the
		// returned error is nil (this path completes the turn without an error today).
		return r.deferOrCommit(class, 0, false, 0, false, nil, commit), nil
	}

	completeRound()
	if r.deps.finalAnswer != nil {
		intercepted, err := r.deps.finalAnswer(ctx, reply.String())
		if err != nil {
			r.recordProviderRound(sel, roundID, roundStart, upstream)
			return nil, errors.Join(err, r.recordTerminal(ctx, roundID, events.TurnOutcomeContinuationFailed, "", false))
		}
		if intercepted {
			r.recordProviderRound(sel, roundID, roundStart, upstream)
			appendSuggestFollowupDebug(r.deps, events.SuggestFollowupStageNoCall, nil, "", "")
			return nil, r.recordTerminal(ctx, roundID, events.TurnOutcomeCompleted, "", false)
		}
	}
	r.deps.Store.Append(sessions.Message{
		ID:        ids.NewV7(),
		Role:      "assistant",
		Content:   sessions.TextContent(reply.String()),
		Timestamp: time.Now().UTC(),
	})
	// The streaming request asks for include_usage, so a clean completion carries
	// an exact final usage chunk; record those real token counts when present and
	// fall back to usage_missing when the chunk was absent (e.g. an older provider
	// that ignores stream_options) rather than inventing counts. In
	// an agentic turn the prior tool-call rounds folded their usage into UsageAcc, so
	// the final round adds its own and records the summed turn total here — a
	// standalone Runner (nil UsageAcc) records only this single round.
	var inputTokens, outputTokens int64
	var cachedInput *int64
	var cachedPartial bool
	var anomalies []string
	var hadUsage bool
	if r.deps.UsageAcc != nil {
		inputTokens, outputTokens, cachedInput, cachedPartial, anomalies, hadUsage = r.deps.UsageAcc.Totals()
	} else {
		inputTokens, outputTokens, cachedInput, anomalies = model.UsageFromStreamUsage(usage, usageValid)
		hadUsage = usageValid
	}
	if err := model.EmitModelResponse(r.deps.Store, sel.Provider, sel.ID, inputTokens, outputTokens, cachedInput, cachedPartial, anomalies, upstream); err != nil {
		return nil, errors.Join(err, r.recordTerminal(ctx, roundID, events.TurnOutcomeContinuationFailed, "", false))
	}
	r.deps.acct.recorded = true
	if hadUsage && r.deps.UsageAcc == nil {
		// Feed the in-flight indicator the exact figure that just became the
		// model_response total, so what it last showed matches /status. Only
		// when a usage chunk arrived in some round: otherwise the indicator keeps its
		// streamed progress value, and the recorded usage_missing means /status counts
		// 0 for this turn. Gated to the bare-Runner path (UsageAcc == nil): under a
		// ToolLoop the loop owns Usage emission and fires it once per round after the
		// round returns, so calling it here too would double-fire on the final round.
		r.deps.Usage(inputTokens, outputTokens)
	}
	// The round's terminal outcome is the final answer. Record this round's
	// provider_round_trip and the whole turn's end-to-end turn_latency now, before the
	// final flush, so both are durable in the same write that persists model_response.
	// turn_latency is recorded only here, on the final no-tool answer, so an agentic
	// turn yields exactly one even though every round carries the same SubmitStart.
	r.recordProviderRound(sel, roundID, roundStart, upstream)
	r.recordTurnLatency(sel)
	// This round reached a final answer with no tool calls, so the model did not
	// call suggest_followup — the most common "missing suggestion" case. Record it so a
	// dev-debug trace distinguishes "model produced prose instead of calling the tool"
	// from "tool not advertised" or "intercepted".
	appendSuggestFollowupDebug(r.deps, events.SuggestFollowupStageNoCall, nil, "", "")
	// Seal the completed reply so the next streamed turn starts a fresh
	// transcript buffer (Step 7). Finalizing before the final flush keeps the reply
	// sealed even when the durability flush fails; FinalFlushError still tells the
	// caller the failure was durability, not provider/stream.
	r.deps.Finalize()
	if err := r.deps.Flush(); err != nil {
		terminalErr := events.EmitTurnTerminal(ctx, r.deps.Store, events.TurnTerminal{
			TurnID: r.deps.TurnID, RoundID: roundID, Outcome: events.TurnOutcomeContinuationFailed,
		}, nil)
		return nil, errors.Join(&FinalFlushError{Err: err}, terminalErr)
	}
	if err := r.deps.FinalizeErr(); err != nil {
		return nil, errors.Join(err, r.recordTerminal(ctx, roundID, events.TurnOutcomeContinuationFailed, "", false))
	}
	return nil, r.recordTerminal(ctx, roundID, events.TurnOutcomeCompleted, "", false)
}

func upstreamProvider(chunk openai.ChatCompletionChunk) string {
	var name *string
	if json.Unmarshal([]byte(chunk.JSON.ExtraFields["provider"].Raw()), &name) != nil || name == nil {
		return ""
	}
	return *name
}

func (r *Runner) handOffToolCalls(ctx context.Context, roundID string, h ToolCallHandoff) (*retrySignal, error) {
	report := &RoundReport{Outcome: events.TurnOutcomeCompleted}
	h.Report = report
	err := r.deps.OnToolCalls(ctx, h)
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		report.Outcome = events.TurnOutcomeCancelled
		report.FailurePhase = ""
		report.FailedTool, report.FailureReason = "", ""
	}
	if err != nil && report.Outcome == events.TurnOutcomeCompleted {
		report.Outcome = events.TurnOutcomeContinuationFailed
	}
	if terminalErr := r.emitTerminal(ctx, roundID, *report); terminalErr != nil {
		return nil, errors.Join(err, terminalErr)
	}
	if err == nil || report.DispatchStarted {
		return nil, err
	}
	reason, ok := handoffRetryReason(report.Outcome)
	if !ok {
		return nil, err
	}
	return &retrySignal{
		phase:        events.RetryPhaseToolHandoff,
		reason:       reason,
		partialChars: r.retainedChars(),
		err:          err,
		commit:       func(int) {},
	}, err
}

func handoffRetryReason(outcome string) (string, bool) {
	switch outcome {
	case events.TurnOutcomeToolAssemblyFailed:
		return events.RetryReasonAssemblyFailed, true
	case events.TurnOutcomeToolPlanInvalid:
		return events.RetryReasonInvalidPlan, true
	}
	return "", false
}

func (r *Runner) recordTerminal(ctx context.Context, roundID, outcome, failurePhase string, dispatchStarted bool) error {
	return r.emitTerminal(ctx, roundID, RoundReport{Outcome: outcome, FailurePhase: failurePhase, DispatchStarted: dispatchStarted})
}

func (r *Runner) emitTerminal(ctx context.Context, roundID string, report RoundReport) error {
	return events.EmitTurnTerminal(ctx, r.deps.Store, events.TurnTerminal{
		TurnID:          r.deps.TurnID,
		RoundID:         roundID,
		Outcome:         report.Outcome,
		FailurePhase:    report.FailurePhase,
		FailedTool:      report.FailedTool,
		FailureReason:   report.FailureReason,
		DispatchStarted: report.DispatchStarted,
	}, r.deps.OnFailureWrite)
}

// emitHTTPBodyFailure records the durable provider_request_failed event and
// surfaces the synthetic notice for a 2xx response whose body was missing or
// truncated. The provider client preserved the status line, so the reason is
// classified via the provider failure classifiers — http_no_body requires the
// status, http_truncated keeps it when present. Write failures route through
// OnFailureWrite; no model_response is emitted. It is shared by the pre-stream
// (non-streaming) and mid-stream (streaming) body-failure branches.
func (r *Runner) emitHTTPBodyFailure(ctx context.Context, sel model.Selection, bodyErr *provider.HTTPBodyError) string {
	class := provider.NoBodyHTTPFailure(int64(bodyErr.Status))
	if bodyErr.Truncated {
		status := int64(bodyErr.Status)
		class = provider.TruncatedHTTPFailure(&status)
	}
	_ = events.EmitProviderRequestFailed(ctx, r.deps.Store, sel.Provider, sel.ID,
		class.Phase, class.Reason, class.ErrorDetail, class.HTTPStatus, class.PartialResponseChars, r.deps.OnFailureWrite)
	surface := fmt.Sprintf("provider %s request to model %s failed (%s/%s): %s",
		sel.Provider, sel.ID, class.Phase, class.Reason, class.ErrorDetail)
	r.deps.Notice(r.deps.RenderNotice(surface, class.Phase, class.Reason, bodyErr.Status))
	return class.Phase
}

// emitStreamIdleDurable records one durable provider_stream_idle event for a stalled
// provider round and returns the payload the caller passes to the live idle hook. It must
// be called with r.mu held: the append+flush is thereby serialized against Runner.Cancel,
// so a cancel racing the idle timer cannot complete before the diagnostic is persisted.
// The event is flushed when emitted so a stall that never resolves still leaves the
// diagnostic on disk; a write/flush failure routes through OnFailureWrite and is otherwise
// ignored here, so a missing diagnostic never cancels or fails the turn. round and
// lastActivity are measured with the now seam and clamped non-negative by elapsedMs. The
// caller fires the live hook only after releasing the lock, so a consumer woken by the
// hook can already read the persisted event back and cannot deadlock by re-entering Cancel.
func (r *Runner) emitStreamIdleDurable(ctx context.Context, sel model.Selection, round, lastActivity time.Time, partialChars int) StreamIdleInfo {
	roundElapsed := elapsedMs(round)
	idleMs := elapsedMs(lastActivity)
	_ = events.EmitProviderStreamIdle(ctx, r.deps.Store, sel.Provider, sel.ID,
		roundElapsed, idleMs, int64(partialChars), r.deps.OnFailureWrite)
	return StreamIdleInfo{
		Provider:       sel.Provider,
		ModelID:        sel.ID,
		RoundElapsedMs: roundElapsed,
		IdleMs:         idleMs,
		PartialChars:   int64(partialChars),
	}
}

// recordProviderRound appends a provider_round_trip event timing the round that
// began at start to its terminal outcome. It appends only — never flushing
// — so it rides the flush the terminal outcome already performs: a failure path's
// EmitProviderRequestFailed flush, the next round's start flush after a tool-call
// handoff, or the final answer's flush. The duration is clamped non-negative so a
// backward clock adjustment cannot produce a payload the validator would reject.
// An append error (only possible on a nil store/payload, neither of which occurs
// here) is ignored: a missing observability event must not fail the turn.
func (r *Runner) recordProviderRound(sel model.Selection, roundID string, start time.Time, upstream string) {
	_, _ = events.Append(r.deps.Store, events.ProviderRoundTrip{
		Provider:         sel.Provider,
		ModelID:          sel.ID,
		DurationMs:       elapsedMs(start),
		TurnID:           r.deps.TurnID,
		RoundID:          roundID,
		UpstreamProvider: upstream,
	})
}

// recordTurnLatency appends one turn_latency event for a completed turn, measured
// from the submit-start threaded onto Deps to now. It is a no-op when
// SubmitStart is unset (a standalone Runner or a test not exercising turn
// latency), so only a production turn carrying the pre-turn boundary records it.
// Like recordProviderRound it appends only and ignores the (practically
// impossible) append error.
func (r *Runner) recordTurnLatency(sel model.Selection) {
	if r.deps.SubmitStart.IsZero() {
		return
	}
	_, _ = events.Append(r.deps.Store, events.TurnLatency{
		Provider:   sel.Provider,
		ModelID:    sel.ID,
		DurationMs: elapsedMs(r.deps.SubmitStart),
	})
}

// elapsedMs returns the milliseconds from start to now, clamped to >= 0 so a
// backward wall-clock adjustment (or a test seam returning an earlier time)
// cannot yield a negative duration_ms, which the payload validator rejects.
func elapsedMs(start time.Time) int64 {
	ms := now().Sub(start).Milliseconds()
	if ms < 0 {
		return 0
	}
	return ms
}

// bodyDeclaresQuotaExhausted reports whether an HTTP-error body clearly states the
// provider account's quota is exhausted. It is deliberately conservative — there is
// no landed quota classifier — matching only a JSON code field with the canonical
// OpenAI insufficient_quota value and unnegated contiguous "quota exceeded/exhausted"
// wording. This keeps incidental or negated mentions one-line (only an
// unambiguous exhaustion body gets the quota hint).
func bodyDeclaresQuotaExhausted(body string) bool {
	b := strings.ToLower(body)
	if jsonCodeEquals(body, "insufficient_quota") {
		return true
	}
	for _, phrase := range []string{
		"exceeded your current quota",
		"quota exceeded",
		"quota exhausted",
	} {
		if containsUnnegatedPhrase(b, phrase) {
			return true
		}
	}
	return false
}

func jsonCodeEquals(body, want string) bool {
	var data any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return false
	}
	return jsonCodeEqualsValue(data, want)
}

func jsonCodeEqualsValue(v any, want string) bool {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if strings.EqualFold(key, "code") {
				if s, ok := value.(string); ok && strings.EqualFold(s, want) {
					return true
				}
			}
			if jsonCodeEqualsValue(value, want) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if jsonCodeEqualsValue(value, want) {
				return true
			}
		}
	}
	return false
}

func containsUnnegatedPhrase(body, phrase string) bool {
	for offset := 0; ; {
		idx := strings.Index(body[offset:], phrase)
		if idx < 0 {
			return false
		}
		idx += offset
		end := idx + len(phrase)
		if phraseDelimited(body, idx, end) && !negatedImmediatelyBefore(body[:idx]) {
			return true
		}
		offset = idx + 1
	}
}

func phraseDelimited(body string, start, end int) bool {
	if start > 0 && quotaTokenChar(body[start-1]) {
		return false
	}
	if end < len(body) && quotaTokenChar(body[end]) {
		return false
	}
	return true
}

func quotaTokenChar(b byte) bool {
	return b == '_' || ('a' <= b && b <= 'z') || ('0' <= b && b <= '9')
}

func negatedImmediatelyBefore(prefix string) bool {
	prefix = strings.TrimRight(prefix, " \t\r\n:\"'([{-,")
	if !strings.HasSuffix(prefix, "not") {
		return false
	}
	return len(prefix) == len("not") || !quotaTokenChar(prefix[len(prefix)-len("not")-1])
}
