// Agentic tool-call iteration for one assistant turn: assemble the streamed
// tool-call deltas the stream loop hands off, persist the assistant tool-call message,
// schedule and dispatch the calls through the scheduler and an injected
// dispatcher seam, persist the tool results, and re-issue the turn until the
// model returns a final no-tool-call answer.
package turn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/agent"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

// AssembledToolCall is one complete tool call reconstructed from the streamed
// per-chunk tool-call fragments the stream loop collects in ToolCallHandoff.ToolCallDeltas.
// ID identifies the call for tool_call_id correlation; Name is the
// function name; Arguments is the raw JSON-encoded arguments string exactly as
// the model produced it.
type AssembledToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// ToolResult is the outcome of dispatching one tool call. Content is the
// tool-message text fed back to the model: captured command output on success,
// or the synthetic deny envelope when the call was refused. A denial is an
// in-band result the loop always records; whether it then halts or continues
// depends on the envelope's denied_by kind (see Denied). An internal dispatch
// failure is instead reported as a non-nil error from Dispatch, which aborts the
// loop. The deny envelope and an executed result are recorded identically, exactly
// as the model should see them; only whether the loop re-issues afterward differs.
//
// Denied marks a permission refusal. When set, the loop persists Content through
// permissions.DeliverDeny (the deny delivery seam) keyed to the call's tool_call_id,
// instead of the ordinary tool-result record, so DeliverDeny is the single
// production delivery path for the deny envelope. The loop then decodes Content's
// denied_by: a user-denied prompt (denied_by:"user") or an unclassifiable
// envelope halts the turn so a refusal cannot be fed back as an invitation to retry,
// try an alternate method, or claim a result without the user; a denial
// permissions.IsRecoverableDeniedBy accepts is instead re-issued, so the model sees the refusal
// and can pick a permitted alternative. Content carries the envelope either way, so the
// model-facing result is byte-identical; the marker selects both the append path and,
// via the decoded kind, the halt-vs-continue decision, because Content alone cannot
// distinguish a deny envelope from ordinary tool output.
//
// Terminal marks an ordinary result that ends the turn; it is not a permission denial.
//
// WrapUp marks a recoverable refusal after which the loop allows exactly one more provider
// round, advertising no tools, for the model's final answer.
//
// Notice is display-only text the loop shows the user for a result that still continues the
// turn, emitted independently of Terminal. A dispatcher must set it already bounded and
// redacted, because it reaches the user verbatim.
type ToolResult struct {
	Content  string
	Denied   bool
	Terminal bool
	WrapUp   bool
	Notice   string

	ModelContextImage string
	DisplayPatch      string

	// WriteTarget is the path a dispatcher resolved and authorized for an edit or create that
	// then returned exit status 0, and is empty otherwise. It is evidence of a successful
	// write, not a record of every filesystem change the call made.
	WriteTarget  string
	DeleteTarget string
	MoveTarget   MoveTarget
}

type MoveTarget struct {
	Source      string
	Destination string
}

// ToolDispatcher is the injected, turn-level seam the agentic loop runs each
// assembled tool call through. Production wiring binds it to the real
// registry/runner and the production authorizer behind DispatchShell/DispatchTool;
// turn tests inject a fake, so the loop is exercised without bootstrap wiring.
type ToolDispatcher interface {
	// Plan classifies each call on its own: prepared project-confined structured reads may
	// overlap within a contiguous run, and every other call is a serial barrier that keeps
	// model-call order across the runs on either side of it.
	Plan(calls []AssembledToolCall, maxConcurrency int) ToolPlan
	// Dispatch executes one authorized-or-denied call and returns its tool-result
	// content. A denied call returns the deny envelope as the content with a nil
	// error and ToolResult.Denied set; the loop persists that envelope and its
	// denied_by decides what happens next — a user or unclassifiable denial halts
	// the turn, a recoverable one (permissions.IsRecoverableDeniedBy) re-issues (see ToolResult).
	// A non-nil error is an internal failure that aborts the loop without partial
	// continuation.
	Dispatch(ctx context.Context, call AssembledToolCall) (ToolResult, error)
}

type ToolPlan struct {
	Units []PlannedToolCall
}

type PlannedToolCall struct {
	Call AssembledToolCall

	Deps    []string
	Targets []string

	// ContinueOnError withholds this unit's failure from the scheduler, so concurrent
	// siblings drain instead of being cancelled. The loop still reports the error before
	// persisting anything.
	ContinueOnError bool

	// PreRun runs before Run and skips it on error. It is separate from Run because a
	// wrapping dispatcher may replace Run, and a planner's guard must survive that.
	PreRun func(ctx context.Context) error

	Run func(ctx context.Context) (ToolResult, error)
}

// ToolLoop drives agentic tool-call iteration for one assistant turn. It is the
// production replacement for a bare Runner.Run when tool dispatch is wired: Run
// issues the streamed turn, and on a tool-call response the OnToolCalls hook
// (onToolCalls below) assembles the calls, persists the assistant tool-call
// message, schedules and dispatches the calls, persists the tool results, and
// signals continuation so Run re-issues the turn. The base Runner loop is
// unchanged — the loop re-enters it through the hook rather than rewriting it.
type ToolLoop struct {
	deps           Deps
	dispatcher     ToolDispatcher
	maxConcurrency int

	// usage sums the exact stream usage of every provider round of the turn so the
	// final round's model_response and Usage indicator report the turn total, not
	// just the last round. NewToolLoop threads &usage into deps; each round's
	// Runner folds its own usage into this single accumulator. The loop is built
	// fresh per turn, so the zero value starts each turn's total at zero.
	usage model.UsageAccumulator

	// liveProgress accounting makes the in-flight retained-char signal cumulative
	// across provider rounds. userProgress is the caller's Deps.Progress (may
	// be nil); NewToolLoop wraps it (progress) so every round reports progressBase —
	// the retained-char total of all completed rounds — plus the current round's
	// count. Without this a fresh per-round Runner resets its retained count to 0, so a
	// turn that streams content before tool_calls and then a shorter final answer would
	// shrink the indicator from base+firstRoundChars to base+finalRoundChars. roundChars
	// holds the current round's latest count, folded into progressBase when the round
	// returns. All three are touched only on the single Run goroutine (progress fires
	// inline from Runner.Run, like continued), so they need no lock.
	userProgress func(retainedChars int)
	progressBase int
	roundChars   int

	// userUsage is the caller's Deps.Usage (may be nil), captured in NewToolLoop the
	// same way userProgress is. ToolLoop owns all Usage emission for an agentic turn
	// (UsageAcc != nil): Run fires this once after every successful round with the
	// cumulative turn totals, so the indicator's ↑ input figure reaches each completed
	// round's real prompt cost the moment that round's usage chunk lands instead of only
	// at turn end. The per-round Runner's own terminal Usage call is gated to UsageAcc ==
	// nil and finalizeInterceptedRound no longer fires it, so this never double-fires.
	userUsage func(inputTokens, outputTokens int64)

	mu      sync.Mutex
	current *Runner
	pending []PendingUserMessage
	closed  bool

	// continued is set by onToolCalls when it handles a tool-call round and read by
	// Run to decide whether to re-issue. Both run on the single Run goroutine
	// (onToolCalls is invoked inline by Runner.Run), so it needs no lock.
	continued bool

	// denied is set by onToolCalls when the round it handled stopped on a terminal permission
	// refusal — a user denial or an unclassifiable deny envelope. Callers read it (via
	// Denied) after Run returns nil to tell a denial-stop apart from a completed final answer: a
	// terminal denial produces no final assistant answer, so first-turn work like title generation
	// must not fire. A recoverable policy denial leaves it false, because that turn continues to
	// a real final answer. Reset per round in Run and touched only on the single Run goroutine, so it
	// needs no lock.
	denied bool

	wrapUp     bool
	finalRound bool

	acct        turnAccounting
	lastCalls   []AssembledToolCall
	lastAttempt int
	repeats     int
	halted      bool

	deadline time.Time
	work     context.Context
	// Expire fires the time limit immediately while Run has a deadline set; only tests call it.
	Expire      func()
	timeLimited bool
}

type PendingUserMessage struct {
	Text  string
	Parts []sessions.ContentPart
}

const wrapUpInstruction = "For this assistant turn only, tools are no longer available. Write your final answer now, using only the information you already have. This restriction ends when the next user message starts a new turn; follow the tools and instructions supplied for that new turn."

const (
	roundLimit  = 200
	repeatLimit = 3
)

const timeLimitCancelledResult = "tool call cancelled: the run's time limit was reached before it finished; it did not run to completion"

var errTimeLimit = errors.New("turn: run time limit reached")

// NewToolLoop builds an agentic loop over the per-turn deps, the injected
// dispatcher seam, and the scheduler concurrency limit (production threads
// Cache.AgentMaxConcurrency() here). It wires its own OnToolCalls hook
// onto deps so every turn it issues hands tool-call responses back to the loop.
func NewToolLoop(deps Deps, dispatcher ToolDispatcher, maxConcurrency int) *ToolLoop {
	l := &ToolLoop{dispatcher: dispatcher, maxConcurrency: maxConcurrency}
	if deps.TurnID == "" {
		deps.TurnID = ids.NewV7()
	}
	if deps.ToolNotice == nil {
		deps.ToolNotice = deps.Notice
	}
	l.userProgress = deps.Progress
	l.userUsage = deps.Usage
	interrupt := deps.Interrupt
	deps.Interrupt = func() {
		// A time-limited partial is discarded before the final round, never sealed onto stdout.
		if !l.finalRound && l.timeUp() {
			return
		}
		if interrupt != nil {
			interrupt()
		}
	}
	deps.OnToolCalls = l.onToolCalls
	deps.finalAnswer = l.interceptFinalAnswer
	deps.UsageAcc = &l.usage
	deps.acct = &l.acct
	deps.Progress = l.progress
	l.deps = deps
	return l
}

// Run drives the turn to a final answer. It issues a fresh single-use Runner per
// provider round (Runner is single-use, and BuildRequest re-reads the store each
// round so the appended assistant/tool messages feed the next request). A
// tool-call round handled by onToolCalls sets continued and re-issues; a final
// no-tool-call round records model_response and finalizes the stream without
// setting continued, ending the loop. A round whose dispatched results include a
// terminal permission denial (a user denial or an unclassifiable envelope)
// leaves continued false, so that refusal halts the attempt without a follow-up
// provider round; a round denied only by mode policy continues so the model sees the
// refusal and can adapt. A round carrying ToolResult.Terminal ends the turn after its
// results are recorded. Any
// provider/stream/flush error, or a dispatch or scheduler failure surfaced by onToolCalls,
// ends the loop and is returned.
func (l *ToolLoop) Run(ctx context.Context) error {
	defer l.close()
	err := l.run(ctx)
	if l.acct.recorded || (err == nil && l.halted) {
		return err
	}
	return l.recordUnfinishedUsage(ctx, err)
}

func (l *ToolLoop) run(ctx context.Context) error {
	l.work = ctx
	if !l.deadline.IsZero() {
		work, expire := context.WithCancelCause(ctx)
		defer expire(nil)
		work, cancel := context.WithDeadlineCause(work, l.deadline, errTimeLimit)
		defer cancel()
		l.work = work
		l.Expire = func() { expire(errTimeLimit) }
	}
	for pass := 0; ; pass++ {
		if !l.wrapUp && l.timeUp() {
			l.timeLimited = true
			l.beginWrapUp()
		}
		if pass > 0 && !l.wrapUp {
			if batch := l.takePending(false); len(batch) > 0 {
				if err := l.commitUserMessages(ctx, nil, batch); err != nil {
					return err
				}
			}
		}
		l.continued = false
		l.denied = false
		l.roundChars = 0
		// Snapshot the count of usage-carrying rounds before this round runs so we can
		// tell whether *this* round folded a real usage chunk — distinct from UsageAcc's
		// cumulative hadUsage, which stays true for the rest of the turn once any earlier
		// round reported usage.
		usageRoundsBefore := l.usage.UsageRounds()
		wrapUpRound := l.wrapUp
		l.finalRound = wrapUpRound
		roundCtx := l.work
		if wrapUpRound {
			roundCtx = ctx
		}
		recordsBefore := len(l.deps.Store.Records())
		deps := l.deps
		deps.Retry.MaxAttempts = min(deps.Retry.MaxAttempts, roundLimit-1-l.acct.attempts)
		if wrapUpRound {
			deps.Retry.MaxAttempts = 1
		}
		runner := New(deps)
		l.setCurrent(runner)
		err := runner.Run(roundCtx)
		l.clearCurrent(runner)
		// Fold this round's retained chars into the cumulative base so the next round's
		// live progress builds on top of it instead of resetting to its own count.
		l.progressBase += l.roundChars
		if err != nil {
			var failure *DispatchFailure
			if !wrapUpRound && l.timeUp() && !errors.As(err, &failure) {
				if l.deps.RollbackPartial != nil {
					l.deps.RollbackPartial()
				}
				continue
			}
			return err
		}
		// Runner.Run commits a whitespace-only final reply as an answer, and reports an empty
		// stream itself but returns nil.
		if wrapUpRound {
			switch found, blank := finalReply(l.deps.Store.Records()[recordsBefore:]); {
			case !found:
				return errors.New("turn: wrap-up round produced no visible assistant response")
			case blank:
				return l.rejectEmptyRound(ctx, "wrap-up round")
			}
		}
		// This round completed successfully and (on every tool-call, text-tool-call,
		// and final-answer branch) folded its exact usage into UsageAcc. Push the cumulative
		// turn total to the caller's Usage callback now — once per successful round that
		// itself carried a usage chunk — so the indicator's ↑ input figure climbs to round 1's
		// real prompt cost the instant its usage chunk lands, not only at turn end. Gate on
		// whether THIS round added valid usage (its UsageRounds count rose), not on the
		// cumulative hadUsage: a usage-missing round after an earlier valid one leaves the
		// running total unchanged, so re-emitting on cumulative hadUsage would fire a spurious
		// duplicate callback with the stale total. Placed after the progressBase fold and on
		// the non-error path only (a failed/interrupted round must not push usage), and before
		// the continued check so it fires for both a continuing tool-call round and the
		// final/suggest-only terminal round.
		if l.userUsage != nil && l.usage.UsageRounds() > usageRoundsBefore {
			inputTokens, outputTokens, _, _, _, _ := l.usage.Totals()
			l.userUsage(inputTokens, outputTokens)
		}
		if l.continued && !l.wrapUp && !l.timeUp() {
			l.limitWrapUp(nil)
		}
		if !l.continued {
			return nil
		}
	}
}

// Cancel cancels the currently active provider stream, when one exists, and reports
// the retained assistant text for the TUI's stream_interrupted event. Tool dispatch
// cancellation is owned by the parent context passed to Run.
func (l *ToolLoop) Cancel() (retainedChars int, inFlight bool) {
	l.mu.Lock()
	runner := l.current
	l.mu.Unlock()
	if runner == nil {
		return 0, false
	}
	return runner.Cancel()
}

func (l *ToolLoop) InFlight() bool {
	l.mu.Lock()
	runner := l.current
	l.mu.Unlock()
	return runner != nil && runner.InFlight()
}

func (l *ToolLoop) AddUserMessage(text string, parts []sessions.ContentPart) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.pending = append(l.pending, PendingUserMessage{Text: text, Parts: parts})
	return true
}

func (l *ToolLoop) Unsent() []PendingUserMessage {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.pending)
}

func (l *ToolLoop) close() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
}

func (l *ToolLoop) takePending(closeIfEmpty bool) []PendingUserMessage {
	l.mu.Lock()
	defer l.mu.Unlock()
	batch := l.pending
	l.pending = nil
	if len(batch) == 0 && closeIfEmpty {
		l.closed = true
	}
	return batch
}

func (l *ToolLoop) commitUserMessages(ctx context.Context, lead []sessions.Record, batch []PendingUserMessage) error {
	recs := lead
	for _, m := range batch {
		recs = append(recs, sessions.Message{
			ID:        ids.NewV7(),
			Role:      "user",
			Content:   userMessageContent(m),
			Timestamp: time.Now().UTC(),
		})
	}
	cat, reason, err := l.deps.Store.CommitRecords(ctx, recs...)
	if err != nil {
		if reason != sessions.ReasonNone && l.deps.OnFailureWrite != nil {
			l.deps.OnFailureWrite(cat, reason, err)
		}
		l.mu.Lock()
		l.pending = append(batch, l.pending...)
		l.closed = true
		l.mu.Unlock()
		return err
	}
	l.lastCalls, l.repeats = nil, 0
	if l.deps.OnUserMessageAdded != nil {
		for _, m := range batch {
			l.deps.OnUserMessageAdded(m.Text, m.Parts)
		}
	}
	return nil
}

func (l *ToolLoop) interceptFinalAnswer(ctx context.Context, text string) (bool, error) {
	if l.wrapUp {
		return false, nil
	}
	batch := l.takePending(true)
	if len(batch) == 0 {
		return false, nil
	}
	answer := sessions.Message{
		ID:        ids.NewV7(),
		Role:      "assistant",
		Content:   sessions.TextContent(text),
		Timestamp: time.Now().UTC(),
	}
	if err := l.commitUserMessages(ctx, []sessions.Record{answer}, batch); err != nil {
		return false, err
	}
	l.continued = true
	return true, nil
}

func (l *ToolLoop) SetDeadline(deadline time.Time) { l.deadline = deadline }

func (l *ToolLoop) TimeLimitReached() bool { return l.timeLimited }

func (l *ToolLoop) timeUp() bool {
	return !l.deadline.IsZero() && l.work != nil && errors.Is(context.Cause(l.work), errTimeLimit)
}

func (l *ToolLoop) beginWrapUp() {
	if l.wrapUp {
		return
	}
	l.deps.Store.Append(sessions.Message{
		ID:        ids.NewV7(),
		Role:      "system",
		Content:   sessions.TextContent(wrapUpInstruction),
		Timestamp: time.Now().UTC(),
	})
	l.deps.Tools = nil
	l.wrapUp = true
}

func (l *ToolLoop) limitWrapUp(repeated []AssembledToolCall) {
	var notice string
	switch {
	case l.acct.attempts >= roundLimit-1:
		notice = fmt.Sprintf("codemeld: this turn reached its %d-round limit; tools were removed and the model is writing its final answer. Send a new message to continue.", roundLimit)
	case repeated != nil:
		notice = fmt.Sprintf("codemeld: this turn repeated the same tool call (%s) %d rounds in a row; tools were removed and the model is writing its final answer. Send a new message to continue.", toolNames(repeated), repeatLimit)
	default:
		return
	}
	l.beginWrapUp()
	if l.deps.ToolNotice != nil {
		l.deps.ToolNotice(notice)
	}
}

func toolNames(calls []AssembledToolCall) string {
	const maxNames, maxRunes = 3, 64
	names := make([]string, 0, maxNames)
	for _, c := range calls[:min(len(calls), maxNames)] {
		name := fserrors.CollapseControls(c.Name)
		if runes := []rune(name); len(runes) > maxRunes {
			name = string(runes[:maxRunes]) + "…"
		}
		names = append(names, name)
	}
	out := strings.Join(names, ", ")
	if len(calls) > maxNames {
		out += fmt.Sprintf(", +%d more", len(calls)-maxNames)
	}
	return out
}

func (l *ToolLoop) recordUnfinishedUsage(ctx context.Context, err error) error {
	inputTokens, outputTokens, cachedInput, cachedPartial, anomalies, hadUsage := l.usage.Totals()
	sel, _, ok := l.deps.Active.Current()
	if !hadUsage || !ok {
		return err
	}
	if appendErr := model.EmitModelResponse(l.deps.Store, sel.Provider, sel.ID, inputTokens, outputTokens, cachedInput, cachedPartial, anomalies, l.acct.upstream); appendErr != nil {
		return errors.Join(err, appendErr)
	}
	l.acct.recorded = true
	// The caller's Flush hook may be bound to the already-cancelled launch context.
	if cat, reason, flushErr := l.deps.Store.Flush(context.WithoutCancel(ctx)); flushErr != nil {
		if reason != sessions.ReasonNone && l.deps.OnFailureWrite != nil {
			l.deps.OnFailureWrite(cat, reason, flushErr)
		}
		return errors.Join(err, flushErr)
	}
	return err
}

// progress wraps the caller's Deps.Progress so the live retained-char signal is
// cumulative across provider rounds: it reports the completed rounds' retained total
// (progressBase) plus the current round's count, and remembers that count (roundChars)
// so Run can fold it into the base when the round returns. A fresh per-round Runner
// resets its own retained count to 0, so without this the reported live count would
// drop from base+firstRoundChars to base+finalRoundChars when a content-then-tool_calls
// turn re-issues for its final answer. This keeps the Progress callback itself
// monotonic for its consumers; production no longer feeds it to the token indicator,
// which is driven by exact per-round Usage only (see Run's Usage emission). It
// runs inline on the single Run goroutine.
func (l *ToolLoop) progress(retainedChars int) {
	l.roundChars = retainedChars
	if l.userProgress != nil {
		l.userProgress(l.progressBase + retainedChars)
	}
}

func (l *ToolLoop) setCurrent(runner *Runner) {
	l.mu.Lock()
	l.current = runner
	l.mu.Unlock()
}

func (l *ToolLoop) clearCurrent(runner *Runner) {
	l.mu.Lock()
	if l.current == runner {
		l.current = nil
	}
	l.mu.Unlock()
}

// onToolCalls is the ToolCallHook wired by NewToolLoop. It handles exactly
// one tool-call round and signals continuation; re-issuing the turn is Run's job.
// It assembles the streamed deltas, dispatches the calls through the scheduler,
// and only then appends the assistant tool-call message and the contiguous tool
// results, so a scheduler/dispatch failure leaves no dangling assistant tool-call
// message in the stream (which would fail load validation) and never a
// partially-continued turn.
func (l *ToolLoop) onToolCalls(ctx context.Context, h ToolCallHandoff) error {
	round := h.report()
	if l.wrapUp {
		if strings.TrimSpace(h.AssistantText) == "" {
			round.Outcome = events.TurnOutcomeProviderFailed
			round.FailurePhase = provider.EmptyStreamClassification().Phase
			return l.rejectEmptyRound(ctx, "wrap-up round")
		}
		if err := l.finalizeInterceptedRound(h.AssistantText, h.UpstreamProvider); err != nil {
			round.Outcome = events.TurnOutcomeContinuationFailed
			return err
		}
		return nil
	}
	calls, err := assembleToolCalls(h.ToolCallDeltas)
	if err != nil {
		round.Outcome = events.TurnOutcomeToolAssemblyFailed
		return err
	}
	if len(calls) == 0 {
		round.Outcome = events.TurnOutcomeToolAssemblyFailed
		return fmt.Errorf("turn: tool-call response carried no assemblable tool calls")
	}
	if l.acct.attempts == l.lastAttempt+1 && slices.EqualFunc(calls, l.lastCalls, func(a, b AssembledToolCall) bool {
		return a.Name == b.Name && a.Arguments == b.Arguments
	}) {
		l.repeats++
	} else {
		l.repeats = 1
	}
	l.lastCalls, l.lastAttempt = calls, l.acct.attempts

	// Intercept suggest_followup before tool activity, scheduling, dispatch, or
	// persistence. Its {label, prompt} are routed to the TUI ghost-text surface and the
	// call itself is dropped — never surfaced as tool activity, never dispatched as a
	// file/shell action, and never written to the session record or transcript. Filtering
	// here (before OnToolActivity and the assistantToolCallRecord below) is what keeps the
	// intercepted call out of every persisted and rendered surface.
	realCalls := make([]AssembledToolCall, 0, len(calls))
	var suggestions []suggestFollowup
	for _, c := range calls {
		if c.Name == provider.SuggestFollowupToolName {
			label, prompt := parseSuggestFollowup(c.Arguments)
			// Record seen-then-intercepted before routing to the surface so the
			// trace order matches the real path (seen → intercepted → surface_called →
			// ghost_set, the last two emitted TUI-side). intercepted carries label/prompt
			// lengths only; the surface call below still routes the text to the live UI.
			appendSuggestFollowupDebug(l.deps, events.SuggestFollowupStageToolCallSeen, nil, "", "")
			appendSuggestFollowupDebug(l.deps, events.SuggestFollowupStageIntercepted, nil, label, prompt)
			// Hold the suggestion until the round is known to be valid, so a
			// blank suggest-only round routes no ghost text for an answer never made.
			suggestions = append(suggestions, suggestFollowup{label: label, prompt: prompt})
			continue
		}
		realCalls = append(realCalls, c)
	}
	// A tool-call round that carried no suggest_followup completed without a
	// suggestion, the tool-call sibling of Runner.Run's natural-completion no-call stage.
	if len(suggestions) == 0 {
		appendSuggestFollowupDebug(l.deps, events.SuggestFollowupStageNoCall, nil, "", "")
	}

	// Suggest-only round: nothing remains to dispatch, so this round is the turn's final
	// answer. Persist/finalize any assistant prose as the ordinary final reply and end the
	// loop without re-issuing — the model is not owed a tool result for an intercepted
	// call, and re-issuing would spend another provider round on the same prose.
	if len(realCalls) == 0 {
		// A suggest_followup-only round with no visible assistant prose (empty or
		// whitespace) produced no answer. Finalizing it would persist an invisible
		// "successful" reply — model_response/turn_latency with nothing to read. Reject it
		// as an empty-response failure instead, routing no ghost-text suggestion.
		if strings.TrimSpace(h.AssistantText) == "" {
			round.Outcome = events.TurnOutcomeProviderFailed
			round.FailurePhase = provider.EmptyStreamClassification().Phase
			return l.rejectEmptyRound(ctx, "suggest_followup-only round")
		}
		intercepted, err := l.interceptFinalAnswer(ctx, h.AssistantText)
		if err != nil {
			round.Outcome = events.TurnOutcomeContinuationFailed
			return err
		}
		if intercepted {
			return nil
		}
		l.routeSuggestFollowups(suggestions)
		if err := l.finalizeInterceptedRound(h.AssistantText, h.UpstreamProvider); err != nil {
			round.Outcome = events.TurnOutcomeContinuationFailed
			return err
		}
		return nil
	}
	l.routeSuggestFollowups(suggestions)

	plan := l.dispatcher.Plan(realCalls, l.maxConcurrency)
	if err := validateToolPlan(plan, realCalls); err != nil {
		round.Outcome = events.TurnOutcomeToolPlanInvalid
		return err
	}
	if l.deps.OnToolActivity != nil {
		if lines := ToolActivityLines(nonEditCalls(realCalls)); len(lines) > 0 {
			l.deps.OnToolActivity(lines)
		}
	}

	results := make([]ToolResult, len(realCalls))
	unitErrs := make([]error, len(realCalls))
	completed := make([]bool, len(realCalls))
	work := make([]agent.WorkUnit, len(realCalls))
	for i := range realCalls {
		work[i] = &toolWorkUnit{
			id:              realCalls[i].ID,
			deps:            plan.Units[i].Deps,
			targets:         plan.Units[i].Targets,
			preRun:          plan.Units[i].PreRun,
			run:             plan.Units[i].Run,
			out:             &results[i],
			err:             &unitErrs[i],
			completed:       &completed[i],
			continueOnError: plan.Units[i].ContinueOnError,
		}
	}

	round.DispatchStarted = true
	schedErr := agent.Schedule(ctx, work, l.maxConcurrency)
	timeLimited := l.timeUp()
	independentErr := independentDispatchError(schedErr, unitErrs)
	if timeLimited && independentErr == nil {
		if l.deps.RollbackPartial != nil {
			l.deps.RollbackPartial()
		}
	} else if l.deps.SealPartial != nil {
		l.deps.SealPartial()
	}
	if timeLimited {
		if independentErr != nil {
			return l.failDispatch(round, independentErr, realCalls, unitErrs)
		}
		for i := range realCalls {
			if !completed[i] {
				results[i] = ToolResult{Content: timeLimitCancelledResult}
			}
		}
	} else {
		if schedErr != nil {
			return l.failDispatch(round, schedErr, realCalls, unitErrs)
		}
		for _, err := range unitErrs {
			if err == nil {
				continue
			}
			return l.failDispatch(round, err, realCalls, unitErrs)
		}
	}

	// All calls dispatched: append the assistant tool-call message followed by its
	// contiguous tool results so the response group is well-formed. Only the
	// real (post-intercept) calls are recorded — a mixed round persists the dispatched
	// calls but never the intercepted suggest_followup. A denied call's envelope is
	// persisted through permissions.DeliverDeny — the deny delivery seam — keyed to the
	// call's tool_call_id; an executed call uses the ordinary tool-result record. Both
	// yield a role:"tool" message with the same tool_call_id, so the response group stays
	// well-formed and the model reads the deny envelope exactly as it would a tool output.
	// DeliverDeny is called only here, after the assistant tool-call
	// record is appended, so it never races ahead of that record or duplicates a result.
	l.deps.Store.Append(assistantToolCallRecord(h.AssistantText, realCalls))
	terminalDenial := false
	terminalResult := false
	wrapUp := false
	for i := range realCalls {
		if !results[i].Denied {
			l.deps.Store.Append(toolResultRecord(realCalls[i].ID, results[i].Content))
			if results[i].Terminal {
				terminalResult = true
				l.emitResultNotice(results[i].Content)
			}
			l.emitResultNotice(results[i].Notice)
			continue
		}
		permissions.DeliverDeny(realCalls[i].ID, results[i].Content, l.deps.Store)
		info, ok := decodeDenyEnvelope(results[i].Content)
		// A positively-identified policy denial is recoverable — the model may see the refusal in
		// the next provider round and choose a permitted alternative. A user denial and any envelope
		// that cannot be classified are terminal: fail closed so a malformed result can never bypass
		// the user-denial halt (the model must not recover from a user refusal by retrying another
		// tool call).
		if !ok || !info.recoverable {
			terminalDenial = true
		}
		wrapUp = wrapUp || results[i].WrapUp
		l.emitDenialNotice(realCalls[i], info, ok)
		l.emitResultNotice(results[i].Notice)
	}

	// Append after the whole tool-result group, never interleaved among the results: a model_context
	// message between tool results breaks tool_call correlation.
	for i := range realCalls {
		if results[i].Denied || results[i].ModelContextImage == "" {
			continue
		}
		l.deps.Store.Append(modelContextImageRecord(results[i].ModelContextImage))
	}

	if l.deps.OnEditPatch != nil {
		for i := range realCalls {
			if results[i].Denied || results[i].DisplayPatch == "" {
				continue
			}
			l.deps.OnEditPatch(results[i].DisplayPatch)
		}
	}

	// Only a terminal denial (user or unclassifiable) halts the attempt — feeding a user
	// refusal back would let the model retry, try an alternate method, or claim a result without the
	// user. A round of only policy denials, or a mix of successes and policy denials,
	// continues so the model sees the refused tool result and adapts; like any continuing round its
	// records reach disk via the next round's round-trip flush. Successful results and
	// malformed-argument in-band errors leave terminalDenial false and continue as before.
	l.continued = timeLimited || (!terminalDenial && !terminalResult)
	l.denied = terminalDenial
	if l.continued && wrapUp {
		l.beginWrapUp()
	}
	if l.continued && !timeLimited && !l.wrapUp {
		var repeated []AssembledToolCall
		if l.repeats >= repeatLimit {
			repeated = realCalls
		}
		l.limitWrapUp(repeated)
	}
	if !l.continued {
		l.halted = true
		// Flush terminal rounds immediately so their records are durable.
		if l.deps.Flush != nil {
			if err := l.deps.Flush(); err != nil {
				round.Outcome = events.TurnOutcomeContinuationFailed
				return &FinalFlushError{Err: err}
			}
		}
	}
	return nil
}

// DispatchFailure classifies a tool-call failure that happened after scheduling began.
// Error() must stay safe text only — every failure surface prints it — while Unwrap keeps
// the original error matchable by errors.Is.
type DispatchFailure struct {
	Err       error
	Reason    string
	Tool      string
	SessionID string
}

func (e *DispatchFailure) Error() string {
	subject := "a tool call"
	if e.Tool != "" {
		subject = "the " + e.Tool + " tool call"
	}
	line := fmt.Sprintf("codemeld could not complete %s (%s)", subject, e.Reason)
	if e.SessionID == "" {
		return line
	}
	return fmt.Sprintf("%s; run `codemeld sessions doctor %s` to see what was recorded", line, e.SessionID)
}

func (e *DispatchFailure) Unwrap() error { return e.Err }

func independentDispatchError(schedErr error, unitErrs []error) error {
	for _, err := range append([]error{schedErr}, unitErrs...) {
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return nil
}

func (l *ToolLoop) failDispatch(round *RoundReport, err error, calls []AssembledToolCall, unitErrs []error) error {
	round.Outcome = events.TurnOutcomeDispatchFailed
	out := l.classifyDispatch(err, calls, unitErrs)
	var failure *DispatchFailure
	if errors.As(out, &failure) {
		round.FailureReason, round.FailedTool = failure.Reason, failure.Tool
	}
	if l.deps.Flush != nil {
		if flushErr := l.deps.Flush(); flushErr != nil {
			return fmt.Errorf("%w; tool-call failure flush: %w", out, flushErr)
		}
	}
	return out
}

// A cancellation is returned unclassified so it stays a cancellation to every caller that
// tests for one, including the headless run's clean-exit branch.
func (l *ToolLoop) classifyDispatch(err error, calls []AssembledToolCall, unitErrs []error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	failure := &DispatchFailure{Err: err, Reason: events.DispatchReasonPostPlanFailed, SessionID: l.deps.Store.SessionID()}
	// Match the reported error back to the unit that produced it rather than taking the
	// first failed unit: a drained sibling can also record an error, and naming its tool
	// would attribute the failure to a call that did not cause it. Concurrent calls can
	// report the same error value, which matches every one of them — that is not a safe
	// identification, so it stays the generic category rather than naming the lowest index.
	origin := -1
	for i, unitErr := range unitErrs {
		if unitErr == nil || !errors.Is(err, unitErr) {
			continue
		}
		if origin >= 0 {
			return failure
		}
		origin = i
	}
	if origin >= 0 && events.SafeFailedTool(calls[origin].Name) {
		failure.Reason, failure.Tool = events.DispatchReasonToolDispatchFailed, calls[origin].Name
	}
	return failure
}

// Both dropped names already show the user what ran — an edit renders its patch, ask_user
// mounts a form that commits its own transcript record — and toolactivity.Format has no case
// for either, so both would otherwise print their raw tool name. Only this display path is
// filtered; scheduling and persistence see the whole round.
func nonEditCalls(calls []AssembledToolCall) []AssembledToolCall {
	kept := make([]AssembledToolCall, 0, len(calls))
	for _, c := range calls {
		if c.Name == filetools.EditToolName || c.Name == provider.AskUserToolName {
			continue
		}
		kept = append(kept, c)
	}
	return kept
}

// These mirror the closed denied_by enum of the deny-envelope wire shape the permissions builders
// write, so the loop's continuation decision stays a read of the existing envelope contract rather
// than a second classifier; permissions owns which of them are recoverable.
const (
	deniedByUser       = "user"
	deniedByMode       = "mode"
	deniedByGuard      = "guard"
	deniedByUnattended = "unattended"
)

// denyEnvelopeInfo is the classification the loop reads back from a deny envelope's JSON: the
// denied_by kind, whether that kind re-issues rather than halts, and the reason for the notice.
type denyEnvelopeInfo struct {
	deniedBy    string
	reason      string
	recoverable bool
}

// decodeDenyEnvelope reads the denied_by/reason fields from a deny-envelope tool result. It reports
// ok=false for content that is not a well-formed deny envelope with a known denied_by value and a
// non-empty reason, so the caller fails closed on anything it cannot positively classify rather
// than string-searching arbitrary tool output.
func decodeDenyEnvelope(content string) (denyEnvelopeInfo, bool) {
	var wire struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(content), &wire); err != nil {
		return denyEnvelopeInfo{}, false
	}
	switch wire.DeniedBy {
	case deniedByUser, deniedByMode, deniedByGuard, deniedByUnattended:
	default:
		return denyEnvelopeInfo{}, false
	}
	if strings.Trim(wire.Reason, " \t\r\n\v\f") == "" {
		return denyEnvelopeInfo{}, false
	}
	return denyEnvelopeInfo{
		deniedBy:    wire.DeniedBy,
		reason:      wire.Reason,
		recoverable: permissions.IsRecoverableDeniedBy(wire.DeniedBy),
	}, true
}

// emitDenialNotice surfaces a friendly one-line denial notice naming the refused tool or command and
// the reason, so a user or policy denial is visible in the UI without the raw deny-envelope JSON
// becoming the primary user-facing text. It reuses formatToolActivity for the display label
// ("Run: <command>", "Edit <path>", …) and the envelope's decoded reason, falling back to a generic
// reason for an unclassifiable envelope. It routes through Deps.ToolNotice — committed in-place in the TUI,
// stderr in a headless run — and is nil-safe for unit tests that wire no notice sink.
func (l *ToolLoop) emitDenialNotice(call AssembledToolCall, info denyEnvelopeInfo, ok bool) {
	if l.deps.ToolNotice == nil {
		return
	}
	reason := info.reason
	if !ok || reason == "" {
		reason = "permission denied"
	}
	l.deps.ToolNotice("Denied " + formatToolActivity(call) + ": " + reason)
}

// The text is already bounded and redacted by the dispatcher.
func (l *ToolLoop) emitResultNotice(text string) {
	if l.deps.ToolNotice == nil || strings.TrimSpace(text) == "" {
		return
	}
	l.deps.ToolNotice(text)
}

// Denied reports whether the turn stopped on a terminal permission refusal — a user denial or an
// unclassifiable deny envelope — rather than a completed final answer. It is valid after Run
// returns nil: a terminal denial-stop appends the assistant tool-call record and deny envelope but
// produces no final assistant answer, so callers gate first-turn completion work (e.g. title
// generation) on this being false. A recoverable policy denial reports false: that turn
// re-issued the model and ran on to a real final answer.
func (l *ToolLoop) Denied() bool { return l.denied }

// parseSuggestFollowup extracts the label/prompt from a suggest_followup call's raw JSON
// arguments. Malformed or partial arguments yield empty strings rather than an error: the
// suggestion is best-effort ephemeral UI state, so a weak model that mis-emits the call
// must not fail the turn — the call is intercepted and dropped regardless.
func parseSuggestFollowup(args string) (label, prompt string) {
	var p struct {
		Label  string `json:"label"`
		Prompt string `json:"prompt"`
	}
	_ = json.Unmarshal([]byte(args), &p)
	return p.Label, p.Prompt
}

// suggestFollowup is a parsed suggest_followup call held until the round is known to be
// valid, so the ghost-text callback fires only for a round that produced a visible
// reply — never for a blank suggest-only round that would otherwise offer a follow-up to an
// answer the user never saw.
type suggestFollowup struct{ label, prompt string }

// routeSuggestFollowups fires the Deps.SuggestFollowup ghost-text callback for each
// intercepted suggestion, once per call. Called only after a round is classified valid
// (a mixed round, or a suggest-only round with non-blank prose).
func (l *ToolLoop) routeSuggestFollowups(suggestions []suggestFollowup) {
	if l.deps.SuggestFollowup == nil {
		return
	}
	for _, s := range suggestions {
		l.deps.SuggestFollowup(s.label, s.prompt)
	}
}

// rejectEmptyRound handles a suggest_followup-only round or a wrap-up round whose
// assistant prose is empty or whitespace: the provider produced no visible answer, so
// recording a model_response/turn_latency or finalizing it would persist an invisible
// "successful" reply. It instead surfaces the same empty-response failure feedback as
// Runner.runAttempt — a durable provider_request_failed event plus the one-line notice —
// appends no assistant message, and returns a non-nil error so ToolLoop.Run skips the
// success-path Usage callback and ends the turn without continuation. The provider_round_trip
// for this round was already recorded before the tool-call handoff, so it is not re-timed.
func (l *ToolLoop) rejectEmptyRound(ctx context.Context, round string) error {
	class := provider.EmptyStreamClassification()
	if sel, _, ok := l.deps.Active.Current(); ok {
		_ = events.EmitProviderRequestFailed(ctx, l.deps.Store, sel.Provider, sel.ID,
			class.Phase, class.Reason, class.ErrorDetail, class.HTTPStatus, class.PartialResponseChars, l.deps.OnFailureWrite)
		if l.deps.Notice != nil && l.deps.RenderNotice != nil {
			surface := fmt.Sprintf("provider %s request to model %s failed (%s/%s): %s",
				sel.Provider, sel.ID, class.Phase, class.Reason, class.ErrorDetail)
			l.deps.Notice(l.deps.RenderNotice(surface, class.Phase, class.Reason, 0))
		}
	}
	return fmt.Errorf("turn: %s produced no visible assistant response", round)
}

func finalReply(records []sessions.Record) (found, blank bool) {
	for _, rec := range records {
		msg, ok := rec.(sessions.Message)
		if ok && msg.Role == "assistant" && len(msg.ToolCalls) == 0 {
			return true, !msg.Content.IsList() && strings.TrimSpace(msg.Content.Text()) == ""
		}
	}
	return false, false
}

// finalizeInterceptedRound closes a round whose only tool calls were intercepted
// suggest_followup calls: nothing remains to dispatch, so the round is the
// turn's final answer. It persists any streamed assistant prose as the ordinary final
// reply, records the turn's summed model_response and the single turn_latency, and
// finalizes/flushes the transcript — mirroring Runner.Run's natural-completion path —
// then leaves continued unset so Run stops. The token indicator's exact-usage figure is
// emitted centrally by ToolLoop.Run after this returns, not here, so a suggest-only
// terminal round fires Usage once rather than twice. The provider_round_trip for
// this round was already recorded and flushed by
// Runner.Run before the tool-call handoff, so it is deliberately not recorded again.
func (l *ToolLoop) finalizeInterceptedRound(assistantText, upstream string) error {
	if assistantText != "" {
		l.deps.Store.Append(sessions.Message{
			ID:        ids.NewV7(),
			Role:      "assistant",
			Content:   sessions.TextContent(assistantText),
			Timestamp: time.Now().UTC(),
		})
	}
	if sel, _, ok := l.deps.Active.Current(); ok {
		inputTokens, outputTokens, cachedInput, cachedPartial, anomalies, _ := l.usage.Totals()
		if err := model.EmitModelResponse(l.deps.Store, sel.Provider, sel.ID, inputTokens, outputTokens, cachedInput, cachedPartial, anomalies, upstream); err != nil {
			return err
		}
		l.acct.recorded = true
		// The Usage callback is owned centrally by ToolLoop.Run, which fires it once
		// with these same cumulative totals after this intercepted round returns. Emitting
		// it here too would double-fire for a suggest-only terminal round, so this records
		// only the summed model_response.
		// One turn_latency per turn, recorded only on the final answer; a
		// suggest-only round is that final answer. Zero SubmitStart means not wired.
		if !l.deps.SubmitStart.IsZero() {
			_, _ = events.Append(l.deps.Store, events.TurnLatency{
				Provider:   sel.Provider,
				ModelID:    sel.ID,
				DurationMs: elapsedMs(l.deps.SubmitStart),
			})
		}
	}
	if l.deps.Finalize != nil {
		l.deps.Finalize()
	}
	if l.deps.Flush != nil {
		if err := l.deps.Flush(); err != nil {
			return &FinalFlushError{Err: err}
		}
	}
	if l.deps.FinalizeErr != nil {
		return l.deps.FinalizeErr()
	}
	return nil
}

func validateToolPlan(plan ToolPlan, calls []AssembledToolCall) error {
	if len(plan.Units) != len(calls) {
		return fmt.Errorf("turn: tool plan has %d units for %d tool calls", len(plan.Units), len(calls))
	}
	for i, unit := range plan.Units {
		if unit.Call.ID != calls[i].ID || unit.Call.Name != calls[i].Name {
			return fmt.Errorf("turn: tool plan unit %d is %q/%q, want tool call %q/%q",
				i, unit.Call.ID, unit.Call.Name, calls[i].ID, calls[i].Name)
		}
		if unit.Run == nil {
			return fmt.Errorf("turn: tool plan unit %d (%q) has no run", i, calls[i].ID)
		}
	}
	return nil
}

type toolWorkUnit struct {
	id              string
	deps            []string
	targets         []string
	preRun          func(ctx context.Context) error
	run             func(ctx context.Context) (ToolResult, error)
	out             *ToolResult
	err             *error
	completed       *bool
	continueOnError bool
}

func (u *toolWorkUnit) ID() string        { return u.id }
func (u *toolWorkUnit) Deps() []string    { return u.deps }
func (u *toolWorkUnit) Targets() []string { return u.targets }

func (u *toolWorkUnit) Run(ctx context.Context) error {
	if u.preRun != nil {
		if err := u.preRun(ctx); err != nil {
			*u.err = err
			return err
		}
	}
	res, err := u.run(ctx)
	*u.out = res
	*u.err = err
	*u.completed = err == nil
	if err != nil && !u.continueOnError {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// assembleToolCalls reconstructs complete tool calls from the streamed per-chunk
// fragments. OpenAI streams a tool call's id/type/name on the first fragment for
// its index and the JSON arguments across one or more later fragments, so this
// accumulates name and arguments per tool-call index and keeps the first non-empty
// id. Calls are returned ordered by index (the model's tool_calls order). It fails
// if a call has no id (no tool_call_id to correlate) or no function name.
func assembleToolCalls(deltas [][]openai.ChatCompletionChunkChoiceDeltaToolCall) ([]AssembledToolCall, error) {
	type acc struct {
		id   string
		name strings.Builder
		args strings.Builder
	}
	byIndex := map[int64]*acc{}
	var indexes []int64
	for _, chunk := range deltas {
		for _, frag := range chunk {
			a, ok := byIndex[frag.Index]
			if !ok {
				a = &acc{}
				byIndex[frag.Index] = a
				indexes = append(indexes, frag.Index)
			}
			if frag.ID != "" {
				a.id = frag.ID
			}
			a.name.WriteString(frag.Function.Name)
			a.args.WriteString(frag.Function.Arguments)
		}
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })

	calls := make([]AssembledToolCall, 0, len(indexes))
	for _, idx := range indexes {
		a := byIndex[idx]
		if a.id == "" {
			return nil, fmt.Errorf("turn: assembled tool call at index %d has no id", idx)
		}
		if a.name.Len() == 0 {
			return nil, fmt.Errorf("turn: assembled tool call %q has no function name", a.id)
		}
		calls = append(calls, AssembledToolCall{ID: a.id, Name: a.name.String(), Arguments: a.args.String()})
	}
	return calls, nil
}

// assistantToolCallRecord builds the assistant message that records a tool-call
// round: the streamed assistant text (possibly empty) plus the assembled calls as
// tool_calls entries. Each entry's raw JSON is the OpenAI-compatible
// {id,type:"function",function:{name,arguments}} shape so the record persists and
// re-feeds the follow-up provider request unchanged (the request builder
// reads it back via providerToolCalls).
func assistantToolCallRecord(text string, calls []AssembledToolCall) sessions.Message {
	tcs := make([]sessions.ToolCall, len(calls))
	for i, c := range calls {
		tcs[i] = sessions.ToolCall{ID: c.ID, Type: "function", Raw: marshalToolCallRaw(c)}
	}
	return sessions.Message{
		ID:        ids.NewV7(),
		Role:      "assistant",
		Content:   sessions.TextContent(text),
		Timestamp: time.Now().UTC(),
		ToolCalls: tcs,
	}
}

// toolResultRecord builds the tool-result message answering one call: Role "tool",
// the call's id in ToolCallID, and the dispatched content (or deny envelope) as the
// message text.
func toolResultRecord(callID, content string) sessions.Message {
	return sessions.Message{
		ID:         ids.NewV7(),
		Role:       "tool",
		Content:    sessions.TextContent(content),
		Timestamp:  time.Now().UTC(),
		ToolCallID: callID,
	}
}

func modelContextImageRecord(dataURI string) sessions.Message {
	return sessions.Message{
		ID:        ids.NewV7(),
		Role:      "model_context",
		Content:   sessions.PartsContent([]sessions.ContentPart{{Type: "image_url", Raw: imageURLRawPart(dataURI)}}),
		Timestamp: time.Now().UTC(),
	}
}

func imageURLRawPart(url string) json.RawMessage {
	type imageURL struct {
		URL string `json:"url"`
	}
	type part struct {
		Type     string   `json:"type"`
		ImageURL imageURL `json:"image_url"`
	}
	b, _ := json.Marshal(part{Type: "image_url", ImageURL: imageURL{URL: url}})
	return json.RawMessage(b)
}

func userMessageContent(m PendingUserMessage) sessions.Content {
	if len(m.Parts) == 0 {
		return sessions.TextContent(m.Text)
	}
	parts := make([]sessions.ContentPart, 0, len(m.Parts)+1)
	if m.Text != "" {
		parts = append(parts, textContentPart(m.Text))
	}
	return sessions.PartsContent(append(parts, m.Parts...))
}

func textContentPart(text string) sessions.ContentPart {
	type part struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	b, _ := json.Marshal(part{Type: "text", Text: text})
	return sessions.ContentPart{Type: "text", Raw: b}
}

// marshalToolCallRaw renders one assembled call as the tool-call entry
// JSON: {"id":...,"type":"function","function":{"name":...,"arguments":...}}.
// Arguments stays a JSON string (json.Marshal escapes it), matching the persisted
// schema and providerToolCalls's inverse read. The struct cannot fail to marshal
// (only string fields), so the error is discarded.
func marshalToolCallRaw(c AssembledToolCall) json.RawMessage {
	type fn struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	type wire struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}
	b, _ := json.Marshal(wire{ID: c.ID, Type: "function", Function: fn{Name: c.Name, Arguments: c.Arguments}})
	return json.RawMessage(b)
}
