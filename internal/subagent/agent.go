// Package subagent runs one bounded child agent conversation in a private,
// memory-only session and reports its outcome as a bounded Result.
package subagent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/turn"
)

// ActivitySink observes one child agent while it is still running. A tool round is
// attributed by the invocation id passed beside it, never by having arrived between a start
// and an end, so children whose lifetimes overlap stay separable.
type ActivitySink interface {
	ChildAgentStarted(start events.ChildAgentStart)
	ChildAgentCalls(invocation string, lines []string)
	ChildAgentEnded(end events.ChildAgentEnd)
}

// Request carries snapshots the caller takes at delegation time. Dispatcher is the
// authorization seam: the caller builds it against the child's mode context, and
// this package never assembles authority of its own.
type Request struct {
	Instruction     string
	Model           model.Selection
	ModelSource     model.Source
	SupportedEffort func(providerID, modelID string) []string
	SystemPrompt    string
	Client          provider.Client
	Tools           []provider.ToolDefinition
	Dispatcher      turn.ToolDispatcher
	StepCap         int
	// Journal is opened before the request is built, because a run that dies mid-dispatch must
	// already have its snapshot on disk.
	Journal *Journal
	// Activity and InvocationID are optional and belong together: the caller that minted the
	// id owns the sink, and validate requires neither.
	Activity     ActivitySink
	InvocationID string
}

func (r Request) validate() error {
	switch {
	case strings.TrimSpace(r.Instruction) == "":
		return errors.New("subagent: instruction is required")
	case r.Model.Provider == "" || r.Model.ID == "":
		return errors.New("subagent: model selection is required")
	case r.SupportedEffort == nil:
		return errors.New("subagent: supported-effort lookup is required")
	case r.SystemPrompt == "":
		return errors.New("subagent: system prompt is required")
	case r.Client == nil:
		return errors.New("subagent: provider client is required")
	case r.Dispatcher == nil:
		return errors.New("subagent: tool dispatcher is required")
	case r.StepCap <= 0:
		return fmt.Errorf("subagent: step cap must be positive, got %d", r.StepCap)
	}
	return nil
}

var errStepCap = errors.New("subagent: step cap reached")

// DefaultStepCap bounds a child that no caller sized itself: enough rounds to read,
// change, and verify a small piece of work, and few enough that a looping child ends.
const DefaultStepCap = 12

// Run returns a usable Result and a nil error for a step cap, a cancellation, and a
// terminal user denial; only an unexpected loop failure returns the partial Result
// together with its error.
func Run(ctx context.Context, req Request) (Result, error) {
	if err := req.validate(); err != nil {
		result := Result{Reason: ReasonFailed}
		applyJournal(&result, req.Journal)
		return result, err
	}

	if req.Journal != nil {
		ctx = filetools.WithWriteJournal(ctx, req.Journal)
	}

	store := sessions.NewMemoryOnly()
	store.Append(sessions.Message{
		ID:        ids.NewV7(),
		Role:      "user",
		Content:   sessions.TextContent(req.Instruction + InstructionSuffix),
		Timestamp: time.Now().UTC(),
	})

	var reply strings.Builder
	// Resetting the reply at each request keeps only the latest round, so a tool-call
	// round's preamble is never fused onto the final answer.
	client := &cappedClient{inner: req.Client, limit: req.StepCap, onRequest: reply.Reset}
	recorder := &callRecorder{inner: req.Dispatcher}
	if req.Activity != nil {
		recorder.onRound = func(calls []turn.AssembledToolCall) {
			req.Activity.ChildAgentCalls(req.InvocationID, turn.ToolActivityLines(calls))
		}
	}

	deps := turn.Deps{
		Active:          model.NewActiveState(&req.Model, req.ModelSource),
		Store:           store,
		Client:          client,
		Tools:           req.Tools,
		SystemPrompt:    req.SystemPrompt,
		SupportedEffort: req.SupportedEffort,
		Sink:            func(delta string) { reply.WriteString(delta) },
		Flush:           func() error { _, _, err := store.Flush(ctx); return err },
	}

	loop := turn.NewToolLoop(deps, recorder, 1)

	runErr := loop.Run(ctx)

	result := Result{
		ProviderRequests: client.started,
		ToolNames:        recorder.names,
		WriteTargets:     recorder.targets(func(res turn.ToolResult) string { return res.WriteTarget }),
		DeleteTargets:    recorder.targets(func(res turn.ToolResult) string { return res.DeleteTarget }),
		MoveTargets:      recorder.moves(),
	}
	result.Refusals, result.RefusalTotal = recorder.refusals()
	result.Reply, result.ReplyTruncated = boundReply(reply.String())
	switch {
	case errors.Is(runErr, errStepCap):
		result.Reason = ReasonStepCap
	case errors.Is(runErr, context.Canceled), errors.Is(runErr, context.DeadlineExceeded):
		result.Reason = ReasonCancelled
	case runErr != nil:
		result.Reason = ReasonFailed
		applyJournal(&result, req.Journal)
		return result, runErr
	case loop.Denied() || !endedWithFinalReply(store):
		result.Reason = ReasonFailed
	default:
		result.Reason = ReasonCompleted
	}
	applyJournal(&result, req.Journal)
	return result, nil
}

func applyJournal(result *Result, journal *Journal) {
	if journal == nil {
		return
	}
	outcome := journal.Finish(result.Reason)
	journal.Close()
	result.RestoredPaths = outcome.Restored
	result.Unrecovered = outcome.Unrecovered
	result.RetainedJournal = outcome.JournalPath
}

// endedWithFinalReply reads the answer back out of the child's own record stream,
// because a nil turn.ToolLoop.Run is not proof of one: a retry-disabled empty
// provider response also ends the loop without an error and without a final reply.
func endedWithFinalReply(store *sessions.Store) bool {
	records := store.Records()
	for i := len(records) - 1; i >= 0; i-- {
		msg, ok := records[i].(sessions.Message)
		if !ok {
			continue
		}
		return msg.Role == "assistant" && len(msg.ToolCalls) == 0
	}
	return false
}

type cappedClient struct {
	inner provider.Client
	limit int
	// turn issues its rounds sequentially on one goroutine, so this needs no lock.
	started   int
	onRequest func()
}

func (c *cappedClient) ChatCompletion(ctx context.Context, req provider.Request) (provider.Response, error) {
	if err := ctx.Err(); err != nil {
		return provider.Response{}, err
	}
	if c.started >= c.limit {
		return provider.Response{}, errStepCap
	}
	c.started++
	c.onRequest()
	return c.inner.ChatCompletion(ctx, req)
}

type callRecorder struct {
	inner turn.ToolDispatcher
	names []string
	// One slot per planned unit per round: a unit writes only its own slot, so the flattened
	// order stays model-call order however the scheduler interleaves the units.
	rounds  [][]recordedCall
	onRound func([]turn.AssembledToolCall)
}

type recordedCall struct {
	result  turn.ToolResult
	refusal *Refusal
}

// Plan is the capture point because it receives one round's calls in model-call
// order, after the loop has dropped its intercepted suggest_followup calls. It is also
// where activity is reported, rather than turn.Deps.OnToolActivity: that hook drops edit
// calls because the parent renders their patches instead, and a child has no patch surface,
// so an edit-only child round would otherwise report nothing at all.
func (r *callRecorder) Plan(calls []turn.AssembledToolCall, maxConcurrency int) turn.ToolPlan {
	for _, call := range calls {
		r.names = append(r.names, call.Name)
	}
	plan := r.inner.Plan(calls, maxConcurrency)
	if r.onRound != nil && len(calls) > 0 {
		r.onRound(calls)
	}
	targets := make([]recordedCall, len(plan.Units))
	r.rounds = append(r.rounds, targets)
	for i := range plan.Units {
		if plan.Units[i].Run == nil {
			continue
		}
		r.admit(&plan.Units[i], &targets[i])
	}
	return plan
}

// admit is where a child tool call starts: the guard runs immediately before the planned unit,
// so a cancellation that lands after the scheduler launched the unit still stops it before the
// unit does anything.
func (r *callRecorder) admit(unit *turn.PlannedToolCall, target *recordedCall) {
	inner := unit.Run
	call := unit.Call
	unit.Run = func(ctx context.Context) (turn.ToolResult, error) {
		if err := ctx.Err(); err != nil {
			return turn.ToolResult{}, err
		}
		res, err := inner(ctx)
		if err == nil {
			target.result = turn.ToolResult{WriteTarget: res.WriteTarget, DeleteTarget: res.DeleteTarget, MoveTarget: res.MoveTarget}
			if res.Denied {
				target.refusal = newRefusal(call, res.Content)
			}
		}
		return res, err
	}
}

func (r *callRecorder) refusals() (listed []Refusal, total int) {
	seen := map[[2]string]bool{}
	for _, round := range r.rounds {
		for _, rec := range round {
			if rec.refusal == nil {
				continue
			}
			key := [2]string{rec.refusal.call.Name, rec.refusal.call.Arguments}
			if seen[key] {
				continue
			}
			seen[key] = true
			total++
			if len(listed) < maxListedRefusals {
				listed = append(listed, *rec.refusal)
			}
		}
	}
	return listed, total
}

func (r *callRecorder) moves() []turn.MoveTarget {
	var moves []turn.MoveTarget
	for _, round := range r.rounds {
		for _, rec := range round {
			if rec.result.MoveTarget != (turn.MoveTarget{}) {
				moves = append(moves, rec.result.MoveTarget)
			}
		}
	}
	return moves
}

func (r *callRecorder) targets(pick func(turn.ToolResult) string) []string {
	var targets []string
	for _, round := range r.rounds {
		for _, rec := range round {
			if target := pick(rec.result); target != "" {
				targets = append(targets, target)
			}
		}
	}
	return targets
}

func (r *callRecorder) Dispatch(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	return r.inner.Dispatch(ctx, call)
}
