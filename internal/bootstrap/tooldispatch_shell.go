package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/sessions"
)

// bashToolName is the pinned built-in name that production routes through DispatchShell
// rather than the registry: no concrete bash Tool exists, so a `bash` tool call is a raw
// shell command, not a structured registry lookup.
const bashToolName = "bash"

// decodeBashCommand pulls the command string out of a `bash` tool call's JSON arguments
// (the conventional {"command":"..."} shape). Malformed JSON or a missing/blank command
// (empty or whitespace-only) is returned as an error the caller surfaces in-band, so a bad
// bash call never prompts or crashes.
func decodeBashCommand(arguments string) (string, error) {
	var decoded struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(arguments), &decoded); err != nil {
		return "", fmt.Errorf("invalid bash arguments: %w", err)
	}
	if strings.TrimSpace(decoded.Command) == "" {
		return "", fmt.Errorf("invalid bash arguments: missing %q", "command")
	}
	return decoded.Command, nil
}

type shellEventRunner struct {
	inner             dispatch.Runner
	active            func() *sessions.Store
	cap               int
	childInvocationID string
	// pending carries the one preflighted pipeline from PreflightPipeline to the Pipeline call that
	// follows it, so a session switch between the two cannot split a pipeline's start and end records
	// across stores. Pipe groups run one at a time, so at most one is ever pending.
	pending pendingPipeline
}

// pendingPipeline is the state a successful preflight leaves for the Pipeline call. store and starts
// are nil when no event emitter is wired.
type pendingPipeline struct {
	inner  runner.PipelineRunner
	store  *sessions.Store
	starts []sessions.Record
}

func (r *shellEventRunner) NewInvocationID() string { return r.inner.NewInvocationID() }

// PreflightPipeline reports the capability only through its own return value: a Pipeline method on
// the decorator makes the caller's type assertion succeed for every wrapped runner, including ones
// that cannot run a pipeline, which would leave the sequential fallback unreachable. A non-nil error
// means nothing was started and nothing was emitted.
func (r *shellEventRunner) PreflightPipeline(ctx context.Context, specs []runner.RunSpec) error {
	return r.preflightPrepared(ctx, specs, specs)
}

func (r *shellEventRunner) preflightPrepared(ctx context.Context, subjects, specs []runner.RunSpec) error {
	r.pending = pendingPipeline{}
	inner, ok := r.inner.(runner.PipelineRunner)
	if !ok {
		return dispatch.ErrPipelineUnsupported
	}
	if err := inner.PreflightPipeline(ctx, specs); err != nil {
		return err
	}
	if r.active == nil {
		r.pending = pendingPipeline{inner: inner}
		return nil
	}
	store := r.active()
	if store == nil {
		return errors.New("bootstrap: no active session store for pipeline tool_exec events")
	}
	starts := make([]sessions.Record, len(subjects))
	for i, spec := range subjects {
		kind, subject := shellExecSubject(spec.Argv)
		rec, err := events.Build(events.ToolExecStart{
			SubjectKind:       kind,
			Subject:           subject,
			PathScope:         spec.Cwd,
			InvocationID:      spec.InvocationID,
			ChildInvocationID: r.childInvocationID,
		})
		if err != nil {
			return err
		}
		starts[i] = rec
	}
	r.pending = pendingPipeline{inner: inner, store: store, starts: starts}
	return nil
}

// Pipeline emits exactly one tool_exec_end per emitted tool_exec_start — including for a post-launch
// failure, whose error is returned only once every start is paired. Ends go through the bounded event
// builder rather than EmitToolExecEnd, which would derive truncated and original_bytes from streams
// the runner had already cut short.
func (r *shellEventRunner) Pipeline(ctx context.Context, specs []runner.RunSpec) ([]runner.PipelineResult, error) {
	return r.pipelinePrepared(ctx, specs, specs)
}

func (r *shellEventRunner) pipelinePrepared(ctx context.Context, subjects, specs []runner.RunSpec) ([]runner.PipelineResult, error) {
	pending := r.pending
	r.pending = pendingPipeline{}
	if pending.inner == nil {
		return nil, errors.New("bootstrap: pipeline run without a successful preflight")
	}
	for _, rec := range pending.starts {
		pending.store.Append(rec)
	}
	results, pipelineErr := pending.inner.Pipeline(ctx, specs, r.cap)
	if pending.store == nil {
		return results, pipelineErr
	}
	ends := make([]sessions.Record, 0, len(subjects))
	var buildErr error
	for i, spec := range subjects {
		var res runner.PipelineResult
		if i < len(results) {
			res = results[i]
		} else {
			res = runner.PipelineResult{InvocationID: spec.InvocationID, ExitCode: -1}
		}
		kind, subject := shellExecSubject(spec.Argv)
		rec, err := events.BuildToolExecEndBounded(events.BoundedToolExec{
			InvocationID:      spec.InvocationID,
			ChildInvocationID: r.childInvocationID,
			SubjectKind:       kind,
			Subject:           subject,
			ExitCode:          res.ExitCode,
			DurationMs:        res.Duration.Milliseconds(),
			Stdout:            res.Stdout,
			Stderr:            res.Stderr,
			StdoutTotal:       res.StdoutTotal,
			StderrTotal:       res.StderrTotal,
		}, r.cap)
		if err != nil {
			buildErr = err
			continue
		}
		ends = append(ends, rec)
	}
	for _, rec := range ends {
		pending.store.Append(rec)
	}
	if buildErr != nil {
		return results, buildErr
	}
	return results, pipelineErr
}

func (r *shellEventRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	kind, subject := shellExecSubject(spec.Argv)
	if r.active != nil {
		if err := events.EmitToolExecStart(r.active(), spec.InvocationID, kind, subject, spec.Cwd, r.childInvocationID); err != nil {
			return runner.RunResult{}, err
		}
	}
	res, err := r.inner.Exec(ctx, spec)
	if err != nil {
		return runner.RunResult{}, err
	}
	if r.active != nil {
		if err := events.EmitToolExecEnd(r.active(), spec.InvocationID, kind, subject, res.ExitCode, res.Duration.Milliseconds(), res.Stdout, res.Stderr, r.cap, r.childInvocationID); err != nil {
			return runner.RunResult{}, err
		}
	}
	return res, nil
}

func (r *shellEventRunner) ExecBounded(ctx context.Context, spec runner.RunSpec, maxCapture int) (runner.RunResult, error) {
	return r.execBoundedPrepared(ctx, spec, spec, maxCapture, false)
}

func (r *shellEventRunner) execBoundedPrepared(ctx context.Context, original, spec runner.RunSpec, maxCapture int, confined bool) (runner.RunResult, error) {
	inner, ok := r.inner.(runner.BoundedExecRunner)
	if !ok {
		return runner.RunResult{}, errors.New("bootstrap: inner runner cannot bound command output")
	}
	if r.active == nil {
		res, err := inner.ExecBounded(ctx, spec, maxCapture)
		if err == nil && confined {
			res = noteConfinedFailure(res, r.cap)
		}
		return res, err
	}
	kind, subject := shellExecSubject(original.Argv)
	if err := events.EmitToolExecStart(r.active(), original.InvocationID, kind, subject, original.Cwd, r.childInvocationID); err != nil {
		return runner.RunResult{}, err
	}
	res, runErr := inner.ExecBounded(ctx, spec, maxCapture)
	if runErr != nil {
		res = runner.RunResult{ExitCode: -1}
	} else if confined {
		res = noteConfinedFailure(res, r.cap)
	}
	_, endErr := events.Append(r.active(), events.ToolExecEndFromBounded(events.BoundedToolExec{
		InvocationID:      spec.InvocationID,
		ChildInvocationID: r.childInvocationID,
		SubjectKind:       kind,
		Subject:           subject,
		ExitCode:          res.ExitCode,
		DurationMs:        res.Duration.Milliseconds(),
		Stdout:            res.Stdout,
		Stderr:            res.Stderr,
		StdoutTotal:       res.StdoutTotal,
		StderrTotal:       res.StderrTotal,
	}, r.cap))
	if runErr != nil || endErr != nil {
		return runner.RunResult{}, errors.Join(runErr, endErr)
	}
	return res, nil
}

func shellExecSubject(argv []string) (kind, subject string) {
	if len(argv) >= 3 && argv[0] == "sh" && argv[1] == "-c" {
		return "literal", argv[2]
	}
	return "direct", strings.Join(argv, " ")
}
