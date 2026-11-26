package dispatch

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/tools"
)

// dispatchLiteral handles an I/O-redirection or wrapper/literal route: the whole
// prefix-stripped command is one literal subject. It is canonicalized for matching, authorized as a
// single MatchRequest with kind "literal" and no SubjectTokens, and — only if authorized — executed
// exactly as written through `sh -c` so accepted redirection and wrapper forms run verbatim.
func dispatchLiteral(ctx context.Context, literalInput string, scope string, authorizer Authorizer, run Runner, modeCtx permissions.ModeContext) (tools.Result, error) {
	canonical, err := permissions.CanonicalLiteralForm(literalInput)
	if err != nil {
		return tools.Result{}, &MalformedCommandError{Err: err}
	}
	req := permissions.MatchRequest{
		Kind:      "literal",
		Subject:   canonical,
		PathScope: scope,
	}
	decision, err := authorizer.Authorize(ctx, req, PromptDisplay{Action: ActionRunCommand, Subject: literalInput, WholeCommand: true}, modeCtx)
	if err != nil {
		return tools.Result{}, err
	}
	if decision.DenyEnvelope != "" {
		return tools.Result{}, &DeniedError{Envelope: decision.DenyEnvelope, WrapUp: decision.WrapUp}
	}
	if err := ctx.Err(); err != nil {
		return tools.Result{}, err
	}
	setShellRequests(ctx, []permissions.MatchRequest{req})

	// The shell decides what this text runs, so an `rg` anywhere in it — including behind a
	// wrapper — must not pick up an inherited ripgrep configuration.
	env := execEnvWithout(nil, ripgrepConfigEnv)
	// An automatic ps literal keeps the ordinary shell environment except for the libxo encoder
	// search path; an approved argv must not select an encoder it did not name.
	if decision.ReadOnlyAuto && permissions.LiteralRunsPS(canonical) {
		env = execEnvWithout(nil, ripgrepConfigEnv, psEncoderPathEnv)
	}
	// One `sh -c` shares one environment, so a literal that reaches hg at all takes the isolated
	// one; the read-only programs that may share it need nothing beyond PATH.
	if decision.ReadOnlyAuto && permissions.LiteralRunsHg(canonical) {
		env = hgAutoEnv()
	}

	authority, _ := permissions.ClassifyExceptional(req, modeCtx)
	// Execute the exact prefix-stripped command through the shell so accepted redirection and
	// wrapper forms (e.g. `git status > out`, `sh -c "git status"`) run as the agent wrote them.
	spec := runner.RunSpec{
		InvocationID:         run.NewInvocationID(),
		Argv:                 []string{"sh", "-c", literalInput},
		Cwd:                  scope,
		Env:                  env,
		ExceptionalAuthority: authority,
	}
	res, err := run.Exec(context.WithValue(ctx, shellSubjectKey{}, canonical), spec)
	if err != nil {
		return tools.Result{}, err
	}
	return toResult(pipeGroupResult{
		stdout:      res.Stdout,
		stderr:      res.Stderr,
		exitCode:    res.ExitCode,
		duration:    res.Duration,
		stdoutTotal: streamTotal(res.StdoutTotal, res.Stdout),
		stderrTotal: streamTotal(res.StderrTotal, res.Stderr),
	}), nil
}

// dispatchDirect handles a direct pipeline: every stage is authorized before any stage runs, so an
// unauthorized later stage cannot let an earlier authorized stage execute. The stages are handed to
// the batched authorizer as one set — it resolves each without prompting and issues one
// command-level approval for the remainder — and a decision carrying a deny envelope
// denies the whole pipeline: *DeniedError is returned and nothing runs. When every stage authorizes,
// the pipeline runs through runPipeGroup. The group's stdout/exit code and the concatenated
// stderr of every executed stage form the result.
func dispatchDirect(ctx context.Context, stages []permissions.StageNormalization, scope string, home string, batch BatchAuthorizer, run Runner, modeCtx permissions.ModeContext, guard securitystate.Policy, mergedFrom string) (tools.Result, error) {
	if err := verifyStagePrograms(stages, scope, home); err != nil {
		return tools.Result{}, err
	}
	asks, err := refuseReadOnlyStages(stages, scope, home, modeCtx, guard)
	if err != nil {
		return tools.Result{}, err
	}
	var pipeline string
	if len(stages) > 1 {
		sources := make([]string, len(stages))
		for i, stage := range stages {
			sources[i] = stage.Source
		}
		pipeline = strings.Join(sources, " | ")
	}

	// Pass 1: authorize every stage before any runs. A denied stage denies the whole pipeline.
	auto, err := authorizeStages(ctx, stages, scope, home, batch, modeCtx, pipeline, mergedFrom, asks)
	if err != nil {
		return tools.Result{}, err
	}

	// Pass 2: every stage authorized — run the pipe group.
	group, err := runPipeGroup(ctx, stages, auto, scope, home, run, mergedFrom != "")
	if err != nil {
		return tools.Result{}, err
	}
	return toResult(group), nil
}

// authorizeStages returns, per stage, whether the active mode allowed it because it classified
// read-only.
func authorizeStages(ctx context.Context, stages []permissions.StageNormalization, scope string, home string, batch BatchAuthorizer, modeCtx permissions.ModeContext, pipeline string, mergedFrom string, asks []bool) ([]bool, error) {
	reqs := make([]BatchAuthRequest, len(stages))
	for i, stage := range stages {
		req, err := stageRequest(stage, scope, home, modeCtx, pipeline)
		if err != nil {
			return nil, err
		}
		req.ModeCtx.ShellPathAsk = i < len(asks) && asks[i]
		if mergedFrom != "" {
			req.Display.Body = "Whole command: " + mergedFrom
		}
		reqs[i] = req
	}
	decisions, err := batch.AuthorizeBatch(ctx, reqs)
	if err != nil {
		return nil, err
	}
	auto := make([]bool, len(stages))
	for i, decision := range decisions {
		if decision.DenyEnvelope != "" {
			return nil, &DeniedError{Envelope: decision.DenyEnvelope, WrapUp: decision.WrapUp}
		}
		if i < len(auto) {
			auto[i] = decision.ReadOnlyAuto
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	matchReqs := make([]permissions.MatchRequest, len(reqs))
	for i, r := range reqs {
		matchReqs[i] = r.Req
	}
	setShellRequests(ctx, matchReqs)
	return auto, nil
}

func stageRequest(stage permissions.StageNormalization, scope string, home string, modeCtx permissions.ModeContext, pipeline string) (BatchAuthRequest, error) {
	expands := make([]bool, len(stage.Tokens))
	for i := range expands {
		expands[i] = home != "" && i < len(stage.ExecForms) && stage.ExecForms[i].Expand
	}
	subject, err := permissions.DirectStageRequestSubject(stage.Tokens, stage.Assignments, stage.ClearEnvironment, expands)
	if err != nil {
		return BatchAuthRequest{}, err
	}
	stageCtx := modeCtx
	stageCtx.LiteralRoute = false
	stageCtx.Stages = []permissions.StageNormalization{stage}
	return BatchAuthRequest{
		Req: permissions.MatchRequest{
			Kind:             "direct",
			Subject:          subject,
			SubjectTokens:    stage.Tokens,
			Assignments:      stage.Assignments,
			ClearEnvironment: stage.ClearEnvironment,
			PathScope:        scope,
		},
		Display: PromptDisplay{Action: ActionRunCommand, Subject: stage.Source, Pipeline: pipeline},
		ModeCtx: stageCtx,
	}, nil
}

func dispatchStaged(ctx context.Context, stages []permissions.StageNormalization, operators []string, scope string, home string, batch BatchAuthorizer, run Runner, modeCtx permissions.ModeContext, guard securitystate.Policy, mergedFrom string) (tools.Result, error) {
	if err := verifyStagePrograms(stages, scope, home); err != nil {
		return tools.Result{}, err
	}
	asks, err := refuseReadOnlyStages(stages, scope, home, modeCtx, guard)
	if err != nil {
		return tools.Result{}, err
	}
	auto, err := authorizeStages(ctx, stages, scope, home, batch, modeCtx, "", mergedFrom, asks)
	if err != nil {
		return tools.Result{}, err
	}

	var all pipeGroupResult
	for start := 0; start < len(stages); {
		end := start + 1
		for end < len(stages) && operators[end-1] == "|" {
			end++
		}
		if start > 0 && !runsAfter(operators[start-1], all.exitCode) {
			start = end
			continue
		}
		if expired, err := executionExpired(ctx, run); err != nil {
			return tools.Result{}, err
		} else if expired {
			all.exitCode = -1
			return toResult(all), nil
		}
		group, err := runPipeGroup(ctx, stages[start:end], auto[start:end], scope, home, run, start == 0 && mergedFrom != "")
		if err != nil {
			return tools.Result{}, err
		}
		all.stderr = append(all.stderr, group.stderr...)
		all.duration += group.duration
		all.exitCode = group.exitCode
		all.stdout = append(all.stdout, group.stdout...)
		all.stdoutTotal += group.stdoutTotal
		all.stderrTotal += group.stderrTotal
		all.pipeCuts = append(all.pipeCuts, group.pipeCuts...)
		start = end
	}
	return toResult(all), nil
}

type pipeGroupResult struct {
	stdout      []byte
	stderr      []byte
	exitCode    int
	duration    time.Duration
	stdoutTotal int64
	stderrTotal int64
	pipeCuts    []tools.PipeCut
}

type stagePlan struct {
	builtin bool
	result  runner.RunResult
	spec    runner.RunSpec
	subject string
}

// runPipeGroup executes one `|`-joined group for both the direct and the staged route. Only
// ErrPipelineUnsupported from the preflight falls back to the sequential loop; every other preflight
// error returns before any process or event, and a post-launch error returns without retrying, so no
// stage can execute twice.
func runPipeGroup(ctx context.Context, stages []permissions.StageNormalization, autoAllowed []bool, scope string, home string, run Runner, mergeHeadStderr bool) (pipeGroupResult, error) {
	plans, err := planStages(stages, autoAllowed, scope, home, run)
	if err != nil {
		return pipeGroupResult{}, err
	}
	if mergeHeadStderr {
		plans[0].spec.MergeStderr = true
	}
	pipeliner, ok := run.(PipelineRunner)
	specs, streamable := pipelineSpecs(plans)
	if ok && streamable {
		subjects := make([]string, len(plans))
		for i, plan := range plans {
			subjects[i] = plan.subject
		}
		ctx := context.WithValue(ctx, shellStageSubjectsKey{}, subjects)
		err := pipeliner.PreflightPipeline(ctx, specs)
		switch {
		case err == nil:
			started := time.Now()
			results, perr := pipeliner.Pipeline(ctx, specs)
			if perr != nil {
				return pipeGroupResult{}, perr
			}
			return adaptPipelineResults(results, time.Since(started)), nil
		case !errors.Is(err, ErrPipelineUnsupported):
			return pipeGroupResult{}, err
		}
	}
	return runStagesSequentially(ctx, plans, run)
}

func planStages(stages []permissions.StageNormalization, autoAllowed []bool, scope string, home string, run Runner) ([]stagePlan, error) {
	plans := make([]stagePlan, len(stages))
	for i, stage := range stages {
		if res, answered := builtinLookupResult(stage); answered {
			plans[i] = stagePlan{builtin: true, result: res}
			continue
		}
		authority, _ := permissions.ExceptionalAuthority(stage.Tokens)
		spec := runner.RunSpec{
			InvocationID:         run.NewInvocationID(),
			Argv:                 execArgv(stage, home),
			Cwd:                  scope,
			Assignments:          stage.Assignments,
			ExceptionalAuthority: authority,
		}
		// a direct stage's leading KEY=VALUE assignments are stripped from the authorization
		// subject but must still take effect when the stage runs, so an accepted command like
		// `FOO=bar ls` executes with FOO=bar rather than the parent environment alone. Layer them over
		// the inherited environment (later duplicates win in exec, matching shell override semantics).
		// An `env -i` stage instead takes its assignments as the whole environment. A stage with no
		// assignments and no clear state leaves Env nil so the runner inherits the parent environment.
		pinName, pin := probeEnvPin(stage)
		switch {
		case stage.ClearEnvironment && pin != "":
			spec.Env = append(slices.Clone(stage.Assignments), pin)
		case stage.ClearEnvironment:
			spec.Env = stage.Assignments
		case i < len(autoAllowed) && autoAllowed[i] && stageRunsHg(stage):
			spec.Env = hgAutoEnv()
		case i < len(autoAllowed) && autoAllowed[i] && stageRunsJJ(stage):
			spec.Argv = jjAutoArgv(spec.Argv)
			spec.Env = jjAutoEnv()
		case i < len(autoAllowed) && autoAllowed[i] && stageRunsPS(stage):
			spec.Env = execEnvWithout(nil, psEncoderPathEnv)
		case pin != "" && len(stage.Assignments) > 0:
			spec.Env = execEnvWithout(append(slices.Clone(stage.Assignments), pin), ripgrepConfigEnv, pinName)
		case pin != "":
			spec.Env = execEnvWithout([]string{pin}, pinName)
		case len(stage.Assignments) > 0 || stageRunsRipgrep(stage):
			spec.Env = execEnvWithout(stage.Assignments, ripgrepConfigEnv)
		}
		if i < len(autoAllowed) && autoAllowed[i] && stageRunsGit(stage) {
			spec.Argv = gitAutoArgv(spec.Argv)
		}
		if err := resolveArgv0FromChildPath(&spec, stage); err != nil {
			return nil, err
		}
		req, err := stageRequest(stage, scope, home, permissions.ModeContext{}, "")
		if err != nil {
			return nil, err
		}
		plans[i] = stagePlan{spec: spec, subject: req.Req.Subject}
	}
	return plans, nil
}

func pipelineSpecs(plans []stagePlan) ([]runner.RunSpec, bool) {
	if len(plans) < 2 {
		return nil, false
	}
	specs := make([]runner.RunSpec, len(plans))
	for i, plan := range plans {
		if plan.builtin || plan.spec.MergeStderr {
			return nil, false
		}
		specs[i] = plan.spec
	}
	return specs, true
}

// adaptPipelineResults takes elapsed rather than summing the per-stage durations because concurrent
// stages overlap, so their sum overstates how long the group took.
func adaptPipelineResults(results []runner.PipelineResult, elapsed time.Duration) pipeGroupResult {
	group := pipeGroupResult{duration: elapsed}
	for _, res := range results {
		group.stderr = append(group.stderr, res.Stderr...)
		group.stderrTotal += streamTotal(res.StderrTotal, res.Stderr)
	}
	if last := len(results) - 1; last >= 0 {
		group.stdout = results[last].Stdout
		group.exitCode = results[last].ExitCode
		group.stdoutTotal = streamTotal(results[last].StdoutTotal, results[last].Stdout)
	}
	return group
}

type pipeHeadKey struct{}

type pipeHead struct{ ranOutside bool }

func IsPipeHead(ctx context.Context) bool {
	_, ok := ctx.Value(pipeHeadKey{}).(*pipeHead)
	return ok
}

func MarkPipeHeadOutside(ctx context.Context) {
	if head, ok := ctx.Value(pipeHeadKey{}).(*pipeHead); ok {
		head.ranOutside = true
	}
}

type feedsPipeKey struct{}

func FeedsPipe(ctx context.Context) bool {
	return ctx.Value(feedsPipeKey{}) != nil
}

func runStagesSequentially(ctx context.Context, plans []stagePlan, run Runner) (pipeGroupResult, error) {
	var group pipeGroupResult
	var stdin []byte
	var stdinTotal int64
	var head pipeHead
	var headExitCode int
	for i, plan := range plans {
		if expired, err := executionExpired(ctx, run); err != nil {
			return pipeGroupResult{}, err
		} else if expired {
			group.exitCode = -1
			return group, nil
		}
		res := plan.result
		if !plan.builtin {
			spec := plan.spec
			spec.Stdin = stdin
			var err error
			execCtx := context.WithValue(ctx, shellSubjectKey{}, plan.subject)
			if i == 0 {
				execCtx = context.WithValue(execCtx, pipeHeadKey{}, &head)
			}
			if i+1 < len(plans) && !plans[i+1].builtin {
				execCtx = context.WithValue(execCtx, feedsPipeKey{}, true)
			}
			res, err = run.Exec(execCtx, spec)
			if err != nil {
				return pipeGroupResult{}, err
			}
			if res.LaunchErrCategory == "" && stdinTotal > int64(len(stdin)) {
				group.pipeCuts = append(group.pipeCuts, tools.PipeCut{Command: i + 1, Received: int64(len(stdin)), Total: stdinTotal})
			}
		}
		// Non-zero exits and launch failures are result-level outcomes: keep chaining.
		// stderr from every executed stage is accumulated in order.
		group.stderr = append(group.stderr, res.Stderr...)
		group.stderrTotal += streamTotal(res.StderrTotal, res.Stderr)
		group.duration += res.Duration
		group.stdout = res.Stdout
		group.stdoutTotal = streamTotal(res.StdoutTotal, res.Stdout)
		group.exitCode = res.ExitCode
		stdin = res.Stdout
		stdinTotal = group.stdoutTotal
		if i == 0 {
			headExitCode = res.ExitCode
		}
	}
	if head.ranOutside && group.exitCode == 0 {
		group.exitCode = headExitCode
	}
	return group, nil
}

// builtinLookupResult answers an accepted `command -v <name>` stage from the $PATH resolution
// normalization already captured (permissions.StageNormalization.LookupPath), printing it the way
// the shell builtin would. `command` is a builtin with no executable to launch, so the authorized
// lookup is completed here rather than handed to the runner; a second resolution at execution time
// could return a different path than the one that was authorized.
func builtinLookupResult(stage permissions.StageNormalization) (runner.RunResult, bool) {
	if stage.LookupPath == "" {
		return runner.RunResult{}, false
	}
	return runner.RunResult{Stdout: []byte(stage.LookupPath + "\n")}, true
}

func runsAfter(operator string, prevExitCode int) bool {
	switch operator {
	case "&&":
		return prevExitCode == 0
	case "||":
		return prevExitCode != 0
	default:
		return true
	}
}

func onlyStagedOperators(operators []string) bool {
	for _, op := range operators {
		if op != "&&" && op != "||" && op != ";" && op != "|" {
			return false
		}
	}
	return len(operators) > 0
}

// execArgv builds the runner argv for a direct stage, expanding a bare leading `~` / `$HOME`
// against home for execution only (StageNormalization.ExecForms). The canonical stage.Tokens —
// used as the authorization subject — are left untouched, so a stored grant still holds the
// literal `~`/`$HOME` form. Expansion is skipped when home is empty (leaving the
// literal token, which fails as it did before) so an unresolved home never yields a bare-root path.
// A stage with no expandable token returns stage.Tokens unchanged.
func execArgv(stage permissions.StageNormalization, home string) []string {
	argv := stage.Tokens
	copied := false
	if stage.ExecProgram != "" && len(argv) > 0 {
		argv = append([]string{stage.ExecProgram}, argv[1:]...)
		copied = true
	}
	if home == "" {
		return argv
	}
	for i := range argv {
		if i < len(stage.ExecForms) && stage.ExecForms[i].Expand {
			if !copied {
				argv = append([]string(nil), argv...)
				copied = true
			}
			argv[i] = home + stage.ExecForms[i].Suffix
		}
	}
	return argv
}

// toResult adapts a runner outcome to the shared tools.Result returned to the dispatch caller.
func toResult(group pipeGroupResult) tools.Result {
	return tools.Result{
		ExitCode:    group.exitCode,
		Stdout:      group.stdout,
		Stderr:      group.stderr,
		Duration:    group.duration,
		StdoutTotal: group.stdoutTotal,
		StderrTotal: group.stderrTotal,
		PipeCuts:    group.pipeCuts,
	}
}

// streamTotal takes the held length too because an unbounded Exec reports a zero total.
func streamTotal(runnerTotal int64, held []byte) int64 {
	return max(runnerTotal, int64(len(held)))
}
