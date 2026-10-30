// Raw shell dispatch: normalize a whole command, resolve one request/execution path scope,
// authorize each stage or the literal subject, then run direct pipelines or the
// literal form through the shared runner —.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/tools"
)

// Action header labels the prompt shows above the subject of the action. They are the
// human-readable framing the permission prompt renders instead of the raw subject-kind/subject
// matching internals: a file write shows "Create file"/"Edit file", a file removal "Delete file", a
// directory creation "Create directory", a rename "Move" (over "source -> destination"), any shell command
// "Run command", and any other structured tool the generic "Run tool" fallback — never the bare registered
// tool token. The dispatch producers (tool.go, shell.go) populate them on PromptDisplay.Action.
const (
	ActionCreateFile      = "Create file"
	ActionEditFile        = "Edit file"
	ActionDeleteFile      = "Delete file"
	ActionCreateDirectory = "Create directory"
	// ActionMoveFile heads the move prompt. Its value is the bare verb "Move" (not "Move file") because a
	// move relocates a file or a directory; the "source -> destination" subject already names what moves.
	ActionMoveFile   = "Move"
	ActionRunCommand = "Run command"
	ActionRunTool    = "Run tool"
)

// PromptDisplay is the human-readable permission-prompt payload a dispatch producer builds for one
// authorization, carried separately from the matching permissions.MatchRequest so the prompt can
// render a plain "are you sure?" approval screen without re-parsing the matching subject or the raw
// tool-call JSON. It supersedes the prior lone command-text string:
//   - Action is the header (one of the Action* constants above).
//   - For shell subjects, Subject is effective source text, not the canonical matching subject.
//
// The matching subject and subject kind stay on MatchRequest for grants and the event log
// and are never shown through this payload.
type PromptDisplay struct {
	Action  string
	Subject string
	Body    string
	// OutOfRootFileWrite marks a mutating file prompt whose resolved write target lies outside the project
	// root — a single-target edit/create/mkdir (via outOfRootFileTool) or one out-of-root endpoint of a move
	// (set per authorized scope by dispatchPreparedMultiScope). It re-enables the "allow in this
	// folder permanently" option for those tools only; the prompt UI keys on it to offer a folder grant
	// anchored at the out-of-root folder. It is false (its zero value) for shell, literal, every other
	// structured tool, any in-root edit/create/mkdir, and an in-root move endpoint — so no other out-of-root
	// prompt is broadened. Set only by DispatchTool on the mutating-file dispatch paths; the shell producers
	// leave it unset.
	OutOfRootFileWrite bool
	// OutOfRootReadScope marks a read-only navigation tool (read/glob/grep/list/tree) prompt whose resolved
	// scope lies outside the project root. Like OutOfRootFileWrite it re-enables the folder grant
	// option for that out-of-root scope, but for a read-only grant (subject = the read tool name), so a
	// folder/session/global grant authorizes descendant reads for that tool without ever authorizing a
	// write. It is false for shell, literal, every other tool, the edit/create tools, and any in-project
	// read. Set only by DispatchTool on the read-tool dispatch path (via externalReadTool).
	OutOfRootReadScope bool
	// GrantStoredSubject is the capability subject (permissions.CapabilityWrite "write" or
	// CapabilityRead "read*") a grant should store when this structured-tool prompt is approved with a
	// grant-creating option: create/edit fold to "write" and the five read/search tools fold to
	// "read*", so one approval covers every sibling member tool at the scope. It rides forward to the
	// prompt and back into the stored grant subject while MatchRequest.Subject stays the concrete tool
	// name, so request matching, cache keys, prompt-shown, and mode-auto records are unchanged. Empty for
	// shell, literal, tools that map to no capability, and in-project reads (which never create a grant);
	// an empty value leaves the stored subject the concrete request subject. Set only by DispatchTool.
	GrantStoredSubject string
	// Pipeline is display-only source text for a direct pipeline.
	Pipeline string
	// WholeCommand marks a literal-route prompt as a whole-command approval: Subject is the entire
	// command run verbatim through the shell, not one stage of a direct pipeline. It lets the
	// prompt frame a literal approval distinctly from a per-stage direct approval. True only on the
	// literal route; false for direct stages and every structured tool. Display-only.
	WholeCommand bool
	// RequestedTarget is the lexical path a prepared structured tool was called with, carried
	// separately because a generic tool's Subject is the registered tool name. It is copied from
	// the validated arguments — never parsed out of the rendered JSON, never the resolved target —
	// and is display-only.
	RequestedTarget      string
	HostRequest          string
	DirectHTTPFallback   bool
	ExceptionalAuthority string
}

// Authorizer is the narrow dispatch-local seam over permissions.Authorize. The startup
// layer binds the full permissions.AuthorizeDeps bundle (grant table, turn-scoped cache, prompt
// func, persist func, event emitters) behind a concrete implementation so internal/dispatch need
// not import internal/config, internal/tui, or internal/events. It mirrors the seam
// structured-tool dispatch uses, keeping both dispatch paths free of those collaborators.
type Authorizer interface {
	// Authorize drives one permission check for req to a Decision, prompting the user when no real
	// grant and no turn-cache entry already resolves it. A denied check carries a non-empty
	// Decision.DenyEnvelope; any other returned Decision (once/session/folder/global) authorizes the
	// request. A non-nil error is an internal failure (cancellation, event-emit, prompt error).
	//
	// display is the human-readable prompt payload (action header, subject of the action, verbatim
	// body) carried separately from req because matching keys on req.Subject (the registered tool
	// name for a structured tool, the canonical command otherwise) while the prompt shows a plain
	// action screen. Shell paths pass effective source text in display.Subject; req.Subject
	// remains canonical for matching. The structured-tool path builds it from the decoded tool name
	// and arguments so the prompt shows the file/content for a write rather than the JSON call.
	//
	// modeCtx is the mode-authorization context: the dispatch caller fills the
	// request-derived fields (operation class, tool name, pre-normalization shell stage data,
	// resolved target path) and the production binding overlays the run-scoped active mode and
	// project root before driving permissions.Authorize, where Plan/Build posture is decided.
	Authorize(ctx context.Context, req permissions.MatchRequest, display PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error)
}

// BatchAuthRequest is one pipeline stage handed to BatchAuthorizer.AuthorizeBatch: the same
// (MatchRequest, PromptDisplay, ModeContext) triple a single Authorizer.Authorize call takes. The
// batched authorizer resolves each without prompting and, for the stages that remain, shows one
// command-level approval; each stage stays its own subject (no compound subject), so its grant, cache
// key, and events are identical to the per-stage path.
type BatchAuthRequest struct {
	Req     permissions.MatchRequest
	Display PromptDisplay
	ModeCtx permissions.ModeContext
}

// BatchAuthorizer is the dispatch-local seam over permissions.AuthorizeBatch: it resolves a set
// of pipeline stages without prompting and issues ONE command-level approval for the stages that still
// need a prompt, applying that single outcome to them all (the presentation complement to the
// per-stage Authorizer). It is a SEPARATE seam from Authorizer — not a new method on it — so an
// authorizer that does not batch prompts needs no batched-prompt stub: dispatch bridges it through
// perStageBatchAuthorizer. The production authorizer (internal/bootstrap) implements it, and
// dispatchDirect and dispatchStaged authorize every pipeline's stages through it. The returned
// decisions are index-aligned with reqs; any decision carrying a non-empty DenyEnvelope denies the
// whole pipeline.
type BatchAuthorizer interface {
	AuthorizeBatch(ctx context.Context, reqs []BatchAuthRequest) ([]permissions.Decision, error)
}

// Runner is the dispatch-local seam over the shared command runner (runner.Runner satisfies it). It is
// mirrored here so shell dispatch can be tested with a fake runner without depending on the
// concrete DirectExecRunner. Every RunSpec passed to Exec must carry an InvocationID minted by
// NewInvocationID, which the runner validates before launching.
type Runner interface {
	// NewInvocationID mints a fresh UUIDv7 invocation id for one command invocation.
	NewInvocationID() string
	// Exec runs a single command (no shell interpretation, no chaining) and returns its result.
	Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error)
}

// ErrPipelineUnsupported is the sentinel a PipelineRunner's preflight returns when it cannot run the
// stages as one pipeline, sending the pipe group to the sequential Exec loop instead.
var ErrPipelineUnsupported = runner.ErrPipelineUnsupported

// PipelineRunner is the dispatch-local mirror of runner.PipelineRunner: the optional capability a
// Runner may also implement to run a pipe group's stages concurrently over OS pipes. It carries no
// capture bound because the implementer owns it.
type PipelineRunner interface {
	PreflightPipeline(ctx context.Context, specs []runner.RunSpec) error
	Pipeline(ctx context.Context, specs []runner.RunSpec) ([]runner.PipelineResult, error)
}

// ExecutionClock is the optional capability a Runner may also implement to own one execution budget
// per shell command. ExecutionContext starts the budget on its first call, which dispatch makes only
// after authorization, and returns the context every later execution of the command shares.
type ExecutionClock interface {
	ExecutionContext(ctx context.Context) context.Context
}

func executionExpired(ctx context.Context, run Runner) (bool, error) {
	clock, ok := run.(ExecutionClock)
	if !ok {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return clock.ExecutionContext(ctx).Err() != nil, nil
}

// UnsupportedConstructError reports a shell command rejected by pipeline splitting because it uses a construct
// outside the allowlist: `$`, a backtick, or a bare newline. Bare simple compounds route onto the
// literal/compound path, so `&&`, `;`, and `||` are absent here.
// Such a command short-circuits with this error to the agent — no prompt is shown and no grant can
// authorize it. Construct names the refused construct for the agent-facing message.
type UnsupportedConstructError struct {
	Construct string
}

func (e *UnsupportedConstructError) Error() string {
	return fmt.Sprintf("unsupported_shell_construct: %s", e.Construct)
}

// MalformedCommandError reports a shell command codemeld could not parse or resolve before
// authorization: a split or canonicalization failure, a model-supplied `cd` prefix naming a path
// that will not resolve, or a direct or staged stage whose program is not found. Like
// UnsupportedConstructError no prompt is shown and no grant can authorize it, so the caller delivers
// the wrapped reason to the agent as the tool result rather than failing the turn. Scope resolution without a `cd` hint, authorization, and execution
// failures are infrastructure faults and are never wrapped in it.
type MalformedCommandError struct {
	Err error
}

func (e *MalformedCommandError) Error() string {
	return e.Err.Error()
}

func (e *MalformedCommandError) Unwrap() error {
	return e.Err
}

// DeniedError reports that authorization denied the shell command. Envelope is the
// synthetic deny-reason tool-error envelope (built by permissions.BuildDenyEnvelope), which the
// caller delivers to the agent as the tool result. A denied command is never executed; the error
// signals the refusal without producing a tools.Result that the tool_exec_* events would otherwise
// log as command output. The same shape serves a single denied literal subject and a denied pipeline
// stage.
type DeniedError struct {
	Envelope string
	WrapUp   bool
}

func (e *DeniedError) Error() string {
	return "shell command denied by permission prompt"
}

// DispatchShell normalizes, authorizes, and runs one raw shell command from the agent.
// It performs no pattern-based shell-to-structured-tool rewriting: a raw command always goes
// through the shell path. input is the verbatim command; home anchors ~ expansion during path-scope
// resolution; processCWD is codemeld's working directory; authorizer and runner are the bound
// permission and command-runner seams.
func DispatchShell(ctx context.Context, input string, home string, processCWD string, authorizer Authorizer, runner Runner, guard ...securitystate.Policy) (tools.Result, error) {
	policy := guardPolicy(guard)
	policy.Blocked = policy.Blocked.Current()
	split, err := permissions.SplitCommand(input)
	if err != nil {
		return tools.Result{}, &MalformedCommandError{Err: err}
	}

	// a rejected construct is refused before any prompt or path resolution — no grant can
	// authorize it, so the agent gets the error directly.
	if !split.AllowedShell {
		return tools.Result{}, &UnsupportedConstructError{Construct: split.RejectedConstruct}
	}

	// resolve one cleaned absolute request scope reused for both authorization
	// (MatchRequest.PathScope) and execution (RunSpec.Cwd) so dispatch never authorizes one directory
	// while running in another. Both direct and literal shell requests pass subject kind "direct"
	// with no tool cwd. A scope-resolution error returns before prompting.
	scope, err := permissions.DerivePathScope(home, split.CdHint, processCWD, "", "direct")
	if err != nil {
		// Only a hint the model wrote is command shape; with no hint this resolved codemeld's own
		// process directory, which no rewritten command can fix.
		if split.CdHint != "" {
			return tools.Result{}, &MalformedCommandError{Err: err}
		}
		return tools.Result{}, err
	}

	modeCtx := permissions.ModeContext{
		Class:        permissions.ClassMutating,
		Stages:       split.Stages,
		LiteralRoute: split.LiteralRoute,
	}

	if split.LiteralRoute {
		if wrapped, stages, operators, ok := permissions.SimpleCompoundStages(split.LiteralInput); ok && !wrapped && onlyStagedOperators(operators) {
			batch, ok := authorizer.(BatchAuthorizer)
			if !ok {
				batch = perStageBatchAuthorizer{authorizer}
			}
			return dispatchStaged(ctx, stages, operators, scope, home, batch, runner, modeCtx, policy)
		}
		ask, err := refuseReadOnlyLiteral(split.LiteralInput, scope, home, modeCtx, policy)
		if err != nil {
			return tools.Result{}, err
		}
		modeCtx.ShellPathAsk = ask
		return dispatchLiteral(ctx, split.LiteralInput, scope, authorizer, runner, modeCtx)
	}
	// A direct pipeline authorizes its stages through the batched seam so its remaining
	// (non-read-only) stages can resolve into one command-level approval. Batching is a
	// TUI presentation feature: the interactive authorizer implements BatchAuthorizer and renders the
	// single command-level prompt, while an authorizer that does not (the headless fail-closed/terminal
	// authorizer, test fakes) is bridged to the same seam by perStageBatchAuthorizer, which keeps the
	// exact per-stage authorize-in-order-stop-at-first-deny behavior with no batched prompt.
	batch, ok := authorizer.(BatchAuthorizer)
	if !ok {
		batch = perStageBatchAuthorizer{authorizer}
	}
	return dispatchDirect(ctx, split.Stages, scope, home, batch, runner, modeCtx, policy)
}

func refuseReadOnlyLiteral(literalInput string, scope string, home string, modeCtx permissions.ModeContext, guard securitystate.Policy) (bool, error) {
	if guard.Blocked == nil {
		return false, nil
	}
	canonical, err := permissions.CanonicalLiteralForm(literalInput)
	if err != nil {
		return false, nil
	}
	if !permissions.ReadOnlyShell(permissions.MatchRequest{Kind: "literal", Subject: canonical, PathScope: scope}, modeCtx) {
		return false, nil
	}
	stages := permissions.LiteralStages(canonical)
	var candidates []string
	for _, stage := range stages {
		candidates = append(candidates, permissions.ShellPathCandidates(execArgv(stage, home), scope, home)...)
	}
	if refusal := guard.RefuseShell("literal", canonical, scope, candidates); refusal != nil {
		refusal.ArgumentHash = permissions.ComputeArgumentHash(canonical)
		return false, refusal
	}
	for _, stage := range stages {
		argv := execArgv(stage, home)
		if permissions.LiteralRewriteAsks(stage, scope) || permissions.ShellPathAsks(guard.Blocked, scope, argv, permissions.ShellPathCandidates(argv, scope, home)) {
			return true, nil
		}
	}
	return false, nil
}

func refuseReadOnlyStages(stages []permissions.StageNormalization, scope string, home string, modeCtx permissions.ModeContext, guard securitystate.Policy) ([]bool, error) {
	if guard.Blocked == nil {
		return nil, nil
	}
	readOnlyArgv := make([][]string, len(stages))
	for i, stage := range stages {
		req, err := stageRequest(stage, scope, home, modeCtx, "")
		if err != nil {
			return nil, err
		}
		if !permissions.ReadOnlyShell(req.Req, req.ModeCtx) {
			continue
		}
		readOnlyArgv[i] = execArgv(stage, home)
		refusal := guard.RefuseShell("direct", strings.Join(stage.Tokens, " "), scope, permissions.ShellPathCandidates(readOnlyArgv[i], scope, home))
		if refusal != nil {
			refusal.DirectRequestSubject = req.Req.Subject
			return nil, refusal
		}
	}
	asks := make([]bool, len(stages))
	for i, argv := range readOnlyArgv {
		asks[i] = argv != nil && permissions.ShellPathAsks(guard.Blocked, scope, argv, permissions.ShellPathCandidates(argv, scope, home))
	}
	return asks, nil
}

// perStageBatchAuthorizer adapts a plain Authorizer to the BatchAuthorizer seam for authorizers that
// do not batch prompts (headless, tests). It authorizes each stage in order through the single
// Authorize call and stops at the first denied stage — nothing at or after a deny is authorized —
// which is the per-stage pipeline behavior dispatchDirect had before the batched seam. Only the
// interactive TUI authorizer implements BatchAuthorizer directly to fold the remaining stages into one
// command-level prompt; every other authorizer keeps this per-stage flow.
type perStageBatchAuthorizer struct{ Authorizer }

func (p perStageBatchAuthorizer) AuthorizeBatch(ctx context.Context, reqs []BatchAuthRequest) ([]permissions.Decision, error) {
	decisions := make([]permissions.Decision, len(reqs))
	for i, r := range reqs {
		decision, err := p.Authorize(ctx, r.Req, r.Display, r.ModeCtx)
		if err != nil {
			return nil, err
		}
		decisions[i] = decision
		if decision.DenyEnvelope != "" {
			break
		}
	}
	return decisions, nil
}

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
	res, err := run.Exec(ctx, spec)
	if err != nil {
		return tools.Result{}, err
	}
	return toResult(res.Stdout, res.Stderr, res.ExitCode, res.Duration), nil
}

// dispatchDirect handles a direct pipeline: every stage is authorized before any stage runs, so an
// unauthorized later stage cannot let an earlier authorized stage execute. The stages are handed to
// the batched authorizer as one set — it resolves each without prompting and issues one
// command-level approval for the remainder — and a decision carrying a deny envelope
// denies the whole pipeline: *DeniedError is returned and nothing runs. When every stage authorizes,
// the pipeline runs through runPipeGroup. The final stage's stdout/exit code and the concatenated
// stderr of every executed stage form the result.
func dispatchDirect(ctx context.Context, stages []permissions.StageNormalization, scope string, home string, batch BatchAuthorizer, run Runner, modeCtx permissions.ModeContext, guard securitystate.Policy) (tools.Result, error) {
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
	auto, err := authorizeStages(ctx, stages, scope, home, batch, modeCtx, pipeline, asks)
	if err != nil {
		return tools.Result{}, err
	}

	// Pass 2: every stage authorized — run the pipe group.
	group, err := runPipeGroup(ctx, stages, auto, scope, home, run)
	if err != nil {
		return tools.Result{}, err
	}
	return toResult(group.stdout, group.stderr, group.exitCode, group.duration), nil
}

// authorizeStages returns, per stage, whether the active mode allowed it because it classified
// read-only.
func authorizeStages(ctx context.Context, stages []permissions.StageNormalization, scope string, home string, batch BatchAuthorizer, modeCtx permissions.ModeContext, pipeline string, asks []bool) ([]bool, error) {
	reqs := make([]BatchAuthRequest, len(stages))
	for i, stage := range stages {
		req, err := stageRequest(stage, scope, home, modeCtx, pipeline)
		if err != nil {
			return nil, err
		}
		req.ModeCtx.ShellPathAsk = i < len(asks) && asks[i]
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

func dispatchStaged(ctx context.Context, stages []permissions.StageNormalization, operators []string, scope string, home string, batch BatchAuthorizer, run Runner, modeCtx permissions.ModeContext, guard securitystate.Policy) (tools.Result, error) {
	if err := verifyStagePrograms(stages, scope, home); err != nil {
		return tools.Result{}, err
	}
	asks, err := refuseReadOnlyStages(stages, scope, home, modeCtx, guard)
	if err != nil {
		return tools.Result{}, err
	}
	auto, err := authorizeStages(ctx, stages, scope, home, batch, modeCtx, "", asks)
	if err != nil {
		return tools.Result{}, err
	}

	var stdout []byte
	var stderr []byte
	var duration time.Duration
	exitCode := 0
	for start := 0; start < len(stages); {
		end := start + 1
		for end < len(stages) && operators[end-1] == "|" {
			end++
		}
		if start > 0 && !runsAfter(operators[start-1], exitCode) {
			start = end
			continue
		}
		if expired, err := executionExpired(ctx, run); err != nil {
			return tools.Result{}, err
		} else if expired {
			return toResult(stdout, stderr, -1, duration), nil
		}
		group, err := runPipeGroup(ctx, stages[start:end], auto[start:end], scope, home, run)
		if err != nil {
			return tools.Result{}, err
		}
		stderr = append(stderr, group.stderr...)
		duration += group.duration
		exitCode = group.exitCode
		stdout = append(stdout, group.stdout...)
		start = end
	}
	return toResult(stdout, stderr, exitCode, duration), nil
}

type pipeGroupResult struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	duration time.Duration
}

type stagePlan struct {
	builtin bool
	result  runner.RunResult
	spec    runner.RunSpec
}

// runPipeGroup executes one `|`-joined group for both the direct and the staged route. Only
// ErrPipelineUnsupported from the preflight falls back to the sequential loop; every other preflight
// error returns before any process or event, and a post-launch error returns without retrying, so no
// stage can execute twice.
func runPipeGroup(ctx context.Context, stages []permissions.StageNormalization, autoAllowed []bool, scope string, home string, run Runner) (pipeGroupResult, error) {
	plans, err := planStages(stages, autoAllowed, scope, home, run)
	if err != nil {
		return pipeGroupResult{}, err
	}
	pipeliner, ok := run.(PipelineRunner)
	specs, streamable := pipelineSpecs(plans)
	if ok && streamable {
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
		if err := resolveArgv0FromChildPath(&spec, stage); err != nil {
			return nil, err
		}
		plans[i] = stagePlan{spec: spec}
	}
	return plans, nil
}

// resolveArgv0FromChildPath pins Argv[0] to the executable the stage's own PATH selects, because the
// runner's exec resolves a bare argv against codemeld's PATH — the wrong environment for a stage that
// cleared it or set its own. Only a stage that clears the environment or assigns PATH is resolved,
// and only over the absolute entries of the computed child PATH in order: a relative entry would be
// resolved against the run directory, so one grant would authorize a different file at every
// descendant of its path scope. A stage whose program cannot be found there fails here rather than
// falling back to codemeld's PATH.
func resolveArgv0FromChildPath(spec *runner.RunSpec, stage permissions.StageNormalization) error {
	if !stage.ClearEnvironment && !assignsPath(stage.Assignments) {
		return nil
	}
	program := spec.Argv[0]
	if filepath.Base(program) != program {
		return nil
	}
	resolved, ok := lookPathEntries(childEnvValue(spec.Env, "PATH"), program)
	if !ok {
		return fmt.Errorf("dispatch: %q not found in the requested PATH", program)
	}
	argv := slices.Clone(spec.Argv)
	argv[0] = resolved
	spec.Argv = argv
	return nil
}

func lookPathEntries(pathValue string, program string) (string, bool) {
	for _, dir := range strings.Split(pathValue, string(os.PathListSeparator)) {
		if !filepath.IsAbs(dir) {
			continue
		}
		if resolved, err := exec.LookPath(filepath.Join(dir, program)); err == nil {
			return resolved, true
		}
	}
	return "", false
}

func verifyStagePrograms(stages []permissions.StageNormalization, scope string, home string) error {
	for i, stage := range stages {
		if _, answered := builtinLookupResult(stage); answered {
			continue
		}
		program := execArgv(stage, home)[0]
		if !stageProgramResolves(stage, program, scope) {
			return &MalformedCommandError{Err: fmt.Errorf("shell stage %d: program %q not found", i, program)}
		}
	}
	return nil
}

// stageProgramResolves mirrors how the runner launches argv[0]: a separator-bearing name is opened
// relative to the stage's working directory with no PATH search, and a bare name is searched on the
// PATH the stage runs with.
func stageProgramResolves(stage permissions.StageNormalization, program string, scope string) bool {
	if stage.ProgramUnescapedSeparator {
		return true
	}
	if filepath.Base(program) != program {
		if !filepath.IsAbs(program) {
			program = filepath.Join(scope, program)
		}
		info, err := os.Stat(program)
		return err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0
	}
	if stage.ClearEnvironment || assignsPath(stage.Assignments) {
		_, ok := lookPathEntries(childEnvValue(stage.Assignments, "PATH"), program)
		return ok
	}
	_, err := exec.LookPath(program)
	return err == nil
}

func assignsPath(assignments []string) bool {
	return slices.ContainsFunc(assignments, func(a string) bool { return strings.HasPrefix(a, "PATH=") })
}

// childEnvValue reports the value the child process sees for name. The last entry wins, matching how
// exec resolves a duplicated variable.
func childEnvValue(env []string, name string) string {
	value := ""
	for _, entry := range env {
		if rest, ok := strings.CutPrefix(entry, name+"="); ok {
			value = rest
		}
	}
	return value
}

// ripgrepConfigEnv names the file ripgrep reads extra options from. Those options include
// `--pre=COMMAND`, so an inherited value runs a program the authorized argv never named.
const ripgrepConfigEnv = "RIPGREP_CONFIG_PATH"

// psEncoderPathEnv names the FreeBSD libxo encoder search path. An inherited value can make an
// otherwise automatic ps invocation load an encoder absent from the authorized argv.
const psEncoderPathEnv = "XO_ENCODER_PATH"

func stageRunsRipgrep(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "rg"
}

func stageRunsPS(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "ps"
}

// Under Go's default GOTOOLCHAIN=auto, even `go version` inside a module that asks for a newer Go
// downloads and runs that toolchain.
const goToolchainEnv = "GOTOOLCHAIN"

func stageRunsGoProbe(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "go" && permissions.ProbeStageReadOnly(stage.Tokens)
}

// `mise version` checks online for a newer mise about once a day unless it runs offline.
const miseOfflineEnv = "MISE_OFFLINE"

func stageRunsMiseProbe(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "mise" && permissions.ProbeStageReadOnly(stage.Tokens)
}

func probeEnvPin(stage permissions.StageNormalization) (name string, assignment string) {
	switch {
	case stageRunsGoProbe(stage):
		name, assignment = goToolchainEnv, goToolchainEnv+"=local"
	case stageRunsMiseProbe(stage):
		name, assignment = miseOfflineEnv, miseOfflineEnv+"=1"
	default:
		return "", ""
	}
	if slices.ContainsFunc(stage.Assignments, func(a string) bool { return strings.HasPrefix(a, name+"=") }) {
		return "", ""
	}
	return name, assignment
}

func stageRunsHg(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "hg"
}

// hgAutoEnv is the whole environment a mode-auto-allowed Mercurial process runs with. hg reads
// aliases, hooks, defaults, and extensions from configuration the approved argv never names, and
// HGPLAIN alone does not stop them, so nothing ambient survives: HGRCPATH and HGRCSKIPREPO drop the
// user and repository hgrc files, and PATH is preserved only so executables still resolve.
func hgAutoEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HGRCPATH=" + os.DevNull,
		"HGRCSKIPREPO=1",
		"HGPLAIN=+strictflags",
	}
}

func stageRunsJJ(stage permissions.StageNormalization) bool {
	return len(stage.Tokens) > 0 && stage.Tokens[0] == "jj"
}

// jjAutoEnv is the whole environment a mode-auto-allowed Jujutsu process runs with: JJ_CONFIG= drops
// the user and system configuration files, JJ_PAGER cannot reach the child at all, and PATH is
// preserved only so executables still resolve. No environment variable disables jj's repository or
// workspace configuration, so jjAutoFlags carries the rest.
func jjAutoEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"JJ_CONFIG=",
	}
}

// jjAutoFlags is the isolation jjAutoEnv cannot express. A command-line --config outranks every
// configuration file, which is the only way to stop a repository-configured ui.pager or
// ui.diff-formatter from launching a program; --ignore-working-copy keeps the read from writing a
// working-copy commit or an operation.
var jjAutoFlags = []string{
	"--no-pager",
	"--config", "ui.paginate=never",
	"--config", `ui.diff-formatter=":color-words"`,
	"--ignore-working-copy",
}

func jjAutoArgv(argv []string) []string {
	prefixed := make([]string, 0, len(argv)+len(jjAutoFlags))
	prefixed = append(prefixed, argv[0])
	prefixed = append(prefixed, jjAutoFlags...)
	return append(prefixed, argv[1:]...)
}

func execEnvWithout(assignments []string, excluded ...string) []string {
	env := os.Environ()
	kept := env[:0]
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if slices.Contains(excluded, name) {
			continue
		}
		kept = append(kept, entry)
	}
	return append(kept, assignments...)
}

func pipelineSpecs(plans []stagePlan) ([]runner.RunSpec, bool) {
	if len(plans) < 2 {
		return nil, false
	}
	specs := make([]runner.RunSpec, len(plans))
	for i, plan := range plans {
		if plan.builtin {
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
	}
	if last := len(results) - 1; last >= 0 {
		group.stdout = results[last].Stdout
		group.exitCode = results[last].ExitCode
	}
	return group
}

func runStagesSequentially(ctx context.Context, plans []stagePlan, run Runner) (pipeGroupResult, error) {
	var group pipeGroupResult
	var stdin []byte
	for _, plan := range plans {
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
			res, err = run.Exec(ctx, spec)
			if err != nil {
				return pipeGroupResult{}, err
			}
		}
		// Non-zero exits and launch failures are result-level outcomes: keep chaining and carry the
		// final stage's exit code. stderr from every executed stage is accumulated in order.
		group.stderr = append(group.stderr, res.Stderr...)
		group.duration += res.Duration
		group.stdout = res.Stdout
		group.exitCode = res.ExitCode
		stdin = res.Stdout
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
	if home == "" {
		return stage.Tokens
	}
	var argv []string
	for i := range stage.Tokens {
		if i < len(stage.ExecForms) && stage.ExecForms[i].Expand {
			if argv == nil {
				argv = append([]string(nil), stage.Tokens...)
			}
			argv[i] = home + stage.ExecForms[i].Suffix
		}
	}
	if argv == nil {
		return stage.Tokens
	}
	return argv
}

// toResult adapts a runner outcome to the shared tools.Result returned to the dispatch caller.
func toResult(stdout, stderr []byte, exitCode int, duration time.Duration) tools.Result {
	return tools.Result{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: duration,
	}
}
