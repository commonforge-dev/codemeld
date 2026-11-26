// Raw shell dispatch: normalize a whole command, resolve one request/execution path scope,
// authorize each stage or the literal subject, then run direct pipelines or the
// literal form through the shared runner —.
package dispatch

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

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

type ConfinementReporter interface {
	Confined(ctx context.Context) (bool, error)
}

// OutsideEntryMatcher is asked before authorization to choose a route, so an implementation must
// only read state.
type OutsideEntryMatcher interface {
	MatchOutsideEntry(ctx context.Context, req permissions.MatchRequest) (entry string, ok bool)
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
// that will not resolve, a direct or staged stage whose program is not found, or a call that would keep
// a saved outside-sandbox command in the sandbox. Like
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

type shellCall struct {
	mu       sync.Mutex
	outside  map[string]bool
	requests []permissions.MatchRequest
}

type shellCallKey struct{}

type shellSubjectKey struct{}

type shellStageSubjectsKey struct{}

// ShellStageSubjects names the request subject of each spec handed to PreflightPipeline, in order.
func ShellStageSubjects(ctx context.Context) []string {
	subjects, _ := ctx.Value(shellStageSubjectsKey{}).([]string)
	return subjects
}

func MarkRunOutside(ctx context.Context, subject string) {
	call, ok := ctx.Value(shellCallKey{}).(*shellCall)
	if !ok {
		return
	}
	call.mu.Lock()
	defer call.mu.Unlock()
	call.outside[subject] = true
}

func setShellRequests(ctx context.Context, reqs []permissions.MatchRequest) {
	call, ok := ctx.Value(shellCallKey{}).(*shellCall)
	if !ok {
		return
	}
	call.mu.Lock()
	defer call.mu.Unlock()
	call.requests = reqs
}

// ShellRequests returns every authorized request of the current shell call, so a runner that sees
// one pipeline stage at a time can still judge the whole call.
func ShellRequests(ctx context.Context) []permissions.MatchRequest {
	call, ok := ctx.Value(shellCallKey{}).(*shellCall)
	if !ok {
		return nil
	}
	call.mu.Lock()
	defer call.mu.Unlock()
	return slices.Clone(call.requests)
}

func ShellSubject(ctx context.Context) string {
	subject, _ := ctx.Value(shellSubjectKey{}).(string)
	return subject
}

func TakeRunOutside(ctx context.Context) bool {
	call, ok := ctx.Value(shellCallKey{}).(*shellCall)
	subject, named := ctx.Value(shellSubjectKey{}).(string)
	if !ok || !named {
		return false
	}
	call.mu.Lock()
	defer call.mu.Unlock()
	marked := call.outside[subject]
	delete(call.outside, subject)
	return marked
}

// DispatchShell normalizes, authorizes, and runs one raw shell command from the agent.
// It performs no pattern-based shell-to-structured-tool rewriting: a raw command always goes
// through the shell path. input is the verbatim command; home anchors ~ expansion during path-scope
// resolution; processCWD is codemeld's working directory; authorizer and runner are the bound
// permission and command-runner seams.
func DispatchShell(ctx context.Context, input string, home string, processCWD string, authorizer Authorizer, runner Runner, guard ...securitystate.Policy) (tools.Result, error) {
	ctx = context.WithValue(ctx, shellCallKey{}, &shellCall{outside: map[string]bool{}})
	policy := guardPolicy(guard)
	policy.Blocked = policy.Blocked.Current()
	split, err := permissions.SplitCommand(input)
	if err != nil {
		return tools.Result{}, &MalformedCommandError{Err: err}
	}

	// Outside a confined run a rejected construct is refused before any prompt or path resolution — no
	// grant can authorize it, so the agent gets the error directly.
	if !split.AllowedShell {
		confined, err := runsConfined(ctx, runner)
		if err != nil {
			return tools.Result{}, err
		}
		if !confined {
			return tools.Result{}, &UnsupportedConstructError{Construct: split.RejectedConstruct}
		}
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
	resolveStagePrograms(split.Stages, scope)

	modeCtx := permissions.ModeContext{
		Class:        permissions.ClassMutating,
		Stages:       split.Stages,
		LiteralRoute: split.LiteralRoute || !split.AllowedShell,
	}

	if !split.AllowedShell {
		ask, err := refuseReadOnlyLiteral(split.LiteralInput, scope, home, modeCtx, policy)
		if err != nil {
			return tools.Result{}, err
		}
		modeCtx.ShellPathAsk = ask
		return dispatchLiteral(ctx, split.LiteralInput, scope, authorizer, runner, modeCtx)
	}
	if split.LiteralRoute {
		if wrapped, stages, operators, ok := permissions.SimpleCompoundStages(split.LiteralInput); ok && !wrapped && onlyStagedOperators(operators) {
			resolveStagePrograms(stages, scope)
			reroute, err := confinedStagesNeedShell(ctx, runner, stages, scope, home)
			if err != nil {
				return tools.Result{}, err
			}
			if reroute {
				return dispatchConfinedShell(ctx, split.LiteralInput, stages, scope, home, authorizer, runner, modeCtx, policy)
			}
			if err := refusePipedEntry(ctx, runner, stages, operators, scope, home); err != nil {
				return tools.Result{}, err
			}
			batch, ok := authorizer.(BatchAuthorizer)
			if !ok {
				batch = perStageBatchAuthorizer{authorizer}
			}
			return dispatchStaged(ctx, stages, operators, scope, home, batch, runner, modeCtx, policy, "")
		}
		if stages, operators, ok := savedMergedStages(ctx, runner, split.LiteralInput, scope, home); ok {
			if err := refusePipedEntry(ctx, runner, stages, operators, scope, home); err != nil {
				return tools.Result{}, err
			}
			batch, ok := authorizer.(BatchAuthorizer)
			if !ok {
				batch = perStageBatchAuthorizer{authorizer}
			}
			mergedFrom := strings.TrimSpace(input)
			if len(operators) == 0 {
				return dispatchDirect(ctx, stages, scope, home, batch, runner, modeCtx, policy, mergedFrom)
			}
			return dispatchStaged(ctx, stages, operators, scope, home, batch, runner, modeCtx, policy, mergedFrom)
		}
		if err := refuseLiteralEntry(ctx, runner, split.LiteralInput, scope, home); err != nil {
			return tools.Result{}, err
		}
		ask, err := refuseReadOnlyLiteral(split.LiteralInput, scope, home, modeCtx, policy)
		if err != nil {
			return tools.Result{}, err
		}
		modeCtx.ShellPathAsk = ask
		return dispatchLiteral(ctx, split.LiteralInput, scope, authorizer, runner, modeCtx)
	}
	reroute, err := confinedStagesNeedShell(ctx, runner, split.Stages, scope, home)
	if err != nil {
		return tools.Result{}, err
	}
	if reroute {
		return dispatchConfinedShell(ctx, split.LiteralInput, split.Stages, scope, home, authorizer, runner, modeCtx, policy)
	}
	if err := refusePipedEntry(ctx, runner, split.Stages, nil, scope, home); err != nil {
		return tools.Result{}, err
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
	return dispatchDirect(ctx, split.Stages, scope, home, batch, runner, modeCtx, policy, "")
}

func savedMergedStages(ctx context.Context, run Runner, command string, scope string, home string) ([]permissions.StageNormalization, []string, bool) {
	matcher, ok := run.(OutsideEntryMatcher)
	if !ok {
		return nil, nil, false
	}
	saved, rest, piped := strings.Cut(command, " 2>&1 | ")
	if !piped {
		var found bool
		if saved, found = strings.CutSuffix(command, " 2>&1"); !found {
			return nil, nil, false
		}
	}
	head, err := permissions.SplitCommand(saved)
	// SplitCommand trims characters the shell keeps in a word and can strip even an empty cd prefix.
	if err != nil || len(head.Stages) != 1 || head.LiteralInput != strings.Trim(saved, " \t") ||
		len(head.Stages[0].Assignments) > 0 || head.Stages[0].ClearEnvironment {
		return nil, nil, false
	}
	stages, parsedIn := head.Stages, permissions.StageSolo
	var operators []string
	if piped {
		var wrapped bool
		wrapped, stages, operators, ok = permissions.SimpleCompoundStages(saved + " | " + rest)
		if !ok || wrapped || !onlyStagedOperators(operators) {
			return nil, nil, false
		}
		parsedIn = permissions.StageInCompound
	}
	for _, stage := range stages {
		// StageNeedsShell reads Source, whose trimming can change the stage's last word.
		parsed, err := permissions.NormalizeDirectStage(stage.Source, parsedIn)
		if err != nil || !slices.Equal(parsed.Tokens, stage.Tokens) {
			return nil, nil, false
		}
	}
	resolveStagePrograms(stages, scope)
	if slices.ContainsFunc(stages, func(stage permissions.StageNormalization) bool { return permissions.StageNeedsShell(stage, scope) }) ||
		verifyStagePrograms(stages, scope, home) != nil {
		return nil, nil, false
	}
	first, err := stageRequest(stages[0], scope, home, permissions.ModeContext{}, "")
	if err != nil {
		return nil, nil, false
	}
	if _, ok := matcher.MatchOutsideEntry(ctx, first.Req); !ok {
		return nil, nil, false
	}
	return stages, operators, true
}

func savedEntries(ctx context.Context, run Runner, stages []permissions.StageNormalization, scope string, home string) []string {
	matcher, ok := run.(OutsideEntryMatcher)
	if !ok {
		return nil
	}
	entries := make([]string, len(stages))
	for i, stage := range stages {
		req, err := stageRequest(stage, scope, home, permissions.ModeContext{}, "")
		if err != nil {
			continue
		}
		if entry, ok := matcher.MatchOutsideEntry(ctx, req.Req); ok {
			entries[i] = entry
		}
	}
	return entries
}

func refuseLiteralEntry(ctx context.Context, run Runner, literalInput string, scope string, home string) error {
	canonical, err := permissions.CanonicalLiteralForm(literalInput)
	if err != nil {
		return nil
	}
	stages := permissions.LiteralStages(canonical)
	resolveStagePrograms(stages, scope)
	for i, entry := range savedEntries(ctx, run, stages, scope, home) {
		if entry != "" {
			return sandboxedEntryError(entry, stages[i], "the call needs the shell")
		}
	}
	return nil
}

func refusePipedEntry(ctx context.Context, run Runner, stages []permissions.StageNormalization, operators []string, scope string, home string) error {
	entries := savedEntries(ctx, run, stages, scope, home)
	if !slices.Contains(entries, "") {
		return nil
	}
	for i, entry := range entries {
		piped := i > 0 && (i > len(operators) || operators[i-1] == "|")
		if entry != "" && piped {
			return sandboxedEntryError(entry, stages[i], "the command receives piped input")
		}
	}
	return nil
}

func sandboxedEntryError(entry string, stage permissions.StageNormalization, reason string) error {
	command := strings.TrimSpace(stage.Source)
	return &MalformedCommandError{Err: fmt.Errorf("codemeld: not run: %q is in outside_sandbox_commands (.codemeld/settings.local.yaml), but this call would keep it in the sandbox\n"+
		"Reason: %s.\n"+
		"Instead: run `%s` on its own, or as `%s 2>&1 | <command that needs no shell>`; a failure of `%s` is then the call's exit status, so PIPESTATUS is not needed",
		entry, reason, command, command, command)}
}

// confinedStagesNeedShell asks for confinement only when a stage needs the shell or names a program
// that is not found, so a resolution error never blocks a command that would keep its route anyway.
func confinedStagesNeedShell(ctx context.Context, run Runner, stages []permissions.StageNormalization, scope string, home string) (bool, error) {
	if !slices.ContainsFunc(stages, func(stage permissions.StageNormalization) bool { return permissions.StageNeedsShell(stage, scope) }) &&
		verifyStagePrograms(stages, scope, home) == nil {
		return false, nil
	}
	return runsConfined(ctx, run)
}

func runsConfined(ctx context.Context, run Runner) (bool, error) {
	reporter, ok := run.(ConfinementReporter)
	if !ok {
		return false, nil
	}
	return reporter.Confined(ctx)
}

// dispatchConfinedShell checks the source stages before the literal route sees the command, because
// the literal form's read-only classification and RunSpec no longer show every stage's paths or
// assignments.
func dispatchConfinedShell(ctx context.Context, literalInput string, stages []permissions.StageNormalization, scope string, home string, authorizer Authorizer, run Runner, modeCtx permissions.ModeContext, guard securitystate.Policy) (tools.Result, error) {
	asks, err := refuseReadOnlyStages(stages, scope, home, modeCtx, guard)
	if err != nil {
		return tools.Result{}, err
	}
	for _, stage := range stages {
		if _, err := runner.FixedEnvironment("", "", "", "", stage.Assignments); err != nil {
			return tools.Result{}, err
		}
	}
	modeCtx.LiteralRoute = true
	modeCtx.Stages = stages
	ask, err := refuseReadOnlyLiteral(literalInput, scope, home, modeCtx, guard)
	if err != nil {
		return tools.Result{}, err
	}
	modeCtx.ShellPathAsk = ask || slices.Contains(asks, true)
	return dispatchLiteral(ctx, literalInput, scope, authorizer, run, modeCtx)
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
