// Structured-tool dispatch: exact-name registry lookup, effective-cwd path-scope resolution,
// permission authorization, and tool invocation — including vcs_<action> launch-failure cwd handling.
package dispatch

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/vcs"
)

// NoSuchToolError reports that no tool is registered under the requested name. Dispatch
// returns it to the agent without ever consulting authorization. A vcs_<action> name that is absent
// because no VCS template was active (no detection match) is indistinguishable
// from any other registry miss at dispatch time and surfaces through this same error.
type NoSuchToolError struct {
	Name string
}

func (e *NoSuchToolError) Error() string {
	return fmt.Sprintf("no_such_tool: %s", e.Name)
}

// effectiveCWDTool is the package-local seam for a tool whose invocation runs in a directory other
// than codemeld's process cwd. *vcs.ActionTool satisfies it via EffectiveCWD(), which
// delegates to the same cwd resolver invocation uses, so dispatch authorizes the exact path the tool
// will execute in. The seam lives here, not on tools.Tool, so internal/tools stays a
// standard-library-only leaf package.
type effectiveCWDTool interface {
	// EffectiveCWD returns the resolved execution directory the tool will run in, or an error if it
	// cannot be resolved. A launch-failure error that still carries a concrete attempted path scope
	// (*vcs.CWDEscapeError / *vcs.RepoRootResolveError) is authorized against that carried
	// scope and the tool is still invoked; any other error returns before prompting.
	EffectiveCWD() (string, error)
}

type effectiveCWDInvoker interface {
	InvokeWithEffectiveCWD(ctx context.Context, args map[string]any, resolvedCwd string, cwdErr error) (tools.Result, error)
}

// protectedStateTool is the package-local seam a VCS action tool implements to report, before
// authorization and before any subprocess, whether executing it could rewrite the run's protected
// settings state. The classification rules live in internal/vcs, so internal/dispatch carries no VCS
// policy — exactly as targetScopedTool's resolution lives in the tool. protectedIn is passed rather
// than a resolved set because enumerating it walks the repository, and only a few actions need it.
type protectedStateTool interface {
	ProtectedStateRisk(ctx context.Context, args map[string]any, protectedIn func(root string) ([]string, error)) bool
}

// targetScopedTool is the package-local seam for a tool whose authorization path scope and mode-auth
// target path are derived from its arguments, resolved before authorization — the mutating structured file
// tools (edit, create, mkdir). It mirrors effectiveCWDTool: dispatch resolves the target once, before prompting, so
// it authorizes (and Auto edits keys auto-approval on) the exact file the tool will modify. The
// resolution rules (path expansion, symlink resolution, project-scope containment) live in the tool, so
// internal/tools stays a standard-library-only leaf and internal/dispatch carries no file-operation
// policy — exactly as EffectiveCWD's resolution lives in internal/vcs.
type targetScopedTool interface {
	// ResolveTarget resolves the file target from args before authorization, returning the resolved
	// target path (placed in the mode-auth context) and the path scope to authorize (the
	// resolved parent directory). A structurally invalid target (missing/non-regular/directory
	// an unresolvable parent, malformed args) returns an error before any prompt — such a target is never
	// authorized or auto-approved. An out-of-root resolved target is NOT such an error:
	// it resolves to its real out-of-root folder and flows on to the approval prompt; the
	// out-of-root verdict is reported separately via outOfRootFileTool.
	ResolveTarget(args map[string]any) (target string, scope string, err error)
}

// outOfRootFileTool is the package-local seam a mutating structured file tool (the edit, create, and mkdir
// tools) implements to report, after ResolveTarget, whether the resolved path scope lies outside its
// project root — the promptable out-of-root case. Only those mutating file tools implement it, so the
// out-of-root folder-grant signal is raised for them only and stays false (its zero value) for
// every other tool and for shell, keeping every unrelated out-of-root prompt exactly as it is today. The
// containment policy (which root, what counts as in-root) lives in the tool, mirroring how ResolveTarget's
// resolution rules do, so internal/dispatch carries no file-operation policy.
type outOfRootFileTool interface {
	// OutOfRootScope reports whether scope (the path scope ResolveTarget returned) is outside the tool's
	// project root. It is consulted only for a successfully resolved target-scoped tool.
	OutOfRootScope(scope string) bool
}

// externalReadTool is the package-local seam a read-only structured file tool (read, glob, grep, list,
// tree) implements to report, after ResolveTarget, whether the resolved path scope is an explicit
// out-of-project read target — the promptable external-read case. It mirrors outOfRootFileTool but
// drives a different posture: an external read bypasses the read-only mode auto-allow so it prompts in
// every active mode, without enabling any write grant. Only the five read tools implement it, so the
// signal stays false (its zero value) for every other tool, for shell, and for the mutating edit/create
// tools (which raise outOfRootFileWrite instead). The containment policy lives in the tool, mirroring how
// ResolveTarget's resolution rules do, so internal/dispatch carries no file-operation policy.
type externalReadTool interface {
	// ExternalReadScope reports whether scope (the path scope ResolveTarget returned) is an explicit
	// out-of-project read target. It is consulted only for a successfully resolved target-scoped tool.
	ExternalReadScope(scope string) bool
}

// editPreviewTool runs before authorization, so an implementation must not write: a validation
// failure returns the tool's own in-band refusal, which dispatch returns instead of prompting.
type editPreviewTool interface {
	Preview(target string, args map[string]any) (string, *tools.Result)
}

// resolvedTargetInvoker lets a target-scoped tool be invoked with the target dispatch already resolved
// before authorization, so the authorized file and the modified file cannot diverge if a symlink
// changes between the two steps — the same reuse-at-invoke contract effectiveCWDInvoker provides for a
// resolved cwd.
type resolvedTargetInvoker interface {
	InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error)
}

// authorizedScopeInvoker is the invocation seam for the four mutating single-target file tools (edit,
// create, mkdir, delete). resolvedTargetInvoker hands invocation a bare path, and an arbitrary amount of
// time passes on the permission prompt in between: a folder deleted and recreated under the same name in
// that window is still reachable at the approved path, so nothing downstream can tell it from the folder
// the user approved. This seam carries the authorized directory's identity as well, and dispatch prefers
// it — the seven read-only target-scoped tools stay on resolvedTargetInvoker unchanged.
type authorizedScopeInvoker interface {
	InvokeWithAuthorizedScope(ctx context.Context, args map[string]any, resolvedTarget string, scope string, scopeIdentity filetools.ScopeIdentity) (tools.Result, error)
}

// preparedGeneralAgentTool is the package-local seam for the general_agent tool: its child write and delete
// declarations are canonicalized before authorization and carried into the mode-auth context, so a
// parent ceiling judges the exact sets the child is built from. Preparation and invocation are one
// interface because invocation must not resolve the raw declarations a second time — satisfying the
// seam guarantees an ancestor or symlink swap in between cannot widen the child's ceiling. The argument
// and containment rules live in the tool, so internal/dispatch carries no delegation policy, exactly as
// targetScopedTool's resolution does.
type preparedGeneralAgentTool interface {
	// schedulerTargets adds the missing directories the child's authorized creates would make to
	// the declared write and delete leaves, move endpoints, and directories. It is ordering data and never
	// part of the child's ceiling.
	PrepareGeneralAgent(args map[string]any) (instruction string, write, remove map[string]bool, moves map[permissions.MovePair]bool, dirs map[string]bool, schedulerTargets []string, err error)
	InvokeWithPreparedGeneralAgent(ctx context.Context, instruction string, write, remove map[string]bool, moves map[permissions.MovePair]bool, dirs map[string]bool) (tools.Result, error)
}

// multiScopeFileTool is the package-local seam for a mutating structured file tool whose authorization
// touches two independent resolved path scopes — the move tool's source and destination. The
// single-target seam (targetScopedTool/resolvedTargetInvoker) carries only one path and one scope, so it
// cannot express a move: a move reads-and-relocates a source and creates a destination, each with its own
// resolved real path, authorization scope, and out-of-root verdict, and either endpoint can be in-root
// while the other is not. Dispatch resolves both endpoints once (filetools.ResolvedMove), authorizes every
// unique resolved scope before prompting, and invokes only after every scope grants, so a move never reads
// or writes either endpoint until both are approved. Resolve and invoke are one interface because a move
// always needs both — there is no move-shaped tool that resolves two scopes but invokes via plain Invoke —
// so satisfying the seam guarantees the resolved pair can be reused at invocation. The resolution and
// containment rules live in the tool (internal/filetools), so internal/dispatch carries no
// file-operation policy, exactly as targetScopedTool's resolution does.
type multiScopeFileTool interface {
	// ResolveEndpoints resolves both move endpoints from args before authorization, returning each
	// endpoint's resolved real path, the parent-directory scope to authorize, and whether that scope lies
	// outside the project root. A structurally invalid endpoint (missing source, existing destination, an
	// unresolvable parent, malformed args) returns an error before any prompt; an out-of-root endpoint is
	// not such an error — it resolves to its real out-of-root folder and flows to the prompt.
	ResolveEndpoints(args map[string]any) (filetools.ResolvedMove, error)
	// InvokeWithResolvedMove performs the move for the endpoint pair dispatch already resolved and
	// authorized, reusing the resolved real paths so authorization and the rename cannot drift if a symlink
	// changes in between — the reuse-at-invoke contract resolvedTargetInvoker provides for a single target,
	// extended to both move endpoints.
	InvokeWithResolvedMove(ctx context.Context, resolved filetools.ResolvedMove) (tools.Result, error)
}

// DispatchTool looks up a structured tool by exact name, authorizes it against its effective
// execution directory, and — only if authorized — invokes it. name is the
// exact registered tool name; args are the decoded tool arguments passed straight to the tool; home
// anchors ~ expansion during path-scope resolution; processCWD is codemeld's working directory and
// the default path scope for a tool with no distinct execution directory; registry is the tool
// registry; authorizer is the bound permission seam shared with shell dispatch.
//
// The routes, in order: an unknown name returns *NoSuchToolError immediately, without prompting —
// this also covers a vcs_<action> name that was never registered because no VCS template is active.
// Otherwise the authorization path scope is resolved before prompting: a tool exposing
// EffectiveCWD anchors on its resolved execution directory, every other tool on
// processCWD. A VCS launch-failure cwd error (cwd escape or repo-root disappearance) carries the
// attempted path scope, so dispatch authorizes against that carried scope and still invokes the tool
// so the VCS action tool produces its launch-failure result and paired tool_exec_* events; an effective-cwd
// error with no concrete path scope returns before prompting. A denied authorization returns
// *DeniedError and the tool is never invoked; a granted authorization invokes the registered tool,
// which owns its own invocation (a vcs_<action> tool routes to the VCS action invoker — dispatch never
// special-cases shell equivalents or rewrites a raw shell command into a structured call).
func DispatchTool(ctx context.Context, name string, args map[string]any, home string, processCWD string, registry *tools.Registry, authorizer Authorizer, guard ...securitystate.Policy) (tools.Result, error) {
	prepared, err := PrepareTool(ctx, name, args, home, processCWD, registry, guard...)
	if err != nil {
		return tools.Result{}, err
	}
	return DispatchPreparedTool(ctx, prepared, authorizer)
}

type PreparedTool struct {
	name    string
	tool    tools.Tool
	args    map[string]any
	modeCtx permissions.ModeContext

	multi        multiScopeFileTool
	resolvedMove filetools.ResolvedMove

	generalAgent            preparedGeneralAgentTool
	generalAgentInstruction string
	generalAgentWrite       map[string]bool
	generalAgentDelete      map[string]bool
	generalAgentMoves       map[permissions.MovePair]bool
	generalAgentDirs        map[string]bool
	generalAgentTargets     []string
	generalAgentRefusal     error

	scope          string
	scopeIdentity  filetools.ScopeIdentity
	resolvedTarget string
	resolvedCwd    string
	cwdErr         error

	editPatch      string
	previewRefusal *tools.Result

	outOfRootFileWrite bool
	externalRead       bool

	home       string
	processCWD string
	registry   *tools.Registry
	policy     securitystate.Policy
}

func (p PreparedTool) Name() string { return p.name }

func (p PreparedTool) Scope() string { return p.scope }

func (p PreparedTool) ExternalRead() bool { return p.externalRead }

// PreparedTarget is the exact target this call was prepared against — the resolved file for a
// target-scoped tool, otherwise the resolved path scope — so a group prompt can name what each
// call will actually touch.
func (p PreparedTool) PreparedTarget() string {
	if p.resolvedTarget != "" {
		return p.resolvedTarget
	}
	return p.scope
}

func (p PreparedTool) PreparedMove() (source, destination string) {
	return p.resolvedMove.Source, p.resolvedMove.Destination
}

func (p PreparedTool) GeneralAgentRefusal() error { return p.generalAgentRefusal }

func (p PreparedTool) GeneralAgentPrepared() bool { return p.generalAgent != nil }

// GeneralAgentDeclaredWrite is the child's canonical write ceiling. Each caller gets its own copy, so an
// authorizer that observes the declaration cannot widen what the child is built from.
func (p PreparedTool) GeneralAgentDeclaredWrite() map[string]bool { return copyDeclared(p.generalAgentWrite) }

func (p PreparedTool) GeneralAgentDeclaredDelete() map[string]bool { return copyDeclared(p.generalAgentDelete) }

// GeneralAgentSchedulerTargets is the path set this call mutates for write-conflict ordering: the
// declared write and delete leaves, move endpoints, and directories plus the missing parents the
// child's authorized creates and mkdirs would make.
// Those parents order the call and grant the child nothing.
func (p PreparedTool) GeneralAgentSchedulerTargets() []string { return slices.Clone(p.generalAgentTargets) }

func copyDeclared[K comparable](declared map[K]bool) map[K]bool {
	if declared == nil {
		return nil
	}
	out := make(map[K]bool, len(declared))
	maps.Copy(out, declared)
	return out
}

// IndependentAuthRequest is one independently authorizable call handed to
// IndependentAuthorizer.AuthorizeIndependent. It carries the same (MatchRequest, PromptDisplay,
// ModeContext) triple a single Authorize takes, plus the prepared target the group prompt lists
// for it.
type IndependentAuthRequest struct {
	Req            permissions.MatchRequest
	Display        PromptDisplay
	ModeCtx        permissions.ModeContext
	PreparedTarget string
}

// IndependentAuthorizer authorizes a group of independently authorizable calls on one prompt and
// returns an index-aligned decision per call. It is a separate seam from BatchAuthorizer, whose
// direct-pipeline stages share one outcome and stop at the first deny: here every call keeps its
// own subject, decision, grant, and deny envelope, so a denied call does not block its siblings.
type IndependentAuthorizer interface {
	AuthorizeIndependent(ctx context.Context, reqs []IndependentAuthRequest) ([]permissions.Decision, error)
}

// IndependentRequest is the authorization request DispatchPreparedTool would make for this
// prepared call, so a caller can authorize a group of prepared calls together and then dispatch
// each against the very target it authorized.
func (p PreparedTool) IndependentRequest() IndependentAuthRequest {
	req, display, modeCtx := p.authorizationInputs()
	return IndependentAuthRequest{Req: req, Display: display, ModeCtx: modeCtx, PreparedTarget: p.PreparedTarget()}
}

func (p PreparedTool) authorizationInputs() (permissions.MatchRequest, PromptDisplay, permissions.ModeContext) {
	// tool requests match on exact registered name; tool matching ignores SubjectTokens
	// so it is left unset ('s token sequence is a direct-subject concern only).
	req := permissions.MatchRequest{
		Kind:      "tool",
		Subject:   p.name,
		PathScope: p.scope,
	}
	display := toolPromptDisplay(p.name, p.args, p.editPatch)
	display.OutOfRootFileWrite = p.outOfRootFileWrite
	// An external read re-enables the folder grant option for that read-only scope (mirroring the
	// edit/create out-of-root signal), so the user can persist a folder/session/global read grant for it.
	display.OutOfRootReadScope = p.externalRead
	if capability, ok := permissions.CapabilityForMember(p.name); ok && (capability == permissions.CapabilityWriteTree || p.externalRead) {
		display.GrantStoredSubject = capability
	}
	modeCtx := p.modeCtx
	modeCtx.GeneralAgentWrite = p.GeneralAgentDeclaredWrite()
	modeCtx.GeneralAgentDelete = p.GeneralAgentDeclaredDelete()
	modeCtx.GeneralAgentMoves = copyDeclared(p.generalAgentMoves)
	modeCtx.GeneralAgentDirs = copyDeclared(p.generalAgentDirs)
	return req, display, modeCtx
}

func PrepareTool(ctx context.Context, name string, args map[string]any, home string, processCWD string, registry *tools.Registry, guard ...securitystate.Policy) (PreparedTool, error) {
	policy := guardPolicy(guard)
	policy.Blocked = policy.Blocked.Current()
	return prepareTool(ctx, name, args, home, processCWD, registry, policy, false)
}

// launch prepares one operation a general_agent call declared rather than a call to run: there is no edit
// content to preview, and a declared delete may name a target the child has yet to create.
func prepareTool(ctx context.Context, name string, args map[string]any, home string, processCWD string, registry *tools.Registry, policy securitystate.Policy, launch bool) (PreparedTool, error) {
	tool, ok := registry.Lookup(name)
	if !ok {
		return PreparedTool{}, &NoSuchToolError{Name: name}
	}

	// The nominal check must precede the operation-specific resolvers, which would otherwise reject a
	// protected target as an ordinary preparation error rather than a protected-state refusal.
	if refusal := policy.RefuseNominal(name, args, home, processCWD); refusal != nil {
		return PreparedTool{}, refusal
	}

	prepared := PreparedTool{
		name: name,
		tool: tool,
		args: args,
		modeCtx: permissions.ModeContext{
			Class:         toolOperationClass(tool),
			ToolName:      name,
			NetworkEgress: isNetworkEgressTool(name),
		},
		home:       home,
		processCWD: processCWD,
		registry:   registry,
		policy:     policy,
	}

	// a multi-scope file tool (the move tool) resolves two endpoints and must authorize each unique
	// resolved scope before invoking — it cannot use the single-target seam below, which carries one path
	// and one scope. It routes through its own all-authorize-before-invoke path so a denial of either
	// endpoint blocks the move with no partial mutation.
	if multiTool, ok := tool.(multiScopeFileTool); ok {
		resolved, err := multiTool.ResolveEndpoints(args)
		if err != nil {
			return PreparedTool{}, err
		}
		if refusal := policy.RefuseResolved(name, resolved.Source, resolved.Destination); refusal != nil {
			return PreparedTool{}, refusal
		}
		prepared.multi = multiTool
		prepared.resolvedMove = resolved
		prepared.modeCtx.MoveSource = resolved.Source
		prepared.modeCtx.MoveDestination = resolved.Destination
		return prepared, nil
	}

	// a target-scoped tool (the edit/create/mkdir tools) resolves its file target before
	// authorization, so dispatch authorizes — and the mode-auth context carries — the exact resolved path
	// the tool will modify. A structurally invalid target fails before any prompt; an out-of-root target
	// resolves and flows to the prompt, raising the out-of-root folder-grant signal (outOfRootFileTool). Every
	// other tool resolves its path scope from its effective cwd (or the process cwd), with no mode-auth
	// target path.
	if targetTool, ok := tool.(targetScopedTool); ok {
		resolve := targetTool.ResolveTarget
		if launch && name == filetools.DeleteToolName {
			resolve = func(args map[string]any) (string, string, error) {
				return resolveLaunchDelete(targetTool, args, home, processCWD)
			}
		}
		target, targetScope, err := resolve(args)
		if err != nil {
			return PreparedTool{}, err
		}
		if refusal := policy.RefuseResolved(name, target); refusal != nil {
			return PreparedTool{}, refusal
		}
		prepared.scope = targetScope
		prepared.resolvedTarget = target
		prepared.modeCtx.TargetPath = target
		// Record which directory the approval is about to cover, before the preview renders or the prompt
		// opens, so invocation compares against the folder the user was shown rather than whatever answers
		// to that path once they decide. A directory that cannot be recorded fails preparation rather than
		// reaching a prompt with nothing to compare against later.
		if _, ok := tool.(authorizedScopeInvoker); ok {
			identity, ierr := filetools.CaptureScopeIdentity(targetScope)
			if ierr != nil {
				return PreparedTool{}, ierr
			}
			prepared.scopeIdentity = identity
		}
		// A mutating structured edit/create/mkdir whose resolved scope is outside the project root
		// is a promptable out-of-root write. Only those mutating file tools implement outOfRootFileTool, so
		// this signal is raised for them alone and stays false for every other tool and for shell — the
		// folder-grant option is re-enabled for an out-of-root edit/create/mkdir only.
		if oor, ok := tool.(outOfRootFileTool); ok {
			prepared.outOfRootFileWrite = oor.OutOfRootScope(targetScope)
		}
		if ext, ok := tool.(externalReadTool); ok {
			prepared.externalRead = ext.ExternalReadScope(targetScope)
		}
		if previewer, ok := tool.(editPreviewTool); ok && !launch {
			prepared.editPatch, prepared.previewRefusal = previewer.Preview(target, args)
		}
	} else {
		scope, resolvedCwd, cwdErr, err := resolveToolPathScope(tool, home, processCWD)
		if err != nil {
			return PreparedTool{}, err
		}
		prepared.scope = scope
		prepared.resolvedCwd = resolvedCwd
		prepared.cwdErr = cwdErr
		// A VCS action runs an unsandboxed subprocess, so the guard has to answer before mode posture,
		// grants, the cache, or a prompt can authorize it and before anything launches: once a branch
		// switch or a stash pop has rewritten the settings file, suppressing its result changes nothing.
		if vcsTool, ok := tool.(protectedStateTool); ok {
			if policy.Guards() {
				if refusal := policy.RefuseVCS(name, scope, vcsTool.ProtectedStateRisk(ctx, args, policy.ProtectedIn)); refusal != nil {
					return PreparedTool{}, refusal
				}
			}
			if refusal := policy.RefuseBlockedVCS(name, scope, func(protectedIn func(string) ([]string, error)) bool {
				return vcsTool.ProtectedStateRisk(ctx, args, protectedIn)
			}); refusal != nil {
				return PreparedTool{}, refusal
			}
		}
	}

	if generalAgentTool, ok := tool.(preparedGeneralAgentTool); ok {
		instruction, write, remove, moves, dirs, schedulerTargets, err := generalAgentTool.PrepareGeneralAgent(args)
		if err != nil {
			// A declaration that does not resolve leaves the call with no candidate, which is an
			// unbounded child rather than a subset of anything. Whether a ceiling is judging the call is
			// the caller's knowledge, not this package's — a child agent's nested call is under one
			// whatever its declaration holds and must deny there, while a top-level call under
			// no ceiling was never a permission question — so the refusal is carried on the prepared
			// call rather than returned from here.
			prepared.generalAgentRefusal = err
			prepared.modeCtx.GeneralAgentRefused = true
		} else {
			prepared.generalAgent = generalAgentTool
			prepared.generalAgentInstruction = instruction
			prepared.generalAgentWrite = copyDeclared(write)
			prepared.generalAgentDelete = copyDeclared(remove)
			prepared.generalAgentMoves = copyDeclared(moves)
			prepared.generalAgentDirs = copyDeclared(dirs)
			prepared.generalAgentTargets = slices.Clone(schedulerTargets)
			prepared.modeCtx.GeneralAgentResolved = true
			if len(write)+len(remove)+len(moves)+len(dirs) == 0 {
				prepared.modeCtx.Class = permissions.ClassReadOnly
			}
		}
	}

	unknownList := policy.Blocked == nil || policy.Blocked.Degraded()
	prepared.modeCtx.OpenRead = prepared.externalRead && !unknownList
	prepared.modeCtx.ExternalRead = prepared.externalRead && unknownList
	return prepared, nil
}

func resolveLaunchDelete(tool targetScopedTool, args map[string]any, home, processCWD string) (string, string, error) {
	path := stringArg(args, "path")
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return filetools.ResolveDeleteDeclaration(home, processCWD, path)
	}
	return tool.ResolveTarget(args)
}

// The zero policy protects nothing, so a call site that supplies no guard is deliberately unguarded.
func guardPolicy(guard []securitystate.Policy) securitystate.Policy {
	if len(guard) == 0 {
		return securitystate.Policy{}
	}
	return guard[0]
}

func DispatchPreparedTool(ctx context.Context, prepared PreparedTool, authorizer Authorizer) (tools.Result, error) {
	if prepared.tool == nil {
		return tools.Result{}, fmt.Errorf("dispatch: tool call was not prepared")
	}
	if prepared.multi != nil {
		return dispatchPreparedMultiScope(ctx, prepared, authorizer)
	}
	if prepared.previewRefusal != nil {
		return *prepared.previewRefusal, nil
	}

	req, display, modeCtx := prepared.authorizationInputs()
	decision, err := authorizer.Authorize(ctx, req, display, modeCtx)
	if err != nil {
		return tools.Result{}, err
	}
	return InvokeDecided(ctx, prepared, decision)
}

// A top-level call's request under its own name can only refuse it; what starts the child is the
// approval of every operation it declares, each authorized as the same direct call would be.
func DispatchPreparedGeneralAgent(ctx context.Context, prepared PreparedTool, authorizer Authorizer, childCeiling bool) (tools.Result, error) {
	if childCeiling {
		return DispatchPreparedTool(ctx, prepared, authorizer)
	}
	if prepared.generalAgent == nil {
		if prepared.generalAgentRefusal != nil {
			return tools.Result{}, prepared.generalAgentRefusal
		}
		return tools.Result{}, fmt.Errorf("dispatch: %s is not a prepared general_agent call", prepared.name)
	}
	ops, err := prepared.launchOperations(ctx)
	if err != nil {
		return tools.Result{}, err
	}
	req, display, modeCtx := prepared.authorizationInputs()
	refusal, err := authorizer.Authorize(ctx, req, display, modeCtx)
	if err != nil {
		return tools.Result{}, err
	}
	if refusal.DenyEnvelope != "" {
		return tools.Result{}, &DeniedError{Envelope: refusal.DenyEnvelope, WrapUp: refusal.WrapUp}
	}
	for _, op := range ops {
		if err := authorizePrepared(ctx, op, authorizer); err != nil {
			return tools.Result{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return tools.Result{}, err
	}
	return prepared.generalAgent.InvokeWithPreparedGeneralAgent(ctx, prepared.generalAgentInstruction, prepared.GeneralAgentDeclaredWrite(), prepared.GeneralAgentDeclaredDelete(),
		copyDeclared(prepared.generalAgentMoves), copyDeclared(prepared.generalAgentDirs))
}

func (p PreparedTool) launchOperations(ctx context.Context) ([]PreparedTool, error) {
	var ops []PreparedTool
	add := func(name string, args map[string]any, want ...string) error {
		op, err := prepareTool(ctx, name, args, p.home, p.processCWD, p.registry, p.policy, true)
		if err != nil {
			return err
		}
		got := []string{op.resolvedTarget}
		if op.multi != nil {
			got = []string{op.resolvedMove.Source, op.resolvedMove.Destination}
		}
		if !slices.Equal(got, want) {
			return &filetools.TargetError{Kind: name, Reason: "the declared path no longer resolves to the target the general_agent call was prepared with"}
		}
		ops = append(ops, op)
		return nil
	}
	for _, path := range slices.Sorted(maps.Keys(p.generalAgentWrite)) {
		name := filetools.EditToolName
		if _, err := os.Lstat(path); err != nil {
			name = filetools.CreateToolName
		}
		if err := add(name, map[string]any{"path": path}, path); err != nil {
			return nil, err
		}
	}
	for _, path := range slices.Sorted(maps.Keys(p.generalAgentDelete)) {
		if err := add(filetools.DeleteToolName, map[string]any{"path": path}, path); err != nil {
			return nil, err
		}
	}
	moves := slices.SortedFunc(maps.Keys(p.generalAgentMoves), func(a, b permissions.MovePair) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Destination, b.Destination))
	})
	for _, pair := range moves {
		if err := add(filetools.MoveToolName, map[string]any{"source": pair.Source, "destination": pair.Destination}, pair.Source, pair.Destination); err != nil {
			return nil, err
		}
	}
	for _, dir := range slices.Sorted(maps.Keys(p.generalAgentDirs)) {
		if err := add(filetools.MkdirToolName, map[string]any{"path": dir}, dir); err != nil {
			return nil, err
		}
	}
	return ops, nil
}

func authorizePrepared(ctx context.Context, prepared PreparedTool, authorizer Authorizer) error {
	if prepared.multi != nil {
		return authorizeMoveEndpoints(ctx, prepared, authorizer)
	}
	req, display, modeCtx := prepared.authorizationInputs()
	decision, err := authorizer.Authorize(ctx, req, display, modeCtx)
	if err != nil {
		return err
	}
	if decision.DenyEnvelope != "" {
		return &DeniedError{Envelope: decision.DenyEnvelope, WrapUp: decision.WrapUp}
	}
	return nil
}

// InvokeDecided invokes a prepared call whose authorization already completed — the path a group
// authorized on one prompt takes, so no member re-prompts and every member runs against the exact
// target its decision covered. A denial returns *DeniedError without invoking anything.
func InvokeDecided(ctx context.Context, prepared PreparedTool, decision permissions.Decision) (tools.Result, error) {
	if prepared.tool == nil {
		return tools.Result{}, fmt.Errorf("dispatch: tool call was not prepared")
	}
	if prepared.multi != nil {
		return tools.Result{}, fmt.Errorf("dispatch: %s authorizes two scopes and has no single decision", prepared.name)
	}
	if prepared.previewRefusal != nil {
		return *prepared.previewRefusal, nil
	}
	if decision.DenyEnvelope != "" {
		return tools.Result{}, &DeniedError{Envelope: decision.DenyEnvelope, WrapUp: decision.WrapUp}
	}
	// An authorized call whose declaration never resolved still starts nothing: its refusal is the
	// model's corrective, reached only once no ceiling has denied the call ahead of it.
	if prepared.generalAgentRefusal != nil {
		return tools.Result{}, prepared.generalAgentRefusal
	}
	if err := ctx.Err(); err != nil {
		return tools.Result{}, err
	}

	if prepared.generalAgent != nil {
		return prepared.generalAgent.InvokeWithPreparedGeneralAgent(ctx, prepared.generalAgentInstruction, prepared.GeneralAgentDeclaredWrite(), prepared.GeneralAgentDeclaredDelete(),
			copyDeclared(prepared.generalAgentMoves), copyDeclared(prepared.generalAgentDirs))
	}

	// This assertion runs before the path-only seam below so the four mutating file tools can never fall
	// through to it and lose the authorized directory's identity.
	if scopeInvoker, ok := prepared.tool.(authorizedScopeInvoker); ok {
		return scopeInvoker.InvokeWithAuthorizedScope(ctx, prepared.args, prepared.resolvedTarget, prepared.scope, prepared.scopeIdentity)
	}

	// invoke a target-scoped tool with the target resolved before authorization, so the
	// authorized file and the modified file cannot diverge if a symlink changes in between.
	if targetInvoker, ok := prepared.tool.(resolvedTargetInvoker); ok {
		return targetInvoker.InvokeWithResolvedTarget(ctx, prepared.args, prepared.resolvedTarget)
	}
	if effInvoker, ok := prepared.tool.(effectiveCWDInvoker); ok {
		return effInvoker.InvokeWithEffectiveCWD(ctx, prepared.args, prepared.resolvedCwd, prepared.cwdErr)
	}
	return prepared.tool.Invoke(ctx, prepared.args)
}

func dispatchPreparedMultiScope(ctx context.Context, prepared PreparedTool, authorizer Authorizer) (tools.Result, error) {
	if err := authorizeMoveEndpoints(ctx, prepared, authorizer); err != nil {
		return tools.Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return tools.Result{}, err
	}
	// every required scope granted: invoke with the endpoints resolved before authorization.
	return prepared.multi.InvokeWithResolvedMove(ctx, prepared.resolvedMove)
}

func authorizeMoveEndpoints(ctx context.Context, prepared PreparedTool, authorizer Authorizer) error {
	// The move prompt shows a plain "Move source -> destination" action over the lexical
	// endpoints, carried separately from the matching subject (the bare "move" name).
	display := toolPromptDisplay(prepared.name, prepared.args, "")
	if capability, ok := permissions.CapabilityForMember(prepared.name); ok && capability == permissions.CapabilityWriteTree {
		display.GrantStoredSubject = capability
	}

	for _, ep := range moveEndpoints(prepared.resolvedMove) {
		req := permissions.MatchRequest{
			Kind:      "tool",
			Subject:   prepared.name,
			PathScope: ep.scope,
		}
		// An out-of-root move endpoint re-enables the folder-grant option for its real out-of-root
		// folder, exactly like an out-of-root edit/create/mkdir write, and only for that endpoint's scope.
		epDisplay := display
		epDisplay.OutOfRootFileWrite = ep.outOfRoot
		decision, err := authorizer.Authorize(ctx, req, epDisplay, prepared.modeCtx)
		if err != nil {
			return err
		}
		if decision.DenyEnvelope != "" {
			return &DeniedError{Envelope: decision.DenyEnvelope, WrapUp: decision.WrapUp}
		}
	}
	return nil
}

// moveEndpoint is one resolved move endpoint dispatch must authorize: the resolved parent-directory scope
// to grant and whether it lies outside the project root (the out-of-root folder-grant signal).
type moveEndpoint struct {
	scope     string
	outOfRoot bool
}

// moveEndpoints returns the unique resolved scopes a move must authorize, source first. A move whose
// source and destination resolve to the same parent directory (a same-directory rename) authorizes that
// one scope once rather than prompting twice for the same folder; a destination in a different directory
// is a distinct scope authorized independently after the source. Source is first so a denied source
// returns before the destination is ever authorized. Two endpoints that share a resolved scope share its
// out-of-root verdict, so collapsing them loses no signal.
func moveEndpoints(resolved filetools.ResolvedMove) []moveEndpoint {
	endpoints := []moveEndpoint{{scope: resolved.SourceScope, outOfRoot: resolved.SourceOutOfRoot}}
	if resolved.DestinationScope != resolved.SourceScope {
		endpoints = append(endpoints, moveEndpoint{scope: resolved.DestinationScope, outOfRoot: resolved.DestinationOutOfRoot})
	}
	return endpoints
}

const (
	webSearchToolName = "web_search"
	webFetchToolName  = "web_fetch"
)

func isNetworkEgressTool(name string) bool {
	return name == webSearchToolName || name == webFetchToolName
}

// toolOperationClass maps a tool's read-only classification (Advertise().ReadOnly) to the
// permission operation class Plan's posture keys on: a read-only tool is read_only
// every other tool (including the mutating structured edit tool) is mutating. This is the
// single classification source, so mode posture and advertised-tool filtering cannot disagree.
func toolOperationClass(tool tools.Tool) permissions.OperationClass {
	if tool.Advertise().ReadOnly {
		return permissions.ClassReadOnly
	}
	return permissions.ClassMutating
}

// toolPromptDisplay only builds display text: the matching subject stays the registered name on
// MatchRequest, so this display choice never affects grant matching or events.
func toolPromptDisplay(name string, args map[string]any, editPatch string) PromptDisplay {
	switch name {
	case filetools.CreateToolName:
		return PromptDisplay{Action: ActionCreateFile, Subject: stringArg(args, "path"), RequestedTarget: stringArg(args, "path"), Body: stringArg(args, "content")}
	case filetools.EditToolName:
		return PromptDisplay{Action: ActionEditFile, Subject: stringArg(args, "path"), RequestedTarget: stringArg(args, "path"), Body: editPatch}
	case filetools.DeleteToolName:
		return PromptDisplay{Action: ActionDeleteFile, Subject: stringArg(args, "path"), RequestedTarget: stringArg(args, "path"), Body: ""}
	case filetools.MkdirToolName:
		// mkdir is a mutating directory creation: show the distinct "Create directory" action over the
		// target path with no body, so it never falls through to the generic "Run tool" label that would
		// make it look like an ordinary structured call. stringArg is display-only; the tool owns validation.
		return PromptDisplay{Action: ActionCreateDirectory, Subject: stringArg(args, "path"), RequestedTarget: stringArg(args, "path"), Body: ""}
	case filetools.MoveToolName:
		// move is a mutating rename across two endpoints: show the distinct "Move" action over
		// "source -> destination" (the lexical endpoints the model produced) with no body, so the prompt
		// names both endpoints and never falls through to the generic "Run tool" label. The per-endpoint
		// out-of-root folder-grant signal is set by dispatchPreparedMultiScope. stringArg is display-only; the tool
		// owns validation.
		moveSubject := stringArg(args, "source") + " -> " + stringArg(args, "destination")
		return PromptDisplay{Action: ActionMoveFile, Subject: moveSubject, RequestedTarget: moveSubject, Body: ""}
	default:
		// A read/search/navigation tool reaches a prompt only for an out-of-project scope (an
		// in-project read is auto-allowed without one), and its Subject is the bare tool name, so
		// its lexical path argument is the only requested-target spelling the prompt can show.
		return PromptDisplay{Action: ActionRunTool, Subject: name, RequestedTarget: readToolRequestedTarget(name, args), Body: toolCommandText(name, args)}
	}
}

func readToolRequestedTarget(name string, args map[string]any) string {
	switch name {
	case filetools.ReadToolName, filetools.GlobToolName, filetools.GrepToolName,
		filetools.ListToolName, filetools.TreeToolName, filetools.FileCountToolName:
		return stringArg(args, "path")
	default:
		return ""
	}
}

// stringArg returns the string value of args[key], or "" when the key is absent or not a string. It
// is display-only and best-effort: a malformed argument simply renders blank on the prompt rather
// than failing dispatch (the tool's own validation rejects a malformed call on invocation).
func stringArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// toolCommandText renders the structured-tool call shown verbatim on the permission prompt:
// the registered name followed by its JSON-encoded arguments, e.g. `read_file({"path":"/x"})`. A tool
// invoked with no arguments displays as the bare name — the only case where the prompt text equals
// MatchRequest.Subject — so the prompt never substitutes the registered name when arguments exist.
// json.Marshal sorts map keys, so the rendering is deterministic; an un-marshalable args map (not
// expected for decoded tool arguments) falls back to the bare name rather than failing dispatch.
func toolCommandText(name string, args map[string]any) string {
	if len(args) == 0 {
		return name
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return name
	}
	return name + "(" + string(encoded) + ")"
}

// resolveToolPathScope derives the authorization path scope for tool. A tool with no
// distinct execution directory authorizes against processCWD. A tool exposing EffectiveCWD()
// authorizes against its resolved execution directory, so the authorized path is the exact path the
// tool runs in. When EffectiveCWD returns a VCS launch-failure error that carries a
// concrete attempted path scope, that carried scope is returned verbatim — matching the path scope
// the VCS tool records on the paired launch-failure events — so the caller authorizes against it and still
// invokes; an effective-cwd error with no concrete path scope is returned so dispatch fails before
// prompting.
func resolveToolPathScope(tool tools.Tool, home, processCWD string) (string, string, error, error) {
	effTool, ok := tool.(effectiveCWDTool)
	if !ok {
		scope, err := permissions.DerivePathScope(home, "", processCWD, processCWD, "tool")
		return scope, "", nil, err
	}
	cwd, err := effTool.EffectiveCWD()
	if err != nil {
		var escErr *vcs.CWDEscapeError
		var rootErr *vcs.RepoRootResolveError
		switch {
		case errors.As(err, &escErr):
			// cwd escapes the repo root: authorize against the attempted (escaping) cwd that the VCS
			// tool records on the launch-failure events, then invoke so it synthesizes that surface.
			return escErr.ResolvedCwd, escErr.ResolvedCwd, err, nil
		case errors.As(err, &rootErr):
			// active repo root vanished after bootstrap bound it: authorize against the
			// would-be effective cwd carried on the error, then invoke for the same launch-failure
			// surface. This path scope is not re-resolved because the target no longer exists on disk.
			return rootErr.PathScope, rootErr.PathScope, err, nil
		default:
			// No concrete path scope to authorize against (e.g. an explicit cwd target vanished while
			// the repo root still resolves — a VCS dispatcher error): surface before prompting.
			return "", "", nil, err
		}
	}
	scope, err := permissions.DerivePathScope(home, "", processCWD, cwd, "tool")
	return scope, cwd, nil, err
}
