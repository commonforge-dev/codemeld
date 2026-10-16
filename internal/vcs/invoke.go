// VCS action invocation: placeholder substitution, cwd containment, launch-failure
// synthesis, and paired tool_exec_* emission.
package vcs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/tools"
)

// EventAppender is the narrow event-write seam this package needs: it accepts an
// events.EventPayload and returns an error. Production adapts it to events.Append
// bound to the active *sessions.Store; tests pass a capturing function. Keeping
// the seam local (rather than importing the store into invocation) follows the
// callback-seam style that avoids package cycles.
type EventAppender func(events.EventPayload) error

type childInvocationKey struct{}

// WithChildInvocationID marks ctx as running inside the child agent identified by id, so the
// action's tool_exec_* payloads carry it. The registry — and with it every ActionTool and the
// EventAppender bound to it — is shared between the parent and its children, so the id cannot be
// held on the tool and has to arrive with the call.
func WithChildInvocationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, childInvocationKey{}, id)
}

func childInvocationID(ctx context.Context) string {
	id, _ := ctx.Value(childInvocationKey{}).(string)
	return id
}

type confinementModeKey struct{}

func WithConfinementMode(ctx context.Context, mode string) context.Context {
	return context.WithValue(ctx, confinementModeKey{}, mode)
}

func ConfinementMode(ctx context.Context) (string, bool) {
	mode, ok := ctx.Value(confinementModeKey{}).(string)
	return mode, ok
}

// CWDEscapeError reports that an action's resolved cwd lies outside the active
// repo root. It carries the cleaned, symlink-resolved cwd so callers
// can build the exact launch-failure stderr and record the attempted path scope.
type CWDEscapeError struct {
	ResolvedCwd string
}

func (e *CWDEscapeError) Error() string {
	return fmt.Sprintf("resolved cwd %s escapes repo root", e.ResolvedCwd)
}

// RepoRootResolveError reports that the active repo root could not be resolved at
// invocation time — e.g. it was removed or became inaccessible after bootstrap
// step 6 bound it ("active repo root binding"). It carries the error
// category (for the launch-failure stderr) and the cleaned, absolute would-be
// effective cwd (the path scope recorded on the paired events), so Invoke can
// synthesize the launch-failure surface instead of surfacing a bare Go
// error with no result and no events.
type RepoRootResolveError struct {
	// PathScope is the cleaned, absolute effective cwd the action would have used,
	// derived from the bootstrap-resolved repo root per the cwd rule. It is
	// not symlink-resolved a second time because the target no longer resolves on
	// disk; the bootstrap-resolved root it is built from was resolved when present.
	PathScope string
	// Category is the error category classified from the resolution failure
	// (e.g. not_found when the root was removed, permission_denied when unreadable).
	Category fserrors.Category
	cause    error
}

func (e *RepoRootResolveError) Error() string {
	return fmt.Sprintf("vcs: active repo root unresolvable: %v", e.cause)
}

func (e *RepoRootResolveError) Unwrap() error { return e.cause }

// toolName is the registered tool name for a VCS action, e.g. "vcs_branch_current".
// Provider APIs (OpenRouter/OpenAI) reject function-tool names containing dots, so the
// "vcs" prefix joins the action with an underscore and hyphens in the action name become
// underscores, keeping every canonical name within ^[A-Za-z_][A-Za-z0-9_]*$.
func toolName(action string) string {
	return "vcs_" + strings.ReplaceAll(action, "-", "_")
}

// ResolveActionCWD resolves the effective working directory for action under
// repoRoot, applying the VCS action cwd rule: an omitted cwd uses repoRoot; an absolute
// cwd is used as-is; a relative cwd is joined to repoRoot. Both the candidate and
// the repo root are symlink-resolved and cleaned, then compared with the same
// descendant/equal rule permissions path-scope matching uses, so a symlink alias
// cannot make authorization and execution disagree. A resolved cwd outside
// repoRoot returns a *CWDEscapeError carrying the resolved path. A repo root that
// no longer resolves (removed or inaccessible after bootstrap bound it
// "active repo root binding") returns a *RepoRootResolveError carrying the would-be
// effective cwd and error category, so the caller can take the launch-failure path;
// any other resolution failure (e.g. an explicit cwd target that vanished while the
// root survives) is returned wrapped. It is the single source of an action's cwd:
// both Invoke and the tool wrapper's EffectiveCWD call it, so the authorized path
// and the executed path cannot drift.
func ResolveActionCWD(action *ActionSpec, repoRoot string) (string, error) {
	if action == nil {
		return "", fmt.Errorf("vcs: nil action spec")
	}
	candidate := action.Cwd
	switch {
	case candidate == "":
		candidate = repoRoot
	case filepath.IsAbs(candidate):
		// absolute cwd: used as-is.
	default:
		candidate = filepath.Join(repoRoot, candidate)
	}

	resolvedRoot, err := filepath.EvalSymlinks(repoRoot)
	if err != nil {
		// The active repo root itself no longer resolves — binds it once at
		// bootstrap, so a later removal/inaccessibility surfaces via the launch-failure
		// path. Carry the cleaned would-be effective cwd (the candidate) as the path
		// scope and the classified category so Invoke can synthesize that surface.
		return "", &RepoRootResolveError{
			PathScope: filepath.Clean(candidate),
			Category:  fserrors.CategorizeErrno(err),
			cause:     fmt.Errorf("vcs: resolve repo root %q: %w", repoRoot, err),
		}
	}
	resolvedCwd, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("vcs: resolve cwd %q: %w", candidate, err)
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	resolvedCwd = filepath.Clean(resolvedCwd)

	if !permissions.IsDescendantOrEqual(resolvedCwd, resolvedRoot) {
		return "", &CWDEscapeError{ResolvedCwd: resolvedCwd}
	}
	return resolvedCwd, nil
}

// Invoke runs a single non-detect VCS action and returns its raw tools.Result. It
// substitutes placeholders into argv, resolves and contains the cwd, mints the
// invocation id via the runner (— the runner owns the id), emits the
// paired tool_exec_start/tool_exec_end events, and synthesizes the
// launch-failure surface for a cwd escape or a failed process launch. cap is the
// registration-supplied sessions.max_tool_output_bytes: the persisted
// tool_exec_end stdout/stderr are capped through the shared truncation helper,
// while the returned tools.Result keeps the raw streams unchanged.
//
// A non-nil error is reserved for invalid input or an internal failure with no
// reliable result (mirroring the runner contract); the three failure modes
// — cwd escape, repo-root disappearance ("active repo root binding"), and
// process-launch failure — are carried on the returned Result, not as errors.
func Invoke(ctx context.Context, actionName string, action *ActionSpec, params map[string]string, repoRoot string, runner cmdrunner.Runner, emit EventAppender, cap int) (tools.Result, error) {
	resolvedCwd, cwdErr := ResolveActionCWD(action, repoRoot)
	return invokeResolvedCWD(ctx, actionName, action, params, runner, emit, resolvedCwd, cwdErr, cap)
}

func invokeResolvedCWD(ctx context.Context, actionName string, action *ActionSpec, params map[string]string, runner cmdrunner.Runner, emit EventAppender, resolvedCwd string, cwdErr error, cap int) (tools.Result, error) {
	if action == nil {
		return tools.Result{}, fmt.Errorf("vcs: nil action spec")
	}
	if actionName == "" {
		return tools.Result{}, fmt.Errorf("vcs: empty action name")
	}

	argv, err := substituteArgv(actionName, action.Argv, params)
	if err != nil {
		return tools.Result{}, err
	}
	if len(argv) == 0 {
		return tools.Result{}, fmt.Errorf("%s: empty argv", toolName(actionName))
	}

	var escErr *CWDEscapeError
	var rootErr *RepoRootResolveError
	switch {
	case errors.As(cwdErr, &escErr):
		// cwd escape: fail via the launch-failure path. The effective
		// cwd that was attempted (the escaping path) is the recorded path scope,
		// matching the moment-of-initiation semantics of a normal invocation.
		stderr := fmt.Sprintf("codemeld: %s: cwd escapes repo root: %s", toolName(actionName), escErr.ResolvedCwd)
		res := tools.Result{ExitCode: -1, Stderr: []byte(stderr)}
		return emitPaired(ctx, emit, actionName, escErr.ResolvedCwd, runner.NewInvocationID(), res, cap)
	case errors.As(cwdErr, &rootErr):
		// The active repo root was removed/became inaccessible after bootstrap bound
		// it ("active repo root binding"): fail via the launch-failure path
		// like a missing binary — same exit_code/stderr shape with argv[0] as the
		// binary and the classified category — and emit paired events. The would-be
		// effective cwd carried on the error is the recorded path scope.
		stderr := fmt.Sprintf("codemeld: %s: launch failed: %s: %s", toolName(actionName), argv[0], rootErr.Category)
		res := tools.Result{ExitCode: -1, Stderr: []byte(stderr)}
		return emitPaired(ctx, emit, actionName, rootErr.PathScope, runner.NewInvocationID(), res, cap)
	case cwdErr != nil:
		// A resolution failure that is neither an escape nor repo-root disappearance
		// — e.g. an action whose explicit cwd target vanished while the repo root
		// itself still resolves. No cleaned absolute path scope can be established
		// for it here, so it surfaces to the dispatcher as an error.
		return tools.Result{}, cwdErr
	}

	invocationID := runner.NewInvocationID()
	if err := emit(startPayload(actionName, resolvedCwd, invocationID, childInvocationID(ctx))); err != nil {
		return tools.Result{}, err
	}

	runRes, err := runner.Exec(ctx, cmdrunner.RunSpec{
		InvocationID: invocationID,
		Argv:         argv,
		Cwd:          resolvedCwd,
	})
	if err != nil {
		runErr := fmt.Errorf("%s: %w", toolName(actionName), err)
		synthesized := endPayload(actionName, tools.Result{ExitCode: -1}, 0, 0, invocationID, cap, childInvocationID(ctx))
		return tools.Result{}, errors.Join(runErr, emit(synthesized))
	}

	var res tools.Result
	var stdoutTotal, stderrTotal int64
	if runRes.LaunchErrCategory != "" {
		// Process failed to launch before starting (launch-failure path):
		// synthesize the prescribed stderr from argv[0] and the runner's category.
		stderr := fmt.Sprintf("codemeld: %s: launch failed: %s: %s", toolName(actionName), argv[0], runRes.LaunchErrCategory)
		res = tools.Result{ExitCode: -1, Stderr: []byte(stderr), Duration: runRes.Duration}
	} else {
		res = tools.Result{
			ExitCode: runRes.ExitCode,
			Stdout:   runRes.Stdout,
			Stderr:   runRes.Stderr,
			Duration: runRes.Duration,
		}
		stdoutTotal, stderrTotal = runRes.StdoutTotal, runRes.StderrTotal
	}

	if err := emit(endPayload(actionName, res, stdoutTotal, stderrTotal, invocationID, cap, childInvocationID(ctx))); err != nil {
		return tools.Result{}, err
	}
	return res, nil
}

// emitPaired emits both tool_exec_start and tool_exec_end for a result produced
// without running the process (the cwd-escape / repo-root-disappearance launch
// failures), with pathScope as the start event's path scope and a shared
// invocation id. cap caps the synthesized end-payload stderr identically to a
// normal completed run.
func emitPaired(ctx context.Context, emit EventAppender, actionName, pathScope, invocationID string, res tools.Result, cap int) (tools.Result, error) {
	childID := childInvocationID(ctx)
	if err := emit(startPayload(actionName, pathScope, invocationID, childID)); err != nil {
		return tools.Result{}, err
	}
	if err := emit(endPayload(actionName, res, 0, 0, invocationID, cap, childID)); err != nil {
		return tools.Result{}, err
	}
	return res, nil
}

func startPayload(actionName, pathScope, invocationID, childID string) events.ToolExecStart {
	return events.ToolExecStart{
		SubjectKind:       "tool",
		Subject:           toolName(actionName),
		PathScope:         pathScope,
		InvocationID:      invocationID,
		ChildInvocationID: childID,
	}
}

// endPayload builds the tool_exec_end for a completed (or synthesized) result,
// capping stdout/stderr through the shared truncation helper so the persisted bytes
// match what BuildModelInputBytes would feed the model for the same cap.
// cap is the registration-supplied sessions.max_tool_output_bytes;
// res.Stdout/res.Stderr stay raw on the returned tools.Result — only the event
// payload is capped.
func endPayload(actionName string, res tools.Result, stdoutTotal, stderrTotal int64, invocationID string, cap int, childID string) events.ToolExecEnd {
	if stdoutTotal != 0 || stderrTotal != 0 {
		return events.ToolExecEndFromBounded(events.BoundedToolExec{
			InvocationID:      invocationID,
			ChildInvocationID: childID,
			SubjectKind:       "tool",
			Subject:           toolName(actionName),
			ExitCode:          res.ExitCode,
			DurationMs:        res.Duration.Milliseconds(),
			Stdout:            res.Stdout,
			Stderr:            res.Stderr,
			StdoutTotal:       stdoutTotal,
			StderrTotal:       stderrTotal,
		}, cap)
	}
	keptOut, keptErr, truncated, original := events.TruncateToolOutput(res.Stdout, res.Stderr, cap)
	return events.ToolExecEnd{
		SubjectKind:       "tool",
		Subject:           toolName(actionName),
		ExitCode:          int64(res.ExitCode),
		DurationMs:        res.Duration.Milliseconds(),
		Stdout:            string(keptOut),
		Stderr:            string(keptErr),
		Truncated:         truncated,
		OriginalBytes:     original,
		InvocationID:      invocationID,
		ChildInvocationID: childID,
	}
}

// substituteArgv replaces every accepted placeholder occurrence in each argv
// element with its value from params. It re-checks the per-action
// placeholder rules as defense in depth — load-time validation already rejected
// template mismatches — and rejects a params map that names a placeholder the
// action does not accept or omits one its argv contains.
func substituteArgv(actionName string, argv []string, params map[string]string) ([]string, error) {
	accepted := placeholderActions[actionName] // "" for actions taking no placeholder
	acceptedKey := ""
	if accepted != "" {
		acceptedKey = strings.Trim(accepted, "{}")
	}
	for k := range params {
		if acceptedKey == "" || k != acceptedKey {
			return nil, fmt.Errorf("%s: unexpected parameter %q", toolName(actionName), k)
		}
	}

	out := make([]string, len(argv))
	for i, elem := range argv {
		result := elem
		for _, ph := range placeholderRe.FindAllString(elem, -1) {
			if !recognizedPlaceholders[ph] {
				return nil, fmt.Errorf("%s: unknown placeholder %s", toolName(actionName), ph)
			}
			if ph != accepted {
				return nil, fmt.Errorf("%s: placeholder %s is not accepted by this action", toolName(actionName), ph)
			}
			val, ok := params[acceptedKey]
			if !ok {
				return nil, fmt.Errorf("%s: missing value for placeholder %s", toolName(actionName), ph)
			}
			result = strings.ReplaceAll(result, ph, val)
		}
		out[i] = result
	}
	return out, nil
}
