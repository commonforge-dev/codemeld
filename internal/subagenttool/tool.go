// Package subagenttool registers the delegate tool, the production caller that hands one
// bounded piece of work to a child agent confined to caller-declared write, delete, and move scopes.
package subagenttool

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/subagent"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/turn"
)

const ToolName = "delegate"

const (
	instructionsArg = "instructions"
	filesArg        = "files"
	filesDeleteArg  = "files_delete"
	filesMoveArg    = "files_move"
	sourceKey       = "source"
	destinationKey  = "destination"
)

// Snapshot is the parent state one delegate call inherits, read when that call starts
// rather than when the tool was registered.
type Snapshot struct {
	Mode            string
	Model           model.Selection
	ModelSource     model.Source
	SupportedEffort func(providerID, modelID string) []string
	SystemPrompt    string
	Client          provider.Client
	Tools           []provider.ToolDefinition
	Registered      []tools.Tool
}

// Deps binds the tool to the run. NewDispatcher receives the child's authorization
// ceiling and returns a dispatcher bound to the parent's real file tools, so this
// package never assembles authority of its own.
type Deps struct {
	Home          string
	LaunchDir     string
	ProjectRoot   string
	Snapshot      func() (Snapshot, bool)
	NewDispatcher func(permissions.ModeContext) turn.ToolDispatcher
	// Store is the parent's session store: a child records into it rather than one of its own.
	Store func() *sessions.Store
	// Activity is the optional live surface for the child lifecycle. It is display-only: the
	// durable record is the start/end pair below, and a nil sink changes nothing.
	Activity subagent.ActivitySink
}

type Tool struct {
	deps Deps
}

var _ tools.Tool = (*Tool)(nil)

func New(deps Deps) *Tool {
	deps.ProjectRoot = normalizeRoot(deps.ProjectRoot)
	return &Tool{deps: deps}
}

func normalizeRoot(projectRoot string) string {
	if resolved, err := filepath.EvalSymlinks(projectRoot); err == nil {
		return resolved
	}
	return filepath.Clean(projectRoot)
}

func (t *Tool) Name() string { return ToolName }

func (t *Tool) SubjectKind() string { return "tool" }

func (t *Tool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Hand one self-contained piece of work to a child agent running in this process. " +
			"The instructions are delivered to the child as text with no shell in the path, so backticks, " +
			"$( ), quotes and newlines reach it byte for byte. The child may create or edit only the paths " +
			"listed in files, delete only the paths listed in files_delete, and move only the source and " +
			"destination pairs listed in files_move, and reports back a single summary of what it did.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				instructionsArg: map[string]any{
					"type":        "string",
					"description": "What the child agent should do, in plain text. Passed through verbatim; no shell interprets it.",
				},
				filesArg: map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Paths, relative to the launch directory and inside the project, that the child may create or edit. Absolute and ~-prefixed paths are refused. Optional when files_delete or files_move names a path.",
				},
				filesDeleteArg: map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Paths inside the project that the child may delete: a file, a symlink (removed as the link itself), or an empty directory. Relative, absolute, ~ and ~/ paths are accepted. A path listed only here may not be created or edited; list it in files as well for that. Optional when files or files_move names a path.",
				},
				filesMoveArg: map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							sourceKey:      map[string]any{"type": "string"},
							destinationKey: map[string]any{"type": "string"},
						},
						"required":             []string{sourceKey, destinationKey},
						"additionalProperties": false,
					},
					"description": "Moves inside the project that the child may make. Each pair names an existing source (a file or directory, not a symlink) and a destination that does not exist yet under an existing parent directory. A pair authorizes exactly that one move: not a move of its source anywhere else, not a write to its destination, and not a delete of its source. No path may be the source of one pair and the destination of another. Relative, absolute, ~ and ~/ paths are accepted. Optional when files or files_delete names a path.",
				},
			},
			"required":             []string{instructionsArg},
			"additionalProperties": false,
		},
		ReadOnly: false,
	}
}

// A caller that prepares separately from invocation must return Result in band; a delegate call
// rejected on its arguments was never a permission question and must not abort the turn.
type PreparationError struct {
	Reason string
}

func (e *PreparationError) Error() string { return ToolName + ": " + e.Reason }

func (e *PreparationError) Result() tools.Result { return failResult(e.Reason) }

func (t *Tool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	instruction, write, remove, moves, refusal := t.prepare(args)
	if refusal != nil {
		return refusal.Result(), nil
	}
	return t.InvokeWithPreparedDelegate(ctx, instruction, write, remove, moves)
}

func (t *Tool) PrepareDelegate(args map[string]any) (string, map[string]bool, map[string]bool, map[permissions.MovePair]bool, []string, error) {
	instruction, write, remove, moves, refusal := t.prepare(args)
	if refusal != nil {
		return "", nil, nil, nil, nil, refusal
	}
	return instruction, write, remove, moves, schedulerTargets(write, remove, moves), nil
}

// schedulerTargets names every path this child may mutate. An authorized create also makes each
// missing directory between its declared leaf and the deepest existing ancestor, so leaf-disjoint
// declarations under a shared missing parent still collide. Those parents are ordering data only —
// the declared leaves alone stay the child's write ceiling.
func schedulerTargets(write, remove map[string]bool, moves map[permissions.MovePair]bool) []string {
	targets := make(map[string]bool, len(write)+len(remove)+2*len(moves))
	for leaf := range remove {
		targets[leaf] = true
	}
	for pair := range moves {
		targets[pair.Source], targets[pair.Destination] = true, true
	}
	for leaf := range write {
		targets[leaf] = true
		for dir := filepath.Dir(leaf); ; {
			// A directory that cannot be stated at all is treated as one the child may create.
			if _, err := os.Lstat(dir); err == nil {
				break
			}
			targets[dir] = true
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return sortedPaths(targets)
}

func (t *Tool) prepare(args map[string]any) (string, map[string]bool, map[string]bool, map[permissions.MovePair]bool, *PreparationError) {
	instruction, write, remove, moves, err := t.validate(args)
	if err != nil {
		return "", nil, nil, nil, &PreparationError{Reason: err.Error()}
	}
	return instruction, write, remove, moves, nil
}

func (t *Tool) InvokeWithPreparedDelegate(ctx context.Context, instruction string, write, remove map[string]bool, moves map[permissions.MovePair]bool) (tools.Result, error) {
	snap, ok := t.deps.Snapshot()
	if !ok {
		return failResult("no model is resolvable, so no child agent can start"), nil
	}
	invocation := ids.NewV7()
	dispatcher := t.deps.NewDispatcher(permissions.ModeContext{
		Mode:              snap.Mode,
		ChildAgent:        true,
		ChildInvocationID: invocation,
		DeclaredWrite:     write,
		DeclaredDelete:    remove,
		DeclaredMoves:     moves,
	})
	if dispatcher == nil {
		return failResult("child agent dispatch is unavailable"), nil
	}

	// One store resolves both halves of the lifecycle pair: re-reading the accessor at the end
	// could hand back a different store or none at all, and a start that has already been
	// appended would then have nothing to close it.
	store, serr := t.store()
	if serr != nil {
		return failResult("the child agent could not be recorded in the session, so no child agent started: " + serr.Error()), nil
	}

	journal, jerr := t.openJournal(ctx, write, remove, moves)
	if jerr != nil {
		return failResult("the child agent's changes could not be made undoable, so no child agent started: " + jerr.Error()), nil
	}

	// A failed start record stops the child, so the journal opened above has to be resolved by
	// hand here: subagent.Run, which normally does it, is never reached.
	start := childStartPayload(invocation, instruction, write, remove, moves, snap)
	if err := events.EmitChildAgentStart(store, t.deps.ProjectRoot, start); err != nil {
		journal.Finish(subagent.ReasonFailed)
		journal.Close()
		return failResult("the child agent could not be recorded in the session, so no child agent started: " + err.Error()), nil
	}
	if t.deps.Activity != nil {
		t.deps.Activity.ChildAgentStarted(start)
	}

	permitted := childPermittedTools(snap.Registered)
	started := time.Now()
	res, runErr := subagent.Run(ctx, subagent.Request{
		Instruction:     instruction,
		Model:           snap.Model,
		ModelSource:     snap.ModelSource,
		SupportedEffort: snap.SupportedEffort,
		SystemPrompt:    snap.SystemPrompt,
		Client:          snap.Client,
		Tools:           childTools(snap.Tools, permitted),
		Dispatcher: &confinedDispatcher{
			inner:     dispatcher,
			permitted: permitted,
			nested:    t.nestedDelegate(snap.Mode, write, remove, moves, invocation),
		},
		StepCap:      subagent.DefaultStepCap,
		Journal:      journal,
		InvocationID: invocation,
		Activity:     t.deps.Activity,
	})
	end := childEndPayload(invocation, res, time.Since(started))
	endErr := events.EmitChildAgentEnd(store, t.deps.ProjectRoot, end)
	// The block closes from the in-process outcome even when the record could not be
	// appended, so a session that lost its end record does not leave a child shown as running.
	if t.deps.Activity != nil {
		t.deps.Activity.ChildAgentEnded(end)
	}
	out := render(res)
	if runErr != nil {
		// The rendered outcome still has to reach the parent: a loop failure is exactly the case where
		// the child's declared writes were rolled back, and reporting only the error would hide that.
		out.ExitCode = 1
		out.Stderr = []byte(ToolName + ": the child agent failed: " + runErr.Error() + "\n")
	}
	if endErr != nil {
		out.ExitCode = 1
		out.Stderr = append(out.Stderr, []byte(ToolName+": the child agent's outcome could not be recorded in the session: "+endErr.Error()+"\n")...)
	}
	return out, nil
}

func childStartPayload(invocation, instruction string, write, remove map[string]bool, moves map[permissions.MovePair]bool, snap Snapshot) events.ChildAgentStart {
	start := events.ChildAgentStart{
		InvocationID:      invocation,
		ProviderID:        snap.Model.Provider,
		ModelID:           snap.Model.ID,
		DeclaredPaths:     sortedPaths(write),
		StepCap:           subagent.DefaultStepCap,
		InstructionBytes:  int64(len(instruction)),
		InstructionDigest: events.ChildInstructionDigest(instruction),
	}
	if len(remove) > 0 {
		start.DeclaredDeletePaths = sortedPaths(remove)
	}
	if len(moves) > 0 {
		start.DeclaredMovePairs = recordedMovePairs(moves)
	}
	return start
}

func childEndPayload(invocation string, res subagent.Result, elapsed time.Duration) events.ChildAgentEnd {
	end := events.ChildAgentEnd{
		InvocationID:    invocation,
		Reason:          string(res.Reason),
		Steps:           int64(res.ProviderRequests),
		WrittenPaths:    firstOccurrences(res.WriteTargets),
		RollbackOutcome: rollbackOutcome(res),
		DurationMs:      elapsed.Milliseconds(),
		ReplyTruncated:  res.ReplyTruncated,
	}
	if len(res.DeleteTargets) > 0 {
		end.DeletedPaths = firstOccurrences(res.DeleteTargets)
	}
	if len(res.MoveTargets) > 0 {
		end.MovedPairs = movedPairs(res.MoveTargets)
	}
	return end
}

func recordedMovePairs(declared map[permissions.MovePair]bool) []events.ChildMovePair {
	pairs := make([]events.ChildMovePair, 0, len(declared))
	for pair := range declared {
		pairs = append(pairs, events.ChildMovePair{Source: pair.Source, Destination: pair.Destination})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Source != pairs[j].Source {
			return pairs[i].Source < pairs[j].Source
		}
		return pairs[i].Destination < pairs[j].Destination
	})
	return pairs
}

func movedPairs(targets []turn.MoveTarget) []events.ChildMovePair {
	seen := make(map[turn.MoveTarget]bool, len(targets))
	out := make([]events.ChildMovePair, 0, len(targets))
	for _, target := range targets {
		if seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, events.ChildMovePair{Source: target.Source, Destination: target.Destination})
	}
	return out
}

func (t *Tool) store() (*sessions.Store, error) {
	if t.deps.Store == nil {
		return nil, fmt.Errorf("no session store is wired for child agent records")
	}
	store := t.deps.Store()
	if store == nil {
		return nil, fmt.Errorf("no active session store for child agent records")
	}
	return store, nil
}

// The journal's report outranks the terminal reason, so a restore that left the child's writes
// in place is never recorded as a clean undo.
func rollbackOutcome(res subagent.Result) string {
	switch {
	case len(res.Unrecovered) > 0 || res.RetainedJournal != "":
		return events.ChildRollbackUnrecovered
	case res.Reason == subagent.ReasonCompleted:
		return events.ChildRollbackNotNeeded
	default:
		return events.ChildRollbackRolledBack
	}
}

// Keeping each path once bounds the recorded list by the declared scope however many times the
// child rewrote or re-deleted a path.
func firstOccurrences(targets []string) []string {
	seen := make(map[string]bool, len(targets))
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		if seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	return out
}

func sortedPaths(declared map[string]bool) []string {
	paths := make([]string, 0, len(declared))
	for target := range declared {
		paths = append(paths, target)
	}
	sort.Strings(paths)
	return paths
}

// openJournal snapshots the declared scope before the child is dispatched, linking a nested delegate's
// journal to the one bound to ctx so the parent can absorb it deepest-first.
func (t *Tool) openJournal(ctx context.Context, write, remove map[string]bool, moves map[permissions.MovePair]bool) (*subagent.Journal, error) {
	parent, _ := filetools.WriteJournalFromContext(ctx).(*subagent.Journal)
	return subagent.OpenJournal(subagent.JournalConfig{
		Home:           t.deps.Home,
		ProjectRoot:    t.deps.ProjectRoot,
		Invocation:     ids.NewV7(),
		Declared:       sortedPaths(write),
		DeclaredDelete: sortedPaths(remove),
		DeclaredMoves:  sortedPairs(moves),
		Parent:         parent,
	})
}

func sortedPairs(declared map[permissions.MovePair]bool) []permissions.MovePair {
	pairs := slices.Collect(maps.Keys(declared))
	slices.SortFunc(pairs, func(a, b permissions.MovePair) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.Destination, b.Destination))
	})
	return pairs
}

// At least one path is required across the forms: the nested containment check reads a
// candidate with no path in any form as a declaration that did not resolve.
func (t *Tool) validate(args map[string]any) (string, map[string]bool, map[string]bool, map[permissions.MovePair]bool, error) {
	if err := rejectUnknownArgs(args); err != nil {
		return "", nil, nil, nil, err
	}
	instruction, err := requireString(args, instructionsArg)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if strings.TrimSpace(instruction) == "" {
		return "", nil, nil, nil, fmt.Errorf("argument %q must not be empty", instructionsArg)
	}
	files, filesGiven, err := optionalStringSlice(args, filesArg)
	if err != nil {
		return "", nil, nil, nil, err
	}
	deletes, deletesGiven, err := optionalStringSlice(args, filesDeleteArg)
	if err != nil {
		return "", nil, nil, nil, err
	}
	pairs, pairsGiven, err := optionalMovePairs(args)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if len(files)+len(deletes)+len(pairs) == 0 {
		return "", nil, nil, nil, fmt.Errorf("arguments %q, %q and %q must name at least one path between them", filesArg, filesDeleteArg, filesMoveArg)
	}
	for i, raw := range files {
		switch {
		case strings.TrimSpace(raw) == "":
			return "", nil, nil, nil, fmt.Errorf("argument %q[%d] must not be empty", filesArg, i)
		case filepath.IsAbs(raw):
			return "", nil, nil, nil, fmt.Errorf("argument %q[%d] %q must be relative to the launch directory", filesArg, i, raw)
		case strings.HasPrefix(raw, "~"):
			return "", nil, nil, nil, fmt.Errorf("argument %q[%d] %q must not be home-relative", filesArg, i, raw)
		}
	}
	for i, raw := range deletes {
		switch {
		case strings.TrimSpace(raw) == "":
			return "", nil, nil, nil, fmt.Errorf("argument %q[%d] must not be empty", filesDeleteArg, i)
		case strings.HasPrefix(raw, "~") && raw != "~" && !strings.HasPrefix(raw, "~/"):
			return "", nil, nil, nil, fmt.Errorf("argument %q[%d] %q uses the unsupported ~user form; only ~ and ~/<subpath> are supported", filesDeleteArg, i, raw)
		}
	}
	write, remove, err := filetools.ResolveDeclaredScopes(t.deps.Home, t.deps.LaunchDir, files, deletes)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("arguments %q and %q: %w", filesArg, filesDeleteArg, err)
	}
	if err := t.confine(filesArg, write); err != nil {
		return "", nil, nil, nil, err
	}
	if err := t.confine(filesDeleteArg, remove); err != nil {
		return "", nil, nil, nil, err
	}
	moves, err := t.resolveMoves(pairs, pairsGiven)
	if err != nil {
		return "", nil, nil, nil, err
	}
	return instruction, suppliedSet(write, filesGiven), suppliedSet(remove, deletesGiven), moves, nil
}

func (t *Tool) confine(arg string, declared map[string]bool) error {
	for target := range declared {
		if !permissions.IsDescendantOrEqual(target, t.deps.ProjectRoot) {
			return fmt.Errorf("argument %q resolves %q outside the project", arg, target)
		}
	}
	return nil
}

func (t *Tool) resolveMoves(pairs []permissions.MovePair, given bool) (map[permissions.MovePair]bool, error) {
	if !given {
		return nil, nil
	}
	mover := filetools.NewMoveTool(t.deps.Home, t.deps.LaunchDir, t.deps.ProjectRoot)
	moves := make(map[permissions.MovePair]bool, len(pairs))
	for i, raw := range pairs {
		resolved, err := mover.ResolveEndpoints(map[string]any{sourceKey: raw.Source, destinationKey: raw.Destination})
		if err != nil {
			return nil, fmt.Errorf("argument %q[%d]: %w", filesMoveArg, i, err)
		}
		for _, endpoint := range []string{resolved.Source, resolved.Destination} {
			if !permissions.IsDescendantOrEqual(endpoint, t.deps.ProjectRoot) {
				return nil, fmt.Errorf("argument %q[%d] resolves %q outside the project", filesMoveArg, i, endpoint)
			}
		}
		moves[permissions.MovePair{Source: resolved.Source, Destination: resolved.Destination}] = true
	}
	return moves, nil
}

// A supplied list stays a non-nil set even when it names nothing, which is how authorization tells a
// supplied empty declaration from an omitted one.
func suppliedSet(declared map[string]bool, supplied bool) map[string]bool {
	if supplied && declared == nil {
		return map[string]bool{}
	}
	return declared
}

// delete, mkdir, move and delegate are pinned in so each reaches authorization and is refused
// there for the child declaration form it lacks. Withholding them instead would make a missing
// declaration look like a missing capability, and a later declaration form would have to unpick
// a prohibition rather than fill a set.
var childToolNames = map[string]bool{
	filetools.ReadToolName:      true,
	filetools.ReadImageToolName: true,
	filetools.GlobToolName:      true,
	filetools.GrepToolName:      true,
	filetools.ListToolName:      true,
	filetools.TreeToolName:      true,
	filetools.FileCountToolName: true,
	filetools.EditToolName:      true,
	filetools.CreateToolName:    true,
	filetools.DeleteToolName:    true,
	filetools.MkdirToolName:     true,
	filetools.MoveToolName:      true,
	ToolName:                    true,
}

const vcsToolNamePrefix = "vcs_"

// A vcs_<action> tool joins the set on what its registered instance advertises, never on its
// name or the source of the template that defined it — only the VCS layer classifies which argv
// an action runs. That classification covers the argv alone: hooks, extensions and repository
// configuration reached through it stay unsandboxed.
func childPermittedTools(registered []tools.Tool) map[string]bool {
	permitted := make(map[string]bool, len(childToolNames)+len(registered))
	for name := range childToolNames {
		permitted[name] = true
	}
	for _, tool := range registered {
		name := tool.Name()
		if !strings.HasPrefix(name, vcsToolNamePrefix) {
			continue
		}
		if meta := tool.Advertise(); meta.ReadOnly && meta.Noncredential {
			permitted[name] = true
		}
	}
	return permitted
}

func childTools(parent []provider.ToolDefinition, permitted map[string]bool) []provider.ToolDefinition {
	out := make([]provider.ToolDefinition, 0, len(permitted))
	for _, def := range parent {
		if permitted[def.Name] {
			out = append(out, def)
		}
	}
	return out
}

// confinedDispatcher holds the child to the pinned set at execution time. childTools narrows
// only what is *advertised*, and an advertised set is a suggestion the model can ignore: the
// child runs on the parent's own production dispatcher, so an unadvertised bash, VCS or web
// call would otherwise reach ordinary authorization and be judged on the parent's permissions
// alone. Provider output is not an enforcement layer. Both halves read the one permitted set,
// so what is offered and what is honored cannot drift apart.
type confinedDispatcher struct {
	inner     turn.ToolDispatcher
	permitted map[string]bool
	// nested handles a delegate call the child itself makes. That one call is withheld from the
	// inner dispatcher so no grant, turn-cache entry, mode auto-allow, or prompt reachable there
	// can authorize it; the child's own declaration is the only route.
	nested func(context.Context, turn.AssembledToolCall) (turn.ToolResult, error)
}

var _ turn.ToolDispatcher = (*confinedDispatcher)(nil)

// Plan is where the confinement has to bite: turn's loop calls Plan once and then runs the
// units it returns, reaching Dispatch only through their Run closures, so a check in Dispatch
// alone would never see a call. A call this dispatcher answers itself — a refusal, or a nested
// delegate — is withheld from the inner Plan entirely rather than filtered afterward: the
// production planner prepares structured reads and assembles authorization groups there, and a
// confined-away call must take part in neither. Forwarded calls
// keep their relative order and the planner's own unit metadata, and a child loop runs at
// concurrency 1, so model-call order survives. What the removal does change is barriers: two
// runs of eligible reads that a withheld call separated are planned as one, so a read whose
// internal error the ContinueOnError path has not yet reported no longer blocks the reads that
// followed the withheld call. Nothing is authorized or executed that would not have been, and a
// refused call itself never runs. Units stay index-aligned with calls, which turn validates.
func (d *confinedDispatcher) Plan(calls []turn.AssembledToolCall, maxConcurrency int) turn.ToolPlan {
	forwarded := make([]turn.AssembledToolCall, 0, len(calls))
	for _, call := range calls {
		if d.forwards(call.Name) {
			forwarded = append(forwarded, call)
		}
	}
	if len(forwarded) == len(calls) {
		return d.inner.Plan(calls, maxConcurrency)
	}
	inner := d.inner.Plan(forwarded, maxConcurrency)
	if len(inner.Units) != len(forwarded) {
		// A malformed inner plan cannot be re-expanded onto the original calls; hand it back
		// untouched so turn's own plan validation rejects it, rather than inventing units here.
		return inner
	}
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	next := 0
	for i, call := range calls {
		if !d.forwards(call.Name) {
			plan.Units[i] = turn.PlannedToolCall{
				Call: call,
				Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.answer(ctx, call) },
			}
			continue
		}
		plan.Units[i] = inner.Units[next]
		next++
	}
	return plan
}

func (d *confinedDispatcher) forwards(name string) bool {
	return d.permitted[name] && !d.handlesNested(name)
}

func (d *confinedDispatcher) handlesNested(name string) bool {
	return name == ToolName && d.nested != nil
}

func (d *confinedDispatcher) answer(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	if d.handlesNested(call.Name) {
		return d.nested(ctx, call)
	}
	return refuseChildTool(call.Name), nil
}

func (d *confinedDispatcher) Dispatch(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	if !d.forwards(call.Name) {
		return d.answer(ctx, call)
	}
	return d.inner.Dispatch(ctx, call)
}

func (t *Tool) nestedDelegate(mode string, write, remove map[string]bool, moves map[permissions.MovePair]bool, invocation string) func(context.Context, turn.AssembledToolCall) (turn.ToolResult, error) {
	return func(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
		nestedWrite, nestedDelete, nestedMoves := t.nestedDeclaration(call.Arguments)
		dispatcher := t.deps.NewDispatcher(permissions.ModeContext{
			Mode:              mode,
			ChildAgent:        true,
			ChildInvocationID: invocation,
			DeclaredWrite:     write,
			DeclaredDelete:    remove,
			DeclaredMoves:     moves,
			DelegateWrite:     nestedWrite,
			DelegateDelete:    nestedDelete,
			DelegateMoves:     nestedMoves,
		})
		if dispatcher == nil {
			return turn.ToolResult{Content: ToolName + ": child agent dispatch is unavailable"}, nil
		}
		return dispatcher.Dispatch(ctx, call)
	}
}

// A nested declaration that does not parse or does not validate resolves to the empty set, which
// the containment check refuses.
func (t *Tool) nestedDeclaration(arguments string) (write, remove map[string]bool, moves map[permissions.MovePair]bool) {
	var args map[string]any
	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return nil, nil, nil
	}
	_, write, remove, moves, err := t.validate(args)
	if err != nil {
		return nil, nil, nil
	}
	return write, remove, moves
}

// A refusal is an in-band tool error, not a deny envelope: the call was never a permission
// question — the tool does not exist for a child at all — so the child should read the
// refusal and pick a permitted alternative rather than have the turn halt on it. Minting a
// deny envelope is the authorizer's business, not this package's.
func refuseChildTool(name string) turn.ToolResult {
	return turn.ToolResult{Content: fmt.Sprintf("tool %q is not available to a child agent", name)}
}

func render(res subagent.Result) tools.Result {
	var b strings.Builder
	fmt.Fprintf(&b, "child agent %s after %d provider request(s)\n", res.Reason, res.ProviderRequests)
	if res.ReplyTruncated {
		b.WriteString("the child's reply was truncated\n")
	}
	if reply := strings.TrimRight(res.Reply, "\n"); reply != "" {
		b.WriteString(reply + "\n")
	}
	if res.Reason != subagent.ReasonCompleted && len(res.RestoredPaths) > 0 {
		b.WriteString("the child agent did not complete, so its changes were undone; restored:\n")
		for _, path := range res.RestoredPaths {
			b.WriteString("  " + path + "\n")
		}
	}
	if res.RetainedJournal != "" {
		b.WriteString("the child agent's changes could not be fully undone; its journal is retained at " + res.RetainedJournal + "\n")
		for _, note := range res.Unrecovered {
			b.WriteString("  " + note + "\n")
		}
	}
	out := tools.Result{Stdout: []byte(b.String())}
	if res.Reason != subagent.ReasonCompleted || res.RetainedJournal != "" {
		out.ExitCode = 1
	}
	return out
}

func failResult(msg string) tools.Result {
	return tools.Result{ExitCode: 1, Stderr: []byte(ToolName + ": " + msg + "\n")}
}

var allowedArgs = map[string]struct{}{instructionsArg: {}, filesArg: {}, filesDeleteArg: {}, filesMoveArg: {}}

func rejectUnknownArgs(args map[string]any) error {
	for key := range args {
		if _, ok := allowedArgs[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only %s, %s, %s and %s are accepted", key, instructionsArg, filesArg, filesDeleteArg, filesMoveArg)
		}
	}
	return nil
}

func optionalMovePairs(args map[string]any) ([]permissions.MovePair, bool, error) {
	raw, ok := args[filesMoveArg]
	if !ok {
		return nil, false, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, true, fmt.Errorf("argument %q must be an array of objects with %q and %q", filesMoveArg, sourceKey, destinationKey)
	}
	out := make([]permissions.MovePair, 0, len(list))
	for i, item := range list {
		fields, isObject := item.(map[string]any)
		source, sourceOK := fields[sourceKey].(string)
		destination, destinationOK := fields[destinationKey].(string)
		if !isObject || len(fields) != 2 || !sourceOK || !destinationOK {
			return nil, true, fmt.Errorf("argument %q[%d] must be an object with exactly the string fields %q and %q", filesMoveArg, i, sourceKey, destinationKey)
		}
		out = append(out, permissions.MovePair{Source: source, Destination: destination})
	}
	return out, true, nil
}

func requireString(args map[string]any, key string) (string, error) {
	raw, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", key)
	}
	return s, nil
}

func optionalStringSlice(args map[string]any, key string) ([]string, bool, error) {
	raw, ok := args[key]
	if !ok {
		return nil, false, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, true, fmt.Errorf("argument %q must be an array of strings", key)
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, true, fmt.Errorf("argument %q[%d] must be a string", key, i)
		}
		out = append(out, s)
	}
	return out, true, nil
}
