// Built-in structured move tool: no-overwrite rename of an existing in-project entry to a new path,
// with independent pre-authorization resolution of both endpoints and an atomic no-overwrite publish
// through the fsutil rename helper. Unregistered in this slice — production wiring, the multi-scope
// dispatch seam, mode posture, and advertising land in later slices; this file owns only the tool, its
// two-endpoint resolved handoff, and its standalone guard.
package filetools

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// MoveToolName is the exact dispatch name the structured move tool will register under once a later
// slice wires it into production. Like `edit`, `create`, and `bash` it is a fixed built-in name carrying
// no template namespace.
const MoveToolName = "move"

// MoveTool is the built-in mutating move tool. It renames an existing entry (a regular file or a
// directory) to a destination that must not already exist in any form, never overwriting and never
// following a final symlink on either endpoint. Unlike the single-target file tools, a move carries two
// independent endpoints — a source to read-and-relocate and a destination to create — each with its own
// resolved real path and authorization scope, so it resolves and classifies them separately rather than
// through the single-target seam. The run-scoped home, process cwd, and project root are bound at
// construction so the same expansion/cleaning/symlink/containment rules used for permission path scopes
// resolve both endpoints, exactly as the edit and create tools resolve their single target.
type MoveTool struct {
	home        string
	processCWD  string
	projectRoot string
}

var _ tools.Tool = (*MoveTool)(nil)

// ResolvedMove is the move-specific two-endpoint handoff the multi-scope dispatch seam consumes. It
// carries each endpoint's resolved real path, the authorization scope to grant (the resolved real parent
// directory the read/write touches), and whether that scope lies outside the project root (the
// promptable out-of-root signal). The two scopes are kept distinct so dispatch can authorize each
// separately — a move can have an in-root source and an out-of-root destination, or vice versa — and so a
// grant on one endpoint can never silently widen to the other. ResolveEndpoints produces it; the
// pre-resolved InvokeWithResolvedMove consumes the same value so authorization and the rename cannot
// drift if a symlink changes in between.
type ResolvedMove struct {
	Source               string
	SourceScope          string
	SourceOutOfRoot      bool
	Destination          string
	DestinationScope     string
	DestinationOutOfRoot bool
}

// NewMoveTool builds the move tool bound to the run's ~ anchor (home), the default base directory for a
// relative endpoint path (processCWD), and the project root both endpoints are classified against. The
// project root is symlink-resolved once here so the containment check compares it against the
// symlink-resolved parent on the same footing — mirroring NewEditTool and NewCreateTool.
func NewMoveTool(home, processCWD, projectRoot string) *MoveTool {
	return &MoveTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot)}
}

func (t *MoveTool) Name() string { return MoveToolName }

func (t *MoveTool) SubjectKind() string { return "tool" }

// Advertise returns the move tool's advertising metadata and mutating classification. The parameter
// JSON-Schema is the OpenAI function-tool shape with additionalProperties:false and a closed
// {source, destination} object so the advertised contract matches the decoder exactly. ReadOnly is false:
// move mutates the filesystem, so Plan denies it and Auto edits may auto-approve it.
func (t *MoveTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Move (rename) an existing file or directory to a new path. The source must already " +
			"exist and must not be a symlink; the destination must not already exist (file, directory, or " +
			"symlink) and its parent directory must already exist; the call fails without moving anything " +
			"otherwise. Never overwrites an existing destination. Source and destination must be on the same " +
			"filesystem. Use to rename or relocate something that already exists.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"source": map[string]any{
					"type":        "string",
					"description": "Path of the existing file or directory to move. Relative or in-project paths resolve against the working directory and move normally; a path whose real (symlink-resolved) parent is outside the project is allowed only after you approve it at the permission prompt.",
				},
				"destination": map[string]any{
					"type":        "string",
					"description": "New path for the entry. Must not already exist and its parent directory must already exist. Relative or in-project paths resolve against the working directory; a path whose real (symlink-resolved) parent is outside the project is allowed only after you approve it at the permission prompt.",
				},
			},
			"required":             []string{"source", "destination"},
			"additionalProperties": false,
		},
		ReadOnly: false,
	}
}

// ResolveEndpoints resolves both move endpoints from args before authorization and classifies each
// against the project root. It rejects unknown arguments, then anchors each endpoint's parent through the
// shared symlink-resolving parent resolver, refuses a source and destination that resolve to the same
// path, applies the source (must-exist, non-symlink) and destination (must-not-exist) preconditions, and
// returns the resolved real paths and authorization scopes for both endpoints together with their
// out-of-root verdicts. A missing source, an existing destination, a missing destination parent, a final
// source symlink, an existing destination node of any kind, a basename escaping its resolved parent, an
// unsupported ~user form, or an invalid argument is rejected with a *TargetError before any prompt. An
// out-of-root endpoint is not rejected here: it is classified out-of-root and routed to the
// approval prompt, anchored on its real out-of-root parent folder.
func (t *MoveTool) ResolveEndpoints(args map[string]any) (ResolvedMove, error) {
	if verr := rejectUnknownMoveArgs(args); verr != nil {
		return ResolvedMove{}, &TargetError{Kind: MoveToolName, Reason: verr.Error()}
	}

	srcParent, srcCandidate, err := t.anchorEndpoint("source", args)
	if err != nil {
		return ResolvedMove{}, err
	}
	dstParent, dstCandidate, err := t.anchorEndpoint("destination", args)
	if err != nil {
		return ResolvedMove{}, err
	}

	// Compare the anchored endpoints before the existence preconditions so a move onto its own resolved
	// path surfaces as the distinct same-endpoint rejection rather than as "destination already exists"
	// (the destination precondition would otherwise see the source entry sitting at the shared path).
	if filepath.Clean(srcCandidate) == filepath.Clean(dstCandidate) {
		return ResolvedMove{}, &TargetError{Kind: MoveToolName, Reason: "source and destination resolve to the same path"}
	}

	source, sourceScope, reason := moveSourcePrecondition(srcParent, srcCandidate)
	if reason != "" {
		return ResolvedMove{}, &TargetError{Kind: MoveToolName, Reason: "source: " + reason}
	}
	destination, destinationScope, reason := moveDestinationPrecondition(dstParent, dstCandidate)
	if reason != "" {
		return ResolvedMove{}, &TargetError{Kind: MoveToolName, Reason: "destination: " + reason}
	}

	return ResolvedMove{
		Source:               source,
		SourceScope:          sourceScope,
		SourceOutOfRoot:      t.OutOfRootScope(sourceScope),
		Destination:          destination,
		DestinationScope:     destinationScope,
		DestinationOutOfRoot: t.OutOfRootScope(destinationScope),
	}, nil
}

// anchorEndpoint reads one endpoint argument by key and anchors its parent directory through the shared
// resolveAnchoredTarget (~ expansion, relative-to-cwd resolution, symlink-resolution of the parent, and
// rejection of the unsupported ~user form), returning the resolved parent and the anchored candidate
// path. A missing/non-string/empty argument or an unresolvable parent is returned as a *TargetError keyed
// to the endpoint so the caller can prefix the reason.
func (t *MoveTool) anchorEndpoint(key string, args map[string]any) (parent string, candidate string, err error) {
	raw, perr := requireStringArg(args, key)
	if perr != nil {
		return "", "", &TargetError{Kind: MoveToolName, Reason: perr.Error()}
	}
	if strings.TrimSpace(raw) == "" {
		return "", "", &TargetError{Kind: MoveToolName, Reason: key + " must be non-empty"}
	}
	parent, candidate, _, reason := resolveAnchoredTarget(t.home, t.processCWD, t.projectRoot, raw)
	if reason != "" {
		return "", "", &TargetError{Kind: MoveToolName, Reason: key + ": " + reason}
	}
	return parent, candidate, nil
}

// OutOfRootScope reports whether scope (a resolved endpoint scope ResolveEndpoints returned) lies outside
// this tool's project root — the out-of-root signal dispatch uses to re-enable the folder grant
// option for an out-of-root move endpoint. Containment uses the same descendant rule as folder-grant path
// scopes; the scope is the resolved real parent directory, so the verdict matches the folder the
// read/write touches.
func (t *MoveTool) OutOfRootScope(scope string) bool {
	return !permissions.IsDescendantOrEqual(scope, t.projectRoot)
}

// moveSourcePrecondition is the move tool's must-exist, non-symlink source precondition. It re-checks
// that the anchored source stays within its resolved parent (a ".." basename can point the candidate
// above the parent — a structural escape refused regardless of project root so the authorized scope
// always contains the endpoint), then uses os.Lstat — not os.Stat — so the final component is inspected
// without being followed: a missing source is refused, and a final symlink is refused rather than
// followed (move relocates the real entry, never a link to it, matching the fd-relative O_NOFOLLOW rename
// the helper performs). A regular file or a directory is accepted. The resolved source is the anchored
// candidate; the scope is the resolved parent. Out-of-root is not a rejection here.
func moveSourcePrecondition(parent string, candidate string) (target string, scope string, reason string) {
	clean := filepath.Clean(candidate)
	if !permissions.IsDescendantOrEqual(clean, parent) {
		return "", "", "source escapes its parent directory"
	}
	info, lerr := os.Lstat(clean)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			return "", "", "source does not exist"
		}
		return "", "", "cannot determine whether the source exists"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", "", "source is a symlink; move does not follow symlinks"
	}
	return clean, parent, ""
}

// moveDestinationPrecondition is the move tool's must-not-exist destination precondition. It re-checks
// that the anchored destination stays within its resolved parent (refusing a ".." escape regardless of
// project root), then uses os.Lstat — not os.Stat — so an existing symlink, including a dangling one,
// counts as an existing destination and is refused rather than mistaken for absence. No-overwrite safety
// depends on refusing every existing destination form before the rename. The resolved destination is the
// anchored candidate; the scope is the resolved parent (a missing parent was already rejected when the
// endpoint was anchored). Out-of-root is not a rejection here.
func moveDestinationPrecondition(parent string, candidate string) (target string, scope string, reason string) {
	clean := filepath.Clean(candidate)
	if !permissions.IsDescendantOrEqual(clean, parent) {
		return "", "", "destination escapes its parent directory"
	}
	if _, lerr := os.Lstat(clean); lerr == nil {
		return "", "", "destination already exists; move does not overwrite"
	} else if !errors.Is(lerr, fs.ErrNotExist) {
		return "", "", "cannot determine whether the destination already exists"
	}
	return clean, parent, ""
}

// InvokeWithResolvedMove performs the rename for the endpoint pair dispatch already resolved and
// authorized, so authorization and the rename cannot drift if a symlink changes in between — the
// resolved-before-authorize / reuse-at-invoke contract the edit and create tools follow, extended to two
// endpoints. It is the pre-resolved invocation path the multi-scope dispatch seam will call after
// authorizing both scopes; it does not re-resolve the lexical arguments.
func (t *MoveTool) InvokeWithResolvedMove(ctx context.Context, resolved ResolvedMove) (tools.Result, error) {
	return t.move(ctx, resolved.Source, resolved.Destination), nil
}

// Invoke resolves both endpoints and moves in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveEndpoints then InvokeWithResolvedMove; this method keeps the tool a
// complete unit for direct callers and tests. An endpoint-resolution failure surfaces as the same in-band
// error result the dispatcher would render, so the observable outcome matches either entry.
//
// Standalone Invoke has no authorizer, so it must enforce the out-of-root boundary itself: an out-of-root
// source or destination (OutOfRootScope) is reachable only by explicit per-write approval, which only the
// dispatch path can obtain. This method therefore refuses either out-of-root endpoint in-band rather than
// moving — without this guard a direct caller could read from or write to outside the project root with
// no prompt or grant check. The fully in-root path is unchanged.
func (t *MoveTool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	resolved, err := t.ResolveEndpoints(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if resolved.SourceOutOfRoot || resolved.DestinationOutOfRoot {
		return failResult("move endpoint outside the project root requires permission approval through dispatch"), nil
	}
	return t.InvokeWithResolvedMove(ctx, resolved)
}

// move renames source to destination through the fsutil no-overwrite helper, which opens both parents
// without following a final symlink, renames relative to the held descriptors with an atomic no-replace
// primitive, and fails closed on an existing destination, a missing source, a cross-device attempt, an
// unsupported platform, or a parent moved mid-operation — so the post-authorization symlink-swap, rename,
// and overwrite guards live in the helper rather than being re-implemented here. A failure surfaces as a
// non-zero result (not a Go error) so the tool-call loop records it in-band and the model can correct
// itself rather than aborting the turn.
func (t *MoveTool) move(ctx context.Context, source string, destination string) tools.Result {
	journal := WriteJournalFor(ctx, source)
	if journal == nil {
		journal = WriteJournalFor(ctx, destination)
	}
	var lifecycle fsutil.MoveLifecycle
	if journal != nil {
		lifecycle = journal.MoveLifecycle(source, destination)
	}
	if _, _, err := fsutil.MoveNoReplace(source, destination, lifecycle); err != nil {
		return failResult("failed to move " + source + " to " + destination + ": " + err.Error())
	}
	return tools.Result{ExitCode: 0, Stdout: []byte(fmt.Sprintf("moved %s to %s\n", source, destination))}
}

// allowedMoveArgs is the exact closed set of argument keys the move tool accepts, matching the advertised
// additionalProperties:false schema.
var allowedMoveArgs = map[string]struct{}{"source": {}, "destination": {}}

// rejectUnknownMoveArgs fails closed if args carries any key outside the advertised closed schema, so the
// runtime contract is no broader than the advertised one. The provider-facing JSON-Schema sets
// additionalProperties:false, so a conforming caller never trips this; it is defense-in-depth that keeps
// an extra-property call from resolving, authorizing, or moving on a mutating tool that Auto edits may
// later auto-approve without prompting.
func rejectUnknownMoveArgs(args map[string]any) error {
	for key := range args {
		if _, ok := allowedMoveArgs[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only source and destination are accepted", key)
		}
	}
	return nil
}
