// Built-in structured edit tool: exact single text replacement on an existing in-project file,
// with pre-authorization target resolution and atomic apply.
package filetools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aymanbagabas/go-udiff"
	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
)

// EditToolName is the exact dispatch name the structured edit tool registers under. Like
// `bash`, it is a fixed built-in name; unlike vcs_<action> it carries no template namespace.
const EditToolName = "edit"

// EditTool is the built-in mutating edit tool. It applies exactly one occurrence of an
// old-text snippet being replaced by new text on an existing regular file, failing closed when the
// precondition is stale or ambiguous so it never silently overwrites unrelated content. The run-scoped
// home, process cwd, and project root are bound at construction — mirroring vcs.ActionTool binding its
// repo root — so the same expansion/cleaning/symlink/containment rules used for permission path scopes
// resolve the target.
type EditTool struct {
	home        string
	processCWD  string
	projectRoot string
}

var _ tools.Tool = (*EditTool)(nil)

// NewEditTool builds the edit tool bound to the run's ~ anchor (home), the default base directory for
// a relative target path (processCWD, codemeld's launch cwd), and the project root the target must stay
// within. The project root is symlink-resolved once here so the containment check
// compares it against the symlink-resolved target on the same footing — the bootstrap project root is
// absolute and cleaned but not symlink-resolved, so a root path containing a symlink would otherwise
// reject in-project edits. The resolved root mirrors the boundary the production authorizer overlays
// onto the mode-authorization context, so dispatch's pre-authorization containment check and Auto
// edits' later in-scope check agree.
func NewEditTool(home, processCWD, projectRoot string) *EditTool {
	return &EditTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot)}
}

func (t *EditTool) Name() string { return EditToolName }

func (t *EditTool) SubjectKind() string { return "tool" }

// Advertise returns the edit tool's advertising metadata and mutating classification.
// The parameter JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so
// the advertised contract matches the decoder exactly. ReadOnly is false: the edit tool mutates, so
// Plan denies it and Auto edits may auto-approve it.
func (t *EditTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Replace an exact, unique snippet of text in an existing file. old_text must " +
			"appear in the file exactly once; the edit fails without modifying the file if it is missing, " +
			"ambiguous, or unchanged. Use for a precise edit to one location in a file.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Path of the existing file to edit. Relative or in-project paths resolve against the working directory and edit normally; a path whose real (symlink-resolved) location is outside the project is allowed only after you approve it at the permission prompt.",
				},
				"old_text": map[string]any{
					"type":        "string",
					"description": "Exact text to replace. Must be non-empty and appear in the file exactly once.",
				},
				"new_text": map[string]any{
					"type":        "string",
					"description": "Replacement text. Must differ from old_text; may be empty to delete the matched snippet.",
				},
			},
			"required":             []string{"path", "old_text", "new_text"},
			"additionalProperties": false,
		},
		ReadOnly: false,
	}
}

// ResolveTarget resolves the edit target from args before authorization and returns the resolved
// target file path (placed in the mode-authorization context for Auto edits' in-scope check)
// and the path scope to authorize (the resolved parent directory the write lands in). It uses
// the same expansion, cleaning, and symlink-resolution rules as permission path scopes
// (permissions.CleanAbsResolve), so a target naming a directory, a non-regular/missing file, or lacking a
// safe parent directory is rejected with a *TargetError before any prompt. Symlinks are resolved on both
// the parent directory and the final component, and the path scope is always the resolved *real* file's
// parent — so a target whose real path lands outside the project root (including an in-root lexical path
// that symlink-resolves outside) is not rejected but classified out-of-root (OutOfRootScope) and routed to
// the approval prompt, anchored on that real out-of-root folder, never the lexical one.
func (t *EditTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownArgs(args); verr != nil {
		return "", "", &TargetError{Kind: EditToolName, Reason: verr.Error()}
	}
	return resolveFileTarget(EditToolName, t.home, t.processCWD, t.projectRoot, args, editPrecondition)
}

// OutOfRootScope reports whether scope (the resolved path scope ResolveTarget returned) lies outside this
// tool's project root — the out-of-root signal dispatch uses to re-enable the folder grant option
// for an out-of-root edit. Containment uses the same descendant rule as folder-grant path scopes; the
// scope is the resolved real parent folder, so a symlink-escaped target is judged on its real location.
func (t *EditTool) OutOfRootScope(scope string) bool {
	return !permissions.IsDescendantOrEqual(scope, t.projectRoot)
}

// editPrecondition is the edit tool's must-exist-regular target precondition for resolveFileTarget: the
// candidate's final component is symlink-resolved and a missing, directory, or non-regular target is
// rejected as a structural failure. It returns the symlink-resolved real file as the target to
// authorize/invoke against and that file's parent as the path scope. Out-of-root is deliberately not a
// rejection here: a target whose real path lands outside the project root returns normally with
// its real out-of-root parent as the scope, and the in-root/out-of-root verdict is computed downstream
// from that scope (EditTool.OutOfRootScope). Symlink-escape protection is preserved because the scope is
// always the resolved *real* folder, so a grant can never authorize a write whose real parent differs.
func editPrecondition(_ string, candidate string) (target string, scope string, reason string) {
	real, eerr := filepath.EvalSymlinks(candidate)
	if eerr != nil {
		return "", "", "target file does not exist or cannot be resolved"
	}
	info, serr := os.Stat(real)
	if serr != nil {
		return "", "", "cannot read the target file's metadata"
	}
	if info.IsDir() {
		return "", "", "target names a directory, not a file"
	}
	if !info.Mode().IsRegular() {
		return "", "", "target is not a regular file"
	}
	return real, filepath.Dir(real), ""
}

// InvokeWithResolvedTarget applies the edit to the target dispatch already resolved before
// authorization, so authorization and the write cannot drift if a symlink changes in between — the
// same resolved-before-authorize / reuse-at-invoke contract vcs.ActionTool follows for its cwd.
// Production dispatch routes the edit tool through InvokeWithAuthorizedScope instead, which carries the
// authorized directory's identity as well as the target.
func (t *EditTool) InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.apply(ctx, nil, resolvedTarget, args), nil
}

// InvokeWithAuthorizedScope is the seam production dispatch invokes the edit tool through: it applies
// the edit only once the directory at scope is still the one whose identity was captured when the target
// resolved, closing the window the permission prompt holds open. The confirmed scope descriptor is held
// for the whole edit and the parent the edit reads and publishes through is reached through it.
func (t *EditTool) InvokeWithAuthorizedScope(ctx context.Context, args map[string]any, resolvedTarget string, scope string, scopeIdentity ScopeIdentity) (tools.Result, error) {
	confirmed, replaced := confirmAuthorizedScope(scope, scopeIdentity)
	if replaced != "" {
		return failResult(replaced), nil
	}
	defer confirmed.Close()
	afterScopeConfirmed()
	return t.apply(ctx, confirmed, resolvedTarget, args), nil
}

// Invoke resolves the target and applies the edit in one call (the standalone, non-dispatch path).
// Production dispatch instead calls ResolveTarget then InvokeWithAuthorizedScope; this method keeps the
// tool a complete unit for direct callers and tests. A target-resolution failure surfaces as the same
// in-band error result the dispatcher would render, so the observable outcome matches either entry.
//
// Standalone Invoke has no authorizer, so it must enforce the out-of-root boundary itself: an out-of-root
// resolved target (OutOfRootScope) — including an in-root lexical path that symlink-resolves outside the
// root — is reachable only by explicit per-write approval, which only the dispatch path can obtain. This
// method therefore refuses an out-of-root target in-band rather than editing it; without this guard a
// direct caller could modify a file outside the project root with no prompt or grant check. The in-root
// path is unchanged.
func (t *EditTool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.OutOfRootScope(scope) {
		return failResult("edit target outside the project root requires permission approval through dispatch"), nil
	}
	return t.apply(ctx, nil, target, args), nil
}

const previewContextLines = 2

type editPlan struct {
	original string
	updated  string
	mode     os.FileMode
}

// planEdit surfaces a precondition failure as a result, not a Go error, so the tool-call loop records
// it in-band and the model can correct itself rather than aborting the turn. It reads the target by
// pathname and so is the preview-only planner; apply plans through planEditAt instead, because a
// pathname read between authorization and publication can be redirected to a different file.
func planEdit(target string, args map[string]any) (editPlan, *tools.Result) {
	oldText, newText, refusal := editArgs(args)
	if refusal != nil {
		return editPlan{}, refusal
	}

	info, err := os.Stat(target)
	if err != nil {
		return failPlan("cannot read the target file's metadata: " + err.Error())
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return failPlan("cannot read the target file: " + err.Error())
	}
	return buildEditPlan(string(data), info.Mode().Perm(), oldText, newText)
}

// planEditAt plans the same edit from the target opened relative to parentDir, the held descriptor the
// publish also runs through. Binding the read and the write to one directory inode is what keeps a
// parent replaced mid-edit from having bytes planned off the old file applied to a different one.
func planEditAt(parentDir *os.File, leaf string, args map[string]any) (editPlan, os.FileInfo, *tools.Result) {
	oldText, newText, refusal := editArgs(args)
	if refusal != nil {
		return editPlan{}, nil, refusal
	}

	data, info, err := readRegularFileAt(parentDir, leaf)
	if err != nil {
		plan, readRefusal := failPlan("cannot read the target file: " + err.Error())
		return plan, nil, readRefusal
	}
	plan, planRefusal := buildEditPlan(string(data), info.Mode().Perm(), oldText, newText)
	return plan, info, planRefusal
}

// readRegularFileAt reads leaf under the held directory descriptor. O_NONBLOCK is what keeps a FIFO
// swapped in at the name from blocking the open forever instead of reaching the regular-file refusal.
func readRegularFileAt(parentDir *os.File, leaf string) ([]byte, os.FileInfo, error) {
	fd, oerr := unix.Openat(int(parentDir.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if oerr != nil {
		return nil, nil, &os.PathError{Op: "openat", Path: leaf, Err: oerr}
	}
	f := os.NewFile(uintptr(fd), leaf)
	defer f.Close() //nolint:errcheck // read-only descriptor; the contents are already read

	info, serr := f.Stat()
	if serr != nil {
		return nil, nil, serr
	}
	if !info.Mode().IsRegular() {
		return nil, nil, &os.PathError{Op: "read", Path: leaf, Err: syscall.EINVAL}
	}
	data, rerr := io.ReadAll(f)
	if rerr != nil {
		return nil, nil, rerr
	}
	return data, info, nil
}

func failPlan(msg string) (editPlan, *tools.Result) {
	r := failResult(msg)
	return editPlan{}, &r
}

func editArgs(args map[string]any) (oldText, newText string, refusal *tools.Result) {
	fail := func(msg string) (string, string, *tools.Result) {
		r := failResult(msg)
		return "", "", &r
	}
	if verr := rejectUnknownArgs(args); verr != nil {
		return fail(verr.Error())
	}
	// The required `path` is enforced here too, not only in ResolveTarget: InvokeWithResolvedTarget
	// reaches apply with an already-resolved target, so without this check a resolved-target call
	// lacking `path` would modify the file even though the advertised schema requires it. apply does
	// not use the value (it writes the separately-resolved target) — this keeps the runtime contract
	// no broader than the advertised one on every entry point that can modify a file.
	if _, perr := requireStringArg(args, "path"); perr != nil {
		return fail(perr.Error())
	}
	oldText, err := requireStringArg(args, "old_text")
	if err != nil {
		return fail(err.Error())
	}
	newText, err = requireStringArg(args, "new_text")
	if err != nil {
		return fail(err.Error())
	}
	if oldText == "" {
		return fail("old_text must be non-empty")
	}
	if oldText == newText {
		return fail("old_text and new_text are identical; there is no change to apply")
	}
	return oldText, newText, nil
}

func buildEditPlan(content string, mode os.FileMode, oldText, newText string) (editPlan, *tools.Result) {
	count, idx := countOverlappingMatches(content, oldText)
	if count == 0 {
		return failPlan("old_text was not found in the file; no edit applied")
	}
	if count > 1 {
		return failPlan(fmt.Sprintf("old_text matches %d times; it must match exactly once so the edit is unambiguous", count))
	}

	return editPlan{
		original: content,
		updated:  content[:idx] + newText + content[idx+len(oldText):],
		mode:     mode,
	}, nil
}

func renderEditPatch(target string, plan editPlan) (string, error) {
	return udiff.ToUnified(target, target, plan.original, udiff.Lines(plan.original, plan.updated), previewContextLines)
}

func (*EditTool) Preview(target string, args map[string]any) (string, *tools.Result) {
	plan, refusal := planEdit(target, args)
	if refusal != nil {
		return "", refusal
	}
	patch, err := renderEditPatch(target, plan)
	if err != nil {
		r := failResult("cannot render the proposed change as a patch: " + err.Error())
		return "", &r
	}
	return patch, nil
}

// beforeEditPublish fires after the plan is bound to the held parent descriptor and before the publish,
// so a test can rename or replace that parent mid-edit and exercise the pre-publish identity guard. A
// move that has to land after publication instead is driven through fsutil's parent-sync seam.
var beforeEditPublish = func() {}

// editTargetChanged is one message for both places the planned target can turn out not to be the file
// at the name — the pre-publish check and the publish itself — because to the caller they are the same
// refusal and only differ in how late the swap happened.
const editTargetChanged = "edit target file changed during the edit; refusing to publish a change planned from a different file"

// apply reads, plans, and publishes through one held parent descriptor. No pathname read may be
// reintroduced between the binding and the publish: a directory swapped in at the authorized path would
// otherwise supply the bytes that are planned from, or receive the bytes that are written. A parent
// renamed after the binding still receives the write, because the descriptor pins the inode, so the
// identity is checked twice: once from the pre-publish hook, which aborts before anything becomes
// visible, and again after publication for a move that lands inside the remaining rename window. Only
// the second case has bytes to undo, and a failed undo is reported as its own outcome — the changed
// bytes are published in the moved directory, which is neither a clean edit nor a clean refusal.
//
// The held descriptor pins the directory, not the entry inside it: a plain rename would replace
// whatever answers to leaf at the instant the kernel resolves the name. The planned target's identity
// therefore goes into the publish itself, which refuses unless the entry it displaces is that exact
// file — a check the hook cannot make, because anything it verifies can still be swapped before the
// rename. The hook checks it too, to refuse a target replaced during planning before staging is even
// published, but it is the publish that closes the window.
func (t *EditTool) apply(ctx context.Context, scope *authorizedScope, target string, args map[string]any) tools.Result {
	authorizedDir := filepath.Dir(target)
	leaf := filepath.Base(target)

	parentDir, openReason := t.openAuthorizedParent(scope, authorizedDir)
	if openReason != "" {
		return failResult(openReason)
	}
	defer parentDir.Close() //nolint:errcheck // nothing useful can be done after the edit result is formed

	plan, plannedTarget, refusal := planEditAt(parentDir, leaf, args)
	if refusal != nil {
		return *refusal
	}

	journal := WriteJournalFor(ctx, target)
	// A pending record is resolved once, after any post-publication compensation has run, so a
	// compensated edit is compared against the state the directory is actually left in.
	// published is the inode left at the path, so the journal can tell the bytes this edit put there
	// from byte-identical bytes another writer put there while it was reconciling; the compensated
	// path has none to name, because its own restore replaced whatever it had published.
	resolve := func(published os.FileInfo) {
		if journal != nil {
			journal.ResolveMutation(target, parentDir, publishedState([]byte(plan.updated), published))
		}
	}

	beforeEditPublish()

	refusedBeforePublish := ""
	abortIfRedirected := func(_ string, data []byte, mode os.FileMode) error {
		if moved := t.confirmParentStillAuthorized(parentDir, authorizedDir); moved != "" {
			refusedBeforePublish = moved
			return errors.New(moved)
		}
		if changed := confirmTargetStillPlanned(parentDir, leaf, plannedTarget); changed != "" {
			refusedBeforePublish = changed
			return errors.New(changed)
		}
		if journal != nil {
			dev, ino := journalIdentity(plannedTarget)
			observed := JournalState{Exists: true, Data: []byte(plan.original), Mode: plan.mode, Dev: dev, Ino: ino}
			if jerr := journal.BeginMutation(target, observed, JournalState{Exists: true, Data: data, Mode: mode}); jerr != nil {
				refusedBeforePublish = "the child agent's rollback journal refused the edit: " + jerr.Error()
				return jerr
			}
		}
		return nil
	}
	_, _, published, werr := fsutil.WriteAtomicReplaceAt(parentDir, leaf, []byte(plan.updated), plan.mode, plannedTarget, abortIfRedirected)
	if werr != nil && published == nil {
		// Nothing became visible, so the pending bytes are not this child's to claim: a target that
		// now holds them was written by whoever displaced the planned identity this publish refused
		// to overwrite.
		if journal != nil {
			journal.AbandonMutation(target, parentDir)
		}
		if refusedBeforePublish != "" {
			return failResult(refusedBeforePublish)
		}
		if errors.Is(werr, fsutil.ErrTargetIdentityChanged) {
			return failResult(editTargetChanged)
		}
		return failResult("failed to write the file: " + werr.Error())
	}
	if moved := t.confirmParentStillAuthorized(parentDir, authorizedDir); moved != "" {
		undone := undoPublishAfterMove(parentDir, leaf, plan, published, moved)
		resolve(nil)
		return failResult(undone)
	}
	resolve(published)
	if werr != nil {
		return failResult("failed to write the file: " + werr.Error())
	}
	patch, rerr := renderEditPatch(target, plan)
	if rerr != nil {
		patch = ""
	}
	return tools.Result{
		ExitCode:     0,
		Stdout:       []byte(fmt.Sprintf("edited %s (replaced 1 occurrence)\n", target)),
		DisplayPatch: patch,
	}
}

// undoPublishAfterMove puts the original bytes back after the edit was published into a directory that
// turned out to have moved, and reports what actually happened. The restore is itself an
// identity-verified publish against the inode this edit published: between the moved-parent check and
// this call another writer can replace that name, and overwriting a replacement with bytes planned
// from a file it never was is the same defect the publish itself refuses. A restore that cannot
// complete is not an ordinary refusal — the caller must be told the changed bytes are still visible —
// so each outcome names the state the directory is left in.
func undoPublishAfterMove(parentDir *os.File, leaf string, plan editPlan, published os.FileInfo, moved string) string {
	_, _, restored, rerr := fsutil.WriteAtomicReplaceAt(parentDir, leaf, []byte(plan.original), plan.mode, published, nil)
	if restored != nil {
		return moved
	}
	switch {
	case errors.Is(rerr, fsutil.ErrTargetIdentityChanged):
		return moved + "; another writer replaced that file first, so nothing of theirs was overwritten but the original contents were not put back"
	case errors.Is(rerr, fsutil.ErrPublishUnreconciled):
		return moved + "; the original contents were not put back under their own name, and a file from that directory is retained there under a temporary name, which must be reconciled by hand: " + rerr.Error()
	default:
		return moved + "; restoring the original contents failed, so the changed bytes are still published in that directory and must be reconciled by hand: " + rerr.Error()
	}
}

// openAuthorizedParent re-checks at invocation time that the parent still resolves to the directory
// authorized at resolution time, then opens it. Both halves matter: the resolve catches a parent
// replaced by a symlink pointing elsewhere, and O_NOFOLLOW refuses to open one at all.
func (t *EditTool) openAuthorizedParent(scope *authorizedScope, authorizedDir string) (*os.File, string) {
	const redirected = "edit target's parent directory changed after authorization; refusing to edit outside the authorized directory"
	reDir, rerr := permissions.CleanAbsResolve(t.home, t.processCWD, authorizedDir)
	if rerr != nil || reDir != authorizedDir {
		return nil, redirected
	}
	if scope != nil {
		return scope.openWithin(authorizedDir)
	}
	dir, oerr := os.OpenFile(authorizedDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return nil, redirected
	}
	return dir, ""
}

// confirmParentStillAuthorized reports whether the held descriptor is still the directory reachable at
// the authorized path. A descriptor follows its inode through a rename, so the check is worth repeating:
// the caller runs it from the pre-publish hook to abort before any rename, and again after publication
// to catch a move inside the window the hook cannot cover, where it undoes the write instead.
func (t *EditTool) confirmParentStillAuthorized(parentDir *os.File, authorizedDir string) string {
	const moved = "edit target's parent directory moved during the edit; refusing to report an edit at a path the file is not located at"
	pathDir, oerr := os.OpenFile(authorizedDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return moved
	}
	defer pathDir.Close() //nolint:errcheck // read-only descriptor opened only to compare directory identity
	heldInfo, herr := parentDir.Stat()
	pathInfo, perr := pathDir.Stat()
	if herr != nil || perr != nil || !os.SameFile(heldInfo, pathInfo) {
		return moved
	}
	return ""
}

// confirmTargetStillPlanned reports whether leaf under the held descriptor is still the exact file the
// plan was read from. The planned bytes are a safe replacement only for that inode: a target renamed
// away and replaced under the same name between the read and the publish would otherwise be overwritten
// with a change computed from contents it never had. A nil planned identity is refused rather than
// compared, so the check can never pass by default.
func confirmTargetStillPlanned(parentDir *os.File, leaf string, planned os.FileInfo) string {
	if planned == nil {
		return editTargetChanged
	}
	fd, oerr := unix.Openat(int(parentDir.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if oerr != nil {
		return editTargetChanged
	}
	current := os.NewFile(uintptr(fd), leaf)
	defer current.Close() //nolint:errcheck // read-only descriptor opened only to compare file identity
	info, serr := current.Stat()
	if serr != nil || !os.SameFile(planned, info) {
		return editTargetChanged
	}
	return ""
}

// allowedEditArgs is the exact closed set of argument keys the edit tool accepts, matching the
// advertised additionalProperties:false schema.
var allowedEditArgs = map[string]struct{}{"path": {}, "old_text": {}, "new_text": {}}

// rejectUnknownArgs fails closed if args carries any key outside the advertised closed schema, so the
// runtime contract is no broader than the advertised one. The provider-facing JSON-Schema sets
// additionalProperties:false, so a conforming caller never trips this; it is defense-in-depth that
// keeps an extra-property call from resolving, authorizing, or modifying a file on a mutating tool
// that Auto edits may later auto-approve without prompting.
func rejectUnknownArgs(args map[string]any) error {
	for key := range args {
		if _, ok := allowedEditArgs[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only path, old_text, and new_text are accepted", key)
		}
	}
	return nil
}

// countOverlappingMatches returns how many start positions oldText occupies in content — counting
// overlapping occurrences, unlike strings.Count, which counts only non-overlapping ones — together with
// the first such position (-1 when there is none). An exact single edit target requires exactly one
// start position, so an overlapping ambiguity (e.g. "aa" within "aaa", which can start at offset 0 or
// 1) must be rejected and not silently applied at the first match. The scan advances one byte past each
// match so every overlapping start position is counted; callers reject empty oldText before this runs,
// so the loop always makes progress and cannot read past the end of content.
func countOverlappingMatches(content, oldText string) (count, firstIdx int) {
	firstIdx = -1
	for from := 0; from <= len(content)-len(oldText); {
		i := strings.Index(content[from:], oldText)
		if i < 0 {
			break
		}
		pos := from + i
		if firstIdx < 0 {
			firstIdx = pos
		}
		count++
		from = pos + 1
	}
	return count, firstIdx
}
