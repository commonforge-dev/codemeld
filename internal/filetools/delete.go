// Built-in structured delete tool: irreversible removal of a single existing in-project file, symlink,
// or empty directory, with pre-authorization target resolution and an fd-relative unlink that can neither
// recurse nor land outside the authorized parent. It never folds under the write capability.
package filetools

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
	"golang.org/x/sys/unix"
)

// DeleteToolName is the exact dispatch name the structured delete tool registers under. Like `edit` and
// `create` it is a fixed built-in name carrying no template namespace. It is deliberately absent from
// permissions.capabilityMembers, so a `write` capability grant (which folds create/edit) never
// authorizes a delete.
const DeleteToolName = "delete"

// DeleteTool is the built-in mutating delete tool. It removes a single existing target — a regular file,
// a final-component symlink (the link entry, never the file it points at), or an empty directory — and
// refuses a non-empty directory in-band, with no recursive fallback. Deletion is irreversible, so it is
// held to stronger guardrails than edit/create: it never folds under the write capability. The run-scoped home, process
// cwd, and project root are bound at construction so the same expansion/cleaning/symlink/containment
// rules used for permission path scopes resolve the target, exactly as the create tool does.
type DeleteTool struct {
	home        string
	processCWD  string
	projectRoot string
}

var _ tools.Tool = (*DeleteTool)(nil)

// beforeDeleteUnlink is a test seam invoked after the authorized parent directory handle is opened and
// the entry type is determined, but before the irreversible unlink, so a test can simulate a
// post-authorization parent swap/rename and prove the held-handle plus revalidation guard refuses to
// redirect the delete.
var beforeDeleteUnlink = func() {}

// NewDeleteTool builds the delete tool bound to the run's ~ anchor (home), the default base directory
// for a relative target path (processCWD), and the project root the target must stay within. The project
// root is symlink-resolved once here so the containment check compares it against the symlink-resolved
// parent on the same footing — mirroring NewCreateTool — so dispatch's pre-authorization containment
// check and the production authorizer's boundary agree.
func NewDeleteTool(home, processCWD, projectRoot string) *DeleteTool {
	return &DeleteTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot)}
}

func (t *DeleteTool) Name() string { return DeleteToolName }

func (t *DeleteTool) SubjectKind() string { return "tool" }

// Advertise returns the delete tool's advertising metadata and mutating classification. The parameter
// JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so the advertised
// contract matches the decoder exactly. ReadOnly is false: delete mutates the filesystem.
func (t *DeleteTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Delete a single existing file, symlink, or empty directory. The target must " +
			"exist; a non-empty directory is refused (remove its contents first — there is no recursive " +
			"delete) and a symlink is removed as a link without following it to its target. Deletion is " +
			"irreversible and may need approval first. Use to " +
			"remove one existing file or empty directory.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Path of the existing file, symlink, or empty directory to delete. Relative or in-project paths resolve against the working directory; a path whose real (symlink-resolved) location is outside the project and every writable folder is allowed only after you approve it at the permission prompt. A non-empty directory is refused. Deletion is irreversible.",
				},
			},
			"required":             []string{"path"},
			"additionalProperties": false,
		},
		ReadOnly: false,
	}
}

// ResolveTarget resolves the delete target from args before authorization. It rejects unknown arguments,
// then runs the shared parent resolution via resolveFileTarget with the delete precondition (must-exist
// file/symlink/directory, the final component never followed). It returns the resolved target path
// (placed in the mode-auth context) and the path scope to authorize (the resolved real parent directory
// the entry lives in). A missing target, a basename escaping the resolved parent, an unsupported type, or
// an invalid argument is rejected with a *TargetError before any prompt. An out-of-root resolved target
// is not rejected: it is classified out-of-root (OutOfRootScope) and routed to the approval
// prompt, anchored on its real out-of-root parent folder.
func (t *DeleteTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownDeleteArgs(args); verr != nil {
		return "", "", &TargetError{Kind: DeleteToolName, Reason: verr.Error()}
	}
	return resolveFileTarget(DeleteToolName, t.home, t.processCWD, t.projectRoot, args, deletePrecondition)
}

// OutOfRootScope reports whether scope (the resolved path scope ResolveTarget returned) lies outside this
// tool's project root — the out-of-root signal dispatch uses to re-enable the folder grant option
// for an out-of-root delete. Containment uses the same descendant rule as folder-grant path scopes; the
// scope is the resolved real parent directory, so the verdict matches the folder the entry lives in. The
// final component is never resolved, so deleting a final symlink that points outside the root is judged on
// its in-root parent, never the link's target.
func (t *DeleteTool) OutOfRootScope(scope string) bool {
	return !permissions.IsDescendantOrEqual(scope, t.projectRoot)
}

// deletePrecondition is the delete tool's must-exist target precondition for resolveFileTarget. The
// resolved parent is already symlink-followed (CleanAbsResolve) and the final component is the literal
// entry name, so os.Lstat inspects the final entry without following a final symlink — a final-component
// symlink is therefore classified as a symlink to be removed as a link, not followed to its target. It
// re-checks that the anchored target stays within its resolved parent (a ".." basename can point above
// the parent — a structural escape, refused regardless of project root so the authorized scope always
// contains the target), rejects a missing target, and accepts only a regular file, a symlink, or a
// directory. Directory emptiness is deliberately not checked here: it is enforced at invoke time by the
// kernel-guaranteed AT_REMOVEDIR unlink, so the emptiness verdict is taken on the held parent handle
// (TOCTOU-safe) rather than from a resolution-time directory read. The resolved target is the anchored
// candidate; the path scope is the resolved parent. Out-of-root is deliberately not a rejection here
// (out-of-root writes are promptable): an out-of-root parent returns normally and the verdict is computed
// downstream from the scope (DeleteTool.OutOfRootScope).
func deletePrecondition(parent string, candidate string) (target string, scope string, reason string) {
	clean := filepath.Clean(candidate)
	if !permissions.IsDescendantOrEqual(clean, parent) {
		return "", "", "target escapes its parent directory"
	}
	info, lerr := os.Lstat(clean)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			return "", "", "target does not exist; there is nothing to delete"
		}
		return "", "", "cannot determine whether the target exists"
	}
	mode := info.Mode()
	if !mode.IsRegular() && mode&fs.ModeSymlink == 0 && !mode.IsDir() {
		return "", "", "target is not a regular file, symlink, or directory; delete refuses to remove it"
	}
	return clean, parent, ""
}

// InvokeWithResolvedTarget deletes the target dispatch already resolved before authorization, so
// authorization and the removal cannot drift if a symlink changes in between — the same
// resolved-before-authorize / reuse-at-invoke contract the create tool follows. Production dispatch
// routes the delete tool through InvokeWithAuthorizedScope instead, which carries the authorized
// directory's identity as well as the target.
func (t *DeleteTool) InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.remove(ctx, nil, resolvedTarget, args), nil
}

// InvokeWithAuthorizedScope is the seam production dispatch invokes the delete tool through: it deletes
// only once the directory at scope is still the one whose identity was captured when the target
// resolved, closing the window the permission prompt holds open. The confirmed scope descriptor is held
// for the whole delete and the parent the unlink runs through is reached through it.
func (t *DeleteTool) InvokeWithAuthorizedScope(ctx context.Context, args map[string]any, resolvedTarget string, scope string, scopeIdentity ScopeIdentity) (tools.Result, error) {
	confirmed, replaced := confirmAuthorizedScope(scope, scopeIdentity)
	if replaced != "" {
		return failResult(replaced), nil
	}
	defer confirmed.Close()
	afterScopeConfirmed()
	return t.remove(ctx, confirmed, resolvedTarget, args), nil
}

// Invoke resolves the target and deletes it in one call (the standalone, non-dispatch path). Production
// dispatch instead calls ResolveTarget then InvokeWithAuthorizedScope; this method keeps the tool a
// complete unit for direct callers and tests. A target-resolution failure surfaces as the same in-band
// error result the dispatcher would render, so the observable outcome matches either entry.
//
// Standalone Invoke has no authorizer, so it must enforce the out-of-root boundary itself: an out-of-root
// resolved target (OutOfRootScope) is reachable only by explicit per-delete approval, which only the
// dispatch path can obtain. This method therefore refuses an out-of-root target in-band rather than
// deleting it — without this guard a direct caller could delete outside the project root with no prompt
// or grant check. The in-root path is unchanged.
func (t *DeleteTool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.OutOfRootScope(scope) {
		return failResult("delete target outside the project root requires permission approval through dispatch"), nil
	}
	return t.remove(ctx, nil, target, args), nil
}

// remove deletes target through a held handle on its authorized parent directory, fd-relative, so the
// unlink can neither land outside the authorized directory nor recurse. Every precondition failure — an
// unknown argument or a missing/non-string path — returns a non-zero result and removes nothing. The
// required `path` and the closed argument set are re-checked here (not only in ResolveTarget) so a
// resolved-target invocation lacking `path` or carrying an extra key cannot delete a file outside the
// advertised contract, even though remove deletes the separately-resolved target. It opens the authorized
// parent without following a final symlink (openAuthorizedParent), re-stats the entry fd-relative without
// following a final symlink to pick the correct unlink flag, then — immediately before the irreversible
// unlink — revalidates that the held handle is still the directory at the authorized path
// (confirmParentStillAuthorized): a destructive verify-then-act, so a parent swapped in after
// authorization cannot redirect the delete. A directory is removed only with AT_REMOVEDIR, which the
// kernel refuses for a non-empty directory, so delete can never become a silent recursive wipe; that
// refusal surfaces in-band. Preconditions surface as a result (not a Go error) so the tool-call loop
// records them in-band and the model can correct itself rather than aborting the turn.
func (t *DeleteTool) remove(ctx context.Context, scope *authorizedScope, target string, args map[string]any) tools.Result {
	if verr := rejectUnknownDeleteArgs(args); verr != nil {
		return failResult(verr.Error())
	}
	if _, perr := requireStringArg(args, "path"); perr != nil {
		return failResult(perr.Error())
	}

	parentDir, reason := t.openAuthorizedParent(scope, target)
	if reason != "" {
		return failResult(reason)
	}
	defer parentDir.Close() //nolint:errcheck // nothing useful can be done after the delete result is formed
	base := filepath.Base(target)

	// Re-stat the entry relative to the held parent handle, without following a final symlink, so a
	// final-component symlink is removed as a link and the unlink uses the right flag for the entry's real
	// type — never a stale type carried from resolution.
	var st unix.Stat_t
	if serr := unix.Fstatat(int(parentDir.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
		return failResult("delete target no longer exists in the authorized directory")
	}
	flag, modeReason := unlinkFlagForMode(uint32(st.Mode))
	if modeReason != "" {
		return failResult(modeReason)
	}

	beforeDeleteUnlink()

	// Verify-then-act: confirm the held handle is still the directory at the authorized path before the
	// irreversible unlink. A delete cannot be rolled back, so this guard runs *before* the removal, unlike
	// the create tool's after-publish confirmation.
	if moved := t.confirmParentStillAuthorized(parentDir, target); moved != "" {
		return failResult(moved)
	}

	journal := WriteJournalFor(ctx, target)
	if journal != nil {
		if jerr := journal.BeginDelete(target, parentDir); jerr != nil {
			return failResult("delete refused: " + jerr.Error())
		}
	}
	if uerr := unix.Unlinkat(int(parentDir.Fd()), base, flag); uerr != nil {
		if journal != nil {
			journal.AbandonMutation(target, parentDir)
		}
		if flag == unix.AT_REMOVEDIR && (errors.Is(uerr, unix.ENOTEMPTY) || errors.Is(uerr, unix.EEXIST)) {
			return failResult("delete target is a non-empty directory; delete removes only an empty directory (remove its contents first — there is no recursive delete)")
		}
		return failResult("failed to delete the target: " + uerr.Error())
	}
	if journal != nil {
		journal.ResolveMutation(target, parentDir, JournalState{})
	}
	return tools.Result{ExitCode: 0, Stdout: []byte(fmt.Sprintf("deleted %s\n", target))}
}

// unlinkFlagForMode maps a fd-relative stat mode to the unlinkat flag for the entry's type: AT_REMOVEDIR
// for a directory (so the kernel removes only an empty one and never recurses), no flag for a regular
// file or a symlink (the symlink entry is removed without following it). Any other type (socket, fifo,
// device) is refused — v1 delete removes only a regular file, symlink, or empty directory.
func unlinkFlagForMode(mode uint32) (flag int, reason string) {
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return unix.AT_REMOVEDIR, ""
	case unix.S_IFREG, unix.S_IFLNK:
		return 0, ""
	default:
		return 0, "delete target is not a regular file, symlink, or directory; delete refuses to remove it"
	}
}

// openAuthorizedParent re-checks, at invocation time, that the target's parent directory still resolves
// to the exact directory authorized at resolution time, then opens that parent without following a final
// symlink. The returned descriptor is used for the fd-relative unlink, so the parent path is not
// re-resolved after revalidation; a later replacement of the parent with a symlink to another directory
// cannot redirect the unlink. The caller owns the returned file and must close it. A nil
// file plus a non-empty reason means rejection. The boundary is the *authorized scope*, not the project
// root: the exact-path pin (reParent == authorizedParent) never widens beyond the exact authorized parent
// (which, for an approved out-of-root delete, is that out-of-root folder), so no project-root containment
// assertion is applied here.
func (t *DeleteTool) openAuthorizedParent(scope *authorizedScope, target string) (*os.File, string) {
	authorizedParent := filepath.Dir(target)
	reParent, rerr := permissions.CleanAbsResolve(t.home, t.processCWD, authorizedParent)
	if rerr != nil {
		return nil, "delete target's parent directory can no longer be resolved to an existing directory"
	}
	if reParent != authorizedParent {
		return nil, "delete target's parent directory changed after authorization; refusing to delete outside the authorized directory"
	}
	if scope != nil {
		return scope.openWithin(authorizedParent)
	}
	dir, oerr := os.OpenFile(authorizedParent, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return nil, "delete target's parent directory changed after authorization; refusing to delete outside the authorized directory"
	}
	return dir, ""
}

// confirmParentStillAuthorized verifies that the held parent descriptor is still the directory reachable
// at the authorized target path. The fd-relative unlink operates on the held directory inode, so a rename
// or move of that directory between openAuthorizedParent and the unlink would delete an entry from
// wherever the inode now lives while delete reports the original authorized path. Re-opening
// filepath.Dir(target) without following a final symlink and matching it to the held descriptor with
// os.SameFile ties the held inode back to the authorized path. An empty reason means the held handle is
// still at the authorized path; a non-empty reason means the directory was renamed/moved out from under
// the authorized path, so the destructive unlink must not proceed. The os.SameFile identity check is the
// rename/move guard and is boundary-independent, so no project-root containment assertion is applied — an
// approved out-of-root delete confirms against its own authorized folder.
func (t *DeleteTool) confirmParentStillAuthorized(parentDir *os.File, target string) string {
	const moved = "delete target's parent directory moved after authorization; refusing to delete from a directory no longer at the authorized path"
	authorizedParent := filepath.Dir(target)
	pathDir, oerr := os.OpenFile(authorizedParent, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
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

// allowedDeleteArgs is the exact closed set of argument keys the delete tool accepts, matching the
// advertised additionalProperties:false schema.
var allowedDeleteArgs = map[string]struct{}{"path": {}}

// rejectUnknownDeleteArgs fails closed if args carries any key outside the advertised closed schema, so
// the runtime contract is no broader than the advertised one. The provider-facing JSON-Schema sets
// additionalProperties:false, so a conforming caller never trips this; it is defense-in-depth that keeps
// an extra-property call from resolving, authorizing, or deleting a file through a tool whose effect is
// irreversible.
func rejectUnknownDeleteArgs(args map[string]any) error {
	for key := range args {
		if _, ok := allowedDeleteArgs[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only path is accepted", key)
		}
	}
	return nil
}
