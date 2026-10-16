// Built-in structured mkdir tool: create a directory and any missing parents (mkdir -p semantics) with
// pre-authorization target resolution and a held-descriptor, fd-relative create. It is registered as a
// built-in mutating tool in the production registry: Build advertises it, Plan filters it out, and each
// directory create needs an explicit mkdir grant or approval rather than folding under the write capability.
package filetools

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
	"golang.org/x/sys/unix"
)

// MkdirToolName is the exact dispatch name the structured mkdir tool registers under. Like `edit`,
// `create`, and `bash`, it is a fixed built-in name carrying no template namespace.
const MkdirToolName = "mkdir"

// MkdirTool is the built-in mutating mkdir tool. It creates a directory and any missing parent directories
// (mkdir -p semantics) at a target inside the project root, authorizing the deepest already-existing
// ancestor directory as the path scope and creating the missing suffix fd-relative to a held descriptor on
// that ancestor (so a symlink or rename swapped in after authorization cannot redirect the create out of
// the authorized tree). It mirrors CreateTool's resolve-once / reuse-at-invoke contract. The run-scoped
// home, process cwd, and project root are bound at construction so the same expansion/cleaning/symlink/
// containment rules used for permission path scopes resolve the target.
type MkdirTool struct {
	home        string
	processCWD  string
	projectRoot string
}

var _ tools.Tool = (*MkdirTool)(nil)

// beforeMkdirCreate is a test seam invoked immediately before the fd-relative create so tests can inject a
// symlink-swap or rename race between authorization and the create. It is a no-op in production.
var beforeMkdirCreate = func() {}

// NewMkdirTool builds the mkdir tool bound to the run's ~ anchor (home), the default base directory for a
// relative target path (processCWD), and the project root the authorized scope is classified against. The
// project root is symlink-resolved once here so the containment check compares it against the
// symlink-resolved ancestor on the same footing — mirroring NewCreateTool.
func NewMkdirTool(home, processCWD, projectRoot string) *MkdirTool {
	return &MkdirTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot)}
}

func (t *MkdirTool) Name() string { return MkdirToolName }

func (t *MkdirTool) SubjectKind() string { return "tool" }

// Advertise returns the mkdir tool's advertising metadata and mutating classification. The parameter
// JSON-Schema is the OpenAI function-tool shape with additionalProperties:false so the advertised contract
// matches the decoder exactly. ReadOnly is false: mkdir mutates the filesystem.
func (t *MkdirTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Create a directory, creating any missing parent directories along the way " +
			"(like mkdir -p). Succeeds without error if the directory already exists. Use to add a new " +
			"directory or a nested directory tree.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Path of the directory to create. Any missing parent directories are created too. Relative or in-project paths resolve against the working directory and create normally; a path whose real (symlink-resolved) location is outside the project is allowed only after you approve it at the permission prompt.",
				},
			},
			"required":             []string{"path"},
			"additionalProperties": false,
		},
		ReadOnly: false,
	}
}

// ResolveTarget resolves the mkdir target from args before authorization. It rejects unknown arguments and
// a missing/non-string/empty path, expands and anchors the path, then walks to the deepest existing
// ancestor directory and symlink-resolves it as the authorized path scope (the directory the new
// subdirectories are created under). The resolved target is the real directory path that will exist after
// the create; the scope is the resolved deepest-existing ancestor. A malformed path, an unsupported ~user
// form, or an existing non-directory component is rejected with a *TargetError before any prompt. An
// out-of-root resolved scope is not rejected: it is classified out-of-root (OutOfRootScope) and
// routed to the approval prompt, anchored on its real out-of-root ancestor folder.
func (t *MkdirTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownMkdirArgs(args); verr != nil {
		return "", "", &TargetError{Kind: MkdirToolName, Reason: verr.Error()}
	}
	rawPath, perr := requireStringArg(args, "path")
	if perr != nil {
		return "", "", &TargetError{Kind: MkdirToolName, Reason: perr.Error()}
	}
	if strings.TrimSpace(rawPath) == "" {
		return "", "", &TargetError{Kind: MkdirToolName, Reason: "path must be non-empty"}
	}

	absTarget, reason := t.absTarget(rawPath)
	if reason != "" {
		return "", "", &TargetError{Kind: MkdirToolName, Reason: reason}
	}

	ancestor, segs, _, reason := splitExistingPrefix(absTarget)
	if reason != "" {
		return "", "", &TargetError{Kind: MkdirToolName, Reason: reason}
	}
	// Symlink-resolve the deepest existing ancestor: this is the directory a folder grant authorizes and
	// the create lands under. Resolving here (never trusting the lexical in-project path) is what keeps an
	// in-project path that resolves outside the root from being authorized as if it were in-root.
	resolvedAncestor, cerr := permissions.CleanAbsResolve(t.home, t.processCWD, ancestor)
	if cerr != nil {
		return "", "", &TargetError{Kind: MkdirToolName, Reason: "cannot resolve a safe existing parent directory for the target"}
	}
	resolvedTarget := resolvedAncestor
	if len(segs) > 0 {
		resolvedTarget = filepath.Join(append([]string{resolvedAncestor}, segs...)...)
	}
	if !permissions.IsDescendantOrEqual(resolvedTarget, resolvedAncestor) {
		return "", "", &TargetError{Kind: MkdirToolName, Reason: "target escapes its resolved parent directory"}
	}
	return resolvedTarget, resolvedAncestor, nil
}

// OutOfRootScope reports whether scope (the resolved path scope ResolveTarget returned) lies outside this
// tool's project root — the out-of-root signal dispatch uses to re-enable the folder grant option
// for an out-of-root mkdir. Containment uses the same descendant rule as folder-grant path scopes; the
// scope is the resolved real deepest-existing ancestor, so the verdict matches the folder the new
// directories would land in.
func (t *MkdirTool) OutOfRootScope(scope string) bool {
	return !permissions.IsDescendantOrEqual(scope, t.projectRoot)
}

// InvokeWithResolvedTarget creates the directory tree at the target dispatch already resolved before
// authorization, so authorization and the create cannot drift if a symlink changes in between — the same
// resolved-before-authorize / reuse-at-invoke contract the create tool follows. Production dispatch
// routes the mkdir tool through InvokeWithAuthorizedScope instead, which carries the authorized
// directory's identity as well as the target.
func (t *MkdirTool) InvokeWithResolvedTarget(_ context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.mkdir(nil, resolvedTarget, args), nil
}

// InvokeWithAuthorizedScope is the seam production dispatch invokes the mkdir tool through. scope is the
// ancestor that was authorized, not the deepest ancestor existing now, so an intermediate directory
// legitimately created while the prompt was open does not read as a replacement. The confirmed scope
// descriptor is held for the whole mkdir and the ancestor the create runs under is reached through it.
func (t *MkdirTool) InvokeWithAuthorizedScope(_ context.Context, args map[string]any, resolvedTarget string, scope string, scopeIdentity ScopeIdentity) (tools.Result, error) {
	confirmed, replaced := confirmAuthorizedScope(scope, scopeIdentity)
	if replaced != "" {
		return failResult(replaced), nil
	}
	defer confirmed.Close()
	afterScopeConfirmed()
	return t.mkdir(confirmed, resolvedTarget, args), nil
}

// Invoke resolves the target and creates the directory tree in one call (the standalone, non-dispatch
// path). Production dispatch instead calls ResolveTarget then InvokeWithAuthorizedScope; this method keeps
// the tool a complete unit for direct callers and tests. A target-resolution failure surfaces as the same
// in-band error result the dispatcher would render.
//
// Standalone Invoke has no authorizer, so it must enforce the out-of-root boundary itself: an out-of-root
// resolved scope (OutOfRootScope) is reachable only by explicit per-write approval, which only the dispatch
// path can obtain. This method therefore refuses an out-of-root target in-band rather than creating it. The
// in-root path is unchanged.
func (t *MkdirTool) Invoke(_ context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.OutOfRootScope(scope) {
		return failResult("mkdir target outside the project root requires permission approval through dispatch"), nil
	}
	return t.mkdir(nil, target, args), nil
}

// mkdir creates target (and any missing parents) under the authorized deepest-existing ancestor. The
// required `path` is re-checked here (not only in ResolveTarget) so a resolved-target invocation lacking
// `path` cannot create a directory outside the advertised contract. It re-derives the deepest existing
// ancestor from the pre-authorized target, revalidates and opens that ancestor without following a final
// symlink (see openAuthorizedAncestor), and creates the missing suffix fd-relative to that held descriptor
// with fsutil.EnsureDirAt — never re-resolving an absolute path through os.MkdirAll, so a parent symlink
// swapped in after authorization cannot redirect the create. Because the held descriptor follows the
// directory inode rather than the path, after the create it confirms that inode is still reachable at the
// authorized ancestor path (see confirmAncestorStillAuthorized); if the ancestor was renamed or moved out
// from under the authorized path during the create, only the directories this call actually created are
// removed (deepest first) through the held descriptor — a suffix directory a concurrent process slipped in
// is left untouched — and the create fails rather than reporting a success at a path the directory is not
// located
// at. An already-existing target directory is idempotent success. Preconditions surface as a result (not a
// Go error) so the tool-call loop records them in-band and the model can correct itself.
func (t *MkdirTool) mkdir(scope *authorizedScope, target string, args map[string]any) tools.Result {
	if verr := rejectUnknownMkdirArgs(args); verr != nil {
		return failResult(verr.Error())
	}
	if _, perr := requireStringArg(args, "path"); perr != nil {
		return failResult(perr.Error())
	}

	ancestor, segs, exists, reason := splitExistingPrefix(target)
	if reason != "" {
		return failResult(reason)
	}
	if exists {
		return tools.Result{ExitCode: 0, Stdout: []byte(fmt.Sprintf("directory %s already exists\n", target))}
	}

	parentDir, openReason := t.openAuthorizedAncestor(scope, ancestor)
	if openReason != "" {
		return failResult(openReason)
	}
	defer parentDir.Close() //nolint:errcheck // nothing useful can be done after the mkdir result is formed

	beforeMkdirCreate()

	_, createdDirs, _, derr := fsutil.EnsureDirAt(parentDir, strings.Join(segs, "/"))
	if derr != nil {
		return failResult("failed to create the directory: " + derr.Error())
	}
	if moved := confirmAncestorStillAuthorized(parentDir, ancestor); moved != "" {
		// Best-effort rollback of only the directories this call actually created. createdDirs omits any
		// suffix segment that already existed when EnsureDirAt descended (a concurrent process can create
		// `safe/a` or `safe/a/b` in the window between splitExistingPrefix and the create), so the rollback
		// can never delete a directory this invocation did not make. Remove them deepest child first — the
		// list is shallowest first — so each AT_REMOVEDIR targets an empty directory; a still-occupied
		// intermediate (one that holds a pre-existing child) simply fails to unlink rather than touching it.
		// Each removal is fd-relative to the held descriptor, pinning it to the authorized inode rather than
		// a path that may now point elsewhere; the failure is reported regardless.
		for i := len(createdDirs) - 1; i >= 0; i-- {
			_ = unix.Unlinkat(int(parentDir.Fd()), createdDirs[i], unix.AT_REMOVEDIR) //nolint:errcheck // best-effort
		}
		return failResult(moved)
	}
	return tools.Result{ExitCode: 0, Stdout: []byte(fmt.Sprintf("created directory %s\n", target))}
}

// absTarget expands a leading ~ (rejecting the unsupported ~user form), resolves a relative path against
// the process cwd, and cleans the result, matching how permissions.CleanAbsResolve absolutizes a path
// before resolution. Unlike CleanAbsResolve it does not require the path to exist, because the mkdir target
// (and its missing parents) does not yet exist. A non-empty reason is a structural rejection.
func (t *MkdirTool) absTarget(rawPath string) (string, string) {
	expanded, eerr := paths.Expand(t.home, rawPath)
	if eerr != nil {
		return "", "unsupported ~user path form; only ~ and ~/<subpath> are supported"
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(t.processCWD, expanded)
	}
	return filepath.Clean(expanded), ""
}

// splitExistingPrefix walks absPath (a cleaned absolute path) upward to its deepest existing ancestor
// directory and returns that ancestor together with the missing trailing segments to create under it.
// exists is true when absPath itself already exists as a directory — the idempotent mkdir -p case, where
// segs is empty and no creation is needed. A non-empty reason is a structural rejection: an existing path
// component is not a directory (so no directory can be created beneath it), a dangling symlink occupies a
// component, or the path cannot be examined. The returned ancestor is the lexical path of the deepest
// existing component; the caller symlink-resolves it (permissions.CleanAbsResolve) to obtain the real
// authorized scope, so a symlink ancestor pointing outside the root surfaces as an out-of-root scope rather
// than being mistaken for an in-project parent.
func splitExistingPrefix(absPath string) (ancestor string, segs []string, exists bool, reason string) {
	cur := filepath.Clean(absPath)
	var missing []string
	for {
		_, err := os.Lstat(cur)
		switch {
		case err == nil:
			// cur exists. Follow a final symlink to classify what it points at: a symlink to a directory is
			// a valid ancestor (resolved to its real location by the caller), while a regular file, a symlink
			// to a non-directory, or a dangling symlink cannot hold a child directory.
			si, serr := os.Stat(cur)
			if serr != nil {
				return "", nil, false, "an existing path component is not a usable directory"
			}
			if !si.IsDir() {
				return "", nil, false, "an existing path component is not a directory"
			}
			if len(missing) == 0 {
				return cur, nil, true, ""
			}
			return cur, missing, false, ""
		case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
			// cur is absent — either truly missing, or an ancestor component is a non-directory (ENOTDIR),
			// which the walk surfaces and rejects when it reaches that component above. Record the segment
			// and ascend toward the deepest existing ancestor.
			parent := filepath.Dir(cur)
			if parent == cur {
				return "", nil, false, "no existing parent directory to create the target under"
			}
			missing = append([]string{filepath.Base(cur)}, missing...)
			cur = parent
		default:
			return "", nil, false, "cannot determine whether the target path exists"
		}
	}
}

// openAuthorizedAncestor re-checks, at invocation time, that the deepest-existing ancestor still resolves
// to the exact directory authorized at resolution time, then opens it without following a final symlink.
// The returned descriptor is used for the fd-relative create, so the ancestor path is not re-resolved after
// revalidation; a later replacement of the ancestor with a symlink to another directory cannot redirect the
// create. The caller owns the returned file and must close it. A nil file plus a non-empty reason means
// rejection.
//
// As in the create tool the boundary is the authorized scope, not the project root: the exact-path pin
// (reAncestor == ancestor) bounds the create to the exact authorized ancestor (which, for an approved
// out-of-root mkdir, is that out-of-root folder). The O_NOFOLLOW open together with the pin and
// confirmAncestorStillAuthorized's os.SameFile check is the post-authorization symlink-swap / rename guard.
func (t *MkdirTool) openAuthorizedAncestor(scope *authorizedScope, ancestor string) (*os.File, string) {
	reAncestor, rerr := permissions.CleanAbsResolve(t.home, t.processCWD, ancestor)
	if rerr != nil {
		return nil, "mkdir target's existing parent directory can no longer be resolved to an existing directory"
	}
	if reAncestor != ancestor {
		return nil, "mkdir target's existing parent directory changed after authorization; refusing to create outside the authorized directory"
	}
	if scope != nil {
		return scope.openWithin(ancestor)
	}
	dir, oerr := os.OpenFile(ancestor, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return nil, "mkdir target's existing parent directory changed after authorization; refusing to create outside the authorized directory"
	}
	return dir, ""
}

// confirmAncestorStillAuthorized verifies, after the fd-relative create, that the held ancestor descriptor
// is still the directory reachable at the authorized ancestor path. The create lands relative to the held
// directory inode, so a rename or move of that directory between openAuthorizedAncestor and the create
// would place the new directories wherever the inode now lives while mkdir reports the original authorized
// path. Re-opening the ancestor without following a final symlink and matching it to the held descriptor
// with os.SameFile ties the held inode back to the authorized path. An empty reason means the create landed
// where it was authorized; a non-empty reason means the caller must roll the create back.
func confirmAncestorStillAuthorized(parentDir *os.File, ancestor string) string {
	const moved = "mkdir target's authorized parent directory moved during the create; refusing to report a directory create at a path it is not located at"
	pathDir, oerr := os.OpenFile(ancestor, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
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

// allowedMkdirArgs is the exact closed set of argument keys the mkdir tool accepts, matching the advertised
// additionalProperties:false schema.
var allowedMkdirArgs = map[string]struct{}{"path": {}}

// rejectUnknownMkdirArgs fails closed if args carries any key outside the advertised closed schema, so the
// runtime contract is no broader than the advertised one. The provider-facing JSON-Schema sets
// additionalProperties:false, so a conforming caller never trips this; it is defense-in-depth that keeps an
// extra-property call from resolving, authorizing, or creating a directory on a mutating tool.
func rejectUnknownMkdirArgs(args map[string]any) error {
	for key := range args {
		if _, ok := allowedMkdirArgs[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only path is accepted", key)
		}
	}
	return nil
}
