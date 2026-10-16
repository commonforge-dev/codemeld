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

// CreateToolName is the exact dispatch name the structured create tool registers under.
// Like `edit` and `bash`, it is a fixed built-in name carrying no template namespace.
const CreateToolName = "create"

// createFileMode is the permission mode a newly created file is given. Create makes a brand-new file
// (it never overwrites), so there is no prior mode to preserve; 0o644 is the conventional default for a
// new source/text file and is further constrained by the process umask.
const createFileMode os.FileMode = 0o644

// processUmask is the process file-creation mask, captured once during package initialization. There
// is no read-only umask syscall — reading it means setting it and putting it back — so capturing it
// per create would open a window in which another goroutine's O_CREAT saw a cleared mask; package
// initialization runs before the process creates anything. fsutil's publish now fchmods the staged
// file to exactly the mode it is handed, so the O_CREAT mode is no longer what the umask trims:
// applying the mask here is what keeps createFileMode's documented umask constraint true.
var processUmask = captureUmask()

// captureUmask reads the process umask by setting it to zero and immediately restoring it.
func captureUmask() os.FileMode {
	mask := unix.Umask(0)
	unix.Umask(mask)
	return os.FileMode(mask) & os.ModePerm
}

type CreateTool struct {
	home        string
	processCWD  string
	projectRoot string
}

var _ tools.Tool = (*CreateTool)(nil)

var beforeCreatePublish = func() {}

// JournalState is the exact visible state of one declared path; absence is the zero value.
type JournalState struct {
	Exists bool
	Data   []byte
	Mode   os.FileMode
	Dev    uint64
	Ino    uint64
}

// WriteJournal is the durable rollback record a delegated child agent's structured writes report to.
// A mutating tool consults it only for a path it covers, and the call order is fixed:
//
// BeginMutation records the state publication is about to make visible and refuses the mutation when
// observed does not equal the durable last-known child state, so an external change made after the
// snapshot is never absorbed as the child's own; its error prevents the publish. ResolveMutation runs
// once the publish and any post-publication compensation have finished, through the same held parent
// descriptor the publish ran through, and is told the identity it published so a byte-identical file
// another writer put at the name in that window is not read as the child's own. AbandonMutation resolves the record instead whenever the write
// never published (the helpers report that as a nil published identity): the pending bytes then belong
// to nobody, so a file that happens to hold them was put there by someone else and must not be taken
// as the child's own work. RemovePublished is the only route by which a caller may take back a create
// it published, because it removes the inode named by published rather than whatever answers to the
// name.
//
// BeginDelete reads the entry the held parent descriptor shows, refuses when it is not the durable
// last-known child state, and records expected absence before the caller unlinks; ResolveMutation then
// settles a completed unlink and AbandonMutation one that failed. An entry replaced after that
// comparison and before the unlink is removed without being detected.
//
// MoveLifecycle brackets one rename: it refuses a source and destination the journal does not declare
// as one pair, or endpoints that are not their durable last-known child states, and settles the move
// once the rename has run.
type WriteJournal interface {
	Covers(target string) bool
	MaxStateBytes() int64
	BeginMutation(target string, observed, next JournalState) error
	BeginDelete(target string, parentDir *os.File) error
	ResolveMutation(target string, parentDir *os.File, published JournalState)
	AbandonMutation(target string, parentDir *os.File)
	RemovePublished(target string, parentDir *os.File, published JournalState)
	DirLifecycle(target, ancestor string) fsutil.DirLifecycle
	MoveLifecycle(source, destination string) fsutil.MoveLifecycle
}

type writeJournalKey struct{}

// WithWriteJournal binds journal to ctx for one child agent's dispatch. It travels as a call parameter
// rather than a package variable because nested delegates hold overlapping declared scopes, so a
// process-wide binding could route a write into the wrong child's journal.
func WithWriteJournal(ctx context.Context, journal WriteJournal) context.Context {
	return context.WithValue(ctx, writeJournalKey{}, journal)
}

// WriteJournalFromContext returns the journal bound to ctx, or nil when the call is not running under
// a child agent.
func WriteJournalFromContext(ctx context.Context) WriteJournal {
	journal, _ := ctx.Value(writeJournalKey{}).(WriteJournal)
	return journal
}

// WriteJournalFor returns the journal bound to ctx when it covers target, and nil otherwise, so an
// undeclared path and an unjournalled call take the same unrecorded route.
func WriteJournalFor(ctx context.Context, target string) WriteJournal {
	journal := WriteJournalFromContext(ctx)
	if journal == nil || !journal.Covers(target) {
		return nil
	}
	return journal
}

// journalIdentity yields the zero identity for a FileInfo this package cannot decode, which the
// journal never accepts as a match.
// publishedState names what a publish left at the path: the bytes it wrote and the inode it linked
// there. The identity is the part a pending record cannot hold, because it is only known afterwards.
func publishedState(data []byte, info os.FileInfo) JournalState {
	if info == nil {
		return JournalState{}
	}
	dev, ino := journalIdentity(info)
	return JournalState{Exists: true, Data: data, Mode: info.Mode().Perm(), Dev: dev, Ino: ino}
}

func journalIdentity(info os.FileInfo) (dev, ino uint64) {
	if info == nil {
		return 0, 0
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return uint64(st.Dev), uint64(st.Ino)
}

// ScopeIdentity is the directory an authorization was granted for, recorded as an inode rather than a
// path so a different folder standing at that path by the time the approval arrives is still
// distinguishable. Its zero value is never a captured directory, so it can be refused rather than
// compared.
type ScopeIdentity struct {
	dev uint64
	ino uint64
}

// CaptureScopeIdentity requires scope to be already symlink-resolved: the open does not follow a final
// symlink, so a link standing at that path is a capture failure rather than a capture of its target.
func CaptureScopeIdentity(scope string) (ScopeIdentity, error) {
	dir, oerr := os.OpenFile(scope, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return ScopeIdentity{}, fmt.Errorf("cannot record the identity of the authorized directory %s: %w", scope, oerr)
	}
	defer dir.Close() //nolint:errcheck // read-only descriptor opened only to record directory identity
	info, serr := dir.Stat()
	if serr != nil {
		return ScopeIdentity{}, fmt.Errorf("cannot record the identity of the authorized directory %s: %w", scope, serr)
	}
	dev, ino := journalIdentity(info)
	if dev == 0 && ino == 0 {
		return ScopeIdentity{}, fmt.Errorf("cannot record the identity of the authorized directory %s", scope)
	}
	return ScopeIdentity{dev: dev, ino: ino}, nil
}

// authorizedScopeReplaced is deliberately not one of the "moved during …" refusals: those report a
// directory that moved while the operation was running, whereas this one reports a directory that was
// already a different directory before the operation began.
const authorizedScopeReplaced = "the authorized directory was replaced while the request was pending; refusing to operate on a directory the approval did not cover"

// authorizedScope is the directory whose identity was compared with the one captured before the prompt,
// held open. Releasing that descriptor and letting the operation re-open the path would leave the very
// window the comparison exists to close: every directory the operation acts through is therefore reached
// fd-relative from dir, so a directory swapped in after the comparison can never be the one written to.
type authorizedScope struct {
	path string
	dir  *os.File
}

// afterScopeConfirmed is a test seam invoked once the authorized scope's identity has been confirmed and
// its descriptor held, before the operation helper opens the directory it acts through. It exists so a
// replacement in exactly that window can be driven deterministically.
var afterScopeConfirmed = func() {}

func confirmAuthorizedScope(scope string, captured ScopeIdentity) (*authorizedScope, string) {
	if captured == (ScopeIdentity{}) {
		return nil, authorizedScopeReplaced
	}
	dir, oerr := os.OpenFile(scope, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return nil, authorizedScopeReplaced
	}
	info, serr := dir.Stat()
	if serr != nil {
		dir.Close() //nolint:errcheck // read-only descriptor opened only to compare directory identity
		return nil, authorizedScopeReplaced
	}
	if dev, ino := journalIdentity(info); dev != captured.dev || ino != captured.ino {
		dir.Close() //nolint:errcheck // read-only descriptor opened only to compare directory identity
		return nil, authorizedScopeReplaced
	}
	return &authorizedScope{path: scope, dir: dir}, ""
}

func (s *authorizedScope) Close() {
	if s != nil && s.dir != nil {
		_ = s.dir.Close() //nolint:errcheck // read-only descriptor held only to pin the authorized directory
	}
}

// openWithin returns a descriptor on dir — the authorized scope itself, or a directory beneath it that
// appeared while the prompt was open — reached only through the confirmed scope descriptor. The
// re-comparison afterwards reports a replacement that landed between the confirmation and this open with
// the pending-request refusal rather than leaving it to a mid-operation "moved" check; a replacement
// after it cannot reach the operation at all, because every later step runs fd-relative to the returned
// descriptor.
func (s *authorizedScope) openWithin(dir string) (*os.File, string) {
	segs, ok := relSegsWithin(s.path, dir)
	if !ok {
		return nil, authorizedScopeReplaced
	}
	opened, reason := openDirRelative(s.dir, segs)
	if reason != "" {
		return nil, authorizedScopeReplaced
	}
	if !s.stillAtPath() {
		opened.Close() //nolint:errcheck // discarded before use; the refusal is reported regardless
		return nil, authorizedScopeReplaced
	}
	return opened, ""
}

func (s *authorizedScope) stillAtPath() bool {
	pathDir, oerr := os.OpenFile(s.path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return false
	}
	defer pathDir.Close() //nolint:errcheck // read-only descriptor opened only to compare directory identity
	heldInfo, herr := s.dir.Stat()
	pathInfo, perr := pathDir.Stat()
	return herr == nil && perr == nil && os.SameFile(heldInfo, pathInfo)
}

// relSegsWithin splits dir into the path segments separating it from scope. A dir that is not scope
// itself or a descendant of it is not expressible as a descent from the confirmed descriptor, so it is
// refused rather than opened by pathname.
func relSegsWithin(scope, dir string) ([]string, bool) {
	if dir == scope {
		return nil, true
	}
	if !permissions.IsDescendantOrEqual(dir, scope) {
		return nil, false
	}
	rel, rerr := filepath.Rel(scope, dir)
	if rerr != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, false
	}
	return strings.Split(rel, string(filepath.Separator)), true
}

// NewCreateTool builds the create tool bound to the run's ~ anchor (home), the default base directory
// for a relative target path (processCWD), and the project root the target must stay within.
// The project root is symlink-resolved once here so the containment check compares it against
// the symlink-resolved parent on the same footing — mirroring NewEditTool — so dispatch's
// pre-authorization containment check and Auto edits' later in-scope check agree.
func NewCreateTool(home, processCWD, projectRoot string) *CreateTool {
	return &CreateTool{home: home, processCWD: processCWD, projectRoot: normalizeRoot(projectRoot)}
}

func (t *CreateTool) Name() string { return CreateToolName }

func (t *CreateTool) SubjectKind() string { return "tool" }

// Advertise returns the create tool's advertising metadata and mutating classification.
// The parameter JSON-Schema is the OpenAI function-tool shape with
// additionalProperties:false so the advertised contract matches the decoder exactly. ReadOnly is false:
// create mutates the filesystem, so Plan denies it and Auto edits may auto-approve it.
func (t *CreateTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: "Create a new file with the given content. The target must not " +
			"already exist (file, directory, or symlink); any missing parent directories are created for " +
			"you. The call fails without writing anything otherwise. Never overwrites an existing file — " +
			"use edit for that. Use to add a brand-new file.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "Path of the new file to create. Any missing parent directories are created for you. Relative or in-project paths resolve against the working directory and create normally; a path whose real (symlink-resolved) location is outside the project is allowed only after you approve it at the permission prompt.",
				},
				"content": map[string]any{
					"type":        "string",
					"description": "Full contents of the new file. May be empty to create an empty file.",
				},
			},
			"required":             []string{"path", "content"},
			"additionalProperties": false,
		},
		ReadOnly: false,
	}
}

func (t *CreateTool) ResolveTarget(args map[string]any) (target string, scope string, err error) {
	if verr := rejectUnknownCreateArgs(args); verr != nil {
		return "", "", &TargetError{Kind: CreateToolName, Reason: verr.Error()}
	}
	rawPath, perr := requireStringArg(args, "path")
	if perr != nil {
		return "", "", &TargetError{Kind: CreateToolName, Reason: perr.Error()}
	}
	if strings.TrimSpace(rawPath) == "" {
		return "", "", &TargetError{Kind: CreateToolName, Reason: "path must be non-empty"}
	}

	absTarget, reason := t.absCreateTarget(rawPath)
	if reason != "" {
		return "", "", &TargetError{Kind: CreateToolName, Reason: reason}
	}

	if _, lerr := os.Lstat(absTarget); lerr == nil {
		return "", "", &TargetError{Kind: CreateToolName, Reason: "target already exists; create does not overwrite (use edit to change an existing file)"}
	} else if !errors.Is(lerr, fs.ErrNotExist) && !errors.Is(lerr, unix.ENOTDIR) {
		return "", "", &TargetError{Kind: CreateToolName, Reason: "cannot determine whether the target already exists"}
	}

	ancestor, segs, _, reason := splitExistingPrefix(absTarget)
	if reason != "" {
		return "", "", &TargetError{Kind: CreateToolName, Reason: reason}
	}
	resolvedAncestor, cerr := permissions.CleanAbsResolve(t.home, t.processCWD, ancestor)
	if cerr != nil {
		return "", "", &TargetError{Kind: CreateToolName, Reason: "cannot resolve a safe existing parent directory for the target"}
	}
	resolvedTarget := filepath.Join(append([]string{resolvedAncestor}, segs...)...)
	if !permissions.IsDescendantOrEqual(resolvedTarget, resolvedAncestor) {
		return "", "", &TargetError{Kind: CreateToolName, Reason: "target escapes its resolved parent directory"}
	}
	return resolvedTarget, resolvedAncestor, nil
}

func (t *CreateTool) absCreateTarget(rawPath string) (string, string) {
	expanded, eerr := paths.Expand(t.home, rawPath)
	if eerr != nil {
		return "", "unsupported ~user path form; only ~ and ~/<subpath> are supported"
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(t.processCWD, expanded)
	}
	return filepath.Clean(expanded), ""
}

// OutOfRootScope reports whether scope (the resolved path scope ResolveTarget returned) lies outside this
// tool's project root — the out-of-root signal dispatch uses to re-enable the folder grant option
// for an out-of-root create. Containment uses the same descendant rule as folder-grant path scopes; the
// scope is the resolved real parent directory, so the verdict matches the folder the file would land in.
func (t *CreateTool) OutOfRootScope(scope string) bool {
	return !permissions.IsDescendantOrEqual(scope, t.projectRoot)
}

// InvokeWithResolvedTarget creates the file at the target dispatch already resolved before
// authorization, so authorization and the write cannot drift if a symlink changes in between — the same
// resolved-before-authorize / reuse-at-invoke contract the edit tool follows. Production dispatch routes
// the create tool through InvokeWithAuthorizedScope instead, which carries the authorized directory's
// identity as well as the target.
func (t *CreateTool) InvokeWithResolvedTarget(ctx context.Context, args map[string]any, resolvedTarget string) (tools.Result, error) {
	return t.create(ctx, nil, resolvedTarget, args), nil
}

// InvokeWithAuthorizedScope is the seam production dispatch invokes the create tool through. scope is
// the ancestor that was authorized, not the deepest ancestor existing now, so an intermediate directory
// legitimately created while the prompt was open does not read as a replacement. The confirmed scope
// descriptor is held for the whole create and every directory the create opens is reached through it.
func (t *CreateTool) InvokeWithAuthorizedScope(ctx context.Context, args map[string]any, resolvedTarget string, scope string, scopeIdentity ScopeIdentity) (tools.Result, error) {
	confirmed, replaced := confirmAuthorizedScope(scope, scopeIdentity)
	if replaced != "" {
		return failResult(replaced), nil
	}
	defer confirmed.Close()
	afterScopeConfirmed()
	return t.create(ctx, confirmed, resolvedTarget, args), nil
}

// Invoke resolves the target and creates the file in one call (the standalone, non-dispatch path).
// Production dispatch instead calls ResolveTarget then InvokeWithAuthorizedScope; this method keeps the
// tool a complete unit for direct callers and tests. A target-resolution failure surfaces as the same
// in-band error result the dispatcher would render, so the observable outcome matches either entry.
//
// Standalone Invoke has no authorizer, so it must enforce the out-of-root boundary itself: an out-of-root
// resolved target (OutOfRootScope) is reachable only by explicit per-write approval, which only the
// dispatch path can obtain. This method therefore refuses an out-of-root target in-band rather than
// writing it — without this guard a direct caller could create outside the project root with no prompt
// or grant check. The in-root path is unchanged.
func (t *CreateTool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	target, scope, err := t.ResolveTarget(args)
	if err != nil {
		return failResult(err.Error()), nil
	}
	if t.OutOfRootScope(scope) {
		return failResult("create target outside the project root requires permission approval through dispatch"), nil
	}
	return t.create(ctx, nil, target, args), nil
}

func (t *CreateTool) create(ctx context.Context, scope *authorizedScope, target string, args map[string]any) tools.Result {
	if verr := rejectUnknownCreateArgs(args); verr != nil {
		return failResult(verr.Error())
	}
	if _, perr := requireStringArg(args, "path"); perr != nil {
		return failResult(perr.Error())
	}
	content, err := requireStringArg(args, "content")
	if err != nil {
		return failResult(err.Error())
	}

	ancestor, segs, exists, reason := splitExistingPrefix(target)
	if reason != "" {
		return failResult(reason)
	}
	if exists || len(segs) == 0 {
		return failResult("target already exists; create does not overwrite (use edit to change an existing file)")
	}

	journal := WriteJournalFor(ctx, target)
	// Checked before the parent directories are made, not at the publish hook: a body the journal
	// cannot record must not leave newly created directories behind as its only trace.
	if journal != nil && int64(len(content)) > journal.MaxStateBytes() {
		return failResult(fmt.Sprintf("content is %d bytes, over the %d-byte limit a child agent's rollback journal can record for one path", len(content), journal.MaxStateBytes()))
	}

	ancestorDir, openReason := t.openAuthorizedParent(scope, ancestor)
	if openReason != "" {
		return failResult(openReason)
	}
	defer ancestorDir.Close() //nolint:errcheck // nothing useful can be done after the create result is formed

	parentDir := ancestorDir
	dirSegs := segs[:len(segs)-1]
	if len(dirSegs) > 0 {
		var lifecycle fsutil.DirLifecycle
		if journal != nil {
			lifecycle = journal.DirLifecycle(target, ancestor)
		}
		if _, _, _, derr := fsutil.EnsureDirAt(ancestorDir, strings.Join(dirSegs, "/"), lifecycle); derr != nil {
			return failResult("failed to create the parent directories: " + derr.Error())
		}
		finalParent, descendReason := openDirRelative(ancestorDir, dirSegs)
		if descendReason != "" {
			return failResult(descendReason)
		}
		parentDir = finalParent
		defer parentDir.Close() //nolint:errcheck // read-only descriptor on the created suffix's final directory
	}

	beforeCreatePublish()

	leaf := filepath.Base(target)
	var record fsutil.PrePublish
	if journal != nil {
		record = func(_ string, data []byte, mode os.FileMode) error {
			return journal.BeginMutation(target, JournalState{}, JournalState{Exists: true, Data: data, Mode: mode})
		}
	}
	_, _, published, werr := fsutil.WriteAtomicCreateAt(parentDir, leaf, []byte(content), createFileMode&^processUmask, record)
	if werr != nil {
		if journal != nil {
			// A nil published identity means the link never happened — a racing EEXIST, most of all,
			// which is create's no-overwrite contract holding. Whatever occupies the name is another
			// writer's file even when it holds byte-identical content, so the record is abandoned
			// rather than reconciled: reconciling would let the rollback remove it.
			if published == nil {
				journal.AbandonMutation(target, parentDir)
			} else {
				journal.ResolveMutation(target, parentDir, publishedState([]byte(content), published))
			}
		}
		return failResult("failed to create the file: " + werr.Error())
	}
	moved := t.confirmParentStillAuthorized(ancestorDir, ancestor)
	if moved == "" {
		moved = confirmFinalParentUnmoved(ancestorDir, parentDir, dirSegs)
	}
	if moved != "" {
		if journal != nil {
			journal.RemovePublished(target, parentDir, publishedState([]byte(content), published))
		} else {
			_ = unix.Unlinkat(int(parentDir.Fd()), leaf, 0) //nolint:errcheck // best-effort rollback; the failure is reported regardless
		}
		return failResult(moved)
	}
	if journal != nil {
		journal.ResolveMutation(target, parentDir, publishedState([]byte(content), published))
	}
	return tools.Result{ExitCode: 0, Stdout: []byte(fmt.Sprintf("created %s (%d bytes)\n", target, len(content)))}
}

func (t *CreateTool) openAuthorizedParent(scope *authorizedScope, authorizedDir string) (*os.File, string) {
	reDir, rerr := permissions.CleanAbsResolve(t.home, t.processCWD, authorizedDir)
	if rerr != nil {
		return nil, "create target's parent directory can no longer be resolved to an existing directory"
	}
	if reDir != authorizedDir {
		return nil, "create target's parent directory changed after authorization; refusing to create outside the authorized directory"
	}
	if scope != nil {
		return scope.openWithin(authorizedDir)
	}
	dir, oerr := os.OpenFile(authorizedDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return nil, "create target's parent directory changed after authorization; refusing to create outside the authorized directory"
	}
	return dir, ""
}

func openDirRelative(parent *os.File, segs []string) (*os.File, string) {
	const redirected = "create target's parent directory changed after authorization; refusing to create outside the authorized directory"
	if len(segs) == 0 {
		// A fresh descriptor on the same directory, never parent itself: the caller closes what it is
		// handed, and parent outlives it.
		fd, oerr := unix.Openat(int(parent.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if oerr != nil {
			return nil, redirected
		}
		return os.NewFile(uintptr(fd), parent.Name()), ""
	}
	cur := parent
	for _, seg := range segs {
		fd, oerr := unix.Openat(int(cur.Fd()), seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if cur != parent {
			_ = cur.Close() //nolint:errcheck // read-only intermediate descriptor opened only to descend fd-relative
		}
		if oerr != nil {
			return nil, redirected
		}
		cur = os.NewFile(uintptr(fd), seg)
	}
	return cur, ""
}

func (t *CreateTool) confirmParentStillAuthorized(ancestorDir *os.File, authorizedDir string) string {
	const moved = "create target's parent directory moved during the create; refusing to report a create at a path the new file is not located at"
	pathDir, oerr := os.OpenFile(authorizedDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if oerr != nil {
		return moved
	}
	defer pathDir.Close() //nolint:errcheck // read-only descriptor opened only to compare directory identity
	heldInfo, herr := ancestorDir.Stat()
	pathInfo, perr := pathDir.Stat()
	if herr != nil || perr != nil || !os.SameFile(heldInfo, pathInfo) {
		return moved
	}
	return ""
}

func confirmFinalParentUnmoved(ancestorDir, parentDir *os.File, dirSegs []string) string {
	const moved = "create target's parent directory moved during the create; refusing to report a create at a path the new file is not located at"
	if len(dirSegs) == 0 {
		return ""
	}
	reParent, reason := openDirRelative(ancestorDir, dirSegs)
	if reason != "" {
		return moved
	}
	defer reParent.Close() //nolint:errcheck // read-only descriptor opened only to compare directory identity
	heldInfo, herr := parentDir.Stat()
	reInfo, rerr := reParent.Stat()
	if herr != nil || rerr != nil || !os.SameFile(heldInfo, reInfo) {
		return moved
	}
	return ""
}

// allowedCreateArgs is the exact closed set of argument keys the create tool accepts, matching the
// advertised additionalProperties:false schema.
var allowedCreateArgs = map[string]struct{}{"path": {}, "content": {}}

// rejectUnknownCreateArgs fails closed if args carries any key outside the advertised closed schema, so
// the runtime contract is no broader than the advertised one. The provider-facing JSON-Schema sets
// additionalProperties:false, so a conforming caller never trips this; it is defense-in-depth that keeps
// an extra-property call from resolving, authorizing, or creating a file on a mutating tool that Auto
// edits may later auto-approve without prompting.
func rejectUnknownCreateArgs(args map[string]any) error {
	for key := range args {
		if _, ok := allowedCreateArgs[key]; !ok {
			return fmt.Errorf("unexpected argument %q; only path and content are accepted", key)
		}
	}
	return nil
}
