// tools.Tool wrapper for a single VCS action, its effective-cwd exposure, and the
// per-template registration of vcs_<action> tools (step 6c).
package vcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/tools"
)

// ActionTool is the tools.Tool for one non-detect VCS action. It dispatches under
// the name vcs_<action> and routes Invoke to the package's action
// invoker with the action spec, repo root, runner, and event seam it was built
// with.
type ActionTool struct {
	actionName string
	action     ActionSpec
	repoRoot   string
	runner     cmdrunner.Runner
	emit       EventAppender
	// cap is sessions.max_tool_output_bytes, supplied by RegisterActions' caller
	// and applied to the persisted tool_exec_end stdout/stderr.
	cap int
	// readOnly is the read-only-vs-mutating classification bound at registration from template
	// provenance and, only for trusted templates, explicit action declarations.
	readOnly bool
	vcsName  string
	// reference marks an embedded built-in or a byte-identical first-run reference copy, whose argv
	// is product-authored wherever the file lives; trusted marks a template loaded from the global
	// directory, whose explicit class declarations bootstrap accepted.
	reference bool
	trusted   bool
}

var _ tools.Tool = (*ActionTool)(nil)

// Name returns the exact dispatch name vcs_<action>.
func (t *ActionTool) Name() string { return toolName(t.actionName) }

// SubjectKind returns the permission subject kind for a structured tool, always "tool".
func (t *ActionTool) SubjectKind() string { return "tool" }

// Advertise returns this action tool's product-authored advertising metadata and its
// source-sensitive read-only classification. The parameter JSON-Schema is keyed by action name —
// viable because template validation rejects unknown action keys, so the action-name set is closed
// even for user-supplied templates. ReadOnly reflects the classification bound at registration from
// the template source, and only an action running the product's own read-only argv is
// noncredential — a template author cannot declare that classification for itself.
func (t *ActionTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description:   t.description(),
		Parameters:    actionParamSchema(t.actionName),
		ReadOnly:      t.readOnly,
		Noncredential: t.readOnly,
	}
}

// description selects the advertised text for this action. A Jujutsu override describes the
// built-in command, but a user template may keep the jj name while replacing any action's argv, so
// those overrides hold only while the action still runs the embedded argv.
func (t *ActionTool) description() string {
	override, ok := vcsActionDescriptions[t.vcsName][t.actionName]
	if !ok {
		return actionDescriptions[t.actionName]
	}
	if t.vcsName == "jj" && !slices.Equal(t.action.Argv, builtinArgv()["jj"][t.actionName]) {
		return configuredJJDescription(t.actionName)
	}
	return override
}

// builtinArgv is the embedded templates' argv per VCS name and action name. A parse failure yields
// no entries, so every action then reads as customized rather than claiming built-in behavior that
// was never confirmed.
var builtinArgv = sync.OnceValue(func() map[string]map[string][]string {
	tmpls, err := LoadBuiltinTemplates()
	if err != nil {
		return nil
	}
	out := make(map[string]map[string][]string, len(tmpls))
	for name, tmpl := range tmpls {
		argv := make(map[string][]string, len(tmpl.Actions))
		for actionName, action := range tmpl.Actions {
			argv[actionName] = action.Argv
		}
		out[name] = argv
	}
	return out
})

func configuredJJDescription(actionName string) string {
	return fmt.Sprintf("Run the configured Jujutsu %s action, which this repository's VCS template defines instead of the built-in command. Use it only as that template defines the action.", actionName)
}

// builtinReadOnlyActions is the product-authored set of VCS template actions that only read
// repository state in embedded built-ins and byte-identical first-run reference copies. The
// complementary actions (add, commit, branch-create, branch-switch, restore-file, stash, stash-pop)
// are always mutating: no template declaration can make one read-only. Detect is never a tool and
// has no entry.
var builtinReadOnlyActions = map[string]bool{
	"status":         true,
	"diff":           true,
	"log":            true,
	"branch-current": true,
	"is-clean":       true,
	"merge-status":   true,
	"rebase-status":  true,
}

// actionDescriptions are the product-authored one-line advertising descriptions for each registered
// vcs_<action> tool, keyed by action name, describing what the action does and when to use it. They
// are the fallback for any VCS name and action without an entry in vcsActionDescriptions. detect is
// not a tool and has no entry.
var actionDescriptions = map[string]string{
	"status":         "Show the working tree's changed, staged, and untracked files. Use to see what has changed before staging or committing.",
	"diff":           "Show the line-level differences between the working tree and the last commit. Use to review the exact changes you are about to commit.",
	"add":            "Stage a file's changes so they are included in the next commit. Use to select a specific path to commit.",
	"commit":         "Record the staged changes as a new commit with the given message. Use once the intended changes are staged.",
	"log":            "Show the most recent commits in summary form. Use to review recent project history.",
	"branch-current": "Report the branch currently checked out. Use to confirm which branch work will land on.",
	"branch-create":  "Create a new branch with the given name without switching to it. Use to start an isolated line of work.",
	"branch-switch":  "Switch the working tree to the named branch. Use to move work onto a different branch.",
	"restore-file":   "Discard a file's uncommitted changes, restoring it to the last committed version. Use to revert unwanted edits to a path.",
	"is-clean":       "Report whether the working tree has any uncommitted changes. Use to check for a clean state before switching branches or committing.",
	"stash":          "Set the current uncommitted changes aside, leaving a clean working tree. Use to temporarily shelve work in progress.",
	"stash-pop":      "Reapply the most recently stashed changes to the working tree. Use to restore previously shelved work.",
	"merge-status":   "Report whether a merge is currently in progress. Use to detect an in-progress merge before starting other VCS work.",
	"rebase-status":  "Report whether a rebase is currently in progress. Use to detect an in-progress rebase before starting other VCS work.",
}

// vcsActionDescriptions are the product-authored one-line advertising descriptions that replace the
// actionDescriptions entry for a given VCS, keyed by Template.Name then action name. An entry exists
// only where the generic wording would be wrong for that backend.
var vcsActionDescriptions = map[string]map[string]string{
	"hg": {
		"status":        "Show the working directory's modified, added, removed, deleted, and unknown files; Mercurial has no staging concept. Use to see what has changed before committing.",
		"add":           "Begin tracking a file Mercurial does not track yet. Use only for an unknown file: a file that is already tracked needs no add, because its changes are committed automatically.",
		"commit":        "Record every tracked modified file as a new commit with the given message; Mercurial has no staging step. Use once the working directory holds the changes you intend to commit.",
		"branch-create": "Name the current working-directory branch, rather than creating a branch without switching to it. Use to start an isolated line of work from the current state.",
	},
	"jj": {
		"status":         "Show the working copy's changed files; Jujutsu has no staging step. Use to see what has changed before committing.",
		"add":            "Begin tracking a file Jujutsu does not track yet. Use only for a path the working-copy snapshot excludes: Jujutsu tracks working-copy files automatically, so every other path is already tracked.",
		"commit":         "Describe the existing working-copy commit with the given message, including all of its current changes, then create a new working-copy commit on top; Jujutsu has no staging step. Use once the working copy holds the changes you intend to commit.",
		"stash":          "Report working-copy state only and set nothing aside: Jujutsu has no stash, because the working copy is already a commit. Use to inspect the working copy, not to shelve work.",
		"stash-pop":      "Report working-copy state only and reapply nothing: Jujutsu has no stash, because the working copy is already a commit. Use to inspect the working copy, not to restore shelved work.",
		"branch-current": "List Jujutsu bookmarks rather than reporting a checked-out branch. Use to inspect bookmark names.",
		"merge-status":   "Report general working-copy state, including conflicts recorded in commits, rather than whether a merge is in progress. Use to inspect the working copy before starting other VCS work.",
		"rebase-status":  "Report general working-copy state; this is a general status probe, not a rebase-specific one. Use to inspect the working copy before starting other VCS work.",
	},
}

// paramDescriptions are the product-authored descriptions for the single placeholder parameter each
// placeholder action accepts, keyed by the placeholder property name (path, message, branch).
var paramDescriptions = map[string]string{
	"path":    "Repository-relative path of the file to act on.",
	"message": "Commit message text.",
	"branch":  "Name of the branch.",
}

// actionParamSchema returns the parameter JSON-Schema (OpenAI function-tool shape) for action.
// A no-placeholder action takes an empty object; a placeholder action requires exactly
// its single string property (path, message, or branch) and forbids any other key, mirroring
// decodeParams and the template placeholder contract. Both shapes set
// additionalProperties:false so provider-facing metadata matches the decoder rather than accepting
// arbitrary extra fields.
func actionParamSchema(actionName string) map[string]any {
	accepted := placeholderActions[actionName]
	if accepted == "" {
		return map[string]any{
			"type":                 "object",
			"properties":           map[string]any{},
			"additionalProperties": false,
		}
	}
	key := strings.Trim(accepted, "{}")
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			key: map[string]any{
				"type":        "string",
				"description": paramDescriptions[key],
			},
		},
		"required":             []string{key},
		"additionalProperties": false,
	}
}

// Invoke decodes args into the action's placeholder params and runs the action.
func (t *ActionTool) Invoke(ctx context.Context, args map[string]any) (tools.Result, error) {
	params, err := decodeParams(t.actionName, args)
	if err != nil {
		return tools.Result{}, err
	}
	return Invoke(ctx, t.actionName, &t.action, params, t.repoRoot, t.runner, t.emit, t.cap)
}

// InvokeWithEffectiveCWD runs the action using a cwd result that was already resolved by
// EffectiveCWD. Structured dispatch uses this after authorizing that same cwd so authorization and
// execution cannot drift if symlinks change between the two steps.
func (t *ActionTool) InvokeWithEffectiveCWD(ctx context.Context, args map[string]any, resolvedCwd string, cwdErr error) (tools.Result, error) {
	params, err := decodeParams(t.actionName, args)
	if err != nil {
		return tools.Result{}, err
	}
	return invokeResolvedCWD(ctx, t.actionName, &t.action, params, t.runner, t.emit, resolvedCwd, cwdErr, t.cap)
}

// EffectiveCWD returns the resolved cwd (or the same cwd error) the action will
// use at invocation, by delegating to ResolveActionCWD. The tool-dispatch layer
// reads this before authorizing so the path scope it authorizes is the
// exact path the action executes in.
func (t *ActionTool) EffectiveCWD() (string, error) {
	return ResolveActionCWD(&t.action, t.repoRoot)
}

// decodeParams pulls the action's single accepted placeholder value out of the
// decoded tool arguments. An action that accepts no placeholder yields
// an empty map. A missing or non-string required value is an error; the full
// argument-schema check is the tool-dispatch layer's concern, so other keys are left untouched.
func decodeParams(actionName string, args map[string]any) (map[string]string, error) {
	accepted := placeholderActions[actionName]
	if accepted == "" {
		return map[string]string{}, nil
	}
	key := strings.Trim(accepted, "{}")
	raw, ok := args[key]
	if !ok {
		return nil, fmt.Errorf("%s: missing required argument %q", toolName(actionName), key)
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%s: argument %q must be a string", toolName(actionName), key)
	}
	return map[string]string{key: s}, nil
}

// RegisterActions registers one ActionTool per non-detect action of tmpl in reg under its
// vcs_<action> name, using tmpl.Source as the registry source. Explicit action class declarations
// are ignored by this untrusted entry point; callers that have already verified template trust should
// use RegisterActionsWithTrustedClasses.
// Registration order follows the canonical action order so any
// same-name replacement warning is deterministic. A nil tmpl (no active template,
// e.g. detection found no match) registers nothing. cap is
// sessions.max_tool_output_bytes (config.Cache.MaxToolOutputBytes()), threaded
// onto each tool so the persisted tool_exec_end output is capped.
func RegisterActions(reg *tools.Registry, tmpl *Template, repoRoot string, runner cmdrunner.Runner, emit EventAppender, cap int) error {
	return registerActions(reg, tmpl, repoRoot, runner, emit, cap, false)
}

// RegisterActionsWithTrustedClasses registers VCS actions like RegisterActions, but treats explicit
// per-action class declarations in tmpl as trusted registration metadata.
func RegisterActionsWithTrustedClasses(reg *tools.Registry, tmpl *Template, repoRoot string, runner cmdrunner.Runner, emit EventAppender, cap int) error {
	return registerActions(reg, tmpl, repoRoot, runner, emit, cap, true)
}

func registerActions(reg *tools.Registry, tmpl *Template, repoRoot string, runner cmdrunner.Runner, emit EventAppender, cap int, trustExplicitClasses bool) error {
	if tmpl == nil {
		return nil
	}
	for _, actionName := range requiredActions {
		if actionName == "detect" {
			continue
		}
		action, ok := tmpl.Actions[actionName]
		if !ok {
			continue
		}
		t := &ActionTool{
			actionName: actionName,
			action:     action,
			repoRoot:   repoRoot,
			runner:     runner,
			emit:       emit,
			cap:        cap,
			readOnly:   actionReadOnly(tmpl, actionName, action, trustExplicitClasses),
			vcsName:    tmpl.Name,
			reference:  isBuiltinTemplateSource(tmpl.Source) || tmpl.BuiltinReferenceCopy,
			trusted:    trustExplicitClasses,
		}
		if err := reg.Register(tmpl.Source, t); err != nil {
			return err
		}
	}
	return nil
}

func actionReadOnly(tmpl *Template, actionName string, action ActionSpec, trustExplicitClasses bool) bool {
	if (isBuiltinTemplateSource(tmpl.Source) || tmpl.BuiltinReferenceCopy) && builtinReadOnlyActions[actionName] {
		return true
	}
	return trustedReadOnlyArgv(tmpl.Name, actionName, action, trustExplicitClasses)
}

// trustedReadOnlyArgv holds a trusted global template's read_only declaration to the product's own
// read-only command: a declaration over any other argv claims something the product never vetted.
func trustedReadOnlyArgv(vcsName, actionName string, action ActionSpec, trusted bool) bool {
	return trusted && action.Class == ClassReadOnly && builtinReadOnlyActions[actionName] &&
		slices.Equal(builtinArgv()[vcsName][actionName], action.Argv)
}

const maxProtectQueryBytes = 1 << 16

var errProtectQuery = errors.New("vcs: protected-state query established no verdict")

// protectQuery is one product-authored, non-mutating backend query about a single protected
// candidate. A non-negative affectedExit reads the verdict from the exit status; a negative one
// reads it from whether the query named any path.
type protectQuery struct {
	argv         []string
	affectedExit int
	safeExit     int
}

func outputQuery(argv ...string) protectQuery {
	return protectQuery{argv: argv, affectedExit: -1}
}

func statusQuery(affected, safe int, argv ...string) protectQuery {
	return protectQuery{argv: argv, affectedExit: affected, safeExit: safe}
}

// protectRule is the pre-execution check for one working-tree-replacing action. revisions resolves
// the revision arguments its queries need and reports noWork when the action has nothing to apply.
// A nil queries builder refuses without running anything, because that backend offers no lossless
// affected-path query for the action.
type protectRule struct {
	revisions func(ctx context.Context, t *ActionTool, params map[string]string) (revs []string, noWork bool, err error)
	queries   func(rel string, revs []string) []protectQuery
	// argPath marks an action whose would-change set is bounded by its {path} argument, so a
	// candidate that argument cannot select is outside this action's reach.
	argPath bool
}

// protectRules is the product-authored table of actions that can replace working-file bytes, per VCS
// name. An action absent from a backend's entry cannot rewrite a checked-out file through its
// built-in argv: Jujutsu's stash actions only report status, and add, commit, and branch-create
// record history without touching the working copy.
var protectRules = map[string]map[string]protectRule{
	// The global --literal-pathspecs flag, not a :(literal) prefix: an inherited
	// GIT_LITERAL_PATHSPECS=1 would read the prefix as part of a filename that matches nothing.
	"git": {
		"branch-switch": {revisions: gitResolveCommit, queries: func(rel string, revs []string) []protectQuery {
			return []protectQuery{statusQuery(1, 0, "git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", revs[0], "--", rel)}
		}},
		"restore-file": {argPath: true, queries: func(rel string, _ []string) []protectQuery {
			return []protectQuery{statusQuery(0, 1, "git", "--literal-pathspecs", "ls-files", "--error-unmatch", "--", rel)}
		}},
		"stash": {queries: func(rel string, _ []string) []protectQuery {
			return []protectQuery{
				statusQuery(1, 0, "git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", "--", rel),
				statusQuery(1, 0, "git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", "--cached", "--", rel),
			}
		}},
		"stash-pop": {revisions: gitResolveStash, queries: func(rel string, revs []string) []protectQuery {
			return []protectQuery{statusQuery(1, 0, "git", "--literal-pathspecs", "diff", "--quiet", "--no-ext-diff", revs[0], revs[1], "--", rel)}
		}},
	},
	"hg": {
		"branch-switch": {revisions: passthroughRevision, queries: func(rel string, revs []string) []protectQuery {
			return []protectQuery{outputQuery("hg", "status", "--rev", revs[0], "--", hgPath(rel))}
		}},
		"restore-file": {argPath: true, queries: func(rel string, _ []string) []protectQuery {
			return []protectQuery{statusQuery(0, 1, "hg", "files", "--", hgPath(rel))}
		}},
		"stash": {queries: func(rel string, _ []string) []protectQuery {
			return []protectQuery{outputQuery("hg", "status", "--modified", "--added", "--removed", "--deleted", "--", hgPath(rel))}
		}},
		"stash-pop": {},
	},
	"jj": {
		"branch-switch": {revisions: passthroughRevision, queries: func(rel string, revs []string) []protectQuery {
			return []protectQuery{outputQuery("jj", "diff", "--from", revs[0], "--to", "@", "--name-only", "--", jjFileset(rel))}
		}},
		"restore-file": {argPath: true, queries: func(rel string, _ []string) []protectQuery {
			return []protectQuery{outputQuery("jj", "diff", "--from", "@-", "--to", "@", "--name-only", "--", jjFileset(rel))}
		}},
	},
}

// ProtectedStateRisk reports whether running this action could rewrite one of the run's protected
// settings identities. It answers before the action launches, using only non-mutating backend
// queries that emit no execution events, and reports risk for anything it cannot prove safe.
// protectedIn supplies the protected identities inside this repository, and is called only for an
// action whose verdict needs them.
func (t *ActionTool) ProtectedStateRisk(ctx context.Context, args map[string]any, protectedIn func(root string) ([]string, error)) bool {
	if !t.productArgv() {
		return true
	}
	rule, risky := protectRules[t.vcsName][t.actionName]
	if !risky {
		return false
	}
	protected, err := protectedIn(t.repoRoot)
	if err != nil {
		return true
	}
	if len(protected) == 0 {
		return false
	}
	if rule.queries == nil {
		return true
	}
	params, err := decodeParams(t.actionName, args)
	if err != nil {
		return true
	}
	var revs []string
	if rule.revisions != nil {
		var noWork bool
		revs, noWork, err = rule.revisions(ctx, t, params)
		if err != nil {
			return true
		}
		if noWork {
			return false
		}
	}
	// The protected set is enumerated under the resolved root, so a candidate is named relative to
	// that same form rather than to a repo root the model could reach through a symlink.
	resolvedRoot, err := filepath.EvalSymlinks(t.repoRoot)
	if err != nil {
		return true
	}
	var targets []string
	if rule.argPath {
		targets, err = requestedTargets(resolvedRoot, params["path"])
		if err != nil {
			return true
		}
	}
	for _, candidate := range protected {
		rel, err := repoRelative(resolvedRoot, candidate)
		if err != nil {
			return true
		}
		if rule.argPath && !selectsCandidate(targets, rel) {
			continue
		}
		for _, q := range rule.queries(rel, revs) {
			affected, err := t.runProtectQuery(ctx, q)
			if err != nil || affected {
				return true
			}
		}
	}
	return false
}

// productArgv reports whether this action runs argv the product itself authored: the embedded
// built-in command for a built-in or byte-identical reference template, or — only for a trusted
// global template — an explicit read_only declaration over that built-in's own read-only argv.
func (t *ActionTool) productArgv() bool {
	if t.reference {
		return slices.Equal(builtinArgv()[t.vcsName][t.actionName], t.action.Argv)
	}
	return trustedReadOnlyArgv(t.vcsName, t.actionName, t.action, t.trusted)
}

func (t *ActionTool) runProtectQuery(ctx context.Context, q protectQuery) (bool, error) {
	res, err := t.execProtectQuery(ctx, q.argv)
	if err != nil {
		return false, err
	}
	if q.affectedExit < 0 {
		if res.ExitCode != 0 {
			return false, errProtectQuery
		}
		// Any byte at all is a record: a path made only of whitespace is a real filename, so
		// trimming the output would read a named protected alias as an empty affected set.
		return len(res.Stdout) > 0, nil
	}
	switch res.ExitCode {
	case q.affectedExit:
		return true, nil
	case q.safeExit:
		return false, nil
	}
	return false, errProtectQuery
}

func (t *ActionTool) execProtectQuery(ctx context.Context, argv []string) (cmdrunner.RunResult, error) {
	res, err := t.runner.Exec(ctx, cmdrunner.RunSpec{
		InvocationID: t.runner.NewInvocationID(),
		Argv:         argv,
		Cwd:          t.repoRoot,
	})
	if err != nil || res.LaunchErrCategory != "" {
		return cmdrunner.RunResult{}, errProtectQuery
	}
	if len(res.Stdout) > maxProtectQueryBytes || bytes.IndexByte(res.Stdout, 0) >= 0 {
		return cmdrunner.RunResult{}, errProtectQuery
	}
	return res, nil
}

// repoRelative converts an absolute protected candidate into the repository-relative path a query
// may name. A path that escapes the repository, or one carrying a character an argument list or a
// Jujutsu fileset cannot express unambiguously, has no safe query form.
func repoRelative(root, candidate string) (string, error) {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", errProtectQuery
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errProtectQuery
	}
	if strings.ContainsAny(rel, "\"\\\n\r\x00") {
		return "", errProtectQuery
	}
	return rel, nil
}

func jjFileset(rel string) string { return `root:"` + rel + `"` }

func hgPath(rel string) string { return "path:" + rel }

// requestedTargets converts an action's {path} argument into the repository-relative forms it can
// select. An empty, flag-shaped, whole-tree, escaping argument, or one written in a backend's
// pattern language (a git pathspec, a Mercurial pattern prefix, a Jujutsu fileset expression),
// selects a set this check cannot bound, so it has no safe form and refuses.
func requestedTargets(root, req string) ([]string, error) {
	if req == "" || strings.HasPrefix(req, "-") || strings.ContainsAny(req, "*?[]{}:|&~()'") {
		return nil, errProtectQuery
	}
	abs := req
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, abs)
	}
	rel, err := repoRelative(root, filepath.Clean(abs))
	if err != nil {
		return nil, err
	}
	targets := []string{rel}
	resolved, err := filepath.EvalSymlinks(abs)
	switch {
	case err == nil:
		// A symlinked component makes the request name a different file than its spelling does.
		if through, relErr := repoRelative(root, resolved); relErr == nil && through != rel {
			targets = append(targets, through)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, errProtectQuery
	}
	return targets, nil
}

// selectsCandidate reports whether a requested form names rel, a directory holding it, or a path
// inside it. The comparison ignores case because a case-insensitive filesystem lets a differently
// cased request select the same file.
func selectsCandidate(targets []string, rel string) bool {
	rel = strings.ToLower(rel)
	sep := string(filepath.Separator)
	for _, target := range targets {
		target = strings.ToLower(target)
		if rel == target || strings.HasPrefix(rel, target+sep) || strings.HasPrefix(target, rel+sep) {
			return true
		}
	}
	return false
}

// passthroughRevision hands the caller-supplied branch to the backend, which resolves the symbolic
// name itself; only its form is checked here.
func passthroughRevision(_ context.Context, _ *ActionTool, params map[string]string) ([]string, bool, error) {
	rev, err := safeRevision(params["branch"])
	if err != nil {
		return nil, false, err
	}
	return []string{rev}, false, nil
}

// safeRevision rejects an argument a backend would read as an option or as more than one word, so a
// query never carries a model-supplied flag.
func safeRevision(rev string) (string, error) {
	if rev == "" || strings.HasPrefix(rev, "-") || strings.ContainsAny(rev, " \t\n\r\x00") {
		return "", errProtectQuery
	}
	return rev, nil
}

func gitResolveCommit(ctx context.Context, t *ActionTool, params map[string]string) ([]string, bool, error) {
	rev, err := safeRevision(params["branch"])
	if err != nil {
		return nil, false, err
	}
	id, err := gitRevParse(ctx, t, rev+"^{commit}")
	if err != nil {
		return nil, false, err
	}
	return []string{id}, false, nil
}

func gitResolveStash(ctx context.Context, t *ActionTool, _ map[string]string) ([]string, bool, error) {
	res, err := t.execProtectQuery(ctx, []string{"git", "rev-parse", "--verify", "--quiet", "refs/stash"})
	if err != nil {
		return nil, false, err
	}
	// An absent stash ref is a verdict, not a failure: there is nothing for a pop to apply.
	if res.ExitCode == 1 && len(bytes.TrimSpace(res.Stdout)) == 0 {
		return nil, true, nil
	}
	if res.ExitCode != 0 {
		return nil, false, errProtectQuery
	}
	stash, err := singleObjectID(res.Stdout)
	if err != nil {
		return nil, false, err
	}
	base, err := gitRevParse(ctx, t, "refs/stash^1")
	if err != nil {
		return nil, false, err
	}
	return []string{base, stash}, false, nil
}

func gitRevParse(ctx context.Context, t *ActionTool, rev string) (string, error) {
	res, err := t.execProtectQuery(ctx, []string{"git", "rev-parse", "--verify", "--quiet", rev})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", errProtectQuery
	}
	return singleObjectID(res.Stdout)
}

// singleObjectID requires exactly one whole object id, so an ambiguous or empty resolution carries
// no verdict of its own.
func singleObjectID(out []byte) (string, error) {
	fields := strings.Fields(string(out))
	if len(fields) != 1 || (len(fields[0]) != 40 && len(fields[0]) != 64) {
		return "", errProtectQuery
	}
	for _, r := range fields[0] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return "", errProtectQuery
		}
	}
	return fields[0], nil
}
