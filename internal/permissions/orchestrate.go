package permissions

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Avoid an import cycle: internal/tui imports internal/permissions.
type PromptChoice int

const (
	PromptAllowOnce PromptChoice = iota
	PromptDeny
	PromptAllowSession
	PromptAllowFolder
	PromptAllowGlobal
	PromptAllowProject
)

type PromptOutcome struct {
	Choice        PromptChoice
	StoredSubject string
	DenyEnvelope  string
}

type GrantTable interface {
	Permissions() []PermissionEntry
	AppendPermission(PermissionEntry)
}

type ApprovalCache interface {
	Lookup(req MatchRequest) (outcome string, hit bool)
	Record(req MatchRequest, outcome string)
}

// DirectIdentity carries a direct request's boundary-preserving identities to the
// event log, which stores them opaquely; only this package decodes them. Both are
// empty for every non-direct request.
type DirectIdentity struct {
	CommandSubject string
	RequestSubject string
}

// Avoid import cycles with internal/config and internal/tui.
type AuthorizeDeps struct {
	Grants      GrantTable
	Cache       ApprovalCache
	Prompt      func(ctx context.Context, esc ScopeEscalation) (PromptOutcome, error)
	PromptBatch func(ctx context.Context, reqs []BatchPromptRequest) (PromptOutcome, error)
	// PromptIndependent asks the user about a group of independently authorizable requests and
	// returns an outcome per prompted request, index-aligned with reqs. It may ask one question for
	// several requests that are the same decision and fan that answer out to each of them, so the
	// number of screens shown is its own concern; this package only requires the per-request
	// outcomes, which it applies independently. Only AuthorizeIndependent uses it.
	PromptIndependent func(ctx context.Context, reqs []BatchPromptRequest) ([]PromptOutcome, error)
	PersistGrant      func(entry PermissionEntry) (PermissionEntry, error)
	// PersistGrantAt binds persistence to one request of an independent group by its index in the
	// AuthorizeIndependent input, so a failed persist degrades to that request's own path scope
	// rather than a sibling's. AuthorizeIndependent falls back to PersistGrant when it is nil.
	PersistGrantAt func(index int) func(entry PermissionEntry) (PermissionEntry, error)
	// EmitPromptShown receives the request's canonical direct tokens verbatim;
	// callers must never rebuild them from the flattened subject.
	EmitPromptShown   func(subjectKind, subject, pathScope string, directTokens []string, id DirectIdentity) error
	EmitDecision      func(subjectKind, subject, pathScope, outcome, grantKind, grantPathScope string, id DirectIdentity) error
	EmitDecisionGrant func(subjectKind, subject, pathScope, grantKind, grantPathScope, grantSubject string, id DirectIdentity) error
	EmitMatched       func(subjectKind, subject, pathScope, grantKind, grantPathScope, outcome, outcomeSource, argumentHash, directRequestSubject string) error
}

// eventSubject is the subject every permission event records. A direct request's
// MatchRequest.Subject is its request identity, so the event keeps the joined
// command tokens the pre-change contract pins.
func eventSubject(req MatchRequest) string {
	if req.Kind == subjectKindDirect && len(req.SubjectTokens) > 0 {
		return strings.Join(req.SubjectTokens, " ")
	}
	return req.Subject
}

func directIdentityOf(req MatchRequest) DirectIdentity {
	if req.Kind != subjectKindDirect || len(req.SubjectTokens) == 0 {
		return DirectIdentity{}
	}
	return DirectIdentity{
		CommandSubject: ExactSubject(req.SubjectTokens[0], req.SubjectTokens[1:]),
		RequestSubject: req.Subject,
	}
}

const (
	outcomeOnce         = "once"
	outcomeDeny         = "deny"
	outcomeSessionGrant = "session_grant"
	outcomeFolderGrant  = "folder_grant"
	outcomeGlobalGrant  = "global_grant"
)

const (
	decisionGranted = "granted"
	decisionDenied  = "denied"
)

const outcomeSourceCache = "cache"

const outcomeSourceModeAuto = "mode_auto"

const outcomeSourceOpenRead = "open_read"

// OutcomeSourceDeclaredScope is the permission_matched outcome_source a run's declared
// file scopes record, for both the approval and the terminal denial.
const OutcomeSourceDeclaredScope = "declared_scope"

// OutcomeSourceDeclaredCommand is the permission_matched outcome_source a project's declared
// command-list hit records, valid only on a non-host path record with outcome once and
// no grant fields.
const OutcomeSourceDeclaredCommand = "declared_command"

const OutcomeSourceConfined = "confined"

const (
	declaredWriteFlag  = "--files-authorized"
	declaredDeleteFlag = "--files-authorized-delete"
)

const (
	modePlan      = "plan"
	modeAutoEdits = "auto_edits"
)

const (
	toolNameEdit   = "edit"
	toolNameCreate = "create"
	toolNameMkdir  = "mkdir"
	toolNameDelete = "delete"
	toolNameMove   = "move"
	// Must stay equal to subagenttool.ToolName, which this package cannot import: subagenttool
	// imports it.
	toolNameDelegate = "delegate"
)

// Must stay equal to the delegate tool's delete-, move-, and directory-declaration arguments, for the
// same import reason.
const (
	childDeleteArg = "files_delete"
	childMoveArg   = "files_move"
	childMkdirArg  = "files_mkdir"
)

type OperationClass string

const (
	ClassReadOnly OperationClass = "read_only"
	ClassMutating OperationClass = "mutating"
)

type MovePair struct {
	Source      string
	Destination string
}

type ModeContext struct {
	Mode            string
	Class           OperationClass
	ToolName        string
	Stages          []StageNormalization
	LiteralRoute    bool
	TargetPath      string
	MoveSource      string
	MoveDestination string
	ProjectRoot     string
	// DeclaredWrite and DeclaredDelete are the run's canonical declared file scopes. A
	// non-empty pair activates the ceiling, so an empty list under an active ceiling denies
	// its operation class rather than deferring it to ordinary authorization. Under ChildAgent a nil
	// DeclaredDelete, DeclaredMoves, or DeclaredDirs is an omitted declaration and a non-nil empty one
	// was supplied empty. No codemeld run flag sets DeclaredMoves or DeclaredDirs.
	DeclaredWrite  map[string]bool
	DeclaredDelete map[string]bool
	DeclaredMoves  map[MovePair]bool
	DeclaredDirs   map[string]bool
	// ChildAgent marks the declared scopes as a child agent's delegate declaration rather than a
	// codemeld run flag pair.
	ChildAgent bool
	// ChildInvocationID identifies which child agent's calls these are, for the attribution the
	// caller's event emitters record. Nothing here reads it; authorization is unchanged by it.
	ChildInvocationID string
	// DeclaredCommands is the project's declared command list: Auto posture only, and
	// never consulted in Plan or Build.
	DeclaredCommands []DeclaredCommand
	// The Delegate forms are resolved before the grandchild starts, so the subset checks against the
	// declared forms are an authorization decision rather than a report on a running child.
	DelegateWrite  map[string]bool
	DelegateDelete map[string]bool
	DelegateMoves  map[MovePair]bool
	DelegateDirs   map[string]bool
	OpenRead       bool
	ExternalRead   bool
	ShellPathAsk   bool
	NetworkEgress  bool
	// ExecutionConstrained is the launch self-test result, not the displayed capability label.
	ExecutionConstrained bool
	SettingsBroken       bool
	WritableFolders      []string
}

type Decision struct {
	Outcome      string
	Grant        *PermissionEntry
	DenyEnvelope string
	// DenyReason and DenialSource describe a denial this package decided without a prompt,
	// so a caller can classify it without reading the envelope text. Both stay empty for an
	// allow and for a denial the prompt outcome supplied.
	DenyReason   string
	DenialSource string
	// ReadOnlyAuto marks the one allow the active mode granted because the request classified
	// read-only. A prompt, a grant, a cache hit, a declared-scope allow, and every other mode
	// posture leave it false.
	ReadOnlyAuto bool
	PersistErr   error
	// WrapUp is never set by Authorize: a caller's authorizer sets it on a refusal after which the
	// turn must end with one tool-less answer round.
	WrapUp bool
}

// CacheIdentity returns the comparable key under which the turn cache records req's outcome.
func CacheIdentity(req MatchRequest) any { return turnCacheKeyOf(req) }

func Authorize(ctx context.Context, req MatchRequest, modeCtx ModeContext, deps AuthorizeDeps) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if err := checkFreshConfirmation(req); err != nil {
		return Decision{}, err
	}

	if !req.FreshConfirmation {
		if dec, resolved, err := resolveWithoutPrompt(req, modeCtx, deps); resolved {
			return dec, err
		}
	}

	return promptFlow(ctx, req, deps)
}

func resolveWithoutPrompt(req MatchRequest, modeCtx ModeContext, deps AuthorizeDeps) (Decision, bool, error) {
	if req.Kind == subjectKindTool && topLevelDelegate(modeCtx) {
		dec, err := topLevelDelegateRefusal(req, modeCtx, deps)
		return dec, true, err
	}
	if dec, handled, err := declaredScopePosture(req, modeCtx, deps); handled {
		return dec, true, err
	}

	if modeCtx.OpenRead {
		argHash := matchArgumentHash(req.Kind, PermissionEntry{Subject: req.Subject})
		if err := deps.EmitMatched(req.Kind, eventSubject(req), req.PathScope,
			"", "", outcomeOnce, outcomeSourceOpenRead, argHash, directIdentityOf(req).RequestSubject); err != nil {
			return Decision{}, true, err
		}
		return Decision{Outcome: outcomeOnce}, true, nil
	}

	if modeCtx.SettingsBroken && confinedShell(req, modeCtx) && (modeCtx.Mode == modePlan || modeCtx.Mode == modeAutoEdits) {
		if outcome, hit := deps.Cache.Lookup(req); hit && outcome == outcomeDeny {
			dec, err := cacheHit(req, outcome, deps)
			return dec, true, err
		}
		return Decision{}, false, nil
	}

	if dec, handled, err := modePosture(req, modeCtx, deps); handled {
		return dec, true, err
	}

	if modeCtx.Mode == modeAutoEdits && confinedShell(req, modeCtx) {
		if authority, _ := ClassifyExceptional(req, modeCtx); authority != "" {
			return Decision{}, false, nil
		}
	}

	if res := Match(req, deps.Grants.Permissions()); res.Matched {
		grant := res.Grant
		outcome := grantOutcome(grant.GrantKind)
		if err := deps.EmitMatched(req.Kind, grantEventSubject(req, grant.Subject), eventScope(req),
			grant.GrantKind, grantEventScope(*grant), outcome, outcomeSourceGrant,
			matchArgumentHash(req.Kind, *grant), directIdentityOf(req).RequestSubject); err != nil {
			return Decision{}, true, err
		}
		return Decision{Outcome: outcome, Grant: grant}, true, nil
	}

	if outcome, hit := deps.Cache.Lookup(req); hit {
		dec, err := cacheHit(req, outcome, deps)
		return dec, true, err
	}

	return Decision{}, false, nil
}

type BatchRequest struct {
	Req     MatchRequest
	ModeCtx ModeContext
}

type BatchPromptRequest struct {
	Req        MatchRequest
	Escalation ScopeEscalation
	// Index is the stage's position in the AuthorizeBatch input.
	Index int
}

func AuthorizeBatch(ctx context.Context, reqs []BatchRequest, deps AuthorizeDeps) ([]Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, r := range reqs {
		if r.Req.FreshConfirmation {
			return nil, errors.New("permissions: fresh confirmation is not valid in batch authorization")
		}
	}

	decisions := make([]Decision, len(reqs))
	var unresolved []int
	for i, r := range reqs {
		dec, resolved, err := resolveWithoutPrompt(r.Req, r.ModeCtx, deps)
		if err != nil {
			return nil, err
		}
		if !resolved {
			unresolved = append(unresolved, i)
			continue
		}
		decisions[i] = dec
		if dec.Outcome == outcomeDeny {
			break
		}
	}
	if len(unresolved) == 0 {
		return decisions, nil
	}

	prompts := make([]BatchPromptRequest, len(unresolved))
	for j, idx := range unresolved {
		req := reqs[idx].Req
		if err := deps.EmitPromptShown(req.Kind, eventSubject(req), eventScope(req), req.SubjectTokens, directIdentityOf(req)); err != nil {
			return nil, err
		}
		prompts[j] = BatchPromptRequest{Req: req, Escalation: FindScopeEscalation(req, deps.Grants.Permissions()), Index: idx}
	}

	outcome, err := deps.PromptBatch(ctx, prompts)
	if err != nil {
		return nil, err
	}

	for _, idx := range unresolved {
		stageOutcome := outcome
		// A shared approval cannot select a scope for every unresolved stage.
		if len(unresolved) > 1 {
			switch stageOutcome.Choice {
			case PromptAllowSession, PromptAllowFolder, PromptAllowGlobal:
				stageOutcome.StoredSubject = ""
			}
		}
		dec, err := applyOutcome(reqs[idx].Req, stageOutcome, deps)
		if err != nil {
			return nil, err
		}
		decisions[idx] = dec
	}
	return decisions, nil
}

// AuthorizeIndependent authorizes a group of requests that are independently authorizable: each
// resolves on its own, so a denial never stops a sibling, and the requests that still need a
// decision are gathered into one prompt returning an outcome per request. Each request keeps its
// own subject, decision, grant, persistence scope, and deny envelope. A prompt error — a
// cancellation or a transport failure — resolves nothing, so no caller may run any member.
// AuthorizeBatch stays the direct-pipeline path, where one outcome covers every stage and a deny
// stops the pipeline.
func AuthorizeIndependent(ctx context.Context, reqs []BatchRequest, deps AuthorizeDeps) ([]Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, r := range reqs {
		if r.Req.FreshConfirmation {
			return nil, errors.New("permissions: fresh confirmation is not valid in independent authorization")
		}
	}

	decisions := make([]Decision, len(reqs))
	var unresolved []int
	for i, r := range reqs {
		dec, resolved, err := resolveWithoutPrompt(r.Req, r.ModeCtx, deps)
		if err != nil {
			return nil, err
		}
		if !resolved {
			unresolved = append(unresolved, i)
			continue
		}
		decisions[i] = dec
	}
	if len(unresolved) == 0 {
		return decisions, nil
	}

	prompts := make([]BatchPromptRequest, len(unresolved))
	for j, idx := range unresolved {
		req := reqs[idx].Req
		if err := deps.EmitPromptShown(req.Kind, eventSubject(req), eventScope(req), req.SubjectTokens, directIdentityOf(req)); err != nil {
			return nil, err
		}
		prompts[j] = BatchPromptRequest{Req: req, Escalation: FindScopeEscalation(req, deps.Grants.Permissions()), Index: idx}
	}

	outcomes, err := deps.PromptIndependent(ctx, prompts)
	if err != nil {
		return nil, err
	}
	// The production prompt bridge blocks in a non-context-aware TUI call, so a cancellation
	// that lands while the group prompt is open surfaces only here.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(outcomes) != len(prompts) {
		return nil, fmt.Errorf("permissions: independent prompt returned %d outcomes for %d requests", len(outcomes), len(prompts))
	}

	for j, idx := range unresolved {
		reqDeps := deps
		if deps.PersistGrantAt != nil {
			reqDeps.PersistGrant = deps.PersistGrantAt(idx)
		}
		dec, err := applyOutcome(reqs[idx].Req, outcomes[j], reqDeps)
		if err != nil {
			return nil, err
		}
		decisions[idx] = dec
	}
	return decisions, nil
}

func cacheHit(req MatchRequest, outcome string, deps AuthorizeDeps) (Decision, error) {
	grantKind, grantScope := "", ""
	argHash := matchArgumentHash(req.Kind, PermissionEntry{Subject: req.Subject})
	if outcome != outcomeOnce && outcome != outcomeDeny {
		grantKind = strings.TrimSuffix(outcome, "_grant")
		grantScope = grantScopeFor(grantKind, eventScope(req))
	}
	if err := deps.EmitMatched(req.Kind, eventSubject(req), eventScope(req),
		grantKind, grantScope, outcome, outcomeSourceCache, argHash, directIdentityOf(req).RequestSubject); err != nil {
		return Decision{}, err
	}
	d := Decision{Outcome: outcome}
	if outcome == outcomeDeny {
		d.DenyEnvelope = BuildDenyEnvelope("")
		d.DenyReason = defaultDenyReason
		d.DenialSource = outcomeSourceCache
	}
	return d, nil
}

func promptFlow(ctx context.Context, req MatchRequest, deps AuthorizeDeps) (Decision, error) {
	if err := deps.EmitPromptShown(req.Kind, eventSubject(req), eventScope(req), req.SubjectTokens, directIdentityOf(req)); err != nil {
		return Decision{}, err
	}
	esc := FindScopeEscalation(req, deps.Grants.Permissions())
	outcome, err := deps.Prompt(ctx, esc)
	if err != nil {
		return Decision{}, err
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	return applyOutcome(req, outcome, deps)
}

func applyOutcome(req MatchRequest, outcome PromptOutcome, deps AuthorizeDeps) (Decision, error) {
	if req.FreshConfirmation && outcome.Choice != PromptAllowOnce && outcome.Choice != PromptDeny {
		return Decision{}, fmt.Errorf("permissions: a fresh confirmation accepts only allow once or deny, not prompt choice %d", outcome.Choice)
	}
	switch outcome.Choice {
	case PromptAllowOnce:
		return allowOnce(req, deps)
	case PromptDeny:
		return deny(req, outcome, deps)
	case PromptAllowSession:
		return grant(req, grantKindSession, outcome, deps)
	case PromptAllowFolder:
		return grant(req, grantKindFolder, outcome, deps)
	case PromptAllowGlobal:
		return grant(req, grantKindGlobal, outcome, deps)
	case PromptAllowProject:
		return grant(req, grantKindProject, outcome, deps)
	default:
		return Decision{}, fmt.Errorf("permissions: unknown prompt choice %d", outcome.Choice)
	}
}

func isConcreteTargetMutation(req MatchRequest) bool {
	return req.Kind == subjectKindTool && (req.Subject == toolNameDelete || req.Subject == toolNameMove)
}

func isCacheableOutcome(req MatchRequest) bool {
	return !req.FreshConfirmation && !isConcreteTargetMutation(req)
}

func allowOnce(req MatchRequest, deps AuthorizeDeps) (Decision, error) {
	if isCacheableOutcome(req) {
		deps.Cache.Record(req, outcomeOnce)
	}
	if err := deps.EmitDecision(req.Kind, eventSubject(req), eventScope(req), decisionGranted, "", "", directIdentityOf(req)); err != nil {
		return Decision{}, err
	}
	return Decision{Outcome: outcomeOnce}, nil
}

func deny(req MatchRequest, outcome PromptOutcome, deps AuthorizeDeps) (Decision, error) {
	if isCacheableOutcome(req) {
		deps.Cache.Record(req, outcomeDeny)
	}
	if err := deps.EmitDecision(req.Kind, eventSubject(req), eventScope(req), decisionDenied, "", "", directIdentityOf(req)); err != nil {
		return Decision{}, err
	}
	env := outcome.DenyEnvelope
	if env == "" {
		env = BuildDenyEnvelope("")
	}
	return Decision{Outcome: outcomeDeny, DenyEnvelope: env}, nil
}

func grant(req MatchRequest, grantKind string, outcome PromptOutcome, deps AuthorizeDeps) (Decision, error) {
	if err := checkGrantLifetime(req, grantKind); err != nil {
		return Decision{}, err
	}
	entry := buildGrant(req, grantKind, outcome.StoredSubject)
	cacheOutcome := grantOutcome(grantKind)
	deps.Cache.Record(req, cacheOutcome)

	if err := deps.EmitDecisionGrant(req.Kind, eventSubject(req), eventScope(req),
		grantKind, grantEventScope(entry), entry.Subject, directIdentityOf(req)); err != nil {
		return Decision{}, err
	}

	d := Decision{Outcome: cacheOutcome}
	if grantKind != grantKindSession {
		entry, d.PersistErr = deps.PersistGrant(entry)
	}
	deps.Grants.AppendPermission(entry)
	d.Grant = &entry
	return d, nil
}

func checkGrantLifetime(req MatchRequest, grantKind string) error {
	isHost := req.Kind == subjectKindHost
	switch grantKind {
	case grantKindFolder, grantKindGlobal:
		if isHost {
			return fmt.Errorf("permissions: %s grant is not valid for a host request", grantKind)
		}
	case grantKindProject:
		if !isHost {
			return fmt.Errorf("permissions: %s grant is only valid for a host request", grantKind)
		}
	}
	return nil
}

func eventScope(req MatchRequest) string {
	if req.Kind == subjectKindHost {
		return req.Host
	}
	return req.PathScope
}

func grantEventScope(entry PermissionEntry) string {
	if entry.HostScope != "" {
		return entry.HostScope
	}
	return entry.PathScope
}

func grantEventSubject(req MatchRequest, grantSubject string) string {
	if IsCapabilitySubject(grantSubject) || isCompoundSubject(grantSubject) {
		return grantSubject
	}
	return eventSubject(req)
}

func buildGrant(req MatchRequest, grantKind, storedSubject string) PermissionEntry {
	if req.Kind == subjectKindHost {
		return PermissionEntry{
			Kind:      subjectKindTool,
			Subject:   req.Subject,
			HostScope: req.Host,
			GrantKind: grantKind,
		}
	}
	subject := storedSubject
	if subject == "" {
		subject = req.Subject
	}
	// A batch fallback already carries the encoded request identity; a chooser
	// subject is command-only, so the request's ordered assignments and clear-environment
	// state are wrapped around it. An unencodable pair falls back to the exact request
	// identity rather than storing a subject broader than the prompt displayed.
	if req.Kind == subjectKindDirect && (len(req.Assignments) > 0 || req.ClearEnvironment) && !isDirectEnvSubject(subject) {
		encoded, err := EncodeDirectEnvSubject(req.Assignments, req.ClearEnvironment, subject)
		if err != nil {
			encoded = req.Subject
		}
		subject = encoded
	}
	entry := PermissionEntry{
		Kind:      req.Kind,
		Subject:   subject,
		PathScope: grantScopeFor(grantKind, req.PathScope),
		GrantKind: grantKind,
	}
	if req.Kind == subjectKindLiteral {
		entry.ArgumentHash = ComputeArgumentHash(subject)
	}
	return entry
}

func grantOutcome(grantKind string) string {
	return grantKind + "_grant"
}

func grantScopeFor(grantKind, requestPath string) string {
	if grantKind == grantKindGlobal {
		return allPathsScope
	}
	return requestPath
}

func matchArgumentHash(reqKind string, grant PermissionEntry) string {
	if reqKind != subjectKindLiteral {
		return ""
	}
	if grant.ArgumentHash != "" {
		return grant.ArgumentHash
	}
	return ComputeArgumentHash(grant.Subject)
}

func planOperationClass(req MatchRequest, mc ModeContext) OperationClass {
	if req.Kind == subjectKindDirect || req.Kind == subjectKindLiteral {
		return classifyReadOnlyShell(req, mc)
	}
	return mc.Class
}

func modePosture(req MatchRequest, mc ModeContext, deps AuthorizeDeps) (Decision, bool, error) {
	if mc.Mode == "" {
		return Decision{}, false, nil
	}
	if req.Kind == subjectKindHost {
		return Decision{}, false, nil
	}
	if confinedShell(req, mc) {
		switch mc.Mode {
		case modePlan:
			return planPosture(req, mc, deps)
		case modeAutoEdits:
			return autoEditsPosture(req, mc, deps)
		}
	}
	if mc.ExternalRead || mc.ShellPathAsk {
		return Decision{}, false, nil
	}
	if mc.NetworkEgress {
		return Decision{}, false, nil
	}
	if planOperationClass(req, mc) == ClassReadOnly {
		if err := emitModeAuto(req, deps, outcomeOnce); err != nil {
			return Decision{}, true, err
		}
		return Decision{Outcome: outcomeOnce, ReadOnlyAuto: true}, true, nil
	}
	switch mc.Mode {
	case modePlan:
		return planPosture(req, mc, deps)
	case modeAutoEdits:
		return autoEditsPosture(req, mc, deps)
	default:
		return Decision{}, false, nil
	}
}

func planPosture(req MatchRequest, mc ModeContext, deps AuthorizeDeps) (Decision, bool, error) {
	if confinedShell(req, mc) {
		if err := emitConfined(req, deps); err != nil {
			return Decision{}, true, err
		}
		return Decision{Outcome: outcomeOnce}, true, nil
	}
	if err := emitModeAuto(req, deps, outcomeDeny); err != nil {
		return Decision{}, true, err
	}
	reason := modeDenyReason(req, mc)
	return Decision{
		Outcome:      outcomeDeny,
		DenyEnvelope: BuildModeDenyEnvelope(reason),
		DenyReason:   reason,
		DenialSource: outcomeSourceModeAuto,
	}, true, nil
}

func modeDenyReason(req MatchRequest, mc ModeContext) string {
	base := fmt.Sprintf("%s mode is read-only; this command is classified as mutating", mc.Mode)
	if req.Kind != subjectKindDirect && req.Kind != subjectKindLiteral {
		return base
	}
	if namesLinuxTop(req, mc) {
		return base + "; automatic permission for top requires batch mode (-b) and a bounded positive" +
			" iteration count (-n), for example top -b -n 1 — an interactive or unbounded form is never allowed"
	}
	return base + "; do not use " + blockedShellShape(eventSubject(req)) +
		" — issue separate read/glob tool calls or simple read-only shell commands (for example ls, cat, rg, hg status) instead"
}

func namesLinuxTop(req MatchRequest, mc ModeContext) bool {
	policy, ok := commandPolicies["top"]
	if !ok || !policy.appliesToPlatform() {
		return false
	}
	if req.Kind != subjectKindDirect || len(mc.Stages) != 1 {
		return false
	}
	stage := mc.Stages[0]
	return stage.Route == RouteDirect && len(stage.Tokens) > 0 && stage.Tokens[0] == "top"
}

func blockedShellShape(command string) string {
	switch {
	case hasShellLoop(command):
		return "shell loops"
	case hasShellWrapper(command):
		return "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs"
	case strings.Contains(command, "$(") || strings.Contains(command, "`"):
		return "command substitution"
	case strings.ContainsAny(command, "<>"):
		return "shell redirection"
	case hasMixedPipeControlFlow(command):
		return "a pipe combined with ;, &&, or || control-flow separators in one command"
	case hasSeparatorEchoBlock(command):
		return "echo separator blocks"
	default:
		return "mutating shell commands"
	}
}

func hasShellWrapper(command string) bool {
	mask, err := bareMask(command)
	if err != nil {
		return hasShellWrapperStage(command)
	}
	start := 0
	for i := 0; i < len(command); i++ {
		if !mask[i] {
			continue
		}
		switch command[i] {
		case '|':
			if hasShellWrapperStage(command[start:i]) {
				return true
			}
			if i+1 < len(command) && command[i+1] == '|' {
				i++
			}
			start = i + 1
		case ';':
			if hasShellWrapperStage(command[start:i]) {
				return true
			}
			start = i + 1
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				if hasShellWrapperStage(command[start:i]) {
					return true
				}
				i++
				start = i + 1
			}
		}
	}
	return hasShellWrapperStage(command[start:])
}

func hasShellWrapperStage(stage string) bool {
	tokens, err := tokenizeShell(strings.TrimSpace(stage))
	if err != nil {
		return false
	}
	first := 0
	for first < len(tokens) && isEnvAssignment(tokens[first]) {
		first++
	}
	if first == len(tokens) {
		return false
	}
	return wrapperPrograms[filepath.Base(tokens[first].Value)]
}

func hasSeparatorEchoBlock(command string) bool {
	stages := controlFlowStages(command)
	if len(stages) < 2 {
		return false
	}
	for _, stage := range stages {
		if fields := strings.Fields(stage); len(fields) > 0 && fields[0] == "echo" {
			return true
		}
	}
	return false
}

func controlFlowStages(command string) []string {
	var stages []string
	start := 0
	for i := 0; i < len(command); i++ {
		switch command[i] {
		case ';':
			stages = append(stages, command[start:i])
			start = i + 1
		case '&', '|':
			if i+1 < len(command) && command[i+1] == command[i] {
				stages = append(stages, command[start:i])
				i++
				start = i + 1
			}
		}
	}
	return append(stages, command[start:])
}

func hasMixedPipeControlFlow(command string) bool {
	hasPipe, hasAnd, hasOr, hasSemicolon := false, false, false, false
	for i := 0; i < len(command); i++ {
		switch command[i] {
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				hasAnd = true
				i++
			}
		case '|':
			if i+1 < len(command) && command[i+1] == '|' {
				hasOr = true
				i++
			} else {
				hasPipe = true
			}
		case ';':
			hasSemicolon = true
		}
	}
	return hasPipe && (hasAnd || hasOr || hasSemicolon)
}

func hasShellLoop(command string) bool {
	head, body := false, false
	sep := func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '&', '|':
			return true
		}
		return false
	}
	for _, tok := range strings.FieldsFunc(command, sep) {
		switch tok {
		case "for", "while", "until":
			head = true
		case "do", "done":
			body = true
		}
	}
	return head && body
}

func autoEditsPosture(req MatchRequest, mc ModeContext, deps AuthorizeDeps) (Decision, bool, error) {
	if isInScopeFileTool(req, mc) || inWritableFolder(req, mc) {
		if err := emitModeAuto(req, deps, outcomeOnce); err != nil {
			return Decision{}, true, err
		}
		return Decision{Outcome: outcomeOnce}, true, nil
	}
	if confinedShell(req, mc) {
		if authority, ok := ClassifyExceptional(req, mc); authority != "" || !ok {
			return Decision{}, false, nil
		}
		if err := emitConfined(req, deps); err != nil {
			return Decision{}, true, err
		}
		return Decision{Outcome: outcomeOnce}, true, nil
	}
	return declaredCommandPosture(req, mc, deps)
}

func inWritableFolder(req MatchRequest, mc ModeContext) bool {
	if !mc.ExecutionConstrained || req.Kind != subjectKindTool {
		return false
	}
	if mc.ToolName != toolNameEdit && mc.ToolName != toolNameCreate && mc.ToolName != toolNameMkdir {
		return false
	}
	return slices.ContainsFunc(mc.WritableFolders, func(root string) bool { return isInProject(mc.TargetPath, root) })
}

// Direct route only: matching a declared prefix against a literal subject would authorize an
// arbitrary tail, which is what the literal route exists to prevent. A hit is a
// mode-posture allow, so it stores no grant and caches nothing.
func declaredCommandPosture(req MatchRequest, mc ModeContext, deps AuthorizeDeps) (Decision, bool, error) {
	if req.Kind != subjectKindDirect || len(req.SubjectTokens) == 0 || len(mc.DeclaredCommands) == 0 {
		return Decision{}, false, nil
	}
	if !MatchesDeclaredCommand(req.SubjectTokens, req.Assignments, req.ClearEnvironment, mc.DeclaredCommands) {
		return Decision{}, false, nil
	}
	if err := emitDeclaredCommand(req, deps); err != nil {
		return Decision{}, true, err
	}
	return Decision{Outcome: outcomeOnce}, true, nil
}

func emitDeclaredCommand(req MatchRequest, deps AuthorizeDeps) error {
	argHash := matchArgumentHash(req.Kind, PermissionEntry{Subject: req.Subject})
	return deps.EmitMatched(req.Kind, eventSubject(req), req.PathScope,
		"", "", outcomeOnce, OutcomeSourceDeclaredCommand, argHash, directIdentityOf(req).RequestSubject)
}

func isInScopeFileTool(req MatchRequest, mc ModeContext) bool {
	if req.Kind != subjectKindTool || !isAutoEditsTool(mc.ToolName) {
		return false
	}
	if mc.ProjectRoot == "" {
		return false
	}
	if mc.ToolName == toolNameMove {
		return isInProject(mc.MoveSource, mc.ProjectRoot) && isInProject(mc.MoveDestination, mc.ProjectRoot)
	}
	return isInProject(mc.TargetPath, mc.ProjectRoot)
}

func isInProject(path, root string) bool {
	return path != "" && IsDescendantOrEqual(path, root)
}

func isAutoEditsTool(name string) bool {
	return name == toolNameEdit || name == toolNameCreate || name == toolNameMkdir || name == toolNameMove
}

func confinedShell(req MatchRequest, mc ModeContext) bool {
	return mc.ExecutionConstrained && (req.Kind == subjectKindDirect || req.Kind == subjectKindLiteral)
}

func emitConfined(req MatchRequest, deps AuthorizeDeps) error {
	argHash := matchArgumentHash(req.Kind, PermissionEntry{Subject: req.Subject})
	return deps.EmitMatched(req.Kind, eventSubject(req), req.PathScope,
		"", "", outcomeOnce, OutcomeSourceConfined, argHash, directIdentityOf(req).RequestSubject)
}

func emitModeAuto(req MatchRequest, deps AuthorizeDeps, outcome string) error {
	argHash := matchArgumentHash(req.Kind, PermissionEntry{Subject: req.Subject})
	return deps.EmitMatched(req.Kind, eventSubject(req), req.PathScope,
		"", "", outcome, outcomeSourceModeAuto, argHash, directIdentityOf(req).RequestSubject)
}

// declaredScopePosture answers every write tool from the run's declared file scopes — and, for a
// child agent, the delegate tool as well — returning handled for the denial as well as the
// approval so an uncovered target can never fall through to a grant, the turn cache, Auto edits,
// or the prompt. Plan is skipped so planPosture stays the sole authority there.
func declaredScopePosture(req MatchRequest, mc ModeContext, deps AuthorizeDeps) (Decision, bool, error) {
	if !declaredScopeActive(mc) || mc.Mode == modePlan {
		return Decision{}, false, nil
	}
	if req.Kind != subjectKindTool || !isDeclaredScopeTool(mc) {
		return Decision{}, false, nil
	}
	if declaredScopeCovers(mc) {
		// A parent run's file declaration bounds a child agent but never grants permission to start
		// one, so a covered top-level delegate call records no approval of its own.
		if topLevelDelegate(mc) {
			return Decision{}, false, nil
		}
		if err := emitDeclaredScope(req, deps, outcomeOnce); err != nil {
			return Decision{}, true, err
		}
		return Decision{Outcome: outcomeOnce}, true, nil
	}
	if err := emitDeclaredScope(req, deps, outcomeDeny); err != nil {
		return Decision{}, true, err
	}
	reason := declaredScopeDenyReason(mc)
	return Decision{
		Outcome:      outcomeDeny,
		DenyEnvelope: BuildDenyEnvelope(reason),
		DenyReason:   reason,
		DenialSource: OutcomeSourceDeclaredScope,
	}, true, nil
}

// The allow returned here is not an approval: the caller still authorizes each operation the
// delegate declares, so no grant, cache entry, or prompt for the tool delegate is ever consulted.
func topLevelDelegateRefusal(req MatchRequest, mc ModeContext, deps AuthorizeDeps) (Decision, error) {
	posture := declaredScopePosture
	if mc.Mode == modePlan {
		posture = modePosture
	}
	if dec, handled, err := posture(req, mc, deps); handled {
		return dec, err
	}
	return Decision{Outcome: outcomeOnce}, nil
}

// A child agent is under a ceiling whatever its lists hold, so a child that reached authorization
// with no resolvable declaration denies rather than falling through to a grant or the prompt.
func declaredScopeActive(mc ModeContext) bool {
	return mc.ChildAgent || len(mc.DeclaredWrite) > 0 || len(mc.DeclaredDelete) > 0
}

func isDeclaredScopeTool(mc ModeContext) bool {
	switch mc.ToolName {
	case toolNameEdit, toolNameCreate, toolNameDelete, toolNameMkdir, toolNameMove:
		return true
	case toolNameDelegate:
		// A top-level call is judged only once dispatch has prepared its candidate.
		return mc.ChildAgent || len(mc.DelegateWrite) > 0 || len(mc.DelegateDelete) > 0 || len(mc.DelegateMoves) > 0 || len(mc.DelegateDirs) > 0
	}
	return false
}

func topLevelDelegate(mc ModeContext) bool {
	return mc.ToolName == toolNameDelegate && !mc.ChildAgent
}

func declaredScopeCovers(mc ModeContext) bool {
	switch mc.ToolName {
	case toolNameEdit, toolNameCreate:
		return mc.TargetPath != "" && mc.DeclaredWrite[mc.TargetPath]
	case toolNameDelete:
		return mc.TargetPath != "" && mc.DeclaredDelete[mc.TargetPath]
	case toolNameMkdir:
		return mc.ChildAgent && mc.TargetPath != "" && mc.DeclaredDirs[mc.TargetPath]
	case toolNameMove:
		return mc.ChildAgent && mc.DeclaredMoves[MovePair{Source: mc.MoveSource, Destination: mc.MoveDestination}]
	case toolNameDelegate:
		return delegateWithinParent(mc)
	}
	return false
}

// A resolved delegate declaration always names a path, so a candidate empty in every form is one that
// did not resolve and fails rather than passing as the empty subset.
func delegateWithinParent(mc ModeContext) bool {
	if len(mc.DelegateWrite) == 0 && len(mc.DelegateDelete) == 0 && len(mc.DelegateMoves) == 0 && len(mc.DelegateDirs) == 0 {
		return false
	}
	return isDeclaredSubset(mc.DelegateWrite, mc.DeclaredWrite) && isDeclaredSubset(mc.DelegateDelete, mc.DeclaredDelete) &&
		isDeclaredSubset(mc.DelegateMoves, mc.DeclaredMoves) && isDeclaredSubset(mc.DelegateDirs, mc.DeclaredDirs)
}

func isDeclaredSubset[K comparable](nested, parent map[K]bool) bool {
	for path := range nested {
		if !parent[path] {
			return false
		}
	}
	return true
}

// declaredScopeDenyReason orders the fixed classification facts ahead of the escaped canonical
// target, so the deny envelope's 512-byte cap can only ever truncate path detail.
func declaredScopeDenyReason(mc ModeContext) string {
	if mc.ChildAgent {
		return childScopeDenyReason(mc)
	}
	if mc.ToolName == toolNameDelegate {
		return topLevelDelegateDenyReason(mc)
	}
	parts := []string{
		"a declared-scope ceiling is active for this run and only declared paths may be written",
		declaredScopeListClause(mc),
	}
	if len(mc.DeclaredWrite) > 0 && len(mc.DeclaredDelete) > 0 {
		parts = append(parts, "this run was started with "+declaredWriteFlag+" and "+declaredDeleteFlag)
	}
	return strings.Join(append(parts,
		"the ceiling cannot widen during the run",
		declaredScopeTargetClause(mc),
	), "; ")
}

// topLevelDelegateDenyReason keeps declaredScopeDenyReason's classification-first ordering, so the
// deny envelope's 512-byte cap can only ever truncate path detail.
func topLevelDelegateDenyReason(mc ModeContext) string {
	if delegateWidensOnlyMoves(mc) {
		return strings.Join([]string{
			"a declared-scope ceiling is active for this run and a child agent may declare no move pairs",
			"neither " + declaredWriteFlag + " nor " + declaredDeleteFlag + " can authorize " + childMoveArg,
			"the ceiling cannot widen during the run",
			childScopeTargetClause(mc),
		}, "; ")
	}
	if delegateWidensOnlyDirs(mc) {
		return strings.Join([]string{
			"a declared-scope ceiling is active for this run and a child agent may declare no directories",
			"neither " + declaredWriteFlag + " nor " + declaredDeleteFlag + " can authorize " + childMkdirArg,
			"the ceiling cannot widen during the run",
			childScopeTargetClause(mc),
		}, "; ")
	}
	form, flag, parent := "write", declaredWriteFlag, mc.DeclaredWrite
	if delegateWidensOnlyDelete(mc) {
		form, flag, parent = "delete", declaredDeleteFlag, mc.DeclaredDelete
	}
	return strings.Join([]string{
		"a declared-scope ceiling is active for this run and a child agent may declare only " + form + " paths it already lists",
		topLevelDelegateListClause(flag, form, len(parent) > 0),
		"the ceiling cannot widen during the run",
		childScopeTargetClause(mc),
	}, "; ")
}

func topLevelDelegateListClause(flag, form string, present bool) string {
	if !present {
		return flag + " was not supplied"
	}
	return flag + " was supplied but does not list every child " + form + " path this call declared"
}

func delegateWidensOnlyDelete(mc ModeContext) bool {
	return len(undeclaredPaths(mc.DelegateWrite, mc.DeclaredWrite)) == 0 &&
		len(undeclaredPaths(mc.DelegateDelete, mc.DeclaredDelete)) > 0
}

func declaredScopeListClause(mc ModeContext) string {
	switch mc.ToolName {
	case toolNameEdit, toolNameCreate:
		return declaredListState(declaredWriteFlag, len(mc.DeclaredWrite) > 0)
	case toolNameDelete:
		return declaredListState(declaredDeleteFlag, len(mc.DeclaredDelete) > 0)
	default:
		return "neither " + declaredWriteFlag + " nor " + declaredDeleteFlag + " can authorize " + mc.ToolName
	}
}

func declaredListState(flag string, present bool) string {
	if !present {
		return flag + " was not supplied"
	}
	return flag + " was supplied but does not list this target"
}

func declaredScopeTargetClause(mc ModeContext) string {
	if mc.ToolName == toolNameMove {
		return "source=" + strconv.Quote(mc.MoveSource) + "; destination=" + strconv.Quote(mc.MoveDestination)
	}
	return "target=" + strconv.Quote(mc.TargetPath)
}

// childScopeDenyReason keeps declaredScopeDenyReason's classification-first ordering, so the deny
// envelope's 512-byte cap can only ever truncate path detail.
func childScopeDenyReason(mc ModeContext) string {
	return strings.Join([]string{
		"a child agent may touch only the paths its delegate call declared",
		childScopeFormClause(mc),
		"the child declaration cannot widen while the child runs",
		childScopeTargetClause(mc),
	}, "; ")
}

func childScopeFormClause(mc ModeContext) string {
	switch mc.ToolName {
	case toolNameDelete:
		return childDeleteFormClause(mc.DeclaredDelete)
	case toolNameMkdir:
		return childDirFormClause(mc.DeclaredDirs)
	case toolNameMove:
		return childMoveFormClause(mc.DeclaredMoves)
	case toolNameDelegate:
		switch {
		case delegateWidensOnlyDelete(mc):
			return "a nested delegate call may declare in " + childDeleteArg + " only delete paths its own parent already declared"
		case delegateWidensOnlyMoves(mc):
			return "a nested delegate call may declare in " + childMoveArg + " only whole move pairs its own parent already declared"
		case delegateWidensOnlyDirs(mc):
			return "a nested delegate call may declare in " + childMkdirArg + " only directories its own parent already declared"
		}
		return "a nested delegate call may declare only write paths its own parent already declared"
	default:
		return "the child's declared write paths do not list this target"
	}
}

func childDeleteFormClause(declared map[string]bool) string {
	switch {
	case declared == nil:
		return "this delegate call did not supply " + childDeleteArg
	case len(declared) == 0:
		return "this delegate call supplied an empty " + childDeleteArg
	default:
		return "this delegate call's " + childDeleteArg + " does not list this target"
	}
}

func childDirFormClause(declared map[string]bool) string {
	switch {
	case declared == nil:
		return "this delegate call did not supply " + childMkdirArg
	case len(declared) == 0:
		return "this delegate call supplied an empty " + childMkdirArg
	default:
		return "this delegate call's " + childMkdirArg + " does not list this directory"
	}
}

func childScopeTargetClause(mc ModeContext) string {
	if mc.ToolName != toolNameDelegate {
		return declaredScopeTargetClause(mc)
	}
	write := undeclaredPaths(mc.DelegateWrite, mc.DeclaredWrite)
	remove := undeclaredPaths(mc.DelegateDelete, mc.DeclaredDelete)
	moves := undeclaredMoves(mc.DelegateMoves, mc.DeclaredMoves)
	dirs := undeclaredPaths(mc.DelegateDirs, mc.DeclaredDirs)
	var clauses []string
	if len(write) > 0 || (len(remove) == 0 && len(moves) == 0 && len(dirs) == 0) {
		clauses = append(clauses, "undeclared="+strconv.Quote(strings.Join(write, " ")))
	}
	if len(remove) > 0 {
		clauses = append(clauses, "undeclared_delete="+strconv.Quote(strings.Join(remove, " ")))
	}
	if len(moves) > 0 {
		clauses = append(clauses, "undeclared_move="+strconv.Quote(strings.Join(moves, ", ")))
	}
	if len(dirs) > 0 {
		clauses = append(clauses, "undeclared_mkdir="+strconv.Quote(strings.Join(dirs, " ")))
	}
	return strings.Join(clauses, "; ")
}

func childMoveFormClause(declared map[MovePair]bool) string {
	switch {
	case declared == nil:
		return "this delegate call did not supply " + childMoveArg
	case len(declared) == 0:
		return "this delegate call supplied an empty " + childMoveArg
	default:
		return "this delegate call's " + childMoveArg + " does not declare this source and destination as one pair"
	}
}

func delegateWidensOnlyMoves(mc ModeContext) bool {
	return len(undeclaredPaths(mc.DelegateWrite, mc.DeclaredWrite)) == 0 &&
		len(undeclaredPaths(mc.DelegateDelete, mc.DeclaredDelete)) == 0 &&
		len(undeclaredMoves(mc.DelegateMoves, mc.DeclaredMoves)) > 0
}

func delegateWidensOnlyDirs(mc ModeContext) bool {
	return len(undeclaredPaths(mc.DelegateWrite, mc.DeclaredWrite)) == 0 &&
		len(undeclaredPaths(mc.DelegateDelete, mc.DeclaredDelete)) == 0 &&
		len(undeclaredMoves(mc.DelegateMoves, mc.DeclaredMoves)) == 0 &&
		len(undeclaredPaths(mc.DelegateDirs, mc.DeclaredDirs)) > 0
}

func undeclaredMoves(nested, parent map[MovePair]bool) []string {
	out := make([]string, 0, len(nested))
	for pair := range nested {
		if !parent[pair] {
			out = append(out, pair.Source+" -> "+pair.Destination)
		}
	}
	slices.Sort(out)
	return out
}

func undeclaredPaths(nested, parent map[string]bool) []string {
	out := make([]string, 0, len(nested))
	for path := range nested {
		if !parent[path] {
			out = append(out, path)
		}
	}
	slices.Sort(out)
	return out
}

func emitDeclaredScope(req MatchRequest, deps AuthorizeDeps, outcome string) error {
	argHash := matchArgumentHash(req.Kind, PermissionEntry{Subject: req.Subject})
	return deps.EmitMatched(req.Kind, req.Subject, req.PathScope,
		"", "", outcome, OutcomeSourceDeclaredScope, argHash, "")
}
