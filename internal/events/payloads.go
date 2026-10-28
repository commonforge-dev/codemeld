// Package events defines the event payload schemas, their per-kind
// cross-field validators, and the append API that mints a record id, stamps the
// canonical timestamp, coerces invalid UTF-8 to U+FFFD, and appends an event to
// the active session store. It stays independent of internal/sessions's load
// path so load orchestration can compose spine validation with
// the payload validation here without an import cycle.
package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

// Event-kind constants. Each EventPayload reports
// its kind via Kind(); these are also the kind strings written to the record.
const (
	KindLaunchBegan             = "launch_began"
	KindSessionForked           = "session_forked"
	KindPermissionPromptShown   = "permission_prompt_shown"
	KindPermissionDecision      = "permission_decision"
	KindPermissionMatched       = "permission_matched"
	KindPermissionPromptWait    = "permission_prompt_wait"
	KindToolExecStart           = "tool_exec_start"
	KindToolExecEnd             = "tool_exec_end"
	KindAgentInstructionsLoaded = "agent_instructions_loaded"
	KindSessionPruneSummary     = "session_prune_summary"
	KindSessionWriteFailed      = "session_write_failed"
	KindPermissionPersistFailed = "permission_persist_failed"
	KindModelTurn               = "model_turn"
	KindModelResponse           = "model_response"
	KindModelChanged            = "model_changed"
	KindModelEffortUnsupported  = "model_effort_unsupported"
	KindModelRecoveryFailed     = "model_recovery_failed"
	KindModelPersistFailed      = "model_persist_failed"
	KindModelGlobalMirrorFailed = "model_global_mirror_failed"
	KindModelCatalogRefreshed   = "model_catalog_refreshed"
	KindSlashCommand            = "slash_command"
	KindStreamInterrupted       = "stream_interrupted"
	KindProviderRequestFailed   = "provider_request_failed"
	KindInteractionMode         = "interaction_mode"
	// turn_latency and provider_round_trip are additive timing events: they
	// record how long a user-visible turn and a single provider
	// round took so a session reviewer can see where the time went. Like
	// interaction_mode they are non-breaking additions — older sessions that lack
	// them load unchanged with no schema_version bump.
	KindTurnLatency       = "turn_latency"
	KindProviderRoundTrip = "provider_round_trip"
	// provider_request_retry records one scheduled auto-retry of a transient
	// provider-round failure, appended and flushed before each
	// backoff wait. Like the timing events it is a non-breaking addition that older
	// sessions load unchanged with no schema_version bump; the terminal
	// provider_request_failed schema is deliberately left untouched, so the attempt
	// count is reconstructed from these events rather than added to that one.
	KindProviderRequestRetry = "provider_request_retry"
	// provider_request_retry_skipped records that a classified retryable
	// provider-round failure was NOT scheduled for another attempt, carrying the
	// closed skip reason (retry_disabled / max_attempts_reached / budget_exhausted).
	// It mirrors provider_request_retry's (phase, reason) taxonomy and, like it, is a
	// non-breaking addition that older sessions load unchanged with no schema_version
	// bump. This slice only defines and validates the event; the retry loop
	// that emits it is wired separately.
	KindProviderRequestRetrySkipped = "provider_request_retry_skipped"
	// suggest_followup_debug is the development-only trace of the
	// suggest_followup path. It is written only when the
	// dev-debug gate is on (CODEMELD_DEV_DEBUG / `run --dev-debug`); a normal
	// session never carries it. Like the timing events it is a non-breaking
	// addition that older sessions load unchanged with no schema_version bump, and
	// it deliberately persists only lengths/booleans/reasons — never suggestion
	// label or prompt text — so it cannot reintroduce the ephemeral UI text the
	// follow-up suggestion channel keeps out of the record.
	KindSuggestFollowupDebug      = "suggest_followup_debug"
	KindQueuedPromptDiscarded     = "queued_prompt_discarded"
	KindProviderStreamIdle        = "provider_stream_idle"
	KindStructuredReadStart       = "structured_read_start"
	KindStructuredReadEnd         = "structured_read_end"
	KindStructuredReadRefused     = "structured_read_refused"
	KindTurnTerminal              = "turn_terminal"
	KindPermissionRevokeRequested = "permission_revoke_requested"
	KindPermissionSystemOneCheck  = "permission_system_one_check"
	KindSecurityStateHalted       = "security_state_halted"
	// child_agent_start and child_agent_end are the delegate lifecycle pair, linked by one
	// invocation id the child's own tool and permission events also carry. Like the timing
	// events they are a non-breaking addition: a parent's own events omit the attribution
	// field, so older sessions load unchanged with no schema_version bump.
	KindChildAgentStart = "child_agent_start"
	KindChildAgentEnd   = "child_agent_end"

	KindExecutionCapability = "execution_capability"
	KindSkillLoaded         = "skill_loaded"
)

// suggest_followup_debug stage labels. Each marks one observable point on
// the suggest_followup path so a developer reproducing a missing suggestion can see
// exactly how far it got: whether the tool was advertised, whether the model called
// it, where it was intercepted, and what the TUI surface did with it. turn-side
// stages (request_built…intercepted) come from the turn loop; the ghost stages come
// from the TUI event loop.
const (
	SuggestFollowupStageRequestBuilt  = "request_built"
	SuggestFollowupStageNoCall        = "provider_round_no_call"
	SuggestFollowupStageToolCallSeen  = "tool_call_seen"
	SuggestFollowupStageIntercepted   = "intercepted"
	SuggestFollowupStageSurfaceCalled = "surface_called"
	SuggestFollowupStageGhostSet      = "ghost_set"
	SuggestFollowupStageGhostAccepted = "ghost_accepted"
	SuggestFollowupStageGhostCleared  = "ghost_cleared"
)

var suggestFollowupStages = set(
	SuggestFollowupStageRequestBuilt,
	SuggestFollowupStageNoCall,
	SuggestFollowupStageToolCallSeen,
	SuggestFollowupStageIntercepted,
	SuggestFollowupStageSurfaceCalled,
	SuggestFollowupStageGhostSet,
	SuggestFollowupStageGhostAccepted,
	SuggestFollowupStageGhostCleared,
)

// EventPayload is the closed set of event payloads. The unexported
// validate keeps the set closed to this package (mirroring sessions.Record) and
// is exercised externally only through Append and ValidatePayload.
type EventPayload interface {
	// Kind returns the kind string for this payload.
	Kind() string
	validate() error
}

// Closed enum sets ---------------

var subjectKinds = set("direct", "literal", "tool")

const subjectKindDirect = "direct"

const subjectKindHost = "host"

const subjectKindTool = "tool"

const grantKindProject = "project"

var hostSubjects = set("web_search", "web_fetch")

// Mirrors the keys of internal/permissions's capability-subject table, which cannot be imported
// here because that package's own tests import this one.
var capabilitySubjects = set("write", "write_tree", "read*")

var hostGrantKinds = set("session", grantKindProject)

var pathGrantKinds = set("session", "folder", "global")

// outcome_source vocabulary. "prompt" is reserved: the prompt path emits permission_decision
// instead. declared_scope is a run's caller-declared file scope deciding a call,
// protected_state is the pre-authorization settings-file guard and blocked_path the
// pre-authorization blocked-path guard; none is ever valid on a host record, whose subjects are
// network hosts.
const (
	outcomeSourcePrompt          = "prompt"
	outcomeSourceGrant           = "grant"
	outcomeSourceDeclaredScope   = "declared_scope"
	outcomeSourceProtectedState  = "protected_state"
	outcomeSourceBlockedPath     = "blocked_path"
	outcomeSourceDeclaredCommand = "declared_command"
	outcomeSourceOpenRead        = "open_read"
	outcomeSourceConfined        = "confined"
	outcomeSourceSystemOneCheck  = "system_one_check"
)

var knownOutcomeSources = set("cache", outcomeSourceGrant, "mode_auto", outcomeSourceDeclaredScope, outcomeSourceProtectedState, outcomeSourceBlockedPath, outcomeSourceDeclaredCommand, outcomeSourceOpenRead, outcomeSourceConfined, outcomeSourceSystemOneCheck)

var openReadSubjects = set("read", "read_image", "grep", "glob", "list", "tree", "file_count")

var hostOutcomeSources = set("cache", outcomeSourceGrant)

var perCallOutcomeSources = set("mode_auto", outcomeSourceDeclaredScope, outcomeSourceSystemOneCheck)

// Mirrors the structured mutation tools and the closed vcs_<action> vocabulary internal/vcs
// registers, both of which internal/securitystate's protected-state guard covers.
var protectedStateSubjects = set(
	"edit", "create", "delete", "mkdir", "move",
	"vcs_status", "vcs_diff", "vcs_add", "vcs_commit", "vcs_log",
	"vcs_branch_current", "vcs_branch_create", "vcs_branch_switch", "vcs_restore_file",
	"vcs_is_clean", "vcs_stash", "vcs_stash_pop", "vcs_merge_status", "vcs_rebase_status",
)

var blockedPathSubjects = set(
	"read", "read_image", "grep", "glob", "list", "tree", "file_count", "skill",
	"edit", "create", "delete", "mkdir", "move",
	"vcs_branch_switch", "vcs_restore_file", "vcs_stash", "vcs_stash_pop",
)

var guardOutcomeSubjects = map[string]map[string]bool{
	outcomeSourceProtectedState: protectedStateSubjects,
	outcomeSourceBlockedPath:    blockedPathSubjects,
}

var perCallOutcomes = set("once", "deny")

// errorCategories is the vocabulary, sourced from fserrors so the two
// stay in lockstep.
var errorCategories = map[string]bool{
	string(fserrors.PermissionDenied): true,
	string(fserrors.NoSpace):          true,
	string(fserrors.ReadOnlyFS):       true,
	string(fserrors.IOError):          true,
	string(fserrors.NotFound):         true,
	string(fserrors.InUse):            true,
}

// persistReasons is the operational failure vocabulary shared by the
// permission/model persist-failure events.
var persistReasons = set(
	"lock_timeout", "lock_acquire_error", "reread_parse_error",
	"reread_io_error", "write_error", "rename_error", "parent_dir_error",
)

// reasonsWithoutCategory are the persist reasons that do not originate in an
// OS-level file syscall, so error_category is omitted for them.
var reasonsWithoutCategory = set("lock_timeout", "reread_parse_error")

const lockTimeoutDetail = "lock acquisition timed out"

// RevokeSourcePermissionsUI is the only source permission_revoke_requested is ever written
// with: the dedicated /permissions revoke control. A revoke recorded from anywhere else would
// make the event's provenance unreadable, so the vocabulary stays closed to this one value.
const RevokeSourcePermissionsUI = "permissions_ui"

var revokeSources = set(RevokeSourcePermissionsUI)

var argumentHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// providerReasons partitions provider_request_failed.reason by phase.
var providerReasons = map[string]map[string]bool{
	"dial":           set("dns_error", "connect_timeout", "connect_refused", "connect_other"),
	"tls":            set("tls_cert_invalid", "tls_cert_expired", "tls_handshake", "tls_other"),
	"http":           set("http_no_body", "http_truncated", "http_error"),
	"decode":         set("decode_error"),
	"stream_drop":    set("stream_read_error", "stream_eof", "stream_no_output"),
	"empty_response": set("no_choices", "null_content", "zero_delta_stream"),
}

// retrySkipReasons is the closed set of reasons a classified retryable failure was
// not scheduled for another attempt (provider_request_retry_skipped).
var retrySkipReasons = set("retry_disabled", "max_attempts_reached", "budget_exhausted")

const (
	RetryPhaseToolHandoff     = "tool_handoff"
	RetryReasonAssemblyFailed = "assembly_failed"
	RetryReasonInvalidPlan    = "invalid_plan"
)

var toolHandoffReasons = set(RetryReasonAssemblyFailed, RetryReasonInvalidPlan)

func retryReasons(phase string) (map[string]bool, bool) {
	if phase == RetryPhaseToolHandoff {
		return toolHandoffReasons, true
	}
	reasons, ok := providerReasons[phase]
	return reasons, ok
}

var discardReasons = set("interrupted", "turn_failed")

var structuredReadOutcomes = set("success", "tool_failure", "denied", "cancelled", "internal_failure")
var structuredReadToolNames = set("read", "glob", "grep", "list", "tree", "file_count")
var structuredReadRefusalReasons = set("not_allowlisted", "args_invalid", "prepare_failed", "scope_unresolved", "out_of_project")

// Payload types (in spec field order) ---------------------------

// LaunchBegan marks the boundary of a launch or in-process session switch.
type LaunchBegan struct {
	Source string `json:"source"` // fresh | resume | fork
}

func (LaunchBegan) Kind() string { return KindLaunchBegan }
func (p LaunchBegan) validate() error {
	return enum(KindLaunchBegan, "source", p.Source, set("fresh", "resume", "fork"))
}

type ExecutionCapability struct {
	Capability string                   `json:"capability"`
	Reason     string                   `json:"reason,omitempty"`
	Legs       []ExecutionCapabilityLeg `json:"legs,omitempty"`
}

type ExecutionCapabilityLeg struct {
	Name     string `json:"name"`
	Observed string `json:"observed"`
}

var executionCapabilityObservations = set("denied", "allowed", "held_by_host", "failed", "not_run")

func (ExecutionCapability) Kind() string { return KindExecutionCapability }
func (p ExecutionCapability) validate() error {
	const k = KindExecutionCapability
	switch p.Capability {
	case "refused":
		if err := required(k, "reason", p.Reason); err != nil {
			return err
		}
	case "constrained":
		if p.Reason != "" {
			return fmt.Errorf("%s: reason must be absent when capability is constrained", k)
		}
		if len(p.Legs) == 0 {
			return fmt.Errorf("%s: capability constrained requires at least one self-test leg", k)
		}
	default:
		return enum(k, "capability", p.Capability, set("constrained", "refused"))
	}
	for i, leg := range p.Legs {
		if err := required(k, fmt.Sprintf("legs[%d].name", i), leg.Name); err != nil {
			return err
		}
		if err := enum(k, fmt.Sprintf("legs[%d].observed", i), leg.Observed, executionCapabilityObservations); err != nil {
			return err
		}
	}
	return nil
}

// SessionForked is appended to the original session as its final event on fork.
type SessionForked struct {
	ToSessionID string `json:"to_session_id"`
}

func (SessionForked) Kind() string { return KindSessionForked }
func (p SessionForked) validate() error {
	return validV7(KindSessionForked, "to_session_id", p.ToSessionID)
}

// PermissionPromptShown records that a permission prompt was displayed.
type PermissionPromptShown struct {
	SubjectKind string `json:"subject_kind"`
	Subject     string `json:"subject"`
	PathScope   string `json:"path_scope,omitempty"`
	HostScope   string `json:"host_scope,omitempty"`
	// DirectTokens is the canonical direct-command token sequence the matcher
	// was given (permissions.MatchRequest.SubjectTokens). It is a pointer so a
	// legacy record's absence (unknown tokens) stays distinct from a present
	// empty array, which canonicalize would otherwise manufacture from a nil
	// slice. Absence must never be reconstructed by re-tokenizing Subject.
	DirectTokens *[]string `json:"direct_tokens,omitempty"`
	// DirectCommandSubject and DirectRequestSubject are the permission checker's
	// boundary-preserving direct identities, stored verbatim. This package never
	// decodes or cross-validates them against Subject or DirectTokens; only
	// internal/permissions parses them.
	DirectCommandSubject string `json:"direct_command_subject,omitempty"`
	DirectRequestSubject string `json:"direct_request_subject,omitempty"`
	// See ToolExecStart.ChildInvocationID.
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

func (PermissionPromptShown) Kind() string { return KindPermissionPromptShown }
func (p PermissionPromptShown) validate() error {
	const k = KindPermissionPromptShown
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	if err := p.validateDirectTokens(); err != nil {
		return err
	}
	if err := directIdentityFields(k, p.SubjectKind, p.DirectCommandSubject, p.DirectRequestSubject); err != nil {
		return err
	}
	if p.SubjectKind == subjectKindHost {
		return hostRequestFields(k, p.Subject, p.HostScope, p.PathScope)
	}
	if err := rejectHostFields(k, p.HostScope, ""); err != nil {
		return err
	}
	if err := enum(k, "subject_kind", p.SubjectKind, subjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	return requestPathScope(k, p.PathScope)
}

// Prompts counts the requests submitted to one prompt call, not the questions shown.
type PermissionPromptWait struct {
	WaitedMs int64  `json:"waited_ms"`
	Prompts  int    `json:"prompts"`
	Ended    string `json:"ended"`
}

var promptWaitEnds = map[string]bool{"answered": true, "cancelled": true, "failed": true}

func (PermissionPromptWait) Kind() string { return KindPermissionPromptWait }
func (p PermissionPromptWait) validate() error {
	const k = KindPermissionPromptWait
	if err := nonNegative(k, "waited_ms", p.WaitedMs); err != nil {
		return err
	}
	if p.Prompts < 1 {
		return fmt.Errorf("%s.prompts: must be >= 1, got %d", k, p.Prompts)
	}
	return enum(k, "ended", p.Ended, promptWaitEnds)
}

func (p PermissionPromptShown) validateDirectTokens() error {
	const k = KindPermissionPromptShown
	if p.DirectTokens == nil {
		return nil
	}
	if p.SubjectKind != subjectKindDirect {
		return fmt.Errorf("%s: direct_tokens is only present when subject_kind is %q, got %q", k, subjectKindDirect, p.SubjectKind)
	}
	if len(*p.DirectTokens) == 0 {
		return fmt.Errorf("%s.direct_tokens: must hold at least one token when present", k)
	}
	if joined := strings.Join(*p.DirectTokens, " "); joined != p.Subject {
		return fmt.Errorf("%s: direct_tokens joins to %q, which is not subject %q", k, joined, p.Subject)
	}
	return nil
}

func directIdentityFields(kind, subjectKind, commandSubject, requestSubject string) error {
	if commandSubject == "" && requestSubject == "" {
		return nil
	}
	if subjectKind != subjectKindDirect {
		return fmt.Errorf("%s: direct_command_subject and direct_request_subject are only present when subject_kind is %q, got %q",
			kind, subjectKindDirect, subjectKind)
	}
	if commandSubject == "" || requestSubject == "" {
		return fmt.Errorf("%s: direct_command_subject and direct_request_subject must both be present or both absent", kind)
	}
	return nil
}

// PermissionDecision records the user's response to a permission prompt.
type PermissionDecision struct {
	SubjectKind    string `json:"subject_kind"`
	Subject        string `json:"subject"`
	PathScope      string `json:"path_scope,omitempty"`
	Outcome        string `json:"outcome"`
	GrantKind      string `json:"grant_kind,omitempty"`
	GrantPathScope string `json:"grant_path_scope,omitempty"`
	HostScope      string `json:"host_scope,omitempty"`
	GrantHostScope string `json:"grant_host_scope,omitempty"`
	// An absent GrantSubject is a legacy record, not an equal subject.
	GrantSubject string `json:"grant_subject,omitempty"`
	// Stored verbatim; see PermissionPromptShown for the ownership rule.
	DirectCommandSubject string `json:"direct_command_subject,omitempty"`
	DirectRequestSubject string `json:"direct_request_subject,omitempty"`
	// See ToolExecStart.ChildInvocationID.
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

func (PermissionDecision) Kind() string { return KindPermissionDecision }
func (p PermissionDecision) validate() error {
	const k = KindPermissionDecision
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	if err := directIdentityFields(k, p.SubjectKind, p.DirectCommandSubject, p.DirectRequestSubject); err != nil {
		return err
	}
	if p.GrantSubject != "" {
		if p.Outcome == "denied" {
			return fmt.Errorf("%s: grant_subject must be absent when outcome is denied", k)
		}
		if p.GrantKind == "" {
			return fmt.Errorf("%s: grant_subject must be absent when grant_kind is absent", k)
		}
	}
	if p.SubjectKind == subjectKindHost {
		return p.validateHost()
	}
	if err := rejectHostFields(k, p.HostScope, p.GrantHostScope); err != nil {
		return err
	}
	if err := enum(k, "subject_kind", p.SubjectKind, subjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	if err := requestPathScope(k, p.PathScope); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, set("granted", "denied")); err != nil {
		return err
	}
	if p.Outcome == "denied" {
		if p.GrantKind != "" || p.GrantPathScope != "" {
			return fmt.Errorf("%s: grant_kind and grant_path_scope must be absent when outcome is denied", k)
		}
		return nil
	}
	if p.GrantKind == "" && p.GrantPathScope == "" {
		return nil
	}
	if err := enum(k, "grant_kind", p.GrantKind, pathGrantKinds); err != nil {
		return err
	}
	return grantPathScopePairing(k, p.GrantKind, p.GrantPathScope)
}

func (p PermissionDecision) validateHost() error {
	const k = KindPermissionDecision
	if err := hostRequestFields(k, p.Subject, p.HostScope, p.PathScope); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, set("granted", "denied")); err != nil {
		return err
	}
	if p.GrantPathScope != "" {
		return fmt.Errorf("%s: grant_path_scope must be absent when subject_kind is %q", k, subjectKindHost)
	}
	if p.Outcome == "denied" {
		if p.GrantKind != "" || p.GrantHostScope != "" {
			return fmt.Errorf("%s: grant_kind and grant_host_scope must be absent when outcome is denied", k)
		}
		return nil
	}
	if p.GrantKind == "" && p.GrantHostScope == "" {
		return nil
	}
	if err := enum(k, "grant_kind", p.GrantKind, hostGrantKinds); err != nil {
		return err
	}
	return grantHostScopePairing(k, p.HostScope, p.GrantHostScope)
}

// PermissionMatched records an existing grant or in-turn cache hit that
// authorized a command without prompting.
type PermissionMatched struct {
	SubjectKind    string `json:"subject_kind"`
	Subject        string `json:"subject"`
	PathScope      string `json:"path_scope,omitempty"`
	GrantKind      string `json:"grant_kind,omitempty"`
	GrantPathScope string `json:"grant_path_scope,omitempty"`
	Outcome        string `json:"outcome"`
	OutcomeSource  string `json:"outcome_source"`
	ArgumentHash   string `json:"argument_hash,omitempty"`
	HostScope      string `json:"host_scope,omitempty"`
	GrantHostScope string `json:"grant_host_scope,omitempty"`
	// Stored verbatim; see PermissionPromptShown for the ownership rule.
	DirectRequestSubject string `json:"direct_request_subject,omitempty"`
	// See ToolExecStart.ChildInvocationID.
	ChildInvocationID  string `json:"child_invocation_id,omitempty"`
	BlockedEntry       string `json:"blocked_entry,omitempty"`
	BlockedEntrySource string `json:"blocked_entry_source,omitempty"`
}

func (PermissionMatched) Kind() string { return KindPermissionMatched }

func (p PermissionMatched) validate() error { return p.check(false) }

// validateLoad is the load-time entry ValidatePayload uses. It accepts a shape-valid
// unrecognized outcome_source so one record written by a newer build cannot fail a whole
// session, while the append-time vocabulary this file's validate() enforces stays closed.
func (p PermissionMatched) validateLoad() error { return p.check(true) }

func (p PermissionMatched) check(allowUnknownSource bool) error {
	if err := optionalV7(KindPermissionMatched, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	if p.DirectRequestSubject != "" && p.SubjectKind != subjectKindDirect {
		return fmt.Errorf("%s: direct_request_subject is only present when subject_kind is %q, got %q",
			KindPermissionMatched, subjectKindDirect, p.SubjectKind)
	}
	if err := p.checkBlockedEntry(allowUnknownSource); err != nil {
		return err
	}
	if p.SubjectKind == subjectKindHost {
		return p.checkHost(allowUnknownSource)
	}
	return p.checkPath(allowUnknownSource)
}

func (p PermissionMatched) checkBlockedEntry(allowUnknownSource bool) error {
	const k = KindPermissionMatched
	hasFields := p.BlockedEntry != "" || p.BlockedEntrySource != ""
	switch {
	case p.OutcomeSource == outcomeSourceBlockedPath:
		if !allowUnknownSource && p.BlockedEntry == "" {
			return fmt.Errorf("%s: outcome_source %s requires blocked_entry", k, outcomeSourceBlockedPath)
		}
	case hasFields && (!allowUnknownSource || knownOutcomeSources[p.OutcomeSource]):
		return fmt.Errorf("%s: blocked_entry and blocked_entry_source are only present when outcome_source is %s", k, outcomeSourceBlockedPath)
	}
	if p.BlockedEntry != "" {
		if err := absCleanPath(k, "blocked_entry", p.BlockedEntry); err != nil {
			return err
		}
	}
	if p.BlockedEntrySource != "" {
		return absCleanPath(k, "blocked_entry_source", p.BlockedEntrySource)
	}
	return nil
}

func (p PermissionMatched) checkPath(allowUnknownSource bool) error {
	const k = KindPermissionMatched
	if err := rejectHostFields(k, p.HostScope, p.GrantHostScope); err != nil {
		return err
	}
	if err := enum(k, "subject_kind", p.SubjectKind, subjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	// path_scope is the request's resolved path evaluated for matching
	// always a concrete cleaned absolute path; the "*" sentinel only ever appears
	// in grant_path_scope for global grants.
	if err := requestPathScope(k, p.PathScope); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, set("once", "session_grant", "folder_grant", "global_grant", "deny")); err != nil {
		return err
	}
	known, err := classifyOutcomeSource(p.OutcomeSource, knownOutcomeSources, allowUnknownSource)
	if err != nil {
		return err
	}
	if err := p.checkKnownSourceOutcome(known); err != nil {
		return err
	}
	if err := p.checkPathGrantFields(); err != nil {
		return err
	}
	return p.checkArgumentHash()
}

// checkKnownSourceOutcome applies the outcome rules a known source carries beyond the shared
// shape checks: a mode_auto or declared_scope decision is per-call, so it is only ever an
// auto-allow ("once") or a denial ("deny"), and a grant source records a matched grant, so it is
// only ever a grant outcome. An unknown load-time source skips these source-specific rules and is
// held to the shape rules alone.
func (p PermissionMatched) checkKnownSourceOutcome(known bool) error {
	const k = KindPermissionMatched
	if !known {
		return nil
	}
	if perCallOutcomeSources[p.OutcomeSource] && !perCallOutcomes[p.Outcome] {
		return fmt.Errorf("%s: outcome_source %s requires outcome once or deny", k, p.OutcomeSource)
	}
	// A declared-command hit has no denial of its own to record, so unlike mode_auto and
	// declared_scope its outcome is pinned to once rather than once-or-deny.
	if p.OutcomeSource == outcomeSourceDeclaredCommand && p.Outcome != "once" {
		return fmt.Errorf("%s: outcome_source %s requires outcome once, not %s", k, outcomeSourceDeclaredCommand, p.Outcome)
	}
	if p.OutcomeSource == outcomeSourceOpenRead {
		if p.Outcome != "once" {
			return fmt.Errorf("%s: outcome_source %s requires outcome once, not %s", k, outcomeSourceOpenRead, p.Outcome)
		}
		if p.SubjectKind != subjectKindTool {
			return fmt.Errorf("%s: outcome_source %s requires subject_kind %s, not %s", k, outcomeSourceOpenRead, subjectKindTool, p.SubjectKind)
		}
		if !openReadSubjects[p.Subject] {
			return fmt.Errorf("%s: outcome_source %s requires a read tool subject, not %q", k, outcomeSourceOpenRead, p.Subject)
		}
	}
	if p.OutcomeSource == outcomeSourceConfined || p.OutcomeSource == outcomeSourceSystemOneCheck {
		if p.Outcome != "once" {
			return fmt.Errorf("%s: outcome_source %s requires outcome once, not %s", k, p.OutcomeSource, p.Outcome)
		}
		if p.SubjectKind != subjectKindDirect && p.SubjectKind != "literal" {
			return fmt.Errorf("%s: outcome_source %s requires subject_kind direct or literal, not %s", k, p.OutcomeSource, p.SubjectKind)
		}
	}
	if p.OutcomeSource == outcomeSourceGrant && perCallOutcomes[p.Outcome] {
		return fmt.Errorf("%s: outcome_source %s requires a matching grant outcome, not %s", k, outcomeSourceGrant, p.Outcome)
	}
	if subjects, ok := guardOutcomeSubjects[p.OutcomeSource]; ok {
		if p.Outcome != "deny" {
			return fmt.Errorf("%s: outcome_source %s requires outcome deny, not %s", k, p.OutcomeSource, p.Outcome)
		}
		if p.OutcomeSource == outcomeSourceBlockedPath && (p.SubjectKind == subjectKindDirect || p.SubjectKind == "literal") {
			return nil
		}
		if p.SubjectKind != subjectKindTool {
			return fmt.Errorf("%s: outcome_source %s requires subject_kind %s, not %s", k, p.OutcomeSource, subjectKindTool, p.SubjectKind)
		}
		if !subjects[p.Subject] {
			return fmt.Errorf("%s: outcome_source %s requires a subject it guards, not %q", k, p.OutcomeSource, p.Subject)
		}
	}
	return nil
}

// checkPathGrantFields keys the grant-field rules on the outcome, never on the source, so an
// unrecognized source is still held to the same shape a known one is.
func (p PermissionMatched) checkPathGrantFields() error {
	const k = KindPermissionMatched
	if perCallOutcomes[p.Outcome] {
		if p.GrantKind != "" || p.GrantPathScope != "" {
			return fmt.Errorf("%s: grant_kind and grant_path_scope must be absent when outcome is once or deny", k)
		}
		return nil
	}
	if err := enum(k, "grant_kind", p.GrantKind, pathGrantKinds); err != nil {
		return err
	}
	// For any grant match the outcome mirrors grant_kind with the _grant suffix.
	if want := p.GrantKind + "_grant"; p.Outcome != want {
		return fmt.Errorf("%s: outcome %q does not mirror grant_kind %q (expected %q)", k, p.Outcome, p.GrantKind, want)
	}
	return grantPathScopePairing(k, p.GrantKind, p.GrantPathScope)
}

// checkArgumentHash mirrors for literal-command matches: argument_hash is required when
// subject_kind is "literal" and forbidden otherwise.
func (p PermissionMatched) checkArgumentHash() error {
	const k = KindPermissionMatched
	if p.SubjectKind != "literal" {
		if p.ArgumentHash != "" {
			return fmt.Errorf("%s: argument_hash is only present for literal-command matches", k)
		}
		return nil
	}
	if p.ArgumentHash == "" {
		return fmt.Errorf("%s: argument_hash is required for literal-command matches", k)
	}
	if !argumentHashRE.MatchString(p.ArgumentHash) {
		return fmt.Errorf("%s.argument_hash: %q is not a lowercase 64-char SHA-256 hex digest", k, p.ArgumentHash)
	}
	// argument_hash is a denormalized projection of subject:
	// it must be the SHA-256 of the canonical literal subject, so a well-formed
	// but mismatched hash cannot belong to the recorded subject.
	if want := literalArgumentHash(p.Subject); p.ArgumentHash != want {
		return fmt.Errorf("%s.argument_hash: %q is not the SHA-256 of subject %q (expected %q)", k, p.ArgumentHash, p.Subject, want)
	}
	return nil
}

func (p PermissionMatched) checkHost(allowUnknownSource bool) error {
	const k = KindPermissionMatched
	if err := hostRequestFields(k, p.Subject, p.HostScope, p.PathScope); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, set("once", "session_grant", "project_grant", "deny")); err != nil {
		return err
	}
	known, err := classifyOutcomeSource(p.OutcomeSource, hostOutcomeSources, allowUnknownSource)
	if err != nil {
		return err
	}
	if err := p.checkKnownSourceOutcome(known); err != nil {
		return err
	}
	if p.ArgumentHash != "" {
		return fmt.Errorf("%s: argument_hash is only present for literal-command matches", k)
	}
	if p.GrantPathScope != "" {
		return fmt.Errorf("%s: grant_path_scope must be absent when subject_kind is %q", k, subjectKindHost)
	}
	if perCallOutcomes[p.Outcome] {
		if p.GrantKind != "" || p.GrantHostScope != "" {
			return fmt.Errorf("%s: grant_kind and grant_host_scope must be absent when outcome is once or deny", k)
		}
		return nil
	}
	if err := enum(k, "grant_kind", p.GrantKind, hostGrantKinds); err != nil {
		return err
	}
	if want := p.GrantKind + "_grant"; p.Outcome != want {
		return fmt.Errorf("%s: outcome %q does not mirror grant_kind %q (expected %q)", k, p.Outcome, p.GrantKind, want)
	}
	return grantHostScopePairing(k, p.HostScope, p.GrantHostScope)
}

// classifyOutcomeSource reports whether source is one of the values valid for the record's
// subject kind. Empty and the reserved "prompt" are rejected on both the append and load paths,
// and a source known to some other subject kind is rejected rather than passed off as unknown;
// only a genuinely unrecognized non-empty value is admitted, and only on the load path.
func classifyOutcomeSource(source string, valid map[string]bool, allowUnknown bool) (bool, error) {
	const k = KindPermissionMatched
	if source == "" {
		return false, required(k, "outcome_source", source)
	}
	if source == outcomeSourcePrompt {
		return false, fmt.Errorf("%s.outcome_source: %q is reserved and is never recorded on this event", k, source)
	}
	if valid[source] {
		return true, nil
	}
	if knownOutcomeSources[source] || !allowUnknown {
		return false, enum(k, "outcome_source", source, valid)
	}
	return false, nil
}

// literalArgumentHash returns the lowercase hex SHA-256 of a canonical literal
// subject, per §Reserved Values "Permission-entry hash algorithm".
func literalArgumentHash(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

var (
	systemOneSubjectKinds = set(subjectKindDirect, "literal")
	systemOneProviders    = set("openrouter", "venice")
	systemOneOutcomes     = set("allowed", "declined", "failed", "skipped")
	systemOneEffects      = set("read_only", "writes_files", "deletes", "network", "runs_hidden_code", "changes_system")
	systemOneReasons      = map[string]map[string]bool{
		"failed":  set("credits", "auth", "rate_limited", "timeout", "server", "network", "malformed", "no_key"),
		"skipped": set("paused", "text", "blocked_paths_unavailable", "substitution", "blocked_path", "wrapper", "program_location", "shell_shape"),
	}
)

// The outcome is not re-derived from the probabilities and thresholds: they are audit data,
// checked for shape only.
type PermissionSystemOneCheck struct {
	SubjectKind       string   `json:"subject_kind"`
	Subject           string   `json:"subject"`
	PathScope         string   `json:"path_scope,omitempty"`
	Provider          string   `json:"provider"`
	ModelID           string   `json:"model_id"`
	Outcome           string   `json:"outcome"`
	Reason            string   `json:"reason,omitempty"`
	Effect            string   `json:"effect,omitempty"`
	PReadOnly         *float64 `json:"p_read_only,omitempty"`
	PSecrets          *float64 `json:"p_secrets,omitempty"`
	PCode             *float64 `json:"p_code,omitempty"`
	TReadOnly         *float64 `json:"t_read_only,omitempty"`
	TSecrets          *float64 `json:"t_secrets,omitempty"`
	TCode             *float64 `json:"t_code,omitempty"`
	DurationMs        int64    `json:"duration_ms"`
	ChildInvocationID string   `json:"child_invocation_id,omitempty"`
}

func (PermissionSystemOneCheck) Kind() string { return KindPermissionSystemOneCheck }

func (p PermissionSystemOneCheck) validate() error {
	const k = KindPermissionSystemOneCheck
	if err := enum(k, "subject_kind", p.SubjectKind, systemOneSubjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	if p.PathScope != "" {
		if err := absCleanPath(k, "path_scope", p.PathScope); err != nil {
			return err
		}
	}
	if err := enum(k, "provider", p.Provider, systemOneProviders); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, systemOneOutcomes); err != nil {
		return err
	}
	if err := nonNegative(k, "duration_ms", p.DurationMs); err != nil {
		return err
	}
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	scores := []struct {
		field string
		value *float64
	}{
		{"p_read_only", p.PReadOnly}, {"p_secrets", p.PSecrets}, {"p_code", p.PCode},
		{"t_read_only", p.TReadOnly}, {"t_secrets", p.TSecrets}, {"t_code", p.TCode},
	}
	if reasons, ok := systemOneReasons[p.Outcome]; ok {
		if err := enum(k, "reason", p.Reason, reasons); err != nil {
			return err
		}
		if p.Effect != "" {
			return fmt.Errorf("%s: effect must be absent when outcome is %s", k, p.Outcome)
		}
		for _, s := range scores {
			if s.value != nil {
				return fmt.Errorf("%s: %s must be absent when outcome is %s", k, s.field, p.Outcome)
			}
		}
		return nil
	}
	if p.Reason != "" {
		return fmt.Errorf("%s: reason must be absent when outcome is %s", k, p.Outcome)
	}
	if err := enum(k, "effect", p.Effect, systemOneEffects); err != nil {
		return err
	}
	for _, s := range scores {
		if s.value == nil {
			return fmt.Errorf("%s.%s: required when outcome is %s", k, s.field, p.Outcome)
		}
		if v := *s.value; !(v >= 0 && v <= 1) {
			return fmt.Errorf("%s.%s: must be a finite number in 0-1, got %v", k, s.field, v)
		}
	}
	return nil
}

// PermissionRevokeRequested records that the /permissions revoke control asked for one stored
// grant to be removed. Its fields are the removed grant's own identity — permissions.DedupKey
// (EntryKind/Subject/PathScope/HostScope/GrantKind) plus the literal ArgumentHash — never the
// subject of the request that once triggered the grant, so a reader can match the record to the
// exact stored entry.
//
// The record is not proof that this process removed a settings entry: the writable target is
// inspected before the delete takes its lock, so a persisted revoke means /permissions observed
// the grant and requested an idempotent delete that reported success.
type PermissionRevokeRequested struct {
	EntryKind    string `json:"kind"`
	Subject      string `json:"subject"`
	PathScope    string `json:"path_scope,omitempty"`
	HostScope    string `json:"host_scope,omitempty"`
	GrantKind    string `json:"grant_kind"`
	ArgumentHash string `json:"argument_hash,omitempty"`
	Source       string `json:"source"`
}

func (PermissionRevokeRequested) Kind() string { return KindPermissionRevokeRequested }

func EmitPermissionRevokeRequested(store *sessions.Store, entryKind, subject, pathScope, hostScope, grantKind, argumentHash string) error {
	_, err := Append(store, PermissionRevokeRequested{
		EntryKind:    entryKind,
		Subject:      subject,
		PathScope:    pathScope,
		HostScope:    hostScope,
		GrantKind:    grantKind,
		ArgumentHash: argumentHash,
		Source:       RevokeSourcePermissionsUI,
	})
	return err
}

func (p PermissionRevokeRequested) validate() error {
	const k = KindPermissionRevokeRequested
	if err := enum(k, "source", p.Source, revokeSources); err != nil {
		return err
	}
	if err := enum(k, "kind", p.EntryKind, subjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	if hostSubjects[p.Subject] {
		return p.validateHost()
	}
	if p.HostScope != "" {
		return fmt.Errorf("%s: host_scope is only present for subject web_search or web_fetch, got %q", k, p.Subject)
	}
	if capabilitySubjects[p.Subject] && p.EntryKind != subjectKindTool {
		return fmt.Errorf("%s: subject %q is a reserved capability subject valid only for kind %q, got %q", k, p.Subject, subjectKindTool, p.EntryKind)
	}
	if err := enum(k, "grant_kind", p.GrantKind, pathGrantKinds); err != nil {
		return err
	}
	if err := pathScopePairing(k, "path_scope", p.GrantKind, p.PathScope); err != nil {
		return err
	}
	return p.checkArgumentHash()
}

func (p PermissionRevokeRequested) validateHost() error {
	const k = KindPermissionRevokeRequested
	if p.EntryKind != subjectKindTool {
		return fmt.Errorf("%s: subject %q is a network subject valid only for kind %q, got %q", k, p.Subject, subjectKindTool, p.EntryKind)
	}
	if p.PathScope != "" {
		return fmt.Errorf("%s: path_scope must be absent for subject %q, which is scoped by host_scope", k, p.Subject)
	}
	if p.ArgumentHash != "" {
		return fmt.Errorf("%s: argument_hash is only present for a literal grant", k)
	}
	if err := enum(k, "grant_kind", p.GrantKind, hostGrantKinds); err != nil {
		return err
	}
	return canonicalHostScope(k, "host_scope", p.HostScope)
}

// checkArgumentHash mirrors permission_matched's: argument_hash is the SHA-256 of the stored
// literal subject, so a well-formed but mismatched hash cannot belong to the recorded grant.
func (p PermissionRevokeRequested) checkArgumentHash() error {
	const k = KindPermissionRevokeRequested
	if p.EntryKind != "literal" {
		if p.ArgumentHash != "" {
			return fmt.Errorf("%s: argument_hash is only present for a literal grant", k)
		}
		return nil
	}
	if p.ArgumentHash == "" {
		return fmt.Errorf("%s: argument_hash is required for a literal grant", k)
	}
	if !argumentHashRE.MatchString(p.ArgumentHash) {
		return fmt.Errorf("%s.argument_hash: %q is not a lowercase 64-char SHA-256 hex digest", k, p.ArgumentHash)
	}
	if want := literalArgumentHash(p.Subject); p.ArgumentHash != want {
		return fmt.Errorf("%s.argument_hash: %q is not the SHA-256 of subject %q (expected %q)", k, p.ArgumentHash, p.Subject, want)
	}
	return nil
}

// ToolExecStart records the start of a tool invocation.
type ToolExecStart struct {
	SubjectKind  string `json:"subject_kind"`
	Subject      string `json:"subject"`
	PathScope    string `json:"path_scope"`
	InvocationID string `json:"invocation_id"`
	// ChildInvocationID names the child_agent_start this call belongs to; a parent's own
	// call omits it. Attribution must be read from here rather than inferred from a child's
	// start/end interval, because disjoint children may run concurrently.
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

func (ToolExecStart) Kind() string { return KindToolExecStart }
func (p ToolExecStart) validate() error {
	const k = KindToolExecStart
	if err := enum(k, "subject_kind", p.SubjectKind, subjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	if err := absCleanPath(k, "path_scope", p.PathScope); err != nil {
		return err
	}
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	return validV7(k, "invocation_id", p.InvocationID)
}

// OriginalBytes carries the pre-truncation byte sizes of a captured stream pair.
type OriginalBytes struct {
	Stdout int64 `json:"stdout"`
	Stderr int64 `json:"stderr"`
}

// ToolExecEnd records the completion of a tool invocation.
type ToolExecEnd struct {
	SubjectKind   string         `json:"subject_kind"`
	Subject       string         `json:"subject"`
	ExitCode      int64          `json:"exit_code"`
	DurationMs    int64          `json:"duration_ms"`
	Stdout        string         `json:"stdout,omitempty"`
	Stderr        string         `json:"stderr,omitempty"`
	Truncated     bool           `json:"truncated"`
	OriginalBytes *OriginalBytes `json:"original_bytes,omitempty"`
	InvocationID  string         `json:"invocation_id"`
	// See ToolExecStart.ChildInvocationID.
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

func (ToolExecEnd) Kind() string { return KindToolExecEnd }
func (p ToolExecEnd) validate() error {
	const k = KindToolExecEnd
	if err := enum(k, "subject_kind", p.SubjectKind, subjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	if err := nonNegative(k, "duration_ms", p.DurationMs); err != nil {
		return err
	}
	if p.Truncated {
		if p.OriginalBytes == nil {
			return fmt.Errorf("%s: original_bytes is required when truncated is true", k)
		}
		// original_bytes is the pre-truncation byte size of each raw stream:
		// it can never be smaller than the bytes actually captured, and a
		// truncated:true record must show at least one stream whose original size
		// exceeds what was kept — otherwise nothing was dropped. validate() runs
		// on the canonical payload, where invalid UTF-8 has already been coerced
		// to U+FFFD, so len(p.Stdout) can exceed the raw captured byte count (one
		// invalid byte expands to a 3-byte U+FFFD). Compare against the minimum
		// raw byte count the coerced string could have come from, so a valid
		// truncated stream carrying invalid UTF-8 is not rejected merely because
		// replacement expanded it.
		stdoutMin := minRawUTF8Bytes(p.Stdout)
		stderrMin := minRawUTF8Bytes(p.Stderr)
		if p.OriginalBytes.Stdout < stdoutMin {
			return fmt.Errorf("%s: original_bytes.stdout (%d) is smaller than the captured stdout byte length (%d)", k, p.OriginalBytes.Stdout, stdoutMin)
		}
		if p.OriginalBytes.Stderr < stderrMin {
			return fmt.Errorf("%s: original_bytes.stderr (%d) is smaller than the captured stderr byte length (%d)", k, p.OriginalBytes.Stderr, stderrMin)
		}
		if p.OriginalBytes.Stdout <= stdoutMin && p.OriginalBytes.Stderr <= stderrMin {
			return fmt.Errorf("%s: truncated is true but neither stream's original_bytes exceeds its captured byte length", k)
		}
	} else if p.OriginalBytes != nil {
		return fmt.Errorf("%s: original_bytes must be absent when truncated is false", k)
	}
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	return validV7(k, "invocation_id", p.InvocationID)
}

// minRawUTF8Bytes returns the fewest raw bytes the (already UTF-8-coerced) string
// s could have been captured from. Each U+FFFD may stand for a single invalid
// raw byte that ToValidUTF8 expanded to the 3-byte replacement rune, so it
// contributes 1; every other rune passed through coercion unchanged and
// contributes its real UTF-8 byte length. This lower bound lets truncation
// validation accept captured output with invalid UTF-8 without trusting the
// inflated post-coercion length.
func minRawUTF8Bytes(s string) int64 {
	var n int64
	for _, r := range s {
		if r == utf8.RuneError {
			n++
			continue
		}
		n += int64(utf8.RuneLen(r))
	}
	return n
}

// AgentInstructionsLoaded records one AGENTS.md file loaded or skipped.
type AgentInstructionsLoaded struct {
	Path          string `json:"path"`
	Layer         string `json:"layer"`
	LoadOrder     int64  `json:"load_order"`
	SkipReason    string `json:"skip_reason,omitempty"`
	ErrorCategory string `json:"error_category,omitempty"`
	ErrorDetail   string `json:"error_detail,omitempty"`
}

func (AgentInstructionsLoaded) Kind() string { return KindAgentInstructionsLoaded }
func (p AgentInstructionsLoaded) validate() error {
	const k = KindAgentInstructionsLoaded
	if err := absCleanPath(k, "path", p.Path); err != nil {
		return err
	}
	if err := enum(k, "layer", p.Layer, set("global", "walked")); err != nil {
		return err
	}
	// Discovery is one sequence: the global file, present or skipped
	// always occupies load_order 1; walked files start at 2. So a "global" record
	// must be 1 and a "walked" record must be >= 2 — orderings the specified
	// discovery cannot produce are rejected.
	switch p.Layer {
	case "global":
		if p.LoadOrder != 1 {
			return fmt.Errorf("%s.load_order: global layer must be 1, got %d", k, p.LoadOrder)
		}
	case "walked":
		if p.LoadOrder < 2 {
			return fmt.Errorf("%s.load_order: walked layer must be >= 2, got %d", k, p.LoadOrder)
		}
	}
	switch p.SkipReason {
	case "": // loaded successfully — no skip/error fields permitted
		if p.ErrorCategory != "" || p.ErrorDetail != "" {
			return fmt.Errorf("%s: error_category and error_detail are only present on unreadable skips", k)
		}
	case "size_limit":
		if p.ErrorCategory != "" || p.ErrorDetail != "" {
			return fmt.Errorf("%s: error_category and error_detail must be absent when skip_reason is size_limit", k)
		}
	case "unreadable":
		if err := enum(k, "error_category", p.ErrorCategory, errorCategories); err != nil {
			return err
		}
		if err := required(k, "error_detail", p.ErrorDetail); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s.skip_reason: %q is not one of unreadable/size_limit", k, p.SkipReason)
	}
	return nil
}

// PruneFailure is one entry of session_prune_summary.failures.
type PruneFailure struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Kind   string `json:"kind"` // file_delete | dir_enumerate
}

// SessionPruneSummary records the outcome of a retention prune pass.
type SessionPruneSummary struct {
	FilesScanned int64          `json:"files_scanned"`
	FilesDeleted int64          `json:"files_deleted"`
	FilesFailed  int64          `json:"files_failed"`
	Failures     []PruneFailure `json:"failures"`
	ElapsedMs    int64          `json:"elapsed_ms"`
}

func (SessionPruneSummary) Kind() string { return KindSessionPruneSummary }
func (p SessionPruneSummary) validate() error {
	const k = KindSessionPruneSummary
	for _, f := range []struct {
		name string
		v    int64
	}{
		{"files_scanned", p.FilesScanned}, {"files_deleted", p.FilesDeleted},
		{"files_failed", p.FilesFailed}, {"elapsed_ms", p.ElapsedMs},
	} {
		if err := nonNegative(k, f.name, f.v); err != nil {
			return err
		}
	}
	// files_failed counts the failure entries, so the two must agree exactly;
	// this also subsumes the empty/non-empty pairing.
	if int64(len(p.Failures)) != p.FilesFailed {
		return fmt.Errorf("%s: files_failed is %d but failures has %d entries", k, p.FilesFailed, len(p.Failures))
	}
	for i, f := range p.Failures {
		if err := absCleanPath(k, fmt.Sprintf("failures[%d].path", i), f.Path); err != nil {
			return err
		}
		if !errorCategories[f.Reason] {
			return fmt.Errorf("%s.failures[%d].reason: %q is not a req-40b error category", k, i, f.Reason)
		}
		if f.Kind != "file_delete" && f.Kind != "dir_enumerate" {
			return fmt.Errorf("%s.failures[%d].kind: %q is not one of file_delete/dir_enumerate", k, i, f.Kind)
		}
	}
	return nil
}

// SessionWriteFailed records a failed atomic session-file write.
type SessionWriteFailed struct {
	TargetPath    string `json:"target_path"`
	Reason        string `json:"reason"`
	ErrorCategory string `json:"error_category"`
	ErrorDetail   string `json:"error_detail"`
}

func (SessionWriteFailed) Kind() string { return KindSessionWriteFailed }
func (p SessionWriteFailed) validate() error {
	const k = KindSessionWriteFailed
	if err := absCleanPath(k, "target_path", p.TargetPath); err != nil {
		return err
	}
	if err := enum(k, "reason", p.Reason, set("write_error", "rename_error", "parent_dir_error")); err != nil {
		return err
	}
	if err := enum(k, "error_category", p.ErrorCategory, errorCategories); err != nil {
		return err
	}
	return required(k, "error_detail", p.ErrorDetail)
}

// PermissionPersistFailed records a failed permission-grant persist.
type PermissionPersistFailed struct {
	TargetPath          string `json:"target_path"`
	GrantKind           string `json:"grant_kind"`
	SubjectKind         string `json:"subject_kind"`
	Subject             string `json:"subject"`
	Reason              string `json:"reason"`
	ErrorCategory       string `json:"error_category,omitempty"`
	ErrorDetail         string `json:"error_detail"`
	DegradedToPathScope string `json:"degraded_to_path_scope,omitempty"`
	HostScope           string `json:"host_scope,omitempty"`
}

func (PermissionPersistFailed) Kind() string { return KindPermissionPersistFailed }
func (p PermissionPersistFailed) validate() error {
	const k = KindPermissionPersistFailed
	if p.SubjectKind == subjectKindHost {
		return p.validateHost()
	}
	if err := rejectHostFields(k, p.HostScope, ""); err != nil {
		return err
	}
	if err := absCleanPath(k, "target_path", p.TargetPath); err != nil {
		return err
	}
	if err := enum(k, "grant_kind", p.GrantKind, set("folder", "global")); err != nil {
		return err
	}
	if err := enum(k, "subject_kind", p.SubjectKind, subjectKinds); err != nil {
		return err
	}
	if err := required(k, "subject", p.Subject); err != nil {
		return err
	}
	if err := persistReasonFields(k, p.Reason, p.ErrorCategory, p.ErrorDetail); err != nil {
		return err
	}
	// degraded_to_path_scope is populated only for a failed global grant, where
	// rewrites the in-memory scope to the resolved request path.
	if p.GrantKind == "folder" && p.DegradedToPathScope != "" {
		return fmt.Errorf("%s: degraded_to_path_scope must be absent when grant_kind is folder", k)
	}
	if p.GrantKind == "global" {
		if p.DegradedToPathScope == "" {
			return fmt.Errorf("%s: degraded_to_path_scope is required when grant_kind is global", k)
		}
		// The rewritten scope is the resolved request path — a concrete
		// absolute directory, never the "*" all-paths sentinel.
		if err := absCleanPath(k, "degraded_to_path_scope", p.DegradedToPathScope); err != nil {
			return err
		}
	}
	return nil
}

func (p PermissionPersistFailed) validateHost() error {
	const k = KindPermissionPersistFailed
	if err := absCleanPath(k, "target_path", p.TargetPath); err != nil {
		return err
	}
	if p.GrantKind != grantKindProject {
		return fmt.Errorf("%s: grant_kind must be %q when subject_kind is %q, got %q", k, grantKindProject, subjectKindHost, p.GrantKind)
	}
	if err := hostRequestFields(k, p.Subject, p.HostScope, ""); err != nil {
		return err
	}
	if err := persistReasonFields(k, p.Reason, p.ErrorCategory, p.ErrorDetail); err != nil {
		return err
	}
	if p.DegradedToPathScope != "" {
		return fmt.Errorf("%s: degraded_to_path_scope must be absent when subject_kind is %q", k, subjectKindHost)
	}
	return nil
}

// ModelTurn records the active model/effort at the start of an assistant turn.
// Effort validation is intentionally independent of provider catalog support.
type ModelTurn struct {
	Provider string `json:"provider"`
	ModelID  string `json:"model_id"`
	Effort   string `json:"effort"`
	Source   string `json:"source"`
}

func (ModelTurn) Kind() string { return KindModelTurn }
func (p ModelTurn) validate() error {
	const k = KindModelTurn
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if err := required(k, "effort", p.Effort); err != nil {
		return err
	}
	return enum(k, "source", p.Source, set("project", "global_fallback", "resume", "picker", "picker_degraded"))
}

// ModelResponse records an assistant turn's token usage.
type ModelResponse struct {
	Provider     string `json:"provider"`
	ModelID      string `json:"model_id"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	// nil is not reported; a non-nil 0 is a reported zero. Without omitempty,
	// requireShape would reject every record written before this field existed.
	CachedInputTokens *int64 `json:"cached_input_tokens,omitempty"`
	// Written only as true, marking the present CachedInputTokens a known lower bound.
	CachedInputTokensPartial bool     `json:"cached_input_tokens_partial,omitempty"`
	CostUSD                  *float64 `json:"cost_usd,omitempty"`
	CostUSDPartial           bool     `json:"cost_usd_partial,omitempty"`
	Anomaly                  []string `json:"anomaly"`
	UpstreamProvider         string   `json:"upstream_provider,omitempty"`
}

func (ModelResponse) Kind() string { return KindModelResponse }
func (p ModelResponse) validate() error {
	const k = KindModelResponse
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if err := nonNegative(k, "input_tokens", p.InputTokens); err != nil {
		return err
	}
	if err := nonNegative(k, "output_tokens", p.OutputTokens); err != nil {
		return err
	}
	if p.CachedInputTokens != nil {
		if err := nonNegative(k, "cached_input_tokens", *p.CachedInputTokens); err != nil {
			return err
		}
	} else if p.CachedInputTokensPartial {
		return fmt.Errorf("%s: cached_input_tokens_partial requires cached_input_tokens", k)
	}
	if p.CostUSD != nil {
		if err := nonNegativeFinite(k, "cost_usd", *p.CostUSD); err != nil {
			return err
		}
	} else if p.CostUSDPartial {
		return fmt.Errorf("%s: cost_usd_partial requires cost_usd", k)
	}
	seen := false
	for i, a := range p.Anomaly {
		if a != "usage_missing" {
			return fmt.Errorf("%s.anomaly[%d]: %q is not a recognized anomaly token", k, i, a)
		}
		if seen {
			return fmt.Errorf("%s.anomaly: usage_missing must appear at most once", k)
		}
		seen = true
	}
	return nil
}

// ModelChanged records a TUI model-picker selection.
type ModelChanged struct {
	NewProvider   string `json:"new_provider"`
	NewModelID    string `json:"new_model_id"`
	NewEffort     string `json:"new_effort"`
	PriorProvider string `json:"prior_provider,omitempty"`
	PriorModelID  string `json:"prior_model_id,omitempty"`
	PriorEffort   string `json:"prior_effort,omitempty"`
}

func (ModelChanged) Kind() string { return KindModelChanged }
func (p ModelChanged) validate() error {
	const k = KindModelChanged
	if err := required(k, "new_provider", p.NewProvider); err != nil {
		return err
	}
	if err := required(k, "new_model_id", p.NewModelID); err != nil {
		return err
	}
	if err := required(k, "new_effort", p.NewEffort); err != nil {
		return err
	}
	// The prior tuple is all-present or all-absent.
	priorCount := 0
	for _, v := range []string{p.PriorProvider, p.PriorModelID, p.PriorEffort} {
		if v != "" {
			priorCount++
		}
	}
	if priorCount != 0 && priorCount != 3 {
		return fmt.Errorf("%s: prior_provider, prior_model_id, and prior_effort must be all present or all absent", k)
	}
	return nil
}

// ModelEffortUnsupported records that the configured effort was dropped.
type ModelEffortUnsupported struct {
	Provider         string `json:"provider"`
	ModelID          string `json:"model_id"`
	ConfiguredEffort string `json:"configured_effort"`
}

func (ModelEffortUnsupported) Kind() string { return KindModelEffortUnsupported }
func (p ModelEffortUnsupported) validate() error {
	const k = KindModelEffortUnsupported
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	return required(k, "configured_effort", p.ConfiguredEffort)
}

// ModelRecoveryFailed records a failed model recovery on resume (step 1).
type ModelRecoveryFailed struct {
	Reason      string `json:"reason"`
	ErrorDetail string `json:"error_detail"`
}

func (ModelRecoveryFailed) Kind() string { return KindModelRecoveryFailed }
func (p ModelRecoveryFailed) validate() error {
	const k = KindModelRecoveryFailed
	if err := enum(k, "reason", p.Reason, set("shape_check_failed", "validation_failed")); err != nil {
		return err
	}
	return required(k, "error_detail", p.ErrorDetail)
}

// ModelPersistFailed records a failed per-project model write (step 1).
type ModelPersistFailed struct {
	TargetPath    string `json:"target_path"`
	Provider      string `json:"provider"`
	ModelID       string `json:"model_id"`
	Effort        string `json:"effort"`
	Reason        string `json:"reason"`
	ErrorCategory string `json:"error_category,omitempty"`
	ErrorDetail   string `json:"error_detail"`
}

func (ModelPersistFailed) Kind() string { return KindModelPersistFailed }
func (p ModelPersistFailed) validate() error {
	return modelPersistFields(KindModelPersistFailed, p.TargetPath, p.Provider, p.ModelID, p.Effort, p.Reason, p.ErrorCategory, p.ErrorDetail)
}

// ModelGlobalMirrorFailed records a failed global mirror write (step 2).
type ModelGlobalMirrorFailed struct {
	TargetPath    string `json:"target_path"`
	Provider      string `json:"provider"`
	ModelID       string `json:"model_id"`
	Effort        string `json:"effort"`
	Reason        string `json:"reason"`
	ErrorCategory string `json:"error_category,omitempty"`
	ErrorDetail   string `json:"error_detail"`
}

func (ModelGlobalMirrorFailed) Kind() string { return KindModelGlobalMirrorFailed }
func (p ModelGlobalMirrorFailed) validate() error {
	return modelPersistFields(KindModelGlobalMirrorFailed, p.TargetPath, p.Provider, p.ModelID, p.Effort, p.Reason, p.ErrorCategory, p.ErrorDetail)
}

type ModelCatalogRefreshed struct {
	Provider string `json:"provider"`
	Outcome  string `json:"outcome"`
}

func (ModelCatalogRefreshed) Kind() string { return KindModelCatalogRefreshed }
func (p ModelCatalogRefreshed) validate() error {
	const k = KindModelCatalogRefreshed
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	return enum(k, "outcome", p.Outcome, set("updated", "no_change", "failed"))
}

// InteractionMode records the active interaction mode at session start and on every
// mode switch, mirroring model_turn. It is an additive event
// kind — non-breaking schema-version semantics.
type InteractionMode struct {
	Mode    string `json:"mode"`
	Source  string `json:"source"`
	Trigger string `json:"trigger"`
}

func (InteractionMode) Kind() string { return KindInteractionMode }
func (p InteractionMode) validate() error {
	const k = KindInteractionMode
	if err := enum(k, "mode", p.Mode, set("plan", "build", "auto_edits")); err != nil {
		return err
	}
	if err := enum(k, "source", p.Source, set("default", "config", "user_command")); err != nil {
		return err
	}
	return enum(k, "trigger", p.Trigger, set("launch", "resume", "clear", "user_command"))
}

// SlashCommand records execution of a recognized slash command.
type SlashCommand struct {
	Name        string   `json:"name"`
	Args        []string `json:"args"`
	Outcome     string   `json:"outcome"`
	ErrorDetail string   `json:"error_detail,omitempty"`
}

func (SlashCommand) Kind() string { return KindSlashCommand }
func (p SlashCommand) validate() error {
	const k = KindSlashCommand
	if err := required(k, "name", p.Name); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, set("success", "error")); err != nil {
		return err
	}
	// error_detail is required iff outcome == error.
	if p.Outcome == "error" && p.ErrorDetail == "" {
		return fmt.Errorf("%s: error_detail is required when outcome is error", k)
	}
	if p.Outcome == "success" && p.ErrorDetail != "" {
		return fmt.Errorf("%s: error_detail is forbidden when outcome is success", k)
	}
	return nil
}

// StreamInterrupted records a user-initiated interruption of a model response.
type StreamInterrupted struct {
	Source       string `json:"source"`
	ContentChars int64  `json:"content_chars"`
}

func (StreamInterrupted) Kind() string { return KindStreamInterrupted }
func (p StreamInterrupted) validate() error {
	const k = KindStreamInterrupted
	if err := enum(k, "source", p.Source, set("esc", "ctrl-c", "slash_clear", "slash_resume_switch")); err != nil {
		return err
	}
	return nonNegative(k, "content_chars", p.ContentChars)
}

// ProviderRequestFailed records a provider request failure before a usable
// response.
type ProviderRequestFailed struct {
	Provider             string `json:"provider"`
	ModelID              string `json:"model_id"`
	Phase                string `json:"phase"`
	HTTPStatus           *int64 `json:"http_status,omitempty"`
	PartialResponseChars int64  `json:"partial_response_chars"`
	Reason               string `json:"reason"`
	ErrorDetail          string `json:"error_detail"`
}

func (ProviderRequestFailed) Kind() string { return KindProviderRequestFailed }
func (p ProviderRequestFailed) validate() error {
	const k = KindProviderRequestFailed
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	reasons, ok := providerReasons[p.Phase]
	if !ok {
		return fmt.Errorf("%s.phase: %q is not one of dial/tls/http/decode/stream_drop/empty_response", k, p.Phase)
	}
	if !reasons[p.Reason] {
		return fmt.Errorf("%s.reason: %q is not valid for phase %q", k, p.Reason, p.Phase)
	}
	if err := required(k, "error_detail", p.ErrorDetail); err != nil {
		return err
	}
	// http_status presence is pinned by (phase, reason).
	switch {
	case p.Phase == "http" && p.Reason == "http_no_body":
		if p.HTTPStatus == nil {
			return fmt.Errorf("%s: http_status is required when phase=http and reason=http_no_body", k)
		}
	case p.Phase == "http" && p.Reason == "http_error":
		// The non-2xx HTTP-error path records the response status it keys on.
		if p.HTTPStatus == nil {
			return fmt.Errorf("%s: http_status is required when phase=http and reason=http_error", k)
		}
	case p.Phase == "http" && p.Reason == "http_truncated":
		// optional: present iff a status line was received before truncation.
	default:
		if p.HTTPStatus != nil {
			return fmt.Errorf("%s: http_status is forbidden for phase %q reason %q", k, p.Phase, p.Reason)
		}
	}
	// partial_response_chars is meaningful only for stream_drop.
	if p.Phase != "stream_drop" && p.PartialResponseChars != 0 {
		return fmt.Errorf("%s: partial_response_chars must be 0 unless phase is stream_drop", k)
	}
	if err := nonNegative(k, "partial_response_chars", p.PartialResponseChars); err != nil {
		return err
	}
	return nil
}

// TurnLatency records the end-to-end wall-clock latency of one completed,
// user-visible turn: the elapsed time from the point the user's input was
// accepted to the point the final answer was committed. One is recorded
// per completed agentic turn, on the final no-tool answer — failed or
// interrupted turns record none. duration_ms is int64 milliseconds, matching the
// tool_exec_end.duration_ms / session_prune_summary.elapsed_ms convention.
type TurnLatency struct {
	Provider   string `json:"provider"`
	ModelID    string `json:"model_id"`
	DurationMs int64  `json:"duration_ms"`
}

func (TurnLatency) Kind() string { return KindTurnLatency }
func (p TurnLatency) validate() error {
	const k = KindTurnLatency
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	return nonNegative(k, "duration_ms", p.DurationMs)
}

// ProviderRoundTrip records the wall-clock latency of one provider round: the
// time around a single model call, from just before the request to the round's
// terminal outcome — a final answer, a tool-call handoff, an empty-response
// classification, a stream drop, or a pre-stream failure. An agentic turn
// records one per provider round. It is recorded even when the round fails, so a
// slow failure is visible alongside the paired provider_request_failed event.
// duration_ms is int64 milliseconds, matching the existing duration convention.
type ProviderRoundTrip struct {
	Provider         string `json:"provider"`
	ModelID          string `json:"model_id"`
	DurationMs       int64  `json:"duration_ms"`
	TurnID           string `json:"turn_id,omitempty"`
	RoundID          string `json:"round_id,omitempty"`
	UpstreamProvider string `json:"upstream_provider,omitempty"`
	Chunks           int64  `json:"chunks,omitempty"`
	ReasoningChars   int64  `json:"reasoning_chars,omitempty"`
}

func (ProviderRoundTrip) Kind() string { return KindProviderRoundTrip }
func (p ProviderRoundTrip) validate() error {
	const k = KindProviderRoundTrip
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if err := nonNegative(k, "duration_ms", p.DurationMs); err != nil {
		return err
	}
	if err := nonNegative(k, "chunks", p.Chunks); err != nil {
		return err
	}
	if err := nonNegative(k, "reasoning_chars", p.ReasoningChars); err != nil {
		return err
	}
	if p.TurnID == "" && p.RoundID == "" {
		return nil
	}
	if p.TurnID == "" || p.RoundID == "" {
		return fmt.Errorf("%s: turn_id and round_id must be both present or both absent", k)
	}
	if err := validV7(k, "turn_id", p.TurnID); err != nil {
		return err
	}
	return validV7(k, "round_id", p.RoundID)
}

// ProviderRequestRetry records one scheduled auto-retry of a transient
// provider-round failure. It is appended and flushed before the
// backoff wait, so a failed attempt is durable even if the process exits during
// the wait. attempt is the 1-based number of the attempt that just failed and is
// being retried; phase/reason carry the classified failure; delay_ms is the
// backoff (or honored Retry-After) wait in milliseconds; partial_chars_discarded
// is the assistant-content runes rolled back before re-issue and is meaningful
// only for a stream_drop (0 otherwise). The terminal provider_request_failed is
// unchanged, so the attempt count is reconstructed from these events.
type ProviderRequestRetry struct {
	Provider              string `json:"provider"`
	ModelID               string `json:"model_id"`
	Attempt               int64  `json:"attempt"`
	Phase                 string `json:"phase"`
	Reason                string `json:"reason"`
	DelayMs               int64  `json:"delay_ms"`
	PartialCharsDiscarded int64  `json:"partial_chars_discarded"`
}

func (ProviderRequestRetry) Kind() string { return KindProviderRequestRetry }
func (p ProviderRequestRetry) validate() error {
	const k = KindProviderRequestRetry
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	// attempt is the 1-based number of the failed attempt being retried, so it is
	// always >= 1 (a turn's first attempt is attempt 1).
	if p.Attempt < 1 {
		return fmt.Errorf("%s.attempt: must be >= 1, got %d", k, p.Attempt)
	}
	reasons, ok := retryReasons(p.Phase)
	if !ok {
		return fmt.Errorf("%s.phase: %q is not one of dial/tls/http/decode/stream_drop/empty_response/tool_handoff", k, p.Phase)
	}
	if !reasons[p.Reason] {
		return fmt.Errorf("%s.reason: %q is not valid for phase %q", k, p.Reason, p.Phase)
	}
	if err := nonNegative(k, "delay_ms", p.DelayMs); err != nil {
		return err
	}
	// partial_chars_discarded mirrors provider_request_failed.partial_response_chars:
	// it is meaningful only for a discard-and-restart of a partial stream_drop.
	if p.Phase != "stream_drop" && p.PartialCharsDiscarded != 0 {
		return fmt.Errorf("%s: partial_chars_discarded must be 0 unless phase is stream_drop", k)
	}
	return nonNegative(k, "partial_chars_discarded", p.PartialCharsDiscarded)
}

// ProviderRequestRetrySkipped records that a classified retryable provider-round
// failure was not scheduled for another attempt. attempt is the 1-based number of the
// attempt that just failed; phase/reason reuse the provider_request_failed taxonomy
// so a skip only ever records a (phase, reason) the classifier can produce;
// skip_reason is the closed set explaining why no retry followed; partial_chars_discarded is the assistant-content runes rolled back
// and is meaningful only for a stream_drop (0 otherwise). HTTP retryability stays
// emitter-enforced (via provider.Retryable in the retry loop), so there is no
// http_status field — mirroring provider_request_retry.
type ProviderRequestRetrySkipped struct {
	Provider              string `json:"provider"`
	ModelID               string `json:"model_id"`
	Attempt               int64  `json:"attempt"`
	Phase                 string `json:"phase"`
	Reason                string `json:"reason"`
	SkipReason            string `json:"skip_reason"`
	PartialCharsDiscarded int64  `json:"partial_chars_discarded"`
}

func (ProviderRequestRetrySkipped) Kind() string { return KindProviderRequestRetrySkipped }
func (p ProviderRequestRetrySkipped) validate() error {
	const k = KindProviderRequestRetrySkipped
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if p.Attempt < 1 {
		return fmt.Errorf("%s.attempt: must be >= 1, got %d", k, p.Attempt)
	}
	reasons, ok := retryReasons(p.Phase)
	if !ok {
		return fmt.Errorf("%s.phase: %q is not one of dial/tls/http/decode/stream_drop/empty_response/tool_handoff", k, p.Phase)
	}
	if !reasons[p.Reason] {
		return fmt.Errorf("%s.reason: %q is not valid for phase %q", k, p.Reason, p.Phase)
	}
	if err := enum(k, "skip_reason", p.SkipReason, retrySkipReasons); err != nil {
		return err
	}
	if p.Phase != "stream_drop" && p.PartialCharsDiscarded != 0 {
		return fmt.Errorf("%s: partial_chars_discarded must be 0 unless phase is stream_drop", k)
	}
	return nonNegative(k, "partial_chars_discarded", p.PartialCharsDiscarded)
}

// SuggestFollowupDebug records one ordered stage of the development-only
// suggest_followup trace. provider/model_id/mode identify the turn that
// produced it. The remaining fields are stage-specific and deliberately
// privacy-safe: advertised is set only on request_built (was the tool in the
// advertised set), label_len/prompt_len carry rune lengths — never the suggestion
// text — on the stages that handle a concrete suggestion, and reason explains a
// discard on ghost_cleared. Persisting lengths and booleans rather than the
// label/prompt keeps the follow-up suggestion's ephemeral UI text out of the record.
type SuggestFollowupDebug struct {
	Stage      string `json:"stage"`
	Provider   string `json:"provider"`
	ModelID    string `json:"model_id"`
	Mode       string `json:"mode"`
	Advertised *bool  `json:"advertised,omitempty"`
	LabelLen   int64  `json:"label_len,omitempty"`
	PromptLen  int64  `json:"prompt_len,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func (SuggestFollowupDebug) Kind() string { return KindSuggestFollowupDebug }
func (p SuggestFollowupDebug) validate() error {
	const k = KindSuggestFollowupDebug
	if err := enum(k, "stage", p.Stage, suggestFollowupStages); err != nil {
		return err
	}
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if err := required(k, "mode", p.Mode); err != nil {
		return err
	}
	if err := nonNegative(k, "label_len", p.LabelLen); err != nil {
		return err
	}
	if err := nonNegative(k, "prompt_len", p.PromptLen); err != nil {
		return err
	}
	// advertised records whether suggest_followup was in the round's advertised tool
	// set, which is only meaningful when the request was just built. Requiring it
	// exactly on request_built keeps "not advertised" (advertised=false) distinct from
	// "field not applicable" (omitted) on every other stage.
	if p.Stage == SuggestFollowupStageRequestBuilt {
		if p.Advertised == nil {
			return fmt.Errorf("%s.advertised: required on stage %q", k, p.Stage)
		}
	} else if p.Advertised != nil {
		return fmt.Errorf("%s.advertised: only valid on stage %q", k, SuggestFollowupStageRequestBuilt)
	}
	// reason explains why a pending suggestion was discarded; it belongs only on
	// ghost_cleared, where it is required so a cleared trace always says why.
	if p.Stage == SuggestFollowupStageGhostCleared {
		if err := required(k, "reason", p.Reason); err != nil {
			return err
		}
	} else if p.Reason != "" {
		return fmt.Errorf("%s.reason: only valid on stage %q", k, SuggestFollowupStageGhostCleared)
	}
	return nil
}

type QueuedPromptDiscarded struct {
	Text       string `json:"text"`
	ImageCount int64  `json:"image_count"`
	Reason     string `json:"reason"`
}

func (QueuedPromptDiscarded) Kind() string { return KindQueuedPromptDiscarded }
func (p QueuedPromptDiscarded) validate() error {
	const k = KindQueuedPromptDiscarded
	if err := enum(k, "reason", p.Reason, discardReasons); err != nil {
		return err
	}
	if err := nonNegative(k, "image_count", p.ImageCount); err != nil {
		return err
	}
	if p.Text == "" && p.ImageCount == 0 {
		return fmt.Errorf("%s: text or a positive image_count is required", k)
	}
	return nil
}

type ProviderStreamIdle struct {
	Provider       string `json:"provider"`
	ModelID        string `json:"model_id"`
	RoundElapsedMs int64  `json:"round_elapsed_ms"`
	IdleMs         int64  `json:"idle_ms"`
	PartialChars   int64  `json:"partial_chars"`
}

func (ProviderStreamIdle) Kind() string { return KindProviderStreamIdle }
func (p ProviderStreamIdle) validate() error {
	const k = KindProviderStreamIdle
	if err := required(k, "provider", p.Provider); err != nil {
		return err
	}
	if err := required(k, "model_id", p.ModelID); err != nil {
		return err
	}
	if err := nonNegative(k, "round_elapsed_ms", p.RoundElapsedMs); err != nil {
		return err
	}
	if err := nonNegative(k, "idle_ms", p.IdleMs); err != nil {
		return err
	}
	return nonNegative(k, "partial_chars", p.PartialChars)
}

type StructuredReadStart struct {
	ToolName              string `json:"tool_name"`
	PathScope             string `json:"path_scope"`
	InvocationID          string `json:"invocation_id"`
	ConfiguredConcurrency int64  `json:"configured_concurrency"`
	// See ToolExecStart.ChildInvocationID. A child agent's read tools run through the
	// structured-read path rather than tool_exec_*, so this is where their attribution lives.
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

func (StructuredReadStart) Kind() string { return KindStructuredReadStart }
func (p StructuredReadStart) validate() error {
	const k = KindStructuredReadStart
	if err := enum(k, "tool_name", p.ToolName, structuredReadToolNames); err != nil {
		return err
	}
	if err := absCleanPath(k, "path_scope", p.PathScope); err != nil {
		return err
	}
	if err := validV7(k, "invocation_id", p.InvocationID); err != nil {
		return err
	}
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	if p.ConfiguredConcurrency < 1 {
		return fmt.Errorf("%s.configured_concurrency: must be >= 1, got %d", k, p.ConfiguredConcurrency)
	}
	return nil
}

type StructuredReadEnd struct {
	ToolName     string `json:"tool_name"`
	InvocationID string `json:"invocation_id"`
	Outcome      string `json:"outcome"`
	DurationMs   int64  `json:"duration_ms"`
	// See StructuredReadStart.ChildInvocationID.
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

func (StructuredReadEnd) Kind() string { return KindStructuredReadEnd }
func (p StructuredReadEnd) validate() error {
	const k = KindStructuredReadEnd
	if err := enum(k, "tool_name", p.ToolName, structuredReadToolNames); err != nil {
		return err
	}
	if err := validV7(k, "invocation_id", p.InvocationID); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, structuredReadOutcomes); err != nil {
		return err
	}
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	return nonNegative(k, "duration_ms", p.DurationMs)
}

type StructuredReadRefused struct {
	ToolName  string `json:"tool_name"`
	Reason    string `json:"reason"`
	BatchSize int64  `json:"batch_size"`
	// See StructuredReadStart.ChildInvocationID. A refusal is child activity too: without it a
	// child's rejected read is indistinguishable from the parent's.
	ChildInvocationID string `json:"child_invocation_id,omitempty"`
}

func (StructuredReadRefused) Kind() string { return KindStructuredReadRefused }

// tool_name is deliberately not held to structuredReadToolNames: a refusal records the
// name the model actually called, which is often one the read allowlist excludes.
func (p StructuredReadRefused) validate() error {
	const k = KindStructuredReadRefused
	if err := required(k, "tool_name", p.ToolName); err != nil {
		return err
	}
	if err := enum(k, "reason", p.Reason, structuredReadRefusalReasons); err != nil {
		return err
	}
	if err := optionalV7(k, "child_invocation_id", p.ChildInvocationID); err != nil {
		return err
	}
	if p.BatchSize < 1 {
		return fmt.Errorf("%s.batch_size: must be >= 1, got %d", k, p.BatchSize)
	}
	return nil
}

const (
	SecurityDetectionBeforeMutatingCall = "before_mutating_call"
	SecurityDetectionBeforeFinalSuccess = "before_final_success"
	SecurityDetectionStartup            = "startup"
)

var securityDetectionPoints = set(
	SecurityDetectionBeforeMutatingCall,
	SecurityDetectionBeforeFinalSuccess,
	SecurityDetectionStartup,
)

// The section, label, and unavailable-reason vocabularies belong to internal/securitystate
// and internal/locks, but are spelled out here as strings because importing the monitor
// would close an import cycle (securitystate -> trust -> filetools -> events).
// TestSecurityStateHalted_VocabularyMatchesTheMonitor pins these copies to that source.
var (
	securitySectionOrder = []string{
		"permissions", "auth", "provider_destination", "provider_credential",
		"provider_auth_header", "web_research_credential", "declared_commands", "blocked_paths",
		"writable_folders",
	}
	securityLabelOrder       = []string{"added", "removed", "changed", "malformed", "unreadable", "missing"}
	securitySemanticLabels   = set("added", "removed", "changed")
	securityUnavailableCause = set("lock_timeout", "lock_acquire_error")
)

// Field names a settings-drift record must never carry, so a hand-written or
// future-written record cannot smuggle the material the halt exists to keep out. Any
// other unknown field is still ignored, keeping the additive-record contract.
var securityForbiddenFields = set(
	"arguments", "tool_arguments",
	"direct_tokens", "direct_command_subject", "direct_request_subject",
	"api_key", "access_token", "refresh_token", "secret", "credential",
	"provider_credential", "provider_auth_header", "web_research_credential",
	"account_id", "settings", "settings_content",
	"parse_error", "error", "error_detail",
)

// SecurityStateHalted records one protected settings layer whose checkpoint stopped the
// launch or the turn.
type SecurityStateHalted struct {
	Path              string   `json:"path"`
	DetectionPoint    string   `json:"detection_point"`
	Sections          []string `json:"sections,omitempty"`
	Labels            []string `json:"labels,omitempty"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
}

func (SecurityStateHalted) Kind() string { return KindSecurityStateHalted }

func (p SecurityStateHalted) validate() error {
	const k = KindSecurityStateHalted
	if err := absCleanPath(k, "path", p.Path); err != nil {
		return err
	}
	if err := enum(k, "detection_point", p.DetectionPoint, securityDetectionPoints); err != nil {
		return err
	}
	if err := fixedOrderSubset(k, "sections", p.Sections, securitySectionOrder); err != nil {
		return err
	}
	if err := fixedOrderSubset(k, "labels", p.Labels, securityLabelOrder); err != nil {
		return err
	}
	if p.UnavailableReason != "" {
		if err := enum(k, "unavailable_reason", p.UnavailableReason, securityUnavailableCause); err != nil {
			return err
		}
		if len(p.Sections) > 0 || len(p.Labels) > 0 {
			return fmt.Errorf("%s: an uninspectable layer carries no sections or labels", k)
		}
		return nil
	}
	return p.validateInspected(k)
}

func (p SecurityStateHalted) validateInspected(k string) error {
	semantic := 0
	for _, label := range p.Labels {
		if securitySemanticLabels[label] {
			semantic++
		}
	}
	switch {
	case len(p.Labels) == 0:
		return fmt.Errorf("%s.labels: required unless unavailable_reason is present", k)
	case semantic > 0 && semantic < len(p.Labels):
		return fmt.Errorf("%s.labels: semantic drift and a non-projectable layer cannot be recorded together", k)
	case semantic == 0 && len(p.Labels) > 1:
		return fmt.Errorf("%s.labels: a non-projectable layer carries exactly one label", k)
	case semantic == 0 && len(p.Sections) > 0:
		return fmt.Errorf("%s.sections: %q names no protected section", k, p.Labels[0])
	case semantic > 0 && len(p.Sections) == 0:
		return fmt.Errorf("%s.sections: required when labels name semantic drift", k)
	}
	return nil
}

const fnEmitSecurityStateHalt = "events.EmitSecurityStateHalt"

// EmitSecurityStateHalt makes one checkpoint's halt durable in a single store commit; a
// startup checkpoint has no started round to close and passes a nil terminal. A returned
// error means the halt was not recorded, and the caller must still stop the turn rather than
// treat the records as durable or present a recorded halt.
func EmitSecurityStateHalt(ctx context.Context, store *sessions.Store, records []SecurityStateHalted, terminal *TurnTerminal, onWriteFailure WriteFailureHandler) error {
	if err := checkSecurityHaltRecords(records, terminal); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("%s: nil store", fnEmitSecurityStateHalt)
	}
	batch := make([]sessions.Record, 0, len(records)+1)
	for _, record := range records {
		ev, err := Build(record)
		if err != nil {
			return err
		}
		batch = append(batch, ev)
	}
	if terminal != nil {
		ev, err := Build(*terminal)
		if err != nil {
			return err
		}
		batch = append(batch, ev)
	}
	cat, reason, err := commitStore(context.WithoutCancel(ctx), store, batch...)
	if err != nil && reason != sessions.ReasonNone && onWriteFailure != nil {
		onWriteFailure(cat, reason, err)
	}
	return err
}

func checkSecurityHaltRecords(records []SecurityStateHalted, terminal *TurnTerminal) error {
	const fn = fnEmitSecurityStateHalt
	if len(records) == 0 {
		return fmt.Errorf("%s: no affected layer to record", fn)
	}
	for _, record := range records {
		if err := record.validate(); err != nil {
			return err
		}
		if record.DetectionPoint != records[0].DetectionPoint {
			return fmt.Errorf("%s: one checkpoint records one detection point", fn)
		}
	}
	startup := records[0].DetectionPoint == SecurityDetectionStartup
	switch {
	case startup && terminal != nil:
		return fmt.Errorf("%s: a %q halt closes no provider round", fn, SecurityDetectionStartup)
	case !startup && terminal == nil:
		return fmt.Errorf("%s: an in-turn halt must close its provider round", fn)
	case terminal != nil && terminal.Outcome != TurnOutcomeSecurityHalted:
		return fmt.Errorf("%s: terminal outcome is %q, want %q", fn, terminal.Outcome, TurnOutcomeSecurityHalted)
	}
	if terminal != nil {
		return terminal.validate()
	}
	return nil
}

// --- Load-time dispatch -----------------------------------------------------

// ValidatePayload is the exported load-time validator: it unmarshals raw into
// the struct for kind and runs that kind's cross-field validation. Load
// orchestration combines this with the session spine validation without
// internal/sessions importing this package. An unknown kind is an error so a
// codemeld-written record stream is held to the closed set.
func ValidatePayload(kind string, raw json.RawMessage) error {
	p, err := unmarshalPayload(kind, raw)
	if err != nil {
		return err
	}
	if pm, ok := p.(PermissionMatched); ok {
		return pm.validateLoad()
	}
	return p.validate()
}

// unmarshalPayload decodes raw into the payload struct for kind. Unknown JSON
// fields are ignored per the forward-compatibility rule; a type mismatch
// (e.g. a string where an integer is required) surfaces as a decode error; and
// an absent required field (one the canonical wire form always carries) is
// rejected by decode so a missing number/bool/list cannot masquerade as a zero.
func unmarshalPayload(kind string, raw json.RawMessage) (EventPayload, error) {
	switch kind {
	case KindLaunchBegan:
		return decode[LaunchBegan](kind, raw)
	case KindExecutionCapability:
		return decode[ExecutionCapability](kind, raw)
	case KindSessionForked:
		return decode[SessionForked](kind, raw)
	case KindPermissionPromptShown:
		return decode[PermissionPromptShown](kind, raw)
	case KindPermissionDecision:
		return decode[PermissionDecision](kind, raw)
	case KindPermissionMatched:
		return decode[PermissionMatched](kind, raw)
	case KindPermissionPromptWait:
		return decode[PermissionPromptWait](kind, raw)
	case KindToolExecStart:
		return decode[ToolExecStart](kind, raw)
	case KindToolExecEnd:
		return decode[ToolExecEnd](kind, raw)
	case KindAgentInstructionsLoaded:
		return decode[AgentInstructionsLoaded](kind, raw)
	case KindSessionPruneSummary:
		return decode[SessionPruneSummary](kind, raw)
	case KindSessionWriteFailed:
		return decode[SessionWriteFailed](kind, raw)
	case KindPermissionPersistFailed:
		return decode[PermissionPersistFailed](kind, raw)
	case KindPermissionRevokeRequested:
		return decode[PermissionRevokeRequested](kind, raw)
	case KindPermissionSystemOneCheck:
		return decode[PermissionSystemOneCheck](kind, raw)
	case KindModelTurn:
		return decode[ModelTurn](kind, raw)
	case KindModelResponse:
		return decode[ModelResponse](kind, raw)
	case KindModelChanged:
		return decode[ModelChanged](kind, raw)
	case KindModelEffortUnsupported:
		return decode[ModelEffortUnsupported](kind, raw)
	case KindModelRecoveryFailed:
		return decode[ModelRecoveryFailed](kind, raw)
	case KindModelPersistFailed:
		return decode[ModelPersistFailed](kind, raw)
	case KindModelGlobalMirrorFailed:
		return decode[ModelGlobalMirrorFailed](kind, raw)
	case KindModelCatalogRefreshed:
		return decode[ModelCatalogRefreshed](kind, raw)
	case KindSlashCommand:
		return decode[SlashCommand](kind, raw)
	case KindStreamInterrupted:
		return decode[StreamInterrupted](kind, raw)
	case KindProviderRequestFailed:
		return decode[ProviderRequestFailed](kind, raw)
	case KindInteractionMode:
		return decode[InteractionMode](kind, raw)
	case KindTurnLatency:
		return decode[TurnLatency](kind, raw)
	case KindProviderRoundTrip:
		return decode[ProviderRoundTrip](kind, raw)
	case KindProviderRequestRetry:
		return decode[ProviderRequestRetry](kind, raw)
	case KindProviderRequestRetrySkipped:
		return decode[ProviderRequestRetrySkipped](kind, raw)
	case KindSuggestFollowupDebug:
		return decode[SuggestFollowupDebug](kind, raw)
	case KindQueuedPromptDiscarded:
		return decode[QueuedPromptDiscarded](kind, raw)
	case KindProviderStreamIdle:
		return decode[ProviderStreamIdle](kind, raw)
	case KindStructuredReadStart:
		return decode[StructuredReadStart](kind, raw)
	case KindStructuredReadEnd:
		return decode[StructuredReadEnd](kind, raw)
	case KindStructuredReadRefused:
		return decode[StructuredReadRefused](kind, raw)
	case KindChildAgentStart:
		return decode[ChildAgentStart](kind, raw)
	case KindChildAgentEnd:
		return decode[ChildAgentEnd](kind, raw)
	case KindSkillLoaded:
		return decode[SkillLoaded](kind, raw)
	case KindTurnTerminal:
		return decodeTurnTerminal(kind, raw)
	case KindSecurityStateHalted:
		return decodeSecurityStateHalted(kind, raw)
	default:
		return nil, fmt.Errorf("unknown event kind %q", kind)
	}
}

func decode[T EventPayload](kind string, raw json.RawMessage) (EventPayload, error) {
	var p T
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	if err := requirePresent(kind, raw, reflect.TypeFor[T]()); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeTurnTerminal(kind string, raw json.RawMessage) (EventPayload, error) {
	var p TurnTerminal
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	for name := range fields {
		if name == "response_text" || name == "tool_arguments" || name == "secret" {
			return nil, fmt.Errorf("%s: forbidden field %q", kind, name)
		}
	}
	if err := requirePresent(kind, raw, reflect.TypeFor[TurnTerminal]()); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeSecurityStateHalted(kind string, raw json.RawMessage) (EventPayload, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	for name := range fields {
		if securityForbiddenFields[name] {
			return nil, fmt.Errorf("%s: forbidden field %q", kind, name)
		}
	}
	return decode[SecurityStateHalted](kind, raw)
}

// requirePresent rejects a load-time record that omits or nulls any field the
// canonical wire form of t always carries (every field whose json tag lacks
// omitempty). Decoding alone cannot catch these: an absent or JSON-null number,
// bool, list, or nested object unmarshals to a zero value indistinguishable from
// an explicit 0/false/[]/{}, so presence and non-nullness are checked against
// the raw JSON. It recurses into nested objects and list elements so a required
// subfield (e.g. original_bytes.stderr) and a required list-element field (e.g.
// failures.path) cannot be omitted or nulled either.
func requirePresent(kind string, raw json.RawMessage, t reflect.Type) error {
	return requireShape(kind, raw, t)
}

// requireShape walks the JSON value raw against the Go type t, enforcing that
// every required (non-omitempty) struct field is present and non-null and
// recursing through nested struct and struct-element-slice fields. path is the
// dotted field path used in error messages. Optional fields may be absent or
// null; when present and non-null they are still recursed into so their own
// required subfields are checked.
func requireShape(path string, raw json.RawMessage, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for i := range t.NumField() {
			f := t.Field(i)
			name, optional := jsonFieldName(f)
			if name == "" {
				continue
			}
			child := path + "." + name
			fieldRaw, ok := fields[name]
			if !ok {
				if optional {
					continue
				}
				return fmt.Errorf("%s: required field is absent", child)
			}
			// The canonical writer never emits null for any field (omitempty
			// fields are omitted, not nulled, when empty), so a present null is
			// non-canonical for an optional field just as for a required one.
			if isJSONNull(fieldRaw) {
				if optional {
					return fmt.Errorf("%s: optional field must be omitted, not null", child)
				}
				return fmt.Errorf("%s: required field is null", child)
			}
			// An optional string is omitted when empty, so a present empty string
			// is non-canonical and would be indistinguishable from absence to the
			// per-kind validators (e.g. model_changed.prior_* counted as absent,
			// slash_command.error_detail treated as omitted on success). Reject it
			// at load time so the validators only ever see true presence.
			if optional && derefKind(f.Type) == reflect.String && isEmptyJSONString(fieldRaw) {
				return fmt.Errorf("%s: optional field must be omitted, not an empty string", child)
			}
			if err := requireShape(child, fieldRaw, f.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		elem := t.Elem()
		et := elem
		for et.Kind() == reflect.Pointer {
			et = et.Elem()
		}
		if et.Kind() != reflect.Struct {
			return nil // slice of scalars: no nested required fields to check
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for i, item := range items {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			if isJSONNull(item) {
				return fmt.Errorf("%s: required element is null", elemPath)
			}
			if err := requireShape(elemPath, item, elem); err != nil {
				return err
			}
		}
	}
	return nil
}

// isJSONNull reports whether raw is the JSON null literal.
func isJSONNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

// isEmptyJSONString reports whether raw is a JSON string with no characters.
func isEmptyJSONString(raw json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	return s == ""
}

// derefKind returns t's kind after following any pointer indirection.
func derefKind(t reflect.Type) reflect.Kind {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind()
}

// jsonFieldName returns f's wire name and whether it is optional (omitempty). A
// field tagged json:"-" yields an empty name so callers skip it.
func jsonFieldName(f reflect.StructField) (name string, optional bool) {
	name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "-" {
		return "", false
	}
	if name == "" {
		name = f.Name
	}
	for opt := range strings.SplitSeq(opts, ",") {
		if opt == "omitempty" {
			optional = true
		}
	}
	return name, optional
}

// --- Shared validation helpers ---------------------------------------------

func set(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

func enum(kind, field, value string, allowed map[string]bool) error {
	if !allowed[value] {
		return fmt.Errorf("%s.%s: %q is not a recognized value", kind, field, value)
	}
	return nil
}

func required(kind, field, value string) error {
	if value == "" {
		return fmt.Errorf("%s.%s: required field is empty", kind, field)
	}
	return nil
}

// validV7 requires a non-empty, canonical UUIDv7 string, rejecting hand-edited
// or non-v7 values for the session/invocation id fields.
func validV7(kind, field, value string) error {
	if value == "" {
		return fmt.Errorf("%s.%s: required field is empty", kind, field)
	}
	if !ids.IsValidV7(value) {
		return fmt.Errorf("%s.%s: %q is not a valid UUIDv7", kind, field, value)
	}
	return nil
}

// optionalV7 keeps absence legal for a field a parent's own event omits, while holding a
// present value to validV7's format.
func optionalV7(kind, field, value string) error {
	if value == "" {
		return nil
	}
	return validV7(kind, field, value)
}

// fixedOrderSubset requires values to appear in order's own sequence, which rejects an
// unknown token, a duplicate, and a reordering in one pass.
func fixedOrderSubset(kind, field string, values, order []string) error {
	next := 0
	for _, value := range values {
		i := slices.Index(order[next:], value)
		if i < 0 {
			return fmt.Errorf("%s.%s: %q is not a recognized value in fixed order", kind, field, value)
		}
		next += i + 1
	}
	return nil
}

func nonNegative(kind, field string, value int64) error {
	if value < 0 {
		return fmt.Errorf("%s.%s: must be >= 0, got %d", kind, field, value)
	}
	return nil
}

func nonNegativeFinite(kind, field string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return fmt.Errorf("%s.%s: must be a finite number >= 0, got %v", kind, field, value)
	}
	return nil
}

// absCleanPath requires a non-empty, cleaned absolute path, rejecting relative
// or unnormalized values for the fields specified as a cleaned absolute
// path (e.g. tool_exec_start.path_scope, agent_instructions_loaded.path,
// the *_failed target paths, and prune-failure paths).
func absCleanPath(kind, field, value string) error {
	if value == "" {
		return fmt.Errorf("%s.%s: required field is empty", kind, field)
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("%s.%s: %q is not a cleaned absolute path", kind, field, value)
	}
	return nil
}

// requestPathScope validates a request's resolved path scope, which is always a
// cleaned absolute path and never "*" (for prompt_shown/decision).
func requestPathScope(kind, value string) error {
	if value == "" {
		return fmt.Errorf("%s.path_scope: required field is empty", kind)
	}
	if value == "*" {
		return fmt.Errorf("%s.path_scope: must be a concrete path, never \"*\"", kind)
	}
	return absCleanPath(kind, "path_scope", value)
}

// grantPathScopePairing enforces the pairing the events mirror: a global
// grant carries path_scope "*", and a folder/session grant carries a cleaned
// absolute path (never "*").
func grantPathScopePairing(kind, grantKind, grantPathScope string) error {
	return pathScopePairing(kind, "grant_path_scope", grantKind, grantPathScope)
}

func pathScopePairing(kind, field, grantKind, pathScope string) error {
	if pathScope == "" {
		return fmt.Errorf("%s.%s: required when a grant is present", kind, field)
	}
	if grantKind == "global" {
		if pathScope != "*" {
			return fmt.Errorf("%s: %s must be \"*\" when grant_kind is global", kind, field)
		}
		return nil
	}
	if pathScope == "*" {
		return fmt.Errorf("%s: %s \"*\" requires grant_kind global", kind, field)
	}
	return absCleanPath(kind, field, pathScope)
}

func hostRequestFields(kind, subject, hostScope, pathScope string) error {
	if !hostSubjects[subject] {
		return fmt.Errorf("%s.subject: %q is not one of web_search, web_fetch", kind, subject)
	}
	if pathScope != "" {
		return fmt.Errorf("%s: path_scope must be absent when subject_kind is %q", kind, subjectKindHost)
	}
	return canonicalHostScope(kind, "host_scope", hostScope)
}

func grantHostScopePairing(kind, hostScope, grantHostScope string) error {
	if err := canonicalHostScope(kind, "grant_host_scope", grantHostScope); err != nil {
		return err
	}
	if grantHostScope != hostScope {
		return fmt.Errorf("%s: grant_host_scope %q must equal host_scope %q", kind, grantHostScope, hostScope)
	}
	return nil
}

var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

func canonicalHostScope(kind, field, value string) error {
	if value == "" {
		return fmt.Errorf("%s.%s: required field is empty", kind, field)
	}
	if value == "*" {
		return fmt.Errorf("%s.%s: must be one exact host, never \"*\"", kind, field)
	}
	canonical, err := canonicalHost(value)
	if err != nil {
		return fmt.Errorf("%s.%s: %q is not a canonical host: %w", kind, field, value, err)
	}
	if canonical != value {
		return fmt.Errorf("%s.%s: %q is not a canonical host, want %q", kind, field, value, canonical)
	}
	return nil
}

// Avoid an import cycle: permissions' in-package tests import events.
func canonicalHost(value string) (string, error) {
	trimmed := strings.TrimSuffix(value, ".")
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String(), nil
	}
	return hostProfile.ToASCII(trimmed)
}

func rejectHostFields(kind, hostScope, grantHostScope string) error {
	if hostScope != "" || grantHostScope != "" {
		return fmt.Errorf("%s: host_scope and grant_host_scope are only present when subject_kind is %q", kind, subjectKindHost)
	}
	return nil
}

// persistReasonFields validates the reason/error_category/error_detail trio
// shared by session_write_failed (via its own inline checks) and the
// permission/model persist-failure events.
func persistReasonFields(kind, reason, errorCategory, errorDetail string) error {
	if !persistReasons[reason] {
		return fmt.Errorf("%s.reason: %q is not a req-200 persist failure reason", kind, reason)
	}
	if reasonsWithoutCategory[reason] {
		if errorCategory != "" {
			return fmt.Errorf("%s: error_category must be absent when reason is %q", kind, reason)
		}
	} else if !errorCategories[errorCategory] {
		return fmt.Errorf("%s.error_category: %q is not a req-40b error category (required for reason %q)", kind, errorCategory, reason)
	}
	if errorDetail == "" {
		return fmt.Errorf("%s.error_detail: required field is empty", kind)
	}
	if reason == "lock_timeout" && errorDetail != lockTimeoutDetail {
		return fmt.Errorf("%s.error_detail: must be %q when reason is lock_timeout", kind, lockTimeoutDetail)
	}
	return nil
}

func modelPersistFields(kind, targetPath, provider, modelID, effort, reason, errorCategory, errorDetail string) error {
	if err := absCleanPath(kind, "target_path", targetPath); err != nil {
		return err
	}
	if err := required(kind, "provider", provider); err != nil {
		return err
	}
	if err := required(kind, "model_id", modelID); err != nil {
		return err
	}
	if err := required(kind, "effort", effort); err != nil {
		return err
	}
	return persistReasonFields(kind, reason, errorCategory, errorDetail)
}
