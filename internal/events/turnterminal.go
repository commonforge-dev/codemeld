package events

import (
	"context"
	"fmt"
	"regexp"

	"codemeld.dev/codemeld/internal/sessions"
)

const (
	TurnOutcomeCompleted          = "completed"
	TurnOutcomeCancelled          = "cancelled"
	TurnOutcomeProviderFailed     = "provider_failed"
	TurnOutcomeInvalidResponse    = "invalid_response"
	TurnOutcomeToolAssemblyFailed = "tool_assembly_failed"
	TurnOutcomeToolPlanInvalid    = "tool_plan_invalid"
	TurnOutcomeDispatchFailed     = "dispatch_failed"
	TurnOutcomeContinuationFailed = "continuation_failed"
	// TurnOutcomeSecurityHalted always names a real started round: a startup checkpoint
	// has none, so it records only security_state_halted and no terminal at all.
	TurnOutcomeSecurityHalted = "security_halted"
)

var turnTerminalOutcomes = set(
	TurnOutcomeCompleted,
	TurnOutcomeCancelled,
	TurnOutcomeProviderFailed,
	TurnOutcomeInvalidResponse,
	TurnOutcomeToolAssemblyFailed,
	TurnOutcomeToolPlanInvalid,
	TurnOutcomeDispatchFailed,
	TurnOutcomeContinuationFailed,
	TurnOutcomeSecurityHalted,
)

const (
	DispatchReasonToolDispatchFailed = "tool_dispatch_failed"
	DispatchReasonPostPlanFailed     = "post_plan_failed"
)

var dispatchFailureReasons = set(
	DispatchReasonToolDispatchFailed,
	DispatchReasonPostPlanFailed,
)

// A frozen retention allowlist, not a mirror of the advertised tool set: a name absent
// here is downgraded to DispatchReasonPostPlanFailed, so a name the model invented can
// never reach the record.
var safeFailedToolNames = set(
	"ask_user", "bash", "create", "delete", "edit", "file_count", "glob", "grep",
	"list", "mkdir", "move", "read", "read_image", "suggest_followup", "tree",
	"web_fetch", "web_search",
	"vcs_add", "vcs_branch_create", "vcs_branch_current", "vcs_branch_switch",
	"vcs_commit", "vcs_diff", "vcs_is_clean", "vcs_log", "vcs_merge_status",
	"vcs_rebase_status", "vcs_restore_file", "vcs_stash", "vcs_stash_pop", "vcs_status",
)

var failedToolPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

const maxFailedToolBytes = 32

func SafeFailedTool(name string) bool {
	return safeFailedToolNames[name] && len(name) <= maxFailedToolBytes && failedToolPattern.MatchString(name)
}

var preDispatchOutcomes = set(
	TurnOutcomeProviderFailed,
	TurnOutcomeInvalidResponse,
	TurnOutcomeToolAssemblyFailed,
	TurnOutcomeToolPlanInvalid,
)

type TurnTerminal struct {
	TurnID          string `json:"turn_id"`
	RoundID         string `json:"round_id"`
	Outcome         string `json:"outcome"`
	FailurePhase    string `json:"failure_phase,omitempty"`
	FailedTool      string `json:"failed_tool,omitempty"`
	FailureReason   string `json:"failure_reason,omitempty"`
	DispatchStarted bool   `json:"dispatch_started"`
}

func (TurnTerminal) Kind() string { return KindTurnTerminal }

func (p TurnTerminal) validate() error {
	const k = KindTurnTerminal
	if err := validV7(k, "turn_id", p.TurnID); err != nil {
		return err
	}
	if err := validV7(k, "round_id", p.RoundID); err != nil {
		return err
	}
	if err := enum(k, "outcome", p.Outcome, turnTerminalOutcomes); err != nil {
		return err
	}
	if p.FailurePhase != "" {
		if p.Outcome != TurnOutcomeProviderFailed {
			return fmt.Errorf("%s: failure_phase is only present when outcome is %q", k, TurnOutcomeProviderFailed)
		}
		if _, ok := providerReasons[p.FailurePhase]; !ok {
			return fmt.Errorf("%s.failure_phase: %q is not one of dial/tls/http/decode/stream_drop/empty_response", k, p.FailurePhase)
		}
	}
	if err := p.validateDispatchDiagnostic(k); err != nil {
		return err
	}
	if p.DispatchStarted && preDispatchOutcomes[p.Outcome] {
		return fmt.Errorf("%s: dispatch_started must be false when outcome is %q", k, p.Outcome)
	}
	if !p.DispatchStarted && p.Outcome == TurnOutcomeDispatchFailed {
		return fmt.Errorf("%s: dispatch_started must be true when outcome is %q", k, p.Outcome)
	}
	return nil
}

func (p TurnTerminal) validateDispatchDiagnostic(k string) error {
	if p.FailedTool == "" && p.FailureReason == "" {
		return nil
	}
	if p.Outcome != TurnOutcomeDispatchFailed {
		return fmt.Errorf("%s: failed_tool/failure_reason are only present when outcome is %q", k, TurnOutcomeDispatchFailed)
	}
	if err := enum(k, "failure_reason", p.FailureReason, dispatchFailureReasons); err != nil {
		return err
	}
	if p.FailureReason == DispatchReasonPostPlanFailed {
		if p.FailedTool != "" {
			return fmt.Errorf("%s: failed_tool must be absent when failure_reason is %q", k, DispatchReasonPostPlanFailed)
		}
		return nil
	}
	if p.FailedTool == "" {
		return fmt.Errorf("%s: failed_tool is required when failure_reason is %q", k, DispatchReasonToolDispatchFailed)
	}
	// The rejected value is never echoed: it is exactly the arbitrary text this check exists
	// to keep out of the record, and an error message is another place it would be retained.
	if !SafeFailedTool(p.FailedTool) {
		return fmt.Errorf("%s.failed_tool: not a built-in advertised tool name", k)
	}
	return nil
}

func EmitTurnTerminal(ctx context.Context, store *sessions.Store, payload TurnTerminal, onWriteFailure WriteFailureHandler) error {
	if _, err := appendEvent(store, payload); err != nil {
		return err
	}
	cat, reason, err := flushStore(context.WithoutCancel(ctx), store)
	if err != nil && reason != sessions.ReasonNone && onWriteFailure != nil {
		onWriteFailure(cat, reason, err)
	}
	return err
}
