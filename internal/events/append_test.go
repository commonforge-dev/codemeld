// Tests for the event append API and the per-kind payload schemas:
// round-trip per kind, UTF-8 coercion, and cross-field rule enforcement at both
// append time and load time.
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

func i64(n int64) *int64 { return &n }

func bptr(b bool) *bool { return &b }

func f64(v float64) *float64 { return &v }

// litHash returns the lowercase hex SHA-256 of a literal subject, the value
// permission_matched.argument_hash must mirror.
func litHash(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var fixedTime = time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)

func newSession() *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     fixedTime,
			UpdatedAt:     fixedTime,
			SchemaVersion: 1,
		},
	}
}

func newStore() *sessions.Store {
	return sessions.New("unused-in-tests", newSession())
}

// validPayloads exercises every event kind, with extra variants for the kinds
// whose payloads carry conditional fields.
var validPayloads = []struct {
	name string
	p    EventPayload
}{
	{"launch_began", LaunchBegan{Source: "fresh"}},
	{"session_forked", SessionForked{ToSessionID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99"}},
	{"permission_prompt_shown", PermissionPromptShown{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj"}},
	{"permission_prompt_shown/host-fetch", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com"}},
	{"permission_prompt_shown/host-search", PermissionPromptShown{SubjectKind: "host", Subject: "web_search", HostScope: "mcp.exa.ai"}},
	{"permission_prompt_shown/host-ip-literal", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "2001:db8::1"}},
	{"permission_prompt_shown/host-punycode", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "xn--bcher-kva.example"}},
	{"permission_prompt_wait/answered", PermissionPromptWait{WaitedMs: 1500, Prompts: 3, Ended: "answered"}},
	{"permission_prompt_wait/zero-duration", PermissionPromptWait{WaitedMs: 0, Prompts: 1, Ended: "cancelled"}},
	{"permission_prompt_wait/failed", PermissionPromptWait{WaitedMs: 7, Prompts: 1, Ended: "failed"}},
	{"permission_decision/granted", PermissionDecision{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", Outcome: "granted", GrantKind: "folder", GrantPathScope: "/home/u/proj"}},
	{"permission_decision/granted-global", PermissionDecision{SubjectKind: "tool", Subject: "Read", PathScope: "/home/u/proj", Outcome: "granted", GrantKind: "global", GrantPathScope: "*"}},
	{"permission_decision/granted-once", PermissionDecision{SubjectKind: "tool", Subject: "vcs_commit", PathScope: "/home/u/proj", Outcome: "granted"}},
	{"permission_decision/denied", PermissionDecision{SubjectKind: "direct", Subject: "rm -rf /", PathScope: "/home/u/proj", Outcome: "denied"}},
	{"permission_decision/host-granted-project", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"permission_decision/host-granted-session", PermissionDecision{SubjectKind: "host", Subject: "web_search", Outcome: "granted", GrantKind: "session", HostScope: "mcp.exa.ai", GrantHostScope: "mcp.exa.ai"}},
	{"permission_decision/host-granted-once", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", HostScope: "docs.example.com"}},
	{"permission_decision/host-denied", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "denied", HostScope: "docs.example.com"}},
	{"permission_decision/host-ip-literal", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "2001:db8::1", GrantHostScope: "2001:db8::1"}},
	{"permission_decision/host-punycode", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "xn--bcher-kva.example", GrantHostScope: "xn--bcher-kva.example"}},
	{"permission_matched/grant-folder", PermissionMatched{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "folder_grant", OutcomeSource: "grant"}},
	{"permission_matched/cache-once", PermissionMatched{SubjectKind: "direct", Subject: "ls", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "cache"}},
	{"permission_matched/cache-deny", PermissionMatched{SubjectKind: "tool", Subject: "Bash", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "cache"}},
	{"permission_matched/grant-global", PermissionMatched{SubjectKind: "tool", Subject: "Read", PathScope: "/home/u/proj", GrantKind: "global", GrantPathScope: "*", Outcome: "global_grant", OutcomeSource: "grant"}},
	{"permission_matched/literal-hash", PermissionMatched{SubjectKind: "literal", Subject: "npm test", PathScope: "/home/u/proj", GrantKind: "session", GrantPathScope: "/home/u/proj", Outcome: "session_grant", OutcomeSource: "grant", ArgumentHash: litHash("npm test")}},
	{"permission_matched/host-grant-project", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "project_grant", OutcomeSource: "grant", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"permission_matched/host-grant-session", PermissionMatched{SubjectKind: "host", Subject: "web_search", GrantKind: "session", Outcome: "session_grant", OutcomeSource: "grant", HostScope: "mcp.exa.ai", GrantHostScope: "mcp.exa.ai"}},
	{"permission_matched/host-cache-once", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", Outcome: "once", OutcomeSource: "cache", HostScope: "docs.example.com"}},
	{"permission_matched/host-cache-deny", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", Outcome: "deny", OutcomeSource: "cache", HostScope: "docs.example.com"}},
	{"permission_matched/mode-auto-once", PermissionMatched{SubjectKind: "tool", Subject: "read_file", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "mode_auto"}},
	{"permission_matched/declared-command-once", PermissionMatched{SubjectKind: "direct", Subject: "prep-open-tasks.sh --only i425", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "declared_command"}},
	{"permission_matched/open-read-once", PermissionMatched{SubjectKind: "tool", Subject: "read_image", PathScope: "/home/u/pictures", Outcome: "once", OutcomeSource: "open_read"}},
	{"permission_matched/mode-auto-deny", PermissionMatched{SubjectKind: "direct", Subject: "rm -rf /", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "mode_auto"}},
	{"permission_matched/mode-auto-literal-deny", PermissionMatched{SubjectKind: "literal", Subject: "npm test", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "mode_auto", ArgumentHash: litHash("npm test")}},
	{"permission_matched/protected-state-deny", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"permission_matched/protected-state-move", PermissionMatched{SubjectKind: "tool", Subject: "move", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"permission_matched/protected-state-vcs-restore", PermissionMatched{SubjectKind: "tool", Subject: "vcs_restore_file", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"permission_matched/protected-state-vcs-stash-pop", PermissionMatched{SubjectKind: "tool", Subject: "vcs_stash_pop", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"permission_matched/protected-state-vcs-status", PermissionMatched{SubjectKind: "tool", Subject: "vcs_status", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"permission_matched/blocked-path-read", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/.ssh", BlockedEntrySource: "/home/u/.codemeld/global/settings.yaml"}},
	{"permission_matched/blocked-path-move", PermissionMatched{SubjectKind: "tool", Subject: "move", PathScope: "/home/u", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/.codemeld"}},
	{"permission_matched/blocked-path-direct", PermissionMatched{SubjectKind: "direct", Subject: "cat /home/u/.ssh/k", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", DirectRequestSubject: "cat /home/u/.ssh/k", BlockedEntry: "/home/u/.ssh", BlockedEntrySource: "/home/u/.codemeld/global/settings.yaml"}},
	{"permission_matched/blocked-path-literal", PermissionMatched{SubjectKind: "literal", Subject: "cat /home/u/.ssh/k 2>/dev/null", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", ArgumentHash: litHash("cat /home/u/.ssh/k 2>/dev/null"), BlockedEntry: "/home/u/.ssh"}},
	{"permission_matched/blocked-path-vcs-branch-switch", PermissionMatched{SubjectKind: "tool", Subject: "vcs_branch_switch", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/proj/secrets", BlockedEntrySource: "/home/u/.codemeld/global/settings.yaml"}},
	{"permission_matched/blocked-path-vcs-restore-file", PermissionMatched{SubjectKind: "tool", Subject: "vcs_restore_file", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/proj/secrets"}},
	{"permission_matched/blocked-path-vcs-stash", PermissionMatched{SubjectKind: "tool", Subject: "vcs_stash", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/proj/secrets"}},
	{"permission_matched/blocked-path-vcs-stash-pop", PermissionMatched{SubjectKind: "tool", Subject: "vcs_stash_pop", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/proj/secrets"}},
	{"tool_exec_start", ToolExecStart{SubjectKind: "tool", Subject: "Read", PathScope: "/home/u/proj", InvocationID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"}},
	{"tool_exec_end/truncated", ToolExecEnd{SubjectKind: "direct", Subject: "ls -la", ExitCode: 0, DurationMs: 12, Stdout: "lots", Stderr: "warn", Truncated: true, OriginalBytes: &OriginalBytes{Stdout: 100000, Stderr: 80000}, InvocationID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"}},
	{"tool_exec_end/clean", ToolExecEnd{SubjectKind: "tool", Subject: "Read", ExitCode: 0, DurationMs: 5, Truncated: false, InvocationID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02"}},
	{"tool_exec_end/truncated-boundary", ToolExecEnd{SubjectKind: "direct", Subject: "x", ExitCode: 0, DurationMs: 1, Stdout: "abc", Truncated: true, OriginalBytes: &OriginalBytes{Stdout: 4, Stderr: 0}, InvocationID: goodV7}},
	{"agent_instructions_loaded/loaded", AgentInstructionsLoaded{Path: "/home/u/proj/AGENTS.md", Layer: "walked", LoadOrder: 2}},
	{"agent_instructions_loaded/unreadable", AgentInstructionsLoaded{Path: "/home/u/.codemeld/global/AGENTS.md", Layer: "global", LoadOrder: 1, SkipReason: "unreadable", ErrorCategory: "permission_denied", ErrorDetail: "open AGENTS.md: permission denied"}},
	{"agent_instructions_loaded/size_limit", AgentInstructionsLoaded{Path: "/home/u/proj/AGENTS.md", Layer: "walked", LoadOrder: 3, SkipReason: "size_limit"}},
	{"session_prune_summary/clean", SessionPruneSummary{FilesScanned: 10, FilesDeleted: 8, FilesFailed: 0, ElapsedMs: 42}},
	{"session_prune_summary/failures", SessionPruneSummary{FilesScanned: 5, FilesDeleted: 1, FilesFailed: 2, Failures: []PruneFailure{{Path: "/s/a.json", Reason: "io_error", Kind: "file_delete"}, {Path: "/s/sub", Reason: "permission_denied", Kind: "dir_enumerate"}}, ElapsedMs: 7}},
	{"session_write_failed", SessionWriteFailed{TargetPath: "/home/u/.codemeld/sessions/s.json", Reason: "write_error", ErrorCategory: "no_space", ErrorDetail: "write: no space left on device"}},
	{"permission_persist_failed/global", PermissionPersistFailed{TargetPath: "/home/u/.codemeld/global/settings.yaml", GrantKind: "global", SubjectKind: "direct", Subject: "git status", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error", DegradedToPathScope: "/home/u/proj"}},
	{"permission_persist_failed/host-project", PermissionPersistFailed{TargetPath: "/home/u/proj/.codemeld/settings.yaml", GrantKind: "project", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error", HostScope: "docs.example.com"}},
	{"permission_persist_failed/host-lock-timeout", PermissionPersistFailed{TargetPath: "/home/u/proj/.codemeld/settings.yaml", GrantKind: "project", SubjectKind: "host", Subject: "web_search", Reason: "lock_timeout", ErrorDetail: lockTimeoutDetail, HostScope: "mcp.exa.ai"}},
	{"permission_persist_failed/folder-lock-timeout", PermissionPersistFailed{TargetPath: "/home/u/proj/.codemeld/settings.yaml", GrantKind: "folder", SubjectKind: "tool", Subject: "Read", Reason: "lock_timeout", ErrorDetail: lockTimeoutDetail}},
	{"model_turn", ModelTurn{Provider: "openai", ModelID: "gpt-5", Effort: "high", Source: "project"}},
	{"model_turn/no-reasoning", ModelTurn{Provider: "openai", ModelID: "gpt-5", Effort: "no-reasoning", Source: "project"}},
	{"model_turn/advertised-token", ModelTurn{Provider: "venice", ModelID: "custom-1", Effort: "ultra", Source: "picker"}},
	{"model_response/healthy", ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 100, OutputTokens: 50}},
	{"model_response/usage-missing", ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 0, OutputTokens: 0, Anomaly: []string{"usage_missing"}}},
	{"model_response/cached-reported", ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 100, OutputTokens: 50, CachedInputTokens: i64(80)}},
	{"model_response/cached-reported-zero", ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 100, OutputTokens: 50, CachedInputTokens: i64(0)}},
	{"model_response/cached-partial", ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 100, OutputTokens: 50, CachedInputTokens: i64(80), CachedInputTokensPartial: true}},
	{"model_response/cost-reported", ModelResponse{Provider: "openrouter", ModelID: "m", InputTokens: 100, OutputTokens: 50, CostUSD: f64(0.00123)}},
	{"model_response/cost-reported-zero", ModelResponse{Provider: "openrouter", ModelID: "m", InputTokens: 100, OutputTokens: 50, CostUSD: f64(0)}},
	{"model_response/cost-partial", ModelResponse{Provider: "openrouter", ModelID: "m", InputTokens: 100, OutputTokens: 50, CostUSD: f64(0.5), CostUSDPartial: true}},
	{"model_changed/with-prior", ModelChanged{NewProvider: "openai", NewModelID: "gpt-5", NewEffort: "high", PriorProvider: "openrouter", PriorModelID: "z-ai/glm-5.1", PriorEffort: "low"}},
	{"model_changed/no-prior", ModelChanged{NewProvider: "openai", NewModelID: "gpt-5", NewEffort: "medium"}},
	{"model_changed/advertised-tokens", ModelChanged{NewProvider: "venice", NewModelID: "custom-1", NewEffort: "ultra", PriorProvider: "venice", PriorModelID: "custom-0", PriorEffort: "max"}},
	{"model_changed/no-reasoning", ModelChanged{NewProvider: "venice", NewModelID: "custom-1", NewEffort: "no-reasoning", PriorProvider: "openai", PriorModelID: "gpt-5", PriorEffort: "default"}},
	{"model_changed/advertised-prior-only", ModelChanged{NewProvider: "openai", NewModelID: "gpt-5", NewEffort: "high", PriorProvider: "venice", PriorModelID: "custom-1", PriorEffort: "ultra"}},
	{"model_effort_unsupported", ModelEffortUnsupported{Provider: "openai", ModelID: "gpt-5", ConfiguredEffort: "high"}},
	{"model_effort_unsupported/advertised-token", ModelEffortUnsupported{Provider: "venice", ModelID: "custom-1", ConfiguredEffort: "ultra"}},
	{"model_recovery_failed", ModelRecoveryFailed{Reason: "validation_failed", ErrorDetail: "effort value 'extreme' not in supported enum"}},
	{"model_persist_failed", ModelPersistFailed{TargetPath: "/home/u/proj/.codemeld/settings.yaml", Provider: "openai", ModelID: "gpt-5", Effort: "high", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error"}},
	{"model_persist_failed/advertised-token", ModelPersistFailed{TargetPath: "/home/u/proj/.codemeld/settings.yaml", Provider: "venice", ModelID: "custom-1", Effort: "max", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error"}},
	{"model_global_mirror_failed", ModelGlobalMirrorFailed{TargetPath: "/home/u/.codemeld/global/settings.yaml", Provider: "openai", ModelID: "gpt-5", Effort: "high", Reason: "rename_error", ErrorCategory: "io_error", ErrorDetail: "rename: io error"}},
	{"model_global_mirror_failed/no-reasoning", ModelGlobalMirrorFailed{TargetPath: "/home/u/.codemeld/global/settings.yaml", Provider: "venice", ModelID: "custom-1", Effort: "no-reasoning", Reason: "rename_error", ErrorCategory: "io_error", ErrorDetail: "rename: io error"}},
	{"model_catalog_refreshed/updated", ModelCatalogRefreshed{Provider: "openai", Outcome: "updated"}},
	{"model_catalog_refreshed/no-change", ModelCatalogRefreshed{Provider: "venice", Outcome: "no_change"}},
	{"model_catalog_refreshed/failed", ModelCatalogRefreshed{Provider: "openrouter", Outcome: "failed"}},
	{"slash_command/success", SlashCommand{Name: "help", Args: []string{"status"}, Outcome: "success"}},
	{"slash_command/error", SlashCommand{Name: "model", Args: []string{}, Outcome: "error", ErrorDetail: "unknown model 'gpt-9'; supported: gpt-5"}},
	{"stream_interrupted", StreamInterrupted{Source: "esc", ContentChars: 128}},
	{"provider_request_failed/http", ProviderRequestFailed{Provider: "openai", ModelID: "gpt-5", Phase: "http", HTTPStatus: i64(401), Reason: "http_no_body", ErrorDetail: "401 Unauthorized"}},
	{"provider_request_failed/http-error", ProviderRequestFailed{Provider: "openai", ModelID: "gpt-5", Phase: "http", HTTPStatus: i64(429), Reason: "http_error", ErrorDetail: `{"error":{"message":"rate limited"}}`}},
	{"provider_request_failed/stream-drop", ProviderRequestFailed{Provider: "openai", ModelID: "gpt-5", Phase: "stream_drop", PartialResponseChars: 42, Reason: "stream_eof", ErrorDetail: "unexpected EOF"}},
	{"provider_request_failed/dial", ProviderRequestFailed{Provider: "openai", ModelID: "gpt-5", Phase: "dial", Reason: "dns_error", ErrorDetail: "no such host"}},
	{"provider_request_failed/tls-cert-invalid", ProviderRequestFailed{Provider: "openai", ModelID: "gpt-5", Phase: "tls", Reason: "tls_cert_invalid", ErrorDetail: "x509: certificate signed by unknown authority"}},
	{"provider_request_failed/tls-cert-expired", ProviderRequestFailed{Provider: "openai", ModelID: "gpt-5", Phase: "tls", Reason: "tls_cert_expired", ErrorDetail: "x509: certificate has expired or is not yet valid"}},
	{"interaction_mode/launch", InteractionMode{Mode: "build", Source: "default", Trigger: "launch"}},
	{"interaction_mode/resume-config", InteractionMode{Mode: "plan", Source: "config", Trigger: "resume"}},
	{"interaction_mode/clear-user", InteractionMode{Mode: "auto_edits", Source: "user_command", Trigger: "clear"}},
	{"interaction_mode/user-command", InteractionMode{Mode: "plan", Source: "user_command", Trigger: "user_command"}},
	{"turn_latency", TurnLatency{Provider: "openai", ModelID: "gpt-5", DurationMs: 1234}},
	{"turn_latency/zero", TurnLatency{Provider: "openrouter", ModelID: "z-ai/glm-5.1", DurationMs: 0}},
	{"provider_round_trip", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: 567}},
	{"provider_round_trip/zero", ProviderRoundTrip{Provider: "openrouter", ModelID: "z-ai/glm-5.1", DurationMs: 0}},
	{"provider_round_trip/upstream", ProviderRoundTrip{Provider: "openrouter", ModelID: "z-ai/glm-5.1", DurationMs: 9, UpstreamProvider: "Google AI Studio"}},
	{"suggest_followup_debug/advertised", SuggestFollowupDebug{Stage: "request_built", Provider: "openai", ModelID: "gpt-5", Mode: "build", Advertised: bptr(true)}},
	{"suggest_followup_debug/not-advertised", SuggestFollowupDebug{Stage: "request_built", Provider: "openai", ModelID: "gpt-5", Mode: "plan", Advertised: bptr(false)}},
	{"suggest_followup_debug/no-call", SuggestFollowupDebug{Stage: "provider_round_no_call", Provider: "openai", ModelID: "gpt-5", Mode: "build"}},
	{"suggest_followup_debug/tool-call-seen", SuggestFollowupDebug{Stage: "tool_call_seen", Provider: "openrouter", ModelID: "z-ai/glm-5.1", Mode: "auto_edits"}},
	{"suggest_followup_debug/intercepted", SuggestFollowupDebug{Stage: "intercepted", Provider: "openai", ModelID: "gpt-5", Mode: "build", LabelLen: 12, PromptLen: 40}},
	{"suggest_followup_debug/surface-called", SuggestFollowupDebug{Stage: "surface_called", Provider: "openai", ModelID: "gpt-5", Mode: "build", LabelLen: 12, PromptLen: 40}},
	{"suggest_followup_debug/ghost-set", SuggestFollowupDebug{Stage: "ghost_set", Provider: "openai", ModelID: "gpt-5", Mode: "build", LabelLen: 12, PromptLen: 40}},
	{"suggest_followup_debug/ghost-accepted", SuggestFollowupDebug{Stage: "ghost_accepted", Provider: "openai", ModelID: "gpt-5", Mode: "build", LabelLen: 12, PromptLen: 40}},
	{"suggest_followup_debug/ghost-cleared", SuggestFollowupDebug{Stage: "ghost_cleared", Provider: "openai", ModelID: "gpt-5", Mode: "build", PromptLen: 40, Reason: "input_changed"}},
	{"queued_prompt_discarded/text-only", QueuedPromptDiscarded{Text: "summarize the diff", Reason: "interrupted"}},
	{"queued_prompt_discarded/image-only", QueuedPromptDiscarded{ImageCount: 2, Reason: "turn_failed"}},
	{"provider_stream_idle", ProviderStreamIdle{Provider: "openai", ModelID: "gpt-5", RoundElapsedMs: 30000, IdleMs: 15000, PartialChars: 128}},
	{"provider_stream_idle/zero", ProviderStreamIdle{Provider: "openrouter", ModelID: "z-ai/glm-5.1", RoundElapsedMs: 0, IdleMs: 0, PartialChars: 0}},
	{"structured_read_start", StructuredReadStart{ToolName: "read", PathScope: "/home/u/proj/a.go", InvocationID: goodV7, ConfiguredConcurrency: 4}},
	{"structured_read_start/serial-cap", StructuredReadStart{ToolName: "glob", PathScope: "/home/u/proj", InvocationID: goodV7, ConfiguredConcurrency: 1}},
	{"structured_read_end/success", StructuredReadEnd{ToolName: "read", InvocationID: goodV7, Outcome: "success", DurationMs: 12}},
	{"structured_read_end/tool_failure", StructuredReadEnd{ToolName: "read", InvocationID: goodV7, Outcome: "tool_failure", DurationMs: 3}},
	{"structured_read_end/denied", StructuredReadEnd{ToolName: "grep", InvocationID: goodV7, Outcome: "denied", DurationMs: 0}},
	{"structured_read_end/cancelled", StructuredReadEnd{ToolName: "glob", InvocationID: goodV7, Outcome: "cancelled", DurationMs: 900}},
	{"structured_read_end/internal_failure", StructuredReadEnd{ToolName: "read", InvocationID: goodV7, Outcome: "internal_failure", DurationMs: 1}},
	{"structured_read_refused/not_allowlisted", StructuredReadRefused{ToolName: "read_image", Reason: "not_allowlisted", BatchSize: 7}},
	{"structured_read_refused/args_invalid", StructuredReadRefused{ToolName: "grep", Reason: "args_invalid", BatchSize: 2}},
	{"structured_read_refused/prepare_failed", StructuredReadRefused{ToolName: "read", Reason: "prepare_failed", BatchSize: 3}},
	{"structured_read_refused/scope_unresolved", StructuredReadRefused{ToolName: "list", Reason: "scope_unresolved", BatchSize: 1}},
	{"structured_read_refused/out_of_project", StructuredReadRefused{ToolName: "read", Reason: "out_of_project", BatchSize: 6}},
	{"child_agent_start", ChildAgentStart{InvocationID: goodV7, ProviderID: "openai", ModelID: "gpt-5.5", DeclaredPaths: []string{"/home/u/proj/a.txt"}, StepCap: 12, InstructionBytes: 40, InstructionDigest: hex64}},
	{"child_agent_end/completed", ChildAgentEnd{InvocationID: goodV7, Reason: "completed", Steps: 3, WrittenPaths: []string{"/home/u/proj/a.txt"}, RollbackOutcome: "not_needed", DurationMs: 1200}},
	{"child_agent_end/cancelled", ChildAgentEnd{InvocationID: goodV7, Reason: "cancelled", Steps: 1, WrittenPaths: []string{"/home/u/proj/a.txt"}, RollbackOutcome: "rolled_back", DurationMs: 30, ReplyTruncated: true}},
	{"child_agent_end/step_cap", ChildAgentEnd{InvocationID: goodV7, Reason: "step_cap", Steps: 12, RollbackOutcome: "rolled_back", DurationMs: 900}},
	{"child_agent_end/failed", ChildAgentEnd{InvocationID: goodV7, Reason: "failed", Steps: 0, RollbackOutcome: "unrecovered", DurationMs: 0}},
	{"child_agent_start/delete-only", ChildAgentStart{InvocationID: goodV7, ProviderID: "openai", ModelID: "gpt-5.5", StepCap: 12, InstructionBytes: 40, InstructionDigest: hex64, DeclaredDeletePaths: []string{"/home/u/proj/old.txt"}}},
	{"child_agent_start/write-and-delete", ChildAgentStart{InvocationID: goodV7, ProviderID: "openai", ModelID: "gpt-5.5", DeclaredPaths: []string{"/home/u/proj/a.txt"}, StepCap: 12, InstructionBytes: 40, InstructionDigest: hex64, DeclaredDeletePaths: []string{"/home/u/proj/a.txt", "/home/u/proj/old.txt"}}},
	{"child_agent_end/deleted", ChildAgentEnd{InvocationID: goodV7, Reason: "completed", Steps: 2, RollbackOutcome: "not_needed", DurationMs: 40, DeletedPaths: []string{"/home/u/proj/old.txt"}}},
	{"child_agent_end/deleted-bounded", ChildAgentEnd{InvocationID: goodV7, Reason: "cancelled", Steps: 2, WrittenPaths: []string{"/home/u/proj/a.txt"}, RollbackOutcome: "rolled_back", DurationMs: 40, DeletedPaths: []string{"/home/u/proj/old.txt"}, DeletedPathsTotal: 300}},
	{"child_agent_start/move-only", ChildAgentStart{InvocationID: goodV7, ProviderID: "openai", ModelID: "gpt-5.5", StepCap: 12, InstructionBytes: 40, InstructionDigest: hex64, DeclaredMovePairs: []ChildMovePair{{Source: "/home/u/proj/old.txt", Destination: "/home/u/proj/new.txt"}}}},
	{"child_agent_end/moved", ChildAgentEnd{InvocationID: goodV7, Reason: "completed", Steps: 2, RollbackOutcome: "not_needed", DurationMs: 40, MovedPairs: []ChildMovePair{{Source: "/home/u/proj/old.txt", Destination: "/home/u/proj/new.txt"}}}},
	{"tool_exec_start/child-attributed", ToolExecStart{SubjectKind: "literal", Subject: "ls", PathScope: "/home/u/proj", InvocationID: goodV7, ChildInvocationID: goodV7}},
	{"tool_exec_end/child-attributed", ToolExecEnd{SubjectKind: "literal", Subject: "ls", DurationMs: 4, InvocationID: goodV7, ChildInvocationID: goodV7}},
	{"prompt_shown/child-attributed", PermissionPromptShown{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/a.txt", ChildInvocationID: goodV7}},
	{"permission_decision/child-attributed", PermissionDecision{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/a.txt", Outcome: "granted", ChildInvocationID: goodV7}},
	{"permission_matched/child-attributed", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/a.txt", Outcome: "once", OutcomeSource: "declared_scope", ChildInvocationID: goodV7}},
}

func TestAppend_RoundTripPerKind(t *testing.T) {
	restore := now
	now = func() time.Time { return fixedTime }
	t.Cleanup(func() { now = restore })

	for _, tc := range validPayloads {
		t.Run(tc.name, func(t *testing.T) {
			// The store mutates sess in place, so after Append sess carries the
			// appended event and can be serialized through the production codec.
			sess := newSession()
			store := sessions.New("unused-in-tests", sess)
			rec, err := Append(store, tc.p)
			if err != nil {
				t.Fatalf("Append() error = %v", err)
			}
			ev, ok := rec.(sessions.Event)
			if !ok {
				t.Fatalf("Append() returned %T, want sessions.Event", rec)
			}
			if ev.Kind != tc.p.Kind() {
				t.Errorf("Kind = %q, want %q", ev.Kind, tc.p.Kind())
			}
			if !ids.IsValidV7(ev.ID) {
				t.Errorf("ID = %q is not a valid UUIDv7", ev.ID)
			}
			if !ev.Timestamp.Equal(fixedTime) {
				t.Errorf("Timestamp = %v, want %v", ev.Timestamp, fixedTime)
			}

			// The appended record is the only one in the store's stream.
			if recs := store.Records(); len(recs) != 1 {
				t.Fatalf("store has %d records, want 1", len(recs))
			}

			// Persisted round-trip through the production session codec: marshal
			// the session, reload it with Unmarshal, and assert the event
			// record shape survives. This exercises sessions.Marshal/Unmarshal
			// rather than the package-private payload decoder alone.
			data, err := sessions.Marshal(sess)
			if err != nil {
				t.Fatalf("sessions.Marshal() error = %v", err)
			}
			loaded, err := sessions.Unmarshal(data)
			if err != nil {
				t.Fatalf("sessions.Unmarshal() error = %v", err)
			}
			if len(loaded.Records) != 1 {
				t.Fatalf("reloaded session has %d records, want 1", len(loaded.Records))
			}
			got, ok := loaded.Records[0].(sessions.Event)
			if !ok {
				t.Fatalf("reloaded record is %T, want sessions.Event", loaded.Records[0])
			}
			if got.Kind != tc.p.Kind() {
				t.Errorf("reloaded Kind = %q, want %q", got.Kind, tc.p.Kind())
			}
			if !ids.IsValidV7(got.ID) {
				t.Errorf("reloaded ID = %q is not a valid UUIDv7", got.ID)
			}
			if !got.Timestamp.Equal(fixedTime) {
				t.Errorf("reloaded Timestamp = %v, want %v", got.Timestamp, fixedTime)
			}
			if !strings.HasPrefix(strings.TrimSpace(string(got.Payload)), "{") {
				t.Errorf("reloaded payload is not a JSON object: %s", got.Payload)
			}

			// Load-time validator accepts the reloaded bytes.
			if err := ValidatePayload(got.Kind, got.Payload); err != nil {
				t.Fatalf("ValidatePayload() error = %v", err)
			}

			// Round-trip equivalence: the reloaded payload decodes back to the
			// canonicalized input (nil slices -> [], strings UTF-8-coerced). It is
			// compared in wire form because an omitted optional list decodes as nil.
			decoded, err := unmarshalPayload(got.Kind, got.Payload)
			if err != nil {
				t.Fatalf("unmarshalPayload() error = %v", err)
			}
			want := canonicalize(reflect.ValueOf(tc.p)).Interface()
			wantWire, werr := json.Marshal(want)
			gotWire, gerr := json.Marshal(decoded)
			if werr != nil || gerr != nil {
				t.Fatalf("json.Marshal() errors = %v / %v", werr, gerr)
			}
			if string(wantWire) != string(gotWire) {
				t.Errorf("round-trip mismatch:\n got: %#v\nwant: %#v\npayload: %s", decoded, want, got.Payload)
			}
		})
	}
}

func TestAppend_MintsDistinctIDs(t *testing.T) {
	store := newStore()
	r1, err := Append(store, LaunchBegan{Source: "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Append(store, LaunchBegan{Source: "resume"})
	if err != nil {
		t.Fatal(err)
	}
	if r1.(sessions.Event).ID == r2.(sessions.Event).ID {
		t.Errorf("two appends shared the same record id")
	}
}

func TestAppend_NilPayload(t *testing.T) {
	if _, err := Append(newStore(), nil); err == nil {
		t.Fatal("Append(nil) did not error")
	}
}

// TestAppend_NilStore guards the append contract for an invalid store: a nil
// *sessions.Store must surface an error rather than panicking in Store.Append.
func TestAppend_NilStore(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Append(nil store) panicked: %v", r)
		}
	}()
	if _, err := Append(nil, LaunchBegan{Source: "fresh"}); err == nil {
		t.Fatal("Append(nil store) did not error")
	}
}

// TestAppend_TypedNilPayload guards against a typed-nil EventPayload: a nil
// pointer carried in the interface passes the == nil check but would panic in a
// value-receiver validate(). Append must reject it and append nothing.
func TestAppend_TypedNilPayload(t *testing.T) {
	var p *LaunchBegan
	store := newStore()
	if _, err := Append(store, p); err == nil {
		t.Fatal("Append(typed nil) did not error")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("rejected typed-nil payload still appended %d record(s)", got)
	}
}

// TestAppend_CanonicalTimestamp verifies the record timestamp is the canonical
// millisecond-truncated UTC form the session codec persists: a now() carrying
// sub-millisecond precision must not leak into the returned record, the store
// snapshot, or the marshaled JSON.
func TestAppend_CanonicalTimestamp(t *testing.T) {
	subMilli := time.Date(2026, 5, 26, 10, 0, 0, 123_456_789, time.UTC)
	wantTS := subMilli.Truncate(time.Millisecond)
	restore := now
	now = func() time.Time { return subMilli }
	t.Cleanup(func() { now = restore })

	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	rec, err := Append(store, LaunchBegan{Source: "fresh"})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if got := rec.(sessions.Event).Timestamp; !got.Equal(wantTS) {
		t.Errorf("returned timestamp = %v, want %v", got, wantTS)
	}
	if got := store.Records()[0].(sessions.Event).Timestamp; !got.Equal(wantTS) {
		t.Errorf("store snapshot timestamp = %v, want %v", got, wantTS)
	}

	data, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("sessions.Marshal() error = %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("sessions.Unmarshal() error = %v", err)
	}
	if got := loaded.Records[0].(sessions.Event).Timestamp; !got.Equal(wantTS) {
		t.Errorf("persisted timestamp = %v, want %v", got, wantTS)
	}
}

func TestAppend_UTF8Coercion(t *testing.T) {
	store := newStore()
	// A run of two invalid bytes collapses to a single U+FFFD (ToValidUTF8
	// semantics), distinct from encoding/json's per-byte replacement.
	original := ModelRecoveryFailed{Reason: "validation_failed", ErrorDetail: "café \xff\xfe broke"}
	rec, err := Append(store, original)
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	var got ModelRecoveryFailed
	if err := json.Unmarshal(rec.(sessions.Event).Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	want := "café � broke"
	if got.ErrorDetail != want {
		t.Errorf("error_detail = %q, want %q", got.ErrorDetail, want)
	}
	if !strings.Contains(string(rec.(sessions.Event).Payload), "�") {
		t.Errorf("persisted payload missing U+FFFD: %s", rec.(sessions.Event).Payload)
	}
	// The caller's payload must be left untouched (deep copy).
	if original.ErrorDetail != "café \xff\xfe broke" {
		t.Errorf("Append mutated the caller's payload: %q", original.ErrorDetail)
	}
}

// TestAppend_ValidatesCanonicalizedPayload guards the append contract that
// cross-field validation observes the post-UTF-8-coercion bytes that get
// persisted: a literal permission_matched whose subject carries an invalid byte
// must have its argument_hash bound to the sanitized subject. The
// sanitized-hash payload must append and load cleanly; the pre-coercion-hash
// payload must be rejected without appending, since the persisted record would
// otherwise fail the load-time validator.
func TestAppend_ValidatesCanonicalizedPayload(t *testing.T) {
	const rawSubject = "npm \xfftest"
	sanitized := strings.ToValidUTF8(rawSubject, "�")

	t.Run("sanitized-hash-appends-and-loads", func(t *testing.T) {
		store := newStore()
		p := PermissionMatched{
			SubjectKind: "literal", Subject: rawSubject, PathScope: "/home/u/proj",
			GrantKind: "session", GrantPathScope: "/home/u/proj",
			Outcome: "session_grant", OutcomeSource: "grant",
			ArgumentHash: litHash(sanitized),
		}
		rec, err := Append(store, p)
		if err != nil {
			t.Fatalf("Append() rejected a payload whose hash matches the sanitized subject: %v", err)
		}
		ev := rec.(sessions.Event)
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload() rejected the appended record: %v", err)
		}
	})

	t.Run("pre-coercion-hash-rejected-without-append", func(t *testing.T) {
		store := newStore()
		p := PermissionMatched{
			SubjectKind: "literal", Subject: rawSubject, PathScope: "/home/u/proj",
			GrantKind: "session", GrantPathScope: "/home/u/proj",
			Outcome: "session_grant", OutcomeSource: "grant",
			ArgumentHash: litHash(rawSubject),
		}
		if _, err := Append(store, p); err == nil {
			t.Error("Append() accepted a hash computed from the pre-coercion subject")
		}
		if got := len(store.Records()); got != 0 {
			t.Errorf("rejected payload still appended %d record(s)", got)
		}
	})
}

// Dropping omitempty from either cached field would turn requireShape's
// absent-required-field rule into a load failure for every session written before
// this change.
func TestModelResponse_LegacyRecordOmittingCachedFields(t *testing.T) {
	const legacy = `{"provider":"openai","model_id":"gpt-5","input_tokens":100,"output_tokens":50,"anomaly":[]}`
	if err := ValidatePayload(KindModelResponse, json.RawMessage(legacy)); err != nil {
		t.Fatalf("ValidatePayload() rejected a pre-change model_response: %v", err)
	}
	var p ModelResponse
	if err := json.Unmarshal([]byte(legacy), &p); err != nil {
		t.Fatalf("unmarshal legacy model_response: %v", err)
	}
	if p.CachedInputTokens != nil {
		t.Errorf("CachedInputTokens = %d, want nil (the provider reported nothing)", *p.CachedInputTokens)
	}
	if p.CachedInputTokensPartial {
		t.Error("CachedInputTokensPartial = true, want false for a record carrying no cached total")
	}
	if p.CostUSD != nil || p.CostUSDPartial {
		t.Errorf("cost = (%v, %v), want (nil, false) for a record carrying no cost", p.CostUSD, p.CostUSDPartial)
	}
}

func TestModelResponse_RejectsNonFiniteCostBeforeMarshalling(t *testing.T) {
	for _, v := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		store := newStore()
		_, err := Append(store, ModelResponse{Provider: "o", ModelID: "m", CostUSD: f64(v)})
		if err == nil || !strings.Contains(err.Error(), "model_response.cost_usd") {
			t.Errorf("Append(cost_usd=%v) error = %v, want a model_response.cost_usd validation error", v, err)
		}
		if got := len(store.Records()); got != 0 {
			t.Errorf("rejected payload still appended %d record(s)", got)
		}
	}
}

func TestModelResponse_CachedZeroSurvivesTheWire(t *testing.T) {
	rec, err := Append(newStore(), ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 1, OutputTokens: 2, CachedInputTokens: i64(0)})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rec.(sessions.Event).Payload)
	if !strings.Contains(raw, `"cached_input_tokens":0`) {
		t.Errorf("a reported zero did not survive serialization: %s", raw)
	}
	if strings.Contains(raw, "cached_input_tokens_partial") {
		t.Errorf("an exact total wrote the partial marker: %s", raw)
	}

	absent, err := Append(newStore(), ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 1, OutputTokens: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(absent.(sessions.Event).Payload); strings.Contains(got, "cached_input_tokens") {
		t.Errorf("a not-reported total wrote a cached key: %s", got)
	}
}

func TestProviderRoundTrip_UpstreamProviderSerialization(t *testing.T) {
	rec, err := Append(newStore(), ProviderRoundTrip{Provider: "openrouter", ModelID: "m", DurationMs: 1, UpstreamProvider: "Google AI Studio"})
	if err != nil {
		t.Fatal(err)
	}
	if raw := string(rec.(sessions.Event).Payload); !strings.Contains(raw, `"upstream_provider":"Google AI Studio"`) {
		t.Errorf("upstream_provider not written verbatim: %s", raw)
	}

	absent, err := Append(newStore(), ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: 1})
	if err != nil {
		t.Fatal(err)
	}
	if raw := string(absent.(sessions.Event).Payload); strings.Contains(raw, "upstream_provider") {
		t.Errorf("an empty upstream wrote the key: %s", raw)
	}

	const legacy = `{"provider":"openrouter","model_id":"m","duration_ms":5}`
	if err := ValidatePayload(KindProviderRoundTrip, json.RawMessage(legacy)); err != nil {
		t.Fatalf("ValidatePayload() rejected a pre-change provider_round_trip: %v", err)
	}
}

func TestProviderRoundTrip_StreamCountersSerialization(t *testing.T) {
	rec, err := Append(newStore(), ProviderRoundTrip{Provider: "openrouter", ModelID: "m", DurationMs: 1, Chunks: 7, ReasoningChars: 12})
	if err != nil {
		t.Fatal(err)
	}
	if raw := string(rec.(sessions.Event).Payload); !strings.Contains(raw, `"chunks":7`) || !strings.Contains(raw, `"reasoning_chars":12`) {
		t.Errorf("counters not written: %s", raw)
	}
	zero, err := Append(newStore(), ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: 1})
	if err != nil {
		t.Fatal(err)
	}
	if raw := string(zero.(sessions.Event).Payload); strings.Contains(raw, "chunks") || strings.Contains(raw, "reasoning_chars") {
		t.Errorf("zero counters wrote a key: %s", raw)
	}
	const old = `{"provider":"openrouter","model_id":"m","duration_ms":5,"turn_id":"` + goodV7 + `","round_id":"` + goodV7 + `"}`
	if err := ValidatePayload(KindProviderRoundTrip, json.RawMessage(old)); err != nil {
		t.Fatalf("ValidatePayload() rejected a provider_round_trip without counters: %v", err)
	}
}

func TestModelResponse_AnomalyRendersAsEmptyArray(t *testing.T) {
	rec, err := Append(newStore(), ModelResponse{Provider: "openai", ModelID: "gpt-5", InputTokens: 1, OutputTokens: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rec.(sessions.Event).Payload), `"anomaly":[]`) {
		t.Errorf("anomaly did not render as []: %s", rec.(sessions.Event).Payload)
	}
}

// TestAppend_TruncatedInvalidUTF8 covers: a truncated stream whose
// captured bytes contain invalid UTF-8 must append and load cleanly even though
// coercion to U+FFFD expands the persisted byte length past the raw captured
// length. Here one raw stdout byte ("\xff") was captured from a two-byte
// original stream; the persisted stdout is the 3-byte U+FFFD, yet original_bytes
// of 2 is valid against the one raw byte that was kept.
func TestAppend_TruncatedInvalidUTF8(t *testing.T) {
	p := ToolExecEnd{SubjectKind: "direct", Subject: "x", ExitCode: 0, DurationMs: 1, Stdout: "\xff", Truncated: true, OriginalBytes: &OriginalBytes{Stdout: 2, Stderr: 0}, InvocationID: goodV7}
	rec, err := Append(newStore(), p)
	if err != nil {
		t.Fatalf("Append() rejected valid truncated invalid-UTF-8 payload: %v", err)
	}
	raw := rec.(sessions.Event).Payload
	if !strings.Contains(string(raw), "�") {
		t.Errorf("persisted stdout did not contain U+FFFD: %s", raw)
	}
	if err := ValidatePayload(KindToolExecEnd, raw); err != nil {
		t.Errorf("ValidatePayload() rejected the canonical persisted payload: %v", err)
	}
}

func TestPermissionDecision_AllowOnceOmitsGrantFields(t *testing.T) {
	rec, err := Append(newStore(), PermissionDecision{SubjectKind: "tool", Subject: "vcs_commit", PathScope: "/home/u/proj", Outcome: "granted"})
	if err != nil {
		t.Fatalf("Append() rejected an allow-once decision: %v", err)
	}
	raw := string(rec.(sessions.Event).Payload)
	if strings.Contains(raw, "grant_kind") || strings.Contains(raw, "grant_path_scope") {
		t.Errorf("allow-once decision serialized grant fields: %s", raw)
	}
	if err := ValidatePayload(KindPermissionDecision, []byte(raw)); err != nil {
		t.Errorf("ValidatePayload() rejected the persisted allow-once decision: %v", err)
	}
}

func TestSlashCommand_ArgsRenderAsEmptyArray(t *testing.T) {
	rec, err := Append(newStore(), SlashCommand{Name: "clear", Outcome: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rec.(sessions.Event).Payload), `"args":[]`) {
		t.Errorf("args did not render as []: %s", rec.(sessions.Event).Payload)
	}
}

// invalidPayloads each violate a cross-field or enum rule; both Append (append
// time) and ValidatePayload (load time) must reject them.
var invalidPayloads = []struct {
	name string
	p    EventPayload
}{
	{"launch_began/bad-source", LaunchBegan{Source: "boot"}},
	{"session_forked/empty", SessionForked{}},
	{"session_forked/bad-uuid", SessionForked{ToSessionID: "not-a-v7"}},
	{"tool_exec_start/bad-uuid", ToolExecStart{SubjectKind: "tool", Subject: "Read", PathScope: "/p", InvocationID: "not-a-v7"}},
	{"tool_exec_start/bad-child-uuid", ToolExecStart{SubjectKind: "tool", Subject: "Read", PathScope: "/p", InvocationID: goodV7, ChildInvocationID: "not-a-v7"}},
	{"tool_exec_end/bad-child-uuid", ToolExecEnd{SubjectKind: "tool", Subject: "Read", DurationMs: 5, InvocationID: goodV7, ChildInvocationID: "not-a-v7"}},
	{"prompt_shown/bad-child-uuid", PermissionPromptShown{SubjectKind: "tool", Subject: "edit", PathScope: "/p", ChildInvocationID: "not-a-v7"}},
	{"permission_decision/bad-child-uuid", PermissionDecision{SubjectKind: "tool", Subject: "edit", PathScope: "/p", Outcome: "granted", ChildInvocationID: "not-a-v7"}},
	{"permission_matched/bad-child-uuid", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/p", Outcome: "once", OutcomeSource: "declared_scope", ChildInvocationID: "not-a-v7"}},
	{"child_agent_start/missing-invocation", ChildAgentStart{ProviderID: "openai", ModelID: "m", DeclaredPaths: []string{"/p/a.txt"}, StepCap: 1, InstructionBytes: 1, InstructionDigest: hex64}},
	{"child_agent_end/unknown-reason", ChildAgentEnd{InvocationID: goodV7, Reason: "abandoned", RollbackOutcome: "not_needed"}},
	{"child_agent_end/unknown-rollback", ChildAgentEnd{InvocationID: goodV7, Reason: "completed", RollbackOutcome: "partially"}},
	{"child_agent_end/negative-steps", ChildAgentEnd{InvocationID: goodV7, Reason: "completed", Steps: -1, RollbackOutcome: "not_needed"}},
	{"tool_exec_end/bad-uuid", ToolExecEnd{SubjectKind: "tool", Subject: "Read", ExitCode: 0, DurationMs: 5, Truncated: false, InvocationID: "not-a-v7"}},
	{"prompt_shown/star-scope", PermissionPromptShown{SubjectKind: "direct", Subject: "x", PathScope: "*"}},
	{"permission_prompt_wait/negative-waited", PermissionPromptWait{WaitedMs: -1, Prompts: 1, Ended: "answered"}},
	{"permission_prompt_wait/zero-prompts", PermissionPromptWait{WaitedMs: 1, Prompts: 0, Ended: "answered"}},
	{"permission_prompt_wait/negative-prompts", PermissionPromptWait{WaitedMs: 1, Prompts: -2, Ended: "answered"}},
	{"permission_prompt_wait/unknown-ended", PermissionPromptWait{WaitedMs: 1, Prompts: 1, Ended: "timed_out"}},
	{"permission_prompt_wait/empty-ended", PermissionPromptWait{WaitedMs: 1, Prompts: 1}},
	{"prompt_shown/host-missing-scope", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch"}},
	{"prompt_shown/host-wildcard", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "*"}},
	{"prompt_shown/host-uppercase", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "Docs.Example.com"}},
	{"prompt_shown/host-trailing-dot", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com."}},
	{"prompt_shown/host-unicode-idn", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "bücher.example"}},
	{"prompt_shown/host-url-form", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com/admin"}},
	{"prompt_shown/host-with-port", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs.example.com:443"}},
	{"prompt_shown/host-empty-label", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "docs..example.com"}},
	{"prompt_shown/host-invalid-punycode", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", HostScope: "xn--0.example.com"}},
	{"prompt_shown/host-non-web-subject", PermissionPromptShown{SubjectKind: "host", Subject: "Read", HostScope: "docs.example.com"}},
	{"prompt_shown/host-with-path-scope", PermissionPromptShown{SubjectKind: "host", Subject: "web_fetch", PathScope: "/p", HostScope: "docs.example.com"}},
	{"prompt_shown/path-with-host-scope", PermissionPromptShown{SubjectKind: "tool", Subject: "Read", PathScope: "/p", HostScope: "docs.example.com"}},
	{"prompt_shown/path-missing-scope", PermissionPromptShown{SubjectKind: "tool", Subject: "Read"}},
	{"decision/denied-with-grant", PermissionDecision{SubjectKind: "direct", Subject: "x", PathScope: "/p", Outcome: "denied", GrantKind: "folder", GrantPathScope: "/p"}},
	{"decision/granted-kind-without-scope", PermissionDecision{SubjectKind: "direct", Subject: "x", PathScope: "/p", Outcome: "granted", GrantKind: "folder"}},
	{"decision/granted-scope-without-kind", PermissionDecision{SubjectKind: "direct", Subject: "x", PathScope: "/p", Outcome: "granted", GrantPathScope: "/p"}},
	{"decision/global-bad-scope", PermissionDecision{SubjectKind: "direct", Subject: "x", PathScope: "/p", Outcome: "granted", GrantKind: "global", GrantPathScope: "/p"}},
	{"decision/host-with-path-scope", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", PathScope: "/p", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"decision/host-with-grant-path-scope", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", GrantPathScope: "/p", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"decision/path-with-host-scope", PermissionDecision{SubjectKind: "tool", Subject: "Read", PathScope: "/p", Outcome: "granted", GrantKind: "folder", GrantPathScope: "/p", HostScope: "docs.example.com"}},
	{"decision/host-missing-scope", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", GrantHostScope: "docs.example.com"}},
	{"decision/host-wildcard", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "*", GrantHostScope: "*"}},
	{"decision/host-uppercase", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "Docs.Example.com", GrantHostScope: "Docs.Example.com"}},
	{"decision/host-trailing-dot", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com.", GrantHostScope: "docs.example.com."}},
	{"decision/host-unicode-idn", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "bücher.example", GrantHostScope: "bücher.example"}},
	{"decision/host-url-form", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com/admin", GrantHostScope: "docs.example.com/admin"}},
	{"decision/host-empty-label", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "docs..example.com", GrantHostScope: "docs..example.com"}},
	{"decision/host-with-port", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "web_fetch:443", GrantHostScope: "web_fetch:443"}},
	{"decision/host-invalid-punycode", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "xn--0.example.com", GrantHostScope: "xn--0.example.com"}},
	{"matched/host-invalid-punycode", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "project_grant", OutcomeSource: "grant", HostScope: "xn--0.example.com", GrantHostScope: "xn--0.example.com"}},
	{"persist_failed/host-with-port", PermissionPersistFailed{TargetPath: "/p", GrantKind: "project", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", HostScope: "web_fetch:443"}},
	{"decision/host-grant-differs", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com", GrantHostScope: "evil.example.com"}},
	{"decision/host-global-lifetime", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "global", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"decision/host-folder-lifetime", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "granted", GrantKind: "folder", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"decision/host-denied-with-grant", PermissionDecision{SubjectKind: "host", Subject: "web_fetch", Outcome: "denied", GrantKind: "project", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"decision/host-non-web-subject", PermissionDecision{SubjectKind: "host", Subject: "Read", Outcome: "granted", GrantKind: "project", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"matched/host-with-path-scope", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", PathScope: "/p", GrantKind: "project", Outcome: "project_grant", OutcomeSource: "grant", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"matched/path-with-grant-host-scope", PermissionMatched{SubjectKind: "tool", Subject: "Read", PathScope: "/p", GrantKind: "folder", GrantPathScope: "/p", Outcome: "folder_grant", OutcomeSource: "grant", GrantHostScope: "docs.example.com"}},
	{"matched/host-missing-scope", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "project_grant", OutcomeSource: "grant", GrantHostScope: "docs.example.com"}},
	{"matched/host-wildcard", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "project_grant", OutcomeSource: "grant", HostScope: "*", GrantHostScope: "*"}},
	{"matched/host-global-lifetime", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "global", Outcome: "global_grant", OutcomeSource: "grant", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"matched/host-outcome-mismatch", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "session_grant", OutcomeSource: "grant", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"matched/host-grant-without-scope", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "project_grant", OutcomeSource: "grant", HostScope: "docs.example.com"}},
	{"matched/host-cache-once-with-grant", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "once", OutcomeSource: "cache", HostScope: "docs.example.com", GrantHostScope: "docs.example.com"}},
	{"matched/host-mode-auto", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", Outcome: "once", OutcomeSource: "mode_auto", HostScope: "docs.example.com"}},
	{"matched/host-with-argument-hash", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", GrantKind: "project", Outcome: "project_grant", OutcomeSource: "grant", HostScope: "docs.example.com", GrantHostScope: "docs.example.com", ArgumentHash: hex64}},
	{"persist_failed/host-global-lifetime", PermissionPersistFailed{TargetPath: "/p", GrantKind: "global", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", HostScope: "docs.example.com"}},
	{"persist_failed/host-session-lifetime", PermissionPersistFailed{TargetPath: "/p", GrantKind: "session", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", HostScope: "docs.example.com"}},
	{"persist_failed/host-missing-scope", PermissionPersistFailed{TargetPath: "/p", GrantKind: "project", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x"}},
	{"persist_failed/host-wildcard", PermissionPersistFailed{TargetPath: "/p", GrantKind: "project", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", HostScope: "*"}},
	{"persist_failed/host-with-degraded-path", PermissionPersistFailed{TargetPath: "/p", GrantKind: "project", SubjectKind: "host", Subject: "web_fetch", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", HostScope: "docs.example.com", DegradedToPathScope: "/home/u/proj"}},
	{"persist_failed/path-with-host-scope", PermissionPersistFailed{TargetPath: "/p", GrantKind: "folder", SubjectKind: "tool", Subject: "Read", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", HostScope: "docs.example.com"}},
	{"matched/source-prompt", PermissionMatched{SubjectKind: "direct", Subject: "x", PathScope: "/p", GrantKind: "folder", GrantPathScope: "/p", Outcome: "folder_grant", OutcomeSource: "prompt"}},
	{"matched/outcome-mismatch", PermissionMatched{SubjectKind: "direct", Subject: "x", PathScope: "/p", GrantKind: "folder", GrantPathScope: "/p", Outcome: "global_grant", OutcomeSource: "grant"}},
	{"matched/cache-once-with-grant", PermissionMatched{SubjectKind: "direct", Subject: "x", PathScope: "/p", GrantKind: "folder", GrantPathScope: "/p", Outcome: "once", OutcomeSource: "cache"}},
	{"matched/hash-non-literal", PermissionMatched{SubjectKind: "direct", Subject: "x", PathScope: "/p", GrantKind: "folder", GrantPathScope: "/p", Outcome: "folder_grant", OutcomeSource: "grant", ArgumentHash: hex64}},
	{"matched/hash-mismatch", PermissionMatched{SubjectKind: "literal", Subject: "npm test", PathScope: "/home/u/proj", GrantKind: "session", GrantPathScope: "/home/u/proj", Outcome: "session_grant", OutcomeSource: "grant", ArgumentHash: hex64}},
	{"matched/literal-missing-hash", PermissionMatched{SubjectKind: "literal", Subject: "npm test", PathScope: "/home/u/proj", GrantKind: "session", GrantPathScope: "/home/u/proj", Outcome: "session_grant", OutcomeSource: "grant"}},
	{"matched/mode-auto-with-grant", PermissionMatched{SubjectKind: "tool", Subject: "x", PathScope: "/p", GrantKind: "folder", GrantPathScope: "/p", Outcome: "once", OutcomeSource: "mode_auto"}},
	{"matched/mode-auto-grant-outcome", PermissionMatched{SubjectKind: "tool", Subject: "x", PathScope: "/p", Outcome: "folder_grant", OutcomeSource: "mode_auto"}},
	{"matched/mode-auto-literal-missing-hash", PermissionMatched{SubjectKind: "literal", Subject: "npm test", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "mode_auto"}},
	{"matched/protected-state-once", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/.codemeld", Outcome: "once", OutcomeSource: "protected_state"}},
	{"matched/protected-state-grant-outcome", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/.codemeld", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "folder_grant", OutcomeSource: "protected_state"}},
	{"matched/protected-state-with-grant", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/.codemeld", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-unregistered-vcs-action", PermissionMatched{SubjectKind: "tool", Subject: "vcs_checkout", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-direct-subject", PermissionMatched{SubjectKind: "direct", Subject: "rm -rf /", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-literal-subject", PermissionMatched{SubjectKind: "literal", Subject: "npm test", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state", ArgumentHash: litHash("npm test")}},
	{"matched/protected-state-host", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", Outcome: "deny", OutcomeSource: "protected_state", HostScope: "docs.example.com"}},
	{"matched/protected-state-missing-scope", PermissionMatched{SubjectKind: "tool", Subject: "edit", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-relative-scope", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: ".codemeld", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-dirty-scope", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/../u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-star-scope", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "*", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-empty-subject", PermissionMatched{SubjectKind: "tool", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-argument-hash", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state", ArgumentHash: hex64}},
	{"matched/protected-state-unguarded-tool", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/protected-state-unknown-tool", PermissionMatched{SubjectKind: "tool", Subject: "frobnicate", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state"}},
	{"matched/blocked-path-once", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "once", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/.ssh"}},
	{"matched/blocked-path-host", PermissionMatched{SubjectKind: "host", Subject: "web_fetch", Outcome: "deny", OutcomeSource: "blocked_path", HostScope: "docs.example.com", BlockedEntry: "/home/u/.ssh"}},
	{"matched/blocked-path-vcs-subject", PermissionMatched{SubjectKind: "tool", Subject: "vcs_commit", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/proj"}},
	{"matched/blocked-path-vcs-status-subject", PermissionMatched{SubjectKind: "tool", Subject: "vcs_status", PathScope: "/home/u/proj", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/proj/secrets"}},
	{"matched/blocked-path-relative-entry", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: ".ssh"}},
	{"matched/blocked-path-dirty-entry", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/../u/.ssh"}},
	{"matched/blocked-path-relative-entry-source", PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/.ssh", BlockedEntrySource: "settings.yaml"}},
	{"matched/blocked-path-direct-once", PermissionMatched{SubjectKind: "direct", Subject: "cat /home/u/.ssh/k", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "blocked_path", BlockedEntry: "/home/u/.ssh"}},
	{"matched/blocked-path-literal-once", PermissionMatched{SubjectKind: "literal", Subject: "cat /home/u/.ssh/k 2>/dev/null", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "blocked_path", ArgumentHash: litHash("cat /home/u/.ssh/k 2>/dev/null"), BlockedEntry: "/home/u/.ssh"}},
	{"matched/protected-state-blocked-entry", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state", BlockedEntry: "/home/u/proj/.codemeld"}},
	{"matched/protected-state-blocked-entry-source", PermissionMatched{SubjectKind: "tool", Subject: "edit", PathScope: "/home/u/proj/.codemeld", Outcome: "deny", OutcomeSource: "protected_state", BlockedEntrySource: "/home/u/.codemeld/global/settings.yaml"}},
	{"matched/mode-auto-blocked-entry", PermissionMatched{SubjectKind: "tool", Subject: "read_file", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "mode_auto", BlockedEntry: "/home/u/proj"}},
	{"matched/mode-auto-blocked-entry-source", PermissionMatched{SubjectKind: "tool", Subject: "read_file", PathScope: "/home/u/proj", Outcome: "once", OutcomeSource: "mode_auto", BlockedEntrySource: "/home/u/.codemeld/global/settings.yaml"}},
	{"tool_exec_end/truncated-missing-bytes", ToolExecEnd{SubjectKind: "direct", Subject: "ls", Truncated: true, InvocationID: "id"}},
	{"tool_exec_end/clean-with-bytes", ToolExecEnd{SubjectKind: "direct", Subject: "ls", Truncated: false, OriginalBytes: &OriginalBytes{}, InvocationID: "id"}},
	{"tool_exec_end/truncated-stdout-smaller", ToolExecEnd{SubjectKind: "direct", Subject: "x", ExitCode: 0, DurationMs: 1, Stdout: "abc", Truncated: true, OriginalBytes: &OriginalBytes{Stdout: 0, Stderr: 0}, InvocationID: goodV7}},
	{"tool_exec_end/truncated-equal-bytes", ToolExecEnd{SubjectKind: "direct", Subject: "x", ExitCode: 0, DurationMs: 1, Stdout: "abc", Truncated: true, OriginalBytes: &OriginalBytes{Stdout: 3, Stderr: 0}, InvocationID: goodV7}},
	{"agent_loaded/loaded-with-error", AgentInstructionsLoaded{Path: "/p", Layer: "walked", LoadOrder: 2, ErrorDetail: "x"}},
	{"agent_loaded/unreadable-missing-category", AgentInstructionsLoaded{Path: "/p", Layer: "walked", LoadOrder: 2, SkipReason: "unreadable", ErrorDetail: "x"}},
	{"agent_loaded/bad-load-order", AgentInstructionsLoaded{Path: "/p", Layer: "global", LoadOrder: 0}},
	{"agent_loaded/walked-order-1", AgentInstructionsLoaded{Path: "/p", Layer: "walked", LoadOrder: 1}},
	{"agent_loaded/global-order-2", AgentInstructionsLoaded{Path: "/p", Layer: "global", LoadOrder: 2}},
	{"prune/nonzero-empty-failures", SessionPruneSummary{FilesScanned: 1, FilesFailed: 1}},
	{"prune/count-mismatch", SessionPruneSummary{FilesScanned: 5, FilesFailed: 2, Failures: []PruneFailure{{Path: "/p", Reason: "io_error", Kind: "file_delete"}}}},
	{"prune/bad-failure-kind", SessionPruneSummary{FilesScanned: 1, FilesFailed: 1, Failures: []PruneFailure{{Path: "/p", Reason: "io_error", Kind: "weird"}}}},
	{"write_failed/bad-reason", SessionWriteFailed{TargetPath: "/p", Reason: "lock_timeout", ErrorCategory: "io_error", ErrorDetail: "x"}},
	{"persist_failed/folder-with-degraded", PermissionPersistFailed{TargetPath: "/p", GrantKind: "folder", SubjectKind: "direct", Subject: "x", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", DegradedToPathScope: "/p"}},
	{"persist_failed/lock-timeout-wrong-detail", PermissionPersistFailed{TargetPath: "/p", GrantKind: "global", SubjectKind: "direct", Subject: "x", Reason: "lock_timeout", ErrorDetail: "nope", DegradedToPathScope: "/p"}},
	{"model_turn/empty-effort", ModelTurn{Provider: "o", ModelID: "m", Effort: "", Source: "project"}},
	{"model_response/bad-anomaly", ModelResponse{Provider: "o", ModelID: "m", Anomaly: []string{"weird"}}},
	{"model_response/negative-cached", ModelResponse{Provider: "o", ModelID: "m", CachedInputTokens: i64(-1)}},
	{"model_response/partial-without-cached", ModelResponse{Provider: "o", ModelID: "m", CachedInputTokensPartial: true}},
	{"model_response/negative-cost", ModelResponse{Provider: "o", ModelID: "m", CostUSD: f64(-0.01)}},
	{"model_response/cost-partial-without-cost", ModelResponse{Provider: "o", ModelID: "m", CostUSDPartial: true}},
	{"model_changed/partial-prior", ModelChanged{NewProvider: "o", NewModelID: "m", NewEffort: "high", PriorProvider: "o"}},
	{"model_changed/empty-new-effort", ModelChanged{NewProvider: "o", NewModelID: "m", NewEffort: ""}},
	{"model_effort_unsupported/empty-configured-effort", ModelEffortUnsupported{Provider: "o", ModelID: "m", ConfiguredEffort: ""}},
	{"model_persist_failed/empty-effort", ModelPersistFailed{TargetPath: "/home/u/proj/.codemeld/settings.yaml", Provider: "o", ModelID: "m", Effort: "", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error"}},
	{"model_global_mirror_failed/empty-effort", ModelGlobalMirrorFailed{TargetPath: "/home/u/.codemeld/global/settings.yaml", Provider: "o", ModelID: "m", Effort: "", Reason: "rename_error", ErrorCategory: "io_error", ErrorDetail: "rename: io error"}},
	{"model_recovery/bad-reason", ModelRecoveryFailed{Reason: "boom", ErrorDetail: "x"}},
	{"model_catalog_refreshed/missing-provider", ModelCatalogRefreshed{Outcome: "updated"}},
	{"model_catalog_refreshed/empty-outcome", ModelCatalogRefreshed{Provider: "openai"}},
	{"model_catalog_refreshed/unknown-outcome", ModelCatalogRefreshed{Provider: "openai", Outcome: "refreshed"}},
	{"slash/error-missing-detail", SlashCommand{Name: "model", Outcome: "error"}},
	{"slash/success-with-detail", SlashCommand{Name: "help", Outcome: "success", ErrorDetail: "x"}},
	{"stream/bad-source", StreamInterrupted{Source: "swipe"}},
	{"provider/http-missing-status", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "http", Reason: "http_no_body", ErrorDetail: "x"}},
	{"provider/http-error-missing-status", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "http", Reason: "http_error", ErrorDetail: "x"}},
	{"provider/http-unknown-reason", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "http", HTTPStatus: i64(500), Reason: "http_bogus", ErrorDetail: "x"}},
	{"provider/dial-with-status", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "dial", HTTPStatus: i64(500), Reason: "dns_error", ErrorDetail: "x"}},
	{"provider/reason-phase-mismatch", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "dial", Reason: "tls_handshake", ErrorDetail: "x"}},
	{"provider/cert-reason-wrong-phase", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "dial", Reason: "tls_cert_invalid", ErrorDetail: "x"}},
	{"provider/tls-with-status", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "tls", HTTPStatus: i64(495), Reason: "tls_cert_invalid", ErrorDetail: "x"}},
	{"provider/partial-chars-wrong-phase", ProviderRequestFailed{Provider: "o", ModelID: "m", Phase: "dial", Reason: "dns_error", PartialResponseChars: 5, ErrorDetail: "x"}},
	{"prompt_shown/relative-scope", PermissionPromptShown{SubjectKind: "direct", Subject: "x", PathScope: "proj"}},
	{"prompt_shown/dirty-scope", PermissionPromptShown{SubjectKind: "direct", Subject: "x", PathScope: "/home/u/../u/proj"}},
	{"matched/relative-scope", PermissionMatched{SubjectKind: "direct", Subject: "git status", PathScope: "proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "folder_grant", OutcomeSource: "grant"}},
	{"matched/dirty-scope", PermissionMatched{SubjectKind: "direct", Subject: "git status", PathScope: "/home/u/../u/proj", GrantKind: "folder", GrantPathScope: "/home/u/proj", Outcome: "folder_grant", OutcomeSource: "grant"}},
	{"matched/star-scope", PermissionMatched{SubjectKind: "tool", Subject: "Read", PathScope: "*", GrantKind: "global", GrantPathScope: "*", Outcome: "global_grant", OutcomeSource: "grant"}},
	{"decision/relative-grant-scope", PermissionDecision{SubjectKind: "direct", Subject: "x", PathScope: "/p", Outcome: "granted", GrantKind: "folder", GrantPathScope: "proj"}},
	{"tool_exec_start/relative-scope", ToolExecStart{SubjectKind: "tool", Subject: "Read", PathScope: "proj", InvocationID: goodV7}},
	{"agent_loaded/relative-path", AgentInstructionsLoaded{Path: "AGENTS.md", Layer: "walked", LoadOrder: 2}},
	{"prune/relative-failure-path", SessionPruneSummary{FilesScanned: 1, FilesFailed: 1, Failures: []PruneFailure{{Path: "s/a.json", Reason: "io_error", Kind: "file_delete"}}}},
	{"write_failed/dirty-target", SessionWriteFailed{TargetPath: "/home/u/../u/s.json", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x"}},
	{"persist_failed/relative-target", PermissionPersistFailed{TargetPath: "settings.yaml", GrantKind: "global", SubjectKind: "direct", Subject: "x", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", DegradedToPathScope: "/home/u/proj"}},
	{"persist_failed/relative-degraded-scope", PermissionPersistFailed{TargetPath: "/p", GrantKind: "global", SubjectKind: "direct", Subject: "x", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "x", DegradedToPathScope: "proj"}},
	{"model_persist_failed/relative-target", ModelPersistFailed{TargetPath: "settings.yaml", Provider: "openai", ModelID: "gpt-5", Effort: "high", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error"}},
	{"model_persist_failed/dirty-target", ModelPersistFailed{TargetPath: "/home/u/../u/settings.yaml", Provider: "openai", ModelID: "gpt-5", Effort: "high", Reason: "write_error", ErrorCategory: "io_error", ErrorDetail: "write: io error"}},
	{"model_global_mirror_failed/relative-target", ModelGlobalMirrorFailed{TargetPath: "settings.yaml", Provider: "openai", ModelID: "gpt-5", Effort: "high", Reason: "rename_error", ErrorCategory: "io_error", ErrorDetail: "rename: io error"}},
	{"model_global_mirror_failed/dirty-target", ModelGlobalMirrorFailed{TargetPath: "/home/u/../u/settings.yaml", Provider: "openai", ModelID: "gpt-5", Effort: "high", Reason: "rename_error", ErrorCategory: "io_error", ErrorDetail: "rename: io error"}},
	{"interaction_mode/bad-mode", InteractionMode{Mode: "turbo", Source: "default", Trigger: "launch"}},
	{"interaction_mode/source-is-trigger", InteractionMode{Mode: "build", Source: "resume", Trigger: "launch"}},
	{"interaction_mode/bad-trigger", InteractionMode{Mode: "build", Source: "default", Trigger: "boot"}},
	{"interaction_mode/empty", InteractionMode{}},
	{"turn_latency/missing-provider", TurnLatency{ModelID: "gpt-5", DurationMs: 1}},
	{"turn_latency/missing-model", TurnLatency{Provider: "openai", DurationMs: 1}},
	{"turn_latency/negative-duration", TurnLatency{Provider: "openai", ModelID: "gpt-5", DurationMs: -1}},
	{"provider_round_trip/missing-provider", ProviderRoundTrip{ModelID: "gpt-5", DurationMs: 1}},
	{"provider_round_trip/missing-model", ProviderRoundTrip{Provider: "openai", DurationMs: 1}},
	{"provider_round_trip/negative-duration", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: -1}},
	{"provider_round_trip/negative-chunks", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: 1, Chunks: -1}},
	{"provider_round_trip/negative-reasoning-chars", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: 1, ReasoningChars: -1}},
	{"provider_round_trip/ids-negative-chunks", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: 1, TurnID: goodV7, RoundID: goodV7, Chunks: -1}},
	{"provider_round_trip/ids-negative-reasoning-chars", ProviderRoundTrip{Provider: "openai", ModelID: "gpt-5", DurationMs: 1, TurnID: goodV7, RoundID: goodV7, ReasoningChars: -1}},
	{"suggest_followup_debug/bad-stage", SuggestFollowupDebug{Stage: "wat", Provider: "o", ModelID: "m", Mode: "build", Advertised: bptr(true)}},
	{"suggest_followup_debug/missing-provider", SuggestFollowupDebug{Stage: "provider_round_no_call", ModelID: "m", Mode: "build"}},
	{"suggest_followup_debug/missing-model", SuggestFollowupDebug{Stage: "provider_round_no_call", Provider: "o", Mode: "build"}},
	{"suggest_followup_debug/missing-mode", SuggestFollowupDebug{Stage: "provider_round_no_call", Provider: "o", ModelID: "m"}},
	{"suggest_followup_debug/negative-label", SuggestFollowupDebug{Stage: "intercepted", Provider: "o", ModelID: "m", Mode: "build", LabelLen: -1}},
	{"suggest_followup_debug/negative-prompt", SuggestFollowupDebug{Stage: "intercepted", Provider: "o", ModelID: "m", Mode: "build", PromptLen: -1}},
	{"suggest_followup_debug/advertised-missing-on-request", SuggestFollowupDebug{Stage: "request_built", Provider: "o", ModelID: "m", Mode: "build"}},
	{"suggest_followup_debug/advertised-on-wrong-stage", SuggestFollowupDebug{Stage: "ghost_set", Provider: "o", ModelID: "m", Mode: "build", Advertised: bptr(true)}},
	{"suggest_followup_debug/reason-missing-on-cleared", SuggestFollowupDebug{Stage: "ghost_cleared", Provider: "o", ModelID: "m", Mode: "build"}},
	{"suggest_followup_debug/reason-on-wrong-stage", SuggestFollowupDebug{Stage: "ghost_set", Provider: "o", ModelID: "m", Mode: "build", Reason: "nope"}},
	{"provider_stream_idle/missing-provider", ProviderStreamIdle{ModelID: "gpt-5", RoundElapsedMs: 1, IdleMs: 1}},
	{"provider_stream_idle/missing-model", ProviderStreamIdle{Provider: "openai", RoundElapsedMs: 1, IdleMs: 1}},
	{"provider_stream_idle/negative-round", ProviderStreamIdle{Provider: "openai", ModelID: "gpt-5", RoundElapsedMs: -1, IdleMs: 1}},
	{"provider_stream_idle/negative-idle", ProviderStreamIdle{Provider: "openai", ModelID: "gpt-5", RoundElapsedMs: 1, IdleMs: -1}},
	{"provider_stream_idle/negative-partial", ProviderStreamIdle{Provider: "openai", ModelID: "gpt-5", RoundElapsedMs: 1, IdleMs: 1, PartialChars: -1}},
	{"queued_prompt_discarded/unknown-reason", QueuedPromptDiscarded{Text: "hi", Reason: "cancelled"}},
	{"queued_prompt_discarded/empty-reason", QueuedPromptDiscarded{Text: "hi"}},
	{"queued_prompt_discarded/negative-image_count", QueuedPromptDiscarded{Text: "hi", ImageCount: -1, Reason: "interrupted"}},
	{"queued_prompt_discarded/no-content", QueuedPromptDiscarded{Reason: "interrupted"}},
	{"structured_read_start/missing-tool_name", StructuredReadStart{PathScope: "/home/u/proj/a.go", InvocationID: goodV7, ConfiguredConcurrency: 1}},
	{"structured_read_start/unknown-tool_name", StructuredReadStart{ToolName: "read_image", PathScope: "/home/u/proj/a.go", InvocationID: goodV7, ConfiguredConcurrency: 1}},
	{"structured_read_start/relative-scope", StructuredReadStart{ToolName: "read", PathScope: "proj/a.go", InvocationID: goodV7, ConfiguredConcurrency: 1}},
	{"structured_read_start/dirty-scope", StructuredReadStart{ToolName: "read", PathScope: "/home/u/../u/proj/a.go", InvocationID: goodV7, ConfiguredConcurrency: 1}},
	{"structured_read_start/star-scope", StructuredReadStart{ToolName: "read", PathScope: "*", InvocationID: goodV7, ConfiguredConcurrency: 1}},
	{"structured_read_start/empty-scope", StructuredReadStart{ToolName: "read", InvocationID: goodV7, ConfiguredConcurrency: 1}},
	{"structured_read_start/bad-uuid", StructuredReadStart{ToolName: "read", PathScope: "/home/u/proj/a.go", InvocationID: "not-a-v7", ConfiguredConcurrency: 1}},
	{"structured_read_start/zero-concurrency", StructuredReadStart{ToolName: "read", PathScope: "/home/u/proj/a.go", InvocationID: goodV7, ConfiguredConcurrency: 0}},
	{"structured_read_start/negative-concurrency", StructuredReadStart{ToolName: "read", PathScope: "/home/u/proj/a.go", InvocationID: goodV7, ConfiguredConcurrency: -1}},
	{"structured_read_end/missing-tool_name", StructuredReadEnd{InvocationID: goodV7, Outcome: "success", DurationMs: 1}},
	{"structured_read_end/unknown-tool_name", StructuredReadEnd{ToolName: "read_image", InvocationID: goodV7, Outcome: "success", DurationMs: 1}},
	{"structured_read_end/bad-uuid", StructuredReadEnd{ToolName: "read", InvocationID: "not-a-v7", Outcome: "success", DurationMs: 1}},
	{"structured_read_end/bad-outcome", StructuredReadEnd{ToolName: "read", InvocationID: goodV7, Outcome: "ok", DurationMs: 1}},
	{"structured_read_end/empty-outcome", StructuredReadEnd{ToolName: "read", InvocationID: goodV7, DurationMs: 1}},
	{"structured_read_end/negative-duration", StructuredReadEnd{ToolName: "read", InvocationID: goodV7, Outcome: "success", DurationMs: -1}},
	{"structured_read_refused/missing-tool_name", StructuredReadRefused{Reason: "out_of_project", BatchSize: 1}},
	{"structured_read_refused/unknown-reason", StructuredReadRefused{ToolName: "read", Reason: "ineligible", BatchSize: 1}},
	{"structured_read_refused/empty-reason", StructuredReadRefused{ToolName: "read", BatchSize: 1}},
	{"structured_read_refused/zero-batch_size", StructuredReadRefused{ToolName: "read", Reason: "out_of_project", BatchSize: 0}},
	{"structured_read_refused/negative-batch_size", StructuredReadRefused{ToolName: "read", Reason: "out_of_project", BatchSize: -1}},
}

func TestAppend_RejectsInvalidPayloads(t *testing.T) {
	for _, tc := range invalidPayloads {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.p); err == nil {
				t.Errorf("Append() accepted invalid payload")
			}
			if got := len(store.Records()); got != 0 {
				t.Errorf("rejected payload still appended %d record(s)", got)
			}
			// Same payload must also be rejected by the load-time validator.
			raw, err := marshalPayload(tc.p)
			if err != nil {
				t.Fatalf("marshalPayload() error = %v", err)
			}
			if err := ValidatePayload(tc.p.Kind(), raw); err == nil {
				t.Errorf("ValidatePayload() accepted invalid payload: %s", raw)
			}
		})
	}
}

func TestAppend_BlockedPathRequiresEntry(t *testing.T) {
	store := newStore()
	p := PermissionMatched{SubjectKind: "tool", Subject: "read", PathScope: "/home/u/.ssh", Outcome: "deny", OutcomeSource: "blocked_path"}
	if _, err := Append(store, p); err == nil {
		t.Fatal("Append() accepted a blocked_path record without blocked_entry")
	}
	if got := len(store.Records()); got != 0 {
		t.Fatalf("rejected payload still appended %d record(s)", got)
	}
}

func TestValidatePayload_UnknownKind(t *testing.T) {
	if err := ValidatePayload("not_a_kind", json.RawMessage(`{}`)); err == nil {
		t.Fatal("ValidatePayload() accepted an unknown kind")
	}
}

func TestValidatePayload_TypeMismatchSurfaces(t *testing.T) {
	// A string where an integer is required is a decode error at load time.
	if err := ValidatePayload(KindStreamInterrupted, json.RawMessage(`{"source":"esc","content_chars":"lots"}`)); err == nil {
		t.Fatal("ValidatePayload() accepted a type-mismatched payload")
	}
	if err := ValidatePayload(KindStructuredReadStart, json.RawMessage(`{"tool_name":"read","path_scope":"/home/u/proj/a.go","invocation_id":"`+goodV7+`","configured_concurrency":"four"}`)); err == nil {
		t.Fatal("ValidatePayload() accepted a string configured_concurrency")
	}
	if err := ValidatePayload(KindStructuredReadEnd, json.RawMessage(`{"tool_name":"read","invocation_id":"`+goodV7+`","outcome":"success","duration_ms":"fast"}`)); err == nil {
		t.Fatal("ValidatePayload() accepted a string duration_ms")
	}
	if err := ValidatePayload(KindStructuredReadRefused, json.RawMessage(`{"tool_name":"read","reason":"out_of_project","batch_size":"six"}`)); err == nil {
		t.Fatal("ValidatePayload() accepted a string batch_size")
	}
	if err := ValidatePayload(KindQueuedPromptDiscarded, json.RawMessage(`{"text":"summarize the diff","image_count":"two","reason":"interrupted"}`)); err == nil {
		t.Fatal("ValidatePayload() accepted a string image_count")
	}
}

const goodV7 = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02"

// TestValidatePayload_RejectsMissingRequiredField verifies the load-time
// validator distinguishes an absent required field from an explicit zero value:
// a record omitting a non-optional number, bool, or list is rejected
// even though the field would otherwise unmarshal to a valid-looking zero.
func TestValidatePayload_RejectsMissingRequiredField(t *testing.T) {
	cases := []struct {
		name string
		kind string
		raw  string
	}{
		{"stream_interrupted/missing-content_chars", KindStreamInterrupted, `{"source":"esc"}`},
		{"tool_exec_end/missing-truncated", KindToolExecEnd, `{"subject_kind":"tool","subject":"Read","exit_code":0,"duration_ms":5,"invocation_id":"` + goodV7 + `"}`},
		{"tool_exec_end/missing-exit_code", KindToolExecEnd, `{"subject_kind":"tool","subject":"Read","duration_ms":5,"truncated":false,"invocation_id":"` + goodV7 + `"}`},
		{"slash_command/missing-args", KindSlashCommand, `{"name":"clear","outcome":"success"}`},
		{"model_response/missing-anomaly", KindModelResponse, `{"provider":"openai","model_id":"gpt-5","input_tokens":1,"output_tokens":2}`},
		{"turn_latency/missing-duration_ms", KindTurnLatency, `{"provider":"openai","model_id":"gpt-5"}`},
		{"provider_round_trip/missing-duration_ms", KindProviderRoundTrip, `{"provider":"openai","model_id":"gpt-5"}`},
		{"provider_stream_idle/missing-idle_ms", KindProviderStreamIdle, `{"provider":"openai","model_id":"gpt-5","round_elapsed_ms":1,"partial_chars":0}`},
		{"provider_stream_idle/missing-partial_chars", KindProviderStreamIdle, `{"provider":"openai","model_id":"gpt-5","round_elapsed_ms":1,"idle_ms":1}`},
		{"structured_read_start/missing-configured_concurrency", KindStructuredReadStart, `{"tool_name":"read","path_scope":"/home/u/proj/a.go","invocation_id":"` + goodV7 + `"}`},
		{"structured_read_start/missing-path_scope", KindStructuredReadStart, `{"tool_name":"read","invocation_id":"` + goodV7 + `","configured_concurrency":2}`},
		{"structured_read_start/missing-tool_name", KindStructuredReadStart, `{"path_scope":"/home/u/proj/a.go","invocation_id":"` + goodV7 + `","configured_concurrency":2}`},
		{"structured_read_start/missing-invocation_id", KindStructuredReadStart, `{"tool_name":"read","path_scope":"/home/u/proj/a.go","configured_concurrency":2}`},
		{"structured_read_end/missing-duration_ms", KindStructuredReadEnd, `{"tool_name":"read","invocation_id":"` + goodV7 + `","outcome":"success"}`},
		{"structured_read_end/missing-outcome", KindStructuredReadEnd, `{"tool_name":"read","invocation_id":"` + goodV7 + `","duration_ms":1}`},
		{"structured_read_end/missing-invocation_id", KindStructuredReadEnd, `{"tool_name":"read","outcome":"success","duration_ms":1}`},
		{"structured_read_end/missing-tool_name", KindStructuredReadEnd, `{"invocation_id":"` + goodV7 + `","outcome":"success","duration_ms":1}`},
		{"structured_read_refused/missing-batch_size", KindStructuredReadRefused, `{"tool_name":"read","reason":"out_of_project"}`},
		{"structured_read_refused/missing-reason", KindStructuredReadRefused, `{"tool_name":"read","batch_size":2}`},
		{"structured_read_refused/missing-tool_name", KindStructuredReadRefused, `{"reason":"out_of_project","batch_size":2}`},
		{"queued_prompt_discarded/missing-text", KindQueuedPromptDiscarded, `{"image_count":2,"reason":"turn_failed"}`},
		{"queued_prompt_discarded/missing-image_count", KindQueuedPromptDiscarded, `{"text":"summarize the diff","reason":"interrupted"}`},
		{"queued_prompt_discarded/missing-reason", KindQueuedPromptDiscarded, `{"text":"summarize the diff","image_count":0}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(tc.kind, json.RawMessage(tc.raw)); err == nil {
				t.Errorf("ValidatePayload() accepted a payload missing a required field: %s", tc.raw)
			}
		})
	}
}

// TestValidatePayload_AcceptsExplicitZeroValues verifies the boundary the
// presence check must not over-reject: a present-but-zero number, an explicit
// false bool, and an explicit empty list are all valid.
func TestValidatePayload_AcceptsExplicitZeroValues(t *testing.T) {
	cases := []struct {
		name string
		kind string
		raw  string
	}{
		{"stream_interrupted/zero-content_chars", KindStreamInterrupted, `{"source":"esc","content_chars":0}`},
		{"tool_exec_end/false-truncated", KindToolExecEnd, `{"subject_kind":"tool","subject":"Read","exit_code":0,"duration_ms":5,"truncated":false,"invocation_id":"` + goodV7 + `"}`},
		{"slash_command/empty-args", KindSlashCommand, `{"name":"clear","args":[],"outcome":"success"}`},
		{"model_response/empty-anomaly", KindModelResponse, `{"provider":"openai","model_id":"gpt-5","input_tokens":0,"output_tokens":0,"anomaly":[]}`},
		{"queued_prompt_discarded/zero-image_count", KindQueuedPromptDiscarded, `{"text":"summarize the diff","image_count":0,"reason":"interrupted"}`},
		{"queued_prompt_discarded/empty-text", KindQueuedPromptDiscarded, `{"text":"","image_count":2,"reason":"turn_failed"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(tc.kind, json.RawMessage(tc.raw)); err != nil {
				t.Errorf("ValidatePayload() rejected a valid present-zero payload %s: %v", tc.raw, err)
			}
		})
	}
}

// TestValidatePayload_RejectsNullRequiredField verifies the load-time validator
// rejects a JSON null in a required field — for a top-level scalar/list, for a
// nested object subfield, and a nested object missing a required subfield — none
// of which a plain struct decode can distinguish from an explicit zero value.
func TestValidatePayload_RejectsNullRequiredField(t *testing.T) {
	cases := []struct {
		name string
		kind string
		raw  string
	}{
		{"stream_interrupted/null-content_chars", KindStreamInterrupted, `{"source":"esc","content_chars":null}`},
		{"tool_exec_end/null-truncated", KindToolExecEnd, `{"subject_kind":"tool","subject":"Read","exit_code":0,"duration_ms":5,"truncated":null,"invocation_id":"` + goodV7 + `"}`},
		{"model_response/null-anomaly", KindModelResponse, `{"provider":"openai","model_id":"gpt-5","input_tokens":1,"output_tokens":2,"anomaly":null}`},
		{"slash_command/null-args", KindSlashCommand, `{"name":"clear","args":null,"outcome":"success"}`},
		{"tool_exec_end/original_bytes-missing-stderr", KindToolExecEnd, `{"subject_kind":"direct","subject":"ls","exit_code":0,"duration_ms":1,"truncated":true,"original_bytes":{"stdout":10},"invocation_id":"` + goodV7 + `"}`},
		{"tool_exec_end/original_bytes-null-stderr", KindToolExecEnd, `{"subject_kind":"direct","subject":"ls","exit_code":0,"duration_ms":1,"truncated":true,"original_bytes":{"stdout":10,"stderr":null},"invocation_id":"` + goodV7 + `"}`},
		{"prune/failure-null-path", KindSessionPruneSummary, `{"files_scanned":1,"files_deleted":0,"files_failed":1,"failures":[{"path":null,"reason":"io_error","kind":"file_delete"}],"elapsed_ms":1}`},
		{"structured_read_start/null-configured_concurrency", KindStructuredReadStart, `{"tool_name":"read","path_scope":"/home/u/proj/a.go","invocation_id":"` + goodV7 + `","configured_concurrency":null}`},
		{"structured_read_start/null-path_scope", KindStructuredReadStart, `{"tool_name":"read","path_scope":null,"invocation_id":"` + goodV7 + `","configured_concurrency":2}`},
		{"structured_read_start/null-tool_name", KindStructuredReadStart, `{"tool_name":null,"path_scope":"/home/u/proj/a.go","invocation_id":"` + goodV7 + `","configured_concurrency":2}`},
		{"structured_read_start/null-invocation_id", KindStructuredReadStart, `{"tool_name":"read","path_scope":"/home/u/proj/a.go","invocation_id":null,"configured_concurrency":2}`},
		{"structured_read_end/null-duration_ms", KindStructuredReadEnd, `{"tool_name":"read","invocation_id":"` + goodV7 + `","outcome":"success","duration_ms":null}`},
		{"structured_read_end/null-outcome", KindStructuredReadEnd, `{"tool_name":"read","invocation_id":"` + goodV7 + `","outcome":null,"duration_ms":1}`},
		{"structured_read_end/null-invocation_id", KindStructuredReadEnd, `{"tool_name":"read","invocation_id":null,"outcome":"success","duration_ms":1}`},
		{"structured_read_end/null-tool_name", KindStructuredReadEnd, `{"tool_name":null,"invocation_id":"` + goodV7 + `","outcome":"success","duration_ms":1}`},
		{"structured_read_refused/null-batch_size", KindStructuredReadRefused, `{"tool_name":"read","reason":"out_of_project","batch_size":null}`},
		{"structured_read_refused/null-reason", KindStructuredReadRefused, `{"tool_name":"read","reason":null,"batch_size":2}`},
		{"structured_read_refused/null-tool_name", KindStructuredReadRefused, `{"tool_name":null,"reason":"out_of_project","batch_size":2}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(tc.kind, json.RawMessage(tc.raw)); err == nil {
				t.Errorf("ValidatePayload() accepted a payload with a null/nested-missing required field: %s", tc.raw)
			}
		})
	}
}

// TestValidatePayload_RejectsPresentNullOrEmptyOptional verifies the load-time
// validator treats an optional field present as JSON null or as an empty string
// as non-canonical and rejects it, rather than silently treating it as absent.
// The canonical writer omits an absent optional field entirely, so the per-kind
// validators must never observe a present-but-empty form — e.g. the
// model_changed prior_* tuple counted as "all absent" or slash_command's
// error_detail treated as omitted on a success outcome.
func TestValidatePayload_RejectsPresentNullOrEmptyOptional(t *testing.T) {
	cases := []struct {
		name string
		kind string
		raw  string
	}{
		{"model_changed/prior-null", KindModelChanged, `{"new_provider":"openai","new_model_id":"gpt-5","new_effort":"high","prior_provider":null,"prior_model_id":null,"prior_effort":null}`},
		{"model_changed/prior-empty", KindModelChanged, `{"new_provider":"openai","new_model_id":"gpt-5","new_effort":"high","prior_provider":"","prior_model_id":"","prior_effort":""}`},
		{"slash_command/success-null-detail", KindSlashCommand, `{"name":"help","args":[],"outcome":"success","error_detail":null}`},
		{"slash_command/success-empty-detail", KindSlashCommand, `{"name":"help","args":[],"outcome":"success","error_detail":""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(tc.kind, json.RawMessage(tc.raw)); err == nil {
				t.Errorf("ValidatePayload() accepted an optional field present as null/empty: %s", tc.raw)
			}
		})
	}
}
