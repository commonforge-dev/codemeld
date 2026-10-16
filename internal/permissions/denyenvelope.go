// Builds and delivers the synthetic deny-reason envelope for denied tool calls.
package permissions

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

// defaultDenyReason is the §Reserved Values fallback substituted when the user
// denies a tool call without typing a reason.
const defaultDenyReason = "user denied this tool call without a reason"

// maxDenyReasonBytes caps the reason text at 512 UTF-8 bytes; bytes beyond the
// cap are dropped on a rune boundary so the field stays valid UTF-8.
const maxDenyReasonBytes = 512

// denyEnvelope is the pinned wire shape of the synthetic tool-error envelope.
// Field order (denied_by, then reason) is fixed so the marshaled JSON matches
// the §Reserved Values "Synthetic deny-reason envelope" byte-for-byte.
type denyEnvelope struct {
	DeniedBy string `json:"denied_by"`
	Reason   string `json:"reason"`
}

// denied_by is a closed enum. A policy denial must never carry "user", so the model and the
// audit trail can tell a Plan-mode or protected-state refusal from a user refusal.
const (
	deniedByUser       = "user"
	deniedByMode       = "mode"
	deniedByGuard      = "guard"
	deniedByUnattended = "unattended"
)

// The reason is fixed rather than derived from the refused call, so no request or path detail
// reaches the model.
const guardDenyReason = "codemeld settings files are protected; manage grants with /settings"

// BuildDenyEnvelope produces the compact JSON deny envelope for a user denial. The reason
// is the user's text with leading/trailing ASCII whitespace trimmed and capped to 512
// UTF-8 bytes; an empty result after trimming yields the default reason. denied_by is
// always the literal "user".
func BuildDenyEnvelope(userText string) string {
	return buildDenyEnvelope(deniedByUser, userText)
}

// BuildModeDenyEnvelope produces the deny envelope for a mode-posture denial: the same
// pinned wire shape with denied_by "mode" and reason naming the active mode and
// restriction. reason is always supplied by the caller (modePosture), so the default-reason
// fallback never applies here; it is shared with the user path only to reuse the trim/cap
// normalization.
func BuildModeDenyEnvelope(reason string) string {
	return buildDenyEnvelope(deniedByMode, reason)
}

func BuildUnattendedDenyEnvelope(reason string) string {
	return buildDenyEnvelope(deniedByUnattended, reason)
}

func BuildGuardDenyEnvelope() string {
	return buildDenyEnvelope(deniedByGuard, guardDenyReason)
}

func BuildBlockedPathDenyEnvelope(target, entry string, floor bool) string {
	suffix := " is blocked by your blocked_paths entry " + entry
	if floor {
		suffix = " is inside codemeld's protected folder ~/.codemeld"
	}
	if room := maxDenyReasonBytes - len(suffix); len(target) > room {
		target = capUTF8Bytes(target, max(room-len("…"), 0)) + "…"
	}
	return buildDenyEnvelope(deniedByGuard, target+suffix)
}

// IsRecoverableDeniedBy reports whether a decoded denied_by names a policy denial the turn loop
// re-issues instead of halting on.
func IsRecoverableDeniedBy(deniedBy string) bool {
	return deniedBy == deniedByMode || deniedBy == deniedByGuard || deniedBy == deniedByUnattended
}

// IsModeDenyEnvelope reports whether envelope is a well-formed deny envelope carrying a
// recoverable denied_by that the turn loop re-issues, as opposed to a terminal user refusal. It
// shares the closed recoverability rule with IsRecoverableDeniedBy and fails closed: a malformed,
// reasonless, or unrecognized envelope returns false, so an unclassifiable denial is still
// treated as terminal.
func IsModeDenyEnvelope(envelope string) bool {
	var e denyEnvelope
	if err := json.Unmarshal([]byte(envelope), &e); err != nil {
		return false
	}
	return IsRecoverableDeniedBy(e.DeniedBy) && strings.TrimFunc(e.Reason, isASCIIWhitespace) != ""
}

// buildDenyEnvelope normalizes text (ASCII-trim, 512-byte UTF-8 cap, default-on-empty) and
// marshals the pinned {denied_by, reason} shape with the given denied_by value. It is the
// shared core of the user- and mode-denial builders so both produce byte-identical
// normalization and field order.
func buildDenyEnvelope(deniedBy, text string) string {
	reason := capUTF8Bytes(strings.TrimFunc(text, isASCIIWhitespace), maxDenyReasonBytes)
	if reason == "" {
		reason = defaultDenyReason
	}
	// A struct with no special characters in the pinned fields never fails to
	// marshal, so the error is unreachable; ignoring it keeps the signature simple.
	out, _ := json.Marshal(denyEnvelope{DeniedBy: deniedBy, Reason: reason})
	return string(out)
}

// RecordAppender is the minimal seam BuildDenyEnvelope's delivery path needs:
// *sessions.Store satisfies it via Append(sessions.Record), and tests pass a
// stub so they stay independent of session-file flushing.
type RecordAppender interface {
	Append(sessions.Record)
}

// DeliverDeny appends the deny envelope to the session record stream as a normal
// tool-result message: a role "tool" record with a fresh UUIDv7 id, the
// canonical millisecond UTC timestamp, string content equal to envelope, and
// tool_call_id referencing the denied assistant tool call. It
// does not flush; durability stays with the store's owner.
func DeliverDeny(toolCallID string, envelope string, appender RecordAppender) {
	appender.Append(sessions.Message{
		ID:         ids.NewV7(),
		Role:       "tool",
		Content:    sessions.TextContent(envelope),
		Timestamp:  time.Now().UTC().Truncate(time.Millisecond),
		ToolCallID: toolCallID,
	})
}

// isASCIIWhitespace reports whether r is one of the six ASCII whitespace bytes
// (space, tab, LF, CR, VT, FF). Trimming is ASCII-only, so Unicode
// whitespace runes are intentionally preserved.
func isASCIIWhitespace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// capUTF8Bytes returns s truncated to at most max bytes, backing off to the
// previous rune boundary if the cut would split a multi-byte rune, so the result
// is always valid UTF-8.
func capUTF8Bytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	b := max
	for b > 0 && !utf8.RuneStart(s[b]) {
		b--
	}
	return s[:b]
}
