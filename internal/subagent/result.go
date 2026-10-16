package subagent

import (
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/turn"
)

type Reason string

const (
	ReasonCompleted Reason = "completed"
	ReasonStepCap   Reason = "step_cap"
	ReasonCancelled Reason = "cancelled"
	ReasonFailed    Reason = "failed"
)

const maxReplyBytes = 16 << 10

type Result struct {
	Reply          string
	ReplyTruncated bool
	// Requests started, not completed rounds: a request whose stream fails after it
	// opened is still counted.
	ProviderRequests int
	ToolNames        []string
	// WriteTargets are the files the child's successful edit and create calls wrote, in call
	// order. It is not a complete record of what the child changed on disk — a create may
	// also have made parent directories, and a call that changed a file before reporting a
	// failure is absent — so it cannot stand in for a rollback snapshot.
	WriteTargets  []string
	DeleteTargets []string
	MoveTargets   []turn.MoveTarget
	Reason        Reason
	RestoredPaths []string
	// Unrecovered is a third outcome alongside a clean rollback and a clean commit: the named paths
	// were left as they are and RetainedJournal survives for recovery or the user to resolve.
	Unrecovered     []string
	RetainedJournal string
}

func boundReply(s string) (reply string, truncated bool) {
	if len(s) <= maxReplyBytes {
		return s, false
	}
	cut := maxReplyBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
