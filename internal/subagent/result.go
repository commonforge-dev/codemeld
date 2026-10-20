package subagent

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/filetools"
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

const (
	maxListedRefusals   = 20
	maxRefusalLineBytes = 512
	deniedByUnknown     = "unknown"
)

const InstructionSuffix = "\n\nIf an operation you attempt is refused, your final reply must name each refused operation and say what you could not do or verify because of it."

// Operation shows the child's arguments as given, never a resolved or authorized target.
type Refusal struct {
	Operation string
	DeniedBy  string
	Reason    string
	call      turn.AssembledToolCall
}

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
	Refusals        []Refusal
	RefusalTotal    int
}

func newRefusal(call turn.AssembledToolCall, content string) *Refusal {
	r := &Refusal{Operation: operationLabel(call), DeniedBy: deniedByUnknown, call: call}
	var wire struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if json.Unmarshal([]byte(content), &wire) != nil || strings.TrimSpace(wire.Reason) == "" {
		return r
	}
	switch wire.DeniedBy {
	case "user", "mode", "guard", "unattended":
		r.DeniedBy, r.Reason = wire.DeniedBy, wire.Reason
	}
	return r
}

func operationLabel(call turn.AssembledToolCall) string {
	label := turn.ToolActivityLines([]turn.AssembledToolCall{call})[0]
	var args map[string]any
	_ = json.Unmarshal([]byte(call.Arguments), &args)
	path, _ := args["path"].(string)
	switch {
	case path == "":
	case call.Name == filetools.GrepToolName || call.Name == filetools.GlobToolName:
		label += " in " + path
	case label == call.Name:
		label += " " + path
	}
	return label
}

func (r Refusal) Line() string {
	line := r.Operation + " (denied_by " + r.DeniedBy + ")"
	if r.Reason != "" {
		line += ": " + r.Reason
	}
	line, _ = boundBytes(line, maxRefusalLineBytes)
	return line
}

func boundReply(s string) (reply string, truncated bool) {
	return boundBytes(s, maxReplyBytes)
}

func boundBytes(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
