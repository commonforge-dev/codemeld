package events

import (
	"codemeld.dev/codemeld/internal/sessions"
)

// childInvocationID attributes the record to the child agent whose call produced it; the
// parent's own reads pass "" and the field is omitted from the persisted payload.
func EmitStructuredReadStart(store *sessions.Store, invocationID, toolName, pathScope string, configuredConcurrency int64, childInvocationID string) error {
	_, err := Append(store, StructuredReadStart{
		ToolName:              toolName,
		PathScope:             pathScope,
		InvocationID:          invocationID,
		ConfiguredConcurrency: configuredConcurrency,
		ChildInvocationID:     childInvocationID,
	})
	return err
}

func EmitStructuredReadRefused(store *sessions.Store, toolName, reason string, batchSize int64, childInvocationID string) error {
	_, err := Append(store, StructuredReadRefused{
		ToolName:          toolName,
		Reason:            reason,
		BatchSize:         batchSize,
		ChildInvocationID: childInvocationID,
	})
	return err
}

func EmitStructuredReadEnd(store *sessions.Store, invocationID, toolName, outcome string, durationMs int64, childInvocationID string) error {
	_, err := Append(store, StructuredReadEnd{
		ToolName:          toolName,
		InvocationID:      invocationID,
		Outcome:           outcome,
		DurationMs:        durationMs,
		ChildInvocationID: childInvocationID,
	})
	return err
}
