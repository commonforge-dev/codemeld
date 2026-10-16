// EmitInteractionMode appends and immediately flushes the interaction_mode event
// recording the active mode at session start, on /clear, and on a /mode switch
package events

import (
	"context"

	"codemeld.dev/codemeld/internal/sessions"
)

// EmitInteractionMode appends an interaction_mode event with the given mode, source,
// and trigger and then immediately flushes the active session, giving the
// session-start (launch/resume), /clear, and /mode emissions the same durability as
// the adjacent launch_began boundary (point (e)). mode, source, and trigger
// are validated by the payload's per-kind rules during Append; an invalid value is
// rejected before anything is appended or flushed. On an atomic-write failure (Flush
// returns a real WriteReason) it invokes onWriteFailure with Flush's category,
// reason, and error so the caller can run the write-failure protocol;
// cancellation and other non-write flush errors (sessions.ReasonNone) bypass the
// handler. In all failure cases it returns the flush (or append) error;
// onWriteFailure may be nil. It mirrors EmitLaunchBegan so launch/resume/clear share
// one persistence policy rather than each rolling its own.
func EmitInteractionMode(ctx context.Context, store *sessions.Store, mode, source, trigger string, onWriteFailure WriteFailureHandler) error {
	if _, err := appendEvent(store, InteractionMode{Mode: mode, Source: source, Trigger: trigger}); err != nil {
		return err
	}
	cat, reason, err := flushStore(ctx, store)
	if err != nil {
		// Only atomic-write failures carry a real WriteReason; cancellation or
		// marshal failures return sessions.ReasonNone, which the
		// session_write_failed contract cannot encode. Hand those off to
		// the write-failure handler only, and surface other flush errors unchanged.
		if reason != sessions.ReasonNone && onWriteFailure != nil {
			onWriteFailure(cat, reason, err)
		}
		return err
	}
	return nil
}
