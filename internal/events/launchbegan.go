// EmitLaunchBegan appends and immediately flushes the launch_began boundary
// event for a launch or in-process session switch (7b1).
package events

import (
	"context"
	"fmt"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

// WriteFailureHandler receives the outcome of the post-append flush when it
// fails (point e). It carries exactly the values
// sessions.Store.Flush returns, so a caller can drive the session
// write-failure protocol (sessionfailures.HandleWriteFailure) without
// internal/events importing that failure code and coupling the event package to
// session failure policy. Keeping the callback minimal — only Flush's return
// tuple — lets the final write-failure API change without touching this helper.
type WriteFailureHandler func(cat fserrors.Category, reason sessions.WriteReason, err error)

// launchSources is the closed set of launch_began.source values. It
// gates EmitLaunchBegan before any append so an invalid source never reaches the
// store, mirroring the LaunchBegan payload validator.
var launchSources = map[string]bool{"fresh": true, "resume": true, "fork": true}

// appendEvent, flushStore and commitStore are test seams (matching the package's
// `now` seam) so a test can observe the append-before-flush ordering and inject a
// write failure without a real filesystem; production callers run Append,
// Store.Flush and Store.CommitRecords unchanged.
var (
	appendEvent = Append
	flushStore  = func(ctx context.Context, store *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
		return store.Flush(ctx)
	}
	commitStore = func(ctx context.Context, store *sessions.Store, recs ...sessions.Record) (fserrors.Category, sessions.WriteReason, error) {
		return store.CommitRecords(ctx, recs...)
	}
)

// EmitLaunchBegan appends a launch_began event with the given source and then
// immediately flushes the active session, satisfying point (e)'s
// flush-after-this-event rule. source must be one of fresh, resume, or fork
// an invalid source is rejected before anything is appended or
// flushed. On an atomic-write failure (Flush returns a real WriteReason) it
// invokes onWriteFailure with Flush's category, reason, and error so the caller
// can run the write-failure protocol; cancellation and other non-write
// flush errors (sessions.ReasonNone) bypass the handler. In all failure cases
// it returns the flush error; onWriteFailure may be nil. It is called from five
// sites:
//   - bootstrap step 7b1 on fresh launch          -> source "fresh"
//   - resume sub-sequence on cold-start --resume  -> source "resume"
//   - /clear in-process switch                    -> source "fresh"
//   - in-TUI /resume switch                       -> source "resume"
//   - fork action                                 -> source "fork"
func EmitLaunchBegan(ctx context.Context, store *sessions.Store, source string, onWriteFailure WriteFailureHandler) error {
	if !launchSources[source] {
		return fmt.Errorf("events.EmitLaunchBegan: source %q is not one of fresh/resume/fork", source)
	}
	if _, err := appendEvent(store, LaunchBegan{Source: source}); err != nil {
		return err
	}
	cat, reason, err := flushStore(ctx, store)
	if err != nil {
		// Only atomic-write failures carry a real WriteReason; cancellation or
		// marshal failures return sessions.ReasonNone, which the
		// session_write_failed contract cannot encode. Hand those
		// off to the write-failure handler only, and surface other flush errors
		// to the caller unchanged.
		if reason != sessions.ReasonNone && onWriteFailure != nil {
			onWriteFailure(cat, reason, err)
		}
		return err
	}
	return nil
}
