// Resume-time updated_at refresh that keeps a resumed session inside the
// retention window for the life of the run.
package sessions

import (
	"context"

	"codemeld.dev/codemeld/internal/fserrors"
)

// RefreshUpdatedAt performs the load-time updated_at rewrite for a
// resumed session. It delegates to Store.RefreshUpdatedAt, which sets
// metadata.updated_at to the current wall-clock time and rewrites the JSONL file
// atomically, so the just-loaded session sorts inside the retention window and
// cannot be pruned out from under the run.
//
// The resume orchestrator calls this once after the per-session sidecar lock is
// held and before the retention pruner starts. ctx is the run
// context; a cancellation short-circuits the refresh exactly as Store.RefreshUpdatedAt
// documents.
//
// It returns Store.RefreshUpdatedAt's result verbatim — ("", ReasonNone, nil) on a clean
// refresh, or the OS error category, the mapped WriteReason, and the underlying
// error on an atomic-write failure. On failure the refreshed timestamp stays in
// the in-memory session, so the run continues and the next successful turn flush
// re-creates the file with the advanced updated_at (step 2). Routing a
// non-ReasonNone result through sessionfailures.HandleWriteFailure (the
// session_write_failed event plus the TUI notice) is the resume orchestrator's
// job: internal/sessions deliberately does not import internal/sessionfailures,
// which already imports internal/sessions.
func RefreshUpdatedAt(ctx context.Context, store *Store) (cat fserrors.Category, reason WriteReason, err error) {
	return store.RefreshUpdatedAt(ctx)
}
