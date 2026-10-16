// Session write-failure protocol: the per-turn handler that records a failed
// atomic session write and the clean-shutdown final-flush retry. It
// lives outside internal/sessions because it appends events via internal/events
// (which already imports internal/sessions), so hosting this glue in sessions
// would create an import cycle.
package sessionfailures

import (
	"context"
	"fmt"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// flushStore is a test seam (matching the seam pattern in
// internal/events/launchbegan.go) so a test can drive CleanShutdownFlush's
// retry ordering without a real filesystem; production callers run
// sessions.Store.Flush unchanged.
var flushStore = func(ctx context.Context, store *sessions.Store) (fserrors.Category, sessions.WriteReason, error) {
	return store.Flush(ctx)
}

// HandleWriteFailure runs the per-turn protocol for an atomic session write that
// failed after session start. It does not truncate the in-memory
// record stream, appends a session_write_failed event describing the failure,
// and renders the one-line TUI notice. It deliberately does not re-flush: the
// next flush boundary carries both the retained records and this failure
// event, so a synchronous retry here would be redundant.
//
// reason must be one of the three write/rename/parent-dir failure reasons;
// sessions.ReasonNone (a successful or never-attempted flush, or a cancellation)
// cannot be encoded as session_write_failed and is rejected. It returns an error
// if reason is ReasonNone or the event payload is rejected by events.Append (for
// example an empty error_detail), in which case no notice is rendered.
func HandleWriteFailure(reason sessions.WriteReason, errCat fserrors.Category, path string, detail error, store *sessions.Store, ui tui.NoticeRenderer) error {
	if reason == sessions.ReasonNone {
		return fmt.Errorf("sessionfailures.HandleWriteFailure: reason %q cannot be encoded as session_write_failed", reason)
	}
	errorDetail := ""
	if detail != nil {
		errorDetail = detail.Error()
	}
	if _, err := events.Append(store, events.SessionWriteFailed{
		TargetPath:    path,
		Reason:        string(reason),
		ErrorCategory: string(errCat),
		ErrorDetail:   errorDetail,
	}); err != nil {
		return fmt.Errorf("sessionfailures.HandleWriteFailure: append session_write_failed: %w", err)
	}
	ui.Notice(tui.RenderSessionWriteFailedNotice(path, string(reason), errCat))
	return nil
}

// CleanShutdownFlush is the final session flush on a clean exit (/exit, /quit,
// bare exit/quit, CTRL-D on an empty buffer, double-CTRL-C on an empty buffer).
// It attempts the flush, and on failure attempts it exactly once more. On the
// second failure it writes the OP_FAIL "session-write-on-exit" line to stderr
// (with the OS error detail) and returns a non-nil error the caller maps to exit
// 1, replacing the usual resume hint.
//
// It never appends a session_write_failed event: at clean shutdown there is no
// later flush boundary to carry such a record, so the OP_FAIL line on stderr is
// the only failure surface.
func CleanShutdownFlush(ctx context.Context, store *sessions.Store) error {
	if _, _, err := flushStore(ctx, store); err == nil {
		return nil
	}
	cat, _, err := flushStore(ctx, store)
	if err == nil {
		return nil
	}
	fserrors.WriteToStderr("session-write-on-exit", store.Path(), cat, err.Error())
	return fmt.Errorf("sessionfailures.CleanShutdownFlush: session write failed on exit after retry: %w", err)
}
