// Background retention-prune wiring for the launch paths: starts the
// background pruner and appends its session_prune_summary to whichever session is
// active when the pass completes.
package bootstrap

import (
	"context"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// startBackgroundPrune kicks off the opportunistic retention prune. Only a
// fresh launch calls it (StartTUI gates on BootstrapResult.BackgroundPrune); no
// resume path prunes — pruning is fresh-launch-only. The pass runs
// in sessions.StartBackgroundPrune's goroutine so it never blocks startup; on
// completion appendPruneSummary appends a session_prune_summary event to the
// session active at that moment and flushes it durable. retention_days is
// global-only, so resumeRetentionDays reads it from the composed config.
func startBackgroundPrune(ctx context.Context, app *tui.App, home string, config map[string]any) {
	sessions.StartBackgroundPrune(home, resumeRetentionDays(config), func(result sessions.PruneResult) {
		appendPruneSummary(ctx, app, result)
	})
}

// appendPruneSummary is the background-prune summary callback. It resolves
// the active session at completion time — not when the pruner started — so a
// /clear or /resume swap that ran mid-pass lands the summary on the session active
// now; a closed prior store silently drops the append inside
// Store.Append, matching the in-process switch-window carve-out. When no session is
// active it drops the result entirely. It then flushes the store so the summary is
// durable. A flush failure carrying a write reason is routed through the per-turn
// write-failure protocol via the background-safe notice sink; a non-write
// failure (cancelled context, marshal error) and an invalid payload are left
// non-fatal, because the background goroutine has no return path to abort the TUI.
func appendPruneSummary(ctx context.Context, app *tui.App, result sessions.PruneResult) {
	store := app.ActiveStore()
	if store == nil {
		return
	}
	if _, err := events.Append(store, pruneSummaryEvent(result)); err != nil {
		return
	}
	cat, reason, err := store.Flush(ctx)
	if err == nil || reason == sessions.ReasonNone {
		return
	}
	_ = sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, backgroundNotice{app})
}

// pruneSummaryEvent converts a sessions.PruneResult into the durable
// events.SessionPruneSummary payload, copying every counter and failure entry. The
// background-prune summary callback (appendPruneSummary) is its sole caller
// internal/sessions cannot build the event itself without importing internal/events.
func pruneSummaryEvent(result sessions.PruneResult) events.SessionPruneSummary {
	summary := events.SessionPruneSummary{
		FilesScanned: result.FilesScanned,
		FilesDeleted: result.FilesDeleted,
		FilesFailed:  result.FilesFailed,
		Failures:     make([]events.PruneFailure, 0, len(result.Failures)),
		ElapsedMs:    result.ElapsedMs,
	}
	for _, failure := range result.Failures {
		summary.Failures = append(summary.Failures, events.PruneFailure{
			Path:   failure.Path,
			Reason: string(failure.Reason),
			Kind:   string(failure.Kind),
		})
	}
	return summary
}

// backgroundNotice adapts the app's off-event-loop notice path to
// tui.NoticeRenderer, so a session_write_failed notice raised from the
// background prune goroutine is marshaled through the tview queue
// (NoticeFromBackground) rather than mutating the transcript directly the way
// app.Notice — used by the on-loop command flush — would.
type backgroundNotice struct{ app *tui.App }

func (b backgroundNotice) Notice(text string) { b.app.NoticeFromBackground(text) }
