// /context command: builds a single in-memory snapshot of how much of the model's
// context window the current session has used — active provider/model, session token
// totals, whether those totals are incomplete, and the context-window size and
// percentage used when codemeld knows the window — and renders it as a modal panel.
package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// ContextState is the in-memory state surface the /context snapshot reads at open
// time. Every method returns without touching disk; the production adapter lives in
// internal/bootstrap so internal/tui stays free of backend imports.
type ContextState interface {
	// Selection is the active provider and model id. Both are empty when no model
	// has been selected yet.
	Selection() (provider, modelID string)
	// Records is a snapshot of the active session's in-memory record stream, used to
	// sum token usage and detect anomalies, mirroring /status.
	Records() []sessions.Record
	// ContextWindow is the active model's context-window size in tokens, or 0 when
	// codemeld does not know it. No provider/catalog source exposes a window size
	// yet, so production reports 0 (unknown) today.
	ContextWindow() int64
}

// ContextSnapshot is the resolved, render-ready /context state captured when the
// panel opens. Once built it is immutable; the panel shows this frozen snapshot until
// ESC is pressed.
type ContextSnapshot struct {
	Provider     string
	ModelID      string
	InputTokens  int64
	OutputTokens int64
	// Incomplete is true when some turn did not report usage (a model_response
	// anomaly), so the token totals are a lower bound.
	Incomplete bool
	// Meaningful only when CachedReported is true; a 0 here is otherwise the absence
	// of any provider-reported figure, not a measured zero.
	CachedInputTokens int64
	CachedReported    bool
	CachedPartial     bool
	// Window is the context-window size in tokens, or 0 when unknown.
	Window int64
}

// BuildContextSnapshot freezes the ContextState into a ContextSnapshot at open time,
// summing input/output tokens from the session's model_response records and flagging
// incomplete counts, matching the /status accounting semantics.
func BuildContextSnapshot(state ContextState) ContextSnapshot {
	provider, modelID := state.Selection()
	snap := ContextSnapshot{Provider: provider, ModelID: modelID, Window: state.ContextWindow()}
	cachedOmitted := false
	for _, rec := range state.Records() {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindModelResponse {
			continue
		}
		var p events.ModelResponse
		// A canonicalized model_response payload is always parseable; an
		// unparseable record came from outside Append and is skipped rather than
		// failing the command, matching /status.
		if json.Unmarshal(ev.Payload, &p) != nil {
			continue
		}
		snap.InputTokens += p.InputTokens
		snap.OutputTokens += p.OutputTokens
		if len(p.Anomaly) > 0 {
			snap.Incomplete = true
		}
		if p.CachedInputTokens == nil {
			cachedOmitted = true
		} else {
			snap.CachedInputTokens += *p.CachedInputTokens
			snap.CachedReported = true
			snap.CachedPartial = snap.CachedPartial || p.CachedInputTokensPartial
		}
	}
	if snap.CachedReported && cachedOmitted {
		snap.CachedPartial = true
	}
	return snap
}

// RenderContext returns the deterministic /context panel text: active provider/model,
// session token totals, and the context-window size with the percentage used when the
// window is known. An unknown window renders an explicit "unknown" fallback and no
// percentage; incomplete counts add a notice while still showing available totals. It
// never includes the system message, environment block, or advertised tool list.
func RenderContext(snap ContextSnapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Provider: %s\n", snap.Provider)
	fmt.Fprintf(&b, "Model: %s\n\n", snap.ModelID)

	total := snap.InputTokens + snap.OutputTokens
	switch {
	case snap.CachedReported && snap.CachedPartial:
		fmt.Fprintf(&b, "Token usage: %d input (at least %d cached), %d output (%d total)\n",
			snap.InputTokens, snap.CachedInputTokens, snap.OutputTokens, total)
		b.WriteString("Cached-token usage is incomplete because some responses did not report it.\n")
	case snap.CachedReported:
		fmt.Fprintf(&b, "Token usage: %d input (%d cached), %d output (%d total)\n",
			snap.InputTokens, snap.CachedInputTokens, snap.OutputTokens, total)
	default:
		fmt.Fprintf(&b, "Token usage: %d input, %d output (%d total)\n", snap.InputTokens, snap.OutputTokens, total)
	}
	if snap.Window > 0 {
		fmt.Fprintf(&b, "Context window: %d tokens\n", snap.Window)
		fmt.Fprintf(&b, "Context used: %d%% of window\n", total*100/snap.Window)
	} else {
		b.WriteString("Context window: unknown\n")
	}
	if snap.Incomplete {
		b.WriteString("Token counts: incomplete (some turns did not report usage)\n")
	}
	return b.String()
}

// NewContextHandler returns the /context handler bound to an in-memory state source.
// Dispatch order mirrors /status: append the canonical slash_command success event,
// FlushActive to make it durable across the command-event boundary, then snapshot
// in-memory state and open the panel. Snapshotting only after the append+flush keeps
// the handler symmetric with /status and /help and opens the panel only once the
// durability boundary is crossed.
func NewContextHandler(state ContextState) HandlerFunc {
	return func(ctx CommandContext, _ []string) error {
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		if err := ctx.FlushActive(); err != nil {
			return err
		}
		ctx.ShowPanel(RenderContext(BuildContextSnapshot(state)))
		return nil
	}
}
