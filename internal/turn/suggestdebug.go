// Development-only suggest_followup trace: the turn loop's seams call
// appendSuggestFollowupDebug to record how far an intercepted-followup attempt got,
// gated by Deps.SuggestFollowupDebug. It complements the TUI-side ghost stages emitted
// from internal/tui so one session log shows the whole suggest_followup path.
package turn

import (
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/provider"
)

// appendSuggestFollowupDebug records one turn-side stage of the trace when the
// dev-debug gate is on. provider/model come from the turn's active selection and mode
// from Deps.Mode (both captured by bootstrap at dispatch); label/prompt are reduced to
// rune lengths so the suggestion text is never persisted. It appends only
// — riding the flush the round already performs — and ignores the (practically
// impossible) append error, so the diagnostic can never fail or reorder the turn.
func appendSuggestFollowupDebug(deps Deps, stage string, advertised *bool, label, prompt string) {
	if !deps.SuggestFollowupDebug {
		return
	}
	sel, _, ok := deps.Active.Current()
	if !ok {
		return
	}
	payload := events.SuggestFollowupDebug{
		Stage:      stage,
		Provider:   sel.Provider,
		ModelID:    sel.ID,
		Mode:       deps.Mode,
		Advertised: advertised,
	}
	if label != "" {
		payload.LabelLen = int64(utf8.RuneCountInString(label))
	}
	if prompt != "" {
		payload.PromptLen = int64(utf8.RuneCountInString(prompt))
	}
	_, _ = events.Append(deps.Store, payload)
}

// toolsAdvertiseSuggestFollowup reports whether the advertised tool set carries the
// suggest_followup definition — the "advertised" boolean the request_built stage records,
// which lets the trace distinguish "model never called it" from "it was never offered".
func toolsAdvertiseSuggestFollowup(tools []provider.ToolDefinition) bool {
	for _, t := range tools {
		if t.Name == provider.SuggestFollowupToolName {
			return true
		}
	}
	return false
}
