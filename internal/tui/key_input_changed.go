package tui

import (
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/events"
)

// Bracketed paste and overlay edits must advance the previous-text snapshot without opening a picker.
func (a *App) onInputChanged() {
	// Clear pending follow-up before overlay or paste early returns.
	if a.pendingFollowup != "" {
		a.emitFollowupDebug(events.SuggestFollowupStageGhostCleared, "input_changed", 0, utf8.RuneCountInString(a.pendingFollowup))
	}
	a.pendingFollowup = ""
	cur := a.input.GetText()
	prev := a.fileRefPrevText
	a.fileRefPrevText = cur
	if a.anyOverlayOpen() || a.input.pasting {
		return
	}
	if at, ok := detectAtTrigger(prev, cur); ok {
		a.openFilePicker(at)
		return
	}
	if at, ok := detectSlashTrigger(prev, cur); ok {
		a.openSlashPicker(at)
	}
}
