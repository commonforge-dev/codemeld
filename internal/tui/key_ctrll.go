// CTRL-L screen repaint: re-renders the current screen from in-memory state to
// clear visual artifacts, routed through the app-level key
// dispatcher and a thin draw seam so it is unit-testable without a live terminal.
package tui

// handleCtrlL requests a full repaint of the current screen from in-memory state.
// It calls the injected draw seam and returns without touching focus
// input text, transcript, or overlay state, so an open overlay stays open and the
// handler is safe to call from either the normal or overlay key path; broader
// overlay key-priority routing is not handled here.
func (a *App) handleCtrlL() {
	a.draw()
}
