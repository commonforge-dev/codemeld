package tui

import (
	"github.com/gdamore/tcell/v2"
)

func (a *App) handleGlobalKey(ev *tcell.EventKey) *tcell.EventKey {
	// CTRL-L must precede hint clearing so pending notices survive a repaint.
	if ev.Key() == tcell.KeyCtrlL {
		// The ESC guard is state rather than a notice, so a repaint keystroke still counts
		// as the non-ESC key that clears it.
		a.escDisarmed = false
		a.handleCtrlL()
		return nil
	}
	// Clear pending follow-up before global-key early returns; Tab accepts it and CTRL-L preserves it.
	if ev.Key() != tcell.KeyTab {
		a.clearPendingFollowup("global_key")
	}
	// Preserve the hint for a second CTRL-C; other keys clear it.
	if ev.Key() != tcell.KeyCtrlC {
		a.clearCtrlCHint()
	}
	// Preserve the disarmed-ESC guard for the ESC it disarms; any other key clears it.
	if ev.Key() != tcell.KeyEscape {
		a.escDisarmed = false
		a.clearEscInterruptHint()
	}
	// Clear this one-shot hint on the next non-CTRL-R keystroke.
	a.clearReverseSearchHint()
	// Repair modal focus before routing the key when terminal focus events were lost.
	if a.promptOpen || a.questionFormOpen {
		a.restoreModalFocusOnTerminalFocus()
	}
	switch ev.Key() {
	case tcell.KeyPgUp, tcell.KeyPgDn:
		if a.anyOverlayOpen() {
			return ev
		}
		if ev.Key() == tcell.KeyPgUp {
			a.transcript.scrollPage(-1)
		} else {
			a.transcript.scrollPage(1)
		}
		return nil
	case tcell.KeyUp, tcell.KeyDown:
		if ev.Modifiers()&tcell.ModShift == 0 || a.anyOverlayOpen() {
			return ev
		}
		if ev.Key() == tcell.KeyUp {
			a.transcript.scrollBy(-1)
		} else {
			a.transcript.scrollBy(1)
		}
		return nil
	case tcell.KeyEscape:
		if a.resumePickerOpen {
			stopped, err := a.interruptStream("esc")
			if err != nil {
				a.Notice(err.Error())
				return nil
			}
			if stopped {
				return nil
			}
			return ev
		}
		a.HandleEsc()
		return nil
	case tcell.KeyCtrlE:
		a.openEffortPicker()
		return nil
	case tcell.KeyCtrlM:
		a.openModelPicker()
		return nil
	case tcell.KeyCtrlR:
		if a.resumePickerOpen {
			return ev
		}
		if a.modelPickerOpen {
			a.forceRefreshHighlightedProvider()
			return nil
		}
		a.openReverseSearch()
		return nil
	case tcell.KeyCtrlV:
		// CTRL-V is consumed even when no image is attached so it cannot reach the input area.
		a.handleClipboardImage()
		return nil
	case tcell.KeyCtrlY:
		// Consume CTRL-Y so tview's TextArea redo cannot mutate the prompt.
		return nil
	case tcell.KeyBacktab:
		a.cycleMode()
		return nil
	case tcell.KeyCtrlC:
		// The secret prompt must consume CTRL-C to cancel before the general priority order runs.
		if a.secretPromptOpen {
			a.cancelSecretPrompt()
			return nil
		}
		a.HandleCtrlC()
		return nil
	case tcell.KeyCtrlD:
		if a.resumePickerOpen {
			return ev
		}
		if a.anyOverlayOpen() {
			return nil
		}
		a.HandleCtrlD()
		return nil
	}
	return ev
}
