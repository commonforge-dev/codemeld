// ESC key handling for the TUI.
package tui

import (
	"fmt"

	"codemeld.dev/codemeld/internal/events"
)

const escInterruptHintText = "press ESC again to interrupt"

// streamStateReporter is the optional capability the installed StreamCanceller may also
// implement, reporting stream state without cancelling — which Cancel cannot do.
type streamStateReporter interface {
	StreamInFlight() bool
}

// An open overlay owns ESC ahead of stream interruption: it is the modal the user is
// looking at, and it blocks the very turn ESC would otherwise cancel.
func (a *App) HandleEsc() {
	for _, o := range a.overlays() {
		if o.isOpen() && o.dismiss != nil {
			o.dismiss()
			return
		}
	}
	if a.escDisarmed {
		a.escDisarmed = false
		a.Notice(escInterruptHintText)
		return
	}
	a.clearEscInterruptHint()
	stopped, err := a.interruptStream("esc")
	if err != nil {
		a.Notice(err.Error())
		return
	}
	if stopped {
		return
	}
	// Clear a non-empty input buffer, mirroring HandleCtrlC step 2: "empty" is the
	// literal buffer (GetText() == ""), so a whitespace-only draft still counts as
	// non-empty and ESC never clears nothing visible. clearCtrlCHint resets any armed
	// CTRL-C exit window so a later empty CTRL-C starts fresh.
	if a.input.GetText() != "" {
		a.input.SetText("")
		a.clearCtrlCHint()
	}
}

func (a *App) streamInFlight() bool {
	reporter, ok := a.StreamCanceller().(streamStateReporter)
	return ok && reporter.StreamInFlight()
}

// clearEscInterruptHint matches on the text so it only clears the notice it set itself.
func (a *App) clearEscInterruptHint() {
	if a.NoticeText() == escInterruptHintText {
		a.Notice("")
	}
}

// interruptStream is driven by key handlers on tview's event-loop goroutine, so
// it mutates the transcript directly instead of queuing through QueueUpdateDraw.
// The off-loop provider finalizer still uses MarkStreamInterrupted.
func (a *App) interruptStream(source string) (bool, error) {
	canceller := a.StreamCanceller()
	if canceller == nil {
		return false, nil
	}
	retained, inFlight := canceller.Cancel()
	if !inFlight {
		return false, nil
	}

	// Hide the in-flight indicator the instant ESC/CTRL-C records the interrupt,
	// on this event-loop goroutine, rather than waiting for the background turn
	// goroutine to observe cancellation and reach the turnController.run backstop —
	// a slow provider/tool loop would otherwise leave the indicator up while
	// stream_interrupted is already recorded.
	a.clearIndicatorDirect()
	a.invalidateStreamRender()
	a.transcript.markInterrupted()
	if _, err := events.Append(a.ActiveStore(), events.StreamInterrupted{
		Source:       source,
		ContentChars: int64(retained),
	}); err != nil {
		return true, fmt.Errorf("record stream interruption: %w", err)
	}
	if err := a.FlushActive(); err != nil {
		return true, err
	}
	return true, nil
}
