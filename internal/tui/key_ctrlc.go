// CTRL-C priority handler: stop an in-flight stream first; else
// clear a non-empty input buffer; else exit via the /exit clean-shutdown path when a
// prior empty-buffer CTRL-C was within the 1500ms window; else show the
// "press Ctrl-C again to exit" hint and arm that window.
package tui

import "time"

// ctrlCExitWindow is the double-press window: a second empty-buffer CTRL-C
// within this span of the first exits; outside it the second press is a fresh
// first press that re-shows the hint.
const ctrlCExitWindow = 1500 * time.Millisecond

// ctrlCHintText is the step-4 one-line notice shown after the first
// empty-buffer CTRL-C.
const ctrlCHintText = "press Ctrl-C again to exit"

// HandleCtrlC applies the priority order, top to bottom:
//
//  1. If a stream is in flight, stop it via the ESC handler's source-parameterized path with
//     source "ctrl-c" (retained content marked interrupted, stream_interrupted
//
// appended, flush). It does not clear input or exit.
//  2. Else if the input buffer is non-empty, clear it (and any pending exit hint).
//  3. Else if a prior empty-buffer CTRL-C was within ctrlCExitWindow, exit via
//     the /exit clean-shutdown path (the bare "exit" synonym through the submit hook),
//
// so the canonical slash_command{name:"exit"} record, the flush, the
// hint / exit-0, and the second-failure exit-1 all come from
//
//	   /exit rather than being duplicated here.
//	4. Else show the "press Ctrl-C again to exit" hint and arm the window.
//
// "Empty" is the literal buffer (GetText() == ""); a whitespace-only buffer counts
// as non-empty and takes step 2, so CTRL-C never exits over text the user can see.
func (a *App) HandleCtrlC() {
	// (1) Stream first. interruptStream is a no-op (returns false) when nothing is
	// streaming; on a flush failure it surfaces the error as a notice, mirroring
	// HandleEsc, and still counts as having stopped the stream.
	stopped, err := a.interruptStream("ctrl-c")
	if err != nil {
		a.Notice(err.Error())
		return
	}
	if stopped {
		return
	}

	// (2) Non-empty input: clear the buffer and reset any pending exit window so a
	// later empty CTRL-C starts fresh rather than exiting on a stale timestamp.
	if a.input.GetText() != "" {
		a.input.SetText("")
		a.clearCtrlCHint()
		return
	}

	// (3) Empty buffer with a recent prior empty CTRL-C: clean exit. Disarm first so
	// the pending timeout cannot fire against a torn-down app.
	if a.ctrlCArmed && a.now().Sub(a.ctrlCArmedAt) <= ctrlCExitWindow {
		a.clearCtrlCHint()
		if a.submit != nil {
			a.submit("exit")
		}
		return
	}

	// (4) First empty CTRL-C (or one outside the window): show the hint and arm.
	a.armCtrlCHint()
}

// armCtrlCHint shows the exit hint, records the arming time for the double-press
// check, and schedules a generation-guarded timeout that clears the hint after
// ctrlCExitWindow if no second press or other key arrives first.
func (a *App) armCtrlCHint() {
	a.ctrlCArmed = true
	a.ctrlCArmedAt = a.now()
	a.ctrlCHintGen++
	gen := a.ctrlCHintGen
	a.Notice(ctrlCHintText)
	a.afterFunc(ctrlCExitWindow, func() { a.expireCtrlCHint(gen) })
}

// clearCtrlCHint disarms the exit window and removes the hint notice. Bumping the
// generation invalidates any still-pending timeout so it cannot clear a hint that
// is later re-armed. It is a no-op when no hint is pending, so it is cheap to call
// on every non-CTRL-C keystroke.
func (a *App) clearCtrlCHint() {
	if !a.ctrlCArmed {
		return
	}
	a.ctrlCArmed = false
	a.ctrlCHintGen++
	a.Notice("")
}

// expireCtrlCHint is the timeout callback armCtrlCHint schedules. It clears the
// hint only if its generation still matches the armed window (so a stale timer from
// a superseded hint is ignored). It marshals through the tview queue while the
// event loop is running, the same as the streaming finalizers, so the state it
// touches is only ever mutated on the event-loop goroutine.
func (a *App) expireCtrlCHint(gen uint64) {
	a.streamUpdate(func() {
		if !a.ctrlCArmed || a.ctrlCHintGen != gen {
			return
		}
		a.ctrlCArmed = false
		a.Notice("")
	})
}
