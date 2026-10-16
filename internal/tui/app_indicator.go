// Streaming activity-indicator methods for the App shell: the in-flight line, its elapsed/token rendering, and the refresh ticker.

package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// indicatorWorkingActivity is the activity word the in-flight indicator leads with:
// one stable word rather than a rotating set.
const indicatorWorkingActivity = "Working…"

const indicatorLongWaitThreshold = 90 * time.Second

// ShowIndicator reveals the in-flight activity line with input/output as its starting token
// figures, records the turn start for the elapsed timer, and launches the refresh ticker.
// It runs on the tview event-loop goroutine, so it renders the line directly — routing
// through QueueUpdateDraw from that loop would deadlock; ClearIndicator is the teardown.
func (a *App) ShowIndicator(input, output int64) {
	a.indicatorMu.Lock()
	a.indicatorActive = true
	// A production turn seeds the elapsed clock with its submit-start so the settled
	// elapsed matches the recorded turn latency; every other path starts from now.
	if a.indicatorSeedStart.IsZero() {
		a.indicatorStart = a.now()
	} else {
		a.indicatorStart = a.indicatorSeedStart
		a.indicatorSeedStart = time.Time{}
	}
	a.indicatorRetry = ""
	a.indicatorIdle = ""
	a.indicatorIdleStart = time.Time{}
	a.indicatorInput = input
	a.indicatorOutput = output
	a.indicatorGen++
	gen := a.indicatorGen
	stop := make(chan struct{})
	a.indicatorStop = stop
	startTicker := a.running.Load()
	var stopped chan struct{}
	if startTicker {
		stopped = make(chan struct{})
		a.indicatorStopped = stopped
	}
	a.renderIndicatorLocked()
	a.indicatorMu.Unlock()

	if startTicker {
		go a.runIndicatorTicker(stop, stopped, gen)
	}
}

// SeedNextIndicatorStart seeds the elapsed clock the next ShowIndicator uses with a
// production turn's submit-start — the instant the user's input was accepted — so the
// indicator's final visible elapsed matches the turn-latency measured from the same
// instant. A zero start leaves ShowIndicator on its default dispatch-start basis. The
// seed is consumed by the next ShowIndicator and applies to that turn only. The turn
// controller calls it on the tview event-loop goroutine at dispatch, so it sets the
// field directly under indicatorMu like the other indicator mutators.
func (a *App) SeedNextIndicatorStart(start time.Time) {
	a.indicatorMu.Lock()
	a.indicatorSeedStart = start
	a.indicatorMu.Unlock()
}

// ShowRetryBackoff switches the in-flight indicator into the reconnecting
// state while the retry loop waits before the next provider attempt. It is safe for
// the turn runtime to call off the event-loop goroutine and is a no-op after clear.
func (a *App) ShowRetryBackoff(nextAttempt, totalAttempts int) {
	a.streamUpdate(func() {
		a.indicatorMu.Lock()
		defer a.indicatorMu.Unlock()
		if !a.indicatorActive {
			return
		}
		a.indicatorRetry = retryIndicatorActivity(nextAttempt, totalAttempts)
		a.renderIndicatorLocked()
	})
}

// SetProviderIdle switches the in-flight indicator into the idle-waiting state,
// replacing the generic Working copy with provider-specific waiting text whose timer
// counts the provider stream's idle duration (time since its last activity), not the
// turn elapsed. idle is that elapsed time since the provider's last activity; the idle
// line starts at that value and advances from it on each redraw. Retry outranks idle, so
// a call during a retry backoff is stored but not rendered until the retry resumes/clears.
// Safe to call from off the event-loop goroutine; it is a no-op after clear so a late
// idle callback cannot resurrect a hidden line.
func (a *App) SetProviderIdle(displayName string, idle time.Duration) {
	a.streamUpdate(func() {
		a.indicatorMu.Lock()
		defer a.indicatorMu.Unlock()
		if !a.indicatorActive {
			return
		}
		a.indicatorIdle = displayName
		a.indicatorIdleStart = a.now().Add(-idle)
		a.renderIndicatorLocked()
	})
}

// ResumeRetry returns the in-flight indicator to the normal Working state after a
// retry backoff completes and before the provider round is re-issued. It clears any
// idle state stored during the failed attempt rather than restoring it, so resume
// lands on clean Working copy.
func (a *App) ResumeRetry() {
	a.streamUpdate(func() {
		a.indicatorMu.Lock()
		defer a.indicatorMu.Unlock()
		if !a.indicatorActive {
			return
		}
		a.indicatorRetry = ""
		a.indicatorIdle = ""
		a.indicatorIdleStart = time.Time{}
		a.renderIndicatorLocked()
	})
}

// SetIndicatorTokens updates the running uploaded (input) and downloaded (output)
// token figures and redraws the line. The turn controller calls it off the
// event-loop goroutine (from the runner's exact per-round Usage callback only; the
// streamed progress signal is not wired in), so the redraw marshals through
// the tview queue. It is a no-op once the indicator is cleared, so a late callback
// cannot resurrect a hidden line.
func (a *App) SetIndicatorTokens(input, output int64) {
	a.streamUpdate(func() {
		a.indicatorMu.Lock()
		defer a.indicatorMu.Unlock()
		if !a.indicatorActive {
			return
		}
		a.indicatorInput = input
		a.indicatorOutput = output
		a.renderIndicatorLocked()
	})
}

// ClearIndicator hides the in-flight line and stops its elapsed ticker. The turn
// controller calls it off the event-loop goroutine when the loop returns —
// covering natural completion, a mid-stream drop, a user interrupt, and a
// background failure alike — so the teardown marshals through the tview queue. It
// is idempotent: a second call (or one with no indicator showing) is a no-op, so
// the stop channel is closed at most once and a stale ticker tick that lost the
// generation race cannot redraw.
func (a *App) ClearIndicator() {
	var stop chan struct{}
	a.streamUpdate(func() { stop = a.clearIndicatorState() })
	if stop != nil {
		close(stop)
	}
}

// clearIndicatorDirect hides the in-flight line from a caller already on the tview
// event-loop goroutine — the ESC/CTRL-C (interruptStream) and slash-command
// (MarkStreamInterruptedFromCommand) interrupt paths — rendering directly like
// ShowIndicator instead of marshaling through QueueUpdateDraw, which would deadlock
// on the loop. So the indicator vanishes the instant the UI records the interrupt
// rather than waiting for the background turn goroutine to observe cancellation; the
// turnController.run ClearIndicator stays an idempotent backstop, a harmless no-op
// once this has fired.
func (a *App) clearIndicatorDirect() {
	if stop := a.clearIndicatorState(); stop != nil {
		close(stop)
	}
}

// clearIndicatorState performs the indicator teardown under indicatorMu and returns
// the elapsed-ticker stop channel (nil when nothing was showing) for the caller to
// close exactly once, outside the lock. It is idempotent: a second call with no
// indicator active mutates nothing and returns nil, so the stop channel is closed at
// most once and a stale ticker tick that lost the generation race cannot redraw.
func (a *App) clearIndicatorState() (stop chan struct{}) {
	a.indicatorMu.Lock()
	defer a.indicatorMu.Unlock()
	if !a.indicatorActive {
		return nil
	}
	a.indicatorActive = false
	a.indicatorRetry = ""
	a.indicatorIdle = ""
	a.indicatorIdleStart = time.Time{}
	a.indicatorInput = 0
	a.indicatorOutput = 0
	a.indicatorGen++
	stop = a.indicatorStop
	a.indicatorStop = nil
	a.indicator.SetText("")
	a.root.ResizeItem(a.indicator, 0, 0)
	return stop
}

// runIndicatorTicker redraws the indicator every indicatorInterval so the elapsed
// time advances even while the provider streams nothing (thinking, or executing a
// tool). It marshals each redraw through the tview queue and exits when the stop
// channel closes (ClearIndicator), closing stopped on the way out so a test can
// join the goroutine and confirm it leaked nothing. Started only under a live
// event loop, so unit and integration tests that never run the loop spawn no
// timer goroutine to race their reads.
func (a *App) runIndicatorTicker(stop, stopped chan struct{}, gen uint64) {
	defer close(stopped)
	t := time.NewTicker(a.indicatorInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.streamUpdate(func() { a.tickIndicator(gen) })
		}
	}
}

// tickIndicator redraws the indicator from a ticker tick, but only while the same
// turn's indicator is still showing: a tick whose generation no longer matches (a
// clear, or a new turn's show) is dropped so it cannot redraw a stale or hidden
// line.
func (a *App) tickIndicator(gen uint64) {
	a.indicatorMu.Lock()
	defer a.indicatorMu.Unlock()
	if !a.indicatorActive || a.indicatorGen != gen {
		return
	}
	a.renderIndicatorLocked()
}

// renderIndicatorLocked writes the indicator text and resizes its row to one line.
// The caller holds indicatorMu and has confirmed the indicator is active.
func (a *App) renderIndicatorLocked() {
	elapsed := a.now().Sub(a.indicatorStart)
	activity := indicatorWorkingActivity
	switch {
	case a.indicatorRetry != "":
		activity = a.indicatorRetry
	case a.indicatorIdle != "":
		elapsed = a.now().Sub(a.indicatorIdleStart)
		activity = idleIndicatorActivity(a.indicatorIdle)
		if elapsed >= indicatorLongWaitThreshold {
			activity = longWaitIndicatorActivity(a.indicatorIdle)
		}
	}
	a.indicator.SetText(fmt.Sprintf("%s (%s · ↑ %s ↓ %s tokens)", activity, formatElapsed(elapsed), compactTokens(a.indicatorInput), compactTokens(a.indicatorOutput)))
	a.root.ResizeItem(a.indicator, 1, 0)
}

func idleIndicatorActivity(displayName string) string {
	return fmt.Sprintf("Waiting for %s…", displayName)
}

func longWaitIndicatorActivity(displayName string) string {
	return fmt.Sprintf("Waiting for %s… still no response — press ESC to cancel", displayName)
}

func retryIndicatorActivity(nextAttempt, totalAttempts int) string {
	if nextAttempt < 1 {
		nextAttempt = 1
	}
	if totalAttempts < nextAttempt {
		totalAttempts = nextAttempt
	}
	return fmt.Sprintf("Reconnecting… (attempt %d of %d)", nextAttempt, totalAttempts)
}

// formatElapsed renders a turn's elapsed time compactly like the reference
// indicator: seconds under a minute ("9s"), minutes and seconds beyond ("9m 50s").
// A negative duration (clock skew) is floored at zero.
func formatElapsed(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 0 {
		secs = 0
	}
	if secs < 60 {
		return strconv.Itoa(secs) + "s"
	}
	return fmt.Sprintf("%dm %ds", secs/60, secs%60)
}

// compactTokens renders a token count compactly like the reference ("39.6k"):
// counts under 1000 print whole, thousands print with one decimal and a "k"
// suffix (trailing ".0" trimmed, so 1000 is "1k" and 1200 is "1.2k"), and
// millions print with an "M" suffix the same way.
func compactTokens(n int64) string {
	switch {
	case n < 1000:
		return strconv.FormatInt(n, 10)
	case n < 1_000_000:
		return trimDecimal(float64(n)/1000) + "k"
	default:
		return trimDecimal(float64(n)/1_000_000) + "M"
	}
}

// trimDecimal formats v to one decimal place, dropping a trailing ".0".
func trimDecimal(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0")
}

// IndicatorVisible reports whether the in-flight indicator is currently showing.
// The before-draw chrome-row budget (chromeRows) reads it to subtract the
// indicator row from the transcript height only while a turn streams. It is also
// a cross-package test seam (like StatusText): bootstrap's production-path turn
// test asserts the indicator appears during a real turn and is cleared after it,
// which the durable events alone cannot show. The read is guarded by indicatorMu
// because the elapsed-refresh ticker goroutine also touches the indicator state.
func (a *App) IndicatorVisible() bool {
	a.indicatorMu.Lock()
	defer a.indicatorMu.Unlock()
	return a.indicatorActive
}

// IndicatorTokens returns the running uploaded (input) and downloaded (output)
// token figures the indicator is tracking. It is a cross-package test seam
// (like IndicatorVisible): bootstrap's production-path turn test reads it mid-turn
// to prove the figures advance from each round's exact Usage (not streamed deltas)
// and settle on the totals /status reports. Production updates them through
// SetIndicatorTokens off the live event loop; this is never called at runtime.
func (a *App) IndicatorTokens() (input, output int64) {
	a.indicatorMu.Lock()
	defer a.indicatorMu.Unlock()
	return a.indicatorInput, a.indicatorOutput
}
