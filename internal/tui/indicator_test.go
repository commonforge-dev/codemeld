// Tests for the in-flight activity indicator: show/update/clear rendering,
// compact token/elapsed formatting, idempotent clear, a live ticker redraw, and
// the ticker's stop-on-clear (no leaked goroutine).
package tui

import (
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// fixedNow pins App.now so the rendered elapsed time is deterministic.
func fixedNow(a *App, at time.Time) { a.now = func() time.Time { return at } }

func TestIndicator_ShowUpdateClear(t *testing.T) {
	a := New(nil)
	base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	fixedNow(a, base)

	if a.IndicatorVisible() {
		t.Fatal("indicator visible before any turn")
	}

	a.ShowIndicator(0, 0)
	if !a.IndicatorVisible() {
		t.Fatal("ShowIndicator did not reveal the indicator")
	}
	if got := a.indicator.GetText(true); got != "Working… (0s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("indicator text = %q, want the activity/elapsed/split-token line", got)
	}

	a.SetIndicatorTokens(39600, 312)
	if in, out := a.IndicatorTokens(); in != 39600 || out != 312 {
		t.Fatalf("IndicatorTokens = (%d, %d), want (39600, 312)", in, out)
	}
	if got := a.indicator.GetText(true); got != "Working… (0s · ↑ 39.6k ↓ 312 tokens)" {
		t.Fatalf("indicator text after token update = %q, want compact split ↑ 39.6k ↓ 312", got)
	}

	a.ClearIndicator()
	if a.IndicatorVisible() {
		t.Fatal("ClearIndicator left the indicator visible")
	}
	if got := a.indicator.GetText(true); got != "" {
		t.Fatalf("indicator text after clear = %q, want empty", got)
	}
	if in, out := a.IndicatorTokens(); in != 0 || out != 0 {
		t.Fatalf("IndicatorTokens after clear = (%d, %d), want (0, 0)", in, out)
	}
}

func TestIndicator_RetryBackoffAndResume(t *testing.T) {
	a := New(nil)
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	fixedNow(a, base)

	a.ShowIndicator(0, 0)
	a.ShowRetryBackoff(2, 4)
	if got := a.indicator.GetText(true); got != "Reconnecting… (attempt 2 of 4) (0s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("indicator text during retry = %q, want reconnecting attempt count", got)
	}

	a.SetIndicatorTokens(1200, 48)
	if got := a.indicator.GetText(true); got != "Reconnecting… (attempt 2 of 4) (0s · ↑ 1.2k ↓ 48 tokens)" {
		t.Fatalf("indicator text after retry token update = %q, want reconnecting state preserved", got)
	}

	a.ResumeRetry()
	if got := a.indicator.GetText(true); got != "Working… (0s · ↑ 1.2k ↓ 48 tokens)" {
		t.Fatalf("indicator text after retry resume = %q, want Working with token count preserved", got)
	}

	a.ClearIndicator()
	a.ShowRetryBackoff(3, 4)
	if a.IndicatorVisible() || a.indicator.GetText(true) != "" {
		t.Fatalf("ShowRetryBackoff resurrected a cleared indicator: visible=%v text=%q", a.IndicatorVisible(), a.indicator.GetText(true))
	}
}

// A token update or a stale ticker tick after clear must not resurrect the hidden
// indicator (the off-loop callbacks and ticker can lag the clear).
func TestIndicator_NoResurrectAfterClear(t *testing.T) {
	a := New(nil)
	fixedNow(a, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))

	a.ShowIndicator(10, 0)
	gen := a.indicatorGen
	a.ClearIndicator()

	a.SetIndicatorTokens(500, 20)
	if a.IndicatorVisible() || a.indicator.GetText(true) != "" {
		t.Fatalf("SetIndicatorTokens resurrected a cleared indicator: visible=%v text=%q", a.IndicatorVisible(), a.indicator.GetText(true))
	}

	// A ticker tick carrying the pre-clear generation is dropped.
	a.tickIndicator(gen)
	if a.indicator.GetText(true) != "" {
		t.Fatalf("stale tick redrew a cleared indicator: %q", a.indicator.GetText(true))
	}

	// A second clear is a no-op (and must not double-close the stop channel).
	a.ClearIndicator()
}

// tickIndicator redraws the elapsed time from the live clock, so the line advances
// while the provider streams nothing.
func TestIndicator_TickAdvancesElapsed(t *testing.T) {
	a := New(nil)
	base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	fixedNow(a, base)
	a.ShowIndicator(0, 0)

	fixedNow(a, base.Add(65*time.Second))
	a.tickIndicator(a.indicatorGen)

	if got := a.indicator.GetText(true); got != "Working… (1m 5s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("indicator text after tick = %q, want elapsed 1m 5s", got)
	}
}

func TestIndicator_CompactTokens(t *testing.T) {
	cases := map[int64]string{
		0: "0", 42: "42", 999: "999", 1000: "1k", 1200: "1.2k",
		39600: "39.6k", 1_000_000: "1M", 1_250_000: "1.2M",
	}
	for n, want := range cases {
		if got := compactTokens(n); got != want {
			t.Errorf("compactTokens(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestIndicator_FormatElapsed(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-time.Second, "0s"},
		{9 * time.Second, "9s"},
		{59 * time.Second, "59s"},
		{60 * time.Second, "1m 0s"},
		{590 * time.Second, "9m 50s"},
	}
	for _, c := range cases {
		if got := formatElapsed(c.d); got != c.want {
			t.Errorf("formatElapsed(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestIndicator_ProviderIdleShowsWaitingCopy(t *testing.T) {
	a := New(nil)
	base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	fixedNow(a, base)

	a.ShowIndicator(0, 0)
	fixedNow(a, base.Add(200*time.Second))
	a.SetProviderIdle("OpenAI", 64*time.Second)

	if got := a.indicator.GetText(true); got != "Waiting for OpenAI… (1m 4s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("idle indicator text = %q, want provider name + supplied idle duration (not turn elapsed)", got)
	}
}

func TestIndicator_ProviderIdleTickAdvancesDuration(t *testing.T) {
	a := New(nil)
	base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	fixedNow(a, base)
	a.ShowIndicator(0, 0)
	// Idle begins at a non-zero supplied duration (10s); a 65s tick must advance it to
	// 75s (1m 15s), proving redraws advance from the supplied value, not the turn start.
	a.SetProviderIdle("OpenAI", 10*time.Second)

	fixedNow(a, base.Add(65*time.Second))
	a.tickIndicator(a.indicatorGen)

	if got := a.indicator.GetText(true); got != "Waiting for OpenAI… (1m 15s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("idle indicator after tick = %q, want idle duration advanced from supplied value, unchanged tokens", got)
	}
}

func TestIndicator_ProviderIdlePreservesTokenUpdates(t *testing.T) {
	a := New(nil)
	fixedNow(a, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	a.ShowIndicator(0, 0)
	a.SetProviderIdle("OpenAI", 5*time.Second)

	a.SetIndicatorTokens(39600, 312)
	if got := a.indicator.GetText(true); got != "Waiting for OpenAI… (5s · ↑ 39.6k ↓ 312 tokens)" {
		t.Fatalf("idle indicator after token update = %q, want idle copy and supplied duration preserved with new tokens", got)
	}
}

func TestIndicator_ProviderIdleRetryPriorityAndResume(t *testing.T) {
	a := New(nil)
	fixedNow(a, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	a.ShowIndicator(0, 0)
	a.SetProviderIdle("OpenAI", 5*time.Second)

	a.ShowRetryBackoff(2, 4)
	if got := a.indicator.GetText(true); got != "Reconnecting… (attempt 2 of 4) (0s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("retry over idle = %q, want reconnecting copy", got)
	}

	// An idle call during retry must not change the rendered reconnecting text.
	a.SetProviderIdle("Anthropic", 30*time.Second)
	if got := a.indicator.GetText(true); got != "Reconnecting… (attempt 2 of 4) (0s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("idle during retry changed the text = %q, want reconnecting copy unchanged", got)
	}

	// Resume returns to clean Working, not the stale idle stored during the retry.
	a.ResumeRetry()
	if got := a.indicator.GetText(true); got != "Working… (0s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("resume text = %q, want clean Working with no stale idle", got)
	}
}

func TestIndicator_LongWaitAddsCancellationHint(t *testing.T) {
	tests := []struct {
		name string
		idle time.Duration
		want string
	}{
		{"just below the threshold", indicatorLongWaitThreshold - time.Second, "Waiting for OpenAI… (1m 29s · ↑ 0 ↓ 0 tokens)"},
		{"at the threshold", indicatorLongWaitThreshold, "Waiting for OpenAI… still no response — press ESC to cancel (1m 30s · ↑ 0 ↓ 0 tokens)"},
		{"well past the threshold", 5 * time.Minute, "Waiting for OpenAI… still no response — press ESC to cancel (5m 0s · ↑ 0 ↓ 0 tokens)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(nil)
			fixedNow(a, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
			a.ShowIndicator(0, 0)
			a.SetProviderIdle("OpenAI", tt.idle)

			if got := a.indicator.GetText(true); got != tt.want {
				t.Fatalf("indicator text = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIndicator_LongWaitEmergesFromTickAndCancelsNothing(t *testing.T) {
	a := New(nil)
	base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	fixedNow(a, base)
	canceller := &fakeStreamCanceller{retained: 3, inFlight: true}
	a.SetStreamCanceller(canceller)

	a.ShowIndicator(0, 0)
	a.SetProviderIdle("OpenAI", 30*time.Second)
	if got := a.indicator.GetText(true); got != "Waiting for OpenAI… (30s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("indicator at the idle callback = %q, want the plain waiting copy", got)
	}

	fixedNow(a, base.Add(60*time.Second))
	a.tickIndicator(a.indicatorGen)

	if got := a.indicator.GetText(true); got != "Waiting for OpenAI… still no response — press ESC to cancel (1m 30s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("indicator after crossing the threshold = %q, want the cancellation hint", got)
	}
	if canceller.calls != 0 {
		t.Fatalf("the long wait cancelled the request itself (%d Cancel calls); cancellation is the user's", canceller.calls)
	}
	if !a.IndicatorVisible() {
		t.Fatal("the indicator was torn down by the long wait; the request must stay in flight and cancellable")
	}
}

func TestIndicator_ActivityResetsLongWaitHint(t *testing.T) {
	a := New(nil)
	base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	fixedNow(a, base)
	a.ShowIndicator(0, 0)
	a.SetIndicatorTokens(1200, 48)
	a.SetProviderIdle("OpenAI", 2*time.Minute)

	a.ResumeRetry()
	if got := a.indicator.GetText(true); got != "Working… (0s · ↑ 1.2k ↓ 48 tokens)" {
		t.Fatalf("indicator after stream activity = %q, want Working with tokens preserved", got)
	}

	a.SetProviderIdle("OpenAI", 5*time.Second)
	if got := a.indicator.GetText(true); got != "Waiting for OpenAI… (5s · ↑ 1.2k ↓ 48 tokens)" {
		t.Fatalf("indicator after a fresh idle stretch = %q, want the plain waiting copy", got)
	}
}

func TestIndicator_RetryOutranksLongWaitHint(t *testing.T) {
	a := New(nil)
	fixedNow(a, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	a.ShowIndicator(0, 0)
	a.SetProviderIdle("OpenAI", 3*time.Minute)

	a.ShowRetryBackoff(2, 4)
	if got := a.indicator.GetText(true); got != "Reconnecting… (attempt 2 of 4) (0s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("retry over the long wait = %q, want reconnecting copy", got)
	}

	a.ResumeRetry()
	if got := a.indicator.GetText(true); got != "Working… (0s · ↑ 0 ↓ 0 tokens)" {
		t.Fatalf("resume text = %q, want clean Working with no stale hint", got)
	}
}

func TestIndicator_LongWaitNoResurrectAfterClear(t *testing.T) {
	a := New(nil)
	fixedNow(a, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	a.ShowIndicator(0, 0)
	a.ClearIndicator()

	a.SetProviderIdle("OpenAI", 4*time.Minute)
	if a.IndicatorVisible() || a.indicator.GetText(true) != "" {
		t.Fatalf("a late long-wait callback resurrected a cleared indicator: visible=%v text=%q", a.IndicatorVisible(), a.indicator.GetText(true))
	}
}

func TestIndicator_ProviderIdleNoResurrectAfterClear(t *testing.T) {
	a := New(nil)
	fixedNow(a, time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	a.ShowIndicator(0, 0)
	a.ClearIndicator()

	a.SetProviderIdle("OpenAI", 5*time.Second)
	if a.IndicatorVisible() || a.indicator.GetText(true) != "" {
		t.Fatalf("late idle resurrected a cleared indicator: visible=%v text=%q", a.IndicatorVisible(), a.indicator.GetText(true))
	}
}

// Under a live event loop the elapsed ticker runs in its own goroutine; clearing
// the indicator must stop it (the goroutine returns, closing indicatorStopped) so
// no ticker goroutine leaks past a turn.
func TestIndicator_TickerStopsOnClear(t *testing.T) {
	a := New(nil)
	a.indicatorInterval = 5 * time.Millisecond
	screen := tcell.NewSimulationScreen("UTF-8")
	a.newScreen = func() (tcell.Screen, error) { return screen, nil }

	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)

	// Show on the loop goroutine (production calls ShowIndicator from dispatch), and
	// capture the ticker's exit channel through the same barrier.
	var stopped chan struct{}
	a.app.QueueUpdate(func() {
		a.ShowIndicator(0, 0)
		stopped = a.indicatorStopped
	})
	if stopped == nil {
		a.app.Stop()
		t.Fatal("ShowIndicator under a live loop did not start the ticker goroutine")
	}

	// Clear (loop still running so a pending ticker redraw can drain), then the
	// ticker goroutine must return promptly.
	a.ClearIndicator()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("indicator ticker did not stop within 2s of ClearIndicator (leaked goroutine)")
	}

	var visible bool
	a.app.QueueUpdate(func() { visible = a.IndicatorVisible() })
	if visible {
		a.app.Stop()
		t.Fatal("indicator still visible after ClearIndicator")
	}

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}
