// Tests for the blocked-prompt notifier: the 30s-then-every-60s schedule on a
// controlled clock, the fixed OSC 9 payload, stop/drain, context cancellation, the TTY
// gate, and the bell's nil-screen and event-loop guards.
package tui

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// fakeNotifyClock replaces time.After with a hand-fired channel and records the delay
// asked for each time, so the schedule is asserted without sleeping. tick is unbuffered:
// a send completes only once the notifier is waiting on it, which is what orders the
// test against the notifier goroutine.
type fakeNotifyClock struct {
	mu    sync.Mutex
	waits []time.Duration
	tick  chan time.Time
}

func newFakeNotifyClock() *fakeNotifyClock {
	return &fakeNotifyClock{tick: make(chan time.Time)}
}

func (c *fakeNotifyClock) after(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	c.mu.Unlock()
	return c.tick
}

// elapsed sums the first n recorded delays: the virtual time at which the nth alert fired.
func (c *fakeNotifyClock) elapsed(n int) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var total time.Duration
	for _, d := range c.waits[:n] {
		total += d
	}
	return total
}

// assertIdle fails if anything is still waiting on the clock, proving the notifier
// goroutine is gone rather than merely quiet.
func (c *fakeNotifyClock) assertIdle(t *testing.T) {
	t.Helper()
	select {
	case c.tick <- time.Time{}:
		t.Fatal("a notifier is still waiting on its clock")
	case <-time.After(50 * time.Millisecond):
	}
}

// beepScreen counts the bells App.beep rings; tcell's simulation screen implements Beep
// as a no-op, so the screen contents cannot show it.
type beepScreen struct {
	tcell.SimulationScreen
	beeps atomic.Int32
}

func (s *beepScreen) Beep() error {
	s.beeps.Add(1)
	return nil
}

func TestPromptNotifySequence_IsTheFixedOSC9Payload(t *testing.T) {
	const want = "\x1b]9;Codemeld is waiting on your input\x07"
	if got := PromptNotifySequence(); got != want {
		t.Fatalf("PromptNotifySequence() = %q, want %q", got, want)
	}
}

func TestPromptNotifier_FirstAlertAt30sThenEvery60s(t *testing.T) {
	clk := newFakeNotifyClock()
	fired := make(chan struct{}, 8)
	n := StartPromptNotifier(context.Background(), clk.after, func() { fired <- struct{}{} })

	for i, want := range []time.Duration{30 * time.Second, 90 * time.Second, 150 * time.Second} {
		clk.tick <- time.Time{}
		select {
		case <-fired:
		case <-time.After(2 * time.Second):
			t.Fatalf("alert %d never fired", i+1)
		}
		if got := clk.elapsed(i + 1); got != want {
			t.Fatalf("alert %d fired at %s, want %s", i+1, got, want)
		}
		if got := len(fired); got != 0 {
			t.Fatalf("alert %d produced %d extra emissions", i+1, got)
		}
	}

	n.Stop()
	if got := len(fired); got != 0 {
		t.Fatalf("%d alerts fired after Stop", got)
	}
	clk.assertIdle(t)
}

func TestPromptNotifier_StopBeforeTheFirstAlertIsSilent(t *testing.T) {
	clk := newFakeNotifyClock()
	var alerts atomic.Int32
	n := StartPromptNotifier(context.Background(), clk.after, func() { alerts.Add(1) })

	n.Stop()

	if got := alerts.Load(); got != 0 {
		t.Fatalf("%d alerts fired for a prompt answered inside the first interval, want silence", got)
	}
	if got := clk.elapsed(1); got != promptNotifyDelay {
		t.Fatalf("first delay = %s, want %s", got, promptNotifyDelay)
	}
	clk.assertIdle(t)
}

// A tick delivered while Stop is running is the boundary case an answer on the exact
// interval hits: whichever side wins, no alert may land after Stop has returned.
func TestPromptNotifier_NoAlertLandsAfterStopReturns(t *testing.T) {
	for i := 0; i < 25; i++ {
		clk := newFakeNotifyClock()
		var alerts atomic.Int32
		n := StartPromptNotifier(context.Background(), clk.after, func() { alerts.Add(1) })

		sent := make(chan struct{})
		go func() {
			defer close(sent)
			select {
			case clk.tick <- time.Time{}:
			case <-time.After(250 * time.Millisecond):
			}
		}()

		n.Stop()
		atStop := alerts.Load()
		<-sent
		if got := alerts.Load(); got != atStop {
			t.Fatalf("run %d: alerts went %d → %d after Stop returned", i, atStop, got)
		}
	}
}

func TestPromptNotifier_StopDrainsAnAlertStillWriting(t *testing.T) {
	clk := newFakeNotifyClock()
	entered := make(chan struct{})
	release := make(chan struct{})
	var returned atomic.Bool
	n := StartPromptNotifier(context.Background(), clk.after, func() {
		close(entered)
		<-release
		returned.Store(true)
	})

	clk.tick <- time.Time{}
	<-entered

	stopped := make(chan struct{})
	go func() { n.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned while an alert was still writing")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the alert finished")
	}
	if !returned.Load() {
		t.Fatal("Stop returned before the in-flight alert did")
	}
	clk.assertIdle(t)
}

func TestPromptNotifier_CancelledContextStops(t *testing.T) {
	t.Run("while waiting on the first interval", func(t *testing.T) {
		clk := newFakeNotifyClock()
		var alerts atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		n := StartPromptNotifier(ctx, clk.after, func() { alerts.Add(1) })

		cancel()
		awaitNotifierExit(t, n)
		n.Stop()

		if got := alerts.Load(); got != 0 {
			t.Fatalf("%d alerts fired after cancellation", got)
		}
	})

	t.Run("mid-sequence", func(t *testing.T) {
		clk := newFakeNotifyClock()
		fired := make(chan struct{}, 8)
		ctx, cancel := context.WithCancel(context.Background())
		n := StartPromptNotifier(ctx, clk.after, func() { fired <- struct{}{} })

		clk.tick <- time.Time{}
		<-fired
		cancel()
		awaitNotifierExit(t, n)
		n.Stop()

		if got := len(fired); got != 0 {
			t.Fatalf("%d alerts fired after cancellation", got)
		}
	})
}

// awaitNotifierExit proves the notifier goroutine ended on its own, without the Stop
// that would have ended it anyway.
func awaitNotifierExit(t *testing.T, n *PromptNotifier) {
	t.Helper()
	select {
	case <-n.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the notifier goroutine did not exit within 2s")
	}
}

func TestPromptNotifyTTY_GatesEverythingButARealTerminal(t *testing.T) {
	if PromptNotifyTTY(&recordingWriter{}) {
		t.Error("a non-*os.File writer was treated as a terminal")
	}
	path := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create redirect target: %v", err)
	}
	defer f.Close()
	if PromptNotifyTTY(f) {
		t.Error("a redirected file was treated as a terminal")
	}
}

func TestAppBeep_NilScreenIsASilentNoOp(t *testing.T) {
	New(nil).beep()
}

func TestAppBeep_RingsTheScreenRunInstalled(t *testing.T) {
	a := New(nil)
	bs := &beepScreen{SimulationScreen: tcell.NewSimulationScreen("UTF-8")}
	a.newScreen = func() (tcell.Screen, error) { return bs, nil }

	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)
	a.RunOnEventLoopForTest(a.beep)
	waitOnLoop(t, a, "the bell to reach the screen", func() bool { return bs.beeps.Load() == 1 })

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

// Outside the running window QueueUpdate would block forever on a queue nobody drains,
// so an unlucky tick must be dropped instead.
func TestNotifyPromptWaiting_DropsATickOutsideTheRunningWindow(t *testing.T) {
	a := New(nil)
	w := &recordingWriter{}
	a.promptNotifyWrite = w.write

	a.notifyPromptWaiting()
	a.running.Store(true)
	a.stopping.Store(true)
	a.notifyPromptWaiting()

	if got := w.all(); len(got) != 0 {
		t.Fatalf("wrote %q outside the running window", got)
	}
}

// recordingWriter collects the notifier's escape-sequence writes.
type recordingWriter struct {
	mu   sync.Mutex
	seqs []string
}

func (w *recordingWriter) Write(p []byte) (int, error) { return len(p), nil }

func (w *recordingWriter) write(seq string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seqs = append(w.seqs, seq)
}

func (w *recordingWriter) all() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.seqs...)
}

func (w *recordingWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.seqs)
}
