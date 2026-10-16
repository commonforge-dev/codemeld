// Shared internal/tui test helpers extracted from the per-feature test files
// (dupl groups 5, 43, 53, 56): the running-app simulation harness base, the
// reverse-video row scan, the draw-then-read screen helper, and the overlay
// open/text/focus assertion.
package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// appHarness runs the real App event loop against a simulation screen and owns the
// draw-synchronization plumbing every running-app test needs — the afterDraw signal,
// a "run a change then wait for its draw" step, and clean shutdown — all serialized
// onto the event-loop goroutine so reads never race the draw. The feature-specific
// harnesses (layoutHarness, overlayBleedHarness) embed it and add their own reads.
type appHarness struct {
	t      *testing.T
	a      *App
	screen tcell.SimulationScreen
	drawn  chan struct{}
	errc   chan error
}

func newAppHarness(t *testing.T, width, height int) *appHarness {
	t.Helper()
	return newAppHarnessFor(t, New(nil), width, height)
}

func newAppHarnessFor(t *testing.T, a *App, width, height int) *appHarness {
	t.Helper()
	h := &appHarness{t: t, a: a, drawn: make(chan struct{}, 1), errc: make(chan error, 1)}
	a.app.SetAfterDrawFunc(func(tcell.Screen) {
		select {
		case h.drawn <- struct{}{}:
		default:
		}
	})
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatalf("screen init: %v", err)
	}
	h.screen = screen
	a.app.SetScreen(screen)
	go func() { h.errc <- a.app.Run() }()
	h.waitDraw()
	// The size has to be set after Run: tview re-initializes the screen it was handed,
	// and a simulation screen's Init resets it to 80x25.
	screen.SetSize(width, height)
	h.runDraw(func() {})
	return h
}

// waitDraw blocks until the next draw completes (the afterDraw signal fires once
// per draw), failing the test if none arrives.
func (h *appHarness) waitDraw() {
	h.t.Helper()
	select {
	case <-h.drawn:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		h.t.Fatal("no draw within 2s")
	}
}

// dropStaleDraw clears any buffered draw token so a following waitDraw observes the
// next draw rather than a previous one.
func (h *appHarness) dropStaleDraw() {
	select {
	case <-h.drawn:
	default:
	}
}

// runDraw runs f on the event-loop goroutine and waits for the draw it triggers, so a
// following state read sees the layout/screen f produced.
func (h *appHarness) runDraw(f func()) {
	h.t.Helper()
	h.dropStaleDraw()
	h.a.app.QueueUpdateDraw(f)
	h.waitDraw()
}

func (h *appHarness) stop() {
	h.a.app.Stop()
	if err := <-h.errc; err != nil {
		h.t.Fatalf("app.Run returned error: %v", err)
	}
}

// QueueUpdate evaluates cond on the event-loop goroutine, so state reads remain synchronized.
func waitOnLoop(t *testing.T, a *App, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ok := false
		a.app.QueueUpdate(func() { ok = cond() })
		if ok {
			return
		}
		if time.Now().After(deadline) {
			a.app.Stop()
			t.Fatalf("%s did not happen within 2s", what)
		}
	}
}

// findReverseVideoRows scans every cell of the drawn screen, fails the test if any
// cell uses the removed fixed-yellow accent (#FFFF00), and returns the concatenated
// runes of the reverse-video cells per row — the selected-row highlight the list
// pickers paint. Shared by the effort and model picker reverse-video tests.
func findReverseVideoRows(t *testing.T, screen tcell.SimulationScreen) map[int]string {
	t.Helper()
	cells, width, height := screen.GetContents()
	reverseByRow := map[int]string{}
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			c := cells[row*width+col]
			fg, bg, attr := c.Style.Decompose()
			if isYellow(fg) || isYellow(bg) {
				t.Errorf("cell (%d,%d) uses yellow (#FFFF00); want no fixed accent color", col, row)
			}
			if attr&tcell.AttrReverse != 0 && len(c.Runes) > 0 {
				reverseByRow[row] += string(c.Runes)
			}
		}
	}
	return reverseByRow
}

// underlinedText concatenates the runes of every underlined cell of the drawn screen in
// row-major order. The copy control is the only underlined run either surface draws, so a
// result wider than the control's label is underline leaking into the text after it —
// something the raw markup cannot show, because the pinned tview version accepts
// defaultTag without clearing the flag.
//
// The underline state has to be read from GetUnderlineStyle, never from the AttrUnderline
// bit: tview v0.42.0's parseTag applies `u` through tcell's Style.Underline (which sets the
// underline style) and then overwrites the whole attribute mask with the value it snapshotted
// before the flag loop, so a tview-tagged underline never reaches Decompose's mask.
func underlinedText(screen tcell.SimulationScreen) string {
	cells, width, height := screen.GetContents()
	var b strings.Builder
	for row := 0; row < height; row++ {
		for col := 0; col < width; col++ {
			c := cells[row*width+col]
			if c.Style.GetUnderlineStyle() != tcell.UnderlineStyleNone && len(c.Runes) > 0 {
				b.WriteString(string(c.Runes))
			}
		}
	}
	return b.String()
}

// readScreenSync forces a draw, then flattens the simulation screen on the loop
// goroutine and returns the text, stopping the app and failing the test if the read
// does not complete within 2s. The prompt-overlay scroll tests share it; unlike
// screenTextSync it forces a draw and enforces the timeout those tests need.
func readScreenSync(t *testing.T, a *App, screen tcell.SimulationScreen) string {
	t.Helper()
	var s string
	done := make(chan struct{})
	a.app.QueueUpdateDraw(func() {})
	a.app.QueueUpdate(func() { s = screenText(screen); close(done) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("screen read did not complete within 2s")
	}
	return s
}

// assertOverlayOpensAndFocuses opens an overlay via open, then asserts the open flag
// is set, the overlay TextView shows body, and focus moved to the overlay (so the
// input is blocked while it is open). The /status and /help overlays share this
// open/text/focus contract. label names the overlay for failure messages.
func assertOverlayOpensAndFocuses(t *testing.T, a *App, open func(), isOpen func() bool, view *tview.TextView, body, label string) {
	t.Helper()
	open()
	if !isOpen() {
		t.Fatalf("%s did not open (open flag false)", label)
	}
	if !strings.Contains(view.GetText(true), body) {
		t.Errorf("%s text = %q, want it to contain %q", label, view.GetText(true), body)
	}
	if a.app.GetFocus() != view {
		t.Errorf("focus is not on the %s while open; input is not blocked", label)
	}
}
