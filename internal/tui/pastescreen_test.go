// Tests for the bracketed-paste screen decorator: LF/CR/CRLF newline normalization,
// Init idempotence/error handling, and the App.Run production wiring.
package tui

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// scriptedScreen is a minimal tcell.Screen whose PollEvent replays a fixed event
// sequence and whose Init returns a configurable error, for driving pasteScreen
// without a terminal. Only PollEvent and Init are exercised; every other method is
// the embedded nil interface and must not be called.
type scriptedScreen struct {
	tcell.Screen
	events    []tcell.Event
	idx       int
	initErr   error
	initCalls int
}

func (s *scriptedScreen) PollEvent() tcell.Event {
	if s.idx >= len(s.events) {
		return nil
	}
	ev := s.events[s.idx]
	s.idx++
	return ev
}

func (s *scriptedScreen) Init() error {
	s.initCalls++
	return s.initErr
}

func keyRune(r rune) tcell.Event { return tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone) }

// keyCR is a pasted carriage return: tcell decodes 0x0D to KeyEnter (== KeyCR), which
// tview's collector already turns into a newline.
func keyCR() tcell.Event { return tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone) }

// keyLF mirrors how tcell decodes a bare pasted LF byte (0x0A): KeyCtrlJ with ModCtrl.
// The collector drops it, which is the bug the decorator fixes.
func keyLF() tcell.Event { return tcell.NewEventKey(tcell.KeyCtrlJ, 0, tcell.ModCtrl) }

// pasteEvents builds the in-paste event stream for text, rendering each '\n' with the
// given line-break style ("lf", "cr", or "crlf") so a single source string can be
// delivered the way each platform's terminal would.
func pasteEvents(text, brk string) []tcell.Event {
	evs := []tcell.Event{tcell.NewEventPaste(true)}
	for _, r := range text {
		if r != '\n' {
			evs = append(evs, keyRune(r))
			continue
		}
		switch brk {
		case "lf":
			evs = append(evs, keyLF())
		case "cr":
			evs = append(evs, keyCR())
		case "crlf":
			evs = append(evs, keyCR(), keyLF())
		}
	}
	return append(evs, tcell.NewEventPaste(false))
}

// collectPaste drives ps to exhaustion and applies tview v0.42.0's exact paste
// collector logic (application.go: KeyRune/KeyEnter/KeyTab while pasting) to the
// rewritten events, returning the string the focused primitive would receive. It is a
// faithful stand-in for the real Run loop, so it proves the decorator hands the
// collector events that survive — not just an in-decorator assertion.
func collectPaste(ps *pasteScreen) string {
	var b strings.Builder
	pasting := false
	for {
		ev := ps.PollEvent()
		if ev == nil {
			break
		}
		switch e := ev.(type) {
		case *tcell.EventPaste:
			if e.Start() {
				pasting = true
			} else if e.End() {
				pasting = false
			}
		case *tcell.EventKey:
			if !pasting {
				continue
			}
			switch e.Key() {
			case tcell.KeyRune:
				b.WriteRune(e.Rune())
			case tcell.KeyEnter:
				b.WriteRune('\n')
			case tcell.KeyTab:
				b.WriteRune('\t')
			}
		}
	}
	return b.String()
}

// TestPasteScreen_NormalizesLineBreaks pins line-break normalization: every line-break
// style yields exactly one newline per break, with no doubling for CRLF and one
// newline per blank line. Each case is fed through the decorator and then through a
// faithful copy of tview's collector.
func TestPasteScreen_NormalizesLineBreaks(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		brk  string
		want string
	}{
		{"bare LF", "line1\nline2", "lf", "line1\nline2"},
		{"CR only", "line1\nline2", "cr", "line1\nline2"},
		{"CRLF", "line1\nline2", "crlf", "line1\nline2"},
		{"consecutive blank lines LF", "a\n\nb", "lf", "a\n\nb"},
		{"consecutive blank lines CRLF", "a\n\nb", "crlf", "a\n\nb"},
		{"trailing newline LF", "x\n", "lf", "x\n"},
		{"trailing newline CRLF", "x\n", "crlf", "x\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPasteScreen(&scriptedScreen{events: pasteEvents(tc.text, tc.brk)})
			if got := collectPaste(ps); got != tc.want {
				t.Fatalf("collected %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPasteScreen_OutsidePastePassthrough proves the decorator only acts inside a
// bracketed paste: a bare LF (KeyCtrlJ) and a CR (KeyEnter) delivered with no paste
// markers pass through unchanged, so the Ctrl+J-inserts-newline /
// Enter-submits contract is untouched.
func TestPasteScreen_OutsidePastePassthrough(t *testing.T) {
	ps := newPasteScreen(&scriptedScreen{events: []tcell.Event{keyLF(), keyCR()}})

	lf, ok := ps.PollEvent().(*tcell.EventKey)
	if !ok || lf.Key() != tcell.KeyCtrlJ {
		t.Fatalf("LF outside paste = %v, want unchanged KeyCtrlJ", lf)
	}
	cr, ok := ps.PollEvent().(*tcell.EventKey)
	if !ok || cr.Key() != tcell.KeyEnter {
		t.Fatalf("CR outside paste = %v, want unchanged KeyEnter", cr)
	}
}

// TestPasteScreen_FocusGainedCallback proves terminal focus events are handled at
// the screen boundary before tview drops them. Only focus-gained restores app focus;
// focus-lost is consumed without disturbing the UI.
func TestPasteScreen_FocusGainedCallback(t *testing.T) {
	called := 0
	ps := newPasteScreen(&scriptedScreen{events: []tcell.Event{
		tcell.NewEventFocus(false),
		tcell.NewEventFocus(true),
		keyRune('x'),
	}}, func() { called++ })

	ev, ok := ps.PollEvent().(*tcell.EventKey)
	if !ok || ev.Key() != tcell.KeyRune || ev.Rune() != 'x' {
		t.Fatalf("PollEvent returned %v, want next non-focus key event", ev)
	}
	if called != 1 {
		t.Fatalf("focus-gained callback called %d times, want 1", called)
	}
}

// TestPasteScreen_InitIdempotentAndError pins the Init contract: Init delegates to the inner
// screen exactly once after success (so tview's SetScreen second call is a no-op) and
// returns the init error without marking itself initialized when it fails.
func TestPasteScreen_InitIdempotentAndError(t *testing.T) {
	t.Run("idempotent after success", func(t *testing.T) {
		inner := &scriptedScreen{}
		ps := newPasteScreen(inner)
		if err := ps.Init(); err != nil {
			t.Fatalf("first Init error: %v", err)
		}
		if err := ps.Init(); err != nil {
			t.Fatalf("second Init error: %v", err)
		}
		if inner.initCalls != 1 {
			t.Fatalf("inner Init called %d times, want 1", inner.initCalls)
		}
	})

	t.Run("returns init error and stays uninitialized", func(t *testing.T) {
		wantErr := errors.New("init failed")
		inner := &scriptedScreen{initErr: wantErr}
		ps := newPasteScreen(inner)
		if err := ps.Init(); !errors.Is(err, wantErr) {
			t.Fatalf("Init error = %v, want %v", err, wantErr)
		}
		if ps.initialized {
			t.Fatal("wrapper marked initialized after a failed Init")
		}
		if err := ps.Init(); !errors.Is(err, wantErr) {
			t.Fatalf("second Init error = %v, want %v (no success memoized)", err, wantErr)
		}
		if inner.initCalls != 2 {
			t.Fatalf("inner Init called %d times, want 2 (retried after failure)", inner.initCalls)
		}
	})
}

// recordingScreen wraps a SimulationScreen and records whether mouse/paste reporting
// was enabled on it, so a running-app test can prove App.Run re-enables both modes on
// the installed screen (tview skips that setup for a SetScreen-provided screen).
type recordingScreen struct {
	tcell.SimulationScreen
	mouseEnabled atomic.Bool
	pasteEnabled atomic.Bool
	focusEnabled atomic.Bool
}

func (r *recordingScreen) EnableMouse(flags ...tcell.MouseFlags) {
	r.mouseEnabled.Store(true)
	r.SimulationScreen.EnableMouse(flags...)
}

func (r *recordingScreen) EnablePaste() {
	r.pasteEnabled.Store(true)
	r.SimulationScreen.EnablePaste()
}

func (r *recordingScreen) EnableFocus() {
	r.focusEnabled.Store(true)
	r.SimulationScreen.EnableFocus()
}

// postEvent posts ev to the screen's event queue, retrying while the fixed-capacity
// queue is momentarily full so a multi-event paste cannot drop events under load.
func postEvent(t *testing.T, s tcell.Screen, ev tcell.Event) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		if err := s.PostEvent(ev); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("event queue stayed full")
}

// TestAppRun_PasteScreenPreservesLFNewlines pins LF newline preservation end to end:
// driving App.Run with an LF-delimited bracketed paste — delivered through the
// wrapped screen's PollEvent, the production path — leaves the input buffer holding
// the real newline, and App.Run enabled mouse and paste on the installed screen.
func TestAppRun_PasteScreenPreservesLFNewlines(t *testing.T) {
	a := New(nil)
	rec := &recordingScreen{SimulationScreen: tcell.NewSimulationScreen("UTF-8")}
	a.newScreen = func() (tcell.Screen, error) { return rec, nil }

	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)

	const want = "line1\nline2"
	postEvent(t, rec, tcell.NewEventPaste(true))
	for _, r := range want {
		if r == '\n' {
			postEvent(t, rec, keyLF())
			continue
		}
		postEvent(t, rec, keyRune(r))
	}
	postEvent(t, rec, tcell.NewEventPaste(false))

	deadline := time.After(2 * time.Second)
	for inputTextSync(a) != want {
		select {
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			got := inputTextSync(a)
			a.app.Stop()
			t.Fatalf("paste buffer = %q, want %q", got, want)
		}
	}

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !rec.mouseEnabled.Load() {
		t.Error("App.Run did not enable mouse on the wrapped screen (f300 regression)")
	}
	if !rec.pasteEnabled.Load() {
		t.Error("App.Run did not enable paste on the wrapped screen (adr-010 regression)")
	}
	if !rec.focusEnabled.Load() {
		t.Error("App.Run did not enable focus reporting on the wrapped screen")
	}
}

// TestAppRun_ReturnsScreenCreationError pins screen-error propagation: a screen-construction
// failure is returned to the caller and the loop never starts.
func TestAppRun_ReturnsScreenCreationError(t *testing.T) {
	a := New(nil)
	wantErr := errors.New("no terminal")
	a.newScreen = func() (tcell.Screen, error) { return nil, wantErr }

	if err := a.Run(); !errors.Is(err, wantErr) {
		t.Fatalf("Run() error = %v, want %v", err, wantErr)
	}
	if a.running.Load() {
		t.Error("running flag set despite screen-creation failure")
	}
}

// TestAppRun_ReturnsScreenInitError pins screen-error propagation: a terminal-init failure
// from the wrapped screen surfaces from App.Run rather than being swallowed.
func TestAppRun_ReturnsScreenInitError(t *testing.T) {
	a := New(nil)
	wantErr := errors.New("init failed")
	a.newScreen = func() (tcell.Screen, error) { return &scriptedScreen{initErr: wantErr}, nil }

	if err := a.Run(); !errors.Is(err, wantErr) {
		t.Fatalf("Run() error = %v, want %v", err, wantErr)
	}
	if a.running.Load() {
		t.Error("running flag set despite screen-init failure")
	}
}
