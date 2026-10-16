// pasteScreen normalizes terminal events at the tcell.Screen layer before tview's
// event loop sees them.
package tui

import "github.com/gdamore/tcell/v2"

// pasteScreen decorates a tcell.Screen so terminal events tview does not handle still
// reach codemeld's app shell. It keeps bracketed-paste line breaks alive through
// tview's Run-loop paste collector: on Linux a pasted line break is a bare LF (0x0A),
// which tcell decodes to tcell.KeyCtrlJ; the collector writes a newline only for
// KeyRune, KeyEnter, and KeyTab, so a pasted LF is silently dropped and the block
// collapses onto one line. While inside a bracketed paste this wrapper rewrites each
// dropped LF into a KeyEnter and de-duplicates CRLF so each CR, LF, or CRLF break
// yields exactly one newline. It also consumes terminal focus-gained events after
// calling onFocusGained because tview v0.42.0 otherwise ignores EventFocus entirely.
// Outside those cases every event passes through untouched, so the Enter-submits /
// Ctrl+J-inserts-newline contract is unchanged.
type pasteScreen struct {
	tcell.Screen

	// initialized guards Init so it delegates to the inner screen exactly once:
	// App.Run initializes the wrapper explicitly to capture the terminal-init error,
	// and tview's SetScreen calls Init again (discarding its error), which must be a
	// no-op rather than re-initializing the terminal.
	initialized bool

	// pasting tracks whether we are between EventPaste start/end markers; only then
	// are key events rewritten. prevWasCR records whether the previous in-paste key
	// was a CR (KeyEnter) so a following LF can be swallowed (CRLF -> one newline); the
	// decision is based on the original event, not the rewritten one. Both fields are
	// touched only from PollEvent, which tview calls from a single event-source
	// goroutine, so they need no lock.
	pasting       bool
	prevWasCR     bool
	onFocusGained func()
}

// newPasteScreen wraps inner so its bracketed-paste line breaks are normalized and
// focus-gained events can be handled before tview drops them.
func newPasteScreen(inner tcell.Screen, onFocusGained ...func()) *pasteScreen {
	ps := &pasteScreen{Screen: inner}
	if len(onFocusGained) > 0 {
		ps.onFocusGained = onFocusGained[0]
	}
	return ps
}

// Init initializes the inner screen at most once and returns its error, so a failed
// terminal initialization still reaches App.Run's caller. The idempotence makes
// tview's SetScreen — which calls Init and discards the returned error — a safe no-op
// after App.Run has already initialized the wrapper.
func (s *pasteScreen) Init() error {
	if s.initialized {
		return nil
	}
	if err := s.Screen.Init(); err != nil {
		return err
	}
	s.initialized = true
	return nil
}

// PollEvent returns the next event from the inner screen, normalizing in-paste line
// breaks so tview's paste collector writes one "\n" per CR, LF, or CRLF. A bare LF
// (KeyCtrlJ) is rewritten to KeyEnter; an LF immediately following a CR is swallowed
// so a CRLF is not doubled; consecutive bare LFs each yield a newline. Focus events
// are consumed after notifying the app shell. Other events outside a paste, and
// non-line-break events inside one, pass through unchanged.
func (s *pasteScreen) PollEvent() tcell.Event {
	for {
		ev := s.Screen.PollEvent()
		if ev == nil {
			return nil // inner screen finalized; stop the loop.
		}
		switch e := ev.(type) {
		case *tcell.EventPaste:
			if e.Start() {
				s.pasting = true
				s.prevWasCR = false
			} else if e.End() {
				s.pasting = false
				s.prevWasCR = false
			}
			return ev
		case *tcell.EventKey:
			if !s.pasting {
				return ev
			}
			switch e.Key() {
			case tcell.KeyEnter: // CR (0x0D): the collector already writes "\n".
				s.prevWasCR = true
				return ev
			case tcell.KeyCtrlJ: // LF (0x0A): dropped by the collector unless rewritten.
				precededByCR := s.prevWasCR
				s.prevWasCR = false
				if precededByCR {
					continue // CRLF: the CR's newline already counted; swallow the LF.
				}
				return tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
			default:
				s.prevWasCR = false
				return ev
			}
		case *tcell.EventFocus:
			if e.Focused && s.onFocusGained != nil {
				s.onFocusGained()
			}
			continue
		default:
			return ev
		}
	}
}
