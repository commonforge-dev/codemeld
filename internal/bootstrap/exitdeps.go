// Production implementation of tui.ExitController (the production binding
// deferred to the registry assembly). It lives in internal/bootstrap so
// FlushOnExit can delegate to sessionfailures.CleanShutdownFlush without the
// sessionfailures -> tui import cycle.
package bootstrap

import (
	"context"
	"fmt"
	"io"
	"os"

	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
)

// exitProcess is a seam over os.Exit so the clean-shutdown exit path can be
// exercised in a test without terminating the test binary; production exits the
// process unchanged.
var exitProcess = os.Exit

// exitController is the production tui.ExitController. It reads the active session
// through activeStore so a /clear or /resume swap is reflected in the
// hint, delegates the clean-shutdown flush to sessionfailures, and tears down the TUI event
// loop before propagating the process exit code.
//
// holder is the run-scoped resumeLockHolder shared with resumeSwitch and the
// /clear swapper. A clean /exit leaves the active (possibly resumed) session for
// good, so Finish releases the held resume lock before the process-exit seam — the
// kernel would drop it on process death anyway, but the explicit release makes the
// run-scoped lifetime observable to a same-run test and keeps the release path
// uniform across /resume, /clear, and /exit. It is nil in tests that do not
// exercise the lock lifetime; releaseHeld is nil-safe.
type exitController struct {
	activeStore   func() *sessions.Store
	beginShutdown func()
	stop          func()
	ctx           context.Context
	stdout        io.Writer
	holder        *resumeLockHolder
	turn          turnStopper
	stopDelivery  func()
}

type turnStopper interface {
	Cancel() (retainedChars int, inFlight bool)
	WaitTurnDrained()
}

// SessionID returns the active session's id, read at exit time so an in-process
// session swap is reflected in the resume hint. An absent active store
// (should not happen once StartTUI has run) yields an empty id.
func (c exitController) SessionID() string {
	store := c.activeStore()
	if store == nil {
		return ""
	}
	return store.SessionID()
}

// FlushOnExit cancels the active turn, waits for it to drain, and then runs the
// clean-shutdown flush over the active store via sessionfailures.CleanShutdownFlush: one retry,
// and on the second failure the OP_FAIL stderr line plus a non-nil error.
//
// The cancel-and-drain belongs here rather than in Finish: NewExitHandler calls
// FlushOnExit before Finish, so a drain placed in Finish would let the records a
// cancelled turn writes on its way out land after the run's last flush.
//
// beginShutdown runs first because /exit reaches here on the tview event-loop
// goroutine: it puts the TUI surface into its discard state so the transcript calls
// the cancelled turn makes while unwinding are dropped instead of queued onto the
// loop this drain is occupying.
func (c exitController) FlushOnExit() error {
	if c.turn != nil {
		if c.beginShutdown != nil {
			c.beginShutdown()
		}
		c.turn.Cancel()
		c.turn.WaitTurnDrained()
	}
	if c.stopDelivery != nil {
		c.stopDelivery()
	}
	return sessionfailures.CleanShutdownFlush(c.ctx, c.activeStore())
}

// Finish ends the run: it releases the run's held resume lock (if any), stops the
// tview event loop (restoring the terminal), prints the resume hint to
// stdout when non-empty, and exits the process with exitCode. resumeHint is empty
// on the status-1 path, where CleanShutdownFlush already wrote the stderr line and the
// hint is suppressed. The resume-lock release runs before the process-exit seam on
// both the clean (exit 0) and second-failure (exit 1) paths so a same-run test can
// observe the lock freed; in production the kernel would also drop it on process
// death. exitProcess never returns in production; the ordering (release, stop,
// hint, exit) keeps the hint off the alternate screen.
func (c exitController) Finish(exitCode int, resumeHint string) {
	c.holder.releaseHeld()
	c.stop()
	if resumeHint != "" {
		// The hint is best-effort terminal output on the way out; a write error has
		// no recovery path at process exit.
		_, _ = fmt.Fprintln(c.stdout, resumeHint)
	}
	exitProcess(exitCode)
}
