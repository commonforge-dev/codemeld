// /clear (alias /new) command: end the current session, flush it, swap to a
// fresh same-folder session, replay the in-memory AGENTS.md load record, and
// carry the active model selection forward.
package tui

import (
	"context"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

// StreamCanceller cancels any in-flight provider request before a session
// switch. Cancel returns the character count already retained for
// the cancelled response and reports whether a stream was actually in flight,
// so the caller only emits stream_interrupted when there really was one.
type StreamCanceller interface {
	Cancel() (retainedChars int, inFlight bool)
}

type TurnDrainer interface {
	WaitTurnDrained()
}

func drainCancelledTurn(c StreamCanceller) {
	if d, ok := c.(TurnDrainer); ok {
		d.WaitTurnDrained()
	}
}

// StreamInterruptionMarker seals the visible in-progress assistant line after a
// slash-command cancellation. It is called from command handlers on the tview
// event-loop goroutine, so production marks the transcript directly rather than
// queuing an off-loop update.
type StreamInterruptionMarker interface {
	MarkStreamInterruptedFromCommand()
}

// SessionSwapper owns the in-process session swap. Close refuses
// any further appends to prior so background events landing during the switch
// window are dropped. Fresh creates the new same-folder session — file path,
// UUIDv7 id, ensured folder dir, initial launch_began{source:"fresh"} — and
// returns its store; the production implementation also replaces the host's
// active-session reference as part of the same call.
type SessionSwapper interface {
	Close(prior *sessions.Store) error
	Fresh() (*sessions.Store, error)
}

// ModelState carries the in-memory model selection forward across the session
// switch so the first model_turn in the new session reuses the prior
// session's last source value rather than re-running the run-start on-disk
// model lookup.
type ModelState interface {
	CarryForward()
}

// ModeCarrier carries the active interaction mode into the fresh session and
// records interaction_mode{trigger:"clear"} on it, so the new session opens in the
// mode active when /clear was issued — with the source that mode originally came
// from — rather than resetting to mode.default. It takes the
// fresh store because, unlike the model carry-forward, it must emit a record into
// the new session. Wired as a distinct capability rather than folded into
// ModelState.CarryForward so mode carry-forward is not hidden inside model
// carry-forward. The production implementation lives in internal/bootstrap so its
// durable emit can route a write failure through sessionfailures without the
// internal/tui ↔ internal/sessionfailures import cycle.
type ModeCarrier interface {
	CarryForward(fresh *sessions.Store) error
}

// AgentInstructionsReplayer replays the in-memory AGENTS.md load record into
// the new session as fresh agent_instructions_loaded events,
// so the new session opens with the same instruction discovery outcome as the
// just-closed one without re-reading from disk.
type AgentInstructionsReplayer interface {
	Replay(target *sessions.Store) error
}

// WriteFailureSink handles a pre-switch flush failure: it appends the
// session_write_failed event to the prior session store and renders the
// one-line notice. The production implementation lives outside
// internal/tui (alongside or above sessionfailures) so it can delegate to
// sessionfailures.HandleWriteFailure without re-introducing the
// internal/tui ↔ internal/sessionfailures import cycle.
type WriteFailureSink interface {
	Handle(reason sessions.WriteReason, cat fserrors.Category, path string, detail error, store *sessions.Store) error
}

// TranscriptResetter wipes the visible transcript pane after the session swap and
// re-renders the post-clear header for the fresh session, so /clear shows a blank
// pane (then the launch banner) instead of the prior conversation
// (visible-screen reset). It is invoked only after the swap and all post-swap
// replay/flush/carry-forward work have succeeded, so a refused switch leaves the
// prior session's transcript untouched. The production implementation lives in
// internal/bootstrap so it can source the launch banner from statusState without
// importing bootstrap state into internal/tui; a nil capability (the swap-sequence
// unit tests) skips the reset.
type TranscriptResetter interface {
	Reset()
}

// ClearDeps gathers the small capability interfaces NewClearHandler closes
// over. Each is independently injectable so the handler can be driven end-to-
// end with fakes; production wiring supplies the implementations bound to the
// running app + bootstrap result.
type ClearDeps struct {
	Stream           StreamCanceller
	StreamTranscript StreamInterruptionMarker
	Session          SessionSwapper
	Model            ModelState
	Mode             ModeCarrier
	Agents           AgentInstructionsReplayer
	WriteFailure     WriteFailureSink
	// Transcript wipes the visible transcript and re-renders the post-clear header
	// once the swap has fully committed. Nil-safe: a nil capability skips
	// the reset, which is how the swap-sequence unit tests run with no transcript.
	Transcript TranscriptResetter
	// FlushCtx is the run context used for the prior session's final pre-switch
	// flush. Threading the real run context (rather than a fixed
	// background one) means a genuinely cancelled run makes that flush a no-op
	// that returns a non-write error, which refuses the swap so the prior
	// session's final records are not dropped before being made durable. Nil
	// means context.Background().
	FlushCtx context.Context
}

// NewClearHandler returns the /clear (alias /new) handler that runs the
// session-switch sequence: cancel any in-flight stream, record the
// canonical slash_command event, flush the prior session, create and swap to a
// fresh same-folder session, seal the prior session, replay the agent
// instructions, and carry the model selection forward. On a pre-switch flush
// failure the swap is refused and the prior session stays active: an
// atomic-write failure routes through deps.WriteFailure, while a
// non-write error (e.g. a cancelled run) surfaces directly. The fresh session
// is created (and installed as active) before the prior store is sealed, so a
// fresh-session failure leaves the prior session active and still appendable
// rather than closing the active session out from under the run.
func NewClearHandler(deps ClearDeps) HandlerFunc {
	return func(cmdCtx CommandContext, _ []string) error {
		prior := cmdCtx.Store()

		// (a) Cancel any in-flight provider request. stream_interrupted is
		// recorded on the prior session only when a stream was actually in
		// flight, so an idle /clear does not synthesize a phantom interrupt.
		retained, inFlight := deps.Stream.Cancel()
		drainCancelledTurn(deps.Stream)
		if inFlight {
			if deps.StreamTranscript != nil {
				deps.StreamTranscript.MarkStreamInterruptedFromCommand()
			}
			if _, err := events.Append(prior, events.StreamInterrupted{
				Source:       "slash_clear",
				ContentChars: int64(retained),
			}); err != nil {
				return err
			}
		}

		// (b) Record the canonical slash_command success event on the prior
		// session. Dispatch already resolved the canonical name, so /new is
		// recorded as clear.
		if err := cmdCtx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}

		// (c) Final pre-switch flush of the prior session. Any flush
		// error refuses the switch and leaves the prior session active so its
		// final records are not dropped before being made durable. A write reason
		// (reason != ReasonNone) means the atomic write itself failed: route it
		// through the sink. A ReasonNone error cannot be encoded as
		// session_write_failed — no write was attempted (the run context was already
		// cancelled) or the session failed to marshal, which still carries a non-empty
		// fserrors category — so return it directly; the next flush retries on
		// the still-active store.
		flushCtx := deps.FlushCtx
		if flushCtx == nil {
			flushCtx = context.Background()
		}
		if cat, reason, ferr := prior.Flush(flushCtx); ferr != nil {
			if reason != sessions.ReasonNone {
				return deps.WriteFailure.Handle(reason, cat, prior.Path(), ferr, prior)
			}
			return ferr
		}

		// (d) Create the fresh same-folder session and commit to the swap. The
		// impl owns id minting, folder-dir creation, the initial
		// launch_began{source:"fresh"}, and installing the fresh store as the
		// app's active session. This runs before the prior store is sealed: if it
		// fails, the prior session is still active and appendable, so the failed
		// /new leaves the current session usable instead of pointing the app at a
		// sealed store that silently drops every later record.
		fresh, err := deps.Session.Fresh()
		if err != nil {
			return err
		}

		// (e) The swap has committed, so seal the prior store against further
		// appends; background events landing in the switch window are dropped
		if err := deps.Session.Close(prior); err != nil {
			return err
		}

		// (f) Replay the in-memory AGENTS.md load record into the new session.
		if err := deps.Agents.Replay(fresh); err != nil {
			return err
		}

		// (f2) Flush the replayed agent_instructions_loaded records:
		// they must be durable before the switch returns control to the TUI, or a
		// crash right after /clear would leave the new session with only its
		// launch_began anchor. The switch has already happened, so an atomic-write
		// failure (reason != ReasonNone) is a per-turn failure on the now-active fresh
		// store — record session_write_failed + notice via the same sink and
		// carry forward, rather than aborting the completed switch. A ReasonNone failure
		// cannot be encoded as session_write_failed (here only a marshal failure, since
		// the background context is never cancelled); return it directly.
		if cat, reason, ferr := fresh.Flush(context.Background()); ferr != nil {
			if reason != sessions.ReasonNone {
				if err := deps.WriteFailure.Handle(reason, cat, fresh.Path(), ferr, fresh); err != nil {
					return err
				}
			} else {
				return ferr
			}
		}

		// (g) Carry the in-memory model selection forward so the first
		// model_turn in the new session reuses the prior source value.
		deps.Model.CarryForward()

		// (g2) Carry the active interaction mode forward and record
		// interaction_mode{trigger:"clear"} into the fresh session, so the new
		// session opens in the mode active when /clear ran rather than resetting to
		// mode.default. Runs after the swap so the record lands in the
		// fresh session; a handled per-turn write failure is absorbed by
		// the production impl, while a non-write error surfaces. Nil-safe for the
		// swap-sequence unit tests, which inject no mode capability.
		if deps.Mode != nil {
			if err := deps.Mode.CarryForward(fresh); err != nil {
				return err
			}
		}

		// (h) The swap and all post-swap work have committed: wipe the prior
		// conversation from the visible pane and re-render the fresh session's header.
		// Done last so any early return above (a refused switch) leaves the
		// prior session's transcript intact. Nil-safe for the swap-sequence unit tests,
		// which inject no transcript capability.
		if deps.Transcript != nil {
			deps.Transcript.Reset()
		}

		return nil
	}
}
