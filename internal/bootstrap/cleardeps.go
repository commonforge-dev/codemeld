// Production implementations of the /clear capability interfaces, bound to the
// running app + bootstrap result. They live in internal/bootstrap (not
// internal/tui) so the write-failure sink can delegate to sessionfailures without
// re-introducing the sessionfailures -> tui import cycle.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// installedStreamCanceller returns the live provider-turn canceller StartTUI
// installs on the app, falling back to an inert handle for tests that build
// command deps without the full provider runtime.
func installedStreamCanceller(app *tui.App) tui.StreamCanceller {
	if c := app.StreamCanceller(); c != nil {
		return c
	}
	return clearStreamCanceller{}
}

// clearStreamCanceller is the inert fallback for command-deps tests and pre-runtime
// assembly. It reports no in-flight stream and zero retained characters so session
// switches correctly suppress stream_interrupted when no provider turn exists.
type clearStreamCanceller struct{}

func (clearStreamCanceller) Cancel() (retainedChars int, inFlight bool) { return 0, false }

// clearSessionSwapper is the production tui.SessionSwapper over the running app +
// the run's home dir. Close refuses further appends to the outgoing store; Fresh
// mints a new same-folder session, installs it as the app's active store,
// and appends launch_began{source:"fresh"} — in that order. The "same folder" is
// resolved from the active store at Fresh time (not captured at startup), so a
// prior in-process session swap (e.g. /resume to a session in another folder) is
// reflected.
type clearSessionSwapper struct {
	app     *tui.App
	ctx     context.Context
	home    string
	ui      tui.NoticeRenderer
	holder  *resumeLockHolder
	acquire func(sessionPath, id string) (release func(), err error)
	emit    func(fresh *sessions.Store) error

	recorder *capabilityRecorder
	conf     *confinement
}

// Close refuses later appends to the prior store so background events landing in
// the switch window are dropped. It never errors: sessions.Store.Close
// is an idempotent no-op-marker, so the SessionSwapper.Close error is reserved for
// future close paths that can fail.
func (s *clearSessionSwapper) Close(prior *sessions.Store) error {
	prior.Close()
	return nil
}

// Fresh creates the new same-folder session, appends and flushes
// launch_began{source:"fresh"}, and only then swaps the app's active-store
// reference to it. The new store is returned so the handler can replay the
// AGENTS.md record into it.
//
// The folder for the new session is read from the active store's metadata at call
// time, so the fresh session lands under whichever session is active when /clear
// runs — including one a prior in-process swap (/resume) installed from a
// different folder — rather than a folder snapshotted at TUI startup. A nil active
// store (no session installed) is an error rather than a session minted from stale
// state.
//
// The active-store swap is the last step, which makes Fresh transactional on the
// launch_began flush. A handled atomic-write failure is recorded on the
// fresh store by emitFreshLaunch, which then reports success, so the swap installs
// and the run continues on the fresh store — the switch stands. A non-write flush
// error (a cancelled context or a marshal failure, which cannot encode)
// returns before the swap, leaving the prior store the active, appendable session
// so the caller can refuse the switch without stranding the app on a fresh store
// that was never committed.
func (s *clearSessionSwapper) Fresh() (*sessions.Store, error) {
	active := s.app.ActiveStore()
	if active == nil {
		return nil, fmt.Errorf("clear: no active store to resolve the fresh-session folder")
	}
	folder, rollback, err := s.conf.prepareReplacement()
	if err != nil {
		return nil, err
	}
	fresh, err := sessions.EnsureSession(s.home, active.MetadataSnapshot().Folder, time.Now().UTC(), nil)
	if err != nil {
		return nil, errors.Join(err, rollback())
	}
	acquire := s.acquire
	if acquire == nil {
		acquire = sessions.AcquireResumeLock
	}
	targetRelease, err := acquire(fresh.Path(), fresh.SessionID())
	if err != nil {
		return nil, errors.Join(err, rollback())
	}
	emit := s.emit
	if emit == nil {
		emit = s.emitFreshLaunch
	}
	if err := emit(fresh); err != nil {
		targetRelease()
		return nil, errors.Join(err, rollback())
	}
	if err := s.recorder.activate(s.ctx, s.app, fresh, s.ui); err != nil {
		targetRelease()
		return nil, errors.Join(err, rollback())
	}
	s.conf.commitReplacement(folder)
	if s.holder != nil {
		if source := s.holder.handoff(targetRelease); source != nil {
			source()
		}
	} else {
		targetRelease()
	}
	return fresh, nil
}

// emitFreshLaunch appends and flushes launch_began{source:"fresh"} on the fresh
// store before Fresh installs it as the app's active session. An
// atomic-write failure on the flush is handed to the per-turn protocol
// via the write-failure callback and reported as handled (returns nil), so the
// caller still completes the swap: it records session_write_failed + renders the
// notice on the fresh store, and the run carries those records forward and retries
// on the next flush. A non-write flush error (cancellation / marshal) is not
// encodable as session_write_failed and is returned to the caller, which then
// leaves the prior session active and refuses the switch. Delegating to
// sessionfailures here is why these production impls live in internal/bootstrap
// (off the sessionfailures→tui import cycle).
func (s *clearSessionSwapper) emitFreshLaunch(fresh *sessions.Store) error {
	handled := false
	onWriteFailure := func(cat fserrors.Category, reason sessions.WriteReason, ferr error) {
		if sessionfailures.HandleWriteFailure(reason, cat, fresh.Path(), ferr, fresh, s.ui) == nil {
			handled = true
		}
	}
	if err := events.EmitLaunchBegan(s.ctx, fresh, "fresh", onWriteFailure); err != nil && !handled {
		return err
	}
	return nil
}

// clearModelState is the production tui.ModelState over the run-scoped active
// model state. CarryForward keeps the current selection and its source so
// the fresh session's first model_turn reuses the prior source instead of
// re-running the run-start model selection's on-disk lookup.
type clearModelState struct{ active *model.ActiveState }

func (m clearModelState) CarryForward() { m.active.CarryForward() }

// clearModeState is the production tui.ModeCarrier over the run-scoped active
// interaction-mode state. CarryForward keeps the active mode and its original
// source across the /clear swap (mirroring the model carry-forward) and durably
// records interaction_mode{trigger:"clear"} into the fresh session, so the new
// session opens in the carried-forward mode with the source it originally came from.
// Living here (not in internal/tui) lets the durable emit route an
// atomic-write failure through sessionfailures without the sessionfailures→tui import
// cycle, exactly like emitFreshLaunch.
type clearModeState struct {
	active *mode.ActiveState
	ctx    context.Context
	ui     tui.NoticeRenderer
}

// CarryForward appends the interaction_mode{trigger:"clear"} record onto the
// already-swapped fresh store, carrying the active mode and its source forward
// unchanged (the run-scoped active state is the same instance across the switch). A
// handled atomic-write failure is recorded on fresh and reported as
// success so the completed switch stands; a non-write flush error (cancellation /
// marshal) surfaces to the caller.
func (m clearModeState) CarryForward(fresh *sessions.Store) error {
	return emitInteractionMode(m.ctx, fresh, m.active, mode.TriggerClear, m.ui)
}

// clearAgentReplayer is the production tui.AgentInstructionsReplayer over the
// in-memory AGENTS.md load record captured at bootstrap step 7c. Replay re-emits
// it as fresh agent_instructions_loaded events on the new store without
// re-walking the disk.
type clearAgentReplayer struct{ entries []agentinstr.LoadEntry }

func (r clearAgentReplayer) Replay(target *sessions.Store) error {
	return agentinstr.Replay(target, r.entries)
}

// clearTranscriptResetter is the production tui.TranscriptResetter for /clear. After
// the session swap commits, Reset wipes the transcript pane (and suppresses the
// accepted "> /clear" echo, via App.ResetTranscript) and re-renders the launch
// banner for the fresh session from the same statusState single source /status and
// the launch banner read, so the cleared screen shows the current run header instead
// of the prior conversation. It runs on the tview event-loop goroutine
// inside the /clear handler, so App.ResetTranscript and App.AppendBanner both mutate
// the view directly there.
type clearTranscriptResetter struct {
	app    *tui.App
	status statusState
	conf   *confinement
}

func (r clearTranscriptResetter) Reset() {
	r.app.ResetTranscript()
	r.app.AppendBanner(bannerLines(r.status)...)
	if warning := r.conf.takeCleanupWarning(); warning != "" {
		r.app.Notice(warning)
	}
}

// clearWriteFailureSink is the production tui.WriteFailureSink. It delegates a
// pre-switch flush failure to sessionfailures.HandleWriteFailure, supplying the
// app as the one-line notice sink. Living here (not in internal/tui) is what lets
// this delegation happen without the sessionfailures -> tui -> sessionfailures
// cycle.
type clearWriteFailureSink struct {
	ui tui.NoticeRenderer
}

func (w clearWriteFailureSink) Handle(reason sessions.WriteReason, cat fserrors.Category, path string, detail error, store *sessions.Store) error {
	return sessionfailures.HandleWriteFailure(reason, cat, path, detail, store, w.ui)
}
