// OlderSchemaForker remains a documented no-op seam (see each type below).
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// newResumeDeps builds the production /resume capabilities bound to the running
// app + bootstrap result, for the BuildRegistry/StartTUI wiring. The
// lister and loader are bound to the run's home + launch directory: /resume only
// ever lists and resolves the current folder's sessions, whose canonical
// folder is fixed for the run. The stream canceller, agent replayer, and
// write-failure sink reuse the /clear production impls (cleardeps.go); FlushCtx is
// the run context so a cancelled run refuses the pre-switch flush instead of
// dropping the prior session's final records. lock is the run-scoped
// resumeLockHolder shared with the /clear swapper and exit controller, so the
// resume lock acquired by a switch is released when the run later leaves the
// resumed session through /clear or a clean /exit (not only on the next /resume).
//
// It is a package-level var (like runApp) so the StartTUI integration test can wrap
// the headless-incompatible picker and record the switch order around the
// production deps while StartTUI still owns the rest of the assembly; production
// never reassigns it.
var newResumeDeps = func(ctx context.Context, app *tui.App, result *BootstrapResult, lock *resumeLockHolder, cache *config.Cache, active *model.ActiveState, recorder *capabilityRecorder, conf *confinement) tui.ResumeDeps {
	return tui.ResumeDeps{
		Lister:           resumeLister{app: app, home: result.Home, cwd: result.LaunchDir},
		Picker:           tui.NewResumePicker(app),
		Rename:           resumeRenamer{},
		Delete:           resumeDeleter{app: app},
		Stream:           installedStreamCanceller(app),
		StreamTranscript: app,
		Loader:           resumeLoader{home: result.Home, cwd: result.LaunchDir},
		Switch:           &resumeSwitch{app: app, holder: lock, ctx: ctx, ui: app, recorder: recorder, conf: conf},
		Refresh:          resumeRefresher{ui: app},
		Model:            resumeModelRecoverer{app: app, cache: cache, active: active},
		Agents:           clearAgentReplayer{entries: result.AgentInstructions},
		Fork:             resumeForker{},
		WriteFailure:     clearWriteFailureSink{ui: app},
		// After an equal-schema switch commits, reset the pane and replay the
		// chosen session's prior conversation so the in-TUI /resume shows its history.
		Transcript: app,
		FlushCtx:   ctx,
	}
}

// resumePreviewMax bounds, in terminal cells, the first-message preview the lister
// attaches to each picker row and the cold-start --resume list.
const resumePreviewMax = 80

// resumeLister is the production tui.SessionLister. It wraps
// sessions.ListResumable for the run's home + launch directory — the canonical
// folder is fixed at launch and /resume only lists the current folder —
// projecting each survivor into a tui.ResumeEntry, bounding the scanned preview to
// the picker's cell budget. A non-ENOENT enumeration failure surfaces as
// the typed *sessions.ResumeListEnumerateError the handler renders (step 3).
// app is the running app, used only to exclude the currently-active session from the
// offered rows (see List).
type resumeLister struct {
	app  *tui.App
	home string
	cwd  string
}

func (l resumeLister) List() ([]tui.ResumeEntry, []sessions.SkippedID, error) {
	list, skipped, err := sessions.ListResumable(l.home, l.cwd)
	if err != nil {
		return nil, nil, err
	}
	// Never offer the currently-active session as a resume target. Resuming the session
	// already running is a no-op, but selecting it would make runResumeSwitch load a
	// stale on-disk copy as the switch target; a later flush of that copy would then
	// overwrite records the pre-switch flush just wrote (e.g. the /resume
	// slash_command{success} or stream_interrupted) — a session-durability regression.
	// Match by session id (metadata.id), not path, since the same file can be reached
	// by different path strings.
	activeID := ""
	if l.app != nil {
		if active := l.app.ActiveStore(); active != nil {
			activeID = active.SessionID()
		}
	}
	entries := make([]tui.ResumeEntry, 0, len(list))
	for _, e := range list {
		if activeID != "" && e.ID == activeID {
			continue
		}
		entries = append(entries, tui.ResumeEntry{
			ID:        e.ID,
			StartedAt: e.StartedAt,
			UpdatedAt: e.UpdatedAt,
			Preview:   truncatePreview(e.Preview),
			Path:      e.Path,
			Title:     e.Title,
		})
	}
	return entries, skipped, nil
}

// truncatePreview keeps a head and the tail, because two sessions started from the same
// long prompt differ only in their tail and the picker cannot recover one this drops.
func truncatePreview(s string) string {
	return tui.FitCells(strings.Join(strings.Fields(s), " "), resumePreviewMax)
}

// resumeRenamer is the production tui.SessionRenamer: it persists a new title on the
// chosen session file via sessions.SetTitle, targeting the file by the
// ResumeEntry.Path the lister populated. SetTitle leaves the file unchanged on any
// failure (lock contention, version refusal, atomic-write failure); the picker surfaces
// the returned error as a transient notice. It carries no state — one value serves the
// whole run.
type resumeRenamer struct{}

func (resumeRenamer) Rename(entry tui.ResumeEntry, title string) error {
	_, err := sessions.SetTitle(entry.Path, title)
	return err
}

// resumeDeleter is the production tui.SessionDeleter: it removes the chosen session
// file via sessions.DeleteSession. As defense-in-depth it refuses to delete
// the run's active session even though resumeLister.List already excludes it — matching
// by metadata.id so the guard holds regardless of the path string. DeleteSession leaves
// the file in place on any failure (lock contention, unlink failure); the picker
// surfaces the returned error as a transient notice.
type resumeDeleter struct{ app *tui.App }

func (d resumeDeleter) Delete(entry tui.ResumeEntry) error {
	if d.app != nil {
		if active := d.app.ActiveStore(); active != nil && active.SessionID() == entry.ID {
			return fmt.Errorf("session %s is the active session and cannot be deleted", entry.ID)
		}
	}
	_, err := sessions.DeleteSession(entry.Path)
	return err
}

// resumeLoader is the production tui.TargetLoader. It resolves the chosen entry to
// its session file and loads + classifies it by reusing sessions.ResolveResumeID
// (expected-path load, the folder-file check, and the CWD-match —
// all of which a current-folder survivor satisfies) and sessions.ClassifyVersion.
// On a load failure — most realistically the file pruned between listing and
// selection (step 8) — it returns a nil store, an error category for
// the step-8 notice, and the error. older is the older-fork-eligible
// classification; while sessions.ReaderSupportedVersion == 1 no loadable session can
// be older (an integer schema_version is either == 1 and loads normally or is
// refused as newer/unparseable, version.go), so older is always false in phase 1 and
// the OlderSchemaForker branch it would drive is unreachable (see resumeForker).
type resumeLoader struct {
	home string
	cwd  string
}

func (l resumeLoader) Load(entry tui.ResumeEntry) (*sessions.Store, bool, fserrors.Category, error) {
	path, sess, err := sessions.ResolveResumeID(entry.ID, l.cwd, l.home, events.ValidatePayload)
	if err != nil {
		return nil, false, resumeLoadCategory(err), err
	}
	status, _ := sessions.ClassifyVersion(sess.Metadata.SchemaVersion)
	return sessions.New(path, sess), status == sessions.StatusOlderForkEligible, "", nil
}

// resumeLoadCategory extracts the error category for the step-8
// load-failure notice from a sessions.ResolveResumeID error. The category-bearing typed errors
// expose it directly; a vanished session (the dominant step-8 case: pruned between
// listing and selection) reports not_found; anything else falls back to the
// syscall category (io_error when no errno is wrapped).
func resumeLoadCategory(err error) fserrors.Category {
	var ffe *sessions.ResumeFolderFileError
	if errors.As(err, &ffe) {
		return ffe.Category
	}
	var ee *sessions.ResumeEnumerateError
	if errors.As(err, &ee) {
		return ee.Category
	}
	var nfe *sessions.ResumeNotFoundError
	if errors.As(err, &nfe) {
		return fserrors.NotFound
	}
	return fserrors.CategorizeErrno(err)
}

type resumeLockHolder struct {
	release func()
}

// handoff installs next as the held resume-lock release and returns the
// previously held one (nil if none) WITHOUT calling it, so the caller controls
// when the prior lock is dropped relative to its own commit point: resumeSwitch
// acquires the chosen session's lock before calling the returned prior release, so
// the cross-instance protection is never dropped mid-switch.
func (h *resumeLockHolder) handoff(next func()) (prev func()) {
	prev = h.release
	h.release = next
	return prev
}

// releaseHeld releases and clears the currently held resume lock, if any. It is
// idempotent (the held release is cleared after firing) and nil-receiver safe, so
// the /clear and /exit paths can call it unconditionally — including when no
// resume lock was ever held (a fresh-launched run) or after a prior path already
// released it.
func (h *resumeLockHolder) releaseHeld() {
	if h == nil || h.release == nil {
		return
	}
	h.release()
	h.release = nil
}

type resumeSwitch struct {
	app          *tui.App
	holder       *resumeLockHolder
	pending      func()
	pendingPrior *sessions.Store
	ctx          context.Context
	ui           tui.NoticeRenderer
	recorder     *capabilityRecorder
	conf         *confinement
}

func (s *resumeSwitch) Switch(target, prior *sessions.Store) error {
	s.Abort()
	release, err := sessions.AcquireResumeLock(target.Path(), target.SessionID())
	if err != nil {
		// Lock timeout / acquire failure: the chosen lock was not taken, so the prior
		// session stays active and its lock is retained — nothing released, nothing
		// installed. The typed error's text is the one-line notice the handler renders.
		return err
	}

	s.pending = release
	s.pendingPrior = prior
	return nil
}

func (s *resumeSwitch) Activate(target *sessions.Store) (string, error) {
	folder, rollback, err := s.conf.prepareReplacement()
	if err != nil {
		return "", err
	}
	if err := s.recorder.activate(s.ctx, s.app, target, s.ui); err != nil {
		return "", errors.Join(err, rollback())
	}
	s.conf.commitReplacement(folder)
	release := s.pending
	prior := s.pendingPrior
	s.pending = nil
	s.pendingPrior = nil
	if source := s.holder.handoff(release); source != nil {
		source()
	}
	prior.Close()
	return s.conf.takeCleanupWarning(), nil
}

func (s *resumeSwitch) Abort() {
	release := s.pending
	s.pending = nil
	s.pendingPrior = nil
	if release != nil {
		release()
	}
}

// resumeRefresher is the production tui.UpdatedAtRefresher. It refreshes the loaded
// session's updated_at via sessions.RefreshUpdatedAt and absorbs a
// per-turn atomic-write failure through the per-turn write-failure sink (session_write_failed +
// notice), returning a non-nil error only for a fatal non-write condition (a
// cancelled run context, an un-encodable marshal failure) or a sink that itself
// could not record the degradation — which aborts the post-switch sequence.
type resumeRefresher struct {
	ui tui.NoticeRenderer
}

func (r resumeRefresher) Refresh(ctx context.Context, target *sessions.Store) error {
	cat, reason, err := sessions.RefreshUpdatedAt(ctx, target)
	if err == nil {
		return nil
	}
	if reason != sessions.ReasonNone {
		// Per-turn atomic-write failure: route through the per-turn write-failure
		// protocol (records carry forward, the run continues). HandleWriteFailure returns nil when it recorded the
		// degradation, or an error when it could not — which surfaces.
		return sessionfailures.HandleWriteFailure(reason, cat, target.Path(), err, target, r.ui)
	}
	// A ReasonNone error (cancelled context / marshal failure) cannot be encoded as
	// session_write_failed; surface it so the post-switch sequence aborts.
	return err
}

// resumeModelRecoverer is the production tui.ModelRecoverer: real step-1
// model recovery for an in-TUI /resume switch.
// It scans the loaded session's record stream for the most recent model_turn via
// model.RecoverActiveSelection and acts on the outcome: a clean recovery is adopted
// into the run-scoped active state as source "resume" (overriding any prior in-memory
// selection); a recovery failure clears the active selection and opens the model
// picker (the helper has already appended exactly one model_recovery_failed); and a
// target with no model_turn leaves the existing active selection unchanged. It writes
// no CLI stderr — a TUI failure is surfaced through the picker, not the launch warn
// surface (Context.Warn left nil) — and returns a non-nil error only for an internal
// append failure the /resume handler must surface, in which case the active selection
// is left unchanged.
type resumeModelRecoverer struct {
	app    *tui.App
	cache  *config.Cache
	active *model.ActiveState
}

func (r resumeModelRecoverer) Recover(target *sessions.Store) error {
	sel, outcome, err := model.RecoverActiveSelection(model.Context{
		Config:        r.cache,
		Resume:        true,
		ResumeRecords: target.Records(),
		Store:         target,
	})
	if err != nil {
		return err
	}
	switch outcome {
	case model.RecoveryClean:
		r.active.ApplyResumeSwitch(sel, model.SourceResume)
	case model.RecoveryFailed:
		// The helper appended the single model_recovery_failed; clear the now-orphaned
		// selection and open the provider-aware picker so the user re-picks.
		r.active.ApplyResumeSwitch(nil, "")
		r.app.OpenModelPicker()
	case model.RecoveryNoModelTurn:
		// Nothing to recover: leave the existing active selection in place.
		// model.RecoverActiveSelection treats an absent model_turn as "not a recovery
		// failure", so no event is appended.
	}
	return nil
}

// resumeForker is the production tui.OlderSchemaForker. The /resume handler invokes it
// only for an older-schema (older-fork-eligible) selection, but while
// sessions.ReaderSupportedVersion == 1 no loadable session can classify as
// older-fork-eligible (version.go: an integer schema_version is either == 1 and
// loads normally or is refused as newer/unparseable), so resumeLoader never reports
// older == true and this branch is unreachable in phase 1. It is therefore a
// documented no-op seam: the read-only view + one-shot fork affordance (sessionfork.Fork
// plus a TUI read-only overlay) is wired when the reader first
// supports a second schema version and older files become reachable. Returning nil
// keeps the interface satisfied without pretending to offer a fork.
type resumeForker struct{}

func (resumeForker) OfferFork(*sessions.Store) error { return nil }
