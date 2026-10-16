// /resume command: open the in-TUI session picker for the current folder and, on
// selection, switch the running session to the chosen one — load + classify the
// target first, then for an equal-schema target cancel the in-flight stream, flush
// and hand off the prior session, lock it, and replay its launch/model/agent-
// instruction anchors; an older-schema or vanished selection leaves the
// originally-active session and its in-flight stream undisturbed. The command behaviour
// lives behind a ResumeDeps dependency-injection seam (mirroring /clear's
// ClearDeps) so it is driven end-to-end with fakes and no real terminal; the
// run-scoped production implementations, the BuildRegistry wiring, and
// the resume-sequence bridge are supplied by production wiring.
package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/sessions"
)

// noResumableSessionsMsg is the one-line message shown when the current folder has
// no resumable sessions; the empty picker dismisses on any keypress.
const noResumableSessionsMsg = "no resumable sessions in this folder"

// ResumeEntry is one row the picker renders for a resumable session: the
// id, the start/update timestamps, and the truncated first user message preview.
// It is the TUI-facing projection of a sessions.ListEntry, whose scan already
// carries the title and the untruncated preview; the production lister only bounds
// the preview to the picker's cell budget. ID is the handle Load resolves (the
// cold-start --resume <id> handle).
type ResumeEntry struct {
	ID        string
	StartedAt time.Time
	UpdatedAt time.Time
	Preview   string
	// Path is the absolute session-file path, populated by the production lister so the
	// rename/delete actions can target the file directly (sessions.SetTitle /
	// sessions.DeleteSession) without re-resolving the id. ID still drives load/switch.
	Path string
	// Title is the persisted optional session title (sessions.Metadata.Title). When
	// non-empty it overrides Preview as the row's display text (resumeRowTitle).
	Title string
}

// PickerResult reports what the user did in the picker: Selected is true when the
// user pressed Enter on a row (Index names it), false when ESC dismissed the
// picker without switching.
type PickerResult struct {
	Selected bool
	Index    int
}

// SessionLister lists the resumable sessions for the current canonical folder.
// It returns the survivors as picker rows, the ids it skipped, and a
// typed enumeration error. The production implementation wraps
// sessions.ListResumable for the run's home/cwd; on a non-ENOENT readdir failure
// it returns the *sessions.ResumeListEnumerateError that names the subdirectory
// and error category.
type SessionLister interface {
	List() (entries []ResumeEntry, skipped []sessions.SkippedID, err error)
}

// ResumePicker presents the resumable sessions and reports the user's choice
// through a continuation, or shows the empty-folder message. It never blocks: the
// production implementation (picker_resume.go) mounts a tview Pages overlay,
// returns control to the event loop immediately, and invokes the supplied callback
// from the focused list's Enter/ESC handlers on the single tview goroutine —
// modeled on the CTRL-M model picker. A blocking call here would freeze the event
// loop before the picker keys could arrive, since the production submit path runs
// handlers synchronously off the tview input callback (Resolution — Option A,
// 2026-06-02). Keeping it behind this seam lets the handler's listing/selection
// behaviour be asserted with a fake that invokes the callback synchronously.
type ResumePicker interface {
	// Present shows entries and returns immediately; when the user selects a row
	// (Enter) or dismisses the picker (ESC) it invokes onResult exactly once with
	// the outcome. The post-selection session-switch sequence runs inside onResult,
	// not after Present returns, so the event-loop submit path is never blocked.
	// actions carries the rename/delete/re-list callbacks the picker invokes while it
	// stays open (ctrl+r / ctrl+d); they are side-effect-only and never resolve
	// onResult, so an in-picker mutation cannot run the session-switch continuation.
	Present(entries []ResumeEntry, onResult func(PickerResult), actions ResumeActions)
	// PresentEmpty shows message and returns immediately; when any keypress
	// dismisses it it invokes onDismiss exactly once. Used only when the
	// folder has no resumable sessions.
	PresentEmpty(message string, onDismiss func())
}

// SessionRenamer persists a new title on a resumable session (rename action).
// The production implementation calls sessions.SetTitle on the entry's file path; a
// non-nil error (lock contention, version refusal, write failure) is rendered as a
// transient picker notice and leaves the file unchanged.
type SessionRenamer interface {
	Rename(entry ResumeEntry, title string) error
}

// SessionDeleter deletes a resumable session file (delete action). The
// production implementation guards the active session and calls sessions.DeleteSession
// on the entry's file path; a non-nil error (lock contention, the active-session guard,
// unlink failure) is rendered as a transient picker notice and leaves the file in place.
type SessionDeleter interface {
	Delete(entry ResumeEntry) error
}

// ResumeActions bundles the in-picker mutation callbacks the open picker invokes while
// it stays mounted: Rename and Delete persist a title / remove a file, and ReList
// re-enumerates the current folder's survivors so the picker can refresh its rows after
// a mutation. They are kept separate from the Enter/ESC onResult continuation so a
// rename or delete never triggers the session-switch sequence (the open picker holds
// mutable row state; only Enter/ESC resolve the switch). ReList ignores skipped ids on
// refresh (the skipped-id notices are shown once, at the initial open).
type ResumeActions struct {
	Rename func(entry ResumeEntry, title string) error
	Delete func(entry ResumeEntry) error
	ReList func() ([]ResumeEntry, error)
}

// TargetLoader resolves and loads the chosen session and classifies its schema
// version. older reports an older-schema file that routes to the
// read-only + fork affordance. On a load failure — e.g. the file was pruned
// between listing and selection — it returns a nil store, failCat carrying the
// error category for the step-8 notice, and a non-nil error; failCat is
// the empty category on success.
type TargetLoader interface {
	Load(entry ResumeEntry) (target *sessions.Store, older bool, failCat fserrors.Category, err error)
}

type ResumeSwitch interface {
	Switch(target, prior *sessions.Store) error
	Activate(target *sessions.Store) (cleanupWarning string, err error)
}

// UpdatedAtRefresher refreshes the loaded session's updated_at and flushes it so a
// resumed session stays inside the retention window. It absorbs a
// per-turn atomic-write failure internally and returns a non-nil error only
// for a fatal condition such as a cancelled run context, which aborts the switch.
type UpdatedAtRefresher interface {
	Refresh(ctx context.Context, target *sessions.Store) error
}

// ModelRecoverer runs the step-1 model recovery against the loaded
// session's record stream. On a clean recovery it adopts the recovered
// selection (overriding any prior in-memory selection, source "resume"); on a
// recovery failure it appends model_recovery_failed, clears the selection, and
// routes to the model picker. Those outcomes are handled inside the capability, so
// it returns a non-nil error only for an internal append/flush failure the handler
// must surface.
type ModelRecoverer interface {
	Recover(target *sessions.Store) error
}

// OlderSchemaForker presents the read-only view and one-shot fork action for an
// older-schema selection. The originally-active session stays active in the
// background — it is neither locked away nor sealed — until the fork action itself
// succeeds, so an ESC out of the fork affordance returns the user to it.
type OlderSchemaForker interface {
	OfferFork(target *sessions.Store) error
}

// TranscriptReplayer resets the visible transcript pane and replays a session's prior
// conversation into it. After an equal-schema /resume switch commits, the handler
// calls Reset then Replay so the chosen session's history replaces the prior session's
// visible transcript instead of mixing the two or leaving the pane empty. The App
// satisfies it via ResetTranscript / ReplaySessionRecords; it is injected so the switch
// sequence can be asserted with a fake, and an unset (nil) capability skips replay
// entirely (the switch still commits).
type TranscriptReplayer interface {
	ResetTranscript()
	ReplaySessionRecords(records []sessions.Record)
}

// ResumeDeps gathers the capability interfaces NewResumeHandler closes over, each
// independently injectable so the handler can be driven end-to-end with fakes
// (mirroring ClearDeps). StreamCanceller, AgentInstructionsReplayer, and
// WriteFailureSink are the same interfaces /clear uses (defined in cmd_clear.go).
// Production wiring supplies the implementations bound to the running app + bootstrap
// result.
type ResumeDeps struct {
	Lister SessionLister
	Picker ResumePicker
	// Rename and Delete are the in-picker mutation capabilities: ctrl+r
	// persists a typed title via Rename, ctrl+d removes the file via Delete. The
	// production wiring binds them to sessions.SetTitle / sessions.DeleteSession (the
	// deleter additionally guards the active session). They are invoked only while the
	// picker is open and never resolve the Enter/ESC continuation.
	Rename           SessionRenamer
	Delete           SessionDeleter
	Stream           StreamCanceller
	StreamTranscript StreamInterruptionMarker
	Loader           TargetLoader
	Switch           ResumeSwitch
	Refresh          UpdatedAtRefresher
	Model            ModelRecoverer
	Agents           AgentInstructionsReplayer
	Fork             OlderSchemaForker
	WriteFailure     WriteFailureSink
	// Transcript resets and re-renders the visible transcript pane after an equal-schema
	// switch commits, so the resumed session shows its prior conversation. A nil
	// capability skips the visible replay; the session switch itself is unaffected.
	Transcript TranscriptReplayer
	// FlushCtx is the run context used for the prior session's pre-switch flush and
	// the loaded session's launch/refresh/post-replay writes. Threading the
	// real run context means a genuinely cancelled run makes the pre-switch flush a
	// no-op that returns a non-write error, refusing the switch so the prior session's
	// final records are not dropped before being made durable. Nil means
	// context.Background().
	FlushCtx context.Context
}

func (d ResumeDeps) flushCtx() context.Context {
	if d.FlushCtx == nil {
		return context.Background()
	}
	return d.FlushCtx
}

func (d ResumeDeps) flushStore(ctx context.Context, store *sessions.Store) (ok bool, err error) {
	cat, reason, ferr := store.Flush(ctx)
	if ferr == nil {
		return true, nil
	}
	if reason != sessions.ReasonNone {
		return false, d.WriteFailure.Handle(reason, cat, store.Path(), ferr, store)
	}
	return false, ferr
}

type resumeAborter interface {
	Abort()
}

// NewResumeHandler returns the /resume handler. It lists the current folder's
// resumable sessions; on a non-ENOENT enumeration failure it records
// slash_command{outcome:error} and renders the failure notice without opening the
// picker (step 3). Otherwise it records slash_command{outcome:success} and flushes
// it durable before opening the picker (the FlushActive contract: a slash_command with no later flush
// boundary is made durable before the next non-append step — here, opening the
// overlay and returning to dispatch — since the production picker's Present returns at
// once). It then opens the picker and returns; the empty-folder dismissal and the ESC
// dismissal have nothing left to do, while the on-selection session-switch sequence
// runs inside the picker's continuation callback (Resolution — Option A: a
// continuation, never a blocking call), so the event-loop submit path is not frozen
// while the picker is open. Because that post-selection sequence runs after the
// handler has returned, a residual failure it produces cannot flow back to the
// dispatch result; surfaceResumeErr renders it as a one-line notice, the only channel
// left (mirroring the CTRL-M model picker's confirm path). The pre-picker steps
// (lister/skipped/success-record-and-flush) still return their errors synchronously to
// dispatch, where a failure retains the input.
func NewResumeHandler(deps ResumeDeps) HandlerFunc {
	return func(cmdCtx CommandContext, _ []string) error {
		prior := cmdCtx.Store()

		entries, skipped, err := deps.Lister.List()
		if err != nil {
			// (step 3) Enumeration failure: do not open the picker. The same one-line
			// text is the rendered notice and the slash_command error_detail.
			text := resumeEnumerateNotice(err)
			cmdCtx.Notice(text)
			if aerr := cmdCtx.AppendSlashCommand(OutcomeError, text); aerr != nil {
				return aerr
			}
			return cmdCtx.FlushActive()
		}

		if len(skipped) > 0 {
			cmdCtx.Notice(resumeSkippedNotice(skipped))
		}

		// Record the picker-open slash_command{success} and make it
		// durable immediately — before opening the picker and returning to dispatch. The
		// FlushActive contract requires a handler that appended a slash_command with no
		// later flush boundary to flush before its next non-append step (opening an overlay
		// or returning). The production picker's Present returns at once, so deferring this
		// flush into the continuation would lose the accepted /resume audit event if the run
		// crashed while the picker was open, and a non-write flush failure could no longer
		// retain the input — dispatch has already cleared it. Flushing here keeps any failure
		// on the synchronous dispatch path, where returning it retains the input. On a
		// selection the success record is already on disk before runResumeSwitch's pre-switch
		// flush carries the switch's own records.
		if aerr := cmdCtx.AppendSlashCommand(OutcomeSuccess, ""); aerr != nil {
			return aerr
		}
		if ferr := cmdCtx.FlushActive(); ferr != nil {
			return ferr
		}

		if len(entries) == 0 {
			// (step 2/DW3) Empty folder: show the message, dismissed on any keypress. The
			// success record is already durable, so the dismissal callback has nothing to do.
			deps.Picker.PresentEmpty(noResumableSessionsMsg, func() {})
			return nil
		}

		// Open the navigable picker and return to the event loop at once. The
		// picker-open success is already durable; the continuation only runs the
		// on-selection switch sequence (which owns its own flushes) or, on ESC, nothing.
		// The rename/delete/re-list actions run while the picker stays open and are
		// side-effect-only — they never resolve onResult, so an in-picker mutation cannot
		// run the session-switch sequence. ReList ignores skipped ids on refresh (the
		// skipped notices were already shown once, above). A nil Rename/Delete capability
		// leaves its func unset so the picker treats the key as inert.
		actions := ResumeActions{
			ReList: func() ([]ResumeEntry, error) {
				next, _, lerr := deps.Lister.List()
				return next, lerr
			},
		}
		if deps.Rename != nil {
			actions.Rename = deps.Rename.Rename
		}
		if deps.Delete != nil {
			actions.Delete = deps.Delete.Delete
		}
		deps.Picker.Present(entries, func(choice PickerResult) {
			if !choice.Selected {
				// (step 4) ESC dismissed the picker; the durable success record stands.
				return
			}
			warning, err := runResumeSwitch(cmdCtx, deps, prior, entries[choice.Index])
			if err == nil && warning != "" {
				cmdCtx.Notice(warning)
			}
			surfaceResumeErr(cmdCtx, err)
		}, actions)
		return nil
	}
}

// surfaceResumeErr renders a residual post-selection error as a one-line notice.
// The continuation form runs the on-selection session-switch sequence after the
// handler has already returned to the event loop (the picker-open success is flushed
// before the picker opens, so the empty-folder and ESC-dismiss paths leave nothing to
// flush in their callbacks), so an error the switch sequence produces cannot flow back
// to the dispatch result (and the /resume input has already been accepted/cleared).
// The notice surface is the only channel left, matching the model picker's confirm
// path. Most runResumeSwitch failure paths render their own prescribed notice and
// route writes through the sink, returning nil; this covers the residual
// internal-failure returns (an AppendSlashCommand/sink failure, or a non-write flush
// error such as a cancelled run).
func surfaceResumeErr(cmdCtx CommandContext, err error) {
	if err != nil {
		cmdCtx.Notice(err.Error())
	}
}

func runResumeSwitch(cmdCtx CommandContext, deps ResumeDeps, prior *sessions.Store, entry ResumeEntry) (string, error) {
	ctx := deps.flushCtx()

	// (step 5 sub-sequence) Resolve, load, and classify the chosen session
	// before disturbing the active session. The two branches that do not switch away — a
	// load failure (step 8) and an older-schema selection (step 6) — must leave the
	// originally-active session and its in-flight stream untouched, so the stream
	// cancellation and pre-switch flush are deferred until after they are handled.
	target, older, failCat, lerr := deps.Loader.Load(entry)
	if lerr != nil {
		// (step 8/DW8) Chosen-session load failure after the picker opened (e.g. the file
		// was pruned between listing and selection): leave the prior session active and its
		// in-flight stream undisturbed, and render a one-line notice naming the chosen id
		// and failure category. The picker-open slash_command{success} already stands, so no
		// further event is recorded; flush the still-active prior session so that success
		// record is durable as a checkpoint (an atomic-write failure routes through the
		// sink, a non-write error surfaces).
		cmdCtx.Notice(resumeLoadFailureNotice(entry.ID, failCat))
		_, ferr := deps.flushStore(ctx, prior)
		return "", ferr
	}

	if older {
		// (step 6/DW6) Older-schema selection bypasses the stream cancellation, lock
		// handoff, and updated_at refresh: the original session stays active in the
		// background — its in-flight stream uninterrupted — until the fork action succeeds,
		// so an ESC out of the fork affordance returns the user to it. First make the
		// picker-open slash_command{success} durable as a checkpoint on the still-active
		// prior session — mirroring the load-failure branch above — so a crash
		// after the read-only/fork view opens cannot lose the /resume audit event. The flush
		// is a checkpoint only: it neither seals nor cancels the active session, so it leaves
		// the originally-active session and its in-flight stream undisturbed. An atomic-write
		// failure routes through the sink; a non-write error (e.g. a cancelled run)
		// surfaces.
		if ok, ferr := deps.flushStore(ctx, prior); !ok {
			return "", ferr
		}
		return "", deps.Fork.OfferFork(target)
	}

	// (step 5) The selection is an equal-schema switch. Cancel any in-flight provider
	// request; stream_interrupted is recorded on the prior session only when a stream was
	// actually in flight, so a real provider transport failure that wins the race (which
	// stays provider_request_failed) is not converted into a synthetic interrupt.
	retained, inFlight := deps.Stream.Cancel()
	drainCancelledTurn(deps.Stream)
	if inFlight {
		if deps.StreamTranscript != nil {
			deps.StreamTranscript.MarkStreamInterruptedFromCommand()
		}
		if _, err := events.Append(prior, events.StreamInterrupted{
			Source:       "slash_resume_switch",
			ContentChars: int64(retained),
		}); err != nil {
			return "", err
		}
	}

	// (step 5) Final pre-switch flush of the prior session. On failure the switch
	// is refused and the prior session stays active and unsealed: an atomic-write failure
	// routes through the sink, and a non-write error (e.g. a cancelled run)
	// surfaces directly. Either way the slash_command and stream_interrupted records stay
	// in memory for the next flush.
	if ok, ferr := deps.flushStore(ctx, prior); !ok {
		return "", ferr
	}

	if serr := deps.Switch.Switch(target, prior); serr != nil {
		text := resumeLockFailureNotice(serr)
		cmdCtx.Notice(text)
		if aerr := cmdCtx.AppendSlashCommand(OutcomeError, text); aerr != nil {
			return "", aerr
		}
		return "", cmdCtx.FlushActive()
	}
	aborter, canAbort := deps.Switch.(resumeAborter)
	activated := false
	if canAbort {
		defer func() {
			if !activated {
				aborter.Abort()
			}
		}()
	}

	var lbHandleErr error
	lbWriteHandled := false
	lberr := events.EmitLaunchBegan(ctx, target, "resume", func(c fserrors.Category, r sessions.WriteReason, e error) {
		lbHandleErr = deps.WriteFailure.Handle(r, c, target.Path(), e, target)
		lbWriteHandled = true
	})
	// A handled per-turn launch write failure is carried forward only when the sink
	// itself succeeded. If WriteFailure.Handle could not append session_write_failed
	// (e.g. invalid failure inputs or append rejection), surface that error and stop
	// the post-switch sequence — otherwise refresh/model/agent replay would run as if
	// the degradation event were durable when it was silently lost.
	if lbHandleErr != nil {
		return "", lbHandleErr
	}
	if lberr != nil && !lbWriteHandled {
		return "", lberr
	}

	warning, err := deps.Switch.Activate(target)
	if err != nil {
		return "", err
	}
	activated = true
	if deps.Transcript != nil {
		deps.Transcript.ResetTranscript()
		deps.Transcript.ReplaySessionRecords(target.Records())
	}

	// Refresh updated_at after the launch anchor and before model recovery.
	if rerr := deps.Refresh.Refresh(ctx, target); rerr != nil {
		return "", rerr
	}

	// (step 1) Recover the model selection from the loaded record stream after
	// the updated_at refresh and before replaying agent instructions.
	if merr := deps.Model.Recover(target); merr != nil {
		return "", merr
	}

	// (7c) Replay the in-memory AGENTS.md load record into the loaded session
	// as fresh agent_instructions_loaded events, after the launch anchor.
	if aerr := deps.Agents.Replay(target); aerr != nil {
		return "", aerr
	}

	// Flush the replayed agent-instruction (and any model-recovery)
	// records so they are durable before control returns to the TUI. The switch has
	// committed, so an atomic-write failure here is a per-turn failure routed through
	// the sink; a non-write failure surfaces.
	_, ferr := deps.flushStore(ctx, target)
	return warning, ferr
}

// resumeEnumerateNotice renders the step-3 enumeration-failure line
// (without the CLI's "codemeld:" prefix) from the typed listing error, falling
// back to the error's own text for any other failure.
func resumeEnumerateNotice(err error) string {
	var ee *sessions.ResumeListEnumerateError
	if errors.As(err, &ee) {
		return fmt.Sprintf("session list: cannot enumerate %s: %s", ee.Subdir, resumeCategoryLabel(ee.Category))
	}
	return err.Error()
}

func resumeSkippedNotice(skipped []sessions.SkippedID) string {
	const shown = 5
	noun := "sessions"
	if len(skipped) == 1 {
		noun = "session"
	}
	ids := make([]string, 0, shown+1)
	for _, s := range skipped[:min(len(skipped), shown)] {
		ids = append(ids, s.ID)
	}
	if more := len(skipped) - shown; more > 0 {
		ids = append(ids, fmt.Sprintf("... %d more", more))
	}
	return fmt.Sprintf("%d %s could not be listed (e.g. %s); run codemeld sessions doctor <id> to see why", len(skipped), noun, strings.Join(ids, ", "))
}

// resumeLockFailureNotice renders the step-7 in-TUI lock-failure line for a
// switch error, stripping the cold-start `codemeld:` CLI prefix that
// *sessions.ResumeLockError.Error() carries (that prefixed form stays the stderr line
// for the `--resume <id>` entry point). For a lock timeout it is
// `session <id> in use by another codemeld instance`; for a non-timeout acquire
// failure it is `session <id>: lock acquisition failed: <category label>`. Any other
// switch error falls back to its own text.
func resumeLockFailureNotice(err error) string {
	var le *sessions.ResumeLockError
	if errors.As(err, &le) {
		if le.Reason == locks.ReasonLockTimeout {
			return fmt.Sprintf("session %s in use by another codemeld instance", le.ID)
		}
		return fmt.Sprintf("session %s: lock acquisition failed: %s", le.ID, resumeCategoryLabel(le.Cat))
	}
	return err.Error()
}

// resumeLoadFailureNotice renders the step-8 one-line notice naming the chosen id
// and the failure category when the chosen session cannot be loaded after the
// picker opened.
func resumeLoadFailureNotice(id string, failCat fserrors.Category) string {
	return fmt.Sprintf("session %s: cannot load chosen session: %s", id, resumeCategoryLabel(failCat))
}

func resumeCategoryLabel(cat fserrors.Category) string {
	switch cat {
	case fserrors.PermissionDenied:
		return "permission denied"
	case fserrors.NoSpace:
		return "no space"
	case fserrors.ReadOnlyFS:
		return "read-only filesystem"
	case fserrors.IOError:
		return "I/O error"
	case fserrors.NotFound:
		return "not found"
	case fserrors.InUse:
		return "in use"
	default:
		return "filesystem error"
	}
}
