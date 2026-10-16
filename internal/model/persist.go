// Model-selection persistence: the per-project model.active and global
// model.last_used writes through the shared config persistence chokepoint, the
// model_changed / persist-failure event helpers, and the TUI picker-selection
// write flow.
package model

import (
	"context"
	"path/filepath"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// lockTimeoutDetail is the exact error_detail the model persist-failure event
// validators require for a lock_timeout reason (events.lockTimeoutDetail).
// config.Persist surfaces the raw context-deadline error for lock_timeout
// (locks.Acquire returns the deadline error), whose message differs, so the
// persist-failure events substitute this canonical detail rather than the raw
// error string.
const lockTimeoutDetail = "lock acquisition timed out"

// persist is a seam over config.Persist so the write helpers and picker flow can
// be exercised against forced reason/category/error outcomes in tests without
// reproducing config.Persist's own filesystem failure modes (which it already
// covers through its internal seams). Production uses config.Persist unchanged.
var persist = config.Persist

var persistLocal = config.PersistLocal

// selectionYAML renders sel as the on-disk YAML mapping with provider
// id, and effort in that order, matching model.active / model.last_used's
// persisted shape and the existing rewrite contract. The on-disk field is id,
// never model_id.
func selectionYAML(sel Selection) yaml.MapSlice {
	return yaml.MapSlice{
		{Key: "provider", Value: sel.Provider},
		{Key: "id", Value: sel.ID},
		{Key: "effort", Value: sel.Effort},
	}
}

func WriteActive(projectRoot string, sel Selection) (targetPath string, created bool, reason config.PersistReason, errCat fserrors.Category, err error) {
	targetPath = config.LocalSettingsPath(projectRoot)
	created, reason, errCat, err = persistLocal(projectRoot, config.KeyModelActive, selectionYAML(sel))
	return targetPath, created, reason, errCat, err
}

// WriteLastUsed mirrors sel to model.last_used in
// <home>/.codemeld/global/settings.yaml through the shared config persistence
// chokepoint (step 2). It returns the resolved target path together with
// config.Persist's reason, error category, and error. The global mirror is
// non-fatal: on failure the caller emits model_global_mirror_failed and surfaces no
// user-facing notice.
func WriteLastUsed(home string, sel Selection) (targetPath string, reason config.PersistReason, errCat fserrors.Category, err error) {
	targetPath = filepath.Join(home, ".codemeld", "global", "settings.yaml")
	reason, errCat, err = persist(targetPath, config.KeyModelLastUsed, selectionYAML(sel))
	return targetPath, reason, errCat, err
}

// EmitModelChanged appends a model_changed event recording a picker selection.
// prior is the selection active before the pick: when non-nil
// the event carries the full prior provider/id/effort tuple, and when nil it omits
// all three, honoring the validator's all-present-or-all-absent rule for the prior
// fields. It appends only; the caller owns the flush.
func EmitModelChanged(store *sessions.Store, sel Selection, prior *Selection) error {
	ev := events.ModelChanged{
		NewProvider: sel.Provider,
		NewModelID:  sel.ID,
		NewEffort:   sel.Effort,
	}
	if prior != nil {
		ev.PriorProvider = prior.Provider
		ev.PriorModelID = prior.ID
		ev.PriorEffort = prior.Effort
	}
	_, err := events.Append(store, ev)
	return err
}

// EmitModelPersistFailed appends a model_persist_failed event for a failed
// per-project model.active write (step 1), using config.Persist's reason
// error category, and error verbatim except for lock_timeout, whose detail is the
// canonical lockTimeoutDetail the validator requires. error_category is passed
// through unchanged: config.Persist already returns it empty for the no-category
// reasons (lock_timeout, reread_parse_error), which the omitempty event field
// drops. It appends only.
func EmitModelPersistFailed(store *sessions.Store, targetPath string, sel Selection, reason config.PersistReason, errCat fserrors.Category, err error) error {
	return emitModelPersistEvent(store, targetPath, sel, reason, errCat, err,
		func(targetPath, provider, modelID, effort, reason, errCat, detail string) events.EventPayload {
			return events.ModelPersistFailed{
				TargetPath:    targetPath,
				Provider:      provider,
				ModelID:       modelID,
				Effort:        effort,
				Reason:        reason,
				ErrorCategory: errCat,
				ErrorDetail:   detail,
			}
		})
}

// EmitModelGlobalMirrorFailed appends a model_global_mirror_failed event for a
// failed global model.last_used mirror write (step 2). It uses the same
// reason/category/detail shape as EmitModelPersistFailed but is silent to the
// user: the caller renders no notice for it. It appends only.
func EmitModelGlobalMirrorFailed(store *sessions.Store, targetPath string, sel Selection, reason config.PersistReason, errCat fserrors.Category, err error) error {
	return emitModelPersistEvent(store, targetPath, sel, reason, errCat, err,
		func(targetPath, provider, modelID, effort, reason, errCat, detail string) events.EventPayload {
			return events.ModelGlobalMirrorFailed{
				TargetPath:    targetPath,
				Provider:      provider,
				ModelID:       modelID,
				Effort:        effort,
				Reason:        reason,
				ErrorCategory: errCat,
				ErrorDetail:   detail,
			}
		})
}

// emitModelPersistEvent builds and appends a model persist-failure event shared by
// EmitModelPersistFailed and EmitModelGlobalMirrorFailed, which differ only in the
// concrete event type. It normalizes the Selection and reason/category into the
// common string fields — substituting the canonical lockTimeoutDetail for
// lock_timeout via persistErrorDetail — and hands them to build, which returns the
// kind-specific payload. It appends only, returning the append error.
func emitModelPersistEvent(store *sessions.Store, targetPath string, sel Selection, reason config.PersistReason, errCat fserrors.Category, err error, build func(targetPath, provider, modelID, effort, reason, errCat, detail string) events.EventPayload) error {
	_, aerr := events.Append(store, build(
		targetPath, sel.Provider, sel.ID, sel.Effort,
		string(reason), string(errCat), persistErrorDetail(reason, err),
	))
	return aerr
}

// persistErrorDetail returns the error_detail for a model persist-failure event.
// lock_timeout requires the exact canonical string the validator pins, which
// differs from config.Persist's raw context-deadline error; every other reason
// carries the underlying OS error message. A reason with a nil error (not expected
// for a failure path) yields an empty detail, which the validator then rejects so
// the inconsistency is not silently persisted.
func persistErrorDetail(reason config.PersistReason, err error) string {
	if reason == config.ReasonLockTimeout {
		return lockTimeoutDetail
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// PickerResult reports the outcome of persisting a picker selection so the caller
// can choose the source for subsequent model_turn events. Degraded is true when the
// per-project model.active write failed: the selection stays active in memory for
// the run (the caller retains ownership), but the next model_turn must record
// SourcePickerDegraded.
type PickerResult struct {
	Degraded bool
}

// heldNotice collects the notices one picker-selection run produces so they reach
// the sink as a single line: a sink keeps only the last line it is given, so two
// separate calls would show the user only the second.
type heldNotice struct{ line string }

func (h *heldNotice) Notice(text string) { h.append(text) }

func (h *heldNotice) append(text string) {
	if h.line == "" {
		h.line = text
		return
	}
	h.line += "; " + text
}

func (h *heldNotice) flush(ui tui.NoticeRenderer) {
	if h.line == "" {
		return
	}
	ui.Notice(h.line)
	h.line = ""
}

// PersistPickerSelection runs the picker-selection persistence sequence for
// sel. It appends model_changed, flushes the session at the durability
// point — routing any flush write failure through the write-failure protocol — and then
// writes model.active to <projectRoot>/.codemeld/settings.local.yaml, rendering the
// ignore notice through ui when that write creates the file. Every notice one run
// produces reaches ui as a single composed line. On a model.active
// failure it emits model_persist_failed, renders the one-line notice via
// ui, and returns a degraded result, leaving the in-memory selection with the
// caller so it stays active for the run. Only after model.active succeeds does it
// mirror the selection to the global model.last_used file; a mirror failure emits
// model_global_mirror_failed silently, with no user-facing notice (step 2).
//
// prior is the selection active before this pick (nil on the run's first pick).
// projectRoot and home are the snapshotted write-target roots. ui receives the
// user-facing notices. PersistPickerSelection returns a non-nil error for an
// internal failure to append an event, to record an atomic-write failure, or when
// the flush itself fails without producing a write reason (a cancelled
// run context or a marshal failure) — in that last case it returns before any
// settings write or source transition so the selection is retained for a retry. It
// never returns an error for the persistence failures themselves, which are
// surfaced through events, notices, and (for model.active) the degraded result.
func PersistPickerSelection(ctx context.Context, store *sessions.Store, ui tui.NoticeRenderer, sel Selection, prior *Selection, projectRoot, home string) (PickerResult, error) {
	// Record the change, then flush for durability. model_changed is
	// always appended before the flush and before any settings write.
	if err := EmitModelChanged(store, sel, prior); err != nil {
		return PickerResult{}, err
	}
	held := &heldNotice{}
	if cat, reason, ferr := store.Flush(ctx); ferr != nil {
		// A non-write flush failure (reason == ReasonNone: the run context was already
		// cancelled, or the session failed to marshal) cannot be encoded as
		// session_write_failed and leaves model_changed non-durable, so return it before
		// any settings write or source transition — the selection stays in memory and
		// the input is retained for a retry past the durability boundary. Only
		// a real atomic-write failure carries a write reason; it routes through the
		// write-failure protocol and the sequence continues to the settings write.
		if reason == sessions.ReasonNone {
			return PickerResult{}, ferr
		}
		if herr := sessionfailures.HandleWriteFailure(reason, cat, store.Path(), ferr, store, held); herr != nil {
			return PickerResult{}, herr
		}
	}

	// Per-project model.active write (step 1).
	activePath, created, areason, aerrCat, awerr := WriteActive(projectRoot, sel)
	if awerr != nil {
		if eerr := EmitModelPersistFailed(store, activePath, sel, areason, aerrCat, awerr); eerr != nil {
			return PickerResult{}, eerr
		}
		held.append(tui.RenderPersistFailureNotice(activePath, string(areason), aerrCat))
		held.flush(ui)
		return PickerResult{Degraded: true}, nil
	}
	if created {
		held.append(tui.RenderLocalSettingsIgnoreNotice(config.LocalSettingsPath(projectRoot), config.LocalSettingsLockPath(projectRoot)))
	}
	held.flush(ui)

	// Global mirror to model.last_used (step 2) — attempted only after the
	// active write succeeds; a failure is recorded but silent to the user.
	lastUsedPath, lreason, lerrCat, lwerr := WriteLastUsed(home, sel)
	if lwerr != nil {
		if eerr := EmitModelGlobalMirrorFailed(store, lastUsedPath, sel, lreason, lerrCat, lwerr); eerr != nil {
			return PickerResult{}, eerr
		}
	}
	return PickerResult{}, nil
}
