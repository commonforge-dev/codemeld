package tui

import (
	"fmt"
	"slices"
	"strings"
)

// noModelSelectedNotice is the one-line TUI error shown when /effort runs before
// a model has been selected in this run. It doubles as the
// slash_command.error_detail for that path.
const noModelSelectedNotice = "no model selected; pick one via Ctrl-M first"

// effortNoReasoning mirrors provider.EffortNoReasoning: internal/tui cannot import
// internal/provider, because internal/model imports internal/tui for the
// persist-failure notice and the reverse edge would be an import cycle. It is
// Codemeld's own choice, distinct from a provider's literal `default` token.
const effortNoReasoning = "no-reasoning"

// The preference order /model falls back through when it must pick an effort the
// newly selected model supports. It is not effort vocabulary: /effort and the
// CTRL-E picker validate against the provider-advertised set instead.
var req510Efforts = []string{"none", "minimal", "low", "medium", "high", "xhigh", "default"}

// EffortModel is the in-memory active-model surface /effort reads. It mirrors the
// run-scoped active state and provider effort catalog without internal/tui
// importing internal/model or internal/provider, which would re-introduce the
// model→tui import cycle. The production implementation wraps *model.ActiveState
// and the run-scoped provider catalog lookup. This seam is deliberate rather than
// removable indirection: collapsing it into the concrete model read would pull
// internal/model and internal/provider into internal/tui, breaching the package
// boundary the interface exists to hold.
type EffortModel interface {
	// ActiveSelection returns the current provider, model id, and effort, and
	// whether a model is selected in memory. /effort refuses when ok is false.
	ActiveSelection() (provider, modelID, effort string, ok bool)
	// SupportedEfforts returns cached efforts, or only effortNoReasoning when
	// capability metadata is absent.
	SupportedEfforts(provider, modelID string) []string
}

// EffortApplier runs the persistence/event transaction for a new effort
// on the current provider/model and updates the run's model_turn source. The
// production implementation lives outside internal/tui so it can call
// model.PersistPickerSelection and model.ActiveState.ApplyUserSelection without
// the import cycle. /effort calls Apply only after validation passes. This seam is
// deliberate rather than removable indirection: collapsing the durable settings
// write, provider lookup, and session-failure events it reaches into internal/tui
// would breach the package boundary the interface holds.
type EffortApplier interface {
	// Apply persists level as model.active.effort — append
	// model_changed (only new_effort differing), flush, write
	// model.active via the shared persistence function, then mirror
	// model.last_used only after the active write succeeds — emitting
	// model_persist_failed / model_global_mirror_failed and the
	// persist-failure notice as prescribed, and setting the next model_turn source
	// to picker or picker_degraded (ending any resume carve-out). A
	// non-nil error is reserved for an internal append/flush failure the handler
	// must surface; persistence failures are not reported as errors here.
	Apply(level string) (EffortApplyResult, error)
}

// EffortApplyResult: MarkerCreated is true only under launch-dir-only mode when
// the model.active write created the launch directory's .codemeld/settings.yaml that did not exist
// before; MarkerPath is that file's absolute path, named in the cross-mode marker
// disclosure. The persist-failure notice and the
// source-state update are already handled inside Apply.
type EffortApplyResult struct {
	MarkerCreated bool
	MarkerPath    string
}

// EffortDeps gathers the injectable capabilities NewEffortHandler closes over, so
// the handler can be driven end-to-end with fakes (mirroring ClearDeps); the
// production wiring supplies the implementations bound to the running app +
// bootstrap result. It stays the single bundle shared by /effort and the CTRL-E
// effort picker (installed once via App.SetEffortDeps) rather than giving each
// surface its own apply path, so the command and the picker cannot drift apart.
type EffortDeps struct {
	Model   EffortModel
	Applier EffortApplier
	// OpenPicker, when non-nil, opens the effort picker for a bare (zero-argument)
	// /effort — the same overlay CTRL-E opens, wired in production to
	// App.OpenEffortPicker. It carries the picker's own semantics (no-op while
	// another overlay is open, and the no-model-selected notice with no picker), so
	// the no-arg handler path delegates to it without recording a slash_command. nil
	// in unit tests and before the production wiring installs the opener, in which
	// case a bare /effort is inert (no panic, no event, no input retention).
	OpenPicker func()
	// Refresh, when non-nil, is called after a successful effort apply (both /effort
	// and the CTRL-E picker share this EffortDeps in production) so the persistent
	// status-line footer live-updates to the new effort. It is not called on
	// validation failures or apply errors. nil in unit tests and before the production
	// wiring installs App.RefreshStatusLine.
	Refresh func()
}

func NewEffortHandler(deps EffortDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		// Dispatch enforces ArgOneOptional, so there are zero or one arguments. A
		// bare /effort opens the picker (the same overlay CTRL-E opens) and records
		// no slash_command — matching the CTRL-E key path, which never appends a
		// slash_command. A nil opener leaves the path inert: no panic, no
		// event, no input retention. The picker opener owns the no-model-selected
		// notice, so the handler does not duplicate it here.
		if len(args) == 0 {
			if deps.OpenPicker != nil {
				deps.OpenPicker()
			}
			return nil
		}
		level := args[0]

		provider, modelID, _, ok := deps.Model.ActiveSelection()
		if !ok {
			return rejectEffort(ctx, noModelSelectedNotice)
		}

		supported := deps.Model.SupportedEfforts(provider, modelID)
		if !effortValid(level, supported) {
			return rejectEffort(ctx, unsupportedEffortNotice(level, supported))
		}

		// The command is recognized and the value is valid, so it succeeds as a
		// command regardless of whether persistence later degrades to
		// session-only. Recording slash_command before the apply mirrors /status's
		// append-then-act ordering; only pins model_changed (appended inside
		// Apply) ahead of the persist-failure events, which Apply preserves.
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		if _, err := deps.Applier.Apply(level); err != nil {
			return err
		}
		// Live-update the persistent status-line footer to the new effort
		// only after the apply succeeded — never on the validation/error paths above.
		if deps.Refresh != nil {
			deps.Refresh()
		}
		return nil
	}
}

// rejectEffort renders the one-line TUI error, retains the typed input so the
// user can edit and retry, records the recognized command with outcome:error
// carrying the same text as error_detail, and flushes that
// record so the error event is durable before the handler returns.
// Validation rejects before the apply transaction, so there is no later
// flush to make the event durable; a crash or exit after the rejection would
// otherwise lose it.
func rejectEffort(ctx CommandContext, notice string) error {
	ctx.Notice(notice)
	ctx.RetainInput()
	if err := ctx.AppendSlashCommand(OutcomeError, notice); err != nil {
		return err
	}
	return ctx.FlushActive()
}

func effortValid(level string, supported []string) bool {
	return level == effortNoReasoning || slices.Contains(supported, level)
}

// unsupportedEffortNotice renders the pinned one-line error for a level the
// active model does not support: "unsupported effort <supplied>
// supported efforts: <comma-separated supported set>". The supported set is
// rendered in the order SupportedEfforts returned it.
func unsupportedEffortNotice(level string, supported []string) string {
	return fmt.Sprintf("unsupported effort %s; supported efforts: %s", level, strings.Join(supported, ", "))
}

// RenderCrossModeMarkerNotice returns the one-line cross-mode marker disclosure
// (reused by /model and the permission-prompt folder option).
// Under launch-dir-only mode, when a write creates a
// .codemeld/settings.yaml that did not exist before, this warns that the file
// will mark the launch directory as a project root if discovery.boundary is
// later set to project-root. It names the absolute path so callers do not
// reinvent the wording.
func RenderCrossModeMarkerNotice(path string) string {
	return "created " + path + " — this file will mark the launch directory as a project root " +
		"if discovery.boundary is later set to project-root"
}
