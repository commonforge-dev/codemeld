// Production implementations of tui.EffortModel and tui.EffortApplier, plus
// the shared picker-apply transaction reused by the /model applier. They
// live in internal/bootstrap because internal/tui cannot import internal/model or
// internal/provider (the model -> tui persist-notice edge makes the reverse a
// cycle).
package bootstrap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// effortModel is the production tui.EffortModel over the run-scoped active model
// state and the provider effort catalog. It is also embedded
// by modelCatalog so /model inherits the same active-selection and supported-effort
// reads.
type effortModel struct {
	active *model.ActiveState
	cache  *config.Cache
}

// ActiveSelection reports the current provider/model/effort and whether a model is
// selected; /effort and /model refuse when ok is false.
func (m effortModel) ActiveSelection() (provider, modelID, effort string, ok bool) {
	sel, _, selected := m.active.Current()
	if !selected {
		return "", "", "", false
	}
	return sel.Provider, sel.ID, sel.Effort, true
}

func (m effortModel) SupportedEfforts(providerName, modelID string) []string {
	if m.cache == nil {
		return provider.Catalog{}.SupportedEffort(providerName, modelID)
	}
	return m.cache.SelectableCatalog().SupportedEffort(providerName, modelID)
}

// pickerApply runs the shared picker-apply transaction used by both the
// /effort and /model production appliers. It is the single place that composes
// model.PersistPickerSelection (which itself appends model_changed, flushes at the
// point, writes model.active, then mirrors model.last_used — in that
// order) with model.ActiveState.ApplyUserSelection (which sets the next
// model_turn source to picker / picker_degraded). It must not call WriteActive /
// WriteLastUsed directly: PersistPickerSelection already wraps them, so layering
// them on top would double-write the settings files and reorder the events.
type pickerApply struct {
	active        *model.ActiveState
	ui            tui.NoticeRenderer
	store         func() *sessions.Store
	ctx           context.Context
	projectRoot   string
	home          string
	launchDirOnly bool
}

// apply persists newSel (prior is the selection it replaces) through the
// transaction and records the resulting picker/picker_degraded source. It is the
// concrete-prior entry point for /effort and /model, which always replace an
// existing selection; the model picker's first-pick path uses applySelection with
// a nil prior. It returns whether the per-project model.active write created a
// launch-directory marker file that did not exist before, which the cross-mode
// disclosure surfaces only under launch-dir-only mode. A
// non-nil error is reserved for an internal append/flush failure; persistence
// failures are surfaced through events and notices inside PersistPickerSelection,
// not as errors here.
func (p pickerApply) apply(newSel, prior model.Selection) (markerCreated bool, markerPath string, err error) {
	return p.applySelection(newSel, &prior)
}

// applySelection is the shared transaction body over a nullable prior. A
// nil prior is the run's first pick (no prior selection), so model_changed omits
// the prior fields per EmitModelChanged's all-present-or-all-absent rule; a
// non-nil prior is the selection newSel replaces. The model picker passes nil when
// ActiveState.Current reports no selection (first-pick path); /effort and
// /model always pass a concrete prior through apply.
func (p pickerApply) applySelection(newSel model.Selection, prior *model.Selection) (markerCreated bool, markerPath string, err error) {
	target := filepath.Join(p.projectRoot, ".codemeld", "settings.yaml")
	_, statErr := os.Stat(target)
	existedBefore := statErr == nil

	res, err := model.PersistPickerSelection(p.ctx, p.store(), p.ui, newSel, prior, p.projectRoot, p.home)
	if err != nil {
		return false, "", err
	}
	p.active.ApplyUserSelection(newSel, res.Degraded)

	// The cross-mode marker disclosure applies only under launch-dir-only mode,
	// where the per-project write lands in the launch directory and would mark it
	// as a project root if discovery.boundary later flips to project-root. A
	// degraded (failed) active write created nothing to disclose.
	if p.launchDirOnly && !res.Degraded && !existedBefore {
		if _, err := os.Stat(target); err == nil {
			return true, target, nil
		}
	}
	return false, "", nil
}

// effortApplier is the production tui.EffortApplier. Apply changes only the effort
// on the current provider/model and runs the shared transaction.
type effortApplier struct{ pickerApply }

// Apply persists level as the active model's effort. The handler only
// calls it after ActiveSelection reported a selection, so a missing selection here
// is a wiring bug surfaced as an error rather than a silent no-op.
func (a effortApplier) Apply(level string) (tui.EffortApplyResult, error) {
	sel, _, ok := a.active.Current()
	if !ok {
		return tui.EffortApplyResult{}, fmt.Errorf("bootstrap: /effort apply with no active model selection")
	}
	newSel := model.Selection{Provider: sel.Provider, ID: sel.ID, Effort: level}
	created, path, err := a.apply(newSel, sel)
	if err != nil {
		return tui.EffortApplyResult{}, err
	}
	return tui.EffortApplyResult{MarkerCreated: created, MarkerPath: path}, nil
}
