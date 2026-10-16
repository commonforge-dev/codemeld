// Run-scoped holder for the active model Selection and the Source the next
// model_turn must record, with a distinct "no model selected yet" state.
package model

// ActiveState holds the run-scoped active model selection and the Source value
// the next model_turn must record. It is the single in-memory owner that
// /effort, /model, Ctrl-E, Ctrl-M, /resume, /clear, and the plain-prompt turn
// path all read and mutate, taking over from the run-start on-disk lookup once the
// run is underway. It represents "no model selected" distinctly from any
// selection so callers can refuse with "no model selected; pick one via Ctrl-M
// first" or route to the model picker.
//
// It is deliberately side-effect free: it performs no event append, flush,
// config write, validation, provider-catalog lookup, or TUI rendering. Callers
// own validation, notices, model_changed, WriteActive, and WriteLastUsed. The
// zero value is a valid "no model selected" state.
type ActiveState struct {
	sel      Selection
	source   Source
	selected bool
}

// NewActiveState builds the run's active-model state from a DetermineSelection
// result. A non-nil sel stores that selection together with the
// returned source (SourceProject, SourceGlobalFallback, or SourceResume). A nil
// sel — the path-4 picker-required outcome — yields a state with no
// active selection; source is ignored because no model_turn can run until the
// picker supplies one.
func NewActiveState(sel *Selection, source Source) *ActiveState {
	s := &ActiveState{}
	s.set(sel, source)
	return s
}

// set replaces the stored selection and source, or clears the selection when sel
// is nil. It is the shared core of launch initialization and in-TUI resume
// switching: a nil selection maps to "no active selection" and a non-nil one to a
// selected state carrying the given source.
func (s *ActiveState) set(sel *Selection, source Source) {
	if sel == nil {
		s.sel = Selection{}
		s.source = ""
		s.selected = false
		return
	}
	s.sel = *sel
	s.source = source
	s.selected = true
}

// Current returns the active selection and the Source to record on the next
// model_turn. ok is false when no model is selected yet — the caller must then
// refuse the turn or route to the model picker rather than starting a turn. The
// returned Selection and Source are zero values when ok is false.
func (s *ActiveState) Current() (sel Selection, source Source, ok bool) {
	if !s.selected {
		return Selection{}, "", false
	}
	return s.sel, s.source, true
}

// ApplyUserSelection records a user-applied selection from /effort, /model, or a
// picker after the apply path has run. The selection is always retained
// for the run, whether or not persistence degraded. The next model_turn source
// becomes SourcePicker on a clean per-project model.active write and
// SourcePickerDegraded when that write failed; degraded mirrors
// PickerResult.Degraded. This ends any prior SourceResume carry-over: once the
// user picks, the run no longer reports the resumed source.
func (s *ActiveState) ApplyUserSelection(sel Selection, degraded bool) {
	s.sel = sel
	s.selected = true
	if degraded {
		s.source = SourcePickerDegraded
		return
	}
	s.source = SourcePicker
}

// ApplyResumeSwitch updates the run state after an in-TUI /resume recovery
// attempt. A non-nil sel replaces the active selection and source with the
// recovered values; a nil sel clears the active selection so the caller opens the
// model picker (the path-4 outcome), leaving the run with no model until a
// pick lands.
func (s *ActiveState) ApplyResumeSwitch(sel *Selection, source Source) {
	s.set(sel, source)
}

// CarryForward carries the current selection and source unchanged across a /clear
// (alias /new) session switch, so the first model_turn in the fresh
// session reuses the prior source rather than re-running the on-disk
// lookup. It is intentionally a no-op on the stored values: it exists as the
// single canonical target for the production ModelState.CarryForward
// implementation and is safe to call when no model is selected.
func (s *ActiveState) CarryForward() {
	// No mutation: the stored selection and source already hold the values the new
	// session must reuse. Present so /clear has one canonical entry point.
}
