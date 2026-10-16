// Initialization, read, user-pick, resume-switch, and /clear carry-forward coverage for ActiveState.
package model

import (
	"testing"

	"codemeld.dev/codemeld/internal/tui"
)

// ActiveState must satisfy the /clear handler's tui.ModelState contract so the TUI launch
// can wire it as the production CarryForward target without an adapter.
var _ tui.ModelState = (*ActiveState)(nil)

// sampleSelection (defined in persist_test.go) and altSelection are two distinct
// selections so source transitions and replacements are observable.
func altSelection() Selection {
	return Selection{Provider: "openai", ID: "gpt-5.5-pro", Effort: "low"}
}

// Done-when: initialization preserves project, global_fallback, and resume
// sources from DetermineSelection.
func TestNewActiveState_PreservesLaunchSources(t *testing.T) {
	sel := sampleSelection()
	for _, src := range []Source{SourceProject, SourceGlobalFallback, SourceResume} {
		t.Run(string(src), func(t *testing.T) {
			st := NewActiveState(&sel, src)
			got, gotSrc, ok := st.Current()
			if !ok {
				t.Fatalf("Current() ok = false, want true")
			}
			if got != sel {
				t.Errorf("Current() selection = %+v, want %+v", got, sel)
			}
			if gotSrc != src {
				t.Errorf("Current() source = %q, want %q", gotSrc, src)
			}
		})
	}
}

// Done-when: a nil launch/resume selection is represented as no active selection
// and is observable by callers.
func TestNewActiveState_NilSelectionHasNoActive(t *testing.T) {
	st := NewActiveState(nil, SourcePicker)
	if sel, src, ok := st.Current(); ok {
		t.Fatalf("Current() = (%+v, %q, true), want ok=false for nil launch selection", sel, src)
	}
}

// Done-when: a user-applied selection sets the subsequent source to picker on
// clean persistence and picker_degraded on active-write failure while retaining
// the new selection in both cases.
func TestApplyUserSelection_SourceAndRetention(t *testing.T) {
	sel := altSelection()
	tests := []struct {
		name     string
		degraded bool
		want     Source
	}{
		{"clean", false, SourcePicker},
		{"degraded", true, SourcePickerDegraded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := NewActiveState(nil, SourcePicker) // start with no selection
			st.ApplyUserSelection(sel, tt.degraded)
			got, gotSrc, ok := st.Current()
			if !ok {
				t.Fatalf("Current() ok = false, want true")
			}
			if got != sel {
				t.Errorf("selection = %+v, want %+v", got, sel)
			}
			if gotSrc != tt.want {
				t.Errorf("source = %q, want %q", gotSrc, tt.want)
			}
		})
	}
}

// Done-when: a user-applied selection after resume no longer reports source
// resume.
func TestApplyUserSelection_EndsResumeCarveOut(t *testing.T) {
	resumeSel := sampleSelection()
	st := NewActiveState(&resumeSel, SourceResume)

	newSel := altSelection()
	st.ApplyUserSelection(newSel, false)

	got, gotSrc, _ := st.Current()
	if gotSrc == SourceResume {
		t.Errorf("source = %q, want non-resume after user pick", gotSrc)
	}
	if gotSrc != SourcePicker {
		t.Errorf("source = %q, want %q", gotSrc, SourcePicker)
	}
	if got != newSel {
		t.Errorf("selection = %+v, want %+v", got, newSel)
	}
}

// Done-when: resume switch can replace the selection/source or clear it on
// recovery failure.
func TestApplyResumeSwitch_ReplaceAndClear(t *testing.T) {
	start := sampleSelection()
	st := NewActiveState(&start, SourcePicker)

	// Successful recovery replaces selection + source.
	recovered := altSelection()
	st.ApplyResumeSwitch(&recovered, SourceResume)
	got, gotSrc, ok := st.Current()
	if !ok || got != recovered || gotSrc != SourceResume {
		t.Fatalf("after replace: Current() = (%+v, %q, %v), want (%+v, %q, true)",
			got, gotSrc, ok, recovered, SourceResume)
	}

	// Recovery failure clears the selection so the picker must open.
	st.ApplyResumeSwitch(nil, SourcePicker)
	if sel, src, ok := st.Current(); ok {
		t.Errorf("after clear: Current() = (%+v, %q, true), want ok=false", sel, src)
	}
}

// Done-when: /clear carry-forward preserves the current selection/source and is
// safe when no selection exists.
func TestCarryForward_PreservesSelectionAndSafeWhenEmpty(t *testing.T) {
	sel := sampleSelection()
	st := NewActiveState(&sel, SourceProject)
	st.CarryForward()
	got, gotSrc, ok := st.Current()
	if !ok || got != sel || gotSrc != SourceProject {
		t.Errorf("after CarryForward: Current() = (%+v, %q, %v), want (%+v, %q, true)",
			got, gotSrc, ok, sel, SourceProject)
	}

	// Safe with no active selection: no panic, still observably unselected.
	empty := NewActiveState(nil, SourcePicker)
	empty.CarryForward()
	if s, src, ok := empty.Current(); ok {
		t.Errorf("empty CarryForward: Current() = (%+v, %q, true), want ok=false", s, src)
	}
}
