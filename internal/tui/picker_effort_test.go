package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestEffortPickerInitialIndex(t *testing.T) {
	cases := []struct {
		name    string
		rows    []string
		current string
		want    int
	}{
		{"current in set", []string{"minimal", "low", "medium", "high"}, "medium", 2},
		{"current first", []string{"minimal", "low", "medium", "high"}, "minimal", 0},
		{"fallback to first row", []string{"low", "high"}, "medium", 0},
		{"fallback with no earlier match", []string{"medium", "high"}, "minimal", 0},
		{"no-reasoning-only current sentinel", []string{"no-reasoning"}, "no-reasoning", 0},
		{"empty current falls back", []string{"low", "medium"}, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effortPickerInitialIndex(tc.rows, tc.current); got != tc.want {
				t.Errorf("effortPickerInitialIndex(%v, %q) = %d, want %d", tc.rows, tc.current, got, tc.want)
			}
		})
	}
}

func TestEffortPickerRows(t *testing.T) {
	cases := []struct {
		name      string
		supported []string
		want      []string
	}{
		{"advertised order preserved", []string{"ultra", "max", "low"}, []string{"no-reasoning", "ultra", "max", "low"}},
		{"literal default stays a separate row", []string{"default"}, []string{"no-reasoning", "default"}},
		{"no-capability model", []string{"no-reasoning"}, []string{"no-reasoning"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effortPickerRows(tc.supported); !equalStrings(got, tc.want) {
				t.Errorf("effortPickerRows(%v) = %v, want %v", tc.supported, got, tc.want)
			}
		})
	}
}

func TestEffortPicker_BuildListsAdvertisedSetInOrder(t *testing.T) {
	a := New(nil)
	rows := effortPickerRows([]string{"minimal", "low", "medium", "high"})
	_, list := a.buildEffortPicker(rows, effortPickerInitialIndex(rows, "medium"), "medium")

	want := []string{"no-reasoning", "minimal", "low", "medium", "high"}
	if got := list.GetItemCount(); got != len(want) {
		t.Fatalf("list item count = %d, want %d", got, len(want))
	}
	for i, w := range want {
		if got, _ := list.GetItemText(i); got != w {
			t.Errorf("row %d = %q, want %q", i, got, w)
		}
	}
	if got := list.GetCurrentItem(); got != 3 {
		t.Errorf("initial highlight = %d, want 3 (current effort medium)", got)
	}
}

// TestEffortPicker_SelectedRowRendersReverseVideo pins step 2 for the shared list
// picker helper (applyPickerListColors): the highlighted row renders with reverse
// video and no fixed yellow color. The effort, resume, and permission-prompt
// pickers all route their list styling through this one helper, so pinning it here
// covers their selected-row appearance too.
func TestEffortPicker_SelectedRowRendersReverseVideo(t *testing.T) {
	a := New(nil)
	supported := []string{"minimal", "low", "medium", "high"}
	_, list := a.buildEffortPicker(supported, effortPickerInitialIndex(supported, "medium"), "medium")

	screen := drawPrimitive(t, list, 40, 10)
	reverseByRow := findReverseVideoRows(t, screen)

	found := false
	for _, text := range reverseByRow {
		if strings.Contains(text, "medium") {
			found = true
		}
	}
	if !found {
		t.Errorf("no reverse-video row carries the selected effort medium; reverse rows = %v", reverseByRow)
	}
}

func openedEffortPickerRows(t *testing.T, supported []string, current string) []string {
	t.Helper()
	a := New(nil)
	model := selectedModel()
	model.effort = current
	model.supported = supported
	a.SetEffortDeps(EffortDeps{Model: model, Applier: &effortApplierFake{}})

	a.openEffortPicker()
	if !a.effortPickerOpen {
		t.Fatalf("picker did not open for supported=%v", supported)
	}
	list, ok := a.app.GetFocus().(*tview.List)
	if !ok {
		t.Fatalf("focused primitive = %T, want the picker's *tview.List", a.app.GetFocus())
	}
	rows := make([]string, 0, list.GetItemCount())
	for i := 0; i < list.GetItemCount(); i++ {
		text, _ := list.GetItemText(i)
		rows = append(rows, text)
	}
	return rows
}

func TestEffortPicker_NoCapabilityModelShowsOnlyNoReasoning(t *testing.T) {
	got := openedEffortPickerRows(t, []string{"no-reasoning"}, "no-reasoning")
	if !equalStrings(got, []string{"no-reasoning"}) {
		t.Errorf("rows = %v, want [no-reasoning] for a model with no advertised capability", got)
	}
}

func TestEffortPicker_LiteralDefaultIsSeparateFromNoReasoning(t *testing.T) {
	got := openedEffortPickerRows(t, []string{"default", "max"}, "default")
	if !equalStrings(got, []string{"no-reasoning", "default", "max"}) {
		t.Errorf("rows = %v, want [no-reasoning default max]", got)
	}
}

func TestEffortPicker_OpenPreservesAdvertisedOrder(t *testing.T) {
	got := openedEffortPickerRows(t, []string{"ultra", "max", "low"}, "max")
	if !equalStrings(got, []string{"no-reasoning", "ultra", "max", "low"}) {
		t.Errorf("rows = %v, want the advertised order [ultra max low] after the sentinel", got)
	}
}

func TestEffortPicker_NoOpWhileOverlayOpen(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	a.statusOpen = true // another overlay holds the screen
	a.openEffortPicker()

	if a.effortPickerOpen {
		t.Error("effortPickerOpen = true; CTRL-E must be a no-op while another overlay is open")
	}
	if a.pages.HasPage(effortPickerPage) {
		t.Error("effort picker page mounted while another overlay is open")
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times, want 0", applier.calls)
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want none", a.transcript.notice)
	}
}

func TestEffortPicker_NoSelectionRendersNoticeAndOpensNothing(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: &effortModelFake{selected: false}, Applier: applier})

	a.openEffortPicker()

	if a.effortPickerOpen || a.pages.HasPage(effortPickerPage) {
		t.Error("picker opened despite no in-memory model selection")
	}
	if a.transcript.notice != noModelSelectedNotice {
		t.Errorf("notice = %q, want %q", a.transcript.notice, noModelSelectedNotice)
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times on the no-selection path, want 0", applier.calls)
	}
	// The picker never touches the active session store, so no slash_command can
	// be emitted on this path; Store() is the only seam to the record stream and
	// the picker never reads it.
	if a.Store() != nil {
		t.Error("test premise broken: no active store should be installed")
	}
}

func TestEffortPicker_UnwiredCtrlEIsInert(t *testing.T) {
	a := New(nil) // no EffortDeps wired
	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlE, 0, tcell.ModNone)); ev != nil {
		t.Errorf("handleGlobalKey returned %v for CTRL-E, want nil (consumed)", ev)
	}
	if a.effortPickerOpen {
		t.Error("picker opened with no effort surface wired")
	}
}

// TestEffortPicker_CtrlTNoLongerOpensPicker pins the effort shortcut move: CTRL-T is
// no longer the effort shortcut, so even with the deps wired it neither opens the
// picker nor is consumed — it passes through to the focused primitive.
func TestEffortPicker_CtrlTNoLongerOpensPicker(t *testing.T) {
	a := New(nil)
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}})
	in := tcell.NewEventKey(tcell.KeyCtrlT, 0, tcell.ModNone)
	if ev := a.handleGlobalKey(in); ev != in {
		t.Errorf("handleGlobalKey consumed CTRL-T (got %v); it must pass through now that CTRL-E owns the effort picker", ev)
	}
	if a.effortPickerOpen {
		t.Error("CTRL-T opened the effort picker; only CTRL-E may open it after f200")
	}
}

func TestEffortPicker_HandleGlobalKeyPassesOtherKeys(t *testing.T) {
	a := New(nil)
	in := tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone)
	if ev := a.handleGlobalKey(in); ev != in {
		t.Errorf("handleGlobalKey altered a non-CTRL-E key; got %v, want pass-through", ev)
	}
}

func TestEffortPicker_ConfirmAppliesChangedLevel(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	// current effort is "medium"; selecting "high" is a real change.
	a.confirmEffortSelection("high", "medium", false)

	if applier.calls != 1 || applier.gotLvl != "high" {
		t.Errorf("Apply calls=%d level=%q, want 1 call with %q", applier.calls, applier.gotLvl, "high")
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want none on a clean apply", a.transcript.notice)
	}
}

func TestEffortPicker_ConfirmCurrentLevelOnMultiEffortStillApplies(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	// Re-selecting the configured effort on a multi-effort model is NOT inert: it
	// must run the same shared apply path as /effort. Apply persists model.active
	// and ends any resume carve-out (model_turn source resume -> picker) even when
	// the effort does not change and no model_changed is appended (Done-when
	// "selection applies via same path as /effort"). Only the {default}-only row is
	// inert, asserted separately.
	a.confirmEffortSelection("medium", "medium", false)

	if applier.calls != 1 || applier.gotLvl != "medium" {
		t.Errorf("Apply calls=%d level=%q, want 1 call with %q (current level still applies)", applier.calls, applier.gotLvl, "medium")
	}
}

func TestEffortPicker_NoReasoningOnlyRowSelectableButInert(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	a.confirmEffortSelection("no-reasoning", "no-reasoning", true)

	if applier.calls != 0 {
		t.Errorf("Apply called %d times selecting the inert no-reasoning row, want 0", applier.calls)
	}
}

func TestEffortPicker_LiteralDefaultRowAlwaysApplies(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	a.confirmEffortSelection("default", "default", false)

	if applier.calls != 1 || applier.gotLvl != "default" {
		t.Errorf("Apply calls=%d level=%q, want 1 call with %q", applier.calls, applier.gotLvl, "default")
	}
}

func TestEffortPicker_ConfirmEmitsNoCrossModeMarkerNotice(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{result: EffortApplyResult{MarkerCreated: true, MarkerPath: "/work/proj/.codemeld/settings.yaml"}}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	a.confirmEffortSelection("high", "medium", false)

	if applier.calls != 1 {
		t.Fatalf("Apply calls = %d, want 1", applier.calls)
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want no project-root-marker notice", a.transcript.notice)
	}
	if got := a.TranscriptText(); strings.Contains(got, "/work/proj/.codemeld/settings.yaml") {
		t.Errorf("transcript = %q, want no project-root-marker line", got)
	}
}

func TestEffortPicker_ConfirmApplyErrorSurfaced(t *testing.T) {
	a := New(nil)
	wantErr := errors.New("append model_changed: boom")
	applier := &effortApplierFake{err: wantErr}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	a.confirmEffortSelection("high", "medium", false)

	if a.transcript.notice != wantErr.Error() {
		t.Errorf("notice = %q, want the surfaced apply error %q", a.transcript.notice, wantErr.Error())
	}
}

func TestEffortPicker_DismissRestoresCapturedFocus(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})
	before := tview.NewBox()
	a.app.SetFocus(before)

	a.openEffortPicker()
	if !a.effortPickerOpen {
		t.Fatal("effort picker did not open")
	}
	if a.effortPickerPrev != before {
		t.Fatalf("captured prior focus = %T, want the primitive focused at open", a.effortPickerPrev)
	}

	a.dismissEffortPicker()

	if a.effortPickerOpen || a.pages.HasPage(effortPickerPage) {
		t.Error("effort picker still mounted after dismissal")
	}
	if a.app.GetFocus() != before {
		t.Errorf("focus = %T, want the primitive focused before the picker opened", a.app.GetFocus())
	}
	if a.effortPickerPrev != nil {
		t.Error("prior focus not cleared after dismissal")
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times on dismissal, want 0", applier.calls)
	}
}

func TestEffortPicker_RepeatedDismissIsInert(t *testing.T) {
	a := New(nil)
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}})
	a.openEffortPicker()
	a.dismissEffortPicker()

	elsewhere := tview.NewBox()
	a.app.SetFocus(elsewhere)

	a.dismissEffortPicker()

	if a.app.GetFocus() != elsewhere {
		t.Errorf("focus after a second dismissal = %T, want it left where it was", a.app.GetFocus())
	}
	if a.effortPickerOpen || a.pages.HasPage(effortPickerPage) {
		t.Error("picker re-mounted by a second dismissal")
	}
}

// TestEffortPicker_CtrlEOpenEnterApplyEscDismiss drives the live key bindings
// over a simulation screen: CTRL-E opens the picker, ESC dismisses it with no
// apply, and a re-opened picker applies the moved-to row on Enter through the
// EffortApplier (the non-slash path) — exercising the real app-level CTRL-E
// capture and the list's Enter/ESC handling.
func TestEffortPicker_CtrlEOpenEnterApplyEscDismiss(t *testing.T) {
	a := New(nil)
	applier := &effortApplierFake{}
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: applier})

	screen := tcell.NewSimulationScreen("UTF-8")
	a.app.SetScreen(screen)

	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	hasPicker := func() bool {
		open := false
		a.app.QueueUpdate(func() { open = a.pages.HasPage(effortPickerPage) })
		return open
	}
	waitPicker := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for hasPicker() != want {
			if time.Now().After(deadline) {
				a.app.Stop()
				t.Fatalf("effort picker page present=%v not reached within 2s", want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// CTRL-E opens the picker, then ESC dismisses it with no change.
	screen.InjectKey(tcell.KeyCtrlE, 0, tcell.ModNone)
	waitPicker(true)
	screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	waitPicker(false)
	if applier.calls != 0 {
		a.app.Stop()
		t.Fatalf("Apply called %d times after ESC dismissal, want 0", applier.calls)
	}

	screen.InjectKey(tcell.KeyCtrlE, 0, tcell.ModNone)
	waitPicker(true)
	screen.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
	screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPicker(false)

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
	if applier.calls != 1 || applier.gotLvl != "high" {
		t.Errorf("Apply calls=%d level=%q, want 1 call with %q", applier.calls, applier.gotLvl, "high")
	}
}
