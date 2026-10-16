package tui

import (
	"slices"

	"github.com/rivo/tview"
)

// effortPickerPage is the Pages name the effort picker overlay is mounted under
// while open, removed when it dismisses.
const effortPickerPage = "effort-picker"

func (a *App) openEffortPicker() {
	if a.anyOverlayOpen() {
		return
	}
	if a.effortDeps.Model == nil {
		return
	}
	provider, modelID, effort, ok := a.effortDeps.Model.ActiveSelection()
	if !ok {
		a.Notice(noModelSelectedNotice)
		return
	}
	rows := effortPickerRows(a.effortDeps.Model.SupportedEfforts(provider, modelID))
	overlay, list := a.buildEffortPicker(rows, effortPickerInitialIndex(rows, effort), effort)
	a.effortPickerOpen = true
	a.effortPickerPrev = a.app.GetFocus()
	a.pages.AddPage(effortPickerPage, wrapOverlayPage(overlay), true, true)
	a.app.SetFocus(list)
}

// OpenEffortPicker opens the effort picker overlay from outside the
// global CTRL-E key path — the narrow seam a bare /effort drives through
// EffortDeps.OpenPicker so the command and the key share one picker. It delegates
// to openEffortPicker so the overlay-open / no-deps / no-model guards stay the
// single implementation, and is therefore inert until SetEffortDeps installs the
// deps, exactly like CTRL-E.
func (a *App) OpenEffortPicker() { a.openEffortPicker() }

// EffortPickerOpen reports whether the effort picker overlay is currently mounted.
// It mirrors ModelPickerOpen as the observable bootstrap's StartTUI assembly test
// reads to prove a bare /effort opened the picker through the wired
// EffortDeps.OpenPicker; production code drives the picker through the key/command
// paths and never needs to poll this.
func (a *App) EffortPickerOpen() bool { return a.effortPickerOpen }

func (a *App) buildEffortPicker(rows []string, initial int, current string) (tview.Primitive, *tview.List) {
	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	for _, e := range rows {
		list.AddItem(e, "", 0, nil)
	}
	if initial >= 0 && initial < len(rows) {
		list.SetCurrentItem(initial)
	}
	noReasoningOnly := isNoReasoningOnlySet(rows)
	list.SetSelectedFunc(func(index int, _ string, _ string, _ rune) {
		a.confirmEffortSelection(rows[index], current, noReasoningOnly)
	})

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(list, len(rows), 0, true)
	body.SetBorder(true)
	body.SetTitle(" reasoning effort ")
	return body, list
}

func (a *App) confirmEffortSelection(level, current string, noReasoningOnly bool) {
	a.dismissEffortPicker()
	if noReasoningOnly && level == current {
		return
	}
	if _, err := a.effortDeps.Applier.Apply(level); err != nil {
		a.Notice(err.Error())
		return
	}
	if a.effortDeps.Refresh != nil {
		a.effortDeps.Refresh()
	}
}

// dismissEffortPicker closes the picker overlay and restores focus to whatever
// held it when the picker opened. The input buffer is never touched, so
// anything typed before CTRL-E survives.
func (a *App) dismissEffortPicker() {
	if !a.effortPickerOpen {
		return
	}
	a.effortPickerOpen = false
	a.closeOverlayPage(effortPickerPage, &a.effortPickerPrev)
}

func effortPickerRows(supported []string) []string {
	if slices.Contains(supported, effortNoReasoning) {
		return slices.Clone(supported)
	}
	return append([]string{effortNoReasoning}, supported...)
}

func isNoReasoningOnlySet(rows []string) bool {
	return len(rows) == 1 && rows[0] == effortNoReasoning
}

func effortPickerInitialIndex(rows []string, current string) int {
	if i := slices.Index(rows, current); i >= 0 {
		return i
	}
	return 0
}
