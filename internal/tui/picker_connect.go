// /connect provider picker overlay: lists connectable providers and confirms one into the direct connect flow.
package tui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const connectPickerPage = "connect-picker"

type connectPickerSession struct {
	options  []ConnectProviderOption
	list     *tview.List
	onSelect func(id string)
}

// OpenConnectPicker opens the provider picker for a bare /connect command. It is a
// no-op while another overlay is open or when there are no rows to show. Selecting a
// provider calls onSelect with the provider id after the overlay is dismissed.
func (a *App) OpenConnectPicker(options []ConnectProviderOption, onSelect func(id string)) {
	a.openConnectPicker(options, onSelect)
}

func (a *App) openConnectPicker(options []ConnectProviderOption, onSelect func(id string)) {
	if a.anyOverlayOpen() || len(options) == 0 || onSelect == nil {
		return
	}
	cp := &connectPickerSession{options: append([]ConnectProviderOption(nil), options...), onSelect: onSelect}
	a.connectPicker = cp
	a.connectPickerOpen = true
	a.connectPickerPrev = a.app.GetFocus()

	body, list := a.buildConnectPicker(cp.options)
	cp.list = list
	a.pages.AddPage(connectPickerPage, wrapOverlayPage(centeredModal(body)), true, true)
	a.app.SetFocus(list)
}

func (a *App) buildConnectPicker(options []ConnectProviderOption) (tview.Primitive, *tview.List) {
	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	for _, option := range options {
		list.AddItem(option.Label, "", 0, nil)
	}
	list.SetSelectedFunc(func(index int, _ string, _ string, _ rune) {
		if index < 0 || index >= len(options) {
			return
		}
		a.confirmConnectProvider(options[index].ID)
	})
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			a.dismissConnectPicker()
			return nil
		}
		return ev
	})

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(list, len(options), 0, true)
	body.SetBorder(true)
	body.SetTitle(" connect provider ")
	return body, list
}

func (a *App) confirmConnectProvider(id string) {
	cp := a.connectPicker
	if cp == nil || cp.onSelect == nil {
		return
	}
	onSelect := cp.onSelect
	a.dismissConnectPicker()
	onSelect(id)
}

func (a *App) dismissConnectPicker() {
	if !a.connectPickerOpen {
		return
	}
	a.connectPickerOpen = false
	a.connectPicker = nil
	a.closeOverlayPage(connectPickerPage, &a.connectPickerPrev)
}

// ConnectPickerOpen reports whether the connect provider picker is currently mounted.
// It is a cross-package test seam for production /connect wiring.
func (a *App) ConnectPickerOpen() bool { return a.connectPickerOpen }

// ConnectPickerRows returns the currently mounted connect picker rows, or nil when the
// picker is closed. It is a cross-package test seam for production /connect wiring.
func (a *App) ConnectPickerRows() []ConnectProviderOption {
	if a.connectPicker == nil {
		return nil
	}
	return append([]ConnectProviderOption(nil), a.connectPicker.options...)
}

// SelectConnectProviderForTest confirms the currently mounted provider row with id.
// It is a cross-package test seam for production /connect wiring.
func (a *App) SelectConnectProviderForTest(id string) bool {
	cp := a.connectPicker
	if cp == nil {
		return false
	}
	for _, option := range cp.options {
		if option.ID == id {
			a.confirmConnectProvider(id)
			return true
		}
	}
	return false
}
