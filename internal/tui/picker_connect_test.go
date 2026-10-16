// Tests for the /connect provider picker overlay: rows, selection, ESC dismissal, and no-side-effect cancel.
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestConnectPicker_OpenRowsAndSelect(t *testing.T) {
	a := New(nil)
	options := []ConnectProviderOption{{ID: "openai", Label: "OpenAI"}, {ID: "venice", Label: "Venice"}}
	selected := ""

	a.OpenConnectPicker(options, func(id string) { selected = id })

	if !a.connectPickerOpen || !a.pages.HasPage(connectPickerPage) {
		t.Fatal("connect picker did not open")
	}
	if a.connectPicker == nil || a.connectPicker.list == nil {
		t.Fatal("connect picker session/list missing")
	}
	if got := a.connectPicker.list.GetItemCount(); got != len(options) {
		t.Fatalf("row count = %d, want %d", got, len(options))
	}
	for i, want := range []string{"OpenAI", "Venice"} {
		if got, _ := a.connectPicker.list.GetItemText(i); got != want {
			t.Errorf("row %d = %q, want %q", i, got, want)
		}
	}

	a.confirmConnectProvider("venice")

	if selected != "venice" {
		t.Errorf("selected = %q, want venice", selected)
	}
	if a.connectPickerOpen || a.pages.HasPage(connectPickerPage) || a.connectPicker != nil {
		t.Error("connect picker stayed open after selection")
	}
}

func TestConnectPicker_EscThroughHandleEscCancelsNoSideEffects(t *testing.T) {
	a := New(nil)
	a.input.SetText("draft")
	called := false
	a.OpenConnectPicker([]ConnectProviderOption{{ID: "openai", Label: "openai"}}, func(string) { called = true })

	a.HandleEsc()

	if called {
		t.Error("selection callback ran on ESC cancel")
	}
	if a.connectPickerOpen || a.pages.HasPage(connectPickerPage) || a.connectPicker != nil {
		t.Error("connect picker stayed open after ESC")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Errorf("input = %q, want draft retained on picker cancel", got)
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want none on picker cancel", a.transcript.notice)
	}
}

func TestConnectPicker_ListEscapeCancels(t *testing.T) {
	a := New(nil)
	called := false
	a.OpenConnectPicker([]ConnectProviderOption{{ID: "openai", Label: "openai"}}, func(string) { called = true })

	a.connectPicker.list.InputHandler()(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone), nil)

	if called {
		t.Error("selection callback ran on list ESC")
	}
	if a.connectPickerOpen || a.pages.HasPage(connectPickerPage) {
		t.Error("connect picker stayed open after list ESC")
	}
}

func TestConnectPicker_SelectionObservesClosedPickerAndRestoredFocus(t *testing.T) {
	a := New(nil)
	before := tview.NewBox()
	a.app.SetFocus(before)

	var openAtCallback, pageAtCallback bool
	var focusAtCallback tview.Primitive
	a.OpenConnectPicker([]ConnectProviderOption{{ID: "openai", Label: "OpenAI"}}, func(string) {
		openAtCallback = a.connectPickerOpen
		pageAtCallback = a.pages.HasPage(connectPickerPage)
		focusAtCallback = a.app.GetFocus()
	})
	if a.connectPickerPrev != before {
		t.Fatalf("captured prior focus = %T, want the primitive focused at open", a.connectPickerPrev)
	}

	a.confirmConnectProvider("openai")

	if openAtCallback || pageAtCallback {
		t.Error("selection callback ran while the picker was still mounted")
	}
	if focusAtCallback != before {
		t.Errorf("focus during the callback = %T, want the primitive focused before the picker opened", focusAtCallback)
	}
	if a.connectPickerPrev != nil {
		t.Error("prior focus not cleared after dismissal")
	}
}

func TestConnectPicker_RepeatedDismissIsInert(t *testing.T) {
	a := New(nil)
	a.OpenConnectPicker([]ConnectProviderOption{{ID: "openai", Label: "OpenAI"}}, func(string) {})
	a.dismissConnectPicker()

	elsewhere := tview.NewBox()
	a.app.SetFocus(elsewhere)

	a.dismissConnectPicker()

	if a.app.GetFocus() != elsewhere {
		t.Errorf("focus after a second dismissal = %T, want it left where it was", a.app.GetFocus())
	}
	if a.connectPickerOpen || a.pages.HasPage(connectPickerPage) {
		t.Error("picker re-mounted by a second dismissal")
	}
}

func TestConnectPicker_NoRowsNoOp(t *testing.T) {
	a := New(nil)
	a.OpenConnectPicker(nil, func(string) { t.Fatal("selection callback should not run") })

	if a.connectPickerOpen || a.pages.HasPage(connectPickerPage) {
		t.Error("connect picker opened with no rows")
	}
}
