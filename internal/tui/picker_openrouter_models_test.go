package tui

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/provider"
)

func capsFixture() map[string]provider.MaxPrice {
	return map[string]provider.MaxPrice{
		"z-ai/glm-4.6":    {Completion: 3, HasCompletion: true},
		maxPriceModelID:   {Prompt: 1.5, Completion: 2, HasPrompt: true, HasCompletion: true},
		"anthropic/haiku": {Prompt: 0.25, HasPrompt: true},
	}
}

const modelsHeaderRow = "model | input $/M | output $/M | quantizations"

var capsFixtureRows = []string{
	modelsHeaderRow,
	"anthropic/haiku | $0.25 | none | none",
	maxPriceModelID + " | $1.5 | $2 | none",
	"z-ai/glm-4.6 | none | $3 | none",
}

func openModelsTable(t *testing.T, a *App, f *fakeOpenRouterSettings) *openRouterModelsTable {
	t.Helper()
	openSettingsTab(a, f)
	pressEnterOnRow(t, a, settingsRowModels)
	m := a.settingsPicker.models
	if m == nil || !a.pages.HasPage(openRouterModelsPage) {
		t.Fatal("Enter on the models row opened no table")
	}
	if a.app.GetFocus() != m.table {
		t.Fatalf("focus = %T, want the models table", a.app.GetFocus())
	}
	return m
}

func tableKey(a *App, ev *tcell.EventKey) {
	a.settingsPicker.models.table.InputHandler()(ev, func(p tview.Primitive) { a.app.SetFocus(p) })
}

func runeKey(r rune) *tcell.EventKey { return tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone) }

func keyEv(k tcell.Key) *tcell.EventKey { return tcell.NewEventKey(k, 0, tcell.ModNone) }

func globalEsc(t *testing.T, a *App) {
	t.Helper()
	if ev := a.handleGlobalKey(keyEv(tcell.KeyEscape)); ev != nil {
		t.Fatal("ESC was not consumed by the app-level key capture")
	}
}

func selectedTableModel(a *App) string {
	_, model := a.settingsPicker.models.selected()
	return model
}

func selectModel(t *testing.T, a *App, model string) {
	t.Helper()
	if !a.selectOpenRouterModelForTest(model) {
		t.Fatalf("no row for %s", model)
	}
}

func assertTableState(t *testing.T, a *App, rows []string, selected string) {
	t.Helper()
	if got := a.openRouterModelsTableRowsForTest(); !slices.Equal(got, rows) {
		t.Errorf("table rows = %q, want %q", got, rows)
	}
	if got := selectedTableModel(a); got != selected {
		t.Errorf("selected model = %q, want %q", got, selected)
	}
	if a.app.GetFocus() != a.settingsPicker.models.table {
		t.Errorf("focus = %T, want the models table", a.app.GetFocus())
	}
	for _, page := range []string{openRouterModelsAddPage, openRouterModelsEditPage, openRouterModelsRemovePage, settingsDeletePage} {
		if a.pages.HasPage(page) {
			t.Errorf("page %s still open", page)
		}
	}
	count := len(rows) - 1
	if slices.Contains(rows, openRouterModelsEmptyRow) {
		count = 0
	}
	if got, want := permissionsRowsOnTab(a)[settingsRowModels], "models: "+strconv.Itoa(count)+" configured"; got != want {
		t.Errorf("settings models row = %q, want %q", got, want)
	}
	if got := a.settingsPicker.list.GetCurrentItem(); got != settingsRowModels {
		t.Errorf("settings cursor = %d, want the models row", got)
	}
}

func openEditor(t *testing.T, a *App, model string) *maxPriceEditor {
	t.Helper()
	selectModel(t, a, model)
	tableKey(a, keyEv(tcell.KeyEnter))
	ed := a.settingsPicker.maxPrice
	if ed == nil || ed.model != model || !a.pages.HasPage(openRouterModelsEditPage) || a.app.GetFocus() != ed.prompt {
		t.Fatalf("Enter on %s opened no focused editor for it", model)
	}
	return ed
}

func TestOpenRouterModels_EnterOpensSortedTableWithActiveModelSelected(t *testing.T) {
	a := New(nil)
	openModelsTable(t, a, maxPriceSettings(capsFixture()))
	if got := a.openRouterModelsTableRowsForTest(); !slices.Equal(got, capsFixtureRows) {
		t.Fatalf("table rows = %q, want %q", got, capsFixtureRows)
	}
	if got := selectedTableModel(a); got != maxPriceModelID {
		t.Errorf("selected model = %q, want the active model", got)
	}
	if !a.settingsPickerOpen || !a.pages.HasPage(settingsPickerPage) {
		t.Error("opening the table closed the settings picker")
	}
}

func TestOpenRouterModels_TableSelectsFirstRowWhenActiveModelHasNoCaps(t *testing.T) {
	for _, tc := range []struct{ name, provider, model string }{
		{"uncapped openrouter model", "openrouter", "x/uncapped"},
		{"another provider", "venice", maxPriceModelID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			f := maxPriceSettings(capsFixture())
			f.activeProvider, f.activeModel = tc.provider, tc.model
			openModelsTable(t, a, f)
			if got := selectedTableModel(a); got != "anthropic/haiku" {
				t.Errorf("selected model = %q, want the first row", got)
			}
		})
	}
}

func TestOpenRouterModels_EmptyTableShowsPlaceholderAndEditRemoveAreInert(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(nil)
	openModelsTable(t, a, f)
	want := []string{modelsHeaderRow, openRouterModelsEmptyRow}
	if got := a.openRouterModelsTableRowsForTest(); !slices.Equal(got, want) {
		t.Fatalf("table rows = %q, want %q", got, want)
	}
	for _, ev := range []*tcell.EventKey{keyEv(tcell.KeyEnter), runeKey('e'), runeKey('r')} {
		tableKey(a, ev)
	}
	if a.pages.HasPage(openRouterModelsEditPage) || a.pages.HasPage(openRouterModelsRemovePage) {
		t.Error("edit or remove opened on the empty table")
	}
	if len(f.wrote) != 0 {
		t.Errorf("writes = %v, want none", f.wrote)
	}
}

func TestOpenRouterModels_ModelsRowIsInertWithoutTheCapsSeam(t *testing.T) {
	a := New(nil)
	openSettingsTab(a, nil)
	pressEnterOnRow(t, a, settingsRowModels)
	if a.pages.HasPage(openRouterModelsPage) || a.settingsPicker.models != nil {
		t.Error("Enter opened the models table without a caps seam")
	}
}

func TestOpenRouterModels_AddPickerOffersOnlyUncappedDiscoveredModelsFilteredAsTyped(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(capsFixture())
	f.models = []string{"qwen/qwen3-coder", maxPriceModelID, "openai/gpt-5", "anthropic/haiku", "qwen/qwen3-max"}
	openModelsTable(t, a, f)

	tableKey(a, runeKey('a'))
	field, ok := a.app.GetFocus().(*tview.InputField)
	if !ok || !a.pages.HasPage(openRouterModelsAddPage) {
		t.Fatal("a opened no focused add picker")
	}
	if got, want := a.settingsPicker.models.addIDs, []string{"openai/gpt-5", "qwen/qwen3-coder", "qwen/qwen3-max"}; !slices.Equal(got, want) {
		t.Fatalf("add choices = %q, want %q", got, want)
	}
	for _, r := range "qwen max" {
		field.InputHandler()(runeKey(r), func(p tview.Primitive) { a.app.SetFocus(p) })
	}
	if got, want := a.settingsPicker.models.addIDs, []string{"qwen/qwen3-max"}; !slices.Equal(got, want) {
		t.Fatalf("filtered add choices = %q, want %q", got, want)
	}
	if got := a.settingsPicker.models.addList.GetItemCount(); got != 1 {
		t.Errorf("add list shows %d rows, want 1", got)
	}
	field.SetText("nothing-matches")
	sendFieldKey(a, field, tcell.KeyEnter)
	if !a.pages.HasPage(openRouterModelsAddPage) || a.settingsPicker.maxPrice != nil {
		t.Error("Enter with no match left the add picker")
	}
}

func TestOpenRouterModels_AddSaveWritesAndSelectsTheNewRow(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(capsFixture())
	f.models = []string{"openai/gpt-5", "qwen/qwen3-max"}
	openModelsTable(t, a, f)

	tableKey(a, runeKey('a'))
	field := a.app.GetFocus().(*tview.InputField)
	sendFieldKey(a, field, tcell.KeyDown)
	sendFieldKey(a, field, tcell.KeyEnter)
	ed := a.settingsPicker.maxPrice
	if ed == nil || ed.model != "qwen/qwen3-max" || a.pages.HasPage(openRouterModelsAddPage) || a.app.GetFocus() != ed.prompt {
		t.Fatal("choosing a model did not open its price editor in place of the add picker")
	}
	if ed.prompt.GetText() != "" || ed.completion.GetText() != "" {
		t.Errorf("new model editor = %q/%q, want empty", ed.prompt.GetText(), ed.completion.GetText())
	}
	ed.prompt.SetText("0.5")
	ed.completion.SetText("2")
	sendFieldKey(a, ed.completion, tcell.KeyEnter)

	want := provider.MaxPrice{Prompt: 0.5, Completion: 2, HasPrompt: true, HasCompletion: true}
	if !slices.Equal(f.wrote, []string{maxPriceWrite("qwen/qwen3-max", want)}) {
		t.Fatalf("writes = %v, want one write of %+v", f.wrote, want)
	}
	rows := append(slices.Clone(capsFixtureRows), "qwen/qwen3-max | $0.5 | $2 | none")
	rows[3], rows[4] = rows[4], rows[3]
	assertTableState(t, a, rows, "qwen/qwen3-max")
	if a.NoticeText() != "" {
		t.Errorf("notice = %q, want none", a.NoticeText())
	}
}

func TestOpenRouterModels_EditSaveChangesCapsAndKeepsSelection(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(capsFixture())
	openModelsTable(t, a, f)

	ed := openEditor(t, a, "z-ai/glm-4.6")
	if ed.prompt.GetText() != "" || ed.completion.GetText() != "3" {
		t.Fatalf("editor = %q/%q, want the stored caps", ed.prompt.GetText(), ed.completion.GetText())
	}
	sendFieldKey(a, ed.prompt, tcell.KeyTab)
	if a.settingsPicker.activeTab != permTabIndexOpenRouter || a.app.GetFocus() != ed.completion {
		t.Fatal("Tab in the editor did not stay inside it")
	}
	ed.prompt.SetText("1")
	ed.completion.SetText("")
	sendFieldKey(a, ed.completion, tcell.KeyEnter)

	if want := maxPriceWrite("z-ai/glm-4.6", provider.MaxPrice{Prompt: 1, HasPrompt: true}); !slices.Equal(f.wrote, []string{want}) {
		t.Fatalf("writes = %v, want %s", f.wrote, want)
	}
	rows := slices.Clone(capsFixtureRows)
	rows[3] = "z-ai/glm-4.6 | $1 | none | none"
	assertTableState(t, a, rows, "z-ai/glm-4.6")
}

func TestOpenRouterModels_EditClearingBothCapsDeletesAndSelectsARemainingRow(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(capsFixture())
	openModelsTable(t, a, f)

	ed := openEditor(t, a, "z-ai/glm-4.6")
	ed.completion.SetText("")
	sendFieldKey(a, ed.prompt, tcell.KeyEnter)

	assertTableState(t, a, capsFixtureRows[:3], maxPriceModelID)
}

func TestOpenRouterModels_EditCancelKeepsRowsAndSelection(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(capsFixture())
	openModelsTable(t, a, f)

	ed := openEditor(t, a, "anthropic/haiku")
	ed.prompt.SetText("9")
	globalEsc(t, a)

	if len(f.wrote) != 0 {
		t.Errorf("writes = %v, want none", f.wrote)
	}
	if a.settingsPicker.maxPrice != nil {
		t.Error("cancel left editor state behind")
	}
	assertTableState(t, a, capsFixtureRows, "anthropic/haiku")
}

func TestOpenRouterModels_InvalidInputStaysInlineWithoutWrites(t *testing.T) {
	for _, tc := range []struct{ prompt, completion, levels, msg string }{
		{"abc", "", "", `input "abc" is not a number of at least 0`},
		{"1", "-0.5", "", `output "-0.5" is not a number of at least 0`},
		{"NaN", "", "", `input "NaN" is not a number of at least 0`},
		{"1", "+Inf", "", `output "+Inf" is not a number of at least 0`},
		{"4", "5", "fp8 fp9", `levels: unknown level "fp9", expected one of int4, int8, fp4, mxfp4, nvfp4, fp6, fp8, mxfp8, fp16, bf16, fp32, unknown`},
		{"4", "", "fp8 int4 fp8", `levels: duplicate level "fp8"`},
		{"x", "", "fp9", `input "x" is not a number of at least 0`},
	} {
		a := New(nil)
		f := maxPriceSettings(capsFixture())
		openModelsTable(t, a, f)

		ed := openEditor(t, a, "z-ai/glm-4.6")
		ed.prompt.SetText(tc.prompt)
		ed.completion.SetText(tc.completion)
		ed.levels.SetText(tc.levels)
		sendFieldKey(a, ed.levels, tcell.KeyEnter)

		if len(f.wrote) != 0 {
			t.Errorf("%q/%q/%q writes = %v, want none", tc.prompt, tc.completion, tc.levels, f.wrote)
		}
		if got := ed.errView.GetText(false); got != tc.msg {
			t.Errorf("inline error = %q, want %q", got, tc.msg)
		}
		if a.NoticeText() != "" {
			t.Errorf("notice = %q, want the error inline only", a.NoticeText())
		}
		if a.settingsPicker.maxPrice != ed || !a.pages.HasPage(openRouterModelsEditPage) {
			t.Fatal("an invalid entry closed the dialog")
		}
		if ed.prompt.GetText() != tc.prompt || ed.completion.GetText() != tc.completion || ed.levels.GetText() != tc.levels {
			t.Errorf("entered values = %q/%q/%q, want them kept", ed.prompt.GetText(), ed.completion.GetText(), ed.levels.GetText())
		}
		globalEsc(t, a)
		assertTableState(t, a, capsFixtureRows, "z-ai/glm-4.6")
	}
}

func TestOpenRouterModels_FailedWritesNotifyWithoutAFalseRowChange(t *testing.T) {
	const notice = "couldn't change the openrouter max price setting: write_error: no space left"
	for _, tc := range []struct {
		name string
		act  func(t *testing.T, a *App)
	}{
		{"edit", func(t *testing.T, a *App) {
			ed := openEditor(t, a, "anthropic/haiku")
			ed.prompt.SetText("4")
			sendFieldKey(a, ed.prompt, tcell.KeyEnter)
		}},
		{"add", func(t *testing.T, a *App) {
			tableKey(a, runeKey('a'))
			field := a.app.GetFocus().(*tview.InputField)
			sendFieldKey(a, field, tcell.KeyEnter)
			ed := a.settingsPicker.maxPrice
			ed.prompt.SetText("4")
			sendFieldKey(a, ed.prompt, tcell.KeyEnter)
		}},
		{"remove", func(t *testing.T, a *App) {
			tableKey(a, runeKey('r'))
			answerConfirm(t, a, tcell.KeyEnter)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			f := maxPriceSettings(capsFixture())
			f.models = []string{"openai/gpt-5"}
			f.err = errors.New("write_error: no\nspace left")
			openModelsTable(t, a, f)
			selectModel(t, a, "anthropic/haiku")

			tc.act(t, a)

			if len(f.wrote) != 1 {
				t.Fatalf("writes = %v, want exactly one attempt", f.wrote)
			}
			if a.NoticeText() != notice {
				t.Errorf("notice = %q, want %q", a.NoticeText(), notice)
			}
			assertTableState(t, a, capsFixtureRows, "anthropic/haiku")
		})
	}
}

func answerConfirm(t *testing.T, a *App, key tcell.Key) {
	t.Helper()
	modal, ok := a.pages.GetPage(openRouterModelsRemovePage).(*tview.Modal)
	if !ok || a.app.GetFocus() == nil {
		t.Fatal("no remove confirmation open")
	}
	if key == tcell.KeyRight {
		modal.InputHandler()(keyEv(key), func(p tview.Primitive) { a.app.SetFocus(p) })
		key = tcell.KeyEnter
	}
	modal.InputHandler()(keyEv(key), func(p tview.Primitive) { a.app.SetFocus(p) })
}

func TestOpenRouterModels_RemoveConfirmedDeletesAndSelectsTheNextRow(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(capsFixture())
	openModelsTable(t, a, f)
	selectModel(t, a, maxPriceModelID)

	tableKey(a, runeKey('r'))
	if a.app.GetFocus() == a.settingsPicker.models.table {
		t.Fatal("r did not move focus to a confirmation")
	}
	answerConfirm(t, a, tcell.KeyEnter)

	if want := maxPriceWrite(maxPriceModelID, provider.MaxPrice{}); !slices.Equal(f.wrote, []string{want}) {
		t.Fatalf("writes = %v, want %s", f.wrote, want)
	}
	assertTableState(t, a, []string{capsFixtureRows[0], capsFixtureRows[1], capsFixtureRows[3]}, "z-ai/glm-4.6")
}

func TestOpenRouterModels_RemovingTheLastRowLeavesTheEmptyTableFocused(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(map[string]provider.MaxPrice{"anthropic/haiku": {Prompt: 1, HasPrompt: true}})
	openModelsTable(t, a, f)

	tableKey(a, runeKey('r'))
	answerConfirm(t, a, tcell.KeyEnter)

	assertTableState(t, a, []string{capsFixtureRows[0], openRouterModelsEmptyRow}, "")
}

func TestOpenRouterModels_RemoveCancelledKeepsRowsAndSelection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel func(t *testing.T, a *App)
	}{
		{"cancel button", func(t *testing.T, a *App) { answerConfirm(t, a, tcell.KeyRight) }},
		{"esc", globalEsc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			f := maxPriceSettings(capsFixture())
			openModelsTable(t, a, f)
			selectModel(t, a, "z-ai/glm-4.6")

			tableKey(a, runeKey('r'))
			tc.cancel(t, a)

			if len(f.wrote) != 0 {
				t.Errorf("writes = %v, want none", f.wrote)
			}
			assertTableState(t, a, capsFixtureRows, "z-ai/glm-4.6")
		})
	}
}

func TestOpenRouterModels_NestedEscClosesOneLayerAtATime(t *testing.T) {
	a := New(nil)
	canceller := &fakeStreamCanceller{retained: 3, inFlight: true}
	a.SetStreamCanceller(canceller)
	a.input.SetText("draft")
	f := maxPriceSettings(capsFixture())
	f.models = []string{"openai/gpt-5"}
	openModelsTable(t, a, f)

	tableKey(a, runeKey('a'))
	if !a.pages.HasPage(openRouterModelsAddPage) {
		t.Fatal("a opened no add picker")
	}
	if ev := a.handleGlobalKey(keyEv(tcell.KeyTab)); ev != nil {
		a.app.GetFocus().InputHandler()(ev, func(p tview.Primitive) { a.app.SetFocus(p) })
	}
	if a.settingsPicker.activeTab != permTabIndexOpenRouter || !a.pages.HasPage(openRouterModelsAddPage) {
		t.Fatal("Tab in the add picker switched the settings tab or closed the picker")
	}
	globalEsc(t, a)
	assertTableState(t, a, capsFixtureRows, maxPriceModelID)

	globalEsc(t, a)
	if a.pages.HasPage(openRouterModelsPage) || a.settingsPicker.models != nil {
		t.Fatal("ESC left the models table open")
	}
	if !a.settingsPickerOpen || a.settingsPicker.activeTab != permTabIndexOpenRouter {
		t.Fatal("ESC from the table did not return to the OpenRouter tab")
	}
	if a.app.GetFocus() != a.settingsPicker.list || a.settingsPicker.list.GetCurrentItem() != settingsRowModels {
		t.Error("ESC from the table did not focus the models row")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Errorf("input draft = %q, want it kept", got)
	}
	if canceller.calls != 0 {
		t.Errorf("turn cancelled %d times, want none", canceller.calls)
	}
}

func TestOpenRouterModels_TabOnTheTableKeepsTheSettingsTab(t *testing.T) {
	a := New(nil)
	openModelsTable(t, a, maxPriceSettings(capsFixture()))
	if ev := a.handleGlobalKey(keyEv(tcell.KeyTab)); ev != nil {
		tableKey(a, ev)
	}
	if a.settingsPicker.activeTab != permTabIndexOpenRouter || a.app.GetFocus() != a.settingsPicker.models.table {
		t.Error("Tab on the models table left it")
	}
}

func TestOpenRouterModels_FullDismissalRemovesEveryPageAndReopensClean(t *testing.T) {
	a := New(nil)
	f := maxPriceSettings(capsFixture())
	openModelsTable(t, a, f)
	openEditor(t, a, "anthropic/haiku")

	a.dismissSettingsPicker()
	for _, page := range append([]string{settingsPickerPage, settingsDeletePage}, openRouterModelsPages...) {
		if a.pages.HasPage(page) {
			t.Errorf("page %s left mounted after dismissal", page)
		}
	}
	if a.settingsPicker != nil || a.settingsPickerOpen {
		t.Fatal("dismissal left settings picker state")
	}

	openSettingsTab(a, f)
	if a.settingsPicker.models != nil || a.pages.HasPage(openRouterModelsPage) {
		t.Fatal("reopening settings brought back the models table")
	}
	globalEsc(t, a)
	if a.settingsPickerOpen {
		t.Fatal("ESC on the reopened settings did not close it")
	}
	if len(f.wrote) != 0 {
		t.Errorf("writes = %v, want none", f.wrote)
	}
}

func quantsFixture() map[string]provider.Quantization {
	return map[string]provider.Quantization{
		maxPriceModelID: {Levels: []string{"fp8", "fp4"}, Mode: "required"},
		"hand/edited":   {Levels: []string{"unknown"}, Mode: "preferred"},
	}
}

func unionSettings() *fakeOpenRouterSettings {
	f := maxPriceSettings(capsFixture())
	f.quants = quantsFixture()
	return f
}

var unionRows = []string{
	modelsHeaderRow,
	"anthropic/haiku | $0.25 | none | none",
	"hand/edited | none | none | unknown (preferred)",
	maxPriceModelID + " | $1.5 | $2 | fp8 fp4 (required)",
	"z-ai/glm-4.6 | none | $3 | none",
}

func TestOpenRouterModels_TableListsCapsQuantizationsAndBoth(t *testing.T) {
	a := New(nil)
	openModelsTable(t, a, unionSettings())
	assertTableState(t, a, unionRows, maxPriceModelID)

	b := New(nil)
	f := maxPriceSettings(nil)
	f.quants = quantsFixture()
	openModelsTable(t, b, f)
	assertTableState(t, b, []string{modelsHeaderRow, unionRows[2], "meta-llama/llama-3.3-70b-instruct:free | none | none | fp8 fp4 (required)"}, maxPriceModelID)
}

func TestOpenRouterModels_AddExcludesTableModelsAndSavesLevelsWithoutCaps(t *testing.T) {
	a := New(nil)
	f := unionSettings()
	f.models = []string{"hand/edited", "openai/gpt-5", maxPriceModelID, "anthropic/haiku"}
	openModelsTable(t, a, f)

	tableKey(a, runeKey('a'))
	if got, want := a.settingsPicker.models.addIDs, []string{"openai/gpt-5"}; !slices.Equal(got, want) {
		t.Fatalf("add choices = %q, want %q", got, want)
	}
	sendFieldKey(a, a.app.GetFocus().(*tview.InputField), tcell.KeyEnter)
	ed := a.settingsPicker.maxPrice
	if ed == nil || ed.model != "openai/gpt-5" {
		t.Fatal("choosing a model opened no dialog for it")
	}
	if _, mode := ed.mode.GetCurrentOption(); ed.levels.GetText() != "" || mode != "Preferred" {
		t.Fatalf("new model dialog = levels %q mode %q, want empty and Preferred", ed.levels.GetText(), mode)
	}
	ed.levels.SetText(" fp8   fp4 ")
	for _, k := range []tcell.Key{tcell.KeyTab, tcell.KeyTab, tcell.KeyTab} {
		sendFocusedKey(a, keyEv(k))
	}
	if a.app.GetFocus() != ed.mode {
		t.Fatalf("focus after three tabs = %T, want the mode choice", a.app.GetFocus())
	}
	sendFocusedKey(a, keyEv(tcell.KeyRight))
	sendFocusedKey(a, keyEv(tcell.KeyEnter))

	want := provider.Quantization{Levels: []string{"fp8", "fp4"}, Mode: "required"}
	if !slices.Equal(f.wrote, []string{quantWrite("openai/gpt-5", want)}) {
		t.Fatalf("writes = %v, want only the quantizations write", f.wrote)
	}
	if _, ok := f.prices["openai/gpt-5"]; ok {
		t.Error("a levels-only save created a max_price entry")
	}
	rows := slices.Insert(slices.Clone(unionRows), 4, "openai/gpt-5 | none | none | fp8 fp4 (required)")
	assertTableState(t, a, rows, "openai/gpt-5")
}

func sendFocusedKey(a *App, ev *tcell.EventKey) {
	a.app.GetFocus().InputHandler()(ev, func(p tview.Primitive) { a.app.SetFocus(p) })
}

func TestOpenRouterModels_ModeChoiceToggles(t *testing.T) {
	a := New(nil)
	openModelsTable(t, a, unionSettings())
	ed := openEditor(t, a, maxPriceModelID)
	if ed.levels.GetText() != "fp8 fp4" {
		t.Fatalf("levels field = %q, want the stored order", ed.levels.GetText())
	}
	a.app.SetFocus(ed.mode)
	for _, step := range []struct {
		ev   *tcell.EventKey
		want string
	}{
		{nil, "Required"},
		{keyEv(tcell.KeyLeft), "Preferred"},
		{runeKey(' '), "Required"},
		{keyEv(tcell.KeyRight), "Preferred"},
	} {
		if step.ev != nil {
			sendFocusedKey(a, step.ev)
		}
		if _, got := ed.mode.GetCurrentOption(); got != step.want {
			t.Fatalf("mode = %q, want %q", got, step.want)
		}
	}
	if ed.mode.IsOpen() {
		t.Error("toggling opened the option list")
	}
}

func TestOpenRouterModels_ClearingLevelsDeletesQuantizationsAndDropsAnEmptyRow(t *testing.T) {
	a := New(nil)
	f := unionSettings()
	openModelsTable(t, a, f)

	ed := openEditor(t, a, maxPriceModelID)
	ed.levels.SetText("  ")
	sendFieldKey(a, ed.levels, tcell.KeyEnter)
	if !slices.Equal(f.wrote, []string{quantClear(maxPriceModelID)}) {
		t.Fatalf("writes = %v, want only the quantizations deletion", f.wrote)
	}
	rows := slices.Clone(unionRows)
	rows[3] = maxPriceModelID + " | $1.5 | $2 | none"
	assertTableState(t, a, rows, maxPriceModelID)

	ed = openEditor(t, a, "hand/edited")
	ed.levels.SetText("")
	sendFieldKey(a, ed.prompt, tcell.KeyEnter)
	assertTableState(t, a, slices.Delete(rows, 2, 3), maxPriceModelID)
}

func TestOpenRouterModels_SaveWritesCapsThenQuantizations(t *testing.T) {
	boom := errors.New("write_error: no\nspace left")
	for _, tc := range []struct {
		name            string
		err, quantErr   error
		wrote           []string
		notice, wantRow string
	}{
		{
			name:    "both succeed",
			wrote:   []string{"caps", "quant"},
			wantRow: maxPriceModelID + " | $9 | $2 | bf16 (preferred)",
		},
		{
			name: "first write fails", err: boom,
			wrote:   []string{"caps"},
			notice:  "couldn't change the openrouter max price setting: write_error: no space left",
			wantRow: unionRows[3],
		},
		{
			name: "second write fails", quantErr: boom,
			wrote:   []string{"caps", "quant"},
			notice:  "couldn't change the openrouter quantizations setting: write_error: no space left; the price caps were saved",
			wantRow: maxPriceModelID + " | $9 | $2 | fp8 fp4 (required)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			f := unionSettings()
			f.err, f.quantErr = tc.err, tc.quantErr
			openModelsTable(t, a, f)

			ed := openEditor(t, a, maxPriceModelID)
			ed.prompt.SetText("9")
			ed.levels.SetText("bf16")
			a.app.SetFocus(ed.mode)
			sendFocusedKey(a, keyEv(tcell.KeyLeft))
			sendFocusedKey(a, keyEv(tcell.KeyEnter))

			names := map[string]string{
				"caps":  maxPriceWrite(maxPriceModelID, provider.MaxPrice{Prompt: 9, Completion: 2, HasPrompt: true, HasCompletion: true}),
				"quant": quantWrite(maxPriceModelID, provider.Quantization{Levels: []string{"bf16"}, Mode: "preferred"}),
			}
			var want []string
			for _, w := range tc.wrote {
				want = append(want, names[w])
			}
			if !slices.Equal(f.wrote, want) {
				t.Fatalf("writes = %v, want %v", f.wrote, want)
			}
			if a.NoticeText() != tc.notice {
				t.Errorf("notice = %q, want %q", a.NoticeText(), tc.notice)
			}
			rows := slices.Clone(unionRows)
			rows[3] = tc.wantRow
			assertTableState(t, a, rows, maxPriceModelID)
		})
	}
}

func TestOpenRouterModels_RemoveClearsCapsThenQuantizations(t *testing.T) {
	boom := errors.New("write_error: no\nspace left")
	for _, tc := range []struct {
		name          string
		model         string
		err, quantErr error
		wrote         []string
		notice        string
		rows          []string
		selected      string
	}{
		{
			name: "both cleared", model: maxPriceModelID,
			wrote:    []string{maxPriceWrite(maxPriceModelID, provider.MaxPrice{}), quantClear(maxPriceModelID)},
			rows:     []string{unionRows[0], unionRows[1], unionRows[2], unionRows[4]},
			selected: "z-ai/glm-4.6",
		},
		{
			name: "quantizations only", model: "hand/edited",
			wrote:    []string{quantClear("hand/edited")},
			rows:     []string{unionRows[0], unionRows[1], unionRows[3], unionRows[4]},
			selected: maxPriceModelID,
		},
		{
			name: "first write fails", model: maxPriceModelID, err: boom,
			wrote:    []string{maxPriceWrite(maxPriceModelID, provider.MaxPrice{})},
			notice:   "couldn't change the openrouter max price setting: write_error: no space left",
			rows:     unionRows,
			selected: maxPriceModelID,
		},
		{
			name: "second write fails", model: maxPriceModelID, quantErr: boom,
			wrote:    []string{maxPriceWrite(maxPriceModelID, provider.MaxPrice{}), quantClear(maxPriceModelID)},
			notice:   "couldn't change the openrouter quantizations setting: write_error: no space left; the price caps were removed",
			rows:     []string{unionRows[0], unionRows[1], unionRows[2], maxPriceModelID + " | none | none | fp8 fp4 (required)", unionRows[4]},
			selected: maxPriceModelID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			f := unionSettings()
			f.err, f.quantErr = tc.err, tc.quantErr
			openModelsTable(t, a, f)
			selectModel(t, a, tc.model)

			tableKey(a, runeKey('r'))
			answerConfirm(t, a, tcell.KeyEnter)

			if !slices.Equal(f.wrote, tc.wrote) {
				t.Fatalf("writes = %v, want %v", f.wrote, tc.wrote)
			}
			if a.NoticeText() != tc.notice {
				t.Errorf("notice = %q, want %q", a.NoticeText(), tc.notice)
			}
			assertTableState(t, a, tc.rows, tc.selected)
		})
	}
}

type fakeHostQuantizations struct {
	counts  map[string]int
	state   provider.OpenRouterHostsState
	calls   []string
	fetched []func()
}

func (f *fakeHostQuantizations) query(model string, fetched func()) (map[string]int, provider.OpenRouterHostsState) {
	f.calls = append(f.calls, model)
	if f.state == provider.OpenRouterHostsPending {
		f.fetched = append(f.fetched, fetched)
	}
	return f.counts, f.state
}

func openTableWithHosts(t *testing.T, a *App, q *fakeHostQuantizations) {
	t.Helper()
	openSettingsTab(a, unionSettings())
	a.openRouterSettings.HostQuantizations = q.query
	pressEnterOnRow(t, a, settingsRowModels)
	if len(q.calls) != 0 {
		t.Fatalf("host lookups opening the table = %q, want none", q.calls)
	}
}

func TestOpenRouterModels_EditDialogShowsTheEditedModelsOfferedLevels(t *testing.T) {
	const allLevels = "providers per level: bf16 2, fp16 1, fp4 14, fp8 9, int4 7, int8 3, mxfp4 1, nvfp4 3, unknown 12, unspecified 5"
	for _, tc := range []struct {
		name   string
		counts map[string]int
		state  provider.OpenRouterHostsState
		want   string
	}{
		{
			"ready", map[string]int{"unknown": 12, "nvfp4": 3, "fp8": 9, "fp4": 14, "": 5, "int8": 3, "bf16": 2, "mxfp4": 1, "int4": 7, "fp16": 1},
			provider.OpenRouterHostsReady, allLevels,
		},
		{"only unspecified", map[string]int{"": 4}, provider.OpenRouterHostsReady, "providers per level: unspecified 4"},
		{"empty successful list", map[string]int{}, provider.OpenRouterHostsReady, "providers per level: none"},
		{"pending", nil, provider.OpenRouterHostsPending, "checking providers\u2026"},
		{"failed", nil, provider.OpenRouterHostsFailed, "provider list unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &fakeHostQuantizations{counts: tc.counts, state: tc.state}
			a := New(nil)
			openTableWithHosts(t, a, q)
			ed := openEditor(t, a, "z-ai/glm-4.6")
			if got := ed.offeredText; got != tc.want {
				t.Errorf("offered line = %q, want %q", got, tc.want)
			}
			if !slices.Equal(q.calls, []string{"z-ai/glm-4.6"}) {
				t.Errorf("host lookups = %q, want only the edited model", q.calls)
			}
			text, lines := modelDialogText(t, a, 80, 24)
			if !strings.Contains(text, tc.want) {
				t.Errorf("80-column dialog does not show the whole offered line %q:\n%s", tc.want, strings.Join(lines, "\n"))
			}
			if last := lines[len(lines)-1]; !strings.HasPrefix(last, "save enter") {
				t.Errorf("last dialog line = %q, want the key footer still visible", last)
			}
		})
	}
}

func TestOpenRouterModels_OfferedLevelsCompletionRedrawsTheLiveDialogOnTheEventLoop(t *testing.T) {
	q := &fakeHostQuantizations{state: provider.OpenRouterHostsPending}
	a := New(nil)
	openTableWithHosts(t, a, q)
	ed := openEditor(t, a, "z-ai/glm-4.6")
	ed.prompt.SetText("0.7")
	ed.levels.SetText("fp8 int4")
	a.app.SetFocus(ed.levels)
	if got := ed.offeredText; got != "checking providers\u2026" || len(q.fetched) != 1 {
		t.Fatalf("offered line = %q with %d pending callbacks, want checking with one", got, len(q.fetched))
	}

	h := newAppHarnessFor(t, a, 80, 24)
	defer h.stop()
	a.running.Store(true)
	defer a.running.Store(false)
	q.counts, q.state = map[string]int{"fp8": 2}, provider.OpenRouterHostsReady
	q.fetched[0]()

	var offered, prompt, levels string
	var focused, live bool
	a.app.QueueUpdate(func() {
		offered, prompt, levels = ed.offeredText, ed.prompt.GetText(), ed.levels.GetText()
		focused, live = a.app.GetFocus() == ed.levels, a.settingsPicker.maxPrice == ed
	})
	if offered != "providers per level: fp8 2" {
		t.Errorf("offered line after the fetch = %q", offered)
	}
	if prompt != "0.7" || levels != "fp8 int4" || !focused || !live {
		t.Errorf("draft after the redraw = %q / %q, focus kept %v, same dialog %v", prompt, levels, focused, live)
	}
	if got := screenTextSync(a, h.screen); !strings.Contains(got, "providers per level: fp8 2") {
		t.Errorf("screen after the fetch does not show the offered line:\n%s", got)
	}
}

func TestOpenRouterModels_OfferedLevelsCompletionForAClosedOrReplacedDialogIsInert(t *testing.T) {
	const model = "z-ai/glm-4.6"
	for _, tc := range []struct {
		name  string
		leave func(t *testing.T, a *App)
		open  bool
	}{
		{"after esc", func(t *testing.T, a *App) { globalEsc(t, a) }, false},
		{"after switching models", func(t *testing.T, a *App) { globalEsc(t, a); openEditor(t, a, "anthropic/haiku") }, true},
		{"after reopening the same model", func(t *testing.T, a *App) { globalEsc(t, a); openEditor(t, a, model) }, true},
		{"after closing settings", func(_ *testing.T, a *App) { a.dismissSettingsPicker() }, false},
		{"while the app stops", func(_ *testing.T, a *App) { a.stopping.Store(true) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &fakeHostQuantizations{state: provider.OpenRouterHostsPending}
			a := New(nil)
			openTableWithHosts(t, a, q)
			openEditor(t, a, model)
			tc.leave(t, a)
			calls := len(q.calls)

			q.counts, q.state = map[string]int{"fp8": 1}, provider.OpenRouterHostsReady
			q.fetched[0]()
			if len(q.calls) != calls {
				t.Errorf("host lookups after a stale completion = %q, want none added", q.calls[calls:])
			}
			var ed *maxPriceEditor
			if a.settingsPicker != nil {
				ed = a.settingsPicker.maxPrice
			}
			if (ed != nil) != tc.open {
				t.Fatalf("dialog open = %v, want %v", ed != nil, tc.open)
			}
			if ed != nil {
				if got := ed.offeredText; got != "checking providers\u2026" {
					t.Errorf("live dialog offered line = %q, want it untouched by the stale completion", got)
				}
			}
		})
	}
}
