package tui

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/provider"
)

const (
	openRouterModelsPage       = "settings-openrouter-models"
	openRouterModelsAddPage    = "settings-openrouter-models-add"
	openRouterModelsEditPage   = "settings-openrouter-models-edit"
	openRouterModelsRemovePage = "settings-openrouter-models-remove"

	openRouterModelsFooter    = "add a   edit enter   remove r   esc back"
	openRouterModelsAddFooter = "choose enter   esc back"
	openRouterModelsEmptyRow  = "(no models configured)"
)

var (
	openRouterModelsChildPages = []string{openRouterModelsAddPage, openRouterModelsEditPage, openRouterModelsRemovePage}
	openRouterModelsPages      = append([]string{openRouterModelsPage}, openRouterModelsChildPages...)
	openRouterModelsHeader     = []string{"model", "input $/M", "output $/M", quantizationsLabel}
)

type openRouterModelRow struct {
	model string
	price provider.MaxPrice
	quant provider.Quantization
}

func (r openRouterModelRow) cells() []string {
	quant := "none"
	if len(r.quant.Levels) > 0 {
		quant = strings.Join(r.quant.Levels, " ") + " (" + r.quant.Mode + ")"
	}
	return []string{r.model, renderPrice(r.price.Prompt, r.price.HasPrompt), renderPrice(r.price.Completion, r.price.HasCompletion), quant}
}

type openRouterModelsTable struct {
	table   *tview.Table
	rows    []openRouterModelRow
	addList *tview.List
	addIDs  []string
}

func (a *App) openRouterModelRows() []openRouterModelRow {
	s := a.openRouterSettings
	if s.MaxPrices == nil || s.Quantizations == nil {
		return nil
	}
	caps, quants := s.MaxPrices(), s.Quantizations()
	rows := make([]openRouterModelRow, 0, len(caps)+len(quants))
	for model, p := range caps {
		rows = append(rows, openRouterModelRow{model: model, price: p, quant: quants[model]})
	}
	for model, q := range quants {
		if _, ok := caps[model]; !ok {
			rows = append(rows, openRouterModelRow{model: model, quant: q})
		}
	}
	slices.SortFunc(rows, func(x, y openRouterModelRow) int { return strings.Compare(x.model, y.model) })
	return rows
}

func (a *App) modelsRow() string {
	return modelsRowLabel + ": " + strconv.Itoa(len(a.openRouterModelRows())) + " configured"
}

func (a *App) openOpenRouterModels() {
	pp := a.settingsPicker
	s := a.openRouterSettings
	if pp == nil || s.MaxPrices == nil || s.SetMaxPrice == nil || s.Quantizations == nil || s.SetQuantization == nil || s.ClearQuantization == nil {
		return
	}
	table := tview.NewTable()
	table.SetSelectable(true, false)
	table.SetFixed(1, 0)
	applyPickerTableColors(table)
	table.SetInputCapture(a.openRouterModelsKeys)
	pp.models = &openRouterModelsTable{table: table}

	footer := tview.NewTextView()
	footer.SetText(openRouterModelsFooter)
	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(table, 0, 1, true).
		AddItem(footer, 1, 0, false)
	body.SetBorder(true)
	body.SetTitle(" openrouter models ")

	a.renderOpenRouterModels(a.maxPriceModel(), 0)
	a.pages.AddPage(openRouterModelsPage, wrapOverlayPage(body), true, true)
	a.app.SetFocus(table)
}

func (a *App) renderOpenRouterModels(want string, fallback int) {
	m := a.settingsPicker.models
	m.rows = a.openRouterModelRows()
	m.table.Clear()
	for col, title := range openRouterModelsHeader {
		m.table.SetCell(0, col, tview.NewTableCell(title).SetSelectable(false).SetStyle(tcell.StyleDefault.Bold(true)))
	}
	if len(m.rows) == 0 {
		m.table.SetCell(1, 0, tview.NewTableCell(openRouterModelsEmptyRow).SetSelectable(false))
		m.table.Select(1, 0)
		return
	}
	selected := min(max(fallback, 0), len(m.rows)-1)
	for i, row := range m.rows {
		for col, text := range row.cells() {
			cell := tview.NewTableCell(tview.Escape(text))
			if col == 0 {
				cell.SetExpansion(1)
			}
			m.table.SetCell(i+1, col, cell)
		}
		if row.model == want {
			selected = i
		}
	}
	m.table.Select(selected+1, 0)
}

func (m *openRouterModelsTable) selected() (int, string) {
	row, _ := m.table.GetSelection()
	if row < 1 || row > len(m.rows) {
		return -1, ""
	}
	return row - 1, m.rows[row-1].model
}

func (a *App) openRouterModelsKeys(ev *tcell.EventKey) *tcell.EventKey {
	pp := a.settingsPicker
	if pp == nil || pp.models == nil {
		return ev
	}
	_, model := pp.models.selected()
	switch {
	case ev.Key() == tcell.KeyEnter || (ev.Key() == tcell.KeyRune && ev.Rune() == 'e'):
		if model != "" {
			a.showMaxPriceEditor(model)
		}
		return nil
	case ev.Key() == tcell.KeyRune && ev.Rune() == 'a':
		a.showOpenRouterModelAdd()
		return nil
	case ev.Key() == tcell.KeyRune && ev.Rune() == 'r':
		if model != "" {
			a.showConfirmPage(openRouterModelsRemovePage,
				"Remove the price caps and quantizations for this model?\n\n"+shareConfirmFact(model), "Remove",
				func() { a.removeOpenRouterModel(model) },
				func() { a.finishOpenRouterModelsChild("") })
		}
		return nil
	}
	return ev
}

func (a *App) removeOpenRouterModel(model string) {
	s := a.openRouterSettings
	_, hasCaps := a.maxPrice(model)
	if hasCaps {
		if err := s.SetMaxPrice(model, provider.MaxPrice{}); err != nil {
			a.Notice(renderSettingFailedNotice(openRouterNoticePrefix+maxPriceRowLabel, err))
			a.finishOpenRouterModelsChild(model)
			return
		}
	}
	if _, has := a.quantization(model); has {
		if err := s.ClearQuantization(model); err != nil {
			a.Notice(quantizationFailedNotice(err, hasCaps, "removed"))
		}
	}
	a.finishOpenRouterModelsChild(model)
}

func (a *App) openRouterAddCandidates() []ProviderModel {
	if a.openRouterSettings.Models == nil {
		return nil
	}
	have := map[string]bool{}
	for _, row := range a.settingsPicker.models.rows {
		have[row.model] = true
	}
	var out []ProviderModel
	for _, id := range a.openRouterSettings.Models() {
		if !have[id] {
			have[id] = true
			out = append(out, ProviderModel{Provider: "openrouter", ModelID: id})
		}
	}
	return out
}

func (a *App) showOpenRouterModelAdd() {
	m := a.settingsPicker.models
	candidates := a.openRouterAddCandidates()

	list := tview.NewList()
	list.SetUseStyleTags(false, false)
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	m.addList = list

	field := tview.NewInputField()
	field.SetLabel(modelFilterLabel)
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
	refill := func(text string) {
		list.Clear()
		m.addIDs = nil
		for _, i := range filterModelRows(candidates, text) {
			m.addIDs = append(m.addIDs, candidates[i].ModelID)
			list.AddItem(candidates[i].ModelID, "", 0, nil)
		}
	}
	refill("")
	field.SetChangedFunc(refill)
	field.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyUp, tcell.KeyDown, tcell.KeyPgUp, tcell.KeyPgDn:
			list.InputHandler()(ev, func(tview.Primitive) {})
			return nil
		case tcell.KeyEnter:
			a.chooseOpenRouterModelAdd()
			return nil
		}
		return ev
	})

	footer := tview.NewTextView()
	footer.SetText(openRouterModelsAddFooter)
	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(field, 1, 0, true).
		AddItem(list, 0, 1, false).
		AddItem(footer, 1, 0, false)
	body.SetBorder(true)
	body.SetTitle(" add openrouter model ")
	a.pages.AddPage(openRouterModelsAddPage, centeredModal(body), true, true)
	a.app.SetFocus(field)
}

func (a *App) chooseOpenRouterModelAdd() {
	m := a.settingsPicker.models
	i := m.addList.GetCurrentItem()
	if i < 0 || i >= len(m.addIDs) {
		return
	}
	model := m.addIDs[i]
	a.pages.RemovePage(openRouterModelsAddPage)
	m.addList, m.addIDs = nil, nil
	a.showMaxPriceEditor(model)
}

func (a *App) finishOpenRouterModelsChild(want string) {
	pp := a.settingsPicker
	for _, page := range openRouterModelsChildPages {
		a.pages.RemovePage(page)
	}
	if pp == nil || pp.models == nil {
		return
	}
	pp.maxPrice = nil
	pp.models.addList, pp.models.addIDs = nil, nil
	prev, model := pp.models.selected()
	if want == "" {
		want = model
	}
	a.renderOpenRouterModels(want, prev)
	a.repaintModelsRow()
	a.app.SetFocus(pp.models.table)
}

func (a *App) repaintModelsRow() {
	pp := a.settingsPicker
	a.renderSettingsTab()
	if tab, i := settingsRowPlace(settingsRowModels); tab == pp.activeTab {
		pp.list.SetCurrentItem(i)
		a.updateRowHelp(i)
	}
}

func (a *App) dismissOpenRouterModelsLayer() bool {
	pp := a.settingsPicker
	if pp == nil || pp.models == nil {
		return false
	}
	for _, page := range openRouterModelsChildPages {
		if a.pages.HasPage(page) {
			a.finishOpenRouterModelsChild("")
			return true
		}
	}
	a.pages.RemovePage(openRouterModelsPage)
	pp.models = nil
	a.repaintModelsRow()
	a.app.SetFocus(pp.list)
	return true
}

func (a *App) openRouterModelsTableRowsForTest() []string {
	pp := a.settingsPicker
	if pp == nil || pp.models == nil {
		return nil
	}
	t := pp.models.table
	rows := make([]string, 0, t.GetRowCount())
	for r := range t.GetRowCount() {
		var cells []string
		for c := range t.GetColumnCount() {
			if cell := t.GetCell(r, c); cell.Text != "" {
				cells = append(cells, cell.Text)
			}
		}
		rows = append(rows, strings.Join(cells, " | "))
	}
	return rows
}

func (a *App) OpenRouterModelsForTest() []string {
	pp := a.settingsPicker
	if pp != nil && pp.models == nil {
		a.pressEnterOnSettingsRowForTest(settingsRowModels)
	}
	return a.openRouterModelsTableRowsForTest()
}

func (a *App) OpenRouterModelsCountRowForTest() string {
	return a.settingsRowTextForTest(settingsRowModels)
}

func (a *App) SaveOpenRouterModelCapsForTest(model, prompt, completion string) bool {
	return a.saveOpenRouterModelForTest(model, func(ed *maxPriceEditor) {
		ed.prompt.SetText(prompt)
		ed.completion.SetText(completion)
	})
}

func (a *App) SaveOpenRouterModelForTest(model, prompt, completion, levels string, required bool) bool {
	return a.saveOpenRouterModelForTest(model, func(ed *maxPriceEditor) {
		ed.prompt.SetText(prompt)
		ed.completion.SetText(completion)
		ed.levels.SetText(levels)
		ed.mode.SetCurrentOption(0)
		if required {
			ed.mode.SetCurrentOption(1)
		}
	})
}

func (a *App) saveOpenRouterModelForTest(model string, fill func(*maxPriceEditor)) bool {
	a.OpenRouterModelsForTest()
	pp := a.settingsPicker
	if pp == nil || pp.models == nil {
		return false
	}
	m := pp.models
	key := func(p tview.Primitive, ev *tcell.EventKey) {
		p.InputHandler()(ev, func(p tview.Primitive) { a.app.SetFocus(p) })
	}
	if a.selectOpenRouterModelForTest(model) {
		key(m.table, tcell.NewEventKey(tcell.KeyRune, 'e', tcell.ModNone))
	} else {
		key(m.table, tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone))
		field, ok := a.app.GetFocus().(*tview.InputField)
		if !ok {
			return false
		}
		field.SetText(model)
		i := slices.Index(m.addIDs, model)
		if i < 0 {
			return false
		}
		m.addList.SetCurrentItem(i)
		key(field, tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	}
	ed := pp.maxPrice
	if ed == nil || ed.model != model {
		return false
	}
	fill(ed)
	key(ed.prompt, tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	return true
}

func (a *App) DraftOpenRouterModelCapsForTest(model, prompt, completion string) bool {
	pp := a.settingsPicker
	if pp == nil || pp.maxPrice == nil || pp.maxPrice.model != model {
		return false
	}
	pp.maxPrice.prompt.SetText(prompt)
	pp.maxPrice.completion.SetText(completion)
	return true
}

func (a *App) SubmitOpenRouterModelEditorForTest(model string) bool {
	pp := a.settingsPicker
	if pp == nil || pp.maxPrice == nil || pp.maxPrice.model != model {
		return false
	}
	pp.maxPrice.prompt.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
	return true
}

func (a *App) EditOpenRouterModelForTest(model string) bool {
	a.OpenRouterModelsForTest()
	pp := a.settingsPicker
	if pp == nil || pp.models == nil || !a.selectOpenRouterModelForTest(model) {
		return false
	}
	pp.models.table.InputHandler()(tcell.NewEventKey(tcell.KeyRune, 'e', tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
	return pp.maxPrice != nil && pp.maxPrice.model == model
}

func (a *App) OpenRouterOfferedLevelsForTest() string {
	if pp := a.settingsPicker; pp != nil && pp.maxPrice != nil {
		return pp.maxPrice.offered.GetText(false)
	}
	return ""
}

func (a *App) RemoveOpenRouterModelForTest(model string) bool {
	a.OpenRouterModelsForTest()
	pp := a.settingsPicker
	if pp == nil || pp.models == nil || !a.selectOpenRouterModelForTest(model) {
		return false
	}
	pp.models.table.InputHandler()(tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
	modal, ok := a.pages.GetPage(openRouterModelsRemovePage).(*tview.Modal)
	if !ok {
		return false
	}
	modal.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
	return true
}

func (a *App) selectOpenRouterModelForTest(model string) bool {
	m := a.settingsPicker.models
	for i, row := range m.rows {
		if row.model == model {
			m.table.Select(i+1, 0)
			return true
		}
	}
	return false
}
