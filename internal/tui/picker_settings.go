package tui

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
)

// settingsPickerPage is the Pages name the overlay is mounted under while open;
// settingsDeletePage is the revoke-confirmation modal layered above it, removed when
// the confirm is answered or cancelled while the overlay itself stays mounted.
const (
	settingsPickerPage = "settings-picker"
	settingsDeletePage = "settings-delete"
)

// permGlobalScope is the path_scope value a global (non-folder) grant carries; the
// permissions package enforces path_scope == "*" iff grant_kind == "global", so it also
// splits the two tabs. permKindTool is the subject-kind discriminator for structured-tool
// grants (capability or legacy concrete tool). Both mirror the permissions package's
// on-disk vocabulary, which does not export them.
const (
	permGlobalScope = "*"
	permKindTool    = "tool"
)

const (
	permTabGlobal        = "commands / tool grants"
	permTabFolders       = "folders"
	permTabHosts         = "project hosts"
	permTabOpenRouter      = "openrouter"
	permTabSettings        = "settings"
	permTabIndexFolders    = 1
	permTabIndexHosts      = 2
	permTabIndexOpenRouter = 3
	permTabIndexSettings   = 4
	permTabCount           = 5
)

// settingsFooterHint is the one-row key legend below the list.
const (
	settingsFooterHint      = "tab switch   revoke r   toggle enter   esc close"
	settingsShareFooterHint = "tab switch   revoke r   share s   toggle enter   esc close"
)

const discoveryLaunchDirOnly = "launch-dir-only"

const (
	openRouterNoticePrefix = "openrouter "
	attributionRowLabel    = "attribution"
	dataCollectionRowLabel = "data collection"
	sortRowLabel           = "sort"
	maxPriceRowLabel       = "max price"
	retentionRowLabel      = "session retention (days)"
)

const (
	settingsRowAttribution = iota
	settingsRowDataCollection
	settingsRowSort
	settingsRowMaxPrice
	settingsRowRetention
)

const (
	dataCollectionAllow = "allow"
	sortDefault         = "default"
	sortBestValue       = "best_value"
)

// settingsEmptyRow is the placeholder row shown when a tab has no grants.
const settingsEmptyRow = "(no grants)"

type settingsPickerSession struct {
	global    []PermissionRow
	folders   []PermissionRow
	hosts     []PermissionRow
	activeTab int
	tabBar    *tview.TextView
	list      *tview.List
	help      *tview.TextView
	footer    *tview.TextView
	deps      SettingsDeps
	maxPrice  *maxPriceEditor
	session   SessionSettings
	retention *tview.InputField
}

type maxPriceEditor struct {
	model              string
	prompt, completion *tview.InputField
}

type OpenRouterSettings struct {
	Attribution       func() bool
	SetAttribution    func(bool) error
	DataCollection    func() string
	SetDataCollection func(string) error
	Sort              func() string
	SetSort           func(string) error
	MaxPrice          func(model string) (provider.MaxPrice, bool)
	SetMaxPrice       func(model string, p provider.MaxPrice) error
	ActiveModel       func() (providerID, modelID string)
	SortEstimate      func(model, sortMode string, fetched func()) (provider.OpenRouterEstimate, bool)
}

type SessionSettings struct {
	RetentionDays    func() int
	SetRetentionDays func(int) error
}

type settingsPicker struct {
	app      *App
	settings OpenRouterSettings
	session  SessionSettings
}

func NewSettingsPicker(app *App, settings OpenRouterSettings, session SessionSettings) SettingsPicker {
	return settingsPicker{app: app, settings: settings, session: session}
}

func (p settingsPicker) Present(rows []PermissionRow, deps SettingsDeps) {
	p.app.openRouterSettings = p.settings
	p.app.openSettingsPicker(rows, deps, p.session)
}

func (a *App) openSettingsPicker(rows []PermissionRow, deps SettingsDeps, session SessionSettings) {
	pp := &settingsPickerSession{deps: deps, session: session}
	pp.global, pp.folders, pp.hosts = splitPermissionGrants(rows)
	a.settingsPicker = pp
	a.settingsPickerOpen = true
	a.settingsPickerPrev = a.app.GetFocus()

	pp.tabBar = tview.NewTextView()
	pp.tabBar.SetDynamicColors(true)

	pp.list = tview.NewList()
	// Grant subjects/paths are user-controlled (commands, folder paths) and can contain
	// literal "[tag]" text; disable style-tag parsing so rows render exactly as granted.
	pp.list.SetUseStyleTags(false, false)
	pp.list.ShowSecondaryText(false)
	applyPickerListColors(pp.list)
	pp.list.SetInputCapture(a.settingsPickerKeys)
	// tview calls the changed func before it moves the cursor, so the index argument is the
	// only reliable source for the row now under it.
	pp.list.SetChangedFunc(func(i int, _, _ string, _ rune) {
		pp.updateFooter(i)
		a.updateRowHelp(i)
	})

	pp.help = tview.NewTextView()

	pp.footer = tview.NewTextView()
	pp.footer.SetDynamicColors(false)
	pp.footer.SetText(settingsFooterHint)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(pp.tabBar, 1, 0, false).
		AddItem(tview.NewBox(), 1, 0, false).
		AddItem(pp.list, 0, 1, true).
		AddItem(pp.help, 1, 0, false).
		AddItem(pp.footer, 1, 0, false)
	body.SetBorder(true)
	body.SetTitle(" settings ")

	a.renderSettingsTab()
	a.pages.AddPage(settingsPickerPage, wrapOverlayPage(body), true, true)
	a.app.SetFocus(pp.list)
}

// Backtab is consumed by the app-level capture for mode cycling.
func (a *App) settingsPickerKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyTab, tcell.KeyRight:
		a.stepSettingsTab(1)
		return nil
	case tcell.KeyLeft:
		a.stepSettingsTab(-1)
		return nil
	case tcell.KeyEnter:
		if pp := a.settingsPicker; pp != nil && (pp.activeTab == permTabIndexOpenRouter || pp.activeTab == permTabIndexSettings) {
			if id, ok := settingsRowID(pp.activeTab, pp.list.GetCurrentItem()); ok {
				a.actOnSettingsRow(id)
			}
			return nil
		}
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'r':
			a.showSettingsDelete()
			return nil
		case 's':
			a.showSettingsShare()
			return nil
		}
	}
	return ev
}

func (a *App) attributionOn() bool {
	if a.openRouterSettings.Attribution == nil {
		return true
	}
	return a.openRouterSettings.Attribution()
}

func (a *App) dataCollection() string {
	if a.openRouterSettings.DataCollection == nil {
		return dataCollectionAllow
	}
	return a.openRouterSettings.DataCollection()
}

func (a *App) routingSort() string {
	if a.openRouterSettings.Sort == nil {
		return sortDefault
	}
	return a.openRouterSettings.Sort()
}

// Only the requested tab's rows are built: the OpenRouter sort row can start a credentialed fetch.
func (a *App) settingsTabRows(tab int) []string {
	switch tab {
	case permTabIndexOpenRouter:
		return []string{
			renderAttributionRow(a.attributionOn()),
			renderSettingsRow(dataCollectionRowLabel, a.dataCollection()),
			renderSettingsRow(sortRowLabel, a.sortRowValue()),
			a.maxPriceRow(),
		}
	case permTabIndexSettings:
		return []string{renderSettingsRow(retentionRowLabel, a.retentionRowValue())}
	}
	return nil
}

func settingsRowPlace(id int) (tab, index int) {
	if id == settingsRowRetention {
		return permTabIndexSettings, 0
	}
	return permTabIndexOpenRouter, id
}

func settingsRowID(tab, index int) (int, bool) {
	switch {
	case tab == permTabIndexOpenRouter && index >= settingsRowAttribution && index <= settingsRowMaxPrice:
		return index, true
	case tab == permTabIndexSettings && index == 0:
		return settingsRowRetention, true
	}
	return 0, false
}

func (a *App) retentionRowValue() string {
	pp := a.settingsPicker
	if pp == nil || pp.session.RetentionDays == nil {
		return "default"
	}
	return strconv.Itoa(pp.session.RetentionDays())
}

func (a *App) sortRowValue() string {
	sortMode := a.routingSort()
	label := renderSortValue(sortMode)
	model := a.maxPriceModel()
	if model == "" || a.openRouterSettings.SortEstimate == nil {
		return label
	}
	pp := a.settingsPicker
	est, ok := a.openRouterSettings.SortEstimate(model, sortMode, func() { a.redrawSortRow(pp, model) })
	if !ok {
		return label
	}
	return label + " (" + renderSortEstimate(est) + ")"
}

func (a *App) redrawSortRow(pp *settingsPickerSession, model string) {
	a.streamUpdate(func() {
		if pp == nil || a.settingsPicker != pp || pp.activeTab != permTabIndexOpenRouter || a.maxPriceModel() != model {
			return
		}
		_, i := settingsRowPlace(settingsRowSort)
		pp.list.SetItemText(i, renderSettingsRow(sortRowLabel, a.sortRowValue()), "")
	})
}

func renderSortEstimate(est provider.OpenRouterEstimate) string {
	text := "about $" + estimatePriceText(est.PromptPerM) + " / $" + estimatePriceText(est.CompletionPerM) + " per M"
	if est.Discount > 0 {
		text += ", " + strconv.FormatFloat(math.Floor(discountPercent(est.Discount)+0.5), 'f', 0, 64) + "% off"
	}
	return text
}

// Shifting the decimal point in the shortest decimal text avoids the rounding error of multiplying the float by 100.
func discountPercent(d float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(d, 'f', -1, 64)+"e2", 64)
	return v
}

func estimatePriceText(v float64) string {
	return strings.TrimSuffix(strings.TrimRight(strconv.FormatFloat(v, 'f', 4, 64), "0"), ".")
}

func (a *App) maxPriceModel() string {
	if a.openRouterSettings.ActiveModel == nil {
		return ""
	}
	providerID, modelID := a.openRouterSettings.ActiveModel()
	if providerID != "openrouter" {
		return ""
	}
	return modelID
}

func (a *App) maxPrice(model string) (provider.MaxPrice, bool) {
	if a.openRouterSettings.MaxPrice == nil {
		return provider.MaxPrice{}, false
	}
	return a.openRouterSettings.MaxPrice(model)
}

func (a *App) maxPriceRow() string {
	model := a.maxPriceModel()
	if model == "" {
		return renderSettingsRow(maxPriceRowLabel, "active model is not an OpenRouter model")
	}
	p, ok := a.maxPrice(model)
	if !ok {
		return renderSettingsRow(maxPriceRowLabel+" ("+model+")", "none")
	}
	return renderSettingsRow(maxPriceRowLabel+" ("+model+")",
		"input "+renderPrice(p.Prompt, p.HasPrompt)+" / output "+renderPrice(p.Completion, p.HasCompletion)+" per M tokens")
}

func renderPrice(v float64, set bool) string {
	if !set {
		return "none"
	}
	return "$" + priceText(v, set)
}

func priceText(v float64, set bool) string {
	if !set {
		return ""
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// The repaint re-reads the seam rather than assuming the requested value, so a failed
// write leaves the row at its on-disk state. This runs on the event loop (the picker's
// input capture), so the notice must go through App.Notice, not the background sink.
func (a *App) actOnSettingsRow(row int) {
	s := a.openRouterSettings
	var label string
	var write func() error
	switch row {
	case settingsRowAttribution:
		if s.SetAttribution == nil {
			return
		}
		label, write = attributionRowLabel, func() error { return s.SetAttribution(!a.attributionOn()) }
	case settingsRowDataCollection:
		if s.SetDataCollection == nil {
			return
		}
		next := "deny"
		if a.dataCollection() == "deny" {
			next = dataCollectionAllow
		}
		label, write = dataCollectionRowLabel, func() error { return s.SetDataCollection(next) }
	case settingsRowSort:
		if s.SetSort == nil {
			return
		}
		label, write = sortRowLabel, func() error { return s.SetSort(nextRoutingSort(a.routingSort())) }
	case settingsRowMaxPrice:
		if model := a.maxPriceModel(); s.SetMaxPrice != nil && model != "" {
			a.showMaxPriceEditor(model)
		}
		return
	case settingsRowRetention:
		a.showRetentionEditor()
		return
	default:
		return
	}
	a.writeSettingsRow(row, openRouterNoticePrefix+label, write)
}

func (a *App) writeSettingsRow(row int, label string, write func() error) {
	if err := write(); err != nil {
		a.Notice(renderSettingFailedNotice(label, err))
	}
	a.renderSettingsTab()
	if pp := a.settingsPicker; pp != nil {
		if tab, i := settingsRowPlace(row); tab == pp.activeTab {
			pp.list.SetCurrentItem(i)
			a.updateRowHelp(i)
		}
	}
}

func (a *App) showMaxPriceEditor(model string) {
	pp := a.settingsPicker
	if pp == nil {
		return
	}
	current, _ := a.maxPrice(model)
	ed := &maxPriceEditor{
		model:      model,
		prompt:     newMaxPriceField("input  $ ", priceText(current.Prompt, current.HasPrompt)),
		completion: newMaxPriceField("output $ ", priceText(current.Completion, current.HasCompletion)),
	}
	pp.maxPrice = ed
	for _, field := range []*tview.InputField{ed.prompt, ed.completion} {
		field.SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				a.submitMaxPrice(ed)
			}
		})
		field.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			switch ev.Key() {
			case tcell.KeyTab, tcell.KeyUp, tcell.KeyDown:
				next := ed.prompt
				if field == ed.prompt {
					next = ed.completion
				}
				a.app.SetFocus(next)
				return nil
			}
			return ev
		})
	}
	form := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ed.prompt, 1, 0, true).
		AddItem(ed.completion, 1, 0, false)
	form.SetBorder(true)
	form.SetTitle(" " + tview.Escape(openRouterNoticePrefix+maxPriceRowLabel+" per M tokens ("+model+")") + " ")
	a.pages.AddPage(settingsDeletePage, centeredModal(form), true, true)
	a.app.SetFocus(ed.prompt)
}

func newMaxPriceField(label, text string) *tview.InputField {
	field := tview.NewInputField()
	field.SetLabel(label)
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
	field.SetText(text)
	return field
}

func (a *App) submitMaxPrice(ed *maxPriceEditor) {
	a.cancelSettingsDelete()
	var p provider.MaxPrice
	var err error
	if p.Prompt, p.HasPrompt, err = parsePriceField("input", ed.prompt.GetText()); err == nil {
		p.Completion, p.HasCompletion, err = parsePriceField("output", ed.completion.GetText())
	}
	if err != nil {
		a.Notice(renderSettingFailedNotice(openRouterNoticePrefix+maxPriceRowLabel, err))
		return
	}
	a.writeSettingsRow(settingsRowMaxPrice, openRouterNoticePrefix+maxPriceRowLabel, func() error {
		return a.openRouterSettings.SetMaxPrice(ed.model, p)
	})
}

func (a *App) showRetentionEditor() {
	pp := a.settingsPicker
	if pp == nil || pp.session.RetentionDays == nil || pp.session.SetRetentionDays == nil {
		return
	}
	field := newMaxPriceField("days ", strconv.Itoa(pp.session.RetentionDays()))
	pp.retention = field
	field.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			a.submitRetention(field.GetText())
		}
	})
	form := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(field, 1, 0, true)
	form.SetBorder(true)
	form.SetTitle(" " + retentionRowLabel + " ")
	a.pages.AddPage(settingsDeletePage, centeredModal(form), true, true)
	a.app.SetFocus(field)
}

func (a *App) submitRetention(text string) {
	a.cancelSettingsDelete()
	pp := a.settingsPicker
	if pp == nil {
		return
	}
	text = strings.TrimSpace(text)
	days, err := strconv.Atoi(text)
	if err != nil || days < 1 {
		a.Notice(renderSettingFailedNotice(retentionRowLabel, fmt.Errorf("%q is not a whole number of at least 1", text)))
		return
	}
	write := func() {
		a.writeSettingsRow(settingsRowRetention, retentionRowLabel, func() error { return pp.session.SetRetentionDays(days) })
	}
	if days >= pp.session.RetentionDays() {
		write()
		return
	}
	a.showSettingsConfirm(retentionConfirmText(days), "Lower", func() {
		write()
		a.refocusSettingsList()
	})
}

func retentionConfirmText(days int) string {
	return "Sessions not updated in the last " + strconv.Itoa(days) + " days become eligible for automatic deletion at the next fresh interactive launch. Resuming a session does not start pruning."
}

func parsePriceField(name, text string) (float64, bool, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, false, fmt.Errorf("%s %q is not a number of at least 0", name, text)
	}
	return v, true, nil
}

func nextRoutingSort(current string) string {
	switch current {
	case sortDefault:
		return "throughput"
	case "throughput":
		return sortBestValue
	}
	return sortDefault
}

func renderSortValue(v string) string {
	if v == sortBestValue {
		return "best value"
	}
	return v
}

func sortHelp(v string) string {
	switch v {
	case sortDefault:
		return "OpenRouter's normal routing: healthy providers, cheaper ones picked more often"
	case "throughput":
		return "Fastest providers first, whatever the price"
	case sortBestValue:
		return "Fastest at typical speed or better, within 20% of the cheapest at that speed"
	}
	return "Set in the settings file; Enter switches to default"
}

func (a *App) updateRowHelp(i int) {
	pp := a.settingsPicker
	if pp == nil || pp.help == nil {
		return
	}
	text := ""
	if id, ok := settingsRowID(pp.activeTab, i); ok {
		text = a.settingsRowHelp(id)
	}
	pp.help.SetText(text)
}

func (a *App) settingsRowHelp(id int) string {
	switch id {
	case settingsRowAttribution:
		return "Identify codemeld to OpenRouter on chat requests (app URL, name, categories)"
	case settingsRowDataCollection:
		return "allow: may use providers that store or train on prompts; deny: avoid them"
	case settingsRowSort:
		return sortHelp(a.routingSort())
	case settingsRowMaxPrice:
		return "Input/output price caps per M tokens for OpenRouter models; empty: no cap"
	case settingsRowRetention:
		return "Idle days before auto-deletion; pruning runs at a fresh launch, not on resume"
	}
	return ""
}

func renderSettingFailedNotice(label string, err error) string {
	return "couldn't change the " + label + " setting: " + fserrors.CollapseControls(err.Error())
}

func (a *App) stepSettingsTab(delta int) {
	pp := a.settingsPicker
	if pp == nil {
		return
	}
	pp.activeTab = ((pp.activeTab+delta)%permTabCount + permTabCount) % permTabCount
	a.renderSettingsTab()
}

// renderSettingsTab repaints the tab bar (highlighting the active tab) and rebuilds the
// list from the active tab's grants, showing the empty placeholder when the tab has none.
func (a *App) renderSettingsTab() {
	pp := a.settingsPicker
	if pp == nil {
		return
	}
	pp.tabBar.SetText(settingsTabBar(pp.activeTab))
	pp.list.Clear()
	switch rows := pp.activeRows(); {
	case pp.activeTab == permTabIndexOpenRouter || pp.activeTab == permTabIndexSettings:
		for _, row := range a.settingsTabRows(pp.activeTab) {
			pp.list.AddItem(row, "", 0, nil)
		}
	case len(rows) == 0:
		pp.list.AddItem(settingsEmptyRow, "", 0, nil)
	default:
		for _, row := range rows {
			pp.list.AddItem(renderPermissionRow(row), "", 0, nil)
		}
	}
	a.updateRowHelp(pp.list.GetCurrentItem())
}

func (pp *settingsPickerSession) updateFooter(i int) {
	if pp.footer == nil {
		return
	}
	hint := settingsFooterHint
	if row, ok := pp.rowAt(i); ok && pp.shareable(row) {
		hint = settingsShareFooterHint
	}
	pp.footer.SetText(hint)
}

func (pp *settingsPickerSession) shareable(row PermissionRow) bool {
	return pp.deps.Share != nil && pp.deps.Approved && row.Layer == permissions.LayerLocal
}

// dismissSettingsPicker removes the overlay and restores focus to whatever held it when
// the picker opened (the input area in production). The input buffer is never touched. It
// is idempotent and nils the per-open state.
func (a *App) dismissSettingsPicker() {
	if !a.settingsPickerOpen {
		return
	}
	a.settingsPickerOpen = false
	a.pages.RemovePage(settingsDeletePage)
	a.closeOverlayPage(settingsPickerPage, &a.settingsPickerPrev)
	a.settingsPicker = nil
}

func splitPermissionGrants(rows []PermissionRow) (global, folders, hosts []PermissionRow) {
	for _, row := range rows {
		switch {
		case permissionIsHostGrant(row.Entry):
			hosts = append(hosts, row)
		case permissionIsFolderGrant(row.Entry):
			folders = append(folders, row)
		default:
			global = append(global, row)
		}
	}
	sortPermissionRows(global)
	sortPermissionRows(folders)
	sortPermissionRows(hosts)
	return global, folders, hosts
}

func sortPermissionRows(rows []PermissionRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := strings.ToLower(renderPermissionEntry(rows[i].Entry)), strings.ToLower(renderPermissionEntry(rows[j].Entry))
		if a != b {
			return a < b
		}
		if rows[i].Layer != rows[j].Layer {
			return rows[i].Layer < rows[j].Layer
		}
		return rows[i].Path < rows[j].Path
	})
}

func samePermissionRow(a, b PermissionRow) bool {
	return a.Layer == b.Layer && a.Path == b.Path && a.Entry.DedupKey() == b.Entry.DedupKey()
}

// Returning no grants for the openrouter and settings tabs is what keeps revoke and cursor restore inert
// there, without each of them re-testing the tab.
func (pp *settingsPickerSession) activeRows() []PermissionRow {
	switch pp.activeTab {
	case permTabIndexFolders:
		return pp.folders
	case permTabIndexHosts:
		return pp.hosts
	case permTabIndexOpenRouter, permTabIndexSettings:
		return nil
	}
	return pp.global
}

func (a *App) settingsList() (*settingsPickerSession, *tview.List) {
	pp := a.settingsPicker
	if pp == nil || pp.list == nil {
		return nil, nil
	}
	return pp, pp.list
}

// settingsHighlightedRow returns the grant under the list cursor on the active tab, or
// ok=false when the tab is empty (the placeholder row backs no grant, so it cannot be revoked).
func (a *App) settingsHighlightedRow() (PermissionRow, bool) {
	pp, list := a.settingsList()
	if pp == nil {
		return PermissionRow{}, false
	}
	return pp.rowAt(list.GetCurrentItem())
}

func (pp *settingsPickerSession) rowAt(i int) (PermissionRow, bool) {
	rows := pp.activeRows()
	if i < 0 || i >= len(rows) {
		return PermissionRow{}, false
	}
	return rows[i], true
}

// showSettingsDelete layers a revoke confirmation over the overlay for the highlighted
// grant: Revoke calls the injected seam then refreshes; Cancel leaves everything untouched.
// ESC is not captured on the modal — the settingsPicker roster dismissal cancels the confirm
// while the overlay stays open (see overlays.go). It is inert when no revoke seam is wired or
// no grant is highlighted, so an empty tab's placeholder can never be revoked.
func (a *App) showSettingsDelete() {
	pp := a.settingsPicker
	if pp == nil || pp.deps.Revoke == nil {
		return
	}
	row, ok := a.settingsHighlightedRow()
	if !ok {
		return
	}
	text, action := revokeConfirmText(row)
	a.showSettingsConfirm(text, action, func() { a.applySettingsRevoke(row) })
}

func revokeConfirmText(row PermissionRow) (text, action string) {
	if row.Layer != permissions.LayerProject {
		return "Revoke this grant?\n\n" + tview.Escape(renderPermissionRow(row)), "Revoke"
	}
	return "Remove this shared grant?\n\n" + shareConfirmFact(renderPermissionEntry(row.Entry)) +
		"\n\nIt is removed from " + shareConfirmFact(row.Path) +
		" for everyone who pulls the repository.", "Remove"
}

func (a *App) showSettingsShare() {
	pp := a.settingsPicker
	if pp == nil {
		return
	}
	row, ok := a.settingsHighlightedRow()
	if !ok || !pp.shareable(row) {
		return
	}
	a.showSettingsConfirm(shareConfirmText(row.Entry, a.refProjectRoot()), "Share", func() { a.applySettingsShare(row) })
}

// shareConfirmText escapes every fact because tview.Modal parses style tags.
func shareConfirmText(e permissions.PermissionEntry, projectRoot string) string {
	var b strings.Builder
	b.WriteString("Share this grant with the team?\n\n")
	b.WriteString(shareConfirmFact(renderPermissionEntry(e)))
	switch {
	case permissionIsHostGrant(e):
		b.WriteString("\n\nIt authorizes network access to " + shareConfirmFact(e.HostScope) + ".")
	case permissionIsFolderGrant(e):
		b.WriteString("\n\nIt covers the folder " + shareConfirmFact(e.PathScope) + ".")
		if projectRoot == "" || !permissions.IsDescendantOrEqual(e.PathScope, projectRoot) {
			b.WriteString(" That folder is outside this project.")
		}
	}
	b.WriteString("\n\nEveryone who approves this repository receives it.")
	return b.String()
}

func shareConfirmFact(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, "\\x%02X", r)
			continue
		}
		b.WriteRune(r)
	}
	return tview.Escape(b.String())
}

func (a *App) showSettingsConfirm(text, action string, apply func()) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{action, "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			a.pages.RemovePage(settingsDeletePage)
			if label == action {
				apply()
				return
			}
			a.refocusSettingsList()
		})
	// The terminal-default theme flattens PrimaryTextColor and ContrastBackgroundColor both to
	// ColorDefault, which collapses tview.Modal's focused-button background (PrimaryTextColor)
	// onto its unfocused-button background (ContrastBackgroundColor) — so in a real terminal the
	// selected action is indistinguishable and looks unmovable. Draw the focused button in
	// reverse video, the same terminal-agnostic highlight applyPickerListColors uses for list
	// cursors, so the active choice reads on both light and dark backgrounds.
	modal.SetButtonActivatedStyle(tcell.StyleDefault.Reverse(true))
	// tview.Modal only moves between buttons on Tab/Backtab; the app-level capture consumes
	// Backtab for mode cycling and arrows are inert on modal buttons, so ←/→ (and ↑/↓) would
	// otherwise never switch buttons. Route them to the Tab/Backtab the button row understands
	// so the destructive confirmation is navigable with the arrow keys a user reaches for.
	modal.SetInputCapture(permissionsDeleteKeys)
	a.pages.AddPage(settingsDeletePage, modal, true, true)
	a.app.SetFocus(modal)
}

// permissionsDeleteKeys maps the arrow keys a user reaches for on the revoke confirmation onto
// the Tab/Backtab that tview.Modal's button row actually navigates on: →/↓ advance to the next
// button, ←/↑ step back. Enter (activate) and every other key pass through unchanged; ESC never
// reaches here — the app-level capture routes it to the central dismiss path first.
func permissionsDeleteKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyLeft, tcell.KeyUp:
		return tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone)
	case tcell.KeyRight, tcell.KeyDown:
		return tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone)
	}
	return ev
}

// applySettingsRevoke revokes entry through the seam and re-reads the live grants. The
// seam owns file/cache removal and surfaces its own skip/failure notice, so this makes no
// row decision of its own: a successful revoke drops the row via the refreshed list, and a
// skipped one leaves it (the live grant is still there).
func (a *App) applySettingsRevoke(row PermissionRow) {
	pp := a.settingsPicker
	if pp == nil {
		return
	}
	prev := 0
	if pp.list != nil {
		prev = pp.list.GetCurrentItem()
	}
	if pp.deps.Revoke != nil {
		pp.deps.Revoke(row)
	}
	a.refreshSettingsRows()
	a.restoreSettingsCursor(prev, row)
	a.refocusSettingsList()
}

// This runs on the event loop, so the notice must go through App.Notice, not the background sink.
func (a *App) applySettingsShare(row PermissionRow) {
	pp := a.settingsPicker
	if pp == nil || !pp.shareable(row) {
		return
	}
	prev := pp.list.GetCurrentItem()
	a.Notice(renderShareOutcome(pp.deps.Share(row), pp.deps.Boundary))
	a.refreshSettingsRows()
	a.restoreSettingsCursor(prev, row)
	a.refocusSettingsList()
}

// renderShareOutcome joins the marker and failure notices because the notice area holds one
// message and both must reach the user.
func renderShareOutcome(res ShareResult, boundary string) string {
	if res.Refused {
		return RenderShareRefusedNotice()
	}
	if res.SharedErr != nil {
		return RenderShareFailedNotice(res.SharedPath, res.SharedErr.Error())
	}
	var lines []string
	if res.SharedCreated {
		path := permissions.BoundPromptFact(res.SharedPath)
		if boundary == discoveryLaunchDirOnly {
			lines = append(lines, RenderCrossModeMarkerNotice(path))
		} else {
			lines = append(lines, RenderProjectRootMarkerNotice(path))
		}
	}
	if res.LocalErr != nil {
		lines = append(lines, RenderShareLocalRemovalFailedNotice(res.SharedPath, res.LocalPath, res.LocalErr.Error(), res.SharedSkipped))
	}
	return strings.Join(lines, "\n")
}

func (a *App) restoreSettingsCursor(prev int, row PermissionRow) {
	pp, list := a.settingsList()
	if pp == nil {
		return
	}
	rows := pp.activeRows()
	if len(rows) == 0 {
		return
	}
	want := prev - 1
	for _, r := range rows {
		if samePermissionRow(r, row) {
			want = prev
			break
		}
	}
	if want < 0 {
		want = 0
	}
	if want >= len(rows) {
		want = len(rows) - 1
	}
	list.SetCurrentItem(want)
}

// refreshSettingsRows re-sources the grants from the live list and repaints the active
// tab, so the row set matches what the revoke seam actually removed.
func (a *App) refreshSettingsRows() {
	pp := a.settingsPicker
	if pp == nil || pp.deps.Rows == nil {
		return
	}
	pp.global, pp.folders, pp.hosts = splitPermissionGrants(pp.deps.Rows())
	a.renderSettingsTab()
}

// refocusSettingsList returns focus to the grants list if the overlay is still open.
func (a *App) refocusSettingsList() {
	if _, list := a.settingsList(); list != nil {
		a.app.SetFocus(list)
	}
}

// cancelSettingsDelete removes the revoke-confirmation modal and refocuses the list
// without revoking anything. The central ESC path calls it so ESC cancels the confirm
// rather than dismissing the whole overlay.
func (a *App) cancelSettingsDelete() {
	a.pages.RemovePage(settingsDeletePage)
	a.refocusSettingsList()
}

// RevokeHighlightedPermissionForTest revokes the highlighted grant exactly as the confirm's
// Revoke button does — a seam for bootstrap tests that drive the real revoke without a
// terminal. It returns false when the overlay is closed or the highlighted row backs no grant.
func (a *App) RevokeHighlightedPermissionForTest() bool {
	row, ok := a.settingsHighlightedRow()
	if !ok {
		return false
	}
	a.applySettingsRevoke(row)
	return true
}

func (a *App) SelectPermissionForTest(entry permissions.PermissionEntry) bool {
	pp := a.settingsPicker
	if pp == nil {
		return false
	}
	switch {
	case permissionIsHostGrant(entry):
		pp.activeTab = permTabIndexHosts
	case permissionIsFolderGrant(entry):
		pp.activeTab = permTabIndexFolders
	default:
		pp.activeTab = 0
	}
	a.renderSettingsTab()
	for i, candidate := range pp.activeRows() {
		if candidate.Entry.DedupKey() == entry.DedupKey() {
			pp.list.SetCurrentItem(i)
			return true
		}
	}
	return false
}

func (a *App) ToggleAttributionForTest() string {
	return a.pressEnterOnSettingsRowForTest(settingsRowAttribution)
}

func (a *App) ToggleDataCollectionForTest() string {
	return a.pressEnterOnSettingsRowForTest(settingsRowDataCollection)
}

func (a *App) StepSortForTest() string {
	return a.pressEnterOnSettingsRowForTest(settingsRowSort)
}

func (a *App) ShowSettingsTabForTest() bool {
	return a.showSettingsTabForTest(permTabIndexSettings)
}

func (a *App) ShowOpenRouterTabForTest() bool {
	return a.showSettingsTabForTest(permTabIndexOpenRouter)
}

func (a *App) showSettingsTabForTest(tab int) bool {
	pp := a.settingsPicker
	if pp == nil {
		return false
	}
	pp.activeTab = tab
	a.renderSettingsTab()
	return true
}

func (a *App) SortRowForTest() string {
	pp := a.settingsPicker
	tab, i := settingsRowPlace(settingsRowSort)
	if pp == nil || pp.activeTab != tab {
		return ""
	}
	main, _ := pp.list.GetItemText(i)
	return main
}

func (a *App) SetMaxPriceForTest(prompt, completion string) string {
	a.pressEnterOnSettingsRowForTest(settingsRowMaxPrice)
	if pp := a.settingsPicker; pp != nil && pp.maxPrice != nil && a.pages.HasPage(settingsDeletePage) {
		pp.maxPrice.prompt.SetText(prompt)
		pp.maxPrice.completion.SetText(completion)
		a.submitMaxPrice(pp.maxPrice)
	}
	return a.settingsRowTextForTest(settingsRowMaxPrice)
}

func (a *App) SetRetentionForTest(text string, confirm bool) string {
	a.pressEnterOnSettingsRowForTest(settingsRowRetention)
	if pp := a.settingsPicker; pp != nil && pp.retention != nil && a.pages.HasPage(settingsDeletePage) {
		pp.retention.SetText(text)
		pp.retention.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
		if a.pages.HasPage(settingsDeletePage) {
			key := tcell.KeyEscape
			if confirm {
				key = tcell.KeyEnter
			}
			if h := a.app.GetFocus().InputHandler(); h != nil {
				h(tcell.NewEventKey(key, 0, tcell.ModNone), func(p tview.Primitive) { a.app.SetFocus(p) })
			}
		}
	}
	return a.settingsRowTextForTest(settingsRowRetention)
}

func (a *App) pressEnterOnSettingsRowForTest(row int) string {
	pp := a.settingsPicker
	if pp == nil {
		return ""
	}
	tab, i := settingsRowPlace(row)
	pp.activeTab = tab
	a.renderSettingsTab()
	pp.list.SetCurrentItem(i)
	a.settingsPickerKeys(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	return a.settingsRowTextForTest(row)
}

func (a *App) settingsRowTextForTest(row int) string {
	tab, i := settingsRowPlace(row)
	return a.settingsTabRows(tab)[i]
}

func renderAttributionRow(on bool) string {
	if on {
		return renderSettingsRow(attributionRowLabel, "on")
	}
	return renderSettingsRow(attributionRowLabel, "off")
}

func renderSettingsRow(label, value string) string {
	return label + "   " + value
}

func settingsTabBar(activeTab int) string {
	labels := []string{permTabGlobal, permTabFolders, permTabHosts, permTabOpenRouter, permTabSettings}
	if activeTab < 0 || activeTab >= len(labels) {
		activeTab = 0
	}
	for i, label := range labels {
		if i == activeTab {
			labels[i] = settingsActiveTab(label)
		} else {
			labels[i] = "[" + chromeOnFillText + ":" + statusSegmentBody1 + ":]" + label + "[-:-:-]"
		}
	}
	return strings.Join(labels, " │ ")
}

func settingsActiveTab(label string) string {
	return "[" + chromeOnFillText + ":" + accentTealHex + ":b]" + label + "[-:-:-]"
}

// permissionIsFolderGrant reports whether e is scoped to a specific folder (folders tab)
// rather than granted globally (commands/tool grants tab).
func permissionIsFolderGrant(e permissions.PermissionEntry) bool {
	return e.PathScope != "" && e.PathScope != permGlobalScope
}

func permissionIsHostGrant(e permissions.PermissionEntry) bool {
	return e.HostScope != ""
}

func renderPermissionRow(row PermissionRow) string {
	label := renderPermissionEntry(row.Entry)
	if row.Layer == "" {
		return label
	}
	return label + " — " + row.Path + " [" + string(row.Layer) + "]"
}

func renderPermissionEntry(e permissions.PermissionEntry) string {
	if permissionIsHostGrant(e) {
		return "allow the " + e.Subject + " tool — " + e.HostScope
	}
	return permissionSubjectPhrase(e) + " — " + permissionScopePhrase(e)
}

// permissionSubjectPhrase renders the "what" of a grant. A capability tool subject
// (write / read*) renders through the shared CapabilityCoveragePhrase so the wording and
// member list cannot drift from the matcher's source of truth; a legacy concrete tool
// subject (create, edit, grep, glob, list, tree, read, file_count) names the tool so old
// grants stay understandable; a direct/literal subject is the command line itself.
func permissionSubjectPhrase(e permissions.PermissionEntry) string {
	if e.Kind == permKindTool {
		if phrase := CapabilityCoveragePhrase(e.Subject); phrase != "" {
			return "allow " + phrase
		}
		return "allow the " + e.Subject + " tool"
	}
	return "run " + e.Subject
}

// permissionScopePhrase renders the "where" of a grant: the folder path for a folder-scoped
// grant, or "globally" for a global one.
func permissionScopePhrase(e permissions.PermissionEntry) string {
	if !permissionIsFolderGrant(e) {
		return "globally"
	}
	return "in " + e.PathScope
}
