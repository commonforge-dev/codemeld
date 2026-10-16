// CTRL-M model picker overlay: a single-column table of the provider×model
// cross-product of the composed config — models grouped under
// a non-selectable, bold provider header — with an inline ←/→
// reasoning-effort control scoped to the
// highlighted model's supported set, the per-project settings-write path
// (and the cross-mode marker disclosure when the write would create a launch-
// directory marker), and a footer hint. A confirmed selection applies the
// chosen provider/model/effort through the provider-aware non-slash apply path —
// the same persistence/event flow /model uses, without emitting a
// slash_command — and the confirmation (plus any marker disclosure) lands as
// permanent session-transcript lines.
package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// modelPickerPage is the Pages name the model picker overlay is mounted under
// while open, removed when it dismisses.
const modelPickerPage = "model-picker"

// modelPickerSession holds the open picker's live state: the cross-product rows,
// the highlighted model's currently supported effort set, the selected effort, and
// the inline effort control to re-render. The effort selection is tracked here (not
// read live off in-memory state) so it can be confirmed on Enter ("effort
// source on confirm matches picker UI selection") and reconciled as the highlighted
// model changes.
//
// dataByRow maps each table row to its index in rows, or -1 for a non-selectable
// provider header row. The provider headers shift table indexes away from the flat
// rows indexes, so selection-changed, Enter, and effort refresh resolve the model
// through this mapping rather than indexing rows by table position directly.
// The full cross-product is kept in rows so the type-to-filter field can
// rebuild the visible table from any query without re-reading the catalog; cat is
// held for the same reason, to recompute a highlighted model's supported efforts
// after a filtered rebuild moves the selection. query is the current filter text,
// table and field are the live tview handles the filter path drives, and dataByRow
// maps each *visible* table row to its index in the full rows (or -1 for a header /
// spacer) so confirm always resolves the original ProviderModel, never a display
// label or a filtered-set position.
type modelPickerSession struct {
	rows         []ProviderModel
	favorites    []ModelFavorite
	dataByRow    []int
	supported    []string
	effort       string
	effortView   *tview.TextView
	cat          ProviderModelCatalog
	query        string
	table        *tview.Table
	field        *tview.InputField
	requested    map[string]bool
	status       *tview.TextView
	refreshToken int
	refreshOwner int
}

// openModelPicker opens the model picker overlay. It is a no-op while
// another overlay is open and while no provider-aware surface is wired
// (CTRL-M stays inert until the deps are injected). Unlike the effort picker it
// opens even when no model is selected in memory — it is how the first model is
// chosen.
func (a *App) openModelPicker() {
	if a.anyOverlayOpen() {
		return
	}
	cat := a.modelPickerDeps.Catalog
	if cat == nil {
		return
	}
	rows := cat.ProviderModels()
	provider, modelID, effort, ok := cat.ActiveSelection()
	initialRow := 0
	if ok {
		if i := modelRowIndex(rows, provider, modelID); i >= 0 {
			initialRow = i
		}
	}
	inMemEffort := ""
	if ok {
		inMemEffort = effort
	}
	overlay, _ := a.buildModelPicker(rows, initialRow, inMemEffort, cat.SettingsTarget(), cat)
	a.modelPickerOpen = true
	a.modelPickerPrev = a.app.GetFocus()
	// Center the bordered body in a small dialog (~50% width / ~60% height) rather
	// than letting it stretch edge to edge; the overlayBackground wrapper still paints
	// the full-screen opaque backdrop, so the area around the box is blank.
	a.pages.AddPage(modelPickerPage, wrapOverlayPage(centeredModal(overlay)), true, true)
	// Focus the filter field (not the table): typing narrows the list while ↑/↓/←/→/
	// Enter/Esc are routed from the field, mirroring the '@' file picker.
	a.app.SetFocus(a.modelPicker.field)
}

// OpenModelPicker opens the provider-aware model picker overlay from
// outside the global CTRL-M key path. It is the narrow seam bootstrap drives for the
// two non-keyboard routes into the picker: the path-4 launch outcome
// and an in-TUI /resume recovery failure. It delegates to openModelPicker so the
// overlay/no-deps guards stay the single implementation — it is therefore
// inert until the model-picker deps are installed, exactly like CTRL-M.
func (a *App) OpenModelPicker() { a.openModelPicker() }

// ConfirmModelRowForTest runs Enter-on-a-row for row without the overlay, so a cross-package
// test can drive the CTRL-M confirm path over production deps the way SelectConnectProviderForTest
// drives /connect. Production reaches confirmModelSelection through the key path.
func (a *App) ConfirmModelRowForTest(row ProviderModel, effort string) {
	a.confirmModelSelection(row, effort)
}

// ModelPickerOpen reports whether the model picker overlay is currently mounted. It
// is the observable bootstrap's StartTUI assembly test reads to prove the launch
// picker-required outcome opened the picker through OpenModelPicker; production code
// drives the picker through the key path and never needs to poll this.
func (a *App) ModelPickerOpen() bool { return a.modelPickerOpen }

// ModelPickerStatusText returns the open picker's in-box refresh status row, or ""
// when no picker is open. Like ModelPickerRows it is a read-only cross-package test
// seam; production writes the row and never polls it.
func (a *App) ModelPickerStatusText() string { return a.modelPicker.statusText() }

// ModelPickerRows returns the provider×model rows the CTRL-M picker is currently
// displaying. While the overlay is open it reads the live session rows — the same
// slice rebuildModelPickerFromCatalog refreshes — so a test observes the visible
// overlay state, not just the underlying cache; a refresh that reloads the cache
// without rebuilding the session leaves this stale, which is the assertion the
// StartTUI refresh test relies on. When no picker session is open it falls back to
// the live selectable catalog (the list openModelPicker would build from). It
// returns nil when the provider-aware deps are not yet wired. Production drives the
// picker through the key path and never polls this.
func (a *App) ModelPickerRows() []ProviderModel {
	if a.modelPickerOpen && a.modelPicker != nil {
		return a.modelPicker.rows
	}
	cat := a.modelPickerDeps.Catalog
	if cat == nil {
		return nil
	}
	return cat.ProviderModels()
}

// centeredModal wraps inner in a small centered dialog: nested tview.Flex layers
// with nil spacers give the inner primitive ~40% of the width (outer columns
// 3:4:3) and ~60% of the height (inner rows 1:3:1), so the model picker no longer
// claims the whole screen on a wide terminal. Focus delegates through both Flex
// layers to inner (the middle column and middle row are the focused items), and the
// surrounding overlayBackground wrapper still paints the full-screen opaque backdrop
// around the box.
func centeredModal(inner tview.Primitive) tview.Primitive {
	return tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(nil, 0, 3, false).
		AddItem(tview.NewFlex().
			SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(inner, 0, 3, true).
			AddItem(nil, 0, 1, false), 0, 4, true).
		AddItem(nil, 0, 3, false)
}

func (a *App) buildModelPicker(rows []ProviderModel, initialRow int, inMemEffort string, target ModelSettingsTarget, cat ProviderModelCatalog) (tview.Primitive, *tview.Table) {
	modelTable := tview.NewTable()
	// Whole-row selection over a single column; provider headers are individually
	// non-selectable so keyboard navigation skips them.
	modelTable.SetSelectable(true, false)
	applyPickerTableColors(modelTable)

	if initialRow < 0 || initialRow >= len(rows) {
		initialRow = 0
	}

	effortView := tview.NewTextView()
	effortView.SetDynamicColors(true)

	field := tview.NewInputField()
	field.SetLabel(modelFilterLabel)
	// No accent on the label — inherit the terminal default rather than tview's
	// built-in yellow, consistent with the terminal-default theme.
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))

	status := tview.NewTextView()
	status.SetDynamicColors(false)

	sess := &modelPickerSession{rows: rows, favorites: a.currentFavorites(), effortView: effortView, cat: cat, table: modelTable, field: field, requested: map[string]bool{}, status: status}
	a.modelPicker = sess

	// Seed the unfiltered table (empty query) and the initial highlight/effort before
	// installing the changed func, so the seed cannot fire a spurious refresh
	// (tview.Table.Select invokes the changed func).
	favOrder := favoriteAliasOrder(rows, sess.favorites, "")
	if len(favOrder) > 0 {
		initialRow = favOrder[0]
	}
	dataByRow, firstModelRow, initialTableRow := populateModelTable(modelTable, rows, favOrder, sortedRowOrder(rows), initialRow)
	sess.dataByRow = dataByRow
	if len(favOrder) > 0 {
		initialTableRow = slices.Index(dataByRow, favOrder[0])
	}
	if initialTableRow < 0 {
		initialTableRow = firstModelRow
	}
	if len(rows) > 0 {
		sess.supported = cat.SupportedEfforts(rows[initialRow].Provider, rows[initialRow].ModelID)
		sess.effort = modelPickerEffortFor(sess.supported, inMemEffort)
		modelTable.Select(initialTableRow, 0)
		a.keepModelHeaderVisible(initialTableRow)
	}
	a.renderModelEffort()

	modelTable.SetSelectionChangedFunc(func(row, _ int) {
		a.refreshHighlightedModel(sess.dataIndex(row))
		a.keepModelHeaderVisible(row)
	})

	modelTable.SetSelectedFunc(func(row, _ int) {
		di := sess.dataIndex(row)
		if di < 0 {
			return
		}
		a.confirmModelSelection(sess.rows[di], sess.effort)
	})

	// The filter field owns focus; each keystroke re-ranks the table, and ↑/↓/←/→/
	// Enter/Esc are routed from the field so no separate focus toggle is needed.
	field.SetChangedFunc(func(text string) { a.onModelFilterChanged(text) })
	field.SetInputCapture(a.modelPickerFieldKeys)
	// Mouse click on a model row still confirms it (the field keeps keyboard focus).
	modelTable.SetInputCapture(a.modelPickerKeys())

	info := tview.NewTextView()
	info.SetDynamicColors(false)
	infoText := renderModelSettingsInfo(target)
	info.SetText(infoText)

	footer := tview.NewTextView()
	footer.SetDynamicColors(false)
	footer.SetText(modelPickerFooterHint)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(field, 1, 0, true).
		AddItem(modelTable, 0, 1, false).
		AddItem(nil, 1, 0, false).
		AddItem(effortView, 1, 0, false).
		AddItem(info, modelInfoHeight(infoText), 0, false).
		AddItem(status, 1, 0, false).
		AddItem(footer, 1, 0, false)
	body.SetBorder(true)
	body.SetTitle(" model picker ")

	if len(rows) > 0 {
		a.requestProviderRefresh(rows[initialRow].Provider, false)
	}
	for _, cp := range cat.ConfiguredProviders() {
		if !providerHasRows(rows, cp.Provider) {
			a.requestProviderRefresh(cp.Provider, false)
		}
	}
	return body, modelTable
}

// modelFilterLabel is the filter field's prompt label. It carries terminal-default
// styling (no yellow accent) to match the theme cleanup.
const modelFilterLabel = "filter: "

func identityRowOrder(n int) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	return order
}

func sortedRowOrder(rows []ProviderModel) []int {
	rank := map[string]int{}
	for _, r := range rows {
		if _, ok := rank[r.Provider]; !ok {
			rank[r.Provider] = len(rank)
		}
	}
	order := identityRowOrder(len(rows))
	slices.SortStableFunc(order, func(a, b int) int {
		if d := rank[rows[a].Provider] - rank[rows[b].Provider]; d != 0 {
			return d
		}
		return strings.Compare(rows[a].ModelID, rows[b].ModelID)
	})
	return order
}

func populateModelTable(tbl *tview.Table, rows []ProviderModel, favOrder, order []int, wantFull int) (dataByRow []int, firstModelRow, wantTableRow int) {
	tbl.Clear()
	dataByRow = make([]int, 0, len(favOrder)+len(order))
	firstModelRow, wantTableRow = -1, -1
	if len(favOrder) > 0 {
		hdrRow := tbl.GetRowCount()
		tbl.SetCell(hdrRow, 0, tview.NewTableCell(favoritesHeaderLabel).
			SetSelectable(false).
			SetStyle(tcell.StyleDefault.Bold(true)))
		dataByRow = append(dataByRow, -1)
		for _, i := range favOrder {
			favRow := tbl.GetRowCount()
			tbl.SetCell(favRow, 0, tview.NewTableCell(favoriteAliasLabel(rows[i])).
				SetReference(i).
				SetExpansion(1))
			dataByRow = append(dataByRow, i)
		}
		spacerRow := tbl.GetRowCount()
		tbl.SetCell(spacerRow, 0, tview.NewTableCell("").SetSelectable(false))
		dataByRow = append(dataByRow, -1)
	}
	prevProvider := ""
	for _, i := range order {
		r := rows[i]
		if r.Provider != prevProvider {
			if prevProvider != "" {
				spacerRow := tbl.GetRowCount()
				tbl.SetCell(spacerRow, 0, tview.NewTableCell("").SetSelectable(false))
				dataByRow = append(dataByRow, -1)
			}
			hdrRow := tbl.GetRowCount()
			tbl.SetCell(hdrRow, 0, tview.NewTableCell(providerHeaderLabel(r)).
				SetSelectable(false).
				SetStyle(tcell.StyleDefault.Bold(true)))
			dataByRow = append(dataByRow, -1)
			prevProvider = r.Provider
		}
		modelRow := tbl.GetRowCount()
		tbl.SetCell(modelRow, 0, tview.NewTableCell(r.ModelID).
			SetReference(i).
			SetExpansion(1))
		dataByRow = append(dataByRow, i)
		if firstModelRow < 0 {
			firstModelRow = modelRow
		}
		if i == wantFull {
			wantTableRow = modelRow
		}
	}
	return dataByRow, firstModelRow, wantTableRow
}

func (s *modelPickerSession) repopulateTable(wantFull int) (firstModelRow, wantTableRow int) {
	favOrder := favoriteAliasOrder(s.rows, s.favorites, s.query)
	order := filterModelRows(s.rows, s.query)
	dataByRow, firstModelRow, wantTableRow := populateModelTable(s.table, s.rows, favOrder, order, wantFull)
	s.dataByRow = dataByRow
	return firstModelRow, wantTableRow
}

func (a *App) refreshHighlightedModel(di int) {
	sess := a.modelPicker
	if sess == nil || di < 0 {
		return
	}
	sess.supported = sess.cat.SupportedEfforts(sess.rows[di].Provider, sess.rows[di].ModelID)
	sess.effort = modelPickerEffortFor(sess.supported, sess.effort)
	a.renderModelEffort()
	a.requestProviderRefresh(sess.rows[di].Provider, false)
}

const builtinChatGPTProviderID = "openai-chatgpt"

func refreshableProvider(providerID string, force bool) bool {
	return providerID != "" && (force || providerID != builtinChatGPTProviderID)
}

func (a *App) requestProviderRefresh(providerID string, force bool) {
	sess := a.modelPicker
	if sess == nil || a.modelPickerDeps.RefreshCatalog == nil {
		return
	}
	if !refreshableProvider(providerID, force) {
		return
	}
	if !force && sess.requested[providerID] {
		return
	}
	sess.requested[providerID] = true
	sess.refreshToken++
	token := sess.refreshToken
	sess.refreshOwner = token
	a.setModelPickerStatus(modelRefreshingStatus(providerID))
	target := sess
	origin := a.ActiveStore()
	a.modelPickerDeps.RefreshCatalog(providerID, force, func(res ModelRefreshResult) {
		a.streamUpdate(func() { a.applyModelRefreshResult(target, token, force, origin, res) })
	})
}

func (a *App) applyModelRefreshResult(target *modelPickerSession, token int, forced bool, origin *sessions.Store, res ModelRefreshResult) {
	if forced {
		if a.ActiveStore() != origin {
			return
		}
		a.recordForcedRefresh(origin, res)
	}
	sess := a.modelPicker
	if sess != target {
		return
	}
	ownsStatus := sess.refreshOwner == token
	switch res.Outcome {
	case ModelRefreshUpdated:
		a.rebuildModelPickerFromCatalog()
		if ownsStatus {
			a.setModelPickerStatus(modelRefreshedStatus(res.Provider))
			sess.refreshOwner = 0
		}
	case ModelRefreshFailed:
		if ownsStatus {
			a.setModelPickerStatus(modelRefreshFailedStatus(res.Provider))
			sess.refreshOwner = 0
		}
	case ModelRefreshCredentialUnavailable:
		if ownsStatus {
			a.setModelPickerStatus(modelRefreshLoginStatus(res.Provider))
			sess.refreshOwner = 0
		}
	case ModelRefreshNoChange:
		if ownsStatus {
			a.setModelPickerStatus(modelRefreshUpToDateStatus(res.Provider))
			sess.refreshOwner = 0
		}
	}
}

// The normal command flush deliberately absorbs a handled atomic-write failure so
// commands can continue with their records queued for retry. A forced-refresh
// completion line instead promises that its model_catalog_refreshed event is durable,
// so production injects FlushRefresh to preserve that failure after reporting it.
func (a *App) recordForcedRefresh(store *sessions.Store, res ModelRefreshResult) {
	_, err := events.Append(store, events.ModelCatalogRefreshed{
		Provider: res.Provider,
		Outcome:  modelRefreshOutcomeName(res.Outcome),
	})
	if err == nil {
		if flush := a.modelPickerDeps.FlushRefresh; flush != nil {
			err = flush(store)
		} else {
			err = a.FlushActive()
		}
	}
	if err != nil {
		a.Notice(fmt.Sprintf("could not record the model refresh: %v", err))
		return
	}
	a.Append("• " + modelRefreshOutcomeStatus(res))
}

func modelRefreshOutcomeName(outcome ModelRefreshOutcome) string {
	switch outcome {
	case ModelRefreshUpdated:
		return "updated"
	case ModelRefreshFailed, ModelRefreshCredentialUnavailable:
		return "failed"
	default:
		return "no_change"
	}
}

func modelRefreshOutcomeStatus(res ModelRefreshResult) string {
	switch res.Outcome {
	case ModelRefreshUpdated:
		return modelRefreshedStatus(res.Provider)
	case ModelRefreshFailed:
		return modelRefreshFailedStatus(res.Provider)
	case ModelRefreshCredentialUnavailable:
		return modelRefreshLoginStatus(res.Provider)
	default:
		return modelRefreshUpToDateStatus(res.Provider)
	}
}

func (a *App) setModelPickerStatus(text string) {
	sess := a.modelPicker
	if sess == nil || sess.status == nil {
		return
	}
	sess.status.SetText(text)
}

func (s *modelPickerSession) statusText() string {
	if s == nil || s.status == nil {
		return ""
	}
	return s.status.GetText(true)
}

func (a *App) rebuildModelPickerFromCatalog() {
	sess := a.modelPicker
	if sess == nil || sess.table == nil {
		return
	}
	prevProvider, prevModel := "", ""
	row, _ := sess.table.GetSelection()
	if di := sess.dataIndex(row); di >= 0 {
		prevProvider = sess.rows[di].Provider
		prevModel = sess.rows[di].ModelID
	}
	sess.rows = sess.cat.ProviderModels()
	firstModelRow, wantTableRow := sess.repopulateTable(modelRowIndex(sess.rows, prevProvider, prevModel))
	if wantTableRow < 0 {
		wantTableRow = firstModelRow
	}
	if wantTableRow < 0 {
		sess.supported = nil
		sess.effort = ""
		a.renderModelEffort()
		return
	}
	sess.table.Select(wantTableRow, 0)
	a.keepModelHeaderVisible(wantTableRow)
	a.refreshHighlightedModel(sess.dataIndex(wantTableRow))
}

// The only CTRL-R entry point, so it owns the no-op message: reporting it from
// requestProviderRefresh instead would make merely highlighting the built-in
// provider say "nothing to refresh" with no key pressed.
func (a *App) forceRefreshHighlightedProvider() {
	sess := a.modelPicker
	if sess == nil || sess.table == nil {
		return
	}
	row, _ := sess.table.GetSelection()
	di := sess.dataIndex(row)
	if di < 0 || !refreshableProvider(sess.rows[di].Provider, true) || a.modelPickerDeps.RefreshCatalog == nil {
		a.setModelPickerStatus(modelNothingToRefreshStatus)
		return
	}
	a.requestProviderRefresh(sess.rows[di].Provider, true)
}

// The picker box is ~40% of the terminal width, so these stay short enough not to wrap.
const modelNothingToRefreshStatus = "nothing to refresh"

func modelRefreshingStatus(provider string) string { return "refreshing " + provider + " models…" }
func modelRefreshedStatus(provider string) string  { return "refreshed " + provider + " models" }
func modelRefreshFailedStatus(provider string) string {
	return "could not refresh " + provider + " models"
}
func modelRefreshUpToDateStatus(provider string) string {
	return provider + " models already up to date"
}
func modelRefreshLoginStatus(_ string) string { return "run codemeld auth login openai-chatgpt" }

// onModelFilterChanged re-ranks and rebuilds the visible table from the new filter
// query, narrowing the provider×model rows live as the user types. Focus stays
// on the filter field throughout.
func (a *App) onModelFilterChanged(query string) {
	sess := a.modelPicker
	if sess == nil {
		return
	}
	sess.query = query
	firstModelRow, _ := sess.repopulateTable(-1)
	if firstModelRow >= 0 {
		sess.table.Select(firstModelRow, 0)
		// Recompute explicitly rather than relying on the selection-changed func: when
		// the new first row reuses the prior selection's coordinates tview may not fire
		// it, which would leave stale supported/effort from the old highlighted model.
		a.refreshHighlightedModel(sess.dataIndex(firstModelRow))
		return
	}
	// Empty filtered set: no headers/model rows, no stale effort, and the inline
	// control shows the empty-set dash. Enter/←/→ become no-ops (they all guard on a
	// selectable highlight / a >1 supported set), and normal state returns as soon as
	// the query matches again and a model row is selected above.
	sess.supported = nil
	sess.effort = ""
	a.renderModelEffort()
}

func filterModelRows(rows []ProviderModel, query string) []int {
	if query == "" {
		return sortedRowOrder(rows)
	}
	terms := strings.Fields(query)
	if len(terms) == 0 {
		return sortedRowOrder(rows)
	}
	type group struct{ prefix, other []int }
	groups := map[string]*group{}
	var providerOrder []string
	for _, i := range sortedRowOrder(rows) {
		r := rows[i]
		if !modelRowMatchesTerms(terms, r) {
			continue
		}
		g, ok := groups[r.Provider]
		if !ok {
			g = &group{}
			groups[r.Provider] = g
			providerOrder = append(providerOrder, r.Provider)
		}
		if strings.HasPrefix(strings.ToLower(r.ModelID), strings.ToLower(terms[0])) {
			g.prefix = append(g.prefix, i)
		} else {
			g.other = append(g.other, i)
		}
	}
	out := make([]int, 0, len(rows))
	for _, p := range providerOrder {
		g := groups[p]
		out = append(out, g.prefix...)
		out = append(out, g.other...)
	}
	return out
}

// modelRowMatchesTerms reports whether every term occurs contiguously
// (case-insensitive) in at least one of the row's searchable fields: model ID,
// stable provider ID, or provider display label. Different terms may match
// different fields. Callers pass strings.Fields output, so terms are non-empty;
// an empty list vacuously matches and is filtered out before this is reached.
func modelRowMatchesTerms(terms []string, r ProviderModel) bool {
	fields := []string{
		strings.ToLower(r.ModelID),
		strings.ToLower(r.Provider),
		strings.ToLower(providerHeaderLabel(r)),
	}
	for _, t := range terms {
		matched := false
		for _, f := range fields {
			if strings.Contains(f, strings.ToLower(t)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

const favoritesHeaderLabel = "Favorites"

func favoriteAliasLabel(r ProviderModel) string {
	return providerHeaderLabel(r) + " · " + r.ModelID
}

func favoriteAliasOrder(rows []ProviderModel, favorites []ModelFavorite, query string) []int {
	if len(favorites) == 0 {
		return nil
	}
	terms := strings.Fields(query)
	seen := map[int]bool{}
	var out []int
	for _, f := range favorites {
		i := modelRowIndex(rows, f.Provider, f.ModelID)
		if i < 0 || seen[i] {
			continue
		}
		if len(terms) > 0 && !modelRowMatchesTerms(terms, rows[i]) {
			continue
		}
		seen[i] = true
		out = append(out, i)
	}
	return out
}

func (a *App) currentFavorites() []ModelFavorite {
	if a.modelPickerDeps.Favorites == nil {
		return nil
	}
	return a.modelPickerDeps.Favorites()
}

func (a *App) toggleHighlightedFavorite() {
	sess := a.modelPicker
	if sess == nil || sess.table == nil || a.modelPickerDeps.ToggleFavorite == nil {
		return
	}
	row, _ := sess.table.GetSelection()
	di := sess.dataIndex(row)
	if di < 0 {
		return
	}
	r := sess.rows[di]
	favorites, err := a.modelPickerDeps.ToggleFavorite(r.Provider, r.ModelID)
	if err != nil {
		a.Notice(err.Error())
		return
	}
	sess.favorites = favorites
	a.rebuildModelPickerFromCatalog()
}

// Up/Down/Enter remain route-specific: the field handles them, while the table passes them to tview.
func (a *App) modelPickerSharedKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyHome:
		a.selectModelBoundary(-1)
	case tcell.KeyEnd:
		a.selectModelBoundary(1)
	case tcell.KeyPgUp:
		a.pageModelPickerSelection(-1)
	case tcell.KeyPgDn:
		a.pageModelPickerSelection(1)
	case tcell.KeyLeft:
		a.stepModelEffort(-1)
	case tcell.KeyRight:
		a.stepModelEffort(1)
	case tcell.KeyCtrlR:
		a.forceRefreshHighlightedProvider()
	case tcell.KeyCtrlF:
		a.toggleHighlightedFavorite()
	default:
		return ev
	}
	return nil
}

func (a *App) modelPickerFieldKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyUp:
		a.moveModelPickerSelection(-1)
		return nil
	case tcell.KeyDown:
		a.moveModelPickerSelection(1)
		return nil
	case tcell.KeyEnter:
		a.confirmHighlightedModel()
		return nil
	}
	return a.modelPickerSharedKeys(ev)
}

func (a *App) selectSelectableRow(row, dir, steps int) {
	sess := a.modelPicker
	if sess == nil || sess.table == nil || dir == 0 || steps < 1 {
		return
	}
	target := -1
	for i := row + dir; i >= 0 && i < len(sess.dataByRow) && steps > 0; i += dir {
		if sess.dataIndex(i) >= 0 {
			target = i
			steps--
		}
	}
	if target >= 0 {
		sess.table.Select(target, 0)
	}
}

func (a *App) moveModelPickerSelection(delta int) {
	sess := a.modelPicker
	if sess == nil || sess.table == nil {
		return
	}
	row, _ := sess.table.GetSelection()
	a.selectSelectableRow(row, delta, 1)
}

func (a *App) selectModelBoundary(dir int) {
	sess := a.modelPicker
	if sess == nil || sess.table == nil {
		return
	}
	if dir < 0 {
		a.selectSelectableRow(-1, 1, 1)
		return
	}
	a.selectSelectableRow(len(sess.dataByRow), -1, 1)
}

func (a *App) pageModelPickerSelection(dir int) {
	sess := a.modelPicker
	if sess == nil || sess.table == nil {
		return
	}
	_, _, _, height := sess.table.GetInnerRect()
	if height < 1 {
		height = 1
	}
	row, _ := sess.table.GetSelection()
	a.selectSelectableRow(row, dir, height)
}

func (a *App) keepModelHeaderVisible(row int) {
	sess := a.modelPicker
	if sess == nil || sess.table == nil || sess.dataIndex(row) < 0 || row == 0 {
		return
	}
	header := sess.table.GetCell(row-1, 0)
	if header == nil || !header.NotSelectable || header.Text == "" {
		return
	}
	sess.table.SetOffset(row-1, 0)
}

// confirmHighlightedModel confirms the currently highlighted visible model through the
// shared apply path. It is a no-op when no model row is highlighted (an empty filtered
// set or a header), so Enter never applies a model on an empty filter.
func (a *App) confirmHighlightedModel() {
	sess := a.modelPicker
	if sess == nil || sess.table == nil {
		return
	}
	row, _ := sess.table.GetSelection()
	di := sess.dataIndex(row)
	if di < 0 {
		return
	}
	a.confirmModelSelection(sess.rows[di], sess.effort)
}

// dataIndex returns the flat rows index for a table row, or -1 when the row is a
// provider header or out of range.
func (s *modelPickerSession) dataIndex(row int) int {
	if row < 0 || row >= len(s.dataByRow) {
		return -1
	}
	return s.dataByRow[row]
}

// applyPickerTableColors mirrors applyPickerListColors for the model table: under the
// terminal-default theme, tview.Table's default selected style is invisible, so the
// selected row is drawn with reverse video — inverting the terminal's own fg/bg — so
// the cursor carries no fixed color and reads on light and dark terminals.
func applyPickerTableColors(t *tview.Table) {
	t.SetSelectedStyle(tcell.StyleDefault.Reverse(true))
}

// modelPickerFooterHint is the one-row key legend below the picker.
const modelPickerFooterHint = "Enter confirm · ↑/↓ model · ←/→ effort · Ctrl-F favorite · Ctrl-R refresh · Esc cancel"

func (a *App) modelPickerKeys() func(*tcell.EventKey) *tcell.EventKey {
	return a.modelPickerSharedKeys
}

// stepModelEffort moves the inline effort selection by delta within the highlighted
// model's supported set, clamped at both ends (no wraparound). It is a no-op when
// the set has one or zero entries — the {default}-only case of the per-model supported-effort set, which
// renders a single inert value with no arrows.
func (a *App) stepModelEffort(delta int) {
	mp := a.modelPicker
	if mp == nil || len(mp.supported) <= 1 {
		return
	}
	i := slices.Index(mp.supported, mp.effort)
	if i < 0 {
		i = 0
	}
	i += delta
	if i < 0 {
		i = 0
	}
	if i >= len(mp.supported) {
		i = len(mp.supported) - 1
	}
	mp.effort = mp.supported[i]
	a.renderModelEffort()
}

// renderModelEffort re-renders the inline effort control from the session's current
// supported set and selected effort.
func (a *App) renderModelEffort() {
	mp := a.modelPicker
	if mp == nil || mp.effortView == nil {
		return
	}
	mp.effortView.SetText(renderInlineEffort(mp.supported, mp.effort))
}

// renderInlineEffort renders the one-row inline effort control as a stepper: only
// the selected effort is shown, in reverse video, flanked by a ◂ when a lower effort
// is available and a ▸ when a higher one is (no wraparound, mirroring stepModelEffort
// clamping). Showing just the selected value — rather than the whole set on one
// line — keeps it visible even in a narrow picker box, where the full set would
// overflow past the right edge and clip the selection out of view. A {default}-only
// model (one entry) renders its single value inert with no arrows; an empty
// set (the guarded len(rows)==0 case) renders a dash.
func renderInlineEffort(supported []string, selected string) string {
	if len(supported) == 0 {
		return "effort: —"
	}
	if len(supported) == 1 {
		return "effort: " + supported[0]
	}
	i := slices.Index(supported, selected)
	if i < 0 {
		i = 0
	}
	var b strings.Builder
	b.WriteString("effort: ")
	if i > 0 {
		b.WriteString("◂ ")
	}
	// Reverse video (the tview [::r] attribute) inverts the terminal's own fg/bg so
	// the active effort stays visible under any theme, with no fixed color.
	fmt.Fprintf(&b, "[::r] %s [::-]", supported[i])
	if i < len(supported)-1 {
		b.WriteString(" ▸")
	}
	return b.String()
}

// confirmModelSelection handles Enter on a picker row: it dismisses the overlay,
// then applies the chosen provider/model/effort through the provider-aware
// ProviderModelApplier — the same non-slash persistence/event path as
// /model, which appends model_changed before WriteActive, mirrors model.last_used
// only after the active write succeeds, and emits no slash_command. On success it
// appends a permanent confirmation line to the session transcript. Every
// selection persists: there is no session-only or inert path, so a model change
// always runs the apply which may switch the provider. An internal apply failure
// is surfaced as a one-line transient notice (the picker has no command-dispatch return path).
func (a *App) confirmModelSelection(row ProviderModel, effort string) {
	a.dismissModelPicker()
	seq := a.NoticeSeq()
	if _, err := a.modelPickerDeps.Applier.ApplyProviderModel(row.Provider, row.ModelID, effort); err != nil {
		a.Notice(err.Error())
		return
	}
	// Clear any stale pinned notice now that the model change has applied, only
	// on this success path — the apply-error branch above keeps its notice, and an apply
	// that emitted a notice of its own (the local-settings ignore notice, or the degraded
	// active-write failure) keeps that too, including when it repeats the previous
	// notice verbatim. The confirmation line below is committed history
	// (a.Append), which the notice clear leaves untouched.
	if a.NoticeSeq() == seq {
		a.ClearNotice()
	}
	// Live-update the persistent status-line footer to the new provider/model/effort
	// only after the apply succeeded (the error path returned above).
	if a.modelPickerDeps.Refresh != nil {
		a.modelPickerDeps.Refresh()
	}
	a.Append(fmt.Sprintf("• model set to %s — %s (effort: %s)", row.Provider, row.ModelID, effort))
}

// dismissModelPicker closes the picker overlay and restores focus to whatever held
// it when the picker opened. The input buffer is never touched, so
// anything typed before CTRL-M survives, and no persistence call or model event is
// made (ESC dismissal emits nothing).
func (a *App) dismissModelPicker() {
	if !a.modelPickerOpen {
		return
	}
	a.modelPickerOpen = false
	a.closeOverlayPage(modelPickerPage, &a.modelPickerPrev)
	a.modelPicker = nil
}

func modelPickerEffortFor(supported []string, prev string) string {
	if effortValid(prev, supported) {
		return prev
	}
	return modelSelectionEffortFallback(supported)
}

// providerHeaderLabel returns the presentation-only group-header text for a row:
// its display name (e.g. "OpenAI ChatGPT") when set, falling back to the stable
// provider id when a row carries no display name. Persistence and
// apply always use ProviderModel.Provider, never this label.
func providerHeaderLabel(r ProviderModel) string {
	if r.DisplayName != "" {
		return r.DisplayName
	}
	return r.Provider
}

// modelRowIndex returns the index of the (provider, modelID) row, or -1 when the
// active selection is not among the configured cross-product rows.
func modelRowIndex(rows []ProviderModel, provider, modelID string) int {
	for i, r := range rows {
		if r.Provider == provider && r.ModelID == modelID {
			return i
		}
	}
	return -1
}

func providerHasRows(rows []ProviderModel, providerID string) bool {
	for _, r := range rows {
		if r.Provider == providerID {
			return true
		}
	}
	return false
}

func renderModelSettingsInfo(t ModelSettingsTarget) string {
	var b strings.Builder
	b.WriteString("settings: " + t.SettingsPath)
	if t.LaunchDir != "" && t.LaunchDir != t.ProjectRoot {
		b.WriteString("\nlaunch dir: " + t.LaunchDir + "  [≠ project root]")
	}
	return b.String()
}

// modelInfoHeight reports the row count the settings info pane needs: one row per
// line in text.
func modelInfoHeight(text string) int {
	return strings.Count(text, "\n") + 1
}
