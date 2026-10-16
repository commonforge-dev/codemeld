package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/fserrors"
)

type BlockedRowKind int

const (
	BlockedRowWarning BlockedRowKind = iota
	BlockedRowGroup
	BlockedRowGlobal
	BlockedRowLocal
	BlockedRowShared
	BlockedRowProject
	BlockedRowFloor
	BlockedRowMissing
)

type BlockedRow struct {
	Kind       BlockedRowKind
	Text       string
	Path       string
	Source     string
	Occurrence int
	Group      string
}

type BlockedPicker interface {
	Present(rows []BlockedRow, remove func(BlockedRow) string, add func(BlockedRow) string, addAll func([]BlockedRow) string, relist func() []BlockedRow)
}

type BlockedDestination string

const (
	BlockedGlobal        BlockedDestination = "global"
	BlockedProjectShared BlockedDestination = "project-shared"
	BlockedProjectLocal  BlockedDestination = "project-local"
)

type BlockedDestinationPresenter interface {
	PresentDestination(path string, add func(string, BlockedDestination) string)
}

type BlockedDeps struct {
	Rows                       func() []BlockedRow
	Picker                     BlockedPicker
	Remove                     func(BlockedRow) string
	Add                        func(BlockedRow) string
	AddAll                     func([]BlockedRow) string
	AddPath                    func(string, BlockedDestination) string
	ProjectDestinationsAllowed bool
	Destinations               BlockedDestinationPresenter
}

const (
	blockedPickerPage     = "blocked-picker"
	blockedConfirmPage    = "blocked-confirm"
	blockedDestPage       = "blocked-destination"
	blockedFooterHint     = "remove r   add a   A add all   esc close"
	blockedRecommendedTop = "Recommended, not in your global settings:"
	blockedUsage          = "usage: /blocked or /blocked add <path>"
	blockedNothingMissing = "every recommended entry is already in your global settings"
)

func NewBlockedHandler(deps BlockedDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		var path string
		if len(args) > 0 {
			word, rest, _ := strings.Cut(args[0], " ")
			if word != "add" || rest == "" {
				ctx.Notice(blockedUsage)
				ctx.RetainInput()
				if err := ctx.AppendSlashCommand(OutcomeError, blockedUsage); err != nil {
					return err
				}
				return ctx.FlushActive()
			}
			path = rest
		}
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		if err := ctx.FlushActive(); err != nil {
			return err
		}
		if path != "" {
			if !deps.ProjectDestinationsAllowed {
				ctx.Notice(deps.AddPath(path, BlockedGlobal))
				return nil
			}
			deps.Destinations.PresentDestination(path, deps.AddPath)
			return nil
		}
		deps.Picker.Present(deps.Rows(), deps.Remove, deps.Add, deps.AddAll, deps.Rows)
		return nil
	}
}

type blockedListItem struct {
	line string
	row  int
}

type blockedPickerSession struct {
	rows    []BlockedRow
	items   []blockedListItem
	list    *tview.List
	remove  func(BlockedRow) string
	add     func(BlockedRow) string
	addAll  func([]BlockedRow) string
	relist  func() []BlockedRow
	confirm func()
}

type blockedPicker struct{ app *App }

func NewBlockedPicker(app *App) BlockedPicker { return blockedPicker{app: app} }

func (p blockedPicker) Present(rows []BlockedRow, remove func(BlockedRow) string, add func(BlockedRow) string, addAll func([]BlockedRow) string, relist func() []BlockedRow) {
	p.app.openBlockedPicker(rows)
	bp := p.app.blockedPicker
	bp.remove, bp.add, bp.addAll, bp.relist = remove, add, addAll, relist
}

func (a *App) openBlockedPicker(rows []BlockedRow) {
	bp := &blockedPickerSession{}
	a.blockedPicker = bp
	a.blockedPickerOpen = true
	a.blockedPickerPrev = a.app.GetFocus()

	bp.list = tview.NewList()
	bp.list.ShowSecondaryText(false)
	applyPickerListColors(bp.list)
	bp.list.SetInputCapture(a.blockedPickerKeys)
	bp.setRows(rows)

	footer := tview.NewTextView()
	footer.SetDynamicColors(false)
	footer.SetText(blockedFooterHint)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(bp.list, 0, 1, true).
		AddItem(footer, 1, 0, false)
	body.SetBorder(true)
	body.SetTitle(" blocked paths ")

	a.pages.AddPage(blockedPickerPage, wrapOverlayPage(body), true, true)
	a.app.SetFocus(bp.list)
}

func (bp *blockedPickerSession) setRows(rows []BlockedRow) {
	bp.rows = rows
	bp.items = blockedListItems(rows)
	bp.list.Clear()
	for _, it := range bp.items {
		bp.list.AddItem(tview.Escape(it.line), "", 0, nil)
	}
}

func (a *App) blockedPickerKeys(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() != tcell.KeyRune {
		return ev
	}
	switch ev.Rune() {
	case 'r':
		a.removeHighlightedBlockedRow()
		return nil
	case 'a':
		a.addHighlightedBlockedRow()
		return nil
	case 'A':
		a.addAllMissingBlockedRows()
		return nil
	}
	return ev
}

func (a *App) highlightedBlockedRow() (*blockedPickerSession, BlockedRow, bool) {
	bp := a.blockedPicker
	if bp == nil {
		return nil, BlockedRow{}, false
	}
	i := bp.list.GetCurrentItem()
	if i < 0 || i >= len(bp.items) || bp.items[i].row < 0 {
		return nil, BlockedRow{}, false
	}
	return bp, bp.rows[bp.items[i].row], true
}

func (a *App) removeHighlightedBlockedRow() {
	bp, row, ok := a.highlightedBlockedRow()
	if !ok || bp.remove == nil {
		return
	}
	switch row.Kind {
	case BlockedRowProject:
		a.Notice("edit " + fserrors.CollapseControls(row.Source) + " to change this entry")
	case BlockedRowGlobal, BlockedRowLocal, BlockedRowShared:
		a.showBlockedConfirm("Remove", "Remove "+row.Path+" from "+row.Source+"?", bp.remove, row)
	}
}

func (a *App) addHighlightedBlockedRow() {
	bp, row, ok := a.highlightedBlockedRow()
	if !ok || bp.add == nil || row.Kind != BlockedRowMissing {
		return
	}
	a.showBlockedConfirm("Add", "Add "+row.Path+" to your global settings?", bp.add, row)
}

func (a *App) addAllMissingBlockedRows() {
	bp := a.blockedPicker
	if bp == nil || bp.addAll == nil {
		return
	}
	missing := slices.DeleteFunc(slices.Clone(bp.rows), func(r BlockedRow) bool { return r.Kind != BlockedRowMissing })
	if len(missing) == 0 {
		a.Notice(blockedNothingMissing)
		return
	}
	text := fmt.Sprintf("Add all %d missing recommended entries to your global settings?", len(missing))
	a.showBlockedConfirm("Add all", text, func(BlockedRow) string { return bp.addAll(missing) }, BlockedRow{})
}

func (a *App) showBlockedConfirm(button, text string, action func(BlockedRow) string, row BlockedRow) {
	a.blockedPicker.confirm = func() { a.applyBlockedAction(action, row) }
	modal := tview.NewModal().
		SetText(tview.Escape(fserrors.CollapseControls(text))).
		AddButtons([]string{button, "Cancel"}).
		SetDoneFunc(func(_ int, label string) { a.answerBlockedConfirm(label == button) })
	modal.SetButtonActivatedStyle(tcell.StyleDefault.Reverse(true))
	modal.SetInputCapture(permissionsDeleteKeys)
	a.pages.AddPage(blockedConfirmPage, modal, true, true)
	a.app.SetFocus(modal)
}

func (a *App) answerBlockedConfirm(confirmed bool) {
	a.pages.RemovePage(blockedConfirmPage)
	bp := a.blockedPicker
	if bp == nil {
		return
	}
	apply := bp.confirm
	bp.confirm = nil
	if confirmed && apply != nil {
		apply()
	}
	a.app.SetFocus(bp.list)
}

func (a *App) applyBlockedAction(action func(BlockedRow) string, row BlockedRow) {
	if msg := action(row); msg != "" {
		a.Notice(msg)
	}
	bp := a.blockedPicker
	if bp.relist == nil {
		return
	}
	prev := bp.list.GetCurrentItem()
	bp.setRows(bp.relist())
	bp.list.SetCurrentItem(prev)
}

var blockedDestinationChoices = []struct {
	label string
	dest  BlockedDestination
}{
	{"Global", BlockedGlobal},
	{"Project (shared)", BlockedProjectShared},
	{"Project (local)", BlockedProjectLocal},
}

type blockedDestinationPresenter struct{ app *App }

func NewBlockedDestinationPresenter(app *App) BlockedDestinationPresenter {
	return blockedDestinationPresenter{app: app}
}

func (p blockedDestinationPresenter) PresentDestination(path string, add func(string, BlockedDestination) string) {
	p.app.openBlockedDestination(path, add)
}

func (a *App) openBlockedDestination(path string, add func(string, BlockedDestination) string) {
	if a.anyOverlayOpen() {
		return
	}
	a.blockedDestinationOpen = true
	a.blockedDestinationPrev = a.app.GetFocus()
	a.blockedDestinationAdd = func(dest BlockedDestination) string { return add(path, dest) }

	text := "Where should " + fserrors.CollapseControls(path) + " be blocked?\n\n" +
		"Global: all your projects.\n" +
		"Project (shared): .codemeld/settings.yaml; applies to everyone who approves this repository.\n" +
		"Project (local): .codemeld/settings.local.yaml; only for you."
	buttons := make([]string, 0, len(blockedDestinationChoices)+1)
	for _, c := range blockedDestinationChoices {
		buttons = append(buttons, c.label)
	}
	modal := tview.NewModal().
		SetText(tview.Escape(text)).
		AddButtons(append(buttons, "Cancel")).
		SetDoneFunc(func(i int, _ string) { a.answerBlockedDestination(i) })
	modal.SetButtonActivatedStyle(tcell.StyleDefault.Reverse(true))
	modal.SetInputCapture(permissionsDeleteKeys)
	a.pages.AddPage(blockedDestPage, modal, true, true)
	a.app.SetFocus(modal)
}

func (a *App) answerBlockedDestination(button int) {
	if !a.blockedDestinationOpen {
		return
	}
	add := a.blockedDestinationAdd
	a.blockedDestinationOpen = false
	a.blockedDestinationAdd = nil
	a.closeOverlayPage(blockedDestPage, &a.blockedDestinationPrev)
	if button < 0 || button >= len(blockedDestinationChoices) || add == nil {
		return
	}
	a.Notice(add(blockedDestinationChoices[button].dest))
}

func (a *App) ChooseBlockedDestinationForTest(dest BlockedDestination) bool {
	if !a.blockedDestinationOpen {
		return false
	}
	for i, c := range blockedDestinationChoices {
		if c.dest == dest {
			a.answerBlockedDestination(i)
			return true
		}
	}
	return false
}

func (a *App) RemoveBlockedPathForTest(path string) bool {
	return a.confirmBlockedRowForTest(BlockedRowGlobal, path, 'r')
}

func (a *App) AddBlockedPathForTest(path string) bool {
	return a.confirmBlockedRowForTest(BlockedRowMissing, path, 'a')
}

func (a *App) confirmBlockedRowForTest(kind BlockedRowKind, path string, key rune) bool {
	bp := a.blockedPicker
	if bp == nil {
		return false
	}
	for i, it := range bp.items {
		if it.row < 0 || bp.rows[it.row].Kind != kind || bp.rows[it.row].Path != path {
			continue
		}
		bp.list.SetCurrentItem(i)
		a.blockedPickerKeys(tcell.NewEventKey(tcell.KeyRune, key, tcell.ModNone))
		if !a.pages.HasPage(blockedConfirmPage) {
			return false
		}
		a.answerBlockedConfirm(true)
		return true
	}
	return false
}

func (a *App) dismissBlockedPicker() {
	if !a.blockedPickerOpen {
		return
	}
	a.blockedPickerOpen = false
	a.pages.RemovePage(blockedConfirmPage)
	a.closeOverlayPage(blockedPickerPage, &a.blockedPickerPrev)
	a.blockedPicker = nil
}

func blockedListItems(rows []BlockedRow) []blockedListItem {
	items := make([]blockedListItem, 0, len(rows)+1)
	headed := false
	for i, r := range rows {
		if r.Kind == BlockedRowGroup && !headed {
			headed = true
			items = append(items, blockedListItem{line: blockedRecommendedTop, row: -1})
		}
		items = append(items, blockedListItem{line: renderBlockedRow(r), row: i})
	}
	return items
}

func renderBlockedRow(r BlockedRow) string {
	path := fserrors.CollapseControls(r.Path)
	source := fserrors.CollapseControls(r.Source)
	switch r.Kind {
	case BlockedRowWarning, BlockedRowGroup:
		return fserrors.CollapseControls(r.Text)
	case BlockedRowGlobal, BlockedRowLocal, BlockedRowShared:
		return path + "  (" + source + ")"
	case BlockedRowProject:
		return path + "  (edit " + source + " to change this entry)"
	case BlockedRowFloor:
		return path + "  (codemeld's own folder, always blocked)"
	case BlockedRowMissing:
		return "  " + path
	}
	return path
}
