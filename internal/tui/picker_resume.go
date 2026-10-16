package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"
)

// resumePickerPage is the Pages name the /resume overlay is mounted under while
// open, removed when it dismisses. The rename input and delete confirmation are
// layered above it under their own page names while the picker stays mounted.
const (
	resumePickerPage = "resume-picker"
	resumeRenamePage = "resume-rename"
	resumeDeletePage = "resume-delete"
)

// The border takes one cell on each side of an 80-column terminal, and tview puts one
// cell between the two columns, so the title and time budgets must sum to 77.
const (
	resumeBodyInnerCells = 78
	resumeTimeCells      = 24
	resumeTitleCells     = resumeBodyInnerCells - resumeTimeCells - 1
)

const resumeRowTimeLayout = "Jan 02 15:04"

// resumeUntitledLabel is the row text for a session with neither a stored title nor
// a derivable preview, so an untitled session is still selectable and its id stays
// hidden. It reads "New session" to match the auto-naming UX.
const resumeUntitledLabel = "New session"

// resumeHeaderSession and resumeHeaderTimes label the two picker columns in the fixed,
// non-selectable header row, so users see that column 0 is the session name and column 1
// is the start stamp and the update age.
const (
	resumeHeaderSession = "Session"
	resumeHeaderTimes   = "Started · Updated age"
)

// resumeHeaderRows is the number of fixed header rows above the entry rows. Entry i is
// rendered at table row i+resumeHeaderRows, so every table-row↔entry conversion goes
// through this single offset.
const resumeHeaderRows = 1

// resumeFooterHint is the one-row key legend below the picker (redesign).
const resumeFooterHint = "delete ctrl+d   rename ctrl+r"

// resumePickerSession holds the open /resume picker's live state. orig is the entry
// slice the handler captured and indexes for the on-selection switch (PickerResult.Index
// resolves into it via each row's stable cell reference, matched by id across refreshes);
// entries is the currently displayed set (swapped by an in-place ReList after a rename
// or delete). table is the selectable row table, onResult the one-shot Enter/ESC
// continuation, actions the rename/delete/re-list callbacks, and fired the one-shot guard
// so an Enter-then-ESC race cannot invoke the session switch twice or run it after a
// dismissal. All access is on the single tview goroutine.
type resumePickerSession struct {
	orig     []ResumeEntry
	entries  []ResumeEntry
	table    *tview.Table
	onResult func(PickerResult)
	actions  ResumeActions
	fired    bool
}

// resumePicker is the production ResumePicker. It holds the app so Present can mount
// the overlay on the app's Pages host and drive focus; the open overlay's state lives
// on App.resumePicker, so a single instance serves every /resume invocation for the run.
type resumePicker struct{ app *App }

// NewResumePicker returns the production ResumePicker bound to app, for the
// production ResumeDeps. The overlay it presents is continuation-based: it never
// blocks the event-loop submit path.
func NewResumePicker(app *App) ResumePicker { return resumePicker{app: app} }

func (p resumePicker) Present(entries []ResumeEntry, onResult func(PickerResult), actions ResumeActions) {
	p.app.openResumePicker(entries, onResult, actions)
}

func (p resumePicker) PresentEmpty(message string, onDismiss func()) {
	p.app.presentResumeEmpty(message, onDismiss)
}

// openResumePicker mounts the navigable session picker. It builds a table of
// the resumable entries over a footer hint, moves focus to it, and returns; ↑/↓
// navigate, Enter resolves onResult with the highlighted row, ESC resolves it as a
// dismissal, and ctrl+r / ctrl+d open the rename / delete affordances over the picker.
// onResult fires exactly once.
func (a *App) openResumePicker(entries []ResumeEntry, onResult func(PickerResult), actions ResumeActions) {
	rp := &resumePickerSession{
		orig:     entries,
		entries:  entries,
		onResult: onResult,
		actions:  actions,
	}
	a.resumePicker = rp
	a.resumePickerOpen = true
	a.resumePickerPrev = a.app.GetFocus()

	table := tview.NewTable()
	// Whole-row selection over the two columns. Row 0 is a fixed, non-selectable header
	// (see populateResumeTable); entry i maps to table row i+resumeHeaderRows.
	table.SetSelectable(true, false)
	table.SetFixed(resumeHeaderRows, 0)
	applyPickerTableColors(table)
	rp.table = table

	a.populateResumeTable()
	// Land the cursor on the first entry row, never on the header.
	table.Select(resumeHeaderRows, 0)

	table.SetSelectedFunc(func(row, _ int) {
		idx := a.resumeRefIndex(row)
		if idx < 0 {
			return
		}
		a.resumeFinish(PickerResult{Selected: true, Index: idx})
	})
	table.SetInputCapture(a.resumePickerKeys)

	a.pages.AddPage(resumePickerPage, wrapOverlayPage(a.buildResumeBody(table)), true, true)
	a.app.SetFocus(table)
}

// buildResumeBody wraps the row table in a bordered FlexRow with a one-row footer hint
// mirroring buildModelPicker's footer.
func (a *App) buildResumeBody(table *tview.Table) *tview.Flex {
	footer := tview.NewTextView()
	footer.SetDynamicColors(false)
	footer.SetText(resumeFooterHint)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(table, 0, 1, true).
		AddItem(footer, 1, 0, false)
	body.SetBorder(true)
	body.SetTitle(" resume session ")
	return body
}

// populateResumeTable (re)builds the picker table from the session's currently
// displayed entries: row 0 is the fixed, non-selectable column header; column 0 the
// title/preview (expanding, never showing the id), column 1 the start stamp and update
// age, right-aligned. Entry i is written at row i+resumeHeaderRows. Each entry's column-0 cell
// stores, as its stable reference, the entry's index in orig (the slice the handler
// indexes on Enter) matched by id — or -1 for a displayed entry absent from orig (e.g. a
// session another process added mid-picker), which the Enter handler then treats as
// unresolvable. The header cells carry no reference and are non-selectable, so navigation
// never lands on them and they never resolve to an entry.
func (a *App) populateResumeTable() {
	rp := a.resumePicker
	if rp == nil || rp.table == nil {
		return
	}
	rp.table.Clear()
	rp.table.SetCell(0, 0, tview.NewTableCell(resumeHeaderSession).
		SetSelectable(false).
		SetExpansion(1).
		SetStyle(tcell.StyleDefault.Bold(true)))
	rp.table.SetCell(0, 1, tview.NewTableCell(resumeHeaderTimes).
		SetSelectable(false).
		SetAlign(tview.AlignRight).
		SetStyle(tcell.StyleDefault.Bold(true)))
	now := time.Now()
	for i, e := range rp.entries {
		row := i + resumeHeaderRows
		rp.table.SetCell(row, 0, tview.NewTableCell(resumeRowTitle(e)).
			SetExpansion(1).
			SetReference(resumeOrigIndex(rp.orig, e.ID)))
		rp.table.SetCell(row, 1, tview.NewTableCell(resumeRowTimes(e, now)).
			SetAlign(tview.AlignRight))
	}
}

// resumePickerKeys is the row table's key handler: ESC dismisses the picker, ctrl+r
// opens the rename input, ctrl+d opens the delete confirmation; every other key falls
// through to the table (↑/↓ navigation, Enter select).
func (a *App) resumePickerKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		a.resumeFinish(PickerResult{Selected: false})
		return nil
	case tcell.KeyCtrlR:
		a.showResumeRename()
		return nil
	case tcell.KeyCtrlD:
		a.showResumeDelete()
		return nil
	}
	return ev
}

// resumeRefIndex returns the orig-slice index stored on the column-0 cell of table
// row, or -1 when the row, cell, or reference is missing/unresolvable. It reads the cell
// at the given table row directly, so the non-selectable header row (which carries no
// reference) resolves to -1. It is the mapping the Enter handler uses so a selection
// always resolves into the entries the /resume handler captured, even after a refresh
// reorders the displayed rows.
func (a *App) resumeRefIndex(row int) int {
	rp := a.resumePicker
	if rp == nil || rp.table == nil {
		return -1
	}
	cell := rp.table.GetCell(row, 0)
	if cell == nil {
		return -1
	}
	idx, ok := cell.GetReference().(int)
	if !ok {
		return -1
	}
	return idx
}

// resumeHighlightedEntry returns the displayed entry under the table cursor — the
// target of a rename or delete, which act on the row's current title/path, not on the
// orig-index the Enter switch uses. The cursor's table row is converted to an entry index
// by subtracting the header offset, so the header row (and any out-of-range row) yields
// ok=false rather than mis-targeting an entry.
func (a *App) resumeHighlightedEntry() (ResumeEntry, bool) {
	rp := a.resumePicker
	if rp == nil || rp.table == nil {
		return ResumeEntry{}, false
	}
	row, _ := rp.table.GetSelection()
	idx := row - resumeHeaderRows
	if idx < 0 || idx >= len(rp.entries) {
		return ResumeEntry{}, false
	}
	return rp.entries[idx], true
}

// showResumeRename layers the rename input over the picker, prefilled with
// the highlighted session's current title (empty for an untitled session). Enter
// persists via actions.Rename and refreshes the rows on success; ESC cancels with no
// mutation. It is inert when no rename capability is wired or no row is highlighted.
func (a *App) showResumeRename() {
	rp := a.resumePicker
	if rp == nil || rp.actions.Rename == nil {
		return
	}
	entry, ok := a.resumeHighlightedEntry()
	if !ok {
		return
	}

	info := tview.NewTextView()
	info.SetDynamicColors(false)
	info.SetText("Rename this session. Enter to save, Esc to cancel.")

	field := tview.NewInputField()
	field.SetLabel("title ")
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
	field.SetText(entry.Title)
	field.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEnter:
			a.applyResumeRename(entry, field.GetText())
		case tcell.KeyEscape:
			a.cancelResumeChild()
		}
	})

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(info, 0, 1, false).
		AddItem(field, 1, 0, true)
	body.SetBorder(true)
	body.SetTitle(" rename session ")
	a.pages.AddPage(resumeRenamePage, wrapOverlayPage(body), true, true)
	a.app.SetFocus(field)
}

// applyResumeRename tears down the rename input and persists the typed title for entry.
// On a Rename failure it leaves the rows unchanged and surfaces a notice; on success it
// refreshes the rows (so the renamed row shows the new title) and refocuses the table.
func (a *App) applyResumeRename(entry ResumeEntry, title string) {
	a.pages.RemovePage(resumeRenamePage)
	rp := a.resumePicker
	if rp == nil {
		return
	}
	if rp.actions.Rename != nil {
		if err := rp.actions.Rename(entry, title); err != nil {
			a.Notice(err.Error())
			a.app.SetFocus(rp.table)
			return
		}
	}
	a.refreshResumeRows()
	a.refocusResumeTable()
}

// showResumeDelete layers a confirmation modal over the picker for the highlighted
// session: Delete removes the file via actions.Delete then refreshes the
// rows; Cancel (or ESC) leaves everything untouched. The prompt uses the display title
// so an untitled session reads as "New session" and ids stay hidden. It is inert when no
// delete capability is wired or no row is highlighted.
func (a *App) showResumeDelete() {
	rp := a.resumePicker
	if rp == nil || rp.actions.Delete == nil {
		return
	}
	entry, ok := a.resumeHighlightedEntry()
	if !ok {
		return
	}

	modal := tview.NewModal().
		SetText(fmt.Sprintf("Delete session %q? This cannot be undone.", resumeRowTitle(entry))).
		AddButtons([]string{"Delete", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			a.pages.RemovePage(resumeDeletePage)
			if label == "Delete" {
				a.applyResumeDelete(entry)
				return
			}
			a.refocusResumeTable()
		})
	// tview.Modal has no built-in ESC-cancel; treat ESC as Cancel so it never deletes.
	modal.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			a.pages.RemovePage(resumeDeletePage)
			a.refocusResumeTable()
			return nil
		}
		return ev
	})
	a.pages.AddPage(resumeDeletePage, modal, true, true)
	a.app.SetFocus(modal)
}

// applyResumeDelete deletes entry's session file. On a Delete failure it leaves the row
// in place and surfaces a notice; on success it refreshes the rows (the deleted row
// disappears) and refocuses the table.
func (a *App) applyResumeDelete(entry ResumeEntry) {
	rp := a.resumePicker
	if rp == nil {
		return
	}
	if rp.actions.Delete != nil {
		if err := rp.actions.Delete(entry); err != nil {
			a.Notice(err.Error())
			a.app.SetFocus(rp.table)
			return
		}
	}
	a.refreshResumeRows()
	a.refocusResumeTable()
}

// cancelResumeChild removes whichever rename/delete child overlay is open and refocuses
// the picker table without mutating anything.
func (a *App) cancelResumeChild() {
	a.pages.RemovePage(resumeRenamePage)
	a.pages.RemovePage(resumeDeletePage)
	a.refocusResumeTable()
}

// refocusResumeTable returns focus to the picker table if the picker is still open
// (a refresh that emptied the list dismisses it, leaving nothing to refocus).
func (a *App) refocusResumeTable() {
	if rp := a.resumePicker; rp != nil && rp.table != nil {
		a.app.SetFocus(rp.table)
	}
}

// refreshResumeRows re-enumerates the folder's survivors via actions.ReList, swaps the
// displayed entries, rebuilds the table, and clamps the selection. A re-list
// error keeps the current rows and surfaces a notice. When the list becomes empty (the
// last session was just deleted) it dismisses the picker, resolving the continuation as
// a dismissal so the durable picker-open success simply stands.
func (a *App) refreshResumeRows() {
	rp := a.resumePicker
	if rp == nil || rp.actions.ReList == nil {
		return
	}
	next, err := rp.actions.ReList()
	if err != nil {
		a.Notice(resumeEnumerateNotice(err))
		return
	}
	if len(next) == 0 {
		a.resumeFinish(PickerResult{Selected: false})
		return
	}
	row, _ := rp.table.GetSelection()
	rp.entries = next
	a.populateResumeTable()
	// Entries occupy rows resumeHeaderRows..len(next)+resumeHeaderRows-1; clamp the
	// preserved selection into that range so it never lands on the header (row 0) or past
	// the last survivor.
	if maxRow := len(next) + resumeHeaderRows - 1; row > maxRow {
		row = maxRow
	}
	if row < resumeHeaderRows {
		row = resumeHeaderRows
	}
	rp.table.Select(row, 0)
}

// resumeFinish resolves the one-shot Enter/ESC continuation: it fires onResult exactly
// once (guarded by the per-open fired flag), dismissing the overlay first so a switch
// the callback drives runs after the picker has torn down.
func (a *App) resumeFinish(res PickerResult) {
	rp := a.resumePicker
	if rp == nil || rp.fired {
		return
	}
	rp.fired = true
	onResult := rp.onResult
	a.dismissResumePicker()
	onResult(res)
}

// presentResumeEmpty shows the empty-folder message as a transient
// overlay dismissed by any keypress, then invokes onDismiss exactly once.
func (a *App) presentResumeEmpty(message string, onDismiss func()) {
	view := tview.NewTextView()
	view.SetText(message)
	view.SetBorder(true)
	view.SetTitle(" resume session ")

	a.resumePickerOpen = true
	a.resumePickerPrev = a.app.GetFocus()

	fired := false
	view.SetInputCapture(func(*tcell.EventKey) *tcell.EventKey {
		if fired {
			return nil
		}
		fired = true
		a.dismissResumePicker()
		onDismiss()
		return nil
	})

	a.pages.AddPage(resumePickerPage, wrapOverlayPage(view), true, true)
	a.app.SetFocus(view)
}

// dismissResumePicker removes the overlay (and any open rename/delete child) and
// restores focus to whatever held it when the picker opened (the input area in
// production). The input buffer is never touched. It is idempotent so the one-shot
// finish guards can call it safely, and nils the per-open state on dismissal.
func (a *App) dismissResumePicker() {
	if !a.resumePickerOpen {
		return
	}
	a.resumePickerOpen = false
	a.pages.RemovePage(resumeRenamePage)
	a.pages.RemovePage(resumeDeletePage)
	a.closeOverlayPage(resumePickerPage, &a.resumePickerPrev)
	a.resumePicker = nil
}

// resumeOrigIndex returns the index of the entry with id in orig, or -1 when no
// original row carries that id (a session that appeared only after the picker opened).
func resumeOrigIndex(orig []ResumeEntry, id string) int {
	for i, e := range orig {
		if e.ID == id {
			return i
		}
	}
	return -1
}

// resumeRowTitle renders a picker row's display text: the stored title when set, else
// the auto-derived first-message preview, else "New session" — never the session id.
func resumeRowTitle(e ResumeEntry) string {
	text := e.Title
	if text == "" {
		text = e.Preview
	}
	if text == "" {
		return resumeUntitledLabel
	}
	return FitCells(text, resumeTitleCells)
}

func resumeRowTimes(e ResumeEntry, now time.Time) string {
	return FitCells(e.StartedAt.Local().Format(resumeRowTimeLayout)+" · "+resumeUpdatedAge(e.UpdatedAt, now), resumeTimeCells)
}

// A future updated_at (writer/reader clock skew) deliberately reads "just now" rather
// than a negative age.
func resumeUpdatedAge(updated, now time.Time) string {
	d := now.Sub(updated)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return fmt.Sprintf("%dy ago", int(d.Hours()/24/365))
	}
}

// FitCells bounds s to maxCells terminal cells, keeping a head and the distinguishing
// tail around a single ellipsis, cutting only on grapheme-cluster boundaries.
// internal/bootstrap shares it so the preview projection cuts the same way.
func FitCells(s string, maxCells int) string {
	if maxCells <= 0 {
		return ""
	}
	if uniseg.StringWidth(s) <= maxCells {
		return s
	}
	if maxCells == 1 {
		return "…"
	}
	head := (maxCells - 1) / 2
	return truncateCells(s, head) + "…" + tailCells(s, maxCells-1-head)
}

func tailCells(s string, maxCells int) string {
	var clusters []string
	var widths []int
	state := -1
	for s != "" {
		cluster, rest, boundaries, st := uniseg.StepString(s, state)
		clusters = append(clusters, cluster)
		widths = append(widths, boundaries>>uniseg.ShiftWidth)
		s, state = rest, st
	}
	used, i := 0, len(clusters)
	for i > 0 && used+widths[i-1] <= maxCells {
		used += widths[i-1]
		i--
	}
	return strings.Join(clusters[i:], "")
}
