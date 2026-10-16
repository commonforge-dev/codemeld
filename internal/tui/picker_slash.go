// Live '/' slash-command autocomplete overlay: typing '/' as the first non-whitespace
// character of the prompt opens a picker listing the registry's commands as "/<name>
// <description>"; typing narrows it by prefix (canonical names and aliases, consistent with Tab
// completion), and selecting one submits the canonical "/<name>" command immediately through the
// normal submit path. It clones the '@' file-reference picker shape (picker_file.go): the same
// live change-hook trigger, overlay chrome, and focus lifecycle. Command metadata comes from the
// registry App already holds, so new commands appear automatically.
package tui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// slashPickerPage is the Pages name the slash-command picker overlay is mounted under while
// open, removed when it dismisses.
const slashPickerPage = "slash-picker"

// slashRefLabel is the picker query field's label and the literal token prefix. It mirrors the
// '/' the user typed so the field reads as a continuation of the command being built and the
// left-literal token begins with it.
const slashRefLabel = "/"

// slashCandidate is one command offered in the picker: its canonical name, aliases (matched by
// prefix but never displayed), and one-line description shown beside the name.
type slashCandidate struct {
	name    string
	aliases []string
	desc    string
}

// slashPickerSession holds the open picker's live state as a plain object (only the list is a
// tview handle), so filtering and token replacement can be asserted without a terminal.
// slashByte is the byte offset of the triggering '/' in the prompt buffer; candidates is the
// full registry-sourced set; query is the text typed into the picker field; shown is the
// current prefix-filtered subset rendered in list.
type slashPickerSession struct {
	slashByte  int
	candidates []slashCandidate
	query      string
	shown      []slashCandidate
	list       *tview.List
}

// slashPickerCandidates reads the registry's commands in source order as picker candidates,
// carrying each command's aliases (for prefix matching) and description (for display).
func slashPickerCandidates(reg *Registry) []slashCandidate {
	cmds := reg.Commands()
	out := make([]slashCandidate, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, slashCandidate{name: c.Name, aliases: c.Aliases, desc: c.Description})
	}
	return out
}

// openSlashPicker opens the slash-command picker anchored at the '/' at slashByte. It is a
// no-op while another overlay is open, and inert until a registry is installed (SetRegistry) —
// with none the typed '/' is left as is, mirroring how Tab name-completion is inert without a
// registry.
func (a *App) openSlashPicker(slashByte int) {
	if a.anyOverlayOpen() {
		return
	}
	if a.registry == nil {
		return // no registry installed: the trigger is inert
	}
	sess := &slashPickerSession{slashByte: slashByte, candidates: slashPickerCandidates(a.registry)}
	overlay, field := a.buildSlashPicker(sess)
	a.slashPicker = sess
	a.slashPickerOpen = true
	a.slashPickerPrev = a.app.GetFocus()
	a.pages.AddPage(slashPickerPage, wrapOverlayPage(centeredModal(overlay)), true, true)
	a.app.SetFocus(field)
}

// buildSlashPicker constructs the picker overlay: a one-line query field (seeded empty, labeled
// '/') above a command list. Each keystroke in the field re-filters and re-renders the list;
// ↑/↓ move the list selection, Enter/Tab confirm the highlighted command, ESC dismisses leaving
// the typed '/'+query literal. It returns the primitive to page in and the field to focus.
func (a *App) buildSlashPicker(sess *slashPickerSession) (tview.Primitive, *tview.InputField) {
	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	sess.list = list
	a.refreshSlashPicker(sess)
	// Fires on a mouse click of a row (the field keeps keyboard focus, so Enter/Tab are routed
	// through slashPickerFieldKeys); kept so the picker is usable with the mouse too.
	list.SetSelectedFunc(func(int, string, string, rune) { a.confirmSlashCommand() })

	field := tview.NewInputField()
	field.SetLabel(slashRefLabel)
	// No accent on the '/' label — inherit the terminal default instead of tview's built-in
	// yellow, consistent with the terminal-default theme.
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
	field.SetChangedFunc(func(text string) { a.onSlashQueryChanged(sess, text) })
	field.SetInputCapture(a.slashPickerFieldKeys)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(field, 1, 0, true).
		AddItem(list, 0, 1, false)
	body.SetBorder(true)
	body.SetTitle(" slash command ")
	return body, field
}

// slashRowText renders one command row as "/<name>  <description>" — the name (with its leading
// '/') and its one-line description on a single line.
func slashRowText(c slashCandidate) string {
	if c.desc == "" {
		return slashRefLabel + c.name
	}
	return slashRefLabel + c.name + "  " + c.desc
}

// slashPickerFieldKeys is the query field's key handler: ESC dismisses leaving the literal,
// Enter/Tab confirm the highlighted command, ↑/↓ move the list selection (the field keeps focus
// so typing continues to narrow). Every other key falls through to the field so the user can
// edit the query.
func (a *App) slashPickerFieldKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		a.dismissSlashPicker(true)
		return nil
	case tcell.KeyEnter, tcell.KeyTab:
		a.confirmSlashCommand()
		return nil
	case tcell.KeyUp:
		a.moveSlashPickerSelection(-1)
		return nil
	case tcell.KeyDown:
		a.moveSlashPickerSelection(1)
		return nil
	}
	return ev
}

// moveSlashPickerSelection moves the list cursor by delta, clamped to the current shown range
// (no wraparound), so ↑/↓ in the query field drive the list without moving the field caret. It
// is a no-op when the list is empty.
func (a *App) moveSlashPickerSelection(delta int) {
	sess := a.slashPicker
	if sess == nil || sess.list == nil || len(sess.shown) == 0 {
		return
	}
	i := sess.list.GetCurrentItem() + delta
	if i < 0 {
		i = 0
	}
	if i >= len(sess.shown) {
		i = len(sess.shown) - 1
	}
	sess.list.SetCurrentItem(i)
}

// onSlashQueryChanged is the picker query field's change hook: it re-filters the command list
// against the new query, then closes the picker when a non-empty query matches nothing —
// emptying the menu and leaving the typed '/'+query literal in the prompt buffer. An empty
// query (every command shown) and a query that still matches keep it open so the user can keep
// narrowing. Closing from the change path mirrors the '@' picker's ESC/Enter dismiss flow.
func (a *App) onSlashQueryChanged(sess *slashPickerSession, query string) {
	sess.query = query
	a.refreshSlashPicker(sess)
	if query != "" && len(sess.shown) == 0 {
		a.dismissSlashPicker(true)
	}
}

// refreshSlashPicker re-filters the candidates against the current query and rebuilds the list,
// resetting the cursor to the top. An empty query lists every command in registry order; a
// non-empty query keeps the prefix matches (canonical name or any alias), each displayed by
// canonical name, consistent with Tab completion's candidateCanonicals semantics.
func (a *App) refreshSlashPicker(sess *slashPickerSession) {
	sess.shown = rankSlashCandidates(sess.candidates, sess.query)
	sess.list.Clear()
	for _, c := range sess.shown {
		sess.list.AddItem(slashRowText(c), "", 0, nil)
	}
}

// rankSlashCandidates narrows candidates to those whose canonical name or any alias begins with
// query, in registry source order — the same prefix+alias rule candidateCanonicals applies for
// Tab completion (case-sensitive; command names are lowercase). An empty query returns every
// candidate. It returns a new slice and never mutates the input.
func rankSlashCandidates(candidates []slashCandidate, query string) []slashCandidate {
	var out []slashCandidate
	for _, c := range candidates {
		if strings.HasPrefix(c.name, query) || aliasHasPrefix(c.aliases, query) {
			out = append(out, c)
		}
	}
	return out
}

// confirmSlashCommand handles Enter/Tab/click: it reads the highlighted command, dismisses the
// overlay, replaces the input with the bare canonical "/<name>" (no trailing space, discarding
// the typed prefix), and submits it once through submitCurrent — the same boundary as pressing
// Enter on typed input, so history, echo/suppression, dispatch, and retention stay owned there.
// With no selectable command (an empty or no-match list) it dismisses leaving the typed
// '/'+query literal instead.
func (a *App) confirmSlashCommand() {
	sess := a.slashPicker
	if sess == nil {
		return
	}
	idx := sess.list.GetCurrentItem()
	if len(sess.shown) == 0 || idx < 0 || idx >= len(sess.shown) {
		a.dismissSlashPicker(true)
		return
	}
	name := sess.shown[idx].name
	a.dismissSlashPicker(false)
	a.input.SetText(slashRefLabel + name)
	a.submitCurrent()
}

// dismissSlashPicker closes the picker overlay and restores focus to whatever held it when the
// picker opened (the input area in production). When leaveLiteral is true (ESC, or Enter with no
// selectable command) it splices the typed query into the prompt buffer right after the
// triggering '/', so the '/'+query text is left literal — the '/' itself is never consumed. When
// false the caller (confirmSlashCommand) performs the token replacement. It is idempotent.
func (a *App) dismissSlashPicker(leaveLiteral bool) {
	if !a.slashPickerOpen {
		return
	}
	sess := a.slashPicker
	a.slashPickerOpen = false
	a.closeOverlayPage(slashPickerPage, &a.slashPickerPrev)
	a.slashPicker = nil
	if leaveLiteral && sess != nil && sess.query != "" {
		text := a.input.GetText()
		insertAt := sess.slashByte + len(slashRefLabel) // right after the '/'
		if insertAt <= len(text) {
			a.input.Replace(insertAt, insertAt, sess.query)
		}
	}
}
