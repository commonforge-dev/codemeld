// CTRL-R history reverse-search overlay: searches the in-session
// input history backwards for the most recent entry containing the typed
// substring, renders that match above a search field, and accepts it into the input
// buffer on Enter. Phase 1 shows the single most-recent match only; cycling to older
// matches is deferred to phase 2. Empty history renders a one-line hint and opens no
// overlay.
package tui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// reverseSearchPage is the Pages name the reverse-search overlay is mounted under
// while open, removed when it dismisses.
const reverseSearchPage = "reverse-search"

// reverseSearchLabel prefixes the overlay's search field so the input area is
// visibly the reverse-search query, not the main prompt.
const reverseSearchLabel = "reverse-search: "

// reverseSearchEmptyHint is the one-line notice shown when CTRL-R is pressed
// with empty in-session history. It opens no overlay and clears on the next keystroke.
const reverseSearchEmptyHint = "no input history yet"

// reverseSearchNoMatch is the explicit no-match state rendered above the search
// field when the current query matches no history entry, so Enter has nothing to
// accept and the prior match is not retained.
const reverseSearchNoMatch = "(no match)"

// reverseSearchSession holds the open overlay's live matching state as a plain
// object (no tview), so the backwards-matching and accept/no-op transitions can be
// asserted without a terminal. history is the input-history snapshot in submission order
// (oldest first, newest last); query is the typed substring; match/matched are the
// most-recent entry containing query and whether one exists.
type reverseSearchSession struct {
	history []string
	query   string
	match   string
	matched bool
}

// newReverseSearchSession starts a session over history with an empty query. An
// empty query matches the newest entry (strings.Contains(_, "") is always true), so
// a freshly opened overlay shows the most recent submission as its initial match.
func newReverseSearchSession(history []string) *reverseSearchSession {
	s := &reverseSearchSession{history: history}
	s.setQuery("")
	return s
}

// setQuery records the typed substring and recomputes the most-recent match,
// searching history newest to oldest. When no entry matches it clears the match so a
// previous match is never retained or accepted.
func (s *reverseSearchSession) setQuery(query string) {
	s.query = query
	s.match, s.matched = mostRecentMatch(s.history, query)
}

// mostRecentMatch returns the most recent history entry containing query as a
// substring, scanning newest (last) to oldest (first). An empty query matches the
// newest entry; an empty history (or no containing entry) returns ("", false). The
// match is an exact substring — specifies no case folding.
func mostRecentMatch(history []string, query string) (string, bool) {
	for i := len(history) - 1; i >= 0; i-- {
		if strings.Contains(history[i], query) {
			return history[i], true
		}
	}
	return "", false
}

// renderReverseSearchMatch is the line shown above the search field: the matched
// entry, or the explicit no-match state when the query matches nothing.
func renderReverseSearchMatch(s *reverseSearchSession) string {
	if s.matched {
		return s.match
	}
	return reverseSearchNoMatch
}

// openReverseSearch opens the reverse-search overlay. It is a no-op while
// another overlay is open. With empty in-session history it renders the
// `no input history yet` hint and opens no overlay; otherwise it builds the
// overlay over a copy of the history snapshot and moves focus to the search field so
// typing drives the match and Enter/ESC/↑/↓ are owned by the overlay.
func (a *App) openReverseSearch() {
	if a.anyOverlayOpen() {
		return
	}
	snapshot := a.history.Snapshot()
	if len(snapshot) == 0 {
		a.showReverseSearchHint()
		return
	}
	a.reverseSearch = newReverseSearchSession(snapshot)
	overlay, field := a.buildReverseSearch()
	a.reverseSearchOpen = true
	a.reverseSearchPrev = a.app.GetFocus()
	a.pages.AddPage(reverseSearchPage, wrapOverlayPage(overlay), true, true)
	a.app.SetFocus(field)
}

// buildReverseSearch constructs the overlay: a one-line match display above a search
// input field. Each keystroke in the field recomputes the match and refreshes the
// display; Enter accepts a match, ESC dismisses with no change, and ↑/↓ are consumed
// at the overlay level (phase 1 keeps the single most-recent match selected; older-
// match cycling is phase 2). It returns the primitive to page in and the
// field to focus.
func (a *App) buildReverseSearch() (tview.Primitive, *tview.InputField) {
	matchView := tview.NewTextView()
	matchView.SetDynamicColors(false)
	matchView.SetText(renderReverseSearchMatch(a.reverseSearch))

	field := tview.NewInputField()
	field.SetLabel(reverseSearchLabel)
	field.SetLabelStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorDefault))
	field.SetChangedFunc(func(text string) {
		a.reverseSearch.setQuery(text)
		matchView.SetText(renderReverseSearchMatch(a.reverseSearch))
	})
	field.SetInputCapture(a.reverseSearchFieldKeys)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(matchView, 1, 0, false).
		AddItem(field, 1, 0, true)
	body.SetBorder(true)
	body.SetTitle(" reverse-search ")
	return body, field
}

// reverseSearchFieldKeys is the search field's key handler: ESC dismisses the
// overlay with no change to the input buffer, Enter accepts the current match, and
// ↑/↓ are consumed at the overlay level so they neither move within the field nor
// reach the main input's history navigation — the single most-recent match stays
// selected (older-match cycling is phase 2). Every other key falls through
// to the field so the user can edit the query.
func (a *App) reverseSearchFieldKeys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		a.dismissReverseSearch()
		return nil
	case tcell.KeyEnter:
		a.acceptReverseSearch()
		return nil
	case tcell.KeyUp, tcell.KeyDown:
		return nil
	}
	return ev
}

// acceptReverseSearch handles Enter in the overlay: with a current match it accepts
// that entry into the main input buffer, dismisses the overlay, and restores normal
// input editability. With no match Enter is a no-op — the prior buffer is
// left untouched and the overlay stays open. Accepting only replaces the editable
// buffer; it appends nothing to history until the user later submits.
func (a *App) acceptReverseSearch() {
	if a.reverseSearch == nil || !a.reverseSearch.matched {
		return
	}
	match := a.reverseSearch.match
	a.dismissReverseSearch()
	a.input.SetText(match)
}

// dismissReverseSearch closes the overlay and restores focus to whatever held it when
// CTRL-R was pressed (the input area in production). The main input buffer is never
// touched here, so ESC dismissal leaves the prior typed text intact. It is
// idempotent.
func (a *App) dismissReverseSearch() {
	if !a.reverseSearchOpen {
		return
	}
	a.reverseSearchOpen = false
	a.pages.RemovePage(reverseSearchPage)
	if a.reverseSearchPrev != nil {
		a.app.SetFocus(a.reverseSearchPrev)
	} else {
		a.app.SetFocus(a.input)
	}
	a.reverseSearchPrev = nil
	a.reverseSearch = nil
}

// showReverseSearchHint renders the empty-history hint on the one-line
// notice surface and marks it shown so the next keystroke clears it.
func (a *App) showReverseSearchHint() {
	a.reverseSearchHintShown = true
	a.Notice(reverseSearchEmptyHint)
}

// clearReverseSearchHint removes the empty-history hint if it is showing. It is a
// no-op otherwise, so handleGlobalKey can call it cheaply on every keystroke, and it
// only clears the notice it set itself.
func (a *App) clearReverseSearchHint() {
	if !a.reverseSearchHintShown {
		return
	}
	a.reverseSearchHintShown = false
	a.Notice("")
}
