package tui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/uniseg"

	"codemeld.dev/codemeld/internal/sessions"
)

// ShowPanel opens the modal text panel over the main layout, moving focus to it
// so it captures input while open. It satisfies the CommandHost panel
// surface used by the /help handler.
func (a *App) ShowPanel(text string) {
	a.panel.SetText(text)
	a.panel.ScrollToBeginning()
	a.panelOpen = true
	a.pages.ShowPage("panel")
	a.app.SetFocus(a.panel)
}

// dismissPanel closes the panel and returns focus to the input area. The input
// buffer is never touched, so the user's typed text survives the panel.
func (a *App) dismissPanel() {
	if !a.panelOpen {
		return
	}
	a.panelOpen = false
	a.pages.HidePage("panel")
	a.app.SetFocus(a.input)
}

// handlePanelKey is the panel's key handler: ESC dismisses it; every other key
// is left to the panel (e.g. for scrolling) and never reaches the input area.
func (a *App) handlePanelKey(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyEscape {
		a.dismissPanel()
		return nil
	}
	return ev
}

// ShowStatus opens the /status overlay with text, moving focus to it so it
// captures input while open. The overlay is sized to fit the rendered
// snapshot (one row per text line, no chrome row — the overlay draws no rule of
// its own) so the temporary panel below the input area is just tall enough
// for its content. It is the embedding-app surface the /status handler reaches
// via CommandHost.ShowStatus.
func (a *App) ShowStatus(text string) {
	a.status.SetText(text)
	a.status.ScrollToBeginning()
	a.status.clearSelection()
	a.armStatusCopy()
	a.statusOpen = true
	a.root.ResizeItem(a.status, statusPanelHeight(text), 0)
	a.app.SetFocus(a.status)
}

// dismissStatus closes the status overlay and returns focus to the input area.
// The input buffer is never touched, so anything typed before the
// overlay opened survives.
func (a *App) dismissStatus() {
	if !a.statusOpen {
		return
	}
	a.statusOpen = false
	a.status.clearSelection()
	a.statusRegions.set(nil)
	a.root.ResizeItem(a.status, 0, 0)
	a.app.SetFocus(a.input)
}

// armStatusCopy captures the session id and the copy control's byte range from the
// snapshot just installed, so a click copies the value the overlay froze rather than
// whatever the session holds at click time.
func (a *App) armStatusCopy() {
	a.statusRegions.set(nil)
	if a.statusLineState == nil {
		return
	}
	id := a.statusLineState.SessionID()
	if id == "" {
		return
	}
	start, end, ok := statusCopyRange(a.status.GetText(true))
	if !ok {
		return
	}
	a.statusRegions.set([]clickRegion{{start: start, end: end, payload: id}})
}

func statusCopyRange(text string) (start, end int, ok bool) {
	base := 0
	for _, line := range strings.SplitAfter(text, "\n") {
		body := strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(body, statusSessionPrefix) && strings.HasSuffix(body, statusCopyControl) {
			return base + len(body) - len(statusCopyControl), base + len(body), true
		}
		base += len(line)
	}
	return 0, 0, false
}

// statusPanelHeight reports the row count the status panel needs to render text
// without scrolling: one row per line in text, with no chrome row reserved — the
// overlay draws no rule or border of its own (an earlier design removed the top rule that the
// row previously accounted for).
func statusPanelHeight(text string) int {
	return strings.Count(text, "\n") + 1
}

// resizeTranscript fixes the transcript row height to its wrapped content,
// capped at the screen height minus the App-owned fixed chrome rows, so the
// input box sits directly below the transcript until the conversation grows tall
// enough to fill the screen — then the transcript holds at max height and the
// renderLocked ScrollToEnd keeps following the newest line. The trailing
// proportion-1 spacer in the root flex absorbs any rows left below the chrome.
// It runs from the before-draw hook on the event-loop goroutine, where the root
// rectangle is already assigned and no transcript mutation can race it.
func (a *App) resizeTranscript(screenWidth, screenHeight int) {
	if screenWidth <= 0 || screenHeight <= 0 {
		return
	}
	avail := screenHeight - a.chromeRows(screenWidth, screenHeight)
	if avail < 0 {
		avail = 0
	}
	h := a.transcript.wrappedLineCount(screenWidth)
	if h > avail {
		h = avail
	}
	a.root.ResizeItem(a.transcript.view, h, 0)
}

// chromeRows reports the fixed root-Flex rows the transcript height must leave room
// for: the always-present non-input chrome (reservedNonInputRows) plus the input area
// itself at the live width/height. tview.Flex exposes no fixed-size readback, so this
// is the single place the row budget is derived from App state rather than the flex
// internals. width is the live terminal width so the input-area term matches the
// width-driven height the before-draw hook sizes the input box to; height is
// passed through so the input's adaptive cap (inputTextRowCap) is computed against the
// same screen the transcript is being sized for.
func (a *App) chromeRows(width, height int) int {
	return a.reservedNonInputRows(height) + a.inputRows(width, height)
}

func (a *App) spacerRows(height int) int {
	if !a.IndicatorVisible() {
		return bannerGapHeight
	}
	reserved := activeGapHeight + statusBarHeight + indicatorHeight + a.statusOverlayRows() + minInputTextRows + inputChromeRows
	if height-reserved >= minTranscriptRows {
		return activeGapHeight
	}
	return bannerGapHeight
}

func (a *App) statusOverlayRows() int {
	if !a.statusOpen {
		return 0
	}
	return statusPanelHeight(a.status.GetText(true))
}

func (a *App) reservedNonInputRows(height int) int {
	rows := a.spacerRows(height) + statusBarHeight
	if a.IndicatorVisible() {
		rows += indicatorHeight
	}
	return rows + a.statusOverlayRows() + len(a.queued)
}

// inputTextRowCap reports the maximum text rows the input box may grow to at the live
// terminal height, reserving the input's own chrome rules, the non-input chrome, and a
// minTranscriptRows conversation floor. Because it subtracts the same
// reservedNonInputRows chromeRows adds, when the input sits at this cap the transcript
// still keeps exactly minTranscriptRows. It floors at minInputTextRows so a terminal too
// short to honor the full reservation still shows one input row.
func (a *App) inputTextRowCap(height int) int {
	cap := height - a.reservedNonInputRows(height) - inputChromeRows - minTranscriptRows
	if cap < minInputTextRows {
		cap = minInputTextRows
	}
	return cap
}

// inputRows reports the input area's current row height: one row per wrapped screen
// row the buffer occupies at the live width (input width minus the "> " label), capped
// at the height-aware inputTextRowCap, plus the two chrome rule rows (inputChromeRows).
// It is width-driven so long lines wrap onto visible rows and the input reflows on
// resize (extending the logical-line growth) and height-driven so an
// expanded paste grows toward the available terminal height instead of a fixed cap;
// a single-line buffer still yields the prior inputHeight (3). The before-draw
// hook sizes the input flex item to it and chromeRows subtracts it at the same
// width/height, so the input and the transcript cap agree each draw.
func (a *App) inputRows(width, height int) int {
	rows := a.input.wrappedRows(width)
	if cap := a.inputTextRowCap(height); rows > cap {
		rows = cap
	}
	return rows + inputChromeRows
}

// SetStatusLineState installs the StatusState the bottom bar's segments render from and
// seeds the bar immediately. The production wiring
// passes the same statusState object /status and the launch banner read, so the three
// never drift. With none installed RefreshStatusLine renders nothing, so unit tests can
// construct App without bootstrap state. It is set once before Run.
func (a *App) SetStatusLineState(s StatusState) {
	a.statusLineState = s
	a.RefreshStatusLine()
}

// RefreshStatusLine re-renders the footer's first row (statusBar) from the current active
// selection: the filled two-tone provider/model/effort/dir segments (RenderStatusLine), so
// the segments live-update after a model or effort change. The mode pill lives on the second
// row and is refreshed separately by RefreshModeHint, so this never touches it. With no
// StatusState installed (unit tests) it renders the row empty. Callers run on the tview
// event-loop goroutine (the model/effort apply paths and the pre-Run seed), so the text is
// set directly without marshaling through the event queue.
func (a *App) RefreshStatusLine() {
	if a.statusLineState == nil {
		a.statusBar.SetText("")
		return
	}
	a.statusBar.SetText(RenderStatusLine(a.statusLineState))
}

func (a *App) RefreshStatusLineFromBackground() { a.streamUpdate(a.RefreshStatusLine) }

// StatusLineText returns the footer's first-row text (the segments), with tview tags
// stripped. It is a cross-package read-only test seam (like StatusText): bootstrap's StartTUI
// assembly test reads it back after driving a real model/effort apply through the production
// path, proving the segments reflect the new selection from the installed statusState — not
// an in-memory-only snapshot. Production renders the row through the view off the live event
// loop; this is never called at runtime.
func (a *App) StatusLineText() string { return a.statusBar.GetText(true) }

// RefreshModeHint records modeKey as the active interaction mode and re-renders the footer's
// second row (statusModeRow) so its filled "• <mode>" pill — followed by the shift+tab hint —
// reflects it (the pill has its own row, folding in the mode-hint row). It is
// seeded at launch from the active mode and called on every switch through the shared
// ModeDeps.Notify seam, so the row always shows the current mode and a switch no longer
// appends a confirmation line to the transcript. Callers run on the tview event-loop goroutine (the
// pre-Run seed and the Notify callback the key/command paths drive), so the text is set
// directly without marshaling through the event queue.
func (a *App) RefreshModeHint(modeKey string) {
	a.statusModeKey = modeKey
	a.statusModeRow.SetText(modePill(modeKey) + " " + statusBarHint)
	a.RefreshStatusLine()
}

func (a *App) StatusModeKey() string { return a.statusModeKey }

const (
	sessionBadgeRightMargin = 2
	sessionBadgeMinRule     = 8
)

func fitSessionBadge(name string, width int) string {
	if name == "" {
		return ""
	}
	avail := width - sessionBadgeRightMargin - sessionBadgeMinRule - 2
	if avail < 1 {
		return ""
	}
	if uniseg.StringWidth(name) > avail {
		if avail < 2 {
			return ""
		}
		name = truncateCells(name, avail-1) + "…"
	}
	return " " + name + " "
}

func truncateCells(s string, max int) string {
	var b strings.Builder
	used, state := 0, -1
	for s != "" {
		cluster, rest, boundaries, st := uniseg.StepString(s, state)
		w := boundaries >> uniseg.ShiftWidth
		if used+w > max {
			break
		}
		b.WriteString(cluster)
		used += w
		s, state = rest, st
	}
	return b.String()
}

// RefreshSessionBadge shows store's title in the badge only while store is the active
// store, and is safe to call off the event loop.
func (a *App) RefreshSessionBadge(store *sessions.Store) {
	a.activeMu.Lock()
	if store != a.activeStore {
		a.activeMu.Unlock()
		return
	}
	name := ""
	if store != nil {
		name = store.Title()
	}
	a.input.setSessionName(name)
	a.activeMu.Unlock()

	if a.stopping.Load() {
		return
	}
	if !a.running.Load() {
		if a.draw != nil {
			a.draw()
		}
		return
	}
	go func() {
		if a.stopping.Load() || !a.running.Load() {
			return
		}
		a.app.QueueUpdate(func() {
			if a.stopping.Load() || a.ActiveStore() != store || a.draw == nil {
				return
			}
			a.draw()
		})
	}()
}

func (a *App) SessionBadgeText() string { return a.input.sessionName() }

// ApplyInputAccent recolors the input's prompt glyph and both horizontal rules to a
// run-scoped accent and requests a redraw so the change is visible immediately. The
// accent lives only on the input field for the running session — nothing is persisted and it
// is not carried across --resume. Global tview.Styles and every surface outside the input area
// are left untouched. The /color command drives this after resolving a palette name to color.
func (a *App) ApplyInputAccent(color tcell.Color) {
	a.input.applyAccent(color)
	if a.draw != nil {
		a.draw()
	}
}

// ModeHintText returns the footer's second-row text (the filled "• <mode>" pill plus the
// shift+tab hint), with tview color tags stripped (GetText(true)). It is a cross-package
// read-only test seam (like StatusLineText): bootstrap's StartTUI assembly test reads it back
// after driving a mode switch through the production Notify path, proving the pill reflects
// the active mode rather than the transcript carrying the confirmation. It is the second
// footer row, distinct from StatusLineText's segments. Production renders the
// row through the view off the live event loop; this is never called at runtime.
func (a *App) ModeHintText() string { return a.statusModeRow.GetText(true) }

// handleStatusKey is the status overlay's key handler: ESC dismisses it; the
// arrow keys are consumed so they cannot scroll or navigate the static snapshot
// ("no auto-refresh", snapshot is static); every other key is left to
// the overlay so it cannot reach the input area while the snapshot is on screen
// ("block input-area keystrokes while open").
func (a *App) handleStatusKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		a.dismissStatus()
		return nil
	case tcell.KeyUp, tcell.KeyDown, tcell.KeyLeft, tcell.KeyRight:
		return nil
	}
	return ev
}
