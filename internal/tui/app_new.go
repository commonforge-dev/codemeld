package tui

import (
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var themeOnce sync.Once

// applyTheme switches tview's process-global default theme to the terminal's own
// colors: PrimitiveBackgroundColor, PrimaryTextColor, BorderColor, TitleColor, and
// ContrastBackgroundColor become tcell.ColorDefault, so every primitive inherits the
// terminal's background and foreground instead of tview's hardcoded black-on-white
// (calls the phase-1 appearance "terminal-default"). It must run before any
// widget is built, because tview snapshots Styles into a widget at construction time;
// New applies it once per process through themeOnce.
//
// ContrastBackgroundColor is defaulted here because tview.InputField snapshots it as
// its field background at construction (tview v0.42 inputfield.go); without this the
// input box draws in tview's hardcoded blue. Defaulting it lets the field background
// inside the input's border inherit the terminal background instead.
func applyTheme() {
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault
	tview.Styles.PrimaryTextColor = tcell.ColorDefault
	tview.Styles.BorderColor = tcell.ColorDefault
	tview.Styles.TitleColor = tcell.ColorDefault
	tview.Styles.ContrastBackgroundColor = tcell.ColorDefault
}

// applyPickerListColors keeps a focusable list's cursor row visible after the
// terminal-default theme change. Defaulting PrimaryTextColor makes tview.List's
// default selected-row style (it snapshots Bg = PrimaryTextColor) invisible, so the
// main text is set to inherit the terminal foreground and the selected row is drawn
// with reverse video — inverting the terminal's own fg/bg — so the highlight carries
// no fixed color and reads on both light and dark terminals. Call it on every
// focusable tview.List the TUI constructs.
func applyPickerListColors(l *tview.List) {
	l.SetMainTextColor(tcell.ColorDefault)
	l.SetSelectedStyle(tcell.StyleDefault.Reverse(true))
}

// overlayBackground wraps a page-mounted overlay's root primitive so the whole
// page rectangle is painted with opaque terminal-default spaces before the
// overlay is drawn over it. tview.Flex roots set their box to dontClear, so a
// full-screen overlay page leaves its unused cells showing whatever the main page
// drew underneath — the transcript bleeds through behind the picker/prompt.
// A plain tview primitive is not an equivalent substitute: the only clearing
// candidate is a tview.Flex with its embedded Box reset to a clearing tview.NewBox()
// and a full-size proportional child, which just relocates this opacity guarantee
// into a more fragile setup that silently regresses to bleed-through if the Box
// reset is ever dropped — so the explicit unconditional fill below is kept.
// Painting the rect first in the terminal-default style (the same base background
// the rest of the UI inherits) makes every page-mounted overlay opaque
// without changing the terminal-default appearance, even where the current root
// happens to clear on its own. The wrapper owns only the background: sizing,
// focus, and key/mouse/paste routing all delegate to inner, so the overlay's
// existing focused child and handlers are unaffected.
type overlayBackground struct {
	*tview.Box
	inner tview.Primitive
}

// wrapOverlayPage returns inner wrapped so its page paints an opaque
// terminal-default background under it. Pass the result to Pages.AddPage and keep
// focusing the builder's own child primitive — the wrapper delegates focus to inner
// (Pages routes input to the page whose item HasFocus, so the delegation below is
// what keeps the wrapped overlay's keys reaching its focused child).
func wrapOverlayPage(inner tview.Primitive) *overlayBackground {
	return &overlayBackground{Box: tview.NewBox(), inner: inner}
}

// Draw paints the page rect with terminal-default spaces, then draws the wrapped
// overlay over it at the same rect. The fill overwrites every cell the main page
// left behind, so no underlying transcript text survives in the overlay page area.
func (o *overlayBackground) Draw(screen tcell.Screen) {
	x, y, width, height := o.GetRect()
	style := tcell.StyleDefault.Background(tview.Styles.PrimitiveBackgroundColor)
	for row := y; row < y+height; row++ {
		for col := x; col < x+width; col++ {
			screen.SetContent(col, row, ' ', nil, style)
		}
	}
	o.inner.SetRect(x, y, width, height)
	o.inner.Draw(screen)
}

func (o *overlayBackground) Focus(delegate func(p tview.Primitive)) { o.inner.Focus(delegate) }
func (o *overlayBackground) HasFocus() bool                         { return o.inner.HasFocus() }
func (o *overlayBackground) Blur()                                  { o.inner.Blur() }

func (o *overlayBackground) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) {
	return o.inner.InputHandler()
}

func (o *overlayBackground) MouseHandler() func(tview.MouseAction, *tcell.EventMouse, func(tview.Primitive)) (bool, tview.Primitive) {
	return o.inner.MouseHandler()
}

func (o *overlayBackground) PasteHandler() func(string, func(tview.Primitive)) {
	return o.inner.PasteHandler()
}

// New constructs the application shell, stacking the transcript pane above the
// input area and binding Enter to submit. submit is the injected dispatch hook;
// a nil hook makes every submission a no-op that retains the input.
func New(submit SubmitFunc) *App {
	// Switch to the terminal-default theme before any widget is constructed: tview
	// snapshots Styles into a widget at construction time, and the transcript/input/
	// status/panel widgets are built immediately below. tview.Styles is process-global
	// and tview reads it while rendering on other goroutines, so the write happens
	// exactly once and every later App — and every render — is ordered after it.
	themeOnce.Do(applyTheme)
	a := &App{
		app:                tview.NewApplication(),
		transcript:         newTranscript(),
		input:              newInput(),
		submit:             submit,
		history:            NewHistory(),
		now:                time.Now,
		afterFunc:          func(d time.Duration, f func()) { time.AfterFunc(d, f) },
		indicatorInterval:  time.Second,
		newScreen:          tcell.NewScreen,
		promptNotifyAfter:  time.After,
		promptNotifyWrite:  defaultPromptNotifyWrite,
		questionFormMounts: make(chan struct{}, 1),
		lifecycle:          make(chan struct{}),
	}
	// The repaint seam wraps the owned tview application's ForceDraw so handlers request
	// a redraw without depending on the terminal; tests override it. ForceDraw and not
	// Draw: every caller runs on the tview event-loop goroutine, where Draw's internal
	// QueueUpdate would block forever on a queue only that goroutine drains.
	a.draw = func() { a.app.ForceDraw() }
	// Install the default OS-clipboard image reader the CTRL-V action reads through.
	// Tests replace it via SetClipboardReader so the real helper subprocess
	// never runs in CI; production reads the live clipboard through it.
	a.clipboard = newClipboardReader()
	a.panel = tview.NewTextView()
	a.panel.SetDynamicColors(false)
	a.panel.SetBorder(true)
	a.panel.SetInputCapture(a.handlePanelKey)

	a.status = &statusView{TextView: tview.NewTextView()}
	// Dynamic colors on so RenderStatus's [::b]Title[::-] section-title markup renders
	// as bold rather than printing literally. RenderStatus escapes its own
	// bracketed data (the [global]/[project] config-layer labels) so only the title
	// tags are interpreted.
	a.status.SetDynamicColors(true)
	// No chrome of its own: the overlay sits directly under the input area, whose own
	// bottom rule already separates the prompt from the snapshot, so the overlay draws
	// neither a four-sided box nor its own top rule — a second rule one row below the
	// input's bottom rule read as a redundant separator bar (superseding the earlier
	// top-rule treatment).
	a.status.SetBorder(false)
	a.status.SetInputCapture(a.handleStatusKey)

	// The in-flight activity indicator is a borderless one-line row that
	// stays collapsed (height 0) until a turn starts. It carries no border so it
	// reads as a single chrome line, like the status-line footer.
	a.indicator = tview.NewTextView()
	a.indicator.SetDynamicColors(false)

	// The persistent bottom footer is two stacked rows: row 1 (statusBar) carries the
	// filled two-tone provider/model/effort/dir segments; row 2 (statusModeRow) carries the
	// filled "• <mode>" pill followed immediately by the fixed shift+tab hint, both
	// left-grouped. Dynamic colors are on for both so the segment fill tags and the mode-pill
	// fill tag (closed literal sets) render rather than printing literally. Neither carries a
	// border, so the footer reads as two clean chrome lines. statusModeKey defaults to plan
	// so the pill renders before the production wiring seeds the real launch mode
	// (RefreshModeHint); the row is seeded with that default pill + hint here.
	a.statusBar = tview.NewTextView()
	a.statusBar.SetDynamicColors(true)
	a.statusModeRow = tview.NewTextView()
	a.statusModeRow.SetDynamicColors(true)
	a.RefreshModeHint(modeKeyPlan)
	a.statusBarRow = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.statusBar, 1, 0, false).
		AddItem(a.statusModeRow, 1, 0, false)

	// The status overlay is a temporary panel drawn
	// directly under the input area, so it lives in the root flex immediately after
	// a.input — before the persistent footer (status line + mode hint), which is
	// pushed below it while the overlay is open. It starts at fixed size 0 and is
	// sized to fit its rendered text when ShowStatus opens it. Keeping it in the root
	// flex — not a full-screen Pages page — preserves the transcript and input layout
	// while the snapshot is on screen, and its single top rule joins the input's
	// bottom rule. inputHeight is the baseline single-line footprint — three rows so
	// the top and bottom rules plus one prompt line fit; inputRows() grows the
	// row beyond it for multi-line drafts.
	a.queueRows = tview.NewTextView()
	a.queueRows.SetDynamicColors(false)
	a.queueRows.SetWrap(false)
	a.queueRows.SetTextStyle(tcell.StyleDefault.Foreground(ghostTextColor).Background(tcell.ColorDefault).Dim(true))

	a.bannerGap = tview.NewBox()
	a.root = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(a.transcript.view, 0, 0, false).
		AddItem(a.bannerGap, bannerGapHeight, 0, false).
		AddItem(a.indicator, 0, 0, false).
		AddItem(a.queueRows, 0, 0, false).
		AddItem(a.input, inputHeight, 0, true).
		AddItem(a.status, 0, 0, false).
		AddItem(a.statusBarRow, statusBarHeight, 0, false).
		AddItem(tview.NewBox(), 0, 1, false)

	// Recompute the transcript height just before each draw, when the root
	// rectangle is already assigned, so content growth, a /clear shrink, and a
	// terminal resize all reflow on the next draw. Returning false lets normal
	// drawing continue.
	a.app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		width, height := screen.Size()
		a.root.ResizeItem(a.bannerGap, a.spacerRows(height), 0)
		// Grow the input row to the current buffer's wrapped-row count at the live
		// width first, so the transcript cap (chromeRows) reflects the same input
		// height this draw and the two never disagree about how many rows the input
		// claims. The width also re-wraps the input on resize.
		a.root.ResizeItem(a.input, a.inputRows(width, height), 0)
		// Align the input's vertical scroll with the box height just allocated, on the
		// same frame: when the buffer fits, re-show the first wrapped row (tview scrolled
		// rowOffset to 1 against the stale height on a wrap); when it overflows the
		// cap, scroll so the cursor's wrapped row is the last visible row, showing the
		// tail of a long expanded paste at the bottom. Same width and cap the
		// resize above used so the fit/overflow decision matches the height allocated.
		// Skipped while an app-owned plain drag is selecting: that drag owns the row
		// offset through scrollDrag, and adjustRowOffset would otherwise snap the viewport
		// to the moving selection end each frame — jumping the view on the initial click
		// and fighting the drag's own scrolling. The buffer cannot change mid-drag,
		// so the fit/overflow realignment this skips is not needed until the drag ends.
		if !a.inputSelecting {
			a.input.adjustRowOffset(width, a.inputTextRowCap(height))
		}
		a.resizeTranscript(width, height)
		return false
	})

	// A Pages host lets the modal panel overlay the main layout: while the panel
	// page is visible and focused it captures input, blocking the input area until
	// ESC dismisses it.
	a.pages = tview.NewPages().
		AddPage("main", a.root, true, true).
		AddPage("panel", wrapOverlayPage(a.panel), true, false)
	a.app.SetRoot(&rootPages{Pages: a.pages, app: a}, true)

	// Global key handling above the focused primitive: CTRL-E opens the effort
	// picker. Every other key falls through to the focused widget
	// unchanged. Cross-overlay key priority as a whole is owned elsewhere; this
	// capture only adds the one app-level shortcut and is a no-op while an overlay
	// is open.
	a.app.SetInputCapture(a.handleGlobalKey)

	// Enable bracketed paste so the terminal marks a pasted block as a paste.
	// With it off — the prior state — a pasted line break arrives as a
	// plain tcell.KeyEnter, indistinguishable from a pressed Enter, so handleInputKey
	// submits at the first line break and the rest of a multi-line paste is lost.
	// With it on, tview's Run loop buffers the block between EventPaste start/end
	// markers and hands the whole string (newlines preserved) to the focused
	// primitive's PasteHandler — the input TextArea inserts it verbatim and nothing
	// submits until the user presses Enter. It does not
	// change the Enter-submits / chord-inserts-newline contract in handleInputKey.
	a.app.EnablePaste(true)

	// Enable terminal mouse reporting so the wheel scrolls the transcript.
	// tview maps the tcell wheel buttons to MouseScrollUp/Down and routes them to
	// the primitive under the cursor; the transcript's capture below acts on those.
	// Mouse mode takes plain click-drag away from the terminal's native selection, so
	// codemeld owns it: a plain drag in the transcript selects and copies text in-app
	// (handleAppMouse), and Shift+drag remains the native select/copy escape
	// hatch where the terminal still offers it (see /help and the TUI learning
	// module). Key handling (pickers, overlays, the permission prompt) is unaffected:
	// mouse events are a separate routing path.
	a.app.EnableMouse(true)
	// The transcript is not focusable, so its wheel scrolling is driven by a mouse
	// capture rather than a focused-primitive handler. The capture checks the cursor
	// is over the transcript before consuming, so a wheel over the input or chrome is
	// left for those rows (the transcript is the first flex child and would otherwise
	// swallow every wheel event).
	a.transcript.view.SetMouseCapture(a.handleTranscriptMouse)
	// Left-click focus preservation runs at the application level, not on the
	// transcript view, because tview only routes an event to a primitive's own capture
	// after deciding which row it lands on — a click on the chrome rows between the
	// transcript and the input (the in-flight indicator and the banner-gap spacer)
	// never reaches the transcript capture. The app capture runs before that routing,
	// so it is the one seam that can keep the input focused for any above-input click.
	a.app.SetMouseCapture(a.handleAppMouse)

	// The input is a tview.TextArea, which has no single-line "done" event, so the
	// Enter-submit / chord-insert-newline split is intercepted in handleInputKey
	// rather than via SetDoneFunc. The capture also routes ↑/↓ to input
	// history at the buffer's first/last logical line and Tab to slash-name
	// completion. It is local to the input field, so when an overlay is
	// focused (panel, pickers, prompts) those keys reach that overlay instead;
	// cross-overlay key priority is owned elsewhere.
	a.input.SetInputCapture(a.handleInputKey)
	// Ordinary typed runes never reach SetInputCapture, so the '@' file-reference
	// trigger watches the buffer through the TextArea change hook instead,
	// comparing each change against the previously observed text to spot a single '@'
	// inserted at a word boundary. tview.TextArea.SetChangedFunc takes no text argument
	// (unlike InputField's), so onInputChanged reads the buffer itself. Short pastes
	// get a second observer so pasted image paths can be promoted immediately without
	// making ordinary typed paths validate before Enter.
	a.input.SetChangedFunc(a.onInputChanged)
	a.input.SetPasteFunc(a.attachPastedImagePaths)
	return a
}
