// Package tui implements the terminal user interface shell: the tview
// application, the transcript pane, and the input area.
package tui

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// Fixed root-Flex chrome row heights the transcript-height computation subtracts, named as
// constants so the before-draw row budget derives from the same values New sets rather than
// re-hard-coding them. inputHeight is the single-line input footprint that a multi-line draft
// grows past.
const (
	inputHeight = 3
	// statusBarHeight is the always-visible bottom chrome footer: two rows — row 1
	// the provider/model/effort/dir segments, row 2 the filled mode pill followed by the
	// shift+tab hint, both left-grouped. An earlier design merged the status footer and the
	// mode-hint row into one row; they are split back into two stacked rows to match the
	// design sample, so the height is 2.
	statusBarHeight = 2
	indicatorHeight = 1 // the in-flight indicator row, counted only while a turn streams
	bannerGapHeight = 1
	activeGapHeight = 2
)

// Input-area sizing for the multi-line prompt: inputChromeRows is
// the two non-text rows newInput draws (the top and bottom rules). One text row plus
// those two chrome rows equals inputHeight, so a single-line buffer keeps its prior
// footprint. The text-row cap is no longer a fixed constant: it grows with the live
// terminal height (App.inputTextRowCap) so an expanded paste fills toward the available
// height, while minTranscriptRows is held back for the conversation above and
// minInputTextRows floors the cap so the input keeps at least one text row on a short
// terminal.
const (
	inputChromeRows = 2
	// minTranscriptRows is the conversation reservation the adaptive input cap leaves
	// free: the input grows toward the terminal height but always leaves at least this
	// many rows for the transcript above it, so an expanded paste cannot claim the whole
	// screen. The exact value mirrors Claude Code's "leave room for the conversation"
	// feel rather than a fixed fraction.
	minTranscriptRows = 6
	// minInputTextRows floors the adaptive cap so the input still shows at least one text
	// row on a terminal too short to honor the full transcript reservation.
	minInputTextRows = 1
)

// statusBarHint is the fixed affordance on the footer's second row, naming the shift+tab
// mode-cycle key. It is placed immediately after the filled mode pill, both left-grouped
// on the mode row.
const statusBarHint = "shift+tab to cycle"

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

// SubmitFunc receives trimmed prompt input plus any pending image content parts and
// reports whether it accepted the submission. The app clears the input field only
// when the hook returns true. imageParts is the variadic tail so existing text-only
// callers and the many command tests still pass just a string; when present
// only the plain-prompt path carries them onward — slash command dispatch stays
// text-only. Slash parsing and command dispatch land behind this seam.
type SubmitFunc func(input string, imageParts ...sessions.ContentPart) bool

// App is the tview application shell: an event loop, a root layout with the
// transcript pane above the input area, and an injected submit hook.
type App struct {
	app        *tview.Application
	pages      *tview.Pages
	root       *tview.Flex
	transcript *transcript
	input      *inputField
	panel      *tview.TextView
	panelOpen  bool
	status     *statusView
	statusOpen bool

	// statusRegions carries the panel's copy control on the shared click-region
	// mechanism the transcript's code-block controls also use.
	statusRegions clickRegions

	// indicator is the transient in-flight activity line shown above the input while a
	// provider turn streams (a collapsed height-0 row until ShowIndicator resizes it to one
	// line and ClearIndicator collapses it again). All its fields below are guarded by
	// indicatorMu because the event-loop goroutine drives show/update/clear while the ticker
	// goroutine and the cross-package test seams read them.
	indicator       *tview.TextView
	bannerGap       *tview.Box
	indicatorMu     sync.Mutex
	indicatorActive bool
	indicatorStart  time.Time
	// indicatorRetry and indicatorIdle are the two above-Working indicator modes, each
	// empty when inactive. renderIndicatorLocked picks the shown copy by priority
	// retry > idle > working, so a stored idle mode never renders over a live retry and
	// ResumeRetry clears both rather than restoring a stale idle from the failed attempt.
	indicatorRetry string // reconnecting copy while the retry loop backs off
	indicatorIdle  string // provider display name while its stream is idle
	// indicatorIdleStart is the elapsed baseline for idle copy, set from the provider
	// stream's supplied idle duration (StreamIdleInfo.IdleMs) rather than the turn start,
	// so the idle line shows time since the last provider activity and advances from it.
	// Read only while indicatorIdle is set; reset with every indicator lifecycle reset.
	indicatorIdleStart time.Time
	indicatorInput     int64  // ↑ session-cumulative uploaded/input tokens
	indicatorOutput    int64  // ↓ session-cumulative downloaded/output tokens
	indicatorGen       uint64 // bumped on show/clear so a stale ticker tick cannot redraw a cleared line
	// indicatorSeedStart, when non-zero, is the elapsed-clock start the next ShowIndicator
	// uses instead of a.now() — the production turn's submit-start, so the indicator's final
	// visible elapsed matches the turn-latency event that measures from the same instant.
	// ShowIndicator consumes it (resets to zero) so it applies to one turn only.
	indicatorSeedStart time.Time
	indicatorStop      chan struct{}
	indicatorStopped   chan struct{} // closed by the ticker goroutine on exit; lets the stop/leak test join it
	indicatorInterval  time.Duration // elapsed-refresh period; a field so tests can shorten it

	// statusBar is the first row of the always-visible bottom footer: the filled
	// two-tone provider/model/effort/dir segments (RenderStatusLine). statusLineState is the
	// optional StatusState source the segments render from, the same single source /status
	// and the launch banner read; statusModeKey is the active interaction-mode key the
	// second-row pill renders, updated through the shared ModeDeps.Notify seam
	// (RefreshModeHint). statusLineState is installed by the production wiring
	// (SetStatusLineState) and nil in unit tests, where RefreshStatusLine renders the row
	// empty so App can be constructed without bootstrap state. All three are read/written
	// only on the tview event-loop goroutine (the apply paths refresh after a
	// model/effort/mode change), so they need no lock.
	statusBar       *tview.TextView
	statusLineState StatusState
	statusModeKey   string

	// statusModeRow is the footer's second row: the filled "• <mode>" mode pill
	// (modePill) followed immediately by the fixed shift+tab hint, both left-grouped.
	// RefreshModeHint re-renders it on every mode switch. statusBarRow is the vertical flex
	// stacking statusBar (row 1) over statusModeRow (row 2); it is the single root-flex
	// footer item that replaced the earlier one-row segments+pill+hint bar. Read/written only on
	// the tview event-loop goroutine.
	statusModeRow *tview.TextView
	statusBarRow  *tview.Flex

	promptOpen       bool
	promptPrev       tview.Primitive
	promptDecisionCh chan PromptDecision

	// secretPromptOpen / secretPromptPrev track the reusable masked secret prompt:
	// whether it is mounted and the primitive focus returns to when it closes.
	// secretPrompt holds the open overlay's live state — the masked input field the
	// secret is typed into (separate from a.input so it never enters the shared buffer)
	// and the caller's submit/cancel callbacks. Registered in overlays() so another
	// overlay cannot mount over it and the central ESC path dismisses it. Opened by
	// app-owned callers via OpenSecretPrompt and wired
	// into /connect.
	secretPromptOpen bool
	secretPromptPrev tview.Primitive

	questionFormOpen bool
	questionFormPrev tview.Primitive
	questionForm     *questionForm
	// questionSel is the one physical left-drag over a question's text. It is held here
	// rather than on the form because closing the form mid-gesture must not release the
	// app's ownership of the move, release and click-class action still to come.
	questionSel questionSelection

	questionFormMounts chan struct{}
	secretPrompt       *secretPrompt

	// effortPickerOpen / effortPickerPrev track the CTRL-E effort picker overlay
	// whether it is mounted and the primitive focus returns to when it
	// dismisses. effortDeps is the effort surface the picker reads its
	// supported set / active selection from and applies a confirmed row through,
	// reusing the same non-slash apply path as /effort. It is injected by the
	// production wiring; a nil Model leaves CTRL-E inert (unit tests inject
	// fakes).
	effortPickerOpen bool
	effortPickerPrev tview.Primitive
	effortDeps       EffortDeps

	systemOnePickerOpen   bool
	systemOnePickerPrev   tview.Primitive
	systemOnePickerStatus string
	systemOneDeps         SystemOneDeps

	// modeDeps is the mode-switch surface the shift+tab cycle key drives — the
	// same ModeDeps BuildRegistry binds to the /mode command, so both
	// surfaces switch through one seam. Injected by the production wiring via
	// SetModeDeps; a nil Switcher leaves shift+tab inert (unit tests inject fakes).
	modeDeps ModeDeps

	// modelPickerOpen / modelPickerPrev track the CTRL-M model picker overlay:
	// whether it is mounted and the primitive focus returns to when it
	// dismisses. modelPickerDeps is the provider-aware surface the
	// picker reads the provider×model cross-product / supported efforts / settings
	// target from and applies a confirmed row through, reusing the same non-slash
	// apply path as /model. modelPicker holds the open picker's live effort
	// selection so the effort column can refresh as the highlighted model changes.
	// A nil Catalog leaves CTRL-M inert (unit tests inject fakes).
	modelPickerOpen bool
	modelPickerPrev tview.Primitive
	modelPickerDeps ModelPickerDeps
	modelPicker     *modelPickerSession

	// resumePickerOpen / resumePickerPrev track the /resume session-picker overlay.
	// Unlike the effort/model pickers it is opened by the /resume
	// command handler through the injected ResumeDeps.Picker capability — not a
	// global key — so the app stores no resume deps. resumePicker holds the open
	// overlay's live per-open state (the displayed rows, the table, the Enter/ESC
	// continuation, and the rename/delete/re-list actions) so the rename/delete
	// overlays and in-place row refresh can read and mutate it; it is nil whenever the
	// picker is closed. Registered in overlays() so another overlay (CTRL-E/CTRL-M)
	// cannot mount over it.
	resumePickerOpen bool
	resumePickerPrev tview.Primitive
	resumePicker     *resumePickerSession

	// reverseSearchOpen / reverseSearchPrev track the CTRL-R history reverse-search
	// overlay: whether it is mounted and the primitive focus returns to
	// when it dismisses. reverseSearch holds the open overlay's live matching state
	// (the searched history snapshot, current query, and most-recent match) so Enter
	// can accept the match and the match display can refresh as the query changes.
	// Registered in overlays() so another overlay cannot mount over it and the central
	// ESC path dismisses it.
	reverseSearchOpen bool
	reverseSearchPrev tview.Primitive
	reverseSearch     *reverseSearchSession

	// openRouterSettings is handed over by SettingsDeps.Picker at Present so the /settings
	// overlay stays independent of config persistence.
	settingsPickerOpen bool
	settingsPickerPrev tview.Primitive
	settingsPicker     *settingsPickerSession
	openRouterSettings OpenRouterSettings

	blockedPickerOpen bool
	blockedPickerPrev tview.Primitive
	blockedPicker     *blockedPickerSession

	blockedDestinationOpen bool
	blockedDestinationPrev tview.Primitive
	blockedDestinationAdd  func(BlockedDestination) string

	// reverseSearchHintShown tracks the one-shot `no input history yet` hint shown
	// when CTRL-R is pressed with empty history: the hint opens no overlay
	// and is cleared by handleGlobalKey on the next keystroke. Read/written only on
	// the tview event-loop goroutine, so it needs no lock.
	reverseSearchHintShown bool

	filePickerOpen  bool
	filePickerPrev  tview.Primitive
	filePicker      *filePickerSession
	home            string
	fileRefPrevText string

	// slashPickerOpen / slashPickerPrev track the live '/' slash-command picker overlay:
	// whether it is mounted and the primitive focus returns to when it dismisses.
	// slashPicker holds the open overlay's live state (the triggering '/' offset, the
	// registry-sourced candidates, the typed query, and the rendered list). It shares the
	// fileRefPrevText change-hook snapshot and reuses the same overlays() registration as
	// the '@' picker, so the two coexist as one-overlay-at-a-time triggers on the
	// typing path. Read/written only on the tview event-loop goroutine.
	slashPickerOpen bool
	slashPickerPrev tview.Primitive
	slashPicker     *slashPickerSession

	// connectPickerOpen / connectPickerPrev track the /connect provider picker overlay:
	// whether it is mounted and the primitive focus returns to when it dismisses.
	// connectPicker holds the open row list and selection callback. It is opened by the
	// /connect handler through the production deps, not by a global key.
	connectPickerOpen bool
	connectPickerPrev tview.Primitive
	connectPicker     *connectPickerSession

	// pendingFollowup is the prompt text a pending follow-up suggestion fills into the
	// input when the user accepts it with Tab; "" means none is pending.
	// SuggestFollowup sets it (alongside the input's ghost text); the Tab branch in
	// handleInputKey consumes it before slash-name completion; any buffer change clears it
	// via onInputChanged, so a typed/accepted/cleared buffer never leaves a stale prompt.
	// Read/written only on the tview event-loop goroutine (SuggestFollowup marshals through
	// streamUpdate), so it needs no lock.
	pendingFollowup string

	// followupDebug carries the development-only suggest_followup trace context. The
	// turn controller arms it per dispatch (SetFollowupDebugContext) with this turn's
	// provider/model/mode, but only when the dev-debug gate is on; while disabled (the
	// default) the surface/ghost/accept/clear seams emit nothing, so a normal session is
	// byte-free of the debug events. Read/written only on the event-loop goroutine, like
	// pendingFollowup, so it needs no lock.
	followupDebug followupDebugContext

	submit SubmitFunc

	// clipboard is the OS-clipboard image reader the CTRL-V action reads through.
	// New installs the default platform-helper reader; tests inject a fake
	// via SetClipboardReader so the real subprocess never runs in CI. A nil reader
	// leaves CTRL-V inert.
	clipboard clipboardReader

	// history is the per-session input history backing ↑/↓ navigation.
	// It is memory only and created empty by New for every fresh launch and
	// `--resume`, so it is never persisted into the session record.
	history *History

	// registry is the command set Tab name-completion matches the typed
	// slash name against. The production wiring (StartTUI) installs it via
	// SetRegistry — the same registry the submit adapter dispatches through — after
	// New returns; it is nil in unit tests and before injection, where Tab is inert.
	registry *Registry

	// activeStore is the mutable reference to the session the app is currently
	// recording into. It is the single source dispatch reads through Store()
	// (the production CommandHost) and that /clear swaps when it starts a fresh
	// same-folder session. activeMu guards it because Store can be
	// read on the event-loop goroutine while a swap installs a new store.
	activeStore *sessions.Store
	activeMu    sync.Mutex

	// commandFlush is the injected command-event flush hook bootstrap
	// installs via SetCommandFlush. It flushes the active session and applies the
	// write-failure protocol on failure; bootstrap supplies it because the
	// failure delegation reaches sessionfailures, which internal/tui cannot import.
	// Nil before injection (and in unit tests), where FlushActive is a no-op.
	commandFlush func() error

	// streamCanceller cancels the in-flight provider request behind the streaming
	// surface (the cancellation shape reused from cmd_clear.go). The ESC
	// CTRL-C handlers reach it via StreamCanceller() to call Cancel(); the
	// production handle is injected by the provider-turn wiring. Nil (unit
	// tests, and before injection) leaves the surface inert — there is nothing to
	// cancel. Installed once before Run like the other injected hooks, so it needs
	// no lock.
	streamCanceller StreamCanceller

	// running reports whether the tview event loop (Run) is active. The exported
	// stream-surface methods read it to decide whether an off-event-loop
	// provider-runtime callback must marshal its widget mutation through the tview
	// queue (loop running) or may mutate the transcript directly (before Run and in
	// unit tests, where the queue is never drained and a blocking QueueUpdate would
	// deadlock).
	running atomic.Bool

	// noticeSeq counts notices emitted. The model-change paths compare it across
	// their apply to tell a notice the apply emitted from a stale pre-apply one;
	// the text cannot, because a repeated failure emits the same text twice.
	noticeSeq atomic.Uint64

	// ctrlCArmed / ctrlCArmedAt / ctrlCHintGen track the step-4 "press
	// Ctrl-C again to exit" window: whether the hint is showing, the clock reading
	// of the empty-buffer CTRL-C that armed it (used for the <=1500ms double-press
	// check), and a generation token that invalidates a stale timeout callback so an
	// old timer cannot clear a freshly re-armed hint. All three are read/written only
	// on the tview event-loop goroutine (key handlers and the QueueUpdateDraw-marshaled
	// timeout), so they need no lock.
	ctrlCArmed   bool
	ctrlCArmedAt time.Time
	ctrlCHintGen uint64

	// escDisarmed makes the ESC that follows a /status dismissal over a live provider
	// stream spend itself on the interrupt hint instead of cancelling the turn. Like the
	// CTRL-C window above it is read/written only on the tview event-loop goroutine, so
	// it needs no lock.
	escDisarmed bool

	// now and afterFunc are the injected clock/timer seams the CTRL-C hint uses, so
	// the 1500ms window and timeout can be driven deterministically in tests without
	// sleeping. New installs the real time.Now / time.AfterFunc; tests overwrite them.
	now       func() time.Time
	afterFunc func(d time.Duration, f func())

	// draw is the injected repaint seam the CTRL-L handler requests a full screen
	// re-render through. New installs the real tview.Application.Draw
	// tests overwrite it to assert the repaint request without launching a terminal.
	// Routing through this wrapper keeps CTRL-L unit-testable and changes no UI state.
	draw func()

	// newScreen constructs the production terminal screen App.Run wraps with the
	// bracketed-paste decorator. New defaults it to tcell.NewScreen; tests
	// that drive App.Run inject a SimulationScreen through it so Run normalizes paste
	// events through the wrapper without grabbing the real terminal.
	newScreen func() (tcell.Screen, error)

	// screen is the terminal Run installed. tview.Application exposes no getter, and the
	// blocked-prompt notifier needs the screen to ring the bell.
	screen tcell.Screen

	// promptNotifyAfter and promptNotifyWrite are the blocked-prompt notifier's clock and
	// escape-sequence seams; the default write is TTY-gated. Tests replace both.
	promptNotifyAfter func(d time.Duration) <-chan time.Time
	promptNotifyWrite func(seq string)

	// suppressNextEcho suppresses the single accepted-submit transcript echo
	// submitCurrent appends after a command handler returns true. /clear resets the
	// transcript inside its own handler (ResetTranscript), so without this the
	// "> /clear" echo would reappear on the freshly-wiped pane. It is set by
	// ResetTranscript during dispatch and consumed by submitCurrent on the same tview
	// event-loop goroutine, so it needs no lock.
	suppressNextEcho bool
	echoOverride     string

	// inputSelecting tracks an app-owned plain left-drag that began inside the input
	// rect. TextArea's native mouse drag can degrade to click-only behavior in real
	// terminals, so plain input selection mirrors the transcript path: the app maps
	// coordinates to byte offsets and drives TextArea.Select directly.
	inputSelecting       bool
	inputSelAnchor       int
	inputSelX, inputSelY int
	inputScrollGen       uint64
	inputScrollPending   bool

	// inputDragging tracks a Shift-modified drag that is deliberately left on the
	// TextArea native path. Its matching MouseLeftUp copies and collapses the native
	// selection even when the release lands outside the input. inputDragX/inputDragY
	// hold the last in-input position the drag passed through; an outside release is
	// finished by handing the TextArea a synthetic release at that spot, so it ends its
	// own native drag. Read/written only on the tview event-loop goroutine.
	inputDragging          bool
	inputDragX, inputDragY int

	queued    []queuedPrompt
	queueRows *tview.TextView
	unsentMu  sync.Mutex
	unsent    []*unsentBatch

	literalPrompt PromptEntrypoint
	literalHold   bool

	// transcriptSel* give the conversation pane the same edge-hold auto-scroll the input
	// has: a plain transcript drag held on the top or bottom visible row scrolls
	// the pane on a timer so the selection can extend past the initially visible
	// conversation, with the held position re-evaluated each tick so mouse jitter cannot
	// stall it. transcriptSelX/Y is the last drag position the timer re-projects the
	// selection through; the gen token ends the timer chain on release; pending dedups
	// the in-flight timer. Read/written only on the tview event-loop goroutine.
	transcriptSelX, transcriptSelY int
	transcriptScrollGen            uint64
	transcriptScrollPending        bool

	// streamRenderPending and streamRenderGen guard the one-shot timer that renders
	// coalesced stream deltas: pending dedups the in-flight timer, and the generation
	// token makes a callback armed for a since-closed stream drop instead of render.
	// Both are event-loop-only like the pair above; stopping is atomic because Stop
	// runs on the event loop while the timer callback that reads it does not.
	streamRenderPending bool
	streamRenderGen     uint64
	stopping            atomic.Bool
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

// SetEffortDeps installs the effort surface the CTRL-E picker reads and
// applies through. The production wiring supplies the
// implementations bound to the running app + bootstrap result; with none set the
// picker stays inert. It is set once before Run, alongside the other injected
// hooks.
func (a *App) SetEffortDeps(d EffortDeps) { a.effortDeps = d }

func (a *App) SetSystemOneDeps(d SystemOneDeps) { a.systemOneDeps = d }

// SetModelPickerDeps installs the provider-aware surface the CTRL-M model picker
// reads and applies through. The production wiring supplies the
// implementations bound to the running app + bootstrap result; with none set the
// picker stays inert. It is set once before Run, alongside the other injected
// hooks.
func (a *App) SetModelPickerDeps(d ModelPickerDeps) { a.modelPickerDeps = d }

// anyOverlayOpen reports whether any modal overlay currently holds the screen, so
// CTRL-E/CTRL-M/CTRL-R and the '@' trigger cannot open one over another.
func (a *App) anyOverlayOpen() bool {
	for _, o := range a.overlays() {
		if o.isOpen() {
			return true
		}
	}
	return false
}

func (a *App) closeOverlayPage(page string, prev *tview.Primitive) {
	a.pages.RemovePage(page)
	if *prev != nil {
		a.app.SetFocus(*prev)
	} else {
		a.app.SetFocus(a.input)
	}
	*prev = nil
}

// rootPages is the application root, which is where tview delivers a completed bracketed
// paste. It repairs modal focus first: a paste never passes through the key capture that
// normally does that repair, so a paste arriving while a lost terminal-focus event has left
// focus on a primitive underneath an open modal would be delivered into that primitive —
// the input draft — rather than to the modal the user is typing into.
type rootPages struct {
	*tview.Pages
	app *App
}

func (r *rootPages) PasteHandler() func(string, func(tview.Primitive)) {
	return func(text string, setFocus func(tview.Primitive)) {
		r.app.restoreModalFocusOnTerminalFocus()
		if handler := r.Pages.PasteHandler(); handler != nil {
			handler(text, setFocus)
		}
	}
}

func (a *App) queueModalFocusRestore() {
	if !a.running.Load() {
		return
	}
	go func() {
		if !a.running.Load() {
			return
		}
		a.app.QueueUpdateDraw(a.restoreModalFocusOnTerminalFocus)
	}()
}

func (a *App) restoreModalFocusOnTerminalFocus() {
	if a.questionFormOpen && a.questionForm != nil {
		a.questionForm.restoreFocus()
		return
	}
	if !a.promptOpen {
		return
	}
	name, item := a.pages.GetFrontPage()
	switch name {
	case promptScopeConfirmPage, promptCompoundPage, promptScopePage, promptBasePage:
		if item != nil {
			a.app.SetFocus(item)
		}
	}
}

// Run starts the tview event loop and blocks until the application stops. It is
// the bootstrap handoff entrypoint a later task wires into the fresh-launch flow.
// While it runs, the streaming surface marshals off-loop transcript mutations
// through the tview queue; running tracks that window so the same methods mutate
// directly before Run and in unit tests.
func (a *App) Run() error {
	// Build the production terminal screen and wrap it so bracketed-paste line breaks
	// are normalized before tview's paste collector sees them. Installing the
	// wrapper with SetScreen before app.Run makes tview use it instead of creating its
	// own screen; the explicit Init captures the terminal-init error that SetScreen
	// (and tview's self-created screen path) would otherwise swallow.
	screen, err := a.newScreen()
	if err != nil {
		return err
	}
	wrapped := newPasteScreen(screen, a.queueModalFocusRestore)
	if err := wrapped.Init(); err != nil {
		return err
	}
	// tview calls EnableMouse/EnablePaste only on a screen it creates itself; for a
	// screen installed via SetScreen it skips that setup, so wheel-scroll,
	// bracketed-paste, and terminal-focus modes must be enabled here. Without
	// EnablePaste the real terminal never emits paste markers and the decorator would
	// have nothing to normalize; without EnableFocus the decorator cannot restore prompt
	// focus after a real terminal blur/return.
	wrapped.EnableMouse()
	wrapped.EnablePaste()
	wrapped.EnableFocus()
	a.app.SetScreen(wrapped)
	a.screen = wrapped

	a.running.Store(true)
	defer a.running.Store(false)
	return a.app.Run()
}

// beep must run on the tview event-loop goroutine, which owns the terminal.
func (a *App) beep() {
	if a.screen == nil {
		return
	}
	_ = a.screen.Beep()
}

// submitCurrent passes the trimmed prompt text to the submit hook, clearing the
// field only if the hook accepts it. Whitespace-only input is ignored. It
// returns whether the input was submitted and accepted. The submitted value is the
// input's expanded text — any collapsed "[Pasted N lines]" placeholder is substituted
// back to its full pasted content — so the hook, history, and transcript echo all carry
// the real text, not the placeholder; an accepted submit clears the field (and its
// hidden paste state via SetText), a rejected one leaves both editable.
func (a *App) submitCurrent() bool {
	// Derive the outgoing prompt from the buffer: collapsed-paste placeholders expand back to
	// their full text and image tokens are stripped, yielding the surviving attachments in
	// buffer order. A rejected submit leaves the buffer (and its tokens) untouched.
	rawText, tokenAtts := a.input.submitText()
	text := strings.TrimSpace(rawText)
	// Slash command dispatch stays text-only: a leading
	// '/' means the input is routed to command dispatch, so image attachments are not
	// collected, recognized in its arguments, or echoed for it — only plain prompts
	// carry attachments to the model path. Any pending image token is dropped on the
	// accepted clear below.
	var imageParts []sessions.ContentPart
	if !strings.HasPrefix(text, "/") {
		// Typed paths are validated at the Enter boundary, not while the user is still
		// editing. Pasted paths and clipboard/'@'-picker images are already pending image
		// tokens; this is the final typed-path conversion/safety check on the stripped text.
		var typed []imageAttachment
		var rejection *imagePathRejection
		text, typed, rejection = a.extractImagePathAttachments(a.dropFileRefAt(text))
		if rejection != nil {
			a.Notice(imageAttachErrorNotice(rejection.path, rejection.err))
			return false
		}
		// Token attachments first (buffer order), then any typed-path attachments.
		for _, att := range tokenAtts {
			imageParts = append(imageParts, att.imagePart())
		}
		for _, att := range typed {
			imageParts = append(imageParts, att.imagePart())
		}
	}
	// An image-only prompt (no typed text but at least one attachment) is accepted; a
	// truly empty submission is not.
	if (text == "" && len(imageParts) == 0) || a.submit == nil {
		return false
	}
	// Record every submitted entry at the Enter boundary, before dispatch decides
	// whether the field clears or stays editable: history holds all
	// submissions (slash commands, bare exit/quit, model prompts), accepted or
	// retained alike, with no dedup. An image-only submission has no text to recall,
	// so nothing is appended for it.
	if text != "" {
		a.history.Append(text)
	}
	// Clear any pinned transient notice as a new submission is entered, so a prior
	// turn's notice cannot carry into — and re-render below — this turn's output.
	// Cleared before dispatch so this submission's own handler can still set a
	// fresh notice (e.g. /model's marker disclosure or a validation error); only the
	// transient notice is touched, committed transcript history is preserved.
	a.ClearNotice()
	// Clear any stale suppression before dispatch so only this submission's handler
	// can suppress its own echo (via ResetTranscript), then consume it once below.
	a.suppressNextEcho = false
	a.echoOverride = ""
	accepted := a.submit(text, imageParts...)
	suppress, echo := a.suppressNextEcho, a.echoOverride
	a.suppressNextEcho = false
	a.echoOverride = ""
	if !accepted {
		return false
	}
	a.RefreshSessionBadge(a.ActiveStore())
	// Echo every accepted submission into the transcript so the conversation log
	// reads prompt-then-answer: the "> text" line (input.go's prompt label) plus one
	// "[image: name (size)]" placeholder per attachment, never the file's bytes.
	// Rendered through userBlockLines so the live echo matches the /resume
	// replay projection exactly. Coupled only to the accept/clear verdict — never
	// re-parses command type — so rejected/retained input is not echoed.
	// Skipped when the handler reset the transcript (ResetTranscript): a successful
	// clear or /new must not leave "> /clear" on the freshly-cleared pane.
	if !suppress && echo != "" {
		a.transcript.append(userBlockLines(echo, nil))
	} else if !suppress {
		a.transcript.append(userBlockLines(text, imageParts))
	}
	a.input.SetText("")
	return true
}

func (a *App) ReplaceNextEcho(text string) { a.echoOverride = text }

// handleInputKey owns the input area's key contract while it is focused.
// Plain Enter submits the whole (possibly multi-line) buffer
// Ctrl+Enter (where the terminal reports the modifier) and Ctrl+J (everywhere)
// insert a newline without submitting. ↑/↓ navigate input history only at the
// buffer's first/last logical line — saving the draft and loading older entries on
// ↑, loading newer entries and restoring the draft on ↓ — and move the caret between
// lines of a multi-line draft otherwise; ↓ on the last line with no navigation
// underway is left untouched so it cannot clobber what the user is typing. Tab is
// always consumed so a Tab outside a slash name is a silent no-op rather than
// TextArea inserting a tab. Every other key falls through to the input field, which
// tracks its own cursor.
func (a *App) handleInputKey(ev *tcell.EventKey) *tcell.EventKey {
	// Tab is handled before the blanket follow-up clear below because it is the sole
	// acceptance key: a pending suggestion accepts — SetText fills the
	// buffer with its prompt, parks the cursor at the end ready to send, and clears the
	// pending state — otherwise Tab runs slash-name completion (a silent no-op outside a
	// slash name rather than TextArea inserting a tab).
	if ev.Key() == tcell.KeyTab {
		if a.pendingFollowup != "" {
			prompt := a.pendingFollowup
			// record acceptance before clearing (resetPendingFollowup is the
			// non-emitting clear, so this stage is not also logged as a discard).
			a.emitFollowupDebug(events.SuggestFollowupStageGhostAccepted, "",
				utf8.RuneCountInString(a.input.ghost), utf8.RuneCountInString(prompt))
			a.resetPendingFollowup()
			a.input.SetText(prompt)
			return nil
		}
		a.completeName()
		return nil
	}
	// Every other key the focused input sees discards a pending follow-up suggestion:
	// Tab is the only acceptance key, so a submit, a history move, a caret key, or even a key
	// that mutates no buffer (KeyLeft, empty-buffer Backspace) — where the onInputChanged
	// change hook never fires — must drop the ghost and pending prompt. clearPendingFollowup
	// is idempotent, so the per-key branches below need not repeat it.
	a.clearPendingFollowup("input_key")
	switch ev.Key() {
	case tcell.KeyEnter:
		// Plain Enter submits the whole (possibly multi-line) buffer; Ctrl+Enter inserts a
		// newline where the terminal reports the modifier (it collapses to a plain Enter
		// elsewhere, which is why Ctrl+J below is the guaranteed fallback).
		if ev.Modifiers()&tcell.ModCtrl != 0 {
			a.input.insertNewline()
			return nil
		}
		a.submitCurrent()
		return nil
	case tcell.KeyCtrlJ:
		// Ctrl+J (LF, 0x0A) is delivered distinctly from Enter (CR, 0x0D) by every
		// terminal, so it inserts a newline even where Ctrl+Enter collapses to Enter.
		a.input.insertNewline()
		return nil
	case tcell.KeyUp:
		if first, _ := a.input.cursorLineEdges(); !first {
			return ev // interior of a multi-line draft: move the caret up a line
		}
		if a.recallQueuedPrompt() {
			return nil
		}
		a.input.SetText(a.history.Up(a.input.GetText()))
		return nil
	case tcell.KeyDown:
		if _, last := a.input.cursorLineEdges(); !last {
			return ev // interior of a multi-line draft: move the caret down a line
		}
		if !a.history.navigating() {
			return nil // last line, no navigation underway: leave the draft untouched
		}
		a.input.SetText(a.history.Down())
		return nil
	}
	return ev
}

// clearPendingFollowup discards a pending follow-up suggestion: it drops
// the app-level acceptance prompt and the input's ghost text together so a submit or any
// consumed non-acceptance key cannot leave stale ghost text behind. Idempotent and cheap,
// so it is safe to call on every discarding key path; the onInputChanged change hook clears
// the same state for ordinary typed edits. reason labels why the suggestion was dropped for
// the debug trace, which is recorded only when something was actually pending (so the common
// "nothing pending" key paths add no event).
func (a *App) clearPendingFollowup(reason string) {
	if a.pendingFollowup != "" {
		a.emitFollowupDebug(events.SuggestFollowupStageGhostCleared, reason,
			utf8.RuneCountInString(a.input.ghost), utf8.RuneCountInString(a.pendingFollowup))
	}
	a.resetPendingFollowup()
}

// resetPendingFollowup drops the pending suggestion and its ghost text without emitting a
// debug event. It is the shared, non-tracing clear behind clearPendingFollowup (which
// adds the discard stage) and the Tab-accept path (which records its own acceptance stage),
// so neither path double-logs a single transition.
func (a *App) resetPendingFollowup() {
	a.pendingFollowup = ""
	a.input.SetGhostText("")
}

// followupDebugContext is the per-turn trace context the turn controller arms via
// SetFollowupDebugContext. enabled is false until the dev-debug gate arms it; the
// provider/model/mode are stamped onto every suggest_followup_debug event the TUI emits.
type followupDebugContext struct {
	enabled  bool
	provider string
	model    string
	mode     string
}

// SetFollowupDebugContext arms the development-only suggest_followup trace for the
// next turn, stamping provider/model/mode onto the TUI-side debug events. The turn
// controller calls it at dispatch — only when the dev-debug gate is on, on the event-loop
// goroutine — so the surface/ghost/accept/clear seams can record which selection produced a
// suggestion. Until armed the seams emit nothing.
func (a *App) SetFollowupDebugContext(provider, model, mode string) {
	a.followupDebug = followupDebugContext{enabled: true, provider: provider, model: model, mode: mode}
}

// emitFollowupDebug appends one TUI-side stage of the suggest_followup trace to the
// active session store when the dev-debug gate is armed. It records stage/provider/model/mode,
// privacy-safe label/prompt rune lengths, and a clear/discard reason — never suggestion text.
// Append-only and best-effort: a missing diagnostic must not disturb the UI,
// so the error is ignored. Runs on the event-loop goroutine, where the followup state lives.
func (a *App) emitFollowupDebug(stage, reason string, labelLen, promptLen int) {
	if !a.followupDebug.enabled {
		return
	}
	store := a.ActiveStore()
	if store == nil {
		return
	}
	_, _ = events.Append(store, events.SuggestFollowupDebug{
		Stage:     stage,
		Provider:  a.followupDebug.provider,
		ModelID:   a.followupDebug.model,
		Mode:      a.followupDebug.mode,
		LabelLen:  int64(labelLen),
		PromptLen: int64(promptLen),
		Reason:    reason,
	})
}

// completeName runs Tab slash-name completion against the current input
// buffer and applies the result: a single or longest-common-prefix completion
// rewrites the buffer (the cursor lands at the end via SetText), and a
// non-extendable multi-match renders the candidate names on the one-line notice. A
// no-op leaves the buffer untouched. The cursor passed to the helper is the input
// wrapper's tracked offset (inputField.Cursor), so Tab completes the name token the
// cursor actually sits on — including when arguments already follow it — and
// no-ops when the cursor is in the argument region. The wrapper reads the caret
// straight from the underlying tview.TextArea (inputField.Cursor), which tracks its
// own cursor. Inert until a registry is installed (SetRegistry), so it is a no-op in
// unit tests and before injection.
func (a *App) completeName() {
	text := a.input.GetText()
	res := completeSlashName(text, a.input.Cursor(), a.registry)
	switch res.Action {
	case tabReplace:
		a.input.SetText(res.Text)
	case tabList:
		a.Notice(strings.Join(res.Matches, "  "))
	}
}

// Append adds one line to the transcript pane, escaping it so any "[...]" in the
// text renders literally rather than being parsed as a tview style tag now that
// the transcript has dynamic colors enabled. All ordinary callers
// (command output, model-picker disclosure) go through here; the launch banner is
// the one intentional styled producer and uses AppendBanner instead.
func (a *App) Append(line string) {
	a.transcript.append(tview.Escape(line))
}

// AppendStyled adds one pre-styled line to the transcript without escaping, so
// intentional tview style/color tags are parsed by dynamic colors — e.g. the launch
// banner's "[::b]…[::-]" bold. (Mode switches no longer append here: their colored
// hint renders into the persistent mode-hint row instead.) It is the single raw
// append seam: callers must pass only controlled,
// non-user text (a closed set of literals), since nothing here escapes "[...]"
// against style-tag injection; every other transcript string is escaped via Append.
func (a *App) AppendStyled(line string) {
	a.transcript.append(line)
}

// LaunchBannerBar renders the launch banner's name line as a teal-filled bar:
// "◆ codemeld" in bold white, then "<version>" immediately after it in a
// dim, non-bold teal-tinted white (bannerVersionText) so the version is easy to find next to
// the wordmark instead of being lost at the right edge on a wide terminal; the remainder of
// the row is padded with spaces so the teal fill still spans the full terminal width. The
// fills paint a background — the chrome exception scoped to chrome (see colors.go).
// width is the terminal width at append time; the bar is not re-filled on a later resize
// (acceptable for launch-only branding, since the banner scrolls away as the
// conversation grows). The version is tview.Escape'd defensively, though it is a build
// constant. A width too small to hold the wordmark + version keeps them adjacent with no
// trailing pad. The caller passes the result as the first AppendBanner line; the bg/fg/bold
// tags are live markup that AppendBanner's raw styled-append seam renders.
func LaunchBannerBar(version string, width int) string {
	wordmark := "◆ codemeld"
	ver := tview.Escape(version)
	// wordmark + one space + version sit together at the left; the rest of the row is pad
	// so the teal fill reaches the terminal edge.
	pad := width - tview.TaggedStringWidth(wordmark) - 1 - tview.TaggedStringWidth(ver)
	if pad < 0 {
		pad = 0
	}
	return fmt.Sprintf("[%s:%s:b]%s [%s:%s:-]%s%s[-:-:-]",
		chromeOnFillText, accentTealHex, wordmark,
		bannerVersionText, accentTealHex, ver,
		strings.Repeat(" ", pad))
}

// LaunchBannerMeta renders the launch banner's metadata subtitle as the single line under
// the teal name bar: the active provider · model · effort · launch-dir segments
// joined by " · ", each in a fixed cool blue-grey that lightens left→right (bannerMeta* in
// colors.go) so the line reads as one dim secondary ramp matching the design sample rather
// than a flat run. When no model is selected (model == ""), provider and effort are empty,
// so the line collapses to "no model selected · <dir>". Every segment value is tview.Escape'd
// because the banner is appended through the raw AppendStyled seam (AppendBanner): only the
// color tags are intentional markup, so a path or model id carrying "[tag]"-like text must
// render literally. The caller passes the result as a banner line; the fg tags are
// live markup that AppendBanner's styled-append seam renders.
func LaunchBannerMeta(provider, model, effort, dir string) string {
	seg := func(color, text string) string {
		return fmt.Sprintf("[%s]%s[-]", color, tview.Escape(text))
	}
	sep := fmt.Sprintf("[%s] · [-]", bannerMetaSeparator)

	var parts []string
	if model == "" {
		parts = append(parts, seg(bannerMetaModel, "no model selected"))
	} else {
		parts = append(parts,
			seg(bannerMetaProvider, provider),
			seg(bannerMetaModel, model),
			seg(bannerMetaEffort, effort+" effort"),
		)
	}
	parts = append(parts, seg(bannerMetaDir, dir))
	return strings.Join(parts, sep)
}

// AppendBanner adds the launch banner as one multi-line transcript block through the raw
// styled-append seam (AppendStyled): the banner's intentional tags are parsed by dynamic
// colors — the teal-filled name bar's "[fg:bg:b]…[-:-:-]" fill (LaunchBannerBar) and
// any styling on the remaining lines. The banner's display lines are joined with a single
// newline and committed as one entry so they stay adjacent — the transcript's block
// separator (one blank line) is inserted only between entries, never inside this one,
// keeping the banner a tight header. Used by the bootstrap banner (StartTUI and /clear's
// transcript reset).
func (a *App) AppendBanner(lines ...string) {
	a.AppendStyled(strings.Join(lines, "\n"))
}

// Notice shows a one-line user-facing notice beneath the transcript. It is for
// callers already running on the tview event-loop goroutine; off-loop callers
// must use NoticeFromBackground.
func (a *App) Notice(text string) {
	a.noticeSeq.Add(1)
	a.invalidateStreamRender()
	a.transcript.setNotice(text)
}

// NoticeFromBackground shows a one-line notice from an off-event-loop caller,
// marshaling the transcript mutation through the tview queue while Run is active.
func (a *App) NoticeFromBackground(text string) {
	a.streamUpdate(func() { a.Notice(text) })
}

func (a *App) RunBackgroundAfterDraw(work func() error, complete func(error)) {
	if a.stopping.Load() {
		return
	}
	if !a.running.Load() {
		complete(work())
		return
	}
	go func() {
		a.streamUpdate(func() {})
		if a.stopping.Load() {
			return
		}
		err := work()
		a.streamUpdate(func() {
			if a.stopping.Load() {
				return
			}
			complete(err)
		})
	}()
}

// SetScreenFactoryForTest replaces the screen constructor Run uses, so a test can
// start the real app lifecycle against a simulation screen instead of a terminal.
// Test-only; it must be called before Run.
func (a *App) SetScreenFactoryForTest(factory func() (tcell.Screen, error)) {
	a.newScreen = factory
}

// RunOnEventLoopForTest runs fn on the tview event-loop goroutine and waits for the
// redraw, so a test driving a running app can touch shared tview state without
// racing the draw loop. Test-only; it deadlocks if called from the loop goroutine.
func (a *App) RunOnEventLoopForTest(fn func()) {
	a.app.QueueUpdateDraw(fn)
}

// CommitProviderError commits a provider/turn request failure as a permanent
// in-place transcript line (escaped) tied to the turn that produced it, so the
// error scrolls with history rather than re-pinning below later turns the way the
// single bottom notice did. The provider-turn runtime calls it off
// the tview event-loop goroutine, so it marshals through the tview queue while Run
// is active and mutates directly before Run — exactly like AppendStreamDelta,
// FinalizeStream, and NoticeFromBackground. Ordering is preserved automatically:
// committing appends after whatever finalize/markInterrupted already sealed (a
// pre-stream failure lands after the submitted prompt; a post-seal failure after
// the sealed turn output).
func (a *App) CommitProviderError(text string) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.commitError(text)
	})
}

// ClearNotice clears the one-line transient notice without touching committed
// transcript history. submitCurrent calls it as a new submission is accepted, and
// the model-change paths (the CTRL-M/picker confirm and /model) call it on a
// successful apply, so a prior turn's notice cannot linger pinned below later
// output. It is for callers on the tview event-loop goroutine (like Notice);
// it never affects committed lines (t.lines).
func (a *App) ClearNotice() {
	a.invalidateStreamRender()
	a.transcript.clearNotice()
}

// SetActiveStore installs s as the session the app records into. The production
// bootstrap sets it once before Run, and /clear's session swap (SessionSwapper)
// replaces it with the fresh same-folder store so subsequent commands and the
// exit hint observe the new session.
func (a *App) SetActiveStore(s *sessions.Store) {
	a.activeMu.Lock()
	a.activeStore = s
	a.activeMu.Unlock()
	a.RefreshSessionBadge(s)
}

// ActiveStore returns the session store the app is currently recording into,
// reflecting any /clear swap. It may be nil before SetActiveStore is called.
func (a *App) ActiveStore() *sessions.Store {
	a.activeMu.Lock()
	defer a.activeMu.Unlock()
	return a.activeStore
}

// Store satisfies CommandHost: dispatch appends each command's slash_command
// event to whichever session is active at invocation time, which is exactly the
// active-store reference ActiveStore returns.
func (a *App) Store() *sessions.Store { return a.ActiveStore() }

// SetCommandFlush installs the command-event flush hook bootstrap
// builds over the active session + sessionfailures. It is set once before Run,
// alongside SetActiveStore and SetSubmit.
func (a *App) SetCommandFlush(fn func() error) { a.commandFlush = fn }

// FlushActive satisfies CommandHost: it runs the injected command-event flush
// hook so a /status, /help, or placeholder command makes its slash_command record
// durable. With no hook installed (unit tests) it is a no-op.
func (a *App) FlushActive() error {
	if a.commandFlush == nil {
		return nil
	}
	return a.commandFlush()
}

// SetStreamCanceller installs the provider-turn cancellation handle the ESC /
// CTRL-C handlers reach to abort an in-flight streamed reply. The
// production handle is injected by the turn wiring; with none installed
// StreamCanceller returns nil and the surface stays inert (nothing to cancel).
// It is set once before Run, alongside the other injected hooks.
func (a *App) SetStreamCanceller(c StreamCanceller) { a.streamCanceller = c }

// StreamCanceller returns the installed cancellation handle so the ESC / CTRL-C
// key handlers can call Cancel() on it. It is nil until
// SetStreamCanceller is called (and in unit tests), where the caller treats the
// stream surface as inert and cancels nothing.
func (a *App) StreamCanceller() StreamCanceller { return a.streamCanceller }

// AppendStreamDelta accumulates one incremental chunk of the in-progress assistant
// reply. While Run is active the mutation is marshaled through the tview queue
// without a draw and a single timer renders the accumulated text; before Run it
// renders on arrival. It returns once the delta has been applied but, unlike the
// per-delta render it replaces, not once it has been drawn. Like PromptUser it must
// not be called from a tview event-loop callback while the loop is running.
func (a *App) AppendStreamDelta(delta string) {
	if a.stopping.Load() {
		return
	}
	if !a.running.Load() {
		a.transcript.appendDelta(delta)
		return
	}
	a.app.QueueUpdate(func() {
		if a.stopping.Load() {
			return
		}
		a.transcript.bufferDelta(delta)
		a.armStreamRender()
	})
}

const streamRenderInterval = 50 * time.Millisecond

func (a *App) armStreamRender() {
	if a.streamRenderPending {
		return
	}
	a.streamRenderPending = true
	gen := a.streamRenderGen
	a.afterFunc(streamRenderInterval, func() {
		if a.stopping.Load() || !a.running.Load() {
			return
		}
		// Not QueueUpdateDraw: a callback invalidated by a boundary still runs, and
		// QueueUpdateDraw would draw after it even though the generation check made
		// it a no-op. Only a current callback renders, and it draws explicitly.
		a.app.QueueUpdate(func() {
			if a.stopping.Load() || a.streamRenderGen != gen {
				return
			}
			a.streamRenderPending = false
			a.transcript.render()
			if a.draw != nil {
				a.draw()
			}
		})
	})
}

func (a *App) invalidateStreamRender() {
	a.streamRenderPending = false
	a.streamRenderGen++
}

// MarkStreamInterrupted closes the in-progress assistant reply with the
// interrupted marker (a no-op when no reply is streaming), so a cancelled stream
// is sealed as interrupted. It is the cross-package finalizer the provider-turn
// runtime calls when it observes the cancellation, and like
// AppendStreamDelta it marshals through the tview queue while Run is active and so
// must be driven off the event-loop goroutine. It also hides the in-flight
// indicator on the same off-loop path (idempotent with the turnController.run
// backstop) so the indicator never outlives the sealed stream.
func (a *App) MarkStreamInterrupted() {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.markInterrupted()
	})
	a.ClearIndicator()
}

// SecurityHalt seals any partial reply as interrupted output and pins the persistent
// protected-settings halt element beneath the transcript. Like MarkStreamInterrupted it must
// be driven off the event-loop goroutine; unlike it, the seal records nothing, so a security
// halt never writes a stream_interrupted event.
func (a *App) SecurityHalt(records []events.SecurityStateHalted) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.setSecurityHalt(records)
	})
	a.ClearIndicator()
}

// MarkStreamInterruptedFromCommand seals a slash-command-cancelled stream from a
// command handler that is already running on the tview event-loop goroutine, and
// hides the in-flight indicator on that same loop path so /clear and /resume
// drop the indicator as soon as they record the interruption.
func (a *App) MarkStreamInterruptedFromCommand() {
	a.invalidateStreamRender()
	a.transcript.markInterrupted()
	a.clearIndicatorDirect()
}

// ResetTranscript wipes the transcript pane — committed lines, any in-progress
// streamed line, and the notice — re-renders it empty, and suppresses the single
// accepted-submit echo submitCurrent would otherwise append for the command that
// triggered the reset. /clear calls it (through the injected ClearDeps.Transcript
// capability) after the session swap commits, so the fresh same-folder session opens
// on a blank pane instead of the prior conversation and without a leftover "> /clear"
// line (visible-screen reset). It is called from the command handler, which
// runs on the tview event-loop goroutine, so it mutates the view directly like
// MarkStreamInterruptedFromCommand rather than marshaling through QueueUpdateDraw
// (which would deadlock the loop from inside a handler).
func (a *App) ResetTranscript() {
	a.invalidateStreamRender()
	a.transcript.reset()
	a.suppressNextEcho = true
}

// FinalizeStream closes a naturally completed streamed assistant reply,
// committing the in-progress line into the transcript (a no-op when no reply is
// streaming) so the next streamed reply starts a fresh buffer instead of merging
// onto the completed one. It is the cross-package finalizer the provider-turn
// runtime calls when a turn ends without cancellation, and like
// AppendStreamDelta it marshals through the tview queue while Run is active and so
// must be driven off the event-loop goroutine.
func (a *App) FinalizeStream() {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
	})
}

// AppendToolActivity renders one tool-call round's about-to-run calls inline in the
// transcript, just before the calls are dispatched, so a multi-step turn shows
// what is about to run (e.g. "Edit path", "Run: go build") instead of going silent. It
// first finalizes any in-progress assistant reply so the model's pre-tool text commits
// above the activity block, then appends the escaped lines as one transcript entry. Like
// the other stream-surface methods it is the cross-package entry point the provider-turn
// runtime calls off the tview event-loop goroutine, so it marshals through
// streamUpdate while Run is active and mutates directly before Run. Tool activity is
// display-only and never recorded.
func (a *App) AppendToolActivity(lines []string) {
	if len(lines) == 0 {
		return
	}
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
		a.transcript.appendToolActivity(lines)
	})
}

func (a *App) AppendEditPatch(patch string) {
	if patch == "" {
		return
	}
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
		a.transcript.appendEditPatch(patch)
	})
}

// ChildAgentStarted, ChildAgentCalls, and ChildAgentEnded are the live child-agent surface
// the delegate tool drives from the child's own goroutine, so — like AppendToolActivity —
// they marshal through streamUpdate while Run is active and mutate directly before it. The
// block is display-only: the durable record is the child_agent_start/end pair the delegate
// already appends.
func (a *App) ChildAgentStarted(start events.ChildAgentStart) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.finalize()
		a.transcript.openChildAgent(start)
	})
}

func (a *App) ChildAgentCalls(invocation string, lines []string) {
	if len(lines) == 0 {
		return
	}
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.updateChildAgent(invocation, lines)
	})
}

func (a *App) ChildAgentEnded(end events.ChildAgentEnd) {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.closeChildAgent(end)
	})
}

// RollbackPartial removes the un-sealed in-progress reply before a
// discard-and-restart retry of a partial stream_drop, so the regenerated answer
// does not stack on the discarded partial. It is the cross-package surface seam the
// provider-turn runtime calls off the tview event-loop goroutine before
// re-issuing (turndeps.go binds it onto turn.Deps).
func (a *App) RollbackPartial() {
	a.streamUpdate(func() {
		a.invalidateStreamRender()
		a.transcript.rollbackPartial()
	})
}

// CommitRetryRecovered commits a faint transcript breadcrumb after an auto-retry
// succeeds, so the user can see that a transient provider hiccup recovered without
// reading provider_request_retry events. It is called off the event-loop goroutine.
func (a *App) CommitRetryRecovered(retries int) {
	a.streamUpdate(func() { a.transcript.commitRetryRecovered(retries) })
}

// SuggestFollowup receives an intercepted suggest_followup tool call: label is
// the imperative the agent proposes and prompt is the text to prefill when the user
// accepts with Tab. It is the cross-package surface seam the provider-turn runtime calls
// when the tool loop intercepts the call (turndeps.go binds it onto turn.Deps).
//
// It stores prompt as the pending acceptance and shows label as dim ghost text in the
// empty input. The tool loop runs off the tview event-loop goroutine, so — like the
// other provider-runtime surface methods — it marshals the widget mutation through
// streamUpdate: QueueUpdateDraw while the loop is running (so the ghost text is drawn), or
// a direct mutation before Run / in unit tests where the queue is never drained. The next
// buffer change clears both the ghost text and the pending prompt (onInputChanged), so the
// suggestion never survives typing or submit.
func (a *App) SuggestFollowup(label, prompt string) {
	a.streamUpdate(func() {
		// record that the surface was reached and with what lengths, before any
		// accept/reject decision, so the trace shows the suggestion arrived at the UI.
		labelLen := utf8.RuneCountInString(label)
		promptLen := utf8.RuneCountInString(prompt)
		a.emitFollowupDebug(events.SuggestFollowupStageSurfaceCalled, "", labelLen, promptLen)
		// A schema-valid call can still carry a blank label or prompt (both are only
		// typed as required strings — internal/provider/tooldefs.go). pendingFollowup ==
		// "" is handleInputKey's sentinel for "nothing pending", so an empty prompt would
		// render a ⇥ Tab ghost that Tab can never accept or clear. Reject either
		// blank field: drop any prior pending suggestion and show no cue. resetPendingFollowup
		// clears without logging, then the explicit ghost_cleared below records the drop.
		if strings.TrimSpace(label) == "" || strings.TrimSpace(prompt) == "" {
			a.resetPendingFollowup()
			a.emitFollowupDebug(events.SuggestFollowupStageGhostCleared, "blank_fields", labelLen, promptLen)
			return
		}
		// The ghost cue only paints over an empty buffer, but pendingFollowup would still
		// arm Tab. handleInputKey accepts any non-empty pendingFollowup before slash
		// completion (app.go:1154), so arming it behind a non-empty draft would let Tab
		// silently replace the user's in-progress text with the hidden prompt instead of
		// completing it. Offer the suggestion only in the empty input: drop it
		// otherwise so Tab keeps its existing behavior for the draft.
		if a.input.GetText() != "" {
			a.resetPendingFollowup()
			a.emitFollowupDebug(events.SuggestFollowupStageGhostCleared, "input_occupied", labelLen, promptLen)
			return
		}
		a.pendingFollowup = prompt
		a.input.SetGhostText(label)
		a.emitFollowupDebug(events.SuggestFollowupStageGhostSet, "", labelLen, promptLen)
	})
}

// streamUpdate applies a transcript mutation safely for the off-event-loop
// provider-runtime callers. While the event loop is running the mutation is
// queued through QueueUpdateDraw (serialized with the draw loop, then redrawn);
// before Run — unit tests and pre-Run wiring — the queue is never drained, so the
// mutation runs directly rather than blocking forever on an undrained queue.
//
// Once shutdown has begun the mutation is dropped rather than queued, matching
// AppendStreamDelta: the shutdown sequence blocks the event-loop goroutine while it
// drains the cancelled turn, so a queued mutation from that draining turn would wait
// on a loop that is itself waiting on the turn.
func (a *App) streamUpdate(f func()) {
	if a.stopping.Load() {
		return
	}
	if a.running.Load() {
		a.app.QueueUpdateDraw(f)
		return
	}
	f()
}

// SetRegistry installs the command registry Tab name-completion matches against
// — the same registry the submit adapter dispatches through, so Tab
// completes exactly the commands /help would list. The production wiring sets it
// once before Run, alongside SetSubmit; with none installed Tab completion is
// inert (unit tests, and before injection).
func (a *App) SetRegistry(r *Registry) { a.registry = r }

// SetSubmit installs the dispatch-backed submit hook after construction. The
// production submit adapter is the app's own CommandHost-backed dispatcher, so it
// cannot be built until New has returned the app; bootstrap calls New(nil) then
// SetSubmit to close that construction cycle without changing New's signature.
func (a *App) SetSubmit(s SubmitFunc) { a.submit = s }

// SubmitInput drives the installed submit hook with input as if it were typed
// and entered, returning whether the hook accepted it (and clearing the field
// on accept) — the same accept/clear contract submitCurrent runs off the Enter
// key, minus the terminal. It is a cross-package test seam: a test outside
// internal/tui (bootstrap's StartTUI assembly) can exercise the real submit
// adapter the app installs via SetSubmit, instead of hand-assembling its own
// NewSubmitFunc. Production input always flows through submitCurrent off Enter;
// this is never called at runtime.
func (a *App) SubmitInput(input string) bool {
	a.input.SetText(input)
	return a.submitCurrent()
}

// SeedInput sets the input buffer to text without submitting it, the way typing
// (without Enter) would leave the field. It is a cross-package test seam (like
// SubmitInput): bootstrap's StartTUI integration test seeds a non-empty buffer to
// prove the production CTRL-C path clears it (step 2) — no existing seam can
// set the buffer without also submitting. Production input is always typed into the
// field off the live event loop; this is never called at runtime.
func (a *App) SeedInput(text string) { a.input.SetText(text) }

// InputText returns the current input-buffer text. It is a cross-package test seam
// (like SubmitInput) that lets bootstrap's StartTUI integration test read the buffer
// back — e.g. to confirm CTRL-C cleared a non-empty buffer (step 2).
// Production reads the buffer through the focused input field off the live event
// loop; this is never called at runtime.
func (a *App) InputText() string { return a.input.GetText() }

// PressCtrlE drives the app-level CTRL-E global-key capture as if the key were
// pressed and reports whether the effort picker overlay opened. It is a
// cross-package test seam (like SubmitInput): bootstrap's StartTUI assembly test
// uses it to prove the production wiring installed the effort picker deps via
// SetEffortDeps — without them effortDeps.Model is nil and CTRL-E stays inert, so
// this returns false. Production CTRL-E always flows through handleGlobalKey off
// the live event loop; this is never called at runtime.
func (a *App) PressCtrlE() bool {
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlE, 0, tcell.ModNone))
	return a.effortPickerOpen
}

// PressCtrlM drives the app-level CTRL-M global-key capture as if the key were
// pressed and reports whether the model picker overlay opened. It mirrors
// PressCtrlE: without the provider-aware deps wired, modelPickerDeps.Catalog
// is nil and CTRL-M stays inert, so this returns false. Production CTRL-M always
// flows through handleGlobalKey off the live event loop; this is never called at
// runtime.
func (a *App) PressCtrlM() bool {
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlM, 0, tcell.ModNone))
	return a.modelPickerOpen
}

// SetClipboardReader installs the OS-clipboard image reader the CTRL-V action reads
// through, replacing the default platform-helper reader New installs. It is a
// cross-package test seam: bootstrap's StartTUI integration test injects a fake that
// returns fixed image bytes so the real CTRL-V → attach → submit → persist → provider
// path can run without an OS clipboard or a helper binary. Production installs the
// default reader in New; this is never called at runtime.
func (a *App) SetClipboardReader(r clipboardReader) { a.clipboard = r }

// PressCtrlV drives the app-level CTRL-V global-key capture as if the key were pressed
// and reports whether a pending image attachment resulted. It is a cross-package test
// seam (like PressCtrlE): bootstrap's StartTUI assembly test uses it to prove the
// production wiring reads the injected clipboard reader and stages an attachment.
// Production CTRL-V always flows through handleGlobalKey off the live event loop; this
// is never called at runtime.
func (a *App) PressCtrlV() bool {
	a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone))
	return len(a.input.imageAttachments()) > 0
}

// SubmitCurrent drives the Enter-key submit path (submitCurrent) without mutating the
// input buffer, so a test can submit after staging a pending attachment via CTRL-V —
// unlike SubmitInput, which replaces the buffer (and clears attachments) first. It is
// a cross-package test seam; production submits flow through submitCurrent off the
// Enter key, and this is never called at runtime.
func (a *App) SubmitCurrent() bool { return a.submitCurrent() }

// PressTab sets input as the buffer (cursor parked at the end, as SetText does)
// and drives a Tab keypress through the input field's real handler — the same
// SetInputCapture → handleInputKey → completeName path the live event loop runs
// — then returns the resulting buffer text and the one-line notice (the
// multi-match candidate list, when Tab listed rather than completed). It is a
// cross-package test seam (like SubmitInput): bootstrap's StartTUI assembly test
// uses it to prove the production wiring installed the command registry via
// SetRegistry — without it App.registry is nil and Tab completion is inert, so the
// buffer comes back unchanged. Production Tab always flows through handleInputKey
// off the live event loop; this is never called at runtime.
func (a *App) PressTab(input string) (text, notice string) {
	a.input.SetText(input)
	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})
	return a.input.GetText(), a.transcript.notice
}

// StatusText returns the text the /status overlay is currently displaying, or ""
// when the overlay is not open. It is a cross-package test seam (like SubmitInput /
// PressCtrlE): bootstrap's StartTUI assembly test drives /status through the
// installed submit hook and reads the overlay text the app's own
// CommandHost.ShowStatus rendered, proving the config cache StartTUI assembled — not
// a cache the test rebuilt — feeds the overlay. Production /status always renders
// through ShowStatus off the live event loop; this is never called at runtime.
func (a *App) StatusText() string {
	if !a.statusOpen {
		return ""
	}
	return a.status.GetText(true)
}

// SettingsOverlayText is a cross-package test seam for bootstrap's StartTUI assembly
// tests; it is never called at runtime.
func (a *App) SettingsOverlayText() string {
	if !a.settingsPickerOpen || a.settingsPicker == nil {
		return ""
	}
	var rows []string
	for _, row := range a.settingsPicker.global {
		rows = append(rows, renderPermissionRow(row))
	}
	for _, row := range a.settingsPicker.folders {
		rows = append(rows, renderPermissionRow(row))
	}
	return strings.Join(rows, "\n")
}

func (a *App) BlockedOverlayText() string {
	if !a.blockedPickerOpen || a.blockedPicker == nil {
		return ""
	}
	lines := make([]string, len(a.blockedPicker.items))
	for i, it := range a.blockedPicker.items {
		lines[i] = it.line
	}
	return strings.Join(lines, "\n")
}

// TranscriptText returns the full rendered transcript pane text — the committed
// lines, the in-progress streamed line, and the one-line notice — exactly as the
// view shows them. It is a cross-package read-only test seam (like StatusText):
// bootstrap's StartTUI assembly test reads it to confirm the production turn sink
// rendered the streamed partial reply into the assembled app's transcript and that
// ESC sealed it with the interrupted marker — an assertion the runner's retained
// counter and the durable event cannot make, because they observe bytes counted,
// not the transcript the user sees. Production renders the transcript through the
// view off the live event loop; this is never called at runtime.
func (a *App) TranscriptText() string { return a.transcript.text(true) }

// NoticeText returns the current one-line transient notice, or "" if none. The ESC
// key path reads it at runtime to tell its own interrupt hint from any other notice,
// and it is also the cross-package read-only seam (like TranscriptText) bootstrap's
// StartTUI assembly test reads.
func (a *App) NoticeText() string {
	a.transcript.mu.Lock()
	defer a.transcript.mu.Unlock()
	return a.transcript.notice
}

// NoticeSeq returns the count of notices emitted so far. The model-change paths read
// it around their apply to tell a notice the apply emitted from a stale pre-apply one.
func (a *App) NoticeSeq() uint64 { return a.noticeSeq.Load() }

// BeginShutdown latches the discard-pending-renders state Stop latches, without
// ending the event loop. The exit sequence calls it before it cancels and drains the
// in-flight turn: that drain runs on the event-loop goroutine, so the surface calls a
// cancelled turn makes on its way out (the held-partial flush and interrupt seal) have
// to be dropped rather than queued, or the drain and the turn deadlock on each other.
// The dropped mutations are view-only — the turn's durable records still land on the
// store, which is what the drain exists to order before the final flush.
func (a *App) BeginShutdown() { a.stopping.Store(true) }

// Stop ends the tview event loop, returning control from Run. The production exit
// controller calls it as part of the clean-shutdown sequence before the
// process exits. Pending stream renders are discarded because that process exit
// owns cleanup of any callback already waiting for the event loop.
func (a *App) Stop() {
	a.BeginShutdown()
	a.app.Stop()
}
