// Package tui implements the terminal user interface shell: the tview
// application, the transcript pane, and the input area.
package tui

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

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
	network          *networkPrompt

	lifecycle     chan struct{}
	lifecycleOnce sync.Once
	lifecycleMu   sync.Mutex

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
	defer a.endLifecycle()
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
func (a *App) BeginShutdown() {
	a.stopping.Store(true)
	a.endLifecycle()
}

func (a *App) endLifecycle() {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	a.lifecycleOnce.Do(func() { close(a.lifecycle) })
}

func (a *App) Done() <-chan struct{} {
	return a.lifecycle
}

func (a *App) WhileRunning(f func()) bool {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.shuttingDown() {
		return false
	}
	f()
	return true
}

// Stop ends the tview event loop, returning control from Run. The production exit
// controller calls it as part of the clean-shutdown sequence before the
// process exits. Pending stream renders are discarded because that process exit
// owns cleanup of any callback already waiting for the event loop.
func (a *App) Stop() {
	a.BeginShutdown()
	a.app.Stop()
}
