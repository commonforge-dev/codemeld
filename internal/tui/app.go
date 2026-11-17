// Package tui implements the terminal user interface shell: the tview
// application, the transcript pane, and the input area.
package tui

import (
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
