package tui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

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
