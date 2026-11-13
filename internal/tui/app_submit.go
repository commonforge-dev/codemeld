package tui

import (
	"strings"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

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
