package tui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// secretPromptPage is the Pages name the masked prompt overlay is mounted under
// while open, removed when it closes.
const secretPromptPage = "secret-prompt"

// SecretPromptRequest is the caller-supplied data for one masked secret prompt: the
// label and help line shown above the field, and the callbacks run once the user
// submits or cancels. OnSubmit receives the entered string; OnCancel (optional) runs
// on ESC or Ctrl-C. Both fire on the tview event loop after the overlay is torn down,
// so the entered text reaches the caller only as the OnSubmit argument.
type SecretPromptRequest struct {
	Label    string
	Help     string
	OnSubmit func(secret string)
	OnCancel func()
}

// secretPrompt owns the open masked prompt's live state: the input field the secret
// is typed into — kept separate from the app's main input so the secret never lands
// in the shared buffer — and the request whose callbacks fire on submit/cancel.
type secretPrompt struct {
	field *tview.InputField
	req   SecretPromptRequest
}

// OpenSecretPrompt mounts the masked secret prompt as a modal overlay and moves focus
// to its field so typing, Enter (submit), and ESC/Ctrl-C (cancel) drive it. It is a
// no-op while another overlay is open, so a caller cannot stack it over an existing
// modal. The typed text lands only in the overlay's own masked field; the app's main
// input buffer, notices, transcript, history, and session events are never touched.
func (a *App) OpenSecretPrompt(req SecretPromptRequest) {
	if a.anyOverlayOpen() {
		return
	}
	field := tview.NewInputField()
	field.SetMaskCharacter('*')
	field.SetLabelColor(tcell.ColorBlack)
	if req.Label != "" {
		field.SetLabel(req.Label + " ")
	}
	// Enter submits; ESC/Ctrl-C are consumed by the app-level capture and routed to
	// cancelSecretPrompt (central overlay dismissal), so they never reach here.
	field.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			a.submitSecretPrompt()
		}
	})

	body := tview.NewFlex().SetDirection(tview.FlexRow)
	if req.Help != "" {
		help := tview.NewTextView()
		help.SetDynamicColors(false)
		help.SetWrap(true)
		help.SetWordWrap(true)
		help.SetText(req.Help)
		body.AddItem(help, strings.Count(req.Help, "\n")+1, 0, false)
	}
	body.AddItem(field, 1, 0, true)
	body.AddItem(nil, 0, 1, false)
	body.SetBorder(true)
	body.SetTitle(" secret ")

	a.secretPrompt = &secretPrompt{field: field, req: req}
	a.secretPromptOpen = true
	a.secretPromptPrev = a.app.GetFocus()
	a.pages.AddPage(secretPromptPage, wrapOverlayPage(body), true, true)
	a.app.SetFocus(field)
}

// submitSecretPrompt reads the entered secret, tears down the overlay, then hands the
// secret to the caller's OnSubmit. The field is removed before the callback runs, so
// the secret survives only as the argument passed on — never re-entered into any app
// buffer. It is a no-op when the prompt is not open.
func (a *App) submitSecretPrompt() {
	if !a.secretPromptOpen || a.secretPrompt == nil {
		return
	}
	onSubmit := a.secretPrompt.req.OnSubmit
	secret := a.secretPrompt.field.GetText()
	a.closeSecretPrompt()
	if onSubmit != nil {
		onSubmit(secret)
	}
}

// cancelSecretPrompt tears down the overlay without reading the field and runs the
// caller's OnCancel, so an ESC or Ctrl-C closes the prompt without the secret reaching
// OnSubmit. It is a no-op when the prompt is not open.
func (a *App) cancelSecretPrompt() {
	if !a.secretPromptOpen || a.secretPrompt == nil {
		return
	}
	onCancel := a.secretPrompt.req.OnCancel
	a.closeSecretPrompt()
	if onCancel != nil {
		onCancel()
	}
}

// SecretPromptOpen reports whether the masked secret prompt is currently mounted. It
// lets an out-of-package test assert a command opened the prompt (rather than completing
// synchronously) without reaching the unexported overlay state.
func (a *App) SecretPromptOpen() bool {
	return a.secretPromptOpen
}

// SubmitSecretPromptForTest sets the open prompt's field to secret and submits it,
// driving OnSubmit exactly as Enter would. It exists so an out-of-package test (e.g.
// internal/bootstrap's /connect wiring) can exercise the full submit path; in-package
// tests set the field and call submitSecretPrompt directly.
func (a *App) SubmitSecretPromptForTest(secret string) {
	if a.secretPrompt != nil {
		a.secretPrompt.field.SetText(secret)
	}
	a.submitSecretPrompt()
}

// closeSecretPrompt is the shared submit/cancel cleanup path: it clears the prompt
// state, removes the overlay page, and restores focus to whatever held it when the
// prompt opened (falling back to the main input). It never touches the main input
// buffer, so a draft typed before the prompt opened survives.
func (a *App) closeSecretPrompt() {
	if !a.secretPromptOpen {
		return
	}
	a.secretPromptOpen = false
	a.secretPrompt = nil
	a.pages.RemovePage(secretPromptPage)
	if a.secretPromptPrev != nil {
		a.app.SetFocus(a.secretPromptPrev)
	} else {
		a.app.SetFocus(a.input)
	}
	a.secretPromptPrev = nil
}
