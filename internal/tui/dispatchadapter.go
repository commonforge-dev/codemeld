// Maps registry dispatch onto the app's SubmitFunc accept/reject contract and
// routes plain (non-slash) prompts to an injected model-turn entrypoint.
package tui

import "codemeld.dev/codemeld/internal/sessions"

// PromptEntrypoint routes a plain (non-slash) prompt into the model-turn path,
// reporting whether the input was accepted (the app clears the input field) or
// must be retained (e.g. a pre-turn durability failure). This is only the
// routing seam; the production implementation (in internal/bootstrap) drives
// the pre-turn persistence contract before any provider request, and the
// provider turn loop itself is owned by later tasks. imageParts carries any pending
// image attachments so the plain-prompt persist path builds a content-part user
// message; it is the variadic tail so text-only callers are unchanged. A
// nil PromptEntrypoint rejects every plain prompt.
type PromptEntrypoint func(input string, imageParts ...sessions.ContentPart) bool

// NewSubmitFunc builds the production SubmitFunc the app submits through: it
// dispatches each line via the registry's DispatchSlashInput and maps the result
// onto the accept/reject boolean that controls input clearing.
//
//   - StatusNotASlashCommand: ordinary prompt text — forward it to prompt and
//     accept only if prompt accepts; a nil prompt rejects.
//   - StatusUnknownCommand / StatusWrongArity: dispatch already rendered the
//     one-line notice and asked to retain input, so reject (no model send, no
//
// event) — the typed text stays for the user to edit.
//   - StatusHandled: accept (clear the input) unless the handler requested input
//
// retention, e.g. /effort's unsupported-value path. A non-nil
//
//	handler error retains the input rather than discarding the user's text on
//	an internal failure; the handler owns any user-facing notice it can render.
func NewSubmitFunc(reg *Registry, host CommandHost, prompt PromptEntrypoint) SubmitFunc {
	return func(input string, imageParts ...sessions.ContentPart) bool {
		res := reg.DispatchSlashInput(input, host)
		switch res.Status {
		case StatusNotASlashCommand:
			if prompt == nil {
				return false
			}
			// Only a plain prompt carries image attachments onward; slash command
			// dispatch above never sees them, keeping commands text-only.
			return prompt(input, imageParts...)
		case StatusUnknownCommand, StatusWrongArity:
			return false
		case StatusHandled:
			if res.Err != nil {
				return false
			}
			return !res.RetainInput
		default:
			return false
		}
	}
}
