// CTRL-D exit shortcut: empty input buffer exits via the clean-shutdown path
// (equivalent to /exit); a non-empty buffer is a no-op in phase 1.
package tui

// HandleCtrlD applies the CTRL-D shortcut. On an empty input buffer it exits via the
// clean-shutdown path by dispatching the bare `exit` synonym through the
// installed submit hook, so the canonical slash_command{name:"exit", args:[],
// outcome:"success"} record and the rest of the /exit sequence (clean-shutdown
// flush, resume hint on success, second-failure exit-1) come from the
// /exit handler rather than being duplicated here. On a non-empty buffer it does
// nothing: the typed text is left untouched and no event, flush, notice, or
// shutdown request occurs.
//
// "Empty" is the literal buffer (GetText() == ""); a whitespace-only buffer
// counts as non-empty and is a no-op, so CTRL-D never exits over text the user
// can still see. With no submit hook installed (New(nil) and unit tests before
// SetSubmit) the empty-buffer path is inert — there is nothing to dispatch through.
func (a *App) HandleCtrlD() {
	if a.input.GetText() != "" {
		return
	}
	if a.submit == nil {
		return
	}
	a.submit("exit")
}
