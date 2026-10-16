// /rename <name> command: persists the active session's user-assigned name into
// the metadata.title field (one Title field,
// not a separate session_name), writing through the active session's owning store
// without advancing updated_at (a rename is metadata housekeeping, not activity).
package tui

import "fmt"

// RenameDeps is the injectable persistence seam NewRenameHandler closes over — a
// deliberate package boundary, not removable indirection: its single SetTitle
// field is what keeps active-store title persistence and atomic-write-failure
// routing (which live in the bootstrap/session-failure layer) out of internal/tui.
// SetTitle persists the new title for the active session and makes the handler's
// just-appended slash_command record durable in the same atomic write.
type RenameDeps struct {
	// SetTitle persists title as the active session's metadata.title through the
	// session's owning store (sessions.Store.FlushTitle), deliberately not via the
	// package-level sessions.SetTitle: the live store already owns the file and, for
	// a resumed session, already holds the sidecar lock SetTitle would try to
	// re-acquire, so a second non-blocking acquire could self-contend. It must not
	// advance updated_at (a rename is not session activity). The
	// production implementation routes an atomic-write failure through the run's
	// session-failure protocol and returns the write error after it is handled, so
	// the command is rejected before its confirmation notice.
	SetTitle func(title string) error
}

// NewRenameHandler returns the /rename handler. Dispatch enforces ArgRestRequired
// and joins all words after the command name into a single argument, so a
// zero-argument /rename is already rejected with the standard arity notice before
// the handler runs and exactly one (possibly multi-word) argument is present here. On a
// valid name the handler records slash_command{outcome:success}, then
// persists the title through the active-store seam — which also flushes the
// just-appended event — and only then renders a one-line confirmation
// notice. A persistence failure returns before the notice so no visible
// confirmation appears past a failed durability boundary; mirroring /status and
// /help, no second slash_command error event is appended on that path.
func NewRenameHandler(deps RenameDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		name := args[0]
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		// Persist the title and flush the appended slash_command event in one atomic
		// write through the active session's owning store (not ctx.FlushActive, which
		// calls Store.Flush and would advance updated_at).
		if err := deps.SetTitle(name); err != nil {
			return err
		}
		ctx.Notice(fmt.Sprintf("Renamed session to %q", name))
		return nil
	}
}
