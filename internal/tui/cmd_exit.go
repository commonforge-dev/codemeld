// exit command (alias /quit, and the bare exit/quit synonym): the
// clean-shutdown sequence — append the slash_command event, run the
// clean-shutdown flush, then print the resume hint and exit 0, or take
// the second-failure exit-1 path.
package tui

// resumeHintPrefix is the fixed lead-in of the clean-exit resume hint
// the active session id is appended to form the full line.
const resumeHintPrefix = "to resume this session run: codemeld --resume "

// ResumeHint returns the clean-exit line that tells the user how to
// resume the just-ended session, e.g. "to resume this session run: codemeld
// --resume <id>".
func ResumeHint(sessionID string) string {
	return resumeHintPrefix + sessionID
}

// ExitController is the process-boundary surface the clean-exit sequence drives.
// It is injected rather than calling *App and internal/sessionfailures directly:
// internal/sessionfailures imports internal/tui for the write-failure notice, so
// a direct call to its CleanShutdownFlush from this package would form an import
// cycle. The production implementation, assembled in internal/bootstrap, binds
// FlushOnExit to sessionfailures.CleanShutdownFlush over the active store and
// Finish to the tview event-loop teardown plus process exit.
type ExitController interface {
	// SessionID returns the active session's id, read at exit time so an
	// in-process session swap (clear, /resume) is reflected in the hint.
	SessionID() string
	// FlushOnExit runs the clean-shutdown flush via
	// sessionfailures.CleanShutdownFlush: it attempts the atomic write, retries
	// exactly once on failure, and on the second failure writes the OP_FAIL "session-write-on-exit"
	// line to stderr and returns a non-nil error. A nil return means the
	// final session state is durable.
	FlushOnExit() error
	// Finish ends the run, stopping the TUI and propagating exitCode as the process
	// status. resumeHint, when non-empty, is the line printed to stdout
	// before a status-0 exit; it is empty on the status-1 second-failure path,
	// where the clean-shutdown flush has already written the stderr line and the
	// resume hint is suppressed.
	Finish(exitCode int, resumeHint string)
}

// NewExitHandler returns the /exit handler (also reached by /quit and the bare
// exit/quit synonym through registry dispatch). It runs the four-step
// clean-shutdown sequence: (1) append slash_command{name:"exit", args:[],
// outcome:"success"} to the in-memory stream before the flush; (2) run the
// clean-shutdown flush; (3) on success print the resume hint
// and exit 0; (4) on the second-failure path exit 1 with no hint — the
// appended slash_command event is lost with the rest of the unflushed tail.
func NewExitHandler(ctrl ExitController) HandlerFunc {
	return func(ctx CommandContext, _ []string) error {
		// (1) The event is appended before the flush so a successful flush carries
		// it to disk; dispatch has bound the canonical name "exit", so /quit and the
		// bare synonym record "exit" rather than the typed alias.
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		// (2) Trigger the clean-shutdown flush. The flush owns the retry and the
		// second-failure stderr line; this handler only maps its result to an exit
		// code.
		if err := ctrl.FlushOnExit(); err != nil {
			// (4) Second-failure path: exit 1, no resume hint.
			ctrl.Finish(1, "")
			return err
		}
		// (3) Flush succeeded: print the resume hint and exit 0.
		ctrl.Finish(0, ResumeHint(ctrl.SessionID()))
		return nil
	}
}
