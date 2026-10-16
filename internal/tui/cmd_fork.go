package tui

import (
	"fmt"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

type ForkDeps struct {
	// Must not mutate or cancel the active turn.
	TurnActive func() bool
	// Must return the underlying store flush error.
	FlushParent func(store *sessions.Store) error
	// A nonnil error can leave a child file; callers must not claim no child exists.
	CreateAndActivate func(parent *sessions.Store, title string, records, terminalParentRecords []sessions.Record) (cleanupWarning string, err error)
}

func NewForkHandler(deps ForkDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		parent := ctx.Store()
		if deps.TurnActive() {
			return rejectFork(ctx, deps, parent, "fork unavailable while a turn is active")
		}
		records := forkContinuationRecords(parent.Records())
		if len(records) == 0 {
			return rejectFork(ctx, deps, parent, "nothing to fork")
		}
		title := deriveForkTitle(parent.Title())
		success, err := events.Build(events.SlashCommand{Name: "fork", Args: args, Outcome: string(OutcomeSuccess)})
		if err != nil {
			return err
		}
		warning, err := deps.CreateAndActivate(parent, title, records, []sessions.Record{success})
		if err != nil {
			notice := fmt.Sprintf("fork failed: %v", err)
			ctx.Notice(notice)
			ctx.RetainInput()
			if appendErr := ctx.AppendSlashCommand(OutcomeError, notice); appendErr != nil {
				return appendErr
			}
			return deps.FlushParent(parent)
		}
		notice := fmt.Sprintf("Forked to %q", title)
		if warning != "" {
			notice += "; " + warning
		}
		ctx.Notice(notice)
		return nil
	}
}

func rejectFork(ctx CommandContext, deps ForkDeps, parent *sessions.Store, notice string) error {
	ctx.Notice(notice)
	ctx.RetainInput()
	if err := ctx.AppendSlashCommand(OutcomeError, notice); err != nil {
		return err
	}
	return deps.FlushParent(parent)
}

func forkContinuationRecords(records []sessions.Record) []sessions.Record {
	out := make([]sessions.Record, 0, len(records))
	for _, rec := range records {
		switch rec.(type) {
		case sessions.Message, sessions.Compaction, *sessions.Compaction:
			out = append(out, rec)
		}
	}
	return out
}

func deriveForkTitle(parentTitle string) string {
	if parentTitle == "" {
		return "Forked session"
	}
	return parentTitle + " (forked)"
}
