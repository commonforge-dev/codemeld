// /compact command: replace the session history with one provider-generated
// summary carried into a fresh child session.
package tui

import (
	"context"
	"errors"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

var (
	errCompactSummaryRequest = errors.New("compaction failed: the summary request failed")
	errCompactNoSummary      = errors.New("compaction failed: the model returned no summary")
	errCompactCancelled      = errors.New("compaction cancelled")
	errCompactChildMayRemain = errors.New("compaction failed: a complete child session may remain and can be resumed")
)

type CompactDeps struct {
	Context context.Context
	// Must not mutate or cancel the active turn.
	TurnActive func() bool
	// Returns the whole summary request plus the provider/model identity it was
	// built from, so the client is resolved from that same identity rather than a
	// second read of the active selection.
	SummaryRequest func(records []sessions.Record) (req provider.Request, providerID, modelID string, ok bool)
	Client         func(providerID, modelID string) (provider.Client, bool)
	// Must return the underlying store flush error.
	FlushParent func(store *sessions.Store) error
	// When ok is false, release is nil; its owner must call it exactly once.
	AcquireExclusive func() (release func(), ok bool)
	// Runs work off the dispatch goroutine and delivers complete back on the
	// event loop, so only complete may touch the terminal session state.
	RunBackground func(work func() error, complete func(error))
	// A nonnil error can leave a child file; callers must not claim no child
	// exists.
	PrepareChild func(parent *sessions.Store, title string, childRecords, finalParentRecords []sessions.Record) (activate func(), err error)
}

func NewCompactHandler(deps CompactDeps) HandlerFunc {
	return func(ctx CommandContext, _ []string) error {
		parent := ctx.Store()
		if deps.TurnActive() {
			return rejectCompact(ctx, deps, parent, "compact unavailable while a turn is active")
		}
		req, providerID, modelID, ok := deps.SummaryRequest(parent.Records())
		if !ok {
			return rejectCompact(ctx, deps, parent, "compaction failed: no model is selected")
		}
		client, ok := deps.Client(providerID, modelID)
		if !ok {
			return rejectCompact(ctx, deps, parent, "compaction failed: the selected provider is unavailable")
		}
		release, ok := deps.AcquireExclusive()
		if !ok {
			ctx.Notice("compaction is already running")
			ctx.RetainInput()
			return nil
		}
		title := deriveCompactTitle(parent.Title())
		var activate func()
		deps.RunBackground(
			func() error {
				resp, err := client.ChatCompletion(deps.Context, req)
				if deps.Context.Err() != nil {
					return failCompactAfterAcceptance(deps, parent, errCompactCancelled)
				}
				if err != nil {
					return failCompactAfterAcceptance(deps, parent, errCompactSummaryRequest)
				}
				if resp.Completion == nil || len(resp.Completion.Choices) == 0 {
					return failCompactAfterAcceptance(deps, parent, errCompactNoSummary)
				}
				summary := strings.TrimSpace(resp.Completion.Choices[0].Message.Content)
				if summary == "" {
					return failCompactAfterAcceptance(deps, parent, errCompactNoSummary)
				}
				if deps.Context.Err() != nil {
					return failCompactAfterAcceptance(deps, parent, errCompactCancelled)
				}
				success, err := events.Build(events.SlashCommand{
					Name:    "compact",
					Outcome: string(OutcomeSuccess),
				})
				if err != nil {
					return failCompactAfterAcceptance(deps, parent, errCompactChildMayRemain)
				}
				compaction := sessions.Compaction{
					ID:        ids.NewV7(),
					Summary:   summary,
					Timestamp: time.Now().UTC().Truncate(time.Millisecond),
					Provider:  providerID,
					ModelID:   modelID,
				}
				done, err := deps.PrepareChild(parent, title,
					[]sessions.Record{compaction}, []sessions.Record{success})
				if err != nil {
					return failCompactAfterAcceptance(deps, parent, errCompactChildMayRemain)
				}
				activate = done
				return nil
			},
			func(err error) {
				if errors.Is(err, errCompactSummaryRequest) ||
					errors.Is(err, errCompactNoSummary) ||
					errors.Is(err, errCompactCancelled) ||
					errors.Is(err, errCompactChildMayRemain) {
					ctx.Notice(err.Error())
				}
				if activate != nil {
					activate()
				}
				release()
			},
		)
		return nil
	}
}
func rejectCompact(ctx CommandContext, deps CompactDeps, parent *sessions.Store, notice string) error {
	if _, err := events.Append(parent, events.SlashCommand{
		Name:        "compact",
		Outcome:     string(OutcomeError),
		ErrorDetail: notice,
	}); err != nil {
		return err
	}
	if err := deps.FlushParent(parent); err != nil {
		return err
	}
	ctx.Notice(notice)
	ctx.RetainInput()
	return nil
}

func failCompactAfterAcceptance(deps CompactDeps, parent *sessions.Store, fail error) error {
	if _, err := events.Append(parent, events.SlashCommand{
		Name:        "compact",
		Outcome:     string(OutcomeError),
		ErrorDetail: fail.Error(),
	}); err != nil {
		return err
	}
	if err := deps.FlushParent(parent); err != nil {
		return err
	}
	return fail
}

func deriveCompactTitle(parentTitle string) string {
	if parentTitle == "" {
		return "Compacted session"
	}
	return parentTitle + " (compacted)"
}
