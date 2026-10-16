package sessionfork

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

type Child struct {
	Title   string
	Records []sessions.Record
}

type OwnedChild struct {
	Store   *sessions.Store
	Release func()
}

func CreateOwnedChild(
	ctx context.Context,
	home string,
	parent sessions.MetadataSnapshot,
	parentStore *sessions.Store,
	child Child,
	terminalRecords []sessions.Record,
	postLaunch func(child *sessions.Store) (rollback func() error, err error),
	onWriteFailure func(path string, cat fserrors.Category, reason sessions.WriteReason, err error),
) (*OwnedChild, error) {
	forkPoint := lastRecordID(parentStore.Records())
	if forkPoint == "" {
		return nil, fmt.Errorf("sessionfork.CreateOwnedChild: parent session %s has no record to fork from", parent.ID)
	}
	origin := sessions.ForkOrigin{SessionID: parent.ID, RecordID: forkPoint}

	childStore, err := sessions.EnsureChildSession(home, parent, child.Title, origin, child.Records)
	if err != nil {
		return nil, err
	}

	rawRelease, err := sessions.AcquireResumeLock(childStore.Path(), childStore.SessionID())
	if err != nil {
		return nil, err
	}
	var once sync.Once
	release := func() { once.Do(rawRelease) }

	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}

	var onLaunchWriteFailure events.WriteFailureHandler
	if onWriteFailure != nil {
		onLaunchWriteFailure = func(cat fserrors.Category, reason sessions.WriteReason, err error) {
			onWriteFailure(childStore.Path(), cat, reason, err)
		}
	}
	if err := events.EmitLaunchBegan(ctx, childStore, "fork", onLaunchWriteFailure); err != nil {
		release()
		return nil, err
	}

	marker, err := events.Build(events.SessionForked{ToSessionID: childStore.SessionID()})
	if err != nil {
		release()
		return nil, err
	}
	rollback := func() error { return nil }
	fail := func(err error) (*OwnedChild, error) {
		rollbackErr := rollback()
		release()
		return nil, errors.Join(err, rollbackErr)
	}
	if postLaunch != nil {
		hookRollback, err := postLaunch(childStore)
		if hookRollback != nil {
			rollback = hookRollback
		}
		if err != nil {
			return fail(err)
		}
	}
	batch := make([]sessions.Record, 0, len(terminalRecords)+1)
	batch = append(batch, terminalRecords...)
	batch = append(batch, marker)
	if _, _, err := parentStore.CommitFinalRecords(ctx, batch...); err != nil {
		return fail(err)
	}

	return &OwnedChild{Store: childStore, Release: release}, nil
}

func CreateChild(
	ctx context.Context,
	home string,
	parent sessions.MetadataSnapshot,
	parentStore *sessions.Store,
	child Child,
	onWriteFailure func(path string, cat fserrors.Category, reason sessions.WriteReason, err error),
) (*sessions.Store, error) {
	owned, err := CreateOwnedChild(ctx, home, parent, parentStore, child, nil, nil, onWriteFailure)
	if err != nil {
		return nil, err
	}
	owned.Release()
	return owned.Store, nil
}

func lastRecordID(records []sessions.Record) string {
	if len(records) == 0 {
		return ""
	}
	switch r := records[len(records)-1].(type) {
	case sessions.Message:
		return r.ID
	case sessions.Event:
		return r.ID
	case sessions.Compaction:
		return r.ID
	case *sessions.Compaction:
		if r != nil {
			return r.ID
		}
		return ""
	default:
		return ""
	}
}

// textRoles is the closed set of message roles a fork copies. Tool messages and
// every event record are dropped because a fork is text-only.
var textRoles = map[string]bool{"user": true, "assistant": true, "system": true}

func ForkSession(
	ctx context.Context,
	home string,
	original *sessions.Session,
	originalStore *sessions.Store,
	onWriteFailure func(fserrors.Category, sessions.WriteReason, error),
) (*sessions.Store, error) {
	parent := sessions.MetadataSnapshot{
		ID:        original.Metadata.ID,
		Folder:    original.Metadata.Folder,
		StartedAt: original.Metadata.StartedAt,
	}
	var handler func(string, fserrors.Category, sessions.WriteReason, error)
	if onWriteFailure != nil {
		handler = func(_ string, cat fserrors.Category, reason sessions.WriteReason, err error) {
			onWriteFailure(cat, reason, err)
		}
	}
	return CreateChild(ctx, home, parent, originalStore, Child{Records: filterTextRecords(original)}, handler)
}

// filterTextRecords returns the text-only subset of a session's records for a
// fork. It keeps only user, assistant, and system messages, dropping
// tool messages and every event record. A kept message preserves its id, role,
// content, and timestamp but is rebuilt without tool_calls or tool_call_id.
// String content is copied verbatim; list content keeps only its text-typed
// parts, and a list that loses all of its text parts stays an empty list rather
// than collapsing to a string so the original content shape survives.
func filterTextRecords(original *sessions.Session) []sessions.Record {
	out := make([]sessions.Record, 0, len(original.Records))
	for _, rec := range original.Records {
		msg, ok := rec.(sessions.Message)
		if !ok {
			continue // event record: dropped
		}
		if !textRoles[msg.Role] {
			continue // tool message (or any non-text role): dropped
		}
		// Rebuild with only the four carried fields so an assistant message's
		// ToolCalls and a (now-impossible) ToolCallID are stripped.
		out = append(out, sessions.Message{
			ID:        msg.ID,
			Role:      msg.Role,
			Content:   filterTextContent(msg.Content),
			Timestamp: msg.Timestamp,
		})
	}
	return out
}

// filterTextContent reduces a message's content to its text payload. String
// content is returned unchanged; list content is rebuilt from only its text-typed
// parts, preserving order and each part's verbatim raw bytes, and stays a list
// even when no text part survives.
func filterTextContent(c sessions.Content) sessions.Content {
	if !c.IsList() {
		return c
	}
	parts := c.Parts()
	kept := make([]sessions.ContentPart, 0, len(parts))
	for _, p := range parts {
		if p.Type == "text" {
			kept = append(kept, p)
		}
	}
	return sessions.PartsContent(kept)
}
