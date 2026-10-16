package events

import (
	"context"

	"codemeld.dev/codemeld/internal/sessions"
)

func EmitProviderStreamIdle(ctx context.Context, store *sessions.Store, providerName, modelID string, roundElapsedMs, idleMs, partialChars int64, onWriteFailure WriteFailureHandler) error {
	payload := ProviderStreamIdle{
		Provider:       providerName,
		ModelID:        modelID,
		RoundElapsedMs: roundElapsedMs,
		IdleMs:         idleMs,
		PartialChars:   partialChars,
	}
	if _, err := appendEvent(store, payload); err != nil {
		return err
	}
	cat, wreason, err := flushStore(ctx, store)
	if err != nil {
		if wreason != sessions.ReasonNone && onWriteFailure != nil {
			onWriteFailure(cat, wreason, err)
		}
		return err
	}
	return nil
}
