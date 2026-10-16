// EmitProviderRequestRetry appends and immediately flushes the
// provider_request_retry event for one scheduled auto-retry of a transient
// provider-round failure, in the same append-then-flush style as
// EmitProviderRequestFailed.
package events

import (
	"context"

	"codemeld.dev/codemeld/internal/sessions"
)

// EmitProviderRequestRetry builds a ProviderRequestRetry event from the already
// classified (phase, reason) tuple, the 1-based failed-attempt number, the
// scheduled backoff delay, and the partial-content runes being discarded, appends
// it via Append (which validates and rejects an invalid payload before the store
// is touched), then flushes the active session so the retry is durable before the
// turn waits out the backoff — a failed attempt survives a process exit during the
// wait. partialCharsDiscarded is non-zero only for a stream_drop; the payload
// validator enforces that. On a real atomic-write failure (Flush returns a
// non-ReasonNone WriteReason) it invokes onWriteFailure with Flush's category,
// reason, and error so the caller can run the write-failure protocol; a
// cancelled context or other ReasonNone flush failure surfaces to the caller
// without invoking the handler. onWriteFailure may be nil. It returns
// the append or flush error, or nil on success.
func EmitProviderRequestRetry(ctx context.Context, store *sessions.Store, providerName, modelID, phase, reason string, attempt, delayMs, partialCharsDiscarded int64, onWriteFailure WriteFailureHandler) error {
	payload := ProviderRequestRetry{
		Provider:              providerName,
		ModelID:               modelID,
		Attempt:               attempt,
		Phase:                 phase,
		Reason:                reason,
		DelayMs:               delayMs,
		PartialCharsDiscarded: partialCharsDiscarded,
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
