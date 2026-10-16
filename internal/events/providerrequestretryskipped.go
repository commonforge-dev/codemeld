// EmitProviderRequestRetrySkipped appends and immediately flushes the
// provider_request_retry_skipped event for a classified retryable provider-round
// failure that is not scheduled for another attempt, in the
// same append-then-flush style as EmitProviderRequestRetry.
package events

import (
	"context"

	"codemeld.dev/codemeld/internal/sessions"
)

// EmitProviderRequestRetrySkipped builds a ProviderRequestRetrySkipped event from the
// already classified (phase, reason) tuple, the 1-based failed-attempt number, the
// closed skip reason, and the partial-content runes discarded, appends it via Append
// (which validates and rejects an invalid payload before the store is touched), then
// flushes the active session so the skip is durable before the turn proceeds to
// terminal failure. partialCharsDiscarded is non-zero only for a stream_drop; the
// payload validator enforces that. On a real atomic-write failure (Flush returns a
// non-ReasonNone WriteReason) it invokes onWriteFailure with Flush's category, reason,
// and error so the caller can run the write-failure protocol; a cancelled context
// or other ReasonNone flush failure surfaces to the caller without invoking the
// handler. onWriteFailure may be nil. It returns the append or flush error, or nil on
// success.
func EmitProviderRequestRetrySkipped(ctx context.Context, store *sessions.Store, providerName, modelID, phase, reason, skipReason string, attempt, partialCharsDiscarded int64, onWriteFailure WriteFailureHandler) error {
	payload := ProviderRequestRetrySkipped{
		Provider:              providerName,
		ModelID:               modelID,
		Attempt:               attempt,
		Phase:                 phase,
		Reason:                reason,
		SkipReason:            skipReason,
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
