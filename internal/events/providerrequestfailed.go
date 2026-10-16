// EmitProviderRequestFailed appends and immediately flushes the
// provider_request_failed event for a transport-level failure,
// in the same append-then-flush style as EmitLaunchBegan.
package events

import (
	"context"

	"codemeld.dev/codemeld/internal/sessions"
)

// EmitProviderRequestFailed builds a ProviderRequestFailed event from the
// already-classified (phase, reason) tuple — produced by
// provider.Classify* — appends it via Append (which validates and rejects an
// invalid payload before the store is touched), then flushes the active session
// so the failure is durable at the point. httpStatus is nil except for
// the http phase, and partialResponseChars is non-zero only for stream_drop;
// the payload validator enforces both. On a real atomic-write failure (Flush
// returns a non-ReasonNone WriteReason) it invokes onWriteFailure with Flush's
// category, reason, and error so the caller can run the write-failure
// protocol; a cancelled context or other ReasonNone flush failure surfaces to
// the caller without invoking the handler, since the session_write_failed
// contract cannot encode ReasonNone. onWriteFailure may be nil. It
// returns the append or flush error, or nil on success.
func EmitProviderRequestFailed(ctx context.Context, store *sessions.Store, providerName, modelID, phase, reason, errorDetail string, httpStatus *int64, partialResponseChars int64, onWriteFailure WriteFailureHandler) error {
	payload := ProviderRequestFailed{
		Provider:             providerName,
		ModelID:              modelID,
		Phase:                phase,
		HTTPStatus:           httpStatus,
		PartialResponseChars: partialResponseChars,
		Reason:               reason,
		ErrorDetail:          errorDetail,
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
