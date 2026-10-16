// Package sessionturn owns the pre-turn boundary that makes user input durable
// on disk before a model-provider request is issued.
package sessionturn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// now is a test seam for the accepted-submit clock so a test can drive the
// captured submit-start deterministically; production reads the wall clock in
// UTC. It stamps the retained user message and is the start of the
// end-to-end turn_latency measurement, so both come from one instant.
var now = func() time.Time { return time.Now().UTC() }

// Persister enforces for one session's submit path: it appends the user
// input as a role:"user" message, makes the session durable via Store.Flush, and
// only then runs the prepared model-request dispatch. It is stateful so a write
// failure can be retried without duplicating the retained user message — bind one
// Persister to one session's store and submit path, and do not share it across
// sessions.
type Persister struct {
	store *sessions.Store
	ui    tui.NoticeRenderer

	// pending is true once a user message has been appended for the current input
	// but not yet durably flushed. While set, a re-submit re-flushes that retained
	// message instead of appending a duplicate (the retry path); a
	// successful flush clears it before the next input.
	pending bool

	// pendingInput is the exact input retained while pending is true. A retry must
	// carry this same text: re-flushing it and only then dispatching is the only
	// way the dispatched model request matches what was made durable. A retry with
	// a different input is rejected (ErrPendingInputMismatch) so a request is never
	// issued for text that was never persisted.
	pendingInput string

	// pendingParts is the image content parts retained alongside pendingInput while
	// pending is true. The retry identity covers the full submit payload — text plus
	// attachments — so a retry that changes either the text or the attached
	// images is rejected, never re-flushing the already-persisted message under a
	// different payload.
	pendingParts []sessions.ContentPart

	// pendingStart is the instant the current input was accepted, captured once when
	// the user message is first appended and reused across retries so the end-to-end
	// turn_latency measures from the original accept, not from a re-flush. It
	// is handed to dispatch on the successful flush and cleared with the rest of the
	// retry state.
	pendingStart time.Time
}

// ErrPendingInputMismatch is returned when a retry — a submit made while a prior
// submit is still pending durability — carries a different input than the
// retained one. Dispatching it would issue a model request for text that was
// never made durable, so the retry is rejected without flushing or dispatching
var ErrPendingInputMismatch = errors.New("sessionturn: pending retry input does not match the retained user input")

// New binds a Persister to the active session store and the one-line notice sink
// used when a write fails. The store and ui are fixed for the session's lifetime;
// the per-input retry state lives on the returned value.
func New(store *sessions.Store, ui tui.NoticeRenderer) *Persister {
	return &Persister{store: store, ui: ui}
}

// PersistUserInputThenIssue runs the ordering for one user submit: append
// the user message (first submit only), flush the session to disk, and dispatch
// the model request only after the flush succeeds.
//
// On a successful flush it clears the retry state and calls dispatch exactly once,
// returning dispatch's error. On an atomic-write failure (Flush returns a real
// WriteReason) it routes the failure through the write-failure
// protocol (sessionfailures.HandleWriteFailure) — appending session_write_failed and
// rendering the one-line notice — and does NOT dispatch; the retained message
// stays in memory for a later retry, and the flush error is returned. On a
// non-atomic flush failure (sessions.ReasonNone: a cancelled context or a marshal
// error) it returns the flush error without dispatching and without routing
// through the write-failure protocol, because ReasonNone cannot be encoded as session_write_failed; the
// message likewise stays retained.
//
// Re-submitting the same retained input after any failure re-flushes the
// already-appended message rather than appending a duplicate, so durability is
// retried idempotently. A retry that carries a different input is rejected with
// ErrPendingInputMismatch — without flushing or dispatching — so the model
// request can never run for input that was not the one made durable.
//
// dispatch receives the instant the input was accepted (the pre-turn boundary),
// captured once on the first submit and reused on retries, so the turn it issues
// can record one end-to-end turn_latency from user submit to final answer.
func (p *Persister) PersistUserInputThenIssue(ctx context.Context, input string, imageParts []sessions.ContentPart, dispatch func(submitStart time.Time) error) error {
	if p.pending {
		// A retry only re-flushes the exact retained payload; a different text or a
		// different set of attachments must not be flushed or dispatched, or the model
		// request would run for a payload that was never made durable.
		if input != p.pendingInput || !contentPartsEqual(imageParts, p.pendingParts) {
			return ErrPendingInputMismatch
		}
	} else {
		start := now()
		p.store.Append(sessions.Message{
			ID:        ids.NewV7(),
			Role:      "user",
			Content:   userContent(input, imageParts),
			Timestamp: start,
		})
		p.pending = true
		p.pendingInput = input
		p.pendingParts = imageParts
		p.pendingStart = start
	}

	cat, reason, err := p.store.Flush(ctx)
	if err != nil {
		if reason != sessions.ReasonNone {
			// Atomic-write failure: record session_write_failed and show the notice,
			// but block the model request. The message stays pending so a re-submit
			// retries the flush rather than appending a duplicate.
			if herr := sessionfailures.HandleWriteFailure(reason, cat, p.store.Path(), err, p.store, p.ui); herr != nil {
				return errors.Join(err, herr)
			}
		}
		// Block dispatch on any durability failure. ReasonNone (cancellation or a
		// marshal error) is not routed through the write-failure protocol — it cannot be encoded as
		// session_write_failed — so it is only surfaced to the caller.
		return err
	}

	p.pending = false
	p.pendingInput = ""
	p.pendingParts = nil
	start := p.pendingStart
	p.pendingStart = time.Time{}
	p.storeFallbackTitle(ctx)
	return dispatch(start)
}

const (
	fallbackTitleWords = 12
	fallbackTitleRunes = 80
)

func (p *Persister) storeFallbackTitle(ctx context.Context) {
	if p.store.IsChild() || p.store.Title() != "" {
		return
	}
	text, ok := onlyPlainUserText(p.store.Records())
	if !ok {
		return
	}
	_, _, _ = p.store.FlushGeneratedTitle(ctx, fallbackTitle(text))
}

func onlyPlainUserText(records []sessions.Record) (string, bool) {
	text, users := "", 0
	for _, r := range records {
		m, ok := r.(sessions.Message)
		if !ok || m.Role != "user" {
			continue
		}
		users++
		if !m.Content.IsList() {
			text = m.Content.Text()
		}
	}
	if users != 1 || strings.TrimSpace(text) == "" {
		return "", false
	}
	return text, true
}

func fallbackTitle(text string) string {
	words := strings.Fields(text)
	if len(words) > fallbackTitleWords {
		words = words[:fallbackTitleWords]
	}
	title := []rune(strings.Join(words, " "))
	if len(title) > fallbackTitleRunes {
		title = title[:fallbackTitleRunes]
	}
	return strings.TrimRightFunc(string(title), unicode.IsSpace)
}

// userContent builds the persisted user-message content for one submit: plain
// TextContent when there are no image attachments (unchanged from the text-only
// path), otherwise a PartsContent list of the typed text part (only when input is
// non-empty, so an image-only prompt persists no empty text part) followed by the
// image parts. The text part's raw shape matches what the provider send
// path consumes: {"type":"text","text":input}.
func userContent(input string, imageParts []sessions.ContentPart) sessions.Content {
	if len(imageParts) == 0 {
		return sessions.TextContent(input)
	}
	parts := make([]sessions.ContentPart, 0, len(imageParts)+1)
	if input != "" {
		parts = append(parts, textContentPart(input))
	}
	parts = append(parts, imageParts...)
	return sessions.PartsContent(parts)
}

// textContentPart builds a "text" content part in the raw shape the provider send path
// consumes. The marshal cannot fail for a string field, so the error is discarded.
func textContentPart(text string) sessions.ContentPart {
	raw, _ := json.Marshal(struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{Type: "text", Text: text})
	return sessions.ContentPart{Type: "text", Raw: raw}
}

// contentPartsEqual reports whether two content-part slices are byte-identical in
// order — the retry-identity comparison for the attachment half of the submit
// payload. Equal length, equal Type, and equal Raw bytes per element.
func contentPartsEqual(a, b []sessions.ContentPart) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || !bytes.Equal(a[i].Raw, b[i].Raw) {
			return false
		}
	}
	return true
}
