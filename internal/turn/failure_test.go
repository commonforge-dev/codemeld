// Failure-path tests for Runner.Run: mid-stream transport drop, clean zero-delta
// (empty_response) stream, and HTTP-error surfacing (plain vs quota hint), all
// driven by the fake provider client.
package turn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// dropDecoder yields one content chunk, then ends iteration with a non-nil Err so
// the stream surfaces a mid-stream transport drop after partial assistant content.
type dropDecoder struct {
	first  []byte
	err    error
	served bool
	cur    ssestream.Event
}

func (d *dropDecoder) Next() bool {
	if !d.served {
		d.served = true
		d.cur = ssestream.Event{Data: d.first}
		return true
	}
	return false
}
func (d *dropDecoder) Event() ssestream.Event { return d.cur }
func (d *dropDecoder) Close() error           { return nil }
func (d *dropDecoder) Err() error             { return d.err }

// findProviderRequestFailed returns the single provider_request_failed payload in
// recs, failing the test if none is present.
func findProviderRequestFailed(t *testing.T, recs []sessions.Record) events.ProviderRequestFailed {
	t.Helper()
	for _, r := range recs {
		e, ok := r.(sessions.Event)
		if !ok || e.Kind != events.KindProviderRequestFailed {
			continue
		}
		var p events.ProviderRequestFailed
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatalf("unmarshal provider_request_failed payload: %v", err)
		}
		return p
	}
	t.Fatalf("no provider_request_failed event; kinds = %v", eventKinds(recs))
	return events.ProviderRequestFailed{}
}

func diskRecords(t *testing.T, store *sessions.Store) []sessions.Record {
	t.Helper()
	sess, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed session %s: %v", store.Path(), err)
	}
	return sess.Records
}

// assertOneDurableProviderRound asserts the flushed session holds exactly one
// provider_round_trip for wantProvider/wantModel with a non-negative duration —
// the timing guarantee that a failed provider round still persists its timing on the
// same flush as its terminal provider_request_failed. Read back from disk so a
// recordProviderRound append that never reaches the flush would fail it.
func assertOneDurableProviderRound(t *testing.T, store *sessions.Store, wantProvider, wantModel string) {
	t.Helper()
	rounds := providerRoundTripEvents(t, diskRecords(t, store))
	if len(rounds) != 1 {
		t.Fatalf("persisted provider_round_trip events = %d, want 1 for a failed round", len(rounds))
	}
	if rounds[0].Provider != wantProvider || rounds[0].ModelID != wantModel {
		t.Fatalf("provider_round_trip identity = %+v, want provider %s model %s", rounds[0], wantProvider, wantModel)
	}
	if rounds[0].DurationMs < 0 {
		t.Fatalf("provider_round_trip duration_ms = %d, want >= 0", rounds[0].DurationMs)
	}
}

// A mid-stream drop after partial content emits provider_request_failed{stream_drop}
// with the retained-character count, seals the transcript as interrupted, and emits
// no assistant message or model_response.
func TestRun_MidStreamDropEmitsEventMarksInterrupted(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	// Multibyte partial so the count assertion distinguishes runes from bytes:
	// "Hi café ☕" is 9 runes but 12 bytes, so a regression from
	// utf8.RuneCountInString to len() in Runner.Run would fail this test.
	const partial = "Hi café ☕"
	var interrupts int
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		dec := &dropDecoder{first: contentChunk(partial), err: io.ErrUnexpectedEOF}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}}
	runner := New(Deps{
		Active:    selectedState("openai", "gpt-x", model.EffortDefault),
		Store:     store,
		Client:    client,
		Interrupt: func() { interrupts++ },
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the mid-stream drop error")
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted on a mid-stream drop; kinds = %v", eventKinds(recs))
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded on a mid-stream drop")
	}
	if interrupts != 1 {
		t.Fatalf("Interrupt called %d times, want 1 on a mid-stream drop", interrupts)
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "stream_drop" {
		t.Fatalf("phase = %q, want stream_drop", prf.Phase)
	}
	if prf.Reason != "stream_eof" {
		t.Fatalf("reason = %q, want stream_eof for io.ErrUnexpectedEOF", prf.Reason)
	}
	if want := int64(utf8.RuneCountInString(partial)); prf.PartialResponseChars != want {
		t.Fatalf("partial_response_chars = %d, want %d (must count runes, not the %d bytes)", prf.PartialResponseChars, want, len(partial))
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Phase != "stream_drop" || diskPRF.Reason != "stream_eof" {
		t.Fatalf("disk (phase, reason) = (%q, %q), want (stream_drop, stream_eof)", diskPRF.Phase, diskPRF.Reason)
	}
	// The stream-drop round records its timing on the same flush as the
	// failure event, so a slow drop is durable. Dropping recordProviderRound from
	// the mid-stream branch (turn.go) makes this fail.
	assertOneDurableProviderRound(t, store, "openai", "gpt-x")
}

// A user cancellation (context.Canceled) is not a provider failure: it must not emit
// provider_request_failed nor call the interrupt hook (the ESC/CTRL-C path seals the
// transcript and records stream_interrupted itself).
func TestRun_CanceledStreamEmitsNoProviderFailure(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var interrupts int
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		dec := &dropDecoder{first: contentChunk("Hi"), err: context.Canceled}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}}
	runner := New(Deps{
		Active:    selectedState("openai", "gpt-x", model.EffortDefault),
		Store:     store,
		Client:    client,
		Interrupt: func() { interrupts++ },
	})

	if err := runner.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if interrupts != 0 {
		t.Fatalf("Interrupt called %d times, want 0 for a user cancellation", interrupts)
	}
	recs := store.Records()
	if hasKind(recs, "provider_request_failed") {
		t.Fatalf("provider_request_failed emitted for a user cancellation; kinds = %v", eventKinds(recs))
	}
}

// A user cancellation that arrives while the reply is still a held text-tool-call
// candidate (its raw JSON withheld from the sink) must still surface that partial
// content and seal it as interrupted. The ESC/CTRL-C path records stream_interrupted with
// the retained char count, but its own markInterrupted is a no-op when nothing reached the
// transcript, so Run flushes the held content to the sink and calls Interrupt on the
// cancellation path. The already-streamed cancellation path is unaffected (see
// TestRun_CanceledStreamEmitsNoProviderFailure, whose ordinary "Hi" reply was never held).
func TestRun_CancelFlushesAndSealsHeldCandidate(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	const held = `{"name":"bash","arguments":{"command":"ls"}}`
	var deltas []string
	var interrupts int
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		dec := &dropDecoder{first: contentChunk(held), err: context.Canceled}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}}
	runner := New(Deps{
		Active:    selectedState("openai", "gpt-x", model.EffortDefault),
		Store:     store,
		Client:    client,
		Sink:      func(d string) { deltas = append(deltas, d) },
		Interrupt: func() { interrupts++ },
	})

	if err := runner.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}

	if got := strings.Join(deltas, ""); got != held {
		t.Fatalf("flushed sink content = %q, want the held candidate %q surfaced on cancel", got, held)
	}
	if interrupts != 1 {
		t.Fatalf("Interrupt called %d times, want 1 to seal the surfaced held content", interrupts)
	}

	recs := store.Records()
	if hasKind(recs, "provider_request_failed") {
		t.Fatalf("provider_request_failed emitted for a user cancellation; kinds = %v", eventKinds(recs))
	}
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted on a cancelled turn; kinds = %v", eventKinds(recs))
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded on a cancelled turn")
	}
}

// A clean stream that reaches EOF with zero assistant-content deltas (and no
// tool-call handoff) emits provider_request_failed{empty_response, zero_delta_stream},
// appends no assistant message, emits no model_response, and neither finalizes nor
// interrupts the transcript.
func TestRun_EmptyZeroDeltaStreamEmitsEmptyResponse(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var interrupts, finalizes int
	var notices []string
	runner := New(Deps{
		Active:       selectedState("openai", "gpt-x", model.EffortDefault),
		Store:        store,
		Client:       streamClient(finishChunk("stop")),
		Interrupt:    func() { interrupts++ },
		Finalize:     func() { finalizes++ },
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil for a recorded empty_response", err)
	}

	recs := store.Records()
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded for a zero-delta stream")
	}
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a zero-delta stream; kinds = %v", eventKinds(recs))
	}
	if interrupts != 0 {
		t.Fatalf("Interrupt called %d times, want 0 for empty_response", interrupts)
	}
	if finalizes != 0 {
		t.Fatalf("Finalize called %d times, want 0 for empty_response", finalizes)
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "empty_response" || prf.Reason != "zero_delta_stream" {
		t.Fatalf("(phase, reason) = (%q, %q), want (empty_response, zero_delta_stream)", prf.Phase, prf.Reason)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Phase != "empty_response" || diskPRF.Reason != "zero_delta_stream" {
		t.Fatalf("disk (phase, reason) = (%q, %q), want (empty_response, zero_delta_stream)", diskPRF.Phase, diskPRF.Reason)
	}

	// the empty_response failure surfaces the one-line notice
	// with no remediation hint (line 1 only).
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one empty_response surface", notices)
	}
	if !strings.Contains(notices[0], "(empty_response/zero_delta_stream)") {
		t.Fatalf("notice = %q, want it to name the empty_response/zero_delta_stream failure", notices[0])
	}
	if strings.Contains(notices[0], "→ hint:") {
		t.Fatalf("notice = %q, want no remediation hint for empty_response (req 564)", notices[0])
	}
}

// A pre-request credential failure (the selected provider has no usable
// credential — e.g. a missing OpenAI ChatGPT session) surfaces the safe,
// provider-named remediation verbatim as a one-line notice and fails the turn, but
// emits NO provider_request_failed event (the reason set has no auth phase)
// and no model_response, and neither finalizes nor interrupts the transcript. The
// message is passed through RenderNotice with empty phase/reason, so the hint table
// is bypassed and the surface renders unchanged.
func TestRun_CredentialUnavailableSurfacesNoticeNoEvent(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	const surface = "OpenAI ChatGPT has no usable local session; run `codemeld auth status` or `codemeld auth login openai-chatgpt`"
	credErr := &provider.CredentialUnavailableError{Surface: surface}
	var notices []string
	var interrupts, finalizes int
	runner := New(Deps{
		Active: selectedState("openai-chatgpt", "gpt-5.5", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, credErr
		}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
		Interrupt:    func() { interrupts++ },
		Finalize:     func() { finalizes++ },
	})

	if err := runner.Run(context.Background()); !errors.Is(err, credErr) {
		t.Fatalf("Run() error = %v, want the credential error", err)
	}
	if len(notices) != 1 || notices[0] != surface {
		t.Fatalf("notices = %v, want exactly the verbatim credential surface %q", notices, surface)
	}
	recs := store.Records()
	if hasKind(recs, "provider_request_failed") {
		t.Fatalf("provider_request_failed emitted for a credential failure (no auth phase exists); kinds = %v", eventKinds(recs))
	}
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a credential failure; kinds = %v", eventKinds(recs))
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded for a credential failure")
	}
	if interrupts != 0 || finalizes != 0 {
		t.Fatalf("Interrupt=%d Finalize=%d, want 0/0 (a pre-request credential failure opens no stream)", interrupts, finalizes)
	}
}

// A non-quota HTTP error with a non-JSON body surfaces the friendly fallback line
// (the bare "provider <name> returned HTTP <status>" prefix, no raw body shown) as
// a one-line notice and persists UTF-8-normalized body text as
// provider_request_failed{http, http_error} with http_status set — verified both
// in-memory and read back from the flushed session — and emits no model_response.
func TestRun_HTTPErrorSurfacesNoticeAndEmitsHTTPError(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	httpErr := &provider.HTTPError{
		Status:  500,
		Body:    "internal server \xff\xfe error",
		Surface: "provider openai returned HTTP 500: internal server \xff\xfe error",
	}
	// A non-JSON body has no extractable human message, so line 1 is the bare prefix.
	const wantNotice = "provider openai returned HTTP 500"
	wantErrorDetail := strings.ToValidUTF8(httpErr.Body, "�")
	var notices []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, httpErr
		}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})

	if err := runner.Run(context.Background()); !errors.Is(err, httpErr) {
		t.Fatalf("Run() error = %v, want the HTTPError", err)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one surfaced HTTP-error notice", notices)
	}
	if notices[0] != wantNotice {
		t.Fatalf("notice = %q, want the friendly fallback line %q (raw body not shown, adr-006)", notices[0], wantNotice)
	}
	if strings.Contains(notices[0], "\xff") {
		t.Fatalf("notice = %q, leaked the raw body bytes (should be the synthetic prefix only)", notices[0])
	}
	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatal("model_response emitted for an HTTP error")
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "http" || prf.Reason != "http_error" {
		t.Fatalf("(phase, reason) = (%q, %q), want (http, http_error)", prf.Phase, prf.Reason)
	}
	// error_detail is the UTF-8-normalized Body, never the synthetic Surface.
	if prf.ErrorDetail != wantErrorDetail {
		t.Fatalf("error_detail = %q, want UTF-8-normalized body %q (not Surface)", prf.ErrorDetail, wantErrorDetail)
	}
	if prf.HTTPStatus == nil || *prf.HTTPStatus != 500 {
		t.Fatalf("http_status = %v, want 500", prf.HTTPStatus)
	}
	// Persisted body is verified from disk, not just the in-memory snapshot.
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Phase != "http" || diskPRF.Reason != "http_error" {
		t.Fatalf("disk (phase, reason) = (%q, %q), want (http, http_error)", diskPRF.Phase, diskPRF.Reason)
	}
	if diskPRF.ErrorDetail != wantErrorDetail {
		t.Fatalf("disk error_detail = %q, want UTF-8-normalized body %q", diskPRF.ErrorDetail, wantErrorDetail)
	}
	if diskPRF.HTTPStatus == nil || *diskPRF.HTTPStatus != 500 {
		t.Fatalf("disk http_status = %v, want 500", diskPRF.HTTPStatus)
	}
	// The pre-stream HTTP-error round records its timing on the same flush as
	// the failure event. Dropping recordProviderRound from the HTTP-error branch
	// (turn.go) makes this fail.
	assertOneDurableProviderRound(t, store, "openai", "gpt-x")
}

// A quota-declaring 4xx/5xx HTTP error renders the quota remediation hint as a
// second line after the friendly line-1 message extracted from the body,
// and also persists provider_request_failed{http, http_error} with the
// body text — the durable event reason stays http_error, distinct from the
// render-path quota hint. No model_response is emitted.
func TestRun_QuotaHTTPErrorSurfacesHintAndEmitsHTTPError(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	httpErr := &provider.HTTPError{
		Status:  429,
		Body:    `{"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}`,
		Surface: `provider openai returned HTTP 429: {"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}`,
	}
	// Line 1 is the friendly message from error.message, not the raw JSON.
	const wantLine1 = "provider openai returned HTTP 429: You exceeded your current quota"
	var notices []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, httpErr
		}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})

	if err := runner.Run(context.Background()); !errors.Is(err, httpErr) {
		t.Fatalf("Run() error = %v, want the HTTPError", err)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one surfaced HTTP-error notice", notices)
	}
	if !strings.HasPrefix(notices[0], wantLine1) {
		t.Fatalf("notice = %q, want it to start with the friendly line %q", notices[0], wantLine1)
	}
	if strings.Contains(notices[0], "{") {
		t.Fatalf("notice = %q, leaked the raw JSON body (adr-006: friendly line only)", notices[0])
	}
	if !strings.Contains(notices[0], "→ hint:") {
		t.Fatalf("quota HTTP error did not render f85's quota hint line: %q", notices[0])
	}
	prf := findProviderRequestFailed(t, store.Records())
	if prf.Phase != "http" || prf.Reason != "http_error" {
		t.Fatalf("(phase, reason) = (%q, %q), want (http, http_error) — not the render-path quota hint", prf.Phase, prf.Reason)
	}
	if prf.ErrorDetail != httpErr.Body {
		t.Fatalf("error_detail = %q, want body text %q", prf.ErrorDetail, httpErr.Body)
	}
	if prf.HTTPStatus == nil || *prf.HTTPStatus != 429 {
		t.Fatalf("http_status = %v, want 429", prf.HTTPStatus)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Reason != "http_error" || diskPRF.ErrorDetail != httpErr.Body {
		t.Fatalf("disk (reason, error_detail) = (%q, %q), want (http_error, body text)", diskPRF.Reason, diskPRF.ErrorDetail)
	}
}

// An HTTP-error provider_request_failed flush failure routes through the injected
// events.WriteFailureHandler: the *HTTPError emit flushes to a missing parent dir, so
// EmitProviderRequestFailed reports a non-ReasonNone WriteReason and Run must have
// passed r.deps.OnFailureWrite into it (task step 2), matching the sibling
// transport-failure emit. Dropping that argument from the HTTP-error emit call makes
// this fail.
func TestRun_HTTPErrorWriteFailureRoutesToHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	dir := filepath.Dir(path)
	store := storeAt(path)
	httpErr := &provider.HTTPError{
		Status:  500,
		Body:    "internal server error",
		Surface: "provider openai returned HTTP 500: internal server error",
	}
	var calls int
	var gotReason sessions.WriteReason
	var gotErr error
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, httpErr
		}},
		Notice: func(string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatalf("remove session directory: %v", err)
			}
			if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
				t.Fatalf("replace session directory: %v", err)
			}
		},
		RenderNotice: tui.RenderProviderRequestFailedNotice,
		OnFailureWrite: func(_ fserrors.Category, reason sessions.WriteReason, err error) {
			calls++
			gotReason = reason
			gotErr = err
		},
	})

	if err := runner.Run(context.Background()); !errors.Is(err, httpErr) {
		t.Fatalf("Run() error = %v, want the HTTPError to propagate", err)
	}
	if calls != 1 {
		t.Fatalf("OnFailureWrite called %d times, want exactly 1 for a flush failure", calls)
	}
	if gotReason == sessions.ReasonNone {
		t.Fatalf("OnFailureWrite reason = %v, want a real (non-ReasonNone) write reason", gotReason)
	}
	if gotErr == nil {
		t.Fatal("OnFailureWrite err = nil, want the atomic-write error")
	}
}

// A 4xx/5xx body that mentions a quota without declaring it exhausted (here a
// negated "quota was not exceeded") must stay one-line: the notice equals the
// verbatim surface with no quota hint. This trips the old broad "quota"+"exceed"
// matcher and passes only once bodyDeclaresQuotaExhausted requires contiguous
// exhaustion wording.
func TestRun_NonQuotaBodyMentioningQuotaStaysOneLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		// want is the friendly line-1 notice: the bare prefix for a
		// non-JSON body, or the extracted error.message for a JSON body.
		want string
	}{
		{
			name: "negated quota phrase",
			body: "internal error: your monthly quota was not exceeded; retry later",
			want: "provider openai returned HTTP 500",
		},
		{
			name: "prefixed quota code",
			body: `{"error":{"code":"not_insufficient_quota","message":"some other failure"}}`,
			want: "provider openai returned HTTP 500: some other failure",
		},
		{
			name: "negated quota code text",
			body: "internal error: not insufficient_quota; retry later",
			want: "provider openai returned HTTP 500",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			httpErr := &provider.HTTPError{
				Status:  500,
				Body:    tc.body,
				Surface: "provider openai returned HTTP 500: " + tc.body,
			}
			var notices []string
			runner := New(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  store,
				Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
					return provider.Response{}, httpErr
				}},
				Notice:       func(text string) { notices = append(notices, text) },
				RenderNotice: tui.RenderProviderRequestFailedNotice,
			})

			if err := runner.Run(context.Background()); !errors.Is(err, httpErr) {
				t.Fatalf("Run() error = %v, want the HTTPError", err)
			}
			if len(notices) != 1 {
				t.Fatalf("notices = %v, want exactly one surfaced HTTP-error notice", notices)
			}
			if notices[0] != tc.want {
				t.Fatalf("notice = %q, want the friendly line %q (no hint for a non-quota body)", notices[0], tc.want)
			}
			if strings.Contains(notices[0], "→ hint:") {
				t.Fatalf("rendered f85's quota hint for a non-quota body: %q", notices[0])
			}
		})
	}
}

func TestRun_EmptyResponseWriteFailureRoutesToHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "session.json")
	store := storeAt(path)
	var calls int
	var gotReason sessions.WriteReason
	var gotErr error
	var notices []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(finishChunk("stop")),
		OnFailureWrite: func(_ fserrors.Category, reason sessions.WriteReason, err error) {
			calls++
			gotReason = reason
			gotErr = err
		},
		Notice: func(text string) { notices = append(notices, text) },
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil after a terminal-record flush failure")
	}
	if calls != 1 {
		t.Fatalf("OnFailureWrite called %d times, want exactly 1 for a flush failure", calls)
	}
	if gotReason == sessions.ReasonNone {
		t.Fatalf("OnFailureWrite reason = %v, want a real (non-ReasonNone) write reason", gotReason)
	}
	if gotErr == nil {
		t.Fatal("OnFailureWrite err = nil, want the atomic-write error")
	}
	if !hasKind(store.Records(), events.KindProviderRequestFailed) {
		t.Fatalf("provider_request_failed missing after a terminal-record write failure; kinds = %v", eventKinds(store.Records()))
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want the provider failure surface", notices)
	}
}

// A 2xx response with a missing body (provider client surfaces *HTTPBodyError with
// Truncated false) emits provider_request_failed{http, http_no_body} carrying the
// required http_status, surfaces a synthetic notice, and emits no model_response or
// assistant message.
func TestRun_MissingHTTPBodyEmitsHTTPNoBody(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	bodyErr := &provider.HTTPBodyError{Status: 200}
	var notices []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, bodyErr
		}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})

	if err := runner.Run(context.Background()); !errors.Is(err, bodyErr) {
		t.Fatalf("Run() error = %v, want the HTTPBodyError", err)
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a missing-body failure; kinds = %v", eventKinds(recs))
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded for a missing-body failure")
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "http" || prf.Reason != "http_no_body" {
		t.Fatalf("(phase, reason) = (%q, %q), want (http, http_no_body)", prf.Phase, prf.Reason)
	}
	if prf.HTTPStatus == nil || *prf.HTTPStatus != 200 {
		t.Fatalf("http_status = %v, want 200 (required for http_no_body)", prf.HTTPStatus)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Phase != "http" || diskPRF.Reason != "http_no_body" {
		t.Fatalf("disk (phase, reason) = (%q, %q), want (http, http_no_body)", diskPRF.Phase, diskPRF.Reason)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one surfaced body-failure notice", notices)
	}
}

// A 2xx response whose body was truncated (provider client surfaces *HTTPBodyError
// with Truncated true) emits provider_request_failed{http, http_truncated} and a
// synthetic notice, with no model_response.
func TestRun_TruncatedHTTPBodyEmitsHTTPTruncated(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	bodyErr := &provider.HTTPBodyError{Status: 200, Truncated: true}
	var notices []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, bodyErr
		}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})

	if err := runner.Run(context.Background()); !errors.Is(err, bodyErr) {
		t.Fatalf("Run() error = %v, want the HTTPBodyError", err)
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a truncated-body failure; kinds = %v", eventKinds(recs))
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "http" || prf.Reason != "http_truncated" {
		t.Fatalf("(phase, reason) = (%q, %q), want (http, http_truncated)", prf.Phase, prf.Reason)
	}
	// http_status is optional for http_truncated, but the client preserved it here.
	if prf.HTTPStatus == nil || *prf.HTTPStatus != 200 {
		t.Fatalf("http_status = %v, want 200 (status line was received before truncation)", prf.HTTPStatus)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Reason != "http_truncated" {
		t.Fatalf("disk reason = %q, want http_truncated", diskPRF.Reason)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one surfaced body-failure notice", notices)
	}
}

// roundTripFunc adapts a function to http.RoundTripper so a production-path test
// can drive the real streaming provider client with a crafted 2xx response.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// truncatedBody yields its bytes once, then fails every later read with
// io.ErrUnexpectedEOF, modeling a streaming 2xx body cut off mid-transfer.
type truncatedBody struct {
	data []byte
	done bool
}

func (b *truncatedBody) Read(p []byte) (int, error) {
	if !b.done && len(b.data) > 0 {
		b.done = true
		return copy(p, b.data), nil
	}
	return 0, io.ErrUnexpectedEOF
}
func (b *truncatedBody) Close() error { return nil }

// realStreamingRunner builds a Runner driving the real openAIClient (Stream: true,
// as BuildRequest always sets) over rt, so the streaming body-failure detection is
// exercised end to end rather than through an injected fake. notices captures the
// surfaced failure notices.
func realStreamingRunner(store *sessions.Store, rt http.RoundTripper, notices *[]string) *Runner {
	client := provider.NewClient(provider.ClientConfig{
		Name:       "openai",
		BaseURL:    "https://stub.invalid",
		AuthHeader: "Authorization",
		AuthValue:  "Bearer sk-test",
		HTTPClient: &http.Client{Transport: rt},
	})
	return New(Deps{
		Active:       selectedState("openai", "gpt-x", model.EffortDefault),
		Store:        store,
		Client:       client,
		Notice:       func(text string) { *notices = append(*notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})
}

// PRODUCTION PATH: the real streaming provider client on a 2xx response with no
// body records provider_request_failed{http, http_no_body}, read back from disk.
// Unlike the fake-injected body-failure tests above, this exercises the streaming
// branch of openAIClient.ChatCompletion. Reverting that branch to NewStreaming
// without the body-failure detector makes the empty body surface as
// zero_delta_stream instead, failing this test.
func TestRun_StreamingMissingBodyEmitsHTTPNoBody(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var notices []string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	})
	runner := realStreamingRunner(store, rt, &notices)

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the missing-body error from the real streaming client")
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a streaming missing-body failure; kinds = %v", eventKinds(recs))
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "http" || prf.Reason != "http_no_body" {
		t.Fatalf("(phase, reason) = (%q, %q), want (http, http_no_body)", prf.Phase, prf.Reason)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Phase != "http" || diskPRF.Reason != "http_no_body" {
		t.Fatalf("disk (phase, reason) = (%q, %q), want (http, http_no_body)", diskPRF.Phase, diskPRF.Reason)
	}
	if diskPRF.HTTPStatus == nil || *diskPRF.HTTPStatus != 200 {
		t.Fatalf("http_status = %v, want 200 (required for http_no_body)", diskPRF.HTTPStatus)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one surfaced body-failure notice", notices)
	}
}

// PRODUCTION PATH: the real streaming provider client on a 2xx body cut off before
// any assistant-content delta records provider_request_failed{http, http_truncated},
// read back from disk. Reverting the streaming branch to NewStreaming without the
// body-failure detector makes the cut-off surface as stream_drop instead, failing
// this test.
func TestRun_StreamingTruncatedBodyEmitsHTTPTruncated(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var notices []string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       &truncatedBody{data: []byte(`data: {"id":"c1"`)},
			Request:    r,
		}, nil
	})
	runner := realStreamingRunner(store, rt, &notices)

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want the truncated-body error from the real streaming client")
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a streaming truncated-body failure; kinds = %v", eventKinds(recs))
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "http" || prf.Reason != "http_truncated" {
		t.Fatalf("(phase, reason) = (%q, %q), want (http, http_truncated)", prf.Phase, prf.Reason)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Reason != "http_truncated" {
		t.Fatalf("disk reason = %q, want http_truncated", diskPRF.Reason)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one surfaced body-failure notice", notices)
	}
}

// A defensively-handled non-streamed completion with no choices emits
// provider_request_failed{empty_response, no_choices}, records no model_response or
// assistant message, and returns nil.
func TestRun_NonStreamedEmptyCompletionEmitsNoChoices(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var notices []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Completion: &openai.ChatCompletion{}}, nil
		}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil for a recorded empty completion", err)
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for an empty completion; kinds = %v", eventKinds(recs))
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded for an empty completion")
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "empty_response" || prf.Reason != "no_choices" {
		t.Fatalf("(phase, reason) = (%q, %q), want (empty_response, no_choices)", prf.Phase, prf.Reason)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Reason != "no_choices" {
		t.Fatalf("disk reason = %q, want no_choices", diskPRF.Reason)
	}

	// the non-streamed empty completion surfaces the same
	// one-line notice as the streamed path, with no hint.
	if len(notices) != 1 || !strings.Contains(notices[0], "(empty_response/no_choices)") {
		t.Fatalf("notices = %v, want one surface naming empty_response/no_choices", notices)
	}
}

// A defensively-handled non-streamed completion whose only choice carries no
// content emits provider_request_failed{empty_response, null_content}.
func TestRun_NonStreamedNullContentCompletionEmitsNullContent(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Completion: &openai.ChatCompletion{
				Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: ""}}},
			}}, nil
		}},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil for a recorded empty completion", err)
	}

	prf := findProviderRequestFailed(t, store.Records())
	if prf.Phase != "empty_response" || prf.Reason != "null_content" {
		t.Fatalf("(phase, reason) = (%q, %q), want (empty_response, null_content)", prf.Phase, prf.Reason)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Reason != "null_content" {
		t.Fatalf("disk reason = %q, want null_content", diskPRF.Reason)
	}
}

// A non-streamed completion that does carry content is an invalid response for a
// streaming request: Run returns an error and emits no provider_request_failed
// (only an empty completion is the defensively-handled empty_response case).
func TestRun_NonStreamedCompletionWithContentIsInvalid(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Completion: &openai.ChatCompletion{
				Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: "hi"}}},
			}}, nil
		}},
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want an invalid-response error for a non-streamed completion with content")
	}
	if hasKind(store.Records(), "provider_request_failed") {
		t.Fatalf("provider_request_failed emitted for a content-bearing completion; kinds = %v", eventKinds(store.Records()))
	}
}

// A pre-stream transport failure — the provider client returns a dial/TLS/decode
// error before any stream opens — is classified via ClassifyRequestError,
// emits a durable provider_request_failed with the classified phase/reason,
// surfaces a synthetic notice, and emits no model_response or assistant message.
// Removing the ClassifyRequestError branch from Run makes this fail (no event,
// no notice for an error that is neither *HTTPError nor a context cancellation).
func TestRun_PreStreamTransportErrorEmitsEvent(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	dnsErr := &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true}
	var notices []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, dnsErr
		}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: tui.RenderProviderRequestFailedNotice,
	})

	if err := runner.Run(context.Background()); !errors.Is(err, dnsErr) {
		t.Fatalf("Run() error = %v, want the DNS transport error", err)
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a pre-stream transport failure; kinds = %v", eventKinds(recs))
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded for a pre-stream transport failure")
	}
	prf := findProviderRequestFailed(t, recs)
	if prf.Phase != "dial" || prf.Reason != "dns_error" {
		t.Fatalf("(phase, reason) = (%q, %q), want (dial, dns_error)", prf.Phase, prf.Reason)
	}
	diskPRF := findProviderRequestFailed(t, diskRecords(t, store))
	if diskPRF.Phase != "dial" || diskPRF.Reason != "dns_error" {
		t.Fatalf("disk (phase, reason) = (%q, %q), want (dial, dns_error)", diskPRF.Phase, diskPRF.Reason)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one surfaced transport-failure notice", notices)
	}
	if !strings.Contains(notices[0], "no such host") {
		t.Fatalf("notice = %q, want it to include the transport error detail", notices[0])
	}
}

// A pre-stream transport failure whose provider_request_failed flush hits a real
// atomic-write error routes through the injected events.WriteFailureHandler:
// EmitProviderRequestFailed reports a non-ReasonNone WriteReason and Run must have
// passed r.deps.OnFailureWrite into it. Dropping that argument from the emit call
// makes this fail.
func TestRun_PreStreamTransportWriteFailureRoutesToHandler(t *testing.T) {
	// Parent dir is missing so the post-append flush fails with a real WriteReason.
	path := filepath.Join(t.TempDir(), "missing", "session.json")
	store := storeAt(path)
	dnsErr := &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true}
	var calls int
	var gotReason sessions.WriteReason
	var gotErr error
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, dnsErr
		}},
		OnFailureWrite: func(_ fserrors.Category, reason sessions.WriteReason, err error) {
			calls++
			gotReason = reason
			gotErr = err
		},
	})

	if err := runner.Run(context.Background()); !errors.Is(err, dnsErr) {
		t.Fatalf("Run() error = %v, want the DNS transport error to propagate", err)
	}
	if calls != 1 {
		t.Fatalf("OnFailureWrite called %d times, want exactly 1 for a flush failure", calls)
	}
	if gotReason == sessions.ReasonNone {
		t.Fatalf("OnFailureWrite reason = %v, want a real (non-ReasonNone) write reason", gotReason)
	}
	if gotErr == nil {
		t.Fatal("OnFailureWrite err = nil, want the atomic-write error")
	}
}
