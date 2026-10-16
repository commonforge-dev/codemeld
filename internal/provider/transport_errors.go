// Classifies wrapped provider transport/TLS/decode/stream-drop/empty-response
// failures into the provider_request_failed (phase, reason) closed set.
// Pure classification only: it never emits an event and stays
// independent of internal/events, so the turn layer hands the result to
// events.EmitProviderRequestFailed and tui.RenderProviderRequestFailedNotice.
package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"github.com/openai/openai-go/v3"
)

// Classification is the provider_request_failed tuple a transport, TLS
// decode, stream-drop, or empty-response failure maps to. Its fields line up
// one-to-one with events.EmitProviderRequestFailed's arguments: HTTPStatus is
// non-nil only for the http phase (required for http_no_body, optional for
// http_truncated, forbidden elsewhere); PartialResponseChars is meaningful only
// for stream_drop; ErrorDetail is always the diagnostic message and is never
// empty so the event validator accepts it.
type Classification struct {
	Phase                string
	Reason               string
	HTTPStatus           *int64
	PartialResponseChars int64
	ErrorDetail          string
}

// retryableHTTPStatuses are the HTTP statuses classified as transient and
// safe to auto-retry: rate limiting (429) and the gateway/availability 5xx family.
// Every other status — notably the 4xx client errors — is deterministic and is
// surfaced immediately.
var retryableHTTPStatuses = map[int64]bool{429: true, 500: true, 502: true, 503: true, 504: true}

// Retryable reports whether a classified provider failure is transient and should
// be auto-retried. The retryable population is a dropped TCP/TLS
// connection (stream_drop, including a partial drop), a dial failure
// (dns/timeout/refused/other), a recoverable TLS handshake/other failure, an empty
// response (no_choices/null_content/zero_delta_stream), and an http response with a
// 429/500/502/503/504 status. Deterministic, user-actionable failures are never
// retried: a 4xx http response, an invalid/expired TLS certificate, a decode error,
// and the 2xx-with-bad-body http_no_body/http_truncated cases (their status is the
// 2xx that was received, so they fall outside the retry-status set). A
// CredentialUnavailableError and a context cancellation never become a
// Classification, so the turn layer handles them and they are never seen here.
func Retryable(c Classification) bool {
	switch c.Phase {
	case "stream_drop", "dial", "empty_response":
		return true
	case "tls":
		return c.Reason == "tls_handshake" || c.Reason == "tls_other"
	case "http":
		return c.HTTPStatus != nil && retryableHTTPStatuses[*c.HTTPStatus]
	default: // "decode" and any future phase: surface immediately
		return false
	}
}

// ClassifyRequestError maps the error returned by a non-streaming
// ChatCompletion call (or the initial Stream open) to a dial, tls, or decode
// classification. It reports false — leaving the caller to handle it elsewhere
// — when err is nil, a context cancellation/deadline (user interrupt or the
// turn deadline, never a provider_request_failed), or an *HTTPError (a real
// non-2xx response the turn layer handles directly, emitting
// provider_request_failed{http, http_error} rather than routing it
// through this transport classifier).
// TLS is checked before the generic connection buckets so a handshake failure
// wrapped in a *url.Error/*net.OpError is not mislabeled as a dial failure.
func ClassifyRequestError(err error) (Classification, bool) {
	if err == nil {
		return Classification{}, false
	}
	// Context cancellation and deadline are not transport failures: the turn
	// layer decides whether it was a user interrupt (stream_interrupted) or
	// its own deadline. A real network dial timeout surfaces as a
	// net.Error i/o timeout below, not as context.DeadlineExceeded.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Classification{}, false
	}
	// A non-2xx provider response is surfaced verbatim as an *HTTPError and persisted as
	// provider_request_failed{http, http_error} directly in the turn layer,
	// so this classifier leaves it alone rather than mapping it to a transport reason.
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return Classification{}, false
	}

	if reason, ok := classifyTLS(err); ok {
		return Classification{Phase: "tls", Reason: reason, ErrorDetail: err.Error()}, true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return Classification{Phase: "dial", Reason: "dns_error", ErrorDetail: err.Error()}, true
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return Classification{Phase: "dial", Reason: "connect_refused", ErrorDetail: err.Error()}, true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Classification{Phase: "dial", Reason: "connect_timeout", ErrorDetail: err.Error()}, true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Connection reset, network/host unreachable, and other dial/connect
		// syscall failures that are neither refused nor timed out.
		return Classification{Phase: "dial", Reason: "connect_other", ErrorDetail: err.Error()}, true
	}

	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return Classification{Phase: "decode", Reason: "decode_error", ErrorDetail: err.Error()}, true
	}

	return Classification{}, false
}

// classifyTLS returns the tls reason for a TLS/x509 failure and whether
// err is a TLS-phase failure at all. Certificate expiry (or not-yet-valid,
// which x509 also reports as Expired) maps to tls_cert_expired; every other
// certificate-validation failure maps to tls_cert_invalid; a record-layer or
// alert handshake failure maps to tls_handshake; any remaining verification
// failure maps to tls_other. The cert/expired split is the upstream signal the
// hint table keys on, so it must not be conflated.
func classifyTLS(err error) (string, bool) {
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		if certInvalid.Reason == x509.Expired {
			return "tls_cert_expired", true
		}
		return "tls_cert_invalid", true
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return "tls_cert_invalid", true
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "tls_cert_invalid", true
	}
	var constraintErr x509.ConstraintViolationError
	if errors.As(err, &constraintErr) {
		return "tls_cert_invalid", true
	}
	var recordHeaderErr tls.RecordHeaderError
	if errors.As(err, &recordHeaderErr) {
		return "tls_handshake", true
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return "tls_handshake", true
	}
	// A certificate-verification wrapper whose inner error is not one of the
	// x509 types above (those unwrap through it and are caught earlier): a TLS
	// failure that is neither a recognized cert nor handshake error.
	var certVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &certVerifyErr) {
		return "tls_other", true
	}
	return "", false
}

// ClassifyStreamDrop maps a mid-stream failure — the stream's final error after
// the turn layer has counted partialResponseChars assistant-content characters
// — to a stream_drop classification. A clean or unexpected EOF maps to
// stream_eof; any other read error maps to stream_read_error. The helper does
// not count characters or infer transcript state itself; partialResponseChars
// is supplied by the caller and must be >= 0. err must be non-nil (a clean
// close with no content is EmptyStreamClassification, not a drop).
func ClassifyStreamDrop(err error, partialResponseChars int64) Classification {
	reason := "stream_read_error"
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		reason = "stream_eof"
	}
	return Classification{
		Phase:                "stream_drop",
		Reason:               reason,
		PartialResponseChars: partialResponseChars,
		ErrorDetail:          err.Error(),
	}
}

// ClassifyEmptyCompletion inspects a 2xx non-streamed completion the SDK decoded
// successfully and reports an empty_response classification when it carries no
// usable assistant output: no_choices for an absent/empty choices list,
// null_content for a present first choice whose message has no content, refusal,
// or tool calls. It reports false when the completion does carry usable output,
// so a legitimate refusal or tool-call turn is never mistaken for a failure.
func ClassifyEmptyCompletion(c *openai.ChatCompletion) (Classification, bool) {
	if c == nil || len(c.Choices) == 0 {
		return Classification{
			Phase:       "empty_response",
			Reason:      "no_choices",
			ErrorDetail: "provider returned a completion with no choices",
		}, true
	}
	msg := c.Choices[0].Message
	if msg.Content == "" && msg.Refusal == "" && len(msg.ToolCalls) == 0 {
		return Classification{
			Phase:       "empty_response",
			Reason:      "null_content",
			ErrorDetail: "provider returned a choice with no message content",
		}, true
	}
	return Classification{}, false
}

// EmptyStreamClassification returns the empty_response/zero_delta_stream
// classification for a stream that closed cleanly (no error) without ever
// emitting an assistant-content delta.
func EmptyStreamClassification() Classification {
	return Classification{
		Phase:       "empty_response",
		Reason:      "zero_delta_stream",
		ErrorDetail: "provider stream closed without any assistant content delta",
	}
}

// HTTPBodyError reports a 2xx provider response whose body could not be consumed
// as a usable completion: Truncated is false when a status line arrived but the
// body was absent (http_no_body) and true when the body was cut off mid-transfer
// (http_truncated). Status is the received HTTP status line. It is the seam
// between the provider client (which detects the condition at the transport, the
// only place the status survives the SDK's body read) and the turn layer (which
// maps it to NoBodyHTTPFailure/TruncatedHTTPFailure and emits the event). It is
// distinct from *HTTPError: a non-2xx response stays on the verbatim path
// and never becomes an HTTPBodyError.
//
// Err is the underlying transport read error on the streaming path, where the
// failure surfaces from the SSE body reader rather than a buffered read; it is
// exposed via Unwrap so a truncation that followed partial assistant content can
// still be classified as a stream_drop with its original io.EOF/ErrUnexpectedEOF
// fidelity. It is nil on the non-streaming path, where the status is enough.
type HTTPBodyError struct {
	Status    int
	Truncated bool
	Err       error
}

func (e *HTTPBodyError) Error() string {
	if e.Truncated {
		return fmt.Sprintf("provider returned HTTP %d with a truncated response body", e.Status)
	}
	return fmt.Sprintf("provider returned HTTP %d with no response body", e.Status)
}

// Unwrap exposes the underlying streaming transport error (nil on the
// non-streaming path) so errors.Is against io.EOF/io.ErrUnexpectedEOF still works.
func (e *HTTPBodyError) Unwrap() error { return e.Err }

// NoBodyHTTPFailure returns the http/http_no_body classification for a provider
// response whose status line arrived but whose body was absent. The status is
// required by for this reason (it is what the hint table keys
// on), so it is taken as a plain int and always recorded.
func NoBodyHTTPFailure(status int64) Classification {
	s := status
	return Classification{
		Phase:       "http",
		Reason:      "http_no_body",
		HTTPStatus:  &s,
		ErrorDetail: fmt.Sprintf("provider returned HTTP %d with no response body", status),
	}
}

// TruncatedHTTPFailure returns the http/http_truncated classification for a
// response body cut off mid-transfer. The status is optional per —
// present when a status line was received before the truncation, nil otherwise.
func TruncatedHTTPFailure(status *int64) Classification {
	return Classification{
		Phase:       "http",
		Reason:      "http_truncated",
		HTTPStatus:  status,
		ErrorDetail: "provider response body was truncated before completion",
	}
}
