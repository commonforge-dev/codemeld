// Table tests for the transport-failure classifier: every phase x reason
// combination against representative wrapped Go errors, plus the not-classified
// pass-throughs (nil, context cancellation, *HTTPError) and an exhaustiveness
// guard against the full closed set.
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
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/openai/openai-go/v3"
)

// providerClosedSet mirrors events.providerReasons: the authoritative
// (phase -> reasons) partition the classifier must cover exhaustively. Kept here
// as a local copy because the events map is unexported; the events-side test
// validates real payloads against the live schema.
var providerClosedSet = map[string][]string{
	"dial":           {"dns_error", "connect_timeout", "connect_refused", "connect_other"},
	"tls":            {"tls_cert_invalid", "tls_cert_expired", "tls_handshake", "tls_other"},
	"http":           {"http_no_body", "http_truncated"},
	"decode":         {"decode_error"},
	"stream_drop":    {"stream_read_error", "stream_eof"},
	"empty_response": {"no_choices", "null_content", "zero_delta_stream"},
}

// timeoutErr is a net.Error whose Timeout reports true, standing in for a dial
// deadline so connect_timeout is reachable without a real network wait.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

// wrapURL nests err under a *url.Error the way net/http surfaces a failed
// request, so the classifier is exercised through the same wrapping the turn
// layer sees.
func wrapURL(err error) error {
	return &url.Error{Op: "Post", URL: "https://api.example.test/v1/chat/completions", Err: err}
}

func TestClassifyRequestError(t *testing.T) {
	syntaxErr := json.Unmarshal([]byte("not json"), &map[string]any{})
	if syntaxErr == nil {
		t.Fatal("expected a JSON syntax error to build the decode case")
	}

	cases := []struct {
		name       string
		err        error
		wantPhase  string
		wantReason string
		wantOK     bool
	}{
		{
			name:       "dns_error",
			err:        wrapURL(&net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "api.example.test", IsNotFound: true}}),
			wantPhase:  "dial",
			wantReason: "dns_error",
			wantOK:     true,
		},
		{
			name:       "connect_refused",
			err:        wrapURL(&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}),
			wantPhase:  "dial",
			wantReason: "connect_refused",
			wantOK:     true,
		},
		{
			name:       "connect_timeout",
			err:        wrapURL(&net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}),
			wantPhase:  "dial",
			wantReason: "connect_timeout",
			wantOK:     true,
		},
		{
			name:       "connect_other",
			err:        wrapURL(&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}),
			wantPhase:  "dial",
			wantReason: "connect_other",
			wantOK:     true,
		},
		{
			name:       "tls_cert_expired",
			err:        wrapURL(&tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Reason: x509.Expired, Detail: "certificate has expired"}}),
			wantPhase:  "tls",
			wantReason: "tls_cert_expired",
			wantOK:     true,
		},
		{
			name:       "tls_cert_invalid/unknown_authority",
			err:        wrapURL(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
			wantPhase:  "tls",
			wantReason: "tls_cert_invalid",
			wantOK:     true,
		},
		{
			name:       "tls_cert_invalid/hostname",
			err:        wrapURL(x509.HostnameError{Host: "api.example.test"}),
			wantPhase:  "tls",
			wantReason: "tls_cert_invalid",
			wantOK:     true,
		},
		{
			name:       "tls_cert_invalid/other_reason",
			err:        wrapURL(x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}),
			wantPhase:  "tls",
			wantReason: "tls_cert_invalid",
			wantOK:     true,
		},
		{
			name:       "tls_handshake/record_header",
			err:        wrapURL(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}),
			wantPhase:  "tls",
			wantReason: "tls_handshake",
			wantOK:     true,
		},
		{
			name:       "tls_handshake/alert",
			err:        wrapURL(tls.AlertError(40)),
			wantPhase:  "tls",
			wantReason: "tls_handshake",
			wantOK:     true,
		},
		{
			name:       "tls_other",
			err:        wrapURL(&tls.CertificateVerificationError{Err: errors.New("non-standard verification failure")}),
			wantPhase:  "tls",
			wantReason: "tls_other",
			wantOK:     true,
		},
		{
			name:       "decode_error/syntax",
			err:        fmt.Errorf("decode chat completion: %w", syntaxErr),
			wantPhase:  "decode",
			wantReason: "decode_error",
			wantOK:     true,
		},
		{
			name:       "decode_error/unexpected_eof",
			err:        fmt.Errorf("read body: %w", io.ErrUnexpectedEOF),
			wantPhase:  "decode",
			wantReason: "decode_error",
			wantOK:     true,
		},
		{name: "nil", err: nil, wantOK: false},
		{name: "context_canceled", err: context.Canceled, wantOK: false},
		{name: "context_deadline", err: fmt.Errorf("request: %w", context.DeadlineExceeded), wantOK: false},
		{name: "http_error_owned_by_g105", err: newHTTPError("openai", 429, "rate limited", ""), wantOK: false},
		{name: "unrecognized", err: errors.New("something unexpected"), wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ClassifyRequestError(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (classification %+v)", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				return
			}
			if got.Phase != tc.wantPhase || got.Reason != tc.wantReason {
				t.Fatalf("(phase, reason) = (%q, %q), want (%q, %q)", got.Phase, got.Reason, tc.wantPhase, tc.wantReason)
			}
			if got.ErrorDetail == "" {
				t.Error("error_detail is empty; the event validator requires it non-empty")
			}
			if got.HTTPStatus != nil {
				t.Errorf("http_status = %v, want nil for a non-http phase", *got.HTTPStatus)
			}
			if got.PartialResponseChars != 0 {
				t.Errorf("partial_response_chars = %d, want 0 outside stream_drop", got.PartialResponseChars)
			}
		})
	}
}

func TestClassifyStreamDrop(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		partial    int64
		wantReason string
	}{
		{"eof", io.EOF, 128, "stream_eof"},
		{"unexpected_eof", fmt.Errorf("stream: %w", io.ErrUnexpectedEOF), 64, "stream_eof"},
		{"read_error", errors.New("connection reset by peer"), 7, "stream_read_error"},
		{"read_error_zero_chars", errors.New("broken pipe"), 0, "stream_read_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyStreamDrop(tc.err, tc.partial)
			if got.Phase != "stream_drop" {
				t.Errorf("phase = %q, want stream_drop", got.Phase)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if got.PartialResponseChars != tc.partial {
				t.Errorf("partial_response_chars = %d, want %d", got.PartialResponseChars, tc.partial)
			}
			if got.HTTPStatus != nil {
				t.Errorf("http_status = %v, want nil", *got.HTTPStatus)
			}
			if got.ErrorDetail == "" {
				t.Error("error_detail is empty")
			}
		})
	}
}

func TestClassifyEmptyCompletion(t *testing.T) {
	t.Run("no_choices/nil", func(t *testing.T) {
		got, ok := ClassifyEmptyCompletion(nil)
		assertEmptyResponse(t, got, ok, "no_choices")
	})
	t.Run("no_choices/empty_slice", func(t *testing.T) {
		got, ok := ClassifyEmptyCompletion(&openai.ChatCompletion{Choices: []openai.ChatCompletionChoice{}})
		assertEmptyResponse(t, got, ok, "no_choices")
	})
	t.Run("null_content", func(t *testing.T) {
		c := &openai.ChatCompletion{Choices: []openai.ChatCompletionChoice{{
			Message: openai.ChatCompletionMessage{Content: ""},
		}}}
		got, ok := ClassifyEmptyCompletion(c)
		assertEmptyResponse(t, got, ok, "null_content")
	})
	t.Run("has_text_content", func(t *testing.T) {
		c := &openai.ChatCompletion{Choices: []openai.ChatCompletionChoice{{
			Message: openai.ChatCompletionMessage{Content: "hello"},
		}}}
		if got, ok := ClassifyEmptyCompletion(c); ok {
			t.Errorf("classified a completion with content as empty: %+v", got)
		}
	})
	t.Run("has_refusal", func(t *testing.T) {
		c := &openai.ChatCompletion{Choices: []openai.ChatCompletionChoice{{
			Message: openai.ChatCompletionMessage{Refusal: "I can't help with that"},
		}}}
		if _, ok := ClassifyEmptyCompletion(c); ok {
			t.Error("classified a refusal turn as empty_response")
		}
	})
}

func assertEmptyResponse(t *testing.T, got Classification, ok bool, wantReason string) {
	t.Helper()
	if !ok {
		t.Fatalf("ok = false, want an empty_response classification")
	}
	if got.Phase != "empty_response" {
		t.Errorf("phase = %q, want empty_response", got.Phase)
	}
	if got.Reason != wantReason {
		t.Errorf("reason = %q, want %q", got.Reason, wantReason)
	}
	if got.ErrorDetail == "" {
		t.Error("error_detail is empty")
	}
	if got.HTTPStatus != nil {
		t.Errorf("http_status = %v, want nil", *got.HTTPStatus)
	}
	if got.PartialResponseChars != 0 {
		t.Errorf("partial_response_chars = %d, want 0", got.PartialResponseChars)
	}
}

func TestEmptyStreamClassification(t *testing.T) {
	got := EmptyStreamClassification()
	if got.Phase != "empty_response" || got.Reason != "zero_delta_stream" {
		t.Errorf("(phase, reason) = (%q, %q), want (empty_response, zero_delta_stream)", got.Phase, got.Reason)
	}
	if got.ErrorDetail == "" {
		t.Error("error_detail is empty")
	}
}

func TestNoBodyHTTPFailure(t *testing.T) {
	got := NoBodyHTTPFailure(503)
	if got.Phase != "http" || got.Reason != "http_no_body" {
		t.Errorf("(phase, reason) = (%q, %q), want (http, http_no_body)", got.Phase, got.Reason)
	}
	if got.HTTPStatus == nil || *got.HTTPStatus != 503 {
		t.Errorf("http_status = %v, want 503 (required for http_no_body)", got.HTTPStatus)
	}
}

func TestTruncatedHTTPFailure(t *testing.T) {
	t.Run("with_status", func(t *testing.T) {
		s := int64(502)
		got := TruncatedHTTPFailure(&s)
		if got.Phase != "http" || got.Reason != "http_truncated" {
			t.Errorf("(phase, reason) = (%q, %q), want (http, http_truncated)", got.Phase, got.Reason)
		}
		if got.HTTPStatus == nil || *got.HTTPStatus != 502 {
			t.Errorf("http_status = %v, want 502", got.HTTPStatus)
		}
	})
	t.Run("without_status", func(t *testing.T) {
		got := TruncatedHTTPFailure(nil)
		if got.HTTPStatus != nil {
			t.Errorf("http_status = %v, want nil (optional for http_truncated)", *got.HTTPStatus)
		}
	})
}

// TestClassifierCoversClosedSet asserts the classifier emits every (phase,
// reason) in the closed set and nothing outside it, so a schema reason
// added later without a classifier path fails this test.
func TestClassifierCoversClosedSet(t *testing.T) {
	syntaxErr := json.Unmarshal([]byte("not json"), &map[string]any{})
	twoHundred := int64(500)

	produced := []Classification{
		mustClassify(t, wrapURL(&net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host"}})),
		mustClassify(t, wrapURL(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})),
		mustClassify(t, wrapURL(&net.OpError{Op: "dial", Err: timeoutErr{}})),
		mustClassify(t, wrapURL(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)})),
		mustClassify(t, wrapURL(&tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Reason: x509.Expired}})),
		mustClassify(t, wrapURL(x509.UnknownAuthorityError{})),
		mustClassify(t, wrapURL(tls.RecordHeaderError{Msg: "bad record"})),
		mustClassify(t, wrapURL(&tls.CertificateVerificationError{Err: errors.New("other")})),
		mustClassify(t, fmt.Errorf("decode: %w", syntaxErr)),
		NoBodyHTTPFailure(500),
		TruncatedHTTPFailure(&twoHundred),
		ClassifyStreamDrop(io.EOF, 1),
		ClassifyStreamDrop(errors.New("reset"), 1),
		EmptyStreamClassification(),
		mustEmpty(t, nil),
		mustEmpty(t, &openai.ChatCompletion{Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{}}}}),
	}

	covered := map[string]map[string]bool{}
	for _, c := range produced {
		reasons, ok := providerClosedSet[c.Phase]
		if !ok {
			t.Errorf("classifier produced phase %q outside the closed set", c.Phase)
			continue
		}
		if !contains(reasons, c.Reason) {
			t.Errorf("classifier produced reason %q not valid for phase %q", c.Reason, c.Phase)
			continue
		}
		if covered[c.Phase] == nil {
			covered[c.Phase] = map[string]bool{}
		}
		covered[c.Phase][c.Reason] = true
	}

	for phase, reasons := range providerClosedSet {
		for _, reason := range reasons {
			if !covered[phase][reason] {
				t.Errorf("no classifier path produces (phase=%q, reason=%q)", phase, reason)
			}
		}
	}
}

func mustClassify(t *testing.T, err error) Classification {
	t.Helper()
	got, ok := ClassifyRequestError(err)
	if !ok {
		t.Fatalf("ClassifyRequestError(%v) returned ok=false", err)
	}
	return got
}

func mustEmpty(t *testing.T, c *openai.ChatCompletion) Classification {
	t.Helper()
	got, ok := ClassifyEmptyCompletion(c)
	if !ok {
		t.Fatalf("ClassifyEmptyCompletion returned ok=false")
	}
	return got
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// status returns a pointer to n for the HTTPStatus field, so the Retryable table
// can express present-vs-absent status without a helper per row.
func statusPtr(n int64) *int64 { return &n }

// TestRetryable pins the auto-retry taxonomy: stream_drop (incl. partial),
// every dial reason, the recoverable TLS handshake/other failures, every
// empty_response reason, and http 429/500/502/503/504 are transient and retried;
// the bad-cert TLS reasons, decode, 4xx (and other non-set) http statuses, and the
// 2xx-with-bad-body http_no_body/http_truncated cases surface immediately.
func TestRetryable(t *testing.T) {
	cases := []struct {
		name  string
		class Classification
		want  bool
	}{
		{"stream_drop/read_error", Classification{Phase: "stream_drop", Reason: "stream_read_error"}, true},
		{"stream_drop/eof", Classification{Phase: "stream_drop", Reason: "stream_eof"}, true},
		{"stream_drop/partial", Classification{Phase: "stream_drop", Reason: "stream_read_error", PartialResponseChars: 42}, true},
		{"dial/dns_error", Classification{Phase: "dial", Reason: "dns_error"}, true},
		{"dial/connect_timeout", Classification{Phase: "dial", Reason: "connect_timeout"}, true},
		{"dial/connect_refused", Classification{Phase: "dial", Reason: "connect_refused"}, true},
		{"dial/connect_other", Classification{Phase: "dial", Reason: "connect_other"}, true},
		{"tls/tls_handshake", Classification{Phase: "tls", Reason: "tls_handshake"}, true},
		{"tls/tls_other", Classification{Phase: "tls", Reason: "tls_other"}, true},
		{"tls/tls_cert_invalid", Classification{Phase: "tls", Reason: "tls_cert_invalid"}, false},
		{"tls/tls_cert_expired", Classification{Phase: "tls", Reason: "tls_cert_expired"}, false},
		{"empty_response/no_choices", Classification{Phase: "empty_response", Reason: "no_choices"}, true},
		{"empty_response/null_content", Classification{Phase: "empty_response", Reason: "null_content"}, true},
		{"empty_response/zero_delta_stream", Classification{Phase: "empty_response", Reason: "zero_delta_stream"}, true},
		{"decode/decode_error", Classification{Phase: "decode", Reason: "decode_error"}, false},
		{"http/429", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(429)}, true},
		{"http/500", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(500)}, true},
		{"http/502", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(502)}, true},
		{"http/503", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(503)}, true},
		{"http/504", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(504)}, true},
		{"http/400", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(400)}, false},
		{"http/401", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(401)}, false},
		{"http/403", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(403)}, false},
		{"http/404", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(404)}, false},
		{"http/408_not_in_set", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(408)}, false},
		{"http/501_not_in_set", Classification{Phase: "http", Reason: "http_error", HTTPStatus: statusPtr(501)}, false},
		{"http/no_body_200", Classification{Phase: "http", Reason: "http_no_body", HTTPStatus: statusPtr(200)}, false},
		{"http/truncated_nil_status", Classification{Phase: "http", Reason: "http_truncated"}, false},
		{"http/error_missing_status", Classification{Phase: "http", Reason: "http_error"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Retryable(tc.class); got != tc.want {
				t.Fatalf("Retryable(%+v) = %v, want %v", tc.class, got, tc.want)
			}
		})
	}
}
