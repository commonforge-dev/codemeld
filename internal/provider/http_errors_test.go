// Tests for provider HTTP-error surfacing: non-2xx status/body capture, verbatim
// (including binary) body preservation, zero-retry behavior, the provider-named
// surface prefix, and 2xx no-error behavior.
package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3/packages/ssestream"
)

func TestUnavailableUpstreamProvider(t *testing.T) {
	const together = `{"error":{"code":502,"message":"Upstream error from Together: service unavailable","metadata":{"error_type":"provider_unavailable","raw":"x"}}}`
	httpErr := func(body string) error { return &HTTPError{Status: 502, Body: body} }
	streamErr := func(body string) error { return &ssestream.StreamError{Event: ssestream.Event{Data: []byte(body)}} }
	cases := []struct {
		name     string
		provider string
		err      error
		want     string
		wantOK   bool
	}{
		{"http body", "openrouter", httpErr(together), "together", true},
		{"stream error event", "openrouter", streamErr(together), "together", true},
		{"wrapped stream error", "openrouter", fmt.Errorf("drop: %w", streamErr(together)), "together", true},
		{"digits and hyphen", "openrouter", httpErr(`{"error":{"message":"Upstream error from Deep-Infra2: x","metadata":{"error_type":"provider_unavailable"}}}`), "deep-infra2", true},
		{"non-openrouter provider", "openai", httpErr(together), "", false},
		{"other error type", "openrouter", httpErr(`{"error":{"message":"Upstream error from Together: x","metadata":{"error_type":"provider_error"}}}`), "", false},
		{"absent error type", "openrouter", httpErr(`{"error":{"message":"Upstream error from Together: x"}}`), "", false},
		{"non-string error type", "openrouter", httpErr(`{"error":{"message":"Upstream error from Together: x","metadata":{"error_type":7}}}`), "", false},
		{"malformed json", "openrouter", streamErr(`{"error":`), "", false},
		{"message without prefix", "openrouter", httpErr(`{"error":{"message":"Together: x","metadata":{"error_type":"provider_unavailable"}}}`), "", false},
		{"message without colon", "openrouter", httpErr(`{"error":{"message":"Upstream error from Together","metadata":{"error_type":"provider_unavailable"}}}`), "", false},
		{"multi-word name", "openrouter", httpErr(`{"error":{"message":"Upstream error from Google AI Studio: x","metadata":{"error_type":"provider_unavailable"}}}`), "", false},
		{"leading hyphen", "openrouter", httpErr(`{"error":{"message":"Upstream error from -together: x","metadata":{"error_type":"provider_unavailable"}}}`), "", false},
		{"unrelated error", "openrouter", errors.New("dial tcp: refused"), "", false},
		{"nil error", "openrouter", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := UnavailableUpstreamProvider(tc.provider, tc.err)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("UnavailableUpstreamProvider() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

const (
	capturedMaxPriceBody          = `{"error":{"message":"No endpoints found that satisfy the max price for this request","code":404,"metadata":{"routing_funnel":[{"step":"Initial Endpoints","endpoint_count":1}],"failed_routing_step":"Filter by Max Price"}}}`
	capturedRequireParametersBody = `{"error":{"message":"No endpoints found that can handle the requested parameters. To learn more about provider routing, visit: https://openrouter.ai/docs/guides/routing/provider-selection","code":404,"metadata":{"routing_funnel":[{"step":"Initial Endpoints","endpoint_count":1}],"failed_routing_step":"Filter by Parameters"}}}`
	routingStepBody               = `{"error":{"message":"No endpoints found","code":404,"metadata":{"failed_routing_step":%s}}}`
)

func TestIsRoutingFilterExhaustion(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"captured max_price", 404, capturedMaxPriceBody, true},
		{"captured require_parameters", 404, capturedRequireParametersBody, true},
		{"uncaptured filter step", 404, fmt.Sprintf(routingStepBody, `"Filter by Data Policy"`), true},
		{"filter step with unrelated message", 404, `{"error":{"message":"something else entirely","metadata":{"failed_routing_step":"Filter by Quantization"}}}`, true},
		{"no failed_routing_step", 404, `{"error":{"message":"No endpoints found that satisfy the max price for this request","code":404,"metadata":{"routing_funnel":[]}}}`, false},
		{"non-string step", 404, fmt.Sprintf(routingStepBody, `7`), false},
		{"empty step", 404, fmt.Sprintf(routingStepBody, `""`), false},
		{"filter prefix without name", 404, fmt.Sprintf(routingStepBody, `"Filter by "`), false},
		{"initial endpoints step", 404, fmt.Sprintf(routingStepBody, `"Initial Endpoints"`), false},
		{"other non-filter step", 404, fmt.Sprintf(routingStepBody, `"Select Provider"`), false},
		{"non-404 with filter step", 503, capturedMaxPriceBody, false},
		{"non-json body", 404, "not found", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRoutingFilterExhaustion(&HTTPError{Status: tc.status, Body: tc.body}); got != tc.want {
				t.Fatalf("isRoutingFilterExhaustion() = %v, want %v", got, tc.want)
			}
		})
	}
}

// newStubClient points a Client at a TLS stub server, counting requests so a
// test can assert no retry occurred.
func newStubClient(t *testing.T, name string, handler http.HandlerFunc) (Client, *int) {
	t.Helper()
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(ClientConfig{
		Name:       name,
		BaseURL:    srv.URL,
		AuthHeader: "Authorization",
		AuthValue:  "Bearer sk-test",
		HTTPClient: srv.Client(),
	})
	return c, &calls
}

func chatOnce(c Client) (Response, error) {
	return c.ChatCompletion(context.Background(), Request{
		Model:    "gpt-5.5",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
}

// A non-2xx response is converted to a typed *HTTPError carrying the status, the
// verbatim body, the Retry-After header (so the auto-retry engine can honor a
// 429/503's requested backoff), and a surface prefix naming the provider; the request is
// issued exactly once (no retry) for every status, including 429 and 503.
func TestChatCompletion_HTTPErrorSurface(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		body           string
		headers        map[string]string
		wantRetryAfter string
	}{
		{name: "401 with body", status: http.StatusUnauthorized, body: `{"error":{"message":"invalid api key"}}`},
		{name: "429 with retry-after", status: http.StatusTooManyRequests, body: `{"error":{"message":"rate limited"}}`, headers: map[string]string{"Retry-After": "30"}, wantRetryAfter: "30"},
		{name: "503 with retry-after", status: http.StatusServiceUnavailable, body: `{"error":{"message":"overloaded"}}`, headers: map[string]string{"Retry-After": "5"}, wantRetryAfter: "5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, calls := newStubClient(t, "openai", func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.headers {
					w.Header().Set(k, v)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})

			resp, err := chatOnce(c)
			if err == nil {
				t.Fatalf("ChatCompletion() error = nil, want *HTTPError")
			}
			if resp.Completion != nil || resp.Stream != nil {
				t.Fatalf("ChatCompletion() Response = %+v, want zero value on error", resp)
			}
			httpErr, ok := err.(*HTTPError)
			if !ok {
				t.Fatalf("ChatCompletion() error type = %T, want *HTTPError", err)
			}
			if httpErr.Status != tt.status {
				t.Fatalf("HTTPError.Status = %d, want %d", httpErr.Status, tt.status)
			}
			if httpErr.RetryAfter != tt.wantRetryAfter {
				t.Fatalf("HTTPError.RetryAfter = %q, want %q (the adapter must preserve the Retry-After header)", httpErr.RetryAfter, tt.wantRetryAfter)
			}
			if httpErr.Body != tt.body {
				t.Fatalf("HTTPError.Body = %q, want %q", httpErr.Body, tt.body)
			}
			if !strings.HasPrefix(httpErr.Surface, "provider openai returned HTTP ") {
				t.Fatalf("HTTPError.Surface = %q, want it to start with the provider-named prefix", httpErr.Surface)
			}
			if !strings.HasSuffix(httpErr.Surface, tt.body) {
				t.Fatalf("HTTPError.Surface = %q, want it to end with the verbatim body", httpErr.Surface)
			}
			if *calls != 1 {
				t.Fatalf("request count = %d, want exactly 1 (no retry)", *calls)
			}
		})
	}
}

// A 500 with a binary, invalid-UTF-8 body is preserved byte-for-byte in both
// HTTPError.Body and the suffix of HTTPError.Surface.
func TestChatCompletion_HTTPErrorPreservesBinaryBody(t *testing.T) {
	binary := []byte{0xff, 0xfe, 0x00, 0x01, 0x80, 0x7f, 0xc0}
	c, calls := newStubClient(t, "custom-provider", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(binary)
	})

	_, err := chatOnce(c)
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("ChatCompletion() error type = %T, want *HTTPError", err)
	}
	if httpErr.Status != http.StatusInternalServerError {
		t.Fatalf("HTTPError.Status = %d, want 500", httpErr.Status)
	}
	if !bytes.Equal([]byte(httpErr.Body), binary) {
		t.Fatalf("HTTPError.Body bytes = %v, want %v", []byte(httpErr.Body), binary)
	}
	surfaceBytes := []byte(httpErr.Surface)
	if got := surfaceBytes[len(surfaceBytes)-len(binary):]; !bytes.Equal(got, binary) {
		t.Fatalf("HTTPError.Surface suffix bytes = %v, want %v", got, binary)
	}
	if !strings.HasPrefix(httpErr.Surface, "provider custom-provider returned HTTP 500:") {
		t.Fatalf("HTTPError.Surface = %q, want the configured provider name in the prefix", httpErr.Surface)
	}
	if *calls != 1 {
		t.Fatalf("request count = %d, want exactly 1 (no retry)", *calls)
	}
}

// A 2xx response returns no error and no HTTPError.
func TestChatCompletion_2xxNoHTTPError(t *testing.T) {
	c, _ := newStubClient(t, "openai", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(minimalCompletionBody))
	})

	resp, err := chatOnce(c)
	if err != nil {
		t.Fatalf("ChatCompletion() error = %v, want nil", err)
	}
	if resp.Completion == nil {
		t.Fatalf("ChatCompletion() Completion = nil, want non-nil")
	}
}
