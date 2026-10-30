// Typed surfacing of provider non-2xx chat-completions responses: HTTPError
// carries the status, the raw response body text, and a one-line human-readable
// surface string used as the Go error text. Provider adapters do not
// retry: each non-2xx response is surfaced as an HTTPError, and the turn layer
// owns any classification-driven retry policy (e.g. honoring RetryAfter).
// The TUI no longer renders Surface directly: the on-screen line-1 message is the
// friendly text from FriendlyHTTPMessage, while the provider package
// stays independent of internal/events and the turn layer persists the body text
// as provider_request_failed{http, http_error} (superseding the earlier rule that
// an HTTP error emits no event).
package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openai/openai-go/v3/packages/ssestream"
)

var (
	upstreamErrorMessage = regexp.MustCompile(`^Upstream error from ([^:]+):`)
	upstreamProviderSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

func UnavailableUpstreamProvider(providerID string, err error) (string, bool) {
	if providerID != openRouterProviderID {
		return "", false
	}
	var body []byte
	var httpErr *HTTPError
	var streamErr *ssestream.StreamError
	switch {
	case errors.As(err, &httpErr):
		body = []byte(httpErr.Body)
	case errors.As(err, &streamErr):
		body = streamErr.Event.Data
	default:
		return "", false
	}
	var parsed struct {
		Error struct {
			Message  string `json:"message"`
			Metadata struct {
				ErrorType string `json:"error_type"`
			} `json:"metadata"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil || parsed.Error.Metadata.ErrorType != "provider_unavailable" {
		return "", false
	}
	match := upstreamErrorMessage.FindStringSubmatch(parsed.Error.Message)
	if match == nil {
		return "", false
	}
	slug := strings.ToLower(match[1])
	if !upstreamProviderSlug.MatchString(slug) {
		return "", false
	}
	return slug, true
}

type RoutingExhaustionError struct {
	Model              string
	MaxPrice           MaxPrice
	DataCollectionDeny bool
	RequireParameters  bool
	Ignore             []string
	Quantization       Quantization
	HTTP               *HTTPError
}

func (e *RoutingExhaustionError) Error() string { return e.HTTP.Error() }

func (e *RoutingExhaustionError) Unwrap() error { return e.HTTP }

func isRoutingFilterExhaustion(e *HTTPError) bool {
	if e.Status != 404 {
		return false
	}
	var parsed struct {
		Error struct {
			Metadata struct {
				FailedRoutingStep string `json:"failed_routing_step"`
			} `json:"metadata"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(e.Body), &parsed) != nil {
		return false
	}
	suffix, ok := strings.CutPrefix(parsed.Error.Metadata.FailedRoutingStep, "Filter by ")
	return ok && suffix != ""
}

// redactedPlaceholder replaces a credential or credential-derived value removed
// from an HTTP-error body, surface, or notice.
const redactedPlaceholder = "[REDACTED]"

// redactCredentials removes each non-empty secret from s, replacing every
// occurrence with redactedPlaceholder. It is used by credentialed providers (the
// OpenAI ChatGPT adapter) to scrub locally held tokens and credential-derived
// values out of a provider response body before it becomes an HTTPError.Body /
// Surface or a FriendlyHTTPMessage, so a provider that echoes the bearer token or
// account id can never leak it. An empty secret is
// skipped so it cannot match — and blank out — the whole string.
func redactCredentials(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, redactedPlaceholder)
		}
	}
	return s
}

// HTTPError is a provider chat-completions response with a non-2xx HTTP status.
// Body holds the response body as received from the HTTP client: it is a Go
// string so arbitrary bytes, including invalid UTF-8 and binary payloads, can be
// carried to the notice path. Surface is a one-line human-readable prefix naming
// the provider and status followed by Body; it is the Go error text, no
// longer the direct on-screen TUI line — the notice path renders the friendly
// FriendlyHTTPMessage instead. Body is the source the friendly extractor
// parses. Every non-2xx status — including 429/503 quota/rate-limit responses
// — flows through this single path; no retry or throttle branching occurs. The
// turn layer persists Body through provider_request_failed{http, http_error},
// where the event append layer applies UTF-8 normalization before
// storage, but still sends no rate-limit signal to the scheduler.
type HTTPError struct {
	Status  int
	Body    string
	Surface string
	// RetryAfter is the verbatim Retry-After response-header value when the
	// provider sent one (a delta-seconds count or an HTTP-date), or "" when
	// absent. It is carried — unlike the rest of the response headers, which the
	// typed error drops — so the auto-retry engine can honor a 429/503's requested
	// backoff. It is never persisted: only Body becomes the durable
	// provider_request_failed error_detail.
	RetryAfter string
}

// Error returns the surface text so an HTTPError prints verbatim wherever a Go
// error value is logged or formatted.
func (e *HTTPError) Error() string { return e.Surface }

// newHTTPError builds an HTTPError for a provider's non-2xx response. The
// surface is the one-line prefix "provider <name> returned HTTP <status>:"
// followed by the body, so the body forms the exact suffix of Surface.
// retryAfter is the response's Retry-After header value (or "" when absent),
// preserved for the auto-retry delay override.
func newHTTPError(name string, status int, body, retryAfter string) *HTTPError {
	surface := fmt.Sprintf("provider %s returned HTTP %d: %s", name, status, body)
	return &HTTPError{Status: status, Body: body, Surface: surface, RetryAfter: retryAfter}
}
