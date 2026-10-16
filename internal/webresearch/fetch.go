package webresearch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const maxRedirects = 10

const maxFinalURLBytes = 2048

const (
	OutcomeOK                 = "ok"
	OutcomeRequestFailed      = "request_failed"
	OutcomeResponseTooLarge   = "response_too_large"
	OutcomeUnsupportedContent = "unsupported_content"
	OutcomeExtractionFailed   = "extraction_failed"
)

type FetchResult struct {
	FinalURL string `json:"final_url,omitempty"`
	Content  string `json:"content,omitempty"`
	Outcome  string `json:"outcome"`
}

type Target struct {
	Host              string
	Scheme            string
	Port              string
	URL               string
	FreshConfirmation bool
}

// Authorizer decides one Target before its request is built. Any non-nil error,
// whether a denial or an undecidable request, means nothing is sent.
type Authorizer func(ctx context.Context, target Target) error

// fetch stays package-private: its raw response carries an unbounded body past
// the egress boundary, so FetchText is the only way out of this package.
func fetch(ctx context.Context, client *http.Client, rawURL string, authorize Authorizer) (*http.Response, error) {
	if client == nil {
		return nil, errors.New("webresearch: no HTTP client")
	}
	if authorize == nil {
		return nil, errors.New("webresearch: no authorization callback")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("webresearch: invalid URL")
	}
	first, target, err := admit(parsed, nil)
	if err != nil {
		return nil, err
	}
	plaintext := target.Scheme == "http"
	if err := authorize(ctx, target); err != nil {
		return nil, fmt.Errorf("webresearch: %s not authorized: %w", target.Host, err)
	}
	noFollow := withoutAutoRedirects(client)
	if plaintext {
		// Authorization for a direct HTTP target covers its initial HTTPS attempt.
		secure, secureTarget := overHTTPS(first, target)
		if resp, err := follow(ctx, noFollow, secure, secureTarget, authorize, false); err == nil {
			return resp, nil
		}
	}
	return follow(ctx, noFollow, first, target, authorize, plaintext)
}

func FetchText(ctx context.Context, client *http.Client, rawURL string, authorize Authorizer, outputCap int) FetchResult {
	if outputCap <= 0 || outputCap > math.MaxInt/2 {
		return FetchResult{Outcome: OutcomeRequestFailed}
	}
	resp, err := fetch(ctx, client, rawURL, authorize)
	if err != nil || resp == nil {
		return FetchResult{Outcome: OutcomeRequestFailed}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusMultipleChoices-1 {
		return FetchResult{Outcome: OutcomeRequestFailed}
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !admittedMediaType(mediaType) {
		return FetchResult{Outcome: OutcomeUnsupportedContent}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(2*outputCap)+1))
	if err != nil {
		return FetchResult{Outcome: OutcomeRequestFailed}
	}
	if len(body) > 2*outputCap {
		return FetchResult{Outcome: OutcomeResponseTooLarge}
	}
	content, err := extractText(mediaType, body, outputCap)
	if err != nil {
		return FetchResult{Outcome: OutcomeExtractionFailed}
	}
	return FetchResult{
		FinalURL: displayURL(resp.Request.URL),
		Content:  content,
		Outcome:  OutcomeOK,
	}
}

// AdmissibleHTTPS reports whether raw names an HTTPS target FetchText would admit, returning
// its canonical credential-redacted form. A caller that surfaces a URL before any fetch runs it
// through here so it cannot offer a target the fetch path would later refuse. The result is never
// length-bounded: a cut through a percent escape names a different target or no valid URL at all,
// so a caller with a field limit must drop an over-long candidate rather than truncate it.
func AdmissibleHTTPS(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return "", false
	}
	dial, _, err := admit(parsed, nil)
	if err != nil {
		return "", false
	}
	return dial.Redacted(), true
}

func displayURL(u *url.URL) string {
	return truncateUTF8(u.Redacted(), maxFinalURLBytes)
}

func admittedMediaType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "text/") || mediaType == "application/json" ||
		mediaType == "application/xml" || mediaType == "application/xhtml+xml"
}

func follow(ctx context.Context, noFollow *http.Client, next *url.URL, target Target, authorize Authorizer, allowHTTP bool) (*http.Response, error) {
	for hop := 0; ; hop++ {
		resp, err := issue(ctx, noFollow, next, target.Host)
		if err != nil {
			return nil, err
		}
		if !isRedirect(resp.StatusCode) {
			return resp, nil
		}
		location := resp.Header.Get("Location")
		_ = resp.Body.Close()
		if location == "" {
			return nil, fmt.Errorf("webresearch: %d redirect from %s has no location", resp.StatusCode, target.Host)
		}
		if hop == maxRedirects {
			return nil, fmt.Errorf("webresearch: more than %d redirects", maxRedirects)
		}
		ref, err := url.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("webresearch: invalid redirect location from %s", target.Host)
		}
		prev := target
		if next, target, err = admit(next.ResolveReference(ref), &prev); err != nil {
			return nil, err
		}
		if target.Scheme == "http" && !allowHTTP {
			return nil, fmt.Errorf("webresearch: refused an http redirect from %s", prev.Host)
		}
		if err := authorize(ctx, target); err != nil {
			return nil, fmt.Errorf("webresearch: %s not authorized: %w", target.Host, err)
		}
	}
}

func overHTTPS(u *url.URL, target Target) (*url.URL, Target) {
	secure := *u
	secure.Scheme = "https"
	target.Scheme = "https"
	if u.Port() == "" {
		target.Port = "443"
	}
	target.URL = displayURL(&secure)
	return &secure, target
}

func issue(ctx context.Context, client *http.Client, u *url.URL, host string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("webresearch: cannot build a request for %s", host)
	}
	resp, err := client.Do(req)
	if err != nil {
		// url.Error repeats the full URL, which may carry query credentials.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, &transportFailure{host: host, err: err}
	}
	if resp.Request == nil {
		resp.Request = req
	}
	return resp, nil
}

// transportFailure keeps the underlying error reachable through errors.Is while
// leaving its arbitrary-length text out of the message that reaches tool output.
type transportFailure struct {
	host string
	err  error
}

func (f *transportFailure) Error() string {
	return "webresearch: request to " + f.host + " failed"
}

func (f *transportFailure) Unwrap() error { return f.err }

// admit refuses a URL the transport must not dial and returns the authorization
// Target beside a copy of u whose host is rewritten to the canonical form, so the
// request goes to exactly the host that was authorized. prev is the preceding hop
// when u is a redirect target.
func admit(u *url.URL, prev *Target) (*url.URL, Target, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, Target{}, errors.New("webresearch: unsupported URL scheme")
	}
	// The refusals here must not repeat any part of the URL: a caller can hand
	// Fetch an arbitrarily long scheme, host label, or port, and that text would
	// otherwise flow out as tool error output.
	host, err := canonicalHost(u.Hostname())
	if err != nil {
		return nil, Target{}, errors.New("webresearch: invalid URL host")
	}
	// A literal the dialer would refuse anyway is stopped here so it is never
	// offered at the permission prompt.
	if addr, addrErr := netip.ParseAddr(host); addrErr == nil && mustNotDial(addr) {
		return nil, Target{}, errors.New("webresearch: refused a non-public destination")
	}
	// url.Parse rejects an authority whose explicit port is not numeric, so an
	// empty u.Port() means the port was omitted, never that it was malformed.
	explicitPort := u.Port()
	if explicitPort != "" {
		number, convErr := strconv.Atoi(explicitPort)
		if convErr != nil || number < 1 || number > 65535 {
			return nil, Target{}, errors.New("webresearch: invalid URL port")
		}
		explicitPort = strconv.Itoa(number)
	}
	standard := "80"
	if scheme == "https" {
		standard = "443"
	}
	port := explicitPort
	if port == "" {
		port = standard
	}
	target := Target{Host: host, Scheme: scheme, Port: port}
	if prev != nil {
		target.FreshConfirmation = target.Scheme != prev.Scheme || target.Port != prev.Port
	} else {
		target.FreshConfirmation = port != standard
	}
	dial := *u
	dial.Scheme = scheme
	dial.Host = hostport(host, explicitPort)
	target.URL = displayURL(&dial)
	return &dial, target, nil
}

func hostport(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

// canonicalHost mirrors permissions.CanonicalHost so a target matches an
// exact-host grant, without importing permission orchestration here. Keep the
// two in step.
func canonicalHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("host is empty")
	}
	if host == "*" {
		return "", errors.New(`wildcard host "*" is not allowed`)
	}
	trimmed := strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String(), nil
	}
	return hostProfile.ToASCII(trimmed)
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// withoutAutoRedirects copies the caller's client so a 3xx comes back unfollowed
// and Fetch can authorize the next target before requesting it.
func withoutAutoRedirects(client *http.Client) *http.Client {
	pinned := *client
	pinned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &pinned
}
