// Tests for the safe direct-fetch transport: URL admission before any dial,
// canonical-host authorization ordering, and redirect targets that must be
// authorized — with a fresh-confirmation marker on a scheme or port change —
// before their request is issued.
package webresearch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

var errDenied = errors.New("denied by the user")

// trace records, in order, every authorization call and every request the
// transport actually attempted, so a test can prove one happened before the
// other and that a refusal dialed nothing.
type trace struct {
	events  []string
	targets []Target
}

func (tr *trace) authorizer(decide func(Target) error) Authorizer {
	return func(_ context.Context, target Target) error {
		tr.events = append(tr.events, "auth "+origin(target))
		tr.targets = append(tr.targets, target)
		if decide == nil {
			return nil
		}
		return decide(target)
	}
}

func (tr *trace) client(respond func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		tr.events = append(tr.events, "req "+r.URL.String())
		if respond == nil {
			return response(http.StatusOK, ""), nil
		}
		return respond(r)
	})}
}

func (tr *trace) requests() []string {
	out := []string{}
	for _, e := range tr.events {
		if after, ok := strings.CutPrefix(e, "req "); ok {
			out = append(out, after)
		}
	}
	return out
}

func origin(t Target) string { return t.Scheme + "://" + t.Host + ":" + t.Port }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, location string) *http.Response {
	header := http.Header{}
	if location != "" {
		header.Set("Location", location)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(""))}
}

// redirectOnce answers first with a 302 to location (omitting the header when
// location is empty) and answers every other URL with 200.
func redirectOnce(first, location string) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == first {
			return response(http.StatusFound, location), nil
		}
		return response(http.StatusOK, ""), nil
	}
}

var errNoTLS = errors.New("connection refused")

const dialSecret = "s3cret-dial-detail"

var errOversizedDial = errors.New(strings.Repeat("transport detail ", 64) + dialSecret)

func withoutHTTPS(secure string, respond func(*http.Request) (*http.Response, error)) func(*http.Request) (*http.Response, error) {
	return func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == secure {
			return nil, errNoTLS
		}
		if respond == nil {
			return response(http.StatusOK, ""), nil
		}
		return respond(r)
	}
}

const maxRefusalBytes = 120

func TestFetch_RefusesInadmissibleURLBeforeAnyRequest(t *testing.T) {
	cases := map[string]string{
		"malformed syntax":      "http://exa mple.com/",
		"host-less":             "http:///only/a/path",
		"relative":              "/only/a/path",
		"opaque":                "http:example.com",
		"empty":                 "",
		"file scheme":           "file:///etc/passwd",
		"ftp scheme":            "ftp://files.example.com/x",
		"javascript scheme":     "javascript:alert(1)",
		"wildcard host":         "https://*/",
		"non-numeric port":      "https://docs.example.com:bad/",
		"trailing port garbage": "http://docs.example.com:80x/",
		"ipv6 non-numeric port": "https://[2001:db8::1]:bad/",
		"port out of range":     "https://docs.example.com:99999/",
		"zero port":             "https://docs.example.com:0/",
		"oversized scheme":      strings.Repeat("a", 4096) + "://docs.example.com/",
		"oversized port":        "https://docs.example.com:" + strings.Repeat("9", 4096) + "/",
		"oversized host label":  "https://" + strings.Repeat("a", 4096) + ".example/",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(nil), raw, tr.authorizer(nil))
			if err == nil {
				resp.Body.Close()
				t.Fatalf("fetch(%.80q) accepted an inadmissible URL, want a refusal", raw)
			}
			if got := len(err.Error()); got > maxRefusalBytes {
				t.Fatalf("fetch(%.80q) refused with a %d-byte error, want at most %d and no URL text repeated", raw, got, maxRefusalBytes)
			}
			if len(tr.events) != 0 {
				t.Fatalf("fetch(%.80q) refused but recorded %v, want nothing authorized or requested", raw, tr.events)
			}
		})
	}
}

func TestFetchText_RefusesUnsafeLiteralBeforeTheAuthorizer(t *testing.T) {
	for _, host := range []string{
		"[::ffff:127.0.0.1]", "[::1]", "[::]", "0.0.0.0", "0.0.0.1",
		"169.254.169.254", "169.254.170.2", "100.100.100.200",
		"10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1",
		"198.18.0.1", "240.0.0.1", "[fc00::1]", "[fe80::1]",
	} {
		bare := strings.Trim(host, "[]")
		for _, authority := range []string{host, host + ":8443"} {
			raw := "https://" + authority + "/probe"
			t.Run(raw, func(t *testing.T) {
				tr := &trace{}
				got := FetchText(context.Background(), tr.client(nil), raw, tr.authorizer(nil), 4096)
				if got.Outcome != OutcomeRequestFailed || got.Content != "" || got.FinalURL != "" {
					t.Fatalf("FetchText(%q) = %+v, want only the %q outcome", raw, got, OutcomeRequestFailed)
				}
				if len(tr.events) != 0 {
					t.Fatalf("FetchText(%q) recorded %v, want nothing authorized and nothing dialed", raw, tr.events)
				}

				tr = &trace{}
				resp, err := fetch(context.Background(), tr.client(nil), raw, tr.authorizer(nil))
				if err == nil {
					resp.Body.Close()
					t.Fatalf("fetch(%q) accepted a non-public destination, want a refusal", raw)
				}
				if len(tr.events) != 0 {
					t.Fatalf("fetch(%q) recorded %v, want nothing authorized and nothing dialed", raw, tr.events)
				}
				for _, leak := range []string{bare, "8443", "probe"} {
					if strings.Contains(err.Error(), leak) {
						t.Fatalf("fetch(%q) refused with %q, want no part of the URL repeated", raw, err)
					}
				}
				if len(err.Error()) > maxRefusalBytes {
					t.Fatalf("fetch(%q) refused with a %d-byte error, want at most %d", raw, len(err.Error()), maxRefusalBytes)
				}
			})
		}
	}
}

func TestFetchText_RefusesAGrantedHostThatResolvesToALoopbackAddress(t *testing.T) {
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "the local body")
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", server.URL, err)
	}
	raw := "http://localhost:" + port + "/page"

	tr := &trace{}
	client := &http.Client{Transport: &http.Transport{DialContext: GuardedDialContext}}
	got := FetchText(context.Background(), client, raw, tr.authorizer(nil), 4096)

	if got.Outcome != OutcomeRequestFailed || got.Content != "" || got.FinalURL != "" {
		t.Fatalf("FetchText(%q) = %+v, want only the %q outcome", raw, got, OutcomeRequestFailed)
	}
	if len(tr.targets) == 0 {
		t.Fatalf("FetchText(%q) authorized nothing, want a hostname target to reach the grant it then fails to use", raw)
	}
	if hit := served.Load(); hit != 0 {
		t.Fatalf("loopback server served %d requests, want 0 — the grant must not carry past the address guard", hit)
	}
}

// Only what net.ParseIP accepts is a literal, so these spellings stay hostnames through
// admit and meet the guard at their resolved address instead.
func TestFetch_NonstandardNumericHostsStayHostnameShaped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		host    string
		resolve string
	}{
		{"octal", "0177.0.0.1", "127.0.0.1"},
		{"decimal", "2130706433", "127.0.0.1"},
		{"resolver alias", "127.0.0.1.nip.io", "127.0.0.1"},
		{"metadata name", "metadata.google.internal", "169.254.169.254"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trace{}
			raw := "https://" + tc.host + "/x"
			resp, err := fetch(context.Background(), tr.client(nil), raw, tr.authorizer(nil))
			if err != nil {
				t.Fatalf("fetch(%q) = %v, want a hostname-shaped host to reach authorization", raw, err)
			}
			resp.Body.Close()
			want := Target{Host: tc.host, Scheme: "https", Port: "443", URL: raw}
			if !slices.Equal(tr.targets, []Target{want}) {
				t.Fatalf("fetch(%q) authorized %+v, want exactly %+v", raw, tr.targets, want)
			}
			if guardDial("tcp4", tc.resolve+":443", nil) == nil {
				t.Fatalf("guardDial accepted %s, the address %q denotes; a grant must not override the dial check", tc.resolve, tc.host)
			}
		})
	}
}

func TestFetch_AuthorizesCanonicalHostBeforeTheFirstRequest(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want Target
		dial string
	}{
		{"uppercase and trailing dot", "https://Docs.EXAMPLE.com./guide", Target{Host: "docs.example.com", Scheme: "https", Port: "443", URL: "https://docs.example.com/guide"}, "https://docs.example.com/guide"},
		{"internationalized name", "https://bücher.example/", Target{Host: "xn--bcher-kva.example", Scheme: "https", Port: "443", URL: "https://xn--bcher-kva.example/"}, "https://xn--bcher-kva.example/"},
		{"explicit port", "http://docs.example.com:8080/", Target{Host: "docs.example.com", Scheme: "http", Port: "8080", URL: "http://docs.example.com:8080/", FreshConfirmation: true}, "https://docs.example.com:8080/"},
		{"padded port", "http://docs.example.com:08080/", Target{Host: "docs.example.com", Scheme: "http", Port: "8080", URL: "http://docs.example.com:8080/", FreshConfirmation: true}, "https://docs.example.com:8080/"},
		{"empty port", "https://docs.example.com:/guide", Target{Host: "docs.example.com", Scheme: "https", Port: "443", URL: "https://docs.example.com/guide"}, "https://docs.example.com/guide"},
		{"path and query", "https://docs.example.com/guide/v2?q=1&r=2", Target{Host: "docs.example.com", Scheme: "https", Port: "443", URL: "https://docs.example.com/guide/v2?q=1&r=2"}, "https://docs.example.com/guide/v2?q=1&r=2"},
		{"ipv4 literal", "http://93.184.216.34/", Target{Host: "93.184.216.34", Scheme: "http", Port: "80", URL: "http://93.184.216.34/"}, "https://93.184.216.34/"},
		{"bracketless ipv6 literal", "https://[2001:0db8::1]:8443/", Target{Host: "2001:db8::1", Scheme: "https", Port: "8443", URL: "https://[2001:db8::1]:8443/", FreshConfirmation: true}, "https://[2001:db8::1]:8443/"},
		{"ipv6 literal without a port", "https://[2001:0db8::1]/x", Target{Host: "2001:db8::1", Scheme: "https", Port: "443", URL: "https://[2001:db8::1]/x"}, "https://[2001:db8::1]/x"},
		{"uppercase scheme", "HTTPS://Docs.Example.com/", Target{Host: "docs.example.com", Scheme: "https", Port: "443", URL: "https://docs.example.com/"}, "https://docs.example.com/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(nil), tc.raw, tr.authorizer(nil))
			if err != nil {
				t.Fatalf("fetch(%q) = %v, want success", tc.raw, err)
			}
			resp.Body.Close()
			if !slices.Equal(tr.targets, []Target{tc.want}) {
				t.Fatalf("fetch(%q) authorized %+v, want exactly %+v", tc.raw, tr.targets, tc.want)
			}
			want := []string{"auth " + origin(tc.want), "req " + tc.dial}
			if !slices.Equal(tr.events, want) {
				t.Fatalf("fetch(%q) recorded %v, want %v", tc.raw, tr.events, want)
			}
		})
	}
}

func TestFetch_UnauthorizedInitialHostSendsNothing(t *testing.T) {
	tr := &trace{}
	deny := func(Target) error { return errDenied }
	resp, err := fetch(context.Background(), tr.client(nil), "https://docs.example.com/guide", tr.authorizer(deny))
	if err == nil {
		resp.Body.Close()
		t.Fatal("fetch returned success for an unauthorized host, want a refusal")
	}
	if !errors.Is(err, errDenied) {
		t.Fatalf("fetch = %v, want the callback's refusal wrapped", err)
	}
	if got := tr.requests(); len(got) != 0 {
		t.Fatalf("fetch attempted %v after an unauthorized host, want no request", got)
	}
}

func TestFetch_AuthorizesChangedRedirectHostBeforeItsRequest(t *testing.T) {
	const first = "https://docs.example.com/guide"
	const second = "https://cdn.other.example/guide"

	t.Run("approved", func(t *testing.T) {
		tr := &trace{}
		resp, err := fetch(context.Background(), tr.client(redirectOnce(first, second)), first, tr.authorizer(nil))
		if err != nil {
			t.Fatalf("fetch = %v, want the redirect followed after authorization", err)
		}
		resp.Body.Close()
		want := []string{
			"auth https://docs.example.com:443",
			"req " + first,
			"auth https://cdn.other.example:443",
			"req " + second,
		}
		if !slices.Equal(tr.events, want) {
			t.Fatalf("fetch recorded %v, want %v", tr.events, want)
		}
		if tr.targets[1].FreshConfirmation {
			t.Fatal("a host-only redirect change asked for fresh confirmation, want an ordinary host authorization")
		}
		if tr.targets[0].URL != first || tr.targets[1].URL != second {
			t.Fatalf("fetch authorized URLs %q and %q, want %q then %q", tr.targets[0].URL, tr.targets[1].URL, first, second)
		}
	})

	t.Run("non-canonical location", func(t *testing.T) {
		tr := &trace{}
		respond := redirectOnce(first, "https://CDN.Other.Example./guide")
		resp, err := fetch(context.Background(), tr.client(respond), first, tr.authorizer(nil))
		if err != nil {
			t.Fatalf("fetch = %v, want success", err)
		}
		resp.Body.Close()
		want := []string{
			"auth https://docs.example.com:443",
			"req " + first,
			"auth https://cdn.other.example:443",
			"req " + second,
		}
		if !slices.Equal(tr.events, want) {
			t.Fatalf("fetch recorded %v, want the redirect authorized and dialed canonically: %v", tr.events, want)
		}
		if tr.targets[1].URL != second {
			t.Fatalf("fetch authorized URL %q, want the canonical %q rather than the raw location", tr.targets[1].URL, second)
		}
	})

	t.Run("denied", func(t *testing.T) {
		tr := &trace{}
		deny := func(target Target) error {
			if target.Host == "cdn.other.example" {
				return errDenied
			}
			return nil
		}
		resp, err := fetch(context.Background(), tr.client(redirectOnce(first, second)), first, tr.authorizer(deny))
		if err == nil {
			resp.Body.Close()
			t.Fatal("fetch followed a redirect to an unauthorized host, want a refusal")
		}
		if got := tr.requests(); !slices.Equal(got, []string{first}) {
			t.Fatalf("fetch attempted %v, want only the authorized first hop", got)
		}
	})
}

func TestFetch_SameOriginRedirectIsStillAuthorized(t *testing.T) {
	const first = "https://docs.example.com/guide"
	const second = "https://docs.example.com/guide/v2?lang=en&page=2"

	tr := &trace{}
	resp, err := fetch(context.Background(), tr.client(redirectOnce(first, "/guide/v2?lang=en&page=2")), first, tr.authorizer(nil))
	if err != nil {
		t.Fatalf("fetch = %v, want success", err)
	}
	resp.Body.Close()
	want := []string{
		"auth https://docs.example.com:443",
		"req " + first,
		"auth https://docs.example.com:443",
		"req " + second,
	}
	if !slices.Equal(tr.events, want) {
		t.Fatalf("fetch recorded %v, want the same-origin target authorized too: %v", tr.events, want)
	}
	if tr.targets[1].FreshConfirmation {
		t.Fatal("a same-origin redirect asked for fresh confirmation, want none")
	}
	if tr.targets[1].URL != second {
		t.Fatalf("fetch authorized URL %q, want the redirected path and query %q rather than a repeat of the first hop", tr.targets[1].URL, second)
	}
}

func TestFetch_DirectNonDefaultPortNeedsFreshConfirmation(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"https default port", "https://docs.example.com/guide", false},
		{"https default port spelled out", "https://docs.example.com:443/guide", false},
		{"http default port", "http://docs.example.com/guide", false},
		{"http default port spelled out", "http://docs.example.com:80/guide", false},
		{"https non-default port", "https://docs.example.com:8443/guide", true},
		{"http non-default port", "http://docs.example.com:8080/guide", true},
		{"https on the http default port", "https://docs.example.com:80/guide", true},
		{"http on the https default port", "http://docs.example.com:443/guide", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(nil), tc.raw, tr.authorizer(nil))
			if err != nil {
				t.Fatalf("fetch(%q) = %v, want success", tc.raw, err)
			}
			resp.Body.Close()
			if len(tr.targets) != 1 {
				t.Fatalf("fetch(%q) authorized %+v, want exactly one target", tc.raw, tr.targets)
			}
			if got := tr.targets[0].FreshConfirmation; got != tc.want {
				t.Fatalf("fetch(%q) authorized fresh_confirmation=%t, want %t", tc.raw, got, tc.want)
			}
		})

		if !tc.want {
			continue
		}
		t.Run(tc.name+"/unconfirmed", func(t *testing.T) {
			tr := &trace{}
			deny := func(target Target) error {
				if target.FreshConfirmation {
					return errDenied
				}
				return nil
			}
			resp, err := fetch(context.Background(), tr.client(nil), tc.raw, tr.authorizer(deny))
			if err == nil {
				resp.Body.Close()
				t.Fatalf("fetch(%q) dialed a non-default port without fresh confirmation, want a refusal", tc.raw)
			}
			if got := tr.requests(); len(got) != 0 {
				t.Fatalf("fetch(%q) attempted %v, want no request", tc.raw, got)
			}
		})
	}
}

func TestFetch_SchemeOrPortChangeNeedsFreshConfirmation(t *testing.T) {
	cases := []struct {
		name    string
		first   string
		to      string
		want    Target
		respond func(*http.Request) (*http.Response, error)
	}{
		{name: "explicit port change", first: "https://docs.example.com/guide", to: "https://docs.example.com:8443/guide", want: Target{Host: "docs.example.com", Scheme: "https", Port: "8443", URL: "https://docs.example.com:8443/guide", FreshConfirmation: true}},
		{name: "default port spelled out", first: "https://docs.example.com/guide", to: "https://docs.example.com:443/guide", want: Target{Host: "docs.example.com", Scheme: "https", Port: "443", URL: "https://docs.example.com:443/guide"}},
		{
			name:  "http fallback to https",
			first: "http://docs.example.com/guide",
			to:    "https://docs.example.com/guide/v2",
			want:  Target{Host: "docs.example.com", Scheme: "https", Port: "443", URL: "https://docs.example.com/guide/v2", FreshConfirmation: true},
			respond: withoutHTTPS("https://docs.example.com/guide",
				redirectOnce("http://docs.example.com/guide", "https://docs.example.com/guide/v2")),
		},
	}
	for _, tc := range cases {
		respond := tc.respond
		if respond == nil {
			respond = redirectOnce(tc.first, tc.to)
		}
		t.Run(tc.name, func(t *testing.T) {
			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(respond), tc.first, tr.authorizer(nil))
			if err != nil {
				t.Fatalf("fetch = %v, want success", err)
			}
			resp.Body.Close()
			if len(tr.targets) != 2 || tr.targets[1] != tc.want {
				t.Fatalf("fetch authorized %+v, want the redirect target %+v", tr.targets, tc.want)
			}
			want := []string{"auth " + origin(tc.want), "req " + tc.to}
			if got := tr.events[len(tr.events)-2:]; !slices.Equal(got, want) {
				t.Fatalf("fetch recorded %v, want it to end with %v", tr.events, want)
			}
		})

		if !tc.want.FreshConfirmation {
			continue
		}
		t.Run(tc.name+"/unconfirmed", func(t *testing.T) {
			tr := &trace{}
			deny := func(target Target) error {
				if target.FreshConfirmation {
					return errDenied
				}
				return nil
			}
			resp, err := fetch(context.Background(), tr.client(respond), tc.first, tr.authorizer(deny))
			if err == nil {
				resp.Body.Close()
				t.Fatal("fetch followed a scheme or port change without fresh confirmation, want a refusal")
			}
			got := tr.requests()
			if len(got) == 0 || got[len(got)-1] != tc.first || slices.Contains(got, tc.to) {
				t.Fatalf("fetch attempted %v, want the chain to stop at the authorized %s", got, tc.first)
			}
		})
	}
}

func TestFetch_RefusesUnusableRedirect(t *testing.T) {
	const first = "https://docs.example.com/guide"
	cases := map[string]string{
		"missing location":   "",
		"malformed location": "http://exa mple.com/",
		"file location":      "file:///etc/passwd",
		"host-less location": "http:///path",
		"wildcard host":      "https://*/",
		"ftp location":       "ftp://files.example.com/x",
	}
	for name, location := range cases {
		t.Run(name, func(t *testing.T) {
			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(redirectOnce(first, location)), first, tr.authorizer(nil))
			if err == nil {
				resp.Body.Close()
				t.Fatalf("fetch accepted redirect location %q, want a refusal", location)
			}
			if got := tr.requests(); !slices.Equal(got, []string{first}) {
				t.Fatalf("fetch attempted %v after an unusable redirect, want only the first hop", got)
			}
		})
	}
}

func TestFetch_BoundsARedirectLoop(t *testing.T) {
	tr := &trace{}
	hop := 0
	respond := func(*http.Request) (*http.Response, error) {
		hop++
		return response(http.StatusFound, "/"+strings.Repeat("x", hop)), nil
	}
	resp, err := fetch(context.Background(), tr.client(respond), "https://docs.example.com/0", tr.authorizer(nil))
	if err == nil {
		resp.Body.Close()
		t.Fatal("fetch followed an unbounded redirect chain, want a refusal")
	}
	if got := len(tr.requests()); got != maxRedirects+1 {
		t.Fatalf("fetch attempted %d requests, want %d", got, maxRedirects+1)
	}
}

func TestFetch_ReturnsEveryRedirectStatusToTheTransport(t *testing.T) {
	const first = "https://docs.example.com/guide"
	const second = "https://cdn.other.example/guide"
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			tr := &trace{}
			respond := func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == first {
					return response(status, second), nil
				}
				return response(http.StatusOK, ""), nil
			}
			deny := func(target Target) error {
				if target.Host == "cdn.other.example" {
					return errDenied
				}
				return nil
			}
			resp, err := fetch(context.Background(), tr.client(respond), first, tr.authorizer(deny))
			if err == nil {
				resp.Body.Close()
				t.Fatalf("a %d redirect reached an unauthorized host, want a refusal", status)
			}
			if got := tr.requests(); !slices.Equal(got, []string{first}) {
				t.Fatalf("fetch attempted %v on a %d redirect, want only the first hop", got, status)
			}
		})
	}
}

func TestFetch_LeavesTheCallerClientUnchanged(t *testing.T) {
	tr := &trace{}
	client := tr.client(nil)
	resp, err := fetch(context.Background(), client, "https://docs.example.com/guide", tr.authorizer(nil))
	if err != nil {
		t.Fatalf("fetch = %v, want success", err)
	}
	resp.Body.Close()
	if client.CheckRedirect != nil {
		t.Fatal("fetch installed a redirect policy on the caller's client, want the caller's client untouched")
	}
}

func TestFetch_RefusesMissingDependencies(t *testing.T) {
	tr := &trace{}
	if _, err := fetch(context.Background(), nil, "https://docs.example.com/", tr.authorizer(nil)); err == nil {
		t.Fatal("fetch accepted a nil HTTP client, want a refusal")
	}
	if _, err := fetch(context.Background(), tr.client(nil), "https://docs.example.com/", nil); err == nil {
		t.Fatal("fetch accepted a nil authorization callback, want a refusal")
	}
	if len(tr.events) != 0 {
		t.Fatalf("fetch recorded %v without its dependencies, want nothing", tr.events)
	}
}

func TestFetch_ReportsATransportFailureWithoutTheURL(t *testing.T) {
	dialFailed := errors.New("no such host")
	tr := &trace{}
	respond := func(*http.Request) (*http.Response, error) { return nil, dialFailed }
	_, err := fetch(context.Background(), tr.client(respond), "https://docs.example.com/guide?token=s3cret", tr.authorizer(nil))
	if !errors.Is(err, dialFailed) {
		t.Fatalf("fetch = %v, want the transport failure wrapped", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("fetch error %q repeats the request URL, want only the host", err)
	}
}

func TestFetch_BindsEveryRequestToTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tr := &trace{}
	respond := func(r *http.Request) (*http.Response, error) {
		if r.Context() != ctx {
			t.Errorf("request %s carried a different context, want the caller's", r.URL)
		}
		return response(http.StatusOK, ""), nil
	}
	resp, err := fetch(ctx, tr.client(respond), "https://docs.example.com/guide", tr.authorizer(nil))
	if err != nil {
		t.Fatalf("fetch = %v, want success", err)
	}
	resp.Body.Close()
	cancel()
}

func TestFetch_HTTPSNeverDowngrades(t *testing.T) {
	const first = "https://docs.example.com/guide"
	toHTTP := redirectOnce(first, "http://docs.example.com/guide")
	cases := []struct {
		name    string
		respond func(*http.Request) (*http.Response, error)
	}{
		{"transport failure", func(*http.Request) (*http.Response, error) { return nil, errNoTLS }},
		{"oversized transport failure", func(*http.Request) (*http.Response, error) { return nil, errOversizedDial }},
		{"redirect to http", toHTTP},
		{"redirect to http on another host", redirectOnce(first, "http://cdn.other.example/guide")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(tc.respond), first, tr.authorizer(nil))
			if err == nil {
				resp.Body.Close()
				t.Fatal("fetch = success, want the failed HTTPS fetch reported")
			}
			if got := len(err.Error()); got > maxRefusalBytes {
				t.Fatalf("fetch failed with a %d-byte error, want at most %d", got, maxRefusalBytes)
			}
			if strings.Contains(err.Error(), dialSecret) {
				t.Fatalf("fetch failed with %q, want no transport error text", err)
			}
			for _, req := range tr.requests() {
				if strings.HasPrefix(req, "http://") {
					t.Fatalf("fetch attempted %v, want no HTTP request even though every target was authorized", tr.requests())
				}
			}
		})
	}
}

func TestFetch_DirectHTTPTriesHTTPSBeforeItsLiteralFallback(t *testing.T) {
	const direct = "http://docs.example.com/guide?q=1"
	const secure = "https://docs.example.com/guide?q=1"

	t.Run("https succeeds", func(t *testing.T) {
		tr := &trace{}
		resp, err := fetch(context.Background(), tr.client(nil), direct, tr.authorizer(nil))
		if err != nil {
			t.Fatalf("fetch = %v, want success", err)
		}
		resp.Body.Close()
		want := []string{"auth http://docs.example.com:80", "req " + secure}
		if !slices.Equal(tr.events, want) {
			t.Fatalf("fetch recorded %v, want the HTTPS equivalent only, on one authorization: %v", tr.events, want)
		}
	})

	t.Run("https fails", func(t *testing.T) {
		tr := &trace{}
		resp, err := fetch(context.Background(), tr.client(withoutHTTPS(secure, nil)), direct, tr.authorizer(nil))
		if err != nil {
			t.Fatalf("fetch = %v, want the HTTP fallback", err)
		}
		resp.Body.Close()
		want := []string{"auth http://docs.example.com:80", "req " + secure, "req " + direct}
		if !slices.Equal(tr.events, want) {
			t.Fatalf("fetch recorded %v, want %v", tr.events, want)
		}
	})

	t.Run("an http redirect cannot replace the literal fallback", func(t *testing.T) {
		tr := &trace{}
		respond := redirectOnce(secure, "http://cdn.other.example/guide")
		resp, err := fetch(context.Background(), tr.client(respond), direct, tr.authorizer(nil))
		if err != nil {
			t.Fatalf("fetch = %v, want the HTTP fallback", err)
		}
		resp.Body.Close()
		want := []string{"auth http://docs.example.com:80", "req " + secure, "req " + direct}
		if !slices.Equal(tr.events, want) {
			t.Fatalf("fetch recorded %v, want only the literal original HTTP URL after HTTPS: %v", tr.events, want)
		}
	})

	t.Run("fallback is never a redirect target", func(t *testing.T) {
		const elsewhere = "https://cdn.other.example/guide"
		tr := &trace{}
		respond := func(r *http.Request) (*http.Response, error) {
			switch r.URL.String() {
			case secure:
				return response(http.StatusFound, elsewhere), nil
			case elsewhere:
				return nil, errNoTLS
			}
			return response(http.StatusOK, ""), nil
		}
		resp, err := fetch(context.Background(), tr.client(respond), direct, tr.authorizer(nil))
		if err != nil {
			t.Fatalf("fetch = %v, want the HTTP fallback", err)
		}
		resp.Body.Close()
		want := []string{
			"auth http://docs.example.com:80",
			"req " + secure,
			"auth https://cdn.other.example:443",
			"req " + elsewhere,
			"req " + direct,
		}
		if !slices.Equal(tr.events, want) {
			t.Fatalf("fetch recorded %v, want the fallback to be the literal original: %v", tr.events, want)
		}
	})
}

func TestFetch_HTTPSFirstTargetCarriesItsUpgradedURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    Target
		upgrade Target
	}{
		{
			name:    "default port",
			raw:     "http://docs.example.com/guide?q=1",
			want:    Target{Host: "docs.example.com", Scheme: "http", Port: "80", URL: "http://docs.example.com/guide?q=1"},
			upgrade: Target{Host: "docs.example.com", Scheme: "https", Port: "443", URL: "https://docs.example.com/guide?q=1"},
		},
		{
			name:    "non-default port",
			raw:     "http://docs.example.com:8080/guide",
			want:    Target{Host: "docs.example.com", Scheme: "http", Port: "8080", URL: "http://docs.example.com:8080/guide", FreshConfirmation: true},
			upgrade: Target{Host: "docs.example.com", Scheme: "https", Port: "8080", URL: "https://docs.example.com:8080/guide", FreshConfirmation: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("url.Parse(%q) = %v", tc.raw, err)
			}
			first, target, err := admit(parsed, nil)
			if err != nil {
				t.Fatalf("admit(%q) = %v, want success", tc.raw, err)
			}
			if target != tc.want {
				t.Fatalf("admit(%q) = %+v, want %+v", tc.raw, target, tc.want)
			}
			secure, secureTarget := overHTTPS(first, target)
			if secureTarget != tc.upgrade {
				t.Fatalf("overHTTPS(%q) = %+v, want %+v", tc.raw, secureTarget, tc.upgrade)
			}
			if got := secure.String(); got != tc.upgrade.URL {
				t.Fatalf("overHTTPS(%q) dials %q, want its target URL %q", tc.raw, got, tc.upgrade.URL)
			}

			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(nil), tc.raw, tr.authorizer(nil))
			if err != nil {
				t.Fatalf("fetch(%q) = %v, want success", tc.raw, err)
			}
			resp.Body.Close()
			if !slices.Equal(tr.targets, []Target{tc.want}) {
				t.Fatalf("fetch(%q) authorized %+v, want only the supplied HTTP target %+v", tc.raw, tr.targets, tc.want)
			}
			if got := tr.requests(); !slices.Equal(got, []string{tc.upgrade.URL}) {
				t.Fatalf("fetch(%q) attempted %v, want only %q", tc.raw, got, tc.upgrade.URL)
			}
		})
	}
}

func TestFetch_TargetURLRedactsCredentials(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"password", "https://reader:s3cret@docs.example.com/guide", "https://reader:xxxxx@docs.example.com/guide"},
		{"username only", "https://reader@docs.example.com/guide", "https://reader@docs.example.com/guide"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trace{}
			resp, err := fetch(context.Background(), tr.client(nil), tc.raw, tr.authorizer(nil))
			if err != nil {
				t.Fatalf("fetch = %v, want success", err)
			}
			resp.Body.Close()
			if len(tr.targets) != 1 || tr.targets[0].URL != tc.want {
				t.Fatalf("fetch authorized %+v, want one target carrying %q", tr.targets, tc.want)
			}
			if strings.Contains(tr.targets[0].URL, "s3cret") {
				t.Fatalf("target URL %q repeats the password, want it redacted", tr.targets[0].URL)
			}
		})
	}
}

func TestFetch_TargetURLUsesTheFinalURLCap(t *testing.T) {
	raw := "https://docs.example.com/" + strings.Repeat("é", maxFinalURLBytes)
	tr := &trace{}
	resp, err := fetch(context.Background(), tr.client(nil), raw, tr.authorizer(nil))
	if err != nil {
		t.Fatalf("fetch = %v, want success", err)
	}
	resp.Body.Close()
	if len(tr.targets) != 1 {
		t.Fatalf("fetch authorized %d targets, want one", len(tr.targets))
	}
	got := tr.targets[0].URL
	if len(got) > maxFinalURLBytes || !utf8.ValidString(got) {
		t.Fatalf("target URL is %d bytes (valid utf8 = %t), want at most %d valid bytes", len(got), utf8.ValidString(got), maxFinalURLBytes)
	}
	if !strings.HasPrefix(got, "https://docs.example.com/") {
		t.Fatalf("target URL = %.40q, want the canonical request URL truncated from its end", got)
	}
	if requested := tr.requests(); len(requested) != 1 || len(requested[0]) <= maxFinalURLBytes {
		t.Fatalf("fetch attempted %d requests, want one whose full-length URL outlives the display cap", len(requested))
	}
}

func TestFetchTextBoundsAndAdmitsResponses(t *testing.T) {
	const cap = 32
	for name, tc := range map[string]struct {
		contentType string
		body        string
		outcome     string
	}{
		"text":                   {"text/plain; charset=utf-8", "readable text", OutcomeOK},
		"json":                   {"application/json", `{"answer":"yes"}`, OutcomeOK},
		"xml":                    {"application/xml", "<answer>yes</answer>", OutcomeOK},
		"xhtml":                  {"application/xhtml+xml", "<p>readable text</p>", OutcomeOK},
		"unsupported":            {"image/png", "secret image bytes", OutcomeUnsupportedContent},
		"missing content type":   {"", "readable text", OutcomeUnsupportedContent},
		"malformed content type": {"text/plain; charset", "readable text", OutcomeUnsupportedContent},
	} {
		t.Run(name, func(t *testing.T) {
			tr := &trace{}
			result := FetchText(context.Background(), tr.client(func(*http.Request) (*http.Response, error) {
				resp := response(http.StatusOK, "")
				resp.Header.Set("Content-Type", tc.contentType)
				resp.Body = io.NopCloser(strings.NewReader(tc.body))
				return resp, nil
			}), "https://docs.example.com/guide", tr.authorizer(nil), cap)
			if result.Outcome != tc.outcome {
				t.Fatalf("FetchText outcome = %q, want %q", result.Outcome, tc.outcome)
			}
			if tc.outcome == OutcomeOK && (result.FinalURL == "" || result.Content == "") {
				t.Fatalf("FetchText success = %+v, want final URL and content", result)
			}
			if tc.outcome != OutcomeOK && (result.FinalURL != "" || result.Content != "") {
				t.Fatalf("FetchText failure = %+v, want no response data", result)
			}
		})
	}

	t.Run("two times cap is admitted and one byte over fails", func(t *testing.T) {
		for _, size := range []int{2 * cap, 2*cap + 1} {
			tr := &trace{}
			result := FetchText(context.Background(), tr.client(func(*http.Request) (*http.Response, error) {
				resp := response(http.StatusOK, "")
				resp.Header.Set("Content-Type", "text/plain")
				resp.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", size)))
				return resp, nil
			}), "https://docs.example.com/guide", tr.authorizer(nil), cap)
			want := OutcomeOK
			if size > 2*cap {
				want = OutcomeResponseTooLarge
			}
			if result.Outcome != want {
				t.Fatalf("FetchText(%d bytes) outcome = %q, want %q", size, result.Outcome, want)
			}
		}
	})
}

func TestFetchTextReturnsBodyFreeFailures(t *testing.T) {
	const hostile = "https://attacker.example/leak?token=hostile-sentinel"
	cases := map[string]func(*http.Request) (*http.Response, error){
		"transport": func(*http.Request) (*http.Response, error) {
			return nil, errors.New(hostile)
		},
		"non-2xx": func(*http.Request) (*http.Response, error) {
			resp := response(http.StatusBadGateway, "")
			resp.Header.Set("X-Secret", hostile)
			resp.Body = io.NopCloser(strings.NewReader(hostile))
			return resp, nil
		},
		"body read": func(*http.Request) (*http.Response, error) {
			resp := response(http.StatusOK, "")
			resp.Header.Set("Content-Type", "text/plain")
			resp.Body = &errBody{data: hostile, err: errors.New(hostile)}
			return resp, nil
		},
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			tr := &trace{}
			result := FetchText(context.Background(), tr.client(respond), "https://docs.example.com/guide", tr.authorizer(nil), 64)
			if result.Outcome != OutcomeRequestFailed || result.FinalURL != "" || result.Content != "" {
				t.Fatalf("FetchText = %+v, want a body-free request failure", result)
			}
		})
	}

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		tr := &trace{}
		result := FetchText(ctx, tr.client(func(r *http.Request) (*http.Response, error) {
			return nil, r.Context().Err()
		}), "https://docs.example.com/guide", tr.authorizer(nil), 64)
		if result.Outcome != OutcomeRequestFailed || result.FinalURL != "" || result.Content != "" {
			t.Fatalf("FetchText = %+v, want a body-free request failure", result)
		}
	})
}

func TestFetchTextRedactsCredentialsInTheFinalURL(t *testing.T) {
	tr := &trace{}
	result := FetchText(context.Background(), tr.client(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "")
		resp.Header.Set("Content-Type", "text/plain")
		resp.Body = io.NopCloser(strings.NewReader("readable text"))
		return resp, nil
	}), "https://reader:s3cret@docs.example.com/guide", tr.authorizer(nil), 64)
	if result.Outcome != OutcomeOK {
		t.Fatalf("FetchText outcome = %q, want %q", result.Outcome, OutcomeOK)
	}
	if strings.Contains(result.FinalURL, "s3cret") {
		t.Fatalf("FetchText final URL = %q, want the password redacted", result.FinalURL)
	}
}

// errBody hands back data before failing, so a read error is exercised after
// hostile bytes have already been buffered rather than on an empty body.
type errBody struct {
	data string
	err  error
}

func (b *errBody) Read(p []byte) (int, error) {
	if b.data == "" {
		return 0, b.err
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (b *errBody) Close() error { return nil }
