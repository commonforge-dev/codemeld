// Tests for the OpenAI ChatGPT OAuth login primitives: deterministic PKCE and
// authorize-URL generation, loopback state/code validation, token exchange
// success/failure with fake servers, typed cancellation/timeout outcomes, and
// assertions that no credential value leaks into errors.
package openaiauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// newTestFlow builds a Flow pointed at baseURL with a fixed clock, an immediate
// (but context-aware) sleep, and an ephemeral loopback address, so tests never
// reach the production origin, the fixed port, or wall-clock time.
func newTestFlow(baseURL string) *Flow {
	f := NewFlow()
	f.now = func() time.Time { return fixedNow }
	f.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	f.authBaseURL = baseURL
	f.loopback = "localhost:0"
	return f
}

// withFixedEntropy makes GeneratePKCE/GenerateState deterministic for one test by
// feeding randReader a repeating fixed byte pattern, restored on cleanup.
func withFixedEntropy(t *testing.T, seed byte) {
	t.Helper()
	prev := randReader
	buf := bytes.Repeat([]byte{seed}, 256)
	randReader = bytes.NewReader(buf)
	t.Cleanup(func() { randReader = prev })
}

// makeIDToken builds an unsigned JWT-shaped id token carrying accountID in the
// Codex-namespaced claim, so the account-id extraction can be exercised without a
// real signing key (the token is never verified, only parsed).
func makeIDToken(t *testing.T, accountID string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": accountID},
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal id-token claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".sig"
}

func TestGeneratePKCEDeterministic(t *testing.T) {
	withFixedEntropy(t, 0xAB)
	first, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	withFixedEntropy(t, 0xAB)
	second, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	if first != second {
		t.Fatalf("same entropy produced different PKCE pairs")
	}
	if first.Method != "S256" {
		t.Errorf("Method = %q, want S256", first.Method)
	}
	if len(first.Verifier) != 43 {
		t.Errorf("verifier length = %d, want 43", len(first.Verifier))
	}
	sum := sha256.Sum256([]byte(first.Verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if first.Challenge != wantChallenge {
		t.Errorf("challenge does not match S256(verifier)")
	}
}

func TestGeneratePKCERealEntropyValid(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != p.Challenge {
		t.Errorf("challenge does not match S256(verifier)")
	}
	if strings.ContainsAny(p.Verifier, "+/=") || strings.ContainsAny(p.Challenge, "+/=") {
		t.Errorf("PKCE values must be base64url without padding")
	}
}

func TestAuthorizeURLDeterministicAndPinned(t *testing.T) {
	f := NewFlow()
	p := PKCE{Verifier: "verifier-secret", Challenge: "challenge-value", Method: "S256"}
	first := f.AuthorizeURL("state-123", p)
	second := f.AuthorizeURL("state-123", p)
	if first != second {
		t.Fatalf("authorize URL not deterministic")
	}
	u, err := url.Parse(first)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	if u.Scheme != "https" || u.Host != "auth.openai.com" {
		t.Errorf("authorize origin = %s://%s, want https://auth.openai.com", u.Scheme, u.Host)
	}
	if u.Path != authorizePath {
		t.Errorf("authorize path = %q, want %q", u.Path, authorizePath)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             clientID,
		"redirect_uri":          loopbackRedirectURI,
		"scope":                 oauthScopes,
		"code_challenge":        "challenge-value",
		"code_challenge_method": "S256",
		"state":                 "state-123",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("authorize query %q mismatch", k)
		}
	}
	if !strings.Contains(q.Get("redirect_uri"), "localhost:1455") {
		t.Errorf("redirect_uri %q is not the fixed loopback", q.Get("redirect_uri"))
	}
	if strings.Contains(first, "verifier-secret") {
		t.Errorf("authorize URL leaks the PKCE verifier")
	}
}

func TestNewFlowPinnedToProductionOrigin(t *testing.T) {
	f := NewFlow()
	if f.authBaseURL != "https://auth.openai.com" {
		t.Errorf("authBaseURL = %q, want production auth origin", f.authBaseURL)
	}
	if f.clientID != "app_EMoamEEZ73f0CkXaXp7hrann" {
		t.Errorf("clientID = %q, want the Codex client id from adr-014", f.clientID)
	}
	if f.loopback != "localhost:1455" {
		t.Errorf("loopback = %q, want localhost:1455", f.loopback)
	}
}

func TestLoopbackCapturesValidCallback(t *testing.T) {
	f := newTestFlow("https://auth.openai.com")
	lb, err := f.StartLoopback("expected-state")
	if err != nil {
		t.Fatalf("StartLoopback() error = %v", err)
	}
	defer func() { _ = lb.Close() }()

	resp, err := http.Get(callbackURL(lb, url.Values{"state": {"expected-state"}, "code": {"auth-code-xyz"}}))
	if err != nil {
		t.Fatalf("callback GET error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("callback status = %d, want 200", resp.StatusCode)
	}

	code, err := lb.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if code != "auth-code-xyz" {
		t.Errorf("captured authorization code mismatch")
	}
}

func TestLoopbackRejectsCallback(t *testing.T) {
	// Every rejection path — wrong state or missing code on a success callback, and
	// wrong/missing state on an error callback — must answer 400 and capture no code.
	cases := []struct {
		name string
		q    url.Values
	}{
		{"wrong state with code", url.Values{"state": {"WRONG"}, "code": {"auth-code-xyz"}}},
		{"missing code", url.Values{"state": {"expected-state"}}},
		{"wrong state with error", url.Values{"state": {"WRONG"}, "error": {"access_denied"}}},
		{"missing state with error", url.Values{"error": {"access_denied"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFlow("https://auth.openai.com")
			lb, err := f.StartLoopback("expected-state")
			if err != nil {
				t.Fatalf("StartLoopback() error = %v", err)
			}
			defer func() { _ = lb.Close() }()

			resp, err := http.Get(callbackURL(lb, tc.q))
			if err != nil {
				t.Fatalf("callback GET error = %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("rejected callback status = %d, want 400", resp.StatusCode)
			}
			assertNoCapturedCode(t, lb)
		})
	}
}

func TestLoopbackUpstreamErrorCallback(t *testing.T) {
	f := newTestFlow("https://auth.openai.com")
	lb, err := f.StartLoopback("expected-state")
	if err != nil {
		t.Fatalf("StartLoopback() error = %v", err)
	}
	defer func() { _ = lb.Close() }()

	resp, err := http.Get(callbackURL(lb, url.Values{"state": {"expected-state"}, "error": {"access_denied"}, "error_description": {"user denied"}}))
	if err != nil {
		t.Fatalf("callback GET error = %v", err)
	}
	_ = resp.Body.Close()

	_, waitErr := lb.Wait(context.Background())
	var oaErr *Error
	if !errors.As(waitErr, &oaErr) {
		t.Fatalf("Wait() error is not typed OpenAI auth error")
	}
	if oaErr.Kind != KindUpstream {
		t.Fatalf("Wait() error kind = %q, want %q", oaErr.Kind, KindUpstream)
	}
	if !strings.Contains(oaErr.Detail, "access_denied") {
		t.Errorf("error detail does not name access_denied")
	}
}

func TestLoopbackErrorCallbackDescriptionRedacted(t *testing.T) {
	f := newTestFlow("https://auth.openai.com")
	lb, err := f.StartLoopback("expected-state")
	if err != nil {
		t.Fatalf("StartLoopback() error = %v", err)
	}
	defer func() { _ = lb.Close() }()

	resp, err := http.Get(callbackURL(lb, url.Values{
		"state":             {"expected-state"},
		"error":             {"access_denied"},
		"error_description": {"denied auth-code-xyz verifier-secret"},
	}))
	if err != nil {
		t.Fatalf("callback GET error = %v", err)
	}
	_ = resp.Body.Close()

	_, waitErr := lb.Wait(context.Background())
	var oaErr *Error
	if !errors.As(waitErr, &oaErr) {
		t.Fatalf("Wait() error is not typed OpenAI auth error")
	}
	if oaErr.Kind != KindUpstream {
		t.Fatalf("Wait() error kind = %q, want %q", oaErr.Kind, KindUpstream)
	}
	if !strings.Contains(oaErr.Detail, "access_denied") {
		t.Errorf("error detail does not name access_denied")
	}
	assertNoSecrets(t, oaErr.Error(), "auth-code-xyz", "verifier-secret")
}

func TestLoopbackErrorCallbackCodeRedacted(t *testing.T) {
	f := newTestFlow("https://auth.openai.com")
	lb, err := f.StartLoopback("expected-state")
	if err != nil {
		t.Fatalf("StartLoopback() error = %v", err)
	}
	defer func() { _ = lb.Close() }()

	resp, err := http.Get(callbackURL(lb, url.Values{
		"state": {"expected-state"},
		"error": {"access_denied auth-code-xyz verifier-secret access-AAA acct-1"},
	}))
	if err != nil {
		t.Fatalf("callback GET error = %v", err)
	}
	_ = resp.Body.Close()

	_, waitErr := lb.Wait(context.Background())
	oaErr := requireKind(t, waitErr, KindUpstream)
	if oaErr.Detail != "OpenAI auth request failed" {
		t.Errorf("unsafe OAuth error code should use generic detail")
	}
	assertNoSecrets(t, oaErr.Error(), "auth-code-xyz", "verifier-secret", "access-AAA", "acct-1")
}

func TestLoopbackWaitCanceled(t *testing.T) {
	f := newTestFlow("https://auth.openai.com")
	lb, err := f.StartLoopback("expected-state")
	if err != nil {
		t.Fatalf("StartLoopback() error = %v", err)
	}
	defer func() { _ = lb.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, waitErr := lb.Wait(ctx)
	assertKind(t, waitErr, KindCanceled)
	if !errors.Is(waitErr, context.Canceled) {
		t.Errorf("Wait() error should wrap context.Canceled, got %v", waitErr)
	}
}

func TestStartLoopbackBindConflict(t *testing.T) {
	busy, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer func() { _ = busy.Close() }()

	f := newTestFlow("https://auth.openai.com")
	f.loopback = busy.Addr().String()
	_, startErr := f.StartLoopback("expected-state")
	assertKind(t, startErr, KindUnsupported)
}

func TestExchangeCodeSuccess(t *testing.T) {
	var gotForm url.Values
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotForm = r.PostForm
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "access-AAA",
				"refresh_token": "refresh-BBB",
				"id_token":      makeIDToken(t, "acct-12345"),
				"expires_in":    3600,
				"token_type":    "Bearer",
			})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	res, err := f.ExchangeCode(context.Background(), "auth-code-xyz", "verifier-secret")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	want := TokenResult{
		AccessToken:  "access-AAA",
		RefreshToken: "refresh-BBB",
		Expiry:       "2026-01-01T01:00:00Z",
		AccountID:    "acct-12345",
	}
	assertTokenResult(t, res, want)
	if gotForm.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", gotForm.Get("grant_type"))
	}
	if gotForm.Get("code") != "auth-code-xyz" {
		t.Errorf("authorization code form field mismatch")
	}
	if gotForm.Get("code_verifier") != "verifier-secret" {
		t.Errorf("code verifier form field mismatch")
	}
	if gotForm.Get("redirect_uri") != loopbackRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", gotForm.Get("redirect_uri"), loopbackRedirectURI)
	}
	if gotForm.Get("client_id") != clientID {
		t.Errorf("client_id = %q, want %q", gotForm.Get("client_id"), clientID)
	}
}

func TestExchangeCodeUpstreamError(t *testing.T) {
	// A non-2xx token exchange yields a 400 KindUpstream error that names the safe
	// error code yet never echoes the submitted code/verifier — and when the unsafe
	// error code itself carries credential-like values the Detail falls back to the
	// generic string instead of naming it.
	cases := []struct {
		name        string
		body        map[string]any
		code        string
		verifier    string
		wantGeneric bool
		secrets     []string
	}{
		{
			name:     "error_description without secrets",
			body:     map[string]any{"error": "invalid_grant", "error_description": "authorization code is invalid"},
			code:     "bad-code",
			verifier: "verifier-secret",
			secrets:  []string{"bad-code", "verifier-secret"},
		},
		{
			name:     "error_description echoes secrets",
			body:     map[string]any{"error": "invalid_grant", "error_description": "bad auth-code-xyz verifier-secret"},
			code:     "auth-code-xyz",
			verifier: "verifier-secret",
			secrets:  []string{"auth-code-xyz", "verifier-secret"},
		},
		{
			name:        "unsafe error code echoes secrets",
			body:        map[string]any{"error": "invalid_grant auth-code-xyz verifier-secret access-AAA acct-1"},
			code:        "auth-code-xyz",
			verifier:    "verifier-secret",
			wantGeneric: true,
			secrets:     []string{"auth-code-xyz", "verifier-secret", "access-AAA", "acct-1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAuthServer(t, map[string]http.HandlerFunc{
				tokenPath: func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusBadRequest, tc.body)
				},
			})
			defer srv.Close()

			f := newTestFlow(srv.URL)
			_, err := f.ExchangeCode(context.Background(), tc.code, tc.verifier)
			oaErr := assertRedactedUpstream(t, err, tc.secrets...)
			if oaErr.Status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", oaErr.Status)
			}
			if tc.wantGeneric {
				if oaErr.Detail != "OpenAI auth request failed" {
					t.Errorf("unsafe OAuth error code should use generic detail")
				}
			} else if !strings.Contains(oaErr.Detail, "invalid_grant") {
				t.Errorf("error detail does not name invalid_grant")
			}
		})
	}
}

func TestExchangeCodeMissingAccountID(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "access-AAA",
				"refresh_token": "refresh-BBB",
				"id_token":      "header.eyJzdWIiOiJubyJ9.sig", // claims without account id
				"expires_in":    3600,
			})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	_, err := f.ExchangeCode(context.Background(), "auth-code", "verifier-secret")
	assertKind(t, err, KindUpstream)
	if !strings.Contains(err.Error(), "account id") {
		t.Errorf("error = %v, want it to mention the missing account id", err)
	}
}

func TestExchangeCodeMissingRefreshToken(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "access-AAA",
				"id_token":     makeIDToken(t, "acct-1"),
				"expires_in":   3600,
			})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	_, err := f.ExchangeCode(context.Background(), "auth-code", "verifier-secret")
	assertKind(t, err, KindUpstream)
}

func TestExchangeCodeCanceled(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "x"})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.ExchangeCode(ctx, "auth-code", "verifier-secret")
	assertKind(t, err, KindCanceled)
}

func TestRevokeSuccess(t *testing.T) {
	var gotForm url.Values
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		revokePath: func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotForm = r.PostForm
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	if err := f.Revoke(context.Background(), "refresh-BBB"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if gotForm.Get("token") != "refresh-BBB" {
		t.Errorf("revoked token form field mismatch")
	}
	if gotForm.Get("token_type_hint") != "refresh_token" {
		t.Errorf("token_type_hint = %q, want refresh_token", gotForm.Get("token_type_hint"))
	}
	if gotForm.Get("client_id") != clientID {
		t.Errorf("client_id = %q, want %q", gotForm.Get("client_id"), clientID)
	}
}

func TestRevokePinnedToRevokeEndpoint(t *testing.T) {
	var gotPath string
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		revokePath: func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()

	if err := newTestFlow(srv.URL).Revoke(context.Background(), "refresh-BBB"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if gotPath != revokePath {
		t.Errorf("revoke path = %q, want %q", gotPath, revokePath)
	}
	if revokePath != "/oauth/revoke" {
		t.Errorf("revokePath = %q, want the RFC 7009 revocation endpoint", revokePath)
	}
}

func TestRevokeUpstreamError(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		revokePath: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": "bad refresh-BBB",
			})
		},
	})
	defer srv.Close()

	err := newTestFlow(srv.URL).Revoke(context.Background(), "refresh-BBB")
	oaErr := requireKind(t, err, KindUpstream)
	if oaErr.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", oaErr.Status)
	}
	assertNoSecrets(t, oaErr.Error(), "refresh-BBB")
}

func TestRevokeUnsupportedEndpoint(t *testing.T) {
	// A 404 models an origin without a revocation endpoint; logout treats any such
	// failure as "only local state removed" and still deletes locally.
	srv := newAuthServer(t, map[string]http.HandlerFunc{})
	defer srv.Close()

	err := newTestFlow(srv.URL).Revoke(context.Background(), "refresh-BBB")
	oaErr := requireKind(t, err, KindUpstream)
	if oaErr.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", oaErr.Status)
	}
}

func TestRevokeCanceled(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		revokePath: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	})
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := newTestFlow(srv.URL).Revoke(ctx, "refresh-BBB")
	assertKind(t, err, KindCanceled)
}

var redirectStatuses = []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect}

func redirectingAuthServer(t *testing.T, status int, body string) (origin *httptest.Server, originHits, destHits *atomic.Int32) {
	t.Helper()
	originHits, destHits = new(atomic.Int32), new(atomic.Int32)
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destHits.Add(1)
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	t.Cleanup(dest.Close)
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.Header().Set("Location", dest.URL+r.URL.Path)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	return origin, originHits, destHits
}

func assertRedirectRefused(t *testing.T, originHits, destHits *atomic.Int32) {
	t.Helper()
	if got := originHits.Load(); got != 1 {
		t.Errorf("origin requests = %d, want 1", got)
	}
	if got := destHits.Load(); got != 0 {
		t.Errorf("redirect destination received %d requests, want 0", got)
	}
}

func TestOAuthOperationsRefuseRedirects(t *testing.T) {
	ops := []struct {
		name string
		run  func(t *testing.T, f *Flow) int
	}{
		{"ExchangeCode", func(t *testing.T, f *Flow) int {
			_, err := f.ExchangeCode(context.Background(), "code-secret", "verifier-secret")
			return requireKind(t, err, KindUpstream).Status
		}},
		{"RequestDeviceCode", func(t *testing.T, f *Flow) int {
			_, err := f.RequestDeviceCode(context.Background())
			return requireKind(t, err, KindUpstream).Status
		}},
		{"PollDeviceToken", func(t *testing.T, f *Flow) int {
			_, err := f.PollDeviceToken(context.Background(), DeviceAuth{DeviceCode: "device-secret", ExpiresIn: 600})
			return requireKind(t, err, KindUpstream).Status
		}},
		{"EnsureFreshSession", func(t *testing.T, f *Flow) int {
			path := seedSession(t, priorSession(expiredExpiry))
			before := readBytes(t, path)
			_, err := f.EnsureFreshSession(context.Background(), path)
			rf := requireRefreshFailure(t, err)
			if readBytes(t, path) != before {
				t.Errorf("failed refresh changed the prior session bytes")
			}
			return rf.Status
		}},
		{"Revoke", func(t *testing.T, f *Flow) int {
			return requireKind(t, f.Revoke(context.Background(), "refresh-secret"), KindUpstream).Status
		}},
	}
	for _, op := range ops {
		for _, status := range redirectStatuses {
			t.Run(op.name+"/"+strconv.Itoa(status), func(t *testing.T) {
				srv, originHits, destHits := redirectingAuthServer(t, status, "")
				if got := op.run(t, newTestFlow(srv.URL)); got != status {
					t.Errorf("status = %d, want %d", got, status)
				}
				assertRedirectRefused(t, originHits, destHits)
			})
		}
	}
}

func TestPollDeviceTokenRedirectStopsPolling(t *testing.T) {
	for _, code := range []string{"authorization_pending", "slow_down", "expired_token"} {
		for _, status := range redirectStatuses {
			t.Run(code+"/"+strconv.Itoa(status), func(t *testing.T) {
				srv, originHits, destHits := redirectingAuthServer(t, status, `{"error":"`+code+`"}`)
				f := newTestFlow(srv.URL)
				sleeps := 0
				f.sleep = func(context.Context, time.Duration) error {
					sleeps++
					if sleeps > 1 {
						return context.Canceled
					}
					return nil
				}
				_, err := f.PollDeviceToken(context.Background(), DeviceAuth{DeviceCode: "device-secret", ExpiresIn: 600})
				if got := requireKind(t, err, KindUpstream).Status; got != status {
					t.Errorf("status = %d, want %d", got, status)
				}
				assertRedirectRefused(t, originHits, destHits)
			})
		}
	}
}

func TestAccountIDFromIDToken(t *testing.T) {
	id := makeIDToken(t, "acct-99")
	if got, ok := accountIDFromIDToken(id); !ok || got != "acct-99" {
		t.Errorf("namespaced claim account id mismatch: ok=%v", ok)
	}

	topLevel := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"chatgpt_account_id":"acct-top"}`)) + ".s"
	if got, ok := accountIDFromIDToken(topLevel); !ok || got != "acct-top" {
		t.Errorf("top-level claim account id mismatch: ok=%v", ok)
	}

	for _, bad := range []string{"", "not-a-jwt", "only.two"} {
		if _, ok := accountIDFromIDToken(bad); ok {
			t.Errorf("accountIDFromIDToken(%q) ok = true, want false", bad)
		}
	}
}

// --- shared helpers ---

func callbackURL(lb *Loopback, q url.Values) string {
	return "http://" + lb.listener.Addr().String() + loopbackCallbackPath + "?" + q.Encode()
}

// assertNoCapturedCode confirms a rejected callback yielded no code: Wait returns
// a timeout against an already-expired context rather than an authorization code.
func assertNoCapturedCode(t *testing.T, lb *Loopback) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	code, err := lb.Wait(ctx)
	if code != "" {
		t.Errorf("rejected callback still captured an authorization code")
	}
	assertKind(t, err, KindTimeout)
}

func assertKind(t *testing.T, err error, want FailureKind) {
	t.Helper()
	_ = requireKind(t, err, want)
}

func requireKind(t *testing.T, err error, want FailureKind) *Error {
	t.Helper()
	var oaErr *Error
	if !errors.As(err, &oaErr) {
		t.Fatalf("error is not *openaiauth.Error")
	}
	if oaErr.Kind != want {
		t.Fatalf("error kind = %q, want %q", oaErr.Kind, want)
	}
	return oaErr
}

// assertRedactedUpstream requires err to be a KindUpstream *Error whose printable
// form leaks none of secrets, returning it so callers can add the variant-specific
// Detail/Status checks. It folds the repeated "typed upstream + secret scan" shape
// shared by the device-poll and ExchangeCode redaction tests (dupl groups 20, 44)
// while leaving the safe-detail vs generic-detail distinction at each call site, so
// the generic-detail assertion for unsafe OAuth error codes is never hidden.
func assertRedactedUpstream(t *testing.T, err error, secrets ...string) *Error {
	t.Helper()
	oaErr := requireKind(t, err, KindUpstream)
	assertNoSecrets(t, oaErr.Error(), secrets...)
	return oaErr
}

func assertTokenResult(t *testing.T, got, want TokenResult) {
	t.Helper()
	if got.AccessToken != want.AccessToken {
		t.Errorf("access token mismatch")
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("refresh token mismatch")
	}
	if got.AccountID != want.AccountID {
		t.Errorf("account id mismatch")
	}
	if got.Expiry != want.Expiry {
		t.Errorf("expiry = %q, want %q", got.Expiry, want.Expiry)
	}
}

func assertNoSecrets(t *testing.T, s string, secrets ...string) {
	t.Helper()
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			t.Errorf("string contains a credential-like value")
		}
	}
}

func newAuthServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	return httptest.NewServer(mux)
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
