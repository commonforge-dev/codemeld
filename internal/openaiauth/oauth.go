// OpenAI ChatGPT (Codex) OAuth2 + PKCE login primitives: PKCE generation,
// authorize-URL construction, fixed-loopback callback capture, and token
// exchange, with typed cancellation/timeout/unsupported/upstream outcomes and a
// storage-deferred success payload. Storage is owned downstream; this
// package never writes credential state.
package openaiauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Production OpenAI Codex login constants. These are deliberately unexported and
// not user-overridable: project or global configuration must never redirect
// ChatGPT credentials to another origin. Tests
// point the flow at an httptest server through unexported fields on Flow, never
// through an exported option.
const (
	// clientID is OpenAI's Codex OAuth client id.
	clientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	// productionAuthBaseURL is the only origin login/token/refresh/logout traffic
	// is sent to.
	productionAuthBaseURL = "https://auth.openai.com"

	// loopbackAddr is the fixed local listener for the OAuth callback.
	// It is a local listener, not an outbound egress origin.
	loopbackAddr         = "localhost:1455"
	loopbackCallbackPath = "/auth/callback"
	// loopbackRedirectURI is the redirect_uri sent in the authorize request and
	// the token exchange; it is fixed to the loopback listener.
	loopbackRedirectURI = "http://localhost:1455/auth/callback"

	authorizePath  = "/oauth/authorize"
	tokenPath      = "/oauth/token"
	deviceCodePath = "/oauth/device/code"
	// revokePath is the RFC 7009 token-revocation endpoint on the pinned auth
	// origin used by logout's best-effort server-side revocation.
	revokePath = "/oauth/revoke"

	// oauthScopes requests an id token (account context), profile/email, and a
	// refresh token via offline_access.
	oauthScopes = "openid profile email offline_access"
)

// FailureKind classifies a login-flow failure without exposing any
// credential-derived value. It lets the wiring command map
// each outcome to an exit/UX path while leaving storage untouched.
type FailureKind string

const (
	// KindCanceled means the caller's context was canceled (user interrupt).
	KindCanceled FailureKind = "canceled"
	// KindTimeout means the caller's context deadline elapsed, or an upstream
	// device-code/session expired before the user completed login.
	KindTimeout FailureKind = "timeout"
	// KindUnsupported means the host cannot run this flow — typically the fixed
	// loopback port could not be bound — so the caller should fall back to the
	// device-code flow or the API-key provider rather than switch redirect URIs.
	KindUnsupported FailureKind = "unsupported_platform"
	// KindUpstream means OpenAI rejected or failed the login (bad/expired code,
	// denied authorization, a non-2xx token response, or an unreachable endpoint).
	KindUpstream FailureKind = "upstream_failure"
)

// Error is the single typed failure value every login primitive returns. Detail
// is a credential-free message safe to print; it never contains an access token,
// refresh token, authorization code, PKCE verifier, or account id.
// Status carries an upstream HTTP status when one applies (0 otherwise).
type Error struct {
	Kind   FailureKind
	Status int
	Detail string
	// cause is unwrapped for errors.Is and is set only to context.Canceled /
	// context.DeadlineExceeded or a local bind error — never to a value that could
	// carry credential content.
	cause error
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Kind, e.Detail, e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Detail)
}

// Unwrap exposes only the safe context/bind cause so errors.Is(err,
// context.Canceled) and errors.Is(err, context.DeadlineExceeded) work for callers.
func (e *Error) Unwrap() error { return e.cause }

// TokenResult is the storage-deferred success payload of a completed login. Its
// fields map one-to-one onto authstate.Session (access_token, refresh_token,
// expires_at, account_id) so the auth login command can persist them under auth.openai-chatgpt; this
// package returns the payload only and never writes settings. The
// token/account values must never be logged, printed, or embedded in errors.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	// Expiry is an RFC3339 timestamp matching authstate.Session.ExpiresAt.
	Expiry    string
	AccountID string
}

// Flow holds the login configuration. Production callers use NewFlow, which pins
// the auth origin and Codex client id; the httpClient, clock, sleep, base URL, and
// loopback address are unexported so only same-package tests can substitute them.
type Flow struct {
	httpClient  *http.Client
	now         func() time.Time
	sleep       func(context.Context, time.Duration) error
	authBaseURL string
	clientID    string
	loopback    string
}

// NewFlow returns a Flow pinned to the production OpenAI auth origin and Codex
// client id. There is no exported way to change the origin.
func NewFlow() *Flow {
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Flow{
		httpClient:  hc,
		now:         time.Now,
		sleep:       contextSleep,
		authBaseURL: productionAuthBaseURL,
		clientID:    clientID,
		loopback:    loopbackAddr,
	}
}

// PKCE is an RFC 7636 verifier/challenge pair. Method is always "S256".
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
}

// randReader is the entropy source for PKCE verifiers and login state. It is a
// package var so tests can make GeneratePKCE/GenerateState deterministic;
// production uses crypto/rand.
var randReader io.Reader = rand.Reader

// GeneratePKCE returns a fresh RFC 7636 S256 verifier/challenge pair. The verifier
// is 32 random bytes base64url-encoded (43 chars, within the 43-128 range); the
// challenge is the base64url-encoded SHA-256 of the verifier. Neither value is
// logged.
func GeneratePKCE() (PKCE, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return PKCE{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		Method:    "S256",
	}, nil
}

// GenerateState returns a random opaque CSRF state value for the authorize
// request, base64url-encoded from 32 random bytes.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", fmt.Errorf("generate login state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthorizeURL builds the deterministic authorize URL for the browser step: given
// the same state and PKCE pair it always returns the same URL. The redirect_uri is
// the fixed loopback callback and the origin is the pinned auth origin.
func (f *Flow) AuthorizeURL(state string, p PKCE) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", f.clientID)
	v.Set("redirect_uri", loopbackRedirectURI)
	v.Set("scope", oauthScopes)
	v.Set("code_challenge", p.Challenge)
	v.Set("code_challenge_method", p.Method)
	v.Set("state", state)
	return f.authBaseURL + authorizePath + "?" + v.Encode()
}

// Loopback is the bound OAuth callback listener. The caller must Close it on every
// path (success, error, cancel, timeout) to release the fixed port and avoid
// leaking the server goroutine.
type Loopback struct {
	expectedState string
	listener      net.Listener
	server        *http.Server
	resultCh      chan callbackResult
	sendOnce      sync.Once
	closeOnce     sync.Once
}

type callbackResult struct {
	code string
	err  error
}

// StartLoopback binds the fixed loopback listener and starts serving the OAuth
// callback. It binds before the authorize URL is opened so a port conflict is
// reported up front as a typed KindUnsupported failure rather than a silent
// redirect-URI switch. The handler accepts only a callback
// whose state matches expectedState and which carries a non-empty code; wrong-state
// or missing-code callbacks get a local 400 and never yield a code for exchange.
func (f *Flow) StartLoopback(expectedState string) (*Loopback, error) {
	ln, err := net.Listen("tcp", f.loopback)
	if err != nil {
		return nil, &Error{
			Kind:   KindUnsupported,
			Detail: "cannot bind loopback callback listener on " + f.loopback,
			cause:  err,
		}
	}
	lb := &Loopback{
		expectedState: expectedState,
		listener:      ln,
		resultCh:      make(chan callbackResult, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(loopbackCallbackPath, lb.handleCallback)
	lb.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = lb.server.Serve(ln) }()
	return lb, nil
}

func (l *Loopback) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("state") != l.expectedState {
		// Validate state before inspecting any OAuth error or code, so a wrong-state
		// or missing-state callback — including a forged error= one — cannot abort
		// the in-progress login: no result is captured and no token exchange runs.
		writeBrowserPage(w, http.StatusBadRequest, "Invalid login state. You can close this window.")
		return
	}
	if errCode := q.Get("error"); errCode != "" {
		// State-valid OAuth error: the user denied consent or OpenAI returned an
		// error on the redirect. The raw error_description is deliberately not
		// rendered (it can echo submitted secrets); only the error code is surfaced.
		writeBrowserPage(w, http.StatusBadRequest, "Login failed. You can close this window.")
		l.send(callbackResult{err: &Error{Kind: KindUpstream, Detail: oauthErrorDetail(errCode)}})
		return
	}
	code := q.Get("code")
	if code == "" {
		writeBrowserPage(w, http.StatusBadRequest, "Missing authorization code. You can close this window.")
		return
	}
	writeBrowserPage(w, http.StatusOK, "Login complete. You can close this window and return to codemeld.")
	l.send(callbackResult{code: code})
}

// send delivers the first observed result and ignores any later callback (e.g. a
// browser retry), so the buffered channel never blocks the handler.
func (l *Loopback) send(res callbackResult) {
	l.sendOnce.Do(func() { l.resultCh <- res })
}

// Wait blocks until a valid callback arrives, the context is canceled, or the
// context deadline elapses. It returns the captured authorization code, or a typed
// KindCanceled/KindTimeout/KindUpstream Error. It never performs token exchange.
func (l *Loopback) Wait(ctx context.Context) (string, error) {
	select {
	case res := <-l.resultCh:
		return res.code, res.err
	case <-ctx.Done():
		return "", contextError(ctx)
	}
}

// Close shuts the listener and server down. It is safe to call multiple times.
func (l *Loopback) Close() error {
	var err error
	l.closeOnce.Do(func() { err = l.server.Close() })
	return err
}

// ExchangeCode swaps an authorization code for tokens at the pinned token
// endpoint, completing the PKCE flow with verifier. On success it returns the
// storage-deferred TokenResult; on failure a typed Error and a zero TokenResult,
// so no partial credential state escapes. It never writes storage.
func (f *Flow) ExchangeCode(ctx context.Context, code, verifier string) (TokenResult, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", loopbackRedirectURI)
	form.Set("client_id", f.clientID)
	form.Set("code_verifier", verifier)
	return f.postToken(ctx, form)
}

// Revoke makes a best-effort RFC 7009 revocation of the ChatGPT session's refresh
// token at the pinned auth origin so logout can invalidate the grant server-side
// before deleting local state. Revoking the refresh token revokes the
// whole grant. It is best-effort: callers proceed with local deletion regardless of
// the result. A non-2xx response (including a 404 when the origin does not support
// revocation) returns a typed KindUpstream Error; a context cancellation/deadline
// returns KindCanceled/KindTimeout; any other transport failure returns a
// credential-free KindUpstream Error. The refresh token is sent only in the form
// body to the pinned origin and is never logged or embedded in the returned error.
func (f *Flow) Revoke(ctx context.Context, refreshToken string) error {
	form := url.Values{}
	form.Set("client_id", f.clientID)
	form.Set("token", refreshToken)
	form.Set("token_type_hint", "refresh_token")
	body, status, err := f.postForm(ctx, revokePath, form)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return upstreamHTTPError(status, body)
	}
	return nil
}

// postToken POSTs an x-www-form-urlencoded body to the pinned token endpoint and
// maps the response to a TokenResult or a typed Error. The form (which carries the
// code and verifier) is never logged.
func (f *Flow) postToken(ctx context.Context, form url.Values) (TokenResult, error) {
	body, status, err := f.postForm(ctx, tokenPath, form)
	if err != nil {
		return TokenResult{}, err
	}
	if status < 200 || status >= 300 {
		return TokenResult{}, upstreamHTTPError(status, body)
	}
	return f.parseTokenResponse(body)
}

// postForm issues the form POST and returns the raw body and status. A context
// cancellation/deadline becomes a typed KindCanceled/KindTimeout; any other
// transport failure becomes a credential-free KindUpstream error (the request URL
// names only the pinned endpoint path, never the form body).
func (f *Flow) postForm(ctx context.Context, path string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.authBaseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, &Error{Kind: KindUpstream, Detail: "could not build OpenAI auth request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := f.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, contextError(ctx)
		}
		return nil, 0, &Error{Kind: KindUpstream, Detail: "could not reach OpenAI auth endpoint"}
	}
	defer func() { _ = resp.Body.Close() }()
	b, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		if ctx.Err() != nil {
			return nil, 0, contextError(ctx)
		}
		return nil, resp.StatusCode, &Error{Kind: KindUpstream, Status: resp.StatusCode, Detail: "could not read OpenAI auth response"}
	}
	return b, resp.StatusCode, nil
}

// tokenResponse is the subset of the OAuth token response this package consumes.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// parseTokenResponse validates a 2xx token body and builds the TokenResult. Every
// required field — access token, refresh token, positive expiry, and an account id
// extracted from the id token — must be present; a missing one is a KindUpstream
// failure rather than a partially usable session. now is captured
// per call so expiry conversion is deterministic in tests.
func (f *Flow) parseTokenResponse(body []byte) (TokenResult, error) {
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return TokenResult{}, &Error{Kind: KindUpstream, Detail: "could not parse OpenAI token response"}
	}
	if tok.AccessToken == "" {
		return TokenResult{}, &Error{Kind: KindUpstream, Detail: "OpenAI token response missing access token"}
	}
	if tok.RefreshToken == "" {
		return TokenResult{}, &Error{Kind: KindUpstream, Detail: "OpenAI token response missing refresh token"}
	}
	if tok.ExpiresIn <= 0 {
		return TokenResult{}, &Error{Kind: KindUpstream, Detail: "OpenAI token response missing token expiry"}
	}
	accountID, ok := accountIDFromIDToken(tok.IDToken)
	if !ok {
		return TokenResult{}, &Error{Kind: KindUpstream, Detail: "OpenAI token response missing account id"}
	}
	expiry := f.now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	return TokenResult{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       expiry,
		AccountID:    accountID,
	}, nil
}

// accountIDFromIDToken extracts the ChatGPT account id from an OIDC id token's
// claims without verifying its signature (the token arrived directly from the
// pinned token endpoint over TLS). It reads the chatgpt_account_id field from the
// "https://api.openai.com/auth" namespaced claim used by the Codex flow, falling
// back to a top-level chatgpt_account_id claim. It reports ok=false when no account
// id is present.
func accountIDFromIDToken(idToken string) (string, bool) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Auth struct {
			ChatGPTAccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
		ChatGPTAccountID string `json:"chatgpt_account_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if claims.Auth.ChatGPTAccountID != "" {
		return claims.Auth.ChatGPTAccountID, true
	}
	if claims.ChatGPTAccountID != "" {
		return claims.ChatGPTAccountID, true
	}
	return "", false
}

// oauthErrorBody is the standard OAuth error response shape (RFC 6749 §5.2 / RFC
// 8628). Only the error code is consumed; error_description is deliberately not
// parsed, because an upstream can echo submitted secrets (authorization codes,
// PKCE verifiers, tokens, device codes) back into it.
type oauthErrorBody struct {
	ErrCode string `json:"error"`
}

// upstreamHTTPError builds a KindUpstream Error from a non-2xx token/device
// response, surfacing only the standard OAuth error code (or the status alone) so
// no upstream response text — which can echo submitted secrets — leaks into the
// error.
func upstreamHTTPError(status int, body []byte) *Error {
	var oe oauthErrorBody
	_ = json.Unmarshal(body, &oe)
	return &Error{Kind: KindUpstream, Status: status, Detail: oauthErrorDetail(oe.ErrCode)}
}

// oauthErrorDetail renders a safe one-line message from a known OAuth error
// code, falling back to a generic message when the code is absent or non-standard.
// The upstream error and error_description fields can echo back submitted secrets,
// so only whitelisted standard codes reach printable Error.Detail.
func oauthErrorDetail(code string) string {
	switch code {
	case "invalid_request",
		"invalid_client",
		"invalid_grant",
		"unauthorized_client",
		"unsupported_grant_type",
		"invalid_scope",
		"server_error",
		"temporarily_unavailable",
		"access_denied",
		"authorization_pending",
		"slow_down",
		"expired_token":
		return "OpenAI auth error: " + code
	default:
		return "OpenAI auth request failed"
	}
}

// contextError maps a context's error to a typed KindCanceled or KindTimeout
// Error, preserving the cause so errors.Is still matches the context sentinel.
func contextError(ctx context.Context) *Error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &Error{Kind: KindTimeout, Detail: "login timed out", cause: context.DeadlineExceeded}
	}
	return &Error{Kind: KindCanceled, Detail: "login canceled", cause: context.Canceled}
}

// contextSleep waits for d or the context, whichever comes first, returning the
// context error if it is canceled/expired during the wait.
func contextSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func writeBrowserPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}
