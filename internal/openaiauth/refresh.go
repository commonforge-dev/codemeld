// OpenAI ChatGPT token refresh policy: a proactive refresh before a near-expiry
// turn and a one-shot reactive refresh after a model 401/403. Successful updates
// are persisted atomically through the shared settings path; any failure leaves
// the prior credential state byte-for-byte unchanged and yields a credential-free,
// actionable error. Refresh traffic targets only the pinned OpenAI auth origin.
package openaiauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/authstate"
)

// refreshSkew is the short window before access-token expiry within which a
// proactive refresh is triggered, so a turn does not start on a token that will
// expire mid-request. It is a fixed constant, never derived from
// wall-clock state, so tests pin near-expiry behavior deterministically; the
// reactive 401/403 path is the backstop for a token that expires after this point.
const refreshSkew = 2 * time.Minute

// renewMu serialises in-process renewal so a caller that waited re-reads the session
// the previous holder saved instead of re-sending a refresh token it may have rotated.
var renewMu sync.Mutex

var renewalWaiting = func() {}

// lockRenewal lets a waiter give up when its context ends; the abandoned Lock
// goroutine releases the mutex as soon as it acquires it.
func lockRenewal(ctx context.Context) error {
	if renewMu.TryLock() {
		return nil
	}
	renewalWaiting()
	acquired := make(chan struct{})
	go func() {
		renewMu.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
		return nil
	case <-ctx.Done():
		go func() {
			<-acquired
			renewMu.Unlock()
		}()
		return &RefreshFailure{cause: ctx.Err()}
	}
}

// refreshFailureMessage is the single credential-free, actionable text every
// refresh failure carries. It names the OpenAI ChatGPT provider and points the
// user at the recovery commands and never
// contains a token, refresh token, account id, header, cookie, or any other
// credential-derived value.
const refreshFailureMessage = "OpenAI ChatGPT token refresh failed; run `codemeld auth status` or `codemeld auth login openai-chatgpt`"

// ErrNoSession is returned by the refresh entrypoints when no usable ChatGPT
// session is stored (absent, unreadable, or corrupted) and so there is nothing to
// refresh. Turn dispatch surfaces it as "not logged in" and points the user
// at login. It carries no credential-derived value.
var ErrNoSession = errors.New("no usable OpenAI ChatGPT session; run `codemeld auth login openai-chatgpt`")

// RefreshFailure is the typed, credential-free error returned when a proactive or
// reactive ChatGPT token refresh cannot complete — an upstream non-2xx, a malformed
// or incomplete token response, a transport error, a context cancellation/deadline,
// or a failure to persist the refreshed state. Its message is always
// refreshFailureMessage, so it never contains a token, refresh token, account id,
// header, cookie, or any other credential-derived value. Status
// carries the upstream HTTP status when the refresh reached OpenAI (0 otherwise);
// cause is exposed only for errors.Is and is only ever a context sentinel
// (context.Canceled / context.DeadlineExceeded).
type RefreshFailure struct {
	Status int
	cause  error
}

func (e *RefreshFailure) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s (HTTP %d)", refreshFailureMessage, e.Status)
	}
	return refreshFailureMessage
}

// Unwrap exposes only the safe context cause so errors.Is(err, context.Canceled)
// and errors.Is(err, context.DeadlineExceeded) work for callers.
func (e *RefreshFailure) Unwrap() error { return e.cause }

// ShouldRefreshAfterStatus reports whether a model-request HTTP status warrants a
// single reactive refresh-and-retry: a 401 or 403. It is a pure
// predicate over the status value so the turn runner can decide whether to invoke
// RefreshNow without coupling this package to the turn-runner types; the one-shot
// retry itself is owned by the turn runner.
func ShouldRefreshAfterStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// EnsureFreshSession is the proactive refresh entrypoint, called before a ChatGPT request. It
// loads the stored ChatGPT session and, if the access token is already expired or
// within refreshSkew of expiry, refreshes it against the pinned auth origin and
// persists the result, returning the session to use for the turn. A still-fresh
// session is returned unchanged with no network call. It returns ErrNoSession when
// no usable session is stored and a *RefreshFailure when the refresh or its
// persistence fails (prior state left unchanged in that case).
func (f *Flow) EnsureFreshSession(ctx context.Context, settingsPath string) (authstate.Session, error) {
	if err := lockRenewal(ctx); err != nil {
		return authstate.Session{}, err
	}
	defer renewMu.Unlock()
	now := f.now()
	s, status, _ := authstate.Load(settingsPath, now)
	switch status {
	case authstate.StatusPresent:
		if !nearExpiry(s, now) {
			return s, nil
		}
	case authstate.StatusExpired:
		// Past expiry: refresh below.
	default: // StatusNone or StatusInvalid: nothing usable to refresh.
		return authstate.Session{}, ErrNoSession
	}
	return f.refreshAndPersist(ctx, settingsPath, s)
}

// RefreshNow is the reactive refresh entrypoint, called at most once per turn after
// a model 401/403 (see ShouldRefreshAfterStatus). It re-loads the stored session
// and forces a refresh regardless of the skew window — a 401/403 can mean the
// access token was revoked server-side while still appearing locally unexpired —
// persists the result, and returns the refreshed session. The turn runner owns the single
// retry of the model request on success and surfaces the error on failure. It
// returns ErrNoSession when no usable session is stored and a *RefreshFailure on
// refresh/persist failure (prior state unchanged).
func (f *Flow) RefreshNow(ctx context.Context, settingsPath string) (authstate.Session, error) {
	if err := lockRenewal(ctx); err != nil {
		return authstate.Session{}, err
	}
	defer renewMu.Unlock()
	s, status, _ := authstate.Load(settingsPath, f.now())
	if status == authstate.StatusNone || status == authstate.StatusInvalid {
		return authstate.Session{}, ErrNoSession
	}
	return f.refreshAndPersist(ctx, settingsPath, s)
}

// refreshAndPersist runs the refresh-token grant for s and, on success, writes the
// merged session through the shared settings path. On any refresh failure it
// returns the error without attempting a write, so the prior stored bytes are
// untouched; on a persist failure the atomic settings write leaves the prior bytes
// intact and the failure is reported as a credential-free *RefreshFailure.
func (f *Flow) refreshAndPersist(ctx context.Context, settingsPath string, s authstate.Session) (authstate.Session, error) {
	accessToken, rotatedRefresh, expiresAt, err := f.refreshTokens(ctx, s.RefreshToken)
	if err != nil {
		return authstate.Session{}, err
	}
	updated := s.ApplyRefresh(accessToken, rotatedRefresh, expiresAt)
	if _, _, werr := authstate.Write(settingsPath, updated); werr != nil {
		// Upstream refresh succeeded but the durable write did not; the atomic
		// rewrite leaves the prior session bytes intact, so treat the turn as a
		// refresh failure rather than proceeding on un-persisted credentials. The
		// persist error names only a path, never a credential, but is dropped in
		// favor of the constant message to keep the surface uniformly redacted.
		return authstate.Session{}, &RefreshFailure{}
	}
	return updated, nil
}

// refreshResponse is the subset of an OAuth refresh-token response this package
// consumes. refresh_token is optional: an absent or empty value means the prior
// refresh token stays valid and is preserved. The response is never
// expected to re-issue the account id, which is preserved from the prior session.
type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// refreshTokens performs the OAuth2 refresh_token grant at the pinned token
// endpoint, reusing the same origin-pinned, redaction-safe transport as login
// (postForm targets f.authBaseURL, which has no exported override).
// It returns the new access token, the rotated refresh token (empty when the
// upstream did not rotate it), and the new RFC3339 expiry. Every failure path
// returns a credential-free *RefreshFailure; the refresh token is sent only in the
// form body to the pinned origin and is never logged or embedded in an error.
func (f *Flow) refreshTokens(ctx context.Context, refreshToken string) (accessToken, rotatedRefresh, expiresAt string, err error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", f.clientID)

	body, status, perr := f.postForm(ctx, tokenPath, form)
	if perr != nil {
		// Convert the transport-level *Error into a credential-free *RefreshFailure,
		// preserving the upstream status and the safe context cause (so errors.Is
		// against context sentinels still matches) and dropping login-flavored text.
		var e *Error
		if errors.As(perr, &e) {
			return "", "", "", &RefreshFailure{Status: e.Status, cause: e.Unwrap()}
		}
		return "", "", "", &RefreshFailure{}
	}
	if status < 200 || status >= 300 {
		// Do not read the upstream body: it can echo submitted secrets, so only the
		// status is surfaced.
		return "", "", "", &RefreshFailure{Status: status}
	}

	var tok refreshResponse
	if jerr := json.Unmarshal(body, &tok); jerr != nil {
		return "", "", "", &RefreshFailure{}
	}
	if tok.AccessToken == "" || tok.ExpiresIn <= 0 {
		// A 2xx response missing the access token or a valid expiry is unusable; a
		// partial token must never become stored credential state.
		return "", "", "", &RefreshFailure{}
	}
	expiry := f.now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	return tok.AccessToken, tok.RefreshToken, expiry, nil
}

// nearExpiry reports whether s should be proactively refreshed at now: its expiry
// is already past or within refreshSkew. An unparseable expiry conservatively
// triggers a refresh rather than trusting an unreadable timestamp (Load classifies
// such state as invalid before it reaches here, so this is a defensive fallback).
func nearExpiry(s authstate.Session, now time.Time) bool {
	expiry, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return true
	}
	return !expiry.After(now.Add(refreshSkew))
}
