// Tests for the OpenAI ChatGPT token refresh policy: no proactive refresh outside
// the skew window, proactive refresh inside skew and after expiry, optional
// refresh-token rotation, account_id and unrelated-state preservation, origin
// pinning, credential-free errors, prior-bytes-unchanged on failure, and the
// one-shot reactive 401/403 status handling.
package openaiauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/fsutil"
)

// Expiries are expressed relative to fixedNow (2026-01-01T00:00:00Z, from the
// oauth test Flow) so proactive skew decisions are deterministic.
var (
	freshExpiry   = fixedNow.Add(time.Hour).Format(time.RFC3339)   // outside the 2m skew
	skewExpiry    = fixedNow.Add(time.Minute).Format(time.RFC3339) // inside the skew, not yet expired
	expiredExpiry = fixedNow.Add(-time.Hour).Format(time.RFC3339)  // already past
	refreshedExp  = fixedNow.Add(time.Hour).Format(time.RFC3339)   // expires_in=3600 from fixedNow
)

func priorSession(expiry string) authstate.Session {
	return authstate.Session{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    expiry,
		AccountID:    "acct-keep",
	}
}

// seedSession writes a session to a fresh temp settings file and returns its path.
func seedSession(t *testing.T, s authstate.Session) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.yaml")
	if _, _, err := authstate.Write(path, s); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return path
}

func readBytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	return string(b)
}

// refreshTokenServer returns a Flow whose token endpoint records the received form
// and the call count, then replies 200 with body.
func refreshTokenServer(t *testing.T, gotForm *url.Values, hits *int, body map[string]any) *Flow {
	t.Helper()
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			*gotForm = r.PostForm
			*hits++
			writeJSON(w, http.StatusOK, body)
		},
	})
	t.Cleanup(srv.Close)
	return newTestFlow(srv.URL)
}

func requireRefreshFailure(t *testing.T, err error) *RefreshFailure {
	t.Helper()
	var rf *RefreshFailure
	if !errors.As(err, &rf) {
		t.Fatalf("error is not *RefreshFailure: %v", err)
	}
	return rf
}

func assertRefreshFailure(t *testing.T, err error) {
	t.Helper()
	_ = requireRefreshFailure(t, err)
}

func assertActionableMessage(t *testing.T, msg string) {
	t.Helper()
	for _, want := range []string{"OpenAI ChatGPT", "codemeld auth status", "codemeld auth login openai-chatgpt"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not mention %q", msg, want)
		}
	}
}

func TestEnsureFreshSession_NoRefreshOutsideSkew(t *testing.T) {
	prior := priorSession(freshExpiry)
	path := seedSession(t, prior)
	before := readBytes(t, path)

	var gotForm url.Values
	hits := 0
	f := refreshTokenServer(t, &gotForm, &hits, map[string]any{"access_token": "new", "expires_in": 3600})

	got, err := f.EnsureFreshSession(context.Background(), path)
	if err != nil {
		t.Fatalf("EnsureFreshSession() error = %v", err)
	}
	if hits != 0 {
		t.Errorf("fresh session triggered %d refresh calls, want 0", hits)
	}
	if got != prior {
		t.Errorf("fresh session was modified:\n got = %+v\nwant = %+v", got, prior)
	}
	if readBytes(t, path) != before {
		t.Errorf("fresh session rewrote the settings file")
	}
}

func TestEnsureFreshSession_RefreshInsideSkew(t *testing.T) {
	assertProactiveRefresh(t, skewExpiry)
}

func TestEnsureFreshSession_RefreshAfterExpiry(t *testing.T) {
	assertProactiveRefresh(t, expiredExpiry)
}

// assertProactiveRefresh seeds a session at the given expiry, refreshes it, and
// asserts the access token and expiry update while account_id is preserved and the
// new state is persisted.
func assertProactiveRefresh(t *testing.T, expiry string) {
	t.Helper()
	path := seedSession(t, priorSession(expiry))

	var gotForm url.Values
	hits := 0
	f := refreshTokenServer(t, &gotForm, &hits, map[string]any{
		"access_token":  "fresh-access",
		"refresh_token": "fresh-refresh",
		"expires_in":    3600,
	})

	got, err := f.EnsureFreshSession(context.Background(), path)
	if err != nil {
		t.Fatalf("EnsureFreshSession() error = %v", err)
	}
	if hits != 1 {
		t.Fatalf("refresh calls = %d, want 1", hits)
	}
	if gotForm.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", gotForm.Get("grant_type"))
	}
	if gotForm.Get("refresh_token") != "old-refresh" {
		t.Errorf("refresh_token form field mismatch")
	}
	if gotForm.Get("client_id") != clientID {
		t.Errorf("client_id = %q, want %q", gotForm.Get("client_id"), clientID)
	}
	want := authstate.Session{AccessToken: "fresh-access", RefreshToken: "fresh-refresh", ExpiresAt: refreshedExp, AccountID: "acct-keep"}
	if got != want {
		t.Fatalf("refreshed session:\n got = %+v\nwant = %+v", got, want)
	}
	stored, status, _ := authstate.Load(path, fixedNow)
	if status != authstate.StatusPresent || stored != want {
		t.Fatalf("persisted session = (%q, %+v), want (present, %+v)", status, stored, want)
	}
}

func TestEnsureFreshSession_RefreshTokenNotRotatedPreservesPrior(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))

	var gotForm url.Values
	hits := 0
	// Response omits refresh_token: the prior refresh token must be preserved.
	f := refreshTokenServer(t, &gotForm, &hits, map[string]any{
		"access_token": "fresh-access",
		"expires_in":   3600,
	})

	got, err := f.EnsureFreshSession(context.Background(), path)
	if err != nil {
		t.Fatalf("EnsureFreshSession() error = %v", err)
	}
	if got.RefreshToken != "old-refresh" {
		t.Errorf("refresh token = %q, want preserved old-refresh", got.RefreshToken)
	}
	if got.AccessToken != "fresh-access" || got.AccountID != "acct-keep" {
		t.Errorf("non-rotated refresh lost other fields: %+v", got)
	}
}

func TestEnsureFreshSession_PreservesUnrelatedSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.yaml")
	const unrelated = "# managed settings\n" +
		"provider:\n  openai:\n    base_url: https://api.openai.com/v1\n    api_key: sk-KEEP\n" +
		"permissions: []\n"
	if err := os.WriteFile(path, []byte(unrelated+
		"auth:\n  openai-chatgpt:\n    access_token: old-access\n    refresh_token: old-refresh\n"+
		"    expires_at: \""+expiredExpiry+"\"\n    account_id: acct-keep\n"), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	var gotForm url.Values
	hits := 0
	f := refreshTokenServer(t, &gotForm, &hits, map[string]any{
		"access_token":  "fresh-access",
		"refresh_token": "fresh-refresh",
		"expires_in":    3600,
	})

	if _, err := f.EnsureFreshSession(context.Background(), path); err != nil {
		t.Fatalf("EnsureFreshSession() error = %v", err)
	}
	got := readBytes(t, path)
	for _, keep := range []string{"# managed settings", "api_key: sk-KEEP", "permissions:", "base_url: https://api.openai.com/v1", "account_id: acct-keep"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("refresh dropped unrelated content %q:\n%s", keep, got)
		}
	}
	if strings.Contains(got, "old-access") {
		t.Errorf("refresh left the stale access token in the file")
	}
	if !strings.Contains(got, "fresh-access") {
		t.Errorf("refresh did not persist the new access token")
	}
}

func TestEnsureFreshSession_UpstreamErrorLeavesPriorStateUnchanged(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))
	before := readBytes(t, path)

	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, _ *http.Request) {
			// The upstream echoes the submitted refresh token back in
			// error_description; it must never reach the printable error.
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_grant",
				"error_description": "bad old-refresh old-access acct-keep",
			})
		},
	})
	defer srv.Close()

	_, err := newTestFlow(srv.URL).EnsureFreshSession(context.Background(), path)
	rf := requireRefreshFailure(t, err)
	if rf.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rf.Status)
	}
	assertNoSecrets(t, rf.Error(), "old-refresh", "old-access", "acct-keep", "invalid_grant")
	assertActionableMessage(t, rf.Error())
	if readBytes(t, path) != before {
		t.Errorf("failed refresh changed the prior session bytes")
	}
}

func TestEnsureFreshSession_MalformedAndIncompleteResponsesFail(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not json", "not-json"},
		{"missing access token", `{"refresh_token":"r","expires_in":3600}`},
		{"non-positive expiry", `{"access_token":"a","expires_in":0}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := seedSession(t, priorSession(expiredExpiry))
			before := readBytes(t, path)
			srv := newAuthServer(t, map[string]http.HandlerFunc{
				tokenPath: func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(tc.body))
				},
			})
			defer srv.Close()

			_, err := newTestFlow(srv.URL).EnsureFreshSession(context.Background(), path)
			assertRefreshFailure(t, err)
			if readBytes(t, path) != before {
				t.Errorf("unusable response changed the prior session bytes")
			}
		})
	}
}

func TestEnsureFreshSession_CanceledLeavesPriorStateUnchanged(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))
	before := readBytes(t, path)

	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "x", "expires_in": 1})
		},
	})
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestFlow(srv.URL).EnsureFreshSession(ctx, path)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled, got %v", err)
	}
	assertRefreshFailure(t, err)
	if readBytes(t, path) != before {
		t.Errorf("canceled refresh changed the prior session bytes")
	}
}

func TestEnsureFreshSession_NoSession(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "settings.yaml")
	if _, err := newTestFlow("https://auth.openai.com").EnsureFreshSession(context.Background(), missing); !errors.Is(err, ErrNoSession) {
		t.Errorf("absent session error = %v, want ErrNoSession", err)
	}
}

func TestRefreshNow_ForcesRefreshOnFreshSession(t *testing.T) {
	// A 401/403 can fire on a locally-unexpired token; the reactive path must
	// refresh regardless of the skew window.
	path := seedSession(t, priorSession(freshExpiry))

	var gotForm url.Values
	hits := 0
	f := refreshTokenServer(t, &gotForm, &hits, map[string]any{
		"access_token":  "fresh-access",
		"refresh_token": "fresh-refresh",
		"expires_in":    3600,
	})

	got, err := f.RefreshNow(context.Background(), path)
	if err != nil {
		t.Fatalf("RefreshNow() error = %v", err)
	}
	if hits != 1 {
		t.Fatalf("refresh calls = %d, want 1", hits)
	}
	if got.AccessToken != "fresh-access" {
		t.Errorf("reactive refresh did not update the access token: %+v", got)
	}
}

func gatedRefreshServer(t *testing.T) (f *Flow, entered, release chan struct{}, awaitWaiter func(), sent func() []string) {
	t.Helper()
	entered, release = make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var tokens []string
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			mu.Lock()
			tokens = append(tokens, r.PostForm.Get("refresh_token"))
			first := len(tokens) == 1
			mu.Unlock()
			if first {
				close(entered)
				<-release
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600,
			})
		},
	})
	t.Cleanup(srv.Close)
	waiting := make(chan struct{}, 1)
	renewalWaiting = func() { waiting <- struct{}{} }
	t.Cleanup(func() { renewalWaiting = func() {} })
	awaitWaiter = func() {
		t.Helper()
		select {
		case <-waiting:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("competing renewal never waited on the renewal lock")
		}
	}
	sent = func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(tokens)
	}
	return newTestFlow(srv.URL), entered, release, awaitWaiter, sent
}

func TestEnsureFreshSession_ConcurrentRenewalSendsOnePOST(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))
	f, entered, release, awaitWaiter, sent := gatedRefreshServer(t)

	results := make([]authstate.Session, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = f.EnsureFreshSession(context.Background(), path)
		}()
	}
	<-entered
	awaitWaiter()
	close(release)
	wg.Wait()

	if got := sent(); !slices.Equal(got, []string{"old-refresh"}) {
		t.Fatalf("refresh POSTs carried %v, want exactly one with old-refresh", got)
	}
	want := authstate.Session{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresAt: refreshedExp, AccountID: "acct-keep"}
	for i := range 2 {
		if errs[i] != nil || results[i] != want {
			t.Errorf("caller %d = (%+v, %v), want (%+v, nil)", i, results[i], errs[i], want)
		}
	}
}

func TestRefreshNow_WaitsAndUsesRenewedRefreshToken(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))
	f, entered, release, awaitWaiter, sent := gatedRefreshServer(t)

	done := make(chan error, 2)
	go func() {
		_, err := f.EnsureFreshSession(context.Background(), path)
		done <- err
	}()
	<-entered
	go func() {
		_, err := f.RefreshNow(context.Background(), path)
		done <- err
	}()
	awaitWaiter()
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("renewal error = %v", err)
		}
	}

	if got := sent(); !slices.Equal(got, []string{"old-refresh", "new-refresh"}) {
		t.Fatalf("refresh POSTs carried %v, want [old-refresh new-refresh]", got)
	}
}

func TestEnsureFreshSession_WaiterHonorsDeadline(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))
	f, entered, release, _, sent := gatedRefreshServer(t)

	first := make(chan error, 1)
	go func() {
		_, err := f.EnsureFreshSession(context.Background(), path)
		first <- err
	}()
	<-entered
	defer func() {
		close(release)
		if err := <-first; err != nil {
			t.Errorf("held renewal error = %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := f.EnsureFreshSession(ctx, path)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter error = %v, want context.DeadlineExceeded", err)
	}
	assertRefreshFailure(t, err)
	if got := sent(); !slices.Equal(got, []string{"old-refresh"}) {
		t.Fatalf("refresh POSTs carried %v, want only the held one", got)
	}
}

func TestRefreshNow_NoSession(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "settings.yaml")
	if _, err := newTestFlow("https://auth.openai.com").RefreshNow(context.Background(), missing); !errors.Is(err, ErrNoSession) {
		t.Errorf("RefreshNow absent session error = %v, want ErrNoSession", err)
	}
}

func TestShouldRefreshAfterStatus(t *testing.T) {
	cases := map[int]bool{
		http.StatusUnauthorized:        true,
		http.StatusForbidden:           true,
		http.StatusOK:                  false,
		http.StatusInternalServerError: false,
		http.StatusTooManyRequests:     false,
		http.StatusBadRequest:          false,
	}
	for status, want := range cases {
		if got := ShouldRefreshAfterStatus(status); got != want {
			t.Errorf("ShouldRefreshAfterStatus(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestRefreshPinnedToTokenEndpoint(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))
	var gotPath string
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "a", "refresh_token": "r", "expires_in": 3600})
		},
	})
	defer srv.Close()

	if _, err := newTestFlow(srv.URL).EnsureFreshSession(context.Background(), path); err != nil {
		t.Fatalf("EnsureFreshSession() error = %v", err)
	}
	if gotPath != tokenPath {
		t.Errorf("refresh path = %q, want %q", gotPath, tokenPath)
	}
	// There is no exported way to point refresh at another origin: NewFlow pins it.
	if NewFlow().authBaseURL != productionAuthBaseURL {
		t.Errorf("NewFlow auth origin = %q, want pinned production origin", NewFlow().authBaseURL)
	}
}

func TestRefreshFailureMessageRedactedAndActionable(t *testing.T) {
	assertActionableMessage(t, (&RefreshFailure{Status: 401}).Error())
	if got := (&RefreshFailure{}).Error(); got != refreshFailureMessage {
		t.Errorf("zero-status message = %q, want %q", got, refreshFailureMessage)
	}
}

// TestEnsureFreshSession_PersistFailureLeavesPriorStateUnchanged is the refresh
// arm of "storage write failure" failure test (Step 2/4): the upstream
// refresh succeeds but the durable settings write fails. The turn must then be
// treated as a refresh failure rather than proceeding on un-persisted credentials,
// and the atomic write must leave the prior session bytes byte-for-byte unchanged.
// A local persist failure carries no upstream status (0) and reuses
// the credential-free, actionable refresh-failure message.
func TestEnsureFreshSession_PersistFailureLeavesPriorStateUnchanged(t *testing.T) {
	path := seedSession(t, priorSession(expiredExpiry))
	before := readBytes(t, path)

	var gotForm url.Values
	hits := 0
	f := refreshTokenServer(t, &gotForm, &hits, map[string]any{
		"access_token":  "fresh-access",
		"refresh_token": "fresh-refresh",
		"expires_in":    3600,
	})

	// Force the post-refresh atomic write to fail. Installed after the session is
	// seeded (its write already happened) and after the fake server is built (which
	// performs no file fsync), so only the refresh's own persist hits the failure.
	sentinel := errors.New("forced temp-file sync failure")
	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	_, err := f.EnsureFreshSession(context.Background(), path)
	rf := requireRefreshFailure(t, err)
	if rf.Status != 0 {
		t.Errorf("status = %d, want 0 (a local persist failure has no upstream status)", rf.Status)
	}
	assertActionableMessage(t, rf.Error())
	assertNoSecrets(t, rf.Error(), "fresh-access", "fresh-refresh", "old-access", "old-refresh", "acct-keep")
	if hits != 1 {
		t.Errorf("upstream refresh calls = %d, want 1 (the failure is the persist, not the grant)", hits)
	}

	restore() // restore the real fsync so the verifying read reflects the on-disk bytes
	if got := readBytes(t, path); got != before {
		t.Errorf("failed persist changed the prior session bytes:\nbefore=%q\nafter=%q", before, got)
	}
}
