// Tests for the device-authorization-grant primitives: device-code request,
// polling through authorization_pending/slow_down to success, denied/expired/
// upstream outcomes, and context cancellation/deadline handling, all against fake
// servers with no real egress and no storage writes.
package openaiauth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestRequestDeviceCodeSuccess(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		deviceCodePath: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"device_code":               "dev-CODE",
				"user_code":                 "WXYZ-1234",
				"verification_uri":          "https://auth.openai.com/device",
				"verification_uri_complete": "https://auth.openai.com/device?user_code=WXYZ-1234",
				"expires_in":                900,
				"interval":                  5,
			})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	da, err := f.RequestDeviceCode(context.Background())
	if err != nil {
		t.Fatalf("RequestDeviceCode() error = %v", err)
	}
	if da.DeviceCode != "dev-CODE" {
		t.Errorf("device code mismatch")
	}
	if da.UserCode != "WXYZ-1234" {
		t.Errorf("user code mismatch")
	}
	if da.VerificationURI != "https://auth.openai.com/device" {
		t.Errorf("VerificationURI = %q", da.VerificationURI)
	}
	if da.Interval != 5 || da.ExpiresIn != 900 {
		t.Errorf("Interval/ExpiresIn = %d/%d, want 5/900", da.Interval, da.ExpiresIn)
	}
}

func TestRequestDeviceCodeRejectsForeignVerificationURL(t *testing.T) {
	// A well-formed body whose verification URLs point at a non-OpenAI origin must be
	// rejected before any device/user code is returned, whether the foreign origin is
	// in verification_uri or only in the optional _complete variant.
	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "foreign verification_uri",
			body: map[string]any{
				"device_code":               "dev",
				"user_code":                 "WXYZ",
				"verification_uri":          "https://evil.example/device",
				"verification_uri_complete": "https://evil.example/device?user_code=WXYZ",
				"expires_in":                900,
			},
		},
		{
			name: "pinned verification_uri but foreign _complete",
			body: map[string]any{
				"device_code":               "dev",
				"user_code":                 "WXYZ",
				"verification_uri":          "https://auth.openai.com/device",
				"verification_uri_complete": "https://evil.example/device?user_code=WXYZ",
				"expires_in":                900,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAuthServer(t, map[string]http.HandlerFunc{
				deviceCodePath: func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, http.StatusOK, tc.body)
				},
			})
			defer srv.Close()

			f := newTestFlow(srv.URL)
			da, err := f.RequestDeviceCode(context.Background())
			assertKind(t, err, KindUpstream)
			if da != (DeviceAuth{}) {
				t.Errorf("rejected response still returned non-zero DeviceAuth")
			}
		})
	}
}

func TestRequestDeviceCodeUpstreamError(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		deviceCodePath: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client"})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	_, err := f.RequestDeviceCode(context.Background())
	assertKind(t, err, KindUpstream)
}

func TestPollDeviceTokenSuccessAfterPending(t *testing.T) {
	calls := 0
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls < 3 {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "access-AAA",
				"refresh_token": "refresh-BBB",
				"id_token":      makeIDToken(t, "acct-dev"),
				"expires_in":    3600,
			})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	res, err := f.PollDeviceToken(context.Background(), DeviceAuth{DeviceCode: "dev-CODE", Interval: 1, ExpiresIn: 900})
	if err != nil {
		t.Fatalf("PollDeviceToken() error = %v", err)
	}
	assertTokenResult(t, res, TokenResult{
		AccessToken:  "access-AAA",
		RefreshToken: "refresh-BBB",
		Expiry:       "2026-01-01T01:00:00Z",
		AccountID:    "acct-dev",
	})
	if calls != 3 {
		t.Errorf("token endpoint called %d times, want 3 (two pending + success)", calls)
	}
}

func TestPollDeviceTokenSlowDownIncreasesInterval(t *testing.T) {
	var slept []time.Duration
	calls := 0
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "slow_down"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  "a",
				"refresh_token": "r",
				"id_token":      makeIDToken(t, "acct"),
				"expires_in":    3600,
			})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	f.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		return ctx.Err()
	}
	if _, err := f.PollDeviceToken(context.Background(), DeviceAuth{DeviceCode: "d", Interval: 5, ExpiresIn: 900}); err != nil {
		t.Fatalf("PollDeviceToken() error = %v", err)
	}
	if len(slept) != 2 {
		t.Fatalf("sleep called %d times, want 2", len(slept))
	}
	if slept[0] != 5*time.Second {
		t.Errorf("first interval = %v, want 5s", slept[0])
	}
	if slept[1] != 10*time.Second {
		t.Errorf("interval after slow_down = %v, want 10s", slept[1])
	}
}

func TestPollDeviceTokenOutcome(t *testing.T) {
	cases := []struct {
		name      string
		errorCode string
		wantKind  FailureKind
	}{
		{name: "access_denied", errorCode: "access_denied", wantKind: KindUpstream},
		{name: "expired_token", errorCode: "expired_token", wantKind: KindTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAuthServer(t, map[string]http.HandlerFunc{
				tokenPath: func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": tc.errorCode})
				},
			})
			defer srv.Close()

			f := newTestFlow(srv.URL)
			_, err := f.PollDeviceToken(context.Background(), DeviceAuth{DeviceCode: "d", Interval: 1, ExpiresIn: 900})
			assertKind(t, err, tc.wantKind)
		})
	}
}

func TestPollDeviceTokenErrorRedacted(t *testing.T) {
	// A device-token error must never echo the device code, an access token, or the
	// account id, whether the credential-like values arrive in error_description or in
	// an unsafe error code (which forces the generic Detail).
	cases := []struct {
		name        string
		body        map[string]any
		wantGeneric bool
		secrets     []string
	}{
		{
			name:        "error_description echoes secrets",
			body:        map[string]any{"error": "invalid_grant", "error_description": "bad dev-CODE token-AAA acct-dev"},
			wantGeneric: false,
			secrets:     []string{"dev-CODE", "token-AAA", "acct-dev"},
		},
		{
			name:        "unsafe error code echoes secrets",
			body:        map[string]any{"error": "invalid_grant dev-CODE access-AAA acct-dev"},
			wantGeneric: true,
			secrets:     []string{"dev-CODE", "access-AAA", "acct-dev"},
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
			_, err := f.PollDeviceToken(context.Background(), DeviceAuth{DeviceCode: "dev-CODE", Interval: 1, ExpiresIn: 900})
			oaErr := assertRedactedUpstream(t, err, tc.secrets...)
			if tc.wantGeneric && oaErr.Detail != "OpenAI auth request failed" {
				t.Errorf("unsafe OAuth error code should use generic detail")
			}
		})
	}
}

func TestPollDeviceTokenContextCanceled(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.PollDeviceToken(ctx, DeviceAuth{DeviceCode: "d", Interval: 1, ExpiresIn: 900})
	assertKind(t, err, KindCanceled)
}

func TestPollDeviceTokenDeadlineExpires(t *testing.T) {
	srv := newAuthServer(t, map[string]http.HandlerFunc{
		tokenPath: func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
		},
	})
	defer srv.Close()

	f := newTestFlow(srv.URL)
	// Advance the clock past the device-code lifetime so the loop's own deadline
	// check (not the context) ends polling with a timeout.
	current := fixedNow
	f.now = func() time.Time {
		current = current.Add(30 * time.Second)
		return current
	}
	f.sleep = func(context.Context, time.Duration) error { return nil }
	_, err := f.PollDeviceToken(context.Background(), DeviceAuth{DeviceCode: "d", Interval: 1, ExpiresIn: 10})
	assertKind(t, err, KindTimeout)
}
