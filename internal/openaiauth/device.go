// OpenAI Codex OAuth device-authorization-grant primitives (RFC 8628) for the
// explicit interactive fallback when browser/loopback login cannot be used. These
// are primitives only: the auth login command owns the decision to invoke them and never starts them
// from non-interactive code. Storage is untouched.
package openaiauth

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

// minDevicePollInterval is the floor and default polling cadence (RFC 8628 §3.5
// default) used when the server omits or under-specifies interval.
const minDevicePollInterval = 5

// verificationHost is the only host a device verification URL may direct the user
// to. It is derived from the pinned auth origin so it cannot drift
// from where the flow actually sends login traffic.
var verificationHost = func() string {
	u, err := url.Parse(productionAuthBaseURL)
	if err != nil || u.Host == "" {
		panic("openaiauth: productionAuthBaseURL is not a valid origin")
	}
	return u.Host
}()

// verificationURLAllowed reports whether a device verification URL is safe to show
// the user: it must be a well-formed https URL on the pinned auth host. Pinning
// these user-facing URLs — not just the polling endpoint — keeps the device
// fallback from directing the user (and their user/device code) to a non-OpenAI
// origin returned in the upstream body.
func verificationURLAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host == verificationHost
}

// DeviceAuth is the device-authorization response. UserCode and the verification
// URIs are meant to be shown to the user; DeviceCode is the polling credential and
// must never be logged or printed. Interval is the requested poll
// cadence in seconds and ExpiresIn the lifetime of the device/user code pair.
type DeviceAuth struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	Interval                int64
	ExpiresIn               int64
}

// deviceAuthResponse is the subset of the device-authorization body consumed here.
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// RequestDeviceCode starts the device flow by requesting a device/user code pair
// from the pinned device endpoint. On success it returns the DeviceAuth to display
// to the user and poll with; on failure a typed Error. It writes no storage.
func (f *Flow) RequestDeviceCode(ctx context.Context) (DeviceAuth, error) {
	form := url.Values{}
	form.Set("client_id", f.clientID)
	form.Set("scope", oauthScopes)

	body, status, err := f.postForm(ctx, deviceCodePath, form)
	if err != nil {
		return DeviceAuth{}, err
	}
	if status < 200 || status >= 300 {
		return DeviceAuth{}, upstreamHTTPError(status, body)
	}
	var dr deviceAuthResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return DeviceAuth{}, &Error{Kind: KindUpstream, Detail: "could not parse OpenAI device authorization response"}
	}
	if dr.DeviceCode == "" || dr.UserCode == "" || dr.VerificationURI == "" {
		return DeviceAuth{}, &Error{Kind: KindUpstream, Detail: "OpenAI device authorization response missing required fields"}
	}
	if dr.ExpiresIn <= 0 {
		return DeviceAuth{}, &Error{Kind: KindUpstream, Detail: "OpenAI device authorization response missing expiry"}
	}
	// Origin-pin the user-facing verification URLs so the upstream body cannot point
	// the user at a non-OpenAI origin. verification_uri_complete is optional (RFC
	// 8628), so it is only checked when present. The error echoes no URL — the
	// complete variant can carry the user code.
	if !verificationURLAllowed(dr.VerificationURI) ||
		(dr.VerificationURIComplete != "" && !verificationURLAllowed(dr.VerificationURIComplete)) {
		return DeviceAuth{}, &Error{Kind: KindUpstream, Detail: "OpenAI device authorization response has unapproved verification URL"}
	}
	return DeviceAuth{
		DeviceCode:              dr.DeviceCode,
		UserCode:                dr.UserCode,
		VerificationURI:         dr.VerificationURI,
		VerificationURIComplete: dr.VerificationURIComplete,
		Interval:                dr.Interval,
		ExpiresIn:               dr.ExpiresIn,
	}, nil
}

// PollDeviceToken polls the token endpoint until the user authorizes the device,
// returning the storage-deferred TokenResult on success. It honors the
// server-requested interval (and slow_down back-off), the context (cancellation /
// deadline), and the device-code lifetime: a denied authorization is a typed
// KindUpstream failure and an expired or timed-out flow is KindTimeout. It writes
// no storage. The first poll happens only after one interval wait, per RFC 8628.
func (f *Flow) PollDeviceToken(ctx context.Context, da DeviceAuth) (TokenResult, error) {
	interval := da.Interval
	if interval < minDevicePollInterval {
		interval = minDevicePollInterval
	}
	deadline := f.now().Add(time.Duration(da.ExpiresIn) * time.Second)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", da.DeviceCode)
	form.Set("client_id", f.clientID)

	for {
		if err := f.sleep(ctx, time.Duration(interval)*time.Second); err != nil {
			return TokenResult{}, contextError(ctx)
		}
		if !f.now().Before(deadline) {
			return TokenResult{}, &Error{Kind: KindTimeout, Detail: "device login expired before authorization"}
		}

		body, status, err := f.postForm(ctx, tokenPath, form)
		if err != nil {
			return TokenResult{}, err
		}
		if status >= 200 && status < 300 {
			return f.parseTokenResponse(body)
		}
		if status >= 300 && status < 400 {
			return TokenResult{}, upstreamHTTPError(status, body)
		}

		var oe oauthErrorBody
		_ = json.Unmarshal(body, &oe)
		switch oe.ErrCode {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += minDevicePollInterval
			continue
		case "access_denied":
			return TokenResult{}, &Error{Kind: KindUpstream, Status: status, Detail: "device authorization was denied"}
		case "expired_token":
			return TokenResult{}, &Error{Kind: KindTimeout, Detail: "device code expired before authorization"}
		default:
			return TokenResult{}, upstreamHTTPError(status, body)
		}
	}
}
