// Parse, classify, and persist the OpenAI ChatGPT session stored as plaintext
// under auth.openai-chatgpt in the global settings file.
package authstate

import (
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fserrors"
)

// Settings keys for the nested auth.openai-chatgpt session state.
const (
	authKey    = "auth"
	chatGPTKey = "openai-chatgpt"
)

// Status classifies a loaded OpenAI ChatGPT session without exposing any
// credential-derived value. Only StatusPresent denotes a usable
// session; every other value is unauthenticated.
type Status string

const (
	// StatusNone means no session is stored: the settings file, the auth block,
	// or the openai-chatgpt entry is absent.
	StatusNone Status = "no_local_session"
	// StatusPresent means a complete, non-expired session is stored.
	StatusPresent Status = "local_session_present"
	// StatusExpired means the session parses but its expiry is in the past. The
	// parsed Session (including its refresh token) is returned so a refresh can
	// be attempted.
	StatusExpired Status = "local_session_expired"
	// StatusInvalid means the stored state is unusable: corrupted/unreadable
	// file, wrong shape, or a missing, wrong-type, empty, or non-RFC3339 field.
	// Treated as unauthenticated and never as a partially usable session.
	StatusInvalid Status = "local_session_invalid"
)

// Session is the parsed auth.openai-chatgpt state. Its fields hold the stored
// plaintext credential values verbatim; they must never be logged, printed,
// embedded in errors, or written to events or session records.
// ExpiresAt is the stored RFC3339 string, preserved exactly on write/read.
type Session struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    string
	AccountID    string
}

// ApplyRefresh returns a copy of s updated with the result of a successful token
// refresh. The new access token and expiry always replace the prior
// values; refreshToken replaces the prior token only when it is non-empty, because
// a refresh response that omits a rotated token means the existing refresh token
// stays valid and must be preserved. account_id and every other field are carried
// over unchanged, so a refresh never drops the account context required for ChatGPT
// requests. It mutates nothing on disk; the caller persists the result through Write.
func (s Session) ApplyRefresh(accessToken, refreshToken, expiresAt string) Session {
	s.AccessToken = accessToken
	s.ExpiresAt = expiresAt
	if refreshToken != "" {
		s.RefreshToken = refreshToken
	}
	return s
}

// persist is a seam over config.Persist so the write/delete helpers can be
// exercised against forced reason/category/error outcomes in tests. Production
// uses config.Persist unchanged.
var persist = config.Persist

// Load reads the global settings file at settingsPath and classifies the stored
// OpenAI ChatGPT session relative to now, without exposing credential values.
// It returns StatusPresent or StatusExpired with the parsed Session, StatusNone
// with a zero Session when nothing is stored, or StatusInvalid with a zero
// Session for corrupted/unreadable/malformed state.
// The returned error is non-nil only for an unexpected file read failure (paired
// with StatusInvalid); it never carries credential content. A missing file is
// StatusNone, not an error.
func Load(settingsPath string, now time.Time) (Session, Status, error) {
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Session{}, StatusNone, nil
		}
		// Unreadable file: unauthenticated, but surface the OS error (which names
		// only the path, no secrets) so the caller may report why.
		return Session{}, StatusInvalid, err
	}

	var root map[string]any
	if err := yaml.Unmarshal(b, &root); err != nil {
		return Session{}, StatusInvalid, nil // corrupted YAML
	}

	authVal, ok := root[authKey]
	if !ok || authVal == nil {
		return Session{}, StatusNone, nil
	}
	authMap, ok := asStringMap(authVal)
	if !ok {
		return Session{}, StatusInvalid, nil // auth is not a mapping
	}
	sessVal, ok := authMap[chatGPTKey]
	if !ok || sessVal == nil {
		return Session{}, StatusNone, nil
	}
	sessMap, ok := asStringMap(sessVal)
	if !ok {
		return Session{}, StatusInvalid, nil // session is not a mapping
	}

	s, ok := parseSession(sessMap)
	if !ok {
		return Session{}, StatusInvalid, nil // missing, wrong-type, or empty field
	}
	expiry, perr := time.Parse(time.RFC3339, s.ExpiresAt)
	if perr != nil {
		return Session{}, StatusInvalid, nil // non-RFC3339 expiry
	}
	if !expiry.After(now) {
		return s, StatusExpired, nil
	}
	return s, StatusPresent, nil
}

// Write persists s as auth.openai-chatgpt in the global settings file at
// settingsPath through the shared config persistence chokepoint, so it serializes
// behind the same sidecar lock and atomic 0600 rewrite as permission and model
// writes. It returns config.Persist's reason, error category, and
// error; on success reason is config.ReasonNone, errCat is empty, and err is nil.
func Write(settingsPath string, s Session) (config.PersistReason, fserrors.Category, error) {
	return persist(settingsPath, config.KeyAuthOpenAIChatGPT, sessionYAML(s))
}

// Delete removes auth.openai-chatgpt from the global settings file at
// settingsPath through the shared persistence chokepoint (logout),
// preserving API keys, permissions, model state, and unrelated settings. It is
// idempotent: with no stored session it succeeds without writing a file. Returns
// config.Persist's reason, error category, and error.
func Delete(settingsPath string) (config.PersistReason, fserrors.Category, error) {
	return persist(settingsPath, config.KeyAuthOpenAIChatGPT, config.AuthDelete)
}

// sessionYAML renders s as the on-disk auth.openai-chatgpt mapping with the four
// fields in their canonical order, matching the schema and the byte-preserving
// rewrite contract.
func sessionYAML(s Session) yaml.MapSlice {
	return yaml.MapSlice{
		{Key: "access_token", Value: s.AccessToken},
		{Key: "refresh_token", Value: s.RefreshToken},
		{Key: "expires_at", Value: s.ExpiresAt},
		{Key: "account_id", Value: s.AccountID},
	}
}

// parseSession extracts the four required string fields, rejecting any that is
// missing, not a string, or empty. It also rejects any unsupported key so an
// unknown stored shape is classified as unauthenticated rather than a partially
// usable session (the settings schema rejects unknown auth-session fields). It
// returns ok=false (and a zero Session, so no partial credential state escapes)
// on the first such failure.
func parseSession(m map[string]any) (Session, bool) {
	for k := range m {
		switch k {
		case "access_token", "refresh_token", "expires_at", "account_id":
		default:
			return Session{}, false // unsupported field
		}
	}
	at, ok := nonEmptyString(m, "access_token")
	if !ok {
		return Session{}, false
	}
	rt, ok := nonEmptyString(m, "refresh_token")
	if !ok {
		return Session{}, false
	}
	ea, ok := nonEmptyString(m, "expires_at")
	if !ok {
		return Session{}, false
	}
	ai, ok := nonEmptyString(m, "account_id")
	if !ok {
		return Session{}, false
	}
	return Session{AccessToken: at, RefreshToken: rt, ExpiresAt: ea, AccountID: ai}, true
}

// nonEmptyString returns m[key] when it is present, a string, and non-empty.
func nonEmptyString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// asStringMap normalizes goccy's string- or interface-keyed maps into
// string-keyed form, reporting false for any non-mapping value.
func asStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, vv := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = vv
		}
		return out, true
	default:
		return nil, false
	}
}
