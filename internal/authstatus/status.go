// Offline OpenAI auth-status report backing `codemeld auth status`: classifies the
// OpenAI Platform (API-key) and OpenAI ChatGPT (subscription) providers from
// OPENAI_API_KEY and the global settings file only, without printing secrets,
// composing project-local settings, constructing a provider client, or making any
// network call.
package authstatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/provider"
)

// Settings keys for the codemeld-owned ChatGPT session, masked out of status's
// schema validation so a malformed session shape is classified by the session
// classifier ([authstate.Load]) rather than failing the command.
const (
	authKey    = "auth"
	chatGPTKey = "openai-chatgpt"
)

// openAIAPIKeyEnv supplies the OpenAI Platform key when set and non-empty, ahead of
// the configured global-settings key, and is reported as source env.
const openAIAPIKeyEnv = "OPENAI_API_KEY"

// Display names for human output. The stable provider ids in [provider] are the
// machine contract emitted in JSON; these names are presentation only and match the
// labels used in the picker provider header and the HTTP-error prefix.
const (
	platformDisplayName = "OpenAI Platform"
	chatGPTDisplayName  = "OpenAI ChatGPT"
)

// Kind is the JSON `kind` enum: how a provider authenticates. It is
// distinct from the provider package's internal AuthKind vocabulary.
type Kind string

const (
	// KindAPIKey is the OpenAI Platform provider (OPENAI_API_KEY or configured key).
	KindAPIKey Kind = "api_key"
	// KindChatGPTSubscription is the OpenAI ChatGPT provider (stored login session).
	KindChatGPTSubscription Kind = "chatgpt_subscription"
)

// Source is the JSON `source` enum: where the credential the status reflects was
// found. none means no usable credential was located.
type Source string

const (
	// SourceEnv means the OpenAI Platform key came from OPENAI_API_KEY.
	SourceEnv Source = "env"
	// SourceGlobalSettings means the credential came from the global settings file:
	// provider.openai.api_key for Platform, or auth.openai-chatgpt for ChatGPT.
	SourceGlobalSettings Source = "global_settings"
	// SourceNone means no credential was found for the provider.
	SourceNone Source = "none"
)

// State is the JSON `state` enum reported per provider. The four ChatGPT
// values mirror the session classifier's [authstate.Status] string values exactly.
type State string

const (
	// StateUsingAPIKey: an OpenAI Platform key is present (env or global settings).
	StateUsingAPIKey State = "using_api_key"
	// StateNoAPIKey: no OpenAI Platform key is configured anywhere status reads.
	StateNoAPIKey State = "no_api_key"
	// StateLocalSessionPresent: a complete, non-expired ChatGPT session is stored.
	StateLocalSessionPresent State = "local_session_present"
	// StateLocalSessionExpired: a ChatGPT session is stored but its expiry has passed.
	StateLocalSessionExpired State = "local_session_expired"
	// StateLocalSessionInvalid: stored ChatGPT session state is corrupted or malformed.
	StateLocalSessionInvalid State = "local_session_invalid"
	// StateNoLocalSession: no ChatGPT session is stored.
	StateNoLocalSession State = "no_local_session"
)

// ProviderStatus is one provider's offline auth state. authenticated is true only
// when the provider has a usable local credential: a Platform key, or a present
// (not expired/invalid) ChatGPT session. It never asserts upstream entitlement.
// No field carries a key, token, or account identifier.
type ProviderStatus struct {
	ID            string `json:"id"`
	Kind          Kind   `json:"kind"`
	Authenticated bool   `json:"authenticated"`
	Source        Source `json:"source"`
	State         State  `json:"state"`
}

// Report is the full offline status. Providers is always ordered Platform first,
// then ChatGPT, so JSON and scripts do not depend on map iteration.
type Report struct {
	Providers []ProviderStatus `json:"providers"`
}

// Collect builds the offline auth-status Report from the global settings file at
// settingsPath and the process environment, classifying the ChatGPT session via the
// session classifier relative to now. It reads only OPENAI_API_KEY and the global
// settings file; it never composes project-local settings, constructs a provider
// client, or performs any network call. It returns an error
// when the global settings file exists but cannot be read, parsed, or schema-validated
// — the one exception being a malformed auth.openai-chatgpt session shape, which is
// masked out of validation and classified by the session classifier as
// local_session_invalid instead of failing the command. A missing file is reported as
// unauthenticated, not an error. The error names only the path, never credential content.
func Collect(settingsPath string, now time.Time) (Report, error) {
	if err := validateGlobalSettings(settingsPath); err != nil {
		return Report{}, err
	}
	platform, err := collectPlatform(settingsPath)
	if err != nil {
		return Report{}, err
	}
	chatgpt, err := collectChatGPT(settingsPath, now)
	if err != nil {
		return Report{}, err
	}
	return Report{Providers: []ProviderStatus{platform, chatgpt}}, nil
}

// collectPlatform resolves the OpenAI Platform provider's state with OPENAI_API_KEY
// winning over the configured global-settings key, matching [provider.ResolvePlatformAPIKey]
// precedence while preserving which source supplied the key.
func collectPlatform(settingsPath string) (ProviderStatus, error) {
	ps := ProviderStatus{ID: provider.PlatformProviderID, Kind: KindAPIKey}

	if env := os.Getenv(openAIAPIKeyEnv); env != "" {
		ps.Authenticated = true
		ps.Source = SourceEnv
		ps.State = StateUsingAPIKey
		return ps, nil
	}

	key, err := configuredPlatformKey(settingsPath)
	if err != nil {
		return ProviderStatus{}, err
	}
	if key != "" {
		ps.Authenticated = true
		ps.Source = SourceGlobalSettings
		ps.State = StateUsingAPIKey
		return ps, nil
	}

	ps.Source = SourceNone
	ps.State = StateNoAPIKey
	return ps, nil
}

// collectChatGPT classifies the stored ChatGPT session through the session classifier,
// which treats corrupted, malformed, or unsupported state as local_session_invalid
// rather than failing. authenticated is true only for a present session; the parsed
// session (with its tokens) is intentionally discarded so no credential is retained.
// A genuinely unreadable settings file surfaces as an error.
func collectChatGPT(settingsPath string, now time.Time) (ProviderStatus, error) {
	_, status, err := authstate.Load(settingsPath, now)
	if err != nil {
		return ProviderStatus{}, fmt.Errorf("reading global settings %s for ChatGPT session: %w", settingsPath, err)
	}

	ps := ProviderStatus{ID: provider.ChatGPTProviderID, Kind: KindChatGPTSubscription}
	switch status {
	case authstate.StatusPresent:
		ps.Authenticated = true
		ps.Source = SourceGlobalSettings
		ps.State = StateLocalSessionPresent
	case authstate.StatusExpired:
		ps.Source = SourceGlobalSettings
		ps.State = StateLocalSessionExpired
	case authstate.StatusInvalid:
		ps.Source = SourceGlobalSettings
		ps.State = StateLocalSessionInvalid
	case authstate.StatusNone:
		ps.Source = SourceNone
		ps.State = StateNoLocalSession
	default:
		return ProviderStatus{}, fmt.Errorf("unexpected ChatGPT session status %q", status)
	}
	return ps, nil
}

// configuredPlatformKey returns provider.openai.api_key from the global settings
// file, or "" when the file is absent or the key is unset. It reads the global file
// only — never project-local settings — so project-local provider keys cannot affect
// auth status. It does not schema-validate the file, so a malformed
// ChatGPT session shape is left for the session classifier rather than failing here.
func configuredPlatformKey(settingsPath string) (string, error) {
	raw, ok, err := loadGlobalRaw(settingsPath)
	if err != nil || !ok {
		return "", err
	}
	providers, err := provider.ParseProviders(raw)
	if err != nil {
		return "", fmt.Errorf("parsing provider block in %s: %w", settingsPath, err)
	}
	return providers[provider.PlatformProviderID].APIKey, nil
}

// validateGlobalSettings runs the global settings schema (the same schema
// config.LoadGlobalSettings enforces) over the file at settingsPath with the
// auth.openai-chatgpt session masked out, so any non-ChatGPT schema violation
// (e.g. agent.max_concurrency as a string) fails `auth status`, while a malformed
// ChatGPT session shape is left for the session classifier to report as
// local_session_invalid. A missing file is not an error; a blank/comment-only file
// validates as an empty object so status reports source: none. The error names only
// the path, never credential content.
func validateGlobalSettings(settingsPath string) error {
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading global settings %s: %w", settingsPath, err)
	}

	var root any
	if err := yaml.Unmarshal(b, &root); err != nil {
		return fmt.Errorf("parsing global settings %s: %w", settingsPath, err)
	}

	// A blank/comment-only file decodes to nil; validate it as an empty object so
	// the schema's object root accepts it (matching config.LoadYAML).
	if root == nil {
		return config.Validate([]byte("{}"), settingsPath)
	}

	masked, err := yaml.Marshal(maskChatGPTSession(root))
	if err != nil {
		return fmt.Errorf("preparing global settings %s for validation: %w", settingsPath, err)
	}
	return config.Validate(masked, settingsPath)
}

// maskChatGPTSession removes auth.openai-chatgpt from the decoded settings so its
// shape is not schema-validated here — that session is classified by the session
// classifier instead. Every other key, including a malformed sibling under auth, is
// left intact so the schema still rejects it. A non-map root or non-map auth block is
// returned unchanged, leaving the schema to reject it as it normally would.
func maskChatGPTSession(root any) any {
	top, ok := root.(map[string]any)
	if !ok {
		return root
	}
	switch auth := top[authKey].(type) {
	case map[string]any:
		delete(auth, chatGPTKey)
	case map[any]any:
		delete(auth, chatGPTKey)
	}
	return top
}

// loadGlobalRaw reads and YAML-decodes the global settings file. A missing file
// yields ok=false with no error; an unreadable file or YAML parse failure yields an
// error naming only the path (the YAML/OS error carries no credential values).
func loadGlobalRaw(settingsPath string) (raw map[string]any, ok bool, err error) {
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("reading global settings %s: %w", settingsPath, err)
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, false, fmt.Errorf("parsing global settings %s: %w", settingsPath, err)
	}
	return raw, true, nil
}

// Render writes the report to w as JSON when asJSON is true, otherwise as the
// human-readable form.
func Render(w io.Writer, r Report, asJSON bool) error {
	if asJSON {
		return RenderJSON(w, r)
	}
	return RenderHuman(w, r)
}

// RenderJSON writes the report as indented JSON with a trailing newline. The
// providers order is deterministic (Platform then ChatGPT) so scripts can rely on
// it.
func RenderJSON(w io.Writer, r Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// RenderHuman writes one line per provider, reporting each independently with no
// cross-provider precedence.
func RenderHuman(w io.Writer, r Report) error {
	for _, p := range r.Providers {
		if _, err := fmt.Fprintln(w, humanLine(p)); err != nil {
			return err
		}
	}
	return nil
}

// humanLine renders one provider's human-readable status line, using labels
// and the ChatGPT entitlement caveat without printing any secret.
func humanLine(p ProviderStatus) string {
	switch p.ID {
	case provider.PlatformProviderID:
		if p.State == StateUsingAPIKey {
			return fmt.Sprintf("%s: using API key (source: %s)", platformDisplayName, humanSource(p.Source))
		}
		return fmt.Sprintf("%s: no API key", platformDisplayName)
	case provider.ChatGPTProviderID:
		switch p.State {
		case StateLocalSessionPresent:
			return chatGPTDisplayName + ": local session present — ChatGPT subscription access may be used where upstream entitlement and access policy allow it"
		case StateLocalSessionExpired:
			return chatGPTDisplayName + ": local session expired"
		case StateLocalSessionInvalid:
			return chatGPTDisplayName + ": local session invalid"
		default:
			return chatGPTDisplayName + ": no local session"
		}
	}
	return ""
}

// humanSource renders the source as the phrasing for the OpenAI Platform key.
func humanSource(s Source) string {
	switch s {
	case SourceEnv:
		return "env"
	case SourceGlobalSettings:
		return "global settings file"
	default:
		return string(s)
	}
}
