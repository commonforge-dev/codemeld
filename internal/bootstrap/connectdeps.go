// Production tui.ConnectDeps for /connect <provider>: it turns a validated,
// connectable provider id into a durable global provider.<name> settings entry
// through the byte-preserving config.Persist writer, so /connect adds no ad-hoc credential
// write of its own. It lives in internal/bootstrap because internal/tui cannot
// import internal/config or internal/provider (that edge would cycle).
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/tui"
)

// openai-chatgpt is intentionally absent: it is the browser-login provider, connected
// via `codemeld auth login`, whose credentials live under auth.openai-chatgpt and never
// as a provider entry.
//
// Drift note: these base_url values duplicate the built-in adapter defaults in
// internal/provider/openai_adapter.go, openrouter_adapter.go, and venice_adapter.go, and
// the first-run example in firstrun_settings.go (canonicalProviderBlock). Keep them in
// sync when a default endpoint changes.
var connectableProviderScaffolds = map[string]string{
	provider.PlatformProviderID: "https://api.openai.com/v1",
	"openrouter":                "https://openrouter.ai/api/v1",
	"venice":                    "https://api.venice.ai/api/v1",
}

// connectDiscoverModels is the seam /connect uses to validate an entered api key by
// discovering the provider's selectable models before persisting anything. It defaults
// to the real OpenAI-compatible discovery call; tests replace it to point at a fake
// /models endpoint. Its errors are already secret-free (a redirect or non-2xx is
// body-free, other failures are credential-redacted), so a failure can be surfaced in a
// notice without leaking the key or the raw provider body.
var connectDiscoverModels = provider.DiscoverAPIKeyModels

// connectDiscoverTimeout bounds the synchronous key-validation request so a hung
// provider endpoint cannot wedge the connect prompt. It matches the ChatGPT discovery
// timeout.
const connectDiscoverTimeout = 15 * time.Second

// connectDiscoverSource labels the models.yaml provider entry /connect writes, so the
// store records where the ids came from (secret-free advisory metadata).
const connectDiscoverSource = "connect-apikey-discovery"

// errConnectPersistFailed is the static error connectDeps.Connect returns on any
// connect failure — key validation, a models.yaml store write, or the settings write.
// It carries no path, reason, or key material: the handler maps any Connect error to
// its own static errConnectFailed, and the actionable (secret-free) detail is surfaced
// through the rendered notice, not the error.
var errConnectPersistFailed = errors.New("bootstrap: connect failed")

type connectDeps struct {
	home  string
	app   *tui.App
	cache *config.Cache
}

// newConnectDeps builds the production /connect deps bound to the run's home (the
// global settings write target), the app it opens the masked API-key prompt on and
// renders the secret-free notice through, and the run's live config cache so a
// successful connect makes the provider selectable in this session (SetProvider)
// without a restart. It must be the same *config.Cache StartTUI wired into the
// model/model-picker deps, so the catalog the picker reads is the one connect updates.
// The session flush is the handler's job (ctx.FlushActive), so no context or store is
// captured here.
func newConnectDeps(app *tui.App, home string, cache *config.Cache) connectDeps {
	return connectDeps{home: home, app: app, cache: cache}
}

// IsProvider reports whether id names a provider /connect can wire — the
// api-key providers with a scaffold above. It returns only a bool, so no id or
// scaffold detail can reach a user-facing notice through this seam.
func (d connectDeps) IsProvider(id string) bool {
	_, ok := connectableProviderScaffolds[id]
	return ok
}

// ConnectableProviders returns the providers /connect can wire, in a stable
// alphabetical order, as id/label pairs. The label is the id in this slice — there is
// no separate display-name source — and each row carries no endpoint, key, or scaffold
// detail, only what the bare-path guidance and the /connect picker need. It performs no
// network I/O.
func (d connectDeps) ConnectableProviders() []tui.ConnectProviderOption {
	ids := make([]string, 0, len(connectableProviderScaffolds))
	for id := range connectableProviderScaffolds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	options := make([]tui.ConnectProviderOption, len(ids))
	for i, id := range ids {
		options[i] = tui.ConnectProviderOption{ID: id, Label: id}
	}
	return options
}

// OpenConnectPicker opens the production provider picker on the running app. The
// handler supplies the selection continuation so choosing a row reuses the same direct
// connect flow as typing `/connect <provider>`.
func (d connectDeps) OpenConnectPicker(options []tui.ConnectProviderOption, onSelect func(id string)) {
	d.app.OpenConnectPicker(options, onSelect)
}

func (d connectDeps) NeedsManualKey(id string) bool {
	_, ok := connectableProviderScaffolds[id]
	return !ok
}

// PromptAPIKey is the production API-key entry seam: it opens the masked prompt so
// the user types the key hidden, and hands what they submit to onSubmit (or runs onCancel
// on dismissal).
func (d connectDeps) PromptAPIKey(id string, onSubmit func(apiKey string), onCancel func()) {
	d.app.OpenSecretPrompt(tui.SecretPromptRequest{
		Label:    "API key",
		Help:     fmt.Sprintf("Paste the %s API key; it is hidden as you type.", id),
		OnSubmit: onSubmit,
		OnCancel: onCancel,
	})
}

func (d connectDeps) Connect(id, apiKey string, onComplete func(error)) {
	d.app.RunBackgroundAfterDraw(func() error {
		baseURL, ok := connectableProviderScaffolds[id]
		if !ok {
			return errConnectPersistFailed
		}
		return d.connectDiscovered(id, baseURL, apiKey)
	}, onComplete)
}

func (d connectDeps) connectDiscovered(id, baseURL, apiKey string) error {
	d.app.NoticeFromBackground(fmt.Sprintf("checking the %s API key by loading its models...", id))
	ctx, cancel := context.WithTimeout(context.Background(), connectDiscoverTimeout)
	defer cancel()
	discovered, err := connectDiscoverModels(ctx, provider.APIKeyDiscoveryConfig{
		ProviderName: id,
		Entry:        provider.ProviderEntry{BaseURL: baseURL, APIKey: apiKey},
	})
	if err != nil {
		// Discovery errors are already secret-free (body-free status / redacted text),
		// so the status can be surfaced to help the user without leaking the key.
		d.app.NoticeFromBackground(fmt.Sprintf("could not validate the %s API key (%v); nothing was saved", id, err))
		return errConnectPersistFailed
	}

	if id == provider.PlatformProviderID {
		discovered = provider.FilterPlatformDiscoveredModels(discovered)
		if len(discovered) == 0 {
			d.app.NoticeFromBackground(fmt.Sprintf("the %s API key is valid but returned no usable models; nothing was saved", id))
			return errConnectPersistFailed
		}
	}

	settingsPath := SettingsPath(d.home)
	modelsPath := config.DiscoveredModelsPath(settingsPath)

	models := make([]config.DiscoveredModel, len(discovered))
	for i, m := range discovered {
		models[i] = config.DiscoveredModel{ID: m.ID, InputModalities: m.InputModalities, Capabilities: m.Capabilities}
	}
	session, _ := d.cache.Provider(id)
	persistFailureNotice := ""
	if err := config.UpdateDiscoveredModelsProviderThen(modelsPath, id, config.DiscoveredProvider{
		Source: connectDiscoverSource,
		Models: models,
	}, func() error {
		// Settings holds key + base_url and no models key — never the discovered ids
		// (settings stays the user's file; the ids are cache data in models.yaml). Omitting
		// the models key (rather than writing an empty []) marks the entry as having no
		// user-owned model list, so the catalog fills selectable ids from models.yaml until
		// the user pins their own; an explicit `models: []` would instead pin an empty list.
		value := yaml.MapSlice{
			{Key: "base_url", Value: baseURL},
			{Key: "api_key", Value: apiKey},
		}
		if session.ContextWindows != nil {
			value = append(value, yaml.MapItem{Key: "context_windows", Value: session.ContextWindows})
		}
		reason, cat, err := config.Persist(settingsPath, config.KeyProviderPrefix+id, value)
		if err != nil {
			persistFailureNotice = tui.RenderPersistFailureNotice(settingsPath, string(reason), cat)
		}
		return err
	}); err != nil {
		if persistFailureNotice != "" {
			d.app.NoticeFromBackground(persistFailureNotice)
		} else {
			d.app.NoticeFromBackground(fmt.Sprintf("could not save the discovered %s models; nothing was saved", id))
		}
		return errConnectPersistFailed
	}

	// Durable writes succeeded: mirror the connection into the live cache. The entry
	// carries no models list — the catalog rebuild reads the discovered ids from the
	// models.yaml store just written, so the running picker offers them now.
	if id == "openrouter" {
		d.cache.SetOpenRouterConnection(baseURL, apiKey)
		return nil
	}
	d.cache.SetProvider(id, provider.ProviderEntry{BaseURL: baseURL, APIKey: apiKey, ContextWindows: session.ContextWindows})
	return nil
}
