// Picker-triggered background refresh of a provider's models.yaml catalog:
// stale-check, per-provider request coalescing, sanitized discovery, atomic store
// write, and live-cache rebuild — with secret-safe result delivery and no
// internal/tui import (the picker owns its wiring and notices).
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/provider"
)

// providerCacheMaxAge is the three-day freshness window: a configured
// provider's discovered-model cache older than this is refreshed on the next
// picker request.
const providerCacheMaxAge = 3 * 24 * time.Hour

// refreshDiscoverTimeout bounds one background /models request so a hung provider
// endpoint cannot leave an in-flight refresh (and its coalesced waiters) parked
// forever. It matches the synchronous /connect discovery timeout.
var refreshDiscoverTimeout = 15 * time.Second

// refreshDiscoverSource labels the models.yaml entry a successful refresh writes,
// so the store records where the ids came from (secret-free advisory metadata).
const refreshDiscoverSource = "picker-catalog-refresh"

// chatGPTDiscoveryHTTPClient stays nil in production; tests point ChatGPT discovery at a
// stub transport without changing the pinned origin.
var chatGPTDiscoveryHTTPClient *http.Client

// RefreshOutcome is the static, secret-free classification of one refresh request.
// It carries no endpoint, key, body, or raw upstream error — the picker maps it to its
// own user-facing notice text.
type RefreshOutcome int

const (
	// RefreshRefused means no discovery and no write happened: the id is not a
	// configured API-key provider, is an unforced or unbound openai-chatgpt request,
	// or no models.yaml path could be derived. Nothing changed.
	RefreshRefused RefreshOutcome = iota
	// RefreshSkippedFresh means the cache was within the freshness window and the
	// request was not forced, so no discovery ran. Nothing changed.
	RefreshSkippedFresh
	// RefreshUpdated means discovery, the atomic store write, and the live-catalog
	// rebuild all succeeded; the picker's live rows now reflect the new catalog.
	RefreshUpdated
	// RefreshFailed means a discovery, platform-filter, persistence, or rebuild
	// step failed; the prior on-disk and live catalog are retained unchanged.
	RefreshFailed
	// RefreshCredentialUnavailable means no usable ChatGPT session could be resolved,
	// so no discovery ran. Nothing changed.
	RefreshCredentialUnavailable
)

func (o RefreshOutcome) String() string {
	switch o {
	case RefreshRefused:
		return "refused"
	case RefreshSkippedFresh:
		return "fresh"
	case RefreshUpdated:
		return "updated"
	case RefreshFailed:
		return "failed"
	case RefreshCredentialUnavailable:
		return "credential_unavailable"
	default:
		return "unknown"
	}
}

// RefreshResult is the secret-safe value delivered to every completion callback:
// the provider it concerns and the static outcome. It never carries credentials
// or raw provider content.
type RefreshResult struct {
	ProviderID string
	Outcome    RefreshOutcome
}

type inflightRefresh struct {
	waiters []func(RefreshResult)
}

// providerGate scopes one provider's freshness read and in-flight claim/join to
// its own mutex. The refresher's global mu guards only the gates map lookup, so a
// slow or blocked store read for one provider is held under that provider's gate
// and never stalls another provider's refresh lifecycle.
type providerGate struct {
	mu       sync.Mutex
	inflight *inflightRefresh
}

// ProviderCatalogRefresher runs picker-triggered background refreshes of the
// shared models.yaml catalog for configured API-key providers and, when forced,
// for openai-chatgpt. It is bootstrap-
// only: the picker wiring installs its Refresh method as the picker's refresh callback and
// marshals the result into the event loop. One refresh per provider runs at a
// time; concurrent requests for the same provider share it.
type ProviderCatalogRefresher struct {
	cache *config.Cache
	path  string
	now   func() time.Time
	// discover is the sanitized, redirect-refusing discovery seam (defaults to
	// provider.DiscoverAPIKeyModels); tests replace it with a fake endpoint.
	discover func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error)
	// readStore is the discovered-model store read seam (defaults to
	// config.ReadDiscoveredModels); tests replace it to block one provider's
	// non-forced freshness read and prove other providers still progress.
	readStore    func(string) (config.DiscoveredModelsStore, error)
	updateStore  func(path, providerID string, entry config.DiscoveredProvider) error
	chatgptAuth  chatGPTAuth
	settingsPath string

	mu    sync.Mutex
	gates map[string]*providerGate
}

// NewProviderCatalogRefresher binds the refresher to the run's live config cache
// and derives the shared models.yaml store path from the cache's global settings
// layer. It constructs no TUI dependency. When no store path can be derived every
// Refresh returns RefreshRefused before any network work.
func NewProviderCatalogRefresher(cache *config.Cache) *ProviderCatalogRefresher {
	var path string
	if layers := cache.LayerPaths(); len(layers) > 0 {
		path = config.DiscoveredModelsPath(layers[0])
	}
	return &ProviderCatalogRefresher{
		cache:       cache,
		path:        path,
		now:         time.Now,
		discover:    provider.DiscoverAPIKeyModels,
		readStore:   config.ReadDiscoveredModels,
		updateStore: config.UpdateDiscoveredModelsProvider,
		gates:       map[string]*providerGate{},
	}
}

// Refresh schedules a background catalog refresh for providerID and never blocks
// the caller. force bypasses the freshness window but not eligibility. onComplete
// receives one secret-safe result. Concurrent requests for the same provider share
// a single discovery attempt and each receives the shared result; different
// providers proceed independently.
func (r *ProviderCatalogRefresher) Refresh(providerID string, force bool, onComplete func(RefreshResult)) {
	go r.schedule(providerID, force, onComplete)
}

// schedule runs the entire refresh lifecycle off the picker caller's goroutine.
// Eligibility, the per-provider in-flight claim/join, freshness classification,
// and every completion delivery — including the refused and fresh outcomes —
// happen here so Refresh returns before any store read or callback runs. The
// freshness read and claim run under the provider's own gate, so same-provider
// requests coalesce onto one discovery while different providers stay independent.
func (r *ProviderCatalogRefresher) schedule(providerID string, force bool, onComplete func(RefreshResult)) {
	deliver := func(res RefreshResult) {
		if onComplete != nil {
			onComplete(res)
		}
	}

	var entry provider.ProviderEntry
	if providerID == provider.ChatGPTProviderID {
		if !force || r.chatgptAuth == nil || r.settingsPath == "" || r.path == "" {
			deliver(RefreshResult{ProviderID: providerID, Outcome: RefreshRefused})
			return
		}
	} else {
		var ok bool
		entry, ok = r.cache.Provider(providerID)
		if !ok || r.path == "" {
			deliver(RefreshResult{ProviderID: providerID, Outcome: RefreshRefused})
			return
		}
	}

	// The global lock only looks up (or creates) this provider's gate; the stale
	// check and claim then hold the gate's own mutex, so a blocked freshness read
	// for one provider cannot serialize another provider's refresh.
	r.mu.Lock()
	g, ok := r.gates[providerID]
	if !ok {
		g = &providerGate{}
		r.gates[providerID] = g
	}
	r.mu.Unlock()

	g.mu.Lock()
	if g.inflight != nil {
		g.inflight.waiters = append(g.inflight.waiters, onComplete)
		g.mu.Unlock()
		return
	}
	if !force {
		store, _ := r.readStore(r.path)
		if !providerCacheStale(store.Providers[providerID], r.now()) {
			g.mu.Unlock()
			deliver(RefreshResult{ProviderID: providerID, Outcome: RefreshSkippedFresh})
			return
		}
	}
	w := &inflightRefresh{waiters: []func(RefreshResult){onComplete}}
	g.inflight = w
	g.mu.Unlock()

	r.run(providerID, entry, g, w)
}

func (r *ProviderCatalogRefresher) run(providerID string, entry provider.ProviderEntry, g *providerGate, w *inflightRefresh) {
	var res RefreshResult
	if providerID == provider.ChatGPTProviderID {
		res = r.discoverAndStoreChatGPT()
	} else {
		res = r.discoverAndStore(providerID, entry)
	}

	g.mu.Lock()
	g.inflight = nil
	waiters := w.waiters
	g.mu.Unlock()

	for _, cb := range waiters {
		if cb != nil {
			cb(res)
		}
	}
}

// discoverAndStore performs the ordered discover -> platform-filter -> atomic
// store write -> live-cache rebuild. Any failure before the rebuild returns
// RefreshFailed and leaves the prior on-disk and live catalog intact. All error
// paths are secret-free: DiscoverAPIKeyModels redacts credentials and drops bodies,
// and only the static outcome is returned.
func (r *ProviderCatalogRefresher) discoverAndStore(providerID string, entry provider.ProviderEntry) RefreshResult {
	failed := RefreshResult{ProviderID: providerID, Outcome: RefreshFailed}

	ctx, cancel := context.WithTimeout(context.Background(), refreshDiscoverTimeout)
	defer cancel()
	discovered, err := r.discover(ctx, provider.APIKeyDiscoveryConfig{
		ProviderName: providerID,
		Entry:        entry,
	})
	if err != nil {
		return failed
	}

	if providerID == provider.PlatformProviderID {
		discovered = provider.FilterPlatformDiscoveredModels(discovered)
		if len(discovered) == 0 {
			return failed
		}
	}

	models := make([]config.DiscoveredModel, len(discovered))
	for i, m := range discovered {
		models[i] = config.DiscoveredModel{ID: m.ID, InputModalities: m.InputModalities, Capabilities: m.Capabilities}
	}
	if err := r.updateStore(r.path, providerID, config.DiscoveredProvider{
		RefreshedAt: r.now().UTC().Format(time.RFC3339),
		Source:      refreshDiscoverSource,
		Models:      models,
	}); err != nil {
		return failed
	}

	r.cache.ReloadDiscoveredCatalog()
	return RefreshResult{ProviderID: providerID, Outcome: RefreshUpdated}
}

// One timeout spans session refresh and discovery so a hung auth request cannot hold
// the provider gate or its coalesced waiters.
func (r *ProviderCatalogRefresher) discoverAndStoreChatGPT() RefreshResult {
	failed := RefreshResult{ProviderID: provider.ChatGPTProviderID, Outcome: RefreshFailed}

	ctx, cancel := context.WithTimeout(context.Background(), refreshDiscoverTimeout)
	defer cancel()
	sess, err := r.chatgptAuth.EnsureFreshSession(ctx, r.settingsPath)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return failed
		}
		return RefreshResult{ProviderID: provider.ChatGPTProviderID, Outcome: RefreshCredentialUnavailable}
	}

	cfg := chatGPTConfig(sess)
	cfg.HTTPClient = chatGPTDiscoveryHTTPClient
	err = provider.RefreshChatGPTModelCache(ctx, cfg, func(discovered []provider.ChatGPTStoreModel) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		models := make([]config.DiscoveredModel, len(discovered))
		for i, m := range discovered {
			models[i] = config.DiscoveredModel{
				ID:              m.ID,
				DisplayName:     m.DisplayName,
				ContextWindow:   m.ContextWindow,
				InputModalities: m.InputModalities,
				Capabilities:    m.Capabilities,
			}
		}
		return r.updateStore(r.path, provider.ChatGPTProviderID, config.DiscoveredProvider{
			RefreshedAt: r.now().UTC().Format(time.RFC3339),
			Source:      refreshDiscoverSource,
			Models:      models,
		})
	})
	if err != nil {
		return failed
	}

	r.cache.ReloadDiscoveredCatalog()
	return RefreshResult{ProviderID: provider.ChatGPTProviderID, Outcome: RefreshUpdated}
}

// providerCacheStale reports whether a provider's discovered-model entry needs a
// refresh. A missing, malformed, or invalid refreshed_at, or one older than
// providerCacheMaxAge, is stale; a timestamp within the window — including one in
// the future — is fresh.
func providerCacheStale(entry config.DiscoveredProvider, now time.Time) bool {
	ts := strings.TrimSpace(entry.RefreshedAt)
	if ts == "" {
		return true
	}
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return true
	}
	return now.Sub(parsed) > providerCacheMaxAge
}
