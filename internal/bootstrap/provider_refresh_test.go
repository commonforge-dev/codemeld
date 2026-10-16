package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/tui"
)

var testClock = time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

type discoverFunc func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error)

func veniceComposed() map[string]any {
	return map[string]any{"provider": map[string]any{
		"venice": map[string]any{"base_url": "https://api.venice.ai/v1", "api_key": "vk-test"},
	}}
}

func platformComposed() map[string]any {
	return map[string]any{"provider": map[string]any{
		"openai": map[string]any{"base_url": "https://api.openai.com/v1", "api_key": "sk-test"},
	}}
}

func TestProviderCatalogRefresher_PlatformRetainsEveryDiscoveredModel(t *testing.T) {
	ids := []string{"gpt-5.5", "text-embedding-3-large", "gpt-not-reviewed"}
	r, cache, storePath := newTestRefresher(t, platformComposed(), func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		out := make([]provider.DiscoveredConfiguredModel, len(ids))
		for i, id := range ids {
			out[i] = provider.DiscoveredConfiguredModel{ID: id}
		}
		return out, nil
	})

	if res := refreshAndWait(t, r, "openai", true); res.Outcome != RefreshUpdated {
		t.Fatalf("platform refresh outcome = %v, want %v", res.Outcome, RefreshUpdated)
	}
	store, _ := config.ReadDiscoveredModels(storePath)
	var stored []string
	for _, m := range store.Providers["openai"].Models {
		stored = append(stored, m.ID)
	}
	if !reflect.DeepEqual(stored, ids) {
		t.Errorf("stored openai ids = %v, want every sanitized discovered id %v", stored, ids)
	}
	if live, _ := cache.SelectableCatalog().Entry("openai"); !reflect.DeepEqual(live.Models, ids) {
		t.Errorf("live openai models = %v, want %v", live.Models, ids)
	}
}

func newTestRefresher(t *testing.T, composed map[string]any, discover discoverFunc) (*ProviderCatalogRefresher, *config.Cache, string) {
	t.Helper()
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	cache, err := config.NewCache(composed, t.TempDir(), []string{globalPath})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	r := NewProviderCatalogRefresher(cache)
	r.now = func() time.Time { return testClock }
	if discover != nil {
		r.discover = discover
	}
	return r, cache, config.DiscoveredModelsPath(globalPath)
}

func seedStore(t *testing.T, storePath, providerID string, entry config.DiscoveredProvider) {
	t.Helper()
	if err := config.UpdateDiscoveredModelsProvider(storePath, providerID, entry); err != nil {
		t.Fatalf("seed store: %v", err)
	}
}

func refreshAndWait(t *testing.T, r *ProviderCatalogRefresher, id string, force bool) RefreshResult {
	t.Helper()
	done := make(chan RefreshResult, 1)
	r.Refresh(id, force, func(res RefreshResult) { done <- res })
	select {
	case res := <-done:
		return res
	case <-time.After(5 * time.Second):
		t.Fatalf("Refresh(%q, force=%v) callback did not fire", id, force)
		return RefreshResult{}
	}
}

func TestProviderCacheStale(t *testing.T) {
	fresh := testClock.Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	future := testClock.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	expired := testClock.Add(-(providerCacheMaxAge + time.Hour)).UTC().Format(time.RFC3339)

	cases := []struct {
		name      string
		refreshed string
		wantStale bool
	}{
		{"absent", "", true},
		{"malformed", "not-a-timestamp", true},
		{"invalid", "2026-13-45T99:99:99Z", true},
		{"expired", expired, true},
		{"fresh", fresh, false},
		{"future", future, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := providerCacheStale(config.DiscoveredProvider{RefreshedAt: tc.refreshed}, testClock)
			if got != tc.wantStale {
				t.Errorf("providerCacheStale(%q) = %v, want %v", tc.refreshed, got, tc.wantStale)
			}
		})
	}
}

func TestProviderCatalogRefresher_FreshSkipsUnlessForced(t *testing.T) {
	var calls atomic.Int64
	r, _, storePath := newTestRefresher(t, veniceComposed(), func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		calls.Add(1)
		return []provider.DiscoveredConfiguredModel{{ID: "venice-x"}}, nil
	})
	fresh := testClock.Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	seedStore(t, storePath, "venice", config.DiscoveredProvider{RefreshedAt: fresh, Models: []config.DiscoveredModel{{ID: "venice-old"}}})

	if res := refreshAndWait(t, r, "venice", false); res.Outcome != RefreshSkippedFresh {
		t.Errorf("fresh non-forced outcome = %v, want %v", res.Outcome, RefreshSkippedFresh)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("fresh non-forced discovery attempts = %d, want 0", n)
	}

	if res := refreshAndWait(t, r, "venice", true); res.Outcome != RefreshUpdated {
		t.Errorf("forced outcome = %v, want %v", res.Outcome, RefreshUpdated)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("forced discovery attempts = %d, want 1", n)
	}
}

func TestProviderCatalogRefresher_FreshCompletionDoesNotBlockRefresh(t *testing.T) {
	r, _, storePath := newTestRefresher(t, veniceComposed(), nil)
	fresh := testClock.Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	seedStore(t, storePath, "venice", config.DiscoveredProvider{RefreshedAt: fresh, Models: []config.DiscoveredModel{{ID: "venice-old"}}})

	release := make(chan struct{})
	done := make(chan RefreshResult, 1)
	// A synchronous fresh completion would park the Refresh call at <-release;
	// Refresh must return while the completion is still blocked.
	r.Refresh("venice", false, func(res RefreshResult) {
		<-release
		done <- res
	})

	select {
	case <-done:
		t.Fatal("fresh completion fired before release; Refresh blocked the caller")
	default:
	}

	close(release)
	select {
	case res := <-done:
		if res.Outcome != RefreshSkippedFresh {
			t.Errorf("fresh completion outcome = %v, want %v", res.Outcome, RefreshSkippedFresh)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fresh completion never fired after release")
	}
}

func TestProviderCatalogRefresher_StaleWritesAndRebuildsLiveCatalog(t *testing.T) {
	var gotEntry provider.ProviderEntry
	r, cache, storePath := newTestRefresher(t, veniceComposed(), func(_ context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		gotEntry = cfg.Entry
		return []provider.DiscoveredConfiguredModel{{ID: "venice-new", Capabilities: map[string]any{
			"supportsReasoningEffort": true,
			"reasoningEffortOptions":  []any{"low", "high"},
		}}}, nil
	})
	stale := testClock.Add(-(providerCacheMaxAge + time.Hour)).UTC().Format(time.RFC3339)
	seedStore(t, storePath, "venice", config.DiscoveredProvider{RefreshedAt: stale, Models: []config.DiscoveredModel{{ID: "venice-old"}}})
	cache.ReloadDiscoveredCatalog()

	if before, _ := cache.SelectableCatalog().Entry("venice"); !reflect.DeepEqual(before.Models, []string{"venice-old"}) {
		t.Fatalf("pre-refresh venice models = %v, want [venice-old]", before.Models)
	}

	if res := refreshAndWait(t, r, "venice", false); res.Outcome != RefreshUpdated {
		t.Fatalf("stale refresh outcome = %v, want %v", res.Outcome, RefreshUpdated)
	}

	if gotEntry.APIKey != "vk-test" || gotEntry.BaseURL != "https://api.venice.ai/v1" {
		t.Errorf("discovery entry = %+v, want the configured Cache.Provider connection values", gotEntry)
	}

	store, err := config.ReadDiscoveredModels(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	got := store.Providers["venice"]
	if len(got.Models) != 1 || got.Models[0].ID != "venice-new" {
		t.Errorf("durable models = %+v, want single venice-new", got.Models)
	}
	if got.RefreshedAt != testClock.UTC().Format(time.RFC3339) {
		t.Errorf("durable refreshed_at = %q, want current clock stamp", got.RefreshedAt)
	}

	after, ok := cache.SelectableCatalog().Entry("venice")
	if !ok {
		t.Fatal("post-refresh catalog missing venice entry")
	}
	if !reflect.DeepEqual(after.Models, []string{"venice-new"}) {
		t.Errorf("live models = %v, want [venice-new]", after.Models)
	}
	if eff := cache.SelectableCatalog().SupportedEffort("venice", "venice-new"); !reflect.DeepEqual(eff, []string{"low", "high"}) {
		t.Errorf("live venice-new effort = %v, want [low high]", eff)
	}
}

func TestProviderCatalogRefresher_CoalescesSameProvider(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	r, _, storePath := newTestRefresher(t, veniceComposed(), func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return []provider.DiscoveredConfiguredModel{{ID: "venice-new"}}, nil
	})
	seedStore(t, storePath, "venice", config.DiscoveredProvider{Models: []config.DiscoveredModel{{ID: "venice-old"}}})

	var wg sync.WaitGroup
	results := make([]RefreshResult, 2)
	// Forced and stale callers for one provider must share a single discovery.
	forces := []bool{true, false}
	for i, force := range forces {
		wg.Add(1)
		r.Refresh("venice", force, func(res RefreshResult) {
			results[i] = res
			wg.Done()
		})
	}

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery never started")
	}
	close(release)
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Errorf("coalesced discovery attempts = %d, want 1", n)
	}
	for i, res := range results {
		if res.Outcome != RefreshUpdated {
			t.Errorf("waiter %d outcome = %v, want %v", i, res.Outcome, RefreshUpdated)
		}
	}
}

func TestProviderCatalogRefresher_RefreshesDifferentProvidersIndependently(t *testing.T) {
	composed := map[string]any{"provider": map[string]any{
		"venice":     map[string]any{"base_url": "https://api.venice.ai/v1", "api_key": "vk-test"},
		"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "or-test"},
	}}
	var calls atomic.Int64
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	r, _, _ := newTestRefresher(t, composed, func(_ context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return []provider.DiscoveredConfiguredModel{{ID: cfg.ProviderName + "-m"}}, nil
	})

	var wg sync.WaitGroup
	wg.Add(2)
	for _, id := range []string{"venice", "openrouter"} {
		r.Refresh(id, true, func(RefreshResult) { wg.Done() })
	}

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 2 provider discoveries started", i)
		}
	}
	close(release)
	wg.Wait()

	if n := calls.Load(); n != 2 {
		t.Errorf("independent discovery attempts = %d, want 2", n)
	}
}

func TestProviderCatalogRefresher_BlockedReadDoesNotStallOtherProvider(t *testing.T) {
	composed := map[string]any{"provider": map[string]any{
		"venice":     map[string]any{"base_url": "https://api.venice.ai/v1", "api_key": "vk-test"},
		"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "or-test"},
	}}
	r, _, _ := newTestRefresher(t, composed, func(_ context.Context, cfg provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		return []provider.DiscoveredConfiguredModel{{ID: cfg.ProviderName + "-m"}}, nil
	})

	readEntered := make(chan struct{})
	releaseRead := make(chan struct{})
	// venice's non-forced request parks in the freshness read holding only venice's
	// gate. A forced openrouter request must still discover and deliver while it
	// is blocked — the old global-mutex read would serialize the two providers.
	r.readStore = func(path string) (config.DiscoveredModelsStore, error) {
		close(readEntered)
		<-releaseRead
		return config.ReadDiscoveredModels(path)
	}

	blocked := make(chan RefreshResult, 1)
	r.Refresh("venice", false, func(res RefreshResult) { blocked <- res })
	select {
	case <-readEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("venice non-forced freshness read never started")
	}

	other := make(chan RefreshResult, 1)
	r.Refresh("openrouter", true, func(res RefreshResult) { other <- res })
	select {
	case res := <-other:
		if res.Outcome != RefreshUpdated {
			t.Errorf("openrouter forced outcome = %v, want %v", res.Outcome, RefreshUpdated)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("openrouter refresh stalled behind venice's blocked read")
	}

	select {
	case <-blocked:
		t.Fatal("venice completed before its blocking read was released")
	default:
	}

	close(releaseRead)
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("venice never completed after its read was released")
	}
}

func TestProviderCatalogRefresher_FailureKeepsPriorCatalog(t *testing.T) {
	t.Run("discovery_error", func(t *testing.T) {
		r, cache, storePath := newTestRefresher(t, veniceComposed(), func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
			return nil, errors.New("provider venice model discovery: 401")
		})
		seedPriorAndAssertRetained(t, r, cache, storePath, "venice", false)
	})

	t.Run("platform_discovery_zero", func(t *testing.T) {
		r, cache, storePath := newTestRefresher(t, platformComposed(), func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
			return nil, nil
		})
		stale := testClock.Add(-(providerCacheMaxAge + time.Hour)).UTC().Format(time.RFC3339)
		seedStore(t, storePath, "openai", config.DiscoveredProvider{RefreshedAt: stale, Models: []config.DiscoveredModel{{ID: "gpt-5.5"}}})
		cache.ReloadDiscoveredCatalog()

		if res := refreshAndWait(t, r, "openai", false); res.Outcome != RefreshFailed {
			t.Errorf("platform-discovery-zero outcome = %v, want %v", res.Outcome, RefreshFailed)
		}
		store, _ := config.ReadDiscoveredModels(storePath)
		if got := store.Providers["openai"]; len(got.Models) != 1 || got.Models[0].ID != "gpt-5.5" || got.RefreshedAt != stale {
			t.Errorf("store changed on discovery-zero failure = %+v, want prior gpt-5.5 + stale stamp", got)
		}
		if live, _ := cache.SelectableCatalog().Entry("openai"); !reflect.DeepEqual(live.Models, []string{"gpt-5.5"}) {
			t.Errorf("live openai models = %v, want prior [gpt-5.5]", live.Models)
		}
	})

	t.Run("persistence_error", func(t *testing.T) {
		r, cache, storePath := newTestRefresher(t, veniceComposed(), func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
			return []provider.DiscoveredConfiguredModel{{ID: "venice-new"}}, nil
		})
		stale := testClock.Add(-(providerCacheMaxAge + time.Hour)).UTC().Format(time.RFC3339)
		seedStore(t, storePath, "venice", config.DiscoveredProvider{RefreshedAt: stale, Models: []config.DiscoveredModel{{ID: "venice-old"}}})
		cache.ReloadDiscoveredCatalog()

		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("write blocker: %v", err)
		}
		r.path = filepath.Join(blocker, "models.yaml")

		if res := refreshAndWait(t, r, "venice", true); res.Outcome != RefreshFailed {
			t.Errorf("persistence-error outcome = %v, want %v", res.Outcome, RefreshFailed)
		}
		store, _ := config.ReadDiscoveredModels(storePath)
		if got := store.Providers["venice"]; len(got.Models) != 1 || got.Models[0].ID != "venice-old" || got.RefreshedAt != stale {
			t.Errorf("derived store changed on write failure = %+v, want prior venice-old", got)
		}
		if live, _ := cache.SelectableCatalog().Entry("venice"); !reflect.DeepEqual(live.Models, []string{"venice-old"}) {
			t.Errorf("live venice models = %v, want prior [venice-old]", live.Models)
		}
	})
}

func seedPriorAndAssertRetained(t *testing.T, r *ProviderCatalogRefresher, cache *config.Cache, storePath, id string, force bool) {
	t.Helper()
	stale := testClock.Add(-(providerCacheMaxAge + time.Hour)).UTC().Format(time.RFC3339)
	seedStore(t, storePath, id, config.DiscoveredProvider{RefreshedAt: stale, Models: []config.DiscoveredModel{{ID: id + "-old"}}})
	cache.ReloadDiscoveredCatalog()

	res := refreshAndWait(t, r, id, force)
	if res.Outcome != RefreshFailed {
		t.Errorf("failure outcome = %v, want %v", res.Outcome, RefreshFailed)
	}
	store, _ := config.ReadDiscoveredModels(storePath)
	if got := store.Providers[id]; len(got.Models) != 1 || got.Models[0].ID != id+"-old" || got.RefreshedAt != stale {
		t.Errorf("store changed on failure = %+v, want prior %s-old + stale stamp", got, id)
	}
	if live, _ := cache.SelectableCatalog().Entry(id); !reflect.DeepEqual(live.Models, []string{id + "-old"}) {
		t.Errorf("live %s models = %v, want prior [%s-old]", id, live.Models, id)
	}
}

func TestProviderCatalogRefresher_RefusesNonconfiguredAndChatGPT(t *testing.T) {
	var calls atomic.Int64
	r, _, storePath := newTestRefresher(t, veniceComposed(), func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		calls.Add(1)
		return []provider.DiscoveredConfiguredModel{{ID: "x"}}, nil
	})

	for _, id := range []string{"not-configured", provider.ChatGPTProviderID} {
		if res := refreshAndWait(t, r, id, true); res.Outcome != RefreshRefused {
			t.Errorf("Refresh(%q) outcome = %v, want %v", id, res.Outcome, RefreshRefused)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("refused discovery attempts = %d, want 0", n)
	}
	if _, err := os.Stat(storePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("refused requests created a store at %s (err=%v), want none", storePath, err)
	}
}

func TestProviderCatalogRefresher_NoStorePathRefusesBeforeNetwork(t *testing.T) {
	cache, err := config.NewCache(veniceComposed(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	r := NewProviderCatalogRefresher(cache)
	r.now = func() time.Time { return testClock }
	var calls atomic.Int64
	r.discover = func(context.Context, provider.APIKeyDiscoveryConfig) ([]provider.DiscoveredConfiguredModel, error) {
		calls.Add(1)
		return []provider.DiscoveredConfiguredModel{{ID: "x"}}, nil
	}

	if r.path != "" {
		t.Fatalf("expected empty store path with no settings layer, got %q", r.path)
	}
	if res := refreshAndWait(t, r, "venice", true); res.Outcome != RefreshRefused {
		t.Errorf("no-store-path outcome = %v, want %v", res.Outcome, RefreshRefused)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("no-store-path discovery attempts = %d, want 0", n)
	}
}

type chatGPTDiscoveryStub struct {
	mu     sync.Mutex
	reqs   []*http.Request
	status int
	body   string
}

func (s *chatGPTDiscoveryStub) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r)
	s.mu.Unlock()
	return &http.Response{
		StatusCode: s.status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Request:    r,
	}, nil
}

func (s *chatGPTDiscoveryStub) requests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

const chatGPTDiscoveryBody = `{"models":[{"slug":"gpt-5.7","display_name":"GPT-5.7","context_window":400000,` +
	`"input_modalities":["text","image"],"supported_reasoning_levels":[{"effort":"high"}],` +
	`"base_instructions":"PROMPT-SECRET","model_messages":["PROMPT-SECRET"]}]}`

func stubChatGPTDiscovery(t *testing.T, status int, body string) *chatGPTDiscoveryStub {
	t.Helper()
	stub := &chatGPTDiscoveryStub{status: status, body: body}
	chatGPTDiscoveryHTTPClient = &http.Client{Transport: stub}
	t.Cleanup(func() { chatGPTDiscoveryHTTPClient = nil })
	return stub
}

const testChatGPTSettingsPath = "/home/u/.codemeld/global/settings.yaml"

func renewedChatGPTAuth() *fakeChatGPTAuth {
	return &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		return authstate.Session{AccessToken: "renewed-access", RefreshToken: "rt-secret", AccountID: "acct-9"}, nil
	}}
}

func newChatGPTTestRefresher(t *testing.T, auth chatGPTAuth) (*ProviderCatalogRefresher, *config.Cache, string) {
	t.Helper()
	r, cache, storePath := newTestRefresher(t, map[string]any{}, nil)
	r.chatgptAuth = auth
	r.settingsPath = testChatGPTSettingsPath
	return r, cache, storePath
}

func TestProviderCatalogRefresher_ChatGPTForcedWritesSanitizedEntry(t *testing.T) {
	stub := stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
	var gotPath string
	var requestsBeforeAuth int
	auth := &fakeChatGPTAuth{ensure: func(_ context.Context, path string) (authstate.Session, error) {
		gotPath = path
		requestsBeforeAuth = len(stub.requests())
		return authstate.Session{AccessToken: "renewed-access", RefreshToken: "rt-secret", AccountID: "acct-9"}, nil
	}}
	r, cache, storePath := newChatGPTTestRefresher(t, auth)
	seedStore(t, storePath, "venice", config.DiscoveredProvider{Models: []config.DiscoveredModel{{ID: "venice-keep"}}})

	if res := refreshAndWait(t, r, provider.ChatGPTProviderID, true); res != (RefreshResult{ProviderID: provider.ChatGPTProviderID, Outcome: RefreshUpdated}) {
		t.Fatalf("forced ChatGPT refresh = %+v, want updated", res)
	}
	if gotPath != testChatGPTSettingsPath || requestsBeforeAuth != 0 {
		t.Fatalf("session resolved from %q with %d prior discovery requests, want %q before any discovery", gotPath, requestsBeforeAuth, testChatGPTSettingsPath)
	}
	reqs := stub.requests()
	if len(reqs) != 1 || reqs[0].URL.Host != "chatgpt.com" || reqs[0].Header.Get("Authorization") != "Bearer renewed-access" {
		t.Fatalf("discovery requests = %d (first %v), want one pinned chatgpt.com request with the renewed token", len(reqs), reqs)
	}

	store, err := config.ReadDiscoveredModels(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	got := store.Providers[provider.ChatGPTProviderID]
	if got.Source != refreshDiscoverSource || got.RefreshedAt != testClock.Format(time.RFC3339) || len(got.Models) != 1 {
		t.Fatalf("stored ChatGPT entry = %+v, want one model stamped %s by %s", got, testClock.Format(time.RFC3339), refreshDiscoverSource)
	}
	m := got.Models[0]
	if m.ID != "gpt-5.7" || m.DisplayName != "GPT-5.7" || m.ContextWindow != 400000 ||
		!slices.Equal(m.InputModalities, []string{"text", "image"}) || m.Capabilities["supported_reasoning_levels"] == nil {
		t.Errorf("stored ChatGPT model = %+v, want every sanitized discovery field", m)
	}
	if venice := store.Providers["venice"]; len(venice.Models) != 1 || venice.Models[0].ID != "venice-keep" {
		t.Errorf("venice entry = %+v, want it untouched", venice)
	}
	raw, _ := os.ReadFile(storePath)
	for _, secret := range []string{"renewed-access", "rt-secret", "acct-9", "PROMPT-SECRET", "base_instructions", "model_messages"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("models.yaml contains %q:\n%s", secret, raw)
		}
	}
	if live, _ := cache.SelectableCatalog().Entry(provider.ChatGPTProviderID); !slices.Contains(live.Models, "gpt-5.7") {
		t.Errorf("live ChatGPT models = %v, want gpt-5.7 after reload", live.Models)
	}
}

func TestProviderCatalogRefresher_ChatGPTForcedIdenticalCatalogRewritesTimestamp(t *testing.T) {
	stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
	r, _, storePath := newChatGPTTestRefresher(t, renewedChatGPTAuth())
	older := testClock.Add(-time.Hour)
	r.now = func() time.Time { return older }
	if res := refreshAndWait(t, r, provider.ChatGPTProviderID, true); res.Outcome != RefreshUpdated {
		t.Fatalf("seeding refresh outcome = %v, want %v", res.Outcome, RefreshUpdated)
	}
	seeded, err := config.ReadDiscoveredModels(storePath)
	if err != nil {
		t.Fatalf("read seeded store: %v", err)
	}

	r.now = func() time.Time { return testClock }
	if res := refreshAndWait(t, r, provider.ChatGPTProviderID, true); res != (RefreshResult{ProviderID: provider.ChatGPTProviderID, Outcome: RefreshUpdated}) {
		t.Fatalf("identical forced ChatGPT refresh = %+v, want updated", res)
	}
	store, err := config.ReadDiscoveredModels(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	before, after := seeded.Providers[provider.ChatGPTProviderID], store.Providers[provider.ChatGPTProviderID]
	if !reflect.DeepEqual(after.Models, before.Models) {
		t.Fatalf("models changed across identical discovery: %+v -> %+v", before.Models, after.Models)
	}
	if before.RefreshedAt != older.Format(time.RFC3339) || after.RefreshedAt != testClock.Format(time.RFC3339) {
		t.Errorf("refreshed_at %q -> %q, want %q -> %q", before.RefreshedAt, after.RefreshedAt, older.Format(time.RFC3339), testClock.Format(time.RFC3339))
	}
}

func TestProviderCatalogRefresher_ChatGPTUnforcedOrUnboundRefused(t *testing.T) {
	stub := stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
	auth := renewedChatGPTAuth()
	r, _, storePath := newChatGPTTestRefresher(t, auth)

	if res := refreshAndWait(t, r, provider.ChatGPTProviderID, false); res.Outcome != RefreshRefused {
		t.Errorf("unforced ChatGPT outcome = %v, want %v", res.Outcome, RefreshRefused)
	}
	r.chatgptAuth = nil
	if res := refreshAndWait(t, r, provider.ChatGPTProviderID, true); res.Outcome != RefreshRefused {
		t.Errorf("unbound forced ChatGPT outcome = %v, want %v", res.Outcome, RefreshRefused)
	}
	if auth.ensureCount() != 0 || len(stub.requests()) != 0 {
		t.Errorf("session resolutions = %d, discovery requests = %d, want none", auth.ensureCount(), len(stub.requests()))
	}
	if _, err := os.Stat(storePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("refused ChatGPT refresh created a store (err=%v)", err)
	}
}

func TestProviderCatalogRefresher_ChatGPTSessionErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want RefreshOutcome
	}{
		{"no_session", openaiauth.ErrNoSession, RefreshCredentialUnavailable},
		{"refresh_failed", &openaiauth.RefreshFailure{Status: http.StatusUnauthorized}, RefreshCredentialUnavailable},
		{"deadline", fmt.Errorf("renew: %w", context.DeadlineExceeded), RefreshFailed},
		{"canceled", context.Canceled, RefreshFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
			r, cache, storePath := newChatGPTTestRefresher(t, &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
				return authstate.Session{}, tc.err
			}})
			seedStore(t, storePath, provider.ChatGPTProviderID, config.DiscoveredProvider{RefreshedAt: "prior", Models: []config.DiscoveredModel{{ID: "gpt-prior"}}})
			cache.ReloadDiscoveredCatalog()

			if res := refreshAndWait(t, r, provider.ChatGPTProviderID, true); res.Outcome != tc.want {
				t.Errorf("outcome = %v, want %v", res.Outcome, tc.want)
			}
			if n := len(stub.requests()); n != 0 {
				t.Errorf("discovery requests = %d, want 0 without a usable session", n)
			}
			store, _ := config.ReadDiscoveredModels(storePath)
			if got := store.Providers[provider.ChatGPTProviderID]; got.RefreshedAt != "prior" || len(got.Models) != 1 || got.Models[0].ID != "gpt-prior" {
				t.Errorf("store = %+v, want prior entry retained", got)
			}
			if live, _ := cache.SelectableCatalog().Entry(provider.ChatGPTProviderID); !slices.Contains(live.Models, "gpt-prior") {
				t.Errorf("live ChatGPT models = %v, want prior gpt-prior", live.Models)
			}
		})
	}
}

func TestProviderCatalogRefresher_ChatGPTOneTimeoutSpansAuthAndDiscovery(t *testing.T) {
	stub := stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
	var authCtx context.Context
	r, _, _ := newChatGPTTestRefresher(t, &fakeChatGPTAuth{ensure: func(ctx context.Context, _ string) (authstate.Session, error) {
		authCtx = ctx
		return authstate.Session{AccessToken: "a", AccountID: "b"}, nil
	}})

	if res := refreshAndWait(t, r, provider.ChatGPTProviderID, true); res.Outcome != RefreshUpdated {
		t.Fatalf("outcome = %v, want %v", res.Outcome, RefreshUpdated)
	}
	reqs := stub.requests()
	if len(reqs) != 1 {
		t.Fatalf("discovery requests = %d, want 1", len(reqs))
	}
	if authCtx == nil || reqs[0].Context() != authCtx {
		t.Fatalf("discovery context %p differs from auth context %p, want one shared context", reqs[0].Context(), authCtx)
	}
	if _, ok := authCtx.Deadline(); !ok {
		t.Error("shared auth/discovery context has no deadline")
	}
}

func TestProviderCatalogRefresher_ChatGPTAuthDeadlineFailsCoalescedWaiters(t *testing.T) {
	stub := stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
	prevTimeout := refreshDiscoverTimeout
	refreshDiscoverTimeout = 50 * time.Millisecond
	t.Cleanup(func() { refreshDiscoverTimeout = prevTimeout })
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	auth := &fakeChatGPTAuth{ensure: func(ctx context.Context, _ string) (authstate.Session, error) {
		started <- struct{}{}
		<-release
		<-ctx.Done()
		return authstate.Session{}, fmt.Errorf("renew: %w", ctx.Err())
	}}
	r, cache, storePath := newChatGPTTestRefresher(t, auth)
	seedStore(t, storePath, provider.ChatGPTProviderID, config.DiscoveredProvider{RefreshedAt: "prior", Models: []config.DiscoveredModel{{ID: "gpt-prior"}}})
	cache.ReloadDiscoveredCatalog()

	done := make(chan RefreshResult, 2)
	for range 2 {
		r.Refresh(provider.ChatGPTProviderID, true, func(res RefreshResult) { done <- res })
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("session resolution never started")
	}
	waitForWaiters(t, r, provider.ChatGPTProviderID, 2)
	close(release)
	for i := range 2 {
		select {
		case res := <-done:
			if res.Outcome != RefreshFailed {
				t.Errorf("waiter %d outcome = %v, want %v", i, res.Outcome, RefreshFailed)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter %d never completed after the auth deadline", i)
		}
	}

	if auth.ensureCount() != 1 || len(stub.requests()) != 0 {
		t.Errorf("session resolutions = %d, discovery requests = %d, want 1 and 0", auth.ensureCount(), len(stub.requests()))
	}
	store, _ := config.ReadDiscoveredModels(storePath)
	if got := store.Providers[provider.ChatGPTProviderID]; got.RefreshedAt != "prior" || len(got.Models) != 1 || got.Models[0].ID != "gpt-prior" {
		t.Errorf("store = %+v, want prior entry retained", got)
	}
	if live, _ := cache.SelectableCatalog().Entry(provider.ChatGPTProviderID); !slices.Contains(live.Models, "gpt-prior") {
		t.Errorf("live ChatGPT models = %v, want prior gpt-prior", live.Models)
	}
}

func TestProviderCatalogRefresher_ChatGPTFailureKeepsPriorCatalog(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		breakRefresh func(t *testing.T, r *ProviderCatalogRefresher)
	}{
		{"discovery_error", http.StatusInternalServerError, func(*testing.T, *ProviderCatalogRefresher) {}},
		{"persistence_error", http.StatusOK, func(t *testing.T, r *ProviderCatalogRefresher) {
			r.updateStore = func(path, providerID string, _ config.DiscoveredProvider) error {
				if path != r.path || providerID != provider.ChatGPTProviderID {
					t.Errorf("store update (%q, %q), want (%q, %q)", path, providerID, r.path, provider.ChatGPTProviderID)
				}
				return errors.New("disk full")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := stubChatGPTDiscovery(t, tc.status, chatGPTDiscoveryBody)
			r, cache, storePath := newChatGPTTestRefresher(t, renewedChatGPTAuth())
			stale := testClock.Add(-time.Hour).UTC().Format(time.RFC3339)
			seedStore(t, storePath, provider.ChatGPTProviderID, config.DiscoveredProvider{RefreshedAt: stale, Models: []config.DiscoveredModel{{ID: "gpt-prior"}}})
			cache.ReloadDiscoveredCatalog()
			tc.breakRefresh(t, r)

			if res := refreshAndWait(t, r, provider.ChatGPTProviderID, true); res.Outcome != RefreshFailed {
				t.Errorf("outcome = %v, want %v", res.Outcome, RefreshFailed)
			}
			if n := len(stub.requests()); n != 1 {
				t.Errorf("discovery requests = %d, want 1 before the failure", n)
			}
			store, _ := config.ReadDiscoveredModels(storePath)
			if got := store.Providers[provider.ChatGPTProviderID]; got.RefreshedAt != stale || len(got.Models) != 1 || got.Models[0].ID != "gpt-prior" {
				t.Errorf("store = %+v, want prior entry retained", got)
			}
			live, _ := cache.SelectableCatalog().Entry(provider.ChatGPTProviderID)
			if !slices.Contains(live.Models, "gpt-prior") || slices.Contains(live.Models, "gpt-5.7") {
				t.Errorf("live ChatGPT models = %v, want prior gpt-prior and no gpt-5.7", live.Models)
			}
		})
	}
}

func TestProviderCatalogRefresher_ChatGPTCoalesces(t *testing.T) {
	stub := stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		started <- struct{}{}
		<-release
		return authstate.Session{AccessToken: "a", AccountID: "b"}, nil
	}}
	r, _, _ := newChatGPTTestRefresher(t, auth)

	var wg sync.WaitGroup
	results := make([]RefreshResult, 2)
	for i := range results {
		wg.Add(1)
		r.Refresh(provider.ChatGPTProviderID, true, func(res RefreshResult) {
			results[i] = res
			wg.Done()
		})
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("session resolution never started")
	}
	waitForWaiters(t, r, provider.ChatGPTProviderID, 2)
	close(release)
	wg.Wait()

	if auth.ensureCount() != 1 || len(stub.requests()) != 1 {
		t.Errorf("session resolutions = %d, discovery requests = %d, want 1 each", auth.ensureCount(), len(stub.requests()))
	}
	for i, res := range results {
		if res.Outcome != RefreshUpdated {
			t.Errorf("waiter %d outcome = %v, want %v", i, res.Outcome, RefreshUpdated)
		}
	}
}

func waitForWaiters(t *testing.T, r *ProviderCatalogRefresher, providerID string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		g := r.gates[providerID]
		r.mu.Unlock()
		if g != nil {
			g.mu.Lock()
			joined := g.inflight != nil && len(g.inflight.waiters) >= n
			g.mu.Unlock()
			if joined {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s never had %d coalesced waiters", providerID, n)
}

func TestNewProviderRefreshCallback_ChatGPTOutcomeMapping(t *testing.T) {
	cases := []struct {
		name     string
		auth     chatGPTAuth
		provider string
		force    bool
		want     tui.ModelRefreshOutcome
	}{
		{"forced_unbound_chatgpt", nil, provider.ChatGPTProviderID, true, tui.ModelRefreshFailed},
		{"unforced_chatgpt", renewedChatGPTAuth(), provider.ChatGPTProviderID, false, tui.ModelRefreshNoChange},
		{"credential_unavailable", &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
			return authstate.Session{}, openaiauth.ErrNoSession
		}}, provider.ChatGPTProviderID, true, tui.ModelRefreshCredentialUnavailable},
		{"configured_refused", renewedChatGPTAuth(), "not-configured", true, tui.ModelRefreshNoChange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
			globalPath := filepath.Join(t.TempDir(), "settings.yaml")
			cache, err := config.NewCache(map[string]any{}, t.TempDir(), []string{globalPath})
			if err != nil {
				t.Fatalf("NewCache: %v", err)
			}
			done := make(chan tui.ModelRefreshResult, 1)
			newProviderRefreshCallback(cache, tc.auth, globalPath)(tc.provider, tc.force, func(res tui.ModelRefreshResult) { done <- res })
			select {
			case res := <-done:
				if res != (tui.ModelRefreshResult{Provider: tc.provider, Outcome: tc.want}) {
					t.Errorf("result = %+v, want %v for %s", res, tc.want, tc.provider)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("callback did not fire")
			}
		})
	}
}
