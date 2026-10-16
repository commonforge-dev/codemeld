// Tests for the shared system-owned discovered-model store: path derivation,
// tolerant reads, owner-only atomic provider-keyed writes, and no-secret persistence.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/locks"
)

func TestDiscoveredModelsPath(t *testing.T) {
	got := DiscoveredModelsPath("/home/u/.codemeld/global/settings.yaml")
	want := filepath.Join("/home/u/.codemeld/global", "models.yaml")
	if got != want {
		t.Errorf("DiscoveredModelsPath = %q, want %q", got, want)
	}
	if got := DiscoveredModelsPath(""); got != "" {
		t.Errorf("DiscoveredModelsPath(\"\") = %q, want empty", got)
	}
}

func TestDiscoveredModelsReadToleratesAbsentMalformed(t *testing.T) {
	dir := t.TempDir()

	// Absent file -> empty store, no error.
	store, err := ReadDiscoveredModels(filepath.Join(dir, "models.yaml"))
	if err != nil {
		t.Fatalf("read absent: unexpected error %v", err)
	}
	if store.Version != 0 || len(store.Providers) != 0 {
		t.Errorf("read absent = %+v, want zero store", store)
	}

	// Empty path -> empty store, no error.
	if _, err := ReadDiscoveredModels(""); err != nil {
		t.Fatalf("read empty path: unexpected error %v", err)
	}

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("::: not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = ReadDiscoveredModels(bad)
	if err != nil {
		t.Fatalf("read malformed: unexpected error %v", err)
	}
	if len(store.Providers) != 0 {
		t.Errorf("read malformed = %+v, want empty providers", store)
	}
}

func TestDiscoveredModelsWriteOwnerOnlyAndMergesProviders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.yaml")

	if err := UpdateDiscoveredModelsProvider(path, "openai-chatgpt", DiscoveredProvider{
		Source: "chatgpt-discovery",
		Models: []DiscoveredModel{{ID: "gpt-x", DisplayName: "GPT X", ContextWindow: 128000}},
	}); err != nil {
		t.Fatalf("write provider A: %v", err)
	}
	// Updating a second provider must not drop the first.
	if err := UpdateDiscoveredModelsProvider(path, "venice", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "venice-1", Capabilities: map[string]any{"reasoning": true}}},
	}); err != nil {
		t.Fatalf("write provider B: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}

	store, err := ReadDiscoveredModels(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Version != DiscoveredModelsVersion {
		t.Errorf("version = %d, want %d", store.Version, DiscoveredModelsVersion)
	}
	if _, ok := store.Providers["openai-chatgpt"]; !ok {
		t.Errorf("first provider dropped after second update: %+v", store.Providers)
	}
	v, ok := store.Providers["venice"]
	if !ok || len(v.Models) != 1 || v.Models[0].ID != "venice-1" {
		t.Errorf("second provider not persisted: %+v", store.Providers)
	}

	// Re-updating the first provider replaces only its own entry.
	if err := UpdateDiscoveredModelsProvider(path, "openai-chatgpt", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "gpt-y"}},
	}); err != nil {
		t.Fatalf("re-write provider A: %v", err)
	}
	store, _ = ReadDiscoveredModels(path)
	if got := store.Providers["openai-chatgpt"].Models[0].ID; got != "gpt-y" {
		t.Errorf("provider A not replaced: got %q", got)
	}
	if _, ok := store.Providers["venice"]; !ok {
		t.Errorf("provider B dropped on provider A re-write")
	}
}

func TestDiscoveredModelsProviderUpdateWaitsForSidecarLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.yaml")
	release, reason, err := locks.Acquire(path+".lock", time.Second)
	if reason != locks.ReasonNone || err != nil {
		t.Fatalf("hold sidecar lock: reason=%q err=%v", reason, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- UpdateDiscoveredModelsProvider(path, "venice", DiscoveredProvider{
			Models: []DiscoveredModel{{ID: "venice-1"}},
		})
	}()

	select {
	case err := <-done:
		release()
		t.Fatalf("provider update completed while sidecar lock was held: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("provider update after lock release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider update did not complete after sidecar lock release")
	}

	store, err := ReadDiscoveredModels(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Providers["venice"].Models[0].ID; got != "venice-1" {
		t.Fatalf("provider update after lock release wrote model %q, want venice-1", got)
	}
}

func TestDiscoveredModelsProviderUpdateThenRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.yaml")
	wantErr := errors.New("settings persist failed")
	if err := UpdateDiscoveredModelsProviderThen(path, "venice", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "venice-1"}},
	}, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("UpdateDiscoveredModelsProviderThen error = %v, want %v", err, wantErr)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("models.yaml stat after failed create = %v, want not-exist", err)
	}

	if err := UpdateDiscoveredModelsProvider(path, "openrouter", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "openrouter-existing"}},
	}); err != nil {
		t.Fatalf("seed existing store: %v", err)
	}
	prior, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := UpdateDiscoveredModelsProviderThen(path, "venice", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "venice-1"}},
	}, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("UpdateDiscoveredModelsProviderThen existing error = %v, want %v", err, wantErr)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(prior) {
		t.Fatalf("models.yaml after rollback differs from prior bytes:\nprior:\n%s\nafter:\n%s", prior, after)
	}
}

func TestDiscoveredModelsProviderUpdateThenBlocksConcurrentWritersUntilRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.yaml")
	if err := UpdateDiscoveredModelsProvider(path, "openrouter", DiscoveredProvider{
		Models: []DiscoveredModel{{ID: "openrouter-existing"}},
	}); err != nil {
		t.Fatalf("seed existing store: %v", err)
	}

	enteredCallback := make(chan struct{})
	releaseCallback := make(chan struct{})
	transactionDone := make(chan error, 1)
	wantErr := errors.New("settings persist failed")
	go func() {
		transactionDone <- UpdateDiscoveredModelsProviderThen(path, "venice", DiscoveredProvider{
			Models: []DiscoveredModel{{ID: "venice-1"}},
		}, func() error {
			close(enteredCallback)
			<-releaseCallback
			return wantErr
		})
	}()

	select {
	case <-enteredCallback:
	case <-time.After(time.Second):
		t.Fatal("transaction did not reach callback")
	}

	concurrentDone := make(chan error, 1)
	go func() {
		concurrentDone <- UpdateDiscoveredModelsProvider(path, "openai-chatgpt", DiscoveredProvider{
			Models: []DiscoveredModel{{ID: "gpt-concurrent"}},
		})
	}()

	select {
	case err := <-concurrentDone:
		close(releaseCallback)
		t.Fatalf("concurrent provider update completed before rollback released the lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(releaseCallback)
	select {
	case err := <-transactionDone:
		if !errors.Is(err, wantErr) {
			t.Fatalf("transaction error = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("transaction did not complete after callback release")
	}
	select {
	case err := <-concurrentDone:
		if err != nil {
			t.Fatalf("concurrent update after rollback: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent update did not complete after rollback")
	}

	store, err := ReadDiscoveredModels(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Providers["venice"]; ok {
		t.Fatalf("failed transaction left venice row: %+v", store.Providers)
	}
	if got := store.Providers["openrouter"].Models[0].ID; got != "openrouter-existing" {
		t.Fatalf("openrouter row = %q, want preserved openrouter-existing", got)
	}
	if got := store.Providers["openai-chatgpt"].Models[0].ID; got != "gpt-concurrent" {
		t.Fatalf("concurrent row = %q, want gpt-concurrent", got)
	}
}

func TestDiscoveredModelsNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.yaml")
	safeBool := true
	// A caller that mistakenly stuffs secret-shaped data into every free-form field must
	// still not leak it to disk: the write path redacts it.
	if err := UpdateDiscoveredModelsProvider(path, "venice", DiscoveredProvider{
		RefreshedAt: "Authorization: Bearer sk-live-refreshed",
		Source:      "sk-live-shouldnotpersist",
		Models: []DiscoveredModel{{
			ID:              "venice-1",
			DisplayName:     "Authorization: Bearer sk-live-abc",
			InputModalities: []string{"text"},
			Capabilities: map[string]any{
				"reasoning":     true,
				"api_key":       "sk-live-abc123",
				"debug":         "api-key-live-value",
				"x-api-key":     "live-hyphenated-secret",
				"authorization": "Bearer sk-live-xyz",
				"nested": map[string]any{
					"api-key": "live-nested-hyphenated-secret",
					"bearer":  "sk-live-nested",
				},
				// Concrete Go container types (not map[string]any / []any) must be
				// recursed too, or secret-shaped keys/values leak through unchanged.
				"concrete_map": map[string]string{
					"api-key": "sk-live-concretemap",
					"tier":    "pro",
				},
				"concrete_slice": []string{"text", "Authorization: Bearer sk-live-slice"},
				"deep": map[string]any{
					"limits": map[string]string{"api_key": "sk-live-deep", "max": "100"},
				},
				// Unsupported value kinds (a struct and a pointer-to-struct) must be
				// dropped, not marshaled: a struct field like Authorization would
				// otherwise persist as `authorization: Bearer sk-...` in models.yaml.
				"struct_secret": struct{ Authorization string }{Authorization: "Bearer sk-live-struct"},
				"struct_ptr":    &struct{ APIKey string }{APIKey: "sk-live-structptr"},
				"safe_int":      int64(42),
				"safe_bool_ptr": &safeBool,
			},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"api_key", "apikey", "api-key", "x-api-key", "authorization", "bearer", "sk-", "api-key-live-value", "live-hyphenated-secret", "sk-live-refreshed", "sk-live-concretemap", "sk-live-slice", "sk-live-deep", "sk-live-struct", "sk-live-structptr"} {
		if strings.Contains(strings.ToLower(string(data)), secret) {
			t.Errorf("persisted store contains secret-shaped token %q:\n%s", secret, data)
		}
	}
	// Safe capabilities must survive the redaction, including safe values inside
	// concrete nested containers.
	store, err := ReadDiscoveredModels(path)
	if err != nil {
		t.Fatal(err)
	}
	caps := store.Providers["venice"].Models[0].Capabilities
	if caps["reasoning"] != true {
		t.Errorf("safe capability dropped by sanitizer: %+v", store.Providers["venice"].Models[0])
	}
	if cm, _ := caps["concrete_map"].(map[string]any); cm["tier"] != "pro" {
		t.Errorf("safe value inside concrete map dropped: %+v", caps["concrete_map"])
	}
	if cs, _ := caps["concrete_slice"].([]any); len(cs) != 1 || cs[0] != "text" {
		t.Errorf("safe value inside concrete slice dropped: %+v", caps["concrete_slice"])
	}
	if _, present := caps["struct_secret"]; present {
		t.Errorf("unsupported struct capability survived sanitizer: %+v", caps["struct_secret"])
	}
	if _, present := caps["struct_ptr"]; present {
		t.Errorf("unsupported pointer-to-struct capability survived sanitizer: %+v", caps["struct_ptr"])
	}
	if caps["safe_int"] != uint64(42) && caps["safe_int"] != int64(42) {
		t.Errorf("safe scalar capability dropped by sanitizer: %#v", caps["safe_int"])
	}
	if caps["safe_bool_ptr"] != true {
		t.Errorf("pointer-to-safe-value not unwrapped/preserved: %#v", caps["safe_bool_ptr"])
	}

	const safeRefreshedAt = "2026-07-07T00:00:00Z"
	if err := UpdateDiscoveredModelsProvider(path, "safe", DiscoveredProvider{
		RefreshedAt: safeRefreshedAt,
		Models:      []DiscoveredModel{{ID: "safe-model"}},
	}); err != nil {
		t.Fatal(err)
	}
	store, err = ReadDiscoveredModels(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Providers["safe"].RefreshedAt; got != safeRefreshedAt {
		t.Errorf("safe refreshed_at not preserved: got %q, want %q", got, safeRefreshedAt)
	}
}

func TestDiscoveredModelsToolCapabilitiesRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "models.yaml")
	if err := UpdateDiscoveredModelsProvider(path, "openrouter", DiscoveredProvider{
		Models: []DiscoveredModel{
			{ID: "vendor/empty-params", Capabilities: map[string]any{
				"supportedParametersEmpty": true,
				"emptyList":                []any{},
			}},
			{ID: "vendor/listed-params", Capabilities: map[string]any{
				"supportedParameters": []any{"max_tokens", "top_p"},
			}},
			{ID: "vendor/no-function-calling", Capabilities: map[string]any{
				"supportsFunctionCalling": false,
			}},
		},
	}); err != nil {
		t.Fatalf("write store: %v", err)
	}

	store, err := ReadDiscoveredModels(path)
	if err != nil {
		t.Fatal(err)
	}
	models := store.Providers["openrouter"].Models
	if len(models) != 3 {
		t.Fatalf("models = %+v, want three records", models)
	}
	if got := models[0].Capabilities["supportedParametersEmpty"]; got != true {
		t.Errorf("supportedParametersEmpty = %#v, want true preserved across the round trip", got)
	}
	if _, present := models[0].Capabilities["emptyList"]; present {
		t.Errorf("empty slice survived as %#v; the marker exists because it does not", models[0].Capabilities["emptyList"])
	}
	if got := models[1].Capabilities["supportedParameters"]; !reflect.DeepEqual(got, []any{"max_tokens", "top_p"}) {
		t.Errorf("supportedParameters = %#v, want [max_tokens top_p]", got)
	}
	if got, present := models[2].Capabilities["supportsFunctionCalling"]; !present || got != false {
		t.Errorf("supportsFunctionCalling = %#v (present=%v), want an explicit false", got, present)
	}
}
