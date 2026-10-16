package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// modelsListServer serves a fixed body at /models and records the request it
// saw, so a test can assert the auth header shape and requested path. It fails
// the test for any request that is not GET /models, pinning the discovery
// request target (t.Errorf, not Fatalf, since this runs off the test goroutine).
func modelsListServer(t *testing.T, status int, body string, seen *http.Header) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != apiKeyModelsPath {
			t.Errorf("discovery request = %s %s, want GET %s", r.Method, r.URL.Path, apiKeyModelsPath)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if seen != nil {
			*seen = r.Header.Clone()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func discoverConfig(name, baseURL, apiKey string, auth *AuthHeader) APIKeyDiscoveryConfig {
	return APIKeyDiscoveryConfig{
		ProviderName: name,
		Entry:        ProviderEntry{BaseURL: baseURL, APIKey: apiKey, AuthHeader: auth},
	}
}

func TestDiscoverAPIKeyModels_SuccessSanitizedStableOrder(t *testing.T) {
	var seen http.Header
	// Duplicate ids, a whitespace-padded id, and a weird id are all present; the
	// result keeps the sanitized, de-duplicated set in response order.
	body := `{"object":"list","data":[
		{"id":"gpt-4o"},
		{"id":" gpt-4o-mini "},
		{"id":"gpt-4o"},
		{"id":"meta-llama/llama-3.1-8b:free"},
		{"id":"bad id with spaces"},
		{"id":"weird\ttab"},
		{"id":""}
	]}`
	srv := modelsListServer(t, http.StatusOK, body, &seen)

	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("openrouter", srv.URL, "sk-secret-KEY", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	ids := idsOf(models)
	want := []string{"gpt-4o", "gpt-4o-mini", "meta-llama/llama-3.1-8b:free"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	if got := seen.Get("Authorization"); got != "Bearer sk-secret-KEY" {
		t.Fatalf("Authorization = %q, want Bearer sk-secret-KEY", got)
	}
}

func TestDiscoverAPIKeyModels_ModelIDLengthBoundary(t *testing.T) {
	atMax := strings.Repeat("a", maxModelIDLength)
	overMax := strings.Repeat("b", maxModelIDLength+1)
	body := `{"data":[{"id":"` + atMax + `"},{"id":"` + overMax + `"}]}`
	srv := modelsListServer(t, http.StatusOK, body, nil)

	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("openrouter", srv.URL, "sk-secret-KEY", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	ids := idsOf(models)
	// The id at exactly the cap survives; one byte over is dropped.
	if len(ids) != 1 || ids[0] != atMax {
		t.Fatalf("ids = %v, want only the %d-char id kept and the %d-char id dropped",
			ids, maxModelIDLength, maxModelIDLength+1)
	}
}

func TestDiscoverAPIKeyModels_CustomAuthHeader(t *testing.T) {
	var seen http.Header
	srv := modelsListServer(t, http.StatusOK, `{"data":[{"id":"venice-uncensored"}]}`, &seen)

	auth := &AuthHeader{Name: "x-api-key", Value: "{api_key}"}
	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("venice", srv.URL, "vk-abc", auth))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	ids := idsOf(models)
	if len(ids) != 1 || ids[0] != "venice-uncensored" {
		t.Fatalf("ids = %v, want [venice-uncensored]", ids)
	}
	if got := seen.Get("x-api-key"); got != "vk-abc" {
		t.Fatalf("x-api-key = %q, want vk-abc", got)
	}
	if got := seen.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty (custom header used instead)", got)
	}
}

func TestDiscoverAPIKeyModels_RefusesRedirect(t *testing.T) {
	var leaked string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = "Authorization"
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/models", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("openrouter", redirector.URL, "sk-secret-XYZ", nil))

	if leaked != "" {
		t.Fatalf("credential header %q reached the redirect target", leaked)
	}
	if models != nil {
		t.Fatalf("models = %v, want nil on refused redirect", models)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error = %v, want *HTTPError for an unfollowed redirect", err)
	}
	if httpErr.Status != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect surfaced, not followed)", httpErr.Status)
	}
	if httpErr.Body != "" {
		t.Fatalf("Body = %q, want empty (no body retained)", httpErr.Body)
	}
	assertNoSecret(t, err.Error(), "sk-secret-XYZ")
}

func TestDiscoverAPIKeyModels_FailuresSecretFree(t *testing.T) {
	// Sentinels embedded in the response bodies. None may reach the error surface:
	// providerProse stands in for non-2xx provider error prose that must be dropped,
	// rawBodySentinel for a raw (potentially secret-bearing) malformed body.
	const providerProse = "PROVIDER-ERROR-PROSE-do-not-surface"
	const rawBodySentinel = "RAW-BODY-SENTINEL-do-not-surface"
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"non-2xx", http.StatusUnauthorized, `{"error":{"message":"bad key ` + providerProse + `"}}`},
		{"malformed", http.StatusOK, `{"note":"` + rawBodySentinel + `","data":[{"id":`},
		{"empty-data", http.StatusOK, `{"object":"list","data":[]}`},
		{"all-unusable", http.StatusOK, `{"data":[{"id":"has space"},{"id":""}]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := modelsListServer(t, tc.status, tc.body, nil)
			models, err := DiscoverAPIKeyModels(context.Background(),
				discoverConfig("openrouter", srv.URL, "sk-super-SECRET", nil))
			if err == nil {
				t.Fatalf("error = nil, want validation failure; models = %v", models)
			}
			if models != nil {
				t.Fatalf("models = %v, want nil on failure", models)
			}
			msg := err.Error()
			assertNoSecret(t, msg, "sk-super-SECRET")
			// The error must omit the raw body, provider prose, and any Authorization
			// header label/bearer text — even though the api key itself was redacted.
			for _, banned := range []string{rawBodySentinel, providerProse, "Authorization", "Bearer "} {
				if strings.Contains(msg, banned) {
					t.Fatalf("error %q leaks %q", msg, banned)
				}
			}
			// A non-2xx must surface as a body-free typed *HTTPError.
			if tc.name == "non-2xx" {
				var httpErr *HTTPError
				if !errors.As(err, &httpErr) {
					t.Fatalf("error = %v, want *HTTPError", err)
				}
				if httpErr.Body != "" {
					t.Fatalf("Body = %q, want empty (provider error body dropped)", httpErr.Body)
				}
			}
		})
	}
}

func assertNoSecret(t *testing.T, msg, secret string) {
	t.Helper()
	if strings.Contains(msg, secret) {
		t.Fatalf("error %q leaks the api key %q", msg, secret)
	}
	if strings.Contains(msg, "Bearer "+secret) {
		t.Fatalf("error %q leaks the Authorization value", msg)
	}
}

func idsOf(models []DiscoveredConfiguredModel) []string {
	ids := make([]string, len(models))
	for i, m := range models {
		ids[i] = m.ID
	}
	return ids
}

func discoverOne(t *testing.T, provider, body string) DiscoveredConfiguredModel {
	t.Helper()
	srv := modelsListServer(t, http.StatusOK, body, nil)
	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig(provider, srv.URL, "vk-abc", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("models = %+v, want exactly one record", models)
	}
	return models[0]
}

func TestDiscoverAPIKeyModels_OpenRouterInputModalities(t *testing.T) {
	tests := []struct {
		name string
		arch string
		want []string
	}{
		{"text-and-image", `{"input_modalities":["text","image"]}`, []string{"text", "image"}},
		{"dedup-and-unknown-dropped", `{"input_modalities":["text","image","text","audio","video"]}`, []string{"text", "image"}},
		{"image-only", `{"input_modalities":["image"]}`, []string{"image"}},
		{"non-string-element-skipped", `{"input_modalities":["text",5,null]}`, []string{"text"}},
		{"input-modalities-wrong-container", `{"input_modalities":"text"}`, nil},
		{"architecture-scalar", `"gpt"`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"data":[{"id":"m1","architecture":` + tc.arch + `}]}`
			m := discoverOne(t, "openrouter", body)
			if m.ID != "m1" {
				t.Fatalf("id = %q, want m1", m.ID)
			}
			if !reflect.DeepEqual(m.InputModalities, tc.want) {
				t.Errorf("InputModalities = %v, want %v", m.InputModalities, tc.want)
			}
			if m.Capabilities != nil {
				t.Errorf("Capabilities = %v, want nil (no Venice vision metadata)", m.Capabilities)
			}
		})
	}
}

func TestDiscoverAPIKeyModels_ArchitectureOverflowTolerated(t *testing.T) {
	body := `{"data":[
		{"id":"archscalar","architecture":1e1000},
		{"id":"archelem","architecture":{"input_modalities":["image",1e1000]}},
		{"id":"good","model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":["low"]}}}
	]}`
	srv := modelsListServer(t, http.StatusOK, body, nil)
	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("openrouter", srv.URL, "vk-abc", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	if ids := idsOf(models); !reflect.DeepEqual(ids, []string{"archscalar", "archelem", "good"}) {
		t.Fatalf("ids = %v, want all records retained despite overflowing architecture metadata", ids)
	}
	if models[0].InputModalities != nil {
		t.Errorf("scalar architecture should yield no modalities, got %v", models[0].InputModalities)
	}
	if !reflect.DeepEqual(models[1].InputModalities, []string{"image"}) {
		t.Errorf("overflowing modality element should be skipped, got %v", models[1].InputModalities)
	}
	if models[2].Capabilities["supportsReasoningEffort"] != true {
		t.Errorf("sibling reasoning metadata lost when a sibling architecture overflows: caps = %v", models[2].Capabilities)
	}
}

func TestDiscoverAPIKeyModels_VeniceVisionCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		caps     string
		wantMod  []string
		wantCaps map[string]any
	}{
		{"vision-multi-max", `"supportsVision":true,"supportsMultipleImages":true,"maxImages":4`,
			[]string{"image"}, map[string]any{"supportsMultipleImages": true, "maxImages": 4}},
		{"vision-multi-no-max", `"supportsVision":true,"supportsMultipleImages":true`,
			[]string{"image"}, map[string]any{"supportsMultipleImages": true}},
		{"vision-no-multi", `"supportsVision":true,"supportsMultipleImages":false,"maxImages":4`,
			[]string{"image"}, nil},
		{"vision-only", `"supportsVision":true`, []string{"image"}, nil},
		{"vision-false", `"supportsVision":false,"supportsMultipleImages":true,"maxImages":4`, nil, nil},
		{"vision-wrong-type", `"supportsVision":"yes","maxImages":4`, nil, nil},
		{"multi-without-vision", `"supportsMultipleImages":true,"maxImages":4`, nil, nil},
		{"max-non-positive", `"supportsVision":true,"supportsMultipleImages":true,"maxImages":0`,
			[]string{"image"}, map[string]any{"supportsMultipleImages": true}},
		{"max-fractional", `"supportsVision":true,"supportsMultipleImages":true,"maxImages":2.5`,
			[]string{"image"}, map[string]any{"supportsMultipleImages": true}},
		{"max-overflow", `"supportsVision":true,"supportsMultipleImages":true,"maxImages":1e40`,
			[]string{"image"}, map[string]any{"supportsMultipleImages": true}},
		{"max-above-4096", `"supportsVision":true,"supportsMultipleImages":true,"maxImages":4097`,
			[]string{"image"}, map[string]any{"supportsMultipleImages": true, "maxImages": 4097}},
		{"max-huge-overflow", `"supportsVision":true,"supportsMultipleImages":true,"maxImages":1e1000`,
			[]string{"image"}, map[string]any{"supportsMultipleImages": true}},
		{"vision-overflow-number", `"supportsVision":1e1000,"supportsMultipleImages":true,"maxImages":4`,
			nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"data":[{"id":"m1","model_spec":{"capabilities":{` + tc.caps + `}}}]}`
			m := discoverOne(t, "venice", body)
			if !reflect.DeepEqual(m.InputModalities, tc.wantMod) {
				t.Errorf("InputModalities = %v, want %v", m.InputModalities, tc.wantMod)
			}
			if !reflect.DeepEqual(m.Capabilities, tc.wantCaps) {
				t.Errorf("Capabilities = %v, want %v", m.Capabilities, tc.wantCaps)
			}
		})
	}
}

func TestDiscoverAPIKeyModels_VisionMetadataPreservesReasoning(t *testing.T) {
	body := `{"data":[{"id":"m1","model_spec":{"capabilities":{
		"supportsReasoningEffort":true,
		"reasoningEffortOptions":["low","high"],
		"supportsVision":true,
		"supportsMultipleImages":"nope",
		"maxImages":"lots"
	}}}]}`
	m := discoverOne(t, "venice", body)
	if !reflect.DeepEqual(m.InputModalities, []string{"image"}) {
		t.Errorf("InputModalities = %v, want [image]", m.InputModalities)
	}
	if m.Capabilities["supportsReasoningEffort"] != true {
		t.Errorf("supportsReasoningEffort lost: caps = %v", m.Capabilities)
	}
	if !reflect.DeepEqual(m.Capabilities["reasoningEffortOptions"], []any{"low", "high"}) {
		t.Errorf("reasoningEffortOptions = %v, want [low high]", m.Capabilities["reasoningEffortOptions"])
	}
	if _, ok := m.Capabilities["supportsMultipleImages"]; ok {
		t.Errorf("wrong-typed supportsMultipleImages was stored: caps = %v", m.Capabilities)
	}
	if _, ok := m.Capabilities["maxImages"]; ok {
		t.Errorf("wrong-typed maxImages was stored: caps = %v", m.Capabilities)
	}
}

func TestDiscoverAPIKeyModels_MalformedCapabilitiesTolerated(t *testing.T) {
	body := `{"data":[
		{"id":"scalar","model_spec":{"capabilities":"bad"}},
		{"id":"overflow","model_spec":{"capabilities":{"supportsVision":1e1000,"maxImages":1e1000}}},
		{"id":"scalarspec","model_spec":"bad"},
		{"id":"arrayspec","model_spec":["bad"]},
		{"id":"good","model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":["low","high"]}}}
	]}`
	srv := modelsListServer(t, http.StatusOK, body, nil)
	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("venice", srv.URL, "vk-abc", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	if ids := idsOf(models); !reflect.DeepEqual(ids, []string{"scalar", "overflow", "scalarspec", "arrayspec", "good"}) {
		t.Fatalf("ids = %v, want all records retained despite malformed optional metadata", ids)
	}
	if models[0].Capabilities != nil {
		t.Errorf("scalar capabilities container should yield nil caps, got %v", models[0].Capabilities)
	}
	if models[1].Capabilities != nil {
		t.Errorf("overflow-only vision fields should yield nil caps, got %v", models[1].Capabilities)
	}
	if models[2].Capabilities != nil {
		t.Errorf("scalar model_spec should yield nil caps, got %v", models[2].Capabilities)
	}
	if models[3].Capabilities != nil {
		t.Errorf("array model_spec should yield nil caps, got %v", models[3].Capabilities)
	}
	if models[4].Capabilities["supportsReasoningEffort"] != true {
		t.Errorf("reasoning metadata on an unaffected record was altered: %v", models[4].Capabilities)
	}
	if !reflect.DeepEqual(models[4].Capabilities["reasoningEffortOptions"], []any{"low", "high"}) {
		t.Errorf("reasoningEffortOptions on an unaffected record was altered: %v", models[4].Capabilities)
	}
}

func TestDiscoverAPIKeyModels_VeniceReasoningCapabilities(t *testing.T) {
	atMax := strings.Repeat("a", maxEffortOptionLength)
	overMax := strings.Repeat("b", maxEffortOptionLength+1)
	body := `{"data":[{
		"id":"claude-opus-4-8",
		"model_spec":{"capabilities":{
			"supportsReasoningEffort":true,
			"reasoningEffortOptions":["max"," ultra ","bad option","","` + atMax + `","` + overMax + `","default","max"],
			"defaultReasoningEffort":"medium"
		}}
	}]}`
	srv := modelsListServer(t, http.StatusOK, body, nil)

	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("venice", srv.URL, "vk-abc", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	if len(models) != 1 || models[0].ID != "claude-opus-4-8" {
		t.Fatalf("models = %+v, want one claude-opus-4-8 record", models)
	}
	caps := models[0].Capabilities
	if got := caps["supportsReasoningEffort"]; got != true {
		t.Errorf("supportsReasoningEffort = %v, want true", got)
	}
	wantOpts := []any{"max", "ultra", atMax, "default"}
	if got := caps["reasoningEffortOptions"]; !reflect.DeepEqual(got, wantOpts) {
		t.Errorf("reasoningEffortOptions = %v, want %v", got, wantOpts)
	}
	if got := caps["defaultReasoningEffort"]; got != "medium" {
		t.Errorf("defaultReasoningEffort = %v, want medium", got)
	}
}

func TestDiscoverAPIKeyModels_CapabilitiesAbsentOrUnsupported(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{"absent", ``},
		{"unsupported", `,"model_spec":{"capabilities":{"supportsReasoningEffort":false,"reasoningEffortOptions":["low","high"]}}`},
		{"supported-no-options", `,"model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":[]}}`},
		{"supported-only-junk-options", `,"model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":["has space","also bad"]}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"data":[{"id":"m1"` + tc.spec + `}]}`
			srv := modelsListServer(t, http.StatusOK, body, nil)
			models, err := DiscoverAPIKeyModels(context.Background(),
				discoverConfig("venice", srv.URL, "vk-abc", nil))
			if err != nil {
				t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
			}
			if len(models) != 1 || models[0].ID != "m1" {
				t.Fatalf("models = %+v, want one m1 record", models)
			}
			if models[0].Capabilities != nil {
				t.Errorf("Capabilities = %v, want nil (no usable reasoning-effort metadata)", models[0].Capabilities)
			}
		})
	}
}

func TestDiscoverAPIKeyModels_NoSynthesizedLevels(t *testing.T) {
	body := `{"data":[
		{"id":"anthropic/claude-opus-4-8","supported_parameters":["tools","reasoning","temperature"]},
		{"id":"openai/gpt-x","supported_parameters":["reasoning"],"model_spec":{"capabilities":{
			"supportsReasoningEffort":true,"reasoningEffortOptions":["max","ultra"]}}}
	]}`
	srv := modelsListServer(t, http.StatusOK, body, nil)

	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("openrouter", srv.URL, "sk-or-abc", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	if ids := idsOf(models); !reflect.DeepEqual(ids, []string{"anthropic/claude-opus-4-8", "openai/gpt-x"}) {
		t.Fatalf("ids = %v, want both records", ids)
	}
	if _, ok := models[0].Capabilities[configuredSupportsReasoningEffortCapKey]; ok {
		t.Errorf("Capabilities = %v, want no reasoning-effort metadata (a reasoning boolean must not synthesize levels)", models[0].Capabilities)
	}
	if got := models[1].Capabilities["reasoningEffortOptions"]; !reflect.DeepEqual(got, []any{"max", "ultra"}) {
		t.Errorf("reasoningEffortOptions = %v, want the advertised [max ultra]", got)
	}
}

func TestDiscoverAPIKeyModels_FailedRefreshReturnsNothing(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusInternalServerError, `{"data":[{"id":"venice-uncensored"}]}`},
		{"malformed body", http.StatusOK, `{"data":[`},
		{"no usable models", http.StatusOK, `{"data":[{"id":"bad id with spaces"}]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := modelsListServer(t, tc.status, tc.body, nil)
			models, err := DiscoverAPIKeyModels(context.Background(),
				discoverConfig("venice", srv.URL, "vk-abc", nil))
			if err == nil {
				t.Fatalf("DiscoverAPIKeyModels() error = nil, want a failure")
			}
			if models != nil {
				t.Fatalf("models = %+v, want nil so the prior cache entry stands", models)
			}
		})
	}
}

// TestDiscoverAPIKeyModels_CapabilityWhitelistDropsExtras covers both halves of the
// traversal boundary: an unrelated top-level root, and a prompt- or secret-bearing
// sibling nested inside a table-declared root.
func TestDiscoverAPIKeyModels_CapabilityWhitelistDropsExtras(t *testing.T) {
	const secret = "SECRET-do-not-store"
	tests := []struct {
		name, provider, body string
		want                 map[string]any
	}{
		{
			name:     "venice root",
			provider: "venice",
			body: `{"data":[{
				"id":"claude-opus-4-8",
				"api_key":"` + secret + `",
				"system_prompt":"` + secret + `",
				"model_spec":{"capabilities":{
					"supportsReasoningEffort":true,
					"reasoningEffortOptions":["low","high"],
					"defaultReasoningEffort":"low",
					"secretBlob":"` + secret + `",
					"prompt":"` + secret + `"
				}}
			}]}`,
			want: map[string]any{
				"supportsReasoningEffort": true,
				"reasoningEffortOptions":  []any{"low", "high"},
				"defaultReasoningEffort":  "low",
			},
		},
		{
			name:     "openrouter root",
			provider: "openrouter",
			body: `{"data":[{
				"id":"deepseek/deepseek-v4-flash-0731",
				"api_key":"` + secret + `",
				"endpoint":{"prompt":"` + secret + `"},
				"reasoning":{
					"supported_efforts":["max","high","low"],
					"default_effort":"high",
					"internal_prompt":"` + secret + `",
					"credentials":{"token":"` + secret + `"}
				}
			}]}`,
			want: map[string]any{
				"supportsReasoningEffort": true,
				"reasoningEffortOptions":  []any{"max", "high", "low"},
				"defaultReasoningEffort":  "high",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := discoverOne(t, tc.provider, tc.body)
			if !reflect.DeepEqual(m.Capabilities, tc.want) {
				t.Fatalf("Capabilities = %v, want only the neutral keys %v", m.Capabilities, tc.want)
			}
			encoded, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal discovered model: %v", err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Errorf("discovered model %s leaked a non-whitelisted secret", encoded)
			}
		})
	}
}

func TestDiscoverAPIKeyModels_OpenRouterReasoningCapabilities(t *testing.T) {
	atMax := strings.Repeat("a", maxEffortOptionLength)
	overMax := strings.Repeat("b", maxEffortOptionLength+1)
	body := `{"data":[{
		"id":"deepseek/deepseek-v4-flash-0731",
		"architecture":{"input_modalities":["text"]},
		"reasoning":{
			"supported_efforts":["max"," high ","bad option","","` + atMax + `","` + overMax + `",7,"max","low"],
			"default_effort":"high"
		}
	}]}`
	m := discoverOne(t, "openrouter", body)
	if !reflect.DeepEqual(m.InputModalities, []string{"text"}) {
		t.Errorf("InputModalities = %v, want [text]", m.InputModalities)
	}
	want := map[string]any{
		"supportsReasoningEffort": true,
		"reasoningEffortOptions":  []any{"max", "high", atMax, "low"},
		"defaultReasoningEffort":  "high",
	}
	if !reflect.DeepEqual(m.Capabilities, want) {
		t.Errorf("Capabilities = %v, want %v", m.Capabilities, want)
	}
}

// A table root a configured provider never sends — ChatGPT's supported_reasoning_levels
// above all — is an optional non-match, not a discovery failure.
func TestDiscoverAPIKeyModels_MissingEffortRootsTolerated(t *testing.T) {
	body := `{"data":[
		{"id":"no-roots","supported_parameters":["reasoning"],"pricing":{"prompt":"0.1"}},
		{"id":"chatgpt-shaped","supported_reasoning_levels":[{"effort":"low"}],"default_reasoning_level":"low"},
		{"id":"openrouter-shaped","reasoning":{"supported_efforts":["high"]}}
	]}`
	srv := modelsListServer(t, http.StatusOK, body, nil)
	models, err := DiscoverAPIKeyModels(context.Background(),
		discoverConfig("openrouter", srv.URL, "sk-or-abc", nil))
	if err != nil {
		t.Fatalf("DiscoverAPIKeyModels() error = %v", err)
	}
	if ids := idsOf(models); !reflect.DeepEqual(ids, []string{"no-roots", "chatgpt-shaped", "openrouter-shaped"}) {
		t.Fatalf("ids = %v, want every record retained", ids)
	}
	if _, ok := models[0].Capabilities[configuredSupportsReasoningEffortCapKey]; ok {
		t.Errorf("Capabilities = %v, want no reasoning-effort metadata when no table root is present", models[0].Capabilities)
	}
	if got := models[1].Capabilities["reasoningEffortOptions"]; !reflect.DeepEqual(got, []any{"low"}) {
		t.Errorf("reasoningEffortOptions = %v, want [low]", got)
	}
	if got := models[2].Capabilities["reasoningEffortOptions"]; !reflect.DeepEqual(got, []any{"high"}) {
		t.Errorf("reasoningEffortOptions = %v, want [high]", got)
	}
}

func TestDiscoverAPIKeyModels_OpenRouterSupportedParametersProjection(t *testing.T) {
	atMax := strings.Repeat("a", maxSupportedParameterLength)
	overMax := strings.Repeat("b", maxSupportedParameterLength+1)
	tests := []struct {
		name     string
		field    string
		wantCaps map[string]any
		wantGate bool
	}{
		{"real names without tools", `,"supported_parameters":["max_tokens","top_p","tool_choice","include_reasoning"]`,
			map[string]any{configuredSupportedParametersCapKey: []any{"max_tokens", "top_p", "tool_choice", "include_reasoning"}}, false},
		{"real names with tools", `,"supported_parameters":["max_tokens","top_p","tools"]`,
			map[string]any{configuredSupportedParametersCapKey: []any{"max_tokens", "top_p", "tools"}}, true},
		{"trimmed deduped and length-capped", `,"supported_parameters":[" top_k ","top_k","bad name","","` + atMax + `","` + overMax + `"]`,
			map[string]any{configuredSupportedParametersCapKey: []any{"top_k", atMax}}, false},
		{"explicit empty array", `,"supported_parameters":[]`,
			map[string]any{configuredSupportedParametersEmptyCapKey: true}, false},
		{"absent", ``, nil, true},
		{"json null", `,"supported_parameters":null`, nil, true},
		{"scalar", `,"supported_parameters":"tools"`, nil, true},
		{"object", `,"supported_parameters":{"tools":true}`, nil, true},
		{"one non-string element", `,"supported_parameters":["max_tokens",7]`, nil, true},
		{"null element among valid names", `,"supported_parameters":["max_tokens",null]`, nil, true},
		{"null element before tools", `,"supported_parameters":[null,"tools"]`, nil, true},
		{"all elements invalid", `,"supported_parameters":["bad name","  "]`, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := discoverOne(t, "openrouter", `{"data":[{"id":"m1"`+tc.field+`}]}`)
			if !reflect.DeepEqual(m.Capabilities, tc.wantCaps) {
				t.Fatalf("Capabilities = %v, want %v", m.Capabilities, tc.wantCaps)
			}
			if got := SupportsTools("openrouter", m.Capabilities); got != tc.wantGate {
				t.Errorf("SupportsTools(openrouter, %v) = %v, want %v", m.Capabilities, got, tc.wantGate)
			}
		})
	}
}

func TestDiscoverAPIKeyModels_OpenRouterSupportedParametersElementCap(t *testing.T) {
	names := func(n int) string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(`"p_%d"`, i)
		}
		return strings.Join(out, ",")
	}

	atCap := discoverOne(t, "openrouter", `{"data":[{"id":"m1","supported_parameters":[`+names(maxSupportedParameterCount)+`]}]}`)
	stored, ok := atCap.Capabilities[configuredSupportedParametersCapKey].([]any)
	if !ok || len(stored) != maxSupportedParameterCount {
		t.Fatalf("at-cap list stored %v, want %d names", atCap.Capabilities, maxSupportedParameterCount)
	}
	if SupportsTools("openrouter", atCap.Capabilities) {
		t.Error("at-cap list lacking tools reads as supported, want gated off")
	}

	overCap := discoverOne(t, "openrouter", `{"data":[{"id":"m1","supported_parameters":[`+names(maxSupportedParameterCount+1)+`]}]}`)
	if overCap.Capabilities != nil {
		t.Errorf("over-cap Capabilities = %v, want nil (ignored whole, never truncated)", overCap.Capabilities)
	}
	if !SupportsTools("openrouter", overCap.Capabilities) {
		t.Error("over-cap list gated the model off, want supported")
	}
}

func TestDiscoverAPIKeyModels_VeniceFunctionCallingProjection(t *testing.T) {
	tests := []struct {
		name     string
		caps     string
		wantCaps map[string]any
		wantGate bool
	}{
		{"explicit false", `"supportsFunctionCalling":false`, map[string]any{configuredSupportsFunctionCallingCapKey: false}, false},
		{"explicit true", `"supportsFunctionCalling":true`, map[string]any{configuredSupportsFunctionCallingCapKey: true}, true},
		{"absent", `"supportsVision":false`, nil, true},
		{"wrong-typed string", `"supportsFunctionCalling":"false"`, nil, true},
		{"wrong-typed number", `"supportsFunctionCalling":0`, nil, true},
		{"json null", `"supportsFunctionCalling":null`, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := discoverOne(t, "venice", `{"data":[{"id":"m1","model_spec":{"capabilities":{`+tc.caps+`}}}]}`)
			if !reflect.DeepEqual(m.Capabilities, tc.wantCaps) {
				t.Fatalf("Capabilities = %v, want %v", m.Capabilities, tc.wantCaps)
			}
			if got := SupportsTools("venice", m.Capabilities); got != tc.wantGate {
				t.Errorf("SupportsTools(venice, %v) = %v, want %v", m.Capabilities, got, tc.wantGate)
			}
		})
	}
}

func TestDiscoverAPIKeyModels_ToolMetadataMergesWithReasoningAndVision(t *testing.T) {
	m := discoverOne(t, "venice", `{"data":[{"id":"m1","model_spec":{"capabilities":{
		"supportsReasoningEffort":true,"reasoningEffortOptions":["low"],
		"supportsVision":true,"supportsMultipleImages":true,"maxImages":2,
		"supportsFunctionCalling":false}}}]}`)
	want := map[string]any{
		configuredSupportsReasoningEffortCapKey: true,
		configuredReasoningEffortOptionsCapKey:  []any{"low"},
		configuredSupportsMultipleImagesCapKey:  true,
		configuredMaxImagesCapKey:               2,
		configuredSupportsFunctionCallingCapKey: false,
	}
	if !reflect.DeepEqual(m.Capabilities, want) {
		t.Fatalf("Capabilities = %v, want %v", m.Capabilities, want)
	}
}
