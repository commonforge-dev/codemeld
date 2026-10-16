// Tests for provider entry parsing, auth-header defaulting, and api-key substitution.
package provider

import (
	"reflect"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestParseProviders_AbsentOrEmpty(t *testing.T) {
	tests := []struct {
		name     string
		composed map[string]any
	}{
		{"no provider key", map[string]any{}},
		{"nil composed", nil},
		{"provider null", map[string]any{"provider": nil}},
		{"provider empty object", map[string]any{"provider": map[string]any{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProviders(tt.composed)
			if err != nil {
				t.Fatalf("ParseProviders() error = %v, want nil", err)
			}
			if got == nil {
				t.Fatalf("ParseProviders() = nil, want non-nil empty map")
			}
			if len(got) != 0 {
				t.Fatalf("ParseProviders() = %v, want empty map", got)
			}
		})
	}
}

func TestParseProviders_Entries(t *testing.T) {
	tests := []struct {
		name     string
		composed map[string]any
		wantKey  string
		want     ProviderEntry
	}{
		{
			name: "minimal entry gets default auth header",
			composed: map[string]any{"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
				},
			}},
			wantKey: "openai",
			want: ProviderEntry{
				BaseURL:    "https://api.openai.com/v1",
				APIKey:     "sk-test",
				AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
			},
		},
		{
			name: "explicit auth_header override",
			composed: map[string]any{"provider": map[string]any{
				"custom": map[string]any{
					"base_url": "https://example.test/v1",
					"api_key":  "secret",
					"auth_header": map[string]any{
						"name":  "X-API-Key",
						"value": "{api_key}",
					},
				},
			}},
			wantKey: "custom",
			want: ProviderEntry{
				BaseURL:    "https://example.test/v1",
				APIKey:     "secret",
				AuthHeader: &AuthHeader{Name: "X-API-Key", Value: "{api_key}"},
			},
		},
		{
			name: "minimal venice entry gets default auth header",
			composed: map[string]any{"provider": map[string]any{
				"venice": map[string]any{
					"base_url": "https://api.venice.ai/api/v1",
					"api_key":  "sk-test",
				},
			}},
			wantKey: "venice",
			want: ProviderEntry{
				BaseURL:    "https://api.venice.ai/api/v1",
				APIKey:     "sk-test",
				AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
			},
		},
		{
			name: "empty api_key still parses",
			composed: map[string]any{"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "",
				},
			}},
			wantKey: "openai",
			want: ProviderEntry{
				BaseURL:    "https://api.openai.com/v1",
				APIKey:     "",
				AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
			},
		},
		{
			name: "custom auth header value with embedded token",
			composed: map[string]any{"provider": map[string]any{
				"openrouter": map[string]any{
					"base_url": "https://openrouter.ai/api/v1",
					"api_key":  "or-key",
					"auth_header": map[string]any{
						"name":  "X-API-Key",
						"value": "Bearer {api_key}",
					},
				},
			}},
			wantKey: "openrouter",
			want: ProviderEntry{
				BaseURL:    "https://openrouter.ai/api/v1",
				APIKey:     "or-key",
				AuthHeader: &AuthHeader{Name: "X-API-Key", Value: "Bearer {api_key}"},
			},
		},
		{
			name: "openrouter routing block",
			composed: map[string]any{"provider": map[string]any{
				"openrouter": map[string]any{
					"base_url": "https://openrouter.ai/api/v1",
					"api_key":  "or-key",
					"routing": map[string]any{
						"sort":               "throughput",
						"data_collection":    "deny",
						"require_parameters": true,
					},
				},
			}},
			wantKey: "openrouter",
			want: ProviderEntry{
				BaseURL:    "https://openrouter.ai/api/v1",
				APIKey:     "or-key",
				AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
				Routing:    Routing{Sort: "throughput", DataCollection: "deny", RequireParameters: true},
			},
		},
		{
			name: "partial openrouter routing block",
			composed: map[string]any{"provider": map[string]any{
				"openrouter": map[string]any{
					"base_url": "https://openrouter.ai/api/v1",
					"api_key":  "or-key",
					"routing":  map[string]any{"data_collection": "allow", "require_parameters": false},
				},
			}},
			wantKey: "openrouter",
			want: ProviderEntry{
				BaseURL:    "https://openrouter.ai/api/v1",
				APIKey:     "or-key",
				AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
				Routing:    Routing{DataCollection: "allow"},
			},
		},
		{
			name: "openrouter routing max_price with every numeric type and explicit zero",
			composed: map[string]any{"provider": map[string]any{
				"openrouter": map[string]any{
					"base_url": "https://openrouter.ai/api/v1",
					"api_key":  "or-key",
					"routing": map[string]any{
						"sort": "throughput",
						"max_price": map[string]any{
							"anthropic/claude-sonnet-4.5": map[string]any{"prompt": 3.5, "completion": uint64(16)},
							"moonshotai/kimi-k2":          map[string]any{"prompt": int64(1)},
							"moonshotai/kimi-k2:free":     map[string]any{"completion": int(0)},
						},
					},
				},
			}},
			wantKey: "openrouter",
			want: ProviderEntry{
				BaseURL:    "https://openrouter.ai/api/v1",
				APIKey:     "or-key",
				AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
				Routing: Routing{Sort: "throughput", MaxPrice: map[string]MaxPrice{
					"anthropic/claude-sonnet-4.5": {Prompt: 3.5, Completion: 16, HasPrompt: true, HasCompletion: true},
					"moonshotai/kimi-k2":          {Prompt: 1, HasPrompt: true},
					"moonshotai/kimi-k2:free":     {Completion: 0, HasCompletion: true},
				}},
			},
		},
		{
			name: "openrouter routing empty max_price",
			composed: map[string]any{"provider": map[string]any{
				"openrouter": map[string]any{
					"base_url": "https://openrouter.ai/api/v1",
					"api_key":  "or-key",
					"routing":  map[string]any{"max_price": map[string]any{}},
				},
			}},
			wantKey: "openrouter",
			want: ProviderEntry{
				BaseURL:    "https://openrouter.ai/api/v1",
				APIKey:     "or-key",
				AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProviders(tt.composed)
			if err != nil {
				t.Fatalf("ParseProviders() error = %v, want nil", err)
			}
			entry, ok := got[tt.wantKey]
			if !ok {
				t.Fatalf("ParseProviders() missing entry %q, got keys %v", tt.wantKey, keysOf(got))
			}
			if !reflect.DeepEqual(entry, tt.want) {
				t.Fatalf("entry = %+v, want %+v", entry, tt.want)
			}
		})
	}
}

func TestParseProviders_RoutingTypeMismatch(t *testing.T) {
	for name, routing := range map[string]any{
		"routing not object":          "fast",
		"sort not string":             map[string]any{"sort": 1},
		"data_collection not string":  map[string]any{"data_collection": true},
		"require_parameters not bool": map[string]any{"require_parameters": "yes"},
		"max_price not object":        map[string]any{"max_price": 1},
		"max_price entry not object":  map[string]any{"max_price": map[string]any{"m": 1}},
		"max_price prompt not number": map[string]any{"max_price": map[string]any{"m": map[string]any{"prompt": "1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProviders(map[string]any{"provider": map[string]any{
				"openrouter": map[string]any{"base_url": "u", "api_key": "k", "routing": routing},
			}})
			if err == nil {
				t.Fatalf("ParseProviders() error = nil, want a type error")
			}
		})
	}
}

func TestParseProviders_FromDecodedYAML(t *testing.T) {
	src := `provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: sk-test
`
	var composed map[string]any
	if err := yaml.Unmarshal([]byte(src), &composed); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	got, err := ParseProviders(composed)
	if err != nil {
		t.Fatalf("ParseProviders() error = %v, want nil", err)
	}
	want := ProviderEntry{
		BaseURL:    "https://api.openai.com/v1",
		APIKey:     "sk-test",
		AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
	}
	if !reflect.DeepEqual(got["openai"], want) {
		t.Fatalf("entry = %+v, want %+v", got["openai"], want)
	}
}

// The openai-chatgpt reservation lives entirely in the schema gate
// (config.Validate rejects a user-defined provider.openai-chatgpt before
// composition). ParseProviders runs only on already-validated config, so it keeps
// no special case for the reserved id: handed such an entry directly it parses it
// exactly like any other provider, and a non-reserved provider alongside it parses
// unchanged. This pins the layering so reservation logic is not duplicated into the
// parser and existing custom providers are untouched.
func TestParseProviders_ReservedNameNotSpecialCased(t *testing.T) {
	composed := map[string]any{"provider": map[string]any{
		"openai-chatgpt": map[string]any{
			"base_url": "https://example.test/v1",
			"api_key":  "k",
		},
		"openrouter": map[string]any{
			"base_url": "https://openrouter.ai/api/v1",
			"api_key":  "or-key",
			"auth_header": map[string]any{
				"name":  "X-API-Key",
				"value": "{api_key}",
			},
		},
	}}
	got, err := ParseProviders(composed)
	if err != nil {
		t.Fatalf("ParseProviders() error = %v, want nil", err)
	}
	want := map[string]ProviderEntry{
		"openai-chatgpt": {
			BaseURL:    "https://example.test/v1",
			APIKey:     "k",
			AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"},
		},
		"openrouter": {
			BaseURL:    "https://openrouter.ai/api/v1",
			APIKey:     "or-key",
			AuthHeader: &AuthHeader{Name: "X-API-Key", Value: "{api_key}"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseProviders() = %+v, want %+v", got, want)
	}
}

func TestResolveAuthHeader(t *testing.T) {
	tests := []struct {
		name      string
		entry     ProviderEntry
		wantName  string
		wantValue string
	}{
		{
			name:      "whole-token value expands to api key",
			entry:     ProviderEntry{APIKey: "secret", AuthHeader: &AuthHeader{Name: "X-API-Key", Value: "{api_key}"}},
			wantName:  "X-API-Key",
			wantValue: "secret",
		},
		{
			name:      "in-token value substitutes within surrounding text",
			entry:     ProviderEntry{APIKey: "secret", AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"}},
			wantName:  "Authorization",
			wantValue: "Bearer secret",
		},
		{
			name:      "empty api key yields empty substitution span",
			entry:     ProviderEntry{APIKey: "", AuthHeader: &AuthHeader{Name: "Authorization", Value: "Bearer {api_key}"}},
			wantName:  "Authorization",
			wantValue: "Bearer ",
		},
		{
			name:      "other tokens pass through unchanged",
			entry:     ProviderEntry{APIKey: "secret", AuthHeader: &AuthHeader{Name: "Authorization", Value: "{scheme} {api_key} {other}"}},
			wantName:  "Authorization",
			wantValue: "{scheme} secret {other}",
		},
		{
			name:      "multiple occurrences all substituted",
			entry:     ProviderEntry{APIKey: "k", AuthHeader: &AuthHeader{Name: "X", Value: "{api_key}-{api_key}"}},
			wantName:  "X",
			wantValue: "k-k",
		},
		{
			name:      "nil auth header falls back to default",
			entry:     ProviderEntry{APIKey: "secret"},
			wantName:  "Authorization",
			wantValue: "Bearer secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, value := tt.entry.ResolveAuthHeader()
			if name != tt.wantName || value != tt.wantValue {
				t.Fatalf("ResolveAuthHeader() = (%q, %q), want (%q, %q)", name, value, tt.wantName, tt.wantValue)
			}
		})
	}
}

func keysOf(m map[string]ProviderEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
