// Parses the composed config provider block into typed entries and resolves auth headers.
package provider

import (
	"fmt"
	"math"
	"strings"
)

// Default auth-header name/value applied when a provider omits auth_header, and
// the literal token substituted with the provider api key at resolve time.
const (
	defaultAuthHeaderName  = "Authorization"
	defaultAuthHeaderValue = "Bearer {api_key}"
	apiKeyToken            = "{api_key}"
)

// RetryConfigKey is the reserved key under the settings `provider` object that
// holds the auto-retry block (provider.retry) rather than a provider
// entry. ParseProviders skips it so it is never parsed as — or selectable as — a
// provider; config.NewCache reads it separately for the retry policy.
const RetryConfigKey = "retry"

// AuthHeader is the runtime form of a provider's optional auth_header object:
// the header name and its value template, where any {api_key} literal is
// substituted at resolve time.
type AuthHeader struct {
	Name  string
	Value string
}

// ProviderEntry is the runtime form of one provider.<name> config entry. APIKey
// is held in plaintext at runtime. AuthHeader is non-nil after
// ParseProviders, carrying the configured header or the Bearer default.
type ProviderEntry struct {
	BaseURL        string
	APIKey         string
	AuthHeader     *AuthHeader
	Routing        Routing
	ContextWindows map[string]int64
}

type Routing struct {
	Sort              string
	DataCollection    string
	RequireParameters bool
	MaxPrice          map[string]MaxPrice
}

type MaxPrice struct {
	Prompt        float64
	Completion    float64
	HasPrompt     bool
	HasCompletion bool
}

// ResolveAuthHeader returns the auth header name and value with every {api_key}
// literal in the value replaced by the entry's api key; other {name} tokens pass
// through unchanged. An empty api key yields an empty substitution, and the
// Bearer default is used when AuthHeader is unset.
func (p ProviderEntry) ResolveAuthHeader() (name, value string) {
	h := p.AuthHeader
	if h == nil {
		h = defaultAuthHeader()
	}
	return h.Name, strings.ReplaceAll(h.Value, apiKeyToken, p.APIKey)
}

// ParseProviders converts the composed config's provider block into typed
// entries keyed by provider name, filling the Bearer default for entries without
// an explicit auth_header. An absent or empty provider block yields an empty
// map. Schema-level shape rules (required fields, unknown keys, auth_header
// shape) are enforced upstream by config.Validate; this returns an error only on
// a value whose runtime type does not match the validated schema.
func ParseProviders(composed map[string]any) (map[string]ProviderEntry, error) {
	out := map[string]ProviderEntry{}
	raw, ok := composed["provider"]
	if !ok || raw == nil {
		return out, nil
	}
	entries, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("provider: expected object, got %T", raw)
	}
	for name, rawEntry := range entries {
		if name == RetryConfigKey {
			// provider.retry is the auto-retry config block, not a provider
			// entry; config.NewCache reads it separately.
			continue
		}
		entry, err := parseEntry(rawEntry)
		if err != nil {
			return nil, fmt.Errorf("provider.%s: %w", name, err)
		}
		out[name] = entry
	}
	return out, nil
}

func parseEntry(raw any) (ProviderEntry, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return ProviderEntry{}, fmt.Errorf("expected object, got %T", raw)
	}

	baseURL, err := asString(m, "base_url")
	if err != nil {
		return ProviderEntry{}, err
	}
	apiKey, err := asString(m, "api_key")
	if err != nil {
		return ProviderEntry{}, err
	}
	auth, err := parseAuthHeader(m)
	if err != nil {
		return ProviderEntry{}, err
	}
	routing, err := parseRouting(m)
	if err != nil {
		return ProviderEntry{}, err
	}
	windows, err := parseContextWindows(m)
	if err != nil {
		return ProviderEntry{}, err
	}

	return ProviderEntry{
		BaseURL:        baseURL,
		APIKey:         apiKey,
		AuthHeader:     auth,
		Routing:        routing,
		ContextWindows: windows,
	}, nil
}

func parseContextWindows(m map[string]any) (map[string]int64, error) {
	raw, ok := m["context_windows"]
	if !ok {
		return nil, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("context_windows: expected object, got %T", raw)
	}
	if len(obj) == 0 {
		return nil, nil
	}
	out := make(map[string]int64, len(obj))
	for model, v := range obj {
		n, ok := tokenCount(v)
		if !ok {
			return nil, fmt.Errorf("context_windows.%s: expected an integer from 1 to %d, got %v", model, maxContextWindow, v)
		}
		out[model] = n
	}
	return out, nil
}

const maxContextWindow = 10000000

func tokenCount(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), n >= 1 && n <= maxContextWindow
	case int64:
		return n, n >= 1 && n <= maxContextWindow
	case uint64:
		return int64(n), n >= 1 && n <= maxContextWindow
	case float64:
		return int64(n), n >= 1 && n <= maxContextWindow && n == math.Trunc(n)
	}
	return 0, false
}

func parseRouting(m map[string]any) (Routing, error) {
	raw, ok := m["routing"]
	if !ok {
		return Routing{}, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return Routing{}, fmt.Errorf("routing: expected object, got %T", raw)
	}
	sort, err := asString(obj, "sort")
	if err != nil {
		return Routing{}, fmt.Errorf("routing.%w", err)
	}
	dataCollection, err := asString(obj, "data_collection")
	if err != nil {
		return Routing{}, fmt.Errorf("routing.%w", err)
	}
	var requireParameters bool
	if v, ok := obj["require_parameters"]; ok {
		if requireParameters, ok = v.(bool); !ok {
			return Routing{}, fmt.Errorf("routing.require_parameters: expected boolean, got %T", v)
		}
	}
	maxPrice, err := parseMaxPrice(obj)
	if err != nil {
		return Routing{}, fmt.Errorf("routing.%w", err)
	}
	return Routing{Sort: sort, DataCollection: dataCollection, RequireParameters: requireParameters, MaxPrice: maxPrice}, nil
}

func parseMaxPrice(m map[string]any) (map[string]MaxPrice, error) {
	raw, ok := m["max_price"]
	if !ok {
		return nil, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("max_price: expected object, got %T", raw)
	}
	if len(obj) == 0 {
		return nil, nil
	}
	out := make(map[string]MaxPrice, len(obj))
	for model, rawEntry := range obj {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("max_price.%s: expected object, got %T", model, rawEntry)
		}
		var p MaxPrice
		var err error
		if p.Prompt, p.HasPrompt, err = asPrice(entry, "prompt"); err != nil {
			return nil, fmt.Errorf("max_price.%s.%w", model, err)
		}
		if p.Completion, p.HasCompletion, err = asPrice(entry, "completion"); err != nil {
			return nil, fmt.Errorf("max_price.%s.%w", model, err)
		}
		out[model] = p
	}
	return out, nil
}

func asPrice(m map[string]any, key string) (float64, bool, error) {
	v, ok := m[key]
	if !ok {
		return 0, false, nil
	}
	switch n := v.(type) {
	case uint64:
		return float64(n), true, nil
	case int64:
		return float64(n), true, nil
	case int:
		return float64(n), true, nil
	case float64:
		return n, true, nil
	}
	return 0, false, fmt.Errorf("%s: expected number, got %T", key, v)
}

func parseAuthHeader(m map[string]any) (*AuthHeader, error) {
	raw, ok := m["auth_header"]
	if !ok {
		return defaultAuthHeader(), nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("auth_header: expected object, got %T", raw)
	}
	name, err := asString(obj, "name")
	if err != nil {
		return nil, fmt.Errorf("auth_header.%w", err)
	}
	value, err := asString(obj, "value")
	if err != nil {
		return nil, fmt.Errorf("auth_header.%w", err)
	}
	return &AuthHeader{Name: name, Value: value}, nil
}

func defaultAuthHeader() *AuthHeader {
	return &AuthHeader{Name: defaultAuthHeaderName, Value: defaultAuthHeaderValue}
}

// asString returns the string at key, "" if the key is absent, or an error if
// present with a non-string type. Required-field presence is guaranteed upstream
// by schema validation.
func asString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s: expected string, got %T", key, v)
	}
	return s, nil
}
