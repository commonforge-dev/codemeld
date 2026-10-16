// OpenAI-compatible API-key GET /models discovery: a redirect-refusing, credential-safe request returning sanitized model ids plus whitelisted reasoning-effort capability metadata.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// apiKeyModelsPath is the OpenAI-compatible discovery endpoint appended to a
// provider's base URL.
const apiKeyModelsPath = "/models"

// maxModelIDLength caps a discovered id so a hostile or malformed /models
// response cannot smuggle a large blob through as a "model id".
const maxModelIDLength = 200

// maxEffortOptionLength caps a discovered reasoning-effort option so a hostile or
// malformed /models response cannot smuggle a large blob through as an "option"
// (the effort names codemeld recognises are short words such as "low"/"xhigh").
const maxEffortOptionLength = 32

const (
	modalityText  = "text"
	modalityImage = "image"
)

const (
	configuredSupportsMultipleImagesCapKey   = "supportsMultipleImages"
	configuredMaxImagesCapKey                = "maxImages"
	configuredSupportedParametersCapKey      = "supportedParameters"
	configuredSupportedParametersEmptyCapKey = "supportedParametersEmpty"
	configuredSupportsFunctionCallingCapKey  = "supportsFunctionCalling"
)

// Both caps sit well clear of any real OpenRouter supported_parameters list, so they
// only ever reject malformed or hostile metadata.
const (
	maxSupportedParameterLength = 64
	maxSupportedParameterCount  = 64
)

// DiscoveredConfiguredModel is one model surfaced by OpenAI-compatible /models
// discovery: its sanitized id plus, when the provider advertises reasoning-effort
// capability metadata in one of the shapes [effortShapes] declares, a whitelisted
// capabilities map (nil otherwise). It is what [DiscoverAPIKeyModels] returns and
// the shape [BuildCatalog] consumes for a configured provider's discovered models.
type DiscoveredConfiguredModel struct {
	ID              string
	InputModalities []string
	Capabilities    map[string]any
}

// APIKeyDiscoveryConfig is the input to DiscoverAPIKeyModels. ProviderName is
// used only in error surface text; Entry supplies the base URL and the resolved
// auth header (ProviderEntry.ResolveAuthHeader); HTTPClient is an optional
// injection point for tests (nil uses http.DefaultClient). Timeout and
// cancellation are the caller's responsibility via ctx — no client-level timeout
// is set here.
type APIKeyDiscoveryConfig struct {
	ProviderName string
	Entry        ProviderEntry
	HTTPClient   *http.Client
}

type apiKeyModelList struct {
	Data []json.RawMessage `json:"data"`
}

func decodeAPIKeyCapabilities(modelSpec json.RawMessage) apiKeyCapabilities {
	var caps apiKeyCapabilities
	if len(modelSpec) == 0 {
		return caps
	}
	var spec struct {
		Capabilities json.RawMessage `json:"capabilities"`
	}
	if err := json.Unmarshal(modelSpec, &spec); err != nil || len(spec.Capabilities) == 0 {
		return caps
	}
	dec := json.NewDecoder(bytes.NewReader(spec.Capabilities))
	dec.UseNumber()
	if err := dec.Decode(&caps); err != nil {
		return apiKeyCapabilities{}
	}
	return caps
}

type apiKeyCapabilities struct {
	SupportsVision          any `json:"supportsVision"`
	SupportsMultipleImages  any `json:"supportsMultipleImages"`
	MaxImages               any `json:"maxImages"`
	SupportsFunctionCalling any `json:"supportsFunctionCalling"`
}

// DiscoverAPIKeyModels performs an OpenAI-compatible GET <base_url>/models
// request bearing the provider's configured api key and returns the sanitized,
// de-duplicated models in response order — each carrying its id and, when the
// provider advertises reasoning-effort capabilities in a declared shape, a
// whitelisted capabilities map. It is a narrow, opt-in discovery entry point: the
// caller passes an explicit provider id, base URL, and resolved auth header, so it
// never overclaims compatibility for a provider that was not asked for.
//
// It is credential-safe: the HTTP client is redirect-pinned, so a 3xx is handed
// back unfollowed and the api key is never re-sent to a redirect Location; a
// redirect and every other non-2xx surface as a body-free *HTTPError; a malformed
// or empty body surfaces as a validation error carrying no api key, auth header,
// or raw/provider error body. Only whitelisted fields survive the projection, so no
// prompt-, secret-, or raw-body content reaches the returned capabilities. It writes
// nothing — the caller persists the result.
func DiscoverAPIKeyModels(ctx context.Context, cfg APIKeyDiscoveryConfig) ([]DiscoveredConfiguredModel, error) {
	authName, authValue := cfg.Entry.ResolveAuthHeader()
	// Belt-and-suspenders: no error path below embeds the body or the auth value,
	// but any transport/decode error text is scrubbed of the key and full header
	// value so a wrapped library message can never leak them.
	redact := func(s string) string { return redactCredentials(s, cfg.Entry.APIKey, authValue) }

	reqURL := strings.TrimSuffix(cfg.Entry.BaseURL, "/") + apiKeyModelsPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("provider %s model discovery: build request: %s", cfg.ProviderName, redact(err.Error()))
	}
	httpReq.Header.Set("Accept", "application/json")
	if authName != "" {
		httpReq.Header.Set(authName, authValue)
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := pinRedirects(hc).Do(httpReq)
	if err != nil {
		// Transport/TLS failure: the error names only the origin and path, no
		// credentials, but scrub it anyway before surfacing.
		return nil, fmt.Errorf("provider %s model discovery: %s", cfg.ProviderName, redact(err.Error()))
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// Covers a refused redirect (pinRedirects hands the 3xx back unfollowed, so
		// the key is never forwarded to the Location) and any other non-2xx. Drop the
		// body entirely: it can echo the key or carry provider error prose.
		return nil, newHTTPError(cfg.ProviderName, res.StatusCode, "", res.Header.Get("Retry-After"))
	}

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("provider %s model discovery: read response: %s", cfg.ProviderName, redact(err.Error()))
	}
	var list apiKeyModelList
	if err := json.Unmarshal(raw, &list); err != nil {
		// Redact and drop the raw body: a malformed body can be large and secret-bearing.
		return nil, fmt.Errorf("provider %s model discovery: decode response: %s", cfg.ProviderName, redact(err.Error()))
	}

	seen := map[string]struct{}{}
	models := make([]DiscoveredConfiguredModel, 0, len(list.Data))
	for _, entry := range list.Data {
		// Only "id", "architecture", "supported_parameters", and the roots [effortShapes]
		// declares may be read from this map; the other top-level values are captured as
		// raw bytes and must never be decoded or projected.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil {
			continue
		}
		var declaredID string
		if err := json.Unmarshal(fields["id"], &declaredID); err != nil {
			continue
		}
		id := strings.TrimSpace(declaredID)
		if id == "" || len(id) > maxModelIDLength {
			continue
		}
		// ponytail: conservative allowlist charset covering real OpenAI-compatible ids
		// (e.g. "gpt-4o-mini", "meta-llama/llama-3.1-8b:free", "venice-uncensored").
		// Anything with whitespace, control chars, or non-ASCII is dropped as unusable.
		safe := true
		for _, r := range id {
			allowed := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
				r == '-' || r == '.' || r == '_' || r == '/' || r == ':'
			if !allowed {
				safe = false
				break
			}
		}
		if !safe {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		caps := decodeAPIKeyCapabilities(fields["model_spec"])
		modalities, visionCaps := visionMetadata(fields["architecture"], caps)
		reasoning := effortCapabilitiesFromRawFields(fields)
		toolCaps := toolMetadata(fields["supported_parameters"], caps)
		models = append(models, DiscoveredConfiguredModel{
			ID:              id,
			InputModalities: modalities,
			Capabilities:    mergeCapabilities(mergeCapabilities(reasoning, visionCaps), toolCaps),
		})
	}
	if len(models) == 0 {
		// Non-2xx already handled above; an empty usable list from a 2xx body is a
		// validation failure with no body or secret echoed.
		return nil, fmt.Errorf("provider %s model discovery: no usable models in response", cfg.ProviderName)
	}
	return models, nil
}

// Options are stored as []any so the record matches the shape read back after a
// models.yaml round-trip.
func sanitizeEffortOptions(options []string) []any {
	out := make([]any, 0, len(options))
	for _, o := range options {
		o = strings.TrimSpace(o)
		if !validEffortToken(o) || slices.Contains(out, any(o)) {
			continue
		}
		out = append(out, o)
	}
	return out
}

// The two tool-call sources are OpenRouter's top-level supported_parameters array and
// Venice's model_spec.capabilities supportsFunctionCalling flag.
func toolMetadata(supportedParameters json.RawMessage, caps apiKeyCapabilities) map[string]any {
	out := map[string]any{}
	if names, sourceCount, ok := sanitizeSupportedParameters(supportedParameters); ok {
		switch {
		case sourceCount == 0:
			out[configuredSupportedParametersEmptyCapKey] = true
		case len(names) > 0:
			out[configuredSupportedParametersCapKey] = names
		}
	}
	if b, ok := caps.SupportsFunctionCalling.(bool); ok {
		out[configuredSupportsFunctionCallingCapKey] = b
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// The returned count is the source array's own length, which is what separates a
// provider's explicit empty list — negative evidence — from a non-empty list nothing
// survived, which is not. Names are stored as []any to match the shape a models.yaml
// round-trip reads back.
func sanitizeSupportedParameters(raw json.RawMessage) ([]any, int, bool) {
	trimmed := bytes.TrimSpace(raw)
	// A JSON null decodes into a nil slice without error, which would otherwise be
	// indistinguishable from an explicit empty array.
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, 0, false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, 0, false
	}
	// Truncating an over-cap list could drop a later "tools" entry and gate a capable
	// model off, so an oversized list is ignored whole rather than cut down.
	if len(items) > maxSupportedParameterCount {
		return nil, 0, false
	}
	out := make([]any, 0, len(items))
	for _, item := range items {
		// A JSON null unmarshals into a string without error and leaves it empty, so the
		// element's own token has to be checked to keep null off the valid-string path.
		elem := bytes.TrimSpace(item)
		if len(elem) == 0 || elem[0] != '"' {
			return nil, 0, false
		}
		var s string
		if err := json.Unmarshal(elem, &s); err != nil {
			return nil, 0, false
		}
		s = strings.TrimSpace(s)
		if !validSupportedParameterToken(s) || slices.Contains(out, any(s)) {
			continue
		}
		out = append(out, s)
	}
	return out, len(items), true
}

// Real OpenRouter parameter names carry underscores and digits, so this cannot reuse
// [validEffortToken], whose letters-and-hyphens charset would reject the whole list.
func validSupportedParameterToken(s string) bool {
	if s == "" || len(s) > maxSupportedParameterLength {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// Reject malformed effort tokens before persisting provider metadata.
func validEffortToken(s string) bool {
	if s == "" || len(s) > maxEffortOptionLength {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
			return false
		}
	}
	return true
}

func visionMetadata(arch json.RawMessage, caps apiKeyCapabilities) ([]string, map[string]any) {
	modalities := openRouterInputModalities(arch)

	vision, _ := caps.SupportsVision.(bool)
	if vision && !slices.Contains(modalities, modalityImage) {
		modalities = append(modalities, modalityImage)
	}

	var visionCaps map[string]any
	if multi, _ := caps.SupportsMultipleImages.(bool); vision && multi {
		visionCaps = map[string]any{configuredSupportsMultipleImagesCapKey: true}
		if n, ok := positiveIntegral(caps.MaxImages); ok {
			visionCaps[configuredMaxImagesCapKey] = n
		}
	}
	if len(modalities) == 0 {
		modalities = nil
	}
	return modalities, visionCaps
}

func openRouterInputModalities(arch json.RawMessage) []string {
	if len(arch) == 0 {
		return nil
	}
	var obj struct {
		InputModalities []json.RawMessage `json:"input_modalities"`
	}
	if err := json.Unmarshal(arch, &obj); err != nil {
		return nil
	}
	var out []string
	for _, e := range obj.InputModalities {
		var s string
		if err := json.Unmarshal(e, &s); err != nil {
			continue
		}
		s = strings.TrimSpace(s)
		if (s == modalityText || s == modalityImage) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func positiveIntegral(v any) (int, bool) {
	num, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := num.Int64()
	if err != nil || i <= 0 {
		return 0, false
	}
	n := int(i)
	if int64(n) != i {
		return 0, false
	}
	return n, true
}

func mergeCapabilities(reasoning, vision map[string]any) map[string]any {
	if len(vision) == 0 {
		return reasoning
	}
	if reasoning == nil {
		reasoning = make(map[string]any, len(vision))
	}
	for k, v := range vision {
		reasoning[k] = v
	}
	return reasoning
}
