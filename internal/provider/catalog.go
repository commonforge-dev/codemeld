// Selectable-provider catalog: merges configured provider.<name> entries with
// built-in providers that declare selectable models outside the provider: map
// (the OpenAI ChatGPT provider). It is the single source model validation, resume
// recovery, and no-selectable diagnostics cross-reference instead of the composed
// provider: map alone.
package provider

import (
	"slices"
)

// AuthKind classifies how a selectable provider resolves its request credentials,
// so turn dispatch can pick the credential source from the provider id
// without re-deriving it and never attaches ChatGPT session state to a custom
// provider.
type AuthKind string

const (
	// AuthKindConfigured resolves credentials from provider.<name>.api_key and the
	// configured auth_header (custom OpenAI-compatible providers and OpenRouter).
	AuthKindConfigured AuthKind = "configured"
	// AuthKindPlatform is the OpenAI Platform provider: the key resolves from
	// OPENAI_API_KEY when set and non-empty, otherwise from provider.openai.api_key
	// (see [ResolvePlatformAPIKey]).
	AuthKindPlatform AuthKind = "platform"
	// AuthKindChatGPTSession is the built-in OpenAI ChatGPT provider: credentials
	// come from the stored auth.openai-chatgpt session and OPENAI_API_KEY is ignored.
	AuthKindChatGPTSession AuthKind = "chatgpt_session"
)

// ModelOrigin records non-overridable provenance for a built-in provider's models.
// It is catalog metadata only and is empty for configured providers.
type ModelOrigin string

const (
	// OriginNone is the origin of a configured provider's models (no built-in
	// provenance).
	OriginNone ModelOrigin = ""
	// OriginChatGPTCodex marks the OpenAI ChatGPT provider's models as served by the
	// ChatGPT/Codex flow, not the OpenAI Platform chat-completions surface.
	OriginChatGPTCodex ModelOrigin = "chatgpt-codex"
)

// CatalogEntry is one selectable provider in the merged catalog: its stable
// provider id (persisted in model.active / model.last_used and matched at resume
// recovery), its human-facing display name, the selectable model id allowlist, the
// auth kind, the model origin, and whether it is a built-in row not read from
// settings. Models is in configured declaration order for configured providers and
// in built-in list order for built-ins. Stable provider ids — not display names —
// are persisted, emitted in events, and validated; display names are metadata for
// the picker.
type CatalogEntry struct {
	ID          string
	DisplayName string
	Models      []string
	AuthKind    AuthKind
	Origin      ModelOrigin
	Builtin     bool
}

func (e CatalogEntry) clone() CatalogEntry {
	e.Models = slices.Clone(e.Models)
	return e
}

// Catalog is the merged, ordered set of selectable providers: configured providers
// first (in sorted provider-id order) followed by built-in selectable providers.
// It is read-only after [BuildCatalog]; its accessors return defensive copies so a
// caller cannot mutate the cached session view.
type Catalog struct {
	order            []string
	byID             map[string]CatalogEntry
	effortByModel    map[string]map[string][]string
	toolsUnsupported map[string]map[string]bool
}

func (c *Catalog) addEffort(providerID, modelID string, efforts []string) {
	if c.effortByModel == nil {
		c.effortByModel = map[string]map[string][]string{}
	}
	if c.effortByModel[providerID] == nil {
		c.effortByModel[providerID] = map[string][]string{}
	}
	c.effortByModel[providerID][modelID] = efforts
}

func (c *Catalog) markToolsUnsupported(providerID, modelID string) {
	if c.toolsUnsupported == nil {
		c.toolsUnsupported = map[string]map[string]bool{}
	}
	if c.toolsUnsupported[providerID] == nil {
		c.toolsUnsupported[providerID] = map[string]bool{}
	}
	c.toolsUnsupported[providerID][modelID] = true
}

func (c *Catalog) add(e CatalogEntry) {
	if c.byID == nil {
		c.byID = map[string]CatalogEntry{}
	}
	c.order = append(c.order, e.ID)
	c.byID[e.ID] = e
}

// Entry returns a copy of the catalog entry for id and whether it is present. The
// boolean distinguishes an unknown provider from one present with an empty model
// list, which model validation relies on.
func (c Catalog) Entry(id string) (CatalogEntry, bool) {
	e, ok := c.byID[id]
	if !ok {
		return CatalogEntry{}, false
	}
	return e.clone(), true
}

// Entries returns copies of every catalog entry in catalog order (configured
// providers sorted by id, then built-ins); mutating the result does not change the
// catalog.
func (c Catalog) Entries() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.byID[id].clone())
	}
	return out
}

// EffortNoReasoning means no reasoning-effort parameter is sent.
const EffortNoReasoning = "no-reasoning"

func (c Catalog) SupportedEffort(providerID, modelID string) []string {
	if levels, ok := c.effortByModel[providerID][modelID]; ok {
		return slices.Clone(levels)
	}
	return []string{EffortNoReasoning}
}

func (c Catalog) SupportsTools(providerID, modelID string) bool {
	return !c.toolsUnsupported[providerID][modelID]
}

func BuildCatalog(configured map[string]ProviderEntry, chatGPTDiscovered []ChatGPTStoreModel, discoveredConfigured map[string][]DiscoveredConfiguredModel) Catalog {
	var cat Catalog

	names := make([]string, 0, len(configured))
	for name := range configured {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, id := range names {
		if _, reserved := builtinSelectable[id]; reserved {
			continue
		}
		disc := discoveredConfigured[id]
		if id == PlatformProviderID {
			disc = FilterPlatformDiscoveredModels(disc)
		}
		models := discoveredConfiguredIDs(disc)
		for _, m := range disc {
			if efforts := configuredEffortFromCapabilities(m.Capabilities); len(efforts) > 0 {
				cat.addEffort(id, m.ID, efforts)
			}
			if !SupportsTools(id, m.Capabilities) {
				cat.markToolsUnsupported(id, m.ID)
			}
		}
		cat.add(CatalogEntry{
			ID:          id,
			DisplayName: displayNameForID(id),
			Models:      models,
			AuthKind:    authKindForConfigured(id),
			Origin:      OriginNone,
			Builtin:     false,
		})
	}

	discovered := discoveredChatGPTModels(&cat, chatGPTDiscovered)

	builtinIDs := make([]string, 0, len(builtinSelectable))
	for id := range builtinSelectable {
		builtinIDs = append(builtinIDs, id)
	}
	slices.Sort(builtinIDs)
	for _, id := range builtinIDs {
		b := builtinSelectable[id]
		models := slices.Clone(b.models)
		if b.id == ChatGPTProviderID {
			models = mergeDiscoveredChatGPTModels(models, discovered)
		}
		cat.add(CatalogEntry{
			ID:          b.id,
			DisplayName: b.displayName,
			Models:      models,
			AuthKind:    b.authKind,
			Origin:      b.origin,
			Builtin:     true,
		})
	}

	return cat
}

func discoveredChatGPTModels(cat *Catalog, models []ChatGPTStoreModel) []string {
	var ids []string
	for _, m := range models {
		if m.ID == "" {
			continue
		}
		ids = append(ids, m.ID)
		if levels := configuredEffortFromCapabilities(effortCapabilitiesFromValue(m.Capabilities)); len(levels) > 0 {
			cat.addEffort(ChatGPTProviderID, m.ID, levels)
		}
	}
	return ids
}

// Neutral capability-map keys under which discovered reasoning-effort metadata is
// persisted in the shared models.yaml store, whichever structural shape the provider
// advertised it in. The discovery projection writes these keys and
// [configuredEffortFromCapabilities] reads them.
const (
	configuredSupportsReasoningEffortCapKey = "supportsReasoningEffort"
	configuredReasoningEffortOptionsCapKey  = "reasoningEffortOptions"
	configuredDefaultReasoningEffortCapKey  = "defaultReasoningEffort"
)

// discoveredConfiguredIDs projects the discovered configured-provider records into the
// selectable-id list, dropping blanks and preserving discovery order.
func discoveredConfiguredIDs(models []DiscoveredConfiguredModel) []string {
	ids := make([]string, 0, len(models))
	for _, m := range models {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

func configuredEffortFromCapabilities(caps map[string]any) []string {
	if b, ok := caps[configuredSupportsReasoningEffortCapKey].(bool); !ok || !b {
		return nil
	}
	var out []string
	for _, opt := range effortOptionStrings(caps[configuredReasoningEffortOptionsCapKey]) {
		if validEffortToken(opt) && !slices.Contains(out, opt) {
			out = append(out, opt)
		}
	}
	return out
}

// effortOptionStrings coerces a stored reasoningEffortOptions value into a string
// slice, tolerating both the []any that survives a models.yaml round-trip and a
// []string built in-memory; any non-string element is skipped so malformed metadata
// cannot crash the mapping.
func effortOptionStrings(v any) []string {
	switch list := v.(type) {
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return list
	default:
		return nil
	}
}

// mergeDiscoveredChatGPTModels appends discovered slugs not already present in
// seed, preserving seed order first so the compiled built-in list stays the
// offline fallback and discovered ids only extend it. Blank and duplicate slugs
// are dropped. seed must be a caller-owned slice (it may be appended to).
func mergeDiscoveredChatGPTModels(seed, discovered []string) []string {
	out := seed
	for _, id := range discovered {
		if id == "" || slices.Contains(out, id) {
			continue
		}
		out = append(out, id)
	}
	return out
}

// displayNameForID returns the human-facing display name for a configured provider
// id: the OpenAI Platform name for the Platform id, otherwise the id
// itself. Built-in providers carry their own display name in their registration.
func displayNameForID(id string) string {
	if id == PlatformProviderID {
		return platformDisplayName
	}
	return id
}

// authKindForConfigured returns the auth kind for a configured provider id: the
// OpenAI Platform id resolves to [AuthKindPlatform] (OPENAI_API_KEY precedence),
// every other configured id to [AuthKindConfigured] (provider.<name>.api_key /
// auth_header). The reserved OpenAI ChatGPT id never reaches here — it is rejected
// at load and supplied only as a built-in.
func authKindForConfigured(id string) AuthKind {
	if id == PlatformProviderID {
		return AuthKindPlatform
	}
	return AuthKindConfigured
}

type builtinProvider struct {
	id          string
	displayName string
	models      []string
	authKind    AuthKind
	origin      ModelOrigin
}

// builtinSelectable holds the built-in selectable providers keyed by provider id.
// It is separate from builtinAdapters: those declare OpenAI-compatible
// chat-completions defaults (base URL, Bearer auth), whereas a built-in selectable
// provider participates in selection without being a chat-completions provider
// (the OpenAI ChatGPT provider speaks the Responses API through its own adapter).
var builtinSelectable = map[string]*builtinProvider{}

func registerBuiltinSelectable(b *builtinProvider) {
	builtinSelectable[b.id] = b
}
