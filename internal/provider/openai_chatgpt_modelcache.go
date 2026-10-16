// Sanitized parse+adapt shape for ChatGPT/Codex discovered models: the codemeld-owned
// struct that keeps only selection/capability metadata (never the discovery response's
// prompt-bearing instructions/messages or raw bodies) and adapts it into the shared
// discovered-model store's neutral entry shape the connect-path writer persists.
package provider

import (
	"encoding/json"
)

// chatGPTModelCache is the codemeld-owned, persisted ChatGPT/Codex model list. It
// carries only selection/capability metadata; the discovery response's prompt-bearing
// base_instructions and model_messages have no field here, so they are dropped by
// construction before anything reaches disk.
type chatGPTModelCache struct {
	Models []chatGPTModel `json:"models"`
}

// chatGPTModel is one discovered model's whitelisted selection/capability metadata.
// Every field is safe to persist and display; the response's base_instructions,
// model_messages, and any other unmodeled field are intentionally absent so they can
// never be unmarshaled, stored, or logged. supported_reasoning_levels is kept as raw
// JSON because this slice only preserves the discovered levels verbatim — the effort
// selection policy (including xhigh mapping) is decided by the catalog-wiring task.
type chatGPTModel struct {
	Slug                     string          `json:"slug"`
	DisplayName              string          `json:"display_name,omitempty"`
	Description              string          `json:"description,omitempty"`
	ContextWindow            int64           `json:"context_window,omitempty"`
	MaxContextWindow         int64           `json:"max_context_window,omitempty"`
	InputModalities          []string        `json:"input_modalities,omitempty"`
	SupportedReasoningLevels json.RawMessage `json:"supported_reasoning_levels,omitempty"`
	DefaultReasoningLevel    string          `json:"default_reasoning_level,omitempty"`
	SupportVerbosity         bool            `json:"support_verbosity,omitempty"`
	DefaultVerbosity         string          `json:"default_verbosity,omitempty"`
	SupportedInAPI           bool            `json:"supported_in_api,omitempty"`
	MinimalClientVersion     string          `json:"minimal_client_version,omitempty"`
	Priority                 int64           `json:"priority,omitempty"`
	Visibility               string          `json:"visibility,omitempty"`
	PreferWebsockets         bool            `json:"prefer_websockets,omitempty"`
	UseResponsesLite         bool            `json:"use_responses_lite,omitempty"`
	ApplyPatchToolType       string          `json:"apply_patch_tool_type,omitempty"`
	WebSearchToolType        string          `json:"web_search_tool_type,omitempty"`
}

// ChatGPTStoreModel is one discovered ChatGPT model adapted to the shared
// discovered-model store's neutral shape: selection/capability metadata only. It is the
// boundary type the connect-path writer consumes so the provider package need not import
// internal/config (which would cycle); the CLI maps it onto the store's own record type.
// Capabilities carries the remaining whitelisted ChatGPT fields (reasoning levels,
// verbosity, …) as a generic map, so no prompt-bearing or raw-response data can ride
// along — chatGPTModel has no field for those.
type ChatGPTStoreModel struct {
	ID              string
	DisplayName     string
	ContextWindow   int64
	InputModalities []string
	Capabilities    map[string]any
}

// chatGPTStoreModels adapts a sanitized discovery result into the neutral store records
// the connect-path writer persists. The core selection fields are promoted to named
// fields; every other whitelisted field is carried under Capabilities so a later catalog
// task (effort/verbosity policy) still sees the discovered metadata.
func chatGPTStoreModels(cache chatGPTModelCache) []ChatGPTStoreModel {
	out := make([]ChatGPTStoreModel, 0, len(cache.Models))
	for _, m := range cache.Models {
		out = append(out, ChatGPTStoreModel{
			ID:              m.Slug,
			DisplayName:     m.DisplayName,
			ContextWindow:   m.ContextWindow,
			InputModalities: m.InputModalities,
			Capabilities:    chatGPTCapabilities(m),
		})
	}
	return out
}

// chatGPTCapabilities projects a whitelisted chatGPTModel onto a generic capabilities
// map, keeping every safe field except the ones promoted to named ChatGPTStoreModel
// fields. It round-trips through the model's own JSON tags, so a field can only appear
// here if chatGPTModel models it — the prompt-bearing base_instructions/model_messages
// have no field and cannot leak. It returns nil when nothing remains so the store's
// omitempty capabilities key stays absent.
func chatGPTCapabilities(m chatGPTModel) map[string]any {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var all map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil
	}
	for _, promoted := range []string{"slug", "display_name", "context_window", "input_modalities"} {
		delete(all, promoted)
	}
	if len(all) == 0 {
		return nil
	}
	return all
}
