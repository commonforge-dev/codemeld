// Table tests for model selection shape parsing and cross-reference validation.
package model

import (
	"path/filepath"
	"testing"

	"codemeld.dev/codemeld/internal/config"
)

// validSelection is the canonical well-formed model.active/last_used mapping.
func validSelection() map[string]any {
	return map[string]any{
		"provider": "openai",
		"id":       "gpt-5.5",
		"effort":   "high",
	}
}

func TestParseSelection_Valid(t *testing.T) {
	tests := []struct {
		name   string
		effort string
	}{
		{"effort none", "none"},
		{"effort high", "high"},
		{"effort minimal", "minimal"},
		{"effort low", "low"},
		{"effort medium", "medium"},
		{"effort xhigh", "xhigh"},
		{"effort default", EffortDefault},
		{"effort no-reasoning sentinel", EffortNoReasoning},
		{"effort max", "max"},
		{"effort ultra", "ultra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := validSelection()
			raw["effort"] = tt.effort
			sel, serr := ParseSelection(raw)
			if serr != nil {
				t.Fatalf("ParseSelection() error = %v, want nil", serr)
			}
			if sel.Provider != "openai" || sel.ID != "gpt-5.5" || sel.Effort != tt.effort {
				t.Fatalf("ParseSelection() = %+v, want provider=openai id=gpt-5.5 effort=%s", sel, tt.effort)
			}
		})
	}
}

func TestParseSelection_Failures(t *testing.T) {
	tests := []struct {
		name string
		raw  any
		want Category
	}{
		{"value is string", "openai", CategoryNotObject},
		{"value is number", 5, CategoryNotObject},
		{"value is list", []any{"openai"}, CategoryNotObject},
		{"value is null", nil, CategoryNotObject},

		{"missing provider", map[string]any{"id": "gpt-5.5", "effort": "high"}, CategoryMissingField},
		{"missing id", map[string]any{"provider": "openai", "effort": "high"}, CategoryMissingField},
		{"missing effort", map[string]any{"provider": "openai", "id": "gpt-5.5"}, CategoryMissingField},

		{"provider wrong type", map[string]any{"provider": 1, "id": "gpt-5.5", "effort": "high"}, CategoryWrongType},
		{"id wrong type", map[string]any{"provider": "openai", "id": []any{}, "effort": "high"}, CategoryWrongType},
		{"effort wrong type", map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": 3}, CategoryWrongType},
		{"effort null", map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": nil}, CategoryWrongType},

		{"effort empty", map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": ""}, CategoryEffortInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel, serr := ParseSelection(tt.raw)
			if serr == nil {
				t.Fatalf("ParseSelection() error = nil, want category %q", tt.want)
			}
			if sel != nil {
				t.Fatalf("ParseSelection() selection = %+v, want nil on failure", sel)
			}
			if serr.Category != tt.want {
				t.Fatalf("ParseSelection() category = %q, want %q", serr.Category, tt.want)
			}
		})
	}
}

func TestParseSelection_ModelNotAliasForID(t *testing.T) {
	raw := map[string]any{"provider": "openai", "model": "gpt-5.5", "effort": "high"}
	sel, serr := ParseSelection(raw)
	if serr == nil {
		t.Fatalf("ParseSelection() error = nil, want missing-field for id")
	}
	if sel != nil {
		t.Fatalf("ParseSelection() selection = %+v, want nil", sel)
	}
	if serr.Category != CategoryMissingField || serr.Field != "id" {
		t.Fatalf("ParseSelection() = {category %q field %q}, want {%q id}", serr.Category, serr.Field, CategoryMissingField)
	}
}

func TestParseSelection_FieldDetail(t *testing.T) {
	_, serr := ParseSelection(map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": ""})
	if serr == nil {
		t.Fatal("ParseSelection() error = nil, want empty-effort failure")
	}
	if serr.Field != "effort" || serr.Value != "" {
		t.Fatalf("ShapeError = {field %q value %q}, want {effort \"\"}", serr.Field, serr.Value)
	}
}

var (
	advertisedEfforts        = []string{"none", "minimal", "low", "medium", "high", "xhigh", EffortDefault, "max"}
	advertisedChatGPTEfforts = []string{"none", "low", "medium", "high", "xhigh"}
)

func seedDiscoveredProvider(t *testing.T, globalPath, providerID string, caps map[string]any, ids ...string) {
	t.Helper()
	models := make([]config.DiscoveredModel, len(ids))
	for i, id := range ids {
		models[i] = config.DiscoveredModel{ID: id, Capabilities: caps}
	}
	if err := config.UpdateDiscoveredModelsProvider(
		config.DiscoveredModelsPath(globalPath), providerID,
		config.DiscoveredProvider{Models: models},
	); err != nil {
		t.Fatalf("seed discovered %s models: %v", providerID, err)
	}
}

func configuredEffortCaps(efforts []string) map[string]any {
	if len(efforts) == 0 {
		return nil
	}
	options := make([]any, len(efforts))
	for i, effort := range efforts {
		options[i] = effort
	}
	return map[string]any{"supportsReasoningEffort": true, "reasoningEffortOptions": options}
}

func chatGPTEffortCaps(efforts []string) map[string]any {
	if len(efforts) == 0 {
		return nil
	}
	levels := make([]any, len(efforts))
	for i, effort := range efforts {
		levels[i] = map[string]any{"effort": effort}
	}
	return map[string]any{"supported_reasoning_levels": levels}
}

func fixtureCache(t *testing.T, advertise bool, model map[string]any) *config.Cache {
	t.Helper()
	var openAIEfforts, chatGPTEfforts []string
	if advertise {
		openAIEfforts, chatGPTEfforts = advertisedEfforts, advertisedChatGPTEfforts
	}
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	seedDiscoveredProvider(t, globalPath, "openai", configuredEffortCaps(openAIEfforts), "gpt-5.5", "gpt-5.5-pro")
	seedDiscoveredProvider(t, globalPath, "openai-chatgpt", chatGPTEffortCaps(chatGPTEfforts), "gpt-5.5", "gpt-5.4", "gpt-5.3-codex-spark")
	composed := map[string]any{
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
			},
		},
	}
	if model != nil {
		composed["model"] = model
	}
	cache, err := config.NewCache(composed, t.TempDir(), []string{globalPath})
	if err != nil {
		t.Fatalf("config.NewCache() error = %v", err)
	}
	return cache
}

func newTestCache(t *testing.T) *config.Cache { return fixtureCache(t, true, nil) }

func newBareTestCache(t *testing.T) *config.Cache { return fixtureCache(t, false, nil) }

func TestValidate(t *testing.T) {
	cache := newTestCache(t)
	tests := []struct {
		name string
		sel  *Selection
		want *Category // nil means success
	}{
		{"valid selection", &Selection{Provider: "openai", ID: "gpt-5.5", Effort: "high"}, nil},
		{"valid selection, second allowlisted id", &Selection{Provider: "openai", ID: "gpt-5.5-pro", Effort: EffortDefault}, nil},
		{"provider not in catalog", &Selection{Provider: "anthropic", ID: "gpt-5.5", Effort: "high"}, catPtr(CategoryProviderUnknown)},
		{"id not in allowlist", &Selection{Provider: "openai", ID: "gpt-9", Effort: "high"}, catPtr(CategoryModelNotAllowed)},
		// provider: openai-chatgpt validates against the built-in
		// catalog even though provider.openai-chatgpt is never configured.
		{"chatgpt built-in model", &Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: "high"}, nil},
		{"chatgpt built-in added model", &Selection{Provider: "openai-chatgpt", ID: "gpt-5.3-codex-spark", Effort: "high"}, nil},
		{"chatgpt pro removed from built-in list", &Selection{Provider: "openai-chatgpt", ID: "gpt-5.5-pro", Effort: EffortDefault}, catPtr(CategoryModelNotAllowed)},
		{"chatgpt id not in built-in list", &Selection{Provider: "openai-chatgpt", ID: "gpt-9", Effort: "high"}, catPtr(CategoryModelNotAllowed)},
		{"unknown provider outranks an unadvertised effort", &Selection{Provider: "anthropic", ID: "gpt-5.5", Effort: "ultra"}, catPtr(CategoryProviderUnknown)},
		{"unknown id outranks an unadvertised effort", &Selection{Provider: "openai", ID: "gpt-9", Effort: "ultra"}, catPtr(CategoryModelNotAllowed)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serr := Validate(tt.sel, cache)
			if tt.want == nil {
				if serr != nil {
					t.Fatalf("Validate() error = %v, want nil", serr)
				}
				return
			}
			if serr == nil {
				t.Fatalf("Validate() error = nil, want category %q", *tt.want)
			}
			if serr.Category != *tt.want {
				t.Fatalf("Validate() category = %q, want %q", serr.Category, *tt.want)
			}
		})
	}
}

// TestValidate_SameModelIDUnderBothProviders confirms Done-when 2:
// the same model id validates under both openai and openai-chatgpt, disambiguated by
// provider id, with no built-in catalog row read from provider.openai-chatgpt.
func TestValidate_SameModelIDUnderBothProviders(t *testing.T) {
	cache := newTestCache(t)
	if serr := Validate(&Selection{Provider: "openai", ID: "gpt-5.5", Effort: "high"}, cache); serr != nil {
		t.Fatalf("Validate(openai, gpt-5.5) = %v, want nil", serr)
	}
	if serr := Validate(&Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: "high"}, cache); serr != nil {
		t.Fatalf("Validate(openai-chatgpt, gpt-5.5) = %v, want nil", serr)
	}
}

// TestValidate_ChatGPTSelectableWithoutConfiguredProviders confirms a fresh config
// with no provider: map still validates a provider: openai-chatgpt selection against
// the always-present built-in catalog.
func TestValidate_ChatGPTSelectableWithoutConfiguredProviders(t *testing.T) {
	cache, err := config.NewCache(map[string]any{}, "/project", nil)
	if err != nil {
		t.Fatalf("config.NewCache() error = %v", err)
	}
	if serr := Validate(&Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: EffortNoReasoning}, cache); serr != nil {
		t.Fatalf("Validate(openai-chatgpt, gpt-5.5) with no providers = %v, want nil", serr)
	}
	if serr := Validate(&Selection{Provider: "openai", ID: "gpt-5.5", Effort: EffortNoReasoning}, cache); serr == nil {
		t.Fatal("Validate(openai, gpt-5.5) with no providers = nil, want provider-unknown (openai is configured-only)")
	}
}

func TestValidate_Effort(t *testing.T) {
	cache := newTestCache(t)
	tests := []struct {
		name    string
		sel     *Selection
		wantErr bool
	}{
		{"sentinel on a configured provider", &Selection{Provider: "openai", ID: "gpt-5.5", Effort: EffortNoReasoning}, false},
		{"sentinel on a built-in provider", &Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: EffortNoReasoning}, false},
		{"advertised literal default", &Selection{Provider: "openai", ID: "gpt-5.5", Effort: EffortDefault}, false},
		{"advertised provider token outside the old enum", &Selection{Provider: "openai", ID: "gpt-5.5", Effort: "max"}, false},
		{"advertised token on a built-in provider", &Selection{Provider: "openai-chatgpt", ID: "gpt-5.4", Effort: "high"}, false},
		{"unadvertised token", &Selection{Provider: "openai", ID: "gpt-5.5", Effort: "ultra"}, true},
		{"literal default unadvertised for this model", &Selection{Provider: "openai-chatgpt", ID: "gpt-5.4", Effort: EffortDefault}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serr := Validate(tt.sel, cache)
			if tt.wantErr {
				if serr == nil {
					t.Fatalf("Validate(%+v) = nil, want %q", tt.sel, CategoryEffortNotAdvertised)
				}
				if serr.Category != CategoryEffortNotAdvertised || serr.Field != "effort" || serr.Value != tt.sel.Effort {
					t.Fatalf("Validate() = {category %q field %q value %q}, want {%q effort %q}",
						serr.Category, serr.Field, serr.Value, CategoryEffortNotAdvertised, tt.sel.Effort)
				}
				return
			}
			if serr != nil {
				t.Fatalf("Validate(%+v) = %v, want nil", tt.sel, serr)
			}
		})
	}
}

func TestValidate_EffortNoCapabilityMetadata(t *testing.T) {
	cache := newBareTestCache(t)
	if serr := Validate(&Selection{Provider: "openai", ID: "gpt-5.5", Effort: EffortNoReasoning}, cache); serr != nil {
		t.Fatalf("Validate(no-reasoning) = %v, want nil — the sentinel never depends on metadata", serr)
	}
	for _, effort := range []string{"high", EffortDefault} {
		if serr := Validate(&Selection{Provider: "openai", ID: "gpt-5.5", Effort: effort}, cache); serr == nil {
			t.Fatalf("Validate(%q) = nil, want rejection when the model advertises no efforts", effort)
		}
	}
}

func catPtr(c Category) *Category { return &c }
