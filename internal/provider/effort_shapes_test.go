package provider

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	veniceShapeBody     = `{"model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":["low","high"],"defaultReasoningEffort":"high"}}}`
	openRouterShapeBody = `{"reasoning":{"supported_efforts":["low","high"],"default_effort":"high"}}`
	chatGPTShapeBody    = `{"supported_reasoning_levels":[{"effort":"low"},{"effort":"high"}],"default_reasoning_level":"high"}`
)

func rawShapeCaps(t *testing.T, body string) map[string]any {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatalf("fixture %s is not a JSON object: %v", body, err)
	}
	return effortCapabilitiesFromRawFields(fields)
}

func decodedShapeCaps(t *testing.T, body string) map[string]any {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		t.Fatalf("fixture %s is not JSON: %v", body, err)
	}
	return effortCapabilitiesFromValue(value)
}

func assertShapeCaps(t *testing.T, body string, want map[string]any) {
	t.Helper()
	if got := rawShapeCaps(t, body); !reflect.DeepEqual(got, want) {
		t.Errorf("raw-message walk of %s = %v, want %v", body, got, want)
	}
	if got := decodedShapeCaps(t, body); !reflect.DeepEqual(got, want) {
		t.Errorf("decoded walk of %s = %v, want %v", body, got, want)
	}
}

func shapeCaps(options []any, def string) map[string]any {
	out := map[string]any{
		configuredSupportsReasoningEffortCapKey: true,
		configuredReasoningEffortOptionsCapKey:  options,
	}
	if def != "" {
		out[configuredDefaultReasoningEffortCapKey] = def
	}
	return out
}

func TestEffortShapes_EveryShapeYieldsIdenticalNeutralOutput(t *testing.T) {
	want := shapeCaps([]any{"low", "high"}, "high")
	for _, tc := range []struct{ name, body string }{
		{"venice", veniceShapeBody},
		{"openrouter", openRouterShapeBody},
		{"chatgpt", chatGPTShapeBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertShapeCaps(t, tc.body, want)
		})
	}
}

func TestEffortShapes_NoUsableOptions(t *testing.T) {
	blob := strings.Repeat("a", maxEffortOptionLength+1)
	tests := []struct{ name, body string }{
		{"no table root", `{"id":"m1","supported_parameters":["reasoning"]}`},
		{"venice gate false", `{"model_spec":{"capabilities":{"supportsReasoningEffort":false,"reasoningEffortOptions":["low"]}}}`},
		{"venice gate absent", `{"model_spec":{"capabilities":{"reasoningEffortOptions":["low"]}}}`},
		{"venice gate malformed", `{"model_spec":{"capabilities":{"supportsReasoningEffort":"yes","reasoningEffortOptions":["low"]}}}`},
		{"venice root scalar", `{"model_spec":"none"}`},
		{"venice malformed container", `{"model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":"low"}}}`},
		{"venice all invalid", `{"model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":["has space","","` + blob + `"]}}}`},
		{"openrouter root scalar", `{"reasoning":"enabled"}`},
		{"openrouter options absent", `{"reasoning":{"default_effort":"high"}}`},
		{"openrouter malformed container", `{"reasoning":{"supported_efforts":{"low":true}}}`},
		{"openrouter all invalid", `{"reasoning":{"supported_efforts":[1,null,"has space"]}}`},
		{"chatgpt malformed container", `{"supported_reasoning_levels":{"effort":"low"}}`},
		{"chatgpt all invalid", `{"supported_reasoning_levels":["low",{"description":"max"},{"effort":123},7]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertShapeCaps(t, tc.body, nil)
		})
	}
}

func TestEffortShapes_MixedListsKeepValidSiblingsInOrder(t *testing.T) {
	tests := []struct {
		name, body string
		want       []any
	}{
		{"venice", `{"model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":["max",5,"bad option",null,{"effort":"high"}," ultra "]}}}`, []any{"max", "ultra"}},
		{"openrouter", `{"reasoning":{"supported_efforts":["max",5,"bad option",null,"low"]}}`, []any{"max", "low"}},
		{"chatgpt", `{"supported_reasoning_levels":[{"effort":"max"},"low",{"description":"none"},{"effort":"bad token","level":"high"},7]}`, []any{"max", "high"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertShapeCaps(t, tc.body, shapeCaps(tc.want, ""))
		})
	}
}

func TestEffortShapes_PreserveAdvertisedOrderAndDropDuplicates(t *testing.T) {
	blob := strings.Repeat("a", maxEffortOptionLength+1)
	body := `{"reasoning":{"supported_efforts":["max","low","max"," high ","","bad option","` + blob + `","low"]}}`
	assertShapeCaps(t, body, shapeCaps([]any{"max", "low", "high"}, ""))
}

func TestEffortShapes_ChatGPTObjectFieldPrecedence(t *testing.T) {
	tests := []struct {
		name, entry string
		want        []any
	}{
		{"current wins", `{"effort":"high","level":"low"}`, []any{"high"}},
		{"unknown current still wins", `{"effort":"max","level":"high"}`, []any{"max"}},
		{"blank current falls back", `{"effort":"","level":"high"}`, []any{"high"}},
		{"non-string current falls back", `{"effort":123,"level":"high"}`, []any{"high"}},
		{"malformed current falls back", `{"effort":"very high","level":"ultra"}`, []any{"ultra"}},
		{"legacy only", `{"level":"minimal"}`, []any{"minimal"}},
		{"both unusable", `{"effort":"very high","level":""}`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var want map[string]any
			if tc.want != nil {
				want = shapeCaps(tc.want, "")
			}
			assertShapeCaps(t, `{"supported_reasoning_levels":[`+tc.entry+`]}`, want)
		})
	}
}

func TestEffortShapes_FirstMatchingShapeWins(t *testing.T) {
	tests := []struct {
		name, body string
		want       []any
	}{
		{"venice precedes openrouter",
			`{"model_spec":{"capabilities":{"supportsReasoningEffort":true,"reasoningEffortOptions":["low"]}},"reasoning":{"supported_efforts":["high"]}}`,
			[]any{"low"}},
		{"closed venice gate falls through",
			`{"model_spec":{"capabilities":{"supportsReasoningEffort":false,"reasoningEffortOptions":["low"]}},"reasoning":{"supported_efforts":["high"]}}`,
			[]any{"high"}},
		{"absent earlier roots reach the last shape",
			`{"supported_reasoning_levels":[{"effort":"minimal"}]}`,
			[]any{"minimal"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertShapeCaps(t, tc.body, shapeCaps(tc.want, ""))
		})
	}
}

// TestEffortShapes_OpenRouterAdvertisedFixture pins the values OpenRouter advertised for
// deepseek/deepseek-v4-flash-0731 on 2026-08-17, so the known list is checked without a
// live provider response.
func TestEffortShapes_OpenRouterAdvertisedFixture(t *testing.T) {
	body := `{"id":"deepseek/deepseek-v4-flash-0731","reasoning":{"supported_efforts":["max","high","low"],"default_effort":"high"}}`
	assertShapeCaps(t, body, shapeCaps([]any{"max", "high", "low"}, "high"))
}

func TestEffortShapes_DefaultEffortIsOptional(t *testing.T) {
	blob := strings.Repeat("a", maxEffortOptionLength+1)
	tests := []struct {
		name, defaultField string
		want               string
	}{
		{"absent", ``, ""},
		{"blank", `,"default_effort":"   "`, ""},
		{"non-string", `,"default_effort":5`, ""},
		{"oversized", `,"default_effort":"` + blob + `"`, ""},
		{"padded", `,"default_effort":" high "`, "high"},
		{"unknown token", `,"default_effort":"max"`, "max"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"reasoning":{"supported_efforts":["low"]` + tc.defaultField + `}}`
			assertShapeCaps(t, body, shapeCaps([]any{"low"}, tc.want))
		})
	}
}
