package provider

import (
	"fmt"
	"strings"
	"testing"
)

func TestSupportsTools_OpenRouterSupportedParametersList(t *testing.T) {
	tests := []struct {
		name string
		caps map[string]any
		want bool
	}{
		{"list with tools", map[string]any{configuredSupportedParametersCapKey: []any{"max_tokens", "tools", "top_p"}}, true},
		{"list without tools", map[string]any{configuredSupportedParametersCapKey: []any{"max_tokens", "top_p", "tool_choice"}}, false},
		{"every name underscore-bearing", map[string]any{configuredSupportedParametersCapKey: []any{"max_tokens", "top_p", "include_reasoning"}}, false},
		{"string slice with tools", map[string]any{configuredSupportedParametersCapKey: []string{"tools", "seed"}}, true},
		{"string slice without tools", map[string]any{configuredSupportedParametersCapKey: []string{"seed"}}, false},
		{"in-memory empty list", map[string]any{configuredSupportedParametersCapKey: []any{}}, false},
		{"one non-string element", map[string]any{configuredSupportedParametersCapKey: []any{"max_tokens", 7}}, true},
		{"scalar instead of list", map[string]any{configuredSupportedParametersCapKey: "tools"}, true},
		{"map instead of list", map[string]any{configuredSupportedParametersCapKey: map[string]any{"tools": true}}, true},
		{"nil value", map[string]any{configuredSupportedParametersCapKey: nil}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupportsTools(openRouterProviderID, tc.caps); got != tc.want {
				t.Errorf("SupportsTools(openrouter, %v) = %v, want %v", tc.caps, got, tc.want)
			}
		})
	}
}

func TestSupportsTools_OpenRouterEmptyMarker(t *testing.T) {
	tests := []struct {
		name string
		caps map[string]any
		want bool
	}{
		{"marker set", map[string]any{configuredSupportedParametersEmptyCapKey: true}, false},
		{"marker false", map[string]any{configuredSupportedParametersEmptyCapKey: false}, true},
		{"marker wrong-typed", map[string]any{configuredSupportedParametersEmptyCapKey: "yes"}, true},
		{"list wins over a stale marker", map[string]any{
			configuredSupportedParametersEmptyCapKey: true,
			configuredSupportedParametersCapKey:      []any{"tools"},
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupportsTools(openRouterProviderID, tc.caps); got != tc.want {
				t.Errorf("SupportsTools(openrouter, %v) = %v, want %v", tc.caps, got, tc.want)
			}
		})
	}
}

func TestSupportsTools_VeniceFunctionCallingFlag(t *testing.T) {
	tests := []struct {
		name string
		caps map[string]any
		want bool
	}{
		{"explicit false", map[string]any{configuredSupportsFunctionCallingCapKey: false}, false},
		{"explicit true", map[string]any{configuredSupportsFunctionCallingCapKey: true}, true},
		{"absent", map[string]any{configuredSupportsMultipleImagesCapKey: true}, true},
		{"wrong-typed", map[string]any{configuredSupportsFunctionCallingCapKey: "false"}, true},
		{"nil value", map[string]any{configuredSupportsFunctionCallingCapKey: nil}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupportsTools(veniceProviderID, tc.caps); got != tc.want {
				t.Errorf("SupportsTools(venice, %v) = %v, want %v", tc.caps, got, tc.want)
			}
		})
	}
}

func TestSupportsTools_UnreadProvidersAndAbsentMetadataStaySupported(t *testing.T) {
	negative := map[string]any{
		configuredSupportedParametersCapKey:      []any{"max_tokens"},
		configuredSupportedParametersEmptyCapKey: true,
		configuredSupportsFunctionCallingCapKey:  false,
	}
	for _, providerID := range []string{"openai", "groq", ChatGPTProviderID, ""} {
		if !SupportsTools(providerID, negative) {
			t.Errorf("SupportsTools(%q, %v) = false, want true (no reader for this provider)", providerID, negative)
		}
	}
	for _, providerID := range []string{openRouterProviderID, veniceProviderID, "openai"} {
		if !SupportsTools(providerID, nil) {
			t.Errorf("SupportsTools(%q, nil) = false, want true", providerID)
		}
		if !SupportsTools(providerID, map[string]any{}) {
			t.Errorf("SupportsTools(%q, empty) = false, want true", providerID)
		}
	}
}

func TestSupportsTools_LegacyCapabilityRecordStaysSupported(t *testing.T) {
	legacy := map[string]any{
		configuredSupportsReasoningEffortCapKey: true,
		configuredReasoningEffortOptionsCapKey:  []any{"low", "high"},
		configuredDefaultReasoningEffortCapKey:  "low",
		configuredSupportsMultipleImagesCapKey:  true,
		configuredMaxImagesCapKey:               3,
	}
	for _, providerID := range []string{openRouterProviderID, veniceProviderID} {
		if !SupportsTools(providerID, legacy) {
			t.Errorf("SupportsTools(%q, legacy record) = false, want true", providerID)
		}
	}
}

func TestSupportsTools_OpenRouterMalformedPersistedListStaysSupported(t *testing.T) {
	overCapAny := make([]any, 0, maxSupportedParameterCount+1)
	overCapStrings := make([]string, 0, maxSupportedParameterCount+1)
	for i := range maxSupportedParameterCount + 1 {
		name := fmt.Sprintf("param_%d", i)
		if i == 0 {
			name = toolsSupportedParameter
		}
		overCapAny = append(overCapAny, name)
		overCapStrings = append(overCapStrings, name)
	}
	overCapWithoutTools := make([]any, 0, maxSupportedParameterCount+1)
	for i := range maxSupportedParameterCount + 1 {
		overCapWithoutTools = append(overCapWithoutTools, fmt.Sprintf("param_%d", i))
	}

	tests := []struct {
		name string
		caps map[string]any
		want bool
	}{
		{"invalid tokens only", map[string]any{configuredSupportedParametersCapKey: []any{"bad name", "top p"}}, true},
		{"invalid tokens only as strings", map[string]any{configuredSupportedParametersCapKey: []string{"bad name"}}, true},
		{"empty strings only", map[string]any{configuredSupportedParametersCapKey: []any{"", "   "}}, true},
		{"over-length token only", map[string]any{configuredSupportedParametersCapKey: []any{strings.Repeat("a", maxSupportedParameterLength+1)}}, true},
		{"padded tools", map[string]any{configuredSupportedParametersCapKey: []any{" tools "}}, true},
		{"padded tools as strings", map[string]any{configuredSupportedParametersCapKey: []string{"\ttools\n"}}, true},
		{"padded name without tools", map[string]any{configuredSupportedParametersCapKey: []any{" max_tokens ", "bad name"}}, false},
		{"over-cap list holding tools", map[string]any{configuredSupportedParametersCapKey: overCapAny}, true},
		{"over-cap list without tools", map[string]any{configuredSupportedParametersCapKey: overCapWithoutTools}, true},
		{"over-cap string slice", map[string]any{configuredSupportedParametersCapKey: overCapStrings}, true},
		{"duplicate names without tools", map[string]any{configuredSupportedParametersCapKey: []any{"max_tokens", "max_tokens"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupportsTools(openRouterProviderID, tc.caps); got != tc.want {
				t.Errorf("SupportsTools(openrouter, %v) = %v, want %v", tc.caps, got, tc.want)
			}
		})
	}
}
