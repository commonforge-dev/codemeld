// Per-model tool-call support, read from whatever capability metadata a provider
// publishes about its own models.
package provider

import (
	"slices"
	"strings"
)

const veniceProviderID = "venice"

const toolsSupportedParameter = "tools"

// A further provider is one more case; the default must stay true so a provider that
// publishes nothing about tool calling keeps its tools.
func SupportsTools(providerID string, caps map[string]any) bool {
	switch providerID {
	case openRouterProviderID:
		return openRouterSupportsTools(caps)
	case veniceProviderID:
		return veniceSupportsTools(caps)
	default:
		return true
	}
}

func openRouterSupportsTools(caps map[string]any) bool {
	if raw, present := caps[configuredSupportedParametersCapKey]; present {
		names, sourceCount, ok := supportedParameterNames(raw)
		if !ok {
			return true
		}
		// A non-empty list nothing survived is malformed metadata, not a provider
		// statement that tools are missing.
		if sourceCount > 0 && len(names) == 0 {
			return true
		}
		return slices.Contains(names, toolsSupportedParameter)
	}
	explicitlyEmpty, ok := caps[configuredSupportedParametersEmptyCapKey].(bool)
	return !ok || !explicitlyEmpty
}

// A models.yaml round-trip yields []any while an in-memory producer holds []string. One
// non-string element, or a length past the discovery cap, makes the whole list malformed
// rather than a short list, so it cannot become negative evidence. The returned count is
// the persisted list's own length, which is what separates an explicit empty list from a
// non-empty list whose every element was invalid.
func supportedParameterNames(v any) ([]string, int, bool) {
	switch list := v.(type) {
	case []any:
		if len(list) > maxSupportedParameterCount {
			return nil, 0, false
		}
		strs := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, 0, false
			}
			strs = append(strs, s)
		}
		return sanitizeParameterNames(strs)
	case []string:
		return sanitizeParameterNames(list)
	default:
		return nil, 0, false
	}
}

func sanitizeParameterNames(list []string) ([]string, int, bool) {
	if len(list) > maxSupportedParameterCount {
		return nil, 0, false
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if !validSupportedParameterToken(s) || slices.Contains(out, s) {
			continue
		}
		out = append(out, s)
	}
	return out, len(list), true
}

func veniceSupportsTools(caps map[string]any) bool {
	supported, ok := caps[configuredSupportsFunctionCallingCapKey].(bool)
	return !ok || supported
}
