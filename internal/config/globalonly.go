package config

import (
	"fmt"
	"sort"
)

// globalOnlyDetail is the remediation suffix appended to every global-only
// violation, so the rendered stderr message names the file, the offending key
// and where to move it.
const globalOnlyDetail = "global-only key must be moved to ~/.codemeld/global/settings.yaml"

// EnforceGlobalOnly reports the first global-only key found in a
// decoded per-project settings map. The returned error's text matches the settings
// loader's schema-validation shape ("<file>: schema validation failed at <key>: <detail>")
// so callers render it with FormatLoadError under SchemaValidationError.
// It returns nil when the map carries no global-only key. Run it only on
// per-project maps after LoadYAML succeeds; the global file legitimately holds
// these keys.
func EnforceGlobalOnly(perProjectPath string, perProject map[string]any) error {
	key, ok := firstGlobalOnlyViolation(perProject)
	if !ok {
		return nil
	}
	return fmt.Errorf("%s: schema validation failed at %s: %s", perProjectPath, key, globalOnlyDetail)
}

// firstGlobalOnlyViolation returns the dotted key of the first global-only entry
// present, checked in list order so a file with several violations yields a
// stable, deterministic error.
func firstGlobalOnlyViolation(m map[string]any) (string, bool) {
	if nestedKeyPresent(m, "discovery", "boundary") {
		return "discovery.boundary", true
	}
	if nestedKeyPresent(m, "sessions", "retention_days") {
		return "sessions.retention_days", true
	}
	if nestedKeyPresent(m, "sessions", "max_tool_output_bytes") {
		return "sessions.max_tool_output_bytes", true
	}
	if v, ok := m["provider"]; ok {
		return providerViolationKey(v), true
	}
	if v, ok := m["auth"]; ok {
		return topLevelViolationKey("auth", v), true
	}
	if nestedKeyPresent(m, "model", "favorites") {
		return "model.favorites", true
	}
	if v, ok := m["web_research"]; ok {
		return topLevelViolationKey("web_research", v), true
	}
	if _, ok := m["attribution"]; ok {
		return "attribution", true
	}
	if v, ok := m["confinement"]; ok {
		return topLevelViolationKey("confinement", v), true
	}
	return "", false
}

// nestedKeyPresent reports whether m[top] is a map that contains child.
func nestedKeyPresent(m map[string]any, top, child string) bool {
	sub, ok := m[top].(map[string]any)
	if !ok {
		return false
	}
	_, present := sub[child]
	return present
}

// providerViolationKey reports the most specific dotted key for a present
// top-level provider value: "provider" for an empty or non-map value,
// "provider.<name>" when the named entry has no fields, and
// "provider.<name>.<field>" otherwise. Provider and field names are chosen by
// sort order so the result is deterministic when several exist.
func providerViolationKey(v any) string {
	providers, ok := v.(map[string]any)
	if !ok || len(providers) == 0 {
		return "provider"
	}
	name := firstSortedKey(providers)
	fields, ok := providers[name].(map[string]any)
	if !ok || len(fields) == 0 {
		return "provider." + name
	}
	return "provider." + name + "." + firstSortedKey(fields)
}

// Do not include values in global-only errors; they may contain credentials.
func topLevelViolationKey(top string, v any) string {
	fields, ok := v.(map[string]any)
	if !ok || len(fields) == 0 {
		return top
	}
	return top + "." + firstSortedKey(fields)
}

// firstSortedKey returns the lexicographically smallest key of a non-empty map.
func firstSortedKey(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0]
}
