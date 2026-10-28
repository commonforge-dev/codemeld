// Table tests for global-only key enforcement (carve-outs).
package config

import (
	"strings"
	"testing"
)

func TestEnforceGlobalOnly_Rejects(t *testing.T) {
	const path = "/home/u/proj/.codemeld/settings.yaml"
	tests := []struct {
		name    string
		m       map[string]any
		wantKey string
	}{
		{
			"discovery.boundary",
			map[string]any{"discovery": map[string]any{"boundary": "project"}},
			"discovery.boundary",
		},
		{
			"sessions.retention_days",
			map[string]any{"sessions": map[string]any{"retention_days": 30}},
			"sessions.retention_days",
		},
		{
			"sessions.max_tool_output_bytes",
			map[string]any{"sessions": map[string]any{"max_tool_output_bytes": 1024}},
			"sessions.max_tool_output_bytes",
		},
		{
			"empty provider map",
			map[string]any{"provider": map[string]any{}},
			"provider",
		},
		{
			"provider name with no fields",
			map[string]any{"provider": map[string]any{"foo": map[string]any{}}},
			"provider.foo",
		},
		{
			"provider nested key",
			map[string]any{"provider": map[string]any{"foo": map[string]any{"api_key": "secret"}}},
			"provider.foo.api_key",
		},
		{
			"empty auth map",
			map[string]any{"auth": map[string]any{}},
			"auth",
		},
		{
			"auth scalar value",
			map[string]any{"auth": "anything"},
			"auth",
		},
		{
			"auth.openai-chatgpt nested",
			map[string]any{"auth": map[string]any{"openai-chatgpt": map[string]any{"access_token": "secret"}}},
			"auth.openai-chatgpt",
		},
		{
			"model.favorites list",
			map[string]any{"model": map[string]any{"favorites": []any{map[string]any{"provider": "openai", "id": "gpt-5.5"}}}},
			"model.favorites",
		},
		{
			"empty model.favorites list",
			map[string]any{"model": map[string]any{"favorites": []any{}}},
			"model.favorites",
		},
		{
			"model.favorites alongside permitted model.active",
			map[string]any{"model": map[string]any{"active": "gpt-5.5", "favorites": []any{}}},
			"model.favorites",
		},
		{
			"empty web_research map",
			map[string]any{"web_research": map[string]any{}},
			"web_research",
		},
		{
			"web_research scalar value",
			map[string]any{"web_research": true},
			"web_research",
		},
		{
			"web_research nil value",
			map[string]any{"web_research": nil},
			"web_research",
		},
		{
			"web_research.enabled only",
			map[string]any{"web_research": map[string]any{"enabled": true}},
			"web_research.enabled",
		},
		{
			"populated web_research",
			map[string]any{"web_research": map[string]any{
				"enabled":         true,
				"api_key":         "exa-secret-sentinel",
				"max_results":     10,
				"timeout_seconds": 30,
			}},
			"web_research.api_key",
		},
		{
			"attribution opt-out",
			map[string]any{"attribution": false},
			"attribution",
		},
		{
			"attribution opt-in",
			map[string]any{"attribution": true},
			"attribution",
		},
		{
			"confinement.program_lookup",
			map[string]any{"confinement": map[string]any{"program_lookup": "strict"}},
			"confinement.program_lookup",
		},
		{
			"confinement.shared_temp_folders",
			map[string]any{"confinement": map[string]any{"shared_temp_folders": "allow"}},
			"confinement.shared_temp_folders",
		},
		{
			"both confinement keys",
			map[string]any{"confinement": map[string]any{"program_lookup": "friendly", "shared_temp_folders": "deny"}},
			"confinement.program_lookup",
		},
		{
			"empty confinement map",
			map[string]any{"confinement": map[string]any{}},
			"confinement",
		},
		{
			"system_one off",
			map[string]any{"system_one": "off"},
			"system_one",
		},
		{
			"system_one model",
			map[string]any{"system_one": "venice:jev-latest"},
			"system_one",
		},
		{
			"attribution outranks confinement",
			map[string]any{"attribution": true, "confinement": map[string]any{"program_lookup": "strict"}},
			"attribution",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EnforceGlobalOnly(path, tt.m)
			if err == nil {
				t.Fatalf("EnforceGlobalOnly() = nil, want error")
			}

			// Raw error matches the settings loader's schema-validation shape.
			wantPrefix := path + ": schema validation failed at " + tt.wantKey + ": "
			if !strings.HasPrefix(err.Error(), wantPrefix) {
				t.Fatalf("error %q does not start with %q", err.Error(), wantPrefix)
			}
			if !strings.Contains(err.Error(), "moved to ~/.codemeld/global/settings.yaml") {
				t.Fatalf("error %q missing move-to-global instruction", err.Error())
			}

			msg := FormatLoadError(path, SchemaValidationError, err, LaunchAborted)
			for _, part := range []string{"codemeld: ", path, tt.wantKey, "moved to ~/.codemeld/global/settings.yaml"} {
				if !strings.Contains(msg, part) {
					t.Fatalf("rendered message %q missing %q", msg, part)
				}
			}
		})
	}
}

func TestEnforceGlobalOnly_Accepts(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
	}{
		{"empty map", map[string]any{}},
		{
			"per-project-permitted keys",
			map[string]any{
				"agent":       map[string]any{"max_concurrency": 4},
				"permissions": []any{map[string]any{"kind": "direct", "subject": "ls"}},
				"model":       map[string]any{"active": "gpt-5.5"},
			},
		},
		{
			"discovery present without boundary",
			map[string]any{"discovery": map[string]any{"ignore": []any{"node_modules"}}},
		},
		{
			"sessions present without global-only keys",
			map[string]any{"sessions": map[string]any{"something_else": true}},
		},
		{
			"model.active and model.last_used without favorites",
			map[string]any{"model": map[string]any{
				"active":    "gpt-5.5",
				"last_used": map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": "high"},
			}},
		},
		{
			"model as a non-map value",
			map[string]any{"model": "gpt-5.5"},
		},
		{
			"project host grant without web_research",
			map[string]any{"permissions": []any{map[string]any{
				"kind": "tool", "subject": "web_search", "host_scope": "example.test", "grant_kind": "project",
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EnforceGlobalOnly("settings.yaml", tt.m); err != nil {
				t.Fatalf("EnforceGlobalOnly() = %v, want nil", err)
			}
		})
	}
}

// With several violations present, the list order is honored so the reported
// key is stable: discovery.boundary outranks the sessions and provider carve-outs.
func TestEnforceGlobalOnly_DeterministicOrder(t *testing.T) {
	m := map[string]any{
		"discovery": map[string]any{"boundary": "project"},
		"sessions":  map[string]any{"retention_days": 30, "max_tool_output_bytes": 1024},
		"provider":  map[string]any{"openai": map[string]any{"api_key": "x"}},
	}
	err := EnforceGlobalOnly("settings.yaml", m)
	if err == nil {
		t.Fatalf("EnforceGlobalOnly() = nil, want error")
	}
	if !strings.Contains(err.Error(), "schema validation failed at discovery.boundary:") {
		t.Fatalf("error %q did not report discovery.boundary first", err.Error())
	}
}

func TestEnforceGlobalOnly_WebResearchKeyValueNotDisclosed(t *testing.T) {
	const secret = "exa-secret-sentinel"
	const path = "/home/u/proj/.codemeld/settings.yaml"
	m := map[string]any{"web_research": map[string]any{"enabled": true, "api_key": secret}}

	err := EnforceGlobalOnly(path, m)
	if err == nil {
		t.Fatalf("EnforceGlobalOnly() = nil, want error")
	}
	if !strings.Contains(err.Error(), "schema validation failed at web_research.api_key:") {
		t.Fatalf("error %q did not report web_research.api_key", err.Error())
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error %q discloses the configured api_key", err.Error())
	}
	if msg := FormatLoadError(path, SchemaValidationError, err, LaunchAborted); strings.Contains(msg, secret) {
		t.Fatalf("rendered message %q discloses the configured api_key", msg)
	}
}

// auth is the codemeld-owned global-only key, checked after the
// carve-outs. A file carrying both a global-only provider map and an auth map
// reports the provider violation first, so the offending-key message is stable.
func TestEnforceGlobalOnly_AuthOrderedAfterProvider(t *testing.T) {
	m := map[string]any{
		"provider": map[string]any{"openai": map[string]any{"api_key": "x"}},
		"auth":     map[string]any{"openai-chatgpt": map[string]any{"access_token": "x"}},
	}
	err := EnforceGlobalOnly("settings.yaml", m)
	if err == nil {
		t.Fatalf("EnforceGlobalOnly() = nil, want error")
	}
	if !strings.Contains(err.Error(), "schema validation failed at provider.openai.api_key:") {
		t.Fatalf("error %q did not report provider before auth", err.Error())
	}
}
