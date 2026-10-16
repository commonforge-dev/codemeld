// Tests for the launch-time config→model bridge (modeldetermine.go): fresh and
// resume determination outcomes, the path-4 picker-required flag and
// no-selectable error, and the ordered, source-attributed provider diagnostics.
package bootstrap

import (
	"io"
	"path/filepath"
	"reflect"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/model"
)

func discoveredOpenAIFixture(t *testing.T, modelBlock map[string]any) (map[string]any, string, []string) {
	t.Helper()
	projectRoot := t.TempDir()
	layerPaths := []string{
		filepath.Join(t.TempDir(), "settings.yaml"),
		filepath.Join(projectRoot, ".codemeld", "settings.yaml"),
	}
	capabilities := map[string]any{
		"supportsReasoningEffort": true,
		"reasoningEffortOptions":  []any{"low", "medium", "high"},
	}
	if err := config.UpdateDiscoveredModelsProvider(config.DiscoveredModelsPath(layerPaths[0]), "openai", config.DiscoveredProvider{
		Models: []config.DiscoveredModel{
			{ID: "gpt-5.5", Capabilities: capabilities},
			{ID: "gpt-5.5-pro", Capabilities: capabilities},
		},
	}); err != nil {
		t.Fatalf("seed discovered OpenAI models: %v", err)
	}
	composed := map[string]any{
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
			},
		},
	}
	if modelBlock != nil {
		composed["model"] = modelBlock
	}
	return composed, projectRoot, layerPaths
}

// TestDetermineLaunchModel_FreshProjectSelection pins the path-2 outcome: a valid
// per-project model.active is adopted as the run's active selection with source
// project and no picker required.
func TestDetermineLaunchModel_FreshProjectSelection(t *testing.T) {
	composed, projectRoot, layerPaths := discoveredOpenAIFixture(t, map[string]any{
		"active": map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": "medium"},
	})
	active, pickerRequired, err := determineLaunchModel(composed, nil, projectRoot, layerPaths, false, nil, io.Discard)
	if err != nil {
		t.Fatalf("determineLaunchModel error: %v", err)
	}
	if pickerRequired {
		t.Error("pickerRequired = true, want false when a project model.active resolves")
	}
	sel, src, ok := active.Current()
	if !ok || sel.Provider != "openai" || sel.ID != "gpt-5.5" || sel.Effort != "medium" || src != model.SourceProject {
		t.Fatalf("active = (%+v, %q, ok=%v), want openai/gpt-5.5/medium source project", sel, src, ok)
	}
}

// TestDetermineLaunchModel_PickerRequiredWhenSelectableButUnset pins the
// path-4 selectable outcome: no model.active / model.last_used but a selectable model
// exists yields an empty active state plus pickerRequired=true.
func TestDetermineLaunchModel_PickerRequiredWhenSelectableButUnset(t *testing.T) {
	composed, projectRoot, layerPaths := discoveredOpenAIFixture(t, nil)
	active, pickerRequired, err := determineLaunchModel(composed, nil, projectRoot, layerPaths, false, nil, io.Discard)
	if err != nil {
		t.Fatalf("determineLaunchModel error: %v", err)
	}
	if !pickerRequired {
		t.Fatal("pickerRequired = false, want true on the req-540 path-4 selectable outcome")
	}
	if _, _, ok := active.Current(); ok {
		t.Error("active state carries a selection, want an empty state for the picker-required outcome")
	}
}

// TestDetermineLaunchModel_BuiltinChatGPTKeepsPickerSelectable pins the
// built-in-provider rule at the bridge: with no configured providers, the built-in OpenAI
// ChatGPT provider is always selectable, so an empty config now yields the picker-
// required outcome (an empty active state, pickerRequired=true) instead of the
// path-4 no-selectable exit. The no-selectable error path remains for stub callers
// (cli/root_test, resume_test) but no longer fires through the real catalog.
func TestDetermineLaunchModel_BuiltinChatGPTKeepsPickerSelectable(t *testing.T) {
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	active, pickerRequired, err := determineLaunchModel(map[string]any{}, nil, t.TempDir(), []string{globalPath}, false, nil, io.Discard)
	if err != nil {
		t.Fatalf("determineLaunchModel error: %v (the built-in ChatGPT provider should keep a model selectable)", err)
	}
	if !pickerRequired {
		t.Fatal("pickerRequired = false, want true — the built-in ChatGPT provider is selectable with no configured providers")
	}
	if _, _, ok := active.Current(); ok {
		t.Error("active state carries a selection, want an empty state for the picker-required outcome")
	}
}

// TestProviderDiagnostics_CatalogOrderSourcePathsAndBuiltin pins the catalog-backed
// diagnostics: configured providers come first in sorted id order
// each attributed to its source settings file (a global-layer provider to the global
// path, a project-only provider to the project path), and the built-in OpenAI
// ChatGPT provider is appended with its built-in models and an empty source path
// (it is read from no settings file).
func TestProviderDiagnostics_CatalogOrderSourcePathsAndBuiltin(t *testing.T) {
	projectRoot := t.TempDir()
	globalPath := filepath.Join(t.TempDir(), "settings.yaml")
	projectPath := filepath.Join(projectRoot, ".codemeld", "settings.yaml")
	composed := map[string]any{
		"provider": map[string]any{
			"aaa_global":  map[string]any{"base_url": "https://a.test/v1", "api_key": "k"},
			"zzz_project": map[string]any{"base_url": "https://z.test/v1", "api_key": "k"},
		},
	}
	global := map[string]any{
		"provider": map[string]any{
			"aaa_global": map[string]any{"base_url": "https://a.test/v1", "api_key": "k"},
		},
	}
	modelsPath := config.DiscoveredModelsPath(globalPath)
	if err := config.UpdateDiscoveredModelsProvider(modelsPath, "aaa_global", config.DiscoveredProvider{
		Models: []config.DiscoveredModel{{ID: "a1"}},
	}); err != nil {
		t.Fatalf("seed discovered aaa_global models: %v", err)
	}
	if err := config.UpdateDiscoveredModelsProvider(modelsPath, "zzz_project", config.DiscoveredProvider{}); err != nil {
		t.Fatalf("seed discovered zzz_project models: %v", err)
	}
	cache, err := config.NewCache(composed, projectRoot, []string{globalPath, projectPath})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	diags := providerDiagnostics(cache, global, []string{globalPath, projectPath})

	want := []model.ProviderDiagnostic{
		{Name: "aaa_global", Models: []string{"a1"}, ModelsSourcePath: globalPath},
		{Name: "zzz_project", Models: []string{}, ModelsSourcePath: projectPath},
		{Name: "openai-chatgpt", Models: []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark"}, ModelsSourcePath: ""},
	}
	if !reflect.DeepEqual(diags, want) {
		t.Fatalf("providerDiagnostics =\n%#v\nwant\n%#v", diags, want)
	}
}

// TestDetermineLaunchModel_ResumeCleanRecovery pins the resume path: step 1
// recovers a valid model_turn from the loaded store and adopts it as source resume,
// taking precedence over the project model.active.
func TestDetermineLaunchModel_ResumeCleanRecovery(t *testing.T) {
	composed, projectRoot, layerPaths := discoveredOpenAIFixture(t, map[string]any{
		"active": map[string]any{"provider": "openai", "id": "gpt-5.5-pro", "effort": "low"},
	})
	target := mkStore(t)
	seedModelTurn(t, target, "openai", "gpt-5.5", "high")

	active, pickerRequired, err := determineLaunchModel(composed, nil, projectRoot, layerPaths, true, target, io.Discard)
	if err != nil {
		t.Fatalf("determineLaunchModel error: %v", err)
	}
	if pickerRequired {
		t.Error("pickerRequired = true, want false on a clean resume recovery")
	}
	sel, src, ok := active.Current()
	if !ok || sel.ID != "gpt-5.5" || src != model.SourceResume {
		t.Fatalf("active = (%+v, %q), want resume recovery of gpt-5.5 (source resume), overriding the project active gpt-5.5-pro", sel, src)
	}
}
