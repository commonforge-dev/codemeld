// Launch-time config→model.Context bridge: assembles the provider
// diagnostics and active model selection for both bootstrap launch paths.
package bootstrap

import (
	"fmt"
	"io"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessions"
)

// determineLaunchModel is the production config→model bridge behind the bootstrap
// DetermineModel step. It builds a config.Cache from the composed config
// assembles the ordered provider diagnostics, and calls
// model.DetermineSelection, translating its outcome into the bootstrap step's
// contract: a non-nil selection becomes a run-scoped active state carrying its
// source; the path-4 picker-required outcome (a nil selection with no error) becomes
// an empty active state plus pickerRequired=true so the caller opens the provider-
// aware picker once the picker deps are installed; and a *model.NoSelectableModelError is
// propagated unchanged so the CLI caller owns rendering its stderr lines and exiting.
// On a resume launch it passes the loaded record stream so step 1 recovers
// before the fresh paths 2-4.
func determineLaunchModel(composed, global map[string]any, projectRoot string, layerPaths []string, resume bool, store *sessions.Store, warn io.Writer) (active *model.ActiveState, pickerRequired bool, err error) {
	if composed == nil {
		composed = map[string]any{}
	}
	cache, err := config.NewCache(composed, projectRoot, layerPaths)
	if err != nil {
		return nil, false, fmt.Errorf("bootstrap: model determination config cache: %w", err)
	}
	mctx := model.Context{
		Config:             cache,
		GlobalSettingsPath: globalSettingsPath(layerPaths),
		Providers:          providerDiagnostics(cache, global, layerPaths),
		Warn:               warn,
	}
	if resume {
		mctx.Resume = true
		mctx.Store = store
		if store != nil {
			mctx.ResumeRecords = store.Records()
		}
	}
	sel, source, err := model.DetermineSelection(mctx)
	if err != nil {
		return nil, false, err
	}
	if sel == nil {
		// path 4 with a selectable model: the run starts with no active
		// selection and an explicit picker-required flag, distinct from a plain "no
		// active selection" state, so StartTUI opens the picker rather than leaving the
		// run model-less.
		return model.NewActiveState(nil, ""), true, nil
	}
	return model.NewActiveState(sel, source), false, nil
}

// launchModelStep adapts determineLaunchModel to the bootstrap DetermineModel step
// contract, returning the active state as the `any` BootstrapResult.Model holds. On
// error it returns an explicit nil so a failed determination never surfaces a
// non-nil interface wrapping a nil *model.ActiveState.
func launchModelStep(composed, global map[string]any, projectRoot string, layerPaths []string, resume bool, store *sessions.Store, warn io.Writer) (any, bool, error) {
	active, pickerRequired, err := determineLaunchModel(composed, global, projectRoot, layerPaths, resume, store, warn)
	if err != nil {
		return nil, false, err
	}
	return active, pickerRequired, nil
}

// globalSettingsPath returns the global settings.yaml path the path-4
// "no providers configured" line names. RunFresh / runResumeSubsequence build
// ConfigLayerPaths global-first (SettingsPath(home) is layerPaths[0]), so the first
// entry is the global file; an empty layer list yields "".
func globalSettingsPath(layerPaths []string) string {
	if len(layerPaths) == 0 {
		return ""
	}
	return layerPaths[0]
}

// providerDiagnostics builds the ordered, source-attributed path-4 provider
// data DetermineSelection needs, from the selectable-provider catalog rather than
// only the composed provider: map: one
// ProviderDiagnostic per catalog entry, in catalog order (configured providers in
// sorted provider-id order, then the built-in selectable providers), with each
// provider's model allowlist preserved in declaration/built-in order. A built-in
// selectable provider (the OpenAI ChatGPT provider) always lists models, so the
// no-selectable launch exit no longer fires on first run; missing-credential
// guidance is turn-scoped. ModelsSourcePath is retained for source
// attribution but unused by the diagnostic.
func providerDiagnostics(cache *config.Cache, global map[string]any, layerPaths []string) []model.ProviderDiagnostic {
	entries := cache.SelectableCatalog().Entries()
	if len(entries) == 0 {
		return nil
	}

	globalProviders := layerProviderNames(global)
	globalPath, projectPath := diagnosticSourcePaths(layerPaths)

	diags := make([]model.ProviderDiagnostic, 0, len(entries))
	for _, e := range entries {
		source := ""
		if !e.Builtin {
			source = projectPath
			if globalProviders[e.ID] {
				source = globalPath
			}
		}
		diags = append(diags, model.ProviderDiagnostic{
			Name:             e.ID,
			Models:           e.Models,
			ModelsSourcePath: source,
		})
	}
	return diags
}

// diagnosticSourcePaths splits the ordered config layer paths into the global path
// (the global-first first entry) and the nearest project layer path (the last entry
// when a project layer contributed, otherwise the global path).
func diagnosticSourcePaths(layerPaths []string) (globalPath, projectPath string) {
	globalPath = globalSettingsPath(layerPaths)
	projectPath = globalPath
	if len(layerPaths) > 1 {
		projectPath = layerPaths[len(layerPaths)-1]
	}
	return globalPath, projectPath
}

// layerProviderNames returns the set of provider names declared in one settings
// layer's provider block, used to attribute each diagnostic's source path. A layer
// with no provider block contributes no names.
func layerProviderNames(layer map[string]any) map[string]bool {
	out := map[string]bool{}
	prov, ok := layer["provider"].(map[string]any)
	if !ok {
		return out
	}
	for name := range prov {
		out[name] = true
	}
	return out
}
