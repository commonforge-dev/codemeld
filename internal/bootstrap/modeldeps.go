// Production implementations of tui.ModelCatalog/tui.ModelApplier (the
// model-only /model path) and the provider-aware tui.ProviderModelCatalog/
// tui.ProviderModelApplier (the CTRL-M model picker, which spans the provider×model
// cross-product and may switch providers). All share the picker-apply
// transaction with effortdeps.go and live in internal/bootstrap for the same
// import-direction reason: internal/tui cannot import internal/model or
// internal/provider.
package bootstrap

import (
	"fmt"
	"slices"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/tui"
)

// modelCatalog is the production tui.ModelCatalog. It embeds effortModel so the
// active-selection read and supported-effort set come from the shared run-scoped
// active state + provider catalog, and adds the active provider's
// model allowlist from the selectable-provider catalog.
type modelCatalog struct {
	effortModel
	cache *config.Cache
}

// Models returns the active provider's model id allowlist from the selectable
// catalog, in declaration order — the set the supplied id must belong to and
// the one named in the unsupported-model error. Reading the catalog (not the
// configured provider: map) is what lets /model validate ids for a built-in
// selectable provider such as openai-chatgpt, whose models live outside settings.
// A provider absent from the catalog yields no models, so /model rejects
// every id for it.
func (c modelCatalog) Models(providerName string) []string {
	entry, ok := c.cache.SelectableCatalog().Entry(providerName)
	if !ok {
		return nil
	}
	return entry.Models
}

// modelApplier is the production tui.ModelApplier. Apply changes the model id (and
// the effort the handler recomputed) on the active provider and runs the shared
// transaction; it never changes the provider.
type modelApplier struct{ pickerApply }

// Apply persists Selection{active provider, modelID, effort} as model.active
// through the transaction and records the resulting picker/picker_degraded
// source. The handler only calls it after ActiveSelection reported a selection, so
// a missing one here is a wiring bug surfaced as an error rather than a silent
// no-op — mirroring effortApplier.Apply.
func (a modelApplier) Apply(modelID, effort string) (tui.ModelApplyResult, error) {
	sel, _, ok := a.active.Current()
	if !ok {
		return tui.ModelApplyResult{}, fmt.Errorf("bootstrap: /model apply with no active model selection")
	}
	newSel := model.Selection{Provider: sel.Provider, ID: modelID, Effort: effort}
	created, path, err := a.apply(newSel, sel)
	if err != nil {
		return tui.ModelApplyResult{}, err
	}
	return tui.ModelApplyResult{MarkerCreated: created, MarkerPath: path}, nil
}

// providerModelCatalog is the production tui.ProviderModelCatalog for the CTRL-M
// model picker. It is the provider-aware analogue of modelCatalog: it
// embeds effortModel for the active-selection and supported-effort reads,
// but spans the whole provider×model cross-product of the selectable-provider
// catalog rather than the active provider's allowlist, because
// the picker may switch providers. It is additive — modelCatalog and the ModelCatalog
// interface are untouched, so the /model wiring is unaffected.
type providerModelCatalog struct {
	effortModel
	cache     *config.Cache
	launchDir string
}

// ProviderModels returns the selectable (provider, model id) cross-product across
// every selectable provider, drawn from the selectable-provider catalog: configured
// providers in sorted id order followed by built-in selectable providers (the
// openai-chatgpt provider), with each provider's model order preserved and a
// provider whose models allowlist is empty contributing no rows. Each row carries
// the provider's display name alongside its stable id, so the picker can show
// "OpenAI ChatGPT" as a group header while persistence keeps the id openai-chatgpt.
// The same model id may appear under both openai and openai-chatgpt
// the rows stay distinct, disambiguated by provider id.
func (c providerModelCatalog) ProviderModels() []tui.ProviderModel {
	var rows []tui.ProviderModel
	for _, e := range c.cache.SelectableCatalog().Entries() {
		for _, id := range e.Models {
			rows = append(rows, tui.ProviderModel{Provider: e.ID, DisplayName: e.DisplayName, ModelID: id})
		}
	}
	return rows
}

// ConfiguredProviders returns one row per configured (non-builtin) provider from
// the selectable catalog, including those with an empty model allowlist. The
// picker uses this to request a non-forced refresh for a configured provider
// whose cache has no model rows when it opens — ProviderModels omits empty
// providers, so without this seam they would never be refreshed.
func (c providerModelCatalog) ConfiguredProviders() []tui.ProviderModel {
	var out []tui.ProviderModel
	for _, e := range c.cache.SelectableCatalog().Entries() {
		if e.Builtin {
			continue
		}
		out = append(out, tui.ProviderModel{Provider: e.ID, DisplayName: e.DisplayName})
	}
	return out
}

func (c providerModelCatalog) SettingsTarget() tui.ModelSettingsTarget {
	projectRoot := c.cache.ProjectRoot()
	settingsPath := config.LocalSettingsPath(projectRoot)
	return tui.ModelSettingsTarget{
		SettingsPath: settingsPath,
		LaunchDir:    c.launchDir,
		ProjectRoot:  projectRoot,
	}
}

// providerModelApplier is the production tui.ProviderModelApplier. Unlike
// modelApplier (model-only, /model) it switches the provider too, so it
// cannot reuse that applier; it runs the same shared transaction over the
// chosen provider+id+effort. It is additive — modelApplier and the model-only
// Apply are untouched.
type providerModelApplier struct{ pickerApply }

// ApplyProviderModel persists Selection{provider, modelID, effort} as model.active
// through the shared transaction (model_changed before WriteActive
// last_used mirror only after the active write succeeds, model_persist_failed /
// model_global_mirror_failed and the picker/picker_degraded source as prescribed).
// The picker opens even with no model selected, so when ActiveState.Current
// reports none it passes a nil prior — model_changed then omits the prior fields
// (first-pick path); otherwise the current selection is the prior.
func (a providerModelApplier) ApplyProviderModel(provider, modelID, effort string) (tui.ModelApplyResult, error) {
	newSel := model.Selection{Provider: provider, ID: modelID, Effort: effort}
	var prior *model.Selection
	if sel, _, ok := a.active.Current(); ok {
		prior = &sel
	}
	created, path, err := a.applySelection(newSel, prior)
	if err != nil {
		return tui.ModelApplyResult{}, err
	}
	return tui.ModelApplyResult{MarkerCreated: created, MarkerPath: path}, nil
}

type providerModelFavorites struct{ cache *config.Cache }

func (f providerModelFavorites) Favorites() []tui.ModelFavorite {
	favs := f.cache.Favorites()
	if len(favs) == 0 {
		return nil
	}
	out := make([]tui.ModelFavorite, len(favs))
	for i, fav := range favs {
		out[i] = tui.ModelFavorite{Provider: fav.Provider, ModelID: fav.ID}
	}
	return out
}

func (f providerModelFavorites) ToggleFavorite(provider, modelID string) ([]tui.ModelFavorite, error) {
	target := config.Favorite{Provider: provider, ID: modelID}
	want := !slices.Contains(f.cache.Favorites(), target)
	list, _, _, err := f.cache.ToggleFavorite(target, want)
	if err != nil {
		return nil, err
	}
	out := make([]tui.ModelFavorite, len(list))
	for i, fav := range list {
		out[i] = tui.ModelFavorite{Provider: fav.Provider, ModelID: fav.ID}
	}
	return out, nil
}

func newProviderRefreshCallback(cache *config.Cache, auth chatGPTAuth, settingsPath string) func(providerID string, force bool, onComplete func(tui.ModelRefreshResult)) {
	r := NewProviderCatalogRefresher(cache)
	r.chatgptAuth = auth
	r.settingsPath = settingsPath
	return func(providerID string, force bool, onComplete func(tui.ModelRefreshResult)) {
		r.Refresh(providerID, force, func(res RefreshResult) {
			if onComplete == nil {
				return
			}
			var outcome tui.ModelRefreshOutcome
			switch {
			case res.Outcome == RefreshUpdated:
				outcome = tui.ModelRefreshUpdated
			case res.Outcome == RefreshFailed:
				outcome = tui.ModelRefreshFailed
			case res.Outcome == RefreshCredentialUnavailable:
				outcome = tui.ModelRefreshCredentialUnavailable
			case force && res.ProviderID == provider.ChatGPTProviderID:
				outcome = tui.ModelRefreshFailed
			default:
				outcome = tui.ModelRefreshNoChange
			}
			onComplete(tui.ModelRefreshResult{Provider: res.ProviderID, Outcome: outcome})
		})
	}
}
