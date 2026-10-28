// Tests for the production tui.ModelCatalog/ModelApplier (modeldeps.go) driven
// through the shared BuildRegistry builder: the configured-allowlist gate, the /model effort
// fallback, the shared apply flow, the source transition, and the picker path's offline
// (no discovery-client construction, no network) guarantee.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/trust"
	"codemeld.dev/codemeld/internal/tui"
)

func TestEffortModel_CachelessExposesNoReasoningOnly(t *testing.T) {
	m := effortModel{active: selectedState()}
	for _, c := range []struct{ providerID, modelID string }{
		{"openai", "gpt-5.5"},
		{"openai", "gpt-5.5-pro"},
		{"openrouter", "openai/gpt-5.5"},
		{"openai-chatgpt", "gpt-5.5"},
		{"venice", "zai-org-glm-5"},
		{"nope", "nope"},
	} {
		if got := m.SupportedEfforts(c.providerID, c.modelID); !slices.Equal(got, []string{provider.EffortNoReasoning}) {
			t.Errorf("SupportedEfforts(%s, %s) = %v, want [no-reasoning]", c.providerID, c.modelID, got)
		}
	}
}

func TestModelApplier_CleanFlow_AllowlistEffortFallbackSourcePicker(t *testing.T) {
	ctx := context.Background()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-model", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: "low"}, model.SourceResume)

	modelDeps := newModelDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"model": tui.NewModelHandler(modelDeps)})
	host := &recordingHost{store: store}

	// gpt-5.5-pro is in the configured allowlist but supports {medium, high,
	// xhigh}; the current effort low is unsupported, so the /model effort fallback recomputes
	// it to medium.
	res := reg.DispatchSlashInput("/model gpt-5.5-pro", host)
	if res.Status != tui.StatusHandled || res.Canonical != "model" || res.Err != nil {
		t.Fatalf("dispatch result = %+v, want {handled, model, no error}", res)
	}

	changed := decodeModelChanged(t, store)
	if len(changed) != 1 || changed[0].NewModelID != "gpt-5.5-pro" || changed[0].NewEffort != "medium" {
		t.Fatalf("model_changed = %+v, want new model gpt-5.5-pro with fallback effort medium", changed)
	}
	if changed[0].NewProvider != "openai" {
		t.Fatalf("model_changed provider = %q, want openai (the provider never changes)", changed[0].NewProvider)
	}
	// The transaction flushes the session at the durability
	// point, so the session file on disk — not just the in-memory store — must
	// carry both the handler's slash_command and PersistPickerSelection's
	// model_changed before the settings write counts as a clean apply. Fails if the
	// registry dispatch adapter path appends those records but bypasses the session flush.
	assertFileContains(t, store.Path(), "slash_command")
	assertFileContains(t, store.Path(), "model_changed")
	assertFileContains(t, config.LocalSettingsPath(projectRoot), "gpt-5.5-pro")
	if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("shared settings.yaml must stay absent; stat err = %v", err)
	}
	sel, src, _ := active.Current()
	if sel.ID != "gpt-5.5-pro" || sel.Effort != "medium" || src != model.SourcePicker {
		t.Fatalf("Current() = (%+v, %q), want gpt-5.5-pro/medium + picker", sel, src)
	}
}

// TestSubmitBoundary_ModelRejectEventIsDurableOnDisk pins that a
// /model validation rejection appends slash_command{outcome:error} and must flush
// it so the recorded error is durable on disk, not left in memory
// until some unrelated later flush. Validation rejects before the apply
// transaction, so the reject path is the only flush boundary. It fails if
// rejectModel's FlushActive call is removed.
func TestSubmitBoundary_ModelRejectEventIsDurableOnDisk(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	app.SetCommandFlush(newCommandFlush(ctx, app))

	modelDeps := newModelDeps(ctx, app, providerCache(t, t.TempDir()), selectedState(), t.TempDir())
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"model": tui.NewModelHandler(modelDeps)})

	if tui.NewSubmitFunc(reg, app, nil)("/model not-a-model") {
		t.Fatal("/model not-a-model must be rejected (retain), not accepted")
	}
	assertFileContains(t, store.Path(), "slash_command")
	assertFileContains(t, store.Path(), "unsupported model not-a-model")
}

// TestSubmitBoundary_ModelCancelledFlushRejectsAndPersistsNothing pins the
// production ModelApplier, which shares PersistPickerSelection
// with /effort: a flush failure without a write reason (a cancelled run
// context) must stop the apply before any model.active / model.last_used write and
// before the picker source transition, rejecting the submit so the input is
// retained. The store path is writable, so cancellation is the only flush failure.
// It fails if persist.go proceeds past a ReasonNone flush failure.
func TestSubmitBoundary_ModelCancelledFlushRejectsAndPersistsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	app.SetCommandFlush(newCommandFlush(ctx, app))
	active := selectedState() // openai/gpt-5.5/medium, source resume

	modelDeps := newModelDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"model": tui.NewModelHandler(modelDeps)})

	if tui.NewSubmitFunc(reg, app, nil)("/model gpt-5.5-pro") {
		t.Fatal("/model gpt-5.5-pro on a cancelled run context must be rejected (retain), not accepted")
	}
	if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("model.active must be absent after a non-write flush failure; stat err = %v", err)
	}
	if _, err := os.Stat(config.LocalSettingsPath(projectRoot)); !os.IsNotExist(err) {
		t.Fatalf("local model.active must be absent after a non-write flush failure; stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("model.last_used must be absent after a non-write flush failure; stat err = %v", err)
	}
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatalf("session file must be absent after a cancelled flush; stat err = %v", err)
	}
	if _, src, _ := active.Current(); src != model.SourceResume {
		t.Fatalf("active source = %q, want resume (no picker transition on a non-write flush failure)", src)
	}
}

func TestModelHandler_UnsupportedId_RejectedNoApply(t *testing.T) {
	ctx := context.Background()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState()

	modelDeps := newModelDeps(ctx, app, providerCache(t, t.TempDir()), active, t.TempDir())
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"model": tui.NewModelHandler(modelDeps)})
	host := &recordingHost{store: store}

	res := reg.DispatchSlashInput("/model not-a-model", host)
	if res.Status != tui.StatusHandled || res.Canonical != "model" || res.Err != nil {
		t.Fatalf("dispatch result = %+v, want handled model no-error (a validation rejection is still a handled command)", res)
	}
	if !res.RetainInput {
		t.Fatal("an unsupported model id must retain the typed input")
	}
	cmds := slashCmds(t, store)
	if len(cmds) != 1 || cmds[0].Outcome != "error" {
		t.Fatalf("slash_command events = %+v, want one {model, error}", cmds)
	}
	if n := len(decodeModelChanged(t, store)); n != 0 {
		t.Fatalf("model_changed events = %d, want 0 (no apply on a rejected id)", n)
	}
	if sel, _, _ := active.Current(); sel.ID != "gpt-5.5" {
		t.Fatalf("active model id = %q, want unchanged gpt-5.5", sel.ID)
	}
}

// TestProviderModelCatalog_CrossProductFromSelectableCatalog pins the migration of
// the picker source to the selectable-provider catalog: the rows span every selectable
// provider in catalog order — configured providers sorted by id, then built-in
// selectable providers (openai-chatgpt) — each provider's model order preserved and an
// empty allowlist contributing no rows. Each row carries the provider's display name
// alongside its stable id (openai -> "OpenAI Platform", openai-chatgpt -> "OpenAI
// ChatGPT"), and the same model id (gpt-5.5) appears under both openai and
// openai-chatgpt as distinct rows disambiguated by provider id. The
// embedded effortModel still supplies the active selection and supported-effort set.
func TestProviderModelCatalog_CrossProductFromSelectableCatalog(t *testing.T) {
	globalSettings := SettingsPath(t.TempDir())
	seedOpenAIDiscovered(t, globalSettings, "gpt-5.5", "gpt-5.5-pro")
	if err := config.UpdateDiscoveredModelsProvider(
		config.DiscoveredModelsPath(globalSettings), "anthropic",
		config.DiscoveredProvider{Models: []config.DiscoveredModel{{ID: "claude-x"}}},
	); err != nil {
		t.Fatalf("seed discovered anthropic models: %v", err)
	}
	composed := map[string]any{
		"provider": map[string]any{
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-o",
			},
			"anthropic": map[string]any{
				"base_url": "https://api.anthropic.com/v1",
				"api_key":  "sk-a",
			},
			"empty": map[string]any{
				"base_url": "https://e/v1",
				"api_key":  "sk-e",
			},
		},
	}
	cache, err := config.NewCache(composed, t.TempDir(), []string{globalSettings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	cat := providerModelCatalog{effortModel: effortModel{active: selectedState()}, cache: cache, launchDir: "/launch"}

	want := []tui.ProviderModel{
		{Provider: "anthropic", DisplayName: "anthropic", ModelID: "claude-x"},
		{Provider: "openai", DisplayName: "OpenAI Platform", ModelID: "gpt-5.5"},
		{Provider: "openai", DisplayName: "OpenAI Platform", ModelID: "gpt-5.5-pro"},
		{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.5"},
		{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.4"},
		{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.4-mini"},
		{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.3-codex-spark"},
	}
	if got := cat.ProviderModels(); !slices.Equal(got, want) {
		t.Fatalf("ProviderModels() = %+v, want %+v (configured sorted then built-ins; display names; duplicate ids under both openai providers)", got, want)
	}
	for _, m := range []struct{ providerID, modelID string }{
		{"openai", "gpt-5.5-pro"},
		{"openai-chatgpt", "gpt-5.5"},
	} {
		if got := cat.SupportedEfforts(m.providerID, m.modelID); !slices.Equal(got, []string{provider.EffortNoReasoning}) {
			t.Fatalf("SupportedEfforts(%s, %s) = %v, want [no-reasoning]", m.providerID, m.modelID, got)
		}
	}
	if p, id, eff, ok := cat.ActiveSelection(); !ok || p != "openai" || id != "gpt-5.5" || eff != "medium" {
		t.Fatalf("ActiveSelection() = (%q,%q,%q,%v), want openai/gpt-5.5/medium/true", p, id, eff, ok)
	}
}

// TestModelCatalog_BuiltinChatGPTAllowlist pins the /model active-
// provider allowlist: modelCatalog.Models now reads the selectable-provider catalog, so the
// built-in openai-chatgpt provider's model list is returned even though it has no
// provider.openai-chatgpt settings entry. A provider absent from the catalog
// still yields no models.
func TestModelCatalog_BuiltinChatGPTAllowlist(t *testing.T) {
	cache := providerCache(t, t.TempDir()) // configures only openai
	mc := modelCatalog{effortModel: effortModel{active: selectedState()}, cache: cache}

	if got := mc.Models("openai-chatgpt"); !slices.Equal(got, []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark"}) {
		t.Fatalf("Models(openai-chatgpt) = %v, want the built-in allowlist [gpt-5.5 gpt-5.4 gpt-5.4-mini gpt-5.3-codex-spark] (read from the catalog, not settings)", got)
	}
	if got := mc.Models("openai"); !slices.Equal(got, []string{"gpt-5.5", "gpt-5.5-pro"}) {
		t.Fatalf("Models(openai) = %v, want the configured allowlist", got)
	}
	if got := mc.Models("nope"); got != nil {
		t.Fatalf("Models(nope) = %v, want nil for a provider absent from the catalog", got)
	}
}

// seedChatGPTDiscovered writes one discovered ChatGPT model (slug plus optional cached
// reasoning levels under capabilities.supported_reasoning_levels) into the shared
// models.yaml store beside globalSettingsPath — the production read path config.NewCache
// derives discovered ChatGPT ids from, via the real store writer.
func seedChatGPTDiscovered(t *testing.T, globalSettingsPath, slug string, levels ...string) {
	t.Helper()
	m := config.DiscoveredModel{ID: slug}
	if len(levels) > 0 {
		objs := make([]any, len(levels))
		for i, l := range levels {
			objs[i] = map[string]any{"effort": l}
		}
		m.Capabilities = map[string]any{"supported_reasoning_levels": objs}
	}
	if err := config.UpdateDiscoveredModelsProvider(
		config.DiscoveredModelsPath(globalSettingsPath), "openai-chatgpt",
		config.DiscoveredProvider{Models: []config.DiscoveredModel{m}},
	); err != nil {
		t.Fatalf("seed discovered ChatGPT models: %v", err)
	}
}

// seedVeniceDiscovered writes a discovered configured-provider (Venice-style) model with
// the given reasoningEffortOptions into the models.yaml store beside globalSettingsPath, via
// the real store writer — the production read path config.NewCache derives a configured
// provider's discovered effort set from.
func seedVeniceDiscovered(t *testing.T, globalSettingsPath, id string, options ...string) {
	t.Helper()
	opts := make([]any, len(options))
	for i, o := range options {
		opts[i] = o
	}
	m := config.DiscoveredModel{ID: id, Capabilities: map[string]any{
		"supportsReasoningEffort": true,
		"reasoningEffortOptions":  opts,
	}}
	if err := config.UpdateDiscoveredModelsProvider(
		config.DiscoveredModelsPath(globalSettingsPath), "venice",
		config.DiscoveredProvider{Models: []config.DiscoveredModel{m}},
	); err != nil {
		t.Fatalf("seed discovered venice models: %v", err)
	}
}

// TestDiscoveredChatGPTModel_SelectableThroughProductionSeams pins discovered-model selectability end to end:
// a model id discovered into the shared models.yaml store is reachable by every consumer a
// user hits, when the cache is built the production way — config.NewCache deriving the store
// path from real global-first layerPaths, not records handed straight to BuildCatalog. It
// fails if NewCache stops deriving the store path, derives it from the wrong layer, or any
// downstream consumer (SelectableCatalog, model.Validate, /model's modelCatalog.Models, or
// the provider-aware picker's providerModelCatalog.ProviderModels) drops the discovered id.
func TestDiscoveredChatGPTModel_SelectableThroughProductionSeams(t *testing.T) {
	dir := t.TempDir()
	// config.NewCache derives the models.yaml store from filepath.Dir(layerPaths[0]), so the
	// global-first settings path and the discovered-model store share a directory.
	layerPaths := []string{filepath.Join(dir, "settings.yaml"), filepath.Join(t.TempDir(), "settings.yaml")}
	seedChatGPTDiscovered(t, layerPaths[0], "gpt-5.6")
	cache, err := config.NewCache(map[string]any{}, t.TempDir(), layerPaths)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	// Seam 1: the selectable catalog carries the discovered slug on the built-in row.
	entry, ok := cache.SelectableCatalog().Entry("openai-chatgpt")
	if !ok || !slices.Contains(entry.Models, "gpt-5.6") {
		t.Fatalf("SelectableCatalog Entry(openai-chatgpt) = (%+v, %v), want it to contain gpt-5.6", entry.Models, ok)
	}

	// Seam 2: model.Validate accepts the discovered slug and still rejects an unknown one.
	if se := model.Validate(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.6", Effort: model.EffortNoReasoning}, cache); se != nil {
		t.Fatalf("Validate(openai-chatgpt/gpt-5.6) = %v, want nil", se)
	}
	if se := model.Validate(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-9.9", Effort: model.EffortNoReasoning}, cache); se == nil {
		t.Fatalf("Validate(openai-chatgpt/gpt-9.9) = nil, want rejection for an undiscovered slug")
	}

	// Seam 3: /model's active-provider allowlist includes the discovered slug.
	if got := (modelCatalog{cache: cache}).Models("openai-chatgpt"); !slices.Contains(got, "gpt-5.6") {
		t.Fatalf("modelCatalog.Models(openai-chatgpt) = %v, want it to contain gpt-5.6", got)
	}

	// Seam 4: the provider-aware picker cross-product carries the discovered slug row.
	want := tui.ProviderModel{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.6"}
	if got := (providerModelCatalog{cache: cache}).ProviderModels(); !slices.Contains(got, want) {
		t.Fatalf("providerModelCatalog.ProviderModels() = %+v, want it to contain %+v", got, want)
	}
}

// TestDiscoveredChatGPTModel_LegacyJSONSidecarIgnored pins the removal of the old
// JSON read path: the retired openai-chatgpt-models.json sidecar is no longer a production
// source, so an id present only there — with no models.yaml store — never becomes
// selectable. Only the compiled seed stays on the built-in ChatGPT row. It fails if
// config.NewCache regains a fallback read of the JSON sidecar.
func TestDiscoveredChatGPTModel_LegacyJSONSidecarIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "openai-chatgpt-models.json"),
		[]byte(`{"models":[{"slug":"gpt-5.6"}]}`), 0o644); err != nil {
		t.Fatalf("write legacy JSON sidecar: %v", err)
	}
	layerPaths := []string{filepath.Join(dir, "settings.yaml"), filepath.Join(t.TempDir(), "settings.yaml")}
	cache, err := config.NewCache(map[string]any{}, t.TempDir(), layerPaths)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	entry, ok := cache.SelectableCatalog().Entry("openai-chatgpt")
	if !ok {
		t.Fatal("SelectableCatalog missing built-in openai-chatgpt row")
	}
	if slices.Contains(entry.Models, "gpt-5.6") {
		t.Fatalf("openai-chatgpt Models = %v, must not include the JSON-sidecar id gpt-5.6 (no production JSON fallback)", entry.Models)
	}
	if se := model.Validate(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.6", Effort: model.EffortNoReasoning}, cache); se == nil {
		t.Fatal("Validate(openai-chatgpt/gpt-5.6) = nil, want rejection (JSON-sidecar id is not selectable)")
	}
}

// TestPickerOffline_NoDiscoveryOrNetwork pins the picker-path half of the
// offline contract (the auth-status half is TestOffline_NoDiscoveryConstruction in
// internal/authstatus): picker listing, open, and highlight make no ChatGPT discovery, and
// /model reads only the local selectable catalog. Only a forced Ctrl-R may reach
// bootstrap's refresh service through the injected RefreshCatalog callback; the picker
// code itself must not construct provider.NewChatGPTClient, call
// provider.RefreshChatGPTModelCache, or import net / net/http.
//
// The scan is scoped to the picker-owned surfaces — the catalog/applier logic in
// modeldeps.go and the three effort/model/picker deps constructors in starttui.go — never the
// whole bootstrap package, because turndeps.go legitimately constructs the ChatGPT client for
// turn dispatch and must not be flagged. The tui package cannot import internal/provider, so a
// discovery client is unconstructible in picker_model.go; there the meaningful offline break is
// a direct net import, which the import ban below catches.
//
// It fails if any of those picker surfaces adds provider.NewChatGPTClient /
// provider.RefreshChatGPTModelCache, or a net / net/http import.
func TestPickerOffline_NoDiscoveryOrNetwork(t *testing.T) {
	fset := token.NewFileSet()
	parse := func(name string) *ast.File {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return f
	}

	forbiddenSel := map[string]bool{"NewChatGPTClient": true, "RefreshChatGPTModelCache": true}
	assertNoDiscovery := func(where string, n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "provider" && forbiddenSel[sel.Sel.Name] {
				t.Fatalf("%s references provider.%s; the model picker must not construct a discovery client or discover", where, sel.Sel.Name)
			}
			return true
		})
	}

	// modelCatalog / providerModelCatalog / the appliers — where a "discover while listing the
	// picker" regression would land.
	assertNoDiscovery("modeldeps.go", parse("modeldeps.go"))

	// The deps constructors live in starttui.go alongside unrelated bootstrap wiring (and, in
	// sibling files, turn dispatch), so scan only these three function bodies, not the file.
	pickerCtors := map[string]bool{"newEffortDeps": true, "newModelDeps": true, "newModelPickerDeps": true}
	for _, d := range parse("starttui.go").Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && pickerCtors[fn.Name.Name] {
			assertNoDiscovery("starttui.go:"+fn.Name.Name, fn.Body)
		}
	}

	// No picker-owned file may dial the network directly.
	forbiddenImp := map[string]bool{`"net"`: true, `"net/http"`: true}
	for _, name := range []string{"modeldeps.go", filepath.Join("..", "tui", "picker_model.go")} {
		for _, imp := range parse(name).Imports {
			if forbiddenImp[imp.Path.Value] {
				t.Fatalf("%s imports %s; the model picker must stay offline", name, imp.Path.Value)
			}
		}
	}
}

func TestDiscoveredChatGPTEfforts_ReachProductionEffortDeps(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	dir := t.TempDir()
	// config.NewCache derives the models.yaml store from filepath.Dir(layerPaths[0]), so the
	// global-first settings path and the discovered-model store share a directory.
	layerPaths := []string{filepath.Join(dir, "settings.yaml"), filepath.Join(t.TempDir(), "settings.yaml")}
	seedChatGPTDiscovered(t, layerPaths[0], "gpt-5.6", "low", "high", "xhigh")
	cache, err := config.NewCache(map[string]any{}, t.TempDir(), layerPaths)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	app := tui.New(nil)
	active := selectedState()
	want := []string{"low", "high", "xhigh"}

	effortDeps := newEffortDeps(ctx, app, cache, active, home)
	if got := effortDeps.Model.SupportedEfforts("openai-chatgpt", "gpt-5.6"); !slices.Equal(got, want) {
		t.Fatalf("/effort SupportedEfforts(openai-chatgpt, gpt-5.6) = %v, want %v (discovered xhigh must reach the effort deps)", got, want)
	}
	modelDeps := newModelDeps(ctx, app, cache, active, home)
	if got := modelDeps.Model.SupportedEfforts("openai-chatgpt", "gpt-5.6"); !slices.Equal(got, want) {
		t.Fatalf("/model SupportedEfforts(openai-chatgpt, gpt-5.6) = %v, want %v (discovered xhigh must reach the /model deps)", got, want)
	}
	pickerDeps := newModelPickerDeps(ctx, app, cache, active, nil, home, "/launch")
	if got := pickerDeps.Catalog.SupportedEfforts("openai-chatgpt", "gpt-5.6"); !slices.Equal(got, want) {
		t.Fatalf("picker SupportedEfforts(openai-chatgpt, gpt-5.6) = %v, want %v (discovered xhigh must reach the picker deps)", got, want)
	}
}

// TestDiscoveredVeniceEfforts_ReachProductionEffortDeps pins that a discovered configured
// Venice model's whitelisted reasoningEffortOptions reach the supported-effort set every
// production consumer reads — /effort (newEffortDeps.Model), /model (newModelDeps.Model), and
// the CTRL-M picker (newModelPickerDeps.Catalog) — through the real discover -> models.yaml ->
// config.NewCache -> catalog path. Unlike the ChatGPT case, Venice is a configured provider,
// so the effort set flows through discoveredConfiguredModels (not the ChatGPT-only path); it
// fails if any constructor stops threading the cache into effortModel, or if the configured
// discovered-effort wiring regresses.
func TestDiscoveredVeniceEfforts_ReachProductionEffortDeps(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	dir := t.TempDir()
	// config.NewCache derives the models.yaml store from filepath.Dir(layerPaths[0]), so the
	// global-first settings path and the discovered-model store share a directory.
	layerPaths := []string{filepath.Join(dir, "settings.yaml"), filepath.Join(t.TempDir(), "settings.yaml")}
	seedVeniceDiscovered(t, layerPaths[0], "claude-opus-4-8", "low", "medium", "high", "max")
	// Venice must be a configured provider for the discovered store to fill its effort set.
	composed := map[string]any{"provider": map[string]any{
		"venice": map[string]any{
			"base_url": "https://api.venice.ai/api/v1",
			"api_key":  "sk-test",
		},
	}}
	cache, err := config.NewCache(composed, t.TempDir(), layerPaths)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	app := tui.New(nil)
	active := selectedState()
	want := []string{"low", "medium", "high", "max"}

	effortDeps := newEffortDeps(ctx, app, cache, active, home)
	if got := effortDeps.Model.SupportedEfforts("venice", "claude-opus-4-8"); !slices.Equal(got, want) {
		t.Fatalf("/effort SupportedEfforts(venice, claude-opus-4-8) = %v, want %v (discovered efforts must reach the effort deps)", got, want)
	}
	modelDeps := newModelDeps(ctx, app, cache, active, home)
	if got := modelDeps.Model.SupportedEfforts("venice", "claude-opus-4-8"); !slices.Equal(got, want) {
		t.Fatalf("/model SupportedEfforts(venice, claude-opus-4-8) = %v, want %v (discovered efforts must reach the /model deps)", got, want)
	}
	pickerDeps := newModelPickerDeps(ctx, app, cache, active, nil, home, "/launch")
	if got := pickerDeps.Catalog.SupportedEfforts("venice", "claude-opus-4-8"); !slices.Equal(got, want) {
		t.Fatalf("picker SupportedEfforts(venice, claude-opus-4-8) = %v, want %v (discovered efforts must reach the picker deps)", got, want)
	}
}

func TestModelApplier_ChatGPT_FallsBackWithoutCachedEffortStaysOnProvider(t *testing.T) {
	ctx := context.Background()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-chatgpt", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: "medium"}, model.SourceResume)

	modelDeps := newModelDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"model": tui.NewModelHandler(modelDeps)})
	host := &recordingHost{store: store}

	res := reg.DispatchSlashInput("/model gpt-5.4", host)
	if res.Status != tui.StatusHandled || res.Canonical != "model" || res.Err != nil {
		t.Fatalf("dispatch result = %+v, want {handled, model, no error}", res)
	}

	changed := decodeModelChanged(t, store)
	if len(changed) != 1 || changed[0].NewModelID != "gpt-5.4" {
		t.Fatalf("model_changed = %+v, want one event for new model gpt-5.4", changed)
	}
	if changed[0].NewEffort == "medium" {
		t.Fatalf("model_changed effort = %q, want a fallback: no cached capability means medium is not advertised", changed[0].NewEffort)
	}
	if changed[0].NewProvider != "openai-chatgpt" {
		t.Fatalf("model_changed provider = %q, want openai-chatgpt (the provider never switches to openai)", changed[0].NewProvider)
	}
	settings := config.LocalSettingsPath(projectRoot)
	assertFileContains(t, settings, "openai-chatgpt")
	assertFileContains(t, settings, "gpt-5.4")
	if sel, _, _ := active.Current(); sel.Provider != "openai-chatgpt" || sel.ID != "gpt-5.4" {
		t.Fatalf("Current() = %+v, want openai-chatgpt/gpt-5.4", sel)
	}
}

func TestProviderModelCatalog_SettingsTargetSnapshot(t *testing.T) {
	projectRoot := t.TempDir()
	cache, err := config.NewCache(map[string]any{}, projectRoot, nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	cat := providerModelCatalog{effortModel: effortModel{active: selectedState()}, cache: cache, launchDir: "/launch"}

	tgt := cat.SettingsTarget()
	wantPath := config.LocalSettingsPath(projectRoot)
	if wantPath != filepath.Join(projectRoot, ".codemeld", "settings.local.yaml") {
		t.Fatalf("config.LocalSettingsPath = %q, want <project>/.codemeld/settings.local.yaml", wantPath)
	}
	if tgt.SettingsPath != wantPath {
		t.Fatalf("SettingsPath = %q, want %q", tgt.SettingsPath, wantPath)
	}
	if tgt.ProjectRoot != projectRoot || tgt.LaunchDir != "/launch" {
		t.Fatalf("target roots = (proj %q, launch %q), want (%q, /launch)", tgt.ProjectRoot, tgt.LaunchDir, projectRoot)
	}
}

// TestProviderModelApplier_CleanProviderSwitch_WritesActiveAndMirrors pins the
// provider-aware apply: it switches the provider (unlike /model), runs the shared
// transaction (model_changed carrying the prior, the per-project active
// write read back from disk, the global mirror after the active write succeeds),
// transitions the source to picker, and appends no slash_command (the picker path
// is non-slash).
func TestProviderModelApplier_CleanProviderSwitch_WritesActiveAndMirrors(t *testing.T) {
	ctx := context.Background()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-switch", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState() // openai/gpt-5.5/medium, source resume

	deps := newModelPickerDeps(ctx, app, providerCache(t, projectRoot), active, nil, home, "/launch")

	if _, err := deps.Applier.ApplyProviderModel("anthropic", "claude-x", "default"); err != nil {
		t.Fatalf("ApplyProviderModel error: %v", err)
	}

	changed := decodeModelChanged(t, store)
	if len(changed) != 1 {
		t.Fatalf("model_changed events = %d, want 1", len(changed))
	}
	mc := changed[0]
	if mc.NewProvider != "anthropic" || mc.NewModelID != "claude-x" || mc.NewEffort != "default" {
		t.Fatalf("model_changed new = %+v, want anthropic/claude-x/default (the provider switches)", mc)
	}
	if mc.PriorProvider != "openai" || mc.PriorModelID != "gpt-5.5" || mc.PriorEffort != "medium" {
		t.Fatalf("model_changed prior = %+v, want openai/gpt-5.5/medium", mc)
	}
	settings := config.LocalSettingsPath(projectRoot)
	assertFileContains(t, settings, "anthropic")
	assertFileContains(t, settings, "claude-x")
	selection := func(path, key string) yaml.MapSlice {
		t.Helper()
		var doc map[string]map[string]yaml.MapSlice
		if err := yaml.Unmarshal([]byte(readFileString(t, path)), &doc); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return doc["model"][key]
	}
	want := yaml.MapSlice{{Key: "provider", Value: "anthropic"}, {Key: "id", Value: "claude-x"}, {Key: "effort", Value: "default"}}
	if got := selection(settings, "active"); !reflect.DeepEqual(got, want) {
		t.Fatalf("local model.active = %#v, want provider/id/effort in that order %#v", got, want)
	}
	if got := selection(settings, "last_used"); got != nil {
		t.Fatalf("local model.last_used = %#v, want it only in the global file", got)
	}
	if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("shared settings.yaml must stay absent; stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); err != nil {
		t.Fatalf("model.last_used mirror not written: %v", err)
	}
	if got := selection(SettingsPath(home), "last_used"); !reflect.DeepEqual(got, want) {
		t.Fatalf("global model.last_used = %#v, want %#v", got, want)
	}
	if n := len(slashCmds(t, store)); n != 0 {
		t.Fatalf("slash_command events = %d, want 0 (the picker apply must not emit a slash_command)", n)
	}
	sel, src, ok := active.Current()
	if !ok || sel.Provider != "anthropic" || sel.ID != "claude-x" || sel.Effort != "default" || src != model.SourcePicker {
		t.Fatalf("Current() = (%+v, %q, %v), want anthropic/claude-x/default + picker", sel, src, ok)
	}
}

// TestProviderModelApplier_FirstPick_NoPriorOmitsPriorFields pins the no-prior
// first-pick path: the picker opens with no model selected, so the apply passes a
// nil prior and model_changed omits the prior provider/id/effort fields
// while still writing the active selection and transitioning the source to picker.
func TestProviderModelApplier_FirstPick_NoPriorOmitsPriorFields(t *testing.T) {
	ctx := context.Background()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-first", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := model.NewActiveState(nil, "") // no model selected — the picker chooses the first

	deps := newModelPickerDeps(ctx, app, providerCache(t, projectRoot), active, nil, home, "/launch")

	if _, err := deps.Applier.ApplyProviderModel("openai", "gpt-5.5", "high"); err != nil {
		t.Fatalf("ApplyProviderModel error: %v", err)
	}

	changed := decodeModelChanged(t, store)
	if len(changed) != 1 {
		t.Fatalf("model_changed events = %d, want 1", len(changed))
	}
	mc := changed[0]
	if mc.NewProvider != "openai" || mc.NewModelID != "gpt-5.5" || mc.NewEffort != "high" {
		t.Fatalf("model_changed new = %+v, want openai/gpt-5.5/high", mc)
	}
	if mc.PriorProvider != "" || mc.PriorModelID != "" || mc.PriorEffort != "" {
		t.Fatalf("model_changed prior = (%q,%q,%q), want all empty (first pick has no prior)", mc.PriorProvider, mc.PriorModelID, mc.PriorEffort)
	}
	assertFileContains(t, config.LocalSettingsPath(projectRoot), "gpt-5.5")
	sel, src, ok := active.Current()
	if !ok || sel.ID != "gpt-5.5" || sel.Effort != "high" || src != model.SourcePicker {
		t.Fatalf("Current() = (%+v, %q, %v), want gpt-5.5/high + picker", sel, src, ok)
	}
}

// TestProviderModelApplier_ActiveWriteFailure_DegradesSkipsMirror pins the degraded
// path: when the per-project model.active write fails, model_changed precedes
// model_persist_failed, the global mirror is skipped, and the source becomes
// picker_degraded — mirroring the effort applier's degradation.
func TestProviderModelApplier_ActiveWriteFailure_DegradesSkipsMirror(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	// A regular file as the project root makes <root>/.codemeld uncreatable, so the
	// per-project model.active write fails deterministically.
	projectRoot := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(projectRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-deg", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState()

	deps := newModelPickerDeps(ctx, app, providerCache(t, projectRoot), active, nil, home, "/launch")

	if _, err := deps.Applier.ApplyProviderModel("anthropic", "claude-x", "default"); err != nil {
		t.Fatalf("ApplyProviderModel error: %v (a persistence degrade is not an internal error)", err)
	}

	kinds := eventKinds(store.Records())
	ci, pi := slices.Index(kinds, events.KindModelChanged), slices.Index(kinds, events.KindModelPersistFailed)
	if ci < 0 || pi < 0 || ci > pi {
		t.Fatalf("event kinds = %v, want model_changed before model_persist_failed", kinds)
	}
	if n := len(kindEvents(t, store, events.KindModelGlobalMirrorFailed)); n != 0 {
		t.Fatalf("model_global_mirror_failed = %d, want 0 (mirror skipped on active-write failure)", n)
	}
	if _, err := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("model.last_used must be absent on active-write failure; stat err = %v", err)
	}
	if _, src, _ := active.Current(); src != model.SourcePickerDegraded {
		t.Fatalf("active source = %q, want picker_degraded", src)
	}
}

// TestProviderModelApplier_SwitchIntoChatGPTPersistsStableId pins the CTRL-M picker
// entrypoint for the openai-chatgpt duplicate-id case through the production deps
// newModelPickerDeps builds: the wired catalog surfaces the built-in "OpenAI ChatGPT"
// group, and confirming its gpt-5.5 row switches the provider from openai to openai-chatgpt
// for the SAME model id — persisting the stable id openai-chatgpt (never the display name,
// never staying on openai) to the on-disk model.active and mirroring last_used (
// 510, 520). The existing picker-switch test switches to anthropic, a distinct model id with
// no disambiguation challenge; the existing openai-chatgpt test is the /model path with the
// provider already active. Neither exercises a picker provider-switch into a built-in
// selectable provider for a model id shared with the configured openai provider.
func TestProviderModelApplier_SwitchIntoChatGPTPersistsStableId(t *testing.T) {
	ctx := context.Background()
	projectRoot := t.TempDir()
	home := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-into-chatgpt", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState() // openai/gpt-5.5/medium, source resume

	deps := newModelPickerDeps(ctx, app, providerCache(t, projectRoot), active, nil, home, "/launch")

	// The wired production catalog (not a fake) surfaces the built-in OpenAI ChatGPT group,
	// so the row the picker confirms below is the real selectable one.
	if !slices.Contains(deps.Catalog.ProviderModels(), tui.ProviderModel{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.5"}) {
		t.Fatalf("wired picker catalog = %+v, want it to include the built-in OpenAI ChatGPT gpt-5.5 row", deps.Catalog.ProviderModels())
	}

	// Confirm openai-chatgpt/gpt-5.5: the same model id as the prior openai selection, so a
	// stable-id-vs-display-name or provider-disambiguation bug surfaces here.
	if _, err := deps.Applier.ApplyProviderModel("openai-chatgpt", "gpt-5.5", "medium"); err != nil {
		t.Fatalf("ApplyProviderModel error: %v", err)
	}

	changed := decodeModelChanged(t, store)
	if len(changed) != 1 {
		t.Fatalf("model_changed events = %d, want 1", len(changed))
	}
	mc := changed[0]
	if mc.NewProvider != "openai-chatgpt" || mc.NewModelID != "gpt-5.5" {
		t.Fatalf("model_changed new = %+v, want openai-chatgpt/gpt-5.5 (the provider switches despite the shared id)", mc)
	}
	if mc.PriorProvider != "openai" {
		t.Fatalf("model_changed prior provider = %q, want openai (the run switched away from it)", mc.PriorProvider)
	}

	// On-disk model.active carries the stable provider id, not the display name.
	settings := config.LocalSettingsPath(projectRoot)
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("read model.active settings: %v", err)
	}
	if !strings.Contains(string(data), "openai-chatgpt") {
		t.Fatalf("model.active does not persist the stable id openai-chatgpt:\n%s", data)
	}
	if strings.Contains(string(data), "OpenAI ChatGPT") {
		t.Fatalf("model.active persisted the display name instead of the stable id:\n%s", data)
	}
	// last_used is mirrored only after the active write succeeds.
	if _, err := os.Stat(filepath.Join(home, ".codemeld", "global", "settings.yaml")); err != nil {
		t.Fatalf("model.last_used mirror not written: %v", err)
	}
	if n := len(slashCmds(t, store)); n != 0 {
		t.Fatalf("slash_command events = %d, want 0 (the picker apply is non-slash)", n)
	}
	sel, src, ok := active.Current()
	if !ok || sel.Provider != "openai-chatgpt" || sel.ID != "gpt-5.5" || src != model.SourcePicker {
		t.Fatalf("Current() = (%+v, %q, %v), want openai-chatgpt/gpt-5.5 + picker", sel, src, ok)
	}
}

func TestModelApplier_WritesLocalSettingsThroughProductionConstructors(t *testing.T) {
	ctx := context.Background()
	projectRoot := mustCanonical(t, t.TempDir())
	home := t.TempDir()
	if err := trust.Record(home, projectRoot); err != nil {
		t.Fatalf("trust.Record: %v", err)
	}
	trustStore := trust.StorePath(home)
	trustBefore, err := os.ReadFile(trustStore)
	if err != nil {
		t.Fatal(err)
	}
	trustStatBefore, err := os.Stat(trustStore)
	if err != nil {
		t.Fatal(err)
	}

	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-local", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	active := selectedState()

	modelDeps := newModelDeps(ctx, app, providerCache(t, projectRoot), active, home)
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"model": tui.NewModelHandler(modelDeps)})
	if res := reg.DispatchSlashInput("/model gpt-5.5-pro", &recordingHost{store: store}); res.Err != nil {
		t.Fatalf("dispatch error = %v, want nil", res.Err)
	}

	body := readFileString(t, config.LocalSettingsPath(projectRoot))
	pi, ii, ei := strings.Index(body, "provider:"), strings.Index(body, "id:"), strings.Index(body, "effort:")
	if pi < 0 || ii < 0 || ei < 0 || pi >= ii || ii >= ei {
		t.Fatalf("local model.active is not a provider/id/effort mapping in that order:\n%s", body)
	}
	if strings.Contains(body, "model_id") {
		t.Fatalf("on-disk field must be id, not model_id:\n%s", body)
	}
	if _, err := os.Stat(filepath.Join(projectRoot, ".codemeld", "settings.yaml")); !os.IsNotExist(err) {
		t.Fatalf("shared settings.yaml must stay absent; stat err = %v", err)
	}

	trustAfter, err := os.ReadFile(trustStore)
	if err != nil {
		t.Fatal(err)
	}
	trustStatAfter, err := os.Stat(trustStore)
	if err != nil {
		t.Fatal(err)
	}
	if string(trustAfter) != string(trustBefore) || !trustStatAfter.ModTime().Equal(trustStatBefore.ModTime()) {
		t.Fatalf("a model pick touched the approval store at %s", trustStore)
	}
}

// noticeApp builds the production-wired app, deps and project the notice tests drive, with a
// stale notice already pinned so a clear is observable.
func noticeApp(t *testing.T, projectRoot string) (*tui.App, tui.ModelDeps, tui.ModelPickerDeps) {
	t.Helper()
	ctx := context.Background()
	home := t.TempDir()
	store := storeAt(t, filepath.Join(t.TempDir(), "s.json"), "id-notice", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)
	app.Notice(staleNotice)
	active := selectedState()
	cache := providerCache(t, projectRoot)
	return app, newModelDeps(ctx, app, cache, active, home), newModelPickerDeps(ctx, app, cache, active, nil, home, "/launch")
}

const staleNotice = "a pinned notice from an earlier turn"

func pickThroughSlashModel(t *testing.T, deps tui.ModelDeps) {
	t.Helper()
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"model": tui.NewModelHandler(deps)})
	if res := reg.DispatchSlashInput("/model gpt-5.5-pro", &recordingHost{store: mkStore(t)}); res.Err != nil {
		t.Fatalf("dispatch error = %v, want nil", res.Err)
	}
}

// A notice the apply itself emitted must outlive the model paths' stale-notice clear, or the
// user never sees that the pick created the local settings file.
func TestModelPick_LocalFileCreationNoticeSurvivesTheApply(t *testing.T) {
	for name, pick := range map[string]func(t *testing.T, app *tui.App, md tui.ModelDeps, pd tui.ModelPickerDeps){
		"/model": func(t *testing.T, _ *tui.App, md tui.ModelDeps, _ tui.ModelPickerDeps) {
			pickThroughSlashModel(t, md)
		},
		"CTRL-M": func(t *testing.T, app *tui.App, _ tui.ModelDeps, pd tui.ModelPickerDeps) {
			app.SetModelPickerDeps(pd)
			app.ConfirmModelRowForTest(tui.ProviderModel{Provider: "anthropic", ModelID: "claude-x"}, "default")
		},
	} {
		t.Run(name, func(t *testing.T) {
			projectRoot := t.TempDir()
			app, md, pd := noticeApp(t, projectRoot)

			pick(t, app, md, pd)

			notice := app.NoticeText()
			for _, want := range []string{config.LocalSettingsPath(projectRoot), config.LocalSettingsLockPath(projectRoot)} {
				if !strings.Contains(notice, want) {
					t.Fatalf("notice = %q, want it to name %q", notice, want)
				}
			}
		})
	}
}

// The degraded active-write notice has the same problem: it is the only report the user gets
// that the selection is session-only.
func TestModelPick_DegradedActiveWriteNoticeSurvivesTheApply(t *testing.T) {
	// A regular file as the project root makes <root>/.codemeld uncreatable, so the
	// per-project model.active write fails deterministically.
	unwritableRoot := func(t *testing.T) string {
		t.Helper()
		root := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return root
	}
	for name, pick := range map[string]func(t *testing.T, app *tui.App, md tui.ModelDeps, pd tui.ModelPickerDeps){
		"/model": func(t *testing.T, _ *tui.App, md tui.ModelDeps, _ tui.ModelPickerDeps) {
			pickThroughSlashModel(t, md)
		},
		"CTRL-M": func(t *testing.T, app *tui.App, _ tui.ModelDeps, pd tui.ModelPickerDeps) {
			app.SetModelPickerDeps(pd)
			app.ConfirmModelRowForTest(tui.ProviderModel{Provider: "anthropic", ModelID: "claude-x"}, "default")
		},
	} {
		t.Run(name, func(t *testing.T) {
			projectRoot := unwritableRoot(t)
			app, md, pd := noticeApp(t, projectRoot)

			pick(t, app, md, pd)

			if notice := app.NoticeText(); !strings.Contains(notice, config.LocalSettingsPath(projectRoot)) {
				t.Fatalf("notice = %q, want the degraded write notice naming %q", notice, config.LocalSettingsPath(projectRoot))
			}
		})
	}
}

// A second pick that fails the same way emits the same notice text, so the stale test cannot
// be text equality: the user would lose the only report that the selection is session-only.
func TestModelPick_RepeatedDegradedNoticeSurvivesTheSecondApply(t *testing.T) {
	for name, pick := range map[string]func(t *testing.T, app *tui.App, md tui.ModelDeps, pd tui.ModelPickerDeps){
		"/model": func(t *testing.T, _ *tui.App, md tui.ModelDeps, _ tui.ModelPickerDeps) {
			pickThroughSlashModel(t, md)
		},
		"CTRL-M": func(t *testing.T, app *tui.App, _ tui.ModelDeps, pd tui.ModelPickerDeps) {
			app.SetModelPickerDeps(pd)
			app.ConfirmModelRowForTest(tui.ProviderModel{Provider: "anthropic", ModelID: "claude-x"}, "default")
		},
	} {
		t.Run(name, func(t *testing.T) {
			projectRoot := filepath.Join(t.TempDir(), "not-a-dir")
			if err := os.WriteFile(projectRoot, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			app, md, pd := noticeApp(t, projectRoot)

			pick(t, app, md, pd)
			first := app.NoticeText()
			pick(t, app, md, pd)

			if got := app.NoticeText(); got != first {
				t.Fatalf("notice after a repeated degraded pick = %q, want the re-emitted %q", got, first)
			}
			if !strings.Contains(first, config.LocalSettingsPath(projectRoot)) {
				t.Fatalf("notice = %q, want the degraded write notice naming %q", first, config.LocalSettingsPath(projectRoot))
			}
		})
	}
}

// The clear itself is preserved: a pick whose apply emits no notice still drops the stale one.
func TestModelPick_SecondPickStillClearsAStaleNotice(t *testing.T) {
	for name, pick := range map[string]func(t *testing.T, app *tui.App, md tui.ModelDeps, pd tui.ModelPickerDeps){
		"/model": func(t *testing.T, _ *tui.App, md tui.ModelDeps, _ tui.ModelPickerDeps) {
			pickThroughSlashModel(t, md)
		},
		"CTRL-M": func(t *testing.T, app *tui.App, _ tui.ModelDeps, pd tui.ModelPickerDeps) {
			app.SetModelPickerDeps(pd)
			app.ConfirmModelRowForTest(tui.ProviderModel{Provider: "anthropic", ModelID: "claude-x"}, "default")
		},
	} {
		t.Run(name, func(t *testing.T) {
			projectRoot := t.TempDir()
			app, md, pd := noticeApp(t, projectRoot)
			pick(t, app, md, pd)

			app.Notice(staleNotice)
			pick(t, app, md, pd)

			if got := app.NoticeText(); got != "" {
				t.Fatalf("notice after a second pick = %q, want the stale notice cleared", got)
			}
		})
	}
}

func favoritesGlobalCache(t *testing.T, favs ...config.Favorite) (*config.Cache, string) {
	t.Helper()
	global := filepath.Join(t.TempDir(), "settings.yaml")
	var sb strings.Builder
	sb.WriteString("model:\n  favorites:\n")
	list := make([]any, 0, len(favs))
	for _, f := range favs {
		fmt.Fprintf(&sb, "    - provider: %s\n      id: %s\n", f.Provider, f.ID)
		list = append(list, map[string]any{"provider": f.Provider, "id": f.ID})
	}
	if err := os.WriteFile(global, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("seed global favorites: %v", err)
	}
	cache, err := config.NewCache(map[string]any{"model": map[string]any{"favorites": list}}, t.TempDir(), []string{global})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache, global
}

func TestProviderModelFavorites_MapsOrderedSnapshot(t *testing.T) {
	cache, _ := favoritesGlobalCache(t,
		config.Favorite{Provider: "openai", ID: "gpt-5.5"},
		config.Favorite{Provider: "anthropic", ID: "claude-x"},
	)
	fav := providerModelFavorites{cache: cache}

	want := []tui.ModelFavorite{
		{Provider: "openai", ModelID: "gpt-5.5"},
		{Provider: "anthropic", ModelID: "claude-x"},
	}
	got := fav.Favorites()
	if !slices.Equal(got, want) {
		t.Fatalf("Favorites() = %+v, want %+v (cache order preserved)", got, want)
	}

	got[0] = tui.ModelFavorite{Provider: "mutated", ModelID: "mutated"}
	if again := fav.Favorites(); !slices.Equal(again, want) {
		t.Fatalf("mutating a returned snapshot changed a later one: %+v, want %+v", again, want)
	}

	emptyCache, err := config.NewCache(map[string]any{}, t.TempDir(), []string{filepath.Join(t.TempDir(), "settings.yaml")})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	if got := (providerModelFavorites{cache: emptyCache}).Favorites(); got != nil {
		t.Fatalf("Favorites() over an empty cache = %+v, want nil", got)
	}
}

func TestProviderModelFavorites_TogglesExactCachedMembership(t *testing.T) {
	cache, global := favoritesGlobalCache(t, config.Favorite{Provider: "openai", ID: "shared-model"})
	fav := providerModelFavorites{cache: cache}

	added, err := fav.ToggleFavorite("anthropic", "shared-model")
	if err != nil {
		t.Fatalf("add toggle error: %v", err)
	}
	wantAdded := []tui.ModelFavorite{
		{Provider: "openai", ModelID: "shared-model"},
		{Provider: "anthropic", ModelID: "shared-model"},
	}
	if !slices.Equal(added, wantAdded) {
		t.Fatalf("add toggle = %+v, want %+v (same id under another provider is an add, not a remove)", added, wantAdded)
	}
	if live := fav.Favorites(); !slices.Equal(live, wantAdded) {
		t.Fatalf("live snapshot after add = %+v, want %+v", live, wantAdded)
	}
	assertFileContains(t, global, "provider: anthropic")

	removed, err := fav.ToggleFavorite("openai", "shared-model")
	if err != nil {
		t.Fatalf("remove toggle error: %v", err)
	}
	wantRemoved := []tui.ModelFavorite{{Provider: "anthropic", ModelID: "shared-model"}}
	if !slices.Equal(removed, wantRemoved) {
		t.Fatalf("remove toggle = %+v, want %+v", removed, wantRemoved)
	}
	if live := fav.Favorites(); !slices.Equal(live, wantRemoved) {
		t.Fatalf("live snapshot after remove = %+v, want %+v", live, wantRemoved)
	}
	assertFileContains(t, global, "provider: anthropic")
	assertFileLacks(t, global, "openai")
}

func TestProviderModelFavorites_ErrorReturnsNoReplacement(t *testing.T) {
	cache, global := favoritesGlobalCache(t, config.Favorite{Provider: "openai", ID: "gpt-5.5"})
	fav := providerModelFavorites{cache: cache}

	sentinel := errors.New("forced parent dir sync failure")
	restore := fsutil.SetSyncDirForTest(func(*os.File) error { return sentinel })
	t.Cleanup(restore)

	got, err := fav.ToggleFavorite("anthropic", "claude-x")
	if got != nil || !errors.Is(err, sentinel) {
		t.Fatalf("failed toggle = (%+v, %v), want (nil, wrap of sentinel)", got, err)
	}
	restore()

	assertFileContains(t, global, "provider: anthropic")
	want := []tui.ModelFavorite{{Provider: "openai", ModelID: "gpt-5.5"}}
	if live := fav.Favorites(); !slices.Equal(live, want) {
		t.Fatalf("live snapshot after failure = %+v, want unchanged %+v (no reload of unconfirmed disk state)", live, want)
	}
}

func TestModelPickerDeps_ForcedChatGPTRefreshWritesStoreAndCatalog(t *testing.T) {
	stubChatGPTDiscovery(t, http.StatusOK, chatGPTDiscoveryBody)
	ctx := context.Background()
	home := t.TempDir()
	projectRoot := t.TempDir()
	cache, err := config.NewCache(map[string]any{}, projectRoot, []string{SettingsPath(home)})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	app := tui.New(nil)
	auth := renewedChatGPTAuth()
	deps := newModelPickerDeps(ctx, app, cache, selectedState(), auth, home, "/launch")

	done := make(chan tui.ModelRefreshResult, 1)
	deps.RefreshCatalog(provider.ChatGPTProviderID, true, func(res tui.ModelRefreshResult) { done <- res })
	select {
	case res := <-done:
		if res != (tui.ModelRefreshResult{Provider: provider.ChatGPTProviderID, Outcome: tui.ModelRefreshUpdated}) {
			t.Fatalf("forced ChatGPT refresh = %+v, want updated", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forced ChatGPT refresh never completed")
	}
	if auth.ensureCount() != 1 {
		t.Fatalf("session resolutions = %d, want 1", auth.ensureCount())
	}

	store, err := config.ReadDiscoveredModels(config.DiscoveredModelsPath(SettingsPath(home)))
	if err != nil {
		t.Fatalf("read models.yaml: %v", err)
	}
	entry := store.Providers[provider.ChatGPTProviderID]
	if entry.Source != "picker-catalog-refresh" || len(entry.Models) != 1 {
		t.Fatalf("stored ChatGPT entry = %+v, want one model from picker-catalog-refresh", entry)
	}
	m := entry.Models[0]
	if m.ID != "gpt-5.7" || m.DisplayName != "GPT-5.7" || m.ContextWindow != 400000 ||
		!slices.Equal(m.InputModalities, []string{"text", "image"}) || m.Capabilities["supported_reasoning_levels"] == nil {
		t.Errorf("stored ChatGPT model = %+v, want every sanitized discovery field", m)
	}
	want := tui.ProviderModel{Provider: provider.ChatGPTProviderID, DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.7"}
	if !slices.Contains(deps.Catalog.ProviderModels(), want) {
		t.Errorf("picker catalog = %+v, want it to expose %+v", deps.Catalog.ProviderModels(), want)
	}
}
