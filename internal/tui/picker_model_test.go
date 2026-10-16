// Tests for the CTRL-M model picker overlay:
// the single-column provider×model table grouped under non-selectable provider
// headers (rendering, order, header-skip navigation, and post-header index
// resolution), the overlay-open no-op, per-highlighted-model
// inline-effort refresh (including the {default}-only single value, the
// unsupported-effort fallback, and ←/→ stepping with clamping), the settings path
// display and cross-mode marker disclosure, the effort-source-on-confirm rule,
// every-selection-persists (no session-only path), the in-session confirmation /
// marker transcript lines, the apply-error notice, and ESC dismissal — driven
// through ProviderModelCatalog/ProviderModelApplier fakes and, for the live key
// bindings, a simulation screen.
//
// The persistence/event behavior the confirm path triggers (model_changed
// before WriteActive, the model_persist_failed / model_global_mirror_failed events,
// the picker/picker_degraded source state, and the last-used mirror) lives inside
// the production ProviderModelApplier (its reuse of the shared
// transaction) and is exercised where that applier lives plus the YAML rewrite-contract
// integration test — mirroring how the effort picker delegates the same flow. At this
// handler/seam layer the picker owns only the call-through and the marker/error/
// confirmation surfacing, which is what these tests assert.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// providerModelCatalogFake is an in-memory ProviderModelCatalog. rows is the
// cross-product the picker renders; supported maps "provider/modelID" to that
// model's effort set (unknown keys canonicalize to {default}); target is the
// settings-path snapshot.
type providerModelCatalogFake struct {
	provider       string
	modelID        string
	effort         string
	selected       bool
	rows           []ProviderModel
	supported      map[string][]string
	target         ModelSettingsTarget
	emptyProviders []ProviderModel
}

func (c *providerModelCatalogFake) ActiveSelection() (string, string, string, bool) {
	return c.provider, c.modelID, c.effort, c.selected
}

func (c *providerModelCatalogFake) ProviderModels() []ProviderModel { return c.rows }

func (c *providerModelCatalogFake) ConfiguredProviders() []ProviderModel {
	seen := map[string]bool{}
	var out []ProviderModel
	for _, r := range c.rows {
		if r.Provider == builtinChatGPTProviderID || seen[r.Provider] {
			continue
		}
		seen[r.Provider] = true
		out = append(out, ProviderModel{Provider: r.Provider, DisplayName: r.DisplayName})
	}
	for _, p := range c.emptyProviders {
		if !seen[p.Provider] {
			seen[p.Provider] = true
			out = append(out, p)
		}
	}
	return out
}

func (c *providerModelCatalogFake) SupportedEfforts(provider, modelID string) []string {
	if s, ok := c.supported[provider+"/"+modelID]; ok {
		return s
	}
	return []string{"default"}
}

func (c *providerModelCatalogFake) SettingsTarget() ModelSettingsTarget { return c.target }

// providerModelApplierFake records the provider/id/effort ApplyProviderModel was
// called with and returns a preset result/error so picker behavior can be asserted
// without persistence.
type providerModelApplierFake struct {
	calls       int
	gotProvider string
	gotID       string
	gotEffort   string
	result      ModelApplyResult
	err         error
}

func (a *providerModelApplierFake) ApplyProviderModel(provider, modelID, effort string) (ModelApplyResult, error) {
	a.calls++
	a.gotProvider = provider
	a.gotID = modelID
	a.gotEffort = effort
	return a.result, a.err
}

// selectedModelCatalog is the default fixture: active selection openai/gpt-5 at
// medium effort, a three-row cross-product spanning two providers, gpt-5-mini with a
// no-medium effort set (to exercise the fallback), and a {default}-only model.
func selectedModelCatalog() *providerModelCatalogFake {
	return &providerModelCatalogFake{
		provider: "openai",
		modelID:  "gpt-5",
		effort:   "medium",
		selected: true,
		rows: []ProviderModel{
			{Provider: "openai", ModelID: "gpt-5"},
			{Provider: "openai", ModelID: "gpt-5-mini"},
			{Provider: "anthropic", ModelID: "claude-x"},
		},
		supported: map[string][]string{
			"openai/gpt-5":       {"minimal", "low", "medium", "high"},
			"openai/gpt-5-mini":  {"low", "high"},
			"anthropic/claude-x": {"default"},
		},
		target: ModelSettingsTarget{
			SettingsPath: "/work/proj/.codemeld/settings.yaml",
			LaunchDir:    "/work/proj",
			ProjectRoot:  "/work/proj",
		},
	}
}

// modelTableRow returns the table row whose model cell references the given flat
// data index, or -1 if none — used to translate a rows index to its table position
// after provider headers shift the indexes.
func modelTableRow(tbl *tview.Table, dataIndex int) int {
	for r := 0; r < tbl.GetRowCount(); r++ {
		if i, ok := tbl.GetCell(r, 0).GetReference().(int); ok && i == dataIndex {
			return r
		}
	}
	return -1
}

func TestModelPicker_BuildGroupsModelsUnderProviderHeaders(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	// The three-row, two-provider fixture renders as: openai header, gpt-5,
	// gpt-5-mini, blank spacer, anthropic header, claude-x — one header per provider
	// group, models in declaration order beneath their header, and a blank spacer row
	// separating the groups.
	wantText := []string{"openai", "gpt-5", "gpt-5-mini", "", "anthropic", "claude-x"}
	if got := tbl.GetRowCount(); got != len(wantText) {
		t.Fatalf("table row count = %d, want %d (3 models + 2 provider headers + 1 spacer)", got, len(wantText))
	}
	for r, want := range wantText {
		cell := tbl.GetCell(r, 0)
		if cell.Text != want {
			t.Errorf("table row %d text = %q, want %q", r, cell.Text, want)
		}
	}

	// Non-model rows (openai header @ 0, spacer @ 3, anthropic header @ 4) are
	// non-selectable and carry no model reference; model rows are selectable and
	// reference their flat rows index.
	for r, want := range wantText {
		cell := tbl.GetCell(r, 0)
		isModel := want != "openai" && want != "anthropic" && want != ""
		if cell.NotSelectable == isModel {
			t.Errorf("table row %d NotSelectable = %v, want %v (model=%v)", r, cell.NotSelectable, !isModel, isModel)
		}
		_, hasRef := cell.GetReference().(int)
		if hasRef != isModel {
			t.Errorf("table row %d has-model-reference = %v, want %v", r, hasRef, isModel)
		}
	}

	// Each model cell maps back to the correct flat row, despite the inserted headers.
	for i, r := range cat.rows {
		tr := modelTableRow(tbl, i)
		if tr < 0 {
			t.Fatalf("no table row references data index %d (%s)", i, r.ModelID)
		}
		if got := tbl.GetCell(tr, 0).Text; got != r.ModelID {
			t.Errorf("data index %d at table row %d = %q, want %q", i, tr, got, r.ModelID)
		}
	}
}

// chatGPTDisplayNameCatalog is a provider display-name fixture: a configured OpenAI Platform
// group and the built-in OpenAI ChatGPT group, each carrying a display name
// distinct from its stable provider id, with the same model id (gpt-5.5) under
// both so the duplicate-id disambiguation can be asserted.
func chatGPTDisplayNameCatalog() *providerModelCatalogFake {
	gpt55ChatGPTEfforts := []string{"none", "low", "medium", "high", "xhigh"}
	return &providerModelCatalogFake{
		provider: "openai",
		modelID:  "gpt-5.5",
		effort:   "medium",
		selected: true,
		rows: []ProviderModel{
			{Provider: "openai", DisplayName: "OpenAI Platform", ModelID: "gpt-5.5"},
			{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.5"},
			{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.4"},
			{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.4-mini"},
			{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "gpt-5.3-codex-spark"},
		},
		supported: map[string][]string{
			"openai/gpt-5.5":                     {"minimal", "low", "medium", "high"},
			"openai-chatgpt/gpt-5.5":             gpt55ChatGPTEfforts,
			"openai-chatgpt/gpt-5.4":             gpt55ChatGPTEfforts,
			"openai-chatgpt/gpt-5.4-mini":        gpt55ChatGPTEfforts,
			"openai-chatgpt/gpt-5.3-codex-spark": gpt55ChatGPTEfforts,
		},
		target: ModelSettingsTarget{SettingsPath: "/work/proj/.codemeld/settings.yaml", LaunchDir: "/work/proj", ProjectRoot: "/work/proj"},
	}
}

// TestModelPicker_RendersProviderDisplayNameHeaders pins display-name group headers: the picker
// renders each provider group's header from its display name ("OpenAI Platform",
// "OpenAI ChatGPT") rather than the stable provider id, while the duplicate gpt-5.5
// id under both providers stays two distinct selectable rows. Confirming an OpenAI
// ChatGPT row applies and reports the stable provider id openai-chatgpt — never the
// display name — so persistence and the confirmation line keep the id.
func TestModelPicker_RendersProviderDisplayNameHeaders(t *testing.T) {
	a := New(nil)
	cat := chatGPTDisplayNameCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	wantText := []string{"OpenAI Platform", "gpt-5.5", "", "OpenAI ChatGPT", "gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.5"}
	if got := tbl.GetRowCount(); got != len(wantText) {
		t.Fatalf("table row count = %d, want %d", got, len(wantText))
	}
	for r, want := range wantText {
		if got := tbl.GetCell(r, 0).Text; got != want {
			t.Errorf("table row %d text = %q, want %q (header shows the display name)", r, got, want)
		}
	}

	// The duplicate gpt-5.5 id maps to two distinct selectable model rows (flat indices
	// 0 and 1), one under each provider header.
	for i := range cat.rows {
		tr := modelTableRow(tbl, i)
		if tr < 0 {
			t.Fatalf("no table row references data index %d", i)
		}
		if tbl.GetCell(tr, 0).NotSelectable {
			t.Errorf("model row for data index %d is non-selectable", i)
		}
	}

	// Confirming the openai-chatgpt row passes the stable provider id, not "OpenAI ChatGPT".
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	a.confirmModelSelection(cat.rows[1], "medium")
	if applier.gotProvider != "openai-chatgpt" {
		t.Errorf("Apply got provider %q, want the stable id openai-chatgpt (not the display name)", applier.gotProvider)
	}
	if got := a.TranscriptText(); !strings.Contains(got, "openai-chatgpt") || strings.Contains(got, "OpenAI ChatGPT") {
		t.Errorf("confirmation transcript = %q, want it to carry the stable id openai-chatgpt, not the display name", got)
	}
}

func TestModelPicker_InitialHighlightLandsOnActiveSelection(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()

	// Active selection is openai/gpt-5 (data index 0) — table row 1, just past the
	// openai header at row 0. openModelPicker converts that flat index to its table
	// row via the same modelRowIndex lookup buildModelPicker is fed here.
	_, tbl := a.buildModelPicker(cat.rows, modelRowIndex(cat.rows, "openai", "gpt-5"), "medium", cat.target, cat)
	row, _ := tbl.GetSelection()
	if want := modelTableRow(tbl, 0); row != want {
		t.Errorf("initial selection row = %d, want %d (gpt-5 row, not the header)", row, want)
	}
	if tbl.GetCell(row, 0).NotSelectable {
		t.Errorf("initial selection landed on a non-selectable header row %d", row)
	}
}

func TestModelPicker_OpenPathHighlightsActiveSelection(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	cat.provider, cat.modelID, cat.effort = "anthropic", "claude-x", "default"
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}})

	a.openModelPicker()

	sess := a.modelPicker
	if sess == nil || sess.table == nil {
		t.Fatal("openModelPicker did not create a live picker session")
	}
	row, _ := sess.table.GetSelection()
	di := sess.dataIndex(row)
	if di < 0 {
		t.Fatalf("initial highlight at table row %d maps to no model (dataByRow = %v)", row, sess.dataByRow)
	}
	if got := sess.rows[di]; got.Provider != "anthropic" || got.ModelID != "claude-x" {
		t.Errorf("initial highlight = %s/%s, want the active anthropic/claude-x", got.Provider, got.ModelID)
	}
	if flat := modelRowIndex(cat.rows, "anthropic", "claude-x"); row == flat {
		t.Errorf("initial highlight row = %d, the flat index; the headers must shift it", row)
	}
}

func TestModelPicker_InitialHighlightFallsBackToFirstModelRow(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	// No active selection and an out-of-range initialRow both fall back to the first
	// model row (table row 1), never the header at row 0.
	_, tbl := a.buildModelPicker(cat.rows, -1, "", cat.target, cat)
	row, _ := tbl.GetSelection()
	if want := modelTableRow(tbl, 0); row != want {
		t.Errorf("fallback selection row = %d, want %d (first model row)", row, want)
	}
}

func TestModelPicker_InitialEffortPreservedWhenSupported(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	// gpt-5 (row 0) supports medium, so the in-memory medium effort is preserved.
	a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	if a.modelPicker.effort != "medium" {
		t.Errorf("initial picker effort = %q, want %q (preserved from in-memory)", a.modelPicker.effort, "medium")
	}
	if strings.Join(a.modelPicker.supported, ",") != "minimal,low,medium,high" {
		t.Errorf("supported set = %v, want gpt-5's full set", a.modelPicker.supported)
	}
	// The inline control shows the selection in the accent bar (effort source).
	if got := a.modelPicker.effortView.GetText(false); !strings.Contains(got, "medium") {
		t.Errorf("inline effort render = %q, want it to show medium", got)
	}
}

func TestModelPicker_EffortRefreshesPerHighlightedModel(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	// Selection is by table row, resolved through the data-index mapping.
	tbl.Select(modelTableRow(tbl, 1), 0)
	if a.modelPicker.effort != "low" {
		t.Errorf("effort after move to gpt-5-mini = %q, want %q (fallback default)", a.modelPicker.effort, "low")
	}
	if strings.Join(a.modelPicker.supported, ",") != "low,high" {
		t.Errorf("supported set = %v, want [low high]", a.modelPicker.supported)
	}

	// Move to claude-x (data index 2, under the anthropic header): {default}-only, so
	// a single inert `default` value.
	tbl.Select(modelTableRow(tbl, 2), 0)
	if strings.Join(a.modelPicker.supported, ",") != "default" {
		t.Fatalf("supported set = %v, want [default] ({default}-only model)", a.modelPicker.supported)
	}
	if a.modelPicker.effort != "default" {
		t.Errorf("effort for {default}-only model = %q, want %q", a.modelPicker.effort, "default")
	}
}

func TestModelPicker_RefreshSelectsFirstAdvertisedEffort(t *testing.T) {
	a := New(nil)
	cat := &providerModelCatalogFake{
		provider: "openai",
		modelID:  "gpt-5-mini",
		effort:   "low",
		selected: true,
		rows: []ProviderModel{
			{Provider: "openai", ModelID: "gpt-5-mini"},
			{Provider: "openai", ModelID: "gpt-5"},
		},
		supported: map[string][]string{
			"openai/gpt-5-mini": {"low", "high"},
			"openai/gpt-5":      {"high", "medium", "minimal"},
		},
	}
	_, tbl := a.buildModelPicker(cat.rows, 0, "low", cat.target, cat)

	tbl.Select(modelTableRow(tbl, 1), 0)
	if a.modelPicker.effort != "high" {
		t.Errorf("effort after move to gpt-5 = %q, want %q (first advertised)", a.modelPicker.effort, "high")
	}
}

func TestModelPicker_NoCapabilityModelSelectsNoReasoning(t *testing.T) {
	a := New(nil)
	cat := &providerModelCatalogFake{
		provider: "openai",
		modelID:  "gpt-5",
		effort:   "medium",
		selected: true,
		rows: []ProviderModel{
			{Provider: "openai", ModelID: "gpt-5"},
			{Provider: "openai", ModelID: "gpt-5-quiet"},
		},
		supported: map[string][]string{
			"openai/gpt-5":       {"medium", "high"},
			"openai/gpt-5-quiet": {effortNoReasoning},
		},
	}
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	tbl.Select(modelTableRow(tbl, 1), 0)
	if a.modelPicker.effort != effortNoReasoning {
		t.Errorf("effort for a no-capability model = %q, want %q", a.modelPicker.effort, effortNoReasoning)
	}
}

func TestModelPicker_RetainsNoReasoningAcrossHighlight(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, effortNoReasoning, cat.target, cat)

	if a.modelPicker.effort != effortNoReasoning {
		t.Fatalf("initial picker effort = %q, want %q (sentinel retained)", a.modelPicker.effort, effortNoReasoning)
	}
	tbl.Select(modelTableRow(tbl, 1), 0)
	if a.modelPicker.effort != effortNoReasoning {
		t.Errorf("effort after move to gpt-5-mini = %q, want %q (sentinel retained)", a.modelPicker.effort, effortNoReasoning)
	}
}

func TestModelPicker_LiteralDefaultIsAProviderToken(t *testing.T) {
	a := New(nil)
	cat := &providerModelCatalogFake{
		provider: "openai",
		modelID:  "gpt-5",
		effort:   "default",
		selected: true,
		rows: []ProviderModel{
			{Provider: "openai", ModelID: "gpt-5"},
			{Provider: "openai", ModelID: "gpt-5-mini"},
			{Provider: "openai", ModelID: "gpt-5-nano"},
		},
		supported: map[string][]string{
			"openai/gpt-5":      {"low", "default", "high"},
			"openai/gpt-5-mini": {"default", "xhigh"},
			"openai/gpt-5-nano": {"low", "high"},
		},
	}
	_, tbl := a.buildModelPicker(cat.rows, 0, "default", cat.target, cat)

	if a.modelPicker.effort != "default" {
		t.Fatalf("initial picker effort = %q, want %q (advertised token retained)", a.modelPicker.effort, "default")
	}
	tbl.Select(modelTableRow(tbl, 2), 0)
	if a.modelPicker.effort != "low" {
		t.Fatalf("effort on gpt-5-nano = %q, want %q (unadvertised default dropped)", a.modelPicker.effort, "low")
	}
	tbl.Select(modelTableRow(tbl, 1), 0)
	if a.modelPicker.effort != "default" {
		t.Errorf("effort on gpt-5-mini = %q, want %q (first advertised)", a.modelPicker.effort, "default")
	}
}

func TestModelPicker_AdvertisedPriorEffortRetained(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	a.buildModelPicker(cat.rows, 0, "high", cat.target, cat)

	if a.modelPicker.effort != "high" {
		t.Errorf("initial picker effort = %q, want %q (advertised prior kept, no fallback)", a.modelPicker.effort, "high")
	}
}

func TestModelPicker_OpensWithoutInMemorySelection(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	cat.selected = false // no model chosen yet — the picker is how the first is chosen
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}})

	a.openModelPicker()

	if !a.modelPickerOpen || !a.pages.HasPage(modelPickerPage) {
		t.Fatal("model picker did not open without an in-memory selection")
	}
	if a.modelPicker.effort != "minimal" {
		t.Errorf("seeded effort = %q, want %q (first advertised)", a.modelPicker.effort, "minimal")
	}
}

func TestModelPicker_NoOpWhileOverlayOpen(t *testing.T) {
	a := New(nil)
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: applier})

	a.statusOpen = true // another overlay holds the screen
	a.openModelPicker()

	if a.modelPickerOpen {
		t.Error("modelPickerOpen = true; CTRL-M must be a no-op while another overlay is open")
	}
	if a.pages.HasPage(modelPickerPage) {
		t.Error("model picker page mounted while another overlay is open")
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times, want 0", applier.calls)
	}
}

func TestModelPicker_UnwiredCtrlMIsInert(t *testing.T) {
	a := New(nil) // no ModelPickerDeps wired
	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlM, 0, tcell.ModNone)); ev != nil {
		t.Errorf("handleGlobalKey returned %v for CTRL-M, want nil (consumed)", ev)
	}
	if a.modelPickerOpen {
		t.Error("picker opened with no provider-aware surface wired")
	}
}

func TestModelPicker_ConfirmAppliesProviderModelEffort(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})

	a.confirmModelSelection(ProviderModel{Provider: "anthropic", ModelID: "claude-x"}, "default")

	if applier.calls != 1 {
		t.Fatalf("Apply calls = %d, want 1 (every selection persists; no session-only path)", applier.calls)
	}
	if applier.gotProvider != "anthropic" || applier.gotID != "claude-x" || applier.gotEffort != "default" {
		t.Errorf("Apply got (%q,%q,%q), want (anthropic,claude-x,default)", applier.gotProvider, applier.gotID, applier.gotEffort)
	}
	// A successful confirm appends a permanent confirmation line to the transcript
	// (the intentional move from the transient notice into the session).
	got := a.TranscriptText()
	if !strings.Contains(got, "claude-x") || !strings.Contains(got, "default") {
		t.Errorf("transcript = %q, want a confirmation line naming the model and effort", got)
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want the confirmation on the transcript, not the notice", a.transcript.notice)
	}
}

func TestModelPicker_ConfirmEffortMatchesPickerSelection(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})

	a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)
	// Step the inline effort off the in-memory medium (index 2) to high (index 3).
	// The confirm must use the picker UI's effort, not the live in-memory one.
	a.stepModelEffort(1)
	if a.modelPicker.effort != "high" {
		t.Fatalf("picker effort after step = %q, want high", a.modelPicker.effort)
	}
	a.confirmModelSelection(cat.rows[0], a.modelPicker.effort)

	if applier.gotEffort != "high" {
		t.Errorf("confirmed effort = %q, want %q (picker UI selection, not in-memory medium)", applier.gotEffort, "high")
	}
}

func TestModelPicker_StepEffortClampsAndDefaultOnly(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	// gpt-5 supports {minimal, low, medium, high}; medium is index 2. Stepping right
	// twice reaches high (index 3) and clamps there (no wraparound).
	a.stepModelEffort(1)
	a.stepModelEffort(1)
	if a.modelPicker.effort != "high" {
		t.Errorf("effort after two right steps = %q, want high (clamped at end)", a.modelPicker.effort)
	}
	// Stepping left past the start clamps at minimal.
	for i := 0; i < 5; i++ {
		a.stepModelEffort(-1)
	}
	if a.modelPicker.effort != "minimal" {
		t.Errorf("effort after stepping left past start = %q, want minimal (clamped at start)", a.modelPicker.effort)
	}

	// On the {default}-only model (claude-x, data index 2), ←/→ is a no-op.
	tbl.Select(modelTableRow(tbl, 2), 0)
	a.stepModelEffort(1)
	a.stepModelEffort(-1)
	if a.modelPicker.effort != "default" {
		t.Errorf("effort on {default}-only model after stepping = %q, want default (inert)", a.modelPicker.effort)
	}
}

func TestModelPicker_EmptyRowsSafe(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	cat.rows = nil
	// Building with no rows must not panic: no headers or rows are rendered, no
	// effort is seeded, and the inline control renders the empty-set dash.
	_, tbl := a.buildModelPicker(nil, 0, "", cat.target, cat)

	if tbl.GetRowCount() != 0 {
		t.Errorf("table row count = %d, want 0 (no headers or model rows)", tbl.GetRowCount())
	}
	if len(a.modelPicker.dataByRow) != 0 {
		t.Errorf("dataByRow = %v, want empty for no rows", a.modelPicker.dataByRow)
	}
	if a.modelPicker.effort != "" || a.modelPicker.supported != nil {
		t.Errorf("seeded effort/supported = (%q,%v), want empty for no rows", a.modelPicker.effort, a.modelPicker.supported)
	}
	if got := a.modelPicker.effortView.GetText(false); !strings.Contains(got, "—") {
		t.Errorf("inline effort render = %q, want the empty-set dash", got)
	}
	// ←/→ stepping is a safe no-op with no rows.
	a.stepModelEffort(1)
	a.stepModelEffort(-1)
}

// isYellow reports whether c is the fixed yellow accent the theme cleanup removed.
// It compares by RGB hex (yellow = #FFFF00) rather than the removed tcell yellow
// symbol so it catches the palette color and an equivalent true-color value alike,
// and so the task's symbol-cleanup check over internal/tui stays clean.
func isYellow(c tcell.Color) bool { return c.Hex() == 0xFFFF00 }

func TestRenderInlineEffort(t *testing.T) {
	// Stepper, middle position: only the selected effort is shown (in reverse video),
	// flanked by both arrows; the unselected efforts are NOT rendered (so a narrow box
	// cannot clip the selection off-screen).
	got := renderInlineEffort([]string{"minimal", "low", "medium", "high"}, "medium")
	if !strings.Contains(got, "◂") || !strings.Contains(got, "▸") {
		t.Errorf("mid-stepper render = %q, want both ◂ ▸ arrows", got)
	}
	if !strings.Contains(got, "[::r] medium [::-]") {
		t.Errorf("mid-stepper render = %q, want the selected effort in reverse-video tags", got)
	}
	if strings.Contains(got, "minimal") || strings.Contains(got, "low") || strings.Contains(got, "high") {
		t.Errorf("mid-stepper render = %q, want only the selected effort shown", got)
	}
	if strings.Contains(got, "[yellow") || strings.Contains(got, "[black:#") {
		t.Errorf("mid-stepper render = %q, want no fixed-color accent tag", got)
	}
	// First position: no left arrow (nothing lower), right arrow present.
	if got := renderInlineEffort([]string{"minimal", "low", "high"}, "minimal"); strings.Contains(got, "◂") || !strings.Contains(got, "▸") {
		t.Errorf("first-stepper render = %q, want no ◂ and a ▸", got)
	}
	// Last position: left arrow present, no right arrow (nothing higher).
	if got := renderInlineEffort([]string{"minimal", "low", "high"}, "high"); !strings.Contains(got, "◂") || strings.Contains(got, "▸") {
		t.Errorf("last-stepper render = %q, want a ◂ and no ▸", got)
	}
	// {default}-only: a single inert value, no arrows.
	if got := renderInlineEffort([]string{"default"}, "default"); got != "effort: default" {
		t.Errorf("{default}-only render = %q, want %q (no arrows)", got, "effort: default")
	}
	// Empty set (guarded len(rows)==0 case): a dash, no panic.
	if got := renderInlineEffort(nil, ""); got != "effort: —" {
		t.Errorf("empty render = %q, want %q", got, "effort: —")
	}
}

// TestModelPicker_ProviderHeaderBoldDefaultColor pins step 3: provider header rows
// render bold in the terminal-default color, never the removed yellow accent, so
// they still read as group labels without a fixed color.
func TestModelPicker_ProviderHeaderBoldDefaultColor(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	for _, hdr := range []struct {
		row  int
		text string
	}{{0, "openai"}, {4, "anthropic"}} {
		cell := tbl.GetCell(hdr.row, 0)
		if cell.Text != hdr.text {
			t.Fatalf("row %d text = %q, want the %q header", hdr.row, cell.Text, hdr.text)
		}
		fg, _, attr := cell.Style.Decompose()
		if attr&tcell.AttrBold == 0 {
			t.Errorf("%q header style = %v, want bold", hdr.text, cell.Style)
		}
		if isYellow(fg) {
			t.Errorf("%q header fg = yellow (#FFFF00), want the default color", hdr.text)
		}
	}
}

// TestModelPicker_CompactCenteredSizing pins step 6: the picker body is laid out as
// a centered box ~50% wide / ~60% tall — not full screen — by centeredModal, with
// near-symmetric margins on both axes.
func TestModelPicker_CompactCenteredSizing(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	body, _ := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	const w, h = 100, 40
	drawPrimitive(t, centeredModal(body), w, h)
	x, y, bw, bh := body.GetRect()

	if bw < w*2/5 || bw > w*3/5 {
		t.Errorf("centered body width = %d, want ~%d (≈50%% of %d)", bw, w/2, w)
	}
	if bh < h*11/20 || bh > h*13/20 {
		t.Errorf("centered body height = %d, want ~%d (≈60%% of %d)", bh, h*3/5, h)
	}
	if bw >= w || bh >= h {
		t.Errorf("body %dx%d fills the %dx%d screen, want a compact box", bw, bh, w, h)
	}
	absDiff := func(a, b int) int {
		if a < b {
			return b - a
		}
		return a - b
	}
	if d := absDiff(x, w-(x+bw)); d > 1 {
		t.Errorf("body not horizontally centered: left=%d right=%d (diff %d)", x, w-(x+bw), d)
	}
	if d := absDiff(y, h-(y+bh)); d > 1 {
		t.Errorf("body not vertically centered: top=%d bottom=%d (diff %d)", y, h-(y+bh), d)
	}
}

// TestModelPicker_SelectedRowRendersReverseVideo pins step 2 for the model table:
// the highlighted model row renders with reverse video (inverting the terminal's
// own fg/bg) and no cell anywhere uses the removed yellow accent.
func TestModelPicker_SelectedRowRendersReverseVideo(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	// Highlight openai/gpt-5 (the active selection).
	body, _ := a.buildModelPicker(cat.rows, modelRowIndex(cat.rows, "openai", "gpt-5"), "medium", cat.target, cat)

	screen := drawPrimitive(t, centeredModal(body), 100, 40)
	reverseByRow := findReverseVideoRows(t, screen)

	found := false
	for _, text := range reverseByRow {
		if strings.Contains(text, "gpt-5") {
			found = true
		}
	}
	if !found {
		t.Errorf("no reverse-video row carries the selected model gpt-5; reverse rows = %v", reverseByRow)
	}
}

// TestModelPicker_ConfirmClearsStaleNotice pins the clear-on-model-change for
// the CTRL-M/picker confirm: a successful apply clears any stale pinned notice (so
// it cannot linger below the confirmation), while the committed confirmation line is
// preserved. The apply-error path is the inverse and is covered by
// TestModelPicker_ConfirmApplyErrorSurfaced (it keeps the surfaced error notice).
func TestModelPicker_ConfirmClearsStaleNotice(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}})

	// A stale pinned notice (e.g. a prior /model validation error) sits below the
	// transcript when the user changes the model through the picker.
	a.Notice("unsupported model gpt-9; supported models: gpt-5")
	a.confirmModelSelection(ProviderModel{Provider: "anthropic", ModelID: "claude-x"}, "default")

	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want it cleared on a successful model change", a.transcript.notice)
	}
	// The committed confirmation line is preserved (the clear touches only the notice).
	if got := a.TranscriptText(); !strings.Contains(got, "claude-x") {
		t.Errorf("transcript = %q, want the confirmation line retained after the clear", got)
	}
}

func TestModelPicker_ConfirmApplyErrorSurfaced(t *testing.T) {
	a := New(nil)
	wantErr := errors.New("append model_changed: boom")
	applier := &providerModelApplierFake{err: wantErr}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: applier})

	a.confirmModelSelection(ProviderModel{Provider: "openai", ModelID: "gpt-5"}, "medium")

	// Apply errors stay on the transient notice surface (not the transcript).
	if a.transcript.notice != wantErr.Error() {
		t.Errorf("notice = %q, want the surfaced apply error %q", a.transcript.notice, wantErr.Error())
	}
	if strings.Contains(a.TranscriptText(), "model set to") {
		t.Errorf("transcript = %q, want no confirmation line on apply error", a.TranscriptText())
	}
}

func TestModelPicker_ConfirmEmitsNoCrossModeMarkerNotice(t *testing.T) {
	a := New(nil)
	applier := &providerModelApplierFake{result: ModelApplyResult{MarkerCreated: true, MarkerPath: "/work/proj/.codemeld/settings.yaml"}}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: applier})

	a.confirmModelSelection(ProviderModel{Provider: "openai", ModelID: "gpt-5"}, "high")

	got := a.TranscriptText()
	if !strings.Contains(got, "• model set to openai — gpt-5 (effort: high)") {
		t.Errorf("transcript = %q, want the confirmation line", got)
	}
	if strings.Contains(got, "/work/proj/.codemeld/settings.yaml") || strings.Contains(got, "project root") {
		t.Errorf("transcript = %q, want no project-root-marker line", got)
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want no project-root-marker notice", a.transcript.notice)
	}
}

// Non-banner App.Append output must be escaped so tag-like text in a confirmation
// line renders literally rather than being swallowed as a tview style
// tag now that the transcript has dynamic colors enabled. Removing the
// tview.Escape from the ordinary App.Append path makes this fail: the "[red]"
// would be parsed as a (rejected) color tag and vanish from the visible text.
func TestModelPicker_ConfirmEscapesTagLikeText(t *testing.T) {
	a := New(nil)
	applier := &providerModelApplierFake{result: ModelApplyResult{MarkerCreated: true, MarkerPath: "/work/[red]proj/.codemeld/settings.yaml"}}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: applier})

	a.confirmModelSelection(ProviderModel{Provider: "[red]openai", ModelID: "gpt-5"}, "high")

	got := a.TranscriptText()
	if !strings.Contains(got, "[red]openai") {
		t.Errorf("transcript = %q, want the literal [red]openai (tag syntax escaped, not parsed)", got)
	}
	if strings.Contains(got, "/work/[red]proj/.codemeld/settings.yaml") {
		t.Errorf("transcript = %q, want no marker path", got)
	}
}

func TestRenderModelSettingsInfo(t *testing.T) {
	cases := []struct {
		name       string
		target     ModelSettingsTarget
		wantPath   bool
		wantLaunch bool
		wantHeight int
	}{
		{
			name:       "plain target",
			target:     ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.local.yaml", LaunchDir: "/p", ProjectRoot: "/p"},
			wantPath:   true,
			wantHeight: 1,
		},
		{
			name:       "launch dir differs from project root",
			target:     ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.local.yaml", LaunchDir: "/p/sub", ProjectRoot: "/p"},
			wantPath:   true,
			wantLaunch: true,
			wantHeight: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderModelSettingsInfo(tc.target)
			if tc.wantPath && !strings.Contains(got, tc.target.SettingsPath) {
				t.Errorf("info = %q, want it to show the settings path", got)
			}
			if gotLaunch := strings.Contains(got, "launch dir:"); gotLaunch != tc.wantLaunch {
				t.Errorf("info launch-dir line = %v, want %v (info=%q)", gotLaunch, tc.wantLaunch, got)
			}
			if strings.Contains(got, "mark the launch directory") || strings.Contains(got, "saving here will create") {
				t.Errorf("info = %q, want no forward-looking marker line", got)
			}
			if h := modelInfoHeight(got); h != tc.wantHeight {
				t.Errorf("modelInfoHeight = %d, want %d (info=%q)", h, tc.wantHeight, got)
			}
		})
	}
}

func TestModelPicker_DismissEmitsNothing(t *testing.T) {
	a := New(nil)
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: applier})

	a.openModelPicker()
	if !a.modelPickerOpen {
		t.Fatal("picker failed to open")
	}
	a.dismissModelPicker()

	if a.modelPickerOpen || a.pages.HasPage(modelPickerPage) {
		t.Error("picker still open after dismissal")
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times on ESC dismissal, want 0", applier.calls)
	}
	if a.transcript.notice != "" {
		t.Errorf("notice = %q, want none on dismissal", a.transcript.notice)
	}
	if a.TranscriptText() != "" {
		t.Errorf("transcript = %q, want none on dismissal", a.TranscriptText())
	}
}

func TestFilterModelRows(t *testing.T) {
	rows := []ProviderModel{
		{Provider: "openai", DisplayName: "OpenAI Platform", ModelID: "gpt-5"},
		{Provider: "openai", DisplayName: "OpenAI Platform", ModelID: "ada-gpt"},
		{Provider: "anthropic", DisplayName: "Anthropic", ModelID: "claude-x"},
		{Provider: "openai", DisplayName: "OpenAI Platform", ModelID: "gpt-5.6-terra"},
		// "sol" is an ordered subsequence of this id (s-onnet, l-arge) but never contiguous,
		// so it fails only if the loose matcher comes back.
		{Provider: "anthropic", DisplayName: "Anthropic", ModelID: "claude-sonnet-large"},
	}
	cases := []struct {
		name  string
		query string
		want  []int
	}{
		{"empty query sorts model ids within each provider group", "", []int{1, 0, 3, 4, 2}},
		{"contiguous term matches model id", "gpt", []int{0, 3, 1}},
		{"case-insensitive", "GPT-5", []int{0, 3}},
		{"stable provider id keeps that provider's models", "anthropic", []int{4, 2}},
		{"provider display label matches its models", "platform", []int{1, 0, 3}},
		{"unsorted filtered group orders by model id", "openai", []int{1, 0, 3}},
		{"multi-term across different fields", "GPT 5.6 terra", []int{3}},
		{"first-term model-id prefix ranks ahead", "gpt-5", []int{0, 3}},
		{"rejects loose subsequence-only match", "sol", []int{}},
		{"contiguous substring of the same id still matches", "sonnet", []int{4}},
		{"no match", "zzz", []int{}},
		{"whitespace-only falls back to empty query", "  ", []int{1, 0, 3, 4, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterModelRows(rows, tc.query)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("filterModelRows(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

// TestModelPicker_FilterHidesEmptyProviderGroups pins that a filter rebuild renders a
// provider header and its spacer only for groups with at least one visible model, and
// that a filtered model cell still maps through dataByRow to its original full-rows
// ProviderModel.
func TestModelPicker_FilterHidesEmptyProviderGroups(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	// Narrow to "claude": only the anthropic group survives, so the openai header and
	// the inter-group spacer must not render — just the anthropic header + claude-x.
	a.onModelFilterChanged("claude")
	wantText := []string{"anthropic", "claude-x"}
	if got := tbl.GetRowCount(); got != len(wantText) {
		t.Fatalf("filtered row count = %d, want %d (no openai header/spacer)", got, len(wantText))
	}
	for r, want := range wantText {
		if got := tbl.GetCell(r, 0).Text; got != want {
			t.Errorf("filtered row %d text = %q, want %q", r, got, want)
		}
	}
	// The visible claude-x cell maps back to its original full-rows index (2), not its
	// position in the filtered set.
	tr := modelTableRow(tbl, 2)
	if tr < 0 {
		t.Fatalf("no visible row references the original claude-x index 2")
	}
	if di := a.modelPicker.dataIndex(tr); di != 2 {
		t.Errorf("dataIndex(%d) = %d, want 2 (original full-rows index)", tr, di)
	}
}

// TestModelPicker_FilteredConfirmResolvesOriginalModel pins that confirming the
// highlighted row after filtering applies the original stable provider/model id —
// never a display label or a filtered-set position.
func TestModelPicker_FilteredConfirmResolvesOriginalModel(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	a.onModelFilterChanged("claude")
	a.confirmHighlightedModel()

	if applier.calls != 1 || applier.gotProvider != "anthropic" || applier.gotID != "claude-x" {
		t.Errorf("Apply calls=%d got (%q,%q), want 1 call with (anthropic,claude-x)", applier.calls, applier.gotProvider, applier.gotID)
	}
}

// TestModelPicker_EmptyFilterResultSafe pins the no-match state: no rows, no stale
// effort, the inline dash, Enter/←/→ as no-ops, and a clean return to normal state
// once the query matches again.
func TestModelPicker_EmptyFilterResultSafe(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	a.onModelFilterChanged("zzzz") // matches nothing
	if tbl.GetRowCount() != 0 {
		t.Errorf("filtered row count = %d, want 0 (no headers or model rows)", tbl.GetRowCount())
	}
	if a.modelPicker.effort != "" || a.modelPicker.supported != nil {
		t.Errorf("effort/supported = (%q,%v), want empty for no matches", a.modelPicker.effort, a.modelPicker.supported)
	}
	if got := a.modelPicker.effortView.GetText(false); !strings.Contains(got, "—") {
		t.Errorf("inline effort render = %q, want the empty-set dash", got)
	}
	// Enter applies nothing; ←/→ are safe no-ops.
	a.confirmHighlightedModel()
	a.stepModelEffort(1)
	a.stepModelEffort(-1)
	if applier.calls != 0 {
		t.Errorf("Apply calls = %d on empty filter, want 0", applier.calls)
	}

	// Recovery: a matching query restores model rows and a real effort, and confirm
	// applies again.
	a.onModelFilterChanged("gpt-5")
	if tbl.GetRowCount() == 0 {
		t.Fatal("rows did not return when the query matched again")
	}
	if a.modelPicker.effort == "" {
		t.Error("effort still empty after matches reappeared, want a seeded effort")
	}
	a.confirmHighlightedModel()
	if applier.calls != 1 || applier.gotID != "gpt-5" {
		t.Errorf("after recovery Apply calls=%d gotID=%q, want 1 call with gpt-5", applier.calls, applier.gotID)
	}
}

// TestModelPicker_EffortStepsAfterFilter pins that the inline effort control tracks
// the highlighted model after a filter rebuild: filtering to gpt-5-mini drops the
// unsupported medium to that model's default, and ←/→ then step within its set.
func TestModelPicker_EffortStepsAfterFilter(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	a.onModelFilterChanged("mini") // narrows to gpt-5-mini, supports {low, high}
	if strings.Join(a.modelPicker.supported, ",") != "low,high" {
		t.Fatalf("supported after filter = %v, want [low high]", a.modelPicker.supported)
	}
	if a.modelPicker.effort != "low" {
		t.Errorf("effort after filter = %q, want low (medium unsupported → default)", a.modelPicker.effort)
	}
	a.stepModelEffort(1)
	if a.modelPicker.effort != "high" {
		t.Errorf("effort after right step = %q, want high", a.modelPicker.effort)
	}
}

func waitPickerPage(t *testing.T, a *App, want bool) {
	t.Helper()
	what := "model picker page removal"
	if want {
		what = "model picker page attach"
	}
	waitOnLoop(t, a, what, func() bool { return a.pages.HasPage(modelPickerPage) == want })
}

// TestModelPicker_FilterLiveKeyboardPath drives the live filter over a simulation
// screen: CTRL-M opens the picker (the filter field holds focus), typing "claude"
// narrows the list to the single anthropic model while focus stays on the field, and
// Enter confirms the highlighted filtered model — proving the typed query reached the
// field's change hook and the keyboard path resolves the filtered selection.
func TestModelPicker_FilterLiveKeyboardPath(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})

	h := newAppHarnessFor(t, a, 80, 25)

	h.screen.InjectKey(tcell.KeyCtrlM, 0, tcell.ModNone)
	waitPickerPage(t, a, true)
	// Type "claude" into the focused filter field one rune at a time.
	for _, ch := range "claude" {
		h.screen.InjectKey(tcell.KeyRune, ch, tcell.ModNone)
	}
	// Enter confirms the only filtered model (anthropic/claude-x). If the query had not
	// reached the field, the highlight would still be the active gpt-5.
	h.screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPickerPage(t, a, false)

	h.stop()
	if applier.calls != 1 || applier.gotProvider != "anthropic" || applier.gotID != "claude-x" {
		t.Errorf("after live filter: Apply calls=%d got (%q,%q), want 1 call with (anthropic,claude-x)",
			applier.calls, applier.gotProvider, applier.gotID)
	}
}

// TestModelPicker_CtrlMOpenArrowEnterApplyEscDismiss drives the live key bindings
// over a simulation screen: CTRL-M opens the picker, ESC dismisses it with no
// apply; a re-opened picker — Right to step the inline effort to "high", Enter —
// applies the highlighted model with the picker-selected effort; and a third open —
// Down twice to cross the anthropic header into claude-x, Enter — proves keyboard
// navigation skips the non-selectable provider header and Enter resolves the correct
// post-header {Provider, ModelID}. It exercises the real app-level CTRL-M capture and
// the model table's Down/Left/Right/Enter/ESC handling (the non-slash apply path).
func TestModelPicker_CtrlMOpenArrowEnterApplyEscDismiss(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})

	h := newAppHarnessFor(t, a, 80, 25)

	// CTRL-M opens the picker, then ESC dismisses it with no change.
	h.screen.InjectKey(tcell.KeyCtrlM, 0, tcell.ModNone)
	waitPickerPage(t, a, true)
	h.screen.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	waitPickerPage(t, a, false)
	if applier.calls != 0 {
		a.app.Stop()
		t.Fatalf("Apply called %d times after ESC dismissal, want 0", applier.calls)
	}

	// Re-open on gpt-5 (effort medium); Right steps the inline effort to "high"
	// (medium index 2 → high index 3), then Enter applies.
	h.screen.InjectKey(tcell.KeyCtrlM, 0, tcell.ModNone)
	waitPickerPage(t, a, true)
	h.screen.InjectKey(tcell.KeyRight, 0, tcell.ModNone)
	h.screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPickerPage(t, a, false)

	if applier.calls != 1 || applier.gotProvider != "openai" || applier.gotID != "gpt-5" || applier.gotEffort != "high" {
		a.app.Stop()
		t.Fatalf("Apply calls=%d got (%q,%q,%q), want 1 call with (openai,gpt-5,high)",
			applier.calls, applier.gotProvider, applier.gotID, applier.gotEffort)
	}

	// Re-open on gpt-5 (table row 1); Down to gpt-5-mini (row 2), Down again must
	// skip the non-selectable spacer (row 3) and anthropic header (row 4) and land on
	// claude-x (row 5), a {default}-only model. Enter applies {anthropic, claude-x}.
	h.screen.InjectKey(tcell.KeyCtrlM, 0, tcell.ModNone)
	waitPickerPage(t, a, true)
	h.screen.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
	h.screen.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
	h.screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	waitPickerPage(t, a, false)

	h.stop()
	if applier.calls != 2 || applier.gotProvider != "anthropic" || applier.gotID != "claude-x" || applier.gotEffort != "default" {
		t.Errorf("after header-skip nav: Apply calls=%d got (%q,%q,%q), want 2 calls, last (anthropic,claude-x,default)",
			applier.calls, applier.gotProvider, applier.gotID, applier.gotEffort)
	}
}

func unsortedTwoProviderCatalog() *providerModelCatalogFake {
	return &providerModelCatalogFake{
		rows: []ProviderModel{
			{Provider: "openai", ModelID: "gpt-c"},
			{Provider: "openai", ModelID: "gpt-a"},
			{Provider: "openai", ModelID: "gpt-b"},
			{Provider: "anthropic", ModelID: "claude-z"},
			{Provider: "anthropic", ModelID: "claude-a"},
		},
		target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml", LaunchDir: "/p", ProjectRoot: "/p"},
	}
}

func TestModelPicker_SortsModelIDsWithinProviderGroup(t *testing.T) {
	a := New(nil)
	cat := unsortedTwoProviderCatalog()
	_, tbl := a.buildModelPicker(cat.rows, 0, "", cat.target, cat)

	want := []string{"openai", "gpt-a", "gpt-b", "gpt-c", "", "anthropic", "claude-a", "claude-z"}
	if got := tbl.GetRowCount(); got != len(want) {
		t.Fatalf("row count = %d, want %d", got, len(want))
	}
	for r, w := range want {
		if got := tbl.GetCell(r, 0).Text; got != w {
			t.Errorf("row %d text = %q, want %q (models sorted within group, groups in catalog order)", r, got, w)
		}
	}
	if di := a.modelPicker.dataIndex(1); di != 1 {
		t.Errorf("row 1 (gpt-a) dataIndex = %d, want 1 (stable catalog source index)", di)
	}
}

func TestModelPicker_ReservesBlankRowBeforeEffort(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	body, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)
	drawPrimitive(t, centeredModal(body), 100, 40)

	_, tableY, _, tableHeight := tbl.GetRect()
	_, effortY, _, _ := a.modelPicker.effortView.GetRect()
	if want := tableY + tableHeight + 1; effortY != want {
		t.Errorf("effort row = %d, want %d (one blank row after model table)", effortY, want)
	}
}

type pickerKeyRoute struct {
	name string
	send func(*tcell.EventKey) *tcell.EventKey
}

func pickerKeyRoutes(a *App) []pickerKeyRoute {
	return []pickerKeyRoute{
		{"field", a.modelPickerFieldKeys},
		{"table", a.modelPickerKeys()},
	}
}

func TestModelPicker_TableRouteLeavesNavigationAndEnterToTview(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	a.openModelPicker()

	tableKeys := a.modelPickerKeys()
	for _, tc := range []struct {
		name string
		key  tcell.Key
	}{
		{"Up", tcell.KeyUp},
		{"Down", tcell.KeyDown},
		{"Enter", tcell.KeyEnter},
	} {
		ev := tcell.NewEventKey(tc.key, 0, tcell.ModNone)
		if got := tableKeys(ev); got != ev {
			t.Errorf("table route consumed %s (returned %v), want it passed through to tview", tc.name, got)
		}
		if got := a.modelPickerFieldKeys(ev); got != nil {
			t.Errorf("field route returned %v for %s, want it handled by the field", got, tc.name)
		}
	}
	if applier.calls != 1 {
		t.Errorf("Apply calls = %d, want 1 (only the field route's Enter confirms; the table's goes to tview)", applier.calls)
	}
}

func TestModelPicker_HomeEndSelectFirstLastVisibleModel(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	firstRow := modelTableRow(tbl, 0)
	lastRow := modelTableRow(tbl, 2)

	home := tcell.NewEventKey(tcell.KeyHome, 0, tcell.ModNone)
	end := tcell.NewEventKey(tcell.KeyEnd, 0, tcell.ModNone)

	for _, route := range pickerKeyRoutes(a) {
		if got := route.send(end); got != nil {
			t.Errorf("%s: End not consumed", route.name)
		}
		if r, _ := tbl.GetSelection(); r != lastRow {
			t.Errorf("%s: End selection row = %d, want %d (last selectable model)", route.name, r, lastRow)
		}
		if got := route.send(home); got != nil {
			t.Errorf("%s: Home not consumed", route.name)
		}
		if r, _ := tbl.GetSelection(); r != firstRow {
			t.Errorf("%s: Home selection row = %d, want %d (first selectable model)", route.name, r, firstRow)
		}
	}
	if applier.calls != 0 {
		t.Errorf("Apply calls = %d, want 0 (Home/End never confirm)", applier.calls)
	}
}

func pagedTwoProviderCatalog(n int) *providerModelCatalogFake {
	var rows []ProviderModel
	for _, p := range []string{"openai", "anthropic"} {
		for i := 0; i < n; i++ {
			rows = append(rows, ProviderModel{Provider: p, ModelID: fmt.Sprintf("%s-m%02d", p, i)})
		}
	}
	return &providerModelCatalogFake{
		rows:   rows,
		target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml", LaunchDir: "/p", ProjectRoot: "/p"},
	}
}

func selectableBetween(mp *modelPickerSession, a, b int) int {
	if a > b {
		a, b = b, a
	}
	c := 0
	for i := a + 1; i <= b; i++ {
		if mp.dataIndex(i) >= 0 {
			c++
		}
	}
	return c
}

func TestModelPicker_PageKeysMoveByViewportOfSelectableRows(t *testing.T) {
	a := New(nil)
	cat := pagedTwoProviderCatalog(20)
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	body, tbl := a.buildModelPicker(cat.rows, 0, "", cat.target, cat)
	drawPrimitive(t, centeredModal(body), 100, 40)

	_, _, _, viewport := tbl.GetInnerRect()
	if viewport < 2 {
		t.Fatalf("table viewport height = %d, want a multi-row viewport for the paging assertion", viewport)
	}

	firstRow := modelTableRow(tbl, 0)
	lastRow := modelTableRow(tbl, len(cat.rows)-1)
	middleRow := modelTableRow(tbl, len(cat.rows)/2)
	pageUp := tcell.NewEventKey(tcell.KeyPgUp, 0, tcell.ModNone)
	pageDown := tcell.NewEventKey(tcell.KeyPgDn, 0, tcell.ModNone)
	for _, route := range pickerKeyRoutes(a) {
		name, send := route.name, route.send

		tbl.Select(middleRow, 0)
		if got := send(pageUp); got != nil {
			t.Errorf("%s: Page Up not consumed", name)
		}
		upRow, _ := tbl.GetSelection()
		if moved := selectableBetween(a.modelPicker, middleRow, upRow); moved != viewport {
			t.Errorf("%s: Page Up moved %d selectable rows, want one viewport = %d", name, moved, viewport)
		}
		if a.modelPicker.dataIndex(upRow) < 0 {
			t.Errorf("%s: Page Up landed on non-model row %d", name, upRow)
		}

		tbl.Select(middleRow, 0)
		if got := send(pageDown); got != nil {
			t.Errorf("%s: Page Down not consumed", name)
		}
		downRow, _ := tbl.GetSelection()
		if moved := selectableBetween(a.modelPicker, middleRow, downRow); moved != viewport {
			t.Errorf("%s: Page Down moved %d selectable rows, want one viewport = %d", name, moved, viewport)
		}
		if a.modelPicker.dataIndex(downRow) < 0 {
			t.Errorf("%s: Page Down landed on non-model row %d", name, downRow)
		}

		tbl.Select(firstRow, 0)
		if got := send(pageUp); got != nil {
			t.Errorf("%s: Page Up at first row not consumed", name)
		}
		if r, _ := tbl.GetSelection(); r != firstRow {
			t.Errorf("%s: Page Up clamped at row %d, want %d", name, r, firstRow)
		}

		tbl.Select(lastRow, 0)
		if got := send(pageDown); got != nil {
			t.Errorf("%s: Page Down at last row not consumed", name)
		}
		if r, _ := tbl.GetSelection(); r != lastRow {
			t.Errorf("%s: Page Down clamped at row %d, want %d", name, r, lastRow)
		}
	}
	if applier.calls != 0 {
		t.Errorf("Apply calls = %d, want 0 (paging never confirms)", applier.calls)
	}
}

func TestModelPicker_NavigationStaysWithinFilterAndKeepsQuery(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	a.onModelFilterChanged("gpt")
	tbl := a.modelPicker.table

	a.selectModelBoundary(1)
	if di := a.modelPicker.dataIndex(mustSelection(t, tbl)); di != 1 {
		t.Errorf("End under filter selected data index %d, want gpt-5-mini (1)", di)
	}
	a.selectModelBoundary(-1)
	if di := a.modelPicker.dataIndex(mustSelection(t, tbl)); di != 0 {
		t.Errorf("Home under filter selected data index %d, want gpt-5 (0)", di)
	}
	a.pageModelPickerSelection(1)
	if di := a.modelPicker.dataIndex(mustSelection(t, tbl)); di != 1 {
		t.Errorf("Page Down under filter selected data index %d, want the filtered last model (1)", di)
	}
	if a.modelPicker.query != "gpt" {
		t.Errorf("query after navigation = %q, want it unchanged (gpt)", a.modelPicker.query)
	}
}

func mustSelection(t *testing.T, tbl *tview.Table) int {
	t.Helper()
	r, _ := tbl.GetSelection()
	return r
}

func TestModelPicker_NavigationSafeOnEmptyAndSingleResult(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	a.onModelFilterChanged("zzzz")
	a.selectModelBoundary(-1)
	a.selectModelBoundary(1)
	a.pageModelPickerSelection(-1)
	a.pageModelPickerSelection(1)
	if applier.calls != 0 {
		t.Errorf("Apply calls = %d on empty set, want 0", applier.calls)
	}

	a.onModelFilterChanged("claude")
	tbl := a.modelPicker.table
	only := modelTableRow(tbl, 2)
	for _, nav := range []func(){
		func() { a.selectModelBoundary(-1) },
		func() { a.selectModelBoundary(1) },
		func() { a.pageModelPickerSelection(-1) },
		func() { a.pageModelPickerSelection(1) },
	} {
		nav()
		if r, _ := tbl.GetSelection(); r != only {
			t.Errorf("single-result navigation moved off the only model row: got %d, want %d", r, only)
		}
	}
	if applier.calls != 0 {
		t.Errorf("Apply calls = %d, want 0 (navigation never confirms)", applier.calls)
	}
}

func TestModelPicker_FirstModelKeepsProviderHeaderVisible(t *testing.T) {
	a := New(nil)
	cat := pagedTwoProviderCatalog(20)
	body, tbl := a.buildModelPicker(cat.rows, 0, "", cat.target, cat)
	drawPrimitive(t, centeredModal(body), 100, 40)

	if off, _ := tbl.GetOffset(); off != 0 {
		t.Errorf("initial table offset = %d, want 0 (provider header visible above first model)", off)
	}

	a.selectModelBoundary(1)
	drawPrimitive(t, centeredModal(body), 100, 40)
	if off, _ := tbl.GetOffset(); off == 0 {
		t.Fatal("offset still 0 after End; fixture is not tall enough to hide the header")
	}

	a.selectModelBoundary(-1)
	drawPrimitive(t, centeredModal(body), 100, 40)
	if r, _ := tbl.GetSelection(); r != 1 {
		t.Errorf("Home selection row = %d, want the first model row 1", r)
	}
	if off, _ := tbl.GetOffset(); off != 0 {
		t.Errorf("table offset after Home = %d, want 0 (provider header back in view)", off)
	}
}

func TestModelPicker_LaterProviderHeaderRemainsVisible(t *testing.T) {
	a := New(nil)
	cat := pagedTwoProviderCatalog(20)
	body, tbl := a.buildModelPicker(cat.rows, 20, "", cat.target, cat)
	drawPrimitive(t, centeredModal(body), 100, 40)

	laterFirstRow := modelTableRow(tbl, 20)
	if r, _ := tbl.GetSelection(); r != laterFirstRow {
		t.Fatalf("initial selection row = %d, want %d", r, laterFirstRow)
	}
	if off, _ := tbl.GetOffset(); off != laterFirstRow-1 {
		t.Errorf("initial table offset = %d, want %d (later provider header visible)", off, laterFirstRow-1)
	}

	tbl.Select(modelTableRow(tbl, 19), 0)
	a.moveModelPickerSelection(1)
	drawPrimitive(t, centeredModal(body), 100, 40)
	if r, _ := tbl.GetSelection(); r != laterFirstRow {
		t.Errorf("selection after crossing provider boundary = %d, want %d", r, laterFirstRow)
	}
	if off, _ := tbl.GetOffset(); off != laterFirstRow-1 {
		t.Errorf("table offset after crossing provider boundary = %d, want %d (later provider header visible)", off, laterFirstRow-1)
	}
}

func TestModelPicker_NavigationRefreshesEffortWithoutConfirming(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	applier := &providerModelApplierFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier})
	a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	a.selectModelBoundary(1)
	if strings.Join(a.modelPicker.supported, ",") != "default" {
		t.Errorf("supported after End = %v, want [default] (effort tracks highlighted model)", a.modelPicker.supported)
	}
	a.selectModelBoundary(-1)
	if strings.Join(a.modelPicker.supported, ",") != "minimal,low,medium,high" {
		t.Errorf("supported after Home = %v, want gpt-5's set", a.modelPicker.supported)
	}
	if applier.calls != 0 {
		t.Errorf("Apply calls = %d, want 0 (navigation must not confirm)", applier.calls)
	}
	if a.TranscriptText() != "" {
		t.Errorf("transcript = %q, want none (navigation appends no confirmation)", a.TranscriptText())
	}
}

type refreshCatalogCall struct {
	provider string
	force    bool
	complete func(ModelRefreshResult)
}

type refreshCatalogFake struct {
	calls []refreshCatalogCall
}

func (f *refreshCatalogFake) refresh(providerID string, force bool, onComplete func(ModelRefreshResult)) {
	f.calls = append(f.calls, refreshCatalogCall{provider: providerID, force: force, complete: onComplete})
}

func (f *refreshCatalogFake) providers() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.provider)
	}
	return out
}

func refreshTriggerCatalog() *providerModelCatalogFake {
	return &providerModelCatalogFake{
		rows: []ProviderModel{
			{Provider: "openai", DisplayName: "OpenAI", ModelID: "gpt-a"},
			{Provider: "openai", DisplayName: "OpenAI", ModelID: "gpt-b"},
			{Provider: "openai-chatgpt", DisplayName: "OpenAI ChatGPT", ModelID: "cgpt-x"},
			{Provider: "venice", DisplayName: "Venice", ModelID: "v-a"},
		},
		target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml"},
	}
}

func refreshRebuildCatalog() *providerModelCatalogFake {
	return &providerModelCatalogFake{
		rows: []ProviderModel{
			{Provider: "openai", ModelID: "alpha-1"},
			{Provider: "openai", ModelID: "alpha-2"},
			{Provider: "venice", ModelID: "beta-1"},
		},
		target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml"},
	}
}

func pickerStatusText(sess *modelPickerSession) string { return sess.statusText() }

// New(nil) alone leaves ActiveStore nil (events.Append rejects it) and FlushActive a
// no-op, so the recording path would reach no disk at all without this.
func refreshStoreApp(t *testing.T) (*App, *sessions.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.json")
	store := escTestStoreAtPath(path)
	a := New(nil)
	a.SetActiveStore(store)
	a.SetCommandFlush(func() error {
		_, _, err := store.Flush(context.Background())
		return err
	})
	return a, store, path
}

func refreshRecordsOnDisk(t *testing.T, path string) []events.ModelCatalogRefreshed {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	var out []events.ModelCatalogRefreshed
	for _, rec := range loaded.Records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindModelCatalogRefreshed {
			continue
		}
		var p events.ModelCatalogRefreshed
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode model_catalog_refreshed: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func selectModelRow(t *testing.T, sess *modelPickerSession, modelID string) {
	t.Helper()
	for row, di := range sess.dataByRow {
		if di >= 0 && sess.rows[di].ModelID == modelID {
			sess.table.Select(row, 0)
			return
		}
	}
	t.Fatalf("no visible row for model %q", modelID)
}

func selectedModelID(sess *modelPickerSession) string {
	row, _ := sess.table.GetSelection()
	di := sess.dataIndex(row)
	if di < 0 {
		return ""
	}
	return sess.rows[di].ModelID
}

func TestModelPicker_StaleProviderRefreshesOnce(t *testing.T) {
	a := New(nil)
	cat := refreshTriggerCatalog()
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
	a.openModelPicker()
	tbl := a.modelPicker.table

	if got := fake.providers(); !reflect.DeepEqual(got, []string{"openai"}) {
		t.Fatalf("after open, requests = %v, want one for [openai]", got)
	}
	if fake.calls[0].force {
		t.Errorf("initial highlight request was forced, want non-forced")
	}

	tbl.Select(modelTableRow(tbl, 1), 0)
	if got := fake.providers(); !reflect.DeepEqual(got, []string{"openai"}) {
		t.Fatalf("same-provider navigation requests = %v, want still [openai]", got)
	}

	tbl.Select(modelTableRow(tbl, 2), 0)
	if got := fake.providers(); !reflect.DeepEqual(got, []string{"openai"}) {
		t.Fatalf("built-in openai-chatgpt highlight requests = %v, want no new request", got)
	}

	tbl.Select(modelTableRow(tbl, 3), 0)
	if got := fake.providers(); !reflect.DeepEqual(got, []string{"openai", "venice"}) {
		t.Fatalf("new configured-provider requests = %v, want [openai venice]", got)
	}
	if fake.calls[1].force {
		t.Errorf("venice highlight request was forced, want non-forced")
	}

	tbl.Select(modelTableRow(tbl, 0), 0)
	if got := fake.providers(); !reflect.DeepEqual(got, []string{"openai", "venice"}) {
		t.Fatalf("revisited-provider requests = %v, want unchanged [openai venice]", got)
	}
}

func TestModelPicker_CtrlRForcesProviderRefresh(t *testing.T) {
	if !strings.Contains(modelPickerFooterHint, "Ctrl-R refresh") {
		t.Errorf("footer hint = %q, want it to advertise Ctrl-R for refresh", modelPickerFooterHint)
	}
	ctrlREvent := tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone)
	runeREvent := tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone)

	assertForces := func(t *testing.T, route func(*App, *tcell.EventKey) *tcell.EventKey, ev *tcell.EventKey, ctrlR bool) {
		a := New(nil)
		cat := refreshTriggerCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		before := len(fake.calls)
		ret := route(a, ev)
		if ctrlR && ret != nil {
			t.Errorf("Ctrl-R not consumed: returned %v, want nil", ret)
		}
		if !ctrlR && ret == nil {
			t.Errorf("lowercase r consumed, want it to pass through to the filter field")
		}
		if ctrlR && !a.modelPickerOpen {
			t.Errorf("picker closed after Ctrl-R; it must stay open")
		}
		if ctrlR && len(fake.calls) != before+1 {
			t.Fatalf("Ctrl-R produced %d new requests, want exactly one", len(fake.calls)-before)
		}
		if ctrlR {
			last := fake.calls[len(fake.calls)-1]
			if last.provider != "openai" || !last.force {
				t.Errorf("Ctrl-R request = %+v, want a forced openai refresh", last)
			}
		}
	}

	t.Run("focused filter Ctrl-R route", func(t *testing.T) {
		assertForces(t, func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerFieldKeys(ev) }, ctrlREvent, true)
	})
	t.Run("model table Ctrl-R route", func(t *testing.T) {
		assertForces(t, func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerKeys()(ev) }, ctrlREvent, true)
	})
	t.Run("lowercase r passes through to filter", func(t *testing.T) {
		assertForces(t, func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerFieldKeys(ev) }, runeREvent, false)
	})
	t.Run("lowercase r passes through to table", func(t *testing.T) {
		assertForces(t, func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerKeys()(ev) }, runeREvent, false)
	})
}

func TestModelPicker_StatusRowSitsAboveTheFooter(t *testing.T) {
	a := New(nil)
	cat := refreshRebuildCatalog()
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: (&refreshCatalogFake{}).refresh})
	body, _ := a.buildModelPicker(cat.rows, 0, "", cat.target, cat)

	flex, ok := body.(*tview.Flex)
	if !ok {
		t.Fatalf("picker body is %T, want *tview.Flex", body)
	}
	n := flex.GetItemCount()
	if n < 2 {
		t.Fatalf("picker body has %d items, want the status row and footer among them", n)
	}
	if flex.GetItem(n-2) != tview.Primitive(a.modelPicker.status) {
		t.Errorf("body item %d is %T, want the status row", n-2, flex.GetItem(n-2))
	}
	footer, ok := flex.GetItem(n - 1).(*tview.TextView)
	if !ok || footer.GetText(true) != modelPickerFooterHint {
		t.Errorf("last body item = %v, want the footer key legend still last and visible", flex.GetItem(n-1))
	}
	if got := pickerStatusText(a.modelPicker); got != modelRefreshingStatus("openai") {
		t.Errorf("status row at build time = %q, want the open-time progress line; a nil status view drops it", got)
	}
}

func TestModelPicker_CtrlRShowsStatusInsideThePicker(t *testing.T) {
	cases := []struct {
		name    string
		outcome ModelRefreshOutcome
		want    string
	}{
		{"updated", ModelRefreshUpdated, modelRefreshedStatus("openai")},
		{"no change", ModelRefreshNoChange, modelRefreshUpToDateStatus("openai")},
		{"failed", ModelRefreshFailed, modelRefreshFailedStatus("openai")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := refreshStoreApp(t)
			cat := refreshRebuildCatalog()
			fake := &refreshCatalogFake{}
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
			a.openModelPicker()
			sess := a.modelPicker

			if ev := a.modelPickerFieldKeys(tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone)); ev != nil {
				t.Fatalf("Ctrl-R not consumed: returned %v", ev)
			}
			forced := fake.calls[len(fake.calls)-1]
			if !forced.force {
				t.Fatalf("last request = %+v, want a forced one", forced)
			}
			if got := pickerStatusText(sess); got != modelRefreshingStatus("openai") {
				t.Fatalf("progress status = %q, want %q", got, modelRefreshingStatus("openai"))
			}

			forced.complete(ModelRefreshResult{Provider: "openai", Outcome: tc.outcome})

			if got := pickerStatusText(a.modelPicker); got != tc.want {
				t.Errorf("completion status = %q, want %q", got, tc.want)
			}
			if a.transcript.notice != "" {
				t.Errorf("refresh state reached the notice (%q); it renders under the picker overlay", a.transcript.notice)
			}
		})
	}
}

func TestModelPicker_CtrlRExplainsEveryReachableNoOp(t *testing.T) {
	ctrlR := tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone)

	t.Run("no model row selected", func(t *testing.T) {
		a := New(nil)
		cat := refreshRebuildCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		sess := a.modelPicker
		a.onModelFilterChanged("no-such-model")
		if len(sess.dataByRow) != 0 {
			t.Fatalf("filtered table rows = %d, want an empty set", len(sess.dataByRow))
		}
		before := len(fake.calls)

		a.modelPickerFieldKeys(ctrlR)

		if len(fake.calls) != before {
			t.Errorf("requests = %v, want no new one with nothing selected", fake.providers())
		}
		if got := pickerStatusText(sess); got != modelNothingToRefreshStatus {
			t.Errorf("status = %q, want %q", got, modelNothingToRefreshStatus)
		}
	})

	t.Run("row with no provider id", func(t *testing.T) {
		a := New(nil)
		cat := &providerModelCatalogFake{
			rows:   []ProviderModel{{ModelID: "orphan-1"}},
			target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml"},
		}
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		sess := a.modelPicker
		before := len(fake.calls)

		a.modelPickerFieldKeys(ctrlR)

		if len(fake.calls) != before {
			t.Errorf("requests = %v, want no new one for a row with no provider id", fake.providers())
		}
		if got := pickerStatusText(sess); got != modelNothingToRefreshStatus {
			t.Errorf("status = %q, want %q", got, modelNothingToRefreshStatus)
		}
	})

	t.Run("refresh dependency unwired", func(t *testing.T) {
		a := New(nil)
		cat := refreshRebuildCatalog()
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}})
		a.openModelPicker()
		sess := a.modelPicker

		a.modelPickerFieldKeys(ctrlR)

		if got := pickerStatusText(sess); got != modelNothingToRefreshStatus {
			t.Errorf("status = %q, want %q", got, modelNothingToRefreshStatus)
		}
	})

	t.Run("highlighting the built-in provider stays silent without Ctrl-R", func(t *testing.T) {
		a := New(nil)
		cat := refreshTriggerCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		sess := a.modelPicker

		selectModelRow(t, sess, "cgpt-x")

		if got := pickerStatusText(sess); got != modelRefreshingStatus("openai") {
			t.Errorf("status = %q, want the open-time progress line; only Ctrl-R may report a no-op", got)
		}
	})
}

func TestModelPicker_CtrlROnChatGPTForcesOneRefresh(t *testing.T) {
	routes := map[string]func(*App, *tcell.EventKey) *tcell.EventKey{
		"filter": func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerFieldKeys(ev) },
		"table":  func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerKeys()(ev) },
	}
	for name, route := range routes {
		t.Run(name, func(t *testing.T) {
			a := New(nil)
			fake := &refreshCatalogFake{}
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: refreshTriggerCatalog(), Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
			a.openModelPicker()
			selectModelRow(t, a.modelPicker, "cgpt-x")
			if slices.Contains(fake.providers(), builtinChatGPTProviderID) {
				t.Fatalf("open/highlight requests = %v, want no ChatGPT refresh before Ctrl-R", fake.providers())
			}
			before := len(fake.calls)

			if ret := route(a, tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone)); ret == nil || len(fake.calls) != before {
				t.Fatalf("lowercase r consumed=%v, new requests=%d; want filter input and no refresh", ret == nil, len(fake.calls)-before)
			}
			if ret := route(a, tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone)); ret != nil {
				t.Fatalf("Ctrl-R not consumed: returned %v", ret)
			}
			if !a.modelPickerOpen {
				t.Error("picker closed after Ctrl-R; it must stay open")
			}
			if len(fake.calls) != before+1 {
				t.Fatalf("Ctrl-R produced %d new requests, want exactly one", len(fake.calls)-before)
			}
			if last := fake.calls[len(fake.calls)-1]; last.provider != builtinChatGPTProviderID || !last.force {
				t.Errorf("Ctrl-R request = %+v, want a forced openai-chatgpt refresh", last)
			}
		})
	}
}

func TestModelPicker_LowercaseROnChatGPTIsFilterInput(t *testing.T) {
	a := New(nil)
	fake := &refreshCatalogFake{}
	cat := &providerModelCatalogFake{
		rows: []ProviderModel{
			{Provider: builtinChatGPTProviderID, ModelID: "gpt-5"},
			{Provider: builtinChatGPTProviderID, ModelID: "gpt-5-pro"},
		},
		target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml"},
	}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
	a.openModelPicker()
	sess := a.modelPicker
	selectModelRow(t, sess, "gpt-5")

	sess.field.InputHandler()(tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone), func(tview.Primitive) {})

	if got := sess.field.GetText(); got != "r" || sess.query != "r" {
		t.Errorf("filter text = %q, query = %q, want both r", got, sess.query)
	}
	var visible []string
	for _, di := range sess.dataByRow {
		if di >= 0 {
			visible = append(visible, sess.rows[di].ModelID)
		}
	}
	if !slices.Equal(visible, []string{"gpt-5-pro"}) {
		t.Errorf("visible models = %v, want only gpt-5-pro after filtering by r", visible)
	}
	if len(fake.calls) != 0 {
		t.Errorf("refresh requests = %v, want none for lowercase r", fake.providers())
	}
}

func TestModelPicker_ChatGPTForcedRefreshOutcomes(t *testing.T) {
	for _, provider := range []string{builtinChatGPTProviderID, "openai", ""} {
		if got := modelRefreshLoginStatus(provider); got != "run codemeld auth login openai-chatgpt" {
			t.Fatalf("login status for %q = %q, want the exact login command", provider, got)
		}
	}
	cases := []struct {
		name    string
		outcome ModelRefreshOutcome
		status  string
		event   string
		rebuilt bool
	}{
		{"updated", ModelRefreshUpdated, modelRefreshedStatus(builtinChatGPTProviderID), "updated", true},
		{"failed", ModelRefreshFailed, modelRefreshFailedStatus(builtinChatGPTProviderID), "failed", false},
		{"credential unavailable", ModelRefreshCredentialUnavailable, modelRefreshLoginStatus(builtinChatGPTProviderID), "failed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, path := refreshStoreApp(t)
			cat := refreshTriggerCatalog()
			applier := &providerModelApplierFake{}
			fake := &refreshCatalogFake{}
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, RefreshCatalog: fake.refresh})
			a.openModelPicker()
			sess := a.modelPicker
			selectModelRow(t, sess, "cgpt-x")
			before := append([]ProviderModel(nil), sess.rows...)
			a.modelPickerFieldKeys(tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone))

			cat.rows = append(slices.Clone(cat.rows), ProviderModel{Provider: builtinChatGPTProviderID, DisplayName: "OpenAI ChatGPT", ModelID: "cgpt-y"})
			fake.calls[len(fake.calls)-1].complete(ModelRefreshResult{Provider: builtinChatGPTProviderID, Outcome: tc.outcome})

			if got := pickerStatusText(sess); got != tc.status {
				t.Errorf("status = %q, want %q", got, tc.status)
			}
			if got := slices.Contains(sess.rows, cat.rows[len(cat.rows)-1]); got != tc.rebuilt {
				t.Errorf("rows include refreshed cgpt-y = %v, want %v", got, tc.rebuilt)
			}
			if !tc.rebuilt && !reflect.DeepEqual(sess.rows, before) {
				t.Errorf("rows changed on %s = %v, want cached rows retained", tc.name, sess.rows)
			}
			if got := selectedModelID(sess); got != "cgpt-x" {
				t.Errorf("selection = %q, want cgpt-x retained", got)
			}
			if applier.calls != 0 || a.transcript.notice != "" {
				t.Errorf("applier calls = %d, notice = %q; want no model change and no notice", applier.calls, a.transcript.notice)
			}
			want := []events.ModelCatalogRefreshed{{Provider: builtinChatGPTProviderID, Outcome: tc.event}}
			if got := refreshRecordsOnDisk(t, path); !reflect.DeepEqual(got, want) {
				t.Errorf("records on disk = %v, want %v", got, want)
			}
			a.dismissModelPicker()
			if !equalStrings(a.transcript.lines, []string{"• " + tc.status}) {
				t.Errorf("scrollback = %v, want [%q]", a.transcript.lines, "• "+tc.status)
			}
		})
	}
}

func TestModelPicker_ForcedRefreshRecordsOneEventAndOneLine(t *testing.T) {
	cases := []struct {
		name    string
		outcome ModelRefreshOutcome
		want    string
		line    string
	}{
		{"updated", ModelRefreshUpdated, "updated", "• " + modelRefreshedStatus("openai")},
		{"no change", ModelRefreshNoChange, "no_change", "• " + modelRefreshUpToDateStatus("openai")},
		{"failed", ModelRefreshFailed, "failed", "• " + modelRefreshFailedStatus("openai")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, store, path := refreshStoreApp(t)
			cat := refreshRebuildCatalog()
			fake := &refreshCatalogFake{}
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
			a.openModelPicker()

			a.forceRefreshHighlightedProvider()
			fake.calls[len(fake.calls)-1].complete(ModelRefreshResult{Provider: "openai", Outcome: tc.outcome})

			want := []events.ModelCatalogRefreshed{{Provider: "openai", Outcome: tc.want}}
			if got := refreshRecordsOnDisk(t, path); !reflect.DeepEqual(got, want) {
				t.Errorf("records read back from the session file = %v, want %v", got, want)
			}
			if got := len(store.Records()); got != 1 {
				t.Errorf("appended %d record(s), want exactly 1", got)
			}
			if a.transcript.notice != "" {
				t.Errorf("notice = %q, want none on a recorded refresh", a.transcript.notice)
			}

			a.dismissModelPicker()

			if !equalStrings(a.transcript.lines, []string{tc.line}) {
				t.Errorf("scrollback after close = %v, want exactly [%q]", a.transcript.lines, tc.line)
			}
		})
	}
}

func TestModelPicker_ForcedCompletionFollowsTheInitiatingSession(t *testing.T) {
	start := func(t *testing.T) (*App, *sessions.Store, string, refreshCatalogCall) {
		t.Helper()
		a, store, path := refreshStoreApp(t)
		cat := refreshRebuildCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		a.forceRefreshHighlightedProvider()
		a.dismissModelPicker()
		return a, store, path, fake.calls[len(fake.calls)-1]
	}

	t.Run("dismissal alone keeps the same session, so it records", func(t *testing.T) {
		a, _, path, forced := start(t)

		forced.complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

		want := []events.ModelCatalogRefreshed{{Provider: "openai", Outcome: "updated"}}
		if got := refreshRecordsOnDisk(t, path); !reflect.DeepEqual(got, want) {
			t.Errorf("records = %v, want %v", got, want)
		}
		if want := []string{"• " + modelRefreshedStatus("openai")}; !equalStrings(a.transcript.lines, want) {
			t.Errorf("scrollback = %v, want %v", a.transcript.lines, want)
		}
	})

	for _, trigger := range []string{"clear", "resume"} {
		t.Run("a "+trigger+" session switch discards it", func(t *testing.T) {
			a, prior, priorPath, forced := start(t)
			freshPath := filepath.Join(t.TempDir(), trigger+".json")
			fresh := escTestStoreAtPath(freshPath)
			a.SetActiveStore(fresh)
			a.SetCommandFlush(func() error {
				_, _, err := fresh.Flush(context.Background())
				return err
			})

			forced.complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

			if got := len(prior.Records()); got != 0 {
				t.Errorf("prior session gained %d record(s), want 0", got)
			}
			if got := len(fresh.Records()); got != 0 {
				t.Errorf("replacement session gained %d record(s), want 0", got)
			}
			if got := refreshRecordsOnDisk(t, priorPath); len(got) != 0 {
				t.Errorf("prior session file holds %v, want nothing", got)
			}
			if got := refreshRecordsOnDisk(t, freshPath); len(got) != 0 {
				t.Errorf("replacement session file holds %v, want nothing", got)
			}
			if got := len(a.transcript.lines); got != 0 {
				t.Errorf("scrollback = %v, want no line for a discarded completion", a.transcript.lines)
			}
			if a.transcript.notice != "" {
				t.Errorf("notice = %q, want none for a discarded completion", a.transcript.notice)
			}
		})
	}
}

func TestModelPicker_ForcedRefreshRecordFailureSkipsTheLine(t *testing.T) {
	t.Run("append failure", func(t *testing.T) {
		a := New(nil)
		cat := refreshRebuildCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()

		a.forceRefreshHighlightedProvider()
		fake.calls[len(fake.calls)-1].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

		if !strings.Contains(a.transcript.notice, "could not record the model refresh") {
			t.Errorf("notice = %q, want the record-failure notice", a.transcript.notice)
		}
		if got := len(a.transcript.lines); got != 0 {
			t.Errorf("scrollback = %v, want no completion line when the record failed", a.transcript.lines)
		}
	})

	t.Run("strict refresh flush failure", func(t *testing.T) {
		a, store, _ := refreshStoreApp(t)
		flushErr := errors.New("flush failed")
		cat := refreshRebuildCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{
			Catalog:        cat,
			Applier:        &providerModelApplierFake{},
			RefreshCatalog: fake.refresh,
			FlushRefresh: func(*sessions.Store) error {
				return flushErr
			},
		})
		a.openModelPicker()

		a.forceRefreshHighlightedProvider()
		fake.calls[len(fake.calls)-1].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

		if !strings.Contains(a.transcript.notice, flushErr.Error()) {
			t.Errorf("notice = %q, want it to carry the flush error", a.transcript.notice)
		}
		if got := len(a.transcript.lines); got != 0 {
			t.Errorf("scrollback = %v, want no completion line when the strict refresh flush failed", a.transcript.lines)
		}
		if got := len(store.Records()); got != 1 {
			t.Errorf("appended %d record(s), want the record still carried forward", got)
		}
	})
}

func TestModelPicker_RefreshSuccessRebuildsFilteredRows(t *testing.T) {
	t.Run("preserves query and selection", func(t *testing.T) {
		a := New(nil)
		cat := refreshRebuildCatalog()
		applier := &providerModelApplierFake{}
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		sess := a.modelPicker
		a.onModelFilterChanged("alpha")
		sess.table.Select(modelTableRow(sess.table, 1), 0)

		cat.rows = []ProviderModel{
			{Provider: "openai", ModelID: "alpha-1"},
			{Provider: "openai", ModelID: "alpha-2"},
			{Provider: "openai", ModelID: "alpha-3"},
			{Provider: "venice", ModelID: "beta-1"},
		}
		fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

		if sess.query != "alpha" {
			t.Errorf("query after rebuild = %q, want it preserved as alpha", sess.query)
		}
		if got := selectedModelID(sess); got != "alpha-2" {
			t.Errorf("selection after rebuild = %q, want the still-present alpha-2 preserved", got)
		}
		if applier.calls != 0 {
			t.Errorf("rebuild applied a model (%d calls); a refresh must not confirm/persist", applier.calls)
		}
	})

	t.Run("falls back when the selected model disappears", func(t *testing.T) {
		a := New(nil)
		cat := refreshRebuildCatalog()
		applier := &providerModelApplierFake{}
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		sess := a.modelPicker
		a.onModelFilterChanged("alpha")
		sess.table.Select(modelTableRow(sess.table, 1), 0)

		cat.rows = []ProviderModel{
			{Provider: "openai", ModelID: "alpha-1"},
			{Provider: "openai", ModelID: "alpha-3"},
			{Provider: "venice", ModelID: "beta-1"},
		}
		fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

		if sess.query != "alpha" {
			t.Errorf("query after rebuild = %q, want it preserved as alpha", sess.query)
		}
		got := selectedModelID(sess)
		if got == "" || got == "alpha-2" {
			t.Errorf("selection after removal = %q, want a valid remaining row (not the gone alpha-2)", got)
		}
		if applier.calls != 0 {
			t.Errorf("fallback applied a model (%d calls); it must not confirm/persist", applier.calls)
		}
	})

	t.Run("table Enter after removal confirms the visible replacement, not the removed model", func(t *testing.T) {
		a := New(nil)
		cat := refreshRebuildCatalog()
		applier := &providerModelApplierFake{}
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		sess := a.modelPicker
		a.onModelFilterChanged("alpha")
		sess.table.Select(modelTableRow(sess.table, 0), 0)

		cat.rows = []ProviderModel{
			{Provider: "openai", ModelID: "alpha-3"},
			{Provider: "openai", ModelID: "alpha-2"},
			{Provider: "venice", ModelID: "beta-1"},
		}
		fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

		visible := selectedModelID(sess)
		if visible == "" || visible == "alpha-1" {
			t.Fatalf("selection after removal = %q, want a remaining visible model (not the gone alpha-1)", visible)
		}

		sess.table.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

		if applier.calls != 1 {
			t.Fatalf("table Enter did not confirm (%d calls), want 1", applier.calls)
		}
		if applier.gotID == "alpha-1" {
			t.Errorf("table Enter confirmed %q, the removed model; want the visible replacement %q", applier.gotID, visible)
		}
		if applier.gotID != visible {
			t.Errorf("table Enter confirmed %q, want the visible selection %q", applier.gotID, visible)
		}
	})
}

func TestModelPicker_RefreshFailureKeepsCachedRows(t *testing.T) {
	a := New(nil)
	cat := refreshRebuildCatalog()
	applier := &providerModelApplierFake{}
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, RefreshCatalog: fake.refresh})
	a.openModelPicker()
	sess := a.modelPicker
	a.onModelFilterChanged("alpha")
	sess.table.Select(modelTableRow(sess.table, 1), 0)
	before := append([]ProviderModel(nil), sess.rows...)

	fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshFailed})

	if !reflect.DeepEqual(sess.rows, before) {
		t.Errorf("rows changed on a failed refresh = %v, want the cached rows retained", sess.rows)
	}
	if sess.query != "alpha" {
		t.Errorf("query after failure = %q, want it preserved as alpha", sess.query)
	}
	if got := selectedModelID(sess); got != "alpha-2" {
		t.Errorf("selection after failure = %q, want alpha-2 retained", got)
	}
	got := pickerStatusText(sess)
	if got != modelRefreshFailedStatus("openai") {
		t.Errorf("failure status = %q, want %q", got, modelRefreshFailedStatus("openai"))
	}
	if strings.Contains(got, "sk-") || strings.Contains(got, "key") {
		t.Errorf("failure status %q must carry no secret", got)
	}
	if a.transcript.notice != "" {
		t.Errorf("failed refresh set a notice %q, want the picker status row to carry it", a.transcript.notice)
	}
	if applier.calls != 0 {
		t.Errorf("failed refresh applied a model (%d calls), want none", applier.calls)
	}
}

func TestModelPicker_NoChangeRefreshLeavesRowsUntouched(t *testing.T) {
	a := New(nil)
	cat := refreshRebuildCatalog()
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
	a.openModelPicker()
	sess := a.modelPicker
	a.onModelFilterChanged("alpha")
	before := append([]ProviderModel(nil), sess.rows...)
	selBefore := selectedModelID(sess)

	fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshNoChange})

	if !reflect.DeepEqual(sess.rows, before) {
		t.Errorf("rows changed on a no-change refresh = %v, want them untouched", sess.rows)
	}
	if got := selectedModelID(sess); got != selBefore {
		t.Errorf("selection changed on a no-change refresh = %q, want %q", got, selBefore)
	}
	if got := pickerStatusText(sess); got != modelRefreshUpToDateStatus("openai") {
		t.Errorf("no-change status = %q, want %q", got, modelRefreshUpToDateStatus("openai"))
	}
	if a.transcript.notice != "" {
		t.Errorf("no-change refresh set a notice %q, want none", a.transcript.notice)
	}
}

func TestModelPicker_IgnoresStaleRefreshCompletion(t *testing.T) {
	t.Run("non-forced completion after dismissal records and shows nothing", func(t *testing.T) {
		a, store, path := refreshStoreApp(t)
		cat := refreshRebuildCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		staleCall := fake.calls[0]

		a.dismissModelPicker()
		staleCall.complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshFailed})

		if a.modelPicker != nil {
			t.Fatalf("a completion after dismissal reopened the picker")
		}
		if a.transcript.notice != "" {
			t.Errorf("a completion after dismissal set the notice to %q, want none", a.transcript.notice)
		}
		if got := a.TranscriptText(); got != "" {
			t.Errorf("non-forced completion appended %q, want no transcript line", got)
		}
		if got := len(store.Records()); got != 0 {
			t.Errorf("non-forced completion appended %d record(s), want 0", got)
		}
		if got := refreshRecordsOnDisk(t, path); len(got) != 0 {
			t.Errorf("non-forced completion persisted %v, want nothing", got)
		}
	})

	t.Run("forced stale completion records but leaves the reopened session's status alone", func(t *testing.T) {
		a, _, path := refreshStoreApp(t)
		cat := refreshRebuildCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		a.forceRefreshHighlightedProvider()
		staleCall := fake.calls[len(fake.calls)-1]
		if !staleCall.force {
			t.Fatalf("last request = %+v, want the forced one", staleCall)
		}

		a.dismissModelPicker()
		a.openModelPicker()
		sessB := a.modelPicker
		statusBeforeB := pickerStatusText(sessB)

		staleCall.complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshFailed})

		if a.modelPicker != sessB {
			t.Errorf("stale completion replaced the reopened session")
		}
		if got := pickerStatusText(sessB); got != statusBeforeB {
			t.Errorf("stale completion changed the reopened session's status from %q to %q", statusBeforeB, got)
		}
		want := []events.ModelCatalogRefreshed{{Provider: "openai", Outcome: "failed"}}
		if got := refreshRecordsOnDisk(t, path); !reflect.DeepEqual(got, want) {
			t.Errorf("persisted records = %v, want %v (the initiating session is still active)", got, want)
		}
		if got := a.TranscriptText(); !strings.Contains(got, "• "+modelRefreshFailedStatus("openai")) {
			t.Errorf("transcript = %q, want the forced completion line", got)
		}
	})
}

func TestModelPicker_EmptyConfiguredProviderRefreshesOnOpen(t *testing.T) {
	a := New(nil)
	cat := &providerModelCatalogFake{
		rows: []ProviderModel{
			{Provider: "openai", DisplayName: "OpenAI", ModelID: "gpt-a"},
		},
		emptyProviders: []ProviderModel{
			{Provider: "venice", DisplayName: "Venice"},
		},
		target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml"},
	}
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
	a.openModelPicker()

	want := []string{"openai", "venice"}
	if got := fake.providers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after open, requests = %v, want %v (openai from highlight + venice from empty-configured)", got, want)
	}
	if fake.calls[1].force {
		t.Errorf("empty-provider request was forced, want non-forced")
	}
	if fake.calls[1].provider != "venice" {
		t.Errorf("empty-provider request = %q, want venice", fake.calls[1].provider)
	}

	cat.rows = []ProviderModel{
		{Provider: "openai", DisplayName: "OpenAI", ModelID: "gpt-a"},
		{Provider: "venice", DisplayName: "Venice", ModelID: "v-1"},
		{Provider: "venice", DisplayName: "Venice", ModelID: "v-2"},
	}
	fake.calls[1].complete(ModelRefreshResult{Provider: "venice", Outcome: ModelRefreshUpdated})

	sess := a.modelPicker
	var hasVenice bool
	for _, r := range sess.rows {
		if r.Provider == "venice" {
			hasVenice = true
			break
		}
	}
	if !hasVenice {
		t.Errorf("picker rows after empty-provider refresh = %+v, want venice rows now present", sess.rows)
	}
}

func TestModelPicker_NonForcedRefreshShowsProgressAndOutcome(t *testing.T) {
	a, store, path := refreshStoreApp(t)
	cat := refreshRebuildCatalog()
	applier := &providerModelApplierFake{}
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, RefreshCatalog: fake.refresh})
	a.openModelPicker()
	sess := a.modelPicker

	if got := pickerStatusText(sess); got != modelRefreshingStatus("openai") {
		t.Errorf("after open, status = %q, want %q (non-forced refresh must show progress)", got, modelRefreshingStatus("openai"))
	}

	cat.rows = []ProviderModel{
		{Provider: "openai", ModelID: "alpha-1"},
		{Provider: "openai", ModelID: "alpha-2"},
		{Provider: "openai", ModelID: "alpha-3"},
		{Provider: "venice", ModelID: "beta-1"},
	}
	fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

	if got := pickerStatusText(a.modelPicker); got != modelRefreshedStatus("openai") {
		t.Errorf("after non-forced update, status = %q, want %q", got, modelRefreshedStatus("openai"))
	}
	if applier.calls != 0 {
		t.Errorf("non-forced refresh applied a model (%d calls), want none", applier.calls)
	}
	if a.transcript.notice != "" {
		t.Errorf("non-forced refresh set a notice %q, want the status row to carry it", a.transcript.notice)
	}
	if got := a.TranscriptText(); got != "" {
		t.Errorf("non-forced refresh appended %q, want no transcript line", got)
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("opening the picker appended %d record(s), want 0", got)
	}
	if got := refreshRecordsOnDisk(t, path); len(got) != 0 {
		t.Errorf("opening the picker persisted %v, want nothing", got)
	}
}

func TestModelPicker_OpenRefreshRecordsNothing(t *testing.T) {
	a, store, path := refreshStoreApp(t)
	cat := &providerModelCatalogFake{
		rows:           []ProviderModel{{Provider: "openai", ModelID: "gpt-a"}},
		emptyProviders: []ProviderModel{{Provider: "venice", DisplayName: "Venice"}},
		target:         ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml"},
	}
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
	a.openModelPicker()

	if len(fake.calls) != 2 {
		t.Fatalf("open-time requests = %v, want one per configured provider", fake.providers())
	}
	fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})
	fake.calls[1].complete(ModelRefreshResult{Provider: "venice", Outcome: ModelRefreshFailed})

	if got := len(store.Records()); got != 0 {
		t.Errorf("open-time refreshes appended %d record(s), want 0", got)
	}
	if got := refreshRecordsOnDisk(t, path); len(got) != 0 {
		t.Errorf("open-time refreshes persisted %v, want nothing", got)
	}
	if got := a.TranscriptText(); got != "" {
		t.Errorf("open-time refreshes appended %q, want no transcript line", got)
	}
}

func TestModelPicker_OutOfOrderCompletionPreservesNewerStatus(t *testing.T) {
	a := New(nil)
	cat := refreshTriggerCatalog()
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
	a.openModelPicker()
	sess := a.modelPicker
	tbl := sess.table

	if len(fake.calls) != 1 || fake.calls[0].provider != "openai" {
		t.Fatalf("after open, requests = %v, want one for [openai]", fake.providers())
	}
	openaiCall := fake.calls[0]

	tbl.Select(modelTableRow(tbl, 3), 0)
	if len(fake.calls) != 2 || fake.calls[1].provider != "venice" {
		t.Fatalf("after venice highlight, requests = %v, want [openai venice]", fake.providers())
	}
	veniceCall := fake.calls[1]
	if got := pickerStatusText(sess); got != modelRefreshingStatus("venice") {
		t.Fatalf("status after venice highlight = %q, want %q", got, modelRefreshingStatus("venice"))
	}

	openaiCall.complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshNoChange})
	if got := pickerStatusText(sess); got != modelRefreshingStatus("venice") {
		t.Errorf("after older openai NoChange, status = %q, want %q (venice progress preserved)", got, modelRefreshingStatus("venice"))
	}

	veniceCall.complete(ModelRefreshResult{Provider: "venice", Outcome: ModelRefreshUpdated})
	if got := pickerStatusText(a.modelPicker); got != modelRefreshedStatus("venice") {
		t.Errorf("after venice Updated, status = %q, want %q", got, modelRefreshedStatus("venice"))
	}
}

type favoriteFake struct {
	snapshot    []ModelFavorite
	next        []ModelFavorite
	err         error
	toggleCalls int
	gotProvider string
	gotID       string
}

func (f *favoriteFake) list() []ModelFavorite { return f.snapshot }

func (f *favoriteFake) toggle(provider, modelID string) ([]ModelFavorite, error) {
	f.toggleCalls++
	f.gotProvider, f.gotID = provider, modelID
	if f.err != nil {
		return nil, f.err
	}
	f.snapshot = f.next
	return f.next, nil
}

func tableTexts(tbl *tview.Table) []string {
	out := make([]string, tbl.GetRowCount())
	for r := range out {
		out[r] = tbl.GetCell(r, 0).Text
	}
	return out
}

func TestModelPicker_FavoritesRenderAsAliasesBeforeGroups(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	favs := []ModelFavorite{
		{Provider: "openai", ModelID: "gpt-5-mini"},
		{Provider: "openai", ModelID: "gpt-5-mini"},
		{Provider: "anthropic", ModelID: "claude-x"},
		{Provider: "ghost", ModelID: "gone"},
	}
	before := append([]ModelFavorite(nil), favs...)
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, Favorites: func() []ModelFavorite { return favs }})
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	want := []string{
		"Favorites", "openai · gpt-5-mini", "anthropic · claude-x", "",
		"openai", "gpt-5", "gpt-5-mini", "",
		"anthropic", "claude-x",
	}
	if got := tableTexts(tbl); !reflect.DeepEqual(got, want) {
		t.Fatalf("table texts = %v, want %v", got, want)
	}
	if !tbl.GetCell(0, 0).NotSelectable {
		t.Error("Favorites heading is selectable, want non-selectable")
	}
	if di := a.modelPicker.dataIndex(1); di != 1 {
		t.Errorf("gpt-5-mini alias dataIndex = %d, want 1 (canonical flat index)", di)
	}
	if di := a.modelPicker.dataIndex(2); di != 2 {
		t.Errorf("claude-x alias dataIndex = %d, want 2 (canonical flat index)", di)
	}
	if tbl.GetCell(1, 0).NotSelectable || tbl.GetCell(2, 0).NotSelectable {
		t.Error("favorite alias rows are non-selectable, want selectable")
	}
	if !reflect.DeepEqual(favs, before) {
		t.Errorf("favorites snapshot mutated to %v, want %v (omission writes nothing)", favs, before)
	}
	row, _ := tbl.GetSelection()
	if got := tbl.GetCell(row, 0).Text; got != "openai · gpt-5-mini" {
		t.Errorf("initial highlight text = %q, want the first favorite's alias row", got)
	}
}

func TestModelPicker_FavoriteAliasResolvesExactPair(t *testing.T) {
	a := New(nil)
	cat := chatGPTDisplayNameCatalog()
	applier := &providerModelApplierFake{}
	favs := []ModelFavorite{
		{Provider: "openai", ModelID: "gpt-5.5"},
		{Provider: "openai-chatgpt", ModelID: "gpt-5.5"},
	}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, Favorites: func() []ModelFavorite { return favs }})
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	if got := tableTexts(tbl)[:3]; !reflect.DeepEqual(got, []string{"Favorites", "OpenAI Platform · gpt-5.5", "OpenAI ChatGPT · gpt-5.5"}) {
		t.Fatalf("favorite alias rows = %v, want the two provider-qualified gpt-5.5 aliases", got)
	}
	if a.modelPicker.dataIndex(1) == a.modelPicker.dataIndex(2) {
		t.Fatal("both gpt-5.5 aliases resolve to the same flat index; want distinct pairs")
	}

	tbl.Select(2, 0)
	a.confirmHighlightedModel()
	if applier.gotProvider != "openai-chatgpt" || applier.gotID != "gpt-5.5" {
		t.Errorf("confirmed favorite = (%q,%q), want (openai-chatgpt,gpt-5.5)", applier.gotProvider, applier.gotID)
	}
}

func TestModelPicker_CtrlFResolvesExactPairForSameModelID(t *testing.T) {
	a := New(nil)
	cat := chatGPTDisplayNameCatalog()
	fav := &favoriteFake{
		snapshot: []ModelFavorite{
			{Provider: "openai", ModelID: "gpt-5.5"},
			{Provider: "openai-chatgpt", ModelID: "gpt-5.5"},
		},
	}
	fav.next = append([]ModelFavorite(nil), fav.snapshot...)
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, Favorites: fav.list, ToggleFavorite: fav.toggle})
	a.openModelPicker()
	tbl := a.modelPicker.table

	if got := tableTexts(tbl)[:3]; !reflect.DeepEqual(got, []string{"Favorites", "OpenAI Platform · gpt-5.5", "OpenAI ChatGPT · gpt-5.5"}) {
		t.Fatalf("favorite alias rows = %v, want the two provider-qualified gpt-5.5 aliases", got)
	}
	tbl.Select(2, 0)

	if ret := a.modelPickerFieldKeys(tcell.NewEventKey(tcell.KeyCtrlF, 0, tcell.ModNone)); ret != nil {
		t.Errorf("Ctrl-F not consumed: returned %v, want nil", ret)
	}
	if fav.toggleCalls != 1 || fav.gotProvider != "openai-chatgpt" || fav.gotID != "gpt-5.5" {
		t.Fatalf("toggle = %d call(s) with (%q,%q), want 1 with (openai-chatgpt,gpt-5.5), not the same-id openai pair", fav.toggleCalls, fav.gotProvider, fav.gotID)
	}
	if !a.modelPickerOpen {
		t.Error("picker closed after Ctrl-F; it must stay open")
	}
}

func TestModelPicker_FavoritesFollowFilterAndPreserveSelection(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	favs := []ModelFavorite{
		{Provider: "openai", ModelID: "gpt-5-mini"},
		{Provider: "anthropic", ModelID: "claude-x"},
	}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, Favorites: func() []ModelFavorite { return favs }})
	_, tbl := a.buildModelPicker(cat.rows, 0, "medium", cat.target, cat)

	a.onModelFilterChanged("claude")
	want := []string{"Favorites", "anthropic · claude-x", "", "anthropic", "claude-x"}
	if got := tableTexts(tbl); !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered table = %v, want only the claude favorite + group", got)
	}
	if a.modelPicker.query != "claude" {
		t.Errorf("query = %q, want it preserved as claude", a.modelPicker.query)
	}
	row, _ := tbl.GetSelection()
	if di := a.modelPicker.dataIndex(row); di < 0 {
		t.Errorf("selection row %d is not a model row after filter rebuild", row)
	}
}

func TestModelPicker_RefreshRebuildsFilteredFavorites(t *testing.T) {
	a := New(nil)
	cat := &providerModelCatalogFake{
		rows: []ProviderModel{
			{Provider: "openai", ModelID: "alpha-1"},
			{Provider: "openai", ModelID: "alpha-2"},
			{Provider: "openai", ModelID: "alpha-3"},
			{Provider: "venice", ModelID: "beta-1"},
		},
		target: ModelSettingsTarget{SettingsPath: "/p/.codemeld/settings.yaml"},
	}
	fake := &refreshCatalogFake{}
	fav := &favoriteFake{
		snapshot: []ModelFavorite{
			{Provider: "openai", ModelID: "alpha-3"},
			{Provider: "openai", ModelID: "alpha-1"},
			{Provider: "openai", ModelID: "alpha-2"},
		},
	}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh, Favorites: fav.list, ToggleFavorite: fav.toggle})
	a.openModelPicker()
	sess := a.modelPicker
	a.onModelFilterChanged("alpha")

	cat.rows = []ProviderModel{
		{Provider: "openai", ModelID: "alpha-1"},
		{Provider: "openai", ModelID: "alpha-3"},
		{Provider: "venice", ModelID: "beta-1"},
	}
	fake.calls[0].complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshUpdated})

	want := []string{"Favorites", "openai · alpha-3", "openai · alpha-1", "", "openai", "alpha-1", "alpha-3"}
	if got := tableTexts(sess.table); !reflect.DeepEqual(got, want) {
		t.Fatalf("rebuilt table = %v, want %v (surviving aliases in snapshot order, stale alpha-2 omitted, group in catalog order)", got, want)
	}
	if sess.query != "alpha" {
		t.Errorf("query after refresh = %q, want it preserved as alpha", sess.query)
	}
	if got := selectedModelID(sess); got != "alpha-1" {
		t.Errorf("selection after refresh = %q, want the retained alpha-1 (still present)", got)
	}
	if fav.toggleCalls != 0 {
		t.Errorf("refresh rebuild called ToggleFavorite %d time(s), want 0 (a refresh never writes favorites)", fav.toggleCalls)
	}
}

func TestModelPicker_CtrlFTogglesFavoriteFromBothRoutes(t *testing.T) {
	ctrlF := tcell.NewEventKey(tcell.KeyCtrlF, 0, tcell.ModNone)
	for _, tc := range []struct {
		name  string
		route func(*App, *tcell.EventKey) *tcell.EventKey
	}{
		{"filter field route", func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerFieldKeys(ev) }},
		{"model table route", func(a *App, ev *tcell.EventKey) *tcell.EventKey { return a.modelPickerKeys()(ev) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			cat := selectedModelCatalog()
			applier := &providerModelApplierFake{}
			fav := &favoriteFake{
				snapshot: []ModelFavorite{{Provider: "anthropic", ModelID: "claude-x"}},
				next:     []ModelFavorite{{Provider: "anthropic", ModelID: "claude-x"}, {Provider: "openai", ModelID: "gpt-5"}},
			}
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: applier, Favorites: fav.list, ToggleFavorite: fav.toggle})
			a.openModelPicker()
			selectModelRow(t, a.modelPicker, "gpt-5")

			if ret := tc.route(a, ctrlF); ret != nil {
				t.Errorf("Ctrl-F not consumed: returned %v, want nil", ret)
			}
			if fav.toggleCalls != 1 || fav.gotProvider != "openai" || fav.gotID != "gpt-5" {
				t.Fatalf("toggle = %d call(s) with (%q,%q), want 1 with (openai,gpt-5)", fav.toggleCalls, fav.gotProvider, fav.gotID)
			}
			if !a.modelPickerOpen {
				t.Error("picker closed after Ctrl-F; it must stay open")
			}
			if applier.calls != 0 {
				t.Errorf("Apply calls = %d, want 0 (favorite toggle never confirms a model)", applier.calls)
			}
			if !reflect.DeepEqual(a.modelPicker.favorites, fav.next) {
				t.Errorf("session favorites = %v, want the returned snapshot %v", a.modelPicker.favorites, fav.next)
			}
			want := []string{
				"Favorites", "anthropic · claude-x", "openai · gpt-5", "",
				"openai", "gpt-5", "gpt-5-mini", "",
				"anthropic", "claude-x",
			}
			if got := tableTexts(a.modelPicker.table); !reflect.DeepEqual(got, want) {
				t.Errorf("table after toggle = %v, want %v", got, want)
			}
			row, _ := a.modelPicker.table.GetSelection()
			if got := a.modelPicker.table.GetCell(row, 0).Text; got != "gpt-5" {
				t.Errorf("highlight after toggle = %q, want the gpt-5 group row", got)
			}
		})
	}
}

func TestModelPicker_FavoriteToggleErrorPreservesState(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	wantErr := errors.New("could not save favorite")
	fav := &favoriteFake{
		snapshot: []ModelFavorite{{Provider: "anthropic", ModelID: "claude-x"}},
		next:     []ModelFavorite{{Provider: "anthropic", ModelID: "claude-x"}, {Provider: "openai", ModelID: "gpt-5"}},
		err:      wantErr,
	}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, Favorites: fav.list, ToggleFavorite: fav.toggle})
	a.openModelPicker()
	a.onModelFilterChanged("gpt-5")
	sess := a.modelPicker
	rowsBefore := append([]ProviderModel(nil), sess.rows...)
	favsBefore := append([]ModelFavorite(nil), sess.favorites...)
	textsBefore := tableTexts(sess.table)
	selBefore, _ := sess.table.GetSelection()

	if ret := a.modelPickerFieldKeys(tcell.NewEventKey(tcell.KeyCtrlF, 0, tcell.ModNone)); ret != nil {
		t.Errorf("Ctrl-F not consumed on error, returned %v", ret)
	}

	if fav.toggleCalls != 1 {
		t.Fatalf("toggle calls = %d, want 1", fav.toggleCalls)
	}
	if a.transcript.notice != wantErr.Error() {
		t.Errorf("notice = %q, want the surfaced toggle error %q", a.transcript.notice, wantErr.Error())
	}
	if !reflect.DeepEqual(sess.rows, rowsBefore) {
		t.Errorf("rows changed on toggle error = %v, want unchanged", sess.rows)
	}
	if !reflect.DeepEqual(sess.favorites, favsBefore) {
		t.Errorf("favorites snapshot changed on toggle error = %v, want unchanged %v", sess.favorites, favsBefore)
	}
	if !reflect.DeepEqual(tableTexts(sess.table), textsBefore) {
		t.Errorf("visible rows changed on toggle error = %v, want %v", tableTexts(sess.table), textsBefore)
	}
	if sess.query != "gpt-5" {
		t.Errorf("query = %q, want it unchanged (gpt-5)", sess.query)
	}
	if sel, _ := sess.table.GetSelection(); sel != selBefore {
		t.Errorf("selection moved to row %d on toggle error, want %d", sel, selBefore)
	}
}

func TestModelPicker_OpeningHighlightPrefersFirstFavorite(t *testing.T) {
	for _, tc := range []struct {
		name     string
		favs     []ModelFavorite
		active   bool
		wantText string
		wantID   string
	}{
		{
			name:     "favorites, no active model",
			favs:     []ModelFavorite{{Provider: "anthropic", ModelID: "claude-x"}},
			wantText: "anthropic · claude-x",
			wantID:   "claude-x",
		},
		{
			name:     "favorites, active model is the second favorite",
			favs:     []ModelFavorite{{Provider: "anthropic", ModelID: "claude-x"}, {Provider: "openai", ModelID: "gpt-5"}},
			active:   true,
			wantText: "anthropic · claude-x",
			wantID:   "claude-x",
		},
		{
			name:     "favorites, active model is not a favorite",
			favs:     []ModelFavorite{{Provider: "openai", ModelID: "gpt-5-mini"}},
			active:   true,
			wantText: "openai · gpt-5-mini",
			wantID:   "gpt-5-mini",
		},
		{
			name:     "no favorites, active model",
			active:   true,
			wantText: "gpt-5",
			wantID:   "gpt-5",
		},
		{
			name:     "no favorites, no active model",
			wantText: "gpt-5",
			wantID:   "gpt-5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			cat := selectedModelCatalog()
			cat.selected = tc.active
			favs := tc.favs
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, Favorites: func() []ModelFavorite { return favs }})
			a.openModelPicker()

			sess := a.modelPicker
			row, _ := sess.table.GetSelection()
			if got := sess.table.GetCell(row, 0).Text; got != tc.wantText {
				t.Errorf("opening highlight text = %q, want %q", got, tc.wantText)
			}
			if got := selectedModelID(sess); got != tc.wantID {
				t.Errorf("opening highlight model = %q, want %q", got, tc.wantID)
			}
		})
	}
}

func TestModelPicker_OpeningFavoriteSeedsEffortHeaderAndRefresh(t *testing.T) {
	a := New(nil)
	cat := selectedModelCatalog()
	fake := &refreshCatalogFake{}
	favs := []ModelFavorite{{Provider: "anthropic", ModelID: "claude-x"}}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh, Favorites: func() []ModelFavorite { return favs }})
	a.openModelPicker()

	sess := a.modelPicker
	if got := selectedModelID(sess); got != "claude-x" {
		t.Fatalf("opening highlight = %q, want the favorite claude-x", got)
	}
	if !reflect.DeepEqual(fake.providers(), []string{"anthropic"}) {
		t.Errorf("opening refresh requests = %v, want only [anthropic] (the highlighted favorite's provider)", fake.providers())
	}
	if !reflect.DeepEqual(sess.supported, []string{"default"}) {
		t.Errorf("supported efforts = %v, want claude-x's [default], not the displaced openai/gpt-5 set", sess.supported)
	}
	if sess.effort != "default" {
		t.Errorf("seeded effort = %q, want default (the in-memory medium is unsupported by claude-x)", sess.effort)
	}
	if got := sess.effortView.GetText(false); !strings.Contains(got, "default") {
		t.Errorf("effort view = %q, want it to show default", got)
	}
	if off, _ := sess.table.GetOffset(); off != 0 {
		t.Errorf("table offset = %d, want 0 so the Favorites header stays visible", off)
	}
}

func TestModelPicker_FooterAdvertisesCtrlF(t *testing.T) {
	if !strings.Contains(modelPickerFooterHint, "Ctrl-F favorite") {
		t.Errorf("footer hint = %q, want it to advertise Ctrl-F for favorites", modelPickerFooterHint)
	}
}

func TestModelPicker_DismissKeepsNoticeItDoesNotOwn(t *testing.T) {
	a := New(nil)
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: &providerModelApplierFake{}})
	a.openModelPicker()
	a.Notice("unrelated notice")

	a.dismissModelPicker()

	if a.transcript.notice != "unrelated notice" {
		t.Errorf("notice = %q, want the unrelated notice preserved by a non-refresh-owning dismissal", a.transcript.notice)
	}
}

func TestModelPicker_DismissRestoresCapturedFocus(t *testing.T) {
	a := New(nil)
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: &providerModelApplierFake{}})
	before := tview.NewBox()
	a.app.SetFocus(before)

	a.openModelPicker()
	if a.modelPickerPrev != before {
		t.Fatalf("captured prior focus = %T, want the primitive focused at open", a.modelPickerPrev)
	}

	a.dismissModelPicker()

	if a.app.GetFocus() != before {
		t.Errorf("focus = %T, want the primitive focused before the picker opened", a.app.GetFocus())
	}
	if a.modelPickerPrev != nil {
		t.Error("prior focus not cleared after dismissal")
	}

	elsewhere := tview.NewBox()
	a.app.SetFocus(elsewhere)
	a.dismissModelPicker()

	if a.app.GetFocus() != elsewhere {
		t.Errorf("focus after a second dismissal = %T, want it left where it was", a.app.GetFocus())
	}
	if a.modelPickerOpen || a.pages.HasPage(modelPickerPage) {
		t.Error("picker re-mounted by a second dismissal")
	}
}

func TestModelPicker_DismissKeepsRefreshOffTheNotice(t *testing.T) {
	a := New(nil)
	cat := refreshRebuildCatalog()
	fake := &refreshCatalogFake{}
	a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
	a.openModelPicker()
	sess := a.modelPicker

	if got := pickerStatusText(sess); got != modelRefreshingStatus("openai") {
		t.Fatalf("after open, status = %q, want %q", got, modelRefreshingStatus("openai"))
	}
	if a.transcript.notice != "" {
		t.Fatalf("in-flight refresh set the notice to %q, want it left alone", a.transcript.notice)
	}
	staleCall := fake.calls[0]
	a.Notice("session write failed: disk full")

	a.dismissModelPicker()
	if a.transcript.notice != "session write failed: disk full" {
		t.Errorf("notice after dismissal = %q, want the unrelated notice to survive the close", a.transcript.notice)
	}
	if got := a.ModelPickerStatusText(); got != "" {
		t.Errorf("status text with no picker open = %q, want empty", got)
	}

	staleCall.complete(ModelRefreshResult{Provider: "openai", Outcome: ModelRefreshFailed})
	if a.transcript.notice != "session write failed: disk full" {
		t.Errorf("notice after late completion = %q, want it unchanged", a.transcript.notice)
	}
}
