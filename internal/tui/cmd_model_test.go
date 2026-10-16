// Tests for the /model handler: no-selection
// refusal, active-provider allowlist validation with the pinned error text and
// slash_command{outcome:error}, the effort-on-success fallback rule, the
// valid-id apply path — all driven through
// injected ModelCatalog/ModelApplier fakes so the handler is exercised without
// the internal/model wiring (which production wiring owns, mirroring the /effort handler's deferral).
package tui

import (
	"errors"
	"testing"
)

// modelCatalogFake is an in-memory ModelCatalog. selected=false models the
// no-selection refusal path; models is the active provider's allowlist and
// supported is the supported-effort set returned for the supplied (new) model id.
type modelCatalogFake struct {
	provider       string
	modelID        string
	effort         string
	selected       bool
	models         []string
	supported      []string
	gotModelsQuery string // the provider id Models was last asked about
}

func (m *modelCatalogFake) ActiveSelection() (string, string, string, bool) {
	return m.provider, m.modelID, m.effort, m.selected
}

func (m *modelCatalogFake) Models(provider string) []string {
	m.gotModelsQuery = provider
	return m.models
}

func (m *modelCatalogFake) SupportedEfforts(string, string) []string { return m.supported }

// modelApplierFake records the id/effort Apply was called with and returns a
// preset result/error so handler behavior can be asserted without persistence.
type modelApplierFake struct {
	calls     int
	gotID     string
	gotEffort string
	result    ModelApplyResult
	err       error
}

func (a *modelApplierFake) Apply(id, effort string) (ModelApplyResult, error) {
	a.calls++
	a.gotID = id
	a.gotEffort = effort
	return a.result, a.err
}

// selectedCatalog is the default selected-model fixture: provider openai, active
// model gpt-5 at medium effort, with a three-model allowlist. The supplied model
// gpt-5-mini supports all four reasoning levels, so the current effort is kept.
func selectedCatalog() *modelCatalogFake {
	return &modelCatalogFake{
		provider:  "openai",
		modelID:   "gpt-5",
		effort:    "medium",
		selected:  true,
		models:    []string{"gpt-5", "gpt-5-mini", "o3"},
		supported: []string{"minimal", "low", "medium", "high"},
	}
}

// dispatchModel builds a one-command registry for /model and dispatches input.
func dispatchModel(t *testing.T, deps ModelDeps, input string) (*fakeHost, DispatchResult) {
	t.Helper()
	host := newFakeHost()
	reg, err := NewRegistry([]Command{
		{Name: "model", Description: "Set the active model", ArgSig: ArgOneOptional, Phase: PhaseOne, Handler: NewModelHandler(deps)},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return host, reg.DispatchSlashInput(input, host)
}

func TestModel_ValidIDAppliesKeepingSupportedEffort(t *testing.T) {
	applier := &modelApplierFake{}
	host, res := dispatchModel(t, ModelDeps{Model: selectedCatalog(), Applier: applier}, "/model gpt-5-mini")

	if res.Status != StatusHandled || res.Canonical != "model" || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/model/nil-err", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true on success, want false (input is cleared)")
	}
	// Current effort medium is in the new model's supported set, so it is kept.
	if applier.calls != 1 || applier.gotID != "gpt-5-mini" || applier.gotEffort != "medium" {
		t.Errorf("Apply calls=%d id=%q effort=%q, want 1 call with gpt-5-mini/medium", applier.calls, applier.gotID, applier.gotEffort)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "model" || p.Outcome != "success" || p.ErrorDetail != "" || !equalStrings(p.Args, []string{"gpt-5-mini"}) {
		t.Errorf("event = %+v, want name=model args=[gpt-5-mini] outcome=success error_detail=\"\"", p)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none on a clean apply", host.notices)
	}
}

// TestModel_ValidatesAgainstActiveProviderAndStaysOnIt pins active-provider validation at the
// handler layer: with openai-chatgpt active, /model validates the supplied id against
// that provider's allowlist (Models is queried for openai-chatgpt, not openai) and the
// model-only ModelApplier — whose Apply takes no provider — cannot switch providers, so
// a model id shared with openai (gpt-5.5) applies under the active provider only.
func TestModel_ValidatesAgainstActiveProviderAndStaysOnIt(t *testing.T) {
	cat := &modelCatalogFake{
		provider:  "openai-chatgpt",
		modelID:   "gpt-5.5",
		effort:    "medium",
		selected:  true,
		models:    []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark"}, // the openai-chatgpt allowlist
		supported: []string{"none", "low", "medium", "high", "xhigh"},
	}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5.4")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if cat.gotModelsQuery != "openai-chatgpt" {
		t.Errorf("Models queried for %q, want the active provider openai-chatgpt (not openai)", cat.gotModelsQuery)
	}
	if applier.calls != 1 || applier.gotID != "gpt-5.4" {
		t.Errorf("Apply calls=%d id=%q, want one model-only apply of gpt-5.4 on the active provider", applier.calls, applier.gotID)
	}
}

func TestModel_BareOpensPickerAndRecordsNoEvent(t *testing.T) {
	// Bare /model routes to the picker opener and records no slash_command,
	// matching the CTRL-M key path. The input is not retained.
	var opened int
	applier := &modelApplierFake{}
	deps := ModelDeps{Model: selectedCatalog(), Applier: applier, OpenPicker: func() { opened++ }}
	host, res := dispatchModel(t, deps, "/model")

	if res.Status != StatusHandled || res.Canonical != "model" || res.Err != nil {
		t.Fatalf("dispatch /model = %+v, want Handled/model/nil-err", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true on the bare picker-open path, want false (input clears)")
	}
	if opened != 1 {
		t.Errorf("OpenPicker called %d times, want 1", opened)
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times on the bare path, want 0", applier.calls)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("bare /model appended %d slash_command events, want 0 (matches CTRL-M)", len(evs))
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none on the bare path", host.notices)
	}
}

func TestModel_BareNilOpenerIsInert(t *testing.T) {
	// A nil OpenPicker (deps not wired) leaves the bare path inert: no panic, no
	// event, no input retention.
	host, res := dispatchModel(t, ModelDeps{Model: selectedCatalog(), Applier: &modelApplierFake{}}, "/model")

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /model = %+v, want Handled/nil-err", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true with a nil opener, want false")
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("bare /model with nil opener appended %d events, want 0", len(evs))
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none with a nil opener", host.notices)
	}
}

func TestModel_TooManyArgsWrongArity(t *testing.T) {
	// Two arguments still fail arity (ArgOneOptional accepts zero or one): the
	// dispatcher rejects before the handler, retaining input and recording no event.
	var opened int
	applier := &modelApplierFake{}
	deps := ModelDeps{Model: selectedCatalog(), Applier: applier, OpenPicker: func() { opened++ }}
	host, res := dispatchModel(t, deps, "/model gpt-5 extra")

	if res.Status != StatusWrongArity || res.Canonical != "model" {
		t.Fatalf("dispatch /model gpt-5 extra = %+v, want StatusWrongArity/model", res)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false on the too-many-args path, want true (req 565)")
	}
	if opened != 0 || applier.calls != 0 {
		t.Errorf("handler ran on a wrong-arity input: OpenPicker=%d Apply=%d, want 0/0", opened, applier.calls)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("wrong-arity /model appended %d events, want 0 (req 570)", len(evs))
	}
}

func TestModel_OutOfSupportedEffortSelectsFirstAdvertised(t *testing.T) {
	cat := selectedCatalog()
	cat.effort = "minimal"
	cat.supported = []string{"high", "medium", "low"}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if applier.calls != 1 || applier.gotEffort != "high" {
		t.Errorf("Apply calls=%d effort=%q, want 1 call with effort high (first advertised)", applier.calls, applier.gotEffort)
	}
}

func TestModel_FallbackSelectsAdvertisedDefaultAsProviderToken(t *testing.T) {
	cat := selectedCatalog()
	cat.effort = "minimal"
	cat.supported = []string{"default", "low"}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if applier.calls != 1 || applier.gotEffort != "default" {
		t.Errorf("Apply calls=%d effort=%q, want 1 call with effort default (first advertised)", applier.calls, applier.gotEffort)
	}
}

func TestModel_NoCapabilityModelSelectsNoReasoning(t *testing.T) {
	cat := selectedCatalog()
	cat.supported = []string{effortNoReasoning}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if applier.calls != 1 || applier.gotEffort != effortNoReasoning {
		t.Errorf("Apply calls=%d effort=%q, want 1 call with effort %s", applier.calls, applier.gotEffort, effortNoReasoning)
	}
}

func TestModel_RetainsNoReasoningAcrossModelChange(t *testing.T) {
	cat := selectedCatalog()
	cat.effort = effortNoReasoning
	cat.supported = []string{"low", "high"}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if applier.calls != 1 || applier.gotEffort != effortNoReasoning {
		t.Errorf("Apply calls=%d effort=%q, want 1 call retaining %s", applier.calls, applier.gotEffort, effortNoReasoning)
	}
}

func TestModel_RetainsAdvertisedDefaultToken(t *testing.T) {
	cat := selectedCatalog()
	cat.effort = "default"
	cat.supported = []string{"low", "default", "high"}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if applier.calls != 1 || applier.gotEffort != "default" {
		t.Errorf("Apply calls=%d effort=%q, want 1 call retaining default", applier.calls, applier.gotEffort)
	}
}

func TestModelSelectionEffortFallback_EmptyAdvertisedSet(t *testing.T) {
	if got := modelSelectionEffortFallback(nil); got != effortNoReasoning {
		t.Errorf("modelSelectionEffortFallback(nil) = %q, want %q", got, effortNoReasoning)
	}
}

func TestModel_UnadvertisedDefaultIsNotRetained(t *testing.T) {
	cat := selectedCatalog()
	cat.effort = "default"
	cat.supported = []string{"low", "high"}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if applier.calls != 1 || applier.gotEffort != "low" {
		t.Errorf("Apply calls=%d effort=%q, want 1 call with effort low (first advertised)", applier.calls, applier.gotEffort)
	}
}

func TestModel_DefaultOnlyModelPicksDefaultEffort(t *testing.T) {
	// The supplied model supports only the {default} sentinel, and the current
	// effort (medium) is unsupported there, so the effort falls back to default.
	cat := selectedCatalog()
	cat.supported = []string{"default"}
	applier := &modelApplierFake{}
	_, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if applier.calls != 1 || applier.gotEffort != "default" {
		t.Errorf("Apply calls=%d effort=%q, want 1 call with effort default", applier.calls, applier.gotEffort)
	}
}

func TestModel_NoSelectionRefuses(t *testing.T) {
	cat := &modelCatalogFake{selected: false}
	applier := &modelApplierFake{}
	host, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-5-mini")

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err", res)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false, want true so the user can edit and retry")
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times on the no-selection path, want 0", applier.calls)
	}
	if len(host.notices) != 1 || host.notices[0] != noModelSelectedNotice {
		t.Errorf("notices = %v, want exactly [%q]", host.notices, noModelSelectedNotice)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1 (req 570: the handler was reached)", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Outcome != "error" || p.ErrorDetail != noModelSelectedNotice {
		t.Errorf("event = %+v, want outcome=error error_detail=%q", p, noModelSelectedNotice)
	}
}

func TestModel_UnsupportedIDRejected(t *testing.T) {
	cat := selectedCatalog()
	applier := &modelApplierFake{}
	host, res := dispatchModel(t, ModelDeps{Model: cat, Applier: applier}, "/model gpt-9")

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/nil-err", res)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false, want true (req 575)")
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times on an invalid id, want 0", applier.calls)
	}
	want := "unsupported model gpt-9; supported models: gpt-5, gpt-5-mini, o3"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Errorf("notices = %v, want exactly [%q]", host.notices, want)
	}
	// the slash_command error_detail carries the same one-line text.
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "model" || p.Outcome != "error" || p.ErrorDetail != want {
		t.Errorf("event = %+v, want name=model outcome=error error_detail=%q", p, want)
	}
	if !equalStrings(p.Args, []string{"gpt-9"}) {
		t.Errorf("event args = %v, want [gpt-9]", p.Args)
	}
}

func TestModel_UnsupportedNoticeRendersAllowlistInOrder(t *testing.T) {
	cat := selectedCatalog()
	cat.models = []string{"o3", "gpt-5", "gpt-5-mini"} // allowlist order is preserved verbatim
	host, _ := dispatchModel(t, ModelDeps{Model: cat, Applier: &modelApplierFake{}}, "/model gpt-9")
	want := "unsupported model gpt-9; supported models: o3, gpt-5, gpt-5-mini"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Errorf("notices = %v, want exactly [%q]", host.notices, want)
	}
}

func TestModel_CreatedMarkerGivesNoNotice(t *testing.T) {
	for _, result := range []ModelApplyResult{
		{MarkerCreated: true, MarkerPath: "/work/proj/.codemeld/settings.yaml"},
		{MarkerCreated: false},
	} {
		applier := &modelApplierFake{result: result}
		host, res := dispatchModel(t, ModelDeps{Model: selectedCatalog(), Applier: applier}, "/model gpt-5-mini")
		if res.Err != nil {
			t.Fatalf("dispatch err = %v, want nil", res.Err)
		}
		if len(host.notices) != 0 {
			t.Errorf("result %+v: notices = %v, want none", result, host.notices)
		}
	}
}

// TestModel_SuccessClearsStaleNotice pins the clear-on-model-change for the
// /model command: a successful apply fires the ClearNotice hook (so a stale pinned
// notice is dropped), while validation failures (unsupported id, no selection) must
// NOT clear — rejectModel sets an error notice the user needs to keep reading.
func TestModel_SuccessClearsStaleNotice(t *testing.T) {
	t.Run("valid id clears", func(t *testing.T) {
		var cleared int
		deps := ModelDeps{Model: selectedCatalog(), Applier: &modelApplierFake{}, ClearNotice: func() { cleared++ }}
		_, res := dispatchModel(t, deps, "/model gpt-5-mini")
		if res.Err != nil {
			t.Fatalf("dispatch err = %v, want nil", res.Err)
		}
		if cleared != 1 {
			t.Errorf("ClearNotice called %d times on a successful apply, want 1", cleared)
		}
	})

	t.Run("unsupported id keeps the error notice", func(t *testing.T) {
		var cleared int
		host, res := dispatchModel(t, ModelDeps{Model: selectedCatalog(), Applier: &modelApplierFake{}, ClearNotice: func() { cleared++ }}, "/model gpt-9")
		if res.Err != nil {
			t.Fatalf("dispatch err = %v, want nil", res.Err)
		}
		if cleared != 0 {
			t.Errorf("ClearNotice called %d times on a validation error, want 0 (the error notice must survive)", cleared)
		}
		want := "unsupported model gpt-9; supported models: gpt-5, gpt-5-mini, o3"
		if len(host.notices) != 1 || host.notices[0] != want {
			t.Errorf("notices = %v, want exactly [%q]", host.notices, want)
		}
	})

	t.Run("no model selected keeps the refusal notice", func(t *testing.T) {
		var cleared int
		host, res := dispatchModel(t, ModelDeps{Model: &modelCatalogFake{selected: false}, Applier: &modelApplierFake{}, ClearNotice: func() { cleared++ }}, "/model gpt-5-mini")
		if res.Err != nil {
			t.Fatalf("dispatch err = %v, want nil", res.Err)
		}
		if cleared != 0 {
			t.Errorf("ClearNotice called %d times on the no-selection refusal, want 0", cleared)
		}
		if len(host.notices) != 1 || host.notices[0] != noModelSelectedNotice {
			t.Errorf("notices = %v, want exactly [%q]", host.notices, noModelSelectedNotice)
		}
	})
}

func TestModel_ApplyErrorSurfacesAfterSuccessEvent(t *testing.T) {
	// An internal apply failure (e.g. a failed event append) is surfaced to the
	// caller; the slash_command success event was already recorded for the
	// recognized, valid invocation.
	wantErr := errors.New("append model_changed: boom")
	applier := &modelApplierFake{err: wantErr}
	host, res := dispatchModel(t, ModelDeps{Model: selectedCatalog(), Applier: applier}, "/model gpt-5-mini")

	if !errors.Is(res.Err, wantErr) {
		t.Fatalf("res.Err = %v, want %v", res.Err, wantErr)
	}
	evs := host.events()
	if len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Errorf("want one slash_command success event recorded before the apply error, got %d events", len(evs))
	}
}

// TestBuildRegistry_ModelDispatchesToHandler pins the production
// dispatch wiring: /model goes through NewModelHandler(model) — not recordHandler
// — so a valid id applies the selection via the injected applier and an
// unsupported id is rejected with the command-specific error rather than a
// generic recordHandler success. If the /model builtin entry were
// left on recordHandler, the applier would never run and the invalid id would
// still record success, so both halves below would fail.
func TestBuildRegistry_ModelDispatchesToHandler(t *testing.T) {
	// Only /model is bound to its real handler; every other command keeps the
	// recordHandler placeholder.
	applier := &modelApplierFake{}
	reg := BuildRegistry(map[string]HandlerFunc{"model": NewModelHandler(ModelDeps{Model: selectedCatalog(), Applier: applier})})

	host := newFakeHost()
	res := reg.DispatchSlashInput("/model gpt-5-mini", host)
	if res.Status != StatusHandled || res.Canonical != "model" || res.Err != nil {
		t.Fatalf("dispatch /model = %+v, want Handled/model/nil-err", res)
	}
	// Current effort medium is supported by the new model, so it is kept; a
	// recordHandler wiring would leave applier.calls at 0.
	if applier.calls != 1 || applier.gotID != "gpt-5-mini" || applier.gotEffort != "medium" {
		t.Errorf("Apply calls=%d id=%q effort=%q, want 1 call with gpt-5-mini/medium", applier.calls, applier.gotID, applier.gotEffort)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "model" || p.Outcome != "success" || p.ErrorDetail != "" {
		t.Errorf("event = %+v, want name=model outcome=success error_detail=\"\"", p)
	}

	// Invalid id through the same production registry: command-specific validation
	// rejects it (recordHandler would instead record success and never validate).
	rejectApplier := &modelApplierFake{}
	rejectReg := BuildRegistry(map[string]HandlerFunc{"model": NewModelHandler(ModelDeps{Model: selectedCatalog(), Applier: rejectApplier})})
	rejectHost := newFakeHost()
	rejectRes := rejectReg.DispatchSlashInput("/model gpt-9", rejectHost)
	if rejectRes.Status != StatusHandled || rejectRes.Canonical != "model" || rejectRes.Err != nil {
		t.Fatalf("dispatch /model gpt-9 = %+v, want Handled/model/nil-err", rejectRes)
	}
	if rejectApplier.calls != 0 {
		t.Errorf("Apply called %d times on an invalid id, want 0 (recordHandler would not validate)", rejectApplier.calls)
	}
	want := "unsupported model gpt-9; supported models: gpt-5, gpt-5-mini, o3"
	revs := rejectHost.events()
	if len(revs) != 1 {
		t.Fatalf("appended %d slash_command events for invalid id, want 1", len(revs))
	}
	if p := decodeSlash(t, revs[0]); p.Outcome != "error" || p.ErrorDetail != want {
		t.Errorf("event = %+v, want outcome=error error_detail=%q", p, want)
	}
}
