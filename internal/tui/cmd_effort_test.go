// Tests for the /effort handler: no-selection
// refusal, /supported-set validation with the pinned error text and
// slash_command{outcome:error}, and the valid-level apply path — all driven
// through injected EffortModel/EffortApplier fakes so the handler is exercised
// without the internal/model wiring.
package tui

import (
	"errors"
	"strings"
	"testing"
)

// effortModelFake is an in-memory EffortModel. selected=false models the
// no-selection refusal path; supported is the set returned for the active model.
type effortModelFake struct {
	provider  string
	modelID   string
	effort    string
	selected  bool
	supported []string
}

func (m *effortModelFake) ActiveSelection() (string, string, string, bool) {
	return m.provider, m.modelID, m.effort, m.selected
}

func (m *effortModelFake) SupportedEfforts(provider, modelID string) []string {
	return m.supported
}

// effortApplierFake records the level Apply was called with and returns a
// preset result/error so handler behavior can be asserted without persistence.
type effortApplierFake struct {
	calls  int
	gotLvl string
	result EffortApplyResult
	err    error
}

func (a *effortApplierFake) Apply(level string) (EffortApplyResult, error) {
	a.calls++
	a.gotLvl = level
	return a.result, a.err
}

func selectedModel() *effortModelFake {
	return &effortModelFake{
		provider:  "openai",
		modelID:   "gpt-5",
		effort:    "medium",
		selected:  true,
		supported: []string{"minimal", "low", "medium", "high"},
	}
}

// dispatchEffort builds a one-command registry for /effort and dispatches input.
func dispatchEffort(t *testing.T, deps EffortDeps, input string) (*fakeHost, DispatchResult) {
	t.Helper()
	host := newFakeHost()
	reg, err := NewRegistry([]Command{
		{Name: "effort", Description: "Set the active reasoning effort", ArgSig: ArgOneOptional, Phase: PhaseOne, Handler: NewEffortHandler(deps)},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return host, reg.DispatchSlashInput(input, host)
}

func TestEffort_ValidLevelApplies(t *testing.T) {
	applier := &effortApplierFake{}
	host, res := dispatchEffort(t, EffortDeps{Model: selectedModel(), Applier: applier}, "/effort high")

	if res.Status != StatusHandled || res.Canonical != "effort" || res.Err != nil {
		t.Fatalf("dispatch = %+v, want Handled/effort/nil-err", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true on success, want false (input is cleared)")
	}
	if applier.calls != 1 || applier.gotLvl != "high" {
		t.Errorf("Apply calls=%d level=%q, want 1 call with %q", applier.calls, applier.gotLvl, "high")
	}
	// Exactly one slash_command success event, no notice.
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "effort" || p.Outcome != "success" || p.ErrorDetail != "" || !equalStrings(p.Args, []string{"high"}) {
		t.Errorf("event = %+v, want name=effort args=[high] outcome=success error_detail=\"\"", p)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none on a clean apply", host.notices)
	}
}

// The /effort tests below intentionally mirror the /model tests in cmd_model_test.go
// (BareOpensPicker, NoSelectionRefuses, CreatedMarkerGivesNoNotice, ApplyErrorSurfaces). The
// duplication is deliberate: it pins the two slash commands in lockstep so a reviewer
// sees both sides change together. Do NOT fold these into a shared helper — that would
// hide the parity the duplication documents (dupl groups 3, 4, 13, 19, 51).
func TestEffort_BareOpensPickerAndRecordsNoEvent(t *testing.T) {
	// Bare /effort routes to the picker opener and records no slash_command,
	// matching the CTRL-E key path. The input is not retained, so the
	// submit adapter clears it.
	var opened int
	applier := &effortApplierFake{}
	deps := EffortDeps{Model: selectedModel(), Applier: applier, OpenPicker: func() { opened++ }}
	host, res := dispatchEffort(t, deps, "/effort")

	if res.Status != StatusHandled || res.Canonical != "effort" || res.Err != nil {
		t.Fatalf("dispatch /effort = %+v, want Handled/effort/nil-err", res)
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
		t.Errorf("bare /effort appended %d slash_command events, want 0 (matches CTRL-E)", len(evs))
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none (the opener owns any notice)", host.notices)
	}
}

func TestEffort_BareNoModelSelectedMatchesCtrlE(t *testing.T) {
	// With no model selected, bare /effort delegates to the same opener CTRL-E
	// drives: it renders the no-model-selected notice, opens no picker, records no
	// slash_command, and retains no input. The opener is the real App.OpenEffortPicker
	// so the notice comes from the picker, not the handler.
	a := New(nil)
	a.SetEffortDeps(EffortDeps{Model: &effortModelFake{selected: false}, Applier: &effortApplierFake{}})
	deps := EffortDeps{Model: &effortModelFake{selected: false}, Applier: &effortApplierFake{}, OpenPicker: a.OpenEffortPicker}
	host, res := dispatchEffort(t, deps, "/effort")

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /effort = %+v, want Handled/nil-err", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true, want false (CTRL-E parity: no input retention)")
	}
	if a.effortPickerOpen {
		t.Error("picker opened despite no in-memory model selection")
	}
	if a.transcript.notice != noModelSelectedNotice {
		t.Errorf("notice = %q, want %q", a.transcript.notice, noModelSelectedNotice)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("no-model bare /effort appended %d slash_command events, want 0", len(evs))
	}
}

func TestEffort_BareNilOpenerIsInert(t *testing.T) {
	// A nil OpenPicker (deps not wired) leaves the bare path inert: no panic, no
	// event, no input retention.
	host, res := dispatchEffort(t, EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}}, "/effort")

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /effort = %+v, want Handled/nil-err", res)
	}
	if res.RetainInput {
		t.Error("RetainInput = true with a nil opener, want false")
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("bare /effort with nil opener appended %d events, want 0", len(evs))
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none with a nil opener", host.notices)
	}
}

func TestEffort_TooManyArgsWrongArity(t *testing.T) {
	// Two arguments still fail arity (ArgOneOptional accepts zero or one): the
	// dispatcher rejects before the handler, retaining input and recording no event.
	var opened int
	applier := &effortApplierFake{}
	deps := EffortDeps{Model: selectedModel(), Applier: applier, OpenPicker: func() { opened++ }}
	host, res := dispatchEffort(t, deps, "/effort high extra")

	if res.Status != StatusWrongArity || res.Canonical != "effort" {
		t.Fatalf("dispatch /effort high extra = %+v, want StatusWrongArity/effort", res)
	}
	if !res.RetainInput {
		t.Error("RetainInput = false on the too-many-args path, want true (req 565)")
	}
	if opened != 0 || applier.calls != 0 {
		t.Errorf("handler ran on a wrong-arity input: OpenPicker=%d Apply=%d, want 0/0", opened, applier.calls)
	}
	if evs := host.events(); len(evs) != 0 {
		t.Errorf("wrong-arity /effort appended %d events, want 0 (req 570)", len(evs))
	}
}

func TestEffort_LiteralDefaultIsValidWhenAdvertised(t *testing.T) {
	model := selectedModel()
	model.supported = []string{"default"}
	applier := &effortApplierFake{}
	_, res := dispatchEffort(t, EffortDeps{Model: model, Applier: applier}, "/effort default")

	if res.Err != nil || applier.calls != 1 {
		t.Fatalf("dispatch /effort default = %+v, applier calls=%d, want handled with 1 apply", res, applier.calls)
	}
}

func TestEffort_AdvertisedTokensOutsideTheOldEnumApply(t *testing.T) {
	for _, level := range []string{"max", "ultra", "default"} {
		t.Run(level, func(t *testing.T) {
			model := selectedModel()
			model.supported = []string{"max", "ultra", "default"}
			applier := &effortApplierFake{}
			host, res := dispatchEffort(t, EffortDeps{Model: model, Applier: applier}, "/effort "+level)

			if res.Err != nil || res.RetainInput {
				t.Fatalf("dispatch /effort %s = %+v, want handled with no input retention", level, res)
			}
			if applier.calls != 1 || applier.gotLvl != level {
				t.Fatalf("Apply calls=%d level=%q, want 1 call with %q", applier.calls, applier.gotLvl, level)
			}
			if len(host.notices) != 0 {
				t.Errorf("notices = %v, want none for an advertised token", host.notices)
			}
		})
	}
}

func TestEffort_AdvertisedTokenRejectedWhenModelDoesNotAdvertiseIt(t *testing.T) {
	model := selectedModel()
	model.supported = []string{"low", "medium", "high"}
	applier := &effortApplierFake{}
	host, res := dispatchEffort(t, EffortDeps{Model: model, Applier: applier}, "/effort max")

	if !res.RetainInput {
		t.Error("RetainInput = false, want true so the user can edit and retry")
	}
	if applier.calls != 0 {
		t.Errorf("Apply called %d times for an unadvertised token, want 0", applier.calls)
	}
	want := "unsupported effort max; supported efforts: low, medium, high"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Errorf("notices = %v, want exactly [%q]", host.notices, want)
	}
}

func TestEffort_NoReasoningAcceptedRegardlessOfAdvertisedSet(t *testing.T) {
	model := selectedModel()
	model.supported = []string{"low", "medium", "high"}
	applier := &effortApplierFake{}
	_, res := dispatchEffort(t, EffortDeps{Model: model, Applier: applier}, "/effort no-reasoning")

	if res.Err != nil || res.RetainInput {
		t.Fatalf("dispatch /effort no-reasoning = %+v, want handled with no input retention", res)
	}
	if applier.calls != 1 || applier.gotLvl != "no-reasoning" {
		t.Errorf("Apply calls=%d level=%q, want 1 call with %q", applier.calls, applier.gotLvl, "no-reasoning")
	}
}

func TestEffort_NoSelectionRefuses(t *testing.T) {
	model := &effortModelFake{selected: false}
	applier := &effortApplierFake{}
	host, res := dispatchEffort(t, EffortDeps{Model: model, Applier: applier}, "/effort high")

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

func TestEffort_UnsupportedValueRejected(t *testing.T) {
	cases := []struct {
		name  string
		level string
	}{
		{"unadvertised-known-token", "minimal"},
		{"unadvertised-unknown-token", "turbo"},
		{"unadvertised-literal-default", "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model := selectedModel()
			model.supported = []string{"low", "medium", "high"}
			applier := &effortApplierFake{}
			host, res := dispatchEffort(t, EffortDeps{Model: model, Applier: applier}, "/effort "+tc.level)

			if res.Status != StatusHandled || res.Err != nil {
				t.Fatalf("dispatch = %+v, want Handled/nil-err", res)
			}
			if !res.RetainInput {
				t.Error("RetainInput = false, want true (req 575)")
			}
			if applier.calls != 0 {
				t.Errorf("Apply called %d times on an invalid value, want 0", applier.calls)
			}
			want := "unsupported effort " + tc.level + "; supported efforts: low, medium, high"
			if len(host.notices) != 1 || host.notices[0] != want {
				t.Errorf("notices = %v, want exactly [%q]", host.notices, want)
			}
			// the slash_command error_detail carries the same one-line text.
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("appended %d slash_command events, want 1", len(evs))
			}
			p := decodeSlash(t, evs[0])
			if p.Name != "effort" || p.Outcome != "error" || p.ErrorDetail != want {
				t.Errorf("event = %+v, want name=effort outcome=error error_detail=%q", p, want)
			}
			if !equalStrings(p.Args, []string{tc.level}) {
				t.Errorf("event args = %v, want [%q]", p.Args, tc.level)
			}
		})
	}
}

func TestEffort_UnsupportedNoticeRendersSupportedSetInOrder(t *testing.T) {
	model := selectedModel()
	model.supported = []string{"default"}
	host, _ := dispatchEffort(t, EffortDeps{Model: model, Applier: &effortApplierFake{}}, "/effort high")
	want := "unsupported effort high; supported efforts: default"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Errorf("notices = %v, want exactly [%q]", host.notices, want)
	}
}

func TestEffort_CreatedMarkerGivesNoNotice(t *testing.T) {
	for _, result := range []EffortApplyResult{
		{MarkerCreated: true, MarkerPath: "/work/proj/.codemeld/settings.yaml"},
		{MarkerCreated: false},
	} {
		applier := &effortApplierFake{result: result}
		host, res := dispatchEffort(t, EffortDeps{Model: selectedModel(), Applier: applier}, "/effort high")
		if res.Err != nil {
			t.Fatalf("dispatch err = %v, want nil", res.Err)
		}
		if len(host.notices) != 0 {
			t.Errorf("result %+v: notices = %v, want none", result, host.notices)
		}
	}
}

func TestEffort_ApplyErrorSurfacesAfterSuccessEvent(t *testing.T) {
	// An internal apply failure (e.g. a failed event append) is surfaced to the
	// caller; the slash_command success event was already recorded for the
	// recognized, valid invocation.
	wantErr := errors.New("append model_changed: boom")
	applier := &effortApplierFake{err: wantErr}
	host, res := dispatchEffort(t, EffortDeps{Model: selectedModel(), Applier: applier}, "/effort high")

	if !errors.Is(res.Err, wantErr) {
		t.Fatalf("res.Err = %v, want %v", res.Err, wantErr)
	}
	evs := host.events()
	if len(evs) != 1 || decodeSlash(t, evs[0]).Outcome != "success" {
		t.Errorf("want one slash_command success event recorded before the apply error, got %d events", len(evs))
	}
}

func TestRenderCrossModeMarkerNotice_NamesPathAndConsequence(t *testing.T) {
	got := RenderCrossModeMarkerNotice("/a/b/.codemeld/settings.yaml")
	for _, want := range []string{"/a/b/.codemeld/settings.yaml", "project root", "discovery.boundary", "project-root"} {
		if !strings.Contains(got, want) {
			t.Errorf("notice %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "\n") {
		t.Errorf("cross-mode notice must be a single line, got %q", got)
	}
}
