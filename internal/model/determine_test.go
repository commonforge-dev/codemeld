// Path coverage, recovery-event assertions, and selectable-model diagnostics for selection.
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

func cacheWith(t *testing.T, model map[string]any) *config.Cache {
	t.Helper()
	return fixtureCache(t, true, model)
}

func bareCacheWith(t *testing.T, model map[string]any) *config.Cache {
	t.Helper()
	return fixtureCache(t, false, model)
}

// validResumePayload is a well-formed model_turn payload (on-wire field model_id).
func validResumePayload() map[string]any {
	return map[string]any{"provider": "openai", "model_id": "gpt-5.5", "effort": "high"}
}

// validDiskSelection is a well-formed model.active/last_used value (on-disk field
// id), using a distinct id from validResumePayload so source precedence is
// observable.
func validDiskSelection() map[string]any {
	return map[string]any{"provider": "openai", "id": "gpt-5.5-pro", "effort": "low"}
}

func modelTurnEvent(t *testing.T, payload map[string]any) sessions.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal model_turn payload: %v", err)
	}
	return sessions.Event{Kind: events.KindModelTurn, Payload: data}
}

func resumeStore(records ...sessions.Record) *sessions.Store {
	sess := &sessions.Session{Records: slices.Clone(records)}
	return sessions.New("/sessions/active.json", sess)
}

// recoveryEvents returns every model_recovery_failed payload appended to store.
func recoveryEvents(t *testing.T, store *sessions.Store) []events.ModelRecoveryFailed {
	t.Helper()
	var out []events.ModelRecoveryFailed
	for _, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindModelRecoveryFailed {
			continue
		}
		var p events.ModelRecoveryFailed
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("unmarshal model_recovery_failed: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func TestDetermineSelection_ResumeClean(t *testing.T) {
	// model.active is present and different; a clean resume must take precedence.
	store := resumeStore(modelTurnEvent(t, validResumePayload()))
	var warn bytes.Buffer
	ctx := Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &warn,
	}
	sel, src, err := DetermineSelection(ctx)
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceResume {
		t.Fatalf("source = %q, want %q", src, SourceResume)
	}
	if sel == nil || sel.Provider != "openai" || sel.ID != "gpt-5.5" || sel.Effort != "high" {
		t.Fatalf("selection = %+v, want openai/gpt-5.5/high", sel)
	}
	if got := recoveryEvents(t, store); len(got) != 0 {
		t.Fatalf("recovery events = %d, want 0 on clean resume", len(got))
	}
	if warn.Len() != 0 {
		t.Fatalf("warning = %q, want empty on clean resume", warn.String())
	}
}

func TestDetermineSelection_ResumeNoModelTurn(t *testing.T) {
	// A non-model_turn record is not a recovery failure: no event, fall to step 2.
	other := sessions.Event{Kind: events.KindLaunchBegan, Payload: json.RawMessage(`{"source":"resume"}`)}
	store := resumeStore(other)
	ctx := Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &bytes.Buffer{},
	}
	sel, src, err := DetermineSelection(ctx)
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceProject || sel == nil || sel.ID != "gpt-5.5-pro" {
		t.Fatalf("got (%+v, %q), want project gpt-5.5-pro", sel, src)
	}
	if got := recoveryEvents(t, store); len(got) != 0 {
		t.Fatalf("recovery events = %d, want 0 when no model_turn present", len(got))
	}
}

func TestDetermineSelection_ResumeShapeFailureFallsBackToProject(t *testing.T) {
	bad := map[string]any{"provider": "openai", "model_id": "gpt-5.5"} // effort absent
	store := resumeStore(modelTurnEvent(t, bad))
	var warn bytes.Buffer
	ctx := Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &warn,
	}
	sel, src, err := DetermineSelection(ctx)
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceProject || sel == nil || sel.ID != "gpt-5.5-pro" {
		t.Fatalf("got (%+v, %q), want project gpt-5.5-pro after recovery failure", sel, src)
	}
	got := recoveryEvents(t, store)
	if len(got) != 1 {
		t.Fatalf("recovery events = %d, want 1", len(got))
	}
	if got[0].Reason != "shape_check_failed" {
		t.Fatalf("reason = %q, want shape_check_failed", got[0].Reason)
	}
	if !strings.Contains(got[0].ErrorDetail, "effort") {
		t.Fatalf("error_detail = %q, want it to name the missing effort field", got[0].ErrorDetail)
	}
	if !strings.Contains(warn.String(), "cannot recover model") {
		t.Fatalf("warning = %q, want recovery warning", warn.String())
	}
}

func TestDetermineSelection_ResumeRecoveryReasons(t *testing.T) {
	tests := []struct {
		name       string
		payload    map[string]any
		wantReason string
		wantDetail string
	}{
		{"missing provider", map[string]any{"model_id": "gpt-5.5", "effort": "high"}, "shape_check_failed", "provider"},
		{"missing model_id", map[string]any{"provider": "openai", "effort": "high"}, "shape_check_failed", "model_id"},
		{"missing effort", map[string]any{"provider": "openai", "model_id": "gpt-5.5"}, "shape_check_failed", "effort"},
		{"provider wrong type", map[string]any{"provider": 1, "model_id": "gpt-5.5", "effort": "high"}, "shape_check_failed", "provider"},
		{"provider unknown", map[string]any{"provider": "anthropic", "model_id": "gpt-5.5", "effort": "high"}, "validation_failed", "anthropic"},
		{"model not allowed", map[string]any{"provider": "openai", "model_id": "gpt-9", "effort": "high"}, "validation_failed", "gpt-9"},
		{"effort not advertised", map[string]any{"provider": "openai", "model_id": "gpt-5.5", "effort": "ultra"}, "validation_failed", "ultra"},
		{"empty provider", map[string]any{"provider": "", "model_id": "gpt-5.5", "effort": "high"}, "shape_check_failed", "provider"},
		{"empty model_id", map[string]any{"provider": "openai", "model_id": "", "effort": "high"}, "shape_check_failed", "model_id"},
		{"empty effort", map[string]any{"provider": "openai", "model_id": "gpt-5.5", "effort": ""}, "shape_check_failed", "effort"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := resumeStore(modelTurnEvent(t, tt.payload))
			ctx := Context{
				Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
				Resume:        true,
				ResumeRecords: store.Records(),
				Store:         store,
				Warn:          &bytes.Buffer{},
			}
			if _, _, err := DetermineSelection(ctx); err != nil {
				t.Fatalf("DetermineSelection() error = %v", err)
			}
			got := recoveryEvents(t, store)
			if len(got) != 1 {
				t.Fatalf("recovery events = %d, want 1", len(got))
			}
			if got[0].Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got[0].Reason, tt.wantReason)
			}
			if !strings.Contains(got[0].ErrorDetail, tt.wantDetail) {
				t.Fatalf("error_detail = %q, want it to contain %q", got[0].ErrorDetail, tt.wantDetail)
			}
		})
	}
}

func TestDetermineSelection_ResumeNonObjectPayload(t *testing.T) {
	store := resumeStore(sessions.Event{Kind: events.KindModelTurn, Payload: json.RawMessage(`["not-an-object"]`)})
	ctx := Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &bytes.Buffer{},
	}
	if _, src, err := DetermineSelection(ctx); err != nil || src != SourceProject {
		t.Fatalf("got (src %q, err %v), want project / nil", src, err)
	}
	got := recoveryEvents(t, store)
	if len(got) != 1 || got[0].Reason != "shape_check_failed" {
		t.Fatalf("recovery events = %+v, want one shape_check_failed", got)
	}
}

func TestDetermineSelection_ResumeMostRecentModelTurnWins(t *testing.T) {
	// An earlier valid turn followed by a later invalid one: the later (invalid)
	// turn is the one recovered, so recovery fails rather than restoring the older.
	older := modelTurnEvent(t, validResumePayload())
	newer := modelTurnEvent(t, map[string]any{"provider": "openai", "model_id": "gpt-9", "effort": "high"})
	store := resumeStore(older, newer)
	ctx := Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &bytes.Buffer{},
	}
	sel, src, err := DetermineSelection(ctx)
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceProject || sel == nil || sel.ID != "gpt-5.5-pro" {
		t.Fatalf("got (%+v, %q), want project fallback after newest turn fails", sel, src)
	}
	got := recoveryEvents(t, store)
	if len(got) != 1 || got[0].Reason != "validation_failed" {
		t.Fatalf("recovery events = %+v, want one validation_failed", got)
	}
}

func TestDetermineSelection_FreshProject(t *testing.T) {
	sel, src, err := DetermineSelection(Context{
		Config: cacheWith(t, map[string]any{"active": validDiskSelection()}),
	})
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceProject || sel == nil || sel.ID != "gpt-5.5-pro" || sel.Effort != "low" {
		t.Fatalf("got (%+v, %q), want project gpt-5.5-pro/low", sel, src)
	}
}

// TestDetermineSelection_ResumeCleanChatGPT pins on the resume path:
// a recovered model_turn with provider openai-chatgpt validates against the built-in
// catalog and is adopted as source resume with no recovery event.
func TestDetermineSelection_ResumeCleanChatGPT(t *testing.T) {
	payload := map[string]any{"provider": "openai-chatgpt", "model_id": "gpt-5.5", "effort": "high"}
	store := resumeStore(modelTurnEvent(t, payload))
	ctx := Context{
		Config:        cacheWith(t, nil),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &bytes.Buffer{},
	}
	sel, src, err := DetermineSelection(ctx)
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceResume || sel == nil || sel.Provider != "openai-chatgpt" || sel.ID != "gpt-5.5" {
		t.Fatalf("got (%+v, %q), want resume openai-chatgpt/gpt-5.5", sel, src)
	}
	if got := recoveryEvents(t, store); len(got) != 0 {
		t.Fatalf("recovery events = %d, want 0 on clean ChatGPT resume", len(got))
	}
}

// TestDetermineSelection_ResumeChatGPTModelNotInBuiltin pins that a recovered
// openai-chatgpt selection whose model id is not in the built-in catalog fails
// validation (validation_failed), exactly like an unknown id under any provider.
func TestDetermineSelection_ResumeChatGPTModelNotInBuiltin(t *testing.T) {
	payload := map[string]any{"provider": "openai-chatgpt", "model_id": "gpt-9", "effort": "high"}
	store := resumeStore(modelTurnEvent(t, payload))
	ctx := Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &bytes.Buffer{},
	}
	if _, _, err := DetermineSelection(ctx); err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	got := recoveryEvents(t, store)
	if len(got) != 1 || got[0].Reason != "validation_failed" {
		t.Fatalf("recovery events = %+v, want one validation_failed", got)
	}
	if !strings.Contains(got[0].ErrorDetail, "gpt-9") {
		t.Fatalf("error_detail = %q, want it to name the rejected id", got[0].ErrorDetail)
	}
}

func TestDetermineSelection_ResumeChatGPTRemovedProFallsBack(t *testing.T) {
	payload := map[string]any{"provider": "openai-chatgpt", "model_id": "gpt-5.5-pro", "effort": "high"}
	store := resumeStore(modelTurnEvent(t, payload))
	ctx := Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
		Warn:          &bytes.Buffer{},
	}
	sel, src, err := DetermineSelection(ctx)
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceProject || sel == nil || sel.Provider != "openai" || sel.ID != "gpt-5.5-pro" {
		t.Fatalf("got (%+v, %q), want project fallback after removed ChatGPT gpt-5.5-pro fails", sel, src)
	}
	got := recoveryEvents(t, store)
	if len(got) != 1 || got[0].Reason != "validation_failed" {
		t.Fatalf("recovery events = %+v, want one validation_failed", got)
	}
	if !strings.Contains(got[0].ErrorDetail, "gpt-5.5-pro") {
		t.Fatalf("error_detail = %q, want it to name the removed id", got[0].ErrorDetail)
	}
}

// TestDetermineSelection_ChatGPTFromConfig pins on both config-sourced
// fresh paths: a model.active (per-project) or model.last_used (global fallback) entry
// whose provider is openai-chatgpt validates against the built-in catalog and is adopted
// with the matching source. The two cases differ only in the config key, expected source,
// and the model id.
func TestDetermineSelection_ChatGPTFromConfig(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		id      string
		effort  string
		wantSrc Source
	}{
		{"project active", "active", "gpt-5.4", "high", SourceProject},
		{"global last_used", "last_used", "gpt-5.5", "low", SourceGlobalFallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := map[string]any{"provider": "openai-chatgpt", "id": tc.id, "effort": tc.effort}
			sel, src, err := DetermineSelection(Context{
				Config: cacheWith(t, map[string]any{tc.key: fixture}),
			})
			if err != nil {
				t.Fatalf("DetermineSelection() error = %v", err)
			}
			if src != tc.wantSrc || sel == nil || sel.Provider != "openai-chatgpt" || sel.ID != tc.id {
				t.Fatalf("got (%+v, %q), want %q openai-chatgpt/%s", sel, src, tc.wantSrc, tc.id)
			}
		})
	}
}

func TestDetermineSelection_FreshGlobalFallback(t *testing.T) {
	sel, src, err := DetermineSelection(Context{
		Config: cacheWith(t, map[string]any{"last_used": validDiskSelection()}),
	})
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourceGlobalFallback || sel == nil || sel.ID != "gpt-5.5-pro" {
		t.Fatalf("got (%+v, %q), want global_fallback gpt-5.5-pro", sel, src)
	}
}

func TestDetermineSelection_InvalidProjectSkipsLastUsed(t *testing.T) {
	// Invalid model.active must route straight to path 4; model.last_used (valid
	// here) must not be consulted (step 3).
	model := map[string]any{
		"active":    map[string]any{"provider": "openai", "id": "gpt-9", "effort": "high"},
		"last_used": validDiskSelection(),
	}
	sel, src, err := DetermineSelection(Context{
		Config:    cacheWith(t, model),
		Providers: []ProviderDiagnostic{{Name: "openai", Models: []string{"gpt-5.5"}, ModelsSourcePath: "/g/settings.yaml"}},
	})
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourcePicker || sel != nil {
		t.Fatalf("got (%+v, %q), want picker / nil selection (last_used must be skipped)", sel, src)
	}
}

func TestDetermineSelection_FreshNeitherSelectablePicker(t *testing.T) {
	sel, src, err := DetermineSelection(Context{
		Config:    cacheWith(t, nil),
		Providers: []ProviderDiagnostic{{Name: "openai", Models: []string{"gpt-5.5"}, ModelsSourcePath: "/g/settings.yaml"}},
	})
	if err != nil {
		t.Fatalf("DetermineSelection() error = %v", err)
	}
	if src != SourcePicker || sel != nil {
		t.Fatalf("got (%+v, %q), want picker / nil selection", sel, src)
	}
}

func TestDetermineSelection_NoProvidersExit(t *testing.T) {
	_, _, err := DetermineSelection(Context{
		Config:             cacheWith(t, nil),
		GlobalSettingsPath: "/home/u/.codemeld/global/settings.yaml",
		Providers:          nil,
	})
	var nse *NoSelectableModelError
	if !errors.As(err, &nse) {
		t.Fatalf("error = %v, want *NoSelectableModelError", err)
	}
	want := "codemeld: no providers configured — add at least one entry under provider: in /home/u/.codemeld/global/settings.yaml"
	if len(nse.Lines) != 1 || nse.Lines[0] != want {
		t.Fatalf("lines = %#v, want exactly [%q]", nse.Lines, want)
	}
}

func TestDetermineSelection_EmptyAllowlistsExit(t *testing.T) {
	_, _, err := DetermineSelection(Context{
		Config:             cacheWith(t, nil),
		GlobalSettingsPath: "/home/u/.codemeld/global/settings.yaml",
		Providers: []ProviderDiagnostic{
			{Name: "openai", Models: nil, ModelsSourcePath: "/proj/.codemeld/settings.yaml"},
			{Name: "openrouter", Models: []string{}, ModelsSourcePath: "/home/u/.codemeld/global/settings.yaml"},
		},
	})
	var nse *NoSelectableModelError
	if !errors.As(err, &nse) {
		t.Fatalf("error = %v, want *NoSelectableModelError", err)
	}
	want := []string{
		"codemeld: no models for provider.openai — refresh the provider catalog before retrying",
		"codemeld: no models for provider.openrouter — refresh the provider catalog before retrying",
	}
	if len(nse.Lines) != len(want) {
		t.Fatalf("lines = %#v, want %d entries", nse.Lines, len(want))
	}
	for i := range want {
		if nse.Lines[i] != want[i] {
			t.Fatalf("line[%d] = %q, want %q", i, nse.Lines[i], want[i])
		}
	}
	for _, line := range nse.Lines {
		if strings.Contains(line, ".models") {
			t.Errorf("empty-catalog line names the retired provider.<id>.models key: %q", line)
		}
		if strings.Contains(line, "settings.yaml") {
			t.Errorf("empty-catalog line names a settings file: %q", line)
		}
	}
}

func TestDetermineSelection_OneEmptyAllowlistAmongFilledIsSelectable(t *testing.T) {
	// At least one non-empty allowlist means a model is selectable: the picker
	// opens and no error is returned even though another provider is empty.
	sel, src, err := DetermineSelection(Context{
		Config: cacheWith(t, nil),
		Providers: []ProviderDiagnostic{
			{Name: "empty", Models: nil, ModelsSourcePath: "/g/settings.yaml"},
			{Name: "openai", Models: []string{"gpt-5.5"}, ModelsSourcePath: "/g/settings.yaml"},
		},
	})
	if err != nil || src != SourcePicker || sel != nil {
		t.Fatalf("got (%+v, %q, %v), want picker / nil / nil", sel, src, err)
	}
}

func TestDetermineSelection_NilConfig(t *testing.T) {
	if _, _, err := DetermineSelection(Context{}); err == nil {
		t.Fatal("DetermineSelection() error = nil, want error for nil config cache")
	}
}

// TestRecoverActiveSelection_Clean pins the in-TUI step-1 helper's clean path: a
// valid model_turn is restored and reported as RecoveryClean with no event appended.
func TestRecoverActiveSelection_Clean(t *testing.T) {
	store := resumeStore(modelTurnEvent(t, validResumePayload()))
	sel, outcome, err := RecoverActiveSelection(Context{
		Config:        cacheWith(t, nil),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
	})
	if err != nil {
		t.Fatalf("RecoverActiveSelection() error = %v", err)
	}
	if outcome != RecoveryClean {
		t.Fatalf("outcome = %v, want RecoveryClean", outcome)
	}
	if sel == nil || sel.Provider != "openai" || sel.ID != "gpt-5.5" || sel.Effort != "high" {
		t.Fatalf("selection = %+v, want openai/gpt-5.5/high", sel)
	}
	if got := recoveryEvents(t, store); len(got) != 0 {
		t.Fatalf("recovery events = %d, want 0 on clean recovery", len(got))
	}
}

// TestRecoverActiveSelection_NoModelTurn pins the absence path: a stream with no
// model_turn reports RecoveryNoModelTurn and appends nothing — unlike DetermineSelection
// the helper does not fall through to the config paths.
func TestRecoverActiveSelection_NoModelTurn(t *testing.T) {
	store := resumeStore(sessions.Event{Kind: events.KindLaunchBegan, Payload: json.RawMessage(`{"source":"resume"}`)})
	sel, outcome, err := RecoverActiveSelection(Context{
		Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
	})
	if err != nil || outcome != RecoveryNoModelTurn || sel != nil {
		t.Fatalf("got (%+v, %v, %v), want nil / RecoveryNoModelTurn / nil — the helper must not fall through to config", sel, outcome, err)
	}
	if got := recoveryEvents(t, store); len(got) != 0 {
		t.Fatalf("recovery events = %d, want 0 when no model_turn", len(got))
	}
}

// TestRecoverActiveSelection_Failure pins the failure path: an invalid model_turn
// reports RecoveryFailed and appends exactly one model_recovery_failed.
func TestRecoverActiveSelection_Failure(t *testing.T) {
	bad := map[string]any{"provider": "openai", "model_id": "gpt-9", "effort": "high"} // not in allowlist
	store := resumeStore(modelTurnEvent(t, bad))
	sel, outcome, err := RecoverActiveSelection(Context{
		Config:        cacheWith(t, nil),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
	})
	if err != nil {
		t.Fatalf("RecoverActiveSelection() error = %v", err)
	}
	if outcome != RecoveryFailed || sel != nil {
		t.Fatalf("got (%+v, %v), want nil / RecoveryFailed", sel, outcome)
	}
	got := recoveryEvents(t, store)
	if len(got) != 1 || got[0].Reason != "validation_failed" {
		t.Fatalf("recovery events = %+v, want exactly one validation_failed", got)
	}
}

// TestRecoverActiveSelection_FailureWithNoStoreSurfaces pins the internal-error path: a
// failing recovery with no store to record model_recovery_failed surfaces an error
// rather than silently dropping the event.
func TestRecoverActiveSelection_FailureWithNoStoreSurfaces(t *testing.T) {
	bad := map[string]any{"provider": "openai", "model_id": "gpt-9", "effort": "high"}
	if _, _, err := RecoverActiveSelection(Context{
		Config:        cacheWith(t, nil),
		Resume:        true,
		ResumeRecords: []sessions.Record{modelTurnEvent(t, bad)},
		Store:         nil,
	}); err == nil {
		t.Fatal("RecoverActiveSelection() error = nil, want an error when a failing recovery has no store to record to")
	}
}

// TestRecoverActiveSelection_NilConfig pins the nil-cache guard.
func TestRecoverActiveSelection_NilConfig(t *testing.T) {
	if _, _, err := RecoverActiveSelection(Context{Resume: true}); err == nil {
		t.Fatal("RecoverActiveSelection() error = nil, want error for nil config cache")
	}
}

func TestDetermineSelection_StoredEffortRequiresAdvertisedSupport(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		effort  string
		wantSrc Source
	}{
		{"sentinel from project active", "active", EffortNoReasoning, SourceProject},
		{"advertised default from project active", "active", EffortDefault, SourceProject},
		{"sentinel from global last_used", "last_used", EffortNoReasoning, SourceGlobalFallback},
		{"advertised default from global last_used", "last_used", EffortDefault, SourceGlobalFallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored := map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": tc.effort}
			sel, src, err := DetermineSelection(Context{Config: cacheWith(t, map[string]any{tc.key: stored})})
			if err != nil {
				t.Fatalf("DetermineSelection() error = %v", err)
			}
			if src != tc.wantSrc || sel == nil || sel.Effort != tc.effort {
				t.Fatalf("got (%+v, %q), want %q with effort %q", sel, src, tc.wantSrc, tc.effort)
			}
		})
	}
}

func TestDetermineSelection_UnavailableStoredEffortRoutesToPicker(t *testing.T) {
	cases := []struct {
		name   string
		cache  func(*testing.T, map[string]any) *config.Cache
		effort string
	}{
		{"unadvertised token", cacheWith, "ultra"},
		{"literal default with no capability metadata", bareCacheWith, EffortDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored := map[string]any{"provider": "openai", "id": "gpt-5.5", "effort": tc.effort}
			cache := tc.cache(t, map[string]any{"active": stored})
			sel, src, err := DetermineSelection(Context{
				Config:    cache,
				Providers: []ProviderDiagnostic{{Name: "openai", Models: []string{"gpt-5.5"}}},
			})
			if err != nil {
				t.Fatalf("DetermineSelection() error = %v", err)
			}
			if src != SourcePicker || sel != nil {
				t.Fatalf("got (%+v, %q), want picker / nil selection", sel, src)
			}
			raw, ok := cache.ModelActiveRaw()
			if !ok {
				t.Fatal("model.active disappeared; the rejected selection must be left in place")
			}
			m, ok := raw.(map[string]any)
			if !ok || m["effort"] != tc.effort {
				t.Fatalf("model.active = %#v, want the stored effort %q preserved unrewritten", raw, tc.effort)
			}
		})
	}
}

func TestDetermineSelection_ResumeEffortRequiresAdvertisedSupport(t *testing.T) {
	for _, effort := range []string{EffortNoReasoning, EffortDefault} {
		t.Run(effort, func(t *testing.T) {
			payload := map[string]any{"provider": "openai", "model_id": "gpt-5.5", "effort": effort}
			store := resumeStore(modelTurnEvent(t, payload))
			sel, src, err := DetermineSelection(Context{
				Config:        cacheWith(t, map[string]any{"active": validDiskSelection()}),
				Resume:        true,
				ResumeRecords: store.Records(),
				Store:         store,
				Warn:          &bytes.Buffer{},
			})
			if err != nil {
				t.Fatalf("DetermineSelection() error = %v", err)
			}
			if src != SourceResume || sel == nil || sel.Effort != effort {
				t.Fatalf("got (%+v, %q), want resume with effort %q", sel, src, effort)
			}
			if got := recoveryEvents(t, store); len(got) != 0 {
				t.Fatalf("recovery events = %d, want 0 for an advertised effort", len(got))
			}
		})
	}
}

func TestRecoverActiveSelection_UnavailableEffortPreservesTurn(t *testing.T) {
	payload := map[string]any{"provider": "openai", "model_id": "gpt-5.5", "effort": EffortDefault}
	turn := modelTurnEvent(t, payload)
	before := string(turn.Payload)
	store := resumeStore(turn)
	sel, outcome, err := RecoverActiveSelection(Context{
		Config:        bareCacheWith(t, nil),
		Resume:        true,
		ResumeRecords: store.Records(),
		Store:         store,
	})
	if err != nil {
		t.Fatalf("RecoverActiveSelection() error = %v", err)
	}
	if outcome != RecoveryFailed || sel != nil {
		t.Fatalf("got (%+v, %v), want nil / RecoveryFailed", sel, outcome)
	}
	got := recoveryEvents(t, store)
	if len(got) != 1 || got[0].Reason != "validation_failed" {
		t.Fatalf("recovery events = %+v, want exactly one validation_failed", got)
	}
	if !strings.Contains(got[0].ErrorDetail, EffortDefault) {
		t.Fatalf("error_detail = %q, want it to name the rejected effort", got[0].ErrorDetail)
	}
	for _, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindModelTurn {
			continue
		}
		if string(ev.Payload) != before {
			t.Fatalf("model_turn payload = %s, want it unchanged (%s)", ev.Payload, before)
		}
	}
}
