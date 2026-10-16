// Tests for model-turn event emission, effort filtering, and usage
// normalization: clean/dropped/failed turn shapes and missing/malformed usage.
package model

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

func newTurnStore() *sessions.Store {
	return sessions.New("/sessions/active.json", &sessions.Session{})
}

// kindEvents returns, in append order, every appended event of the given kind.
func kindEvents(t *testing.T, store *sessions.Store, kind string) []sessions.Event {
	t.Helper()
	var out []sessions.Event
	for _, r := range store.Records() {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// decodePayload unmarshals an appended event's payload and asserts the load-time
// validator accepts it, so every emitted record is also a valid persisted one.
func decodePayload[T any](t *testing.T, ev sessions.Event) T {
	t.Helper()
	if err := events.ValidatePayload(ev.Kind, ev.Payload); err != nil {
		t.Fatalf("ValidatePayload(%s) rejected an emitted record: %v", ev.Kind, err)
	}
	var p T
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatalf("unmarshal %s payload: %v", ev.Kind, err)
	}
	return p
}

func TestEmitTurnStart_CleanTurn(t *testing.T) {
	store := newTurnStore()
	sel := Selection{Provider: "openai", ID: "gpt-5", Effort: "high"}
	supported := []string{"none", "minimal", "low", "medium", "high", "xhigh", EffortDefault}

	effortToSend, dropped, err := EmitTurnStart(store, sel, SourceProject, supported)
	if err != nil {
		t.Fatalf("EmitTurnStart() error = %v", err)
	}
	if effortToSend != "high" || dropped {
		t.Fatalf("got (effortToSend=%q, dropped=%v), want (\"high\", false)", effortToSend, dropped)
	}
	if got := kindEvents(t, store, events.KindModelEffortUnsupported); len(got) != 0 {
		t.Fatalf("model_effort_unsupported events = %d, want 0 on a supported effort", len(got))
	}
	turns := kindEvents(t, store, events.KindModelTurn)
	if len(turns) != 1 {
		t.Fatalf("model_turn events = %d, want 1", len(turns))
	}
	mt := decodePayload[events.ModelTurn](t, turns[0])
	if mt.Provider != "openai" || mt.ModelID != "gpt-5" || mt.Effort != "high" || mt.Source != string(SourceProject) {
		t.Fatalf("model_turn = %+v, want openai/gpt-5/high/project", mt)
	}

	// A successful turn is finished by a model_response carrying no anomalies.
	if err := EmitModelResponse(store, sel.Provider, sel.ID, 100, 50, nil, false, nil, ""); err != nil {
		t.Fatalf("EmitModelResponse() error = %v", err)
	}
	resps := kindEvents(t, store, events.KindModelResponse)
	if len(resps) != 1 {
		t.Fatalf("model_response events = %d, want 1", len(resps))
	}
	mr := decodePayload[events.ModelResponse](t, resps[0])
	if mr.InputTokens != 100 || mr.OutputTokens != 50 || len(mr.Anomaly) != 0 {
		t.Fatalf("model_response = %+v, want 100/50 tokens and empty anomaly", mr)
	}
	if !strings.Contains(string(resps[0].Payload), `"anomaly":[]`) {
		t.Errorf("anomaly did not render as []: %s", resps[0].Payload)
	}
}

func TestEmitTurnStart_EffortDropped(t *testing.T) {
	store := newTurnStore()
	sel := Selection{Provider: "openai", ID: "gpt-5", Effort: "high"}
	supported := []string{EffortDefault} // high unsupported -> dropped

	effortToSend, dropped, err := EmitTurnStart(store, sel, SourceProject, supported)
	if err != nil {
		t.Fatalf("EmitTurnStart() error = %v", err)
	}
	if effortToSend != "" || !dropped {
		t.Fatalf("got (effortToSend=%q, dropped=%v), want (\"\", true)", effortToSend, dropped)
	}

	recs := store.Records()
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2 (effort_unsupported then turn)", len(recs))
	}
	first := recs[0].(sessions.Event)
	second := recs[1].(sessions.Event)
	if first.Kind != events.KindModelEffortUnsupported {
		t.Fatalf("first event kind = %q, want %q", first.Kind, events.KindModelEffortUnsupported)
	}
	if second.Kind != events.KindModelTurn {
		t.Fatalf("second event kind = %q, want %q", second.Kind, events.KindModelTurn)
	}
	meu := decodePayload[events.ModelEffortUnsupported](t, first)
	if meu.Provider != "openai" || meu.ModelID != "gpt-5" || meu.ConfiguredEffort != "high" {
		t.Fatalf("model_effort_unsupported = %+v, want openai/gpt-5/high", meu)
	}
	mt := decodePayload[events.ModelTurn](t, second)
	if mt.Effort != EffortNoReasoning {
		t.Fatalf("model_turn.effort = %q, want %q", mt.Effort, EffortNoReasoning)
	}
}

func TestEmitTurnStart_NoReasoningNotDropped(t *testing.T) {
	store := newTurnStore()
	sel := Selection{Provider: "openai", ID: "gpt-5", Effort: EffortNoReasoning}

	effortToSend, dropped, err := EmitTurnStart(store, sel, SourceResume, []string{"high", EffortDefault})
	if err != nil {
		t.Fatalf("EmitTurnStart() error = %v", err)
	}
	if effortToSend != "" || dropped {
		t.Fatalf("got (effortToSend=%q, dropped=%v), want (\"\", false)", effortToSend, dropped)
	}
	if got := kindEvents(t, store, events.KindModelEffortUnsupported); len(got) != 0 {
		t.Fatalf("model_effort_unsupported events = %d, want 0 for EffortNoReasoning", len(got))
	}
	turns := kindEvents(t, store, events.KindModelTurn)
	if len(turns) != 1 {
		t.Fatalf("model_turn events = %d, want 1", len(turns))
	}
	if mt := decodePayload[events.ModelTurn](t, turns[0]); mt.Effort != EffortNoReasoning {
		t.Fatalf("model_turn.effort = %q, want %q", mt.Effort, EffortNoReasoning)
	}
}

func TestEmitTurnStart_AdvertisedEffortRetainedVerbatim(t *testing.T) {
	supported := []string{EffortDefault, "max", "ultra"}
	for _, effort := range supported {
		t.Run(effort, func(t *testing.T) {
			store := newTurnStore()
			sel := Selection{Provider: "venice", ID: "custom-1", Effort: effort}

			effortToSend, dropped, err := EmitTurnStart(store, sel, SourceProject, supported)
			if err != nil {
				t.Fatalf("EmitTurnStart() error = %v", err)
			}
			if effortToSend != effort || dropped {
				t.Fatalf("got (effortToSend=%q, dropped=%v), want (%q, false)", effortToSend, dropped, effort)
			}
			if got := kindEvents(t, store, events.KindModelEffortUnsupported); len(got) != 0 {
				t.Fatalf("model_effort_unsupported events = %d, want 0 for an advertised effort", len(got))
			}
			turns := kindEvents(t, store, events.KindModelTurn)
			if len(turns) != 1 {
				t.Fatalf("model_turn events = %d, want 1", len(turns))
			}
			if mt := decodePayload[events.ModelTurn](t, turns[0]); mt.Effort != effort {
				t.Fatalf("model_turn.effort = %q, want %q unchanged", mt.Effort, effort)
			}
		})
	}
}

func TestEmitTurnStart_UnsupportedStoredEffortNotRewritten(t *testing.T) {
	store := newTurnStore()
	sel := Selection{Provider: "venice", ID: "custom-1", Effort: "ultra"}

	effortToSend, dropped, err := EmitTurnStart(store, sel, SourceProject, []string{EffortDefault, "max"})
	if err != nil {
		t.Fatalf("EmitTurnStart() error = %v", err)
	}
	if effortToSend != "" || !dropped {
		t.Fatalf("got (effortToSend=%q, dropped=%v), want (\"\", true)", effortToSend, dropped)
	}
	if sel.Effort != "ultra" {
		t.Fatalf("sel.Effort = %q, want %q (the stored selection must not be rewritten)", sel.Effort, "ultra")
	}
	unsupported := kindEvents(t, store, events.KindModelEffortUnsupported)
	if len(unsupported) != 1 {
		t.Fatalf("model_effort_unsupported events = %d, want exactly 1", len(unsupported))
	}
	if meu := decodePayload[events.ModelEffortUnsupported](t, unsupported[0]); meu.ConfiguredEffort != "ultra" {
		t.Fatalf("configured_effort = %q, want %q verbatim", meu.ConfiguredEffort, "ultra")
	}
	turns := kindEvents(t, store, events.KindModelTurn)
	if len(turns) != 1 {
		t.Fatalf("model_turn events = %d, want 1", len(turns))
	}
	if mt := decodePayload[events.ModelTurn](t, turns[0]); mt.Effort != EffortNoReasoning {
		t.Fatalf("model_turn.effort = %q, want %q", mt.Effort, EffortNoReasoning)
	}
}

func TestEmitTurnStart_FailedTurnEmitsNoResponse(t *testing.T) {
	// A failed/interrupted turn appends only model_turn; the caller never reaches
	// EmitModelResponse, so the stream carries none.
	store := newTurnStore()
	sel := Selection{Provider: "openai", ID: "gpt-5", Effort: "high"}
	if _, _, err := EmitTurnStart(store, sel, SourceProject, []string{"high"}); err != nil {
		t.Fatalf("EmitTurnStart() error = %v", err)
	}
	if got := kindEvents(t, store, events.KindModelTurn); len(got) != 1 {
		t.Fatalf("model_turn events = %d, want 1", len(got))
	}
	if got := kindEvents(t, store, events.KindModelResponse); len(got) != 0 {
		t.Fatalf("model_response events = %d, want 0 on a failed turn", len(got))
	}
}

func TestEmitTurnStart_AppendErrorPropagates(t *testing.T) {
	// An empty provider fails the model_effort_unsupported validator, so the error
	// surfaces and the paired model_turn is never appended.
	store := newTurnStore()
	sel := Selection{Provider: "", ID: "gpt-5", Effort: "high"}
	if _, _, err := EmitTurnStart(store, sel, SourceProject, []string{EffortDefault}); err == nil {
		t.Fatal("EmitTurnStart() error = nil, want a validation error for empty provider")
	}
	if got := len(store.Records()); got != 0 {
		t.Fatalf("records = %d, want 0 after a rejected first append", got)
	}
}

func TestResolveRequestEffort(t *testing.T) {
	tests := []struct {
		name        string
		effort      string
		supported   []string
		wantSend    string
		wantDropped bool
	}{
		{"no-reasoning-not-dropped", EffortNoReasoning, []string{EffortNoReasoning}, "", false},
		{"no-reasoning-even-when-absent", EffortNoReasoning, []string{"high"}, "", false},
		{"default-is-a-provider-token", EffortDefault, []string{EffortDefault, "high"}, EffortDefault, false},
		{"default-dropped-when-not-advertised", EffortDefault, []string{"high"}, "", true},
		{"none-is-explicit-effort", "none", []string{"none", "low"}, "none", false},
		{"xhigh-is-explicit-effort", "xhigh", []string{"high", "xhigh"}, "xhigh", false},
		{"advertised-token-sent-asis", "ultra", []string{"max", "ultra"}, "ultra", false},
		{"supported-sent-asis", "high", []string{"low", "high", EffortDefault}, "high", false},
		{"unsupported-dropped", "high", []string{EffortDefault}, "", true},
		{"unsupported-among-others", "minimal", []string{"low", "high"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel := Selection{Provider: "openai", ID: "gpt-5", Effort: tt.effort}
			send, configured, dropped := ResolveRequestEffort(sel, tt.supported)
			if send != tt.wantSend || dropped != tt.wantDropped {
				t.Fatalf("got (send=%q, dropped=%v), want (%q, %v)", send, dropped, tt.wantSend, tt.wantDropped)
			}
			if configured != tt.effort {
				t.Fatalf("configuredEffort = %q, want %q (always echoes sel.Effort)", configured, tt.effort)
			}
		})
	}
}

func TestEmitModelTurn_EffortValidation(t *testing.T) {
	store := newTurnStore()
	if err := EmitModelTurn(store, "openai", "gpt-5", "", SourceProject); err == nil {
		t.Fatal("EmitModelTurn() accepted an empty effort")
	}
	if got := len(store.Records()); got != 0 {
		t.Fatalf("records = %d, want 0 after a rejected append", got)
	}
	if err := EmitModelTurn(store, "venice", "custom-1", "ultra", SourceProject); err != nil {
		t.Fatalf("EmitModelTurn() rejected an advertised provider token: %v", err)
	}
}

func TestUsageFromStreamUsage(t *testing.T) {
	// The streaming path reads usage off the final chunk: usageValid mirrors
	// chunk.JSON.Usage.Valid(), so build each case from a real ChatCompletionChunk
	// JSON the way turn.go does.
	tests := []struct {
		name       string
		chunk      string
		wantIn     int64
		wantOut    int64
		wantCached *int64
		wantAnoms  []string
	}{
		{
			name:    "final-usage-chunk",
			chunk:   `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160}}`,
			wantIn:  120,
			wantOut: 40,
		},
		{
			name:       "cached-tokens-reported",
			chunk:      `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"prompt_tokens_details":{"cached_tokens":96}}}`,
			wantIn:     120,
			wantOut:    40,
			wantCached: ptrInt64(96),
		},
		{
			name:       "cached-tokens-reported-zero",
			chunk:      `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"prompt_tokens_details":{"cached_tokens":0}}}`,
			wantIn:     120,
			wantOut:    40,
			wantCached: ptrInt64(0),
		},
		{
			name:    "cached-tokens-absent-from-details",
			chunk:   `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"prompt_tokens_details":{"audio_tokens":0}}}`,
			wantIn:  120,
			wantOut: 40,
		},
		{
			name:    "cached-tokens-null",
			chunk:   `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"prompt_tokens_details":{"cached_tokens":null}}}`,
			wantIn:  120,
			wantOut: 40,
		},
		{
			name:    "cached-tokens-negative",
			chunk:   `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"prompt_tokens_details":{"cached_tokens":-1}}}`,
			wantIn:  120,
			wantOut: 40,
		},
		{
			name:      "content-chunk-has-null-usage",
			chunk:     `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[{"index":0,"delta":{"content":"hi"}}],"usage":null}`,
			wantAnoms: []string{anomalyUsageMissing},
		},
		{
			name:      "no-usage-field",
			chunk:     `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[{"index":0,"delta":{"content":"hi"}}]}`,
			wantAnoms: []string{anomalyUsageMissing},
		},
		{
			name:      "malformed-missing-completion-tokens",
			chunk:     `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":120,"total_tokens":120}}`,
			wantIn:    120,
			wantAnoms: []string{anomalyUsageMissing},
		},
		{
			name:      "malformed-missing-prompt-tokens",
			chunk:     `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"completion_tokens":40,"total_tokens":40}}`,
			wantOut:   40,
			wantAnoms: []string{anomalyUsageMissing},
		},
		{
			name:      "malformed-negative",
			chunk:     `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":-1,"completion_tokens":5,"total_tokens":4}}`,
			wantOut:   5,
			wantAnoms: []string{anomalyUsageMissing},
		},
		{
			name:      "all-subfields-missing-single-token",
			chunk:     `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{}}`,
			wantAnoms: []string{anomalyUsageMissing},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var chunk openai.ChatCompletionChunk
			if err := json.Unmarshal([]byte(tt.chunk), &chunk); err != nil {
				t.Fatalf("unmarshal chunk: %v", err)
			}
			in, out, cached, anoms := UsageFromStreamUsage(chunk.Usage, chunk.JSON.Usage.Valid())
			if in != tt.wantIn || out != tt.wantOut {
				t.Fatalf("tokens = (%d, %d), want (%d, %d)", in, out, tt.wantIn, tt.wantOut)
			}
			if !sameCached(cached, tt.wantCached) {
				t.Fatalf("cached = %s, want %s", showCached(cached), showCached(tt.wantCached))
			}
			if !slices.Equal(anoms, tt.wantAnoms) {
				t.Fatalf("anomalies = %v, want %v", anoms, tt.wantAnoms)
			}
			// A zero-value usage with usageValid=false is the interrupted-stream fallback.
			if err := EmitModelResponse(newTurnStore(), "openai", "gpt-5", in, out, cached, false, anoms, ""); err != nil {
				t.Fatalf("EmitModelResponse() rejected normalized stream usage: %v", err)
			}
		})
	}
}

func ptrInt64(v int64) *int64 { return &v }

func sameCached(got, want *int64) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return *got == *want
}

func showCached(v *int64) string {
	if v == nil {
		return "nil (not reported)"
	}
	return fmt.Sprintf("%d", *v)
}

// usageChunkOf decodes a raw chunk into the pair turn.go feeds the usage path, so the
// presence metadata comes from real provider JSON rather than a hand-built struct.
func usageChunkOf(t *testing.T, raw string) (openai.CompletionUsage, bool) {
	t.Helper()
	var chunk openai.ChatCompletionChunk
	if err := json.Unmarshal([]byte(raw), &chunk); err != nil {
		t.Fatalf("unmarshal chunk: %v", err)
	}
	return chunk.Usage, chunk.JSON.Usage.Valid()
}

const (
	cachedRoundJSON   = `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_tokens_details":{"cached_tokens":80}}}`
	cachedZeroJSON    = `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_tokens_details":{"cached_tokens":0}}}`
	uncachedRoundJSON = `{"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[],"usage":{"prompt_tokens":50,"completion_tokens":10,"total_tokens":60}}`
)

func TestUsageAccumulator_CachedTotals(t *testing.T) {
	tests := []struct {
		name        string
		rounds      []string
		wantCached  *int64
		wantPartial bool
	}{
		{
			name:       "every-round-reports",
			rounds:     []string{cachedRoundJSON, cachedRoundJSON},
			wantCached: ptrInt64(160),
		},
		{
			name:       "reported-zero-stays-exact",
			rounds:     []string{cachedRoundJSON, cachedZeroJSON},
			wantCached: ptrInt64(80),
		},
		{
			name:        "one-round-omits-marks-lower-bound",
			rounds:      []string{cachedRoundJSON, uncachedRoundJSON},
			wantCached:  ptrInt64(80),
			wantPartial: true,
		},
		{
			name:   "no-round-reports",
			rounds: []string{uncachedRoundJSON, uncachedRoundJSON},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var acc UsageAccumulator
			for _, raw := range tt.rounds {
				acc.Add(usageChunkOf(t, raw))
			}
			_, _, cached, partial, anoms, _ := acc.Totals()
			if !sameCached(cached, tt.wantCached) {
				t.Fatalf("cached total = %s, want %s", showCached(cached), showCached(tt.wantCached))
			}
			if partial != tt.wantPartial {
				t.Fatalf("cachedPartial = %v, want %v", partial, tt.wantPartial)
			}
			if len(anoms) != 0 {
				t.Fatalf("anomalies = %v, want none (an unreported cached count is not usage_missing)", anoms)
			}
		})
	}
}

func TestUsageAccumulator_MissingUsageRoundMarksCachedPartial(t *testing.T) {
	var acc UsageAccumulator
	acc.Add(usageChunkOf(t, cachedRoundJSON))
	acc.Add(openai.CompletionUsage{}, false)

	_, _, cached, partial, anoms, _ := acc.Totals()
	if !sameCached(cached, ptrInt64(80)) {
		t.Fatalf("cached total = %s, want 80", showCached(cached))
	}
	if !partial {
		t.Fatal("cachedPartial = false, want true (a round carried no usage chunk)")
	}
	if !slices.Equal(anoms, []string{anomalyUsageMissing}) {
		t.Fatalf("anomalies = %v, want [usage_missing] (unchanged by cached handling)", anoms)
	}
}

func TestEmitModelResponse_CachedRoundTrip(t *testing.T) {
	store := newTurnStore()
	if err := EmitModelResponse(store, "openai", "gpt-5", 100, 50, ptrInt64(0), false, nil, ""); err != nil {
		t.Fatalf("EmitModelResponse() rejected a reported zero: %v", err)
	}
	if err := EmitModelResponse(store, "openai", "gpt-5", 100, 50, ptrInt64(80), true, nil, ""); err != nil {
		t.Fatalf("EmitModelResponse() rejected a partial total: %v", err)
	}
	if err := EmitModelResponse(store, "openai", "gpt-5", 100, 50, nil, false, nil, ""); err != nil {
		t.Fatalf("EmitModelResponse() rejected a not-reported total: %v", err)
	}

	resps := kindEvents(t, store, events.KindModelResponse)
	if len(resps) != 3 {
		t.Fatalf("model_response events = %d, want 3", len(resps))
	}

	zero := decodePayload[events.ModelResponse](t, resps[0])
	if zero.CachedInputTokens == nil || *zero.CachedInputTokens != 0 || zero.CachedInputTokensPartial {
		t.Fatalf("reported zero = %s partial=%v, want 0/false", showCached(zero.CachedInputTokens), zero.CachedInputTokensPartial)
	}
	if !strings.Contains(string(resps[0].Payload), `"cached_input_tokens":0`) {
		t.Errorf("a reported zero was dropped from the wire form: %s", resps[0].Payload)
	}

	partial := decodePayload[events.ModelResponse](t, resps[1])
	if partial.CachedInputTokens == nil || *partial.CachedInputTokens != 80 || !partial.CachedInputTokensPartial {
		t.Fatalf("partial total = %s partial=%v, want 80/true", showCached(partial.CachedInputTokens), partial.CachedInputTokensPartial)
	}

	absent := decodePayload[events.ModelResponse](t, resps[2])
	if absent.CachedInputTokens != nil || absent.CachedInputTokensPartial {
		t.Fatalf("not-reported total = %s partial=%v, want nil/false", showCached(absent.CachedInputTokens), absent.CachedInputTokensPartial)
	}
	if strings.Contains(string(resps[2].Payload), "cached_input_tokens") {
		t.Errorf("a not-reported total wrote a cached key: %s", resps[2].Payload)
	}
}

func TestEmitModelResponse_UpstreamProviderRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	now := time.Now().UTC()
	store := sessions.New(path, &sessions.Session{Metadata: sessions.Metadata{
		ID: ids.NewV7(), Folder: filepath.Dir(path), StartedAt: now, UpdatedAt: now, SchemaVersion: sessions.CurrentSchemaVersion,
	}})
	if err := EmitModelResponse(store, "openrouter", "m", 10, 5, nil, false, nil, "Groq"); err != nil {
		t.Fatalf("EmitModelResponse() error = %v", err)
	}
	if err := EmitModelResponse(store, "openai", "gpt-5", 10, 5, nil, false, nil, ""); err != nil {
		t.Fatalf("EmitModelResponse() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	reloaded, _, err := sessions.OpenSession(path)
	if err != nil {
		t.Fatalf("reopen persisted session: %v", err)
	}
	var resps []sessions.Event
	for _, r := range reloaded.Records {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == events.KindModelResponse {
			resps = append(resps, ev)
		}
	}
	if len(resps) != 2 {
		t.Fatalf("model_response events = %d, want 2", len(resps))
	}
	if got := decodePayload[events.ModelResponse](t, resps[0]).UpstreamProvider; got != "Groq" {
		t.Fatalf("upstream_provider = %q, want Groq", got)
	}
	if !strings.Contains(string(resps[0].Payload), `"upstream_provider":"Groq"`) {
		t.Errorf("stored payload lacks upstream_provider: %s", resps[0].Payload)
	}
	if strings.Contains(string(resps[1].Payload), "upstream_provider") {
		t.Errorf("an empty upstream provider wrote the key: %s", resps[1].Payload)
	}
	legacy := json.RawMessage(`{"provider":"openai","model_id":"gpt-5","input_tokens":1,"output_tokens":2,"anomaly":[]}`)
	if err := events.ValidatePayload(events.KindModelResponse, legacy); err != nil {
		t.Fatalf("a record without upstream_provider no longer validates: %v", err)
	}
}

func TestSumModelResponseTokens(t *testing.T) {
	store := newTurnStore()
	// Two completed turns plus an interrupted turn (no model_response) and an
	// unrelated event: only the model_response records contribute.
	if err := EmitModelResponse(store, "openai", "gpt-5", 100, 50, nil, false, nil, ""); err != nil {
		t.Fatalf("EmitModelResponse() error = %v", err)
	}
	if err := EmitModelTurn(store, "openai", "gpt-5", EffortDefault, SourceProject); err != nil {
		t.Fatalf("EmitModelTurn() error = %v", err)
	}
	if err := EmitModelResponse(store, "openai", "gpt-5", 7, 3, nil, false, []string{anomalyUsageMissing}, ""); err != nil {
		t.Fatalf("EmitModelResponse() error = %v", err)
	}

	in, out := SumModelResponseTokens(store.Records())
	if in != 107 || out != 53 {
		t.Fatalf("SumModelResponseTokens = (%d, %d), want (107, 53)", in, out)
	}

	if gotIn, gotOut := SumModelResponseTokens(nil); gotIn != 0 || gotOut != 0 {
		t.Fatalf("SumModelResponseTokens(nil) = (%d, %d), want (0, 0)", gotIn, gotOut)
	}
}
