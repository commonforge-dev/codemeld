// Model-turn event append helpers, request-effort filtering, and
// usage-anomaly normalization for the assistant-turn boundary.
package model

import (
	"encoding/json"
	"math"
	"slices"

	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// anomalyUsageMissing is the sole model_response anomaly token, emitted
// once when the provider response carries missing or malformed token usage.
const anomalyUsageMissing = "usage_missing"

// EmitModelTurn appends a model_turn event recording the active provider, model,
// effort, and selection source at the start of an assistant turn.
// It appends only — the caller owns flushing.
func EmitModelTurn(store *sessions.Store, provider, modelID, effort string, source Source) error {
	_, err := events.Append(store, events.ModelTurn{
		Provider: provider,
		ModelID:  modelID,
		Effort:   effort,
		Source:   string(source),
	})
	return err
}

// EmitModelResponse appends a model_response event recording an assistant turn's
// token usage. A nil anomalies slice renders as []. It appends only — the caller
// owns flushing.
func EmitModelResponse(store *sessions.Store, provider, modelID string, inputTokens, outputTokens int64, cachedInputTokens *int64, cachedPartial bool, costUSD *float64, costPartial bool, anomalies []string, upstreamProvider string) error {
	_, err := events.Append(store, events.ModelResponse{
		Provider:                 provider,
		ModelID:                  modelID,
		InputTokens:              inputTokens,
		OutputTokens:             outputTokens,
		CachedInputTokens:        cachedInputTokens,
		CachedInputTokensPartial: cachedPartial,
		CostUSD:                  costUSD,
		CostUSDPartial:           costPartial,
		Anomaly:                  anomalies,
		UpstreamProvider:         upstreamProvider,
	})
	return err
}

// EmitModelEffortUnsupported appends a model_effort_unsupported event recording
// that the configured effort was dropped because the active model does not
// support it. It appends only; requires the caller to flush the store afterward
// and route any flush failure through the write-failure protocol — coupling
// this package intentionally does not take on.
func EmitModelEffortUnsupported(store *sessions.Store, provider, modelID, configuredEffort string) error {
	_, err := events.Append(store, events.ModelEffortUnsupported{
		Provider:         provider,
		ModelID:          modelID,
		ConfiguredEffort: configuredEffort,
	})
	return err
}

// ResolveRequestEffort applies the request-time effort filter for sel
// against the active model's supportedSet. effortToSend is the reasoning-effort
// value to put on the provider request; "" means send no parameter.
// configuredEffort echoes sel.Effort for a model_effort_unsupported event.
// dropped reports whether a concrete configured effort was filtered out as
// unsupported.
func ResolveRequestEffort(sel Selection, supportedSet []string) (effortToSend, configuredEffort string, dropped bool) {
	configuredEffort = sel.Effort
	if sel.Effort == EffortNoReasoning {
		return "", configuredEffort, false
	}
	if slices.Contains(supportedSet, sel.Effort) {
		return sel.Effort, configuredEffort, false
	}
	return "", configuredEffort, true
}

// EmitTurnStart resolves the request effort and emits the start-of-turn events.
// It appends only — never flushing — so the caller owns the post-unsupported
// flush and the write-failure protocol; the returned dropped flag tells the
// caller a flush is required. effortToSend is the reasoning-effort value for the provider
// request ("" sends no parameter). On an append error it returns after the failed
// append without attempting the remaining one.
func EmitTurnStart(store *sessions.Store, sel Selection, source Source, supportedSet []string) (effortToSend string, dropped bool, err error) {
	effortToSend, configuredEffort, dropped := ResolveRequestEffort(sel, supportedSet)
	if dropped {
		if err := EmitModelEffortUnsupported(store, sel.Provider, sel.ID, configuredEffort); err != nil {
			return effortToSend, dropped, err
		}
	}
	if err := EmitModelTurn(store, sel.Provider, sel.ID, recordedEffort(effortToSend), source); err != nil {
		return effortToSend, dropped, err
	}
	return effortToSend, dropped, nil
}

func recordedEffort(effortToSend string) string {
	if effortToSend == "" {
		return EffortNoReasoning
	}
	return effortToSend
}

// UsageFromStreamUsage extracts the model_response token counts from a
// streaming turn's final usage chunk (include_usage), normalizing missing or
// malformed usage per subfield. usageValid reports whether a usage chunk was
// actually seen (its choices array is empty, so it is detected by
// chunk.JSON.Usage.Valid(), not by a content choice); when false — the stream
// ended without a usage chunk, e.g. an interrupted reply or a provider that
// ignores stream_options — the counts fall back to zero with usage_missing.
func UsageFromStreamUsage(u openai.CompletionUsage, usageValid bool) (inputTokens, outputTokens int64, cached *int64, cost *float64, anomalies []string) {
	return normalizeUsage(u, usageValid)
}

// normalizeUsage validates each token subfield independently: a present
// non-negative integer is preserved, a missing/negative subfield records 0, and
// any missing/malformed subfield (or an invalid usage object) yields usage_missing
// at most once. A healthy usage object returns a nil anomaly slice, which
// model_response renders as []. A missing cached count is deliberately not
// usage_missing: providers legitimately omit that field.
func normalizeUsage(u openai.CompletionUsage, usageValid bool) (inputTokens, outputTokens int64, cached *int64, cost *float64, anomalies []string) {
	if !usageValid {
		return 0, 0, nil, nil, []string{anomalyUsageMissing}
	}
	missing := false
	if u.JSON.PromptTokens.Valid() && u.PromptTokens >= 0 {
		inputTokens = u.PromptTokens
	} else {
		missing = true
	}
	if u.JSON.CompletionTokens.Valid() && u.CompletionTokens >= 0 {
		outputTokens = u.CompletionTokens
	} else {
		missing = true
	}
	// The nested metadata's zero value reports invalid when prompt_tokens_details is
	// absent entirely, so this one check also covers a missing details object.
	if u.PromptTokensDetails.JSON.CachedTokens.Valid() && u.PromptTokensDetails.CachedTokens >= 0 {
		c := u.PromptTokensDetails.CachedTokens
		cached = &c
	}
	cost = reportedCost(u)
	if missing {
		return inputTokens, outputTokens, cached, cost, []string{anomalyUsageMissing}
	}
	return inputTokens, outputTokens, cached, cost, nil
}

func reportedCost(u openai.CompletionUsage) *float64 {
	f, ok := u.JSON.ExtraFields["cost"]
	if !ok {
		return nil
	}
	var cost *float64
	if json.Unmarshal([]byte(f.Raw()), &cost) != nil || cost == nil || *cost < 0 || math.IsNaN(*cost) || math.IsInf(*cost, 0) {
		return nil
	}
	return cost
}

// UsageAccumulator sums the exact stream usage of every provider round in one
// agentic turn so the turn's single final model_response records the whole turn's
// tokens, not just the last round. A tool-call round folds its usage chunk
// in with Add before handing off to the next round; the final round folds its own
// and reads Totals. The zero value is an empty accumulator — ToolLoop owns one per
// turn.
type UsageAccumulator struct {
	inputTokens   int64
	outputTokens  int64
	cachedTokens  int64
	hadCached     bool
	missingCached bool
	costUSD       float64
	hadCost       bool
	missingCost   bool
	hadUsage      bool
	missing       bool
	validRounds   int
}

// Add folds one round's stream usage into the running total,
// normalizing the chunk exactly as UsageFromStreamUsage does: each present
// non-negative subfield adds to the total, and a missing/negative subfield or an
// absent chunk (usageValid false) records the usage_missing condition without
// inventing counts.
func (a *UsageAccumulator) Add(u openai.CompletionUsage, usageValid bool) {
	inputTokens, outputTokens, cached, cost, anomalies := normalizeUsage(u, usageValid)
	a.inputTokens += inputTokens
	a.outputTokens += outputTokens
	if cached != nil {
		a.cachedTokens += *cached
		a.hadCached = true
	} else {
		a.missingCached = true
	}
	if cost != nil && !math.IsInf(a.costUSD+*cost, 0) {
		a.costUSD += *cost
		a.hadCost = true
	} else {
		a.missingCost = true
	}
	if usageValid {
		a.hadUsage = true
		a.validRounds++
	}
	if len(anomalies) > 0 {
		a.missing = true
	}
}

// UsageRounds reports how many folded rounds carried a valid usage chunk. A
// ToolLoop snapshots this before and after a single round (around Runner.Run) to
// tell whether *that* round supplied real usage — distinct from hadUsage, which
// stays true for the rest of the turn once any one round reports usage, and so
// cannot distinguish a later usage-missing round from one that re-confirms the
// running total.
func (a *UsageAccumulator) UsageRounds() int {
	return a.validRounds
}

// Totals returns the summed token counts across every folded round, the combined
// model_response anomaly slice (usage_missing when any round's usage was missing or
// malformed, else nil), and hadUsage — whether any round carried a usage chunk at
// all. hadUsage gates the exact-figure indicator update the same way a single
// round's usageValid did: a usage chunk arrived somewhere, so the
// indicator can show a real (possibly partial) total instead of its streamed guess.
func (a *UsageAccumulator) Totals() (inputTokens, outputTokens int64, cached *int64, cachedPartial bool, cost *float64, costPartial bool, anomalies []string, hadUsage bool) {
	if a.missing {
		anomalies = []string{anomalyUsageMissing}
	}
	if a.hadCached {
		sum := a.cachedTokens
		cached = &sum
		cachedPartial = a.missingCached
	}
	if a.hadCost {
		sum := a.costUSD
		cost = &sum
		costPartial = a.missingCost
	}
	return a.inputTokens, a.outputTokens, cached, cachedPartial, cost, costPartial, anomalies, a.hadUsage
}

// SumModelResponseTokens totals recorded provider token usage across every
// model_response event in records, applying the same per-event sum the /status
// overlay surfaces (BuildStatusSnapshot) so the in-flight indicator's session
// figure stays consistent with /status. An unparseable model_response payload is
// skipped rather than panicking, matching /status; non-event and non-model_response
// records are ignored.
func SumModelResponseTokens(records []sessions.Record) (inputTokens, outputTokens int64) {
	for _, rec := range records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindModelResponse {
			continue
		}
		var p events.ModelResponse
		if json.Unmarshal(ev.Payload, &p) != nil {
			continue
		}
		inputTokens += p.InputTokens
		outputTokens += p.OutputTokens
	}
	return inputTokens, outputTokens
}
