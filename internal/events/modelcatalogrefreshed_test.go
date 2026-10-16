package events

import (
	"encoding/json"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

func TestModelCatalogRefreshed_AcceptsEveryOutcome(t *testing.T) {
	for _, outcome := range []string{"updated", "no_change", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			store := newStore()
			rec, err := Append(store, ModelCatalogRefreshed{Provider: "openai", Outcome: outcome})
			if err != nil {
				t.Fatalf("Append() error = %v", err)
			}
			raw, err := marshalPayload(ModelCatalogRefreshed{Provider: "openai", Outcome: outcome})
			if err != nil {
				t.Fatalf("marshalPayload() error = %v", err)
			}
			if err := ValidatePayload(KindModelCatalogRefreshed, raw); err != nil {
				t.Fatalf("ValidatePayload() rejected a valid payload %s: %v", raw, err)
			}
			ev, ok := rec.(sessions.Event)
			if !ok {
				t.Fatalf("Append() returned %T, want sessions.Event", rec)
			}
			var got ModelCatalogRefreshed
			if err := json.Unmarshal(ev.Payload, &got); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			if got.Provider != "openai" || got.Outcome != outcome {
				t.Errorf("payload = %+v, want provider openai with outcome %q", got, outcome)
			}
		})
	}
}

func TestModelCatalogRefreshed_RejectsInvalidFields(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty-provider", `{"provider":"","outcome":"updated"}`},
		{"missing-provider", `{"outcome":"updated"}`},
		{"null-provider", `{"provider":null,"outcome":"updated"}`},
		{"empty-outcome", `{"provider":"openai","outcome":""}`},
		{"missing-outcome", `{"provider":"openai"}`},
		{"null-outcome", `{"provider":"openai","outcome":null}`},
		{"unknown-outcome", `{"provider":"openai","outcome":"refreshed"}`},
		{"outcome-case-mismatch", `{"provider":"openai","outcome":"Updated"}`},
		{"outcome-type-mismatch", `{"provider":"openai","outcome":3}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(KindModelCatalogRefreshed, json.RawMessage(tc.raw)); err == nil {
				t.Errorf("ValidatePayload() accepted %s", tc.raw)
			}
		})
	}
}

func TestModelCatalogRefreshed_RejectedAppendLeavesNoRecord(t *testing.T) {
	store := newStore()
	if _, err := Append(store, ModelCatalogRefreshed{Provider: "openai", Outcome: "refreshed"}); err == nil {
		t.Fatal("Append() accepted an unknown outcome")
	}
	if got := len(store.Records()); got != 0 {
		t.Errorf("rejected payload appended %d record(s), want 0", got)
	}
}
