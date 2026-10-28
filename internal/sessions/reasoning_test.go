package sessions

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func reasoningRecord(role, reasoning string) string {
	return `{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02","role":"` + role +
		`","content":"a","timestamp":"2026-05-25T12:00:01.000Z","reasoning":` + reasoning + `}`
}

func TestReasoningRoundTrips(t *testing.T) {
	const reasoning = `{"provider":"openrouter","model_id":"reflection/beam","text":"t","details":[{"type":"reasoning.text","text":"t","index":0}]}`
	s, err := Unmarshal([]byte(withRecords(reasoningRecord("assistant", reasoning))))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	data, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	back, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("re-Unmarshal() error = %v", err)
	}
	got := back.Records[0].(Message).Reasoning
	if got == nil || got.Provider != "openrouter" || got.ModelID != "reflection/beam" || got.Text != "t" {
		t.Fatalf("reasoning = %+v, want the stored provider, model and text", got)
	}
	var compact bytes.Buffer
	_ = json.Compact(&compact, got.Details)
	if compact.String() != `[{"type":"reasoning.text","text":"t","index":0}]` {
		t.Fatalf("details = %s, want them verbatim", got.Details)
	}

	plain, err := Unmarshal([]byte(withRecords(`{"type":"message","id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02","role":"assistant","content":"a","timestamp":"2026-05-25T12:00:01.000Z"}`)))
	if err != nil {
		t.Fatalf("Unmarshal(plain) error = %v", err)
	}
	if data, _ := Marshal(plain); strings.Contains(string(data), "reasoning") {
		t.Fatalf("message without reasoning marshals a reasoning field: %s", data)
	}
}

func TestReasoningRejectsMalformed(t *testing.T) {
	for _, tc := range []struct{ name, role, reasoning string }{
		{"non-assistant role", "user", `{"provider":"openrouter","model_id":"m","text":"t"}`},
		{"missing provider", "assistant", `{"model_id":"m","text":"t"}`},
		{"missing model", "assistant", `{"provider":"openrouter","text":"t"}`},
		{"details not a list", "assistant", `{"provider":"openrouter","model_id":"m","details":{"type":"x"}}`},
		{"details number member", "assistant", `{"provider":"openrouter","model_id":"m","details":[42]}`},
		{"details string member", "assistant", `{"provider":"openrouter","model_id":"m","details":["bad"]}`},
		{"details bool member", "assistant", `{"provider":"openrouter","model_id":"m","details":[true]}`},
		{"details null member", "assistant", `{"provider":"openrouter","model_id":"m","details":[null]}`},
		{"details nested array member", "assistant", `{"provider":"openrouter","model_id":"m","details":[[{"type":"x"}]]}`},
		{"details mixed members", "assistant", `{"provider":"openrouter","model_id":"m","details":[{"type":"reasoning.text","text":"t"},7]}`},
		{"empty", "assistant", `{"provider":"openrouter","model_id":"m"}`},
		{"not an object", "assistant", `"t"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Unmarshal([]byte(withRecords(reasoningRecord(tc.role, tc.reasoning)))); err == nil || !strings.Contains(err.Error(), "reasoning") {
				t.Fatalf("Unmarshal() error = %v, want a reasoning error", err)
			}
		})
	}
}
