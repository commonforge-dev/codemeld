package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

func TestExecutionCapability_RoundTripsThroughSessionFile(t *testing.T) {
	want := []ExecutionCapability{
		{
			Capability: "refused",
			Reason:     "landlock unavailable on this kernel",
			Legs: []ExecutionCapabilityLeg{
				{Name: "write_outside_root", Observed: "held_by_host"},
				{Name: "read_inside_root", Observed: "not_run"},
			},
		},
		{
			Capability: "constrained",
			Legs: []ExecutionCapabilityLeg{
				{Name: "write_outside_root", Observed: "denied"},
				{Name: "network_egress", Observed: "held_by_host"},
				{Name: "read_inside_root", Observed: "allowed"},
			},
		},
	}
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())
	for _, p := range want {
		if _, err := Append(store, p); err != nil {
			t.Fatalf("Append(%+v) error = %v", p, err)
		}
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse session file: %v", err)
	}
	if len(loaded.Records) != len(want) {
		t.Fatalf("persisted records = %d, want %d", len(loaded.Records), len(want))
	}
	for i, rec := range loaded.Records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != KindExecutionCapability {
			t.Fatalf("record %d = %T kind %q, want sessions.Event %q", i, rec, ev.Kind, KindExecutionCapability)
		}
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("record %d fails load validation: %v", i, err)
		}
		var got ExecutionCapability
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("decode record %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, want[i]) {
			t.Errorf("record %d = %+v, want %+v", i, got, want[i])
		}
	}
}

func TestExecutionCapability_RejectsInvalidRecords(t *testing.T) {
	leg := []ExecutionCapabilityLeg{{Name: "write_outside_root", Observed: "denied"}}
	cases := []struct {
		name string
		p    ExecutionCapability
	}{
		{"unknown capability", ExecutionCapability{Capability: "unknown", Legs: leg}},
		{"refused without reason", ExecutionCapability{Capability: "refused", Legs: leg}},
		{"constrained with reason", ExecutionCapability{Capability: "constrained", Reason: "why", Legs: leg}},
		{"constrained without legs", ExecutionCapability{Capability: "constrained"}},
		{"leg without name", ExecutionCapability{Capability: "constrained", Legs: []ExecutionCapabilityLeg{{Observed: "denied"}}}},
		{"leg with unknown observation", ExecutionCapability{Capability: "refused", Reason: "why", Legs: []ExecutionCapabilityLeg{{Name: "write_outside_root", Observed: "maybe"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore()
			if _, err := Append(store, tc.p); err == nil {
				t.Fatalf("Append(%+v) accepted an invalid record", tc.p)
			}
			if got := len(store.Records()); got != 0 {
				t.Fatalf("rejected payload appended %d record(s), want 0", got)
			}
			raw, err := json.Marshal(tc.p)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			if err := ValidatePayload(KindExecutionCapability, raw); err == nil {
				t.Fatalf("ValidatePayload(%s) accepted an invalid record", raw)
			}
		})
	}
}
