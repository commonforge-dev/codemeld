package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

func TestConnectDecision_EachKindRoundTripsThroughSessionFile(t *testing.T) {
	want := []ConnectDecision{
		{Destination: "127.0.0.1:3128", Decision: "allowed", Step: "proxy", Count: 4},
		{Destination: "127.0.0.1:8080", Decision: "allowed", Step: "own listener", Count: 1},
		{Destination: "/run/user/1000/bus", Decision: "allowed", Step: "grant", Count: 1},
		{Destination: "[::1]:5432", Decision: "allowed", Step: "session approval", Count: 2},
		{Destination: "/tmp/agent.sock", Decision: "allowed", Step: "prompt once", Answer: "once", Count: 1},
		{Destination: "10.0.0.5:22", Decision: "allowed", Step: "prompt session", Answer: "session", Count: 1},
		{Destination: "10.0.0.6:443", Decision: "denied", Reason: "direct connection not allowed (use the proxy)", Count: 3},
		{Destination: "/var/run/docker.sock", Decision: "denied", Reason: "Unix socket connect not granted", Count: 1},
		{Destination: "/home/u/.ssh/agent", Decision: "denied", Reason: "always denied: /home/u/.ssh/agent", Count: 1},
		{Destination: "/tmp/x.sock", Decision: "denied", Reason: "not approved (denied)", Answer: "deny", Count: 1},
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
		if !ok || ev.Kind != "connect_decision" {
			t.Fatalf("record %d = %T kind %q, want a connect_decision event", i, rec, ev.Kind)
		}
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("record %d fails load validation: %v", i, err)
		}
		var got ConnectDecision
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("decode record %d: %v", i, err)
		}
		if got != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, got, want[i])
		}
	}
}

func TestConnectDecision_RejectsInvalidRecords(t *testing.T) {
	for name, p := range map[string]ConnectDecision{
		"no destination":        {Decision: "allowed", Step: "proxy", Count: 1},
		"unknown decision":      {Destination: "/s", Decision: "maybe", Count: 1},
		"allowed unknown step":  {Destination: "/s", Decision: "allowed", Step: "luck", Count: 1},
		"allowed with reason":   {Destination: "/s", Decision: "allowed", Step: "grant", Reason: "why", Count: 1},
		"denied without reason": {Destination: "/s", Decision: "denied", Count: 1},
		"denied with step":      {Destination: "/s", Decision: "denied", Step: "grant", Reason: "why", Count: 1},
		"unknown answer":        {Destination: "/s", Decision: "allowed", Step: "prompt once", Answer: "always", Count: 1},
		"zero count":            {Destination: "/s", Decision: "allowed", Step: "grant"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Append(newStore(), p); err == nil {
				t.Fatalf("Append(%+v) accepted an invalid record", p)
			}
		})
	}
}
