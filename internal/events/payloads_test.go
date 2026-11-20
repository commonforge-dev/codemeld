package events

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"codemeld.dev/codemeld/internal/sessions"
)

func TestSandboxWriteRefused_RoundTripsThroughSessionFile(t *testing.T) {
	want := []SandboxWriteRefused{
		{Path: "/ssdtmp/go-build/e3/x-a", Process: "go", Folder: "/ssdtmp/go-build", Variable: "GOCACHE"},
		{Path: "/opt/cache/f", Process: "cc", Folder: "/opt/cache"},
		{Path: "/etc/x", Process: "sh", Reason: "blocked path"},
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
		if !ok || ev.Kind != "sandbox_write_refused" {
			t.Fatalf("record %d = %T kind %q, want a sandbox_write_refused event", i, rec, ev.Kind)
		}
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("record %d fails load validation: %v", i, err)
		}
		var got SandboxWriteRefused
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("decode record %d: %v", i, err)
		}
		if got != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, got, want[i])
		}
	}
}

func TestSandboxWriteRefused_RejectsInvalidRecords(t *testing.T) {
	for name, p := range map[string]SandboxWriteRefused{
		"no path":                {Folder: "/a"},
		"variable but no folder": {Path: "/a/b", Variable: "GOCACHE"},
	} {
		if err := p.validate(); err == nil {
			t.Errorf("%s: validate() = nil, want an error", name)
		}
	}
}
