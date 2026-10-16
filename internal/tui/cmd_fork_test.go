package tui

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	forkMetaID  = "0190c0de-0000-7000-8000-000000000101"
	forkIDUser  = "0190c0de-0000-7000-8000-0000000001a1"
	forkIDAsst  = "0190c0de-0000-7000-8000-0000000001a2"
	forkIDTool  = "0190c0de-0000-7000-8000-0000000001a3"
	forkIDSys   = "0190c0de-0000-7000-8000-0000000001a4"
	forkIDEvent = "0190c0de-0000-7000-8000-0000000001a5"
	forkIDComp  = "0190c0de-0000-7000-8000-0000000001b0"
	forkIDPar   = "0190c0de-0000-7000-8000-0000000001b1"
	forkOrigSes = "0190c0de-0000-7000-8000-0000000000f1"
	forkOrigRec = "0190c0de-0000-7000-8000-0000000000f2"
)

var forkTS = time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC)

func forkTextPart(s string) sessions.ContentPart {
	return sessions.ContentPart{Type: "text", Raw: json.RawMessage(`{"type":"text","text":"` + s + `"}`)}
}

func forkImagePart() sessions.ContentPart {
	return sessions.ContentPart{Type: "image_url", Raw: json.RawMessage(`{"type":"image_url","image_url":{"url":"http://x"}}`)}
}

func loadParentWithToolPair(t *testing.T) []sessions.Record {
	t.Helper()
	ts := func(sec int) time.Time { return forkTS.Add(time.Duration(sec) * time.Second) }
	parent := &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            forkMetaID,
			Folder:        "/proj/demo",
			StartedAt:     forkTS,
			UpdatedAt:     forkTS,
			SchemaVersion: sessions.CurrentSchemaVersion,
			ForkedFrom:    &sessions.ForkOrigin{SessionID: forkOrigSes, RecordID: forkOrigRec},
		},
		Records: []sessions.Record{
			sessions.Message{ID: forkIDUser, Role: "user", Content: sessions.TextContent("hi"), Timestamp: ts(0), ParentID: forkOrigRec},
			sessions.Message{
				ID:        forkIDAsst,
				Role:      "assistant",
				Content:   sessions.PartsContent([]sessions.ContentPart{forkTextPart("hello"), forkImagePart()}),
				Timestamp: ts(1),
				ToolCalls: []sessions.ToolCall{{ID: "call_1", Type: "function", Raw: json.RawMessage(`{"id":"call_1","type":"function","function":{"name":"ls","arguments":"{}"}}`)}},
			},
			sessions.Message{ID: forkIDTool, Role: "tool", Content: sessions.TextContent("result"), Timestamp: ts(2), ToolCallID: "call_1"},
			sessions.Message{ID: forkIDSys, Role: "system", Content: sessions.TextContent("sys"), Timestamp: ts(3)},
			sessions.Event{ID: forkIDEvent, Kind: "launch_began", Timestamp: ts(4), Payload: json.RawMessage(`{"source":"fresh"}`)},
		},
	}
	data, err := sessions.Marshal(parent)
	if err != nil {
		t.Fatalf("Marshal parent: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal parent: %v", err)
	}
	return loaded.Records
}

func TestForkContinuationRecords_PreservesCompleteMessagesAndToolPair(t *testing.T) {
	records := loadParentWithToolPair(t)

	var want []sessions.Record
	for _, rec := range records {
		if _, ok := rec.(sessions.Event); ok {
			continue
		}
		want = append(want, rec)
	}

	got := forkContinuationRecords(records)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projection did not preserve complete records in order:\n got %#v\nwant %#v", got, want)
	}
	if first, ok := got[0].(sessions.Message); !ok || first.ParentID != forkOrigRec {
		t.Fatalf("fork provenance ParentID not preserved: %#v", got[0])
	}
	if err := sessions.ValidateRecordStream(got); err != nil {
		t.Fatalf("projected stream fails the load-path validator: %v", err)
	}

	asst, ok := got[1].(sessions.Message)
	if !ok || len(asst.ToolCalls) != 1 || asst.ToolCalls[0].ID != "call_1" {
		t.Fatalf("assistant tool_calls not preserved: %#v", got[1])
	}
	tool, ok := got[2].(sessions.Message)
	if !ok || tool.ToolCallID != "call_1" {
		t.Fatalf("tool result tool_call_id not preserved: %#v", got[2])
	}
	if !asst.Content.IsList() || len(asst.Content.Parts()) != 2 {
		t.Fatalf("assistant list content parts not preserved: %#v", asst.Content)
	}
}

func TestForkContinuationRecords_ReturnsFreshSlice(t *testing.T) {
	records := loadParentWithToolPair(t)
	got := forkContinuationRecords(records)
	if len(got) > 0 && &got[0] == &records[0] {
		t.Fatal("projection returned the caller's backing array, not a fresh slice")
	}
}

func TestForkContinuationRecords_ExcludesEvents(t *testing.T) {
	records := []sessions.Record{
		sessions.Event{ID: forkIDEvent, Kind: "launch_began", Timestamp: forkTS, Payload: json.RawMessage(`{"source":"fresh"}`)},
		sessions.Message{ID: forkIDUser, Role: "user", Content: sessions.TextContent("hi"), Timestamp: forkTS},
		sessions.Event{ID: forkIDPar, Kind: "slash_command", Timestamp: forkTS, Payload: json.RawMessage(`{}`)},
		sessions.Message{ID: forkIDAsst, Role: "assistant", Content: sessions.TextContent("hey"), Timestamp: forkTS},
		sessions.Event{ID: forkIDSys, Kind: "session_forked", Timestamp: forkTS, Payload: json.RawMessage(`{}`)},
	}

	got := forkContinuationRecords(records)

	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 messages", len(got))
	}
	for i, rec := range got {
		if _, ok := rec.(sessions.Event); ok {
			t.Fatalf("record %d is an event; events must be excluded", i)
		}
	}
}

func TestForkContinuationRecords_PreservesCompactionContext(t *testing.T) {
	compaction := sessions.Compaction{
		ID:        forkIDComp,
		Summary:   "prior conversation summary",
		Timestamp: forkTS,
		Provider:  "anthropic",
		ModelID:   "claude",
		ParentID:  forkIDPar,
	}
	records := []sessions.Record{
		compaction,
		sessions.Message{ID: forkIDUser, Role: "user", Content: sessions.TextContent("continue"), Timestamp: forkTS},
		sessions.Event{ID: forkIDEvent, Kind: "launch_began", Timestamp: forkTS, Payload: json.RawMessage(`{"source":"fork"}`)},
		sessions.Message{ID: forkIDAsst, Role: "assistant", Content: sessions.TextContent("ok"), Timestamp: forkTS},
	}

	got := forkContinuationRecords(records)

	if len(got) != 3 {
		t.Fatalf("got %d records, want compaction + 2 messages", len(got))
	}
	first, ok := got[0].(sessions.Compaction)
	if !ok {
		t.Fatalf("record 0 is not a compaction: %#v", got[0])
	}
	if !reflect.DeepEqual(first, compaction) {
		t.Fatalf("compaction record was altered:\n got %#v\nwant %#v", first, compaction)
	}
	for i, rec := range got {
		if _, ok := rec.(sessions.Event); ok {
			t.Fatalf("record %d is an event; events must be excluded", i)
		}
	}
}

func forkableSession(title string) *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            forkMetaID,
			Folder:        "/proj/demo",
			Title:         title,
			StartedAt:     forkTS,
			UpdatedAt:     forkTS,
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
		Records: []sessions.Record{
			sessions.Message{ID: forkIDUser, Role: "user", Content: sessions.TextContent("hi"), Timestamp: forkTS},
		},
	}
}

func forkStore(t *testing.T, session *sessions.Session) *sessions.Store {
	t.Helper()
	return sessions.New(filepath.Join(t.TempDir(), "parent.json"), session)
}

func flushForkParent(store *sessions.Store) error {
	_, _, err := store.Flush(context.Background())
	return err
}

func persistedForkEvents(t *testing.T, store *sessions.Store) []sessions.Event {
	t.Helper()
	session, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed parent session: %v", err)
	}
	var out []sessions.Event
	for _, record := range session.Records {
		if event, ok := record.(sessions.Event); ok && event.Kind == events.KindSlashCommand {
			out = append(out, event)
		}
	}
	return out
}

func forkRegistry(t *testing.T, deps ForkDeps) *Registry {
	t.Helper()
	reg, err := NewRegistry([]Command{
		{Name: "fork", Description: "Fork the current session", ArgSig: ArgNone, Phase: PhaseTwo, Handler: NewForkHandler(deps)},
	})
	if err != nil {
		t.Fatalf("build fork registry: %v", err)
	}
	return reg
}

func TestForkHandler_RefusesActiveTurnWithoutCancellation(t *testing.T) {
	host := &fakeHost{store: forkStore(t, forkableSession("Refactor plan"))}
	var flushCalls, createCalls int
	deps := ForkDeps{
		TurnActive: func() bool { return true },
		FlushParent: func(store *sessions.Store) error {
			flushCalls++
			evs := slashEvents(store)
			if len(evs) != 1 {
				t.Fatalf("at refusal flush the store holds %d slash_command events, want 1", len(evs))
			}
			if p := decodeSlash(t, evs[0]); p.Outcome != "error" || p.ErrorDetail != "fork unavailable while a turn is active" {
				t.Errorf("event at refusal flush = %+v, want outcome=error with active-turn detail", p)
			}
			return flushForkParent(store)
		},
		CreateAndActivate: func(*sessions.Store, string, []sessions.Record, []sessions.Record) (string, error) {
			createCalls++
			return "", nil
		},
	}

	res := forkRegistry(t, deps).DispatchSlashInput("/fork", host)

	if res.Status != StatusHandled || res.Canonical != "fork" || res.Err != nil {
		t.Fatalf("dispatch /fork = %+v, want Handled/fork/nil-err", res)
	}
	if !res.RetainInput {
		t.Error("active-turn refusal did not retain the typed input")
	}
	want := "fork unavailable while a turn is active"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Fatalf("notices = %v, want exactly [%q]", host.notices, want)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "fork" || p.Outcome != "error" || p.ErrorDetail != want {
		t.Errorf("event = %+v, want name=fork outcome=error error_detail=%q", p, want)
	}
	persisted := persistedForkEvents(t, host.store)
	if len(persisted) != 1 {
		t.Fatalf("persisted slash_command events = %d, want 1", len(persisted))
	}
	if p := decodeSlash(t, persisted[0]); p.Name != "fork" || p.Outcome != "error" || p.ErrorDetail != want {
		t.Errorf("persisted event = %+v, want name=fork outcome=error error_detail=%q", p, want)
	}
	if flushCalls != 1 {
		t.Errorf("FlushParent called %d times, want 1 (the refusal event must be made durable)", flushCalls)
	}
	if createCalls != 0 {
		t.Errorf("CreateAndActivate called %d times on an active-turn refusal, want 0", createCalls)
	}
}

func TestForkHandler_RefusesEmptyContinuation(t *testing.T) {
	emptyParent := &sessions.Session{
		Metadata: forkableSession("").Metadata,
		Records: []sessions.Record{
			sessions.Event{ID: forkIDEvent, Kind: "launch_began", Timestamp: forkTS, Payload: json.RawMessage(`{"source":"fresh"}`)},
		},
	}
	host := &fakeHost{store: forkStore(t, emptyParent)}
	var flushCalls, createCalls int
	deps := ForkDeps{
		TurnActive: func() bool { return false },
		FlushParent: func(store *sessions.Store) error {
			flushCalls++
			evs := slashEvents(store)
			if len(evs) != 1 {
				t.Fatalf("at refusal flush the store holds %d slash_command events, want 1", len(evs))
			}
			if p := decodeSlash(t, evs[0]); p.Outcome != "error" || p.ErrorDetail != "nothing to fork" {
				t.Errorf("event at refusal flush = %+v, want outcome=error error_detail=%q", p, "nothing to fork")
			}
			return flushForkParent(store)
		},
		CreateAndActivate: func(*sessions.Store, string, []sessions.Record, []sessions.Record) (string, error) {
			createCalls++
			return "", nil
		},
	}

	res := forkRegistry(t, deps).DispatchSlashInput("/fork", host)

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /fork = %+v, want Handled/nil-err", res)
	}
	if !res.RetainInput {
		t.Error("empty-continuation refusal did not retain the typed input")
	}
	if len(host.notices) != 1 || host.notices[0] != "nothing to fork" {
		t.Fatalf("notices = %v, want exactly [%q]", host.notices, "nothing to fork")
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Outcome != "error" || p.ErrorDetail != "nothing to fork" {
		t.Errorf("event = %+v, want outcome=error error_detail=%q", p, "nothing to fork")
	}
	persisted := persistedForkEvents(t, host.store)
	if len(persisted) != 1 {
		t.Fatalf("persisted slash_command events = %d, want 1", len(persisted))
	}
	if p := decodeSlash(t, persisted[0]); p.Name != "fork" || p.Outcome != "error" || p.ErrorDetail != "nothing to fork" {
		t.Errorf("persisted event = %+v, want name=fork outcome=error error_detail=%q", p, "nothing to fork")
	}
	if flushCalls != 1 {
		t.Errorf("FlushParent called %d times, want 1 (the refusal event must be made durable)", flushCalls)
	}
	if createCalls != 0 {
		t.Errorf("CreateAndActivate called %d times on an empty parent, want 0", createCalls)
	}
}

func TestForkHandler_CompactionOnlyParentIsEligible(t *testing.T) {
	compactionParent := &sessions.Session{
		Metadata: forkableSession("").Metadata,
		Records: []sessions.Record{
			sessions.Compaction{ID: forkIDComp, Summary: "prior summary", Timestamp: forkTS, Provider: "anthropic", ModelID: "claude", ParentID: forkIDPar},
		},
	}
	host := &fakeHost{store: sessions.New("", compactionParent)}
	var createCalls int
	deps := ForkDeps{
		TurnActive:  func() bool { return false },
		FlushParent: func(*sessions.Store) error { return nil },
		CreateAndActivate: func(_ *sessions.Store, _ string, records, _ []sessions.Record) (string, error) {
			createCalls++
			if len(records) != 1 {
				t.Errorf("callback got %d records, want 1 (the compaction record)", len(records))
			}
			return "", nil
		},
	}

	res := forkRegistry(t, deps).DispatchSlashInput("/fork", host)

	if res.Status != StatusHandled || res.Err != nil || res.RetainInput {
		t.Fatalf("dispatch /fork = %+v, want accepted Handled/nil-err", res)
	}
	if createCalls != 1 {
		t.Errorf("CreateAndActivate called %d times, want 1 (a compaction-only parent is nonempty)", createCalls)
	}
}

func finalizeForkParent(t *testing.T, parent *sessions.Store, terminal []sessions.Record) {
	t.Helper()
	marker, err := events.Build(events.SessionForked{ToSessionID: forkOrigSes})
	if err != nil {
		t.Fatalf("build session_forked: %v", err)
	}
	if _, _, err := parent.CommitFinalRecords(context.Background(), append(terminal, marker)...); err != nil {
		t.Fatalf("commit terminal records: %v", err)
	}
}

func TestForkHandler_PassesSuccessIntoChildFinalization(t *testing.T) {
	host := &fakeHost{store: forkStore(t, forkableSession("Refactor plan"))}
	var flushCalls, createCalls int
	deps := ForkDeps{
		TurnActive: func() bool { return false },
		FlushParent: func(*sessions.Store) error {
			flushCalls++
			return nil
		},
		CreateAndActivate: func(parent *sessions.Store, title string, records, terminal []sessions.Record) (string, error) {
			createCalls++
			if parent != host.store {
				t.Error("CreateAndActivate got a different store than the active parent")
			}
			if title != "Refactor plan (forked)" {
				t.Errorf("callback title = %q, want %q", title, "Refactor plan (forked)")
			}
			if len(records) != 1 {
				t.Errorf("callback got %d continuation records, want 1", len(records))
			} else if msg, ok := records[0].(sessions.Message); !ok || msg.ID != forkIDUser {
				t.Errorf("callback record = %#v, want the projected user message", records[0])
			}
			if n := len(slashEvents(parent)); n != 0 {
				t.Errorf("parent holds %d slash_command events before finalization, want 0", n)
			}
			if len(terminal) != 1 {
				t.Fatalf("terminal records = %d, want the success event", len(terminal))
			}
			ev, ok := terminal[0].(sessions.Event)
			if !ok || ev.Kind != events.KindSlashCommand {
				t.Fatalf("terminal record = %#v, want a slash_command event", terminal[0])
			}
			if p := decodeSlash(t, ev); p.Name != "fork" || p.Outcome != "success" || p.ErrorDetail != "" {
				t.Errorf("terminal event = %+v, want name=fork outcome=success", p)
			}
			finalizeForkParent(t, parent, terminal)
			return "", nil
		},
	}

	res := forkRegistry(t, deps).DispatchSlashInput("/fork", host)

	if res.Status != StatusHandled || res.Err != nil || res.RetainInput {
		t.Fatalf("dispatch /fork = %+v, want accepted Handled/nil-err", res)
	}
	if createCalls != 1 || flushCalls != 0 {
		t.Fatalf("CreateAndActivate calls = %d, FlushParent calls = %d; want 1 and 0", createCalls, flushCalls)
	}
	disk, _, err := sessions.OpenSession(host.store.Path())
	if err != nil {
		t.Fatalf("open parent: %v", err)
	}
	var kinds []string
	for _, rec := range disk.Records {
		if ev, ok := rec.(sessions.Event); ok {
			kinds = append(kinds, ev.Kind)
		}
	}
	if !reflect.DeepEqual(kinds, []string{events.KindSlashCommand, events.KindSessionForked}) {
		t.Fatalf("persisted parent events = %v, want one success immediately before session_forked", kinds)
	}
}

func TestForkHandler_CreateFailureIsConservativeAndRetainsInput(t *testing.T) {
	host := &fakeHost{store: forkStore(t, forkableSession("Refactor plan"))}
	var flushCalls int
	deps := ForkDeps{
		TurnActive: func() bool { return false },
		FlushParent: func(store *sessions.Store) error {
			flushCalls++
			return flushForkParent(store)
		},
		CreateAndActivate: func(*sessions.Store, string, []sessions.Record, []sessions.Record) (string, error) {
			return "", errors.New("capability write failed")
		},
	}

	res := forkRegistry(t, deps).DispatchSlashInput("/fork", host)

	if res.Status != StatusHandled || res.Err != nil {
		t.Fatalf("dispatch /fork = %+v, want Handled/nil-err", res)
	}
	if !res.RetainInput {
		t.Error("callback failure did not retain the typed input")
	}
	want := "fork failed: capability write failed"
	if len(host.notices) != 1 || host.notices[0] != want {
		t.Fatalf("notices = %v, want exactly [%q] (conservative: no no-child claim)", host.notices, want)
	}
	if flushCalls != 1 {
		t.Errorf("FlushParent called %d times, want 1 (the error record)", flushCalls)
	}
	disk, _, err := sessions.OpenSession(host.store.Path())
	if err != nil {
		t.Fatalf("open parent: %v", err)
	}
	var slash []sessions.Event
	for _, rec := range disk.Records {
		ev, ok := rec.(sessions.Event)
		if !ok {
			continue
		}
		switch ev.Kind {
		case events.KindSessionForked:
			t.Fatal("parent persisted session_forked after a failed preparation")
		case events.KindSlashCommand:
			slash = append(slash, ev)
		}
	}
	if len(slash) != 1 {
		t.Fatalf("persisted slash_command events = %d, want only the error outcome", len(slash))
	}
	if p := decodeSlash(t, slash[0]); p.Name != "fork" || p.Outcome != "error" || p.ErrorDetail != want {
		t.Errorf("persisted event = %+v, want name=fork outcome=error error_detail=%q", p, want)
	}
	before := len(host.store.Records())
	if _, err := events.Append(host.store, events.SlashCommand{Name: "fork", Args: []string{}, Outcome: "error", ErrorDetail: "still writable"}); err != nil {
		t.Fatalf("append to parent after callback failure: %v", err)
	}
	if got := len(host.store.Records()); got != before+1 {
		t.Errorf("parent records = %d after post-failure append, want %d (parent must remain appendable)", got, before+1)
	}
}

func TestForkHandler_SuccessNoticeFollowsActivationCallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		warning string
		want    string
	}{
		{name: "no warning", want: `Forked to "Refactor plan (forked)"`},
		{name: "cleanup warning", warning: "can't remove private temp folder /t/old: denied; codemeld retries when it exits",
			want: `Forked to "Refactor plan (forked)"; can't remove private temp folder /t/old: denied; codemeld retries when it exits`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHost{store: sessions.New("", forkableSession("Refactor plan"))}
			var noticesAtCallback int
			deps := ForkDeps{
				TurnActive:  func() bool { return false },
				FlushParent: func(*sessions.Store) error { return nil },
				CreateAndActivate: func(*sessions.Store, string, []sessions.Record, []sessions.Record) (string, error) {
					noticesAtCallback = len(host.notices)
					return tc.warning, nil
				},
			}

			res := forkRegistry(t, deps).DispatchSlashInput("/fork", host)

			if res.Status != StatusHandled || res.Err != nil {
				t.Fatalf("dispatch /fork = %+v, want Handled/nil-err", res)
			}
			if res.RetainInput {
				t.Error("successful /fork retained the typed input, want it cleared")
			}
			if noticesAtCallback != 0 {
				t.Errorf("%d notices rendered before the callback returned, want 0", noticesAtCallback)
			}
			if len(host.notices) != 1 || host.notices[0] != tc.want {
				t.Fatalf("notices = %v, want exactly [%q]", host.notices, tc.want)
			}
		})
	}
}

func TestDeriveForkTitle(t *testing.T) {
	cases := []struct {
		name   string
		parent string
		want   string
	}{
		{"titled parent", "Refactor plan", "Refactor plan (forked)"},
		{"untitled parent", "", "Forked session"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveForkTitle(tc.parent); got != tc.want {
				t.Errorf("deriveForkTitle(%q) = %q, want %q", tc.parent, got, tc.want)
			}
		})
	}
}
