package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

const childRoot = "/home/u/proj"

func childDeclared(names ...string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, filepath.Join(childRoot, name))
	}
	return out
}

func validChildStart(invocation string) ChildAgentStart {
	return ChildAgentStart{
		InvocationID:      invocation,
		ProviderID:        "openai",
		ModelID:           "gpt-5.5",
		DeclaredPaths:     childDeclared("a.txt", "b.txt"),
		StepCap:           12,
		InstructionBytes:  42,
		InstructionDigest: ChildInstructionDigest("rewrite the report"),
	}
}

func validChildEnd(invocation string) ChildAgentEnd {
	return ChildAgentEnd{
		InvocationID:    invocation,
		Reason:          ChildAgentReasonCompleted,
		Steps:           3,
		WrittenPaths:    childDeclared("a.txt"),
		RollbackOutcome: ChildRollbackNotNeeded,
		DurationMs:      1200,
	}
}

func TestEmitChildAgentPair_DurableRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())
	invocation := ids.NewV7()

	const instruction = "rewrite the report and keep the tone plain"
	start := validChildStart(invocation)
	start.InstructionBytes = int64(len(instruction))
	start.InstructionDigest = ChildInstructionDigest(instruction)
	if err := EmitChildAgentStart(store, childRoot, start); err != nil {
		t.Fatalf("EmitChildAgentStart() error = %v", err)
	}
	end := validChildEnd(invocation)
	end.ReplyTruncated = true
	if err := EmitChildAgentEnd(store, childRoot, end); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Store.Flush() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("session file not written (flush did not run): %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if len(loaded.Records) != 2 {
		t.Fatalf("persisted records = %d, want 2", len(loaded.Records))
	}
	startEv, ok := loaded.Records[0].(sessions.Event)
	if !ok || startEv.Kind != KindChildAgentStart {
		t.Fatalf("record 0 = %T kind %q, want sessions.Event %q", loaded.Records[0], startEv.Kind, KindChildAgentStart)
	}
	endEv, ok := loaded.Records[1].(sessions.Event)
	if !ok || endEv.Kind != KindChildAgentEnd {
		t.Fatalf("record 1 = %T kind %q, want sessions.Event %q", loaded.Records[1], endEv.Kind, KindChildAgentEnd)
	}
	for i, ev := range []sessions.Event{startEv, endEv} {
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload(%q) rejected persisted record %d: %v", ev.Kind, i, err)
		}
	}

	var gotStart ChildAgentStart
	mustUnmarshal(t, startEv.Payload, &gotStart)
	if gotStart.InvocationID != invocation {
		t.Errorf("start invocation_id = %q, want %q", gotStart.InvocationID, invocation)
	}
	if gotStart.ProviderID != "openai" || gotStart.ModelID != "gpt-5.5" {
		t.Errorf("start model = %q/%q, want openai/gpt-5.5", gotStart.ProviderID, gotStart.ModelID)
	}
	if strings.Join(gotStart.DeclaredPaths, ",") != strings.Join(childDeclared("a.txt", "b.txt"), ",") {
		t.Errorf("start declared_paths = %v, want the declared list in order", gotStart.DeclaredPaths)
	}
	if gotStart.StepCap != 12 || gotStart.InstructionBytes != int64(len(instruction)) {
		t.Errorf("start step_cap/instruction_bytes = %d/%d, want 12/%d", gotStart.StepCap, gotStart.InstructionBytes, len(instruction))
	}
	if gotStart.InstructionDigest != ChildInstructionDigest(instruction) {
		t.Errorf("start instruction_digest = %q, want the instruction's SHA-256", gotStart.InstructionDigest)
	}

	var gotEnd ChildAgentEnd
	mustUnmarshal(t, endEv.Payload, &gotEnd)
	if gotEnd.InvocationID != invocation {
		t.Errorf("end invocation_id = %q, want the start's %q", gotEnd.InvocationID, invocation)
	}
	if gotEnd.Reason != ChildAgentReasonCompleted || gotEnd.RollbackOutcome != ChildRollbackNotNeeded {
		t.Errorf("end reason/rollback = %q/%q, want completed/not_needed", gotEnd.Reason, gotEnd.RollbackOutcome)
	}
	if gotEnd.Steps != 3 || gotEnd.DurationMs != 1200 || !gotEnd.ReplyTruncated {
		t.Errorf("end steps/duration/truncated = %d/%d/%v, want 3/1200/true", gotEnd.Steps, gotEnd.DurationMs, gotEnd.ReplyTruncated)
	}

	for _, forbidden := range []string{"instruction", "instructions", "reply", "content", "text", "api_key", "token"} {
		if _, present := rawFields(t, startEv.Payload)[forbidden]; present {
			t.Errorf("child_agent_start carries %q: %s", forbidden, startEv.Payload)
		}
		if _, present := rawFields(t, endEv.Payload)[forbidden]; present {
			t.Errorf("child_agent_end carries %q: %s", forbidden, endEv.Payload)
		}
	}
	for _, forbidden := range []string{instruction, "rewrite the report", "the tone plain"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Errorf("session file carries the delegated text %q", forbidden)
		}
	}
}

func TestChildAgentPayloads_RejectMalformed(t *testing.T) {
	invocation := ids.NewV7()
	overDeclared := make([]string, maxChildDeclaredPaths+1)
	for i := range overDeclared {
		overDeclared[i] = filepath.Join(childRoot, "f", string(rune('a'+i%26)), "x.txt")
	}
	overWritten := make([]string, maxChildWrittenPaths+1)
	for i := range overWritten {
		overWritten[i] = filepath.Join(childRoot, "w", string(rune('a'+i%26)), "x.txt")
	}
	overDeleted := make([]string, maxChildDeletedPaths+1)
	for i := range overDeleted {
		overDeleted[i] = filepath.Join(childRoot, "d", fmt.Sprintf("f%03d.txt", i))
	}

	tests := []struct {
		name    string
		payload EventPayload
	}{
		{"start missing invocation id", func() EventPayload {
			p := validChildStart(invocation)
			p.InvocationID = ""
			return p
		}()},
		{"start non-uuidv7 invocation id", func() EventPayload {
			p := validChildStart(invocation)
			p.InvocationID = "not-an-id"
			return p
		}()},
		{"start over-cap declared list", func() EventPayload {
			p := validChildStart(invocation)
			p.DeclaredPaths = overDeclared
			return p
		}()},
		{"start relative declared path", func() EventPayload {
			p := validChildStart(invocation)
			p.DeclaredPaths = []string{"a.txt"}
			return p
		}()},
		{"start relative declared delete path", func() EventPayload {
			p := validChildStart(invocation)
			p.DeclaredDeletePaths = []string{"old.txt"}
			return p
		}()},
		{"start over-cap declared delete list", func() EventPayload {
			p := validChildStart(invocation)
			p.DeclaredPaths = nil
			p.DeclaredDeletePaths = overDeclared
			return p
		}()},
		{"start missing provider", func() EventPayload {
			p := validChildStart(invocation)
			p.ProviderID = ""
			return p
		}()},
		{"start missing model", func() EventPayload {
			p := validChildStart(invocation)
			p.ModelID = ""
			return p
		}()},
		{"start non-positive step cap", func() EventPayload {
			p := validChildStart(invocation)
			p.StepCap = 0
			return p
		}()},
		{"start empty instruction", func() EventPayload {
			p := validChildStart(invocation)
			p.InstructionBytes = 0
			return p
		}()},
		{"start malformed digest", func() EventPayload {
			p := validChildStart(invocation)
			p.InstructionDigest = "abc"
			return p
		}()},
		{"end missing invocation id", func() EventPayload {
			p := validChildEnd(invocation)
			p.InvocationID = ""
			return p
		}()},
		{"end unknown terminal reason", func() EventPayload {
			p := validChildEnd(invocation)
			p.Reason = "abandoned"
			return p
		}()},
		{"end empty terminal reason", func() EventPayload {
			p := validChildEnd(invocation)
			p.Reason = ""
			return p
		}()},
		{"end unknown rollback outcome", func() EventPayload {
			p := validChildEnd(invocation)
			p.RollbackOutcome = "partially"
			return p
		}()},
		{"end empty rollback outcome", func() EventPayload {
			p := validChildEnd(invocation)
			p.RollbackOutcome = ""
			return p
		}()},
		{"end negative step count", func() EventPayload {
			p := validChildEnd(invocation)
			p.Steps = -1
			return p
		}()},
		{"end negative duration", func() EventPayload {
			p := validChildEnd(invocation)
			p.DurationMs = -1
			return p
		}()},
		{"end over-cap written list", func() EventPayload {
			p := validChildEnd(invocation)
			p.WrittenPaths = overWritten
			return p
		}()},
		{"end relative written path", func() EventPayload {
			p := validChildEnd(invocation)
			p.WrittenPaths = []string{"a.txt"}
			return p
		}()},
		{"end over-cap deleted list", func() EventPayload {
			p := validChildEnd(invocation)
			p.DeletedPaths = overDeleted
			return p
		}()},
		{"end relative deleted path", func() EventPayload {
			p := validChildEnd(invocation)
			p.DeletedPaths = []string{"old.txt"}
			return p
		}()},
		{"end deleted total that bounded nothing", func() EventPayload {
			p := validChildEnd(invocation)
			p.DeletedPaths = childDeclared("old.txt")
			p.DeletedPathsTotal = 1
			return p
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Append(newStore(), tc.payload); err == nil {
				t.Fatalf("Append(%T) = nil error, want the payload rejected", tc.payload)
			}
		})
	}
}

func TestValidatePayload_RejectsNullRequiredChildFields(t *testing.T) {
	invocation := ids.NewV7()
	tests := []struct {
		name string
		kind string
		raw  string
	}{
		{"start null invocation id", KindChildAgentStart,
			`{"invocation_id":null,"provider_id":"openai","model_id":"m","declared_paths":["/home/u/proj/a.txt"],"step_cap":12,"instruction_bytes":4,"instruction_digest":"` + hex64 + `"}`},
		{"start null declared paths", KindChildAgentStart,
			`{"invocation_id":"` + invocation + `","provider_id":"openai","model_id":"m","declared_paths":null,"step_cap":12,"instruction_bytes":4,"instruction_digest":"` + hex64 + `"}`},
		{"end null reason", KindChildAgentEnd,
			`{"invocation_id":"` + invocation + `","reason":null,"steps":1,"written_paths":[],"rollback_outcome":"not_needed","duration_ms":1}`},
		{"end null rollback outcome", KindChildAgentEnd,
			`{"invocation_id":"` + invocation + `","reason":"completed","steps":1,"written_paths":[],"rollback_outcome":null,"duration_ms":1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(tc.kind, json.RawMessage(tc.raw)); err == nil {
				t.Fatalf("ValidatePayload(%q) = nil error, want the null required field rejected", tc.kind)
			}
		})
	}
}

func TestEmitChildAgent_RefusesPathsOutsideTheProjectRoot(t *testing.T) {
	invocation := ids.NewV7()

	start := validChildStart(invocation)
	start.DeclaredPaths = append(childDeclared("a.txt"), "/etc/passwd")
	if err := EmitChildAgentStart(newStore(), childRoot, start); err == nil {
		t.Fatal("EmitChildAgentStart() = nil error, want a declared path outside the project refused")
	}

	sibling := validChildStart(invocation)
	sibling.DeclaredPaths = []string{childRoot + "-other/a.txt"}
	if err := EmitChildAgentStart(newStore(), childRoot, sibling); err == nil {
		t.Fatal("EmitChildAgentStart() = nil error, want a sibling-directory prefix refused")
	}

	end := validChildEnd(invocation)
	end.WrittenPaths = []string{"/etc/passwd"}
	if err := EmitChildAgentEnd(newStore(), childRoot, end); err == nil {
		t.Fatal("EmitChildAgentEnd() = nil error, want a written path outside the project refused")
	}

	deleteStart := validChildStart(invocation)
	deleteStart.DeclaredDeletePaths = []string{"/etc/passwd"}
	if err := EmitChildAgentStart(newStore(), childRoot, deleteStart); err == nil {
		t.Fatal("EmitChildAgentStart() = nil error, want a declared delete path outside the project refused")
	}

	deleted := validChildEnd(invocation)
	deleted.DeletedPaths = []string{childRoot + "-other/old.txt"}
	if err := EmitChildAgentEnd(newStore(), childRoot, deleted); err == nil {
		t.Fatal("EmitChildAgentEnd() = nil error, want a deleted path outside the project refused")
	}

	relativeRoot := validChildStart(invocation)
	if err := EmitChildAgentStart(newStore(), "proj", relativeRoot); err == nil {
		t.Fatal("EmitChildAgentStart() = nil error, want a non-absolute project root refused")
	}
}

func TestChildInstructionDigest_IsBoundedAndTextFree(t *testing.T) {
	instruction := strings.Repeat("secret plan ", 4096)
	digest := ChildInstructionDigest(instruction)
	if !argumentHashRE.MatchString(digest) {
		t.Fatalf("digest = %q, want a lowercase 64-char SHA-256 hex digest", digest)
	}
	if strings.Contains(digest, "secret") {
		t.Fatalf("digest = %q, want no instruction text", digest)
	}
	if ChildInstructionDigest(instruction+"!") == digest {
		t.Fatal("digest did not change with the instruction")
	}
}

// A child confined to one declared directory can write more distinct files than the record
// carries. Refusing the end record there would leave its child_agent_start unclosed, so the
// emitter bounds the list and keeps the true count beside it.
func TestEmitChildAgentEnd_BoundsAnOverCapWrittenListRatherThanRefusingIt(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	written := make([]string, maxChildWrittenPaths+9)
	for i := range written {
		written[i] = filepath.Join(childRoot, "w", fmt.Sprintf("f%03d.txt", i))
	}
	end := validChildEnd(ids.NewV7())
	end.WrittenPaths = written

	if err := EmitChildAgentEnd(store, childRoot, end); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v, want the over-cap list bounded and appended", err)
	}
	evs := reloadAll(t, sess)
	if len(evs) != 1 {
		t.Fatalf("persisted records = %d, want the terminal record appended", len(evs))
	}
	var got ChildAgentEnd
	if err := json.Unmarshal(evs[0].Payload, &got); err != nil {
		t.Fatalf("unmarshal child_agent_end: %v", err)
	}
	if len(got.WrittenPaths) != maxChildWrittenPaths {
		t.Fatalf("written_paths = %d, want it bounded to %d", len(got.WrittenPaths), maxChildWrittenPaths)
	}
	if got.WrittenPathsTotal != int64(len(written)) {
		t.Fatalf("written_paths_total = %d, want the true count %d", got.WrittenPathsTotal, len(written))
	}
	if got.WrittenPaths[0] != written[0] {
		t.Fatalf("written_paths[0] = %q, want the first write %q kept", got.WrittenPaths[0], written[0])
	}
	if err := ValidatePayload(evs[0].Kind, evs[0].Payload); err != nil {
		t.Fatalf("bounded record failed load-time validation: %v", err)
	}
}

func TestEmitChildAgentEnd_AnUnboundedListCarriesNoTotal(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	if err := EmitChildAgentEnd(store, childRoot, validChildEnd(ids.NewV7())); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v", err)
	}
	evs := reloadAll(t, sess)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(evs[0].Payload, &fields); err != nil {
		t.Fatalf("unmarshal child_agent_end: %v", err)
	}
	if _, present := fields["written_paths_total"]; present {
		t.Errorf("record carries written_paths_total with nothing bounded: %s", evs[0].Payload)
	}
}

func TestEmitChildAgentPair_DeleteOnlyChildRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())
	invocation := ids.NewV7()

	start := validChildStart(invocation)
	start.DeclaredPaths = nil
	start.DeclaredDeletePaths = childDeclared("old.txt", "stale")
	if err := EmitChildAgentStart(store, childRoot, start); err != nil {
		t.Fatalf("EmitChildAgentStart() error = %v, want a delete-only child admitted", err)
	}
	end := validChildEnd(invocation)
	end.WrittenPaths = nil
	end.DeletedPaths = childDeclared("old.txt")
	if err := EmitChildAgentEnd(store, childRoot, end); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Store.Flush() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("session file not written: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if len(loaded.Records) != 2 {
		t.Fatalf("persisted records = %d, want 2", len(loaded.Records))
	}
	startEv, _ := loaded.Records[0].(sessions.Event)
	endEv, _ := loaded.Records[1].(sessions.Event)
	for i, ev := range []sessions.Event{startEv, endEv} {
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload(%q) rejected persisted record %d: %v", ev.Kind, i, err)
		}
	}

	var gotStart ChildAgentStart
	mustUnmarshal(t, startEv.Payload, &gotStart)
	if len(gotStart.DeclaredPaths) != 0 {
		t.Errorf("start declared_paths = %v, want no write authority", gotStart.DeclaredPaths)
	}
	if strings.Join(gotStart.DeclaredDeletePaths, ",") != strings.Join(childDeclared("old.txt", "stale"), ",") {
		t.Errorf("start declared_delete_paths = %v, want the delete declaration in order", gotStart.DeclaredDeletePaths)
	}

	var gotEnd ChildAgentEnd
	mustUnmarshal(t, endEv.Payload, &gotEnd)
	if len(gotEnd.WrittenPaths) != 0 || gotEnd.WrittenPathsTotal != 0 {
		t.Errorf("end written_paths = %v (total %d), want no write recorded for a delete", gotEnd.WrittenPaths, gotEnd.WrittenPathsTotal)
	}
	if strings.Join(gotEnd.DeletedPaths, ",") != strings.Join(childDeclared("old.txt"), ",") {
		t.Errorf("end deleted_paths = %v, want the successful delete", gotEnd.DeletedPaths)
	}
	if _, present := rawFields(t, endEv.Payload)["deleted_paths_total"]; present {
		t.Errorf("record carries deleted_paths_total with nothing bounded: %s", endEv.Payload)
	}
}

func TestEmitChildAgentPair_AWriteOnlyChildCarriesNoDeleteFields(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	invocation := ids.NewV7()
	if err := EmitChildAgentStart(store, childRoot, validChildStart(invocation)); err != nil {
		t.Fatalf("EmitChildAgentStart() error = %v", err)
	}
	if err := EmitChildAgentEnd(store, childRoot, validChildEnd(invocation)); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v", err)
	}
	for _, ev := range reloadAll(t, sess) {
		for _, field := range []string{"declared_delete_paths", "deleted_paths", "deleted_paths_total"} {
			if _, present := rawFields(t, ev.Payload)[field]; present {
				t.Errorf("%s carries %q for a child with no delete authority: %s", ev.Kind, field, ev.Payload)
			}
		}
	}
}

func TestChildAgentPayloads_RecordsWithoutDeleteFieldsStayReadable(t *testing.T) {
	invocation := ids.NewV7()
	start := json.RawMessage(`{"invocation_id":"` + invocation + `","provider_id":"openai","model_id":"m","declared_paths":["/home/u/proj/a.txt"],"step_cap":12,"instruction_bytes":4,"instruction_digest":"` + hex64 + `"}`)
	end := json.RawMessage(`{"invocation_id":"` + invocation + `","reason":"completed","steps":1,"written_paths":["/home/u/proj/a.txt"],"rollback_outcome":"not_needed","duration_ms":1,"reply_truncated":false}`)
	if err := ValidatePayload(KindChildAgentStart, start); err != nil {
		t.Fatalf("ValidatePayload(start) error = %v, want a record without declared_delete_paths accepted", err)
	}
	if err := ValidatePayload(KindChildAgentEnd, end); err != nil {
		t.Fatalf("ValidatePayload(end) error = %v, want a record without deleted_paths accepted", err)
	}
	var gotStart ChildAgentStart
	mustUnmarshal(t, start, &gotStart)
	if len(gotStart.DeclaredDeletePaths) != 0 {
		t.Errorf("declared_delete_paths = %v, want no delete authority", gotStart.DeclaredDeletePaths)
	}
	var gotEnd ChildAgentEnd
	mustUnmarshal(t, end, &gotEnd)
	if len(gotEnd.DeletedPaths) != 0 || gotEnd.DeletedPathsTotal != 0 {
		t.Errorf("deleted_paths = %v (total %d), want no deletions", gotEnd.DeletedPaths, gotEnd.DeletedPathsTotal)
	}
}

func TestChildAgentStart_DeclarationUnionLimit(t *testing.T) {
	paths := func(from, to int) []string {
		out := make([]string, 0, to-from)
		for i := from; i < to; i++ {
			out = append(out, filepath.Join(childRoot, fmt.Sprintf("f%02d.txt", i)))
		}
		return out
	}
	target := filepath.Join(childRoot, "target.txt")
	link := filepath.Join(childRoot, "link.txt")
	tests := []struct {
		name          string
		write, remove []string
		wantErr       bool
	}{
		{"32 distinct paths with overlaps between the lists", paths(0, 20), paths(10, 32), false},
		{"the same 32 paths in both lists", paths(0, 32), paths(0, 32), false},
		{"33 distinct paths", paths(0, 20), paths(10, 33), true},
		{"an identical target in both lists counts once", append(paths(0, 31), target), []string{target}, false},
		{"a symlink's followed write target and retained delete entry count twice", append(paths(0, 31), target), []string{link}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validChildStart(ids.NewV7())
			p.DeclaredPaths, p.DeclaredDeletePaths = tc.write, tc.remove
			_, err := Append(newStore(), p)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Append() error = %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}

func TestEmitChildAgentEnd_BoundsAnOverCapDeletedListOnItsOwnTotal(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	deleted := make([]string, maxChildDeletedPaths+3)
	for i := range deleted {
		deleted[i] = filepath.Join(childRoot, "d", fmt.Sprintf("f%03d.txt", i))
	}
	end := validChildEnd(ids.NewV7())
	end.DeletedPaths = deleted

	if err := EmitChildAgentEnd(store, childRoot, end); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v, want the over-cap list bounded and appended", err)
	}
	evs := reloadAll(t, sess)
	var got ChildAgentEnd
	mustUnmarshal(t, evs[0].Payload, &got)
	if len(got.DeletedPaths) != maxChildDeletedPaths || got.DeletedPathsTotal != int64(len(deleted)) {
		t.Fatalf("deleted_paths = %d (total %d), want %d bounded with the true count %d", len(got.DeletedPaths), got.DeletedPathsTotal, maxChildDeletedPaths, len(deleted))
	}
	if len(got.WrittenPaths) != 1 || got.WrittenPathsTotal != 0 {
		t.Fatalf("written_paths = %v (total %d), want the write list untouched by the delete bound", got.WrittenPaths, got.WrittenPathsTotal)
	}
	if err := ValidatePayload(evs[0].Kind, evs[0].Payload); err != nil {
		t.Fatalf("bounded record failed load-time validation: %v", err)
	}
}

func TestEmitChildAgentPair_MoveOnlyChildRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := sessions.New(path, newSession())
	invocation := ids.NewV7()
	pairs := []ChildMovePair{{Source: filepath.Join(childRoot, "old.txt"), Destination: filepath.Join(childRoot, "new.txt")}}

	start := validChildStart(invocation)
	start.DeclaredPaths = nil
	start.DeclaredMovePairs = pairs
	if err := EmitChildAgentStart(store, childRoot, start); err != nil {
		t.Fatalf("EmitChildAgentStart() error = %v, want a move-only child admitted", err)
	}
	end := validChildEnd(invocation)
	end.WrittenPaths = nil
	end.MovedPairs = pairs
	if err := EmitChildAgentEnd(store, childRoot, end); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Store.Flush() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("session file not written: %v", err)
	}
	loaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if len(loaded.Records) != 2 {
		t.Fatalf("persisted records = %d, want 2", len(loaded.Records))
	}
	startEv, _ := loaded.Records[0].(sessions.Event)
	endEv, _ := loaded.Records[1].(sessions.Event)
	for i, ev := range []sessions.Event{startEv, endEv} {
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload(%q) rejected persisted record %d: %v", ev.Kind, i, err)
		}
	}

	var gotStart ChildAgentStart
	mustUnmarshal(t, startEv.Payload, &gotStart)
	if len(gotStart.DeclaredPaths) != 0 || len(gotStart.DeclaredDeletePaths) != 0 || fmt.Sprint(gotStart.DeclaredMovePairs) != fmt.Sprint(pairs) {
		t.Errorf("start declared_paths/declared_delete_paths/declared_move_pairs = %v / %v / %v, want none / none / %v", gotStart.DeclaredPaths, gotStart.DeclaredDeletePaths, gotStart.DeclaredMovePairs, pairs)
	}
	var gotEnd ChildAgentEnd
	mustUnmarshal(t, endEv.Payload, &gotEnd)
	if len(gotEnd.WrittenPaths) != 0 || len(gotEnd.DeletedPaths) != 0 || fmt.Sprint(gotEnd.MovedPairs) != fmt.Sprint(pairs) {
		t.Errorf("end written_paths/deleted_paths/moved_pairs = %v / %v / %v, want none / none / %v", gotEnd.WrittenPaths, gotEnd.DeletedPaths, gotEnd.MovedPairs, pairs)
	}
}

func TestEmitChildAgentPair_AWriteOnlyChildCarriesNoMoveFields(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	invocation := ids.NewV7()
	if err := EmitChildAgentStart(store, childRoot, validChildStart(invocation)); err != nil {
		t.Fatalf("EmitChildAgentStart() error = %v", err)
	}
	if err := EmitChildAgentEnd(store, childRoot, validChildEnd(invocation)); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v", err)
	}
	for _, ev := range reloadAll(t, sess) {
		for _, field := range []string{"declared_move_pairs", "moved_pairs"} {
			if _, present := rawFields(t, ev.Payload)[field]; present {
				t.Errorf("%s carries %q for a child with no move authority: %s", ev.Kind, field, ev.Payload)
			}
		}
	}
}

func TestChildAgentStart_MoveEndpointsCountTowardTheDeclarationLimit(t *testing.T) {
	paths := make([]string, 31)
	for i := range paths {
		paths[i] = filepath.Join(childRoot, fmt.Sprintf("f%02d.txt", i))
	}
	for _, tc := range []struct {
		name    string
		pair    ChildMovePair
		wantErr bool
	}{
		{"a pair with one endpoint already declared reaches 32", ChildMovePair{Source: paths[0], Destination: filepath.Join(childRoot, "moved.txt")}, false},
		{"a pair of two new endpoints reaches 33", ChildMovePair{Source: filepath.Join(childRoot, "a.txt"), Destination: filepath.Join(childRoot, "b.txt")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validChildStart(ids.NewV7())
			p.DeclaredPaths, p.DeclaredMovePairs = paths, []ChildMovePair{tc.pair}
			_, err := Append(newStore(), p)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Append() error = %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}

func TestEmitChildAgentPair_RefusesAMoveEndpointOutsideTheProject(t *testing.T) {
	inside := filepath.Join(childRoot, "old.txt")
	outside := "/home/u/elsewhere/new.txt"

	start := validChildStart(ids.NewV7())
	start.DeclaredMovePairs = []ChildMovePair{{Source: inside, Destination: outside}}
	if err := EmitChildAgentStart(newStore(), childRoot, start); err == nil || !strings.Contains(err.Error(), "declared_move_pairs") {
		t.Fatalf("EmitChildAgentStart() error = %v, want a declared move destination outside the project refused", err)
	}
	end := validChildEnd(ids.NewV7())
	end.MovedPairs = []ChildMovePair{{Source: outside, Destination: inside}}
	if err := EmitChildAgentEnd(newStore(), childRoot, end); err == nil || !strings.Contains(err.Error(), "moved_pairs") {
		t.Fatalf("EmitChildAgentEnd() error = %v, want a moved source outside the project refused", err)
	}
}

func TestChildAgentEnd_RejectsATotalThatBoundedNothing(t *testing.T) {
	end := validChildEnd(ids.NewV7())
	end.WrittenPathsTotal = int64(len(end.WrittenPaths))
	if _, err := Append(newStore(), end); err == nil {
		t.Fatal("Append() = nil error, want a written_paths_total that exceeds nothing rejected")
	}
}

func TestEmitChildAgentStart_DirectoryOnlyChildRoundTrips(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	dirs := childDeclared("build", "build/out")
	start := validChildStart(ids.NewV7())
	start.DeclaredPaths = nil
	start.DeclaredDirs = dirs
	if err := EmitChildAgentStart(store, childRoot, start); err != nil {
		t.Fatalf("EmitChildAgentStart() error = %v, want a directory-only child admitted", err)
	}
	evs := reloadAll(t, sess)
	if len(evs) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(evs))
	}
	if err := ValidatePayload(evs[0].Kind, evs[0].Payload); err != nil {
		t.Fatalf("ValidatePayload() rejected the directory-only start: %v", err)
	}
	var got ChildAgentStart
	mustUnmarshal(t, evs[0].Payload, &got)
	if strings.Join(got.DeclaredDirs, ",") != strings.Join(dirs, ",") {
		t.Errorf("declared_dirs = %v, want %v", got.DeclaredDirs, dirs)
	}
	if len(got.DeclaredPaths)+len(got.DeclaredDeletePaths)+len(got.DeclaredMovePairs) != 0 {
		t.Errorf("start carries write/delete/move authority %v / %v / %v, want none", got.DeclaredPaths, got.DeclaredDeletePaths, got.DeclaredMovePairs)
	}
}

func TestChildAgentStart_DeclaredDirsValidation(t *testing.T) {
	paths := func(prefix string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = filepath.Join(childRoot, fmt.Sprintf("%s%02d", prefix, i))
		}
		return out
	}

	union := validChildStart(ids.NewV7())
	union.DeclaredPaths, union.DeclaredDirs = paths("f", 31), paths("d", 2)
	_, err := Append(newStore(), union)
	if err == nil || !strings.Contains(err.Error(), "declared_paths, declared_delete_paths, declared_move_pairs and declared_dirs exceeds") {
		t.Errorf("Append(33 distinct paths with directories) error = %v, want the shared cap naming all four forms", err)
	}
	union.DeclaredDirs = append(paths("d", 1), union.DeclaredPaths[0])
	if _, err := Append(newStore(), union); err != nil {
		t.Errorf("Append(32 distinct paths, a directory equal to a write path) error = %v, want accepted", err)
	}

	over := validChildStart(ids.NewV7())
	over.DeclaredPaths, over.DeclaredDirs = nil, paths("d", maxChildDeclaredPaths+1)
	if _, err := Append(newStore(), over); err == nil {
		t.Error("Append(over-cap declared_dirs) = nil error, want refused")
	}

	relative := validChildStart(ids.NewV7())
	relative.DeclaredDirs = []string{"build"}
	if _, err := Append(newStore(), relative); err == nil {
		t.Error("Append(relative declared_dirs) = nil error, want refused")
	}

	outside := validChildStart(ids.NewV7())
	outside.DeclaredDirs = []string{childRoot + "-other/build"}
	if err := EmitChildAgentStart(newStore(), childRoot, outside); err == nil || !strings.Contains(err.Error(), "declared_dirs") {
		t.Errorf("EmitChildAgentStart(out-of-project directory) error = %v, want declared_dirs refused", err)
	}
}

func TestChildAgentStart_ReaderWithoutDeclaredDirs(t *testing.T) {
	legacy := json.RawMessage(`{"invocation_id":"` + ids.NewV7() + `","provider_id":"openai","model_id":"m","declared_paths":["/home/u/proj/a.txt"],"step_cap":12,"instruction_bytes":4,"instruction_digest":"` + hex64 + `"}`)
	if err := ValidatePayload(KindChildAgentStart, legacy); err != nil {
		t.Fatalf("ValidatePayload(start without declared_dirs) error = %v, want accepted", err)
	}

	mixed := validChildStart(ids.NewV7())
	mixed.DeclaredDirs = childDeclared("build")
	raw, err := json.Marshal(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePayload(KindChildAgentStart, raw); err != nil {
		t.Fatalf("ValidatePayload() error = %v, want the current reader to accept it", err)
	}
	var old ChildAgentStart
	mustUnmarshal(t, raw, &old)
	old.DeclaredDirs = nil
	if err := old.validate(); err != nil {
		t.Fatalf("validate() without declared_dirs error = %v, want a mixed start to keep its known forms", err)
	}
}

func TestEmitChildAgentPair_ReadOnlyChildRoundTrips(t *testing.T) {
	sess := newSession()
	store := sessions.New("unused-in-tests", sess)
	invocation := ids.NewV7()
	start := validChildStart(invocation)
	start.DeclaredPaths = []string{}
	if err := EmitChildAgentStart(store, childRoot, start); err != nil {
		t.Fatalf("EmitChildAgentStart() error = %v, want a child with no declared path admitted", err)
	}
	end := validChildEnd(invocation)
	end.WrittenPaths = []string{}
	if err := EmitChildAgentEnd(store, childRoot, end); err != nil {
		t.Fatalf("EmitChildAgentEnd() error = %v", err)
	}

	evs := reloadAll(t, sess)
	if len(evs) != 2 || evs[0].Kind != KindChildAgentStart || evs[1].Kind != KindChildAgentEnd {
		t.Fatalf("persisted records = %+v, want one start then one end", evs)
	}
	for _, ev := range evs {
		if err := ValidatePayload(ev.Kind, ev.Payload); err != nil {
			t.Fatalf("ValidatePayload(%q) rejected the read-only child record: %v", ev.Kind, err)
		}
	}
	var fields map[string]json.RawMessage
	mustUnmarshal(t, evs[0].Payload, &fields)
	if got := string(fields["declared_paths"]); got != "[]" {
		t.Errorf("declared_paths = %s, want []", got)
	}
	for _, absent := range []string{"declared_delete_paths", "declared_move_pairs", "declared_dirs"} {
		if raw, ok := fields[absent]; ok {
			t.Errorf("%s = %s, want the field omitted", absent, raw)
		}
	}
	var gotEnd ChildAgentEnd
	mustUnmarshal(t, evs[1].Payload, &gotEnd)
	if gotEnd.InvocationID != invocation {
		t.Errorf("end invocation_id = %q, want the start's %q", gotEnd.InvocationID, invocation)
	}

	omitted := validChildStart(ids.NewV7())
	omitted.DeclaredPaths = nil
	if _, err := Append(newStore(), omitted); err != nil {
		t.Errorf("Append(nil declared_paths) error = %v, want accepted", err)
	}
	for name, mutate := range map[string]func(*ChildAgentStart){
		"missing model":      func(p *ChildAgentStart) { p.ModelID = "" },
		"zero step cap":      func(p *ChildAgentStart) { p.StepCap = 0 },
		"bad digest":         func(p *ChildAgentStart) { p.InstructionDigest = "x" },
		"bad invocation id":  func(p *ChildAgentStart) { p.InvocationID = "not-an-id" },
		"empty instructions": func(p *ChildAgentStart) { p.InstructionBytes = 0 },
	} {
		bad := validChildStart(ids.NewV7())
		bad.DeclaredPaths = []string{}
		mutate(&bad)
		if _, err := Append(newStore(), bad); err == nil {
			t.Errorf("Append(read-only start with %s) = nil error, want rejected", name)
		}
	}
}
