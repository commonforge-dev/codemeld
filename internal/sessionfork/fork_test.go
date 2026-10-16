// Tests for the text-only fork: record filtering, success ordering/metadata,
// original-store closure, and the no-event write-failure paths.
package sessionfork

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	origMetaID = "0190c0de-0000-7000-8000-000000000001"
	idUser     = "0190c0de-0000-7000-8000-0000000000a1"
	idAsst     = "0190c0de-0000-7000-8000-0000000000a2"
	idTool     = "0190c0de-0000-7000-8000-0000000000a3"
	idSystem   = "0190c0de-0000-7000-8000-0000000000a4"
	idAsstBare = "0190c0de-0000-7000-8000-0000000000a5"
	idEvent    = "0190c0de-0000-7000-8000-0000000000a6"
	idAfter    = "0190c0de-0000-7000-8000-0000000000a7"
	idCompact  = "0190c0de-0000-7000-8000-0000000000a8"
)

var startedAt = time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC)

// textPart and imagePart are list content-part fixtures: one text-typed (kept by
// a fork) and one non-text (dropped).
func textPart(s string) sessions.ContentPart {
	return sessions.ContentPart{Type: "text", Raw: json.RawMessage(`{"type":"text","text":"` + s + `"}`)}
}

func imagePart() sessions.ContentPart {
	return sessions.ContentPart{Type: "image_url", Raw: json.RawMessage(`{"type":"image_url","image_url":{"url":"http://x"}}`)}
}

// originalSession builds an older-schema session carrying every record shape a
// fork must filter: text and list messages, a tool message, an event, an
// assistant turn with tool_calls, and an assistant list with no text part.
func originalSession(folder string) *sessions.Session {
	ts := func(sec int) time.Time { return startedAt.Add(time.Duration(sec) * time.Second) }
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            origMetaID,
			Folder:        folder,
			StartedAt:     startedAt,
			UpdatedAt:     startedAt,
			SchemaVersion: 1,
		},
		Records: []sessions.Record{
			sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("hi"), Timestamp: ts(0)},
			sessions.Message{
				ID:        idAsst,
				Role:      "assistant",
				Content:   sessions.PartsContent([]sessions.ContentPart{textPart("hello"), imagePart()}),
				Timestamp: ts(1),
				ToolCalls: []sessions.ToolCall{{ID: "call_1", Type: "function", Raw: json.RawMessage(`{"id":"call_1","type":"function","function":{"name":"ls","arguments":"{}"}}`)}},
			},
			sessions.Message{ID: idTool, Role: "tool", Content: sessions.TextContent("result"), Timestamp: ts(2), ToolCallID: "call_1"},
			sessions.Message{ID: idSystem, Role: "system", Content: sessions.TextContent("sys"), Timestamp: ts(3)},
			sessions.Message{
				ID:        idAsstBare,
				Role:      "assistant",
				Content:   sessions.PartsContent([]sessions.ContentPart{imagePart()}),
				Timestamp: ts(4),
			},
			sessions.Event{ID: idEvent, Kind: "launch_began", Timestamp: ts(5), Payload: json.RawMessage(`{"source":"fresh"}`)},
		},
	}
}

const (
	idChildA    = "0190c0de-0000-7000-8000-0000000000b1"
	idChildB    = "0190c0de-0000-7000-8000-0000000000b2"
	idTerminalA = "0190c0de-0000-7000-8000-0000000000b3"
	idTerminalB = "0190c0de-0000-7000-8000-0000000000b4"
)

func preparedChild() []sessions.Record {
	return []sessions.Record{
		sessions.Message{ID: idChildA, Role: "user", Content: sessions.TextContent("carried"), Timestamp: startedAt},
		sessions.Message{ID: idChildB, Role: "assistant", Content: sessions.TextContent("also carried"), Timestamp: startedAt},
	}
}

func snapshotOf(s *sessions.Session) sessions.MetadataSnapshot {
	return sessions.MetadataSnapshot{ID: s.Metadata.ID, Folder: s.Metadata.Folder, StartedAt: s.Metadata.StartedAt}
}

func TestCreateChild_Success(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/demo"
	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)

	childStore, err := CreateChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Title: "carried title", Records: preparedChild()}, failOnChildWriteFailure(t))
	if err != nil {
		t.Fatalf("CreateChild error = %v", err)
	}

	child := readSession(t, childStore.Path())
	if err := sessions.ValidateRecordStream(child.Records); err != nil {
		t.Fatalf("child fails the load-path stream validator: %v", err)
	}
	if child.Metadata.ID == origMetaID || child.Metadata.ID != childStore.SessionID() {
		t.Errorf("child id = %q, want the store's fresh id %q", child.Metadata.ID, childStore.SessionID())
	}
	if child.Metadata.Folder != folder || !child.Metadata.StartedAt.Equal(startedAt) {
		t.Errorf("child folder/started_at = %q/%v, want copied %q/%v", child.Metadata.Folder, child.Metadata.StartedAt, folder, startedAt)
	}
	if child.Metadata.Title != "carried title" {
		t.Errorf("child title = %q, want %q", child.Metadata.Title, "carried title")
	}
	want := sessions.ForkOrigin{SessionID: origMetaID, RecordID: idEvent}
	if child.Metadata.ForkedFrom == nil || *child.Metadata.ForkedFrom != want {
		t.Fatalf("child forked_from = %+v, want %+v (parent id and its last record)", child.Metadata.ForkedFrom, want)
	}

	if len(child.Records) != 3 {
		t.Fatalf("child records = %d, want 3 (2 supplied + launch_began)", len(child.Records))
	}
	for i, wantID := range []string{idChildA, idChildB} {
		msg, ok := child.Records[i].(sessions.Message)
		if !ok || msg.ID != wantID {
			t.Fatalf("child record %d = %+v, want the supplied message %q", i, child.Records[i], wantID)
		}
	}
	if got := child.Records[0].(sessions.Message).ParentID; got != idEvent {
		t.Errorf("child record 0 parent_id = %q, want %q", got, idEvent)
	}
	if got := child.Records[1].(sessions.Message).ParentID; got != "" {
		t.Errorf("child record 1 parent_id = %q, want empty", got)
	}
	ev, ok := child.Records[2].(sessions.Event)
	if !ok || ev.Kind != events.KindLaunchBegan || ev.ParentID != "" {
		t.Fatalf("child record 2 = %+v, want an unlinked launch_began event", child.Records[2])
	}

	parentFile := readSession(t, parentStore.Path())
	last := parentFile.Records[len(parentFile.Records)-1]
	fev, ok := last.(sessions.Event)
	if !ok || fev.Kind != events.KindSessionForked {
		t.Fatalf("parent's last durable record = %+v, want session_forked", last)
	}
	var sf events.SessionForked
	if err := json.Unmarshal(fev.Payload, &sf); err != nil {
		t.Fatalf("decode session_forked payload: %v", err)
	}
	if sf.ToSessionID != childStore.SessionID() {
		t.Errorf("session_forked.to_session_id = %q, want %q", sf.ToSessionID, childStore.SessionID())
	}

	before := len(parentStore.Records())
	parentStore.Append(sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("after"), Timestamp: startedAt})
	if after := len(parentStore.Records()); after != before {
		t.Errorf("parent accepted an append after the switch: %d -> %d, want sealed", before, after)
	}
	childBefore := len(childStore.Records())
	childStore.Append(sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("next turn"), Timestamp: startedAt})
	if after := len(childStore.Records()); after != childBefore+1 {
		t.Errorf("child store refused an append: %d -> %d, want open", childBefore, after)
	}

	assertSidecarReacquirable(t, sessions.ResumeLockPath(childStore.Path()))
}

func TestCreateChild_CompactionOnlyParent(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/demo"
	ancestor := sessions.MetadataSnapshot{ID: origMetaID, Folder: folder, StartedAt: startedAt}
	origin := sessions.ForkOrigin{SessionID: origMetaID, RecordID: idEvent}
	parentStore, err := sessions.EnsureChildSession(home, ancestor, "compacted", origin, []sessions.Record{
		sessions.Compaction{
			ID: idCompact, Summary: "prior context", Timestamp: startedAt,
			Provider: "openai", ModelID: "gpt-test",
		},
	})
	if err != nil {
		t.Fatalf("EnsureChildSession error = %v", err)
	}
	parent := sessions.MetadataSnapshot{ID: parentStore.SessionID(), Folder: folder, StartedAt: startedAt}

	childStore, err := CreateChild(context.Background(), home, parent, parentStore,
		Child{Records: preparedChild()}, failOnChildWriteFailure(t))
	if err != nil {
		t.Fatalf("CreateChild error = %v", err)
	}

	child := readSession(t, childStore.Path())
	want := sessions.ForkOrigin{SessionID: parent.ID, RecordID: idCompact}
	if child.Metadata.ForkedFrom == nil || *child.Metadata.ForkedFrom != want {
		t.Fatalf("child forked_from = %+v, want %+v", child.Metadata.ForkedFrom, want)
	}
	if got := child.Records[0].(sessions.Message).ParentID; got != idCompact {
		t.Errorf("child record 0 parent_id = %q, want %q", got, idCompact)
	}
}

func TestCreateOwnedChild_ParentFinalFailureReleasesCompleteOrphan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	home := t.TempDir()
	folder := "/proj/orphan"
	parent := originalSession(folder)

	parentDir := t.TempDir()
	parentStore := sessions.New(filepath.Join(parentDir, "original.json"), parent)
	if err := os.Chmod(parentDir, 0o500); err != nil {
		t.Fatalf("seal parent dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parentDir, 0o755) })
	before := len(parentStore.Records())

	var calls int
	handler := func(path string, cat fserrors.Category, reason sessions.WriteReason, err error) { calls++ }

	owned, err := CreateOwnedChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, nil, nil, handler)
	if err == nil {
		t.Fatal("CreateOwnedChild reported success despite an unwritable parent, want error")
	}
	if owned != nil {
		t.Errorf("owned result on parent-final failure = %+v, want nil", owned)
	}
	if calls != 0 {
		t.Errorf("child-write callback called %d times on a parent-final failure, want 0", calls)
	}

	if _, statErr := os.Stat(parentStore.Path()); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("parent file exists after a failed parent-final batch: stat err = %v", statErr)
	}
	if got := len(parentStore.Records()); got != before {
		t.Errorf("parent records after a failed batch = %d, want the pre-batch %d (whole batch rolled back)", got, before)
	}
	assertOriginalUntouchedAndOpen(t, parentStore, before)

	if err := os.Chmod(parentDir, 0o755); err != nil {
		t.Fatalf("restore parent dir write access: %v", err)
	}
	if _, _, err := parentStore.Flush(context.Background()); err != nil {
		t.Fatalf("flush parent after restoring write access: %v", err)
	}
	reloaded := readSession(t, parentStore.Path())
	for i, rec := range reloaded.Records {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == events.KindSessionForked {
			t.Fatalf("records[%d] persisted session_forked after a failed parent-final batch", i)
		}
	}

	childPath := soleSessionFile(t, home, folder)
	child := readSession(t, childPath)
	if err := sessions.ValidateRecordStream(child.Records); err != nil {
		t.Fatalf("orphan child fails the load-path stream validator: %v", err)
	}
	if child.Metadata.ForkedFrom == nil || child.Metadata.ForkedFrom.SessionID != origMetaID {
		t.Errorf("orphan child forked_from = %+v, want the parent's provenance", child.Metadata.ForkedFrom)
	}
	if len(child.Records) != 3 {
		t.Errorf("orphan child records = %d, want the complete 3", len(child.Records))
	}
	assertSidecarReacquirable(t, sessions.ResumeLockPath(childPath))
}

func TestCreateChild_ConcurrentParentAppendNeverFollowsTheMarker(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/demo"
	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)

	competed := make(chan struct{})
	go func() {
		defer close(competed)
		parentStore.Append(sessions.Message{ID: idAfter, Role: "user", Content: sessions.TextContent("competing"), Timestamp: startedAt})
	}()

	childStore, err := CreateChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, failOnChildWriteFailure(t))
	<-competed
	if err != nil {
		t.Fatalf("CreateChild error = %v", err)
	}

	parentFile := readSession(t, parentStore.Path())
	last := parentFile.Records[len(parentFile.Records)-1]
	fev, ok := last.(sessions.Event)
	if !ok || fev.Kind != events.KindSessionForked {
		t.Fatalf("parent's last durable record = %+v, want session_forked", last)
	}
	var sf events.SessionForked
	if err := json.Unmarshal(fev.Payload, &sf); err != nil {
		t.Fatalf("decode session_forked payload: %v", err)
	}
	if sf.ToSessionID != childStore.SessionID() {
		t.Errorf("session_forked.to_session_id = %q, want %q", sf.ToSessionID, childStore.SessionID())
	}

	recs := parentStore.Records()
	if inMemLast, ok := recs[len(recs)-1].(sessions.Event); !ok || inMemLast.Kind != events.KindSessionForked {
		t.Fatalf("parent's last in-memory record = %+v, want session_forked", recs[len(recs)-1])
	}
	before := len(recs)
	parentStore.Append(sessions.Message{ID: idAfter, Role: "user", Content: sessions.TextContent("after"), Timestamp: startedAt})
	if after := len(parentStore.Records()); after != before {
		t.Errorf("parent accepted an append after the switch: %d -> %d, want sealed", before, after)
	}
}

func TestCreateOwnedChild_LockFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; lock-file creation cannot fail")
	}
	home := t.TempDir()
	folder := "/proj/lockfail"

	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir folder dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "folder"), []byte(folder+"\n"), 0o644); err != nil {
		t.Fatalf("write folder file: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("seal folder dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)
	before := len(parentStore.Records())

	owned, err := CreateOwnedChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, nil, nil, failOnChildWriteFailure(t))
	if err == nil {
		t.Fatal("CreateOwnedChild succeeded with an unlockable child sidecar, want error")
	}
	if owned != nil {
		t.Errorf("owned result on lock failure = %+v, want nil", owned)
	}
	var rle *sessions.ResumeLockError
	if !errors.As(err, &rle) {
		t.Fatalf("error = %v, want a *sessions.ResumeLockError (sidecar acquisition failed before publish)", err)
	}
	if n := childSessionFileCount(t, dir); n != 0 {
		t.Errorf("child session files after a lock failure = %d, want 0 (no publish)", n)
	}
	assertOriginalUntouchedAndOpen(t, parentStore, before)
}

func TestCreateOwnedChild_ChildWriteFailureReleasesOwnership(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/syncfail"
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))

	forced := errors.New("forced parent-dir sync failure")
	var publishedPath string
	restore := fsutil.SetSyncDirForTest(func(f *os.File) error {
		if p := soleChildSessionFile(t, dir); p != "" {
			publishedPath = p
			return forced
		}
		return f.Sync()
	})
	defer restore()

	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)
	before := len(parentStore.Records())

	var calls int
	var gotPath string
	var gotCat fserrors.Category
	var gotReason sessions.WriteReason
	var gotErr error
	handler := func(path string, cat fserrors.Category, reason sessions.WriteReason, err error) {
		calls++
		gotPath, gotCat, gotReason, gotErr = path, cat, reason, err
	}

	owned, err := CreateOwnedChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, nil, nil, handler)
	if err == nil {
		t.Fatal("CreateOwnedChild succeeded with a failing child parent-dir sync, want error")
	}
	if owned != nil {
		t.Errorf("owned result on child write failure = %+v, want nil", owned)
	}
	if calls != 1 {
		t.Fatalf("write-failure handler called %d times, want 1", calls)
	}
	if gotPath == "" || gotPath != publishedPath {
		t.Errorf("callback path = %q, want the failed child file %q", gotPath, publishedPath)
	}
	if gotCat != fserrors.IOError {
		t.Errorf("callback category = %q, want %q", gotCat, fserrors.IOError)
	}
	if gotReason != sessions.ReasonParentDirError {
		t.Errorf("callback reason = %q, want %q", gotReason, sessions.ReasonParentDirError)
	}
	if !errors.Is(gotErr, forced) {
		t.Errorf("callback error = %v, want the forced sync error", gotErr)
	}
	restore()
	if n := childSessionFileCount(t, dir); n != 0 {
		t.Errorf("child session files after a failed initial flush = %d, want 0", n)
	}
	assertOriginalUntouchedAndOpen(t, parentStore, before)
	assertSidecarReacquirable(t, sessions.ResumeLockPath(gotPath))
}

func childSessionFileCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("read child folder dir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			n++
		}
	}
	return n
}

func soleChildSessionFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read child folder dir: %v", err)
	}
	var found string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			if found != "" {
				t.Fatalf("multiple child session files in %s", dir)
			}
			found = filepath.Join(dir, e.Name())
		}
	}
	return found
}

func TestCreateChild_RefusesUnlinkableInput(t *testing.T) {
	tests := []struct {
		name    string
		parent  *sessions.Session
		records []sessions.Record
	}{
		{"no prepared child records", originalSession("/proj/demo"), nil},
		{"parent has no records", &sessions.Session{Metadata: originalSession("/proj/demo").Metadata}, preparedChild()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), tt.parent)
			before := len(parentStore.Records())

			childStore, err := CreateChild(context.Background(), home, snapshotOf(tt.parent), parentStore,
				Child{Records: tt.records}, failOnChildWriteFailure(t))
			if err == nil {
				t.Fatal("CreateChild() = nil error, want rejection")
			}
			if childStore != nil {
				t.Errorf("CreateChild returned a store on rejection, want nil")
			}
			if _, statErr := os.Stat(sessions.SessionRoot(home)); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("sessions root created for a refused child: stat err = %v", statErr)
			}
			assertOriginalUntouchedAndOpen(t, parentStore, before)
		})
	}
}

func TestCreateChild_RefusesUnresumableRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []sessions.Record
	}{
		{
			"schema-invalid record id",
			[]sessions.Record{
				sessions.Message{ID: "not-a-uuidv7", Role: "user", Content: sessions.TextContent("carried"), Timestamp: startedAt},
			},
		},
		{
			"tool message without its assistant tool_calls",
			[]sessions.Record{
				sessions.Message{ID: idChildA, Role: "user", Content: sessions.TextContent("carried"), Timestamp: startedAt},
				sessions.Message{ID: idChildB, Role: "tool", ToolCallID: "call-1", Content: sessions.TextContent("result"), Timestamp: startedAt},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			parent := originalSession("/proj/demo")
			parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)
			before := len(parentStore.Records())

			childStore, err := CreateChild(context.Background(), home, snapshotOf(parent), parentStore,
				Child{Records: tt.records}, failOnChildWriteFailure(t))
			if err == nil {
				t.Fatal("CreateChild() = nil error, want rejection")
			}
			if childStore != nil {
				t.Errorf("CreateChild returned a store on rejection, want nil")
			}
			if _, statErr := os.Stat(sessions.SessionRoot(home)); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("sessions root created for an unresumable child: stat err = %v", statErr)
			}
			assertOriginalUntouchedAndOpen(t, parentStore, before)
		})
	}
}

func readSession(t *testing.T, path string) *sessions.Session {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return s
}

func soleSessionFile(t *testing.T, home, folder string) string {
	t.Helper()
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read folder dir: %v", err)
	}
	var found []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			found = append(found, filepath.Join(dir, e.Name()))
		}
	}
	if len(found) != 1 {
		t.Fatalf("session files in %s = %v, want exactly 1", dir, found)
	}
	return found[0]
}

func TestFilterTextRecords(t *testing.T) {
	got := filterTextRecords(originalSession("/proj/demo"))

	// Tool message and event dropped; the four text messages survive in order.
	wantIDs := []string{idUser, idAsst, idSystem, idAsstBare}
	if len(got) != len(wantIDs) {
		t.Fatalf("filtered record count = %d, want %d", len(got), len(wantIDs))
	}
	for i, want := range wantIDs {
		msg, ok := got[i].(sessions.Message)
		if !ok {
			t.Fatalf("record %d type = %T, want sessions.Message", i, got[i])
		}
		if msg.ID != want {
			t.Fatalf("record %d id = %q, want %q", i, msg.ID, want)
		}
		if len(msg.ToolCalls) != 0 {
			t.Errorf("record %d (%s) kept %d tool_calls, want 0", i, msg.Role, len(msg.ToolCalls))
		}
		if msg.ToolCallID != "" {
			t.Errorf("record %d (%s) kept tool_call_id %q, want empty", i, msg.Role, msg.ToolCallID)
		}
	}

	// String content copied verbatim.
	if c := got[0].(sessions.Message).Content; c.IsList() || c.Text() != "hi" {
		t.Errorf("user content = %+v, want string %q", c, "hi")
	}

	// List content keeps only its text-typed part, preserving raw bytes.
	asst := got[1].(sessions.Message).Content
	if !asst.IsList() {
		t.Fatalf("assistant content is not a list")
	}
	if len(asst.Parts()) != 1 || asst.Parts()[0].Type != "text" {
		t.Fatalf("assistant parts = %+v, want one text part", asst.Parts())
	}
	if string(asst.Parts()[0].Raw) != `{"type":"text","text":"hello"}` {
		t.Errorf("text part raw = %s, want verbatim", asst.Parts()[0].Raw)
	}

	// A list message with no text part stays an empty list, not a string.
	bare := got[3].(sessions.Message).Content
	if !bare.IsList() {
		t.Errorf("text-less assistant content collapsed to a string, want empty list")
	}
	if len(bare.Parts()) != 0 {
		t.Errorf("text-less assistant parts = %d, want 0", len(bare.Parts()))
	}
}

func TestForkSession_Success(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/demo"
	original := originalSession(folder)
	originalStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), original)

	newStore, err := ForkSession(context.Background(), home, original, originalStore, failOnWriteFailure(t))
	if err != nil {
		t.Fatalf("ForkSession error = %v", err)
	}
	if newStore == nil {
		t.Fatal("ForkSession returned a nil store on success")
	}

	newID := newStore.SessionID()
	if newID == origMetaID {
		t.Fatalf("new session id %q equals the original id, want a fresh id", newID)
	}

	// Read the new file back: launch_began{fork} is the first event, after the
	// filtered text messages, and the metadata copies folder/started_at with a
	// fresh id, refreshed updated_at, and the current schema version.
	data, err := os.ReadFile(newStore.Path())
	if err != nil {
		t.Fatalf("new session file not written: %v", err)
	}
	forked, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse new session file: %v", err)
	}

	if forked.Metadata.ID != newID {
		t.Errorf("file id = %q, want %q", forked.Metadata.ID, newID)
	}
	if forked.Metadata.Folder != folder {
		t.Errorf("folder = %q, want %q", forked.Metadata.Folder, folder)
	}
	if !forked.Metadata.StartedAt.Equal(startedAt) {
		t.Errorf("started_at = %s, want copied %s", forked.Metadata.StartedAt, startedAt)
	}
	if forked.Metadata.SchemaVersion != sessions.CurrentSchemaVersion {
		t.Errorf("schema_version = %d, want %d", forked.Metadata.SchemaVersion, sessions.CurrentSchemaVersion)
	}
	if !forked.Metadata.UpdatedAt.After(startedAt) {
		t.Errorf("updated_at = %s, want refreshed past started_at %s", forked.Metadata.UpdatedAt, startedAt)
	}

	// Records: the four filtered messages (the text-less assistant kept as an
	// empty list) then the fork launch event, in order.
	if len(forked.Records) != 5 {
		t.Fatalf("new session records = %d, want 5 (4 messages + launch_began)", len(forked.Records))
	}
	wantMsgIDs := []string{idUser, idAsst, idSystem, idAsstBare}
	for i, want := range wantMsgIDs {
		msg, ok := forked.Records[i].(sessions.Message)
		if !ok {
			t.Fatalf("record %d type = %T, want sessions.Message", i, forked.Records[i])
		}
		if msg.ID != want {
			t.Errorf("record %d id = %q, want %q", i, msg.ID, want)
		}
		if len(msg.ToolCalls) != 0 || msg.ToolCallID != "" {
			t.Errorf("record %d retained tool fields, want stripped", i)
		}
	}
	ev, ok := forked.Records[4].(sessions.Event)
	if !ok {
		t.Fatalf("record 4 type = %T, want sessions.Event", forked.Records[4])
	}
	if ev.Kind != events.KindLaunchBegan {
		t.Fatalf("record 3 kind = %q, want %q", ev.Kind, events.KindLaunchBegan)
	}
	var lb events.LaunchBegan
	if err := json.Unmarshal(ev.Payload, &lb); err != nil {
		t.Fatalf("decode launch_began payload: %v", err)
	}
	if lb.Source != "fork" {
		t.Errorf("launch_began source = %q, want \"fork\"", lb.Source)
	}

	// The original store records session_forked{to_session_id} as its final event.
	origRecs := originalStore.Records()
	last := origRecs[len(origRecs)-1]
	fev, ok := last.(sessions.Event)
	if !ok {
		t.Fatalf("original last record type = %T, want sessions.Event", last)
	}
	if fev.Kind != events.KindSessionForked {
		t.Fatalf("original last event kind = %q, want %q", fev.Kind, events.KindSessionForked)
	}
	var sf events.SessionForked
	if err := json.Unmarshal(fev.Payload, &sf); err != nil {
		t.Fatalf("decode session_forked payload: %v", err)
	}
	if sf.ToSessionID != newID {
		t.Errorf("session_forked.to_session_id = %q, want %q", sf.ToSessionID, newID)
	}

	// The original file on disk carries that same session_forked as its final
	// record: the fork must flush the marker, not merely append it in memory
	// (— the original file is modified by exactly this append).
	origData, err := os.ReadFile(originalStore.Path())
	if err != nil {
		t.Fatalf("original session file not written: %v", err)
	}
	origFile, err := sessions.Unmarshal(origData)
	if err != nil {
		t.Fatalf("parse original session file: %v", err)
	}
	diskLast := origFile.Records[len(origFile.Records)-1]
	diskEv, ok := diskLast.(sessions.Event)
	if !ok {
		t.Fatalf("on-disk original last record type = %T, want sessions.Event", diskLast)
	}
	if diskEv.Kind != events.KindSessionForked {
		t.Fatalf("on-disk original last event kind = %q, want %q", diskEv.Kind, events.KindSessionForked)
	}
	var diskSF events.SessionForked
	if err := json.Unmarshal(diskEv.Payload, &diskSF); err != nil {
		t.Fatalf("decode on-disk session_forked payload: %v", err)
	}
	if diskSF.ToSessionID != newID {
		t.Errorf("on-disk session_forked.to_session_id = %q, want %q", diskSF.ToSessionID, newID)
	}

	// The original store is closed: a later append does not mutate its stream.
	before := len(originalStore.Records())
	originalStore.Append(sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("after"), Timestamp: startedAt})
	if after := len(originalStore.Records()); after != before {
		t.Errorf("original accepted an append after fork: %d -> %d, want closed", before, after)
	}
}

// TestForkSession_EnsureSessionError verifies a folder-dir failure (here, the
// sessions root cannot be created because ~/.codemeld is a regular file) is
// surfaced unchanged, leaves the original unforked, and keeps it open.
func TestForkSession_EnsureSessionError(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".codemeld"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocking ~/.codemeld file: %v", err)
	}

	original := originalSession("/proj/demo")
	originalStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), original)
	before := len(originalStore.Records())

	newStore, err := ForkSession(context.Background(), home, original, originalStore, failOnWriteFailure(t))
	if err == nil {
		t.Fatal("ForkSession succeeded with an uncreatable sessions root, want error")
	}
	if newStore != nil {
		t.Errorf("ForkSession returned a store on EnsureSession failure, want nil")
	}
	var fde *sessions.FolderDirError
	if !errors.As(err, &fde) {
		t.Fatalf("error = %v, want a *sessions.FolderDirError", err)
	}
	assertOriginalUntouchedAndOpen(t, originalStore, before)
}

// TestForkSession_CollisionError verifies a folder-hash collision from
// EnsureSession (the folder dir already records a different canonical folder) is
// surfaced unchanged, leaves the original unforked, and keeps it open.
func TestForkSession_CollisionError(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/collide"

	// Seed the folder dir with a folder file recording a different canonical
	// folder, so EnsureFolderDir reports a *CollisionError rather than writing a
	// session file.
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir folder dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "folder"), []byte("/different/folder\n"), 0o644); err != nil {
		t.Fatalf("write colliding folder file: %v", err)
	}

	original := originalSession(folder)
	originalStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), original)
	before := len(originalStore.Records())

	newStore, err := ForkSession(context.Background(), home, original, originalStore, failOnWriteFailure(t))
	if err == nil {
		t.Fatal("ForkSession succeeded despite a folder-hash collision, want error")
	}
	if newStore != nil {
		t.Errorf("ForkSession returned a store on collision, want nil")
	}
	var ce *sessions.CollisionError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v, want a *sessions.CollisionError", err)
	}
	assertOriginalUntouchedAndOpen(t, originalStore, before)
}

func TestForkSession_FlushFailure(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/forktest"
	dir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))

	forced := errors.New("forced parent-dir sync failure")
	restore := fsutil.SetSyncDirForTest(func(f *os.File) error {
		if soleChildSessionFile(t, dir) != "" {
			return forced
		}
		return f.Sync()
	})
	defer restore()

	original := originalSession(folder)
	originalStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), original)
	before := len(originalStore.Records())

	var calls int
	var gotReason sessions.WriteReason
	handler := func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		calls++
		gotReason = reason
	}

	newStore, err := ForkSession(context.Background(), home, original, originalStore, handler)
	if err == nil {
		t.Fatal("ForkSession succeeded with a failing child parent-dir sync, want error")
	}
	if newStore != nil {
		t.Errorf("ForkSession returned a store on flush failure, want nil")
	}
	if calls != 1 {
		t.Fatalf("write-failure handler called %d times, want 1", calls)
	}
	if gotReason != sessions.ReasonParentDirError {
		t.Errorf("handler reason = %q, want %q", gotReason, sessions.ReasonParentDirError)
	}
	restore()
	assertOriginalUntouchedAndOpen(t, originalStore, before)
}

// assertOriginalUntouchedAndOpen checks that a failed fork left no session_forked
// event on the original and that the original still accepts appends.
func assertOriginalUntouchedAndOpen(t *testing.T, store *sessions.Store, before int) {
	t.Helper()
	recs := store.Records()
	if len(recs) != before {
		t.Errorf("original record count = %d, want unchanged %d", len(recs), before)
	}
	for _, r := range recs {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == events.KindSessionForked {
			t.Errorf("original gained a session_forked event after a failed fork")
		}
	}
	store.Append(sessions.Message{ID: idUser, Role: "user", Content: sessions.TextContent("still open"), Timestamp: startedAt})
	if after := len(store.Records()); after != before+1 {
		t.Errorf("original did not accept an append after a failed fork: %d -> %d", before, after)
	}
}

// failOnWriteFailure returns a handler that fails the test if invoked, for the
// success path where no write failure is expected.
func failOnWriteFailure(t *testing.T) func(fserrors.Category, sessions.WriteReason, error) {
	t.Helper()
	return func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		t.Errorf("unexpected write failure: cat=%q reason=%q err=%v", cat, reason, err)
	}
}

func failOnChildWriteFailure(t *testing.T) func(string, fserrors.Category, sessions.WriteReason, error) {
	t.Helper()
	return func(path string, cat fserrors.Category, reason sessions.WriteReason, err error) {
		t.Errorf("unexpected write failure: path=%q cat=%q reason=%q err=%v", path, cat, reason, err)
	}
}

type probeCtx struct {
	context.Context
	fn func()
}

func (c *probeCtx) Err() error {
	c.fn()
	return c.Context.Err()
}

func childFolderDir(home, folder string) string {
	return filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))
}

func soleLockFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read folder dir: %v", err)
	}
	var found string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json.lock") {
			if found != "" {
				t.Fatalf("multiple lock files in %s", dir)
			}
			found = filepath.Join(dir, e.Name())
		}
	}
	return found
}

func assertSidecarHeld(t *testing.T, lockPath string) {
	t.Helper()
	if lockPath == "" {
		t.Fatal("no sidecar lock file present, want ownership held")
	}
	rel, reason, err := locks.TryAcquire(lockPath)
	if err != nil {
		t.Fatalf("probe sidecar %s: %v", lockPath, err)
	}
	if reason != locks.ReasonLockContended {
		if rel != nil {
			rel()
		}
		t.Fatalf("sidecar %s reason = %q, want %q (ownership held)", lockPath, reason, locks.ReasonLockContended)
	}
}

func assertSidecarReacquirable(t *testing.T, lockPath string) {
	t.Helper()
	rel, reason, err := locks.TryAcquire(lockPath)
	if err != nil {
		t.Fatalf("reacquire sidecar %s: %v", lockPath, err)
	}
	if reason != locks.ReasonNone || rel == nil {
		if rel != nil {
			rel()
		}
		t.Fatalf("sidecar %s reason = %q, want %q (released/reacquirable)", lockPath, reason, locks.ReasonNone)
	}
	rel()
}

func TestCreateOwnedChild_SuccessHoldsOwnershipThroughParentFinalization(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/owned"
	dir := childFolderDir(home, folder)
	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)

	var probes int
	pc := &probeCtx{Context: context.Background(), fn: func() {
		probes++
		assertSidecarHeld(t, soleLockFile(t, dir))
	}}

	owned, err := CreateOwnedChild(pc, home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, nil, nil, failOnChildWriteFailure(t))
	if err != nil {
		t.Fatalf("CreateOwnedChild error = %v", err)
	}
	if owned == nil || owned.Store == nil || owned.Release == nil {
		t.Fatalf("owned result = %+v, want a store and a release", owned)
	}
	if probes < 3 {
		t.Errorf("ownership probes = %d, want >= 3 (before publish, child flush, parent finalization)", probes)
	}

	lockPath := sessions.ResumeLockPath(owned.Store.Path())
	assertSidecarHeld(t, lockPath)

	owned.Release()
	owned.Release()
	assertSidecarReacquirable(t, lockPath)
}

func TestCreateOwnedChild_TerminalRecordsPrecedeSessionForked(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/terminal"
	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)
	if _, _, err := parentStore.Flush(context.Background()); err != nil {
		t.Fatalf("seed parent flush: %v", err)
	}

	terminal := []sessions.Record{
		sessions.Message{ID: idTerminalA, Role: "assistant", Content: sessions.TextContent("terminal one"), Timestamp: startedAt},
		sessions.Message{ID: idTerminalB, Role: "user", Content: sessions.TextContent("terminal two"), Timestamp: startedAt},
	}

	owned, err := CreateOwnedChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, terminal, nil, failOnChildWriteFailure(t))
	if err != nil {
		t.Fatalf("CreateOwnedChild error = %v", err)
	}
	defer owned.Release()

	child := readSession(t, owned.Store.Path())
	if len(child.Records) != 3 {
		t.Fatalf("child records = %d, want 3 (2 supplied + launch_began)", len(child.Records))
	}
	if ev, ok := child.Records[2].(sessions.Event); !ok || ev.Kind != events.KindLaunchBegan {
		t.Fatalf("child last record = %+v, want launch_began", child.Records[2])
	}

	parentFile := readSession(t, parentStore.Path())
	recs := parentFile.Records
	n := len(recs)
	if n < 3 {
		t.Fatalf("parent records = %d, want the pre-batch records plus two terminal + marker", n)
	}
	if got := recs[n-3].(sessions.Message).ID; got != idTerminalA {
		t.Errorf("third-from-last parent record = %q, want terminal %q", got, idTerminalA)
	}
	if got := recs[n-2].(sessions.Message).ID; got != idTerminalB {
		t.Errorf("second-from-last parent record = %q, want terminal %q", got, idTerminalB)
	}
	marker, ok := recs[n-1].(sessions.Event)
	if !ok || marker.Kind != events.KindSessionForked {
		t.Fatalf("last parent record = %+v, want session_forked", recs[n-1])
	}
	var sf events.SessionForked
	if err := json.Unmarshal(marker.Payload, &sf); err != nil {
		t.Fatalf("decode session_forked payload: %v", err)
	}
	if sf.ToSessionID != owned.Store.SessionID() {
		t.Errorf("session_forked.to_session_id = %q, want the durable child %q", sf.ToSessionID, owned.Store.SessionID())
	}
}

func TestCreateOwnedChild_CancellationReleasesOwnership(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/cancel"
	dir := childFolderDir(home, folder)
	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)
	before := len(parentStore.Records())

	base, cancel := context.WithCancel(context.Background())
	var lockPath string
	var fired bool
	pc := &probeCtx{Context: base, fn: func() {
		if fired {
			return
		}
		fired = true
		lockPath = soleLockFile(t, dir)
		assertSidecarHeld(t, lockPath)
		cancel()
	}}

	owned, err := CreateOwnedChild(pc, home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, nil, nil, failOnChildWriteFailure(t))
	if err == nil {
		t.Fatal("CreateOwnedChild succeeded despite cancellation, want error")
	}
	if owned != nil {
		t.Errorf("owned result on cancellation = %+v, want nil", owned)
	}
	if childSessionFileCount(t, dir) != 0 {
		t.Errorf("child session file published despite cancellation before the first child write")
	}
	assertOriginalUntouchedAndOpen(t, parentStore, before)
	assertSidecarReacquirable(t, lockPath)
}

func TestCreateOwnedChild_PostLaunchErrorLeavesParentUnfinalized(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/postlaunch"
	dir := childFolderDir(home, folder)
	parent := originalSession(folder)
	parentStore := sessions.New(filepath.Join(t.TempDir(), "original.json"), parent)
	if _, _, err := parentStore.Flush(context.Background()); err != nil {
		t.Fatalf("seed parent flush: %v", err)
	}
	before := len(parentStore.Records())
	terminal := []sessions.Record{
		sessions.Message{ID: idTerminalA, Role: "assistant", Content: sessions.TextContent("terminal"), Timestamp: startedAt},
	}

	hookErr := errors.New("forced post-launch failure")
	var lastKind string
	rollbacks := 0
	hook := func(child *sessions.Store) (func() error, error) {
		recs := child.Records()
		if ev, ok := recs[len(recs)-1].(sessions.Event); ok {
			lastKind = ev.Kind
		}
		return func() error {
			rollbacks++
			assertSidecarHeld(t, sessions.ResumeLockPath(child.Path()))
			return nil
		}, hookErr
	}
	owned, err := CreateOwnedChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, terminal, hook, failOnChildWriteFailure(t))
	if !errors.Is(err, hookErr) || owned != nil {
		t.Fatalf("CreateOwnedChild = (%+v, %v), want the hook error", owned, err)
	}
	if lastKind != events.KindLaunchBegan {
		t.Errorf("child's last record at hook time = %q, want launch_began", lastKind)
	}
	if rollbacks != 1 {
		t.Errorf("rollback calls = %d, want 1", rollbacks)
	}
	for _, rec := range readSession(t, parentStore.Path()).Records {
		if m, ok := rec.(sessions.Message); ok && m.ID == idTerminalA {
			t.Error("parent file gained the terminal record after a post-launch failure")
		}
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == events.KindSessionForked {
			t.Error("parent file gained session_forked after a post-launch failure")
		}
	}
	assertOriginalUntouchedAndOpen(t, parentStore, before)
	assertSidecarReacquirable(t, soleLockFile(t, dir))
}

func TestCreateOwnedChild_FinalizationFailureRunsRollbackOnce(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	home := t.TempDir()
	folder := "/proj/finalfail"
	dir := childFolderDir(home, folder)
	parent := originalSession(folder)
	parentDir := t.TempDir()
	parentStore := sessions.New(filepath.Join(parentDir, "original.json"), parent)
	if err := os.Chmod(parentDir, 0o500); err != nil {
		t.Fatalf("seal parent dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parentDir, 0o755) })
	before := len(parentStore.Records())

	rollbackErr := errors.New("forced rollback failure")
	rollbacks := 0
	hook := func(child *sessions.Store) (func() error, error) {
		return func() error {
			rollbacks++
			assertSidecarHeld(t, sessions.ResumeLockPath(child.Path()))
			return rollbackErr
		}, nil
	}
	owned, err := CreateOwnedChild(context.Background(), home, snapshotOf(parent), parentStore,
		Child{Records: preparedChild()}, nil, hook, failOnChildWriteFailure(t))
	if err == nil || owned != nil {
		t.Fatalf("CreateOwnedChild = (%+v, %v), want a finalization error", owned, err)
	}
	if rollbacks != 1 {
		t.Errorf("rollback calls = %d, want 1", rollbacks)
	}
	if !errors.Is(err, rollbackErr) {
		t.Errorf("error = %v, want the rollback error joined", err)
	}
	if i := strings.Index(err.Error(), rollbackErr.Error()); i <= 0 {
		t.Errorf("error = %q, want the finalization error before the rollback error", err)
	}
	assertOriginalUntouchedAndOpen(t, parentStore, before)
	assertSidecarReacquirable(t, soleLockFile(t, dir))
}
