// Tests for EnsureSession: fresh/fork shapes, folder-dir and collision passthrough, and an append/flush smoke.
package sessions

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/ids"
)

func TestCurrentSchemaVersion(t *testing.T) {
	// Pin the writer-side schema version value, not just that EnsureSession copies
	// the constant: a changed constant must fail here, since the reader-side version support
	// is asserted against this exact value.
	if CurrentSchemaVersion != 1 {
		t.Errorf("CurrentSchemaVersion = %d, want 1", CurrentSchemaVersion)
	}
}

func TestEnsureSession_FreshShape(t *testing.T) {
	home := t.TempDir()
	const folder = "/home/u/proj"
	startedAt := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)

	store, err := EnsureSession(home, folder, startedAt, nil)
	if err != nil {
		t.Fatalf("EnsureSession error: %v", err)
	}

	subdir := filepath.Join(SessionRoot(home), FolderDirName(folder))
	meta := store.session.Metadata
	if !ids.IsValidV7(meta.ID) {
		t.Errorf("ID %q is not a valid UUIDv7", meta.ID)
	}
	wantPath := filepath.Join(subdir, meta.ID+".json")
	if store.Path() != wantPath {
		t.Errorf("Path() = %q, want %q", store.Path(), wantPath)
	}
	if meta.Folder != folder {
		t.Errorf("Folder = %q, want %q", meta.Folder, folder)
	}
	if !meta.StartedAt.Equal(startedAt) || !meta.UpdatedAt.Equal(startedAt) {
		t.Errorf("StartedAt/UpdatedAt = %v/%v, want both %v", meta.StartedAt, meta.UpdatedAt, startedAt)
	}
	if meta.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", meta.SchemaVersion, CurrentSchemaVersion)
	}
	if got := store.Records(); len(got) != 0 {
		t.Errorf("record stream = %v, want empty", got)
	}
}

func TestEnsureSession_ForkShape(t *testing.T) {
	home := t.TempDir()
	const folder = "/home/u/proj"
	startedAt := time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC) // a past time, not now
	records := []Record{
		Message{ID: ids.NewV7(), Role: "user", Content: TextContent("first"), Timestamp: startedAt},
		Message{ID: ids.NewV7(), Role: "assistant", Content: TextContent("second"), Timestamp: startedAt},
	}

	store, err := EnsureSession(home, folder, startedAt, records)
	if err != nil {
		t.Fatalf("EnsureSession error: %v", err)
	}

	meta := store.session.Metadata
	if !meta.StartedAt.Equal(startedAt) {
		t.Errorf("StartedAt = %v, want caller-supplied %v", meta.StartedAt, startedAt)
	}
	if !meta.UpdatedAt.After(startedAt) {
		t.Errorf("UpdatedAt = %v, want after seeded StartedAt %v", meta.UpdatedAt, startedAt)
	}
	got := store.Records()
	if len(got) != len(records) {
		t.Fatalf("record stream length = %d, want %d", len(got), len(records))
	}
	for i := range records {
		gotMsg, ok := got[i].(Message)
		if !ok {
			t.Fatalf("record[%d] is %T, want Message", i, got[i])
		}
		wantMsg := records[i].(Message)
		if gotMsg.ID != wantMsg.ID || gotMsg.Content.Text() != wantMsg.Content.Text() {
			t.Errorf("record[%d] = %+v, want %+v (order must be preserved)", i, gotMsg, wantMsg)
		}
	}
}

func TestEnsureChildSession_ReadBack(t *testing.T) {
	home := t.TempDir()
	parent := MetadataSnapshot{
		ID:        "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b01",
		Folder:    "/home/u/proj",
		StartedAt: time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC),
	}
	origin := ForkOrigin{SessionID: parent.ID, RecordID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b02"}
	records := []Record{
		Message{ID: ids.NewV7(), Role: "user", Content: TextContent("first"), Timestamp: parent.StartedAt},
		Message{ID: ids.NewV7(), Role: "assistant", Content: TextContent("second"), Timestamp: parent.StartedAt},
	}

	store, err := EnsureChildSession(home, parent, "child title", origin, records)
	if err != nil {
		t.Fatalf("EnsureChildSession error: %v", err)
	}
	if cat, reason, ferr := store.Flush(context.Background()); ferr != nil {
		t.Fatalf("Flush error: cat=%q reason=%q err=%v", cat, reason, ferr)
	}

	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("child session file not written: %v", err)
	}
	child, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("parse child session file: %v", err)
	}
	if child.Metadata.ID == parent.ID || !ids.IsValidV7(child.Metadata.ID) {
		t.Errorf("child id = %q, want a fresh UUIDv7 distinct from the parent", child.Metadata.ID)
	}
	if child.Metadata.Folder != parent.Folder {
		t.Errorf("folder = %q, want copied %q", child.Metadata.Folder, parent.Folder)
	}
	if !child.Metadata.StartedAt.Equal(parent.StartedAt) {
		t.Errorf("started_at = %v, want copied %v", child.Metadata.StartedAt, parent.StartedAt)
	}
	if child.Metadata.Title != "child title" {
		t.Errorf("title = %q, want %q", child.Metadata.Title, "child title")
	}
	if child.Metadata.TitleSource != TitleSourceGenerated {
		t.Errorf("title_source = %q, want %q", child.Metadata.TitleSource, TitleSourceGenerated)
	}
	if child.Metadata.ForkedFrom == nil || *child.Metadata.ForkedFrom != origin {
		t.Fatalf("forked_from = %+v, want %+v", child.Metadata.ForkedFrom, origin)
	}
	if got := child.Records[0].(Message).ParentID; got != origin.RecordID {
		t.Errorf("records[0].parent_id = %q, want %q", got, origin.RecordID)
	}
	if got := child.Records[1].(Message).ParentID; got != "" {
		t.Errorf("records[1].parent_id = %q, want empty", got)
	}
	if got := records[0].(Message).ParentID; got != "" {
		t.Errorf("caller's record slice was mutated: records[0].ParentID = %q, want empty", got)
	}
}

func TestEnsureChildSession_PointerCompaction(t *testing.T) {
	home := t.TempDir()
	parent := MetadataSnapshot{
		ID:        "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b01",
		Folder:    "/home/u/proj",
		StartedAt: time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC),
	}
	origin := ForkOrigin{SessionID: parent.ID, RecordID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b02"}
	comp := &Compaction{
		ID:        ids.NewV7(),
		Summary:   "prior context",
		Timestamp: parent.StartedAt,
		Provider:  "anthropic",
		ModelID:   "claude-opus-4-8",
	}
	records := []Record{comp}

	store, err := EnsureChildSession(home, parent, "", origin, records)
	if err != nil {
		t.Fatalf("EnsureChildSession(*Compaction) error: %v", err)
	}
	if cat, reason, ferr := store.Flush(context.Background()); ferr != nil {
		t.Fatalf("Flush error: cat=%q reason=%q err=%v", cat, reason, ferr)
	}
	if comp.ParentID != "" {
		t.Errorf("caller's *Compaction was mutated: ParentID = %q, want empty", comp.ParentID)
	}

	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("child session file not written: %v", err)
	}
	child, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("parse child session file: %v", err)
	}
	if got := recordParentID(child.Records[0]); got != origin.RecordID {
		t.Errorf("records[0].parent_id = %q, want stamped %q", got, origin.RecordID)
	}
}

func TestEnsureChildSession_Rejects(t *testing.T) {
	parent := MetadataSnapshot{
		ID:        "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b01",
		Folder:    "/home/u/proj",
		StartedAt: time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC),
	}
	validOrigin := ForkOrigin{SessionID: parent.ID, RecordID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4b02"}
	record := Message{ID: ids.NewV7(), Role: "user", Content: TextContent("x"), Timestamp: parent.StartedAt}

	tests := []struct {
		name    string
		origin  ForkOrigin
		records []Record
		wantSub string
	}{
		{"no initial records", validOrigin, nil, "at least one initial record"},
		{
			"non-UUIDv7 source session",
			ForkOrigin{SessionID: "nope", RecordID: validOrigin.RecordID},
			[]Record{record},
			"forked_from.session_id",
		},
		{
			"non-UUIDv7 source record",
			ForkOrigin{SessionID: parent.ID, RecordID: "nope"},
			[]Record{record},
			"forked_from.record_id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			store, err := EnsureChildSession(home, parent, "", tt.origin, tt.records)
			if err == nil {
				t.Fatalf("EnsureChildSession() = nil error, want rejection")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
			if store != nil {
				t.Errorf("store = %v, want nil", store)
			}
			if _, statErr := os.Stat(SessionRoot(home)); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("sessions root created for a refused child: stat err = %v", statErr)
			}
		})
	}
}

func TestEnsureSession_FolderDirErrorPassthrough(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codemeld"), 0o755); err != nil {
		t.Fatalf("mkdir .codemeld: %v", err)
	}
	// Occupy the sessions root with a regular file so EnsureFolderDir hits ENOTDIR.
	if err := os.WriteFile(SessionRoot(home), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed file at sessions root: %v", err)
	}

	store, err := EnsureSession(home, "/home/u/proj", time.Now().UTC(), nil)
	var fde *FolderDirError
	if !errors.As(err, &fde) {
		t.Fatalf("err = %v, want *FolderDirError", err)
	}
	// Contract is unchanged passthrough: errors.As alone would still pass if
	// EnsureSession wrapped the error, so pin exact identity.
	if err != fde {
		t.Errorf("err = %v, want unchanged *FolderDirError %v", err, fde)
	}
	if store != nil {
		t.Errorf("store = %v, want nil on folder-dir failure", store)
	}
}

func TestEnsureSession_CollisionPassthrough(t *testing.T) {
	home := t.TempDir()
	const folder = "/home/u/proj"
	const recorded = "/home/u/other"
	subdir := filepath.Join(SessionRoot(home), FolderDirName(folder))
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("seed subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, folderFileName), []byte(recorded+"\n"), 0o644); err != nil {
		t.Fatalf("seed folder file: %v", err)
	}

	store, err := EnsureSession(home, folder, time.Now().UTC(), nil)
	var ce *CollisionError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *CollisionError", err)
	}
	// Contract is unchanged passthrough: errors.As alone would still pass if
	// EnsureSession wrapped the error, so pin exact identity.
	if err != ce {
		t.Errorf("err = %v, want unchanged *CollisionError %v", err, ce)
	}
	if store != nil {
		t.Errorf("store = %v, want nil on collision", store)
	}
}

func TestEnsureSession_AppendFlushSmoke(t *testing.T) {
	home := t.TempDir()
	startedAt := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)

	store, err := EnsureSession(home, "/home/u/proj", startedAt, nil)
	if err != nil {
		t.Fatalf("EnsureSession error: %v", err)
	}
	// EnsureSession must not flush: the session file must be absent until the
	// caller owns the first durable write. A flush inside EnsureSession would
	// create the file here and break the fresh/fork boundary.
	if _, statErr := os.Stat(store.Path()); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("session file exists before caller flush: stat err = %v, want fs.ErrNotExist", statErr)
	}
	store.Append(Message{ID: ids.NewV7(), Role: "user", Content: TextContent("hi"), Timestamp: startedAt})
	if cat, reason, ferr := store.Flush(context.Background()); ferr != nil {
		t.Fatalf("Flush error: cat=%q reason=%q err=%v", cat, reason, ferr)
	}
	if _, statErr := os.Stat(store.Path()); statErr != nil {
		t.Fatalf("session file not written: %v", statErr)
	}
}
