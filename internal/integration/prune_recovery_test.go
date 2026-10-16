// Cross-package integration tests composing the real session store and retention
// pruner: retention ages by updated_at, a real crash-during-write flush retains
// records and then persists on repair, and an all-expired per-folder subdir is
// cleaned up (Testing Requirements).
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/sessions"
)

// Valid UUIDv7 ids for the fixture sessions, so each fixture round-trips the
// spine validation when read back from disk through the real store.
const (
	pruneIDRetained = "0190d00e-0000-7000-8000-000000000001"
	pruneIDDeleted  = "0190d00e-0000-7000-8000-000000000002"
	pruneIDExpired1 = "0190d00e-0000-7000-8000-000000000003"
	pruneIDExpired2 = "0190d00e-0000-7000-8000-000000000004"
	pruneIDSurvivor = "0190d00e-0000-7000-8000-000000000005"
	crashMetaID     = "0190d00e-0000-7000-8000-00000000000a"
	crashRecID      = "0190d00e-0000-7000-8000-00000000000b"
)

// writePruneSession writes a valid session file <id>.json into subdir with the
// given started_at/updated_at, marshalled through the public sessions codec
// (not a Store flush, which would overwrite updated_at with the wall clock).
func writePruneSession(t *testing.T, subdir, id string, startedAt, updatedAt time.Time) string {
	t.Helper()
	sess := &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            id,
			Folder:        "/home/u/proj",
			StartedAt:     startedAt,
			UpdatedAt:     updatedAt,
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
	}
	data, err := sessions.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal prune session: %v", err)
	}
	path := filepath.Join(subdir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write prune session: %v", err)
	}
	return path
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestPruneRecovery_RetentionAgesByUpdatedAt drives the real synchronous
// sessions.Prune over a real per-folder subdir and proves retention is decided by
// metadata.updated_at, not started_at: a session started long ago but updated
// recently is kept, while a session started recently but updated long ago is
// deleted (Done-when 1). Ages use wide margins (40 days vs 1 day under a
// 30-day window) because the package time seam is unexported outside
// internal/sessions, so the assertions never depend on an exact cutoff.
func TestPruneRecovery_RetentionAgesByUpdatedAt(t *testing.T) {
	home := t.TempDir()
	subdir, err := sessions.EnsureFolderDir(home, "/home/u/proj")
	if err != nil {
		t.Fatalf("EnsureFolderDir: %v", err)
	}

	now := time.Now().UTC()
	// Old started_at, fresh updated_at -> retained.
	retained := writePruneSession(t, subdir, pruneIDRetained, now.Add(-40*24*time.Hour), now.Add(-1*24*time.Hour))
	// Fresh started_at, old updated_at -> deleted.
	deleted := writePruneSession(t, subdir, pruneIDDeleted, now.Add(-1*24*time.Hour), now.Add(-40*24*time.Hour))

	result, err := sessions.Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if result.FilesScanned != 2 || result.FilesDeleted != 1 || result.FilesFailed != 0 {
		t.Fatalf("counts = scanned %d/deleted %d/failed %d, want 2/1/0",
			result.FilesScanned, result.FilesDeleted, result.FilesFailed)
	}
	if !fileExists(retained) {
		t.Errorf("session with a fresh updated_at was deleted; prune must age by updated_at, not started_at")
	}
	if fileExists(deleted) {
		t.Errorf("session with an old updated_at survived; want deleted")
	}
	// The survivor keeps the subdir and its folder file in place.
	if !fileExists(subdir) || !fileExists(filepath.Join(subdir, "folder")) {
		t.Errorf("subdir or its folder file was removed despite a surviving session")
	}
}

// TestPruneRecovery_CrashDuringWriteRetainsThenPersists exercises a real
// sessions.Store.Flush write failure (a missing parent directory, the same shape
// a session write hits if its directory vanishes mid-run): the in-memory records
// survive the failed flush, no partial file is left behind, and once the path is
// repaired the next flush persists the retained stream — verified by reading the
// file back through the real store, not just by re-inspecting memory (Done-when 2
// and 4).
func TestPruneRecovery_CrashDuringWriteRetainsThenPersists(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "missing", crashMetaID+".json")

	ts := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	sess := &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            crashMetaID,
			Folder:        "/home/u/proj",
			StartedAt:     ts,
			UpdatedAt:     ts,
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
		Records: []sessions.Record{
			sessions.Message{
				ID:        crashRecID,
				Role:      "user",
				Content:   sessions.TextContent("hello"),
				Timestamp: ts,
			},
		},
	}
	store := sessions.New(path, sess)

	cat, reason, err := store.Flush(context.Background())
	if err == nil {
		t.Fatalf("flush into a missing parent succeeded, want a write failure")
	}
	if reason != sessions.ReasonParentDirError {
		t.Fatalf("flush reason = %q, want %q", reason, sessions.ReasonParentDirError)
	}
	if cat != fserrors.NotFound {
		t.Fatalf("flush category = %q, want %q", cat, fserrors.NotFound)
	}

	// The record survives the failed write in memory (the stream is the source of
	// truth between flushes).
	if recs := store.Records(); len(recs) != 1 {
		t.Fatalf("in-memory records after the failed flush = %d, want 1 (retained)", len(recs))
	}
	// No partial file was left behind by the failed atomic write.
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("a session file exists after the failed flush (stat err=%v), want none", statErr)
	}

	// Repair the path and re-flush: the retained records now persist.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("repair parent dir: %v", err)
	}
	if _, reason2, err := store.Flush(context.Background()); err != nil || reason2 != sessions.ReasonNone {
		t.Fatalf("re-flush after repair = (reason %q, err %v), want success", reason2, err)
	}

	// Done-when 4: read the file back through its real store and assert the records
	// persisted on disk, not merely that the in-memory stream survived.
	persisted := readSession(t, path)
	if persisted.Metadata.ID != crashMetaID {
		t.Fatalf("persisted metadata id = %q, want %q", persisted.Metadata.ID, crashMetaID)
	}
	if len(persisted.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(persisted.Records))
	}
	msg, ok := persisted.Records[0].(sessions.Message)
	if !ok || msg.ID != crashRecID {
		t.Fatalf("persisted record 0 = %+v, want the retained user message %q", persisted.Records[0], crashRecID)
	}
}

// TestPruneRecovery_EmptySubdirCleanup proves that when every session file in a
// per-folder subdir is pruned, the real pruner removes the subdir and its folder
// file, while a sibling subdir with a surviving session is left intact (Done-when
// 3).
func TestPruneRecovery_EmptySubdirCleanup(t *testing.T) {
	home := t.TempDir()
	now := time.Now().UTC()

	// A subdir whose every session is expired.
	allExpired, err := sessions.EnsureFolderDir(home, "/proj/expired")
	if err != nil {
		t.Fatalf("EnsureFolderDir(expired): %v", err)
	}
	writePruneSession(t, allExpired, pruneIDExpired1, now.Add(-40*24*time.Hour), now.Add(-40*24*time.Hour))
	writePruneSession(t, allExpired, pruneIDExpired2, now.Add(-50*24*time.Hour), now.Add(-50*24*time.Hour))

	// A sibling subdir with a survivor that must remain.
	survivorDir, err := sessions.EnsureFolderDir(home, "/proj/survivor")
	if err != nil {
		t.Fatalf("EnsureFolderDir(survivor): %v", err)
	}
	writePruneSession(t, survivorDir, pruneIDSurvivor, now.Add(-1*24*time.Hour), now.Add(-1*24*time.Hour))

	result, err := sessions.Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if result.FilesScanned != 3 || result.FilesDeleted != 2 || result.FilesFailed != 0 {
		t.Fatalf("counts = scanned %d/deleted %d/failed %d, want 3/2/0",
			result.FilesScanned, result.FilesDeleted, result.FilesFailed)
	}

	// The all-expired subdir and its folder file are gone.
	if fileExists(allExpired) {
		t.Errorf("all-expired subdir %s still exists, want removed", allExpired)
	}
	if fileExists(filepath.Join(allExpired, "folder")) {
		t.Errorf("folder file in the all-expired subdir still exists, want removed")
	}
	// The survivor subdir and its folder file remain.
	if !fileExists(survivorDir) || !fileExists(filepath.Join(survivorDir, "folder")) {
		t.Errorf("survivor subdir or its folder file was removed, want intact")
	}
}
