// Tests for SetTitle: title persistence without advancing updated_at, the no-version-bump
// additive-field contract, and the non-blocking sidecar-lock contention refusal
package sessions

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
)

// titleTestID is a valid UUIDv7 so OpenSession (which SetTitle calls) accepts the file.
const titleTestID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

// writeTitleSession writes a minimal valid v1 session file <titleTestID>.json in dir
// with the given title and updated_at, returning its path. Shared with the
// DeleteSession tests.
func writeTitleSession(t *testing.T, dir, title string, updatedAt time.Time) string {
	t.Helper()
	sess := &Session{
		Metadata: Metadata{
			ID:            titleTestID,
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     updatedAt,
			SchemaVersion: CurrentSchemaVersion,
			Title:         title,
		},
	}
	data, err := Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	path := filepath.Join(dir, titleTestID+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}
	return path
}

// TestSetTitle_PersistsWithoutAdvancingUpdatedAt is the DW round-trip: the typed title
// is written, the file is re-opened/re-parsed from disk, and the title reads back —
// while updated_at stays put (a rename is not session activity) and schema_version is
// unchanged.
func TestSetTitle_PersistsWithoutAdvancingUpdatedAt(t *testing.T) {
	dir := t.TempDir()
	updated := time.Date(2026, 5, 25, 12, 5, 0, 0, time.UTC)
	path := writeTitleSession(t, dir, "", updated)

	cat, err := SetTitle(path, "renamed session")
	if err != nil {
		t.Fatalf("SetTitle error = %v (cat %q)", err, cat)
	}
	if cat != "" {
		t.Errorf("SetTitle cat = %q, want empty on success", cat)
	}

	sess, _, oerr := OpenSession(path)
	if oerr != nil {
		t.Fatalf("reopen session: %v", oerr)
	}
	if sess.Metadata.Title != "renamed session" {
		t.Errorf("persisted title = %q, want %q", sess.Metadata.Title, "renamed session")
	}
	if !sess.Metadata.UpdatedAt.Equal(updated) {
		t.Errorf("updated_at = %v, want unchanged %v (rename must not advance it)", sess.Metadata.UpdatedAt, updated)
	}
	if sess.Metadata.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("schema_version = %d, want unchanged %d", sess.Metadata.SchemaVersion, CurrentSchemaVersion)
	}
}

func TestSetTitle_RecordsUserProvenance(t *testing.T) {
	dir := t.TempDir()
	path := writeTitleSession(t, dir, "", time.Date(2026, 5, 25, 12, 5, 0, 0, time.UTC))

	if cat, err := SetTitle(path, "renamed session"); err != nil {
		t.Fatalf("SetTitle error = %v (cat %q)", err, cat)
	}

	sess, _, oerr := OpenSession(path)
	if oerr != nil {
		t.Fatalf("reopen session: %v", oerr)
	}
	if sess.Metadata.TitleSource != TitleSourceUser {
		t.Errorf("persisted title_source = %q, want %q", sess.Metadata.TitleSource, TitleSourceUser)
	}
	if sess.Metadata.Title != "renamed session" {
		t.Errorf("persisted title = %q, want %q", sess.Metadata.Title, "renamed session")
	}
}

func TestSetTitle_LockContendedLeavesProvenanceUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := writeTitleSession(t, dir, "generated name", time.Date(2026, 5, 25, 12, 5, 0, 0, time.UTC))

	release, reason, err := locks.TryAcquire(ResumeLockPath(path))
	if reason != locks.ReasonNone || err != nil {
		t.Fatalf("precondition: could not hold sidecar lock (reason %q, err %v)", reason, err)
	}
	t.Cleanup(release)

	if _, serr := SetTitle(path, "should not apply"); serr == nil {
		t.Fatal("SetTitle on a held lock returned nil error, want refusal")
	}

	sess, _, oerr := OpenSession(path)
	if oerr != nil {
		t.Fatalf("reopen session: %v", oerr)
	}
	if sess.Metadata.TitleSource != "" {
		t.Errorf("title_source = %q after a contended rename, want it unchanged (empty)", sess.Metadata.TitleSource)
	}
	if sess.Metadata.Title != "generated name" {
		t.Errorf("title = %q after a contended rename, want it unchanged %q", sess.Metadata.Title, "generated name")
	}
}

// TestSetTitle_LockContendedRefusesAndLeavesFileUnchanged pins the DW lock contract: a
// rename of a session whose sidecar lock is held by another instance is refused with
// fserrors.InUse and the file is left unchanged.
func TestSetTitle_LockContendedRefusesAndLeavesFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := writeTitleSession(t, dir, "original", time.Date(2026, 5, 25, 12, 5, 0, 0, time.UTC))

	// Hold the session's sidecar lock so SetTitle's single non-blocking try is contended
	// (a separate flock instance conflicts even within this process).
	release, reason, err := locks.TryAcquire(ResumeLockPath(path))
	if reason != locks.ReasonNone || err != nil {
		t.Fatalf("precondition: could not hold sidecar lock (reason %q, err %v)", reason, err)
	}
	t.Cleanup(release)

	cat, serr := SetTitle(path, "should not apply")
	if serr == nil {
		t.Fatal("SetTitle on a held lock returned nil error, want refusal")
	}
	if cat != fserrors.InUse {
		t.Errorf("SetTitle cat = %q, want %q on contention", cat, fserrors.InUse)
	}

	sess, _, oerr := OpenSession(path)
	if oerr != nil {
		t.Fatalf("reopen session: %v", oerr)
	}
	if sess.Metadata.Title != "original" {
		t.Errorf("title changed to %q despite contention, want %q", sess.Metadata.Title, "original")
	}
}

// TestSetTitle_VanishedFileReportsNotFound covers the open-failure category: a file
// pruned between listing and rename reports not_found (the lock is taken first, then
// the load fails).
func TestSetTitle_VanishedFileReportsNotFound(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, titleTestID+".json")
	cat, err := SetTitle(missing, "x")
	if err == nil {
		t.Fatal("SetTitle on a missing file returned nil error")
	}
	if cat != fserrors.NotFound {
		t.Errorf("SetTitle cat = %q, want %q for a missing file", cat, fserrors.NotFound)
	}
}
