// Tests for DeleteSession: success removes the session file and its sidecar, the
// non-blocking lock-contention refusal (fserrors.InUse) leaves the file in place, and a
// missing file reports not_found. Prune's own use of the shared
// deleteSessionUnderLock core stays covered by prune_test.go.
package sessions

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
)

// TestDeleteSession_RemovesFileAndSidecar pins the DW: choosing Delete removes the
// <id>.json file (verified by reading the directory back) and the dedicated sidecar.
func TestDeleteSession_RemovesFileAndSidecar(t *testing.T) {
	dir := t.TempDir()
	path := writeTitleSession(t, dir, "", time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC))
	lockPath := ResumeLockPath(path)
	// Seed the sidecar so its removal is observable (it would otherwise be created and
	// removed within the same DeleteSession call).
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("seed sidecar: %v", err)
	}

	cat, err := DeleteSession(path)
	if err != nil {
		t.Fatalf("DeleteSession error = %v (cat %q)", err, cat)
	}
	if cat != "" {
		t.Errorf("DeleteSession cat = %q, want empty on success", cat)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Errorf("session file still present after delete (stat err %v)", serr)
	}
	if _, lerr := os.Stat(lockPath); !os.IsNotExist(lerr) {
		t.Errorf("sidecar lock still present after delete (stat err %v)", lerr)
	}
}

// TestDeleteSession_LockContendedRefuses pins the DW lock contract: deleting a session
// whose resume lock is held by another instance is refused with fserrors.InUse and the
// file stays on disk.
func TestDeleteSession_LockContendedRefuses(t *testing.T) {
	dir := t.TempDir()
	path := writeTitleSession(t, dir, "", time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC))

	release, reason, err := locks.TryAcquire(ResumeLockPath(path))
	if reason != locks.ReasonNone || err != nil {
		t.Fatalf("precondition: could not hold sidecar lock (reason %q, err %v)", reason, err)
	}
	t.Cleanup(release)

	cat, derr := DeleteSession(path)
	if derr == nil {
		t.Fatal("DeleteSession on a held lock returned nil error, want refusal")
	}
	if cat != fserrors.InUse {
		t.Errorf("DeleteSession cat = %q, want %q on contention", cat, fserrors.InUse)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Errorf("session file removed despite contention: %v", serr)
	}
}

// TestDeleteSession_MissingFileReportsNotFound covers the unlink-failure category for a
// file that vanished before the delete.
func TestDeleteSession_MissingFileReportsNotFound(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, titleTestID+".json")
	cat, err := DeleteSession(missing)
	if err == nil {
		t.Fatal("DeleteSession on a missing file returned nil error")
	}
	if cat != fserrors.NotFound {
		t.Errorf("DeleteSession cat = %q, want %q for a missing file", cat, fserrors.NotFound)
	}
}
