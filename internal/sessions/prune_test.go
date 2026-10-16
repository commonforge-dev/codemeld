// Tests for the retention pruner: cutoff/boundary deletion, subdir cleanup, the
// non-blocking pre-unlink lock skip branches, per-file and enumeration failure
// accounting, scanned-only candidates, and the background callback handoff.
package sessions

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/locks"
)

// fixedNow is the deterministic "current time" these tests pin via the package
// time seam so retention cutoffs never depend on wall-clock sleeps.
var fixedNow = time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

// pinNow swaps the package time seam (shared with Store.Flush) to fixedNow for
// the duration of the test.
func pinNow(t *testing.T) {
	t.Helper()
	orig := now
	t.Cleanup(func() { now = orig })
	now = func() time.Time { return fixedNow }
}

// daysAgo returns fixedNow minus n*24h, matching the pruner's day-as-24h window.
func daysAgo(n int) time.Time {
	return fixedNow.Add(-time.Duration(n) * 24 * time.Hour)
}

// makePruneSubdir creates a per-folder subdir under SessionRoot(home) for the
// canonical folder, with its folder file, and returns the subdir path.
func makePruneSubdir(t *testing.T, home, folder string) string {
	t.Helper()
	subdir := filepath.Join(SessionRoot(home), FolderDirName(folder))
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, folderFileName), []byte(folder+"\n"), 0o644); err != nil {
		t.Fatalf("write folder file: %v", err)
	}
	return subdir
}

// writeSessionUpdatedAt writes a minimal valid session file <id>.json in subdir
// whose metadata.updated_at is updatedAt, returning its path.
func writeSessionUpdatedAt(t *testing.T, subdir, id string, updatedAt time.Time) string {
	t.Helper()
	sess := &Session{
		Metadata: Metadata{
			ID:            id,
			Folder:        "/home/u/proj",
			StartedAt:     updatedAt,
			UpdatedAt:     updatedAt,
			SchemaVersion: CurrentSchemaVersion,
		},
	}
	data, err := Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	path := filepath.Join(subdir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}
	return path
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// assertCounts checks the scalar counters and that FilesFailed stays equal to the
// failure-entry count (the session_prune_summary invariant).
func assertCounts(t *testing.T, r PruneResult, scanned, deleted, failed int64) {
	t.Helper()
	if r.FilesScanned != scanned || r.FilesDeleted != deleted || r.FilesFailed != failed {
		t.Fatalf("counts = scanned %d/deleted %d/failed %d, want %d/%d/%d",
			r.FilesScanned, r.FilesDeleted, r.FilesFailed, scanned, deleted, failed)
	}
	if int64(len(r.Failures)) != r.FilesFailed {
		t.Fatalf("FilesFailed %d != len(Failures) %d", r.FilesFailed, len(r.Failures))
	}
	if r.ElapsedMs < 0 {
		t.Fatalf("ElapsedMs = %d, want >= 0", r.ElapsedMs)
	}
}

func TestPrune_DeletesExpiredRetainsFresh(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	expired := writeSessionUpdatedAt(t, subdir, "expired", daysAgo(40))
	fresh := writeSessionUpdatedAt(t, subdir, "fresh", daysAgo(5))

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 2, 1, 0)

	if exists(expired) {
		t.Errorf("expired session %s still exists, want deleted", expired)
	}
	if !exists(fresh) {
		t.Errorf("fresh session %s deleted, want retained", fresh)
	}
	// A survivor keeps the subdir and its folder file in place.
	if !exists(subdir) || !exists(filepath.Join(subdir, folderFileName)) {
		t.Errorf("subdir or folder file removed despite a surviving session")
	}
}

func TestPrune_RetentionBoundaryExactCutoffRetained(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	cutoff := fixedNow.Add(-30 * 24 * time.Hour)
	atCutoff := writeSessionUpdatedAt(t, subdir, "at-cutoff", cutoff)
	justPast := writeSessionUpdatedAt(t, subdir, "just-past", cutoff.Add(-time.Millisecond))

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 2, 1, 0)

	if !exists(atCutoff) {
		t.Errorf("session exactly at the cutoff was deleted; a session within the window must be retained")
	}
	if exists(justPast) {
		t.Errorf("session 1ms past the cutoff was retained; want deleted")
	}
}

func TestPrune_ZeroRetentionBoundary(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	atNow := writeSessionUpdatedAt(t, subdir, "at-now", fixedNow)
	justBefore := writeSessionUpdatedAt(t, subdir, "just-before", fixedNow.Add(-time.Millisecond))

	result, err := Prune(home, 0)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 2, 1, 0)

	if !exists(atNow) {
		t.Errorf("with retention 0, a session updated exactly now must be retained")
	}
	if exists(justBefore) {
		t.Errorf("with retention 0, a session updated before now must be deleted")
	}
}

func TestPrune_LargeRetentionKeepsRecentSession(t *testing.T) {
	for _, days := range []int{106752, math.MaxInt} {
		t.Run(fmt.Sprint(days), func(t *testing.T) {
			pinNow(t)
			home := t.TempDir()
			subdir := makePruneSubdir(t, home, "/home/u/proj")
			recent := writeSessionUpdatedAt(t, subdir, "recent", fixedNow.Add(-time.Hour))

			result, err := Prune(home, days)
			if err != nil {
				t.Fatalf("Prune error: %v", err)
			}
			assertCounts(t, result, 1, 0, 0)
			if !exists(recent) {
				t.Errorf("session updated one hour ago was deleted with retention %d days", days)
			}
		})
	}
}

func TestPrune_SubdirCleanupWhenAllDeleted(t *testing.T) {
	pinNow(t)
	home := t.TempDir()

	allExpired := makePruneSubdir(t, home, "/proj/a")
	writeSessionUpdatedAt(t, allExpired, "e1", daysAgo(40))
	writeSessionUpdatedAt(t, allExpired, "e2", daysAgo(50))

	survivor := makePruneSubdir(t, home, "/proj/b")
	writeSessionUpdatedAt(t, survivor, "fresh", daysAgo(1))

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 3, 2, 0)

	// All-expired subdir and its folder file are gone.
	if exists(allExpired) {
		t.Errorf("subdir %s with no survivors still exists, want removed", allExpired)
	}
	// Survivor subdir and its folder file remain.
	if !exists(survivor) || !exists(filepath.Join(survivor, folderFileName)) {
		t.Errorf("survivor subdir or its folder file was removed")
	}
}

func TestPrune_LockContendedSkips(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")
	sessionPath := writeSessionUpdatedAt(t, subdir, "expired", daysAgo(40))

	// Hold the session's sidecar lock so the pruner's single non-blocking try is
	// contended — the same lock target a resumer holds.
	release, reason, err := locks.TryAcquire(ResumeLockPath(sessionPath))
	if err != nil || reason != locks.ReasonNone {
		t.Fatalf("test could not pre-acquire sidecar lock: reason=%q err=%v", reason, err)
	}
	defer release()

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	// Scanned, not deleted, no failure entry.
	assertCounts(t, result, 1, 0, 0)
	if !exists(sessionPath) {
		t.Errorf("lock-contended session was deleted, want skipped")
	}
	if !exists(subdir) {
		t.Errorf("subdir removed despite a skipped (surviving) session")
	}
}

func TestPrune_LockAcquireErrorSkips(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory mode bits; lock-create failure unobservable")
	}
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")
	sessionPath := writeSessionUpdatedAt(t, subdir, "expired", daysAgo(40))

	// A read+exec but non-writable subdir lets the candidate be read and aged but
	// makes the pruner's attempt to create the sidecar lock fail (acquire error),
	// which must skip the file with no failure entry.
	if err := os.Chmod(subdir, 0o500); err != nil {
		t.Fatalf("chmod subdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(subdir, 0o700) })

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 1, 0, 0)
	if !exists(sessionPath) {
		t.Errorf("session was deleted despite a lock acquire error, want skipped")
	}
}

func TestPrune_FileDeleteFailureAccumulates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory mode bits; unlink failure unobservable")
	}
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")
	sessionPath := writeSessionUpdatedAt(t, subdir, "expired", daysAgo(40))

	// Pre-create the sidecar lock (via the real helper) so the pruner can acquire
	// it even after the subdir is made non-writable; then the session-file unlink
	// is what fails, producing a file_delete entry.
	rel, reason, err := locks.TryAcquire(ResumeLockPath(sessionPath))
	if err != nil || reason != locks.ReasonNone {
		t.Fatalf("pre-create sidecar lock: reason=%q err=%v", reason, err)
	}
	rel()

	if err := os.Chmod(subdir, 0o500); err != nil {
		t.Fatalf("chmod subdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(subdir, 0o700) })

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 1, 0, 1)
	if !exists(sessionPath) {
		t.Errorf("session reported as a delete failure but no longer exists")
	}
	f := result.Failures[0]
	if f.Kind != FailureFileDelete {
		t.Errorf("failure kind = %q, want %q", f.Kind, FailureFileDelete)
	}
	if f.Path != sessionPath {
		t.Errorf("failure path = %q, want %q", f.Path, sessionPath)
	}
	if f.Reason != fserrors.PermissionDenied {
		t.Errorf("failure reason = %q, want %q", f.Reason, fserrors.PermissionDenied)
	}
}

func TestPrune_RootMissingIsEmptyPass(t *testing.T) {
	pinNow(t)
	home := t.TempDir() // no ~/.codemeld/sessions created

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 0, 0, 0)
}

func TestPrune_RootEnumerateFailureEndsPass(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	// Make ~/.codemeld/sessions a regular file so readdir fails with ENOTDIR — a
	// non-ENOENT enumeration failure that ends the pass with one root entry.
	if err := os.MkdirAll(filepath.Join(home, ".codemeld"), 0o700); err != nil {
		t.Fatalf("mkdir .codemeld: %v", err)
	}
	if err := os.WriteFile(SessionRoot(home), []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write sessions-as-file: %v", err)
	}

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 0, 0, 1)
	f := result.Failures[0]
	if f.Kind != FailureDirEnumerate {
		t.Errorf("failure kind = %q, want %q", f.Kind, FailureDirEnumerate)
	}
	if f.Path != SessionRoot(home) {
		t.Errorf("failure path = %q, want root %q", f.Path, SessionRoot(home))
	}
	if f.Reason != fserrors.IOError {
		t.Errorf("failure reason = %q, want %q", f.Reason, fserrors.IOError)
	}
}

func TestPrune_PerFolderEnumerateFailureContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory mode bits; readdir failure unobservable")
	}
	pinNow(t)
	home := t.TempDir()

	bad := makePruneSubdir(t, home, "/proj/bad")
	writeSessionUpdatedAt(t, bad, "x", daysAgo(40))
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatalf("chmod bad subdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o700) })

	good := makePruneSubdir(t, home, "/proj/good")
	goodSession := writeSessionUpdatedAt(t, good, "y", daysAgo(40))

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	// The unreadable subdir contributes one dir_enumerate failure and zero scans;
	// the readable subdir is still pruned (its expired session deleted).
	assertCounts(t, result, 1, 1, 1)
	if exists(goodSession) {
		t.Errorf("expired session in the readable subdir was not deleted")
	}
	f := result.Failures[0]
	if f.Kind != FailureDirEnumerate || f.Path != bad || f.Reason != fserrors.PermissionDenied {
		t.Errorf("failure = %+v, want dir_enumerate on %s with permission_denied", f, bad)
	}
}

func TestPrune_UnparseableCandidatesScannedOnly(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	cases := map[string]string{
		"badjson.json":     "this is not json",
		"nometa.json":      `{"records":[]}`,
		"noupdated.json":   `{"metadata":{"id":"x"}}`,
		"badtime.json":     `{"metadata":{"updated_at":"not-a-timestamp"}}`,
		"numtime.json":     `{"metadata":{"updated_at":12345}}`,
		"nullmeta.json":    `{"metadata":null}`,
		"toplevelarr.json": `[1,2,3]`,
	}
	for name, body := range cases {
		if err := os.WriteFile(filepath.Join(subdir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	// Every candidate is counted in files_scanned only: none deleted, none failed.
	assertCounts(t, result, int64(len(cases)), 0, 0)
	for name := range cases {
		if !exists(filepath.Join(subdir, name)) {
			t.Errorf("unparseable candidate %s was deleted, want left in place", name)
		}
	}
	// Survivors keep the subdir.
	if !exists(subdir) {
		t.Errorf("subdir removed despite scanned-only survivors")
	}
}

// TestPrune_MalformedRecordLineScannedOnly proves prune leaves a candidate in
// place when one of its record lines is not a valid session record, even if that
// line carries a parseable timestamp. The metadata is old enough to be expired, so
// before readUpdatedAt parsed records through parseRecord the stray
// {"timestamp":...} line (which OpenSession rejects for having no type) was
// accepted and drove deletion; now an unparseable record line forces the
// scanned-only/no-delete path (1).
func TestPrune_MalformedRecordLineScannedOnly(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	sess := &Session{
		Metadata: Metadata{
			ID:            "expired",
			Folder:        "/home/u/proj",
			StartedAt:     daysAgo(40),
			UpdatedAt:     daysAgo(40),
			SchemaVersion: CurrentSchemaVersion,
		},
	}
	data, err := Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	// A complete record line with a parseable timestamp but no type: the real load
	// path rejects it, so prune must not delete the file off this stray timestamp.
	data = append(data, []byte(`{"timestamp":"2026-04-01T00:00:00.000Z"}`+"\n")...)
	path := filepath.Join(subdir, "expired.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 1, 0, 0)
	if !exists(path) {
		t.Errorf("candidate with a malformed record line was deleted, want left in place")
	}
}

func writeCompactedSession(t *testing.T, subdir, name string, metaAt, compactionAt time.Time) string {
	t.Helper()
	sess := &Session{
		Metadata: Metadata{
			ID:            ids.NewV7(),
			Folder:        "/home/u/proj",
			StartedAt:     metaAt,
			UpdatedAt:     metaAt,
			SchemaVersion: CurrentSchemaVersion,
			ForkedFrom: &ForkOrigin{
				SessionID: ids.NewV7(),
				RecordID:  ids.NewV7(),
			},
		},
	}
	sess.Records = []Record{Compaction{
		ID:        ids.NewV7(),
		Summary:   "summary text",
		Timestamp: compactionAt,
		Provider:  "openai",
		ModelID:   "gpt-x",
		ParentID:  sess.Metadata.ForkedFrom.RecordID,
	}}
	data, err := Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	path := filepath.Join(subdir, name+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}
	return path
}

func TestPrune_CompactionTimestampParticipatesInRecency(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	fresh := writeCompactedSession(t, subdir, "fresh", daysAgo(40), daysAgo(1))
	stale := writeCompactedSession(t, subdir, "stale", daysAgo(40), daysAgo(35))

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 2, 1, 0)
	if !exists(fresh) {
		t.Errorf("session with a fresh compaction record was deleted, want retained")
	}
	if exists(stale) {
		t.Errorf("session with an old compaction record was retained, want deleted (compaction timestamp drives recency)")
	}
}

func TestPrune_UnlinkedCompactionScannedOnly(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	sess := &Session{
		Metadata: Metadata{
			ID:            ids.NewV7(),
			Folder:        "/home/u/proj",
			StartedAt:     daysAgo(40),
			UpdatedAt:     daysAgo(40),
			SchemaVersion: CurrentSchemaVersion,
		},
	}
	data, err := Marshal(sess)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	line, err := json.Marshal(Compaction{
		ID:        ids.NewV7(),
		Summary:   "summary text",
		Timestamp: daysAgo(35),
		Provider:  "openai",
		ModelID:   "gpt-x",
	})
	if err != nil {
		t.Fatalf("marshal unlinked compaction: %v", err)
	}
	data = append(data, line...)
	data = append(data, '\n')
	path := filepath.Join(subdir, "unlinked.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	assertCounts(t, result, 1, 0, 0)
	if !exists(path) {
		t.Errorf("unlinked compaction candidate was deleted, want scanned-only")
	}
}

func TestPrune_NonSessionFilesIgnored(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")

	// Only the .json file is a candidate. The folder file, a .lock sidecar, and a
	// .tmp-<hex> atomic-write temp file are non-candidates and must not be scanned.
	writeSessionUpdatedAt(t, subdir, "expired", daysAgo(40))
	if err := os.WriteFile(filepath.Join(subdir, "expired.json.lock"), nil, 0o600); err != nil {
		t.Fatalf("write lock sidecar: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "expired.json.tmp-0011223344556677"), []byte("partial"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	result, err := Prune(home, 30)
	if err != nil {
		t.Fatalf("Prune error: %v", err)
	}
	// Exactly one candidate scanned and deleted; the non-candidates were ignored.
	assertCounts(t, result, 1, 1, 0)
}

func TestStartBackgroundPrune_InvokesCallbackWithResult(t *testing.T) {
	pinNow(t)
	home := t.TempDir()
	subdir := makePruneSubdir(t, home, "/home/u/proj")
	expired := writeSessionUpdatedAt(t, subdir, "expired", daysAgo(40))

	done := make(chan PruneResult, 1)
	StartBackgroundPrune(home, 30, func(r PruneResult) { done <- r })

	select {
	case got := <-done:
		assertCounts(t, got, 1, 1, 0)
		if exists(expired) {
			t.Errorf("background prune did not delete the expired session")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("background prune callback was not invoked")
	}
}
