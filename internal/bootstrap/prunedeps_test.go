// Tests for the background-prune wiring: the summary callback's
// append/drop/flush/write-failure behavior, the real end-to-end pass driven through
// StartTUI for the fresh launch path, and proof that resume paths start no prune.
package bootstrap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// writeExpiredSession writes a minimal valid session file under SessionRoot(home)
// in folder's per-folder subdir whose updated_at is 40 days in the past, so a
// default-30-day retention prune deletes it regardless of the wall clock (the
// bootstrap package cannot pin the sessions time seam). It returns the file path.
func writeExpiredSession(t *testing.T, home, folder, id string) string {
	t.Helper()
	subdir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatalf("mkdir expired subdir: %v", err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour).UTC()
	data, err := sessions.Marshal(&sessions.Session{Metadata: sessions.Metadata{
		ID:            id,
		Folder:        folder,
		StartedAt:     old,
		UpdatedAt:     old,
		SchemaVersion: sessions.CurrentSchemaVersion,
	}})
	if err != nil {
		t.Fatalf("marshal expired session: %v", err)
	}
	path := filepath.Join(subdir, id+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write expired session: %v", err)
	}
	return path
}

func prunePathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// waitForPrune polls cond until it holds or a short deadline elapses, so a test can
// account for the background prune goroutine without assuming synchronous
// completion. The deadline is generous because the only work is one small temp-dir
// prune pass plus an atomic flush.
func waitForPrune(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background prune did not reach the expected state before the deadline")
}

func pruneSummaries(t *testing.T, store *sessions.Store) []events.SessionPruneSummary {
	t.Helper()
	return decodeStoreEvents[events.SessionPruneSummary](t, store, events.KindSessionPruneSummary)
}

// TestAppendPruneSummary_AppendsAndFlushesToActiveStore pins the happy path of the
// callback: it resolves the active store, appends one session_prune_summary
// carrying the pass's counters, and flushes it durable on disk.
func TestAppendPruneSummary_AppendsAndFlushesToActiveStore(t *testing.T) {
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	appendPruneSummary(context.Background(), app, sessions.PruneResult{FilesScanned: 3, FilesDeleted: 2, ElapsedMs: 4})

	summaries := pruneSummaries(t, store)
	if len(summaries) != 1 {
		t.Fatalf("session_prune_summary events = %d, want 1", len(summaries))
	}
	if got := summaries[0]; got.FilesScanned != 3 || got.FilesDeleted != 2 {
		t.Fatalf("summary = %+v, want scanned=3 deleted=2", got)
	}
	assertFileContains(t, store.Path(), "session_prune_summary")
}

// TestAppendPruneSummary_DropsWhenNoActiveStore pins the drop carve-out:
// with no active session the callback appends nothing and does not panic.
func TestAppendPruneSummary_DropsWhenNoActiveStore(t *testing.T) {
	app := tui.New(nil) // no SetActiveStore: ActiveStore() is nil
	appendPruneSummary(context.Background(), app, sessions.PruneResult{FilesScanned: 1})
}

// TestAppendPruneSummary_DropsForClosedActiveStore pins the in-process
// switch-window carve-out: when the active store has been closed (a
// /clear or /resume swap closed the prior session), the summary append is dropped
// rather than landing in the just-closed stream.
func TestAppendPruneSummary_DropsForClosedActiveStore(t *testing.T) {
	store := mkStore(t)
	store.Close()
	app := tui.New(nil)
	app.SetActiveStore(store)

	appendPruneSummary(context.Background(), app, sessions.PruneResult{FilesScanned: 1, FilesDeleted: 1})

	if got := len(kindEvents(t, store, events.KindSessionPruneSummary)); got != 0 {
		t.Fatalf("session_prune_summary appended to a closed store = %d, want 0", got)
	}
}

// TestAppendPruneSummary_WriteFailureRoutesThroughHandler pins for the
// background callback: when the flush fails with a write reason the callback routes
// it through sessionfailures.HandleWriteFailure, which records session_write_failed,
// and stays non-fatal (no panic, no abort).
func TestAppendPruneSummary_WriteFailureRoutesThroughHandler(t *testing.T) {
	store := unwritableStore(t, "prune-flush-fail", "/proj")
	app := tui.New(nil)
	app.SetActiveStore(store)

	appendPruneSummary(context.Background(), app, sessions.PruneResult{FilesScanned: 1, FilesDeleted: 1})

	if got := len(pruneSummaries(t, store)); got != 1 {
		t.Fatalf("session_prune_summary events = %d, want 1 (appended before the failed flush)", got)
	}
	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (req 400a routing of the failed summary flush)", got)
	}
}

// TestStartTUI_FreshLaunchRunsBackgroundPruneAndAppendsDurableSummary pins that a
// fresh launch (BackgroundPrune marker set) starts the real
// sessions.StartBackgroundPrune — no fake at the seam — which deletes an expired
// session under the sessions root and appends a durable session_prune_summary to
// the active session.
func TestStartTUI_FreshLaunchRunsBackgroundPruneAndAppendsDurableSummary(t *testing.T) {
	defer swapRunApp(func(*tui.App) error { return nil })()

	home := t.TempDir()
	expired := writeExpiredSession(t, home, "/home/u/old-proj", "0190a000-0000-7000-8000-0000000000ad")
	active, err := sessions.EnsureSession(home, "/home/u/proj", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}

	result := &BootstrapResult{
		Home:            home,
		LaunchDir:       "/home/u/proj",
		ProjectRoot:     "/home/u/proj",
		Session:         active,
		BackgroundPrune: true,
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	waitForPrune(t, func() bool {
		if prunePathExists(expired) {
			return false
		}
		data, err := os.ReadFile(active.Path())
		return err == nil && strings.Contains(string(data), "session_prune_summary")
	})

	if prunePathExists(expired) {
		t.Fatalf("expired session %s not deleted by the background prune", expired)
	}
	assertFileContains(t, active.Path(), "session_prune_summary")
	summaries := pruneSummaries(t, active)
	if len(summaries) != 1 {
		t.Fatalf("session_prune_summary events = %d, want 1", len(summaries))
	}
	if got := summaries[0]; got.FilesScanned != 2 || got.FilesDeleted != 1 || got.FilesFailed != 0 {
		t.Fatalf("summary = %+v, want scanned=2 deleted=1 failed=0 (the real pass deleted the one expired session and kept the active one)", got)
	}
}

// TestStartTUI_FreshLaunchEmptyPruneStillAppendsDurableZeroSummary pins the
// empty-prune-result requirement: a fresh launch whose retention pass deletes and fails
// nothing must STILL append exactly one durable session_prune_summary to the active
// session rather than suppress it. The sessions root holds only the active session file
// the launch capability record wrote, so the real background pass scans it and deletes
// nothing. The summary is decoded back from the active session file on disk, so the test fails if
// empty results are dropped or the summary is only present in memory.
func TestStartTUI_FreshLaunchEmptyPruneStillAppendsDurableZeroSummary(t *testing.T) {
	defer swapRunApp(func(*tui.App) error { return nil })()

	home := t.TempDir()
	active, err := sessions.EnsureSession(home, "/home/u/proj", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}

	result := &BootstrapResult{
		Home:            home,
		LaunchDir:       "/home/u/proj",
		ProjectRoot:     "/home/u/proj",
		Session:         active,
		BackgroundPrune: true,
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	waitForPrune(t, func() bool {
		data, err := os.ReadFile(active.Path())
		return err == nil && strings.Contains(string(data), "session_prune_summary")
	})

	disk := readSessionFile(t, active.Path())
	summaries := decodeDiskEvents[events.SessionPruneSummary](t, disk, events.KindSessionPruneSummary)
	if len(summaries) != 1 {
		t.Fatalf("durable session_prune_summary events = %d, want exactly 1 for an empty prune result", len(summaries))
	}
	if got := summaries[0]; got.FilesScanned != 1 || got.FilesDeleted != 0 || got.FilesFailed != 0 {
		t.Fatalf("summary = %+v, want only the active session scanned (empty prune result still summarized durably)", got)
	}
}

// TestStartTUI_ResumeWithIDDoesNotPrune pins that a direct `--resume <id>` launch
// initiates no retention prune. The sub-sequence still refreshes updated_at
// (the retention-safety measure), but BackgroundPrune stays unset so
// StartTUI starts no pruner — a separate expired session survives untouched and no
// session_prune_summary is appended to the resumed session. It drives
// runResumeSubsequence so the marker propagation and the refresh→no-prune wiring are
// exercised end to end; with no goroutine spawned the assertions hold immediately
// after StartTUI returns.
func TestStartTUI_ResumeWithIDDoesNotPrune(t *testing.T) {
	defer swapRunApp(func(*tui.App) error { return nil })()

	home := t.TempDir()
	expired := writeExpiredSession(t, home, "/home/u/old-proj", "0190a000-0000-7000-8000-0000000000be")

	const resumedFolder = "/home/u/proj"
	const resumedID = "0190b000-0000-7000-8000-0000000000cd"
	resumedSubdir := filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(resumedFolder))
	if err := os.MkdirAll(resumedSubdir, 0o700); err != nil {
		t.Fatalf("mkdir resumed subdir: %v", err)
	}
	resumedPath := filepath.Join(resumedSubdir, resumedID+".json")
	// Seed the resumed session on disk with an old updated_at. No prune runs on this
	// path, so its survival is not the point; the refresh below must still advance its
	// timestamp as a retention-safety measure against other pruners.
	oldUpdatedAt := time.Now().Add(-40 * 24 * time.Hour).UTC()
	resumedSession := &sessions.Session{Metadata: sessions.Metadata{
		ID:            resumedID,
		Folder:        resumedFolder,
		StartedAt:     oldUpdatedAt,
		UpdatedAt:     oldUpdatedAt,
		SchemaVersion: sessions.CurrentSchemaVersion,
	}}
	seeded, err := sessions.Marshal(resumedSession)
	if err != nil {
		t.Fatalf("marshal resumed session: %v", err)
	}
	if err := os.WriteFile(resumedPath, seeded, 0o600); err != nil {
		t.Fatalf("write resumed session: %v", err)
	}

	var order []string
	steps := recordingResumeSteps(&order)
	steps.ResolveResume = func(string, string, string) (string, *sessions.Session, error) {
		order = append(order, "R1:ResolveResume")
		return resumedPath, resumedSession, nil
	}
	steps.AcquireLock = func(string, string) (func(), error) {
		order = append(order, "R2:AcquireLock")
		return func() {}, nil
	}
	// Run the production updated_at refresh rather than the recording
	// no-op, so the resumed session's on-disk timestamp is advanced even though resume
	// no longer prunes.
	steps.RefreshUpdatedAt = func(ctx context.Context, store *sessions.Store) error {
		order = append(order, "R4:RefreshUpdatedAt")
		return refreshResumeUpdatedAt(ctx, store, stderrNoticeRenderer{w: io.Discard})
	}
	steps.StartTUI = func(ctx context.Context, result *BootstrapResult) error {
		order = append(order, "8:StartTUI")
		return StartTUI(ctx, result, io.Discard)
	}

	res, err := runResumeSubsequence(context.Background(), home, resumedFolder, resumedID, nil, steps)
	if err != nil {
		t.Fatalf("runResumeSubsequence error: %v", err)
	}
	if res.BackgroundPrune {
		t.Fatal("direct --resume <id> launch set BackgroundPrune; no resume path may prune (req 450)")
	}
	// the updated_at refresh still runs before StartTUI.
	refresh := slices.Index(order, "R4:RefreshUpdatedAt")
	start := slices.Index(order, "8:StartTUI")
	if refresh < 0 || start < 0 || refresh >= start {
		t.Fatalf("RefreshUpdatedAt must precede StartTUI; order=%v", order)
	}

	// No prune ran: the separate expired session is untouched and no summary landed on
	// the resumed session. BackgroundPrune is unset so StartTUI spawns no goroutine,
	// making this deterministic immediately.
	if !prunePathExists(expired) {
		t.Fatalf("expired session %s was deleted; --resume <id> must not prune (req 450)", expired)
	}
	if got := len(kindEvents(t, res.Session, events.KindSessionPruneSummary)); got != 0 {
		t.Fatalf("session_prune_summary events = %d, want 0 on a resumed run", got)
	}
	// The refresh still advanced the resumed session's updated_at on disk.
	disk := readSessionFile(t, resumedPath)
	if !disk.Metadata.UpdatedAt.After(oldUpdatedAt) {
		t.Fatalf("resumed updated_at = %s, want advanced beyond the seeded %s (req 450a refresh)", disk.Metadata.UpdatedAt, oldUpdatedAt)
	}
}

// TestStartTUI_NoBackgroundPruneWhenMarkerUnset pins that when the
// marker is unset (the no-id `--resume` picker path), StartTUI starts no pruner, so
// an expired session survives and no summary is appended. With no goroutine spawned
// the assertion is deterministic immediately after StartTUI returns.
func TestStartTUI_NoBackgroundPruneWhenMarkerUnset(t *testing.T) {
	defer swapRunApp(func(*tui.App) error { return nil })()

	home := t.TempDir()
	expired := writeExpiredSession(t, home, "/home/u/old-proj", "0190a000-0000-7000-8000-0000000000df")
	active, err := sessions.EnsureSession(home, "/home/u/proj", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}

	result := &BootstrapResult{
		Home:            home,
		LaunchDir:       "/home/u/proj",
		ProjectRoot:     "/home/u/proj",
		Session:         active,
		BackgroundPrune: false,
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}

	if !prunePathExists(expired) {
		t.Fatal("expired session was pruned despite the BackgroundPrune marker being unset")
	}
	if got := len(kindEvents(t, active, events.KindSessionPruneSummary)); got != 0 {
		t.Fatalf("session_prune_summary events = %d, want 0 when no background prune runs", got)
	}
}
