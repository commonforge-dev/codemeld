// Retention pruner: deletes expired session files across every per-folder subdir, with a non-blocking pre-unlink lock and accumulated failures (1, 450c).
package sessions

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/locks"
)

// PruneFailureKind classifies a prune failure as a per-file unlink failure or a
// directory-enumeration failure, mirroring the session_prune_summary failure
// kinds. The strings match events.PruneFailure.Kind exactly so the
// caller's conversion is a verbatim field copy.
type PruneFailureKind string

const (
	// FailureFileDelete is a per-candidate unlink failure.
	FailureFileDelete PruneFailureKind = "file_delete"
	// FailureDirEnumerate is a readdir failure on the sessions root or a
	// per-folder subdirectory.
	FailureDirEnumerate PruneFailureKind = "dir_enumerate"
)

// PruneFailure is one accumulated prune failure. It mirrors events.PruneFailure
// without importing internal/events (which already imports internal/sessions, so
// a reverse import would cycle): the caller converts a PruneResult into the
// session_prune_summary payload. Path is the absolute file or directory path;
// Reason is the error category for that failure.
type PruneFailure struct {
	Path   string
	Reason fserrors.Category
	Kind   PruneFailureKind
}

// PruneResult is the outcome of a single retention prune pass. It mirrors the
// fields of events.SessionPruneSummary without importing
// internal/events, so a caller (the background summary callback or the
// resume orchestration) can convert it into the event payload. FilesFailed is
// kept equal to len(Failures), the invariant the event validator enforces.
type PruneResult struct {
	FilesScanned int64
	FilesDeleted int64
	FilesFailed  int64
	Failures     []PruneFailure
	ElapsedMs    int64
}

// addFailure appends one failure entry and keeps FilesFailed in lockstep with the
// failure count (the session_prune_summary invariant files_failed == len(failures)).
func (r *PruneResult) addFailure(path string, cat fserrors.Category, kind PruneFailureKind) {
	r.Failures = append(r.Failures, PruneFailure{Path: path, Reason: cat, Kind: kind})
	r.FilesFailed = int64(len(r.Failures))
}

// Prune walks every per-folder subdirectory under SessionRoot(home) and deletes
// each session file whose metadata.updated_at is past the retention window
// (retentionDays days). Age is measured against updated_at, not file
// mtime and not started_at, so a session edited recently survives even if it was
// started long ago. It never prints and never exits — StartBackgroundPrune runs it
// in a goroutine on a fresh launch (the only prune path) — so all surfacing
// (the session_prune_summary event) stays with the caller.
//
// Failure accounting follows -1: a per-file unlink failure
// accumulates a file_delete entry without aborting the pass; a non-ENOENT readdir
// failure accumulates a single dir_enumerate entry (ending the pass for the root,
// skipping just that subdirectory for a per-folder dir); an ENOENT directory is
// treated as empty with no failure; and a candidate that cannot be read, whose
// top-level JSON will not parse, or whose updated_at is missing/invalid is counted
// in FilesScanned only and left in place. The returned error is reserved for a
// fatal precondition and is nil for every failure mode the pruner defines, because
// those are accumulated into the result rather than aborting the pass.
func Prune(home string, retentionDays int) (PruneResult, error) {
	start := now()
	retentionDays = min(retentionDays, int(math.MaxInt64/int64(24*time.Hour)))
	cutoff := start.Add(-time.Duration(retentionDays) * 24 * time.Hour)

	var result PruneResult
	root := SessionRoot(home)

	entries, err := os.ReadDir(root)
	if err != nil {
		// Root ENOENT is a clean empty pass with no failure (ENOENT
		// carve-out); any other readdir failure is one dir_enumerate entry and
		// ends the pass.
		if !errors.Is(err, fs.ErrNotExist) {
			result.addFailure(root, fserrors.CategorizeErrno(err), FailureDirEnumerate)
		}
		result.ElapsedMs = elapsedMs(start)
		return result, nil
	}

	for _, e := range entries {
		// Only per-folder subdirectories are walked; stray files at the root
		// (none are written there by the system) are ignored.
		if !e.IsDir() {
			continue
		}
		pruneSubdir(filepath.Join(root, e.Name()), cutoff, &result)
	}

	result.ElapsedMs = elapsedMs(start)
	return result, nil
}

// StartBackgroundPrune runs Prune in a goroutine and invokes appendSummary with
// the completed result, so a fresh launch prunes opportunistically without blocking
// startup (background mode; the only prune path). appendSummary is the
// caller's seam for resolving the active session at append time and appending
// session_prune_summary only when a session is active; when no session
// is active the callback drops the result silently. The callback indirection
// keeps the event conversion and append in the caller, since internal/sessions
// must not import internal/events.
func StartBackgroundPrune(home string, retentionDays int, appendSummary func(PruneResult)) {
	go func() {
		// The background prune has no error or stderr surface: its only
		// surface is the session_prune_summary event the callback appends. Prune
		// accumulates every filesystem failure into the result, so its error is nil
		// today; the result alone carries the outcome.
		result, _ := Prune(home, retentionDays)
		appendSummary(result)
	}()
}

// pruneSubdir scans one per-folder subdirectory: it ages each candidate session
// file, deletes the expired ones under the non-blocking pre-unlink lock, and —
// when every candidate it saw was deleted — removes the now-empty subdirectory
// and its folder file. Enumeration and per-file failures are recorded
// on result without aborting; the caller's loop continues with later subdirs.
func pruneSubdir(subdir string, cutoff time.Time, result *PruneResult) {
	entries, err := os.ReadDir(subdir)
	if err != nil {
		// Per-folder ENOENT: treat as empty and skip silently; any other readdir
		// failure is one dir_enumerate entry, then skip this subdir and continue
		// with the rest.
		if !errors.Is(err, fs.ErrNotExist) {
			result.addFailure(subdir, fserrors.CategorizeErrno(err), FailureDirEnumerate)
		}
		return
	}

	sawCandidate := false
	survivors := 0
	for _, e := range entries {
		name := e.Name()
		// Candidates are regular <id>.json files. The .json suffix also excludes
		// the folder file, the .lock sidecars, and the .tmp-<hex> atomic-write temp
		// files, none of which are session files (non-candidate rule).
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		sawCandidate = true
		result.FilesScanned++

		sessionPath := filepath.Join(subdir, name)
		updatedAt, ok := readUpdatedAt(sessionPath)
		switch {
		case !ok:
			// Unreadable / top-level-unparseable / missing-or-invalid updated_at:
			// scanned only, left in place, no failure (1).
			survivors++
		case !updatedAt.Before(cutoff):
			// Within the retention window: retained.
			survivors++
		case !tryDeleteExpired(sessionPath, result):
			// Expired but lock-contended, lock-error, or unlink-failed: the file is
			// still on disk, so it counts as a survivor and blocks subdir cleanup.
			survivors++
		}
	}

	// the subdirectory and its folder file are removed only once every
	// session file that was present has been deleted. Requiring a candidate to have
	// been seen avoids destroying a freshly created folder-dir whose first session
	// file has not landed yet.
	if sawCandidate && survivors == 0 {
		removeEmptySubdir(subdir)
	}
}

// tryDeleteExpired deletes an expired session file under the non-blocking
// pre-unlink lock. It returns true only when the session file was unlinked.
//
// It delegates the lock-probe-and-unlink to the shared deleteSessionUnderLock core
// (also used by the explicit DeleteSession, so prune and delete cannot drift on lock
// or sidecar handling): a contended or unacquirable lock skips the file with no
// failure entry (counted toward FilesScanned by the caller, never FilesDeleted),
// while a session-file unlink failure accumulates one file_delete entry. A
// sidecar-unlink failure is left untracked by the core (the candidate is already
// deleted, so no new failure kind is invented).
func tryDeleteExpired(sessionPath string, result *PruneResult) bool {
	reason, cat, err := deleteSessionUnderLock(sessionPath)
	if reason != locks.ReasonNone {
		// Lock held by a live session (this or another process) or a lock-acquire
		// failure: skip with no failure entry, leaving the file in place.
		return false
	}
	if err != nil {
		result.addFailure(sessionPath, cat, FailureFileDelete)
		return false
	}
	result.FilesDeleted++
	return true
}

// readUpdatedAt reads a JSONL session and returns its effective updated_at: the
// metadata timestamp or the last complete record timestamp, whichever is later.
// It returns ok=false — the -1 "leave in place, scanned only" signal —
// when the file cannot be read or parsed, or a compaction record lacks valid
// session provenance.
func readUpdatedAt(path string) (updatedAt time.Time, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	lines := completeJSONLLines(data)
	if len(lines) == 0 {
		return time.Time{}, false
	}
	updated, ok := metadataUpdatedAt(lines[0])
	if !ok {
		return time.Time{}, false
	}
	var records []Record
	hasCompaction := false
	for i, line := range lines[1:] {
		rec, err := parseRecord(i, line)
		if err != nil {
			return time.Time{}, false
		}
		records = append(records, rec)
		if _, ok := asCompaction(rec); ok {
			hasCompaction = true
		}
		ts, ok := recordTimestamp(i, line)
		if !ok {
			return time.Time{}, false
		}
		if ts.After(updated) {
			updated = ts
		}
	}
	if hasCompaction {
		meta, err := parseMetadataLine(lines[0])
		if err != nil || validateProvenance(meta, records) != nil {
			return time.Time{}, false
		}
	}
	return updated, true
}

func metadataUpdatedAt(raw json.RawMessage) (time.Time, bool) {
	if !isJSONObject(raw) {
		return time.Time{}, false
	}
	var line struct {
		Type     *string `json:"type"`
		Metadata struct {
			UpdatedAt *string `json:"updated_at"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &line); err != nil || line.Type == nil || *line.Type != "metadata" || line.Metadata.UpdatedAt == nil {
		return time.Time{}, false
	}
	ts, err := parseTimestamp(*line.Metadata.UpdatedAt)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// recordTimestamp parses one JSONL record line through parseRecord — the same
// per-record parser the load path uses — and returns the parsed record's
// timestamp. A line that is not a valid record (e.g. a stray
// {"timestamp":...} object with no type, which OpenSession rejects at load) yields
// ok=false, so readUpdatedAt leaves the candidate scanned-only instead of deleting
// it off an unvalidated timestamp (1). i is the zero-based record index
// used only for parse-error context here.
func recordTimestamp(i int, raw json.RawMessage) (time.Time, bool) {
	rec, err := parseRecord(i, raw)
	if err != nil {
		return time.Time{}, false
	}
	switch r := rec.(type) {
	case Message:
		return r.Timestamp, true
	case Event:
		return r.Timestamp, true
	case Compaction:
		return r.Timestamp, true
	case *Compaction:
		if r == nil {
			return time.Time{}, false
		}
		return r.Timestamp, true
	}
	return time.Time{}, false
}

// removeEmptySubdir removes a per-folder subdirectory whose session files have all
// been deleted, taking the folder file first because os.Remove only removes an
// empty directory. Both removals are best-effort: there is no defined
// failure entry for subdir cleanup, and os.Remove on the directory deliberately
// fails (leaving it in place) if any unrelated file remains, so an in-flight
// session write's temp file is never clobbered.
func removeEmptySubdir(subdir string) {
	_ = os.Remove(filepath.Join(subdir, folderFileName))
	_ = os.Remove(subdir)
}

// elapsedMs returns the prune pass duration in milliseconds, measured off the
// package time seam and clamped at zero so a backward wall-clock adjustment never
// yields a negative elapsed_ms.
func elapsedMs(start time.Time) int64 {
	d := now().Sub(start)
	if d < 0 {
		return 0
	}
	return d.Milliseconds()
}
