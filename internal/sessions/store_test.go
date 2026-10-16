// Tests for the in-memory session store: append/flush durability, multi-append
// capture, write-failure reason mapping, and updated_at handling.
package sessions

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

const (
	testMetaID   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	testRecID1   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a01"
	testRecID2   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a02"
	testRecID3   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a03"
	markerRecID  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a04"
	laterRecID   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a05"
	markerRecID2 = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a06"
	postFailRec  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a07"
)

// baseSession returns a records-less session usable as a flush target.
func baseSession() *Session {
	return &Session{
		Metadata: Metadata{
			ID:            testMetaID,
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
	}
}

func userMessage(id, text string) Message {
	return Message{
		ID:        id,
		Role:      "user",
		Content:   TextContent(text),
		Timestamp: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
	}
}

// readBack loads and validates the session file the store wrote.
func readBack(t *testing.T, path string) *Session {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	sess, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session file: %v", err)
	}
	return sess
}

func TestStore_AppendThenFlush_WritesParseableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "hello"))

	cat, reason, err := s.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush error: %v (cat=%q reason=%q)", err, cat, reason)
	}
	if cat != "" || reason != ReasonNone {
		t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone on success", cat, reason)
	}

	got := readBack(t, path)
	if len(got.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1", len(got.Records))
	}
	msg, ok := got.Records[0].(Message)
	if !ok {
		t.Fatalf("record 0 type = %T, want Message", got.Records[0])
	}
	if msg.ID != testRecID1 || msg.Content.Text() != "hello" {
		t.Fatalf("persisted message = %+v, want id=%q text=%q", msg, testRecID1, "hello")
	}
}

func TestStore_MultiAppendBetweenFlushes_CapturesEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())

	s.Append(userMessage(testRecID1, "first"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("first Flush error: %v", err)
	}
	if got := len(readBack(t, path).Records); got != 1 {
		t.Fatalf("after first flush records = %d, want 1", got)
	}

	// Two appends with no intervening flush must both land on the next flush.
	s.Append(userMessage(testRecID2, "second"))
	s.Append(userMessage(testRecID3, "third"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("second Flush error: %v", err)
	}

	got := readBack(t, path)
	if len(got.Records) != 3 {
		t.Fatalf("after second flush records = %d, want 3", len(got.Records))
	}
	wantIDs := []string{testRecID1, testRecID2, testRecID3}
	for i, want := range wantIDs {
		msg, ok := got.Records[i].(Message)
		if !ok {
			t.Fatalf("record %d type = %T, want Message", i, got.Records[i])
		}
		if msg.ID != want {
			t.Fatalf("record %d id = %q, want %q", i, msg.ID, want)
		}
	}
}

func TestStore_FlushAppendsOnlyNewLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "first"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("first Flush error: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first flush: %v", err)
	}

	s.Append(userMessage(testRecID2, "second"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("second Flush error: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second flush: %v", err)
	}

	if len(after) <= len(before) || string(after[:len(before)]) != string(before) {
		t.Fatalf("second flush rewrote existing bytes\nbefore: %s\nafter: %s", before, after)
	}
	if got := len(readBack(t, path).Records); got != 2 {
		t.Fatalf("persisted records = %d, want 2", got)
	}
}

// TestStore_AppendAfterTornTailRecovery_RepairsBeforeAppending pins the
// crash-recovery contract end to end: a session file whose final line was torn by
// a crash loads (via OpenSession) back to its last complete record, and the next
// append through a Store built on that file repairs the torn tail before writing,
// so a second OpenSession returns the recovered record plus the new one and never a
// parse error. Without the repair the append lands after the half-written bytes,
// fusing them into one malformed newline-terminated line that fails to load.
func TestStore_AppendAfterTornTailRecovery_RepairsBeforeAppending(t *testing.T) {
	complete := `{"type":"message","id":"` + testRecID1 + `","role":"user","content":"kept","timestamp":"2026-05-25T12:00:00.000Z"}`
	torn := `{"type":"message","id":"` + testRecID2 + `","role":"user"` // crash-truncated tail: no newline
	path := writeSessionFile(t, sessionJSONWithVersion("1")+complete+"\n"+torn)

	sess, _, err := OpenSession(path)
	if err != nil {
		t.Fatalf("OpenSession of torn-tail file: %v", err)
	}
	if len(sess.Records) != 1 {
		t.Fatalf("recovered records = %d, want 1 (only the complete record)", len(sess.Records))
	}

	s := New(path, sess)
	s.Append(userMessage(testRecID3, "added after recovery"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("Flush after recovery: %v", err)
	}

	got, _, err := OpenSession(path)
	if err != nil {
		t.Fatalf("reopen after post-recovery append must parse, got: %v", err)
	}
	if len(got.Records) != 2 {
		t.Fatalf("records after recovery+append = %d, want 2", len(got.Records))
	}
	if id := got.Records[0].(Message).ID; id != testRecID1 {
		t.Fatalf("record 0 id = %q, want the recovered complete record %q", id, testRecID1)
	}
	if id := got.Records[1].(Message).ID; id != testRecID3 {
		t.Fatalf("record 1 id = %q, want the appended record %q", id, testRecID3)
	}
}

func TestStore_FlushFailure_ReadOnlyTarget_ReturnsWriteReason(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir read-only parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

	path := filepath.Join(parent, "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "hello"))

	cat, reason, err := s.Flush(context.Background())
	if err == nil {
		t.Fatalf("Flush into read-only parent succeeded, want error")
	}
	if reason != ReasonWriteError {
		t.Fatalf("reason = %q, want %q", reason, ReasonWriteError)
	}
	if cat != fserrors.PermissionDenied {
		t.Fatalf("cat = %q, want %q", cat, fserrors.PermissionDenied)
	}

	// the in-memory stream is retained so the next flush re-attempts.
	if got := len(s.Records()); got != 1 {
		t.Fatalf("in-memory records after failed flush = %d, want 1 (retained)", got)
	}
}

func TestStore_FlushFailure_ReasonMapping(t *testing.T) {
	t.Run("rename_error_target_is_dir", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.json")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("mkdir target dir: %v", err)
		}
		s := New(path, baseSession())
		cat, reason, err := s.Flush(context.Background())
		if err == nil {
			t.Fatalf("Flush onto directory target succeeded, want error")
		}
		if reason != ReasonRenameError {
			t.Fatalf("reason = %q, want %q", reason, ReasonRenameError)
		}
		if cat == "" {
			t.Fatalf("cat is empty on rename failure, want a category")
		}
	})

	t.Run("parent_dir_error_missing_parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
		s := New(path, baseSession())
		cat, reason, err := s.Flush(context.Background())
		if err == nil {
			t.Fatalf("Flush into missing parent succeeded, want error")
		}
		if reason != ReasonParentDirError {
			t.Fatalf("reason = %q, want %q", reason, ReasonParentDirError)
		}
		if cat != fserrors.NotFound {
			t.Fatalf("cat = %q, want %q", cat, fserrors.NotFound)
		}
	})
}

func TestStore_FlushDoesNotRewriteMetadataUpdatedAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	base := baseSession()
	base.Metadata.UpdatedAt = time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	msg := userMessage(testRecID1, "hello")
	msg.Timestamp = time.Date(2026, 5, 25, 12, 0, 5, 0, time.UTC)
	s := New(path, base)
	s.Append(msg)

	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("Flush error: %v", err)
	}
	loaded := readBack(t, path)

	if !loaded.Metadata.UpdatedAt.Equal(base.Metadata.UpdatedAt) {
		t.Fatalf("metadata updated_at = %s, want unchanged %s", loaded.Metadata.UpdatedAt, base.Metadata.UpdatedAt)
	}
	if got := loaded.Records[len(loaded.Records)-1].(Message).Timestamp; !got.Equal(msg.Timestamp) {
		t.Fatalf("last record timestamp = %s, want %s", got, msg.Timestamp)
	}
}

// TestStore_FlushTitle_PersistsTitleWithoutAdvancingUpdatedAt pins the
// active-store rename seam: FlushTitle sets metadata.title, persists the whole
// session (records included) to disk, and — unlike Flush — leaves updated_at at the
// session's existing value (a rename is not session activity). The `now`
// seam is wired to a clearly later instant to prove FlushTitle never consults it.
func TestStore_FlushTitle_PersistsTitleWithoutAdvancingUpdatedAt(t *testing.T) {
	orig := now
	t.Cleanup(func() { now = orig })
	now = func() time.Time { return time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) }

	path := filepath.Join(t.TempDir(), "session.json")
	base := baseSession()
	wantUpdatedAt := base.Metadata.UpdatedAt
	s := New(path, base)
	s.Append(userMessage(testRecID1, "hello"))

	cat, reason, err := s.FlushTitle(context.Background(), "my session")
	if err != nil {
		t.Fatalf("FlushTitle error: %v (cat=%q reason=%q)", err, cat, reason)
	}
	if cat != "" || reason != ReasonNone {
		t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone on success", cat, reason)
	}

	got := readBack(t, path)
	if got.Metadata.Title != "my session" {
		t.Fatalf("persisted title = %q, want %q", got.Metadata.Title, "my session")
	}
	if !got.Metadata.UpdatedAt.Equal(wantUpdatedAt) {
		t.Fatalf("updated_at = %s after FlushTitle, want it unchanged at %s", got.Metadata.UpdatedAt, wantUpdatedAt)
	}
	if len(got.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1 (the appended message persists with the title)", len(got.Records))
	}
}

func TestStore_FlushTitle_RecordsUserProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())

	if _, _, err := s.FlushTitle(context.Background(), "my session"); err != nil {
		t.Fatalf("FlushTitle error: %v", err)
	}
	if got := s.Title(); got != "my session" {
		t.Errorf("in-memory Title = %q, want %q", got, "my session")
	}

	got := readBack(t, path)
	if got.Metadata.TitleSource != TitleSourceUser {
		t.Fatalf("persisted title_source = %q, want %q", got.Metadata.TitleSource, TitleSourceUser)
	}
	if reopened := New(path, got).Title(); reopened != "my session" {
		t.Errorf("reopened Title = %q, want %q", reopened, "my session")
	}
}

func TestStore_FlushTitle_EmptyNameRecordsNoProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())

	if _, _, err := s.FlushTitle(context.Background(), "named"); err != nil {
		t.Fatalf("FlushTitle to seed a name: %v", err)
	}
	if _, _, err := s.FlushTitle(context.Background(), ""); err != nil {
		t.Fatalf("FlushTitle clearing the name: %v", err)
	}

	got := readBack(t, path)
	if got.Metadata.TitleSource != "" {
		t.Errorf("persisted title_source = %q after clearing the name, want empty", got.Metadata.TitleSource)
	}
	if s.Title() != "" {
		t.Errorf("Title = %q after clearing the name, want empty", s.Title())
	}
}

// TestStore_FlushTitle_WriteFailure_ReturnsReason pins that FlushTitle reports the
// same category/WriteReason shape as Flush on an atomic-write failure, so the
// production seam can route it through the session-failure protocol.
func TestStore_FlushTitle_WriteFailure_ReturnsReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
	s := New(path, baseSession())

	cat, reason, err := s.FlushTitle(context.Background(), "x")
	if err == nil {
		t.Fatalf("FlushTitle into missing parent succeeded, want error")
	}
	if reason != ReasonParentDirError {
		t.Fatalf("reason = %q, want %q", reason, ReasonParentDirError)
	}
	if cat != fserrors.NotFound {
		t.Fatalf("cat = %q, want %q", cat, fserrors.NotFound)
	}
}

func TestStore_FlushTitle_WriteFailureRestoresPriorMetadata(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "no-such-subdir")
	path := filepath.Join(parent, "session.json")
	base := baseSession()
	base.Metadata.Title = "previous name"
	base.Metadata.TitleSource = TitleSourceUser
	s := New(path, base)

	if _, _, err := s.FlushTitle(context.Background(), "rejected name"); err == nil {
		t.Fatal("FlushTitle into missing parent succeeded, want error")
	}
	if got := s.Title(); got != "previous name" {
		t.Fatalf("in-memory title after failed FlushTitle = %q, want prior title", got)
	}
	if got := s.session.Metadata.TitleSource; got != TitleSourceUser {
		t.Fatalf("in-memory title_source after failed FlushTitle = %q, want %q", got, TitleSourceUser)
	}

	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent for recovery flush: %v", err)
	}
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("recovery Flush error: %v", err)
	}
	got := readBack(t, path).Metadata
	if got.Title != "previous name" || got.TitleSource != TitleSourceUser {
		t.Errorf("persisted metadata after recovery = title=%q source=%q, want prior user title", got.Title, got.TitleSource)
	}
}

// TestStore_FlushGeneratedTitle_PersistsWithoutAdvancingUpdatedAt pins the
// store-write half of auto-naming: when metadata.title is still empty, the helper
// persists the generated title (records included) and — like FlushTitle — leaves
// updated_at at the session's existing value, since a generated title is metadata
// housekeeping, not session activity. The `now` seam is wired to a clearly later
// instant to prove the helper never consults it.
func TestStore_FlushGeneratedTitle_PersistsWithoutAdvancingUpdatedAt(t *testing.T) {
	orig := now
	t.Cleanup(func() { now = orig })
	now = func() time.Time { return time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) }

	path := filepath.Join(t.TempDir(), "session.json")
	base := baseSession()
	wantUpdatedAt := base.Metadata.UpdatedAt
	s := New(path, base)
	s.Append(userMessage(testRecID1, "hello"))

	cat, reason, err := s.FlushGeneratedTitle(context.Background(), "auto title")
	if err != nil {
		t.Fatalf("FlushGeneratedTitle error: %v (cat=%q reason=%q)", err, cat, reason)
	}
	if cat != "" || reason != ReasonNone {
		t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone on success", cat, reason)
	}

	got := readBack(t, path)
	if got.Metadata.Title != "auto title" {
		t.Fatalf("persisted title = %q, want %q", got.Metadata.Title, "auto title")
	}
	if !got.Metadata.UpdatedAt.Equal(wantUpdatedAt) {
		t.Fatalf("updated_at = %s after FlushGeneratedTitle, want it unchanged at %s", got.Metadata.UpdatedAt, wantUpdatedAt)
	}
	if len(got.Records) != 1 {
		t.Fatalf("persisted records = %d, want 1 (the appended message persists with the title)", len(got.Records))
	}
}

func TestStore_FlushGeneratedTitle_RecordsGeneratedProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())

	if _, _, err := s.FlushGeneratedTitle(context.Background(), "auto title"); err != nil {
		t.Fatalf("FlushGeneratedTitle error: %v", err)
	}
	if got := s.Title(); got != "auto title" {
		t.Errorf("in-memory Title = %q, want the raw generated title %q", got, "auto title")
	}

	got := readBack(t, path)
	if got.Metadata.TitleSource != TitleSourceGenerated {
		t.Fatalf("persisted title_source = %q, want %q", got.Metadata.TitleSource, TitleSourceGenerated)
	}
	if reopened := New(path, got).Title(); reopened != "auto title" {
		t.Errorf("reopened Title = %q, want %q", reopened, "auto title")
	}
}

func TestStore_FlushGeneratedTitle_DoesNotOverwriteUserProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	if _, _, err := s.FlushTitle(context.Background(), "manual"); err != nil {
		t.Fatalf("FlushTitle to seed manual title: %v", err)
	}

	if _, _, err := s.FlushGeneratedTitle(context.Background(), "generated"); err != nil {
		t.Fatalf("FlushGeneratedTitle over a manual title errored: %v", err)
	}

	got := readBack(t, path)
	if got.Metadata.TitleSource != TitleSourceUser {
		t.Errorf("persisted title_source = %q, want %q (the manual rename wins)", got.Metadata.TitleSource, TitleSourceUser)
	}
	if got := s.Title(); got != "manual" {
		t.Errorf("Title = %q, want %q", got, "manual")
	}
}

func generatedTitleStore(t *testing.T, title string) (*Store, string) {
	t.Helper()
	s, path := seededStore(t, testRecID1)
	if _, _, err := s.FlushGeneratedTitle(t.Context(), title); err != nil {
		t.Fatalf("seed generated title: %v", err)
	}
	return s, path
}

func TestStore_FlushGeneratedTitle_ReplacesAGeneratedTitle(t *testing.T) {
	s, path := generatedTitleStore(t, "first prompt")

	if _, _, err := s.FlushGeneratedTitle(t.Context(), "Model title"); err != nil {
		t.Fatalf("FlushGeneratedTitle over a generated title: %v", err)
	}
	if got := s.Title(); got != "Model title" {
		t.Fatalf("in-memory Title = %q, want %q", got, "Model title")
	}
	got := readBack(t, path).Metadata
	if got.Title != "Model title" || got.TitleSource != TitleSourceGenerated {
		t.Fatalf("persisted (title, source) = (%q, %q), want (%q, %q)", got.Title, got.TitleSource, "Model title", TitleSourceGenerated)
	}
}

func TestStore_FlushGeneratedTitle_NeverWritesOverUserSource(t *testing.T) {
	for name, title := range map[string]string{"user title": "manual", "empty title with user source": ""} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
			base := baseSession()
			base.Metadata.Title = title
			base.Metadata.TitleSource = TitleSourceUser
			s := New(path, base)

			if _, reason, err := s.FlushGeneratedTitle(t.Context(), "generated"); err != nil || reason != ReasonNone {
				t.Fatalf("FlushGeneratedTitle = (%q, %v), want the no-op success without a write", reason, err)
			}
			if got := s.Title(); got != title {
				t.Fatalf("Title = %q, want %q", got, title)
			}
		})
	}
}

func TestStore_FlushGeneratedTitle_FailureRestoresPreviousGeneratedTitle(t *testing.T) {
	wantMemory := func(t *testing.T, s *Store) {
		t.Helper()
		if got, src := s.Title(), s.session.Metadata.TitleSource; got != "first prompt" || src != TitleSourceGenerated {
			t.Fatalf("in-memory (title, source) = (%q, %q), want the previous generated title", got, src)
		}
	}

	t.Run("before publication", func(t *testing.T) {
		s, path := generatedTitleStore(t, "first prompt")
		t.Cleanup(fsutil.SetSyncFileForTest(func(*os.File) error { return syscall.EIO }))

		if _, _, err := s.FlushGeneratedTitle(t.Context(), "Model title"); err == nil {
			t.Fatal("FlushGeneratedTitle succeeded, want a write_error")
		}
		wantMemory(t, s)
		if got := readBack(t, path).Metadata; got.Title != "first prompt" || got.TitleSource != TitleSourceGenerated {
			t.Fatalf("persisted (title, source) = (%q, %q), want the previous generated title", got.Title, got.TitleSource)
		}
	})

	t.Run("after publication", func(t *testing.T) {
		s, _ := generatedTitleStore(t, "first prompt")
		failParentSync(t)

		if _, _, err := s.FlushGeneratedTitle(t.Context(), "Model title"); err == nil {
			t.Fatal("FlushGeneratedTitle succeeded, want a parent_dir_error")
		}
		wantMemory(t, s)
	})
}

func TestStore_FlushGeneratedTitle_WriteFailureRollsBackProvenance(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "no-such-subdir")
	path := filepath.Join(parent, "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "hello"))

	if _, _, err := s.FlushGeneratedTitle(context.Background(), "auto title"); err == nil {
		t.Fatal("FlushGeneratedTitle into missing parent succeeded, want error")
	}

	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent for recovery flush: %v", err)
	}
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("recovery Flush error: %v", err)
	}
	if got := readBack(t, path).Metadata.TitleSource; got != "" {
		t.Errorf("persisted title_source = %q after a rolled-back generated write, want empty", got)
	}
}

// TestStore_FlushGeneratedTitle_DoesNotOverwriteExistingTitle pins that a generated title
// never replaces a user or legacy title, and that the no-op path does not attempt a write.
func TestStore_FlushGeneratedTitle_DoesNotOverwriteExistingTitle(t *testing.T) {
	t.Run("persisted_manual_title_unchanged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.json")
		s := New(path, baseSession())
		if _, _, err := s.FlushTitle(context.Background(), "manual"); err != nil {
			t.Fatalf("FlushTitle to seed manual title: %v", err)
		}

		cat, reason, err := s.FlushGeneratedTitle(context.Background(), "generated")
		if err != nil {
			t.Fatalf("FlushGeneratedTitle over existing title errored: %v", err)
		}
		if cat != "" || reason != ReasonNone {
			t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone for the no-op path", cat, reason)
		}
		if got := readBack(t, path).Metadata.Title; got != "manual" {
			t.Fatalf("title = %q after generated-title no-op, want the manual title %q", got, "manual")
		}
	})

	t.Run("no_write_attempted_for_noop", func(t *testing.T) {
		// Missing parent: a real write would fail with ReasonParentDirError, so a clean
		// ReasonNone success proves the helper short-circuited before touching disk.
		path := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
		base := baseSession()
		base.Metadata.Title = "manual"
		s := New(path, base)

		cat, reason, err := s.FlushGeneratedTitle(context.Background(), "generated")
		if err != nil {
			t.Fatalf("FlushGeneratedTitle no-op attempted a write: %v", err)
		}
		if cat != "" || reason != ReasonNone {
			t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone for the no-op path", cat, reason)
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("session file exists after the no-op, want no write (stat err=%v)", statErr)
		}
	})
}

// TestStore_FlushGeneratedTitle_EmptyCandidateNoop pins the empty-candidate half of
// the no-op contract independently from the existing-title case: an empty generated
// title must short-circuit to the no-op success shape and never touch disk, even when
// the session still has no title of its own.
func TestStore_FlushGeneratedTitle_EmptyCandidateNoop(t *testing.T) {
	// Missing parent: a real write would fail with ReasonParentDirError, so a clean
	// ReasonNone success proves the helper short-circuited before touching disk. The
	// session keeps baseSession's empty title, isolating the title=="" guard.
	path := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
	s := New(path, baseSession())

	cat, reason, err := s.FlushGeneratedTitle(context.Background(), "")
	if err != nil {
		t.Fatalf("FlushGeneratedTitle with empty candidate attempted a write: %v", err)
	}
	if cat != "" || reason != ReasonNone {
		t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone for the empty-candidate no-op", cat, reason)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("session file exists after the empty-candidate no-op, want no write (stat err=%v)", statErr)
	}
}

// TestStore_FlushGeneratedTitle_WriteFailureRollsBackTitle pins that a failed
// generated-title write leaves no phantom in-memory title: the failure must restore
// the empty title and return the same category/WriteReason shape as Flush, so a later
// ordinary Flush persists a session that still omits the title.
func TestStore_FlushGeneratedTitle_WriteFailureRollsBackTitle(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "no-such-subdir")
	path := filepath.Join(parent, "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "hello"))

	cat, reason, err := s.FlushGeneratedTitle(context.Background(), "auto title")
	if err == nil {
		t.Fatalf("FlushGeneratedTitle into missing parent succeeded, want error")
	}
	if reason != ReasonParentDirError {
		t.Fatalf("reason = %q, want %q", reason, ReasonParentDirError)
	}
	if cat != fserrors.NotFound {
		t.Fatalf("cat = %q, want %q", cat, fserrors.NotFound)
	}

	// Recover the write path and flush ordinarily; the rolled-back title must leave the
	// persisted file with no `title` key.
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent for recovery flush: %v", err)
	}
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("recovery Flush error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recovered session file: %v", err)
	}
	if bytes.Contains(raw, []byte(`"title"`)) {
		t.Fatalf("persisted session carries a title key after a failed generated-title write:\n%s", raw)
	}
	if got := readBack(t, path).Metadata.Title; got != "" {
		t.Fatalf("persisted title = %q, want empty after rollback", got)
	}
}

func TestStore_FlushCancelledContext_NoWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "hello"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cat, reason, err := s.Flush(ctx)
	if err == nil {
		t.Fatalf("Flush with cancelled context succeeded, want error")
	}
	if cat != "" || reason != ReasonNone {
		t.Fatalf("cat=%q reason=%q, want empty cat and ReasonNone for a non-write failure", cat, reason)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("session file exists after cancelled flush, want no write (stat err=%v)", statErr)
	}
}

func TestStore_Path_ReturnsConstructionTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	if got := s.Path(); got != path {
		t.Fatalf("Path() = %q, want %q", got, path)
	}
}

func TestStore_SessionID_ReturnsMetadataID(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "session.json"), baseSession())
	if got := s.SessionID(); got != testMetaID {
		t.Fatalf("SessionID() = %q, want %q", got, testMetaID)
	}
}

func TestStore_MetadataSnapshot_CopiesIdentifyingMetadata(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "session.json"), baseSession())
	snap := s.MetadataSnapshot()
	if snap.ID != testMetaID {
		t.Fatalf("snapshot ID = %q, want %q", snap.ID, testMetaID)
	}
	if snap.Folder != "/home/u/proj" {
		t.Fatalf("snapshot Folder = %q, want %q", snap.Folder, "/home/u/proj")
	}
	if want := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC); !snap.StartedAt.Equal(want) {
		t.Fatalf("snapshot StartedAt = %v, want %v", snap.StartedAt, want)
	}
}

func TestStore_Close_BlocksFurtherAppends(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "session.json"), baseSession())
	s.Append(userMessage(testRecID1, "first"))

	s.Close()
	s.Append(userMessage(testRecID2, "after close"))

	recs := s.Records()
	if len(recs) != 1 {
		t.Fatalf("records after append-post-close = %d, want 1 (append ignored)", len(recs))
	}
	if got := recs[0].(Message).ID; got != testRecID1 {
		t.Fatalf("record 0 id = %q, want %q", got, testRecID1)
	}

	// Close is idempotent and a second close keeps the stream sealed.
	s.Close()
	s.Append(userMessage(testRecID3, "still ignored"))
	if got := len(s.Records()); got != 1 {
		t.Fatalf("records after second close = %d, want 1", got)
	}
}

// TestStore_Close_DoesNotBlockFlush pins the contract that Close seals only
// Appends: a record appended before Close still flushes durably afterward, so the
// fork/in-process-switch callers can persist a final record and then close.
func TestStore_Close_DoesNotBlockFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "kept"))

	s.Close()

	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("Flush after Close error: %v", err)
	}
	if got := len(readBack(t, path).Records); got != 1 {
		t.Fatalf("flushed records after close = %d, want 1", got)
	}
}

type probeContext struct {
	context.Context
	once sync.Once
	fn   func()
}

func (c *probeContext) Err() error {
	c.once.Do(c.fn)
	return c.Context.Err()
}

func TestStore_CommitRecords_KeepsTheBatchContiguousAndLeavesTheStoreOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "first"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("seed flush: %v", err)
	}

	ctx := &probeContext{Context: context.Background()}
	ctx.fn = func() { s.Append(userMessage(testRecID3, "competing")) }

	if _, _, err := s.CommitRecords(ctx,
		userMessage(testRecID2, "batch-a"), userMessage(markerRecID, "batch-b")); err != nil {
		t.Fatalf("CommitRecords error: %v", err)
	}

	persisted := readBack(t, path).Records
	if n := len(persisted); n < 2 || persisted[n-2].(Message).ID != testRecID2 || persisted[n-1].(Message).ID != markerRecID {
		t.Fatalf("persisted records = %v, want the ordered batch [%s %s] contiguous at the end", recIDs(persisted), testRecID2, markerRecID)
	}

	before := len(s.Records())
	s.Append(userMessage(laterRecID, "after"))
	if got := len(s.Records()); got != before+1 {
		t.Fatalf("records after a post-commit append = %d, want %d — CommitRecords must leave the store open", got, before+1)
	}
}

func TestStore_CommitRecords_RefusesAClosedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "first"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("seed flush: %v", err)
	}
	s.Close()

	if _, _, err := s.CommitRecords(context.Background(), userMessage(testRecID2, "batch-a")); err == nil {
		t.Fatal("CommitRecords on a closed store succeeded, want error")
	}
	if got := len(s.Records()); got != 1 {
		t.Fatalf("records after a refused commit = %d, want 1", got)
	}
	if persisted := readBack(t, path).Records; len(persisted) != 1 {
		t.Fatalf("persisted records = %v, want only the pre-close record", recIDs(persisted))
	}
}

func TestStore_CommitFinalRecords_SuccessSealsWithOrderedBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "first"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("seed flush: %v", err)
	}

	ctx := &probeContext{Context: context.Background()}
	ctx.fn = func() { s.Append(userMessage(testRecID3, "competing")) }

	if _, _, err := s.CommitFinalRecords(ctx,
		userMessage(testRecID2, "batch-a"), userMessage(markerRecID, "batch-b")); err != nil {
		t.Fatalf("CommitFinalRecords error: %v", err)
	}

	recs := s.Records()
	if n := len(recs); n < 2 || recs[n-2].(Message).ID != testRecID2 || recs[n-1].(Message).ID != markerRecID {
		t.Fatalf("final records = %v, want the ordered batch [%s %s] contiguous at the end", recIDs(recs), testRecID2, markerRecID)
	}
	before := len(recs)
	s.Append(userMessage(laterRecID, "after"))
	if got := len(s.Records()); got != before {
		t.Fatalf("records after a post-commit append = %d, want the store sealed at %d", got, before)
	}

	persisted := readBack(t, path).Records
	if len(persisted) != before {
		t.Fatalf("persisted records = %d, want %d", len(persisted), before)
	}
	if persisted[len(persisted)-2].(Message).ID != testRecID2 || persisted[len(persisted)-1].(Message).ID != markerRecID {
		t.Fatalf("last two persisted records = %v, want the ordered batch [%s %s]", recIDs(persisted), testRecID2, markerRecID)
	}
}

func TestStore_CommitFinalRecords_FailureRollsBackEntireBatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; write failure unobservable")
	}
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	s.Append(userMessage(testRecID1, "durable"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("seed flush: %v", err)
	}
	s.Append(userMessage(testRecID2, "undurable"))
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("seal session file read-only: %v", err)
	}

	ctx := &probeContext{Context: context.Background()}
	ctx.fn = func() { s.Append(userMessage(testRecID3, "competing")) }

	if _, _, err := s.CommitFinalRecords(ctx,
		userMessage(markerRecID, "batch-a"), userMessage(markerRecID2, "batch-b")); err == nil {
		t.Fatal("CommitFinalRecords into a read-only file succeeded, want error")
	}

	recs := s.Records()
	wantIDs := []string{testRecID1, testRecID2, testRecID3}
	if len(recs) != len(wantIDs) {
		t.Fatalf("records after a failed batch = %v, want %v (whole batch dropped, earlier records kept)", recIDs(recs), wantIDs)
	}
	for i, want := range wantIDs {
		if got := recs[i].(Message).ID; got != want {
			t.Fatalf("record %d id = %q, want %q", i, got, want)
		}
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restore session file write access: %v", err)
	}
	s.Append(userMessage(postFailRec, "later"))
	if _, _, err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush after restoring write access: %v", err)
	}
	wantPersisted := []string{testRecID1, testRecID2, testRecID3, postFailRec}
	persisted := readBack(t, path).Records
	if len(persisted) != len(wantPersisted) {
		t.Fatalf("persisted records = %v, want %v", recIDs(persisted), wantPersisted)
	}
	for i, want := range wantPersisted {
		if got := persisted[i].(Message).ID; got != want {
			t.Fatalf("persisted record %d id = %q, want %q (no rolled-back batch record may resurface)", i, got, want)
		}
	}
}

func recIDs(recs []Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		if m, ok := r.(Message); ok {
			out[i] = m.ID
		}
	}
	return out
}

func TestStore_RecordsReturnsCopy(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "session.json"), baseSession())
	s.Append(userMessage(testRecID1, "hello"))

	snap := s.Records()
	snap[0] = userMessage(testRecID2, "mutated")

	if got := s.Records()[0].(Message).ID; got != testRecID1 {
		t.Fatalf("mutating the snapshot changed the store: id = %q, want %q", got, testRecID1)
	}
}

func TestStore_NewMemoryOnly_FlushSucceedsWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	s := NewMemoryOnly()
	if s.Path() != "" {
		t.Fatalf("Path() = %q, want empty", s.Path())
	}
	if s.SessionID() == "" {
		t.Fatal("a memory-only store has no session id")
	}

	s.Append(userMessage(testRecID1, "first"))
	for i := 0; i < 2; i++ {
		if cat, reason, err := s.Flush(t.Context()); err != nil || reason != ReasonNone || cat != "" {
			t.Fatalf("flush %d: (%q, %q, %v), want a clean success", i+1, cat, reason, err)
		}
	}

	s.Append(userMessage(testRecID2, "second"))
	if _, _, err := s.Flush(t.Context()); err != nil {
		t.Fatalf("post-durable flush: %v", err)
	}
	if _, _, err := s.RefreshUpdatedAt(t.Context()); err != nil {
		t.Fatalf("RefreshUpdatedAt: %v", err)
	}
	if _, _, err := s.FlushTitle(t.Context(), "child"); err != nil {
		t.Fatalf("FlushTitle: %v", err)
	}

	if got := recIDs(s.Records()); len(got) != 2 || got[0] != testRecID1 || got[1] != testRecID2 {
		t.Fatalf("records = %v, want both appends readable in memory", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read working dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("a memory-only store wrote %d file(s): %v", len(entries), entries)
	}
}

func TestStore_EmptyPathFlush_StillFailsWithAWriteReason(t *testing.T) {
	t.Chdir(t.TempDir())

	s := New("", baseSession())
	s.Append(userMessage(testRecID1, "hello"))

	_, reason, err := s.Flush(t.Context())
	if err == nil {
		t.Fatal("an empty-path flush succeeded; resume and session-failure paths rely on its write failure")
	}
	if reason == ReasonNone {
		t.Fatalf("reason = %q, want a real write reason", reason)
	}
}

// TestCreateSessionFile_KeepsItsResultContractAfterThePublishAPIGainedAnIdentity pins the initial
// create's three-value result: the publish now also reports the inode it published, which session
// storage has no use for and must not surface.
func TestCreateSessionFile_KeepsItsResultContractAfterThePublishAPIGainedAnIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")

	step, cat, err := createSessionFile(path, []byte("{}\n"), sessionFileMode)
	if err != nil || step != "" || cat != "" {
		t.Fatalf("createSessionFile = (%q, %q, %v), want a clean create", step, cat, err)
	}
	info, serr := os.Stat(path)
	if serr != nil {
		t.Fatalf("stat session file: %v", serr)
	}
	if info.Mode().Perm() != sessionFileMode.Perm() {
		t.Fatalf("session file mode = %v, want %v", info.Mode().Perm(), sessionFileMode.Perm())
	}
	if got := string(mustRead(t, path)); got != "{}\n" {
		t.Fatalf("session file = %q, want the bytes it was given", got)
	}

	step, _, err = createSessionFile(path, []byte("second\n"), sessionFileMode)
	if err == nil {
		t.Fatal("createSessionFile overwrote an existing session file")
	}
	if step != fsutil.LinkStep {
		t.Fatalf("step = %q, want %q for a target that already exists", step, fsutil.LinkStep)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

var longRewriteTitle = strings.Repeat("a much longer title that grows the metadata line ", 6)

func failParentSync(t *testing.T) (restore func()) {
	t.Helper()
	restore = fsutil.SetSyncDirForTest(func(*os.File) error { return syscall.EIO })
	t.Cleanup(restore)
	return restore
}

func seededStore(t *testing.T, ids ...string) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.json")
	s := New(path, baseSession())
	for _, id := range ids {
		s.Append(userMessage(id, "seed"))
	}
	if _, _, err := s.Flush(t.Context()); err != nil {
		t.Fatalf("seed flush: %v", err)
	}
	return s, path
}

func messages(ids ...string) []Record {
	out := make([]Record, len(ids))
	for i, id := range ids {
		out[i] = userMessage(id, "batch")
	}
	return out
}

func wantDiskIDs(t *testing.T, path string, want ...string) {
	t.Helper()
	if got := recIDs(readBack(t, path).Records); !slices.Equal(got, want) {
		t.Fatalf("persisted records = %v, want %v", got, want)
	}
}

func wantMemoryIDs(t *testing.T, s *Store, want ...string) {
	t.Helper()
	if got := recIDs(s.Records()); !slices.Equal(got, want) {
		t.Fatalf("in-memory records = %v, want %v", got, want)
	}
}

func statFile(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info
}

type storeWrite func(*Store) (fserrors.Category, WriteReason, error)

func titleWriters(ctx context.Context) map[string]storeWrite {
	return map[string]storeWrite{
		"generated title": func(s *Store) (fserrors.Category, WriteReason, error) {
			return s.FlushGeneratedTitle(ctx, longRewriteTitle)
		},
		"user title": func(s *Store) (fserrors.Category, WriteReason, error) {
			return s.FlushTitle(ctx, longRewriteTitle)
		},
	}
}

func TestStore_PublishedTitleRewriteWithFailedParentSync_LaterAppendKeepsEveryRecord(t *testing.T) {
	for name, write := range titleWriters(context.Background()) {
		t.Run(name, func(t *testing.T) {
			s, path := seededStore(t, testRecID1, testRecID2)
			restore := failParentSync(t)

			_, reason, err := write(s)
			if err == nil || reason != ReasonParentDirError {
				t.Fatalf("title write = (%q, %v), want a reported parent_dir_error", reason, err)
			}
			if got := s.Title(); got != "" {
				t.Fatalf("in-memory title = %q, want the pre-call empty title restored", got)
			}
			if !bytes.Contains(mustRead(t, path), []byte(longRewriteTitle)) {
				t.Fatal("the longer title was not published; the regression needs a published rewrite")
			}

			restore()
			s.Append(userMessage(testRecID3, "after"))
			if _, _, err := s.Flush(t.Context()); err != nil {
				t.Fatalf("flush after restoring parent sync: %v", err)
			}
			wantDiskIDs(t, path, testRecID1, testRecID2, testRecID3)
		})
	}
}

func TestStore_FailedRewriteWithPendingRecords_KeepsEveryRecordExactlyOnce(t *testing.T) {
	writers := titleWriters(context.Background())
	writers["refresh"] = func(s *Store) (fserrors.Category, WriteReason, error) {
		return s.RefreshUpdatedAt(context.Background())
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			s, path := seededStore(t, testRecID1)
			s.Append(userMessage(testRecID2, "pending"))
			restore := failParentSync(t)

			if _, _, err := write(s); err == nil {
				t.Fatal("rewrite with failing parent sync succeeded, want error")
			}
			if s.durableRecords != 2 || s.durableBytes != int64(len(mustRead(t, path))) {
				t.Fatalf("bookkeeping = (%d records, %d bytes), want the published file's 2 records and its size",
					s.durableRecords, s.durableBytes)
			}
			if s.unverifiedRewrite || !s.rewriteUnsynced {
				t.Fatalf("flags = (unverified %v, unsynced %v), want only the durability obligation", s.unverifiedRewrite, s.rewriteUnsynced)
			}

			restore()
			s.Append(userMessage(testRecID3, "after"))
			if _, _, err := s.Flush(t.Context()); err != nil {
				t.Fatalf("flush after restoring parent sync: %v", err)
			}
			wantDiskIDs(t, path, testRecID1, testRecID2, testRecID3)
			if s.durableRecords != 3 || s.durableBytes != int64(len(mustRead(t, path))) || s.rewriteUnsynced {
				t.Fatalf("bookkeeping after recovery = (%d, %d, unsynced %v), want 3 records at file size and no obligation",
					s.durableRecords, s.durableBytes, s.rewriteUnsynced)
			}
		})
	}
}

func TestStore_UnconfirmedRewrite_NextWriteRewritesTheWholeFile(t *testing.T) {
	t.Run("mismatching read-back", func(t *testing.T) {
		s, path := seededStore(t, testRecID1)
		s.Append(userMessage(testRecID2, "pending"))
		restore := fsutil.SetSyncFileForTest(func(*os.File) error { return syscall.EIO })
		t.Cleanup(restore)

		if _, reason, err := s.FlushTitle(t.Context(), longRewriteTitle); err == nil || reason != ReasonWriteError {
			t.Fatalf("FlushTitle = (%q, %v), want a write_error", reason, err)
		}
		if !s.unverifiedRewrite || s.rewriteUnsynced || s.durableRecords != 1 {
			t.Fatalf("state = (unverified %v, unsynced %v, %d records), want only the unverified mark and unchanged bookkeeping",
				s.unverifiedRewrite, s.rewriteUnsynced, s.durableRecords)
		}
		wantDiskIDs(t, path, testRecID1)

		restore()
		before := statFile(t, path)
		s.Append(userMessage(testRecID3, "after"))
		if _, _, err := s.Flush(t.Context()); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if os.SameFile(before, statFile(t, path)) {
			t.Fatal("next flush appended in place, want a whole-file rewrite")
		}
		wantDiskIDs(t, path, testRecID1, testRecID2, testRecID3)
		if s.unverifiedRewrite {
			t.Fatal("unverified mark survived a successful rewrite")
		}
	})

	t.Run("unreadable read-back after a pre-publication parent error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root bypasses mode bits")
		}
		s, path := seededStore(t, testRecID1)
		s.Append(userMessage(testRecID2, "pending"))
		parent := filepath.Dir(path)
		if err := os.Chmod(parent, 0); err != nil {
			t.Fatalf("chmod parent: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

		if _, reason, err := s.RefreshUpdatedAt(t.Context()); err == nil || reason != ReasonParentDirError {
			t.Fatalf("RefreshUpdatedAt = (%q, %v), want a parent_dir_error", reason, err)
		}
		if !s.unverifiedRewrite || s.rewriteUnsynced || s.durableRecords != 1 {
			t.Fatalf("state = (unverified %v, unsynced %v, %d records), want only the unverified mark and unchanged bookkeeping",
				s.unverifiedRewrite, s.rewriteUnsynced, s.durableRecords)
		}

		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatalf("restore parent: %v", err)
		}
		before := statFile(t, path)
		if _, _, err := s.Flush(t.Context()); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if os.SameFile(before, statFile(t, path)) {
			t.Fatal("next flush appended in place, want a whole-file rewrite")
		}
		wantDiskIDs(t, path, testRecID1, testRecID2)
	})

	t.Run("equal read-back clears the unverified mark but not the durability obligation", func(t *testing.T) {
		s, path := seededStore(t, testRecID1)
		restoreFile := fsutil.SetSyncFileForTest(func(*os.File) error { return syscall.EIO })
		t.Cleanup(restoreFile)
		if _, _, err := s.FlushTitle(t.Context(), longRewriteTitle); err == nil {
			t.Fatal("FlushTitle succeeded, want a write_error")
		}
		restoreFile()

		restoreDir := failParentSync(t)
		if _, _, err := s.Flush(t.Context()); err == nil {
			t.Fatal("recovery flush with failing parent sync succeeded, want error")
		}
		if s.unverifiedRewrite || !s.rewriteUnsynced {
			t.Fatalf("flags = (unverified %v, unsynced %v), want the mark cleared and the obligation kept", s.unverifiedRewrite, s.rewriteUnsynced)
		}

		restoreDir()
		if _, _, err := s.Flush(t.Context()); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if s.unverifiedRewrite || s.rewriteUnsynced {
			t.Fatal("a successful rewrite left a recovery flag set")
		}
		wantDiskIDs(t, path, testRecID1)
	})

	t.Run("failed initial creation leaves no file and a later retry creates it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.json")
		s := New(path, baseSession())
		s.Append(userMessage(testRecID1, "first"))
		restore := failParentSync(t)

		if _, _, err := s.Flush(t.Context()); err == nil {
			t.Fatal("initial creation with failing parent sync succeeded, want error")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("failed initial creation left a target (stat err=%v)", err)
		}
		if s.fileWritten || s.unverifiedRewrite || s.rewriteUnsynced {
			t.Fatal("failed initial creation changed replacement-recovery state")
		}

		restore()
		if _, _, err := s.Flush(t.Context()); err != nil {
			t.Fatalf("retry: %v", err)
		}
		wantDiskIDs(t, path, testRecID1)
	})
}

func TestStore_UnsyncedPublishedRewrite_BlocksFlushAndCommitsUntilRecovered(t *testing.T) {
	failed := []string{markerRecID, markerRecID2}
	for name, retry := range map[string][]string{"same batch": failed, "different batch": {laterRecID}} {
		t.Run(name, func(t *testing.T) {
			s, path := seededStore(t, testRecID1)
			restore := failParentSync(t)
			if _, _, err := s.FlushTitle(t.Context(), longRewriteTitle); err == nil {
				t.Fatal("FlushTitle succeeded, want a parent_dir_error")
			}

			if _, reason, err := s.Flush(t.Context()); err == nil || reason != ReasonParentDirError {
				t.Fatalf("no-new-record Flush = (%q, %v), want the retried rewrite's parent_dir_error", reason, err)
			}
			if _, reason, err := s.CommitRecords(t.Context(), messages(failed...)...); err == nil || reason != ReasonParentDirError {
				t.Fatalf("CommitRecords = (%q, %v), want the preflight's parent_dir_error", reason, err)
			}
			if _, reason, err := s.CommitFinalRecords(t.Context(), messages(failed...)...); err == nil || reason != ReasonParentDirError {
				t.Fatalf("CommitFinalRecords = (%q, %v), want the preflight's parent_dir_error", reason, err)
			}
			if s.closed {
				t.Fatal("a failed final commit sealed the store")
			}
			wantMemoryIDs(t, s, testRecID1)
			wantDiskIDs(t, path, testRecID1)

			restore()
			if _, _, err := s.CommitRecords(t.Context(), messages(retry...)...); err != nil {
				t.Fatalf("retry commit: %v", err)
			}
			want := append([]string{testRecID1}, retry...)
			wantDiskIDs(t, path, want...)
			if s.rewriteUnsynced || s.unverifiedRewrite {
				t.Fatal("recovery rewrite left a recovery flag set")
			}

			if _, _, err := s.FlushTitle(t.Context(), "renamed"); err != nil {
				t.Fatalf("later title rewrite: %v", err)
			}
			if _, _, err := s.Flush(t.Context()); err != nil {
				t.Fatalf("later flush: %v", err)
			}
			wantDiskIDs(t, path, want...)
		})
	}
}

type commitFunc func(*Store, context.Context, ...Record) (fserrors.Category, WriteReason, error)

var commitMethods = map[string]commitFunc{
	"CommitRecords":      (*Store).CommitRecords,
	"CommitFinalRecords": (*Store).CommitFinalRecords,
}

type commitSetup func(t *testing.T) (s *Store, path string, prefix []string)

var commitSetups = map[string]commitSetup{
	"fresh store": func(t *testing.T) (*Store, string, []string) {
		path := filepath.Join(t.TempDir(), "session.json")
		return New(path, baseSession()), path, nil
	},
	"fresh store with pending records": func(t *testing.T) (*Store, string, []string) {
		path := filepath.Join(t.TempDir(), "session.json")
		s := New(path, baseSession())
		s.Append(userMessage(testRecID1, "pending"))
		return s, path, []string{testRecID1}
	},
	"metadata-only file": func(t *testing.T) (*Store, string, []string) {
		path := writeSessionFile(t, sessionJSONWithVersion("1"))
		sess, _, err := OpenSession(path)
		if err != nil {
			t.Fatalf("open metadata-only file: %v", err)
		}
		return New(path, sess), path, nil
	},
	"unterminated metadata-only file": func(t *testing.T) (*Store, string, []string) {
		s, path := unterminatedMetadataStore(t)
		return s, path, nil
	},
}

func unterminatedMetadataStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := writeSessionFile(t, strings.TrimSuffix(sessionJSONWithVersion("1"), "\n"))
	sess, _, err := OpenSession(path)
	if err != nil {
		t.Fatalf("open unterminated metadata-only file: %v", err)
	}
	return New(path, sess), path
}

func wantDiskMetadataID(t *testing.T, path string) {
	t.Helper()
	if got := readBack(t, path).Metadata.ID; got != testMetaID {
		t.Fatalf("persisted metadata id = %q, want %q", got, testMetaID)
	}
}

func TestStore_UnterminatedMetadataOnlyFile_AppendFlushKeepsMetadata(t *testing.T) {
	s, path := unterminatedMetadataStore(t)
	s.Append(userMessage(testRecID1, "first"))
	if _, _, err := s.Flush(t.Context()); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	wantDiskMetadataID(t, path)
	wantDiskIDs(t, path, testRecID1)

	s.Append(userMessage(testRecID2, "second"))
	if _, _, err := s.Flush(t.Context()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	wantDiskMetadataID(t, path)
	wantDiskIDs(t, path, testRecID1, testRecID2)
}

func TestStore_UnterminatedMetadataOnlyFile_FailedNormalizationBlocksCommitUntilRetried(t *testing.T) {
	for method, commit := range commitMethods {
		t.Run(method, func(t *testing.T) {
			s, path := unterminatedMetadataStore(t)
			restore := failParentSync(t)

			if _, reason, err := commit(s, t.Context(), messages(markerRecID, markerRecID2)...); err == nil || reason != ReasonParentDirError {
				t.Fatalf("%s = (%q, %v), want the normalization's parent_dir_error", method, reason, err)
			}
			if s.closed {
				t.Fatal("a failed normalization sealed the store")
			}
			wantMemoryIDs(t, s)
			wantDiskMetadataID(t, path)
			wantDiskIDs(t, path)

			restore()
			var published [][]byte
			t.Cleanup(fsutil.SetSyncDirForTest(func(f *os.File) error {
				if data, err := os.ReadFile(path); err == nil {
					published = append(published, data)
				}
				return f.Sync()
			}))
			if _, _, err := commit(s, t.Context(), messages(markerRecID, markerRecID2)...); err != nil {
				t.Fatalf("retry %s: %v", method, err)
			}
			for _, data := range published {
				if bytes.Contains(data, []byte(markerRecID)) {
					t.Fatalf("an atomic rewrite published the batch:\n%s", data)
				}
			}
			wantDiskMetadataID(t, path)
			wantDiskIDs(t, path, markerRecID, markerRecID2)
			if sealed := method == "CommitFinalRecords"; s.closed != sealed {
				t.Fatalf("closed = %v, want %v", s.closed, sealed)
			}
		})
	}
}

func TestStore_Commit_PersistsPendingRecordsBeforeAppendingTheBatch(t *testing.T) {
	setups := map[string]commitSetup{
		"persisted file with pending records": func(t *testing.T) (*Store, string, []string) {
			s, path := seededStore(t, testRecID1)
			s.Append(userMessage(testRecID2, "pending"))
			return s, path, []string{testRecID1, testRecID2}
		},
	}
	for name, setup := range commitSetups {
		setups[name] = setup
	}
	for method, commit := range commitMethods {
		for name, setup := range setups {
			t.Run(method+"/"+name, func(t *testing.T) {
				s, path, prefix := setup(t)
				var published [][]byte
				t.Cleanup(fsutil.SetSyncDirForTest(func(f *os.File) error {
					if data, err := os.ReadFile(path); err == nil {
						published = append(published, data)
					}
					return f.Sync()
				}))

				if _, _, err := commit(s, t.Context(), messages(markerRecID, markerRecID2)...); err != nil {
					t.Fatalf("%s: %v", method, err)
				}
				for _, data := range published {
					if bytes.Contains(data, []byte(markerRecID)) {
						t.Fatalf("an atomic rewrite published the batch:\n%s", data)
					}
				}
				wantDiskIDs(t, path, append(slices.Clone(prefix), markerRecID, markerRecID2)...)
				if sealed := method == "CommitFinalRecords"; s.closed != sealed {
					t.Fatalf("closed = %v, want %v", s.closed, sealed)
				}
			})
		}
	}
}

func TestStore_Commit_AppendFailureAfterPreflightRollsBackOnlyTheBatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses mode bits; append failure unobservable")
	}
	failed := []string{markerRecID, markerRecID2}
	for method, commit := range commitMethods {
		for name, setup := range commitSetups {
			for retryName, retry := range map[string][]string{"same batch": failed, "different batch": {laterRecID}} {
				t.Run(method+"/"+name+"/"+retryName, func(t *testing.T) {
					s, path, prefix := setup(t)
					if _, err := os.Stat(path); err == nil {
						if err := os.Chmod(path, 0o400); err != nil {
							t.Fatalf("seal file read-only: %v", err)
						}
					}
					restore := fsutil.SetSyncDirForTest(func(f *os.File) error {
						if err := os.Chmod(path, 0o400); err != nil {
							return err
						}
						return f.Sync()
					})
					t.Cleanup(restore)

					if _, _, err := commit(s, t.Context(), messages(failed...)...); err == nil {
						t.Fatalf("%s into a read-only file succeeded, want the batch append to fail", method)
					}
					if s.closed {
						t.Fatal("a failed batch append sealed the store")
					}
					wantMemoryIDs(t, s, prefix...)
					wantDiskIDs(t, path, prefix...)

					restore()
					if err := os.Chmod(path, 0o600); err != nil {
						t.Fatalf("restore write access: %v", err)
					}
					if _, _, err := commit(s, t.Context(), messages(retry...)...); err != nil {
						t.Fatalf("retry %s: %v", method, err)
					}
					want := append(slices.Clone(prefix), retry...)
					wantDiskIDs(t, path, want...)
					if sealed := method == "CommitFinalRecords"; s.closed != sealed {
						t.Fatalf("closed = %v, want %v", s.closed, sealed)
					}

					if _, _, err := s.FlushTitle(t.Context(), longRewriteTitle); err != nil {
						t.Fatalf("later title rewrite: %v", err)
					}
					if _, _, err := s.RefreshUpdatedAt(t.Context()); err != nil {
						t.Fatalf("later refresh: %v", err)
					}
					if _, _, err := s.Flush(t.Context()); err != nil {
						t.Fatalf("later flush: %v", err)
					}
					wantMemoryIDs(t, s, want...)
					wantDiskIDs(t, path, want...)
				})
			}
		}
	}
}

func TestStore_TitleSourceAndIsChild_ReadStoredMetadata(t *testing.T) {
	plain := New(filepath.Join(t.TempDir(), "session.json"), baseSession())
	if plain.TitleSource() != "" || plain.IsChild() {
		t.Fatalf("(TitleSource, IsChild) = (%q, %v), want (\"\", false)", plain.TitleSource(), plain.IsChild())
	}
	if _, _, err := plain.FlushGeneratedTitle(t.Context(), "auto"); err != nil {
		t.Fatalf("FlushGeneratedTitle: %v", err)
	}
	if got := plain.TitleSource(); got != TitleSourceGenerated {
		t.Fatalf("TitleSource = %q, want %q", got, TitleSourceGenerated)
	}

	base := baseSession()
	base.Metadata.ForkedFrom = &ForkOrigin{SessionID: testMetaID, RecordID: testRecID1}
	if !New("", base).IsChild() {
		t.Fatal("IsChild = false for a session with forked_from")
	}
}
