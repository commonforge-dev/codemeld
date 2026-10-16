// In-memory session record stream plus JSONL append and metadata rewrite flushing.
package sessions

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

// sessionFileMode is the permission mode for the session file. Session
// transcripts hold the user's conversation content and captured tool output, so
// they are owner-only, matching the 0600 posture of settings.yaml.
// Nothing fixes a mode for session files; 0600 is the conservative
// default.
const sessionFileMode os.FileMode = 0o600

// now is a test seam for the flush timestamp so updated_at advancement is
// observable without wall-clock sleeps; production callers see time.Now().
var now = func() time.Time { return time.Now().UTC() }

// WriteReason classifies why an atomic session flush failed, in the vocabulary
// shares with. ReasonNone covers both a successful flush and a
// flush that was never attempted (e.g. a cancelled context); the write-failure protocol builds a
// session_write_failed event only from the three failure reasons.
type WriteReason string

const (
	ReasonNone           WriteReason = "none"
	ReasonWriteError     WriteReason = "write_error"
	ReasonRenameError    WriteReason = "rename_error"
	ReasonParentDirError WriteReason = "parent_dir_error"
)

// reasonForStep maps the shared atomic-write helper's typed step to the runtime
// reason. The temp-file write step (which the helper also reports for create and
// temp-name failures) is write_error; the rename step is rename_error; the
// parent-directory step — covering a sessions directory removed mid-run — is
// parent_dir_error. The zero step value (success) yields ReasonNone.
func reasonForStep(step fsutil.AtomicWriteStep) WriteReason {
	switch step {
	case fsutil.WriteStep:
		return ReasonWriteError
	case fsutil.RenameStep, fsutil.LinkStep:
		return ReasonRenameError
	case fsutil.ParentSyncStep:
		return ReasonParentDirError
	default:
		return ReasonNone
	}
}

// Store owns the active session as the in-memory source of truth between flushes
// and writes it to a fixed path. Append and Flush are serialized by a
// single mutex; reads via Records take the same lock and return a copy, so a
// reader never races an in-progress Append or Flush. Session files are unlocked
// across processes; the mutex guards only intra-process access.
type Store struct {
	mu             sync.Mutex
	path           string
	session        *Session
	durableRecords int
	// durableBytes is the byte offset past which the file holds no complete record:
	// the end of its last complete JSONL line. Append flushes resume here, not at
	// physical EOF, so a torn final line recovered at load (completeJSONLLines drops
	// it in memory) is truncated away before the next append instead of being fused
	// onto the new record and corrupting the file (recovery).
	durableBytes      int64
	fileWritten       bool
	closed            bool
	memoryOnly        bool
	unverifiedRewrite bool
	rewriteUnsynced   bool
}

// New returns a Store that flushes session to path. The Store takes ownership of
// session and mutates it in place (appending records, refreshing updated_at). When
// path already names a regular file, New records the recovered durable byte
// boundary (the end of its last complete line) so the first append repairs any
// torn tail rather than writing after it; if the file cannot be read, it falls
// back to physical size so behavior matches a clean file. A file with no complete
// line, such as a bare unterminated metadata line, is rewritten whole before any
// append, since appending at offset 0 would erase that metadata.
func New(path string, session *Session) *Store {
	s := &Store{path: path, session: session}
	if path == "" {
		return s
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return s
	}
	s.fileWritten = true
	s.durableRecords = len(session.Records)
	s.durableBytes = info.Size()
	if data, rerr := os.ReadFile(path); rerr == nil {
		s.durableBytes = completeLineBoundary(data)
		s.unverifiedRewrite = s.durableBytes == 0
	}
	return s
}

// NewMemoryOnly returns a Store for a fresh session that is never written to disk:
// its flushes succeed while every record stays in memory. New("", session) is
// deliberately not this — its flushes fail on a real write, and the resume and
// session-failure paths depend on those failure reasons.
func NewMemoryOnly() *Store {
	return &Store{session: newSession("", now(), nil, "", nil), memoryOnly: true}
}

// Append adds a record to the in-memory stream. It does not flush; callers
// trigger durability at the points via Flush. Once the store is Closed
// the append is silently dropped, so a stream that has been forked away from (or
// otherwise switched out of) never gains further records.
func (s *Store) Append(rec Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.session.Records = append(s.session.Records, rec)
}

// CommitRecords appends recs and flushes them without releasing the store mutex in
// between, so no concurrent Append can land inside the batch and no concurrent Close can
// drop part of it while the flush still reports success. A closed store is an error rather
// than a silent drop, and a failed flush rolls the whole batch back.
func (s *Store) CommitRecords(ctx context.Context, recs ...Record) (cat fserrors.Category, reason WriteReason, err error) {
	if err := ctx.Err(); err != nil {
		return "", ReasonNone, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.commitLocked("CommitRecords", recs)
}

func (s *Store) CommitFinalRecords(ctx context.Context, recs ...Record) (cat fserrors.Category, reason WriteReason, err error) {
	if err := ctx.Err(); err != nil {
		return "", ReasonNone, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cat, reason, err = s.commitLocked("CommitFinalRecords", recs)
	if err != nil {
		return cat, reason, err
	}
	s.closed = true
	return "", ReasonNone, nil
}

func (s *Store) commitLocked(fn string, recs []Record) (fserrors.Category, WriteReason, error) {
	if s.closed {
		return "", ReasonNone, fmt.Errorf("sessions: %s on a closed store", fn)
	}
	if cat, reason, err := s.flushLocked(); err != nil {
		return cat, reason, err
	}
	staged := len(recs)
	s.session.Records = append(s.session.Records, recs...)
	cat, reason, err := s.flushLocked()
	if err != nil {
		s.session.Records = s.session.Records[:len(s.session.Records)-staged]
		return cat, reason, err
	}
	return "", ReasonNone, nil
}

// SessionID returns the session's UUIDv7 id from the in-memory metadata. It lets
// cross-package orchestration (the fork action) populate event payloads
// such as session_forked.to_session_id from the live store rather than parsing
// the id out of Path()'s file-name convention. The id is fixed at construction;
// the lock is taken only to share the mutex that guards the metadata struct
// against a concurrent Flush.
func (s *Store) SessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.Metadata.ID
}

// Title returns the session's current metadata title from memory. The value can
// change when the live session is renamed or generated-title persistence lands,
// so callers take the same lock that guards metadata writes.
func (s *Store) Title() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.Metadata.Title
}

func (s *Store) TitleSource() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.Metadata.TitleSource
}

func (s *Store) IsChild() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.Metadata.ForkedFrom != nil
}

// MetadataSnapshot is an immutable copy of a session's identifying metadata,
// taken at one instant. It lets in-memory readers (the /status overlay
// items 2-3, and the active-session references the production CommandHost / exit
// controller hold) report the session id, canonical folder, and start timestamp
// without reaching into the store's mutable Session struct or racing a Flush.
type MetadataSnapshot struct {
	ID        string
	Folder    string
	StartedAt time.Time
}

// MetadataSnapshot returns a copy of the session's identifying metadata under the
// same mutex that guards Append/Flush, so callers never observe a half-updated
// metadata struct. The values are fixed at construction (Flush only advances
// updated_at, which this snapshot does not expose), so the snapshot stays valid
// for the session's lifetime.
func (s *Store) MetadataSnapshot() MetadataSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return MetadataSnapshot{
		ID:        s.session.Metadata.ID,
		Folder:    s.session.Metadata.Folder,
		StartedAt: s.session.Metadata.StartedAt,
	}
}

// Close marks the store closed so no later Append mutates its record stream. The
// fork success path closes the original session once its final session_forked
// event is appended, and the in-process switch callers close the outgoing store
// after switching away. Close is idempotent and takes the same mutex
// as Append/Flush/Records. It does not flush and does not block Flush: a caller
// must durably persist any final record itself, and a post-Close Flush still
// writes the current in-memory stream — closing only refuses further Appends.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// Path returns the absolute path of the session file this store flushes to. It
// is fixed at construction and never mutated, so it needs no lock; cross-package
// failure handling uses it to name the target file in the
// session_write_failed event and the clean-shutdown OP_FAIL line without
// reaching into the store's mutable state.
func (s *Store) Path() string {
	return s.path
}

// Records returns a snapshot copy of the in-memory record stream, safe to read
// while other goroutines Append or Flush.
func (s *Store) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.session.Records))
	copy(out, s.session.Records)
	return out
}

// Flush persists new session records. The first write creates the JSONL file via
// the atomic temp+fsync+rename path; later writes append only the records not yet
// durably recorded and fsync before advancing the durable boundary. Normal record
// flushes do not rewrite metadata.updated_at; readers compute effective recency
// from metadata plus the last complete record timestamp.
func (s *Store) Flush(ctx context.Context) (cat fserrors.Category, reason WriteReason, err error) {
	if err := ctx.Err(); err != nil {
		return "", ReasonNone, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.flushLocked()
}

func (s *Store) flushLocked() (fserrors.Category, WriteReason, error) {
	if !s.fileWritten || s.unverifiedRewrite || s.rewriteUnsynced {
		return s.rewriteLocked()
	}
	if s.durableRecords == len(s.session.Records) {
		return "", ReasonNone, nil
	}
	data, err := marshalRecordLines(s.session.Records[s.durableRecords:], s.durableRecords)
	if err != nil {
		return fserrors.IOError, ReasonNone, err
	}
	cat, werr := appendFileSync(s.path, data, s.durableBytes)
	if werr != nil {
		return cat, ReasonWriteError, werr
	}
	s.durableRecords = len(s.session.Records)
	s.durableBytes += int64(len(data))
	return "", ReasonNone, nil
}

func (s *Store) rewriteLocked() (fserrors.Category, WriteReason, error) {
	if s.memoryOnly {
		return "", ReasonNone, nil
	}
	data, err := Marshal(s.session)
	if err != nil {
		return fserrors.IOError, ReasonNone, fmt.Errorf("marshal session: %w", err)
	}
	write := fsutil.WriteAtomic
	if !s.fileWritten {
		write = createSessionFile
	}
	step, cat, werr := write(s.path, data, sessionFileMode)
	if werr != nil {
		if s.fileWritten {
			s.reconcileFailedRewrite(data)
		}
		return cat, reasonForStep(step), werr
	}
	s.durableRecords = len(s.session.Records)
	s.durableBytes = int64(len(data))
	s.fileWritten = true
	s.unverifiedRewrite = false
	s.rewriteUnsynced = false
	return "", ReasonNone, nil
}

// reconcileFailedRewrite compares the live file by name with the intended bytes:
// WriteAtomic can fail after its rename published them, and no failure step proves
// whether that happened.
func (s *Store) reconcileFailedRewrite(data []byte) {
	live, err := os.ReadFile(s.path)
	if err != nil || !bytes.Equal(live, data) {
		s.unverifiedRewrite = true
		return
	}
	s.durableRecords = len(s.session.Records)
	s.durableBytes = completeLineBoundary(live)
	s.unverifiedRewrite = false
	s.rewriteUnsynced = true
}

// createSessionFile is the initial write's publish path: unlike WriteAtomic, whose
// parent-directory-sync failure can return an error after the target was renamed
// into place, a failed create leaves no session file behind — the guarantee a
// child session's first flush depends on.
func createSessionFile(targetPath string, data []byte, mode os.FileMode) (fsutil.AtomicWriteStep, fserrors.Category, error) {
	dirFD, openErr := os.Open(filepath.Dir(targetPath))
	if openErr != nil {
		return fsutil.ParentSyncStep, fserrors.CategorizeErrno(openErr), openErr
	}
	defer dirFD.Close() //nolint:errcheck // read-only descriptor opened only to publish into and fsync the parent dir
	step, cat, _, werr := fsutil.WriteAtomicCreateAt(dirFD, filepath.Base(targetPath), data, mode)
	return step, cat, werr
}

func marshalRecordLines(records []Record, offset int) ([]byte, error) {
	var out bytes.Buffer
	for i, rec := range records {
		line, err := marshalRecordLine(rec)
		if err != nil {
			return nil, fmt.Errorf("records[%d]: %w", offset+i, err)
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// appendFileSync appends data to path and fsyncs before returning. boundary is the
// store's durable byte offset (the end of the last complete record line); when the
// file on disk is longer, the excess is a torn final line recovered at load, so the
// file is truncated back to boundary before the append lands — otherwise O_APPEND
// would write after the half-written bytes and the next load would fail to parse.
// On any failure the file is rolled back to its pre-append size (boundary when a
// repair truncation occurred, else the original size) so a failed flush leaves no
// partial record behind.
func appendFileSync(path string, data []byte, boundary int64) (fserrors.Category, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, sessionFileMode)
	if err != nil {
		return fserrors.CategorizeErrno(err), err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fserrors.CategorizeErrno(err), err
	}
	rollbackSize := info.Size()
	if info.Size() > boundary {
		if terr := f.Truncate(boundary); terr != nil {
			_ = f.Close()
			return fserrors.CategorizeErrno(terr), terr
		}
		rollbackSize = boundary
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Truncate(rollbackSize)
		_ = f.Close()
		return fserrors.CategorizeErrno(err), err
	}
	if err := f.Sync(); err != nil {
		_ = f.Truncate(rollbackSize)
		_ = f.Close()
		return fserrors.CategorizeErrno(err), err
	}
	if err := f.Close(); err != nil {
		_ = os.Truncate(path, rollbackSize)
		return fserrors.CategorizeErrno(err), err
	}
	return "", nil
}

// RefreshUpdatedAt rewrites the metadata line with the current wall-clock time.
// It is used for explicit recency refreshes such as resume, not for normal record
// appends.
func (s *Store) RefreshUpdatedAt(ctx context.Context) (cat fserrors.Category, reason WriteReason, err error) {
	if err := ctx.Err(); err != nil {
		return "", ReasonNone, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session.Metadata.UpdatedAt = now()
	return s.rewriteLocked()
}

// FlushTitle sets the session's metadata.title in memory and writes the whole
// session atomically, but — unlike Flush — deliberately does NOT advance
// updated_at: a rename is metadata housekeeping, not session activity, matching
// SetTitle's contract so the retention clock and most-recent-first
// picker order are preserved. It is the active-session counterpart to the
// package-level SetTitle: the live store already owns the file (and, for a resumed
// session, already holds the sidecar lock), so routing the rename through the
// owning store avoids the self-contention a second SetTitle lock attempt would hit.
// Return shape matches Flush — ("", ReasonNone, nil) on success, otherwise the
// category, the mapped WriteReason, and the underlying error with the in-memory
// title restored to its pre-call value. If ctx is already cancelled, no write is
// attempted.
func (s *Store) FlushTitle(ctx context.Context, title string) (cat fserrors.Category, reason WriteReason, err error) {
	if err := ctx.Err(); err != nil {
		return "", ReasonNone, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	previousTitle := s.session.Metadata.Title
	previousSource := s.session.Metadata.TitleSource
	s.session.Metadata.Title = title
	s.session.Metadata.TitleSource = userTitleSource(title)
	cat, reason, err = s.rewriteLocked()
	if err != nil {
		s.session.Metadata.Title = previousTitle
		s.session.Metadata.TitleSource = previousSource
	}
	return cat, reason, err
}

// FlushGeneratedTitle persists an auto-generated title over an empty or generated
// title, never over a user or legacy one; an empty candidate is a no-op. Like
// FlushTitle it does not advance updated_at, and a write failure restores the previous
// title and source in memory. It does not tell a child session's derived title from any
// other generated title, so automatic callers must not call it for a child session.
func (s *Store) FlushGeneratedTitle(ctx context.Context, title string) (cat fserrors.Category, reason WriteReason, err error) {
	if err := ctx.Err(); err != nil {
		return "", ReasonNone, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	md := &s.session.Metadata
	if title == "" || md.TitleSource == TitleSourceUser || (md.Title != "" && md.TitleSource != TitleSourceGenerated) {
		return "", ReasonNone, nil
	}

	previousTitle, previousSource := md.Title, md.TitleSource
	md.Title = title
	md.TitleSource = TitleSourceGenerated
	cat, reason, err = s.rewriteLocked()
	if err != nil {
		md.Title = previousTitle
		md.TitleSource = previousSource
		return cat, reason, err
	}
	return "", ReasonNone, nil
}
