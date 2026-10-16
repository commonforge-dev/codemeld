// --resume no-id listing: enumerate resumable sessions for the current canonical
// folder and the tty/skipped-id preflight, as reusable sessions-package
// helpers (CLI/TUI wiring stays with later orchestration).
package sessions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
)

const (
	listTTYRequiredLine = "codemeld: session list: --resume without an id requires an interactive terminal"
	listSkippedHintLine = "codemeld: session list: run codemeld sessions doctor <id> to see why"
	listPressAnyKeyLine = "press any key to continue"
	listSkippedShown    = 5
)

// ListEntry is one resumable session surfaced by ListResumable. ID is the file's
// name stem (the handle codemeld --resume <id> resolves), which production stamps
// equal to metadata.id (a UUIDv7); Path is the absolute session-file path; Preview is the untruncated text
// of the first user message, which display surfaces bound themselves; StartedAt is
// metadata.started_at and UpdatedAt is the effective update time that drives the
// sort.
type ListEntry struct {
	ID        string
	Path      string
	Folder    string
	Title     string
	Preview   string
	StartedAt time.Time
	UpdatedAt time.Time
}

// Byte budgets for the bounded per-candidate scan. The forward scan reads a chunk
// at a time so it can stop at the first user message instead of always consuming
// its whole allowance. The tail window is always read at its cap, because a newer
// record can sit anywhere in it: append order does not imply timestamp order.
const (
	listForwardScanMax = 64 << 10
	listForwardChunk   = 8 << 10
	listTailScanMax    = 128 << 10
)

type SkippedID struct {
	ID string
}

// ResumeListEnumerateError reports: readdir on the current folder's session
// subdirectory failed for a reason other than absence (an absent subdirectory is a
// clean empty listing, not an error). Its Error() is the exact stderr line the
// caller prints before exiting 1; Category is drawn from the vocabulary.
type ResumeListEnumerateError struct {
	Subdir   string
	Category fserrors.Category
}

func (e *ResumeListEnumerateError) Error() string {
	return fmt.Sprintf("codemeld: session list: cannot enumerate %s: %s", e.Subdir, e.Category)
}

// ListResumable lists the resumable sessions in the per-folder subdirectory for the
// current canonical folder. It returns the survivors, the ids it
// skipped, and a typed enumeration error — it prints nothing and leaves the tty gate,
// skipped-id output, and listing to the caller (RunResumeListPreflight and later
// CLI/TUI orchestration).
//
// The subdirectory is SessionRoot(home)/<folder-dir> for CanonicalizeFolder(cwd); it
// is never created here, because a missing subdirectory must read as a clean empty
// listing. An absent subdirectory yields an empty result and a nil error; any other
// readdir failure yields a *ResumeListEnumerateError.
//
// Each non-directory <id>.json file is read in bounded slices instead of loaded
// whole: its metadata line, a forward budget ending at the first user message, and
// a tail window. Record-stream and event-payload validation deliberately do not run
// here — a session that fails them is listed and rejected at selection by
// ResolveResumeID, which can report the error against a named session. A candidate
// joins the skipped bucket, without surfacing its reason, only when its metadata
// line cannot be read or parsed, is refused on schema_version grounds, or names a
// folder the folder file does not match. Survivors are sorted by the later of
// metadata.updated_at and the newest record timestamp in the tail window,
// descending, ties broken by id (file stem) descending.
func ListResumable(home, cwd string) ([]ListEntry, []SkippedID, error) {
	canonical, err := CanonicalizeFolder(cwd)
	if err != nil {
		return nil, nil, fmt.Errorf("codemeld: session list: cannot resolve working directory %s: %w", cwd, err)
	}
	subdir := filepath.Join(SessionRoot(home), FolderDirName(canonical))

	list, skipped, rerr := scanFolderCandidates(subdir)
	if rerr != nil {
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, &ResumeListEnumerateError{Subdir: subdir, Category: fserrors.CategorizeErrno(rerr)}
	}
	slices.SortFunc(list, compareListEntries)
	return list, skipped, nil
}

func scanFolderCandidates(subdir string) ([]ListEntry, []SkippedID, error) {
	entries, err := os.ReadDir(subdir)
	if err != nil {
		return nil, nil, err
	}

	folderPath := filepath.Join(subdir, folderFileName)
	var list []ListEntry
	var skipped []SkippedID
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		path := filepath.Join(subdir, name)

		entry, serr := scanListEntry(id, path, folderPath)
		if serr != nil {
			skipped = append(skipped, SkippedID{ID: id})
			continue
		}
		list = append(list, entry)
	}
	return list, skipped, nil
}

func compareListEntries(a, b ListEntry) int {
	switch {
	case a.UpdatedAt.After(b.UpdatedAt):
		return -1
	case a.UpdatedAt.Before(b.UpdatedAt):
		return 1
	default:
		// Tie on updated_at: id (UUIDv7 in production) descending. strings.Compare
		// with the operands swapped yields the descending order.
		return strings.Compare(b.ID, a.ID)
	}
}

type ListAllSkip struct {
	Dir       string
	ID        string
	Folder    string
	Duplicate bool
}

func ListResumableAll(home string) ([]ListEntry, []ListAllSkip, error) {
	root := SessionRoot(home)
	dirs, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, &ResumeListEnumerateError{Subdir: root, Category: fserrors.CategorizeErrno(err)}
	}

	var merged []ListEntry
	var skips []ListAllSkip
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		subdir := filepath.Join(root, d.Name())
		recorded, present, ferr := readFolderFile(filepath.Join(subdir, folderFileName))
		if ferr != nil || !present {
			skips = append(skips, ListAllSkip{Dir: d.Name()})
			continue
		}
		list, skipped, rerr := scanFolderCandidates(subdir)
		if rerr != nil {
			skips = append(skips, ListAllSkip{Dir: d.Name()})
			continue
		}
		for _, s := range skipped {
			skips = append(skips, ListAllSkip{Dir: d.Name(), ID: s.ID, Folder: recorded})
		}
		merged = append(merged, list...)
	}

	winners := map[string]ListEntry{}
	for _, e := range merged {
		kept, seen := winners[e.ID]
		if !seen {
			winners[e.ID] = e
			continue
		}
		loser := e
		if preferListEntry(e, kept) {
			winners[e.ID], loser = e, kept
		}
		skips = append(skips, ListAllSkip{ID: loser.ID, Folder: loser.Folder, Duplicate: true})
	}
	result := slices.SortedFunc(maps.Values(winners), compareListEntries)
	return result, skips, nil
}

func preferListEntry(a, b ListEntry) bool {
	if !a.UpdatedAt.Equal(b.UpdatedAt) {
		return a.UpdatedAt.After(b.UpdatedAt)
	}
	if a.Folder != b.Folder {
		return a.Folder < b.Folder
	}
	return a.Path < b.Path
}

func scanListEntry(id, path, folderPath string) (ListEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return ListEntry{}, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return ListEntry{}, err
	}
	size := info.Size()

	metaLine, preview, err := scanForward(f)
	if err != nil {
		return ListEntry{}, err
	}
	if metaLine == nil {
		return ListEntry{}, fmt.Errorf("session %s must start with a metadata line", path)
	}

	raw, err := rawSchemaVersion(metaLine)
	if err != nil {
		return ListEntry{}, err
	}
	status, err := classifyVersion(raw, ReaderSupportedVersion)
	if err != nil {
		return ListEntry{}, err
	}
	if status == StatusNewer || status == StatusUnparseable {
		return ListEntry{}, fmt.Errorf("session %s has a %s schema_version", path, status)
	}
	meta, err := parseMetadataLine(metaLine)
	if err != nil {
		return ListEntry{}, err
	}
	if err := checkFolderFileMatch(id, folderPath, meta.Folder); err != nil {
		return ListEntry{}, err
	}

	updated := meta.UpdatedAt
	if ts, ok := newestTailTimestamp(f, size); ok && ts.After(updated) {
		updated = ts
	}
	return ListEntry{
		ID:        id,
		Path:      path,
		Folder:    meta.Folder,
		Title:     meta.Title,
		Preview:   preview,
		StartedAt: meta.StartedAt,
		UpdatedAt: updated,
	}, nil
}

// scanForward reads r a chunk at a time and returns as soon as the first user
// message completes, so a session whose prompt sits near the top costs one chunk
// rather than the whole forward budget. The metadata line is read to its newline
// even past that budget, because SetTitle accepts a title of any length and a
// first line cut mid-record would read as unparseable and drop an otherwise valid
// session; the budget still bounds the records after it. It returns a nil metadata
// line when r held nothing but whitespace, and an empty preview when the budget or
// EOF arrived first. Bytes after the last newline are dropped as a torn record,
// except when r held no newline at all and is therefore a bare metadata line — the
// completeJSONLLines rule the whole-file load path applies.
func scanForward(r io.Reader) ([]byte, string, error) {
	var buf, meta []byte
	haveMeta := false
	pos := 0
	for {
		start := len(buf)
		room := listForwardChunk
		if haveMeta {
			if start >= listForwardScanMax {
				break
			}
			room = min(listForwardChunk, listForwardScanMax-start)
		}
		buf = append(buf, make([]byte, room)...)
		n, rerr := io.ReadFull(r, buf[start:])
		buf = buf[:start+n]

		for {
			i := bytes.IndexByte(buf[pos:], '\n')
			if i < 0 {
				break
			}
			line := buf[pos : pos+i]
			pos += i + 1
			if !haveMeta {
				meta, haveMeta = line, true
				continue
			}
			if pos > listForwardScanMax {
				break
			}
			if text, isUser := userMessageText(line); isUser {
				return meta, text, nil
			}
		}

		if rerr != nil {
			if !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
				return nil, "", rerr
			}
			break
		}
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil, "", nil
	}
	if !haveMeta {
		meta = bytes.TrimRight(buf, "\r")
	}
	return meta, "", nil
}

// userMessageText reports the first user message as found even when its content is
// a list, so an image prompt yields an empty preview instead of the scan running on
// and borrowing a later message's text.
func userMessageText(line []byte) (string, bool) {
	var rec struct {
		Type    *string         `json:"type"`
		Role    *string         `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return "", false
	}
	if rec.Type == nil || *rec.Type != "message" || rec.Role == nil || *rec.Role != "user" {
		return "", false
	}
	var text string
	if json.Unmarshal(rec.Content, &text) != nil {
		return "", true
	}
	return text, true
}

// newestTailTimestamp reports the newest timestamp among every complete record in
// the capped tail window, not the newest in some smaller prefix of it: a record
// stamped later than the ones after it is still the session's effective update
// time. It reports false when the window yields no usable timestamp, leaving the
// caller on metadata.updated_at.
func newestTailTimestamp(f *os.File, size int64) (time.Time, bool) {
	window := min(size, int64(listTailScanMax))
	start, length := size-window, window
	if start > 0 {
		// Read one byte before the window so a record starting exactly on its
		// leading edge is not mistaken for the partial record dropped there.
		start, length = start-1, length+1
	}
	buf := make([]byte, length)
	n, _ := f.ReadAt(buf, start)
	return newestRecordTimestamp(buf[:n])
}

// newestRecordTimestamp treats bytes up to the first newline as a partial record
// and bytes after the last newline as the torn final line load itself drops; a
// complete line whose JSON or timestamp will not parse is ignored, not fatal.
func newestRecordTimestamp(window []byte) (time.Time, bool) {
	first := bytes.IndexByte(window, '\n')
	if first < 0 {
		return time.Time{}, false
	}
	rest := window[first+1:]
	last := bytes.LastIndexByte(rest, '\n')
	if last < 0 {
		return time.Time{}, false
	}
	var newest time.Time
	var found bool
	for _, line := range bytes.Split(rest[:last], []byte("\n")) {
		var rec struct {
			Timestamp *string `json:"timestamp"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.Timestamp == nil {
			continue
		}
		ts, terr := parseTimestamp(*rec.Timestamp)
		if terr != nil {
			continue
		}
		if !found || ts.After(newest) {
			newest, found = ts, true
		}
	}
	return newest, found
}

func RunResumeListPreflight(stdin io.Reader, stdinFd int, stderr io.Writer, stderrFd int, skipped []SkippedID, isTerminal func(fd int) bool, waitKey func(stdin io.Reader, stdinFd int)) (exitCode int) {
	if !isTerminal(stdinFd) || !isTerminal(stderrFd) {
		_, _ = io.WriteString(stderr, listTTYRequiredLine+"\n")
		return 1
	}
	if len(skipped) > 0 {
		noun := "sessions"
		if len(skipped) == 1 {
			noun = "session"
		}
		var b strings.Builder
		_, _ = fmt.Fprintf(&b, "codemeld: session list: %d %s could not be listed, e.g.:\n", len(skipped), noun)
		for _, s := range skipped[:min(len(skipped), listSkippedShown)] {
			_, _ = fmt.Fprintf(&b, "  %s\n", s.ID)
		}
		if more := len(skipped) - listSkippedShown; more > 0 {
			_, _ = fmt.Fprintf(&b, "  ... (%d more)\n", more)
		}
		b.WriteString(listSkippedHintLine + "\n")
		b.WriteString(listPressAnyKeyLine + "\n")
		_, _ = io.WriteString(stderr, b.String())
		waitKey(stdin, stdinFd)
	}
	return 0
}
