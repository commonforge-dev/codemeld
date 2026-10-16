// Tests for the --resume no-id listing: subdir enumeration, valid/invalid
// bucketing, the sort order, and the tty/skipped-id preflight.
package sessions

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
)

// listSessionDoc builds a structurally valid, schema_version-1 session with the
// given metadata.folder and updated_at (started_at is fixed; only updated_at drives
// the sort).
func listSessionDoc(folder, updatedAt string) string {
	return listDoc(folder, updatedAt, "")
}

// listDoc appends metaFields inside the metadata object (its leading comma is the
// caller's) and each record line verbatim, so a test can plant a deliberately
// corrupt record the codec would refuse to marshal.
func listDoc(folder, updatedAt, metaFields string, records ...string) string {
	doc := `{"type":"metadata","metadata":{"id":"` + testMetaID + `","folder":` + strconv.Quote(folder) +
		`,"started_at":"2026-05-25T12:00:00.000Z","updated_at":` + strconv.Quote(updatedAt) +
		`,"schema_version":1` + metaFields + `}}` + "\n"
	for _, rec := range records {
		doc += rec + "\n"
	}
	return doc
}

func listRecID(i int) string {
	return fmt.Sprintf("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f%04d", i)
}

func listMessageRecord(i int, role, ts, content string) string {
	return `{"type":"message","id":"` + listRecID(i) + `","role":"` + role +
		`","content":` + content + `,"timestamp":"` + ts + `"}`
}

func listEventRecord(i int, ts, kind, payload string) string {
	return `{"type":"event","id":"` + listRecID(i) + `","kind":"` + kind +
		`","timestamp":"` + ts + `","payload":` + payload + `}`
}

// listBulkRecords builds n assistant records whose combined size comfortably
// exceeds want bytes, so a fixture can push a planted record outside a bounded
// scan window.
func listBulkRecords(from, n int, ts string, want int) []string {
	body := strings.Repeat("y", want/n+64)
	out := make([]string, n)
	for i := range out {
		out[i] = listMessageRecord(from+i, "assistant", ts, strconv.Quote(body))
	}
	return out
}

// listNewerDoc builds a session whose schema_version (2) exceeds the reader's
// supported version, so OpenSession refuses it and the listing skips it.
func listNewerDoc(folder string) string {
	return `{"type":"metadata","metadata":{"id":"` + testMetaID + `","folder":` + strconv.Quote(folder) +
		`,"started_at":"2026-05-25T12:00:00.000Z","updated_at":"2026-05-25T12:00:00.000Z","schema_version":2}}` + "\n"
}

func entryIDs(entries []ListEntry) []string {
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	return ids
}

func skippedIDs(skips []SkippedID) []string {
	ids := make([]string, len(skips))
	for i, s := range skips {
		ids[i] = s.ID
	}
	return ids
}

// A missing per-folder subdirectory is a clean empty listing, not an error.
func TestListResumable_MissingSubdir(t *testing.T) {
	home, _, rawCWD, _, _ := resumeEnv(t)

	entries, skipped, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if len(entries) != 0 || len(skipped) != 0 {
		t.Fatalf("entries=%v skipped=%v, want both empty", entries, skipped)
	}
}

// An existing subdirectory with only the folder file (no session files) is empty.
func TestListResumable_EmptySubdir(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	entries, skipped, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if len(entries) != 0 || len(skipped) != 0 {
		t.Fatalf("entries=%v skipped=%v, want both empty", entries, skipped)
	}
}

// Valid candidates are returned sorted by updated_at descending; only a metadata
// failure (unparseable, version-refused, folder-mismatch) lands in the skipped
// bucket, without surfacing its reason. A record-stream violation and an event
// payload the load path rejects are no longer listing failures.
func TestListResumable_SortsValidAndBucketsInvalid(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	writeFile(t, filepath.Join(dir, "v1.json"), listSessionDoc(canonical, "2026-05-25T12:00:02.000Z"))
	writeFile(t, filepath.Join(dir, "v2.json"), listSessionDoc(canonical, "2026-05-25T12:00:01.000Z"))
	writeFile(t, filepath.Join(dir, "bad.json"), "this is not valid json")
	writeFile(t, filepath.Join(dir, "lone.json"), sessionDoc(canonical, loneToolRecord))
	writeFile(t, filepath.Join(dir, "payload.json"), sessionDoc(canonical, streamInterruptedRecord(`{"source":"bad"}`)))
	writeFile(t, filepath.Join(dir, "newer.json"), listNewerDoc(canonical))
	writeFile(t, filepath.Join(dir, "mismatch.json"), listSessionDoc("/elsewhere", "2026-05-25T12:00:03.000Z"))

	entries, skipped, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}

	// updated_at: v1 (T2) before v2 (T1), then the two T0 sessions by id descending.
	// The mismatch.json has the latest updated_at but is skipped, proving the sort
	// runs over survivors only.
	if got, want := entryIDs(entries), []string{"v1", "v2", "payload", "lone"}; !slicesEqual(got, want) {
		t.Errorf("entry ids = %v, want %v", got, want)
	}
	if want := filepath.Join(dir, "v1.json"); entries[0].Path != want {
		t.Errorf("entries[0].Path = %q, want %q", entries[0].Path, want)
	}
	if entries[0].Folder != canonical {
		t.Errorf("entries[0].Folder = %q, want %q", entries[0].Folder, canonical)
	}
	// Skipped ids are in os.ReadDir (filename) order.
	if got, want := skippedIDs(skipped), []string{"bad", "mismatch", "newer"}; !slicesEqual(got, want) {
		t.Errorf("skipped ids = %v, want %v", got, want)
	}
}

// A tie on updated_at is broken by id (file stem) descending.
func TestListResumable_TieBreakByIDDescending(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	writeFile(t, filepath.Join(dir, "aaa.json"), listSessionDoc(canonical, "2026-05-25T12:00:02.000Z"))
	writeFile(t, filepath.Join(dir, "bbb.json"), listSessionDoc(canonical, "2026-05-25T12:00:02.000Z"))
	writeFile(t, filepath.Join(dir, "ccc.json"), listSessionDoc(canonical, "2026-05-25T12:00:01.000Z"))

	entries, _, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if got, want := entryIDs(entries), []string{"bbb", "aaa", "ccc"}; !slicesEqual(got, want) {
		t.Errorf("entry ids = %v, want %v", got, want)
	}
}

// Records between the first user message and the tail window are never parsed:
// invalid JSON and an event payload the load path rejects sit there, yet the
// session lists with the right title, preview and updated_at.
func TestListResumable_ListsCorruptRecordsBetweenBoundedWindows(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	records := []string{
		listMessageRecord(1, "user", "2026-05-25T12:00:01.000Z", `"first prompt"`),
		`{"type":"message","id":"` + listRecID(2) + `","role":"user"`,
		listEventRecord(3, "2026-05-25T12:00:02.000Z", "stream_interrupted", `{"source":"bad"}`),
	}
	// Push the corrupt pair past the tail window so it is outside both bounded reads.
	records = append(records, listBulkRecords(10, 20, "2026-05-25T12:00:03.000Z", listTailScanMax)...)
	records = append(records, listMessageRecord(99, "assistant", "2026-05-25T12:00:04.000Z", `"done"`))
	doc := listDoc(canonical, "2026-05-25T12:00:00.000Z", `,"title":"kept","title_source":"user"`, records...)
	writeFile(t, filepath.Join(dir, "corrupt.json"), doc)

	entries, skipped, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none (a corrupt middle must not drop the row)", skippedIDs(skipped))
	}
	if got, want := entryIDs(entries), []string{"corrupt"}; !slicesEqual(got, want) {
		t.Fatalf("entry ids = %v, want %v", got, want)
	}
	if entries[0].Title != "kept" {
		t.Errorf("Title = %q, want %q", entries[0].Title, "kept")
	}
	if entries[0].Preview != "first prompt" {
		t.Errorf("Preview = %q, want %q", entries[0].Preview, "first prompt")
	}
	if want := mustTime(t, "2026-05-25T12:00:04.000Z"); !entries[0].UpdatedAt.Equal(want) {
		t.Errorf("UpdatedAt = %s, want %s", entries[0].UpdatedAt, want)
	}
}

// The effective updated_at is the newest timestamp among the tail window's complete
// records or metadata.updated_at, whichever is later — not the last record's
// timestamp and not the metadata value alone.
func TestListResumable_SortsByNewestTailTimestamp(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	writeFile(t, filepath.Join(dir, "lag.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z", "",
		listMessageRecord(1, "user", "2026-05-25T12:00:09.000Z", `"hi"`)))
	writeFile(t, filepath.Join(dir, "meta.json"), listSessionDoc(canonical, "2026-05-25T12:00:05.000Z"))
	writeFile(t, filepath.Join(dir, "unordered.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z", "",
		listMessageRecord(2, "user", "2026-05-25T12:00:20.000Z", `"hi"`),
		listMessageRecord(3, "assistant", "2026-05-25T12:00:02.000Z", `"reply"`)))

	entries, _, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if got, want := entryIDs(entries), []string{"unordered", "lag", "meta"}; !slicesEqual(got, want) {
		t.Fatalf("entry ids = %v, want %v", got, want)
	}
	for i, want := range []string{"2026-05-25T12:00:20.000Z", "2026-05-25T12:00:09.000Z", "2026-05-25T12:00:05.000Z"} {
		if ts := mustTime(t, want); !entries[i].UpdatedAt.Equal(ts) {
			t.Errorf("%s UpdatedAt = %s, want %s", entries[i].ID, entries[i].UpdatedAt, ts)
		}
	}
}

// A record beginning exactly on the tail window's leading edge is a complete record,
// not the partial one the scan drops there.
func TestListResumable_TailCountsRecordOnWindowBoundary(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	newest := listMessageRecord(1, "assistant", "2026-05-25T13:00:00.000Z", `"newest"`) + "\n"
	prefix := `{"type":"message","id":"` + listRecID(2) + `","role":"assistant","content":"`
	suffix := `","timestamp":"2026-05-25T12:00:01.000Z"}` + "\n"
	filler := prefix + strings.Repeat("x", listTailScanMax-len(newest)-len(prefix)-len(suffix)) + suffix

	// The head keeps the file larger than the cap, so newest begins exactly on the
	// window's leading edge instead of the window covering the whole file.
	head := listDoc(canonical, "2026-05-25T12:00:00.000Z", "",
		listMessageRecord(3, "user", "2026-05-25T12:00:00.000Z", `"hi"`))
	writeFile(t, filepath.Join(dir, "edge.json"), head+newest+filler)

	entries, _, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if want := mustTime(t, "2026-05-25T13:00:00.000Z"); !entries[0].UpdatedAt.Equal(want) {
		t.Errorf("UpdatedAt = %s, want %s (the boundary record was dropped)", entries[0].UpdatedAt, want)
	}
}

// With no usable timestamp in the capped tail window the entry keeps
// metadata.updated_at: malformed complete records are ignored, and a final record
// larger than the cap leaves the window without any complete record at all.
func TestListResumable_TailFallsBackToMetadataUpdatedAt(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	writeFile(t, filepath.Join(dir, "malformed.json"), listDoc(canonical, "2026-05-25T12:00:04.000Z", "",
		`{"type":"message","id":"`+listRecID(1)+`","role":"user","content":"hi","timestamp":"not-a-time"}`,
		`{"type":"event" this is not json`))
	writeFile(t, filepath.Join(dir, "oversized.json"), listDoc(canonical, "2026-05-25T12:00:07.000Z", "",
		listMessageRecord(2, "user", "2026-05-25T13:00:00.000Z", strconv.Quote(strings.Repeat("z", 2*listTailScanMax)))))

	entries, _, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	want := map[string]string{
		"malformed": "2026-05-25T12:00:04.000Z",
		"oversized": "2026-05-25T12:00:07.000Z",
	}
	if len(entries) != len(want) {
		t.Fatalf("entry ids = %v, want %d entries", entryIDs(entries), len(want))
	}
	for _, e := range entries {
		if ts := mustTime(t, want[e.ID]); !e.UpdatedAt.Equal(ts) {
			t.Errorf("%s UpdatedAt = %s, want metadata.updated_at %s", e.ID, e.UpdatedAt, ts)
		}
	}
}

// The tail scan inspects the whole capped window rather than returning from the
// first slice of it that holds a timestamp: a newer out-of-order record further
// from EOF still sets the effective updated_at.
func TestListResumable_TailScansThroughCapForOutOfOrderRecord(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	records := []string{
		listMessageRecord(1, "user", "2026-05-25T12:00:01.000Z", `"hi"`),
		listMessageRecord(2, "assistant", "2026-05-25T13:00:00.000Z", `"newest, written early"`),
	}
	// Enough filler to put the out-of-order record well beyond the last few KiB of
	// the file while keeping it inside the capped tail window.
	records = append(records, listBulkRecords(10, 20, "2026-05-25T12:00:02.000Z", listTailScanMax/4)...)
	records = append(records, listMessageRecord(99, "assistant", "2026-05-25T12:00:03.000Z", `"last"`))
	writeFile(t, filepath.Join(dir, "unordered.json"),
		listDoc(canonical, "2026-05-25T12:00:00.000Z", "", records...))

	entries, _, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if want := mustTime(t, "2026-05-25T13:00:00.000Z"); !entries[0].UpdatedAt.Equal(want) {
		t.Errorf("UpdatedAt = %s, want %s (the scan stopped before the cap)", entries[0].UpdatedAt, want)
	}
}

// A metadata line larger than the forward budget is still read to its newline, so
// a session whose user title outgrows the budget lists with that title instead of
// being skipped on an unparseable prefix.
func TestListResumable_OversizedMetadataLineStillLists(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	title := strings.Repeat("t", 2*listForwardScanMax)
	writeFile(t, filepath.Join(dir, "bigtitle.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z",
		`,"title":`+strconv.Quote(title)+`,"title_source":"user"`,
		listMessageRecord(1, "user", "2026-05-25T12:00:01.000Z", `"hi"`)))

	entries, skipped, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none (an oversized metadata line must not drop the row)", skippedIDs(skipped))
	}
	if got, want := entryIDs(entries), []string{"bigtitle"}; !slicesEqual(got, want) {
		t.Fatalf("entry ids = %v, want %v", got, want)
	}
	if entries[0].Title != title {
		t.Errorf("Title = %d chars, want the whole %d-char title", len(entries[0].Title), len(title))
	}
	if entries[0].Preview != "" {
		t.Errorf("Preview = %q, want empty: the metadata line spent the forward budget", entries[0].Preview)
	}
	if want := mustTime(t, "2026-05-25T12:00:01.000Z"); !entries[0].UpdatedAt.Equal(want) {
		t.Errorf("UpdatedAt = %s, want %s", entries[0].UpdatedAt, want)
	}
}

func TestListResumable_ExposesTheStoredTitleForEveryProvenance(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	writeFile(t, filepath.Join(dir, "user.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z",
		`,"title":"chosen","title_source":"user"`))
	writeFile(t, filepath.Join(dir, "generated.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z",
		`,"title":"auto","title_source":"generated"`))
	writeFile(t, filepath.Join(dir, "nosource.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z",
		`,"title":"orphan"`))
	writeFile(t, filepath.Join(dir, "unknown.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z",
		`,"title":"imported","title_source":"elsewhere"`))

	entries, _, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	want := map[string]string{"user": "chosen", "generated": "auto", "nosource": "orphan", "unknown": "imported"}
	if len(entries) != len(want) {
		t.Fatalf("entry ids = %v, want %d entries", entryIDs(entries), len(want))
	}
	for _, e := range entries {
		if e.Title != want[e.ID] {
			t.Errorf("%s Title = %q, want %q", e.ID, e.Title, want[e.ID])
		}
	}
}

// The preview comes from the literal first user message: list content yields an
// empty preview even when a later user message is plain text, a session with no
// user message still lists, and a first user message past the forward budget
// empties the preview rather than dropping the row.
func TestListResumable_PreviewFromFirstUserMessage(t *testing.T) {
	home, root, rawCWD, canonical, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	writeFile(t, filepath.Join(dir, folderFileName), canonical+"\n")

	writeFile(t, filepath.Join(dir, "text.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z", "",
		listMessageRecord(1, "user", "2026-05-25T12:00:01.000Z", `"plain prompt"`)))
	writeFile(t, filepath.Join(dir, "list.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z", "",
		listMessageRecord(2, "user", "2026-05-25T12:00:01.000Z", `[{"type":"image_url","image_url":{"url":"data:x"}}]`),
		listMessageRecord(3, "user", "2026-05-25T12:00:02.000Z", `"later text"`)))
	writeFile(t, filepath.Join(dir, "nouser.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z", "",
		listMessageRecord(4, "assistant", "2026-05-25T12:00:01.000Z", `"only me"`)))
	overBudget := append(
		listBulkRecords(10, 20, "2026-05-25T12:00:01.000Z", listForwardScanMax),
		listMessageRecord(99, "user", "2026-05-25T12:00:02.000Z", `"too late"`))
	writeFile(t, filepath.Join(dir, "budget.json"), listDoc(canonical, "2026-05-25T12:00:00.000Z", "", overBudget...))

	entries, _, err := ListResumable(home, rawCWD)
	if err != nil {
		t.Fatalf("ListResumable() error = %v", err)
	}
	want := map[string]string{"text": "plain prompt", "list": "", "nouser": "", "budget": ""}
	if len(entries) != len(want) {
		t.Fatalf("entry ids = %v, want %d entries", entryIDs(entries), len(want))
	}
	for _, e := range entries {
		if e.Preview != want[e.ID] {
			t.Errorf("%s Preview = %q, want %q", e.ID, e.Preview, want[e.ID])
		}
	}
}

type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

// The forward scan stops consuming the file at the first user message: a session
// whose prompt sits near the top costs one chunk however large the rest of the file
// is, and one with no user message at all stops at the forward budget.
func TestScanForward_StopsConsumingAtFirstUserMessage(t *testing.T) {
	bulk := listBulkRecords(10, 20, "2026-05-25T12:00:02.000Z", 4*listForwardScanMax)

	t.Run("stops at the first user message", func(t *testing.T) {
		prompt := listMessageRecord(1, "user", "2026-05-25T12:00:01.000Z", `"plain prompt"`)
		doc := listDoc("/w", "2026-05-25T12:00:00.000Z", "", append([]string{prompt}, bulk...)...)
		r := &countingReader{r: strings.NewReader(doc)}

		meta, preview, err := scanForward(r)
		if err != nil {
			t.Fatalf("scanForward() error = %v", err)
		}
		if preview != "plain prompt" {
			t.Errorf("preview = %q, want %q", preview, "plain prompt")
		}
		if !bytes.Contains(meta, []byte(`"type":"metadata"`)) {
			t.Errorf("metadata line = %q, want the metadata record", meta)
		}
		promptEnd := strings.Index(doc, prompt) + len(prompt) + 1
		if want := promptEnd + listForwardChunk; r.read > want {
			t.Errorf("consumed %d bytes past the first user message (%d), want at most %d", r.read, promptEnd, want)
		}
		if r.read >= len(doc) {
			t.Errorf("consumed %d bytes of a %d-byte session, want a bounded prefix", r.read, len(doc))
		}
	})

	t.Run("stops at the forward budget", func(t *testing.T) {
		doc := listDoc("/w", "2026-05-25T12:00:00.000Z", "", bulk...)
		r := &countingReader{r: strings.NewReader(doc)}

		meta, preview, err := scanForward(r)
		if err != nil {
			t.Fatalf("scanForward() error = %v", err)
		}
		if preview != "" {
			t.Errorf("preview = %q, want empty", preview)
		}
		if !bytes.Contains(meta, []byte(`"type":"metadata"`)) {
			t.Errorf("metadata line = %q, want the metadata record", meta)
		}
		if r.read > listForwardScanMax {
			t.Errorf("consumed %d bytes, want at most the %d-byte forward budget", r.read, listForwardScanMax)
		}
	})
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := parseTimestamp(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

// A non-ENOENT readdir failure on the subdirectory yields a typed enumeration error
// carrying the exact stderr line and a category.
func TestListResumable_EnumerateError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	home, root, rawCWD, _, folderDir := resumeEnv(t)
	dir := mkdir(t, filepath.Join(root, folderDir))
	// Execute-only: the subdirectory is listed by its parent but its own readdir
	// fails with EACCES.
	if err := os.Chmod(dir, 0o111); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	_, _, err := ListResumable(home, rawCWD)
	var ee *ResumeListEnumerateError
	if !errors.As(err, &ee) {
		t.Fatalf("error %v is not a *ResumeListEnumerateError", err)
	}
	if ee.Category != fserrors.PermissionDenied {
		t.Errorf("Category = %q, want %q", ee.Category, fserrors.PermissionDenied)
	}
	want := "codemeld: session list: cannot enumerate " + dir + ": permission_denied"
	if err.Error() != want {
		t.Errorf("Error() = %q\nwant %q", err.Error(), want)
	}
}

func listFolder(t *testing.T, root, dirName, folder string) string {
	t.Helper()
	dir := mkdir(t, filepath.Join(root, dirName))
	writeFile(t, filepath.Join(dir, folderFileName), folder+"\n")
	return dir
}

func TestListResumableAll_MissingRoot(t *testing.T) {
	entries, skips, err := ListResumableAll(t.TempDir())
	if err != nil || len(entries) != 0 || len(skips) != 0 {
		t.Fatalf("entries=%v skips=%v err=%v, want all empty", entries, skips, err)
	}
}

func TestListResumableAll_RootEnumerateError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	home := t.TempDir()
	root := mkdir(t, SessionRoot(home))
	if err := os.Chmod(root, 0o111); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	_, _, err := ListResumableAll(home)
	var ee *ResumeListEnumerateError
	if !errors.As(err, &ee) {
		t.Fatalf("error %v is not a *ResumeListEnumerateError", err)
	}
	if ee.Subdir != root || ee.Category != fserrors.PermissionDenied {
		t.Errorf("error = %+v, want Subdir %q and %q", ee, root, fserrors.PermissionDenied)
	}
}

func TestListResumableAll_MergesDeduplicatesAndSkips(t *testing.T) {
	home := t.TempDir()
	root := mkdir(t, SessionRoot(home))
	writeFile(t, filepath.Join(root, "stray.json"), "not a folder")

	b := listFolder(t, root, "aaa-b", "/proj/b")
	a := listFolder(t, root, "zzz-a", "/proj/a")
	c1 := listFolder(t, root, "ccc-1", "/proj/c")
	c2 := listFolder(t, root, "ccc-2", "/proj/c")
	mkdir(t, filepath.Join(root, "no-folder-file"))
	empty := mkdir(t, filepath.Join(root, "empty-folder-file"))
	writeFile(t, filepath.Join(empty, folderFileName), " \n")

	writeFile(t, filepath.Join(a, "a1.json"), listSessionDoc("/proj/a", "2026-05-25T12:00:01.000Z"))
	writeFile(t, filepath.Join(b, "b1.json"), listSessionDoc("/proj/b", "2026-05-25T12:00:03.000Z"))
	writeFile(t, filepath.Join(a, "a2.json"), listSessionDoc("/proj/a", "2026-05-25T12:00:05.000Z"))
	writeFile(t, filepath.Join(b, "bad.json"), "not json")

	writeFile(t, filepath.Join(b, "newer.json"), listSessionDoc("/proj/b", "2026-05-25T12:00:02.000Z"))
	writeFile(t, filepath.Join(a, "newer.json"), listSessionDoc("/proj/a", "2026-05-25T12:00:04.000Z"))
	writeFile(t, filepath.Join(b, "tie.json"), listSessionDoc("/proj/b", "2026-05-25T12:00:00.000Z"))
	writeFile(t, filepath.Join(a, "tie.json"), listSessionDoc("/proj/a", "2026-05-25T12:00:00.000Z"))
	writeFile(t, filepath.Join(c2, "same.json"), listSessionDoc("/proj/c", "2026-05-25T11:00:00.000Z"))
	writeFile(t, filepath.Join(c1, "same.json"), listSessionDoc("/proj/c", "2026-05-25T11:00:00.000Z"))

	entries, skips, err := ListResumableAll(home)
	if err != nil {
		t.Fatalf("ListResumableAll() error = %v", err)
	}
	if got, want := entryIDs(entries), []string{"a2", "newer", "b1", "a1", "tie", "same"}; !slicesEqual(got, want) {
		t.Fatalf("entry ids = %v, want %v", got, want)
	}
	wantFolder := map[string]string{"a2": "/proj/a", "newer": "/proj/a", "b1": "/proj/b", "a1": "/proj/a", "tie": "/proj/a", "same": "/proj/c"}
	for _, e := range entries {
		if e.Folder != wantFolder[e.ID] {
			t.Errorf("%s Folder = %q, want %q", e.ID, e.Folder, wantFolder[e.ID])
		}
	}
	if want := filepath.Join(c1, "same.json"); entries[5].Path != want {
		t.Errorf("same Path = %q, want %q", entries[5].Path, want)
	}

	want := []ListAllSkip{
		{Dir: "aaa-b", ID: "bad", Folder: "/proj/b"},
		{Dir: "empty-folder-file"},
		{Dir: "no-folder-file"},
		{ID: "same", Folder: "/proj/c", Duplicate: true},
		{ID: "newer", Folder: "/proj/b", Duplicate: true},
		{ID: "tie", Folder: "/proj/b", Duplicate: true},
	}
	if fmt.Sprint(skips) != fmt.Sprint(want) {
		t.Errorf("skips = %+v\nwant %+v", skips, want)
	}
}

func TestListResumableAll_UnreadableFolderIsSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("readdir permission failure is not reproducible as root")
	}
	home := t.TempDir()
	root := mkdir(t, SessionRoot(home))
	ok := listFolder(t, root, "ok", "/proj/ok")
	writeFile(t, filepath.Join(ok, "s1.json"), listSessionDoc("/proj/ok", "2026-05-25T12:00:00.000Z"))
	locked := listFolder(t, root, "locked", "/proj/locked")
	writeFile(t, filepath.Join(locked, "s2.json"), listSessionDoc("/proj/locked", "2026-05-25T12:00:00.000Z"))
	if err := os.Chmod(locked, 0o111); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	unreadable := listFolder(t, root, "unreadable-folder-file", "/proj/u")
	if err := os.Chmod(filepath.Join(unreadable, folderFileName), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	entries, skips, err := ListResumableAll(home)
	if err != nil {
		t.Fatalf("ListResumableAll() error = %v", err)
	}
	if got, want := entryIDs(entries), []string{"s1"}; !slicesEqual(got, want) {
		t.Errorf("entry ids = %v, want %v", got, want)
	}
	want := []ListAllSkip{{Dir: "locked"}, {Dir: "unreadable-folder-file"}}
	if fmt.Sprint(skips) != fmt.Sprint(want) {
		t.Errorf("skips = %+v, want %+v", skips, want)
	}
}

func readOneKey(calls *int) func(io.Reader, int) {
	return func(stdin io.Reader, _ int) {
		*calls++
		var buf [1]byte
		_, _ = stdin.Read(buf[:])
	}
}

func TestRunResumeListPreflight_TTYRequired(t *testing.T) {
	tests := []struct {
		name     string
		stdinFd  int
		stderrFd int
		ttyFd    int
	}{
		{"stdin not a tty", 0, 2, 2},
		{"stderr not a tty", 0, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			var waits int
			stdin := strings.NewReader("x")
			isTTY := func(fd int) bool { return fd == tt.ttyFd }
			code := RunResumeListPreflight(stdin, tt.stdinFd, &stderr, tt.stderrFd, []SkippedID{{ID: "alpha"}}, isTTY, readOneKey(&waits))
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if got, want := stderr.String(), listTTYRequiredLine+"\n"; got != want {
				t.Errorf("stderr = %q, want %q", got, want)
			}
			if waits != 0 || stdin.Len() != 1 {
				t.Errorf("key wait ran %d times with %d bytes left; want 0 waits and 1 byte", waits, stdin.Len())
			}
		})
	}
}

func numberedSkips(n int) []SkippedID {
	out := make([]SkippedID, n)
	for i := range out {
		out[i] = SkippedID{ID: fmt.Sprintf("id%03d", i)}
	}
	return out
}

func TestRunResumeListPreflight_CondensedSkippedBlock(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want []string
	}{
		{"one", 1, []string{
			"codemeld: session list: 1 session could not be listed, e.g.:",
			"  id000",
		}},
		{"five", 5, []string{
			"codemeld: session list: 5 sessions could not be listed, e.g.:",
			"  id000", "  id001", "  id002", "  id003", "  id004",
		}},
		{"many", 413, []string{
			"codemeld: session list: 413 sessions could not be listed, e.g.:",
			"  id000", "  id001", "  id002", "  id003", "  id004",
			"  ... (408 more)",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			var waits int
			stdin := strings.NewReader("xy")
			code := RunResumeListPreflight(stdin, 0, &stderr, 2, numberedSkips(tt.n), func(int) bool { return true }, readOneKey(&waits))
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			want := strings.Join(append(tt.want,
				"codemeld: session list: run codemeld sessions doctor <id> to see why",
				"press any key to continue"), "\n") + "\n"
			if stderr.String() != want {
				t.Errorf("stderr = %q\nwant %q", stderr.String(), want)
			}
			if waits != 1 || stdin.Len() != 1 {
				t.Errorf("key wait ran %d times with %d bytes left; want 1 wait and 1 byte", waits, stdin.Len())
			}
		})
	}
}

func TestRunResumeListPreflight_NoSkipNoPrompt(t *testing.T) {
	var stderr bytes.Buffer
	var waits int
	stdin := strings.NewReader("x")
	code := RunResumeListPreflight(stdin, 0, &stderr, 2, nil, func(int) bool { return true }, readOneKey(&waits))
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	if waits != 0 || stdin.Len() != 1 {
		t.Errorf("key wait ran %d times with %d bytes left; want 0 waits and 1 byte", waits, stdin.Len())
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
