// Tests for the pre-turn boundary: append-then-flush-then-dispatch
// ordering, atomic vs non-atomic flush-failure routing, and retry idempotence.
package sessionturn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

// fakeUI records the one-line notices the helper renders so tests can assert
// which failures surface to the user.
type fakeUI struct{ notices []string }

func (f *fakeUI) Notice(text string) { f.notices = append(f.notices, text) }

// newStore returns a Store with a valid session header that flushes to path.
func newStore(path string) *sessions.Store {
	return sessions.New(path, &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
	})
}

func countUserMessages(recs []sessions.Record) int {
	n := 0
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "user" {
			n++
		}
	}
	return n
}

func countWriteFailedEvents(recs []sessions.Record) int {
	n := 0
	for _, r := range recs {
		if e, ok := r.(sessions.Event); ok && e.Kind == events.KindSessionWriteFailed {
			n++
		}
	}
	return n
}

// soleUserMessage returns the single role:"user" record, failing if there is not
// exactly one. Used to inspect the appended message's fields directly rather than
// scanning raw JSON.
func soleUserMessage(t *testing.T, recs []sessions.Record) sessions.Message {
	t.Helper()
	var found []sessions.Message
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "user" {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("user messages = %d, want exactly 1", len(found))
	}
	return found[0]
}

// assertUserMessageFields checks the fields the helper must set on the
// appended user message: a valid UUIDv7 id, role "user", the exact input text,
// and a non-zero UTC timestamp. A substring scan would miss a dropped id or a
// zero/non-UTC timestamp; this does not.
func assertUserMessageFields(t *testing.T, m sessions.Message, want string) {
	t.Helper()
	if !ids.IsValidV7(m.ID) {
		t.Fatalf("message id %q is not a valid UUIDv7", m.ID)
	}
	if m.Role != "user" {
		t.Fatalf("message role = %q, want \"user\"", m.Role)
	}
	if m.Content.IsList() {
		t.Fatal("message content is a list, want string content")
	}
	if got := m.Content.Text(); got != want {
		t.Fatalf("message text = %q, want %q", got, want)
	}
	if m.Timestamp.IsZero() {
		t.Fatal("message timestamp is the zero value")
	}
	if m.Timestamp.Location() != time.UTC {
		t.Fatalf("message timestamp location = %v, want UTC", m.Timestamp.Location())
	}
}

// Clean path: the user message is appended and durably flushed to disk before
// dispatch runs, and dispatch is called exactly once.
func TestPersistUserInputThenIssue_CleanPathDurableBeforeDispatch(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	ui := &fakeUI{}
	p := New(store, ui)

	const input = "hello model"
	dispatched := 0
	dispatch := func(time.Time) error {
		dispatched++
		// durability happens before dispatch — the session file must
		// already hold the user message at the moment dispatch runs.
		data, err := os.ReadFile(sessionPath)
		if err != nil {
			t.Fatalf("session file not on disk at dispatch time: %v", err)
		}
		if !strings.Contains(string(data), `"role":"user"`) || !strings.Contains(string(data), input) {
			t.Fatalf("user message not persisted before dispatch:\n%s", data)
		}
		return nil
	}

	if err := p.PersistUserInputThenIssue(context.Background(), input, nil, dispatch); err != nil {
		t.Fatalf("PersistUserInputThenIssue() error = %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("dispatch called %d times, want 1", dispatched)
	}
	if p.pending {
		t.Fatal("pending still set after a successful flush")
	}
	if len(ui.notices) != 0 {
		t.Fatalf("notices on a clean path = %v, want none", ui.notices)
	}

	// The appended in-memory record must carry the full user-message
	// fields, not merely a role:"user" tag — a dropped UUIDv7 id or a zero/non-UTC
	// timestamp must fail here.
	assertUserMessageFields(t, soleUserMessage(t, store.Records()), input)

	// Independent disk read-back parsed through the session codec (not a substring
	// scan), so a malformed persisted id or timestamp is caught too.
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	sess, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse persisted session: %v", err)
	}
	assertUserMessageFields(t, soleUserMessage(t, sess.Records), input)
}

// The accepted-submit instant captured at the pre-turn boundary is threaded to
// dispatch, so the turn it issues can measure end-to-end latency from the user
// submit.
func TestPersistUserInputThenIssue_PassesAcceptedSubmitStartToDispatch(t *testing.T) {
	restore := now
	accepted := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return accepted }
	t.Cleanup(func() { now = restore })

	store := newStore(filepath.Join(t.TempDir(), "session.json"))
	p := New(store, &fakeUI{})

	var got time.Time
	dispatch := func(submitStart time.Time) error { got = submitStart; return nil }
	if err := p.PersistUserInputThenIssue(context.Background(), "hi", nil, dispatch); err != nil {
		t.Fatalf("PersistUserInputThenIssue() error = %v", err)
	}
	if !got.Equal(accepted) {
		t.Fatalf("dispatch submitStart = %v, want the accepted-submit instant %v", got, accepted)
	}
}

// A retry after a write failure reuses the original accept instant rather than
// re-stamping it, so end-to-end latency still measures from the first submit even
// though the clock advanced between attempts.
func TestPersistUserInputThenIssue_RetryReusesOriginalSubmitStart(t *testing.T) {
	subdir := filepath.Join(t.TempDir(), "subdir")
	store := newStore(filepath.Join(subdir, "session.json"))
	p := New(store, &fakeUI{})

	restore := now
	first := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	later := first.Add(5 * time.Second)
	cur := first
	now = func() time.Time { return cur }
	t.Cleanup(func() { now = restore })

	const input = "the only user message"
	var got time.Time
	dispatch := func(submitStart time.Time) error { got = submitStart; return nil }

	// First submit fails (parent dir missing); the accept instant is captured at `first`.
	if err := p.PersistUserInputThenIssue(context.Background(), input, nil, dispatch); err == nil {
		t.Fatal("first submit: want a flush error")
	}
	// The clock advances and the write target is fixed before the retry.
	cur = later
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := p.PersistUserInputThenIssue(context.Background(), input, nil, dispatch); err != nil {
		t.Fatalf("retry submit error = %v", err)
	}
	if !got.Equal(first) {
		t.Fatalf("retry dispatch submitStart = %v, want the original accept instant %v (not the retry-time %v)", got, first, later)
	}
}

// Dispatch error propagation: after a successful flush the helper returns
// dispatch's error to the caller, and the successful durability boundary still
// clears the retry state.
func TestPersistUserInputThenIssue_DispatchErrorReturnedAfterFlush(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	ui := &fakeUI{}
	p := New(store, ui)

	sentinel := errors.New("dispatch failed")
	dispatched := 0
	dispatch := func(time.Time) error { dispatched++; return sentinel }

	err := p.PersistUserInputThenIssue(context.Background(), "hello model", nil, dispatch)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the dispatch sentinel surfaced to the caller", err)
	}
	if dispatched != 1 {
		t.Fatalf("dispatch called %d times, want 1", dispatched)
	}
	if p.pending {
		t.Fatal("pending still set after a successful flush, even though dispatch failed")
	}
}

// Pending-retry input identity: a retry that carries a different input than the
// retained one is rejected without flushing or dispatching, so a model request
// can never be issued for text that was never made durable.
func TestPersistUserInputThenIssue_PendingRetryRejectsDifferentInput(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "subdir")
	sessionPath := filepath.Join(subdir, "session.json")
	store := newStore(sessionPath)
	ui := &fakeUI{}
	p := New(store, ui)

	dispatched := 0
	dispatch := func(time.Time) error { dispatched++; return nil }

	// First submit: parent dir missing -> atomic failure, "original" retained.
	if err := p.PersistUserInputThenIssue(context.Background(), "original", nil, dispatch); err == nil {
		t.Fatal("first submit: want an error from the failed flush")
	}
	if !p.pending {
		t.Fatal("after first submit: pending not set")
	}

	// Fix the write target, then retry with a DIFFERENT input.
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := p.PersistUserInputThenIssue(context.Background(), "edited", nil, dispatch)
	if !errors.Is(err, ErrPendingInputMismatch) {
		t.Fatalf("retry with a different input: error = %v, want ErrPendingInputMismatch", err)
	}
	if dispatched != 0 {
		t.Fatalf("dispatch called %d times for a mismatched retry, want 0", dispatched)
	}
	if got := countUserMessages(store.Records()); got != 1 {
		t.Fatalf("user messages = %d, want 1 (no message appended for the mismatched input)", got)
	}
	if m := soleUserMessage(t, store.Records()); m.Content.Text() != "original" {
		t.Fatalf("retained user message text = %q, want \"original\"", m.Content.Text())
	}
	if !p.pending {
		t.Fatal("pending cleared by a rejected mismatch retry; the retained input would be lost")
	}
	// The rejected retry returned before flushing, so nothing was written to disk.
	if _, serr := os.Stat(sessionPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("session file written by a rejected mismatch retry: stat err = %v", serr)
	}
}

// imagePartFixture builds an image_url content part carrying url, in the raw shape
// the provider send path consumes.
func imagePartFixture(url string) sessions.ContentPart {
	return sessions.ContentPart{
		Type: "image_url",
		Raw:  []byte(`{"type":"image_url","image_url":{"url":"` + url + `"}}`),
	}
}

// With image attachments present, the user message is persisted as a PartsContent
// list of the typed text part followed by the image parts, in the provider send path's expected raw
// shapes, verified by reading the record back through the session codec.
func TestPersistUserInputThenIssue_PersistsTextAndImageParts(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	p := New(store, &fakeUI{})

	img := imagePartFixture("data:image/png;base64,AAAA")
	if err := p.PersistUserInputThenIssue(context.Background(), "look at this", []sessions.ContentPart{img}, func(time.Time) error { return nil }); err != nil {
		t.Fatalf("PersistUserInputThenIssue() error = %v", err)
	}

	data, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	sess, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse persisted session: %v", err)
	}
	m := soleUserMessage(t, sess.Records)
	if !m.Content.IsList() {
		t.Fatal("content is not a parts list; a submission with attachments must persist as PartsContent")
	}
	parts := m.Content.Parts()
	if len(parts) != 2 || parts[0].Type != "text" || parts[1].Type != "image_url" {
		t.Fatalf("parts = %+v, want [text, image_url]", parts)
	}
	if !strings.Contains(string(parts[0].Raw), `"text":"look at this"`) {
		t.Errorf("text part raw = %s, want the typed text in {\"type\":\"text\",\"text\":…} shape", parts[0].Raw)
	}
	if !strings.Contains(string(parts[1].Raw), "data:image/png;base64,AAAA") {
		t.Errorf("image part raw = %s, want the verbatim image_url data URI", parts[1].Raw)
	}
}

// An image-only submission (no typed text) persists only the image parts, with no
// empty text part.
func TestPersistUserInputThenIssue_ImageOnlyPersistsNoTextPart(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	p := New(store, &fakeUI{})

	img := imagePartFixture("data:image/gif;base64,R0lGOD")
	if err := p.PersistUserInputThenIssue(context.Background(), "", []sessions.ContentPart{img}, func(time.Time) error { return nil }); err != nil {
		t.Fatalf("PersistUserInputThenIssue() error = %v", err)
	}
	m := soleUserMessage(t, store.Records())
	if !m.Content.IsList() {
		t.Fatal("image-only content is not a parts list")
	}
	if parts := m.Content.Parts(); len(parts) != 1 || parts[0].Type != "image_url" {
		t.Fatalf("image-only parts = %+v, want exactly one image_url part (no empty text part)", parts)
	}
}

// Retry identity covers the attachments: re-submitting the same text with identical
// attachments after a failure re-flushes the retained message without duplicating it.
func TestPersistUserInputThenIssue_RetrySameAttachmentsReflushes(t *testing.T) {
	subdir := filepath.Join(t.TempDir(), "subdir")
	store := newStore(filepath.Join(subdir, "session.json"))
	p := New(store, &fakeUI{})

	dispatched := 0
	dispatch := func(time.Time) error { dispatched++; return nil }
	const url = "data:image/png;base64,AAAA"

	if err := p.PersistUserInputThenIssue(context.Background(), "same", []sessions.ContentPart{imagePartFixture(url)}, dispatch); err == nil {
		t.Fatal("first submit: want a flush error (parent dir missing)")
	}
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A freshly built but byte-identical attachment must compare equal on retry.
	if err := p.PersistUserInputThenIssue(context.Background(), "same", []sessions.ContentPart{imagePartFixture(url)}, dispatch); err != nil {
		t.Fatalf("retry with identical attachments error = %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("dispatch called %d times, want 1 after the successful retry", dispatched)
	}
	if got := countUserMessages(store.Records()); got != 1 {
		t.Fatalf("user messages = %d, want 1 (no duplicate on retry)", got)
	}
}

// A retry that changes the attachments — same text, different image — is rejected,
// so a request is never issued for a payload that was never made durable.
func TestPersistUserInputThenIssue_RetryRejectsDifferentAttachments(t *testing.T) {
	subdir := filepath.Join(t.TempDir(), "subdir")
	store := newStore(filepath.Join(subdir, "session.json"))
	p := New(store, &fakeUI{})

	dispatched := 0
	dispatch := func(time.Time) error { dispatched++; return nil }

	if err := p.PersistUserInputThenIssue(context.Background(), "same", []sessions.ContentPart{imagePartFixture("data:image/png;base64,AAAA")}, dispatch); err == nil {
		t.Fatal("first submit: want a flush error")
	}
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := p.PersistUserInputThenIssue(context.Background(), "same", []sessions.ContentPart{imagePartFixture("data:image/png;base64,BBBB")}, dispatch)
	if !errors.Is(err, ErrPendingInputMismatch) {
		t.Fatalf("retry with a different attachment: error = %v, want ErrPendingInputMismatch", err)
	}
	if dispatched != 0 {
		t.Fatalf("dispatch called %d times for a mismatched-attachment retry, want 0", dispatched)
	}
	if got := countUserMessages(store.Records()); got != 1 {
		t.Fatalf("user messages = %d, want 1 (no message appended for the mismatched retry)", got)
	}
}

// Atomic flush failure: dispatch is not called, the message stays in memory,
// session_write_failed is appended via the write-failure protocol, and the notice is rendered.
func TestPersistUserInputThenIssue_AtomicFlushFailureRoutedThroughG250(t *testing.T) {
	// A missing parent directory makes the atomic flush fail with parent_dir_error.
	sessionPath := filepath.Join(t.TempDir(), "no-such-subdir", "session.json")
	store := newStore(sessionPath)
	ui := &fakeUI{}
	p := New(store, ui)

	dispatched := 0
	dispatch := func(time.Time) error { dispatched++; return nil }

	err := p.PersistUserInputThenIssue(context.Background(), "retained input", nil, dispatch)
	if err == nil {
		t.Fatal("PersistUserInputThenIssue() returned nil on an atomic flush failure, want the flush error")
	}
	if dispatched != 0 {
		t.Fatalf("dispatch called %d times on a write failure, want 0", dispatched)
	}
	recs := store.Records()
	if got := countUserMessages(recs); got != 1 {
		t.Fatalf("user messages = %d, want the retained message to remain in memory (1)", got)
	}
	if got := countWriteFailedEvents(recs); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (routed through g250)", got)
	}
	if len(ui.notices) != 1 {
		t.Fatalf("notices = %v, want exactly one session-write-failed notice", ui.notices)
	}
	if !p.pending {
		t.Fatal("pending cleared after a write failure; a retry would append a duplicate")
	}
}

// Non-atomic flush failure (ReasonNone via a cancelled context): the failure is
// surfaced to the caller, but it is not encoded as session_write_failed and no
// dispatch occurs.
func TestPersistUserInputThenIssue_ReasonNoneNotRoutedAndNotDispatched(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	ui := &fakeUI{}
	p := New(store, ui)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a cancelled context makes Flush return ReasonNone + ctx.Err()

	dispatched := 0
	dispatch := func(time.Time) error { dispatched++; return nil }

	err := p.PersistUserInputThenIssue(ctx, "retained input", nil, dispatch)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled surfaced to the caller", err)
	}
	if dispatched != 0 {
		t.Fatalf("dispatch called %d times on a ReasonNone flush failure, want 0", dispatched)
	}
	recs := store.Records()
	if got := countUserMessages(recs); got != 1 {
		t.Fatalf("user messages = %d, want the message appended (1)", got)
	}
	if got := countWriteFailedEvents(recs); got != 0 {
		t.Fatalf("session_write_failed events = %d, want 0 (ReasonNone is not encodable for g250)", got)
	}
	if len(ui.notices) != 0 {
		t.Fatalf("notices = %v, want none (ReasonNone bypasses g250)", ui.notices)
	}
	if !p.pending {
		t.Fatal("pending cleared after a ReasonNone failure; a retry would append a duplicate")
	}
	if _, serr := os.Stat(sessionPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("session file unexpectedly written on a cancelled flush: stat err = %v", serr)
	}
}

// Idempotence: a failed submit retains the user message; after the write target
// is fixed, re-submitting the same input re-flushes and dispatches without
// appending a duplicate user message.
func TestPersistUserInputThenIssue_RetryAfterFixDoesNotDuplicate(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "subdir")
	sessionPath := filepath.Join(subdir, "session.json")
	store := newStore(sessionPath)
	ui := &fakeUI{}
	p := New(store, ui)

	const input = "the only user message"
	dispatched := 0
	dispatch := func(time.Time) error { dispatched++; return nil }

	// First submit: parent dir missing -> atomic failure, message retained.
	if err := p.PersistUserInputThenIssue(context.Background(), input, nil, dispatch); err == nil {
		t.Fatal("first submit: want an error from the failed flush")
	}
	if dispatched != 0 {
		t.Fatalf("dispatch called %d times before durability succeeded, want 0", dispatched)
	}
	if got := countUserMessages(store.Records()); got != 1 {
		t.Fatalf("after first submit: user messages = %d, want 1", got)
	}
	if !p.pending {
		t.Fatal("after first submit: pending not set")
	}

	// Fix the write target, then re-submit the same retained input.
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := p.PersistUserInputThenIssue(context.Background(), input, nil, dispatch); err != nil {
		t.Fatalf("retry submit error = %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("dispatch called %d times after the retry succeeded, want 1", dispatched)
	}
	if got := countUserMessages(store.Records()); got != 1 {
		t.Fatalf("after retry: user messages = %d, want 1 (no duplicate)", got)
	}
	if p.pending {
		t.Fatal("pending not reset after a successful retry flush")
	}

	// The retained message is durable on disk, and only one user record exists.
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	if !strings.Contains(string(data), input) {
		t.Fatalf("retained user message not persisted after retry:\n%s", data)
	}
	if n := strings.Count(string(data), `"role":"user"`); n != 1 {
		t.Fatalf("persisted role:user records = %d, want exactly 1 (no duplicate)", n)
	}
}

func readSession(t *testing.T, path string) *sessions.Session {
	t.Helper()
	sess, _, err := sessions.OpenSession(path)
	if err != nil {
		t.Fatalf("OpenSession(%s): %v", path, err)
	}
	return sess
}

func assertDiskTitle(t *testing.T, path, wantTitle, wantSource string) {
	t.Helper()
	md := readSession(t, path).Metadata
	if md.Title != wantTitle || md.TitleSource != wantSource {
		t.Fatalf("disk title = %q (source %q), want %q (source %q)", md.Title, md.TitleSource, wantTitle, wantSource)
	}
}

func submit(t *testing.T, p *Persister, input string, parts []sessions.ContentPart) {
	t.Helper()
	if err := p.PersistUserInputThenIssue(context.Background(), input, parts, func(time.Time) error { return nil }); err != nil {
		t.Fatalf("PersistUserInputThenIssue(%q) error = %v", input, err)
	}
}

func TestPersistUserInputThenIssue_FirstPlainPromptStoresFallbackTitle(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	p := New(store, &fakeUI{})

	submit(t, p, "  Fix   the\tlogin\nbug in the session store please  ", nil)
	const want = "Fix the login bug in the session store please"
	assertDiskTitle(t, sessionPath, want, sessions.TitleSourceGenerated)
	if store.Title() != want || store.TitleSource() != sessions.TitleSourceGenerated {
		t.Fatalf("memory title = %q (source %q), want %q (generated)", store.Title(), store.TitleSource(), want)
	}

	submit(t, p, "a completely different second prompt", nil)
	assertDiskTitle(t, sessionPath, want, sessions.TitleSourceGenerated)
	if got := countUserMessages(readSession(t, sessionPath).Records); got != 2 {
		t.Fatalf("disk user messages = %d, want 2", got)
	}
}

func TestPersistUserInputThenIssue_FallbackTitleIneligibleFirstPrompts(t *testing.T) {
	img := []sessions.ContentPart{imagePartFixture("data:image/png;base64,AAAA")}
	tests := []struct {
		name  string
		input string
		parts []sessions.ContentPart
	}{
		{"text with image parts", "look at this", img},
		{"image only", "", img},
		{"whitespace only", " \t\n  ", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionPath := filepath.Join(t.TempDir(), "session.json")
			store := newStore(sessionPath)
			p := New(store, &fakeUI{})

			submit(t, p, tt.input, tt.parts)
			assertDiskTitle(t, sessionPath, "", "")

			submit(t, p, "a later plain-text prompt", nil)
			assertDiskTitle(t, sessionPath, "", "")
			if store.Title() != "" || store.TitleSource() != "" {
				t.Fatalf("memory title = %q (source %q), want untitled", store.Title(), store.TitleSource())
			}
		})
	}
}

func TestPersistUserInputThenIssue_ResumedUntitledSessionNotTitled(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	legacy := newStore(sessionPath)
	legacy.Append(sessions.Message{ID: ids.NewV7(), Role: "user", Content: sessions.TextContent("old question"), Timestamp: time.Now().UTC()})
	legacy.Append(sessions.Message{ID: ids.NewV7(), Role: "assistant", Content: sessions.TextContent("old answer"), Timestamp: time.Now().UTC()})
	if _, _, err := legacy.Flush(context.Background()); err != nil {
		t.Fatalf("seed legacy session: %v", err)
	}

	resumed := sessions.New(sessionPath, readSession(t, sessionPath))
	submit(t, New(resumed, &fakeUI{}), "a new prompt after resume", nil)

	assertDiskTitle(t, sessionPath, "", "")
	if resumed.Title() != "" {
		t.Fatalf("memory title = %q, want untitled", resumed.Title())
	}
}

func TestPersistUserInputThenIssue_ChildSessionNotTitled(t *testing.T) {
	parent := sessions.MetadataSnapshot{
		ID:        ids.NewV7(),
		Folder:    "/home/u/proj",
		StartedAt: time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC),
	}
	forkRecord := func() []sessions.Record {
		return []sessions.Record{sessions.Message{ID: ids.NewV7(), Role: "assistant", Content: sessions.TextContent("prior answer"), Timestamp: parent.StartedAt}}
	}
	compactRecord := func() []sessions.Record {
		return []sessions.Record{&sessions.Compaction{ID: ids.NewV7(), Summary: "prior context", Timestamp: parent.StartedAt, Provider: "anthropic", ModelID: "claude-opus-4-8"}}
	}
	tests := []struct {
		name    string
		title   string
		records []sessions.Record
	}{
		{"fork child with derived title", "Parent (forked)", forkRecord()},
		{"untitled fork child", "", forkRecord()},
		{"summary-only compact child with derived title", "Parent (compacted)", compactRecord()},
		{"untitled summary-only compact child", "", compactRecord()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin := sessions.ForkOrigin{SessionID: parent.ID, RecordID: ids.NewV7()}
			store, err := sessions.EnsureChildSession(t.TempDir(), parent, tt.title, origin, tt.records)
			if err != nil {
				t.Fatalf("EnsureChildSession: %v", err)
			}
			if _, _, err := store.Flush(context.Background()); err != nil {
				t.Fatalf("flush child: %v", err)
			}
			wantSource := ""
			if tt.title != "" {
				wantSource = sessions.TitleSourceGenerated
			}

			submit(t, New(store, &fakeUI{}), "the first new prompt in the child", nil)

			sess := readSession(t, store.Path())
			if got := countUserMessages(sess.Records); got != 1 {
				t.Fatalf("disk user messages = %d, want exactly the one new prompt", got)
			}
			assertDiskTitle(t, store.Path(), tt.title, wantSource)
			if store.Title() != tt.title || store.TitleSource() != wantSource {
				t.Fatalf("memory title = %q (source %q), want %q (source %q)", store.Title(), store.TitleSource(), tt.title, wantSource)
			}
		})
	}
}

func TestPersistUserInputThenIssue_RenamedTitleNotReplacedByFallback(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	if _, _, err := store.FlushTitle(context.Background(), "My rename"); err != nil {
		t.Fatalf("FlushTitle: %v", err)
	}
	p := New(store, &fakeUI{})

	submit(t, p, "first prompt text", nil)
	assertDiskTitle(t, sessionPath, "My rename", sessions.TitleSourceUser)
	submit(t, p, "second prompt text", nil)
	assertDiskTitle(t, sessionPath, "My rename", sessions.TitleSourceUser)
}

func TestPersistUserInputThenIssue_FailedFallbackWriteStillDispatches(t *testing.T) {
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	store := newStore(sessionPath)
	// Seed the file so the user-message flush is an append, which bypasses the
	// atomic-write sync seam that the title rewrite goes through.
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("seed session file: %v", err)
	}
	ui := &fakeUI{}
	p := New(store, ui)

	restore := fsutil.SetSyncFileForTest(func(*os.File) error { return syscall.EIO })
	t.Cleanup(restore)
	dispatched := 0
	err := p.PersistUserInputThenIssue(context.Background(), "first prompt text", nil, func(time.Time) error {
		dispatched++
		return nil
	})
	restore()
	if err != nil {
		t.Fatalf("PersistUserInputThenIssue() error = %v, want nil despite the failed title write", err)
	}
	if dispatched != 1 {
		t.Fatalf("dispatch called %d times, want 1", dispatched)
	}
	if store.Title() != "" || store.TitleSource() != "" {
		t.Fatalf("memory title = %q (source %q), want the prior empty title restored", store.Title(), store.TitleSource())
	}
	sess := readSession(t, sessionPath)
	if sess.Metadata.Title != "" || sess.Metadata.TitleSource != "" {
		t.Fatalf("disk title = %q (source %q), want untitled", sess.Metadata.Title, sess.Metadata.TitleSource)
	}
	assertUserMessageFields(t, soleUserMessage(t, sess.Records), "first prompt text")
	if len(ui.notices) != 0 || countWriteFailedEvents(store.Records()) != 0 {
		t.Fatalf("title failure routed through write-failure handling: notices=%v events=%d", ui.notices, countWriteFailedEvents(store.Records()))
	}

	submit(t, p, "second prompt text", nil)
	sess = readSession(t, sessionPath)
	if sess.Metadata.Title != "" || store.Title() != "" {
		t.Fatalf("second prompt supplied a fallback: disk %q, memory %q", sess.Metadata.Title, store.Title())
	}
	if got := countUserMessages(sess.Records); got != 2 {
		t.Fatalf("disk user messages = %d, want 2", got)
	}
}

func TestPersistUserInputThenIssue_RetriedFirstFlushStoresFallbackOnce(t *testing.T) {
	subdir := filepath.Join(t.TempDir(), "subdir")
	sessionPath := filepath.Join(subdir, "session.json")
	store := newStore(sessionPath)
	p := New(store, &fakeUI{})

	const input = "the first prompt that failed to persist"
	if err := p.PersistUserInputThenIssue(context.Background(), input, nil, func(time.Time) error { return nil }); err == nil {
		t.Fatal("first submit: want a flush error (parent dir missing)")
	}
	if store.Title() != "" {
		t.Fatalf("title %q stored before the user message was durable", store.Title())
	}
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	submit(t, p, input, nil)
	assertDiskTitle(t, sessionPath, input, sessions.TitleSourceGenerated)

	submit(t, p, "a later prompt", nil)
	assertDiskTitle(t, sessionPath, input, sessions.TitleSourceGenerated)
}

func TestFallbackTitle(t *testing.T) {
	long79 := strings.Repeat("a", 79)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"single word kept", "hello", "hello"},
		{"whitespace collapsed", "  hello \t\t world\n\nagain\r\n ", "hello world again"},
		{"exactly 12 words kept", "1 2 3 4 5 6 7 8 9 10 11 12", "1 2 3 4 5 6 7 8 9 10 11 12"},
		{"cut to 12 words", "1 2 3 4 5 6 7 8 9 10 11 12 13 14", "1 2 3 4 5 6 7 8 9 10 11 12"},
		{"cut to 80 runes", strings.Repeat("x", 100), strings.Repeat("x", 80)},
		{"multi-byte runes not split", strings.Repeat("日本", 50), strings.Repeat("日本", 40)},
		{"trailing space trimmed after rune cut", long79 + " bbbb", long79},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fallbackTitle(tt.in); got != tt.want {
				t.Fatalf("fallbackTitle(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
