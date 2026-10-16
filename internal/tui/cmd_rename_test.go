// Tests for /rename: dispatch + title persistence through the active-store seam,
// wrong-arity refusal with no event, persistence-failure rejection before the
// confirmation notice, a disk read-back terminal test, and the production-registry
// wiring + /help listing.
package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/sessions"
)

// renameSession returns a valid, records-less session usable as a disk flush
// target for the /rename read-back test.
func renameSession() *sessions.Session {
	return &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			Folder:        "/home/u/proj",
			StartedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
			SchemaVersion: 1,
		},
	}
}

// renameRegistry builds a one-command registry binding /rename to a handler over
// deps, so dispatch (including the ArgRestRequired arity gate and multi-word join)
// exercises the real handler path.
func renameRegistry(t *testing.T, deps RenameDeps) *Registry {
	t.Helper()
	reg, err := NewRegistry([]Command{
		{Name: "rename", Description: "Rename the current session", ArgSig: ArgRestRequired, Phase: PhaseTwo, Handler: NewRenameHandler(deps)},
	})
	if err != nil {
		t.Fatalf("build rename registry: %v", err)
	}
	return reg
}

// TestRenameHandler_DispatchPersistsTitleAndRecordsSuccess is the disk read-back
// terminal test (done-when): after /rename foo on the active session, re-opening the
// session file from disk shows Title == "foo", the slash_command event was flushed
// alongside it, and updated_at did not advance (a rename is not
// session activity). It drives the real Store.FlushTitle through the handler's seam.
func TestRenameHandler_DispatchPersistsTitleAndRecordsSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	startUpdatedAt := renameSession().Metadata.UpdatedAt
	host := &fakeHost{store: sessions.New(path, renameSession())}
	deps := RenameDeps{SetTitle: func(title string) error {
		_, _, err := host.store.FlushTitle(context.Background(), title)
		return err
	}}

	res := renameRegistry(t, deps).DispatchSlashInput("/rename foo", host)

	if res.Status != StatusHandled || res.Canonical != "rename" || res.Err != nil {
		t.Fatalf("dispatch /rename foo = %+v, want Handled/rename/nil-err", res)
	}
	if len(host.notices) != 1 || !strings.Contains(host.notices[0], "foo") {
		t.Fatalf("notices = %v, want one confirmation mentioning foo", host.notices)
	}

	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "rename" || p.Outcome != "success" || len(p.Args) != 1 || p.Args[0] != "foo" {
		t.Errorf("event = %+v, want name=rename args=[foo] outcome=success", p)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	got, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if got.Metadata.Title != "foo" {
		t.Errorf("persisted title = %q, want %q", got.Metadata.Title, "foo")
	}
	if !got.Metadata.UpdatedAt.Equal(startUpdatedAt) {
		t.Errorf("updated_at = %s after /rename, want it unchanged at %s", got.Metadata.UpdatedAt, startUpdatedAt)
	}
	if len(got.Records) != 1 {
		t.Errorf("persisted records = %d, want 1 (the slash_command event is flushed with the title)", len(got.Records))
	}
}

// TestRenameHandler_MultiWordNameJoinsAndPersists pins the done-when: /rename with
// several words dispatches successfully, persists the joined title, and records the
// joined string as the single slash_command arg (so dispatch's rest-join, not just
// the handler, is exercised).
func TestRenameHandler_MultiWordNameJoinsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	host := &fakeHost{store: sessions.New(path, renameSession())}
	deps := RenameDeps{SetTitle: func(title string) error {
		_, _, err := host.store.FlushTitle(context.Background(), title)
		return err
	}}

	res := renameRegistry(t, deps).DispatchSlashInput("/rename work on something", host)

	if res.Status != StatusHandled || res.Canonical != "rename" || res.Err != nil {
		t.Fatalf("dispatch multi-word /rename = %+v, want Handled/rename/nil-err", res)
	}

	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); len(p.Args) != 1 || p.Args[0] != "work on something" {
		t.Errorf("event args = %v, want [\"work on something\"] (rest-join)", p.Args)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	got, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("parse written session: %v", err)
	}
	if got.Metadata.Title != "work on something" {
		t.Errorf("persisted title = %q, want %q", got.Metadata.Title, "work on something")
	}
}

// TestRenameHandler_NoArgRefusedWithArityNoticeNoEvent pins the done-when: a
// zero-argument /rename is refused with the standard arity notice, the
// handler never runs, no SetTitle write happens, and no event is appended.
func TestRenameHandler_NoArgRefusedWithArityNoticeNoEvent(t *testing.T) {
	host := &fakeHost{store: sessions.New("", renameSession())}
	var setTitleCalls int
	deps := RenameDeps{SetTitle: func(string) error { setTitleCalls++; return nil }}

	res := renameRegistry(t, deps).DispatchSlashInput("/rename", host)

	if res.Status != StatusWrongArity || res.Canonical != "rename" {
		t.Fatalf("dispatch bare /rename = %+v, want StatusWrongArity/rename", res)
	}
	if !res.RetainInput {
		t.Error("wrong-arity /rename did not retain the typed input")
	}
	if setTitleCalls != 0 {
		t.Errorf("SetTitle called %d times on a wrong-arity /rename, want 0", setTitleCalls)
	}
	if got := len(host.events()); got != 0 {
		t.Errorf("appended %d slash_command events on a wrong-arity /rename, want 0", got)
	}
}

// TestRenameHandler_PersistFailureReturnsBeforeNotice covers the durability
// boundary: when the title write fails, the handler returns the error before any
// confirmation notice (no visible confirmation past a failed boundary), and — like
// /status/help — appends no second slash_command error event. The success
// slash_command appended before the write stays in memory for a later retry.
func TestRenameHandler_PersistFailureReturnsBeforeNotice(t *testing.T) {
	host := &fakeHost{store: sessions.New("", renameSession())}
	writeErr := errors.New("session write failed persisting title")
	deps := RenameDeps{SetTitle: func(string) error { return writeErr }}

	res := renameRegistry(t, deps).DispatchSlashInput("/rename foo", host)

	if res.Status != StatusHandled || !errors.Is(res.Err, writeErr) {
		t.Fatalf("dispatch /rename foo = %+v, want Handled with the write error", res)
	}
	if len(host.notices) != 0 {
		t.Errorf("notices = %v, want none past a failed durability boundary", host.notices)
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1 (the success append retained in memory)", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Outcome != "success" {
		t.Errorf("retained event outcome = %q, want success (no second error event appended)", p.Outcome)
	}
}

func TestRenameThroughApp_BadgeFollowsThePersistenceOutcome(t *testing.T) {
	renameApp := func(t *testing.T, path string) (*App, *sessions.Store) {
		t.Helper()
		a := New(nil)
		store := sessions.New(path, renameSession())
		a.SetActiveStore(store)
		reg := renameRegistry(t, RenameDeps{SetTitle: func(title string) error {
			_, _, err := store.FlushTitle(context.Background(), title)
			return err
		}})
		a.SetSubmit(NewSubmitFunc(reg, a, nil))
		return a, store
	}

	t.Run("persisted", func(t *testing.T) {
		a, _ := renameApp(t, filepath.Join(t.TempDir(), "session.json"))

		if !a.SubmitInput("/rename My session") {
			t.Fatal("submit rejected a rename whose write succeeded")
		}
		if got := a.NoticeText(); !strings.Contains(got, "My session") {
			t.Errorf("notice = %q, want the rename confirmation", got)
		}
		if got := a.SessionBadgeText(); got != "My session" {
			t.Errorf("badge = %q, want the session-name badge after a persisted rename", got)
		}
	})

	t.Run("write_failed", func(t *testing.T) {
		a, store := renameApp(t, filepath.Join(t.TempDir(), "no-such-subdir", "session.json"))

		if a.SubmitInput("/rename My session") {
			t.Fatal("submit accepted a rename whose write failed")
		}
		if got := a.NoticeText(); strings.Contains(got, "Renamed session") {
			t.Errorf("notice = %q, want no confirmation past a failed durability boundary", got)
		}
		if got := a.SessionBadgeText(); got != "" {
			t.Errorf("badge = %q, want none past a failed durability boundary", got)
		}
		if got := store.Title(); got != "" {
			t.Errorf("in-memory title = %q, want the prior empty title restored", got)
		}
	})
}

// TestBuildRegistry_RenameDispatchesToHandler pins the production wiring: the
// registry binds the supplied rename handler to /rename, and the phase-2 command
// now appears in the rendered /help listing (buildPhase == PhaseTwo).
func TestBuildRegistry_RenameDispatchesToHandler(t *testing.T) {
	var gotTitle string
	deps := RenameDeps{SetTitle: func(title string) error { gotTitle = title; return nil }}
	reg := BuildRegistry(map[string]HandlerFunc{"rename": NewRenameHandler(deps)})

	host := newFakeHost()
	res := reg.DispatchSlashInput("/rename work on something", host)
	if res.Status != StatusHandled || res.Canonical != "rename" || res.Err != nil {
		t.Fatalf("dispatch multi-word /rename = %+v, want Handled/rename/nil-err", res)
	}
	if gotTitle != "work on something" {
		t.Errorf("rename handler set title %q, want %q (production handler not bound or /rename miswired to ArgOneRequired)", gotTitle, "work on something")
	}
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); len(p.Args) != 1 || p.Args[0] != "work on something" {
		t.Errorf("event args = %v, want [\"work on something\"] (real /rename entry must use ArgRestRequired)", p.Args)
	}

	help := RenderHelp(reg)
	if !strings.Contains(help, "/rename") || !strings.Contains(help, "Rename the current session") {
		t.Errorf("/help listing missing the phase-2 /rename command:\n%s", help)
	}
}
