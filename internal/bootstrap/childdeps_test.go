// Tests for the prepared-child activation lifecycle: parent validation, real
// creation/activation order, lock retention/release, and transcript reconstruction.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

const (
	clParentID = "0190c1de-0000-7000-8000-000000000001"
	clUser     = "0190c1de-0000-7000-8000-0000000000a1"
	clAfter    = "0190c1de-0000-7000-8000-0000000000a2"
	clChildA   = "0190c1de-0000-7000-8000-0000000000b1"
	clChildB   = "0190c1de-0000-7000-8000-0000000000b2"
	clChildC   = "0190c1de-0000-7000-8000-0000000000b3"
	clChildD   = "0190c1de-0000-7000-8000-0000000000b4"
	clCompact  = "0190c1de-0000-7000-8000-0000000000c1"
)

var clStart = time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)

func clParentStore(t *testing.T, dir, folder string) *sessions.Store {
	t.Helper()
	sess := &sessions.Session{
		Metadata: sessions.Metadata{ID: clParentID, Folder: folder, StartedAt: clStart, UpdatedAt: clStart, SchemaVersion: 1},
		Records: []sessions.Record{
			sessions.Message{ID: clUser, Role: "user", Content: sessions.TextContent("parent turn"), Timestamp: clStart},
		},
	}
	return sessions.New(filepath.Join(dir, "parent.json"), sess)
}

func clChildRecords() []sessions.Record {
	return []sessions.Record{
		sessions.Message{ID: clChildA, Role: "user", Content: sessions.TextContent("carried question"), Timestamp: clStart},
		sessions.Message{ID: clChildB, Role: "assistant", Content: sessions.TextContent("carried answer"), Timestamp: clStart},
	}
}

type clFixture struct {
	app             *tui.App
	released        int
	activeAtRelease *sessions.Store
	bannerCalls     int
	holder          *resumeLockHolder
	lc              preparedChildLifecycle
}

func newCLFixture(t *testing.T, home string, parent *sessions.Store) *clFixture {
	t.Helper()
	f := &clFixture{app: tui.New(nil)}
	f.app.SetActiveStore(parent)
	holder := &resumeLockHolder{}
	holder.release = func() {
		f.released++
		f.activeAtRelease = f.app.ActiveStore()
	}
	f.lc = preparedChildLifecycle{
		ctx:    context.Background(),
		home:   home,
		app:    f.app,
		holder: holder,
		banner: func() []string {
			f.bannerCalls++
			return []string{"child-banner-line"}
		},
		recorder: fixedRecorder(injectedResolution),
	}
	f.holder = holder
	return f
}

func clFolderDir(home, folder string) string {
	return filepath.Join(sessions.SessionRoot(home), sessions.FolderDirName(folder))
}

func clChildFiles(t *testing.T, home, folder string) []string {
	t.Helper()
	dir := clFolderDir(home, folder)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read child folder dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files
}

func clAssertParentRetained(t *testing.T, f *clFixture, parent *sessions.Store, transcriptBefore string) {
	t.Helper()
	if got := f.app.ActiveStore(); got != parent {
		t.Errorf("active store changed on failure: got %p, want the parent %p", got, parent)
	}
	if f.released != 0 {
		t.Errorf("resume lock released %d times on failure, want 0", f.released)
	}
	if f.bannerCalls != 0 {
		t.Errorf("banner rendered %d times on failure, want 0", f.bannerCalls)
	}
	if got := f.app.TranscriptText(); got != transcriptBefore {
		t.Errorf("transcript changed on failure:\ngot  %q\nwant %q", got, transcriptBefore)
	}
	before := len(parent.Records())
	parent.Append(sessions.Message{ID: clAfter, Role: "user", Content: sessions.TextContent("still open"), Timestamp: clStart})
	if after := len(parent.Records()); after != before+1 {
		t.Errorf("parent refused an append after failure: %d -> %d, want open", before, after)
	}
}

func TestChildLifecycle_NilParentRejected(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-nil"
	parent := clParentStore(t, t.TempDir(), folder)
	f := newCLFixture(t, home, parent)
	f.app.AppendBanner("stale-transcript-line")
	before := f.app.TranscriptText()

	_, err := f.lc.CreateAndActivate(nil, "child title", clChildRecords(), nil)
	if err == nil {
		t.Fatal("CreateAndActivate accepted a nil parent, want error")
	}
	if n := len(clChildFiles(t, home, folder)); n != 0 {
		t.Errorf("child files after a nil-parent rejection = %d, want 0", n)
	}
	clAssertParentRetained(t, f, parent, before)
}

func TestChildLifecycle_StaleParentRejected(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-stale"
	parent := clParentStore(t, t.TempDir(), folder)
	stale := clParentStore(t, t.TempDir(), folder)
	f := newCLFixture(t, home, parent)
	f.app.AppendBanner("stale-transcript-line")
	before := f.app.TranscriptText()

	_, err := f.lc.CreateAndActivate(stale, "child title", clChildRecords(), nil)
	if err == nil {
		t.Fatal("CreateAndActivate accepted a non-active parent, want error")
	}
	if !strings.Contains(err.Error(), "not the active session") {
		t.Errorf("error = %v, want the stale-parent rejection", err)
	}
	if n := len(clChildFiles(t, home, folder)); n != 0 {
		t.Errorf("child files after a stale-parent rejection = %d, want 0", n)
	}
	clAssertParentRetained(t, f, parent, before)
	staleBefore := len(stale.Records())
	stale.Append(sessions.Message{ID: clAfter, Role: "user", Content: sessions.TextContent("still open"), Timestamp: clStart})
	if after := len(stale.Records()); after != staleBefore+1 {
		t.Errorf("stale store refused an append after rejection: %d -> %d, want open", staleBefore, after)
	}
}

func TestChildLifecycle_SuccessActivatesExactChildAndSealsParent(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-success"
	parent := clParentStore(t, t.TempDir(), folder)
	f := newCLFixture(t, home, parent)

	if _, err := f.lc.CreateAndActivate(parent, "child title", clChildRecords(), nil); err != nil {
		t.Fatalf("CreateAndActivate error = %v", err)
	}

	child := f.app.ActiveStore()
	if child == nil || child == parent {
		t.Fatalf("active store = %p, want the created child (parent %p)", child, parent)
	}
	files := clChildFiles(t, home, folder)
	if len(files) != 1 {
		t.Fatalf("child files = %d, want 1", len(files))
	}
	if child.Path() != files[0] {
		t.Errorf("active store path = %q, want the created child file %q", child.Path(), files[0])
	}
	sess := readSessionFile(t, files[0])
	if sess.Metadata.ID != child.SessionID() {
		t.Errorf("active session id = %q, want the child file's %q", child.SessionID(), sess.Metadata.ID)
	}
	if sess.Metadata.Title != "child title" {
		t.Errorf("child title = %q, want %q", sess.Metadata.Title, "child title")
	}
	want := sessions.ForkOrigin{SessionID: clParentID, RecordID: clUser}
	if sess.Metadata.ForkedFrom == nil || *sess.Metadata.ForkedFrom != want {
		t.Fatalf("child forked_from = %+v, want %+v", sess.Metadata.ForkedFrom, want)
	}
	first, ok := sess.Records[0].(sessions.Message)
	if !ok || first.ID != clChildA || first.ParentID != clUser {
		t.Errorf("child record 0 = %+v, want the supplied %s linked to %s", sess.Records[0], clChildA, clUser)
	}
	second, ok := sess.Records[1].(sessions.Message)
	if !ok || second.ID != clChildB {
		t.Errorf("child record 1 = %+v, want the supplied %s", sess.Records[1], clChildB)
	}

	if f.released != 1 {
		t.Errorf("resume lock released %d times, want 1", f.released)
	}
	if f.activeAtRelease != child {
		t.Errorf("active store during lock release = %p, want the child %p (install before release)", f.activeAtRelease, child)
	}
	if f.bannerCalls != 1 {
		t.Errorf("banner rendered %d times, want 1", f.bannerCalls)
	}

	parentBefore := len(parent.Records())
	parent.Append(sessions.Message{ID: clAfter, Role: "user", Content: sessions.TextContent("after"), Timestamp: clStart})
	if after := len(parent.Records()); after != parentBefore {
		t.Errorf("parent accepted an append after activation: %d -> %d, want sealed", parentBefore, after)
	}
	childBefore := len(child.Records())
	child.Append(sessions.Message{ID: clAfter, Role: "user", Content: sessions.TextContent("next turn"), Timestamp: clStart})
	if after := len(child.Records()); after != childBefore+1 {
		t.Errorf("child refused an append after activation: %d -> %d, want open", childBefore, after)
	}
}

func TestChildLifecycle_SuccessResetsTranscriptAndReplaysVisible(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-replay"
	parent := clParentStore(t, t.TempDir(), folder)
	f := newCLFixture(t, home, parent)
	f.app.AppendBanner("stale-transcript-line")

	records := []sessions.Record{
		sessions.Compaction{ID: clCompact, Summary: "compacted summary text", Provider: "openai", ModelID: "gpt-test", Timestamp: clStart},
		sessions.Message{ID: clChildA, Role: "user", Content: sessions.TextContent("carried question"), Timestamp: clStart},
		sessions.Message{ID: clChildB, Role: "assistant", Content: sessions.TextContent("carried answer"), Timestamp: clStart},
		sessions.Message{ID: clChildC, Role: "system", Content: sessions.TextContent("hidden system note"), Timestamp: clStart},
		sessions.Message{ID: clChildD, Role: "assistant", Content: sessions.TextContent(" \t"), Timestamp: clStart},
	}
	if _, err := f.lc.CreateAndActivate(parent, "child title", records, nil); err != nil {
		t.Fatalf("CreateAndActivate error = %v", err)
	}

	got := f.app.TranscriptText()
	if strings.Contains(got, "stale-transcript-line") {
		t.Errorf("transcript still shows pre-activation content:\n%s", got)
	}
	for _, hidden := range []string{"compacted summary text", "hidden system note"} {
		if strings.Contains(got, hidden) {
			t.Errorf("transcript shows hidden record content %q:\n%s", hidden, got)
		}
	}
	banner := strings.Index(got, "child-banner-line")
	question := strings.Index(got, "carried question")
	answer := strings.Index(got, "carried answer")
	if banner < 0 || question < 0 || answer < 0 {
		t.Fatalf("transcript missing banner/replayed content (banner %d, question %d, answer %d):\n%s", banner, question, answer, got)
	}
	if banner >= question || question >= answer {
		t.Errorf("transcript order = banner %d, question %d, answer %d; want banner before question before answer:\n%s", banner, question, answer, got)
	}
}

func TestChildLifecycle_PrepareHasNoLiveMutation(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-prepare"
	parent := clParentStore(t, t.TempDir(), folder)
	f := newCLFixture(t, home, parent)
	f.app.AppendBanner("stale-transcript-line")
	before := f.app.TranscriptText()

	prepared, err := f.lc.Prepare(parent, "child title", clChildRecords(), nil, f.app)
	if err != nil {
		t.Fatalf("Prepare error = %v", err)
	}
	if prepared.store == nil || prepared.store == parent {
		t.Fatalf("prepared store = %p, want a new child (parent %p)", prepared.store, parent)
	}
	if prepared.release == nil {
		t.Fatal("prepared child carries no ownership token")
	}
	if got := f.app.ActiveStore(); got != parent {
		t.Errorf("active store changed during preparation: got %p, want parent %p", got, parent)
	}
	if f.released != 0 {
		t.Errorf("source token released %d times during preparation, want 0", f.released)
	}
	if f.bannerCalls != 0 {
		t.Errorf("banner rendered %d times during preparation, want 0", f.bannerCalls)
	}
	if got := f.app.TranscriptText(); got != before {
		t.Errorf("transcript changed during preparation:\ngot  %q\nwant %q", got, before)
	}
	if !resumeLockHeld(t, prepared.store.Path()) {
		t.Error("prepared child's sidecar is not held; Prepare must retain ownership")
	}
}

func TestChildLifecycle_ActivateTransfersExactOwnedChild(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-activate"
	parent := clParentStore(t, t.TempDir(), folder)
	f := newCLFixture(t, home, parent)
	f.app.AppendBanner("stale-transcript-line")

	terminal := []sessions.Record{
		sessions.Message{ID: clAfter, Role: "assistant", Content: sessions.TextContent("terminal parent record"), Timestamp: clStart},
	}
	prepared, err := f.lc.Prepare(parent, "child title", clChildRecords(), terminal, f.app)
	if err != nil {
		t.Fatalf("Prepare error = %v", err)
	}
	child := prepared.store

	f.lc.Activate(prepared)

	if got := f.app.ActiveStore(); got != child {
		t.Fatalf("active store after Activate = %p, want the exact prepared child %p", got, child)
	}
	if f.released != 1 {
		t.Errorf("source token released %d times, want exactly 1", f.released)
	}
	if f.activeAtRelease != child {
		t.Errorf("active store at source release = %p, want the child %p (install before source release)", f.activeAtRelease, child)
	}
	if !resumeLockHeld(t, child.Path()) {
		t.Error("child token is not held after activation")
	}
	if f.bannerCalls != 1 {
		t.Errorf("banner rendered %d times, want 1", f.bannerCalls)
	}
	got := f.app.TranscriptText()
	if strings.Contains(got, "stale-transcript-line") {
		t.Errorf("transcript still shows pre-activation content:\n%s", got)
	}
	banner := strings.Index(got, "child-banner-line")
	question := strings.Index(got, "carried question")
	if banner < 0 || question < 0 || banner >= question {
		t.Errorf("transcript order = banner %d, question %d; want banner before replayed child content:\n%s", banner, question, got)
	}

	pf := readSessionFile(t, parent.Path())
	termIdx, forkIdx := -1, -1
	for i, rec := range pf.Records {
		switch r := rec.(type) {
		case sessions.Message:
			if r.ID == clAfter {
				termIdx = i
			}
		case sessions.Event:
			if r.Kind == events.KindSessionForked {
				forkIdx = i
			}
		}
	}
	if termIdx < 0 || forkIdx < 0 || termIdx >= forkIdx {
		t.Errorf("parent final batch order: terminal record idx %d, session_forked idx %d; want terminal record before the marker", termIdx, forkIdx)
	}
	f.holder.releaseHeld()
	if resumeLockHeld(t, child.Path()) {
		t.Error("terminal cleanup did not release the child token")
	}
	f.holder.releaseHeld()
	if resumeLockHeld(t, child.Path()) {
		t.Error("a second terminal cleanup reacquired the child token")
	}
}

func TestChildLifecycle_InitialWriteFailureRetainsParent(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-writefail"
	dir := clFolderDir(home, folder)

	forced := errors.New("forced parent-dir sync failure")
	var publishedPath string
	restore := fsutil.SetSyncDirForTest(func(f *os.File) error {
		files, _ := os.ReadDir(dir)
		for _, e := range files {
			if filepath.Ext(e.Name()) == ".json" {
				publishedPath = filepath.Join(dir, e.Name())
				return forced
			}
		}
		return f.Sync()
	})
	defer restore()

	parent := clParentStore(t, t.TempDir(), folder)
	f := newCLFixture(t, home, parent)
	f.app.AppendBanner("stale-transcript-line")
	before := f.app.TranscriptText()

	_, err := f.lc.CreateAndActivate(parent, "child title", clChildRecords(), nil)
	if err == nil {
		t.Fatal("CreateAndActivate succeeded with a failing child flush, want error")
	}
	if !errors.Is(err, forced) {
		t.Errorf("error = %v, want it to wrap the forced sync failure", err)
	}
	if publishedPath == "" || !strings.Contains(err.Error(), publishedPath) {
		t.Errorf("error = %v, want the failed child path %q", err, publishedPath)
	}
	if !strings.Contains(err.Error(), string(fserrors.IOError)) || !strings.Contains(err.Error(), string(sessions.ReasonParentDirError)) {
		t.Errorf("error = %v, want the callback's category %q and reason %q", err, fserrors.IOError, sessions.ReasonParentDirError)
	}
	restore()
	if n := len(clChildFiles(t, home, folder)); n != 0 {
		t.Errorf("child files after a failed initial write = %d, want 0", n)
	}
	clAssertParentRetained(t, f, parent, before)
}

func TestChildLifecycle_PrepareFailureRetainsParentAndUnlocksOrphan(t *testing.T) {
	home := t.TempDir()
	folder := "/proj/child-orphan"
	parentDir := t.TempDir()
	parent := clParentStore(t, parentDir, folder)

	forced := errors.New("forced parent-marker sync failure")
	restore := fsutil.SetSyncDirForTest(func(fh *os.File) error {
		if fh.Name() == parentDir {
			return forced
		}
		return fh.Sync()
	})
	defer restore()

	f := newCLFixture(t, home, parent)
	f.app.AppendBanner("stale-transcript-line")
	before := f.app.TranscriptText()

	_, err := f.lc.Prepare(parent, "child title", clChildRecords(), nil, f.app)
	if err == nil {
		t.Fatal("Prepare succeeded with a failing parent-marker flush, want error")
	}
	if !errors.Is(err, forced) {
		t.Errorf("error = %v, want it to wrap the forced marker sync failure", err)
	}
	if strings.Contains(err.Error(), "was not written") {
		t.Errorf("error = %v, want no initial-write facts on a parent-marker failure", err)
	}
	restore()

	if active := f.app.ActiveStore(); active.SessionID() != clParentID {
		t.Errorf("active session = %q, want the parent %q (a preparation failure must not activate)", active.SessionID(), clParentID)
	}
	files := clChildFiles(t, home, folder)
	if len(files) != 1 {
		t.Fatalf("surviving child files = %d, want the published 1", len(files))
	}
	if resumeLockHeld(t, files[0]) {
		t.Error("surviving orphan child still holds its sidecar; a preparation failure must release child ownership")
	}
	release, lerr := sessions.AcquireResumeLock(files[0], "orphan")
	if lerr != nil {
		t.Errorf("orphan child sidecar could not be re-acquired: %v", lerr)
	} else {
		release()
	}
	if _, _, oerr := sessions.OpenSession(files[0]); oerr != nil {
		t.Errorf("orphan child does not load: %v", oerr)
	}
	clAssertParentRetained(t, f, parent, before)
}

func clSwitch(t *testing.T, f *clFixture, parent *sessions.Store, via string) (*sessions.Store, string, error) {
	t.Helper()
	if via == "fork" {
		warning, err := f.lc.CreateAndActivate(parent, "child title", clChildRecords(), nil)
		return f.app.ActiveStore(), warning, err
	}
	prepared, err := f.lc.Prepare(parent, "child title", clChildRecords(), nil, turnNoticeRenderer{surface: f.app})
	if err != nil {
		return nil, "", err
	}
	return prepared.store, f.lc.Activate(prepared), nil
}

func clCapabilityEvents(sess *sessions.Session) []sessions.Event {
	var out []sessions.Event
	for _, rec := range sess.Records {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == events.KindExecutionCapability {
			out = append(out, ev)
		}
	}
	return out
}

func clReadOnlyChildCapability(t *testing.T, parent *sessions.Store) {
	t.Helper()
	orig := recordExecutionCapability
	recordExecutionCapability = func(ctx context.Context, store *sessions.Store, resolution enforce.Resolution, notices tui.NoticeRenderer) error {
		if store != parent {
			if err := os.Chmod(store.Path(), 0o400); err != nil {
				return err
			}
		}
		return orig(ctx, store, resolution, notices)
	}
	t.Cleanup(func() { recordExecutionCapability = orig })
}

func clSkipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only file")
	}
}

func TestChildLifecycle_RecordsTheLaunchCapabilityInTheChild(t *testing.T) {
	for _, via := range []string{"fork", "compact"} {
		t.Run(via, func(t *testing.T) {
			parent := clParentStore(t, t.TempDir(), "/proj/child-capability")
			f := newCLFixture(t, t.TempDir(), parent)
			if err := recordExecutionCapability(context.Background(), parent, injectedResolution, f.app); err != nil {
				t.Fatalf("record the launch capability: %v", err)
			}
			launchDisk := readSessionFile(t, parent.Path())
			launch := clCapabilityEvents(launchDisk)
			if len(launch) != 1 {
				t.Fatalf("launch capability events = %+v, want one", launch)
			}
			launchCaps := decodeDiskEvents[events.ExecutionCapability](t, launchDisk, events.KindExecutionCapability)
			time.Sleep(2 * time.Millisecond)

			child, _, err := clSwitch(t, f, parent, via)
			if err != nil {
				t.Fatalf("switch: %v", err)
			}
			disk := readSessionFile(t, child.Path())
			began := slices.IndexFunc(disk.Records, func(rec sessions.Record) bool {
				ev, ok := rec.(sessions.Event)
				return ok && ev.Kind == events.KindLaunchBegan
			})
			if began < 0 || began+1 >= len(disk.Records) {
				t.Fatalf("child records on disk = %+v, want launch_began followed by a record", disk.Records)
			}
			got, ok := disk.Records[began+1].(sessions.Event)
			if !ok || got.Kind != events.KindExecutionCapability {
				t.Fatalf("child record after launch_began = %+v, want execution_capability", disk.Records[began+1])
			}
			caps := decodeDiskEvents[events.ExecutionCapability](t, disk, events.KindExecutionCapability)
			if len(caps) != 1 || !reflect.DeepEqual(caps[0], launchCaps[0]) {
				t.Fatalf("child execution_capability = %+v, want exactly the launch session's %+v", caps, launchCaps[0])
			}
			if got.ID == "" || got.ID == launch[0].ID || !got.Timestamp.After(launch[0].Timestamp) {
				t.Fatalf("child capability event %+v, want its own ID and a timestamp after the launch event %+v", got, launch[0])
			}
		})
	}
}

func TestChildLifecycle_CapabilityOrFinalizationFailureKeepsTheParentAndOldFolder(t *testing.T) {
	for _, tc := range []string{"append", "flush", "finalization"} {
		t.Run(tc, func(t *testing.T) {
			conf := injectedTempDir(t)
			old := conf.tmpDir
			home, folder, parentDir := t.TempDir(), "/proj/child-capfail", t.TempDir()
			parent := clParentStore(t, parentDir, folder)
			f := newCLFixture(t, home, parent)
			f.lc.conf = conf
			forced := errors.New("forced sync failure")
			switch tc {
			case "append":
				f.lc.recorder = fixedRecorder(enforce.Resolution{})
			case "flush":
				clSkipIfRoot(t)
				clReadOnlyChildCapability(t, parent)
			case "finalization":
				defer fsutil.SetSyncDirForTest(func(fh *os.File) error {
					if fh.Name() == parentDir {
						return forced
					}
					return fh.Sync()
				})()
			}
			f.app.AppendBanner("stale-transcript-line")
			before := f.app.TranscriptText()

			_, err := f.lc.Prepare(parent, "child title", clChildRecords(), nil, &recordingHost{})
			if err == nil {
				t.Fatal("Prepare succeeded, want the failure")
			}
			if tc == "flush" && !errors.Is(err, fs.ErrPermission) || tc == "finalization" && !errors.Is(err, forced) {
				t.Fatalf("error = %v, want the forced %s failure", err, tc)
			}
			assertTempDirKept(t, conf, old)
			clAssertParentRetained(t, f, parent, before)
		})
	}
}

func TestChildLifecycle_ReplacementRemovalFailureIsJoinedAfterThePrimaryError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove a folder from a read-only parent")
	}
	conf := injectedTempDir(t)
	old := conf.tmpDir
	tmp := os.TempDir()
	t.Cleanup(func() { _ = os.Chmod(tmp, 0o700) })
	parentDir := t.TempDir()
	parent := clParentStore(t, parentDir, "/proj/child-rollbackfail")
	f := newCLFixture(t, t.TempDir(), parent)
	f.lc.conf = conf
	forced := errors.New("forced parent finalization failure")
	defer fsutil.SetSyncDirForTest(func(fh *os.File) error {
		if fh.Name() == parentDir {
			_ = os.Chmod(tmp, 0o500)
			return forced
		}
		return fh.Sync()
	})()

	_, err := f.lc.Prepare(parent, "child title", clChildRecords(), nil, &recordingHost{})
	if !errors.Is(err, forced) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want the finalization failure joined with the replacement removal failure", err)
	}
	if msg := err.Error(); strings.Index(msg, forced.Error()) > strings.LastIndex(msg, "permission denied") {
		t.Fatalf("error = %q, want the primary failure before the removal failure", msg)
	}
	if conf.tmpDir != old || f.app.ActiveStore() != parent {
		t.Fatalf("tmpDir = %q active = %p, want %q and the parent", conf.tmpDir, f.app.ActiveStore(), old)
	}
}

func TestChildLifecycle_CapabilityWriteFailureNoticeSurface(t *testing.T) {
	for _, via := range []string{"fork", "compact"} {
		t.Run(via, func(t *testing.T) {
			clSkipIfRoot(t)
			parent := clParentStore(t, t.TempDir(), "/proj/child-notice")
			f := newCLFixture(t, t.TempDir(), parent)
			clReadOnlyChildCapability(t, parent)
			surface := &recordingSurface{}

			var err error
			if via == "fork" {
				_, err = f.lc.CreateAndActivate(parent, "child title", clChildRecords(), nil)
			} else {
				_, err = f.lc.Prepare(parent, "child title", clChildRecords(), nil, turnNoticeRenderer{surface: surface})
			}
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("error = %v, want the capability write failure", err)
			}
			direct, background := f.app.NoticeText(), len(surface.notices)
			if via == "fork" && (direct == "" || background != 0) {
				t.Fatalf("direct notice = %q, background notices = %d; want the direct notice only", direct, background)
			}
			if via == "compact" && (direct != "" || background == 0) {
				t.Fatalf("direct notice = %q, background notices = %d; want the background notice only", direct, background)
			}
		})
	}
}

func TestChildLifecycle_ReplacesThePrivateTempFolder(t *testing.T) {
	for _, via := range []string{"fork", "compact"} {
		newFixture := func(t *testing.T, conf *confinement) (*clFixture, *sessions.Store) {
			parent := clParentStore(t, t.TempDir(), "/proj/child-tmp")
			f := newCLFixture(t, t.TempDir(), parent)
			f.lc.conf = conf
			return f, parent
		}
		t.Run(via+" replaced", func(t *testing.T) {
			conf := injectedTempDir(t)
			old := conf.tmpDir
			f, parent := newFixture(t, conf)
			if _, warning, err := clSwitch(t, f, parent, via); err != nil || warning != "" {
				t.Fatalf("switch = (%q, %v), want success without a warning", warning, err)
			}
			if _, err := os.Stat(old); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("old folder stat = %v, want it removed", err)
			}
			assertTempDirReplaced(t, conf, old)
		})
		t.Run(via+" old folder cleanup fails", func(t *testing.T) {
			conf := stuckTempDir(t)
			old := conf.tmpDir
			f, parent := newFixture(t, conf)
			_, warning, err := clSwitch(t, f, parent, via)
			if err != nil || f.app.ActiveStore() == parent {
				t.Fatalf("switch error = %v, want the switch to stand", err)
			}
			assertTempDirReplaced(t, conf, old)
			if !slices.Equal(conf.retryPaths, []string{old}) {
				t.Fatalf("retry = %v, want [%s]", conf.retryPaths, old)
			}
			if !strings.HasPrefix(warning, "can't remove private temp folder "+old+": ") || !strings.HasSuffix(warning, "; codemeld retries when it exits") {
				t.Fatalf("warning = %q", warning)
			}
		})
		t.Run(via+" empty tmpDir", func(t *testing.T) {
			conf := &confinement{}
			f, parent := newFixture(t, conf)
			if _, _, err := clSwitch(t, f, parent, via); err != nil {
				t.Fatalf("switch: %v", err)
			}
			if conf.tmpDir != "" {
				t.Fatalf("tmpDir = %q, want it to stay empty", conf.tmpDir)
			}
		})
	}
}

func TestForkAndCompact_TurnActiveRefusalKeepsTheTempFolder(t *testing.T) {
	for _, command := range []string{"/fork", "/compact"} {
		t.Run(command, func(t *testing.T) {
			conf := injectedTempDir(t)
			old := conf.tmpDir
			app := tui.New(nil)
			parent := clParentStore(t, t.TempDir(), "/proj/child-refused")
			app.SetActiveStore(parent)
			ctx := context.Background()
			fork := newForkDeps(ctx, app, t.TempDir(), &resumeLockHolder{}, &turnController{}, statusState{}, fixedRecorder(injectedResolution), conf)
			fork.TurnActive = func() bool { return true }
			compact := newCompactDeps(ctx, app, nil, nil, t.TempDir(), &resumeLockHolder{}, &turnController{}, statusState{}, &compactLease{}, fixedRecorder(injectedResolution), conf)
			compact.TurnActive = func() bool { return true }
			reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"fork": tui.NewForkHandler(fork), "compact": tui.NewCompactHandler(compact)})

			if tui.NewSubmitFunc(reg, app, nil)(command) {
				t.Fatalf("%s was accepted while a turn is active", command)
			}
			if app.ActiveStore() != parent {
				t.Fatalf("active store changed on a refused %s", command)
			}
			assertTempDirKept(t, conf, old)
		})
	}
}

func TestCompact_CleanupWarningStaysVisibleAfterCompletion(t *testing.T) {
	conf := stuckTempDir(t)
	old := conf.tmpDir
	app := tui.New(nil)
	parent := clParentStore(t, t.TempDir(), "/proj/child-compact-warning")
	app.SetActiveStore(parent)
	status := newStatusState(app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})
	deps := newCompactDeps(context.Background(), app, nil, nil, t.TempDir(), &resumeLockHolder{}, &turnController{}, status, &compactLease{}, fixedRecorder(injectedResolution), conf)
	deps.TurnActive = func() bool { return false }
	deps.SummaryRequest = func([]sessions.Record) (provider.Request, string, string, bool) {
		return provider.Request{}, "openai", "gpt-5.5", true
	}
	deps.Client = func(string, string) (provider.Client, bool) {
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Completion: &openai.ChatCompletion{
				Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: "the plan, summarized"}}},
			}}, nil
		}}, true
	}
	reg := tui.BuildRegistry(map[string]tui.HandlerFunc{"compact": tui.NewCompactHandler(deps)})

	if !tui.NewSubmitFunc(reg, app, nil)("/compact") {
		t.Fatal("/compact should be accepted")
	}
	if app.ActiveStore() == parent {
		t.Fatalf("active store not swapped after /compact; notice %q", app.NoticeText())
	}
	if got := app.NoticeText(); !strings.HasPrefix(got, "can't remove private temp folder "+old+": ") {
		t.Fatalf("notice = %q, want the cleanup warning for %s", got, old)
	}
}

func TestChildLifecycle_RecordsTheLiveCapabilityAfterASettingsChange(t *testing.T) {
	for _, via := range []string{"fork", "compact"} {
		for _, tc := range liveCapabilityCases {
			t.Run(via+" "+tc.name, func(t *testing.T) {
				recorder, f := liveSettingsRecorder(t, tc.launch)
				setSettingsBroken(t, f, !tc.broken)
				recorder.blocked.Current()
				parent := clParentStore(t, t.TempDir(), "/proj/child-live")
				fx := newCLFixture(t, t.TempDir(), parent)
				fx.lc.recorder = recorder

				setSettingsBroken(t, f, tc.broken)
				child, _, err := clSwitch(t, fx, parent, via)
				if err != nil {
					t.Fatalf("switch: %v", err)
				}
				requireDiskCapabilities(t, child, tc.want)
			})
		}
	}
}

func TestChildLifecycle_ActivationRecordsAChangeSincePreparation(t *testing.T) {
	for _, via := range []string{"fork", "compact"} {
		for _, afterFinalization := range []bool{false, true} {
			for _, recovers := range []bool{false, true} {
				name := fmt.Sprintf("%s afterFinalization=%v recovers=%v", via, afterFinalization, recovers)
				t.Run(name, func(t *testing.T) {
					recorder, f := liveSettingsRecorder(t, constrainedLaunch)
					setSettingsBroken(t, f, recovers)
					recorder.blocked.Current()
					parent := clParentStore(t, t.TempDir(), "/proj/child-reconcile")
					fx := newCLFixture(t, t.TempDir(), parent)
					fx.lc.recorder = recorder
					var records <-chan storedCapability
					change := func() {
						setSettingsBroken(t, f, !recovers)
						refreshWithin(t, recorder.blocked)
						nextCapabilityRecord(t, records, func(r storedCapability) bool { return r.store == parent })
					}
					var changed atomic.Bool
					records = watchCapabilityRecords(t, func(store *sessions.Store) {
						if !afterFinalization && store != parent && changed.CompareAndSwap(false, true) {
							change()
						}
					})
					runLiveDelivery(t, fx.app, recorder)

					switch {
					case via == "compact":
						status := newStatusState(fx.app, providerCache(t, t.TempDir()), selectedState(), &BootstrapResult{LaunchDir: "/launch"}, enforce.Resolution{})
						deps := newCompactDeps(context.Background(), fx.app, nil, nil, fx.lc.home, fx.holder, &turnController{}, status, &compactLease{}, recorder, nil)
						activate, err := deps.PrepareChild(parent, "child title", clChildRecords(), nil)
						if err != nil {
							t.Fatalf("PrepareChild: %v", err)
						}
						if afterFinalization {
							change()
						}
						activate()
					case afterFinalization:
						prepared, err := fx.lc.Prepare(parent, "child title", clChildRecords(), nil, fx.app)
						if err != nil {
							t.Fatalf("Prepare: %v", err)
						}
						change()
						if warning := fx.lc.Activate(prepared); warning != "" {
							t.Fatalf("Activate warning = %q, want none", warning)
						}
					default:
						if _, err := fx.lc.CreateAndActivate(parent, "child title", clChildRecords(), nil); err != nil {
							t.Fatalf("CreateAndActivate: %v", err)
						}
					}

					child := fx.app.ActiveStore()
					if child == parent {
						t.Fatal("the child was not activated")
					}
					requireDiskCapabilities(t, child, capabilityFor(recovers), capabilityFor(!recovers))
					if afterFinalization {
						if caps := decodeDiskEvents[events.ExecutionCapability](t, readSessionFile(t, parent.Path()), events.KindExecutionCapability); len(caps) != 0 {
							t.Fatalf("sealed parent capabilities on disk = %+v, want the delivery dropped", caps)
						}
					}
				})
			}
		}
	}
}

func TestChildLifecycle_ActivationCorrectionFailureKeepsTheSwitch(t *testing.T) {
	prepare := func(t *testing.T) (*clFixture, *sessions.Store, preparedChild) {
		recorder, f := liveSettingsRecorder(t, constrainedLaunch)
		parent := clParentStore(t, t.TempDir(), "/proj/child-correction")
		fx := newCLFixture(t, t.TempDir(), parent)
		fx.lc.recorder = recorder
		prepared, err := fx.lc.Prepare(parent, "child title", clChildRecords(), nil, fx.app)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		setSettingsBroken(t, f, true)
		return fx, parent, prepared
	}

	t.Run("write failure", func(t *testing.T) {
		clSkipIfRoot(t)
		fx, parent, prepared := prepare(t)
		child := prepared.store
		if err := os.Chmod(child.Path(), 0o400); err != nil {
			t.Fatal(err)
		}

		warning := fx.lc.Activate(prepared)
		if fx.app.ActiveStore() != child || fx.released != 1 {
			t.Fatalf("active = %p released = %d, want the child %p and the parent lock released", fx.app.ActiveStore(), fx.released, child)
		}
		if !strings.HasPrefix(warning, "session log unwritable — "+child.Path()+": ") {
			t.Fatalf("Activate warning = %q, want the write-failure notice for %s", warning, child.Path())
		}
		requireDiskCapabilities(t, child, constrainedCapability)

		if err := os.Chmod(child.Path(), 0o600); err != nil {
			t.Fatal(err)
		}
		mustFlush(t, child)
		requireDiskCapabilities(t, child, constrainedCapability, brokenCapability)
		if failed := decodeDiskEvents[events.SessionWriteFailed](t, readSessionFile(t, child.Path()), events.KindSessionWriteFailed); len(failed) != 1 || failed[0].TargetPath != child.Path() {
			t.Fatalf("session_write_failed on disk = %+v, want one for %s", failed, child.Path())
		}
		before := len(parent.Records())
		parent.Append(sessions.Message{ID: clAfter, Role: "user", Content: sessions.TextContent("late"), Timestamp: clStart})
		if len(parent.Records()) != before {
			t.Fatal("the finalized parent accepted an append")
		}
	})

	t.Run("unreported failure", func(t *testing.T) {
		fx, _, prepared := prepare(t)
		forced := errors.New("forced unreported failure")
		orig := recordExecutionCapability
		recordExecutionCapability = func(context.Context, *sessions.Store, enforce.Resolution, tui.NoticeRenderer) error { return forced }
		t.Cleanup(func() { recordExecutionCapability = orig })

		warning := fx.lc.Activate(prepared)
		if !strings.Contains(warning, forced.Error()) || !strings.Contains(warning, prepared.store.Path()) {
			t.Fatalf("Activate warning = %q, want the unreported failure for %s", warning, prepared.store.Path())
		}
		if fx.app.ActiveStore() != prepared.store {
			t.Fatal("the switch was undone after an unreported correction failure")
		}
	})
}
