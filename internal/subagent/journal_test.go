package subagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
)

type fixture struct {
	home    string
	project string
	next    int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{home: realDir(t, t.TempDir()), project: realDir(t, t.TempDir())}
}

func realDir(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	return resolved
}

func (f *fixture) invocation() string {
	f.next++
	return fmt.Sprintf("inv-%04d", f.next)
}

func (f *fixture) open(t *testing.T, declared ...string) *Journal {
	t.Helper()
	j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: declared})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(j.Close)
	return j
}

func (f *fixture) seed(t *testing.T, rel, content string) string {
	t.Helper()
	path := filepath.Join(f.project, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("seed dirs for %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed %s: %v", rel, err)
	}
	return path
}

// childEdit and childCreate drive the production structured tools with the journal bound to the
// context exactly as a delegated child's dispatch binds it, so the journal is exercised through the
// publish seams rather than through a stand-in.
func (f *fixture) childEdit(t *testing.T, j *Journal, target, oldText, newText string) tools.Result {
	t.Helper()
	tool := filetools.NewEditTool(f.home, f.project, f.project)
	args := map[string]any{"path": target, "old_text": oldText, "new_text": newText}
	res, err := tool.InvokeWithResolvedTarget(f.ctx(j), args, target)
	if err != nil {
		t.Fatalf("edit %s: %v", target, err)
	}
	return res
}

func (f *fixture) childCreate(t *testing.T, j *Journal, target, content string) tools.Result {
	t.Helper()
	tool := filetools.NewCreateTool(f.home, f.project, f.project)
	args := map[string]any{"path": target, "content": content}
	res, err := tool.InvokeWithResolvedTarget(f.ctx(j), args, target)
	if err != nil {
		t.Fatalf("create %s: %v", target, err)
	}
	return res
}

func (f *fixture) ctx(j *Journal) context.Context {
	return filetools.WithWriteJournal(context.Background(), j)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func recordPath(j *Journal) string { return filepath.Join(j.Path(), journalRecordName) }

func onDiskRecord(t *testing.T, j *Journal) journalRecord {
	t.Helper()
	return recordIn(t, j.Path())
}

func recordIn(t *testing.T, dir string) journalRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, journalRecordName))
	if err != nil {
		t.Fatalf("read journal record: %v", err)
	}
	var rec journalRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decode journal record: %v", err)
	}
	return rec
}

// resumeFromDisk replaces the journal's in-memory state with the durable record, which is what a
// process that died mid-transaction leaves behind for recovery to pick up. It stands in for the recovery
// loader so the write-ahead protocol's idempotency can be proved here, where the protocol is written.
func resumeFromDisk(t *testing.T, j *Journal) {
	t.Helper()
	j.rec = onDiskRecord(t, j)
	j.index = make(map[string]int, len(j.rec.Paths))
	for i := range j.rec.Paths {
		j.index[j.rec.Paths[i].Path] = i
	}
}

func crashAt(t *testing.T, label string) {
	t.Helper()
	fired := false
	beforeJournalStep = func(step string) error {
		if step == label && !fired {
			fired = true
			return errors.New("simulated crash at " + label)
		}
		return nil
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })
}

// onJournalStep runs fn just before the named boundary is flushed.
func onJournalStep(t *testing.T, label string, fn func()) {
	t.Helper()
	fired := false
	beforeJournalStep = func(step string) error {
		if step == label && !fired {
			fired = true
			fn()
		}
		return nil
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })
}

// swapAndCrashAt moves the journal's storage aside, plants a symlink to a decoy where its path
// pointed, and then fails the named boundary. It stands in for a process killed at that write-ahead
// point while an attacker holds the storage path.
func swapAndCrashAt(t *testing.T, j *Journal, label string) (moved, decoy string) {
	t.Helper()
	original := j.Path()
	moved = original + "-moved"
	decoy = realDir(t, t.TempDir())
	fired := false
	beforeJournalStep = func(step string) error {
		if step != label || fired {
			return nil
		}
		fired = true
		if err := os.Rename(original, moved); err != nil {
			t.Errorf("move the journal directory aside: %v", err)
			return nil
		}
		if err := os.Symlink(decoy, original); err != nil {
			t.Errorf("plant the decoy: %v", err)
			return nil
		}
		return errors.New("simulated crash at " + label)
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })
	return moved, decoy
}

// restoreStorage puts the real journal directory back at its path, which is what recovery finds once
// the attacker's symlink is gone.
func restoreStorage(t *testing.T, j *Journal, moved string) {
	t.Helper()
	if err := os.Remove(j.Path()); err != nil {
		t.Fatalf("remove the decoy symlink: %v", err)
	}
	if err := os.Rename(moved, j.Path()); err != nil {
		t.Fatalf("restore the journal directory: %v", err)
	}
}

func assertGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s still exists (err=%v), want it removed", path, err)
	}
}

func TestOpenJournal_RecordsIntentAndHoldsItsLockBeforeTheChildRuns(t *testing.T) {
	f := newFixture(t)
	existing := f.seed(t, "a.txt", "ORIGINAL\n")
	missing := filepath.Join(f.project, "new/deep/b.txt")

	j := f.open(t, existing, missing)

	rec := onDiskRecord(t, j)
	if rec.SchemaVersion != journalSchemaVersion || rec.Lifecycle != lifecycleActive {
		t.Fatalf("record = %+v, want an active schema-%d record", rec, journalSchemaVersion)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(readBytes(t, recordPath(j)), &raw); err != nil {
		t.Fatalf("decode journal record: %v", err)
	}
	if _, ok := raw["owner"]; ok {
		t.Fatalf("record = %s, want no owner field", readBytes(t, recordPath(j)))
	}
	assertLockHeld(t, j)
	byPath := map[string]pathRecord{}
	for _, pr := range rec.Paths {
		byPath[pr.Path] = pr
	}
	if got := byPath[existing]; !got.Pre.Exists || string(got.Pre.Data) != "ORIGINAL\n" || got.Pre.Mode.Perm() != 0o644 {
		t.Fatalf("snapshot of %s = %+v, want its pre-run bytes and mode", existing, got.Pre)
	}
	if got := byPath[missing]; got.Pre.Exists {
		t.Fatalf("snapshot of the missing path = %+v, want an explicit absence", got.Pre)
	}
	if got := byPath[missing]; got.Ancestor != f.project || strings.Join(got.Suffix, "/") != "new/deep/b.txt" {
		t.Fatalf("missing suffix = %q under %q, want the deepest existing ancestor and its missing suffix", got.Suffix, got.Ancestor)
	}
	if strings.HasPrefix(j.Path(), f.project) {
		t.Fatalf("journal at %s, want it outside the project %s", j.Path(), f.project)
	}
	wantDir := filepath.Join(filepath.Dir(sessions.SessionRoot(f.home)), journalsDirName, sessions.FolderDirName(f.project), rec.Invocation)
	if j.Path() != wantDir {
		t.Fatalf("journal at %s, want the session-derived layout %s", j.Path(), wantDir)
	}
	if strings.HasPrefix(j.Path(), sessions.SessionRoot(f.home)+string(filepath.Separator)) {
		t.Fatalf("journal at %s, want it beside the sessions tree rather than inside it", j.Path())
	}
}

func TestOpenJournal_UsesOwnerOnlyModesOnDisk(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)

	dirInfo, err := os.Stat(j.Path())
	if err != nil {
		t.Fatalf("stat journal dir: %v", err)
	}
	if dirInfo.Mode().Perm() != journalDirMode {
		t.Fatalf("journal dir mode = %v, want %v", dirInfo.Mode().Perm(), journalDirMode)
	}
	recInfo, err := os.Stat(recordPath(j))
	if err != nil {
		t.Fatalf("stat journal record: %v", err)
	}
	if recInfo.Mode().Perm() != journalRecordMode {
		t.Fatalf("journal record mode = %v, want %v", recInfo.Mode().Perm(), journalRecordMode)
	}
	lockInfo, err := os.Lstat(lockPath(j))
	if err != nil {
		t.Fatalf("stat journal lock: %v", err)
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("journal lock mode = %v, want a 0600 regular file", lockInfo.Mode())
	}
	if flags, err := unix.FcntlInt(uintptr(j.writerLock.fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("writer lock descriptor flags = %#x (err=%v), want close-on-exec", flags, err)
	}

	var tempModes []os.FileMode
	restore := fsutil.SetBeforePublishRenameForTest(func() {
		entries, rerr := os.ReadDir(j.Path())
		if rerr != nil {
			return
		}
		for _, entry := range entries {
			if !strings.Contains(entry.Name(), ".tmp-") {
				continue
			}
			if info, ierr := entry.Info(); ierr == nil {
				tempModes = append(tempModes, info.Mode().Perm())
			}
		}
	})
	defer restore()
	if err := j.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(tempModes) == 0 {
		t.Fatal("observed no staged journal temporary file")
	}
	for _, mode := range tempModes {
		if mode != journalRecordMode {
			t.Fatalf("journal temp file mode = %v, want %v", mode, journalRecordMode)
		}
	}
}

func TestOpenJournal_RefusesUnsafeScopeBeforeCreatingStorage(t *testing.T) {
	t.Run("non-regular declared paths", func(t *testing.T) {
		cases := []struct {
			name string
			make func(t *testing.T, f *fixture) string
		}{
			{"directory", func(t *testing.T, f *fixture) string {
				path := filepath.Join(f.project, "dir")
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				return path
			}},
			{"fifo", func(t *testing.T, f *fixture) string {
				path := filepath.Join(f.project, "pipe")
				if err := unix.Mkfifo(path, 0o644); err != nil {
					t.Fatalf("mkfifo: %v", err)
				}
				return path
			}},
			{"symlink", func(t *testing.T, f *fixture) string {
				f.seed(t, "real.txt", "x")
				path := filepath.Join(f.project, "link.txt")
				if err := os.Symlink(filepath.Join(f.project, "real.txt"), path); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return path
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t)
				target := tc.make(t, f)
				if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}}); err == nil {
					t.Fatal("OpenJournal accepted a non-regular declared path")
				}
				assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
			})
		}
	})

	t.Run("a symlinked ancestor on the way to a declared path", func(t *testing.T) {
		f := newFixture(t)
		outside := realDir(t, t.TempDir())
		if err := os.WriteFile(filepath.Join(outside, "b.txt"), []byte("OUTSIDE\n"), 0o644); err != nil {
			t.Fatalf("seed outside the project: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(f.project, "sub")); err != nil {
			t.Fatalf("plant the symlinked ancestor: %v", err)
		}
		for _, target := range []string{
			filepath.Join(f.project, "sub", "b.txt"),
			filepath.Join(f.project, "sub", "deep", "c.txt"),
		} {
			if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}}); err == nil {
				t.Fatalf("OpenJournal followed a symlinked ancestor to reach %s", target)
			}
			assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
		}
	})

	t.Run("more than the declared-path cap", func(t *testing.T) {
		f := newFixture(t)
		var declared []string
		for i := range maxDeclaredPaths + 1 {
			declared = append(declared, f.seed(t, fmt.Sprintf("f%02d.txt", i), "x"))
		}
		if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: declared}); err == nil {
			t.Fatalf("OpenJournal accepted %d declared paths", len(declared))
		}
		assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))

		f2 := newFixture(t)
		declared = nil
		for i := range maxDeclaredPaths {
			declared = append(declared, f2.seed(t, fmt.Sprintf("f%02d.txt", i), "x"))
		}
		j, err := OpenJournal(JournalConfig{Home: f2.home, ProjectRoot: f2.project, Invocation: f2.invocation(), Declared: declared})
		if err != nil {
			t.Fatalf("OpenJournal refused exactly %d declared paths: %v", maxDeclaredPaths, err)
		}
		j.Close()
	})

	t.Run("per-file snapshot cap is inclusive", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			size    int
			wantErr bool
		}{
			{"exactly the cap", maxSnapshotBytesPerFile, false},
			{"one byte over", maxSnapshotBytesPerFile + 1, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t)
				target := f.seed(t, "big.bin", strings.Repeat("x", tc.size))
				j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}})
				if tc.wantErr {
					if err == nil {
						t.Fatal("OpenJournal accepted a snapshot over the per-file cap")
					}
					assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
					return
				}
				if err != nil {
					t.Fatalf("OpenJournal refused a snapshot at exactly the cap: %v", err)
				}
				j.Close()
			})
		}
	})

	t.Run("aggregate snapshot cap", func(t *testing.T) {
		f := newFixture(t)
		var declared []string
		for i := range 12 {
			declared = append(declared, f.seed(t, fmt.Sprintf("big%02d.bin", i), strings.Repeat("x", maxSnapshotBytesPerFile)))
		}
		declared = append(declared, f.seed(t, "tail.bin", strings.Repeat("x", (maxSnapshotBytesTotal-12*maxSnapshotBytesPerFile)+1)))
		if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: declared}); err == nil {
			t.Fatal("OpenJournal accepted snapshots over the aggregate cap")
		}
		assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
	})
}

func TestOpenJournal_RefusesAJournalInsideTheWorkingCopy(t *testing.T) {
	t.Run("project is the home", func(t *testing.T) {
		home := realDir(t, t.TempDir())
		target := filepath.Join(home, "a.txt")
		if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := OpenJournal(JournalConfig{Home: home, ProjectRoot: home, Invocation: "inv", Declared: []string{target}}); err == nil {
			t.Fatal("OpenJournal placed a journal inside the working copy")
		}
		assertGone(t, filepath.Join(home, ".codemeld"))
	})

	t.Run("declared target contains the journal", func(t *testing.T) {
		f := newFixture(t)
		declared := filepath.Join(f.home, ".codemeld", journalsDirName)
		if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: "inv", Declared: []string{declared}}); err == nil {
			t.Fatal("OpenJournal accepted a declared target that can contain its own journal")
		}
		assertGone(t, filepath.Join(f.home, ".codemeld"))
	})
}

func TestOpenJournal_MeasuresTheCompleteSerializedRecordInclusively(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	probe := f.open(t, target)
	exact, err := json.Marshal(&probe.rec)
	if err != nil {
		t.Fatalf("marshal probe record: %v", err)
	}
	probe.Close()

	original := maxJournalBytes
	t.Cleanup(func() { maxJournalBytes = original })

	maxJournalBytes = len(exact)
	j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}})
	if err != nil {
		t.Fatalf("OpenJournal refused a record of exactly the limit: %v", err)
	}
	j.Close()

	maxJournalBytes = len(exact) - 1
	if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}}); err == nil {
		t.Fatal("OpenJournal accepted a record one byte over the limit")
	}
}

func TestJournal_RefusesAnEditWhoseFileChangedAfterTheSnapshot(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)

	const external = "SOMEONE ELSE WROTE THIS\n"
	if err := os.WriteFile(target, []byte(external), 0o644); err != nil {
		t.Fatalf("external write: %v", err)
	}

	res := f.childEdit(t, j, target, "SOMEONE", "CHILD")
	if res.ExitCode == 0 {
		t.Fatalf("edit succeeded on an externally changed file: %s", res.Stdout)
	}
	if got := readFile(t, target); got != external {
		t.Fatalf("target = %q, want the external content preserved", got)
	}
	if rec := onDiskRecord(t, j); rec.Paths[0].Pending != nil {
		t.Fatalf("pending = %+v, want the refused edit never journalled", rec.Paths[0].Pending)
	}
}

func TestJournal_RefusesAnOverCapCreateBeforeMakingParentDirectories(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "made/up/deep.txt")
	j := f.open(t, target)

	res := f.childCreate(t, j, target, strings.Repeat("x", maxStateBytesPerPath+1))
	if res.ExitCode == 0 {
		t.Fatal("create accepted content over the per-path state cap")
	}
	assertGone(t, filepath.Join(f.project, "made"))

	atCap := f.childCreate(t, j, target, strings.Repeat("y", maxStateBytesPerPath))
	if atCap.ExitCode != 0 {
		t.Fatalf("create refused content at exactly the cap: %s", atCap.Stderr)
	}
}

func TestReconcilePending_ResolvesPriorPendingAndThirdState(t *testing.T) {
	cases := []struct {
		name            string
		leave           string
		wantLastKnown   string
		wantUnrecovered bool
	}{
		{name: "prior state means the write never published", leave: "ORIGINAL\n", wantLastKnown: "ORIGINAL\n"},
		{name: "pending state means the write published and is the child's", leave: "CHILD\n", wantLastKnown: "CHILD\n"},
		{name: "any other state is an external conflict", leave: "A THIRD WRITER\n", wantUnrecovered: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)

			pr := j.record(target)
			pr.Pending = &pendingMutation{State: fileState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644}, NeedsParentSync: true}
			if err := j.flush(); err != nil {
				t.Fatalf("flush pending: %v", err)
			}
			if err := os.WriteFile(target, []byte(tc.leave), 0o644); err != nil {
				t.Fatalf("stage the crash state: %v", err)
			}

			j.ReconcilePending()

			rec := onDiskRecord(t, j)
			if rec.Paths[0].Pending != nil && !tc.wantUnrecovered {
				t.Fatalf("pending = %+v, want it resolved", rec.Paths[0].Pending)
			}
			if tc.wantUnrecovered {
				if len(rec.Unrecovered) == 0 {
					t.Fatal("a third state was not reported as unrecovered")
				}
				return
			}
			if got := string(rec.Paths[0].LastKnown.Data); got != tc.wantLastKnown {
				t.Fatalf("last-known = %q, want %q", got, tc.wantLastKnown)
			}
		})
	}
}

func TestReconcilePending_RetainsWhenTheHeldParentCannotBeSynced(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)

	pr := j.record(target)
	pr.Pending = &pendingMutation{State: fileState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644}, NeedsParentSync: true}
	if err := j.flush(); err != nil {
		t.Fatalf("flush pending: %v", err)
	}
	if err := os.WriteFile(target, []byte("CHILD\n"), 0o644); err != nil {
		t.Fatalf("publish: %v", err)
	}

	parent, err := os.Open(f.project)
	if err != nil {
		t.Fatalf("open parent: %v", err)
	}
	defer parent.Close() //nolint:errcheck // read-only descriptor
	failSyncOnce(t)

	j.ResolveMutation(target, parent, filetools.JournalState{})

	rec := onDiskRecord(t, j)
	if rec.Paths[0].Pending == nil {
		t.Fatal("pending was cleared from visibility alone even though the parent sync failed")
	}
	if !rec.Paths[0].Pending.NeedsParentSync {
		t.Fatal("the pending record no longer owes a parent sync after that sync failed")
	}
	if string(rec.Paths[0].LastKnown.Data) != "ORIGINAL\n" {
		t.Fatal("last-known advanced to a state whose directory entry is not durable")
	}
	if len(rec.Unrecovered) == 0 {
		t.Fatal("a failed parent sync was not reported as unrecovered")
	}
	if len(rec.Retained) == 0 {
		t.Fatal("a failed durability retry was not recorded as durable transaction state")
	}

	// The retry failure has to survive terminal handling: the second sync here succeeds, and a
	// transaction that re-derived its outcome from that would commit and delete its own journal.
	outcome := j.Finish(ReasonCompleted)
	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained after a failed durability retry", outcome)
	}
	if got := onDiskRecord(t, j); got.Lifecycle == lifecycleCommitted {
		t.Fatal("the transaction committed despite a failed durability retry")
	}
	if _, err := os.Stat(recordPath(j)); err != nil {
		t.Fatalf("journal record: %v, want it retained", err)
	}
}

func (f *fixture) openScopes(t *testing.T, write, remove []string) *Journal {
	t.Helper()
	j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: write, DeclaredDelete: remove})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(j.Close)
	return j
}

func (f *fixture) childDelete(t *testing.T, j *Journal, target string) tools.Result {
	t.Helper()
	tool := filetools.NewDeleteTool(f.home, f.project, f.project)
	res, err := tool.InvokeWithResolvedTarget(f.ctx(j), map[string]any{"path": target}, target)
	if err != nil {
		t.Fatalf("delete %s: %v", target, err)
	}
	return res
}

func (f *fixture) mustDelete(t *testing.T, j *Journal, target string) {
	t.Helper()
	mustSucceed(t, f.childDelete(t, j, target))
	assertGone(t, target)
}

func (f *fixture) seedMode(t *testing.T, rel, content string, mode os.FileMode) string {
	t.Helper()
	path := f.seed(t, rel, content)
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", rel, err)
	}
	return path
}

func (f *fixture) dir(t *testing.T, rel string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(f.project, rel)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", rel, err)
	}
	return path
}

func (f *fixture) link(t *testing.T, rel, target string) string {
	t.Helper()
	path := filepath.Join(f.project, rel)
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s: %v", rel, err)
	}
	return path
}

func mustSucceed(t *testing.T, res tools.Result) {
	t.Helper()
	if res.ExitCode != 0 {
		t.Fatalf("tool result = %+v (stderr %q), want success", res, res.Stderr)
	}
}

func assertFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("%s = %v (err=%v), want a regular file with mode %o", path, info, err, mode)
	}
	if got := readFile(t, path); got != content {
		t.Fatalf("%s = %q, want %q", path, got, content)
	}
}

func assertDir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode {
		t.Fatalf("%s = %v (err=%v), want a directory with mode %o", path, info, err, mode)
	}
}

func assertLink(t *testing.T, path, target string) {
	t.Helper()
	got, err := os.Readlink(path)
	if err != nil || got != target {
		t.Fatalf("readlink %s = %q (err=%v), want a symlink to %q", path, got, err, target)
	}
}

func assertContent(t *testing.T, path, want string) {
	t.Helper()
	if want == "" {
		assertGone(t, path)
		return
	}
	if got := readFile(t, path); got != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func replaceFile(t *testing.T, path, content string) {
	t.Helper()
	staged := path + ".staged"
	if err := os.WriteFile(staged, []byte(content), 0o644); err != nil {
		t.Fatalf("stage replacement: %v", err)
	}
	if err := os.Chmod(staged, 0o644); err != nil {
		t.Fatalf("chmod replacement: %v", err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatalf("publish replacement: %v", err)
	}
}

func TestOpenJournal_CapturesEveryDeletePreStateByKind(t *testing.T) {
	f := newFixture(t)
	file := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	link := f.link(t, "link", "a.txt")
	empty := f.dir(t, "empty", 0o750)
	full := f.dir(t, "full", 0o711)
	f.seed(t, "full/inside.txt", "x")
	missing := filepath.Join(f.project, "missing.txt")

	j := f.openScopes(t, nil, []string{file, link, empty, full, missing})

	rec := onDiskRecord(t, j)
	if rec.SchemaVersion != journalDeleteSchemaVersion {
		t.Fatalf("schema_version = %d, want %d for a journal holding delete paths", rec.SchemaVersion, journalDeleteSchemaVersion)
	}
	want := map[string]fileState{
		file:    {Exists: true, Data: []byte("ORIGINAL\n"), Mode: 0o640},
		link:    {Exists: true, Kind: kindSymlink, Link: "a.txt"},
		empty:   {Exists: true, Kind: kindDir, Mode: 0o750},
		full:    {Exists: true, Kind: kindDir, Mode: 0o711},
		missing: {},
	}
	if len(rec.Paths) != len(want) {
		t.Fatalf("recorded paths = %d, want %d", len(rec.Paths), len(want))
	}
	for _, pr := range rec.Paths {
		if !pr.Delete {
			t.Fatalf("%s is not marked delete-declared", pr.Path)
		}
		if pr.Pre.Exists && pr.Pre.Ino == 0 {
			t.Fatalf("%s pre-state carries no identity", pr.Path)
		}
		pre := pr.Pre
		pre.Dev, pre.Ino = 0, 0
		if !reflect.DeepEqual(pre, want[pr.Path]) {
			t.Fatalf("%s pre-state = %+v, want %+v", pr.Path, pre, want[pr.Path])
		}
		if !reflect.DeepEqual(pr.LastKnown, pr.Pre) {
			t.Fatalf("%s last-known = %+v, want the captured pre-state", pr.Path, pr.LastKnown)
		}
	}

	writeOnly := f.open(t, f.seed(t, "b.txt", "B\n"))
	if got := onDiskRecord(t, writeOnly).SchemaVersion; got != journalSchemaVersion {
		t.Fatalf("write-only schema_version = %d, want the unchanged %d", got, journalSchemaVersion)
	}
}

func TestOpenJournal_RefusesADeletePathOfAKindItCannotRestore(t *testing.T) {
	f := newFixture(t)
	pipe := filepath.Join(f.project, "pipe")
	if err := unix.Mkfifo(pipe, 0o644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	_, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), DeclaredDelete: []string{pipe}})
	if err == nil || !strings.Contains(err.Error(), "not a regular file, symlink, or directory") {
		t.Fatalf("OpenJournal error = %v, want the unsupported kind refused", err)
	}
	assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
}

func TestOpenJournal_CapsTheUnionOfWriteAndDeletePaths(t *testing.T) {
	t.Run("a path in both forms counts once", func(t *testing.T) {
		f := newFixture(t)
		var paths []string
		for i := range maxDeclaredPaths {
			paths = append(paths, f.seed(t, fmt.Sprintf("f%02d.txt", i), "x"))
		}
		j := f.openScopes(t, paths, paths)
		if got := len(onDiskRecord(t, j).Paths); got != maxDeclaredPaths {
			t.Fatalf("recorded paths = %d, want %d", got, maxDeclaredPaths)
		}
	})

	t.Run("exactly the cap across both forms", func(t *testing.T) {
		f := newFixture(t)
		var write, remove []string
		for i := range maxDeclaredPaths / 2 {
			write = append(write, f.seed(t, fmt.Sprintf("w%02d.txt", i), "x"))
			remove = append(remove, f.seed(t, fmt.Sprintf("d%02d.txt", i), "x"))
		}
		f.openScopes(t, write, remove)
	})

	t.Run("one path past the cap across both forms", func(t *testing.T) {
		f := newFixture(t)
		var write, remove []string
		for i := range maxDeclaredPaths / 2 {
			write = append(write, f.seed(t, fmt.Sprintf("w%02d.txt", i), "x"))
		}
		for i := range maxDeclaredPaths/2 + 1 {
			remove = append(remove, f.seed(t, fmt.Sprintf("d%02d.txt", i), "x"))
		}
		if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: write, DeclaredDelete: remove}); err == nil {
			t.Fatalf("OpenJournal accepted %d distinct paths", len(write)+len(remove))
		}
		assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
	})

	t.Run("the per-snapshot cap is inclusive for a delete path", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			size    int
			wantErr bool
		}{
			{"exactly the cap", maxSnapshotBytesPerFile, false},
			{"one byte over", maxSnapshotBytesPerFile + 1, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t)
				target := f.seed(t, "big.bin", strings.Repeat("x", tc.size))
				j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), DeclaredDelete: []string{target}})
				if tc.wantErr {
					if err == nil {
						t.Fatal("OpenJournal accepted a delete snapshot over the per-file cap")
					}
					assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
					return
				}
				if err != nil {
					t.Fatalf("OpenJournal refused a delete snapshot at exactly the cap: %v", err)
				}
				j.Close()
			})
		}
	})

	t.Run("the aggregate snapshot cap spans both forms", func(t *testing.T) {
		f := newFixture(t)
		var write, remove []string
		for i := range 6 {
			write = append(write, f.seed(t, fmt.Sprintf("w%02d.bin", i), strings.Repeat("x", maxSnapshotBytesPerFile)))
			remove = append(remove, f.seed(t, fmt.Sprintf("d%02d.bin", i), strings.Repeat("x", maxSnapshotBytesPerFile)))
		}
		remove = append(remove, f.seed(t, "tail.bin", strings.Repeat("x", (maxSnapshotBytesTotal-12*maxSnapshotBytesPerFile)+1)))
		if _, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: write, DeclaredDelete: remove}); err == nil {
			t.Fatal("OpenJournal accepted write and delete snapshots over the aggregate cap")
		}
		assertGone(t, filepath.Join(f.home, ".codemeld", journalsDirName))
	})
}

func TestJournalDelete_RefusesAnIntentWhoseRecordWouldPassTheLimit(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.openScopes(t, nil, []string{target})
	pr := j.record(target)
	pr.Pending = &pendingMutation{NeedsParentSync: true}
	withIntent, err := json.Marshal(&j.rec)
	pr.Pending = nil
	if err != nil {
		t.Fatalf("marshal the record with its intent: %v", err)
	}
	original := maxJournalBytes
	t.Cleanup(func() { maxJournalBytes = original })

	maxJournalBytes = len(withIntent) - 1
	if res := f.childDelete(t, j, target); res.ExitCode == 0 {
		t.Fatalf("delete = %+v, want the intent refused one byte over the record limit", res)
	}
	if got := readFile(t, target); got != "ORIGINAL\n" {
		t.Fatalf("%s = %q, want nothing deleted when the intent could not be persisted", target, got)
	}

	maxJournalBytes = len(withIntent)
	f.mustDelete(t, j, target)
}

func TestJournalDelete_ExpectedAbsenceIsDurableBeforeTheUnlinkAndAdvancesAfterTheParentSync(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.openScopes(t, nil, []string{target})

	var presentAtIntent bool
	onJournalStep(t, "pending", func() {
		_, err := os.Lstat(target)
		presentAtIntent = err == nil
	})
	var synced, goneAtSync, pendingAtSync bool
	syncTargetParent = func(dir *os.File) error {
		if !synced {
			synced = true
			_, err := os.Lstat(target)
			goneAtSync = os.IsNotExist(err)
			pendingAtSync = onDiskRecord(t, j).Paths[0].Pending != nil
		}
		return dir.Sync()
	}
	t.Cleanup(func() { syncTargetParent = (*os.File).Sync })

	f.mustDelete(t, j, target)

	if !presentAtIntent {
		t.Fatal("the entry was already gone when expected absence was recorded")
	}
	if !synced || !goneAtSync || !pendingAtSync {
		t.Fatalf("parent sync ran=%v with the entry gone=%v and the durable intent still pending=%v, want all true", synced, goneAtSync, pendingAtSync)
	}
	if pr := onDiskRecord(t, j).Paths[0]; pr.Pending != nil || pr.LastKnown.Exists {
		t.Fatalf("record = %+v, want last-known absence after the sync", pr)
	}
}

func TestJournalDelete_AParentSyncFailureRetainsThePendingDeletion(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.openScopes(t, nil, []string{target})
	failSyncOnce(t)

	f.mustDelete(t, j, target)

	if rec := onDiskRecord(t, j); rec.Paths[0].Pending == nil || len(rec.Retained) == 0 {
		t.Fatalf("record = %+v, want the deletion still pending with the durability failure retained", rec)
	}
	outcome := j.Finish(ReasonCompleted)
	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained as unrecovered", outcome)
	}
	assertRecordPresent(t, j)
}

func TestJournalDelete_AReplacementVisibleBeforeTheComparisonSurvives(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"the same bytes on a new inode", "ORIGINAL\n"},
		{"different bytes", "THIRD PARTY\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.openScopes(t, nil, []string{target})
			replaceFile(t, target, tc.content)

			res := f.childDelete(t, j, target)

			if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "changed outside the child agent") {
				t.Fatalf("delete = %+v, want it refused for an entry replaced after the snapshot", res)
			}
			if got := readFile(t, target); got != tc.content {
				t.Fatalf("%s = %q, want the replacement %q to survive", target, got, tc.content)
			}
			if pr := onDiskRecord(t, j).Paths[0]; pr.Pending != nil {
				t.Fatalf("record = %+v, want no intent recorded for a refused delete", pr)
			}
		})
	}
}

func TestJournalDelete_AReplacementAfterTheComparisonIsNotDetected(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.openScopes(t, nil, []string{target})
	onJournalStep(t, "pending", func() { replaceFile(t, target, "THIRD PARTY\n") })

	f.mustDelete(t, j, target)

	rec := onDiskRecord(t, j)
	if pr := rec.Paths[0]; pr.Pending != nil || pr.LastKnown.Exists || len(rec.Unrecovered) != 0 {
		t.Fatalf("record = %+v, want the replacement's removal read as the child's own delete", rec)
	}
}

func TestJournalDelete_ANonEmptyDirectoryIsStillRefused(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "tree", 0o755)
	inside := f.seed(t, "tree/inside.txt", "STAYS\n")
	j := f.openScopes(t, nil, []string{tree})

	res := f.childDelete(t, j, tree)

	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "non-empty directory") {
		t.Fatalf("delete = %+v, want the kernel's non-empty refusal", res)
	}
	if got := readFile(t, inside); got != "STAYS\n" {
		t.Fatalf("%s = %q, want the directory's contents intact", inside, got)
	}
	if pr := onDiskRecord(t, j).Paths[0]; pr.Pending != nil {
		t.Fatalf("record = %+v, want the abandoned intent cleared", pr)
	}
	if outcome := j.Finish(ReasonCompleted); len(outcome.Unrecovered) != 0 || outcome.JournalPath != "" {
		t.Fatalf("outcome = %+v, want a clean commit", outcome)
	}
}

func TestJournalRollback_RestoresDeletedFilesByteIdenticalWithTheirModes(t *testing.T) {
	f := newFixture(t)
	first := f.seedMode(t, "first.txt", "FIRST ORIGINAL\n", 0o640)
	second := f.seedMode(t, "bin/second.sh", "#!/bin/sh\necho second\n", 0o755)
	j := f.openScopes(t, nil, []string{first, second})
	f.mustDelete(t, j, first)
	f.mustDelete(t, j, second)

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	assertFile(t, first, "FIRST ORIGINAL\n", 0o640)
	assertFile(t, second, "#!/bin/sh\necho second\n", 0o755)
	if !slices.Contains(outcome.Restored, first) || !slices.Contains(outcome.Restored, second) {
		t.Fatalf("restored = %v, want both deleted files named", outcome.Restored)
	}
	assertGone(t, j.Path())
}

func TestJournalRollback_RestoresDeletedSymlinksAndDirectoriesByKind(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "real.txt", "REAL\n")
	link := f.link(t, "link", "real.txt")
	empty := f.dir(t, "empty", 0o750)
	tree := f.dir(t, "tree", 0o711)
	inner := f.dir(t, "tree/inner", 0o700)
	leaf := f.seedMode(t, "tree/inner/leaf.txt", "LEAF\n", 0o600)
	never := filepath.Join(f.project, "never.txt")
	j := f.openScopes(t, nil, []string{link, empty, tree, inner, leaf, never})
	for _, path := range []string{link, empty, leaf, inner, tree} {
		f.mustDelete(t, j, path)
	}

	descendantsChecked := 0
	beforeJournalStep = func(step string) error {
		if step != "restoring" {
			return nil
		}
		onDisk := recordIn(t, j.Path())
		for i := range j.rec.Paths {
			starting := j.rec.Paths[i]
			if starting.Progress != rollbackRestoring || onDisk.Paths[i].Progress == rollbackRestoring {
				continue
			}
			for _, d := range onDisk.Paths {
				if d.Pre.Kind != kindDir || !strings.HasPrefix(starting.Path, d.Path+string(filepath.Separator)) {
					continue
				}
				descendantsChecked++
				if d.ReplacementIno == 0 {
					t.Errorf("%s began restoring before the recreated %s was durably identified", starting.Path, d.Path)
				}
			}
		}
		return nil
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	if descendantsChecked < 3 {
		t.Fatalf("descendant restores checked = %d, want inner and leaf checked against their recreated ancestors", descendantsChecked)
	}
	assertLink(t, link, "real.txt")
	assertDir(t, empty, 0o750)
	assertDir(t, tree, 0o711)
	assertDir(t, inner, 0o700)
	assertFile(t, leaf, "LEAF\n", 0o600)
	assertGone(t, never)
	assertGone(t, j.Path())
}

func TestJournalRollback_RestoresNothingThroughADirectoryItDidNotRecreate(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "tree", 0o755)
	leaf := f.seed(t, "tree/leaf.txt", "LEAF\n")
	j := f.openScopes(t, nil, []string{tree, leaf})
	f.mustDelete(t, j, leaf)
	f.mustDelete(t, j, tree)
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatalf("plant a stranger's directory: %v", err)
	}
	if err := os.Chmod(tree, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained", outcome)
	}
	assertGone(t, leaf)
}

func TestJournalRollback_ResumesAKindChangingRestoreFromTheEmptySlotItLeft(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "real.txt", "REAL\n")
	link := f.link(t, "link", "real.txt")
	j := f.openScopes(t, []string{link}, []string{link})
	f.mustDelete(t, j, link)
	mustSucceed(t, f.childCreate(t, j, link, "CHILD\n"))
	j.record(link).Progress = rollbackRestoring
	if err := j.flush(); err != nil {
		t.Fatalf("flush the interrupted restore: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatalf("remove the child's file as the interrupted pass had: %v", err)
	}

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want the resumed restore to complete", outcome.Unrecovered)
	}
	assertLink(t, link, "real.txt")
	assertGone(t, j.Path())
}

func TestJournalRollback_DescendsOnlyThroughARecreatedDirectoryWhoseIdentityIsDurable(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "tree", 0o755)
	leaf := f.seed(t, "tree/leaf.txt", "LEAF\n")
	j := f.openScopes(t, nil, []string{tree, leaf})
	f.mustDelete(t, j, leaf)
	f.mustDelete(t, j, tree)
	crashAt(t, "dir_recreated")

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained", outcome)
	}
	assertGone(t, leaf)
	if pr := onDiskRecord(t, j).Paths[0]; pr.ReplacementIno != 0 {
		t.Fatalf("record = %+v, want no replacement identity the failed step never made durable", pr)
	}
}

func TestJournalRollback_AdoptsNoDirectorySwappedInBeforeTheRecreatedOneIsOpened(t *testing.T) {
	cases := []struct {
		name  string
		mode  os.FileMode
		plant func(t *testing.T, stranger string)
	}{
		{name: "holding entries", mode: 0o755, plant: func(t *testing.T, stranger string) {
			if err := os.WriteFile(filepath.Join(stranger, "theirs.txt"), []byte("THEIRS\n"), 0o644); err != nil {
				t.Fatalf("seed the stranger's directory: %v", err)
			}
		}},
		{name: "granting wider permissions", mode: 0o777, plant: func(*testing.T, string) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tree := f.dir(t, "tree", 0o755)
			leaf := f.seed(t, "tree/leaf.txt", "LEAF\n")
			j := f.openScopes(t, nil, []string{tree, leaf})
			f.mustDelete(t, j, leaf)
			f.mustDelete(t, j, tree)
			stranger := filepath.Join(realDir(t, t.TempDir()), "stranger")
			if err := os.Mkdir(stranger, 0o755); err != nil {
				t.Fatalf("make the stranger's directory: %v", err)
			}
			tc.plant(t, stranger)
			if err := os.Chmod(stranger, tc.mode); err != nil {
				t.Fatalf("chmod the stranger's directory: %v", err)
			}
			afterRecreateMkdir = func() {
				if err := os.Remove(tree); err != nil {
					t.Errorf("remove the recreated directory: %v", err)
					return
				}
				if err := os.Rename(stranger, tree); err != nil {
					t.Errorf("swap in the stranger's directory: %v", err)
				}
			}
			t.Cleanup(func() { afterRecreateMkdir = func() {} })

			outcome := j.Finish(ReasonCancelled)

			if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
				t.Fatalf("outcome = %+v, want the journal retained", outcome)
			}
			assertDir(t, tree, tc.mode)
			assertGone(t, leaf)
			if pr := onDiskRecord(t, j).Paths[0]; pr.ReplacementIno != 0 {
				t.Fatalf("record = %+v, want the stranger's directory never recorded as the rollback's", pr)
			}
		})
	}
}

// escapeRecreatedDir fires once the rollback has recreated tree, before any descendant is restored:
// it moves the recreated directory out of the project and plants a symlink to it in place of tree's parent.
func escapeRecreatedDir(t *testing.T, tree string) (outside string) {
	t.Helper()
	outside = realDir(t, t.TempDir())
	parent := filepath.Dir(tree)
	onJournalStep(t, "restored", func() {
		if err := os.Rename(tree, filepath.Join(outside, filepath.Base(tree))); err != nil {
			t.Errorf("move the recreated directory out of the project: %v", err)
			return
		}
		if err := os.Remove(parent); err != nil {
			t.Errorf("remove the emptied parent: %v", err)
			return
		}
		if err := os.Symlink(outside, parent); err != nil {
			t.Errorf("plant the symlink: %v", err)
		}
	})
	return outside
}

func TestJournalRollback_RestoresNothingThroughASymlinkPlantedAboveARecreatedDirectory(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "a/tree", 0o755)
	leaf := f.seed(t, "a/tree/leaf.txt", "LEAF\n")
	j := f.openScopes(t, nil, []string{tree, leaf})
	f.mustDelete(t, j, leaf)
	f.mustDelete(t, j, tree)
	outside := escapeRecreatedDir(t, tree)

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained", outcome)
	}
	assertGone(t, filepath.Join(outside, "tree", "leaf.txt"))
	assertRecordPresent(t, j)
}

// moveOutOfProjectAt relocates rel to a directory outside the project just before the named boundary is
// flushed, which is after the rollback opened its parent descriptor and before it acts through it.
func (f *fixture) moveOutOfProjectAt(t *testing.T, label, rel string) (escaped string) {
	t.Helper()
	escaped = filepath.Join(realDir(t, t.TempDir()), filepath.Base(rel))
	onJournalStep(t, label, func() {
		if err := os.Rename(filepath.Join(f.project, rel), escaped); err != nil {
			t.Errorf("move %s out of the project: %v", rel, err)
		}
	})
	return escaped
}

func TestJournalRollback_ReversesAMoveUndoneThroughAParentMovedOutOfTheProject(t *testing.T) {
	f := newFixture(t)
	source := f.seed(t, "sub/a.txt", "ORIGINAL\n")
	destination := filepath.Join(f.project, "sub", "b.txt")
	j := f.openMoves(t, nil, pairOf(source, destination))
	f.mustMove(t, j, source, destination)
	escaped := f.moveOutOfProjectAt(t, "move_undoing", "sub")

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained", outcome)
	}
	assertContent(t, filepath.Join(escaped, "b.txt"), "ORIGINAL\n")
	assertGone(t, filepath.Join(escaped, "a.txt"))
	assertRecordPresent(t, j)
}

func TestJournalRollback_RetainsTheJournalWhenARestoredPathsParentMovesOutOfTheProject(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "made", "x.txt")
	j := f.open(t, target)
	mustSucceed(t, f.childCreate(t, j, target, "CHILD\n"))
	f.moveOutOfProjectAt(t, "restoring", "made")

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained rather than a restore recorded outside the project", outcome)
	}
	assertRecordPresent(t, j)
}

func TestJournalRollback_RetainsTheJournalWhenACreatedDirectorysParentMovesOutOfTheProject(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "made", "deeper", "x.txt")
	j := f.open(t, target)
	mustSucceed(t, f.childCreate(t, j, target, "CHILD\n"))
	f.moveOutOfProjectAt(t, "dir_restoring", "made")

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained rather than a directory removal recorded outside the project", outcome)
	}
	assertRecordPresent(t, j)
}

type sameContentReplacement struct {
	name    string
	seed    func(t *testing.T, f *fixture) string
	replace func(t *testing.T, target string)
}

var sameContentReplacements = []sameContentReplacement{
	{
		name: "regular file",
		seed: func(t *testing.T, f *fixture) string { return f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640) },
		replace: func(t *testing.T, target string) {
			if err := os.WriteFile(target, []byte("ORIGINAL\n"), 0o640); err != nil {
				t.Fatalf("recreate the file: %v", err)
			}
			if err := os.Chmod(target, 0o640); err != nil {
				t.Fatalf("chmod: %v", err)
			}
		},
	},
	{
		name: "symlink",
		seed: func(t *testing.T, f *fixture) string {
			f.seed(t, "real.txt", "REAL\n")
			return f.link(t, "link", "real.txt")
		},
		replace: func(t *testing.T, target string) {
			if err := os.Symlink("real.txt", target); err != nil {
				t.Fatalf("recreate the symlink: %v", err)
			}
		},
	},
	{
		name: "directory",
		seed: func(t *testing.T, f *fixture) string { return f.dir(t, "empty", 0o750) },
		replace: func(t *testing.T, target string) {
			if err := os.Mkdir(target, 0o750); err != nil {
				t.Fatalf("recreate the directory: %v", err)
			}
			if err := os.Chmod(target, 0o750); err != nil {
				t.Fatalf("chmod: %v", err)
			}
		},
	},
}

// replaceDeleted deletes target through the child, lets a third party recreate it identically, and
// returns what that third party left.
func (f *fixture) replaceDeleted(t *testing.T, j *Journal, tc sameContentReplacement, target string) os.FileInfo {
	t.Helper()
	f.mustDelete(t, j, target)
	tc.replace(t, target)
	replaced, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat the replacement: %v", err)
	}
	return replaced
}

func assertSameEntry(t *testing.T, path string, want os.FileInfo) {
	t.Helper()
	got, err := os.Lstat(path)
	if err != nil || !os.SameFile(got, want) {
		t.Fatalf("%s = %v (err=%v), want the replacement left in place", path, got, err)
	}
}

type entrySnapshot struct {
	path     string
	info     os.FileInfo
	data     string
	children []entrySnapshot
}

func lstatEntry(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		return info
	case os.IsNotExist(err), errors.Is(err, syscall.ENOTDIR):
		return nil
	default:
		t.Fatalf("lstat %s: %v", path, err)
		return nil
	}
}

func captureEntries(t *testing.T, paths ...string) []entrySnapshot {
	t.Helper()
	captured := make([]entrySnapshot, 0, len(paths))
	for _, path := range paths {
		captured = append(captured, captureEntry(t, path))
	}
	return captured
}

func captureEntry(t *testing.T, path string) entrySnapshot {
	t.Helper()
	snap := entrySnapshot{path: path, info: lstatEntry(t, path)}
	switch {
	case snap.info == nil:
	case snap.info.Mode().IsRegular():
		snap.data = readFile(t, path)
	case snap.info.IsDir():
		for _, name := range dirNames(t, path) {
			snap.children = append(snap.children, captureEntry(t, filepath.Join(path, name)))
		}
	}
	return snap
}

func dirNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func entryContent(snap entrySnapshot, rel string) string {
	described := fmt.Sprintf("%s %v %q", rel, snap.info.Mode(), snap.data)
	for _, child := range snap.children {
		described += "\n" + entryContent(child, filepath.Join(rel, filepath.Base(child.path)))
	}
	return described
}

func assertEntriesUnchanged(t *testing.T, captured []entrySnapshot) {
	t.Helper()
	for _, snap := range captured {
		assertEntryUnchanged(t, snap)
	}
}

func assertEntryUnchanged(t *testing.T, snap entrySnapshot) {
	t.Helper()
	got := lstatEntry(t, snap.path)
	if snap.info == nil {
		if got != nil {
			t.Fatalf("%s = %v, want the absence it held before", snap.path, got)
		}
		return
	}
	assertSameEntry(t, snap.path, snap.info)
	if got.Mode() != snap.info.Mode() {
		t.Fatalf("%s mode = %v, want the %v it held before", snap.path, got.Mode(), snap.info.Mode())
	}
	switch {
	case snap.info.Mode().IsRegular():
		if data := readFile(t, snap.path); data != snap.data {
			t.Fatalf("%s = %q, want the %q it held before", snap.path, data, snap.data)
		}
	case snap.info.IsDir():
		want := make([]string, 0, len(snap.children))
		for _, child := range snap.children {
			want = append(want, filepath.Base(child.path))
		}
		if names := dirNames(t, snap.path); !slices.Equal(names, want) {
			t.Fatalf("%s holds %v, want the %v it held before", snap.path, names, want)
		}
		for _, child := range snap.children {
			assertEntryUnchanged(t, child)
		}
	}
}

func TestJournalRollback_LeavesASameContentReplacementOfADeletedPath(t *testing.T) {
	for _, tc := range sameContentReplacements {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			replaced := f.replaceDeleted(t, j, tc, target)

			outcome := j.Finish(ReasonCancelled)

			if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
				t.Fatalf("outcome = %+v, want the journal retained", outcome)
			}
			assertSameEntry(t, target, replaced)
			assertRecordPresent(t, j)
		})
	}
}

// interruptRestore leaves the record a crash after the restore act and its parent sync, but before the
// `restored` step, would leave. A failed step alone cannot produce it: the failing pass flushes its
// in-memory progress on the way out.
func interruptRestore(t *testing.T, j *Journal, finish func()) {
	t.Helper()
	crashAt(t, "restored")
	finish()
	rewriteRecord(t, j, func(rec *journalRecord) { rec.Paths[0].Progress = rollbackRestoring })
	if pr := onDiskRecord(t, j).Paths[0]; pr.ReplacementIno == 0 {
		t.Fatalf("record = %+v, want the restored entry's identity recorded", pr)
	}
}

// swapInSameContent builds the identical entry beside target before renaming it over, so the
// replacement cannot reuse the inode number of the entry it displaces.
func swapInSameContent(t *testing.T, tc sameContentReplacement, target string) os.FileInfo {
	t.Helper()
	displaced, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat the restored entry: %v", err)
	}
	staged := target + ".third-party"
	tc.replace(t, staged)
	if displaced.IsDir() {
		if err := os.Remove(target); err != nil {
			t.Fatalf("remove the restored directory: %v", err)
		}
	}
	if err := os.Rename(staged, target); err != nil {
		t.Fatalf("swap in the replacement: %v", err)
	}
	replaced, err := os.Lstat(target)
	if err != nil || os.SameFile(replaced, displaced) {
		t.Fatalf("replacement = %v (err=%v), want an entry other than the restored one", replaced, err)
	}
	return replaced
}

func TestJournalRollback_ResumesAnInterruptedRestoreOnlyThroughTheEntryItPublished(t *testing.T) {
	for _, tc := range sameContentReplacements {
		t.Run(tc.name+" left in place", func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			f.mustDelete(t, j, target)
			interruptRestore(t, j, func() { j.Finish(ReasonCancelled) })
			restored, err := os.Lstat(target)
			if err != nil {
				t.Fatalf("lstat the restored entry: %v", err)
			}

			resumeFromDisk(t, j)
			outcome := j.Finish(ReasonCancelled)

			if len(outcome.Unrecovered) != 0 {
				t.Fatalf("unrecovered = %v, want the resumed restore to complete", outcome.Unrecovered)
			}
			assertSameEntry(t, target, restored)
			assertGone(t, j.Path())
		})
		t.Run(tc.name+" replaced with the same content", func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			f.mustDelete(t, j, target)
			interruptRestore(t, j, func() { j.Finish(ReasonCancelled) })
			replaced := swapInSameContent(t, tc, target)

			resumeFromDisk(t, j)
			outcome := j.Finish(ReasonCancelled)

			if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
				t.Fatalf("outcome = %+v, want the journal retained", outcome)
			}
			assertSameEntry(t, target, replaced)
			assertRecordPresent(t, j)
		})
	}
}

type unprovenRestore struct {
	name      string
	seed      func(t *testing.T, f *fixture) string
	interrupt func(t *testing.T)
}

var unprovenRestores = []unprovenRestore{
	{
		name:      "regular file identity record",
		seed:      func(t *testing.T, f *fixture) string { return f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640) },
		interrupt: func(t *testing.T) { crashAt(t, "restore_published") },
	},
	{
		name: "symlink identity record",
		seed: func(t *testing.T, f *fixture) string {
			f.seed(t, "real.txt", "REAL\n")
			return f.link(t, "link", "real.txt")
		},
		interrupt: func(t *testing.T) { crashAt(t, "restore_published") },
	},
	{
		name:      "directory identity record",
		seed:      func(t *testing.T, f *fixture) string { return f.dir(t, "empty", 0o750) },
		interrupt: func(t *testing.T) { crashAt(t, "dir_recreated") },
	},
	{
		name:      "directory sync",
		seed:      func(t *testing.T, f *fixture) string { return f.dir(t, "empty", 0o750) },
		interrupt: func(t *testing.T) { failSyncCalls(t, 1) },
	},
}

func TestJournalRollback_RetainsARestoreWhoseIdentityNeverBecameDurable(t *testing.T) {
	for _, tc := range unprovenRestores {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			f.mustDelete(t, j, target)
			tc.interrupt(t)
			if outcome := j.Finish(ReasonCancelled); outcome.JournalPath == "" {
				t.Fatalf("outcome = %+v, want the interrupted pass to retain the journal", outcome)
			}
			left, err := os.Lstat(target)
			if err != nil {
				t.Fatalf("lstat the entry the interrupted pass left: %v", err)
			}

			resumeFromDisk(t, j)
			outcome := j.Finish(ReasonCancelled)

			if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
				t.Fatalf("outcome = %+v, want the journal retained", outcome)
			}
			assertSameEntry(t, target, left)
			assertRecordPresent(t, j)
			if pr := onDiskRecord(t, j).Paths[0]; pr.Progress == rollbackRestored || pr.ReplacementIno != 0 {
				t.Fatalf("record = %+v, want an unfinished restore naming no entry", pr)
			}
		})
	}
}

func TestJournalCommit_ACompletedDeleteStandsAndLeavesNoJournal(t *testing.T) {
	f := newFixture(t)
	file := f.seed(t, "a.txt", "A\n")
	tree := f.dir(t, "tree", 0o755)
	leaf := f.seed(t, "tree/leaf.txt", "LEAF\n")
	j := f.openScopes(t, nil, []string{file, tree, leaf})
	f.mustDelete(t, j, file)
	f.mustDelete(t, j, leaf)
	f.mustDelete(t, j, tree)

	if outcome := j.Finish(ReasonCompleted); len(outcome.Unrecovered) != 0 || outcome.JournalPath != "" {
		t.Fatalf("outcome = %+v, want a clean commit", outcome)
	}
	assertGone(t, file)
	assertGone(t, tree)
	assertGone(t, j.Path())
}

type deleteSequence struct {
	name          string
	seeded        bool
	run           func(t *testing.T, f *fixture, j *Journal, target string)
	wantCompleted string
}

var deleteSequences = []deleteSequence{
	{
		name: "create then delete",
		run: func(t *testing.T, f *fixture, j *Journal, target string) {
			mustSucceed(t, f.childCreate(t, j, target, "CHILD\n"))
			f.mustDelete(t, j, target)
		},
	},
	{
		name:   "edit then delete",
		seeded: true,
		run: func(t *testing.T, f *fixture, j *Journal, target string) {
			mustSucceed(t, f.childEdit(t, j, target, "ORIGINAL", "CHILD"))
			f.mustDelete(t, j, target)
		},
	},
	{
		name:   "delete then create",
		seeded: true,
		run: func(t *testing.T, f *fixture, j *Journal, target string) {
			f.mustDelete(t, j, target)
			mustSucceed(t, f.childCreate(t, j, target, "CHILD\n"))
		},
		wantCompleted: "CHILD\n",
	},
}

func (s deleteSequence) preState() string {
	if s.seeded {
		return "ORIGINAL\n"
	}
	return ""
}

func TestJournalSequences_KeepOnePerPathHistoryAcrossCreateEditAndDelete(t *testing.T) {
	for _, seq := range deleteSequences {
		for _, reason := range []Reason{ReasonCancelled, ReasonCompleted} {
			t.Run(seq.name+"/"+string(reason), func(t *testing.T) {
				f := newFixture(t)
				target := filepath.Join(f.project, "a.txt")
				if seq.seeded {
					f.seed(t, "a.txt", seq.preState())
				}
				j := f.openScopes(t, []string{target}, []string{target})
				seq.run(t, f, j, target)

				outcome := j.Finish(reason)

				if len(outcome.Unrecovered) != 0 {
					t.Fatalf("unrecovered = %v, want a clean outcome", outcome.Unrecovered)
				}
				want := seq.preState()
				if reason == ReasonCompleted {
					want = seq.wantCompleted
				}
				assertContent(t, target, want)
				assertGone(t, j.Path())
			})
		}
	}
}

func failSyncOnce(t *testing.T) {
	t.Helper()
	failSyncCalls(t, 1)
}

// failSyncCalls fails the numbered parent syncs and performs the real one on every other call, so a
// durability failure can be aimed at one specific fsync in a rollback that makes several — and held
// across a resumed pass, which is the only way to tell a retried sync from a skipped one.
func failSyncCalls(t *testing.T, fail ...int) {
	t.Helper()
	failed := make(map[int]bool, len(fail))
	for _, n := range fail {
		failed[n] = true
	}
	call := 0
	syncTargetParent = func(f *os.File) error {
		call++
		if failed[call] {
			return errors.New("forced parent sync failure")
		}
		return f.Sync()
	}
	t.Cleanup(func() { syncTargetParent = (*os.File).Sync })
}

// failAfterSyncOnce performs the first parent sync for real and only then reports it failed, so a
// pass is interrupted after that durability landed rather than before it.
func failAfterSyncOnce(t *testing.T) {
	t.Helper()
	interrupted := false
	syncTargetParent = func(f *os.File) error {
		if err := f.Sync(); err != nil {
			return err
		}
		if interrupted {
			return nil
		}
		interrupted = true
		return errors.New("forced interruption after the parent sync landed")
	}
	t.Cleanup(func() { syncTargetParent = (*os.File).Sync })
}

// TestJournalRollback_RetainsWhenARestoredEntryCannotBeMadeDurable pins the gate a resumed rollback
// depends on: a restore is only recorded as done once the directory entry it published is durable.
func TestJournalRollback_RetainsWhenARestoredEntryCannotBeMadeDurable(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")

	failSyncOnce(t)
	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained when the restore could not be made durable", outcome)
	}
	if rec := onDiskRecord(t, j); rec.Paths[0].Progress == rollbackRestored {
		t.Fatal("the rollback was recorded as restored before its directory entry was durable")
	}

	resumeFromDisk(t, j)
	if outcome := j.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want the resumed rollback to complete", outcome.Unrecovered)
	}
	if got := readFile(t, target); got != "ORIGINAL\n" {
		t.Fatalf("%s = %q, want its pre-run bytes", target, got)
	}
	assertGone(t, j.Path())
}

func TestJournalFinish_RollsBackEveryTerminalReasonThatIsNotCompletion(t *testing.T) {
	for _, reason := range []Reason{ReasonCancelled, ReasonStepCap, ReasonFailed} {
		t.Run(string(reason), func(t *testing.T) {
			f := newFixture(t)
			first := f.seed(t, "a.txt", "FIRST ORIGINAL\n")
			second := f.seed(t, "b.txt", "SECOND ORIGINAL\n")
			third := f.seed(t, "c.txt", "THIRD ORIGINAL\n")
			created := filepath.Join(f.project, "made/up/new.txt")
			j := f.open(t, first, second, third, created)

			f.childEdit(t, j, first, "FIRST", "CHILD")
			f.childEdit(t, j, second, "SECOND", "CHILD")
			f.childCreate(t, j, created, "CHILD MADE THIS\n")

			outcome := j.Finish(reason)

			if len(outcome.Unrecovered) != 0 {
				t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
			}
			if got := readFile(t, first); got != "FIRST ORIGINAL\n" {
				t.Fatalf("%s = %q, want its pre-run bytes", first, got)
			}
			if got := readFile(t, second); got != "SECOND ORIGINAL\n" {
				t.Fatalf("%s = %q, want its pre-run bytes", second, got)
			}
			if got := readFile(t, third); got != "THIRD ORIGINAL\n" {
				t.Fatalf("%s = %q, want the untouched file left alone", third, got)
			}
			assertGone(t, created)
			assertGone(t, filepath.Join(f.project, "made/up"))
			assertGone(t, filepath.Join(f.project, "made"))
			assertGone(t, j.Path())
			if !strings.Contains(strings.Join(outcome.Restored, ","), first) {
				t.Fatalf("restored = %v, want it to name the files put back", outcome.Restored)
			}
		})
	}
}

func TestJournalRollback_LeavesADirectoryItDidNotEmpty(t *testing.T) {
	f := newFixture(t)
	created := filepath.Join(f.project, "made/new.txt")
	j := f.open(t, created)
	f.childCreate(t, j, created, "CHILD\n")

	keep := filepath.Join(f.project, "made", "someone-else.txt")
	if err := os.WriteFile(keep, []byte("not mine\n"), 0o644); err != nil {
		t.Fatalf("seed foreign file: %v", err)
	}

	if outcome := j.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	assertGone(t, created)
	if got := readFile(t, keep); got != "not mine\n" {
		t.Fatalf("foreign file = %q, want it retained", got)
	}
}

func TestJournalRollback_LeavesAReplacedCreatedDirectory(t *testing.T) {
	f := newFixture(t)
	created := filepath.Join(f.project, "made/new.txt")
	j := f.open(t, created)
	f.childCreate(t, j, created, "CHILD\n")

	made := filepath.Join(f.project, "made")
	// The swap has to land after the created file is removed and before the directory sweep runs,
	// which is the one window in which the recorded inode can still be replaced.
	onJournalStep(t, "restored", func() {
		if err := os.Remove(made); err != nil {
			t.Fatalf("remove the created directory: %v", err)
		}
		if err := os.Mkdir(made, 0o755); err != nil {
			t.Fatalf("plant a replacement directory: %v", err)
		}
	})

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) == 0 || outcome.JournalPath == "" {
		t.Fatalf("outcome = %+v, want the replaced directory reported and the journal retained", outcome)
	}
	if _, err := os.Lstat(made); err != nil {
		t.Fatalf("%s: %v, want another writer's directory left alone", made, err)
	}
}

func TestJournalCommit_KeepsTheChildsWorkAndRemovesTheJournal(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	created := filepath.Join(f.project, "made/new.txt")
	j := f.open(t, target, created)

	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	f.childCreate(t, j, created, "CHILD MADE THIS\n")

	outcome := j.Finish(ReasonCompleted)

	if len(outcome.Unrecovered) != 0 || outcome.JournalPath != "" {
		t.Fatalf("outcome = %+v, want a clean commit", outcome)
	}
	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want the child's result", target, got)
	}
	if got := readFile(t, created); got != "CHILD MADE THIS\n" {
		t.Fatalf("%s = %q, want the child's result", created, got)
	}
	assertGone(t, j.Path())
}

func TestJournalCommit_RetainsAPathChangedWithoutAJournalCallback(t *testing.T) {
	cases := []struct {
		name  string
		mutex func(t *testing.T, target string)
	}{
		{"a structured VCS subprocess writes with no callback", func(t *testing.T, target string) {
			if err := os.WriteFile(target, []byte("HOOK REWROTE THIS\n"), 0o644); err != nil {
				t.Fatalf("simulated subprocess write: %v", err)
			}
		}},
		{"an outside writer changes a path the child never touched", func(t *testing.T, target string) {
			if err := os.WriteFile(target, []byte("OUTSIDE\n"), 0o644); err != nil {
				t.Fatalf("external write: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)
			tc.mutex(t, target)

			outcome := j.Finish(ReasonCompleted)

			if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
				t.Fatalf("outcome = %+v, want a retained journal naming the path", outcome)
			}
			if !strings.Contains(strings.Join(outcome.Unrecovered, "|"), target) {
				t.Fatalf("unrecovered = %v, want it to name %s", outcome.Unrecovered, target)
			}
			if _, err := os.Stat(recordPath(j)); err != nil {
				t.Fatalf("journal record: %v, want it retained", err)
			}
			if rec := onDiskRecord(t, j); rec.Lifecycle == lifecycleCommitted {
				t.Fatal("the journal was committed despite an unreconciled path")
			}
		})
	}
}

func TestJournalCommit_RetainsAnUnconfirmedDirectoryIntent(t *testing.T) {
	f := newFixture(t)
	created := filepath.Join(f.project, "made/new.txt")
	j := f.open(t, created)

	if err := j.DirLifecycle(created, f.project).Intent("made"); err != nil {
		t.Fatalf("record the intent: %v", err)
	}

	outcome := j.Finish(ReasonCompleted)
	if outcome.JournalPath == "" {
		t.Fatalf("outcome = %+v, want the journal retained for an unconfirmed intent", outcome)
	}
	if _, err := os.Stat(recordPath(j)); err != nil {
		t.Fatalf("journal record: %v, want it retained", err)
	}
}

// TestJournalCommit_RetainsADirectoryConfirmationThatCouldNotBePersisted pins the durable side of a
// directory intent: a confirmation whose flush failed leaves the live record unconfirmed too, so
// completion cannot read it as settled and delete the journal over a directory the child materialized.
func TestJournalCommit_RetainsADirectoryConfirmationThatCouldNotBePersisted(t *testing.T) {
	f := newFixture(t)
	created := filepath.Join(f.project, "made/new.txt")
	j := f.open(t, created)

	crashAt(t, "dir_confirm")
	if res := f.childCreate(t, j, created, "CHILD\n"); res.ExitCode == 0 {
		t.Fatal("create succeeded even though its directory confirmation could not be persisted")
	}

	if rec := onDiskRecord(t, j); len(rec.Paths[0].Dirs) == 0 || rec.Paths[0].Dirs[0].Confirmed {
		t.Fatalf("durable dirs = %+v, want the intent left unconfirmed", rec.Paths[0].Dirs)
	}
	if dirs := j.record(created).Dirs; len(dirs) == 0 || dirs[0].Confirmed {
		t.Fatalf("live dirs = %+v, want the failed confirmation taken back in memory too", dirs)
	}

	outcome := j.Finish(ReasonCompleted)
	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained for an unconfirmed intent", outcome)
	}
	if _, err := os.Stat(recordPath(j)); err != nil {
		t.Fatalf("journal record: %v, want it retained", err)
	}
}

func TestJournalCommit_FlushesTheCommittedMarkerBeforeCleanup(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")

	crashAt(t, "committed")
	outcome := j.Finish(ReasonCompleted)
	if outcome.JournalPath == "" {
		t.Fatalf("outcome = %+v, want the journal retained when the committed marker never landed", outcome)
	}
	if rec := onDiskRecord(t, j); rec.Lifecycle == lifecycleCommitted {
		t.Fatal("the durable record claims committed even though its flush failed")
	}

	// A crash before the committed marker rolls the completed work back; that direction is the safe
	// one and is intended.
	resumeFromDisk(t, j)
	if outcome := j.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want the resumed rollback to complete", outcome.Unrecovered)
	}
	if got := readFile(t, target); got != "ORIGINAL\n" {
		t.Fatalf("%s = %q, want its pre-run bytes", target, got)
	}
	assertGone(t, j.Path())
}

func TestJournalCommit_ASurvivingCommittedJournalIsCleanupOnly(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")

	j.rec.Lifecycle = lifecycleCommitted
	if err := j.flush(); err != nil {
		t.Fatalf("flush the committed marker: %v", err)
	}
	resumeFromDisk(t, j)

	// Cancellation is the reason that would otherwise restore. A durable committed marker outranks it.
	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath != "" || len(outcome.Unrecovered) != 0 || len(outcome.Restored) != 0 {
		t.Fatalf("outcome = %+v, want a committed survivor cleaned up without a restore", outcome)
	}
	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want the committed work never restored", target, got)
	}
	assertGone(t, j.Path())
}

func TestJournalRollback_ResumesIdempotentlyAcrossEveryWriteAheadBoundary(t *testing.T) {
	for _, label := range []string{"restoring", "restored", "dir_restoring", "dir_restored"} {
		t.Run("crash at "+label, func(t *testing.T) {
			f := newFixture(t)
			edited := f.seed(t, "a.txt", "ORIGINAL\n")
			created := filepath.Join(f.project, "made/new.txt")
			j := f.open(t, edited, created)
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			f.childCreate(t, j, created, "CHILD MADE THIS\n")

			crashAt(t, label)
			j.Finish(ReasonCancelled)

			resumeFromDisk(t, j)
			outcome := j.Finish(ReasonCancelled)

			if len(outcome.Unrecovered) != 0 {
				t.Fatalf("unrecovered = %v, want the resumed rollback to complete", outcome.Unrecovered)
			}
			if got := readFile(t, edited); got != "ORIGINAL\n" {
				t.Fatalf("%s = %q, want its pre-run bytes", edited, got)
			}
			assertGone(t, created)
			assertGone(t, filepath.Join(f.project, "made"))
			assertGone(t, j.Path())
		})
	}
}

func TestJournalRollback_RetainsWhenTheStateOrItsParentChangedFirst(t *testing.T) {
	t.Run("the path changed before the comparison", func(t *testing.T) {
		// The guarantee covers the state observed when comparison begins. A publish landing inside the
		// unavoidable compare-to-rename interval is outside it and is not what this asserts.
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		if err := os.WriteFile(target, []byte("A THIRD WRITER\n"), 0o644); err != nil {
			t.Fatalf("external write: %v", err)
		}

		outcome := j.Finish(ReasonCancelled)

		if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
			t.Fatalf("outcome = %+v, want a retained journal", outcome)
		}
		if got := readFile(t, target); got != "A THIRD WRITER\n" {
			t.Fatalf("%s = %q, want the third writer's bytes retained", target, got)
		}
		if _, err := os.Stat(recordPath(j)); err != nil {
			t.Fatalf("journal record: %v, want it retained", err)
		}
	})

	t.Run("the captured parent directory was replaced", func(t *testing.T) {
		f := newFixture(t)
		sub := filepath.Join(f.project, "sub")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		target := f.seed(t, "sub/a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")

		if err := os.RemoveAll(sub); err != nil {
			t.Fatalf("remove parent: %v", err)
		}
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("recreate parent: %v", err)
		}

		outcome := j.Finish(ReasonCancelled)
		if outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want a retained journal for a replaced parent", outcome)
		}
	})
}

func TestJournalStorage_StaysBoundToItsRetainedDescriptorAfterASwap(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)

	original := j.Path()
	moved := original + "-moved"
	if err := os.Rename(original, moved); err != nil {
		t.Fatalf("move the journal directory aside: %v", err)
	}
	decoy := realDir(t, t.TempDir())
	if err := os.Symlink(decoy, original); err != nil {
		t.Fatalf("plant the decoy: %v", err)
	}

	f.childEdit(t, j, target, "ORIGINAL", "CHILD")

	data, err := os.ReadFile(filepath.Join(moved, journalRecordName))
	if err != nil {
		t.Fatalf("read the moved journal record: %v", err)
	}
	var rec journalRecord
	if uerr := json.Unmarshal(data, &rec); uerr != nil {
		t.Fatalf("decode the moved journal record: %v", uerr)
	}
	if got := string(rec.Paths[0].LastKnown.Data); got != "CHILD\n" {
		t.Fatalf("retained journal last-known = %q, want the update to have reached the held descriptor", got)
	}
	entries, err := os.ReadDir(decoy)
	if err != nil {
		t.Fatalf("read decoy: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("decoy holds %d entries, want the symlink swap to have redirected nothing", len(entries))
	}
}

func TestJournalStorage_StaysBoundToItsRetainedDescriptorAtEveryTerminalWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason Reason
		want   string
	}{
		{name: "before the committed write", reason: ReasonCompleted, want: "CHILD\n"},
		{name: "before the rollback-progress writes", reason: ReasonCancelled, want: "ORIGINAL\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)
			f.childEdit(t, j, target, "ORIGINAL", "CHILD")

			original := j.Path()
			moved := original + "-moved"
			if err := os.Rename(original, moved); err != nil {
				t.Fatalf("move the journal directory aside: %v", err)
			}
			if err := os.Mkdir(original, journalDirMode); err != nil {
				t.Fatalf("plant the decoy: %v", err)
			}

			outcome := j.Finish(tc.reason)

			if len(outcome.Unrecovered) != 0 {
				t.Fatalf("unrecovered = %v, want the swap to have changed nothing", outcome.Unrecovered)
			}
			if got := readFile(t, target); got != tc.want {
				t.Fatalf("%s = %q, want %q", target, got, tc.want)
			}
			// A journal that re-resolved its storage by path would have written and unlinked inside the
			// decoy, leaving its own record behind where the held descriptor still points.
			assertGone(t, filepath.Join(moved, journalRecordName))
			// Cleanup unlinks the directory by name, which is the one act the held descriptor cannot
			// pin, so it must remove neither: the decoy is not this journal's to delete, and deleting
			// it would leave the directory this journal actually held behind in its place.
			if _, err := os.Stat(original); err != nil {
				t.Fatalf("%s: %v, want the decoy directory left alone", original, err)
			}
			if _, err := os.Stat(moved); err != nil {
				t.Fatalf("%s: %v, want the journal's own directory left where the swap put it", moved, err)
			}
		})
	}
}

// TestJournalStorage_SurvivesASymlinkSwapCrashAtEveryWriteAheadBoundary drives the two hazards
// together at each terminal boundary: the process dies exactly at the write-ahead update, and the
// storage path has been replaced by a symlink to somewhere else by the time it does. Neither the lost
// entry nor the redirection may leave the durable record claiming more than actually happened, and the
// decoy must never receive a journal record.
func TestJournalStorage_SurvivesASymlinkSwapCrashAtEveryWriteAheadBoundary(t *testing.T) {
	t.Run("before the pending write", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)

		moved, decoy := swapAndCrashAt(t, j, "pending")
		if res := f.childEdit(t, j, target, "ORIGINAL", "CHILD"); res.ExitCode == 0 {
			t.Fatal("the edit published even though its pending record could not be persisted")
		}
		assertGone(t, filepath.Join(decoy, journalRecordName))
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the interrupted pending record to have withheld the publish", target, got)
		}
		if rec := recordIn(t, moved); rec.Paths[0].Pending != nil {
			t.Fatalf("retained pending = %+v, want the lost write-ahead entry absent from the held record", rec.Paths[0].Pending)
		}

		restoreStorage(t, j, moved)
		resumeFromDisk(t, j)
		if outcome := j.Finish(ReasonCompleted); len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want the resumed transaction to settle cleanly", outcome.Unrecovered)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the state the interrupted write never left", target, got)
		}
		assertGone(t, j.Path())
	})

	t.Run("before the committed write", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")

		moved, decoy := swapAndCrashAt(t, j, "committed")
		outcome := j.Finish(ReasonCompleted)
		if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
			t.Fatalf("outcome = %+v, want the journal retained when the committed marker never landed", outcome)
		}
		assertGone(t, filepath.Join(decoy, journalRecordName))
		if rec := recordIn(t, moved); rec.Lifecycle == lifecycleCommitted {
			t.Fatal("the retained record claims committed even though that flush was interrupted")
		}

		// A crash before the committed marker follows the rollback direction, which is the safe one.
		restoreStorage(t, j, moved)
		resumeFromDisk(t, j)
		if outcome := j.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want the resumed rollback to complete", outcome.Unrecovered)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want its pre-run bytes", target, got)
		}
		assertGone(t, j.Path())
	})

	t.Run("before the rollback-progress write", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")

		moved, decoy := swapAndCrashAt(t, j, "restoring")
		outcome := j.Finish(ReasonCancelled)
		if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
			t.Fatalf("outcome = %+v, want the journal retained when the rollback could not be recorded", outcome)
		}
		assertGone(t, filepath.Join(decoy, journalRecordName))
		if got := readFile(t, target); got != "CHILD\n" {
			t.Fatalf("%s = %q, want the restore withheld until its progress could be recorded", target, got)
		}
		if rec := recordIn(t, moved); rec.Paths[0].Progress == rollbackRestored {
			t.Fatal("the retained record claims restored even though the rollback never began")
		}

		restoreStorage(t, j, moved)
		resumeFromDisk(t, j)
		if outcome := j.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want the resumed rollback to complete", outcome.Unrecovered)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want its pre-run bytes", target, got)
		}
		assertGone(t, j.Path())
	})
}

func TestJournalRemovePublished_TakesBackOnlyTheInodeItCreated(t *testing.T) {
	t.Run("its own inode is removed and the record settles", func(t *testing.T) {
		f := newFixture(t)
		created := filepath.Join(f.project, "new.txt")
		j := f.open(t, created)

		parent, err := os.Open(f.project)
		if err != nil {
			t.Fatalf("open parent: %v", err)
		}
		defer parent.Close() //nolint:errcheck // read-only descriptor
		if err := j.BeginMutation(created, filetools.JournalState{}, filetools.JournalState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644}); err != nil {
			t.Fatalf("BeginMutation: %v", err)
		}
		_, _, published, werr := fsutil.WriteAtomicCreateAt(parent, "new.txt", []byte("CHILD\n"), 0o644)
		if werr != nil {
			t.Fatalf("publish: %v", werr)
		}
		dev, ino := identityOf(t, published)

		j.RemovePublished(created, parent, filetools.JournalState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644, Dev: dev, Ino: ino})

		assertGone(t, created)
		rec := onDiskRecord(t, j)
		if rec.Paths[0].Pending != nil || len(rec.Unrecovered) != 0 {
			t.Fatalf("record = %+v, want the pending write cleared as never published", rec.Paths[0])
		}
	})

	t.Run("a swapped leaf survives and the journal is retained", func(t *testing.T) {
		f := newFixture(t)
		created := filepath.Join(f.project, "new.txt")
		j := f.open(t, created)

		parent, err := os.Open(f.project)
		if err != nil {
			t.Fatalf("open parent: %v", err)
		}
		defer parent.Close() //nolint:errcheck // read-only descriptor
		if err := j.BeginMutation(created, filetools.JournalState{}, filetools.JournalState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644}); err != nil {
			t.Fatalf("BeginMutation: %v", err)
		}
		if err := os.WriteFile(created, []byte("A THIRD WRITER\n"), 0o644); err != nil {
			t.Fatalf("third-party write: %v", err)
		}

		j.RemovePublished(created, parent, filetools.JournalState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644, Dev: 1, Ino: 999999})

		if got := readFile(t, created); got != "A THIRD WRITER\n" {
			t.Fatalf("%s = %q, want the third writer's file untouched", created, got)
		}
		if rec := onDiskRecord(t, j); len(rec.Unrecovered) == 0 {
			t.Fatal("a third-party replacement was not reported as unrecovered")
		}
	})
}

func identityOf(t *testing.T, info os.FileInfo) (dev, ino uint64) {
	t.Helper()
	if info == nil {
		t.Fatal("the create publish reported no identity for a visible outcome")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("identity of %T is not a stat record", info.Sys())
	}
	return uint64(st.Dev), uint64(st.Ino)
}

func TestJournalNested_AbsorbsTransferReadyDescendantsBeforeComparing(t *testing.T) {
	t.Run("a completed grandchild's write is the parent's to roll back", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)

		child, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}, Parent: parent})
		if err != nil {
			t.Fatalf("OpenJournal nested: %v", err)
		}
		defer child.Close()
		f.childEdit(t, child, target, "ORIGINAL", "GRANDCHILD")

		if outcome := child.Finish(ReasonCompleted); outcome.JournalPath != "" {
			t.Fatalf("nested outcome = %+v, want a clean transfer", outcome)
		}
		assertGone(t, child.Path())
		if got := string(parent.record(target).LastKnown.Data); got != "GRANDCHILD\n" {
			t.Fatalf("parent last-known = %q, want the absorbed grandchild state", got)
		}

		if outcome := parent.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want the grandchild's write rolled back", outcome.Unrecovered)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the parent's pre-run bytes", target, got)
		}
	})

	t.Run("a still-linked transfer-ready child is processed before the parent compares", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)

		child, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}, Parent: parent})
		if err != nil {
			t.Fatalf("OpenJournal nested: %v", err)
		}
		defer child.Close()
		f.childEdit(t, child, target, "ORIGINAL", "GRANDCHILD")
		if err := child.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady: %v", err)
		}

		outcome := parent.Finish(ReasonStepCap)

		if len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want the still-linked child absorbed and rolled back", outcome.Unrecovered)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the parent's pre-run bytes", target, got)
		}
		assertGone(t, child.Path())
		assertGone(t, parent.Path())
	})

	t.Run("two still-linked levels are absorbed deepest-first", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)

		child, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}, Parent: parent})
		if err != nil {
			t.Fatalf("OpenJournal child: %v", err)
		}
		defer child.Close()
		grandchild, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}, Parent: child})
		if err != nil {
			t.Fatalf("OpenJournal grandchild: %v", err)
		}
		defer grandchild.Close()

		f.childEdit(t, grandchild, target, "ORIGINAL", "GREAT GRANDCHILD")
		if err := grandchild.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady grandchild: %v", err)
		}
		if err := child.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady child: %v", err)
		}

		// Only absorbing the grandchild into the child before the child into the parent carries the
		// write far enough for the parent to recognise it as child-owned.
		outcome := parent.Finish(ReasonCancelled)

		if len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want both levels absorbed before the comparison", outcome.Unrecovered)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the parent's pre-run bytes", target, got)
		}
		assertGone(t, grandchild.Path())
		assertGone(t, child.Path())
		assertGone(t, parent.Path())
	})

	t.Run("a failed absorption retains both journals", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)

		child, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}, Parent: parent})
		if err != nil {
			t.Fatalf("OpenJournal nested: %v", err)
		}
		defer child.Close()
		f.childEdit(t, child, target, "ORIGINAL", "GRANDCHILD")

		crashAt(t, "child_absorbed")
		outcome := child.Finish(ReasonCompleted)

		if outcome.JournalPath == "" {
			t.Fatalf("nested outcome = %+v, want the child journal retained", outcome)
		}
		if _, err := os.Stat(recordPath(child)); err != nil {
			t.Fatalf("child journal record: %v, want it retained", err)
		}
		if rec := onDiskRecord(t, parent); len(rec.Unrecovered) == 0 {
			t.Fatal("the parent journal does not record the failed absorption")
		}
	})
}

func TestBeginMutation_RefusesAStateOverThePerPathCap(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	observed := filetools.JournalState{Exists: true, Data: []byte("ORIGINAL\n"), Mode: 0o644}

	atCap := filetools.JournalState{Exists: true, Data: make([]byte, maxStateBytesPerPath), Mode: 0o644}
	if err := j.BeginMutation(target, observed, atCap); err != nil {
		t.Fatalf("BeginMutation refused a state at exactly the cap: %v", err)
	}
	j.record(target).Pending = nil
	if err := j.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	over := filetools.JournalState{Exists: true, Data: make([]byte, maxStateBytesPerPath+1), Mode: 0o644}
	if err := j.BeginMutation(target, observed, over); err == nil {
		t.Fatal("BeginMutation accepted a state one byte over the cap")
	}
	if rec := onDiskRecord(t, j); rec.Paths[0].Pending != nil {
		t.Fatalf("pending state is %d bytes, want the refused mutation never recorded", len(rec.Paths[0].Pending.State.Data))
	}
}

// TestReconcilePending_ResumesAcrossTheRetrySyncBoundary drives the crash that lands between the
// publish helper's return and the pending record's rewrite. The pending record is pessimistic about
// the target parent's durability until a sync succeeds, so a resumed reconciliation syncs before it
// clears or advances rather than trusting what is merely visible.
func TestReconcilePending_ResumesAcrossTheRetrySyncBoundary(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)

	crashAt(t, "pending")
	res := f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	if res.ExitCode == 0 {
		t.Fatal("the edit published even though its pending record could not be persisted")
	}
	if got := readFile(t, target); got != "ORIGINAL\n" {
		t.Fatalf("%s = %q, want a failed pending record to prevent the publish", target, got)
	}

	pr := j.record(target)
	pr.Pending = &pendingMutation{State: fileState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644}, NeedsParentSync: true}
	if err := j.flush(); err != nil {
		t.Fatalf("flush pending: %v", err)
	}
	if err := os.WriteFile(target, []byte("CHILD\n"), 0o644); err != nil {
		t.Fatalf("publish: %v", err)
	}

	crashAt(t, "reconciled")
	j.ReconcilePending()
	if rec := onDiskRecord(t, j); rec.Paths[0].Pending == nil || !rec.Paths[0].Pending.NeedsParentSync {
		t.Fatalf("durable pending = %+v, want the unresolved transition kept with its sync still owed", rec.Paths[0].Pending)
	}

	resumeFromDisk(t, j)
	j.ReconcilePending()

	rec := onDiskRecord(t, j)
	if rec.Paths[0].Pending != nil {
		t.Fatalf("pending = %+v, want the resumed reconciliation to resolve it", rec.Paths[0].Pending)
	}
	if got := string(rec.Paths[0].LastKnown.Data); got != "CHILD\n" {
		t.Fatalf("last-known = %q, want the published state advanced", got)
	}
	if len(rec.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want the resume to be clean", rec.Unrecovered)
	}
}

// Declared siblings under one missing directory: the directory is recorded against whichever declared
// path's create materialized it, so a terminal pass over the untouched sibling has to recognize it as
// the child's own work rather than as a component that appeared from somewhere else.
func TestJournalTerminal_TraversesADirectoryCreatedForADeclaredSibling(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason Reason
	}{
		{name: "completed", reason: ReasonCompleted},
		{name: "cancelled", reason: ReasonCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			written := filepath.Join(f.project, "made/a.txt")
			untouched := filepath.Join(f.project, "made/b.txt")
			j := f.open(t, written, untouched)

			f.childCreate(t, j, written, "CHILD MADE THIS\n")

			outcome := j.Finish(tc.reason)

			if len(outcome.Unrecovered) != 0 || outcome.JournalPath != "" {
				t.Fatalf("outcome = %+v, want the untouched sibling to settle cleanly", outcome)
			}
			assertGone(t, untouched)
			assertGone(t, j.Path())
			if tc.reason == ReasonCompleted {
				if got := readFile(t, written); got != "CHILD MADE THIS\n" {
					t.Fatalf("%s = %q, want the child's result", written, got)
				}
				return
			}
			assertGone(t, written)
			assertGone(t, filepath.Join(f.project, "made"))
		})
	}
}

// A rollback act whose parent sync failed leaves the record on `restoring` with the act already done.
// The resumed pass therefore reads the pre-run state back and must still owe the fsync: recording
// `restored` off the visible state alone would call a namespace change the filesystem can still lose
// finished. Both acts that change the namespace are pinned — the file restore and the created
// directory's removal.
func TestJournalRollback_RetriesTheParentSyncAResumedActStillOwes(t *testing.T) {
	t.Run("restored file", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")

		// The restore's own sync and the sync the resumed pass owes for it.
		failSyncCalls(t, 1, 2)
		if outcome := j.Finish(ReasonCancelled); outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the journal retained on the failed sync", outcome)
		}

		resumeFromDisk(t, j)
		outcome := j.Finish(ReasonCancelled)
		if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
			t.Fatalf("outcome = %+v, want the resumed pass to retry the sync and retain on its failure", outcome)
		}
		if rec := onDiskRecord(t, j); rec.Paths[0].Progress == rollbackRestored {
			t.Fatal("the resumed rollback recorded restored without a durable directory entry")
		}

		resumeFromDisk(t, j)
		if outcome := j.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want the rollback to complete once the sync succeeds", outcome.Unrecovered)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want its pre-run bytes", target, got)
		}
		assertGone(t, j.Path())
	})

	t.Run("removed directory", func(t *testing.T) {
		f := newFixture(t)
		created := filepath.Join(f.project, "made/new.txt")
		j := f.open(t, created)
		f.childCreate(t, j, created, "CHILD\n")

		// Call 1 is the created file's removal, which must succeed; calls 2 and 3 are the created
		// directory's removal and the sync the resumed pass owes for it.
		failSyncCalls(t, 2, 3)
		if outcome := j.Finish(ReasonCancelled); outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the journal retained on the failed sync", outcome)
		}

		resumeFromDisk(t, j)
		outcome := j.Finish(ReasonCancelled)
		if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
			t.Fatalf("outcome = %+v, want the resumed pass to retry the sync and retain on its failure", outcome)
		}
		if rec := onDiskRecord(t, j); rec.Paths[0].Dirs[0].Progress == rollbackRestored {
			t.Fatal("the resumed directory removal recorded restored without a durable directory entry")
		}

		resumeFromDisk(t, j)
		if outcome := j.Finish(ReasonCancelled); len(outcome.Unrecovered) != 0 {
			t.Fatalf("unrecovered = %v, want the rollback to complete once the sync succeeds", outcome.Unrecovered)
		}
		assertGone(t, filepath.Join(f.project, "made"))
		assertGone(t, j.Path())
	})
}

// A publish that never happened leaves bytes nobody published. Both structured writes must therefore
// abandon their pending record rather than reconcile it: a racing writer that put byte-identical
// content at the declared path owns that file, and absorbing it as the child's own would let the
// rollback restore over it — or, for a create, delete it outright.
func TestJournalFailedPublish_LeavesARacingWritersFileAlone(t *testing.T) {
	t.Run("create refused by a racing file", func(t *testing.T) {
		f := newFixture(t)
		target := filepath.Join(f.project, "a.txt")
		j := f.open(t, target)

		// The window between the pending record and create's no-replace link is the one in which
		// another writer can take the name; the link then fails EEXIST with nothing of ours visible.
		onJournalStep(t, "pending", func() { plantForeignFile(t, j, target) })

		if res := f.childCreate(t, j, target, "CHILD MADE THIS\n"); res.ExitCode == 0 {
			t.Fatal("the create reported success, want it refused by the racing file")
		}

		outcome := j.Finish(ReasonCancelled)

		if got := readFile(t, target); got != "CHILD MADE THIS\n" {
			t.Fatalf("%s = %q, want the other writer's file left in place", target, got)
		}
		if len(outcome.Unrecovered) == 0 || outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the external change reported and the journal retained", outcome)
		}
	})

	t.Run("edit refused by a replaced target", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)

		// The planned-identity check the publish makes at the rename is the last gate; the swap has
		// to land after the pending record, which is written past the tool's own re-check.
		onJournalStep(t, "pending", func() { plantForeignFile(t, j, target) })

		if res := f.childEdit(t, j, target, "ORIGINAL", "CHILD"); res.ExitCode == 0 {
			t.Fatal("the edit reported success, want it refused by the replaced target")
		}

		outcome := j.Finish(ReasonCancelled)

		if got := readFile(t, target); got != "CHILD\n" {
			t.Fatalf("%s = %q, want the other writer's file left in place", target, got)
		}
		if len(outcome.Unrecovered) == 0 || outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the external change reported and the journal retained", outcome)
		}
	})
}

// plantForeignFile publishes another writer's file at the declared path, holding exactly the bytes and
// mode the outstanding write was about to publish — the one case content equality cannot tell apart
// from the child's own work. It links a fresh inode into place, so an edit's planned-identity check
// sees the target replaced and a create's no-replace link sees the name taken.
func plantForeignFile(t *testing.T, j *Journal, target string) {
	t.Helper()
	pending := j.rec.Paths[0].Pending
	if pending == nil {
		t.Fatal("no pending record to copy the outstanding write's state from")
	}
	publishAt(t, target, pending.State.Data, pending.State.Mode)
}

// publishAt links a fresh inode holding data at path, the way an atomic publish does, so the file's
// identity changes even though its bytes need not.
func publishAt(t *testing.T, path string, data []byte, mode os.FileMode) os.FileInfo {
	t.Helper()
	staged := path + ".staged"
	if err := os.WriteFile(staged, data, mode); err != nil {
		t.Fatalf("stage %s: %v", path, err)
	}
	// WriteFile's mode is subject to the umask, and the mode is half of what a state comparison reads.
	if err := os.Chmod(staged, mode); err != nil {
		t.Fatalf("set the mode on %s: %v", path, err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatalf("publish %s: %v", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info
}

// The window between a publish and its reconciliation: another writer can replace the just-published
// file with the same bytes and mode. Content alone cannot tell that apart from the child's own write,
// so the identity the publish reported is what settles it.
func TestResolveMutation_TellsThePublishedInodeFromASameContentReplacement(t *testing.T) {
	const childBytes = "CHILD\n"
	for _, tc := range []struct {
		name    string
		replace bool
	}{
		{name: "the published inode still holds the bytes"},
		{name: "another writer replaced it with the same bytes", replace: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)

			parent, err := os.Open(f.project)
			if err != nil {
				t.Fatalf("open parent: %v", err)
			}
			defer parent.Close() //nolint:errcheck // read-only descriptor

			prior := j.rec.Paths[0].LastKnown
			observed := filetools.JournalState{Exists: true, Data: prior.Data, Mode: prior.Mode, Dev: prior.Dev, Ino: prior.Ino}
			pending := filetools.JournalState{Exists: true, Data: []byte(childBytes), Mode: prior.Mode.Perm()}
			if err := j.BeginMutation(target, observed, pending); err != nil {
				t.Fatalf("BeginMutation: %v", err)
			}

			mine := publishAt(t, target, []byte(childBytes), prior.Mode.Perm())
			if tc.replace {
				publishAt(t, target, []byte(childBytes), prior.Mode.Perm())
			}
			pending.Dev, pending.Ino = identityOf(t, mine)

			j.ResolveMutation(target, parent, pending)

			rec := onDiskRecord(t, j)
			if tc.replace {
				if rec.Paths[0].Pending == nil || len(rec.Unrecovered) == 0 {
					t.Fatalf("record = %+v, want another writer's inode reported rather than adopted", rec.Paths[0])
				}
				if string(rec.Paths[0].LastKnown.Data) != "ORIGINAL\n" {
					t.Fatalf("last known = %q, want the pre-run state kept", rec.Paths[0].LastKnown.Data)
				}
				return
			}
			if rec.Paths[0].Pending != nil || len(rec.Unrecovered) != 0 {
				t.Fatalf("record = %+v, want the child's own publish adopted", rec.Paths[0])
			}
			if string(rec.Paths[0].LastKnown.Data) != childBytes {
				t.Fatalf("last known = %q, want the published bytes", rec.Paths[0].LastKnown.Data)
			}
		})
	}
}

func (f *fixture) openMoves(t *testing.T, write []string, pairs ...permissions.MovePair) *Journal {
	t.Helper()
	j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: write, DeclaredMoves: pairs})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(j.Close)
	return j
}

func (f *fixture) childMove(t *testing.T, j *Journal, source, destination string) tools.Result {
	t.Helper()
	tool := filetools.NewMoveTool(f.home, f.project, f.project)
	res, err := tool.InvokeWithResolvedMove(f.ctx(j), filetools.ResolvedMove{Source: source, Destination: destination})
	if err != nil {
		t.Fatalf("move %s -> %s: %v", source, destination, err)
	}
	return res
}

func (f *fixture) mustMove(t *testing.T, j *Journal, source, destination string) {
	t.Helper()
	mustSucceed(t, f.childMove(t, j, source, destination))
	assertGone(t, source)
}

func pairOf(source, destination string) permissions.MovePair {
	return permissions.MovePair{Source: source, Destination: destination}
}

func TestJournalMove_RefusesEndpointsItDoesNotDeclareAsOnePair(t *testing.T) {
	f := newFixture(t)
	a := f.seed(t, "a.txt", "A\n")
	c := f.seed(t, "c.txt", "C\n")
	b := filepath.Join(f.project, "b.txt")
	d := filepath.Join(f.project, "d.txt")
	j := f.openMoves(t, nil, pairOf(a, b), pairOf(c, d))

	res := f.childMove(t, j, a, d)

	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "not a declared move pair") {
		t.Fatalf("move = %+v, want endpoints from two pairs refused", res)
	}
	assertContent(t, a, "A\n")
	assertGone(t, d)
	if rec := onDiskRecord(t, j); len(rec.Moves) != 0 || rec.Paths[0].Pending != nil {
		t.Fatalf("record = %+v, want nothing recorded for a refused move", rec)
	}
}

func TestJournalRollback_UndoesCompletedMovesInReverseOrderAndRestoresEveryEndpoint(t *testing.T) {
	f := newFixture(t)
	first := f.seedMode(t, "first.txt", "FIRST ORIGINAL\n", 0o640)
	second := f.seedMode(t, "bin/second.sh", "#!/bin/sh\necho second\n", 0o755)
	f.dir(t, "moved", 0o755)
	firstTo := filepath.Join(f.project, "moved", "first.txt")
	secondTo := filepath.Join(f.project, "bin", "renamed.sh")
	j := f.openMoves(t, nil, pairOf(first, firstTo), pairOf(second, secondTo))
	f.mustMove(t, j, first, firstTo)
	f.mustMove(t, j, second, secondTo)
	if rec := onDiskRecord(t, j); len(rec.Moves) != 2 || rec.Moves[0].Source != first || rec.Moves[1].Source != second {
		t.Fatalf("journalled moves = %+v, want both completed moves in the order they were made", rec.Moves)
	}

	var undone []string
	beforeJournalStep = func(step string) error {
		if step == "move_undoing" {
			for _, m := range j.rec.Moves {
				if m.State == moveUndoing {
					undone = append(undone, m.Source)
				}
			}
		}
		return nil
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	if want := []string{second, first}; !slices.Equal(undone, want) {
		t.Fatalf("moves undone in order %v, want the reverse of the journal %v", undone, want)
	}
	assertFile(t, first, "FIRST ORIGINAL\n", 0o640)
	assertFile(t, second, "#!/bin/sh\necho second\n", 0o755)
	assertGone(t, firstTo)
	assertGone(t, secondTo)
	for _, path := range []string{first, firstTo, second, secondTo} {
		if !slices.Contains(outcome.Restored, path) {
			t.Fatalf("restored = %v, want every endpoint named, including %s", outcome.Restored, path)
		}
	}
	assertGone(t, j.Path())
}

func TestJournalRollback_ADestinationWrittenAfterItsMoveIsAbsentAgain(t *testing.T) {
	f := newFixture(t)
	source := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	destination := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, []string{destination}, pairOf(source, destination))
	f.mustMove(t, j, source, destination)
	mustSucceed(t, f.childEdit(t, j, destination, "ORIGINAL", "CHILD EDIT"))
	assertContent(t, destination, "CHILD EDIT\n")

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	assertFile(t, source, "ORIGINAL\n", 0o640)
	assertGone(t, destination)
	assertGone(t, j.Path())
}

func TestJournalRollback_RestoresAMoveSourceWhoseDestinationTheChildThenDeleted(t *testing.T) {
	f := newFixture(t)
	source := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	destination := filepath.Join(f.project, "b.txt")
	j, err := OpenJournal(JournalConfig{
		Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(),
		DeclaredDelete: []string{destination}, DeclaredMoves: []permissions.MovePair{pairOf(source, destination)},
	})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(j.Close)
	f.mustMove(t, j, source, destination)
	f.mustDelete(t, j, destination)

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	assertFile(t, source, "ORIGINAL\n", 0o640)
	assertGone(t, destination)
	if !slices.Contains(outcome.Restored, source) {
		t.Fatalf("restored = %v, want the move source named", outcome.Restored)
	}
	assertGone(t, j.Path())
}

func TestJournalRollback_PutsAMovedDirectoryBackWholeWithItsMode(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "tree", 0o750)
	leaf := f.seedMode(t, "tree/inner/leaf.txt", "LEAF\n", 0o600)
	if err := os.Chmod(tree, 0o750); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	before, err := os.Lstat(tree)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	renamed := filepath.Join(f.project, "renamed")
	j := f.openMoves(t, nil, pairOf(tree, renamed))
	f.mustMove(t, j, tree, renamed)
	assertFile(t, filepath.Join(renamed, "inner", "leaf.txt"), "LEAF\n", 0o600)

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	assertDir(t, tree, 0o750)
	assertFile(t, leaf, "LEAF\n", 0o600)
	after, err := os.Lstat(tree)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("restored %s is not the directory that was moved (err=%v): it was recreated rather than moved back", tree, err)
	}
	assertGone(t, renamed)
	assertGone(t, j.Path())
}

func TestJournalRollback_RemovesWhatTheChildCreatedInsideADirectoryItMoved(t *testing.T) {
	for _, rel := range []string{"new.txt", "sub/new.txt"} {
		t.Run(rel, func(t *testing.T) {
			f := newFixture(t)
			tree := f.dir(t, "tree", 0o755)
			moved := filepath.Join(f.project, "moved")
			created := filepath.Join(moved, rel)
			j := f.openMoves(t, []string{created}, pairOf(tree, moved))
			f.mustMove(t, j, tree, moved)
			mustSucceed(t, f.childCreate(t, j, created, "CHILD\n"))

			outcome := j.Finish(ReasonCancelled)

			if len(outcome.Unrecovered) != 0 {
				t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
			}
			assertDir(t, tree, 0o755)
			assertGone(t, filepath.Join(tree, strings.Split(rel, "/")[0]))
			assertGone(t, moved)
			assertGone(t, j.Path())
		})
	}
}

func TestJournal_RefusesChangingAFileAMovedDirectoryCarriedInAndRollsBackCleanly(t *testing.T) {
	cases := []struct {
		name   string
		config func(cfg *JournalConfig, inside string)
		change func(t *testing.T, f *fixture, j *Journal, inside string) tools.Result
	}{
		{
			name:   "deleted",
			config: func(cfg *JournalConfig, inside string) { cfg.DeclaredDelete = []string{inside} },
			change: func(t *testing.T, f *fixture, j *Journal, inside string) tools.Result {
				return f.childDelete(t, j, inside)
			},
		},
		{
			name:   "edited",
			config: func(cfg *JournalConfig, inside string) { cfg.Declared = []string{inside} },
			change: func(t *testing.T, f *fixture, j *Journal, inside string) tools.Result {
				return f.childEdit(t, j, inside, "ORIGINAL", "CHILD EDIT")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tree := f.dir(t, "tree", 0o755)
			leaf := f.seedMode(t, "tree/leaf.txt", "ORIGINAL\n", 0o640)
			moved := filepath.Join(f.project, "moved")
			inside := filepath.Join(moved, "leaf.txt")
			cfg := JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), DeclaredMoves: []permissions.MovePair{pairOf(tree, moved)}}
			tc.config(&cfg, inside)
			j, err := OpenJournal(cfg)
			if err != nil {
				t.Fatalf("OpenJournal: %v", err)
			}
			t.Cleanup(j.Close)
			f.mustMove(t, j, tree, moved)
			if res := tc.change(t, f, j, inside); res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "changed outside the child agent") {
				t.Fatalf("change = %+v, want a file the journal never snapshotted refused", res)
			}

			outcome := j.Finish(ReasonCancelled)

			if len(outcome.Unrecovered) != 0 {
				t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
			}
			assertFile(t, leaf, "ORIGINAL\n", 0o640)
			assertGone(t, moved)
			assertGone(t, j.Path())
		})
	}
}

func TestJournalRollback_RemovesADirectoryTheChildCreatedInsideOneItCreatedEarlier(t *testing.T) {
	f := newFixture(t)
	first := filepath.Join(f.project, "new", "first.txt")
	second := filepath.Join(f.project, "new", "deep", "second.txt")
	j := f.open(t, first, second)
	mustSucceed(t, f.childCreate(t, j, first, "FIRST\n"))
	mustSucceed(t, f.childCreate(t, j, second, "SECOND\n"))

	outcome := j.Finish(ReasonCancelled)

	if len(outcome.Unrecovered) != 0 {
		t.Fatalf("unrecovered = %v, want a clean rollback", outcome.Unrecovered)
	}
	assertGone(t, filepath.Join(f.project, "new"))
	assertGone(t, j.Path())
}

func TestJournalRollback_LeavesAMoveWhoseDestinationChangedOutsideTheChild(t *testing.T) {
	f := newFixture(t)
	source := f.seed(t, "a.txt", "ORIGINAL\n")
	destination := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, nil, pairOf(source, destination))
	f.mustMove(t, j, source, destination)
	replaceFile(t, destination, "THIRD PARTY\n")

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained as unrecovered", outcome)
	}
	assertGone(t, source)
	assertContent(t, destination, "THIRD PARTY\n")
	assertRecordPresent(t, j)
}

func TestJournalRollback_HoldsEveryMoveLinkedToOneItCannotUndo(t *testing.T) {
	f := newFixture(t)
	a := f.seedMode(t, "a.txt", "A ORIGINAL\n", 0o640)
	c := f.seedMode(t, "c.txt", "C ORIGINAL\n", 0o600)
	b := filepath.Join(f.project, "b.txt")
	spare := f.seedMode(t, "spare.txt", "SPARE\n", 0o644)
	spareTo := filepath.Join(f.project, "spare-moved.txt")
	j := f.openMoves(t, nil, pairOf(spare, spareTo), pairOf(a, b), pairOf(c, a))
	f.mustMove(t, j, spare, spareTo)
	f.mustMove(t, j, a, b)
	f.mustMove(t, j, c, a)
	replaceFile(t, b, "A THIRD WRITER\n")
	before := captureEntries(t, a, b, c)

	outcome := j.Finish(ReasonCancelled)

	if outcome.JournalPath == "" || len(outcome.Unrecovered) == 0 {
		t.Fatalf("outcome = %+v, want the journal retained", outcome)
	}
	assertEntriesUnchanged(t, before)
	assertHeldMovesNamed(t, outcome.HeldMoves, []permissions.MovePair{pairOf(a, b), pairOf(c, a)}, outsideChangeCause)
	assertFile(t, spare, "SPARE\n", 0o644)
	assertGone(t, spareTo)
	if !slices.Contains(outcome.Restored, spare) {
		t.Fatalf("restored = %v, want the unlinked move put back", outcome.Restored)
	}
	assertRecordPresent(t, j)
}

func TestJournalCommit_ACompletedMoveStandsAndLeavesNoJournal(t *testing.T) {
	f := newFixture(t)
	source := f.seed(t, "a.txt", "ORIGINAL\n")
	destination := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, nil, pairOf(source, destination))
	f.mustMove(t, j, source, destination)

	outcome := j.Finish(ReasonCompleted)

	if len(outcome.Unrecovered) != 0 || outcome.JournalPath != "" {
		t.Fatalf("outcome = %+v, want a clean commit", outcome)
	}
	assertGone(t, source)
	assertContent(t, destination, "ORIGINAL\n")
	assertGone(t, j.Path())
}

func TestJournalMove_RecoveryUndoesAnOrphanedMoveJournal(t *testing.T) {
	f := newFixture(t)
	source := f.seed(t, "a.txt", "ORIGINAL\n")
	destination := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, nil, pairOf(source, destination))
	f.mustMove(t, j, source, destination)
	rec := onDiskRecord(t, j)
	if rec.SchemaVersion != journalAnswerSchemaVersion {
		t.Fatalf("schema_version = %d, want %d for a journal holding a move with its identity", rec.SchemaVersion, journalAnswerSchemaVersion)
	}
	if len(rec.Moves) != 1 || rec.Moves[0].State != moveCompleted {
		t.Fatalf("journalled moves = %+v, want the completed move recorded", rec.Moves)
	}
	orphan(t, j)

	report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

	if len(report.Retained) != 0 || !slices.Contains(report.Restored, source) {
		t.Fatalf("report = %+v, want the move undone and its journal recovered", report)
	}
	assertContent(t, source, "ORIGINAL\n")
	assertGone(t, destination)
	assertGone(t, j.Path())

	for _, tc := range []struct {
		name string
		j    *Journal
		want int
	}{
		{"write only", f.open(t, f.seed(t, "w.txt", "W\n")), journalSchemaVersion},
		{"with a delete path", f.openScopes(t, nil, []string{f.seed(t, "d.txt", "D\n")}), journalDeleteSchemaVersion},
	} {
		if got := onDiskRecord(t, tc.j).SchemaVersion; got != tc.want {
			t.Fatalf("%s schema_version = %d, want the unchanged %d for a journal with no move pair", tc.name, got, tc.want)
		}
	}
}

func (f *fixture) openConfig(t *testing.T, cfg JournalConfig) *Journal {
	t.Helper()
	cfg.Home, cfg.ProjectRoot, cfg.Invocation = f.home, f.project, f.invocation()
	j, err := OpenJournal(cfg)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(j.Close)
	return j
}

func (f *fixture) childMkdir(t *testing.T, j *Journal, target string) tools.Result {
	t.Helper()
	tool := filetools.NewMkdirTool(f.home, f.project, f.project)
	res, err := tool.InvokeWithResolvedTarget(f.ctx(j), map[string]any{"path": target}, target)
	if err != nil {
		t.Fatalf("mkdir %s: %v", target, err)
	}
	return res
}

func pathIn(t *testing.T, rec journalRecord, path string) pathRecord {
	t.Helper()
	for _, pr := range rec.Paths {
		if pr.Path == path {
			return pr
		}
	}
	t.Fatalf("journal record holds no path %s", path)
	return pathRecord{}
}

func createdDirsAt(rec journalRecord, path string) int {
	n := 0
	for _, pr := range rec.Paths {
		for _, d := range pr.Dirs {
			if d.Created && filepath.Join(pr.Ancestor, filepath.FromSlash(d.Rel)) == path {
				n++
			}
		}
	}
	return n
}

func assertCleanOutcome(t *testing.T, j *Journal, outcome JournalOutcome) {
	t.Helper()
	if len(outcome.Unrecovered) != 0 || len(outcome.RetainedDirs) != 0 || outcome.JournalPath != "" {
		t.Fatalf("outcome = %+v, want a clean outcome", outcome)
	}
	assertGone(t, j.Path())
}

func TestJournalMkdir_CommitSettlesTheCreatedDirectoryAndRemovesTheJournal(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "made", "deep")
	j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{target}})

	mustSucceed(t, f.childMkdir(t, j, target))

	rec := onDiskRecord(t, j)
	if rec.SchemaVersion != journalDirSchemaVersion {
		t.Fatalf("schema_version = %d, want %d for a journal holding a declared directory", rec.SchemaVersion, journalDirSchemaVersion)
	}
	info := lstatEntry(t, target)
	dev, ino := identityOf(t, info)
	pr := pathIn(t, rec, target)
	if pr.Pending != nil || pr.Pre.Exists || pr.LastKnown.Kind != kindDir || pr.LastKnown.Mode != info.Mode().Perm() || pr.LastKnown.Dev != dev || pr.LastKnown.Ino != ino {
		t.Fatalf("record = %+v, want an absent pre-state and the created directory settled with its mode and identity", pr)
	}
	if len(pr.Dirs) != 2 || !pr.Dirs[0].Mkdir || !pr.Dirs[1].Created || pr.Dirs[1].Ino != ino {
		t.Fatalf("dirs = %+v, want the intermediate and the target recorded in creation order", pr.Dirs)
	}

	assertCleanOutcome(t, j, j.Finish(ReasonCompleted))
	assertDir(t, target, info.Mode().Perm())
}

func TestJournalMkdir_CrashBeforeConfirmationKeepsTheJournal(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "made")
	j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{target}})
	crashAt(t, "dir_confirm")

	if res := f.childMkdir(t, j, target); res.ExitCode == 0 {
		t.Fatalf("mkdir = %+v, want the failed confirmation reported", res)
	}

	outcome := j.Finish(ReasonCompleted)
	if len(outcome.Unrecovered) == 0 || outcome.JournalPath == "" {
		t.Fatalf("outcome = %+v, want the unconfirmed directory retained with its journal", outcome)
	}
	if got := pathIn(t, onDiskRecord(t, j), target); got.LastKnown.Exists {
		t.Fatalf("record = %+v, want the unconfirmed directory never adopted", got)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("%s: %v, want an unconfirmed directory left alone", target, err)
	}
}

func TestJournalRollback_RestoresAFileBeforeRemovingTheDeclaredDirectoryHoldingIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps func(t *testing.T, f *fixture, j *Journal, dir, file string)
	}{
		{"mkdir then create", func(t *testing.T, f *fixture, j *Journal, dir, file string) {
			mustSucceed(t, f.childMkdir(t, j, dir))
			mustSucceed(t, f.childCreate(t, j, file, "CHILD\n"))
		}},
		{"create then mkdir", func(t *testing.T, f *fixture, j *Journal, dir, file string) {
			mustSucceed(t, f.childCreate(t, j, file, "CHILD\n"))
			mustSucceed(t, f.childMkdir(t, j, dir))
			mustSucceed(t, f.childMkdir(t, j, dir))
		}},
		{"create only", func(t *testing.T, f *fixture, j *Journal, dir, file string) {
			mustSucceed(t, f.childCreate(t, j, file, "CHILD\n"))
		}},
	} {
		for _, reason := range []Reason{ReasonCancelled, ReasonCompleted} {
			t.Run(tc.name+"/"+string(reason), func(t *testing.T) {
				f := newFixture(t)
				dir := filepath.Join(f.project, "a")
				file := filepath.Join(dir, "f.txt")
				j := f.openConfig(t, JournalConfig{Declared: []string{file}, DeclaredDirs: []string{dir}})
				tc.steps(t, f, j, dir, file)
				if n := createdDirsAt(onDiskRecord(t, j), dir); n != 1 {
					t.Fatalf("%d created-directory records for %s, want its one ownership neither lost nor duplicated", n, dir)
				}

				assertCleanOutcome(t, j, j.Finish(reason))
				if reason == ReasonCompleted {
					assertContent(t, file, "CHILD\n")
					return
				}
				assertGone(t, dir)
			})
		}
	}
}

func TestJournalRollback_RemovesADeclaredDirectoryInsideAMovedEntryBeforeUndoingTheMove(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "tree", 0o750)
	f.seedMode(t, "tree/leaf.txt", "LEAF\n", 0o600)
	before := captureEntries(t, tree)
	moved := filepath.Join(f.project, "moved")
	sub := filepath.Join(moved, "sub")
	j := f.openConfig(t, JournalConfig{DeclaredMoves: []permissions.MovePair{pairOf(tree, moved)}, DeclaredDirs: []string{sub}})
	f.mustMove(t, j, tree, moved)
	mustSucceed(t, f.childMkdir(t, j, sub))

	assertCleanOutcome(t, j, j.Finish(ReasonCancelled))
	assertEntriesUnchanged(t, before)
	assertGone(t, moved)
}

func TestJournalRollback_RemovesADirectoryCreatedBelowADeletedThenRecreatedAncestor(t *testing.T) {
	f := newFixture(t)
	ancestor := f.dir(t, "d", 0o750)
	sub := filepath.Join(ancestor, "sub")
	j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{ancestor}, DeclaredDirs: []string{ancestor, sub}})
	f.mustDelete(t, j, ancestor)
	mustSucceed(t, f.childMkdir(t, j, ancestor))
	mustSucceed(t, f.childMkdir(t, j, sub))

	assertCleanOutcome(t, j, j.Finish(ReasonCancelled))
	assertDir(t, ancestor, 0o750)
	if names := dirNames(t, ancestor); len(names) != 0 {
		t.Fatalf("%s holds %v, want the child's directory removed", ancestor, names)
	}
}

func TestJournalMkdir_RefusesBelowAnAncestorItDidNotRecreate(t *testing.T) {
	f := newFixture(t)
	ancestor := f.dir(t, "d", 0o750)
	sub := filepath.Join(ancestor, "sub")
	j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{ancestor}, DeclaredDirs: []string{ancestor, sub}})
	f.mustDelete(t, j, ancestor)
	mustSucceed(t, f.childMkdir(t, j, ancestor))
	if err := os.Rename(ancestor, ancestor+"-child"); err != nil {
		t.Fatalf("move the recreated directory aside: %v", err)
	}
	if err := os.Mkdir(ancestor, 0o750); err != nil {
		t.Fatalf("plant another writer's directory: %v", err)
	}

	if res := f.childMkdir(t, j, sub); res.ExitCode == 0 {
		t.Fatalf("mkdir = %+v, want a directory beneath another writer's ancestor refused", res)
	}
	assertGone(t, sub)
}

func TestJournalRollback_RemovesNestedCreatedDirectoriesDeepestFirst(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "x", "y", "z")
	j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{target}})
	mustSucceed(t, f.childMkdir(t, j, target))
	var order []string
	beforeJournalStep = func(step string) error {
		if step == "dir_restoring" {
			for _, d := range j.rec.Paths[0].Dirs {
				if d.Progress == rollbackRestoring {
					order = append(order, d.Rel)
				}
			}
		}
		return nil
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

	assertCleanOutcome(t, j, j.Finish(ReasonCancelled))
	if want := []string{"x/y/z", "x/y", "x"}; !slices.Equal(order, want) {
		t.Fatalf("directories removed in order %v, want %v", order, want)
	}
	assertGone(t, filepath.Join(f.project, "x"))
}

func TestJournalRollback_SettlesUnchangedDeclaredDirectoriesAsCleanNoOps(t *testing.T) {
	for _, reason := range []Reason{ReasonCancelled, ReasonCompleted} {
		t.Run(string(reason), func(t *testing.T) {
			f := newFixture(t)
			existing := f.dir(t, "existing", 0o750)
			f.seed(t, "existing/keep.txt", "KEEP\n")
			before := captureEntries(t, existing)
			unused := filepath.Join(f.project, "unused")
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{existing, unused}})

			res := f.childMkdir(t, j, existing)
			mustSucceed(t, res)
			if !strings.Contains(string(res.Stdout), "already exists") {
				t.Fatalf("mkdir = %+v, want the existing directory reported as already there", res)
			}

			assertCleanOutcome(t, j, j.Finish(reason))
			assertEntriesUnchanged(t, before)
			assertGone(t, unused)
		})
	}
}

func TestJournalRollback_RetainsAndReportsUnsafeCreatedDirectories(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		left   string
		change func(t *testing.T, left string)
	}{
		{"holding another writer's file", "made", "made", func(t *testing.T, left string) {
			if err := os.WriteFile(filepath.Join(left, "foreign.txt"), []byte("NOT MINE\n"), 0o644); err != nil {
				t.Fatalf("seed foreign file: %v", err)
			}
		}},
		{"replaced", "made", "made", func(t *testing.T, left string) {
			if err := os.Remove(left); err != nil {
				t.Fatalf("remove the created directory: %v", err)
			}
			if err := os.Mkdir(left, 0o755); err != nil {
				t.Fatalf("plant a replacement: %v", err)
			}
		}},
		{"intermediate holding another writer's file", "x/y", "x", func(t *testing.T, left string) {
			if err := os.WriteFile(filepath.Join(left, "foreign.txt"), []byte("NOT MINE\n"), 0o644); err != nil {
				t.Fatalf("seed foreign file: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := filepath.Join(f.project, tc.target)
			left := filepath.Join(f.project, tc.left)
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{target}})
			mustSucceed(t, f.childMkdir(t, j, target))
			tc.change(t, left)
			kept := left
			if tc.left != tc.target {
				kept = filepath.Join(left, "foreign.txt")
			}
			before := captureEntries(t, kept)

			outcome := j.Finish(ReasonCancelled)

			if !slices.Equal(outcome.RetainedDirs, []string{left}) || outcome.JournalPath == "" {
				t.Fatalf("outcome = %+v, want %s retained and reported", outcome, left)
			}
			if !slices.ContainsFunc(outcome.Unrecovered, func(note string) bool { return strings.HasPrefix(note, left+": ") }) {
				t.Fatalf("unrecovered = %v, want %s named", outcome.Unrecovered, left)
			}
			assertEntriesUnchanged(t, before)
			assertRecordPresent(t, j)
			if tc.left != tc.target {
				assertGone(t, target)
			}
		})
	}
}

func TestJournalMkdir_RepeatedMkdirKeepsTheOriginalOwnership(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "made")
	j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{target}})
	mustSucceed(t, f.childMkdir(t, j, target))
	first := pathIn(t, onDiskRecord(t, j), target)

	mustSucceed(t, f.childMkdir(t, j, target))

	if again := pathIn(t, onDiskRecord(t, j), target); !reflect.DeepEqual(again, first) {
		t.Fatalf("record after a repeated mkdir = %+v, want it unchanged from %+v", again, first)
	}
	assertCleanOutcome(t, j, j.Finish(ReasonCancelled))
	assertGone(t, target)
}

func TestJournalMkdir_RefusesAnotherWritersDirectoryWithoutAdoptingIt(t *testing.T) {
	plant := func(t *testing.T, target string) {
		t.Helper()
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("plant another writer's directory: %v", err)
		}
	}
	for _, tc := range []struct {
		name   string
		before func(t *testing.T, j *Journal, target string)
	}{
		{"visible before the intent", func(t *testing.T, _ *Journal, target string) { plant(t, target) }},
		{"racing the create", func(t *testing.T, _ *Journal, target string) {
			onJournalStep(t, "pending", func() { plant(t, target) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := filepath.Join(f.project, "made")
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{target}})
			tc.before(t, j, target)

			if res := f.childMkdir(t, j, target); res.ExitCode == 0 {
				t.Fatalf("mkdir = %+v, want another writer's directory refused", res)
			}
			before := captureEntries(t, target)
			if pr := pathIn(t, onDiskRecord(t, j), target); pr.LastKnown.Exists || createdDirsAt(onDiskRecord(t, j), target) != 0 {
				t.Fatalf("record = %+v, want another writer's directory never claimed", pr)
			}

			outcome := j.Finish(ReasonCancelled)

			if outcome.JournalPath == "" || len(outcome.RetainedDirs) != 0 {
				t.Fatalf("outcome = %+v, want the journal retained without claiming the directory", outcome)
			}
			assertEntriesUnchanged(t, before)
		})
	}
}

func TestJournalMkdir_RecreatesADirectoryItDeletedAtTheSamePath(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, reason := range []Reason{ReasonCompleted, ReasonCancelled} {
			name := "absent/" + string(reason)
			if existing {
				name = "pre-existing/" + string(reason)
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				target := filepath.Join(f.project, "d")
				if existing {
					f.dir(t, "d", 0o750)
				}
				j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{target}, DeclaredDirs: []string{target}})
				if existing {
					f.mustDelete(t, j, target)
				}
				mustSucceed(t, f.childMkdir(t, j, target))
				f.mustDelete(t, j, target)
				mustSucceed(t, f.childMkdir(t, j, target))
				made := captureEntries(t, target)

				assertCleanOutcome(t, j, j.Finish(reason))
				switch {
				case reason == ReasonCompleted:
					assertEntriesUnchanged(t, made)
				case existing:
					assertDir(t, target, 0o750)
				default:
					assertGone(t, target)
				}
			})
		}
	}
}

// recreateThroughTheNestedDeclaration holds the first a open while deleting it, so its inode number cannot
// be reused by the second a, which a/sub's declaration creates.
func recreateThroughTheNestedDeclaration(t *testing.T, f *fixture) (j *Journal, a, sub string) {
	t.Helper()
	a = filepath.Join(f.project, "a")
	sub = filepath.Join(a, "sub")
	j = f.openConfig(t, JournalConfig{DeclaredDelete: []string{a, sub}, DeclaredDirs: []string{a, sub}})
	mustSucceed(t, f.childMkdir(t, j, a))
	mustSucceed(t, f.childMkdir(t, j, sub))
	first, err := os.Open(a)
	if err != nil {
		t.Fatalf("hold the first directory open: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	f.mustDelete(t, j, sub)
	f.mustDelete(t, j, a)
	mustSucceed(t, f.childMkdir(t, j, sub))
	return j, a, sub
}

func TestJournalMkdir_RemovesADirectoryRecreatedThroughAnotherDeclaration(t *testing.T) {
	f := newFixture(t)
	j, a, sub := recreateThroughTheNestedDeclaration(t, f)

	assertCleanOutcome(t, j, j.Finish(ReasonCancelled))
	assertGone(t, sub)
	assertGone(t, a)
}

func TestJournalMkdir_ClaimsNothingWhenRecreatingADirectoryItDeletedFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  func(t *testing.T, target string)
	}{
		{"another writer's directory racing the create", func(t *testing.T, target string) {
			onJournalStep(t, "pending", func() {
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatalf("plant another writer's directory: %v", err)
				}
			})
		}},
		{"a confirmation that could not be persisted", func(t *testing.T, _ string) { crashAt(t, "dir_confirm") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := filepath.Join(f.project, "d")
			j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{target}, DeclaredDirs: []string{target}})
			mustSucceed(t, f.childMkdir(t, j, target))
			f.mustDelete(t, j, target)
			tc.arm(t, target)

			if res := f.childMkdir(t, j, target); res.ExitCode == 0 {
				t.Fatalf("mkdir = %+v, want the second creation reported as failed", res)
			}
			if pr := pathIn(t, onDiskRecord(t, j), target); pr.LastKnown.Exists {
				t.Fatalf("record = %+v, want the directory never claimed", pr)
			}
			before := captureEntries(t, target)

			outcome := j.Finish(ReasonCancelled)

			if outcome.JournalPath == "" || len(outcome.RetainedDirs) != 0 {
				t.Fatalf("outcome = %+v, want the journal retained without claiming the directory", outcome)
			}
			assertEntriesUnchanged(t, before)
		})
	}
}

func journalDirFor(f *fixture, invocation string) string {
	return filepath.Join(filepath.Dir(sessions.SessionRoot(f.home)), journalsDirName, sessions.FolderDirName(f.project), invocation)
}

func assertDescriptorClosed(t *testing.T, fd int) {
	t.Helper()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("descriptor %d: F_GETFD err = %v, want it closed", fd, err)
	}
}

func assertDescriptorOpen(t *testing.T, fd int) {
	t.Helper()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("descriptor %d: F_GETFD err = %v, want it still open", fd, err)
	}
}

func TestOpenJournal_ReleasesAFailedLockSetupAndItsStorage(t *testing.T) {
	recordOpened := func(opened *int) func(int, string, int, uint32) (int, error) {
		return func(dir int, name string, flags int, mode uint32) (int, error) {
			fd, err := unix.Openat(dir, name, flags, mode)
			if err == nil {
				*opened = fd
			}
			return fd, err
		}
	}
	cases := []struct {
		name   string
		nested bool
		arm    func(t *testing.T, opened *int)
	}{
		{name: "the lock cannot be created", arm: func(*testing.T, *int) {
			openJournalLock = func(int, string, int, uint32) (int, error) { return -1, unix.EACCES }
		}},
		{name: "the lock cannot be taken", arm: func(t *testing.T, opened *int) {
			open := recordOpened(opened)
			openJournalLock = func(dir int, name string, flags int, mode uint32) (int, error) {
				fd, err := open(dir, name, flags, mode)
				if err != nil {
					return fd, err
				}
				other, oErr := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if oErr != nil {
					t.Fatalf("open a competing descriptor: %v", oErr)
				}
				t.Cleanup(func() { _ = unix.Close(other) })
				if lErr := unix.Flock(other, unix.LOCK_EX|unix.LOCK_NB); lErr != nil {
					t.Fatalf("take the competing lock: %v", lErr)
				}
				return fd, nil
			}
		}},
		{name: "the parent cannot record the link", nested: true, arm: func(t *testing.T, opened *int) {
			openJournalLock = recordOpened(opened)
			crashAt(t, "link_child")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			var parent *Journal
			if tc.nested {
				parent = f.open(t, target)
			}
			opened := -1
			tc.arm(t, &opened)
			t.Cleanup(func() { openJournalLock = unix.Openat })
			invocation := f.invocation()

			j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: invocation, Declared: []string{target}, Parent: parent})

			if err == nil {
				j.Close()
				t.Fatal("OpenJournal succeeded, want the failed lock setup refused")
			}
			assertGone(t, journalDirFor(f, invocation))
			if opened >= 0 {
				assertDescriptorClosed(t, opened)
			}
		})
	}
}

func TestJournalLock_RepeatedCleanupNeverClosesAReusedDescriptor(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	writer := j.writerLock.fd
	stand, err := os.Open(f.project)
	if err != nil {
		t.Fatalf("open a stand-in descriptor: %v", err)
	}
	defer stand.Close() //nolint:errcheck // read-only descriptor
	recovery, err := unix.Dup(int(stand.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	j.recoveryLock = heldLock{fd: recovery, held: true}

	assertCleanOutcome(t, j, j.Finish(ReasonCompleted))
	j.Close()
	assertDescriptorClosed(t, writer)
	assertDescriptorClosed(t, recovery)
	for _, fd := range []int{writer, recovery} {
		if err := unix.Dup3(int(stand.Fd()), fd, unix.O_CLOEXEC); err != nil {
			t.Fatalf("reuse descriptor %d: %v", fd, err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
	}

	j.mu.Lock()
	err = j.remove()
	j.mu.Unlock()
	if err != nil {
		t.Fatalf("repeated remove: %v", err)
	}
	j.writerLock.close()
	j.Close()
	j.Close()

	assertDescriptorOpen(t, writer)
	assertDescriptorOpen(t, recovery)
}

func TestJournalLock_CloseKeepsARetainedWritersLock(t *testing.T) {
	t.Run("a retained journal", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		replaceFile(t, target, "A HAND EDIT\n")
		if outcome := j.Finish(ReasonCancelled); outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the journal retained", outcome)
		}
		j.Close()

		assertLockHeld(t, j)
		if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
			t.Fatalf("report = %+v, want a retained running writer's journal to add nothing", report)
		}
		assertContent(t, target, "A HAND EDIT\n")
		assertRecordPresent(t, j)
	})

	t.Run("an unabsorbed nested child", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)
		child := f.openNested(t, parent, target)
		f.childEdit(t, child, target, "ORIGINAL", "CHILD")
		child.Close()
		orphan(t, parent)

		assertLockHeld(t, child)
		if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
			t.Fatalf("report = %+v, want the held child and its deferred parent to add nothing", report)
		}
		assertContent(t, target, "CHILD\n")
		assertRecordPresent(t, child)
		assertRecordPresent(t, parent)
	})
}

func TestJournalLock_IsRemovedWithItsJournal(t *testing.T) {
	finished := func(t *testing.T, j *Journal) {
		t.Helper()
		assertGone(t, j.Path())
		if j.writerLock.held {
			t.Fatal("writer lock still held after the journal was removed")
		}
	}

	t.Run("on commit", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		assertLockHeld(t, j)

		assertCleanOutcome(t, j, j.Finish(ReasonCompleted))
		finished(t, j)
	})

	t.Run("on absorption into a parent", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)
		child := f.openNested(t, parent, target)
		f.childEdit(t, child, target, "ORIGINAL", "CHILD")
		assertLockHeld(t, child)

		if outcome := child.Finish(ReasonCompleted); outcome.JournalPath != "" {
			t.Fatalf("outcome = %+v, want the child absorbed", outcome)
		}
		finished(t, child)
		assertLockHeld(t, parent)
	})

	t.Run("on a full rollback", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")

		assertCleanOutcome(t, j, j.Finish(ReasonCancelled))
		finished(t, j)
		assertContent(t, target, "ORIGINAL\n")
	})
}

func TestJournalRemove_KeepsTheLockWhileARecoverableRecordRemains(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	folder := filepath.Dir(j.Path())
	if err := os.Chmod(folder, 0o600); err != nil {
		t.Fatalf("remove search permission: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, journalDirMode) })

	outcome := j.Finish(ReasonCompleted)
	if err := os.Chmod(folder, journalDirMode); err != nil {
		t.Fatalf("restore search permission: %v", err)
	}

	if outcome.JournalPath == "" {
		t.Fatalf("outcome = %+v, want the journal retained", outcome)
	}
	assertRecordPresent(t, j)
	assertLockHeld(t, j)
	if !j.writerLock.held {
		t.Fatal("writer lock released while its record remains")
	}
}

func TestJournalRemove_NeverRepublishesARecordItAlreadyUnlinked(t *testing.T) {
	t.Run("the lock cannot be unlinked", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		if err := os.Remove(lockPath(j)); err != nil {
			t.Fatalf("remove the lock: %v", err)
		}
		if err := os.Mkdir(lockPath(j), 0o700); err != nil {
			t.Fatalf("plant an unremovable lock: %v", err)
		}

		if outcome := j.Finish(ReasonCompleted); outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the cleanup failure reported", outcome)
		}

		assertGone(t, recordPath(j))
		if _, err := os.Lstat(lockPath(j)); err != nil {
			t.Fatalf("stat the lock: %v, want it left in place", err)
		}
		if !j.writerLock.held {
			t.Fatal("writer lock released by a failed cleanup")
		}
		if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
			t.Fatalf("report = %+v, want record-less residue passed over in silence", report)
		}
	})

	t.Run("the directory cannot be removed", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		stray := filepath.Join(j.Path(), "stray")
		if err := os.WriteFile(stray, nil, 0o600); err != nil {
			t.Fatalf("plant a stray entry: %v", err)
		}

		if outcome := j.Finish(ReasonCompleted); outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the cleanup failure reported", outcome)
		}
		j.retain("a later error report")

		assertGone(t, recordPath(j))
		assertGone(t, lockPath(j))
		if !j.writerLock.held {
			t.Fatal("writer lock released by a failed cleanup")
		}
		if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
			t.Fatalf("report = %+v, want record-less residue passed over in silence", report)
		}

		if err := os.Remove(stray); err != nil {
			t.Fatalf("remove the stray entry: %v", err)
		}
		j.mu.Lock()
		err := j.remove()
		j.mu.Unlock()
		if err != nil {
			t.Fatalf("retried cleanup: %v", err)
		}
		assertGone(t, j.Path())
		if j.writerLock.held {
			t.Fatal("writer lock still held after the retried cleanup")
		}
	})
}

func TestJournalSchema_RecoveryReadsEverySupportedVersion(t *testing.T) {
	builders := map[int]func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)){
		journalSchemaVersion: func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			target := f.seed(t, "w.txt", "ORIGINAL\n")
			j := f.open(t, target)
			f.childEdit(t, j, target, "ORIGINAL", "CHILD")
			return j, func(t *testing.T) { assertContent(t, target, "ORIGINAL\n") }
		},
		journalDeleteSchemaVersion: func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			target := f.seed(t, "d.txt", "ORIGINAL\n")
			j := f.openScopes(t, nil, []string{target})
			f.mustDelete(t, j, target)
			return j, func(t *testing.T) { assertContent(t, target, "ORIGINAL\n") }
		},
		journalMoveSchemaVersion: func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			a, b := f.seed(t, "a.txt", "ORIGINAL\n"), filepath.Join(f.project, "b.txt")
			j := f.openMoves(t, nil, pairOf(a, b))
			f.mustMove(t, j, a, b)
			rewriteRecord(t, j, func(rec *journalRecord) {
				rec.SchemaVersion, rec.MoveSeq = journalMoveSchemaVersion, 0
				for i := range rec.Moves {
					rec.Moves[i].ID = moveID{}
				}
			})
			return j, func(t *testing.T) {
				assertContent(t, a, "ORIGINAL\n")
				assertGone(t, b)
			}
		},
		journalDirSchemaVersion: func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			dir := filepath.Join(f.project, "made")
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{dir}})
			mustSucceed(t, f.childMkdir(t, j, dir))
			return j, func(t *testing.T) { assertGone(t, dir) }
		},
		journalAnswerSchemaVersion: func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			a, b := f.seed(t, "a.txt", "ORIGINAL\n"), filepath.Join(f.project, "b.txt")
			j := f.openMoves(t, nil, pairOf(a, b))
			f.mustMove(t, j, a, b)
			return j, func(t *testing.T) {
				assertContent(t, a, "ORIGINAL\n")
				assertGone(t, b)
			}
		},
		6: func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			edited, outside := f.seed(t, "c.txt", "ORIGINAL\n"), f.seed(t, "o.txt", "ORIGINAL\n")
			j := f.open(t, edited, outside)
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			replaceFile(t, outside, "OUTSIDE\n")
			j.Finish(ReasonCompleted)
			return j, func(t *testing.T) {
				assertContent(t, edited, "CHILD\n")
				assertContent(t, outside, "OUTSIDE\n")
			}
		},
	}
	for v := journalSchemaVersion; v <= 6; v++ {
		build, ok := builders[v]
		if !ok {
			t.Fatalf("no journal staged for schema %d, which this reader accepts", v)
		}
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			f := newFixture(t)
			j, check := build(t, f)
			if got := onDiskRecord(t, j).SchemaVersion; got != v {
				t.Fatalf("schema_version = %d, want %d", got, v)
			}
			orphan(t, j)

			report := Recover(f.home, f.project, f.policy(), nil)

			if v == 6 {
				if len(report.Retained) != 1 || !report.Retained[0].Completed || len(report.CompletedRestored) != 0 || len(report.Restored) != 0 {
					t.Fatalf("report = %+v, want the completed child's journal held for a question", report)
				}
				check(t)
				assertRecordPresent(t, j)
				return
			}
			if len(report.Retained) != 0 || len(report.LeftAlone) != 0 {
				t.Fatalf("report = %+v, want a schema %d journal recovered", report, v)
			}
			check(t)
			assertGone(t, j.Path())
		})
	}
}

func TestJournalSchema_RefusesAnswerStateBelowItsSchema(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, f *fixture) (*Journal, []string, func(*journalRecord))
	}{
		{"move identities", func(t *testing.T, f *fixture) (*Journal, []string, func(*journalRecord)) {
			j, a, b := heldFileMove(t, f)
			return j, []string{a, b}, func(*journalRecord) {}
		}},
		{"a recorded answer", func(t *testing.T, f *fixture) (*Journal, []string, func(*journalRecord)) {
			j, a, b := heldFileMove(t, f)
			return j, []string{a, b}, func(rec *journalRecord) {
				rec.Answers = []groupAnswer{{Members: []moveID{rec.Moves[0].ID}, Endpoints: []string{a, b}, Choice: ChoiceKeep}}
			}
		}},
		{"kept directory state", func(t *testing.T, f *fixture) (*Journal, []string, func(*journalRecord)) {
			dir := filepath.Join(f.project, "made")
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{dir}})
			mustSucceed(t, f.childMkdir(t, j, dir))
			orphan(t, j)
			return j, []string{dir}, func(rec *journalRecord) {
				for i := range rec.Paths {
					for k := range rec.Paths[i].Dirs {
						rec.Paths[i].Dirs[k].KeptByUser = true
					}
				}
			}
		}},
	} {
		for v := journalSchemaVersion; v < journalAnswerSchemaVersion; v++ {
			t.Run(fmt.Sprintf("%s/%d", tc.name, v), func(t *testing.T) {
				f := newFixture(t)
				j, watch, edit := tc.build(t, f)
				rewriteRecord(t, j, func(rec *journalRecord) {
					edit(rec)
					rec.SchemaVersion = v
				})
				record := readBytes(t, recordPath(j))
				before := captureEntries(t, watch...)

				report := Recover(f.home, f.project, f.policy(), neverAsked(t))

				assertEntriesUnchanged(t, before)
				if got := readBytes(t, recordPath(j)); string(got) != string(record) {
					t.Fatalf("record changed:\n%s\nwant\n%s", got, record)
				}
				want := fmt.Sprintf("a schema %d journal holds move identities or answers", v)
				if len(report.Retained) != 1 || len(report.Restored) != 0 || !strings.Contains(strings.Join(report.Retained[0].Notes, "\n"), want) {
					t.Fatalf("report = %+v, want the journal retained for %q", report, want)
				}
			})
		}
	}
}

func TestJournalAnswer_LegacyMovesTakeTheirIdentitiesInTheAnswersOwnWrite(t *testing.T) {
	f := newFixture(t)
	a := f.seed(t, "a.txt", "ORIGINAL\n")
	b := filepath.Join(f.project, "b.txt")
	edited := f.seed(t, "e.txt", "ORIGINAL\n")
	j := f.openMoves(t, []string{edited}, pairOf(a, b))
	f.mustMove(t, j, a, b)
	f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
	replaceFile(t, b, "A THIRD WRITER\n")
	replaceFile(t, edited, "A HAND EDIT\n")
	orphan(t, j)
	rewriteRecord(t, j, func(rec *journalRecord) {
		rec.SchemaVersion, rec.MoveSeq = journalMoveSchemaVersion, 0
		for i := range rec.Moves {
			rec.Moves[i].ID = moveID{}
		}
	})
	keepGroup := func(u Unresolved) Choice {
		if len(u.Moves) > 0 {
			return ChoiceKeep
		}
		return ChoiceDefer
	}
	assertLegacy := func(t *testing.T, rec journalRecord) {
		t.Helper()
		if rec.SchemaVersion != journalMoveSchemaVersion || rec.MoveSeq != 0 || len(rec.Answers) != 0 || len(rec.Moves) != 1 || rec.Moves[0].ID != (moveID{}) {
			t.Fatalf("record = %+v, want the legacy move still without an identity", rec)
		}
	}

	crashAt(t, "group_answered")
	Recover(f.home, f.project, f.policy(), keepGroup)

	assertLegacy(t, onDiskRecord(t, j))

	var beforeAnswer, atAnswer journalRecord
	beforeJournalStep = func(step string) error {
		switch step {
		case "group_answered":
			beforeAnswer = recordIn(t, j.Path())
		case "group_kept":
			atAnswer = recordIn(t, j.Path())
		}
		return nil
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

	Recover(f.home, f.project, f.policy(), keepGroup)

	beforeJournalStep = func(string) error { return nil }
	assertLegacy(t, beforeAnswer)
	id := moveID{Invocation: atAnswer.Invocation, Seq: 1}
	if atAnswer.SchemaVersion != journalAnswerSchemaVersion || atAnswer.MoveSeq != 1 || len(atAnswer.Moves) != 1 || atAnswer.Moves[0].ID != id ||
		len(atAnswer.Answers) != 1 || !slices.Equal(atAnswer.Answers[0].Members, []moveID{id}) {
		t.Fatalf("record at the answer = %+v, want the identity %+v and the answer naming it in one schema %d write", atAnswer, id, journalAnswerSchemaVersion)
	}
	for launch := 1; launch <= 2; launch++ {
		Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
			if len(u.Moves) > 0 {
				t.Errorf("launch %d asked about the kept group %+v", launch, u.Moves)
			}
			return ChoiceDefer
		})

		rec := onDiskRecord(t, j)
		if rec.SchemaVersion != journalAnswerSchemaVersion || len(rec.Moves) != 1 || rec.Moves[0].ID != id || !reflect.DeepEqual(rec.Answers, atAnswer.Answers) {
			t.Fatalf("launch %d record = %+v, want schema %d, the identity, and the answer unchanged", launch, rec, journalAnswerSchemaVersion)
		}
	}
}

func TestJournalAbsorb_CarriesIdentitiesAnswersAndKeptStateIntoTheParent(t *testing.T) {
	f := newFixture(t)
	a := f.seed(t, "a.txt", "ORIGINAL\n")
	b := filepath.Join(f.project, "b.txt")
	made := filepath.Join(f.project, "made")
	parent := f.openConfig(t, JournalConfig{Declared: []string{a, b}, DeclaredDirs: []string{made}})
	if got := onDiskRecord(t, parent).SchemaVersion; got != journalDirSchemaVersion {
		t.Fatalf("parent schema_version = %d, want %d before it absorbs anything", got, journalDirSchemaVersion)
	}
	child := f.openConfig(t, JournalConfig{DeclaredMoves: []permissions.MovePair{pairOf(a, b)}, DeclaredDirs: []string{made}, Parent: parent})
	f.mustMove(t, child, a, b)
	mustSucceed(t, f.childMkdir(t, child, made))
	child.rec.Answers = []groupAnswer{{Members: []moveID{child.rec.Moves[0].ID}, Endpoints: []string{a, b}, Choice: ChoiceKeep}}
	for i := range child.rec.Paths {
		pr := &child.rec.Paths[i]
		pr.KeptByUser = pr.Path == a || pr.Path == b
		for k := range pr.Dirs {
			pr.Dirs[k].KeptByUser = true
		}
	}
	if err := child.MarkTransferReady(); err != nil {
		t.Fatalf("MarkTransferReady: %v", err)
	}
	want := onDiskRecord(t, child)

	if err := parent.Absorb(child); err != nil {
		t.Fatalf("Absorb: %v", err)
	}

	rec := onDiskRecord(t, parent)
	if rec.SchemaVersion != journalAnswerSchemaVersion {
		t.Fatalf("parent schema_version = %d, want %d once it holds answer state", rec.SchemaVersion, journalAnswerSchemaVersion)
	}
	if !slices.Equal(rec.Moves, want.Moves) || rec.Moves[0].ID.Invocation != want.Invocation || !reflect.DeepEqual(rec.Answers, want.Answers) {
		t.Fatalf("parent moves %+v and answers %+v, want the child's %+v and %+v unchanged", rec.Moves, rec.Answers, want.Moves, want.Answers)
	}
	for _, path := range []string{a, b} {
		if !pathIn(t, rec, path).KeptByUser {
			t.Fatalf("parent record for %s = %+v, want it kept", path, pathIn(t, rec, path))
		}
	}
	if !slices.ContainsFunc(pathIn(t, rec, made).Dirs, func(d dirRecord) bool { return d.KeptByUser }) {
		t.Fatalf("parent directory records = %+v, want the kept directory carried over", pathIn(t, rec, made).Dirs)
	}
	assertGone(t, child.Path())
}

func TestJournalAbsorb_RetainsBothJournalsRatherThanLoseAnAnswerOrItsBinding(t *testing.T) {
	answerKeep := func(child *Journal, a, b string) {
		child.rec.Answers = []groupAnswer{{Members: []moveID{child.rec.Moves[0].ID}, Endpoints: []string{a, b}, Choice: ChoiceKeep}}
	}
	for _, tc := range []struct {
		name     string
		parentOf func(a, b string) []string
		edit     func(parent, child *Journal, a, b string)
		reason   string
	}{
		{"an answer naming a path the parent does not hold", func(a, _ string) []string { return []string{a} }, func(_, child *Journal, a, b string) {
			answerKeep(child, a, b)
		}, "answered for"},
		{"a kept path the parent does not hold", func(a, _ string) []string { return []string{a} }, func(_, child *Journal, _, b string) {
			child.record(b).KeptByUser = true
		}, "kept"},
		{"a move identity the parent already holds", func(a, b string) []string { return []string{a, b} }, func(parent, child *Journal, a, b string) {
			answerKeep(child, a, b)
			parent.rec.Moves = append(parent.rec.Moves, child.rec.Moves[0])
		}, "an identity this journal already holds"},
		{"a parent move linked to the answered group", func(a, b string) []string { return []string{a, b} }, func(parent, child *Journal, a, b string) {
			answerKeep(child, a, b)
			parent.rec.Moves = append(parent.rec.Moves, moveRecord{movePair: movePair{Source: b, Destination: a + ".elsewhere"}, State: moveCompleted, ID: parent.newMoveID()})
		}, "leaves out the linked move"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			a := f.seed(t, "a.txt", "ORIGINAL\n")
			b := filepath.Join(f.project, "b.txt")
			parent := f.open(t, tc.parentOf(a, b)...)
			child := f.openConfig(t, JournalConfig{DeclaredMoves: []permissions.MovePair{pairOf(a, b)}, Parent: parent})
			f.mustMove(t, child, a, b)
			tc.edit(parent, child, a, b)
			if err := child.MarkTransferReady(); err != nil {
				t.Fatalf("MarkTransferReady: %v", err)
			}
			parentRecord, childRecord := readBytes(t, recordPath(parent)), readBytes(t, recordPath(child))

			err := parent.Absorb(child)

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("Absorb = %v, want a refusal naming %q", err, tc.reason)
			}
			if got := readBytes(t, recordPath(parent)); string(got) != string(parentRecord) {
				t.Fatalf("parent record changed:\n%s\nwant\n%s", got, parentRecord)
			}
			if got := readBytes(t, recordPath(child)); string(got) != string(childRecord) {
				t.Fatalf("child record changed:\n%s\nwant\n%s", got, childRecord)
			}
		})
	}
}

func TestJournalFinish_RecordsTheCompletionMarkerBeforeAnyOtherTerminalStep(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *fixture, j *Journal, edited, outside string)
	}{
		{"a failed end-of-run check", func(t *testing.T, f *fixture, j *Journal, edited, outside string) {
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			replaceFile(t, outside, "OUTSIDE\n")
		}},
		{"a retained durability failure", func(t *testing.T, f *fixture, j *Journal, edited, _ string) {
			failSyncOnce(t)
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			if len(onDiskRecord(t, j).Retained) == 0 {
				t.Fatal("no durability failure was retained, so the early return is not exercised")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			edited, outside := f.seed(t, "a.txt", "ORIGINAL\n"), f.seed(t, "b.txt", "ORIGINAL\n")
			j := f.open(t, edited, outside)
			tc.setup(t, f, j, edited, outside)

			outcome := j.Finish(ReasonCompleted)

			if outcome.JournalPath == "" {
				t.Fatalf("outcome = %+v, want the journal retained", outcome)
			}
			rec := onDiskRecord(t, j)
			if !rec.Completed || rec.SchemaVersion != 6 || rec.Lifecycle != lifecycleActive {
				t.Fatalf("record completed=%v schema=%d lifecycle=%s, want the marker at schema 6 on an active record", rec.Completed, rec.SchemaVersion, rec.Lifecycle)
			}
			assertContent(t, edited, "CHILD\n")
		})
	}

	t.Run("a nested child is not marked", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)
		child := f.openNested(t, parent, target)
		f.childEdit(t, child, target, "ORIGINAL", "CHILD")
		crashAt(t, "transfer_ready")

		if outcome := child.Finish(ReasonCompleted); outcome.JournalPath == "" {
			t.Fatalf("outcome = %+v, want the nested journal retained", outcome)
		}
		if rec := onDiskRecord(t, child); rec.Completed || rec.SchemaVersion != 1 {
			t.Fatalf("nested record completed=%v schema=%d, want no marker at schema 1", rec.Completed, rec.SchemaVersion)
		}
	})
}

func TestJournalFinish_AFailedCompletionMarkerRetainsTheWorkWithoutRollingBack(t *testing.T) {
	setup := func(t *testing.T) (*fixture, *Journal, string) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		return f, j, target
	}

	t.Run("a recoverable failure persists the marker for a later headless recovery", func(t *testing.T) {
		f, j, target := setup(t)
		crashAt(t, "completed")

		outcome := j.Finish(ReasonCompleted)

		if outcome.JournalPath == "" || !strings.Contains(strings.Join(outcome.Unrecovered, "|"), "could not be recorded") {
			t.Fatalf("outcome = %+v, want the journal retained with the failure reported", outcome)
		}
		assertContent(t, target, "CHILD\n")
		rec := onDiskRecord(t, j)
		if !rec.Completed || rec.SchemaVersion != 6 || rec.Lifecycle == lifecycleCommitted || len(rec.Retained) != 1 {
			t.Fatalf("record = %+v, want the marker and one retained failure at schema 6, uncommitted", rec)
		}

		orphan(t, j)
		report := Recover(f.home, f.project, f.policy(), nil)

		assertContent(t, target, "CHILD\n")
		assertRecordPresent(t, j)
		if len(report.Retained) != 1 || !report.Retained[0].Completed {
			t.Fatalf("report = %+v, want the completed journal held", report)
		}
	})

	t.Run("storage refusing every write is reported as a limit", func(t *testing.T) {
		_, j, target := setup(t)
		before := readBytes(t, recordPath(j))
		beforeJournalStep = func(step string) error {
			if step == "completed" || step == "completion_retained" {
				return errors.New("simulated storage refusal")
			}
			return nil
		}
		t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

		outcome := j.Finish(ReasonCompleted)

		if outcome.JournalPath == "" || !strings.Contains(strings.Join(outcome.Unrecovered, "|"), "may treat this run as interrupted") {
			t.Fatalf("outcome = %+v, want the missing completion signal reported", outcome)
		}
		assertContent(t, target, "CHILD\n")
		if got := readBytes(t, recordPath(j)); string(got) != string(before) {
			t.Fatalf("record = %s, want it unchanged (%s)", got, before)
		}
	})
}

func TestJournalSchema_PromotesTheCompletionMarkerAndNeverLowersIt(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	if got := onDiskRecord(t, j).SchemaVersion; got != 1 {
		t.Fatalf("schema_version = %d before completion, want 1", got)
	}

	j.mu.Lock()
	j.rec.Completed = true
	err := j.flush()
	j.mu.Unlock()
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if rec := onDiskRecord(t, j); !rec.Completed || rec.SchemaVersion != 6 {
		t.Fatalf("record completed=%v schema=%d, want the marker published only at schema 6", rec.Completed, rec.SchemaVersion)
	}

	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	if got := onDiskRecord(t, j).SchemaVersion; got != 6 {
		t.Fatalf("schema_version = %d after later flushes, want 6 kept", got)
	}
}
