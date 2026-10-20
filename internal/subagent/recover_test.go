package subagent

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
)

func lockPath(j *Journal) string { return filepath.Join(j.Path(), journalLockName) }

// orphan swaps the journal's lock for a fresh unlocked file, the on-disk state a writer that died
// leaves behind, while this process keeps its descriptor on the old one.
func orphan(t *testing.T, j *Journal) {
	t.Helper()
	if err := os.Remove(lockPath(j)); err != nil {
		t.Fatalf("remove the writer's lock: %v", err)
	}
	if err := os.WriteFile(lockPath(j), nil, journalRecordMode); err != nil {
		t.Fatalf("leave an unlocked lock file: %v", err)
	}
}

// holdLock takes the journal's lock through a descriptor of its own until the returned release runs.
func holdLock(t *testing.T, j *Journal) (release func()) {
	t.Helper()
	fd, err := unix.Open(lockPath(j), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open the journal lock: %v", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("take the journal lock: %v", err)
	}
	released := false
	release = func() {
		if !released {
			released = true
			_ = unix.Close(fd)
		}
	}
	t.Cleanup(release)
	return release
}

func assertLockHeld(t *testing.T, j *Journal) {
	t.Helper()
	fd, err := unix.Open(lockPath(j), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open the journal lock: %v", err)
	}
	defer unix.Close(fd) //nolint:errcheck // probe descriptor
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("flock = %v, want the writer still holding the journal lock", err)
	}
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

const deadWriterEnv = "CODEMELD_TEST_DEAD_JOURNAL_WRITER"

// TestDeadJournalWriterHelper is not a test: run as a separate process, it opens a journal, lets the
// child edit through it, and exits without closing it, as a killed codemeld would.
func TestDeadJournalWriterHelper(t *testing.T) {
	spec := os.Getenv(deadWriterEnv)
	if spec == "" {
		t.Skip("runs only as the dead journal writer process")
	}
	var dirs [2]string
	if err := json.Unmarshal([]byte(spec), &dirs); err != nil {
		t.Fatalf("decode %s: %v", deadWriterEnv, err)
	}
	f := &fixture{home: dirs[0], project: dirs[1]}
	target := filepath.Join(f.project, "a.txt")
	j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: []string{target}})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	mustSucceed(t, f.childEdit(t, j, target, "ORIGINAL", "CHILD"))
}

func TestRecover_PutsBackTheWritesOfAWriterProcessThatExited(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	spec, err := json.Marshal([2]string{f.home, f.project})
	if err != nil {
		t.Fatalf("encode the helper's folders: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeadJournalWriterHelper$")
	cmd.Env = append(os.Environ(), deadWriterEnv+"="+string(spec))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run the journal writer process: %v\n%s", err, out)
	}
	journal := filepath.Join(filepath.Dir(sessions.SessionRoot(f.home)), journalsDirName, sessions.FolderDirName(f.project), f.invocation())
	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want the exited writer's child edit on disk", target, got)
	}
	if _, err := os.Stat(filepath.Join(journal, journalRecordName)); err != nil {
		t.Fatalf("stat the exited writer's record: %v", err)
	}

	report := Recover(f.home, f.project, nil)

	if got := readFile(t, target); got != "ORIGINAL\n" {
		t.Fatalf("%s = %q, want its pre-run bytes read back from disk", target, got)
	}
	assertGone(t, journal)
	if !slices.Contains(report.Restored, target) || len(report.Retained) != 0 || len(report.LeftAlone) != 0 {
		t.Fatalf("report = %+v, want the exited writer's edit reported as put back", report)
	}
}

func (f *fixture) openNested(t *testing.T, parent *Journal, declared ...string) *Journal {
	t.Helper()
	j, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), Declared: declared, Parent: parent})
	if err != nil {
		t.Fatalf("OpenJournal nested: %v", err)
	}
	t.Cleanup(j.Close)
	return j
}

func answer(choice Choice) func(Unresolved) Choice {
	return func(Unresolved) Choice { return choice }
}

func assertRecordPresent(t *testing.T, j *Journal) {
	t.Helper()
	if _, err := os.Stat(recordPath(j)); err != nil {
		t.Fatalf("journal record: %v, want it retained", err)
	}
}

func TestRecover_PutsBackTheWritesOfAnOrphanedChild(t *testing.T) {
	f := newFixture(t)
	edited := f.seed(t, "a.txt", "ORIGINAL\n")
	created := filepath.Join(f.project, "made/new.txt")
	j := f.open(t, edited, created)
	f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
	f.childCreate(t, j, created, "CHILD MADE THIS\n")
	orphan(t, j)

	report := Recover(f.home, f.project, nil)

	if got := readFile(t, edited); got != "ORIGINAL\n" {
		t.Fatalf("%s = %q, want its pre-run bytes", edited, got)
	}
	assertGone(t, created)
	assertGone(t, filepath.Join(f.project, "made"))
	assertGone(t, j.Path())
	if !slices.Contains(report.Restored, edited) || !slices.Contains(report.Restored, created) {
		t.Fatalf("restored = %v, want both declared paths named", report.Restored)
	}
	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
	}
}

func TestRecover_SkipsAJournalWhoseLockIsHeldWithoutReadingItsRecord(t *testing.T) {
	cases := []struct {
		name   string
		record func(t *testing.T, j *Journal)
	}{
		{name: "an active record", record: func(*testing.T, *Journal) {}},
		{name: "an absent record", record: func(t *testing.T, j *Journal) {
			if err := os.Remove(recordPath(j)); err != nil {
				t.Fatalf("remove the record: %v", err)
			}
		}},
		{name: "a malformed record", record: func(t *testing.T, j *Journal) {
			if err := os.WriteFile(recordPath(j), []byte("{not json"), journalRecordMode); err != nil {
				t.Fatalf("corrupt the record: %v", err)
			}
		}},
		{name: "an unsupported schema", record: func(t *testing.T, j *Journal) {
			rewriteRecord(t, j, func(rec *journalRecord) { rec.SchemaVersion = journalAnswerSchemaVersion + 1 })
		}},
		{name: "a mismatched directory identity", record: func(t *testing.T, j *Journal) {
			rewriteRecord(t, j, func(rec *journalRecord) { rec.DirIno++ })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)
			f.childEdit(t, j, target, "ORIGINAL", "CHILD")
			tc.record(t, j)
			before, _ := os.ReadFile(recordPath(j))

			report := Recover(f.home, f.project, answer(ChoiceRestore))

			if got := readFile(t, target); got != "CHILD\n" {
				t.Fatalf("%s = %q, want the running writer's file untouched", target, got)
			}
			if after, _ := os.ReadFile(recordPath(j)); string(after) != string(before) {
				t.Fatalf("record = %q, want it untouched (%q)", after, before)
			}
			if !report.Empty() {
				t.Fatalf("report = %+v, want a running writer's journal to add nothing", report)
			}
			assertLockHeld(t, j)
		})
	}
}

func TestRecover_LeavesAJournalItCannotTellHasEnded(t *testing.T) {
	cases := []struct {
		name   string
		lock   func(t *testing.T, j *Journal)
		reason string
	}{
		{
			name: "a record without a lock",
			lock: func(t *testing.T, j *Journal) {
				if err := os.Remove(lockPath(j)); err != nil {
					t.Fatalf("remove the lock: %v", err)
				}
			},
			reason: "written by an earlier codemeld version that cannot show whether its run has ended",
		},
		{
			name: "a symlink in place of the lock",
			lock: func(t *testing.T, j *Journal) {
				outside := filepath.Join(t.TempDir(), "lock")
				if err := os.WriteFile(outside, nil, 0o600); err != nil {
					t.Fatalf("seed the symlink target: %v", err)
				}
				if err := os.Remove(lockPath(j)); err != nil {
					t.Fatalf("remove the lock: %v", err)
				}
				if err := os.Symlink(outside, lockPath(j)); err != nil {
					t.Fatalf("plant the symlink: %v", err)
				}
			},
			reason: "its lock could not be checked: ",
		},
		{
			name: "a directory in place of the lock",
			lock: func(t *testing.T, j *Journal) {
				if err := os.Remove(lockPath(j)); err != nil {
					t.Fatalf("remove the lock: %v", err)
				}
				if err := os.Mkdir(lockPath(j), 0o700); err != nil {
					t.Fatalf("plant the directory: %v", err)
				}
			},
			reason: "its lock could not be checked: it is not a regular file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)
			f.childEdit(t, j, target, "ORIGINAL", "CHILD")
			tc.lock(t, j)
			before := readBytes(t, recordPath(j))

			report := Recover(f.home, f.project, answer(ChoiceRestore))

			if got := readFile(t, target); got != "CHILD\n" {
				t.Fatalf("%s = %q, want the file left as it is", target, got)
			}
			if after := readBytes(t, recordPath(j)); string(after) != string(before) {
				t.Fatalf("record = %q, want it untouched", after)
			}
			if len(report.Restored) > 0 || len(report.Kept) > 0 || len(report.Retained) > 0 {
				t.Fatalf("report = %+v, want nothing recovered or retained for a journal left alone", report)
			}
			if len(report.LeftAlone) != 1 || report.LeftAlone[0].Path != j.Path() || !strings.HasPrefix(report.LeftAlone[0].Reason, tc.reason) {
				t.Fatalf("report.LeftAlone = %+v, want %s named with reason %q", report.LeftAlone, j.Path(), tc.reason)
			}
		})
	}

	t.Run("a lock and record that are both gone", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		for _, path := range []string{lockPath(j), recordPath(j)} {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove %s: %v", path, err)
			}
		}

		if report := Recover(f.home, f.project, answer(ChoiceRestore)); !report.Empty() {
			t.Fatalf("report = %+v, want record-less storage passed over in silence", report)
		}
		if got := readFile(t, target); got != "CHILD\n" {
			t.Fatalf("%s = %q, want the file left as it is", target, got)
		}
	})

	t.Run("a record whose existence cannot be checked", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		if err := os.Chmod(j.Path(), 0o600); err != nil {
			t.Fatalf("remove search permission: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(j.Path(), journalDirMode) })

		report := Recover(f.home, f.project, answer(ChoiceRestore))

		if len(report.LeftAlone) != 0 || len(report.Retained) != 1 || report.Retained[0].Path != j.Path() ||
			!strings.Contains(strings.Join(report.Retained[0].Notes, "\n"), "permission denied") {
			t.Fatalf("report = %+v, want the unchecked record reported as unreadable", report)
		}
		if got := readFile(t, target); got != "CHILD\n" {
			t.Fatalf("%s = %q, want the file left as it is", target, got)
		}
	})
}

func TestRecover_SkipsARecordLessDirectoryWhoseLockIsFree(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	orphan(t, j)
	if err := os.Remove(recordPath(j)); err != nil {
		t.Fatalf("remove the record: %v", err)
	}

	if report := Recover(f.home, f.project, answer(ChoiceRestore)); !report.Empty() {
		t.Fatalf("report = %+v, want record-less residue passed over in silence", report)
	}
	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want no project write for record-less residue", target, got)
	}
	if _, err := os.Stat(lockPath(j)); err != nil {
		t.Fatalf("stat the lock: %v, want record-less residue left as it is", err)
	}
}

// transferReadyChain builds a parent, child, and grandchild whose grandchild edited target and handed
// its journal up, with every writer gone.
func transferReadyChain(t *testing.T, f *fixture, target string) (parent, child, grandchild *Journal) {
	t.Helper()
	parent = f.open(t, target)
	child = f.openNested(t, parent, target)
	grandchild = f.openNested(t, child, target)
	f.childEdit(t, grandchild, target, "ORIGINAL", "GRANDCHILD")
	if err := grandchild.MarkTransferReady(); err != nil {
		t.Fatalf("MarkTransferReady grandchild: %v", err)
	}
	if err := child.MarkTransferReady(); err != nil {
		t.Fatalf("MarkTransferReady child: %v", err)
	}
	orphan(t, parent)
	orphan(t, child)
	orphan(t, grandchild)
	return parent, child, grandchild
}

func TestRecover_DefersEveryJournalAboveADescendantAnotherProcessHolds(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	parent, child, grandchild := transferReadyChain(t, f, target)
	release := holdLock(t, grandchild)
	before := map[string]string{}
	for _, j := range []*Journal{parent, child, grandchild} {
		before[j.Path()] = string(readBytes(t, recordPath(j)))
	}

	if report := Recover(f.home, f.project, answer(ChoiceRestore)); !report.Empty() {
		t.Fatalf("report = %+v, want a deferred chain to add nothing", report)
	}
	if got := readFile(t, target); got != "GRANDCHILD\n" {
		t.Fatalf("%s = %q, want no project write while a descendant is held", target, got)
	}
	for path, want := range before {
		if got := string(readBytes(t, filepath.Join(path, journalRecordName))); got != want {
			t.Fatalf("%s record = %q, want it untouched (%q)", path, got, want)
		}
	}

	release()
	report := Recover(f.home, f.project, nil)

	if got := readFile(t, target); got != "ORIGINAL\n" {
		t.Fatalf("%s = %q, want the parent's pre-run bytes once the descendant is free", target, got)
	}
	assertGone(t, grandchild.Path())
	assertGone(t, child.Path())
	assertGone(t, parent.Path())
	if !slices.Contains(report.Restored, target) || len(report.Retained) != 0 {
		t.Fatalf("report = %+v, want the later pass to recover the whole chain", report)
	}
}

func TestRecover_RetainsEveryJournalAboveADescendantItCannotUse(t *testing.T) {
	cases := []struct {
		name        string
		unavailable func(t *testing.T, j *Journal)
		leftAlone   bool
	}{
		{name: "a descendant record without a lock", leftAlone: true, unavailable: func(t *testing.T, j *Journal) {
			if err := os.Remove(lockPath(j)); err != nil {
				t.Fatalf("remove the lock: %v", err)
			}
		}},
		{name: "a malformed descendant record", unavailable: func(t *testing.T, j *Journal) {
			if err := os.WriteFile(recordPath(j), []byte("{not json"), journalRecordMode); err != nil {
				t.Fatalf("corrupt the record: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			parent, child, grandchild := transferReadyChain(t, f, target)
			tc.unavailable(t, grandchild)
			before := readBytes(t, recordPath(grandchild))

			report := Recover(f.home, f.project, answer(ChoiceRestore))

			if got := readFile(t, target); got != "GRANDCHILD\n" {
				t.Fatalf("%s = %q, want no project write while a descendant is unavailable", target, got)
			}
			if got := readBytes(t, recordPath(grandchild)); string(got) != string(before) {
				t.Fatalf("descendant record = %q, want it untouched", got)
			}
			assertRecordPresent(t, child)
			assertRecordPresent(t, parent)
			if len(report.Restored) > 0 || (len(report.LeftAlone) == 1) != tc.leftAlone {
				t.Fatalf("report = %+v, want nothing put back and the descendant reported once", report)
			}
			for _, j := range []*Journal{child, parent} {
				i := slices.IndexFunc(report.Retained, func(r RetainedJournal) bool { return r.Path == j.Path() })
				if i < 0 || !strings.Contains(strings.Join(report.Retained[i].Notes, "\n"), grandchild.Path()+" (") {
					t.Fatalf("retained = %+v, want %s retained naming the unavailable descendant %s", report.Retained, j.Path(), grandchild.Path())
				}
			}
		})
	}
}

func TestRecover_OffersARetainedJournalAgainInTheSameProcess(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	orphan(t, j)
	if err := os.WriteFile(target, []byte("A HAND EDIT\n"), 0o644); err != nil {
		t.Fatalf("hand edit: %v", err)
	}

	for pass := 1; pass <= 2; pass++ {
		report := Recover(f.home, f.project, nil)
		if len(report.Retained) != 1 || report.Retained[0].Path != j.Path() {
			t.Fatalf("pass %d retained = %+v, want the retained journal offered again", pass, report.Retained)
		}
	}
	if got := readFile(t, target); got != "A HAND EDIT\n" {
		t.Fatalf("%s = %q, want the hand edit left as it is", target, got)
	}
}

// TestRecover_CleansUpACommittedSurvivorWithoutComparingAPath pins the lifecycle dispatch: a durable
// committed marker means the child's work already stood, so recovery removes the record and compares
// nothing — including a path something else changed after the crash.
func TestRecover_CleansUpACommittedSurvivorWithoutComparingAPath(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	j.rec.Lifecycle = lifecycleCommitted
	if err := j.flush(); err != nil {
		t.Fatalf("flush the committed marker: %v", err)
	}
	if err := os.WriteFile(target, []byte("A THIRD WRITER\n"), 0o644); err != nil {
		t.Fatalf("external write: %v", err)
	}
	orphan(t, j)

	report := Recover(f.home, f.project, answer(ChoiceRestore))

	if got := readFile(t, target); got != "A THIRD WRITER\n" {
		t.Fatalf("%s = %q, want a committed survivor to compare and restore nothing", target, got)
	}
	assertGone(t, j.Path())
	if !report.Empty() {
		t.Fatalf("report = %+v, want a cleanup-only survivor to report nothing", report)
	}
}

func TestRecover_ProcessesLinkedTransferReadyDescendantsDeepestFirst(t *testing.T) {
	t.Run("two levels are absorbed before the parent compares", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)
		child := f.openNested(t, parent, target)
		grandchild := f.openNested(t, child, target)

		f.childEdit(t, grandchild, target, "ORIGINAL", "GREAT GRANDCHILD")
		if err := grandchild.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady grandchild: %v", err)
		}
		if err := child.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady child: %v", err)
		}
		orphan(t, parent)
		orphan(t, child)
		orphan(t, grandchild)

		report := Recover(f.home, f.project, nil)

		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the parent's pre-run bytes", target, got)
		}
		assertGone(t, grandchild.Path())
		assertGone(t, child.Path())
		assertGone(t, parent.Path())
		if !slices.Contains(report.Restored, target) || len(report.Retained) != 0 {
			t.Fatalf("report = %+v, want the absorbed write reported as put back", report)
		}
	})

	t.Run("a failed absorption retains the journals it involved", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)
		child := f.openNested(t, parent, target)

		f.childEdit(t, child, target, "ORIGINAL", "GRANDCHILD")
		if err := child.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady: %v", err)
		}
		orphan(t, parent)
		orphan(t, child)

		crashAt(t, "child_absorbed")
		report := Recover(f.home, f.project, nil)

		assertRecordPresent(t, child)
		assertRecordPresent(t, parent)
		if len(report.Retained) != 2 {
			t.Fatalf("retained = %+v, want both journals reported", report.Retained)
		}

		// The handover is the only thing that failed, so the next launch completes it rather than
		// leaving the pair behind for good.
		if second := Recover(f.home, f.project, nil); len(second.Retained) != 0 {
			t.Fatalf("retained = %+v, want the resumed handover to complete", second.Retained)
		}
		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the parent's pre-run bytes", target, got)
		}
		assertGone(t, child.Path())
		assertGone(t, parent.Path())
	})
}

// TestRecover_ReconcilesAPendingWriteBeforeItCompares covers the crash on either side of a child's
// publication: only the prior/pending/third comparison can tell them apart, and it has to run before
// the last-known comparison recovery restores from.
func TestRecover_ReconcilesAPendingWriteBeforeItCompares(t *testing.T) {
	cases := []struct {
		name     string
		leave    string
		wantFile string
		wantGone bool
	}{
		{name: "the prior state means the write never published", leave: "ORIGINAL\n", wantFile: "ORIGINAL\n", wantGone: true},
		{name: "the pending state is the child's and is put back", leave: "CHILD\n", wantFile: "ORIGINAL\n", wantGone: true},
		{name: "a third state is left alone", leave: "A THIRD WRITER\n", wantFile: "A THIRD WRITER\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)
			j.record(target).Pending = &pendingMutation{
				State:           fileState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644},
				NeedsParentSync: true,
			}
			if err := j.flush(); err != nil {
				t.Fatalf("flush pending: %v", err)
			}
			if err := os.WriteFile(target, []byte(tc.leave), 0o644); err != nil {
				t.Fatalf("stage the crash state: %v", err)
			}
			orphan(t, j)

			Recover(f.home, f.project, nil)

			if got := readFile(t, target); got != tc.wantFile {
				t.Fatalf("%s = %q, want %q", target, got, tc.wantFile)
			}
			if tc.wantGone {
				assertGone(t, j.Path())
				return
			}
			assertRecordPresent(t, j)
		})
	}
}

// TestRecover_RetainsAPendingWriteWhoseParentCannotBeSynced pins the durability retry recovery owes a
// crash between a publish and its parent sync: visibility alone never settles the pending record.
func TestRecover_RetainsAPendingWriteWhoseParentCannotBeSynced(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	j.record(target).Pending = &pendingMutation{
		State:           fileState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644},
		NeedsParentSync: true,
	}
	if err := j.flush(); err != nil {
		t.Fatalf("flush pending: %v", err)
	}
	if err := os.WriteFile(target, []byte("CHILD\n"), 0o644); err != nil {
		t.Fatalf("publish: %v", err)
	}
	orphan(t, j)
	failSyncOnce(t)

	report := Recover(f.home, f.project, nil)

	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want the write left alone after a failed durability retry", target, got)
	}
	assertRecordPresent(t, j)
	rec := onDiskRecord(t, j)
	if len(rec.Retained) == 0 {
		t.Fatal("the failed durability retry was not recorded as durable transaction state")
	}
	if len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the journal reported", report.Retained)
	}
}

// TestRecover_ResumesAcrossEveryWriteAheadBoundary crashes the recovery pass at each durable
// boundary it writes and then launches again, which is the only way a rollback interrupted twice is
// proved idempotent.
func TestRecover_ResumesAcrossEveryWriteAheadBoundary(t *testing.T) {
	for _, label := range []string{"restoring", "restored", "dir_restoring", "dir_restored"} {
		t.Run("crash at "+label, func(t *testing.T) {
			f := newFixture(t)
			edited := f.seed(t, "a.txt", "ORIGINAL\n")
			created := filepath.Join(f.project, "made/new.txt")
			j := f.open(t, edited, created)
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			f.childCreate(t, j, created, "CHILD MADE THIS\n")
			orphan(t, j)

			crashAt(t, label)
			if report := Recover(f.home, f.project, nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}

			report := Recover(f.home, f.project, nil)

			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want the resumed pass to complete", report.Retained)
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

// TestRecover_RetriesTheRemovalParentSyncAResumedPassStillOwes pins the removal boundary: a
// child-created file whose unlink was never made durable is not recorded as put back until a later
// pass syncs the parent it was removed from.
func TestRecover_RetriesTheRemovalParentSyncAResumedPassStillOwes(t *testing.T) {
	f := newFixture(t)
	created := filepath.Join(f.project, "new.txt")
	j := f.open(t, created)
	f.childCreate(t, j, created, "CHILD MADE THIS\n")
	orphan(t, j)
	failSyncOnce(t)

	if report := Recover(f.home, f.project, nil); len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the failed removal sync to retain the journal", report.Retained)
	}
	assertGone(t, created)
	if got := onDiskRecord(t, j); got.Paths[0].Progress != rollbackRestoring {
		t.Fatalf("progress = %q, want the removal still owed its parent sync", got.Paths[0].Progress)
	}

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want the retried sync to complete the rollback", report.Retained)
	}
	assertGone(t, j.Path())
}

func TestRecover_TakesBackACreatedFileOnlyWhileItMatches(t *testing.T) {
	t.Run("the created file still holds what the child left", func(t *testing.T) {
		f := newFixture(t)
		created := filepath.Join(f.project, "new.txt")
		j := f.open(t, created)
		f.childCreate(t, j, created, "CHILD MADE THIS\n")
		orphan(t, j)

		report := Recover(f.home, f.project, nil)

		assertGone(t, created)
		assertGone(t, j.Path())
		if !slices.Contains(report.Restored, created) {
			t.Fatalf("restored = %v, want the created file named", report.Restored)
		}
	})

	t.Run("the created file was replaced after the crash", func(t *testing.T) {
		f := newFixture(t)
		created := filepath.Join(f.project, "new.txt")
		j := f.open(t, created)
		f.childCreate(t, j, created, "CHILD MADE THIS\n")
		if err := os.WriteFile(created, []byte("SOMEONE ELSE\n"), 0o644); err != nil {
			t.Fatalf("external write: %v", err)
		}
		orphan(t, j)

		report := Recover(f.home, f.project, nil)

		if got := readFile(t, created); got != "SOMEONE ELSE\n" {
			t.Fatalf("%s = %q, want the replacement kept", created, got)
		}
		assertRecordPresent(t, j)
		if len(report.Retained) != 1 || len(report.Retained[0].Notes) == 0 {
			t.Fatalf("retained = %+v, want the path named for the user", report.Retained)
		}
	})
}

// TestRecover_PersistsTheUsersChoiceForAChangedPath covers the three answers a path recovery cannot
// put back on its own can get, including that an answered path is not asked about again.
func TestRecover_PersistsTheUsersChoiceForAChangedPath(t *testing.T) {
	changed := func(t *testing.T) (*fixture, *Journal, string) {
		t.Helper()
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		if err := os.WriteFile(target, []byte("A HAND EDIT\n"), 0o644); err != nil {
			t.Fatalf("hand edit: %v", err)
		}
		orphan(t, j)
		return f, j, target
	}

	t.Run("keeping the current state resolves the path for good", func(t *testing.T) {
		f, j, target := changed(t)

		asked := 0
		report := Recover(f.home, f.project, func(Unresolved) Choice {
			asked++
			return ChoiceKeep
		})

		if asked != 1 {
			t.Fatalf("asked %d times, want exactly one question", asked)
		}
		if got := readFile(t, target); got != "A HAND EDIT\n" {
			t.Fatalf("%s = %q, want the kept state", target, got)
		}
		if !slices.Contains(report.Kept, target) {
			t.Fatalf("kept = %v, want the answered path named", report.Kept)
		}
		if len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want a fully resolved journal deleted", report.Retained)
		}
		assertGone(t, j.Path())
	})

	t.Run("a kept path is not reported again at the next launch", func(t *testing.T) {
		f := newFixture(t)
		kept := f.seed(t, "a.txt", "ORIGINAL\n")
		pending := filepath.Join(f.project, "b.txt")
		j := f.open(t, kept, pending)
		f.childEdit(t, j, kept, "ORIGINAL", "CHILD")
		f.childCreate(t, j, pending, "CHILD MADE THIS\n")
		if err := os.WriteFile(kept, []byte("A HAND EDIT\n"), 0o644); err != nil {
			t.Fatalf("hand edit: %v", err)
		}
		orphan(t, j)

		crashAt(t, "restoring")
		if report := Recover(f.home, f.project, answer(ChoiceKeep)); !slices.Contains(report.Kept, kept) {
			t.Fatalf("kept = %v, want the answered path named", report.Kept)
		}

		var asked []string
		report := Recover(f.home, f.project, func(u Unresolved) Choice {
			asked = append(asked, u.Path)
			return ChoiceDefer
		})

		if len(asked) != 0 {
			t.Fatalf("asked about %v, want an already-answered path never re-offered", asked)
		}
		if got := readFile(t, kept); got != "A HAND EDIT\n" {
			t.Fatalf("%s = %q, want the kept state untouched by the second pass", kept, got)
		}
		assertGone(t, pending)
		assertGone(t, j.Path())
		if len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want the resolved journal deleted", report.Retained)
		}
	})

	t.Run("choosing to restore puts the captured state back over the change", func(t *testing.T) {
		f, j, target := changed(t)

		report := Recover(f.home, f.project, answer(ChoiceRestore))

		if got := readFile(t, target); got != "ORIGINAL\n" {
			t.Fatalf("%s = %q, want the captured pre-run bytes", target, got)
		}
		if !slices.Contains(report.Restored, target) {
			t.Fatalf("restored = %v, want the path named", report.Restored)
		}
		assertGone(t, j.Path())
	})

	t.Run("deferring leaves the path and the journal for the next launch", func(t *testing.T) {
		f, j, target := changed(t)

		report := Recover(f.home, f.project, answer(ChoiceDefer))

		if got := readFile(t, target); got != "A HAND EDIT\n" {
			t.Fatalf("%s = %q, want a deferred path left alone", target, got)
		}
		assertRecordPresent(t, j)
		if len(report.Retained) != 1 || !slices.Contains(report.Retained[0].Notes[0:1], target+": it was changed outside the child agent's journalled writes") {
			t.Fatalf("retained = %+v, want the path named in plain terms", report.Retained)
		}
		if onDiskRecord(t, j).Paths[0].KeptByUser {
			t.Fatal("a deferred path was recorded as answered")
		}
	})

	t.Run("an answer that cannot be recorded is not acted on", func(t *testing.T) {
		f, j, target := changed(t)

		crashAt(t, "kept")
		report := Recover(f.home, f.project, answer(ChoiceKeep))

		if len(report.Kept) != 0 {
			t.Fatalf("kept = %v, want an unrecorded answer not reported", report.Kept)
		}
		if onDiskRecord(t, j).Paths[0].KeptByUser {
			t.Fatal("an answer that could not be recorded was persisted anyway")
		}
		if got := readFile(t, target); got != "A HAND EDIT\n" {
			t.Fatalf("%s = %q, want the path left alone", target, got)
		}
		assertRecordPresent(t, j)
	})
}

func TestRecover_ReportsAJournalItCannotRead(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	orphan(t, j)
	if err := os.WriteFile(recordPath(j), []byte("{not json"), journalRecordMode); err != nil {
		t.Fatalf("corrupt the record: %v", err)
	}

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 1 || len(report.Retained[0].Notes) == 0 {
		t.Fatalf("retained = %+v, want the unreadable journal reported", report.Retained)
	}
	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want an unreadable journal to change nothing", target, got)
	}
}

// TestRecover_LoadsOnlyARecordFromTheDirectoryItNames pins the identity check the recovered
// descriptor chain rests on: a directory swapped in at the journal's path cannot present its own
// record as this transaction's.
func TestRecover_LoadsOnlyARecordFromTheDirectoryItNames(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	orphan(t, j)

	moved := j.Path() + "-moved"
	if err := os.Rename(j.Path(), moved); err != nil {
		t.Fatalf("move the journal storage aside: %v", err)
	}
	if err := os.Mkdir(j.Path(), journalDirMode); err != nil {
		t.Fatalf("plant a replacement directory: %v", err)
	}
	for _, name := range []string{journalRecordName, journalLockName} {
		if err := os.Rename(filepath.Join(moved, name), filepath.Join(j.Path(), name)); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}

	report := Recover(f.home, f.project, nil)

	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want a record from a swapped directory refused", target, got)
	}
	if len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the refusal reported", report.Retained)
	}
}

// TestRecover_ReportsAJournalFolderItCannotOpen separates the two ways the folder can fail to open:
// an absent one is the ordinary launch and says nothing, while one that cannot be traversed is a
// recovery failure the launch has to name.
func TestRecover_ReportsAJournalFolderItCannotOpen(t *testing.T) {
	f := newFixture(t)
	folder := filepath.Join(f.home, ".codemeld", journalsDirName, sessions.FolderDirName(f.project))
	if err := os.MkdirAll(filepath.Dir(folder), journalDirMode); err != nil {
		t.Fatalf("build the journals chain: %v", err)
	}
	if err := os.WriteFile(folder, nil, 0o600); err != nil {
		t.Fatalf("plant a file where the folder belongs: %v", err)
	}

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 1 || report.Retained[0].Path != folder {
		t.Fatalf("retained = %+v, want the unopenable folder named", report.Retained)
	}
}

func TestRecover_DoesNothingWhenNoJournalWasLeftBehind(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "a.txt", "ORIGINAL\n")

	if report := Recover(f.home, f.project, answer(ChoiceRestore)); !report.Empty() {
		t.Fatalf("report = %+v, want nothing reported when no journal exists", report)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".codemeld")); !os.IsNotExist(err) {
		t.Fatalf("stat ~/.codemeld: %v, want recovery to create nothing", err)
	}
}

func rewriteRecord(t *testing.T, j *Journal, edit func(*journalRecord)) {
	t.Helper()
	rec := onDiskRecord(t, j)
	edit(&rec)
	data, err := json.Marshal(&rec)
	if err != nil {
		t.Fatalf("encode journal record: %v", err)
	}
	if err := os.WriteFile(recordPath(j), data, journalRecordMode); err != nil {
		t.Fatalf("write journal record: %v", err)
	}
}

func TestRecover_RestoresEveryDeleteStateOfAnOrphanedChild(t *testing.T) {
	f := newFixture(t)
	file := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	link := f.link(t, "link", "a.txt")
	tree := f.dir(t, "tree", 0o750)
	leaf := f.seedMode(t, "tree/leaf.txt", "LEAF\n", 0o600)
	j := f.openScopes(t, nil, []string{file, link, tree, leaf})
	for _, path := range []string{link, file, leaf, tree} {
		f.mustDelete(t, j, path)
	}
	orphan(t, j)

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
	}
	assertFile(t, file, "ORIGINAL\n", 0o640)
	assertLink(t, link, "a.txt")
	assertDir(t, tree, 0o750)
	assertFile(t, leaf, "LEAF\n", 0o600)
	for _, path := range []string{file, link, tree, leaf} {
		if !slices.Contains(report.Restored, path) {
			t.Fatalf("restored = %v, want %s named", report.Restored, path)
		}
	}
	assertGone(t, j.Path())
}

func TestRecover_ResumesADeleteRollbackAcrossItsWriteAheadBoundaries(t *testing.T) {
	for _, label := range []string{"restoring", "restored"} {
		t.Run("crash at "+label, func(t *testing.T) {
			f := newFixture(t)
			tree := f.dir(t, "tree", 0o750)
			leaf := f.seedMode(t, "tree/leaf.txt", "LEAF\n", 0o644)
			j := f.openScopes(t, nil, []string{tree, leaf})
			f.mustDelete(t, j, leaf)
			f.mustDelete(t, j, tree)
			orphan(t, j)

			crashAt(t, label)
			if report := Recover(f.home, f.project, nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}

			report := Recover(f.home, f.project, nil)

			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want the resumed pass to complete", report.Retained)
			}
			assertDir(t, tree, 0o750)
			assertFile(t, leaf, "LEAF\n", 0o644)
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_PreservesAnExternalChangeToADeletedPath(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.openScopes(t, nil, []string{target})
	f.mustDelete(t, j, target)
	if err := os.WriteFile(target, []byte("THIRD PARTY\n"), 0o644); err != nil {
		t.Fatalf("write the external file: %v", err)
	}
	orphan(t, j)

	report := Recover(f.home, f.project, nil)

	if got := readFile(t, target); got != "THIRD PARTY\n" {
		t.Fatalf("%s = %q, want the external change left alone", target, got)
	}
	assertRecordPresent(t, j)
	if len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the journal reported", report.Retained)
	}
}

func TestRecover_LeavesASameContentReplacementOfADeletedPath(t *testing.T) {
	for _, tc := range sameContentReplacements {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			replaced := f.replaceDeleted(t, j, tc, target)
			orphan(t, j)

			report := Recover(f.home, f.project, nil)

			assertSameEntry(t, target, replaced)
			assertRecordPresent(t, j)
			if len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the journal reported", report.Retained)
			}
		})
	}
}

func TestRecover_ResumesAnInterruptedRestoreOnlyThroughTheEntryItPublished(t *testing.T) {
	interrupted := func(t *testing.T, f *fixture, j *Journal) {
		t.Helper()
		orphan(t, j)
		interruptRestore(t, j, func() {
			if report := Recover(f.home, f.project, nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}
		})
	}
	for _, tc := range sameContentReplacements {
		t.Run(tc.name+" left in place", func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			f.mustDelete(t, j, target)
			interrupted(t, f, j)
			restored, err := os.Lstat(target)
			if err != nil {
				t.Fatalf("lstat the restored entry: %v", err)
			}

			report := Recover(f.home, f.project, nil)

			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want the resumed restore to complete", report.Retained)
			}
			assertSameEntry(t, target, restored)
			assertGone(t, j.Path())
		})
		t.Run(tc.name+" replaced with the same content", func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			f.mustDelete(t, j, target)
			interrupted(t, f, j)
			replaced := swapInSameContent(t, tc, target)

			report := Recover(f.home, f.project, nil)

			assertSameEntry(t, target, replaced)
			assertRecordPresent(t, j)
			if len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the journal reported", report.Retained)
			}
		})
	}
}

func TestRecover_RetainsARestoreWhoseIdentityNeverBecameDurable(t *testing.T) {
	for _, tc := range unprovenRestores {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := tc.seed(t, f)
			j := f.openScopes(t, nil, []string{target})
			f.mustDelete(t, j, target)
			orphan(t, j)
			tc.interrupt(t)
			if report := Recover(f.home, f.project, nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}
			left, err := os.Lstat(target)
			if err != nil {
				t.Fatalf("lstat the entry the interrupted pass left: %v", err)
			}

			report := Recover(f.home, f.project, nil)

			assertSameEntry(t, target, left)
			assertRecordPresent(t, j)
			if len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the journal reported", report.Retained)
			}
			if pr := onDiskRecord(t, j).Paths[0]; pr.Progress == rollbackRestored || pr.ReplacementIno != 0 {
				t.Fatalf("record = %+v, want an unfinished restore naming no entry", pr)
			}
		})
	}
}

func TestRecover_RestoresNothingThroughASymlinkPlantedAboveARecreatedDirectory(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "a/tree", 0o755)
	leaf := f.seed(t, "a/tree/leaf.txt", "LEAF\n")
	j := f.openScopes(t, nil, []string{tree, leaf})
	f.mustDelete(t, j, leaf)
	f.mustDelete(t, j, tree)
	orphan(t, j)
	outside := escapeRecreatedDir(t, tree)

	report := Recover(f.home, f.project, nil)

	assertGone(t, filepath.Join(outside, "tree", "leaf.txt"))
	assertRecordPresent(t, j)
	if len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the journal reported", report.Retained)
	}
}

func TestRecover_SettlesAPendingDeletionOnlyWhenItCanBeProved(t *testing.T) {
	tests := []struct {
		name         string
		unlink       bool
		external     string
		failSync     bool
		want         string
		wantRetained bool
	}{
		{name: "a crash before the unlink leaves the file and cleans up", want: "ORIGINAL\n"},
		{name: "a crash after the unlink puts the file back", unlink: true, want: "ORIGINAL\n"},
		{name: "a third state at the path is left alone", unlink: true, external: "THIRD PARTY\n", want: "THIRD PARTY\n", wantRetained: true},
		{name: "a parent that cannot be synced keeps the deletion unresolved", unlink: true, failSync: true, wantRetained: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.openScopes(t, nil, []string{target})
			parent, err := os.Open(f.project)
			if err != nil {
				t.Fatalf("open the project: %v", err)
			}
			defer parent.Close() //nolint:errcheck // read-only directory descriptor
			if err := j.BeginDelete(target, parent); err != nil {
				t.Fatalf("BeginDelete: %v", err)
			}
			if tc.unlink {
				if err := os.Remove(target); err != nil {
					t.Fatalf("unlink: %v", err)
				}
			}
			if tc.external != "" {
				if err := os.WriteFile(target, []byte(tc.external), 0o644); err != nil {
					t.Fatalf("write the external file: %v", err)
				}
			}
			orphan(t, j)
			if tc.failSync {
				failSyncOnce(t)
			}

			report := Recover(f.home, f.project, nil)

			assertContent(t, target, tc.want)
			if tc.wantRetained {
				assertRecordPresent(t, j)
				if len(report.Retained) != 1 {
					t.Fatalf("retained = %+v, want the journal reported", report.Retained)
				}
				return
			}
			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
			}
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_RestoresEachDeleteSequenceFromItsOneHistory(t *testing.T) {
	for _, seq := range deleteSequences {
		t.Run(seq.name, func(t *testing.T) {
			f := newFixture(t)
			target := filepath.Join(f.project, "a.txt")
			if seq.seeded {
				f.seed(t, "a.txt", seq.preState())
			}
			j := f.openScopes(t, []string{target}, []string{target})
			seq.run(t, f, j, target)
			orphan(t, j)

			report := Recover(f.home, f.project, nil)

			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
			}
			assertContent(t, target, seq.preState())
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_ReadsJournalsOfBothSchemaVersions(t *testing.T) {
	f := newFixture(t)
	edited := f.seed(t, "edited.txt", "ORIGINAL\n")
	writeOnly := f.open(t, edited)
	f.childEdit(t, writeOnly, edited, "ORIGINAL", "CHILD")
	deleted := f.seed(t, "deleted.txt", "ORIGINAL\n")
	withDeletes := f.openScopes(t, nil, []string{deleted})
	f.mustDelete(t, withDeletes, deleted)
	if got := onDiskRecord(t, writeOnly).SchemaVersion; got != journalSchemaVersion {
		t.Fatalf("write-only schema_version = %d, want %d", got, journalSchemaVersion)
	}
	if got := onDiskRecord(t, withDeletes).SchemaVersion; got != journalDeleteSchemaVersion {
		t.Fatalf("delete schema_version = %d, want %d", got, journalDeleteSchemaVersion)
	}
	orphan(t, writeOnly)
	orphan(t, withDeletes)

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want both schemas recovered", report.Retained)
	}
	assertContent(t, edited, "ORIGINAL\n")
	assertContent(t, deleted, "ORIGINAL\n")
	assertGone(t, writeOnly.Path())
	assertGone(t, withDeletes.Path())
}

func TestRecover_UndoesTwoCompletedFileMovesInReverseJournalOrder(t *testing.T) {
	f := newFixture(t)
	first := f.seedMode(t, "first.txt", "FIRST ORIGINAL\n", 0o640)
	second := f.seedMode(t, "bin/second.sh", "#!/bin/sh\necho second\n", 0o755)
	f.dir(t, "moved", 0o755)
	firstTo := filepath.Join(f.project, "moved", "first.txt")
	secondTo := filepath.Join(f.project, "bin", "renamed.sh")
	j := f.openMoves(t, nil, pairOf(first, firstTo), pairOf(second, secondTo))
	f.mustMove(t, j, first, firstTo)
	f.mustMove(t, j, second, secondTo)
	orphan(t, j)

	var order []string
	beforeJournalStep = func(step string) error {
		if step != "move_undone" {
			return nil
		}
		for _, path := range []string{first, second} {
			if _, err := os.Lstat(path); err == nil && !slices.Contains(order, path) {
				order = append(order, path)
			}
		}
		return nil
	}
	t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
	}
	if want := []string{second, first}; !slices.Equal(order, want) {
		t.Fatalf("moves undone in order %v, want the reverse of the journal %v", order, want)
	}
	assertFile(t, first, "FIRST ORIGINAL\n", 0o640)
	assertFile(t, second, "#!/bin/sh\necho second\n", 0o755)
	assertGone(t, firstTo)
	assertGone(t, secondTo)
	for _, path := range []string{first, firstTo, second, secondTo} {
		if !slices.Contains(report.Restored, path) {
			t.Fatalf("restored = %v, want every endpoint named, including %s", report.Restored, path)
		}
	}
	assertGone(t, j.Path())
}

func TestRecover_ReturnsAMovedDirectoryWholeWithItsModeAndIdentity(t *testing.T) {
	f := newFixture(t)
	leaf := f.seedMode(t, "tree/inner/leaf.txt", "LEAF\n", 0o600)
	tree := f.dir(t, "tree", 0o750)
	identity, err := os.Lstat(tree)
	if err != nil {
		t.Fatalf("lstat the directory to move: %v", err)
	}
	renamed := filepath.Join(f.project, "renamed")
	j := f.openMoves(t, nil, pairOf(tree, renamed))
	f.mustMove(t, j, tree, renamed)
	orphan(t, j)

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
	}
	assertDir(t, tree, 0o750)
	assertSameEntry(t, tree, identity)
	assertFile(t, leaf, "LEAF\n", 0o600)
	assertGone(t, renamed)
	assertGone(t, j.Path())
}

func TestRecover_RemovesTheChildsWritesBeneathADirectoryItMoved(t *testing.T) {
	f := newFixture(t)
	tree := f.dir(t, "tree", 0o755)
	moved := filepath.Join(f.project, "moved")
	created := filepath.Join(moved, "sub", "new.txt")
	j := f.openMoves(t, []string{created}, pairOf(tree, moved))
	f.mustMove(t, j, tree, moved)
	mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
	orphan(t, j)

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
	}
	assertDir(t, tree, 0o755)
	assertGone(t, filepath.Join(tree, "sub"))
	assertGone(t, moved)
	assertGone(t, j.Path())
}

func TestRecover_CarriesAnOutsideEditInsideAMovedDirectoryBackWithIt(t *testing.T) {
	f := newFixture(t)
	leaf := f.seedMode(t, "tree/leaf.txt", "LEAF\n", 0o640)
	tree := f.dir(t, "tree", 0o750)
	identity, err := os.Lstat(tree)
	if err != nil {
		t.Fatalf("lstat the directory to move: %v", err)
	}
	moved := filepath.Join(f.project, "moved")
	j := f.openMoves(t, nil, pairOf(tree, moved))
	f.mustMove(t, j, tree, moved)
	replaceFile(t, filepath.Join(moved, "leaf.txt"), "A THIRD WRITER\n")
	orphan(t, j)

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
	}
	assertDir(t, tree, 0o750)
	assertSameEntry(t, tree, identity)
	assertFile(t, leaf, "A THIRD WRITER\n", 0o644)
	assertGone(t, moved)
	assertGone(t, j.Path())
}

func TestRecover_ClearsASourceTheChildRecreatedBeforeRenamingTheMovedEntryHome(t *testing.T) {
	f := newFixture(t)
	source := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	destination := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, nil, pairOf(source, destination))
	f.mustMove(t, j, source, destination)
	moved, err := os.Lstat(destination)
	if err != nil {
		t.Fatalf("lstat the moved entry: %v", err)
	}
	mustSucceed(t, f.childCreate(t, j, source, "CHILD REMADE THIS\n"))
	orphan(t, j)

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery", report.Retained)
	}
	assertFile(t, source, "ORIGINAL\n", 0o640)
	assertSameEntry(t, source, moved)
	assertGone(t, destination)
	assertGone(t, j.Path())
}

func TestRecover_HoldsTheGroupOfAMoveWhoseSourceSomeoneElseRecreated(t *testing.T) {
	f := newFixture(t)
	a := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	b := filepath.Join(f.project, "b.txt")
	c := filepath.Join(f.project, "c.txt")
	j := f.openMoves(t, nil, pairOf(a, b), pairOf(b, c))
	f.mustMove(t, j, a, b)
	f.mustMove(t, j, b, c)
	replaceFile(t, a, "A THIRD WRITER\n")
	orphan(t, j)
	before := captureEntries(t, a, b, c)

	report := Recover(f.home, f.project, func(u Unresolved) Choice {
		if len(u.Moves) > 0 {
			return ChoiceDefer
		}
		return ChoiceRestore
	})

	assertEntriesUnchanged(t, before)
	assertRecordPresent(t, j)
	if len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the journal reported", report.Retained)
	}
	assertHeldMoves(t, report.Retained[0], []permissions.MovePair{pairOf(a, b), pairOf(b, c)}, outsideChangeCause)
}

func TestRecover_RecordsACompletedPairAlreadyAtBothPreRunStatesAsUndone(t *testing.T) {
	f := newFixture(t)
	source := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	destination := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, nil, pairOf(source, destination))
	f.mustMove(t, j, source, destination)
	if err := os.Rename(destination, source); err != nil {
		t.Fatalf("put the moved entry back by hand: %v", err)
	}
	orphan(t, j)

	crashAt(t, "restored")
	if report := Recover(f.home, f.project, nil); len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
	}
	if got := onDiskRecord(t, j).Moves; len(got) != 1 || got[0].State != moveUndone {
		t.Fatalf("journalled moves = %+v, want the settled pair recorded as undone", got)
	}

	report := Recover(f.home, f.project, nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want the resumed pass to complete", report.Retained)
	}
	assertFile(t, source, "ORIGINAL\n", 0o640)
	assertGone(t, destination)
	assertGone(t, j.Path())
}

// The four reasons a held move carries, quoted from internal/subagent/journal.go so a reason that
// stops naming its cause fails the tests that stage that cause.
const (
	outsideChangeCause        = "an endpoint was changed outside the child agent's journalled writes"
	unresolvedMoveCause       = "a move the child agent started was never resolved"
	unrestoredDescendantCause = "a path the child agent changed inside the moved entry could not be put back first"
	linkedHoldReason          = "a linked move could not be undone, so this one was left in place"
)

func assertHeldMoves(t *testing.T, retained RetainedJournal, want []permissions.MovePair, cause string) {
	t.Helper()
	assertHeldMovesNamed(t, retained.Moves, want, cause)
}

// assertHeldMovesNamed pins why each move was held, not just that it was named: exactly one member
// carries the cause the case staged and every other member carries the linked-move reason.
func assertHeldMovesNamed(t *testing.T, held []HeldMove, want []permissions.MovePair, cause string) {
	t.Helper()
	if len(held) != len(want) {
		t.Fatalf("held moves = %+v, want exactly %+v", held, want)
	}
	staged := 0
	for _, pair := range want {
		i := slices.IndexFunc(held, func(h HeldMove) bool {
			return h.Source == pair.Source && h.Destination == pair.Destination
		})
		if i < 0 {
			t.Fatalf("held moves = %+v, want %s -> %s named", held, pair.Source, pair.Destination)
		}
		switch reason := held[i].Reason; {
		case strings.Contains(reason, cause):
			staged++
		case reason == linkedHoldReason:
		default:
			t.Fatalf("held move %+v, want %q or the linked-move reason", held[i], cause)
		}
	}
	if staged != 1 {
		t.Fatalf("held moves = %+v, want exactly one of them to name %q", held, cause)
	}
}

func assertPendingRecords(t *testing.T, rec journalRecord, want bool, paths ...string) {
	t.Helper()
	for _, path := range paths {
		i := slices.IndexFunc(rec.Paths, func(pr pathRecord) bool { return pr.Path == path })
		if i < 0 {
			t.Fatalf("journalled paths = %+v, want %s among them", rec.Paths, path)
		}
		if got := rec.Paths[i].Pending != nil; got != want {
			t.Fatalf("%s pending = %+v, want a pending record on disk = %v", path, rec.Paths[i].Pending, want)
		}
	}
}

// The rows are the whole source-state by destination-state matrix — each endpoint holding its
// recorded identity, absent, or replaced from outside — because only two of the nine settle.
func TestRecover_SettlesAPendingMoveOnlyFromBothEndpointsTogether(t *testing.T) {
	cases := []struct {
		name          string
		stage         func(t *testing.T, source, destination string)
		interrupt     func(t *testing.T)
		wantMoveState moveState
		wantPending   bool
		wantCompleted bool
		wantHeld      bool
	}{
		{
			name: "the source holds its recorded identity and the destination is absent",
			stage: func(t *testing.T, source, destination string) {
				if err := os.Rename(destination, source); err != nil {
					t.Fatalf("put the moved entry back by hand: %v", err)
				}
			},
			interrupt: func(t *testing.T) { crashAt(t, "restored") },
		},
		{
			name:          "the destination holds the moved identity and the source is absent",
			stage:         func(t *testing.T, source, destination string) {},
			wantCompleted: true,
		},
		{
			name: "a replaced source with an absent destination",
			stage: func(t *testing.T, source, destination string) {
				clearEntry(t, destination)
				replaceFile(t, source, "A THIRD WRITER\n")
			},
			wantMoveState: movePending,
			wantPending:   true,
			wantHeld:      true,
		},
		{
			name: "a replaced source and the destination holding the moved identity",
			stage: func(t *testing.T, source, destination string) {
				replaceFile(t, source, "A THIRD WRITER\n")
			},
			wantMoveState: movePending,
			wantPending:   true,
			wantHeld:      true,
		},
		{
			name:          "neither endpoint exists",
			stage:         func(t *testing.T, source, destination string) { clearEntry(t, destination) },
			wantMoveState: movePending,
			wantPending:   true,
			wantHeld:      true,
		},
		{
			name: "the source holds its recorded identity and so does the destination",
			stage: func(t *testing.T, source, destination string) {
				if err := os.Link(destination, source); err != nil {
					t.Fatalf("link the moved entry back at the source: %v", err)
				}
			},
			wantMoveState: movePending,
			wantPending:   true,
			wantHeld:      true,
		},
		{
			name: "the source holds its recorded identity and the destination was replaced",
			stage: func(t *testing.T, source, destination string) {
				if err := os.Rename(destination, source); err != nil {
					t.Fatalf("put the moved entry back by hand: %v", err)
				}
				replaceFile(t, destination, "A THIRD WRITER\n")
			},
			wantMoveState: movePending,
			wantPending:   true,
			wantHeld:      true,
		},
		{
			name: "an absent source and a replaced destination",
			stage: func(t *testing.T, source, destination string) {
				replaceFile(t, destination, "A THIRD WRITER\n")
			},
			wantMoveState: movePending,
			wantPending:   true,
			wantHeld:      true,
		},
		{
			name: "a replaced source and a replaced destination",
			stage: func(t *testing.T, source, destination string) {
				replaceFile(t, source, "A THIRD WRITER\n")
				replaceFile(t, destination, "ANOTHER THIRD WRITER\n")
			},
			wantMoveState: movePending,
			wantPending:   true,
			wantHeld:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			source := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
			destination := filepath.Join(f.project, "b.txt")
			j := f.openMoves(t, nil, pairOf(source, destination))
			crashAt(t, "move_completed")
			f.mustMove(t, j, source, destination)
			if got := onDiskRecord(t, j).Moves; len(got) != 1 || got[0].State != movePending {
				t.Fatalf("journalled moves = %+v, want the move left pending", got)
			}
			tc.stage(t, source, destination)
			orphan(t, j)
			before := captureEntries(t, source, destination)
			var atUndoBegan journalRecord
			switch {
			case tc.interrupt != nil:
				tc.interrupt(t)
			case tc.wantCompleted:
				onJournalStep(t, "move_undoing", func() { atUndoBegan = recordIn(t, j.Path()) })
			}

			report := Recover(f.home, f.project, answer(ChoiceRestore))

			if tc.wantHeld || tc.interrupt != nil {
				assertEntriesUnchanged(t, before)
				assertRecordPresent(t, j)
				rec := onDiskRecord(t, j)
				switch {
				case tc.wantMoveState == "":
					if len(rec.Moves) != 0 {
						t.Fatalf("journalled moves = %+v, want the move that never happened dropped", rec.Moves)
					}
				case len(rec.Moves) != 1 || rec.Moves[0].State != tc.wantMoveState:
					t.Fatalf("journalled moves = %+v, want one move recorded as %q", rec.Moves, tc.wantMoveState)
				}
				assertPendingRecords(t, rec, tc.wantPending, source, destination)
				if len(report.Retained) != 1 {
					t.Fatalf("retained = %+v, want the journal reported", report.Retained)
				}
				if tc.wantHeld {
					assertHeldMoves(t, report.Retained[0], []permissions.MovePair{pairOf(source, destination)}, unresolvedMoveCause)
					return
				}
				report = Recover(f.home, f.project, answer(ChoiceRestore))
			}

			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want the resolved pending move recovered", report.Retained)
			}
			if tc.wantCompleted {
				var whenUndoBegan []moveState
				for _, m := range atUndoBegan.Moves {
					whenUndoBegan = append(whenUndoBegan, m.State)
				}
				if !slices.Equal(whenUndoBegan, []moveState{moveCompleted}) {
					t.Fatalf("journalled moves when the undo began = %v, want the pending move recorded as completed first", whenUndoBegan)
				}
				assertPendingRecords(t, atUndoBegan, false, source, destination)
			}
			assertFile(t, source, "ORIGINAL\n", 0o640)
			assertGone(t, destination)
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_LeavesANewerSchemaJournalAndEveryProjectPathUntouched(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.openScopes(t, nil, []string{target})
	f.mustDelete(t, j, target)
	orphan(t, j)
	rewriteRecord(t, j, func(rec *journalRecord) { rec.SchemaVersion = journalAnswerSchemaVersion + 1 })

	report := Recover(f.home, f.project, answer(ChoiceRestore))

	assertGone(t, target)
	assertRecordPresent(t, j)
	if len(report.Retained) != 1 || len(report.Restored) != 0 {
		t.Fatalf("report = %+v, want the unreadable journal retained and nothing restored", report)
	}
	if got := onDiskRecord(t, j).SchemaVersion; got != journalAnswerSchemaVersion+1 {
		t.Fatalf("schema_version = %d, want the record left as it was", got)
	}
}

func clearEntry(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("clear %s: %v", path, err)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatalf("lstat %s: %v", src, err)
	}
	switch {
	case info.IsDir():
		if mErr := os.Mkdir(dst, 0o700); mErr != nil {
			t.Fatalf("stage the replacement directory: %v", mErr)
		}
		for _, name := range dirNames(t, src) {
			copyTree(t, filepath.Join(src, name), filepath.Join(dst, name))
		}
	case info.Mode()&os.ModeSymlink != 0:
		target, lErr := os.Readlink(src)
		if lErr != nil {
			t.Fatalf("readlink %s: %v", src, lErr)
		}
		if sErr := os.Symlink(target, dst); sErr != nil {
			t.Fatalf("stage the replacement symlink: %v", sErr)
		}
		return
	default:
		if wErr := os.WriteFile(dst, []byte(readFile(t, src)), info.Mode().Perm()); wErr != nil {
			t.Fatalf("stage the replacement file: %v", wErr)
		}
	}
	if cErr := os.Chmod(dst, info.Mode().Perm()); cErr != nil {
		t.Fatalf("chmod the replacement: %v", cErr)
	}
}

func replaceWithSameContent(t *testing.T, path string) {
	t.Helper()
	displaced := captureEntry(t, path)
	if displaced.info == nil {
		t.Fatalf("%s is absent, want an entry to replace", path)
	}
	staged := path + ".third-party"
	copyTree(t, path, staged)
	clearEntry(t, path)
	if rErr := os.Rename(staged, path); rErr != nil {
		t.Fatalf("swap in the replacement: %v", rErr)
	}
	replacement := captureEntry(t, path)
	if replacement.info == nil || os.SameFile(replacement.info, displaced.info) {
		t.Fatalf("replacement of %s = %v, want another identity", path, replacement.info)
	}
	want := entryContent(displaced, ".")
	if got := entryContent(replacement, "."); got != want {
		t.Fatalf("replacement of %s = %q, want the %q it displaced", path, got, want)
	}
}

type outsideEndpointState struct {
	name  string
	plant func(t *testing.T, path string)
}

var outsideEndpointStates = []outsideEndpointState{
	{
		name: "an outside file",
		plant: func(t *testing.T, path string) {
			clearEntry(t, path)
			replaceFile(t, path, "A THIRD WRITER\n")
		},
	},
	{
		name: "an outside directory with entries",
		plant: func(t *testing.T, path string) {
			clearEntry(t, path)
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatalf("plant an outside directory: %v", err)
			}
			if err := os.WriteFile(filepath.Join(path, "kept.txt"), []byte("KEPT\n"), 0o644); err != nil {
				t.Fatalf("fill the outside directory: %v", err)
			}
		},
	},
	{
		name: "an empty outside directory",
		plant: func(t *testing.T, path string) {
			clearEntry(t, path)
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatalf("plant an empty outside directory: %v", err)
			}
		},
	},
	{
		name: "a symlink",
		plant: func(t *testing.T, path string) {
			clearEntry(t, path)
			if err := os.Symlink("elsewhere", path); err != nil {
				t.Fatalf("plant a symlink: %v", err)
			}
		},
	},
	{name: "a deleted entry", plant: clearEntry},
	{name: "a same-content replacement with a different identity", plant: replaceWithSameContent},
}

type linkedMoves struct {
	j             *Journal
	group         []permissions.MovePair
	broken        string
	pendingSource string
	watch         []string
	spare         permissions.MovePair
}

type linkedMoveShape struct {
	name  string
	build func(t *testing.T, f *fixture, beforeLast func()) *linkedMoves
}

var linkedMoveShapes = []linkedMoveShape{
	{name: "a shared endpoint", build: buildSharedEndpointMoves},
	{name: "a chain", build: buildChainedMoves},
	{name: "containment", build: buildContainedMoves},
}

func (f *fixture) spareMove(t *testing.T) permissions.MovePair {
	t.Helper()
	return pairOf(f.seedMode(t, "spare.txt", "SPARE\n", 0o644), filepath.Join(f.project, "spare-moved.txt"))
}

func assertSpareMoveUndone(t *testing.T, report Report, spare permissions.MovePair) {
	t.Helper()
	assertFile(t, spare.Source, "SPARE\n", 0o644)
	assertGone(t, spare.Destination)
	if !slices.Contains(report.Restored, spare.Source) {
		t.Fatalf("restored = %v, want the unlinked move's source named", report.Restored)
	}
}

func buildSharedEndpointMoves(t *testing.T, f *fixture, beforeLast func()) *linkedMoves {
	t.Helper()
	a := f.seedMode(t, "a.txt", "A ORIGINAL\n", 0o640)
	c := f.seedMode(t, "c.txt", "C ORIGINAL\n", 0o600)
	b := filepath.Join(f.project, "b.txt")
	spare := f.spareMove(t)
	j := f.openMoves(t, nil, spare, pairOf(a, b), pairOf(c, a))
	f.mustMove(t, j, spare.Source, spare.Destination)
	f.mustMove(t, j, a, b)
	beforeLast()
	f.mustMove(t, j, c, a)
	return &linkedMoves{
		j:             j,
		group:         []permissions.MovePair{pairOf(a, b), pairOf(c, a)},
		broken:        b,
		pendingSource: c,
		watch:         []string{a, b, c},
		spare:         spare,
	}
}

func buildChainedMoves(t *testing.T, f *fixture, beforeLast func()) *linkedMoves {
	t.Helper()
	a := f.seedMode(t, "a.txt", "A ORIGINAL\n", 0o640)
	c := f.seedMode(t, "c.txt", "C ORIGINAL\n", 0o600)
	d := f.seedMode(t, "d.txt", "D ORIGINAL\n", 0o604)
	b := filepath.Join(f.project, "b.txt")
	spare := f.spareMove(t)
	j := f.openMoves(t, nil, spare, pairOf(a, b), pairOf(c, a), pairOf(d, c))
	f.mustMove(t, j, spare.Source, spare.Destination)
	f.mustMove(t, j, a, b)
	f.mustMove(t, j, c, a)
	beforeLast()
	f.mustMove(t, j, d, c)
	return &linkedMoves{
		j:             j,
		group:         []permissions.MovePair{pairOf(a, b), pairOf(c, a), pairOf(d, c)},
		broken:        b,
		pendingSource: d,
		watch:         []string{a, b, c, d},
		spare:         spare,
	}
}

func buildContainedMoves(t *testing.T, f *fixture, beforeLast func()) *linkedMoves {
	t.Helper()
	f.seedMode(t, "tree/inner/leaf.txt", "LEAF\n", 0o600)
	inner := f.dir(t, "tree/inner", 0o700)
	tree := f.dir(t, "tree", 0o750)
	other := filepath.Join(tree, "other")
	moved := filepath.Join(f.project, "moved")
	spare := f.spareMove(t)
	j := f.openMoves(t, nil, spare, pairOf(inner, other), pairOf(tree, moved))
	f.mustMove(t, j, spare.Source, spare.Destination)
	f.mustMove(t, j, inner, other)
	beforeLast()
	f.mustMove(t, j, tree, moved)
	return &linkedMoves{
		j:             j,
		group:         []permissions.MovePair{pairOf(inner, other), pairOf(tree, moved)},
		broken:        moved,
		pendingSource: tree,
		watch:         []string{tree, inner, other, moved, filepath.Join(moved, "other"), filepath.Join(moved, "other", "leaf.txt")},
		spare:         spare,
	}
}

func assertGroupHeld(t *testing.T, f *fixture, lm *linkedMoves, before []entrySnapshot, cause string) {
	t.Helper()
	var asked []string
	report := Recover(f.home, f.project, func(u Unresolved) Choice {
		if len(u.Moves) > 0 {
			return ChoiceDefer
		}
		asked = append(asked, u.Path)
		return ChoiceRestore
	})

	assertEntriesUnchanged(t, before)
	if len(asked) != 0 {
		t.Fatalf("asked about %v, want no question for a held move or its endpoints", asked)
	}
	assertRecordPresent(t, lm.j)
	if len(report.Retained) != 1 || report.Retained[0].Path != lm.j.Path() {
		t.Fatalf("retained = %+v, want the journal reported", report.Retained)
	}
	assertHeldMoves(t, report.Retained[0], lm.group, cause)
	assertSpareMoveUndone(t, report, lm.spare)
}

func TestRecover_HoldsEveryMoveLinkedToAnEndpointChangedOutsideTheChild(t *testing.T) {
	for _, shape := range linkedMoveShapes {
		for _, state := range outsideEndpointStates {
			t.Run(shape.name+"/"+state.name, func(t *testing.T) {
				f := newFixture(t)
				lm := shape.build(t, f, func() {})
				state.plant(t, lm.broken)
				orphan(t, lm.j)

				assertGroupHeld(t, f, lm, captureEntries(t, lm.watch...), outsideChangeCause)
			})
		}
	}
}

func TestRecover_HoldsEveryMoveLinkedToOneThatWasNeverResolved(t *testing.T) {
	for _, shape := range linkedMoveShapes {
		t.Run(shape.name, func(t *testing.T) {
			f := newFixture(t)
			lm := shape.build(t, f, func() { crashAt(t, "move_completed") })
			replaceFile(t, lm.pendingSource, "A THIRD WRITER\n")
			orphan(t, lm.j)
			if got := onDiskRecord(t, lm.j).Moves; got[len(got)-1].State != movePending {
				t.Fatalf("journalled moves = %+v, want the last one left pending", got)
			}

			assertGroupHeld(t, f, lm, captureEntries(t, lm.watch...), unresolvedMoveCause)
		})
	}
}

func TestRecover_HoldsAGroupWhoseJournalledPathInsideAMovedEntryCannotBePutBack(t *testing.T) {
	f := newFixture(t)
	inner := f.dir(t, "tree/inner", 0o700)
	tree := f.dir(t, "tree", 0o750)
	other := filepath.Join(tree, "other")
	moved := filepath.Join(f.project, "moved")
	created := filepath.Join(moved, "new.txt")
	j := f.openMoves(t, []string{created}, pairOf(inner, other), pairOf(tree, moved))
	f.mustMove(t, j, inner, other)
	f.mustMove(t, j, tree, moved)
	mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
	replaceFile(t, created, "A THIRD WRITER\n")
	orphan(t, j)
	before := captureEntries(t, tree, inner, other, moved, filepath.Join(moved, "other"), created)

	var asked []string
	report := Recover(f.home, f.project, func(u Unresolved) Choice {
		asked = append(asked, u.Path)
		return ChoiceDefer
	})

	assertEntriesUnchanged(t, before)
	for _, endpoint := range []string{tree, inner, other, moved} {
		if slices.Contains(asked, endpoint) {
			t.Fatalf("asked about %v, want no question for a held move's endpoints", asked)
		}
	}
	assertRecordPresent(t, j)
	if len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the journal reported", report.Retained)
	}
	assertHeldMoves(t, report.Retained[0], []permissions.MovePair{pairOf(inner, other), pairOf(tree, moved)}, unrestoredDescendantCause)
}

func TestRecover_ResumesAMoveUndoInterruptedAtEachDurablePoint(t *testing.T) {
	cases := []struct {
		name              string
		recreate          bool
		interrupt         func(t *testing.T)
		wantMovedAtSource bool
		wantState         moveState
	}{
		{name: "after the source the child recreated is cleared", recreate: true, interrupt: failAfterSyncOnce, wantState: moveUndoing},
		{name: "after the undo is recorded as begun", interrupt: func(t *testing.T) { crashAt(t, "move_undone") }, wantMovedAtSource: true, wantState: moveUndoing},
		{name: "after the undo is recorded as done", interrupt: func(t *testing.T) { crashAt(t, "restored") }, wantMovedAtSource: true, wantState: moveUndone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			source := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
			destination := filepath.Join(f.project, "b.txt")
			j := f.openMoves(t, nil, pairOf(source, destination))
			f.mustMove(t, j, source, destination)
			moved, err := os.Lstat(destination)
			if err != nil {
				t.Fatalf("lstat the moved entry: %v", err)
			}
			if tc.recreate {
				mustSucceed(t, f.childCreate(t, j, source, "CHILD REMADE THIS\n"))
			}
			orphan(t, j)

			tc.interrupt(t)
			if report := Recover(f.home, f.project, nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}

			assertRecordPresent(t, j)
			if tc.wantMovedAtSource {
				assertFile(t, source, "ORIGINAL\n", 0o640)
				assertSameEntry(t, source, moved)
				assertGone(t, destination)
			} else {
				assertGone(t, source)
				assertFile(t, destination, "ORIGINAL\n", 0o640)
				assertSameEntry(t, destination, moved)
			}
			if got := onDiskRecord(t, j).Moves; len(got) != 1 || got[0].State != tc.wantState {
				t.Fatalf("journalled moves after the interrupted pass = %+v, want one move recorded as %q", got, tc.wantState)
			}

			report := Recover(f.home, f.project, nil)

			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want the resumed pass to complete", report.Retained)
			}
			assertFile(t, source, "ORIGINAL\n", 0o640)
			assertSameEntry(t, source, moved)
			assertGone(t, destination)
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_RemovesOnlyTheJournalOfACommittedMoveSurvivor(t *testing.T) {
	f := newFixture(t)
	source := f.seedMode(t, "a.txt", "ORIGINAL\n", 0o640)
	destination := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, nil, pairOf(source, destination))
	f.mustMove(t, j, source, destination)
	rewriteRecord(t, j, func(rec *journalRecord) { rec.Lifecycle = lifecycleCommitted })
	orphan(t, j)
	before := captureEntries(t, source, destination)

	report := Recover(f.home, f.project, answer(ChoiceRestore))

	assertEntriesUnchanged(t, before)
	assertGone(t, j.Path())
	if !report.Empty() {
		t.Fatalf("report = %+v, want a committed move survivor to report nothing", report)
	}
}

func TestRecover_SettlesAnOrphanedChildsDeclaredDirectoriesLikeALiveRollback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, f *fixture) (*Journal, func(t *testing.T))
	}{
		{"a directory and the file declared inside it", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			dir := filepath.Join(f.project, "a")
			file := filepath.Join(dir, "f.txt")
			j := f.openConfig(t, JournalConfig{Declared: []string{file}, DeclaredDirs: []string{dir}})
			mustSucceed(t, f.childMkdir(t, j, dir))
			mustSucceed(t, f.childCreate(t, j, file, "CHILD\n"))
			return j, func(t *testing.T) { assertGone(t, dir) }
		}},
		{"a directory first made as a declared file's parent", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			dir := filepath.Join(f.project, "a")
			file := filepath.Join(dir, "f.txt")
			j := f.openConfig(t, JournalConfig{Declared: []string{file}, DeclaredDirs: []string{dir}})
			mustSucceed(t, f.childCreate(t, j, file, "CHILD\n"))
			mustSucceed(t, f.childMkdir(t, j, dir))
			return j, func(t *testing.T) { assertGone(t, dir) }
		}},
		{"a directory inside a moved entry", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			tree := f.dir(t, "tree", 0o750)
			f.seedMode(t, "tree/leaf.txt", "LEAF\n", 0o600)
			before := captureEntries(t, tree)
			moved := filepath.Join(f.project, "moved")
			j := f.openConfig(t, JournalConfig{DeclaredMoves: []permissions.MovePair{pairOf(tree, moved)}, DeclaredDirs: []string{filepath.Join(moved, "sub")}})
			f.mustMove(t, j, tree, moved)
			mustSucceed(t, f.childMkdir(t, j, filepath.Join(moved, "sub")))
			return j, func(t *testing.T) {
				assertEntriesUnchanged(t, before)
				assertGone(t, moved)
			}
		}},
		{"a directory made where a moved entry left", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			tree := f.dir(t, "tree", 0o750)
			f.seedMode(t, "tree/leaf.txt", "LEAF\n", 0o600)
			before := captureEntries(t, tree)
			moved := filepath.Join(f.project, "moved")
			j := f.openConfig(t, JournalConfig{DeclaredMoves: []permissions.MovePair{pairOf(tree, moved)}, DeclaredDirs: []string{tree}})
			f.mustMove(t, j, tree, moved)
			mustSucceed(t, f.childMkdir(t, j, tree))
			return j, func(t *testing.T) {
				assertEntriesUnchanged(t, before)
				assertGone(t, moved)
			}
		}},
		{"a directory below a deleted then recreated ancestor", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			ancestor := f.dir(t, "d", 0o750)
			sub := filepath.Join(ancestor, "sub")
			j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{ancestor}, DeclaredDirs: []string{ancestor, sub}})
			f.mustDelete(t, j, ancestor)
			mustSucceed(t, f.childMkdir(t, j, ancestor))
			mustSucceed(t, f.childMkdir(t, j, sub))
			return j, func(t *testing.T) {
				assertDir(t, ancestor, 0o750)
				assertGone(t, sub)
			}
		}},
		{"a directory recreated after the child deleted it", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			target := filepath.Join(f.project, "d")
			j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{target}, DeclaredDirs: []string{target}})
			mustSucceed(t, f.childMkdir(t, j, target))
			f.mustDelete(t, j, target)
			mustSucceed(t, f.childMkdir(t, j, target))
			return j, func(t *testing.T) { assertGone(t, target) }
		}},
		{"a pre-existing directory deleted and recreated twice", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			target := f.dir(t, "d", 0o750)
			j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{target}, DeclaredDirs: []string{target}})
			for range 2 {
				f.mustDelete(t, j, target)
				mustSucceed(t, f.childMkdir(t, j, target))
			}
			return j, func(t *testing.T) { assertDir(t, target, 0o750) }
		}},
		{"a directory recreated through another declaration", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			j, a, sub := recreateThroughTheNestedDeclaration(t, f)
			return j, func(t *testing.T) {
				assertGone(t, sub)
				assertGone(t, a)
			}
		}},
		{"nested directories", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			target := filepath.Join(f.project, "x", "y", "z")
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{target}})
			mustSucceed(t, f.childMkdir(t, j, target))
			return j, func(t *testing.T) { assertGone(t, filepath.Join(f.project, "x")) }
		}},
		{"an unused and a pre-existing declaration", func(t *testing.T, f *fixture) (*Journal, func(t *testing.T)) {
			existing := f.dir(t, "existing", 0o750)
			f.seed(t, "existing/keep.txt", "KEEP\n")
			before := captureEntries(t, existing)
			unused := filepath.Join(f.project, "unused")
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{existing, unused}})
			mustSucceed(t, f.childMkdir(t, j, existing))
			return j, func(t *testing.T) {
				assertEntriesUnchanged(t, before)
				assertGone(t, unused)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			j, check := tc.build(t, f)
			rec := onDiskRecord(t, j)
			want := journalDirSchemaVersion
			if len(rec.Moves) > 0 {
				want = journalAnswerSchemaVersion
			}
			if rec.SchemaVersion != want {
				t.Fatalf("schema_version = %d, want %d for a journal holding a declared directory and %d moves", rec.SchemaVersion, want, len(rec.Moves))
			}
			orphan(t, j)

			report := Recover(f.home, f.project, func(u Unresolved) Choice {
				t.Fatalf("asked about %s, want nothing left to ask", u.Path)
				return ChoiceDefer
			})

			if len(report.Retained) != 0 {
				t.Fatalf("retained = %+v, want the journal fully recovered", report.Retained)
			}
			check(t)
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_ReportsARetainedDirectoryAtEveryLaunchWithoutOfferingIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, dir string)
	}{
		{"holding another writer's file", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "foreign.txt"), []byte("NOT MINE\n"), 0o644); err != nil {
				t.Fatalf("seed foreign file: %v", err)
			}
		}},
		{"replaced", func(t *testing.T, dir string) {
			if err := os.Remove(dir); err != nil {
				t.Fatalf("remove the created directory: %v", err)
			}
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatalf("plant a replacement: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			dir := filepath.Join(f.project, "made")
			edited := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.openConfig(t, JournalConfig{Declared: []string{edited}, DeclaredDirs: []string{dir}})
			mustSucceed(t, f.childMkdir(t, j, dir))
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			tc.change(t, dir)
			if err := os.WriteFile(edited, []byte("A HAND EDIT\n"), 0o644); err != nil {
				t.Fatalf("hand edit: %v", err)
			}
			before := captureEntries(t, dir)
			orphan(t, j)

			for launch := 1; launch <= 2; launch++ {
				var asked []string
				report := Recover(f.home, f.project, func(u Unresolved) Choice {
					asked = append(asked, u.Path)
					return ChoiceDefer
				})

				if !slices.Equal(asked, []string{edited}) {
					t.Fatalf("launch %d asked about %v, want only the ordinary path %s", launch, asked, edited)
				}
				if len(report.Retained) != 1 || !slices.Equal(report.Retained[0].Dirs, []string{dir}) {
					t.Fatalf("launch %d retained = %+v, want %s listed as a retained directory", launch, report.Retained, dir)
				}
				notes := report.Retained[0].Notes
				if slices.ContainsFunc(notes, func(n string) bool { return strings.HasPrefix(n, dir) }) || !slices.ContainsFunc(notes, func(n string) bool { return strings.HasPrefix(n, edited) }) {
					t.Fatalf("launch %d notes = %v, want the ordinary path and not the directory", launch, notes)
				}
				assertEntriesUnchanged(t, before)
				assertRecordPresent(t, j)
			}
		})
	}
}

func TestRecover_KeepsTheChoiceOfADeletePathAlsoDeclaredAsADirectory(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "d", "ORIGINAL\n")
	j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{target}, DeclaredDirs: []string{target}})
	f.mustDelete(t, j, target)
	if err := os.WriteFile(target, []byte("THIRD PARTY\n"), 0o644); err != nil {
		t.Fatalf("third-party write: %v", err)
	}
	orphan(t, j)

	var asked []string
	report := Recover(f.home, f.project, func(u Unresolved) Choice {
		asked = append(asked, u.Path)
		return ChoiceKeep
	})

	if !slices.Equal(asked, []string{target}) || !slices.Contains(report.Kept, target) {
		t.Fatalf("asked %v, report %+v, want the delete path offered and kept", asked, report)
	}
	assertContent(t, target, "THIRD PARTY\n")
	assertGone(t, j.Path())
}

func TestRecover_NeverOffersADirectoryOnlyDeclarationAnotherWriterFilled(t *testing.T) {
	for _, tc := range []struct {
		name string
		fill func(t *testing.T, f *fixture, j *Journal, dir string)
	}{
		{"unused, then made by another writer", func(t *testing.T, _ *fixture, _ *Journal, dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatalf("plant another writer's directory: %v", err)
			}
		}},
		{"a creation never confirmed", func(t *testing.T, f *fixture, j *Journal, dir string) {
			crashAt(t, "dir_confirm")
			if res := f.childMkdir(t, j, dir); res.ExitCode == 0 {
				t.Fatalf("mkdir = %+v, want the failed confirmation reported", res)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			dir := filepath.Join(f.project, "made")
			edited := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.openConfig(t, JournalConfig{Declared: []string{edited}, DeclaredDirs: []string{dir}})
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			tc.fill(t, f, j, dir)
			if err := os.WriteFile(edited, []byte("A HAND EDIT\n"), 0o644); err != nil {
				t.Fatalf("hand edit: %v", err)
			}
			before := captureEntries(t, dir)
			orphan(t, j)

			var asked []string
			Recover(f.home, f.project, func(u Unresolved) Choice {
				asked = append(asked, u.Path)
				return ChoiceRestore
			})

			if !slices.Equal(asked, []string{edited}) {
				t.Fatalf("asked about %v, want only the ordinary path %s", asked, edited)
			}
			assertContent(t, edited, "ORIGINAL\n")
			assertEntriesUnchanged(t, before)
			assertRecordPresent(t, j)
		})
	}
}

func TestRecover_OffersADeletePathWhoseDirectoryCreationIsUnsettled(t *testing.T) {
	for _, tc := range []struct {
		choice Choice
		want   string
	}{
		{ChoiceRestore, "ORIGINAL\n"},
		{ChoiceKeep, "THIRD PARTY\n"},
	} {
		t.Run(string(tc.choice), func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "d", "ORIGINAL\n")
			j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{target}, DeclaredDirs: []string{target}})
			f.mustDelete(t, j, target)
			mustSucceed(t, f.childMkdir(t, j, target))
			if err := os.Remove(target); err != nil {
				t.Fatalf("remove the created directory: %v", err)
			}
			if err := os.WriteFile(target, []byte("THIRD PARTY\n"), 0o644); err != nil {
				t.Fatalf("third-party write: %v", err)
			}
			orphan(t, j)

			var asked []string
			report := Recover(f.home, f.project, func(u Unresolved) Choice {
				asked = append(asked, u.Path)
				return tc.choice
			})

			if !slices.Equal(asked, []string{target}) || len(report.Retained) != 0 {
				t.Fatalf("asked %v, report %+v, want the delete path offered and the journal recovered", asked, report)
			}
			assertContent(t, target, tc.want)
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_RetainsADirectoryFirstMadeAsADeclaredFilesParent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, dir string) string
	}{
		{"holding another writer's file", func(t *testing.T, dir string) string {
			foreign := filepath.Join(dir, "foreign.txt")
			if err := os.WriteFile(foreign, []byte("NOT MINE\n"), 0o644); err != nil {
				t.Fatalf("seed foreign file: %v", err)
			}
			return foreign
		}},
		{"replaced", func(t *testing.T, dir string) string {
			if err := os.Rename(dir, dir+"-aside"); err != nil {
				t.Fatalf("move the created directory aside: %v", err)
			}
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatalf("plant a replacement: %v", err)
			}
			return dir
		}},
	} {
		for _, orphaned := range []bool{false, true} {
			name := tc.name + "/live"
			if orphaned {
				name = tc.name + "/orphaned"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				dir := filepath.Join(f.project, "a")
				file := filepath.Join(dir, "f.txt")
				j := f.openConfig(t, JournalConfig{Declared: []string{file}, DeclaredDirs: []string{dir}})
				mustSucceed(t, f.childCreate(t, j, file, "CHILD\n"))
				mustSucceed(t, f.childMkdir(t, j, dir))
				if n := createdDirsAt(onDiskRecord(t, j), dir); n != 1 {
					t.Fatalf("%d created-directory records for %s, want one", n, dir)
				}
				before := captureEntries(t, tc.change(t, dir))

				if !orphaned {
					outcome := j.Finish(ReasonCancelled)
					if !slices.Equal(outcome.RetainedDirs, []string{dir}) || outcome.JournalPath == "" {
						t.Fatalf("outcome = %+v, want %s retained and reported", outcome, dir)
					}
				} else {
					orphan(t, j)
					report := Recover(f.home, f.project, func(u Unresolved) Choice {
						t.Fatalf("asked about %s, want nothing offered", u.Path)
						return ChoiceDefer
					})
					if len(report.Retained) != 1 || !slices.Equal(report.Retained[0].Dirs, []string{dir}) ||
						slices.ContainsFunc(report.Retained[0].Notes, func(n string) bool { return strings.HasPrefix(n, dir+": ") }) {
						t.Fatalf("retained = %+v, want %s listed in Dirs and not in Notes", report.Retained, dir)
					}
				}
				assertEntriesUnchanged(t, before)
				assertRecordPresent(t, j)
			})
		}
	}
}
