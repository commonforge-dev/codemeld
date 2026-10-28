package subagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/filetools"
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

	report := Recover(f.home, f.project, f.policy(), nil)

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

func (f *fixture) policy(blocked ...string) RecoveryPolicy {
	refresh := func() (*permissions.BlockedPaths, error) { return f.blockedList(blocked...), nil }
	return RecoveryPolicy{Blocked: f.blockedList(blocked...), Refresh: refresh}
}

func (f *fixture) blockedList(blocked ...string) *permissions.BlockedPaths {
	entries := make([]permissions.BlockedEntry, 0, len(blocked))
	for _, path := range blocked {
		entries = append(entries, permissions.BlockedEntry{Path: path, Source: "settings.yaml"})
	}
	return permissions.NewBlockedPaths(f.home, entries)
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

	report := Recover(f.home, f.project, f.policy(), nil)

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
			rewriteRecord(t, j, func(rec *journalRecord) { rec.SchemaVersion = journalCompletedSchemaVersion + 1 })
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

			report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

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

			report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

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

		if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
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

		report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

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

	if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
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

	if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
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
	report := Recover(f.home, f.project, f.policy(), nil)

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

			report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

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
		report := Recover(f.home, f.project, f.policy(), nil)
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

	report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

	if got := readFile(t, target); got != "A THIRD WRITER\n" {
		t.Fatalf("%s = %q, want a committed survivor to compare and restore nothing", target, got)
	}
	assertGone(t, j.Path())
	if !report.Empty() {
		t.Fatalf("report = %+v, want a cleanup-only survivor to report nothing", report)
	}
}

func TestRecover_AttributesACompletedCommittedSurvivorWhoseCleanupFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	j.rec.Completed = true
	j.rec.Lifecycle = lifecycleCommitted
	if err := j.flush(); err != nil {
		t.Fatalf("flush the completed and committed markers: %v", err)
	}
	orphan(t, j)
	if err := os.Chmod(j.Path(), 0o500); err != nil {
		t.Fatalf("remove write permission: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(j.Path(), journalDirMode) })

	report := Recover(f.home, f.project, f.policy(), neverAsked(t))

	if got := readFile(t, target); got != "CHILD\n" {
		t.Fatalf("%s = %q, want the child's work left as it is", target, got)
	}
	if rec := onDiskRecord(t, j); !rec.Completed || rec.Lifecycle != lifecycleCommitted {
		t.Fatalf("record = %+v, want the completed committed record still on disk", rec)
	}
	if len(report.Retained) != 1 || report.Retained[0].Path != j.Path() || !report.Retained[0].Completed || !report.Retained[0].Committed || report.Retained[0].Unanswered != 0 ||
		!strings.Contains(strings.Join(report.Retained[0].Notes, "\n"), "the committed journal could not be removed") ||
		len(report.Restored) != 0 || len(report.Kept) != 0 {
		t.Fatalf("report = %+v, want the cleanup failure retained as completed work", report)
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

		report := Recover(f.home, f.project, f.policy(), nil)

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
		report := Recover(f.home, f.project, f.policy(), nil)

		assertRecordPresent(t, child)
		assertRecordPresent(t, parent)
		if len(report.Retained) != 2 {
			t.Fatalf("retained = %+v, want both journals reported", report.Retained)
		}

		// The handover is the only thing that failed, so the next launch completes it rather than
		// leaving the pair behind for good.
		if second := Recover(f.home, f.project, f.policy(), nil); len(second.Retained) != 0 {
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

			Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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
			if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}

			report := Recover(f.home, f.project, f.policy(), nil)

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

	if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the failed removal sync to retain the journal", report.Retained)
	}
	assertGone(t, created)
	if got := onDiskRecord(t, j); got.Paths[0].Progress != rollbackRestoring {
		t.Fatalf("progress = %q, want the removal still owed its parent sync", got.Paths[0].Progress)
	}

	report := Recover(f.home, f.project, f.policy(), nil)

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

		report := Recover(f.home, f.project, f.policy(), nil)

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

		report := Recover(f.home, f.project, f.policy(), nil)

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
		report := Recover(f.home, f.project, f.policy(), func(Unresolved) Choice {
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
		if report := Recover(f.home, f.project, f.policy(), answer(ChoiceKeep)); !slices.Contains(report.Kept, kept) {
			t.Fatalf("kept = %v, want the answered path named", report.Kept)
		}

		var asked []string
		report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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

		report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

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

		report := Recover(f.home, f.project, f.policy(), answer(ChoiceDefer))

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
		report := Recover(f.home, f.project, f.policy(), answer(ChoiceKeep))

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

	if len(report.Retained) != 1 || report.Retained[0].Path != folder {
		t.Fatalf("retained = %+v, want the unopenable folder named", report.Retained)
	}
}

func TestRecover_DoesNothingWhenNoJournalWasLeftBehind(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "a.txt", "ORIGINAL\n")

	if report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore)); !report.Empty() {
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

	report := Recover(f.home, f.project, f.policy(), nil)

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
			if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}

			report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

			report := Recover(f.home, f.project, f.policy(), nil)

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
			if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 1 {
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

			report := Recover(f.home, f.project, f.policy(), nil)

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

			report := Recover(f.home, f.project, f.policy(), nil)

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
			if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 1 {
				t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
			}
			left, err := os.Lstat(target)
			if err != nil {
				t.Fatalf("lstat the entry the interrupted pass left: %v", err)
			}

			report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

			report := Recover(f.home, f.project, f.policy(), nil)

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

			report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
	if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 1 {
		t.Fatalf("retained = %+v, want the interrupted pass to report the journal", report.Retained)
	}
	if got := onDiskRecord(t, j).Moves; len(got) != 1 || got[0].State != moveUndone {
		t.Fatalf("journalled moves = %+v, want the settled pair recorded as undone", got)
	}

	report := Recover(f.home, f.project, f.policy(), nil)

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

			report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

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
				report = Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))
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
	rewriteRecord(t, j, func(rec *journalRecord) { rec.SchemaVersion = journalCompletedSchemaVersion + 1 })

	report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

	assertGone(t, target)
	assertRecordPresent(t, j)
	if len(report.Retained) != 1 || len(report.Restored) != 0 {
		t.Fatalf("report = %+v, want the unreadable journal retained and nothing restored", report)
	}
	if got := onDiskRecord(t, j).SchemaVersion; got != journalCompletedSchemaVersion+1 {
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
	report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
	report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
			if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 1 {
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

			report := Recover(f.home, f.project, f.policy(), nil)

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

	report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

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

			report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
				report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
	report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
			Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
			report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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
					report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
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

type listSwitch struct {
	blocked []string
	err     error
	calls   int
	onCall  func(call int)
}

func (f *fixture) switchPolicy(s *listSwitch) RecoveryPolicy {
	return RecoveryPolicy{Blocked: f.blockedList(), Refresh: func() (*permissions.BlockedPaths, error) {
		s.calls++
		if s.onCall != nil {
			s.onCall(s.calls)
		}
		if s.err != nil {
			return nil, s.err
		}
		return f.blockedList(s.blocked...), nil
	}}
}

func neverAsked(t *testing.T) func(Unresolved) Choice {
	return func(u Unresolved) Choice {
		t.Errorf("asked about %+v, want no question", u)
		return ChoiceDefer
	}
}

func blockedNote(label, entry string) string { return label + ": a blocked path is involved: " + entry }

func assertPolicyHeld(t *testing.T, report Report, j *Journal, notes ...string) {
	t.Helper()
	i := slices.IndexFunc(report.Retained, func(r RetainedJournal) bool { return r.Path == j.Path() })
	if i < 0 {
		t.Fatalf("retained = %+v, want %s reported", report.Retained, j.Path())
	}
	got := report.Retained[i]
	for _, note := range notes {
		if !slices.Contains(got.Notes, note) {
			t.Fatalf("notes = %q, want %q", got.Notes, note)
		}
	}
	if got.PolicyNotes != len(notes) || len(got.Moves) != 0 || slices.ContainsFunc(report.LeftAlone, func(l LeftAloneJournal) bool { return l.Path == j.Path() }) {
		t.Fatalf("retained = %+v, want %d policy notes and no held moves", got, len(notes))
	}
	assertRecordPresent(t, j)
}

func TestRecover_LeavesAMovedDirectoryAloneOnceABlockedPathLiesInIt(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "a/keep.txt", "KEEP\n")
	a, b := filepath.Join(f.project, "a"), filepath.Join(f.project, "b")
	j := f.openMoves(t, nil, pairOf(a, b))
	f.mustMove(t, j, a, b)
	orphan(t, j)
	secret := filepath.Join(b, "secret")
	if err := os.MkdirAll(secret, 0o700); err != nil {
		t.Fatalf("make the blocked folder: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secret, "token.txt"), []byte("TOKEN\n"), 0o600); err != nil {
		t.Fatalf("write the blocked file: %v", err)
	}
	before := readBytes(t, recordPath(j))

	report := Recover(f.home, f.project, f.policy(secret), neverAsked(t))

	assertContent(t, filepath.Join(secret, "token.txt"), "TOKEN\n")
	assertContent(t, filepath.Join(b, "keep.txt"), "KEEP\n")
	assertGone(t, a)
	assertPolicyHeld(t, report, j, blockedNote(a+" -> "+b, secret))
	if len(report.Restored) != 0 {
		t.Fatalf("restored = %v, want nothing put back", report.Restored)
	}
	if got := onDiskRecord(t, j).Moves; !slices.Equal(got, recordFrom(t, before).Moves) {
		t.Fatalf("moves = %+v, want the move still recorded as it was", got)
	}

	report = Recover(f.home, f.project, f.policy(), nil)

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want a clean recovery once nothing is blocked", report.Retained)
	}
	assertContent(t, filepath.Join(a, "secret", "token.txt"), "TOKEN\n")
	assertGone(t, b)
	assertGone(t, j.Path())
}

func TestRecover_HoldsAWholeLinkedGroupOverABlockedEndpointOrDescendant(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry func(source, destination string) string
	}{
		{"the destination itself", func(_, destination string) string { return destination }},
		{"an absent path under the destination", func(_, destination string) string { return filepath.Join(destination, "absent") }},
		{"a path under the source only", func(source, _ string) string { return filepath.Join(source, "ghost") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.seed(t, "tree/leaf.txt", "LEAF\n")
			tree := filepath.Join(f.project, "tree")
			moved, again := filepath.Join(f.project, "moved"), filepath.Join(f.project, "again")
			created := filepath.Join(again, "sub", "new.txt")
			pending := filepath.Join(again, "pending.txt")
			j := f.openMoves(t, []string{created, pending}, pairOf(tree, moved), pairOf(moved, again))
			f.mustMove(t, j, tree, moved)
			f.mustMove(t, j, moved, again)
			mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
			crashAt(t, "reconciled")
			f.childCreate(t, j, pending, "PENDING\n")
			orphan(t, j)
			assertPendingRecords(t, onDiskRecord(t, j), true, pending)
			entry := tc.entry(tree, again)
			before := captureEntries(t, tree, moved, again)
			record := recordFrom(t, readBytes(t, recordPath(j)))

			report := Recover(f.home, f.project, f.policy(entry), neverAsked(t))

			assertEntriesUnchanged(t, before)
			assertPolicyHeld(t, report, j, blockedNote(tree+" -> "+moved, entry))
			if got := onDiskRecord(t, j).Moves; !slices.Equal(got, record.Moves) {
				t.Fatalf("moves = %+v, want the group's records untouched", got)
			}
			assertPendingRecords(t, onDiskRecord(t, j), true, pending)
		})
	}
}

func recordFrom(t *testing.T, data []byte) journalRecord {
	t.Helper()
	var rec journalRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decode the record: %v", err)
	}
	return rec
}

func TestRecover_PutsBackUnrelatedWorkInAJournalWhoseOtherGroupIsBlocked(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "tree/leaf.txt", "LEAF\n")
	tree, moved := filepath.Join(f.project, "tree"), filepath.Join(f.project, "moved")
	x := f.seed(t, "x.txt", "X\n")
	y := filepath.Join(f.project, "y.txt")
	edited := f.seed(t, "e.txt", "ORIGINAL\n")
	j := f.openMoves(t, []string{edited}, pairOf(tree, moved), pairOf(x, y))
	f.mustMove(t, j, tree, moved)
	f.mustMove(t, j, x, y)
	f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
	orphan(t, j)
	secret := filepath.Join(moved, "secret")
	before := captureEntries(t, tree, moved)

	report := Recover(f.home, f.project, f.policy(secret), neverAsked(t))

	assertEntriesUnchanged(t, before)
	assertContent(t, x, "X\n")
	assertGone(t, y)
	assertContent(t, edited, "ORIGINAL\n")
	assertPolicyHeld(t, report, j, blockedNote(tree+" -> "+moved, secret))
	for _, path := range []string{x, edited} {
		if !slices.Contains(report.Restored, path) {
			t.Fatalf("restored = %v, want %s put back", report.Restored, path)
		}
	}
}

func TestRecover_HoldsASinglePathTheListBlocks(t *testing.T) {
	f := newFixture(t)
	blocked := f.seed(t, "a.txt", "ORIGINAL\n")
	other := f.seed(t, "b.txt", "ORIGINAL\n")
	j := f.open(t, blocked, other)
	f.childEdit(t, j, blocked, "ORIGINAL", "CHILD")
	f.childEdit(t, j, other, "ORIGINAL", "CHILD")
	orphan(t, j)

	report := Recover(f.home, f.project, f.policy(blocked), neverAsked(t))

	assertContent(t, blocked, "CHILD\n")
	assertContent(t, other, "ORIGINAL\n")
	assertPolicyHeld(t, report, j, blockedNote(blocked, blocked))

	if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want the path put back once it is no longer blocked", report.Retained)
	}
	assertContent(t, blocked, "ORIGINAL\n")
	assertGone(t, j.Path())
}

func heldFileMove(t *testing.T, f *fixture) (j *Journal, a, b string) {
	t.Helper()
	a = f.seed(t, "a.txt", "ORIGINAL\n")
	b = filepath.Join(f.project, "b.txt")
	j = f.openMoves(t, nil, pairOf(a, b))
	f.mustMove(t, j, a, b)
	replaceFile(t, b, "A THIRD WRITER\n")
	orphan(t, j)
	return j, a, b
}

func TestRecover_ARecordedRestoreWaitsOutABlockAndReplaysAfterIt(t *testing.T) {
	f := newFixture(t)
	j, a, b := heldFileMove(t, f)
	crashAt(t, "move_undoing")
	Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))
	answers := onDiskRecord(t, j).Answers
	if len(answers) != 1 || answers[0].Choice != ChoiceRestore {
		t.Fatalf("answers = %+v, want one recorded Restore", answers)
	}
	before := captureEntries(t, a, b)

	report := Recover(f.home, f.project, f.policy(b), neverAsked(t))

	assertEntriesUnchanged(t, before)
	assertPolicyHeld(t, report, j, blockedNote(a+" -> "+b, b))
	if got := onDiskRecord(t, j).Answers; !slices.EqualFunc(got, answers, func(x, y groupAnswer) bool { return x.Choice == y.Choice && slices.Equal(x.Endpoints, y.Endpoints) }) {
		t.Fatalf("answers = %+v, want the recorded Restore kept (%+v)", got, answers)
	}

	report = Recover(f.home, f.project, f.policy(), neverAsked(t))

	if len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want the recorded Restore replayed", report.Retained)
	}
	assertContent(t, a, "ORIGINAL\n")
	assertGone(t, b)
	assertGone(t, j.Path())
}

func TestRecover_ABlockAddedWhileAQuestionIsOpenStopsTheAnswer(t *testing.T) {
	for _, choice := range []Choice{ChoiceRestore, ChoiceKeep} {
		t.Run(string(choice), func(t *testing.T) {
			f := newFixture(t)
			j, a, b := heldFileMove(t, f)
			before := captureEntries(t, a, b)
			list := &listSwitch{}
			asked := 0

			report := Recover(f.home, f.project, f.switchPolicy(list), func(u Unresolved) Choice {
				asked++
				list.blocked = []string{b}
				return choice
			})

			if asked != 1 {
				t.Fatalf("asked %d times, want the group asked about once", asked)
			}
			assertEntriesUnchanged(t, before)
			assertPolicyHeld(t, report, j, blockedNote(a+" -> "+b, b))
			if got := onDiskRecord(t, j).Answers; len(got) != 0 {
				t.Fatalf("answers = %+v, want no answer recorded under the new block", got)
			}
		})
	}
}

func TestRecover_ABlockAddedWhileAPathQuestionIsOpenStopsTheAnswer(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL\n")
	j := f.open(t, target)
	f.childEdit(t, j, target, "ORIGINAL", "CHILD")
	replaceFile(t, target, "A HAND EDIT\n")
	orphan(t, j)
	list := &listSwitch{}

	report := Recover(f.home, f.project, f.switchPolicy(list), func(Unresolved) Choice {
		list.blocked = []string{target}
		return ChoiceRestore
	})

	assertContent(t, target, "A HAND EDIT\n")
	assertPolicyHeld(t, report, j, blockedNote(target, target))
	if got := onDiskRecord(t, j).Paths[0]; got.KeptByUser || got.Progress == rollbackRestored {
		t.Fatalf("record = %+v, want no answer adopted under the new block", got)
	}
}

func TestRecover_AnUnreadableListLeavesEveryJournalByteForByte(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy func(f *fixture) RecoveryPolicy
	}{
		{"no policy", func(*fixture) RecoveryPolicy { return RecoveryPolicy{} }},
		{"an unavailable reason", func(f *fixture) RecoveryPolicy {
			p := f.policy()
			p.Blocked, p.Unavailable = nil, "settings.yaml is not valid YAML"
			return p
		}},
		{"a failing refresh", func(f *fixture) RecoveryPolicy {
			return f.switchPolicy(&listSwitch{err: errors.New("the settings lock is busy")})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			edited := f.seed(t, "a.txt", "ORIGINAL\n")
			changed := f.seed(t, "b.txt", "ORIGINAL\n")
			source, destination := f.seed(t, "m.txt", "MOVED\n"), filepath.Join(f.project, "n.txt")
			j := f.openMoves(t, []string{edited, changed}, pairOf(source, destination))
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			f.childEdit(t, j, changed, "ORIGINAL", "CHILD")
			f.mustMove(t, j, source, destination)
			replaceFile(t, changed, "A HAND EDIT\n")
			replaceFile(t, destination, "A THIRD WRITER\n")
			orphan(t, j)
			live := f.open(t, f.seed(t, "c.txt", "ORIGINAL\n"))
			liveRecord := readBytes(t, recordPath(live))
			record := readBytes(t, recordPath(j))
			group := captureEntries(t, source, destination)

			report := Recover(f.home, f.project, tc.policy(f), neverAsked(t))

			assertEntriesUnchanged(t, group)

			if got := readBytes(t, recordPath(j)); string(got) != string(record) {
				t.Fatalf("record changed:\n%s\nwant\n%s", got, record)
			}
			if got := readBytes(t, recordPath(live)); string(got) != string(liveRecord) {
				t.Fatalf("live writer's record changed")
			}
			assertContent(t, edited, "CHILD\n")
			assertContent(t, changed, "A HAND EDIT\n")
			if len(report.Retained) != 1 || report.Retained[0].Path != j.Path() || !slices.Equal(report.Retained[0].Notes, []string{listUnavailable}) || report.Retained[0].PolicyNotes != 1 || len(report.Restored) != 0 {
				t.Fatalf("report = %+v, want only the orphan held for the unreadable list", report)
			}

			Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

			assertContent(t, edited, "ORIGINAL\n")
			assertContent(t, changed, "ORIGINAL\n")
			assertContent(t, source, "MOVED\n")
			assertGone(t, destination)
			assertGone(t, j.Path())
		})
	}
}

func TestRecover_LosingTheListMidPassKeepsFinishedWorkAndStopsTheRest(t *testing.T) {
	f := newFixture(t)
	first := f.seed(t, "a.txt", "ORIGINAL\n")
	second := f.seed(t, "b.txt", "ORIGINAL\n")
	j := f.open(t, first, second)
	f.childEdit(t, j, first, "ORIGINAL", "CHILD")
	f.childEdit(t, j, second, "ORIGINAL", "CHILD")
	orphan(t, j)
	var atLoss []byte
	list := &listSwitch{}
	list.onCall = func(int) {
		if atLoss == nil && onDiskRecord(t, j).Paths[0].Progress == rollbackRestored {
			atLoss = readBytes(t, recordPath(j))
			list.err = errors.New("the settings file changed during the read")
		}
	}

	report := Recover(f.home, f.project, f.switchPolicy(list), neverAsked(t))

	assertContent(t, first, "ORIGINAL\n")
	assertContent(t, second, "CHILD\n")
	if got := readBytes(t, recordPath(j)); string(got) != string(atLoss) {
		t.Fatalf("record changed after the list was lost:\n%s\nwant\n%s", got, atLoss)
	}
	if rec := onDiskRecord(t, j); rec.Paths[0].Progress != rollbackRestored || rec.Paths[1].Progress == rollbackRestored {
		t.Fatalf("paths = %+v, want only the first put back durably", rec.Paths)
	}
	if !slices.Equal(report.Restored, []string{first}) || len(report.Retained) != 1 || !slices.Equal(report.Retained[0].Notes, []string{listUnavailable}) {
		t.Fatalf("report = %+v, want the first path put back and the journal held", report)
	}

	if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 0 {
		t.Fatalf("retained = %+v, want the rest recovered on a healthy launch", report.Retained)
	}
	assertContent(t, second, "ORIGINAL\n")
	assertGone(t, j.Path())
}

func TestRecover_HoldsAPolicyHeldNestedJournalAndTheParentWorkOverIt(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "x/note.txt", "NOTE\n")
	x, y := filepath.Join(f.project, "x"), filepath.Join(f.project, "y")
	note := filepath.Join(y, "note.txt")
	unrelated := f.seed(t, "u.txt", "ORIGINAL\n")
	parent := f.open(t, note, unrelated)
	child, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), DeclaredMoves: []permissions.MovePair{pairOf(x, y)}, Parent: parent})
	if err != nil {
		t.Fatalf("OpenJournal nested: %v", err)
	}
	t.Cleanup(child.Close)
	f.mustMove(t, child, x, y)
	if err := child.MarkTransferReady(); err != nil {
		t.Fatalf("MarkTransferReady: %v", err)
	}
	f.childEdit(t, parent, unrelated, "ORIGINAL", "PARENT")
	orphan(t, parent)
	orphan(t, child)
	secret := filepath.Join(y, "secret")
	before := captureEntries(t, x, y)
	childMoves := onDiskRecord(t, child).Moves

	report := Recover(f.home, f.project, f.policy(secret), neverAsked(t))

	assertEntriesUnchanged(t, before)
	assertContent(t, unrelated, "ORIGINAL\n")
	held := blockedNote(x+" -> "+y, secret)
	assertPolicyHeld(t, report, child, held)
	assertPolicyHeld(t, report, parent, held)
	if got := onDiskRecord(t, child); got.Lifecycle != lifecycleTransferReady || !slices.Equal(got.Moves, childMoves) {
		t.Fatalf("child record = %+v, want it kept transfer-ready and unabsorbed", got)
	}
	if got := onDiskRecord(t, parent); len(got.Moves) != 0 || !slices.ContainsFunc(got.Children, func(c childLink) bool { return c.Dir == filepath.Base(child.Path()) && !c.Absorbed }) {
		t.Fatalf("parent record = %+v, want the child still linked and unabsorbed", got)
	}
}

func failingFrom(call int) *listSwitch {
	s := &listSwitch{}
	s.onCall = func(c int) {
		if c >= call {
			s.err = errors.New("the settings lock is busy")
		}
	}
	return s
}

func assertHeldForTheList(t *testing.T, report Report, j *Journal) {
	t.Helper()
	i := slices.IndexFunc(report.Retained, func(r RetainedJournal) bool { return r.Path == j.Path() })
	if i < 0 || !slices.Equal(report.Retained[i].Notes, []string{listUnavailable}) || report.Retained[i].PolicyNotes != 1 {
		t.Fatalf("retained = %+v, want %s held for the unreadable list", report.Retained, j.Path())
	}
}

func TestRecover_AFailedRefreshStopsEveryDurableFinalization(t *testing.T) {
	t.Run("committed cleanup", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		j.rec.Lifecycle = lifecycleCommitted
		if err := j.flush(); err != nil {
			t.Fatalf("flush the committed marker: %v", err)
		}
		orphan(t, j)
		record := readBytes(t, recordPath(j))

		report := Recover(f.home, f.project, f.switchPolicy(failingFrom(1)), neverAsked(t))

		if got := readBytes(t, recordPath(j)); string(got) != string(record) {
			t.Fatalf("record changed:\n%s\nwant\n%s", got, record)
		}
		assertHeldForTheList(t, report, j)

		Recover(f.home, f.project, f.policy(), nil)
		assertGone(t, j.Path())
	})

	t.Run("transfer-ready absorption", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent := f.open(t, target)
		child := f.openNested(t, parent, target)
		f.childEdit(t, child, target, "ORIGINAL", "CHILD")
		if err := child.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady: %v", err)
		}
		orphan(t, parent)
		orphan(t, child)
		parentRecord, childRecord := readBytes(t, recordPath(parent)), readBytes(t, recordPath(child))

		report := Recover(f.home, f.project, f.switchPolicy(failingFrom(2)), neverAsked(t))

		if got := readBytes(t, recordPath(child)); string(got) != string(childRecord) {
			t.Fatalf("child record changed:\n%s\nwant\n%s", got, childRecord)
		}
		if got := readBytes(t, recordPath(parent)); string(got) != string(parentRecord) {
			t.Fatalf("parent record changed:\n%s\nwant\n%s", got, parentRecord)
		}
		assertContent(t, target, "CHILD\n")
		assertHeldForTheList(t, report, child)
		assertHeldForTheList(t, report, parent)

		Recover(f.home, f.project, f.policy(), nil)
		assertContent(t, target, "ORIGINAL\n")
		assertGone(t, child.Path())
		assertGone(t, parent.Path())
	})

	t.Run("linked-parent retention", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		parent, child, grandchild := transferReadyChain(t, f, target)
		if err := os.WriteFile(recordPath(grandchild), []byte("{not json"), journalRecordMode); err != nil {
			t.Fatalf("corrupt the record: %v", err)
		}
		parentRecord, childRecord := readBytes(t, recordPath(parent)), readBytes(t, recordPath(child))

		Recover(f.home, f.project, f.switchPolicy(failingFrom(1)), neverAsked(t))

		if got := readBytes(t, recordPath(child)); string(got) != string(childRecord) {
			t.Fatalf("child record changed:\n%s\nwant\n%s", got, childRecord)
		}
		if got := readBytes(t, recordPath(parent)); string(got) != string(parentRecord) {
			t.Fatalf("parent record changed:\n%s\nwant\n%s", got, parentRecord)
		}
		assertContent(t, target, "GRANDCHILD\n")
	})

	t.Run("final cleanup after a completed action", func(t *testing.T) {
		f := newFixture(t)
		target := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, target)
		f.childEdit(t, j, target, "ORIGINAL", "CHILD")
		orphan(t, j)
		var atLoss []byte
		list := &listSwitch{}
		list.onCall = func(int) {
			if atLoss == nil && onDiskRecord(t, j).Paths[0].Progress == rollbackRestored {
				atLoss = readBytes(t, recordPath(j))
				list.err = errors.New("the settings lock is busy")
			}
		}

		report := Recover(f.home, f.project, f.switchPolicy(list), neverAsked(t))

		assertContent(t, target, "ORIGINAL\n")
		if atLoss == nil {
			t.Fatal("the path was never put back before the list was lost")
		}
		if got := readBytes(t, recordPath(j)); string(got) != string(atLoss) {
			t.Fatalf("record changed after the list was lost:\n%s\nwant\n%s", got, atLoss)
		}
		if !slices.Equal(report.Restored, []string{target}) {
			t.Fatalf("restored = %v, want the finished restore reported", report.Restored)
		}
		assertHeldForTheList(t, report, j)

		if report := Recover(f.home, f.project, f.policy(), nil); len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want the journal removed on a healthy launch", report.Retained)
		}
		assertGone(t, j.Path())
	})
}

func TestRecover_ARecordedKeepWaitsOutABlockBeforeItSettles(t *testing.T) {
	answeredRecord := func(t *testing.T, f *fixture) (j *Journal, a, b string, answered []byte) {
		t.Helper()
		j, a, b = heldFileMove(t, f)
		beforeJournalStep = func(step string) error {
			if step == "group_kept" && answered == nil {
				answered = readBytes(t, recordPath(j))
				return errors.New("simulated crash at group_kept")
			}
			return nil
		}
		Recover(f.home, f.project, f.policy(), answer(ChoiceKeep))
		beforeJournalStep = func(string) error { return nil }
		if err := os.WriteFile(recordPath(j), answered, journalRecordMode); err != nil {
			t.Fatalf("leave the record as the crash did: %v", err)
		}
		rec := onDiskRecord(t, j)
		if len(rec.Answers) != 1 || rec.Answers[0].Choice != ChoiceKeep || slices.ContainsFunc(rec.Paths, func(pr pathRecord) bool { return pr.KeptByUser }) {
			t.Fatalf("record = %+v, want one durable Keep answer not yet settled", rec)
		}
		return j, a, b, answered
	}
	unsettled := func(t *testing.T, j *Journal, answered []byte) {
		t.Helper()
		rec, want := onDiskRecord(t, j), recordFrom(t, answered)
		if !reflect.DeepEqual(rec.Answers, want.Answers) || !reflect.DeepEqual(rec.Paths, want.Paths) || !slices.Equal(rec.Moves, want.Moves) {
			t.Fatalf("record = %+v, want the Keep answer and its records left unsettled (%+v)", rec, want)
		}
	}

	t.Run("a block", func(t *testing.T) {
		f := newFixture(t)
		t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })
		j, a, b, answered := answeredRecord(t, f)
		before := captureEntries(t, a, b)

		list := &listSwitch{}
		list.onCall = func(call int) {
			if call >= 2 {
				list.blocked = []string{b}
			}
		}

		report := Recover(f.home, f.project, f.switchPolicy(list), neverAsked(t))

		assertEntriesUnchanged(t, before)
		assertPolicyHeld(t, report, j, blockedNote(a+" -> "+b, b))
		unsettled(t, j, answered)

		if report := Recover(f.home, f.project, f.policy(), neverAsked(t)); len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want the recorded Keep settled once nothing is blocked", report.Retained)
		}
		assertContent(t, b, "A THIRD WRITER\n")
		assertGone(t, a)
		assertGone(t, j.Path())
	})

	t.Run("a failed refresh", func(t *testing.T) {
		f := newFixture(t)
		t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })
		j, a, b, answered := answeredRecord(t, f)
		before := captureEntries(t, a, b)

		report := Recover(f.home, f.project, f.switchPolicy(failingFrom(2)), neverAsked(t))

		assertEntriesUnchanged(t, before)
		if got := readBytes(t, recordPath(j)); string(got) != string(answered) {
			t.Fatalf("record changed:\n%s\nwant\n%s", got, answered)
		}
		assertHeldForTheList(t, report, j)
	})
}

func TestRecover_ABlockAddedAfterClassificationHoldsTheWholeGroupAtEachOperation(t *testing.T) {
	type built struct {
		j       *Journal
		watched []string
		trigger func(call int) bool
	}
	for _, op := range []struct {
		name  string
		build func(t *testing.T, f *fixture, a, b, unrelated string) built
	}{
		{"early path restoration", func(t *testing.T, f *fixture, a, b, unrelated string) built {
			created := filepath.Join(b, "new.txt")
			j := f.openMoves(t, []string{created, unrelated}, pairOf(a, b))
			f.mustMove(t, j, a, b)
			mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
			f.childEdit(t, j, unrelated, "ORIGINAL", "CHILD")
			return built{j: j, watched: []string{created}, trigger: func(call int) bool { return call >= 2 }}
		}},
		{"pending reconciliation", func(t *testing.T, f *fixture, a, b, unrelated string) built {
			pending := filepath.Join(b, "pending.txt")
			j := f.openMoves(t, []string{pending, unrelated}, pairOf(a, b))
			f.mustMove(t, j, a, b)
			f.childEdit(t, j, unrelated, "ORIGINAL", "CHILD")
			crashAt(t, "reconciled")
			f.childCreate(t, j, pending, "PENDING\n")
			assertPendingRecords(t, onDiskRecord(t, j), true, pending)
			return built{j: j, watched: []string{pending}, trigger: func(call int) bool { return call >= 2 }}
		}},
		{"created-directory cleanup", func(t *testing.T, f *fixture, a, b, unrelated string) built {
			sub := filepath.Join(b, "sub")
			created := filepath.Join(sub, "new.txt")
			j := f.openMoves(t, []string{created, unrelated}, pairOf(a, b))
			f.mustMove(t, j, a, b)
			mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
			f.childEdit(t, j, unrelated, "ORIGINAL", "CHILD")
			return built{j: j, watched: []string{sub}, trigger: func(int) bool {
				_, err := os.Lstat(created)
				return errors.Is(err, os.ErrNotExist)
			}}
		}},
	} {
		for _, block := range []struct {
			name  string
			entry func(a, b string) string
		}{
			{"a destination sibling", func(_, b string) string { return filepath.Join(b, "secret") }},
			{"a source-only descendant", func(a, _ string) string { return filepath.Join(a, "ghost") }},
		} {
			t.Run(op.name+"/"+block.name, func(t *testing.T) {
				f := newFixture(t)
				f.seed(t, "a/keep.txt", "KEEP\n")
				a, b := filepath.Join(f.project, "a"), filepath.Join(f.project, "b")
				unrelated := f.seed(t, "u.txt", "ORIGINAL\n")
				fx := op.build(t, f, a, b, unrelated)
				orphan(t, fx.j)
				entry := block.entry(a, b)
				var before []entrySnapshot
				var record journalRecord
				list := &listSwitch{}
				list.onCall = func(call int) {
					if before == nil && fx.trigger(call) {
						before = captureEntries(t, append([]string{a, b}, fx.watched...)...)
						record = onDiskRecord(t, fx.j)
						list.blocked = []string{entry}
					}
				}

				report := Recover(f.home, f.project, f.switchPolicy(list), neverAsked(t))

				if before == nil {
					t.Fatal("the block was never added")
				}
				assertEntriesUnchanged(t, before)
				if got := onDiskRecord(t, fx.j); !reflect.DeepEqual(got.Paths[:len(got.Paths)-1], record.Paths[:len(record.Paths)-1]) || !slices.Equal(got.Moves, record.Moves) {
					t.Fatalf("record = %+v, want the group's path, pending and directory records as they were (%+v)", got, record)
				}
				assertContent(t, unrelated, "ORIGINAL\n")
				assertPolicyHeld(t, report, fx.j, blockedNote(a+" -> "+b, entry))
			})
		}
	}
}

func TestRecover_ABlockAddedWhileAPathQuestionInsideAGroupIsOpenHoldsTheGroup(t *testing.T) {
	f := newFixture(t)
	f.seed(t, "a/keep.txt", "KEEP\n")
	a, b := filepath.Join(f.project, "a"), filepath.Join(f.project, "b")
	created := filepath.Join(b, "new.txt")
	j := f.openMoves(t, []string{created}, pairOf(a, b))
	f.mustMove(t, j, a, b)
	mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
	replaceFile(t, created, "A THIRD WRITER\n")
	orphan(t, j)
	before := captureEntries(t, a, b, created)
	lastKnown := pathIn(t, onDiskRecord(t, j), created).LastKnown
	entry := filepath.Join(b, "secret")
	list := &listSwitch{}
	asked := false

	report := Recover(f.home, f.project, f.switchPolicy(list), func(u Unresolved) Choice {
		if u.Path != created {
			return ChoiceDefer
		}
		asked = true
		list.blocked = []string{entry}
		return ChoiceRestore
	})

	if !asked {
		t.Fatal("the path inside the moved directory was never asked about")
	}
	assertEntriesUnchanged(t, before)
	if got := pathIn(t, onDiskRecord(t, j), created).LastKnown; !reflect.DeepEqual(got, lastKnown) {
		t.Fatalf("last known = %+v, want no answer adopted under the new block (%+v)", got, lastKnown)
	}
	if i := slices.IndexFunc(report.Retained, func(r RetainedJournal) bool { return r.Path == j.Path() }); i < 0 || !slices.Contains(report.Retained[i].Notes, blockedNote(a+" -> "+b, entry)) {
		t.Fatalf("retained = %+v, want the group held for the new block", report.Retained)
	}
}

func TestRecover_AsksOneQuestionPerHeldGroupInJournalOrderBeforeAnyPath(t *testing.T) {
	f := newFixture(t)
	a := f.seedMode(t, "a.txt", "A ORIGINAL\n", 0o640)
	c := f.seedMode(t, "c.txt", "C ORIGINAL\n", 0o600)
	b := filepath.Join(f.project, "b.txt")
	x := f.seed(t, "x.txt", "X ORIGINAL\n")
	y := filepath.Join(f.project, "y.txt")
	edited := f.seed(t, "e.txt", "ORIGINAL\n")
	deleted := f.seed(t, "d.txt", "ORIGINAL\n")
	j := f.openConfig(t, JournalConfig{Declared: []string{edited}, DeclaredDelete: []string{deleted}, DeclaredMoves: []permissions.MovePair{pairOf(a, b), pairOf(c, a), pairOf(x, y)}})
	f.mustMove(t, j, a, b)
	f.mustMove(t, j, c, a)
	f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
	f.mustDelete(t, j, deleted)
	crashAt(t, "move_completed")
	f.mustMove(t, j, x, y)
	replaceFile(t, b, "A THIRD WRITER\n")
	replaceFile(t, x, "X THIRD WRITER\n")
	replaceFile(t, edited, "A HAND EDIT\n")
	replaceFile(t, deleted, "A HAND EDIT\n")
	orphan(t, j)
	moves := onDiskRecord(t, j).Moves
	if len(moves) != 3 || slices.ContainsFunc(moves, func(m moveRecord) bool { return m.ID == (moveID{}) }) || moves[2].State != movePending {
		t.Fatalf("journalled moves = %+v, want three with identities and the last left pending", moves)
	}

	var asked []Unresolved
	Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
		asked = append(asked, u)
		return ChoiceDefer
	})

	want := []Unresolved{
		{Moves: []UnresolvedMove{{ID: moves[0].ID, Source: a, Destination: b}, {ID: moves[1].ID, Source: c, Destination: a}}, Choices: []Choice{ChoiceKeep, ChoiceRestore, ChoiceDefer}},
		{Moves: []UnresolvedMove{{ID: moves[2].ID, Source: x, Destination: y, Pending: true}}, Choices: []Choice{ChoiceKeep, ChoiceDefer}, RestoreRefusal: unresolvedMoveCause},
		{Path: deleted},
		{Path: edited},
	}
	if !reflect.DeepEqual(asked, want) {
		t.Fatalf("questions = %+v, want one per held group in journal order and then each changed path (%+v)", asked, want)
	}
}

func TestRecover_AsksAboutAPolicyHeldGroupOnlyOnceThePolicyPermits(t *testing.T) {
	f := newFixture(t)
	j, a, b := heldFileMove(t, f)
	before := captureEntries(t, a, b)

	report := Recover(f.home, f.project, f.policy(b), neverAsked(t))

	assertEntriesUnchanged(t, before)
	assertPolicyHeld(t, report, j, blockedNote(a+" -> "+b, b))

	var asked []Unresolved
	Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
		asked = append(asked, u)
		return ChoiceDefer
	})

	if len(asked) != 1 || len(asked[0].Moves) != 1 || asked[0].Moves[0].Source != a || asked[0].Moves[0].Destination != b {
		t.Fatalf("questions = %+v, want the group asked about once the block is gone", asked)
	}
	assertEntriesUnchanged(t, before)
	assertRecordPresent(t, j)
}

func TestRecover_RetriesAnInterruptedUndoWithoutAQuestionAndReportsItRetryOnly(t *testing.T) {
	f := newFixture(t)
	a := f.seed(t, "a.txt", "ORIGINAL\n")
	b := filepath.Join(f.project, "b.txt")
	j := f.openMoves(t, nil, pairOf(a, b))
	f.mustMove(t, j, a, b)
	orphan(t, j)
	crashAt(t, "move_undone")
	Recover(f.home, f.project, f.policy(), nil)
	if got := onDiskRecord(t, j).Moves; len(got) != 1 || got[0].State != moveUndoing {
		t.Fatalf("journalled moves = %+v, want the undo recorded as begun", got)
	}
	replaceFile(t, a, "A THIRD WRITER\n")
	before := captureEntries(t, a, b)

	for launch := 1; launch <= 2; launch++ {
		report := Recover(f.home, f.project, f.policy(), neverAsked(t))

		assertEntriesUnchanged(t, before)
		if len(report.Retained) != 1 || len(report.Retained[0].Moves) != 1 || !report.Retained[0].Moves[0].Resumes {
			t.Fatalf("launch %d retained = %+v, want the interrupted undo reported as retried, not asked about", launch, report.Retained)
		}
	}
}

func TestRecover_KeepLeavesEveryNamedEndpointAsItIs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, f *fixture) (j *Journal, endpoints []string, atQuestion func(t *testing.T))
	}{
		{"a write the child made at an endpoint", func(t *testing.T, f *fixture) (*Journal, []string, func(t *testing.T)) {
			a := f.seed(t, "a.txt", "ORIGINAL\n")
			b := filepath.Join(f.project, "b.txt")
			j := f.openMoves(t, []string{a}, pairOf(a, b))
			f.mustMove(t, j, a, b)
			mustSucceed(t, f.childCreate(t, j, a, "CHILD REMADE THIS\n"))
			replaceFile(t, b, "A THIRD WRITER\n")
			return j, []string{a, b}, nil
		}},
		{"a delete the child made at an endpoint", func(t *testing.T, f *fixture) (*Journal, []string, func(t *testing.T)) {
			a := f.seed(t, "a.txt", "ORIGINAL\n")
			b := filepath.Join(f.project, "b.txt")
			j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{b}, DeclaredMoves: []permissions.MovePair{pairOf(a, b)}})
			f.mustMove(t, j, a, b)
			f.mustDelete(t, j, b)
			replaceFile(t, a, "A THIRD WRITER\n")
			return j, []string{a, b}, nil
		}},
		{"a directory the child made at an endpoint beside a write beneath the moved directory", func(t *testing.T, f *fixture) (*Journal, []string, func(t *testing.T)) {
			f.seed(t, "tree/leaf.txt", "LEAF\n")
			tree, moved := filepath.Join(f.project, "tree"), filepath.Join(f.project, "moved")
			created := filepath.Join(moved, "new.txt")
			j := f.openConfig(t, JournalConfig{Declared: []string{created}, DeclaredDirs: []string{tree}, DeclaredMoves: []permissions.MovePair{pairOf(tree, moved)}})
			f.mustMove(t, j, tree, moved)
			mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
			mustSucceed(t, f.childMkdir(t, j, tree))
			if err := os.WriteFile(filepath.Join(tree, "outside.txt"), []byte("OUTSIDE\n"), 0o644); err != nil {
				t.Fatalf("write an outside entry: %v", err)
			}
			return j, []string{tree, moved}, func(t *testing.T) {
				assertGone(t, created)
				assertContent(t, filepath.Join(moved, "leaf.txt"), "LEAF\n")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			j, endpoints, atQuestion := tc.build(t, f)
			orphan(t, j)
			identities := make([]os.FileInfo, 0, len(endpoints))
			for _, path := range endpoints {
				identities = append(identities, lstatEntry(t, path))
			}
			var asked []entrySnapshot

			report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
				if len(u.Moves) == 0 {
					t.Fatalf("asked about %s, want only the group asked about", u.Path)
				}
				if atQuestion != nil {
					atQuestion(t)
				}
				asked = captureEntries(t, endpoints...)
				return ChoiceKeep
			})

			if asked == nil {
				t.Fatal("the group was never asked about")
			}
			assertEntriesUnchanged(t, asked)
			for i, path := range endpoints {
				if identities[i] != nil {
					assertSameEntry(t, path, identities[i])
				}
			}
			if !slices.Equal(report.Kept, endpoints) || len(report.Retained) != 0 {
				t.Fatalf("report = %+v, want every endpoint reported kept and nothing retained", report)
			}
			assertGone(t, j.Path())
			if report := Recover(f.home, f.project, f.policy(), neverAsked(t)); !report.Empty() {
				t.Fatalf("report = %+v, want nothing left to recover", report)
			}
		})
	}
}

func TestRecover_AKeptGroupIsNeitherAskedNorReportedAgainWhileItsJournalSurvives(t *testing.T) {
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

	report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
		if len(u.Moves) > 0 {
			return ChoiceKeep
		}
		return ChoiceDefer
	})

	if !slices.Equal(report.Kept, []string{a, b}) {
		t.Fatalf("kept = %v, want the group's endpoints", report.Kept)
	}
	assertRecordPresent(t, j)
	before := captureEntries(t, a, b, edited)
	for launch := 1; launch <= 2; launch++ {
		var asked []string
		report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
			if len(u.Moves) > 0 {
				t.Errorf("launch %d asked about the kept group %+v", launch, u.Moves)
			}
			asked = append(asked, u.Path)
			return ChoiceDefer
		})

		if !slices.Equal(asked, []string{edited}) {
			t.Fatalf("launch %d asked about %v, want only %s", launch, asked, edited)
		}
		if len(report.Retained) != 1 || len(report.Retained[0].Moves) != 0 || slices.ContainsFunc(report.Retained[0].Notes, func(n string) bool {
			return strings.HasPrefix(n, a) || strings.HasPrefix(n, b)
		}) {
			t.Fatalf("launch %d retained = %+v, want the kept group's moves absent from the report", launch, report.Retained)
		}
		assertEntriesUnchanged(t, before)
	}
}

func TestRecover_RestorePutsEveryEndpointBackToItsPreRunState(t *testing.T) {
	t.Run("files, one replaced by an outside file", func(t *testing.T) {
		f := newFixture(t)
		a := f.seedMode(t, "a.txt", "A ORIGINAL\n", 0o640)
		c := f.seedMode(t, "c.txt", "C ORIGINAL\n", 0o600)
		b := filepath.Join(f.project, "b.txt")
		j := f.openMoves(t, nil, pairOf(a, b), pairOf(c, a))
		f.mustMove(t, j, a, b)
		f.mustMove(t, j, c, a)
		replaceFile(t, b, "A THIRD WRITER\n")
		orphan(t, j)

		report := Recover(f.home, f.project, f.policy(), answer(ChoiceRestore))

		assertFile(t, a, "A ORIGINAL\n", 0o640)
		assertFile(t, c, "C ORIGINAL\n", 0o600)
		assertGone(t, b)
		assertGone(t, j.Path())
		for _, path := range []string{a, b, c} {
			if !slices.Contains(report.Restored, path) {
				t.Fatalf("restored = %v, want %s named", report.Restored, path)
			}
		}
		if len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want nothing left", report.Retained)
		}
	})

	t.Run("a directory renamed back whole with entries in it", func(t *testing.T) {
		f := newFixture(t)
		f.seedMode(t, "tree/leaf.txt", "LEAF\n", 0o600)
		tree := f.dir(t, "tree", 0o750)
		identity := lstatEntry(t, tree)
		a := f.seedMode(t, "a.txt", "A ORIGINAL\n", 0o640)
		moved := filepath.Join(f.project, "moved")
		inMoved := filepath.Join(moved, "a.txt")
		j := f.openMoves(t, nil, pairOf(tree, moved), pairOf(a, inMoved))
		f.mustMove(t, j, tree, moved)
		f.mustMove(t, j, a, inMoved)
		replaceFile(t, inMoved, "A THIRD WRITER\n")
		if err := os.WriteFile(filepath.Join(moved, "outside.txt"), []byte("OUTSIDE\n"), 0o644); err != nil {
			t.Fatalf("write an outside entry: %v", err)
		}
		orphan(t, j)
		var asked []Unresolved

		report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
			asked = append(asked, u)
			return ChoiceRestore
		})

		if len(asked) != 1 || !slices.Contains(asked[0].Choices, ChoiceRestore) {
			t.Fatalf("questions = %+v, want one group question offering Restore", asked)
		}
		assertDir(t, tree, 0o750)
		assertSameEntry(t, tree, identity)
		assertFile(t, filepath.Join(tree, "leaf.txt"), "LEAF\n", 0o600)
		assertContent(t, filepath.Join(tree, "outside.txt"), "OUTSIDE\n")
		assertFile(t, a, "A ORIGINAL\n", 0o640)
		assertGone(t, moved)
		assertGone(t, j.Path())
		if len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want nothing left", report.Retained)
		}
	})
}

func TestRecover_WithholdsRestoreAndSaysWhyWhenItCannotBeDoneSafely(t *testing.T) {
	movedTree := func(t *testing.T, f *fixture, cfg JournalConfig) (j *Journal, tree, moved string) {
		t.Helper()
		f.seed(t, "tree/leaf.txt", "LEAF\n")
		tree, moved = filepath.Join(f.project, "tree"), filepath.Join(f.project, "moved")
		cfg.DeclaredMoves = append(cfg.DeclaredMoves, pairOf(tree, moved))
		j = f.openConfig(t, cfg)
		f.mustMove(t, j, tree, moved)
		return j, tree, moved
	}
	for _, tc := range []struct {
		name    string
		build   func(t *testing.T, f *fixture) (j *Journal, watch []string)
		refusal string
	}{
		{"an unresolved pending move", func(t *testing.T, f *fixture) (*Journal, []string) {
			a := f.seed(t, "a.txt", "ORIGINAL\n")
			b := filepath.Join(f.project, "b.txt")
			j := f.openMoves(t, nil, pairOf(a, b))
			crashAt(t, "move_completed")
			f.mustMove(t, j, a, b)
			replaceFile(t, a, "A THIRD WRITER\n")
			return j, []string{a, b}
		}, unresolvedMoveCause},
		{"a moved directory that was deleted", func(t *testing.T, f *fixture) (*Journal, []string) {
			j, tree, moved := movedTree(t, f, JournalConfig{})
			clearEntry(t, moved)
			return j, []string{tree, moved}
		}, "was deleted or replaced, so its contents cannot be restored"},
		{"a moved directory that was replaced", func(t *testing.T, f *fixture) (*Journal, []string) {
			j, tree, moved := movedTree(t, f, JournalConfig{})
			replaceWithSameContent(t, moved)
			return j, []string{tree, moved}
		}, "was deleted or replaced, so its contents cannot be restored"},
		{"a directory the child made at the source holding an outside entry", func(t *testing.T, f *fixture) (*Journal, []string) {
			j, tree, moved := movedTree(t, f, JournalConfig{DeclaredDirs: []string{filepath.Join(f.project, "tree")}})
			mustSucceed(t, f.childMkdir(t, j, tree))
			if err := os.WriteFile(filepath.Join(tree, "outside.txt"), []byte("OUTSIDE\n"), 0o644); err != nil {
				t.Fatalf("write an outside entry: %v", err)
			}
			return j, []string{tree, moved}
		}, "now holds entries"},
		{"a directory the child made at the source holding the child's own entry", func(t *testing.T, f *fixture) (*Journal, []string) {
			own := filepath.Join(f.project, "tree", "new.txt")
			j, tree, moved := movedTree(t, f, JournalConfig{Declared: []string{own}, DeclaredDirs: []string{filepath.Join(f.project, "tree")}})
			mustSucceed(t, f.childMkdir(t, j, tree))
			mustSucceed(t, f.childCreate(t, j, own, "CHILD MADE THIS\n"))
			replaceFile(t, own, "A HAND EDIT\n")
			return j, []string{tree, moved}
		}, "now holds entries"},
		{"a moved directory with entries that would have to be removed to put it back", func(t *testing.T, f *fixture) (*Journal, []string) {
			j, tree, moved := movedTree(t, f, JournalConfig{})
			if err := os.Chmod(moved, 0o700); err != nil {
				t.Fatalf("chmod the moved directory: %v", err)
			}
			return j, []string{tree, moved}
		}, "holds entries, so it cannot be removed to put the path back"},
		{"an unresolved rollback beneath the moved directory", func(t *testing.T, f *fixture) (*Journal, []string) {
			created := filepath.Join(f.project, "moved", "new.txt")
			j, tree, moved := movedTree(t, f, JournalConfig{Declared: []string{created}})
			mustSucceed(t, f.childCreate(t, j, created, "CHILD MADE THIS\n"))
			replaceFile(t, created, "A HAND EDIT\n")
			return j, []string{tree, moved}
		}, unrestoredDescendantCause},
		{"a destination also declared for deletion", func(t *testing.T, f *fixture) (*Journal, []string) {
			a := f.seed(t, "a.txt", "ORIGINAL\n")
			b := filepath.Join(f.project, "b.txt")
			j := f.openConfig(t, JournalConfig{DeclaredDelete: []string{b}, DeclaredMoves: []permissions.MovePair{pairOf(a, b)}})
			f.mustMove(t, j, a, b)
			replaceFile(t, b, "A THIRD WRITER\n")
			return j, []string{a, b}
		}, "cannot be proven that a moved directory is still intact"},
		{"an endpoint whose parent directory was replaced", func(t *testing.T, f *fixture) (*Journal, []string) {
			a := f.seed(t, "a.txt", "ORIGINAL\n")
			sub := f.dir(t, "sub", 0o755)
			b := filepath.Join(sub, "b.txt")
			j := f.openMoves(t, nil, pairOf(a, b))
			f.mustMove(t, j, a, b)
			replaceWithSameContent(t, sub)
			return j, []string{a, sub}
		}, "could not be safely reopened"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			j, watch := tc.build(t, f)
			orphan(t, j)
			before := captureEntries(t, watch...)
			var groups []Unresolved

			report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
				if len(u.Moves) == 0 {
					return ChoiceDefer
				}
				groups = append(groups, u)
				return ChoiceRestore
			})

			if len(groups) != 1 || !slices.Equal(groups[0].Choices, []Choice{ChoiceKeep, ChoiceDefer}) || !strings.Contains(groups[0].RestoreRefusal, tc.refusal) {
				t.Fatalf("group questions = %+v, want one without Restore saying %q", groups, tc.refusal)
			}
			assertEntriesUnchanged(t, before)
			if got := onDiskRecord(t, j).Answers; len(got) != 0 {
				t.Fatalf("answers = %+v, want none recorded", got)
			}
			if len(report.Retained) != 1 || report.Retained[0].Path != j.Path() {
				t.Fatalf("retained = %+v, want the journal kept", report.Retained)
			}
		})
	}
}

func TestRecover_AnEndpointChangedWhileTheQuestionIsOpenStopsARestore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, a, b string)
	}{
		{"the destination replaced again", func(t *testing.T, _, b string) { replaceFile(t, b, "A LATER WRITER\n") }},
		{"an outside file at the source", func(t *testing.T, a, _ string) { replaceFile(t, a, "A LATER WRITER\n") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			j, a, b := heldFileMove(t, f)
			record := onDiskRecord(t, j)
			var during []entrySnapshot

			report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
				if !slices.Contains(u.Choices, ChoiceRestore) {
					t.Fatalf("question = %+v, want Restore offered before the change", u)
				}
				tc.change(t, a, b)
				during = captureEntries(t, a, b)
				return ChoiceRestore
			})

			assertEntriesUnchanged(t, during)
			if rec := onDiskRecord(t, j); len(rec.Answers) != 0 || !slices.Equal(rec.Moves, record.Moves) || rec.MoveSeq != record.MoveSeq {
				t.Fatalf("record = %+v, want no answer published", rec)
			}
			note := a + " -> " + b + ": these moves were not put back and are asked about again at the next launch: an endpoint changed while the question was open"
			if len(report.Retained) != 1 || !slices.Contains(report.Retained[0].Notes, note) {
				t.Fatalf("retained = %+v, want %q", report.Retained, note)
			}
		})
	}
}

func TestRecover_DeferRecordsNothingAndAsksTheSameQuestionAtTheNextLaunch(t *testing.T) {
	f := newFixture(t)
	a := f.seed(t, "a.txt", "ORIGINAL\n")
	b := filepath.Join(f.project, "b.txt")
	edited := f.seed(t, "e.txt", "ORIGINAL\n")
	j := f.openMoves(t, []string{edited}, pairOf(a, b))
	f.mustMove(t, j, a, b)
	f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
	replaceFile(t, b, "A THIRD WRITER\n")
	orphan(t, j)
	before := captureEntries(t, a, b)
	record := onDiskRecord(t, j)
	var first []Unresolved

	report := Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
		first = append(first, u)
		return ChoiceDefer
	})

	if len(first) != 1 || len(first[0].Moves) != 1 {
		t.Fatalf("questions = %+v, want the group asked about once", first)
	}
	assertEntriesUnchanged(t, before)
	assertContent(t, edited, "ORIGINAL\n")
	if !slices.Contains(report.Restored, edited) {
		t.Fatalf("restored = %v, want the unrelated write put back", report.Restored)
	}
	rec := onDiskRecord(t, j)
	if len(rec.Answers) != 0 || !slices.Equal(rec.Moves, record.Moves) || slices.ContainsFunc(rec.Paths, func(pr pathRecord) bool { return pr.KeptByUser }) {
		t.Fatalf("record = %+v, want no answer recorded", rec)
	}
	var second []Unresolved

	Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
		second = append(second, u)
		return ChoiceDefer
	})

	if !reflect.DeepEqual(second, first) {
		t.Fatalf("next launch questions = %+v, want the same %+v", second, first)
	}
	assertEntriesUnchanged(t, before)
	assertRecordPresent(t, j)
}

func TestRecover_FinishesARecordedAnswerAfterALaunchInterruptedAtEachDurablePoint(t *testing.T) {
	for _, tc := range []struct {
		choice Choice
		crash  string
		a, b   string
	}{
		{ChoiceKeep, "group_kept", "", "A THIRD WRITER\n"},
		{ChoiceRestore, "move_undoing", "ORIGINAL\n", ""},
		{ChoiceRestore, "move_undone", "ORIGINAL\n", ""},
		{ChoiceRestore, "restoring", "ORIGINAL\n", ""},
		{ChoiceRestore, "restored", "ORIGINAL\n", ""},
	} {
		for _, next := range []struct {
			name string
			ask  func(t *testing.T) func(Unresolved) Choice
		}{
			{"interactive", neverAsked},
			{"headless", func(*testing.T) func(Unresolved) Choice { return nil }},
		} {
			t.Run(string(tc.choice)+"/"+tc.crash+"/"+next.name, func(t *testing.T) {
				f := newFixture(t)
				j, a, b := heldFileMove(t, f)
				crashAt(t, tc.crash)
				Recover(f.home, f.project, f.policy(), answer(tc.choice))
				rec := onDiskRecord(t, j)
				if len(rec.Answers) != 1 || rec.Answers[0].Choice != tc.choice || len(rec.Moves) != 1 {
					t.Fatalf("record = %+v, want the answer and its move recorded before the interruption", rec)
				}

				report := Recover(f.home, f.project, f.policy(), next.ask(t))

				if len(report.Retained) != 0 {
					t.Fatalf("retained = %+v, want the recorded answer finished", report.Retained)
				}
				assertContent(t, a, tc.a)
				assertContent(t, b, tc.b)
				assertGone(t, j.Path())
			})
		}
	}
}

func TestRecover_ReplaysARecordedAnswerBeforeReconcilingRollingBackOrAbsorbing(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(data)
	}

	t.Run("pending reconciliation and ordinary rollback", func(t *testing.T) {
		f := newFixture(t)
		a := f.seed(t, "a.txt", "ORIGINAL\n")
		b := filepath.Join(f.project, "b.txt")
		x := f.seed(t, "x.txt", "X ORIGINAL\n")
		y := filepath.Join(f.project, "y.txt")
		edited := f.seed(t, "e.txt", "ORIGINAL\n")
		pending := f.seed(t, "p.txt", "ORIGINAL\n")
		j := f.openMoves(t, []string{edited, pending}, pairOf(a, b), pairOf(x, y))
		f.mustMove(t, j, a, b)
		f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
		crashAt(t, "move_completed")
		f.mustMove(t, j, x, y)
		resumeFromDisk(t, j)
		crashAt(t, "reconciled")
		f.childEdit(t, j, pending, "ORIGINAL", "CHILD")
		replaceFile(t, b, "A THIRD WRITER\n")
		orphan(t, j)
		crashAt(t, "move_undoing")
		Recover(f.home, f.project, f.policy(edited, pending, x), answer(ChoiceRestore))
		rec := onDiskRecord(t, j)
		assertPendingRecords(t, rec, true, pending)
		if len(rec.Answers) != 1 || rec.Moves[1].State != movePending {
			t.Fatalf("record = %+v, want the recorded Restore beside a pending move and a pending write", rec)
		}
		replayedBy := make(map[string]bool)
		beforeJournalStep = func(step string) error {
			done := read(a) == "ORIGINAL\n" && read(b) == ""
			for label, reached := range map[string]bool{
				"move reconciliation":  step == "move_completed",
				"write reconciliation": step == "reconciled",
				"rollback":             read(edited) == "ORIGINAL\n",
			} {
				if _, seen := replayedBy[label]; reached && !seen {
					replayedBy[label] = done
				}
			}
			return nil
		}
		t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

		report := Recover(f.home, f.project, f.policy(), neverAsked(t))

		for _, label := range []string{"move reconciliation", "write reconciliation", "rollback"} {
			if done, seen := replayedBy[label]; !seen || !done {
				t.Fatalf("%s seen = %v, replay finished before it = %v; want the recorded Restore finished first", label, seen, done)
			}
		}
		if len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want everything recovered", report.Retained)
		}
		assertContent(t, a, "ORIGINAL\n")
		assertContent(t, x, "X ORIGINAL\n")
		assertContent(t, edited, "ORIGINAL\n")
		assertContent(t, pending, "ORIGINAL\n")
		assertGone(t, j.Path())
	})

	t.Run("transfer-ready absorption", func(t *testing.T) {
		f := newFixture(t)
		a := f.seed(t, "a.txt", "ORIGINAL\n")
		b := filepath.Join(f.project, "b.txt")
		parent := f.open(t, a, b)
		child, err := OpenJournal(JournalConfig{Home: f.home, ProjectRoot: f.project, Invocation: f.invocation(), DeclaredMoves: []permissions.MovePair{pairOf(a, b)}, Parent: parent})
		if err != nil {
			t.Fatalf("OpenJournal nested: %v", err)
		}
		t.Cleanup(child.Close)
		f.mustMove(t, child, a, b)
		replaceFile(t, b, "A THIRD WRITER\n")
		if err := child.MarkTransferReady(); err != nil {
			t.Fatalf("MarkTransferReady: %v", err)
		}
		rewriteRecord(t, child, func(rec *journalRecord) {
			rec.Answers = []groupAnswer{{Members: []moveID{rec.Moves[0].ID}, Endpoints: []string{a, b}, Choice: ChoiceKeep}}
		})
		orphan(t, parent)
		orphan(t, child)
		var steps []string
		beforeJournalStep = func(step string) error {
			steps = append(steps, step)
			return nil
		}
		t.Cleanup(func() { beforeJournalStep = func(string) error { return nil } })

		report := Recover(f.home, f.project, f.policy(), neverAsked(t))

		kept, absorbed := slices.Index(steps, "group_kept"), slices.Index(steps, "child_absorbed")
		if kept < 0 || absorbed < kept {
			t.Fatalf("steps = %v, want the recorded Keep settled before the parent absorbs the journal", steps)
		}
		if len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want both journals recovered", report.Retained)
		}
		assertGone(t, a)
		assertContent(t, b, "A THIRD WRITER\n")
		assertGone(t, child.Path())
		assertGone(t, parent.Path())
	})
}

func TestRecover_AFailedAnswerPublicationSettlesNothingAndChangesNoEndpoint(t *testing.T) {
	for _, choice := range []Choice{ChoiceKeep, ChoiceRestore} {
		t.Run(string(choice), func(t *testing.T) {
			f := newFixture(t)
			j, a, b := heldFileMove(t, f)
			before := captureEntries(t, a, b)
			record := onDiskRecord(t, j)
			crashAt(t, "group_answered")

			report := Recover(f.home, f.project, f.policy(), answer(choice))

			assertEntriesUnchanged(t, before)
			rec := onDiskRecord(t, j)
			if len(rec.Answers) != 0 || !slices.Equal(rec.Moves, record.Moves) || rec.MoveSeq != record.MoveSeq || !reflect.DeepEqual(rec.Paths, record.Paths) {
				t.Fatalf("record = %+v, want no answer and every member as it was (%+v)", rec, record)
			}
			if len(report.Kept) != 0 || len(report.Restored) != 0 || len(report.Retained) != 1 {
				t.Fatalf("report = %+v, want nothing kept or put back and the journal retained", report)
			}
			asked := 0
			Recover(f.home, f.project, f.policy(), func(u Unresolved) Choice {
				asked++
				return ChoiceDefer
			})
			if asked != 1 {
				t.Fatalf("asked %d times at the next launch, want the group asked about again", asked)
			}
		})
	}
}

func TestRecover_RetainsAJournalWithABadAnswerWithoutTouchingAProjectPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(rec *journalRecord, a, b, c string)
		reason string
	}{
		{"an unknown choice", func(rec *journalRecord, _, _, _ string) { rec.Answers[0].Choice = "maybe" }, "malformed move answer"},
		{"a recorded Defer", func(rec *journalRecord, _, _, _ string) { rec.Answers[0].Choice = ChoiceDefer }, "malformed move answer"},
		{"no members", func(rec *journalRecord, _, _, _ string) { rec.Answers[0].Members, rec.Answers[0].Endpoints = nil, nil }, "malformed move answer"},
		{"a duplicate member", func(rec *journalRecord, _, _, _ string) {
			rec.Answers[0].Members = append(rec.Answers[0].Members, rec.Moves[0].ID)
		}, "does not hold exactly once"},
		{"an unknown member", func(rec *journalRecord, _, _, _ string) {
			rec.Answers[0].Members[1] = moveID{Invocation: "inv-9999", Seq: 1}
		}, "does not hold exactly once"},
		{"a move answered twice", func(rec *journalRecord, _, _, _ string) {
			rec.Answers = append(rec.Answers, rec.Answers[0])
		}, "does not hold exactly once"},
		{"endpoints that are not its moves'", func(rec *journalRecord, a, _, c string) { rec.Answers[0].Endpoints = []string{a, c} }, "endpoints that are not its moves'"},
		{"a Keep with adopted states", func(rec *journalRecord, a, b, c string) {
			rec.Answers[0].Adopted = []adoptedState{{Path: a}, {Path: b}, {Path: c}}
		}, "adopted states do not match"},
		{"a Restore without adopted states", func(rec *journalRecord, _, _, _ string) { rec.Answers[0].Choice = ChoiceRestore }, "adopted states do not match"},
		{"an answer leaving out a linked move", func(rec *journalRecord, a, b, _ string) {
			rec.Answers[0].Members, rec.Answers[0].Endpoints = rec.Answers[0].Members[:1], []string{a, b}
		}, "leaves out the linked move"},
		{"a move identity that is not its own", func(rec *journalRecord, _, _, _ string) {
			rec.Moves[1].ID = rec.Moves[0].ID
		}, "has an identity that is not its own"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			a := f.seed(t, "a.txt", "ORIGINAL\n")
			b, c := filepath.Join(f.project, "b.txt"), filepath.Join(f.project, "c.txt")
			edited := f.seed(t, "e.txt", "ORIGINAL\n")
			j := f.openMoves(t, []string{edited}, pairOf(a, b), pairOf(b, c))
			f.mustMove(t, j, a, b)
			f.mustMove(t, j, b, c)
			f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
			replaceFile(t, c, "A THIRD WRITER\n")
			orphan(t, j)
			rewriteRecord(t, j, func(rec *journalRecord) {
				rec.Answers = []groupAnswer{{Members: []moveID{rec.Moves[0].ID, rec.Moves[1].ID}, Endpoints: []string{a, b, c}, Choice: ChoiceKeep}}
				tc.edit(rec, a, b, c)
			})
			record := readBytes(t, recordPath(j))
			before := captureEntries(t, a, b, c, edited)

			report := Recover(f.home, f.project, f.policy(), neverAsked(t))

			assertEntriesUnchanged(t, before)
			if got := readBytes(t, recordPath(j)); string(got) != string(record) {
				t.Fatalf("record changed:\n%s\nwant\n%s", got, record)
			}
			if len(report.Retained) != 1 || report.Retained[0].Path != j.Path() || len(report.Restored) != 0 || !strings.Contains(strings.Join(report.Retained[0].Notes, "\n"), tc.reason) {
				t.Fatalf("report = %+v, want the journal retained for %q and nothing put back", report, tc.reason)
			}
		})
	}
}

type completedRun struct {
	f                        *fixture
	j                        *Journal
	edited, outside, created string
}

func newCompletedRun(t *testing.T) completedRun {
	t.Helper()
	f := newFixture(t)
	r := completedRun{f: f, edited: f.seed(t, "a.txt", "ORIGINAL\n"), outside: f.seed(t, "b.txt", "ORIGINAL\n"), created: filepath.Join(f.project, "made/new.txt")}
	r.j = f.open(t, r.edited, r.outside, r.created)
	f.childEdit(t, r.j, r.edited, "ORIGINAL", "CHILD")
	f.childCreate(t, r.j, r.created, "CHILD MADE THIS\n")
	replaceFile(t, r.outside, "OUTSIDE\n")
	finishCompleted(t, r.j)
	return r
}

func finishCompleted(t *testing.T, j *Journal) {
	t.Helper()
	if outcome := j.Finish(ReasonCompleted); outcome.JournalPath == "" {
		t.Fatalf("outcome = %+v, want the end-of-run check to keep the journal", outcome)
	}
	orphan(t, j)
}

func (r completedRun) assertChildState(t *testing.T) {
	t.Helper()
	assertContent(t, r.edited, "CHILD\n")
	assertContent(t, r.created, "CHILD MADE THIS\n")
	assertContent(t, r.outside, "OUTSIDE\n")
}

func answers(t *testing.T, asked *[]Unresolved, byKey map[string]Choice) func(Unresolved) Choice {
	return func(u Unresolved) Choice {
		*asked = append(*asked, u)
		key := u.Path
		if key == "" {
			key = u.Moves[0].Source
		}
		choice, ok := byKey[key]
		if !ok {
			t.Errorf("asked about %+v, want no question", u)
			return ChoiceDefer
		}
		return choice
	}
}

func askedPaths(asked []Unresolved) []string {
	var out []string
	for _, u := range asked {
		if u.Path != "" {
			out = append(out, u.Path)
		} else {
			out = append(out, u.Moves[0].Source+" -> "+u.Moves[0].Destination)
		}
	}
	return out
}

func assertCompletedRetained(t *testing.T, report Report, unanswered int) RetainedJournal {
	t.Helper()
	if len(report.Retained) != 1 || !report.Retained[0].Completed || report.Retained[0].Unanswered != unanswered {
		t.Fatalf("retained = %+v, want one completed journal with %d unanswered questions", report.Retained, unanswered)
	}
	if len(report.Restored) != 0 || len(report.Kept) != 0 {
		t.Fatalf("report = %+v, want nothing attributed to an interrupted child", report)
	}
	return report.Retained[0]
}

func TestRecover_LeavesACompletedChildsWorkWhenNoOneCanAnswer(t *testing.T) {
	r := newCompletedRun(t)

	for launch := 1; launch <= 2; launch++ {
		report := Recover(r.f.home, r.f.project, r.f.policy(), nil)

		r.assertChildState(t)
		assertRecordPresent(t, r.j)
		if !onDiskRecord(t, r.j).Completed {
			t.Fatalf("launch %d: the completion marker was lost", launch)
		}
		assertCompletedRetained(t, report, 3)
		if len(report.CompletedRestored) != 0 || len(report.CompletedKept) != 0 {
			t.Fatalf("launch %d: report = %+v, want nothing settled without an answer", launch, report)
		}
	}
}

func TestRecover_AsksAboutEveryChangedPathOfACompletedChild(t *testing.T) {
	t.Run("keep", func(t *testing.T) {
		r := newCompletedRun(t)
		var asked []Unresolved

		report := Recover(r.f.home, r.f.project, r.f.policy(), answers(t, &asked, map[string]Choice{r.edited: ChoiceKeep, r.outside: ChoiceKeep, r.created: ChoiceKeep}))

		if got := askedPaths(asked); !slices.Equal(got, []string{r.edited, r.outside, r.created}) {
			t.Fatalf("asked about %v, want every changed path once", got)
		}
		for _, u := range asked {
			if !u.Completed || !slices.Contains(u.Choices, ChoiceRestore) {
				t.Fatalf("question = %+v, want a completed-child question offering put back", u)
			}
		}
		if asked[0].Reason != "" || !strings.Contains(asked[1].Reason, "it was changed outside the child agent's journalled writes") {
			t.Fatalf("reasons = %q, %q, want none for the confirmed edit and the outside change named", asked[0].Reason, asked[1].Reason)
		}
		r.assertChildState(t)
		assertGone(t, r.j.Path())
		if !slices.Equal(report.CompletedKept, []string{r.edited, r.outside, r.created}) || len(report.Kept) != 0 || len(report.Retained) != 0 {
			t.Fatalf("report = %+v, want every path reported kept for the completed child", report)
		}
	})

	t.Run("put back", func(t *testing.T) {
		r := newCompletedRun(t)

		report := Recover(r.f.home, r.f.project, r.f.policy(), answer(ChoiceRestore))

		assertContent(t, r.edited, "ORIGINAL\n")
		assertContent(t, r.outside, "ORIGINAL\n")
		assertGone(t, r.created)
		assertGone(t, filepath.Dir(r.created))
		assertGone(t, r.j.Path())
		for _, path := range []string{r.edited, r.outside, r.created} {
			if !slices.Contains(report.CompletedRestored, path) {
				t.Fatalf("report = %+v, want %s reported put back for the completed child", report, path)
			}
		}
		if len(report.Restored) != 0 || len(report.Retained) != 0 {
			t.Fatalf("report = %+v, want nothing else", report)
		}
	})

	t.Run("decide later", func(t *testing.T) {
		r := newCompletedRun(t)

		report := Recover(r.f.home, r.f.project, r.f.policy(), answer(ChoiceDefer))

		r.assertChildState(t)
		assertRecordPresent(t, r.j)
		assertCompletedRetained(t, report, 3)
	})

	t.Run("a durability failure outlives every answer", func(t *testing.T) {
		f := newFixture(t)
		edited := f.seed(t, "a.txt", "ORIGINAL\n")
		j := f.open(t, edited)
		failSyncOnce(t)
		f.childEdit(t, j, edited, "ORIGINAL", "CHILD")
		finishCompleted(t, j)

		report := Recover(f.home, f.project, f.policy(), answer(ChoiceKeep))

		assertContent(t, edited, "CHILD\n")
		assertRecordPresent(t, j)
		retained := assertCompletedRetained(t, report, 0)
		if !slices.Equal(report.CompletedKept, []string{edited}) || !strings.Contains(strings.Join(retained.Notes, "|"), "could not be made durable") {
			t.Fatalf("report = %+v, want the path kept and the durability failure named", report)
		}
	})

	t.Run("a policy hold outlives every answer", func(t *testing.T) {
		r := newCompletedRun(t)
		var asked []Unresolved

		report := Recover(r.f.home, r.f.project, r.f.policy(r.outside), answers(t, &asked, map[string]Choice{r.edited: ChoiceKeep, r.created: ChoiceKeep}))

		r.assertChildState(t)
		assertRecordPresent(t, r.j)
		retained := assertCompletedRetained(t, report, 0)
		if retained.PolicyNotes != 1 || !slices.Contains(retained.Notes, blockedNote(r.outside, r.outside)) {
			t.Fatalf("retained = %+v, want the blocked path named as the remaining hold", retained)
		}
	})
}

func TestRecover_ACompletedChildsMixedAnswersTouchOnlyAuthorizedPaths(t *testing.T) {
	t.Run("files across repeated launches", func(t *testing.T) {
		r := newCompletedRun(t)
		var asked []Unresolved

		Recover(r.f.home, r.f.project, r.f.policy(), answers(t, &asked, map[string]Choice{r.edited: ChoiceKeep, r.created: ChoiceRestore, r.outside: ChoiceDefer}))

		assertContent(t, r.edited, "CHILD\n")
		assertGone(t, r.created)
		assertGone(t, filepath.Dir(r.created))
		assertContent(t, r.outside, "OUTSIDE\n")
		assertRecordPresent(t, r.j)

		asked = nil
		report := Recover(r.f.home, r.f.project, r.f.policy(), answers(t, &asked, map[string]Choice{r.outside: ChoiceDefer}))
		if got := askedPaths(asked); !slices.Equal(got, []string{r.outside}) {
			t.Fatalf("asked about %v, want only the deferred path", got)
		}
		assertContent(t, r.edited, "CHILD\n")
		assertContent(t, r.outside, "OUTSIDE\n")
		assertCompletedRetained(t, report, 1)

		Recover(r.f.home, r.f.project, r.f.policy(), answers(t, &asked, map[string]Choice{r.outside: ChoiceRestore}))
		assertContent(t, r.outside, "ORIGINAL\n")
		assertContent(t, r.edited, "CHILD\n")
		assertGone(t, r.j.Path())
	})

	parents := func(t *testing.T) (f *fixture, j *Journal, x, y, outside string) {
		f = newFixture(t)
		x, y, outside = filepath.Join(f.project, "made/x.txt"), filepath.Join(f.project, "made/y.txt"), f.seed(t, "o.txt", "ORIGINAL\n")
		j = f.open(t, x, y, outside)
		f.childCreate(t, j, x, "X\n")
		f.childCreate(t, j, y, "Y\n")
		replaceFile(t, outside, "OUTSIDE\n")
		finishCompleted(t, j)
		return f, j, x, y, outside
	}

	t.Run("a created parent follows the last path that needs it", func(t *testing.T) {
		f, j, x, y, outside := parents(t)
		var asked []Unresolved

		Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{x: ChoiceRestore, y: ChoiceDefer, outside: ChoiceKeep}))

		assertGone(t, x)
		assertContent(t, y, "Y\n")
		assertRecordPresent(t, j)

		Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{y: ChoiceRestore}))

		assertGone(t, y)
		assertGone(t, filepath.Dir(x))
		assertContent(t, outside, "OUTSIDE\n")
		assertGone(t, j.Path())
	})

	t.Run("a kept file keeps the created parent it needs", func(t *testing.T) {
		f, j, x, y, outside := parents(t)
		var asked []Unresolved

		Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{x: ChoiceRestore, y: ChoiceKeep, outside: ChoiceKeep}))

		assertGone(t, x)
		assertContent(t, y, "Y\n")
		assertGone(t, j.Path())
	})

	moved := func(t *testing.T) (f *fixture, j *Journal, tree, dest, created, outside string) {
		f = newFixture(t)
		tree = f.dir(t, "tree", 0o755)
		f.seed(t, "tree/keep.txt", "TREE\n")
		dest = filepath.Join(f.project, "moved")
		created = filepath.Join(dest, "new.txt")
		outside = f.seed(t, "o.txt", "ORIGINAL\n")
		j = f.openMoves(t, []string{created, outside}, pairOf(tree, dest))
		f.mustMove(t, j, tree, dest)
		mustSucceed(t, f.childCreate(t, j, created, "CHILD\n"))
		replaceFile(t, outside, "OUTSIDE\n")
		finishCompleted(t, j)
		return f, j, tree, dest, created, outside
	}

	t.Run("a changed path beneath a moved directory and its group are put back in one pass", func(t *testing.T) {
		f, j, tree, dest, created, outside := moved(t)
		var asked []Unresolved

		report := Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{created: ChoiceRestore, outside: ChoiceKeep, tree: ChoiceRestore}))

		if got := askedPaths(asked); !slices.Equal(got, []string{created, outside, tree + " -> " + dest}) {
			t.Fatalf("asked about %v, want the path beneath the moved directory before its group", got)
		}
		if group := asked[2]; !group.Completed || !slices.Contains(group.Choices, ChoiceRestore) {
			t.Fatalf("group question = %+v, want put back offered once the path beneath is scheduled", group)
		}
		assertContent(t, filepath.Join(tree, "keep.txt"), "TREE\n")
		assertGone(t, filepath.Join(tree, "new.txt"))
		assertGone(t, dest)
		assertContent(t, outside, "OUTSIDE\n")
		assertGone(t, j.Path())
		if len(report.Retained) != 0 {
			t.Fatalf("retained = %+v, want a settled journal", report.Retained)
		}
	})

	t.Run("a deferred path beneath a moved directory holds its group across launches", func(t *testing.T) {
		f, j, tree, dest, created, outside := moved(t)
		var asked []Unresolved

		Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{created: ChoiceDefer, outside: ChoiceKeep, tree: ChoiceRestore}))

		if group := asked[2]; slices.Contains(group.Choices, ChoiceRestore) || group.RestoreRefusal == "" {
			t.Fatalf("group question = %+v, want put back withheld with a reason", group)
		}
		assertContent(t, created, "CHILD\n")
		assertGone(t, tree)
		assertRecordPresent(t, j)

		asked = nil
		Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{created: ChoiceRestore, tree: ChoiceRestore}))

		if got := askedPaths(asked); !slices.Equal(got, []string{created, tree + " -> " + dest}) {
			t.Fatalf("asked about %v, want the kept path not asked again", got)
		}
		assertContent(t, filepath.Join(tree, "keep.txt"), "TREE\n")
		assertGone(t, dest)
		assertContent(t, outside, "OUTSIDE\n")
		assertGone(t, j.Path())
	})

	t.Run("a kept path beneath a moved directory is never moved by its group's put back", func(t *testing.T) {
		f, j, tree, _, created, outside := moved(t)
		var asked []Unresolved

		Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{created: ChoiceKeep, outside: ChoiceKeep, tree: ChoiceRestore}))

		assertContent(t, created, "CHILD\n")
		assertGone(t, tree)
		assertRecordPresent(t, j)
	})

	for _, child := range []Choice{ChoiceDefer, ChoiceKeep} {
		t.Run("a recreated directory stays while a deleted file inside it is answered "+string(child), func(t *testing.T) {
			f := newFixture(t)
			d := f.dir(t, "d", 0o750)
			file, outside := f.seed(t, "d/file.txt", "ORIGINAL\n"), f.seed(t, "o.txt", "ORIGINAL\n")
			j := f.openConfig(t, JournalConfig{Declared: []string{outside}, DeclaredDelete: []string{d, file}, DeclaredDirs: []string{d}})
			f.mustDelete(t, j, file)
			f.mustDelete(t, j, d)
			mustSucceed(t, f.childMkdir(t, j, d))
			replaceFile(t, outside, "OUTSIDE\n")
			finishCompleted(t, j)
			info, err := os.Lstat(d)
			if err != nil {
				t.Fatalf("stat the recreated directory: %v", err)
			}
			dev, ino := identityOf(t, info)

			for launch, byKey := range []map[string]Choice{{d: ChoiceRestore, file: child, outside: ChoiceKeep}, {d: ChoiceRestore, file: child}} {
				if child == ChoiceKeep && launch == 1 {
					byKey = map[string]Choice{d: ChoiceRestore}
				}
				Recover(f.home, f.project, f.policy(), answers(t, new([]Unresolved), byKey))

				info, err := os.Lstat(d)
				if err != nil {
					t.Fatalf("launch %d: stat the recreated directory: %v", launch, err)
				}
				if gotDev, gotIno := identityOf(t, info); gotDev != dev || gotIno != ino {
					t.Fatalf("launch %d: %s was replaced, want the child's directory left while %s is %s", launch, d, file, child)
				}
				assertGone(t, file)
				assertRecordPresent(t, j)
			}
		})
	}

	movedWithDir := func(t *testing.T) (f *fixture, j *Journal, tree, dest, sub, outside string) {
		f = newFixture(t)
		tree = f.dir(t, "tree", 0o755)
		f.seed(t, "tree/keep.txt", "TREE\n")
		dest = filepath.Join(f.project, "moved")
		sub = filepath.Join(dest, "sub")
		outside = f.seed(t, "o.txt", "ORIGINAL\n")
		j = f.openConfig(t, JournalConfig{Declared: []string{outside}, DeclaredMoves: []permissions.MovePair{pairOf(tree, dest)}, DeclaredDirs: []string{sub}})
		f.mustMove(t, j, tree, dest)
		mustSucceed(t, f.childMkdir(t, j, sub))
		replaceFile(t, outside, "OUTSIDE\n")
		finishCompleted(t, j)
		return f, j, tree, dest, sub, outside
	}

	t.Run("a group's put back settles a directory the child created inside the moved entry", func(t *testing.T) {
		f, j, tree, dest, _, outside := movedWithDir(t)
		var asked []Unresolved

		Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{outside: ChoiceKeep, tree: ChoiceRestore}))

		if got := askedPaths(asked); !slices.Equal(got, []string{outside, tree + " -> " + dest}) {
			t.Fatalf("asked about %v, want no question about the created directory", got)
		}
		if group := asked[1]; !slices.Contains(group.Choices, ChoiceRestore) {
			t.Fatalf("group question = %+v, want put back offered", group)
		}
		assertContent(t, filepath.Join(tree, "keep.txt"), "TREE\n")
		assertGone(t, filepath.Join(tree, "sub"))
		assertGone(t, dest)
		assertContent(t, outside, "OUTSIDE\n")
		assertGone(t, j.Path())
	})

	t.Run("a deferred group leaves the directory the child created inside the moved entry", func(t *testing.T) {
		f, j, tree, dest, sub, outside := movedWithDir(t)

		Recover(f.home, f.project, f.policy(), answers(t, new([]Unresolved), map[string]Choice{outside: ChoiceKeep, tree: ChoiceDefer}))

		assertDir(t, sub, 0o755)
		assertContent(t, filepath.Join(dest, "keep.txt"), "TREE\n")
		assertGone(t, tree)
		assertRecordPresent(t, j)
	})
}

func TestRecover_RederivesACompletedChildsReasonsAndHoldsUnsafeStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(t *testing.T, f *fixture) (*Journal, string, func(t *testing.T))
		reason string
	}{
		{"an unresolved pending write", func(t *testing.T, f *fixture) (*Journal, string, func(t *testing.T)) {
			target := f.seed(t, "a.txt", "ORIGINAL\n")
			j := f.open(t, target)
			if err := j.BeginMutation(target, filetools.JournalState{Exists: true, Data: []byte("ORIGINAL\n"), Mode: 0o644}, filetools.JournalState{Exists: true, Data: []byte("CHILD\n"), Mode: 0o644}); err != nil {
				t.Fatalf("begin the write: %v", err)
			}
			replaceFile(t, target, "OUTSIDE\n")
			return j, target, func(t *testing.T) { assertContent(t, target, "OUTSIDE\n") }
		}, "a write the child agent started was never resolved"},
		{"an unreadable state", func(t *testing.T, f *fixture) (*Journal, string, func(t *testing.T)) {
			target := f.seed(t, "sub/x.txt", "ORIGINAL\n")
			j := f.open(t, target)
			f.childEdit(t, j, target, "ORIGINAL", "CHILD")
			sub := filepath.Dir(target)
			if err := os.Rename(sub, sub+".old"); err != nil {
				t.Fatalf("move the parent aside: %v", err)
			}
			f.seed(t, "sub/x.txt", "OTHER\n")
			return j, target, func(t *testing.T) {
				assertContent(t, target, "OTHER\n")
				assertContent(t, filepath.Join(sub+".old", "x.txt"), "CHILD\n")
			}
		}, "the target's parent directory could not be safely reopened"},
		{"an unconfirmed directory", func(t *testing.T, f *fixture) (*Journal, string, func(t *testing.T)) {
			target := filepath.Join(f.project, "made/new.txt")
			j := f.open(t, target)
			if err := j.DirLifecycle(target, f.project).Intent("made"); err != nil {
				t.Fatalf("record the intent: %v", err)
			}
			made := f.dir(t, "made", 0o755)
			return j, target, func(t *testing.T) { assertDir(t, made, 0o755) }
		}, "a parent directory the child agent started to create was never confirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			j, target, unchanged := tc.setup(t, f)
			finishCompleted(t, j)

			for launch := 1; launch <= 2; launch++ {
				var asked []Unresolved
				report := Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{target: ChoiceRestore}))

				if len(asked) != 1 || !strings.Contains(asked[0].Reason, tc.reason) || slices.Contains(asked[0].Choices, ChoiceRestore) || asked[0].RestoreRefusal == "" {
					t.Fatalf("launch %d: asked %+v, want one question naming %q without put back", launch, asked, tc.reason)
				}
				unchanged(t)
				assertRecordPresent(t, j)
				assertCompletedRetained(t, report, 1)
			}
		})
	}

	t.Run("a third-state path", func(t *testing.T) {
		r := newCompletedRun(t)
		var asked []Unresolved

		Recover(r.f.home, r.f.project, r.f.policy(), answers(t, &asked, map[string]Choice{r.edited: ChoiceDefer, r.outside: ChoiceDefer, r.created: ChoiceDefer}))

		if len(asked) != 3 || asked[1].Path != r.outside || asked[1].Reason != "it was changed outside the child agent's journalled writes" {
			t.Fatalf("asked %+v, want the outside change named as the reason", asked)
		}
	})
}

func TestRecover_NeverOffersACompletedChildsDirectories(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *fixture) (*Journal, string)
	}{
		{"a directory-only journal whose directory was replaced", func(t *testing.T, f *fixture) (*Journal, string) {
			dir := filepath.Join(f.project, "made")
			j := f.openConfig(t, JournalConfig{DeclaredDirs: []string{dir}})
			mustSucceed(t, f.childMkdir(t, j, dir))
			if err := os.Remove(dir); err != nil {
				t.Fatalf("remove the child's directory: %v", err)
			}
			f.dir(t, "made", 0o755)
			return j, dir
		}},
		{"an unconfirmed directory intent", func(t *testing.T, f *fixture) (*Journal, string) {
			target := filepath.Join(f.project, "made/new.txt")
			j := f.open(t, target)
			if err := j.DirLifecycle(target, f.project).Intent("made"); err != nil {
				t.Fatalf("record the intent: %v", err)
			}
			return j, filepath.Join(f.project, "made")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			j, dir := tc.setup(t, f)
			finishCompleted(t, j)
			_, statErr := os.Lstat(dir)

			for launch := 1; launch <= 2; launch++ {
				report := Recover(f.home, f.project, f.policy(), neverAsked(t))

				retained := assertCompletedRetained(t, report, 0)
				if !slices.Equal(retained.Dirs, []string{dir}) {
					t.Fatalf("launch %d: dirs = %v, want %s reported", launch, retained.Dirs, dir)
				}
				if _, err := os.Lstat(dir); (err == nil) != (statErr == nil) {
					t.Fatalf("launch %d: %s changed presence (err=%v, before %v)", launch, dir, err, statErr)
				}
				assertRecordPresent(t, j)
			}
		})
	}

	t.Run("a declared directory holding another writer's entry after its file is put back", func(t *testing.T) {
		f := newFixture(t)
		dir := filepath.Join(f.project, "made")
		created, outside := filepath.Join(dir, "new.txt"), f.seed(t, "o.txt", "ORIGINAL\n")
		j := f.openConfig(t, JournalConfig{Declared: []string{created, outside}, DeclaredDirs: []string{dir}})
		mustSucceed(t, f.childMkdir(t, j, dir))
		mustSucceed(t, f.childCreate(t, j, created, "CHILD\n"))
		stranger := f.seed(t, "made/stranger.txt", "STRANGER\n")
		replaceFile(t, outside, "OUTSIDE\n")
		finishCompleted(t, j)
		var asked []Unresolved

		report := Recover(f.home, f.project, f.policy(), answers(t, &asked, map[string]Choice{created: ChoiceRestore, outside: ChoiceKeep}))

		assertGone(t, created)
		assertContent(t, stranger, "STRANGER\n")
		assertRecordPresent(t, j)
		if retained := assertCompletedRetained(t, report, 0); !slices.Equal(retained.Dirs, []string{dir}) {
			t.Fatalf("dirs = %v, want %s retained", retained.Dirs, dir)
		}
	})

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *fixture) (j *Journal, dir string, answer map[string]Choice)
	}{
		{"a confirmed declared directory holding another writer's entry while a separate file is kept", func(t *testing.T, f *fixture) (*Journal, string, map[string]Choice) {
			dir, outside := filepath.Join(f.project, "made"), f.seed(t, "o.txt", "ORIGINAL\n")
			j := f.openConfig(t, JournalConfig{Declared: []string{outside}, DeclaredDirs: []string{dir}})
			mustSucceed(t, f.childMkdir(t, j, dir))
			replaceFile(t, outside, "OUTSIDE\n")
			return j, dir, map[string]Choice{outside: ChoiceKeep}
		}},
		{"an implicit parent holding another writer's entry whose file is already at its pre-run state", func(t *testing.T, f *fixture) (*Journal, string, map[string]Choice) {
			created := filepath.Join(f.project, "made/new.txt")
			j := f.open(t, created)
			mustSucceed(t, f.childCreate(t, j, created, "CHILD\n"))
			if err := os.Remove(created); err != nil {
				t.Fatalf("remove the child's file: %v", err)
			}
			return j, filepath.Dir(created), map[string]Choice{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			j, dir, answer := tc.setup(t, f)
			stranger := f.seed(t, "made/stranger.txt", "STRANGER\n")
			finishCompleted(t, j)

			for _, byKey := range []map[string]Choice{answer, {}} {
				report := Recover(f.home, f.project, f.policy(), answers(t, new([]Unresolved), byKey))

				if retained := assertCompletedRetained(t, report, 0); !slices.Equal(retained.Dirs, []string{dir}) {
					t.Fatalf("dirs = %v, want %s retained", retained.Dirs, dir)
				}
				assertDir(t, dir, 0o755)
				assertContent(t, stranger, "STRANGER\n")
				if rec := onDiskRecord(t, j); !rec.Completed {
					t.Fatalf("record = %+v, want the completed journal kept", rec)
				}
			}
		})
	}
}

func TestRecover_RetainsACompletedChildsUnresolvedImplicitParent(t *testing.T) {
	assertHeld := func(t *testing.T, j *Journal, report Report, created, dir string) {
		t.Helper()
		if retained := assertCompletedRetained(t, report, 0); !slices.Equal(retained.Dirs, []string{dir}) {
			t.Fatalf("dirs = %v, want %s retained", retained.Dirs, dir)
		}
		assertDir(t, dir, 0o755)
		assertGone(t, created)
		assertRecordPresent(t, j)
		rec := onDiskRecord(t, j)
		if !rec.Completed || !slices.ContainsFunc(pathIn(t, rec, created).Dirs, func(d dirRecord) bool { return d.Rel == "made" && d.Progress != rollbackRestored }) {
			t.Fatalf("record = %+v, want the completed journal still tracking made", rec)
		}
	}
	stranger := func(t *testing.T) (f *fixture, j *Journal, created, outside, stranger string) {
		f = newFixture(t)
		created, outside = filepath.Join(f.project, "made/new.txt"), f.seed(t, "o.txt", "ORIGINAL\n")
		j = f.open(t, created, outside)
		mustSucceed(t, f.childCreate(t, j, created, "CHILD\n"))
		stranger = f.seed(t, "made/stranger.txt", "STRANGER\n")
		replaceFile(t, outside, "OUTSIDE\n")
		finishCompleted(t, j)
		return f, j, created, outside, stranger
	}

	t.Run("holding another writer's file after every path is answered", func(t *testing.T) {
		f, j, created, outside, kept := stranger(t)

		for launch, byKey := range []map[string]Choice{{created: ChoiceRestore, outside: ChoiceKeep}, {}} {
			var asked []Unresolved
			report := Recover(f.home, f.project, f.policy(), answers(t, &asked, byKey))

			assertHeld(t, j, report, created, filepath.Dir(created))
			assertContent(t, kept, "STRANGER\n")
			assertContent(t, outside, "OUTSIDE\n")
			if launch == 0 && (!slices.Equal(report.CompletedRestored, []string{created}) || !slices.Equal(report.CompletedKept, []string{outside})) {
				t.Fatalf("report = %+v, want the answered paths settled", report)
			}
		}
	})

	t.Run("replaced after its file is put back", func(t *testing.T) {
		f, j, created, outside, kept := stranger(t)
		dir := filepath.Dir(created)
		Recover(f.home, f.project, f.policy(), answers(t, new([]Unresolved), map[string]Choice{created: ChoiceRestore, outside: ChoiceKeep}))
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Fatalf("move the created parent aside: %v", err)
		}
		f.dir(t, "made", 0o755)

		for range 2 {
			report := Recover(f.home, f.project, f.policy(), neverAsked(t))

			assertHeld(t, j, report, created, dir)
			assertContent(t, filepath.Join(dir+".old", filepath.Base(kept)), "STRANGER\n")
		}
	})

	t.Run("an unconfirmed intent after its file is put back", func(t *testing.T) {
		f := newFixture(t)
		created := filepath.Join(f.project, "made/new.txt")
		j := f.open(t, created)
		mustSucceed(t, f.childCreate(t, j, created, "CHILD\n"))
		if err := j.DirLifecycle(created, f.project).Intent("made"); err != nil {
			t.Fatalf("record the intent: %v", err)
		}
		finishCompleted(t, j)

		for launch, byKey := range []map[string]Choice{{created: ChoiceRestore}, {}} {
			var asked []Unresolved
			report := Recover(f.home, f.project, f.policy(), answers(t, &asked, byKey))

			assertHeld(t, j, report, created, filepath.Dir(created))
			if launch == 0 && !slices.Equal(report.CompletedRestored, []string{created}) {
				t.Fatalf("report = %+v, want the file put back", report)
			}
		}
	})
}

func TestRecover_HoldsTheJournalLockWhileACompletedChildsQuestionIsOpen(t *testing.T) {
	r := newCompletedRun(t)
	opened := false

	report := Recover(r.f.home, r.f.project, r.f.policy(), func(Unresolved) Choice {
		if !opened {
			opened = true
			before := readBytes(t, recordPath(r.j))
			if second := Recover(r.f.home, r.f.project, r.f.policy(), neverAsked(t)); !second.Empty() {
				t.Errorf("second pass report = %+v, want the open journal skipped", second)
			}
			if after := readBytes(t, recordPath(r.j)); string(after) != string(before) {
				t.Errorf("record changed under the open question:\n%s\nwant\n%s", after, before)
			}
			r.assertChildState(t)
		}
		return ChoiceDefer
	})

	if !opened {
		t.Fatal("no question was asked")
	}
	r.assertChildState(t)
	assertRecordPresent(t, r.j)
	assertCompletedRetained(t, report, 3)
}

func TestRecover_RechecksACompletedChildsPathBeforePuttingItBack(t *testing.T) {
	t.Run("a path replaced while its question is open", func(t *testing.T) {
		r := newCompletedRun(t)

		report := Recover(r.f.home, r.f.project, r.f.policy(), func(u Unresolved) Choice {
			if u.Path == r.outside {
				replaceFile(t, r.outside, "NEWER\n")
			}
			return ChoiceRestore
		})

		assertContent(t, r.outside, "NEWER\n")
		assertContent(t, r.edited, "ORIGINAL\n")
		assertRecordPresent(t, r.j)
		if retained := assertCompletedRetained(t, report, 1); !slices.Contains(retained.Notes, r.outside+": it changed while the question was open, so it was not put back") {
			t.Fatalf("notes = %v, want the changed path reported", retained.Notes)
		}
	})

	t.Run("a path blocked before its put back", func(t *testing.T) {
		r := newCompletedRun(t)
		s := &listSwitch{}

		report := Recover(r.f.home, r.f.project, r.f.switchPolicy(s), func(u Unresolved) Choice {
			if u.Path == r.outside {
				s.blocked = []string{r.outside}
			}
			return ChoiceRestore
		})

		assertContent(t, r.outside, "OUTSIDE\n")
		assertContent(t, r.edited, "ORIGINAL\n")
		assertRecordPresent(t, r.j)
		if retained := assertCompletedRetained(t, report, 0); !slices.Contains(retained.Notes, blockedNote(r.outside, r.outside)) {
			t.Fatalf("notes = %v, want the newly blocked path held", retained.Notes)
		}
	})
}

func TestRecover_RetainsACompletionMarkerBelowItsSchemaWithoutTouchingAProjectPath(t *testing.T) {
	for v := 1; v <= 5; v++ {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			r := newCompletedRun(t)
			rewriteRecord(t, r.j, func(rec *journalRecord) { rec.SchemaVersion = v })
			record := readBytes(t, recordPath(r.j))

			report := Recover(r.f.home, r.f.project, r.f.policy(), answer(ChoiceRestore))

			r.assertChildState(t)
			if got := readBytes(t, recordPath(r.j)); string(got) != string(record) {
				t.Fatalf("record changed:\n%s\nwant\n%s", got, record)
			}
			want := fmt.Sprintf("a schema %d journal holds a completion marker", v)
			if len(report.Retained) != 1 || len(report.CompletedRestored)+len(report.Restored) != 0 || !strings.Contains(strings.Join(report.Retained[0].Notes, "\n"), want) {
				t.Fatalf("report = %+v, want the journal retained for %q", report, want)
			}
		})
	}
}
