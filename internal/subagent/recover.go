package subagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/sessions"
)

// Choice is the answer to one path recovery cannot put back on its own. Defer is the safe answer:
// nothing is written and the path is offered again at the next launch.
type Choice string

const (
	ChoiceDefer   Choice = "defer"
	ChoiceKeep    Choice = "keep"
	ChoiceRestore Choice = "restore"
)

// A group question leaves Path empty and lists its moves in journal order.
type Unresolved struct {
	Path           string
	Moves          []UnresolvedMove
	Choices        []Choice
	RestoreRefusal string
}

type UnresolvedMove struct {
	ID          moveID
	Source      string
	Destination string
	Pending     bool
}

type RetainedJournal struct {
	Path  string
	Notes []string
	Moves []HeldMove
	Dirs  []string
}

type LeftAloneJournal struct {
	Path   string
	Reason string
}

type Report struct {
	Restored  []string
	Kept      []string
	Retained  []RetainedJournal
	LeftAlone []LeftAloneJournal
}

func (r Report) Empty() bool {
	return len(r.Restored) == 0 && len(r.Kept) == 0 && len(r.Retained) == 0 && len(r.LeftAlone) == 0
}

var (
	errNoJournalRecord = errors.New("subagent: the journal directory holds no record")
	errJournalHeld     = errors.New("subagent: another codemeld holds the journal's lock")
)

type leftAloneError struct{ reason string }

func (e *leftAloneError) Error() string { return e.reason }

// Recover puts back the declared writes of every child agent whose codemeld process died before it
// could unwind them, for the project folder being opened. A journal whose lock another process holds is
// skipped without reading its record, and so is every journal linked above it. ask decides each held
// move group whose undo has not begun, and then the paths that match neither the state the child left
// nor the state captured before it ran; a nil ask defers all of them, while answers recorded earlier are
// still carried out.
func Recover(home, projectRoot string, ask func(Unresolved) Choice) Report {
	if home == "" || projectRoot == "" {
		return Report{}
	}
	holder, folder, err := openJournalFolder(home, projectRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Report{}
		}
		return Report{Retained: []RetainedJournal{{
			Path:  folder,
			Notes: []string{"the child agent journals could not be opened: " + err.Error()},
		}}}
	}
	defer holder.Close() //nolint:errcheck // read-only directory descriptor

	names, err := holder.Readdirnames(-1)
	if err != nil {
		return Report{Retained: []RetainedJournal{{
			Path:  folder,
			Notes: []string{"the child agent journals could not be listed: " + err.Error()},
		}}}
	}
	sort.Strings(names)

	var report Report
	orphans := make([]*Journal, 0, len(names))
	held := make(map[string]bool)
	unavailable := make(map[string]string)
	for _, name := range names {
		j, lErr := loadJournal(holder, folder, name, projectRoot)
		var leftAlone *leftAloneError
		switch {
		case errors.Is(lErr, errNoJournalRecord):
			// A live codemeld creates the directory before it writes the record, so an empty one is
			// another process's work in progress rather than a transaction to recover.
			continue
		case errors.Is(lErr, errJournalHeld):
			held[name] = true
			continue
		case errors.As(lErr, &leftAlone):
			report.LeftAlone = append(report.LeftAlone, LeftAloneJournal{Path: filepath.Join(folder, name), Reason: leftAlone.reason})
			unavailable[name] = filepath.Join(folder, name) + " (" + leftAlone.reason + ")"
			continue
		case lErr != nil:
			note := "the child agent journal could not be read: " + lErr.Error()
			report.Retained = append(report.Retained, RetainedJournal{Path: filepath.Join(folder, name), Notes: []string{note}})
			unavailable[name] = filepath.Join(folder, name) + " (" + note + ")"
			continue
		}
		j.resetNotes()
		orphans = append(orphans, j)
	}

	orphans = holdBackLinkedParents(orphans, held, unavailable, &report)
	linkOrphans(orphans)
	sort.SliceStable(orphans, func(a, b int) bool { return orphans[a].rec.Depth > orphans[b].rec.Depth })
	for _, j := range orphans {
		recoverJournal(j, ask, &report)
		j.Close()
	}
	return report
}

// recoverJournal dispatches one orphaned journal by lifecycle. It runs deepest-first, so a
// transfer-ready descendant has handed its last-known state over before its parent compares a path.
func recoverJournal(j *Journal, ask func(Unresolved) Choice, report *Report) {
	switch {
	case j.rec.Lifecycle == lifecycleCommitted:
		collect(report, j.cleanUpCommitted())
	case j.rec.Lifecycle == lifecycleTransferReady && j.parent != nil:
		j.replayAnswers()
		if err := j.parent.Absorb(j); err != nil {
			j.parent.retain("a nested child agent's journal could not be absorbed: " + err.Error())
			collect(report, j.retain("its parent could not absorb it: "+err.Error()))
		}
	default:
		replayed := j.replayAnswers()
		j.ReconcilePending()
		outcome := j.rollback(nil)
		outcome.Restored = append(replayed, outcome.Restored...)
		if outcome.JournalPath != "" && ask != nil {
			outcome = answerQuestions(j, ask, outcome, report)
		}
		if outcome.JournalPath != "" && j.parent != nil {
			j.parent.retain(j.path + ": a nested child agent's journal could not be recovered")
		}
		collect(report, outcome)
	}
}

// Only a path answer runs a second rollback, and that rollback leaves every group still open exactly as
// it was.
func answerQuestions(j *Journal, ask func(Unresolved) Choice, outcome JournalOutcome, report *Report) JournalOutcome {
	pass := askGroups(j, ask, outcome.heldAt)
	report.Kept = append(report.Kept, pass.kept...)
	kept, resolved := applyChoices(j, ask)
	report.Kept = append(report.Kept, kept...)
	restored := append(outcome.Restored, pass.restored...)
	switch {
	case resolved:
		j.resetNotes()
		j.mu.Lock()
		for _, note := range pass.notes {
			j.note(note)
		}
		j.mu.Unlock()
		next := j.rollback(pass.frozen)
		next.Restored = append(restored, next.Restored...)
		return next
	case pass.answered || len(pass.notes) > 0:
		next := j.settledOutcome(pass.frozen)
		next.Restored = restored
		return next
	}
	return outcome
}

type groupPass struct {
	kept, restored, notes []string
	frozen                map[int]HeldMove
	answered              bool
}

func askGroups(j *Journal, ask func(Unresolved) Choice, heldAt map[int]HeldMove) groupPass {
	j.mu.Lock()
	defer j.mu.Unlock()
	pass := groupPass{frozen: maps.Clone(heldAt)}
	hold := func(group []int, msg string) {
		note := j.rec.Moves[group[0]].Source + " -> " + j.rec.Moves[group[0]].Destination + ": " + msg
		j.note(note)
		pass.notes = append(pass.notes, note)
	}
	for _, group := range j.moveGroups() {
		if !slices.ContainsFunc(group, func(i int) bool { h, ok := heldAt[i]; return ok && !h.Resumes }) {
			continue
		}
		observed, refusal := j.restoreRefusal(group)
		switch ask(j.groupQuestion(group, refusal)) {
		case ChoiceKeep:
			ans, err := j.publishAnswer(group, ChoiceKeep, nil)
			if err != nil {
				hold(group, "the answer to keep these moves could not be recorded: "+err.Error())
				continue
			}
			pass.answered = true
			j.clearGroupNotes(group, ans.Endpoints)
			for _, i := range group {
				delete(pass.frozen, i)
			}
			if err := j.settleKept(ans); err != nil {
				j.note("the kept moves could not be recorded as settled: " + err.Error())
			}
			pass.kept = append(pass.kept, ans.Endpoints...)
		case ChoiceRestore:
			if refusal != "" {
				continue
			}
			again, refusal := j.restoreRefusal(group)
			if refusal == "" && !sameObservations(observed, again) {
				refusal = "an endpoint changed while the question was open"
			}
			if refusal != "" {
				hold(group, "these moves were not put back and are asked about again at the next launch: "+refusal)
				continue
			}
			ans, err := j.publishAnswer(group, ChoiceRestore, again)
			if err != nil {
				hold(group, "the answer to put these moves back could not be recorded: "+err.Error())
				continue
			}
			pass.answered = true
			changed, held := j.restoreGroup(group, ans.Endpoints)
			for _, i := range group {
				delete(pass.frozen, i)
			}
			maps.Copy(pass.frozen, held)
			pass.restored = append(pass.restored, changed...)
			if len(held) == 0 && !slices.ContainsFunc(j.rec.Unrecovered, j.groupNote(group, ans.Endpoints)) {
				for _, path := range ans.Endpoints {
					if !slices.Contains(pass.restored, path) {
						pass.restored = append(pass.restored, path)
					}
				}
			}
		}
	}
	return pass
}

func sameObservations(a, b map[string]fileState) bool {
	return maps.EqualFunc(a, b, sameState)
}

// applyChoices offers every path still holding a third state and records the answer durably. A kept
// path is what stops an answered path from being offered again at the next launch; a restore adopts
// the state now on disk as the child's, which is what lets the shared rollback protocol replace it.
func applyChoices(j *Journal, ask func(Unresolved) Choice) (kept []string, resolved bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		answered := slices.ContainsFunc(j.rec.Answers, func(ans groupAnswer) bool { return slices.Contains(ans.Endpoints, pr.Path) })
		// Directory ownership is never offered; a record carries no write form, so only a delete or move
		// form at the same path keeps a declared directory's path eligible.
		if answered || pr.Progress == rollbackRestored || pr.KeptByUser || pr.Mkdir && !pr.Delete && !pr.Move || j.endpointOf(pr.Path, func(s moveState) bool { return s != moveUndone }) {
			continue
		}
		dir, err := j.openTargetParent(pr)
		if err != nil {
			continue
		}
		current, cErr := j.currentState(pr, dir)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		if cErr != nil || sameState(current, pr.LastKnown) {
			continue
		}
		switch ask(Unresolved{Path: pr.Path}) {
		case ChoiceKeep:
			pr.KeptByUser = true
			if sErr := j.step("kept"); sErr != nil {
				pr.KeptByUser = false
				continue
			}
			kept = append(kept, pr.Path)
			resolved = true
		case ChoiceRestore:
			prior := pr.LastKnown
			pr.LastKnown = current
			if sErr := j.step("adopted"); sErr != nil {
				pr.LastKnown = prior
				continue
			}
			resolved = true
		}
	}
	return kept, resolved
}

func collect(report *Report, outcome JournalOutcome) {
	report.Restored = append(report.Restored, outcome.Restored...)
	if outcome.JournalPath == "" {
		return
	}
	notes := slices.DeleteFunc(slices.Clone(outcome.Unrecovered), func(note string) bool {
		return slices.ContainsFunc(outcome.HeldMoves, func(h HeldMove) bool { return h.note() == note }) ||
			slices.ContainsFunc(outcome.RetainedDirs, func(dir string) bool {
				return note == dir+": "+errDirHoldsEntries.Error() || note == dir+": "+errDirReplaced.Error()
			})
	})
	report.Retained = append(report.Retained, RetainedJournal{Path: outcome.JournalPath, Notes: notes, Moves: outcome.HeldMoves, Dirs: outcome.RetainedDirs})
}

func holdBackLinkedParents(orphans []*Journal, held map[string]bool, unavailable map[string]string, report *Report) []*Journal {
	propagate := func(blocked func(string) bool, mark func(j *Journal, child string)) {
		for changed := true; changed; {
			changed = false
			for _, j := range orphans {
				if held[j.dirName] || unavailable[j.dirName] != "" {
					continue
				}
				for _, link := range j.rec.Children {
					if blocked(link.Dir) {
						mark(j, link.Dir)
						changed = true
						break
					}
				}
			}
		}
	}
	propagate(func(dir string) bool { return held[dir] }, func(j *Journal, _ string) { held[j.dirName] = true })
	propagate(func(dir string) bool { return unavailable[dir] != "" }, func(j *Journal, child string) { unavailable[j.dirName] = unavailable[child] })

	kept := orphans[:0]
	for _, j := range orphans {
		switch {
		case held[j.dirName]:
			j.Close()
		case unavailable[j.dirName] != "":
			collect(report, j.retain("a linked nested child agent journal is unavailable, so this journal was not recovered: "+unavailable[j.dirName]))
			j.Close()
		default:
			kept = append(kept, j)
		}
	}
	return kept
}

func linkOrphans(orphans []*Journal) {
	byDir := make(map[string]*Journal, len(orphans))
	for _, j := range orphans {
		byDir[j.dirName] = j
	}
	for _, j := range orphans {
		for _, link := range j.rec.Children {
			// A link to a journal no deeper than this one is not a descendant, and a record naming
			// itself would otherwise make a journal its own parent — an absorption of itself.
			child, ok := byDir[link.Dir]
			if !ok || child.rec.Depth <= j.rec.Depth {
				continue
			}
			child.parent = j
			j.children = append(j.children, child)
		}
	}
}

// openJournalFolder descends one component at a time, each opened from the descriptor above it, so no
// component swapped for a symlink can move the pass outside the codemeld home. It creates nothing: a
// launch with no journals must cost no more than the failing open.
func openJournalFolder(home, projectRoot string) (*os.File, string, error) {
	codemeldHome := filepath.Base(filepath.Dir(sessions.SessionRoot(home)))
	components := []string{codemeldHome, journalsDirName, sessions.FolderDirName(projectRoot)}
	folder := filepath.Join(append([]string{home}, components...)...)
	cur, err := openDirNoFollow(home)
	if err != nil {
		return nil, folder, err
	}
	for _, name := range components {
		next, oErr := openSubdirNoFollow(cur, name)
		_ = cur.Close() //nolint:errcheck // read-only intermediate descriptor; the descent holds the next one
		if oErr != nil {
			return nil, folder, oErr
		}
		cur = next
	}
	return cur, folder, nil
}

// loadJournal rebuilds a journal from the record a dead process left behind, bound to the descriptors
// every later write and the final unlink run through. The record is read only once this pass holds the
// journal's lock, and is accepted only from the directory whose identity it names, so a directory
// swapped in at the path cannot present its own record.
func loadJournal(holder *os.File, folder, name, projectRoot string) (*Journal, error) {
	dir, err := openSubdirNoFollow(holder, name)
	if err != nil {
		return nil, err
	}
	lock, err := lockForRecovery(dir)
	if err != nil {
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		return nil, err
	}
	j, err := journalFromDir(holder, dir, folder, name, projectRoot)
	if err != nil {
		_ = dir.Close()      //nolint:errcheck // read-only directory descriptor
		_ = unix.Close(lock) //nolint:errcheck // releasing the lock; there is nothing to retry
		return nil, err
	}
	j.recoveryLock = heldLock{fd: lock, held: true}
	return j, nil
}

// lockForRecovery never creates the lock: a missing one marks a record an earlier codemeld wrote, whose
// run this one cannot show has ended.
func lockForRecovery(dir *os.File) (int, error) {
	fd, err := unix.Openat(int(dir.Fd()), journalLockName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
			err = errors.New("it is not a regular file")
		}
		if err == nil {
			err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		}
		if err == nil {
			return fd, nil
		}
		_ = unix.Close(fd) //nolint:errcheck // the lock was never taken
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		return 0, errJournalHeld
	}
	var st unix.Stat_t
	switch sErr := unix.Fstatat(int(dir.Fd()), journalRecordName, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(sErr, unix.ENOENT):
		return 0, errNoJournalRecord
	case sErr != nil:
		return 0, &os.PathError{Op: "fstatat", Path: journalRecordName, Err: sErr}
	case errors.Is(err, unix.ENOENT):
		return 0, &leftAloneError{reason: "written by an earlier codemeld version that cannot show whether its run has ended"}
	default:
		return 0, &leftAloneError{reason: "its lock could not be checked: " + err.Error()}
	}
}

func journalFromDir(holder, dir *os.File, folder, name, projectRoot string) (*Journal, error) {
	dev, ino, err := descriptorIdentity(dir)
	if err != nil {
		return nil, err
	}
	snap, err := fsutil.SnapshotFileAt(dir, journalRecordName, int64(maxJournalBytes))
	if err != nil {
		return nil, err
	}
	if !snap.Exists {
		return nil, errNoJournalRecord
	}
	var rec journalRecord
	if err := json.Unmarshal(snap.Data, &rec); err != nil {
		return nil, err
	}
	if rec.SchemaVersion < journalSchemaVersion || rec.SchemaVersion > journalAnswerSchemaVersion {
		return nil, fmt.Errorf("subagent: journal schema version %d is not one this codemeld reads", rec.SchemaVersion)
	}
	if err := checkAnswerBindings(&rec); err != nil {
		return nil, err
	}
	if rec.DirDev != dev || rec.DirIno != ino {
		return nil, fmt.Errorf("subagent: %s is no longer the directory the journal was written in", name)
	}
	hold, err := dupDir(holder)
	if err != nil {
		return nil, err
	}
	j := &Journal{
		holder:      hold,
		dir:         dir,
		dirName:     name,
		path:        filepath.Join(folder, name),
		projectRoot: projectRoot,
		rec:         rec,
		index:       make(map[string]int, len(rec.Paths)),
		written:     true,
	}
	for i := range rec.Paths {
		j.index[rec.Paths[i].Path] = i
	}
	return j, nil
}

func checkAnswerBindings(rec *journalRecord) error {
	if rec.SchemaVersion < journalAnswerSchemaVersion && carriesAnswerState(rec) {
		return fmt.Errorf("subagent: a schema %d journal holds move identities or answers", rec.SchemaVersion)
	}
	byID := make(map[moveID]int, len(rec.Moves))
	for i, m := range rec.Moves {
		if m.ID == (moveID{}) {
			continue
		}
		if _, dup := byID[m.ID]; dup || m.ID.Invocation == rec.Invocation && m.ID.Seq > rec.MoveSeq {
			return fmt.Errorf("subagent: the journal's move %s -> %s has an identity that is not its own", m.Source, m.Destination)
		}
		byID[m.ID] = i
	}
	answered := make(map[moveID]bool)
	for _, ans := range rec.Answers {
		if ans.Choice != ChoiceKeep && ans.Choice != ChoiceRestore || len(ans.Members) == 0 {
			return errors.New("subagent: the journal holds a malformed move answer")
		}
		members := make([]int, 0, len(ans.Members))
		for _, id := range ans.Members {
			i, ok := byID[id]
			if !ok || answered[id] {
				return errors.New("subagent: a recorded move answer names a move the journal does not hold exactly once")
			}
			answered[id] = true
			members = append(members, i)
		}
		if !slices.Equal(endpointsOf(rec.Moves, members), ans.Endpoints) {
			return errors.New("subagent: a recorded move answer names endpoints that are not its moves'")
		}
		for _, path := range ans.Endpoints {
			if !slices.ContainsFunc(rec.Paths, func(pr pathRecord) bool { return pr.Path == path }) {
				return fmt.Errorf("subagent: a recorded move answer names %s, which the journal does not hold", path)
			}
		}
		adopted := make([]string, 0, len(ans.Adopted))
		for _, a := range ans.Adopted {
			adopted = append(adopted, a.Path)
		}
		if ans.Choice == ChoiceKeep && len(adopted) > 0 || ans.Choice == ChoiceRestore && !slices.Equal(adopted, ans.Endpoints) {
			return errors.New("subagent: a recorded move answer's adopted states do not match its endpoints")
		}
	}
	return checkAnswersCoverLinks(rec.Moves, rec.Answers)
}

func checkAnswersCoverLinks(moves []moveRecord, answers []groupAnswer) error {
	for _, ans := range answers {
		member := func(m moveRecord) bool { return m.ID != (moveID{}) && slices.Contains(ans.Members, m.ID) }
		for _, m := range moves {
			if !member(m) && slices.ContainsFunc(moves, func(p moveRecord) bool { return member(p) && movesLinked(p.movePair, m.movePair) }) {
				return fmt.Errorf("subagent: a recorded move answer leaves out the linked move %s -> %s", m.Source, m.Destination)
			}
		}
	}
	return nil
}

// dupDir gives each recovered journal a descriptor of its own for the directory it will be unlinked
// from, so closing one journal cannot take the holder out from under the others.
func dupDir(dir *os.File) (*os.File, error) {
	fd, err := unix.Dup(int(dir.Fd()))
	if err != nil {
		return nil, &os.PathError{Op: "dup", Path: dir.Name(), Err: err}
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), dir.Name()), nil
}
