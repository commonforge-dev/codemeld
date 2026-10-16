package subagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/procowner"
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

type Unresolved struct {
	Path string
}

type RetainedJournal struct {
	Path  string
	Notes []string
	Moves []HeldMove
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

var errNoJournalRecord = errors.New("subagent: the journal directory holds no record")

// Recover puts back the declared writes of every child agent whose codemeld process died before it
// could unwind them, for the project folder being opened. A journal whose recorded process cannot be
// proved gone belongs to another possibly running codemeld and is read but never written. ask decides
// the paths that match neither the state the child left nor the state captured before it ran; a nil
// ask defers all of them.
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
	for _, name := range names {
		j, lErr := loadJournal(holder, folder, name, projectRoot)
		switch {
		case errors.Is(lErr, errNoJournalRecord):
			// A live codemeld creates the directory before it writes the record, so an empty one is
			// another process's work in progress rather than a transaction to recover.
			continue
		case lErr != nil:
			report.Retained = append(report.Retained, RetainedJournal{
				Path:  filepath.Join(folder, name),
				Notes: []string{"the child agent journal could not be read: " + lErr.Error()},
			})
			continue
		}
		if procowner.Classify(j.rec.Owner) != procowner.Orphaned {
			report.LeftAlone = append(report.LeftAlone, LeftAloneJournal{
				Path:   j.path,
				Reason: "another codemeld may still be running the child agent that wrote it",
			})
			j.Close()
			continue
		}
		j.resetNotes()
		orphans = append(orphans, j)
	}

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
		if err := j.parent.Absorb(j); err != nil {
			j.parent.retain("a nested child agent's journal could not be absorbed: " + err.Error())
			collect(report, j.retain("its parent could not absorb it: "+err.Error()))
		}
	default:
		j.ReconcilePending()
		outcome := j.rollback()
		if len(outcome.Unrecovered) > 0 && ask != nil {
			kept, resolved := applyChoices(j, ask)
			report.Kept = append(report.Kept, kept...)
			if resolved {
				j.resetNotes()
				second := j.rollback()
				second.Restored = append(outcome.Restored, second.Restored...)
				outcome = second
			}
		}
		if outcome.JournalPath != "" && j.parent != nil {
			j.parent.retain(j.path + ": a nested child agent's journal could not be recovered")
		}
		collect(report, outcome)
	}
}

// applyChoices offers every path still holding a third state and records the answer durably. A kept
// path is what stops an answered path from being offered again at the next launch; a restore adopts
// the state now on disk as the child's, which is what lets the shared rollback protocol replace it.
func applyChoices(j *Journal, ask func(Unresolved) Choice) (kept []string, resolved bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if pr.Progress == rollbackRestored || pr.KeptByUser || j.endpointOf(pr.Path, func(s moveState) bool { return s != moveUndone }) {
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
		return slices.ContainsFunc(outcome.HeldMoves, func(h HeldMove) bool { return h.note() == note })
	})
	report.Retained = append(report.Retained, RetainedJournal{Path: outcome.JournalPath, Notes: notes, Moves: outcome.HeldMoves})
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
// every later write and the final unlink run through. The record is accepted only from the directory
// whose identity it names, so a directory swapped in at the path cannot present its own record.
func loadJournal(holder *os.File, folder, name, projectRoot string) (*Journal, error) {
	dir, err := openSubdirNoFollow(holder, name)
	if err != nil {
		return nil, err
	}
	j, err := journalFromDir(holder, dir, folder, name, projectRoot)
	if err != nil {
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		return nil, err
	}
	return j, nil
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
	if rec.SchemaVersion < journalSchemaVersion || rec.SchemaVersion > journalMoveSchemaVersion {
		return nil, fmt.Errorf("subagent: journal schema version %d is not one this codemeld reads", rec.SchemaVersion)
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
