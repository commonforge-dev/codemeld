package subagent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
)

type moveUndoAct int

const (
	undoRename moveUndoAct = iota
	undoRenamed
	undoSettle
	undoSkip
)

// planMoveUndo must stay the only undo decision: preflight passes it projected states, so an undo that
// decided on its own could start an act its group's preflight never checked.
func planMoveUndo(m *moveRecord, src, dst *pathRecord, srcLast, dstLast, source, destination fileState) (act moveUndoAct, clear bool, err error) {
	undoing := m.State == moveUndoing
	switch {
	case undoing && dstLast.Exists && !destination.Exists && sameState(source, dstLast):
		return undoRenamed, false, nil
	case sameState(source, src.Pre) && sameState(destination, dst.Pre):
		return undoSettle, false, nil
	case !dstLast.Exists && !destination.Exists && sameState(source, srcLast):
		// A later journalled delete of the destination already took the moved entry, so there is nothing to
		// rename back and the source is left to its snapshot restore.
		return undoSkip, false, nil
	case destination.Exists && sameState(destination, dstLast):
		if !source.Exists && (undoing || !srcLast.Exists) {
			return undoRename, false, nil
		}
		if source.Exists && srcLast.Ino != 0 && sameState(source, srcLast) {
			return undoRename, true, nil
		}
	}
	return undoRename, false, errors.New("an endpoint was changed outside the child agent's journalled writes, so the move cannot be undone")
}

func (j *Journal) moveEndpoints(m *moveRecord) (src, dst *pathRecord, err error) {
	if m.State == movePending {
		return nil, nil, errors.New("a move the child agent started was never resolved")
	}
	src, dst = j.record(m.Source), j.record(m.Destination)
	if src == nil || dst == nil {
		return nil, nil, errors.New("the move names a path this journal does not hold")
	}
	return src, dst, nil
}

type projectedEntry struct {
	state fileState
	pr    *pathRecord
	at    string
}

// preflightUndo runs a group's undo newest move first without touching an endpoint. Each simulated
// rename is carried into the older moves' checks: the endpoints it would swap take their projected
// states, and a path beneath the entry it would carry home is read where that entry still is.
// A non-nil adopt takes each endpoint's first reading, made before any simulated rename moved something
// onto it, as its last-known state, once that reading shows a moved directory still where the child
// left it.
func (j *Journal) preflightUndo(members []int, adopt map[string]fileState, restore []*pathRecord) (failed int, err error) {
	entries := make(map[string]projectedEntry)
	last := make(map[string]fileState)
	var renames []movePair
	read := func(pr *pathRecord) (projectedEntry, error) {
		if e, ok := entries[pr.Path]; ok {
			return e, nil
		}
		at := relocate(pr.Ancestor, renames)
		dir, err := j.openTargetParentAt(pr, at)
		if err != nil {
			return projectedEntry{}, errors.New("the parent directory of " + pr.Path + " could not be safely reopened: " + err.Error())
		}
		defer dir.Close() //nolint:errcheck // read-only directory descriptor
		state, err := readEntryState(dir, filepath.Base(pr.Path))
		if err != nil {
			return projectedEntry{}, errors.New("the endpoints could not be read: " + err.Error())
		}
		if _, seen := adopt[pr.Path]; adopt != nil && !seen {
			adopt[pr.Path], last[pr.Path] = state, state
		}
		return projectedEntry{state: state, pr: pr, at: at}, nil
	}
	lastKnown := func(pr *pathRecord) fileState {
		if state, ok := last[pr.Path]; ok {
			return state
		}
		return pr.LastKnown
	}
	for k := len(members) - 1; k >= 0; k-- {
		m := &j.rec.Moves[members[k]]
		src, dst, err := j.moveEndpoints(m)
		if err != nil {
			return members[k], err
		}
		source, err := read(src)
		if err != nil {
			return members[k], err
		}
		_, seen := adopt[dst.Path]
		destination, err := read(dst)
		if err != nil {
			return members[k], err
		}
		srcLast, dstLast := lastKnown(src), lastKnown(dst)
		if adopt != nil {
			proof := dstLast
			if !seen {
				proof = dst.LastKnown
			}
			switch {
			case !proof.Exists || dst.Delete:
				return members[k], errors.New("what the child agent moved to " + dst.Path + " may have been deleted or replaced later, so it cannot be proven that a moved directory is still intact")
			case !seen && proof.Kind == kindDir && (destination.state.Kind != kindDir || destination.state.Dev != proof.Dev || destination.state.Ino != proof.Ino):
				return members[k], errors.New("the directory the child agent moved to " + dst.Path + " was deleted or replaced, so its contents cannot be restored")
			}
		}
		act, clear, err := planMoveUndo(m, src, dst, srcLast, dstLast, source.state, destination.state)
		if err != nil {
			return members[k], err
		}
		switch act {
		case undoSettle:
			last[src.Path], last[dst.Path] = source.state, destination.state
		case undoRenamed:
			last[src.Path], last[dst.Path] = dstLast, fileState{}
		case undoRename:
			if clear && source.state.Kind == kindDir {
				if err := j.clearableDir(source); err != nil {
					return members[k], err
				}
			}
			entries[src.Path], entries[dst.Path] = destination, projectedEntry{}
			last[src.Path], last[dst.Path] = dstLast, fileState{}
			renames = append([]movePair{m.movePair}, renames...)
		}
	}
	for _, pr := range restore {
		e, err := read(pr)
		if err == nil {
			err = j.restorable(pr, e, lastKnown(pr))
		}
		if err != nil {
			return -1, err
		}
	}
	return -1, nil
}

// restorable mirrors restorePath's choice of act for the entry the undo would leave at pr.
func (j *Journal) restorable(pr *pathRecord, e projectedEntry, last fileState) error {
	switch current := e.state; {
	case sameContent(current, pr.Pre) && sameState(current, last):
		return nil
	case !sameState(current, last):
		return errors.New(pr.Path + ": it was changed outside the child agent's journalled writes")
	case !current.Exists || current.Kind != kindDir:
		return nil
	}
	dir, err := j.openTargetParentAt(e.pr, e.at)
	if err != nil {
		return errors.New("the parent directory of " + pr.Path + " could not be safely reopened: " + err.Error())
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor
	empty, err := dirIsEmpty(dir, filepath.Base(e.pr.Path))
	switch {
	case err != nil:
		return errors.New("the directory that would be back at " + pr.Path + " could not be read: " + err.Error())
	case !empty:
		return errors.New("the directory that would be back at " + pr.Path + " holds entries, so it cannot be removed to put the path back")
	}
	return nil
}

func (j *Journal) clearableDir(e projectedEntry) error {
	dir, err := j.openTargetParentAt(e.pr, e.at)
	if err != nil {
		return errors.New("the source's parent directory could not be safely reopened: " + err.Error())
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor
	empty, err := dirIsEmpty(dir, filepath.Base(e.pr.Path))
	switch {
	case err != nil:
		return errors.New("the directory the child agent left at the source could not be read: " + err.Error())
	case !empty:
		return errors.New("the directory the child agent left at the source now holds entries, so it cannot be removed to undo the move")
	}
	return nil
}

// relocate maps a path named before renames happened to where it is now, applying them oldest first.
func relocate(path string, renames []movePair) string {
	for _, r := range renames {
		if permissions.IsDescendantOrEqual(path, r.Source) {
			path = r.Destination + strings.TrimPrefix(path, r.Source)
		}
	}
	return path
}

func (j *Journal) undoMove(m *moveRecord) (changed bool, err error) {
	src, dst, err := j.moveEndpoints(m)
	if err != nil {
		return false, err
	}
	srcDir, err := j.openTargetParent(src)
	if err != nil {
		return false, errors.New("the source's parent directory could not be safely reopened: " + err.Error())
	}
	defer srcDir.Close() //nolint:errcheck // read-only directory descriptor
	dstDir, err := j.openTargetParent(dst)
	if err != nil {
		return false, errors.New("the destination's parent directory could not be safely reopened: " + err.Error())
	}
	defer dstDir.Close() //nolint:errcheck // read-only directory descriptor

	source, serr := readEntryState(srcDir, filepath.Base(m.Source))
	destination, derr := readEntryState(dstDir, filepath.Base(m.Destination))
	if err := errors.Join(serr, derr); err != nil {
		return false, errors.New("the endpoints could not be read: " + err.Error())
	}
	act, clear, err := planMoveUndo(m, src, dst, src.LastKnown, dst.LastKnown, source, destination)
	if err != nil {
		return false, err
	}
	priorState, priorSrc, priorDst := m.State, src.LastKnown, dst.LastKnown
	if act == undoSettle || act == undoSkip {
		if act == undoSettle {
			src.LastKnown, dst.LastKnown = source, destination
		}
		m.State = moveUndone
		if err := j.step("move_undone"); err != nil {
			m.State, src.LastKnown, dst.LastKnown = priorState, priorSrc, priorDst
			return false, errors.New("the undone move could not be recorded: " + err.Error())
		}
		return act == undoSkip, nil
	}
	if act == undoRename {
		if m.State != moveUndoing {
			m.State = moveUndoing
			if err := j.step("move_undoing"); err != nil {
				return false, errors.New("the undo could not be recorded before it began: " + err.Error())
			}
		}
		if clear {
			if err := removeEntry(srcDir, filepath.Base(m.Source), src.LastKnown); err != nil {
				return false, err
			}
			if parentMoved(srcDir, func() (*os.File, error) { return j.openTargetParent(src) }) {
				return false, errParentMoved
			}
		}
		// An absent source the child last left in place was cleared by an earlier pass that may have
		// stopped before its unlink became durable.
		if clear || (!source.Exists && src.LastKnown.Exists) {
			if err := syncTargetParent(srcDir); err != nil {
				return false, errors.New("the cleared source could not be made durable: " + err.Error())
			}
		}
		if err := fsutil.RenameNoReplaceAt(dstDir, filepath.Base(m.Destination), srcDir, filepath.Base(m.Source)); err != nil {
			return false, errors.New("the moved entry could not be put back: " + err.Error())
		}
		if parentMoved(srcDir, func() (*os.File, error) { return j.openTargetParent(src) }) || parentMoved(dstDir, func() (*os.File, error) { return j.openTargetParent(dst) }) {
			if err := fsutil.RenameNoReplaceAt(srcDir, filepath.Base(m.Source), dstDir, filepath.Base(m.Destination)); err != nil {
				return false, errors.New(errParentMoved.Error() + ", and the undo could not be reversed: " + err.Error())
			}
			return false, errParentMoved
		}
	}
	if err := syncTargetParent(dstDir); err != nil {
		return false, errors.New("the undone move could not be made durable: " + err.Error())
	}
	if err := syncTargetParent(srcDir); err != nil {
		return false, errors.New("the undone move could not be made durable: " + err.Error())
	}
	src.LastKnown, dst.LastKnown = dst.LastKnown, fileState{}
	m.State = moveUndone
	if err := j.step("move_undone"); err != nil {
		m.State, src.LastKnown, dst.LastKnown = moveUndoing, priorSrc, priorDst
		return false, errors.New("the undone move could not be recorded: " + err.Error())
	}
	return true, nil
}

// restorePath puts one declared path back as its captured kind. The three-state progress is written
// around the filesystem act, not after it, so a crash on either side of the act resumes: a resumed
// restore accepts either the state the child left or the captured pre-state as a valid starting point.
func (j *Journal) restorePath(pr *pathRecord) (changed bool, err error) {
	dir, err := j.openTargetParent(pr)
	if err != nil {
		if errors.Is(err, errSuffixAbsent) {
			if pr.Pre.Exists || pr.LastKnown.Exists {
				return false, errors.New("the directories holding it are gone, so it cannot be put back")
			}
			pr.Progress = rollbackRestored
			return false, j.step("restored")
		}
		return false, errors.New("the target's parent directory could not be safely reopened: " + err.Error())
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor

	current, cerr := j.currentState(pr, dir)
	if cerr != nil {
		return false, errors.New("the current state could not be read: " + cerr.Error())
	}
	// A restore publishes a new inode, so a resumed pass accepts the pre-run state only under the identity
	// an earlier pass durably recorded publishing; a same-content entry under any other identity is a
	// third party's, and an act whose identity never became durable cannot be told apart from one.
	resumed := pr.Progress == rollbackRestoring
	published := resumed && pr.ReplacementIno != 0 && current.Dev == pr.ReplacementDev && current.Ino == pr.ReplacementIno
	if sameContent(current, pr.Pre) && (published || sameState(current, pr.LastKnown) || resumed && !current.Exists) {
		// Reaching the pre-run state from `restoring` means an earlier pass performed the act but
		// never proved its directory entry durable, so the fsync that pass owed is retried here. The
		// bytes alone cannot stand in for it: a namespace change the filesystem can still lose would
		// otherwise be recorded as finished.
		if resumed {
			if sErr := syncTargetParent(dir); sErr != nil {
				return false, errors.New("the restored directory entry could not be made durable: " + sErr.Error())
			}
		}
		pr.Progress = rollbackRestored
		return false, j.step("restored")
	}
	// A delete-declared path whose entry kind changed is put back by removing the entry and then
	// recreating the pre-state, so a pass interrupted between the two acts leaves the slot empty.
	resumedEmpty := pr.anyKind() && resumed && !current.Exists
	if !resumedEmpty && !sameState(current, pr.LastKnown) {
		return false, errors.New("it was changed outside the child agent's journalled writes")
	}

	pr.Progress = rollbackRestoring
	if err := j.step("restoring"); err != nil {
		return false, errors.New("the rollback could not be recorded before it began: " + err.Error())
	}
	if err := j.putBack(pr, dir, current); err != nil {
		return false, err
	}
	if parentMoved(dir, func() (*os.File, error) { return j.openTargetParent(pr) }) {
		return false, errParentMoved
	}
	// The namespace change has to be durable before the record says so, or a resumed rollback would
	// read a restore that the filesystem can still lose as finished.
	if sErr := syncTargetParent(dir); sErr != nil {
		return false, errors.New("the restored directory entry could not be made durable: " + sErr.Error())
	}
	pr.Progress = rollbackRestored
	if err := j.step("restored"); err != nil {
		return true, errors.New("the completed rollback could not be recorded: " + err.Error())
	}
	return true, nil
}

func (j *Journal) putBack(pr *pathRecord, dir *os.File, current fileState) error {
	leaf := filepath.Base(pr.Path)
	if pr.Pre.Exists && pr.Pre.Kind == "" && current.Exists && current.Kind == "" {
		planned, sErr := statEntry(dir, leaf)
		if sErr != nil {
			return errors.New("the file to restore could not be identified: " + sErr.Error())
		}
		_, _, published, wErr := fsutil.WriteAtomicReplaceAt(dir, leaf, pr.Pre.Data, pr.Pre.Mode, planned, nil)
		if published == nil {
			return errors.New("the original contents could not be put back: " + wErr.Error())
		}
		return j.recordPublished(pr, published)
	}
	if current.Exists {
		if err := removeEntry(dir, leaf, current); err != nil {
			return err
		}
	}
	if !pr.Pre.Exists {
		return nil
	}
	switch pr.Pre.Kind {
	case kindSymlink:
		if err := unix.Symlinkat(pr.Pre.Link, int(dir.Fd()), leaf); err != nil {
			return errors.New("the original symlink could not be put back: " + err.Error())
		}
		made, err := readEntryState(dir, leaf)
		if err != nil {
			return errors.New("the restored symlink could not be identified: " + err.Error())
		}
		if !sameContent(made, pr.Pre) {
			return errors.New("another writer replaced the restored symlink before it could be recorded")
		}
		return j.recordRestored(pr, made.Dev, made.Ino)
	case kindDir:
		return j.recreateDir(pr, dir, leaf)
	default:
		// A create whose own parent sync failed may already have unlinked what it published, so only a
		// clean return names an entry this journal can claim.
		_, _, published, wErr := fsutil.WriteAtomicCreateAt(dir, leaf, pr.Pre.Data, pr.Pre.Mode)
		if wErr != nil {
			return errors.New("the original contents could not be put back: " + wErr.Error())
		}
		return j.recordPublished(pr, published)
	}
}

func (j *Journal) recordPublished(pr *pathRecord, published os.FileInfo) error {
	st, ok := published.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the restored file could not be identified")
	}
	return j.recordRestored(pr, uint64(st.Dev), uint64(st.Ino))
}

func (j *Journal) recordRestored(pr *pathRecord, dev, ino uint64) error {
	pr.ReplacementDev, pr.ReplacementIno = dev, ino
	if err := j.step("restore_published"); err != nil {
		pr.ReplacementDev, pr.ReplacementIno = 0, 0
		return errors.New("the restored entry could not be recorded: " + err.Error())
	}
	return nil
}

func removeEntry(dir *os.File, leaf string, current fileState) error {
	dev, ino, iErr := entryIdentity(dir, leaf)
	switch {
	case errors.Is(iErr, fs.ErrNotExist):
		return nil
	case iErr != nil:
		return errors.New("the created file could not be identified: " + iErr.Error())
	case dev != current.Dev || ino != current.Ino:
		return errors.New("another writer replaced the created file before it could be removed")
	}
	flag := 0
	if current.Kind == kindDir {
		flag = unix.AT_REMOVEDIR
	}
	if uErr := unix.Unlinkat(int(dir.Fd()), leaf, flag); uErr != nil {
		return errors.New("the created file could not be removed: " + uErr.Error())
	}
	return nil
}
