package subagent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/permissions"
)

// afterRecreateMkdir is the test seam for the window between creating a directory and opening it.
var afterRecreateMkdir = func() {}

// recreateDir records the replacement's identity durably before returning, because the paths declared
// beneath it are reopened only through the directory that identity names.
func (j *Journal) recreateDir(pr *pathRecord, dir *os.File, leaf string) error {
	mode := uint32(pr.Pre.Mode.Perm())
	if err := unix.Mkdirat(int(dir.Fd()), leaf, mode); err != nil {
		return errors.New("the original directory could not be put back: " + err.Error())
	}
	afterRecreateMkdir()
	made, err := openSubdirNoFollow(dir, leaf)
	if err != nil {
		return errors.New("the recreated directory could not be opened: " + err.Error())
	}
	defer made.Close() //nolint:errcheck // read-only directory descriptor
	if err := checkFreshlyMade(made, mode); err != nil {
		return errors.New("the opened directory is not the one the rollback recreated: " + err.Error())
	}
	if err := unix.Fchmod(int(made.Fd()), mode); err != nil {
		return errors.New("the recreated directory's mode could not be applied: " + err.Error())
	}
	if err := syncTargetParent(made); err != nil {
		return errors.New("the recreated directory could not be made durable: " + err.Error())
	}
	if pr.ReplacementDev, pr.ReplacementIno, err = descriptorIdentity(made); err != nil {
		return errors.New("the recreated directory could not be identified: " + err.Error())
	}
	if err := j.step("dir_recreated"); err != nil {
		pr.ReplacementDev, pr.ReplacementIno = 0, 0
		return errors.New("the recreated directory could not be recorded: " + err.Error())
	}
	return nil
}

// checkFreshlyMade stands in for the identity mkdir cannot return: a directory swapped in before the open
// is refused unless it is indistinguishable from one just made — empty, owned by this process, and
// granting nothing beyond the requested mode (the umask or a default ACL may grant less).
func checkFreshlyMade(made *os.File, mode uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(made.Fd()), &st); err != nil {
		return &os.PathError{Op: "fstat", Path: made.Name(), Err: err}
	}
	if int(st.Uid) != os.Geteuid() {
		return errors.New("it is owned by another user")
	}
	if uint32(st.Mode)&0o777&^mode != 0 {
		return errors.New("it grants permissions the original did not")
	}
	names, err := made.Readdirnames(1)
	if len(names) > 0 {
		return errors.New("it already holds entries")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

var errSuffixAbsent = errors.New("subagent: a directory on the way to the declared path is absent")

// openTargetParent reopens the directory the declared path lives in, starting from the captured
// deepest existing ancestor and verifying its identity before descending. Only directories this child
// confirmed creating are walked through: a component that appeared from somewhere else is refused
// rather than treated as part of the child's own chain.
func (j *Journal) openTargetParent(pr *pathRecord) (*os.File, error) {
	return j.openTargetParentAt(pr, pr.Ancestor)
}

func (j *Journal) openTargetParentAt(pr *pathRecord, location string) (*os.File, error) {
	dir, err := j.openAncestorAt(pr, location)
	if err != nil {
		return nil, err
	}
	for i, seg := range pr.Suffix[:len(pr.Suffix)-1] {
		rel := strings.Join(pr.Suffix[:i+1], "/")
		next, oErr := openSubdirNoFollow(dir, seg)
		if oErr != nil {
			_ = dir.Close() //nolint:errcheck // read-only directory descriptor
			if errors.Is(oErr, fs.ErrNotExist) {
				return nil, errSuffixAbsent
			}
			return nil, oErr
		}
		nDev, nIno, iErr := descriptorIdentity(next)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		if iErr != nil || (!j.confirmedDir(nDev, nIno) && !j.movedInAt(filepath.Join(pr.Ancestor, rel), nDev, nIno)) {
			_ = next.Close() //nolint:errcheck // read-only directory descriptor
			return nil, fmt.Errorf("subagent: %s is not the directory the child agent created", rel)
		}
		dir = next
	}
	return dir, nil
}

// movedInAt reports whether dev/ino is the directory a completed, not yet undone, move put at path, so a
// path declared beneath a moved directory can be restored through it before the move is undone.
func (j *Journal) movedInAt(path string, dev, ino uint64) bool {
	for _, m := range j.rec.Moves {
		if m.State != moveCompleted || m.Destination != path {
			continue
		}
		if dst := j.record(path); dst != nil && dst.LastKnown.Kind == kindDir && dst.LastKnown.Dev == dev && dst.LastKnown.Ino == ino {
			return true
		}
	}
	return false
}

// confirmedDir finds the record of a directory this child confirmed on the way to any of its declared
// paths, by the identity that confirmation captured. A confirmation is recorded against the one
// declared path whose create materialized the directory, but declared siblings share ancestors: the
// directory made for made/a.txt is the same directory made/b.txt must be traversed through, so an
// untouched sibling has no record of its own to match. Identity is what the check is really after —
// a component that appeared from somewhere else still matches no confirmation.
func (j *Journal) confirmedDir(dev, ino uint64) bool {
	for i := range j.rec.Paths {
		dirs := j.rec.Paths[i].Dirs
		for k := range dirs {
			if dirs[k].Confirmed && dirs[k].Dev == dev && dirs[k].Ino == ino {
				return true
			}
		}
	}
	return false
}

func (j *Journal) restorePaths(restored []string, include func(path string) bool) []string {
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if pr.Progress == rollbackRestored || pr.KeptByUser || !include(pr.Path) || j.awaitsCreatedDir(pr) || !j.beginOp(pr.Path, []string{pr.Path}) {
			continue
		}
		changed, err := j.restorePath(pr)
		j.endOp()
		if err != nil {
			j.note(pr.Path + ": " + err.Error())
			continue
		}
		if changed && !slices.Contains(restored, pr.Path) {
			restored = append(restored, pr.Path)
		}
	}
	return restored
}

func (j *Journal) changedInsideMovedEntries() (inside, early map[string]bool) {
	inside = j.insideMovedEntries()
	early = make(map[string]bool, len(inside))
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		early[pr.Path] = inside[pr.Path] && (pr.Pending != nil || !sameState(pr.LastKnown, pr.Pre))
	}
	return inside, early
}

func (j *Journal) unrestoredBeneath(early map[string]bool) func(destination string) bool {
	return func(destination string) bool {
		return slices.ContainsFunc(j.rec.Paths, func(pr pathRecord) bool {
			return early[pr.Path] && pr.Progress != rollbackRestored && strings.HasPrefix(pr.Path, destination+string(filepath.Separator))
		})
	}
}

// insideMovedEntries names the declared paths beneath the destination of a move not yet undone. Move
// endpoints are left out: a moved entry goes back whole through its own undo.
func (j *Journal) insideMovedEntries() map[string]bool {
	inside := make(map[string]bool)
	for i := range j.rec.Paths {
		path := j.rec.Paths[i].Path
		endpoint, beneath := false, false
		for _, m := range j.rec.Moves {
			endpoint = endpoint || path == m.Source || path == m.Destination
			beneath = beneath || (m.State != moveUndone && strings.HasPrefix(path, m.Destination+string(filepath.Separator)))
		}
		if beneath && !endpoint {
			inside[path] = true
		}
	}
	return inside
}

// removeCreatedDirs unlinks the directories the child materialized, deepest first, each only while it
// still holds the recorded inode and only while it is empty. A directory holding anything else is
// left in place: its contents are not this transaction's to delete.
func (j *Journal) removeCreatedDirs(include func(owner, dir string) bool) {
	type candidate struct {
		pr  *pathRecord
		dir *dirRecord
	}
	var all []candidate
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		for k := range pr.Dirs {
			path := filepath.Join(pr.Ancestor, filepath.FromSlash(pr.Dirs[k].Rel))
			if !include(pr.Path, path) {
				continue
			}
			if _, cur := j.currentDir(path); cur == &pr.Dirs[k] {
				all = append(all, candidate{pr: pr, dir: &pr.Dirs[k]})
			}
		}
	}
	depth := func(c candidate) int { return strings.Count(filepath.Join(c.pr.Ancestor, c.dir.Rel), "/") }
	sort.SliceStable(all, func(a, b int) bool { return depth(all[a]) > depth(all[b]) })
	for _, c := range all {
		path := filepath.Join(c.pr.Ancestor, filepath.FromSlash(c.dir.Rel))
		if c.dir.Progress == rollbackRestored || c.dir.KeptByUser || !j.beginOp(path, []string{path}) {
			continue
		}
		j.removeCandidate(c.pr, c.dir, path)
		j.endOp()
	}
	_ = j.flush() //nolint:errcheck // every step above already flushed its own transition
}

func (j *Journal) removeCandidate(pr *pathRecord, dr *dirRecord, path string) {
	if dr.Confirmed && !dr.Created {
		dr.Progress = rollbackRestored
		return
	}
	held := j.rec.Completed
	err := errDirUnconfirmed
	if dr.Confirmed {
		err = j.removeCreatedDir(pr, dr)
	}
	switch {
	case err == nil:
		return
	case errors.Is(err, errDirHoldsEntries) || errors.Is(err, errDirReplaced):
		j.note(path + ": " + err.Error())
		held = true
	default:
		j.note(pr.Path + ": " + err.Error())
	}
	if held && !slices.Contains(j.retainedDirs, path) {
		j.retainedDirs = append(j.retainedDirs, path)
	}
}

var (
	errDirUnconfirmed  = errors.New("a parent directory the child agent started to create was never confirmed, so it was left in place")
	errDirHoldsEntries = errors.New("the directory the child agent created holds entries it did not create, so it was left in place")
	errDirReplaced     = errors.New("another writer replaced the directory the child agent created, so it was left in place")
)

func (j *Journal) removeCreatedDir(pr *pathRecord, dr *dirRecord) error {
	if dr.KeptByUser {
		return nil
	}
	segs := strings.Split(dr.Rel, "/")
	path := filepath.Join(pr.Ancestor, filepath.FromSlash(dr.Rel))
	if r := j.record(path); r != nil && r.Mkdir && r.KeptByUser {
		dr.Progress = rollbackRestored
		return j.step("dir_restored")
	}
	dir, err := j.openDirChain(pr, segs[:len(segs)-1])
	if err != nil {
		if errors.Is(err, errSuffixAbsent) {
			return j.settleCreatedDir(path, dr, true)
		}
		return errors.New("the created directory's parent could not be safely reopened: " + err.Error())
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor

	name := segs[len(segs)-1]
	dev, ino, iErr := entryIdentity(dir, name)
	if errors.Is(iErr, fs.ErrNotExist) {
		// An absent directory under `dir_restoring` is this transaction's own unlink resumed, so it
		// owes the same parent sync the interrupted pass could not complete.
		if dr.Progress == rollbackRestoring {
			if sErr := syncTargetParent(dir); sErr != nil {
				return errors.New("the removed directory entry could not be made durable: " + sErr.Error())
			}
		}
		return j.settleCreatedDir(path, dr, true)
	}
	if iErr != nil {
		return errors.New("the created directory could not be identified: " + iErr.Error())
	}
	if dev != dr.Dev || ino != dr.Ino {
		if !dr.Mkdir {
			return errors.New("another writer replaced the created directory " + dr.Rel)
		}
		if !j.holdsRecordedState(path, dir, name) {
			return errDirReplaced
		}
		dr.Progress = rollbackRestored
		return j.step("dir_restored")
	}
	empty, eErr := dirIsEmpty(dir, name)
	if eErr != nil {
		return errors.New("the created directory could not be read: " + eErr.Error())
	}
	if !empty {
		if dr.Mkdir || j.rec.Completed {
			return errDirHoldsEntries
		}
		return j.settleCreatedDir(path, dr, false)
	}

	dr.Progress = rollbackRestoring
	if err := j.step("dir_restoring"); err != nil {
		return errors.New("the directory rollback could not be recorded before it began: " + err.Error())
	}
	if uErr := unix.Unlinkat(int(dir.Fd()), name, unix.AT_REMOVEDIR); uErr != nil {
		return errors.New("the created directory could not be removed: " + uErr.Error())
	}
	if parentMoved(dir, func() (*os.File, error) { return j.openDirChain(pr, segs[:len(segs)-1]) }) {
		return errParentMoved
	}
	if sErr := syncTargetParent(dir); sErr != nil {
		return errors.New("the removed directory entry could not be made durable: " + sErr.Error())
	}
	return j.settleCreatedDir(path, dr, true)
}

func (j *Journal) settleCreatedDir(path string, dr *dirRecord, removed bool) error {
	dr.Progress = rollbackRestored
	for i := range j.rec.Paths {
		r := &j.rec.Paths[i]
		switch {
		case !r.Mkdir || r.Path != path:
		case !removed:
			r.Progress = rollbackRestored
		case r.LastKnown.Kind == kindDir && r.LastKnown.Dev == dr.Dev && r.LastKnown.Ino == dr.Ino:
			r.LastKnown = fileState{}
		}
	}
	return j.step("dir_restored")
}

// A created directory's slot that holds the path's snapshotted entry (put back by an undone move) or the
// state the journal last recorded there (a third state the user adopted for a delete or move form) was
// emptied by a journalled act or an answer, not by a replacement.
func (j *Journal) holdsRecordedState(path string, dir *os.File, name string) bool {
	r := j.record(path)
	if r == nil || !r.Mkdir {
		return false
	}
	current, err := readEntryState(dir, name)
	return err == nil && current.Exists && (sameState(current, r.Pre) || sameState(current, r.LastKnown))
}

var errParentMoved = errors.New("a parent directory was moved while the rollback acted through it, so the result is not at the path it was recorded for")

// parentMoved reports whether a rollback act through held may have landed outside the project: a held
// descriptor follows its directory wherever it is renamed, so only a fresh descent from the project root
// reaching the same directory confirms the act happened at the recorded path.
func parentMoved(held *os.File, reopen func() (*os.File, error)) bool {
	fresh, err := reopen()
	if err != nil {
		return true
	}
	defer fresh.Close() //nolint:errcheck // read-only directory descriptor
	hDev, hIno, hErr := descriptorIdentity(held)
	fDev, fIno, fErr := descriptorIdentity(fresh)
	return hErr != nil || fErr != nil || hDev != fDev || hIno != fIno
}

// An ancestor gone because the child deleted a declared directory at or above it is an absent suffix:
// nothing beneath it can exist either. The ancestor is reached from the project root rather than by its
// recorded pathname, which would follow an intermediate symlink to a directory that still carries the
// recorded identity outside the project.
func (j *Journal) openAncestor(pr *pathRecord) (*os.File, error) {
	return j.openAncestorAt(pr, pr.Ancestor)
}

func (j *Journal) openAncestorAt(pr *pathRecord, location string) (*os.File, error) {
	rel, err := filepath.Rel(j.projectRoot, location)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("subagent: %s is not inside the project directory %s", location, j.projectRoot)
	}
	dir, err := openDirNoFollow(j.projectRoot)
	if err != nil {
		return nil, err
	}
	if rel != "." {
		for _, seg := range strings.Split(rel, string(filepath.Separator)) {
			next, oErr := openSubdirNoFollow(dir, seg)
			_ = dir.Close() //nolint:errcheck // read-only intermediate descriptor; the descent holds the next one
			if oErr != nil {
				if errors.Is(oErr, fs.ErrNotExist) && j.deletedByChild(pr.Ancestor) {
					return nil, errSuffixAbsent
				}
				return nil, oErr
			}
			dir = next
		}
	}
	dev, ino, err := descriptorIdentity(dir)
	if err != nil {
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		return nil, err
	}
	if (dev != pr.ParentDev || ino != pr.ParentIno) && !j.recreatedAt(pr.Ancestor, dev, ino) && j.createdDirAt(pr.Ancestor, func(d dirRecord) bool {
		return d.Mkdir && d.Dev == dev && d.Ino == ino
	}) == nil {
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		return nil, fmt.Errorf("subagent: %s is no longer the directory that was snapshotted", pr.Ancestor)
	}
	return dir, nil
}

func (j *Journal) deletedByChild(path string) bool {
	for i := range j.rec.Paths {
		p := &j.rec.Paths[i]
		if p.Delete && p.Pre.Kind == kindDir && !p.LastKnown.Exists && permissions.IsDescendantOrEqual(path, p.Path) {
			return true
		}
	}
	return false
}

func (j *Journal) recreatedAt(path string, dev, ino uint64) bool {
	for i := range j.rec.Paths {
		p := &j.rec.Paths[i]
		if p.Path == path && p.ReplacementIno != 0 && p.ReplacementDev == dev && p.ReplacementIno == ino {
			return true
		}
	}
	return false
}

func (j *Journal) openDirChain(pr *pathRecord, segs []string) (*os.File, error) {
	dir, err := j.openAncestor(pr)
	if err != nil {
		return nil, err
	}
	for i, seg := range segs {
		rel := strings.Join(segs[:i+1], "/")
		next, oErr := openSubdirNoFollow(dir, seg)
		if oErr != nil {
			_ = dir.Close() //nolint:errcheck // read-only directory descriptor
			if errors.Is(oErr, fs.ErrNotExist) {
				return nil, errSuffixAbsent
			}
			return nil, oErr
		}
		nDev, nIno, iErr := descriptorIdentity(next)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		if iErr != nil || (!j.confirmedDir(nDev, nIno) && !j.movedInAt(filepath.Join(pr.Ancestor, rel), nDev, nIno)) {
			_ = next.Close() //nolint:errcheck // read-only directory descriptor
			return nil, fmt.Errorf("subagent: %s is not the directory the child agent created", rel)
		}
		dir = next
	}
	return dir, nil
}

func dirIsEmpty(parent *os.File, name string) (bool, error) {
	dir, err := openSubdirNoFollow(parent, name)
	if err != nil {
		return false, err
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor
	names, rErr := dir.Readdirnames(1)
	if rErr != nil && !errors.Is(rErr, io.EOF) {
		return false, rErr
	}
	return len(names) == 0, nil
}

func statEntry(parent *os.File, name string) (os.FileInfo, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close() //nolint:errcheck // read-only descriptor opened only to read the entry's identity
	return f.Stat()
}

// remove deletes the journal after its terminal state is durable, through the retained descriptors, so
// a directory swapped in at the path cannot make cleanup unlink something else. The record goes
// through the descriptor holding the journal directory itself, which no rename can redirect. The
// directory's own removal cannot: it is an unlink of a name in the holder above it, resolved at the
// instant the kernel reads it. So that name is checked against the identity recorded at creation, and
// a name that leads anywhere else is left alone — removing it would delete a stranger's directory and
// still leave this one behind. The journal is done either way: everything it owns is gone, and what
// survives is an empty directory answering to no record.
func (j *Journal) remove() error {
	if j.gone {
		return nil
	}
	if j.gate != nil && !j.gate.allows() {
		return errRecoveryStopped
	}
	dev, ino, iErr := entryIdentity(j.holder, j.dirName)
	if iErr != nil && !errors.Is(iErr, fs.ErrNotExist) {
		return iErr
	}
	stillOurs := iErr == nil && dev == j.rec.DirDev && ino == j.rec.DirIno
	if j.written {
		if err := unix.Unlinkat(int(j.dir.Fd()), journalRecordName, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	j.recordUnlinked = true
	if err := unix.Unlinkat(int(j.dir.Fd()), journalLockName, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := j.dir.Sync(); err != nil {
		return err
	}
	if stillOurs {
		if err := unix.Unlinkat(int(j.holder.Fd()), j.dirName, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := j.holder.Sync(); err != nil {
		return err
	}
	j.gone = true
	j.writerLock.close()
	return nil
}

func (j *Journal) removeStorage() {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.remove() //nolint:errcheck // the journal never became usable; nothing depends on the cleanup
}

func fromToolState(s filetools.JournalState) fileState {
	return fileState{Exists: s.Exists, Data: s.Data, Mode: s.Mode, Dev: s.Dev, Ino: s.Ino}
}

// sameState compares two observations of one path. Identity is compared only when both sides know it,
// because a pending record is written before publication and so cannot name the inode it will create.
func sameState(a, b fileState) bool {
	if !sameContent(a, b) {
		return false
	}
	if a.Exists && a.Ino != 0 && b.Ino != 0 {
		return a.Dev == b.Dev && a.Ino == b.Ino
	}
	return true
}

func sameContent(a, b fileState) bool {
	if a.Exists != b.Exists {
		return false
	}
	if !a.Exists {
		return true
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case kindSymlink:
		return a.Link == b.Link
	case kindDir:
		return a.Mode.Perm() == b.Mode.Perm()
	default:
		return bytes.Equal(a.Data, b.Data) && a.Mode.Perm() == b.Mode.Perm()
	}
}
