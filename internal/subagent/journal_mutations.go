package subagent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/fsutil"
)

func (j *Journal) BeginMutation(target string, observed, next filetools.JournalState) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil {
		return nil
	}
	if int64(len(next.Data)) > maxStateBytesPerPath {
		return fmt.Errorf("subagent: %s would hold %d bytes, over the %d-byte limit a child agent journal records for one path", target, len(next.Data), int64(maxStateBytesPerPath))
	}
	if !sameState(fromToolState(observed), pr.LastKnown) {
		return fmt.Errorf("subagent: %s changed outside the child agent since it was snapshotted", target)
	}
	pr.Pending = &pendingMutation{State: fromToolState(next), NeedsParentSync: true}
	if err := j.step("pending"); err != nil {
		pr.Pending = nil
		return err
	}
	return nil
}

func (j *Journal) BeginDelete(target string, parentDir *os.File) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil {
		return nil
	}
	if !pr.Delete {
		return fmt.Errorf("subagent: %s is not a declared delete path, so its removal cannot be rolled back", target)
	}
	current, err := readEntryState(parentDir, filepath.Base(target))
	if err != nil {
		return fmt.Errorf("subagent: cannot read %s before deleting it: %w", target, err)
	}
	if !sameState(current, pr.LastKnown) {
		return fmt.Errorf("subagent: %s changed outside the child agent since it was snapshotted", target)
	}
	pr.Pending = &pendingMutation{NeedsParentSync: true}
	if err := j.step("pending"); err != nil {
		pr.Pending = nil
		return err
	}
	return nil
}

// ResolveMutation settles the pending record against what the publish actually left. published names
// the inode the caller put at the path, or is the zero value when it has none to name. A pending
// record is written before publication and so cannot name the inode it will create; adopting the
// caller's is what keeps a byte-identical file another writer put at the name in the publish-to-
// reconcile window from being read as this child's own work. Recovery, which arrives after a crash
// with no such identity to offer, still falls back to comparing content alone.
func (j *Journal) ResolveMutation(target string, parentDir *os.File, published filetools.JournalState) {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil || pr.Pending == nil {
		return
	}
	if published.Ino != 0 {
		pr.Pending.State.Dev, pr.Pending.State.Ino = published.Dev, published.Ino
	}
	j.reconcile(pr, parentDir)
}

// AbandonMutation resolves a pending record whose publication never happened. The pending state is
// then a state no one published, so a file holding it is another writer's — content equality cannot
// stand in for ownership here the way it can after a real publish, and absorbing it would let the
// rollback restore over, or remove, a file this child never wrote. Only the durable last-known state
// clears the record; anything else is reported rather than claimed.
func (j *Journal) AbandonMutation(target string, parentDir *os.File) {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil || pr.Pending == nil {
		return
	}
	// The pending state is dropped rather than compared against, and dropped first: no namespace
	// change was published, so there is none to make durable, and a record left pending would be
	// reconciled later by the terminal pass or by recovery — both of which read pending bytes as the
	// child's own work.
	pr.Pending = nil
	if err := j.step("reconciled"); err != nil {
		j.note(pr.Path + ": the resolved state could not be recorded: " + err.Error())
	}
	current, err := j.currentState(pr, parentDir)
	switch {
	case err != nil:
		j.markUnrecovered(pr, "the current state could not be read: "+err.Error())
	case !sameState(current, pr.LastKnown):
		j.markUnrecovered(pr, "it was changed outside the child agent's journalled writes while a refused write was outstanding")
	}
}

func (j *Journal) MoveLifecycle(source, destination string) fsutil.MoveLifecycle {
	pair := movePair{Source: source, Destination: destination}
	return fsutil.MoveLifecycle{
		BeforeRename: func(sourceParent, destinationParent *os.File) error {
			return j.beginMove(pair, sourceParent, destinationParent)
		},
		AfterRename: func(sourceParent, destinationParent *os.File) {
			j.resolveMove(pair, sourceParent, destinationParent)
		},
	}
}

// A rename keeps the inode, so the destination's pending state carries the source's identity.
func (j *Journal) beginMove(pair movePair, sourceParent, destinationParent *os.File) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !slices.Contains(j.rec.MovePairs, pair) {
		return fmt.Errorf("subagent: %s -> %s is not a declared move pair, so the move cannot be rolled back", pair.Source, pair.Destination)
	}
	src, dst := j.record(pair.Source), j.record(pair.Destination)
	if src.Pending != nil || dst.Pending != nil {
		return fmt.Errorf("subagent: %s -> %s has an earlier change to an endpoint that was never resolved", pair.Source, pair.Destination)
	}
	source, err := readEntryState(sourceParent, filepath.Base(pair.Source))
	if err != nil {
		return fmt.Errorf("subagent: cannot read %s before moving it: %w", pair.Source, err)
	}
	destination, err := readEntryState(destinationParent, filepath.Base(pair.Destination))
	if err != nil {
		return fmt.Errorf("subagent: cannot read %s before moving onto it: %w", pair.Destination, err)
	}
	if !sameState(source, src.LastKnown) || !sameState(destination, dst.LastKnown) {
		return fmt.Errorf("subagent: %s -> %s changed outside the child agent since it was snapshotted", pair.Source, pair.Destination)
	}
	src.Pending = &pendingMutation{NeedsParentSync: true}
	dst.Pending = &pendingMutation{State: source, NeedsParentSync: true}
	j.rec.Moves = append(j.rec.Moves, moveRecord{movePair: pair, State: movePending, ID: j.newMoveID()})
	if err := j.step("move_pending"); err != nil {
		src.Pending, dst.Pending = nil, nil
		j.rec.Moves = j.rec.Moves[:len(j.rec.Moves)-1]
		return err
	}
	return nil
}

func (j *Journal) resolveMove(pair movePair, sourceParent, destinationParent *os.File) {
	j.mu.Lock()
	defer j.mu.Unlock()
	i := slices.IndexFunc(j.rec.Moves, func(m moveRecord) bool { return m.movePair == pair && m.State == movePending })
	if i < 0 {
		return
	}
	j.reconcileMove(i, sourceParent, destinationParent)
}

// A pending move this cannot resolve is left pending without a note of its own: the rollback holds it
// and reports it as a move, which is the only report that does not promise a question about its paths.
func (j *Journal) reconcilePendingMove(i int) {
	m := j.rec.Moves[i]
	src, dst := j.record(m.Source), j.record(m.Destination)
	if src == nil || dst == nil {
		return
	}
	srcDir, err := j.openTargetParent(src)
	if err != nil {
		return
	}
	defer srcDir.Close() //nolint:errcheck // read-only directory descriptor
	dstDir, err := j.openTargetParent(dst)
	if err != nil {
		return
	}
	defer dstDir.Close() //nolint:errcheck // read-only directory descriptor
	j.reconcileMove(i, srcDir, dstDir)
}

// reconcileMove settles a pending move from both endpoints together: either endpoint read alone can
// match a move that never happened just as well as one whose other endpoint was changed from outside.
func (j *Journal) reconcileMove(i int, sourceParent, destinationParent *os.File) {
	m := j.rec.Moves[i]
	src, dst := j.record(m.Source), j.record(m.Destination)
	for _, end := range []struct {
		pr  *pathRecord
		dir *os.File
	}{{src, sourceParent}, {dst, destinationParent}} {
		if end.pr.Pending == nil || !end.pr.Pending.NeedsParentSync {
			continue
		}
		if err := syncTargetParent(end.dir); err != nil {
			reason := "the target's parent directory could not be made durable: " + err.Error()
			j.retainDurable(end.pr.Path + ": " + reason)
			j.markUnrecovered(end.pr, reason)
			return
		}
		end.pr.Pending.NeedsParentSync = false
	}
	source, serr := readEntryState(sourceParent, filepath.Base(m.Source))
	destination, derr := readEntryState(destinationParent, filepath.Base(m.Destination))
	if serr != nil || derr != nil {
		return
	}
	step := "move_completed"
	switch {
	case !destination.Exists && !dst.LastKnown.Exists && sameState(source, src.LastKnown):
		j.rec.Moves = slices.Delete(j.rec.Moves, i, i+1)
		step = "move_abandoned"
	case !source.Exists && destination.Exists && dst.Pending != nil && sameState(destination, dst.Pending.State):
		src.LastKnown, dst.LastKnown = source, destination
		j.rec.Moves[i].State = moveCompleted
	default:
		return
	}
	src.Pending, dst.Pending = nil, nil
	if err := j.step(step); err != nil {
		j.note(m.Source + " -> " + m.Destination + ": the resolved move could not be recorded: " + err.Error())
	}
}

func (j *Journal) RemovePublished(target string, parentDir *os.File, published filetools.JournalState) {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil {
		return
	}
	leaf := filepath.Base(target)
	dev, ino, err := entryIdentity(parentDir, leaf)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil || dev != published.Dev || ino != published.Ino || published.Ino == 0:
		j.markUnrecovered(pr, "another writer replaced the created file before it could be taken back")
		return
	default:
		if uErr := unix.Unlinkat(int(parentDir.Fd()), leaf, 0); uErr != nil {
			j.markUnrecovered(pr, "the created file could not be removed: "+uErr.Error())
			return
		}
	}
	j.reconcile(pr, parentDir)
}

// DirLifecycle records each segment against the path's snapshotted ancestor, which rollback descends
// from. EnsureDirAt names segments from ancestor, the directory the create started in, and that is
// deeper than the snapshotted one once an earlier act made or moved in a directory above the target.
func (j *Journal) DirLifecycle(target, ancestor string) fsutil.DirLifecycle {
	return j.dirLifecycle(target, ancestor, false)
}

func (j *Journal) dirLifecycle(target, ancestor string, standalone bool) fsutil.DirLifecycle {
	recordedRel := func(pr *pathRecord, rel string) (string, error) {
		r, err := filepath.Rel(pr.Ancestor, filepath.Join(ancestor, filepath.FromSlash(rel)))
		if err != nil || r == "." || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("subagent: %s is not beneath the snapshotted directory %s", rel, pr.Ancestor)
		}
		return filepath.ToSlash(r), nil
	}
	return fsutil.DirLifecycle{
		Intent: func(segPath string) error {
			j.mu.Lock()
			defer j.mu.Unlock()
			pr := j.record(target)
			if pr == nil {
				return nil
			}
			rel, err := recordedRel(pr, segPath)
			if err != nil {
				return err
			}
			if _, cur := j.currentDir(filepath.Join(ancestor, filepath.FromSlash(segPath))); cur != nil && !cur.Confirmed {
				return nil
			}
			pr.Dirs = append(pr.Dirs, dirRecord{Rel: rel, Progress: rollbackUnresolved, Mkdir: standalone, Seq: j.maxDirSeq() + 1})
			if err := j.step("dir_intent"); err != nil {
				pr.Dirs = pr.Dirs[:len(pr.Dirs)-1]
				return err
			}
			return nil
		},
		Confirm: func(seg fsutil.DirSegment) error {
			j.mu.Lock()
			defer j.mu.Unlock()
			pr := j.record(target)
			if pr == nil {
				return nil
			}
			if _, err := recordedRel(pr, seg.Path); err != nil {
				return err
			}
			_, cur := j.currentDir(filepath.Join(ancestor, filepath.FromSlash(seg.Path)))
			if cur == nil || cur.Confirmed {
				return nil
			}
			prior := *cur
			cur.Confirmed = true
			cur.Created = seg.Created
			cur.Dev, cur.Ino = seg.Dev, seg.Ino
			if err := j.step("dir_confirm"); err != nil {
				*cur = prior
				return err
			}
			return nil
		},
	}
}

// A non-nil lifecycle leaves a durable pending creation that the caller must pass to ResolveMkdir whether
// or not the create succeeds.
func (j *Journal) BeginMkdir(target, ancestor string) (declared bool, lifecycle *fsutil.DirLifecycle, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil || !pr.Mkdir {
		return false, nil, nil
	}
	if pr.Pending != nil {
		return true, nil, fmt.Errorf("subagent: %s has an earlier change that was never resolved", target)
	}
	current, err := j.targetState(pr)
	if err != nil {
		return true, nil, fmt.Errorf("subagent: cannot read %s before creating it: %w", target, err)
	}
	if !sameState(current, pr.LastKnown) {
		if pr.LastKnown.Exists || !j.ownsCreatedDir(pr, current) {
			return true, nil, fmt.Errorf("subagent: %s changed outside the child agent since it was snapshotted", target)
		}
		owner := j.createdDirAt(pr.Path, func(d dirRecord) bool { return d.Dev == current.Dev && d.Ino == current.Ino })
		wasMkdir := owner.Mkdir
		pr.LastKnown, owner.Mkdir = current, true
		if err := j.step("dir_adopted"); err != nil {
			pr.LastKnown, owner.Mkdir = fileState{}, wasMkdir
			return true, nil, err
		}
		return true, nil, nil
	}
	if current.Exists {
		return true, nil, nil
	}
	pr.Pending = &pendingMutation{State: fileState{Exists: true, Kind: kindDir}, NeedsParentSync: true}
	if err := j.step("pending"); err != nil {
		pr.Pending = nil
		return true, nil, err
	}
	lc := j.dirLifecycle(target, ancestor, true)
	return true, &lc, nil
}

func (j *Journal) ResolveMkdir(target string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	pr := j.record(target)
	if pr == nil {
		return nil
	}
	j.reconcileRecord(pr)
	if pr.Pending != nil || pr.LastKnown.Kind != kindDir {
		return fmt.Errorf("subagent: %s is not a directory the child agent created", target)
	}
	return nil
}

func (j *Journal) targetState(pr *pathRecord) (fileState, error) {
	dir, err := j.openTargetParent(pr)
	if errors.Is(err, errSuffixAbsent) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor
	return readEntryState(dir, filepath.Base(pr.Path))
}

func (j *Journal) ownsCreatedDir(pr *pathRecord, current fileState) bool {
	return pr.Mkdir && current.Exists && current.Kind == kindDir && j.createdDirAt(pr.Path, func(d dirRecord) bool {
		return d.Dev == current.Dev && d.Ino == current.Ino
	}) != nil
}

func (j *Journal) createdDirAt(path string, match func(dirRecord) bool) *dirRecord {
	if _, d := j.currentDir(path); d != nil && d.Confirmed && d.Created && match(*d) {
		return d
	}
	return nil
}

// currentDir selects the one creation record for a directory path, across every path record, that
// ownership and rollback act on: a later intent is recorded only once the segment is missing, so an
// earlier one names a directory already gone, whose inode number may since have been reused.
func (j *Journal) currentDir(path string) (*pathRecord, *dirRecord) {
	var owner *pathRecord
	var cur *dirRecord
	for i := range j.rec.Paths {
		q := &j.rec.Paths[i]
		for k := range q.Dirs {
			d := &q.Dirs[k]
			if filepath.Join(q.Ancestor, filepath.FromSlash(d.Rel)) == path && (cur == nil || d.Seq >= cur.Seq) {
				owner, cur = q, d
			}
		}
	}
	return owner, cur
}

func (j *Journal) maxDirSeq() uint64 {
	var high uint64
	for i := range j.rec.Paths {
		for _, d := range j.rec.Paths[i].Dirs {
			high = max(high, d.Seq)
		}
	}
	return high
}

// awaitsCreatedDir holds a declared directory back from path restoration until the directory created
// there has been settled, because its removal must follow whatever is restored beneath it and precede
// any pre-state another form puts back at the same path.
func (j *Journal) awaitsCreatedDir(pr *pathRecord) bool {
	return pr.Mkdir && j.createdDirAt(pr.Path, func(d dirRecord) bool { return d.Progress != rollbackRestored && !d.KeptByUser }) != nil
}

func (j *Journal) record(target string) *pathRecord {
	i, ok := j.index[target]
	if !ok {
		return nil
	}
	return &j.rec.Paths[i]
}

// ReconcilePending resolves every outstanding pending mutation without a live publish in hand. It is
// the entry point recovery must run before it compares any unresolved path: only this comparison can
// tell a crash before publication from a crash after it. Each path's captured target parent is
// reopened and identity-verified before it is synced and read.
func (j *Journal) ReconcilePending() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := len(j.rec.Moves) - 1; i >= 0; i-- {
		if j.rec.Moves[i].State == movePending && j.answerOf(j.rec.Moves[i]) == "" {
			if group := j.groupOf(i); j.beginOp(j.groupLabel(group), endpointsOf(j.rec.Moves, group)) {
				j.reconcilePendingMove(i)
				j.endOp()
			}
		}
	}
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if pr.Pending == nil || j.endpointOf(pr.Path, func(s moveState) bool { return s == movePending }) || !j.beginOp(pr.Path, []string{pr.Path}) {
			continue
		}
		j.reconcileRecord(pr)
		j.endOp()
	}
}

func (j *Journal) reconcileRecord(pr *pathRecord) {
	if pr.Pending == nil {
		return
	}
	dir, err := j.openTargetParent(pr)
	if errors.Is(err, errSuffixAbsent) {
		if pr.LastKnown.Exists {
			j.markUnrecovered(pr, "the directories holding it are gone, so the write cannot be resolved")
			return
		}
		pr.Pending = nil
		if fErr := j.step("reconciled"); fErr != nil {
			j.note(pr.Path + ": the resolved state could not be recorded: " + fErr.Error())
		}
		return
	}
	if err != nil {
		j.markUnrecovered(pr, "the target's parent directory could not be safely reopened: "+err.Error())
		return
	}
	j.reconcile(pr, dir)
	_ = dir.Close() //nolint:errcheck // read-only directory descriptor
}

// reconcile is the one prior/pending/third-state contract, shared by live terminal handling and
// recovery. Visibility alone never settles a pending record: the target parent is fsynced first, so a
// publish or compensation that reported a parent-sync failure — or a crash between the helper's return
// and this record's rewrite — cannot leave the namespace less durable than the journal claims.
func (j *Journal) reconcile(pr *pathRecord, parentDir *os.File) {
	if pr.Pending == nil {
		return
	}
	if pr.Pending.NeedsParentSync {
		if err := syncTargetParent(parentDir); err != nil {
			reason := "the target's parent directory could not be made durable: " + err.Error()
			j.retainDurable(pr.Path + ": " + reason)
			j.markUnrecovered(pr, reason)
			return
		}
		pr.Pending.NeedsParentSync = false
	}
	current, err := j.currentState(pr, parentDir)
	if err != nil {
		j.markUnrecovered(pr, "the current state could not be read: "+err.Error())
		return
	}
	pending := pr.Pending.State
	switch {
	case sameState(current, pr.LastKnown):
		pr.Pending = nil
	case pending.Kind == kindDir && pending.Ino == 0:
		// A pending directory names no identity, so only the creation its own confirmation recorded is
		// the child's; any other directory there is another writer's, whatever its mode.
		if !j.ownsCreatedDir(pr, current) {
			j.markUnrecovered(pr, "the directory there is not one the child agent created")
			return
		}
		pr.LastKnown = current
		pr.Pending = nil
	case sameState(current, pending):
		pr.LastKnown = current
		pr.Pending = nil
	default:
		j.markUnrecovered(pr, "the file holds neither the state before the write nor the state the write was to publish")
		return
	}
	if err := j.step("reconciled"); err != nil {
		j.note(pr.Path + ": the resolved state could not be recorded: " + err.Error())
	}
}

func (j *Journal) currentState(pr *pathRecord, parentDir *os.File) (fileState, error) {
	if pr.anyKind() {
		return readEntryState(parentDir, filepath.Base(pr.Path))
	}
	return regularState(parentDir, filepath.Base(pr.Path))
}

func (j *Journal) markUnrecovered(pr *pathRecord, reason string) {
	j.note(pr.Path + ": " + reason)
	_ = j.flush() //nolint:errcheck // the in-memory outcome is already unrecovered; a failed flush cannot make it worse
}

func (j *Journal) note(msg string) {
	for _, existing := range j.rec.Unrecovered {
		if existing == msg {
			return
		}
	}
	j.rec.Unrecovered = append(j.rec.Unrecovered, msg)
}

func (j *Journal) retainDurable(msg string) {
	for _, existing := range j.rec.Retained {
		if existing == msg {
			return
		}
	}
	j.rec.Retained = append(j.rec.Retained, msg)
}

func (j *Journal) hasDurableFailure() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.rec.Retained) > 0
}

// retainedOutcome reports the transaction as unrecovered without re-deriving it from what the
// filesystem now holds.
func (j *Journal) retainedOutcome() JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.flush() //nolint:errcheck // the journal is retained either way
	return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
}

// link records a nested delegate's journal on this one before that child runs, so a parent's stale
// last-known state can never be compared without first accounting for the descendant that owns the
// visible mutation.
func (j *Journal) link(child *Journal) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.rec.Children = append(j.rec.Children, childLink{Dir: child.dirName, Depth: child.rec.Depth})
	if err := j.step("link_child"); err != nil {
		j.rec.Children = j.rec.Children[:len(j.rec.Children)-1]
		return err
	}
	return nil
}

// MarkTransferReady hands a completed nested child's journal to its parent. The child never deletes
// its own journal on completion: until the parent has durably absorbed it, it is the only record of
// which writes belong to the child rather than to an outside writer.
func (j *Journal) MarkTransferReady() error {
	j.mu.Lock()
	j.rec.Lifecycle = lifecycleTransferReady
	err := j.step("transfer_ready")
	j.mu.Unlock()
	if err != nil {
		return err
	}
	if j.parent == nil {
		return nil
	}
	return j.parent.setChildTransferReady(j.dirName)
}

func (j *Journal) setChildTransferReady(dir string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.rec.Children {
		if j.rec.Children[i].Dir == dir {
			j.rec.Children[i].TransferReady = true
			return j.step("child_transfer_ready")
		}
	}
	return nil
}

// Absorb folds a transfer-ready descendant's state into this journal and then deletes it. The parent
// takes over the child's last-known states and created directories so its own comparison reads the
// grandchild's writes as child-owned rather than as an external edit.
func (j *Journal) Absorb(child *Journal) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.absorbLocked(child)
}

func (j *Journal) absorbLocked(child *Journal) error {
	if child.gone {
		j.dropChild(child)
		return j.step("child_absorbed")
	}
	child.mu.Lock()
	if err := j.refuseAnswerLoss(child); err != nil {
		child.mu.Unlock()
		return err
	}
	base := j.maxDirSeq()
	for i := range child.rec.Paths {
		cp := &child.rec.Paths[i]
		pp := j.record(cp.Path)
		if pp == nil {
			continue
		}
		pp.LastKnown = cp.LastKnown
		pp.Pending = cp.Pending
		pp.KeptByUser = pp.KeptByUser || cp.KeptByUser
		for _, d := range cp.Dirs {
			d.Seq += base
			pp.Dirs = append(pp.Dirs, d)
		}
	}
	j.rec.Moves = append(j.rec.Moves, child.rec.Moves...)
	j.rec.Answers = append(j.rec.Answers, child.rec.Answers...)
	for _, note := range child.rec.Unrecovered {
		j.note(note)
	}
	child.mu.Unlock()

	for i := range j.rec.Children {
		if j.rec.Children[i].Dir == child.dirName {
			j.rec.Children[i].Absorbed = true
		}
	}
	if err := j.step("child_absorbed"); err != nil {
		return err
	}
	if err := child.remove(); err != nil {
		return err
	}
	j.dropChild(child)
	return j.step("child_dropped")
}

func (j *Journal) refuseAnswerLoss(child *Journal) error {
	for _, ans := range child.rec.Answers {
		for _, path := range ans.Endpoints {
			if j.record(path) == nil {
				return fmt.Errorf("subagent: the nested journal answered for %s, which this journal does not hold", path)
			}
		}
	}
	for i := range child.rec.Paths {
		cp := &child.rec.Paths[i]
		if j.record(cp.Path) == nil && (cp.KeptByUser || slices.ContainsFunc(cp.Dirs, func(d dirRecord) bool { return d.KeptByUser })) {
			return fmt.Errorf("subagent: the nested journal kept %s, which this journal does not hold", cp.Path)
		}
	}
	for _, m := range child.rec.Moves {
		if m.ID != (moveID{}) && slices.ContainsFunc(j.rec.Moves, func(p moveRecord) bool { return p.ID == m.ID }) {
			return fmt.Errorf("subagent: the nested journal's move %s -> %s has an identity this journal already holds", m.Source, m.Destination)
		}
	}
	return checkAnswersCoverLinks(slices.Concat(j.rec.Moves, child.rec.Moves), slices.Concat(j.rec.Answers, child.rec.Answers))
}

func (j *Journal) dropChild(child *Journal) {
	kept := j.rec.Children[:0]
	for _, link := range j.rec.Children {
		if link.Dir != child.dirName {
			kept = append(kept, link)
		}
	}
	j.rec.Children = kept
	live := j.children[:0]
	for _, c := range j.children {
		if c != child {
			live = append(live, c)
		}
	}
	j.children = live
}
