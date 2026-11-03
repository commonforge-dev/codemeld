package subagent

import (
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"codemeld.dev/codemeld/internal/permissions"
)

// Finish resolves the transaction. A completed child's work stands only when every unresolved
// declared path still matches the durable last-known child state; every other terminal reason puts
// the declared scope back as the child found it. A path that matches neither is a third outcome: it
// is left alone and the journal survives naming it.
func (j *Journal) Finish(reason Reason) JournalOutcome {
	j.resetNotes()
	j.mu.Lock()
	committed := j.rec.Lifecycle == lifecycleCommitted
	j.mu.Unlock()
	// A durable committed marker outranks the terminal reason: the child's work already stood, so a
	// survivor is cleanup and never a restore.
	if committed {
		return j.cleanUpCommitted()
	}
	if reason == ReasonCompleted && j.parent == nil {
		if outcome, ok := j.markCompleted(); !ok {
			return outcome
		}
	}
	j.absorbTransferReady()
	j.ReconcilePending()
	if reason != ReasonCompleted {
		return j.rollback(nil)
	}
	if j.hasDurableFailure() {
		return j.retainedOutcome()
	}
	if j.parent == nil {
		return j.commit()
	}
	if err := j.MarkTransferReady(); err != nil {
		return j.retain("the completed nested journal could not be handed to its parent: " + err.Error())
	}
	if err := j.parent.Absorb(j); err != nil {
		j.parent.retain("a nested child agent's journal could not be absorbed: " + err.Error())
		return j.retain("its parent could not absorb it: " + err.Error())
	}
	return JournalOutcome{}
}

func (j *Journal) markCompleted() (JournalOutcome, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.rec.Completed {
		return JournalOutcome{}, true
	}
	j.rec.Completed = true
	err := j.step("completed")
	if err == nil {
		return JournalOutcome{}, true
	}
	reason := "the child agent completed, but that could not be recorded: " + err.Error()
	j.retainDurable(reason)
	j.note(reason)
	if rErr := j.step("completion_retained"); rErr != nil {
		j.note("the record of the run could not be saved either (" + rErr.Error() + "), so the next codemeld launch may treat this run as interrupted and put its changes back")
	}
	return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}, false
}

// resetNotes clears what a terminal pass re-derives from the current state, so notes left by an
// attempt that was interrupted cannot outlive the condition that produced them. A retained durability
// failure is re-noted: it cannot be re-derived, and a later successful sync would otherwise turn the
// transaction into a clean outcome.
func (j *Journal) resetNotes() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.rec.Unrecovered = nil
	j.retainedDirs = nil
	for _, msg := range slices.Concat(j.rec.Retained, j.policyNotes) {
		j.note(msg)
	}
}

func (j *Journal) retain(reason string) JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.note(reason)
	_ = j.flush() //nolint:errcheck // the journal is retained either way
	return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
}

// absorbTransferReady processes still-linked descendants deepest-first, so a grandchild's journal is
// folded into its own parent before that parent is folded into this one.
func (j *Journal) absorbTransferReady() {
	j.mu.Lock()
	children := append([]*Journal(nil), j.children...)
	j.mu.Unlock()
	sort.SliceStable(children, func(a, b int) bool { return children[a].rec.Depth > children[b].rec.Depth })
	for _, child := range children {
		child.absorbTransferReady()
		if !child.transferReady() {
			continue
		}
		j.mu.Lock()
		err := j.absorbLocked(child)
		j.mu.Unlock()
		if err != nil {
			j.mu.Lock()
			j.note(child.path + ": the nested child agent's journal could not be absorbed: " + err.Error())
			_ = j.flush() //nolint:errcheck // the outcome is already unrecovered
			j.mu.Unlock()
		}
	}
}

func (j *Journal) transferReady() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.rec.Lifecycle == lifecycleTransferReady
}

func (j *Journal) commit() JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if pr.KeptByUser {
			continue
		}
		reasons, _, _ := j.completionFailures(pr)
		for _, reason := range reasons {
			j.note(pr.Path + ": " + reason)
		}
	}
	if len(j.rec.Unrecovered) > 0 {
		_ = j.flush() //nolint:errcheck // the journal is retained either way; a failed flush is reported by its survival
		return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	j.rec.Lifecycle = lifecycleCommitted
	if err := j.step("committed"); err != nil {
		j.note("the committed state could not be recorded: " + err.Error())
		return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	return j.removeCommitted()
}

const dirNeverConfirmed = "a parent directory the child agent started to create was never confirmed"

func (j *Journal) completionFailures(pr *pathRecord) (reasons []string, current fileState, read bool) {
	for _, dir := range pr.Dirs {
		if !dir.Confirmed && !slices.Contains(reasons, dirNeverConfirmed) {
			reasons = append(reasons, dirNeverConfirmed)
		}
	}
	if pr.Pending != nil {
		return append(reasons, "a write the child agent started was never resolved"), fileState{}, false
	}
	dir, err := j.openTargetParent(pr)
	switch {
	case errors.Is(err, errSuffixAbsent):
	case err != nil:
		return append(reasons, "the target's parent directory could not be safely reopened: "+err.Error()), fileState{}, false
	default:
		var cerr error
		current, cerr = j.currentState(pr, dir)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		if cerr != nil {
			return append(reasons, "the current state could not be read: "+cerr.Error()), fileState{}, false
		}
	}
	if !sameState(current, pr.LastKnown) && !j.ownsCreatedDir(pr, current) {
		reasons = append(reasons, "it was changed outside the child agent's journalled writes")
	}
	return reasons, current, true
}

func (j *Journal) cleanUpCommitted() JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.removeCommitted()
}

func (j *Journal) removeCommitted() JournalOutcome {
	if err := j.remove(); err != nil {
		j.note("the committed journal could not be removed: " + err.Error())
		_ = j.flush() //nolint:errcheck // the journal survives either way; its survival is the report
		return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	return JournalOutcome{}
}

func (j *Journal) rollback(frozen map[int]HeldMove) JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	// A path declared beneath a moved entry is reachable only where the move left it, so what the child
	// changed there, and the directories it made there, are put back before the undo carries that entry
	// home. An untouched path still holds what the move carried in and settles once the move is undone.
	inside, early := j.changedInsideMovedEntries()
	waiting := make(map[string]bool)
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		waiting[pr.Path] = j.awaitsCreatedDir(pr)
	}
	// Which groups end up held is known only after their undo, so a directory at any open move endpoint
	// waits until then and survives if its group is held.
	endpoints := make(map[string]bool)
	for _, m := range j.rec.Moves {
		if m.State != moveUndone && j.answerOf(m) != ChoiceKeep {
			endpoints[m.Source], endpoints[m.Destination] = true, true
		}
	}
	restored := j.restorePaths(nil, func(path string) bool { return early[path] })
	j.removeCreatedDirs(func(owner, dir string) bool { return inside[owner] && !endpoints[dir] })
	restored = j.restorePaths(restored, func(path string) bool { return early[path] && waiting[path] })
	undone, held, heldMoves, heldAt := j.undoMoves(j.unrestoredBeneath(early), frozen)
	for _, path := range undone {
		if !slices.Contains(restored, path) {
			restored = append(restored, path)
		}
	}
	// Paths are recorded sorted, so a deleted directory is recreated before anything declared beneath it.
	restored = j.restorePaths(restored, func(path string) bool { return !early[path] && !held[path] })
	j.removeCreatedDirs(func(owner, dir string) bool { return (!inside[owner] || endpoints[dir]) && !held[dir] })
	restored = j.restorePaths(restored, func(path string) bool { return !early[path] && !held[path] && waiting[path] })
	if len(j.rec.Unrecovered) > 0 {
		_ = j.flush() //nolint:errcheck // the journal is retained either way
		return JournalOutcome{Restored: restored, Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path, HeldMoves: heldMoves, RetainedDirs: slices.Clone(j.retainedDirs), heldAt: heldAt}
	}
	if err := j.remove(); err != nil {
		j.note("the rolled-back journal could not be removed: " + err.Error())
		return JournalOutcome{Restored: restored, Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
	}
	return JournalOutcome{Restored: restored}
}

// undoMoves puts every moved entry back whole, newest move first, before any endpoint is restored by
// kind, which would recreate a moved directory empty and strand its contents. Linked moves are undone
// or held together, and a group is held before its first act unless its whole undo can be simulated.
func (j *Journal) undoMoves(unrestoredBeneath func(destination string) bool, frozen map[int]HeldMove) (restored []string, held map[string]bool, heldMoves []HeldMove, heldAt map[int]HeldMove) {
	held = make(map[string]bool)
	heldAt = make(map[int]HeldMove)
	for _, group := range j.newestGroupsFirst() {
		if !slices.ContainsFunc(group, func(i int) bool { return j.rec.Moves[i].State != moveUndone }) || !j.beginOp(j.groupLabel(group), endpointsOf(j.rec.Moves, group)) {
			continue
		}
		changed, groupHeld := j.undoGroup(group, unrestoredBeneath, frozen)
		j.endOp()
		for _, path := range changed {
			if !slices.Contains(restored, path) {
				restored = append(restored, path)
			}
		}
		for _, i := range slices.Sorted(maps.Keys(groupHeld)) {
			h := groupHeld[i]
			j.note(h.note())
			heldMoves = append(heldMoves, h)
			held[h.Source], held[h.Destination] = true, true
			heldAt[i] = h
		}
	}
	return restored, held, heldMoves, heldAt
}

func (j *Journal) newestGroupsFirst() [][]int {
	groups := j.moveGroups()
	slices.SortFunc(groups, func(a, b []int) int { return b[len(b)-1] - a[len(a)-1] })
	return groups
}

const linkedMoveHeld = "a linked move could not be undone, so this one was left in place"

func (j *Journal) undoGroup(group []int, unrestoredBeneath func(destination string) bool, frozen map[int]HeldMove) (restored []string, held map[int]HeldMove) {
	members := slices.DeleteFunc(slices.Clone(group), func(i int) bool { return j.rec.Moves[i].State == moveUndone })
	if len(members) == 0 {
		return nil, nil
	}
	if slices.ContainsFunc(members, func(i int) bool { _, ok := frozen[i]; return ok }) {
		held = make(map[int]HeldMove, len(members))
		for _, i := range members {
			h, ok := frozen[i]
			if !ok {
				h = HeldMove{Source: j.rec.Moves[i].Source, Destination: j.rec.Moves[i].Destination, Reason: linkedMoveHeld, Resumes: j.undoResumes(group)}
			}
			held[i] = h
		}
		return nil, held
	}
	failed, err := -1, error(nil)
	if k := slices.IndexFunc(members, func(i int) bool { return unrestoredBeneath(j.rec.Moves[i].Destination) }); k >= 0 {
		failed, err = members[k], errors.New("a path the child agent changed inside the moved entry could not be put back first")
	} else {
		failed, err = j.preflightUndo(members, nil, nil)
	}
	for k := len(members) - 1; err == nil && k >= 0; k-- {
		m := &j.rec.Moves[members[k]]
		var changed bool
		if changed, err = j.undoMove(m); err != nil {
			failed = members[k]
			continue
		}
		for _, path := range []string{m.Source, m.Destination} {
			if changed && !slices.Contains(restored, path) {
				restored = append(restored, path)
			}
		}
	}
	if err == nil {
		return restored, nil
	}
	resumes := j.undoResumes(group)
	held = make(map[int]HeldMove, len(members))
	for _, i := range members {
		m := j.rec.Moves[i]
		if m.State == moveUndone {
			continue
		}
		h := HeldMove{Source: m.Source, Destination: m.Destination, Reason: linkedMoveHeld, Resumes: resumes}
		if i == failed {
			h.Reason = err.Error()
		}
		held[i] = h
	}
	return restored, held
}

// undoResumes counts a recorded Restore answer as an undo already under way: the answer is replayed at
// every launch and is never asked about again.
func (j *Journal) undoResumes(group []int) bool {
	return undoBegun(j.rec.Moves, group) || slices.ContainsFunc(group, func(i int) bool { return j.answerOf(j.rec.Moves[i]) == ChoiceRestore })
}

func endpointsOf(moves []moveRecord, members []int) []string {
	var out []string
	for _, i := range members {
		for _, path := range []string{moves[i].Source, moves[i].Destination} {
			if !slices.Contains(out, path) {
				out = append(out, path)
			}
		}
	}
	return out
}

func (j *Journal) answerMembers(ans groupAnswer) []int {
	var members []int
	for i, m := range j.rec.Moves {
		if m.ID != (moveID{}) && slices.Contains(ans.Members, m.ID) {
			members = append(members, i)
		}
	}
	return members
}

// restoreRefusal changes nothing; the states it returns are the ones a Restore answer adopts.
func (j *Journal) restoreRefusal(group []int) (observed map[string]fileState, refusal string) {
	_, early := j.changedInsideMovedEntries()
	return j.restoreRefusalWith(group, j.unrestoredBeneath(early))
}

func (j *Journal) restoreRefusalWith(group []int, beneath func(destination string) bool) (observed map[string]fileState, refusal string) {
	for _, i := range group {
		if _, _, err := j.moveEndpoints(&j.rec.Moves[i]); err != nil {
			return nil, err.Error()
		}
	}
	if slices.ContainsFunc(group, func(i int) bool { return beneath(j.rec.Moves[i].Destination) }) {
		return nil, "a path the child agent changed inside the moved entry could not be put back first"
	}
	endpoints := endpointsOf(j.rec.Moves, group)
	records := make([]*pathRecord, 0, len(endpoints))
	for _, path := range endpoints {
		pr := j.record(path)
		if pr.Pending != nil {
			return nil, path + ": a write the child agent started was never resolved"
		}
		records = append(records, pr)
	}
	observed = make(map[string]fileState, len(endpoints))
	if _, err := j.preflightUndo(group, observed, records); err != nil {
		return nil, err.Error()
	}
	return observed, ""
}

func (j *Journal) groupQuestion(group []int, refusal string) Unresolved {
	u := Unresolved{Choices: []Choice{ChoiceKeep, ChoiceRestore, ChoiceDefer}, RestoreRefusal: refusal}
	if refusal != "" {
		u.Choices = []Choice{ChoiceKeep, ChoiceDefer}
	}
	for _, i := range group {
		m := j.rec.Moves[i]
		u.Moves = append(u.Moves, UnresolvedMove{ID: m.ID, Source: m.Source, Destination: m.Destination, Pending: m.State == movePending})
	}
	return u
}

func (j *Journal) publishAnswer(group []int, choice Choice, adopted map[string]fileState) (groupAnswer, error) {
	priorMoves, priorAnswers, priorSeq := slices.Clone(j.rec.Moves), len(j.rec.Answers), j.rec.MoveSeq
	ans := groupAnswer{Choice: choice, Endpoints: endpointsOf(j.rec.Moves, group)}
	for _, i := range group {
		if j.rec.Moves[i].ID == (moveID{}) {
			j.rec.Moves[i].ID = j.newMoveID()
		}
		ans.Members = append(ans.Members, j.rec.Moves[i].ID)
	}
	prior := make(map[string]fileState)
	if choice == ChoiceRestore {
		for _, path := range ans.Endpoints {
			pr := j.record(path)
			prior[path], pr.LastKnown = pr.LastKnown, adopted[path]
			ans.Adopted = append(ans.Adopted, adoptedState{Path: path, State: adopted[path]})
		}
	}
	j.rec.Answers = append(j.rec.Answers, ans)
	if err := j.step("group_answered"); err != nil {
		j.rec.Moves, j.rec.Answers, j.rec.MoveSeq = priorMoves, j.rec.Answers[:priorAnswers], priorSeq
		for path, state := range prior {
			j.record(path).LastKnown = state
		}
		return groupAnswer{}, err
	}
	return ans, nil
}

// settleKept derives a Keep answer's settled records and changes nothing once they are settled, so it
// can run again after a crash at any point.
func (j *Journal) settleKept(ans groupAnswer) error {
	if !j.markKept(ans, true) {
		return nil
	}
	return j.step("group_kept")
}

func (j *Journal) markKept(ans groupAnswer, apply bool) (changed bool) {
	for _, path := range ans.Endpoints {
		if pr := j.record(path); pr != nil && (!pr.KeptByUser || pr.Pending != nil) {
			if apply {
				pr.KeptByUser, pr.Pending = true, nil
			}
			changed = true
		}
		for i := range j.rec.Paths {
			q := &j.rec.Paths[i]
			for k := range q.Dirs {
				if d := &q.Dirs[k]; !d.KeptByUser && filepath.Join(q.Ancestor, filepath.FromSlash(d.Rel)) == path {
					if apply {
						d.KeptByUser = true
					}
					changed = true
				}
			}
		}
	}
	return changed
}

func (j *Journal) groupNote(group []int, endpoints []string) func(string) bool {
	return func(note string) bool {
		return slices.ContainsFunc(group, func(i int) bool {
			return strings.HasPrefix(note, j.rec.Moves[i].Source+" -> "+j.rec.Moves[i].Destination+": ")
		}) || slices.ContainsFunc(endpoints, func(path string) bool { return strings.HasPrefix(note, path+": ") })
	}
}

func (j *Journal) clearGroupNotes(group []int, endpoints []string) {
	ofGroup := j.groupNote(group, endpoints)
	j.rec.Unrecovered = slices.DeleteFunc(j.rec.Unrecovered, func(note string) bool {
		return ofGroup(note) && !slices.Contains(j.rec.Retained, note) && !slices.Contains(j.policyNotes, note)
	})
	j.retainedDirs = slices.DeleteFunc(j.retainedDirs, func(dir string) bool { return slices.Contains(endpoints, dir) })
}

func (j *Journal) restoreGroup(group []int, endpoints []string) (restored []string, held map[int]HeldMove) {
	j.clearGroupNotes(group, endpoints)
	_, early := j.changedInsideMovedEntries()
	restored, held = j.undoGroup(group, j.unrestoredBeneath(early), nil)
	if len(held) > 0 {
		for _, i := range slices.Sorted(maps.Keys(held)) {
			j.note(held[i].note())
		}
		return restored, held
	}
	named := func(path string) bool { return slices.Contains(endpoints, path) }
	waiting := make(map[string]bool)
	for _, path := range endpoints {
		waiting[path] = j.awaitsCreatedDir(j.record(path))
	}
	restored = j.restorePaths(restored, named)
	j.removeCreatedDirs(func(_, dir string) bool { return named(dir) })
	return j.restorePaths(restored, func(path string) bool { return named(path) && waiting[path] }), nil
}

// The notes replayAnswers leaves are dropped, because the pass that follows re-derives them.
func (j *Journal) replayAnswers() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.rec.Answers) == 0 {
		return nil
	}
	notes, dirs := slices.Clone(j.rec.Unrecovered), slices.Clone(j.retainedDirs)
	defer func() {
		j.rec.Unrecovered, j.retainedDirs = notes, dirs
		for _, msg := range slices.Concat(j.rec.Retained, j.policyNotes) {
			j.note(msg)
		}
	}()
	var restored []string
	for _, ans := range j.rec.Answers {
		members := j.answerMembers(ans)
		switch ans.Choice {
		case ChoiceKeep:
			if !j.markKept(ans, false) || !j.beginOp(j.groupLabel(members), ans.Endpoints) {
				continue
			}
			if err := j.settleKept(ans); err != nil {
				j.note("the kept moves could not be recorded as settled: " + err.Error())
			}
			j.endOp()
		case ChoiceRestore:
			if !j.beginOp(j.groupLabel(members), ans.Endpoints) {
				continue
			}
			changed, _ := j.restoreGroup(members, ans.Endpoints)
			j.endOp()
			for _, path := range changed {
				if !slices.Contains(restored, path) {
					restored = append(restored, path)
				}
			}
		}
	}
	return restored
}

func (j *Journal) settledOutcome(frozen map[int]HeldMove) JournalOutcome {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.rec.Unrecovered) == 0 {
		if err := j.remove(); err != nil {
			j.note("the rolled-back journal could not be removed: " + err.Error())
			return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path}
		}
		return JournalOutcome{}
	}
	_ = j.flush() //nolint:errcheck // the journal is retained either way
	var heldMoves []HeldMove
	for _, group := range j.newestGroupsFirst() {
		for _, i := range group {
			if h, ok := frozen[i]; ok && j.rec.Moves[i].State != moveUndone {
				heldMoves = append(heldMoves, h)
			}
		}
	}
	return JournalOutcome{Unrecovered: append([]string(nil), j.rec.Unrecovered...), JournalPath: j.path, HeldMoves: heldMoves, RetainedDirs: slices.Clone(j.retainedDirs), heldAt: frozen}
}

func undoBegun(moves []moveRecord, group []int) bool {
	var undone, open bool
	for _, i := range group {
		switch moves[i].State {
		case moveUndoing:
			return true
		case moveUndone:
			undone = true
		default:
			open = true
		}
	}
	return undone && open
}

func (j *Journal) moveGroups() [][]int {
	root := make([]int, len(j.rec.Moves))
	for i := range root {
		root[i] = i
	}
	find := func(i int) int {
		for root[i] != i {
			i = root[i]
		}
		return i
	}
	kept := func(i int) bool { return j.answerOf(j.rec.Moves[i]) == ChoiceKeep }
	for i := range j.rec.Moves {
		for k := i + 1; k < len(j.rec.Moves); k++ {
			if !kept(i) && !kept(k) && movesLinked(j.rec.Moves[i].movePair, j.rec.Moves[k].movePair) {
				root[find(k)] = find(i)
			}
		}
	}
	var groups [][]int
	slot := make(map[int]int)
	for i := range j.rec.Moves {
		if kept(i) {
			continue
		}
		r := find(i)
		g, ok := slot[r]
		if !ok {
			g = len(groups)
			slot[r] = g
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], i)
	}
	return groups
}

func movesLinked(a, b movePair) bool {
	for _, p := range []string{a.Source, a.Destination} {
		for _, q := range []string{b.Source, b.Destination} {
			if permissions.IsDescendantOrEqual(p, q) || permissions.IsDescendantOrEqual(q, p) {
				return true
			}
		}
	}
	return false
}

func (j *Journal) endpointOf(path string, include func(moveState) bool) bool {
	return slices.ContainsFunc(j.rec.Moves, func(m moveRecord) bool {
		return include(m.State) && (m.Source == path || m.Destination == path) && j.answerOf(m) != ChoiceKeep
	})
}

func (j *Journal) answerOf(m moveRecord) Choice {
	if m.ID == (moveID{}) {
		return ""
	}
	for _, ans := range j.rec.Answers {
		if slices.Contains(ans.Members, m.ID) {
			return ans.Choice
		}
	}
	return ""
}
