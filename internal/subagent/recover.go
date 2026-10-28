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
	"strings"

	"golang.org/x/sys/unix"

	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/permissions"
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
	Completed      bool
	Reason         string
}

type UnresolvedMove struct {
	ID          moveID
	Source      string
	Destination string
	Pending     bool
}

type RetainedJournal struct {
	Path        string
	Notes       []string
	Moves       []HeldMove
	Dirs        []string
	PolicyNotes int
	Completed   bool
	Committed   bool
	Unanswered  int
}

type LeftAloneJournal struct {
	Path   string
	Reason string
}

type Report struct {
	Restored          []string
	Kept              []string
	CompletedRestored []string
	CompletedKept     []string
	Retained          []RetainedJournal
	LeftAlone         []LeftAloneJournal
}

func (r Report) Empty() bool {
	return len(r.Restored) == 0 && len(r.Kept) == 0 && len(r.CompletedRestored) == 0 && len(r.CompletedKept) == 0 &&
		len(r.Retained) == 0 && len(r.LeftAlone) == 0
}

var (
	errNoJournalRecord = errors.New("subagent: the journal directory holds no record")
	errJournalHeld     = errors.New("subagent: another codemeld holds the journal's lock")
)

// Blocked nil, a non-empty Unavailable, or a nil Refresh leaves every journal unchanged.
type RecoveryPolicy struct {
	Blocked     *permissions.BlockedPaths
	Unavailable string
	Refresh     func() (*permissions.BlockedPaths, error)
}

const listUnavailable = "the blocked-path list cannot be read, so nothing was put back"

type recoveryGate struct {
	refresh func() (*permissions.BlockedPaths, error)
	op      *permissions.BlockedPaths
	depth   int
	lost    bool
}

func (g *recoveryGate) snapshot() (*permissions.BlockedPaths, bool) {
	if g.lost {
		return nil, false
	}
	if g.op != nil {
		return g.op, true
	}
	snap, err := g.refresh()
	if err != nil || snap == nil {
		g.lost = true
		return nil, false
	}
	return snap, true
}

func (g *recoveryGate) begin() (*permissions.BlockedPaths, bool) {
	snap, ok := g.snapshot()
	if ok {
		g.op = snap
		g.depth++
	}
	return snap, ok
}

func (g *recoveryGate) end() {
	if g.depth--; g.depth == 0 {
		g.op = nil
	}
}

// allows is the check every durable journal write and removal runs through: outside an operation it
// takes a snapshot of its own, so no write rests on availability an earlier operation established.
func (g *recoveryGate) allows() bool {
	_, ok := g.snapshot()
	return ok
}

type leftAloneError struct{ reason string }

func (e *leftAloneError) Error() string { return e.reason }

// Recover puts back the declared writes of every child agent whose codemeld process died before it
// could unwind them, for the project folder being opened. A journal whose lock another process holds is
// skipped without reading its record, and so is every journal linked above it. ask decides each held
// move group whose undo has not begun, and then the paths that match neither the state the child left
// nor the state captured before it ran; a nil ask defers all of them, while answers recorded earlier are
// still carried out, unless policy blocks a path they would act on.
func Recover(home, projectRoot string, policy RecoveryPolicy, ask func(Unresolved) Choice) Report {
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
	gate := &recoveryGate{refresh: policy.Refresh, lost: policy.Blocked == nil || policy.Unavailable != "" || policy.Refresh == nil}
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
		j.gate = gate
		orphans = append(orphans, j)
	}

	orphans = holdBackLinkedParents(orphans, held, unavailable, &report, !gate.lost)
	if gate.lost {
		for _, j := range orphans {
			holdUnavailable(&report, j, nil)
			j.Close()
		}
		return report
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
	if j.gate.lost || j.rec.Lifecycle != lifecycleCommitted && !j.classify() {
		holdUnavailable(report, j, nil)
		return
	}
	switch {
	case j.rec.Lifecycle == lifecycleCommitted:
		outcome := j.cleanUpCommitted()
		if j.gate.lost {
			holdUnavailable(report, j, nil)
			return
		}
		collect(report, j, outcome)
	case j.rec.Completed:
		recoverCompleted(j, ask, report)
	case j.rec.Lifecycle == lifecycleTransferReady && j.parent != nil:
		j.replayAnswers()
		if _, ok := j.gate.begin(); !ok {
			holdUnavailable(report, j, nil)
			return
		}
		defer j.gate.end()
		j.classify()
		switch {
		case len(j.policyRoots) > 0:
			j.parent.inheritHolds(j)
			collectHeld(report, j, j.retainedOutcome())
		default:
			if err := j.parent.Absorb(j); err != nil {
				j.parent.retain("a nested child agent's journal could not be absorbed: " + err.Error())
				collect(report, j, j.retain("its parent could not absorb it: "+err.Error()))
			}
		}
	default:
		replayed := j.replayAnswers()
		j.ReconcilePending()
		outcome := j.rollback(nil)
		outcome.Restored = append(replayed, outcome.Restored...)
		if outcome.JournalPath != "" && ask != nil && !j.gate.lost {
			outcome = answerQuestions(j, ask, outcome, report)
		}
		if j.gate.lost {
			holdUnavailable(report, j, outcome.Restored)
			return
		}
		if outcome.JournalPath != "" && j.parent != nil {
			j.parent.inheritHolds(j)
			j.parent.retain(j.path + ": a nested child agent's journal could not be recovered")
		}
		collectHeld(report, j, outcome)
	}
}

func holdUnavailable(report *Report, j *Journal, restored []string) {
	if j.rec.Completed {
		report.CompletedRestored = append(report.CompletedRestored, restored...)
	} else {
		report.Restored = append(report.Restored, restored...)
	}
	report.Retained = append(report.Retained, RetainedJournal{Path: j.path, Notes: []string{listUnavailable}, PolicyNotes: 1, Completed: j.rec.Completed})
}

func collectHeld(report *Report, j *Journal, outcome JournalOutcome) {
	collect(report, j, outcome)
	if outcome.JournalPath == "" {
		return
	}
	retained := &report.Retained[len(report.Retained)-1]
	for _, note := range retained.Notes {
		if slices.Contains(j.policyNotes, note) {
			retained.PolicyNotes++
		}
	}
}

// Only a path answer runs a second rollback, and that rollback leaves every group still open exactly as
// it was.
func answerQuestions(j *Journal, ask func(Unresolved) Choice, outcome JournalOutcome, report *Report) JournalOutcome {
	holds := len(j.policyNotes)
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
	case pass.answered || len(pass.notes) > 0 || len(j.policyNotes) > holds:
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
		note := j.groupLabel(group) + ": " + msg
		j.note(note)
		pass.notes = append(pass.notes, note)
	}
	begin := func(group []int, endpoints []string) bool {
		if j.beginOp(j.groupLabel(group), endpoints) {
			return true
		}
		j.clearGroupNotes(group, endpoints)
		for _, i := range group {
			delete(pass.frozen, i)
		}
		return false
	}
	for _, group := range j.moveGroups() {
		if !slices.ContainsFunc(group, func(i int) bool { h, ok := heldAt[i]; return ok && !h.Resumes }) {
			continue
		}
		endpoints := endpointsOf(j.rec.Moves, group)
		if !begin(group, endpoints) {
			continue
		}
		observed, refusal := j.restoreRefusal(group)
		j.endOp()
		choice := ask(j.groupQuestion(group, refusal))
		if choice != ChoiceKeep && (choice != ChoiceRestore || refusal != "") || !begin(group, endpoints) {
			continue
		}
		func() {
			defer j.endOp()
			switch choice {
			case ChoiceKeep:
				ans, err := j.publishAnswer(group, ChoiceKeep, nil)
				if err != nil {
					hold(group, "the answer to keep these moves could not be recorded: "+err.Error())
					return
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
				again, refusal := j.restoreRefusal(group)
				if refusal == "" && !sameObservations(observed, again) {
					refusal = "an endpoint changed while the question was open"
				}
				if refusal != "" {
					hold(group, "these moves were not put back and are asked about again at the next launch: "+refusal)
					return
				}
				ans, err := j.publishAnswer(group, ChoiceRestore, again)
				if err != nil {
					hold(group, "the answer to put these moves back could not be recorded: "+err.Error())
					return
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
		}()
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
		own := []string{pr.Path}
		if !j.beginOp(pr.Path, own) {
			continue
		}
		dir, err := j.openTargetParent(pr)
		if err != nil {
			j.endOp()
			continue
		}
		current, cErr := j.currentState(pr, dir)
		_ = dir.Close() //nolint:errcheck // read-only directory descriptor
		j.endOp()
		if cErr != nil || sameState(current, pr.LastKnown) {
			continue
		}
		choice := ask(Unresolved{Path: pr.Path})
		if choice != ChoiceKeep && choice != ChoiceRestore || !j.beginOp(pr.Path, own) {
			continue
		}
		switch choice {
		case ChoiceKeep:
			pr.KeptByUser = true
			if sErr := j.step("kept"); sErr != nil {
				pr.KeptByUser = false
				break
			}
			kept = append(kept, pr.Path)
			resolved = true
		case ChoiceRestore:
			prior := pr.LastKnown
			pr.LastKnown = current
			if sErr := j.step("adopted"); sErr != nil {
				pr.LastKnown = prior
				break
			}
			resolved = true
		}
		j.endOp()
	}
	return kept, resolved
}

type completedPass struct {
	kept       []string
	restore    []*pathRecord
	observed   map[string]fileState
	groups     []completedGroup
	unanswered int
}

type completedGroup struct {
	group    []int
	observed map[string]fileState
}

const (
	completedLeftAsIs       = "the child agent's change was left as it is until you decide"
	completedUndoUnfinished = "a put back chosen earlier could not be finished, so codemeld tries it again at the next launch"
)

func recoverCompleted(j *Journal, ask func(Unresolved) Choice, report *Report) {
	restored := j.replayAnswers()
	j.ReconcilePending()
	j.resetNotes()
	pass := j.askCompleted(ask)
	restored = append(restored, j.applyCompleted(&pass)...)
	j.holdUnsettledDirs()
	report.CompletedKept = append(report.CompletedKept, pass.kept...)
	outcome := j.settledOutcome(nil)
	if j.gate.lost {
		holdUnavailable(report, j, restored)
		return
	}
	report.CompletedRestored = append(report.CompletedRestored, restored...)
	collectHeld(report, j, outcome)
	if outcome.JournalPath != "" {
		retained := &report.Retained[len(report.Retained)-1]
		retained.Unanswered = pass.unanswered
	}
}

func (j *Journal) askCompleted(ask func(Unresolved) Choice) completedPass {
	j.mu.Lock()
	defer j.mu.Unlock()
	pass := completedPass{observed: make(map[string]fileState)}
	choose := func(u Unresolved) Choice {
		if ask == nil {
			return ChoiceDefer
		}
		if choice := ask(u); choice == ChoiceKeep || choice == ChoiceRestore && u.RestoreRefusal == "" {
			return choice
		}
		return ChoiceDefer
	}
	hold := func(label string, reasons []string) {
		pass.unanswered++
		if len(reasons) == 0 {
			reasons = []string{completedLeftAsIs}
		}
		for _, reason := range reasons {
			j.note(label + ": " + reason)
		}
	}
	inside, early := j.changedInsideMovedEntries()
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if pr.KeptByUser || pr.Progress == rollbackRestored || inside[pr.Path] && !early[pr.Path] || j.endpointOf(pr.Path, func(s moveState) bool { return s != moveUndone }) {
			continue
		}
		if pr.Progress == rollbackRestoring {
			pass.restore = append(pass.restore, pr)
			continue
		}
		if !j.beginOp(pr.Path, []string{pr.Path}) {
			continue
		}
		reasons, current, read := j.completionFailures(pr)
		j.endOp()
		refusal := ""
		if !read {
			refusal = reasons[len(reasons)-1]
		}
		reasons = append(reasons, j.retainedFor(pr.Path)...)
		switch {
		case pr.Mkdir && !pr.Delete && !pr.Move:
			if len(reasons) > 0 {
				j.holdDirs(pr, reasons, true)
			}
			continue
		case read && pr.Pending == nil && sameState(current, pr.Pre):
			if slices.Contains(reasons, dirNeverConfirmed) {
				j.holdDirs(pr, []string{dirNeverConfirmed}, false)
			}
			continue
		}
		u := Unresolved{Path: pr.Path, Completed: true, Reason: strings.Join(reasons, "; "), Choices: []Choice{ChoiceKeep, ChoiceRestore, ChoiceDefer}, RestoreRefusal: refusal}
		if refusal != "" {
			u.Choices = []Choice{ChoiceKeep, ChoiceDefer}
		}
		switch choose(u) {
		case ChoiceKeep:
			if !j.beginOp(pr.Path, []string{pr.Path}) {
				continue
			}
			pending := pr.Pending
			pr.KeptByUser, pr.Pending = true, nil
			if err := j.step("kept"); err != nil {
				pr.KeptByUser, pr.Pending = false, pending
				hold(pr.Path, []string{"the answer to keep it could not be recorded: " + err.Error()})
			} else {
				pass.kept = append(pass.kept, pr.Path)
			}
			j.endOp()
		case ChoiceRestore:
			pass.restore = append(pass.restore, pr)
			pass.observed[pr.Path] = current
		default:
			hold(pr.Path, reasons)
		}
	}

	scheduled := make(map[string]bool, len(pass.restore))
	for _, pr := range pass.restore {
		scheduled[pr.Path] = true
	}
	beneath := j.completedBeneath(scheduled)
	for _, group := range j.moveGroups() {
		if !slices.ContainsFunc(group, func(i int) bool { return j.rec.Moves[i].State != moveUndone }) {
			continue
		}
		label, endpoints := j.groupLabel(group), endpointsOf(j.rec.Moves, group)
		if j.undoResumes(group) {
			j.note(label + ": " + completedUndoUnfinished)
			continue
		}
		if !j.beginOp(label, endpoints) {
			continue
		}
		observed, refusal := j.restoreRefusalWith(group, beneath)
		var reasons []string
		for _, path := range endpoints {
			if pr := j.record(path); pr != nil {
				found, _, _ := j.completionFailures(pr)
				for _, reason := range append(found, j.retainedFor(path)...) {
					reasons = append(reasons, path+": "+reason)
				}
			}
		}
		j.endOp()
		u := j.groupQuestion(group, refusal)
		u.Completed, u.Reason = true, strings.Join(reasons, "; ")
		switch choose(u) {
		case ChoiceKeep:
			if !j.beginOp(label, endpoints) {
				continue
			}
			if ans, err := j.publishAnswer(group, ChoiceKeep, nil); err != nil {
				hold(label, []string{"the answer to keep these moves could not be recorded: " + err.Error()})
			} else {
				if err := j.settleKept(ans); err != nil {
					j.note("the kept moves could not be recorded as settled: " + err.Error())
				}
				pass.kept = append(pass.kept, ans.Endpoints...)
			}
			j.endOp()
		case ChoiceRestore:
			pass.groups = append(pass.groups, completedGroup{group: group, observed: observed})
		default:
			hold(label, reasons)
		}
	}
	return pass
}

func (j *Journal) applyCompleted(pass *completedPass) []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var restored []string
	for _, pr := range pass.restore {
		if !j.beginOp(pr.Path, []string{pr.Path}) {
			continue
		}
		waiting := j.awaitsCreatedDir(pr)
		if dep := j.heldBeneath(pr.Path); waiting && dep != "" {
			j.note(pr.Path + ": it was not put back because " + dep + " inside it is kept or left for later")
			pass.unanswered++
			j.endOp()
			continue
		}
		if observed, asked := pass.observed[pr.Path]; asked && !j.authorizeRestore(pr, observed) {
			pass.unanswered++
			j.endOp()
			continue
		}
		named := func(path string) bool { return path == pr.Path }
		restored = j.restorePaths(restored, named)
		j.removeCreatedDirs(func(_, dir string) bool { return dir == pr.Path })
		if waiting {
			restored = j.restorePaths(restored, named)
		}
		j.endOp()
	}

	inside, _ := j.changedInsideMovedEntries()
	endpoints := make(map[string]bool)
	for _, m := range j.rec.Moves {
		if m.State != moveUndone && j.answerOf(m) != ChoiceKeep {
			endpoints[m.Source], endpoints[m.Destination] = true, true
		}
	}
	j.removeCreatedDirs(func(owner, dir string) bool { return inside[owner] && !endpoints[dir] && j.removableDir(owner, dir) })
	for _, g := range pass.groups {
		label, members := j.groupLabel(g.group), endpointsOf(j.rec.Moves, g.group)
		if !j.beginOp(label, members) {
			continue
		}
		again, refusal := j.restoreRefusalWith(g.group, j.completedBeneath(nil))
		if refusal == "" && !sameObservations(g.observed, again) {
			refusal = "an endpoint changed while the question was open"
		}
		if refusal == "" {
			refusal = j.settleDirsInside(g.group)
		}
		if refusal != "" {
			j.note(label + ": these moves were not put back and are asked about again at the next launch: " + refusal)
			pass.unanswered++
		} else if ans, err := j.publishAnswer(g.group, ChoiceRestore, again); err != nil {
			j.note(label + ": the answer to put these moves back could not be recorded: " + err.Error())
			pass.unanswered++
		} else {
			changed, _ := j.restoreGroup(g.group, ans.Endpoints)
			for _, path := range changed {
				if !slices.Contains(restored, path) {
					restored = append(restored, path)
				}
			}
		}
		j.endOp()
	}
	j.removeCreatedDirs(j.removableDir)
	return restored
}

func (j *Journal) authorizeRestore(pr *pathRecord, observed fileState) bool {
	current, err := j.targetState(pr)
	if err != nil || !sameState(current, observed) {
		j.note(pr.Path + ": it changed while the question was open, so it was not put back")
		return false
	}
	prior, progress := pr.LastKnown, pr.Progress
	pr.LastKnown, pr.Progress = observed, rollbackRestoring
	if err := j.step("adopted"); err != nil {
		pr.LastKnown, pr.Progress = prior, progress
		j.note(pr.Path + ": the answer to put it back could not be recorded: " + err.Error())
		return false
	}
	return true
}

func (j *Journal) completedBeneath(scheduled map[string]bool) func(destination string) bool {
	inside, early := j.changedInsideMovedEntries()
	return func(destination string) bool {
		return slices.ContainsFunc(j.rec.Paths, func(p pathRecord) bool {
			return inside[p.Path] && strings.HasPrefix(p.Path, destination+string(filepath.Separator)) &&
				(p.KeptByUser || j.noted(p.Path) || early[p.Path] && p.Progress != rollbackRestored && !scheduled[p.Path] && !createdDirOnly(&p))
		})
	}
}

func createdDirOnly(p *pathRecord) bool { return p.Mkdir && !p.Delete && !p.Move }

func (j *Journal) settleDirsInside(group []int) string {
	inside := func(path string) bool {
		return slices.ContainsFunc(group, func(i int) bool {
			return strings.HasPrefix(path, j.rec.Moves[i].Destination+string(filepath.Separator))
		})
	}
	j.removeCreatedDirs(func(owner, dir string) bool {
		r := j.record(owner)
		return r != nil && createdDirOnly(r) && inside(dir) && j.heldBeneath(dir) == ""
	})
	_, early := j.changedInsideMovedEntries()
	if slices.ContainsFunc(group, func(i int) bool { return j.unrestoredBeneath(early)(j.rec.Moves[i].Destination) }) {
		return "a directory the child agent created inside the moved entry could not be removed first"
	}
	return ""
}

func (j *Journal) removableDir(_, dir string) bool {
	return j.heldBeneath(dir) == "" && slices.ContainsFunc(j.rec.Paths, func(p pathRecord) bool {
		return p.Progress == rollbackRestored && permissions.IsDescendantOrEqual(p.Path, dir)
	})
}

func (j *Journal) heldBeneath(dir string) string {
	for i := range j.rec.Paths {
		p := &j.rec.Paths[i]
		if permissions.IsDescendantOrEqual(p.Path, dir) && (p.KeptByUser || j.noted(p.Path) || j.endpointOf(p.Path, func(s moveState) bool { return s != moveUndone })) {
			return p.Path
		}
	}
	return ""
}

func (j *Journal) holdUnsettledDirs() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		for k := range pr.Dirs {
			dr := &pr.Dirs[k]
			path := filepath.Join(pr.Ancestor, filepath.FromSlash(dr.Rel))
			if _, cur := j.currentDir(path); cur != dr || dr.Progress == rollbackRestored || dr.KeptByUser || dr.Confirmed && !dr.Created || slices.Contains(j.retainedDirs, path) {
				continue
			}
			if r := j.record(path); r != nil && r.Mkdir && r.KeptByUser {
				continue
			}
			reason, inspected := "", j.beginOp(path, []string{path})
			if inspected {
				reason = j.unsettledDir(pr, dr, path)
				j.endOp()
			}
			if !inspected || reason != "" {
				if reason != "" {
					j.note(path + ": " + reason)
				}
				j.retainedDirs = append(j.retainedDirs, path)
			}
		}
	}
}

func (j *Journal) unsettledDir(pr *pathRecord, dr *dirRecord, path string) string {
	if !dr.Confirmed {
		return errDirUnconfirmed.Error()
	}
	segs := strings.Split(dr.Rel, "/")
	parent, err := j.openDirChain(pr, segs[:len(segs)-1])
	if errors.Is(err, errSuffixAbsent) {
		return ""
	}
	if err != nil {
		return "the created directory's parent could not be safely reopened: " + err.Error()
	}
	defer parent.Close() //nolint:errcheck // read-only directory descriptor
	name := segs[len(segs)-1]
	dev, ino, err := entryIdentity(parent, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ""
	case err != nil:
		return "the created directory could not be identified: " + err.Error()
	case dev != dr.Dev || ino != dr.Ino:
		if dr.Mkdir && j.holdsRecordedState(path, parent, name) {
			return ""
		}
		return errDirReplaced.Error()
	}
	dir, err := openSubdirNoFollow(parent, name)
	if err != nil {
		return "the created directory could not be read: " + err.Error()
	}
	defer dir.Close() //nolint:errcheck // read-only directory descriptor
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return "the created directory could not be read: " + err.Error()
	}
	for _, n := range names {
		entry := filepath.Join(path, n)
		if _, d := j.currentDir(entry); j.record(entry) == nil && d == nil {
			return errDirHoldsEntries.Error()
		}
	}
	return ""
}

func (j *Journal) holdDirs(pr *pathRecord, reasons []string, declared bool) {
	for _, reason := range reasons {
		j.note(pr.Path + ": " + reason)
	}
	var dirs []string
	if declared {
		dirs = append(dirs, pr.Path)
	}
	for _, d := range pr.Dirs {
		if !d.Confirmed {
			dirs = append(dirs, filepath.Join(pr.Ancestor, filepath.FromSlash(d.Rel)))
		}
	}
	for _, dir := range dirs {
		if !slices.Contains(j.retainedDirs, dir) {
			j.retainedDirs = append(j.retainedDirs, dir)
		}
	}
}

func (j *Journal) retainedFor(path string) []string {
	var out []string
	for _, note := range j.rec.Retained {
		if reason, ok := strings.CutPrefix(note, path+": "); ok {
			out = append(out, reason)
		}
	}
	return out
}

func (j *Journal) noted(path string) bool {
	return slices.ContainsFunc(j.rec.Unrecovered, func(note string) bool { return strings.HasPrefix(note, path+": ") })
}

func collect(report *Report, j *Journal, outcome JournalOutcome) {
	if j.rec.Completed {
		report.CompletedRestored = append(report.CompletedRestored, outcome.Restored...)
	} else {
		report.Restored = append(report.Restored, outcome.Restored...)
	}
	if outcome.JournalPath == "" {
		return
	}
	notes := slices.DeleteFunc(slices.Clone(outcome.Unrecovered), func(note string) bool {
		return slices.ContainsFunc(outcome.HeldMoves, func(h HeldMove) bool { return h.note() == note }) ||
			slices.ContainsFunc(outcome.RetainedDirs, func(dir string) bool {
				return note == dir+": "+errDirHoldsEntries.Error() || note == dir+": "+errDirReplaced.Error()
			})
	})
	report.Retained = append(report.Retained, RetainedJournal{Path: outcome.JournalPath, Notes: notes, Moves: outcome.HeldMoves, Dirs: outcome.RetainedDirs, Completed: j.rec.Completed, Committed: j.rec.Lifecycle == lifecycleCommitted})
}

func holdBackLinkedParents(orphans []*Journal, held map[string]bool, unavailable map[string]string, report *Report, flush bool) []*Journal {
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
			note := "a linked nested child agent journal is unavailable, so this journal was not recovered: " + unavailable[j.dirName]
			if flush {
				collect(report, j, j.retain(note))
			} else {
				report.Retained = append(report.Retained, RetainedJournal{Path: j.path, Notes: []string{note}, Completed: j.rec.Completed})
			}
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
	if rec.SchemaVersion < journalSchemaVersion || rec.SchemaVersion > journalCompletedSchemaVersion {
		return nil, fmt.Errorf("subagent: journal schema version %d is not one this codemeld reads", rec.SchemaVersion)
	}
	if rec.Completed && rec.SchemaVersion < journalCompletedSchemaVersion {
		return nil, fmt.Errorf("subagent: a schema %d journal holds a completion marker", rec.SchemaVersion)
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

var errRecoveryStopped = errors.New("subagent: recovery stopped because the blocked-path list cannot be read")

func blockingEntry(snap *permissions.BlockedPaths, paths []string) (string, bool) {
	for _, path := range paths {
		if e, ok := snap.Blocking(path); ok {
			return e.Path, true
		}
		if e, ok := snap.BlockedWithin(path); ok {
			return e.Path, true
		}
	}
	return "", false
}

func (j *Journal) classify() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	snap, ok := j.gate.snapshot()
	if !ok {
		return false
	}
	for _, group := range j.moveGroups() {
		if !slices.ContainsFunc(group, func(i int) bool { return j.rec.Moves[i].State != moveUndone }) {
			continue
		}
		endpoints := endpointsOf(j.rec.Moves, group)
		if note, over := j.heldOver(endpoints); over {
			j.addHold(endpoints, note)
		} else if entry, blocked := blockingEntry(snap, endpoints); blocked {
			j.holdPolicy(j.groupLabel(group), endpoints, entry)
		}
	}
	for i := range j.rec.Paths {
		pr := &j.rec.Paths[i]
		if _, over := j.heldOver([]string{pr.Path}); over || pr.Progress == rollbackRestored || pr.KeptByUser {
			continue
		}
		if entry, blocked := blockingEntry(snap, []string{pr.Path}); blocked {
			j.holdPolicy(pr.Path, []string{pr.Path}, entry)
		}
	}
	return true
}

type opScope struct {
	label string
	paths []string
}

// On true the caller must call endOp; a nested call reuses the outer call's snapshot. Every open move
// group whose endpoints overlap paths is checked whole, so an operation inside a group's tree holds
// the group rather than changing part of it.
func (j *Journal) beginOp(label string, paths []string) bool {
	if j.gate == nil {
		return true
	}
	scopes := append(j.overlappingGroups(paths), opScope{label: label, paths: paths})
	for _, s := range scopes {
		if note, over := j.heldOver(s.paths); over {
			j.addHold(s.paths, note)
			return false
		}
	}
	snap, ok := j.gate.begin()
	if !ok {
		return false
	}
	for _, s := range scopes {
		if entry, blocked := blockingEntry(snap, s.paths); blocked {
			j.gate.end()
			j.holdPolicy(s.label, s.paths, entry)
			return false
		}
	}
	return true
}

func (j *Journal) endOp() {
	if j.gate != nil {
		j.gate.end()
	}
}

func (j *Journal) overlappingGroups(paths []string) []opScope {
	var scopes []opScope
	for _, group := range j.moveGroups() {
		if !slices.ContainsFunc(group, func(i int) bool { return j.rec.Moves[i].State != moveUndone }) {
			continue
		}
		endpoints := endpointsOf(j.rec.Moves, group)
		if slices.ContainsFunc(endpoints, func(e string) bool {
			return slices.ContainsFunc(paths, func(p string) bool {
				return permissions.IsDescendantOrEqual(p, e) || permissions.IsDescendantOrEqual(e, p)
			})
		}) {
			scopes = append(scopes, opScope{label: j.groupLabel(group), paths: endpoints})
		}
	}
	return scopes
}

func (j *Journal) heldOver(paths []string) (string, bool) {
	for _, root := range slices.Sorted(maps.Keys(j.policyRoots)) {
		if slices.ContainsFunc(paths, func(path string) bool {
			return permissions.IsDescendantOrEqual(path, root) || permissions.IsDescendantOrEqual(root, path)
		}) {
			return j.policyRoots[root], true
		}
	}
	return "", false
}

func (j *Journal) holdPolicy(label string, roots []string, entry string) {
	j.addHold(roots, label+": a blocked path is involved: "+entry)
}

func (j *Journal) addHold(roots []string, note string) {
	if j.policyRoots == nil {
		j.policyRoots = make(map[string]string)
	}
	if !slices.Contains(j.policyNotes, note) {
		j.policyNotes = append(j.policyNotes, note)
	}
	for _, root := range roots {
		if _, ok := j.policyRoots[root]; !ok {
			j.policyRoots[root] = note
		}
		j.rec.Unrecovered = slices.DeleteFunc(j.rec.Unrecovered, func(n string) bool {
			return strings.HasPrefix(n, root+": ") && !slices.Contains(j.rec.Retained, n) && !slices.Contains(j.policyNotes, n)
		})
	}
	j.note(note)
}

func (j *Journal) inheritHolds(child *Journal) {
	if len(child.policyRoots) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, root := range slices.Sorted(maps.Keys(child.policyRoots)) {
		j.addHold([]string{root}, child.policyRoots[root])
	}
}

func (j *Journal) groupLabel(group []int) string {
	return j.rec.Moves[group[0]].Source + " -> " + j.rec.Moves[group[0]].Destination
}

func (j *Journal) groupOf(i int) []int {
	for _, group := range j.moveGroups() {
		if slices.Contains(group, i) {
			return group
		}
	}
	return []int{i}
}
