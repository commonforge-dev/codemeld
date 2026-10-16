// Parallel agent work scheduling: runs a single assistant turn's independent work units up to
// agent.max_concurrency at a time, while serializing on declared dependencies and conflicting write
// targets. Permission-prompt non-overlap is NOT handled here — each
// unit's Run authorizes independently and the shared single-slot prompt gate guarantees
// prompts never overlap, so this package imports no dispatch, permission, or UI collaborators.
package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// WorkUnit is one independently schedulable piece of a single assistant turn. The scheduler orders
// units by their declared dependencies and conflicting write targets, then invokes Run; it never
// inspects what Run does. Run owns its own dispatch and authorization — the scheduler
// adds no prompt locking, batching, or pre-resolution (is the shared prompt gate's job).
type WorkUnit interface {
	// ID returns this unit's stable identifier, unique within one Schedule call. Other units name it
	// in their Deps to order after it.
	ID() string
	// Deps returns the IDs of units that must complete before this one runs. Every named ID must
	// belong to a unit in the same Schedule batch.
	Deps() []string
	// Targets returns the write target paths or resource keys this unit mutates, used only to
	// serialize conflicting writes. Read-only targets must not be listed. Two units with
	// equal or path-overlapping targets are run in input order rather than concurrently.
	Targets() []string
	// Run executes the unit. It should honor ctx cancellation; the scheduler cancels a context
	// derived from the caller's once any unit fails so cooperating units can stop early.
	Run(ctx context.Context) error
}

// Schedule runs work for a single assistant turn, executing up to maxConcurrency units concurrently
// while honoring dependency ordering and serializing units with conflicting write targets
// in input order. maxConcurrency=1 disables parallelism entirely. It
// returns the first error encountered: an invalid plan (maxConcurrency < 1, duplicate IDs, an unknown
// dependency, a self-dependency, or a dependency cycle) is reported before any unit runs, so a bad
// plan never partially executes; otherwise the first Run error or context cancellation is returned.
// On the first failure no further units are launched and the derived run context is cancelled;
// already-running units are awaited (they may finish or observe the cancellation) before Schedule
// returns.
//
// The scheduler is collaborator-agnostic: it only calls Run. Permission-prompt serialization
// is provided by the shared gated prompt binding the production authorizer wiring installs,
// not here, so concurrent Run calls authorize independently without the scheduler
// locking, queuing, or pre-resolving anything.
func Schedule(ctx context.Context, work []WorkUnit, maxConcurrency int) error {
	if maxConcurrency < 1 {
		// Defensive: production passes config.Cache.AgentMaxConcurrency() (validated >= 1, default 3).
		// A value < 1 would launch zero workers and hang, so fail fast instead.
		return fmt.Errorf("agent: maxConcurrency must be >= 1, got %d", maxConcurrency)
	}
	n := len(work)
	if n == 0 {
		return nil
	}

	indegree, succs, err := buildGraph(work)
	if err != nil {
		return err
	}
	if hasCycle(n, indegree, succs) {
		return fmt.Errorf("agent: dependency cycle among work units")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	return run(ctx, work, indegree, succs, maxConcurrency)
}

// buildGraph validates the plan and builds the "must run before" edge set: a predecessor->successor
// edge for every declared dependency and an input-order edge between every pair of units
// with conflicting write targets. It returns each unit's predecessor count (indegree) and
// successor list, or an error for a duplicate ID, an unknown dependency, or a self-dependency.
// Duplicate edges (a dependency that is also a target conflict) are collapsed so indegree counts each
// predecessor once.
func buildGraph(work []WorkUnit) (indegree []int, succs [][]int, err error) {
	n := len(work)
	index := make(map[string]int, n)
	for i, w := range work {
		id := w.ID()
		if _, dup := index[id]; dup {
			return nil, nil, fmt.Errorf("agent: duplicate work-unit ID %q", id)
		}
		index[id] = i
	}

	indegree = make([]int, n)
	succs = make([][]int, n)
	edges := make(map[[2]int]bool)
	addEdge := func(from, to int) {
		if from == to {
			return
		}
		key := [2]int{from, to}
		if edges[key] {
			return
		}
		edges[key] = true
		succs[from] = append(succs[from], to)
		indegree[to]++
	}

	for i, w := range work {
		for _, dep := range w.Deps() {
			j, ok := index[dep]
			if !ok {
				return nil, nil, fmt.Errorf("agent: work unit %q depends on unknown ID %q", w.ID(), dep)
			}
			if j == i {
				return nil, nil, fmt.Errorf("agent: work unit %q depends on itself", w.ID())
			}
			addEdge(j, i) // dependency j must run before i
		}
	}

	// Conflicting writes serialize in input order: earlier unit before later unit.
	for i := range n {
		for j := i + 1; j < n; j++ {
			if targetsConflict(work[i].Targets(), work[j].Targets()) {
				addEdge(i, j)
			}
		}
	}

	return indegree, succs, nil
}

// hasCycle reports whether the combined dependency/conflict graph cannot be fully ordered (Kahn's
// algorithm). It works on a copy of indegree so the live counts are left intact for execution. A
// cycle here includes a dependency that contradicts the input-order conflict serialization, which is
// likewise unsatisfiable and would otherwise deadlock the run.
func hasCycle(n int, indegree []int, succs [][]int) bool {
	deg := make([]int, n)
	copy(deg, indegree)
	queue := make([]int, 0, n)
	for i := range n {
		if deg[i] == 0 {
			queue = append(queue, i)
		}
	}
	ordered := 0
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		ordered++
		for _, w := range succs[v] {
			deg[w]--
			if deg[w] == 0 {
				queue = append(queue, w)
			}
		}
	}
	return ordered != n
}

// unitResult reports one unit's completion back to the driver goroutine.
type unitResult struct {
	idx int
	err error
}

// run drives concurrent execution. A single driver goroutine owns all scheduling state (unit status,
// live indegree, in-flight count, first error); worker goroutines only run a unit and report on the
// done channel, so no lock is needed. The driver launches ready units (indegree 0) in input order up
// to maxConcurrency, and on each success decrements its successors' indegree to unlock more. On the
// first error (a Run failure or context cancellation) it records the error, cancels the derived run
// context, stops launching, and drains the remaining in-flight units before returning.
func run(ctx context.Context, work []WorkUnit, indegree []int, succs [][]int, maxConcurrency int) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	n := len(work)
	const (
		pending = iota
		running
		done
	)
	state := make([]int, n)
	results := make(chan unitResult, n)
	inFlight := 0
	var firstErr error

	launchReady := func() {
		for inFlight < maxConcurrency {
			next := -1
			for i := range n {
				if state[i] == pending && indegree[i] == 0 {
					next = i
					break
				}
			}
			if next == -1 {
				return
			}
			state[next] = running
			inFlight++
			i := next
			go func() {
				results <- unitResult{idx: i, err: work[i].Run(runCtx)}
			}()
		}
	}

	launchReady()
	for inFlight > 0 {
		if firstErr != nil {
			// A failure (or cancellation) was already recorded: launch nothing new, just drain the
			// units still running. runCtx is cancelled so cooperating units can return promptly.
			<-results
			inFlight--
			continue
		}
		select {
		case res := <-results:
			inFlight--
			state[res.idx] = done
			if res.err != nil {
				firstErr = res.err
				cancel()
				continue
			}
			for _, s := range succs[res.idx] {
				indegree[s]--
			}
			launchReady()
		case <-ctx.Done():
			// Caller cancelled even though no unit reported it (e.g. units that ignore ctx). Stop
			// launching and drain; report the cancellation.
			firstErr = ctx.Err()
			cancel()
		}
	}
	return firstErr
}

// targetsConflict reports whether any target in a overlaps any target in b, meaning the two units
// write the same or nested locations and must not run concurrently.
func targetsConflict(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if targetsOverlap(x, y) {
				return true
			}
		}
	}
	return false
}

// targetsOverlap reports whether two write targets collide: equal after cleaning, or one a path
// ancestor of the other (so a directory write serializes against a write beneath it). Empty strings
// are treated as absent targets and never conflict. Sibling paths and resource keys that merely share
// a textual prefix without a path-segment boundary (e.g. "foo" vs "foobar") do not conflict.
func targetsOverlap(x, y string) bool {
	if x == "" || y == "" {
		return false
	}
	cx := foldTarget(x)
	cy := foldTarget(y)
	if cx == cy {
		return true
	}
	return isAncestor(cx, cy) || isAncestor(cy, cx)
}

// Whether a target's volume folds case cannot be established from the path, so every target is
// folded: on a case-sensitive volume that costs only conservative serialization of case-distinct
// entries, while a case-insensitive one never runs two names for one entry concurrently.
//
// Cleaning is filepath's, not path's, because targets reach the scheduler as native paths
// (subagenttool builds a child's from filepath.Dir). On Windows that rewrites a slash-spelled
// target to the native separator, so the two spellings of one path fold together and a descendant
// still matches its ancestor at a segment boundary.
func foldTarget(target string) string {
	return strings.ToLower(filepath.Clean(target))
}

// isAncestor reports whether anc is a strict path ancestor of desc, matching only at a segment
// boundary so "/a" is an ancestor of "/a/b" but not of "/ab". The boundary is the native separator,
// which foldTarget has already normalized both arguments to.
func isAncestor(anc, desc string) bool {
	sep := anc
	if !strings.HasSuffix(sep, string(filepath.Separator)) {
		sep += string(filepath.Separator)
	}
	return strings.HasPrefix(desc, sep)
}
