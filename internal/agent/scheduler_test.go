// Unit tests for Schedule: parallelism under max_concurrency, sequential mode, dependency ordering,
// conflicting-target serialization, plan validation, run-error/cancellation propagation, and the
// absence of any prompt-specific handling (delegated to the shared gate).
package agent

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUnit is a test stand-in for WorkUnit. A nil run behaves as an immediate success.
type fakeUnit struct {
	id      string
	deps    []string
	targets []string
	run     func(ctx context.Context) error
}

func (f fakeUnit) ID() string        { return f.id }
func (f fakeUnit) Deps() []string    { return f.deps }
func (f fakeUnit) Targets() []string { return f.targets }
func (f fakeUnit) Run(ctx context.Context) error {
	if f.run == nil {
		return nil
	}
	return f.run(ctx)
}

// tracker records concurrency peak and unit start order across a schedule.
type tracker struct {
	mu      sync.Mutex
	running int
	peak    int
	order   []string
}

func (t *tracker) enter(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running++
	if t.running > t.peak {
		t.peak = t.running
	}
	t.order = append(t.order, id)
}

func (t *tracker) leave() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running--
}

func (t *tracker) peakConcurrency() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peak
}

func (t *tracker) startOrder() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.order)
}

// countingUnit increments counter once when run; used to assert nothing runs on an invalid plan.
func countingUnit(id string, deps []string, counter *int32) fakeUnit {
	return fakeUnit{id: id, deps: deps, run: func(context.Context) error {
		atomic.AddInt32(counter, 1)
		return nil
	}}
}

// TestScheduleRunsIndependentUnitsInParallel asserts that with maxConcurrency=3 three independent
// units all run at once (each blocks until every one has started). This also demonstrates the
// scheduler adds no prompt-specific serialization: independent Run calls overlap freely, since
// permission-prompt non-overlap is the shared gate's job, not the scheduler's.
func TestScheduleRunsIndependentUnitsInParallel(t *testing.T) {
	const n = 3
	started := make(chan struct{}, n)
	release := make(chan struct{})
	mk := func(id string) fakeUnit {
		return fakeUnit{id: id, run: func(ctx context.Context) error {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}}
	}
	work := []WorkUnit{mk("a"), mk("b"), mk("c")}

	errCh := make(chan error, 1)
	go func() { errCh <- Schedule(context.Background(), work, 3) }()

	for i := range n {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d units started concurrently; want all running in parallel", i, n)
		}
	}
	close(release)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Schedule returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Schedule did not return after units were released")
	}
}

// TestScheduleMaxConcurrencyOneRunsSequentially asserts maxConcurrency=1 never overlaps work and runs
// in input order.
func TestScheduleMaxConcurrencyOneRunsSequentially(t *testing.T) {
	var tr tracker
	mk := func(id string) fakeUnit {
		return fakeUnit{id: id, run: func(context.Context) error {
			tr.enter(id)
			time.Sleep(5 * time.Millisecond) // widen the window so wrongful parallelism would overlap
			tr.leave()
			return nil
		}}
	}
	work := []WorkUnit{mk("a"), mk("b"), mk("c")}

	if err := Schedule(context.Background(), work, 1); err != nil {
		t.Fatalf("Schedule returned %v, want nil", err)
	}
	if p := tr.peakConcurrency(); p != 1 {
		t.Fatalf("peak concurrency = %d, want 1 (maxConcurrency=1 must be sequential)", p)
	}
	if got := tr.startOrder(); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("start order = %v, want [a b c]", got)
	}
}

// TestScheduleHonorsDependencies asserts a unit waits for its declared dependency even when it
// appears earlier in input order and a free worker slot is available.
func TestScheduleHonorsDependencies(t *testing.T) {
	aStarted := make(chan struct{})
	aRelease := make(chan struct{})
	bStarted := make(chan struct{})
	a := fakeUnit{id: "a", run: func(context.Context) error {
		close(aStarted)
		<-aRelease
		return nil
	}}
	b := fakeUnit{id: "b", deps: []string{"a"}, run: func(context.Context) error {
		close(bStarted)
		return nil
	}}
	// b is first in input order but depends on a, so a must still run first.
	work := []WorkUnit{b, a}

	errCh := make(chan error, 1)
	go func() { errCh <- Schedule(context.Background(), work, 2) }()

	<-aStarted
	select {
	case <-bStarted:
		t.Fatal("b ran before its dependency a completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(aRelease)
	select {
	case <-bStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("b did not run after a completed")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Schedule returned %v, want nil", err)
	}
}

// TestScheduleSerializesConflictingTargets asserts two units with conflicting write targets run one
// after the other in input order, even with a spare worker slot — for both equal targets and an
// ancestor/descendant (overlapping path) pair.
func TestScheduleSerializesConflictingTargets(t *testing.T) {
	cases := []struct {
		name    string
		aTarget string
		bTarget string
	}{
		{"equal targets", "shared.txt", "shared.txt"},
		{"overlapping ancestor/descendant", "dir", "dir/file.txt"},
		{"casing variants of one entry", "Shared.txt", "shared.TXT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aStarted := make(chan struct{})
			aRelease := make(chan struct{})
			bStarted := make(chan struct{})
			a := fakeUnit{id: "a", targets: []string{tc.aTarget}, run: func(context.Context) error {
				close(aStarted)
				<-aRelease
				return nil
			}}
			b := fakeUnit{id: "b", targets: []string{tc.bTarget}, run: func(context.Context) error {
				close(bStarted)
				return nil
			}}
			work := []WorkUnit{a, b}

			errCh := make(chan error, 1)
			go func() { errCh <- Schedule(context.Background(), work, 2) }() // slot free, but targets conflict

			<-aStarted
			select {
			case <-bStarted:
				t.Fatal("b ran before a completed despite conflicting targets and maxConcurrency=2")
			case <-time.After(50 * time.Millisecond):
			}
			close(aRelease)
			select {
			case <-bStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("b did not run after a completed")
			}
			if err := <-errCh; err != nil {
				t.Fatalf("Schedule returned %v, want nil", err)
			}
		})
	}
}

// TestScheduleNonConflictingTargetsRunInParallel asserts sibling write targets (no ancestor relation)
// are treated as independent and allowed to run concurrently.
func TestScheduleNonConflictingTargetsRunInParallel(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	mk := func(id, target string) fakeUnit {
		return fakeUnit{id: id, targets: []string{target}, run: func(context.Context) error {
			started <- struct{}{}
			<-release
			return nil
		}}
	}
	work := []WorkUnit{mk("a", "dir/a"), mk("b", "dir/b")}

	errCh := make(chan error, 1)
	go func() { errCh <- Schedule(context.Background(), work, 2) }()

	for i := range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("sibling-target units did not run in parallel (%d started)", i)
		}
	}
	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("Schedule returned %v, want nil", err)
	}
}

// native spells each target the way the platform does, so the table below exercises backslash
// separators on Windows — the form schedulerTargets actually hands the scheduler (it builds a
// child's targets with filepath.Dir) — and is a no-op elsewhere.
func native(targets ...string) []string {
	out := make([]string, len(targets))
	for i, target := range targets {
		out[i] = filepath.FromSlash(target)
	}
	return out
}

// TestTargetsConflict checks the overlap predicate directly: equal, ancestor/descendant, and
// casing-variant targets conflict; siblings, non-segment prefixes, disjoint keys, and empty strings
// do not. Path-shaped targets are given in native form; the mixed-separator cases pin that a
// slash-spelled target still collides with its native twin, which on Windows is a different string.
func TestTargetsConflict(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"equal", native("a/b"), native("a/b"), true},
		{"ancestor", native("a"), native("a/b"), true},
		{"descendant", native("a/b/c"), native("a/b"), true},
		{"uncleaned-equal", native("a//b/"), native("a/b"), true},
		{"multi-target-hit", native("x", "a/b"), native("a/b/c", "y"), true},
		{"casing-variant-equal", native("a/Notes.txt"), native("a/notes.TXT"), true},
		{"casing-variant-ancestor", native("a/Shared"), native("a/shared/b.txt"), true},
		{"mixed-separator-equal", []string{"a/b"}, native("a/b"), true},
		{"mixed-separator-ancestor", []string{"a/b"}, native("a/b/c"), true},
		{"mixed-separator-descendant", []string{"a/b/c"}, native("a/b"), true},
		{"siblings", native("a/b"), native("a/c"), false},
		{"casing-variant-siblings", native("a/B"), native("a/c"), false},
		{"casing-variant-prefix-not-segment", []string{"Foo"}, []string{"foobar"}, false},
		{"prefix-not-segment", []string{"foo"}, []string{"foobar"}, false},
		{"mixed-separator-prefix-not-segment", []string{"a/b"}, native("a/bc"), false},
		{"disjoint", []string{"x"}, []string{"y"}, false},
		{"empty-string", []string{""}, native("a"), false},
		{"no-targets", nil, native("a"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetsConflict(tc.a, tc.b); got != tc.want {
				t.Fatalf("targetsConflict(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestScheduleRejectsInvalidPlans asserts duplicate IDs, unknown/self deps, and cycles fail before any
// unit runs, so a bad plan never partially executes.
func TestScheduleRejectsInvalidPlans(t *testing.T) {
	cases := []struct {
		name string
		work func(*int32) []WorkUnit
	}{
		{"duplicate ID", func(c *int32) []WorkUnit {
			return []WorkUnit{countingUnit("a", nil, c), countingUnit("a", nil, c)}
		}},
		{"unknown dep", func(c *int32) []WorkUnit {
			return []WorkUnit{countingUnit("a", []string{"ghost"}, c)}
		}},
		{"self dep", func(c *int32) []WorkUnit {
			return []WorkUnit{countingUnit("a", []string{"a"}, c)}
		}},
		{"two-node cycle", func(c *int32) []WorkUnit {
			return []WorkUnit{countingUnit("a", []string{"b"}, c), countingUnit("b", []string{"a"}, c)}
		}},
		{"three-node cycle", func(c *int32) []WorkUnit {
			return []WorkUnit{
				countingUnit("a", []string{"c"}, c),
				countingUnit("b", []string{"a"}, c),
				countingUnit("c", []string{"b"}, c),
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c int32
			if err := Schedule(context.Background(), tc.work(&c), 3); err == nil {
				t.Fatal("Schedule returned nil, want a plan-validation error")
			}
			if got := atomic.LoadInt32(&c); got != 0 {
				t.Fatalf("ran %d units on an invalid plan; want 0", got)
			}
		})
	}
}

// TestScheduleRejectsNonPositiveConcurrency asserts a maxConcurrency below 1 is rejected before any
// unit runs (production passes a config-validated value >= 1).
func TestScheduleRejectsNonPositiveConcurrency(t *testing.T) {
	var c int32
	for _, mc := range []int{0, -1} {
		if err := Schedule(context.Background(), []WorkUnit{countingUnit("a", nil, &c)}, mc); err == nil {
			t.Fatalf("maxConcurrency=%d: Schedule returned nil, want error", mc)
		}
	}
	if atomic.LoadInt32(&c) != 0 {
		t.Fatal("a unit ran despite invalid maxConcurrency")
	}
}

// TestScheduleReturnsRunErrorAndStopsDependents asserts a Run error is returned and that work
// depending on the failed unit is never launched.
func TestScheduleReturnsRunErrorAndStopsDependents(t *testing.T) {
	sentinel := errors.New("boom")
	var bRan int32
	a := fakeUnit{id: "a", run: func(context.Context) error { return sentinel }}
	b := fakeUnit{id: "b", deps: []string{"a"}, run: func(context.Context) error {
		atomic.AddInt32(&bRan, 1)
		return nil
	}}

	err := Schedule(context.Background(), []WorkUnit{a, b}, 2)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Schedule returned %v, want %v", err, sentinel)
	}
	if atomic.LoadInt32(&bRan) != 0 {
		t.Fatal("dependent b ran after its dependency a failed")
	}
}

// TestScheduleContextCancelledBeforeStart asserts an already-cancelled context returns the
// cancellation error and runs nothing.
func TestScheduleContextCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var c int32
	err := Schedule(ctx, []WorkUnit{countingUnit("a", nil, &c)}, 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Schedule returned %v, want context.Canceled", err)
	}
	if atomic.LoadInt32(&c) != 0 {
		t.Fatal("a unit ran despite an already-cancelled context")
	}
}

// TestScheduleContextCancelledDuringRun asserts cancellation propagates to a cooperating unit and is
// returned by Schedule.
func TestScheduleContextCancelledDuringRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	a := fakeUnit{id: "a", run: func(rctx context.Context) error {
		close(started)
		<-rctx.Done()
		return rctx.Err()
	}}

	errCh := make(chan error, 1)
	go func() { errCh <- Schedule(ctx, []WorkUnit{a}, 2) }()

	<-started
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Schedule returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Schedule did not return after cancellation")
	}
}

// TestScheduleHonorsCancellationDespiteUncooperativeUnit asserts the driver records caller
// cancellation even when the running unit ignores ctx and ultimately succeeds.
func TestScheduleHonorsCancellationDespiteUncooperativeUnit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	proceed := make(chan struct{})
	a := fakeUnit{id: "a", run: func(context.Context) error {
		close(started)
		<-proceed // ignores cancellation entirely
		return nil
	}}

	errCh := make(chan error, 1)
	go func() { errCh <- Schedule(ctx, []WorkUnit{a}, 2) }()

	<-started
	cancel()
	// While the unit is still blocked, the driver's only ready case is ctx.Done(); let it observe the
	// cancellation before the unit reports completion.
	time.Sleep(20 * time.Millisecond)
	close(proceed)
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Schedule returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Schedule did not return")
	}
}

// TestScheduleEmpty asserts an empty batch is a no-op success.
func TestScheduleEmpty(t *testing.T) {
	if err := Schedule(context.Background(), nil, 3); err != nil {
		t.Fatalf("Schedule(nil) returned %v, want nil", err)
	}
}
