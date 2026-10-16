package tui

import (
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	childA = "01920000-0000-7000-8000-00000000000a"
	childB = "01920000-0000-7000-8000-00000000000b"
)

func childStart(invocation string, declared ...string) events.ChildAgentStart {
	if len(declared) == 0 {
		declared = []string{"/project/notes.md"}
	}
	return events.ChildAgentStart{
		InvocationID:      invocation,
		ProviderID:        "openai",
		ModelID:           "gpt-5.5",
		DeclaredPaths:     declared,
		StepCap:           12,
		InstructionBytes:  42,
		InstructionDigest: strings.Repeat("a", 64),
	}
}

func childEnd(invocation, reason, rollback string, written ...string) events.ChildAgentEnd {
	return events.ChildAgentEnd{
		InvocationID:    invocation,
		Reason:          reason,
		Steps:           3,
		WrittenPaths:    written,
		RollbackOutcome: rollback,
		DurationMs:      1200,
	}
}

// A child agent that has started but not finished shows a block naming it, the paths it may
// write, and a running indicator — before any end notification exists.
func TestChildAgent_OpensARunningBlock(t *testing.T) {
	a := New(nil)
	a.Append("> prompt")
	a.ChildAgentStarted(childStart(childA, "/project/notes.md", "/project/todo.md"))

	want := "> prompt\n\n" + childAgentRunningHeading + "\n" +
		"  may write:\n" +
		"    /project/notes.md\n" +
		"    /project/todo.md"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("running block = %q, want %q", got, want)
	}
	if len(a.transcript.lines) != 2 {
		t.Fatalf("committed lines = %v, want the prompt plus one child block", a.transcript.lines)
	}
}

// A child's tool rounds update the block it already owns instead of committing new blocks,
// so the user watches one child working rather than a growing stack of fragments.
func TestChildAgent_UpdatesTheSameBlockWhileRunning(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childStart(childA))
	a.ChildAgentCalls(childA, []string{"Read /project/notes.md"})
	a.ChildAgentCalls(childA, []string{"Edit /project/notes.md", "Run: go build ./..."})

	want := childAgentRunningHeading + "\n" +
		"  may write:\n" +
		"    /project/notes.md\n" +
		"  Read /project/notes.md\n" +
		"  Edit /project/notes.md\n" +
		"  Run: go build ./..."
	if got := a.TranscriptText(); got != want {
		t.Fatalf("updated block = %q, want %q", got, want)
	}
	if len(a.transcript.lines) != 1 {
		t.Fatalf("committed lines = %v, want one child block updated in place", a.transcript.lines)
	}
}

// An empty round and a round for an invocation no block owns both commit nothing, so a
// stray payload can never invent or grow a block.
func TestChildAgent_UnknownOrEmptyUpdateCommitsNothing(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childStart(childA))
	before := a.TranscriptText()

	a.ChildAgentCalls(childB, []string{"Read /elsewhere.go"})
	a.ChildAgentCalls(childA, nil)
	a.ChildAgentEnded(childEnd(childB, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded))

	if got := a.TranscriptText(); got != before {
		t.Fatalf("transcript = %q, want it unchanged at %q", got, before)
	}
	if len(a.transcript.lines) != 1 {
		t.Fatalf("committed lines = %v, want only the one opened block", a.transcript.lines)
	}
}

// A start carrying no invocation id opens nothing: without an id no later payload could be
// routed to the block anyway.
func TestChildAgent_StartWithoutAnInvocationIDOpensNoBlock(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childStart(""))

	if len(a.transcript.lines) != 0 {
		t.Fatalf("committed lines = %v, want none", a.transcript.lines)
	}
}

// The closing block carries the terminal reason, what the step count counts, the rollback
// outcome, and the paths the child changed, and each non-completed reason reads distinctly
// from a clean finish.
func TestChildAgent_ClosesWithTheFullOutcome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reason   string
		rollback string
		want     string
	}{
		{
			name:     "completed",
			reason:   events.ChildAgentReasonCompleted,
			rollback: events.ChildRollbackNotNeeded,
			want: "✓ Child agent completed\n" +
				"  may write:\n    /project/notes.md\n" +
				"  3 provider request(s)\n" +
				"  changed 1 file(s), none undone:\n    /project/notes.md",
		},
		{
			name:     "cancelled",
			reason:   events.ChildAgentReasonCancelled,
			rollback: events.ChildRollbackRolledBack,
			want: "⚠ Child agent cancelled\n" +
				"  may write:\n    /project/notes.md\n" +
				"  3 provider request(s)\n" +
				"  changed 1 file(s), since undone:\n    /project/notes.md",
		},
		{
			name:     "step cap",
			reason:   events.ChildAgentReasonStepCap,
			rollback: events.ChildRollbackRolledBack,
			want: "⚠ Child agent stopped at its step cap\n" +
				"  may write:\n    /project/notes.md\n" +
				"  3 provider request(s)\n" +
				"  changed 1 file(s), since undone:\n    /project/notes.md",
		},
		{
			name:     "failed",
			reason:   events.ChildAgentReasonFailed,
			rollback: events.ChildRollbackUnrecovered,
			want: "⚠ Child agent failed\n" +
				"  may write:\n    /project/notes.md\n" +
				"  3 provider request(s)\n" +
				"  changed 1 file(s), which could not be undone and are still in the worktree:\n    /project/notes.md",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ChildAgentStarted(childStart(childA))
			a.ChildAgentEnded(childEnd(childA, tc.reason, tc.rollback, "/project/notes.md"))

			if got := a.TranscriptText(); got != tc.want {
				t.Fatalf("closed block = %q, want %q", got, tc.want)
			}
			if strings.Contains(a.TranscriptText(), childAgentRunningHeading) {
				t.Error("the closed block still shows the running indicator")
			}
		})
	}
}

// A child that changed nothing says so rather than printing an empty list, and every
// rollback outcome stays visible on that line — including the two that record no paths.
func TestChildAgent_ClosesWithNoChangedFiles(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rollback string
		want     string
	}{
		{
			name:     "clean",
			rollback: events.ChildRollbackNotNeeded,
			want:     "  " + childAgentNoFilesLine + ", so nothing needed undoing",
		},
		{
			name:     "undone",
			rollback: events.ChildRollbackRolledBack,
			want:     "  " + childAgentNoFilesLine + ", and its rollback completed",
		},
		{
			name:     "unrecovered",
			rollback: events.ChildRollbackUnrecovered,
			want:     "  " + childAgentNoFilesLine + ", and its rollback did not complete",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ChildAgentStarted(childStart(childA))
			a.ChildAgentEnded(childEnd(childA, events.ChildAgentReasonCompleted, tc.rollback))

			got := a.TranscriptText()
			if !strings.HasSuffix(got, "\n"+tc.want) {
				t.Fatalf("closed block = %q, want it to end with %q", got, tc.want)
			}
			if strings.Contains(got, "changed 0 file(s)") {
				t.Error("a child that changed nothing rendered a file count")
			}
		})
	}
}

// A written-path list the record bounded renders the prefix it kept plus the true total, so
// the block never reads as though the child changed only what fits.
func TestChildAgent_ClosesWithATruncatedChangedList(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childStart(childA))
	end := childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, "/project/a.go", "/project/b.go")
	end.WrittenPathsTotal = 30
	a.ChildAgentEnded(end)

	got := a.TranscriptText()
	for _, want := range []string{"changed 30 file(s), none undone:", "    /project/a.go", "    /project/b.go", "    … and 28 more"} {
		if !strings.Contains(got, want) {
			t.Fatalf("closed block = %q, want it to contain %q", got, want)
		}
	}
}

// A list that exactly fills the display bound prints every path and no "more" line; one path
// past it prints the bound plus the remainder.
func TestChildAgent_ChangedListBound(t *testing.T) {
	atCap := make([]string, maxChildAgentPaths)
	for i := range atCap {
		atCap[i] = "/project/at" + string(rune('a'+i)) + ".go"
	}

	a := New(nil)
	a.ChildAgentStarted(childStart(childA))
	a.ChildAgentEnded(childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, atCap...))
	if got := a.TranscriptText(); strings.Contains(got, "more") {
		t.Fatalf("a list at the display bound = %q, want no truncation marker", got)
	}
	for _, path := range atCap {
		if !strings.Contains(a.TranscriptText(), "    "+path) {
			t.Fatalf("closed block dropped %q", path)
		}
	}

	b := New(nil)
	b.ChildAgentStarted(childStart(childB))
	b.ChildAgentEnded(childEnd(childB, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, append(append([]string{}, atCap...), "/project/extra.go")...))
	got := b.TranscriptText()
	if !strings.Contains(got, "    … and 1 more") {
		t.Fatalf("a list one past the display bound = %q, want a truncation marker", got)
	}
	if strings.Contains(got, "/project/extra.go") {
		t.Fatalf("a list one past the display bound = %q, want the overflow path folded into the marker", got)
	}
}

// Two children whose lifetimes overlap keep their own blocks: every line lands in the block
// its invocation id names, nothing interleaves, and a payload arriving after its own end is
// dropped rather than absorbed by the child still running.
func TestChildAgent_RoutesByInvocationIDAlone(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childStart(childA, "/project/a.go"))
	a.ChildAgentCalls(childA, []string{"Read /project/a.go"})
	a.ChildAgentStarted(childStart(childB, "/project/b.go"))
	a.ChildAgentCalls(childB, []string{"Read /project/b.go"})
	a.ChildAgentCalls(childA, []string{"Edit /project/a.go"})
	a.ChildAgentEnded(childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, "/project/a.go"))
	// Both arrive after A's end while B is still open: neither may reach B's block.
	a.ChildAgentCalls(childA, []string{"Read /late.go"})
	a.ChildAgentEnded(childEnd(childA, events.ChildAgentReasonFailed, events.ChildRollbackRolledBack, "/project/late.go"))
	a.ChildAgentCalls(childB, []string{"Edit /project/b.go"})

	blockA := "✓ Child agent completed\n" +
		"  may write:\n    /project/a.go\n" +
		"  Read /project/a.go\n" +
		"  Edit /project/a.go\n" +
		"  3 provider request(s)\n" +
		"  changed 1 file(s), none undone:\n    /project/a.go"
	blockB := childAgentRunningHeading + "\n" +
		"  may write:\n    /project/b.go\n" +
		"  Read /project/b.go\n" +
		"  Edit /project/b.go"
	if got := a.TranscriptText(); got != blockA+"\n\n"+blockB {
		t.Fatalf("overlapping children = %q, want %q", got, blockA+"\n\n"+blockB)
	}
	if len(a.transcript.lines) != 2 {
		t.Fatalf("committed lines = %v, want exactly one block per child", a.transcript.lines)
	}
}

// Parent tool activity committed while a child runs stays its own block, and the child's
// later rounds still land inside the child's block rather than after the parent's.
func TestChildAgent_ParentActivityStaysOutsideTheChildBlock(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childStart(childA, "/project/a.go"))
	a.AppendToolActivity([]string{"Run: go test ./..."})
	a.ChildAgentCalls(childA, []string{"Edit /project/a.go"})
	a.AppendToolActivity([]string{"Read /project/other.go"})

	want := childAgentRunningHeading + "\n" +
		"  may write:\n    /project/a.go\n" +
		"  Edit /project/a.go" +
		"\n\nRun: go test ./..." +
		"\n\nRead /project/other.go"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("interleaved parent activity = %q, want %q", got, want)
	}
}

// /clear drops the block index with the lines it pointed at, so a child payload arriving
// after the reset cannot rewrite a line that now belongs to the fresh session.
func TestChildAgent_ResetDropsOpenBlocks(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childStart(childA))
	a.ResetTranscript()
	a.Append("fresh")
	a.ChildAgentCalls(childA, []string{"Edit /project/notes.md"})
	a.ChildAgentEnded(childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded))

	if got := a.TranscriptText(); got != "fresh" {
		t.Fatalf("transcript after reset = %q, want only the post-reset line", got)
	}
}

func childDeleteStart(invocation string, write, remove []string) events.ChildAgentStart {
	start := childStart(invocation)
	start.DeclaredPaths, start.DeclaredDeletePaths = write, remove
	return start
}

func TestChildAgent_DeleteOnlyChildShowsDeleteAuthorityAndDeletion(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childDeleteStart(childA, nil, []string{"/project/old.md"}))

	running := childAgentRunningHeading + "\n" +
		"  may delete:\n    /project/old.md"
	if got := a.TranscriptText(); got != running {
		t.Fatalf("running block = %q, want %q", got, running)
	}

	end := childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded)
	end.DeletedPaths = []string{"/project/old.md"}
	a.ChildAgentEnded(end)

	want := "✓ Child agent completed\n" +
		"  may delete:\n    /project/old.md\n" +
		"  3 provider request(s)\n" +
		"  deleted 1 file(s), none undone:\n    /project/old.md"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("closed block = %q, want %q", got, want)
	}
}

func TestChildAgent_LabelsWriteAndDeleteSeparately(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reason   string
		rollback string
		want     string
	}{
		{
			name:     "undone",
			reason:   events.ChildAgentReasonCancelled,
			rollback: events.ChildRollbackRolledBack,
			want: "⚠ Child agent cancelled\n" +
				"  may write:\n    /project/a.go\n" +
				"  may delete:\n    /project/old.go\n" +
				"  3 provider request(s)\n" +
				"  changed 1 file(s), since undone:\n    /project/a.go\n" +
				"  deleted 1 file(s), since undone:\n    /project/old.go",
		},
		{
			name:     "unrecovered",
			reason:   events.ChildAgentReasonFailed,
			rollback: events.ChildRollbackUnrecovered,
			want: "⚠ Child agent failed\n" +
				"  may write:\n    /project/a.go\n" +
				"  may delete:\n    /project/old.go\n" +
				"  3 provider request(s)\n" +
				"  changed 1 file(s), which could not be undone and are still in the worktree:\n    /project/a.go\n" +
				"  deleted 1 file(s), which could not be undone and are still missing from the worktree:\n    /project/old.go",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ChildAgentStarted(childDeleteStart(childA, []string{"/project/a.go"}, []string{"/project/old.go"}))
			end := childEnd(childA, tc.reason, tc.rollback, "/project/a.go")
			end.DeletedPaths = []string{"/project/old.go"}
			a.ChildAgentEnded(end)

			if got := a.TranscriptText(); got != tc.want {
				t.Fatalf("closed block = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestChildAgent_ClosesWithATruncatedDeletedList(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childDeleteStart(childA, nil, []string{"/project/old"}))
	end := childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded)
	end.DeletedPaths = []string{"/project/old/a.go", "/project/old/b.go"}
	end.DeletedPathsTotal = 30
	a.ChildAgentEnded(end)

	got := a.TranscriptText()
	for _, want := range []string{"deleted 30 file(s), none undone:", "    /project/old/a.go", "    /project/old/b.go", "    … and 28 more"} {
		if !strings.Contains(got, want) {
			t.Fatalf("closed block = %q, want it to contain %q", got, want)
		}
	}
	if strings.Contains(got, "changed") {
		t.Fatalf("closed block = %q, want no changed-files line for a delete-only child", got)
	}
}

func TestReplaySessionRecords_DeleteChildBlockMatchesTheLivePath(t *testing.T) {
	start := childDeleteStart(childA, []string{"/project/a.go"}, []string{"/project/old.go"})
	end := childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, "/project/a.go")
	end.DeletedPaths = []string{"/project/old.go"}

	live := New(nil)
	live.ChildAgentStarted(start)
	live.ChildAgentEnded(end)

	replayed := New(nil)
	replayed.ReplaySessionRecords([]sessions.Record{childStartEvent(start), childEndEvent(end)})

	if got, want := replayed.TranscriptText(), live.TranscriptText(); got != want {
		t.Fatalf("replayed block = %q, want the live block %q", got, want)
	}
	if !strings.Contains(replayed.TranscriptText(), "  deleted 1 file(s), none undone:\n    /project/old.go") {
		t.Fatalf("replayed block = %q, want the deletion shown", replayed.TranscriptText())
	}
}

func TestReplaySessionRecords_ChildRecordsWithoutDeleteFieldsShowNoDeleteAuthority(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		rawEvent(events.KindChildAgentStart, `{"invocation_id":"`+childA+`","provider_id":"openai","model_id":"m","declared_paths":["/project/a.go"],"step_cap":12,"instruction_bytes":4,"instruction_digest":"`+strings.Repeat("a", 64)+`"}`),
		rawEvent(events.KindChildAgentEnd, `{"invocation_id":"`+childA+`","reason":"completed","steps":3,"written_paths":["/project/a.go"],"rollback_outcome":"not_needed","duration_ms":1}`),
	})

	want := "✓ Child agent completed\n" +
		"  may write:\n    /project/a.go\n" +
		"  3 provider request(s)\n" +
		"  changed 1 file(s), none undone:\n    /project/a.go"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed legacy block = %q, want %q", got, want)
	}
}

func childMoveStart(invocation string, pairs ...events.ChildMovePair) events.ChildAgentStart {
	start := childStart(invocation)
	start.DeclaredPaths, start.DeclaredMovePairs = nil, pairs
	return start
}

var childMovedPair = events.ChildMovePair{Source: "/project/old.md", Destination: "/project/new.md"}

func TestChildAgent_MoveOnlyChildShowsMoveAuthorityAndMove(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childMoveStart(childA, childMovedPair))

	running := childAgentRunningHeading + "\n" +
		"  may move:\n    /project/old.md -> /project/new.md"
	if got := a.TranscriptText(); got != running {
		t.Fatalf("running block = %q, want %q", got, running)
	}

	end := childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded)
	end.MovedPairs = []events.ChildMovePair{childMovedPair}
	a.ChildAgentEnded(end)

	want := "✓ Child agent completed\n" +
		"  may move:\n    /project/old.md -> /project/new.md\n" +
		"  3 provider request(s)\n" +
		"  moved 1 file(s), none undone:\n    /project/old.md -> /project/new.md"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("closed block = %q, want %q", got, want)
	}
}

func TestChildAgent_AMoveThatCouldNotBeUndoneSaysItIsStillAtItsNewPath(t *testing.T) {
	a := New(nil)
	a.ChildAgentStarted(childMoveStart(childA, childMovedPair))
	end := childEnd(childA, events.ChildAgentReasonFailed, events.ChildRollbackUnrecovered)
	end.MovedPairs = []events.ChildMovePair{childMovedPair}
	a.ChildAgentEnded(end)

	want := "  moved 1 file(s), which could not be undone and are still at their new paths:\n    /project/old.md -> /project/new.md"
	if got := a.TranscriptText(); !strings.HasSuffix(got, want) {
		t.Fatalf("closed block = %q, want it to end with %q", got, want)
	}
}

func TestReplaySessionRecords_MoveChildBlockMatchesTheLivePath(t *testing.T) {
	start := childMoveStart(childA, childMovedPair)
	end := childEnd(childA, events.ChildAgentReasonCancelled, events.ChildRollbackRolledBack)
	end.MovedPairs = []events.ChildMovePair{childMovedPair}

	live := New(nil)
	live.ChildAgentStarted(start)
	live.ChildAgentEnded(end)

	replayed := New(nil)
	replayed.ReplaySessionRecords([]sessions.Record{childStartEvent(start), childEndEvent(end)})

	if got, want := replayed.TranscriptText(), live.TranscriptText(); got != want {
		t.Fatalf("replayed block = %q, want the live block %q", got, want)
	}
	if !strings.Contains(replayed.TranscriptText(), "  moved 1 file(s), since undone:\n    /project/old.md -> /project/new.md") {
		t.Fatalf("replayed block = %q, want the move shown", replayed.TranscriptText())
	}
}

// The child lifecycle is driven from the child's own goroutine, so the surface has to
// marshal onto the event loop. The -race build would flag a direct off-loop mutation here.
func TestChildAgent_OffLoopMarshalsThroughQueue(t *testing.T) {
	a, stop := newRunningApp(t)

	a.ChildAgentStarted(childStart(childA))
	a.ChildAgentCalls(childA, []string{"Edit /project/notes.md"})
	a.ChildAgentEnded(childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, "/project/notes.md"))

	want := "✓ Child agent completed\n" +
		"  may write:\n    /project/notes.md\n" +
		"  Edit /project/notes.md\n" +
		"  3 provider request(s)\n" +
		"  changed 1 file(s), none undone:\n    /project/notes.md"
	if got := transcriptText(t, a); got != want {
		a.app.Stop()
		t.Fatalf("rendered transcript = %q, want %q", got, want)
	}
	stop()
}
