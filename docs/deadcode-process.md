# Deadcode process

How to run the `deadcode` tool, classify its findings, and turn real findings into
tracked cleanup work.

## Running deadcode

Two mise tasks are wired up:

```sh
mise run deadcode       # whole-program — starts from main(), reports truly unreachable funcs
mise run deadcode-test  # same but also starts from test entry points
```

Both filter output to `codemeld.dev/codemeld` packages only — stdlib and third-party
noise is suppressed.

Output format: `file.go:line:col: unreachable func: Name`

`deadcode-test` answers a different question — "what functions can no test reach?" — so
run it separately and triage its output separately.

## Stale allowlist warnings

`scripts/deadcode-check.sh` fails only on findings missing from `.deadcode-allow`. It also
warns, on stderr and without changing its exit status, about the inverse: allowlist entries
`deadcode` no longer reports.

A stale entry means the function is now reachable from `main()`, or was moved, renamed, or
already deleted. It is **not** authority to delete the function. The response is to remove the
now-pointless allowlist line — a deletion still needs tracked cleanup work and the
classification below. Nothing prunes the list automatically; leaving a stale entry never breaks
a build, it just keeps the list from staying tiny.

## Classifying each finding

A finding is not automatically a deletion target. Put each one in one of three buckets:

**1. Truly dead** — safe to delete.

- No call sites anywhere in the codebase (`rg 'FuncName'` returns only the definition).
- No tracked or planned follow-up work that will wire it up.
- Not an exported symbol held for a future public API.

Action: open tracked cleanup work (see below), then delete as part of it.

**2. Not yet integrated** — leave alone.

- The function is complete and tested but its bootstrap caller is stubbed.
- There is tracked or upcoming follow-up work that will wire it up.

How to check: search the project's tracked follow-up work for the function name or its
package. If some follow-up owns the wiring, note that owner next to the finding and move on.

Example: the settings-drift monitor `securitystate.NewMonitor` with `Monitor.Checkpoint`, and
the halt recorder `events.EmitSecurityStateHalt` — all are implemented and tested, but no
runtime startup path creates the monitor yet, so `deadcode` reports them until the tracked
wiring work lands.

**3. Intentional** — leave alone, document why.

- Test helpers that no production code calls by design.
- Exported symbols kept for a future public API surface.
- Code unreachable because of a known build-tag gap the tool cannot see.

Add a comment in the source or a note in this file so the next person does not
re-investigate.

## Grouping findings for cleanup

- Group findings **by package**, not by function. Functions in the same package share
  context and are fast to clean up together.
- One cleanup unit per package (or small cluster of related packages).
- Keep each cleanup unit to **≤6 functions** — larger batches are harder to review and
  harder to localize when `mise run check` fails.
- Each cleanup unit's completion criteria must name the specific functions deleted and
  prove they are gone — see "Verifying removal" below for the exact checkable items.

## No deletion without tracked work

Never delete or modify a dead function outside tracked cleanup work. The sequence is:

1. Run `mise run deadcode`, capture the output with the date.
2. Classify each finding (buckets above).
3. For bucket 1 findings, open tracked work to own the deletion.
4. Record the dated `deadcode` output alongside the cleanup work so a later check can
   verify the finding was real when the work started.
5. Implement the deletion as part of that work.
6. Before marking the work done, verify removal (see "Verifying removal").
7. Record each removed function alongside the work so the deletion can be traced and
   recovered later (see "Recovering a removal").
8. Account for skips. Alongside the work, list any finding it was scoped to delete or
   investigate but did not, and why (reclassified to bucket 2/3 with the reason, a live
   caller was found, deferred to named follow-up, etc.). Every finding must end as
   deleted, reclassified-with-reason, or explicitly deferred to named follow-up — never
   silently dropped.

## Verifying removal

Naming a function in the completion criteria is not proof it was deleted. For **every**
function the cleanup names, its completion criteria must include these checkable items:

- `rg '\bFuncName\b' <repo>` returns no hits other than ones the cleanup names and
  justifies (e.g. an unrelated identifier, a doc mention).
- `mise run deadcode` (and `mise run deadcode-test` when the finding came from it) no
  longer lists the function.
- `mise run check` passes clean.

Before the cleanup is accepted, confirm the diff deletes **every** function it names, and
that any function it did not delete is accounted for. This is a maintainer-review
expectation, not a new automated gate.

## Recovering a removal

So a deletion can be undone later, lean on Mercurial history — it is the source of truth.

- `hg grep --all 'FuncName'` — lists every revision the function appears in; the `-:` lines
  mark the changeset that removed it, and show the file it lived in.
- `hg log -r <removing-rev> -p path/to/file.go` — shows that changeset's patch; the deleted
  function appears as `-` lines, ready to lift back out (`hg diff -c <removing-rev>
  path/to/file.go` shows the same diff).
