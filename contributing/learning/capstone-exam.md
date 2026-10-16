# Capstone exam

> The modules taught the subsystems one at a time. The capstone checks whether you can **connect**
> them — trace one action across the whole codebase, answer questions that span modules, and make a
> real change. Do this after you've worked through the modules you care about (at least 3–8).

## Part 1 — The grand trace (open-book)

Trace a single user action end to end and write down the `file:function` chain at each hop. The
action: **you type `git log` and press Enter; the permission prompt appears; you choose "allow in
this folder permanently"; the command runs and its output appears in the transcript.**

Hops to fill in (each maps to a module):

1. **Input → submit** — how the typed line is parsed (slash vs prompt) and submitted. *(Module 10)*
2. **Prompt → request** — how a tool/shell request is built and a path scope is resolved. *(Modules 6, 5)*
3. **Authorize** — how `git log` is normalized to a canonical subject and matched (or prompted). *(Module 5)*
4. **The prompt UI** — the option order, and how the folder-grant decision flows back. *(Module 10)*
5. **Persist the grant** — where a folder grant is written, and what happens if that write fails. *(Modules 4, 11)*
6. **Execute** — how the command runs (no shell), and why every pipeline stage was authorized first. *(Module 6)*
7. **Record** — which events are appended, and how the session is flushed crash-safely. *(Module 7)*
8. **Render** — how the result reaches the transcript safely while the loop runs. *(Module 10)*

You're done with Part 1 when you can name the function at each hop without re-reading the module.

## Part 2 — Synthesis quiz (closed-book)

Take [`quizzes/capstone.md`](quizzes/capstone.md) closed-book. These questions deliberately span
modules. Grade against [`quizzes/capstone-key.md`](quizzes/capstone-key.md).

## Part 3 — Build / fix / test challenge (open-book)

Pick **one**:

**A. Write a cross-cutting test.** Choose an invariant you learned (e.g. "a folder grant doesn't match
a sibling," "the runner doesn't interpret a shell," "an empty project `permissions: []` doesn't revoke
global grants") and add a small passing test in the right package. Run `go test ./...` and find it
in the output. You're proving you can navigate to the right package and use its test harness.

**B. (Optional) Planted-bug hunt — clearly a learning exercise; revert when done.** Make a *deliberate*
one-line change that breaks an invariant, predict which test will fail first, then run `go test ./...`
to check your prediction. Good targets:
- In `internal/permissions/scope.go`, change `IsDescendantOrEqual` to a naive `strings.HasPrefix`
  check — predict which `scope_test.go` case catches it (hint: the "sibling prefix trap").
- In `internal/tools/registry.go`, reorder `builtinNames` — predict the failing test.

This drives home the module's recurring lesson: **the tests are the executable spec.** Revert your
change afterward (`hg revert`) and confirm `go test ./...` is green again.

## Done when

- You completed the Part 1 trace and can name the function at each hop.
- You scored the Part 2 synthesis quiz closed-book.
- You did one Part 3 challenge and `go test ./...` is green.

## Where to go next

- Re-read any module whose quiz exposed a gap (your [`progress.md`](progress.md) notes show which).
- Read [`../invariants.md`](../invariants.md) again — every line should now read as "obvious."
- Make a real contribution: the contribution workflow is in [`../workflow.md`](../workflow.md).
