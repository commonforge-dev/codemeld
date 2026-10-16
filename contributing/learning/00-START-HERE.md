# Learn the codemeld internals

_Last updated: 2026-10-10_

A self-paced curriculum for understanding this codebase the way someone who built it would —
not by reading every line, but by following the real dependency spine, building a mental model
of each subsystem, and **testing yourself** at each step.

It assumes you can read Go. It does not assume you know *this* codebase, tview, or the OpenAI
client. Where the code uses a non-obvious Go idiom, the module flags it.

## How this track is kept

The modules are snapshots: each one carries the date it was last current. They are not updated
when a feature changes. When someone starts studying a module, it is regenerated from the code
first, so refresh a module before you rely on it.

## How to use a module

Each module file follows the same shape:

1. **Goal** — what you'll be able to *do* afterward.
2. **Why it matters** — where this sits in the whole.
3. **Read (in order)** — specific shipping files, plus the relevant public docs under `docs/`.
4. **Mental model** — the few types and flows to internalize, with a `file:function` chain.
5. **Watch for (Go idioms)** — non-obvious patterns specific to this code.
6. **Quiz** — in `quizzes/module-NN.md`.
7. **Hands-on** — trace a flow, predict behavior then verify, locate a requirement, write a test.
8. **Done when** — an explicit self-check.

## The self-test loop (this is the part that proves you learned it)

For each module:

1. **Read** the module and the files it points to.
2. **Take the quiz closed-book.** Open `quizzes/module-NN.md`, write your answers down
   *without* looking at the code or the key.
3. **Self-grade** against `quizzes/module-NN-key.md`. The key cites the **file and
   function/symbol name** (not line numbers, which drift as the code changes) so a wrong answer
   points you straight back at what to re-read.
4. **Do the hands-on.** These are open-book by design — you run the app, run tests, trace code,
   and (sometimes) write a small test. They're where understanding becomes real.
5. **Record** your result in [`progress.md`](progress.md).

**Closed-book vs open-book:** quizzes are closed-book (recall), hands-on is open-book (apply).
If you can't answer a quiz question from memory after reading, that's the signal to re-read —
not to peek. The point isn't the score; it's finding the gaps.

## Module map

Order follows the real dependency spine. Core path first; module 11 is optional breadth.

| # | Module | Focus | Status |
|---|--------|-------|--------|
| 1 | [Orientation](module-01-orientation.md) | What codemeld is, the 5 differentiators, the constraints | available |
| 2 | [Core types & vocabulary](module-02-core-types.md) | The nouns: Session, Event, Config/Cache, PermissionEntry, Tool | available |
| 3 | [Bootstrap / the launch spine](module-03-bootstrap-launch.md) | `RunFresh` steps 0a–8, the orchestrator | available |
| 4 | [Config: load & compose](module-04-config.md) | Two-layer settings, discovery, the session Cache | available |
| 5 | [**Permissions** (the differentiator)](module-05-permissions.md) | Canonical subjects, lifetimes, path-scope, turn cache | **available** |
| 6 | [Dispatch & runner](module-06-dispatch-runner.md) | The two dispatch paths; how authorization wraps execution | available |
| 7 | [Sessions & events](module-07-sessions-events.md) | Append-only audit log, atomic writes, resume | available |
| 8 | [Turn & provider](module-08-turn-provider.md) | The streaming LLM turn, tool-call extraction, the sanctioned provider egress paths | available |
| 9 | [VCS templates](module-09-vcs-templates.md) | YAML-driven VCS, auto-detection, tie-breaking | available |
| 10 | [TUI](module-10-tui.md) | The tview app shell, slash commands, the permission prompt | available |
| 11 | [Infra & periphery](module-11-infra-breadth.md) *(optional)* | locks, fsutil, ids, paths, fserrors, recovery packages | available |
| — | [Capstone exam](capstone-exam.md) | A cumulative cross-module trace + a small build/fix/test challenge | available |

Looking specifically for system prompts? Start with the dedicated
[`system-prompts.md`](system-prompts.md) page, then use Module 12 for the wider agent-modes flow.

### Follow-on subsystems (post phase-1)

Modules 1–11 cover the original baseline. These cover newer subsystems; each module lands as the
code does.

| # | Module | Focus | Status |
|---|--------|-------|--------|
| 12 | [Agent modes & system prompt](module-12-agent-modes.md) | Plan / Build / Auto-edits, product-authored prompt, tool advertising | available |
| 13 | [Read-only navigation tools](module-13-readonly-tools.md) | `read`/`grep`/`glob`/`list`/`tree`, project-root confinement, codemeldignore | available |
| 14 | [Web research](module-14-web-search.md) | Exa `web_search` and direct `web_fetch`, advertised by default, per-host permission gate | **available** — quiz not written yet |
| 15 | [ChatGPT auth](module-15-chatgpt-auth.md) | `openai-chatgpt` provider, OAuth + dedicated response adapter | available |

> No module is currently **planned**: every subsystem listed above has code in the tree. A planned
> module, when one appears, is a stub pointing at the relevant design docs rather than a code
> walkthrough, and becomes a full module once the subsystem ships. Module 14 has landed but has no
> `quizzes/module-14.md` yet, so use its hands-on until the quiz is written. Markdown rendering of
> assistant replies is also in flight; it is folded into Module 10 (TUI) rather than getting its
> own module.

> Start at **Module 1** for the intended reading order, or jump straight to whichever subsystem you
> need — each module stands on its own (a couple note a helpful prerequisite at the top). Module 5
> (Permissions) is a good showcase of the format if you just want to kick the tires.

## Running things

All you need is the Go toolchain declared in [`../../go.mod`](../../go.mod) — see
[`../setup.md`](../setup.md). The hands-on exercises use
`CGO_ENABLED=0 go build -o codemeld ./cmd/codemeld`, `go test ./...` (or one package, e.g.
`go test ./internal/permissions`), and reading real `_test.go` files. Both the build and the full race test suite are confirmed green on this
codebase, so those steps work.
