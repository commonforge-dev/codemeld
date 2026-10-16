# How work happens here

_Last updated: 2026-10-16_

codemeld is built deliberately: a change starts from a clear, written description of the
problem and the behavior you intend — not an ad-hoc request — and it lands with tests and a
passing gate. This page orients you to that flow; it deliberately stays short and links out to
the authoritative sources rather than duplicating them.

## From an idea to shipped code

1. **Describe the change first.** Start from a written description of the problem and the
   behavior you intend, scoped tightly enough that a reviewer can tell when it is done.
2. **Build it against that scope, with tests.** Keep each change traceable to its description,
   and add or update tests for the behavior you touch.
3. **Run the gate and preserve the invariants** before you propose it (see below).
4. **Document it afterwards, separately.** Contributor documentation lands as its own follow-up
   change once the behavior has shipped (see below).

## Before you propose a change

- Run `mise run fmt` and `mise run check`. Before the change lands, also run
  `mise run check-race` — see [setup.md](setup.md) for the full command list and for the three
  checks that fail on purpose until you take a deliberate step.
- Both of those gates end with the shipping-set reference check, which fails if a file that ships
  to the public repository names an internal requirement tag, points at a directory that does
  not ship, or cites a task or ADR id. Public code and docs have to stand on their own for a
  reader who does not have those files, so fix the reference by stating the reason in plain words
  rather than re-pointing it. In Go files only comments are checked, so an id inside a string or
  an identifier passes; every other shipping file is checked in full. A token that merely looks
  like an id — a CPU architecture name, a fragment of a hash — is a false positive: add one exact
  entry for that file path and token to [`.oss-reference-allow`](../.oss-reference-allow) instead
  of loosening the pattern. A reference to a directory that does not ship can never be allowed.
  [`docs/gated-changes.md`](../docs/gated-changes.md) §5 has the full rules.
  The scanner builds its file list with `find` over the shipping roots, not from the VCS
  manifest — so an **untracked** scratch file you left under one of them fails `check` and
  `check-race` exactly like a committed one. Delete or move the scratch file.
- Keep the change tightly scoped and its intent clear.
- Preserve the project [invariants](invariants.md) — these are the things a reviewer will
  block a change for breaking.

## After resolving a merge

Merging is where a change most often picks up damage that every other check misses, so two
things are refused outright when work is integrated — before any review happens, and without
anything being deleted for you:

- **Conflict markers.** No file may still contain a `<<<<<<<`, `=======`, or `>>>>>>>` line.
  This bites hardest in a generated Markdown file, where the tool that rebuilds the file and the
  checker that validates it both look at the lines they own — so both can pass while marker
  blocks sit around those lines untouched. Resolve every block by hand and commit the result; a
  half-resolved file is reported by name and line number, and the merge is left in place for you
  to finish.
- **Merge backups.** No `*.orig` or `*.rej` may be left lying around. Mercurial writes these
  next to each file it merged, and an untracked one otherwise shows up later as a vague "dirty
  repository". Read each one first — it is the pre-merge copy, and it is sometimes the quickest
  way to recover content the merge mangled — then delete it yourself.

## Scoping a change

Decide the file scope before you start, and keep it. A change that stays inside the files its
description names is one a reviewer can check against that description; a change that grows
mid-flight is one nobody can tell is finished.

Two things reliably widen a diff, so plan for them:

- **Removing or renaming an exported symbol** pulls in every file that references it. Search for
  the symbol first (`rg '\bOldName\b'`) and decide up front whether those call sites belong in
  this change or a follow-up.
- **Changing behavior a snapshot test pins** turns into a fixture diff. That is intended — see
  [setup.md](setup.md) → "Checks that fail on purpose" for how to regenerate the saved copies so
  the change reads as deliberate.

If a change needs a decision nobody has made yet — provider scope, user-visible wording, event
ordering, whether a write refreshes live state — settle it in the written description before
you implement, not in review. Vague words like "persisted", "selectable", or "wired" should
become a concrete test before any code is written.

## Contributor documentation lands separately

The pages under `contributing/` are refreshed by hand, and they describe behavior that is already
in the tree. So a change ships the behavior on its own, and the documentation update follows as a
separate change afterwards — a page never describes a plan that is not implemented yet.

When you make that follow-up, name the exact pages it edits and refresh the `_Last updated:_` line
on each one. Which page owns what is unchanged:

- Toolchain, build, test, and gate commands → [setup.md](setup.md).
- How work happens and what you can run and verify from this repository → this page.
- Non-negotiables (egress, permissions, modes, root-confinement, atomic writes) →
  [invariants.md](invariants.md).
- Teaching material for a subsystem → its module under
  [`learning/`](learning/00-START-HERE.md).

## Reviewing your own change first

Before you propose a change, read your own diff against the description you started from:

- Every behavior you promised has evidence in the code or a test.
- The changed behavior is reachable from its real entrypoint, not only from a test helper.
- Each new branch and input kind you introduced is covered.
- Durable effects (settings, session records, grants) are read back from their real store in a
  test, not asserted from an in-memory value.
- Each new test actually protects the production behavior it names. When you are unsure, break
  that behavior on purpose, confirm the test fails, restore it, and confirm the test passes.

## Comments are absent by default

The comment policy is: **write no code comments by default, including on exported or public
symbols.** A comment earns its place only when the surrounding code, types, callers, and tests
could not otherwise reliably communicate a necessary constraint, invariant, reason, or
workaround — and then only the minimum wording. Directives (`//go:...`, build tags, `//nolint`)
and `//`/`/*` inside deliberately user-facing string or template output are exempt. There is no
rule that every exported symbol gets a doc comment; a comment that only restates a name, a
type, or the control flow below it should be deleted rather than reworded.

## Model-facing text: where to edit it, what checks it

codemeld sends the model more than one kind of instruction, and they do **not** share a gate. Find
the row you are changing before you edit — picking the wrong one is how a change lands untested.

| What you are changing | Edit here | What catches a change |
|---|---|---|
| Normal-turn base prompt (shared core + one block per mode) | the five embedded Markdown files in `internal/agentinstr/baseprompts/` (`shared.md`, `plan.md`, `build.md`, `auto_edits.md`, `special-instructions.md`) | the six golden fixtures — regenerate with `mise run snapshot-update` |
| Environment context block | `internal/agentinstr/envblock.go` (generated Go, not Markdown) | the same six golden fixtures |
| Title-generation instruction | `titleSystemPrompt` in `internal/turn/titlegen.go` | `go test ./internal/turn` — `TestGenerateTitle_RequestShape` pins it verbatim |
| Compaction instruction, and the wrapper stored summaries are replayed in | `compactionSummaryInstruction` and `compactionContextMessage` in `internal/turn/request.go` | `go test ./internal/turn` — `TestBuildCompactionSummaryRequest_ExactShape` and the `BuildRequest` compaction tests |
| Tool descriptions the model reads | each tool's `Advertise()` metadata in its own package (`internal/filetools`, `internal/vcs/tool.go`, `internal/bootstrap/tooldispatch_web.go`), plus `AskUserToolDefinition` / `BashToolDefinition` / `SuggestFollowupToolDefinition` in `internal/provider/tooldefs.go` | `internal/provider/tooldefs_test.go` pins the product definitions; registry metadata coverage varies by tool, with no shared exact-description test |

The first two rows are the normal-turn assembly sources the six fixtures cover, and only the first
row is Markdown at all — the environment block is generated Go. The six fixtures also pin the fourth
assembly section: `base_env_only.txt` and `with_agents.txt` cover an empty and a populated loaded
`AGENTS.md`, so they catch a change to how that text is assembled in, not to its wording. Rows three
and four are product-authored instruction text just as much — `titleSystemPrompt` and
`compactionSummaryInstruction` are inline Go you edit at their source, guarded by the focused
request-shape tests named beside them instead of by the fixtures. The guided maintainer editor offers
exactly those five Markdown files and nothing else; it does not edit a project's `AGENTS.md`, the
inline instructions, or a tool description.

Terms used here:

- **Assembled system message** — the hidden instruction message codemeld builds for a **normal
  chat turn**: mode base prompt, optional model-specific block, environment block, then loaded
  `AGENTS.md` text. A normal turn assembles at most one of these, and `BuildRequest` prepends it
  only when it is non-empty; the same request can still carry `system`-role records replayed from
  session history. Title and compaction are separate requests with their own fixed instructions.
- **Environment context block** — the generated `Environment:` section inside that message. It is
  code, not Markdown, and lists stable facts such as date, working directory, OS, project name, and
  version-control type.
- **Snapshot tests** — file-backed tests that compare the fully assembled normal-turn message with
  committed expected output, so prompt wording changes show up as an intentional fixture diff.

Keep the environment block prompt-cache friendly: do not add per-turn-volatile data such as current
branch/head, dirty status, or directory listings (see [invariants.md](invariants.md)).

Use [`learning/system-prompts.md`](learning/system-prompts.md) for the full inventory — every
model-facing source, its authority level, and its coverage. After changing prompt Markdown or the
environment block, run `mise run check`; if the snapshot check fires, follow
[setup.md](setup.md) → "Checks that fail on purpose" to regenerate the fixtures. Never hand-edit a
fixture.

## Where the rules live

- [`docs/architecture.md`](../docs/architecture.md) — cross-cutting design constraints and the
  reasoning behind the invariants.
- [setup.md](setup.md) — the toolchain, the build/test/lint commands, and the checks that fail
  on purpose.
- [`ROADMAP.md`](../ROADMAP.md) — the public direction/status document: where
  codemeld is now and where it is going. Update it when your change makes its current/shipped
  or future wording stale.

For contribution logistics — licensing, the code of conduct, and reporting a security issue
privately — see the top-level [`CONTRIBUTING.md`](../CONTRIBUTING.md) and
[`SECURITY.md`](../SECURITY.md).
