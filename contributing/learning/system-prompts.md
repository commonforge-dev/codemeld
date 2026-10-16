# Model-facing instructions in codemeld

_Last updated: 2026-08-22_

This page is the inventory of **everything codemeld tells a model**: what each source is, which
request carries it, how much authority it has, and what test catches a change to it.

There is a common mistake this page exists to prevent: assuming the assembled system prompt is the
whole story. It is not. codemeld makes three different kinds of request, some of them carry more
than one `system` message, and tool descriptions are model-facing text that never touches the
prompt files at all.

## The inventory

| # | Source | Which request | Authority | How it gets there | What catches a change |
|---|---|---|---|---|---|
| 1 | Mode base prompt (`shared.md` + one of `plan.md`/`build.md`/`auto_edits.md`) | normal chat turn | product-authored `system` | `BasePrompt` → `AssembleSystemMessage` | golden fixtures (`mise run snapshot-update`) |
| 2 | Model-specific block (`special-instructions.md`) | normal chat turn | product-authored `system` | `SpecialInstructions(provider, modelID)` → `AssembleSystemMessage` | golden fixtures (`special_latex.txt` only) |
| 3 | Environment context block | normal chat turn | product-authored `system` | `EnvironmentBlock` → `AssembleSystemMessage` | golden fixtures |
| 4 | Loaded `AGENTS.md` text | normal chat turn | user/project text, inside the product `system` message | `SystemPrompt(entries)` → `AssembleSystemMessage` | golden fixtures (`with_agents.txt`, `base_env_only.txt`) |
| 5 | Advertised tool descriptions | normal chat turn (the `tools` field, not a message) | product-authored, model-facing | `advertisedTools` → `provider.Request.Tools` | `internal/provider/tooldefs_test.go` pins the two product definitions; registry metadata coverage varies by tool |
| 6 | Title instruction | separate title request | product-authored `system` | `titleSystemPrompt` in `GenerateTitle` | `TestGenerateTitle_RequestShape` |
| 7 | Compaction instruction | separate compaction request | product-authored `system` | `compactionSummaryInstruction` in `BuildCompactionSummaryRequest` | `TestBuildCompactionSummaryRequest_ExactShape` |
| 8 | Persisted `system` message records | normal and compaction requests | `system`, from session history | `messagesFromRecords` | `TestBuildRequest_CarriesToolContinuationHistory` |
| 9 | Stored compaction summaries | normal and compaction requests | **`user`** reference data, deliberately below instructions | `compactionContextMessage` in `messagesFromRecords` | `TestBuildRequest_ProjectsCompactionSummaryAfterInstructions`, `TestBuildRequest_InstructionLikeSummaryIsNeverASystemMessage` |

Rows 1–4 are the assembled system message, and the golden fixtures cover all four of those assembly
sections. Of those, rows 1–3 are the product-authored prompt text a maintainer edits; row 4 is
whatever a project's `AGENTS.md` happens to say, so the fixtures pin how it is assembled, not its
wording. Rows 6 and 7 are product-authored, editable instruction text as well — `titleSystemPrompt`
and `compactionSummaryInstruction` are inline Go literals you edit at their source, pinned by the
focused request-shape tests in the last column rather than by the fixtures. The guided maintainer
editor covers only the five embedded Markdown files behind rows 1–2.

## 1. The assembled system message (normal turns)

`AssembleSystemMessage` in `internal/agentinstr/assemble.go` joins four sections, in this order,
with a single blank line between them:

1. The active mode's base prompt — `BasePrompt(m)`, the shared core plus that mode's behavior block.
2. Optional model-specific special instructions — `SpecialInstructions(provider, modelID)`, usually
   empty.
3. The generated environment context block — `EnvironmentBlock(env)`.
4. Loaded `AGENTS.md` text — `SystemPrompt(entries)`.

`joinSections` trims and drops empty sections, so an unflagged model or a project with no
`AGENTS.md` leaves no dangling separator. Sections 1 and 3 are always present, so the message is
never empty. No section headings are emitted by code: every `##` you see in the output is literal
text inside the embedded Markdown, and the only code-generated literal is the `Environment:` prefix.

`newSystemPromptAssembler` in `internal/bootstrap/starttui.go` builds the closure once at launch and
calls it **once per turn dispatch**; the result is then frozen for every provider round within that
turn, so a `/mode` or `/model` switch takes effect on the next dispatch, not mid-turn.

### The assembled message is one conditional `system` message, not the request's only one

`BuildRequest` in `internal/turn/request.go` prepends the assembled message as a single `system`
message — **only when the assembler produced a non-empty string**, and only at index 0. Two things
follow that are easy to state wrongly:

- A request can carry **more than one** `system` message, because session history can contain
  persisted `system`-role records (see §5).
- A request can carry **none**, because an empty assembled prompt adds no message at all
  (`TestBuildRequest_EmptySystemPromptAddsNoMessage`).

For the ChatGPT-subscription provider there is a further wire-level step:
`responsesInstructionsAndInput` in `internal/provider/openai_chatgpt_client.go` removes every
`system` message from the input list and joins their content, in order, into the single top-level
`instructions` field. So "how many system messages" is a chat-completions question; on the
Responses API they all collapse into one string.

## 2. The five embedded Markdown prompt files

The product-authored prompt text lives in `internal/agentinstr/baseprompts/` and is embedded into
the binary with `//go:embed`:

- `shared.md` — the shared core used in every mode.
- `plan.md`, `build.md`, `auto_edits.md` — the mode-specific behavior blocks. `behaviorBlock` falls
  back to `build.md` for an unrecognized mode, so this section is never empty.
- `special-instructions.md` — per-model blocks, split on `## ` headings and selected by
  provider/model id in `internal/agentinstr/special.go`. Today exactly one model maps to one block.

These five files are the right place to change stable product instructions, mode behavior wording,
and shared tool-use rules. They are also **exactly** the set the guided maintainer editor offers —
nothing in §3 through §7 is reachable from that menu.

### What `shared.md` says about which files are in scope

`shared.md` carries the product's file-scope guidance, and it is worth reading as three separate
statements because they are easy to collapse into one:

- **Permission is not scope.** "Being permitted to change a file is never a reason to change it"
  (`## Deciding what to do`). Being allowed to write a path says nothing about whether the request
  wanted it written.
- **An unclear file stops.** The model must be able to point to the part of the request that
  requires a file before changing it, and ask the user when it cannot.
- **The stop is about files, not about re-approving the work.** The same section still says an
  explicit request to fix, implement, add, or change something *is* the authorization for that
  work, so a file the accepted request plainly requires needs no second approval round.

`## Making changes` then closes the other direction: the focused-diff rule forbids removing,
reverting, disabling, or resetting unrelated configuration, generated state, user changes, or
authorization state, not just adding unrelated work.

All of this is **prose asked of the model** — inventory row 1, product-authored `system` text. It
does not block a write. A model that ignored every word of it would still be stopped only by the
code-enforced boundaries in §4: mode posture, tool advertising, permission grants, and deny
envelopes. Treat the prompt text as defense in depth over those boundaries, never as a substitute
for one. The wording is pinned phrase-by-phrase in
`TestBasePrompt_SharedGuidancePinnedAcrossModes` (`internal/agentinstr/assemble_test.go`) so a
reworded or dropped rule fails by mode name, on top of the golden fixtures.

## 3. The generated environment context block

`EnvironmentBlock` in `internal/agentinstr/envblock.go` generates this section in code, not from a
Markdown file. It emits stable facts only: date at day granularity, working directory, operating
system, project name, the repository root when a VCS was detected, and the version-control type
(rendered through `vcsDisplay`, so `hg` reads as `Mercurial`).

Keep this block prompt-cache friendly. Do not add facts that change every turn or grow with the
repository — branch/head, dirty status, directory listings. Those go stale immediately and break the
provider's cached prefix; the agent should fetch them with tools when it needs them.

## 4. How `AGENTS.md` fits in — and what actually enforces anything

`AGENTS.md` files are loaded **once per process launch**, before the TUI starts
(`LoadAgentInstructions` in `internal/agentinstr/load.go`, wired through `internal/bootstrap`).
Editing an `AGENTS.md` mid-session does not change the assembled prompt. `SystemPrompt` in
`internal/agentinstr/prompt.go` skips skipped and empty entries and joins the rest **verbatim** —
no path banner, no wrapper element, no heading of its own — as the final section of the message.

That final position, and the `## Project instructions` section of `shared.md`, are the whole of the
precedence story: they are **text asking the model to behave a certain way**. No code inspects,
sanitizes, or filters `AGENTS.md` content. The only code-level gates are at load time, in
`loadCandidate` (`internal/agentinstr/load.go`): a candidate path with no file is silently absent —
no entry, no error, a project without `AGENTS.md` is perfectly normal. A candidate that *is* there
is loaded only when it is readable and at or below `agent_instructions.max_file_bytes`; an
unreadable or oversized one is recorded as skipped and contributes no text.

So state it precisely:

- **Text-level guidance.** `AGENTS.md` may add project and workflow instructions and may override
  non-safety preferences like style or process. That precedence holds because the shared prompt says
  so and because of section order — not because anything checks it.
- **Code-enforced boundaries.** These hold whatever any prompt text says:
  - **Tool advertising.** `advertisedTools` in `internal/bootstrap/starttui.go` never offers a
    mutating registry tool in Plan mode. The model cannot call a tool it was not given.
  - **Mode posture.** `modePosture` in `internal/permissions/orchestrate.go` runs *before* grant
    matching and the approval cache. In Plan, anything classified mutating is denied outright —
    no prompt, and a matching grant cannot override it.
  - **Permission grants.** Approval, path scoping, and lifetimes live in the permission system;
    prompt text has no vote.
  - **Denial envelopes.** `BuildModeDenyEnvelope` returns the pinned `denied_by: "mode"` result the
    turn loop treats as recoverable, distinct from a user refusal.

A prompt that told the model it could ignore Plan mode would change nothing about what Plan allows.

## 5. Session history is its own source

`messagesFromRecords` in `internal/turn/request.go` projects persisted session records into provider
messages, and two kinds carry instructions the model may read:

- **Persisted `system` records.** A stored `sessions.Message` with role `system` and string content
  is projected **as a `system` message**, in its original position in history. The role list is
  pinned in `internal/sessions/schema.go` (`user`, `assistant`, `system`, `tool`, `model_context`).
  This is why the "exactly one system message" claim is wrong as a general statement.
- **Stored compaction summaries.** A `sessions.Compaction` record is projected by
  `compactionContextMessage` as a **`user`** message, wrapped in a note and
  `<prior_conversation_summary>` delimiters that mark it as reference data rather than instructions.
  This is deliberate: a summary is model-written text, so it must not come back with instruction
  authority. Only the `Summary` field is read — no record id, provider, model id, or parent id
  reaches the model.

Nothing here changed the durable schema. `sessions.Message` and `sessions.Compaction` are the
existing records; this is only how they project into a request.

## 6. Advertised tool descriptions

Tool descriptions are model-facing text that lives nowhere near the prompt files. They ride the
`tools` field of the request, not a message.

`advertisedTools` in `internal/bootstrap/starttui.go` walks `registry.List()`, reads each tool's
`Advertise()` `Metadata` (`Description` and `Parameters` from `internal/tools/registry.go`), drops
non-`ReadOnly` tools when the mode is Plan, then appends two product-authored definitions from
`internal/provider/tooldefs.go` and sorts the whole set by name:

- `provider.BashToolDefinition()` — `bash` has no registry entry (dispatch routes the pinned name
  before any registry lookup) and is advertised in **every** mode, because its read/write intent is
  per invocation. Plan's shell restriction is enforced by posture, not by hiding the tool.
- `provider.SuggestFollowupToolDefinition()` — advertised in every mode; the turn loop intercepts
  it, so it is never dispatched or persisted.

Where the descriptions themselves live: each registry tool authors its own in its package
(`internal/filetools` for the file tools, `internal/vcs/tool.go` for `vcs_<action>`,
`internal/bootstrap/tooldispatch.go` for `web_search` / `web_fetch`); `bash` and `suggest_followup`
are authored in `internal/provider/tooldefs.go`. `internal/provider/tooldefs_test.go` pins the two
product definitions. Registry metadata coverage varies by tool, with no shared exact-description
check, so review a registry description together with its package tests. The prompt snapshots will
not notice any of them.

## 7. Title and compaction are separate requests

Both are non-streaming, one-shot requests with their own fixed instruction and no advertised tools.

**Title.** `GenerateTitle` in `internal/turn/titlegen.go` sends exactly two messages: `system` =
`titleSystemPrompt`, and `user` = the opening exchange rendered by `exchangeText`. The instruction
tells the model the exchange is *content to label, not instructions to it* — the opening user
message is untrusted input, so the trust boundary is stated in the prompt and the result is
sanitized in code (`sanitizeTitle`, capped at 80 runes). No history, no tools, no cache key.
`TestGenerateTitle_RequestShape` pins the literal.

**Compaction.** `BuildCompactionSummaryRequest` in `internal/turn/request.go` prepends
`compactionSummaryInstruction` as a `system` message ahead of the projected history. The
instruction states the same boundary — everything after it is material to summarize, never
instructions to follow — and lists what the summary must preserve (goals, constraints, whether the
work was read-only, approvals given and still required, unresolved work, proposed versus completed).
The request is non-streaming with no tools and no prompt cache key.
`TestBuildCompactionSummaryRequest_ExactShape` pins the whole shape.

The summary that comes *back* is stored and then replayed at lower authority — see §5.

## 8. What the snapshot fixtures test

`TestAssembledSystemMessage_GoldenSnapshots` in `internal/agentinstr/snapshot_test.go` compares
`AssembleSystemMessage` output against six committed files under
`internal/agentinstr/testdata/snapshots/`: `plan.txt`, `build.txt`, `auto_edits.txt`,
`base_env_only.txt`, `with_agents.txt`, `special_latex.txt`. (The operating-system name is stored as
a `<goos>` placeholder so the fixtures read the same on every machine.)

They cover **the assembled normal-turn message and nothing else** — sources 1 through 4 of the
inventory. They say nothing about advertised tool descriptions, the title instruction, the
compaction instruction, the compaction-summary wrapper, or persisted record projection. The title,
compaction, and provider-definition checks are focused tests listed in the inventory; registry
metadata coverage varies by tool, with no shared exact-description test.

These are snapshot tests: they make prompt wording changes visible in review instead of silently
changing what every model sees. If you intentionally change base prompt Markdown or the generated
environment block, run `mise run snapshot-update` and then `mise run check` — see
[`setup.md`](../setup.md) → "Checks that fail on purpose" and
[`docs/gated-changes.md`](../../docs/gated-changes.md) gate 1. Regenerate the fixtures; never edit
one by hand.

## Quiz

This reference page has no separate quiz. Use Module 12's
[`agent modes quiz`](quizzes/module-12.md) for the overlapping system-prompt material.
