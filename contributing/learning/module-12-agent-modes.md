# Module 12 — Agent Modes, System Prompt & Tool Advertising

_Snapshot as of 2026-08-22; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-08-22_

> Prerequisite: Module 5 (permissions) and Module 8 (turn & provider) make this much
> easier — modes *drive* the permission system you learned in Module 5, and the assembled
> system message + advertised tools ride the provider request you traced in Module 8.

## Goal

After this module you can:

- Name the three interaction modes and state precisely what each does — and point at the
  code that makes **Plan** read-only by *enforcement*, not just by instruction.
- Explain how the active mode selects the base prompt inside the assembled `system` message,
  and know that the always-on environment block rides every turn in every mode. (The full
  assembly order, special-instructions slot, cache rationale, and the *other* model-facing
  instruction sources live in [`system-prompts.md`](system-prompts.md).)
- Explain mode-filtered tool advertising: which tools Plan advertises, and the
  `Advertise()` / `ReadOnly` mechanism behind the filter.
- Explain how modes compose with (rather than replace) the existing permission seam.
- Tell **prompt guidance** apart from **code enforcement** — and name the code that holds when
  the prompt text is ignored.

## Why it matters

Before this subsystem, codemeld sent the model only the user's `AGENTS.md` — and **nothing
at all** when no `AGENTS.md` existed — and it never told the model which tools it had. This
subsystem adds three **modes** (Plan, Build, Auto edits), each bundling a product-authored base
prompt, a mode-filtered advertised tool set, and a permission/interruption posture, plus an
always-on environment block. The headline guarantee is that **Plan cannot change anything** — and
that is enforced at the permission seam and the advertise step, not merely asked of the model in
prose. This module is where "what the model is told" meets "what the model is allowed to do."

## Read (in order)

1. `docs/architecture.md` → "Permission system is the front door" (the seam modes plug into).
2. The code, in dependency order — each file's top comment explains its role:
   - `internal/mode/active_state.go` — `Mode` (`Plan`/`Build`/`AutoEdits`), `Source`, `Trigger`,
     `ActiveState`, `NewActiveState`, `Current`, `ApplyUserCommand`, `CarryForward`. The
     run-scoped active-mode holder, mirroring `model.ActiveState`.
   - `internal/agentinstr/envblock.go` — `EnvironmentInputs`, `EnvironmentBlock`, `vcsDisplay`.
     The always-on environment context formatter.
   - `internal/agentinstr/assemble.go` — `BasePrompt`, `behaviorBlock`, `AssembleSystemMessage`,
     `joinSections`, and the four `//go:embed` base-prompt strings. The system-message builder.
   - `internal/agentinstr/baseprompts/shared.md`, `plan.md`, `build.md`, `auto_edits.md` — the
     embedded base-prompt markdown (shared core + one behavior block per mode).
   - `internal/tools/registry.go` — `Metadata` (`Description`/`Parameters`/`ReadOnly`), `Tool`
     (`Advertise()`), `Registry.List`. The advertising-metadata + read-only-class contract.
   - `internal/permissions/planshell.go` — `commandPolicies`, `stageTokensReadOnly` (reached via
     `classifyReadOnlyShell`). The one shared all-mode read-only shell classifier:
     a product-authored command-policy table plus the admitted read-only diagnostics.
   - `internal/permissions/orchestrate.go` — `ModeContext`, `OperationClass`, `modePosture`,
     `planOperationClass`, `planPosture`, `autoEditsPosture`, `isAutoEditsTool`,
     `isInScopeFileTool`, `emitModeAuto`. Where mode posture drives `Authorize`.
   - `internal/permissions/capability.go` — `CapabilityWrite`, `CapabilityWriteTree`,
     `capabilityMembers`, `CapabilityForMember`. The stored grant families Auto edits is *not*
     — read it to keep mode approval and grant approval apart.
   - `internal/bootstrap/starttui.go` — `advertisedTools`, `newToolAdvertiser`. The
     mode-filtered advertise step.
   - `internal/provider/tooldefs.go` — `ToolDefinition`, `BashToolDefinition`,
     `SuggestFollowupToolDefinition`. The provider-agnostic tool-definition plus the two
     product-authored definitions that have no registry entry.
   - `internal/tui/cmd_mode.go` — `NewModeHandler`, `normalizeModeArg`, `cycleMode`,
     `ModeSwitcher`. The `/mode` command and shift+tab cycle.

> Citations in this module and its answer key use **file + function/symbol name**, never line
> numbers — lines move as the code changes, but a symbol name stays findable.

## Mental model

### The three modes

`internal/mode/active_state.go` defines exactly three `Mode` values — `Plan` = `"plan"`,
`Build` = `"build"`, `AutoEdits` = `"auto_edits"` — and `TestModeKeysAreExactlyThree` pins
those exact keys. There are no custom modes.

- **Plan** — read-only investigation. The agent reads, searches, and produces a plan, but
  makes no changes. Read-only is *enforced*, three ways at once (below).
- **Build** — normal work. Ungranted mutating requests pause for permission per the existing
  grant system (today's behavior).
- **Auto edits** — continuous work: in-project changes to the **project tree** — a structured
  `create`, `edit`, `mkdir`, or `move` — auto-approve without a prompt, while shell commands,
  `delete`, VCS mutations, and out-of-scope/risky actions still pause as in Build. It is a
  posture, not an approve-all: the boundary is the resolved project root, and the approval is
  per call (no grant, no cache entry).

The active mode is a **run-scoped** in-memory state (`ActiveState`), mirroring
`model.ActiveState`. The launch default comes from config `mode.default` (default `build`,
resolved by `config.Cache.ModeDefault`) and is **never** restored from a prior session; even a
resumed session starts at `mode.default`. A `/clear` switch carries the active mode *forward*
(`CarryForward` — deliberately a no-op on the shared instance), so the fresh session opens in the
same mode rather than silently resetting Plan back to Build mid-run.

### How Plan is *enforced* read-only (not just instructed)

Three independent mechanisms, none of which trusts the model to behave:

1. **No write tools advertised.** `advertisedTools` (`starttui.go`) skips any registry tool
   whose `Advertise().ReadOnly` is false when the mode is `mode.Plan`. The model never sees the
   `edit`/`create`/`delete` tools in Plan.
2. **Mutating requests denied at the seam.** `modePosture` (`orchestrate.go`) runs *before*
   grant match and turn cache. In Plan, anything not classified read-only hits `planPosture`,
   which returns a deny with a `denied_by: "mode"` envelope — without prompting, and without an
   existing grant being able to override it (posture runs first).
3. **Raw shell conservatively classified.** `bash` *is* advertised in every mode (its read/write
   intent is per-invocation), so Plan's shell restriction is enforced by the one shared all-mode
   classifier, `classifyReadOnlyShell` → `stageTokensReadOnly` (`planshell.go`): a shell request is
   read-only only if every stage is an admitted read-only form — a name-only allowlisted reader, a read-only
   VCS subcommand, or one of the platform-specific argument-sensitive diagnostics in its exact bounded
   form. Linux admits `ps`, `pgrep`, `pidof`, `pstree`, `lsof`, `ss`, `free`, `vmstat`, `uptime`,
   `journalctl`, and `dmesg`; FreeBSD admits `ps`, `pgrep`, `pidof`, `pstree`, `fstat`, `procstat`,
   `sockstat`, `vmstat`, and `uptime`, but not `dmesg`. The shared names may have different admitted
   forms on each platform. A read-only request also has **no stage carrying env assignments**, and an
   argument-sensitive stage runs the exact validated argv — the direct or staged route, or the
   `sh -c` literal route only when every raw token of every stage in the command is expansion-free, so
   the shell's argument list is provably the validated one (an unquoted `$`, `*`/`?`/`[`, `{a,b}`, or
   leading `~` anywhere in the command, and every `sh -c` wrapper spelling, keep it mutating).
   Anything else is mutating → denied in Plan.
   The same verdict drives the read-only auto-allow in Build and Auto edits; no mode owns a duplicate
   list. Module 5 works through the classifier in full, and
   [`internal/permissions/planshell_test.go`](../../internal/permissions/planshell_test.go) is the
   executable record of what the table admits and what it fails closed on.

The Plan base prompt (`baseprompts/plan.md`) *also* tells the model it is read-only — but that
instruction is belt-and-suspenders on top of the three enforcement points, not the guarantee.

### The assembled system message

Every **normal chat turn** gets one synthetic `system` message, built by `AssembleSystemMessage`
(`assemble.go`). Its full lifecycle — the fixed section order, the optional per-model
special-instructions slot, how empty sections are dropped, and why the message is non-empty even
with zero `AGENTS.md` — lives in [`system-prompts.md`](system-prompts.md); read it there rather
than duplicating it here.

Do not generalize that to *every* provider request. Title generation and compaction are separate
requests with their own fixed instructions, and a persisted `system`-role session record projects
as a second `system` message on a normal turn. [`system-prompts.md`](system-prompts.md) has the
full inventory; this module stays on the normal turn.

What matters for **modes**: the first section is the *active mode's* base prompt, `BasePrompt(m)` —
the shared core (`baseprompts/shared.md`) plus that mode's behavior block
(`plan.md`/`build.md`/`auto_edits.md`). Switching mode swaps only that behavior block, not the rest
of the message, and `BasePrompt` falls back to Build's block for an unrecognized mode so the base
section is never empty. The base prompts are **embedded markdown** (`//go:embed`), not inline Go
string literals.

### Asked in prose vs. enforced in code

The assembled message ends with whatever the project's `AGENTS.md` files say, and `shared.md`
tells the model those instructions may override non-safety preferences like style or process but
not the mode, safety, permission, tool-use, or denial contracts. That ordering and that paragraph
are the **entire** mechanism: `SystemPrompt` (`prompt.go`) appends the loaded bytes verbatim, and
no code anywhere inspects, filters, or validates what an `AGENTS.md` says. Load-time checks cover
existence, readability, and a byte-size cap — nothing about content.

So keep the two columns apart:

| Asked in prose | Enforced in code |
|---|---|
| `AGENTS.md` may not override the mode/safety/permission contracts (`shared.md` → `## Project instructions`) | `modePosture` (`orchestrate.go`) denies mutating work in Plan before grants and cache are consulted |
| `plan.md` tells the model it is read-only | `advertisedTools` (`starttui.go`) never offers a mutating registry tool in Plan |
| The base prompt describes when to prompt or proceed | The grant table and turn cache decide, and `BuildModeDenyEnvelope` emits the pinned `denied_by: "mode"` result |
| `shared.md` tells the model to stop and ask before changing a file the request does not clearly require, and never to remove or roll back unrelated configuration, generated state, user changes, or authorization state | Nothing. There is no code check on whether a permitted write was *in scope* — only whether it was permitted |

A model that ignored every line of prompt text would still not be able to write a file in Plan.
That is the whole point of doing it in code.

The last row is the one to be careful with: unlike the rows above it, it has **no** enforced
counterpart at all. Permission answers "may this write happen"; nothing in code answers "did the
request want this file touched". So the file-scope rule is defense in depth on top of the
permission system, not a second gate inside it — a grant that allows the write still allows it, and
the only thing standing between an allowed write and an out-of-scope one is the model following
prose. Note also what the rule does *not* do: it does not add an approval round to work the user
already asked for. `shared.md` still says an explicit request to fix, implement, add, or change
something is itself the authorization for that work, so the stop applies to a file whose
relationship to the request is unclear, not to the files an accepted request plainly needs. The
full three-part reading, and how it is pinned, is in
[`system-prompts.md`](system-prompts.md) → "What `shared.md` says about which files are in scope".

### The environment context block

`EnvironmentBlock` (`envblock.go`) formats an always-on block of stable facts — date, working
directory, OS, project, version control — and deliberately excludes per-turn-volatile state
(branch/head, dirty status, listings) so it stays prompt-cache friendly. It is **not**
mode-specific: it rides every turn in every mode unchanged. The full field list, exclusions, and
cache rationale live in [`system-prompts.md`](system-prompts.md).

### Mode-filtered tool advertising

The advertised set is assembled at **each** turn dispatch. `turnController.dispatch`
(`turndeps.go`) calls the advertiser once per user turn and freezes the result onto the turn's
deps, so every provider round in that turn — including a tool-call continuation — carries the
same set; a mode switch mid-turn cannot change it and is picked up at the next dispatch.
`advertisedTools` (`starttui.go`) enumerates
`registry.List()` (already name-sorted), reads each tool's `Advertise()` `Metadata`, filters out
non-`ReadOnly` tools in Plan, then appends `provider.BashToolDefinition()` and
`provider.SuggestFollowupToolDefinition()` and sorts the whole set by name. The single `ReadOnly`
bit on `Metadata` (`registry.go`) drives **both** this advertise filter and the posture decisions —
one classification, so the two can never disagree.

Those descriptions are model-facing text too — they just ride the request's `tools` field instead
of a message, so the system-prompt snapshots never see them. Each registry tool authors its own
`Description` in its own package.

`bash` is special: it has **no registry `Tool`** — dispatch routes the pinned name `bash` to the
shell path before any registry lookup — so its definition is product-authored directly in
`BashToolDefinition` (`tooldefs.go`) and advertised in every mode. `suggest_followup` is the same
shape for a different reason: it is intercepted by the turn loop and never dispatched, so it has no
registry entry and is advertised in every mode. For `vcs_<action>` tools, the
read-only set is product-authored per action name (`builtinReadOnlyActions` in
`internal/vcs/tool.go`: `status`, `diff`, `log`, `branch-current`, `is-clean`, `merge-status`,
`rebase-status`); the complementary actions are mutating, and a **user-supplied** template action
defaults to mutating regardless of name — Plan never trusts user-provided argv.

### Modes drive (not replace) the permission system

`modePosture` (`orchestrate.go`) is the mode integration point, and `Authorize` calls it
**before** the real-grant match and the turn cache, so a Plan denial or a mode auto-approval
pre-empts them. One thing runs even earlier, and only when a `codemeld run` was started with a
declared write scope — see the next section:

```
Authorize(req, modeCtx, deps)
   │
   ├─ (-1) declaredScopePosture  ← only when --files-authorized/-delete was given
   │        Plan?  → skipped entirely; planPosture decides
   │        write tool + target in the matching list? → declared_scope "once"
   │        write tool, anything else → declared_scope "deny", denied_by:"user" (terminal)
   │        not a write tool (reads, shell, network) → handled=false → fall through ↓
   │
   ├─ (0) modePosture          ← mode decides next
   │        read-only?  → mode_auto "once"  (auto-allow in EVERY mode)
   │        Plan + mutating?   → mode_auto "deny", denied_by:"mode"
   │        AutoEdits + in-scope edit/create/mkdir,
   │          or move with both endpoints in-project? → mode_auto "once"
   │        else handled=false → fall through ↓
   │
   ├─ (1) Match(real grants)   ← Module 5
   ├─ (2) TurnCache.Lookup     ← Module 5
   └─ (3) prompt the user
```

Key invariants:

- It introduces **no second permission store** — it composes with the existing grant table and
  turn cache.
- A mode-made decision is recorded as `permission_matched` with `outcome_source: "mode_auto"`
  and **no grant fields** (`emitModeAuto`), never creating a grant and never writing to the turn
  cache. The cache key omits the edit target, so caching one Auto-edits approval would leak to a
  different target in the same turn — `autoEditsPosture` deliberately records nothing to it.
- `isInScopeFileTool` decides Auto edits' in-scope class: a call to the `edit`, `create`, or
  `mkdir` tool whose resolved target is within `ProjectRoot`, using the same descendant rule
  (`IsDescendantOrEqual`) as folder-grant path scopes. `move` is in the class too, but it is the
  one tool with **two** targets, so it needs **both** to qualify: dispatch copies
  `filetools.ResolvedMove`'s canonical `Source` and `Destination` into `ModeContext`, and a move
  auto-approves only when both are descendants of `ProjectRoot`. One endpoint outside the root —
  including a destination whose *lexical* path spells in-project but resolves out through a
  symlink — sends the whole move to the prompt, so an auto-approval can never relocate a file
  across the project boundary. The `delete` tool is mutating but is deliberately **not** in this
  set: `isAutoEditsTool` omits it, so an irreversible delete is never auto-approved by any mode,
  and it belongs to no capability, so no write approval ever folds it in. Outside a declared
  delete scope (next section) it therefore always prompts. `move` is the mirror-image case: it *is* in the Auto-edits class but belongs to no
  capability either, so being mode-auto approved is not a grant match and does not change move's
  grant identity.

### A declared write scope is a ceiling, not a mode

`codemeld run --files-authorized <path>` names what the run may `create`/`edit`;
`--files-authorized-delete <path>` names what it may `delete`. It is easy to read these as "another
mode", and they are not. A mode is a posture that decides on the agent's behalf; a declared scope is
the invoking human refusing in advance, on the command line, with more precision than any prompt
answer offers. Four consequences follow, all in `declaredScopePosture` (`orchestrate.go`):

- **It runs before mode posture, not inside it.** Either flag present makes the two lists the
  **only** thing that can authorize `create`, `edit`, `delete`, `mkdir`, or `move` for the whole
  run. An uncovered call is decided there and is never handed on to a grant, the turn cache, Auto
  edits' project-root rule, or `--prompt-for-approval`; the posture returns *handled* for the
  denial exactly as it does for the approval. With **neither** flag present nothing changes — an
  absent flag is not an empty ceiling.
- **Plan is skipped entirely.** `mc.Mode == modePlan` short-circuits the check, so `planPosture`
  stays the sole authority and a write declared in both lists is still denied in Plan, with Plan's
  own `denied_by: "mode"` envelope and its `mode_auto`/`deny` record.
- **`delete` no longer always prompts — but only this way.** A declared delete covers the exact
  path, whether that is a file, a symlink, or an **empty** directory; a non-empty directory is
  still refused by `AT_REMOVEDIR`. Auto edits still never covers `delete` (`isAutoEditsTool` omits
  it), and `delete` still belongs to no capability. `mkdir` and `move` are covered by **neither**
  list.
- **The record says who decided.** A declared decision emits `permission_matched` with
  `outcome_source: "declared_scope"` — not `mode_auto` — and, like a mode decision, no grant fields
  and no turn-cache entry. Reading `mode_auto/deny` as "a posture refused" and
  `declared_scope/deny` as "the invoking human refused in advance" is the whole point of the extra
  value. A miss carries `denied_by: "user"`, which makes it terminal and puts it in the run's exit
  denial summary.

The ceiling binds codemeld's **file tools**, so it is not a sandbox: a write inside a granted shell
command never calls those tools and the lists cannot see it.

### Auto-edits approval ≠ a stored write grant

These are two different mechanisms with two different vocabularies, and conflating them is the
easiest mistake to make here.

**Auto edits (mode posture)** approves one call, right now, because of *where the target is*. It
covers the four tools in `isAutoEditsTool` and stores nothing.

**A capability grant** approves a *family of tools at a path scope*, persistently, because the
user picked "allow in this folder / globally" at a prompt. The family table is
`capabilityMembers` (`internal/permissions/capability.go`):

| Capability subject | Members | Where it comes from |
|---|---|---|
| `write` (legacy) | `create`, `edit` | Only grants already stored from before `write_tree` existed. Nothing creates a new one. |
| `write_tree` (successor) | `create`, `edit`, `mkdir` | Every new create/edit/mkdir folder/global approval. |
| `read*` | `read`, `grep`, `glob`, `list`, `tree`, `file_count` | An **external** read approval. |

Two rules to hold onto:

1. **A legacy `write` grant is never upgraded.** It keeps meaning `{create, edit}` — it does not
   grow `mkdir`, and nothing rewrites it on load. Matching just checks membership
   (`capabilityContains` via `Match`), so an old grant keeps its old, narrower meaning forever.
   New approvals get `write_tree` because `CapabilityForMember` tests `write_tree` first and
   `write_tree` is a superset — which is why `CapabilityWrite` is unreachable as a *return* value
   while remaining meaningful as a *stored* one.
2. **Neither capability includes `move` or `delete`.** `move` can be mode-auto approved (both
   endpoints in-project) but never rides a write grant; `delete` gets neither. Both keep their
   concrete subject.

So "Auto edits created `foo/bar/baz.go` without asking" and "I have a `write_tree` grant on
`foo/`" are unrelated facts — the first left nothing behind on disk.

## Watch for (Go idioms)

- **Read-only auto-allows in every mode, not only Plan.** A bare read-only command
  (`rg`/`cat`/`vcs_status`) auto-allows in Build and Auto edits too — `modePosture` checks
  `planOperationClass(req, mc) == ClassReadOnly` for every mode *before* the per-mode switch. So
  Build does **not** prompt on a read-only request even though it prompts on ungranted *mutating*
  ones.
- **Program-scope confirm is a single keypress.** Granting Program scope is an inline
  single-keypress confirm against the breadth warning, not typing the program name verbatim. Tie
  this to Module 5 — it changes the prompt UI, not the matching rules.
- **Raw-bytes safety, again.** `classifyReadOnlyShell` rejects any stage carrying env assignments
  using the **pre-normalization** stage data — because normalization strips `KEY=VALUE` off the
  matched subject but they are re-applied at exec, so `LD_PRELOAD=/x/evil.so ls` would otherwise
  pass the `ls` allowlist while loading arbitrary code. Same defensive instinct as Module 5's
  `isEnvAssignment`.
- **One classification, two consumers.** `Metadata.ReadOnly` (a single bool) drives both the
  advertise filter and the posture decision. Its zero value is `false` = mutating — the safe
  default for any source not product-verified as read-only (user VCS templates).
- **The tests are the spec.** `cmd_mode_test.go`, `active_state_test.go`, `planshell_test.go`,
  and `orchestrate_test.go` pin the exact keys, cycle order, allowlist, and posture outcomes.

## Quiz

Take it closed-book: [`quizzes/module-12.md`](quizzes/module-12.md). Grade against
[`quizzes/module-12-key.md`](quizzes/module-12-key.md) — the key cites file and function/symbol.

## Hands-on (open-book)

**A. Predict, then verify.** In **Build** mode, will a bare `rg foo` prompt the user? Write your
prediction first. Then read `modePosture` and `planOperationClass` (`orchestrate.go`) and
`classifyReadOnlyShell` → `stageTokensReadOnly` (`planshell.go`): `rg` is in `commandPolicies`, so
it classifies `ClassReadOnly`, and the read-only auto-allow fires *before* the per-mode switch — in every mode.
Did your prediction match? (Bonus: predict `LD_PRELOAD=x rg foo` and find the stage-assignment
check that flips it to mutating.)

**B. Write a test.** Add a test asserting the assembled system message is **non-empty** with
**zero** `AGENTS.md` entries (the always-on invariant). A clean shape:

```go
func TestAssembleSystemMessage_NonEmptyWithoutAgents(t *testing.T) {
    env := EnvironmentInputs{
        Now:         time.Date(2026, 6, 13, 9, 0, 0, 0, time.UTC),
        WorkingDir:  "/work",
        ProjectRoot: "/work",
        VCSName:     "hg",
    }
    // Blank provider/model id ⇒ no model-specific special-instructions section.
    msg := AssembleSystemMessage(mode.Plan, "", "", env, nil)
    if msg == "" {
        t.Fatal("system message must be non-empty even with zero AGENTS.md")
    }
    if !strings.Contains(msg, "Mercurial") {
        t.Errorf("environment block should render hg as Mercurial; got:\n%s", msg)
    }
}
```

Put it in `internal/agentinstr/assemble_test.go`, run `go test ./internal/agentinstr`, and find
your test's result. It should pass against current code — you're proving the always-on invariant and
learning the assembly API. *(Revert afterward, or keep it if you think it adds value.)*

**C. Locate the classification.** Find where the single read-only classification driving both the
advertised-tool filter and posture is implemented. Record the `file:function` (there are two
consumers of one bit) in [`progress.md`](progress.md).

## Done when

- You answered every quiz question correctly **without** the key.
- Your hands-on A prediction matched what the code actually does — and you can explain *why* a
  read-only command auto-allows in Build even though a mutating one prompts.
- Your hands-on B test passed, and you can point at `joinSections` and `BasePrompt` to explain
  why the message is never empty.
