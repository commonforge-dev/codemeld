# Answer key — Module 12: Agent Modes, System Prompt & Tool Advertising

_Last updated: 2026-08-22_

Citations are **file + function/symbol name**, not line numbers — lines drift as the code
changes, but a function name stays findable. Search (or your editor's "go to symbol") lands you
on the exact code.

> Answers 3–6b cover the assembled system message, environment block, and shared file-scope
> guidance, whose full lifecycle now
> lives in [`system-prompts.md`](../system-prompts.md); Module 12 keeps only the mode-specific
> view. The code citations below stay authoritative for both pages.

---

**1. The three modes.**
`Plan` (`"plan"`) — mutating actions are **denied** without prompting; `Build` (`"build"`) —
ungranted mutating actions **prompt**; `AutoEdits` (`"auto_edits"`) — in-project structured
`create`/`edit`/`mkdir`/`move` calls **auto-approve**, everything else still prompts. Source: the
`Mode` constants in `internal/mode/active_state.go`; `TestModeKeysAreExactlyThree` pins the exact
keys.

**2. Plan enforcement.** Three independent mechanisms:
- **No write tools advertised** — `advertisedTools` (`internal/bootstrap/starttui.go`) skips any
  tool whose `Advertise().ReadOnly` is false when the mode is `mode.Plan`.
- **Mutating requests denied at the seam** — `planPosture` (via `modePosture`) in
  `internal/permissions/orchestrate.go` returns a deny (no prompt) for anything not classified
  read-only.
- **Raw shell conservatively classified** — `classifyPlanShell` (`internal/permissions/planshell.go`)
  admits a shell command as read-only only if it is a pure direct pipeline of
  `planReadOnlyExecutables` with no env assignments; everything else is mutating → denied.
The Plan base prompt (`baseprompts/plan.md`) also instructs read-only, but that is on top of the
three enforcement points, not the guarantee.

**3. Assembly order.**
`AssembleSystemMessage` (`internal/agentinstr/assemble.go`) builds, in order: (1) the active
mode's base prompt (`BasePrompt`), (2) the active model's special instructions — **optional**,
(3) the environment block (`EnvironmentBlock`), (4) the loaded `AGENTS.md` text (`SystemPrompt`).
An **unflagged** model (no special instructions) assembles only sections (1), (3), (4) —
byte-identical to having no special slot. An empty optional section is trimmed away and
contributes nothing — no dangling separator. (This much is on the page.)
_From the code:_ section (2) is present only for **flagged** models —
`SpecialInstructions(provider, modelID)` (`internal/agentinstr/special.go`) returns a block only
when the provider+model pair matches a `modelSpecialInstructions` entry, otherwise `""`; the active
provider/model ids come from `activeModelIDs` (`internal/bootstrap/starttui.go`), threaded in by
`newSystemPromptAssembler`. `joinSections` joins the non-empty sections with a single blank line
(`sectionSeparator` = `"\n\n"`). `TestAssembleSystemMessage_FlaggedModelInsertsSpecialInstructions`
(`assemble_test.go`) pins the four-slot order.

**4. Empty AGENTS.md. — Not empty.**
Sections (1) base prompt and (3) environment block are always present, so the message is non-empty
even with zero `AGENTS.md`. This **supersedes** the earlier behavior, where an empty
`AGENTS.md` set produced no system message at all. `BasePrompt` even falls back to Build's behavior
block for an unrecognized mode, so the base section is never empty. Source: `AssembleSystemMessage`
and `BasePrompt`/`joinSections` (`assemble.go`).

**5. Environment block — included.**
Date (day granularity, `Now.Format("2006-01-02")`), absolute working directory, operating system
(`runtime.GOOS`), project name (basename of `ProjectRoot`), and version control name. Function:
`EnvironmentBlock` (`internal/agentinstr/envblock.go`); VCS rendering via `vcsDisplay`
(git/hg/jj → Git/Mercurial/Jujutsu, custom verbatim, empty → "no version control detected").

**6. Environment block — excluded.**
Current branch/head, working-tree dirty status, and directory listings. Reason: they are
per-turn-volatile or large, so baking them into the always-on prompt breaks provider prompt-cache
reuse and goes stale the moment the agent edits a file — they are fetched on demand via tools
instead. Documented in the `EnvironmentBlock` doc comment.

**6b. File scope in the shared prompt. — Nothing enforces it.**
There is no code path. Permission answers only "may this write happen"; no check anywhere asks
whether the request wanted that file touched, so a model that ignores the rule and writes a
permitted-but-unrelated file is allowed to. The rule is product-authored prose in
`internal/agentinstr/baseprompts/shared.md` — `## Deciding what to do` carries the stop-and-ask
half, `## Making changes` the "do not remove, revert, disable, or reset unrelated configuration,
generated state, user changes, or authorization state" half — riding row 1 of the inventory into
every mode via `sharedCore` in `BasePrompt` (`internal/agentinstr/assemble.go`). It is defense in
depth over the code-enforced boundaries (`modePosture`, `advertisedTools`, grants,
`BuildModeDenyEnvelope`), never a replacement for one.

**No second approval round.** The same section still says an explicit request to fix, implement,
add, or change something *is* the authorization for that work, and adds that the file-scope rule
settles which files are in scope rather than whether accepted work needs approving again. The stop
triggers only when the model cannot point to the part of the request that requires the file — the
files an accepted "fix X" plainly needs are already in scope.

**What catches a change:** `TestBasePrompt_SharedGuidancePinnedAcrossModes`
(`internal/agentinstr/assemble_test.go`) asserts the literal phrases against `BasePrompt` for Plan,
Build, and Auto edits, so a dropped or reworded rule fails by mode name; the six golden fixtures in
`TestAssembledSystemMessage_GoldenSnapshots` catch it as a diff as well.

**7. Tool advertising in Plan.**
Only **read-only** tools (plus `bash`, which is always advertised). The filter keys on the single
`Metadata.ReadOnly` bool (`internal/tools/registry.go`), applied by `advertisedTools`
(`internal/bootstrap/starttui.go`): `if m == mode.Plan && !meta.ReadOnly { continue }`. That same
bool also drives the posture decisions — one classification, two consumers.

**8. The `bash` definition.**
`bash` has **no registry `Tool`** — dispatch routes the pinned name `bash` to the shell path before
any registry lookup, so registering a bash `Tool` would be dead code. Its definition is
product-authored in `BashToolDefinition` (`internal/provider/tooldefs.go`) and advertised in
**every** mode (Plan, Build, Auto edits), because a shell command's read/write intent is
per-invocation and is enforced by posture, not at advertise time.

**9. Posture ordering.**
`Authorize` (`internal/permissions/orchestrate.go`) calls `modePosture` at step (0), **before** the
real-grant `Match` (step 1) and the turn-cache `Lookup` (step 2). It matters for Plan because a
mutating request must be denied even if a matching grant or cache entry exists — posture running
first means a grant cannot override Plan's read-only restriction, and the shadowed grant emits no
`permission_matched` of its own.

The earlier check is `declaredScopePosture` (`orchestrate.go`), at the very top of
`resolveWithoutPrompt`. It is on only when the run was started with `--files-authorized` or
`--files-authorized-delete`; with neither, it hands the call straight on and nothing changes. It
must return `handled=true` for its **denials** too, because returning `handled=false` on a miss
would re-open the grant match, the turn cache, Auto edits, and the prompt — turning the caller's
declared ceiling back into a suggestion. Reads, shell, and network are not write tools, so it
returns `handled=false` for them and their authorization is untouched.

**9b. Declared write scopes.** With only `--files-authorized notes.md`:
- `edit notes.md` → **allowed**, `declared_scope`/`once`, no grant, no cache entry.
- `edit other.md` with a covering folder grant → **denied**. The posture resolves ahead of the
  grant match, so the grant is never consulted.
- `delete notes.md` → **denied**. The lists are independent; the write list never implies the
  delete list (which mirrors `delete`'s membership in no capability). The absent delete list is an
  empty list *within* an active ceiling, not an absence of ceiling.
- `mkdir` → **denied**. Neither list can ever authorize `mkdir` or `move`.
- `edit notes.md` in **Plan** → **denied**, unchanged. The posture is skipped in Plan, so
  `planPosture` decides with its own `denied_by: "mode"` envelope and `mode_auto`/`deny` record.

Adding `--files-authorized-delete notes.md` changes exactly the third case (the `delete` is now
allowed) and the reason text of the others (both flags are named). A **delete** declaration covers
the exact path whether it is a file, a **symlink** (the link entry, never its target), or an
**empty** directory — a non-empty one is still refused by `AT_REMOVEDIR`. A **write** declaration
for `a/b/c.txt` when `a/` does not exist also authorizes creating `a/` and `a/b/`, because `create`
builds missing parents inside its own single authorization; the declaration is exact at the *tool
target*, not at the filesystem-mutation level. Source: `declaredScopePosture` /
`declaredScopeCovers` (`orchestrate.go`), `ResolveDeclaredScopes`
(`internal/filetools/resolve.go`).

**10. mode_auto records.**
Recorded as a `permission_matched` event with `outcome_source: "mode_auto"` and **no grant fields**,
via `emitModeAuto` (`orchestrate.go`). Side effects deliberately absent: it creates **no grant** and
records **nothing to the turn cache**. (`autoEditsPosture` notes the cache key omits the edit target,
so caching one approval would leak to a different target in the same turn.)

A declared write scope emits the same shape — `once` or `deny`, no grant fields, no cache entry, no
settings write — under `outcome_source: "declared_scope"` (`emitDeclaredScope`). Reusing
`mode_auto` would assert that a *mode* approved the call, which for an approved `delete` is simply
false and is what the "delete is never auto-approved by a mode" invariant forbids; a reader
auditing a session has to be able to tell a mode's decision from a caller's declaration. A declared
miss carries `denied_by: "user"`, not `"mode"` — so `IsModeDenyEnvelope` is false, the turn loop
does **not** re-issue it (nothing the model tries can widen the ceiling), and the refusal appears in
the headless run's exit denial summary, which is the surface the caller actually reads.

**11. Auto edits in-scope class.**
A call to the `edit`, `create`, or `mkdir` structured tool whose resolved target path is within the
project root, plus a `move` whose **two** resolved endpoints are both within it — exactly the four
names in `isAutoEditsTool` (`orchestrate.go`). Function: `isInScopeFileTool` (`orchestrate.go`),
which checks `isAutoEditsTool(mc.ToolName)` and `IsDescendantOrEqual` against `mc.ProjectRoot` —
the same descendant rule folder-grant path scopes use. `move` is the one tool with a source *and* a
destination, so a single `mc.TargetPath` would be a half-target: one in-root endpoint could
authorize a relocation whose other end is outside the project. `dispatchPreparedMultiScope`
(`internal/dispatch/tool.go`) therefore copies `filetools.ResolvedMove`'s canonical `Source` and
`Destination` into `mc.MoveSource`/`mc.MoveDestination`, and both must be descendants of the root —
the *resolved* paths, so a lexically in-project destination that resolves out through a symlink does
not qualify. Still prompted (any two): raw **shell** commands, **`delete`**, **VCS mutations**, and
any target **outside** the project root — all fall through to Build behavior.

A declared write scope changes none of this class — `isInScopeFileTool` is untouched — but it
**pre-empts** it: while a ceiling is active, `declaredScopePosture` decides every write tool before
`autoEditsPosture` ever runs, so an in-project target Auto edits would have approved is denied
unless it was declared.

**11b. Legacy `write` vs successor `write_tree`.**
**No — the grant does not cover `mkdir`.** `capabilityMembers`
(`internal/permissions/capability.go`) is the table that settles it: `write` is exactly
`{create, edit}`, `write_tree` is `{create, edit, mkdir}`, `read*` is the six read/search tools.
Matching tests membership in the **stored** subject (`capabilityContains`, reached from `Match`),
so a pre-existing `write` grant keeps its original narrower meaning — it is never upgraded, and
nothing rewrites it on load. That compatibility guarantee is the whole reason both subjects exist.

Today the same approval stores **`write_tree`**, decided by `CapabilityForMember`
(`capability.go`) at the `GrantStoredSubject` call site in `DispatchTool`
(`internal/dispatch/tool.go`). It checks `write_tree` **first** and returns early; since
`write_tree` is a strict superset of `write`, every new create/edit/mkdir approval folds to
`write_tree` — which makes `CapabilityWrite` unreachable as a *return* value while it stays
meaningful as a *stored* one.

**Neither capability covers `move` or `delete`** — neither name appears in any member list, so
`CapabilityForMember` returns `("", false)` and both keep their concrete subject. One write
approval therefore never authorizes a relocation or an irreversible removal.

**12. Read-only auto-allow across modes.**
The read-only auto-allow covers **all three modes** — Plan, Build, and Auto edits — not just Plan.
So a bare read-only command (`rg`, `cat`, `vcs_status`) auto-allows everywhere, while Build still
prompts on ungranted *mutating* requests. In code: `modePosture` (`orchestrate.go`) checks
`planOperationClass(req, mc) == ClassReadOnly` for every mode *before* the per-mode switch, so the
read-only decision is made once and shared across modes.

**13. `mode.default` persistence.**
Default launch mode is `build` (config key `mode.default`, resolved by `config.Cache.ModeDefault`).
The active mode is **never** restored from a prior session — both launch and a resumed session start
from `mode.default` (a resume records `trigger: "resume"`). On `/clear` the mode **carries forward**
(`ActiveState.CarryForward`, a no-op on the shared instance), so the fresh session opens in the same
mode rather than resetting to the default. Source: `internal/mode/active_state.go`.
