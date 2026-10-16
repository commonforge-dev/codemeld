# Permissions and tool-execution rules

This page holds the detailed authorization, prompt-authority and tool-execution rules that
[`contributing/invariants.md`](../contributing/invariants.md) summarizes: what codemeld allows
without asking, what it refuses, what it asks about, and which code decides each case. The
cross-cutting rules (network egress, the permission front door, exact-name dispatch, settings-file
protection, and others) live in [`architecture.md`](architecture.md).

## An approved web host authorizes public web access only

A host grant names where codemeld may go, not what answers there. Approving a host must never become
a way to reach a loopback, private, or cloud-metadata service that the name resolves to.

`web_fetch` refuses loopback, unspecified, link-local, private and unique-local, carrier-grade NAT,
benchmarking, reserved and cloud-metadata destinations
([`internal/webresearch/address.go`](../internal/webresearch/address.go)), and a host grant cannot
override that. The check runs at dial time, on the address the dialer attempts, so it covers every
address actually tried and every redirect hop. The
[egress note](../contributing/invariants.md#note-extending-the-egress-policy) explains why the check
sits at dial time and why the `web_fetch` transport carries no proxy.

## A repository contributes nothing codemeld acts on until its root is approved

A cloned repository is written by someone else. Its settings can grant permissions, set the mode,
declare prompt-free commands, and supply the argv codemeld runs for version control, so reading them
on arrival would let any repository authorize itself.

Until the project root is listed in the approval store `~/.codemeld/global/approved-projects.yaml`,
a launch takes:

- **no** project settings layer — neither the shared `.codemeld/settings.yaml` nor the local
  `.codemeld/settings.local.yaml` is parsed;
- no project VCS template overlay from `.codemeld/vcs`;
- no `blocked_paths` entries from either file.

This is `gateTrust` in `internal/bootstrap/trust.go` and `runFreshCore` in
`internal/bootstrap/orchestrate.go`. `AGENTS.md` is **not** covered and loads regardless.

An interactive launch asks once per root, and approval is permanent: it names the root, not the
files' contents, so later commits to those files take effect with no further question. The store
lives outside every repository, and the structured file tools refuse to write it or its `.lock`
sidecar (see
[Protected settings state under confinement](architecture.md#protected-settings-state-under-confinement)).
A non-interactive run honors the list but never prompts and never appends to it
(`headlessTrustGate`).

## Modes drive permissions — they never replace them

Plan / Build / Auto edits change the *posture*, not the authorization model. There is still no
"approve everything." Structured tools and shell commands follow different rules.

**Constrained shell.** When a session's execution capability is constrained, the capability is the
authorization for shell commands in Plan and Auto. A direct or literal shell stage runs inside the
boundary with no ordinary command prompt, recorded with outcome source `confined` and no grant or
turn-cache entry (`confinedShell`/`planPosture`/`autoEditsPosture` in
`internal/permissions/orchestrate.go`).

- Exceptional-command prompts are **Auto-only**: a command that the fixed table in
  `internal/permissions/exceptional.go` (`ClassifyExceptional`) recognizes as network access, file
  deletion, or a VCS history rewrite asks with allow once or deny only, and the approved command
  still runs confined. The table matches program names and subcommands (for example `curl`, `rm`,
  `git clean`, `find -delete`, `git push`, `git rebase`, `git reset --hard`, `hg strip`,
  `commit --amend`); see
  [What the capability authorizes](architecture.md#what-the-capability-authorizes) for the full list.
- An unrecognized script or program (`bash build.sh`, `make`, `python tool.py`) runs confined with
  no prompt, so it can delete files or rewrite history inside the write roots without asking; it
  still cannot reach the network or write outside the write roots.
- A literal command that cannot be split into stages is not checked against the table; it needs an
  existing grant or a prompt answer, and still runs confined.
- With valid settings, Plan adds no exceptional authority — a network call or write fails inside the
  ordinary Plan boundary, with no prompt.
- A broken settings file after a passed self-test makes every shell command ask in **both** Plan and
  Auto, still confined.
- Build, and every mode on a `refused` host, uses the unconfined rules below.

**The mode is captured once per call.** `productionToolDispatcher.Dispatch`
(`internal/bootstrap/tooldispatch.go`) pins the active mode when a call's dispatch begins, after any
child-agent pin (`pinMode`). Authorization reads that pinned mode (`callMode` in
`internal/bootstrap/authdeps.go`) and so does the confined runner (`internal/bootstrap/confinedrunner.go`),
so an in-flight call keeps its mode through authorization and execution, including every shell
stage. Consecutive read-only calls authorized together capture the mode once per authorization
segment. A mode switch affects later calls only.

**Structured tools and unconfined shell.**

- Plan mode is **genuinely read-only — enforced, not just instructed**: write tools are not
  advertised and unconfined raw shell is classified read-only only for safe pipelines
  (`internal/permissions/planshell.go`).
- Read-only operations auto-allow in all modes without creating a grant, except web tools,
  out-of-project reads while the blocked-path list is unavailable, and shell commands that name a
  blocked path, which follow the ordinary grant and prompt rules.
- For a direct (`|`) pipeline that auto-allow is **per-stage**: each independently read-only stage
  auto-allows on its own and only genuinely non-read-only stages prompt (Build/Auto edits) or deny
  (Plan). `dispatchDirect` (`internal/dispatch/shell.go`) scopes the classifier to one stage per
  authorization.
- A recognized bare chain of `&&`/`||`/`;`/`|` is classified the same per-stage way (its stages
  reach the classifier as direct stages, not as one literal subject, and each `|` run executes as
  one pipe group); only a chain held whole by an `sh -c` wrapper, redirection, command
  substitution, backgrounding, a newline, or an environment-assignment stage stays whole-compound
  (see [the compound rule](#a-bare--compound-of-all-read-only-shell-stages-is-itself-read-only)). On
  that per-stage path an argument-sensitive program such as `sed` is judged by its own validator
  against the exact tokens, so `sed -n 1p f || uptime` auto-allows where the whole-compound path
  vetoed it.
- Authorize-all-before-run still gates execution, so a denied sibling stops the whole pipeline or
  chain before anything runs.

**Auto edits' auto-approval is bounded to the project tree and is not a grant.**
`autoEditsPosture`/`isInScopeFileTool` cover exactly `create`/`edit`/`mkdir`/`move`
(`isAutoEditsTool`) whose resolved target is `IsDescendantOrEqual` the canonical `ProjectRoot`.
Everything else — unconfined shell, `delete`, VCS mutations, any out-of-root target — keeps its
ordinary prompt. It decides **per call**, emitting `mode_auto`/`once` with no grant fields and no
turn-cache entry (`emitModeAuto`), so it can never widen what a later grant match covers. A switch
back to Build binds from the next tool call; a call already in flight keeps the mode it started
with.

## A non-interactive run is fail-closed (default-deny), never YOLO

`codemeld run` (the headless one-shot) has no interactive approver and is often fed untrusted input,
so it must not become a back door around the permission front door.

The headless authorizer (`internal/bootstrap/headless.go`) binds a default-deny prompt. Any call not
authorized by an existing grant, the active mode's auto-allow, or — on a `constrained` host — the
confinement boundary for a Plan or Auto edits shell command is denied in-band (a synthetic deny
envelope the agent reads and continues from), and nothing mutating runs outside those routes. A
confined command runs inside the same boundary as in the TUI, and its Auto exceptional-command and
broken-settings asks are prompts, so they deny without the flag below. The mode posture (including
Plan's mutating deny for structured tools and unconfined shell) is honored exactly as in the TUI.

**`--prompt-for-approval`.** `codemeld run --prompt-for-approval` opts into interactive terminal
escalation: a would-be-denied call instead pauses and asks on the terminal, offering four choices in
the TUI's order — allow once, deny, allow for this session, and **allow in this project**. The last
writes the ordinary folder grant to the project's local `.codemeld/settings.local.yaml` through the
same writer and revoke seam the TUI uses.

- **Allow in this project** is offered only when that run's project is approved (or holds nothing
  for approval to cover); for an unapproved project the prompt offers three choices and a typed `4`
  denies (`internal/bootstrap/headlessprompt.go`).
- The headless write path persists exactly two grant kinds, and only ever into that same local
  settings file: the folder grant, and the **exact project host grant** a web-tool approval creates
  (one host, one tool).
- Neither reaches the shared `.codemeld/settings.yaml`: codemeld writes that file only through the
  TUI `/settings` picker's two confirmed actions, sharing one entry into it and removing one from it.
- The **machine-wide global grant stays TUI-only**: it is never rendered, no input token reaches it,
  and the write path refuses a global grant and every other persisted kind before any write,
  degrading it to a session grant.
- The relaxation is licensed **solely by the tty requirement**: the flag exits 2 before the agent
  starts when stdin is not a terminal (`internal/cli/run.go`), so a prompt under it is always
  answered by a present human. Weakening, defaulting, or env-var-bypassing that check would turn an
  unattended process into one that can write permanent permissions, and is not a change to make
  without a fresh security review.
- EOF/empty/malformed input still denies.

**Default-deny is unchanged**: without the flag there is no prompt, no escalation, and no grant of
any kind. There is deliberately **no `--yolo`/skip-approvals flag**.

Every denial surfaces a friendly refusal line on stderr, but only terminal prompt/default-deny
subjects are gathered into the on-exit summary (`no approval available in non-interactive run mode`
/ `to authorize, grant …`). A recoverable Plan/mode-policy denial is left out of that summary — the
model reads its in-band deny envelope and continues.

## Every turn carries a product-authored system prompt

The model must know its tools, mode, and environment even with zero `AGENTS.md`.

The prompt is assembled in `internal/agentinstr` as the active mode base prompt, optional
model-specific special instructions, the generated environment context block, then loaded
`AGENTS.md` content, alongside the mode-filtered advertised tools. It is kept cache-friendly: no
per-turn-volatile content. See
[`contributing/learning/system-prompts.md`](../contributing/learning/system-prompts.md) for the
full system-prompt lifecycle.

## Only codemeld's product-authored prompt carries instruction authority — a compaction summary is data

A `/compact` summary is model-written text derived from whatever the conversation held, including
tool output codemeld does not trust. Sent as a `system` message it would sit in the same authority
channel as the product prompt — and on the Responses API it would become the top-level
`instructions` — so anything the summarizer copied, or was induced to write, would read as a
command on every later turn.

`messagesFromRecords` (`internal/turn/request.go`) projects a stored `sessions.Compaction` summary
as a **`user`** message: a note that its contents are reference data, then the summary verbatim
between `<prior_conversation_summary>` delimiters. That is the lowest-authority representation both
mappings share — `toSDKMessages` (`internal/provider/client.go`) sends a non-system message as a
user message and `responsesInstructionsAndInput` (`internal/provider/openai_chatgpt_client.go`)
puts it in `input`, while only a `system` message reaches `instructions`.

The summarization request itself carries exactly one system message, the fixed product-authored
`compactionSummaryInstruction` used by `BuildCompactionSummaryRequest`. Conversation, tool results,
and any earlier summary are named as material to summarize rather than instructions to follow, and
the summary must preserve goals, constraints, read-only scope, approvals already given, approvals
still required, unresolved work, and proposed-versus-completed status. History is never
concatenated into that instruction, and summary text is **never sanitized or keyword-filtered** —
the boundary is the transport role, not the content.

Pinned by `TestBuildCompactionSummaryRequest_InstructionLikeContentStaysData` and
`TestBuildRequest_InstructionLikeSummaryIsNeverASystemMessage` (`turn/request_test.go`),
`TestToSDKMessages_OnlyProductPromptOccupiesTheSystemRole` (`provider/client_test.go`), and
`TestChatGPTClient_OnlyProductPromptReachesInstructions` (`provider/openai_chatgpt_client_test.go`).

## Read-only tools read an explicitly named, unblocked path without a prompt; implicit escapes fail closed

The `read`/`grep`/`glob`/`list`/`tree` tools must never read outside the project through a path
nobody named. A path the model names explicitly is read as asked unless it is blocked; an implicit
escape is refused before anything is read.

All five reuse the shared read-target resolver (`internal/filetools/readresolve.go`).

- **In the project.** An in-project target auto-allows in every mode (`ReadOnly == true`, no shell
  allowlist entry needed for `find`/`tree`).
- **Explicitly named, outside the project.** An explicitly named absolute or `~` path outside the
  project resolves to its real external scope. When the blocked-path list is known, `PrepareTool`
  (`internal/dispatch/tool.go`) sets `ModeContext.OpenRead`, and `resolveWithoutPrompt`
  (`internal/permissions/orchestrate.go`) authorizes the read before grant matching or any prompt,
  recorded with outcome source `open_read`. So a structured read of an explicitly named path that is
  not blocked runs with no prompt and no grant, inside or outside the project, in every mode,
  headless runs included.
- **Exception: blocked-path list unknown.** When the blocked-path list is unknown (a broken settings
  file), `PrepareTool` sets `ModeContext.ExternalRead` instead. That bypasses **only** the read-only
  auto-allow and routes the read to the four-option prompt: approval grants read-only access to
  that folder for that tool, and denial blocks with no read and no grant.
- **Implicit escapes** — a relative `..` traversal, an in-root path whose final symlink escapes the
  root, a `~user` form, a directory-symlink root for the recursive tools, a malformed path — stay
  fail-closed before any read.
- The standalone (non-dispatch) `Invoke` path, having no authorizer, refuses an external target
  in-band.

## Tool calls overlap only within a contiguous run of project-confined structured reads, every other call is a serial barrier, and every overlapped read is recorded

Concurrency is where a single call nobody could positively classify would otherwise let something
mutating, external, or ambiguous run beside a read — and concurrency nobody can reconstruct
afterwards cannot be audited.

`productionToolDispatcher.Plan` (`internal/bootstrap/tooldispatch.go`) drops the synthetic
`production-tool-dispatch` conflict target — the only thing that lets `agent.Schedule` overlap
units — **only** for a call that is an exact `read`/`glob`/`grep`/`list`/`tree`/`file_count` name
whose arguments pass `filetools.ValidatePhase1ReadArgs` and whose target resolves through
`dispatch.PrepareTool` to a positively in-project scope.

- Any mixed, malformed, unknown, failed-preparation, `read_image`, external, VCS, shell, or mutating
  call keeps the target and becomes a **model-order barrier**: it waits for the run of eligible
  reads immediately before it, and the next run waits for it, so it never overlaps an eligible read
  and an `edit` followed by a `read` is still observed in that order.
- Because a barrier can change what a later read's path resolves to, an admitted read resolves its
  target again at dispatch and fails closed without dispatching if it no longer qualifies.
- Results are persisted in model-call order regardless of completion order.
- `agent.max_concurrency` is the sole cap (1 = sequential, peak never above the configured value);
  there is no second limit and no worker pool.
- A valid child-agent delegate call is the one other exception to the barrier rule: it is ordered by
  its child's declared targets, so delegates that cannot reach the same path may overlap under the
  same cap. An invalid delegate is a barrier.

Every overlapped invocation is wrapped in the `structured_read_start`/`structured_read_end` pair
(one UUIDv7 per invocation, exact tool name, resolved scope, configured cap, monotonic duration,
terminal outcome). A start that cannot be appended refuses the read, and an end that cannot be
appended surfaces as a dispatch error, so an unrecorded read never runs. Each excluded call instead
leaves one best-effort `structured_read_refused` planning record, so both facts — what overlapped
and what was held out — stay reconstructable. Permission prompts stay serialized by the shared
prompt gate alone (`internal/bootstrap/promptgate.go`); the scheduler adds no prompt locking.

## Out-of-root file writes are reachable only by explicit per-write approval

A structured `edit`/`create` outside the project root is sometimes legitimate, but must never happen
silently or by a blanket escape hatch.

An out-of-root resolved **real** target is not a hard `TargetError`: it routes to the four-option
prompt (once / session / this project / globally), anchored on the resolved real out-of-root folder,
and denial leaves no grant and no approval. The grant's `path_scope` may point outside the project
but its settings **file** stays in the project. Auto edits never auto-approves an out-of-root write
(`isInScopeFileTool` stays project-root-bound). Symlink-escape protection is preserved by the
real-folder path scope plus `create`'s invoke-time `O_NOFOLLOW` / `os.SameFile` / exact-parent
guards (`internal/filetools/{resolve,edit,create,delete}.go`).

**Exception — a [declared write scope](#a-declared-write-scope-is-a-ceiling-not-another-route-to-yes)**
(`--files-authorized`): a path the caller named on the command line before the run started is
written with no prompt even when it resolves outside the root. An out-of-root write is still never
auto-approved by a *mode*.

## `delete` is irreversible, so it is never auto-approved and never recursively wipes

A structured removal is the one mutating file tool whose effect cannot be undone, so it must never
be auto-approved by a mode, never ride a create/edit grant, and never silently delete a directory
tree. This is a stronger guardrail than the one on `edit`/`create`.

- The `delete` tool removes only a regular file, a final-component **symlink** (the link entry,
  never the file it points at), or an **empty** directory. A non-empty directory is refused in-band:
  the fd-relative `unlinkat` uses `AT_REMOVEDIR`, which the kernel refuses for a non-empty
  directory, so there is no recursive fallback.
- It is mutating but is **not** in the Auto edits in-scope class (`isAutoEditsTool` lists
  `edit`/`create`/`mkdir`/`move` — never `delete`) and is a member of **no** capability — neither
  legacy `write` nor its successor `write_tree` — so a delete always reaches an explicit
  grant/approval and one create/edit/mkdir approval never authorizes it.
- Containment reuses the create-tool construction: the removal goes through the held
  authorized-parent handle (revalidated `O_NOFOLLOW` / `os.SameFile` / exact-parent guards) so a
  post-authorization parent swap cannot redirect it. An out-of-root target is promptable per
  [the out-of-root write rule](#out-of-root-file-writes-are-reachable-only-by-explicit-per-write-approval);
  standalone `Invoke` refuses out-of-root in-band (`internal/filetools/delete.go`).

**Exception — a [declared delete scope](#a-declared-write-scope-is-a-ceiling-not-another-route-to-yes)**
(`--files-authorized-delete`): a path the caller named on the command line before the run started
is removed with no prompt. `delete` is still never auto-approved by a *mode* and still belongs to no
capability, and the empty-directory bound above is unchanged.

## Auto edits auto-approves a `move` only when *both* canonical endpoints are in project

A move has a source and a destination, and either can be outside the project root. A one-endpoint
check would let a prompt-free Auto edits approval relocate a project file to an arbitrary place on
disk (or pull an outside file in), so the containment test must cover the whole operation, not half
of it.

`PrepareTool` (`internal/dispatch/tool.go`) copies `filetools.ResolvedMove`'s **canonical**
`Source` and `Destination` — resolved through parent symlinks before any authorization and reused
verbatim at `InvokeWithResolvedMove` — into `ModeContext.MoveSource`/`MoveDestination`, and
`dispatchPreparedMultiScope` authorizes the move against them.
`isInScopeFileTool` (`internal/permissions/orchestrate.go`) auto-approves the move only when
**both** satisfy `IsDescendantOrEqual` against the canonical `ProjectRoot`; the single-target
`TargetPath` is never consulted for a move.

- Either endpoint outside the root — including a lexically in-project path that resolves out
  through a symlink — sends the whole move to the existing explicit-approval path (per-endpoint
  out-of-root folder-grant signal intact, source authorized first, denial blocking invocation with
  no mutation).
- A mode-auto move emits the ordinary `mode_auto`/`once` `permission_matched` with no grant fields,
  persists no grant, and writes no turn-cache entry.
- `move` stays outside **both** the legacy `write` and the successor `write_tree` capability, and
  ordinary move grants keep their concrete `move` subject, so auto-approval never widens what a later
  grant match covers.

## A declared write scope is a ceiling, not another route to yes

`codemeld run` is the non-interactive entry point, so a caller that names the files a job may touch
is stating a maximum. If a stale folder grant, the turn cache, a mode, or `--prompt-for-approval`
could still authorize a file the caller did not name, the declaration would be decorative.

`codemeld run --files-authorized <path>` lists what the run may `create`/`edit`;
`--files-authorized-delete <path>` lists what it may `delete`.

- Each flag **repeats** once per path and is never split on a separator, so a comma is filename
  text.
- The two lists are **independent** — one never implies the other, matching `delete`'s membership in
  no capability (see
  [`delete`](#delete-is-irreversible-so-it-is-never-auto-approved-and-never-recursively-wipes)).
- Either flag present activates the ceiling for the **whole run**, and it is then the **sole**
  authorization for `create`/`edit`/`delete`/`mkdir`/`move`. `declaredScopePosture`
  (`internal/permissions/orchestrate.go`) resolves at the top of `resolveWithoutPrompt`, **ahead
  of** mode posture, the grant match, the turn cache, and the prompt, and returns *handled* for the
  denial as well as the approval — so an uncovered write never falls through to a route that would
  have said yes.
- An absent list is an empty list **within** an active ceiling, not an absence of ceiling; with
  **neither** flag present authorization is entirely unchanged.
- `mkdir` and `move` are authorized by **neither** list, ever.
- A delete declaration covers the **exact path — a file, a symlink, or an empty directory** (a
  non-empty directory is still refused by `AT_REMOVEDIR`). A write declaration for a path whose
  parents do not exist also authorizes `create` building those parents, because it builds them
  inside its own single authorization.
- **Plan is untouched**: the check is skipped there, so `planPosture` stays the sole authority and a
  declared write is still denied (see
  [Modes drive permissions](#modes-drive-permissions--they-never-replace-them)).
- Declarations are canonicalized once, before the first agent turn, into the same targets the tools
  resolve — so a path swapped for a symlink afterwards no longer matches and is denied.
- Approval is **per call**: `permission_matched` with `outcome_source: declared_scope`, no grant
  fields, no turn-cache entry, no settings write. A miss is a terminal `denied_by: "user"` envelope
  that reaches the run's exit denial summary.

It binds codemeld's **file tools only**, not shell writes, and is **not a sandbox** — a write inside
a shell command never calls those tools. A confined shell command's writes are bounded by the
confinement policy's write roots, not by the declared file list; an unconfined command's writes are
bounded by nothing codemeld checks.

## A VCS action advertises read-only only from a trusted source; a repository-controlled template fails closed

A `vcs.<action>` marked read-only auto-allows in every mode without a prompt, so letting a
checked-in project template declare its own actions read-only would let a repository widen its own
trust boundary — a permission bypass.

Exactly three sources may advertise a VCS action as read-only:

- embedded built-ins;
- **unchanged** first-run built-in reference copies (byte-identical to the shipped `git`/`hg`/`jj`,
  detected by raw-byte equality, not YAML-equivalence);
- explicit `class: read_only` declarations in **trusted global** templates
  (`~/.codemeld/global/vcs/`) that run the built-in's own read-only argv for that backend and
  action, byte for byte. A declaration over any other command is a claim about something the
  product never vetted and earns nothing.

A project-local template (`<project>/.codemeld/vcs/`) is untrusted: its `class` declarations are
still checked for a valid value when it loads, but are ignored for classification, so every action
stays mutating (promptable). An absent, unknown, or non-string `class` fails closed in any
template — unknown/non-string is a load-time `ValidationError`; absent stays mutating.

`actionReadOnly` in `internal/vcs/tool.go` (via `RegisterActions` untrusted vs
`RegisterActionsWithTrustedClasses` trusted) gates the decision; `loadVCSTemplates` with
`overlayGlobalTemplates`/`overlayProjectTemplates` in `internal/bootstrap/vcs_bootstrap.go` mark the
global layer trusted and the project layer untrusted.

## Raw hg/git shell is read-only only for a curated subcommand set with no dangerous flag

`hg` and `git` are also destructive programs (they can `commit`/`push`/`rebase`/`checkout`), so
they cannot be admitted to the executable-name-only read-only allowlist — but their read-only
inspection (`log`/`status`/`diff`/`cat`/`show`) should auto-allow like the structured `read` tool,
mode-independently.

A per-program policy table in `internal/permissions/planshell.go` (`commandPolicies`) admits a
`RouteDirect` stage `<hg|git> <sub> …` as `ClassReadOnly` **iff** all three checks pass:

1. `<sub>` is in that program's curated subcommand set;
2. no stage token matches that program's dangerous-flag deny-list;
3. no stage token matches the deny-list scoped to the resolved subcommand.

Every other subcommand, any deny-listed flag, and every literal-route form except the
all-read-only compound carve-out and its neutral-redirect exception (see
[the compound rule](#a-bare--compound-of-all-read-only-shell-stages-is-itself-read-only)) — other
redirection, wrappers, command substitution — stays mutating (for an unconfined command: prompt in
Build/Auto edits, deny in Plan; on a `constrained` host Plan and Auto edits run it confined instead,
per [Modes drive permissions](#modes-drive-permissions--they-never-replace-them)). Classification flows through the existing `classifyReadOnlyShell`/`OperationClass` path, so it is
identical across modes with no mode-specific branch.

### Mercurial subcommands

hg `{status,st,diff,log,history,cat,summary,sum,files,help,grep,root,id,identify,manifest,parents,heads,annotate,blame,tags,branches,tip,paths,version,locate,export,verify,admin::verify,resolve,bookmark,bookmarks,branch,phase}`
— the whole Mercurial 6.7.2 command surface, hidden options included, audited command by command.

- Documented **aliases** are listed (`st`, `sum`, `history`, and the canonical `identify`, of which
  `id` is the alias). Command **prefixes** are not, because which prefixes hg resolves
  unambiguously depends on the installed extension set, so an admit-side prefix rule would fail
  open: `hg sta` stays prompt-gated.
- Seven entries are admitted only in an exact argument form, checked by
  `commandPolicy.subcommandArgs` — a per-subcommand check that runs **alongside** the deny scans,
  never a policy-level `validator`, which `stageReadOnly` returns from before it reaches the
  subcommand set at all:
  - `resolve` only as exactly `-l` or `--list` (`hg resolve --tool CMD` runs an arbitrary merge
    program, `-m`/`-u`/`--all` rewrite merge state);
  - `id`/`identify` only with **no positional token** — a SOURCE need not contain `://`, since hg
    resolves a `[paths]` alias, so `hg id default` reaches a remote over identify's hidden
    `-e`/`--ssh CMD` transport program with no URL text anywhere in the stage;
  - `bookmarks`/`bookmark` only bare or as exactly `-l`/`--list` (a positional NAME creates a
    bookmark, and `-d`/`-m`/`-r`/`-i`/`-f` delete, rename, or move one);
  - `branch` only bare (every argument it takes sets a branch, including its EXPERIMENTAL
    `-r`/`--rev VALUE`, which is why `branch` and `phase` never share a validator despite the
    identical spelling);
  - `phase` only bare or with the repeatable `-r`/`--rev` selector in its separate or `=`-joined
    spelling (`-p`/`-d`/`-s` move a phase boundary that is not locally reversible once a changeset
    is published).
- A flag's **value** is guarded by the deny scans rather than by the validator, so
  `hg phase -r --template` is rejected even though the validator consumed `--template` as that
  flag's value.
- Excluded: `config`/`showconfig`/`debugconfig` (`-e`/`-l`/`-g` launch `$HGEDITOR`, and the output
  prints `auth.*.password`); every `debug*` command (`debugstrip`, `debugsetparents`, `debugshell`,
  `debugupgraderepo`, … mutate or execute, and the set shifts between versions); `bisect`, because a
  bare `hg bisect` resumes the search and updates the working directory, so it has no read-only form
  worth a validator; and extension-provided `glog` and `shelve`, because the
  [automatic environment](#an-automatically-allowed-mercurial-process-runs-in-a-codemeld-owned-environment-a-prompt-approved-one-does-not)
  loads no extension — `hg shelve --list` is read-only at the Mercurial command level, but a command
  that may not exist has no basis for admission.

### Git subcommands

git `{status,diff,log,show,ls-files,help,grep,blame,ls-tree,describe,shortlog,show-ref,for-each-ref,merge-base,name-rev,rev-list,cat-file,check-ignore}`
— each token admitted only after its `git help <sub>` flag surface was audited for a flag that
writes a file, runs a program, or retargets the repository. `check-ignore` is admitted only with
`--no-index` plus its quiet, verbose, stdin, NUL-separator, and non-matching flags
(`gitCheckIgnoreArgsReadOnly`). Excluded for that reason:

- `branch`/`tag`/`remote`/`config`/`symbolic-ref`/`notes` (bare form reads, argument form writes);
- `stash`/`worktree`/`reflog`/`bisect` (read-only only in a sub-subcommand);
- `ls-remote`/`fetch` (network egress);
- `archive` (`-o` writes, `--exec` runs);
- `rev-parse` (its `--git-dir`/`--show-toplevel` flags collide with the position-independent deny
  scan).

`cat-file` is admitted, with its `--filters`/`--textconv` denied at subcommand scope.

### Program-wide deny flags

- hg: `--config`/`-R`/`--repository`/`--pager`/`-o`/`--output`/`--ssh`/`--remotecmd`/`--insecure`/`--debugger`/`-T`/`--template`/`--style`.
  hg runs `--ssh`/`--remotecmd` as the transport program; `--debugger` enters pdb, which reads
  Python from stdin, and debuggers are excluded; a template or style renders a configured
  `auth.*.password` verbatim, since `hg paths` hides passwords only for a plain formatter.
- git: `-c`/`--config-env`/`--git-dir`/`--work-tree`/`--exec-path`/`--output` — code-exec,
  repository-retargeting, and file-write vectors.

### Subcommand-scoped deny flags

`subcommandDenyFlags`: hg `id`/`identify` → `-e`, `admin::verify` → `--option`; git `grep` →
`-O`/`--open-files-in-pager`/`--textconv`/`--ext-grep`, `diff`/`log`/`show` → `--textconv`,
`cat-file` → `--filters`/`--textconv`, `help` → `-w`/`--web`.

- hg's `-e` is scoped rather than program-wide because the short-flag rule matches by prefix and
  would otherwise reject the documented read-only `hg help -e`. `--option` needs its own entry
  because it is neither equal to nor a prefix of the denied `--output`.
- `git grep -O[<pager>]` opens the matches in an arbitrary program, while the identical `-O`
  spelling on `git diff`/`log`/`show` is their read-only `--order-file`. `git help -w` opens the
  manual in a browser, while `-w` on `diff`/`blame`/`log`/`shortlog` only ignores whitespace or
  wraps output.

### Long-option abbreviations

Git resolves any unambiguous abbreviation of a subcommand long option, so a scoped long flag denies
**every prefix of itself** (so `git grep --textcon` and `git cat-file --fil`, which already run the
textconv program and the filter, are denied), minus an audited list of exact safe spellings on the
entry (`scopedDenyFlag.safeSpellings`, today only `--text` inside `--textconv` on
`grep`/`diff`/`log`/`show`).

- A blanket prefix match with **no** exemption is wrong for git because it would reject the real
  read-only `git grep/diff/log/show --text`, and the same blanket rule at program scope would reject
  `git rev-list --filter=blob:none`.
- An exact-only opt-out per flag would leave those abbreviations live, and a per-flag minimum
  abbreviation length is read off one binary's ambiguity set (`--textc` is the shortest unambiguous
  prefix only because `--text` exists), so it would fail open on a git whose flag set changed.
- A safe spelling is per subcommand, never program-wide: `cat-file` has no `--text` flag of its
  own, so `git cat-file --text` resolves to `--textconv`.
- The exact top-level git flags stay exact matches (`git.abbrevLong` unset), because git's
  top-level parser does not abbreviate (`git --git-di` is an unknown option).
- hg's deliberately over-broad program-level `abbrevLong` rule rejects `--debug`/`--debu`/`--deb`
  as prefixes of `--debugger`. That over-denial is accepted rather than adding a program-wide
  safe-spelling mechanism, because `--debug` only adds diagnostic output and a denied flag costs a
  prompt, never an auto-allow.
- hg also opts into `clusterShortFlags` so a bundle cannot conceal the program-wide `-R`, `-o`, or
  `-T` (`hg log -nT'{rev}'`); the same scan cannot tell a glued value from a bundle, so a revision
  spelled with an `R`, `o`, or `T` (`hg log -rTIP`) also prompts. The scan does not cover
  subcommand-scoped flags: a bundled identify `-e` (`hg id -ne CMD`) is refused because `id` admits
  no positional token.

### Finding the subcommand

`<sub>` is **not** `Tokens[1]`: `commandPolicy.stageSubcommand` scans the leading tokens for the
first one not starting with `-`, and only an exact `globalValueFlags` spelling may precede it — hg
`--cwd`, git `-C` — whose **separate** value token is skipped so a directory named like an admitted
subcommand (`hg --cwd status commit`, `git -C log commit`) cannot stand in for one.

- A `--flag=value` spelling consumes nothing, and a value-less `--cwd`/`-C` yields no subcommand.
- **Any other leading flag** — including hg's own abbreviation `--cw`, since the exact match is
  admit-side and hg's over-broad `abbrevLong` prefix rule stays deny-side-only — yields no
  subcommand and fails closed.
- The cwd-selecting flag is admitted rather than denied because read-only shell classification
  never consults path scope: `cd P && hg log` already auto-allows, and `hg --cwd P log` reads the
  same repository the same way, so denying it blocked no capability.
- The repository-retargeting flags (`-R`/`--repository`, `--git-dir`/`--work-tree`) stay denied,
  and both deny scans cover **every** stage token, so a permitted cwd flag never rescues a denied
  one.

## An automatically allowed Mercurial process runs in a codemeld-owned environment; a prompt-approved one does not

Argv is not hg's only input. A user or repository hgrc supplies aliases (`[alias] x = !<shell>` runs
a shell command), hooks, defaults, and extensions — none of them named by the argv the classifier
approved — and `HGPLAIN` alone stops none of them. Classifying the tokens is therefore not enough on
its own: the same auto-allowed `hg status` could run a configured program. But a command the
**user** approved at a prompt is the user's own decision, and silently stripping their configuration
from it would break a pager, colour, or alias setting they asked for.

`permissions.Decision.ReadOnlyAuto` (`internal/permissions/orchestrate.go`) is set **only** where
`modePosture` allows a request because it classified read-only — never for a prompt, a stored grant,
a turn-cache hit, a declared-scope allow, or any other mode posture. `authorizeStages` carries it per
stage into `planStages` (`internal/dispatch/shell.go`), and a stage that both holds it and runs `hg`
gets exactly `PATH=<inherited PATH>`, `HGRCPATH=/dev/null`, `HGRCSKIPREPO=1`,
`HGPLAIN=+strictflags` and **nothing else** — no `HOME`, locale, `HGENCODING`, `PYTHONPATH`, or any
other ambient variable. `PATH` is preserved only so executables resolve, and a stage assignment
cannot appear because an assignment-bearing stage never classifies read-only.

- This holds on the direct, pipeline, staged, and auto-allowed stripped-literal routes.
- One `sh -c` shares one environment, so a literal that reaches hg at all
  (`permissions.LiteralRunsHg`) takes the owned one; the read-only programs that may share such a
  literal need nothing beyond `PATH`.
- Prompt-approved, grant-approved, and cached hg commands keep `RunSpec.Env` exactly as they had it,
  non-hg stages are untouched, and ripgrep's single-variable scrub is unchanged.

The cost is deliberate: outside confinement, an automatic hg command does not honour user
configuration until the same command is approved through a prompt or covered by a stored grant.
Under confinement every command, hg included, runs in the fixed confined environment instead
(`runner.FixedEnvironment`, applied by `internal/bootstrap/confinedrunner.go`), which withholds
every `HG` variable but does not set `HGRCPATH`, so a confined hg reads hgrc normally.

## A program admitted by name alone has no write, program-execution, or scope-retarget flag — and argv is not its only input

An empty `commandPolicies` entry auto-allows every direct invocation of that program on every
platform in every mode without inspecting one argument (blocked-path checks still apply, and on a
`constrained` host Plan and Auto edits run it confined), and exempts it from the literal route's expansion-free requirement (see
[the compound rule](#a-bare--compound-of-all-read-only-shell-stages-is-itself-read-only)). The entry
is therefore an authorization claim about the program's whole flag surface. A flag list also does
not cover a program that reads options from somewhere other than argv.

Every entry of `commandPolicies` (`internal/permissions/planshell.go`) has been audited against three
hazard classes — a flag that writes a file, a flag that runs a program, a flag that retargets scope.

- **Entries with deny lists.** Four entries failed and carry `denyFlags`, so they are not
  name-only (`sort`, `date`, `hg`, `git`, and `jj` also carry deny lists: `sort` denies `-o`,
  `--output`, and `--compress-program`; `date` denies `-s` and `--set`; `jj` admits only the
  read-only subcommands `status`/`st`, `log`, `diff`, `show`, `evolog`, `interdiff`, `root`,
  `version`, and `help`, and denies `--config`, `--config-file`, `-R`/`--repository`,
  `--at-operation`/`--at-op`, `--tool`, and `-T`/`--template`; `hg` and `git` are covered in their
  own sections):
  - `rg`: `--pre` (runs a program per searched file), `--hostname-bin`, `-z`, `--search-zip`;
  - `file`: `-C`/`--compile` (writes a compiled magic database), and
    `-z`/`-Z`/`--uncompress`/`--uncompress-noreport`, which shell out to
    gzip/bzip2/lzip/lrzip/zstd;
  - `df`: `--sync` (flushes dirty buffers);
  - `tail`: `-f`, `-F`, `--follow` (an unbounded read; reads stay bounded).

  `file -m`/`--magic-file` stays admitted — it only selects the magic file to read, and denying the
  compile flags is what stops it being written.
- **Name-only entries, Linux audit.** `ls`, `cat`, `head`, `grep`, `wc`, `stat`, `pwd`, `du`,
  `which`, `realpath`, `readlink`, `basename`, `dirname`, `printenv`, `whoami`, `id`, `uname`, `nl`,
  `column`, `echo`, `jq`, `printf`, `true`, `cut`, `tr`, `col` were audited against GNU coreutils
  9.4, GNU grep 3.11, util-linux 2.39.3, and jq 1.7 on Linux. A deny list is a fail-closed superset,
  so denying a flag another platform's implementation lacks costs nothing, and no audited BSD or
  macOS option surface is claimed for those entries.
- **`cmp` and `od`** also stay name-only, and were additionally audited for option sources other
  than argv: against GNU diffutils 3.10 and GNU coreutils 9.4 on Linux and, because an empty entry
  carries no platform restriction, against the FreeBSD `usr.bin/cmp` and `usr.bin/hexdump` sources
  (releng/14.3 and releng/15.0) and macOS `shell_cmds-329`. They are the only name-only entries with
  an audited BSD and macOS surface.
- **`test` and `[` are not name-only.** They passed the same audit as external programs (GNU
  coreutils 9.4, FreeBSD `bin/test`, macOS `shell_cmds-329`), but that settles only the direct
  route, which runs `/usr/bin/test` and `/usr/bin/[`. On the literal route `sh -c` runs the shell
  builtin instead, Bash's builtin adds the `-v` and `-R` primaries, and `test -v 'x[$(…)]'`
  executes the command substitution inside the array subscript. So `test` and `[` are
  argument-sensitive pass-through entries whose arguments are checked: every direct argv is
  admitted, and a literal-route form auto-allows only when it passes the expansion-free check, so a
  literal-route `test` or `[` carrying `$`, `*`, `?`, `[`, `{`, or `~` prompts.

**Bundled short flags.** A bundled short flag is part of the spelling. `stageMatchesDenyFlag`
matches a short flag by prefix, so a cluster **led** by a denied flag (`rg -zn`, `file -Cb`) is
caught, but the same flag later in the cluster (`rg -nz`, `file -bC`, `sort -uo out.txt f`) is not
by that rule alone. `commandPolicy.clusterShortFlags` opts `rg`, `file`, `sort`, `tail`, `hg`, and
`jj` into scanning the whole cluster. That scan is **opt-in per policy, never blanket**: `date -Iseconds`
carries date's denied `-s` and is an asserted read-only form, so a blanket rule would reject it.
Over-denial inside an opted-in cluster costs a prompt; under-denial admits the flag.

**Options from the environment.** `rg` reads options from the file named by
`RIPGREP_CONFIG_PATH`, and a config line `--pre=<helper>` runs that helper for a plain
`rg needle file` carrying no denied token. So `internal/dispatch/shell.go` removes that variable
from every direct, pipe-group, or staged stage that runs `rg` or carries an assignment, and from
the `sh -c` of the literal route, where the shell decides what runs. Other inherited variables and
every authorized stage assignment survive, so an unconfined approved
`RIPGREP_CONFIG_PATH=<path> rg …` still takes effect. A confined command never receives the
variable, and an explicit assignment to it is refused, because the confined environment is a fixed
table.

Adding a name-only entry, or a flag to one of these deny lists, requires the same per-flag audit.
The membership of both the name-only set and the cluster-scan opt-in is pinned by
`TestReadOnlyExecutableSetUnchanged`, `TestVCSReadOnlySubcommandSetsAreCurated`, and
`TestShortFlagClusterScanIsOptInPerPolicy`.

## A bare `&&`-compound of all-read-only shell stages is itself read-only

A compound that stays on the literal route — `git diff | head 2>/dev/null && git log`, for example
— is authorized as one subject, so it would otherwise always prompt even though every stage is a
safe read. A plain `hg log && hg status`, or `hg log | head ; git status`, never needs this rule:
dispatch decomposes a recognized bare `&&`/`||`/`;`/`|` compound into direct stages, each
classified on its own (see
[Tool dispatch](architecture.md#tool-dispatch-is-exact-name-in-phase-1)). What still reaches this
rule is a compound whose wrapper, redirection, env assignment, or malformed stage kept it whole.

### When the compound is read-only

`classifyLiteralCompound` in `internal/permissions/planshell.go` removes the neutral redirects
(the classification strip below), splits the result with `SimpleCompoundStages`, and returns
`ClassReadOnly` **iff**:

- the subject carries no `$(`/backtick text at all (a literal subject runs verbatim through
  `sh -c`, where even quoted substitution executes);
- a **bare** compound either carries **at least one non-`|` operator** (`&&`, `||`, or `;`) **or**
  had a redirection removed by the strip; an `sh -c`-wrapped compound is admitted only under the
  [expansion-free rule](#argument-sensitive-programs-need-an-expansion-free-command) below;
- **every** decomposed stage is read-only under the same per-stage rule the direct pipeline uses
  (`stageTokensReadOnly` — the stage's program must have an entry in the `commandPolicies` table, or
  the `freebsdCommandPolicies` table, whose rule admits the stage's arguments), and no stage is a
  shell program or a `jj` stage.

A compound mixing `|` with those operators reaches this rule only when something else held it on
the literal route, and is admitted on the same all-stages-read-only basis. An **all-`|`** compound
is admitted on that basis only when the strip is what freed it: `grep a f 2>/dev/null | head` and
`grep a f | head 2>/dev/null` auto-allow, because the stripped copy is the stage list dispatch would
have judged one at a time anyway. A redirect-free `grep a f | head` never arrives here at all (it
stays on the direct route), and an all-`|` compound held whole by a wrapper, subshell, env
assignment, or surviving redirect stays mutating.

### The classification strip

Two redirections do not disqualify a command — discarding output to `/dev/null`, and duplicating one
standard descriptor onto the other, which creates no file and truncates none. `stripNullRedirects`
removes, from a **classification-local copy** before the stages are judged:

- the bare forms `>/dev/null`, `1>/dev/null`, and `2>/dev/null` (whitespace before the target
  allowed; a descriptor-less `>` may follow the preceding word directly as in `grep x f>/dev/null`,
  while a `1`/`2` descriptor must be its own token, so `grep x f2>/dev/null` stays mutating);
- the bare duplications `2>&1` and `1>&2` (both descriptors explicit and adjacent, so `>&1`,
  `3>&1`, `2>&3`, `2>& 1`, `2>&1x`, and `f2>&1` all stay mutating).

A lone command left by that strip is classified directly, so `grep -n x f 2>/dev/null` and
`grep -n x f 2>&1` auto-allow.

Everything else stays mutating and **fails closed**: a wrapper, any other redirection (`> out`,
`>> /dev/null`, `&>/dev/null`, `< in`, any other descriptor pairing, a variable or glob target, a
quoted or escaped target such as `2>'/dev/null'`), command substitution, backticks, an
env-assignment-bearing stage, a malformed compound, an argument-sensitive program such as `find`,
`sed`, or `awk` carrying an expandable token, or a compound with one non-read-only stage — because
`RecognizeSimpleCompound` rejects the un-tokenizable forms and `stageTokensReadOnly` rejects the
mutating stages. Quoted or escaped redirect-looking text is never structure and is never stripped,
so `echo "2>/dev/null" f` stays a direct-route `echo` whose argument happens to contain `>`, and no
quoted text can enable the strip.

### Argument-sensitive programs need an expansion-free command

An **argument-sensitive** program is the one exception to that refusal on this route. It is
read-only when its own validator passes **and** `tokenExpansionFree` proves **every raw token of
every stage** of the command inert, so the argv `sh -c` builds is provably the argv the validator
inspected. Quoted and escaped bytes are literal text, a double-quoted `$` still expands, and an
unquoted `$`, `*`, `?`, `[`, `{`, or `~`, an unterminated quote, or any byte outside the
always-inert set makes the token expandable. So `sed -n 1,5p f 2>/dev/null` auto-allows;
`sed -n 1,5p $F 2>/dev/null` and `sed -n 1,5p f 2>/dev/null && grep x *.go` do not.

- The condition is whole-command, not per-stage, because a variable in any stage can be assigned a
  value that changes what a later stage sees.
- The only `sh -c` wrapper spelling that is not mutating is the recognized
  `sh -c '<simple compound>'` carrying an argument-checked stage whose every token is inert
  (`sh -c 'sed -n 1,5p f'`). A wrapper with no argument-checked stage (`sh -c "ls"`,
  `sh -c 'hg log && hg status'`), any other wrapper spelling, and `bash -c` in every form stay
  mutating.
- A recognized bare compound that reaches the staged executor instead of `sh -c` is unaffected.
- **Name-only** allowlisted commands are outside the condition entirely, because their safety rests
  on the program name, so `grep x $F 2>/dev/null`, `grep x *.md 2>/dev/null | head`, and
  `grep a f 2>/dev/null | head -$N` are not held back by it.

The trigger is **argument-dependence, not a validator**. A policy whose verdict reads argument text
— a validator (for example `find`, `sed`, `awk`, `top`), a `readOnlySubcommands` set (`hg`, `git`,
`jj`), or a `denyFlags` list (`hg`, `git`, `jj`, `sort`, `date`, `rg`, `file`, `df`, `tail`) — is judged on the
literal tokens it was handed, and the shell expands `$X` into a denied flag *after* that scan. So
`hg log $X 2>/dev/null`, `hg log $X 2>/dev/null | head`, `hg log $X && hg status`,
`sort $X 2>/dev/null`, and `date $X 2>/dev/null` all stay mutating on both the single-stage and
compound forms of this route, while the expansion-free `hg log 2>/dev/null | grep x | head -20`
still auto-allows. `commandPolicy.argDependent` is that predicate. A name-only entry is an empty
policy, so it is never argument-dependent — an exemption only as sound as the entries it trusts,
which is why every entry was audited (see
[name-only programs](#a-program-admitted-by-name-alone-has-no-write-program-execution-or-scope-retarget-flag--and-argv-is-not-its-only-input)).
`rg`, `file`, `df`, and `tail` carry deny lists and are argument-dependent like the rest, which is
why `rg needle *.md 2>/dev/null` and `file -b *.md 2>/dev/null` prompt while the redirect-free
direct-route `rg needle *.md` still auto-allows.

### Grant identity uses a second, narrower strip

The classification strip above and the grant strip are two different rules, and neither is the
other. `stripNullRedirectsForGrant` / `RecognizeSimpleCompoundForGrant`
(`internal/permissions/compound.go`) remove only the bare `>/dev/null`, `1>/dev/null`, and
`2>/dev/null` forms, never the duplications `2>&1` and `1>&2`, and the two **stdout** forms only on
a stage that does **not** feed a pipe (the last stage, or one followed by `&&`, `;`, or `||`) —
`a >/dev/null | b` and `a | b` do not deliver the same bytes to `b`, the same downstream-data reason
that excludes the duplications. So a saved compound grant's identity is "the compound modulo bare
`/dev/null` redirects".

- When that grant strip actually removed a redirect, the command must **also** be expansion-free
  across every stage (`stagesExpansionFree`), because `sh -c` re-parses the text the per-stage
  chooser generalized. A redirect-free compound keeps exactly the recognition it had, with no extra
  gate.
- Every other redirect keeps a **byte-exact** grant — a different target, `>>`, `<`, `&>`, `3>&1`,
  a quoted target such as `2>'/dev/null'`, or a glued word suffix such as `f1>/dev/null` (an
  argument followed by a stdout redirect, never an explicit descriptor).

Execution is untouched by both strips: `CanonicalLiteralForm`, `RecognizeSimpleCompound`, and
`SimpleCompoundStages` still see the original redirect bytes, so the command still routes to
`dispatchLiteral` and still runs verbatim through `sh -c`, and the prompt still shows the redirect.
The classification strip alone is mode-auto only (it stores no grant at all), mode-independent
through `classifyReadOnlyShell`/`OperationClass`.

## Raw `find` shell is read-only only for a narrow argument-parsed listing subset

`find` can mutate (`-delete`, `-exec`, `-fprint`, …), so its program name alone cannot make it
read-only — but common listing/filtering forms (`find . -type f`, `find src -name '*.go'`) read only
and should auto-allow like the structured search tools. Safety is argument-position-sensitive, so a
token deny-list is not enough.

`find` has an argument-validated `commandPolicies` entry whose validator is `findStageReadOnly` in
`internal/permissions/planshell.go`, so `stageTokensReadOnly` admits a `find` stage only when that
fail-closed left-to-right parser accepts it. It admits a `RouteDirect` `find` stage as `ClassReadOnly` **iff** every token
is consumed in the position the parser expects:

- one or more **relative** start paths (rejecting absolute paths, any `..` segment,
  empty/dash-leading tokens, and `--`);
- then **only** supported read-only predicates with validated values: `-type`,
  `-name`/`-iname`/`-path`/`-ipath`, `-maxdepth`/`-mindepth`,
  `-mtime`/`-ctime`/`-atime`/`-mmin`/`-cmin`/`-amin`, `-size`, `-newer` (its value validated as a
  start path by `findValidStartPath`), `-empty`, `-print`, `-print0`, joined by the boolean
  operators `-a`, `-o`, `!`, and `-not`.

Binary `-a` and `-o` require a complete expression on their left; all four accepted boolean
operators require a complete expression on their right. Parentheses, comma operators, unknown
options, and malformed expressions remain mutating, as do any mutating action, missing or invalid
value, or a plain path token after the expression begins.
Env-assignment, wrapper, and other-redirection `find` forms still fail closed upstream in
`classifyReadOnlyShell`; a literal-route `find` is read-only only under the whole-command expansion-free
rule (see [the compound rule](#a-bare--compound-of-all-read-only-shell-stages-is-itself-read-only)).
It composes per-stage with the direct pipeline (`find . -type f | grep foo | head` auto-allows), and
grant semantics are unchanged. Parentheses, comma operators, symlink flags,
`-printf`/`-prune`, and absolute/parent-traversal starts are intentionally excluded and need a fresh
security review to add.

## A web tool call is never auto-allowed by a mode — an approval or a grant made at the prompt is the only route to the network

Web research is eligible only when the user asked for it, and what counts as proof is settled: a
human answer at the permission prompt, or a grant previously created at one. No user text is
inspected and there is no `/research` command, so a single automatic allow anywhere around the call
would void the whole authorization boundary — and a mode-generated *deny* would hide the prompt just
as effectively.

`PrepareTool` (`internal/dispatch/tool.go`) marks a call to the two exact registered names
`web_search`/`web_fetch` — and nothing else — with `ModeContext.NetworkEgress`, pinned to the names
rather than derived from the tool's advertised read-only classification, so a later
re-classification cannot restore the read-only auto-allow. `modePosture`
(`internal/permissions/orchestrate.go`) resolves **no** marked call: it skips the read-only mode
auto-allow, Plan's mutating deny, and Auto edits' in-scope approval alike, so the call continues to
ordinary grant matching and, absent a match, to the prompt — in Build, Auto edits, and Plan.

- An unapproved call denies through the existing bounded `denied_by:"user"` envelope with no grant,
  no cache entry, and no socket opened, leaving the model free to propose the call again.
- Neither an enabled `web_research` setting, a configured API key, nor tool registration is
  authorization; those only decide whether the tools exist.
- An approved or granted call proceeds under the ordinary exact-host matching.

## An approved `web_search` reaches exactly one host — `mcp.exa.ai` — and a result host is reached only by an explicit `web_fetch`

A search that also fetched its own results would turn one approval into a burst of per-page prompts
for pages nobody chose. Approving *a search* must not be a decision about *which pages get read*;
those are separate questions and get separate answers.

`dispatchWebSearch` (`internal/bootstrap/tooldispatch_web.go`) authorizes `mcp.exa.ai`, calls the
`SearchBackend`, and hands the ranked candidates straight to `encodeSearchCandidates`, which builds
model-visible metadata only — `title`, `url`, `snippet`, `published_date`, each bounded at the
capability layer rather than trusting the backend's own caps, plus an `omitted` count for usable
HTTPS candidates the result does not carry, whether past the five-candidate limit or too long to
carry as a whole URL.

- There is **no** call to `webresearch.FetchText` on that path: no candidate host is authorized, and
  no candidate socket is opened.
- A non-HTTPS or malformed candidate is dropped and is not counted as omitted.
- Each surfaced `url` is the complete canonical credential-redacted URL `web_fetch` accepts, never a
  truncated one — a cut through a percent escape would name a different target or none.
- Reading a candidate is an ordinary `dispatchWebFetch` call the model issues itself, authorized on
  its own exact canonical host before the dial with every redirect, scheme, port, media-admission,
  extraction, and output bound intact.
- Candidate titles and snippets stay untrusted external data.

## `bash`/`sh` are read-only only for four exact no-exec syntax-check spellings on the direct route

`bash` and `sh` execute arbitrary code, so they are wrapper programs that never reach direct
matching — which would make a pure syntax check (`bash -n script.sh`) prompt in Build/Auto edits and
deny in Plan even though Bash's no-exec mode parses without running a single command. One
unrecognized option would restore execution, so the exception must be argument-sensitive and closed.

The accepted grammar is exactly `bash -n`, `bash -o noexec`, `bash -O extglob -n` (either option
order), and `sh -n`, each followed only by plain non-option script operands (`noExecShellTokens` in
`internal/permissions/planshell.go`, wired as the `bash`/`sh` `commandPolicy` validators and reused
by `noExecShellStage` in `internal/permissions/normalize_direct.go` to lift **only** those forms out
of `wrapperPrograms`). `-O extglob` is admitted only alongside `-n`, because a parser setting must
never be the whole option list.

Everything else **fails closed** and keeps its posture (for an unconfined command: prompt in
Build/Auto edits, deny in Plan, nothing executed without approval; on a `constrained` host Plan and
Auto edits run it confined instead): `bash --noexec` (not a Bash option at all), `-c`, interactive/login/startup
options, any other `-O` value, any unknown flag, a dash-leading, plus-leading, or empty operand, bare
`bash`/`sh`, a path form (`/bin/bash -n`), a quoted or escaped program word (`"bash" -n`), and a
leading env assignment (`FOO=bar bash -n`).

- The plus-leading exclusion is load-bearing: `+n` and `+o noexec` — and grouped spellings such as
  `+xn` — cancel no-exec mode, so `bash -n +n f.sh` would parse the script and then **run** it. A
  script whose name begins with `+` stays reachable as `bash -n ./+f.sh`.
- The exception holds **only where dispatch runs the exact validated argv** — `dispatchDirect` and
  `dispatchStaged`. A shell stage reached through the literal route is forced mutating by
  `stageIsShellProgram`, so `sh -c "bash -n f.sh"`, `bash -n f.sh > out`,
  `bash -n f.sh > /dev/null`, and a literal-route `bash -n f.sh && ls` never borrow the direct
  verdict.
- Accepted forms auto-allow identically in Build, Auto edits, and Plan through the one shared
  `classifyReadOnlyShell`/`modePosture` path, with no grant stored.

**Routing is not classification.** A **standalone** flagless script invocation is also lifted onto
the direct route: `scriptInvocationStage` in `internal/permissions/normalize_direct.go` accepts a
bare, unquoted, unescaped `bash`/`sh` program word, no leading env assignment, and a first operand
that is non-empty and begins with neither `-` nor `+` (everything after it is the script's argv and
is not inspected). So `bash process-dir.sh u.txt` becomes the direct subject
`["bash", "process-dir.sh", "u.txt"]` and can be approved once as `bash process-dir.sh :*` instead
of one dead byte-exact string.

- That confers **no** read-only status: `commandPolicies["bash"]`/`["sh"]` still validate with
  `noExecShellTokens`, so `bash foo.sh` stays `ClassMutating`: unconfined, it still prompts in Build
  and Auto edits and denies in Plan; on a `constrained` host Plan and Auto edits run it confined.
- The plus-leading rejection is load-bearing here too: `bash +O extglob -c '<code>'` parses `+O` as
  an invocation option and still reaches `-c`, so it stays literal and no direct `bash :*` or
  `bash +O :*` grant can authorize it (`grantMatches` requires equal subject kinds).
- The exception is **single-stage only**: `NormalizeDirectStage` takes a `StageContext` and admits
  the grammar only under `StageSolo`. `SplitCommand` supplies `StageSolo` only for a one-stage
  command and `StageInCompound` for every pipeline stage, and `SimpleCompoundStages` supplies
  `StageInCompound` to every stage it rechecks — so `bash process-dir.sh u.txt | tail -n 25` stays
  one byte-exact literal subject and still executes as `sh -c '<original pipeline>'`, keeping the
  outer shell's expansion and streaming.
- A direct-routed stage runs from verbatim argv, so `bash script.sh *.txt` reaches the runner
  unexpanded while a bare leading `~` still expands through `ExecForms`, exactly as
  `./script.sh *.txt` already behaves.

## `command -v <name>` is read-only only as a resolved bare lookup, and codemeld answers it in Go rather than running anything

`command` is a wrapper that can launch any program (`command sh -c '…'`), so it never reaches direct
matching — which would make the pure question "is `magick` installed?" prompt every time. It is
also a shell **builtin**: there is no `command` executable to launch, so admitting it as an
ordinary direct stage would authorize a lookup and then fail to perform one.

The accepted grammar is exactly `command -v <name>` — one operand, spelled as a plain program name
of letters, digits, `_`, `-`, `.`, `+` and not starting with `-` (`commandLookupTokens`/
`plainProgramName` in `internal/permissions/planshell.go`, wired as the `command` `commandPolicy`
validator). `commandLookupStage` in `internal/permissions/normalize_direct.go` lifts **only** that
form out of `wrapperPrograms`, requiring every token to be the bare, unquoted, unescaped spelling
and the stage to carry no leading env assignment, and it qualifies the carve-out on `exec.LookPath`
resolving the operand. The resolved path is kept on `StageNormalization.LookupPath`, and
`builtinLookupResult` (`internal/dispatch/shell.go`) returns it plus a newline with exit 0 from
`dispatchDirect` and `dispatchStaged`, so **no shell and no program is executed and the path is
never resolved a second time**.

- The admitted namespace is PATH executables only: a shell alias, function, or builtin such as
  `cd` is a **miss**, and every miss keeps the literal route and prompts, because telling an absent
  program apart from a builtin would mean running a shell.
- `type <name>` with exactly one plain program-name operand is admitted the same way and answered
  in Go (`typeLookupTokens`, `typeLookupStage`); every other `type` form is not.
- Everything else **fails closed** (for an unconfined command: prompt in Build/Auto edits, deny in
  Plan; on a `constrained` host Plan and Auto edits run it confined): `command -V`, every other
  `type` form, a bare or multi-operand `-v`, any other option, `command ls -la`, `command sh -c '…'`, a path or
  dash-leading operand, an operand carrying quoting, whitespace, `=`, or a metacharacter, a quoted
  or path-form program word, and a leading assignment such as `PATH=/opt/bin command -v foo`.
- As with the no-exec shells, the exception holds only where dispatch performs the validated
  operation: `stageIsShellProgram` forces `sh -c "command -v magick"` and
  `command -v magick > out` mutating.

## `top` is read-only only as a Linux bounded batch run; `col` is a name-only filter

Without `-b`, `top` seizes the terminal and never returns, so it can never be trusted by program
name — but a bounded batch snapshot is a pure read, and with no entry at all every stage naming
`top` would fail closed. `col` is the opposite case: a stdin-to-stdout formatting filter whose whole
option set (`-b`, `-f`, `-p`, `-h`, `-x`, `-l NUM`) only reflows or buffers output, so the name
alone is enough. Only Linux is covered, because the procps-ng option dialect is the one that was
verified.

`topStageReadOnly` in `internal/permissions/planshell.go` is wired as the `top` `commandPolicy`
validator with `platforms: linuxOnly` and `argSensitive: true`. A stage is `ClassReadOnly` **iff**
it carries `-b` **and** an `-n` whose value is a positive integer bounded by `maxDiagCount`
(separated or glued, as `journalctl --lines` is), and every remaining token is one of the
display-only flags `-e`/`-E` (one scale letter), `-o` (an alphanumeric sort-field name with an
optional `+`/`-`), `-p` (a `validPidList`), `-H`, `-h`, `-V`, `-O`.

- Everything else **fails closed** (stays mutating: prompt or Plan deny when unconfined, a confined
  run in Plan and Auto edits on a `constrained` host): bare `top`, `top -n 1`, `top -d 1`, `top -b` with no count,
  `-n 0`, `-n 99999`, a clustered `-bn1`, any long option (`--batch-mode`), any unlisted flag
  (`-d`, `-u`, `-s`), a missing or malformed value, and **every** `top` form on FreeBSD and macOS.
- Being argument-sensitive, `top` is read-only on the direct and staged routes only, and a literal
  route needs the whole-command expansion-free rule — so `top -b -n 1 -p $$` stays mutating.
- `col` is a bare `commandPolicies` entry judged by name like `cut`/`tr`/`nl`.
- Admitted forms auto-allow in Build, Auto edits, and Plan with no grant and no turn-cache entry.

Instructions never widen this. `internal/agentinstr/baseprompts/shared.md` tells the model the
Linux-only bounded batch form in every mode and that FreeBSD/macOS `top` is not automatic, and
`modeDenyReason` (`internal/permissions/orchestrate.go`) answers a Plan-mode denial of a **direct
Linux** `top` stage with corrective wording naming `-b`, a bounded positive `-n`, and
`top -b -n 1`. Every other command, route, and platform keeps the generic recovery text, and the
validator remains the only authorization.

## Raw `awk` shell is read-only only for a program that cannot write, run commands, or reach past its operands

AWK is a programming language: `system()`, a command pipe, and a coprocess run programs, `getline`
reads an unvalidated source, `>`/`>>` write files, `ENVIRON`/`PROCINFO` expose the environment,
`ARGV`/`ARGC` change which files are read, and `-f`/`-v` replace or reprogram the script — so it can
never join the executable-name-only allowlist. But the programs a reader actually asks for — a line
range, `{print $1}`, a filter such as `$3 > 100`, a column sum — are pure reads and would otherwise
prompt every time.

`awkStageReadOnly` in `internal/permissions/planshell.go` is wired as the `awk` `commandPolicy`
validator with `argSensitive: true` (`awk` stays **out** of the name-only set, pinned by
`TestReadOnlyExecutableSetUnchanged` and `TestVCSReadOnlySubcommandSetsAreCurated`).

### Stage shape

A stage is `ClassReadOnly` **iff** it is:

- optional field-separator options before the program — `-F sep` with a non-empty separate
  argument, or the attached `-Fsep` — and no other option (`-f`, `-v`, `-E`, `-i`, `-l`, `--`, and
  every long option such as `--field-separator=:` reject);
- then exactly one inline program;
- then **zero** or more input operands. Zero operands is allowed: the program reads stdin, which
  holds only what the user piped in (`ls -l | awk '{print $5}'`).

### Program check

The program is admitted through either of two paths.

**Range-print grammar.** `awkRangePrintProgram` admits one shape — one inclusive range over a single
counter (`NR >= N && NR <= M`, or `FNR` on both sides) then one `{ print … }` of `NR`, `FNR`, `$0`,
digit strings, and backslash-free strings — so `awk 'NR>=55 && NR<=70 {print NR ":" $0}' file`
auto-allows.

**Lexer.** Every other program goes through `awkReadOnlyProgram`
(`internal/permissions/awkprogram.go`), which walks it token by token, skips whitespace and `#`
comments, and **fails closed** on:

- a `>` or `>=` anywhere inside a `print`/`printf` statement, even a parenthesized comparison
  (`{ print (a > b) }`) that writes nothing, because AWK allows an output redirection in those
  statements and the lexer does not try to tell a redirect from a comparison, so it refuses both.
  The statement ends at `;`, `}`, or a newline that follows a complete value at the statement's own
  parenthesis depth (a newline after `,`, `&&`, `||`, or `?` continues it), so `$3 > 100 { print }`,
  a comparison outside any print, is admitted;
- `>>` anywhere (append redirect);
- `|` other than as part of `||` (a command pipe `| "cmd"`, `"cmd" | getline`, or gawk's coprocess
  `|&`);
- `@` (gawk's `@load`/`@include` and indirect calls such as `@f("id")`, which reach a function by a
  name held in a variable);
- a backtick, a single `&`, a bare `\` other than a backslash-newline line continuation, and any
  other byte outside AWK's operator set, because none is part of read-only AWK and an unknown byte
  is never guessed at;
- the identifiers `getline` (reads a file or command output), `system` (runs a command), `close`
  and `fflush` (act on output files and command pipes, which a read-only program never opens),
  `ENVIRON` and `PROCINFO` (environment and process data, including secrets), `ARGV` and `ARGC`
  (rewrite the operand list — `BEGIN { ARGV[1] = "/etc/shadow" }` — so the program reads a file the
  operand checks never saw), and `SYMTAB` and `FUNCTAB` (gawk's by-name access to any variable or
  function, a back door to the banned ones);
- a number that runs straight into a letter (`0x1system("id")`), because some AWKs read hex
  literals and the token boundary would differ;
- a `/` outside the regex and unambiguous-division positions.

**Regex versus division.** AWK's `/` either starts a regex or divides, and a misread hides code
inside what the lexer took for regex text (`/"/ { print > "/tmp/x" } /"/`). So `/` starts a regex
only where an operand is expected (program start, after an operator, `(`, `{`, `;`, `}`, a newline,
`print`, `printf`, `return`, `exit`, or `in`) and divides only right after a value (a variable,
number, string, `]`, or a `)` that does not close an `if`/`while`/`for`/`switch` condition), so
`{ s += $2 } END { print s/NR }` is admitted. Anywhere else — after `$`, `++`/`--`, a regex, a
control-statement `)`, or a keyword such as `length`, `next`, or `if` — the reading depends on
context the lexer does not model, and division there fails closed.

The program is also rejected if a literal is unterminated or contains a newline, or if a regex
contains a bracket expression that holds a `/` or is left unclosed before the regex ends; a
backslash followed by a newline inside a string or regex counts as a newline. AWK implementations
disagree on whether a `/` inside a bracket ends the regex, so `/[/]/` prompts as a deliberate
fail-closed choice, not because it is invalid AWK; `/\//` (the slash escaped outside a bracket) is
the admitted spelling. An empty or comment-only program is rejected.

### Operands and routes

Every operand after the program must be non-empty, not start with `-`, contain no `=` (AWK reads
`name=value` as a variable assignment, not a file), and not start `/dev/` or `/inet` (GNU AWK
resolves `/dev/tcp/host/port`, `/dev/udp/host/port`, and `/inet/tcp/0/host/port` to an outbound
network connection, not to a file on disk).

Being argument-sensitive, `awk` is read-only on the direct and staged routes, which run the exact
validated argv. A literal `sh -c` route needs the whole-command expansion-free rule, so
`sh -c 'awk "{print NF}" f'` and `sh -c 'awk "NR>=1 && NR<=10 {print}" f'` auto-allow while a
leading assignment, `bash -c`, a nested or trailing-operand wrapper, command substitution, an unsafe
redirect, and a double-quoted program carrying an unescaped `$` stay mutating. Admitted forms
auto-allow in Build, Auto edits, and Plan with no grant and no turn-cache entry; every rejected form
keeps its prompt/Plan-deny posture when unconfined, and runs confined in Plan and Auto edits on a
`constrained` host.

## Direct `ps` is read-only for any argument list, on Linux and FreeBSD alike

The question a read-only classification answers is whether a command can **write a file, execute
another program, create network egress, or escape scope** — and no documented `ps` option on either
platform does any of those. A narrow per-platform flag allowlist would make ordinary reads prompt:
`ps --help`, `ps --version`, `ps -eF`, `ps --forest`, `ps -eo pid,cmd --sort=-pcpu`, `ps -L`, and
`ps ax` on Linux; `ps -ww`, `ps -tt`, `ps -L`, `ps -Dboth`, `ps 1234`, `ps -o etime,nlwp`, and
every `--libxo` form on FreeBSD.

- Linux `ps` reports a `/proc` snapshot.
- FreeBSD `ps(1)` (15.0-RELEASE-p8) documents no output-to-file, signal-delivery, write, execution,
  or scope-escape option, and its positional operands are PIDs. FreeBSD `-e` reads process
  environments and `-M`/`-N` read caller-chosen core/namelist paths — reads the name-only `cat` and
  `printenv` already perform — and `--libxo` loads an encoder only via `XO_ENCODER_PATH`, which the
  leading-assignment rule refuses.
- This axis is **not** a confidentiality filter: what the agent may see is bounded by the
  system-wide-readers trade-off that already covers every process/socket/log reader, not by which
  `ps` options are spelled out.

One shared `psStageReadOnly` in `internal/permissions/planshell.go` is wired as the validator for
**both** the Linux and the FreeBSD `ps` `commandPolicy` row, each keeping its own `platforms` entry.
It classifies a stage `ClassReadOnly` for any argument list, with one refusal: a token containing
command-substitution syntax (`$(` or a backtick) fails closed.

- A substitution the shell would perform never reaches the validator on a direct stage:
  `SplitCommand` refuses an unquoted one before any prompt and sends a double-quoted `"$(cmd)"` down
  the literal `sh -c` route, where it always prompts until an exact-text grant covers it. So the
  refusal only costs a prompt for inert quoted text such as `ps '$(id)'`.
- A direct `ps "$HOME"` or `ps '*.go'` auto-allows, because under direct execution the literal argv
  runs and a variable or glob only changes argument text.
- Both rows stay `argSensitive`, so the route guards are unchanged: a leading assignment, a
  file-target redirect, command substitution, and the mutating compound/literal forms —
  `LD_PRELOAD=/tmp/x.so ps -ef`, `FOO=bar ps -ef`, `ps -ef > out`, `ps -ef && ls`,
  `sh -c "ps -ef && ls ~/x"`, `ps "$(id)"` — stay mutating.
- The recognized inert `sh -c` wrapper and bare `/dev/null` routes, open to `ps` on Linux
  (`sh -c "ps aux"`, pinned by `TestDiagnosticsRouteVerdicts`), keep their existing guards and
  follow the shared validator, so `sh -c "ps --help"` and `ps --help 2>/dev/null` auto-allow exactly
  as the direct forms do.
- Admitted forms auto-allow in Build, Auto edits, and Plan with no grant and no turn-cache entry.

This rule covers `ps` alone: the FreeBSD `pgrep`, `pidof`, `pstree`, `fstat`, `procstat`,
`sockstat`, `vmstat`, and `uptime` validators and their Linux counterparts stay per-option
fail-closed.
