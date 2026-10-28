# Invariants — what a change must not break

_Last updated: 2026-10-24_

These are the non-negotiables. A change that violates one of them will be rejected
regardless of how useful it is otherwise. Each row gives the rule, why it exists, and where a
violation gets caught, then links to the section that states it in plain words: cross-cutting
rules in [`docs/architecture.md`](../docs/architecture.md), and what codemeld allows, asks about,
and refuses in [`docs/approvals.md`](../docs/approvals.md). These can be **extended** by later work — but only deliberately,
opt-in, and behind the permission system, never by quietly loosening a default (see the
network note below).

| Invariant | Why | Enforced by |
|-----------|-----|-------------|
| **No outbound network except to sanctioned destinations** | Zero phone-home: no telemetry, analytics, crash reporting, or update checks. | `NewClient` (`internal/provider/client.go`); code review; the no-network tests cover only idle startup and one headless turn. [Details](../docs/architecture.md#privacy--telemetry). |
| **An approved web host authorizes public web access only** | Approving a host must never reach a loopback, private, or cloud-metadata service the name resolves to. | Dial-time address check in `internal/webresearch/address.go`. [Details](../docs/approvals.md#web-access). |
| **The permission system is the front door** | It authorizes structured tools, web tools, and unconfined shell; only the confinement boundary also authorizes, for Plan and Auto edits shell on a `constrained` host. | No YOLO or opt-out mode; `internal/enforce`, `internal/bootstrap/confinedrunner.go`. [Details](../docs/architecture.md#permission-system-is-the-front-door). |
| **No CGO** | The deliverable is one static binary per platform with no runtime dependencies. | `CGO_ENABLED=0` in the documented build command ([`setup.md`](setup.md)). [Details](../docs/architecture.md#no-cgo-in-phase-1). |
| **Tool dispatch is exact-name** | Predictable authorization; no surprising pattern matches. | Flat `tools.Registry.byName map[string]entry` (`internal/tools/registry.go`); `DispatchShell` (`internal/dispatch/shell.go`), `RecognizeSimpleCompound` (`internal/permissions/compound.go`). [Details](../docs/architecture.md#tool-dispatch-is-exact-name-in-phase-1). |
| **Project root is marked by `.codemeld/settings.yaml`, not inferred from VCS** | Breaks a circular bootstrap dependency and makes non-VCS projects work without a special case. | `internal/config` discovery. [Details](../docs/architecture.md#project-root-marked-by-codemeldsettingsyaml-not-inferred-from-vcs). |
| **A repository contributes nothing codemeld acts on until its root is approved** | A cloned repository's settings would otherwise authorize themselves. | `gateTrust`, `headlessTrustGate` (`internal/bootstrap/trust.go`), `runFreshCore` (`internal/bootstrap/orchestrate.go`). [Details](../docs/approvals.md#project-approval-for-cloned-repositories). |
| **Cross-platform parity or an explicit per-OS gate** | A feature that works on one OS creates a different kind of lock-in. | The Per-OS Gates table in `docs/architecture.md`. [Details](../docs/architecture.md#per-os-gates). |
| **Durable files are written atomically** | Crash safety for sessions and settings. | `fsutil.WriteAtomic`, `internal/locks`. [Details](../docs/architecture.md#atomic-writes-and-file-locks). |
| **A process owns exactly its current active session, and a switch transfers that ownership target-before-source** | No other process may resume, prune, or append to a session this one is writing, and the session being left is never unowned. | `sessions.AcquireResumeLock`, `resumeLockHolder`, `preparedChildLifecycle.Activate` (`internal/bootstrap/childdeps.go`). [Details](../docs/architecture.md#a-process-owns-exactly-its-current-active-session). |
| **`/compact` runs off the event loop, and its durable success is never written before it is true** | On the loop it would freeze the screen, and success recorded early could claim a switch that never happened. | `App.RunBackgroundAfterDraw`, `StartTUI`, `tui.NewSubmitFunc`, `sessionfork.CreateOwnedChild`. [Details](../docs/architecture.md#a-process-owns-exactly-its-current-active-session). |
| **Modes drive permissions — they never replace them** | Plan / Build / Auto edits change the posture, not the authorization model. Read-only commands the classifier proves read-only auto-allow per mode; without confinement, Plan denies a command the classifier cannot prove read-only. The one model-judged route is the [System One check](../docs/system-one.md): off by default and on only through the global-only `system_one` setting or `/systemone`, it uses only a model from the validated list, each with its own thresholds. It covers shell commands only (`direct` and `literal`), never a tool, host, network-egress or external-read request, and runs only in Plan and Auto edits, never in Build. codemeld's structural checks run first. Exceptional actions (network access, file deletion, destructive version-control history operations) are not sent to the model; their prompt asks the user, because the model is never asked whether something may write, delete, use the network or run other code. Its only automatic outcome is one allowed read-only invocation, with no grant and no cache entry; any failure falls back to the ordinary prompt or deny with a note, and every check is recorded in the session file as `permission_system_one_check`. | `confinedShell`, `planPosture`, `autoEditsPosture`, `isInScopeFileTool`, `prePromptEligible`, `prePromptCheck` (`internal/permissions/orchestrate.go`), `internal/permissions/exceptional.go`, `internal/permissions/planshell.go`, `SystemOneEligible` (`internal/permissions/systemone_eligible.go`), `Models`, `Model.Allows` (`internal/systemone/client.go`), `systemOneCheck.check` (`internal/bootstrap/systemonecheck.go`), `EnforceGlobalOnly` (`internal/config/globalonly.go`), `dispatchDirect` (`internal/dispatch/shell.go`). [Details](../docs/approvals.md#modes). |
| **A non-interactive run is fail-closed (default-deny), never YOLO** | `codemeld run` has no interactive approver and is often fed untrusted input. The one exception is the opt-in [System One check](../docs/system-one.md) (off by default, on only through the global-only setting): in Plan and Auto edits, after codemeld's structural checks, a shell command it approves runs once as a read-only invocation, with no grant and no cache entry. Otherwise the deny stays, with any failure or pause note in its reason, and each check is recorded in the session file. | `internal/bootstrap/headless.go`, `systemOneCheck.check` (`internal/bootstrap/systemonecheck.go`), `internal/bootstrap/headlessprompt.go`, tty check in `internal/cli/run.go`. [Details](../docs/approvals.md#headless-runs-codemeld-run). |
| **Every turn carries a product-authored system prompt** | The model must know its tools, mode, and environment even with no `AGENTS.md`. | `internal/agentinstr`. [Details](../docs/approvals.md#what-the-model-is-told). |
| **Only codemeld's product-authored prompt carries instruction authority — a compaction summary is data** | A model-written summary sent as a system message would turn copied or induced text into commands. | `messagesFromRecords` (`internal/turn/request.go`), `toSDKMessages` (`internal/provider/client.go`), `responsesInstructionsAndInput` (`internal/provider/openai_chatgpt_client.go`), `BuildCompactionSummaryRequest`. [Details](../docs/approvals.md#what-the-model-is-told). |
| **Read-only tools read an explicitly named, unblocked path without a prompt; implicit escapes fail closed** | No read may leave the project through a path nobody named. | `internal/filetools/readresolve.go`, `PrepareTool` setting `ModeContext.OpenRead`/`ExternalRead` (`internal/dispatch/tool.go`), `resolveWithoutPrompt` (`internal/permissions/orchestrate.go`). [Details](../docs/approvals.md#reading-files). |
| **Tool calls overlap only within a contiguous run of project-confined structured reads; every other call is a serial barrier, and every overlapped read is recorded** | Unclassified concurrency could run a mutation beside a read, and unrecorded concurrency cannot be audited. | `productionToolDispatcher.Plan` (`internal/bootstrap/tooldispatch.go`), `internal/bootstrap/promptgate.go`. [Details](../docs/approvals.md#reading-files). |
| **Out-of-root file writes are reachable only by explicit per-write approval** | An out-of-root `edit`/`create` is sometimes legitimate but must never happen silently. | `isInScopeFileTool`, `internal/filetools/{resolve,edit,create,delete}.go`. [Details](../docs/approvals.md#writing-outside-the-project). |
| **`delete` is irreversible, so it is never auto-approved and never recursively wipes** | Its effect cannot be undone. | `isAutoEditsTool`, `AT_REMOVEDIR` in `internal/filetools/delete.go`. [Details](../docs/approvals.md#deleting-files). |
| **Auto edits auto-approves a `move` only when *both* canonical endpoints are in project** | A one-endpoint check would let Auto edits move a file into or out of the project unasked. | `dispatchPreparedMultiScope` (`internal/dispatch/tool.go`), `isInScopeFileTool`. [Details](../docs/approvals.md#modes). |
| **A declared write scope is a ceiling, not another route to yes** | A caller naming the files a job may touch is stating a maximum. | `--files-authorized`, `--files-authorized-delete`, `declaredScopePosture` (`internal/permissions/orchestrate.go`). [Details](../docs/approvals.md#headless-runs-codemeld-run). |
| **codemeld's own settings files are never mutated by a model-facing structured file tool** | A front door that can authorize rewriting its own policy is not a front door. | `protectedStatePolicy` (`internal/bootstrap/trust.go`), `guardedTools` (`internal/securitystate/protect.go`), `PrepareTool`, `protectRules` (`internal/vcs/tool.go`), `internal/bootstrap/confinedrunner.go`, `internal/enforce/landlock_linux.go`. [Details](../docs/architecture.md#protected-settings-state-under-confinement). |
| **A VCS action advertises read-only only from a trusted source; a repository-controlled template fails closed** | A repository must not widen its own trust boundary. | `actionReadOnly` (`internal/vcs/tool.go`), `internal/bootstrap/vcs_bootstrap.go`. [Details](../docs/approvals.md#shell-commands). |
| **Raw hg/git shell is read-only only for a curated subcommand set with no dangerous flag** | `hg` and `git` can also rewrite history, so only audited inspection forms auto-allow. | `commandPolicies`, `subcommandDenyFlags`, `commandPolicy.stageSubcommand` (`internal/permissions/planshell.go`). [Details](../docs/approvals.md#shell-commands). |
| **An automatically allowed Mercurial process runs in a codemeld-owned environment; a prompt-approved one does not** | hg config can run programs the argv never named, while a person's approval keeps their own config. | `Decision.ReadOnlyAuto` (`internal/permissions/orchestrate.go`), `authorizeStages`, `planStages` (`internal/dispatch/shell.go`). [Details](../docs/approvals.md#shell-commands). |
| **A program admitted by name alone has no write, program-execution, or scope-retarget flag — and argv is not its only input** | A name-only entry auto-allows every invocation, so it is a claim about the whole flag surface. | `commandPolicies`, `stageMatchesDenyFlag` (`internal/permissions/planshell.go`), `RIPGREP_CONFIG_PATH` removal in `internal/dispatch/shell.go`. [Details](../docs/approvals.md#shell-commands). |
| **A bare `&&`-compound of all-read-only shell stages is itself read-only** | A compound kept whole would otherwise always prompt even when every stage is a safe read. | `classifyLiteralCompound`, `stageTokensReadOnly`, `stripNullRedirects` (`internal/permissions/planshell.go`), `stripNullRedirectsForGrant` (`internal/permissions/compound.go`). [Details](../docs/approvals.md#shell-commands). |
| **Raw `find` shell is read-only only for a narrow argument-parsed listing subset** | `find` can mutate, and its safety depends on argument position. | `findStageReadOnly` (`internal/permissions/planshell.go`). [Details](../docs/approvals.md#shell-commands). |
| **A web tool call is never auto-allowed by a mode — an approval or a grant made at the prompt is the only route to the network** | Any automatic allow or deny around the call would void the authorization boundary. | `ModeContext.NetworkEgress` set by `PrepareTool` (`internal/dispatch/tool.go`), `modePosture` (`internal/permissions/orchestrate.go`). [Details](../docs/approvals.md#web-access). |
| **An approved `web_search` reaches exactly one host — `mcp.exa.ai` — and a result host is reached only by an explicit `web_fetch`** | Approving a search is not a decision about which pages get read. | `dispatchWebSearch`, `encodeSearchCandidates` (`internal/bootstrap/tooldispatch_web.go`). [Details](../docs/approvals.md#web-access). |
| **`bash`/`sh` are read-only only for four exact no-exec syntax-check spellings on the direct route** | They run arbitrary code, and one unrecognized option restores execution. | `noExecShellTokens` (`internal/permissions/planshell.go`), `noExecShellStage`, `scriptInvocationStage` (`internal/permissions/normalize_direct.go`). [Details](../docs/approvals.md#shell-commands). |
| **`command -v <name>` is read-only only as a resolved bare lookup, answered in Go** | `command` can launch any program, and as a builtin it has no executable to run. | `commandLookupStage` (`internal/permissions/normalize_direct.go`), `builtinLookupResult` (`internal/dispatch/shell.go`). [Details](../docs/approvals.md#shell-commands). |
| **`top` is read-only only as a Linux bounded batch run; `col` is a name-only filter** | Unbounded `top` seizes the terminal; `col` only reformats. | `topStageReadOnly` (`internal/permissions/planshell.go`), `modeDenyReason` (`internal/permissions/orchestrate.go`). [Details](../docs/approvals.md#shell-commands). |
| **Raw `awk` shell is read-only only for a program that cannot write, run commands, or reach past its operands** | AWK is a programming language. | `awkStageReadOnly` (`internal/permissions/planshell.go`), `awkReadOnlyProgram` (`internal/permissions/awkprogram.go`). [Details](../docs/approvals.md#shell-commands). |
| **Direct `ps` is read-only for any argument list, on Linux and FreeBSD alike** | No documented `ps` option writes, executes, opens the network, or escapes scope. | `psStageReadOnly` (`internal/permissions/planshell.go`), which refuses a token containing `$(` or a backtick. [Details](../docs/approvals.md#shell-commands). |

## Config & data format invariants

- **YAML for humans, per-session JSONL for machines.** `settings.yaml` and `vcs/*.yaml` are
  human-authored and comment-annotated at generation time; `sessions/*.json` is one
  machine-written, schema-versioned JSON-lines stream per session. The first line is tagged
  metadata (**not** a `Record`); later lines are each one record of the closed set —
  `message`, `event`, or `compaction` (a linked child's record-zero summary). Whole-file
  metadata rewrites stay atomic, and normal turn flushes append only new record lines with fsync.
  The `compaction` discriminator was added under `schema_version:1` without a bump because it is
  predeployment: existing message/event v1 files stay readable, but older builds reject a
  compacted child because they do not know the new type — this is a deliberate same-version
  incompatibility, not backward-compatible unknown-record handling.
- **Credentials are global-only plaintext local state in phase 1.** Provider API keys, and the
  ChatGPT session state under `auth.openai-chatgpt`, belong in
  `~/.codemeld/global/settings.yaml` at mode `0600`; project-local settings must not provide,
  shadow, or redirect credentials. The broader-than-`0600` warning names both kinds of credential.
- **Permissions are auditable by hand.** Grants are plain YAML entries with explicit `subject`,
  `path_scope`, and `grant_kind`. See the [permissions module](learning/module-05-permissions.md).
- **A key written through the `/settings` settings tab is global-only.** `attribution` — whether
  outbound OpenRouter requests name codemeld — and the three OpenRouter routing rows (data
  collection, sort, and max price, stored under `provider.openrouter.routing`) each live only in
  `~/.codemeld/global/settings.yaml`; a project file carrying one fails to load with the standard
  global-only error. One owning file is what lets the settings tab guarantee the value it shows is
  the value in effect, and lets each row write back to the file it read from. This does not extend
  to every UI writer: the model picker, for one, writes the project-scoped `model.active`. A
  settings-tab write publishes to the running session **only after** its durable write is
  confirmed, so a failed write leaves disk, session, and screen agreed.
- **A stored capability never gains members under an existing grant.** `capabilityMembers`
  (`internal/permissions/capability.go`) is the source of truth: legacy `write` stays exactly
  `{create, edit}`, its successor `write_tree` is `{create, edit, mkdir}`, and `read*` is the six
  read/search tools. A `write` grant already in someone's `settings.yaml` therefore keeps
  authorizing only `create`/`edit` — it never silently starts covering `mkdir`, and nothing
  rewrites it on load. New grants are the only place `write_tree` appears: `CapabilityForMember`
  checks `write_tree` first, so a fresh create/edit/mkdir approval stores `write_tree`. **Neither
  capability contains `move` or `delete`** — both keep their concrete subject, so one write
  approval never authorizes a relocation or a removal.
- **Ignore filtering is codemeld-owned, not native VCS.** The read/search/list tools honor a
  codemeld-owned `codemeldignore` file (`.codemeld/codemeldignore` + the global one), **not**
  native `.gitignore`/`.hgignore` parsing — carrying two divergent external ignore dialects was
  deliberately rejected. See `internal/filetools/codemeldignore.go`.

## TUI invariants

- **An overlay with a roster dismissal owns ESC, ahead of stream interruption.** One ESC does one
  thing: it closes the surface the user is looking at, and never also cancels the turn behind it —
  that turn is usually what the user opened the overlay to steer. `HandleEsc`
  (`internal/tui/key_esc.go`) dismisses the first open overlay before `interruptStream`; a second
  ESC interrupts. `/status` closed over a running turn is the one variation: its dismissal
  (`internal/tui/overlays.go`) sets `escDisarmed`, so the next consecutive ESC only shows
  `press ESC again to interrupt` and the one after it interrupts; any other key clears the guard,
  and closing `/status` with no turn running does not set it. The `/resume` picker is the
  deliberate exception: it dismisses itself with the continuation result it owes its caller, so it
  carries a `nil` dismissal and registers for the open-state guard only, and `handleGlobalKey`
  (`internal/tui/key_global.go`) keeps its stream-first route — ESC there interrupts a running turn
  first and otherwise falls through to the resume list.
- **Every overlay registers in one roster.** `overlays()` (`internal/tui/overlays.go`) is the single
  ordered list of overlay open flags, predicates, and dismissals; `HandleEsc` and `anyOverlayOpen`
  both derive from it. A new overlay adds an entry there — not a boolean plus a switch case, which is
  how the ESC list drifted apart from the open-state list in the first place. A missing entry fails
  `TestOverlays_RosterCoversEveryOpenFlag`, which walks the `App` struct's `…Open` fields.

## Note: extending the egress policy

The "no outbound network except configured providers" promise is a **default**, not a wall that
later work may quietly knock down. The OpenAI ChatGPT auth path is the first
capability to add a second sanctioned destination, origin-scoped to OpenAI and off when the
provider is unused; web research is the second — and it reaches exactly the hosts a human approved
at a prompt, or that a matching grant for that exact host and tool covers, in every mode:
`mcp.exa.ai` for a search, which never fetches the candidates it returns, and each page the model
explicitly asked to fetch, plus each redirect hop, authorized on its own host. A redirect changing
scheme or port requires a fresh one-time confirmation even when the hostname has a project grant;
scheme and port are never added to a persistent grant. Each must keep the promise intact by
construction. Shell subprocesses are outside this promise: an unconfined command has the account's
ordinary network access, and a confined one cannot create sockets unless an Auto edits network
approval adds internet sockets for that one command.
The bar for any new egress is the same: **explicit, origin-scoped, and inert until a human
approves it**. What may never loosen is the authorization gate, not the tool list: web research
ships advertised (`web_research.enabled` defaults to true) precisely because advertising is not
authorization — no host is reachable until the user answers the permission prompt or a grant made
at one covers it (an Exa key authorizes nothing either), and
`enabled: false` remains the switch for an install that must never egress. A disabled feature makes
no connection at all, and neither does an enabled one nobody has approved. Anything that opens a
connection outside its approved origin and trigger rules is a bug.

Web research carries a second boundary that no approval unlocks: **an approved host authorizes
public web access only**. `web_fetch` refuses loopback, unspecified, link-local, private and
unique-local, carrier-grade NAT, benchmarking, reserved and cloud-metadata destinations
([`internal/webresearch/address.go`](../internal/webresearch/address.go)) — the classes are the
contract, not a list of ranges copied into prose. A literal address in one of those classes is
refused before the permission prompt can offer it; every other case is checked at dial time, on the
address the dialer attempts. That is deliberately narrower than "every DNS result": an address the
dialer never tries is also an address nothing connects to. Dial time is where the check belongs
because the name that was approved and the address that is connected are resolved at different
moments, so a check on the hostname alone leaves a later lookup, a redirect hop, or a rebinding
answer unaccounted for. The consequence is that the `web_fetch` transport is **direct-only** — it
carries no proxy, because a proxy would resolve and reach the blocked destination on codemeld's
behalf. Restoring proxy support to it breaks this invariant.

When in doubt, read [`docs/architecture.md`](../docs/architecture.md) → "Cross-cutting design
decisions" and "Privacy & Telemetry", and [`docs/approvals.md`](../docs/approvals.md); this
page is the checklist, those short pages describe the behavior a change must keep.
