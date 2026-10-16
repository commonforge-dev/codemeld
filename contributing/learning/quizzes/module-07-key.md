# Answer key — Module 7: Sessions & events

_Last updated: 2026-10-06_

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** The first write and explicit metadata changes marshal the JSONL stream and call
`fsutil.WriteAtomic` (`fsutil/atomic.go`): sibling `<base>.tmp-<hex>` write → fsync temp → rename onto
`<id>.json` → fsync parent directory. Normal turn flushes append only new record lines, fsync the file,
and advance the durable-record boundary only after success, so a failed append is retried without
duplicating already-durable lines. *Proof:* `Store.Flush`, `rewriteLocked`, `appendFileSync`
(`sessions/store.go`); `TestStore_AppendThenFlush_WritesParseableFile`,
`TestStore_FlushAppendsOnlyNewLines` in `store_test.go`.

**2.** `~/.codemeld/sessions/<folder-dir>/<id>.json`, where `<folder-dir>` = `FolderDirName` =
`<first-16-bytes-of-SHA256-hex>-<sanitized-basename>`. *Proof:* `SessionRoot`, `FolderDirName`
(`sessions/folderdir.go`); `TestEnsureSession_FreshShape` in `ensuresession_test.go`.

**3.** No — it returns a `*Store` over the path but never flushes; the first durable write is the
caller's (the launch sequence's `launch_began` flush). *Proof:* `EnsureSession` (`ensuresession.go`);
`TestEnsureSession_AppendFlushSmoke` asserts `fs.ErrNotExist` before the caller flushes.

**4.** **Every** active session — not just resumed ones: fresh interactive, fresh headless,
resumed, `/clear` targets, and the linked children `/fork` and `/compact` create. Each takes an
exclusive advisory lock on its own **sidecar** `<id>.json.lock` (never the session file, because
atomic rename swaps the session file's inode) before its first durable append, and holds it while
that session is active, with a **2-second** acquisition timeout (`resumeLockTimeout`). The
`ResumeLock` names are historical and were deliberately left unrenamed. *Proof:* `AcquireResumeLock`,
`ResumeLockPath` (`sessions/resume_lock.go`); the fresh path's `AcquireLock` step and
`ResumeLockRelease` handoff (`bootstrap/orchestrate.go`); `CreateOwnedChild`
(`sessionfork/fork.go`); `TestAcquireResumeLock_CleanAcquireAndRelease`,
`TestAcquireResumeLock_ContendedTimeoutClassifiesAndUnwraps`.

**5.** The exclusive sidecar flock: a second process targeting that session contends and fails after
2 s with `*ResumeLockError{ReasonLockTimeout}` ("session <id> in use by another codemeld instance");
the kernel releases the lock on process exit. Because ownership is no longer resume-only, this also
covers a fresh or child session another process tries to resume or prune. *Proof:*
`AcquireResumeLock`; `TestAcquireResumeLock_AutoReleaseOnProcessExit`.

**6.** The run does **not** abort: the full in-memory record stream is **retained**, a
`session_write_failed` event is appended (carried to the next flush), a one-line notice is rendered,
and there is **no** synchronous retry. *Proof:* `HandleWriteFailure` (`sessionfailures/failures.go`);
`TestHandleWriteFailure_RetainsRecords_EmitsEvent_NoSyncRetry`.

**7.** `CleanShutdownFlush` retries the flush exactly once; on the second failure it prints the
`OP_FAIL` `session-write-on-exit` stderr line and returns an error mapped to exit 1 — and emits **no**
`session_write_failed` event (there's no later flush to carry it). *Proof:* `CleanShutdownFlush`
(`failures.go`); `TestCleanShutdownFlush_SecondFailure_OpFail_Exit1_NoEvent`.

**8.** Only `user`/`assistant`/`system` **messages** (text content), into a fresh-UUIDv7, current-schema
session; it **drops** tool messages, all event records, and strips `tool_calls`/`tool_call_id`. *Proof:*
`filterTextRecords` (`sessionfork/fork.go`); `TestFilterTextRecords`.

**9.** `OpenSession` pre-scans `schema_version` from the JSONL metadata line and **refuses** with a `*VersionError`
(`StatusNewer`) **without parsing records** (a future schema may carry fields the current parser can't
read). *Proof:* `OpenSession`/`ClassifyVersion` (`sessions/version.go`);
`TestOpenSession_NewerRefusedBeforeUnmarshal`.

**10.** Pruning runs **only on a fresh launch** — a background goroutine; no resume path (`--resume <id>`,
no-id `--resume`, or in-TUI `/resume`) prunes. Within a pass it deletes `<id>.json` whose
`updated_at` is **strictly before** `now − retention` (exactly-at-cutoff is **retained**). Before unlinking
it takes a **non-blocking** try on the sidecar lock, so any session another process currently owns
(lock held — resumed, fresh, or a live child) is **skipped**, never pruned. *Proof:* `Prune`/`tryDeleteExpired` (`sessions/prune.go`), `startBackgroundPrune` gated on
`BackgroundPrune` (`bootstrap/starttui.go`); `TestPrune_RetentionBoundaryExactCutoffRetained`,
`TestPrune_LockContendedSkips`, `TestRunResume_BackgroundPruneMarker`.

**11.** **Read-only** means it never writes, locks, prunes, forks, or refreshes `updated_at` — it only
loads and inspects. `doctor` exits **0 even when findings exist** (it ends with a per-severity count and
treats findings as normal output); it exits non-zero **only** on a load/validation failure. *Proof:*
`runSessionsDoctor` (`internal/cli/sessions.go`); `TestSessionsDoctor_Path_ReportsAllFindings` asserts
exit 0 with findings present, `TestSessionsDoctor_LoadErrors` asserts non-zero on a load failure.

**12.** Severity is **derived**, not stored — `classifyFinding` is the whole convention:
- **error** — the `*_failed` events (`session_write_failed`, `permission_persist_failed`,
  `model_recovery_failed`, `model_persist_failed`, `model_global_mirror_failed`),
  `provider_request_failed`, and a `tool_exec_end` with a **non-zero** `exit_code`.
- **warning** — `model_effort_unsupported`, a `model_response` carrying `anomaly` tokens, and a
  `slash_command` with `outcome == "error"`.
- **info** — `stream_interrupted`.

Not a finding: every other kind, plus a **zero-exit** `tool_exec_end` and an **anomaly-free**
`model_response`. *Proof:* `classifyFinding` (`internal/cli/sessions.go`);
`TestSessionsDoctor_Path_ReportsAllFindings`/`_JSON` pin the `error:7 warning:3 info:1` summary.

**13.** Both accept **either** an id **or** an explicit file path — a value that is a valid session id
is treated as an id, anything else as a path. An **id** goes through the same `ResolveResumeID` path
`--resume` uses, but a **folder mismatch is not a refusal here**: `resolveSession` catches the
wrong-folder / CWD-mismatch error, takes the session file that resolution located, and reads it. So a
bare id works from **any** directory, and the report names the folder the session was recorded in.
`--resume <id>` still refuses a session from another folder, because resuming would run the session's
next tool call against the wrong tree, while these commands take no lock and append nothing. A
**path** goes straight through `OpenSession` + `ValidateRecordStream` — the **standard loader**, never
a format-specific reader — so a newer `schema_version`, a not-found file, or a parse failure surfaces
as the existing typed load error. *Proof:* `resolveSession`, `mismatchedFolderPath`
(`internal/cli/sessions.go`); `TestSessionsDoctor_ResolvesByID`,
`TestSessions_ResolveIDRecordedInAnotherFolder`, `TestSessions_JSONReportsNameTheRecordedFolder`,
`TestSessionsDoctor_LoadErrors`.

**14.** Adding an event kind is **additive / non-breaking**: an older session simply lacks the new records,
so it still loads unchanged — only `events.ValidatePayload`'s closed dispatch must learn the new kinds
(`unmarshalPayload`), which is a forward, version-*equal* concern, not a schema change. So `turn_latency`,
`provider_round_trip`, and `turn_terminal` ride along at `schema_version` 1. New provider-round and
terminal records share UUIDv7 `turn_id` / `round_id` values; legacy round records omit both IDs. A terminal
record carries only its closed lifecycle outcome, an applicable provider failure phase, and whether dispatch
started, rejecting response, tool-argument, and secret fields while accepting future optional fields.
`doctor` currently treats
these events as **non-findings** (`classifyFinding`'s `default` returns `isFinding=false`), so it neither
flags nor chokes on them; `show` renders them like any event, so the per-turn / per-round evidence surfaces.
*Proof:* `TurnLatency`, `ProviderRoundTrip`, `TurnTerminal`, `unmarshalPayload` (`internal/events/payloads.go`);
`TestSessions_ToleratesAndSurfacesLatencyEvents` (`internal/cli/sessions_test.go`).

**15.** `internal/events/payloads.go` is authoritative: the `Kind…` constants are the full kind set and
each payload struct's JSON tags + validator are that kind's fields; `ValidatePayload` maps a kind to its
struct. Confirm against a live session with the shipped reader —
`codemeld sessions show <session-id|path>` prints the message, event, and compaction records in
order, so you can see which kinds a real run emits and what one record of a kind actually carries.
(Every line of the file is also ordinary JSON, so any JSON reader works if you prefer the raw
records.) Never copy a static field table;
[`docs/sessions.md`](../../../docs/sessions.md) records this discovery workflow and why.

**16.** `show` renders the compaction as a numbered record (numbering of the following records is
preserved) with its timestamp, the full multiline summary, and two **separately labeled** lines:
`generated by: provider=… model=…` — generation metadata only, saying which model wrote the summary —
and `source record: parent_id=…`, which together with the header's
`forked_from: session=… record=…` (printed when `metadata.forked_from` is present) is the **source
link** an operator compares against record zero. Provider/model is never the source identity.
`doctor` treats a valid compaction as **durable context, not a finding** — `buildDoctorReport` walks
only `Event` records, so the session reports clean and exits 0; no compaction severity exists. A
malformed one (compaction not at record zero, missing `forked_from`, or a `parent_id` mismatching
`forked_from.record_id`) is rejected by `validateProvenance` in the **standard load path**, so both
subcommands exit 1 with the typed loader error and empty stdout. An **older reader** (a build
predating the record type) fails parsing with `unknown record type "compaction"` — a load error, not
silent omission — because `parseRecord`'s type switch is closed. Showing summary and generation
metadata to a human CLI is intentional; the *model-input* boundary (what a resumed conversation
feeds back to the provider) is a separate exclusion and is not affected by diagnostics. *Proof:*
`renderShow`/`renderCompaction`, `buildDoctorReport` (`internal/cli/sessions.go`);
`validateProvenance`, `parseRecord` (`internal/sessions/schema.go`);
`TestSessionsShow_CompactedChild`, `TestSessionsDoctor_CompactedChild_NotAFinding`,
`TestSessions_MalformedCompactionProvenanceRejected` (`internal/cli/sessions_test.go`).

**17.** Only the **initial child write** (the `launch_began{source: fork}` flush) reports the path:
`CreateChild` wraps `events.EmitLaunchBegan`'s handler and invokes its own callback **exactly once**
with the exact child file path plus the unchanged category/reason/error. The path is needed exactly
there because a failed create leaves **no target on disk** and every `CreateChild` error returns a
**nil child** — with no file, no store, and no later flush, the callback is the only place the
failed child's identity exists. The **parent-marker** flush failure never invokes the path-aware
callback: by then the child is published, complete, and resumable, so there is no unpublished path
to report (the parent's own failure follows the parent's write-failure handling). `ForkSession`
keeps its legacy **three-value** callback (category, reason, error — no path), adapting internally
by discarding the path. *Proof:* `CreateChild`, `ForkSession` (`sessionfork/fork.go`);
`TestCreateChild_ChildFlushParentDirSyncFailureLeavesNoChildFile` pins the exact
path/category/reason/error tuple, `TestCreateChild_ParentMarkerFlushFailure` pins zero path-aware
calls, `TestForkSession_FlushFailure` pins the unchanged legacy tuple (`sessionfork/fork_test.go`).

**18.** The **source** (parent) lock and the **target** (child) lock, transferred **target before
source**. `Prepare` validates the parent (non-nil **and** pointer-equal to the app's
active store) → `CreateOwnedChild` writes the child file and acquires the child's sidecar → the
parent's terminal batch is committed and the parent sealed. Then `Activate`, which cannot fail:
**install the exact prepared child as the active store** → hand the child's release token to the
run-scoped `resumeLockHolder` and release the parent's → reset the transcript → append the current
launch banner → replay the child's records through the visible-only projection. So the process
briefly holds two session locks, which is required: releasing the source first would leave the
session being left **unowned** for an interval another process could resume, prune, or append to.
Steady state is still exactly one held lock. Nothing fallible may run after the parent is sealed —
returning an error there would falsely imply the sealed parent is still usable — which is why every
step after the install is non-erroring. A `Prepare` failure (including failing to acquire the child's
lock) releases any tentative child ownership and leaves the parent active and owned. **Two commands
drive it today:** the shipped phase-2 `/fork`, synchronously via `CreateAndActivate`, and the shipped
phase-2 `/compact`, which calls `Prepare` on a background goroutine and `Activate` back on the event
loop. *Proof:* `preparedChildLifecycle` (`bootstrap/childdeps.go`), `CreateOwnedChild`
(`sessionfork/fork.go`); `TestChildLifecycle_SuccessActivatesExactChildAndSealsParent` pins the
exact-child install, the sealed parent, and the active-child-during-release ordering;
`TestChildLifecycle_SuccessResetsTranscriptAndReplaysVisible` pins reset → banner → ordered
visible replay with events/system/compaction hidden (`bootstrap/childdeps_test.go`);
`TestStartTUI_ForkThroughInstalledSubmitSwitchesToDurableChild` and
`TestStartTUI_CompactThroughInstalledSubmitCreatesOwnedSummaryChild` pin the two shipped commands
driving it end-to-end through the installed submit hook (`bootstrap/starttui_test.go`) — the compact
test asserts the active store is already the child at the moment the parent's ownership is released.

**19.** On **every** creation failure the parent stays the active store, its ownership is
**not** released, and the transcript is untouched (nil and stale parents are rejected before any
durable work, too). The **initial-write** failure surfaces the path-aware callback's exact
path/category/reason/error as the returned operation error — it does **not** go through
`sessionfailures.HandleWriteFailure`, because that protocol retains records on a live store for a
later flush to carry `session_write_failed`, and an unpublished child has no store, no listing,
and no later flush. The **parent-marker** failure can leave a complete, resumable child file on
disk; the lifecycle never scans for or activates that survivor — the parent stays open and
active, and the child is only ever entered by a later explicit resume. *Proof:*
`TestChildLifecycle_InitialWriteFailureRetainsParent` pins the exact facts in the error and the
retained parent/lock/transcript; `TestChildLifecycle_PrepareFailureRetainsParentAndUnlocksOrphan`
pins the surviving-but-ignored child (`bootstrap/childdeps_test.go`).

**20.** A successful `/fork` first appends its `slash_command` **success** record to the parent and
flushes it, so the parent's durable stream ends with that success record **followed by** the
`session_forked` marker (whose `to_session_id` names the child) — success-before-marker, and the
parent is then sealed **in this process only** (further appends are dropped) while its file stays
loadable and resumable. The child file carries `metadata.forked_from {session_id, record_id}` naming
the parent and the fork-point record, and its **first record repeats that record id as `parent_id`**;
it copies the parent's **full continuation** — message and compaction records — and **drops events**
(`forkContinuationRecords`), then gets its own `launch_began{source: fork}`. Afterward the running app
points at the **child** as the active store, with the re-rendered banner and the replayed child
history visible and the old resume lock released. `StartTUI` binds the parent flush to the store's own
`Store.Flush` (not the handled `newCommandFlush`) precisely because a handled flush swallows an
atomic-write failure and returns `nil`; the fork must instead **halt before creating the child** when
the parent's success record is not durable, so the direct flush reports the failure but still returns
the original error. This differs from **`ForkSession`**, the legacy **text-only** migration fork
that copies only text messages and does not activate a live child. *Proof:*
`TestStartTUI_ForkThroughInstalledSubmitSwitchesToDurableChild` reads the parent and child back from
disk for the exact order/provenance/continuation and inspects the running app's active child, banner,
history, and released lock (`bootstrap/starttui_test.go`); `TestBuildRegistry_ForkReplacementDispatches`
and `TestCompleteSlashName_IncludesFork` pin the shipped registration and Tab completion
(`tui/registry_test.go`).

**21.** Three stages, two goroutines. **Admission** runs on the event loop inside command
dispatch: `TurnActive` gate, then `ActiveState.Current` is read **exactly once** — that single
snapshot fixes the provider, the model, *and* the fixed non-streaming summary request built from the
captured parent's records, and the client is resolved from that same provider's catalog auth kind, so
there is no second read and no fallback to another provider. Then the exclusive submission gate is
taken. **Provider call plus `Prepare`** run on a background goroutine handed to
`App.RunBackgroundAfterDraw`, which paints once first so the UI is not frozen behind provider
latency. **Activation** marshals back onto the event loop for `Activate`, the transcript rebuild, and
one gate release — exactly once, on every terminal path. While the gate is held, a prompt or a
`/clear` is rejected and its typed text **retained**; nothing is dispatched. Gating only
`newPromptEntrypoint` does not work because `tui.NewSubmitFunc` dispatches slash commands *before* it
reaches the prompt path, so `/clear`, `/resume`, `/fork`, `/exit`, or a second `/compact` would still
mutate, replace, or close the captured parent — the gate therefore wraps the whole submit adapter in
`StartTUI`. *Proof:* `NewCompactHandler`/`CompactDeps` (`tui/cmd_compact.go`), `newCompactDeps` and
the `compactLease` submit wrapper (`bootstrap/starttui.go`), `App.RunBackgroundAfterDraw`
(`tui/app.go`); `TestStartTUI_CompactThroughInstalledSubmitCreatesOwnedSummaryChild` pins the
paint-before-work ordering, the retained overlapping submissions, and the single-provider identity
(`bootstrap/starttui_test.go`).

**22.** The success record is **not** written on acceptance — acceptance is not a truthful terminal
outcome, because persistence or child finalization can still fail. It travels as a *terminal record*
into `CreateOwnedChild`, which commits it atomically **together with** the `session_forked` marker in
one `CommitFinalRecords` batch, so the parent's durable stream ends with `slash_command{compact,
success}` **immediately followed by** `session_forked`. A durable success therefore implies the child
and the marker are both durable and only non-failing live activation remains. A failed compaction
appends `slash_command{compact,error}` with an `error_detail` to the **still-open** parent, strictly
flushes it, records **no** success and **no** `session_forked`, and switches no session; the parent
stays active and appendable. If the failure came after the child was already published, that complete
child stays on disk as an unlocked, resumable orphan — the UI says so rather than claiming a
rollback. *Proof:* `failCompactAfterAcceptance` (`tui/cmd_compact.go`), `CreateOwnedChild`
(`sessionfork/fork.go`); `TestStartTUI_CompactThroughInstalledSubmitCreatesOwnedSummaryChild` reads
the parent back from disk and asserts the last two records in that exact order;
`TestStartTUI_CompactSelectedProviderFailureLeavesParentActive` pins the error record, the absent
marker, and the still-appendable parent (`bootstrap/starttui_test.go`).

**23.** A `/compact` child is **summary-only**: `Records[0]` is the compaction record (its `summary`
plus `provider`/`model_id` audit metadata) and the rest is its own `launch_began` — none of the
parent's messages. A `/fork` child is a **full continuation**: every message and compaction record,
events dropped. Titles: `<parent> (compacted)` versus `<parent> (forked)`. The `forked_from.record_id`
differs because of *when* each command's success record is written. `/fork` appends and flushes its
success record **first**, so that record is the parent's last record when the child is created and
therefore the fork point. `/compact` cannot: its success is only true after the child exists, so it is
written **afterwards** as part of the parent's terminal batch — leaving the parent's last
*conversation* record as the fork point. *Proof:* `deriveCompactTitle` (`tui/cmd_compact.go`),
`lastRecordID`/`CreateOwnedChild` (`sessionfork/fork.go`);
`TestStartTUI_CompactThroughInstalledSubmitCreatesOwnedSummaryChild` (summary-only child, compacted
title, fork point = last conversation record) and
`TestStartTUI_ForkThroughInstalledSubmitSwitchesToDurableChild` (full continuation, forked title,
fork point = the success record) (`bootstrap/starttui_test.go`).

**24.** **What was stored.** A granted decision that carries **no** `grant_kind` is an **allow-once**
approval — that one call was authorized and nothing was written — and the row says
`grant=allow_once`. Otherwise the row names the stored grant kind (`session` / `folder` / `global`
for a path subject, `session` / `project` for a host subject), the folder or host it was stored at,
and the **stored subject**, which may be wider than the requested one. A **global** grant is named by
its kind alone: its recorded scope is the all-paths sentinel `*`, not a folder, and is never rendered
as a path. A **host** row carries its host scope and never a path field.
**Scope escalation.** A prompt is flagged when its own request scope **strictly contains** a folder
an earlier decision in the same session already granted *and* that grant's `grant_subject` covers
this request; the **narrowest** (deepest) qualifying earlier grant is named. Containment reuses
`IsDescendantOrEqual`, and the subject question goes to `permissions.AuditSubjectMatches`, which
packs the recorded values into a `MatchRequest`/`PermissionEntry` pair and delegates to the live
`subjectMatches` — so a stored `:*` wildcard or a capability grant behaves exactly as it does at
authorization time and the audit cannot drift. Global grants are skipped (`*` is not a narrower
folder) and host prompts, being scoped by host, never escalate.
**Unknown data.** An absent `permission_decision.grant_subject` (a grant written before the field
existed) and an absent `permission_prompt_shown.direct_tokens` on a direct prompt both mean
*unknown*, and either one leaves the row unflagged. The flattened `subject` is never re-split to
stand in for the tokens: that would turn one quoted argument into two and could manufacture an
escalation that never happened — and the marker asserts something about a human's security decision,
so a false claim is worse than a missing one.
**It changes nothing.** The report is read-only and historical; the marker never affects what is
allowed at runtime. *Proof:* `AuditSubjectMatches` (`internal/permissions/matcher.go`),
`classifyGrant`/`findEscalation`/`buildPermissionsReport` (`internal/cli/sessions.go`);
`TestAuditSubjectMatches` pins the helper against the live matcher's answer for the same values
(`internal/permissions/matcher_test.go`);
`TestSessionsPermissions_ClassifiesGrantsAndEscalations`,
`TestSessionsPermissions_NarrowestEscalationWins`, and `TestSessionsPermissions_NoEscalationMarked`
pin the classifications, the narrowest-wins choice, and every pair that must stay unflagged, with
`TestSessionsPermissions_JSONMatchesGolden` pinning the `--json` document against
`internal/cli/testdata/sessions-permissions.json` (`internal/cli/sessions_test.go`).

**24a.** **The event and its sole writer.** `permission_revoke_requested`. Its `source` is a closed
vocabulary whose one value is `permissions_ui`, and the only producer is the `/settings` revoke
seam, so a hand edit, another tool, or another process leaves no such record — which is exactly what
lets a reader tell a deliberate revoke from a grant that merely vanished from the YAML.
**Whose identity.** The **removed grant's** own stored identity: `permissions.PermissionEntry`'s
`DedupKey` (`kind`, `subject`, `path_scope` or `host_scope`, `grant_kind`) plus a literal grant's
`argument_hash` — never the request subject that once produced the grant. The stored subject is
copied verbatim because correlating the record to that exact stored grant *is* the event's purpose;
hashing or truncating it would destroy that. It equals `permission_decision.grant_subject` only when
that field is present, and a legacy decision missing it leaves only the link back to *that decision*
unknown. `permission_matched` carries the concrete request subject, so it cannot identify a widened
direct grant such as `git :*` and is not a correlation source for one.
**What it does not prove.**
(1) *A persisted revocation is an observed request.* `targetHasGrant` reads the writable settings
file unlocked, and only then does `permissionpersist.DeleteGrant` take its sidecar lock and treat a
missing key as a clean no-op — so if another actor removed the entry in that window the record still
only claims that /settings saw the grant and asked for an idempotent delete that succeeded.
(2) *Not every successful revoke has an event.* Settings and session are separate files with no
cross-file transaction (the session log is fsynced per append, with no two-phase commit), so once the delete
succeeds the live grant is dropped **before** the append. That order is chosen to avoid the worse
failure — a revoked grant that keeps authorizing — and its accepted cost is a crash in that window
leaving a real revoke unrecorded.
(3) *Recorded is not durable.* After the append the command flush hook runs; it owns the
`session_write_failed` notice/retry protocol and returns nil once it has handled such a failure, so
the revoke adds no second notice and no second event and the one appended record waits for the next
flush boundary. Only an append rejection or a flush error that protocol does not own raises the
revoke's own "revoke not recorded" notice, which deliberately does not read as a failed revoke.
**Zero, and never inferred.** A session with no such records prints `explicit revocation requests: 0`
and an empty `revocation_requests` list — the count prints even at zero. A grant that is simply
absent from a settings file produces no row: the report reads revocations only from the records, and
a session written before the event existed reports zero rather than being back-filled. *Proof:*
`EmitPermissionRevokeRequested`, `PermissionRevokeRequested`
and its validator (`internal/events/payloads.go`), `RevokeGrant`/`recordRevokeRequest`
(`internal/bootstrap/authdeps.go`), `buildPermissionsReport`/`renderPermissions`
(`internal/cli/sessions.go`);
`TestEmitPermissionRevokeRequested_RoundTripsEachIdentityForm` and
`TestPermissionRevokeRequested_RejectionsAppendNothing` (`internal/events/securitystate_test.go`),
`TestProductionAuthorizer_RevokeStaleSessionGrantRecordsNothing`,
`TestProductionAuthorizer_RevokeRecordingFailureKeepsTheGrantRemoved` and
`TestProductionAuthorizer_RevokeNonWriteFlushFailureKeepsOneQueuedEvent`
(`internal/bootstrap/authdeps_test.go`),
`TestPermissionsRevoke_HandledSessionWriteFailureKeepsOneQueuedEvent`
(`internal/bootstrap/tui_commands_test.go`), and
`TestSessionsPermissions_RevocationsComeOnlyFromRecords` (`internal/cli/sessions_test.go`).

**25.** **Inputs and target.** It reads only the loaded records: assistant `web_search`/`web_fetch`
tool calls, the one contiguous `role: tool` message answering each call id, later visible assistant
text, and `permission_prompt_shown` events. It takes the same `<session-id|path>` through the same
`singleTarget` + `resolveSession` path the other four use, so a missing file, a too-new
`schema_version`, a parse failure, a record-stream failure, and an event-payload failure all
surface as the existing typed errors with no partial report; `--json` emits the same facts as one
document.
**The labels.** `candidate` — a search's result listed that address. `selected` — a `web_fetch`
issued at a **later record** asked for that **exact** address (a comparison of two persisted calls;
a fetch of an address no earlier search offered is simply left unmarked rather than attributed to
one). `retrieved`/`failed` — that fetch's result recorded `outcome: "ok"`, or one of the bounded
failure outcomes the fetch contract emits; any other string is unclassified evidence and gets no
label, because the record does not establish a failure.
`cited` — that exact address appears in the text of a **later visible assistant answer**. The three
texts that are *not* citation evidence: a tool result (fetched content, not the model's words), an
assistant message carrying tool calls (the model asking for work, not answering), and an answer
written *before* the address was recorded — plus a merely partial address, a longer address that
merely begins with the recorded one, and an occurrence inside another address, none of which match.
When a redirect leaves both a requested and a final address on one source, the report names and
counts the exact address the answer repeated.
**Uncited ≠ unused.** No `cited` label means only that no later visible answer repeated that exact
string. It is not evidence the model ignored the source: nothing in the file records influence, so
the report never claims it, and no label in the set means "unused".
**Two shapes.** The result object is told apart by its key: the landed contract carries
`candidates` (metadata only, each read by its own later `web_fetch`), the older one carried a
`sources` bundle the search had **already** fetched with a per-source `outcome`. The old shape is
reported as a **legacy auto-fetch** with its own totals rather than converted, so existing sessions
need no migration and are never misreported as a history of explicit selections — a later
`web_fetch` of a legacy address leaves that source at its persisted labels, because only a
candidate-first source is eligible for `selected`.
**Host prompts.** Only `permission_prompt_shown` with `subject_kind: host` and subject `web_search`
or `web_fetch`, counted as prompts shown and as distinct `host_scope` values. A
`permission_matched` never prompted a human, and a prompt for any other subject is not web
research, so neither counts.
**Unreadable versus invalid.** Tool arguments and results are schema-valid opaque text: one that is
not readable JSON is reported as **unclassified** evidence on that call — no query, address,
outcome, or citation is invented — and the command still succeeds. One field outside the contract
carries the same weight as an unreadable whole: a negative `omitted`, a legacy source with no
`outcome`, a non-string `final_url`, a null `candidates`/`sources` value, or a result carrying both
shapes' keys marks the result unclassified while the readable facts around it stay visible. A
present JSON `null` never reads as an absent field — `"omitted": null` is not a confirmed zero and a
`null` `final_url`, explicit or legacy, is not a source that never redirected. Nor does a present
blank string: no stored address, outcome, or tool name may be empty or whitespace-only, so a
`final_url` of `""` or `"   "` is malformed, not an absent redirect. A `candidates[].url` is held to
the contract the search producer writes — a complete canonical HTTPS address `web_fetch` would
admit, in exactly the stored spelling — so a blank, `http://`, or differently-spelled value is
unclassified result evidence rather than a candidate. So are the producer's bounds: a sixth
candidate or an address past 2048 bytes is no candidate, over-long candidate metadata unclassifies
the result while its address stays visible, and a `final_url` counts only on `outcome: "ok"` and
within its own bound, so a final address on a failed outcome never reaches citation matching. Fields omitted from the report are not
omitted from validation: candidate `title`, `snippet`, and `published_date`, and current or legacy
fetched `content`, must still be stored strings. A malformed one unclassifies the result without
hiding an independently readable address or outcome. On the
argument side, a recognized web call whose `arguments` are not a JSON string stays in the report
(only its arguments are unclassified), and a whitespace-only query or address — which the
dispatcher rejects — is unreadable rather than a query or a source. Two calls sharing one ID in one
assistant message leave the stored response attributed to neither. An invalid *record* is a
different thing and still fails in the loader before any report is printed. The report is
read-only: it writes no rating, annotation, or derived event back. *Proof:* `buildResearchReport`,
`classifySearchResult`, `markSelections`, `markCitations`, `visibleAnswers`, `webHostPrompts`
(`internal/cli/sessions.go`); `TestSessionsResearch_Fixture_HumanReport` and
`TestSessionsResearch_Fixture_JSONCarriesTheSameFacts` pin both output forms against
`internal/cli/testdata/sessions-research.json`,
`TestSessionsResearch_CitationNeedsAnExactLaterAnswer` pins every non-citation,
`TestSessionsResearch_LoadErrors` the loader failures, and
`TestSessionsResearch_LeavesTheSessionUnchanged` the read-only promise
(`internal/cli/sessions_test.go`).

**26.** **The kind is `permission_matched`.** No new kind was minted because a protected-state
refusal *is* a permission outcome; a private kind would split the permission audit across two
streams for no gain. The append-time validator pins the combination closed: `outcome_source:
protected_state` requires `outcome: deny`, `subject_kind: tool`, and a subject drawn from the five
guarded mutation tools — any other combination is rejected before a record is written. The load path
still tolerates an unrecognized `outcome_source`, so a session written by a newer build stays
loadable.

**Whose write it is.** `dispatch.PrepareTool` produces the typed refusal but holds no session store;
the production dispatcher owns the active one, so it is the single writer. That also keeps the
record following a `/clear` or `/resume` store swap, like every other tool-side event.

**Append failure.** It fails closed: `Dispatch` returns an internal failure that aborts the turn, and
the file tool is not invoked (it never was — the refusal happened during preparation). An
unrecordable refusal is never returned as an unrecorded denial.

**Why the in-memory store is not evidence.** `events.Append` only appends in memory; durability
comes at the next flush boundary. An assertion against the live store proves the record was built,
not that it survives the run — so the evidence to trust is the session **file** reopened after the
turn's continuation flush. *Proof:* `PermissionMatched.checkKnownSourceOutcome` in
`events/payloads.go`, `EmitMatched` in `events/permissions.go`, `denyProtectedState` in
`bootstrap/tooldispatch.go`; pinned by
`TestStartTUI_ProtectedSettingsMutationIsRefusedAndTheTurnReIssues` and
`TestRunHeadless_ProtectedSettingsMutationIsRefusedAndTheTurnReIssues`, which both reopen the
session file rather than reading the active store.

**27.** **The two decisions are `omitempty` and the `*int64`, and they solve different problems.**

**`omitempty` keeps pre-change sessions loadable.** `requirePresent` → `requireShape`
(`internal/events/payloads.go`) rejects a stored record that omits any field whose json tag lacks
`omitempty`. Declared as a plain required field, every `model_response` written before the field
existed would fail `ValidatePayload` at load — the field would break reading old sessions, not just
writing new ones.

**The pointer keeps absence distinct from a reported zero.** nil means the provider reported no
cached count, and the key is absent from the JSON. A non-nil `0` means the provider explicitly
reported zero cache use, and the key is written as `"cached_input_tokens":0`. A plain
`int64` with `omitempty` cannot express both: Go drops a `0` on write, so a reported zero would
serialize identically to silence. `ProviderRequestFailed.HTTPStatus` is the same pattern.

**`cached_input_tokens_partial`** says the recorded total is a **known lower bound**, because at
least one provider round contributing to that turn reported no cached count. It is written **only as
`true`**, and only alongside a present total — the validator rejects the marker without one. Its
absence means either that the present total is exact or that there is no total at all; it never
means "exactly zero rounds were missing" as a separate claim.

**No anomaly.** An absent cached count does not add `usage_missing`. Providers legitimately omit the
field, so treating omission as a fault would flag healthy turns; `usage_missing` stays limited to
`input_tokens`/`output_tokens`. *Proof:* `ModelResponse` and its `validate` in
`internal/events/payloads.go`; `TestModelResponse_LegacyRecordOmittingCachedFields` (the record that
would fail without `omitempty`), `TestModelResponse_CachedZeroSurvivesTheWire`, and the
`model_response/negative-cached` and `model_response/partial-without-cached` entries in
`invalidPayloads` (`internal/events/append_test.go`); `normalizeUsage` and
`TestUsageFromStreamUsage` (`internal/model/turn_events.go`, `turn_events_test.go`) for the
no-anomaly rule.

**28.** The order is `doctor` → `show` → `permissions` → `research` → `summary`, and each step narrows
what the next has to read. `codemeld sessions doctor <session-id|path>` comes first: it reports the recorded
errors, failures, and anomalies plus the turns that never finished (a `turn_terminal` with an outcome
other than completed/cancelled, and a provider round no terminal ever closed, reported as
`reason=incomplete_round`), so it names the turn to look at. `codemeld sessions show
<session-id|path>` then prints the message, event, and compaction records in order with tool-call
arguments unescaped, giving the context around that finding. `codemeld sessions permissions
<session-id|path>` is for anything about authorization: the prompts a human was actually shown with
their decisions, the authorizations that never prompted counted by source, and the explicit
revocation requests. `codemeld sessions research <session-id|path>` covers a run that used the web:
the searches, the sources fetched, and which addresses a later answer cited. `codemeld sessions
summary <session-id|path>` gives the shape of the whole run: the durable execution records, the
permission path scopes they ran under, and the turn, round, and token totals — read under the limits
`docs/sessions.md` states before quoting any figure from it.

All five targeted diagnostics (every `sessions` subcommand except the `list` inventory) take the same
target, `<session-id|path>`: a value that is a valid session id is treated as an id, anything else
as a path to a session JSON file. A bare id is found **from any directory** —
unlike `codemeld --resume <id>`, which refuses a session recorded in another folder — so you can run
these on a colleague's id without moving to the folder the run happened in. The two decisive
properties: they are **strictly read-only** — they never write,
lock, prune, fork, or refresh a session, so running one on a suspect file is always safe — and their
output **prints stored session content verbatim**, so a report is as sensitive as the session file
itself and must be handled the same way.

Evidence: `newSessionsCommand`, `resolveSession` (`internal/cli/sessions.go`);
`runSessionsSummary` (`internal/cli/sessions_summary.go`); the `Troubleshooting a session` section
of [`docs/sessions.md`](../../../docs/sessions.md).

**29.** Only a finding that reports a `turn_id` can be followed with `show --turn`. Those are the
**turn-lifecycle** finding — a `turn_terminal` whose outcome is one of the failure outcomes, carrying
`turn_id`, `round_id`, `outcome`, and `failure_phase` — and the **incomplete-round** finding, a
`provider_round_trip` carrying a turn/round pair that no `turn_terminal` ever closed, reported as
`reason=incomplete_round` with the same two ids.

The **tool-execution** finding is the one that names a failed tool and no turn. A `tool_exec_end`
with a non-zero `exit_code` reports `failed_tool` (the program name for a `direct` subject, the tool
name for a `tool` subject, and nothing at all for an `sh -c` literal, whose script cannot be reduced
to a safe name), plus `subject_kind`, `invocation_id`, `duration_ms`, and `exit_code`. The recorded
arguments and the captured stdout/stderr are deliberately never printed. Since there is no turn id to
pass, narrow `show` another way: `--kind tool_exec_end` (repeatable, and pairable with
`tool_exec_start`) for the call records, or `--last <n>` for the tail of the session; `--json` emits
the same selection machine-readably.

One overlap worth knowing: a `turn_terminal` that failed in **tool dispatch** carries `failed_tool`
*as well as* its turn — that finding does support `--turn`.

*Proof:* `toolExecFinding`, `boundedToolName`, `incompleteRoundFinding`, `toFinding`
(`internal/cli/sessions.go`); `TestSessionsDoctor_FailedToolIdentityIsBoundedInHumanOutput`,
`TestSessionsDoctor_FailedToolIdentityIsBoundedInJSON`, `TestSessionsShow_TurnFilter`.

**30.** Run `codemeld sessions list`, the inventory step that comes before the targeted diagnostics. It
takes no arguments (a positional one is a usage error) and by default lists the sessions recorded for
the folder you run it from — the same sessions the no-id `codemeld --resume` picker offers, though
`list` never resumes, writes, or locks anything. Each row shows the title you set for the session,
or its first user message when there is no title you set (a generated or legacy title is never
shown), then the full session id, the folder it was recorded in, and its
started and last-updated times, ordered by last-updated time, newest first, then by id.

`--all` lists the sessions of every recorded folder instead. When one session id appears in more than
one folder, only the most recently updated copy is listed and each discarded copy is reported on
stderr. `--json` prints the same rows as a JSON array with the keys `name`, `id`, `folder`,
`started_at`, and `updated_at`, and `[]` when there are none.

The corrupt file is skipped with a warning on stderr naming it — in the default mode as well as with
`--all` — and the listing carries on; under `--all` an unreadable folder is skipped the same way.
Warnings never go to stdout, so the `--json` array stays valid for a script. Those per-file and
per-folder skips stay warnings, but failing to read the current folder's session directory, or with
`--all` the sessions directory itself, stops the command with an error. So do a positional argument
or invalid flag (a usage error) and failing to resolve the home directory or the current folder.

Evidence: `runSessionsList` and the `list` subcommand in `newSessionsCommand`
(`internal/cli/sessions.go`); `ListResumable`, `ListResumableAll` (`internal/sessions/resume_list.go`);
`TestSessionsList_CurrentFolderAndAll`, `TestSessionsList_AllDeduplicatesAndSkipsFolders`,
`TestSessionsList_EmptyResults`, `TestSessionsList_EnumerationFailures`,
`TestSessionsList_UsageErrors` (`internal/cli/sessions_test.go`);
`TestListResumable_ExposesOnlyUserProvenanceTitles` (`internal/sessions/resume_list_test.go`).
