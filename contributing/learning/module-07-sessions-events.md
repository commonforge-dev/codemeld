# Module 7 — Sessions & events: durability

_Snapshot as of 2026-10-06; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-10-06_

> A session is the whole audit trail: metadata plus every message and event, written to one JSONL file, crash-safely.
> This module covers how it's created, stored, resumed, and recovered.

## Goal

After this module you can:

- Explain how a session is created and where its file lives.
- Explain the append-only JSONL write path and the in-memory-then-flush model.
- Explain which sessions take an ownership lock, and what prevents two processes entering one.
- Explain what happens to a session on a write failure mid-turn, and what a fork copies.
- Explain how `/fork` and `/compact` transfer ownership from parent to child, and why `/compact`
  runs asynchronously.

## Why it matters

The session is the source of truth for "what happened." Durability and recovery are subtle — and
several decisions (sidecar lock, atomic write, append-only) recur across the codebase.

## Read (in order)

1. `internal/sessions/ensuresession.go` — `EnsureSession`.
2. `internal/sessions/folderdir.go` — `SessionRoot`, `FolderDirName`, `CanonicalizeFolder`.
3. `internal/sessions/store.go` — `Store`, `Append`, `Flush` (and `fsutil/atomic.go` `WriteAtomic`).
4. `internal/sessions/version.go` — schema-version handling (`OpenSession`, `ClassifyVersion`).
5. `internal/sessions/validate.go` — `ValidateRecordStream`.
6. `internal/sessions/resume_lock.go`, `resume_resolve.go`, `resume_list.go`, `resume_refresh.go`.
7. `internal/sessions/prune.go`.
8. `internal/events/append.go`; `internal/sessionfailures/failures.go`; `internal/sessionfork/fork.go`; `internal/bootstrap/childdeps.go`.
9. `internal/cli/sessions.go` — the read-only `codemeld sessions` command: the `sessions list`
   inventory (`runSessionsList`, over `ListResumable`/`ListResumableAll` in
   `internal/sessions/resume_list.go`), the `sessions doctor`/`sessions show`/`sessions
   permissions`/`sessions research`/`sessions summary` diagnostics, their shared
   `<session-id|path>` target, and `show`'s `--kind`/`--turn`/`--last`/`--json` filters;
   `internal/cli/sessions_summary.go` — `runSessionsSummary`.

To discover the current event kinds and payload fields off the code and a real session — rather than
from a snapshot that goes stale — see [`../../docs/sessions.md`](../../docs/sessions.md);
`internal/events/payloads.go` is the authoritative schema. That guide also opens with `sessions list`
for finding which session to look at, then the troubleshooting order for the five targeted
diagnostics: `doctor` first for failures and unfinished turns,
then `show` for the records in order — narrowed with `--kind`, `--turn`, and `--last`, or emitted
machine-readably with `--json` — `permissions` for prompts and decisions, `research` for the web
funnel, and `summary` for the shape of the whole run.

## Mental model

### Lifecycle

`EnsureSession` mints a UUIDv7 id, builds the path `~/.codemeld/sessions/<folder-dir>/<id>.json`, and
returns a `*Store` — but **does not write the file**. The first durable write is the caller's job (the
launch sequence appends `launch_began` and flushes). `<folder-dir>` is `FolderDirName` =
`<sha256-prefix>-<sanitized-basename>`; each folder-dir carries a one-line `folder` file recording the
canonical launch directory.

`Store` buffers records in memory (the source of truth between flushes). The file is JSON-lines: line
1 is `{"type":"metadata","metadata":{...}}` (**not** a `Record` — `Records[0]` is the first later
line), and each later line is one record of the closed set: a `message`, an `event`, or a
`compaction` (see **Recovery and fork**).
The first write and explicit metadata changes use `fsutil.WriteAtomic` (sibling temp file, fsync,
rename, parent-dir fsync). Normal turn flushes append only the new record lines, fsync, and advance the
durable record boundary only after success. That boundary is tracked as a **byte offset** (the end of
the last complete line), not just a record count: when a store opens a file that recovered from a torn
final line, the first append truncates the half-written tail back to that offset before writing, so the
torn bytes can never fuse onto the new record and break the file. The file mode is `0600`.

### Append-only audit log

`Store.Append` adds a record in memory (no flush; silently dropped if the store is closed).
`events.Append` canonicalizes a payload (UTF-8 coercion, nil-slice → `[]`), mints an id and timestamp,
and appends an `Event`. `ValidateRecordStream` is the load-time *cross-record* validator (tool-call
correlation, sibling-field placement) layered on top of the per-record shape parse.

Because ordinary flushes do not rewrite metadata just to advance recency, readers use an effective
`updated_at`: the metadata timestamp or the latest complete record timestamp, whichever is later.
`RefreshUpdatedAt` is the explicit resume-time metadata rewrite that keeps a resumed session inside the
retention window.

The event-kind set is **closed but additive**: `events.ValidatePayload` rejects an *unknown* kind, so a
new kind must be added to its dispatch — but adding one is non-breaking (older sessions simply lack it),
so it needs **no `schema_version` bump**. Recent additive events include the timing events: `turn_latency`
(end-to-end wall-clock of one completed user turn, submit → final answer) and `provider_round_trip` (one
provider round, request → terminal outcome). Both carry `provider`, `model_id`, and an `int64`
`duration_ms` (the same millisecond convention as `tool_exec_end.duration_ms`). The submit-start the
end-to-end measurement needs is captured at the pre-turn boundary (`sessionturn.Persister`) and threaded
through bootstrap into the final provider round, so one completed agentic turn records exactly one
`turn_latency` and one `provider_round_trip` per provider round (failed rounds included, paired with
`provider_request_failed`). New `provider_round_trip` records also carry matching UUIDv7 `turn_id` and
`round_id` values; their absence remains valid for legacy sessions. `turn_terminal` closes each provider
round with the same IDs, a closed outcome, an optional provider failure phase, and whether tool dispatch
started. It deliberately has no response, tool-argument, or error-detail field, and rejects unknown
content fields while accepting future optional fields for compatibility.

**Fields are additive too, and an optional field has to earn its `omitempty`.** `model_response`
carries `cached_input_tokens` (`internal/events/payloads.go`) — the prompt input a provider says it
served from cache. Two details of its declaration are load-bearing, and both are the kind of thing
that looks like style until it breaks a session:

- **`omitempty` keeps old sessions loadable.** `requirePresent` → `requireShape` rejects a stored
  record that omits any field whose json tag lacks `omitempty`. Adding the field without it would
  make every `model_response` written before the field existed fail `ValidatePayload` at load. This
  is the general rule for adding a field to an existing kind, not a quirk of this one.
- **The `*int64` keeps "not reported" distinct from "reported zero".** Providers legitimately omit
  the count. A nil pointer (key absent) means the provider said nothing; a non-nil `0` (key present,
  written as `"cached_input_tokens":0`) means the provider reported zero cache use. A plain `int64`
  with `omitempty` collapses the two, because Go drops a `0` on write. `ProviderRequestFailed.HTTPStatus`
  is the older instance of the same pattern.

The companion `cached_input_tokens_partial` is written only as `true`, and only next to a present
total: it says the recorded number is a **known lower bound**, because some provider round in that
turn reported no count. Its absence means the total is exact, or that there is no total. The
per-record validator enforces both halves — a present count must be non-negative, and the marker is
rejected without a count. Note what it is *not*: an absent cached count never adds `usage_missing`,
which stays limited to `input_tokens`/`output_tokens`.

`permission_revoke_requested` (`internal/events/payloads.go`,
`EmitPermissionRevokeRequested`) is another additive kind, and a good example of an event whose
*meaning* is narrower than it first looks. The `/settings` revoke control is its only writer —
`source` is a closed vocabulary with the single value `permissions_ui` — so it separates "a human
deliberately revoked this grant" from "this grant is no longer in the YAML," which a settings file
alone cannot distinguish.

Its payload copies the **removed grant's own stored identity** (`permissions.PermissionEntry`'s
`DedupKey` — `kind`, `subject`, `path_scope` or `host_scope`, `grant_kind` — plus a literal grant's
`argument_hash`), never the request subject that once created the grant. The stored subject is kept
verbatim: hashing or truncating it would destroy the correlation the record exists for.

Three limits are part of the contract, and `productionAuthorizer.RevokeGrant`
(`internal/bootstrap/authdeps.go`) is where you can read them off the code:

- **Observed request, not proven removal.** For a persisted grant the writable settings file is
  checked for the entry (`targetHasGrant`) *before* `permissionpersist.DeleteGrant` takes its lock,
  and that delete treats a missing key as a clean no-op. So the record means /settings saw the
  grant and asked for an idempotent delete that reported success — not that this process is what
  removed a line from disk.
- **Delete before record, on purpose.** Once the settings delete succeeds the live grant is dropped
  from the table *before* the event is appended. The session log is fsynced per append, with no two-phase
  commit across two files, so one of the two failures has to be accepted — and a revoked grant that
  keeps authorizing is worse than a revoke with no event. A crash in that window leaves a real
  revoke unrecorded.
- **Recorded is not yet durable.** The append is followed by the command flush hook. That hook owns
  the `session_write_failed` notice/retry protocol and returns nil once it has handled such a
  failure, so the revoke adds no second notice and no second event: the one appended record simply
  waits for the next flush boundary. Only an append rejection (nothing queued) or a flush error the
  protocol does not own produces the revoke's own "revoke not recorded" notice — which deliberately
  does not read as a failed revoke, because the grant is already gone. The memory-only arm records
  nothing at all unless the synchronized table removal reports it actually removed the grant, so a
  stale or duplicate request stays silent.

`structured_read_start` / `structured_read_end` (`internal/events/structuredread.go`,
`EmitStructuredReadStart` / `EmitStructuredReadEnd`) are a second, additive lifecycle pair — the
audit evidence for **concurrent structured reads**. They are deliberately *not* `tool_exec_*`: those
carry shell-shaped fields (`exit_code`, `stdout`, `stderr`, `truncated`) whose meaning belongs to the
shell/VCS emitters that write them today, and a structured read has neither an exit code nor a stream
pair. So `tool_exec_*` keeps one unconditional meaning and the read pair stands alone.

How to read the pair as an auditor:

- **`invocation_id`** (a UUIDv7) is the pairing key and the *only* one. Both records repeat it.
- **Intervals come from the record timestamps `events.Append` stamps**, not from the payload — neither
  event carries its own timestamp or sequence number. Two invocations overlap when their
  start→end intervals intersect, which is why the start is a separate record: a single
  after-the-fact summary event could not show that an invocation had begun.
- **The start records `configured_concurrency`** — the positive `agent.max_concurrency` in force for
  the scheduled group. It lives on the start only, so the cap in force for any group is recoverable
  even if configuration later changed. The end records `duration_ms`, measured from a monotonic clock
  rather than by subtracting record timestamps.
- **The end's `outcome`** is a closed five-value set covering every path after a start is appended:
  `success`, `tool_failure`, `denied`, `cancelled`, `internal_failure`.
- **Presence is itself a signal.** Only a prepared, positively classified in-project read emits the
  pair, so a `structured_read_start` proves the invocation was admitted to the concurrent path.
  An excluded or out-of-project call is never half a pair; it instead records a third, standalone
  kind, `structured_read_refused` (`EmitStructuredReadRefused`), carrying the exact name the model
  called, a closed `reason` (`not_allowlisted`, `args_invalid`, `prepare_failed`,
  `scope_unresolved`, `out_of_project`), and the batch size — planning evidence with no
  `invocation_id`, duration, or outcome. Unlike the pair, its append is best effort: planning
  cannot surface an append failure. A lost refusal record loses the evidence that the call was
  refused; it never changes that call's classification, its ordering among its siblings, or
  whether it executes.
- **Append failure fails closed**: if the start cannot be appended the read does not run,
  and a failed end surfaces rather than being swallowed — an unpaired start would make an overlap
  audit ambiguous exactly where it matters. Neither event carries tool output; the results are
  already in the message records.

Every rule above is pinned by a test: read
[`internal/events/structuredread_test.go`](../../internal/events/structuredread_test.go) for the
pair's shape and closed outcome set, and
[`internal/bootstrap/readtools_integration_test.go`](../../internal/bootstrap/readtools_integration_test.go)
for which invocations emit the pair at all.

`permission_matched` (`EmitMatched`) is the one existing kind the protected-state guard reuses
rather than adding a kind of its own — a refusal *is* a permission outcome, and giving it a private
event would split the permission audit across two streams. It carries a closed source:
`outcome_source: protected_state` is only ever paired with `outcome: deny`, `subject_kind: tool`,
and one of the five guarded mutation subjects; the validator in `internal/events/payloads.go`
rejects any other combination at append time, so a malformed guard record cannot be written in the
first place. The load path still tolerates an unrecognized `outcome_source`, so a session written by
a newer build stays loadable.

Two properties are worth reading off the code in `internal/bootstrap/tooldispatch.go`:

- **The dispatcher, not the guard, records it.** `dispatch.PrepareTool` has no session store; the
  production dispatcher owns the active one, so it is the single writer. That also means the record
  follows a `/clear` or `/resume` store swap, like every other tool-side event.
- **Append failure fails closed**, the same rule as the read pair above: an unrecordable refusal
  fails the turn rather than being returned as an unrecorded denial, and the tool is not invoked
  either way. And "recorded" is not "durable" — the record waits for the next flush boundary, so the
  evidence a test (or an auditor) should trust is the one read back from the session **file** after
  the turn's continuation flush, not the in-memory store.

### Ownership: a process owns its current active session

- **The lock:** `AcquireResumeLock` takes an exclusive advisory lock on a **sidecar**
  `<id>.json.lock`, **never the session file** — because per-turn writes replace the session file's
  inode by atomic rename, a lock on that inode would be orphaned. Timeout: **2 seconds**. The kernel
  releases it on process exit.
- **Every active session, not just resumed ones.** Fresh interactive launches, fresh
  headless runs, resumes, `/clear` targets, and the linked children `/fork` and `/compact` create all
  acquire that sidecar **before their first durable append** and hold it while they are active.
  Resume-only locking used to be the rule; it left fresh and child sessions exposed, because UUID
  uniqueness keeps two fresh launches off each other's file but does not stop another process from
  resuming, pruning, or appending to a file this process is still writing. The `ResumeLock` names are
  historical and were deliberately left unrenamed.
- **What it prevents:** a second process entering a session this one is mutating — a second
  `--resume <id>` contends and times out, and the pruner's non-blocking try fails and skips the file.
- **Resolve / list:** `ResolveResumeID` (`resume_resolve.go`) loads the whole session file and runs
  `ValidateRecordStream` and `ValidateEventPayloads` over it, then checks the folder-file and that the
  canonical cwd matches the session's recorded folder. That is where a resume candidate's records are
  validated: the session the user selects is checked when it is resolved and loaded, not when it is
  listed.
  `ListResumable` (`resume_list.go`) does not load a candidate through the session loader or
  validate its records. Per file it reads the metadata line, always through to its newline however
  long it is, because a title can be any length. Then it reads the records after it up to the first
  user message, within a forward budget (`listForwardScanMax`) counted from the start of the file —
  so an oversized metadata line spends that budget and the row lists with an empty preview. Last, it
  reads a tail window of at most `listTailScanMax` bytes for the newest record timestamp; a file no
  larger than that cap is read whole for this step. So a session whose middle records are corrupt
  still appears in the list and fails only once it is selected.
  A candidate lands in the **skipped** bucket only when its metadata line cannot be read or parsed,
  its `schema_version` is refused (newer or unparseable), or its `metadata.folder` does not match the
  folder file. Skip reasons are **redacted** — a skipped candidate shows only its id.
  Survivors sort most-recent-first by the later of `metadata.updated_at` and the newest record
  timestamp found in the tail window, ties broken by id descending.
- **Refresh:** `RefreshUpdatedAt` rewrites `updated_at` right after locking so the resumed session
  sorts inside the retention window. Resume itself starts no prune (see **Prune** below); this refresh is
  retention safety against a *concurrent* pruner — another instance, or a later fresh launch.

### Recovery and fork

- **Torn final line:** if a crash truncates mid-append, the last line lacks its newline. On load
  `completeJSONLLines` drops that incomplete tail back to the last complete record (the load
  succeeds); the store then records the recovered byte boundary so its first append **repairs** the
  file — truncating the torn bytes — before writing, keeping the file parseable across that first
  post-recovery write.
- **Write failure mid-turn:** `HandleWriteFailure` (in `sessionfailures`) **retains** the in-memory
  records, appends a `session_write_failed` event, renders a one-line notice, and does **no**
  synchronous retry — the next flush carries everything. On *clean shutdown*, `CleanShutdownFlush`
  retries once, then prints an `OP_FAIL` line and exits 1 (and emits no event, since no later flush
  could carry it).
- **Child sessions:** `sessionfork.CreateChild` is the one way a session is created from a live
  parent. The caller hands it the already-prepared child records; it writes the **whole child
  first** (`launch_began{source: fork}` is that file's first and only durable write), and only once
  that lands does the parent get a `session_forked` marker, a flush, and a `Close`. `Close` seals
  the parent **in this process only** — the parent file stays on disk, stays listed, and stays
  resumable in later runs. Two files cannot be committed together, so the child-first order is what
  prevents a durable parent link to a missing child; if the *parent* marker then fails to flush, the
  parent stays open and appendable and the child that already landed is a complete, resumable
  session, not a partial file.
  When that **initial child write itself fails**, `CreateChild` invokes its write-failure callback
  exactly once with the exact child file path plus the raw category/reason/error from the flush —
  the path matters because the child was never published (a failed create leaves no target), so
  no listing, store, or later flush can name the failed file. The path is reported **only** for
  that initial write: a parent-marker failure happens after the child is safely published, so it
  never invokes the path-aware callback. `ForkSession` keeps its original three-value callback
  (no path) and adapts internally.
- **Owning a created child:** `sessionfork.CreateOwnedChild` first prepares the child **in memory**
  — `sessions.EnsureChildSession` builds and validates the child store without touching disk — then
  acquires the child's own `<id>.json.lock` sidecar **before** `launch_began` makes that file
  durable, holds it through the parent's terminal batch, and returns that release token alongside
  the child store. Nothing is ever written under an unheld child lock. So during a
  switch the process briefly holds **two** session locks — the parent's and the child's. That
  overlap is required, not accidental: releasing the source first would leave the session being
  left unowned for an interval another process could step into. Steady state is still
  exactly one held session lock.
- **Preparing and activating a created child (live state):** `preparedChildLifecycle`
  (`internal/bootstrap/childdeps.go`) is the one shared transition from a created child onto the
  running TUI, split into a fallible `Prepare` and a non-failing `Activate`. `CreateAndActivate`
  is the synchronous convenience wrapper the shipped `/fork` uses; the shipped `/compact` calls
  `Prepare` on a background goroutine and `Activate` back on the event loop.
  `Prepare` rejects a nil or non-active parent (pointer equality with the app's active store)
  before any durable work, then creates and owns the child. `Activate` **installs the exact
  prepared child as the active store first**, then hands the child's release token to the
  run-scoped `resumeLockHolder` and releases the parent's — target before source, so the just-left
  session is never unowned while it is still active — and finally resets the transcript,
  re-renders the launch banner, and replays the child's records through the visible-only
  projection. Nothing fallible runs after the parent is sealed, which is why `Activate` cannot
  fail. Every creation failure leaves the parent active, its ownership held, and the transcript
  untouched; a parent-marker failure can leave a complete child file behind as an unlocked
  resumable orphan, which is never scanned for or activated. An initial-child-write failure
  surfaces the callback's exact path/category/reason/error as the operation error and deliberately
  does **not** go through `sessionfailures.HandleWriteFailure` — that protocol retains records on
  a live store for a later flush, and an unpublished child has no store, listing, or later flush
  to carry a `session_write_failed` event.
- **Provenance:** a child carries `metadata.forked_from {session_id, record_id}` naming the parent
  and the parent record it was taken at, and its **first record only** repeats that record id as
  `parent_id`. Both fields are additive and optional (no `schema_version` bump); `validateProvenance`
  enforces the link on both `Marshal` and `Unmarshal`, so a mismatched, misplaced, or dangling link
  can neither be written nor loaded.
- **Compaction record (the third record shape):** a `compaction` (`internal/sessions/schema.go`
  `Compaction`) is the durable summary `/compact` writes so a linked child can start **without**
  copying the parent's messages. It is valid **only as `Records[0]` of a linked child** — the same
  first-record slot the fork stamps — so `EnsureChildSession` stamps its `parent_id` through the
  generic `withParentID(records[0], …)` path and `validateProvenance` requires
  `parent_id == metadata.forked_from.record_id`. A second (or misplaced) compaction is rejected by
  **position**, not by any global record-id uniqueness rule; a completed child may still carry later
  records such as `launch_began`. Its `summary` is the model-facing continuation text; its
  `provider` and `model_id` are **audit metadata** identifying which model generated the summary and
  are *not* source provenance (source identity lives only in `forked_from`/`parent_id`). The
  discriminator ships under `schema_version:1` **without a bump on purpose**: the feature is
  predeployment, so existing message/event v1 files stay readable, but an older build **rejects** a
  compacted child because `parseRecord` treats the unknown `compaction` type as a hard error — a
  deliberate same-version incompatibility, not backward-compatible unknown-record handling.
- **Fork (two distinct paths):** the shipped `/fork` command copies the parent's **full
  continuation** — message and compaction records, dropping only events — through
  `forkContinuationRecords`, then activates the child live via `CreateAndActivate`. `ForkSession`
  is the separate **legacy text-only** wrapper over `CreateChild`: it copies text-only messages
  (drops tool messages and all events) and owns that filtering policy itself, reserved for the
  older-schema migration fork, not the `/fork` command.

### `/compact`: the asynchronous child switch

`/compact` (shipped phase-2, no arguments) is the other child switch. It produces a **summary-only**
child: `Records[0]` is one compaction record and the rest is the child's own `launch_began` — none of
the parent's messages are copied, which is exactly what distinguishes it from `/fork`.

The interesting part is *when* things happen. Summarization is a provider request, so
running it on the event loop would freeze drawing and input:

1. **On the loop (admission).** The handler reads `ActiveState.Current` **once** — that single
   snapshot fixes the provider, the model, and the fixed non-streaming summary request built from
   the captured parent's records — and resolves the client from that same provider's catalog auth
   kind. No second read, no fallback to another provider. Then it takes an exclusive submission
   gate. A turn already in flight, no model selected, or an unavailable provider is rejected here,
   before any of it, with a `slash_command{compact,error}` on the parent.
2. **Off the loop (work).** `App.RunBackgroundAfterDraw` paints once, then runs the provider call
   and `Prepare` on a background goroutine. While the gate is held, every prompt and command is
   **retained and undispatched** — the gate wraps the whole submit adapter, not just the prompt
   path, because slash commands are dispatched first and `/clear`, `/resume`, `/fork`, `/exit`, or a
   second `/compact` could otherwise mutate, replace, or close the captured parent.
3. **Back on the loop (activation).** Completion marshals back to the event loop for `Activate`,
   the transcript rebuild, and one gate release — exactly once, on every terminal path.

**Success is written only once it is true.** The parent's `slash_command{compact,success}` is *not*
recorded on acceptance. It travels as a terminal record in the same atomic batch as the
`session_forked` marker (`CreateOwnedChild`), so the parent's durable stream ends with success
immediately followed by the marker, and a durable success implies the child and the marker are both
durable with only non-failing activation left. Any earlier failure appends
`slash_command{compact,error}` to the still-open parent, records no success and no marker, and
switches no session. Note the fork point: because the success record is written *after* preparation,
the child's `forked_from.record_id` is the parent's last conversation record, not that success
record — unlike `/fork`, which flushes its success record first.

### Prune

Pruning runs **only on a fresh launch** — a background goroutine kicked off after startup. No resume path
prunes: `--resume <id>`, the no-id `--resume` picker, and in-TUI `/resume` all skip it, so the
no-id listing can surface an expired-but-unpruned session until the next fresh launch removes it. StartTUI
gates the pass on `BackgroundPrune`, which only the fresh path sets.

`Prune` deletes `<id>.json` whose `updated_at` is **strictly before** `now − retention`. Exactly-at-cutoff
is retained. Before unlinking, it takes a **non-blocking** try on the sidecar lock, so any session
another process currently owns — resumed, fresh, or a live child — is skipped, never pruned.

### Diagnostics (read-only)

`codemeld sessions` (in `internal/cli/sessions.go`) is a **strictly read-only** way to inspect a session
without resuming it — it never writes, locks, prunes, forks, or refreshes `updated_at`.

- **`sessions list`** is the inventory step, for when you do not yet know which session to inspect. It
  takes no arguments and lists the current folder's sessions — the same ones the no-id `--resume`
  picker offers, but it never resumes one. Each row carries the user-set title (or, when there is none,
  the first-user-message preview — a generated or legacy title is never shown), the
  full id, the recording folder, and the started/updated times, ordered by last-updated time, newest
  first, then by id. `--all` lists every recorded folder instead and keeps only the most recently
  updated copy of a session id found in more than one folder; `--json` prints the same rows as a JSON
  array. A skipped candidate (an unreadable first line, or a file belonging to another folder), an
  unreadable folder under `--all`, and a discarded duplicate are each a warning on stderr, never a
  failure, so `--json` stdout stays valid. Failing to read the current folder's session directory, or
  with `--all` the sessions root, is an error; so are a positional argument or invalid flag (a usage
  error) and failing to resolve the home directory or the current folder.
- **`sessions doctor <session-id|path>`** walks the record stream and reports every error/failure/anomaly event,
  grouped by a **derived** severity (there is no stored severity field — `classifyFinding` is the whole
  convention): the `*_failed` events and `provider_request_failed` and a non-zero `tool_exec_end`
  `exit_code` are **errors**; `model_effort_unsupported`, a `model_response` anomaly, and a failed
  `slash_command` are **warnings**; `stream_interrupted` is **info**. It ends with a per-severity count and
  exits non-zero only on a load/validation failure, never because findings exist. `--json` emits the same
  report machine-readably. The timing events (`turn_latency`, `provider_round_trip`) are **healthy
  data, not findings** — `classifyFinding`'s default ignores them, so `doctor` neither flags nor chokes on
  them. Two finding shapes are easy to conflate and lead to different next steps. A failed
  `tool_exec_end` names the tool as `failed_tool` — the program name for a direct run, the tool name
  for a structured or `vcs_*` run, nothing at all for an `sh -c` literal — along with `subject_kind`
  and `invocation_id`, but it carries **no turn id**. A `turn_terminal` that ended on a failure
  outcome, and a provider round no terminal ever closed (`reason=incomplete_round`), both name a
  `turn_id` and `round_id` — and a `turn_terminal` that failed in tool dispatch names its
  `failed_tool` alongside that turn.
- **`sessions show <session-id|path>`** prints the records in order and **unescapes/indents tool-call `arguments`
  for display only** — storage keeps the verbatim escaped string so it round-trips to the
  provider unchanged; malformed arguments are shown raw and flagged, not fatal. Four options narrow a
  session that is otherwise far more than you want to read: `--kind <event-kind>` (repeatable) keeps
  event records of that kind and never matches messages or compactions; `--turn <turn-id>` selects one
  agent turn whole, from the user message that opened it through the `turn_terminal` that closed it;
  `--last <n>` keeps the final n records after the other filters; `--json` emits the selection
  machine-readably. Reach for `--turn` only after a finding actually reported a turn id — a
  failed-tool finding gives you a tool and an invocation id, so narrow that one with `--kind` or
  `--last` instead. With any filter active the header reads `records: <selected> of <total>`, so a
  filter that matched nothing is visibly a filter result rather than an empty session.
- **`sessions permissions <session-id|path>`** lists the prompts a human was actually shown, in record order,
  each paired FIFO with the next decision for the same subject kind, subject, and request scope
  (`pending` when none), followed by a tally of the authorizations that never prompted and then the
  explicit revocation requests. `--json`
  emits the same report machine-readably, rendered from the same value as the human form.
- **`sessions research <session-id|path>`** reports the web-research funnel in record order — every
  `web_search`/`web_fetch` call, its query or address, the candidates a search returned, each
  fetch's outcome, and the addresses a later visible answer quoted exactly — then the totals.
  `--json` emits the same facts as one document.
- **`sessions summary <session-id|path>`** aggregates what the file already stores into the shape of
  the whole run: the durable execution records (`tool_exec_*` rows ending in an exit code, kept apart
  from `structured_read_*` rows ending in a closed outcome), the permission path scopes they ran
  under, and the turn, round, and token totals. It derives no number the records do not support;
  `docs/sessions.md` states the limits to read it under before quoting a figure.

`sessions permissions` is an **audit** read, so it answers three questions a bare "granted" hides.
**What was stored:** a granted row says `grant=allow_once` when the decision carried no grant fields
(that one call was approved and nothing was written), and otherwise names the stored grant kind, the
folder or host it was stored at, and the stored subject — which may be *wider* than the requested one
(approving `edit` can store the `write` capability). A global grant is named by its kind alone,
because its recorded scope is the all-paths sentinel rather than a folder.
**Whether the prompt broadened an earlier approval:** a prompt is flagged as a **scope escalation**
when its request scope strictly contains a folder an earlier decision already granted *and* that
grant's stored subject covers this request. The subject question is answered by
`permissions.AuditSubjectMatches`, which builds the recorded values into a request/entry pair and
delegates to the live `subjectMatches` — the audit calls the authorization rule instead of copying
it, so the two cannot drift; containment reuses `IsDescendantOrEqual`, and the narrowest qualifying
grant wins.
**Where the record cannot say:** a direct command's request side is the recorded
`permission_prompt_shown.direct_tokens`, never the flattened `subject` — re-splitting it would turn
one quoted argument into two and could manufacture an escalation that never happened. An absent
`direct_tokens` or `grant_subject` is legacy *unknown* data and leaves the row unflagged. The marker
is a historical read of one file and never affects what is allowed at runtime.
**What a human explicitly revoked:** the report ends with the `permission_revoke_requested` records,
in record order, each naming the removed grant's own kind, subject, scope, and grant kind. It is the
same non-inference rule as everywhere else in this report: the rows come only from those records, so
a grant that is simply missing from a settings file produces none and a session written before the
event existed reports zero rather than being back-filled. The count prints even when it is zero.

`sessions research` is the **evidence** read, and its whole design is about what a session file
cannot say. There is no stored field for "this source influenced the answer," so the report never
claims one. It labels each address only from a closed, record-backed set: `candidate` (a search
returned it), `selected` (a *later* `web_fetch` asked for that exact address), `retrieved`/`failed`
(one of the outcomes the fetch contract actually emits — anything else stays unlabelled
unclassified evidence), and `cited` (that exact address appears in a **later visible assistant
answer** — not in a tool result, not in an assistant message that is itself making tool calls, and
neither as a partial address, as the beginning of a longer one, nor as a fragment of some other
address that happens to carry it). A redirect leaves two persisted addresses on one source, so the
report names and counts the exact one the answer repeated rather than crediting the requested
address for its destination. **Uncited is not unused**: it means only that no later answer repeated
that exact string. Two search shapes coexist and are reported apart: the landed candidate-first
`candidates` list, whose sources are read by separate `web_fetch` calls, and the older `sources`
bundle the search had already fetched — reported as **legacy auto-fetches**, so old files stay
analyzable without conversion and are never dressed up as explicit selections, not even when a
later `web_fetch` repeats one of their addresses (only a candidate-first source can be `selected`). Totals keep total
and unique counts apart for queries, candidate addresses, and host prompts, and count only
`permission_prompt_shown` events whose subject is a web tool (a `permission_matched` asked nobody).
Tool arguments and results are opaque stored text: an unreadable one is reported as unclassified
evidence on that call rather than guessed at, and never fails the command. One field outside the
contract is enough — a negative `omitted`, a legacy source with no `outcome`, a non-string
`final_url`, a `candidates`/`sources` value that is not a real list, or a result carrying both
shapes' keys — and the readable facts around it still show. A present JSON `null` is such a value
wherever a field is optional: it decodes into a Go string or number silently, so `"omitted": null`
is not a zero and a `null` `final_url` is not a source that never redirected. A present blank string
reads the same way — no stored address, outcome, or tool name may be empty or whitespace-only, so a
`final_url` of `""` or `"   "` is malformed rather than an absent redirect. A candidate address is
held to the contract the search producer writes: only a complete canonical HTTPS address `web_fetch`
would admit, in exactly the stored spelling, is a candidate, so a blank, `http://`, or
differently-spelled `candidates[].url` is unclassified result evidence. The producer's limits count
the same way: a search stores at most five candidates and bounds each field, so a sixth entry or an
over-long address is no candidate, and over-long candidate metadata unclassifies the result without
hiding the address. A `final_url` is only what a successful fetch can produce — the address the
response came back on, within its own bound — so one carried by a failed outcome, or one that is not
an address, is unclassified and is never matched against a later answer. A recognized web call whose
`arguments` are not the contract's JSON string keeps its place in the report with its arguments
marked unclassified, and a query or address that is only whitespace (which the dispatcher itself
rejects) never becomes a funnel fact. Correlation is by call ID, so two calls sharing one ID in a
single assistant message get the stored response attributed to neither. Candidate metadata and
fetched content are validated even though this report does not display them; a malformed
`title`, `snippet`, `published_date`, or current/legacy `content` marks the result unclassified while
readable address and outcome facts remain visible. An invalid *record* still
fails in the loader, exactly as for the other four.

The five targeted diagnostics (every subcommand but `list`) take the same target,
`<session-id|path>`: a value that is a valid session id is treated as an id, anything else as a path
to a session JSON file. An **id** goes through the same `ResolveResumeID`
path `--resume` uses, but a folder mismatch is not a refusal here — these readers take no lock and
append nothing, so the session is read wherever it was recorded and the report names that folder. A
bare id therefore works from **any** directory for the diagnostics, while `--resume <id>` stays bound
to the recording folder, because resuming would run the session's next tool call against the wrong
tree. An explicit **file path** goes straight through `OpenSession` plus `ValidateRecordStream` /
`ValidateEventPayloads` — the standard loader, never a format-specific reader — so they surface the
existing typed load errors (not-found, newer `schema_version`, parse failure) and keep working as the
storage format evolves.

## Watch for (Go idioms)

- **Test seams as package vars.** `now`, `acquireLock`, `isTerminal` are reassignable so tests drive
  timestamps, lock contention, and tty checks deterministically.
- **Closed sum type + presence flags.** `Record` is sealed (`isRecord()`); `Message` tracks whether a
  key was *present* (independent of value) so the validator can tell absent from empty.
- **Typed errors with exact stderr text.** The whole `Resume*Error`/`VersionError`/`FolderDirError`
  family has `Error()` = the literal user-facing line, plus `Unwrap()`.
- **`math/big` for version parsing** so a future `schema_version` beyond int64 still classifies as
  "newer" rather than overflowing into "unparseable."

## Quiz

Closed-book: [`quizzes/module-07.md`](quizzes/module-07.md). Grade against
[`quizzes/module-07-key.md`](quizzes/module-07-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** Does `EnsureSession` write the session file to disk? Predict, then read
`EnsureSession` and confirm against `TestEnsureSession_AppendFlushSmoke` (`ensuresession_test.go`).
Who performs the first durable write?

**B. Predict, then verify.** Does session ownership lock the session file or a sidecar — and why?
Which launch paths take it? Predict, then read `resume_lock.go` (`AcquireResumeLock`,
`ResumeLockPath`) and the fresh path's `AcquireLock` step in `orchestrate.go`, and confirm with
`TestAcquireResumeLock_CleanAcquireAndRelease`.

**D. Trace the asynchronous switch.** Trace one `/compact` from the installed submit hook to the
activated child: where the active selection is read, where the submission gate is taken and released,
which goroutine each step runs on, and where the success record enters the parent's terminal batch.
Confirm against `TestStartTUI_CompactThroughInstalledSubmitCreatesOwnedSummaryChild`
(`bootstrap/starttui_test.go`).

**C. Trace the two write paths.** Trace the first `Store.Flush` / explicit metadata rewrite through
`fsutil.WriteAtomic`, then trace a later append-only `Store.Flush`. Record the `file:function` chains in
[`progress.md`](progress.md).

## Done when

- You can explain the in-memory-then-JSONL-flush model and why first writes, metadata rewrites, and record appends are crash-safe.
- You can explain the sidecar lock, which sessions take it, and what prevents two processes entering one.
- You can explain the target-before-source ownership transfer and why the two-lock overlap is required.
- You can explain why `/compact` runs asynchronously and why its success record is written last.
- You can explain mid-turn write recovery versus clean-shutdown failure.
- You can explain why a protected-state refusal reuses `permission_matched`, why the dispatcher is
  its only writer, and why "recorded" is not yet "durable".
- You can say what `omitempty` and a pointer each buy an optional payload field, and what breaks if
  either is dropped from `model_response.cached_input_tokens`.
