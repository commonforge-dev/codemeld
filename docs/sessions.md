# Sessions — format, inspection, and troubleshooting

A codemeld session is one JSONL file: the whole audit trail of a run. This guide tells you
**where the files live**, **which diagnostic to run when something looks wrong**, and **how to
read the current schema off the code and a real session** — it deliberately does **not** copy
out the event kinds and payload fields, because that list changes as the schema evolves and a
pasted snapshot would go stale silently. Read the source of truth and inspect a live session
instead.

## Troubleshooting a session

If you do not yet know which session to look at, list them first:

- `codemeld sessions list` — the inventory. It takes no arguments and lists the sessions recorded
  for the folder you run it from: the same sessions `codemeld --resume` offers, but it never
  resumes one. Each row shows the session's stored title, whether you set it or it was generated
  (or its first message when there is no title), the full session id, the folder it was recorded
  in, and its started and last-updated times (UTC).
  Rows are ordered by last-updated time, newest first, then by id. Pass `--all` to list the
  sessions of every recorded folder instead; when the same session id appears in more than one
  folder, only the most recently updated copy is listed. Pass `--json` for a JSON array of the
  same rows (`[]` when there are none).

  A session file whose first line cannot be read, or that belongs to another folder, is skipped
  with a warning on stderr; with `--all`, so is a folder that cannot be read, and each discarded
  duplicate copy is reported there too. These warnings never stop the listing and never touch
  stdout, so `--json` output stays valid. Failing to read the current folder's session directory,
  or with `--all` the sessions directory itself, is an error.

Then work down this list; each step narrows what the next one has to read. Each of these five
commands takes the same target, `<session-id|path>`: a valid session id is found no matter which
directory you run from, and anything else is treated as a path to a session JSON file. This is
where these commands part company with `codemeld --resume <id>`, which refuses a session recorded
in another folder because resuming would run its next tool call against the wrong tree. Reading
takes no lock and appends nothing, so each report simply names the folder the session was
recorded in.

1. `codemeld sessions doctor <session-id|path>` — start here. It reports the recorded errors,
   failures, and anomalies, and the turns that never finished, so you learn *whether* something
   went wrong and which turn to look at.
2. `codemeld sessions show <session-id|path>` — read the message, event, and compaction records
   in order, with tool-call arguments unescaped, to see the context around a finding. Point it at
   the turn `doctor` named with `--turn <turn-id>`, or narrow it with `--kind` and `--last`,
   rather than reading a whole session; `--json` emits the same selection machine-readably.
3. `codemeld sessions permissions <session-id|path>` — for anything about authorization: the
   prompts a human was actually shown, each with its decision, the authorizations that never
   prompted, and the explicit revocation requests.
4. `codemeld sessions research <session-id|path>` — for a run that used the web: the searches,
   the sources fetched, and which of those addresses a later answer cited.
5. `codemeld sessions summary <session-id|path>` — for the shape of the whole run: the durable
   execution records, the permission path scopes they ran under, the turn, round, and token
   totals, and the provider-reported cost. Read its limits below before quoting a number from it.

All six `sessions` commands are strictly read-only: they never write, lock, prune, fork, or
refresh a session, so running them is always safe. They do print stored session content verbatim,
so their output is as sensitive as the session file itself — treat a pasted report the same way
you would treat the session.

## Source of truth

`internal/events/payloads.go` is authoritative and always current:

- The block of `Kind…` constants (`KindLaunchBegan`, `KindToolExecEnd`, …) is the complete set
  of event kind strings written to the `kind` field.
- Each payload struct beneath it carries the JSON field tags and a validator, so the struct for
  a kind *is* that event's field list and rules. `EventPayload` is the closed interface every
  payload implements. `ValidatePayload` is the load-time entry point; the `unmarshalPayload` switch
  it calls maps a kind string to its payload struct — read that switch to see which struct owns a
  given kind.

One combination is easy to misread, so it is worth naming here: a `permission_decision` with
`outcome: "granted"` and **no** grant fields — no `grant_kind`, and no `grant_path_scope` (or
`grant_host_scope` on a host prompt) — is an **allow this once** approval: the user approved that
one call and nothing was stored. A granted decision that carries both grant fields records a stored
grant: session, folder, or global for a path subject, and session or project for a host subject. A
partial pair (one field without the other) is invalid and never written. Every answered prompt
therefore has exactly one `permission_decision`, so `permission_prompt_shown` and `permission_decision` counts match for a
session in which the user answered every prompt.

A decision that stored a grant also carries `grant_subject`: the subject actually written to the
grant table, which can be **wider** than the request's own `subject` — approving `git commit -m wip`
may store `git`, and approving the `edit` tool may store the `write` capability. `subject` always
stays the requested one, so a prompt and its decision still pair up; `grant_subject` is what tells
you which stored grant a later `permission_matched` is resolving against. It is absent on an
allow-once or denied decision (nothing was stored), and also absent on every stored grant written
before the field existed — an absent `grant_subject` on a granted decision that carries grant fields
means an older session, not a subject equal to `subject`.

Replaying a **direct command** permission check needs two inputs, and they live on two different
records. The request side is `permission_prompt_shown.direct_tokens`: the exact canonical token
sequence the matcher was given, one array element per shell token, so an argument that contains
whitespace (`git commit -m "First task"`) stays one element. The event's own `subject` is the same
tokens flattened with spaces and is *lossy* — re-splitting it would turn that one argument into two
and can invent a scope escalation that never happened, so never tokenize `subject`. The grant side
stays `permission_decision.grant_subject`, kept as the raw stored spelling: a bare trailing `:*` is
wildcard syntax, while a quoted `":*"` or escaped `:\*` is a literal argument that matches nothing
wider. Together they let an auditor re-run the same comparison the live matcher made.

`direct_tokens` is absent on literal, tool, and host prompts, which have no direct token sequence.
It is also absent on every direct prompt written before the field existed: that absence means the
tokens are **unknown**, not empty and not equal to `subject`. An absent value can never be treated
as evidence that a stored grant covered the request.

### `permission_prompt_wait`: how long a person was asked

Each call that asks a person for approval appends one `permission_prompt_wait` after the call
returns, whatever the result (`finishPromptCall` in `internal/permissions/orchestrate.go`). That
covers a single request, a command pipeline asked as one question, and a group of independent
calls. `waited_ms` is measured on the process's monotonic clock from just before the prompt call
to just after it returned, so it includes time spent queued for the one-at-a-time prompt slot
behind another request's prompt. It is time the run spent blocked on a person, and in
`codemeld run --prompt-for-approval` it counts against `--time-limit`.

`ended` is `cancelled` when the run's context was already done when the prompt returned — the time
limit, an interrupt, or an answer typed after the limit, which authorizes nothing — `failed` for
any other prompt error, and `answered` otherwise. A cancellation that lands after the prompt
returned does not change an already appended `answered`, though the request is still refused.

`prompts` counts the **requests** submitted to the call, not the questions shown and not records
in the file: a pipeline asks one question for all its stages, and an independent group asks one
question per distinct decision but submits every member. The rule that `permission_prompt_shown`
and `permission_decision` counts match does not extend to this event: a cancelled or failed call
has a wait and shown events but no decision.

The record's `timestamp` is when it was appended, an approximation of the moment the wait ended,
so the wait covered roughly `timestamp − waited_ms` to `timestamp`, at millisecond precision.
Concurrent requests queue behind the same prompt slot, so their intervals overlap; adding up
`waited_ms` across records counts the overlap more than once, and a total must merge the
intervals instead.

An unattended `codemeld run` (no `--prompt-for-approval`) and every child agent refuse through
the same prompt step but ask nobody, so they write no wait record; their `permission_prompt_shown`
and `permission_decision` are unchanged (`headlessAuthorizer.Authorize` in
`internal/bootstrap/headless.go` binds the recorder only when a terminal approver exists).

The record is appended in memory and becomes durable at the session's existing flush points,
including the final flush after an interrupt. Nothing is written before the prompt call returns:
a terminal read or TUI prompt that stays blocked after cancellation, a process that is killed
outright, or a session switch that closed the store the prompt was recording into all leave no
wait record.

### `permission_revoke_requested`: what a revocation record does and does not prove

The `/settings` revoke control is the only writer of `permission_revoke_requested`: `source` is a
closed vocabulary whose single value is `permissions_ui`. It appends one record per qualifying
revoke — a session grant the live table really removed, or a persisted grant that the delete, run
under the settings file's lock, actually removed from that file. A stale, duplicate, cancelled,
skipped, or failed revoke appends nothing; that includes a persisted grant that was still in the
file when `/settings` checked but was gone by the time the delete held the lock, which is reported
as skipped. The two limits below bound the windows in which a qualifying revoke still leaves no
record. A grant that disappeared some other way — a hand edit, another tool, another process — is
never recorded here. Without the event, a settings file that no longer holds a grant looks the same
however the grant left.

Its fields are the **removed grant's own stored identity**, not the request that once created the
grant: `kind` (the stored entry's matching mode — `direct`, `literal`, or `tool`), `subject`,
`grant_kind`, either `path_scope` or `host_scope`, and `argument_hash` for a literal grant. That is
exactly the permission entry's on-disk shape, and validation enforces that shape rather than merely
describing it: a pairing no stored entry could hold — a reserved capability subject such as
`write_tree` under any `kind` but `tool`, a network subject carrying a path scope, a literal whose
`argument_hash` is not the SHA-256 of its own subject — is refused both on append and on load, so a
record that survives matches the stored grant field for field and cannot name one that could never
have existed. The stored subject is copied verbatim and is never hashed or shortened — redacting it
would destroy the correlation the record exists for. It equals `permission_decision.grant_subject` when
that field is present; an older granted decision that lacks it leaves only the link back to *that
decision* unknown, never the link to the grant. `permission_matched` records the concrete request
subject rather than the stored one, so it cannot identify a widened direct grant such as `git :*`
and is not a correlation source for one.

Two limits are deliberate:

- **Not every successful revoke has a record.** Settings and session are separate files with no
  cross-file transaction. Once the settings delete succeeds the live grant is dropped immediately,
  before the event is recorded, because a revoked grant that keeps authorizing is the worse failure.
  A process that exits in that window leaves a real revoke with no event.
- **A recorded revoke may not be durable yet.** The record is appended and then flushed. If that
  flush fails the way ordinary session writes can, the existing `session_write_failed` protocol
  reports it and the one appended record stays in memory for the next flush boundary — never
  duplicated, never rolled back.

So the event is usable evidence that a revoke was deliberate, and is **not** authoritative
provenance: its absence is not evidence that a grant was removed illegitimately.

Record framing lives in `internal/sessions/schema.go`: `Marshal` shows the metadata-first
layout, and `Message` / `Event` / `Compaction` are the three record shapes (see below). The
`Record` interface and its unexported `isRecord()` method are the authoritative closed set — a
type that does not implement `isRecord()` cannot be a record.

## Where session files live

```
~/.codemeld/sessions/<folder-dir>/<session-id>.json
```

One folder-dir per launch directory (`<sha256-prefix>-<sanitized-basename>`). Each file is
JSONL — **one JSON object per line**:

- **Line 1** is the metadata record: `{"type":"metadata","metadata":{…}}`. It is **not** a
  `Record` — `Session.Records[0]` is the first *later* line, not the metadata.
- **Every later line** is one record of three shapes: a **message** (`"type":"message"`), an
  **event** (`"type":"event"` with a `kind` and a `payload`), or a **compaction**
  (`"type":"compaction"`). Not every line is an event.

A **compaction** record is the durable summary that lets `/compact` start a linked child without
copying the parent's messages. It is valid **only as `Records[0]` of a linked child**: the child's
`metadata.forked_from {session_id, record_id}` names the source, and the compaction's `parent_id`
(stamped on record zero) must equal `forked_from.record_id` — the *only* source provenance. Its
`summary` is the model-facing continuation text; its `provider` and `model_id` are audit metadata
naming which model generated the summary and are **not** source provenance. A completed child may
carry later records (e.g. a `launch_began` event), but a second compaction anywhere is rejected by
position. Because the discriminator is new, older predeployment builds **reject** a compacted child
(they do not know the `compaction` type); existing message/event v1 files stay readable and the
`schema_version` stays `1`.

### What a shipped `/compact` leaves on disk

Two files, in a fixed order.

The **child** is summary-only. Its whole record stream is the compaction record at `Records[0]`
plus its own `launch_began` (`source: fork`) — none of the parent's messages are copied, which is
what distinguishes it from `/fork`'s full-continuation child. Its title is the parent's stored
title with ` (compacted)` appended, or `Compacted session` when the parent has no title. Its
`forked_from.record_id` is the id of the parent's **last record** — whatever its type, message or
event — at the moment the child is created, after the summary came back — not the compact success
record, which is written afterwards as part of the parent's terminal batch. The child is written and owned before the parent
is touched.

The **parent**'s durable stream then ends with exactly two records, committed atomically together:
the `slash_command` record for `compact` with `outcome: "success"`, immediately followed by the
`session_forked` marker whose `to_session_id` names that child. The parent is sealed in-process
afterwards; its file stays on disk and stays resumable. Reading the parent back is the check that
matters — a compact success record with no `session_forked` after it, or in the other order, means
the ordering contract broke.

A failed compaction writes a `slash_command` record with `outcome: "error"` and an `error_detail`
onto the still-open parent, and **no** `session_forked`. The parent stays active and appendable. A
failure after the child was already published leaves that child on disk as a complete, unlocked,
resumable session; nothing scans for or activates it.

## Tracing a stuck child process back to its session

A shell command codemeld launched can hang. From another terminal you see the stuck process in
`ps` but not which session started it, and sorting the flat UUIDv7 filenames in
`~/.codemeld/sessions/<folder-dir>/` by mtime is ambiguous as soon as two sessions are open. The
procedure below runs from a cold start — a bare pid and nothing else — and ends at the session
file.

The evidence it relies on is the **live process argv**, read while the command is still running.
That is the authoritative record of what is hanging. A durable `tool_exec_start` in the session
file is optional corroboration only (last step); do not go looking for one first, and do not treat
its absence as evidence against what you read off the live process.

**1. Find the stuck process.** Any pid of the hung command will do — `ps`, `top`, or `pgrep`.

**2. Walk up the ancestor chain to the codemeld process, recording argv on the way.** Do not take
a single parent. codemeld runs direct commands and recognized bare compounds as argv, so a stuck
direct child can sit immediately under codemeld; it runs literal commands (redirection, wrapper
forms) through `sh -c`, so there the immediate child of codemeld is that shell and the stuck
program is below it. A pipeline program or any other intermediary can add further levels. Print the
whole chain and find the codemeld process in it:

```sh
pid=<stuck-pid>
while [ -n "$pid" ] && [ "$pid" != 1 ]; do
  ps -ww -o pid=,ppid=,comm=,args= -p "$pid" || break
  pid=$(ps -o ppid= -p "$pid" | tr -d ' ')
done
```

`-ww` is not optional: without it `ps` truncates `args` to the terminal width, and the arguments
that identify the hang are exactly the ones at the end that get cut. If in doubt that a line is
complete, read the argv from the kernel directly — `tr '\0' ' ' < /proc/<pid>/cmdline` on Linux,
`procstat -c <pid>` on FreeBSD — both of which never truncate. Keep the full argv of the stuck
process: this is the command evidence.

If the walk reaches pid 1 without passing a codemeld process, this process was not started by
codemeld (or its codemeld parent already exited) and there is no session to find. A dev build may
be installed under a different binary name; match on the `args` path rather than `comm` alone.

**3. List the codemeld process's open files.** Every active session holds its own
`<session-file>.json.lock` sidecar, and the lock keeps that descriptor open for as long
as the session is active, so the path is visible in the process's open-file table.

| Platform | Command | Availability |
|---|---|---|
| Linux | `ls -l /proc/<pid>/fd` | base |
| Linux, macOS | `lsof -p <pid>` | base on macOS; usually a package on Linux |
| FreeBSD | `procstat -f <pid>` | base — `/proc` is **not** mounted by default, so `/proc/<pid>/fd` does not work |

`/proc/<pid>/fd` is Linux-specific; it is not the portable lookup. On FreeBSD without `procstat`,
the older base equivalent is `fstat -p <pid>`.

**4. Strip `.lock` to get the session file.** The open path ends in `.lock`
(`sessions.ResumeLockPath` appends exactly that suffix); removing it gives
`~/.codemeld/sessions/<folder-dir>/<session-id>.json`, and the filename is that session's id. If
the codemeld process has no `.lock` descriptor open, the lookup is unavailable for that process —
it does not mean some other session matched. Going the other way is not valid either: a session
file on disk, or a `.lock` sidecar with no process holding it, says nothing about a live process.

This works identically for every kind of active session — fresh, resumed, a `/clear` target, and
the linked children `/fork` and `/compact` create — because each of them acquires and holds its
own sidecar. During a switch the two locks briefly overlap; at steady state exactly one is held.

**5. Optionally corroborate from the session file.** A `tool_exec_start` whose `invocation_id` has
no matching `tool_exec_end` means that invocation had not returned as of the file's last flush:

```sh
jq -r 'select(.type=="event" and (.kind=="tool_exec_start" or .kind=="tool_exec_end"))
       | .payload.invocation_id' <session-file> \
  | sort | uniq -u
```

Treat a hit as corroboration and nothing more, and treat a miss as inconclusive. The runner appends
`tool_exec_start` before invoking the command and `tool_exec_end` after it returns, but neither
append flushes: the turn's flush happens *before* dispatch, and a command that never returns never
reaches the next one. So a genuinely hung command routinely leaves **no** start record on disk. The
live argv from step 2 stands on its own.

**One limit: NFS.** The lock uses `flock(2)`, whose behavior over NFS is weak and differs by
platform (a limit inherited here rather than introduced). On an NFS home directory the
descriptor is still visible and still names the `.lock` path this process opened, so steps 3 and 4
still identify *this* process's session. What you cannot conclude there is exclusivity — that no
other process is also holding or appending to that session.

## Turn lifecycle records: telling finished work from interrupted work

Every provider round a turn makes ends with a `turn_terminal` (how it ended), and a round that got
far enough to time its provider call also writes a `provider_round_trip` (how long the round took).
They are correlated by the same `turn_id` / `round_id` pair, so the two records describe one round,
and an agentic turn whose three provider calls all completed has three pairs. Read `internal/events/payloads.go` and `internal/events/turnterminal.go` for the
exact fields and the closed set of outcomes — as everywhere else in this guide, the code is the
schema, not this page.

What the outcome means for reading a session:

- **`completed`** — the round produced its answer or its tool handoff. Nothing to look at.
- **`cancelled`** — the user stopped it (ESC). Also not a failure: it is the interrupt working.
- **Anything else** — the round ended badly, and the outcome names the stage it died at. A
  `provider_failed` round additionally carries the phase the provider call failed in.

A `turn_terminal` with no `provider_round_trip` beside it is normal: some rounds fail before
there is anything to time (a refused credential, a cancel before dispatch). The reverse is the
signal worth chasing — a round that recorded its timing and then never recorded how it ended.

`codemeld sessions doctor <id|path>` derives both from the file for you. It reports a
non-`completed`, non-`cancelled` `turn_terminal` as an error, and reports a correlated
`provider_round_trip` that no `turn_terminal` ever closed as an error with
`reason=incomplete_round`. Each finding carries its `turn_id`, `round_id`, `outcome`, and — where
the outcome has one — its `failure_phase`, so you can find the round in the file. It never
carries response text or tool arguments; use `sessions show` when you need the content.

A failed tool call is reported under the same promise. `doctor` names its `subject_kind`,
`invocation_id`, `duration_ms`, and `exit_code`, and identifies the tool as `failed_tool` by
program name only: the executable for a `direct` run, the tool name for a structured or `vcs_*`
run, and nothing at all for an `sh -c` literal, whose script has no safe name to derive (its first
word can be an assignment such as `TOKEN=…`, a builtin, or punctuation) — there, `subject_kind`
plus `invocation_id` is the identity. The recorded command's arguments and the captured stdout and
stderr appear in neither the human report nor `--json`; `sessions show` remains the place for the
full command and any captured output.

Two absences are deliberately **not** findings. A `provider_round_trip` with no `turn_id` /
`round_id` at all was written before those fields existed: it says nothing either way about
completion, so it is left alone. And a request that is still running has not written its round
trip yet, so a live session in the middle of a turn reports clean rather than accusing the turn
the user is still waiting on.

**When codemeld cuts a stream itself: `stream_no_output`.** A round whose stream sends no
assistant text and no tool call for 30 minutes is cancelled by codemeld, not by the provider. Its
`turn_terminal` is `provider_failed` with phase `stream_drop`. When a retry follows,
`provider_request_retry` carries reason `stream_no_output`; when none follows (retry off, or
attempts or budget used up), `provider_request_retry_skipped` and `provider_request_failed` carry
it, the failure with `partial_response_chars` 0 and an `error_detail` saying codemeld cancelled the
stream. So under `stream_drop`, `stream_no_output` is a local cut before any usable output, while
`stream_eof` and `stream_read_error` are transport failures, which can follow partial output.

The 30 minutes start once the provider has returned the stream, so time spent opening the request
does not count (`provider_round_trip.duration_ms` still covers the whole round). Reasoning text,
empty chunks, and usage-only chunks are not output and do not restart the clock; the first
non-empty assistant text or tool call turns the limit off for the rest of the round. Each retry
starts a fresh 30 minutes, and the retry budget is checked only between attempts, so it never
shortens an attempt that is still streaming. A user cancel or run time limit that lands first is
recorded as `cancelled`, not as `stream_no_output`.

`provider_round_trip` also counts what a streaming round received: `chunks` is every stream chunk
the round read, including empty and usage-only ones and one read while the round was being cut,
and `reasoning_chars` is the Unicode character count of the OpenRouter `reasoning` text captured in
the round. `reasoning_chars` does not count `reasoning_details`, and only OpenRouter rounds fill it.
The OpenAI ChatGPT adapter drops reasoning events before they reach the round, so even `chunks` 0
and `reasoning_chars` 0 do not prove the provider sent nothing. Both are left out of the record
when 0, and older records never have them, so a missing counter means 0 or not measured.

**Nothing here is replayed.** The lifecycle records exist to make an interrupted turn *visible*,
not to resume it. `doctor` is read-only — it never writes, repairs, re-sends, or re-runs anything
it reports, and no other code path replays a recorded round. Recovering from an incomplete turn is
the user's decision: read the diagnosis, then re-ask. The same boundary holds live in the TUI,
where a provider that goes quiet for a long stretch is only *reported* as quiet — the request is
not cancelled or retried on the user's behalf unless it reaches the `stream_no_output` limit above.

## Protected-settings halt records: format and inspection

The session schema defines a `security_state_halted` record, and a `turn_terminal` outcome
`security_halted`, for a check that would compare the protected settings files a launch admitted
with what is on disk. This release does not start that security-state monitor. It does not watch
settings files for drift, does not record or report settings drift of any kind — including changes
to `blocked_paths` or `writable_folders` — and does not halt a launch or a turn on such drift, so a
session it writes contains neither record. This section documents the record format, so that a
session file that does carry one can be read, and how `sessions doctor` reports it.

This is separate from the `blocked_paths` list itself, which is re-read from the settings files
whenever a path is checked against it, so an edit to that list takes effect in a running session.
That re-read is not drift reporting and writes no session record.

**Fields.** A `security_state_halted` record names one settings file in `path` (an absolute path)
and the point the check ran in `detection_point`: `startup`, `before_mutating_call`, or
`before_final_success`. Its other fields are either `sections` and `labels`, or
`unavailable_reason` alone. Read `internal/events/payloads.go` and `internal/events/turnterminal.go`
for the exact fields and validation; the code is the schema, not this page.

**Ordering and pairing.** The records of one check are one `security_state_halted` per affected
settings file, all with the same `detection_point`. For an in-turn detection point they are
followed by exactly one `turn_terminal` with outcome `security_halted` that closes the round, and the records
and the terminal are committed together. A `startup` record stands **alone**: no provider round
exists before the first prompt, so there is no `turn_terminal` to pair it with, and none is invented
— a synthetic one would name a round that never happened.

How to read one record:

- **It names sections** (`permissions`, `provider_credential`, …) — the file was read and
  compared, and those protected areas differ from what the launch admitted. The change labels
  say how (`added` / `removed` / `changed`).
- **It carries one of `malformed`, `unreadable`, or `missing` and no sections** — the file could
  not be compared at all: it no longer parses under the rules the launch applied, it could not be
  read, or it is gone. There is nothing to name, so nothing is named.
- **It carries an `unavailable_reason` and nothing else** — the file could not even be inspected,
  because its lock could not be taken (`lock_timeout` or `lock_acquire_error`). This is not the
  same as reading it and finding it unreadable.

The record is metadata only. It never holds settings contents, a parse error, a raw filesystem
error, a permission argument, a key, a token, or an account identifier. It does **not** claim
anyone revoked anything: it reports that the protected state is no longer confirmed, which is a
different statement.

`codemeld sessions doctor <id|path>` reports every `security_state_halted` record and every
`security_halted` turn as an error, naming the file and the detection point. A startup record is
reported on its own and never as an unclosed round.

## Inspect a live session

A whole session is far more than you want to read — a long run is tens of thousands of lines — so
narrow it before you read it. Pull the records of one kind to see its exact payload fields on a
real session rather than a documented snapshot:

```sh
codemeld sessions show <session-id|path> --kind tool_exec_end
```

`--kind` is repeatable and unions its values, so one command can put a tool call next to the
permission decision that let it run:

```sh
codemeld sessions show <session-id|path> \
  --kind permission_decision --kind tool_exec_start --kind tool_exec_end
```

`doctor` names the turn that went wrong; `--turn` then prints that turn and nothing else — its
opening user message, its messages, its tool activity, every round it made, and the run of
`provider_request_failed` / `provider_request_retry` / `provider_request_retry_skipped` records
written *after* the last of those (the turn records its `turn_terminal` before it commits the
failure naming the HTTP, dial, TLS, decode, stream-drop or empty-response cause) — even though only
the lifecycle records carry the turn id. That trailing set is closed, so a `/model` or any other
command run between turns is not swept into the turn before it. A `turn_terminal` closes one round
rather than the turn, so a
round `doctor` reports as `incomplete_round` — it wrote its `provider_round_trip` and died before
its terminal — stays inside the range even when an earlier round of the same turn did close:

```sh
codemeld sessions doctor <session-id|path>
codemeld sessions show <session-id|path> --turn <turn-id>
```

`--last <n>` keeps the final n records after the other filters, which is the quickest way to see
how a run ended:

```sh
codemeld sessions show <session-id|path> --kind tool_exec_end --last 5
```

To see which kinds a session actually contains, count the rendered event headers:

```sh
codemeld sessions show <session-id|path> | grep -o 'kind=[a-z_]*' | sort | uniq -c
```

The filters compose in one invocation, a record keeps the number of its position in the whole
session, and whenever a filter is active the header reads `records: <selected> of <total>` — so a
filter that matched nothing is visibly a filter result rather than an empty session, and still
exits 0. An unknown kind, a `--turn` that is not a well-formed turn id, and a `--last` below 1 are
usage errors (exit 2) rather than silent empty selections; the unknown-kind message lists the kinds
the command accepts.

Add `--json` for the same selection machine-readably, with tool-call arguments unescaped into JSON
values — an argument that is not valid JSON is carried raw under an `invalid_json_arguments` flag
rather than failing the command:

```sh
codemeld sessions show <session-id|path> --kind model_response --last 1 --json
```

`codemeld sessions doctor <id|path>` reports anomalies and incomplete turns (above),
`codemeld sessions permissions <id|path>` lists the permission prompts a human was actually
shown — in record order, each with its decision or `pending` — followed by a count of the
authorizations that never prompted (`permission_matched`) grouped by `outcome_source`, then a
separate block of [System One checks](system-one.md) (`permission_system_one_check`), and then the
explicit revocation requests (`permission_revoke_requested`), and
`codemeld sessions research <id|path>` reports the web-research funnel (below), and
`codemeld sessions summary <id|path>` aggregates the durable execution records, the permission path
scopes they ran under, the turn, round, and token totals, and the provider-reported cost (below). These are
diagnostics, not the schema source — `internal/events/payloads.go` remains authoritative, and
every line of the file is ordinary JSON if you would rather read it with a JSON tool.

`sessions permissions` reads the distinctions above off the records for you, and `--json` emits the
same facts as one machine-readable document:

- **What the approval stored.** A granted row says `grant=allow_once` when the decision carried no
  grant fields, and otherwise names the stored grant kind (`session` / `folder` / `global` for a
  path subject, `session` / `project` for a host subject), the folder or host it was stored at, and
  the stored subject — which may be wider than the requested one. A global grant is named by its
  kind alone: its recorded scope is the all-paths sentinel, not a folder, and is never printed as a
  path.
- **Whether the prompt broadened an earlier approval.** A prompt is flagged as a scope escalation
  when its own `path_scope` strictly contains a folder an earlier decision in the same session
  already granted *and* that decision's `grant_subject` covers this request under the same rule live
  matching applies — the report calls the matcher rather than re-implementing it. The narrowest
  qualifying earlier grant is named. Host prompts are scoped by host, not by folder, so they never
  escalate.
- **Where the record cannot say.** An absent `grant_subject`, or an absent `direct_tokens` on a
  direct prompt, is unknown legacy data: the row is left unflagged. The report never falls back to
  the requested subject or re-splits the flattened one — a false escalation claim, which reads as an
  accusation about a human's security decision, is worse than a missing one.
- **What the System One check decided.** A command the check allowed is counted once among the
  non-prompted authorizations, under the `system_one_check` source. The System One checks block
  that follows counts every recorded check by outcome (`allowed`, `declined`, `failed`, `skipped`),
  counts the failures by reason (including `no_key`), counts the skipped checks by reason (`paused`,
  or a structural reason when the command could not qualify and no model was asked), and lists each
  allowed command with its model, `p_read_only`, and the `t_read_only` threshold applied, so its
  margin can be reviewed (`renderPermissions`, `internal/cli/sessions.go`). The event's fields,
  validation rules and reason values are in `PermissionSystemOneCheck` and `systemOneReasons` in
  `internal/events/payloads.go`.
- **Which grants a human explicitly revoked.** The report ends with the `permission_revoke_requested`
  records, in record order, each naming the removed grant's own kind, subject, scope, and grant kind
  (and a literal grant's `argument_hash`). It counts them even when there are none, and it reads
  them only from those records: a grant missing from a settings file with no such record produces no
  row, and a session written before the event existed reports zero rather than being back-filled.

The marker is a historical read of one file. It is never a live authorization decision and changes
nothing about what is allowed.

## Web research: what the file can and cannot tell you

A session records the web tool calls the model made, their stored arguments and results, the
answers it then wrote, and the host prompts a human saw. It records **nothing** about whether a
source changed the model's mind — no such field exists, and no honest report can invent one.

`codemeld sessions research <id|path>` therefore reports the *objective funnel* only, in record
order, with `--json` emitting the same facts as one document. Each address it lists carries labels
drawn from a closed set, and every label is backed by a record:

- **`candidate`** — a `web_search` result listed that address.
- **`selected`** — a later `web_fetch` call asked for that exact address. Selection is a
  comparison of two persisted calls, never an inference about why the model chose one. Only a
  candidate-first search source can earn it: a legacy auto-fetched source was already read when the
  search ran, so a later fetch of the same address is a second retrieval, not a selection.
- **`retrieved`** / **`failed`** — the fetch result recorded `outcome: "ok"`, or one of the bounded
  failure outcomes the fetch contract emits (`request_failed`, `response_too_large`,
  `unsupported_content`, `extraction_failed`). Any other string is reported as unclassified
  evidence with no label, because the record does not establish that the fetch failed.
- **`cited`** — that exact address appears in the text of a **later visible assistant answer**. A
  message carrying tool calls is the model asking for work rather than answering, and a tool
  result is fetched content rather than the model's own words, so neither counts. Neither does a
  partial address, a longer address that merely begins with the recorded one (an extra path
  segment, query, or fragment makes it a different address), an occurrence *inside* another
  address (a proxy, archive, or redirect link carrying the recorded one in its own path or
  query), nor an answer written *before* the address was recorded.

A redirect leaves two persisted addresses on one source — the requested `url` and the recorded
`final_url` — and the answer repeated one of them, not both. The report names the exact address it
matched (`cited=` in the human output, a `cited` list in `--json`) and counts that address, so the
requested address is never reported as cited on the strength of its redirect destination, and two
destinations of one requested address stay two cited addresses.

**An address with no `cited` label is not "unused."** It only means no later visible answer
repeated that exact string — the model may have read it, relied on it, and paraphrased it. The
report never labels a source unused, and neither should a reader of the report.

Two shapes are reported, because the tool contract changed and old files are not converted. The
current shape is candidate-first: `web_search` returns a `candidates` list of metadata only, and
each source is read by its own later `web_fetch`. The older shape returned a `sources` bundle the
search had **already** fetched, with a per-source `outcome`; those are reported as **legacy
auto-fetches** and counted separately, so an existing session stays analyzable and is never
misreported as a series of explicit selections.

Totals separate what is easy to conflate: queries and candidate addresses are counted both in
total and unique (so a repeat is visible), explicit fetch outcomes are kept apart from legacy
auto-fetch outcomes, and web host prompts are counted both as prompts shown and as distinct hosts.
Only a `permission_prompt_shown` whose subject is `web_search` or `web_fetch` counts — a
`permission_matched` authorized nobody's attention, and a prompt for any other subject is not web
research.

Tool arguments and results are opaque stored text: schema-valid but not necessarily readable JSON.
One that cannot be read is reported as **unclassified evidence** on that call rather than guessed
at, and never fails the command. A single field outside the contract is enough: a negative
`omitted` count, a legacy source with no `outcome`, or a `final_url` that is not a string marks the
call's result unclassified, while the facts that *are* readable (the address, a valid outcome) stay
visible. A **present JSON `null`** is one of those malformed values, never an absent field: `null`
decodes into a Go string or number without complaint, so `"omitted": null` is not a confirmed zero
and a `null` `final_url` — explicit or legacy — is not a source that never redirected. A **present
blank string** reads the same way: no stored address, outcome, or tool name has an empty or
whitespace-only value in range, so a `final_url` of `""` or `"   "` — explicit or legacy — is a
malformed value, not an absent redirect. A candidate address is held to the contract the search
producer writes: only a complete canonical HTTPS address `web_fetch` would admit, in exactly the
spelling it was stored in, is a candidate, so a blank, `http://`, or differently-spelled
`candidates[].url` is out of range too. The producer's own limits are part of that contract: a
search stores at most five candidates and bounds every stored field, so a sixth entry or a
`candidates[].url` past 2048 bytes is not a candidate at all, while an over-long `title`,
`snippet`, or `published_date` unclassifies the result and leaves its readable address visible. A
`final_url` is held to the shape a fetch can produce — the address a successful response came back
on, within its own 2048-byte bound — so a final address carried by a failed outcome, or one that is
not an address, is out of range and never enters citation matching. Each is
reported as unclassified result evidence with no value invented in its place. A recognized `web_search` or `web_fetch` call whose stored `arguments` are not the
contract's JSON string never vanishes from the report: its name still identifies it and its
arguments are the unclassified part. A query or address the dispatcher itself would reject —
anything that is only whitespace — is unreadable evidence too, not a query in the totals or an
address in the funnel. On the result side, a `candidates` or `sources` value that is not a real
list (a JSON `null` is not an empty list) and a result carrying **both** shapes' keys are
unclassified as well, since neither is a shape the contract emits and neither establishes a
zero-result search. Fields the report does not display are still part of those contracts: candidate
`title`, `snippet`, and `published_date`, plus current and legacy fetched `content`, must retain
their stored string form. A malformed one marks the result unclassified while an independently
readable address or outcome stays visible. Correlation is by tool-call ID, so if one assistant message repeats an ID
across two calls, that single stored response is evidence for neither: both calls are reported with
unclassified result evidence rather than each claiming the same outcome. An invalid *record*, by
contrast, still fails in the loader
exactly as it does for the other diagnostics. The report is read-only: it writes no rating,
annotation, or derived event back into the file. It prints the stored queries and addresses
verbatim (answer text is read for the citation check but not echoed), so treat its output as
carrying session content.

## Run summary: what the totals do and do not count

`codemeld sessions summary <id|path>` aggregates records the session already stores — it adds no
new event and derives no number the file does not support. `--json` emits the same facts as one
machine-readable document, with the resolved path under `session`. Six limits decide how to read
it.

**It is an execution-record summary, not a table of every tool call.** The file keeps two distinct
durable lifecycles, and the report keeps them apart:

- `tool_exec_start` / `tool_exec_end` cover shell and VCS execution and end in an **exit code**, so
  those rows count invocations, non-zero-exit failures, and total duration per
  `subject_kind`/`subject`.
- `structured_read_start` / `structured_read_end` cover the six allowlisted read tools (`read`,
  `glob`, `grep`, `list`, `tree`, `file_count`) and end in a **closed outcome** instead, so those
  rows count invocations, non-success outcomes, the outcome breakdown, and total duration per tool.
  A failed read is a non-success *outcome*, never an exit code.

Every other structured tool call records no durable start/end pair at all. It is absent from both
tables rather than counted as zero, because the file has no duration or result to attribute to it.
A tool missing from the report is therefore not evidence that it never ran.

**The path-scope table lists permission scopes, not edited files.** A session does **not** record
which files were changed. `path_scope` on either start record is the *authorization* scope, and for
a tool subject it is a directory (`/proj/internal/cli`), never a file. The exact path lives only
inside the tool call's stored `arguments` string, which would need a per-tool argument schema to
decode and would break silently the moment a tool's arguments change — so the report does not decode
it, and neither should you read the table as a list of edits. It says *these scopes were
authorized*, and nothing more.

**A scope's start count can exceed the matching execution count.** The scope table counts
`*_start` records and the execution tables count `*_end` records. A start is written before the
call runs, so a process that stopped mid-call leaves a start with no end: the call shows up in the
scope table and in neither execution table. A larger start total is normal evidence of that, not a
miscount.

**Terminated is not the same as successful, and legacy rounds count for less.** Turns are the union
of the non-empty `turn_id` values on `provider_round_trip` and `turn_terminal`. A round is counted
only from a `provider_round_trip` carrying **both** a `turn_id` and a `round_id`. A counted round a
`turn_terminal` closed is **terminated** whatever that outcome was — a `cancelled` or
`provider_failed` round is terminated too — so the terminated count is closure, not success; use
`sessions doctor` for the outcomes. A counted round with no matching terminal is **incomplete**, the
same rounds `doctor` reports as `reason=incomplete_round`. A legacy round trip carrying neither id
is counted in neither bucket and contributes only its duration and its provider/model pair.
Provider/model pairs are the de-duplicated union of `provider_round_trip` and `model_response`, so a
session recorded before round trips existed still shows what it ran on.

**Cached tokens and cost are reported as availability, not as bare numbers.** Input and output tokens are
plain sums of `model_response`. Cached input tokens are not: an absent `cached_input_tokens` means
the provider did not report the value, and `cached_input_tokens_partial` marks a present value as a
known lower bound. So the report shows an **exact** total only when every contributing response
reported a non-partial value (a reported zero counts as reported), a **lower bound** (`>= n`) as
soon as any response omitted it or marked it partial, and **unavailable** when no response reported
it at all. This is the same accounting `/context` uses live.

Provider-reported cost follows the same rules, from `cost_usd` and `cost_usd_partial` on each
`model_response`. An absent `cost_usd` means the provider sent no cost for that turn (only
OpenRouter among the built-in providers is known to send one); a reported zero is a real zero and
counts as reported; `cost_usd_partial` means the turn spanned several provider rounds and at least
one of them carried no cost, so its value is a lower bound. The cost is assumed to be USD, following
OpenRouter's convention: a custom provider's `usage.cost` is recorded and summed the same way, and
its currency is neither checked nor converted. **Exact** means every recorded `model_response`
reported a complete, non-partial cost — not that the total matches the provider's bill. A request
that recorded no cost can still be charged: an interrupted or failed attempt with no final usage,
or a child agent's turns, which run on an in-memory session and are never recorded in this file. A
failed tool turn can still record the cost of its completed rounds, so a failed turn does not
always lack cost. Costs are stored and summed as float64, so the total carries ordinary
floating-point rounding and is not exact to the credit; the text report prints the shortest
decimal that round-trips the stored value.

**Permission-prompt wait is the recorded wait coverage, not a sum and not a count of questions.**
The `approval_*` totals come from `permission_prompt_wait` records (`buildSummaryReport` in
`internal/cli/sessions_summary.go`). Each record is turned into the interval
`timestamp − waited_ms` to `timestamp`, using the record's millisecond timestamp, and
`approval_wait_ms` is the length of the **union** of those intervals: prompt calls that waited at
the same time are counted once, so the total is never the plain sum of `waited_ms`. The record
timestamp is taken when the record is appended after the prompt returned, not at the exact moment it
returned, so this is the coverage of the recorded intervals, not a more precise measurement of real
waiting. `approval_requests` sums each record's `prompts`: the requests submitted to a prompt call,
not the questions or screens shown — one question can cover several requests, and a cancelled call
can end before all its questions were displayed. `approval_waits_cancelled` counts records with
`ended: cancelled`. A `failed` wait counts toward the duration and request totals and has no
counter of its own, so a wait that was not cancelled was not necessarily answered. The text report
prints `permission-prompt wait: <ms> ms across <requests> requests (<cancelled> waits cancelled)`
whenever at least one wait record exists, even one that waited 0 ms.

With no wait records all three totals are `0` and the text report omits that line. Zero then means
no wait was *recorded*, not that no waiting happened: sessions written before wait records existed
carry none, a session can span older and newer versions, and a prompt call interrupted before its
record was saved contributes nothing, so even a nonzero total covers only recorded waits. The three
totals cannot tell a run that never waited from one whose waits went unrecorded. To check, read the
underlying records with `sessions show`: `permission_prompt_shown` records with no
`permission_prompt_wait` records mean the timing is missing, not a wait that can be reconstructed.

A session with no execution records, no rounds, or no model responses reports zeroes and exits 0.
Like the other diagnostics, `summary` is read-only and prints stored subjects and path scopes
verbatim, so treat its output as carrying session content.

## Skill loads: what a `skill_loaded` record proves

A `skill_loaded` record says that a skill's instructions, or one file from its folder, went to
the model. `codemeld sessions show --kind skill_loaded <id|path>` lists only these records. A skill
reaches the model in two ways, and `via` tells them apart:

- **`slash`**: the user typed `/<skill>` in the TUI. The record is appended only once the message
  was actually submitted, before that command's `slash_command` record, and both are saved by one
  write. A command that sent nothing (an empty message, or a submission that was not accepted)
  records no load.
- **`tool`**: the model called the `skill` tool. Each successful read appends one record: a read of
  the instructions, or a read of one file in the skill folder. A read that was refused or failed
  (an unknown skill, bad arguments, automatic loading turned off, a blocked or missing file, a file
  over the size limit) records nothing. The record goes to the session of the turn that made the
  call, so a load in a turn started after `/clear` or `/resume` lands in the new session; if the
  session was switched while that turn was still running, the closed session drops the record. It
  is saved with the session's next write.

**What is hashed.** `bytes` and `sha256` describe exactly what was loaded, never the skill text
itself: the record holds the skill's name, its `layer` (`global` or `project`), a file path, a size,
and a hash. When `file` is empty the subject is the skill's instructions as codemeld loaded them at
startup: the `SKILL.md` text after its front matter. Both paths hash those same bytes, so a slash
load and a tool load of the same skill carry the same hash. The tool's answer also contains the
skill folder and a list of its other files, but neither is hashed, and an instructions read still
records its load when that list is unavailable. A slash load hashes the instructions before the
command's arguments are filled in. When `file` is set, the subject is the file's full contents as
read.

**The file path.** `file` is relative to the skill folder, uses `/` separators, and is written in
its clean form: the tool accepts `./scripts//run.sh` and records `scripts/run.sh`. A slash load
never carries a file.

**Who loaded it.** A tool load made by a child agent carries that child's `child_invocation_id`; a
load by the main agent carries none. A slash load is always the user's and never carries one.

**What the record does not say.** It does not name the folder the skill was read from. When a skill
folder, or the skills folder above it, is a symbolic link, the record cannot tell you where that
link pointed at the time, and the disk today cannot either: the link may have been changed since.
Compare `sha256` with the content you expect rather than with whatever the path holds now.

**When the record cannot be saved.** The two paths fail differently, on purpose:

- **`slash`**: the message has already been sent, so it stays sent. The TUI shows a notice that the
  skill load record could not be saved.
- **`tool`**: if the record is rejected, the tool call fails with an error and the model does not
  get the content, so a load never reaches the model without its record. A tool that has no
  session to write to records nothing and still reads.

## Why this doc has no field tables

Enumerating every event and its fields here would duplicate `payloads.go` and drift out of date
the moment a kind or field changes, with nothing to flag the staleness. The code and a live
session are always correct, so this guide points at them rather than snapshotting them.
