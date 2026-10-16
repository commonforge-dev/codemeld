# Module 2 — Core types & vocabulary

_Snapshot as of 2026-07-21; it may be out of date — refresh it from the code before studying._

> This module is a **vocabulary** module: breadth over depth. Its job is to teach you the central
> nouns so the later subsystem modules have words to use. You'll meet each type again in depth later.

## Goal

After this module you can:

- Name the central types — `Session`/`Record`/`Message`/`Event`, `EventPayload`, the config `Cache`,
  the model `Selection`/`ActiveState`, `Tool`/`Registry`, the UUIDv7 helpers — and say what each holds.
- Explain how a session document is structured and how events relate to it.
- Explain what the config `Cache` is and the one thing it deliberately never does.

## Why it matters

Almost every later module manipulates one of these types. If you know the nouns, the verbs (load,
compose, dispatch, append, persist) are easy.

## Read (in order)

1. `internal/sessions/schema.go` — `Session`, `Metadata`, `Record`, `Message`, `Event`,
   `Compaction`, `Content`, `ContentPart`, `ToolCall`.
2. `internal/events/payloads.go` — `EventPayload` and the per-kind payload structs.
3. `internal/config/cache.go` — `Cache`, `NewCache`.
4. `internal/model/selection.go` and `internal/model/active_state.go` — `Selection`, `ActiveState`,
   `Source`.
5. `internal/tools/registry.go` — `Tool`, `Result`, `Registry`.
6. `internal/ids/uuidv7.go` — `NewV7`, `IsValidV7`.
7. `internal/permissions/entry.go` — `PermissionEntry`.

Each is its own small package under `internal/` — the package and file names above are the index.

## Mental model

### The session document (`sessions/schema.go`)

A **`Session`** = a `Metadata` header + an ordered `[]Record`. A **`Record`** is a *closed* sum type
(interface with an unexported `isRecord()` method) with exactly three implementers:

- **`Message`** — a role-tagged turn: `Role` (user/assistant/system/tool), `Content`, optional
  `ToolCalls` (assistant) or `ToolCallID` (tool result), timestamp.
- **`Event`** — a kind-tagged record: `Kind string` + an **opaque** `Payload json.RawMessage`.
  The session layer does *not* interpret the payload — that's the `events` package's job.
- **`Compaction`** — a `/compact` summary that becomes **`Records[0]` of a linked child** so the
  child need not copy the parent's messages. `Summary` is the model-facing continuation text;
  `Provider`/`ModelID` are audit metadata for which model generated it (**not** source provenance);
  `ParentID` is stamped on record zero and must equal the child's `Metadata.ForkedFrom.RecordID` —
  the only source provenance. Valid only as the first record of a forked child.

The metadata header is **not** a `Record`: `Records[0]` is the first later line, which is where a
compaction must sit when present.

`Content` is "a string **or** a list of parts" (`ContentPart`s preserve unknown provider block types
verbatim via `Raw json.RawMessage`). `ToolCall` likewise preserves its entry as `Raw`.

### Events (`events/payloads.go`)

**`EventPayload`** is another *closed* set (unexported `validate()`), one struct per event
kind (`LaunchBegan`, `PermissionDecision`, `ToolExecStart`/`ToolExecEnd`, `ModelTurn`,
`ModelResponse`, …). Event kinds are **string constants** (`KindLaunchBegan = "launch_began"`, …),
not an enum type; read the `Kind...` constants in `events/payloads.go` for the current list.
`ValidatePayload(kind, raw)` dispatches by kind to validate one.

The write path ties events to the session: `events.Append(store, payload)` canonicalizes the payload,
validates it, mints a `NewV7()` id and a canonical timestamp, builds a `sessions.Event`, and calls
`sessions.Store.Append`. So **events flow into the session through the store.**

### The config Cache (`config/cache.go`)

**`Cache`** is the single, session-lifetime read source for composed config. Built **once** by
`NewCache` (which parses providers and permissions up front); after that **it never re-reads files** —
external edits to the on-disk YAML are deliberately invisible for the run. It exposes defaulted
accessors (`Discovery()`, `AgentMaxConcurrency()`, …) and parsed views (`Providers()`,
`Permissions()`), plus in-memory write-backs (`AppendPermission`, `SetModelActiveRaw`) that are
visible immediately but are **not** persisted (persistence lives elsewhere — Module 4).

### The active model (`model/selection.go`, `active_state.go`)

**`Selection`** = `{Provider, ID, Effort}` (on disk the model field is `id`, never `model`).
**`ActiveState`** is the run's single mutable owner of the active selection; its **zero value is a
meaningful "no model selected" state**. **`Source`** is the `model_turn.source` enum
(project / global_fallback / resume / picker / picker_degraded).

### Tools (`tools/registry.go`)

**`Tool`** = `{Name(); Invoke(ctx, args) (Result, error); SubjectKind()}` (`SubjectKind()` is always
`"tool"`). **`Registry`** is a flat exact-name `map[string]Tool` — no regex, no pattern fallback.
`Register(source, tool)` distinguishes a same-source duplicate (hard error) from a cross-source
replacement (warn + later wins). The structured built-ins are `edit`, `create`, `delete`, `read`, `glob`,
`grep`, `list`, `tree`, plus the `vcs.*` action tools registered only when a VCS is active.
`Registry.List()` returns them in deterministic ascending-name order (not registration order).
`bash` is **not** a registry `Tool`: it has no `Tool` entry, is advertised separately via the
product-authored provider definition, and dispatch special-cases its pinned name to run through the
shell path.

### IDs (`ids/uuidv7.go`)

`NewV7()` mints a canonical lowercase UUIDv7 (and **panics** on a randomness failure rather than
returning an unusable id). `IsValidV7()` is a *strict* check — it rejects uppercase hex that
`uuid.Parse` would otherwise accept.

## Watch for (Go idioms)

- **Closed sum type via an unexported method.** Both `Record` (`isRecord()`, implemented by
  `Message`/`Event`/`Compaction`) and `EventPayload` (`validate()`) keep their implementer set
  closed to the package — outside code can't add a new variant. This is Go's idiom for a sealed
  union, and adding `Compaction` meant giving every closed helper switch
  (`recordParentID`/`withParentID`/`effectiveUpdatedAt`) a matching case.
- **Copy-isolation in the cache.** Every `Cache` getter returns a *copy* (e.g. `slices.Clone`,
  `deepCopyValue`, `copyProviderEntry`) so callers can't mutate the cached view; inputs are copied
  too. Pinned by `TestCacheReturnedValuesCannotMutate` and `TestCacheExternalEditsInvisible`.
- **Reflective canonicalization + presence checks.** `events.canonicalize` walks a payload via
  `reflect` to coerce strings to valid UTF-8 and materialize nil slices as `[]`; `requireShape`
  rejects an absent required field that would otherwise decode to a zero value.
- **Generics for per-kind decode.** `decode[T EventPayload]` is one type-parameterized decoder used
  by each event kind instead of one hand-written decoder per kind.

## Quiz

Closed-book: [`quizzes/module-02.md`](quizzes/module-02.md). Grade against
[`quizzes/module-02-key.md`](quizzes/module-02-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** Does `IsValidV7` accept an *uppercase*-hex UUIDv7 (which the underlying
`uuid.Parse` would accept)? Predict, then read `IsValidV7` in `ids/uuidv7.go` and confirm against
`TestIsValidV7_Rejections` in `ids/uuidv7_test.go`. Why be stricter than the library?

**B. Map the nouns.** Without looking, name which type holds each of: the session's ordered records;
a message's role; an event's opaque payload; a tool's registration source. Then verify in
`sessions/schema.go`, `events/payloads.go`, and `tools/registry.go`.

**C. Trace the write path.** Follow how an event payload becomes a stored record: start at
`events.Append` (`events/append.go`) and find where it calls `sessions.Store.Append`
(`sessions/store.go`). Note the `canonicalize` step in between. Record the `file:function` chain in
[`progress.md`](progress.md).

## Done when

- You can sketch the `Session → Record → {Message | Event | Compaction}` shape from memory, and
  say why a compaction is valid only as `Records[0]` of a linked child.
- You can state what the `Cache` does and the one thing it never does after construction.
- Your hands-on A prediction matched the code.
