# Module 13 — Read-only navigation & inspection tools

_Snapshot as of 2026-08-24; it may be out of date — refresh it from the code before studying._

> Prerequisite: Module 6 (tool dispatch & the runner) explains how a tool call reaches a tool;
> Module 5 (permissions) explains the read-only auto-allow posture these tools lean on. Both
> make this module easier, but you can read it standalone.

## Goal

After this module you can:

- Name the **six** read-only tools, what shell command each replaces, and why an **in-project**
  call never prompts in *any* mode — while an explicit **out-of-project** target now prompts
  instead of being silently rejected.
- Explain how a `read`/`grep`/`glob`/`list`/`tree`/`file_count` call is **confined to the project
  root** by default, fail-closed, where the shared resolver enforces it, and the one promptable
  exception for an explicit external target.
- Describe what the **shared walker** does for the recursive tools — hidden filtering, the
  no-follow-directory-symlink rule, ordered traversal, and the ignore-filter seam.
- Explain the **ignore story**: why codemeld ships its own `codemeldignore` file instead of
  parsing `.gitignore`/`.hgignore`, and what that supersedes.
- Say how output stays **bounded** and how the truncation indicator survives the byte cap.
- State the **exact-name dispatch invariant** and how these six tools satisfy it.
- Say why these same six names are the **only** calls production ever runs concurrently, what
  excludes a call, how an excluded call orders the calls around it, and what durable evidence
  every overlapped read leaves behind.

## Why it matters

Investigation is the agent's most common activity, and before these tools existed it rode on
raw shell (`cat`, `rg`, `find`, `tree`). That meant a permission prompt on first use of each,
and it meant the dangerous binaries `find` (has `-delete`, `-exec`) and `tree` (writes with
`-o`) could never be added to the read-only shell allowlist. The six structured tools give the
model first-class, project-root-scoped equivalents that auto-allow everywhere — so locating code
before an edit is never interrupted, and no mutating-capable binary has to be trusted. This is
the subsystem that makes "the agent can find, read, and search project files in any mode with
zero prompts" true.

## Read (in order)

1. `docs/architecture.md` → "Tool dispatch is exact-name" and "Permission system is the front
   door" (the two invariants these tools plug into).
2. The code, in dependency order — each file's top comment explains its role:
   - `internal/tools/registry.go` — `Tool`, `Metadata`, `Registry`, `Register`, `Lookup`. The
     flat exact-name map every tool registers into.
   - `internal/filetools/readresolve.go` — `ResolveReadTarget`, `ResolveReadFile`,
     `IsDirectorySymlink`, `ClassifyEntry`, `EntryKind`. The shared read-target resolver and
     symlink-policy predicates.
   - `internal/filetools/limits.go` — the limit constants, `ValidateNumericArgs`, `OutputMeta`,
     `BoundedResult`. Bounded output + the byte-cap-safe truncation indicator.
   - `internal/filetools/phase1readargs.go` — `ValidatePhase1ReadArgs`,
     `rejectUnknownPhase1ReadArgs`. The one place all six read-tool argument schemas are defined.
   - `internal/filetools/walk.go` — `Walk`, `WalkOptions`, `WalkEntry`, `IgnoreMatcher`,
     `classifyDirEntry`. The shared recursive walker and its ignore seam.
   - `internal/filetools/codemeldignore.go` — `CodemeldignoreMatcher`, `ShouldSkip`,
     `LoadCodemeldignoreMatcher`, `defaultIgnoreMatchers`. The ignore filter.
   - `internal/filetools/read.go` — `ReadTool`, `Advertise`, `paginateLines`, `isBinaryContent`.
   - `internal/filetools/grep.go` — `GrepTool`, `grep`, `searchMatches`, `mergeGrepRanges`.
   - `internal/filetools/glob.go` — `GlobTool`, `glob`, `matchEntries` (uses
     `github.com/bmatcuk/doublestar/v4`).
   - `internal/filetools/list.go` — `ListTool`, `list`.
   - `internal/filetools/tree.go` — `TreeTool`, `tree`.
   - `internal/filetools/filecount.go` — `FileCountTool`, `count`, `aggregateFileCount`,
     `renderFileCount`.
   - `internal/bootstrap/tooldispatch.go` — `toolRegistryFactory.realize`, where all six
     register as built-ins alongside `edit`/`create`.
3. Cross-references: the negative-test matrix `internal/filetools/readtools_negative_test.go` and
   walker tests `internal/filetools/walk_test.go` (the tests are the spec — see "Watch for").

> Citations in this module and its answer key use **file + function/symbol name**, never line
> numbers — lines move as the code changes, but a symbol name stays findable with your editor's
> "go to symbol" or a quick search.

## Mental model

### The six tools, and what each replaces

| Tool | Shell equivalent | File | Required arg |
|------|------------------|------|--------------|
| `read`  | `cat`           | `read.go` (`ReadTool`)  | `path` |
| `grep`  | `grep` / `rg`   | `grep.go` (`GrepTool`)  | `pattern` |
| `glob`  | filename glob   | `glob.go` (`GlobTool`)  | `pattern` |
| `list`  | `ls`            | `list.go` (`ListTool`)  | none (defaults to project root) |
| `tree`  | `tree`          | `tree.go` (`TreeTool`)  | none (defaults to project root) |
| `file_count` | `ls \| wc -l` / `find … \| wc -l` | `filecount.go` (`FileCountTool`) | none (defaults to project root) |

Every one implements the `tools.Tool` interface (`registry.go`): `Name()`, `Invoke()`,
`SubjectKind()` (always `"tool"`), `Advertise()`. They register as built-ins in
`toolRegistryFactory.realize` (`tooldispatch.go`) for **every** launch, independent of VCS
detection, right after `edit` and `create`.

### Why in-project reads never prompt — and why an explicit external read prompts

Each tool's `Advertise()` returns `Metadata{ReadOnly: true}`. That single classification is what
the read-only auto-allow keys on: an **in-project** read-only request is **auto-allowed without
prompting in all three modes** — Plan, Build, and Auto edits — evaluated *before* grant match and
the turn cache, recorded as `permission_matched{outcome_source: "mode_auto", outcome: "once"}`
with **no grant created**. `ReadOnly: true` also means each tool is **advertised in Plan**, so the
model can actually call it there. Two consequences worth internalizing:

- In-project investigation never prompts, so there is no per-folder grant to manage for
  searching/reading project files.
- `find` and `tree` need **no shell allowlist entry** — these structured tools cover that
  navigation, and the *executable-name* read-only shell allowlist (`planReadOnlyExecutables`)
  deliberately omits `find`/`tree` because their mutating flags (`find -delete`/`-exec`, `tree -o`)
  can't be ruled out by an executable-name-only check. `find` does, however, have a narrow
  **argument-sensitive** carve-out in `stageTokensReadOnly` (`findStageReadOnly`): a direct `find`
  stage whose every token parses as a safe read-only listing form — one or more relative start paths
  (no absolute, `..`, dash-leading, or `--`) followed only by supported read-only predicates
  (`-type`, `-name`, `-maxdepth`, `-mtime`, `-size`, `-empty`, `-print`, …) — auto-allows, while any
  mutating action, unsupported operator, missing/invalid value, or path escape falls closed to
  mutating. `find` stays out of `planReadOnlyExecutables`; this is an argument parse, not a name match.

**The one exception: an explicit out-of-project read prompts rather than failing closed.**
Earlier, a `read`/`grep`/`glob`/`list`/`tree` call whose target was an explicit absolute or
`~` path outside the project root was *rejected before authorization ran* ("target's parent
directory is outside the project root"), so the user never saw a prompt. Today the resolver
returns that as a concrete external scope (`ExternalReadScope`), dispatch sets
`ModeContext.ExternalRead` (`internal/permissions/orchestrate.go`), and `modePosture` falls
**straight through** for it: it skips both the read-only auto-allow *and* Plan's mutating-deny, so
the request flows on to match → cache → prompt. The user gets a normal permission prompt —
approvable once/session/folder/global — in Build, Auto edits, *and* Plan; an approved folder grant
authorizes read-only access to that external folder for that tool (see Module 5), and a deny is a
genuine user deny. In-project reads are unaffected: their posture is exactly the auto-allow above.
An *implicit* escape (a `../` chain, a symlink out, a directory-symlink root, `~user`) is **not**
an explicit external target — it still fails closed before any read (next section).

### Argument validation lives in one place

None of the six tools defines its own argument rules. Each schema — the closed key set (matching the
advertised `additionalProperties: false`), the required fields, the types, the numeric ranges, the
enum values (`tree.format`, `file_count.group_by`), the list-element rules (`file_count.kinds`,
`include_globs`/`exclude_globs`), the empty-value rules, and the malformed glob/regular-expression
rules — is defined once in `ValidatePhase1ReadArgs` (`phase1readargs.go`), keyed by the tool's
**exact** dispatch name. The allowlist is exactly `read`, `glob`, `grep`, `list`, `tree`, and
`file_count`; every other name — a lookalike, a prefix, `read_image`, a mutating tool — is rejected,
so it can never be treated as validated. Each tool's invoke path calls the validator and then
re-extracts the already-validated values; its `ResolveTarget` calls `rejectUnknownPhase1ReadArgs`,
the key-set half, because value rules stay deferred to invocation.

The schemas are kept **exact**, not normalized to each other: `file_count`'s hidden-file flag is
`include_dotfiles` (so `include_hidden` is an *unknown argument* there, while it is a valid flag on
the other five), and `file_count` alone accepts `kinds`/`group_by`/glob lists.

What the validator is **not**: it is preparation-only and pure. It touches no filesystem, resolves no
target, consults no registry, authorizes nothing, invokes nothing, and enables no concurrency. A
successful validation means only "these arguments are well-formed" — every rejection below still
applies afterwards, and a malformed call is rendered as the same in-band failure result it always was.

### Project-root confinement (the security boundary)

Every path argument flows through `ResolveReadTarget` (`readresolve.go`) **before any read**.
It is the shared boundary for all six tools and it fails closed:

- A relative `path` resolves against the **project root**, not the process cwd, so behavior is
  stable however `codemeld` was launched.
- It expands a leading `~` (rejecting `~user`), contains the parent, anchors the basename, then
  follows a final-component symlink and re-checks the real target with
  `permissions.IsDescendantOrEqual` against the normalized root. An *implicit* escape — anything
  that lands outside the root *through* `..` normalization or *through* a symlink — is rejected
  with a `*TargetError` before a single byte is read. The one thing **not** rejected is an
  **explicit** absolute or `~` target naming a path outside the root: that resolves to an
  external scope and is marked promptable (`ExternalReadScope`) instead of failing closed, so it
  reaches the permission prompt rather than a silent rejection (see "Why … an explicit external
  read prompts" above).
- An omitted/blank `path` defaults to the project root for the directory tools
  (`grep`/`glob`/`list`/`tree`/`file_count`); `read.path` is **required** with no directory default
  (`ReadTargetOptions.RequirePath`).

Symlink policy splits by tool:

- **Recursive tools** (`grep`, `glob`, `tree`, `file_count`) set `RejectDirectorySymlink: true`, so a
  directory-symlink `path` is refused fail-closed — a recursive walk can't be redirected through
  a link. Each also re-`Lstat`s the resolved root immediately before walking (`os.ReadDir`
  follows a symlink root), so a *post-authorization* swap is caught too.
- **`list`** reports a symlink *entry* as type `symlink` and never descends it (a symlinked
  directory `path`, though, is resolved to its real in-root target and listed).
- **`read`** may read a symlink only when its resolved target is a **regular file** inside the
  root — that final check is `ResolveReadFile` (`readresolve.go`), applied at invoke time.

### The shared walker

The recursive tools never walk the filesystem themselves — they call `Walk`
(`walk.go`) with a `WalkOptions`:

```
grep / glob / tree / file_count
   │  WalkOptions{Root, ProjectRoot, Limit, MaxDepth, IncludeHidden, IncludeIgnored, Ignore}
   ▼
Walk  ── os.ReadDir (ascending by name) ──► for each entry:
   │      skip dot-prefixed unless IncludeHidden
   │      classifyDirEntry — lstat-equivalent, never follows a symlink
   │      consult ordered Ignore matchers unless IncludeIgnored
   │      append WalkEntry{RelPath, AbsPath, Kind, Depth}
   └────► descend only a real EntryDir, only under MaxDepth
```

Key properties: traversal is **deterministic** (each directory's children ascending by name,
every directory before its descendants — pre-order), a **directory symlink is reported as a
symlink and never descended** (`classifyDirEntry` classifies by the entry's *own* type), and the
walker owns only the `IgnoreMatcher` **seam** — it implements no ignore syntax itself.
`MaxDepth` does double duty: `1` is single-level (the `list` tool), `0` is unlimited, `N` caps
descent. Each tool tunes the walk:

- `list` walks with `MaxDepth: 1` and `Limit: <per-tool limit>` — only immediate entries count.
- `grep` and `glob` walk **unbounded** (`Limit: 0`, `MaxDepth: 0`) and bound *matches* / *paths*
  afterward — capping the walk could silently drop matches deeper than the cap.
- `tree` passes the tool's `depth` and total-entry `limit` straight through to the walker.
- `file_count` walks **unbounded** (`Limit: 0`, `MaxDepth: 0`) — a count must see every entry — and
  bounds only how many *groups* the breakdown shows, folding the remainder into `other`.

### The ignore story (read this carefully)

codemeld does **not** parse `.gitignore` or `.hgignore`. Carrying two divergent external ignore
dialects inside the filter was rejected as too costly and not ours to control — gitignore has
nested-file composition and negation, while Mercurial's `.hgignore` is regex-by-default with a
`syntax:` directive state machine whose Python/Perl regexp dialect **does not map onto Go's RE2**
(no backreferences/lookaround). So neither native file is parsed in phase 1.

Instead, codemeld owns a single format, `codemeldignore` (`codemeldignore.go`):

- **Locations**: `<project-root>/.codemeld/codemeldignore` and `~/.codemeld/global/codemeldignore`.
  Both optional; a missing file is not an error; their patterns apply as a **union**
  (`LoadCodemeldignoreMatcher`).
- **Syntax**: one `doublestar` glob per line; blank and `#`-comment lines skipped; invalid
  patterns rejected at load via `doublestar.ValidatePattern` (naming file + line). **No
  negation, no `syntax:` directives** — so the two files are an order-independent union.
- **Match semantics**: literal, against the project-root-relative slash-path. A slash-less
  pattern (`node_modules`) matches only at the root; "match a name at any depth" needs an
  explicit leading `**/` (`**/node_modules`). `CodemeldignoreMatcher.ShouldSkip` does the match;
  a matched directory prunes its whole subtree because the walker consults the matcher *before*
  descending.

The matcher plugs into the walker's seam through `defaultIgnoreMatchers`, which every directory
tool calls unless `include_ignored` is set. `include_hidden` and `include_ignored` are
**independent** opt-in flags: hidden disables the dot-entry filter, ignored disables the
`codemeldignore` matcher.

> **Implementation-state note.** The matcher and its wiring (`codemeldignore.go`,
> `defaultIgnoreMatchers`, the per-tool `include_ignored` gates) are present and active. The
> older `walk.go` `IgnoreMatcher` comment still mentions native `.gitignore`/`.hgignore` parsers
> as the seam's future fillers — that text predates the `codemeldignore` decision; the *actual*
> filter registered through the seam today is `CodemeldignoreMatcher`, not a native VCS parser.

### Bounded output and the byte cap

Limits are named constants in `limits.go`: `read` defaults to 2000 lines (max 10000);
`grep`/`glob`/`list`/`tree` default to 250 entries (max 5000), and `file_count`'s `limit` bounds
visible *groups* on the same 250/5000 scale. `ValidateNumericArgs` enforces
`offset >= 1`, `limit` in `[1, Max]`, `context >= 0`, `depth >= 0` — over-max names the maximum,
nothing is silently clamped, every violation is an in-band `*TargetError`.

Truncation is single-sourced. `BoundedResult` (`limits.go`) writes the truncation indicator —
`OutputMeta{Truncated, TruncationReason, RetryHint, NextOffset}` as one compact JSON line —
prefixed with `MetadataPrefix` (`codemeld-tool-meta: `) at the **start of stderr**, never in
stdout. That placement is deliberate: it keeps `read`'s verbatim file content uncorrupted, and
because the global byte cap (`sessions.max_tool_output_bytes`, applied via
`events.TruncateToolOutput`) preserves a *prefix* of each stream, the indicator **survives** even
when stdout is trimmed. `byte_cap` truncation takes precedence over a per-tool `limit` reason.

### Exact-name dispatch

The registry (`registry.go`) is a **flat `map[string]entry`** keyed by `Name()`. `Lookup` is
**exact-name only** — no regex, no shell-equivalence fallback. These six tools satisfy that
invariant simply: each `Name()` returns a fixed built-in string (`read`, `grep`, `glob`, `list`,
`tree`, `file_count`), with no template namespace, registered under `tools.BuiltinSource`. The
shared argument validator is keyed by those same six exact names, so the dispatch allowlist and the
validation allowlist cannot drift apart. A model tool call
named `read` reaches `ReadTool` and nothing else. (See Module 6 for how `DispatchTool` resolves
the target, authorizes, then calls `InvokeWithResolvedTarget` so the authorized path and the
path actually read can't drift.)

### The concurrency boundary (the same six names)

These six tools are also the *only* calls production ever runs at the same time, and the bar is the
individual call. `productionToolDispatcher.Plan` (`internal/bootstrap/tooldispatch.go`) admits a call
when it is one of the six exact names, decodes, passes `ValidatePhase1ReadArgs`, and resolves through
`dispatch.PrepareTool` to a non-empty scope the tool reports as **inside** the project. Only those
planned units are returned without the synthetic `production-tool-dispatch` conflict target, which is
the single thing that lets `agent.Schedule` overlap them — bounded by `agent.max_concurrency`
(1 means sequential) and by nothing else. There is no prose/prefix shortcut.

A call that is shell, VCS, `read_image`, mutating, unknown, malformed, or an explicit external read
keeps the target and becomes a **model-order barrier**. It does not send the response back to the
serial path; it splits it. The barrier waits for the run of eligible reads immediately before it, and
the next run waits for the barrier, so overlap happens within each *contiguous* run of eligible calls
and never across a barrier. `read A, grep B, edit C, read D, glob E` therefore runs `{A, B}`, then
`C`, then `{D, E}`, and an `edit` followed by a `read` is still observed in that order. Because a
barrier can change what a later read's path resolves to, an admitted read resolves its target again
immediately before dispatching and fails closed without dispatching if it no longer qualifies.

Nothing about the classification changes how a call is authorized: an overlapped read still
authorizes on its own, and the shared prompt gate remains the only thing serializing prompts.

Every overlapped read is also recorded, because concurrency you cannot reconstruct afterwards cannot
be reviewed. `dispatchPrepared` appends a `structured_read_start` — one UUIDv7 for the
invocation, the exact tool name, the resolved scope, the configured cap — *before* invoking, and
exactly one `structured_read_end` with the terminal outcome (`success`, `tool_failure`, `denied`,
`cancelled`, `internal_failure`) and the monotonic duration after. It fails closed at the start: a
start that cannot be appended means the read never runs. An end append failure is returned as an
internal dispatch error after the start already exists. An excluded call emits neither half of that
pair; it leaves one best-effort `structured_read_refused` planning record naming the exact tool the
model called and the reason, so the barriers between the runs are reconstructable too.

## Watch for (Go idioms)

- **The tests are the spec.** `internal/filetools/readtools_negative_test.go` is a cross-tool
  table proving every tool rejects `../` traversal, absolute-outside paths, symlink escapes,
  directory symlinks in recursive tools, and `~user` forms — all fail-closed *before* any read
  (`assertInBandRejection`, `assertNoCanaryLeak`). Note the external-target nuance for the
  absolute-outside case: the **standalone** `Invoke` has no authorizer, so it refuses an explicit
  external target in-band with a "requires permission approval through dispatch" message
  (`TestReadOnlyTools_StandaloneInvokeRefusesExplicitExternalTarget`) — still fail-closed, no read.
  Only the **dispatch** path prompts for and then reads such a target
  (`TestReadOnlyTools_ExternalReadAnchorsOutputAtExternalRoot`). When unsure how a containment edge
  behaves, that table answers faster than re-reading prose. `walk_test.go` does the same for
  ordering, hidden filtering, and depth.
- **Resolve once, reuse at invoke.** Each tool splits `ResolveTarget` (pre-authorization) from
  `InvokeWithResolvedTarget` (runs against the *already-authorized* path). This is the same
  reuse-at-invoke contract `edit`/`create` follow, so a symlink swapped between authorization and
  the read can't redirect it — which is why the recursive tools also re-`Lstat` the root.
- **Bound the result, not the walk.** `grep`/`glob` deliberately walk unbounded and bound
  matches/paths after — read `grep.go`'s comment on `Walk(... Limit: 0 ...)`. Capping the walk
  would drop matches in files past the cap, a subtle correctness bug.
- **Classify by the entry's own type.** `classifyDirEntry` (`walk.go`) and `ClassifyEntry`
  (`readresolve.go`) both use lstat-equivalents so a symlink is `EntrySymlink` even when it points
  at a directory — the whole no-follow guarantee rests on never resolving the link to classify it.
- **Binary detection before bytes.** `isBinaryContent` (`read.go`) is a NUL-byte scan (the signal
  git/grep use); `read` returns a short notice and `grep` skips the file, so raw binary bytes
  never reach stdout.

## Quiz

Take it closed-book: [`quizzes/module-13.md`](quizzes/module-13.md). Grade against
[`quizzes/module-13-key.md`](quizzes/module-13-key.md) — the key cites file and function/symbol.

## Hands-on (open-book)

**A. Predict, then verify.** A directory `vendor/` lives at the project root, and the project
`codemeldignore` contains the single line `vendor`. Will `glob` with pattern `**/*.go` return Go
files under `vendor/`? Will it if the pattern were `node_modules` instead of `vendor` in the
ignore file (with a `node_modules/` dir nested two levels deep)? Write your predictions, then
verify against `CodemeldignoreMatcher.ShouldSkip` (`codemeldignore.go`) and the match-semantics
paragraph above — recall that a slash-less pattern is **root-only**. (Bonus: find where the
matcher is consulted *before* descent in `Walk` (`walk.go`), which is why a matched directory
prunes its subtree.)

**B. Write a test.** Add a test asserting a **recursive** tool refuses a directory-symlink `path`
argument fail-closed. A clean shape exercising the resolver directly:

```go
func TestResolveReadTarget_RecursiveRejectsDirSymlink(t *testing.T) {
    root := t.TempDir()
    real := filepath.Join(root, "real")
    if err := os.Mkdir(real, 0o755); err != nil {
        t.Fatal(err)
    }
    link := filepath.Join(root, "link")
    if err := os.Symlink(real, link); err != nil {
        t.Fatal(err)
    }
    _, _, err := ResolveReadTarget("", root, root,
        map[string]any{"path": "link"},
        ReadTargetOptions{Kind: GrepToolName, RejectDirectorySymlink: true})
    if err == nil {
        t.Fatal("recursive tool must reject a directory-symlink path argument")
    }
}
```

Put it in `internal/filetools/readresolve_test.go`, run `go test ./internal/filetools`, and find
your test's result. It should pass against current code — you're proving the invariant and learning the
resolver API. Cross-check: `readtools_negative_test.go`'s
`TestReadOnlyTools_RecursiveToolsDoNotFollowDirSymlinks` already encodes the end-to-end form.
*(Revert afterward, or keep it if you think it adds value and want to propose it.)*

**C. Locate the limits.** Find where the per-tool limits + the byte-cap-safe truncation indicator
are implemented. Record the `file:function` in [`progress.md`](progress.md).

## Done when

- You answered every quiz question correctly **without** the key.
- Your hands-on A predictions matched what `ShouldSkip` and the root-only rule actually do.
- Your hands-on B test passed, and you can explain *why* by pointing at the
  `RejectDirectorySymlink` branch in `ResolveReadTarget`.
