# Module 11 — Infra & periphery (optional)

_Snapshot as of 2026-08-01; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-08-01_

> The small, shared primitives that the rest of the codebase stands on: atomic writes, advisory
> locks, home/path resolution, error categories, and the persist-failure fallback. Optional, but it
> ties together patterns you've seen repeatedly (atomic write, sidecar lock, function-var seams).

## Goal

After this module you can:

- Recite the steps of an atomic write and explain the failure-step tokens.
- Explain what is locked, the blocking vs non-blocking variants, and process-exit auto-release.
- Explain the error-category vocabulary and the OP_FAIL output chokepoint.
- Explain what happens when a folder/global permission grant fails to persist.

## Why it matters

These primitives are reused everywhere (sessions, config, vcs). Understanding them makes the durable
and concurrent paths in earlier modules click into place.

## Read (in order)

1. `internal/fsutil/atomic.go` and `mkdir.go` — `WriteAtomic`, `EnsureDir`, `EnsureDirAt`.
2. `internal/locks/flock.go` — `Acquire`, `TryAcquire`.
3. `internal/paths/home.go` — `ResolveHome`, `Expand`.
4. `internal/fserrors/category.go` and `opfail.go` — `CategorizeErrno`, `FormatOpFail`, `WriteToStderr`.
5. `internal/permissionpersist/persist.go` — `PersistGrant`.
6. Skim `internal/integration/` — the cross-process wiring tests.

## Mental model

### fsutil

`WriteAtomic(target, data, mode)` is the crash-safe write used everywhere durable: open+stat the
**parent dir** → create a unique `.tmp-<hex>` sibling with `O_EXCL` → write → **fsync the temp file**
→ close → **rename** over the target → **fsync the parent directory**. It returns an
`AtomicWriteStep` token (`write` / `rename` / `parent_sync`) so callers map failures without parsing
strings; it does **not** create the parent (pair it with `EnsureDir`). `EnsureDir` does
`MkdirAll(0755)` and reports whether it created the directory.

`EnsureDirAt(parentDir, relPath)` is the **fd-relative, post-authorization** sibling of `EnsureDir`. Where
`EnsureDir` re-resolves an absolute path through `MkdirAll` — fine for internal paths, unsafe **after** a
location was authorized, because a symlink or rename swapped in afterward could redirect it — `EnsureDirAt`
creates the missing suffix **one component at a time under a held directory descriptor**: `Mkdirat` the
segment, `fsync` the parent that received it, then re-`Openat` it with `O_DIRECTORY|O_NOFOLLOW` before
descending. `O_NOFOLLOW` rejects a symlink component (ELOOP) and `O_DIRECTORY` rejects a non-directory one
(ENOTDIR), so the create **can never escape the authorized tree**. It returns `createdDirs` — the exact
segments *this call* made (an already-present segment is skipped) — but those segments are removable only
**by name**, and a concurrent process can delete this call's directory and put a same-named one in its place
before any rollback runs, so a name-based removal cannot prove it is deleting the directory this call created
rather than a concurrent replacement. Because of that the `create` tool **does not roll back its created
parent directories** on a later failure — it leaves them in place and cleans up only the target file and temp
file through the held parent descriptor. `EnsureDirAt` has one more sharp edge: on an internal failure it
returns **no** ownership list and leaves the segments it created — the just-created one plus any earlier
synced ancestors — in place (like `MkdirAll`), because unlinking a segment by name could delete a concurrent
replacement rather than the directory this call made. This is how the `mkdir` and
`create` tools build missing parents after authorization — composed with `WriteAtomicCreateAt` for
`create`'s leaf file.

### locks

`Acquire(path, timeout)` is a **blocking-with-timeout** advisory lock (production uses 2 s, retrying
every 25 ms). `TryAcquire(path)` is a **single non-blocking** attempt that returns
`ReasonLockContended` (a non-error skip) on contention — the retention pruner uses this so it never
waits on a session being resumed. Crucially, the helper locks **exactly the path it's given**, and
callers always pass a **sidecar** (`<file>.lock`), never the atomically-renamed-over data file. The
kernel **auto-releases** the lock when the process exits, even without an explicit release.

### paths

`ResolveHome` prefers a set, non-empty, *existing* `$HOME`, else falls back to `os/user`. `Expand`
handles `~` and `~/rest` but **rejects** the `~user` form. `FormatHomeError` maps the sentinels to
user-facing reason strings.

### fserrors

The `Category` vocabulary: `permission_denied`, `no_space`, `read_only_fs`, `not_found`, `in_use`,
and the fallback `io_error`. `CategorizeErrno` maps wrapped `syscall.Errno`s (through arbitrarily
nested `PathError`/`SyscallError`) to those. The OP_FAIL chokepoint formats
`codemeld: <op> failed: <path>: <category>` (control chars collapsed, **no** trailing newline);
`WriteToStderr` is the single place un-renderable errors go — and it deliberately **does not** call
`os.Exit` (the caller picks the exit code).

### permissionpersist

When a **folder**, **global**, or **project** grant fails to persist, `PersistGrant` does not fail
authorization: it **degrades** the grant to a session-equivalent (a global grant is rescoped from
`"*"` to the request path; a folder grant keeps its scope; a **project host** grant keeps its exact
canonical host and gains no path scope, because host authorization is equality on that one host, so
only the lifetime changes), appends one `permission_persist_failed` event, renders a one-line notice,
and returns the degraded grant — still active for the run.

### integration

`internal/integration/` composes the **real** production components and verifies they interoperate,
including via re-exec'd child processes for true cross-process coverage (concurrent persist, prune
recovery, schema-fork).

## Watch for (Go idioms)

- **Function-var seams for unmockable syscalls.** `syncFile`/`syncDir`, `newLock`, `currentUser`,
  and `persist` are package vars swapped in tests to force fsync/lock/lookup failures deterministically.
- **Multi-value `(step/reason, error)` returns** instead of parsing error strings, so each caller maps
  outcomes to its own vocabulary.
- **`TestMain` re-exec** of the test binary is the only way to prove kernel auto-release and
  cross-process flock serialization (goroutines share one fd table).

## Quiz

Closed-book: [`quizzes/module-11.md`](quizzes/module-11.md). Grade against
[`quizzes/module-11-key.md`](quizzes/module-11-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** Does `WriteAtomic` create the parent directory if it's missing? Predict,
then confirm against `TestWriteAtomic_ParentDirMissing` (`atomic_test.go`) — what step token and
category come back? What should you call first?

**B. Predict, then verify.** When a *folder* grant fails to persist, is it lost for the rest of the
session? Predict, then read `PersistGrant` (`permissionpersist/persist.go`) and confirm against
`TestPersistGrant_FolderFailureDegradesPathScopeUnchanged`.

**C. Locate the seams.** Find the `syncFile`/`syncDir` function-var seams in `fsutil/atomic.go` and
explain in one sentence why they exist (hint: which two failures need to be distinguishable?). Record
it in [`progress.md`](progress.md).

## Done when

- You can recite the atomic-write steps and name the failure-step tokens.
- You can explain the sidecar lock, the blocking/non-blocking variants, and auto-release.
- You can explain persist-failure degradation.
