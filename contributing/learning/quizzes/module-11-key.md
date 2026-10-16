# Answer key — Module 11: Infra & periphery

_Last updated: 2026-08-01_

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** Open + stat the parent dir (must be a directory) → create a unique `.tmp-<16hex>` sibling with
`O_EXCL` → write data → **fsync the temp file** → close → **rename** temp over the target → **fsync the
parent directory**. *Proof:* `fsutil/atomic.go` `WriteAtomic`; clean path in `TestWriteAtomic_CleanWrite`.

**2.** `RenameStep`, and the temp file is removed — no orphan is left. *Proof:* `fsutil/atomic.go`
`WriteAtomic`; `TestWriteAtomic_RenameFailure_TargetIsDirectory`.

**3.** A **dedicated sidecar lock file** (`<settings>.lock` / `<session>.json.lock`), never the data
file (it gets renamed-over, so a lock on its inode gives no cross-process exclusion). The **kernel
auto-releases** the advisory lock when the holding process exits, even with no explicit release.
*Proof:* `locks/flock.go` `Acquire`/`TryAcquire` doc comments; `TestAcquire_AutoReleaseOnProcessExit`.

**4.** `Acquire(path, 0)` hands flock an already-expired context, so it reports a *timeout* without ever
calling the lock syscall. `TryAcquire` calls `TryLock` directly — exactly one real, non-blocking
attempt — returning `ReasonLockContended` (nil error, nil release) on contention. *Proof:* `locks/flock.go`
`TryAcquire` doc comment; `TestTryAcquire_ContendedReturnsImmediately`, `TestTryAcquire_CleanAcquireAndRelease`.

**5.** Authorization is **not** failed: the grant is degraded to a **session** grant (a global grant is
rescoped from `"*"` to the request path; a folder grant keeps its scope; a project host grant keeps its
exact canonical host and gains no path scope), exactly one `permission_persist_failed` event is appended
(with `degraded_to_path_scope` only for the global case, and `host_scope` — never a degraded path — for
the host case), a one-line notice is rendered, and the grant stays active for the run. *Proof:*
`permissionpersist/persist.go` `PersistGrant` + `permissions/degrade.go` `DegradeGrant`;
`TestPersistGrant_FolderFailureDegradesPathScopeUnchanged`,
`TestPersistGrant_GlobalFailureRewritesScopeAndRecordsDegradedPath`,
`TestDegradeGrant_ProjectHostKeepsCanonicalHostAndTool`.

**6.** `EACCES`/`EPERM` → `permission_denied`; `ENOSPC` → `no_space`; `EROFS` → `read_only_fs`; `ENOENT`
→ `not_found`; `EBUSY`/`ETXTBSY` → `in_use`; any unknown errno, non-errno error, or nil → `io_error`
(the fallback). *Proof:* `fserrors/category.go` `CategorizeErrno`; `TestCategorizeErrno`.

**7.** `codemeld: <operation> failed: <target_path>: <category>`, with operation and path run through
`CollapseControls`, and **no** trailing newline (the newline is added only by `WriteToStderr`).
*Proof:* `fserrors/opfail.go` `FormatOpFail`; `TestFormatOpFail`.

**8.** It prefers a set, non-empty, *existing* `$HOME`; otherwise falls back to `os/user.Current()`.
(A missing `$HOME` path → `errHomeMissing`; empty user home → `errHomeUnset`; lookup failure →
`osUserLookupError`.) `Expand("~root")` is **rejected** — the `~user` form is not supported. *Proof:*
`paths/home.go` `ResolveHome`/`Expand`; `TestResolveHome_HomeMissing`, `TestExpand`.

**9.** `os.MkdirAll` re-resolves the whole path by string, so a symlink or rename swapped in **after** a
location was authorized could redirect the create outside the authorized tree. `EnsureDirAt` instead
`Mkdirat`s each segment relative to a **held** parent descriptor and re-`Openat`s it before descending, with
`O_NOFOLLOW` (rejects a symlink component, ELOOP) and `O_DIRECTORY` (rejects a non-directory component,
ENOTDIR) — so the create can never escape the authorized directory. `createdDirs` reports exactly the
segments **this call** created (an already-present segment is skipped), but those directories are removable
only **by name**; a concurrent process can delete this call's directory and create a same-named replacement
before rollback runs, so a name-based removal cannot prove it targets the directory this call made. So on a
failed nested create the `create` tool **does not remove its created parent directories** — it leaves them in
place and cleans up only the target file and temp file through the held parent descriptor. `EnsureDirAt`
itself, on an internal failure, returns **no** ownership list and leaves the segments it created — including
the just-created one plus any earlier already-synced ancestors — in place (as with `MkdirAll`), since a
name-based unlink could remove a concurrent replacement. *Proof:* `fsutil/mkdir.go`
`EnsureDirAt`; consumed by `filetools/create.go` `CreateTool.create` and `filetools/mkdir.go`
`MkdirTool.mkdir`, with the create-tool leave-in-place cleanup contract pinned by
`TestCreateTool_NestedCreateFailureCleanup`.
