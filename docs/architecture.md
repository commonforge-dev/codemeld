# codemeld Architecture Notes

This document captures cross-cutting constraints and design decisions that shape the
codebase. It is not a full architecture spec — the forward-looking summary lives in
[`ROADMAP.md`](../ROADMAP.md), and the "why" behind the bigger calls lives in
[`RATIONALE.md`](RATIONALE.md).

## Overview

codemeld is a terminal UI (TUI) agentic code editor. Phase 1 ships as a **single static
binary per target with no CGO**, drops into any project without provider lock-in, and treats
the permission system as the front door for its own tools and for every unconfined shell command.
On Linux amd64/arm64 hosts whose startup self-test passes, Plan and Auto edits shell commands run
inside a mandatory OS-enforced boundary, and that boundary is what authorizes them (see
[Execution capability](#execution-capability)). Outbound network traffic is limited to configured
LLM providers, the fixed OpenAI ChatGPT origins when that provider is used, and web research hosts
a human approved (see [Privacy & Telemetry](#privacy--telemetry)).

## Platform Support

- **Tested target:** Linux. It is the only platform where the test suite is run, and the only one
  where shell commands can run confined (amd64 and arm64).
- **Build-only targets:** macOS and FreeBSD. codemeld compiles for them, but nothing is tested
  there.
- **Windows:** not supported. codemeld does not compile for Windows, because shared filesystem and
  locking code uses Unix-only system calls. A dependency that supports Windows (such as the file
  lock library) does not make codemeld buildable there.
- **Design constraint:** any feature that cannot be implemented uniformly across Linux, macOS,
  and FreeBSD must either have a documented cross-platform fallback or be explicitly
  gated per-OS, with the gate recorded in the [Per-OS Gates](#per-os-gates) table below.
  New phase-1 code that introduces an OS-specific path must add a row here.
- **Build:** single static binary per target; no CGO in phase 1 (see
  [No CGO in phase 1](#no-cgo-in-phase-1)).

### Why platform parity matters

codemeld is a developer tool. Linux, macOS, and FreeBSD reflect the platforms its users are
most likely to work on, even though only Linux is tested today. Parity is not aesthetic —
features that only work on one OS create lock-in of a different kind ("to use the good version, use Linux") that runs against the
project's stated goals. Ship cross-platform or gate explicitly.

### Validation expectations

- Linux: the local gate (`mise run check`) builds codemeld and runs the whole test suite. There is
  no hosted CI.
- macOS and FreeBSD: codemeld cross-compiles for both. No tests and no manual smoke test run on
  either.
- Windows: not built and not validated, since the build fails.

## Per-OS Gates

This table records the per-OS gates that are design decisions. It is not an exhaustive list of
OS-specific code (see below). A feature that is
fully cross-platform through a library or `path/filepath` does not need a gate; it is listed
only where that cross-platform guarantee is itself the design decision worth recording.

**Confined shell execution is gated to Linux amd64 and arm64.** Its implementation in
`internal/enforce` uses Linux-only source files, and every other target resolves `refused` at
startup, keeping ordinary permission behavior (row below). The tree also has other OS-specific
source files and `runtime.GOOS` branches — for example `isWindows` in `internal/config/load.go`,
which suppresses a POSIX file-mode warning on Windows — so a package missing from this table is not
a claim that it has no per-OS code. The Windows column describes such code paths only: codemeld does
not compile for Windows, so none of them runs there.

| Feature | Mechanism | Linux | FreeBSD | macOS | Windows (code path only; does not build) | Notes |
|---|---|---|---|---|---|---|
| Advisory file locking (settings + session sidecars) | `gofrs/flock` over a dedicated `.lock` sidecar | ✅ `flock(2)` | ✅ `flock(2)` | ✅ `flock(2)` | — | The library supports Windows (`LockFileEx`), but codemeld opens the sidecar with Unix-only calls; see [`internal/locks/flock.go`](../internal/locks/flock.go). |
| Config-file permission warning (mode broader than `0600`) | `runtime.GOOS == "windows"` check (`isWindows`) | ✅ warns | ✅ warns | ✅ warns | ⚪ suppressed | Windows lacks POSIX mode bits, so the code suppresses the warning there; the branch exists although codemeld does not build for Windows (`internal/config/load.go`). The warning names both provider API keys and ChatGPT session tokens, since the OpenAI ChatGPT login stores both plaintext in this file. |
| OpenAI ChatGPT auth storage (login + `auth.openai-chatgpt` state) | Same global settings file and login flow on every target; no OS keychain | ✅ | ✅ | ✅ | — | Uniform, **no platform gate**: the session is stored plaintext under `auth.openai-chatgpt` in `~/.codemeld/global/settings.yaml` at mode `0600` on every target, with no OS keychain/keyring. Browser-loopback login falls back to RFC 8628 device-code when the local listener cannot bind — a host condition, not an OS gate. |
| Path handling / case-sensitivity | `path/filepath`; ordinary OS lookups with no case folding | ✅ | ✅ | ✅ | — | Config lookups follow the filesystem: codemeld does no case folding of its own, so a case-insensitive filesystem matches a differently cased name. Permission path matching for `writable_folders` and `blocked_paths` is the exception: it compares case-insensitively on macOS and Windows (`internal/permissions/writable_folders.go`, `internal/permissions/blockedpaths.go`). |
| Sandbox opt-out or alternative backend | none, by design | ⚪ | ⚪ | ⚪ | ⚪ | The confinement boundary in the next row is mandatory: no setting, flag, or environment variable turns it off, there is no noop backend, and no failure is ever shown as `constrained`. |
| Confined shell execution (Plan and Auto edits) | Landlock ABI ≥ 3, seccomp, `no_new_privs`, and resource limits, applied by a re-exec helper and admitted only by the startup self-test | ✅ amd64 and arm64, when the self-test passes on that host | ⛔ `refused` | ⛔ `refused` | ⛔ `refused` | Any other Linux architecture, a Landlock ABI below 3 (kernels before 6.2), or a failed self-test leg also resolves `refused` with a reason. A `refused` host keeps ordinary unconfined permission behavior, including Plan's denials. See [Execution capability](#execution-capability) and [Protected settings state under confinement](#protected-settings-state-under-confinement). |

Legend: ✅ supported · ⚪ intentionally inactive · ⛔ no enforceable mechanism, resolves `refused` ·
— codemeld does not build for Windows, so the feature does not exist there.

### Process control

Anything dealing with signals, process groups, ttys, or pipes should go through small
OS-abstracted wrappers rather than `syscall.*` calls scattered through the codebase. FreeBSD,
macOS, and Linux mostly agree on POSIX semantics here, but small differences exist (e.g.,
signal numbers for non-standard signals, `SIGINFO` on BSD/macOS). Any such wrapper that ends
up branching per-OS must add a row to [Per-OS Gates](#per-os-gates).

### Filesystem semantics

Path separator, case-sensitivity, and permission bits differ across targets. All path handling
uses `path/filepath`. Config-file lookups use ordinary OS calls with no case folding, so they are
case-sensitive only where the filesystem is.

## Execution capability

Each session has one execution capability, resolved at startup by `internal/enforce` and recorded
as an `execution_capability` session event:

- **`constrained`** — the host is Linux amd64 or arm64 and every leg of the startup self-test
  observed what it expected.
- **`refused`** — anything else, with a reason: another OS or architecture, a Landlock ABI below 3,
  a failed self-test leg, or (live, after a passed self-test) a settings file whose blocked-path list
  no longer loads.

There is no toggle and no noop backend. No setting, flag, or environment variable selects a
different capability, and no failure is ever shown as `constrained`.

### The boundary

A confined command is started as codemeld's own binary running a hidden helper command. The
helper reads its policy from a length-prefixed frame at the head of its stdin, never from the
command line (other processes can read that from `/proc`). In order, it then sets resource limits,
sets `no_new_privs`, applies a Landlock ruleset, installs a seccomp filter with `TSYNC`, and
replaces itself with the target program. Everything the target starts inherits the restrictions,
and none of them can be removed. The child sees only a fixed environment built from a table, never
a filtered copy of codemeld's own.

- **Landlock.** codemeld asks the kernel for the Landlock ABI and never infers it from the kernel
  version. Below ABI 3 (Linux 6.2 is the minimum kernel; ABI 3 is the first with a truncate right) the host
  resolves `refused`. The ruleset is always the ABI-3 one, never go-landlock's best-effort mode,
  which succeeds without restricting anything on a kernel lacking Landlock. Reads are allowed
  everywhere except the blocked paths, which always include `~/.codemeld`.
- **seccomp.** In both modes the filter denies `socket` and `socketpair`, `ptrace` and
  `process_vm_readv`/`process_vm_writev`, System V shared memory, message queues and semaphores,
  `mq_open`, the io_uring calls, `unshare`, `setns`, mount and the new mount API, `pivot_root`,
  `chroot`, `bpf`, and namespace-creating `clone` flags. `clone3` fails with `ENOSYS`. Plan also denies the `chmod`, `chown`, extended-attribute and timestamp calls
  and the two file-flag `ioctl` requests. A system call from a non-native architecture kills the
  process (i386 on amd64, 32-bit arm on arm64). On amd64, an x32-numbered call fails with `EPERM`.
- **Write access, as wired today.** Plan grants no filesystem writes except `/dev/null`. Auto edits
  grants each canonical top-level entry of the project except `.codemeld`, skipping entries that
  resolve to the project root itself, into `.codemeld`, or outside the project, plus the session's private temp folder
  (mode `0700`, under `$TMPDIR`, removed when the session ends). Blocked paths are carved out of
  every write root, and `/dev/shm` itself is never writable. Declared `writable_folders` and shared
  temp folders are not policy write roots today.
- **Network.** Confined commands cannot create sockets of any family. In Auto edits, an approved
  network-access action runs with a filter variant that permits non-raw `AF_INET`/`AF_INET6` sockets
  and `socketpair` for that one command. Every other deny stays, including Unix sockets and io_uring.

### The self-test gate

Before resolving `constrained`, startup runs the helper against a scratch fixture and observes each
property from inside a real helper process: writes and truncation outside the write roots, reading
protected state, creating a Unix stream socket, an IPv4 stream socket, and a socketpair, System V
and POSIX IPC, `ptrace` and reading another process's
environment, user namespaces, mount, `chroot`, metadata changes, `no_new_privs`, the fixed
environment, and foreign-architecture system calls. A denied case runs first as an unrestricted
control, so a host that already denies it is told apart from a broken boundary. Any unexpected
result resolves `refused` with a reason naming the leg. A kernel version alone therefore never
makes a host `constrained`.

### What the capability authorizes

When a session's execution capability is constrained, the capability is the authorization for shell
commands in Plan and Auto. A direct or literal shell stage runs inside the boundary with no ordinary
command prompt. Its permission record has the outcome source `confined`, and no grant or turn-cache
entry is written. The same boundary wraps the subprocesses of the structured version-control tools
and the commands of child agents.

| Startup self-test | Settings file | Recorded capability | Shell commands in Plan and Auto edits |
|---|---|---|---|
| passed | valid | `constrained` | confined, no ordinary prompt; in Auto edits, recognized exceptional commands ask |
| passed | broken | `refused` (broken settings) | confined, every command asks |
| failed or unsupported | any | `refused` with its reason | unconfined, ordinary prompts and Plan denials |

- **The runner is chosen by the self-test, not the label.** Once the self-test has passed, every Plan
  and Auto edits command runs confined for the rest of the session. A broken settings file changes
  only the prompting.
- **Recognized exceptional commands ask only in Auto edits.** A fixed table in
  `internal/permissions/exceptional.go` (`ClassifyExceptional`) recognizes commands by program and
  subcommand: network access (`curl`, `wget`, `ssh`, `scp`, `git`/`hg` `pull`, `push`, `clone`,
  `git fetch`, `pip install`), file deletion (`rm`, `rmdir`, `unlink`, `shred`, `git clean`,
  `find -delete`, `find -exec rm`), and version-control history rewrites (`git rebase`,
  `git reset --hard`, `git filter-branch`, `git filter-repo`, `git`/`hg commit --amend`, and `hg`
  `strip`, `rollback`, `histedit`, `rebase`, `uncommit`, `amend`). Their prompt offers only allow
  once or deny, saved grants and the turn cache do not answer it, and the approved command still
  runs inside the boundary. A literal command codemeld cannot split into stages is not checked
  against the table; it needs an existing grant or a prompt answer, and still runs confined. With
  valid settings, Plan adds no exceptional authority: a network call or write simply fails inside
  the ordinary Plan boundary.
- **Unrecognized programs do not ask.** The table sees only the command line. A script or program
  it does not list — `bash build.sh`, `make`, `python tool.py` — runs confined with no prompt, so it
  can delete files or rewrite version-control history inside the write roots without asking. It
  stays inside the boundary: it cannot open network sockets or write outside the write roots.
- **The mode is fixed when a call starts.** A tool call captures the active mode once, when its
  dispatch begins (a child agent's calls keep the child's own mode), and keeps it through
  authorization and execution, including every stage of a shell command. A mode switch while a call
  is prompting or running applies to later calls, not to the one in flight.
- **No unconfined retry.** If the helper cannot set up the boundary for a command, that command
  fails with the helper's error and is never re-run unconfined. A confined command that fails gets a
  note saying the failure may be a boundary denial.
- **Build** always runs commands unconfined with ordinary prompts.

The TUI shows `sandbox: on` (Plan or Auto edits on a `constrained` host), `sandbox: off` (Build on a
`constrained` host), or `sandbox: unavailable` with its reason; headless runs print the same label to
stderr. `constrained`/`refused` are the recorded values reported by `codemeld sessions summary`, not
display labels.

### What stays open

The boundary does not close these:

- **Unconfined execution.** Build mode, and every host whose self-test did not pass, runs commands
  with the account's full authority once the permission system allows them.
- **Metadata.** In Auto edits, a command can change permissions, ownership, extended attributes,
  and timestamps on any file the user owns, blocked paths and security state included. ABI-3
  Landlock has no metadata right, and seccomp cannot see paths. Plan denies the ordinary metadata
  calls, but any kernel route to file metadata outside that list stays open.
- **Other channels.** Same-user signals; `/proc` process listings and command lines; host processes
  watching a write root or the temp folder, including through FIFOs and socket files created there;
  command output reaching the transcript and the model provider; approved network commands as upload
  channels, loopback and local network included; kernel vulnerabilities and resource exhaustion; no
  per-command intent review; and corruption through authorized writes.

## Privacy & Telemetry

Phase 1 emits **no outbound traffic other than to these application destinations**:

- **Configured LLM providers.** The provider client (`NewClient` in
  [`internal/provider/client.go`](../internal/provider/client.go)) sends model requests to the
  configured base URL. The same base URL receives the credentialed `/models` discovery request
  (`/connect` and model refresh, redirects refused) and, for OpenRouter's best-value routing only,
  the per-model endpoint listing.
- **The OpenAI ChatGPT origins**, only when that provider is used: `https://auth.openai.com` for
  login (including the device-code fallback), token refresh, and logout revocation, and
  `https://chatgpt.com/backend-api/codex` for model (Responses API) and model-list requests. These
  origins are not user-overridable. The loopback listener used during ChatGPT login
  (`http://localhost:1455`) is a local callback, not outbound egress.
- **Web research, only per human approval.** `web_search` reaches the fixed endpoint
  `https://mcp.exa.ai/mcp` and never fetches the candidates it returns. `web_fetch` reaches the URL
  the model asked for and each redirect hop, with every hop authorized on its exact host. A redirect
  changing scheme or port requires a fresh one-time confirmation even when the hostname has a
  project grant; scheme and port are never added to a persistent grant. The `web_fetch` transport is
  direct-only, refuses loopback, private, link-local and cloud-metadata addresses at dial time, and is
  not built at all when `web_research.enabled` is false. The tools are advertised by default, but
  neither that setting nor an Exa key authorizes anything: each call needs a prompt answer or a
  matching exact-host grant in every mode.

Host names resolve through Go's standard resolver inside the dialer; codemeld does no DNS of its
own. Provider, ChatGPT, and Exa requests use Go's default transport, so they honor the standard
proxy environment variables; `web_fetch` never uses a proxy. Shell commands are separate: an
unconfined command has the account's ordinary network access, while a confined one cannot create
sockets (see [Execution capability](#execution-capability)).

Any other network call codemeld makes itself is a bug. That is enforced by code review. The
no-network tests cover two scenarios only: an idle startup with web research enabled makes no
search request, and one headless turn's provider client dials only the configured provider. They do
not police raw dials, DNS, the ChatGPT, discovery, or web transports, or subprocesses.

A request's reasoning effort is serialized per provider by that same client. OpenRouter
uses the nested `reasoning: {effort: <level>}` object (the flat `reasoning_effort` is not the form
it honors); Venice and custom OpenAI-compatible providers keep the flat `reasoning_effort` field.
The branch keys off the provider id in
[`internal/provider/client.go`](../internal/provider/client.go), so Venice and custom serialization
stay unchanged. `ChatCompletion` sends any non-empty effort token through unchanged — it never
rewrites, maps, or filters the value — and writes no reasoning field at all when the request effort
is empty.

Two similar-looking values are deliberately distinct. `no-reasoning` is
codemeld's own sentinel rather than a provider token: it is displayed, persisted as
`model.active.effort` / `model.last_used.effort`, recorded on `model_turn`, and resolves to an empty
request effort, so the request carries no reasoning field. A literal `default` is an ordinary
provider token — it exists only when a provider advertises it, and it is displayed, persisted,
recorded, recovered, and sent on the wire unchanged like any other advertised value. Nothing treats
a provider's `default` as "send no parameter".

`ResolveRequestEffort` ([`internal/model/turn_events.go`](../internal/model/turn_events.go)) is where
that split is applied per turn: `no-reasoning` resolves to omission with no extra event, and a
configured token the active model no longer advertises also resolves to omission but emits
`model_effort_unsupported` carrying the configured value — the stored selection is never silently
rewritten. Either path records `effort: no-reasoning` on that turn's `model_turn`, which is what was
actually sent. `Validate` ([`internal/model/selection.go`](../internal/model/selection.go)) mirrors
it at selection time: `no-reasoning` is accepted for any model, and every other token must appear in
the model's cached advertised set.

Which effort levels a model exposes comes only from cached capability metadata — nothing is
declared statically and nothing is inferred from the model id. Providers spell the same three facts
(supported, the list of levels, the default) in different places, so one shape table in
[`internal/provider/effort_shapes.go`](../internal/provider/effort_shapes.go) records where each
spelling lives and one walker reads them all. It carries no provider id: the field paths themselves
identify the shape.

| Shape | Levels | Default | Gate |
|-------|--------|---------|------|
| Venice | `model_spec.capabilities.reasoningEffortOptions` | `…defaultReasoningEffort` | `…supportsReasoningEffort` must be true |
| OpenRouter | `reasoning.supported_efforts` | `reasoning.default_effort` | none |
| ChatGPT (cached) | `supported_reasoning_levels[].effort`, or the legacy `[].level` | `default_reasoning_level` | none |

The shapes are tried in that order and the first one that yields options wins; a shape whose root key
is absent is an optional non-match, not an error. Whatever the shape, the walker emits the same
neutral `supportsReasoningEffort` / `reasoningEffortOptions` / `defaultReasoningEffort` keys, with
every option length- and charset-capped so a hostile body cannot smuggle a blob through as an option.
A malformed container or an all-invalid list yields no options at all; a mixed list keeps its valid
entries in advertised order and skips the rest.

Discovery in
[`internal/provider/apikey_model_discovery.go`](../internal/provider/apikey_model_discovery.go)
decodes each `/models` record as a map of raw top-level messages, then reads only `id`, the input
modalities under `architecture`, `supported_parameters`, a fixed set of vision and function-calling
flags under `model_spec.capabilities`, and the effort roots the table declares — inside an effort
root it reaches only the declared segments and leaves. It keeps only the id, the input modalities,
and a whitelisted capabilities map, so an unrelated nested field carrying prompt or credential
material is never decoded or persisted. The catalog (`configuredEffortFromCapabilities` in
[`internal/provider/catalog.go`](../internal/provider/catalog.go)) then keeps a model's options only
when the cached entry set `supportsReasoningEffort`, de-duplicating the surviving tokens. The same
walker runs over cached ChatGPT capabilities at read time, so entries written before the table
existed keep working with no re-login or migration.

`Catalog.SupportedEffort` is the single selectable-effort source. A model with no surviving cached
options — metadata absent, unsupported, or malformed — exposes only `no-reasoning`, and so does the
cacheless `provider.SupportedEffort` helper, which delegates to an empty `Catalog`. There is no
static table or `default` fallback behind either path. The built-in `openai-chatgpt` provider keeps
compiled *model ids* as a fallback, but its effort options come the same way — only from its cached
discovery capabilities.

The older encoding, where a stored `effort: default` meant "send no reasoning-effort
parameter", is unsupported. There is no compatibility parser, no automatic migration, and codemeld
never edits or deletes those bytes itself. An old `default` the active model does not advertise
fails the `model.active` / `model.last_used` shape check and routes to the picker through the
existing soft-recovery path; in a resumed session it fails the same check on the recovered
`model_turn`, records `model_recovery_failed`, and falls through to the normal selection paths. If
the model *does* advertise a literal `default`, the old value validates and is then sent as a real
provider token — the opposite of what it used to mean, which is why the cleanup is a prerequisite
rather than a nicety. The one-time cleanup users perform before first launch is written up in
[`contributing/learning/module-08-turn-provider.md`](../contributing/learning/module-08-turn-provider.md).

A configured provider's discovered-model catalog (`models.yaml`) is written only by user-driven
actions — never at startup, on an ordinary catalog read, or on `/model` validation. There are three
writers. `/connect` ([`internal/bootstrap/connectdeps.go`](../internal/bootstrap/connectdeps.go))
validates a newly entered API key and writes that provider's initial catalog. `codemeld auth login`
writes the ChatGPT provider's catalog after a login. `ProviderCatalogRefresher`
([`internal/bootstrap/provider_refresh.go`](../internal/bootstrap/provider_refresh.go)) is the
picker-refresh service, installed as the model picker's refresh callback by `newProviderRefreshCallback`
in [`internal/bootstrap/modeldeps.go`](../internal/bootstrap/modeldeps.go). Opening the picker or
highlighting a row asks it to refresh that provider, which happens only when its `refreshed_at` is
missing, malformed, or more than three days old; Ctrl-R forces a refresh, and is the only way the
ChatGPT provider is refreshed from the picker. For an API-key provider a refresh runs one
background `DiscoverAPIKeyModels` call — the same redirect-refusing, credential-safe `/models` egress `/connect` uses — then
atomically replaces that provider's `models.yaml` entry and rebuilds the run's live catalog
(`Cache.ReloadDiscoveredCatalog`). Concurrent picker requests for one provider share a single discovery
while different providers stay independent; any discovery, Platform-filter, or write failure keeps the
prior catalog and stays secret-free. This is **provider egress, not telemetry**: it sends only the
provider's own credentialed `/models` request to the configured base URL and writes only sanitized model
metadata to the local cache. See [`provider-model-cache.md`](provider-model-cache.md) for the cache's
ownership and failure semantics.

There is **no opt-in or opt-out telemetry toggle, because no telemetry exists**. No
analytics, crash reporting, or update checks are collected or sent, so there is nothing for a
toggle to control. This stance is recorded deliberately: a future phase that introduces
optional telemetry must update this section first — adding the toggle is a documented design
change, not an incidental code edit.

## File System Helpers

Shared filesystem behavior lives in [`internal/fsutil/`](../internal/fsutil/) so config,
session, and VCS writers do not each re-implement directory creation and crash-safe writes.
Architecture-level note only — the contracts live in the code:

- **`EnsureDir`** ([`internal/fsutil/mkdir.go`](../internal/fsutil/mkdir.go)) — creates a
  directory and any missing parents (mode `0755`) if absent, reporting whether it had to
  create the target and an error category on failure. It re-resolves an absolute path through
  `os.MkdirAll`, so it must not run after a location is authorized (a symlink or rename swapped
  in afterward could redirect it).
- **`EnsureDirAt`** ([`internal/fsutil/mkdir.go`](../internal/fsutil/mkdir.go)) — the
  fd-relative, post-authorization counterpart of `EnsureDir`. Given an already-open, authorized
  parent directory, it creates a missing suffix one component at a time under a held descriptor,
  re-opening each new segment with `O_DIRECTORY|O_NOFOLLOW` (so a symlink or non-directory
  component is rejected, never followed) and never re-resolving by path — so directory creation
  cannot escape the authorized tree. It reports the exact segments it created (`createdDirs`) and,
  through an optional `DirLifecycle` hook, each one's inode identity. The `create` tool does **not**
  remove created parent directories itself on failure, because removal by name cannot prove the
  directory is still the one this call created against a concurrent delete-and-replace; it cleans up
  only the target and temp file through the held descriptor. Inside a child agent, `create` passes
  the hook so the child's rollback journal records those parents by identity. The `mkdir` tool, by
  contrast, makes a best-effort descriptor-relative removal of only the segments it created when its
  parent moves after creation. For the same reason a parent-fsync failure inside
  `EnsureDirAt` returns the categorized error without unlinking the segment it just made, leaving
  that segment (and any earlier synced ancestors) as partial residue rather than risk deleting a
  concurrent replacement at the same name. This is how the `mkdir` and `create` tools build missing
  parents after authorization, composed with `WriteAtomicCreateAt`; use `EnsureDir` (not this) for
  pre-authorized internal paths.
- **`WriteAtomic`** ([`internal/fsutil/atomic.go`](../internal/fsutil/atomic.go)) — writes a
  file via a sibling temp file plus rename, fsyncing both the temp file and the parent
  directory, at the caller-supplied mode. The parent directory must already exist (compose
  with `EnsureDir`). First-run settings generation, `models.yaml`, and the project approval store
  use it. Session files use it only for a whole-file rewrite (after an unverified write, or to set
  a title): a session file is created with `WriteAtomicCreateAt`, and an ordinary flush appends new
  JSON lines with `O_APPEND` and fsyncs instead of rewriting (`internal/sessions/store.go`). Settings updates publish through
  `WriteAtomicReplaceAt` under a held parent directory handle (`internal/config/rewrite.go`).
- **`Acquire` / `TryAcquire`** ([`internal/locks/flock.go`](../internal/locks/flock.go)) —
  cross-platform advisory locks over `gofrs/flock`, taken on a dedicated `.lock` sidecar
  (never the renamed-over data file).
  `Acquire` waits up to a timeout (settings writes, session ownership); `TryAcquire` is the
  non-blocking probe the retention pruner uses.

## Cross-cutting design decisions

### No outbound network traffic except to sanctioned destinations

The sanctioned destinations are the configured LLM providers, the fixed OpenAI ChatGPT origins
when that provider is used, and the web research hosts a human approved — `mcp.exa.ai` for search,
and the fetched page and its redirect hops for `web_fetch` — all listed under
[Privacy & Telemetry](#privacy--telemetry). Web tools are advertised by default but reach nothing
without a prompt answer or a matching exact-host grant, in every mode. Any other network call
codemeld makes itself is a bug. That is enforced by code review; the no-network tests cover only
the startup and headless-turn scenarios described there.

Zero phone-home is a core promise: no telemetry, analytics, crash reporting, or update checks. In
concrete terms, model requests go to the configured base URL through `NewClient`
(`internal/provider/client.go`), and `/models` discovery and OpenRouter's endpoint listing make
their own requests to that same base URL through a redirect-refusing HTTP client; the ChatGPT origins are
`https://auth.openai.com` for login, refresh, and logout and `https://chatgpt.com/backend-api/codex`
for ChatGPT model requests, off when that provider is unused. Shell subprocesses are separate: an
unconfined command has the account's ordinary network access. The rules for extending this policy
are in the [egress note](../contributing/invariants.md#note-extending-the-egress-policy).

### No CGO in phase 1

The deliverable is a single static binary per platform with no runtime dependencies, so the
documented build command sets `CGO_ENABLED=0` (see
[`contributing/setup.md`](../contributing/setup.md)). This excludes: libseccomp, tree-sitter C
bindings, embedded SQLite, `libgit2`. If a dependency requires CGO, either find a pure-Go
alternative, shell out to an external tool, or defer the feature.

### Permission system is the front door

The permission system is the authorization mechanism for codemeld's structured tools, its web
tools, and every shell command that runs unconfined. The permission subsystem and its tests define
that model, and there is still no approve-everything mode.

The only other authorization is the mandatory confinement boundary: on a Linux amd64/arm64 host
whose startup self-test passed (`constrained`), it authorizes Plan and Auto edits shell commands.
There is deliberately no "YOLO" mode and no opt-out mode either, and neither may be added. The
detailed rules are in [Permissions and tool-execution rules](permissions.md). The boundary has no toggle and no noop backend (`internal/enforce`). A `refused` host
keeps ordinary permission behavior, Build always does, and a helper failure fails the command rather
than re-running it unconfined (`internal/bootstrap/confinedrunner.go`).

For an unconfined command, the permission system decides *whether* it runs, never *which files it
touches*. That limit is why confinement exists: when the execution capability is `constrained`, the
boundary itself authorizes Plan and Auto edits shell commands and bounds what they can touch (see
[Execution capability](#execution-capability)). The next subsection records what that means for
codemeld's own settings files.

### Protected settings state under confinement

codemeld protects its settings files, its project approval store, and their `.lock` sidecars —
`<project-root>/.codemeld/settings.yaml`, `<project-root>/.codemeld/settings.local.yaml`,
`<home>/.codemeld/global/settings.yaml`, and `<home>/.codemeld/global/approved-projects.yaml` —
from its own structured file tools and VCS tools, through a pre-authorization guard in
`internal/securitystate`. Shell commands do not pass through that write guard. What protects the
files from a shell command depends on where the command runs.

The permission system is the front door, and a front door that can authorize rewriting its own
policy is not a front door — so no model-facing structured file tool may change these files.

**Structured file tools.** The run's three bootstrap-configured settings paths and the approval
store above, plus each one's `.lock` sidecar, are refused for exactly five operations: `edit`,
`create`, `delete`, `mkdir`, and `move` (`protectedStatePolicy` in `internal/bootstrap/trust.go`,
`guardedTools` in `internal/securitystate/protect.go`).

- The protected set is those **configured** names, not every path shaped like a settings file, so
  an unrelated nested `settings.yaml` is ordinary.
- `PrepareTool` (`internal/dispatch/tool.go`) checks the nominal endpoint **before** any
  operation-specific resolver and the resolved identity after it, so an alias, a `..` path, a
  final-component symlink, or a `move` of a directory that *holds* a protected file is refused too.
- It runs ahead of mode posture, a declared scope, the grant match, the turn cache, and the prompt,
  so it takes precedence over the out-of-root write, `delete`, `move`, and declared-scope rules in
  [Permissions and tool-execution rules](permissions.md).
- The refusal is the fixed `denied_by: "guard"` envelope, recorded as `permission_matched` with
  `outcome_source: protected_state` and `outcome: deny` (`productionToolDispatcher.Dispatch` in
  `internal/bootstrap/tooldispatch.go`), and it is **recoverable**: the turn re-issues so the model
  can tell the user to run `/settings`.
- **Exception — the dedicated typed writers**: permission persistence and revocation, `auth`
  login/logout/refresh, `/connect`, `/model`, `/effort`, model favorites, and first-run settings
  generation remain the supported route for changing these files — the route codemeld offers, not
  the only one that can reach them.

**VCS actions, checked before the subprocess starts.** A VCS template runs its argv directly,
unconfined in Build or on a `refused` host, so a `vcs_restore_file`, branch switch, or stash pop that
had already rewritten the settings file could not be undone by suppressing its result. `PrepareTool`
therefore asks the action for a verdict after it resolves the execution directory and before
authorization.

- A built-in (or byte-identical first-run reference copy) action that can replace working-file
  bytes — Git `branch-switch`, `restore-file`, `stash`, and `stash-pop`, Mercurial `branch-switch`,
  `restore-file`, and `stash`, plus Jujutsu `branch-switch` and `restore-file` — first runs a
  product-authored, non-mutating backend query asking whether a protected identity is in its
  would-change set, and is refused when the answer is yes or cannot be established (`protectRules`
  in `internal/vcs/tool.go`). Mercurial `stash-pop` has no such query and is refused whenever a
  protected file exists in the repository.
- For `restore-file` that would-change set is bounded by the requested `{path}`, so restoring an
  unrelated file stays available while the protected file, a directory holding it, a hardlink or
  symlinked-directory alias, and any argument the check cannot bound — a whole-tree `.`, a flag, a
  wildcard, a Git pathspec, a Mercurial pattern, or a Jujutsu fileset expression — refuse.
- Jujutsu's `stash`/`stash-pop` only report status, and `add`/`commit` record history without
  touching the working copy, so staging and committing settings bytes a user already approved stays
  available.
- Protected identities are matched inside the repository by path, by symlink, and by `os.SameFile`
  **hardlink** identity (`Policy.ProtectedIn` in `internal/securitystate/protect.go`).
- A **custom** VCS template's argv is arbitrary, so while the guard is active a custom action is
  refused unless it comes from the trusted global template directory, declares `class: read_only`,
  **and** matches the built-in's own read-only argv exactly; a project template never gets that
  exception.
- Every refusal reuses the same envelope and `protected_state` record as the file-tool guard.

**Shell commands** never pass through this guard; the next paragraphs cover them. The confinement
rules are enforced by `policy` in `internal/bootstrap/confinedrunner.go` and `landlockRules` in
`internal/enforce/landlock_linux.go`.

**Confined commands** — Plan and Auto edits on a `constrained` host, including the subprocesses of
the VCS tools and the commands of child agents — cannot write them. `~/.codemeld` is the fixed
blocked floor of every policy, so a confined command can neither read nor write anything under it,
and `<project>/.codemeld` is never a write root in either mode. A confined content write, create,
delete, rename, or truncate therefore cannot reach the protected state.

**Unconfined commands** are not covered. In Build mode, and in every mode on a host whose self-test
did not pass, nothing prevents an allowed shell command from rewriting these files. That exposure
is not limited to commands a user approved: a shell stage classified read-only is auto-allowed in
every mode with no grant and no prompt, and the classification is a judgement about command text,
not a statement about which files will be written.

Residuals that remain even under confinement, all accepted:

- **Metadata in Auto edits.** A confined command can still change permissions, ownership,
  extended attributes, and timestamps on these files, since ABI-3 Landlock has no metadata right.
  Making a settings file unreadable puts the session into the broken-settings state, where every
  Plan and Auto edits command asks — so that route fails closed.
- **Metadata routes in Plan** outside the seccomp deny list stay open.
- **Host processes and watchers.** A process outside the boundary, such as an editor or a file
  watcher on a write root, is not confined and can act on anything a command leaves in a writable
  folder.

Also outside the guard, and also accepted rather than closed: structured **reads** of these files,
and, for VCS, everything beyond the actions above — repository hooks, filters, extensions, and a
concurrent repository or filesystem change *after* the query runs.

No userspace defence could close the unconfined case. The shell child runs under the same uid as
codemeld and may read any user-accessible path, so a snapshot, digest, or marker the defence relies
on is writable by the thing it is meant to catch. Only reducing the child's authority below the
parent's — an OS primitive it cannot undo, as the confinement boundary does — is fail-closed.

### Config: YAML for humans, per-session JSON for machines

- `settings.yaml` and `vcs/*.yaml`: human-authored, annotated with comments at generation time,
  rarely edited.
- Session files (`.json` extension): machine-written JSON lines, one file per session — a metadata
  record on the first line, then one record per line. The first write creates the file atomically
  (`WriteAtomicCreateAt`); an ordinary flush appends only the new lines and fsyncs; a whole-file
  rewrite — after an earlier write could not be verified, or when a session's title is set — goes
  through `WriteAtomic` (`Store.Flush` in `internal/sessions/store.go`).
- Schemas: JSON Schema (`santhosh-tekuri/jsonschema`), shipped as `.json` files; same schema
  validates YAML data at runtime and drives editor autocomplete.

### A process owns exactly its current active session

Every active session — fresh interactive, fresh headless, resumed, a `/clear` target, or a
linked child created by `/fork` or `/compact` — is owned through that session's dedicated
`.lock` sidecar, acquired before the first durable append and held while the session is
active. Locking only resumed sessions left fresh and child sessions exposed: UUID
uniqueness keeps two fresh launches off each other's file, but it does not stop another
process from resuming, pruning, or appending to a file this process is still writing.
The sidecar is `<session>.json.lock`, taken by `sessions.AcquireResumeLock`; the `ResumeLock`
names are historical and kept deliberately unrenamed.

An in-process switch transfers ownership **target before source**. The switch acquires the
target's lock while still holding the source's, installs the target as the active session,
moves the target's release token into the run-scoped holder, and only then releases the
source. Steady state is exactly one held session lock; the two-lock overlap is bounded to
the switch itself, so the session being left is never unowned while it is still active. An
acquisition or initialization failure releases any tentative target ownership and leaves the
source active and owned. Releasing the source before taking the target would leave the session
being left unowned for an interval, so the overlap is *required*, not a bug. The run-scoped holder
is `resumeLockHolder`, and the switch is `preparedChildLifecycle.Activate`
([`internal/bootstrap/childdeps.go`](../internal/bootstrap/childdeps.go)).

### `/compact` is asynchronous and terminally truthful

Summarization is a provider request, so running it on the event loop would freeze drawing
and input. `/compact` snapshots the active parent and selection on the loop, takes an
exclusive submission gate, and runs the provider call and the child preparation in the
background ([`App.RunBackgroundAfterDraw`](../internal/tui/app.go)). While the gate is held,
prompts and commands that could mutate, replace, or close the captured parent are retained
and not dispatched — the gate wraps the whole submit adapter, because slash commands are
dispatched before the prompt path is reached. Concretely, the gate wraps the submit adapter in
`StartTUI`, not just the prompt entrypoint, because `tui.NewSubmitFunc` dispatches slash commands
first: gating prompts alone would still let `/clear`, `/resume`, `/fork`, `/exit`, or a second
`/compact` mutate, replace, or close the captured parent. While the gate is held, every submission
is retained and undispatched. Completion returns to the loop for activation, and the gate is
released exactly once on every terminal path.

Success is recorded only once it is true. The parent's `slash_command` success record and the
`session_forked` marker are committed as one atomic terminal batch, so a durable success
implies the child and the marker are both durable and only non-failing live activation
remains. Any earlier failure appends a `slash_command` error to the still-open parent,
records no success and no marker, and switches no session; a complete but unactivated child
may survive as an unlocked resumable orphan, which the UI describes rather than pretending to
have rolled back.

Recording success on acceptance would claim a session switch that a later persistence failure
never made. The records are `slash_command{compact,success}` and, on failure,
`slash_command{compact,error}`; the atomic batch is written by `sessionfork.CreateOwnedChild`.

### OpenAI authentication: two separate providers

codemeld ships two independent OpenAI providers; the active credential always follows the selected
model's provider, with no cross-provider precedence chain and no silent credential shadowing.

- **`openai` — OpenAI Platform (API key).** Pay-as-you-go usage billing. The key resolves from
  `OPENAI_API_KEY` when set and non-empty, otherwise from `provider.openai.api_key` in the global
  settings file. This is the supported path for CI, servers, automation, and commercial
  deployments. `codemeld auth login openai` is rejected — Platform uses an API key, not a browser
  login.
- **`openai-chatgpt` — OpenAI ChatGPT (subscription session).** A built-in provider for individual,
  interactive developer use where a ChatGPT subscription grants model access. `codemeld auth login
  openai-chatgpt` runs an OAuth2 + PKCE browser flow (device-code fallback) and stores the session
  under `auth.openai-chatgpt`; `codemeld auth logout openai-chatgpt` removes it (best-effort upstream
  revocation, then local deletion). The provider id is reserved — a `provider.openai-chatgpt` entry
  is a load-time error. Its Responses requests send the active session id as an optional
  `prompt_cache_key` to route one session's repeated requests, omitted when there is no session key.
  A controlled live probe recorded that the endpoint accepts the field and that a same-key repeat
  still gets a full prompt-cache hit; requests without the key hit too, so no cache-hit improvement
  is attributed to it. The captured-wire tests prove only what codemeld serializes, not what the
  endpoint does with it. The field is a cache-routing hint — it adds no Codex client identity
  header or metadata, and the request still sends `store: false`.

`codemeld auth status` (and `--json`) reports both providers' state **offline** — it reads only
`OPENAI_API_KEY` and the global settings file, makes no network call, and prints no secrets. ChatGPT
auth state is **plaintext** in `~/.codemeld/global/settings.yaml` at mode `0600` (there is no OS
keychain support); credentials are global-only and never composed from or
redirected by project-local settings. Because this file may hold plaintext provider API keys **and**
ChatGPT session tokens, and is readable by the local user account, it must not be checked into a
project, pasted into a bug report, or synced to untrusted locations. ChatGPT credential egress is
limited to the approved OpenAI origins (see [Privacy & Telemetry](#privacy--telemetry)).

**Unresolved permission risk.** codemeld does not claim official OpenAI approval for the ChatGPT
flow. It is user-initiated, oriented at individual interactive use, and dependent on upstream
ChatGPT/Codex access that OpenAI may change or revoke. If upstream policy, terms, or technical
controls later disallow the flow, the feature is stopped, disabled, or removed rather than bypassing
those controls.

### Tool dispatch is exact-name in phase 1

No regex, no pattern matching, no shell-equivalence rewriting. The tool registry
(`tools.Registry` in `internal/tools/registry.go`) is a flat map keyed by exact tool name.
Pipelines are authorized stage-by-stage by exact program name.

Exact names keep authorization predictable, with no surprising pattern matches. How that applies to
shell commands:

- **Recognized bare compounds are split into stages.** Pure `|` pipelines, and a recognized bare
  `&&`/`||`/`;`/`|` compound, are authorized stage by stage by exact program name: `DispatchShell`
  decomposes the compound and makes each stage its own `direct` subject. A direct grant the user
  already approved (say `go test :*`) therefore authorizes **every matching stage** of that chain at
  the granted scope and its descendants. Authorize-all-before-run still gates execution, so one
  denied or non-matching stage stops the whole chain before anything runs.
- **Shell precedence is kept without `sh -c`.** Stages joined by `|` form one pipe group that chains
  stdout into stdin, and `&&`/`||`/`;` sequence completed groups, so `a; b | c` keeps shell
  precedence while staying off `sh -c`. Because such a compound is not handed to `sh -c`, its stages
  run as literal argv: shell glob and variable expansion does **not** apply to them, exactly as it
  never applied to a direct pipeline.
- **A direct grant never stretches over an unclassifiable command.** Redirection, a wrapper, a
  subshell, backgrounding, an env-assignment-bearing stage, and any malformed or empty stage route
  the whole command to the literal/compound path. It matches byte-exact or — for a *simple compound*
  recognized by `RecognizeSimpleCompound` — a generalized grant that still pins the exact program
  set and operator structure and only widens leaf arguments to a chosen scope
  (`internal/permissions/compound.go`).
- **Recognition is fail-closed at both layers.** The operator allowlist in
  `internal/dispatch/shell.go` admits only bare `&&`/`||`/`;`/`|`, and any non-simple shape or
  destructive-program stage falls back to byte-exact literal matching. A false "not simple" is only
  friction; a false "simple" would widen a grant.
- **Some constructs are refused outright.** An unquoted command substitution `$(…)` or backtick, and
  bare newlines, are refused before any prompt and can never be authorized by a grant.
- **Quoted substitution takes the literal route.** A `$(…)` or backtick inside double quotes is not
  refused, because the shell performs it: the whole command takes the literal route and runs through
  `sh -c` with the substitution performed, always prompts until an exact-text grant covers it (Plan
  denies it), and can never hold a direct, per-stage, or generalized grant
  (`TestSplitCommand_DoubleQuotedSubstitutionRoutesLiteral`,
  `TestDoubleQuotedSubstitutionIsNeverAutoAllowed`).

No regex, no inferred widening. Which shell commands auto-allow as read-only is covered in
[Permissions and tool-execution rules](permissions.md).

### Project root: marked by `.codemeld/settings.yaml`, not inferred from VCS

codemeld determines the project root by walking upward from the current working directory to the
innermost ancestor that contains a `.codemeld/settings.yaml` file. This is observable on the
filesystem before any VCS work runs, which breaks what would otherwise be a circular bootstrap
dependency between user-defined VCS template loading and VCS root detection (templates discover
relative to the project root; detection produces what would otherwise *be* the project root —
under a VCS-anchored design, neither could run first). It also means non-VCS projects work
without a special case, and users mark their project root explicitly rather than codemeld
inferring it. The upward walk is the discovery code in `internal/config`.

Global codemeld state — settings, VCS templates — lives under `~/.codemeld/global/`. The
top-level `~/.codemeld/` directory therefore has no `settings.yaml` directly inside it and is
never matched as a project root during the upward walk. Sessions are stored at
`~/.codemeld/sessions/<folder-dir>/<id>.json`, where `<folder-dir>` is derived from the folder the
session was started in (a hash of the folder path plus its sanitized base name); they live outside
the project and don't participate in marker discovery.
