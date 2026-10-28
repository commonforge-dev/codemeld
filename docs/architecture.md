# codemeld architecture

How codemeld is put together and the rules a change must keep. Planned work is in
[`ROADMAP.md`](../ROADMAP.md), the reasons behind bigger choices in [`RATIONALE.md`](RATIONALE.md),
and what codemeld asks before acting in [Permissions](approvals.md).

## Overview

codemeld is a terminal coding assistant shipped as one static Go binary. Its main parts, under
`internal/`:

- **Startup** (`cli`, `bootstrap`): parses the command line, loads settings, resolves the sandbox,
  opens the session, and wires the terminal UI (`tui`) or a headless run to the same turn loop.
- **Turn loop** (`turn`, `agent`, `agentinstr`): builds each request, streams the reply, runs tools.
- **Providers** (`provider`, `model`, `openaiauth`): talk to the model providers, discover their
  model lists, hold the active model selection, and run the ChatGPT login.
- **Tools** (`tools`, `dispatch`, `filetools`, `vcs`, `webresearch`, `subagent`): the file, shell,
  version-control, web and child-agent tools the model can call.
- **Permissions** (`permissions`, `trust`, `securitystate`): decide whether a tool call runs, asks,
  or is refused; project approval; protection of codemeld's own settings files.
- **Commands and sandbox** (`runner`, `enforce`): `runner` runs every command; `enforce` holds the
  Linux sandbox helper and the startup self-test.
- **Sessions and settings** (`sessions`, `config`): the per-session log and the YAML settings files.

## Platform Support

- **Linux** is the tested target and the only one where shell commands can run sandboxed (amd64
  and arm64). The local gate, `mise run check`, runs lint, the test suite and static checks; there
  is no hosted CI.
- **macOS and FreeBSD** build, but nothing is tested there.
- **Windows** is not supported: shared filesystem and locking code uses Unix-only system calls, so
  codemeld does not compile for it.

## Per-OS Gates

A feature that cannot work the same way on Linux, macOS and FreeBSD must have a fallback or a row
in this table. The table is not a list of every OS-specific code path: a package missing from it
may still have per-OS code. The Windows column describes code paths only.

| Feature | Mechanism | Linux | FreeBSD | macOS | Windows (code path only; does not build) | Notes |
|---|---|---|---|---|---|---|
| Advisory file locking (settings + session sidecars) | `gofrs/flock` over a dedicated `.lock` sidecar | ✅ `flock(2)` | ✅ `flock(2)` | ✅ `flock(2)` | — | The library supports Windows (`LockFileEx`), but codemeld opens the sidecar with Unix-only calls; see [`internal/locks/flock.go`](../internal/locks/flock.go). |
| Config-file permission warning (mode broader than `0600`) | `runtime.GOOS == "windows"` check (`isWindows`) | ✅ warns | ✅ warns | ✅ warns | ⚪ suppressed | Windows lacks POSIX mode bits, so the code suppresses the warning there (`internal/config/load.go`). The warning names both provider API keys and ChatGPT session tokens, since the global settings file can hold both in plain text. |
| OpenAI ChatGPT auth storage (login + `auth.openai-chatgpt` state) | Same global settings file and login flow on every target; no OS keychain | ✅ | ✅ | ✅ | — | Uniform, **no platform gate**: the session is stored in plain text under `auth.openai-chatgpt` in `~/.codemeld/global/settings.yaml` at mode `0600`. Browser login falls back to a device code when the local listener cannot bind, a host condition, not an OS gate. |
| Path handling / case-sensitivity | `path/filepath`; ordinary OS lookups with no case folding | ✅ | ✅ | ✅ | — | codemeld does no case folding of its own, so a case-insensitive filesystem matches a differently cased name. Permission path matching for `writable_folders` and `blocked_paths` is the exception: it compares case-insensitively on macOS and Windows (`internal/permissions/writable_folders.go`, `internal/permissions/blockedpaths.go`). |
| Sandbox opt-out or alternative backend | none, by design | ⚪ | ⚪ | ⚪ | ⚪ | The sandbox in the last row is mandatory: no setting, flag, or environment variable turns it off, there is no no-op backend, and no failure is ever shown as `constrained`. |
| Escaped-descendant cleanup on command cancel or timeout | Process-group `SIGKILL`; on Linux also a `/proc` scan for same-user descendants by parent chain and by the runner-owned `CODEMELD_RUN_ID` environment marker | ✅ group kill, then escaped descendants found by parent chain or marker | ⚪ group kill only, no marker | ⚪ group kill only, no marker | — | Best-effort, not a containment boundary: a process that removed the marker and was already reparented, or whose `/proc/<pid>/environ` is unreadable, survives. Bounded output collection after the command's root exits is uniform and needs no row ([`internal/runner/descendants_linux.go`](../internal/runner/descendants_linux.go)). |
| Confined shell execution (Plan and Auto edits) | Landlock ABI ≥ 3, seccomp, `no_new_privs`, and resource limits, applied by a re-exec helper and admitted only by the startup self-test | ✅ amd64 and arm64, when the self-test passes on that host | ⛔ `refused` | ⛔ `refused` | ⛔ `refused` | Any other Linux architecture, a Landlock ABI below 3 (kernels before 6.2), or a failed self-test leg also resolves `refused` with a reason. A `refused` host keeps ordinary unconfined permission behavior, including Plan's refusals. See [Execution capability](#execution-capability). |

Legend: ✅ supported · ⚪ intentionally inactive · ⛔ no enforceable mechanism, resolves `refused` ·
— codemeld does not build for Windows, so the feature does not exist there.

## Execution capability

The execution capability is resolved at startup and recorded in the session log:
**`constrained`** when the host is Linux amd64 or arm64 and every leg of the startup self-test
passed, otherwise **`refused`** with a reason. While a settings file is broken the recorded value
is `refused`, and it returns when the file is fixed. There is no toggle and no no-op backend.

### The boundary

A sandboxed command starts as codemeld's own binary running a hidden helper. The helper reads its
policy from its stdin (never the command line, which other processes can read), sets resource
limits and `no_new_privs`, applies a Landlock ruleset and a seccomp filter, then becomes the
command. Everything the command starts inherits the restrictions, and none can be removed. The
command sees codemeld's launch environment minus withheld-authority names, secret-looking names
and values carrying a URL credential (`runner.InheritedEnvironment`), then the fixed table's
`PATH`, `HOME`, `PWD`, `TMPDIR`, `GOCACHE`, `SHELL`, `TERM`, `LANG` and `LC_ALL`, then the
command's own assignments (`confinement.prepare`).

- **Files.** Reads are allowed everywhere except the blocked paths, which always include
  `~/.codemeld`. Plan may write only `/dev/null`. Auto edits may write each top-level entry of the
  project except `.codemeld` (skipping an entry that resolves outside the project, to the project
  itself, into `.codemeld`, or nowhere), the session's private temp folder (given to the command
  as `TMPDIR` and removed when the session ends), and declared `writable_folders`. Blocked
  paths, the `.codemeld` folders and `/dev/shm` are carved out of every write root, and `/tmp` is
  writable only through one of those roots.
- **Network.** A sandboxed command cannot create a socket that reaches another process. The one
  socket it may create is a Unix stream or seqpacket socket pair, whose ends connect only to each
  other; datagram pairs are denied, with the same pair rule in every seccomp filter
  (`seccompFilterFor` in `internal/enforce/seccomp_linux.go`). In Auto edits, a network command you
  approve gets internet sockets for that one command.
- **Self-test.** At startup the helper runs against a scratch folder and checks each property from
  inside: writes, protected reads, sockets, process, namespace and metadata calls, and the fixed
  environment, which this leg checks against the fixed table alone, never the launch environment
  (`runLeg` in `internal/enforce/selftest.go`). Each denied case first runs unrestricted, to tell a host that already denies it from
  a broken boundary. Any unexpected result resolves `refused` naming the leg.

### What the capability authorizes

On a `constrained` host, the sandbox is the authorization for Plan and Auto edits shell commands:
they run inside it with no ordinary prompt, and nothing is saved. The same boundary wraps the
commands of the version-control tools and of child agents. Build is never sandboxed.

| Startup self-test | Settings file | Recorded capability | Shell commands in Plan and Auto edits |
|---|---|---|---|
| passed | valid | `constrained` | sandboxed, no ordinary prompt; in Auto edits, a command with a recognized network or history-rewrite stage asks, and file deletion and commands codemeld cannot split run without asking |
| passed | broken | `refused` (broken settings) | still sandboxed, every command asks |
| failed or unsupported | any | `refused` with its reason | unsandboxed, ordinary prompts and Plan refusals |

- Once the self-test has passed, every Plan and Auto edits command stays sandboxed for the rest of
  the session; a broken settings file changes only the prompting.
- If the helper cannot set up the boundary for a command, that command fails with the helper's
  error and is never re-run unsandboxed. A sandboxed command that fails gets a note saying the
  failure may be a boundary denial.
- The status bar shows `sandbox: on` (Plan or Auto edits after a passed self-test with valid
  settings), `sandbox: off` (Build after a passed self-test), or `sandbox: unavailable`; `/status`
  and the headless stderr label add the reason. `codemeld sessions summary` reports the recorded
  value.

### What stays open

The sandbox does not cover unsandboxed commands, metadata changes in Auto edits, same-user
signals, `/proc` listings, outside processes watching a write root, output sent to the model
provider, approved network commands, or kernel bugs; see
[SECURITY.md](../SECURITY.md#what-the-confinement-boundary-does-not-cover).

## Privacy & Telemetry

codemeld itself connects only to:

- the configured model providers, at the base URL you set, for model requests and model discovery;
- `https://auth.openai.com` and `https://chatgpt.com/backend-api/codex`, only when the ChatGPT
  provider is used;
- `mcp.exa.ai` for an approved `web_search`, and the page and redirects of an approved `web_fetch`.

Any other network call codemeld makes itself is a bug. No telemetry exists: no analytics, crash
reporting, or update checks, so there is no toggle; adding one is a design change that updates
this section first. An unsandboxed shell command has the account's ordinary network access.

What codemeld stores, all on your machine:

- `~/.codemeld/global/settings.yaml`: global settings, approvals, provider API keys and the ChatGPT
  login, in plain text at mode `0600`. Credentials are read only from this file and the
  environment, never from project settings.
- `~/.codemeld/global/approved-projects.yaml`: the project folders you approved.
- `<project>/.codemeld/settings.yaml` and `settings.local.yaml`: project settings and project
  approvals.
- `~/.codemeld/sessions/`: one JSON-lines file per session, holding the transcript and event log.
- `~/.codemeld/global/models.yaml`: each provider's model list, holding only sanitized model
  metadata and written only when you connect a provider, log in, or refresh the model picker.
- `~/.codemeld/journals/`: copies of files a child agent declared, used to undo its changes.

### OpenAI authentication: two separate providers

`openai` uses an OpenAI Platform API key, from `OPENAI_API_KEY` or the global settings file.
`openai-chatgpt` uses a ChatGPT subscription session from `codemeld auth login openai-chatgpt`.
The credential always follows the selected model's provider, with no fallback to the other's.
`codemeld auth status` reports both offline, without secrets. codemeld does not claim OpenAI
approval for the ChatGPT flow; if OpenAI disallows it, the feature is removed, not worked around.

## Cross-cutting design decisions

### Permission system is the front door

Every structured tool call, web call, and unsandboxed shell command goes through the permission
checks. The only other authorization is the sandbox for Plan and Auto edits shell commands. There
is no approve-everything or opt-out mode, and neither may be added. For an unsandboxed command the
permission checks decide *whether* it runs, never *which files it touches*; that limit is why the
sandbox exists.

### Protected settings state under confinement

codemeld's own file and version-control tools refuse to change the settings files, the project
approval list, or their `.lock` files, including through a symlink or by moving a folder that
holds one; the version-control tools also refuse a hardlink to one. Only codemeld's dedicated
writers change them: saving approvals, `/settings`, `/blocked`, `/model`, `/effort`, favorites,
`/connect`, login, logout and token refresh, the project-approval prompt, and first-run setup. A
sandboxed command cannot write them either; an unsandboxed one can, as the same user.

### No CGO in phase 1

`mise run build` sets `CGO_ENABLED=0` and produces one static binary per platform with no runtime
dependencies. A dependency that needs CGO is replaced with a pure-Go one, an external tool, or the
feature waits.

### Tool dispatch is exact-name in phase 1

Tools are looked up by exact name in a flat registry, and shell commands are authorized by exact
program name, stage by stage. There is no regex: a saved approval can widen only by a `:*` tail or
a folder scope. A command that cannot be split safely is matched on its exact text, with only
quoting differences that cannot change what runs evened out.

### Atomic writes and file locks

Settings, model-cache and approval files are written to a temp file next to the target and renamed
over it, with the file and its folder synced to disk, so a crash leaves the old or the new file,
never half of one. A new session file is published the same way by hard link, and a session flush
appends new lines and syncs. Concurrent writers coordinate through an advisory lock on a separate
`.lock` file, never the data file (`internal/fsutil`, `internal/locks`).

### A process owns exactly its current active session

Every active session, including a `/clear`, `/fork` or `/compact` target, is owned through its
`.lock` file from before the first write until it is no longer active, so no other process can
resume, prune, or append to it meanwhile. A switch takes the new session's lock before releasing
the old one. While `/compact` runs, new input is held back; it records success only after the new
session is safely written, and a failure leaves the original session active.

### Project root: marked by `.codemeld/settings.yaml`, not inferred from VCS

The project root is the folder holding `.codemeld/settings.yaml`, or the launch folder when none
is found; it is never inferred from version control, so a project without version control needs
no special case. By default codemeld looks only in the folder you launch from; with
`discovery.boundary: project-root` in the global settings file it walks upward to the nearest
folder that has one, never matching your home folder, whose `.codemeld` holds global state.
