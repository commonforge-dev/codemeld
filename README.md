# codemeld

> An agentic code editor for the terminal — without vendor lock-in, permission re-prompt fatigue, or telemetry.

**codemeld** lets a language model help you write code in your own projects, from your own terminal, without giving up the things developers actually care about: control over which provider you use, which version-control system you prefer, what leaves your machine, and how often you have to re-approve the same command.

Writing and changing code is the point, but not every request ends in a diff. Ask it to explain a subsystem, draft or update documentation, research how something works, analyse output, or track down why a build fails, and it answers from what it can read — the agent is instructed to treat a request to *diagnose* or *investigate* as read-only until you ask for the change, and Plan mode enforces read-only. What it can reach is not limited to your project folder: under the permission rules below, it reads files outside the project without a prompt, writes outside the project only after a prompt, and a [confined shell command](#confined-shell-commands-linux) can read the whole filesystem except `~/.codemeld` and your blocked paths.

> **Status:** v0.4.5 is the first public release. See [the roadmap](ROADMAP.md) for what's planned.

---

## Why codemeld?

Today's agentic editors share a recurring set of frustrations:

- They lock you into a single model family or vendor.
- They assume git is the only version-control system worth supporting.
- Their permission prompts re-ask for the same operation written slightly differently.
- They phone home with telemetry, analytics, and update checks by default.
- Their "approve everything" modes trade safety for speed in ways many developers wouldn't choose deliberately.

codemeld is a response to those patterns. It treats the permission system as a first-class feature, not a checkbox; speaks to 3 inference providers at launch; supports git, Mercurial, and Jujutsu out of the box (and any other VCS through user-defined templates); and sends nothing anywhere except to the LLM providers you configure and the web hosts you approve for web research (see [Zero phone-home](#zero-phone-home)).

---

## What sets it apart

### Permissions that respect your time

Most editors will ask you to approve `git log`, then ask again when the agent runs `/usr/bin/git log`, then ask again for `cd src && git log`, then again for `git log | head`. These are the same operation, but the prompts treat them as separate.

In codemeld, you approve `git log` **once** in a folder. After that, none of these re-prompt:

```
cd ~/code/myproject/sub && git log
/usr/bin/git log
git log | head -n5
```

(`/usr/bin/git log` matches only when `/usr/bin/git` is the `git` on your `PATH`.)

Approvals are also:

- **Persistent across sessions and restarts.** A "permanent" grant survives `codemeld` restarts, machine reboots, and config reloads.
- **Path-scoped.** A grant authorised in `~/code/foo` does *not* apply in `~/code/bar`. It applies in the folder you approved it in and its descendants — never ancestors, never siblings.
- **Four explicit lifetimes.** Session (in-memory only), folder (saved to `<project root>/.codemeld/settings.local.yaml`), global (saved to `~/.codemeld/global/settings.yaml`), and, for web hosts only, project (also saved to `<project root>/.codemeld/settings.local.yaml`). Global is never the default.
- **No "approve everything" mode.** There is no YOLO toggle and no opt-out mode. Fewer prompts come from read-only requests allowed automatically in every mode, structured reads outside the project, Auto edits approvals, `declared_commands`, your grants, a per-turn cache of answers, the paths a caller names with `codemeld run --files-authorized` or `--files-authorized-delete` (a [declared write scope](docs/permissions.md#a-declared-write-scope-is-a-ceiling-not-another-route-to-yes)), and [confined shell commands](#confined-shell-commands-linux): on a supported Linux host, Plan and Auto edits run shell commands inside a mandatory OS-enforced boundary, which no setting turns off.

### Three interaction modes

A mode sets the agent's *posture* — how much it may do before it stops and asks. It never replaces the permission system:

| Mode | What the agent may do | Actions that change things |
|---|---|---|
| **Plan** | Read, search, and produce a plan. | **Denied outright.** Write tools aren't even offered to the model, and mutating requests are refused without a prompt — read-only is enforced, not just requested. On a [confined host](#confined-shell-commands-linux), a shell command runs inside the read-only boundary with no ordinary command prompt, so a write or network call simply fails; elsewhere a mutating shell command is refused. |
| **Build** | Normal work. This is the default. | **Prompted**, unless an existing grant already covers the request. Shell commands always run outside the boundary, with these prompts. |
| **Auto edits** | Continuous work with fewer interruptions. | **Auto-approved for changes inside your project tree** — a `create`, `edit`, `mkdir`, or `move` whose resolved target is in the project. On a confined host, shell commands run inside the boundary with no ordinary command prompt; a recognized network, deletion or history-rewrite command asks. Everything else still prompts. |

Auto edits is narrower than it sounds, and deliberately so:

- It covers exactly four structured operations, and only when the resolved (symlink-followed) target is inside the project. A `move` needs **both** its source and its destination in-project — one end outside sends the whole move to a prompt.
- It **still prompts** for the structured `delete` tool (irreversible, so no mode ever auto-approves it; a path the caller named with `--files-authorized-delete` before the run started is removed with no prompt), version-control tool changes, and any path outside the project.
- Shell commands depend on the host. On a confined host, a direct or literal shell stage runs inside the boundary with no ordinary command prompt, and only a recognized exceptional action — network access (`curl`, `git push`, `pip install`, …), file deletion (`rm`, …), or a history rewrite (`hg strip`, `git reset --hard`, …) — asks, offering only allow once or deny; a literal command codemeld cannot split into stages gets an ordinary prompt. Where the self-test failed or the host is unsupported, shell commands prompt as in Build, except a command matching the project's `declared_commands` list, which runs without a prompt.
- It approves **per call**. It stores no grant and caches nothing, so it never widens what a later approval covers, and switching back to Build applies from the next tool call.

Switch with `/mode <plan|build|auto-edits>`, or press **shift+tab** to cycle plan → build → auto-edits. Each tool call captures the mode in effect when codemeld starts handling it and keeps that mode through its authorization and execution, so a switch governs only later tool calls, not later checks or stages of a call already under way; a prompt already on screen is still yours to answer. The launch default is `build` (set `mode.default` in config) and is never restored from a prior session.

### Confined shell commands (Linux)

On Linux amd64 and arm64, codemeld runs a self-test at startup. When it passes, every Plan and Auto edits shell command — including the commands behind the version-control tools and those run by child agents — runs inside a mandatory boundary built from Landlock, seccomp, `no_new_privs`, resource limits, and a fixed environment. No setting, flag, or environment variable turns it off, and it is not an approve-everything mode:

- **Plan** gets no filesystem writes except `/dev/null` and no network sockets, and adds no exceptional authority: a write or network call fails inside the boundary, with no prompt to widen it.
- **Auto edits** may write the project's top-level files and folders, except `.codemeld` and any entry that is a symlink to the project root, to protected state, or to somewhere outside the project, plus a private temp folder for the session. Blocked paths are carved out of both. Approving network access for one command adds internet sockets for that command only; every other restriction stays.
- **Every confined command** can read the filesystem except `~/.codemeld` and your blocked paths, and cannot write `~/.codemeld` or `<project>/.codemeld`, though an Auto edits command can still change file metadata such as permissions there (see [SECURITY.md](SECURITY.md)). Declared `writable_folders` and shared temp folders are not write roots today.
- **Build** always runs shell commands outside the boundary, with ordinary prompts.

The status bar shows which applies: `sandbox: on` (Plan or Auto edits, confined), `sandbox: off` (Build on a confined host), or `sandbox: unavailable`; `/status` and headless output add the reason, as `sandbox: unavailable (reason)`. `unavailable` does not by itself mean commands run unconfined:

- If the self-test failed or the host is unsupported, Plan and Auto edits keep ordinary unconfined permission behavior — prompts, and Plan's usual refusals.
- If the self-test passed but a settings file's blocked-path list later breaks, Plan and Auto edits commands stay confined, and every shell command asks until the file is fixed, except one you already denied this turn. Version-control tool calls do not ask.
- If the boundary cannot be set up for one command, that command fails with the error. codemeld never re-runs it outside the boundary.

The session record keeps the underlying value — `constrained`, or `refused` with its reason — which `codemeld sessions summary` reports. See [SECURITY.md](SECURITY.md) for what the boundary does not cover.

### No vendor lock-in

codemeld speaks the OpenAI chat-completions contract as its internal provider interface. Built-in adapters ship for OpenAI, OpenRouter, and Venice — and through OpenRouter you can reach Claude, Gemini, Llama, DeepSeek, and dozens of other models without rebuilding codemeld.

Adding a new OpenAI-compatible provider is a config edit, not a code change:

```yaml
provider:
  my-provider:
    base_url: https://api.example.com/v1
    api_key: sk-...
```

A provider entry is connection-only: `base_url`, `api_key`, and an optional
`auth_header`. The selectable model list is discovered from the provider's
`/models` endpoint and refreshed from the model picker. `/connect` validates and
saves a key for the built-in OpenAI, OpenRouter, and Venice entries only.

The `openrouter` entry also accepts an optional `routing` block that tells OpenRouter
how to pick the upstream provider for each request:

```yaml
provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: sk-or-...
    routing:
      sort: throughput          # throughput or latency; omit for OpenRouter's price-weighted default
      data_collection: deny     # allow or deny; deny skips providers that store or train on prompts
      require_parameters: true  # only use providers that support every request parameter
```

If a provider blocks your account, raises prices, or shuts down, you change one config block and keep working.

### Any VCS, not just git

codemeld represents version control as YAML templates, not hard-coded logic. Built-in templates ship for:

- **git**
- **Mercurial (hg)**
- **Jujutsu (jj)**

Adding support for a new VCS — Fossil, Pijul, your in-house system — is a single YAML file in `~/.codemeld/global/vcs/<name>.yaml` (or `<project>/.codemeld/vcs/<name>.yaml` for one project). No fork, no PR, no waiting on upstream.

When two VCS markers are present in the same tree (rare but real — e.g., a `.git`/`.hg` co-existence), tie-breaking is configurable through `vcs.priority`, and you can hard-override with `vcs.preferred`.

### Zero phone-home

codemeld is a strict client. It connects only to:

- **The LLM providers you configure**, at the base URL you set: model requests, the `/models` discovery behind `/connect` and model refresh, and, for OpenRouter's best-value routing, its endpoint listing.
- **OpenAI's fixed ChatGPT origins**, only if you use the ChatGPT subscription login: `https://auth.openai.com` for login, token refresh, and logout, and `https://chatgpt.com/backend-api/codex` for model requests.
- **Web research hosts you approve**: Exa (`mcp.exa.ai`) for `web_search`, and for `web_fetch` the page you approved plus any redirect hop it follows.

Model requests to a configured provider, and ChatGPT login, token refresh, and logout, refuse redirects, so they never leave these origins. Only `web_fetch` follows redirects, and it authorizes each hop on its own host.

Model requests and model discovery, ChatGPT login, token refresh, and logout, and `web_search` honor the standard proxy variables: an `https://` request goes through the proxy named by `HTTPS_PROXY` and an `http://` request through `HTTP_PROXY`, and a host matching `NO_PROXY` is reached directly. With no matching variable set, the request connects directly. `web_fetch` always connects directly.

There is no telemetry, no analytics, no crash reporter, no auto-updater, no dependency phone-home. There is no opt-out toggle because there is nothing to toggle. Host names are resolved through your system's ordinary DNS resolver.

The web tools are advertised by default; set `web_research.enabled: false` in the global settings file to remove them. Advertising is not authorization. Every web call needs your answer at the permission prompt, or a matching grant for that exact host and tool, in every mode. An allow-once answer covers that host and tool for the rest of the turn. Enabling the tools or supplying an Exa key authorizes nothing. A search contacts only Exa and never fetches the pages it lists. Reading one is a separate `web_fetch` call, authorized on its own host, and each redirect hop is authorized on its own host too. A redirect changing scheme or port requires a fresh one-time confirmation even when the hostname has a project grant; scheme and port are never added to a persistent grant. `web_fetch` also refuses loopback, private-network, link-local, and cloud-metadata addresses, even for an approved host.

Shell commands are separate. A command running outside the boundary has your account's ordinary network access. On a [confined host](#confined-shell-commands-linux), Plan and Auto edits commands cannot open sockets unless you approve network access for one Auto edits command.

How this is kept honest:

- Tests check that an idle startup with web research enabled makes no search request, and that a turn in an interactive session sends provider traffic only to the configured provider. They cover those scenarios, not every network path in the binary.
- A code-review rule: any network call outside the destinations above is a bug.
- An explicit, documented project non-goal.

You can verify it yourself with `strace`, `dtrace`, or a packet sniffer.

### Single binary, runs where developers work

- **Linux** is the tested target. macOS and FreeBSD build but are untested. codemeld does not currently compile for Windows and is not supported there.
- **Single binary** per platform, static when built with `mise run build`. No CGO required, no runtime, no `npm install`, no Python virtualenv, no Docker.
- **No installer required.** Install it with `go install` (see [Quick start](#quick-start)) or build it from source. No downloadable release binaries are published.
- **Confined shell commands are Linux amd64/arm64 only.** They need Landlock ABI 3 or newer (Linux 6.2 or later) and a passing startup self-test on that host, arm64 included; a kernel version alone does not prove the boundary works. Older kernels, other architectures, FreeBSD, and macOS keep ordinary permission behavior and show `sandbox: unavailable`.
- **The structured `move` tool is Linux-only.** On other systems it refuses to move rather than risk overwriting a destination.

### Open formats, inspectable everywhere

- Config: human-authored YAML, generated with comments on first run so you can see what every key means.
- Sessions: one JSON-lines file per session, one record per line, appended as the session runs, schema-versioned. You can `jq` your own session history.
- Permissions: stored as plain entries in YAML with explicit `subject`, `path_scope`, and `grant_kind`. Auditable by hand.
- VCS templates: YAML, embedded at compile time but materialised to `~/.codemeld/global/vcs/` on first run so you can read and edit them.

---

## Status & roadmap

v0.4.5 is the current release. Confined shell commands for Linux amd64/arm64 have already shipped (see [Confined shell commands](#confined-shell-commands-linux)).

See [the roadmap](ROADMAP.md) for released versions and planned work.

---

## Building from source

**Prerequisites:** [mise](https://mise.jdx.dev/) (manages the Go version).

```sh
git clone https://github.com/commonforge-dev/codemeld
cd codemeld
mise install        # installs the Go version declared in mise.toml
mise run build      # produces ./codemeld
```

Then follow the Quick start steps below from step 2, using `./codemeld` in place of the installed `codemeld`.

---

## Quick start

```sh
# 1. Install with the Go toolchain (the version on the go line of go.mod,
#    currently 1.26.9). The binary lands in $(go env GOBIN), or
#    $(go env GOPATH)/bin when GOBIN is unset; put that on your $PATH.
go install codemeld.dev/codemeld/cmd/codemeld@latest

# 2. First run generates ~/.codemeld/global/settings.yaml with comments and exits.
codemeld

# 3. Authenticate with a provider. For OpenAI there are two independent,
#    separately-billed paths — pick one:
#
#    a) ChatGPT subscription (individual, interactive use, no API key):
codemeld auth login openai-chatgpt        # browser sign-in (device-code fallback)
#
#    b) OpenAI Platform (pay-as-you-go API key; for CI/servers/non-interactive):
#       set OPENAI_API_KEY (it takes precedence over a saved key), or edit
#       ~/.codemeld/global/settings.yaml and add provider.openai.api_key.

# 4. Check OpenAI authentication: Platform key and ChatGPT login (prints no secrets).
codemeld auth status            # add --json for machine-readable output

# 5. Run codemeld inside any project folder.
cd ~/code/myproject
codemeld
```

To resume a prior session in the same folder:

```sh
codemeld --resume          # lists resumable sessions for this folder
codemeld --resume <id>     # resumes a specific session
```

---

## Configuration at a glance

| Layer | Path | Purpose |
|---|---|---|
| Global | `~/.codemeld/global/settings.yaml` | Provider keys, ChatGPT auth session, default behaviour, global permissions |
| Per-project | `<project>/.codemeld/settings.yaml` | Project overrides; folder grants you approve are saved to `settings.local.yaml` beside it |
| VCS templates | `~/.codemeld/global/vcs/{git,hg,jj}.yaml` (+ user files; `<project>/.codemeld/vcs/` per project) | Per-VCS action definitions |
| Instructions | `AGENTS.md` (default) | Project-specific guidance for the agent |
| Sessions | `~/.codemeld/sessions/<folder-dir>/<id>.json` | Per-session transcript and event log |

Per-project config discovery is bounded: by default, codemeld only reads `.codemeld/settings.yaml` in your launch directory and never walks upward. The accepted `discovery.boundary` values are `launch-dir-only` (the default) and `project-root`, which opts in to walking upward to the nearest `.codemeld/settings.yaml`.

> **Handle the global settings file with care.** `~/.codemeld/global/settings.yaml` is written at mode `0600` and may contain **plaintext provider API keys and your ChatGPT session token** (there is no OS keychain support). Do not check it into a project, paste it into a bug report, or sync it to untrusted locations.

---

## Documentation

- [Roadmap](ROADMAP.md) — released versions and planned work
- [Architecture notes](docs/architecture.md) — cross-cutting constraints
- [Tech stack](docs/tech-stack.md) — libraries and tooling choices
- [Design rationale](docs/RATIONALE.md) — what existing tools got wrong, in the author's view

---

## Contributing

Bug reports and design feedback on the roadmap are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.

---

## Project home

- **Repository:** [github.com/commonforge-dev/codemeld](https://github.com/commonforge-dev/codemeld)
- **Website:** [codemeld.dev](https://codemeld.dev) (in development)

---

## License

MIT — see [LICENSE](LICENSE).
