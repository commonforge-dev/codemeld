# codemeld

> An agentic code editor for the terminal — without vendor lock-in, permission re-prompt fatigue, or telemetry.

**codemeld** is a coding assistant you run in your own projects, from your own terminal. You choose the model provider and the version-control system, you decide what leaves your machine, and you approve a command once instead of every time it's written slightly differently.

> **Status:** v0.4.5 is the first public release. See [the roadmap](ROADMAP.md) for what's planned.

---

## Before you try it

- It is alpha software and under heavy development.
- AI was used in its development.

## Why try it

- **Your choice of provider:** ChatGPT subscription, OpenRouter, or Venice.
- **Tuned OpenRouter routing:** pick providers by speed or best value, and cap the price per model so you get speed without the most expensive providers.
- **Your choice of version control:** Git, Jujutsu, and Mercurial work out of the box. Other systems are added with YAML templates.
- **Permission modes** from read-only to auto-approved edits inside your project. See below.
- **No phone-home:** no telemetry, analytics, crash reporter, or auto-updater.
- **Open formats:** config and permissions are YAML, and each session is a JSON-lines log you can query with `jq`.

---

## Permission modes

A mode sets how much the agent may do before it stops to ask. It never replaces the permission system.

| Mode | What the agent may do | Changes |
|---|---|---|
| **Plan** | Read, search, and plan. | Denied. Write tools aren't offered to the model, and mutating requests are refused without a prompt. |
| **Build** (default) | Normal work. | Prompted, unless an existing grant covers the request. |
| **Auto edits** | Continuous work with fewer interruptions. | Auto-approved inside your project: creating, editing, making folders, and moving files. Deletes, version-control changes, and anything outside the project still prompt. |

- Switch with `/mode <plan|build|auto-edits>`, or press shift+tab to cycle through them.
- Auto edits covers only those four operations, and only when the target is inside the project after symlinks are resolved. A move needs both ends inside the project.
- Auto-edit approvals are per call. Nothing is stored, so switching back to Build applies from the next tool call.
- Shell commands follow their own rules. On a supported Linux host they run inside a boundary (below). Elsewhere they prompt, and Plan refuses mutating ones.

Full rules: [docs/permissions.md](docs/permissions.md).

### Confined shell commands (Linux)

On Linux amd64 and arm64 hosts with Landlock ABI 3 or newer (kernel 6.2+) that pass codemeld's startup self-test, Plan and Auto edits shell commands run inside a fixed boundary built from Landlock, seccomp, and resource limits. No setting turns it off.

- **Plan:** no filesystem writes (except `/dev/null`) and no network. A blocked write or network call simply fails.
- **Auto edits:** writes are limited to the project's top-level files and folders (not `.codemeld`, and not symlinks that leave the project), plus a private temp folder for the session. Approving network access for one command opens sockets for that command only.
- **Every confined command** can read the filesystem except `~/.codemeld` and your blocked paths, and cannot write `~/.codemeld` or `<project>/.codemeld`.
- **Build** shell commands always run outside the boundary, with ordinary prompts.

The status bar shows `sandbox: on`, `sandbox: off`, or `sandbox: unavailable`. `unavailable` means the boundary is off on this host, so Plan and Auto edits use ordinary permission behavior: prompts, and Plan's usual refusals. What the boundary does not cover is in [SECURITY.md](SECURITY.md); fallback cases are in [docs/architecture.md](docs/architecture.md).

---

## Runs where developers work

- **Linux** is the tested target. macOS and FreeBSD build but are untested. Windows is not supported.
- **One binary** with no runtime, `npm install`, Python virtualenv, or Docker. Built with `mise run build`, it is static.
- **No release binaries are published.** Install with `go install` or build from source.
- **Confined shell commands** are Linux amd64/arm64 only. Elsewhere the status bar shows `sandbox: unavailable`.
- **The structured `move` tool** is Linux-only. Elsewhere it refuses to move anything rather than risk overwriting a destination.

---

## Install

### From Binaries
See [Releases](https://github.com/commonforge-dev/codemeld/releases)


### With the Go toolchain

Needs the Go version on the `go` line of `go.mod` (currently 1.26.9).

```sh
go install codemeld.dev/codemeld/cmd/codemeld@latest
```

The binary lands in `$(go env GOBIN)`, or `$(go env GOPATH)/bin` when `GOBIN` is unset. Put that folder on your `$PATH`.

### From source

Requires [mise](https://mise.jdx.dev/), which manages the Go version.

```sh
git clone https://github.com/commonforge-dev/codemeld
cd codemeld
mise install        # installs the Go version declared in mise.toml
mise run build      # produces ./codemeld
```

Then follow the steps below, using `./codemeld` in place of `codemeld`.

---

## First run

1. **Run `codemeld` once.** It writes `~/.codemeld/global/settings.yaml`, with comments explaining each key, and exits.
2. **Run it in a project:** `cd ~/code/myproject && codemeld`
3. **Connect a provider.**
   - **API key (OpenAI Platform, OpenRouter, or Venice):** type `/connect`, pick the provider, and paste its key. The key is hidden as you type, checked by loading the provider's models, and saved to the global settings file only if that check succeeds. `/connect openrouter` skips the picker.
   - **ChatGPT subscription** (no API key): run `codemeld auth login openai-chatgpt` in your shell. This opens a browser sign-in, with a device-code fallback.

   A ChatGPT subscription and the OpenAI Platform are separate, separately billed options.

   Without the app (for CI or servers): set `OPENAI_API_KEY`, which takes precedence over a saved key, or add `api_key` under `provider.openai`, `provider.openrouter`, or `provider.venice` in the settings file.

   Check your setup with `codemeld auth status`. It prints no secrets; add `--json` for machine-readable output.
4. **Resume a session in the same folder:** `codemeld --resume` lists resumable sessions, and `codemeld --resume <id>` opens one.

> **Keep the global settings file private.** It is written with mode `0600`, but it holds plaintext provider API keys and your ChatGPT session token (there is no OS keychain support). Don't commit it, paste it into bug reports, or sync it to untrusted places.

---

## Configuration

| File | Purpose |
|---|---|
| `~/.codemeld/global/settings.yaml` | Provider keys, ChatGPT login, defaults, global permissions |
| `<project>/.codemeld/settings.yaml` | Project overrides. Folder approvals are saved beside it in `settings.local.yaml`. |
| `~/.codemeld/global/vcs/` and `<project>/.codemeld/vcs/` | VCS templates for `git`, `hg`, `jj`, or your own |
| `AGENTS.md` | Project guidance for the agent |
| `~/.codemeld/sessions/` | Per-session transcripts and event logs |

By default, codemeld reads only the `.codemeld/settings.yaml` in the folder you launch from. To let it search upward for the nearest one, set `discovery.boundary: project-root` in the global settings file; project files reject that key.

---

## Learn more

- [Roadmap](ROADMAP.md): released versions and planned work
- [Architecture notes](docs/architecture.md): cross-cutting constraints
- [Permissions](docs/permissions.md): the full rules behind the modes and prompts
- [Tech stack](docs/tech-stack.md): libraries and tooling choices
- [Design rationale](docs/RATIONALE.md): what existing tools got wrong, in the author's view

Bug reports and design feedback are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Repository:** [github.com/commonforge-dev/codemeld](https://github.com/commonforge-dev/codemeld) · **Website:** [codemeld.dev](https://codemeld.dev) (in development)

**License:** MIT. See [LICENSE](LICENSE).
