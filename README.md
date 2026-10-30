# codemeld

> An agentic code editor for the terminal — without vendor lock-in or telemetry, and with you in control of what it may do.

**codemeld** is a coding assistant you run in your own projects, from your own terminal. You choose the model provider and the version-control system, you decide what leaves your machine, and you set how much the agent may do before it asks, from read-only to auto-approved edits inside your project.

> **Status:** v0.4.8 is the latest release. See [the roadmap](ROADMAP.md) for what's planned.

---

## Why try it

- **Your choice of provider:** ChatGPT subscription, OpenRouter, or Venice.
- **Your choice of version control:** Git, Jujutsu, and Mercurial work out of the box. Other systems are added with YAML templates.
- **Permission modes** from read-only to auto-approved edits inside your project. See below.
- **No phone-home:** no telemetry, analytics, crash reporter, or auto-updater.
- **Open formats:** config and permissions are YAML, and each session is a JSON-lines log you can query with `jq`.

### OpenRouter features

Get the most out of OpenRouter:

- **Speed or value:** route each request to the fastest provider, or to the fastest of those at least as fast as the median and priced within 20% of the cheapest of them. When codemeld cannot pick one that way, because none qualifies or the provider list cannot be read, it asks OpenRouter to sort by price.
- **Price caps per model:** get speed without landing on the most expensive providers.
- **Quantization control:** let a model prefer or require the quantization levels you list, tried in your order.
- **One place for it all:** `/openrouter` opens these settings, with a models table holding each model's price caps and quantization levels.

## Before you try it

- **Beta.** Stable enough for everyday work, and still changing quickly, so expect changes between releases. See the [roadmap](ROADMAP.md).
- **Linux first.** Release binaries and the sandbox are Linux-only; see [Runs where developers work](#runs-where-developers-work).
- **Built with AI assistance.**

---

## Permission modes

A mode sets how much the agent may do before it stops to ask. It never replaces the permission system.

| Mode | What the agent may do | Changes |
|---|---|---|
| **Plan** | Read, search, and plan. | Denied. Write tools aren't offered to the model, and mutating requests to codemeld's own tools are refused without a prompt. On a host with confined shell commands (below), Plan's shell commands run inside the boundary, where writes fail. |
| **Build** (default) | Normal work. | Prompted, unless an existing grant covers the request. |
| **Auto edits** | Continuous work with fewer interruptions. | Auto-approved inside your project: creating, editing, making folders, and moving files. Creating, editing, and making folders are also auto-approved inside a declared `writable_folders` entry (see below). With shell commands confined and no settings file broken, deleting is auto-approved inside the project and declared folders too. Version-control changes and any other change outside the project still prompt. |

- Switch with `/mode <plan|build|auto-edits>`, or press shift+tab to cycle through them.
- Auto edits covers only those four operations, plus deleting while shell commands are confined (below) and no settings file is broken, and only when the target, after symlinks are resolved, is inside the project, or, for creating, editing, making folders, and deleting, inside a folder declared in `writable_folders` while shell commands are confined and no settings file is broken. Deleting the project folder or a declared folder itself still prompts. A move needs both ends inside the project; a declared folder never auto-approves a move.
- Auto-edit approvals are per call. Nothing is stored, so switching back to Build applies from the next tool call.
- Shell commands follow their own rules. On a supported Linux host they run inside a boundary (below). Elsewhere they prompt, and Plan refuses mutating ones.

What codemeld asks and when: [docs/approvals.md](docs/approvals.md).

**System One check (opt-in, off by default).** In Plan and Auto edits, codemeld can ask a small decision model whether a shell command that would otherwise prompt only reads, and run that one command without asking when the model is confident. It is never used in Build, never for network access, deletion, or history rewrites, and it saves no approval. Turning it on sends the checked command text to the model's provider and accepts a model's judgment in place of a proof. How the models were chosen and the risks: [docs/system-one.md](docs/system-one.md).

### Confined shell commands (Linux)

On Linux amd64 and arm64 hosts with Landlock ABI 3 or newer (kernel 6.2+) that pass codemeld's startup self-test, Plan and Auto edits shell commands run inside a fixed boundary. No setting turns it off.

- **Plan:** no file writes (except `/dev/null`) and no network.
- **Auto edits:** writes only to the project's top-level files and folders (not `.codemeld`), a private temp folder for the session, and folders declared in `writable_folders`; a command recognized as network access or a history rewrite asks.
- **Build:** always outside the boundary, with ordinary prompts.

The status bar shows `sandbox: on` (Plan or Auto edits inside the boundary), `sandbox: off` (Build on a host where the self-test passed), or `sandbox: unavailable`. `unavailable` means either the self-test failed or the host is unsupported, so commands run outside the boundary with ordinary prompts and Plan's usual refusals, or a settings file is broken, so commands stay confined but every shell command asks ([the broken-settings case](SECURITY.md#broken-settings)). `/status` shows the reason. The security model and what the boundary does not cover: [SECURITY.md](SECURITY.md). How the boundary works: [docs/architecture.md](docs/architecture.md#execution-capability).

---

## Runs where developers work

- **Linux** is the tested target. macOS and FreeBSD build but are untested. Windows is not supported.
- **One binary** with no runtime, `npm install`, Python virtualenv, or Docker. Built with `mise run build`, it is static.
- **Release binaries are Linux-only.** Linux amd64 and arm64 binaries are attached to each GitHub release. Elsewhere, install with `go install` or build from source.
- **Confined shell commands** are Linux amd64/arm64 only. Elsewhere the status bar shows `sandbox: unavailable`.
- **The structured `move` tool** is Linux-only. Elsewhere it refuses to move anything rather than risk overwriting a destination.

---

## Install

### From Binaries
See [Releases](https://github.com/commonforge-dev/codemeld/releases)


### With the Go toolchain

Needs the Go version on the `go` line of `go.mod`.

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

   For CI or servers with an API key (`codemeld run`): a headless run never loads a provider's model list, so its model must already be in `~/.codemeld/global/models.yaml`. Load the list once in the app, through `/connect` or the model picker, or copy to the host a `models.yaml` the app wrote that lists the provider and model. The host's settings file also needs the provider's entry under `provider:`, with `base_url` and `api_key`. Then pick the model with `codemeld run --model <provider>/<id>`; a model missing from `models.yaml` is rejected. For `openai` only, a set `OPENAI_API_KEY` takes precedence over the entry's `api_key` (which may then be empty) when the run sends requests. The variable does not create the entry, and the app loads the model list with the saved or pasted key, not `OPENAI_API_KEY`.

   Check your OpenAI setup with `codemeld auth status`. It reports only the OpenAI Platform key and the ChatGPT login, reads only local files, and prints no secrets; add `--json` for machine-readable output.
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

### Skills

A skill is a folder with a `SKILL.md` of instructions, in `~/.codemeld/skills/<name>/` or `<project>/.codemeld/skills/<name>/`. Start one with `/<name>` in the app, or let the model load it when a request matches its description. How to write one and how codemeld treats it: [docs/skills.md](docs/skills.md).

---

## Learn more

- [Roadmap](ROADMAP.md): released versions and planned work
- [Architecture](docs/architecture.md): the main parts, platform support, the sandbox, privacy, and the rules a change must keep
- [Permissions](docs/approvals.md): what codemeld does without asking, what it asks about, and what it refuses
- [Tech stack](docs/tech-stack.md): libraries and tooling choices
- [Design rationale](docs/RATIONALE.md): what existing tools got wrong, in the author's view

Bug reports and design feedback are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Repository:** [github.com/commonforge-dev/codemeld](https://github.com/commonforge-dev/codemeld) · **Website:** [codemeld.dev](https://codemeld.dev) (in development)

**License:** MIT. See [LICENSE](LICENSE).
