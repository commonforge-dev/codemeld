# Development setup

_Last updated: 2026-10-21_

This page is the whole "get building" story: the toolchain, the commands, and how to run the
binary. The dependency list itself is [`go.mod`](../go.mod).

## Prerequisite: mise

[mise](https://mise.jdx.dev/) installs the Go toolchain declared in
[`mise.toml`](../mise.toml) and runs every build/test task in this repo:

```sh
mise install        # installs the pinned Go version
```

There is no code generation step, and the shipped binary is built `CGO_ENABLED=0`, so a plain
build needs nothing beyond the Go toolchain. The race-detector tasks (`mise run test` and
`mise run check-race`) do need cgo and therefore the platform C toolchain — Go's race detector
requires it. The `go` directive in [`go.mod`](../go.mod) is the language-version floor.

Two Go tools are used by the checks below and are installed separately; you only need them when
you run those checks:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest   # for `mise run lint`
go install golang.org/x/tools/cmd/deadcode@latest                          # for `mise run deadcode-check`
```

`govulncheck`, used by the release-only `mise run release-check`, is **not** installed this way —
mise pins it at `v1.6.0` through its Go backend, so `mise install` provides it.

## Build, test, lint

Run these from the repository root. Use the `mise run` tasks rather than raw `go` /
`golangci-lint` invocations — they encode the correct flags and behave the same everywhere. The
full task list lives in [`docs/tech-stack.md`](../docs/tech-stack.md) → "Build & test commands".

| Command | Use it to |
|---------|-----------|
| `mise run build` | Produce the `./codemeld` binary (static, no CGO). |
| `mise run test-fast` | Run the whole suite without the race detector. |
| `mise run test` | Run the whole suite with the race detector. |
| `mise run vet` | Static checks (`mise run lint` already includes them). |
| `mise run lint` | Linting, using the checked-in [`.golangci.yml`](../.golangci.yml). |
| `mise run fmt` | Format the tree. |
| `mise run deadcode-check` | Fail if `deadcode` reports an unreachable func not listed in [`.deadcode-allow`](../.deadcode-allow). |
| `mise run oss-reference-check` | Fail if a file that ships to the public repository names an internal requirement tag, points at a directory that does not ship, or cites a task or ADR id (in Go files, only in comments). |
| `mise run check-dev` | lint → `test-fast` → wiring-stub check. The iterative loop while you work. |
| `mise run check` | lint → `test-fast` → deadcode → wiring-stub check → shipping-set reference check. The gate before you propose a change. |
| `mise run check-race` | lint → race test → deadcode → wiring-stub check → shipping-set reference check. The authoritative gate. |
| `mise run release-check` | **Release** gate, fail-fast in order: shipping-set reference check → secret scan → `go vet ./...` → `govulncheck ./...`. Only the secret scan and `govulncheck` are exclusive to it, and `govulncheck` needs network access to `https://vuln.go.dev`. |

Run **`mise run fmt`** and then **`mise run check`** before proposing a change, and
`mise run check-race` before it lands — the race build and the deadcode reachability check are
the two slow gates, so they are worth one deliberate run rather than one per edit. The
wiring-stub check runs a real check only in the maintainers' development tree; in the public
repository it does nothing and always passes. The shipping-set reference check runs in both, so
a banned reference fails the everyday gate rather than waiting for release; see
[workflow.md](workflow.md) for what it scans.

`mise run test-fast` runs the **entire** suite. To iterate on one package, call `go test`
directly — `go test ./internal/permissions` — but run the gate before you propose the change.

## Checks that fail on purpose

Three checks refuse to pass until you take one deliberate step. Never silence them by deleting a
test or blindly accepting new output.

- **System-prompt snapshots** (`internal/agentinstr/snapshot_test.go`, six saved copies in
  `internal/agentinstr/testdata/snapshots/`) fail when the assembled **normal-turn** system
  message stops matching the committed copies. They cover all four assembly sections: the five
  embedded Markdown files under `internal/agentinstr/baseprompts/`, the generated environment block
  in `internal/agentinstr/envblock.go`, and — via `base_env_only.txt` and `with_agents.txt` — how an
  empty and a populated `AGENTS.md` are assembled in. Of those, the first two are the
  product-authored prompt text this gate covers; the guided maintainer editor offers exactly the
  five Markdown files and never edits a project's `AGENTS.md` content. To accept an intended wording
  change, rewrite the copies and then assert against them:

  ```sh
  mise run snapshot-update   # rewrites the copies, then fails on purpose
  mise run check             # asserts against the new copies: now it passes
  ```

  The deliberate failure is the point: it stops the copies from quietly updating themselves.
  Never hand-edit a fixture — regenerate it. Review
  `hg diff internal/agentinstr/testdata/snapshots/` and commit the copies with the prompt change.

  These fixtures do **not** cover the other model-facing instructions — the title instruction
  (`titleSystemPrompt` in `internal/turn/titlegen.go`), the compaction instruction
  (`compactionSummaryInstruction` in `internal/turn/request.go`), or the advertised tool
  descriptions (each tool's `Advertise()` metadata, plus `internal/provider/tooldefs.go`). The title
  and compaction instructions are product-authored, editable instruction text too — they are just
  inline Go outside the normal-turn assembly. `TestGenerateTitle_RequestShape` and
  `TestBuildCompactionSummaryRequest_ExactShape` pin those two instructions, and
  `internal/provider/tooldefs_test.go` pins the three product-authored tool definitions. Registry
  metadata coverage varies by tool, with no shared exact-description test; review a registry
  description with its package tests, not `snapshot-update`. See
  [`learning/system-prompts.md`](learning/system-prompts.md) for the full inventory.

- **First-run snapshots** (`internal/bootstrap/firstrun_snapshot_test.go`,
  `firstrun_settings_test.go`) cover the first-run message and the starter
  `settings.yaml`. There is no rewrite command — edit the saved file or the expected-text constant
  by hand, only after confirming the new-user experience change is intended.

- **`scripts/deadcode-check.sh`** fails on a function nothing reachable from `main()` calls. Hook
  it up, delete it, or — for a test-only seam — add its `file Name` line to
  [`.deadcode-allow`](../.deadcode-allow) with an `// intentional: test-only seam` comment. Keep
  that list short.

  It also warns — without failing — about allowlist entries `deadcode` no longer reports. A
  stale entry means that function became reachable (or was moved, renamed, or already deleted);
  it is not authority to delete the function. Drop the allowlist line; any deletion still needs
  tracked cleanup work.

## Run it

```sh
mise run build
./codemeld          # first run generates ~/.codemeld/global/settings.yaml and exits
```

To reach an OpenAI model you pick one of the two independent OpenAI providers (they are billed
differently and neither overrides the other):

- **`openai-chatgpt` (ChatGPT subscription):** from an interactive shell, run
  `./codemeld auth login openai-chatgpt` to sign in through your browser — no API key required.
- **`openai` (Platform API key):** set `OPENAI_API_KEY`, or edit
  `~/.codemeld/global/settings.yaml` and add an OpenAI Platform key under `provider:`. This is the
  path for CI, servers, and other non-interactive setups.

Run `./codemeld auth status` to see which providers are authenticated (it prints no secrets), then
run `./codemeld` inside any project folder. See the top-level [`README.md`](../README.md) "Quick
start" for the full first-run flow,
[`docs/architecture.md`](../docs/architecture.md#openai-authentication-two-separate-providers) →
"OpenAI authentication: two separate providers" for how the two providers differ, and that page's
[Overview](../docs/architecture.md#overview) for what startup sets up.

Run `./codemeld config check` to validate your settings files without starting a session. It
writes nothing and never approves a project.

A launch composes three settings layers, named by kind and listed farthest to nearest: `global`
(`~/.codemeld/global/settings.yaml`), `project` (the shared `.codemeld/settings.yaml` a team
commits), and `local` (`.codemeld/settings.local.yaml`, this machine's own settings, which wins
over the other two). The command checks them like this:

- **No argument:** it checks the global file, then the project's shared `.codemeld/settings.yaml`,
  found the way `discovery.boundary` says. It does not yet validate `.codemeld/settings.local.yaml`.
- **A path argument** (`./codemeld config check .codemeld/settings.yaml`): it checks only that
  file and does no project discovery. The global settings path is checked under the global
  layer's rules; any other path — including a `settings.local.yaml` — is checked under the project
  layer's rules, which do not apply the local file's narrower list of accepted keys. A relative
  path is reported as an absolute one.

It prints one line per layer, `<path> (<rules>): <state>`, where `<rules>` is
`global layer rules` or `project layer rules`:

| State | Meaning |
|-------|---------|
| `ok` | The file loads under those rules. |
| `not present` | There is no file at that path. This is not a failure: most projects have no settings file, and a missing global file is reported, not generated. |
| `present, not approved` | The shared project settings file exists in a project you have not approved yet, so it was not parsed. Until you approve the project, a launch ignores both of its project-scope files — `.codemeld/settings.yaml` and `.codemeld/settings.local.yaml` — though this line names only the shared one. The lines that follow say how to approve the project and give the command that checks the file directly. |
| `failed to load` | Followed by the same what happened / to fix message a launch prints, stating that codemeld would not start with this file in place. |

The command exits `1` when any checked layer fails to load — `not present` and
`present, not approved` do not fail it — and also exits `1`, with an error on stderr and no report,
when it cannot resolve your home or working directory. Passing more than one path is a usage error
and exits `2`. Otherwise it exits `0`.

## Optional: clipboard image paste

Pasting an image from the system clipboard with **CTRL-V**
shells out to an external
helper, so install one if you want that feature — it is entirely optional and codemeld shows a
friendly message when none is present:

- **Wayland:** `wl-paste` (from `wl-clipboard`)
- **X11:** `xclip` (or `xsel`)
- **macOS:** `pngpaste`

codemeld picks the right helper for your session automatically. Nothing is bundled; these are
plain runtime tools, and each is strictly optional.

## Platform note

Linux is the tested platform: `mise run check` builds codemeld and runs the test suite there, and
there is no hosted CI. macOS and FreeBSD build but are untested. Windows is not supported: codemeld
does not compile for it. Confined shell execution works only on Linux amd64 and arm64; every other
platform runs shell commands unconfined with ordinary prompts. There is **no CGO**, so the
binary is a single static file with no runtime dependencies. See the Per-OS Gates table in
[`docs/architecture.md`](../docs/architecture.md#per-os-gates).
