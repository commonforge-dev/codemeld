# Tech Stack

## Backend

- **Language**: Go (version pinned in `mise.toml` and the `go` directive in `go.mod`)
- **CLI**: https://github.com/urfave/cli (flags and subcommands)
- **TUI**: https://github.com/rivo/tview (built on tcell) — higher-level widgets (flex, tables, forms), imperative API
- **Markdown**: https://github.com/yuin/goldmark (pure Go, no CGO) — parser/AST only, feeding a custom tview-tag renderer for assistant replies; goldmark's HTML renderer is discarded
- **LLM client**: openai-go. Its chat-completions client, pointed at each provider's base URL, serves every provider except OpenAI ChatGPT; the OpenAI chat-completions shape is codemeld's internal provider contract. The OpenAI ChatGPT provider instead sends Responses API requests over `net/http` to a fixed ChatGPT origin and converts the streamed events back into openai-go chat-completion chunks.
- **Providers**: built in — OpenAI Platform (API key), OpenAI ChatGPT (ChatGPT sign-in, Responses API), OpenRouter, and Venice; any other OpenAI-compatible provider can be added under `provider.<name>` with a `base_url` in settings
- **YAML**: https://github.com/goccy/go-yaml (chosen over gopkg.in/yaml.v3 for better error messages)
- **Config schema validation**: https://github.com/santhosh-tekuri/jsonschema; CUE was considered and rejected as overkill for current needs
- **Diff rendering**: https://github.com/aymanbagabas/go-udiff (a copy of the Go tools' internal diff package, Myers algorithm) — renders the unified-diff preview of `edit` tool changes
- **Logging**: no logging framework and no log file by default — session transcripts serve as the audit trail. log/slog (stdlib) appears only as a discard logger that silences the MCP library.
- **Embedded assets**: embed.FS for built-in VCS templates
- **File locking**: https://github.com/gofrs/flock (pure Go; `flock(2)` on a dedicated `.lock` sidecar; used so concurrent writes to the shared settings file and session sidecars stay atomic). The library also supports Windows, but that does not make codemeld build there.
- **UUIDv7 generation**: https://github.com/google/uuid (pure Go, no CGO; `uuid.NewV7()` per RFC 9562 — used for session ids and per-record ids). Migrate to Go stdlib `uuid.NewV7()` when Go 1.27 is the project's minimum supported version.
- **Landlock**: https://github.com/landlock-lsm/go-landlock (pure Go, no CGO) — used only by `internal/enforce` to restrict confined commands; always through the ABI 3 ruleset, never `BestEffort`
- **seccomp**: https://github.com/elastic/go-seccomp-bpf (pure Go, no CGO) — used only by `internal/enforce`, for its amd64/arm64 syscall tables; the deny filter is assembled with `golang.org/x/net/bpf` and installed with `TSYNC`
- **MCP client**: https://github.com/mark3labs/mcp-go (pure Go, no CGO) — confined to the private Exa web-search adapter in `internal/webresearch/exa`, which speaks Streamable HTTP to the single fixed endpoint `https://mcp.exa.ai/mcp` and calls only the `web_search_exa` tool. Codemeld is not a general MCP host: no remote prompt, resource, server-advertised tool, or discovered capability is exposed to the model, and MCP types do not cross out of that package. The library reads response bodies without a caller-configurable limit and surfaces no typed HTTP status, so the adapter wraps its injected HTTP client in a bounded status-preserving transport.

## Constraints

- **Single static binary per platform**. Linux is the tested target: `mise run check` builds codemeld and runs the test suite there, and there is no hosted CI. macOS and FreeBSD build but are untested. Windows is not supported: codemeld does not compile for it. Confined shell execution works only on Linux amd64 and arm64.
- **No CGO in the shipped binary today** — this excludes tree-sitter bindings, embedded sqlite, and anything else that requires a C toolchain on the build host. Revisit when the constraint becomes limiting.
- **No outbound network traffic** other than to configured LLM providers, the fixed OpenAI ChatGPT login and model origins when that provider is used, and web research hosts a human approved (`mcp.exa.ai` for search; the fetched page and its redirect hops for `web_fetch`). No analytics, telemetry, crash reporting, or update checks. See [Privacy & Telemetry](architecture.md#privacy--telemetry).

## Optional runtime dependencies

These are external command-line tools codemeld shells out to when present. They are **not
vendored or embedded** — the single static binary does not bundle them — and each is
strictly optional: the feature degrades to a friendly notice when none is installed.

- **Clipboard image helpers (CTRL-V "paste image from clipboard"):** one of
  `wl-paste` (Wayland), `xclip` or `xsel` (X11), or `pngpaste` (macOS). codemeld detects the
  right one at runtime per platform/session and reads the image off the OS clipboard through a
  bounded local subprocess (no extra network egress). With none installed, or with no image on
  the clipboard, CTRL-V shows a one-line message and does nothing. (CTRL-V is the image-paste
  key; CTRL-SHIFT-V / right-click stays the terminal's own text paste.)

## Development

- **Tooling manager**: mise (pins Go and `govulncheck`; `golangci-lint` and `deadcode` are installed separately — see `contributing/setup.md`)
- **Package manager**: go mod
- **Linting**: golangci-lint (configured in `.golangci.yml`)
- **Formatting**: gofmt
- **Testing**: go test with the standard library `testing` package; no assertion library

### Build & test commands

Use the mise tasks, not raw `go`/`golangci-lint` invocations — they encode the correct flags:

- `mise run build` — builds `./cmd/codemeld` into a `./codemeld` static binary at the repo root (`CGO_ENABLED=0`)
- `mise run test` — `go test -race ./...` (race detector; cgo defaults on, which `-race` requires)
- `mise run test-fast` — `go test ./...` (no race detector; faster, reuses the normal build cache)
- `mise run fuzz-slash` — `go test ./internal/tui -run=^$ -fuzz=FuzzSlashParse -fuzztime=30s` (local slash-parser fuzz run; future hosted CI should call this task once an external CI runner is chosen)
- `mise run vet` — `go vet ./...`
- `mise run lint` — `golangci-lint run` (includes the `govet` analyzers, so it subsumes `mise run vet`)
- `mise run fmt` — `gofmt -w .`
- `mise run check-dev` — lint → `test-fast` → `wiring-stub-check`, fail-fast. The iterative review-fix/dev loop; it deliberately skips `deadcode-check` so deadcode does not become a repeated review-round penalty.
- `mise run check` — lint → `test-fast` → `deadcode-check` → `wiring-stub-check` → `oss-reference-check`, fail-fast. The final local gate before proposing a code change. It omits a separate `go vet` (lint already runs govet) and skips the race detector to stay fast.
- `mise run snapshot-update` — `CODEMELD_UPDATE_SNAPSHOTS=1 go test ./internal/agentinstr/...`: the one command that rewrites the system-prompt golden fixtures. It fails on purpose after rewriting them; review the diff, then run `mise run check`. See gate 1 in `docs/gated-changes.md`.
- `mise run check-race` — lint → `test` (race) → `deadcode-check` → `wiring-stub-check` → `oss-reference-check`, fail-fast. The authoritative gate; run it once at the integration boundary, before pushing.
- `mise run release-check` — the **release** gate: runs `oss-reference-check` → `oss-secret-scan` → `go vet ./...` → `govulncheck ./...`, fail-fast, so the first failing check stops the rest. Only the secret scan and `govulncheck` are exclusive to it; the reference check already ran in `check` / `check-race`. `go vet` runs standalone here so the release gate does not lean on the lint task, and `govulncheck` checks the module against the Go vulnerability database. Run it before exporting to the public repo. `mise run oss-gate-selftest` exercises the scanners against fixtures.

So race coverage moves from every dev iteration to the integration boundary: a data race surfaces when work is integrated rather than on each local gate, but still before it leaves `main/`. Static reachability and the shipping-set reference check run in `check` and `check-race`; all three gates call `wiring-stub-check`, but the real stale-stub check runs only in the development tree, where a development-only mise overlay that does not ship replaces it. In the public tree `wiring-stub-check` is an intentionally inactive step that does nothing.

The two open-source scans are split by what they cost to run. `oss-reference-check` is a local scan over the shipping-file list (grep, plus a small awk lexer that pulls the comment text out of Go files), so it runs in `check` and `check-race` as well as `release-check`: it fails if a shipping file reintroduces an internal requirement-number tag, a pointer to internal-only files, or a task or ADR id (in Go files, only in comments), and keeping it in the everyday gates stops that drift at the edit that caused it rather than at release. `oss-secret-scan` stays release-only — it fails on credential-shaped values, session-dump paths, or private developer-machine paths inside a shipping file, and those only have to be absent when the project ships. Both read one shared shipping-file list (`scripts/oss-shipping-files.sh`) so they cannot drift. That list is built with `find` over the shipping roots rather than from the VCS manifest, so an untracked scratch file under one of them is scanned like a committed one. See `docs/gated-changes.md` for the fix steps.

The release gate also runs the Go vulnerability scanner. mise pins `govulncheck` at `v1.6.0` through its Go backend, so `mise install` provides it and no separate `go install` is needed. `govulncheck ./...` consults the Go vulnerability database at `https://vuln.go.dev`, so `release-check` needs outbound network access and fails if the database is unreachable or if a reachable vulnerability is reported. That network round-trip is why it stays out of `check` / `check-race`: an everyday gate must not fail because a remote database was unreachable.

Some changes are **deliberately gated** behind a special step — a check refuses to pass until you do something explicit (e.g. regenerating the system-prompt golden snapshots with `mise run snapshot-update`, satisfying the deadcode allowlist, or re-pointing a wiring stub). If `mise run check` fails with one of those gate messages, see `docs/gated-changes.md` for what fired it and the exact step to satisfy it.

The shipped binary stays cgo-free via `build` (`CGO_ENABLED=0`); the race detector in `test`/`check-race` needs cgo, so the current no-CGO constraint applies to the binary, not the test toolchain.

## Conventions

### Code Style
- Follow gofmt for Go

### VCS
- Mercurial for VCS (the codemeld project itself uses hg; the shipped binary supports git/hg/jj via templates)
- Conventional commits
- Feature branches off main

### Provider adapter authoring

An adapter carries connection defaults only — provider name, default base URL, and default auth header. Adapters declare no model lists and no reasoning-effort data.

Selectable reasoning efforts come solely from provider-discovered capability metadata held in the system-owned `models.yaml` store; a model with no usable cached metadata resolves to `no-reasoning`. Assert effort levels in the cache-driven catalog tests, not in a per-adapter table.

## Deferred

- **General MCP host support** (arbitrary user-configured MCP servers, remote prompts, resources, and discovered tools): The `mcp-go` use above is the Exa search adapter only.
- **LSP client**: go.lsp.dev/protocol
- **Tree-sitter**: https://github.com/smacker/go-tree-sitter (blocked on no-CGO constraint)
- **Anthropic native SDK**: anthropic-sdk-go (Anthropic reachable via OpenRouter until then)
- **Sandboxing runtime**: not deferred — confinement has shipped for Linux amd64 and arm64 hosts whose startup self-test passes, built on the Landlock and seccomp libraries above inside `internal/enforce`; every other platform runs shell commands unconfined with ordinary prompts. There is no bwrap, firejail, or container runtime, and no opt-out setting or noop backend.
- **Pre-apply scanning**: gitleaks (secrets), semgrep, gosec (SAST) — shelled out, not embedded
