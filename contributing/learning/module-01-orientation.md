# Module 1 — Orientation: what codemeld is and why

_Snapshot as of 2026-08-05; it may be out of date — refresh it from the code before studying._

> Start here. This module is mostly reading and running, not code-diving. Its job is to give you
> the *whole* before the parts, so every later module slots into a frame you already have.

## Goal

After this module you can:

- Explain in plain terms what codemeld is and the problem it solves.
- Name the **five things it deliberately does differently** and the mechanism or promise behind each.
- List the **hard constraints** that shape the entire codebase (and will explain odd-looking decisions later).
- Say where the authoritative documents live and what each is for.

## Why it matters

Every other module is a subsystem of this whole. If you know the five differentiators and the
constraints, you can predict *why* a package is built the way it is before you read a line of it.

## Read (in order)

1. `README.md` — the positioning, the five differentiators, the quick-start flow.
2. `docs/RATIONALE.md` — what the author thinks existing agentic editors got wrong (the "why build this").
3. `docs/architecture.md` — Overview, Platform Support, Privacy & Telemetry, and "Cross-cutting
   design decisions". This is where the constraints are stated.
4. `docs/tech-stack.md` — the libraries chosen and why each one.
5. `docs/ROADMAP.md` — the phase 1 / 2 / 3 scope, so you know what's in the baseline and what's
   deliberately deferred.

## Mental model

### What it is

codemeld is a **terminal-UI (TUI) agentic code editor**: a language model helps you write code in
your own project, from your own terminal. It ships as a **single static binary** and is built to
avoid four things developers dislike in other tools — vendor lock-in, permission re-prompt fatigue,
VCS assumptions, and telemetry.

### The five differentiators (and the mechanism behind each)

| # | Differentiator | Mechanism | Studied in |
|---|----------------|-----------|------------|
| 1 | **Permissions that respect your time** | Approve an operation *once*; equivalent spellings collapse to one canonical subject; grants are path-scoped with three lifetimes; no "approve everything" mode. | Module 5 |
| 2 | **No vendor lock-in** | The internal provider contract *is* the OpenAI chat-completions shape; built-in adapters for OpenAI and OpenRouter; new providers are a **config edit**, not a code change. | Module 8 |
| 3 | **Any VCS, not just git** | Version control is expressed as **YAML templates** (git, Mercurial, Jujutsu built in); add one by dropping a YAML file in `~/.codemeld/vcs/`. | Module 9 |
| 4 | **Zero phone-home** | Outbound traffic goes **only** to sanctioned, origin-scoped destinations — the configured provider client (primary) and the built-in `openai-chatgpt` auth/Codex path; enforced by code review and an automated no-network test. | Modules 1 & 8 |
| 5 | **Single static binary** | No CGO, no runtime, no installer; primary targets Linux/FreeBSD/macOS, Windows best-effort. | this module |

### The constraints that shape everything

These appear over and over; learn them now and later code stops looking arbitrary:

- **No CGO in phase 1** → single static binary; excludes tree-sitter C bindings, embedded SQLite,
  libgit2, libseccomp. Pure-Go, shell out, or defer.
- **No outbound network except to sanctioned, origin-scoped destinations** → the configured provider
  client plus the built-in `openai-chatgpt` auth/Codex path; verified by code review and a no-network test.
- **Tool dispatch is exact-name** → the registry is a flat `map[string]Tool`; no regex/pattern routing.
- **Project root is marked by `.codemeld/settings.yaml`, never inferred from VCS** (that would break a
  bootstrap chicken-and-egg between VCS template loading and VCS detection). The default
  `launch-dir-only` discovery mode checks only the launch directory for that marker; the opt-in
  `project-root` mode walks upward to the innermost marker.
- **Cross-platform parity or an explicit per-OS gate** (the gate table is in `docs/architecture.md` → "Platform Support").
- **YAML for humans, per-session JSON for machines**; durable files written atomically.

### Where the documents live

| Document | Role |
|----------|------|
| `docs/architecture.md` | Cross-cutting constraints and design decisions. The source of truth for phase-1 behavior. |
| `docs/RATIONALE.md` | Why codemeld exists; critique of other tools. |
| `docs/ROADMAP.md` | Phase 1 / 2 / 3 scope. |
| `docs/tech-stack.md` | Libraries and why each one was chosen. |

## Watch for (how to read this repo)

- **Doc comments state the constraint, not a number.** A file's top doc comment explains the
  non-obvious *why* in words. When a decision looks odd, that comment — or the package's tests —
  usually explains it.
- **The package layout is the index.** Before grepping, skim `internal/` — each subsystem is its
  own package (`permissions`, `config`, `sessions`, `provider`, `vcs`, `tui`, …), so the directory
  name tells you where to look.
- **Tests are the spec.** Behavior is pinned by table-driven `_test.go` files; when in doubt about
  an edge case, the test answers faster than prose.

## Quiz

Closed-book: [`quizzes/module-01.md`](quizzes/module-01.md). Grade against
[`quizzes/module-01-key.md`](quizzes/module-01-key.md).

## Hands-on (open-book)

**A. Build and run it.** Run `CGO_ENABLED=0 go build -o codemeld ./cmd/codemeld`, then
`./codemeld`. The first run
generates `~/.codemeld/global/settings.yaml` and exits. Open that file and read the generated
comments — they document what each setting means. (See [`../setup.md`](../setup.md).)

**B. Trace the sanctioned egress paths.** Predict which outbound destinations codemeld is allowed to
reach. Then verify: find the primary provider client (`internal/provider/`, function `NewClient`) and
the other sanctioned path (`internal/provider/openai_chatgpt_client.go` with
`internal/openaiauth/oauth.go`, pinned to `https://chatgpt.com/backend-api/codex` and
`https://auth.openai.com`). What does keeping egress origin-scoped buy the project?

**C. Map the tree to the differentiators.** List the directories under `internal/` (e.g.
`ls internal/`). Match at least five of them to the differentiator or subsystem they implement
(hint: `permissions`, `provider`, `vcs`, `sessions`, `tui`). Note which differentiator each serves.

## Done when

- You can recite the five differentiators and the constraints without looking.
- You built and ran codemeld and read its generated settings file.
- You found the sanctioned egress paths and can say how the "zero phone-home" promise is enforced.
