# Answer key — Module 1: Orientation

Citations are to the docs (this module is orientation, not code-diving).

---

**1.** Permissions that respect your time; no vendor lock-in; any VCS (not just git); zero
phone-home; single static binary. (README → "What sets it apart".)

**2.** The internal provider contract **is** the OpenAI chat-completions shape. You add a provider
by editing `settings.yaml` — a `provider.<name>` block with `base_url`, `api_key`, and `models` —
not by changing code. Built-in adapters ship for OpenAI and OpenRouter (and OpenRouter reaches
Claude, Gemini, Llama, etc.). (README → "No vendor lock-in".)

**3.** git, Mercurial (hg), and Jujutsu (jj). Add another by dropping a YAML template at
`~/.codemeld/vcs/<name>.yaml` — no fork, no code change. (README → "Any VCS, not just git".)

**4.** Only **sanctioned, origin-scoped destinations**. The primary egress is the configured LLM
provider client (`NewClient` in `internal/provider/client.go`). The only other sanctioned egress is
the built-in `openai-chatgpt` auth/Codex path, pinned to OpenAI-owned origins —
`https://auth.openai.com` (login, token refresh, logout) and `https://chatgpt.com/backend-api/codex`
(ChatGPT model requests) — and not user-overridable. Enforced by (a) an automated no-network test
that fails if any HTTP call targets a host outside the configured allowlist, and (b) a code-review
rule that any other network call is a bug. (docs/architecture.md → "Privacy & Telemetry"; README →
"Zero phone-home".)

**5.** To ship a single static binary with no runtime dependencies. It excludes (any two of):
tree-sitter C bindings, embedded SQLite, libgit2, libseccomp. (docs/architecture.md → "No CGO in
phase 1".)

**6.** The root is marked by `.codemeld/settings.yaml` and is *never* VCS-inferred — that would create
a circular bootstrap (user VCS templates load relative to the project root, but VCS detection would
itself *produce* that root) and non-VCS projects should work without a special case. The default
`launch-dir-only` discovery mode checks **only** the launch directory for the marker; the opt-in
`project-root` mode walks upward to the **innermost** directory containing it. (docs/architecture.md →
"Project root: marked by `.codemeld/settings.yaml`".)

**7.** Primary: Linux, FreeBSD, macOS. Best-effort/secondary: Windows. (docs/architecture.md →
"Platform Support".)

**8.** `docs/architecture.md` is the source of truth for phase-1 cross-cutting behavior (with
`docs/RATIONALE.md` for the "why" and `docs/ROADMAP.md` for scope). In the source, a file's top doc
comment states the non-obvious constraint *in words*, and the table-driven `_test.go` files pin the
exact behavior — the tests are the executable spec.

**9.** Settings (`settings.yaml`) and VCS templates are **human-authored YAML**, annotated with
comments at generation time. Sessions are **machine-written JSON**, one document per session,
written atomically (temp file + rename) for crash safety. YAML for humans, JSON for machines.
(docs/architecture.md → "Config: YAML for humans, per-session JSON for machines".)

**10.** No — deliberately. There is no YOLO toggle; if you want unattended runs, you build a sandbox
*around* codemeld. (README → "No 'approve everything' mode".)
