# Module 15 — OpenAI ChatGPT authentication

_Snapshot as of 2026-09-23; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-09-23_

ChatGPT subscription access (ChatGPT Plus/Pro) as a **separate built-in provider**, selected in
the model picker like any other. The existing OpenAI Platform API-key provider (`openai`) is
unchanged; the subscription path is a new provider with the stable id `openai-chatgpt`. This module
covers the shipped implementation: the `codemeld auth` command surfaces, where credentials
live, and the egress boundary the feature must keep.

## Goal

Afterward you can explain why ChatGPT access is a *separate provider* (not a second credential on
`openai`), name the `auth` subcommands and what each touches, say exactly where ChatGPT credentials
are stored and which origins they may reach, and point at the code that enforces all of this.

## Why it matters (and the seams it touches)

The defining design decision: rather than layering a second credential onto one OpenAI provider and
resolving it by hidden precedence, codemeld models the subscription as **its own provider**. The
active credential always follows the selected model — there is no cross-provider precedence chain to
reason about, and no silent shadowing of one credential by another.

- **The provider seam (Module 8).** Today `provider.NewClient` speaks the OpenAI chat-completions
  wire shape and resolves one auth header. The `openai-chatgpt` provider needs a **different
  adapter** (the ChatGPT/Codex Responses API) and an **OAuth login** flow instead of a static API
  key — the first real second shape behind the provider abstraction.
- **It is still a sanctioned provider path.** Even though it adds OAuth and is built in rather than
  configured through `provider:`, it routes through the provider/auth seams and must not loosen the
  [network invariant](../invariants.md): ChatGPT credentials reach **only** the approved
  OpenAI origins (pinned in code, listed below) and never become telemetry or arbitrary egress.
- **Credentials stay out of logs.** Access tokens, refresh tokens, the account id, and auth headers
  are never logged, written to transcripts, emitted in events, or printed in errors;
  connect this to the session/event audit log (Module 7).
- **Credential storage follows the phase-1 config posture.** ChatGPT session tokens are plaintext
  global settings state, like provider API keys: global-only placement, `0600` writes, settings-file
  locking, and no leakage to project settings or transcripts.

## Read (in order)

- [`docs/architecture.md`](../../docs/architecture.md) → "Privacy & Telemetry" and "No outbound
  network traffic except to sanctioned, origin-scoped destinations" — the egress policy this
  provider must hold while adding OAuth login.
- [`internal/cli/auth.go`](../../internal/cli/auth.go) — the `auth login` / `auth logout` actions:
  provider-id routing, interactive-context gating, the upstream login flow, best-effort revocation,
  and local deletion.
- [`internal/cli/root.go`](../../internal/cli/root.go) (`newAuthCommand`, `runAuthStatus`) — how the
  `auth` command tree, including `auth status --json`, is wired under root.
- [`internal/authstatus/status.go`](../../internal/authstatus/status.go) — the offline status report
  and its closed JSON enums (`kind`, `source`, `state`).
- [`internal/bootstrap/provider_refresh.go`](../../internal/bootstrap/provider_refresh.go)
  (`discoverAndStoreChatGPT`) and [`internal/tui/picker_model.go`](../../internal/tui/picker_model.go)
  (`refreshableProvider`, `forceRefreshHighlightedProvider`) — the model picker's forced `Ctrl-R`
  refresh of the ChatGPT model list.
- That refresh replaces only the `openai-chatgpt` cache entry, keeps the prior catalog on failure,
  and leaves rendering and `auth status` offline.

## The command surface (landed)

| Command | What it does |
|---------|--------------|
| `codemeld auth status` | Offline report of both providers' state; prints no secrets. |
| `codemeld auth status --json` | Same report as script-friendly JSON with closed enums. |
| `codemeld auth login openai-chatgpt` | OAuth2 + PKCE browser login (device-code fallback); stores the session only after upstream login succeeds. Requires an interactive terminal. |
| `codemeld auth logout openai-chatgpt` | Best-effort upstream revocation, then deletes the local session. Idempotent: no session → exits 0. |
| `codemeld auth login openai` | **Rejected** — `openai` is the API-key provider, not a browser login. |
| `codemeld auth logout openai` | **Rejected** — the Platform provider keeps no login session to remove. |

In the TUI model picker, highlight any `openai-chatgpt` model and press **`Ctrl-R`** to refresh the
ChatGPT model list from your stored session. It is the only way the picker fetches ChatGPT models:
opening the picker or moving the highlight never does.

## Mental model (the few facts to internalize)

- **Two provider ids.** `openai` = OpenAI Platform, API-key auth (`OPENAI_API_KEY` or
  `provider.openai.api_key`), the path for CI/servers/automation/commercial use. `openai-chatgpt` =
  OpenAI ChatGPT, a stored login session for individual interactive use. The `openai-chatgpt` id is
  **reserved** — a `provider.openai-chatgpt` config entry is a load-time error.
- **Storage.** The ChatGPT session lives under `auth.openai-chatgpt` in
  `~/.codemeld/global/settings.yaml` (`bootstrap.SettingsPath`), written through the settings sidecar
  lock at mode `0600`. It is plaintext — there is no OS keychain in phase 1.
- **Status is offline.** `authstatus.Collect` reads only `OPENAI_API_KEY` and the global settings
  file, builds no provider client, and makes no network call. It classifies each provider
  independently with no cross-provider precedence.
- **Egress is pinned.** ChatGPT credentials go only to `https://auth.openai.com` (login, refresh,
  logout revocation) and `https://chatgpt.com/backend-api/codex` (model requests). The
  `http://localhost:1455` loopback during login is a local callback, not outbound egress.
- **Picker refresh is forced-only and uses the stored session.** `Ctrl-R` on a highlighted ChatGPT
  model runs one background refresh. It first calls the same proactive token refresh a turn uses
  (`EnsureFreshSession`): a fresh token is used as is, a token near expiry is renewed against
  `auth.openai.com` and saved. It then requests the model list from the pinned
  `chatgpt.com/backend-api/codex` origin and, on success, replaces only the `openai-chatgpt` entry
  in the `models.yaml` cache beside global settings. The picker stays open throughout.
- **No session means guidance, not a login.** If no session is stored or it cannot be renewed, the
  picker shows `run codemeld auth login openai-chatgpt`. It never opens a browser or starts a
  device-code login, and the cached list and your selected model do not change.
- **A failed refresh keeps the old list.** A timeout, upstream error, or cache-write failure reports
  "could not refresh" and leaves the prior cache, picker rows, and selection as they were.
- **Redaction.** No token, refresh token, account id, auth header, PKCE verifier, authorization
  code, or device code is ever printed or logged on any path, including failures.

## Watch for (Go idioms)

- **Package-local seams.** `auth.go` swaps `isInteractiveContext`, `runChatGPTLoginFlow`,
  `storeChatGPTSession`, `revokeChatGPTSession`, and `deleteChatGPTSession` for fakes in tests so the
  command runs without a TTY, real network, or a real settings write. The production defaults are the
  `live*` functions and the `authstate` writers.
- **Typed, credential-free errors.** `loginErrorMessage` matches `*openaiauth.Error` by `Kind`
  (canceled/timeout/unsupported/upstream) so the user sees an actionable message while the detail
  string is guaranteed free of secrets.
- **Closed enums as types.** `authstatus` models `Kind`, `Source`, and `State` as string types with a
  fixed set of constants, so the JSON contract scripts depend on cannot silently grow a new value.

## Unresolved permission risk (do not gloss over this)

codemeld does **not** claim official OpenAI approval for the ChatGPT flow. It reuses the Codex client
id and there is no confirmed third-party client-registration path. User-facing text says it is
user-initiated, oriented at individual interactive use, and dependent on upstream ChatGPT/Codex
access that OpenAI may change or revoke. If upstream policy, terms, or controls later disallow the
flow, the feature is **stopped, disabled, or removed** rather than bypassing those controls.
When you touch this area, keep that framing — never imply approval or a
supported automation path.

## Hands-on (open-book)

1. **Trace a login.** Follow `runAuthLogin` → `runChatGPTLogin` in `internal/cli/auth.go`. List every
   point at which the command exits non-zero **before** any storage write, and confirm the session is
   persisted only after `runChatGPTLoginFlow` returns successfully.
2. **Predict, then verify, status output.** Without a configured key or session, predict the two
   human lines `codemeld auth status` prints, then read `humanLine` in
   `internal/authstatus/status.go` to check. Now predict the JSON `state` values for each provider.
3. **Find the egress boundary in code.** Locate where the approved OpenAI origins are pinned (start
   from `internal/openaiauth`) and confirm the base URL is not user-overridable.
4. **Trace a picker refresh.** Start at the `tcell.KeyCtrlR` case in `internal/tui/picker_model.go`
   and follow it to `discoverAndStoreChatGPT` in `internal/bootstrap/provider_refresh.go`. Find why
   an unforced ChatGPT request (picker open or highlight) is refused, which outcome a missing
   session maps to and what the picker shows for it, and where a failure returns before the
   `models.yaml` write.
5. **Confirm redaction.** Read `TestTurnController_ChatGPTHTTPFailureRedactsCredentialsAcrossLayers`
   (`internal/bootstrap/turndeps_test.go`) and name the three surfaces it proves a
   credential never reaches.

## Done when

- You can explain why ChatGPT access is a *separate provider* rather than a second credential on the
  `openai` provider.
- You can name the four `auth` commands, what each touches, and why `auth login openai` is rejected.
- You can say where the ChatGPT session is stored, at what mode, and which origins it may reach.
- You can explain why `auth status` is offline and prints no secrets.
- You can say what `Ctrl-R` does for a ChatGPT model in the picker, what happens without a usable
  session, and why a failed refresh changes nothing.
- You can state the unresolved OpenAI permission risk and the stop/disable/remove path without
  implying approval.

## Quiz

Closed-book check: [`quizzes/module-15.md`](quizzes/module-15.md) (answers in
[`quizzes/module-15-key.md`](quizzes/module-15-key.md)). It covers provider separation, the `auth`
commands, credential storage, the pinned origins, redaction, the picker's `Ctrl-R` model refresh,
and the unresolved OpenAI permission risk. Use the open-book hands-on above as the warm-up.
