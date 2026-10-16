# Answer key — Module 15: OpenAI ChatGPT authentication

_Last updated: 2026-09-23_

Citations are **file + function/symbol name**, not line numbers — lines drift as the code
changes, but a function name stays findable. Search (or your editor's "go to symbol") lands you
on the exact code.

---

**1. Separate provider, not a second credential.**
The two ids: `openai` = OpenAI Platform (API-key auth via `OPENAI_API_KEY` or
`provider.openai.api_key`, the path for CI/servers/automation), and `openai-chatgpt` = OpenAI
ChatGPT, a stored login session for individual interactive use. Modelling the subscription as its
**own provider** means the active credential always follows the selected model — there is **no
cross-provider precedence chain** to reason about and no silent shadowing of one credential by
another. The `openai-chatgpt` id is **reserved**: a `provider.openai-chatgpt` config entry is a
**load-time error**, so the built-in provider can never be shadowed by a user-configured one.

**2. The command surface.**
- `codemeld auth status` — offline report of both providers' state; prints no secrets.
- `codemeld auth status --json` — the same report as script-friendly JSON with closed enums.
- `codemeld auth login openai-chatgpt` — OAuth2 + PKCE browser login (device-code fallback); stores
  the session **only after** upstream login succeeds; requires an interactive terminal.
- `codemeld auth logout openai-chatgpt` — best-effort upstream revocation, then deletes the local
  session; idempotent (no session → exits 0).

`auth login openai` and `auth logout openai` are **rejected** because `openai` is the API-key
Platform provider: there is no browser login to perform and no stored login session to remove.
Wiring is `newAuthCommand` / `runAuthStatus` (`internal/cli/root.go`) over the actions in
`internal/cli/auth.go`.

**3. Login ordering.**
In `runChatGPTLogin` (`internal/cli/auth.go`) the command exits non-zero **before** any storage
write when: the context is not interactive (`isInteractiveContext` fails — no TTY), and when the
upstream login flow (`runChatGPTLoginFlow`) returns an error (canceled/timeout/unsupported/upstream).
The invariant: `storeChatGPTSession` is called **only after** `runChatGPTLoginFlow` returns
successfully — a failed or aborted login never persists a partial session.

**4. Storage.**
The ChatGPT session lives under the `auth.openai-chatgpt` key in
`~/.codemeld/global/settings.yaml`, whose path comes from `bootstrap.SettingsPath`. It is written
through the **settings sidecar lock** at mode **`0600`**. It is **plaintext** — there is no OS
keychain in phase 1, so the `0600` mode (owner-only) is what keeps the token off group/world reads.
Writers are the `authstate` helpers.

**5. Status is offline.**
`authstatus.Collect` (`internal/authstatus/status.go`) reads **only** `OPENAI_API_KEY` and the
global settings file. It builds **no** provider client and makes **no** network call. It classifies
each provider **independently** — there is no cross-provider precedence — emitting the closed
`Kind`/`Source`/`State` enums (string types with a fixed constant set) so the JSON contract cannot
silently grow a new value.

**6. Pinned egress.**
- `https://auth.openai.com` — login/token/refresh/logout-revoke traffic, via
  `openaiauth.Flow.postForm` (`internal/openaiauth/oauth.go`); pinned by the `productionAuthBaseURL`
  constant, set in `NewFlow` into the unexported `authBaseURL` field.
- `https://chatgpt.com/backend-api/codex` — model (Responses API) requests, via
  `provider.NewChatGPTClient` (`internal/provider/openai_chatgpt_client.go`); pinned by the
  `chatGPTCodexBaseURL` constant into the unexported `baseURL` field, with redirect pinning so a 3xx
  cannot carry credentials off-origin.

Neither origin is overridable by a setting, environment variable, custom provider, or user base URL
— the fields are unexported and only same-package tests substitute a stub. `http://localhost:1455`
is the **loopback callback** the browser redirects to during PKCE login; it is a local listener, not
outbound egress.

**7. Redaction.**
Never printed or logged on any path (including failures): the access token, refresh token, account
id, auth header, PKCE verifier, authorization code, and device code.
`TestTurnController_ChatGPTHTTPFailureRedactsCredentialsAcrossLayers`
(`internal/bootstrap/turndeps_test.go`) proves a credential never reaches the three surfaces: the
committed **surface notice**, the **persisted session JSON**, and the **`provider_request_failed`
event** payload. (Adapter-level coverage: `TestChatGPTClient_HTTPErrorRedactsCredentials` and
`TestChatGPTClient_StreamErrorRedactsCredentials`.)

**8. The package-local seams.**
Any three of (swapped for fakes in tests, production default in parentheses):
`isInteractiveContext` (real TTY check), `runChatGPTLoginFlow` (the `live*` login flow),
`storeChatGPTSession` / `revokeChatGPTSession` / `deleteChatGPTSession` (the `authstate` writers).
Swapping them lets the command run without a TTY, real network, or a real settings write.

**9. Typed errors stay credential-free.**
`loginErrorMessage` matches `*openaiauth.Error` by its `Kind`
(`canceled`/`timeout`/`unsupported`/`upstream`) and maps each kind to a fixed, actionable sentence —
so the message comes from the typed `Kind`, never from interpolating the raw error detail string,
which is guaranteed free of secrets.

**10. The unresolved permission risk.**
codemeld does **not** claim official OpenAI approval for the ChatGPT flow — it reuses the Codex
client id (`clientID` in `openaiauth/oauth.go`) and there is no confirmed third-party
client-registration path. The explicit policy: if upstream policy, terms, or controls later
disallow the flow, the feature is **stopped, disabled, or removed** rather than bypassing those
controls. It matters because when you touch this area you must keep that framing — never imply
approval or a supported automation path.

**11. Refreshing ChatGPT models from the picker.**
Only **`Ctrl-R`** on a highlighted `openai-chatgpt` model triggers a refresh. Opening the picker,
moving the highlight, and the three-day staleness check never do: `refreshableProvider`
(`internal/tui/picker_model.go`) rejects an unforced ChatGPT request, and
`ProviderCatalogRefresher.schedule` (`internal/bootstrap/provider_refresh.go`) refuses it again
before any network or store work. Plain `r` stays filter input, and the picker stays open.

`discoverAndStoreChatGPT` first calls `EnsureFreshSession` (`internal/openaiauth/refresh.go`), the
same proactive token refresh a turn uses: a fresh token is used unchanged, and one near expiry is
renewed against `https://auth.openai.com` and saved, with concurrent renewals serialized into one
request. Discovery then goes through `provider.RefreshChatGPTModelCache` to the pinned
`https://chatgpt.com/backend-api/codex` origin. No other origin is added.

With no stored session, or one that cannot be renewed, the outcome is `credential_unavailable` and
the picker shows `run codemeld auth login openai-chatgpt` (`modelRefreshLoginStatus`). It **never**
opens a browser or starts a device-code login, and no discovery runs.

On success, only the `openai-chatgpt` entry of the `models.yaml` cache beside global settings is
atomically replaced (with a new `refreshed_at`), the live catalog is rebuilt, and the outcome is
`updated`. On a timeout, upstream error, or cache-write failure the outcome is `failed`: the prior
cache entry, picker rows, and selected model are kept. Rendering the picker's rows from the cache
and `codemeld auth status` stay offline.
