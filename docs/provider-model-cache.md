# Provider model cache (`models.yaml`)

`models.yaml` is codemeld's local, system-owned cache of the selectable model ids for **configured
API-key providers** (`provider.<name>` entries such as `openai`, `openrouter`, `venice`) and for the
built-in `openai-chatgpt` provider. It lives beside the global `settings.yaml` and is derived from
`config.DiscoveredModelsPath`, so the reader and every writer target the same file and cannot drift.
It is **cache data, not user settings**: users edit `settings.yaml`; the ids in `models.yaml` are
populated by discovery.

The built-in `openai-chatgpt` provider is discovered with its login session instead of an API key,
and keeps a compiled fallback catalog of model *ids* that its discovered ids only extend. Its
reasoning-effort options are not compiled: like every other provider's, they come only from its
cached discovery capabilities (see [Reasoning-effort capabilities](#reasoning-effort-capabilities)).

## What it holds

Per provider (`config.DiscoveredProvider` in `internal/config/discovered_models.go`):

- `models` — sanitized model ids plus whitelisted selection/capability metadata (display name, context
  window, input modalities, reasoning-effort options). Never API keys, auth headers, prompts, or raw
  provider responses.
- `refreshed_at` — RFC3339 timestamp of the last successful picker refresh (advisory). Only the
  picker refresh sets it; `/connect` and login-time discovery leave it empty.
- `source` — a static, secret-free label of where the ids came from.

The store's write path (`sanitizeProvider`) redacts any secret-shaped key or value as a backstop, so
auth material cannot reach disk even if a producer places it in the free-form metadata.

## Reads are offline; writes are discovery-driven

Ordinary catalog construction, `/model` validation, and picker row rendering read `models.yaml`
**locally, with no network I/O**. Nothing repopulates it on a startup poll or a plain catalog read — a
write happens only through one of the three discovery writers below.

Three paths write `models.yaml`, each a credentialed, redirect-refusing `/models` request. API-key
discovery goes through `provider.DiscoverAPIKeyModels`; ChatGPT discovery goes through
`provider.RefreshChatGPTModelCache` with the stored login session:

- **`/connect`** (`internal/bootstrap/connectdeps.go`) validates a newly entered API key with
  `provider.DiscoverAPIKeyModels` and writes that provider's initial catalog when the user connects it.
- **`codemeld auth login openai-chatgpt`** (`liveRefreshChatGPTModels` in `internal/cli/auth.go`) runs
  `provider.RefreshChatGPTModelCache` after a successful login and writes the `openai-chatgpt` entry.
  It is best-effort: a discovery or write failure never fails the login.
- **`ProviderCatalogRefresher`** (`internal/bootstrap/provider_refresh.go`) is the model picker's
  refresh callback, installed by `newModelPickerDeps` (`internal/bootstrap/starttui.go`) through
  `newProviderRefreshCallback` (`internal/bootstrap/modeldeps.go`). It re-discovers an
  already-configured API-key provider through `provider.DiscoverAPIKeyModels`, or — only on a forced
  (CTRL-R) refresh — `openai-chatgpt` through `provider.RefreshChatGPTModelCache`. The service itself
  imports no TUI code.

## Reasoning-effort capabilities

The cached capability metadata is the **only** source of a model's selectable reasoning-effort values.
Providers state the same three facts in different places, so `internal/provider/effort_shapes.go`
holds one table of structural shapes and one walker that reads all of them into the same neutral
cache keys — `supportsReasoningEffort`, `reasoningEffortOptions`, and `defaultReasoningEffort`:

| Shape | Levels | Default | Gate |
|-------|--------|---------|------|
| Venice | `model_spec.capabilities.reasoningEffortOptions` | `…defaultReasoningEffort` | `…supportsReasoningEffort` must be true |
| OpenRouter | `reasoning.supported_efforts` | `reasoning.default_effort` | none |
| ChatGPT (cached) | `supported_reasoning_levels[].effort`, or the legacy `[].level` | `default_reasoning_level` | none |

The table names no provider — the paths themselves identify the shape — and the shapes are tried in
that order until one yields options. A root that is absent is an optional non-match, so a provider
that sends only one of these shapes discovers normally. Every option is length- and charset-capped,
so a hostile `/models` body cannot smuggle a blob through as an option; a malformed container or a
list with no valid entry yields no options, while a mixed list keeps its valid entries and skips the
rest. Discovery (`internal/provider/apikey_model_discovery.go`) decodes each record as a map of raw
top-level messages and then traverses only `id`, `architecture`, and the table's roots, reaching only
the declared segments and leaves inside them, so unrelated roots and nested siblings never enter a
decoded value or the store.

`configuredEffortFromCapabilities` (`internal/provider/catalog.go`) keeps a model's options only when
the cached entry set `supportsReasoningEffort`, de-duplicates them, and preserves the provider's own
order, including values that did not exist when codemeld was built. Nothing is declared in source and
nothing is inferred from a model id. The `openai-chatgpt` entry follows the same rule through the same
walker, run at read time over its cached `supported_reasoning_levels` — so caches written before the
table existed, including ones carrying the legacy `level` member, stay readable with no re-login or
migration. A configured provider's cached entry gains newly readable options only after its next
refresh.

`Catalog.SupportedEffort` reads that cache and is the single selectable-effort source for the picker,
`/effort`, `/model`, `codemeld run --effort`, and selection validation. A model with no surviving
cached options — metadata absent, `supportsReasoningEffort` false, or the options malformed — exposes
only codemeld's own `no-reasoning` choice, which sends no reasoning-effort parameter at all. There is
no static table and no static `default` fallback behind it. A provider that advertises a literal
`default` option is a separate case: that is an ordinary token, selectable and sent on the wire
unchanged, not a request for omission.

Capability metadata follows the same retention rules as the model ids, because it lives in the same
per-provider entry: a successful refresh replaces that entry atomically, so withdrawn options stop
being selectable and newly advertised ones become selectable in the same write, while a failed or
malformed refresh leaves the prior options and the live catalog untouched. Until a provider has a
valid cached entry, its models offer only `no-reasoning` — codemeld invents no provider effort values
to fill the gap.

## Three-day freshness

A provider entry is **stale** when its `refreshed_at` is missing, malformed, invalid, or older than
three days. A picker refresh discovers a stale (or force-requested) provider; a fresh entry is left
alone unless the request is forced. A future timestamp is treated as fresh. Because `/connect` and
login-time discovery leave `refreshed_at` empty, their entries are stale as soon as they are written.

The picker refreshes on its own: opening it and highlighting a row each request an unforced refresh
of that row's provider, at most once per provider per picker session. An unforced request discovers
only a configured API-key provider whose entry is stale. CTRL-R forces a refresh of the highlighted
row's provider; `openai-chatgpt` is refreshed only when forced.

## Ordering and coalescing

A successful refresh runs in a fixed order:

1. `DiscoverAPIKeyModels` — one background `/models` request bearing the provider's configured key.
2. For `openai` only, `FilterPlatformDiscoveredModels` projects the discovery result. It admits no model
   ids of its own and rejects none: every sanitized record is preserved in discovery order, because the
   provider cache is the sole source of selectable reasoning efforts.
3. `UpdateDiscoveredModelsProvider` — atomically replaces that provider's entry (preserving every other
   provider) with the discovered models and the fresh `refreshed_at` the refresher stamped.
4. `Cache.ReloadDiscoveredCatalog` — rebuilds the run's live selectable catalog from the just-written
   store.

A forced `openai-chatgpt` refresh first calls `EnsureFreshSession`, which renews a near-expiry stored
session, then runs `RefreshChatGPTModelCache` in place of step 1, skips step 2, and finishes with
steps 3 and 4. One timeout spans the session renewal and the discovery.

Only after the durable write and live rebuild is a success reported, so the picker never shows ids that
are not yet on disk. Concurrent picker requests for **one** provider share a single discovery attempt
and all receive the same result; requests for **different** providers proceed independently.

## Failure retention and secrets

Any failure — a refused redirect, malformed body, authentication error, an empty discovered-model list, a
persistence error, a timed-out session renewal, or a rebuild before completion — leaves the **prior
on-disk entry and live catalog unchanged**. The result handed back to the picker is a static
classification carrying no API key, auth header, provider body, or raw upstream error:

- `refused` — not a configured API-key provider, an `openai-chatgpt` request that is unforced or has
  no login session source bound, or no store path; no discovery ran.
- `fresh` — the entry is within the freshness window and the request was not forced.
- `updated` — discovery, the store write, and the live rebuild all succeeded.
- `failed` — any failure above.
- `credential_unavailable` — no stored ChatGPT session, or its renewal was rejected; no discovery ran.

## Egress boundary

This is provider egress, not telemetry: the only outbound traffic is the provider's own credentialed
`/models` request — to an API-key provider's configured base URL, or to the pinned ChatGPT discovery
base URL `https://chatgpt.com/backend-api/codex` — plus, for `openai-chatgpt`, session traffic to
`https://auth.openai.com` for login and session renewal. Discovery runs only when the user connects a
provider, logs in to ChatGPT, or the model picker requests a refresh. A forced picker refresh of
`openai-chatgpt` renews a near-expiry stored session before discovery but never starts a login: with
no stored session it ends as `credential_unavailable`. None of these clients follows a redirect. No
data is sent anywhere else, and nothing but sanitized model metadata is written to the cache.
