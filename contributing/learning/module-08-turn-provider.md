# Module 8 — Turn & provider: the LLM loop

_Snapshot as of 2026-10-06; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-10-06_

> This is where codemeld talks to the model. A "turn" streams one assistant response, extracts tool
> calls, and loops. It's also where the "zero phone-home" promise is enforced.

## Goal

After this module you can:

- Trace a single assistant turn from request build to completion.
- Explain the provider abstraction and why the OpenAI chat-completions shape *is* the internal contract.
- Name the sanctioned, origin-scoped egress paths and explain how the no-network test enforces them.
- Explain how parallel tool work is scheduled and how AGENTS.md becomes a system prompt.

## Why it matters

This is the agent's core loop — model → tool calls → tools → model — and the main place outbound
traffic is allowed. It ties together permissions (Module 5), dispatch (Module 6), and sessions
(Module 7).

## Read (in order)

1. `internal/turn/turn.go` — `Runner`, `Run`, `Deps`.
2. `internal/turn/request.go` — `BuildRequest`, `messagesFromRecords`, `BuildCompactionSummaryRequest`.
3. `internal/turn/tools.go` — `ToolLoop`, `assembleToolCalls`.
4. `internal/provider/client.go` — `Client`, `NewClient`, `Response`; skim the OpenAI/OpenRouter adapters.
5. `internal/provider/openai_chatgpt_client.go` and `internal/openaiauth/oauth.go` — the built-in `openai-chatgpt` auth/Codex egress path.
6. `internal/agent/scheduler.go` — `Schedule`, `WorkUnit`.
7. `internal/agentinstr/load.go` and `prompt.go` — instruction discovery + system prompt.
8. `internal/bootstrap/no_network_test.go` — the zero-phone-home test.

## Mental model

### The turn loop

A `turn.Runner` is **single-use — one per provider round**. `Run`:

1. `BuildRequest` reads the active model (`model.ActiveState.Current()`); **no model → `ErrNoModelSelected`,
   no provider call**. It projects message history from the session store and **prepends the AGENTS.md
   system prompt** as a leading `system` message. The request is built with `Stream: true`.
2. The effort is filtered via the injected `Deps.SupportedEffort` lookup — production binds it to the
   run-scoped `Catalog.SupportedEffort` off the config cache (`internal/bootstrap/turndeps.go`), so the
   only supported values are the cached validated capabilities; `model_turn` (and, if the effort was dropped,
   `model_effort_unsupported`) is emitted and **durably flushed before the provider call**.
3. `Client.ChatCompletion` streams; content deltas accumulate (and push to a `Sink` in order), tool-call
   deltas accumulate per index, the finish reason is tracked.
4. If the finish is `tool_calls`, `Run` hands off to `OnToolCalls`; the agentic `ToolLoop` schedules and
   dispatches the calls, appends the assistant tool-call message + tool results, and **re-issues a fresh
   `Runner`** for the next round. A natural completion appends the assistant message and emits
   `model_response`.

Events during a turn: `model_turn`, `model_response` (success), `model_effort_unsupported`
(conditional), and `provider_request_failed` (transport/empty-response failures — **not** HTTP errors
or user cancels).

### Usage normalization: one path, per-field presence

Every provider's token usage lands in `normalizeUsage` (`internal/model/turn_events.go`), and the
rule there is **per subfield, on presence rather than value**. `openai-go` decodes a response's field
metadata alongside its values, so `u.JSON.PromptTokens.Valid()` distinguishes "the provider sent 0"
from "the provider sent nothing" — a distinction a plain `int64` erases. A missing or negative
`prompt_tokens`/`completion_tokens` records 0 and raises `usage_missing` once; a healthy object
raises nothing.

`prompt_tokens_details.cached_tokens` rides the same path but with a different verdict for absence.
Providers legitimately omit it, so it returns a `*int64` — nil for absent/null/negative, non-nil for
a reported value including 0 — and its absence is **not** an anomaly. Watch where the presence
metadata lives: it is `u.PromptTokensDetails.JSON.CachedTokens`, on the nested details struct, not on
`u.JSON`. The zero value of that struct reports `Valid() == false`, which is what makes a response
with no `prompt_tokens_details` at all read correctly as "not reported".

An agentic turn folds every round through `UsageAccumulator`, which sums the rounds that reported a
cached count and separately remembers whether any round did not. `Totals` then returns the sum plus
`cachedPartial` — the flag that becomes `model_response.cached_input_tokens_partial` and marks the
number a lower bound. Both `EmitModelResponse` call sites carry it: `Runner.Run`'s final-answer path
(`internal/turn/turn.go`) and `ToolLoop.finalizeInterceptedRound` (`internal/turn/tools.go`), the
suggest-only terminal round that never reaches the first.

**The ChatGPT bridge feeds the same path rather than forking it.** `enqueueCompletion`
(`internal/provider/openai_chatgpt_client.go`) synthesizes a chat-completion usage chunk from the
Responses `usage` object. Its three counts are always emitted, because a Responses usage object
always carries them — a synthesized 0 there is honest. `prompt_tokens_details` is the opposite: the
bridge attaches it **only when the upstream payload carried `input_tokens_details.cached_tokens`**,
because synthesizing `cached_tokens: 0` for a response that said nothing would manufacture a
"cache was cold" reading no provider ever reported. Same reasoning, opposite default; the deciding
question is what the upstream shape guarantees.

None of this is provider-branched, and none of it attributes a cache hit or miss to a cause. It
records what the provider said it served from cache — not whether `prompt_cache_key`, routing, or a
prompt change is why.

### Permission denials in the loop

A dispatched tool call can come back **denied** (`ToolResult.Denied`, carrying the deny envelope
instead of output). `ToolLoop.onToolCalls` always persists the deny envelope through
`permissions.DeliverDeny` — so the transcript stays well-formed — and always surfaces a friendly denial
line through `Deps.Notice` (committed in-place in the TUI, stderr in a headless run) that names the
refused tool/command and reason **without** making the raw JSON the primary UI text. What differs is
whether the loop then re-issues, and it is decided by the envelope's `denied_by`, **not** a second
classifier:

- **Successful results → continue.** The ordinary case: append results, re-issue the next round —
  unless one of them is marked terminal (see below).
- **User denial (`denied_by:"user"`) → terminal stop.** The loop does **not** re-issue; feeding a user
  refusal back would let the model retry, try an alternate method, or claim a result the user never
  approved. It flushes the denied round itself (no later round will) and sets `ToolLoop.Denied()` true,
  which gates first-turn work like title generation off. An **unclassifiable** envelope is treated the
  same way — fail closed, so a malformed result can never bypass the user-denial halt.
- **Mode-policy denial (`denied_by:"mode"`) → recoverable continuation.** A Plan-mode refusal is *not* a
  user refusal: the loop re-issues so the model sees the refused tool result and picks a permitted
  read-only alternative. `Denied()` stays false because that turn runs on to a real final answer. The
  deny reason (built in `permissions.planPosture`) carries concrete recovery guidance — e.g. *do not use
  shell loops; issue separate `read`/`glob` calls or simple read-only shell commands* — so the model is
  steered, never by executing the blocked command.
- **Unattended refusal (`denied_by:"unattended"`) → recoverable continuation.** A headless
  `codemeld run` without `--prompt-for-approval` has nobody to approve a call, so the headless
  authorizer (`internal/bootstrap/headless.go`) turns every refusal that is not already a mode
  refusal into an `unattended` envelope. The loop re-issues exactly as for `mode`: the model is told
  the call was refused and continues with what it is allowed to do. `Denied()` stays false.

**The repeat cap.** Recovering from refusals could let a headless model retry the same refused call
forever, so the headless authorizer counts refusals per call — keyed on the call's kind, subject,
and path scope (`permissions.CacheIdentity`; the host instead of the path scope for a network call).
When the **same** call is refused for the 5th time (`maxRefusalsPerCall`), its result carries
`ToolResult.WrapUp`, stderr names the call, and the loop starts a **final round**: it appends a
`system` message telling the model tools are no longer available, advertises no tools, and asks once
more. The reply is the run's answer; if that reply still contains tool calls, they are not run —
only its text is kept, and an empty reply is a failure. Refusals of *different* calls have no limit.

**`--time-limit`.** `codemeld run --time-limit <duration>` sets a deadline on the loop
(`ToolLoop.SetDeadline`). When it passes, the in-flight provider stream or tool calls are cancelled
(a cancelled tool call's result says it did not finish, and a partial reply is discarded), and the
loop runs the same final tool-less round, which the deadline does not bound; stderr then reports that
the time limit was reached. Ctrl-C is different: it cancels the run immediately and gets **no** final
round.

There is one more terminal stop that is *not* a refusal: `ToolResult.Terminal`. The production
dispatcher sets it for a web search the backend could not complete (the Exa adapter has already made
its one bounded retry). The result is persisted through the **ordinary** tool-result path — not
`DeliverDeny`, because nothing was refused — the bounded failure is surfaced through `Deps.Notice`,
the round is flushed, and the loop stops without re-issuing, so the model cannot answer the failure
by running the same search again. `Denied()` stays false: it remains a permission signal.

### The provider abstraction

`provider.Client.ChatCompletion(ctx, Request)` is the internal interface. **The OpenAI chat-completions
shape *is* the contract** — `provider.Response` exposes the `openai-go` types directly.
`NewClient` builds the chat service **directly** (not `openai.NewClient`) so **no `OPENAI_*` env var can
inject** a base URL, key, or header, and sets `MaxRetries(0)` so an HTTP error surfaces **verbatim,
once**. Adapters (`openai`, `openrouter`, `venice`) register via `init()` and supply *connection defaults only* —
a name, a default base URL, and a default auth header (`provider.Adapter`, `client.go`). They carry no
per-model effort catalog; a custom OpenAI-compatible provider needs only config, no adapter code.

A configured provider's **selectable model ids come from the local discovered catalog** (`models.yaml`,
read offline), not from a settings `provider.<name>.models` list — that legacy list is parsed
but no longer consulted for selection. `BuildCatalog` (`internal/provider/catalog.go`) projects the
discovered ids into each configured `CatalogEntry.Models`; a provider with no discovered ids stays
present with an empty allowlist, and the empty-catalog diagnostic tells the user to refresh the catalog
rather than edit settings.

Ordinary catalog reads are **offline** — startup, catalog construction, and model-selection actions
never repopulate `models.yaml`. A write happens only when the user explicitly triggers discovery, either
through the `/connect` discovery command or a picker refresh. Two writers exist, both credentialed `/models` requests
through the same redirect-refusing `provider.DiscoverAPIKeyModels`. `/connect`
(`internal/bootstrap/connectdeps.go`) validates a new API key and writes that provider's initial catalog.
`ProviderCatalogRefresher` (`internal/bootstrap/provider_refresh.go`) refreshes an already-configured
provider from the **model picker**: `newModelPickerDeps` installs its `Refresh` method as the
picker's `RefreshCatalog` callback, so highlighting a configured provider starts one non-forced background
refresh and **Ctrl-R** forces one regardless of age. The picker owns only the triggering (deduped per provider,
built-in `openai-chatgpt` excluded), the event-loop-marshaled row re-render, and a one-line outcome notice;
the service owns staleness (the three-day window), per-provider coalescing, discovery, the atomic write,
and the live-cache rebuild — in that order, so the picker never shows ids that are not yet on disk. It
refreshes a provider whose `refreshed_at` is missing, malformed, or older than three days; a discovery or
write failure keeps the prior cached models and returns only a static, secret-free outcome
(`refused`/`fresh`/`updated`/`failed`). See [`docs/provider-model-cache.md`](../../docs/provider-model-cache.md).

The reasoning effort is serialized **per provider**: OpenRouter's documented contract is the
nested `reasoning: {effort}` object, so `ChatCompletion` injects it there and omits the flat
`reasoning_effort`; Venice and custom OpenAI-compatible providers keep the flat `reasoning_effort` field.
The branch keys off the provider id (`ClientConfig.Name`). Whatever token reaches `ChatCompletion`
goes out unchanged; an **empty** request effort writes no reasoning field at all.

Attribution headers key off the same provider id, one level earlier. When the composed
`attribution` setting is true (its default) **and** the provider is `openrouter`, `NewClient` installs
`HTTP-Referer: https://codemeld.dev` and `X-Title: Codemeld` as request-wide options, so OpenRouter's
activity dashboard groups codemeld's spend under a named app instead of `Unknown`. Because they are
construction-time options, both the streaming and non-streaming chat-completion calls carry them, and
the `/models` discovery request does not. No other provider ever receives them — Venice is chosen for
privacy and would only see an unknown header.

A user who does not want to name their editor to OpenRouter opts out on the **settings** tab of the
`/settings` overlay: Enter on the `openrouter attribution` row flips it, writing `attribution` to
`~/.codemeld/global/settings.yaml` through the locked config writer and updating the session's
`Cache.Attribution()` on success. `buildTurnClient` snapshots that accessor per client, so the next
turn drops both headers with no restart, leaving auth and the nested `reasoning.effort` body untouched.
The key is **global-only**: a project `.codemeld/settings.yaml` carrying it fails to load, which is
what lets the row promise that what it shows is what is in effect.

OpenRouter forwards each request to one of several upstream providers, and a failure can name the
upstream that failed. When the selected provider is `openrouter` and a failure the retry loop would
already retry carries `metadata.error_type: "provider_unavailable"` with a message starting
`Upstream error from <Name>:`, `provider.UnavailableUpstreamProvider` (`internal/provider/http_errors.go`)
lowercases the name and returns it as a slug only when it matches `^[a-z0-9][a-z0-9-]*$`. It reads the
body from either an HTTP error or a mid-stream `ssestream.StreamError`, which is how the failure
usually arrives. Anything else — another error type, a malformed body, a multi-word name such as
`Google AI Studio`, a single-word name with other characters such as `foo_bar`, any other provider —
returns nothing, and the retry runs as before. For a new slug, `Runner.runWithRetry`
(`internal/turn/retry.go`), the retry loop `Runner.Run` (`internal/turn/turn.go`) calls, adds it to
`turn.IgnoredProviders`, shows
`Provider <slug> failing to respond. Removing for rest of this session` once, and re-issues the same
round with no backoff delay. That attempt still counts toward `max_attempts` and the retry budget, and
the partial reply is still rolled back. A later failure naming a slug already on the list takes the
normal backoff with no notice; with auto-retry turned off, the slug is still added and the notice shown
before the failure is reported. Every request then carries the list on `provider.Request.IgnoredProviders`,
which `ChatCompletion` writes as `provider.ignore` only for `openrouter` and only when the list is
non-empty, so OpenRouter can still fall back among the upstreams not on it.

The list lives only in memory. `turnController` keeps one per session store and starts an empty one
when `/clear` or `/resume` switches the store; a headless run starts empty. Nothing is written to
settings or to the session file, so no account-wide routing preference changes and a resumed session
does not bring the list back. It applies to main-turn rounds, including tool-continuation rounds;
compaction, title generation, and delegated child turns send no ignore list.

Configured routing rides in the same `provider` object as that ignore list. When the `openrouter`
entry carries a `routing` block (Module 4), `ChatCompletion` adds its values beside
`provider.ignore`, again only for `openrouter`. The rule for what is sent: absent values and
`require_parameters: false` are not sent; an explicit `data_collection: allow` is sent. So a set
`sort` (`throughput` or `latency`) goes out as `provider.sort`, a set `data_collection` as
`provider.data_collection`, and `require_parameters` only as `provider.require_parameters: true`.
`max_price` is looked up by the request's **exact** model id — a suffixed id such as `:free` is a
separate key — and when that model has an entry it is sent as `provider.max_price` holding only the
caps the entry sets: a cap written as `0` is present and sent as `0`, an omitted cap is left out,
and a model with no entry sends no `provider.max_price` at all. Unlike the session ignore list,
routing applies to every request through the OpenRouter client — turns, subagents, `/compact`, and
title generation — because each builds its client through `buildTurnClient`, which passes the
cached entry's `Routing` into `ClientConfig`.

`sort: best_value` is not sent as written. `ChatCompletion` sends `provider.sort: "price"` plus
`provider.preferred_min_throughput` set to the model's speed bar: the median p50 speed (the lower
middle value when the count is even) of the model's providers, read from an authenticated
`GET <base_url>/models/<model id>/endpoints` request to the same configured OpenRouter base URL
(`internal/provider/openrouter_endpoints.go`). One `OpenRouterEndpointStore` holds that data per
base-URL/model pair. It is fetched on the first lookup for a pair — either the request-side
speed-bar lookup (`ClientConfig.MinThroughput`, wired by `buildTurnClient` to
`OpenRouterEndpointStore.SpeedBar`) or the settings tab's sort estimate
(`OpenRouterSettings.SortEstimate` → `OpenRouterEndpointStore.Estimate`) — and again once a
successful fetch is 12 hours old; a failed fetch is retried after 15 minutes. With no speed data,
only `provider.sort: "price"` is sent.

Each OpenRouter turn's `model_response` also carries `upstream_provider`: the upstream OpenRouter
actually routed to, taken from the first non-empty top-level `provider` field of the streamed chunks
(`upstreamProvider` in `internal/turn/turn.go`). It is read only when the selected provider is
`openrouter`, and left out when the stream never names one.

When the filters leave no provider, OpenRouter answers HTTP 404. `isRoutingFilterExhaustion`
(`internal/provider/http_errors.go`) recognizes that case only from a 404 whose JSON body has an
`error.metadata.failed_routing_step` that starts with `Filter by ` and has a nonempty suffix (for
example `Filter by Max Price`). For `openrouter`, `ChatCompletion` then wraps the `HTTPError` in a
`RoutingExhaustionError` that records the model and the filters sent, so the failure notice can say
which setting to loosen. It still unwraps to the same 404 and follows the ordinary non-retryable
HTTP path (the retry policy does not retry HTTP 404); there is no status-independent bypass.
`TestRun_RoutingExhaustionSurfacesOnceWithFilters` (`internal/turn/retry_policy_test.go`) pins the
result: one request, no backoff, and the ignore list unchanged.

Which effort levels a model offers comes only from cached capability metadata, never from a static
table of *values* or the model id. Providers do not agree on where to put those values, so
`internal/provider/effort_shapes.go` keeps one table of *structural shapes* — where each provider
states its levels — and one walker that reads them all:

| Shape | Levels | Default | Gate |
|-------|--------|---------|------|
| Venice | `model_spec.capabilities.reasoningEffortOptions` | `…defaultReasoningEffort` | `…supportsReasoningEffort` must be true |
| OpenRouter | `reasoning.supported_efforts` | `reasoning.default_effort` | none |
| ChatGPT (cached) | `supported_reasoning_levels[].effort`, or the legacy `[].level` | `default_reasoning_level` | none |

Read the two together: the table says *where to look*, and the values found there are still purely
the provider's. No row names a provider — the paths identify the shape — so a fourth provider is a
new row, not new code. Shapes are tried top to bottom and the first with usable options wins; a
missing root just means "not this shape". All three land in the same neutral cache keys
(`supportsReasoningEffort`, `reasoningEffortOptions`, `defaultReasoningEffort`), each option length-
and charset-capped.

Discovery (`internal/provider/apikey_model_discovery.go`) decodes a `/models` record into raw
top-level messages and then reads only `id`, `architecture`, and the table's roots — and inside a
root, only the declared path — so unrelated fields never get decoded or stored. The catalog
(`internal/provider/catalog.go`) keeps a model's options only when the cached entry set
`supportsReasoningEffort`, and runs the same walker over cached ChatGPT capabilities at read time.
`Catalog.SupportedEffort` is the single selectable-effort source: a model
with no surviving cached options — absent, unsupported, or malformed metadata — exposes only
`no-reasoning`, and the cacheless `provider.SupportedEffort` helper delegates to an empty `Catalog`
for the same result. See [`docs/provider-model-cache.md`](../../docs/provider-model-cache.md).

### `no-reasoning` is not the provider's `default`

Two tokens read alike and mean opposite things — this is the one place in the effort path that
regularly trips people up.

| | `no-reasoning` | a literal `default` |
|---|---|---|
| Who owns it | codemeld | the provider |
| When it exists | always, for every model | only when the provider advertises it |
| Stored in `model.active.effort` | yes | yes |
| Recorded on `model_turn` | yes | yes |
| On the wire | **no reasoning field is sent** | sent unchanged, like any other advertised value |

`ResolveRequestEffort` (`internal/model/turn_events.go`) applies the split once per turn and returns
the value to send, where `""` means "omit the parameter":

- `no-reasoning` → omit, no extra event. This is a normal, fully supported choice.
- a token the active model still advertises (including `default`) → send it verbatim.
- a token the active model **no longer** advertises → omit, and emit `model_effort_unsupported`
  carrying the configured value under `configured_effort`. The stored selection on disk is left
  alone; nothing is silently rewritten behind the user's back.

In the last two omit cases the turn's `model_turn` records `effort: no-reasoning`, because that is
what actually went out — the configured intent survives on `model_effort_unsupported`, so the audit
trail keeps both. Selection-time validation (`Validate` in `internal/model/selection.go`) mirrors
this: `no-reasoning` is accepted for any model, every other token must be in the cached advertised
set. `codemeld run` follows the same rule — passing `--model` without `--effort` selects
`no-reasoning`.

### One-time cleanup before your first run of this build

Older builds encoded "send no reasoning-effort parameter" as the string `default`, which collided
with providers that advertise a real effort named `default`. There is no compatibility parser and no
automatic migration, and codemeld will not edit or delete your files for you. Before you first launch
a build that contains this change, do exactly three things:

1. In each project's `<project_root>/.codemeld/settings.yaml`, remove the `model.active` entry if its
   `effort` is the old ambiguous `default`. Leave every other key in the file alone.
2. In `~/.codemeld/global/settings.yaml`, remove the `model.last_used` entry if its `effort` is the
   old ambiguous `default`. Again, only that entry.
3. Do not resume a session whose last `model_turn` records `effort: default` from an older build.
   Start a fresh session instead; a session whose recorded effort is still advertised by its model
   resumes normally.

Then pick a model again — the picker writes the new representation. Nothing else needs touching: do
**not** delete your settings files, your API keys or stored credentials, `models.yaml`, or session
history that this cleanup does not name.

Skipping the cleanup is not silently safe. If the model does not advertise `default`, the stale value
fails validation and you land in the model picker (with `model_recovery_failed` recorded on a resume)
— annoying but harmless. If the model *does* advertise `default`, the stale value now validates and
is sent to the provider as a real effort, which is the opposite of what you originally chose.

### Zero phone-home

**Outbound traffic goes only to sanctioned, origin-scoped destinations** — there is no general network
access. Two paths are allowed:

1. **Primary provider traffic through `provider.NewClient`** (`provider/client.go`). Production reaches it
   through the `newTurnProviderClient` seam; the origin comes from the configured provider, not from the
   environment.
2. **The built-in `openai-chatgpt` auth/Codex path.** `provider.NewChatGPTClient`
   (`provider/openai_chatgpt_client.go`) POSTs to the pinned Codex origin
   (`https://chatgpt.com/backend-api/codex`) and refuses 3xx redirects off that origin (`pinRedirects`),
   and the OAuth flow (`openaiauth/oauth.go`, `postForm`) POSTs to the pinned auth origin
   (`https://auth.openai.com`) while serving the callback on a loopback listener (`localhost:1455`).

`TestNoNetwork_FullSessionDialsOnlyConfiguredProvider` (`bootstrap/no_network_test.go`) runs a real
launch against a stub server, injects a guarded HTTP client whose `DialContext` counts any dial outside
the allowlist, submits a prompt, and asserts `rejectedDials == 0` (and `allowedDials > 0`, so the guard
can't pass vacuously). This proves a full session dials **only** the configured provider; it does **not**
exercise the auth/Codex path. (Documented limitation: the guard sees dials through the injected client,
not raw `net.Dial` — deferred to a later phase.)

### Compaction summaries are data, not instructions

`/compact` asks the model to summarize the session, and the summary it returns is stored as the child's
record-zero `sessions.Compaction`. That text is derived from whatever the conversation held — including
tool output codemeld does not trust — so **it never occupies the instruction channel**:

- The summarization request (`BuildCompactionSummaryRequest`, `turn/request.go`) has exactly one system
  message, the fixed product-authored `compactionSummaryInstruction`. It tells the model that the
  messages, tool results, and any earlier summary that follow are material to summarize rather than
  instructions to follow, and requires the summary to preserve goals, constraints, read-only scope,
  approvals already given, approvals still required, unresolved work, and proposed-versus-completed
  status. History is projected as ordinary messages **after** it — never concatenated into it.
- On a later normal turn, `messagesFromRecords` projects the stored summary as a **`user`** message: a
  short note that its contents are reference data, then the summary verbatim between
  `<prior_conversation_summary>` delimiters. `user` is the lowest-authority representation both
  provider mappings share — `toSDKMessages` sends it as a user message, and
  `responsesInstructionsAndInput` puts it in `input`, whereas a `system` message becomes the Responses
  **top-level `instructions`**.

The boundary is the transport role, not the content: the summary is carried verbatim and nothing is
sanitized or keyword-filtered, so continuation stays useful. Record shape, provenance, and the linked
child lifecycle are untouched by this — see the invariants page.

### Work scheduling

`agent.Schedule(ctx, units, maxConcurrency)` runs up to `maxConcurrency` (default 3) independent
`WorkUnit`s in parallel, serializing on declared dependencies (`Deps()`) and **conflicting write
targets** (`Targets()`). Conflict is segment-boundary aware: `dir/a` vs `dir/b` don't conflict, but
`dir` vs `dir/file` do (and `foo` vs `foobar` don't). The plan is validated (cycles, dup ids) **before**
anything runs.

### Planning the batch, then scheduling it

`ToolDispatcher.Plan(calls, maxConcurrency)` is handed the **whole** tool-call response at once and
returns a `ToolPlan`: one `PlannedToolCall` per real call, in order, each carrying that call's
`Deps`/`Targets`, its `ContinueOnError` flag, an optional `PreRun` guard, and the `Run` closure the
scheduler executes. Planning a batch rather than a call at a time is what lets a planner order calls
*against each other* — a call it cannot positively identify becomes a barrier its neighbours have to
wait for, rather than something that runs beside them.

`ToolLoop.onToolCalls` then does, in order: assemble → intercept `suggest_followup` → tool-activity
hook → `Plan` → **`validateToolPlan`** → `agent.Schedule` → persist. The validation rejects a plan whose
units don't answer the round's calls one-for-one (wrong count, reordered or substituted call, missing
`Run`) *before* anything is scheduled, because scheduling such a plan would correlate a result to the
wrong `tool_call_id`. The loop always schedules with **its own** configured limit; `ToolPlan` echoes
that limit back for a planner to read, so a planner can't widen it.

**Production overlaps one shape of call, run by run.** `productionToolDispatcher.Plan` classifies
each call on its own: a project-confined structured read is an exact name from the six-tool
allowlist, arguments that decode and pass `filetools.ValidatePhase1ReadArgs`, a target that resolves,
and a scope the tool itself reports as inside the project. Only those units are returned **without**
the synthetic `productionToolDispatchTarget`, which is what lets `agent.Schedule` run them together
up to `agent.max_concurrency`. Every other call — shell, VCS, `read_image`, a mutating call, an
unknown name, malformed arguments, an external read — keeps the target and becomes a **model-order
barrier**: it depends on the run of eligible reads immediately before it, and the next run of
eligible reads depends on it. So `read A, grep B, edit C, read D, glob E` runs `{A, B}`, then `C`,
then `{D, E}` — an excluded call never overlaps a read, and an `edit` followed by a `read` is still
observed in that order.

Because a barrier can change what a later read's path resolves to, plan-time preparation decides
only the plan shape: each eligible unit's `Run` resolves its own target again immediately before
dispatching, and fails closed without dispatching if the call no longer qualifies. (The converse is
deliberately conservative — a read whose target only a preceding barrier will create is refused at
planning and runs serially.)

Failure handling follows the same partition. An eligible unit sets `ContinueOnError`, so its
internal failure is kept from the scheduler and its concurrent siblings drain instead of being
cancelled; the plan then latches the lowest model-call-index failure, and the next barrier's
`PreRun` guard returns it before dispatching, so no later call runs. A barrier that has already
completed in model order is never undone. An excluded unit stays fail-fast. `PreRun` is a field
separate from `Run` precisely so a wrapping dispatcher — the headless experiment binding replaces an
extra tool's `Run` — cannot drop the guard.

Overlapping reads are also the only calls that carry lifecycle evidence: `dispatchPrepared`
appends a `structured_read_start` (one UUIDv7, the exact tool name, the resolved scope, the configured
cap) *before* invoking and exactly one `structured_read_end` (terminal outcome + monotonic duration)
after, so the durable session is enough to reconstruct what actually ran concurrently. A start that
cannot be appended means the read does not run; an end append failure is returned as an internal
dispatch error after the start already exists. Each excluded call leaves one best-effort
`structured_read_refused` planning record instead, so the barriers between the runs are
reconstructable too.
Results still reach the store in model-call order — `onToolCalls` writes each unit's result into its
own pre-indexed slot — so completion order changes the events, never the transcript.

### Agent instructions

`LoadAgentInstructions` discovers the global `AGENTS.md` then walks ancestors **root → launchDir**
(farthest-first), applying size/readability skips. `SystemPrompt` concatenates the loaded entries in
order; `BuildRequest` prepends the result as the leading `system` message.

## Watch for (Go idioms)

- **DI seams at the network boundary.** `turn.Deps` injects the `Client`/`Sink`/`Flush`/hooks (so
  `internal/turn` imports neither `tui` nor `bootstrap`), and `newTurnProviderClient` is a reassignable
  package var the no-network test swaps for a guarded client.
- **Streaming assembly with per-index accumulators.** `assembleToolCalls` rebuilds whole tool calls
  from fragmented SSE chunks keyed on `frag.Index`, keeping the first non-empty id, emitting sorted by
  index.
- **Rune-correct counting.** Retained/partial character counts use `utf8.RuneCountInString`, not `len`.
- **Lock-free scheduling.** `agent.run` keeps all scheduling state on one driver goroutine, so no mutex
  is needed.
- **Read the envelope, don't re-classify it.** The user-vs-mode denial fork keys on the deny envelope's
  `denied_by` field (a local decode), not a string search over tool output; anything it can't positively
  classify falls closed to the terminal user-denial path.

## Quiz

Closed-book: [`quizzes/module-08.md`](quizzes/module-08.md). Grade against
[`quizzes/module-08-key.md`](quizzes/module-08-key.md).

## Hands-on (open-book)

**A. Trace the sanctioned egress paths.** Confirm the two allowed outbound paths: the primary provider
client (`provider.NewClient`) reached via the `newTurnProviderClient` seam, and the built-in
`openai-chatgpt` auth/Codex path (`provider.NewChatGPTClient` to `https://chatgpt.com/backend-api/codex`,
`openaiauth` `postForm` to `https://auth.openai.com`). Then read
`TestNoNetwork_FullSessionDialsOnlyConfiguredProvider` and note what it proves (a normal session dials
only the configured provider) and what it does **not** cover (the auth/Codex path). Record the seam name
(`newTurnProviderClient`) and both pinned origins in [`progress.md`](progress.md).

**B. Predict, then verify.** If no model is selected, does a turn call the provider? Predict, then read
`BuildRequest`/`Run` and confirm against `TestRun_NoModelRefusedNoProviderCall` (`turn_test.go`).

**C. Locate the hardening.** Find where `NewClient` avoids `openai.NewClient` and sets `MaxRetries(0)`.
Write one sentence each on what those two choices prevent (hint: env injection; silent retries).

## Done when

- You can trace a turn from `BuildRequest` to `model_response`, including the tool-call handoff.
- You can name the sanctioned egress paths and explain what the no-network test does and does not prove.
- You can explain how conflicting tool writes get serialized.
- You can explain how usage normalization tells a reported `0` from an unreported field, and why the
  ChatGPT bridge always emits the three counts but only conditionally emits `prompt_tokens_details`.
