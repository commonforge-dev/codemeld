# Answer key — Module 8: Turn & provider

_Last updated: 2026-10-06_

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** **Two sanctioned, origin-scoped paths.** (a) Primary provider traffic through `provider.NewClient`
(`provider/client.go`), reached in production only via the `newTurnProviderClient` seam
(`bootstrap/turndeps.go`); its origin comes from the configured provider, not the environment. (b) The
built-in `openai-chatgpt` auth/Codex path: `provider.NewChatGPTClient`
(`provider/openai_chatgpt_client.go`) POSTs to the pinned `https://chatgpt.com/backend-api/codex` and
refuses off-origin redirects (`pinRedirects`), and `openaiauth` `postForm` (`openaiauth/oauth.go`) POSTs
to the pinned `https://auth.openai.com`. Enforced by code review plus
`TestNoNetwork_FullSessionDialsOnlyConfiguredProvider` (`bootstrap/no_network_test.go`), which counts
non-allowlisted `DialContext` calls and asserts `rejectedDials == 0` (and `allowedDials > 0`) — it proves
a normal session dials only the configured provider, and does not itself exercise the auth/Codex path.

**2.** The **OpenAI chat-completions shape**. `provider.Response` exposes the `openai-go` types
directly (`*openai.ChatCompletion` or a chunk `Stream`). *Proof:* `provider/client.go` `Client`,
`Response`.

**3.** `Run` sees a non-context stream error; `provider.ClassifyStreamDrop` yields `phase=stream_drop`,
a `provider_request_failed` event is recorded durably (with the **rune** count), `Interrupt()` seals the
partial reply, and **no** `model_response`/assistant message is written. *Proof:* `turn/turn.go` `Run`;
`TestRun_MidStreamDropEmitsEventMarksInterrupted` in `failure_test.go`.

One drop gets extra handling: with provider `openrouter`, a retryable `ssestream.StreamError` whose body
has `metadata.error_type: "provider_unavailable"` and an upstream name that, lowercased, matches
`^[a-z0-9][a-z0-9-]*$` (`Upstream error from Together: …`) is turned into a slug by `provider.UnavailableUpstreamProvider`
(`provider/http_errors.go`). `Runner.Run` (`turn/turn.go`) calls the retry loop `Runner.runWithRetry`
(`turn/retry.go`), which adds a new slug to `turn.IgnoredProviders`, sends
`Provider together failing to respond. Removing for rest of this session` once through
`Deps.ProviderIgnoredNotice`, and retries the round with no delay, still counted toward `max_attempts`.
Later main-turn requests, including tool-continuation rounds, carry the list as
`provider.Request.IgnoredProviders`, which `ChatCompletion` (`provider/client.go`) writes as
`provider.ignore` for OpenRouter only; compaction, title generation, and delegated child turns send no
list. The list is
memory-only: it is never written to settings or the session, `turnController` (`bootstrap/turndeps.go`)
starts an empty one when the session store changes (`/clear`, `/resume`), and `runHeadlessTurn`
(`bootstrap/headless.go`) starts empty each run. *Proof:* `TestUnavailableUpstreamProvider`
(`provider/http_errors_test.go`), `TestChatCompletion_IgnoredProvidersSerialization`
(`provider/client_test.go`), `TestRun_UnavailableUpstreamRetriesImmediatelyWithIgnoreList`,
`TestRun_AlreadyIgnoredUpstreamTakesNormalBackoff`, `TestRun_UnrecognizedFailuresKeepNormalRetry`,
`TestRun_RetryDisabledStillIgnoresUpstreamBeforeFailure`,
`TestRun_NewlyIgnoredUpstreamRetriesCountTowardMaxAttempts`,
`TestToolLoop_IgnoredUpstreamKeptOnLaterRoundsAndTurns` (`turn/retry_policy_test.go`),
`TestTurnController_UnavailableUpstreamIsIgnoredUntilTheSessionChanges` (`bootstrap/turndeps_test.go`),
`TestRunHeadless_UnavailableUpstreamIsIgnoredWithOneNotice` (`bootstrap/headless_test.go`).

**4.** `assembleToolCalls` (`turn/tools.go`) accumulates name/args per `frag.Index`, keeps the first
non-empty `id`, returns calls sorted by index, and errors if a call is missing an id or name. *Proof:*
`TestAssembleToolCalls_FragmentedNameAndArguments`, `_MultipleIndexesOrderedByIndex`,
`_RejectsMissingIDAndName` in `tools_test.go`.

**5.** `BuildRequest` returns `ok=false` and `Run` returns `ErrNoModelSelected` with **no** provider call
and **no** event. *Proof:* `turn/request.go` `BuildRequest`, `turn/turn.go` `Run`;
`TestRun_NoModelRefusedNoProviderCall` (`turn_test.go`), `TestBuildRequest_NoModelRefused`
(`request_test.go`).

**6.** **No.** A non-2xx HTTP error is surfaced verbatim as a `*provider.HTTPError` notice (with a
`→ hint:` second line if the body declares a quota); it emits **no** event and writes no `model_response`.
*Proof:* `provider/http_errors.go` `surfaceHTTPError`; `TestRun_HTTPErrorSurfacesNoticeNoEvent`,
`TestRun_QuotaHTTPErrorSurfacesHintNoEvent` in `failure_test.go`. (Transport/empty-response failures *do*
emit `provider_request_failed`.) `provider.UnavailableUpstreamProvider` also reads an OpenRouter HTTP error
body; when that failure is retried and names an unavailable upstream, the upstream is excluded for the
rest of the session exactly as in answer 3.

**7.** Up to `maxConcurrency` (= `Cache.AgentMaxConcurrency()`, default **3**) via `agent.Schedule`;
dependencies (`Deps()`) and overlapping write `Targets()` serialize in input order; `maxConcurrency = 1`
is fully sequential. *Proof:* `agent/scheduler.go` `Schedule`; `TestScheduleRunsIndependentUnitsInParallel`,
`TestScheduleSerializesConflictingTargets`, `TestScheduleMaxConcurrencyOneRunsSequentially`.

**8.** **Global first**, then walked ancestors **farthest-first** (filesystem root → launchDir),
concatenated by `agentinstr.SystemPrompt`, then prepended as the leading `system` message by
`BuildRequest`. *Proof:* `agentinstr/prompt.go` `SystemPrompt`, `agentinstr/load.go`
`LoadAgentInstructions`; `TestSystemPrompt_AssemblesLoadedInOrderGlobalBeforeWalked`,
`TestBuildRequest_PrependsSystemPromptBeforeHistory`.

**9.** **No reasoning-effort parameter is sent**; `model_effort_unsupported` is emitted (before
`model_turn`), and `model_turn.effort` records `no-reasoning` — what actually went out — while the
configured value is preserved on the event's `configured_effort`. The stored selection is not
rewritten. The event is flushed durably before the provider call. Selecting `no-reasoning` yields the
same omitted parameter but **no** `model_effort_unsupported`, since it is a supported choice rather
than a dropped one; a provider's literal `default`, when the model still advertises it, is sent
unchanged like any other value. *Proof:* `model/turn_events.go` `ResolveRequestEffort` /
`EmitTurnStart`; `TestRun_UnsupportedEffortDurableBeforeProviderReturn`,
`TestRun_SupportedEffortReachesProviderRequest` in `turn_test.go`.

**10.** Building the chat service directly prevents any `OPENAI_*` environment variable from injecting a
base URL, API key, or header (only the resolved auth header is sent). `MaxRetries(0)` ensures a non-2xx
HTTP error is surfaced **verbatim, exactly once** — no silent 429/503 retries. *Proof:*
`provider/client.go` `NewClient`.

**11.** `ToolLoop.onToolCalls` (`turn/tools.go`) always persists the deny envelope via
`permissions.DeliverDeny` and always surfaces a friendly `Deps.Notice` line naming the refused
tool/command and reason (not the raw JSON). It then decodes the envelope's **`denied_by`** (a local
read of the existing contract, not a re-classifier): **`denied_by:"user"` halts** — no re-issue,
flush the round, `ToolLoop.Denied()` true (so title generation is skipped) — because a user refusal
must not be fed back as an invitation to retry; **`denied_by:"mode"` continues** — re-issue so the
model sees the refusal and picks a permitted read-only alternative, `Denied()` false, with recovery
guidance built into the reason by `permissions.planPosture`. A **malformed/unknown** envelope
**fails closed** to the terminal user-denial path so it can't bypass the halt. *Proof:*
`turn/tools.go` `ToolLoop.onToolCalls`, `decodeDenyEnvelope`; `permissions/orchestrate.go` `planPosture`,
`modeDenyReason`; `TestToolLoop_UserDeniedResultAppendedAndStops`,
`TestToolLoop_ModeDeniedResultAppendedAndContinues`, `TestToolLoop_DeniedResultMalformedEnvelopeStops`
(`turn/tools_test.go`), `TestPlanModeDenyReasonGivesRecoveryGuidance`
(`permissions/orchestrate_test.go`), `TestRunHeadless_PlanModeDeniesMutating` (`bootstrap/headless_test.go`).

**12.** **Only from the local discovered catalog** (`models.yaml`, read offline). `BuildCatalog`
(`provider/catalog.go`) projects the discovered ids read via `config.discoveredConfiguredModels`
(`config/cache.go`) into each configured `CatalogEntry.Models`; a settings `provider.<name>.models` list
is still parsed (`ProviderEntry.ModelsSet`/`Models`, `provider/schema.go`) but **no longer consulted for
selection**. A configured provider with no discovered ids stays present with an empty allowlist, and the
empty-catalog diagnostic tells the user to **refresh the provider catalog** rather than edit settings
(`Context.noSelectableLines`, `model/determine.go` — "refresh the provider catalog before retrying").
*Proof:* `TestBuildCatalog_ConfiguredProviderPreserved`, `TestBuildCatalog_SettingsModelsIgnored`,
`TestBuildCatalog_EmptyDiscoveredModelsDoNotFallbackToSettings` (`provider/catalog_test.go`).

**13.** `newModelPickerDeps` (`bootstrap/starttui.go` → `bootstrap/modeldeps.go`
`newProviderRefreshCallback`) installs `ProviderCatalogRefresher.Refresh`
(`bootstrap/provider_refresh.go`) as `tui.ModelPickerDeps.RefreshCatalog`. **Highlighting** a configured
provider fires **one non-forced** refresh (deduped per provider per picker session), and **Ctrl-R forces**
one regardless of age; the built-in **`openai-chatgpt`** is excluded (the picker skips it, and the service
also refuses any non-configured id / ChatGPT). **The picker owns** the trigger, the reserved Ctrl-R key, the
event-loop-marshaled row re-render (kept for the still-open session only), and the one-line secret-safe
notice; **the service owns** staleness (the three-day window), per-provider coalescing, discovery, the
atomic `models.yaml` write, and the live-cache rebuild — returning only a static outcome
(`refused`/`fresh`/`updated`/`failed`), never a credential. *Proof:* `TestModelPicker_StaleProviderRefreshesOnce`,
`TestModelPicker_CtrlRForcesProviderRefresh`, `TestModelPicker_IgnoresStaleRefreshCompletion`
(`tui/picker_model_test.go`), `TestModelPicker_RefreshProductionWiring` (`bootstrap/tui_commands_test.go`),
`TestProviderCatalogRefresher_RefusesNonconfiguredAndChatGPT` (`bootstrap/provider_refresh_test.go`).

**14.** The **`user`** role. `messagesFromRecords` (`turn/request.go`) projects a stored
`sessions.Compaction` as a user message — a note that its contents are reference data, then the summary
verbatim between `<prior_conversation_summary>` delimiters — because `user` is the lowest-authority
representation both mappings share: `toSDKMessages` (`provider/client.go`) sends it as a chat-completions
user message and `responsesInstructionsAndInput` (`provider/openai_chatgpt_client.go`) puts it in `input`,
while a `system` message would become the Responses **top-level `instructions`**, i.e. the same authority
channel as codemeld's product prompt. The summarization request's instruction channel holds **exactly one**
message: the fixed product-authored `compactionSummaryInstruction` used by `BuildCompactionSummaryRequest`,
which names the messages, tool results, and any earlier summary as material to summarize rather than
instructions to follow, and requires goals, constraints, read-only scope, approvals already given,
approvals still required, unresolved work, and proposed-versus-completed status to be preserved; history is
projected after it and never concatenated into it. What is deliberately **not** done: the summary is never
sanitized, keyword-filtered, or rewritten — it is carried verbatim, and only its transport role is
constrained. *Proof:* `TestBuildCompactionSummaryRequest_InstructionLikeContentStaysData`,
`TestCompactionSummaryInstruction_NamesRequiredStatusCategories`,
`TestBuildRequest_InstructionLikeSummaryIsNeverASystemMessage` (`turn/request_test.go`),
`TestToSDKMessages_OnlyProductPromptOccupiesTheSystemRole` (`provider/client_test.go`),
`TestChatGPTClient_OnlyProductPromptReachesInstructions` (`provider/openai_chatgpt_client_test.go`).

**15.** `HTTP-Referer: https://codemeld.dev` and `X-Title: Codemeld` — OpenRouter groups dashboard
activity by the referer and shows the title as the app name, so the referer has to be the real site it
can fetch for an icon. **Only `openrouter`** receives them: `NewClient` (`provider/client.go`) appends
the two `option.WithHeader` options when `ClientConfig.Attribution` is true **and** `ClientConfig.Name`
is the OpenRouter id, the same provider-id keying the nested `reasoning.effort` branch uses. Because
they are **construction-time request options**, they ride every chat-completion call, streaming or not,
and the `/models` discovery request — which builds no chat client — never carries them; Venice, OpenAI,
and custom providers never see them under either setting value. The user opts out on the **settings**
tab of the `/settings` overlay (Enter on the `openrouter attribution` row), which writes
**`attribution: false`** into `~/.codemeld/global/settings.yaml` — the key is global-only, so a project
file carrying it fails to load — and then updates `Cache.Attribution()` in the session. **Yes, before
the next turn:** `buildTurnClient` (`bootstrap/turndeps.go`) snapshots that accessor per client and
passes it into `ClientConfig`, so the two headers drop with no restart while the resolved auth header
and the nested `reasoning.effort` body are untouched. *Proof:*
`TestNewClient_OpenRouterAttributionHeadersSent`,
`TestNewClient_OpenRouterAttributionOptOutKeepsRestOfRequest`,
`TestNewClient_NonOpenRouterNeverAttributed` (`provider/client_test.go`),
`TestBuildTurnClient_FreeFunctionContract` and
`TestF1210_PermissionsSettingsTab_TogglesAttributionThroughRealWiring`
(`bootstrap/turndeps_test.go`, `bootstrap/tui_commands_test.go`).

**16.** **Presence, not value.** `openai-go` decodes field metadata alongside values, so
`normalizeUsage` (`internal/model/turn_events.go`) gates each subfield on
`u.JSON.PromptTokens.Valid()` / `u.JSON.CompletionTokens.Valid()` rather than on the number itself.
A present non-negative value is kept; a missing or negative one records 0 and raises `usage_missing`
once per event.

**Absence means "not reported", not "zero".** `cached_tokens` returns a `*int64` — nil for absent,
null, or negative; non-nil for a reported value, **including a reported 0**. Absence is not an
anomaly because providers legitimately omit the field: flagging it would mark healthy turns faulty,
so `usage_missing` stays limited to `prompt_tokens`/`completion_tokens`.

**The gating field is `u.PromptTokensDetails.JSON.CachedTokens`** — the presence metadata lives on
the nested details struct, not on `CompletionUsage.JSON`. `CompletionUsage.JSON.PromptTokensDetails`
answers a different question (was the *container* present), and reading it would still leave
`cached_tokens` itself unchecked inside a details object that carried only `audio_tokens`. The zero
value of the nested metadata reports `Valid() == false`, which is what makes a response with no
`prompt_tokens_details` at all read correctly as not reported.

**A mixed turn stays a lower bound.** `UsageAccumulator` sums the rounds that reported a cached count
and separately remembers that some round did not; `Totals` then returns the known sum together with
`cachedPartial`, which is persisted as `model_response.cached_input_tokens_partial: true`. The sum is
never discarded and never presented as exact. **Both** `EmitModelResponse` call sites carry it:
`Runner.Run`'s final-answer path (`internal/turn/turn.go`) and `ToolLoop.finalizeInterceptedRound`
(`internal/turn/tools.go`) — the suggest-only terminal round finishes in `tool_calls` and never
reaches the first, so omitting it there would silently drop the count for that turn shape.

**Same principle, opposite defaults.** The bridge emits what the upstream shape guarantees. A
Responses `usage` object always carries its three counts, so synthesizing them (including a 0) is an
honest reading — and emitting them unconditionally is what keeps `normalizeUsage` from recording
`usage_missing`. It carries `input_tokens_details.cached_tokens` only sometimes, so
`enqueueCompletion` attaches `prompt_tokens_details` **only when the payload actually carried it**;
synthesizing `cached_tokens: 0` would manufacture a "cache was cold" measurement no provider
reported. *Proof:* `normalizeUsage`, `UsageAccumulator.Add`/`Totals`
(`internal/model/turn_events.go`) pinned by `TestUsageFromStreamUsage`,
`TestUsageAccumulator_CachedTotals`, and
`TestUsageAccumulator_MissingUsageRoundMarksCachedPartial` (`turn_events_test.go`);
`TestRun_CachedPromptTokensReachRecordAndContext` (`turn/turn_test.go`) and
`TestToolLoop_SuggestOnlyRoundRecordsCachedTokens` (`turn/tools_test.go`) for the two call sites;
`enqueueCompletion` (`internal/provider/openai_chatgpt_client.go`) pinned by
`TestChatGPTClient_MapsResponsesCachedInputTokens` and
`TestChatGPTClient_OmittedResponsesCachedTokensSynthesizesNoDetails`.

**17.** Only `provider.data_collection: "allow"` is sent. The rule: absent values and
`require_parameters: false` are not sent, while an explicit `data_collection: allow` is — so there is
no `provider.sort` (no `sort` set) and no `provider.require_parameters` (only `true` is ever sent).
The routing values sit in the **same** `provider` object as the retry loop's `provider.ignore`, which
is added only when the session ignore list is non-empty; none of this is sent to any provider but
`openrouter`. *Proof:* `openAIClient.ChatCompletion` (`provider/client.go`); pinned by
`TestChatCompletion_OpenRouterRoutingAllowSentFalseOmitted`,
`TestChatCompletion_OpenRouterRoutingSentWithIgnore`, and
`TestChatCompletion_NonOpenRouterNeverSendsRouting` (`provider/client_test.go`).
