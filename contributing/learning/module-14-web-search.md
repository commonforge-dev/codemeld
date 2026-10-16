# Module 14 — Web research (`web_search` and `web_fetch`)

_Snapshot as of 2026-08-27; it may be out of date — refresh it from the code before studying._

> **Status: shipped, on by default, gated per host.** Both tools are in the tree. They are
> advertised to the model unless `web_research.enabled` is explicitly `false` in the global
> settings file, and every host they contact is authorization-checked before a connection is
> opened — a permission prompt appears whenever no already-saved grant or cached decision for that
> host resolves the request. Authorization is not the last check: an approved host buys public web
> access only, and `web_fetch` still refuses loopback, unspecified, link-local, private and
> unique-local, carrier-grade NAT, benchmarking, reserved and cloud-metadata destinations.
> There is no `quizzes/module-14.md` yet — use the hands-on below until it lands.

## Goal

Afterward you can say exactly what must be true before codemeld opens a network connection that
is not the LLM provider, and point at the code that enforces each condition.

## Why it matters

This is the subsystem that **extends codemeld's egress policy**, so it is the one most often
reviewed against the [network invariant](../invariants.md). Until it shipped, the sanctioned
outbound paths were the configured LLM provider client (Module 8) and the OpenAI ChatGPT
auth/Codex path (Module 15, pinned to OpenAI-owned origins). Web research adds host-scoped
destinations on top of those —
Exa's fixed search endpoint, plus whatever page the user approves — and it keeps the promise by
construction rather than by trust:

- **Availability is not authorization** — `web_research.enabled` defaults to `true`, so the model
  can *propose* a web call out of the box. Proposing is all it buys: the prompt still decides.
  Setting `enabled: false` is the kill switch for an install that must never egress; a disabled
  build never advertises the tools, so the model cannot even name them.
- **Global-only configuration** — the `web_research` block is rejected in a per-project
  `.codemeld/settings.yaml`, so a checked-out repository cannot switch egress on.
- **Configuration authorizes nothing** — enabling the feature grants no host. Every fetch and
  every search is still authorization-checked before the dial, and the only way a host ever becomes
  authorized is a permission prompt the user answered; later requests that a saved grant or a
  cached session decision already covers resolve without asking again
  (`internal/permissions/orchestrate.go` → `resolveWithoutPrompt`).
- **Permission-gated per host** — the grant is scoped to one canonical hostname, not a filesystem
  path, and a path grant can never satisfy a host request.
- **No shipped credential** — codemeld ships no Exa key and is never preconfigured for Exa.
  Neither tool needs a key: with `web_research.api_key` empty, an enabled and authorized
  `web_search` still runs keyless, exactly as `web_fetch` does. Supplying a key only adds Exa's
  `x-api-key` header (redacted out of anything that comes back); it authorizes no host and unlocks
  no tool.
- **Untrusted by contract** — fetched pages and search results are data, never instructions. The
  Build-mode system prompt says so explicitly (`internal/agentinstr/baseprompts/build.md`).
- **A search finds; a fetch reads** — `web_search` returns up to five ranked candidates (title,
  address, snippet, published date) and contacts nothing but Exa. It opens no connection to a result
  host, so approving a search is a decision about the search alone. The model then picks the
  promising candidates and calls `web_fetch` on each, and every one of those raises its own
  exact-host prompt. The split is deliberate: web research is authorized at the permission prompt
  and nowhere else, so approving a search never carries approval to read what it found
  (`internal/permissions/entry.go`).
- **Auditable after the fact, without guesswork** — because each stage is a separate persisted call,
  a finished session can be read back as a funnel: `codemeld sessions research <id|path>` lists the
  searches, their candidates, which candidates a later `web_fetch` actually asked for, what each
  fetch recorded, and which addresses a later visible answer quoted exactly. It reports what was
  called and answered, never why: an address the report does not mark `cited` is **not** an address
  the model ignored. See [Module 7](module-07-sessions-events.md) and
  [`docs/sessions.md`](../../docs/sessions.md).

## Read (in order)

- [`internal/config/cache.go`](../../internal/config/cache.go) → `WebResearchSettings`,
  `Cache.WebResearch`, `Cache.WebResearchAPIKey`, and the `defaultWebResearch*` constants. Note
  that the API key is deliberately *not* a field of `WebResearchSettings`, so no formatted
  settings dump can disclose it.
- [`internal/config/globalonly.go`](../../internal/config/globalonly.go) → why any `web_research`
  key in a project settings file is a load-time violation.
- [`internal/bootstrap/tooldispatch.go`](../../internal/bootstrap/tooldispatch.go) →
  `webResearchTools`, `setWebFetch`, `dispatchWebFetch`, `dispatchWebSearch`, and
  `encodeSearchCandidates`. This is the spine: registration behind the switch, the authorization
  call per target, and the bounded JSON handed back to the model. Note what
  `encodeSearchCandidates` does *not* do — it never calls `FetchText`, so the search path ends at
  metadata.
- [`internal/webresearch/fetch.go`](../../internal/webresearch/fetch.go) → `FetchText`. The
  authorization callback runs *before* the request is built, and again for every redirect hop; a
  nil callback is a hard error rather than an open door.
- [`internal/webresearch/address.go`](../../internal/webresearch/address.go) → `mustNotDial`,
  `guardDial`, and `GuardedDialContext`. The destination classes a fetch may never reach, and the
  dialer hook that applies them to the address a connection is about to use. `admit` in `fetch.go`
  calls the same predicate on a literal-IP URL so such a host is never offered at the prompt.
- [`internal/webresearch/exa/adapter.go`](../../internal/webresearch/exa/adapter.go) → `Config`,
  `New`, and the bounded transport: one fixed endpoint, the optional `x-api-key` header, and key
  redaction on the way back.
- [`internal/permissions/entry.go`](../../internal/permissions/entry.go) and
  [`internal/permissions/matcher.go`](../../internal/permissions/matcher.go) → `HostScope`,
  `parseHostEntry`, `hostGrantMatches`. This is the schema extension Module 5 does not cover.
- [`contributing/invariants.md`](../invariants.md) → the network egress invariant, and the rule
  that no mode ever auto-allows a web tool.
- [`docs/architecture.md`](../../docs/architecture.md) → "Privacy & Telemetry" and the
  sanctioned-destination policy this feature is a narrow exception to.

For the *why* behind each decision, read the tests that pin it — they are the executable record:
[`internal/webresearch/exa/adapter_test.go`](../../internal/webresearch/exa/adapter_test.go) (the
one fixed endpoint, keyless by default, and key redaction),
[`internal/webresearch/fetch_test.go`](../../internal/webresearch/fetch_test.go) (authorization
before the dial and again per redirect hop),
[`internal/webresearch/address_test.go`](../../internal/webresearch/address_test.go) (every
non-public class refused, each dial classified on its own, and a real loopback listener refused
before the connection completes), and
[`internal/permissions/matcher_test.go`](../../internal/permissions/matcher_test.go) (why a host
grant is one exact host, project-scoped, and never satisfied by a path grant).

## Mental model

Five gates stand between the model and a packet on the wire. Trace them in order:

1. **Configuration** — `Cache.WebResearch()` reads the global `web_research` block. An omitted
   block resolves enabled; an explicit `enabled: false` wins over that default, and disabled means
   `webResearchTools` is never registered and `setWebFetch` leaves `fetchClient` nil, so even a
   hand-crafted call fails closed with `errWebResearchUnavailable`.
2. **Advertising** — when enabled, exactly two web-research tools join the registry, `web_search`
   (parameter `query`) and `web_fetch` (parameter `url`), both marked mutating; the file and VCS
   tools stay registered alongside them. The registry entries are placeholders; the real work
   happens in the dispatcher.
3. **Authorization** — `dispatchWebFetch` authorizes the target host, and `dispatchWebSearch`
   authorizes `mcp.exa.ai` before the query and nothing else. The prompt offers allow once / deny /
   this session / this project; a kept grant is written as `kind: tool`, subject `web_search` or
   `web_fetch`, `host_scope: <one canonical host>`, `grant_kind: project`. Wildcards, folder grants,
   and global grants are all rejected. A candidate the search returned reaches authorization only
   when the model issues its own `web_fetch` for it.
4. **Address safety** — the host the prompt approved is a name, and a name is not a machine. On the
   fetch path, `guardedFetchClient` builds a client whose dialer is `GuardedDialContext`, so
   `mustNotDial` runs on the concrete address each connection is about to use: an approved host that
   resolves — now or on a later lookup — to a loopback, unspecified, link-local, private and
   unique-local, carrier-grade NAT, benchmarking, reserved or cloud-metadata address is refused
   anyway, on every redirect hop as much as on the first. A grant is not permission to reach one of
   those. The same predicate runs earlier in `admit` for a URL that is already a literal address, so
   the prompt never offers one. That client also carries no proxy, because a proxy would resolve and reach the
   blocked destination on codemeld's behalf.
5. **Bounds** — one timeout per request from `timeout_seconds`, at most five returned candidates
   with each metadata field capped at the capability layer, and results encoded to fit the
   tool-output cap as a *complete* JSON object rather than a truncated string: overflow shrinks
   candidate metadata and then drops whole candidates into the `omitted` count. A candidate `url` is
   the one field never shortened: it is surfaced as the complete canonical URL `web_fetch` accepts or
   the candidate goes into `omitted`, because a cut URL points somewhere else. That holds beneath the
   capability layer too — the Exa adapter caps every other field it parses but hands the result URL
   over whole, since once it is cut the capability layer cannot tell it from a URL Exa really ranked.

Chain to memorize:
`tooldispatch.go:dispatchWebFetch` → `fetchAuthorization.authorize` → `permissions.Authorize`
(host match) → `webresearch.FetchText` → `guardDial` (per connection) → `encodeFetchResult`.

The search path is a shorter, separate chain that never joins it:
`dispatchWebSearch` → `permissions.Authorize` (`mcp.exa.ai` only) → `SearchBackend.Search` →
`encodeSearchCandidates`. Reading a candidate means the model starts the fetch chain above from the
top, with its own prompt.

## Watch for (Go idioms)

- **A callback as the gate.** `FetchText` takes an authorization func instead of a pre-checked
  flag, so the check cannot drift away from the dial — including on redirects, where the host
  changes after the first approval.
- **Fail-closed nil.** A nil HTTP client and a nil authorization callback are both errors, not
  no-ops. The disabled state is represented by absence, so forgetting to wire it up cannot
  accidentally enable egress.
- **A struct that omits a field on purpose.** `WebResearchSettings` has no API key field; the key
  reaches `exa.Config` through a separate accessor at the single construction site.

## Hands-on

1. **Confirm on by default, and the opt-out.** Run `CGO_ENABLED=0 go build -o codemeld ./cmd/codemeld`
   and launch codemeld with no `web_research` block; `/status` shows web research on. Add
   `web_research: {enabled: false}` to the global settings file and relaunch to see it off. Then
   find the code that decides that string.
2. **Predict, then verify.** Before reading `hostGrantMatches`, predict whether a saved
   `web_fetch` grant for `example.com` lets `web_search` reach `mcp.exa.ai`. Then read the
   function and check yourself.
3. **Break it in a test.** In `internal/bootstrap/tooldispatch_test.go`, find a test that asserts
   the per-target authorization subjects for a search. Temporarily remove the Exa authorization
   call from `dispatchWebSearch` and confirm the test fails — then restore it.
4. **Trace a redirect.** Follow `FetchText` through one redirect hop and name the exact line that
   re-authorizes the new host.
5. **Count the prompts.** Predict how many permission prompts a single approved `web_search` raises
   before the model does anything else, then check yourself against
   `TestWebSearchIntegration_AuthorizesOnlyExaThenTheSelectedCandidateSeparately`.
6. **Read a funnel back.** Run `codemeld sessions research internal/cli/testdata/sessions-research.json`.
   Pick one address the report labels `candidate` and nothing else, and write down everything the
   file actually proves about it — then notice how little that is, and why "the model did not use
   it" is not on the list.

## Done when

- You can name the five gates above in order and the function that implements each.
- You can say which destination classes a `web_fetch` refuses whatever the user approved, and why
  that check belongs at the address the dialer attempts rather than on the hostname.
- You can say what a `web_search` result contains, what it deliberately does not, and why reading a
  candidate needs a second tool call with its own approval.
- You can say what `sessions research` can prove about a source from the session file — and why an
  uncited source is not an unused one.
- You can state why the `web_research` block is global-only, and what an enabled block does *not*
  authorize.
- You can explain why a host grant is `grant_kind: project` and never `folder` or `global`.
- You can say what both tools need from the user (an approval at the prompt, on an install that has
  not set `enabled: false`), why neither needs an Exa key, and that supplying one authorizes no host.
- You can point at the Build-mode instruction that classifies fetched content as untrusted data.
