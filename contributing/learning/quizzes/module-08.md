# Quiz — Module 8: Turn & provider

_Last updated: 2026-10-06_

Closed-book. Write your answers before opening `module-08-key.md`.

---

**1.** Which sanctioned, origin-scoped paths is codemeld allowed to reach over the network, and what
enforces that guarantee?

**2.** What is the internal provider contract (the request/response shape)?

**3.** What happens on a transport drop mid-stream, after some content has arrived?

**4.** How are streamed tool-call fragments reassembled into whole calls?

**5.** What does a turn do when no model is selected?

**6.** Does a non-2xx HTTP error from the provider emit a `provider_request_failed` event?

**7.** How many work units run in parallel by default, and how are conflicting writes handled?

**8.** In what order are `AGENTS.md` files assembled into the system prompt?

**9.** When a model doesn't support the configured effort, what is sent to the provider and what is
recorded? How does that differ from selecting `no-reasoning`, or from a provider that advertises a
literal `default`?

**10.** Why does `NewClient` build the chat service directly instead of via `openai.NewClient`, and
why `MaxRetries(0)`?

**11.** A dispatched tool call comes back **denied**. How does the turn loop decide whether to halt the
turn or re-issue the model, what does the user see either way, and how does a malformed deny envelope
behave?

**12.** Where does a configured provider's selectable model ids come from, what happens to a
`provider.<name>.models` list in settings, and what does the user see when a configured provider has no
selectable ids?

**13.** In the model picker, what triggers a background catalog refresh for a configured provider, which
provider is excluded, and which responsibilities belong to the picker versus the refresh service?

**14.** A `/compact` summary is written by the model from a conversation that included tool output. Which
message role carries that stored summary on the next normal turn and why that one, what occupies the
instruction channel of the summarization request itself, and what is deliberately *not* done to the
summary text?

**15.** Codemeld sends two headers that name the editor to the provider. Which headers and values,
which providers receive them and which never do, where in the client are they attached (and what does
that placement imply for streaming versus discovery requests), and how does a user switch them off
without losing auth or the OpenRouter reasoning-effort shape? Does the opt-out take effect before the
next turn, and which settings file does it land in?

**16.** A provider reports token usage and codemeld records it. How does `normalizeUsage` tell a
reported `0` from a field the provider never sent, and where does that presence information come
from? `prompt_tokens_details.cached_tokens` follows the same path but reaches the opposite verdict
on absence — what does it return when absent, and why is that not an anomaly? Name the exact field
whose presence gates it, and say why reading it off `CompletionUsage.JSON` would be wrong. In an
agentic turn, how does one round that reported no cached count change what the turn's single
`model_response` records, and which **two** call sites have to carry that? Finally, the ChatGPT
Responses bridge always emits three counts but only sometimes emits `prompt_tokens_details`:
justify both defaults from the same principle.

**17.** A global `provider.openrouter.routing` block sets `data_collection: allow`,
`require_parameters: false`, and no `sort`. Which of these values does `ChatCompletion` send, under
which keys, and where do they sit relative to the retry loop's `provider.ignore` list?
