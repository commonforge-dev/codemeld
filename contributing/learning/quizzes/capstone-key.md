# Answer key — Capstone (synthesis)

Citations are **file + function/symbol name**, drawing across modules.

---

**1.** Three sanctioned functions open outbound connections, each pinned to its own origin:
- `provider.NewClient` (`provider/client.go`) — OpenAI-compatible chat-completions traffic to the
  **configured** provider base URL; reached in production only via the `newTurnProviderClient` seam
  (`bootstrap/turndeps.go`).
- `provider.NewChatGPTClient` (`provider/openai_chatgpt_client.go`) — ChatGPT/Codex model requests,
  hardcoded and non-overridable to `https://chatgpt.com/backend-api/codex` (`chatGPTCodexBaseURL`).
- `openaiauth.Flow.postForm` (`openaiauth/oauth.go`) — OAuth login/token/refresh/revoke traffic,
  hardcoded and non-overridable to `https://auth.openai.com` (`productionAuthBaseURL`).

Tests: `TestNoNetwork_FullSessionDialsOnlyConfiguredProvider` (`bootstrap/no_network_test.go`) runs a
real launch against a stub, guards `DialContext` with an allowlist, and asserts `rejectedDials == 0`
(and `allowedDials > 0`); `TestNewChatGPTClient_PinsApprovedOrigin` and
`TestAuthorizeURLDeterministicAndPinned` / `TestNewFlowPinnedToProductionOrigin` pin the ChatGPT and
auth origins; `TestTurnController_ChatGPTHTTPFailureRedactsCredentialsAcrossLayers`
(`bootstrap/turndeps_test.go`) proves credentials are redacted from the surface notice, persisted
session, and the failure event. *(Modules 1, 8, 15)*

**2.** Atomic writes happen in: **session flush** (`sessions/store.go` `Flush` → `fsutil.WriteAtomic`),
**settings persistence** (`config/rewrite.go` `RewriteKey` → `fsutil.WriteAtomic`), and **first-run /
VCS template materialization** (`bootstrap/firstrun_*`). The advisory lock is on a **sidecar**
(`<file>.lock`) because `WriteAtomic` replaces the data file's inode via rename — a lock on that inode
would be orphaned and give no cross-process exclusion. *(Modules 4, 7, 11)*

**3.** **session** — persists nowhere (in memory only); **folder** — `<project_root>/.codemeld/settings.local.yaml`;
**global** — `~/.codemeld/global/settings.yaml`. Creating + saving a folder grant involves: `permissions`
(the grant + matcher), the TUI prompt (`tui/prompt.go` `PromptUser`), the in-memory append
(`config/cache.go` `AppendPermission`), and durable write via `config/persist.go` `Persist` →
`config/rewrite.go` `RewriteKey` → `fsutil.WriteAtomic` (with `permissionpersist.PersistGrantReportingCreate` handling
a failed write by degrading to session scope). *(Modules 5, 4, 11)*

**4.** Inferring the root from VCS would be circular: user VCS *templates* are discovered relative to
the project root, but VCS *detection* would itself produce that root — neither could run first. The
`.codemeld/settings.yaml` marker is observable on the filesystem before any VCS work, breaking the
cycle (and letting non-VCS projects work without a special case). *Proof:* `docs/architecture.md` →
"Project root: marked by `.codemeld/settings.yaml`"; `config/discovery.go` `LocateProjectRoot`. *(Modules 1, 4, 9)*

**5.** **Nothing runs.** `dispatchDirect` (`dispatch/shell.go`) is two passes — it authorizes *all*
stages first and returns `*DeniedError` before pass 2 begins, so even the granted `cat x` stage never
executes. *Proof:* `TestDispatchShell_PipelineOneStageDeniedShortCircuits`. *(Module 6)*

**6.** `App.submitCurrent` (`tui/app.go`) → the `SubmitFunc`; a non-slash line returns
`StatusNotASlashCommand` and is forwarded to the `PromptEntrypoint` (the turn path). The system
message is assembled per turn by `newSystemPromptAssembler` → `assembleSystemMessageFrom`
(`bootstrap/starttui.go`), which calls `agentinstr.AssembleSystemMessage` (`agentinstr/assemble.go`)
to build the **full** synthetic message: active-mode base prompt + special instructions +
environment block + the AGENTS.md text. `agentinstr.SystemPrompt` (`agentinstr/prompt.go`)
contributes **only** that last AGENTS.md section, not the whole message. `turn.BuildRequest`
(`turn/request.go`) then projects the session history and **prepends** the already-assembled single
`system` message as the leading message. *(Modules 12, 10, 8)*

**7.** A **real grant** is a durable/in-memory `PermissionEntry` matched by `Match` (`permissions/matcher.go`);
a **turn-cache hit** is a per-turn memoized *outcome* (`permissions/turncache.go` `TurnCache`) that
creates no grant. A **real grant always wins** — the cache is consulted only when `Match` returns no
match. *Proof:* `matcher.go` `Match`, `turncache.go` `Lookup`. *(Module 5)*

**8.** **Mid-turn** (`sessionfailures.HandleWriteFailure`): retain the in-memory records, append a
`session_write_failed` event, render a notice, **no** synchronous retry — the next flush carries
everything. **Clean shutdown** (`sessionfailures.CleanShutdownFlush`): retry the flush exactly once,
then print an `OP_FAIL` line and exit 1, emitting **no** event (no later flush could carry it). *Proof:*
`sessionfailures/failures.go`; `TestHandleWriteFailure_RetainsRecords_EmitsEvent_NoSyncRetry`,
`TestCleanShutdownFlush_SecondFailure_OpFail_Exit1_NoEvent`. *(Module 7)*

**9.** Steps 0a–7 must succeed first: resolve home (0a), first-run check (0), load global settings (1),
resolve project root (2), compose config (3), load VCS templates (4), validate preferred VCS (5),
detect VCS (6), build the tool registry (6c), and determine the active model (7). Only then does
`EnsureFreshSession` (7b) create the session. *Proof:* `bootstrap/orchestrate.go` `RunFresh`;
`TestRunFresh_StepOrder`. *(Module 3)*

**10.** Examples (any two): `TestIsDescendantOrEqual` (`permissions/scope_test.go`) *is* the definition
of path containment, including the "sibling prefix trap" `/a/foobar` vs `/a/foo`; `TestParseSlashInput`
(`tui/slashparse_test.go`) *is* the grammar of a slash command; `TestNormalizeDirectStage_Assignments`
(`permissions/normalize_direct_test.go`) *is* the definition of env-assignment stripping;
`TestCategorizeErrno` (`fserrors/category_test.go`) *is* the errno→category mapping. *(Modules 5, 10, 11)*
