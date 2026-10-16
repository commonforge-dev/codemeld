// Production wiring for the provider turn: the bootstrap-owned controller that
// builds a turn.Runner per accepted prompt, runs it off the tview event loop,
// streams its deltas into the transcript, and exposes cancellation to the
// ESC/CTRL-C path.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
)

// newTurnProviderClient builds the production provider client for one turn. It is
// a package-level seam (like runApp and newResumeDeps) so bootstrap tests can
// drive the wired submit path against a stub client and assert a turn is issued
// without any outbound network traffic; production never reassigns it.
var newTurnProviderClient = func(cfg provider.ClientConfig) provider.Client {
	return provider.NewClient(cfg)
}

// newChatGPTProviderClient builds the production OpenAI ChatGPT Responses API adapter
// from already-resolved credentials. Like newTurnProviderClient it is a
// package-level seam so a ChatGPT dispatch test can capture the credentials the turn
// wiring resolved — proving the proactively-refreshed session reaches client
// construction — and return a no-network stub; production never reassigns it.
var newChatGPTProviderClient = func(cfg provider.ChatGPTClientConfig) provider.Client {
	return provider.NewChatGPTClient(cfg)
}

var openRouterEndpoints = &provider.OpenRouterEndpointStore{}

// chatGPTAuth resolves and refreshes the stored OpenAI ChatGPT session for turn
// dispatch. *openaiauth.Flow satisfies it in production; ChatGPT dispatch tests
// inject a fake to drive the missing-session, proactive-refresh, and reactive-retry
// paths without network or stored credential state.
type chatGPTAuth interface {
	EnsureFreshSession(ctx context.Context, settingsPath string) (authstate.Session, error)
	RefreshNow(ctx context.Context, settingsPath string) (authstate.Session, error)
}

// chatGPTNoSessionNotice is the safe, credential-free remediation surfaced when a
// submitted openai-chatgpt turn has no usable stored session (absent, corrupted, or
// otherwise unauthenticated). It names the selected provider and both recovery
// commands and never contains a token, account id, or other credential-derived value.
const chatGPTNoSessionNotice = "OpenAI ChatGPT has no usable local session; run `codemeld auth status` or `codemeld auth login openai-chatgpt`"

// chatGPTTurnClient is the production provider.Client for a turn whose selected
// provider is openai-chatgpt. Per provider request (one ChatCompletion call — one
// provider round) it proactively loads and, when near expiry, refreshes the stored
// ChatGPT session, constructs the Responses adapter from the resolved
// credentials, and on a provider 401/403 performs exactly one reactive
// refresh-and-retry before surfacing a safe error. A missing/invalid/expired session
// or a failed refresh fails the turn as a credential-free, provider-named
// *provider.CredentialUnavailableError, never switching to the OpenAI Platform or any
// other provider. Each round builds a fresh adapter and gets its
// own one-shot reactive budget, so a tool-call continuation round refreshes
// independently. It holds no mutable state, so the per-round Runner calls it
// sequentially without synchronization.
type chatGPTTurnClient struct {
	auth         chatGPTAuth
	settingsPath string
	newInner     func(provider.ChatGPTClientConfig) provider.Client
}

func (c *chatGPTTurnClient) ChatCompletion(ctx context.Context, req provider.Request) (provider.Response, error) {
	// Proactive refresh before client construction: a near-expiry or already-expired
	// token is refreshed and persisted now so the request does not start on a token
	// that expires mid-flight. A missing/invalid session fails the turn here,
	// before any request, with the lazy missing-session notice.
	sess, err := c.auth.EnsureFreshSession(ctx, c.settingsPath)
	if err != nil {
		return provider.Response{}, c.credentialError(err)
	}
	resp, err := c.newInner(chatGPTConfig(sess)).ChatCompletion(ctx, req)
	if !reactiveRefreshWarranted(err) {
		return resp, err
	}
	// Exactly one reactive refresh-and-retry on a provider 401/403: a
	// 401/403 can mean the token was revoked server-side while still locally unexpired,
	// so force a refresh and retry the request once. A failed refresh fails the turn
	// with the safe refresh-failure surface; a second 401/403 (or any other error) from
	// the retry is returned as-is, so a still-rejected credential surfaces a safe error
	// with no further retry.
	refreshed, rerr := c.auth.RefreshNow(ctx, c.settingsPath)
	if rerr != nil {
		return provider.Response{}, c.credentialError(rerr)
	}
	return c.newInner(chatGPTConfig(refreshed)).ChatCompletion(ctx, req)
}

// credentialError maps a session-load or refresh failure onto the turn-surfacing
// error. A context cancellation/deadline (a user interrupt or the turn deadline) is
// returned untouched so the turn layer treats it as a cancel, not a credential
// failure; every other failure becomes a credential-free, provider-named
// *provider.CredentialUnavailableError so the turn fails actionably without switching
// providers.
func (c *chatGPTTurnClient) credentialError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &provider.CredentialUnavailableError{Surface: chatGPTCredentialSurface(err)}
}

// chatGPTConfig packs a resolved session into the ChatGPT adapter config. Only the
// access token and account id are supplied; the adapter pins its own approved origin.
func chatGPTConfig(s authstate.Session) provider.ChatGPTClientConfig {
	return provider.ChatGPTClientConfig{AccessToken: s.AccessToken, AccountID: s.AccountID}
}

// reactiveRefreshWarranted reports whether a model-request error is a ChatGPT provider
// 401/403 that warrants the one reactive refresh-and-retry. Only an *provider.HTTPError
// with a 401/403 status qualifies (openaiauth.ShouldRefreshAfterStatus); a quota/rate-limit
// response, transport failure, empty response, or any non-HTTP error is left for the
// turn layer to surface unchanged.
func reactiveRefreshWarranted(err error) bool {
	var httpErr *provider.HTTPError
	return errors.As(err, &httpErr) && openaiauth.ShouldRefreshAfterStatus(httpErr.Status)
}

// chatGPTCredentialSurface returns the safe, provider-named remediation for a
// session-load/refresh failure. A refresh failure reuses the credential-free
// *openaiauth.RefreshFailure message (which also names both recovery commands); a
// missing/invalid session (or any other unexpected failure) yields the
// login-or-status notice rather than risk surfacing an unredacted message.
func chatGPTCredentialSurface(err error) string {
	var refreshErr *openaiauth.RefreshFailure
	if errors.As(err, &refreshErr) {
		return refreshErr.Error()
	}
	return chatGPTNoSessionNotice
}

// goTurn runs the per-turn work on a background goroutine. It is a package-level
// seam (like runApp) so a test can wrap the launch in a WaitGroup and wait for the
// turn goroutine to finish before reading the session store; production launches a
// plain goroutine so the submit hook returns to the tview event loop immediately.
var goTurn = func(fn func()) { go fn() }

// newToolLoop builds the per-turn agentic loop. It is a package-level seam
// (like goTurn) so a controller test can capture the as-built turn.Deps and fire the
// idle/activity hooks dispatch wires — the only way to prove that wiring without
// driving the unexported turn-package idle timer; production builds the real loop.
var newToolLoop = turn.NewToolLoop

// turnSurface is the subset of *tui.App the turn controller renders through: the
// streamed-delta sink, the natural-completion finalizer, the mid-stream-drop
// interrupt sealer, retry UX hooks, the committed in-place
// provider-error sink, and the one-line notice sink used for
// session-write failures. *tui.App satisfies it; controller tests substitute a
// fake to observe the calls without a running tview screen.
type turnSurface interface {
	AppendStreamDelta(delta string)
	FinalizeStream()
	MarkStreamInterrupted()
	// AppendToolActivity renders one tool-call round's about-to-run calls as live,
	// inline transcript lines — the formatted lines turn.ToolActivityLines
	// produced, fired before dispatch. *tui.App finalizes any in-progress reply first,
	// then appends the escaped lines as one block; it is display-only and never replayed.
	AppendToolActivity(lines []string)
	// CommitProviderError commits a provider/turn request failure as a permanent
	// in-place transcript line tied to the turn that produced it, so the error
	// scrolls with history instead of re-pinning below later turns. It is the
	// sink for the turn's Notice hook (the verbatim provider surface + remediation hint).
	CommitProviderError(text string)
	// NoticeFromBackground surfaces a one-line transient notice for
	// session-write failures (routed via turnNoticeRenderer/OnFailureWrite) — session
	// durability problems, which are not provider/turn request errors and do not
	// belong in committed history.
	NoticeFromBackground(text string)
	// In-flight indicator: ShowIndicator reveals it at dispatch seeded with
	// the session's starting uploaded (input) and downloaded (output) token totals,
	// SetIndicatorTokens updates the running ↑/↓ figures from the runner's exact
	// per-round Usage callback only (the streamed Progress signal is deliberately not
	// wired in — see the Usage binding below), and ClearIndicator hides it when the turn
	// loop returns (covering completion, interrupt, and failure).
	ShowIndicator(input, output int64)
	SetIndicatorTokens(input, output int64)
	ClearIndicator()
	TurnEnded(outcome string)
	// SeedNextIndicatorStart seeds the next ShowIndicator's elapsed clock with a
	// production turn's submit-start so the indicator's final visible elapsed matches the
	// turn's recorded turn_latency. dispatch calls it just before ShowIndicator
	// when submitStart is non-zero; a zero submitStart leaves the default dispatch-start.
	SeedNextIndicatorStart(start time.Time)
	// AppendCompletionFooter appends the "provider - model - duration" footer for the
	// just-completed successful turn from the store's durable model_turn/turn_latency
	// records. run calls it after a natural completion; a turn with no visible
	// reply or missing timing records appends nothing, so failed/interrupted turns stay
	// footer-free.
	AppendCompletionFooter(records []sessions.Record)
	// SuggestFollowup receives an intercepted suggest_followup tool call: label
	// is the imperative shown as Tab-to-accept ghost text and prompt is the prefill text.
	// The turn loop fires it instead of dispatching/persisting the call, so it is purely
	// ephemeral UI state. *tui.App renders the ghost text.
	SuggestFollowup(label, prompt string)
	// RollbackPartial removes the un-sealed in-progress reply before an auto-retry's
	// discard-and-restart retry of a partial stream_drop, so the regenerated answer does
	// not stack on the discarded partial. The retry engine calls it before re-issuing.
	RollbackPartial()
	// ShowRetryBackoff switches the in-flight indicator to a reconnecting state while
	// the retry loop waits before the next attempt.
	ShowRetryBackoff(nextAttempt, totalAttempts int)
	// ResumeRetry switches the in-flight indicator back to Working before re-issue.
	// It also clears any idle-waiting state, so it doubles as the return-to-Working
	// sink for a provider stream that resumes after going idle (the turn's OnProviderStreamActivity hook).
	ResumeRetry()
	// SetProviderIdle switches the in-flight indicator to provider-specific waiting copy
	// (provider display name + idle duration) when the live turn stream goes idle
	// (the turn's OnProviderStreamIdle). displayName is the selected provider's catalog
	// display name, resolved at dispatch. The surface owns the retry-priority and
	// no-resurrect-after-clear guards, so a late idle callback cannot revive a cleared line.
	SetProviderIdle(displayName string, idle time.Duration)
	// CommitRetryRecovered leaves a faint transcript breadcrumb after retry recovery.
	CommitRetryRecovered(retries int)
}

type editPatchSurface interface {
	AppendEditPatch(patch string)
}

var _ editPatchSurface = (*tui.App)(nil)

type queuedMessageSurface interface {
	UserMessageAdded(abort <-chan struct{}, store *sessions.Store, text string, parts []sessions.ContentPart)
	UserMessagesUnsent(store *sessions.Store, n, recorded int, outcome string) func()
	DiscardHeldPrompts()
}

var _ queuedMessageSurface = (*tui.App)(nil)

type turnNoticeRenderer struct{ surface turnSurface }

func (r turnNoticeRenderer) Notice(text string) { r.surface.NoticeFromBackground(text) }

// turnController owns the single in-flight provider turn for the run. It builds a
// fresh agentic tool-call loop (turn.NewToolLoop) per accepted prompt, starts
// it off the tview event loop, and implements tui.StreamCanceller over the live turn's
// context so the ESC/CTRL-C path can cancel it.
//
// Only one turn runs at a time: the submit path refuses a new prompt while a turn
// is in flight (busy), and dispatch is a no-op if a turn is somehow already active.
// The background goroutine reads a per-turn model.ActiveState snapshot, not the
// run-scoped active state, which is mutable and not concurrency-safe.
type turnController struct {
	ctx     context.Context
	surface turnSurface
	cache   *config.Cache
	active  *model.ActiveState

	// chatgptAuth resolves and refreshes the stored OpenAI ChatGPT session for a turn
	// whose selected provider is openai-chatgpt. settingsPath is the
	// resolved global settings file (~/.codemeld/global/settings.yaml) that resolver
	// reads and writes through. Both are bound by setChatGPTAuth — to openaiauth.NewFlow()
	// and SettingsPath(home) in production; they stay nil/empty in tests that never
	// select the openai-chatgpt provider.
	chatgptAuth  chatGPTAuth
	settingsPath string

	// assemblePrompt builds the system message for one turn at dispatch time, off the
	// current run-scoped interaction mode plus the environment inputs and
	// the launch-loaded AGENTS.md entries. It is called on the event-loop
	// goroutine in dispatch — the same place the model state is snapshotted — so a
	// later /mode switch affects the next turn rather than being frozen at startup.
	// nil yields no system message (tests that do not exercise prompt assembly).
	assemblePrompt func() string

	// assembleTools builds the turn's mode-filtered advertised tool set at dispatch time:
	// it snapshots the current run-scoped interaction mode and enumerates
	// the realized registry tools plus the product-authored `bash`
	// definition, filtering to read-only tools in Plan. Like assemblePrompt it is called
	// on the event-loop goroutine in dispatch and the result is frozen onto the turn's
	// Deps, so every provider round in the turn advertises the same set and a /mode
	// switch only affects the next turn. StartTUI binds it (setToolAdvertiser) once the
	// registry is realized; nil advertises no tools (tests not exercising advertising).
	assembleTools func() []provider.ToolDefinition

	// authorizer is the run's shared production permission authorizer: the dispatch seam
	// over permissions.Authorize, gated by the single prompt gate and safe for concurrent
	// scheduler workers. It is held here — the production turn-wiring seam — so the agentic
	// tool-call loop authorizes real tool/shell calls through this one gated path. StartTUI assembles
	// and hands off the authorizer and binds it (with the registry, runner, and home/process cwd)
	// into the dispatcher below.
	authorizer dispatch.Authorizer
	toolEvents *toolEventStore

	// dispatcher is the production binding of turn.ToolDispatcher: it routes the model's
	// tool calls to DispatchShell (bash) / DispatchTool (structured) behind the shared authorizer.
	// It is bound after construction by StartTUI (setToolDispatcher); it stays nil in tests that do
	// not exercise tool calls, which is safe because the tool-call loop only consults it on a tool-call
	// response.
	dispatcher turn.ToolDispatcher

	// delegateParent is the run-scoped holder a delegate call reads a child's inherited model,
	// mode, and system prompt from. StartTUI binds the same instance it gave the registry's
	// delegate binding (setDelegateParent); it stays nil where delegation is not wired, which
	// publishes nothing and leaves a delegate call with no parent.
	delegateParent *parentTurnHolder

	// devDebug, modeName, and armTUIDebug carry the dev-debug wiring, set once by
	// StartTUI (setDevDebug). When devDebug is on, dispatch threads the gate and the active
	// mode onto the turn's Deps (so the turn loop records its suggest_followup trace) and
	// arms the TUI surface with this turn's provider/model/mode (so the ghost stages stamp
	// the same context). All three stay zero in a controller whose gate was never set.
	devDebug    bool
	modeName    func() string
	armTUIDebug func(provider, model, mode string)

	// onTurnComplete fires after a successful first turn with the run-scoped context
	// (the per-turn context is already cancelled) and the opening exchange captured
	// before the turn slot was released, when a queued prompt cannot yet have landed.
	onTurnComplete func(ctx context.Context, client provider.Client, sel model.Selection, store *sessions.Store, firstUser, firstAssistant string)

	onUnsent func(store *sessions.Store, unsent []turn.PendingUserMessage, outcome string) func()

	ignoredProviders      *turn.IgnoredProviders
	ignoredProvidersStore *sessions.Store

	// mu guards live, the currently active turn's cancellation handle (nil when idle). It is taken
	// on the tview event-loop goroutine (dispatch, busy, Cancel) and on the turn goroutine (clearing
	// live when the loop returns), so it serializes the active-turn handoff between them.
	mu   sync.Mutex
	live *liveTurn
}

// setDevDebug binds the dev-debug wiring onto the controller. StartTUI calls it once
// with the resolved gate, a snapshot of the active interaction mode, and the TUI surface's
// per-turn debug arm. When enabled is false the controller threads nothing, so a normal
// run records no suggest_followup debug events.
func (c *turnController) setDevDebug(enabled bool, modeName func() string, armTUIDebug func(provider, model, mode string)) {
	c.devDebug = enabled
	c.modeName = modeName
	c.armTUIDebug = armTUIDebug
}

// liveTurn is the controller's cancellation handle for one in-flight agentic turn. The
// controller cancels the whole loop through its context, while the loop reports whether
// a provider stream was active for the TUI's stream_interrupted contract.
type liveTurn struct {
	cancel    context.CancelFunc
	loop      *turn.ToolLoop
	drained   chan struct{}
	draining  chan struct{}
	drainOnce sync.Once

	explained atomic.Bool
}

type turnCacheResetter interface {
	resetTurnCache()
}

// setToolDispatcher binds the production tool-call dispatcher onto the controller. StartTUI
// calls it once, after realizing the registry, so the tool-call loop routes real tool/shell
// calls through it.
func (c *turnController) setToolDispatcher(d turn.ToolDispatcher) { c.dispatcher = d }

func (c *turnController) setToolEventStore(store *toolEventStore) { c.toolEvents = store }

// setDelegateParent binds the run-scoped parent-turn holder onto the controller. StartTUI
// passes the same instance it gave the registry's delegate binding, so what this controller
// publishes is what a child reads.
func (c *turnController) setDelegateParent(h *parentTurnHolder) { c.delegateParent = h }

// setChatGPTAuth binds the OpenAI ChatGPT session resolver and the resolved global
// settings path so a submitted turn whose selected provider is openai-chatgpt can
// proactively refresh and one-shot reactively refresh the stored session.
// StartTUI calls it once with openaiauth.NewFlow() and SettingsPath(home); a
// controller without it never selects openai-chatgpt in production.
func (c *turnController) setChatGPTAuth(auth chatGPTAuth, settingsPath string) {
	c.chatgptAuth = auth
	c.settingsPath = settingsPath
}

// setToolAdvertiser binds the per-turn advertised-tool assembler onto the
// controller. StartTUI calls it once, after realizing the registry, so each dispatch
// advertises the mode-filtered tool set to the provider.
func (c *turnController) setToolAdvertiser(assemble func() []provider.ToolDefinition) {
	c.assembleTools = assemble
}

// setTurnCompleteHook binds the successful-turn completion hook. StartTUI calls
// it once with the first-turn auto-title generator; a controller without it runs turns
// with no completion side effect.
func (c *turnController) setTurnCompleteHook(fn func(ctx context.Context, client provider.Client, sel model.Selection, store *sessions.Store, firstUser, firstAssistant string)) {
	c.onTurnComplete = fn
}

func (c *turnController) setUnsentHook(fn func(*sessions.Store, []turn.PendingUserMessage, string) func()) {
	c.onUnsent = fn
}

func (c *turnController) addUserMessage(text string, parts []sessions.ContentPart) bool {
	c.mu.Lock()
	live := c.live
	c.mu.Unlock()
	return live != nil && live.loop != nil && live.loop.AddUserMessage(text, parts)
}

// newTurnController builds the run-scoped provider-turn controller over the running
// app's stream surface, the session config cache (for provider resolution and the
// scheduler concurrency limit), the run-scoped active model state (snapshotted per
// turn), the per-turn system-prompt assembler that leads every turn's provider
// request, and the production permission authorizer. assemblePrompt is invoked
// at dispatch so a /mode switch affects the next turn; a nil assembler sends no system
// message. StartTUI binds the production tool-call dispatcher separately (setToolDispatcher)
// once the registry is realized.
func newTurnController(ctx context.Context, surface turnSurface, cache *config.Cache, active *model.ActiveState, assemblePrompt func() string, authorizer dispatch.Authorizer) *turnController {
	return &turnController{ctx: ctx, surface: surface, cache: cache, active: active, assemblePrompt: assemblePrompt, authorizer: authorizer}
}

// Cancel cancels the currently active turn and reports the characters retained so
// far plus whether a provider stream was actually in flight, satisfying
// tui.StreamCanceller for the ESC/CTRL-C path. It cancels the whole agentic turn
// through its context (so tool scheduling/dispatch stops too), but the returned
// inFlight flag still means provider streaming, so key handlers only emit
// stream_interrupted for a real stream.
func (c *turnController) Cancel() (retainedChars int, inFlight bool) {
	c.mu.Lock()
	live := c.live
	c.mu.Unlock()
	if live == nil {
		return 0, false
	}
	if live.loop != nil {
		retainedChars, inFlight = live.loop.Cancel()
	}
	live.cancel()
	return retainedChars, inFlight
}

// StreamInFlight reports whether a provider stream is currently streaming, taking the
// same locks Cancel takes but cancelling nothing, so the TUI can decide whether an ESC
// has a turn to interrupt without interrupting it.
func (c *turnController) StreamInFlight() bool {
	c.mu.Lock()
	live := c.live
	c.mu.Unlock()
	return live != nil && live.loop != nil && live.loop.InFlight()
}

func (c *turnController) WaitTurnDrained() {
	c.mu.Lock()
	live := c.live
	c.mu.Unlock()
	if live != nil {
		live.drainOnce.Do(func() { close(live.draining) })
		<-live.drained
	}
	if s, ok := c.surface.(queuedMessageSurface); ok {
		s.DiscardHeldPrompts()
	}
}

// busy reports whether a turn is currently in flight. The submit path checks it
// before persisting so an overlapping prompt is retained (not persisted twice)
// rather than starting a second turn while one is streaming.
func (c *turnController) busy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.live != nil
}

// buildClient constructs the per-turn provider.Client for the selected provider from
// the controller's bound config cache and ChatGPT auth resolver. It delegates to the
// free buildTurnClient so the TUI turn controller and the headless driver build
// the provider client through one identical path.
func (c *turnController) buildClient(providerID string, kind provider.AuthKind) (provider.Client, bool) {
	return buildTurnClient(providerID, kind, c.cache, c.chatgptAuth, c.settingsPath)
}

// buildTurnClient constructs the per-turn provider.Client for the selected provider,
// branching on the selectable catalog's auth kind so a model selection fixes the provider's
// credential source for the turn. A custom/OpenRouter provider
// keeps its configured api_key/auth_header unchanged; OpenAI Platform applies the
// OPENAI_API_KEY-over-configured-key precedence; OpenAI ChatGPT ignores
// OPENAI_API_KEY and resolves the stored auth.openai-chatgpt session through the bound
// resolver, speaking the Responses API with one reactive refresh-and-retry per request.
// It reports ok=false (no turn) only for a defensively-unreachable state: a
// configured/Platform provider the catalog lists but the configured map lacks, or a
// ChatGPT turn with no bound auth resolver (production always binds one). It keeps the
// reassignable newTurnProviderClient / newChatGPTProviderClient seams intact so a test
// drives the wired path against a no-network stub. It is a free function — not a
// turnController method — so the headless run (which has no turnController) can build
// its single turn's client the same way the TUI path does.
func buildTurnClient(providerID string, kind provider.AuthKind, cache *config.Cache, chatgptAuth chatGPTAuth, settingsPath string) (provider.Client, bool) {
	if kind == provider.AuthKindChatGPTSession {
		if chatgptAuth == nil {
			return nil, false
		}
		return &chatGPTTurnClient{
			auth:         chatgptAuth,
			settingsPath: settingsPath,
			newInner:     newChatGPTProviderClient,
		}, true
	}
	entry, ok := cache.Provider(providerID)
	if !ok {
		return nil, false
	}
	if kind == provider.AuthKindPlatform {
		// OpenAI Platform: OPENAI_API_KEY wins over the configured provider.openai key.
		// ChatGPT and custom providers never take this branch.
		entry.APIKey = provider.ResolvePlatformAPIKey(entry.APIKey)
	}
	authHeader, authValue := entry.ResolveAuthHeader()
	cfg := provider.ClientConfig{
		Name:        providerID,
		BaseURL:     entry.BaseURL,
		AuthHeader:  authHeader,
		AuthValue:   authValue,
		Attribution: cache.Attribution(),
		Routing:     entry.Routing,
	}
	if providerID == "openrouter" {
		store := openRouterEndpoints
		cfg.MinThroughput = func(ctx context.Context, model string) (float64, bool) {
			return store.SpeedBar(ctx, entry, authHeader, authValue, model)
		}
	}
	return newTurnProviderClient(cfg), true
}

// dispatch starts a provider turn for the already-persisted active store. It runs
// on the tview event-loop goroutine (as the persist-before-dispatch callback):
// it snapshots the run-scoped active model state, resolves the selected provider's
// credential source from the selectable catalog (so a built-in openai-chatgpt
// selection resolves outside the configured provider: map), builds the agentic
// tool-call loop, and launches it on a background goroutine so the event loop
// stays free for ESC/CTRL-C cancellation and queued stream rendering. It returns nil
// once the turn is launched. Provider, credential, and runtime errors surface on the
// background goroutine, not here — the submit hook has already returned to the event
// loop, and provider/credential-failure recording/UX belongs to the turn's failure hooks.
//
// The loop runs through turn.NewToolLoop, threading the configured scheduler
// concurrency (Cache.AgentMaxConcurrency()) and the production dispatcher so a
// tool-call response routes real tool/shell calls to the dispatch backbone; a plain
// non-tool turn behaves exactly as the bare runner did.
//
// With no model selected, or a selected provider that is in neither the configured
// provider: map nor the built-in catalog, it issues no turn: there is no provider to
// build a client for (the turn Runner would itself refuse a no-model turn), and the
// model picker owns guiding the user to a selection. A selected provider that
// is in the catalog but has no usable credential (a missing OpenAI ChatGPT session)
// still launches a turn — the turn fails fast with a safe, provider-named notice
// rather than silently switching providers.
//
// submitStart is the wall-clock instant the user's input was accepted at the pre-turn
// boundary (sessionturn.Persister), forwarded here by the prompt entrypoint and frozen
// onto the turn's Deps so the final provider round records one end-to-end turn_latency
// event for the whole turn. A zero submitStart (a path that issues a turn without
// the pre-turn boundary) records no turn_latency.
func (c *turnController) dispatch(store *sessions.Store, submitStart time.Time) error {
	sel, source, ok := c.active.Current()
	if !ok {
		return nil
	}
	catalogEntry, ok := c.cache.SelectableCatalog().Entry(sel.Provider)
	if !ok {
		return nil
	}
	c.mu.Lock()
	if c.live != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	if resetter, ok := c.authorizer.(turnCacheResetter); ok {
		resetter.resetTurnCache()
	}
	if c.toolEvents != nil {
		c.toolEvents.Set(store)
	}

	client, ok := c.buildClient(sel.Provider, catalogEntry.AuthKind)
	if !ok {
		return nil
	}

	// Per-turn snapshot: the background goroutine must not read the run-scoped
	// active state, which pickers and slash commands mutate on the event loop and
	// which has no synchronization. NewActiveState copies the selection.
	snapshot := model.NewActiveState(&sel, source)

	// Assemble the system message for this turn now, on the event-loop goroutine,
	// from the current run-scoped mode plus the environment and AGENTS.md inputs.
	// Snapshotting it here keeps every provider round inside this turn stable
	// while a later /mode switch is picked up by the next dispatch. A nil assembler
	// (tests not exercising prompt assembly) sends no system message.
	systemPrompt := ""
	if c.assemblePrompt != nil {
		systemPrompt = c.assemblePrompt()
	}

	// Assemble the mode-filtered advertised tool set for this turn now, alongside the
	// system prompt, off the same run-scoped mode snapshot. Freezing it here keeps
	// every provider round in this turn — including tool-call continuation rounds — on the
	// same advertised set while a later /mode switch is picked up by the next dispatch. A
	// nil assembler (tests not exercising advertising) advertises no tools.
	var advertisedTools []provider.ToolDefinition
	if c.assembleTools != nil {
		advertisedTools = c.assembleTools()
	}

	// Capture the active mode for this turn and, when the dev-debug gate is on, arm
	// the TUI surface with this turn's provider/model/mode so its ghost stages stamp the
	// same context the turn-side trace does. Both run here on the event-loop goroutine,
	// the same place the model/mode are snapshotted, before the turn goroutine starts.
	modeName := ""
	if c.modeName != nil {
		modeName = c.modeName()
	}
	if c.devDebug && c.armTUIDebug != nil {
		c.armTUIDebug(sel.Provider, sel.ID, modeName)
	}

	// Publish this turn for any child a delegate call in it starts. It happens here, on the
	// event-loop goroutine before the turn goroutine exists, so the tool-dispatch goroutine
	// never reads the run-scoped active states and a /model or /mode change landing mid-turn
	// reaches the next turn's children, not this turn's.
	if c.delegateParent != nil {
		c.delegateParent.publish(sel, source, modeName, systemPrompt)
	}

	// One cancellation handle for the whole agentic turn. The turn runs under turnCtx
	// so Cancel() (and a /clear or /resume swap) aborts the in-flight provider round or
	// scheduler through context cancellation; the loop reports the current runner's
	// retained assistant characters for the ESC/CTRL-C retained count.
	turnCtx, cancel := context.WithCancel(c.ctx)
	live := &liveTurn{cancel: cancel, drained: make(chan struct{}), draining: make(chan struct{})}

	// In-flight indicator: the session's input/output token totals so far
	// (summed from the model_response events already on the store, the same per-event
	// sum /status uses) are this turn's ↑/↓ display bases. Each round's exact usage is
	// added on top per channel, so the figures the indicator settles on equal what
	// /status reports after the turn (its prior session totals plus this turn's usage).
	priorIn, priorOut := model.SumModelResponseTokens(store.Records())

	// Idle indicator: the provider's human-facing name for the waiting copy,
	// resolved once here from the selected provider's catalog entry (id fallback for a
	// configured provider that displays as its id). Captured on the event-loop goroutine
	// so the idle hook, which fires on the turn goroutine, closes over a stable value.
	idleName := catalogEntry.DisplayName
	if idleName == "" {
		idleName = sel.Provider
	}

	if c.ignoredProvidersStore != store {
		c.ignoredProviders = &turn.IgnoredProviders{}
		c.ignoredProvidersStore = store
	}

	flush := c.flushStore(store)
	deps := turn.Deps{
		Active:               snapshot,
		Store:                store,
		Client:               client,
		SubmitStart:          submitStart,
		SystemPrompt:         systemPrompt,
		Tools:                advertisedTools,
		SuggestFollowupDebug: c.devDebug,
		Mode:                 modeName,
		Sink: func(delta string) {
			c.surface.AppendStreamDelta(delta)
		},
		// Emit the about-to-run tool calls inline before dispatch. The hook is
		// fired by the agentic loop after assembly and before scheduling, so the lines
		// commit ahead of the calls actually running.
		OnToolActivity: c.surface.AppendToolActivity,
		// Route an intercepted suggest_followup call to the TUI ghost-text
		// surface. The agentic loop fires this instead of dispatching/persisting the call.
		SuggestFollowup: c.surface.SuggestFollowup,
		// Both ↑ (uploaded/input) and ↓ (downloaded/output) advance only from the
		// real per-round usage carried by Usage — ↑ = priorIn + input, ↓ = priorOut +
		// output. UsageAcc.Totals is monotonic (Add only increments), so each channel is
		// non-decreasing within the turn and settles on the figure /status reports. The
		// streamed Progress signal is deliberately not wired to the indicator: it counts
		// retained output *runes*, which routinely exceed the exact output *tokens* the
		// round then reports, so feeding it into ↓ would make the figure climb while
		// streaming and then drop when usage lands — the non-monotonic downward correction
		// the indicator is built to avoid (the same reason no upfront input estimate is used for ↑).
		// The cost is the accepted brief 0 on both channels at the very start of a turn,
		// before round 1's usage chunk arrives. Usage runs on the single turn goroutine
		// (from ToolLoop.Run after a round returns), so it needs no lock.
		Usage: func(inputTokens, outputTokens int64) {
			c.surface.SetIndicatorTokens(priorIn+inputTokens, priorOut+outputTokens)
		},
		// Idle indicator: when the live provider round goes quiet, swap the
		// generic Working copy for provider-specific waiting text carrying the stream's
		// idle duration; when a chunk arrives after idle, return to Working via the same
		// sink retry resume uses. The surface's ShowRetryBackoff still outranks idle, and its
		// no-resurrect-after-clear guard drops a late idle callback — this slice only
		// forwards the live hooks and never reads durable provider_stream_idle events back.
		OnProviderStreamIdle: func(info turn.StreamIdleInfo) {
			c.surface.SetProviderIdle(idleName, time.Duration(info.IdleMs)*time.Millisecond)
		},
		OnProviderStreamActivity: c.surface.ResumeRetry,
		Flush:                    flush,
		FlushUnsupported:         flush,
		SupportedEffort:          c.cache.SelectableCatalog().SupportedEffort,
		// Failure hooks: commit provider/turn request errors (HTTP errors / quota
		// hints, pre-stream transport/body failures) as in-place transcript history
		// tied to the turn, seal a dropped stream as interrupted, finalize a
		// completed reply, and route a failed provider_request_failed flush through the
		// protocol — which surfaces session-write failures on the transient
		// notice via turnNoticeRenderer (NoticeFromBackground), not as committed history.
		Notice: func(text string) {
			live.explained.Store(true)
			c.surface.CommitProviderError(text)
		},
		ToolNotice:        c.surface.CommitProviderError,
		RenderNotice:      tui.RenderProviderRequestFailedNotice,
		RenderRetryNotice: tui.RenderProviderRequestFailedAfterAttemptsNotice,
		Interrupt:         c.surface.MarkStreamInterrupted,
		Finalize:          c.surface.FinalizeStream,
		OnFailureWrite:    c.onProviderFailureWrite(store),
		// Auto-retry: thread the provider.retry config and the visible retry UX seams.
		Retry:           retryPolicy(c.cache.ProviderRetry()),
		RetryBackoff:    c.surface.ShowRetryBackoff,
		RetryResume:     c.surface.ResumeRetry,
		RetryRecovered:  c.surface.CommitRetryRecovered,
		RollbackPartial: c.surface.RollbackPartial,

		IgnoredProviders:      c.ignoredProviders,
		ProviderIgnoredNotice: c.surface.CommitProviderError,
	}
	if patchSurface, ok := c.surface.(editPatchSurface); ok {
		deps.OnEditPatch = patchSurface.AppendEditPatch
	}
	if queueSurface, ok := c.surface.(queuedMessageSurface); ok {
		deps.OnUserMessageAdded = func(text string, parts []sessions.ContentPart) {
			queueSurface.UserMessageAdded(live.draining, store, text, parts)
		}
	}
	loop := newToolLoop(deps, c.dispatcher, c.cache.AgentMaxConcurrency())
	live.loop = loop

	c.mu.Lock()
	if c.live != nil {
		c.mu.Unlock()
		cancel() // one active turn at a time; drop this overlap and release its context
		return nil
	}
	c.live = live
	c.mu.Unlock()

	// Committed to running this turn: reveal the in-flight indicator now, on the
	// event-loop goroutine (dispatch runs there), seeded with the session input/output
	// token bases. run() clears it when the loop returns, so every accepted turn that
	// shows the indicator also tears it down. Placed after the single-in-flight commit
	// so a dropped overlap never shows an orphan indicator.
	//
	// For a production turn (non-zero submitStart) seed the indicator's elapsed
	// clock from that submit-start — the same instant turn_latency measures from — so the
	// final visible elapsed matches the recorded turn_latency the completion footer shows.
	// A zero submitStart leaves the indicator on its default dispatch-start basis.
	if !submitStart.IsZero() {
		c.surface.SeedNextIndicatorStart(submitStart)
	}
	c.surface.ShowIndicator(priorIn, priorOut)

	goTurn(func() { c.run(turnCtx, loop, live, client, sel, store) })
	return nil
}

// run executes the agentic tool-call loop synchronously on the background goroutine
// and clears the active-turn handle when it returns. The loop drives all of the turn's
// transcript and failure UX through the injected hooks: it finalizes a completed
// reply, seals a dropped stream as interrupted, surfaces HTTP-error notices, and emits
// provider_request_failed events itself, so the controller only releases the turn slot
// (and its context). The loop's error is otherwise already acted on inside the loop (or
// is a context cancellation from Cancel()); run only inspects it to decide whether the
// turn completed successfully, which gates the first-turn completion hook.
func (c *turnController) run(ctx context.Context, loop *turn.ToolLoop, live *liveTurn, client provider.Client, sel model.Selection, store *sessions.Store) {
	err := loop.Run(ctx)
	outcome := turnOutcome(err, loop.Denied())
	var firstUser, firstAssistant string
	titleable := false
	if err == nil && !loop.Denied() && c.onTurnComplete != nil {
		firstUser, firstAssistant, titleable = firstTurnTitleInputs(store)
	}
	ended := func() { c.surface.TurnEnded(outcome) }
	if c.onUnsent != nil {
		if end := c.onUnsent(store, loop.Unsent(), outcome); end != nil {
			ended = end
		}
	}
	live.cancel() // release the turn context whether the loop completed or was cancelled

	c.mu.Lock()
	if c.live == live {
		c.live = nil
	}
	c.mu.Unlock()
	close(live.drained)

	// Tear down the in-flight indicator on the single join point the loop always
	// returns through, so it clears on natural completion, a mid-stream drop, a user
	// ESC/CTRL-C interrupt, and a background failure alike. ClearIndicator is
	// idempotent, so a finalize/interrupt that also cleared earlier is harmless.
	c.surface.ClearIndicator()

	if err != nil && !errors.Is(err, context.Canceled) && !live.explained.Load() {
		c.surface.CommitProviderError(turnRecoveryLine(err, store.SessionID()))
	}

	// Best-effort first-turn metadata after a durably-successful turn. A nil
	// loop error means the final assistant answer is already appended, recorded,
	// finalized, and flushed; a cancelled or failed turn skips the hook. A permission
	// denial also returns nil, but it halts the attempt with no final assistant
	// answer, so loop.Denied() gates it out — otherwise the interactive title hook would
	// fire a follow-up provider request off a turn the user refused. Fire it off the
	// run-scoped context (the per-turn ctx was just cancelled above) and on its own
	// goroutine via the goTurn seam, after the turn slot is released, so the title
	// provider round neither holds the turn slot nor delays this turn's teardown — and
	// so a test can await it through the same waitable goTurn the turn itself uses.
	if err == nil && !loop.Denied() {
		// Append the completion footer for the just-finished reply from the store's
		// durable model_turn + turn_latency records, after Deps.Finalize (queued during the
		// loop) already committed the reply. A turn missing a visible reply or the timing
		// records appends nothing, so the footer never attaches to a failed/interrupted turn.
		c.surface.AppendCompletionFooter(store.Records())
		if titleable {
			hook := c.onTurnComplete
			goTurn(func() { hook(c.ctx, client, sel, store, firstUser, firstAssistant) })
		}
	}

	ended()
}

func turnRecoveryLine(err error, sessionID string) string {
	var failure *turn.DispatchFailure
	if errors.As(err, &failure) {
		return failure.Error()
	}
	return fmt.Sprintf("the turn did not finish cleanly; session %s — run `codemeld sessions doctor %s` to see what was recorded", sessionID, sessionID)
}

func turnOutcome(err error, denied bool) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "interrupted"
	case err != nil, denied:
		return "turn_failed"
	default:
		return "completed"
	}
}

// retryPolicy maps the resolved provider.retry settings onto turn's policy type,
// converting the millisecond knobs to durations. The per-turn retry
// wall-clock budget is not a settings knob — turn.New applies its fixed default
// when Budget is left zero here.
func retryPolicy(s config.RetrySettings) turn.RetryPolicy {
	return turn.RetryPolicy{
		Enabled:     s.Enabled,
		MaxAttempts: s.MaxAttempts,
		BaseDelay:   time.Duration(s.BaseDelayMs) * time.Millisecond,
		MaxDelay:    time.Duration(s.MaxDelayMs) * time.Millisecond,
	}
}

// onProviderFailureWrite builds the events.WriteFailureHandler the turn passes to
// EmitProviderRequestFailed: when that event's own flush hits a real atomic-write
// failure, it runs the same per-turn protocol the normal flush hook uses
// (records carry forward, session_write_failed appended, one-line notice rendered).
func (c *turnController) onProviderFailureWrite(store *sessions.Store) events.WriteFailureHandler {
	return func(cat fserrors.Category, reason sessions.WriteReason, err error) {
		_ = sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, turnNoticeRenderer{surface: c.surface})
	}
}

// flushStore builds the runtime's session flush hook for a turn bound to
// store. On an atomic-write failure it routes the per-turn protocol
// through sessionfailures.HandleWriteFailure (records carry forward, the one-line
// notice renders) and still returns the error so the runtime refuses to cross the
// durability boundary. A non-atomic flush failure (a cancelled context or a marshal
// error, sessions.ReasonNone) cannot be encoded as session_write_failed and is
// returned unrouted.
func (c *turnController) flushStore(store *sessions.Store) turn.FlushHook {
	return func() error {
		cat, reason, err := store.Flush(c.ctx)
		if err == nil {
			return nil
		}
		if reason != sessions.ReasonNone {
			if herr := sessionfailures.HandleWriteFailure(reason, cat, store.Path(), err, store, turnNoticeRenderer{surface: c.surface}); herr != nil {
				return errors.Join(err, herr)
			}
		}
		return err
	}
}
