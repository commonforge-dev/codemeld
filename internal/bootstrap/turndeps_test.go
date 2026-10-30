// Controller-level tests for the production provider-turn wiring: provider
// resolution, single active runner + cancellation, natural-completion
// finalization, the unsupported-effort flush path, and no-network client
// injection. Shared stub-provider/SSE fixtures used by the wired-app submit
// test live here.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"codemeld.dev/codemeld/internal/authstate"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/openaiauth"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
)

// --- seam swappers ----------------------------------------------------------

// swapGoTurn overrides the goTurn launch seam and returns a restore function.
func swapGoTurn(fn func(func())) func() {
	prev := goTurn
	goTurn = fn
	return func() { goTurn = prev }
}

// swapTurnProviderClient overrides the provider-client builder seam (so tests run
// without outbound network) and returns a restore function.
func swapTurnProviderClient(fn func(provider.ClientConfig) provider.Client) func() {
	prev := newTurnProviderClient
	newTurnProviderClient = fn
	return func() { newTurnProviderClient = prev }
}

// swapToolLoop overrides the newToolLoop seam so a dispatch test can capture the
// as-built turn.Deps (to fire the idle/activity hooks the controller wired)
// while still delegating to the real loop builder, and returns a restore function.
func swapToolLoop(fn func(turn.Deps, turn.ToolDispatcher, int) *turn.ToolLoop) func() {
	prev := newToolLoop
	newToolLoop = fn
	return func() { newToolLoop = prev }
}

// swapChatGPTProviderClient overrides the OpenAI ChatGPT adapter builder seam so a
// ChatGPT dispatch test can capture the resolved credentials and return a no-network
// stub, and returns a restore function.
func swapChatGPTProviderClient(fn func(provider.ChatGPTClientConfig) provider.Client) func() {
	prev := newChatGPTProviderClient
	newChatGPTProviderClient = fn
	return func() { newChatGPTProviderClient = prev }
}

// fakeChatGPTAuth is a no-network chatGPTAuth for the ChatGPT dispatch tests: it
// records call counts and delegates each entrypoint to its injected closure, so a
// test drives the missing-session, proactive-refresh, and reactive-retry paths
// without real stored credential state.
type fakeChatGPTAuth struct {
	ensure       func(ctx context.Context, settingsPath string) (authstate.Session, error)
	refresh      func(ctx context.Context, settingsPath string) (authstate.Session, error)
	ensureCalls  int32
	refreshCalls int32
}

func (f *fakeChatGPTAuth) EnsureFreshSession(ctx context.Context, settingsPath string) (authstate.Session, error) {
	atomic.AddInt32(&f.ensureCalls, 1)
	return f.ensure(ctx, settingsPath)
}

func (f *fakeChatGPTAuth) RefreshNow(ctx context.Context, settingsPath string) (authstate.Session, error) {
	atomic.AddInt32(&f.refreshCalls, 1)
	if f.refresh == nil {
		return authstate.Session{}, openaiauth.ErrNoSession
	}
	return f.refresh(ctx, settingsPath)
}

func (f *fakeChatGPTAuth) ensureCount() int  { return int(atomic.LoadInt32(&f.ensureCalls)) }
func (f *fakeChatGPTAuth) refreshCount() int { return int(atomic.LoadInt32(&f.refreshCalls)) }

// writeChatGPTSession writes a minimal global settings.yaml under home carrying a
// non-expired auth.openai-chatgpt session, so the production openaiauth flow's
// proactive load returns it without any network refresh (the far-future expiry keeps
// it outside the refresh-skew window).
func writeChatGPTSession(t *testing.T, home, accessToken, accountID string) {
	t.Helper()
	dir := filepath.Join(home, ".codemeld", "global")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir global settings dir: %v", err)
	}
	doc := fmt.Sprintf("auth:\n  openai-chatgpt:\n    access_token: %s\n    refresh_token: stored-refresh\n    expires_at: \"2099-01-01T00:00:00Z\"\n    account_id: %s\n", accessToken, accountID)
	if err := os.WriteFile(filepath.Join(dir, "settings.yaml"), []byte(doc), 0o600); err != nil {
		t.Fatalf("write global settings: %v", err)
	}
}

// waitableGoTurn returns a goTurn override that tracks launched turns on wg so a
// test can join the background turn goroutine before reading shared state.
func waitableGoTurn(wg *sync.WaitGroup) func(func()) {
	return func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}
}

// --- streamed-chunk fixtures ------------------------------------------------

func contentChunk(text string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":%q},"finish_reason":""}]}`, text))
}

func finishChunk(reason string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":%q}]}`, reason))
}

// usageChunk is the include_usage final chunk: empty choices, populated usage.
func usageChunk(in, out int64) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`, in, out, in+out))
}

// sliceDecoder replays a fixed list of chunk payloads as SSE events (a complete
// turn). It mirrors the turn-package test fixture.
type sliceDecoder struct {
	events [][]byte
	i      int
	cur    ssestream.Event
}

func (d *sliceDecoder) Next() bool {
	if d.i >= len(d.events) {
		return false
	}
	d.cur = ssestream.Event{Data: d.events[d.i]}
	d.i++
	return true
}
func (d *sliceDecoder) Event() ssestream.Event { return d.cur }
func (d *sliceDecoder) Close() error           { return nil }
func (d *sliceDecoder) Err() error             { return nil }

func newStream(chunks ...[]byte) *ssestream.Stream[openai.ChatCompletionChunk] {
	return ssestream.NewStream[openai.ChatCompletionChunk](&sliceDecoder{events: chunks}, nil)
}

// blockingDecoder yields one chunk, signals ready once the runtime has consumed it
// (the second Next call, which proves the delta was already streamed and counted),
// then blocks until the request context is cancelled — surfacing the cancellation
// as the stream error. It lets a test observe a cancellable in-flight turn
// deterministically.
type blockingDecoder struct {
	ctx    context.Context
	first  []byte
	ready  chan struct{}
	served bool
	cur    ssestream.Event
	err    error
}

func (d *blockingDecoder) Next() bool {
	if !d.served {
		d.served = true
		d.cur = ssestream.Event{Data: d.first}
		return true
	}
	close(d.ready)
	<-d.ctx.Done()
	d.err = d.ctx.Err()
	return false
}
func (d *blockingDecoder) Event() ssestream.Event { return d.cur }
func (d *blockingDecoder) Close() error           { return nil }
func (d *blockingDecoder) Err() error             { return d.err }

func blockingStream(ctx context.Context, first []byte, ready chan struct{}) *ssestream.Stream[openai.ChatCompletionChunk] {
	return ssestream.NewStream[openai.ChatCompletionChunk](&blockingDecoder{ctx: ctx, first: first, ready: ready}, nil)
}

// gatedDecoder is blockingDecoder that stays parked until the test closes release,
// independently of context cancellation: it yields one chunk, signals ready, then
// blocks on release. So a test can interrupt the turn (cancelling its context) and
// still hold the background turn goroutine inside the stream past the interrupt —
// isolating the UI-path indicator clear from the turnController.run backstop clear,
// which cannot run until release lets the loop return. It then surfaces the
// cancellation as the stream error, like blockingDecoder.
type gatedDecoder struct {
	ctx     context.Context
	first   []byte
	ready   chan struct{}
	release chan struct{}
	served  bool
	cur     ssestream.Event
	err     error
}

func (d *gatedDecoder) Next() bool {
	if !d.served {
		d.served = true
		d.cur = ssestream.Event{Data: d.first}
		return true
	}
	close(d.ready)
	<-d.release
	d.err = d.ctx.Err()
	return false
}
func (d *gatedDecoder) Event() ssestream.Event { return d.cur }
func (d *gatedDecoder) Close() error           { return nil }
func (d *gatedDecoder) Err() error             { return d.err }

func gatedStream(ctx context.Context, first []byte, ready, release chan struct{}) *ssestream.Stream[openai.ChatCompletionChunk] {
	return ssestream.NewStream[openai.ChatCompletionChunk](&gatedDecoder{ctx: ctx, first: first, ready: ready, release: release}, nil)
}

// dropDecoder yields one content chunk, then ends iteration with a non-nil,
// non-context Err so the stream surfaces a mid-stream transport drop after
// partial assistant content (mirrors the turn-package test fixture).
type dropDecoder struct {
	first  []byte
	err    error
	served bool
	cur    ssestream.Event
}

func (d *dropDecoder) Next() bool {
	if !d.served {
		d.served = true
		d.cur = ssestream.Event{Data: d.first}
		return true
	}
	return false
}
func (d *dropDecoder) Event() ssestream.Event { return d.cur }
func (d *dropDecoder) Close() error           { return nil }
func (d *dropDecoder) Err() error             { return d.err }

func dropStream(first []byte, err error) *ssestream.Stream[openai.ChatCompletionChunk] {
	return ssestream.NewStream[openai.ChatCompletionChunk](&dropDecoder{first: first, err: err}, nil)
}

// --- stub provider client ---------------------------------------------------

// stubTurnClient is a no-network provider.Client for the wired-turn tests. It
// records its call count and delegates each call to fn. When title is set, it answers
// title requests instead, and those are counted in titleCalls rather than calls.
type stubTurnClient struct {
	calls      int32
	titleCalls int32
	fn         func(ctx context.Context, req provider.Request) (provider.Response, error)
	title      func(ctx context.Context, req provider.Request) (provider.Response, error)
}

func (c *stubTurnClient) ChatCompletion(ctx context.Context, req provider.Request) (provider.Response, error) {
	if c.title != nil && isTitleRequest(req) {
		atomic.AddInt32(&c.titleCalls, 1)
		return c.title(ctx, req)
	}
	atomic.AddInt32(&c.calls, 1)
	return c.fn(ctx, req)
}

func (c *stubTurnClient) callCount() int { return int(atomic.LoadInt32(&c.calls)) }

func (c *stubTurnClient) titleCallCount() int { return int(atomic.LoadInt32(&c.titleCalls)) }

// toolThenContentClient builds a no-network stubTurnClient with the two-round shape the
// modes and turn-deps integration tests drive: its first provider round emits a single
// tool call (toolName/args under id "call_1"), and every later round answers with content
// text plus a stop finish. When rounds is non-nil it appends the advertised tool names
// seen on each round, so a caller can assert the continuation re-advertises the same set.
func toolThenContentClient(rounds *[][]string, toolName, args, content string) *stubTurnClient {
	var round int32
	return &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if rounds != nil {
			*rounds = append(*rounds, toolNames(req.Tools))
		}
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", toolName, args)))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk(content), finishChunk("stop"))}, nil
	}}
}

// --- recording stream surface -----------------------------------------------

// recordingSurface is a fake turnSurface that records the sink deltas, finalize
// calls, and write-failure notices the controller drives, so controller tests can
// assert them without a running tview screen. *tui.App is the production surface.
type recordingSurface struct {
	mu             sync.Mutex
	deltas         []string
	finalized      int
	interrupted    int
	notices        []string
	committed      []string   // in-place provider-error history lines
	activity       [][]string // tool-call activity rounds appended before dispatch
	editPatches    []string
	suggestions    [][2]string // intercepted suggest_followup {label, prompt} pairs
	rolledBack     int         // auto-retry discard-and-restart rollbacks before a retry re-issue
	retryBackoffs  [][2]int
	retryResumes   int
	retryRecovered []int
	providerIdles  []providerIdle // each SetProviderIdle call's {displayName, idle}

	shown        int
	cleared      int
	clearEntered chan struct{}
	clearRelease chan struct{}
	shownInput   int64      // ↑ base passed to ShowIndicator
	shownOutput  int64      // ↓ base passed to ShowIndicator
	tokenUpdates [][2]int64 // each SetIndicatorTokens call's {↑ input, ↓ output}

	seededStarts []time.Time         // each SeedNextIndicatorStart call's submit-start
	footerCalls  [][]sessions.Record // each AppendCompletionFooter call's records

	turnOutcomes []string
	onTurnEnded  func(outcome string)
}

func (s *recordingSurface) AppendStreamDelta(delta string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deltas = append(s.deltas, delta)
}

func (s *recordingSurface) FinalizeStream() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalized++
}

func (s *recordingSurface) MarkStreamInterrupted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interrupted++
}

func (s *recordingSurface) NoticeFromBackground(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notices = append(s.notices, text)
}

func (s *recordingSurface) CommitProviderError(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.committed = append(s.committed, text)
}

func (s *recordingSurface) AppendToolActivity(lines []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activity = append(s.activity, append([]string(nil), lines...))
}

func (s *recordingSurface) AppendEditPatch(patch string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPatches = append(s.editPatches, patch)
}

func (s *recordingSurface) patches() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.editPatches)
}

func (s *recordingSurface) activityRounds() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.activity))
	copy(out, s.activity)
	return out
}

func (s *recordingSurface) SuggestFollowup(label, prompt string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suggestions = append(s.suggestions, [2]string{label, prompt})
}

func (s *recordingSurface) RollbackPartial() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rolledBack++
}

func (s *recordingSurface) ShowRetryBackoff(nextAttempt, totalAttempts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryBackoffs = append(s.retryBackoffs, [2]int{nextAttempt, totalAttempts})
}

func (s *recordingSurface) ResumeRetry() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryResumes++
}

// providerIdle records one SetProviderIdle call for the idle-wiring assertions.
type providerIdle struct {
	name string
	idle time.Duration
}

func (s *recordingSurface) SetProviderIdle(displayName string, idle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providerIdles = append(s.providerIdles, providerIdle{name: displayName, idle: idle})
}

func (s *recordingSurface) idleCalls() []providerIdle {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.providerIdles)
}

func (s *recordingSurface) CommitRetryRecovered(retries int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryRecovered = append(s.retryRecovered, retries)
}

func (s *recordingSurface) rollbackCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rolledBack
}

func (s *recordingSurface) retryUX() ([][2]int, int, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.retryBackoffs), s.retryResumes, slices.Clone(s.retryRecovered)
}

func (s *recordingSurface) suggestionPairs() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][2]string, len(s.suggestions))
	copy(out, s.suggestions)
	return out
}

func (s *recordingSurface) ShowIndicator(input, output int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shown++
	s.shownInput = input
	s.shownOutput = output
}

func (s *recordingSurface) SetIndicatorTokens(input, output int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenUpdates = append(s.tokenUpdates, [2]int64{input, output})
}

func (s *recordingSurface) ClearIndicator() {
	s.mu.Lock()
	s.cleared++
	entered := s.clearEntered
	release := s.clearRelease
	s.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
}

func (s *recordingSurface) TurnEnded(outcome string) {
	s.mu.Lock()
	s.turnOutcomes = append(s.turnOutcomes, outcome)
	hook := s.onTurnEnded
	s.mu.Unlock()
	if hook != nil {
		hook(outcome)
	}
}

func (s *recordingSurface) outcomeList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.turnOutcomes)
}

func (s *recordingSurface) SeedNextIndicatorStart(start time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seededStarts = append(s.seededStarts, start)
}

func (s *recordingSurface) AppendCompletionFooter(records []sessions.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.footerCalls = append(s.footerCalls, records)
}

func (s *recordingSurface) seededStartList() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seededStarts)
}

func (s *recordingSurface) footerCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.footerCalls)
}

// lastFooterRecords returns the records passed to the most recent AppendCompletionFooter
// call, so a test can confirm the success path handed the controller the durable
// turn_latency the footer is built from.
func (s *recordingSurface) lastFooterRecords() ([]sessions.Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.footerCalls) == 0 {
		return nil, false
	}
	return s.footerCalls[len(s.footerCalls)-1], true
}

func (s *recordingSurface) showCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shown
}

func (s *recordingSurface) clearCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleared
}

func (s *recordingSurface) lastTokenUpdate() (input, output int64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tokenUpdates) == 0 {
		return 0, 0, false
	}
	last := s.tokenUpdates[len(s.tokenUpdates)-1]
	return last[0], last[1], true
}

// allTokenUpdates returns a copy of every SetIndicatorTokens call's {↑ input, ↓
// output} pair, in order, so a test can assert each channel's series is monotonic.
func (s *recordingSurface) allTokenUpdates() [][2]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][2]int64(nil), s.tokenUpdates...)
}

func (s *recordingSurface) deltaText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := ""
	for _, d := range s.deltas {
		out += d
	}
	return out
}

func (s *recordingSurface) finalizeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finalized
}

func (s *recordingSurface) interruptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interrupted
}

func (s *recordingSurface) noticeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.notices)
}

func (s *recordingSurface) noticeList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.notices)
}

func (s *recordingSurface) committedList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.committed)
}

// turnSelection builds a run-scoped active state for one selection (a stand-in for
// the run's model.ActiveState the controller snapshots per turn).
func turnSelection(prov, id, effort string) *model.ActiveState {
	return model.NewActiveState(&model.Selection{Provider: prov, ID: id, Effort: effort}, model.SourceProject)
}

// retryProviderCache builds a config cache whose provider.retry block enables
// auto-retry with zero-millisecond delays, so a wired-turn test exercises
// the retry path without any wall-clock backoff.
func retryProviderCache(t *testing.T, projectRoot string) *config.Cache {
	t.Helper()
	composed := map[string]any{
		"provider": map[string]any{
			"retry": map[string]any{
				"enabled": true, "max_attempts": int64(4), "base_delay_ms": int64(0), "max_delay_ms": int64(0),
			},
			"openai": map[string]any{
				"base_url": "https://api.openai.com/v1",
				"api_key":  "sk-test",
				"models":   []string{"gpt-5.5", "gpt-5.5-pro"},
			},
		},
	}
	cache, err := config.NewCache(composed, projectRoot, nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache
}

func openRouterRequestProviderObject(t *testing.T, cache *config.Cache) map[string]any {
	t.Helper()
	var raw []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"c1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(srv.Close)
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		cfg.BaseURL = srv.URL
		cfg.HTTPClient = srv.Client()
		return provider.NewClient(cfg)
	})()
	client, ok := buildTurnClient("openrouter", provider.AuthKindConfigured, cache, nil, "")
	if !ok {
		t.Fatalf("buildTurnClient(openrouter) ok = false, want a client")
	}
	if _, err := client.ChatCompletion(context.Background(), provider.Request{
		Model:    "m",
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("ChatCompletion() error = %v, want nil", err)
	}
	var body struct {
		Provider map[string]any `json:"provider"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode request body: %v\nbody = %s", err, raw)
	}
	return body.Provider
}

// --- tests ------------------------------------------------------------------

func TestBuildTurnClient_GlobalOpenRouterRoutingReachesRequests(t *testing.T) {
	global := []byte(`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      sort: latency
      data_collection: deny
      require_parameters: true
`)
	raw, _, err := config.ValidateGlobalSettingsBytes(global, "settings.yaml")
	if err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes: %v", err)
	}
	composed, err := config.Compose(raw, nil)
	if err != nil {
		t.Fatalf("config.Compose: %v", err)
	}
	cache, err := config.NewCache(composed, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	got := openRouterRequestProviderObject(t, cache)
	want := map[string]any{"sort": "latency", "data_collection": "deny", "require_parameters": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request provider object = %#v, want %#v", got, want)
	}
}

func TestBuildTurnClient_OpenRouterMaxPriceReachesRequests(t *testing.T) {
	global := []byte(`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      sort: throughput
      max_price:
        m: { prompt: 0, completion: 2.5 }
        m:nitro: { prompt: 9 }
`)
	raw, _, err := config.ValidateGlobalSettingsBytes(global, "settings.yaml")
	if err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes: %v", err)
	}
	composed, err := config.Compose(raw, nil)
	if err != nil {
		t.Fatalf("config.Compose: %v", err)
	}
	cache, err := config.NewCache(composed, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	got := openRouterRequestProviderObject(t, cache)
	want := map[string]any{"sort": "throughput", "max_price": map[string]any{"prompt": float64(0), "completion": 2.5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request provider object = %#v, want %#v", got, want)
	}
}

func TestBuildTurnClient_OpenRouterBestValueSendsPickedEndpoint(t *testing.T) {
	const model = "meta-llama/llama-3.3-70b-instruct"
	var endpointHits atomic.Int32
	var endpointAuth string
	var chatBodies [][]byte
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/models/" + model + "/endpoints":
			endpointHits.Add(1)
			mu.Lock()
			endpointAuth = r.Header.Get("Authorization")
			mu.Unlock()
			_, _ = io.WriteString(w, `{"data":{"endpoints":[
				{"provider_name":"a","tag":"a/fp8","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":90}},
				{"provider_name":"b","tag":"b","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":30}},
				{"provider_name":"c","tag":"c","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":null},
				{"provider_name":"d","tag":"d/fp4/us","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":55.5}}
			]}}`)
		case "/api/v1/chat/completions":
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			chatBodies = append(chatBodies, raw)
			mu.Unlock()
			_, _ = io.WriteString(w, `{"id":"c1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	global := []byte(fmt.Sprintf(`provider:
  openrouter:
    base_url: %s/api/v1
    api_key: or-key
    routing:
      sort: best_value
`, srv.URL))
	raw, _, err := config.ValidateGlobalSettingsBytes(global, "settings.yaml")
	if err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes: %v", err)
	}
	composed, err := config.Compose(raw, nil)
	if err != nil {
		t.Fatalf("config.Compose: %v", err)
	}
	cache, err := config.NewCache(composed, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	prevStore := openRouterEndpoints
	openRouterEndpoints = &provider.OpenRouterEndpointStore{HTTPClient: srv.Client()}
	t.Cleanup(func() { openRouterEndpoints = prevStore })
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		cfg.HTTPClient = srv.Client()
		return provider.NewClient(cfg)
	})()

	client, ok := buildTurnClient("openrouter", provider.AuthKindConfigured, cache, nil, "")
	if !ok {
		t.Fatalf("buildTurnClient(openrouter) ok = false, want a client")
	}
	if got := endpointHits.Load(); got != 0 {
		t.Fatalf("endpoint requests after building the client = %d, want 0", got)
	}
	for _, ignored := range [][]string{nil, {"a"}} {
		if _, err := client.ChatCompletion(context.Background(), provider.Request{
			Model:            model,
			Messages:         []provider.Message{{Role: "user", Content: "hi"}},
			IgnoredProviders: ignored,
		}); err != nil {
			t.Fatalf("ChatCompletion() error = %v, want nil", err)
		}
	}
	if got := endpointHits.Load(); got != 1 {
		t.Fatalf("endpoint requests after two turns = %d, want 1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if endpointAuth != "Bearer or-key" {
		t.Fatalf("endpoints Authorization = %q, want the configured key", endpointAuth)
	}
	if len(chatBodies) != 2 {
		t.Fatalf("chat requests = %d, want 2", len(chatBodies))
	}
	wants := []map[string]any{
		{"order": []any{"a/fp8"}},
		{"order": []any{"d/fp4/us"}, "ignore": []any{"a"}},
	}
	for i, b := range chatBodies {
		var body struct {
			Provider map[string]any `json:"provider"`
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("decode request body %d: %v\nbody = %s", i, err, b)
		}
		if !reflect.DeepEqual(body.Provider, wants[i]) {
			t.Fatalf("turn %d provider object = %#v, want %#v", i+1, body.Provider, wants[i])
		}
	}
}

func TestBuildTurnClient_OpenRouterQuantizationReachesRequests(t *testing.T) {
	const model = "z-ai/glm-5.3"
	const exhausted = `{"error":{"message":"No endpoints found","code":404,"metadata":{"failed_routing_step":"Filter by Quantization"}}}`
	var endpointHits atomic.Int32
	var chatBodies [][]byte
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/models/" + model + "/endpoints":
			endpointHits.Add(1)
			_, _ = io.WriteString(w, `{"data":{"endpoints":[
				{"provider_name":"a","tag":"a/fp8","quantization":"fp8","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":90}},
				{"provider_name":"b","tag":"b/bf16","quantization":"bf16","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":200}},
				{"provider_name":"d","tag":"d/fp4/us","quantization":"nvfp4","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":55.5}},
				{"provider_name":"e","tag":"e/fp8","quantization":"fp8","pricing":{"prompt":"0.0000001","completion":"0.0000002"},"throughput_last_30m":{"p50":10}}
			]}}`)
		case "/api/v1/chat/completions":
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			chatBodies = append(chatBodies, raw)
			first := len(chatBodies) == 1
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, exhausted)
				return
			}
			_, _ = io.WriteString(w, `{"id":"c1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	global := []byte(fmt.Sprintf(`provider:
  openrouter:
    base_url: %s/api/v1
    api_key: or-key
    routing:
      sort: best_value
      quantizations:
        %s: { levels: [fp4, fp8], mode: required }
`, srv.URL, model))
	raw, _, err := config.ValidateGlobalSettingsBytes(global, "settings.yaml")
	if err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes: %v", err)
	}
	composed, err := config.Compose(raw, nil)
	if err != nil {
		t.Fatalf("config.Compose: %v", err)
	}
	cache, err := config.NewCache(composed, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	prevStore := openRouterEndpoints
	openRouterEndpoints = &provider.OpenRouterEndpointStore{HTTPClient: srv.Client()}
	t.Cleanup(func() { openRouterEndpoints = prevStore })
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		cfg.HTTPClient = srv.Client()
		return provider.NewClient(cfg)
	})()

	client, ok := buildTurnClient("openrouter", provider.AuthKindConfigured, cache, nil, "")
	if !ok {
		t.Fatalf("buildTurnClient(openrouter) ok = false, want a client")
	}
	if _, err := client.ChatCompletion(context.Background(), provider.Request{
		Model:    model,
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("ChatCompletion() error = %v, want nil", err)
	}
	if got := endpointHits.Load(); got != 1 {
		t.Fatalf("endpoint requests = %d, want 1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	wants := []map[string]any{
		{"order": []any{"d/fp4/us"}, "quantizations": []any{"fp4"}},
		{"order": []any{"a/fp8"}, "quantizations": []any{"fp8"}},
	}
	if len(chatBodies) != len(wants) {
		t.Fatalf("chat requests = %d, want %d", len(chatBodies), len(wants))
	}
	for i, b := range chatBodies {
		var body struct {
			Provider map[string]any `json:"provider"`
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("decode request body %d: %v\nbody = %s", i, err, b)
		}
		if !reflect.DeepEqual(body.Provider, wants[i]) {
			t.Fatalf("attempt %d provider object = %#v, want %#v", i+1, body.Provider, wants[i])
		}
	}
}

// The production turn wiring threads the provider.retry policy and the partial
// rollback seam onto the turn's Deps: a partial stream drop on the
// first round is auto-retried, the second round succeeds, the wired
// surface.RollbackPartial fires once before re-issue, and the durable
// provider_request_retry lands on the store. Pins the turndeps wiring of
// Retry/RollbackPartial, not just the turn-package mechanics.
func TestTurnController_DispatchWiresRetryAndRollback(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var round int32
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: dropStream(contentChunk("Par"), io.ErrUnexpectedEOF)}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("Recovered"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, retryProviderCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (the wired retry policy re-issued the dropped round)", client.callCount())
	}
	if got := surface.rollbackCount(); got != 1 {
		t.Fatalf("RollbackPartial calls = %d, want 1 (turndeps must wire surface.RollbackPartial)", got)
	}
	backoffs, resumes, recovered := surface.retryUX()
	if len(backoffs) != 1 || backoffs[0] != [2]int{2, 4} {
		t.Fatalf("ShowRetryBackoff calls = %+v, want next attempt 2 of 4", backoffs)
	}
	if resumes != 1 {
		t.Fatalf("ResumeRetry calls = %d, want 1", resumes)
	}
	if len(recovered) != 1 || recovered[0] != 1 {
		t.Fatalf("CommitRetryRecovered calls = %+v, want one breadcrumb with 1 retry", recovered)
	}
	if got := surface.deltaText(); !strings.Contains(got, "Recovered") {
		t.Fatalf("streamed text = %q, want it to contain the regenerated answer", got)
	}
	if !slices.Contains(eventKinds(store.Records()), events.KindProviderRequestRetry) {
		t.Fatalf("store missing provider_request_retry; the wired retry policy did not record it; kinds = %v", eventKinds(store.Records()))
	}
}

const togetherIgnoredNotice = "Provider together failing to respond. Removing for rest of this session"

func unavailableUpstreamDrop() *ssestream.Stream[openai.ChatCompletionChunk] {
	body := `{"error":{"code":502,"message":"Upstream error from Together: service unavailable","metadata":{"error_type":"provider_unavailable"}}}`
	return dropStream(contentChunk("Par"), &ssestream.StreamError{Event: ssestream.Event{Data: []byte(body)}})
}

func unavailableUpstreamClient(ignoreLists *[][]string) *stubTurnClient {
	return &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		*ignoreLists = append(*ignoreLists, req.IgnoredProviders)
		if len(*ignoreLists) == 1 {
			return provider.Response{Stream: unavailableUpstreamDrop()}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("Recovered"), finishChunk("stop"))}, nil
	}}
}

func TestTurnController_UnavailableUpstreamIsIgnoredUntilTheSessionChanges(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var ignoreLists [][]string
	client := unavailableUpstreamClient(&ignoreLists)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	globalSettings := SettingsPath(t.TempDir())
	seedOpenRouterDiscoveredModels(t, globalSettings, toolGateModels())
	cache, err := config.NewCache(map[string]any{"provider": map[string]any{
		"retry":      map[string]any{"enabled": true, "max_attempts": int64(4), "base_delay_ms": int64(0), "max_delay_ms": int64(0)},
		"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "sk-or-test"},
	}}, t.TempDir(), []string{globalSettings})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, cache, toolGateActive(toolfulModelID), nil, nil)
	store := mkStore(t)
	for _, s := range []*sessions.Store{store, store, mkStore(t)} {
		if err := ctl.dispatch(s, time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		turns.Wait()
	}

	want := [][]string{nil, {"together"}, {"together"}, nil}
	if !slices.EqualFunc(ignoreLists, want, slices.Equal[[]string]) {
		t.Fatalf("request ignore lists = %v, want %v (immediate retry and the next turn ignore together; a new session starts empty)", ignoreLists, want)
	}
	notices := 0
	for _, line := range surface.committedList() {
		if line == togetherIgnoredNotice {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("committed lines = %q, want %q exactly once", surface.committedList(), togetherIgnoredNotice)
	}
}

// The production turn wiring forwards the turn's live idle hook to the surface's SetProviderIdle
// with the selected provider's catalog display name (not its id) and the stream's idle
// duration, and never reads durable provider_stream_idle events back. Captures the
// as-built turn.Deps at the dispatch seam and fires the hook the controller wired.
func TestTurnController_DispatchWiresProviderIdleIndicator(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hi"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var deps turn.Deps
	defer swapToolLoop(func(d turn.Deps, disp turn.ToolDispatcher, n int) *turn.ToolLoop {
		deps = d
		return turn.NewToolLoop(d, disp, n)
	})()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	deps.OnProviderStreamIdle(turn.StreamIdleInfo{Provider: "openai", ModelID: "gpt-5.5", IdleMs: 184_000})

	idles := surface.idleCalls()
	if len(idles) != 1 {
		t.Fatalf("SetProviderIdle calls = %d, want 1 (dispatch must forward the g1125 idle hook)", len(idles))
	}
	// "openai" is the OpenAI Platform provider id; its catalog display name is "OpenAI
	// Platform", so the display name reaching SetProviderIdle must differ from the raw id.
	if idles[0].name != "OpenAI Platform" {
		t.Fatalf("SetProviderIdle name = %q, want %q (dispatch must supply the catalog display name, not the provider id)", idles[0].name, "OpenAI Platform")
	}
	if idles[0].idle != 184*time.Second {
		t.Fatalf("SetProviderIdle idle = %v, want %v (IdleMs must convert to a duration)", idles[0].idle, 184*time.Second)
	}
	if kinds := eventKinds(store.Records()); slices.Contains(kinds, events.KindProviderStreamIdle) {
		t.Fatalf("idle indicator wiring must not depend on durable provider_stream_idle events; kinds = %v", kinds)
	}
}

// The activity/resume hook the production wiring binds returns the indicator to the
// normal Working state after an idle crossing: the turn's OnProviderStreamActivity routes
// to the same ResumeRetry sink retry resume uses, which clears the surface's idle state.
func TestTurnController_DispatchIdleActivityClears(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hi"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var deps turn.Deps
	defer swapToolLoop(func(d turn.Deps, disp turn.ToolDispatcher, n int) *turn.ToolLoop {
		deps = d
		return turn.NewToolLoop(d, disp, n)
	})()

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	deps.OnProviderStreamIdle(turn.StreamIdleInfo{Provider: "openai", ModelID: "gpt-5.5", IdleMs: 30_000})
	deps.OnProviderStreamActivity()

	if got := len(surface.idleCalls()); got != 1 {
		t.Fatalf("SetProviderIdle calls = %d, want 1", got)
	}
	if _, resumes, _ := surface.retryUX(); resumes != 1 {
		t.Fatalf("activity hook ResumeRetry calls = %d, want 1 (activity must return the indicator to Working)", resumes)
	}
}

const wiredEditPatch = "--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n-old\n+new\n"

func TestTurnController_DispatchWiresEditPatchToSurface(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hi"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	var deps turn.Deps
	defer swapToolLoop(func(d turn.Deps, disp turn.ToolDispatcher, n int) *turn.ToolLoop {
		deps = d
		return turn.NewToolLoop(d, disp, n)
	})()

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if deps.OnEditPatch == nil {
		t.Fatal("turn.Deps.OnEditPatch is nil; dispatch must bind the interactive edit-patch sink")
	}
	deps.OnEditPatch(wiredEditPatch)

	got := surface.patches()
	if len(got) != 1 || got[0] != wiredEditPatch {
		t.Fatalf("surface patches = %v, want the delivered patch forwarded verbatim", got)
	}
}

type fakeTurnDispatcher struct{ results map[string]turn.ToolResult }

func (d *fakeTurnDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d *fakeTurnDispatcher) Dispatch(_ context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	return d.results[call.ID], nil
}

func TestRunHeadlessTurn_KeepsNonEditActivityAndEmitsNoEditPatch(t *testing.T) {
	var round int32
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(
				toolFrag(0, "call_1", "bash", `{"command":"go build ./..."}`),
				toolFrag(1, "call_2", "edit", `{"path":"a.txt"}`),
			))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("all done"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	dispatcher := &fakeTurnDispatcher{results: map[string]turn.ToolResult{
		"call_1": {Content: "build ok"},
		"call_2": {Content: "edited a.txt", DisplayPatch: wiredEditPatch},
	}}

	var stdout, stderr strings.Builder
	surface := newHeadlessSurface(&stdout, &stderr)
	if _, ok := turnSurface(surface).(editPatchSurface); ok {
		t.Fatal("the headless surface implements the edit-patch sink; a headless run must have no patch surface to bind")
	}

	err := runHeadlessTurn(context.Background(), mkStore(t), providerCache(t, t.TempDir()),
		turnSelection("openai", "gpt-5.5", model.EffortDefault), surface, dispatcher,
		func() string { return "" }, func() []provider.ToolDefinition { return nil },
		t.TempDir(), time.Time{}, false, "build")
	if err != nil {
		t.Fatalf("runHeadlessTurn error = %v, want nil", err)
	}

	if got := stderr.String(); !strings.Contains(got, "Run: go build ./...") {
		t.Fatalf("stderr = %q, want the non-edit activity line preserved", got)
	}
	if got := stderr.String(); strings.Contains(got, "Edit a.txt") {
		t.Fatalf("stderr = %q, want no pre-dispatch edit placeholder", got)
	}
	for name, out := range map[string]string{"stdout": stdout.String(), "stderr": stderr.String()} {
		if strings.Contains(out, "@@ -1 +1 @@") {
			t.Fatalf("%s = %q, want no edit patch in headless output", name, out)
		}
	}
	if got := stdout.String(); !strings.Contains(got, "all done") {
		t.Fatalf("stdout = %q, want the model's answer", got)
	}
}

// A dispatched turn streams its deltas through the surface's sink and finalizes
// the transcript on natural completion, against an injected stub client (no
// network). Pins Done-when 3 and 4 at the controller level.
func TestTurnController_DispatchStreamsDeltasAndFinalizes(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hel"), contentChunk("lo"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if got := surface.deltaText(); got != "Hello" {
		t.Fatalf("streamed delta text = %q, want %q (deltas must render through AppendStreamDelta)", got, "Hello")
	}
	if got := surface.finalizeCount(); got != 1 {
		t.Fatalf("FinalizeStream called %d times, want 1 after a natural completion", got)
	}
	if got := surface.interruptCount(); got != 0 {
		t.Fatalf("MarkStreamInterrupted called %d times, want 0 on a natural completion", got)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want 1", client.callCount())
	}
	if _, inFlight := ctl.Cancel(); inFlight {
		t.Fatal("controller still reports an in-flight turn after natural completion")
	}
}

// A successful production turn appends exactly one completion footer, handing the
// controller the store's records — which carry the durable turn_latency the footer is
// built from — and seeds the in-flight indicator's elapsed clock from the accepted-input
// submit-start so its final elapsed matches that turn_latency.
func TestTurnController_AppendsCompletionFooterOnSuccessfulTurn(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	submitStart := time.Now().Add(-100 * time.Millisecond)
	if err := ctl.dispatch(store, submitStart); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if got := surface.footerCallCount(); got != 1 {
		t.Fatalf("AppendCompletionFooter called %d times, want 1 after a successful turn", got)
	}
	records, ok := surface.lastFooterRecords()
	if !ok || !slices.Contains(eventKinds(records), events.KindTurnLatency) {
		t.Fatalf("footer records missing turn_latency; kinds = %v", eventKinds(records))
	}
	seeds := surface.seededStartList()
	if len(seeds) != 1 || !seeds[0].Equal(submitStart) {
		t.Fatalf("SeedNextIndicatorStart calls = %v, want one seeded with submitStart %v", seeds, submitStart)
	}
}

// A failed or interrupted turn appends no completion footer: the success gate skips the
// append for a provider error (loop returns non-nil) and a mid-stream drop (sealed as
// interrupted), so neither turn attaches a "provider - model - duration" footer.
func TestTurnController_NoCompletionFooterOnFailureOrInterrupt(t *testing.T) {
	t.Run("provider error", func(t *testing.T) {
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		httpErr := &provider.HTTPError{Status: 429, Body: `{"error":{"message":"quota"}}`, Surface: "provider openai returned HTTP 429"}
		client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, httpErr
		}}
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		surface := &recordingSurface{}
		ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
		if err := ctl.dispatch(mkStore(t), time.Now()); err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		turns.Wait()
		if got := surface.footerCallCount(); got != 0 {
			t.Fatalf("AppendCompletionFooter called %d times, want 0 on a provider error", got)
		}
	})

	t.Run("mid-stream drop", func(t *testing.T) {
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Stream: dropStream(contentChunk("partial"), io.ErrUnexpectedEOF)}, nil
		}}
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		surface := &recordingSurface{}
		ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
		if err := ctl.dispatch(mkStore(t), time.Now()); err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		turns.Wait()
		if got := surface.footerCallCount(); got != 0 {
			t.Fatalf("AppendCompletionFooter called %d times, want 0 on a mid-stream drop", got)
		}
	})
}

func TestTurnController_TurnCompleteHookInputsPrecedeAQueuedPrompt(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("first answer"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	store.Append(sessions.Message{Role: "user", Content: sessions.TextContent("first prompt"), Timestamp: testStart})
	queued := make(chan struct{})
	surface := &recordingSurface{onTurnEnded: func(string) {
		store.Append(sessions.Message{Role: "user", Content: sessions.TextContent("queued prompt"), Timestamp: testStart})
		close(queued)
	}}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	var calls, usersAtHook int
	var gotUser, gotAssistant string
	ctl.setTurnCompleteHook(func(_ context.Context, _ provider.Client, _ model.Selection, s *sessions.Store, firstUser, firstAssistant string) {
		<-queued
		calls++
		usersAtHook = userMessageCount(s)
		gotUser, gotAssistant = firstUser, firstAssistant
	})

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if calls != 1 {
		t.Fatalf("completion hook calls = %d, want 1 (a queued prompt must not suppress it)", calls)
	}
	if usersAtHook != 2 {
		t.Fatalf("user records when the hook ran = %d, want 2 (the queued prompt already landed)", usersAtHook)
	}
	if gotUser != "first prompt" || gotAssistant != "first answer" {
		t.Fatalf("hook inputs = (%q, %q), want the opening exchange (%q, %q)", gotUser, gotAssistant, "first prompt", "first answer")
	}
}

func TestTurnController_TurnEndedReportsTerminalOutcome(t *testing.T) {
	t.Run("completed after the turn slot is released", func(t *testing.T) {
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
		}}
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		surface := &recordingSurface{}
		var ctl *turnController
		busyAtOutcome := true
		surface.onTurnEnded = func(string) { busyAtOutcome = ctl.busy() }
		ctl = newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

		if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		turns.Wait()

		if got := surface.outcomeList(); !slices.Equal(got, []string{"completed"}) {
			t.Fatalf("TurnEnded outcomes = %v, want exactly one completed", got)
		}
		if busyAtOutcome {
			t.Fatal("TurnEnded fired while the controller still reported a busy turn; the front queued prompt would be refused instead of dispatched")
		}
	})

	t.Run("cancellation is interrupted", func(t *testing.T) {
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		entered := make(chan struct{})
		ready := make(chan struct{})
		client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
			close(entered)
			return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
		}}
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		surface := &recordingSurface{}
		ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
		if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		<-entered
		<-ready
		ctl.Cancel()
		turns.Wait()

		if got := surface.outcomeList(); !slices.Equal(got, []string{"interrupted"}) {
			t.Fatalf("TurnEnded outcomes = %v, want exactly one interrupted (a cancelled turn is not a failure)", got)
		}
	})

	t.Run("deadline expiry is turn_failed", func(t *testing.T) {
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
			<-ctx.Done()
			return provider.Response{}, ctx.Err()
		}}
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(100*time.Millisecond))
		defer cancel()

		surface := &recordingSurface{}
		ctl := newTurnController(ctx, surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
		if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		turns.Wait()

		if got := surface.outcomeList(); !slices.Equal(got, []string{"turn_failed"}) {
			t.Fatalf("TurnEnded outcomes = %v, want exactly one turn_failed (a deadline is not a user interrupt)", got)
		}
	})

	t.Run("provider error is turn_failed", func(t *testing.T) {
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, &provider.HTTPError{Status: 500, Body: `{"error":{"message":"boom"}}`, Surface: "provider openai returned HTTP 500"}
		}}
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		surface := &recordingSurface{}
		ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
		if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v, want nil", err)
		}
		turns.Wait()

		if got := surface.outcomeList(); !slices.Equal(got, []string{"turn_failed"}) {
			t.Fatalf("TurnEnded outcomes = %v, want exactly one turn_failed", got)
		}
	})
}

// Terminal test: a real turn driven through the production turn controller
// (NewToolLoop + Runner, no fake at the event seam) against a stubbed provider
// transport persists a per-turn turn_latency and a per-round provider_round_trip,
// read back from the on-disk session file (not just the in-memory store), each with
// a plausible non-negative millisecond value and the turn's provider/model. The
// submit-start is the instant the prompt entrypoint forwards into dispatch.
func TestTurnController_DispatchPersistsLatencyEvents(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	submitStart := time.Now().Add(-100 * time.Millisecond)
	if err := ctl.dispatch(store, submitStart); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	// Read back the latency events from the flushed file, not the in-memory store.
	sess, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed session %s: %v", store.Path(), err)
	}
	var latency []events.TurnLatency
	var rounds []events.ProviderRoundTrip
	for _, r := range sess.Records {
		ev, ok := r.(sessions.Event)
		if !ok {
			continue
		}
		switch ev.Kind {
		case events.KindTurnLatency:
			var p events.TurnLatency
			if uerr := json.Unmarshal(ev.Payload, &p); uerr != nil {
				t.Fatalf("decode turn_latency: %v", uerr)
			}
			latency = append(latency, p)
		case events.KindProviderRoundTrip:
			var p events.ProviderRoundTrip
			if uerr := json.Unmarshal(ev.Payload, &p); uerr != nil {
				t.Fatalf("decode provider_round_trip: %v", uerr)
			}
			rounds = append(rounds, p)
		}
	}

	if len(latency) != 1 {
		t.Fatalf("persisted turn_latency events = %d, want 1", len(latency))
	}
	if latency[0].DurationMs < 0 {
		t.Fatalf("turn_latency duration_ms = %d, want a plausible non-negative value", latency[0].DurationMs)
	}
	if latency[0].Provider != "openai" || latency[0].ModelID != "gpt-5.5" {
		t.Fatalf("turn_latency identity = %+v, want provider openai model gpt-5.5", latency[0])
	}
	if len(rounds) != 1 {
		t.Fatalf("persisted provider_round_trip events = %d, want 1", len(rounds))
	}
	if rounds[0].DurationMs < 0 {
		t.Fatalf("provider_round_trip duration_ms = %d, want a plausible non-negative value", rounds[0].DurationMs)
	}
	if rounds[0].Provider != "openai" || rounds[0].ModelID != "gpt-5.5" {
		t.Fatalf("provider_round_trip identity = %+v, want provider openai model gpt-5.5", rounds[0])
	}
}

// A dispatched turn shows the in-flight indicator once at dispatch, forwards the
// exact final usage as the indicator's settled figure, and clears it once when the
// loop returns. The forwarded figure equals the session total /status sums from the
// persisted model_response, which is the indicator's consistency gate (Done-when 3).
func TestTurnController_IndicatorShowsClearsAndForwardsExactTokens(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hello"), finishChunk("stop"), usageChunk(120, 40))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if surface.showCount() != 1 {
		t.Fatalf("ShowIndicator called %d times, want 1 per turn", surface.showCount())
	}
	if surface.clearCount() != 1 {
		t.Fatalf("ClearIndicator called %d times, want 1 when the loop returns", surface.clearCount())
	}
	// Fresh session: the indicator starts at a zero base on both channels.
	if surface.shownInput != 0 || surface.shownOutput != 0 {
		t.Fatalf("ShowIndicator base tokens = (%d, %d), want (0, 0) for a fresh session", surface.shownInput, surface.shownOutput)
	}
	lastIn, lastOut, ok := surface.lastTokenUpdate()
	if !ok {
		t.Fatal("no SetIndicatorTokens call; the runner did not forward exact usage")
	}
	// The settled ↑/↓ figures equal what /status sums from the persisted model_response
	// (base 0 + this turn's 120 input / 40 output), so the split display stays consistent
	// with /status per channel.
	in, out := model.SumModelResponseTokens(store.Records())
	if in != 120 || out != 40 {
		t.Fatalf("/status token totals = (%d, %d), want (120, 40) (exact usage persisted)", in, out)
	}
	if lastIn != in || lastOut != out {
		t.Fatalf("indicator settled tokens = (%d, %d), want (%d, %d) (consistent with /status)", lastIn, lastOut, in, out)
	}
}

// Regression: the ↓ (output) figure must never decrease across a turn. Streamed
// assistant text routinely has more runes than the round's exact output tokens, so the
// fixture sends "Hello world" (11 runes) and a usage chunk reporting only 3 output
// tokens — the realistic runes>tokens case the prior monotonicity test masked by
// choosing tokens above runes. With the production binding feeding ↓ from retained runes
// the series would be [11, 3] (a downward correction); driving ↓ from exact usage only,
// it never exceeds the settled 3. Asserts the whole ↓ series is non-decreasing and ↑/↓
// settle on the /status totals.
func TestTurnController_IndicatorOutputNeverDecreasesWhenRunesExceedTokens(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hello world"), finishChunk("stop"), usageChunk(120, 3))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	updates := surface.allTokenUpdates()
	if len(updates) == 0 {
		t.Fatal("no SetIndicatorTokens call; the turn forwarded no usage")
	}
	var prevIn, prevOut int64
	for i, u := range updates {
		if u[0] < prevIn {
			t.Fatalf("↑ input series decreased at update %d: %d after %d (%v)", i, u[0], prevIn, updates)
		}
		if u[1] < prevOut {
			t.Fatalf("↓ output series decreased at update %d: %d after %d (11 runes must not be shown then dropped to 3 tokens) (%v)", i, u[1], prevOut, updates)
		}
		prevIn, prevOut = u[0], u[1]
	}
	// The settled figures equal what /status sums (base 0 + this turn's 120/3).
	in, out := model.SumModelResponseTokens(store.Records())
	if lastIn, lastOut, _ := surface.lastTokenUpdate(); lastIn != in || lastOut != out || in != 120 || out != 3 {
		t.Fatalf("settled tokens = (%d, %d), /status = (%d, %d), want both (120, 3)", lastIn, lastOut, in, out)
	}
}

// indicatorTurnResult builds the no-network launch snapshot the production-path
// indicator tests drive a real turn through.
func indicatorTurnResult(t *testing.T, store *sessions.Store) *BootstrapResult {
	t.Helper()
	return &BootstrapResult{
		Home:      t.TempDir(),
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": "https://api.openai.com/v1",
					"api_key":  "sk-test",
					"models":   []string{"gpt-5.5"},
				},
			},
		},
	}
}

// Production path: a prompt submitted through the app StartTUI assembles makes the
// in-flight indicator visible while the turn streams (with a non-zero token figure
// from the streamed deltas), and a user interrupt clears it — proving the indicator
// is wired to the real turn controller, not just unit-level fakes (Done-when 1/2,
// cleared-on-interrupt).
func TestTurnController_IndicatorVisibleDuringTurnClearsOnInterrupt(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	ready := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app, restore := startCaptured(t, ctx, indicatorTurnResult(t, store), io.Discard)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the turn entrypoint is not wired")
	}
	<-entered
	<-ready // the first delta streamed and counted; the turn is now blocked in-flight

	if !app.IndicatorVisible() {
		t.Fatal("indicator not visible during an in-flight turn (Done-when 1)")
	}
	// Mid-stream, before round 1's usage chunk lands, both channels stay at the session
	// base (fresh session → 0): the indicator advances ↑/↓ only from exact per-round usage, never
	// from streamed runes, so a pre-usage in-flight state shows the accepted brief 0
	// rather than a rune estimate that would later drop when usage arrives (the
	// non-monotonic correction the indicator avoids). The indicator is visible regardless.
	if in, out := app.IndicatorTokens(); in != 0 || out != 0 {
		t.Fatalf("indicator tokens = (↑%d ↓%d) mid-stream before usage, want (0, 0) (exact usage only, no rune estimate)", in, out)
	}

	app.HandleEsc()
	turns.Wait()

	if app.IndicatorVisible() {
		t.Fatal("indicator still visible after a user interrupt (Done-when 1: cleared on interrupt)")
	}
}

// Production path: ESC clears the in-flight indicator the moment it records the
// interrupt, not when the background turn goroutine later joins. The gated stub
// keeps that goroutine parked in the stream past the cancel, so the only thing that
// can have cleared the indicator before turns.Wait() is HandleEsc's own UI-path
// clear — the turnController.run backstop cannot have run yet. Without the
// interruptStream-side clear this fails (the indicator stays up while
// stream_interrupted is already recorded); the post-join assertion in the test
// above would still pass via the backstop, so this is the assertion that pins the
// requirement that the indicator disappears *when* a turn is interrupted.
func TestTurnController_IndicatorClearsOnInterruptBeforeTurnGoroutineExits(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	ready := make(chan struct{})
	release := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: gatedStream(ctx, contentChunk("Hi"), ready, release)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app, restore := startCaptured(t, ctx, indicatorTurnResult(t, store), io.Discard)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the turn entrypoint is not wired")
	}
	<-entered
	<-ready // the first delta streamed; the turn is blocked in-flight on release

	if !app.IndicatorVisible() {
		t.Fatal("indicator not visible during an in-flight turn")
	}

	// ESC records the interrupt and, on this same goroutine, must clear the
	// indicator — while the turn goroutine is still parked on release (so the
	// run() backstop has not run).
	app.HandleEsc()
	if app.IndicatorVisible() {
		t.Fatal("indicator still visible immediately after ESC recorded the interrupt; the UI interrupt path did not clear it (it waited for the background turn to exit)")
	}

	close(release) // let the parked turn goroutine observe the cancel and unwind
	turns.Wait()
}

// Production path: a turn that completes naturally clears the indicator, and
// /status — read through the same app — reports this turn's exact provider usage,
// so what the indicator tracked is consistent with /status (Done-when 1/3).
func TestTurnController_IndicatorClearsOnCompletionAndStatusConsistent(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hi"), finishChunk("stop"), usageChunk(120, 40))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app, restore := startCaptured(t, ctx, indicatorTurnResult(t, store), io.Discard)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt")
	}
	turns.Wait()

	if app.IndicatorVisible() {
		t.Fatal("indicator still visible after natural completion (Done-when 1)")
	}

	if !app.SubmitInput("/status") {
		t.Fatal("/status rejected through the production submit path")
	}
	overlay := app.StatusText()
	if !strings.Contains(overlay, "Token usage: 120 input, 40 output") {
		t.Fatalf("/status token usage is not the turn's exact usage:\n%s", overlay)
	}
	// Exact usage carries no anomaly, so the session stays fully attestable — proof
	// the recorded usage was real, not the usage_missing fallback. That
	// shows as the absence of the incomplete-counts line (no always-on attestability
	// line anymore).
	if strings.Contains(overlay, "Token counts:") {
		t.Fatalf("/status renders an incomplete-counts line; usage was not recorded exactly:\n%s", overlay)
	}
}

func TestTurnController_IndicatorClearsOnProviderFailureWithSingleCommittedError(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	dnsErr := &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true}
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{}, dnsErr
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	app, restore := startCaptured(t, ctx, indicatorTurnResult(t, store), io.Discard)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the turn entrypoint is not wired")
	}
	turns.Wait()

	if app.IndicatorVisible() {
		t.Fatal("tracker still visible after a provider failure; the turn-controller teardown did not clear it")
	}
	text := app.TranscriptText()
	const wantErr = "provider openai request to model gpt-5.5 failed"
	if n := strings.Count(text, wantErr); n != 1 {
		t.Fatalf("provider error appears %d times in the transcript, want exactly one committed line:\n%s", n, text)
	}
	if strings.Contains(text, "Working…") {
		t.Fatalf("transcript retains transient tracker copy after the failure:\n%s", text)
	}
}

// A dispatched turn leads its provider request with the controller's assembled
// AGENTS.md system prompt. Pins Done-when 3: the bootstrap turn wiring
// passes the loaded instructions into the runtime so production turns include the
// system prompt.
func TestTurnController_DispatchLeadsRequestWithSystemPrompt(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotMessages []provider.Message
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		gotMessages = req.Messages
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), func() string { return "assembled AGENTS.md" }, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if len(gotMessages) == 0 {
		t.Fatal("provider request carried no messages, want a leading system message")
	}
	if gotMessages[0].Role != "system" || gotMessages[0].Content != "assembled AGENTS.md" {
		t.Fatalf("first request message = %+v, want a system message carrying the assembled prompt", gotMessages[0])
	}
	systemCount := 0
	for _, m := range gotMessages {
		if m.Role == "system" {
			systemCount++
		}
	}
	if systemCount != 1 {
		t.Fatalf("request carried %d system messages, want exactly 1 (the assembled AGENTS.md prompt)", systemCount)
	}
}

// A dispatched turn advertises the controller's mode-filtered tool set on the provider
// request (Done-when 1/2). The advertiser is bound from a real registry + mode
// (newToolAdvertiser), so the captured request carries the registry tools plus bash; a
// nil advertiser would carry none.
func TestTurnController_DispatchAdvertisesModeFilteredTools(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotTools []provider.ToolDefinition
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		gotTools = req.Tools
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	// Plan: only the read-only registry tool is advertised, but bash always is.
	ctl.setToolAdvertiser(newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Plan, mode.SourceDefault)))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	got := toolNames(gotTools)
	want := []string{"bash", "suggest_followup", "vcs_status"} // vcs_commit (mutating) filtered out in Plan
	if !slices.Equal(got, want) {
		t.Fatalf("advertised tools on request = %v, want %v", got, want)
	}
}

// A suggest_followup tool call is intercepted at the production turn
// controller — it fires the bound surface.SuggestFollowup callback with the parsed
// label/prompt, is never dispatched as an action, and never appears in the session
// record read back from disk, while the round's assistant prose is preserved as the
// ordinary final reply. This pins the production wiring seam (turn.Deps.SuggestFollowup →
// surface.SuggestFollowup), not just the turn-package unit behavior.
func TestTurnController_SuggestFollowupInterceptedAndNotPersisted(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	args := `{"label":"Add LOC deltas","prompt":"Add before/after LOC deltas to each task"}`
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(
			contentChunk("Here is the summary."),
			toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", args)),
		)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolAdvertiser(newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Build, mode.SourceDefault)))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	// The production callback fired once with the parsed label/prompt.
	pairs := surface.suggestionPairs()
	if len(pairs) != 1 || pairs[0][0] != "Add LOC deltas" || pairs[0][1] != "Add before/after LOC deltas to each task" {
		t.Fatalf("SuggestFollowup callback pairs = %v, want one parsed {label, prompt}", pairs)
	}
	// A suggest-only round is terminal: one provider round, no continuation.
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (no continuation for a suggest-only round)", client.callCount())
	}

	// suggest_followup appears nowhere in the persisted session, read back from disk.
	reloaded := reloadStore(t, store)
	for _, r := range reloaded.Records() {
		m, ok := r.(sessions.Message)
		if !ok {
			continue
		}
		if strings.Contains(m.Content.Text(), "suggest_followup") {
			t.Fatalf("session message contains suggest_followup: %q", m.Content.Text())
		}
		for _, tc := range m.ToolCalls {
			if strings.Contains(string(tc.Raw), "suggest_followup") {
				t.Fatalf("session assistant tool_calls contain suggest_followup: %s", tc.Raw)
			}
		}
	}
	// The assistant prose is preserved as the ordinary final reply (no tool_calls on it).
	asst := messagesByRole(reloaded, "assistant")
	if len(asst) != 1 || asst[0].Content.Text() != "Here is the summary." {
		t.Fatalf("assistant messages = %+v, want one carrying the streamed prose", asst)
	}
	if len(asst[0].ToolCalls) != 0 {
		t.Fatalf("final assistant message carries tool_calls %+v, want none", asst[0].ToolCalls)
	}
}

// TestTurnController_DevDebugWiresTraceAndArmsSurface pins the dev-debug production wiring: when
// the dev-debug gate is armed (setDevDebug), dispatch threads the gate and the active mode
// onto the turn so the loop records the turn-side suggest_followup trace (request_built →
// tool_call_seen → intercepted, stamped with this turn's provider/model/mode), and it arms
// the TUI surface with the same provider/model/mode for the ghost stages.
func TestTurnController_DevDebugWiresTraceAndArmsSurface(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	args := `{"label":"Add LOC deltas","prompt":"Add before/after LOC deltas to each task"}`
	client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(
			contentChunk("Here is the summary."),
			toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", args)),
		)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolAdvertiser(newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Build, mode.SourceDefault)))

	var armed [][3]string
	ctl.setDevDebug(true, func() string { return "build" }, func(provider, model, mode string) {
		armed = append(armed, [3]string{provider, model, mode})
	})

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	// The TUI surface was armed once with this turn's provider/model/mode.
	if len(armed) != 1 || armed[0] != [3]string{"openai", "gpt-5.5", "build"} {
		t.Fatalf("armed TUI debug context = %v, want one [openai gpt-5.5 build]", armed)
	}

	// The turn-side trace was recorded with the wired context.
	var stages []string
	var advertised *bool
	for _, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindSuggestFollowupDebug {
			continue
		}
		var p events.SuggestFollowupDebug
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode suggest_followup_debug: %v", err)
		}
		if p.Provider != "openai" || p.ModelID != "gpt-5.5" || p.Mode != "build" {
			t.Fatalf("debug context = (%q,%q,%q), want (openai,gpt-5.5,build)", p.Provider, p.ModelID, p.Mode)
		}
		stages = append(stages, p.Stage)
		if p.Stage == events.SuggestFollowupStageRequestBuilt {
			advertised = p.Advertised
		}
	}
	want := []string{
		events.SuggestFollowupStageRequestBuilt,
		events.SuggestFollowupStageToolCallSeen,
		events.SuggestFollowupStageIntercepted,
	}
	if strings.Join(stages, ",") != strings.Join(want, ",") {
		t.Fatalf("turn-side debug stages = %v, want %v", stages, want)
	}
	if advertised == nil || !*advertised {
		t.Fatalf("request_built advertised = %v, want true (suggest_followup is advertised in every mode)", advertised)
	}
}

// Production path: with the dev-debug gate on, an intercepted suggest_followup call flows
// through the real TUI surface and the persisted session records the complete ordered trace
// (turn-side request/intercept stages followed by TUI surface/ghost stages). With the gate
// off, the same forced call records no debug events.
func TestTurnController_DevDebugProductionAppRecordsFullSequence(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		want    []string
	}{
		{
			name:    "enabled records full sequence",
			enabled: true,
			want: []string{
				events.SuggestFollowupStageRequestBuilt,
				events.SuggestFollowupStageToolCallSeen,
				events.SuggestFollowupStageIntercepted,
				events.SuggestFollowupStageSurfaceCalled,
				events.SuggestFollowupStageGhostSet,
			},
		},
		{name: "disabled records nothing", enabled: false, want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			args := `{"label":"Add LOC deltas","prompt":"Add before/after LOC deltas to each task"}`
			client := &stubTurnClient{fn: func(_ context.Context, _ provider.Request) (provider.Response, error) {
				return provider.Response{Stream: newStream(
					contentChunk("Here is the summary."),
					toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", args)),
				)}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			store := mkStore(t)
			app := tui.New(nil)
			app.SetActiveStore(store)
			ctl := newTurnController(context.Background(), app, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
			ctl.setToolAdvertiser(newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Build, mode.SourceDefault)))
			ctl.setDevDebug(tc.enabled, func() string { return "build" }, app.SetFollowupDebugContext)

			if err := ctl.dispatch(store, time.Time{}); err != nil {
				t.Fatalf("dispatch error = %v", err)
			}
			turns.Wait()

			reloaded := reloadStore(t, store)
			var stages []string
			for _, r := range reloaded.Records() {
				ev, ok := r.(sessions.Event)
				if !ok || ev.Kind != events.KindSuggestFollowupDebug {
					continue
				}
				if strings.Contains(string(ev.Payload), "Add LOC deltas") || strings.Contains(string(ev.Payload), "Add before/after LOC deltas to each task") {
					t.Fatalf("suggest_followup_debug persisted suggestion text: %s", ev.Payload)
				}
				var p events.SuggestFollowupDebug
				if err := json.Unmarshal(ev.Payload, &p); err != nil {
					t.Fatalf("decode suggest_followup_debug: %v", err)
				}
				if p.Provider != "openai" || p.ModelID != "gpt-5.5" || p.Mode != "build" {
					t.Fatalf("debug context = (%q,%q,%q), want (openai,gpt-5.5,build)", p.Provider, p.ModelID, p.Mode)
				}
				if p.Stage == events.SuggestFollowupStageRequestBuilt && (p.Advertised == nil || !*p.Advertised) {
					t.Fatalf("request_built advertised = %v, want true", p.Advertised)
				}
				stages = append(stages, p.Stage)
			}

			if !slices.Equal(stages, tc.want) {
				t.Fatalf("persisted debug stages = %v, want %v", stages, tc.want)
			}
		})
	}
}

// A nil advertiser advertises no tools, so the request carries an empty set and the
// provider client omits the tools/tool_choice fields.
func TestTurnController_DispatchWithoutAdvertiserSendsNoTools(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotTools []provider.ToolDefinition
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		gotTools = req.Tools
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if len(gotTools) != 0 {
		t.Fatalf("advertised tools = %v, want none for a nil advertiser", gotTools)
	}
}

// The advertised set is snapshotted once per dispatch, so a tool-call continuation round
// re-issues with the same tools as the initial round. The advertiser
// is read once at dispatch; both provider rounds of the agentic turn capture the same set.
func TestTurnController_ToolCallContinuationPreservesAdvertisedTools(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var perRound [][]string
	client := toolThenContentClient(&perRound, "bash", `{"command":"echo hi"}`, "done")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	store := mkStore(t)
	run := &fakeDispatchRunner{result: cmdrunner.RunResult{Stdout: []byte("hi\n")}}
	auth := &recordingAuthorizer{decision: allow()}
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolAdvertiser(newToolAdvertiser(advRegistry(t), mode.NewActiveState(mode.Build, mode.SourceDefault)))
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if len(perRound) != 2 {
		t.Fatalf("provider rounds = %d, want 2 (tool-call round + final round)", len(perRound))
	}
	want := []string{"bash", "suggest_followup", "vcs_commit", "vcs_status"}
	for i, got := range perRound {
		if !slices.Equal(got, want) {
			t.Fatalf("round %d advertised %v, want %v (continuation must preserve the initial set)", i, got, want)
		}
	}
}

// The system message is assembled per dispatch from the current run-scoped mode, so a
// /mode switch between turns changes the next provider request's leading system
// message. Two dispatches around an ApplyUserCommand switch carry
// the Build then the Plan base prompt, while both still carry the environment block —
// proving the prompt is not frozen at controller construction.
func TestTurnController_DispatchAssemblesPromptFromCurrentModeAcrossSwitch(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var captured []string
	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if len(req.Messages) > 0 && req.Messages[0].Role == "system" {
			captured = append(captured, req.Messages[0].Content)
		} else {
			captured = append(captured, "")
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	modeActive := mode.NewActiveState(mode.Build, mode.SourceDefault)
	result := &BootstrapResult{LaunchDir: "/launch", ProjectRoot: "/launch"}
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), newSystemPromptAssembler(result, modeActive, model.NewActiveState(nil, "")), nil)

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("first dispatch error = %v", err)
	}
	turns.Wait()

	modeActive.ApplyUserCommand(mode.Plan)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("second dispatch error = %v", err)
	}
	turns.Wait()

	if len(captured) != 2 {
		t.Fatalf("captured %d system messages, want 2", len(captured))
	}
	if !strings.Contains(captured[0], "Build mode") {
		t.Fatalf("first turn system message did not carry the Build base prompt:\n%s", captured[0])
	}
	if !strings.Contains(captured[1], "Plan mode") {
		t.Fatalf("second turn (after /mode switch) did not carry the Plan base prompt:\n%s", captured[1])
	}
	if captured[0] == captured[1] {
		t.Fatal("system message did not change after the mode switch; the prompt was frozen at construction")
	}
	for i, msg := range captured {
		if !strings.Contains(msg, "Environment:") || !strings.Contains(msg, "Working directory: /launch") {
			t.Fatalf("turn %d system message missing the environment block:\n%s", i, msg)
		}
	}
}

func TestTurnController_StreamInFlightReportsWithoutCancelling(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	ready := make(chan struct{})
	release := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: gatedStream(ctx, contentChunk("Hi"), ready, release)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if ctl.StreamInFlight() {
		t.Fatal("an idle controller reports a provider stream in flight")
	}

	store := mkStore(t)
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	<-entered
	<-ready

	if !ctl.StreamInFlight() {
		t.Fatal("StreamInFlight = false while the turn's provider stream was being consumed")
	}

	close(release)
	turns.Wait()

	if ctl.StreamInFlight() {
		t.Fatal("StreamInFlight = true after the turn completed")
	}
	recs := store.Records()
	if !slices.Contains(eventKinds(recs), "model_response") {
		t.Fatalf("no model_response after the observed turn completed; kinds = %v (StreamInFlight must not cancel)", eventKinds(recs))
	}
	if slices.Contains(eventKinds(recs), "stream_interrupted") {
		t.Fatalf("stream_interrupted recorded for a turn only observed through StreamInFlight; kinds = %v", eventKinds(recs))
	}
}

// The TUI reaches the controller's read-only report through an optional interface it
// type-asserts on the installed canceller, so the two must keep matching shapes.
func TestTurnController_DisarmsTheEscAfterAStatusDismissal(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	ready := make(chan struct{})
	release := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: gatedStream(ctx, contentChunk("Hi"), ready, release)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	store := mkStore(t)
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	<-entered
	<-ready

	app := tui.New(nil)
	app.SetActiveStore(store)
	app.SetStreamCanceller(ctl)
	app.ShowStatus("snapshot")

	app.HandleEsc()
	app.HandleEsc()

	if got := app.NoticeText(); got != "press ESC again to interrupt" {
		t.Fatalf("notice = %q, want the disarmed-ESC hint; the TUI did not see the controller's in-flight report", got)
	}
	if slices.Contains(eventKinds(store.Records()), "stream_interrupted") {
		t.Fatalf("the ESC after a /status dismissal interrupted the turn; kinds = %v", eventKinds(store.Records()))
	}

	close(release)
	turns.Wait()
}

func TestTurnController_WaitTurnDrainedBlocksUntilCancelledLoopReturns(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	ready := make(chan struct{})
	release := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: gatedStream(ctx, contentChunk("Hi"), ready, release)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	<-entered
	<-ready

	if _, inFlight := ctl.Cancel(); !inFlight {
		t.Fatal("Cancel did not report the in-flight stream it was supposed to target")
	}

	drained := make(chan struct{})
	go func() { defer close(drained); ctl.WaitTurnDrained() }()

	select {
	case <-drained:
		t.Fatal("WaitTurnDrained returned while the cancelled turn was still inside its loop")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-drained
	turns.Wait()

	if ctl.busy() {
		t.Fatal("controller still reports a live turn after WaitTurnDrained returned")
	}
}

func TestTurnController_WaitTurnDrainedDoesNotWaitForIndicatorCleanup(t *testing.T) {
	launched := make(chan func(), 1)
	defer swapGoTurn(func(fn func()) { launched <- fn })()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hi"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{clearEntered: make(chan struct{}), clearRelease: make(chan struct{})}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	runTurn := <-launched
	runDone := make(chan struct{})
	go func() {
		runTurn()
		close(runDone)
	}()

	<-surface.clearEntered
	drained := make(chan struct{})
	go func() {
		ctl.WaitTurnDrained()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("WaitTurnDrained blocked on indicator cleanup after the loop returned")
	}

	close(surface.clearRelease)
	<-runDone
}

func TestTurnController_WaitTurnDrainedReturnsImmediatelyWhenIdle(t *testing.T) {
	defer swapGoTurn(func(func()) { t.Fatal("goTurn launched without a dispatch") })()

	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	done := make(chan struct{})
	go func() { defer close(done); ctl.WaitTurnDrained() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitTurnDrained blocked on an idle controller")
	}
}

func TestTurnController_WaitTurnDrainedAfterNaturalCompletion(t *testing.T) {
	launched := make(chan func(), 1)
	defer swapGoTurn(func(fn func()) { launched <- fn })()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("Hi"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	runTurn := <-launched

	done := make(chan struct{})
	go func() { defer close(done); ctl.WaitTurnDrained() }()
	select {
	case <-done:
		t.Fatal("WaitTurnDrained returned for a live turn whose loop had not run yet")
	case <-time.After(50 * time.Millisecond):
	}

	runTurn()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WaitTurnDrained never returned for a turn that completed without cancellation")
	}

	if ctl.busy() {
		t.Fatal("controller still holds a live turn after natural completion")
	}
}

// A second dispatch while a turn is in flight is dropped (one active runner at a
// time), and Cancel targets the first, still-streaming runner. Pins the
// architecture-review single-active-runner policy.
func TestTurnController_SingleActiveRunnerDropsOverlap(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered := make(chan struct{})
	ready := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		close(entered)
		return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("first dispatch error = %v", err)
	}
	<-entered
	<-ready // the first turn has streamed a delta and is now blocked in-flight
	if !ctl.busy() {
		t.Fatal("controller not busy during an in-flight turn")
	}

	// Overlapping dispatch is a no-op: it neither issues a second provider call nor
	// replaces the cancellable active runner.
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("overlapping dispatch error = %v", err)
	}

	retained, inFlight := ctl.Cancel()
	if !inFlight || retained == 0 {
		t.Fatalf("Cancel targeted the wrong runner: retained=%d inFlight=%v, want retained>0 inFlight=true", retained, inFlight)
	}
	turns.Wait()
	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want 1 (overlapping dispatch must be dropped)", client.callCount())
	}
}

// With no model selected, dispatch issues no turn: no client is built and no turn
// goroutine is launched.
func TestTurnController_NoModelIssuesNoTurn(t *testing.T) {
	defer swapGoTurn(func(func()) { t.Fatal("goTurn launched for a no-model dispatch") })()
	var built int32
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		atomic.AddInt32(&built, 1)
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) { return provider.Response{}, nil }}
	})()

	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), model.NewActiveState(nil, ""), nil, nil)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	if atomic.LoadInt32(&built) != 0 {
		t.Fatal("provider client built for a no-model dispatch")
	}
	if _, inFlight := ctl.Cancel(); inFlight {
		t.Fatal("a turn was started for a no-model dispatch")
	}
}

// A selection whose provider is not configured issues no turn: the client cannot
// be built, so none is, and no turn goroutine launches.
func TestTurnController_UnconfiguredProviderIssuesNoTurn(t *testing.T) {
	defer swapGoTurn(func(func()) { t.Fatal("goTurn launched for an unconfigured provider") })()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		t.Fatal("provider client built for an unconfigured provider")
		return nil
	})()

	// providerCache configures only "openai"; "anthropic" is absent.
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("anthropic", "claude", model.EffortDefault), nil, nil)
	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
}

func TestTurnController_SupportedEffortStartFlushFailureRoutesThroughG250(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := unwritableStore(t, "turn-flush-fail", "/proj")
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if client.callCount() != 0 {
		t.Fatalf("provider client called %d times, want 0 (model_turn flush failure blocks the provider)", client.callCount())
	}
	kinds := eventKinds(store.Records())
	for _, want := range []string{"model_turn", "session_write_failed"} {
		if !slices.Contains(kinds, want) {
			t.Fatalf("missing %q after a routed start flush failure; kinds = %v", want, kinds)
		}
	}
	if slices.Contains(kinds, "model_response") {
		t.Fatalf("model_response emitted despite a blocked provider call; kinds = %v", kinds)
	}
	if surface.noticeCount() == 0 {
		t.Fatal("req-400a write-failure notice not rendered through the surface")
	}
	if surface.finalizeCount() != 0 {
		t.Fatal("FinalizeStream called despite a blocked turn")
	}
}

func TestTurnController_FinalFlushFailureStillFinalizesCompletedStream(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	dir := t.TempDir()
	store := storeAt(t, filepath.Join(dir, "session.json"), "turn-final-flush-fail", "/proj")
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("remove session dir: %v", err)
		}
		if err := os.WriteFile(dir, []byte("not a dir"), 0o600); err != nil {
			t.Fatalf("replace session dir with file: %v", err)
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want 1 completed turn", client.callCount())
	}
	if surface.noticeCount() == 0 {
		t.Fatal("req-400a final write-failure notice not rendered through the surface")
	}
	if surface.finalizeCount() != 1 {
		t.Fatalf("FinalizeStream called %d times, want 1 after completed stream despite final flush failure", surface.finalizeCount())
	}
}

// An unsupported-effort flush failure routes through the per-turn protocol
// (records retained, session_write_failed appended, notice rendered) and blocks the
// provider call, finalizing nothing. Pins Step 7's production flush binding.
func TestTurnController_UnsupportedEffortFlushFailureRoutesThroughG250(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	// Unwritable store so the post-unsupported flush fails with a real write reason.
	store := unwritableStore(t, "turn-flush-fail", "/proj")
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "ghost-model", "high"), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if client.callCount() != 0 {
		t.Fatalf("provider client called %d times, want 0 (an unsupported-effort flush failure blocks the provider)", client.callCount())
	}
	kinds := eventKinds(store.Records())
	for _, want := range []string{"model_effort_unsupported", "model_turn", "session_write_failed"} {
		if !slices.Contains(kinds, want) {
			t.Fatalf("missing %q after a routed flush failure; kinds = %v", want, kinds)
		}
	}
	if surface.noticeCount() == 0 {
		t.Fatal("req-400a write-failure notice not rendered through the surface")
	}
	if surface.finalizeCount() != 0 {
		t.Fatal("FinalizeStream called despite a blocked turn")
	}
}

// An exhausted quota-declaring HTTP retry commits the attempt-count prefix plus
// the friendly line-1 provider message
// (extracted from the body, not the raw JSON) plus the quota remediation hint as
// an in-place transcript line through the controller's wired Notice/RenderNotice
// hooks (provider/turn request errors are committed history, not the
// bottom-pinned notice). Removing either field from the dispatch turn.Deps literal
// fails this: dropping Notice yields zero committed lines, dropping RenderNotice
// drops the "→ hint:" line (the runner then defaults RenderNotice to an identity
// renderer). It also pins that the provider error does NOT take the transient
// NoticeFromBackground surface. Pins the committed-error wiring at the production
// registration point.
func TestTurnController_QuotaHTTPErrorSurfacesHintNotice(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	httpErr := &provider.HTTPError{
		Status:  429,
		Body:    `{"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}`,
		Surface: `provider openai returned HTTP 429: {"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}`,
	}
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{}, httpErr
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed errors = %v, want exactly one in-place provider-error line", committed)
	}
	// Line 1 is enriched with the retry attempt count, then the friendly
	// message extracted from error.message, not the raw JSON.
	const wantLine1 = "failed after 4 attempts: provider openai returned HTTP 429: You exceeded your current quota"
	if !strings.HasPrefix(committed[0], wantLine1) {
		t.Fatalf("committed error = %q, want it to start with the friendly line %q (Notice/RenderNotice must be wired)", committed[0], wantLine1)
	}
	if strings.Contains(committed[0], "{") {
		t.Fatalf("committed error = %q, leaked the raw JSON body (adr-006: friendly line only)", committed[0])
	}
	if !strings.Contains(committed[0], "→ hint:") {
		t.Fatalf("committed error = %q, want f85's quota hint line (RenderNotice must be wired, not the identity default)", committed[0])
	}
	// A provider/turn request error is committed history, never the transient
	// bottom-pinned notice (that is reserved for session-write failures).
	if n := surface.noticeList(); len(n) != 0 {
		t.Fatalf("transient notices = %v, want none (provider errors commit to history, not the notice)", n)
	}
	if surface.finalizeCount() != 0 {
		t.Fatalf("FinalizeStream called %d times, want 0 on an HTTP error", surface.finalizeCount())
	}
	if surface.interruptCount() != 0 {
		t.Fatalf("MarkStreamInterrupted called %d times, want 0 on an HTTP error", surface.interruptCount())
	}
}

// An exhausted mid-stream transport-drop retry seals the transcript as interrupted
// through the controller's wired Interrupt hook, finalizes nothing, and then commits
// the stream-drop failure as an in-place transcript line tied to the turn. The
// committed line lands after the interrupt so it follows the sealed block. Removing
// the Interrupt field from the dispatch turn.Deps literal fails the interrupt
// assertion (the runner defaults it to a no-op); removing the new Notice call in the
// runner's stream-drop branch fails the committed-line assertion (no committed
// error, the partial reply is sealed but never surfaced). It also pins that the
// drop error does NOT take the transient NoticeFromBackground surface. Pins the
// stream-drop interrupt + committed-error wiring.
func TestTurnController_MidStreamDropMarksInterruptedAndCommitsError(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: dropStream(contentChunk("partial"), io.ErrUnexpectedEOF)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if got := surface.interruptCount(); got != 1 {
		t.Fatalf("MarkStreamInterrupted called %d times, want 1 on a mid-stream drop", got)
	}
	if got := surface.finalizeCount(); got != 0 {
		t.Fatalf("FinalizeStream called %d times, want 0 on a mid-stream drop", got)
	}
	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed errors = %v, want exactly one in-place stream-drop error line", committed)
	}
	const wantPrefix = "failed after 4 attempts: provider openai request to model gpt-5.5 failed (stream_drop/stream_eof)"
	if !strings.HasPrefix(committed[0], wantPrefix) {
		t.Fatalf("committed error = %q, want it to start with %q (the rendered stream-drop surface)", committed[0], wantPrefix)
	}
	// The stream-drop error is committed history, never the transient
	// bottom-pinned notice (reserved for session-write failures).
	if n := surface.noticeList(); len(n) != 0 {
		t.Fatalf("transient notices = %v, want none (the stream drop commits to history, not the notice)", n)
	}
}

// A pre-stream transport failure whose provider_request_failed flush hits a real
// atomic-write error routes the session_write_failed notice through the
// controller's wired OnFailureWrite hook. The initial start flush succeeds, then
// the client makes the store path unwritable before returning a DNS error, so the
// event's own flush fails with a real WriteReason. Only OnFailureWrite can route
// the "session log unwritable" notice; removing that field from the dispatch
// turn.Deps literal (it has no runner default — it stays nil) drops the notice and
// fails this test. Pins the write-failure-handler wiring.
func TestTurnController_PreStreamTransportWriteFailureRoutesNotice(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	dir := t.TempDir()
	store := storeAt(t, filepath.Join(dir, "session.json"), "turn-prestream-write-fail", "/proj")
	dnsErr := &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true}
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		// The start flush has already succeeded; make the parent path a file so the
		// provider_request_failed flush fails with a real (non-ReasonNone) reason.
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("remove session dir: %v", err)
		}
		if err := os.WriteFile(dir, []byte("not a dir"), 0o600); err != nil {
			t.Fatalf("replace session dir with file: %v", err)
		}
		return provider.Response{}, dnsErr
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	var routed bool
	for _, n := range surface.noticeList() {
		if strings.HasPrefix(n, "session log unwritable —") {
			routed = true
		}
	}
	if !routed {
		t.Fatalf("notices = %v, want a \"session log unwritable\" notice routed through OnFailureWrite", surface.noticeList())
	}
	if surface.finalizeCount() != 0 {
		t.Fatalf("FinalizeStream called %d times, want 0 on a pre-stream transport failure", surface.finalizeCount())
	}
}

// --- provider-scoped auth dispatch ------------------------------------------

// A submitted openai-chatgpt turn with no usable session commits the lazy
// missing-session notice (naming the provider and both recovery commands) as an
// in-place transcript line, never constructs the ChatGPT adapter, and never falls
// back to the OpenAI Platform client — pinning Done-when 1 and 3 at the controller.
func TestTurnController_ChatGPTMissingSessionCommitsLazyNoticeNoFallback(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		t.Fatal("ChatGPT adapter constructed despite no usable session")
		return nil
	})()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		t.Fatal("OpenAI Platform client built for an openai-chatgpt turn (silent provider switch)")
		return nil
	})()

	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		return authstate.Session{}, openaiauth.ErrNoSession
	}}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai-chatgpt", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed = %v, want exactly one missing-session notice", committed)
	}
	for _, want := range []string{"OpenAI ChatGPT", "codemeld auth login openai-chatgpt", "codemeld auth status"} {
		if !strings.Contains(committed[0], want) {
			t.Fatalf("missing-session notice = %q, want it to contain %q", committed[0], want)
		}
	}
	if auth.refreshCount() != 0 {
		t.Fatalf("RefreshNow called %d times, want 0 (nothing to refresh)", auth.refreshCount())
	}
	if surface.finalizeCount() != 0 {
		t.Fatal("FinalizeStream called for a missing-session turn")
	}
}

// A non-ChatGPT turn never touches the ChatGPT session resolver, so the
// missing-session guidance stays lazy — it is not produced while using the OpenAI
// Platform provider (Done-when 2).
func TestTurnController_PlatformTurnDoesNotConsultChatGPTAuth(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		t.Fatal("ChatGPT adapter constructed for an OpenAI Platform turn")
		return nil
	})()

	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		t.Fatal("ChatGPT session resolver consulted for an OpenAI Platform turn")
		return authstate.Session{}, nil
	}}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if auth.ensureCount() != 0 {
		t.Fatalf("EnsureFreshSession called %d times for a Platform turn, want 0", auth.ensureCount())
	}
	if len(surface.committedList()) != 0 {
		t.Fatalf("committed = %v, want no ChatGPT notice on a Platform turn", surface.committedList())
	}
}

// A ChatGPT turn proactively refreshes the stored session before constructing the
// adapter, and the adapter is built from the resolved (refreshed) credentials —
// pinning Step 2's "load session, proactively refresh, then construct the adapter".
func TestTurnController_ChatGPTProactiveRefreshBeforeClientConstruction(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotConfig provider.ChatGPTClientConfig
	var constructed int32
	var ensuredBeforeConstruct bool
	inner := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("hi"), finishChunk("stop"))}, nil
	}}
	defer swapChatGPTProviderClient(func(cfg provider.ChatGPTClientConfig) provider.Client {
		atomic.AddInt32(&constructed, 1)
		gotConfig = cfg
		return inner
	})()

	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		if atomic.LoadInt32(&constructed) == 0 {
			ensuredBeforeConstruct = true
		}
		return authstate.Session{AccessToken: "fresh-token", AccountID: "acct-1"}, nil
	}}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai-chatgpt", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if auth.ensureCount() != 1 {
		t.Fatalf("EnsureFreshSession called %d times, want 1 proactive refresh", auth.ensureCount())
	}
	if !ensuredBeforeConstruct {
		t.Fatal("ChatGPT adapter constructed before the proactive refresh resolved the session")
	}
	if gotConfig.AccessToken != "fresh-token" || gotConfig.AccountID != "acct-1" {
		t.Fatalf("adapter config = %+v, want the proactively-refreshed session credentials", gotConfig)
	}
	if surface.deltaText() != "hi" || surface.finalizeCount() != 1 {
		t.Fatalf("ChatGPT turn did not complete: delta=%q finalize=%d", surface.deltaText(), surface.finalizeCount())
	}
}

// A ChatGPT provider 401 triggers exactly one reactive refresh-and-retry: the adapter
// is rebuilt with the rotated token and the retried request succeeds. Pins Done-when 5.
func TestTurnController_ChatGPTReactiveRefreshRetriesOnceOn401(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var configs []provider.ChatGPTClientConfig
	var round int32
	httpErr := &provider.HTTPError{Status: 401, Surface: "provider OpenAI ChatGPT returned HTTP 401: "}
	defer swapChatGPTProviderClient(func(cfg provider.ChatGPTClientConfig) provider.Client {
		configs = append(configs, cfg)
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			if atomic.AddInt32(&round, 1) == 1 {
				return provider.Response{}, httpErr
			}
			return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
		}}
	})()

	auth := &fakeChatGPTAuth{
		ensure: func(context.Context, string) (authstate.Session, error) {
			return authstate.Session{AccessToken: "stale", AccountID: "acct"}, nil
		},
		refresh: func(context.Context, string) (authstate.Session, error) {
			return authstate.Session{AccessToken: "rotated", AccountID: "acct"}, nil
		},
	}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai-chatgpt", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if auth.refreshCount() != 1 {
		t.Fatalf("RefreshNow called %d times, want exactly 1 reactive refresh on 401", auth.refreshCount())
	}
	if len(configs) != 2 {
		t.Fatalf("adapter constructed %d times, want 2 (initial + one retry)", len(configs))
	}
	if configs[1].AccessToken != "rotated" {
		t.Fatalf("retry adapter token = %q, want the rotated token from RefreshNow", configs[1].AccessToken)
	}
	if surface.deltaText() != "ok" {
		t.Fatalf("streamed text = %q, want the retried turn's reply", surface.deltaText())
	}
	if len(surface.committedList()) != 0 {
		t.Fatalf("committed = %v, want none after a successful retry", surface.committedList())
	}
}

// A reactive refresh that itself fails surfaces the safe, credential-free
// refresh-failure notice (no token leaked) and makes no second retry — the still
// one-shot budget. Pins Done-when 5's "surfaces a safe error if still rejected".
func TestTurnController_ChatGPTReactiveRefreshFailureSurfacesSafeNotice(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var built int32
	httpErr := &provider.HTTPError{Status: 403, Surface: "provider OpenAI ChatGPT returned HTTP 403: "}
	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		atomic.AddInt32(&built, 1)
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, httpErr
		}}
	})()

	auth := &fakeChatGPTAuth{
		ensure: func(context.Context, string) (authstate.Session, error) {
			return authstate.Session{AccessToken: "secret-token", AccountID: "acct"}, nil
		},
		refresh: func(context.Context, string) (authstate.Session, error) {
			return authstate.Session{}, &openaiauth.RefreshFailure{Status: 400}
		},
	}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai-chatgpt", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if auth.refreshCount() != 1 {
		t.Fatalf("RefreshNow called %d times, want exactly 1 (one-shot budget)", auth.refreshCount())
	}
	if atomic.LoadInt32(&built) != 1 {
		t.Fatalf("ChatGPT adapter built %d times, want 1 (no retry adapter after a failed refresh)", built)
	}
	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed = %v, want exactly one refresh-failure notice", committed)
	}
	if !strings.Contains(committed[0], "OpenAI ChatGPT") || !strings.Contains(committed[0], "codemeld auth") {
		t.Fatalf("refresh-failure notice = %q, want a provider-named, actionable message", committed[0])
	}
	if strings.Contains(committed[0], "secret-token") {
		t.Fatalf("refresh-failure notice = %q leaked a credential", committed[0])
	}
}

// A ChatGPT provider 401 whose retried request is ALSO rejected (after a successful
// reactive refresh) holds the one-shot budget: exactly one refresh, two adapters
// (the second on the rotated token), then the still-rejected request surfaces as a
// safe, provider-named provider error — one committed notice, no credential leaked,
// no finalize. Pins Done-when 5's "surfaces a safe error if still rejected" for the
// producer-reachable persistent-401-after-refresh branch the other reactive-refresh
// tests (successful retry, failed refresh) leave uncovered.
func TestTurnController_ChatGPTReactiveRefreshStillRejectedSurfacesSafeError(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var configs []provider.ChatGPTClientConfig
	httpErr := &provider.HTTPError{
		Status:  401,
		Surface: "provider OpenAI ChatGPT returned HTTP 401: ",
		Body:    `{"error":{"message":"Unauthorized"}}`,
	}
	defer swapChatGPTProviderClient(func(cfg provider.ChatGPTClientConfig) provider.Client {
		configs = append(configs, cfg)
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, httpErr
		}}
	})()

	auth := &fakeChatGPTAuth{
		ensure: func(context.Context, string) (authstate.Session, error) {
			return authstate.Session{AccessToken: "seeded-access", AccountID: "seeded-acct"}, nil
		},
		refresh: func(context.Context, string) (authstate.Session, error) {
			return authstate.Session{AccessToken: "rotated-access", AccountID: "seeded-acct"}, nil
		},
	}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai-chatgpt", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if auth.refreshCount() != 1 {
		t.Fatalf("RefreshNow called %d times, want exactly 1 (the one-shot budget holds when the retry is still rejected)", auth.refreshCount())
	}
	if len(configs) != 2 {
		t.Fatalf("adapter constructed %d times, want 2 (initial + one retry, no third attempt)", len(configs))
	}
	if configs[1].AccessToken != "rotated-access" {
		t.Fatalf("retry adapter token = %q, want the rotated token from RefreshNow", configs[1].AccessToken)
	}
	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed = %v, want exactly one provider-error notice for the still-rejected request", committed)
	}
	if !strings.Contains(committed[0], "openai-chatgpt") || !strings.Contains(committed[0], "401") {
		t.Fatalf("committed notice = %q, want a safe provider-named HTTP 401 surface", committed[0])
	}
	for _, secret := range []string{"seeded-access", "rotated-access", "seeded-acct"} {
		if strings.Contains(committed[0], secret) {
			t.Fatalf("committed notice = %q leaked credential %q", committed[0], secret)
		}
	}
	if surface.finalizeCount() != 0 {
		t.Fatalf("FinalizeStream called %d times, want 0 — a still-rejected request must not finalize a reply", surface.finalizeCount())
	}
}

// OpenAI Platform applies the OPENAI_API_KEY-over-configured-key precedence
// when constructing the turn client, while a custom provider keeps its configured
// key — pinning Step 1's "OpenAI Platform uses API-key auth" without disturbing
// custom OpenAI-compatible providers.
func TestTurnController_PlatformPrefersOpenAIAPIKeyEnv(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	t.Setenv("OPENAI_API_KEY", "sk-env")

	var gotCfg provider.ClientConfig
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		gotCfg = cfg
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
		}}
	})()

	// providerCache configures provider.openai.api_key = sk-test; the env var wins.
	ctl := newTurnController(context.Background(), &recordingSurface{}, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if gotCfg.AuthValue != "Bearer sk-env" {
		t.Fatalf("Platform auth value = %q, want Bearer sk-env (OPENAI_API_KEY precedence)", gotCfg.AuthValue)
	}
}

// acmeProviderCache builds a cache with a single non-Platform, non-built-in
// configured provider (AuthKindConfigured) carrying a distinct base URL, api key,
// and custom auth header, so a dispatch test can prove a custom provider keeps its
// configured auth — never the OpenAI Platform OPENAI_API_KEY override or the ChatGPT
// session resolver.
func acmeProviderCache(t *testing.T) *config.Cache {
	t.Helper()
	composed := map[string]any{
		"provider": map[string]any{
			"acme": map[string]any{
				"base_url": "https://acme.example/v1",
				"api_key":  "acme-secret-key",
				"models":   []string{"acme-large"},
				"auth_header": map[string]any{
					"name":  "X-Acme-Key",
					"value": "Token {api_key}",
				},
			},
		},
	}
	cache, err := config.NewCache(composed, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache
}

// A turn dispatched for a configured custom provider keeps that provider's configured
// auth (base URL, custom auth header, api-key-substituted value) and consults neither
// the OPENAI_API_KEY Platform override nor the ChatGPT session resolver, with no
// ChatGPT notice committed. Pins Step 1's "custom providers use their configured auth
// unchanged" and Done-when 2's "ChatGPT missing-session guidance is not shown while
// using custom providers" for the AuthKindConfigured branch the Platform test does not
// exercise.
func TestTurnController_CustomProviderKeepsConfiguredAuth(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	t.Setenv("OPENAI_API_KEY", "sk-env-should-be-ignored")

	var gotCfg provider.ClientConfig
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		gotCfg = cfg
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
		}}
	})()
	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		t.Error("ChatGPT adapter built for a custom-provider turn (ChatGPT auth applied to a configured provider)")
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, nil
		}}
	})()

	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		t.Error("ChatGPT session resolver consulted for a custom-provider turn")
		return authstate.Session{}, nil
	}}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, acmeProviderCache(t), turnSelection("acme", "acme-large", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if gotCfg.Name != "acme" {
		t.Fatalf("client provider name = %q, want acme", gotCfg.Name)
	}
	if gotCfg.BaseURL != "https://acme.example/v1" {
		t.Fatalf("client base URL = %q, want the configured acme base URL", gotCfg.BaseURL)
	}
	if gotCfg.AuthHeader != "X-Acme-Key" {
		t.Fatalf("auth header = %q, want the configured X-Acme-Key (not the Platform Authorization default)", gotCfg.AuthHeader)
	}
	if gotCfg.AuthValue != "Token acme-secret-key" {
		t.Fatalf("auth value = %q, want the configured api key (not OPENAI_API_KEY)", gotCfg.AuthValue)
	}
	if auth.ensureCount() != 0 {
		t.Fatalf("EnsureFreshSession called %d times for a custom-provider turn, want 0", auth.ensureCount())
	}
	if len(surface.committedList()) != 0 {
		t.Fatalf("committed = %v, want no ChatGPT notice on a custom-provider turn", surface.committedList())
	}
}

// A selected OpenAI Platform provider whose credential is rejected (HTTP 401) fails
// THAT turn as a safe, provider-named in-place error and never silently switches to
// another provider: the ChatGPT adapter is never constructed and the ChatGPT session
// resolver is never consulted. The existing no-fallback tests pin only the
// openai-chatgpt -> openai direction (a missing/failed ChatGPT session never builds
// the Platform client); this pins the openai -> {openai-chatgpt, ...} direction on a
// rejected credential. A custom/OpenRouter rejected credential takes the identical
// AuthKindConfigured dispatch path (newTurnProviderClient -> HTTPError commit), so the
// same guarantee holds for those providers.
func TestTurnController_PlatformCredentialRejectedDoesNotSwitchProviders(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	httpErr := &provider.HTTPError{
		Status:  401,
		Body:    `{"error":{"message":"Incorrect API key provided"}}`,
		Surface: `provider openai returned HTTP 401: {"error":{"message":"Incorrect API key provided"}}`,
	}
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{}, httpErr
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		t.Fatal("ChatGPT adapter built after an OpenAI Platform credential rejection (silent provider switch)")
		return nil
	})()

	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		t.Fatal("ChatGPT session resolver consulted after an OpenAI Platform credential rejection")
		return authstate.Session{}, nil
	}}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want exactly 1 (no retry, no switch)", client.callCount())
	}
	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed = %v, want exactly one provider-named error line", committed)
	}
	if !strings.Contains(committed[0], "openai") || !strings.Contains(committed[0], "401") {
		t.Fatalf("committed error = %q, want a provider-named HTTP 401 surface", committed[0])
	}
	if auth.ensureCount() != 0 {
		t.Fatalf("EnsureFreshSession called %d times after a Platform rejection, want 0", auth.ensureCount())
	}
	if surface.finalizeCount() != 0 {
		t.Fatalf("FinalizeStream called %d times, want 0 on a rejected credential", surface.finalizeCount())
	}
}

// A selected configured (AuthKindConfigured) provider whose credential is rejected
// (HTTP 401) fails THAT turn as a safe, provider-named in-place error built with the
// configured provider's own auth, and never switches providers: the client is built
// for acme alone, called once, the ChatGPT adapter is never constructed, and the
// ChatGPT session resolver is never consulted. The Platform rejection test above pins
// the openai -> {...} direction through the AuthKindPlatform branch; this pins the same
// no-switch guarantee for the AuthKindConfigured dispatch path (custom/OpenRouter
// providers), which the Platform-only test does not exercise.
func TestTurnController_ConfiguredProviderCredentialRejectedDoesNotSwitchProviders(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	t.Setenv("OPENAI_API_KEY", "sk-env-should-be-ignored")

	httpErr := &provider.HTTPError{
		Status:  401,
		Body:    `{"error":{"message":"invalid api key"}}`,
		Surface: `provider acme returned HTTP 401: {"error":{"message":"invalid api key"}}`,
	}
	var gotCfg provider.ClientConfig
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{}, httpErr
	}}
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		gotCfg = cfg
		return client
	})()
	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		t.Fatal("ChatGPT adapter built after a configured-provider credential rejection (silent provider switch)")
		return nil
	})()

	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		t.Fatal("ChatGPT session resolver consulted after a configured-provider credential rejection")
		return authstate.Session{}, nil
	}}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, acmeProviderCache(t), turnSelection("acme", "acme-large", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if gotCfg.Name != "acme" {
		t.Fatalf("client provider name = %q, want acme (the selected configured provider, not a fallback)", gotCfg.Name)
	}
	if gotCfg.BaseURL != "https://acme.example/v1" {
		t.Fatalf("client base URL = %q, want the configured acme base URL", gotCfg.BaseURL)
	}
	if gotCfg.AuthHeader != "X-Acme-Key" {
		t.Fatalf("auth header = %q, want the configured X-Acme-Key (not the Platform Authorization default)", gotCfg.AuthHeader)
	}
	if gotCfg.AuthValue != "Token acme-secret-key" {
		t.Fatalf("auth value = %q, want the configured api key (not OPENAI_API_KEY)", gotCfg.AuthValue)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider client called %d times, want exactly 1 (no retry, no switch)", client.callCount())
	}
	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed = %v, want exactly one provider-named error line", committed)
	}
	if !strings.Contains(committed[0], "acme") || !strings.Contains(committed[0], "401") {
		t.Fatalf("committed error = %q, want a provider-named HTTP 401 surface", committed[0])
	}
	if auth.ensureCount() != 0 {
		t.Fatalf("EnsureFreshSession called %d times after a configured-provider rejection, want 0", auth.ensureCount())
	}
	if surface.finalizeCount() != 0 {
		t.Fatalf("FinalizeStream called %d times, want 0 on a rejected credential", surface.finalizeCount())
	}
}

// TestTurnController_UserDeniedToolCallCommitsDenialLineAndSkipsCompletion pins the wired TUI
// controller: a user-denied tool call commits a friendly, in-place denial line (through Notice →
// CommitProviderError) that names the refused command and reason without exposing the raw envelope
// JSON, and the user-denial stop still gates the first-turn completion hook off (no follow-up title
// provider round). It complements the turn-loop unit tests with the real production surface/dispatcher
// wiring.
func TestTurnController_UserDeniedToolCallCommitsDenialLineAndSkipsCompletion(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			t.Errorf("unexpected title request after a user denial")
			return titleCompletion("should not be generated"), nil
		}
		return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"rm -rf /"}`)))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cwd := t.TempDir()
	home := t.TempDir()
	store := mkStore(t)
	store.Append(sessions.Message{Role: "user", Content: sessions.TextContent("run the command"), Timestamp: testStart})
	app := tui.New(nil)
	app.SetActiveStore(store)
	cache := providerCache(t, cwd)

	authorizer := newProductionAuthorizer(app, cache, permissions.NewTurnCache(),
		newPromptGateBuilder(func(tui.PromptRequest) (tui.PromptDecision, error) {
			return tui.PromptDecision{Option: tui.OptionDeny, DenyEnvelope: permissions.BuildDenyEnvelope("out of scope")}, nil
		}), home, cwd, mode.NewActiveState(mode.Build, mode.SourceDefault))

	run := &fakeDispatchRunner{}
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, cache,
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, authorizer)
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, authorizer, home, cwd, func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))
	ctl.setTurnCompleteHook(newTitleOnComplete(app, func(providerID, modelID string) []string {
		return cache.SelectableCatalog().SupportedEffort(providerID, modelID)
	}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if got := client.callCount(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (a user denial must not trigger a follow-up title request)", got)
	}
	if run.callCount() != 0 {
		t.Fatalf("runner Exec calls = %d, want 0 (a denied command must not execute)", run.callCount())
	}
	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed lines = %v, want exactly one denial line", committed)
	}
	line := committed[0]
	if !strings.Contains(line, "Denied") || !strings.Contains(line, "rm -rf /") || !strings.Contains(line, "out of scope") {
		t.Fatalf("denial line = %q, want a friendly line naming the refused command and reason", line)
	}
	if strings.Contains(line, "denied_by") || strings.Contains(line, "{") {
		t.Fatalf("denial line = %q, leaked the raw deny-envelope JSON", line)
	}
	if got := surface.outcomeList(); !slices.Equal(got, []string{"turn_failed"}) {
		t.Fatalf("TurnEnded outcomes = %v, want exactly one turn_failed after a permission denial", got)
	}
}

// TestBuildTurnClient_FreeFunctionContract pins the extracted free function
// buildTurnClient the headless run reuses: a Platform provider builds a client
// from the catalog entry through the reassignable seam, a ChatGPT-session selection
// with no bound auth resolver reports no client, and an unknown provider reports no
// client. The turnController.buildClient tests above already cover the full credential
// branching through the method; this pins the same contract at the free function the
// headless driver calls directly (it has no turnController).
func TestBuildTurnClient_FreeFunctionContract(t *testing.T) {
	t.Run("platform provider builds a client from the catalog entry", func(t *testing.T) {
		var gotCfg provider.ClientConfig
		defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
			gotCfg = cfg
			return &stubTurnClient{}
		})()
		client, ok := buildTurnClient("openai", provider.AuthKindPlatform, providerCache(t, t.TempDir()), nil, "")
		if !ok || client == nil {
			t.Fatalf("buildTurnClient = (%v, %v), want a client", client, ok)
		}
		if gotCfg.Name != "openai" || gotCfg.BaseURL != "https://api.openai.com/v1" {
			t.Fatalf("client config = %+v, want the openai catalog entry", gotCfg)
		}
	})
	t.Run("the effective attribution setting reaches the provider config", func(t *testing.T) {
		for _, want := range []bool{true, false} {
			t.Run(fmt.Sprintf("%v", want), func(t *testing.T) {
				var gotCfg provider.ClientConfig
				defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
					gotCfg = cfg
					return &stubTurnClient{}
				})()
				cache, err := config.NewCache(map[string]any{
					"attribution": want,
					"provider": map[string]any{
						"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "api_key": "sk-test"},
					},
				}, t.TempDir(), nil)
				if err != nil {
					t.Fatalf("config.NewCache: %v", err)
				}
				if _, ok := buildTurnClient("openrouter", provider.AuthKindConfigured, cache, nil, ""); !ok {
					t.Fatal("buildTurnClient reported no client")
				}
				if gotCfg.Attribution != want {
					t.Fatalf("ClientConfig.Attribution = %v, want the cache value %v", gotCfg.Attribution, want)
				}
			})
		}
	})
	t.Run("chatgpt session with no bound auth reports no client", func(t *testing.T) {
		if client, ok := buildTurnClient("openai-chatgpt", provider.AuthKindChatGPTSession, providerCache(t, t.TempDir()), nil, ""); ok || client != nil {
			t.Fatalf("buildTurnClient(chatgpt, nil auth) = (%v, %v), want (nil, false)", client, ok)
		}
	})
	t.Run("unknown configured provider reports no client", func(t *testing.T) {
		if client, ok := buildTurnClient("ghost", provider.AuthKindConfigured, providerCache(t, t.TempDir()), nil, ""); ok || client != nil {
			t.Fatalf("buildTurnClient(unknown) = (%v, %v), want (nil, false)", client, ok)
		}
	})
}

// Terminal test: a prompt submitted with provider openai-chatgpt selected runs
// through the REAL StartTUI turn setup — the production controller resolves the
// built-in catalog entry, loads the stored ChatGPT session through the wired
// openaiauth flow, and constructs the Responses adapter from those credentials —
// against a fake adapter (no network). The OpenAI Platform client is never built, so a
// ChatGPT selection cannot silently switch providers. Pins the end-to-end provider-scoped auth wiring
// at the production entrypoint.
func TestStartTUI_ChatGPTPromptRunsThroughRealTurnSetup(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	var gotCfg provider.ChatGPTClientConfig
	var built int32
	defer swapChatGPTProviderClient(func(cfg provider.ChatGPTClientConfig) provider.Client {
		atomic.AddInt32(&built, 1)
		gotCfg = cfg
		return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Stream: newStream(contentChunk("chatgpt-reply"), finishChunk("stop"))}, nil
		}}
	})()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		t.Fatal("OpenAI Platform client built for an openai-chatgpt turn (silent provider switch)")
		return nil
	})()

	home := t.TempDir()
	writeChatGPTSession(t, home, "stored-access", "stored-acct")

	store := mkStore(t)
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the ChatGPT turn entrypoint is not wired")
	}
	turns.Wait()

	if atomic.LoadInt32(&built) != 2 {
		t.Fatalf("ChatGPT adapter built %d times, want 2 (the real turn setup plus the best-effort title request)", built)
	}
	if gotCfg.AccessToken != "stored-access" || gotCfg.AccountID != "stored-acct" {
		t.Fatalf("adapter credentials = %+v, want the stored ChatGPT session", gotCfg)
	}
}

// Terminal test: a prompt submitted with openai-chatgpt selected and
// NO stored session runs through the REAL StartTUI turn setup — the wired openaiauth flow
// resolves no usable session offline, so the turn commits the lazy, provider-scoped
// missing-session notice to the transcript without constructing the ChatGPT adapter or
// silently falling back to the OpenAI Platform client. The controller-level test pins this
// against a fakeChatGPTAuth; this proves the same lazy/no-fallback behavior through the
// assembled app and the production session resolver.
func TestStartTUI_ChatGPTMissingSessionLazyNoticeNoFallback(t *testing.T) {
	ctx := context.Background()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	defer swapChatGPTProviderClient(func(provider.ChatGPTClientConfig) provider.Client {
		t.Fatal("ChatGPT adapter constructed despite no usable session")
		return nil
	})()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		t.Fatal("OpenAI Platform client built for an openai-chatgpt turn (silent provider switch)")
		return nil
	})()

	// home carries no auth.openai-chatgpt session, so the wired openaiauth flow resolves
	// none offline — nothing to refresh, no network.
	home := t.TempDir()
	store := mkStore(t)
	result := &BootstrapResult{
		Home:      home,
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai-chatgpt", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
	}
	app, restore := startCaptured(t, ctx, result, io.Discard)
	defer restore()

	if !app.SubmitInput("hello") {
		t.Fatal("wired submit rejected a plain prompt; the ChatGPT turn entrypoint is not wired")
	}
	turns.Wait()

	// The missing-session guidance is lazy: it is committed only now, on submission of an
	// openai-chatgpt turn, and is provider-scoped — naming the provider and both auth commands.
	transcript := app.TranscriptText()
	for _, want := range []string{"OpenAI ChatGPT", "codemeld auth login openai-chatgpt", "codemeld auth status"} {
		if !strings.Contains(transcript, want) {
			t.Fatalf("transcript missing missing-session clause %q\n--- transcript ---\n%s", want, transcript)
		}
	}
}

// --- cross-layer ChatGPT credential-leak regression -------------------------

// chatGPTEchoErrorTransport is a no-network http.RoundTripper that answers the
// ChatGPT adapter's Responses request with a non-2xx body echoing back the
// Authorization bearer token and ChatGPT-Account-ID header the adapter sent — the
// worst case of a provider that reflects credentials in its error. It never dials, so
// the adapter's pinned chatgpt.com origin (which the ChatGPTClientConfig.HTTPClient
// seam keeps fixed) is honored with zero network egress while the real adapter redaction
// runs over a body that genuinely contains the live, production-resolved credentials.
type chatGPTEchoErrorTransport struct{ status int }

func (tr chatGPTEchoErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	body := fmt.Sprintf(
		`{"error":{"message":"upstream rejected %s for account %s","type":"server_error"}}`,
		req.Header.Get("Authorization"), req.Header.Get("ChatGPT-Account-ID"))
	return &http.Response{
		StatusCode: tr.status,
		Status:     http.StatusText(tr.status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

// diskProviderRequestFailed reloads the flushed session file and returns its single
// provider_request_failed payload, so the leak assertions run against the bytes that
// were actually persisted rather than only the in-memory store.
func diskProviderRequestFailed(t *testing.T, store *sessions.Store) events.ProviderRequestFailed {
	t.Helper()
	sess, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed session %s: %v", store.Path(), err)
	}
	for _, r := range sess.Records {
		e, ok := r.(sessions.Event)
		if !ok || e.Kind != events.KindProviderRequestFailed {
			continue
		}
		var p events.ProviderRequestFailed
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatalf("unmarshal provider_request_failed payload: %v", err)
		}
		return p
	}
	t.Fatalf("no provider_request_failed event persisted to %s", store.Path())
	return events.ProviderRequestFailed{}
}

// A single ChatGPT turn whose provider error echoes the seeded credentials must
// leak none of them across the three failure surfaces that no existing single test
// spans together: the committed provider-error transcript line, the raw persisted
// session JSON, and the persisted provider_request_failed event detail/payload. It
// drives the REAL ChatGPT adapter (so the real redaction runs) over a no-network
// transport that reflects the production-resolved access token and account id back in
// a 500 body, through the provider-scoped dispatch + turn.Run path that commits the notice and
// persists the event. The dependency tests that already cover origin-pinned egress,
// offline `auth status`, custom/OpenAI-compatible provider isolation, refresh-error
// redaction, adapter-level body redaction, and CLI status redaction are deliberately
// not duplicated here.
func TestTurnController_ChatGPTHTTPFailureRedactsCredentialsAcrossLayers(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	// Step 1: distinctive seeded ChatGPT credentials. Each carries a unique ZZ…ZZ
	// sentinel so any partial leak is unambiguous and cannot collide with ordinary
	// transcript or JSON text.
	const (
		accessToken  = "sk-chatgpt-ZZACCESSZZ-9f3a1c7e2b4d"
		refreshToken = "rt-ZZREFRESHZZ-4d8e6a0b1f"
		accountID    = "acct-ZZACCOUNTZZ-77c2e9"
	)
	authHeaderValue := "Bearer " + accessToken
	// Forbidden across every surface: whole secrets, the auth-header-shaped value, and
	// each distinctive fragment that would expose partial (non-whole-token) leakage.
	forbidden := []string{
		accessToken, refreshToken, accountID, authHeaderValue,
		"ZZACCESSZZ", "ZZREFRESHZZ", "ZZACCOUNTZZ",
	}

	// The real ChatGPT adapter, built from the production-resolved session credentials,
	// over the no-network echo transport. Swapping only injects the transport; the
	// AccessToken/AccountID flow in from the resolved session exactly as in production.
	defer swapChatGPTProviderClient(func(cfg provider.ChatGPTClientConfig) provider.Client {
		cfg.HTTPClient = &http.Client{Transport: chatGPTEchoErrorTransport{status: http.StatusInternalServerError}}
		return provider.NewChatGPTClient(cfg)
	})()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client {
		t.Fatal("OpenAI Platform client built for an openai-chatgpt turn (silent provider switch)")
		return nil
	})()

	// Step 2: drive one ChatGPT turn through the production dispatch seam. The resolver
	// returns a session carrying all seeded secrets; only AccessToken and AccountID
	// reach the adapter (chatGPTConfig), and the refresh token must never surface in any
	// downstream turn artifact.
	auth := &fakeChatGPTAuth{ensure: func(context.Context, string) (authstate.Session, error) {
		return authstate.Session{AccessToken: accessToken, RefreshToken: refreshToken, AccountID: accountID}, nil
	}}
	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai-chatgpt", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setChatGPTAuth(auth, "/settings.yaml")

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	// The failure path must actually have run, or the absence assertions below are
	// vacuous: exactly one committed provider-error line and a persisted
	// provider_request_failed{http, http_error}.
	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed = %v, want exactly one provider-error line for the HTTP 500", committed)
	}
	notice := committed[0]
	if !strings.Contains(notice, "returned HTTP 500") || !strings.Contains(notice, "upstream rejected") {
		t.Fatalf("committed notice = %q, want the HTTP 500 surface carrying the safe body sentence", notice)
	}

	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read persisted session %s: %v", store.Path(), err)
	}
	rawJSON := string(raw)

	prf := diskProviderRequestFailed(t, store)
	if prf.Phase != "http" || prf.Reason != "http_error" {
		t.Fatalf("persisted provider_request_failed (phase, reason) = (%q, %q), want (http, http_error)", prf.Phase, prf.Reason)
	}
	if prf.Provider != "openai-chatgpt" {
		t.Fatalf("provider_request_failed.provider = %q, want openai-chatgpt", prf.Provider)
	}

	// Step 3: the seeded values and fragments must appear in NONE of the committed
	// notice, the raw persisted session JSON, or the persisted event detail/payload.
	payloadText := fmt.Sprintf("%+v", prf)
	for _, secret := range forbidden {
		if strings.Contains(notice, secret) {
			t.Fatalf("committed notice leaked %q: %s", secret, notice)
		}
		if strings.Contains(rawJSON, secret) {
			t.Fatalf("persisted session JSON leaked %q", secret)
		}
		if strings.Contains(prf.ErrorDetail, secret) || strings.Contains(payloadText, secret) {
			t.Fatalf("provider_request_failed payload leaked %q: %s", secret, prf.ErrorDetail)
		}
	}

	// The credentials really were echoed and scrubbed, so the absence above is a
	// redaction result rather than a vacuous no-echo pass.
	if !strings.Contains(prf.ErrorDetail, "[REDACTED]") {
		t.Fatalf("provider_request_failed.error_detail did not redact the echoed credentials: %s", prf.ErrorDetail)
	}
	if !strings.Contains(rawJSON, "[REDACTED]") {
		t.Fatal("persisted session JSON has no [REDACTED] marker; the echoed credentials were not scrubbed before persistence")
	}
	if surface.finalizeCount() != 0 {
		t.Fatalf("FinalizeStream called %d times, want 0 on an HTTP failure", surface.finalizeCount())
	}
}

func diskTurnTerminals(t *testing.T, store *sessions.Store) []events.TurnTerminal {
	t.Helper()
	sess, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed session %s: %v", store.Path(), err)
	}
	var out []events.TurnTerminal
	for _, r := range sess.Records {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindTurnTerminal {
			continue
		}
		var p events.TurnTerminal
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("unmarshal turn_terminal: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func TestTurnController_UnexplainedFailureCommitsSessionDoctorRecovery(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "", "do", "{}")))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed errors = %v, want exactly one recovery line", committed)
	}
	id := store.SessionID()
	if !strings.Contains(committed[0], id) {
		t.Fatalf("recovery line %q does not name session %q", committed[0], id)
	}
	if !strings.Contains(committed[0], "codemeld sessions doctor "+id) {
		t.Fatalf("recovery line %q does not name the session's doctor command", committed[0])
	}
	if surface.clearCount() == 0 {
		t.Fatal("in-flight indicator not cleared after an unexplained failure")
	}
	if got := surface.outcomeList(); len(got) != 1 || got[0] != "turn_failed" {
		t.Fatalf("turn outcomes = %v, want [turn_failed]", got)
	}
	if ctl.busy() {
		t.Fatal("controller still busy after the failed turn; the next prompt would be refused")
	}
	terminals := diskTurnTerminals(t, store)
	if len(terminals) != client.callCount() {
		t.Fatalf("persisted turn_terminal events = %d, want one per provider attempt (%d)", len(terminals), client.callCount())
	}
	for i, got := range terminals {
		if got.Outcome != events.TurnOutcomeToolAssemblyFailed || got.DispatchStarted {
			t.Fatalf("terminal %d = (%q, %t), want (%q, false)", i, got.Outcome, got.DispatchStarted, events.TurnOutcomeToolAssemblyFailed)
		}
	}
}

// The real dispatcher's Plan refuses `bash` for the parallel structured-read optimization
// and records bash/not_allowlisted before routing the call serially, so this fixture needs
// no stub to produce that refusal ahead of the shell runner's failure.
func TestTurnController_PostPlanShellFailureExplainsSafelyAndDurably(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if isTitleRequest(req) {
			t.Error("unexpected title request after a dispatch failure")
			return titleCompletion("should not be generated"), nil
		}
		return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"cat /etc/shadow"}`)))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	runnerErr := errors.New("fork/exec /bin/sh: token sk-live-abcdef rejected")
	run := &fakeDispatchRunner{err: runnerErr}
	store := mkStore(t)
	cache := providerCache(t, t.TempDir())
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, cache,
		turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, &recordingAuthorizer{decision: allow()})
	ctl.setToolDispatcher(newProductionToolDispatcher(tools.NewRegistry(), run, &recordingAuthorizer{decision: allow()},
		t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, cache.MaxToolOutputBytes(), securitystate.Policy{}))

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	turns.Wait()

	if run.callCount() != 1 {
		t.Fatalf("runner Exec calls = %d, want exactly 1 (a started dispatch is never replayed)", run.callCount())
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (the round is not re-issued)", client.callCount())
	}

	refusals := diskStructuredReadRefusals(t, store)
	if len(refusals) != 1 || refusals[0].ToolName != "bash" || refusals[0].Reason != "not_allowlisted" {
		t.Fatalf("structured_read_refused records = %+v, want one bash/not_allowlisted", refusals)
	}

	terminals := diskTurnTerminals(t, store)
	if len(terminals) != 1 {
		t.Fatalf("persisted turn_terminal events = %d, want 1", len(terminals))
	}
	got := terminals[0]
	if got.Outcome != events.TurnOutcomeDispatchFailed || !got.DispatchStarted {
		t.Fatalf("(outcome, dispatch_started) = (%q, %t), want (%q, true)", got.Outcome, got.DispatchStarted, events.TurnOutcomeDispatchFailed)
	}
	if got.FailureReason != events.DispatchReasonToolDispatchFailed || got.FailedTool != "bash" {
		t.Fatalf("(failure_reason, failed_tool) = (%q, %q), want (%q, \"bash\")", got.FailureReason, got.FailedTool, events.DispatchReasonToolDispatchFailed)
	}

	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed lines = %v, want exactly one dispatch-failure line", committed)
	}
	line := committed[0]
	for _, want := range []string{"bash", events.DispatchReasonToolDispatchFailed, "codemeld sessions doctor " + store.SessionID()} {
		if !strings.Contains(line, want) {
			t.Fatalf("failure line %q is missing %q", line, want)
		}
	}
	for _, leak := range []string{"sk-live-abcdef", "/etc/shadow", "fork/exec", "not_allowlisted", "cat "} {
		if strings.Contains(line, leak) {
			t.Fatalf("failure line %q leaked %q", line, leak)
		}
		if strings.Contains(got.FailedTool+" "+got.FailureReason, leak) {
			t.Fatalf("terminal record leaked %q: %+v", leak, got)
		}
	}
	if got := surface.outcomeList(); !slices.Equal(got, []string{"turn_failed"}) {
		t.Fatalf("TurnEnded outcomes = %v, want exactly one turn_failed", got)
	}
}

func diskStructuredReadRefusals(t *testing.T, store *sessions.Store) []events.StructuredReadRefused {
	t.Helper()
	sess, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed session %s: %v", store.Path(), err)
	}
	var out []events.StructuredReadRefused
	for _, r := range sess.Records {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindStructuredReadRefused {
			continue
		}
		var p events.StructuredReadRefused
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("unmarshal structured_read_refused: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func TestTurnController_UserCancellationRendersNoRecoveryLine(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	ready := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	<-ready
	if _, inFlight := ctl.Cancel(); !inFlight {
		t.Fatal("Cancel found no in-flight stream")
	}
	turns.Wait()

	if got := surface.committedList(); len(got) != 0 {
		t.Fatalf("committed errors = %v, want none for a user cancellation", got)
	}
	if surface.clearCount() == 0 {
		t.Fatal("in-flight indicator not cleared after a cancelled turn")
	}
	if got := surface.outcomeList(); len(got) != 1 || got[0] != "interrupted" {
		t.Fatalf("turn outcomes = %v, want [interrupted]", got)
	}
	terminals := diskTurnTerminals(t, store)
	if len(terminals) != 1 || terminals[0].Outcome != events.TurnOutcomeCancelled {
		t.Fatalf("persisted turn_terminal = %+v, want one %q record", terminals, events.TurnOutcomeCancelled)
	}
}

func TestTurnController_CompletedTurnPersistsCorrelatedTerminalRecord(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if got := surface.committedList(); len(got) != 0 {
		t.Fatalf("committed errors = %v, want none for a completed turn", got)
	}
	terminals := diskTurnTerminals(t, store)
	if len(terminals) != 1 {
		t.Fatalf("persisted turn_terminal events = %d, want 1", len(terminals))
	}
	if terminals[0].Outcome != events.TurnOutcomeCompleted || terminals[0].DispatchStarted {
		t.Fatalf("terminal = (%q, %t), want (%q, false)", terminals[0].Outcome, terminals[0].DispatchStarted, events.TurnOutcomeCompleted)
	}
	sess, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("open flushed session: %v", err)
	}
	var rounds []events.ProviderRoundTrip
	for _, r := range sess.Records {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindProviderRoundTrip {
			continue
		}
		var p events.ProviderRoundTrip
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("unmarshal provider_round_trip: %v", err)
		}
		rounds = append(rounds, p)
	}
	if len(rounds) != 1 {
		t.Fatalf("persisted provider_round_trip events = %d, want 1", len(rounds))
	}
	if rounds[0].TurnID != terminals[0].TurnID || rounds[0].RoundID != terminals[0].RoundID {
		t.Fatalf("round correlation = (%q, %q), want the terminal record's (%q, %q)",
			rounds[0].TurnID, rounds[0].RoundID, terminals[0].TurnID, terminals[0].RoundID)
	}
}

func TestTurnController_ExplainedProviderFailureAddsNoRecoveryLine(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: dropStream(contentChunk("partial"), io.ErrUnexpectedEOF)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	store := mkStore(t)
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	committed := surface.committedList()
	if len(committed) != 1 {
		t.Fatalf("committed errors = %v, want exactly the provider's own failure line", committed)
	}
	if strings.Contains(committed[0], "codemeld sessions doctor") {
		t.Fatalf("committed line %q is the generic recovery line, want the provider failure surface", committed[0])
	}
	terminals := diskTurnTerminals(t, store)
	if len(terminals) != client.callCount() {
		t.Fatalf("persisted turn_terminal events = %d, want one per provider attempt (%d)", len(terminals), client.callCount())
	}
	for i, got := range terminals {
		if got.Outcome != events.TurnOutcomeProviderFailed || got.FailurePhase != "stream_drop" {
			t.Fatalf("terminal %d = (%q, %q), want (%q, stream_drop)", i, got.Outcome, got.FailurePhase, events.TurnOutcomeProviderFailed)
		}
	}
}

func TestTurnController_TerminalRecordDoesNotDoubleReportAWriteFailure(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	dir := t.TempDir()
	store := storeAt(t, filepath.Join(dir, "session.json"), "01890000-0000-7000-8000-0000000020a0", "/proj")
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("remove session dir: %v", err)
		}
		if err := os.WriteFile(dir, []byte("not a dir"), 0o600); err != nil {
			t.Fatalf("replace session dir with file: %v", err)
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)

	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()

	if got := len(kindEvents(t, store, events.KindSessionWriteFailed)); got != 1 {
		t.Fatalf("session_write_failed events = %d, want 1 (the existing protocol reports the failure once)", got)
	}
	terminals := kindEvents(t, store, events.KindTurnTerminal)
	if len(terminals) != 1 {
		t.Fatalf("turn_terminal events = %d, want 1 even when the round could not be persisted", len(terminals))
	}
	var got events.TurnTerminal
	if err := json.Unmarshal(terminals[0].Payload, &got); err != nil {
		t.Fatalf("unmarshal turn_terminal: %v", err)
	}
	if got.Outcome != events.TurnOutcomeContinuationFailed {
		t.Fatalf("outcome = %q, want %q: the answer never reached disk", got.Outcome, events.TurnOutcomeContinuationFailed)
	}
	committed := surface.committedList()
	if len(committed) != 1 || !strings.Contains(committed[0], "the turn did not finish cleanly") {
		t.Fatalf("committed errors = %v, want the durable-failure recovery line", committed)
	}
}

type queueRecordingSurface struct {
	*recordingSurface
	logMu sync.Mutex
	log   []string
}

func (s *queueRecordingSurface) record(entry string) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.log = append(s.log, entry)
}

func (s *queueRecordingSurface) entries() []string {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	return slices.Clone(s.log)
}

func (s *queueRecordingSurface) AppendToolActivity(lines []string) {
	s.recordingSurface.AppendToolActivity(lines)
	s.record("activity")
}

func (s *queueRecordingSurface) UserMessageAdded(_ <-chan struct{}, _ *sessions.Store, text string, _ []sessions.ContentPart) {
	s.record("added:" + text)
}

func (s *queueRecordingSurface) UserMessagesUnsent(_ *sessions.Store, n, _ int, _ string) func() {
	s.record(fmt.Sprintf("unsent:%d", n))
	return nil
}

func (s *queueRecordingSurface) DiscardHeldPrompts() {}

func (s *queueRecordingSurface) TurnEnded(outcome string) {
	s.record("ended:" + outcome)
	s.recordingSurface.TurnEnded(outcome)
}

func newQueueTurnController(t *testing.T, surface *queueRecordingSurface, results map[string]turn.ToolResult) *turnController {
	t.Helper()
	ctl := newTurnController(context.Background(), surface, providerCache(t, t.TempDir()), turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setToolDispatcher(&fakeTurnDispatcher{results: results})
	ctl.setUnsentHook(func(_ *sessions.Store, unsent []turn.PendingUserMessage, outcome string) func() {
		if len(unsent) == 0 {
			return nil
		}
		texts := make([]string, len(unsent))
		for i, m := range unsent {
			texts[i] = m.Text
		}
		surface.record("unsent:" + strings.Join(texts, ",") + "@" + outcome)
		return nil
	})
	return ctl
}

func gatedToolCallClient(entered, release chan struct{}, second *provider.Request) *stubTurnClient {
	var round int32
	return &stubTurnClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			close(entered)
			<-release
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"go test ./..."}`)))}, nil
		}
		*second = req
		return provider.Response{Stream: newStream(contentChunk("all green"), finishChunk("stop"))}, nil
	}}
}

func TestTurnController_MidTurnMessageJoinsNextRequestAfterToolResults(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	entered, release := make(chan struct{}), make(chan struct{})
	var second provider.Request
	client := gatedToolCallClient(entered, release, &second)
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	surface := &queueRecordingSurface{recordingSurface: &recordingSurface{}}
	store := mkStore(t)
	ctl := newQueueTurnController(t, surface, map[string]turn.ToolResult{"call_1": {Content: "ok"}})
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v", err)
	}
	<-entered
	image := sessions.ContentPart{Type: "image_url", Raw: json.RawMessage(`{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}`)}
	if !ctl.addUserMessage("also run lint", []sessions.ContentPart{image}) {
		t.Fatal("the running turn refused a mid-turn message")
	}
	close(release)
	turns.Wait()

	if got := client.callCount(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
	msgs := second.Messages
	if len(msgs) < 2 || msgs[len(msgs)-1].Role != "user" || msgs[len(msgs)-2].Role != "tool" {
		t.Fatalf("second request messages = %+v, want the added user message right after the tool result", msgs)
	}
	if !hasImageURLPart(msgs[len(msgs)-1].Parts) {
		t.Fatalf("added message parts = %+v, want the image part carried through", msgs[len(msgs)-1].Parts)
	}

	toolAt, userAt, answerAt := -1, -1, -1
	for i, rec := range store.Records() {
		m, ok := rec.(sessions.Message)
		if !ok {
			continue
		}
		switch {
		case m.Role == "tool":
			toolAt = i
		case m.Role == "user":
			userAt = i
		case m.Role == "assistant" && m.Content.Text() == "all green":
			answerAt = i
		}
	}
	if toolAt < 0 || userAt <= toolAt || answerAt <= userAt {
		t.Fatalf("store order tool=%d user=%d answer=%d, want tool result, then the added message, then the answer", toolAt, userAt, answerAt)
	}
	replay := tui.New(nil)
	replay.ReplaySessionRecords(store.Records())
	transcript := replay.TranscriptText()
	if u, a := strings.Index(transcript, "also run lint"), strings.Index(transcript, "all green"); u < 0 || a < u {
		t.Fatalf("replayed transcript = %q, want the added message before the answer that followed it", transcript)
	}

	if got, want := surface.entries(), []string{"activity", "added:also run lint", "ended:completed"}; !slices.Equal(got, want) {
		t.Fatalf("surface calls = %q, want %q", got, want)
	}
	if ctl.addUserMessage("too late", nil) {
		t.Fatal("addUserMessage accepted a message with no running turn")
	}
}

func TestTurnController_UnsentMessageReachesHookBeforeTurnEnded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  turn.ToolResult
		outcome string
	}{
		{"terminal tool result completes", turn.ToolResult{Content: "done", Terminal: true}, "completed"},
		{"permission denial fails", turn.ToolResult{Content: permissions.BuildDenyEnvelope(""), Denied: true}, "turn_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var turns sync.WaitGroup
			defer swapGoTurn(waitableGoTurn(&turns))()

			entered, release := make(chan struct{}), make(chan struct{})
			var second provider.Request
			client := gatedToolCallClient(entered, release, &second)
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			surface := &queueRecordingSurface{recordingSurface: &recordingSurface{}}
			ctl := newQueueTurnController(t, surface, map[string]turn.ToolResult{"call_1": tc.result})
			if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
				t.Fatalf("dispatch error = %v", err)
			}
			<-entered
			if !ctl.addUserMessage("held", nil) {
				t.Fatal("the running turn refused a mid-turn message")
			}
			close(release)
			turns.Wait()

			if got := client.callCount(); got != 1 {
				t.Fatalf("provider calls = %d, want 1", got)
			}
			if got, want := surface.entries(), []string{"activity", "unsent:held@" + tc.outcome, "ended:" + tc.outcome}; !slices.Equal(got, want) {
				t.Fatalf("surface calls = %q, want %q", got, want)
			}
		})
	}

	t.Run("interrupt", func(t *testing.T) {
		var turns sync.WaitGroup
		defer swapGoTurn(waitableGoTurn(&turns))()

		ready := make(chan struct{})
		client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
			return provider.Response{Stream: blockingStream(ctx, contentChunk("Hi"), ready)}, nil
		}}
		defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

		surface := &queueRecordingSurface{recordingSurface: &recordingSurface{}}
		ctl := newQueueTurnController(t, surface, nil)
		if err := ctl.dispatch(mkStore(t), time.Time{}); err != nil {
			t.Fatalf("dispatch error = %v", err)
		}
		<-ready
		if !ctl.addUserMessage("held", nil) {
			t.Fatal("the running turn refused a mid-turn message")
		}
		ctl.Cancel()
		turns.Wait()

		if got, want := surface.entries(), []string{"unsent:held@interrupted", "ended:interrupted"}; !slices.Equal(got, want) {
			t.Fatalf("surface calls = %q, want %q", got, want)
		}
	})
}

const configuredWindowAdvice = " This is not one request's size. If individual requests approach the limit, check the server/model limit and match `context_windows`; the declaration does not raise capacity. For Ollama, check `OLLAMA_CONTEXT_LENGTH` or model `num_ctx`."

func windowCache(t *testing.T, windows map[string]any) *config.Cache {
	t.Helper()
	cache, err := config.NewCache(map[string]any{"provider": map[string]any{
		"openai": map[string]any{"base_url": "u", "api_key": "k", "models": []string{"gpt-5.5", "gpt-small", "gpt-unknown"}, "context_windows": windows},
	}}, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache
}

func discoveredWindowCache(t *testing.T, window int64) *config.Cache {
	t.Helper()
	settingsPath := SettingsPath(t.TempDir())
	if err := config.UpdateDiscoveredModelsProvider(config.DiscoveredModelsPath(settingsPath), "openai", config.DiscoveredProvider{
		Models: []config.DiscoveredModel{{ID: "gpt-5.5", ContextWindow: window}},
	}); err != nil {
		t.Fatalf("seed discovered models: %v", err)
	}
	cache, err := config.NewCache(map[string]any{"provider": map[string]any{
		"openai": map[string]any{"base_url": "u", "api_key": "k"},
	}}, t.TempDir(), []string{settingsPath})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	return cache
}

type windowTurns struct {
	ctl     *turnController
	app     *tui.App
	store   *sessions.Store
	surface *recordingSurface
}

func newWindowTurns(t *testing.T, cache *config.Cache, modelID string) *windowTurns {
	t.Helper()
	app := tui.New(nil)
	store := mkStore(t)
	app.SetActiveStore(store)
	surface := &recordingSurface{}
	ctl := newTurnController(context.Background(), surface, cache, turnSelection("openai", modelID, model.EffortDefault), nil, nil)
	ctl.setResponseObserver(newContextWindowNotice(app, cache))
	return &windowTurns{ctl: ctl, app: app, store: store, surface: surface}
}

func (w *windowTurns) run(t *testing.T, client provider.Client) string {
	t.Helper()
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	if err := w.ctl.dispatch(w.store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	turns.Wait()
	return w.app.NoticeText()
}

func usageReply(in, out int64) *stubTurnClient {
	return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"), usageChunk(in, out))}, nil
	}}
}

func toolRoundThenReply(first []byte, second ...[]byte) *stubTurnClient {
	var round int32
	return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"ls"}`)), first)}, nil
		}
		return provider.Response{Stream: newStream(second...)}, nil
	}}
}

func TestContextWindowNotice_WarnsFromTheTurnsInputAtNinetyPercent(t *testing.T) {
	cases := []struct {
		name    string
		window  int64
		modelID string
		in, out int64
		want    string
	}{
		{"exactly 90%", 1000, "gpt-5.5", 900, 1, "openai/gpt-5.5: 900 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice},
		{"above 90%", 1000, "gpt-5.5", 999, 1, "openai/gpt-5.5: 999 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice},
		{"just below 90%", 1000, "gpt-5.5", 899, 1, ""},
		{"output tokens do not count", 1000, "gpt-5.5", 100, 5000, ""},
		{"non-multiple of ten at the ceiling", 1005, "gpt-5.5", 905, 1, "openai/gpt-5.5: 905 recorded input tokens across rounds/retries; window 1005, 90% threshold 905." + configuredWindowAdvice},
		{"non-multiple of ten below the ceiling", 1005, "gpt-5.5", 904, 1, ""},
		{"maximum discovered window at the threshold", math.MaxInt64, "gpt-5.5", 8301034833169298227, 1, "openai/gpt-5.5: 8301034833169298227 recorded input tokens across rounds/retries; window 9223372036854775807, 90% threshold 8301034833169298227." + configuredWindowAdvice},
		{"maximum discovered window below the threshold", math.MaxInt64, "gpt-5.5", 8301034833169298226, 1, ""},
		{"unknown window", 1000, "gpt-unknown", 1 << 40, 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cache *config.Cache
			if tc.window > 10000000 {
				cache = discoveredWindowCache(t, tc.window)
			} else {
				cache = windowCache(t, map[string]any{"gpt-5.5": tc.window})
			}
			w := newWindowTurns(t, cache, tc.modelID)
			if got := w.run(t, usageReply(tc.in, tc.out)); got != tc.want {
				t.Fatalf("notice = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestContextWindowNotice_IgnoresPriorSessionUsage(t *testing.T) {
	seed := func(t *testing.T) *windowTurns {
		w := newWindowTurns(t, windowCache(t, map[string]any{"gpt-5.5": 1000}), "gpt-5.5")
		if err := model.EmitModelResponse(w.store, "openai", "gpt-5.5", 950, 10, nil, false, nil, false, nil, ""); err != nil {
			t.Fatalf("seed model_response: %v", err)
		}
		return w
	}
	t.Run("turn with no new response", func(t *testing.T) {
		w := seed(t)
		failing := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{}, &provider.HTTPError{Status: 400, Body: "boom", Surface: "provider openai returned HTTP 400"}
		}}
		if got := w.run(t, failing); got != "" {
			t.Fatalf("notice = %q, want none when the turn recorded no response", got)
		}
	})
	t.Run("small turn after a large session total", func(t *testing.T) {
		w := seed(t)
		if got := w.run(t, usageReply(200, 10)); got != "" {
			t.Fatalf("notice = %q, want none for a 200-token turn whatever the session total", got)
		}
	})
}

func TestContextWindowNotice_LaterTurnWarnsAndTitleHookIsUnchanged(t *testing.T) {
	w := newWindowTurns(t, windowCache(t, map[string]any{"gpt-5.5": 1000}), "gpt-5.5")
	var titleCalls atomic.Int32
	w.ctl.setTurnCompleteHook(func(context.Context, provider.Client, model.Selection, *sessions.Store, string, string) {
		titleCalls.Add(1)
	})
	w.store.Append(sessions.Message{Role: "user", Content: sessions.TextContent("first"), Timestamp: testStart})
	if got := w.run(t, usageReply(100, 10)); got != "" {
		t.Fatalf("first-turn notice = %q, want none below the threshold", got)
	}
	w.store.Append(sessions.Message{Role: "user", Content: sessions.TextContent("second"), Timestamp: testStart})
	want := "openai/gpt-5.5: 950 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice
	if got := w.run(t, usageReply(950, 10)); got != want {
		t.Fatalf("second-turn notice = %q, want %q", got, want)
	}
	if got := titleCalls.Load(); got != 1 {
		t.Fatalf("title hook calls = %d, want 1 (first turn only)", got)
	}
}

func TestContextWindowNotice_ObservesInterruptedAndDeniedTurns(t *testing.T) {
	want := "openai/gpt-5.5: 950 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice
	t.Run("interrupted", func(t *testing.T) {
		w := newWindowTurns(t, windowCache(t, map[string]any{"gpt-5.5": 1000}), "gpt-5.5")
		ready := make(chan struct{})
		client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
			return provider.Response{Stream: blockingStream(ctx, usageChunk(950, 1), ready)}, nil
		}}
		go func() {
			<-ready
			w.ctl.Cancel()
		}()
		if got := w.run(t, client); got != want {
			t.Fatalf("notice = %q, want %q", got, want)
		}
		if got := w.surface.outcomeList(); !slices.Equal(got, []string{"interrupted"}) {
			t.Fatalf("outcomes = %v, want [interrupted]", got)
		}
	})
	t.Run("denied", func(t *testing.T) {
		w := newWindowTurns(t, windowCache(t, map[string]any{"gpt-5.5": 1000}), "gpt-5.5")
		w.ctl.setToolDispatcher(&fakeTurnDispatcher{results: map[string]turn.ToolResult{
			"call_1": {Denied: true, Content: permissions.BuildDenyEnvelope("no")},
		}})
		if got := w.run(t, toolRoundThenReply(usageChunk(950, 1))); got != want {
			t.Fatalf("notice = %q, want %q", got, want)
		}
		if got := w.surface.outcomeList(); !slices.Equal(got, []string{"turn_failed"}) {
			t.Fatalf("outcomes = %v, want [turn_failed]", got)
		}
	})
}

func TestContextWindowNotice_SumsRoundsAndLabelsPartialUsage(t *testing.T) {
	cases := []struct {
		name          string
		first, second []byte
		want          string
	}{
		{"rounds each below 90% sum above it", usageChunk(500, 1), usageChunk(450, 1), "openai/gpt-5.5: 950 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice},
		{"usage missing from a round at the threshold", usageChunk(900, 1), nil, "openai/gpt-5.5: at least 900 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice},
		{"usage missing from a round below the threshold", usageChunk(899, 1), nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWindowTurns(t, windowCache(t, map[string]any{"gpt-5.5": 1000}), "gpt-5.5")
			w.ctl.setToolDispatcher(&fakeTurnDispatcher{results: map[string]turn.ToolResult{"call_1": {Content: "done"}}})
			second := [][]byte{contentChunk("ok"), finishChunk("stop")}
			if tc.second != nil {
				second = append(second, tc.second)
			}
			if got := w.run(t, toolRoundThenReply(tc.first, second...)); got != tc.want {
				t.Fatalf("notice = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestContextWindowNotice_UsesTheCompletedResponsesModel(t *testing.T) {
	w := newWindowTurns(t, windowCache(t, map[string]any{"gpt-small": 1000, "gpt-5.5": 100000}), "gpt-small")
	switched := make(chan struct{})
	client := &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		<-switched
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"), usageChunk(950, 1))}, nil
	}}
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	if err := w.ctl.dispatch(w.store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	w.ctl.active.ApplyUserSelection(model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, false)
	close(switched)
	turns.Wait()
	want := "openai/gpt-small: 950 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice
	if got := w.app.NoticeText(); got != want {
		t.Fatalf("notice = %q, want %q", got, want)
	}
}

func TestContextWindowNotice_ChatGPTTemplate(t *testing.T) {
	settingsPath := SettingsPath(t.TempDir())
	if err := config.UpdateDiscoveredModelsProvider(config.DiscoveredModelsPath(settingsPath), "openai-chatgpt", config.DiscoveredProvider{
		Models: []config.DiscoveredModel{{ID: "gpt-chat", ContextWindow: 1000}},
	}); err != nil {
		t.Fatalf("seed discovered models: %v", err)
	}
	cache, err := config.NewCache(map[string]any{}, t.TempDir(), []string{settingsPath})
	if err != nil {
		t.Fatalf("config.NewCache: %v", err)
	}
	app := tui.New(nil)
	store := mkStore(t)
	app.SetActiveStore(store)
	newContextWindowNotice(app, cache)(store.SessionID(), events.ModelResponse{Provider: "openai-chatgpt", ModelID: "gpt-chat", InputTokens: 900, Anomaly: []string{"usage_missing"}})
	want := "openai-chatgpt/gpt-chat: at least 900 recorded input tokens across rounds/retries; window 1000, 90% threshold 900. This is not one request's size. If individual requests approach the limit, start a shorter or new session, or switch to a larger-window model."
	if got := app.NoticeText(); got != want {
		t.Fatalf("notice = %q, want %q", got, want)
	}
}

func TestContextWindowNotice_CapturedBeforeTheDrainReleases(t *testing.T) {
	launched := make(chan func(), 1)
	defer swapGoTurn(func(fn func()) { launched <- fn })()
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return usageReply(950, 1) })()

	cache := windowCache(t, map[string]any{"gpt-5.5": 1000})
	w := newWindowTurns(t, cache, "gpt-5.5")
	w.surface.clearEntered = make(chan struct{})
	w.surface.clearRelease = make(chan struct{})
	if err := w.ctl.dispatch(w.store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	runTurn := <-launched
	runDone := make(chan struct{})
	go func() { defer close(runDone); runTurn() }()

	<-w.surface.clearEntered
	w.ctl.WaitTurnDrained()
	if err := model.EmitModelResponse(w.store, "openai", "gpt-5.5", 10, 1, nil, false, nil, false, nil, ""); err != nil {
		t.Fatalf("append queued-turn response: %v", err)
	}
	close(w.surface.clearRelease)
	<-runDone

	want := "openai/gpt-5.5: 950 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice
	if got := w.app.NoticeText(); got != want {
		t.Fatalf("notice = %q, want %q", got, want)
	}
}

func TestContextWindowNotice_OwnershipCheckedAtDelivery(t *testing.T) {
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()
	ready := make(chan struct{})
	client := &stubTurnClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		return provider.Response{Stream: blockingStream(ctx, usageChunk(950, 1), ready)}, nil
	}}
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	cache := windowCache(t, map[string]any{"gpt-5.5": 1000})
	app := tui.New(nil)
	app.SetScreenFactoryForTest(func() (tcell.Screen, error) { return tcell.NewSimulationScreen("UTF-8"), nil })
	store := mkStore(t)
	app.SetActiveStore(store)
	errc := make(chan error, 1)
	go func() { errc <- app.Run() }()
	defer func() {
		app.Stop()
		<-errc
	}()
	onEventLoop(t, app, func() {})

	notice := newContextWindowNotice(app, cache)
	queued := make(chan struct{})
	ctl := newTurnController(context.Background(), &recordingSurface{}, cache, turnSelection("openai", "gpt-5.5", model.EffortDefault), nil, nil)
	ctl.setResponseObserver(func(sessionID string, resp events.ModelResponse) {
		notice(sessionID, resp)
		close(queued)
	})
	if err := ctl.dispatch(store, time.Time{}); err != nil {
		t.Fatalf("dispatch error = %v, want nil", err)
	}
	<-ready
	fresh := storeAt(t, filepath.Join(t.TempDir(), "session.json"), "01890000-0000-7000-8000-00000000b001", "/proj")
	onEventLoop(t, app, func() {
		ctl.Cancel()
		ctl.WaitTurnDrained()
		<-queued
		app.SetActiveStore(fresh)
	})
	turns.Wait()
	waitTitleBackgroundDone(t)
	if got := noticeOnEventLoop(t, app); got != "" {
		t.Fatalf("notice = %q, want the swapped-away session's warning dropped", got)
	}

	onEventLoop(t, app, func() { app.SetActiveStore(store) })
	notice(store.SessionID(), events.ModelResponse{Provider: "openai", ModelID: "gpt-5.5", InputTokens: 950})
	waitTitleBackgroundDone(t)
	want := "openai/gpt-5.5: 950 recorded input tokens across rounds/retries; window 1000, 90% threshold 900." + configuredWindowAdvice
	if got := noticeOnEventLoop(t, app); got != want {
		t.Fatalf("notice on returning to the unwarned session = %q, want %q", got, want)
	}
}
