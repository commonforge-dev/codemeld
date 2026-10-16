package turn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessionfailures"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
)

// --- streamed-chunk fixtures ------------------------------------------------

func contentChunk(text string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":%q},"finish_reason":""}]}`, text))
}

func finishChunk(reason string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":%q}]}`, reason))
}

func toolCallChunk() []byte {
	return []byte(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"do","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`)
}

// usageChunk is the include_usage final chunk: empty choices, populated usage.
func usageChunk(in, out int64) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`, in, out, in+out))
}

func cachedUsageChunk(in, out, cached int64) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d,"prompt_tokens_details":{"cached_tokens":%d}}}`, in, out, in+out, cached))
}

// sliceDecoder replays a fixed list of chunk payloads as SSE events.
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

// cancelDecoder yields one chunk, then blocks until the request context is
// cancelled, surfacing the cancellation as the stream error.
type cancelDecoder struct {
	ctx    context.Context
	first  []byte
	served bool
	onWait func()
	cur    ssestream.Event
	err    error
}

func (d *cancelDecoder) Next() bool {
	if !d.served {
		d.served = true
		d.cur = ssestream.Event{Data: d.first}
		return true
	}
	if d.onWait != nil {
		d.onWait()
	}
	<-d.ctx.Done()
	d.err = d.ctx.Err()
	return false
}
func (d *cancelDecoder) Event() ssestream.Event { return d.cur }
func (d *cancelDecoder) Close() error           { return nil }
func (d *cancelDecoder) Err() error             { return d.err }

// blockingDecoder serves pre chunks, then blocks the next read on gate (the idle
// window under test), then serves post chunks; Err returns err after the stream
// ends. It models a provider stream that stalls mid-round: the gate blocks inside
// Next() until the test (or the idle hook) releases it, so the idle timer can fire
// while the read is still blocked.
type blockingDecoder struct {
	pre, post [][]byte
	gate      <-chan struct{}
	onBlock   func()
	err       error
	idx       int
	gated     bool
	cur       ssestream.Event
}

func (d *blockingDecoder) Next() bool {
	if d.idx < len(d.pre) {
		d.cur = ssestream.Event{Data: d.pre[d.idx]}
		d.idx++
		return true
	}
	if !d.gated {
		if d.onBlock != nil {
			d.onBlock()
		}
		<-d.gate
		d.gated = true
	}
	if p := d.idx - len(d.pre); p < len(d.post) {
		d.cur = ssestream.Event{Data: d.post[p]}
		d.idx++
		return true
	}
	return false
}
func (d *blockingDecoder) Event() ssestream.Event { return d.cur }
func (d *blockingDecoder) Close() error           { return nil }
func (d *blockingDecoder) Err() error             { return d.err }

func blockingStream(dec *blockingDecoder) provider.Response {
	return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}
}

// deterministicIdle replaces the idleTimer seam with a channel that fires only when a
// read is known blocked, so idle-crossing tests wait on no wall clock. It returns the
// onBlock trigger a blockingDecoder calls the instant it stalls; production keeps its
// 30-second threshold. Buffered by one so the decoder's send never blocks ahead of the
// runner's select.
func deterministicIdle(t *testing.T) (onBlock func()) {
	t.Helper()
	restore := idleTimer
	c := make(chan time.Time, 1)
	idleTimer = func() (<-chan time.Time, func()) { return c, func() {} }
	t.Cleanup(func() { idleTimer = restore })
	return func() { c <- time.Time{} }
}

func providerStreamIdleEvents(t *testing.T, recs []sessions.Record) []events.ProviderStreamIdle {
	t.Helper()
	return eventsOf[events.ProviderStreamIdle](t, recs, events.KindProviderStreamIdle, "provider_stream_idle")
}

// --- fake provider client ---------------------------------------------------

type fakeClient struct {
	calls int32
	fn    func(ctx context.Context, req provider.Request) (provider.Response, error)
}

func (c *fakeClient) ChatCompletion(ctx context.Context, req provider.Request) (provider.Response, error) {
	atomic.AddInt32(&c.calls, 1)
	return c.fn(ctx, req)
}

func (c *fakeClient) callCount() int { return int(atomic.LoadInt32(&c.calls)) }

// streamClient returns a client whose every call yields a fresh stream of chunks.
func streamClient(chunks ...[]byte) *fakeClient {
	return &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return provider.Response{Stream: newStream(chunks...)}, nil
	}}
}

// --- helpers ----------------------------------------------------------------

type recordingNotice struct {
	mu    sync.Mutex
	texts []string
}

func (n *recordingNotice) Notice(text string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.texts = append(n.texts, text)
}

func (n *recordingNotice) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.texts)
}

func storeAt(path string) *sessions.Store {
	sess := &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            ids.NewV7(),
			Folder:        filepath.Dir(path),
			StartedAt:     time.Now().UTC(),
			UpdatedAt:     time.Now().UTC(),
			SchemaVersion: sessions.CurrentSchemaVersion,
		},
	}
	return sessions.New(path, sess)
}

func selectedState(provider, id, effort string) *model.ActiveState {
	sel := model.Selection{Provider: provider, ID: id, Effort: effort}
	return model.NewActiveState(&sel, model.SourceProject)
}

func eventKinds(recs []sessions.Record) []string {
	var kinds []string
	for _, r := range recs {
		if e, ok := r.(sessions.Event); ok {
			kinds = append(kinds, e.Kind)
		}
	}
	return kinds
}

func hasKind(recs []sessions.Record, kind string) bool {
	for _, k := range eventKinds(recs) {
		if k == kind {
			return true
		}
	}
	return false
}

func assistantMessages(recs []sessions.Record) []sessions.Message {
	var out []sessions.Message
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "assistant" {
			out = append(out, m)
		}
	}
	return out
}

// --- tests ------------------------------------------------------------------

func TestRun_HappyPathStream(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var deltas []string
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("Hello"), contentChunk(" world"), finishChunk("stop")),
		Sink:   func(d string) { deltas = append(deltas, d) },
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if want := []string{"Hello", " world"}; fmt.Sprint(deltas) != fmt.Sprint(want) {
		t.Fatalf("sink deltas = %v, want %v", deltas, want)
	}
	retained, inFlight := runner.Cancel()
	if inFlight {
		t.Fatalf("Cancel after completion inFlight = true, want false")
	}
	if retained != len("Hello world") {
		t.Fatalf("retained chars = %d, want %d", retained, len("Hello world"))
	}

	recs := store.Records()
	if !hasKind(recs, "model_effort_unsupported") {
		t.Fatalf("missing model_effort_unsupported for a cacheless legacy default-effort turn; kinds = %v", eventKinds(recs))
	}
	if !hasKind(recs, "model_turn") {
		t.Fatalf("missing model_turn; kinds = %v", eventKinds(recs))
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response; kinds = %v", eventKinds(recs))
	}
	msgs := assistantMessages(recs)
	if len(msgs) != 1 || msgs[0].Content.Text() != "Hello world" {
		t.Fatalf("assistant messages = %+v, want one with %q", msgs, "Hello world")
	}
	// Ordering: assistant message and model_response come after model_turn.
	turnIdx, msgIdx, respIdx := -1, -1, -1
	for i, r := range recs {
		switch rec := r.(type) {
		case sessions.Event:
			if rec.Kind == "model_turn" {
				turnIdx = i
			}
			if rec.Kind == "model_response" {
				respIdx = i
			}
		case sessions.Message:
			if rec.Role == "assistant" {
				msgIdx = i
			}
		}
	}
	if turnIdx >= msgIdx || msgIdx >= respIdx {
		t.Fatalf("record order turn=%d msg=%d resp=%d, want turn<msg<resp", turnIdx, msgIdx, respIdx)
	}
}

// decodeModelResponse returns the single model_response payload in recs, failing
// if there is not exactly one.
func decodeModelResponse(t *testing.T, recs []sessions.Record) events.ModelResponse {
	t.Helper()
	var found []events.ModelResponse
	for _, r := range recs {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindModelResponse {
			continue
		}
		var p events.ModelResponse
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode model_response: %v", err)
		}
		found = append(found, p)
	}
	if len(found) != 1 {
		t.Fatalf("model_response events = %d, want 1; kinds = %v", len(found), eventKinds(recs))
	}
	return found[0]
}

// A clean stream that ends with an include_usage final chunk records the exact
// provider token counts on model_response (not usage_missing) and forwards them to
// the Usage callback, while Progress reports the cumulative retained runes as the
// content streams. This is the /status-consistency signal: the persisted totals
// are exact when the usage chunk is present. This is a bare Runner with nil UsageAcc,
// so it exercises the Usage gate: the terminal Usage callback fires exactly once here
// (under a ToolLoop, UsageAcc != nil and the loop owns per-round emission instead).
func TestRun_StreamUsageRecordsExactUsageAndForwardsCallbacks(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var progress []int
	var usageIn, usageOut int64
	var usageCalls int
	runner := New(Deps{
		Active:   selectedState("openai", "gpt-x", model.EffortDefault),
		Store:    store,
		Client:   streamClient(contentChunk("Hello"), contentChunk(" world"), finishChunk("stop"), usageChunk(120, 40)),
		Progress: func(retained int) { progress = append(progress, retained) },
		Usage: func(in, out int64) {
			usageCalls++
			usageIn, usageOut = in, out
		},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	mr := decodeModelResponse(t, store.Records())
	if mr.InputTokens != 120 || mr.OutputTokens != 40 {
		t.Fatalf("model_response tokens = (%d, %d), want (120, 40) from the usage chunk", mr.InputTokens, mr.OutputTokens)
	}
	if len(mr.Anomaly) != 0 {
		t.Fatalf("model_response anomaly = %v, want none for an exact usage chunk", mr.Anomaly)
	}
	if usageCalls != 1 || usageIn != 120 || usageOut != 40 {
		t.Fatalf("Usage callback = %d calls (%d, %d), want 1 (120, 40)", usageCalls, usageIn, usageOut)
	}
	// Progress reports a monotonically growing retained-rune count, one per content
	// delta ("Hello"=5, then " world"=11).
	if want := []int{5, 11}; fmt.Sprint(progress) != fmt.Sprint(want) {
		t.Fatalf("Progress retained counts = %v, want %v", progress, want)
	}
}

// Without an include_usage final chunk (e.g. a provider that ignores
// stream_options) a clean stream still records model_response, but with the
// usage_missing fallback and no exact figure forwarded — preserving the earlier
// behavior rather than inventing counts.
func TestRun_NoUsageChunkFallsBackToUsageMissing(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var usageCalls int
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("hi"), finishChunk("stop")),
		Usage:  func(int64, int64) { usageCalls++ },
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	mr := decodeModelResponse(t, store.Records())
	if mr.InputTokens != 0 || mr.OutputTokens != 0 {
		t.Fatalf("model_response tokens = (%d, %d), want (0, 0) without a usage chunk", mr.InputTokens, mr.OutputTokens)
	}
	if len(mr.Anomaly) != 1 || mr.Anomaly[0] != "usage_missing" {
		t.Fatalf("model_response anomaly = %v, want [usage_missing]", mr.Anomaly)
	}
	if usageCalls != 0 {
		t.Fatalf("Usage callback fired %d times, want 0 when no usage chunk arrived", usageCalls)
	}
	if mr.CachedInputTokens != nil {
		t.Fatalf("cached_input_tokens = %d, want nil when no usage chunk arrived", *mr.CachedInputTokens)
	}
}

// A real Runner, a real persisted record, and the real /context renderer, with no
// fake standing in at the provider usage seam.
func TestRun_CachedPromptTokensReachRecordAndContext(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("Hello"), finishChunk("stop"), cachedUsageChunk(120, 40, 96)),
		Usage:  func(int64, int64) {},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	mr := decodeModelResponse(t, store.Records())
	if mr.InputTokens != 120 || mr.OutputTokens != 40 {
		t.Fatalf("model_response tokens = (%d, %d), want (120, 40)", mr.InputTokens, mr.OutputTokens)
	}
	if mr.CachedInputTokens == nil || *mr.CachedInputTokens != 96 {
		t.Fatalf("model_response cached_input_tokens = %v, want 96", mr.CachedInputTokens)
	}
	if mr.CachedInputTokensPartial {
		t.Error("cached_input_tokens_partial = true, want false for a single fully reported round")
	}

	// Reopening through the production loader also re-runs load-time payload validation.
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	reloaded, _, err := sessions.OpenSession(store.Path())
	if err != nil {
		t.Fatalf("reopen persisted session: %v", err)
	}
	if persisted := decodeModelResponse(t, reloaded.Records); persisted.CachedInputTokens == nil || *persisted.CachedInputTokens != 96 {
		t.Fatalf("reloaded cached_input_tokens = %v, want 96", persisted.CachedInputTokens)
	}

	out := tui.RenderContext(tui.BuildContextSnapshot(recordContextState(reloaded.Records)))
	if want := "Token usage: 120 input (96 cached), 40 output (160 total)"; !strings.Contains(out, want) {
		t.Fatalf("/context missing %q\n--- output ---\n%s", want, out)
	}
	if strings.Contains(out, "at least") {
		t.Errorf("/context rendered a fully reported total as a lower bound\n--- output ---\n%s", out)
	}
}

func TestRun_UnreportedCachedTokensLeaveContextUnchanged(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("Hello"), finishChunk("stop"), usageChunk(120, 40)),
		Usage:  func(int64, int64) {},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if mr := decodeModelResponse(t, store.Records()); mr.CachedInputTokens != nil {
		t.Fatalf("cached_input_tokens = %d, want nil for a provider that omitted the field", *mr.CachedInputTokens)
	}
	out := tui.RenderContext(tui.BuildContextSnapshot(recordContextState(store.Records())))
	if want := "Token usage: 120 input, 40 output (160 total)"; !strings.Contains(out, want) {
		t.Fatalf("/context missing %q\n--- output ---\n%s", want, out)
	}
	if strings.Contains(out, "cached") {
		t.Errorf("/context invented a cached clause with nothing reported\n--- output ---\n%s", out)
	}
}

func withUpstream(chunk []byte, raw string) []byte {
	return append([]byte(`{"provider":`+raw+`,`), chunk[1:]...)
}

func modelResponsePayload(t *testing.T, recs []sessions.Record) string {
	t.Helper()
	decodeModelResponse(t, recs)
	for _, r := range recs {
		if ev, ok := r.(sessions.Event); ok && ev.Kind == events.KindModelResponse {
			return string(ev.Payload)
		}
	}
	return ""
}

func TestRun_OpenRouterRecordsUpstreamProvider(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openrouter", "meta/llama", model.EffortDefault),
		Store:  store,
		Client: streamClient(withUpstream(contentChunk("Hello"), `"Groq"`), withUpstream(finishChunk("stop"), `"Groq"`)),
		Flush:  storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := decodeModelResponse(t, diskRecords(t, store)).UpstreamProvider; got != "Groq" {
		t.Fatalf("persisted upstream_provider = %q, want Groq", got)
	}
}

func TestRun_UpstreamProviderOmittedWithoutAStringValue(t *testing.T) {
	for _, tc := range []struct {
		name, provider string
		chunk          []byte
	}{
		{"non-openrouter provider", "openai", withUpstream(contentChunk("hi"), `"Groq"`)},
		{"field absent", "openrouter", contentChunk("hi")},
		{"empty string", "openrouter", withUpstream(contentChunk("hi"), `""`)},
		{"null", "openrouter", withUpstream(contentChunk("hi"), `null`)},
		{"number", "openrouter", withUpstream(contentChunk("hi"), `7`)},
		{"bool", "openrouter", withUpstream(contentChunk("hi"), `true`)},
		{"array", "openrouter", withUpstream(contentChunk("hi"), `["Groq"]`)},
		{"object", "openrouter", withUpstream(contentChunk("hi"), `{"name":"Groq"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			runner := New(Deps{
				Active: selectedState(tc.provider, "m", model.EffortDefault),
				Store:  store,
				Client: streamClient(tc.chunk, finishChunk("stop")),
			})
			if err := runner.Run(context.Background()); err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}
			if payload := modelResponsePayload(t, store.Records()); strings.Contains(payload, "upstream_provider") {
				t.Fatalf("model_response = %s, want no upstream_provider key", payload)
			}
		})
	}
}

func TestToolLoop_NaturalFinalAnswerRecordsFinalRoundUpstreamProvider(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))
	client := &scriptedClient{rounds: [][][]byte{
		{withUpstream(toolCallChunk(), `"Groq"`)},
		{withUpstream(contentChunk("all done"), `"Cerebras"`), finishChunk("stop")},
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openrouter", "m", model.EffortDefault),
		Store:  store,
		Client: client,
	}, &fakeDispatcher{}, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2", client.callCount())
	}
	if got := decodeModelResponse(t, store.Records()).UpstreamProvider; got != "Cerebras" {
		t.Fatalf("upstream_provider = %q, want the final round's Cerebras", got)
	}
}

func TestRun_RetriedAttemptUpstreamProviderDoesNotLeak(t *testing.T) {
	noSleep(t)
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			dec := &dropDecoder{first: withUpstream(contentChunk("x"), `"Failed Upstream"`), err: io.ErrUnexpectedEOF}
			return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"))}, nil
	})
	runner := New(Deps{
		Active:          selectedState("openrouter", "m", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           retryOn(),
		RollbackPartial: func() {},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil (recovered on the second attempt)", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2", client.callCount())
	}
	if payload := modelResponsePayload(t, store.Records()); strings.Contains(payload, "upstream_provider") {
		t.Fatalf("model_response = %s, want no upstream_provider from the failed attempt", payload)
	}
}

// recordContextState feeds a session's real record stream to /context, so the panel
// renders from the same events the turn wrote rather than a hand-built fixture.
type recordContextState []sessions.Record

func (recordContextState) Selection() (string, string) { return "openai", "gpt-x" }
func (s recordContextState) Records() []sessions.Record {
	return s
}
func (recordContextState) ContextWindow() int64 { return 0 }

func TestRun_SupportedEffortReachesProviderRequest(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))

	var captured provider.Request
	client := &fakeClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		captured = req
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-5.5", provider.EffortHigh),
		Store:           store,
		Client:          client,
		SupportedEffort: func(string, string) []string { return []string{provider.EffortHigh} },
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if captured.Effort != provider.EffortHigh {
		t.Fatalf("provider request Effort = %q, want %q", captured.Effort, provider.EffortHigh)
	}
	if !captured.Stream {
		t.Fatalf("provider request Stream = false, want true")
	}
	if hasKind(store.Records(), "model_effort_unsupported") {
		t.Fatalf("unexpected model_effort_unsupported for a supported high-effort turn")
	}
}

func TestRun_DiscoveredSupportedEffortReachesProviderRequest(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))

	var captured provider.Request
	client := &fakeClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		captured = req
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	var gotProvider, gotModelID string
	runner := New(Deps{
		Active: selectedState("openai-chatgpt", "gpt-6-discovered", provider.EffortXHigh),
		Store:  store,
		Client: client,
		SupportedEffort: func(providerID, modelID string) []string {
			gotProvider, gotModelID = providerID, modelID
			if providerID != "openai-chatgpt" || modelID != "gpt-6-discovered" {
				return []string{provider.EffortDefault}
			}
			return []string{provider.EffortNone, provider.EffortLow, provider.EffortMedium, provider.EffortHigh, provider.EffortXHigh}
		},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if gotProvider != "openai-chatgpt" || gotModelID != "gpt-6-discovered" {
		t.Fatalf("SupportedEffort lookup key = (%q, %q), want the selected (openai-chatgpt, gpt-6-discovered)", gotProvider, gotModelID)
	}
	if captured.Effort != provider.EffortXHigh {
		t.Fatalf("provider request Effort = %q, want %q", captured.Effort, provider.EffortXHigh)
	}
	if hasKind(store.Records(), "model_effort_unsupported") {
		t.Fatalf("unexpected model_effort_unsupported for a supported discovered xhigh turn")
	}
}

func TestRun_DiscoveredUnsupportedEffortDropsBeforeProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)

	entered := make(chan struct{})
	release := make(chan struct{})
	var captured provider.Request
	client := &fakeClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		captured = req
		close(entered)
		<-release
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}

	flushed := false
	var gotProvider, gotModelID string
	runner := New(Deps{
		Active: selectedState("openai-chatgpt", "gpt-6-discovered", provider.EffortXHigh),
		Store:  store,
		Client: client,
		// Discovered set without xhigh, returned only for the selected provider/model: the
		// active xhigh must drop as unsupported. A wrong lookup target returns default-only;
		// xhigh drops either way, so the arg assertion after <-entered is what catches a
		// mis-keyed lookup here.
		SupportedEffort: func(providerID, modelID string) []string {
			gotProvider, gotModelID = providerID, modelID
			if providerID != "openai-chatgpt" || modelID != "gpt-6-discovered" {
				return []string{provider.EffortDefault}
			}
			return []string{provider.EffortLow, provider.EffortMedium, provider.EffortHigh}
		},
		FlushUnsupported: func() error {
			flushed = true
			_, _, err := store.Flush(context.Background())
			return err
		},
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-entered // provider reached: the unsupported-effort flush hook has already run
	if !flushed {
		t.Fatalf("provider call started before the unsupported-effort flush hook ran")
	}
	if gotProvider != "openai-chatgpt" || gotModelID != "gpt-6-discovered" {
		t.Fatalf("SupportedEffort lookup key = (%q, %q), want the selected (openai-chatgpt, gpt-6-discovered)", gotProvider, gotModelID)
	}
	if captured.Effort != "" {
		t.Fatalf("provider request Effort = %q, want empty (dropped to default)", captured.Effort)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted session: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session: %v", err)
	}
	unsupportedIdx, turnIdx := -1, -1
	for i, r := range reloaded.Records {
		if e, ok := r.(sessions.Event); ok {
			switch e.Kind {
			case "model_effort_unsupported":
				unsupportedIdx = i
			case "model_turn":
				turnIdx = i
			}
		}
	}
	if unsupportedIdx == -1 || turnIdx == -1 || unsupportedIdx >= turnIdx {
		t.Fatalf("on-disk records: model_effort_unsupported(%d) must precede model_turn(%d) before provider returns; kinds = %v",
			unsupportedIdx, turnIdx, eventKinds(reloaded.Records))
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
}

func catalogSupportedEffort(modelID string, advertised ...string) func(string, string) []string {
	options := make([]any, len(advertised))
	for i, effort := range advertised {
		options[i] = effort
	}
	cat := provider.BuildCatalog(
		map[string]provider.ProviderEntry{"openai": {BaseURL: "https://api.openai.com/v1", APIKey: "sk-test"}},
		nil,
		map[string][]provider.DiscoveredConfiguredModel{"openai": {{ID: modelID, Capabilities: map[string]any{
			"supportsReasoningEffort": true,
			"reasoningEffortOptions":  options,
		}}}},
	)
	return cat.SupportedEffort
}

func TestRun_CatalogAdvertisedEffortReachesProviderRequest(t *testing.T) {
	advertised := []string{"max", "ultra", provider.EffortDefault}
	cases := []struct {
		selected string
		want     string
	}{
		{"max", "max"},
		{"ultra", "ultra"},
		{provider.EffortDefault, provider.EffortDefault},
		{provider.EffortNoReasoning, ""},
	}
	for _, tc := range cases {
		t.Run(tc.selected, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))

			var captured provider.Request
			client := &fakeClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				captured = req
				return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
			}}
			runner := New(Deps{
				Active:          selectedState("openai", "gpt-5.5", tc.selected),
				Store:           store,
				Client:          client,
				SupportedEffort: catalogSupportedEffort("gpt-5.5", advertised...),
			})

			if err := runner.Run(context.Background()); err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}
			if captured.Effort != tc.want {
				t.Fatalf("provider request Effort = %q, want %q for %q against the advertised %v", captured.Effort, tc.want, tc.selected, advertised)
			}
			if hasKind(store.Records(), "model_effort_unsupported") {
				t.Fatalf("unexpected model_effort_unsupported for %q against the advertised %v", tc.selected, advertised)
			}
		})
	}
}

func TestRun_FormerlyAdvertisedEffortAuditsThenOmits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)

	entered := make(chan struct{})
	release := make(chan struct{})
	var captured provider.Request
	client := &fakeClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		captured = req
		close(entered)
		<-release
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}

	active := selectedState("openai", "gpt-5.5", "ultra")
	runner := New(Deps{
		Active:          active,
		Store:           store,
		Client:          client,
		SupportedEffort: catalogSupportedEffort("gpt-5.5", "max"),
		FlushUnsupported: func() error {
			_, _, err := store.Flush(context.Background())
			return err
		},
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-entered // unsupported-effort event is durable before reading the session file
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted session: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session: %v", err)
	}
	audits := eventsOf[events.ModelEffortUnsupported](t, reloaded.Records, events.KindModelEffortUnsupported, "model_effort_unsupported")
	if len(audits) != 1 || audits[0].Provider != "openai" || audits[0].ModelID != "gpt-5.5" || audits[0].ConfiguredEffort != "ultra" {
		t.Fatalf("on-disk model_effort_unsupported = %+v, want one {openai, gpt-5.5, ultra} before the provider request; kinds = %v", audits, eventKinds(reloaded.Records))
	}
	if captured.Effort != "" {
		t.Fatalf("provider request Effort = %q, want empty (the unadvertised ultra is omitted)", captured.Effort)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if sel, _, ok := active.Current(); !ok || sel.Effort != "ultra" {
		t.Fatalf("active selection = %+v (ok=%v), want the stored ultra left unrewritten by the drop", sel, ok)
	}
}

func TestRun_ModelTurnDurableBeforeProviderCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)
	entered := make(chan struct{})
	release := make(chan struct{})

	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		close(entered)
		<-release
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush: func() error {
			_, _, err := store.Flush(context.Background())
			return err
		},
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-entered
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted session before provider returns: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session before provider returns: %v", err)
	}
	if !hasKind(reloaded.Records, "model_turn") {
		t.Fatalf("on-disk records before provider returns missing model_turn; kinds = %v", eventKinds(reloaded.Records))
	}
	if hasKind(reloaded.Records, "model_response") {
		t.Fatalf("model_response persisted before provider returned; kinds = %v", eventKinds(reloaded.Records))
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
}

func TestRun_ModelResponseDurableBeforeReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("Hello"), finishChunk("stop")),
		Flush: func() error {
			_, _, err := store.Flush(context.Background())
			return err
		},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted session after turn: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session after turn: %v", err)
	}
	if !hasKind(reloaded.Records, "model_response") {
		t.Fatalf("on-disk records after turn missing model_response; kinds = %v", eventKinds(reloaded.Records))
	}
	msgs := assistantMessages(reloaded.Records)
	if len(msgs) != 1 || msgs[0].Content.Text() != "Hello" {
		t.Fatalf("on-disk assistant messages = %+v, want one with %q", msgs, "Hello")
	}
}

func TestRun_NoModelRefusedNoProviderCall(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := streamClient(contentChunk("Hello"), finishChunk("stop"))
	runner := New(Deps{
		Active: model.NewActiveState(nil, ""),
		Store:  store,
		Client: client,
	})

	err := runner.Run(context.Background())
	if !errors.Is(err, ErrNoModelSelected) {
		t.Fatalf("Run() error = %v, want ErrNoModelSelected", err)
	}
	if client.callCount() != 0 {
		t.Fatalf("provider call count = %d, want 0", client.callCount())
	}
	if len(store.Records()) != 0 {
		t.Fatalf("store gained %d records, want 0 for a refused turn", len(store.Records()))
	}
}

func TestRun_CancelMidStreamStopsDeltas(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	firstDelta := make(chan struct{}, 1)
	var mu sync.Mutex
	var deltas []string

	client := &fakeClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		dec := &cancelDecoder{ctx: ctx, first: contentChunk("Hello")}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}}
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Sink: func(d string) {
			mu.Lock()
			deltas = append(deltas, d)
			mu.Unlock()
			select {
			case firstDelta <- struct{}{}:
			default:
			}
		},
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-firstDelta
	retained, inFlight := runner.Cancel()
	if !inFlight {
		t.Fatalf("Cancel mid-stream inFlight = false, want true")
	}
	if retained != len("Hello") {
		t.Fatalf("Cancel retained = %d, want %d", retained, len("Hello"))
	}

	err := <-done
	if err == nil {
		t.Fatalf("Run() error = nil, want a cancellation error")
	}

	mu.Lock()
	gotDeltas := append([]string(nil), deltas...)
	mu.Unlock()
	if fmt.Sprint(gotDeltas) != fmt.Sprint([]string{"Hello"}) {
		t.Fatalf("deltas = %v, want only [Hello] (no deltas after cancel)", gotDeltas)
	}

	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted on a cancelled turn; kinds = %v", eventKinds(recs))
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatalf("assistant message recorded on a cancelled turn")
	}
	// A second cancel is idempotent: the loop has observed cancellation.
	if _, inFlight := runner.Cancel(); inFlight {
		t.Fatalf("second Cancel inFlight = true, want false")
	}
}

func TestInFlight_ReportsStreamStateWithoutCancelling(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	gate := make(chan struct{})
	blocked := make(chan struct{})
	dec := &blockingDecoder{
		pre:     [][]byte{contentChunk("Hello")},
		post:    [][]byte{finishChunk("stop")},
		gate:    gate,
		onBlock: func() { close(blocked) },
	}
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(dec), nil
		}},
	})

	if runner.InFlight() {
		t.Fatal("a runner that has not run reports a stream in flight")
	}

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-blocked
	if !runner.InFlight() {
		t.Fatal("InFlight = false while the provider stream was being consumed")
	}

	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil (InFlight must not cancel the stream it observes)", err)
	}

	if runner.InFlight() {
		t.Fatal("InFlight = true after the stream completed")
	}
	recs := store.Records()
	if !hasKind(recs, "model_response") {
		t.Fatalf("no model_response after natural completion; kinds = %v", eventKinds(recs))
	}
	terminals := turnTerminalEvents(t, recs)
	if len(terminals) != 1 || terminals[0].Outcome != events.TurnOutcomeCompleted {
		t.Fatalf("turn_terminal events = %+v, want exactly one %q", terminals, events.TurnOutcomeCompleted)
	}
}

func TestRun_ToolCallHandoff(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var got ToolCallHandoff
	var called bool
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("Let me"), toolCallChunk()),
		OnToolCalls: func(_ context.Context, h ToolCallHandoff) error {
			called = true
			got = h
			return nil
		},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if !called {
		t.Fatalf("tool-call hook was not invoked for a tool_calls finish")
	}
	if got.AssistantText != "Let me" {
		t.Fatalf("handoff AssistantText = %q, want %q", got.AssistantText, "Let me")
	}
	if len(got.ToolCallDeltas) == 0 {
		t.Fatalf("handoff ToolCallDeltas is empty, want the collected tool-call fragments")
	}
	recs := store.Records()
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a tool-call turn; the no-op default records nothing")
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatalf("assistant message recorded for a tool-call turn; should be deferred to g370")
	}
}

// A clean stream carrying only tool-call deltas — zero assistant-content deltas —
// still hands off to OnToolCalls instead of being classified as empty_response
// (preserve the tool-call seam for zero-content streams).
// If the empty-response check ran before the tool-call branch it would steal this
// exact case, so this pins their order.
func TestRun_ZeroContentToolCallHandoff(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var got ToolCallHandoff
	var called bool
	runner := New(Deps{
		Active:      selectedState("openai", "gpt-x", model.EffortDefault),
		Store:       store,
		Client:      streamClient(toolCallChunk()),
		OnToolCalls: func(_ context.Context, h ToolCallHandoff) error { called = true; got = h; return nil },
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if !called {
		t.Fatalf("tool-call hook not invoked for a zero-content tool_calls stream")
	}
	if got.AssistantText != "" {
		t.Fatalf("handoff AssistantText = %q, want empty for a zero-content stream", got.AssistantText)
	}
	if len(got.ToolCallDeltas) == 0 {
		t.Fatalf("handoff ToolCallDeltas is empty, want the collected tool-call fragments")
	}
	recs := store.Records()
	if hasKind(recs, "provider_request_failed") {
		t.Fatalf("provider_request_failed emitted for a zero-content tool-call stream; kinds = %v", eventKinds(recs))
	}
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for a zero-content tool-call stream")
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatalf("assistant message recorded for a zero-content tool-call stream; should be deferred to g370")
	}
}

// An unsupported effort is dropped, emits model_effort_unsupported, and runs
// the flush hook before the provider call so the drop is durable on disk before
// the fake provider is allowed to return (durability boundary).
func TestRun_UnsupportedEffortDurableBeforeProviderReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)

	entered := make(chan struct{})
	release := make(chan struct{})
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		close(entered)
		<-release
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}

	flushed := false
	runner := New(Deps{
		Active: selectedState("openai", "ghost-model", "high"),
		Store:  store,
		Client: client,
		FlushUnsupported: func() error {
			flushed = true
			_, _, err := store.Flush(context.Background())
			return err
		},
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-entered // provider reached: the flush hook has already run
	if !flushed {
		t.Fatalf("provider call started before the flush hook ran")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted session: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session: %v", err)
	}
	unsupportedIdx, turnIdx := -1, -1
	for i, r := range reloaded.Records {
		if e, ok := r.(sessions.Event); ok {
			switch e.Kind {
			case "model_effort_unsupported":
				unsupportedIdx = i
			case "model_turn":
				turnIdx = i
			}
		}
	}
	if unsupportedIdx == -1 || turnIdx == -1 || unsupportedIdx >= turnIdx {
		t.Fatalf("on-disk records: model_effort_unsupported(%d) must precede model_turn(%d) before provider returns; kinds = %v",
			unsupportedIdx, turnIdx, eventKinds(reloaded.Records))
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
}

// An unsupported-effort flush failure routes through the per-turn
// write-failure protocol (records retained, session_write_failed appended, notice
// rendered) and, because it returns the error, the provider call never starts.
func TestRun_UnsupportedEffortFlushFailureBlocksProvider(t *testing.T) {
	// Parent dir is missing so the atomic write fails with a real WriteReason.
	path := filepath.Join(t.TempDir(), "missing", "session.json")
	store := storeAt(path)
	notice := &recordingNotice{}

	client := streamClient(contentChunk("ok"), finishChunk("stop"))
	runner := New(Deps{
		Active: selectedState("openai", "ghost-model", "high"),
		Store:  store,
		Client: client,
		// Production-style flush binding: flush, route an atomic-write failure
		// through sessionfailures, and return the error so the provider is blocked.
		FlushUnsupported: func() error {
			cat, reason, ferr := store.Flush(context.Background())
			if ferr == nil {
				return nil
			}
			if reason != sessions.ReasonNone {
				if herr := sessionfailures.HandleWriteFailure(reason, cat, store.Path(), ferr, store, notice); herr != nil {
					return errors.Join(ferr, herr)
				}
			}
			return ferr
		},
	})

	err := runner.Run(context.Background())
	if err == nil {
		t.Fatalf("Run() error = nil, want the flush failure to propagate")
	}
	if client.callCount() != 0 {
		t.Fatalf("provider call count = %d, want 0 on an unhandled flush failure", client.callCount())
	}

	recs := store.Records()
	// Retained in-memory records: both start-of-turn events survive the failure.
	if !hasKind(recs, "model_effort_unsupported") || !hasKind(recs, "model_turn") {
		t.Fatalf("start-of-turn records not retained; kinds = %v", eventKinds(recs))
	}
	if !hasKind(recs, "session_write_failed") {
		t.Fatalf("session_write_failed not appended; kinds = %v", eventKinds(recs))
	}
	if notice.count() != 1 {
		t.Fatalf("notice rendered %d times, want 1", notice.count())
	}
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted despite a blocked provider call")
	}
}

// --- provider-stream idle detector ------------------------------------------

// A provider stream that stalls past the idle threshold emits exactly one durable
// provider_stream_idle event for the round with all five fields populated, proven by
// reloading the real session store while stream.Next() is still blocked; the turn
// then completes normally.
func TestRun_BlockedStreamEmitsProviderStreamIdleOnce(t *testing.T) {
	onBlock := deterministicIdle(t)
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	gate := make(chan struct{})
	idle := make(chan StreamIdleInfo, 1)
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return blockingStream(&blockingDecoder{
			pre:     [][]byte{contentChunk("hi")},
			gate:    gate,
			post:    [][]byte{finishChunk("stop")},
			onBlock: onBlock,
		}), nil
	}}
	runner := New(Deps{
		Active:               selectedState("openai", "gpt-x", model.EffortDefault),
		Store:                store,
		Client:               client,
		Flush:                storeFlush(store),
		OnProviderStreamIdle: func(info StreamIdleInfo) { idle <- info },
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	// The idle hook fires while stream.Next() is still blocked on the gate; the durable
	// event was flushed before the hook, so reload it from disk BEFORE releasing.
	info := <-idle
	if info.Provider != "openai" || info.ModelID != "gpt-x" {
		t.Fatalf("idle hook identity = %+v, want openai/gpt-x", info)
	}
	if info.PartialChars != int64(len("hi")) {
		t.Fatalf("idle hook partial_chars = %d, want %d", info.PartialChars, len("hi"))
	}
	if info.IdleMs < 0 || info.RoundElapsedMs < 0 {
		t.Fatalf("idle hook durations = %+v, want non-negative", info)
	}

	idleEvents := providerStreamIdleEvents(t, diskRecords(t, store))
	if len(idleEvents) != 1 {
		t.Fatalf("persisted provider_stream_idle events before unblock = %d, want 1", len(idleEvents))
	}
	if ev := idleEvents[0]; ev.Provider != "openai" || ev.ModelID != "gpt-x" ||
		ev.PartialChars != int64(len("hi")) || ev.IdleMs < 0 || ev.RoundElapsedMs < 0 {
		t.Fatalf("persisted idle event = %+v, want openai/gpt-x with %d partial chars and non-negative durations", ev, len("hi"))
	}

	close(gate) // let the stream finish
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	final := diskRecords(t, store)
	if got := len(providerStreamIdleEvents(t, final)); got != 1 {
		t.Fatalf("provider_stream_idle events after completion = %d, want exactly 1", got)
	}
	msgs := assistantMessages(final)
	if len(msgs) != 1 || msgs[0].Content.Text() != "hi" {
		t.Fatalf("assistant messages = %+v, want one %q", msgs, "hi")
	}
	if !hasKind(final, "model_response") {
		t.Fatalf("missing model_response; kinds = %v", eventKinds(final))
	}
}

// A chunk arriving after an idle crossing fires the live activity hook exactly once
// (so the UI can clear the waiting copy) and does NOT emit a second durable event for
// the same round.
func TestRun_ProviderStreamIdleActivityHookClearsAfterLaterChunk(t *testing.T) {
	onBlock := deterministicIdle(t)
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	gate := make(chan struct{})
	idle := make(chan StreamIdleInfo, 1)
	var activity int32
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return blockingStream(&blockingDecoder{
			pre:     [][]byte{contentChunk("a")},
			gate:    gate,
			post:    [][]byte{contentChunk("b"), finishChunk("stop")},
			onBlock: onBlock,
		}), nil
	}}
	runner := New(Deps{
		Active:                   selectedState("openai", "gpt-x", model.EffortDefault),
		Store:                    store,
		Client:                   client,
		Flush:                    storeFlush(store),
		OnProviderStreamIdle:     func(info StreamIdleInfo) { idle <- info },
		OnProviderStreamActivity: func() { atomic.AddInt32(&activity, 1) },
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-idle      // idle crossed while blocked
	close(gate) // a later chunk arrives -> activity hook clears the idle state
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := atomic.LoadInt32(&activity); got != 1 {
		t.Fatalf("activity hook fired %d times, want exactly 1 after the later chunk", got)
	}
	recs := diskRecords(t, store)
	if got := len(providerStreamIdleEvents(t, recs)); got != 1 {
		t.Fatalf("provider_stream_idle events = %d, want exactly 1 (no second durable event for the same round)", got)
	}
	msgs := assistantMessages(recs)
	if len(msgs) != 1 || msgs[0].Content.Text() != "ab" {
		t.Fatalf("assistant messages = %+v, want one %q", msgs, "ab")
	}
}

// A stalled stream that crosses idle and then ends with no later chunk (clean EOF)
// must NOT fire the live activity hook: activity reports a real post-idle chunk, so an
// idle-pending read that returns ok=false leaves the downstream waiting state set.
func TestRun_ProviderStreamIdleNoActivityHookOnEndWithoutChunk(t *testing.T) {
	onBlock := deterministicIdle(t)
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	gate := make(chan struct{})
	idle := make(chan StreamIdleInfo, 1)
	var activity int32
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return blockingStream(&blockingDecoder{
			pre:     [][]byte{contentChunk("hi")},
			gate:    gate, // released with no post chunk -> stream ends after the idle crossing
			onBlock: onBlock,
		}), nil
	}}
	runner := New(Deps{
		Active:                   selectedState("openai", "gpt-x", model.EffortDefault),
		Store:                    store,
		Client:                   client,
		Flush:                    storeFlush(store),
		OnProviderStreamIdle:     func(info StreamIdleInfo) { idle <- info },
		OnProviderStreamActivity: func() { atomic.AddInt32(&activity, 1) },
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()

	<-idle      // idle crossed while blocked
	close(gate) // stream ends without a later chunk
	<-done
	if got := atomic.LoadInt32(&activity); got != 0 {
		t.Fatalf("activity hook fired %d times, want 0 when the stream ends without a post-idle chunk", got)
	}
}

// Usage-only and tool-call chunks count as stream activity exactly like content
// chunks: one arriving before the stall is the activity the idle timing is measured
// from, and one arriving after an idle crossing fires the resume hook once and emits no
// second durable event. Guards against a regression that tracked activity for content
// chunks only.
func TestRun_ProviderStreamIdleNonContentChunkActivity(t *testing.T) {
	// A non-content chunk before the stall still lets the round reach the idle branch
	// and emit its one durable event.
	t.Run("usage-only chunk before the stall", func(t *testing.T) {
		onBlock := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		idle := make(chan StreamIdleInfo, 1)
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{usageChunk(10, 5)},
				gate:    gate,
				post:    [][]byte{contentChunk("hi"), finishChunk("stop")},
				onBlock: onBlock,
			}), nil
		}}
		runner := New(Deps{
			Active:               selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                store,
			Client:               client,
			Flush:                storeFlush(store),
			OnProviderStreamIdle: func(info StreamIdleInfo) { idle <- info },
		})

		done := make(chan error, 1)
		go func() { done <- runner.Run(context.Background()) }()
		info := <-idle // idle crossed after the usage-only chunk, before any content
		if info.PartialChars != 0 {
			t.Fatalf("idle partial_chars = %d, want 0 (no content had streamed yet)", info.PartialChars)
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if got := len(providerStreamIdleEvents(t, diskRecords(t, store))); got != 1 {
			t.Fatalf("provider_stream_idle events = %d, want exactly 1", got)
		}
	})

	t.Run("tool-call chunk before the stall", func(t *testing.T) {
		onBlock := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		idle := make(chan StreamIdleInfo, 1)
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{toolCallChunk()},
				gate:    gate,
				onBlock: onBlock,
			}), nil
		}}
		runner := New(Deps{
			Active:               selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                store,
			Client:               client,
			Flush:                storeFlush(store),
			OnProviderStreamIdle: func(info StreamIdleInfo) { idle <- info },
			OnToolCalls:          func(context.Context, ToolCallHandoff) error { return nil },
		})

		done := make(chan error, 1)
		go func() { done <- runner.Run(context.Background()) }()
		<-idle
		close(gate)
		if err := <-done; err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if got := len(providerStreamIdleEvents(t, diskRecords(t, store))); got != 1 {
			t.Fatalf("provider_stream_idle events = %d, want exactly 1", got)
		}
	})

	// A non-content chunk arriving after the idle crossing fires the resume hook once
	// (clearing the waiting state) and adds no second durable event for the round.
	t.Run("usage-only chunk after idle", func(t *testing.T) {
		onBlock := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		idle := make(chan StreamIdleInfo, 1)
		var activity int32
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{contentChunk("hi")},
				gate:    gate,
				post:    [][]byte{usageChunk(10, 5), finishChunk("stop")},
				onBlock: onBlock,
			}), nil
		}}
		runner := New(Deps{
			Active:                   selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                    store,
			Client:                   client,
			Flush:                    storeFlush(store),
			OnProviderStreamIdle:     func(info StreamIdleInfo) { idle <- info },
			OnProviderStreamActivity: func() { atomic.AddInt32(&activity, 1) },
		})

		done := make(chan error, 1)
		go func() { done <- runner.Run(context.Background()) }()
		<-idle
		close(gate) // usage-only chunk arrives first after the stall
		if err := <-done; err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if got := atomic.LoadInt32(&activity); got != 1 {
			t.Fatalf("activity hook fired %d times, want 1 after a usage-only post-idle chunk", got)
		}
		if got := len(providerStreamIdleEvents(t, diskRecords(t, store))); got != 1 {
			t.Fatalf("provider_stream_idle events = %d, want exactly 1 (no second durable event)", got)
		}
	})

	t.Run("tool-call chunk after idle", func(t *testing.T) {
		onBlock := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		idle := make(chan StreamIdleInfo, 1)
		var activity int32
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{contentChunk("hi")},
				gate:    gate,
				post:    [][]byte{toolCallChunk()},
				onBlock: onBlock,
			}), nil
		}}
		runner := New(Deps{
			Active:                   selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                    store,
			Client:                   client,
			Flush:                    storeFlush(store),
			OnProviderStreamIdle:     func(info StreamIdleInfo) { idle <- info },
			OnProviderStreamActivity: func() { atomic.AddInt32(&activity, 1) },
			OnToolCalls:              func(context.Context, ToolCallHandoff) error { return nil },
		})

		done := make(chan error, 1)
		go func() { done <- runner.Run(context.Background()) }()
		<-idle
		close(gate) // tool-call chunk arrives after the stall
		if err := <-done; err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if got := atomic.LoadInt32(&activity); got != 1 {
			t.Fatalf("activity hook fired %d times, want 1 after a tool-call post-idle chunk", got)
		}
		if got := len(providerStreamIdleEvents(t, diskRecords(t, store))); got != 1 {
			t.Fatalf("provider_stream_idle events = %d, want exactly 1 (no second durable event)", got)
		}
	})
}

// A user cancel that races the idle timer must not surface a false idle diagnostic:
// once streamCtx is cancelled the round follows the cancellation path and emits neither
// a durable provider_stream_idle event nor the live idle hook, even if the idle timer
// becomes ready while the outstanding read is still blocked.
func TestRun_ProviderStreamNoIdleOnCancelRace(t *testing.T) {
	// Cancel arrives before the idle timer fires: the idle branch's recheck sees the
	// cancellation and takes the cancel path.
	t.Run("cancel before idle timer", func(t *testing.T) {
		fireIdle := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		blocked := make(chan struct{}, 1)
		var idleHook int32
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{contentChunk("hi")},
				gate:    gate,
				err:     context.Canceled,
				onBlock: func() { blocked <- struct{}{} },
			}), nil
		}}
		runner := New(Deps{
			Active:               selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                store,
			Client:               client,
			Flush:                storeFlush(store),
			OnProviderStreamIdle: func(StreamIdleInfo) { atomic.AddInt32(&idleHook, 1) },
		})

		done := make(chan error, 1)
		go func() { done <- runner.Run(context.Background()) }()

		<-blocked       // the read is now blocked inside Next()
		runner.Cancel() // cancel streamCtx while the read is blocked
		fireIdle()      // make the idle timer ready after cancellation
		close(gate)     // release the blocked read so the turn can unwind
		<-done

		if got := atomic.LoadInt32(&idleHook); got != 0 {
			t.Fatalf("idle hook fired %d times, want 0 for a cancelled stream", got)
		}
		recs := diskRecords(t, store)
		if got := len(providerStreamIdleEvents(t, recs)); got != 0 {
			t.Fatalf("provider_stream_idle events = %d, want 0 for a cancelled stream", got)
		}
	})

	// The caller's PARENT context is cancelled, not Runner.Cancel, so r.cancelled stays
	// false and only streamCtx.Done() marks the cancellation. The seam pauses the idle
	// branch after it has already won the outer select; the test cancels the parent during
	// that pause, so the branch resumes with streamCtx.Done() ready. The priority check
	// must consult streamCtx.Done() and suppress the emit even though r.cancelled is false —
	// this is the case the r.cancelled recheck alone cannot catch.
	t.Run("parent context cancel during pre-emit pause", func(t *testing.T) {
		fireIdle := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		blocked := make(chan struct{}, 1)
		atEmit := make(chan struct{})
		release := make(chan struct{})
		restore := beforeIdleEmit
		beforeIdleEmit = func() {
			atEmit <- struct{}{}
			<-release
		}
		t.Cleanup(func() { beforeIdleEmit = restore })
		var idleHook int32
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{contentChunk("hi")},
				gate:    gate,
				err:     context.Canceled,
				onBlock: func() { blocked <- struct{}{} },
			}), nil
		}}
		runner := New(Deps{
			Active:               selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                store,
			Client:               client,
			Flush:                storeFlush(store),
			OnProviderStreamIdle: func(StreamIdleInfo) { atomic.AddInt32(&idleHook, 1) },
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runner.Run(ctx) }()

		<-blocked      // the read is blocked inside Next()
		fireIdle()     // idle branch wins the outer select and pauses at the seam
		<-atEmit       // paused before the priority check
		cancel()       // cancel the PARENT context; streamCtx.Done() now ready, r.cancelled false
		close(release) // resume; the priority check must see streamCtx.Done() and suppress
		close(gate)    // release the blocked read so the turn can unwind
		<-done

		if got := atomic.LoadInt32(&idleHook); got != 0 {
			t.Fatalf("idle hook fired %d times, want 0 for a parent-context cancel", got)
		}
		recs := diskRecords(t, store)
		if got := len(providerStreamIdleEvents(t, recs)); got != 0 {
			t.Fatalf("provider_stream_idle events = %d, want 0 for a parent-context cancel", got)
		}
	})

	// Cancel arrives at the last instant before the diagnostic is committed: the seam
	// pauses the idle branch immediately before its synchronized recheck, the test
	// cancels during that pause, and the recheck must still suppress the emit.
	t.Run("cancel during pre-emit pause", func(t *testing.T) {
		fireIdle := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		blocked := make(chan struct{}, 1)
		atEmit := make(chan struct{})
		release := make(chan struct{})
		restore := beforeIdleEmit
		beforeIdleEmit = func() {
			atEmit <- struct{}{}
			<-release
		}
		t.Cleanup(func() { beforeIdleEmit = restore })
		var idleHook int32
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{contentChunk("hi")},
				gate:    gate,
				err:     context.Canceled,
				onBlock: func() { blocked <- struct{}{} },
			}), nil
		}}
		runner := New(Deps{
			Active:               selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                store,
			Client:               client,
			Flush:                storeFlush(store),
			OnProviderStreamIdle: func(StreamIdleInfo) { atomic.AddInt32(&idleHook, 1) },
		})

		done := make(chan error, 1)
		go func() { done <- runner.Run(context.Background()) }()

		<-blocked       // the read is blocked inside Next()
		fireIdle()      // fire the idle timer so the idle branch runs
		<-atEmit        // idle branch paused just before the recheck/emit
		runner.Cancel() // cancel now, in the window the regression exploited
		close(release)  // let the idle branch reach its synchronized recheck
		close(gate)     // release the blocked read so the turn can unwind
		<-done

		if got := atomic.LoadInt32(&idleHook); got != 0 {
			t.Fatalf("idle hook fired %d times, want 0 for a last-moment cancel", got)
		}
		recs := diskRecords(t, store)
		if got := len(providerStreamIdleEvents(t, recs)); got != 0 {
			t.Fatalf("provider_stream_idle events = %d, want 0 for a last-moment cancel", got)
		}
	})

	// The reverse ordering: the idle branch wins the race and commits the durable event
	// while holding r.mu, so a Cancel issued at that moment blocks behind the same lock and
	// cannot complete until the emit releases it. The durable append+flush therefore runs
	// under the cancellation lock — proven directly: a TryLock from the emit seam must fail
	// because the emitting goroutine already holds r.mu. It would succeed under the
	// unlock-before-emit regression, where the durable append runs after the lock is
	// released and a racing Cancel can slip in first.
	t.Run("durable emit holds the cancellation lock", func(t *testing.T) {
		fireIdle := deterministicIdle(t)
		store := storeAt(filepath.Join(t.TempDir(), "session.json"))
		gate := make(chan struct{})
		blocked := make(chan struct{}, 1)
		inEmit := make(chan struct{})
		release := make(chan struct{})
		var idleHook int32
		client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return blockingStream(&blockingDecoder{
				pre:     [][]byte{contentChunk("hi")},
				gate:    gate,
				err:     context.Canceled,
				onBlock: func() { blocked <- struct{}{} },
			}), nil
		}}
		runner := New(Deps{
			Active:               selectedState("openai", "gpt-x", model.EffortDefault),
			Store:                store,
			Client:               client,
			Flush:                storeFlush(store),
			OnProviderStreamIdle: func(StreamIdleInfo) { atomic.AddInt32(&idleHook, 1) },
		})
		restore := duringIdleEmit
		duringIdleEmit = func() {
			if runner.mu.TryLock() {
				runner.mu.Unlock()
				t.Errorf("r.mu was not held during the durable idle emit: a racing Cancel could preempt it")
			}
			inEmit <- struct{}{}
			<-release
		}
		t.Cleanup(func() { duringIdleEmit = restore })

		done := make(chan error, 1)
		go func() { done <- runner.Run(context.Background()) }()

		<-blocked  // the read is blocked inside Next()
		fireIdle() // fire the idle timer; the idle branch wins and commits the emit
		<-inEmit   // idle branch holds r.mu with the durable event already appended+flushed

		// A Cancel issued now blocks on r.mu until the emit releases it.
		cancelReturned := make(chan struct{})
		go func() { runner.Cancel(); close(cancelReturned) }()
		close(release) // idle branch unlocks; Cancel proceeds
		<-cancelReturned
		close(gate) // release the blocked read so the turn can unwind
		<-done

		if got := atomic.LoadInt32(&idleHook); got != 1 {
			t.Fatalf("idle hook fired %d times, want 1 for an emit that won the race", got)
		}
		recs := diskRecords(t, store)
		if got := len(providerStreamIdleEvents(t, recs)); got != 1 {
			t.Fatalf("provider_stream_idle events = %d, want 1 for an emit that won the race", got)
		}
	})
}

// Two idle attempts under retry each emit their own one-shot event: a retry's
// runAttempt starts a fresh detector, so stale idle state from the failed attempt
// does not leak into the next attempt. The idle hook releases each attempt's stall
// once its durable event is written, so the test needs no wall-clock sleep.
func TestRun_ProviderStreamIdleRetryRounds(t *testing.T) {
	onBlock := deterministicIdle(t)
	noSleep(t)
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	gates := []chan struct{}{make(chan struct{}), make(chan struct{})}
	var mu sync.Mutex
	var infos []StreamIdleInfo
	client := steppedClient(func(call int) (provider.Response, error) {
		gate := gates[call-1]
		if call == 1 {
			// idle, then a mid-stream drop -> retryable.
			return blockingStream(&blockingDecoder{pre: [][]byte{contentChunk("x")}, gate: gate, err: io.ErrUnexpectedEOF, onBlock: onBlock}), nil
		}
		// idle, then a clean completion.
		return blockingStream(&blockingDecoder{pre: [][]byte{contentChunk("done")}, gate: gate, post: [][]byte{finishChunk("stop")}, onBlock: onBlock}), nil
	})
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           retryOn(),
		RollbackPartial: func() {},
		Flush:           storeFlush(store),
		OnProviderStreamIdle: func(info StreamIdleInfo) {
			mu.Lock()
			n := len(infos)
			infos = append(infos, info)
			mu.Unlock()
			close(gates[n]) // release this attempt's stall now that its idle event is durable
		},
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil (recovered on the second attempt)", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (idle+drop, then idle+success)", client.callCount())
	}
	recs := diskRecords(t, store)
	if got := len(providerStreamIdleEvents(t, recs)); got != 2 {
		t.Fatalf("provider_stream_idle events = %d, want 2 (one per attempt's fresh one-shot detector)", got)
	}
	mu.Lock()
	fired := len(infos)
	mu.Unlock()
	if fired != 2 {
		t.Fatalf("idle hook fired %d times, want 2 (once per attempt)", fired)
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response for the recovered turn; kinds = %v", eventKinds(recs))
	}
}

// The idle diagnostic is an event record only: it adds no assistant/user/tool
// message and is dropped by request construction, so it never reaches model context.
func TestRun_ProviderStreamIdleNotModelVisible(t *testing.T) {
	onBlock := deterministicIdle(t)
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	gate := make(chan struct{})
	idle := make(chan StreamIdleInfo, 1)
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return blockingStream(&blockingDecoder{pre: [][]byte{contentChunk("hi")}, gate: gate, post: [][]byte{finishChunk("stop")}, onBlock: onBlock}), nil
	}}
	active := selectedState("openai", "gpt-x", model.EffortDefault)
	runner := New(Deps{
		Active:               active,
		Store:                store,
		Client:               client,
		Flush:                storeFlush(store),
		OnProviderStreamIdle: func(info StreamIdleInfo) { idle <- info },
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()
	<-idle
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	recs := store.Records()
	if !hasKind(recs, events.KindProviderStreamIdle) {
		t.Fatalf("missing provider_stream_idle event; kinds = %v", eventKinds(recs))
	}
	msgs := messagesFromRecords(recs)
	if len(msgs) != 1 || msgs[0].Role != "assistant" || msgs[0].Content != "hi" {
		t.Fatalf("request history = %+v, want only the assistant %q message (idle event excluded)", msgs, "hi")
	}
	req, _, _, ok := BuildRequest(active, store, "", nil)
	if !ok {
		t.Fatal("BuildRequest ok = false, want true")
	}
	if len(req.Messages) != 1 || req.Messages[0].Role != "assistant" {
		t.Fatalf("BuildRequest messages = %+v, want exactly the assistant turn, no idle diagnostic", req.Messages)
	}
}

func TestRun_ProviderStreamIdleAndTerminalWriteFailureFailsTurn(t *testing.T) {
	onBlock := deterministicIdle(t)
	store := storeAt(filepath.Join(t.TempDir(), "missing", "session.json"))
	gate := make(chan struct{})
	idle := make(chan StreamIdleInfo, 1)
	var writeFailures int32
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		return blockingStream(&blockingDecoder{pre: [][]byte{contentChunk("hi")}, gate: gate, post: [][]byte{finishChunk("stop")}, onBlock: onBlock}), nil
	}}
	runner := New(Deps{
		Active:               selectedState("openai", "gpt-x", model.EffortDefault),
		Store:                store,
		Client:               client,
		OnProviderStreamIdle: func(info StreamIdleInfo) { idle <- info },
		OnFailureWrite: func(_ fserrors.Category, reason sessions.WriteReason, _ error) {
			if reason != sessions.ReasonNone {
				atomic.AddInt32(&writeFailures, 1)
			}
		},
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()
	<-idle
	close(gate)
	if err := <-done; err == nil {
		t.Fatal("Run() error = nil after a terminal-record flush failure")
	}
	if got := atomic.LoadInt32(&writeFailures); got != 2 {
		t.Fatalf("OnFailureWrite fired %d times, want 2 for the idle and terminal flush failures", got)
	}
	if !hasKind(store.Records(), "model_response") {
		t.Fatalf("missing model_response; the terminal write failure must occur after the completed reply is recorded; kinds = %v", eventKinds(store.Records()))
	}
}

// --- OpenAI ChatGPT (Responses API) adapter through the turn contract -------
//
// Drive the real provider.NewChatGPTClient adapter — request, two-header
// auth, Responses SSE bridge, and safe errors — through Runner.Run against a fake
// ChatGPT/Codex server, proving the bridged stream consumes identically to the
// chat-completions stream the other tests use. The pinned origin is non-overridable,
// so the fake server is reached via a transport that rewrites only the host (the
// request URL stays chatgpt.com), not a base-URL override.

const (
	chatGPTTestToken   = "sk-turn-secret-001"
	chatGPTTestAccount = "acct-turn-002"
)

type hostRewriteTransport struct{ target *url.URL }

func (rt hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = rt.target.Scheme
	clone.URL.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

// chatGPTAdapterTo builds the real ChatGPT adapter pointed (via host rewrite only)
// at a fake server that serves the given Responses SSE events, or a non-2xx body
// when status is non-OK.
func chatGPTAdapterTo(t *testing.T, status int, events ...string) provider.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			if len(events) > 0 {
				_, _ = io.WriteString(w, events[0])
			}
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, ev := range events {
			_, _ = io.WriteString(w, "data: "+ev+"\n\n")
		}
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return provider.NewChatGPTClient(provider.ChatGPTClientConfig{
		AccessToken: chatGPTTestToken,
		AccountID:   chatGPTTestAccount,
		HTTPClient:  &http.Client{Transport: hostRewriteTransport{target: u}},
	})
}

func recordsLeak(recs []sessions.Record, secret string) bool {
	for _, r := range recs {
		switch rec := r.(type) {
		case sessions.Event:
			if strings.Contains(string(rec.Payload), secret) {
				return true
			}
		case sessions.Message:
			if strings.Contains(rec.Content.Text(), secret) {
				return true
			}
		}
	}
	return false
}

func TestRun_ChatGPTAdapterStreamsTextAndUsage(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var deltas []string
	var usageIn, usageOut int64
	runner := New(Deps{
		Active: selectedState(provider.ChatGPTProviderID, "gpt-5.5", model.EffortDefault),
		Store:  store,
		Client: chatGPTAdapterTo(t, http.StatusOK,
			`{"type":"response.output_text.delta","delta":"Hel"}`,
			`{"type":"response.output_text.delta","delta":"lo"}`,
			`{"type":"response.completed","response":{"usage":{"input_tokens":7,"output_tokens":2,"total_tokens":9}}}`,
		),
		Sink:  func(d string) { deltas = append(deltas, d) },
		Usage: func(in, out int64) { usageIn, usageOut = in, out },
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := strings.Join(deltas, ""); got != "Hello" {
		t.Fatalf("streamed content = %q, want %q", got, "Hello")
	}
	mr := decodeModelResponse(t, store.Records())
	if mr.InputTokens != 7 || mr.OutputTokens != 2 {
		t.Fatalf("model_response tokens = (%d, %d), want (7, 2) from the Responses usage", mr.InputTokens, mr.OutputTokens)
	}
	if usageIn != 7 || usageOut != 2 {
		t.Fatalf("Usage callback = (%d, %d), want (7, 2)", usageIn, usageOut)
	}
	msgs := assistantMessages(store.Records())
	if len(msgs) != 1 || msgs[0].Content.Text() != "Hello" {
		t.Fatalf("assistant messages = %+v, want one %q", msgs, "Hello")
	}
}

func TestRun_ChatGPTAdapterToolCallHandsOff(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var handoff ToolCallHandoff
	var hookCalls int
	runner := New(Deps{
		Active: selectedState(provider.ChatGPTProviderID, "gpt-5.5", model.EffortDefault),
		Store:  store,
		Client: chatGPTAdapterTo(t, http.StatusOK,
			`{"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"bash","arguments":""}}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"cmd\":\"ls\"}"}`,
			`{"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"cmd\":\"ls\"}"}`,
			`{"type":"response.completed","response":{"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}`,
		),
		OnToolCalls: func(_ context.Context, h ToolCallHandoff) error { hookCalls++; handoff = h; return nil },
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if hookCalls != 1 {
		t.Fatalf("OnToolCalls fired %d times, want 1", hookCalls)
	}
	calls, err := assembleToolCalls(handoff.ToolCallDeltas)
	if err != nil {
		t.Fatalf("assembleToolCalls() error = %v", err)
	}
	if len(calls) != 1 || calls[0].ID != "call_1" || calls[0].Name != "bash" || calls[0].Arguments != `{"cmd":"ls"}` {
		t.Fatalf("assembled calls = %+v, want one call_1/bash/{\"cmd\":\"ls\"}", calls)
	}
	// A tool-call round hands off before recording model_response.
	if hasKind(store.Records(), "model_response") {
		t.Fatalf("model_response emitted on a tool-call handoff round")
	}
}

func TestRun_ChatGPTAdapterHTTPErrorRedactedThroughTurn(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	var notices []string
	body := `{"error":{"message":"denied for ` + chatGPTTestToken + ` on account ` + chatGPTTestAccount + `"}}`
	runner := New(Deps{
		Active: selectedState(provider.ChatGPTProviderID, "gpt-5.5", model.EffortDefault),
		Store:  store,
		Client: chatGPTAdapterTo(t, http.StatusUnauthorized, body),
		Notice: func(text string) { notices = append(notices, text) },
	})

	err := runner.Run(context.Background())
	var httpErr *provider.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("Run() error = %v, want *provider.HTTPError", err)
	}
	if httpErr.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", httpErr.Status)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %d, want 1", len(notices))
	}
	for _, secret := range []string{chatGPTTestToken, chatGPTTestAccount} {
		if strings.Contains(notices[0], secret) {
			t.Fatalf("notice leaked %q: %s", secret, notices[0])
		}
		if recordsLeak(store.Records(), secret) {
			t.Fatalf("persisted records leaked %q", secret)
		}
	}
	if !hasKind(store.Records(), "provider_request_failed") {
		t.Fatalf("missing provider_request_failed event; kinds = %v", eventKinds(store.Records()))
	}
	if hasKind(store.Records(), "model_response") {
		t.Fatalf("model_response emitted despite an HTTP error")
	}
}

func turnTerminalEvents(t *testing.T, recs []sessions.Record) []events.TurnTerminal {
	t.Helper()
	return eventsOf[events.TurnTerminal](t, recs, events.KindTurnTerminal, "turn_terminal")
}

func onlyTerminal(t *testing.T, store *sessions.Store) events.TurnTerminal {
	t.Helper()
	recs := diskRecords(t, store)
	terminals := turnTerminalEvents(t, recs)
	if len(terminals) != 1 {
		t.Fatalf("persisted turn_terminal events = %d, want exactly 1; kinds = %v", len(terminals), eventKinds(recs))
	}
	return terminals[0]
}

func TestRun_CompletedRoundRecordsCorrelatedTerminal(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("hi"), finishChunk("stop")),
		Flush:  storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	recs := diskRecords(t, store)
	terminals := turnTerminalEvents(t, recs)
	if len(terminals) != 1 {
		t.Fatalf("persisted turn_terminal events = %d, want exactly 1 (no duplicate); kinds = %v", len(terminals), eventKinds(recs))
	}
	got := terminals[0]
	if got.Outcome != events.TurnOutcomeCompleted {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeCompleted)
	}
	if got.DispatchStarted {
		t.Fatal("dispatch_started = true for a final answer that dispatched no tools")
	}
	if got.FailurePhase != "" {
		t.Fatalf("failure_phase = %q, want empty for a completed round", got.FailurePhase)
	}
	rounds := providerRoundTripEvents(t, recs)
	if len(rounds) != 1 {
		t.Fatalf("provider_round_trip events = %d, want 1", len(rounds))
	}
	if rounds[0].TurnID != got.TurnID || rounds[0].RoundID != got.RoundID {
		t.Fatalf("provider_round_trip correlation = (%q, %q), want the terminal record's (%q, %q)",
			rounds[0].TurnID, rounds[0].RoundID, got.TurnID, got.RoundID)
	}
}

func TestRun_CancelledRoundRecordsCancelledTerminal(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	firstDelta := make(chan struct{}, 1)
	client := &fakeClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		dec := &cancelDecoder{ctx: ctx, first: contentChunk("Hello")}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}}
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
		Sink: func(string) {
			select {
			case firstDelta <- struct{}{}:
			default:
			}
		},
	})

	done := make(chan error, 1)
	go func() { done <- runner.Run(context.Background()) }()
	<-firstDelta
	runner.Cancel()
	if err := <-done; err == nil {
		t.Fatal("Run() error = nil, want a cancellation error")
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeCancelled {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeCancelled)
	}
	if got.FailurePhase != "" {
		t.Fatalf("failure_phase = %q, want empty: a cancellation is not a provider failure", got.FailurePhase)
	}
}

func TestRun_CancelledInitialRequestRecordsCancelledTerminal(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	entered := make(chan struct{})
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
			close(entered)
			<-ctx.Done()
			return provider.Response{}, ctx.Err()
		}},
		Flush: storeFlush(store),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}

	if got := onlyTerminal(t, store); got.Outcome != events.TurnOutcomeCancelled {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeCancelled)
	}
}

func TestRun_ProviderFailureRecordsTerminalWithPhase(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(finishChunk("stop")),
		Flush:  storeFlush(store),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil (empty_response is a recorded failure)", err)
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeProviderFailed {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeProviderFailed)
	}
	if got.FailurePhase != "empty_response" {
		t.Fatalf("failure_phase = %q, want empty_response", got.FailurePhase)
	}
	if got.DispatchStarted {
		t.Fatal("dispatch_started = true for a round that never reached a tool call")
	}
	prf := findProviderRequestFailed(t, diskRecords(t, store))
	if prf.Phase != "empty_response" {
		t.Fatalf("provider_request_failed phase = %q, want empty_response (existing contract preserved)", prf.Phase)
	}
}

func TestRun_InvalidResponseRecordsTerminalBeforeDispatch(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
			return provider.Response{Completion: &openai.ChatCompletion{
				Choices: []openai.ChatCompletionChoice{{Message: openai.ChatCompletionMessage{Content: "hi"}}},
			}}, nil
		}},
		Flush: storeFlush(store),
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want an invalid-response error")
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeInvalidResponse {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeInvalidResponse)
	}
	if got.DispatchStarted {
		t.Fatal("dispatch_started = true for a response that never produced a tool call")
	}
	recs := diskRecords(t, store)
	rounds := providerRoundTripEvents(t, recs)
	if len(rounds) != 1 {
		t.Fatalf("provider_round_trip events = %d, want 1", len(rounds))
	}
	if rounds[0].TurnID != got.TurnID || rounds[0].RoundID != got.RoundID {
		t.Fatalf("provider_round_trip correlation = (%q, %q), want (%q, %q)",
			rounds[0].TurnID, rounds[0].RoundID, got.TurnID, got.RoundID)
	}
	for _, m := range assistantMessages(recs) {
		if len(m.ToolCalls) > 0 {
			t.Fatalf("assistant tool-call record persisted for an invalid response; kinds = %v", eventKinds(recs))
		}
	}
}

func TestRun_EachRoundRecordsItsOwnTerminalUnderOneTurnID(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	deps := Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("hi"), finishChunk("stop")),
		Flush:  storeFlush(store),
		TurnID: ids.NewV7(),
	}
	for range 2 {
		if err := New(deps).Run(context.Background()); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	}

	terminals := turnTerminalEvents(t, diskRecords(t, store))
	if len(terminals) != 2 {
		t.Fatalf("persisted turn_terminal events = %d, want one per round", len(terminals))
	}
	if terminals[0].TurnID != deps.TurnID || terminals[1].TurnID != deps.TurnID {
		t.Fatalf("turn ids = (%q, %q), want both %q", terminals[0].TurnID, terminals[1].TurnID, deps.TurnID)
	}
	if terminals[0].RoundID == terminals[1].RoundID {
		t.Fatalf("both rounds recorded round id %q, want distinct ids", terminals[0].RoundID)
	}
}

func TestRun_TerminalWriteFailureFailsTurnAndRoutesToHandler(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "missing", "session.json"))
	var calls int
	var gotReason sessions.WriteReason
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(contentChunk("hi"), finishChunk("stop")),
		OnFailureWrite: func(_ fserrors.Category, reason sessions.WriteReason, _ error) {
			calls++
			gotReason = reason
		},
	})

	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil after a terminal-record flush failure")
	}
	if calls != 1 {
		t.Fatalf("OnFailureWrite calls = %d, want 1", calls)
	}
	if gotReason == sessions.ReasonNone {
		t.Fatal("OnFailureWrite reason = ReasonNone, want an atomic-write reason")
	}
}

func TestRun_FinalizeWriteFailureFailsTheCompletedRound(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	writeErr := errors.New("stdout closed")
	finalized := false
	runner := New(Deps{
		Active:      selectedState("openai", "gpt-x", model.EffortDefault),
		Store:       store,
		Client:      streamClient(contentChunk("hi"), finishChunk("stop")),
		Flush:       storeFlush(store),
		Finalize:    func() { finalized = true },
		FinalizeErr: func() error { return writeErr },
	})

	if err := runner.Run(context.Background()); !errors.Is(err, writeErr) {
		t.Fatalf("Run() error = %v, want the finalize write failure", err)
	}
	if !finalized {
		t.Fatal("Finalize was not called")
	}
	if got := onlyTerminal(t, store); got.Outcome != events.TurnOutcomeContinuationFailed {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeContinuationFailed)
	}
}

func TestRun_FailedAttemptFoldsItsUsageOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		decoder func(ctx context.Context, cancel context.CancelFunc) ssestream.Decoder
	}{
		{"stream error after usage", func(context.Context, context.CancelFunc) ssestream.Decoder {
			return &dropDecoder{first: usageChunk(40, 4), err: io.ErrUnexpectedEOF}
		}},
		{"cancelled after usage", func(ctx context.Context, cancel context.CancelFunc) ssestream.Decoder {
			return &cancelDecoder{ctx: ctx, first: usageChunk(40, 4), onWait: cancel}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var acc model.UsageAccumulator
			runner := New(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  storeAt(filepath.Join(t.TempDir(), "session.json")),
				Client: &fakeClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
					return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](tc.decoder(ctx, cancel), nil)}, nil
				}},
				UsageAcc: &acc,
			})

			if err := runner.Run(ctx); err == nil {
				t.Fatal("Run() error = nil, want the attempt's failure")
			}
			in, out, _, _, anomalies, hadUsage := acc.Totals()
			if in != 40 || out != 4 || !hadUsage || len(anomalies) != 0 || acc.UsageRounds() != 1 {
				t.Fatalf("accumulated = (%d, %d, had %v, anomalies %v, rounds %d), want (40, 4) folded once", in, out, hadUsage, anomalies, acc.UsageRounds())
			}
		})
	}
}

func TestRun_RetriedAttemptUsageIsCountedOnce(t *testing.T) {
	noSleep(t)
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := steppedClient(func(call int) (provider.Response, error) {
		if call == 1 {
			dec := &dropDecoder{first: usageChunk(40, 4), err: io.ErrUnexpectedEOF}
			return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("done"), finishChunk("stop"), usageChunk(50, 5))}, nil
	})
	var acc model.UsageAccumulator
	runner := New(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Retry:           retryOn(),
		RollbackPartial: func() {},
		UsageAcc:        &acc,
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil (recovered on the second attempt)", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2", client.callCount())
	}
	if mr := decodeModelResponse(t, store.Records()); mr.InputTokens != 90 || mr.OutputTokens != 9 || len(mr.Anomaly) != 0 {
		t.Fatalf("model_response = %+v, want (90, 9): each billed attempt counted once", mr)
	}
	if acc.UsageRounds() != 2 {
		t.Fatalf("usage rounds = %d, want 2", acc.UsageRounds())
	}
}
