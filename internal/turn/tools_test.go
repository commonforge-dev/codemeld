package turn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

// --- tool-call chunk fixtures (extend turn_test.go's content/finish helpers) ---

// toolFrag renders one streamed tool_calls fragment for a chunk's delta.
func toolFrag(index int, id, name, args string) string {
	return fmt.Sprintf(`{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}`, index, id, name, args)
}

// toolCallsChunk builds a streamed chunk whose delta carries the given tool_calls
// fragments and finish_reason "tool_calls".
func toolCallsChunk(frags ...string) []byte {
	return []byte(fmt.Sprintf(
		`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[%s]},"finish_reason":"tool_calls"}]}`,
		strings.Join(frags, ","),
	))
}

// --- scripted multi-round provider client ----------------------------------

// scriptedClient returns one stream per call from rounds (the last round repeats
// if the loop somehow re-issues past the script) and captures every request it
// received, so a test can assert what the follow-up turn was fed.
type scriptedClient struct {
	mu       sync.Mutex
	rounds   [][][]byte
	requests []provider.Request
}

func (c *scriptedClient) ChatCompletion(_ context.Context, req provider.Request) (provider.Response, error) {
	c.mu.Lock()
	idx := len(c.requests)
	c.requests = append(c.requests, req)
	c.mu.Unlock()
	chunks := c.rounds[len(c.rounds)-1]
	if idx < len(c.rounds) {
		chunks = c.rounds[idx]
	}
	return provider.Response{Stream: newStream(chunks...)}, nil
}

func (c *scriptedClient) request(i int) (provider.Request, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.requests) {
		return provider.Request{}, false
	}
	return c.requests[i], true
}

func (c *scriptedClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

// --- fake dispatcher --------------------------------------------------------

// fakeDispatcher is the injected ToolDispatcher seam. It records dispatch order
// and peak concurrency so scheduling tests can assert parallelism vs.
// serialization, and lets each test pin per-call plans and results. An optional
// barrier blocks every dispatch until barrierN are concurrently in flight (used
// to prove independent calls actually overlap); hold widens the dispatch window
// so a serialization bug is observable as peak concurrency > 1.
type fakeDispatcher struct {
	mu        sync.Mutex
	order     []string
	active    int
	maxActive int

	planFn   func(AssembledToolCall) (deps, targets []string)
	resultFn func(AssembledToolCall) (ToolResult, error)

	plannedBatches     []int
	plannedConcurrency int

	barrier  chan struct{}
	barrierN int
	hold     time.Duration
}

func (d *fakeDispatcher) Plan(calls []AssembledToolCall, maxConcurrency int) ToolPlan {
	d.mu.Lock()
	d.plannedBatches = append(d.plannedBatches, len(calls))
	d.plannedConcurrency = maxConcurrency
	d.mu.Unlock()

	plan := ToolPlan{Units: make([]PlannedToolCall, len(calls))}
	for i, call := range calls {
		var deps, targets []string
		if d.planFn != nil {
			deps, targets = d.planFn(call)
		}
		plan.Units[i] = PlannedToolCall{
			Call:    call,
			Deps:    deps,
			Targets: targets,
			Run:     func(ctx context.Context) (ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d *fakeDispatcher) Dispatch(ctx context.Context, call AssembledToolCall) (ToolResult, error) {
	d.mu.Lock()
	d.order = append(d.order, call.ID)
	d.active++
	if d.active > d.maxActive {
		d.maxActive = d.active
	}
	reached := d.barrier != nil && d.active == d.barrierN
	d.mu.Unlock()

	if reached {
		close(d.barrier)
	}
	if d.barrier != nil {
		select {
		case <-d.barrier:
		case <-ctx.Done():
		case <-time.After(2 * time.Second): // fail fast if a bug serializes a parallel batch
		}
	}
	if d.hold > 0 {
		time.Sleep(d.hold)
	}

	d.mu.Lock()
	d.active--
	d.mu.Unlock()

	if d.resultFn != nil {
		return d.resultFn(call)
	}
	return ToolResult{Content: "out:" + call.ID}, nil
}

func (d *fakeDispatcher) dispatchedOrder() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.order...)
}

func (d *fakeDispatcher) peakConcurrency() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.maxActive
}

// --- helpers ----------------------------------------------------------------

func toolMessages(recs []sessions.Record) []sessions.Message {
	var out []sessions.Message
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "tool" {
			out = append(out, m)
		}
	}
	return out
}

func assistantToolCallMessages(recs []sessions.Record) []sessions.Message {
	var out []sessions.Message
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "assistant" && len(m.ToolCalls) > 0 {
			out = append(out, m)
		}
	}
	return out
}

// finalAnswer is the round that ends the loop: a content reply with a stop finish.
func finalAnswer(text string) [][]byte {
	return [][]byte{contentChunk(text), finishChunk("stop")}
}

// --- assembly ---------------------------------------------------------------

func TestAssembleToolCalls_FragmentedNameAndArguments(t *testing.T) {
	deltas := [][]openai.ChatCompletionChunkChoiceDeltaToolCall{
		{{Index: 0, ID: "call_1", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "sea", Arguments: `{"q":`}}},
		{{Index: 0, Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "rch", Arguments: `"hi"}`}}},
	}
	calls, err := assembleToolCalls(deltas)
	if err != nil {
		t.Fatalf("assembleToolCalls error = %v, want nil", err)
	}
	if len(calls) != 1 {
		t.Fatalf("assembled %d calls, want 1", len(calls))
	}
	want := AssembledToolCall{ID: "call_1", Name: "search", Arguments: `{"q":"hi"}`}
	if calls[0] != want {
		t.Fatalf("assembled call = %+v, want %+v", calls[0], want)
	}
}

func TestAssembleToolCalls_MultipleIndexesOrderedByIndex(t *testing.T) {
	// Two calls whose first-seen order is reversed from their index order.
	deltas := [][]openai.ChatCompletionChunkChoiceDeltaToolCall{
		{
			{Index: 1, ID: "b", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "two", Arguments: "{}"}},
			{Index: 0, ID: "a", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "one", Arguments: "{}"}},
		},
	}
	calls, err := assembleToolCalls(deltas)
	if err != nil {
		t.Fatalf("assembleToolCalls error = %v, want nil", err)
	}
	if len(calls) != 2 || calls[0].ID != "a" || calls[1].ID != "b" {
		t.Fatalf("assembled = %+v, want [a, b] ordered by index", calls)
	}
}

func TestAssembleToolCalls_RejectsMissingIDAndName(t *testing.T) {
	noID := [][]openai.ChatCompletionChunkChoiceDeltaToolCall{
		{{Index: 0, Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "x", Arguments: "{}"}}},
	}
	if _, err := assembleToolCalls(noID); err == nil {
		t.Fatalf("assembleToolCalls(noID) error = nil, want an error for a call with no id")
	}
	noName := [][]openai.ChatCompletionChunkChoiceDeltaToolCall{
		{{Index: 0, ID: "call_1", Type: "function"}},
	}
	if _, err := assembleToolCalls(noName); err == nil {
		t.Fatalf("assembleToolCalls(noName) error = nil, want an error for a call with no function name")
	}
}

// --- loop behavior ----------------------------------------------------------

// Done-when 1: a single tool call is adapted, scheduled, dispatched, its result
// appended, and the turn re-issued to a final answer. Also pins zero-assistant-text
// handling (the tool-call round carries no content) and that the persisted
// assistant message records the call while the tool message records the result.
func TestToolLoop_SingleRoundTripToFinalAnswer(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()}, // round 1: call_1 (name "do")
		finalAnswer("all done"),
	}}
	disp := &fakeDispatcher{}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (tool round + final answer)", client.callCount())
	}
	if got := disp.dispatchedOrder(); len(got) != 1 || got[0] != "call_1" {
		t.Fatalf("dispatched = %v, want [call_1]", got)
	}

	recs := store.Records()
	asst := assistantToolCallMessages(recs)
	if len(asst) != 1 {
		t.Fatalf("assistant tool-call messages = %d, want 1", len(asst))
	}
	if asst[0].Content.Text() != "" {
		t.Fatalf("assistant tool-call content = %q, want empty (zero-text tool round)", asst[0].Content.Text())
	}
	if len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_1" || asst[0].ToolCalls[0].Type != "function" {
		t.Fatalf("assistant ToolCalls = %+v, want one function call_1", asst[0].ToolCalls)
	}
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != "out:call_1" {
		t.Fatalf("tool messages = %+v, want one answering call_1 with out:call_1", tools)
	}
	// The final answer recorded a model_response and a plain assistant reply.
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response after final answer; kinds = %v", eventKinds(recs))
	}
	if final := lastAssistantText(recs); final != "all done" {
		t.Fatalf("final assistant text = %q, want %q", final, "all done")
	}

	// The follow-up request carried the assistant tool-call message and the tool
	// result so the model could produce the final answer.
	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured")
	}
	assertContinuation(t, follow, "call_1", "out:call_1")
}

// An agentic turn records one provider_round_trip per provider round and
// exactly one turn_latency — on the final no-tool answer only — even though the
// same SubmitStart rides every round's Deps.
func TestToolLoop_RecordsPerRoundTimingAndSingleTurnLatency(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},       // round 1: tool call
		finalAnswer("all done"), // round 2: final no-tool answer
	}}
	disp := &fakeDispatcher{}
	loop := NewToolLoop(Deps{
		Active:      selectedState("openai", "gpt-x", model.EffortDefault),
		Store:       store,
		Client:      client,
		SubmitStart: time.Now().Add(-30 * time.Millisecond),
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	recs := store.Records()
	if rounds := providerRoundTripEvents(t, recs); len(rounds) != 2 {
		t.Fatalf("provider_round_trip events = %d, want 2 (one per provider round); kinds = %v", len(rounds), eventKinds(recs))
	}
	turns := turnLatencyEvents(t, recs)
	if len(turns) != 1 {
		t.Fatalf("turn_latency events = %d, want exactly 1 (final answer only); kinds = %v", len(turns), eventKinds(recs))
	}
	if turns[0].DurationMs < 0 {
		t.Fatalf("turn_latency duration_ms = %d, want >= 0", turns[0].DurationMs)
	}
}

// Done-when 1 (parallel): independent calls run concurrently through Schedule.
func TestToolLoop_ParallelIndependentCalls(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "a", "{}"), toolFrag(1, "call_b", "b", "{}"))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{barrier: make(chan struct{}), barrierN: 2}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if peak := disp.peakConcurrency(); peak != 2 {
		t.Fatalf("peak concurrency = %d, want 2 (independent calls run in parallel)", peak)
	}
	if len(toolMessages(store.Records())) != 2 {
		t.Fatalf("tool messages = %d, want 2", len(toolMessages(store.Records())))
	}
}

// Done-when 3 (dependency ordering): call_b depends on call_a, so the scheduler
// runs them in order and never concurrently.
func TestToolLoop_DependencyOrderingSerializes(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "a", "{}"), toolFrag(1, "call_b", "b", "{}"))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{
		hold: 20 * time.Millisecond,
		planFn: func(c AssembledToolCall) (deps, targets []string) {
			if c.ID == "call_b" {
				return []string{"call_a"}, nil
			}
			return nil, nil
		},
	}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if peak := disp.peakConcurrency(); peak != 1 {
		t.Fatalf("peak concurrency = %d, want 1 (dependency serializes)", peak)
	}
	if got := disp.dispatchedOrder(); len(got) != 2 || got[0] != "call_a" || got[1] != "call_b" {
		t.Fatalf("dispatched order = %v, want [call_a, call_b]", got)
	}
}

// Done-when 3 (target-conflict ordering): two calls writing the same target are
// serialized in input order even at max_concurrency 2.
func TestToolLoop_TargetConflictSerializes(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "write", "{}"), toolFrag(1, "call_b", "write", "{}"))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{
		hold: 20 * time.Millisecond,
		planFn: func(AssembledToolCall) (deps, targets []string) {
			return nil, []string{"/repo/out.txt"} // both write the same file
		},
	}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if peak := disp.peakConcurrency(); peak != 1 {
		t.Fatalf("peak concurrency = %d, want 1 (conflicting writes serialize)", peak)
	}
	if got := disp.dispatchedOrder(); len(got) != 2 || got[0] != "call_a" || got[1] != "call_b" {
		t.Fatalf("dispatched order = %v, want [call_a, call_b] (input order)", got)
	}
}

// A user-denied result halts the assistant attempt. The deny
// envelope is appended (through DeliverDeny) keyed to the call so the transcript stays
// well-formed, but the loop does not re-issue the model — the provider call count stays
// at one, no model_response is recorded, and no final answer is synthesized — Run returns
// nil (a denial is an in-band refusal, not an internal error), and Denied() reports the
// terminal stop. A friendly denial line names the refused tool and reason without exposing
// the raw envelope JSON. The scripted final answer must never be reached.
func TestToolLoop_UserDeniedResultAppendedAndStops(t *testing.T) {
	const denyEnvelope = `{"denied_by":"user","reason":"out of repo scope"}`
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "run the command"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},                     // round 1: call_1
		finalAnswer("the result is the same"), // must never be issued after a denial
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: denyEnvelope, Denied: true}, nil
	}}
	var notices, providerNotices []string
	loop := NewToolLoop(Deps{
		Active:     selectedState("openai", "gpt-x", model.EffortDefault),
		Store:      store,
		Client:     client,
		Notice:     func(text string) { providerNotices = append(providerNotices, text) },
		ToolNotice: func(text string) { notices = append(notices, text) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil (a denial is an in-band refusal, not a failure)", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (a user denial must not re-issue the model)", client.callCount())
	}
	if !loop.Denied() {
		t.Fatalf("loop.Denied() = false, want true (a user denial is a terminal stop)")
	}

	recs := store.Records()
	asst := assistantToolCallMessages(recs)
	if len(asst) != 1 || len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_1" {
		t.Fatalf("assistant tool-call messages = %+v, want one recording call_1", asst)
	}
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != denyEnvelope {
		t.Fatalf("tool messages = %+v, want one deny envelope keyed to call_1", tools)
	}
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response recorded after a denial; want none (the attempt was halted); kinds = %v", eventKinds(recs))
	}
	if final := lastAssistantText(recs); final != "" {
		t.Fatalf("final assistant answer = %q, want none after a denial", final)
	}
	// The friendly denial line names the refused tool and reason, and never exposes raw JSON.
	if len(notices) != 1 {
		t.Fatalf("denial notices = %v, want exactly one friendly line", notices)
	}
	if !strings.Contains(notices[0], "Denied") || !strings.Contains(notices[0], "out of repo scope") {
		t.Fatalf("denial notice = %q, want a friendly line naming the refusal reason", notices[0])
	}
	if strings.Contains(notices[0], "denied_by") {
		t.Fatalf("denial notice = %q, leaked the raw deny-envelope JSON", notices[0])
	}
}

func costToolRound(n int, in, out int64, cost string) accountingRound {
	return func(context.Context, *accountingEnv) (provider.Response, error) {
		return streamResponse(toolCallsChunk(toolFrag(0, fmt.Sprintf("call_%d", n), "do", "{}")), costUsageChunk(in, out, cost))
	}
}

func TestToolLoop_HaltedTurnRecordsOneModelResponseWithEveryRoundsUsage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		halt       ToolResult
		wantDenied bool
	}{
		{"user denial", ToolResult{Content: `{"denied_by":"user","reason":"no"}`, Denied: true}, true},
		{"terminal result", ToolResult{Content: "stopped", Terminal: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			afterHalt := func(context.Context, *accountingEnv) (provider.Response, error) {
				t.Error("provider called after the halt")
				return provider.Response{}, errBadRequest
			}
			e := newAccountingEnv(t, "openrouter", costToolRound(1, 100, 10, "0.25"), costToolRound(2, 50, 5, "0.5"), afterHalt)
			e.loop.dispatcher = &fakeDispatcher{resultFn: func(call AssembledToolCall) (ToolResult, error) {
				if call.ID == "call_2" {
					return tc.halt, nil
				}
				return ToolResult{Content: "out:" + call.ID}, nil
			}}

			if err := e.loop.Run(e.ctx); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if e.loop.Denied() != tc.wantDenied {
				t.Fatalf("loop.Denied() = %v, want %v", e.loop.Denied(), tc.wantDenied)
			}
			recs := diskRecords(t, e.store)
			mr := decodeModelResponse(t, recs)
			if mr.InputTokens != 150 || mr.OutputTokens != 15 {
				t.Fatalf("model_response tokens = (%d, %d), want (150, 15)", mr.InputTokens, mr.OutputTokens)
			}
			if mr.CostUSD == nil || *mr.CostUSD != 0.75 || mr.CostUSDPartial {
				t.Fatalf("model_response cost = %v partial %v, want 0.75 complete", mr.CostUSD, mr.CostUSDPartial)
			}
			if final := lastAssistantText(recs); final != "" {
				t.Fatalf("final assistant answer = %q, want none after a halt", final)
			}
		})
	}
}

func TestToolLoop_DeniedTurnFallbackFlushFailureIsReported(t *testing.T) {
	e := newAccountingEnv(t, "openai", usageToolRound(1, 100, 10, ""))
	e.loop.dispatcher = &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: `{"denied_by":"user","reason":"no"}`, Denied: true}, nil
	}}
	// Runs after the denial round's own records are flushed and before the fallback writes.
	e.loop.userUsage = func(int64, int64) {
		if err := os.RemoveAll(e.dir); err != nil {
			t.Fatalf("remove session directory: %v", err)
		}
		if err := os.WriteFile(e.dir, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("replace session directory: %v", err)
		}
	}

	err := e.loop.Run(e.ctx)
	if err == nil {
		t.Fatal("loop.Run() error = nil, want the fallback's write failure")
	}
	if !e.loop.Denied() {
		t.Fatal("loop.Denied() = false, want the denial halt")
	}
	if len(e.writeFailures) != 1 || !errors.Is(err, e.writeFailures[0]) {
		t.Fatalf("write failures = %v, want one, returned as %v", e.writeFailures, err)
	}
}

// A mode-policy denial (denied_by:"mode") is recoverable. The deny envelope is
// appended keyed to the call and a friendly refusal line is surfaced, but — unlike a user denial —
// the loop re-issues the model so it sees the refused tool result and can pick a permitted
// alternative. The provider is called twice, the follow-up request carries the deny envelope in
// context, a final answer completes, and Denied() reports false (no terminal stop).
func TestToolLoop_ModeDeniedResultAppendedAndContinues(t *testing.T) {
	const modeEnvelope = `{"denied_by":"mode","reason":"plan mode is read-only; this command is classified as mutating; do not use shell loops — issue separate read/glob tool calls or simple read-only shell commands instead"}`
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "summarize the archives"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "bash", `{"command":"for f in a b; do echo $f; done"}`))},
		finalAnswer("I used separate read calls instead"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: modeEnvelope, Denied: true}, nil
	}}
	var notices, providerNotices []string
	loop := NewToolLoop(Deps{
		Active:     selectedState("openai", "gpt-x", model.EffortDefault),
		Store:      store,
		Client:     client,
		Notice:     func(text string) { providerNotices = append(providerNotices, text) },
		ToolNotice: func(text string) { notices = append(notices, text) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (a mode-policy denial re-issues the model)", client.callCount())
	}
	if loop.Denied() {
		t.Fatalf("loop.Denied() = true, want false (a recoverable mode denial is not a terminal stop)")
	}
	if len(providerNotices) != 0 {
		t.Fatalf("provider notices = %v, want mode-denial notices on the tool sink", providerNotices)
	}

	recs := store.Records()
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != modeEnvelope {
		t.Fatalf("tool messages = %+v, want one mode deny envelope keyed to call_1", tools)
	}
	// The follow-up request fed the assistant tool-call and the deny envelope back to the model.
	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured after a mode denial")
	}
	assertContinuation(t, follow, "call_1", modeEnvelope)
	if final := lastAssistantText(recs); final != "I used separate read calls instead" {
		t.Fatalf("final assistant text = %q, want the recovery answer", final)
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response after mode-denial continuation; kinds = %v", eventKinds(recs))
	}
	// The refusal is surfaced as a friendly line naming the command, not the raw JSON.
	if len(notices) != 1 || !strings.Contains(notices[0], "Denied") || !strings.Contains(notices[0], "Run:") {
		t.Fatalf("denial notices = %v, want one friendly line naming the refused command", notices)
	}
	if strings.Contains(notices[0], "denied_by") {
		t.Fatalf("denial notice = %q, leaked the raw deny-envelope JSON", notices[0])
	}
}

// A protected-state denial (denied_by:"guard") is recoverable exactly as a mode denial is: the loop
// re-issues the model instead of halting the turn.
func TestToolLoop_GuardDeniedResultAppendedAndContinues(t *testing.T) {
	guardEnvelope := permissions.BuildGuardDenyEnvelope()
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "turn off the permission prompts"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "edit", `{"path":".codemeld/settings.yaml","old":"a","new":"b"}`))},
		finalAnswer("I cannot edit that file; run /settings instead"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: guardEnvelope, Denied: true}, nil
	}}
	var notices []string
	loop := NewToolLoop(Deps{
		Active:     selectedState("openai", "gpt-x", model.EffortDefault),
		Store:      store,
		Client:     client,
		ToolNotice: func(text string) { notices = append(notices, text) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (a protected-state denial re-issues the model)", client.callCount())
	}
	if loop.Denied() {
		t.Fatalf("loop.Denied() = true, want false (a recoverable guard denial is not a terminal stop)")
	}

	recs := store.Records()
	toolMsgs := toolMessages(recs)
	if len(toolMsgs) != 1 || toolMsgs[0].ToolCallID != "call_1" || toolMsgs[0].Content.Text() != guardEnvelope {
		t.Fatalf("tool messages = %+v, want one guard deny envelope keyed to call_1", toolMsgs)
	}
	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured after a guard denial")
	}
	assertContinuation(t, follow, "call_1", guardEnvelope)
	if final := lastAssistantText(recs); final != "I cannot edit that file; run /settings instead" {
		t.Fatalf("final assistant text = %q, want the recovery answer", final)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "Denied") {
		t.Fatalf("denial notices = %v, want one friendly refusal line", notices)
	}
	if strings.Contains(notices[0], "denied_by") {
		t.Fatalf("denial notice = %q, leaked the raw deny-envelope JSON", notices[0])
	}
}

// An unattended denial is recoverable exactly as a mode or guard denial is: the halt semantics
// exist to stop a model retrying past a person who said no, and no person answered here.
func TestToolLoop_UnattendedDeniedResultAppendedAndContinues(t *testing.T) {
	envelope := permissions.BuildUnattendedDenyEnvelope("no approval available in non-interactive run mode")
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "delete my notes"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},
		finalAnswer("I was not authorized to run that"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: envelope, Denied: true}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (an unattended denial re-issues the model)", client.callCount())
	}
	if loop.Denied() {
		t.Fatalf("loop.Denied() = true, want false (no human refused this call)")
	}
	recs := store.Records()
	toolMsgs := toolMessages(recs)
	if len(toolMsgs) != 1 || toolMsgs[0].ToolCallID != "call_1" || toolMsgs[0].Content.Text() != envelope {
		t.Fatalf("tool messages = %+v, want one unattended deny envelope keyed to call_1", toolMsgs)
	}
	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured after an unattended denial")
	}
	assertContinuation(t, follow, "call_1", envelope)
	if final := lastAssistantText(recs); final != "I was not authorized to run that" {
		t.Fatalf("final assistant text = %q, want the recovery answer", final)
	}
}

func wrapUpLoop(t *testing.T, wrapUpRound [][]byte) (*ToolLoop, *scriptedClient, *sessions.Store, *[]string) {
	t.Helper()
	envelope := permissions.BuildUnattendedDenyEnvelope("no approval available in non-interactive run mode")
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "delete my notes"))
	client := &scriptedClient{rounds: [][][]byte{{toolCallChunk()}, wrapUpRound}}
	disp := &fakeDispatcher{resultFn: func(call AssembledToolCall) (ToolResult, error) {
		if call.ID != "call_1" {
			t.Errorf("dispatched %s from the wrap-up reply, want no dispatch after the wrap-up refusal", call.ID)
		}
		return ToolResult{Content: envelope, Denied: true, WrapUp: true}, nil
	}}
	var notices []string
	loop := NewToolLoop(Deps{
		Active:       selectedState("openai", "gpt-x", model.EffortDefault),
		Store:        store,
		Client:       client,
		Tools:        []provider.ToolDefinition{{Name: "do", Parameters: map[string]any{"type": "object"}}},
		Notice:       func(text string) { notices = append(notices, text) },
		RenderNotice: func(verbatim, _, _ string, _ int) string { return verbatim },
	}, disp, 3)
	return loop, client, store, &notices
}

func TestToolLoop_WrapUpRefusalGetsOneToolLessRoundForTheFinalAnswer(t *testing.T) {
	loop, client, store, _ := wrapUpLoop(t, finalAnswer("Here is what I found."))

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want exactly one wrap-up request after the refusal", client.callCount())
	}
	if loop.Denied() {
		t.Fatal("loop.Denied() = true, want false: the wrap-up ends with a real answer")
	}
	first, _ := client.request(0)
	if len(first.Tools) == 0 {
		t.Fatal("first request advertised no tools; the fixture must prove the wrap-up removes them")
	}
	wrap, _ := client.request(1)
	if len(wrap.Tools) != 0 {
		t.Fatalf("wrap-up request advertised %d tools, want none", len(wrap.Tools))
	}
	last := wrap.Messages[len(wrap.Messages)-1]
	if last.Role != "system" || last.Content != wrapUpText(refusalCause) {
		t.Fatalf("wrap-up request ends with %+v, want the wrap-up system instruction", last)
	}
	assertContinuation(t, wrap, "call_1", permissions.BuildUnattendedDenyEnvelope("no approval available in non-interactive run mode"))
	recs := store.Records()
	if got := systemMessages(recs); !slices.Equal(got, []string{wrapUpText(refusalCause)}) {
		t.Fatalf("stored system messages = %q, want the refusal cause before the instruction", got)
	}
	if got := messageRoleSeq(recs); !slices.Equal(got, []string{"user", "assistant_tc", "tool", "system", "assistant"}) {
		t.Fatalf("message roles = %v, want the refused group, the instruction, then the answer", got)
	}
	if final := lastAssistantText(recs); final != "Here is what I found." {
		t.Fatalf("final assistant text = %q, want the wrap-up answer", final)
	}
}

func TestToolLoop_WrapUpReplyNeverDispatchesAToolCall(t *testing.T) {
	for _, tc := range []struct {
		name        string
		round       [][]byte
		wantFinal   string
		wantErr     bool
		wantSkipped bool
	}{
		{name: "structured call with text", round: [][]byte{contentChunk("Final words."), toolCallsChunk(toolFrag(0, "call_2", "do", "{}"))}, wantFinal: "Final words."},
		{name: "structured call only", round: [][]byte{toolCallsChunk(toolFrag(0, "call_2", "do", "{}"))}, wantErr: true},
		{name: "structured call with whitespace", round: [][]byte{contentChunk(" \n"), toolCallsChunk(toolFrag(0, "call_2", "do", "{}"))}, wantErr: true},
		{name: "suggest-only with whitespace", round: [][]byte{contentChunk(" \n"), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs))}, wantErr: true},
		{name: "whole-message text call", round: finalAnswer(`{"name":"do","arguments":{}}`), wantErr: true},
		{name: "whitespace-only answer", round: finalAnswer("  \n\t "), wantErr: true, wantSkipped: true},
		{name: "empty answer", round: [][]byte{finishChunk("stop")}, wantErr: true, wantSkipped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loop, client, store, notices := wrapUpLoop(t, tc.round)
			loop.deps.Retry = retryOn()

			err := loop.Run(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("loop.Run() error = %v, want error %v", err, tc.wantErr)
			}
			if client.callCount() != 2 {
				t.Fatalf("provider calls = %d, want 2: nothing follows the wrap-up request", client.callCount())
			}
			recs := store.Records()
			if got := assistantToolCallMessages(recs); len(got) != 1 {
				t.Fatalf("assistant tool-call records = %d, want only the refused round's", len(got))
			}
			if got := toolMessages(recs); len(got) != 1 {
				t.Fatalf("tool messages = %d, want only the refused round's", len(got))
			}
			if tc.wantFinal != "" {
				if final := lastAssistantText(recs); final != tc.wantFinal {
					t.Fatalf("final assistant text = %q, want %q", final, tc.wantFinal)
				}
				return
			}
			if strings.TrimSpace(lastAssistantText(recs)) != "" {
				t.Fatalf("final assistant text = %q, want no visible answer", lastAssistantText(recs))
			}
			failures := 0
			for _, k := range eventKinds(recs) {
				if k == "provider_request_failed" {
					failures++
				}
			}
			emptyNotices := 0
			for _, n := range *notices {
				if strings.Contains(n, "empty_response") {
					emptyNotices++
				}
			}
			if failures != 1 || emptyNotices != 1 {
				t.Fatalf("kinds = %v, notices = %v, want exactly one empty-response failure and its notice", eventKinds(recs), *notices)
			}
			if !strings.Contains(err.Error(), "no visible assistant response") {
				t.Fatalf("loop.Run() error = %v, want the no-visible-response error", err)
			}
			if rs := findProviderRequestRetry(t, recs); len(rs) != 0 {
				t.Fatalf("provider_request_retry = %+v, want none: wrap-up runs one attempt", rs)
			}
			skipped := findProviderRequestRetrySkipped(t, recs)
			if tc.wantSkipped != (len(skipped) == 1) || len(skipped) > 1 {
				t.Fatalf("provider_request_retry_skipped = %+v, want one only for a plain blank reply (%t)", skipped, tc.wantSkipped)
			}
			if tc.wantSkipped && (skipped[0].Phase != "empty_response" || skipped[0].SkipReason != "max_attempts_reached") {
				t.Fatalf("provider_request_retry_skipped = %+v, want empty_response max_attempts_reached", skipped[0])
			}
		})
	}
}

func TestToolLoop_ResultNoticeFollowsTheDenialLine(t *testing.T) {
	const notice = "Blocked by the blocked_paths entry /home/u/secrets in /home/u/.codemeld/settings.yaml"
	guardEnvelope := permissions.BuildGuardDenyEnvelope()
	cases := []struct {
		name   string
		result ToolResult
		want   []string
	}{
		{"denied with notice", ToolResult{Content: guardEnvelope, Denied: true, Notice: notice}, []string{"Denied ", notice}},
		{"denied without notice", ToolResult{Content: guardEnvelope, Denied: true}, []string{"Denied "}},
		{"allowed with notice", ToolResult{Content: "file contents", Notice: notice}, []string{notice}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "read the secrets"))
			client := &scriptedClient{rounds: [][][]byte{
				{toolCallsChunk(toolFrag(0, "call_1", "read", `{"path":"/home/u/secrets"}`))},
				finalAnswer("done"),
			}}
			disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
				return tc.result, nil
			}}
			var notices []string
			loop := NewToolLoop(Deps{
				Active:     selectedState("openai", "gpt-x", model.EffortDefault),
				Store:      store,
				Client:     client,
				ToolNotice: func(text string) { notices = append(notices, text) },
			}, disp, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if len(notices) != len(tc.want) {
				t.Fatalf("notices = %q, want %d lines matching %q", notices, len(tc.want), tc.want)
			}
			for i, want := range tc.want {
				if !strings.HasPrefix(notices[i], want) {
					t.Fatalf("notices[%d] = %q, want prefix %q (notices = %q)", i, notices[i], want, notices)
				}
			}
		})
	}
}

// Fail-closed: a denied result whose content is not a positively-classifiable deny
// envelope is terminal, never mode-continuation. This guards the classifier bypass — a malformed,
// reasonless, or unknown envelope must not be mistaken for a recoverable mode denial. The provider is
// called once, Denied() is true, and the scripted final answer is never reached.
func TestToolLoop_DeniedResultMalformedEnvelopeStops(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"unknown denied_by", `{"denied_by":"sideways","reason":"???"}`},
		{"missing reason", `{"denied_by":"mode"}`},
		{"empty reason", `{"denied_by":"mode","reason":""}`},
		{"guard missing reason", `{"denied_by":"guard"}`},
		{"guard blank reason", `{"denied_by":"guard","reason":" \t"}`},
		{"guard case mismatch", `{"denied_by":"Guard","reason":"settings are protected"}`},
		{"unattended missing reason", `{"denied_by":"unattended"}`},
		{"unattended case mismatch", `{"denied_by":"Unattended","reason":"no approver"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "run the command"))

			client := &scriptedClient{rounds: [][][]byte{
				{toolCallChunk()},
				finalAnswer("must never be issued"),
			}}
			disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
				return ToolResult{Content: tc.content, Denied: true}, nil
			}}
			loop := NewToolLoop(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  store,
				Client: client,
			}, disp, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if client.callCount() != 1 {
				t.Fatalf("provider calls = %d, want 1 (an unclassifiable denial must fail closed and halt)", client.callCount())
			}
			if !loop.Denied() {
				t.Fatalf("loop.Denied() = false, want true (fail closed on an unclassifiable envelope)")
			}
			if final := lastAssistantText(store.Records()); final != "" {
				t.Fatalf("final assistant answer = %q, want none (an unclassifiable denial halts)", final)
			}
		})
	}
}

func TestToolLoop_MixedResultsStopAfterDenied(t *testing.T) {
	const denyEnvelope = `{"denied_by":"user","reason":"blocked"}`
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do two things"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "read", "{}"), toolFrag(1, "call_b", "write", "{}"))},
		finalAnswer("unreached"),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		if c.ID == "call_b" {
			return ToolResult{Content: denyEnvelope, Denied: true}, nil
		}
		return ToolResult{Content: "out:" + c.ID}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (a denied call in the round must stop continuation)", client.callCount())
	}

	tools := toolMessages(store.Records())
	if len(tools) != 2 {
		t.Fatalf("tool messages = %d, want 2 (every result from the round persisted)", len(tools))
	}
	byID := map[string]string{}
	for _, m := range tools {
		byID[m.ToolCallID] = m.Content.Text()
	}
	if byID["call_a"] != "out:call_a" {
		t.Fatalf("call_a result = %q, want the successful output out:call_a", byID["call_a"])
	}
	if byID["call_b"] != denyEnvelope {
		t.Fatalf("call_b result = %q, want the deny envelope", byID["call_b"])
	}
	if hasKind(store.Records(), "model_response") {
		t.Fatalf("model_response recorded after a mixed denied round; want none (the attempt was halted)")
	}
}

// A denial ends the turn, so — unlike a continuing round, whose records
// reach disk via the next round's round-trip flush — no later provider round flushes the
// records appended for the denied round. onToolCalls therefore crosses the durability
// boundary itself before returning. Reading the flushed session back with diskRecords
// (not the in-memory store.Records() snapshot) and no manual flush after Run proves it:
// before the fix these records lived only in memory and were absent from disk.
func TestToolLoop_DeniedResultDurableOnDisk(t *testing.T) {
	const denyEnvelope = `{"denied_by":"user","reason":"out of repo scope"}`
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "run the command"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},        // round 1: call_1
		finalAnswer("unreached"), // must never be issued after a denial
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: denyEnvelope, Denied: true}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	// Read from disk with no manual flush after Run: the denied round's records are
	// durable only if onToolCalls flushed them before returning.
	recs := diskRecords(t, store)
	asst := assistantToolCallMessages(recs)
	if len(asst) != 1 || len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_1" {
		t.Fatalf("on-disk assistant tool-call messages = %+v, want one recording call_1", asst)
	}
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != denyEnvelope {
		t.Fatalf("on-disk tool messages = %+v, want one deny envelope keyed to call_1", tools)
	}
}

func TestToolLoop_TerminalResultRecordedAndStopsTheTurn(t *testing.T) {
	const searchFailure = "exa: the search request failed"
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "look this up"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},                      // round 1: call_1
		finalAnswer("searching again instead"), // must never be issued after a terminal result
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: searchFailure, Terminal: true}, nil
	}}
	var notices []string
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Notice: func(text string) { notices = append(notices, text) },
		Flush:  storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil (a failed search is an in-band result, not a failure)", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (a terminal result must not re-issue the model)", client.callCount())
	}
	if loop.Denied() {
		t.Fatalf("loop.Denied() = true, want false (a failed search is not a permission refusal)")
	}

	recs := diskRecords(t, store)
	asst := assistantToolCallMessages(recs)
	if len(asst) != 1 || len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_1" {
		t.Fatalf("on-disk assistant tool-call messages = %+v, want one recording call_1", asst)
	}
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != searchFailure {
		t.Fatalf("on-disk tool messages = %+v, want one bounded failure keyed to call_1", tools)
	}
	if final := lastAssistantText(recs); final != "" {
		t.Fatalf("final assistant answer = %q, want none after a terminal result", final)
	}
	if len(notices) != 1 || notices[0] != searchFailure {
		t.Fatalf("notices = %v, want exactly the bounded failure surfaced to the user", notices)
	}
}

func TestToolLoop_MixedResultsStopAfterTerminal(t *testing.T) {
	const searchFailure = "exa: the search request failed"
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "read and search"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "read", "{}"), toolFrag(1, "call_b", "web_search", "{}"))},
		finalAnswer("unreached"),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		if c.ID == "call_b" {
			return ToolResult{Content: searchFailure, Terminal: true}, nil
		}
		return ToolResult{Content: "out:" + c.ID}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (a terminal result in the round stops continuation)", client.callCount())
	}
	tools := toolMessages(store.Records())
	if len(tools) != 2 {
		t.Fatalf("tool messages = %d, want 2 (every result from the round persisted)", len(tools))
	}
	byID := map[string]string{}
	for _, m := range tools {
		byID[m.ToolCallID] = m.Content.Text()
	}
	if byID["call_a"] != "out:call_a" || byID["call_b"] != searchFailure {
		t.Fatalf("results = %v, want the successful output and the bounded failure", byID)
	}
	if hasKind(store.Records(), "model_response") {
		t.Fatalf("model_response recorded after a terminal round; want none (the attempt was halted)")
	}
}

func TestToolLoop_FailedSearchNoticeIsSurfacedAndTheTurnContinues(t *testing.T) {
	const searchFailure = "exa: the search request failed"
	const answer = "I could not search, so here is what I already know"
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "look this up"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "web_search", `{"query":"codemeld"}`))},
		finalAnswer(answer),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: searchFailure, Notice: searchFailure}, nil
	}}
	var notices []string
	loop := NewToolLoop(Deps{
		Active:     selectedState("openai", "gpt-x", model.EffortDefault),
		Store:      store,
		Client:     client,
		ToolNotice: func(text string) { notices = append(notices, text) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (a failed search continues to the next model round)", client.callCount())
	}
	if loop.Denied() {
		t.Fatalf("loop.Denied() = true, want false (a failed search is not a permission refusal)")
	}

	recs := store.Records()
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != searchFailure {
		t.Fatalf("tool messages = %+v, want one bounded failure keyed to call_1", tools)
	}
	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured after a failed search")
	}
	assertContinuation(t, follow, "call_1", searchFailure)
	if final := lastAssistantText(recs); final != answer {
		t.Fatalf("final assistant text = %q, want the answer the model produced after the failure", final)
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response after a failed search; kinds = %v", eventKinds(recs))
	}
	if len(notices) != 1 || notices[0] != searchFailure {
		t.Fatalf("notices = %v, want exactly one bounded failure line", notices)
	}
}

func TestToolLoop_FailedSearchInABatchKeepsEverySiblingResult(t *testing.T) {
	const searchFailure = "exa: the search request failed"
	const answer = "two of the three searches were enough"
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "research this from several angles"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(
			toolFrag(0, "call_a", "web_search", `{"query":"alpha"}`),
			toolFrag(1, "call_b", "web_search", `{"query":"beta"}`),
			toolFrag(2, "call_c", "web_search", `{"query":"gamma"}`),
		)},
		finalAnswer(answer),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		if c.ID == "call_b" {
			return ToolResult{Content: searchFailure, Notice: searchFailure}, nil
		}
		return ToolResult{Content: "candidates:" + c.ID}, nil
	}}
	var notices []string
	loop := NewToolLoop(Deps{
		Active:     selectedState("openai", "gpt-x", model.EffortDefault),
		Store:      store,
		Client:     client,
		ToolNotice: func(text string) { notices = append(notices, text) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (a failed sibling must not end the batch's turn)", client.callCount())
	}

	recs := store.Records()
	tools := toolMessages(recs)
	wantResults := []struct{ id, content string }{
		{"call_a", "candidates:call_a"},
		{"call_b", searchFailure},
		{"call_c", "candidates:call_c"},
	}
	if len(tools) != len(wantResults) {
		t.Fatalf("tool messages = %+v, want every result of the batch", tools)
	}
	for i, want := range wantResults {
		if tools[i].ToolCallID != want.id || tools[i].Content.Text() != want.content {
			t.Fatalf("tool message %d = %s/%q, want %s/%q (results keep model-call order)", i, tools[i].ToolCallID, tools[i].Content.Text(), want.id, want.content)
		}
	}
	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured after a mixed batch")
	}
	for _, want := range wantResults {
		assertContinuation(t, follow, want.id, want.content)
	}
	if final := lastAssistantText(recs); final != answer {
		t.Fatalf("final assistant text = %q, want the answer built from the surviving candidates", final)
	}
	if len(notices) != 1 || notices[0] != searchFailure {
		t.Fatalf("notices = %v, want exactly one line for the single failed search", notices)
	}
}

func TestToolLoop_AllFailedSearchesInABatchStillContinue(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "research this from several angles"))

	failures := map[string]string{
		"call_a": "exa: the search request failed",
		"call_b": "exa: your Exa account has reached its limit",
	}
	const answer = "searching is unavailable right now"
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(
			toolFrag(0, "call_a", "web_search", `{"query":"alpha"}`),
			toolFrag(1, "call_b", "web_search", `{"query":"beta"}`),
		)},
		finalAnswer(answer),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: failures[c.ID], Notice: failures[c.ID]}, nil
	}}
	var notices []string
	loop := NewToolLoop(Deps{
		Active:     selectedState("openai", "gpt-x", model.EffortDefault),
		Store:      store,
		Client:     client,
		ToolNotice: func(text string) { notices = append(notices, text) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (an all-failed batch must not silently end the turn)", client.callCount())
	}

	recs := store.Records()
	tools := toolMessages(recs)
	if len(tools) != 2 {
		t.Fatalf("tool messages = %+v, want both failure results", tools)
	}
	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured after an all-failed batch")
	}
	for i, id := range []string{"call_a", "call_b"} {
		if tools[i].ToolCallID != id || tools[i].Content.Text() != failures[id] {
			t.Fatalf("tool message %d = %s/%q, want %s/%q", i, tools[i].ToolCallID, tools[i].Content.Text(), id, failures[id])
		}
		assertContinuation(t, follow, id, failures[id])
	}
	if final := lastAssistantText(recs); final != answer {
		t.Fatalf("final assistant text = %q, want the answer the model chose after every search failed", final)
	}
	if len(notices) != 2 || notices[0] != failures["call_a"] || notices[1] != failures["call_b"] {
		t.Fatalf("notices = %v, want one bounded line per failed search", notices)
	}
}

// An internal dispatch error (not a deny) aborts the turn: the scheduler surfaces
// it, the loop returns it, and NO assistant tool-call or tool message is appended,
// so the turn is never partially continued.
func TestToolLoop_DispatchErrorAbortsWithoutPartialContinuation(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},
		finalAnswer("unreached"),
	}}
	boom := errors.New("dispatch boom")
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{}, boom
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	err := loop.Run(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("loop.Run() error = %v, want the dispatch error", err)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (no re-issue after a dispatch failure)", client.callCount())
	}
	recs := store.Records()
	if len(assistantToolCallMessages(recs)) != 0 {
		t.Fatalf("assistant tool-call message appended despite a dispatch failure")
	}
	if len(toolMessages(recs)) != 0 {
		t.Fatalf("tool messages appended despite a dispatch failure")
	}
}

func TestToolLoop_SerialDispatchErrorPreventsFollowingCall(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{{
		toolCallsChunk(toolFrag(0, "call_a", "a", "{}"), toolFrag(1, "call_b", "b", "{}")),
	}}}
	boom := errors.New("dispatch boom")
	disp := &fakeDispatcher{
		planFn: func(AssembledToolCall) ([]string, []string) {
			return nil, []string{"serial"}
		},
		resultFn: func(call AssembledToolCall) (ToolResult, error) {
			if call.ID == "call_a" {
				return ToolResult{}, boom
			}
			return ToolResult{Content: "out:" + call.ID}, nil
		},
	}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("loop.Run() error = %v, want %v", err, boom)
	}
	if got := disp.dispatchedOrder(); len(got) != 1 || got[0] != "call_a" {
		t.Fatalf("dispatch order = %v, want only the failed first serial call", got)
	}
	if len(assistantToolCallMessages(store.Records())) != 0 || len(toolMessages(store.Records())) != 0 {
		t.Fatalf("tool records = %v, want no partial continuation", store.Records())
	}
}

// Regression: when the tool continuation fails (here an internal dispatch
// error) the provider round has already reached its tool-call-handoff terminal
// outcome, so its provider_round_trip timing must be durable on disk even though the
// loop aborts before any later round's start flush would have persisted it. Before
// the fix the event was only appended in memory and lost when Run returned the
// dispatch error, so reading the flushed session back found zero round-trip events.
func TestToolLoop_StructuredHandoffTimingDurableWhenContinuationFails(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},        // round 1: structured tool call
		finalAnswer("unreached"), // never issued: the continuation fails first
	}}
	boom := errors.New("dispatch boom")
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{}, boom
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("loop.Run() error = %v, want the dispatch error", err)
	}

	recs := diskRecords(t, store)
	if rounds := providerRoundTripEvents(t, recs); len(rounds) != 1 {
		t.Fatalf("persisted provider_round_trip events = %d, want 1 (handoff timing must be durable before the failing continuation); kinds = %v", len(rounds), eventKinds(recs))
	}
}

func TestToolLoop_StructuredReadEvidenceDurableWhenDispatchFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome string
		err     error
	}{
		{name: "cancellation", outcome: "cancelled", err: context.Canceled},
		{name: "internal failure", outcome: "internal_failure", err: errors.New("dispatch boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "read the file"))
			invocationID := ids.NewV7()
			disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
				if err := events.EmitStructuredReadStart(store, invocationID, "read", t.TempDir(), 1, ""); err != nil {
					return ToolResult{}, err
				}
				if err := events.EmitStructuredReadEnd(store, invocationID, "read", tc.outcome, 0, ""); err != nil {
					return ToolResult{}, err
				}
				return ToolResult{}, tc.err
			}}
			loop := NewToolLoop(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  store,
				Flush:  storeFlush(store),
			}, disp, 1)

			handoff := ToolCallHandoff{
				ToolCallDeltas: [][]openai.ChatCompletionChunkChoiceDeltaToolCall{{
					{Index: 0, ID: "call_1", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "read", Arguments: `{}`}},
				}},
			}
			if err := loop.onToolCalls(context.Background(), handoff); !errors.Is(err, tc.err) {
				t.Fatalf("onToolCalls() error = %v, want %v", err, tc.err)
			}

			var starts []events.StructuredReadStart
			var ends []events.StructuredReadEnd
			for _, rec := range diskRecords(t, store) {
				ev, ok := rec.(sessions.Event)
				if !ok {
					continue
				}
				switch ev.Kind {
				case events.KindStructuredReadStart:
					var start events.StructuredReadStart
					if err := json.Unmarshal(ev.Payload, &start); err != nil {
						t.Fatalf("unmarshal structured_read_start payload: %v", err)
					}
					starts = append(starts, start)
				case events.KindStructuredReadEnd:
					var end events.StructuredReadEnd
					if err := json.Unmarshal(ev.Payload, &end); err != nil {
						t.Fatalf("unmarshal structured_read_end payload: %v", err)
					}
					ends = append(ends, end)
				}
			}
			if len(starts) != 1 || len(ends) != 1 {
				t.Fatalf("durable structured_read events = %d start/%d end, want 1/1", len(starts), len(ends))
			}
			if starts[0].InvocationID != invocationID || ends[0].InvocationID != invocationID || ends[0].Outcome != tc.outcome {
				t.Fatalf("durable structured_read pair = (%+v, %+v), want invocation %q and outcome %q", starts[0], ends[0], invocationID, tc.outcome)
			}
		})
	}
}

// Regression (text-tool-call branch): a whole-message text tool call is the
// same handoff terminal outcome as a structured call, so its provider_round_trip
// must likewise be flushed durable before a failing continuation can strand it.
func TestToolLoop_TextHandoffTimingDurableWhenContinuationFails(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "where is yellow set?"))

	content := `{"name":"grep","arguments":{"pattern":"yellow"}}`
	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk(content), finishChunk("stop")}, // text-format tool call, non-tool_calls finish
		finalAnswer("unreached"),
	}}
	boom := errors.New("dispatch boom")
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{}, boom
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("loop.Run() error = %v, want the dispatch error", err)
	}

	recs := diskRecords(t, store)
	if rounds := providerRoundTripEvents(t, recs); len(rounds) != 1 {
		t.Fatalf("persisted provider_round_trip events = %d, want 1 (text-handoff timing must be durable); kinds = %v", len(rounds), eventKinds(recs))
	}
}

// Duplicate tool-call ids are an invalid scheduler plan caught before any unit
// runs, so the loop aborts and appends nothing (architecture-review backstop).
func TestToolLoop_DuplicateCallIDsAbortBeforeDispatch(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "dup", "a", "{}"), toolFrag(1, "dup", "b", "{}"))},
		finalAnswer("unreached"),
	}}
	disp := &fakeDispatcher{}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err == nil {
		t.Fatalf("loop.Run() error = nil, want a duplicate-id scheduler error")
	}
	if n := len(disp.dispatchedOrder()); n != 0 {
		t.Fatalf("dispatched %d calls, want 0 (invalid plan rejected before launch)", n)
	}
	// The start-of-turn model_turn event is expected; no assistant tool-call or
	// tool message may be appended for a rejected plan.
	recs := store.Records()
	if len(assistantToolCallMessages(recs)) != 0 || len(toolMessages(recs)) != 0 {
		t.Fatalf("assistant/tool messages appended for an invalid plan; want none")
	}
}

func TestToolLoop_PlansWholeResponseOnceWithConfiguredConcurrency(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "a", "{}"), toolFrag(1, "call_b", "b", "{}"))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if got := disp.plannedBatches; len(got) != 1 || got[0] != 2 {
		t.Fatalf("planned batches = %v, want one batch of 2 (the whole response planned at once)", got)
	}
	if disp.plannedConcurrency != 2 {
		t.Fatalf("planner got maxConcurrency = %d, want the loop's configured 2", disp.plannedConcurrency)
	}
}

type planMutatingDispatcher struct {
	mutate     func([]PlannedToolCall) []PlannedToolCall
	mu         sync.Mutex
	dispatched int
}

func (d *planMutatingDispatcher) Plan(calls []AssembledToolCall, maxConcurrency int) ToolPlan {
	units := make([]PlannedToolCall, len(calls))
	for i, call := range calls {
		units[i] = PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return ToolPlan{Units: d.mutate(units)}
}

func (d *planMutatingDispatcher) Dispatch(_ context.Context, call AssembledToolCall) (ToolResult, error) {
	d.mu.Lock()
	d.dispatched++
	d.mu.Unlock()
	return ToolResult{Content: "out:" + call.ID}, nil
}

func (d *planMutatingDispatcher) dispatchCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dispatched
}

func TestToolLoop_RejectsMalformedPlanBeforeScheduling(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]PlannedToolCall) []PlannedToolCall
	}{
		{"unit count mismatch", func(u []PlannedToolCall) []PlannedToolCall { return u[:1] }},
		{"reordered units", func(u []PlannedToolCall) []PlannedToolCall {
			return []PlannedToolCall{u[1], u[0]}
		}},
		{"substituted call id", func(u []PlannedToolCall) []PlannedToolCall {
			u[1].Call.ID = "call_other"
			return u
		}},
		{"substituted call name", func(u []PlannedToolCall) []PlannedToolCall {
			u[0].Call.Name = "other"
			return u
		}},
		{"nil run", func(u []PlannedToolCall) []PlannedToolCall {
			u[1].Run = nil
			return u
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			client := &scriptedClient{rounds: [][][]byte{
				{toolCallsChunk(toolFrag(0, "call_a", "a", "{}"), toolFrag(1, "call_b", "b", "{}"))},
				finalAnswer("unreached"),
			}}
			disp := &planMutatingDispatcher{mutate: tc.mutate}
			loop := NewToolLoop(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  store,
				Client: client,
			}, disp, 2)

			if err := loop.Run(context.Background()); err == nil {
				t.Fatal("loop.Run() error = nil, want the malformed plan rejected")
			}
			if n := disp.dispatchCount(); n != 0 {
				t.Fatalf("dispatched %d calls, want 0 (a malformed plan is rejected before scheduling)", n)
			}
			recs := store.Records()
			if len(assistantToolCallMessages(recs)) != 0 || len(toolMessages(recs)) != 0 {
				t.Fatal("assistant/tool messages appended for a malformed plan; want none")
			}
			if client.callCount() != 1 {
				t.Fatalf("provider calls = %d, want 1 (a rejected plan does not re-issue the turn)", client.callCount())
			}
		})
	}
}

func TestToolLoop_PlannedResultsKeepInputOrder(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "a", "{}"), toolFrag(1, "call_b", "b", "{}"))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		if c.ID == "call_a" {
			time.Sleep(30 * time.Millisecond)
		}
		return ToolResult{Content: "out:" + c.ID}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	msgs := toolMessages(store.Records())
	if len(msgs) != 2 {
		t.Fatalf("tool messages = %d, want 2", len(msgs))
	}
	for i, want := range []struct{ id, content string }{{"call_a", "out:call_a"}, {"call_b", "out:call_b"}} {
		if msgs[i].ToolCallID != want.id || msgs[i].Content.Text() != want.content {
			t.Fatalf("tool message %d = (%q, %q), want (%q, %q)", i, msgs[i].ToolCallID, msgs[i].Content.Text(), want.id, want.content)
		}
	}
}

// Done-when 3 (durable readback): the assistant ToolCalls and tool messages the
// loop persisted survive a real flush + reload, pass correlation
// validation, and feed a freshly built follow-up provider request.
func TestToolLoop_PersistedToolCallsReloadAndFeedFollowup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)
	store.Append(textMsg("user", "read the file"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "read_file", `{"path":"/x"}`))},
		finalAnswer("the file says hi"),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: "contents of /x"}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush: func() error {
			_, _, err := store.Flush(context.Background())
			return err
		},
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted session: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload persisted session: %v", err)
	}
	if err := sessions.ValidateRecordStream(reloaded.Records); err != nil {
		t.Fatalf("persisted tool-call stream failed req-425a validation: %v", err)
	}

	asst := assistantToolCallMessages(reloaded.Records)
	if len(asst) != 1 || len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_1" {
		t.Fatalf("reloaded assistant tool-call message = %+v, want one with call_1", asst)
	}
	tools := toolMessages(reloaded.Records)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != "contents of /x" {
		t.Fatalf("reloaded tool messages = %+v, want one answering call_1", tools)
	}

	// Build a fresh follow-up request from the reloaded stream: it must carry the
	// assistant tool-call (with name/arguments) and the tool result.
	reloadedStore := sessions.New(path, reloaded)
	req, _, _, ok := BuildRequest(selectedState("openai", "gpt-x", model.EffortDefault), reloadedStore, "", nil)
	if !ok {
		t.Fatalf("BuildRequest over reloaded store ok = false, want true")
	}
	assertContinuation(t, req, "call_1", "contents of /x")
	// The reloaded tool-call also round-trips its function name and arguments.
	for _, m := range req.Messages {
		if m.Role == "assistant" && len(m.ToolCalls) == 1 {
			if m.ToolCalls[0].Name != "read_file" || m.ToolCalls[0].Arguments != `{"path":"/x"}` {
				t.Fatalf("reloaded assistant tool call = %+v, want read_file with {\"path\":\"/x\"}", m.ToolCalls[0])
			}
		}
	}
}

// A multi-round agentic turn sums the exact stream usage of every provider
// round into its single final model_response, not just the last round, and fires the
// Usage indicator callback once per successful round — the first call carrying round 1's
// totals (so the indicator climbs the moment its usage lands), the last carrying the
// turn total. Round 1 ends in tool_calls with its own usage chunk; the follow-up answer
// round carries its own usage chunk. The recorded model_response and the /status-style
// SumModelResponseTokens total reflect both rounds. Dropping the tool-call-round
// accumulation regresses every assertion here to only the final round's (120, 40).
func TestToolLoop_AccumulatesUsageAcrossToolCallRounds(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk(), usageChunk(100, 20)},                               // round 1: tool call + usage
		{contentChunk("all done"), finishChunk("stop"), usageChunk(120, 40)}, // final answer + usage
	}}
	disp := &fakeDispatcher{}

	var usageCalls [][2]int64
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Usage: func(in, out int64) {
			usageCalls = append(usageCalls, [2]int64{in, out})
		},
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	// Exactly one model_response (the final round) carrying the summed turn total.
	mr := decodeModelResponse(t, store.Records())
	if mr.InputTokens != 220 || mr.OutputTokens != 60 {
		t.Fatalf("model_response tokens = (%d, %d), want (220, 60) summed across both rounds", mr.InputTokens, mr.OutputTokens)
	}
	if len(mr.Anomaly) != 0 {
		t.Fatalf("model_response anomaly = %v, want none (both rounds had exact usage)", mr.Anomaly)
	}
	if in, out := model.SumModelResponseTokens(store.Records()); in != 220 || out != 60 {
		t.Fatalf("SumModelResponseTokens = (%d, %d), want (220, 60)", in, out)
	}
	// One Usage callback per round: round 1's cumulative (100, 20) first, then the turn
	// total (220, 60) after the final round.
	if len(usageCalls) != 2 {
		t.Fatalf("Usage callback fired %d times, want 2 (one per successful round): %v", len(usageCalls), usageCalls)
	}
	if usageCalls[0] != [2]int64{100, 20} {
		t.Fatalf("first Usage call = %v, want (100, 20) (round-1 totals pushed before the final round)", usageCalls[0])
	}
	if usageCalls[len(usageCalls)-1] != [2]int64{220, 60} {
		t.Fatalf("last Usage call = %v, want (220, 60) (turn total)", usageCalls[len(usageCalls)-1])
	}
}

func TestToolLoop_AccumulatesCachedTokensAcrossRounds(t *testing.T) {
	tests := []struct {
		name        string
		firstRound  []byte
		wantCached  int64
		wantPartial bool
	}{
		{"every-round-reports", cachedUsageChunk(100, 20, 80), 176, false},
		{"one-round-omits", usageChunk(100, 20), 96, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "do the thing"))

			client := &scriptedClient{rounds: [][][]byte{
				{toolCallChunk(), tt.firstRound},
				{contentChunk("all done"), finishChunk("stop"), cachedUsageChunk(120, 40, 96)},
			}}
			loop := NewToolLoop(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  store,
				Client: client,
			}, &fakeDispatcher{}, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}

			mr := decodeModelResponse(t, store.Records())
			if mr.CachedInputTokens == nil || *mr.CachedInputTokens != tt.wantCached {
				t.Fatalf("cached_input_tokens = %v, want %d", mr.CachedInputTokens, tt.wantCached)
			}
			if mr.CachedInputTokensPartial != tt.wantPartial {
				t.Fatalf("cached_input_tokens_partial = %v, want %v", mr.CachedInputTokensPartial, tt.wantPartial)
			}
		})
	}
}

func TestToolLoop_AccumulatesCostAcrossRounds(t *testing.T) {
	tests := []struct {
		name        string
		firstRound  [][]byte
		wantCost    float64
		wantPartial bool
	}{
		{"every-round-reports", [][]byte{toolCallChunk(), costUsageChunk(100, 20, "0.25")}, 0.75, false},
		{"one-round-omits", [][]byte{toolCallChunk(), usageChunk(100, 20)}, 0.5, true},
		{"one-round-has-no-usage-chunk", [][]byte{toolCallChunk()}, 0.5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "do the thing"))

			client := &scriptedClient{rounds: [][][]byte{
				tt.firstRound,
				{contentChunk("all done"), finishChunk("stop"), costUsageChunk(120, 40, "0.5")},
			}}
			loop := NewToolLoop(Deps{
				Active: selectedState("openrouter", "m", model.EffortDefault),
				Store:  store,
				Client: client,
			}, &fakeDispatcher{}, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}

			mr := decodeModelResponse(t, store.Records())
			if mr.CostUSD == nil || *mr.CostUSD != tt.wantCost {
				t.Fatalf("cost_usd = %v, want %v", mr.CostUSD, tt.wantCost)
			}
			if mr.CostUSDPartial != tt.wantPartial {
				t.Fatalf("cost_usd_partial = %v, want %v", mr.CostUSDPartial, tt.wantPartial)
			}
		})
	}
}

// Both rounds here finish in tool_calls, so the single model_response can only have
// come from finalizeInterceptedRound rather than Runner.Run's final-answer path.
func TestToolLoop_SuggestOnlyRoundRecordsCachedTokens(t *testing.T) {
	tests := []struct {
		name        string
		finalUsage  []byte
		wantCached  int64
		wantPartial bool
	}{
		{"every-round-reports", cachedUsageChunk(150, 25, 96), 176, false},
		{"terminal-round-omits", usageChunk(150, 25), 80, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "summarize the tasks"))

			client := &scriptedClient{rounds: [][][]byte{
				{toolCallChunk(), cachedUsageChunk(100, 20, 80)},
				{contentChunk("Here is the summary."), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), tt.finalUsage},
			}}
			disp := &fakeDispatcher{}
			var suggestCalls int
			loop := NewToolLoop(Deps{
				Active:          selectedState("openai", "gpt-x", model.EffortDefault),
				Store:           store,
				Client:          client,
				SuggestFollowup: func(string, string) { suggestCalls++ },
			}, disp, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if suggestCalls != 1 {
				t.Fatalf("SuggestFollowup fired %d times, want 1 (the terminal round must be the intercepted one)", suggestCalls)
			}
			if final := lastAssistantText(store.Records()); final != "Here is the summary." {
				t.Fatalf("final assistant text = %q, want the intercepted round's prose", final)
			}

			mr := decodeModelResponse(t, store.Records())
			if mr.CachedInputTokens == nil || *mr.CachedInputTokens != tt.wantCached {
				t.Fatalf("cached_input_tokens = %v, want %d", mr.CachedInputTokens, tt.wantCached)
			}
			if mr.CachedInputTokensPartial != tt.wantPartial {
				t.Fatalf("cached_input_tokens_partial = %v, want %v", mr.CachedInputTokensPartial, tt.wantPartial)
			}
		})
	}
}

func TestToolLoop_SuggestOnlyRoundRecordsFinalRoundUpstreamProvider(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "summarize the tasks"))
	client := &scriptedClient{rounds: [][][]byte{
		{withUpstream(toolCallChunk(), `"Groq"`)},
		{withUpstream(contentChunk("Here is the summary."), `"Cerebras"`), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs))},
	}}
	loop := NewToolLoop(Deps{
		Active:          selectedState("openrouter", "m", model.EffortDefault),
		Store:           store,
		Client:          client,
		SuggestFollowup: func(string, string) {},
	}, &fakeDispatcher{}, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2", client.callCount())
	}
	if got := decodeModelResponse(t, store.Records()).UpstreamProvider; got != "Cerebras" {
		t.Fatalf("upstream_provider = %q, want the intercepted final round's Cerebras", got)
	}
}

func TestToolLoop_WrapUpRoundRecordsItsUpstreamProvider(t *testing.T) {
	loop, client, store, _ := wrapUpLoop(t, [][]byte{
		withUpstream(contentChunk("Final words."), `"Cerebras"`),
		toolCallsChunk(toolFrag(0, "call_2", "do", "{}")),
	})
	client.rounds[0] = [][]byte{withUpstream(toolCallChunk(), `"Groq"`)}
	loop.deps.Active.ApplyUserSelection(model.Selection{Provider: "openrouter", ID: "m", Effort: model.EffortDefault}, false)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if got := decodeModelResponse(t, store.Records()).UpstreamProvider; got != "Cerebras" {
		t.Fatalf("upstream_provider = %q, want the wrap-up round's Cerebras", got)
	}
}

func TestToolLoop_SuggestOnlyRoundWithoutCachedUsageRecordsNothing(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "summarize the tasks"))

	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk("Here is the summary."), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), usageChunk(150, 25)},
	}}
	loop := NewToolLoop(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		SuggestFollowup: func(string, string) {},
	}, &fakeDispatcher{}, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	mr := decodeModelResponse(t, store.Records())
	if mr.CachedInputTokens != nil {
		t.Fatalf("cached_input_tokens = %d, want nil (no round reported one)", *mr.CachedInputTokens)
	}
	if mr.CachedInputTokensPartial {
		t.Error("cached_input_tokens_partial = true, want false with no cached total to bound")
	}
}

// A tool-call first round with a large prompt and almost no output must push its
// real input to the indicator the instant its usage chunk lands — before the final
// round — so a tool-heavy turn climbs into the thousands within the first seconds
// instead of sitting at ↑ 0. The first Usage callback carries round 1's input; only the
// last carries the turn total.
func TestToolLoop_InputReachesIndicatorBeforeFinalRound(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "grep the tree then answer"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk(), usageChunk(8400, 3)},                                   // round 1: large prompt, ~no output
		{contentChunk("the answer"), finishChunk("stop"), usageChunk(8600, 120)}, // final answer
	}}
	disp := &fakeDispatcher{}

	var usageCalls [][2]int64
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Usage:  func(in, out int64) { usageCalls = append(usageCalls, [2]int64{in, out}) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	if len(usageCalls) < 2 {
		t.Fatalf("Usage callback fired %d times, want one per round (>=2): %v", len(usageCalls), usageCalls)
	}
	// The very first Usage call already carries round 1's real input (8400), proving ↑
	// reaches the round-1 prompt cost before the final round — not the final (17000, 123).
	if usageCalls[0] != [2]int64{8400, 3} {
		t.Fatalf("first Usage call = %v, want (8400, 3) (round-1 input surfaced immediately)", usageCalls[0])
	}
	if usageCalls[len(usageCalls)-1] != [2]int64{17000, 123} {
		t.Fatalf("last Usage call = %v, want (17000, 123) (turn total)", usageCalls[len(usageCalls)-1])
	}
}

// An intermediate tool-call round that carries no usage chunk (usage_missing)
// must not fire a spurious Usage callback — the cumulative total has no real figure to
// show yet. Only once the final round's usage chunk lands does the callback fire, once,
// with the turn total. The recorded model_response still carries usage_missing because
// one round was missing.
func TestToolLoop_UsageMissingRoundFiresNoSpuriousCall(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()}, // round 1: tool call, NO usage chunk
		{contentChunk("all done"), finishChunk("stop"), usageChunk(120, 40)}, // final answer + usage
	}}
	disp := &fakeDispatcher{}

	var usageCalls [][2]int64
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Usage:  func(in, out int64) { usageCalls = append(usageCalls, [2]int64{in, out}) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	// Exactly one Usage call (after the final round); the usage-missing round 1 fired none.
	if len(usageCalls) != 1 {
		t.Fatalf("Usage callback fired %d times, want 1 (the usage-missing round must not fire): %v", len(usageCalls), usageCalls)
	}
	if usageCalls[0] != [2]int64{120, 40} {
		t.Fatalf("Usage call = %v, want (120, 40) (only the final round had usage)", usageCalls[0])
	}
	// model_response still records usage_missing: one round had no usage chunk.
	mr := decodeModelResponse(t, store.Records())
	if len(mr.Anomaly) != 1 || mr.Anomaly[0] != "usage_missing" {
		t.Fatalf("model_response anomaly = %v, want [usage_missing] (round 1 carried no usage)", mr.Anomaly)
	}
}

// A usage-missing round in the MIDDLE of a turn — after an earlier round
// already reported usage — must not fire a spurious duplicate Usage callback. Once
// round 1 reports usage the accumulator's cumulative hadUsage stays true, so gating
// emission on hadUsage alone would re-emit round 1's stale total for the
// usage-missing round 2. Only the rounds that themselves carry a usage chunk fire:
// round 1 (100, 20) and the final round (220, 60); the missing middle round fires
// none. This is the producer-reachable sequence the missing-first-round test above
// cannot reach (there cumulative hadUsage was still false), so it is the one that
// catches a regression to cumulative-hadUsage gating.
func TestToolLoop_UsageMissingMiddleRoundFiresNoDuplicate(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk(), usageChunk(100, 20)}, // round 1: tool call WITH usage
		{toolCallChunk()},                      // round 2: tool call, NO usage chunk
		{contentChunk("done"), finishChunk("stop"), usageChunk(120, 40)}, // final answer + usage
	}}
	disp := &fakeDispatcher{}

	var usageCalls [][2]int64
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Usage:  func(in, out int64) { usageCalls = append(usageCalls, [2]int64{in, out}) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	// Exactly two Usage calls — round 1 and the final round. The usage-missing middle
	// round 2 fires none; gating on cumulative hadUsage would emit a duplicate (100, 20)
	// between them, making three calls.
	if len(usageCalls) != 2 {
		t.Fatalf("Usage callback fired %d times, want 2 (round 1 and final; the usage-missing middle round must fire none): %v", len(usageCalls), usageCalls)
	}
	if usageCalls[0] != [2]int64{100, 20} {
		t.Fatalf("first Usage call = %v, want (100, 20) (round 1)", usageCalls[0])
	}
	if usageCalls[1] != [2]int64{220, 60} {
		t.Fatalf("second Usage call = %v, want (220, 60) (turn total at the final round; no duplicate from the usage-missing middle round)", usageCalls[1])
	}
	// model_response still records usage_missing: the middle round had no usage chunk.
	mr := decodeModelResponse(t, store.Records())
	if len(mr.Anomaly) != 1 || mr.Anomaly[0] != "usage_missing" {
		t.Fatalf("model_response anomaly = %v, want [usage_missing] (round 2 carried no usage)", mr.Anomaly)
	}
}

// Across an agentic turn the live in-flight indicator's ↑ (input) and ↓ (output)
// series must each never decrease. Both channels advance only from the exact per-round
// Usage callback, whose figures come from the monotonic UsageAcc.Totals; the streamed
// Progress signal (retained output runes) is deliberately not fed into the indicator,
// because runes routinely exceed the round's exact output tokens and would make ↓ climb
// then drop. This fixture uses that realistic case — each round's streamed text has far
// more runes than its exact output tokens — to prove the Usage-driven series stays
// monotonic regardless. The binding-level guard that the production wiring really does
// keep runes out of ↓ lives in TestTurnController_IndicatorOutputNeverDecreasesWhenRunesExceedTokens
// (internal/bootstrap). This test also pins the separate ToolLoop concern that the
// cumulative Progress signal builds on round 1's retained chars across rounds.
func TestToolLoop_LiveProgressNeverDecreasesAcrossRounds(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do the thing"))

	const round1Text = "here is a longer first reply"       // 28 runes >> round-1 output tokens (3)
	const round2Text = "and an even longer final reply now" // streamed runes >> the round's output tokens (6)
	round1Chars := utf8.RuneCountInString(round1Text)
	round2Chars := utf8.RuneCountInString(round2Text)

	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk(round1Text), toolCallChunk(), usageChunk(100, 3)},     // content, tool call, usage
		{contentChunk(round2Text), finishChunk("stop"), usageChunk(120, 6)}, // answer, usage
	}}
	disp := &fakeDispatcher{}

	// Reconstruct the ↑/↓ figures the turndeps binding shows: only Usage advances the
	// indicator (↑ = input, ↓ = output); Progress is not wired to it. priorIn = priorOut
	// = 0 for this fresh session.
	var progress []int
	var ups, downs []int64
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Progress: func(retainedChars int) {
			progress = append(progress, retainedChars)
		},
		Usage: func(in, out int64) {
			ups = append(ups, in)
			downs = append(downs, out)
		},
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	assertNonDecreasing(t, "↑ input", ups)
	assertNonDecreasing(t, "↓ output", downs)
	if len(progress) < 2 {
		t.Fatalf("Progress calls = %d, want at least one per provider round", len(progress))
	}
	// The final round's live progress must include round 1's retained chars, not reset
	// to its own count: round1 + round2 cumulative across rounds.
	last := progress[len(progress)-1]
	if last != round1Chars+round2Chars {
		t.Fatalf("final live progress = %d, want %d (round1 %d + round2 %d cumulative across rounds)", last, round1Chars+round2Chars, round1Chars, round2Chars)
	}
}

// assertNonDecreasing fails if series dips at any index, naming the channel for a clear
// diagnostic when an ↑ or ↓ regression slips in.
func assertNonDecreasing(t *testing.T, name string, series []int64) {
	t.Helper()
	for i := 1; i < len(series); i++ {
		if series[i] < series[i-1] {
			t.Fatalf("%s series decreased across the turn: %v (index %d < index %d)", name, series, i, i-1)
		}
	}
}

// OnToolActivity fires exactly once per tool-call round, before any call is
// dispatched, with exactly ToolActivityLines(calls) in assembled order — and it still
// fires for a denied call (the line is emitted before the deny is even known). The
// dispatched-order snapshot taken inside the hook must be empty, pinning "before dispatch".
func TestToolLoop_ToolActivityFiresBeforeDispatch(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(
			toolFrag(0, "call_a", "bash", `{"command":"go build ./..."}`),
			toolFrag(1, "call_b", "read", `{"path":"server.go"}`),
		)},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: `{"denied_by":"user"}`, Denied: true}, nil // denied still shows its line
	}}

	var rounds [][]string
	var dispatchedWhenFired []int
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		OnToolActivity: func(lines []string) {
			rounds = append(rounds, append([]string(nil), lines...))
			dispatchedWhenFired = append(dispatchedWhenFired, len(disp.dispatchedOrder()))
		},
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if len(rounds) != 1 {
		t.Fatalf("OnToolActivity fired %d times, want once per tool-call round", len(rounds))
	}
	if dispatchedWhenFired[0] != 0 {
		t.Fatalf("%d calls already dispatched when OnToolActivity fired, want 0 (hook precedes dispatch)", dispatchedWhenFired[0])
	}
	want := ToolActivityLines([]AssembledToolCall{
		{ID: "call_a", Name: "bash", Arguments: `{"command":"go build ./..."}`},
		{ID: "call_b", Name: "read", Arguments: `{"path":"server.go"}`},
	})
	if joinLines(rounds[0]) != joinLines(want) {
		t.Fatalf("activity lines = %v, want %v (assembled order, matching ToolActivityLines)", rounds[0], want)
	}
}

// joinLines collapses a line slice to one string for order-sensitive equality without
// pulling in reflect; \x00 cannot appear in a formatted activity line.
func joinLines(lines []string) string { return strings.Join(lines, "\x00") }

// --- assertion helpers ------------------------------------------------------

// assertContinuation checks a follow-up provider request carries the assistant
// tool-call message for wantID and the tool-result message answering it with
// wantToolContent.
func assertContinuation(t *testing.T, req provider.Request, wantID, wantToolContent string) {
	t.Helper()
	var sawAssistant, sawTool bool
	for _, m := range req.Messages {
		if m.Role == "assistant" {
			for _, tc := range m.ToolCalls {
				if tc.ID == wantID {
					sawAssistant = true
				}
			}
		}
		if m.Role == "tool" && m.ToolCallID == wantID && m.Content == wantToolContent {
			sawTool = true
		}
	}
	if !sawAssistant {
		t.Fatalf("follow-up request missing assistant tool-call for %q; messages = %+v", wantID, req.Messages)
	}
	if !sawTool {
		t.Fatalf("follow-up request missing tool result for %q with %q; messages = %+v", wantID, wantToolContent, req.Messages)
	}
}

func lastAssistantText(recs []sessions.Record) string {
	last := ""
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "assistant" && len(m.ToolCalls) == 0 && !m.Content.IsList() {
			last = m.Content.Text()
		}
	}
	return last
}

func modelContextMessages(recs []sessions.Record) []sessions.Message {
	var out []sessions.Message
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "model_context" {
			out = append(out, m)
		}
	}
	return out
}

func requestHasImagePart(req provider.Request, uri string) bool {
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		for _, p := range m.Parts {
			if p.Type == "image_url" && p.ImageURL == uri {
				return true
			}
		}
	}
	return false
}

func messageRoleSeq(recs []sessions.Record) []string {
	var seq []string
	for _, r := range recs {
		m, ok := r.(sessions.Message)
		if !ok {
			continue
		}
		role := m.Role
		if role == "assistant" && len(m.ToolCalls) > 0 {
			role = "assistant_tc"
		}
		seq = append(seq, role)
	}
	return seq
}

func indexOf(seq []string, want string) int {
	for i, s := range seq {
		if s == want {
			return i
		}
	}
	return -1
}

func lastIndexOf(seq []string, want string) int {
	last := -1
	for i, s := range seq {
		if s == want {
			last = i
		}
	}
	return last
}

func TestToolLoop_DisplayPatchIsNeverPersistedOrResent(t *testing.T) {
	const patch = "--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n-old\n+new\n"
	const content = "edited a.txt (replaced 1 occurrence)"
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)
	store.Append(textMsg("user", "rename old to new"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "edit", `{"path":"a.txt","old_text":"old","new_text":"new"}`))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: content, DisplayPatch: patch}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	msgs := toolMessages(store.Records())
	if len(msgs) != 1 || msgs[0].ToolCallID != "call_1" {
		t.Fatalf("tool messages = %+v, want one for call_1", msgs)
	}
	if got := msgs[0].Content.Text(); got != content {
		t.Fatalf("tool message content = %q, want only the model-facing content %q", got, content)
	}

	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("store.Flush error = %v", err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if strings.Contains(string(persisted), "@@ -1 +1 @@") {
		t.Fatalf("session file persisted the transient patch:\n%s", persisted)
	}

	follow, ok := client.request(1)
	if !ok {
		t.Fatal("no follow-up request captured")
	}
	encoded, err := json.Marshal(follow.Messages)
	if err != nil {
		t.Fatalf("Marshal follow-up messages: %v", err)
	}
	if strings.Contains(string(encoded), "@@ -1 +1 @@") {
		t.Fatalf("follow-up request carried the transient patch: %s", encoded)
	}
	if !strings.Contains(string(encoded), content) {
		t.Fatalf("follow-up request lost the model-facing tool content: %s", encoded)
	}
}

const (
	editPatchA = "--- a.txt\n+++ a.txt\n@@ -1 +1 @@\n-old a\n+new a\n"
	editPatchB = "--- b.txt\n+++ b.txt\n@@ -1 +1 @@\n-old b\n+new b\n"
)

func TestToolLoop_EditPatchesFollowTheResultGroupInAssembledOrder(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(
			toolFrag(0, "call_a", "edit", `{"path":"a.txt"}`),
			toolFrag(1, "call_b", "bash", `{"command":"go build ./..."}`),
			toolFrag(2, "call_c", "edit", `{"path":"b.txt"}`),
			toolFrag(3, "call_d", "read", `{"path":"server.go"}`),
		)},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(call AssembledToolCall) (ToolResult, error) {
		switch call.ID {
		case "call_a":
			return ToolResult{Content: "edited a.txt", DisplayPatch: editPatchA}, nil
		case "call_c":
			return ToolResult{Content: "edited b.txt", DisplayPatch: editPatchB}, nil
		}
		return ToolResult{Content: "out:" + call.ID}, nil
	}}

	var activity [][]string
	var patches []string
	var resultsWhenDelivered []int
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		OnToolActivity: func(lines []string) {
			activity = append(activity, append([]string(nil), lines...))
		},
		OnEditPatch: func(patch string) {
			patches = append(patches, patch)
			resultsWhenDelivered = append(resultsWhenDelivered, len(toolMessages(store.Records())))
		},
	}, disp, 1)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	if len(activity) != 1 {
		t.Fatalf("OnToolActivity fired %d times, want once for the round's non-edit calls", len(activity))
	}
	want := ToolActivityLines([]AssembledToolCall{
		{ID: "call_b", Name: "bash", Arguments: `{"command":"go build ./..."}`},
		{ID: "call_d", Name: "read", Arguments: `{"path":"server.go"}`},
	})
	if joinLines(activity[0]) != joinLines(want) {
		t.Fatalf("activity lines = %v, want %v (non-edit calls only, assembled order)", activity[0], want)
	}
	for _, line := range activity[0] {
		if strings.HasPrefix(line, "Edit ") {
			t.Fatalf("pre-dispatch activity carried an edit placeholder %q", line)
		}
	}
	if joinLines(patches) != joinLines([]string{editPatchA, editPatchB}) {
		t.Fatalf("delivered patches = %v, want the two edits in assembled call order", patches)
	}
	for i, got := range resultsWhenDelivered {
		if got != 4 {
			t.Fatalf("patch %d delivered with %d tool results appended, want all 4 (the whole result group must be assembled first)", i, got)
		}
	}
}

func TestToolLoop_EditOnlyRoundEmitsNoPreDispatchActivity(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "edit", `{"path":"a.txt"}`))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: "edited a.txt", DisplayPatch: editPatchA}, nil
	}}

	activityRounds := 0
	var patches []string
	loop := NewToolLoop(Deps{
		Active:         selectedState("openai", "gpt-x", model.EffortDefault),
		Store:          store,
		Client:         client,
		OnToolActivity: func([]string) { activityRounds++ },
		OnEditPatch:    func(patch string) { patches = append(patches, patch) },
	}, disp, 1)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if activityRounds != 0 {
		t.Fatalf("OnToolActivity fired %d times for an edit-only round, want 0", activityRounds)
	}
	if joinLines(patches) != editPatchA {
		t.Fatalf("delivered patches = %v, want [%q]", patches, editPatchA)
	}
}

func TestToolLoop_AskUserRoundEmitsNoPreDispatchActivityButStillDispatches(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", provider.AskUserToolName, `{"questions":[{"id":"a","prompt":"p","options":["x"]}]}`))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: `{"answers":[]}`}, nil
	}}

	activityRounds := 0
	loop := NewToolLoop(Deps{
		Active:         selectedState("openai", "gpt-x", model.EffortDefault),
		Store:          store,
		Client:         client,
		OnToolActivity: func([]string) { activityRounds++ },
	}, disp, 1)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if activityRounds != 0 {
		t.Fatalf("OnToolActivity fired %d times for an ask_user-only round, want 0", activityRounds)
	}
	if got := disp.dispatchedOrder(); len(got) != 1 || got[0] != "call_1" {
		t.Fatalf("dispatched = %v, want [call_1] (the display filter must not reach scheduling)", got)
	}
	tools := toolMessages(store.Records())
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" || tools[0].Content.Text() != `{"answers":[]}` {
		t.Fatalf("tool messages = %+v, want the ask_user result persisted under call_1", tools)
	}
}

func TestToolLoop_MixedAskUserRoundKeepsTheOtherActivityLinesInOrder(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(
			toolFrag(0, "call_a", provider.AskUserToolName, `{"questions":[{"id":"a","prompt":"p","options":["x"]}]}`),
			toolFrag(1, "call_b", "bash", `{"command":"go build ./..."}`),
			toolFrag(2, "call_c", "edit", `{"path":"a.txt"}`),
			toolFrag(3, "call_d", "read", `{"path":"server.go"}`),
		)},
		finalAnswer("done"),
	}}

	var activity [][]string
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		OnToolActivity: func(lines []string) {
			activity = append(activity, append([]string(nil), lines...))
		},
	}, &fakeDispatcher{}, 1)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if len(activity) != 1 {
		t.Fatalf("OnToolActivity fired %d times, want once for the round's displayed calls", len(activity))
	}
	want := ToolActivityLines([]AssembledToolCall{
		{ID: "call_b", Name: "bash", Arguments: `{"command":"go build ./..."}`},
		{ID: "call_d", Name: "read", Arguments: `{"path":"server.go"}`},
	})
	if joinLines(activity[0]) != joinLines(want) {
		t.Fatalf("activity lines = %v, want %v (neither ask_user nor edit, assembled order)", activity[0], want)
	}
	for _, line := range activity[0] {
		if strings.Contains(line, provider.AskUserToolName) {
			t.Fatalf("pre-dispatch activity carried the raw tool name %q", line)
		}
	}
}

func TestToolLoop_UnsuccessfulEditsDeliverNoPatch(t *testing.T) {
	cases := []struct {
		name    string
		result  func(cancel context.CancelFunc) (ToolResult, error)
		wantErr bool
	}{
		{
			name: "user denial",
			result: func(context.CancelFunc) (ToolResult, error) {
				return ToolResult{Content: `{"denied_by":"user","reason":"refused"}`, Denied: true, DisplayPatch: editPatchA}, nil
			},
		},
		{
			name: "in-band failure",
			result: func(context.CancelFunc) (ToolResult, error) {
				return ToolResult{Content: "edit failed: stale old_text"}, nil
			},
		},
		{
			name: "dispatcher error",
			result: func(context.CancelFunc) (ToolResult, error) {
				return ToolResult{DisplayPatch: editPatchA}, errors.New("dispatch: internal failure")
			},
			wantErr: true,
		},
		{
			name: "cancelled mid-round",
			result: func(cancel context.CancelFunc) (ToolResult, error) {
				cancel()
				return ToolResult{Content: "edited a.txt", DisplayPatch: editPatchA}, nil
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			client := &scriptedClient{rounds: [][][]byte{
				{toolCallsChunk(toolFrag(0, "call_1", "edit", `{"path":"a.txt"}`))},
				finalAnswer("done"),
			}}
			disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
				return tc.result(cancel)
			}}

			var patches []string
			loop := NewToolLoop(Deps{
				Active:      selectedState("openai", "gpt-x", model.EffortDefault),
				Store:       store,
				Client:      client,
				OnEditPatch: func(patch string) { patches = append(patches, patch) },
			}, disp, 1)

			err := loop.Run(ctx)
			if tc.wantErr && err == nil {
				t.Fatal("loop.Run() error = nil, want the failure that ended the round")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if len(patches) != 0 {
				t.Fatalf("delivered patches = %v, want none for an edit that did not complete", patches)
			}
			for _, m := range toolMessages(store.Records()) {
				if strings.Contains(m.Content.Text(), "@@ -1 +1 @@") {
					t.Fatalf("tool result carried the transient patch: %q", m.Content.Text())
				}
			}
		})
	}
}

func TestToolLoop_ImageResultAppendsModelContextAndProjects(t *testing.T) {
	const imgURI = "data:image/png;base64,AAAA"
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "compare the labels"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "read_image", `{"path":"logo.png"}`))},
		finalAnswer("the label is blue"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: "read logo.png (image/png, 12 bytes)", ModelContextImage: imgURI}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	recs := store.Records()
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].ToolCallID != "call_1" {
		t.Fatalf("tool messages = %+v, want one for call_1", tools)
	}
	if strings.Contains(tools[0].Content.Text(), "data:") {
		t.Fatalf("tool message leaked the data URI: %q", tools[0].Content.Text())
	}
	mc := modelContextMessages(recs)
	if len(mc) != 1 || !mc[0].Content.IsList() {
		t.Fatalf("model_context messages = %+v, want one image list", mc)
	}
	parts := mc[0].Content.Parts()
	if len(parts) != 1 || parts[0].Type != "image_url" || !strings.Contains(string(parts[0].Raw), imgURI) {
		t.Fatalf("model_context parts = %+v, want one image_url part carrying the URI", parts)
	}

	seq := messageRoleSeq(recs)
	tcIdx, toolIdx, mcIdx := indexOf(seq, "assistant_tc"), indexOf(seq, "tool"), indexOf(seq, "model_context")
	if tcIdx < 0 || toolIdx < 0 || mcIdx < 0 || tcIdx >= toolIdx || toolIdx >= mcIdx {
		t.Fatalf("record order = %v, want assistant_tc < tool < model_context", seq)
	}

	follow, ok := client.request(1)
	if !ok {
		t.Fatalf("no follow-up request captured")
	}
	if !requestHasImagePart(follow, imgURI) {
		t.Fatalf("follow-up request carried no image_url part; messages = %+v", follow.Messages)
	}
}

func TestToolLoop_MixedImageAndTextResultsOrderContext(t *testing.T) {
	const uriB = "data:image/png;base64,BBBB"
	const uriC = "data:image/gif;base64,CCCC"
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "look at both"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(
			toolFrag(0, "call_a", "read", `{"path":"notes.txt"}`),
			toolFrag(1, "call_b", "read_image", `{"path":"a.png"}`),
			toolFrag(2, "call_c", "read_image", `{"path":"b.gif"}`),
		)},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{
		hold: 10 * time.Millisecond,
		resultFn: func(c AssembledToolCall) (ToolResult, error) {
			switch c.ID {
			case "call_b":
				return ToolResult{Content: "read a.png (image/png, 9 bytes)", ModelContextImage: uriB}, nil
			case "call_c":
				return ToolResult{Content: "read b.gif (image/gif, 9 bytes)", ModelContextImage: uriC}, nil
			default:
				return ToolResult{Content: "text of notes"}, nil
			}
		},
	}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	recs := store.Records()
	tools := toolMessages(recs)
	if len(tools) != 3 || tools[0].ToolCallID != "call_a" || tools[1].ToolCallID != "call_b" || tools[2].ToolCallID != "call_c" {
		t.Fatalf("tool messages = %+v, want three in call order a,b,c", tools)
	}
	mc := modelContextMessages(recs)
	if len(mc) != 2 {
		t.Fatalf("model_context messages = %d, want 2 (only the two successful images)", len(mc))
	}
	if !strings.Contains(string(mc[0].Content.Parts()[0].Raw), uriB) || !strings.Contains(string(mc[1].Content.Parts()[0].Raw), uriC) {
		t.Fatalf("model_context order = %+v, want the images in call order b then c", mc)
	}

	seq := messageRoleSeq(recs)
	lastTool, firstMC := lastIndexOf(seq, "tool"), indexOf(seq, "model_context")
	if lastTool < 0 || firstMC < 0 || lastTool >= firstMC {
		t.Fatalf("record order = %v, want the whole tool-result group before any model_context", seq)
	}
}

func TestToolLoop_FailedImageAppendsNoContext(t *testing.T) {
	const okURI = "data:image/png;base64,DDDD"
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "two images"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(
			toolFrag(0, "call_bad", "read_image", `{"path":"broken.png"}`),
			toolFrag(1, "call_ok", "read_image", `{"path":"good.png"}`),
		)},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		if c.ID == "call_bad" {
			return ToolResult{Content: "not a supported image file"}, nil
		}
		return ToolResult{Content: "read good.png (image/png, 9 bytes)", ModelContextImage: okURI}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	recs := store.Records()
	if len(toolMessages(recs)) != 2 {
		t.Fatalf("tool messages = %d, want 2", len(toolMessages(recs)))
	}
	mc := modelContextMessages(recs)
	if len(mc) != 1 || !strings.Contains(string(mc[0].Content.Parts()[0].Raw), okURI) {
		t.Fatalf("model_context messages = %+v, want exactly one for the successful image", mc)
	}
}

func TestToolLoop_ImageDurableAcrossLaterRoundAndReload(t *testing.T) {
	const imgURI = "data:image/webp;base64,EEEE"
	path := filepath.Join(t.TempDir(), "session.json")
	store := storeAt(path)
	store.Append(textMsg("user", "read the image then grep"))

	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_1", "read_image", `{"path":"pic.webp"}`))},
		{toolCallsChunk(toolFrag(0, "call_2", "grep", `{"pattern":"x"}`))},
		finalAnswer("done"),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		if c.ID == "call_1" {
			return ToolResult{Content: "read pic.webp (image/webp, 9 bytes)", ModelContextImage: imgURI}, nil
		}
		return ToolResult{Content: "grep: no matches"}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	for _, i := range []int{1, 2} {
		req, ok := client.request(i)
		if !ok {
			t.Fatalf("request %d not captured", i)
		}
		if !requestHasImagePart(req, imgURI) {
			t.Fatalf("round %d request carried no image_url part; messages = %+v", i, req.Messages)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	reloaded, err := sessions.Unmarshal(data)
	if err != nil {
		t.Fatalf("reload session: %v", err)
	}
	if err := sessions.ValidateRecordStream(reloaded.Records); err != nil {
		t.Fatalf("reloaded stream failed validation: %v", err)
	}
	if mc := modelContextMessages(reloaded.Records); len(mc) != 1 {
		t.Fatalf("reloaded model_context messages = %d, want 1", len(mc))
	}
	reloadedStore := sessions.New(path, reloaded)
	req, _, _, ok := BuildRequest(selectedState("openai", "gpt-x", model.EffortDefault), reloadedStore, "", nil)
	if !ok {
		t.Fatalf("BuildRequest over reloaded store ok = false")
	}
	if !requestHasImagePart(req, imgURI) {
		t.Fatalf("request from reloaded store carried no image_url part; messages = %+v", req.Messages)
	}
}

func TestToolLoop_AssemblyFailureRecordsPreDispatchTerminal(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "", "do", "{}"))},
		finalAnswer("unreached"),
	}}
	disp := &fakeDispatcher{}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 2)

	if err := loop.Run(context.Background()); err == nil {
		t.Fatal("loop.Run() error = nil, want the unassemblable tool call surfaced")
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeToolAssemblyFailed {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeToolAssemblyFailed)
	}
	if got.DispatchStarted {
		t.Fatal("dispatch_started = true for a round that failed before planning")
	}
	if n := len(disp.dispatchedOrder()); n != 0 {
		t.Fatalf("dispatched %d calls, want 0", n)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (retry is off by default)", client.callCount())
	}
}

func TestToolLoop_InvalidPlanRecordsPreDispatchTerminal(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallsChunk(toolFrag(0, "call_a", "a", "{}"), toolFrag(1, "call_b", "b", "{}"))},
		finalAnswer("unreached"),
	}}
	disp := &planMutatingDispatcher{mutate: func(u []PlannedToolCall) []PlannedToolCall { return u[:1] }}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 2)

	if err := loop.Run(context.Background()); err == nil {
		t.Fatal("loop.Run() error = nil, want the malformed plan rejected")
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeToolPlanInvalid {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeToolPlanInvalid)
	}
	if got.DispatchStarted {
		t.Fatal("dispatch_started = true for a plan rejected before the scheduler ran")
	}
	if n := disp.dispatchCount(); n != 0 {
		t.Fatalf("dispatched %d calls, want 0", n)
	}
}

func TestToolLoop_DispatchFailureRecordsTerminalAndNeverReplays(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},
		finalAnswer("unreached"),
	}}
	dispatchErr := errors.New("edit refused by the filesystem")
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{}, dispatchErr
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 2)

	if err := loop.Run(context.Background()); !errors.Is(err, dispatchErr) {
		t.Fatalf("loop.Run() error = %v, want %v", err, dispatchErr)
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeDispatchFailed {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeDispatchFailed)
	}
	if !got.DispatchStarted {
		t.Fatal("dispatch_started = false after the scheduler ran the call")
	}
	if order := disp.dispatchedOrder(); len(order) != 1 {
		t.Fatalf("dispatched %v, want exactly one attempt (a started dispatch is never replayed)", order)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (the round is not re-issued)", client.callCount())
	}
}

func TestToolLoop_DispatchFailureClassifiesTheFailedCall(t *testing.T) {
	secret := errors.New("fork/exec /bin/sh: cannot run `curl -H \"authorization: Bearer sk-live-abcdef\"`")
	for _, tc := range []struct {
		name       string
		tool       string
		wantReason string
		wantTool   string
	}{
		{name: "built-in name", tool: "bash", wantReason: events.DispatchReasonToolDispatchFailed, wantTool: "bash"},
		{name: "uppercase provider-valid name", tool: "BashTool", wantReason: events.DispatchReasonPostPlanFailed},
		{name: "over-long provider-valid name", tool: strings.Repeat("a", 33), wantReason: events.DispatchReasonPostPlanFailed},
		{name: "unadvertised name the model invented", tool: "ACCESSKEYEXAMPLE1234", wantReason: events.DispatchReasonPostPlanFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			client := &scriptedClient{rounds: [][][]byte{
				{toolCallsChunk(toolFrag(0, "call_1", tc.tool, `{"command":"cat /etc/shadow"}`))},
				finalAnswer("unreached"),
			}}
			disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
				return ToolResult{}, secret
			}}
			loop := NewToolLoop(Deps{
				Active: selectedState("openai", "gpt-x", model.EffortDefault),
				Store:  store,
				Client: client,
				Flush:  storeFlush(store),
			}, disp, 2)

			err := loop.Run(context.Background())
			if !errors.Is(err, secret) {
				t.Fatalf("loop.Run() error = %v, want the underlying error still matchable", err)
			}
			var failure *DispatchFailure
			if !errors.As(err, &failure) {
				t.Fatalf("loop.Run() error = %v, want a *DispatchFailure the surfaces can render", err)
			}
			if failure.Reason != tc.wantReason || failure.Tool != tc.wantTool {
				t.Fatalf("(reason, tool) = (%q, %q), want (%q, %q)", failure.Reason, failure.Tool, tc.wantReason, tc.wantTool)
			}
			if failure.SessionID != store.SessionID() {
				t.Fatalf("SessionID = %q, want the store's %q", failure.SessionID, store.SessionID())
			}

			got := onlyTerminal(t, store)
			if got.Outcome != events.TurnOutcomeDispatchFailed || !got.DispatchStarted {
				t.Fatalf("(outcome, dispatch_started) = (%q, %t), want (%q, true)", got.Outcome, got.DispatchStarted, events.TurnOutcomeDispatchFailed)
			}
			if got.FailureReason != tc.wantReason || got.FailedTool != tc.wantTool {
				t.Fatalf("persisted (failure_reason, failed_tool) = (%q, %q), want (%q, %q)", got.FailureReason, got.FailedTool, tc.wantReason, tc.wantTool)
			}

			for _, leak := range []string{"sk-live-abcdef", "/etc/shadow", "fork/exec", "curl", "authorization"} {
				if strings.Contains(got.FailedTool+" "+got.FailureReason, leak) {
					t.Fatalf("terminal record leaked %q: %+v", leak, got)
				}
				if strings.Contains(failure.Error(), leak) {
					t.Fatalf("DispatchFailure.Error() = %q leaked %q", failure.Error(), leak)
				}
			}
			if len(toolMessages(diskRecords(t, store))) != 0 {
				t.Fatal("a failed dispatch fabricated a tool result")
			}
			if order := disp.dispatchedOrder(); len(order) != 1 || client.callCount() != 1 {
				t.Fatalf("dispatched %v over %d provider call(s), want one attempt and no replay", order, client.callCount())
			}
		})
	}
}

type continueOnErrorDispatcher struct {
	errs     map[string]error
	terminal string
}

func (d continueOnErrorDispatcher) Plan(calls []AssembledToolCall, _ int) ToolPlan {
	plan := ToolPlan{Units: make([]PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = PlannedToolCall{
			Call:            call,
			ContinueOnError: call.ID != d.terminal,
			Run:             func(context.Context) (ToolResult, error) { return ToolResult{}, d.errs[call.ID] },
		}
	}
	return plan
}

func (d continueOnErrorDispatcher) Dispatch(_ context.Context, call AssembledToolCall) (ToolResult, error) {
	return ToolResult{}, d.errs[call.ID]
}

func TestToolLoop_DispatchFailureNamesTheReportedUnitNotADrainedSibling(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	boom := errors.New("the shell runner died")
	disp := continueOnErrorDispatcher{
		errs:     map[string]error{"call_1": context.Canceled, "call_2": boom},
		terminal: "call_2",
	}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Flush:  storeFlush(store),
	}, disp, 1)

	handoff := ToolCallHandoff{
		Report: &RoundReport{Outcome: events.TurnOutcomeCompleted},
		ToolCallDeltas: [][]openai.ChatCompletionChunkChoiceDeltaToolCall{{
			{Index: 0, ID: "call_1", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "read", Arguments: `{}`}},
			{Index: 1, ID: "call_2", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "bash", Arguments: `{}`}},
		}},
	}
	err := loop.onToolCalls(context.Background(), handoff)
	if !errors.Is(err, boom) {
		t.Fatalf("onToolCalls() error = %v, want the reported failure %v", err, boom)
	}
	var failure *DispatchFailure
	if !errors.As(err, &failure) {
		t.Fatalf("onToolCalls() error = %v, want a *DispatchFailure", err)
	}
	if failure.Tool != "bash" {
		t.Fatalf("failed tool = %q, want \"bash\" (the drained read sibling must not be named)", failure.Tool)
	}
	if handoff.Report.FailedTool != "bash" || handoff.Report.FailureReason != events.DispatchReasonToolDispatchFailed {
		t.Fatalf("report = %+v, want the reported unit's bounded diagnostic", handoff.Report)
	}
}

// A shared runner error is reported by whichever concurrent unit reaches it first and is
// recorded by every unit that saw it, so errors.Is matches them all; naming one would be a guess.
type sharedErrDispatcher struct {
	err   error
	first string
	gate  chan struct{}
}

func (d sharedErrDispatcher) Plan(calls []AssembledToolCall, _ int) ToolPlan {
	plan := ToolPlan{Units: make([]PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = PlannedToolCall{
			Call:            call,
			ContinueOnError: true,
			Run: func(ctx context.Context) (ToolResult, error) {
				if call.ID == d.first {
					close(d.gate)
				} else {
					select {
					case <-d.gate:
					case <-ctx.Done():
					}
				}
				return ToolResult{}, d.err
			},
		}
	}
	return plan
}

func (d sharedErrDispatcher) Dispatch(context.Context, AssembledToolCall) (ToolResult, error) {
	return ToolResult{}, d.err
}

func TestToolLoop_SharedDispatchErrorNamesNoTool(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	shared := errors.New("the shared runner died")
	disp := sharedErrDispatcher{err: shared, first: "call_2", gate: make(chan struct{})}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Flush:  storeFlush(store),
	}, disp, 2)

	handoff := ToolCallHandoff{
		Report: &RoundReport{Outcome: events.TurnOutcomeCompleted},
		ToolCallDeltas: [][]openai.ChatCompletionChunkChoiceDeltaToolCall{{
			{Index: 0, ID: "call_1", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "read", Arguments: `{}`}},
			{Index: 1, ID: "call_2", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "bash", Arguments: `{}`}},
		}},
	}
	err := loop.onToolCalls(context.Background(), handoff)
	if !errors.Is(err, shared) {
		t.Fatalf("onToolCalls() error = %v, want the shared failure %v", err, shared)
	}
	var failure *DispatchFailure
	if !errors.As(err, &failure) {
		t.Fatalf("onToolCalls() error = %v, want a *DispatchFailure", err)
	}
	if failure.Tool != "" || failure.Reason != events.DispatchReasonPostPlanFailed {
		t.Fatalf("(reason, tool) = (%q, %q), want (%q, \"\") — an error shared by two calls identifies neither", failure.Reason, failure.Tool, events.DispatchReasonPostPlanFailed)
	}
	if handoff.Report.FailedTool != "" || handoff.Report.FailureReason != events.DispatchReasonPostPlanFailed {
		t.Fatalf("report = %+v, want the generic post-plan diagnostic", handoff.Report)
	}
}

func TestToolLoop_CancelledDispatchIsNotReclassified(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{}, context.Canceled
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Flush:  storeFlush(store),
	}, disp, 1)

	handoff := ToolCallHandoff{
		Report: &RoundReport{Outcome: events.TurnOutcomeCompleted},
		ToolCallDeltas: [][]openai.ChatCompletionChunkChoiceDeltaToolCall{{
			{Index: 0, ID: "call_1", Type: "function", Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{Name: "bash", Arguments: `{}`}},
		}},
	}
	err := loop.onToolCalls(context.Background(), handoff)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("onToolCalls() error = %v, want the cancellation preserved", err)
	}
	var failure *DispatchFailure
	if errors.As(err, &failure) {
		t.Fatalf("a cancellation was reclassified as %+v; it must stay a cancellation", failure)
	}
	if handoff.Report.FailureReason != "" || handoff.Report.FailedTool != "" {
		t.Fatalf("report carried a dispatch diagnostic for a cancellation: %+v", handoff.Report)
	}
}

func TestToolLoop_DeniedCallRecordsDispatchStartedAndNeverReplays(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},
		finalAnswer("unreached"),
	}}
	disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: `{"denied_by":"user","reason":"you said no"}`, Denied: true}, nil
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, disp, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil (a user denial halts without an error)", err)
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeCompleted || !got.DispatchStarted {
		t.Fatalf("(outcome, dispatch_started) = (%q, %t), want (%q, true)", got.Outcome, got.DispatchStarted, events.TurnOutcomeCompleted)
	}
	if order := disp.dispatchedOrder(); len(order) != 1 {
		t.Fatalf("dispatched %v, want exactly one attempt for a denied call", order)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (a user denial does not re-issue)", client.callCount())
	}
}

func TestToolLoop_ContinuationFailureKeepsResultsAndNeverReplays(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},
		finalAnswer("unreached"),
	}}
	disp := &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		return ToolResult{Content: "out:" + c.ID, Terminal: true}, nil
	}}
	flushErr := errors.New("session write failed")
	flush := storeFlush(store)
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush: func() error {
			if len(disp.dispatchedOrder()) > 0 {
				return flushErr
			}
			return flush()
		},
	}, disp, 2)

	if err := loop.Run(context.Background()); !errors.Is(err, flushErr) {
		t.Fatalf("loop.Run() error = %v, want %v", err, flushErr)
	}

	got := onlyTerminal(t, store)
	if got.Outcome != events.TurnOutcomeContinuationFailed {
		t.Fatalf("outcome = %q, want %q", got.Outcome, events.TurnOutcomeContinuationFailed)
	}
	if !got.DispatchStarted {
		t.Fatal("dispatch_started = false after a round whose tools ran")
	}
	recs := diskRecords(t, store)
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].Content.Text() != "out:call_1" {
		t.Fatalf("persisted tool messages = %+v, want the one recorded result intact", tools)
	}
	if order := disp.dispatchedOrder(); len(order) != 1 {
		t.Fatalf("dispatched %v, want exactly one attempt", order)
	}
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1", client.callCount())
	}
}

func TestToolLoop_EveryRoundOfATurnRecordsOneTerminal(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{
		{toolCallChunk()},
		finalAnswer("all done"),
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
	}, &fakeDispatcher{}, 2)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	recs := diskRecords(t, store)
	terminals := turnTerminalEvents(t, recs)
	if len(terminals) != 2 {
		t.Fatalf("persisted turn_terminal events = %d, want one per provider round; kinds = %v", len(terminals), eventKinds(recs))
	}
	if terminals[0].Outcome != events.TurnOutcomeCompleted || !terminals[0].DispatchStarted {
		t.Fatalf("tool round = (%q, %t), want (%q, true)", terminals[0].Outcome, terminals[0].DispatchStarted, events.TurnOutcomeCompleted)
	}
	if terminals[1].Outcome != events.TurnOutcomeCompleted || terminals[1].DispatchStarted {
		t.Fatalf("final round = (%q, %t), want (%q, false)", terminals[1].Outcome, terminals[1].DispatchStarted, events.TurnOutcomeCompleted)
	}
	if terminals[0].TurnID != terminals[1].TurnID {
		t.Fatalf("turn ids = (%q, %q), want both rounds under one turn", terminals[0].TurnID, terminals[1].TurnID)
	}
	if terminals[0].RoundID == terminals[1].RoundID {
		t.Fatalf("both rounds recorded round id %q, want distinct ids", terminals[0].RoundID)
	}
	rounds := providerRoundTripEvents(t, recs)
	if len(rounds) != 2 {
		t.Fatalf("provider_round_trip events = %d, want 2", len(rounds))
	}
	for i, r := range rounds {
		if r.TurnID != terminals[i].TurnID || r.RoundID != terminals[i].RoundID {
			t.Fatalf("round %d correlation = (%q, %q), want the terminal record's (%q, %q)",
				i, r.TurnID, r.RoundID, terminals[i].TurnID, terminals[i].RoundID)
		}
	}
}

// partitionDispatcher plans the shape the production planner produces: 'e' units continue on
// error so their concurrent segment drains, 'x' units are serial barriers whose PreRun guard
// returns the lowest-index eligible failure recorded so far.
type partitionDispatcher struct {
	shape string
	fail  map[string]error
	// waitFor holds a unit until another unit has recorded its outcome, so a test can pin which
	// concurrent failure lands in the latch first.
	waitFor map[string]chan struct{}
	signal  map[string]chan struct{}

	mu    sync.Mutex
	ran   []string
	err   error
	index int
	set   bool
}

func (d *partitionDispatcher) record(index int, err error) {
	if err == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.set || index < d.index {
		d.err, d.index, d.set = err, index, true
	}
}

func (d *partitionDispatcher) recorded() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

func (d *partitionDispatcher) Plan(calls []AssembledToolCall, _ int) ToolPlan {
	plan := ToolPlan{Units: make([]PlannedToolCall, len(calls))}
	var segment []string
	barrier := ""
	for i, call := range calls {
		unit := PlannedToolCall{Call: call}
		if d.shape[i] == 'e' {
			unit.ContinueOnError = true
			unit.Run = func(ctx context.Context) (ToolResult, error) {
				if wait, ok := d.waitFor[call.ID]; ok {
					<-wait
				}
				res, err := d.Dispatch(ctx, call)
				d.record(i, err)
				if signal, ok := d.signal[call.ID]; ok {
					close(signal)
				}
				return res, err
			}
			if barrier != "" {
				unit.Deps = []string{barrier}
			}
			segment = append(segment, call.ID)
		} else {
			unit.Targets = []string{"serial"}
			unit.Deps = segment
			unit.PreRun = func(context.Context) error { return d.recorded() }
			unit.Run = func(ctx context.Context) (ToolResult, error) { return d.Dispatch(ctx, call) }
			barrier, segment = call.ID, nil
		}
		plan.Units[i] = unit
	}
	return plan
}

func (d *partitionDispatcher) Dispatch(_ context.Context, call AssembledToolCall) (ToolResult, error) {
	d.mu.Lock()
	d.ran = append(d.ran, call.ID)
	d.mu.Unlock()
	if err, ok := d.fail[call.ID]; ok {
		return ToolResult{}, err
	}
	return ToolResult{Content: "out:" + call.ID}, nil
}

func (d *partitionDispatcher) executed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.ran)
}

func runPartitionRound(t *testing.T, disp ToolDispatcher, maxConcurrency int, ids ...string) (*sessions.Store, error) {
	t.Helper()
	frags := make([]string, len(ids))
	for i, id := range ids {
		frags[i] = toolFrag(i, id, "t"+id, "{}")
	}
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	client := &scriptedClient{rounds: [][][]byte{{toolCallsChunk(frags...)}, finalAnswer("done")}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, maxConcurrency)
	return store, loop.Run(context.Background())
}

func TestToolLoop_EligibleFailureDrainsItsSegmentAndStopsLaterCalls(t *testing.T) {
	boom := errors.New("read failed")
	disp := &partitionDispatcher{shape: "xeexe", fail: map[string]error{"c1": boom}}

	store, err := runPartitionRound(t, disp, 3, "c0", "c1", "c2", "c3", "c4")
	if !errors.Is(err, boom) {
		t.Fatalf("loop.Run() error = %v, want the eligible failure %v", err, boom)
	}

	ran := disp.executed()
	slices.Sort(ran)
	if want := []string{"c0", "c1", "c2"}; !slices.Equal(ran, want) {
		t.Fatalf("executed = %v, want %v (the earlier barrier stands, the failing segment drains, nothing later runs)", ran, want)
	}
	recs := store.Records()
	if len(assistantToolCallMessages(recs)) != 0 || len(toolMessages(recs)) != 0 {
		t.Fatal("assistant/tool messages appended for a failed round; want none")
	}
}

func TestToolLoop_ConcurrentEligibleFailuresSurfaceTheLowestIndex(t *testing.T) {
	first, second := errors.New("first failed"), errors.New("second failed")
	for _, tc := range []struct {
		name, shape, records, waits string
		ids                         []string
	}{
		{"barrier follows, lower index records first", "eex", "c0", "c1", []string{"c0", "c1", "c2"}},
		{"barrier follows, higher index records first", "eex", "c1", "c0", []string{"c0", "c1", "c2"}},
		{"terminal segment, lower index records first", "ee", "c0", "c1", []string{"c0", "c1"}},
		{"terminal segment, higher index records first", "ee", "c1", "c0", []string{"c0", "c1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorded := make(chan struct{})
			disp := &partitionDispatcher{
				shape:   tc.shape,
				fail:    map[string]error{"c0": first, "c1": second},
				signal:  map[string]chan struct{}{tc.records: recorded},
				waitFor: map[string]chan struct{}{tc.waits: recorded},
			}

			_, err := runPartitionRound(t, disp, 3, tc.ids...)
			if !errors.Is(err, first) {
				t.Fatalf("loop.Run() error = %v, want the lowest model-call-index failure %v regardless of completion order", err, first)
			}
			if ran := disp.executed(); !slices.Contains(ran, "c0") || !slices.Contains(ran, "c1") {
				t.Fatalf("executed = %v, want the whole failing segment to drain", ran)
			}
			if slices.Contains(disp.executed(), "c2") {
				t.Fatalf("executed = %v, want the barrier after a failing segment left unexecuted", disp.executed())
			}
		})
	}
}

func TestToolLoop_ExcludedFailureStopsEveryLaterCall(t *testing.T) {
	boom := errors.New("barrier failed")
	disp := &partitionDispatcher{shape: "xeex", fail: map[string]error{"c0": boom}}

	_, err := runPartitionRound(t, disp, 3, "c0", "c1", "c2", "c3")
	if !errors.Is(err, boom) {
		t.Fatalf("loop.Run() error = %v, want the excluded failure %v", err, boom)
	}
	if ran := disp.executed(); !slices.Equal(ran, []string{"c0"}) {
		t.Fatalf("executed = %v, want only the failing barrier", ran)
	}
}

type timeLimitClient struct {
	mu       sync.Mutex
	requests []provider.Request
	ctxErrs  []error
	rounds   []func(ctx context.Context) (provider.Response, error)
}

func (c *timeLimitClient) ChatCompletion(ctx context.Context, req provider.Request) (provider.Response, error) {
	c.mu.Lock()
	i := len(c.requests)
	c.requests = append(c.requests, req)
	c.ctxErrs = append(c.ctxErrs, ctx.Err())
	c.mu.Unlock()
	if i >= len(c.rounds) {
		return provider.Response{}, fmt.Errorf("unexpected provider request %d", i+1)
	}
	return c.rounds[i](ctx)
}

func answer(text string) func(context.Context) (provider.Response, error) {
	return func(context.Context) (provider.Response, error) {
		return provider.Response{Stream: newStream(finalAnswer(text)...)}, nil
	}
}

func timeLimitLoop(t *testing.T, client *timeLimitClient, disp ToolDispatcher) (*ToolLoop, *sessions.Store, *streamSurface, *int) {
	t.Helper()
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "survey the repo"))
	surface := &streamSurface{}
	rollbacks := 0
	if disp == nil {
		disp = &fakeDispatcher{}
	}
	loop := NewToolLoop(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Tools:           []provider.ToolDefinition{{Name: "do", Parameters: map[string]any{"type": "object"}}},
		Sink:            surface.sink,
		Finalize:        surface.finalize,
		Interrupt:       surface.interrupt,
		RollbackPartial: func() { rollbacks++; surface.open.Reset() },
		Flush:           storeFlush(store),
	}, disp, 3)
	return loop, store, surface, &rollbacks
}

func assertTimeLimitWrapUp(t *testing.T, client *timeLimitClient, loop *ToolLoop, store *sessions.Store, wantRequests int, wantFinal string) {
	t.Helper()
	if len(client.requests) != wantRequests {
		t.Fatalf("provider requests = %d, want %d", len(client.requests), wantRequests)
	}
	final := client.requests[wantRequests-1]
	if len(final.Tools) != 0 {
		t.Fatalf("final request advertised %d tools, want none", len(final.Tools))
	}
	if last := final.Messages[len(final.Messages)-1]; last.Role != "system" || last.Content != wrapUpText(timeLimitCause) {
		t.Fatalf("final request's last message = %+v, want the wrap-up instruction", last)
	}
	if got := systemMessages(diskRecords(t, store)); !slices.Equal(got, []string{wrapUpText(timeLimitCause)}) {
		t.Fatalf("durable system messages = %q, want the time-limit cause before the instruction", got)
	}
	if err := client.ctxErrs[wantRequests-1]; err != nil {
		t.Fatalf("final request context error = %v, want the live parent context", err)
	}
	if !loop.TimeLimitReached() {
		t.Fatal("TimeLimitReached() = false, want true")
	}
	if got := lastAssistantText(store.Records()); got != wantFinal {
		t.Fatalf("final assistant text = %q, want %q", got, wantFinal)
	}
}

func TestToolLoop_TimeLimitAlreadyPassedSendsOnlyTheFinalRequest(t *testing.T) {
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){answer("summary so far")}}
	loop, store, surface, _ := timeLimitLoop(t, client, nil)
	loop.SetDeadline(time.Now().Add(-time.Second))

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertTimeLimitWrapUp(t, client, loop, store, 1, "summary so far")
	if surface.shown() != "summary so far" {
		t.Fatalf("shown = %q, want only the final answer", surface.shown())
	}
}

func TestToolLoop_TimeLimitDuringStreamDiscardsThePartial(t *testing.T) {
	for _, tc := range []struct{ name, first string }{
		{"ordinary prose", "Half an answer"},
		{"held text tool call", `{"name":"grep"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var loop *ToolLoop
			client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
				func(ctx context.Context) (provider.Response, error) {
					dec := &cancelDecoder{ctx: ctx, first: contentChunk(tc.first), onWait: func() { loop.Expire() }}
					return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
				},
				answer("final answer"),
			}}
			loop, store, surface, rollbacks := timeLimitLoop(t, client, nil)
			loop.SetDeadline(time.Now().Add(time.Hour))

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			assertTimeLimitWrapUp(t, client, loop, store, 2, "final answer")
			if *rollbacks == 0 {
				t.Fatal("RollbackPartial was not called for the time-limited round")
			}
			if surface.shown() != "final answer" {
				t.Fatalf("shown = %q, want only the final answer", surface.shown())
			}
		})
	}
}

type expireDecoder struct {
	sliceDecoder
	expire func()
}

func (d *expireDecoder) Next() bool {
	if d.i == 1 {
		d.expire()
	}
	return d.sliceDecoder.Next()
}

func TestToolLoop_TimeLimitBeforeCleanStreamEndRejectsTheReply(t *testing.T) {
	var loop *ToolLoop
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(context.Context) (provider.Response, error) {
			dec := &expireDecoder{sliceDecoder: sliceDecoder{events: finalAnswer("ordinary reply")}, expire: func() { loop.Expire() }}
			return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
		},
		answer("final answer"),
	}}
	loop, store, surface, rollbacks := timeLimitLoop(t, client, nil)
	loop.SetDeadline(time.Now().Add(time.Hour))

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertTimeLimitWrapUp(t, client, loop, store, 2, "final answer")
	if *rollbacks == 0 {
		t.Fatal("RollbackPartial was not called for the time-limited round")
	}
	if surface.shown() != "final answer" {
		t.Fatalf("shown = %q, want only the final answer", surface.shown())
	}
	for _, rec := range store.Records() {
		if msg, ok := rec.(sessions.Message); ok && msg.Role == "assistant" && msg.Content.Text() == "ordinary reply" {
			t.Fatal("the reply that finished after the time limit was accepted")
		}
	}
}

func TestToolLoop_TimeLimitBeforeCleanToolCallStreamEndSkipsDispatch(t *testing.T) {
	var loop *ToolLoop
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(context.Context) (provider.Response, error) {
			events := [][]byte{contentChunk("Let me look first."), toolCallsChunk(toolFrag(0, "c1", "do", "{}"))}
			dec := &expireDecoder{sliceDecoder: sliceDecoder{events: events}, expire: func() { loop.Expire() }}
			return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
		},
		answer("final answer"),
	}}
	disp := &fakeDispatcher{}
	loop, store, surface, rollbacks := timeLimitLoop(t, client, disp)
	loop.SetDeadline(time.Now().Add(time.Hour))

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertTimeLimitWrapUp(t, client, loop, store, 2, "final answer")
	if *rollbacks == 0 {
		t.Fatal("RollbackPartial was not called for the time-limited round")
	}
	if surface.shown() != "final answer" {
		t.Fatalf("shown = %q, want only the final answer", surface.shown())
	}
	if len(disp.order) != 0 {
		t.Fatalf("dispatched %v after the time limit, want nothing", disp.order)
	}
	if got, want := messageRoleSeq(store.Records()), []string{"user", "system", "assistant"}; !slices.Equal(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
}

func TestToolLoop_TimeLimitDuringRetryBackoffWrapsUp(t *testing.T) {
	var loop *ToolLoop
	restore := sleep
	sleep = func(ctx context.Context, _ time.Duration) error {
		loop.Expire()
		<-ctx.Done()
		return ctx.Err()
	}
	t.Cleanup(func() { sleep = restore })
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(context.Context) (provider.Response, error) { return dropStream("Par", io.ErrUnexpectedEOF), nil },
		answer("final answer"),
	}}
	loop, store, surface, _ := timeLimitLoop(t, client, nil)
	loop.deps.Retry = retryOn()
	loop.SetDeadline(time.Now().Add(time.Hour))

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertTimeLimitWrapUp(t, client, loop, store, 2, "final answer")
	if surface.shown() != "final answer" {
		t.Fatalf("shown = %q, want only the final answer", surface.shown())
	}
}

type timeLimitDispatcher struct {
	expire    func()
	doneRan   chan struct{}
	ranQueued bool
	done      *ToolResult
	slowErr   error
}

func (d *timeLimitDispatcher) Plan(calls []AssembledToolCall, _ int) ToolPlan {
	units := make([]PlannedToolCall, len(calls))
	for i, call := range calls {
		units[i] = PlannedToolCall{Call: call}
		switch call.ID {
		case "done":
			units[i].Run = func(context.Context) (ToolResult, error) {
				defer close(d.doneRan)
				if d.done != nil {
					return *d.done, nil
				}
				return ToolResult{Content: "finished before time ran out"}, nil
			}
		case "slow":
			units[i].Run = func(ctx context.Context) (ToolResult, error) {
				<-d.doneRan
				d.expire()
				<-ctx.Done()
				if d.slowErr != nil {
					return ToolResult{}, d.slowErr
				}
				return ToolResult{}, ctx.Err()
			}
		case "queued":
			units[i].Deps = []string{"slow"}
			units[i].Run = func(context.Context) (ToolResult, error) {
				d.ranQueued = true
				return ToolResult{Content: "ran"}, nil
			}
		}
	}
	return ToolPlan{Units: units}
}

func (d *timeLimitDispatcher) Dispatch(context.Context, AssembledToolCall) (ToolResult, error) {
	return ToolResult{}, errors.New("unexpected direct dispatch")
}

func TestToolLoop_TimeLimitDuringDispatchKeepsCompletedResults(t *testing.T) {
	calls := toolCallsChunk(toolFrag(0, "done", "do", "{}"), toolFrag(1, "slow", "do", "{}"), toolFrag(2, "queued", "do", "{}"))
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(context.Context) (provider.Response, error) {
			return provider.Response{Stream: newStream(calls)}, nil
		},
		answer("final answer"),
	}}
	disp := &timeLimitDispatcher{doneRan: make(chan struct{})}
	loop, store, _, _ := timeLimitLoop(t, client, disp)
	disp.expire = func() { loop.Expire() }
	loop.SetDeadline(time.Now().Add(time.Hour))

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertTimeLimitWrapUp(t, client, loop, store, 2, "final answer")
	if disp.ranQueued {
		t.Fatal("the queued call started after the time limit")
	}
	recs := store.Records()
	if got, want := messageRoleSeq(recs), []string{"user", "assistant_tc", "tool", "tool", "tool", "system", "assistant"}; !slices.Equal(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
	final := client.requests[1]
	assertContinuation(t, final, "done", "finished before time ran out")
	assertContinuation(t, final, "slow", timeLimitCancelledResult)
	assertContinuation(t, final, "queued", timeLimitCancelledResult)
}

func TestToolLoop_TimeLimitDuringDispatchWrapsUpAfterATerminalResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		done ToolResult
	}{
		{"terminal result", ToolResult{Content: "stop here", Terminal: true}},
		{"terminal denial", ToolResult{Content: "refused", Denied: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := toolCallsChunk(toolFrag(0, "done", "do", "{}"), toolFrag(1, "slow", "do", "{}"))
			client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
				func(context.Context) (provider.Response, error) {
					return provider.Response{Stream: newStream(calls)}, nil
				},
				answer("final answer"),
			}}
			disp := &timeLimitDispatcher{doneRan: make(chan struct{}), done: &tc.done}
			loop, store, _, _ := timeLimitLoop(t, client, disp)
			disp.expire = func() { loop.Expire() }
			loop.SetDeadline(time.Now().Add(time.Hour))

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			assertTimeLimitWrapUp(t, client, loop, store, 2, "final answer")
			assertContinuation(t, client.requests[1], "slow", timeLimitCancelledResult)
		})
	}
}

func TestToolLoop_TimeLimitDuringDispatchKeepsARealFailure(t *testing.T) {
	calls := toolCallsChunk(toolFrag(0, "done", "do", "{}"), toolFrag(1, "slow", "do", "{}"))
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(context.Context) (provider.Response, error) {
			return provider.Response{Stream: newStream(calls)}, nil
		},
		answer("final answer"),
	}}
	broken := errors.New("dispatch broke")
	disp := &timeLimitDispatcher{doneRan: make(chan struct{}), slowErr: broken}
	loop, store, _, _ := timeLimitLoop(t, client, disp)
	disp.expire = func() { loop.Expire() }
	loop.SetDeadline(time.Now().Add(time.Hour))

	if err := loop.Run(context.Background()); !errors.Is(err, broken) {
		t.Fatalf("Run() error = %v, want %v", err, broken)
	}
	if len(client.requests) != 1 {
		t.Fatalf("provider requests = %d, want 1", len(client.requests))
	}
	if got := messageRoleSeq(store.Records()); !slices.Equal(got, []string{"user"}) {
		t.Fatalf("records = %v, want no tool-call group", got)
	}
}

func TestToolLoop_TimeLimitDoesNotRetriggerDuringRefusalWrapUp(t *testing.T) {
	loop, _, store, _ := wrapUpLoop(t, nil)
	tl := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(context.Context) (provider.Response, error) {
			return provider.Response{Stream: newStream(toolCallChunk())}, nil
		},
		func(ctx context.Context) (provider.Response, error) {
			loop.Expire()
			return answer("refusal wrap-up")(ctx)
		},
	}}
	loop.deps.Client = tl
	loop.SetDeadline(time.Now().Add(time.Hour))

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(tl.requests) != 2 {
		t.Fatalf("provider requests = %d, want 2", len(tl.requests))
	}
	if loop.TimeLimitReached() {
		t.Fatal("TimeLimitReached() = true, want the refusal to own the only wrap-up")
	}
	if got := lastAssistantText(store.Records()); got != "refusal wrap-up" {
		t.Fatalf("final assistant text = %q", got)
	}
}

func TestToolLoop_ParentCancelWithTimeLimitSendsNoFinalRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(streamCtx context.Context) (provider.Response, error) {
			cancel()
			dec := &cancelDecoder{ctx: streamCtx, first: contentChunk("Hello")}
			return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
		},
	}}
	loop, _, _, _ := timeLimitLoop(t, client, nil)
	loop.SetDeadline(time.Now().Add(time.Hour))

	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if len(client.requests) != 1 || loop.TimeLimitReached() {
		t.Fatalf("requests = %d, TimeLimitReached = %v; want 1 and false", len(client.requests), loop.TimeLimitReached())
	}
}

func TestToolLoop_TimeLimitFinalReplyWriteFailureFailsTheRun(t *testing.T) {
	reply := [][]byte{contentChunk("partial summary"), toolCallChunk()}
	client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
		func(context.Context) (provider.Response, error) {
			return provider.Response{Stream: newStream(reply...)}, nil
		},
	}}
	loop, _, _, _ := timeLimitLoop(t, client, nil)
	writeErr := errors.New("stdout closed")
	loop.deps.FinalizeErr = func() error { return writeErr }
	loop.SetDeadline(time.Now().Add(-time.Second))

	if err := loop.Run(context.Background()); !errors.Is(err, writeErr) {
		t.Fatalf("Run() error = %v, want the final write failure", err)
	}
}

type midTurnHarness struct {
	t             *testing.T
	dir           string
	store         *sessions.Store
	loop          *ToolLoop
	cancel        context.CancelFunc
	requests      []provider.Request
	added         []string
	finalizes     int
	suggestions   int
	writeFailures []sessions.WriteReason
}

type midTurnScript struct {
	respond  func(h *midTurnHarness, call int) (provider.Response, error)
	dispatch func(h *midTurnHarness) ToolResult
	usage    func(h *midTurnHarness)
}

func newMidTurnHarness(t *testing.T, s midTurnScript) (*midTurnHarness, context.Context) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "session")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create session directory: %v", err)
	}
	h := &midTurnHarness{t: t, dir: dir, store: storeAt(filepath.Join(dir, "session.json"))}
	h.store.Append(textMsg("user", "do X"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.cancel = cancel
	client := &fakeClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		h.requests = append(h.requests, req)
		return s.respond(h, len(h.requests)-1)
	}}
	disp := &fakeDispatcher{resultFn: func(call AssembledToolCall) (ToolResult, error) {
		if s.dispatch == nil {
			return ToolResult{Content: "out:" + call.ID}, nil
		}
		return s.dispatch(h), nil
	}}
	h.loop = NewToolLoop(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           h.store,
		Client:          client,
		Flush:           storeFlush(h.store),
		Finalize:        func() { h.finalizes++ },
		SubmitStart:     time.Now().Add(-time.Millisecond),
		SuggestFollowup: func(string, string) { h.suggestions++ },
		Usage: func(int64, int64) {
			if s.usage != nil {
				s.usage(h)
			}
		},
		OnUserMessageAdded: func(text string, _ []sessions.ContentPart) { h.added = append(h.added, text) },
		OnFailureWrite: func(_ fserrors.Category, reason sessions.WriteReason, _ error) {
			h.writeFailures = append(h.writeFailures, reason)
		},
	}, disp, 3)
	return h, ctx
}

func (h *midTurnHarness) add(text string, parts ...sessions.ContentPart) {
	if !h.loop.AddUserMessage(text, parts) {
		h.t.Errorf("AddUserMessage(%q) = false during the turn, want true", text)
	}
}

func streamResponse(chunks ...[]byte) (provider.Response, error) {
	return provider.Response{Stream: newStream(chunks...)}, nil
}

func userTextCount(recs []sessions.Record, text string) int {
	n := 0
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "user" && !m.Content.IsList() && m.Content.Text() == text {
			n++
		}
	}
	return n
}

func TestToolLoop_UserMessageAddedDuringToolRoundReachesTheNextRequest(t *testing.T) {
	img := imagePart(testImageURI)
	h, ctx := newMidTurnHarness(t, midTurnScript{
		respond: func(_ *midTurnHarness, call int) (provider.Response, error) {
			if call == 0 {
				return streamResponse(toolCallChunk())
			}
			return streamResponse(finalAnswer("done")...)
		},
		dispatch: func(h *midTurnHarness) ToolResult {
			h.add("and also Y")
			h.add("look at this", img)
			h.add("", img)
			return ToolResult{Content: "out:call_1"}
		},
	})

	if err := h.loop.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(h.requests) != 2 {
		t.Fatalf("provider requests = %d, want 2", len(h.requests))
	}
	msgs := h.requests[1].Messages
	tool := slices.IndexFunc(msgs, func(m provider.Message) bool { return m.Role == "tool" && m.ToolCallID == "call_1" })
	if tool < 0 || len(msgs) != tool+4 {
		t.Fatalf("follow-up messages = %+v, want the tool result followed by exactly three user messages", msgs)
	}
	want := []provider.Message{
		{Role: "user", Content: "and also Y"},
		{Role: "user", Parts: []provider.ContentPart{{Type: "text", Text: "look at this"}, {Type: "image_url", ImageURL: testImageURI}}},
		{Role: "user", Parts: []provider.ContentPart{{Type: "image_url", ImageURL: testImageURI}}},
	}
	for i, w := range want {
		got := msgs[tool+1+i]
		if got.Role != w.Role || got.Content != w.Content || !slices.Equal(got.Parts, w.Parts) {
			t.Fatalf("follow-up message %d = %+v, want %+v", i, got, w)
		}
	}
	if !slices.Equal(h.added, []string{"and also Y", "look at this", ""}) {
		t.Fatalf("OnUserMessageAdded = %q, want the three messages in submit order", h.added)
	}

	disk := diskRecords(t, h.store)
	var injected []sessions.Message
	for _, r := range disk {
		if m, ok := r.(sessions.Message); ok && m.Role == "user" {
			injected = append(injected, m)
		}
	}
	if len(injected) != 4 {
		t.Fatalf("persisted user messages = %d, want the prompt plus three injected", len(injected))
	}
	injected = injected[1:]
	if injected[0].Content.IsList() || injected[0].Content.Text() != "and also Y" {
		t.Fatalf("text message content = %+v, want string content", injected[0].Content)
	}
	wantParts := [][]sessions.ContentPart{{textContentPart("look at this"), img}, {img}}
	for i, parts := range wantParts {
		c := injected[i+1].Content
		if !c.IsList() || len(c.Parts()) != len(parts) {
			t.Fatalf("image message %d content = %+v, want %d parts", i, c, len(parts))
		}
		for j, p := range parts {
			if got := c.Parts()[j]; got.Type != p.Type || string(got.Raw) != string(p.Raw) {
				t.Fatalf("image message %d part %d = %s %s, want %s %s", i, j, got.Type, got.Raw, p.Type, p.Raw)
			}
		}
	}
	for _, r := range h.store.Records() {
		m, ok := r.(sessions.Message)
		if !ok || m.Role != "user" || m.Content.Text() == "do X" {
			continue
		}
		if !ids.IsValidV7(m.ID) || m.Timestamp.Location() != time.UTC {
			t.Fatalf("injected record id %q timestamp %v, want a UUIDv7 and a UTC timestamp", m.ID, m.Timestamp)
		}
	}
}

func TestToolLoop_UserMessageAddedDuringFinalAnswerExtendsTheTurn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first [][]byte
	}{
		{"natural", [][]byte{contentChunk("answer to X"), finishChunk("stop"), usageChunk(100, 10)}},
		{"suggest-only", [][]byte{contentChunk("answer to X"), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), usageChunk(100, 10)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ctx := newMidTurnHarness(t, midTurnScript{
				respond: func(h *midTurnHarness, call int) (provider.Response, error) {
					if call == 0 {
						h.add("actually X and Y")
						return streamResponse(tc.first...)
					}
					return streamResponse(contentChunk("answer to X and Y"), finishChunk("stop"), usageChunk(130, 12))
				},
			})

			if err := h.loop.Run(ctx); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if len(h.requests) != 2 {
				t.Fatalf("provider requests = %d, want 2", len(h.requests))
			}
			msgs := h.requests[1].Messages
			if n := len(msgs); n < 2 || msgs[n-2].Role != "assistant" || msgs[n-2].Content != "answer to X" ||
				msgs[n-1].Role != "user" || msgs[n-1].Content != "actually X and Y" {
				t.Fatalf("second request messages = %+v, want the first answer then the added message", msgs)
			}
			recs := diskRecords(t, h.store)
			if got := assistantMessages(recs); len(got) != 2 || got[0].Content.Text() != "answer to X" || got[1].Content.Text() != "answer to X and Y" {
				t.Fatalf("assistant messages = %+v, want both answers", got)
			}
			if resp := decodeModelResponse(t, recs); resp.InputTokens != 230 || resp.OutputTokens != 22 {
				t.Fatalf("model_response tokens = %d/%d, want the cumulative 230/22", resp.InputTokens, resp.OutputTokens)
			}
			if n := len(turnLatencyEvents(t, recs)); n != 1 {
				t.Fatalf("turn_latency events = %d, want 1", n)
			}
			if h.finalizes != 1 {
				t.Fatalf("Finalize calls = %d, want 1", h.finalizes)
			}
			if n := len(providerRoundTripEvents(t, recs)); n != 2 {
				t.Fatalf("provider_round_trip events = %d, want one per round", n)
			}
			terminals := turnTerminalEvents(t, recs)
			if len(terminals) != 2 || terminals[0].Outcome != events.TurnOutcomeCompleted || terminals[1].Outcome != events.TurnOutcomeCompleted {
				t.Fatalf("turn_terminal events = %+v, want two completed rounds", terminals)
			}
			if h.suggestions != 0 {
				t.Fatalf("SuggestFollowup calls = %d, want none for the superseded answer", h.suggestions)
			}
			if !slices.Equal(h.added, []string{"actually X and Y"}) || len(h.loop.Unsent()) != 0 {
				t.Fatalf("added = %q unsent = %+v, want the message committed once", h.added, h.loop.Unsent())
			}
			if h.loop.AddUserMessage("after", nil) {
				t.Fatal("AddUserMessage after Run = true, want false")
			}
		})
	}
}

func TestToolLoop_PendingUserMessageIsUnsentWhenTheLoopEnds(t *testing.T) {
	toolRound := func(_ *midTurnHarness, call int) (provider.Response, error) {
		if call == 0 {
			return streamResponse(toolCallChunk(), usageChunk(10, 2))
		}
		return streamResponse(finalAnswer("final")...)
	}
	addThen := func(res ToolResult) func(h *midTurnHarness) ToolResult {
		return func(h *midTurnHarness) ToolResult {
			h.add("late")
			return res
		}
	}
	for _, tc := range []struct {
		name             string
		script           midTurnScript
		timeLimit        bool
		wantErr          bool
		wantWriteFailure bool
	}{
		{name: "provider error", wantErr: true, script: midTurnScript{respond: func(h *midTurnHarness, _ int) (provider.Response, error) {
			h.add("late")
			return provider.Response{}, &provider.HTTPError{Status: 400, Body: "bad request", Surface: "HTTP 400"}
		}}},
		{name: "cancellation", wantErr: true, script: midTurnScript{respond: func(h *midTurnHarness, _ int) (provider.Response, error) {
			h.add("late")
			h.cancel()
			return provider.Response{}, context.Canceled
		}}},
		{name: "denial halt", script: midTurnScript{respond: toolRound,
			dispatch: addThen(ToolResult{Content: `{"denied_by":"user","reason":"no"}`, Denied: true})}},
		{name: "terminal tool result", script: midTurnScript{respond: toolRound,
			dispatch: addThen(ToolResult{Content: "stopped", Terminal: true})}},
		{name: "wrap-up", script: midTurnScript{respond: toolRound,
			dispatch: addThen(ToolResult{Content: permissions.BuildUnattendedDenyEnvelope("no approval"), Denied: true, WrapUp: true})}},
		{name: "time limit", timeLimit: true, script: midTurnScript{respond: func(*midTurnHarness, int) (provider.Response, error) {
			return streamResponse(finalAnswer("summary")...)
		}}},
		{name: "closed store", wantErr: true, script: midTurnScript{respond: func(h *midTurnHarness, _ int) (provider.Response, error) {
			h.add("late")
			h.store.Close()
			return streamResponse(finalAnswer("answer")...)
		}}},
		{name: "drain commit failure", wantErr: true, wantWriteFailure: true, script: midTurnScript{respond: toolRound,
			dispatch: addThen(ToolResult{Content: "out"}),
			usage: func(h *midTurnHarness) {
				if err := os.RemoveAll(h.dir); err != nil {
					h.t.Fatalf("remove session directory: %v", err)
				}
				if err := os.WriteFile(h.dir, []byte("not a directory"), 0o600); err != nil {
					h.t.Fatalf("replace session directory: %v", err)
				}
			}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ctx := newMidTurnHarness(t, tc.script)
			if tc.timeLimit {
				h.loop.SetDeadline(time.Now().Add(-time.Second))
				h.add("late")
			}

			err := h.loop.Run(ctx)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Run() error = %v, want error %v", err, tc.wantErr)
			}
			if got := h.loop.Unsent(); len(got) != 1 || got[0].Text != "late" || got[0].Parts != nil {
				t.Fatalf("Unsent() = %+v, want the one pending message", got)
			}
			if n := userTextCount(h.store.Records(), "late"); n != 0 {
				t.Fatalf("store holds %d copies of the unsent message, want 0", n)
			}
			if len(h.added) != 0 {
				t.Fatalf("OnUserMessageAdded = %q, want no call for an uncommitted message", h.added)
			}
			if h.loop.AddUserMessage("after", nil) {
				t.Fatal("AddUserMessage after Run = true, want false")
			}
			if tc.wantWriteFailure && !slices.ContainsFunc(h.writeFailures, func(r sessions.WriteReason) bool { return r != sessions.ReasonNone }) {
				t.Fatalf("OnFailureWrite reasons = %v, want the drain commit's write failure", h.writeFailures)
			}
		})
	}
}

func TestToolLoop_CommittedUserMessageIsNotUnsentWhenALaterRoundFails(t *testing.T) {
	h, ctx := newMidTurnHarness(t, midTurnScript{
		respond: func(_ *midTurnHarness, call int) (provider.Response, error) {
			if call == 0 {
				return streamResponse(toolCallChunk())
			}
			return provider.Response{}, &provider.HTTPError{Status: 400, Body: "bad request", Surface: "HTTP 400"}
		},
		dispatch: func(h *midTurnHarness) ToolResult {
			h.add("in time")
			return ToolResult{Content: "out"}
		},
	})

	if err := h.loop.Run(ctx); err == nil {
		t.Fatal("Run() error = nil, want the second round's failure")
	}
	if got := h.loop.Unsent(); len(got) != 0 {
		t.Fatalf("Unsent() = %+v, want none after the message was committed", got)
	}
	if n := userTextCount(diskRecords(t, h.store), "in time"); n != 1 {
		t.Fatalf("persisted copies = %d, want 1", n)
	}
	if !slices.Equal(h.added, []string{"in time"}) {
		t.Fatalf("OnUserMessageAdded = %q, want one call", h.added)
	}
}

func TestToolLoop_ConcurrentAddUserMessageLandsExactlyOnce(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "go"))
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	client := &fakeClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		once.Do(func() {
			close(held)
			<-release
		})
		return streamResponse(finalAnswer("ok")...)
	}}
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, &fakeDispatcher{}, 3)

	done := make(chan error, 1)
	go func() { done <- loop.Run(context.Background()) }()
	select {
	case <-held:
	case err := <-done:
		t.Fatalf("Run() returned %v before the first provider call", err)
	}

	const workers, perWorker = 8, 200
	accepted := make([][]string, workers)
	rejected := make([][]string, workers)
	finished := make(chan struct{})
	var ready, wg sync.WaitGroup
	ready.Add(workers)
	submit := func(w int, text string) {
		if loop.AddUserMessage(text, nil) {
			accepted[w] = append(accepted[w], text)
		} else {
			rejected[w] = append(rejected[w], text)
		}
	}
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			submit(w, fmt.Sprintf("m-%d-held", w))
			ready.Done()
			for i := range perWorker {
				submit(w, fmt.Sprintf("m-%d-%d", w, i))
			}
			<-finished
			submit(w, fmt.Sprintf("m-%d-after", w))
		}()
	}
	ready.Wait()
	close(release)
	err := <-done
	close(finished)
	wg.Wait()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if n := client.callCount(); n < 2 {
		t.Fatalf("provider calls = %d, want the held final answer extended by the pending messages", n)
	}
	for w := range workers {
		if len(accepted[w]) == 0 || accepted[w][0] != fmt.Sprintf("m-%d-held", w) {
			t.Fatalf("worker %d accepted %q, want its submission during the held response accepted", w, accepted[w])
		}
		if len(rejected[w]) == 0 || rejected[w][len(rejected[w])-1] != fmt.Sprintf("m-%d-after", w) {
			t.Fatalf("worker %d rejected %q, want its submission after Run returned rejected", w, rejected[w])
		}
	}

	seen := map[string]int{}
	for _, r := range store.Records() {
		if m, ok := r.(sessions.Message); ok && m.Role == "user" {
			seen[m.Content.Text()]++
		}
	}
	for _, m := range loop.Unsent() {
		seen[m.Text]++
	}
	for w := range workers {
		for _, text := range accepted[w] {
			if seen[text] != 1 {
				t.Fatalf("accepted %q appears %d times across the store and Unsent, want exactly 1", text, seen[text])
			}
		}
		for _, text := range rejected[w] {
			if seen[text] != 0 {
				t.Fatalf("rejected %q appears %d times, want 0", text, seen[text])
			}
		}
	}
}

const roundLimitNoticeText = "codemeld: this turn reached its 200-round limit; tools were removed and the model is writing its final answer. Send a new message to continue."

func repeatNoticeText(names string) string {
	return "codemeld: this turn repeated the same tool call (" + names + ") 3 rounds in a row; tools were removed and the model is writing its final answer. Send a new message to continue."
}

type limitHarness struct {
	store    *sessions.Store
	loop     *ToolLoop
	disp     *fakeDispatcher
	fail     func(request int) bool
	requests []provider.Request
	notices  []string
	noticeAt []int
}

func newLimitHarness(t *testing.T, store *sessions.Store, respond func(request int) (provider.Response, error)) *limitHarness {
	t.Helper()
	h := &limitHarness{store: store, disp: &fakeDispatcher{}}
	client := &fakeClient{fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
		h.requests = append(h.requests, req)
		n := len(h.requests)
		if h.fail != nil && h.fail(n) {
			return provider.Response{}, &provider.HTTPError{Status: 503, Body: "busy", Surface: "provider openai returned HTTP 503: busy"}
		}
		if len(req.Tools) == 0 {
			return streamResponse(contentChunk("final answer"), finishChunk("stop"), usageChunk(10, 1))
		}
		return respond(n)
	}}
	h.loop = NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		Flush:  storeFlush(store),
		Tools:  []provider.ToolDefinition{{Name: "do", Parameters: map[string]any{"type": "object"}}},
		ToolNotice: func(text string) {
			h.notices = append(h.notices, text)
			h.noticeAt = append(h.noticeAt, len(h.requests))
		},
	}, h.disp, 3)
	return h
}

func limitStore(t *testing.T) *sessions.Store {
	t.Helper()
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "go"))
	return store
}

func callRound(id, name, args string) (provider.Response, error) {
	return streamResponse(toolCallsChunk(toolFrag(0, id, name, args)), usageChunk(10, 1))
}

func distinctCall(n int) (provider.Response, error) {
	return callRound(fmt.Sprintf("call_%d", n), "do", fmt.Sprintf(`{"n":%d}`, n))
}

func limitNotices(notices []string) []string {
	var out []string
	for _, n := range notices {
		if strings.HasPrefix(n, "codemeld: this turn ") {
			out = append(out, n)
		}
	}
	return out
}

const (
	timeLimitCause  = "The run's time limit was reached, ending tool use in this turn."
	roundLimitCause = "This turn reached its 200-round limit."
	refusalCause    = "Repeated refusals of a tool call ended tool use in this turn."
)

func wrapUpText(cause string) string {
	return cause + " For this assistant turn only, tools are no longer available. Write your final answer now, using only the information you already have. If your final answer reports why work stopped, state this cause. This restriction ends when the next user message starts a new turn; follow the tools and instructions supplied for that new turn."
}

func systemMessages(recs []sessions.Record) []string {
	var out []string
	for _, r := range recs {
		if m, ok := r.(sessions.Message); ok && m.Role == "system" {
			out = append(out, m.Content.Text())
		}
	}
	return out
}

func TestToolLoop_RoundLimitMakesTheTwoHundredthRoundTheWrapUp(t *testing.T) {
	store := limitStore(t)
	h := newLimitHarness(t, store, distinctCall)

	if err := h.loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if len(h.requests) != 200 {
		t.Fatalf("provider requests = %d, want 200", len(h.requests))
	}
	for i, req := range h.requests[:199] {
		if len(req.Tools) == 0 {
			t.Fatalf("request %d offered no tools, want tools before the limit", i+1)
		}
	}
	if n := len(h.requests[199].Tools); n != 0 {
		t.Fatalf("request 200 offered %d tools, want none on the wrap-up round", n)
	}
	if final := lastAssistantText(store.Records()); final != "final answer" {
		t.Fatalf("final assistant text = %q, want the wrap-up answer", final)
	}
	if !slices.Equal(h.notices, []string{roundLimitNoticeText}) || h.noticeAt[0] != 199 {
		t.Fatalf("notices = %q at requests %v, want the round-limit notice once before request 200", h.notices, h.noticeAt)
	}
	if got := systemMessages(diskRecords(t, store)); !slices.Equal(got, []string{wrapUpText(roundLimitCause)}) {
		t.Fatalf("durable system messages = %q, want the wrap-up instruction", got)
	}
}

func TestToolLoop_ThirdIdenticalToolCallRoundWrapsUp(t *testing.T) {
	type step struct {
		name, args string
		thenUser   bool
	}
	same := step{name: "do", args: `{"path":"a.txt"}`}
	sameThenUser := step{name: "do", args: `{"path":"a.txt"}`, thenUser: true}
	oneCharOff := step{name: "do", args: `{"path":"b.txt"}`}
	other := step{name: "look", args: `{"path":"a.txt"}`}
	for _, tc := range []struct {
		name  string
		steps []step
		wrap  bool
	}{
		{"three identical rounds", []step{same, same, same}, true},
		{"two identical rounds", []step{same, same}, false},
		{"arguments differ by one character", []step{same, same, oneCharOff, same}, false},
		{"a different call in between", []step{same, other, same, same}, false},
		{"a user message resets the count", []step{same, sameThenUser, same, same}, false},
		{"a third identical round after a user message", []step{same, sameThenUser, same, same, same}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := limitStore(t)
			h := newLimitHarness(t, store, func(n int) (provider.Response, error) {
				if n > len(tc.steps) {
					return streamResponse(contentChunk("natural answer"), finishChunk("stop"))
				}
				s := tc.steps[n-1]
				return callRound(fmt.Sprintf("call_%d", n), s.name, s.args)
			})
			h.disp.resultFn = func(call AssembledToolCall) (ToolResult, error) {
				if tc.steps[len(h.requests)-1].thenUser {
					h.loop.AddUserMessage("I fixed it, run it again", nil)
				}
				return ToolResult{Content: "out:" + call.ID}, nil
			}

			if err := h.loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if len(h.requests) != len(tc.steps)+1 {
				t.Fatalf("provider requests = %d, want %d", len(h.requests), len(tc.steps)+1)
			}
			recs := store.Records()
			if got := len(toolMessages(recs)); got != len(tc.steps) {
				t.Fatalf("tool results = %d, want one per dispatched round (%d)", got, len(tc.steps))
			}
			last := h.requests[len(tc.steps)]
			if !tc.wrap {
				if len(last.Tools) == 0 || len(h.notices) != 0 || len(systemMessages(recs)) != 0 {
					t.Fatalf("last request tools = %d, notices = %q, system = %q; want no wrap-up", len(last.Tools), h.notices, systemMessages(recs))
				}
				return
			}
			if len(last.Tools) != 0 {
				t.Fatalf("request after the third identical round offered %d tools, want the wrap-up round", len(last.Tools))
			}
			if !slices.Equal(h.notices, []string{repeatNoticeText("do")}) || h.noticeAt[0] != len(tc.steps) {
				t.Fatalf("notices = %q at requests %v, want the repeat notice once before the wrap-up round", h.notices, h.noticeAt)
			}
			if seq := messageRoleSeq(recs); !slices.Equal(seq[len(seq)-3:], []string{"tool", "system", "assistant"}) {
				t.Fatalf("message roles = %v, want the third round's result, the instruction, then the answer", seq)
			}
			if got, want := systemMessages(recs), wrapUpText("The same tool call (do) was repeated 3 rounds in a row."); !slices.Equal(got, []string{want}) {
				t.Fatalf("stored system messages = %q, want %q", got, want)
			}
			if final := lastAssistantText(recs); final != "final answer" {
				t.Fatalf("final assistant text = %q, want the wrap-up answer", final)
			}
		})
	}
}

func TestToolLoop_FailedRetryAttemptBreaksTheRepeatStreak(t *testing.T) {
	failures := map[string]func() (provider.Response, error){
		"empty response": func() (provider.Response, error) { return streamResponse(finishChunk("stop")) },
		"stream drop":    func() (provider.Response, error) { return dropStream("", io.ErrUnexpectedEOF), nil },
		"pre-stream": func() (provider.Response, error) {
			return provider.Response{}, &provider.HTTPError{Status: 503, Body: "busy", Surface: "provider openai returned HTTP 503: busy"}
		},
	}
	for name, fail := range failures {
		for _, after := range []int{2, 3} {
			t.Run(fmt.Sprintf("%s then %d identical calls", name, after), func(t *testing.T) {
				noSleep(t)
				calls := 2 + after
				store := limitStore(t)
				h := newLimitHarness(t, store, func(n int) (provider.Response, error) {
					switch {
					case n == 3:
						return fail()
					case n <= calls+1:
						return callRound(fmt.Sprintf("call_%d", n), "do", `{"path":"a.txt"}`)
					}
					return streamResponse(contentChunk("natural answer"), finishChunk("stop"))
				})
				h.loop.deps.Retry = retryOn()

				if err := h.loop.Run(context.Background()); err != nil {
					t.Fatalf("loop.Run() error = %v, want nil", err)
				}
				recs := store.Records()
				if got := len(toolMessages(recs)); got != calls {
					t.Fatalf("tool results = %d, want %d", got, calls)
				}
				if got := len(findProviderRequestRetry(t, recs)); got != 1 {
					t.Fatalf("retries = %d, want 1", got)
				}
				last := h.requests[len(h.requests)-1]
				if after == 2 {
					if len(last.Tools) == 0 || len(h.notices) != 0 || lastAssistantText(recs) != "natural answer" {
						t.Fatalf("last request tools = %d, notices = %q, final = %q; want no wrap-up", len(last.Tools), h.notices, lastAssistantText(recs))
					}
					return
				}
				if len(last.Tools) != 0 || !slices.Equal(h.notices, []string{repeatNoticeText("do")}) || h.noticeAt[0] != calls+1 {
					t.Fatalf("last request tools = %d, notices = %q at %v; want one repeat wrap-up after the third call following the failure", len(last.Tools), h.notices, h.noticeAt)
				}
				if seq := messageRoleSeq(recs); !slices.Equal(seq[len(seq)-3:], []string{"tool", "system", "assistant"}) {
					t.Fatalf("message roles = %v, want the third round's result, the instruction, then the answer", seq)
				}
			})
		}
	}
}

func TestToolLoop_RepeatNoticeNamesBoundedToolsWithoutArguments(t *testing.T) {
	names := []string{"grep\nfiles\tnow", strings.Repeat("é", 70), "c", "d", "e"}
	args := "{\"pattern\":\"secret\nvalue\twith controls\"}"
	store := limitStore(t)
	h := newLimitHarness(t, store, func(n int) (provider.Response, error) {
		frags := make([]string, len(names))
		for i, name := range names {
			frags[i] = toolFrag(i, fmt.Sprintf("call_%d_%d", n, i), name, args)
		}
		return streamResponse(toolCallsChunk(frags...))
	})

	if err := h.loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	want := repeatNoticeText("grep files now, " + strings.Repeat("é", 64) + "…, c, +2 more")
	if !slices.Equal(h.notices, []string{want}) {
		t.Fatalf("notices = %q, want %q", h.notices, want)
	}
	if strings.ContainsAny(h.notices[0], "\n\r\t") || strings.Contains(h.notices[0], "secret") {
		t.Fatalf("notice = %q, want one line with no argument text", h.notices[0])
	}
}

func TestToolLoop_RepeatAtTheRoundLimitWrapsUpOnceWithTheRoundLimitNotice(t *testing.T) {
	store := limitStore(t)
	h := newLimitHarness(t, store, func(n int) (provider.Response, error) {
		if n >= 197 {
			return callRound(fmt.Sprintf("call_%d", n), "do", `{"path":"a.txt"}`)
		}
		return distinctCall(n)
	})

	if err := h.loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if len(h.requests) != 200 || len(h.requests[199].Tools) != 0 {
		t.Fatalf("provider requests = %d, want 200 ending in one tool-less wrap-up", len(h.requests))
	}
	if !slices.Equal(h.notices, []string{roundLimitNoticeText}) || h.noticeAt[0] != 199 {
		t.Fatalf("notices = %q at requests %v, want only the round-limit notice before request 200", h.notices, h.noticeAt)
	}
	recs := store.Records()
	if got := systemMessages(recs); !slices.Equal(got, []string{wrapUpText(roundLimitCause)}) {
		t.Fatalf("system messages = %q, want one wrap-up instruction with the round-limit cause", got)
	}
	if got := len(toolMessages(recs)); got != 199 {
		t.Fatalf("tool results = %d, want 199", got)
	}
	if seq := messageRoleSeq(recs); !slices.Equal(seq[len(seq)-3:], []string{"tool", "system", "assistant"}) {
		t.Fatalf("message roles end %v, want the last result before the instruction", seq[len(seq)-3:])
	}
}

func TestToolLoop_TerminalRoundAtALimitHaltsWithoutWrapUp(t *testing.T) {
	userDenial := ToolResult{Content: `{"denied_by":"user","reason":"no"}`, Denied: true}
	terminal := ToolResult{Content: "stopped", Terminal: true}
	for _, tc := range []struct {
		name   string
		at     int
		repeat bool
		result ToolResult
	}{
		{"terminal result on the third identical round", 3, true, terminal},
		{"user denial on the third identical round", 3, true, userDenial},
		{"terminal result on round 199", 199, false, terminal},
		{"user denial on round 199", 199, false, userDenial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := limitStore(t)
			h := newLimitHarness(t, store, func(n int) (provider.Response, error) {
				if tc.repeat {
					return callRound(fmt.Sprintf("call_%d", n), "do", "{}")
				}
				return distinctCall(n)
			})
			h.disp.resultFn = func(call AssembledToolCall) (ToolResult, error) {
				if len(h.requests) == tc.at {
					return tc.result, nil
				}
				return ToolResult{Content: "out:" + call.ID}, nil
			}

			if err := h.loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if len(h.requests) != tc.at {
				t.Fatalf("provider requests = %d, want %d (the terminal round halts)", len(h.requests), tc.at)
			}
			if got := limitNotices(h.notices); len(got) != 0 {
				t.Fatalf("limit notices = %q, want none after a halt", got)
			}
			if got := systemMessages(store.Records()); len(got) != 0 {
				t.Fatalf("system messages = %q, want no wrap-up after a halt", got)
			}
		})
	}
}

func TestToolLoop_RetriesCountTowardTheRoundLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fail      func(request int) bool
		requests  int
		wantFinal bool
		retries   int
	}{
		{"request 199 fails and is not retried", func(n int) bool { return n == 199 }, 199, false, 0},
		{"the wrap-up request fails and is not retried", func(n int) bool { return n == 200 }, 200, false, 0},
		{"an earlier retry still counts", func(n int) bool { return n == 2 }, 200, true, 1},
		{"every round needs a retry", func(n int) bool { return n%2 == 1 }, 199, false, 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noSleep(t)
			store := limitStore(t)
			h := newLimitHarness(t, store, distinctCall)
			h.fail = tc.fail
			h.loop.deps.Retry = retryOn()

			err := h.loop.Run(context.Background())
			if len(h.requests) != tc.requests {
				t.Fatalf("provider requests = %d, want %d", len(h.requests), tc.requests)
			}
			recs := store.Records()
			if got := len(findProviderRequestRetry(t, recs)); got != tc.retries {
				t.Fatalf("retries = %d, want %d", got, tc.retries)
			}
			if tc.wantFinal {
				if err != nil || lastAssistantText(recs) != "final answer" {
					t.Fatalf("loop.Run() error = %v, final = %q; want the wrap-up answer", err, lastAssistantText(recs))
				}
				return
			}
			var httpErr *provider.HTTPError
			if !errors.As(err, &httpErr) {
				t.Fatalf("loop.Run() error = %v, want the original HTTP failure", err)
			}
			skipped := findProviderRequestRetrySkipped(t, recs)
			if len(skipped) != 1 || skipped[0].SkipReason != "max_attempts_reached" {
				t.Fatalf("retry_skipped = %+v, want one max_attempts_reached", skipped)
			}
			if kindIndex(recs, events.KindProviderRequestFailed) < 0 {
				t.Fatalf("no provider_request_failed committed; kinds = %v", eventKinds(recs))
			}
			if wrapped := len(systemMessages(recs)) == 1; wrapped != (tc.requests == 200) {
				t.Fatalf("system messages = %q, want a wrap-up only when the wrap-up request itself failed", systemMessages(recs))
			}
		})
	}
}

func TestToolLoop_NextTurnAfterARoundLimitGetsToolsAndFreshCounts(t *testing.T) {
	store := limitStore(t)
	first := newLimitHarness(t, store, distinctCall)
	if err := first.loop.Run(context.Background()); err != nil {
		t.Fatalf("first turn error = %v, want nil", err)
	}
	instruction := systemMessages(store.Records())
	if len(instruction) != 1 || !strings.Contains(instruction[0], "This restriction ends when the next user message starts a new turn") ||
		strings.HasPrefix(instruction[0], "Tools are no longer available") {
		t.Fatalf("persisted wrap-up instruction = %q, want one scoped to its own turn", instruction)
	}

	store.Append(textMsg("user", "continue"))
	second := newLimitHarness(t, store, func(n int) (provider.Response, error) {
		if n <= 2 {
			return callRound(fmt.Sprintf("next_%d", n), "do", `{"n":199}`)
		}
		return streamResponse(contentChunk("second answer"), finishChunk("stop"))
	})
	if err := second.loop.Run(context.Background()); err != nil {
		t.Fatalf("second turn error = %v, want nil", err)
	}
	if len(second.requests) != 3 {
		t.Fatalf("second turn requests = %d, want 3", len(second.requests))
	}
	for i, req := range second.requests {
		if len(req.Tools) == 0 {
			t.Fatalf("second turn request %d offered no tools, want fresh limits", i+1)
		}
	}
	if len(second.notices) != 0 {
		t.Fatalf("second turn notices = %q, want none", second.notices)
	}
	if got := second.disp.dispatchedOrder(); !slices.Equal(got, []string{"next_1", "next_2"}) {
		t.Fatalf("second turn dispatched %v, want both calls", got)
	}
	if !slices.ContainsFunc(second.requests[0].Messages, func(m provider.Message) bool { return m.Role == "user" && m.Content == "go" }) {
		t.Fatal("second turn request omits the earlier turn's messages")
	}
}

func TestToolLoop_NextTurnAfterATimeLimitGetsTools(t *testing.T) {
	store := limitStore(t)
	first := newLimitHarness(t, store, distinctCall)
	first.loop.SetDeadline(time.Now().Add(-time.Second))
	if err := first.loop.Run(context.Background()); err != nil {
		t.Fatalf("first turn error = %v, want nil", err)
	}
	want := wrapUpText(timeLimitCause)
	if got := systemMessages(store.Records()); !slices.Equal(got, []string{want}) {
		t.Fatalf("persisted wrap-up instruction = %q, want %q", got, want)
	}

	store.Append(textMsg("user", "continue"))
	second := newLimitHarness(t, store, func(int) (provider.Response, error) {
		return streamResponse(contentChunk("second answer"), finishChunk("stop"))
	})
	if err := second.loop.Run(context.Background()); err != nil {
		t.Fatalf("second turn error = %v, want nil", err)
	}
	req := second.requests[0]
	if len(req.Tools) == 0 {
		t.Fatal("second turn request offered no tools after the earlier time limit")
	}
	if !slices.ContainsFunc(req.Messages, func(m provider.Message) bool { return m.Role == "system" && m.Content == want }) {
		t.Fatal("second turn request does not replay the earlier wrap-up instruction")
	}
}

func TestToolLoop_RefusalWrapUpKeepsItsCauseWhenTheDeadlineExpires(t *testing.T) {
	refusal := ToolResult{Content: permissions.BuildUnattendedDenyEnvelope("no approval"), Denied: true, WrapUp: true}
	t.Run("deadline expires after the wrap-up began", func(t *testing.T) {
		client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
			func(context.Context) (provider.Response, error) {
				return streamResponse(toolCallsChunk(toolFrag(0, "call_1", "do", "{}")), usageChunk(10, 1))
			},
			answer("final answer"),
		}}
		disp := &fakeDispatcher{resultFn: func(AssembledToolCall) (ToolResult, error) { return refusal, nil }}
		loop, store, _, _ := timeLimitLoop(t, client, disp)
		loop.userUsage = func(int64, int64) { loop.Expire() }
		loop.SetDeadline(time.Now().Add(time.Hour))

		if err := loop.Run(context.Background()); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !loop.timeUp() {
			t.Fatal("the deadline never expired; the fixture must expire it after the refusal wrap-up")
		}
		if len(client.requests) != 2 || len(client.requests[1].Tools) != 0 {
			t.Fatalf("provider requests = %d, want one tool-less wrap-up after the refusal", len(client.requests))
		}
		if got := systemMessages(diskRecords(t, store)); !slices.Equal(got, []string{wrapUpText(refusalCause)}) {
			t.Fatalf("durable system messages = %q, want only the refusal wrap-up", got)
		}
	})
	t.Run("deadline expires during the refusing dispatch", func(t *testing.T) {
		calls := toolCallsChunk(toolFrag(0, "done", "do", "{}"), toolFrag(1, "slow", "do", "{}"))
		client := &timeLimitClient{rounds: []func(context.Context) (provider.Response, error){
			func(context.Context) (provider.Response, error) {
				return provider.Response{Stream: newStream(calls)}, nil
			},
			answer("final answer"),
		}}
		disp := &timeLimitDispatcher{doneRan: make(chan struct{}), done: &refusal}
		loop, store, _, _ := timeLimitLoop(t, client, disp)
		disp.expire = func() { loop.Expire() }
		loop.SetDeadline(time.Now().Add(time.Hour))

		if err := loop.Run(context.Background()); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if len(client.requests) != 2 || len(client.requests[1].Tools) != 0 {
			t.Fatalf("provider requests = %d, want one tool-less wrap-up", len(client.requests))
		}
		if got := systemMessages(diskRecords(t, store)); !slices.Equal(got, []string{wrapUpText(refusalCause)}) {
			t.Fatalf("durable system messages = %q, want only the refusal wrap-up", got)
		}
	})
}

func TestToolLoop_DeadlineAtALimitBoundaryWrapsUpForTheTimeLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		at      int
		respond func(int) (provider.Response, error)
	}{
		{"repeat limit", 3, func(n int) (provider.Response, error) {
			return callRound(fmt.Sprintf("call_%d", n), "do", `{"path":"a.txt"}`)
		}},
		{"round limit", 199, distinctCall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := limitStore(t)
			h := newLimitHarness(t, store, tc.respond)
			h.disp.resultFn = func(call AssembledToolCall) (ToolResult, error) {
				if len(h.requests) == tc.at {
					h.loop.Expire()
				}
				return ToolResult{Content: "out:" + call.ID}, nil
			}
			h.loop.SetDeadline(time.Now().Add(time.Hour))

			if err := h.loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}
			if len(h.requests) != tc.at+1 || len(h.requests[tc.at].Tools) != 0 {
				t.Fatalf("provider requests = %d, want %d ending in one tool-less wrap-up", len(h.requests), tc.at+1)
			}
			if got := limitNotices(h.notices); len(got) != 0 {
				t.Fatalf("limit notices = %q, want none when the deadline expired first", got)
			}
			if got := systemMessages(diskRecords(t, store)); !slices.Equal(got, []string{wrapUpText(timeLimitCause)}) {
				t.Fatalf("durable system messages = %q, want only the time-limit wrap-up", got)
			}
		})
	}
}

func TestToolLoop_LaterWrapUpKeepsTheFirstCause(t *testing.T) {
	store := limitStore(t)
	loop := newLimitHarness(t, store, distinctCall).loop
	loop.beginWrapUp("First cause.")
	loop.beginWrapUp("Second cause.")
	if got := systemMessages(store.Records()); !slices.Equal(got, []string{wrapUpText("First cause.")}) {
		t.Fatalf("system messages = %q, want one instruction with the first cause", got)
	}
}

func TestToolLoop_TurnUnderTheLimitsKeepsItsRecords(t *testing.T) {
	store := limitStore(t)
	h := newLimitHarness(t, store, func(n int) (provider.Response, error) {
		if n <= 2 {
			return distinctCall(n)
		}
		return streamResponse(contentChunk("done"), finishChunk("stop"), usageChunk(10, 1))
	})

	if err := h.loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	recs := diskRecords(t, store)
	if got := messageRoleSeq(recs); !slices.Equal(got, []string{"user", "assistant_tc", "tool", "assistant_tc", "tool", "assistant"}) {
		t.Fatalf("message roles = %v, want two tool rounds and the answer", got)
	}
	if len(h.notices) != 0 {
		t.Fatalf("notices = %q, want none", h.notices)
	}
	if mr := decodeModelResponse(t, recs); mr.InputTokens != 30 || mr.OutputTokens != 3 || len(mr.Anomaly) != 0 {
		t.Fatalf("model_response = %+v, want (30, 3) with no anomaly", mr)
	}
}

type accountingEnv struct {
	dir           string
	store         *sessions.Store
	loop          *ToolLoop
	ctx           context.Context
	cancel        context.CancelFunc
	writeFailures []error
}

type accountingRound func(ctx context.Context, e *accountingEnv) (provider.Response, error)

// newAccountingEnv binds Deps.Flush to the turn's own context, as headless does, so a cancelled
// turn's hook can no longer flush.
func newAccountingEnv(t *testing.T, providerID string, rounds ...accountingRound) *accountingEnv {
	t.Helper()
	e := &accountingEnv{dir: filepath.Join(t.TempDir(), "session")}
	if err := os.Mkdir(e.dir, 0o700); err != nil {
		t.Fatalf("create session directory: %v", err)
	}
	e.store = storeAt(filepath.Join(e.dir, "session.json"))
	e.store.Append(textMsg("user", "go"))
	e.ctx, e.cancel = context.WithCancel(context.Background())
	t.Cleanup(e.cancel)
	var n int
	client := &fakeClient{fn: func(ctx context.Context, _ provider.Request) (provider.Response, error) {
		n++
		return rounds[n-1](ctx, e)
	}}
	e.loop = NewToolLoop(Deps{
		Active: selectedState(providerID, "m", model.EffortDefault),
		Store:  e.store,
		Client: client,
		Flush: func() error {
			_, _, err := e.store.Flush(e.ctx)
			return err
		},
		OnFailureWrite: func(_ fserrors.Category, _ sessions.WriteReason, err error) {
			e.writeFailures = append(e.writeFailures, err)
		},
	}, &fakeDispatcher{}, 3)
	return e
}

func usageToolRound(n int, in, out int64, upstream string) accountingRound {
	return func(context.Context, *accountingEnv) (provider.Response, error) {
		chunk := toolCallsChunk(toolFrag(0, fmt.Sprintf("call_%d", n), "do", fmt.Sprintf(`{"n":%d}`, n)))
		if upstream != "" {
			chunk = withUpstream(chunk, upstream)
		}
		return streamResponse(chunk, usageChunk(in, out))
	}
}

var errBadRequest = &provider.HTTPError{Status: 400, Body: "bad request", Surface: "provider returned HTTP 400: bad request"}

func failedRound(context.Context, *accountingEnv) (provider.Response, error) {
	return provider.Response{}, errBadRequest
}

func cancelledRound(_ context.Context, e *accountingEnv) (provider.Response, error) {
	e.cancel()
	return provider.Response{}, context.Canceled
}

func TestToolLoop_UnfinishedTurnRecordsOneModelResponseWithItsKnownUsage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		last        accountingRound
		wantErr     error
		in, out     int64
		wantMissing bool
	}{
		{"provider HTTP error", failedRound, errBadRequest, 150, 15, true},
		{"cancelled", cancelledRound, context.Canceled, 150, 15, true},
		{"empty response", func(context.Context, *accountingEnv) (provider.Response, error) {
			return streamResponse(usageChunk(30, 2))
		}, nil, 180, 17, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newAccountingEnv(t, "openai", usageToolRound(1, 100, 10, ""), usageToolRound(2, 50, 5, ""), tc.last)

			err := e.loop.Run(e.ctx)
			if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("loop.Run() error = %v, want %v", err, tc.wantErr)
			}
			mr := decodeModelResponse(t, diskRecords(t, e.store))
			if mr.InputTokens != tc.in || mr.OutputTokens != tc.out {
				t.Fatalf("model_response tokens = (%d, %d), want (%d, %d)", mr.InputTokens, mr.OutputTokens, tc.in, tc.out)
			}
			if got := slices.Contains(mr.Anomaly, "usage_missing"); got != tc.wantMissing {
				t.Fatalf("model_response anomaly = %v, want usage_missing %v", mr.Anomaly, tc.wantMissing)
			}
		})
	}
}

func TestToolLoop_FailedFirstRoundWithoutUsageRecordsNoModelResponse(t *testing.T) {
	e := newAccountingEnv(t, "openai", failedRound)

	if err := e.loop.Run(e.ctx); !errors.Is(err, errBadRequest) {
		t.Fatalf("loop.Run() error = %v, want the HTTP failure", err)
	}
	if hasKind(e.store.Records(), events.KindModelResponse) {
		t.Fatalf("model_response recorded with no reported usage; kinds = %v", eventKinds(e.store.Records()))
	}
}

func TestToolLoop_FallbackWriteFailureIsJoinedWithTheTurnError(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "api.example.com", IsNotFound: true}
	e := newAccountingEnv(t, "openai", usageToolRound(1, 100, 10, ""), func(context.Context, *accountingEnv) (provider.Response, error) {
		return provider.Response{}, dnsErr
	})
	// The failure notice is the last step of the failed round, after its own events are flushed.
	e.loop.deps.Notice = func(string) {
		if err := os.RemoveAll(e.dir); err != nil {
			t.Fatalf("remove session directory: %v", err)
		}
		if err := os.WriteFile(e.dir, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("replace session directory: %v", err)
		}
	}

	err := e.loop.Run(e.ctx)
	if !errors.Is(err, dnsErr) {
		t.Fatalf("loop.Run() error = %v, want the transport failure kept", err)
	}
	if len(e.writeFailures) != 1 || !errors.Is(err, e.writeFailures[0]) {
		t.Fatalf("write failures = %v, want one, joined into %v", e.writeFailures, err)
	}
}

func TestToolLoop_UnfinishedTurnAttributesTheLastCompletedRoundsUpstream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second accountingRound
		last   accountingRound
		want   string
	}{
		{"failure after two upstreams", usageToolRound(2, 50, 5, `"Cerebras"`), failedRound, "Cerebras"},
		{"cancel after two upstreams", usageToolRound(2, 50, 5, `"Cerebras"`), cancelledRound, "Cerebras"},
		{"unknown last upstream", usageToolRound(2, 50, 5, ""), failedRound, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newAccountingEnv(t, "openrouter", usageToolRound(1, 100, 10, `"Groq"`), tc.second, tc.last)

			if err := e.loop.Run(e.ctx); err == nil {
				t.Fatal("loop.Run() error = nil, want the turn's failure")
			}
			if got := decodeModelResponse(t, diskRecords(t, e.store)).UpstreamProvider; got != tc.want {
				t.Fatalf("upstream_provider = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestToolLoop_ErrorAfterTheModelResponseAddsNoSecondOne(t *testing.T) {
	natural := func(context.Context, *accountingEnv) (provider.Response, error) {
		return streamResponse(contentChunk("done"), finishChunk("stop"), usageChunk(10, 1))
	}
	intercepted := func(context.Context, *accountingEnv) (provider.Response, error) {
		return streamResponse(contentChunk("done"), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), usageChunk(10, 1))
	}
	errFlush := errors.New("final flush failed")
	errFinalize := errors.New("stdout closed")
	for _, tc := range []struct {
		name     string
		last     accountingRound
		finalize bool
		want     error
	}{
		{"natural completion, final flush error", natural, false, errFlush},
		{"intercepted completion, final flush error", intercepted, false, errFlush},
		{"natural completion, finalization error", natural, true, errFinalize},
		{"intercepted completion, finalization error", intercepted, true, errFinalize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newAccountingEnv(t, "openai", usageToolRound(1, 100, 10, ""), tc.last)
			if tc.finalize {
				e.loop.deps.FinalizeErr = func() error { return errFinalize }
			} else {
				e.loop.deps.Flush = func() error {
					if hasKind(e.store.Records(), events.KindModelResponse) {
						return errFlush
					}
					return nil
				}
			}

			if err := e.loop.Run(e.ctx); !errors.Is(err, tc.want) {
				t.Fatalf("loop.Run() error = %v, want %v", err, tc.want)
			}
			if mr := decodeModelResponse(t, e.store.Records()); mr.InputTokens != 110 || mr.OutputTokens != 11 {
				t.Fatalf("model_response tokens = (%d, %d), want (110, 11)", mr.InputTokens, mr.OutputTokens)
			}
		})
	}
}

type raceDecoder struct {
	ctx    context.Context
	chunks [][]byte
	onLast func()
	i      int
	cur    ssestream.Event
	err    error
}

func (d *raceDecoder) Next() bool {
	if d.i < len(d.chunks) {
		d.cur = ssestream.Event{Data: d.chunks[d.i]}
		d.i++
		if d.i == len(d.chunks) {
			d.onLast()
		}
		return true
	}
	d.err = d.ctx.Err()
	return false
}
func (d *raceDecoder) Event() ssestream.Event { return d.cur }
func (d *raceDecoder) Close() error           { return nil }
func (d *raceDecoder) Err() error             { return d.err }

func TestToolLoop_CancelRacingCompletionRecordsOneModelResponse(t *testing.T) {
	for i := range 30 {
		var wg sync.WaitGroup
		e := newAccountingEnv(t, "openai", usageToolRound(1, 100, 10, ""), func(ctx context.Context, e *accountingEnv) (provider.Response, error) {
			dec := &raceDecoder{ctx: ctx, chunks: [][]byte{contentChunk("done"), finishChunk("stop"), usageChunk(10, 1)}, onLast: func() {
				wg.Go(func() { e.loop.Cancel() })
			}}
			return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
		})

		err := e.loop.Run(e.ctx)
		wg.Wait()
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: loop.Run() error = %v, want nil or a cancellation", i, err)
		}
		if mr := decodeModelResponse(t, diskRecords(t, e.store)); mr.InputTokens != 110 || mr.OutputTokens != 11 {
			t.Fatalf("iteration %d: model_response tokens = (%d, %d), want (110, 11)", i, mr.InputTokens, mr.OutputTokens)
		}
	}
}
