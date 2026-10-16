package subagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/filetools"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/turn"
)

func contentChunk(text string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":%q},"finish_reason":""}]}`, text))
}

func finishChunk() []byte {
	return []byte(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)
}

func toolCallChunk(id, name string) []byte {
	return toolCallChunkArgs(id, name, "{}")
}

func toolCallChunkArgs(id, name, arguments string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}]},"finish_reason":"tool_calls"}]}`, id, name, arguments))
}

type sliceDecoder struct {
	events [][]byte
	err    error
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
func (d *sliceDecoder) Err() error             { return d.err }

func streamRound(chunks ...[]byte) func(context.Context) (provider.Response, error) {
	return func(context.Context) (provider.Response, error) {
		dec := &sliceDecoder{events: chunks}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}
}

func droppedStreamRound() func(context.Context) (provider.Response, error) {
	return func(context.Context) (provider.Response, error) {
		dec := &sliceDecoder{events: [][]byte{contentChunk("partial")}, err: errors.New("stream broke")}
		return provider.Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](dec, nil)}, nil
	}
}

type scriptedClient struct {
	rounds   []func(context.Context) (provider.Response, error)
	repeat   func(context.Context) (provider.Response, error)
	requests []provider.Request
}

func (c *scriptedClient) ChatCompletion(ctx context.Context, req provider.Request) (provider.Response, error) {
	c.requests = append(c.requests, req)
	if i := len(c.requests) - 1; i < len(c.rounds) {
		return c.rounds[i](ctx)
	}
	if c.repeat != nil {
		return c.repeat(ctx)
	}
	return provider.Response{}, fmt.Errorf("unscripted provider round %d", len(c.requests))
}

func twoToolCallChunk(firstID, firstName, secondID, secondName string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":"{}"}},{"index":1,"id":%q,"type":"function","function":{"name":%q,"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`, firstID, firstName, secondID, secondName))
}

type stubDispatcher struct {
	results map[string]turn.ToolResult
	byID    map[string]turn.ToolResult
	onCall  func(name string)
}

func (d *stubDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d *stubDispatcher) Dispatch(_ context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	if d.onCall != nil {
		d.onCall(call.Name)
	}
	if res, ok := d.byID[call.ID]; ok {
		return res, nil
	}
	if res, ok := d.results[call.Name]; ok {
		return res, nil
	}
	return turn.ToolResult{Content: "ok:" + call.Name}, nil
}

func denyEnvelope(deniedBy string) turn.ToolResult {
	return turn.ToolResult{
		Content: fmt.Sprintf(`{"denied_by":%q,"reason":"the user refused this call"}`, deniedBy),
		Denied:  true,
	}
}

const (
	childInstruction = "summarize the changed files"
	childPrompt      = "you are a child agent\n<environment>cwd=/repo</environment>"
)

func baseRequest(client provider.Client, dispatcher turn.ToolDispatcher) Request {
	return Request{
		Instruction:     childInstruction,
		Model:           model.Selection{Provider: "openrouter", ID: "some/model", Effort: "high"},
		ModelSource:     model.SourceProject,
		SupportedEffort: func(string, string) []string { return []string{"high"} },
		SystemPrompt:    childPrompt,
		Client:          client,
		Tools:           []provider.ToolDefinition{{Name: "read", Description: "read a file"}},
		Dispatcher:      dispatcher,
		StepCap:         4,
	}
}

func TestRun_MultiRoundConversationReturnsFinalReply(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(contentChunk("let me look"), toolCallChunk("call_1", "read")),
		streamRound(contentChunk("thinking"), toolCallChunk("call_2", "grep")),
		streamRound(contentChunk("the answer"), finishChunk()),
	}}
	disp := &stubDispatcher{}

	res, err := Run(t.Context(), baseRequest(client, disp))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonCompleted)
	}
	if res.Reply != "the answer" {
		t.Fatalf("reply = %q, want only the final round's text", res.Reply)
	}
	if res.ReplyTruncated {
		t.Fatal("short reply reported as truncated")
	}
	if res.ProviderRequests != 3 {
		t.Fatalf("provider requests = %d, want 3", res.ProviderRequests)
	}
	if got := strings.Join(res.ToolNames, ","); got != "read,grep" {
		t.Fatalf("tool names = %q, want %q in model-call order", got, "read,grep")
	}
}

func TestRun_EveryRoundKeepsInheritedEffortAndPrompt(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "read")),
		streamRound(contentChunk("done"), finishChunk()),
	}}

	if _, err := Run(t.Context(), baseRequest(client, &stubDispatcher{})); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(client.requests) != 2 {
		t.Fatalf("provider requests = %d, want an initial and a continuation round", len(client.requests))
	}
	for i, req := range client.requests {
		if req.Effort != "high" {
			t.Fatalf("round %d effort = %q, want the inherited %q", i+1, req.Effort, "high")
		}
		if len(req.Messages) == 0 || req.Messages[0].Role != "system" || req.Messages[0].Content != childPrompt {
			t.Fatalf("round %d does not lead with the parent's assembled system prompt: %+v", i+1, req.Messages)
		}
		if req.Model != "some/model" {
			t.Fatalf("round %d model = %q, want the snapshotted parent model", i+1, req.Model)
		}
	}
}

func TestRun_ChildHistoryHoldsOnlyItsOwnConversation(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "read")),
		streamRound(contentChunk("done"), finishChunk()),
	}}

	if _, err := Run(t.Context(), baseRequest(client, &stubDispatcher{})); err != nil {
		t.Fatalf("Run: %v", err)
	}

	first := client.requests[0].Messages
	if len(first) != 2 {
		t.Fatalf("initial round sent %d messages, want the system prompt and the instruction only: %+v", len(first), first)
	}
	if first[1].Role != "user" || first[1].Content != childInstruction {
		t.Fatalf("the instruction is not the child's sole user message: %+v", first[1])
	}

	second := client.requests[1].Messages
	var roles []string
	for _, m := range second {
		roles = append(roles, m.Role)
	}
	if got := strings.Join(roles, ","); got != "system,user,assistant,tool" {
		t.Fatalf("continuation roles = %q, want the child's own tool-call group", got)
	}
	if second[2].ToolCalls[0].Name != "read" || second[3].ToolCallID != "call_1" {
		t.Fatalf("continuation did not replay the child's tool-call group: %+v", second[2:])
	}
}

func TestRun_StepCapStopsBeforeTheNextProviderRequest(t *testing.T) {
	client := &scriptedClient{repeat: streamRound(toolCallChunk("call_1", "read"))}
	req := baseRequest(client, &stubDispatcher{})
	req.StepCap = 2

	res, err := Run(t.Context(), req)
	if err != nil {
		t.Fatalf("a step cap must not be an error, got %v", err)
	}
	if res.Reason != ReasonStepCap {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonStepCap)
	}
	if res.ProviderRequests != 2 {
		t.Fatalf("provider requests = %d, want exactly the cap", res.ProviderRequests)
	}
	if len(client.requests) != 2 {
		t.Fatalf("the client saw %d requests, want the cap to refuse the third before it", len(client.requests))
	}
	if len(res.ToolNames) != 2 {
		t.Fatalf("tool names = %v, want the partial result to survive the cap", res.ToolNames)
	}
}

func TestRun_CancellationStopsBeforeTheNextProviderRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	client := &scriptedClient{repeat: streamRound(toolCallChunk("call_1", "read"))}
	disp := &stubDispatcher{onCall: func(string) { cancel() }}

	res, err := Run(ctx, baseRequest(client, disp))
	if err != nil {
		t.Fatalf("a cancellation must not be an error, got %v", err)
	}
	if res.Reason != ReasonCancelled {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonCancelled)
	}
	if res.ProviderRequests != 1 {
		t.Fatalf("provider requests = %d, want the cancellation to prevent the next one", res.ProviderRequests)
	}
	if len(res.ToolNames) != 1 {
		t.Fatalf("tool names = %v, want the partial result to survive cancellation", res.ToolNames)
	}
}

// admissionPlanner records which inner units were entered. A preRun hook fires after the
// scheduler picked the unit up but before the guard; an inRun hook fires inside the inner unit.
type admissionPlanner struct {
	preRun  map[string]func()
	inRun   map[string]func()
	entered []string
}

func (p *admissionPlanner) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		unit := turn.PlannedToolCall{
			Call: call,
			Run: func(context.Context) (turn.ToolResult, error) {
				p.entered = append(p.entered, call.ID)
				if hook := p.inRun[call.ID]; hook != nil {
					hook()
				}
				return turn.ToolResult{Content: "ok"}, nil
			},
		}
		if hook := p.preRun[call.ID]; hook != nil {
			unit.PreRun = func(context.Context) error { hook(); return nil }
		}
		plan.Units[i] = unit
	}
	return plan
}

func (p *admissionPlanner) Dispatch(context.Context, turn.AssembledToolCall) (turn.ToolResult, error) {
	return turn.ToolResult{}, errors.New("the child runs planned units, not Dispatch")
}

func TestRun_CancellationStopsTheSecondCallOfOneResponse(t *testing.T) {
	cases := []struct {
		name  string
		place func(*admissionPlanner, func())
	}{
		{
			name:  "cancelled while the first call runs",
			place: func(p *admissionPlanner, cancel func()) { p.inRun = map[string]func(){"call_1": cancel} },
		},
		{
			name:  "cancelled after the second call is picked up",
			place: func(p *admissionPlanner, cancel func()) { p.preRun = map[string]func(){"call_2": cancel} },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			planner := &admissionPlanner{}
			tc.place(planner, cancel)
			client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
				streamRound(twoToolCallChunk("call_1", "read", "call_2", "edit")),
				streamRound(contentChunk("should never run"), finishChunk()),
			}}

			res, err := Run(ctx, baseRequest(client, planner))
			if err != nil {
				t.Fatalf("a cancellation must not be an error, got %v", err)
			}
			if res.Reason != ReasonCancelled {
				t.Fatalf("reason = %q, want %q", res.Reason, ReasonCancelled)
			}
			if got := strings.Join(planner.entered, ","); got != "call_1" {
				t.Fatalf("entered units = %q, want only the call admitted before the cancellation", got)
			}
			if len(client.requests) != 1 {
				t.Fatalf("provider requests = %d, want the cancellation to stop the next round", len(client.requests))
			}
		})
	}
}

func TestRun_ReportsSuccessfulWriteTargetsInCallOrder(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(twoToolCallChunk("call_1", "edit", "call_2", "read")),
		streamRound(toolCallChunk("call_3", "edit")),
		streamRound(toolCallChunk("call_4", "create")),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	disp := &stubDispatcher{byID: map[string]turn.ToolResult{
		"call_1": {Content: "ok", WriteTarget: "/repo/a.go"},
		"call_2": {Content: "file contents"},
		"call_3": denyEnvelope("mode"),
		"call_4": {Content: "ok", WriteTarget: "/repo/b.go"},
	}}

	res, err := Run(t.Context(), baseRequest(client, disp))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonCompleted)
	}
	if got := strings.Join(res.WriteTargets, ","); got != "/repo/a.go,/repo/b.go" {
		t.Fatalf("write targets = %q, want the successful writes in call order", got)
	}
}

func TestRun_ReportsDeleteTargetsApartFromWriteTargets(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(twoToolCallChunk("call_1", "create", "call_2", "delete")),
		streamRound(toolCallChunk("call_3", "delete")),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	disp := &stubDispatcher{byID: map[string]turn.ToolResult{
		"call_1": {Content: "ok", WriteTarget: "/repo/new.go"},
		"call_2": {Content: "ok", DeleteTarget: "/repo/old.go"},
		"call_3": denyEnvelope("mode"),
	}}

	res, err := Run(t.Context(), baseRequest(client, disp))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(res.WriteTargets, ","); got != "/repo/new.go" {
		t.Fatalf("write targets = %q, want only the create", got)
	}
	if got := strings.Join(res.DeleteTargets, ","); got != "/repo/old.go" {
		t.Fatalf("delete targets = %q, want only the successful delete", got)
	}
}

func TestRun_ReportsMoveTargetsApartFromWriteAndDeleteTargets(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "move")),
		streamRound(toolCallChunk("call_2", "move")),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	moved := turn.MoveTarget{Source: "/repo/old.go", Destination: "/repo/new.go"}
	disp := &stubDispatcher{byID: map[string]turn.ToolResult{
		"call_1": {Content: "ok", MoveTarget: moved},
		"call_2": denyEnvelope("mode"),
	}}

	res, err := Run(t.Context(), baseRequest(client, disp))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.MoveTargets) != 1 || res.MoveTargets[0] != moved {
		t.Fatalf("move targets = %v, want only the successful move %v", res.MoveTargets, moved)
	}
	if len(res.WriteTargets) != 0 || len(res.DeleteTargets) != 0 {
		t.Fatalf("write/delete targets = %v / %v, want a move recorded as neither", res.WriteTargets, res.DeleteTargets)
	}
}

func TestRun_ReportsWriteTargetsOfACancelledChild(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	client := &scriptedClient{repeat: streamRound(toolCallChunk("call_1", "edit"))}
	disp := &stubDispatcher{
		results: map[string]turn.ToolResult{"edit": {Content: "ok", WriteTarget: "/repo/a.go"}},
		onCall:  func(string) { cancel() },
	}

	res, err := Run(ctx, baseRequest(client, disp))
	if err != nil {
		t.Fatalf("a cancellation must not be an error, got %v", err)
	}
	if res.Reason != ReasonCancelled {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonCancelled)
	}
	if got := strings.Join(res.WriteTargets, ","); got != "/repo/a.go" {
		t.Fatalf("write targets = %q, want the write that landed before the cancellation", got)
	}
}

func TestRun_TerminalUserDenialIsNotCompleted(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "create")),
		streamRound(toolCallChunk("call_2", "edit")),
		streamRound(contentChunk("should never run"), finishChunk()),
	}}
	disp := &stubDispatcher{results: map[string]turn.ToolResult{"edit": denyEnvelope("user")}}

	res, err := Run(t.Context(), baseRequest(client, disp))
	if err != nil {
		t.Fatalf("a user denial must not be an error, got %v", err)
	}
	if res.Reason != ReasonFailed {
		t.Fatalf("reason = %q, want %q so the partial write is rolled back", res.Reason, ReasonFailed)
	}
	if res.ProviderRequests != 2 {
		t.Fatalf("provider requests = %d, want the denial to halt before another round", res.ProviderRequests)
	}
	if got := strings.Join(res.ToolNames, ","); got != "create,edit" {
		t.Fatalf("tool names = %q, want the authorized write and the denied call", got)
	}
}

func TestRun_PolicyDenialStillReachesAFinalReply(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "edit")),
		streamRound(contentChunk("took another route"), finishChunk()),
	}}
	disp := &stubDispatcher{results: map[string]turn.ToolResult{"edit": denyEnvelope("mode")}}

	res, err := Run(t.Context(), baseRequest(client, disp))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("reason = %q, want a recoverable policy denial to continue to %q", res.Reason, ReasonCompleted)
	}
}

func TestRun_SameCallCapWrapsUpWithTheFinalReply(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "edit")),
		streamRound(contentChunk("I could not edit it; here is the plan."), toolCallChunk("call_2", "edit")),
	}}
	wrapUp := denyEnvelope("unattended")
	wrapUp.WrapUp = true
	var dispatched []string
	disp := &stubDispatcher{
		results: map[string]turn.ToolResult{"edit": wrapUp},
		onCall:  func(name string) { dispatched = append(dispatched, name) },
	}

	res, err := Run(t.Context(), baseRequest(client, disp))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("reason = %q, want %q after the wrap-up answer", res.Reason, ReasonCompleted)
	}
	if res.Reply != "I could not edit it; here is the plan." {
		t.Fatalf("reply = %q, want the wrap-up answer", res.Reply)
	}
	if len(dispatched) != 1 || res.ProviderRequests != 2 {
		t.Fatalf("dispatched = %v over %d requests, want only the refused call and one wrap-up request", dispatched, res.ProviderRequests)
	}
	if len(client.requests[1].Tools) != 0 {
		t.Fatalf("wrap-up request advertised %d tools, want none", len(client.requests[1].Tools))
	}
}

func TestRun_EmptyProviderResponseIsNotCompleted(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "create")),
		streamRound(finishChunk()),
	}}

	res, err := Run(t.Context(), baseRequest(client, &stubDispatcher{}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonFailed {
		t.Fatalf("reason = %q, want %q: the child wrote and then produced no final reply", res.Reason, ReasonFailed)
	}
}

func TestRun_CountsAProviderRequestWhoseStreamLaterFails(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){droppedStreamRound()}}

	res, err := Run(t.Context(), baseRequest(client, &stubDispatcher{}))
	if err == nil {
		t.Fatal("an unexpected loop failure must return its error")
	}
	if res.Reason != ReasonFailed {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonFailed)
	}
	if res.ProviderRequests != 1 {
		t.Fatalf("provider requests = %d, want the started request counted", res.ProviderRequests)
	}
}

func TestRun_BoundsAnOversizedReply(t *testing.T) {
	long := strings.Repeat("z", maxReplyBytes+100)
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(contentChunk(long), finishChunk()),
	}}

	res, err := Run(t.Context(), baseRequest(client, &stubDispatcher{}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.ReplyTruncated {
		t.Fatal("oversized reply was not marked truncated")
	}
	if len(res.Reply) != maxReplyBytes {
		t.Fatalf("reply is %d bytes, want the %d-byte cap", len(res.Reply), maxReplyBytes)
	}
}

func TestRun_ChildRunWritesNoSessionFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(toolCallChunk("call_1", "read")),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	if _, err := Run(t.Context(), baseRequest(client, &stubDispatcher{})); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read working dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("the child run left %d file(s) behind: %v", len(entries), entries)
	}
}

func TestRun_RejectsAnIncompleteRequestBeforeAnyProviderCall(t *testing.T) {
	cases := map[string]func(*Request){
		"instruction":      func(r *Request) { r.Instruction = "  " },
		"model":            func(r *Request) { r.Model = model.Selection{} },
		"supported effort": func(r *Request) { r.SupportedEffort = nil },
		"system prompt":    func(r *Request) { r.SystemPrompt = "" },
		"client":           func(r *Request) { r.Client = nil },
		"dispatcher":       func(r *Request) { r.Dispatcher = nil },
		"zero step cap":    func(r *Request) { r.StepCap = 0 },
		"negative cap":     func(r *Request) { r.StepCap = -1 },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			client := &scriptedClient{repeat: streamRound(contentChunk("hi"), finishChunk())}
			req := baseRequest(client, &stubDispatcher{})
			break_(&req)

			res, err := Run(t.Context(), req)
			if err == nil {
				t.Fatal("an incomplete request was accepted")
			}
			if res.Reason != ReasonFailed {
				t.Fatalf("reason = %q, want %q", res.Reason, ReasonFailed)
			}
			if len(client.requests) != 0 {
				t.Fatalf("the client saw %d requests, want none", len(client.requests))
			}
		})
	}
}

func TestPackageImportsNeitherTUINorBootstrap(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	parsed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		for _, spec := range file.Imports {
			path, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				t.Fatalf("%s: unquote import %s: %v", name, spec.Path.Value, uerr)
			}
			if path == "codemeld.dev/codemeld/internal/tui" || path == "codemeld.dev/codemeld/internal/bootstrap" {
				t.Fatalf("%s imports %q; internal/subagent must stay free of it", name, path)
			}
		}
	}
	if parsed == 0 {
		t.Fatal("parsed no package sources")
	}
}

// EmitTurnTerminal flushes the store directly rather than through turn.Deps.Flush,
// so the memory-only child store has to absorb that call too.
func TestMemoryOnlyStore_TerminalEventFlushWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	store := sessions.NewMemoryOnly()
	err := events.EmitTurnTerminal(t.Context(), store, events.TurnTerminal{
		TurnID:  ids.NewV7(),
		RoundID: ids.NewV7(),
		Outcome: events.TurnOutcomeCompleted,
	}, nil)
	if err != nil {
		t.Fatalf("EmitTurnTerminal on a memory-only store: %v", err)
	}

	recs := store.Records()
	if len(recs) != 1 {
		t.Fatalf("records = %d, want the terminal event retained in memory", len(recs))
	}
	if ev, ok := recs[0].(sessions.Event); !ok || ev.Kind != events.KindTurnTerminal {
		t.Fatalf("record = %+v, want a %s event", recs[0], events.KindTurnTerminal)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatalf("read working dir: %v", rerr)
	}
	if len(entries) != 0 {
		t.Fatalf("the terminal-event flush wrote %d file(s): %v", len(entries), entries)
	}
}

func TestCappedClient_RefusesOnceCancelledOrPastTheCap(t *testing.T) {
	inner := &scriptedClient{repeat: streamRound(finishChunk())}
	c := &cappedClient{inner: inner, limit: 1, onRequest: func() {}}

	if _, err := c.ChatCompletion(t.Context(), provider.Request{}); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := c.ChatCompletion(t.Context(), provider.Request{}); !errors.Is(err, errStepCap) {
		t.Fatalf("request past the cap: err = %v, want the step-cap sentinel", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c.limit = 10
	if _, err := c.ChatCompletion(ctx, provider.Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("request on a cancelled context: err = %v, want context.Canceled", err)
	}
	if c.started != 1 || len(inner.requests) != 1 {
		t.Fatalf("started = %d, inner requests = %d; want only the one allowed request to reach the client", c.started, len(inner.requests))
	}
}

func argToolCallChunk(id, name, arguments string) []byte {
	return []byte(fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":%q,"arguments":%q}}]},"finish_reason":"tool_calls"}]}`, id, name, arguments))
}

// editingDispatcher runs the child's edit calls on the real structured edit tool so a Run-level test
// observes the journal through the publish seam rather than through a stand-in.
type editingDispatcher struct {
	tool   *filetools.EditTool
	onCall func()
}

func (d *editingDispatcher) Plan(calls []turn.AssembledToolCall, _ int) turn.ToolPlan {
	plan := turn.ToolPlan{Units: make([]turn.PlannedToolCall, len(calls))}
	for i, call := range calls {
		plan.Units[i] = turn.PlannedToolCall{
			Call: call,
			Run:  func(ctx context.Context) (turn.ToolResult, error) { return d.Dispatch(ctx, call) },
		}
	}
	return plan
}

func (d *editingDispatcher) Dispatch(ctx context.Context, call turn.AssembledToolCall) (turn.ToolResult, error) {
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
		return turn.ToolResult{Content: "bad arguments"}, nil
	}
	target, _ := args["path"].(string)
	res, err := d.tool.InvokeWithResolvedTarget(ctx, args, target)
	if err != nil {
		return turn.ToolResult{}, err
	}
	if d.onCall != nil {
		d.onCall()
	}
	return turn.ToolResult{Content: string(res.Stdout) + string(res.Stderr), WriteTarget: target}, nil
}

func editRound(id, target string) func(context.Context) (provider.Response, error) {
	args := fmt.Sprintf(`{"path":%q,"old_text":"ORIGINAL","new_text":"CHILD"}`, target)
	return streamRound(argToolCallChunk(id, "edit", args))
}

func TestRun_CancelledChildIsRolledBackToItsPreRunState(t *testing.T) {
	f := newFixture(t)
	targets := []string{
		f.seed(t, "a.txt", "ORIGINAL a\n"),
		f.seed(t, "b.txt", "ORIGINAL b\n"),
		f.seed(t, "c.txt", "ORIGINAL c\n"),
		f.seed(t, "d.txt", "ORIGINAL d\n"),
	}
	journal := f.open(t, targets...)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		editRound("call_1", targets[0]),
		editRound("call_2", targets[1]),
		editRound("call_3", targets[2]),
		editRound("call_4", targets[3]),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	calls := 0
	disp := &editingDispatcher{
		tool: filetools.NewEditTool(f.home, f.project, f.project),
		onCall: func() {
			calls++
			if calls == 2 {
				cancel()
			}
		},
	}

	req := baseRequest(client, disp)
	req.StepCap = 8
	req.Journal = journal
	res, err := Run(ctx, req)
	if err != nil {
		t.Fatalf("a cancellation must not be an error, got %v", err)
	}
	if res.Reason != ReasonCancelled {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonCancelled)
	}
	if calls != 2 {
		t.Fatalf("child edits = %d, want the cancellation to stop it after two of four", calls)
	}
	for i, target := range targets {
		want := fmt.Sprintf("ORIGINAL %c\n", 'a'+i)
		if got := readFile(t, target); got != want {
			t.Fatalf("%s = %q, want its pre-run bytes %q", target, got, want)
		}
	}
	if len(res.RestoredPaths) != 2 {
		t.Fatalf("restored = %v, want the two paths the child actually wrote", res.RestoredPaths)
	}
	if len(res.Unrecovered) != 0 || res.RetainedJournal != "" {
		t.Fatalf("result = %+v, want a clean rollback", res)
	}
	assertGone(t, journal.Path())
}

func TestRun_CompletedChildKeepsItsWorkAndLeavesNoJournal(t *testing.T) {
	f := newFixture(t)
	target := f.seed(t, "a.txt", "ORIGINAL a\n")
	journal := f.open(t, target)

	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		editRound("call_1", target),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	disp := &editingDispatcher{tool: filetools.NewEditTool(f.home, f.project, f.project)}

	req := baseRequest(client, disp)
	req.Journal = journal
	res, err := Run(t.Context(), req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonCompleted)
	}
	if got := readFile(t, target); got != "CHILD a\n" {
		t.Fatalf("%s = %q, want the child's result kept", target, got)
	}
	if len(res.RestoredPaths) != 0 || res.RetainedJournal != "" {
		t.Fatalf("result = %+v, want a completion to claim no rollback", res)
	}
	assertGone(t, journal.Path())
}

func TestRun_StepCapAndFailureRollBackAsCancellationDoes(t *testing.T) {
	cases := []struct {
		name    string
		want    Reason
		build   func(f *fixture, target string) (*scriptedClient, int)
		wantErr bool
	}{
		{
			name: "step cap",
			want: ReasonStepCap,
			build: func(_ *fixture, target string) (*scriptedClient, int) {
				return &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
					editRound("call_1", target),
				}}, 1
			},
		},
		{
			name:    "child loop failure",
			want:    ReasonFailed,
			wantErr: true,
			build: func(_ *fixture, target string) (*scriptedClient, int) {
				return &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
					editRound("call_1", target),
					func(context.Context) (provider.Response, error) {
						return provider.Response{}, errors.New("the child loop broke")
					},
				}}, 2
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.seed(t, "a.txt", "ORIGINAL a\n")
			journal := f.open(t, target)
			client, cap := tc.build(f, target)

			req := baseRequest(client, &editingDispatcher{tool: filetools.NewEditTool(f.home, f.project, f.project)})
			req.StepCap = cap
			req.Journal = journal
			res, err := Run(t.Context(), req)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Run error = %v, wantErr = %v", err, tc.wantErr)
			}
			if res.Reason != tc.want {
				t.Fatalf("reason = %q, want %q", res.Reason, tc.want)
			}
			if got := readFile(t, target); got != "ORIGINAL a\n" {
				t.Fatalf("%s = %q, want its pre-run bytes", target, got)
			}
			if len(res.RestoredPaths) != 1 || res.RetainedJournal != "" {
				t.Fatalf("result = %+v, want the same clean rollback a cancellation produces", res)
			}
			assertGone(t, journal.Path())
		})
	}
}

type recordingActivity struct {
	started []events.ChildAgentStart
	rounds  []activityRound
	ended   []events.ChildAgentEnd
	onCalls func()
}

type activityRound struct {
	invocation string
	lines      []string
}

func (r *recordingActivity) ChildAgentStarted(start events.ChildAgentStart) {
	r.started = append(r.started, start)
}

func (r *recordingActivity) ChildAgentCalls(invocation string, lines []string) {
	r.rounds = append(r.rounds, activityRound{invocation: invocation, lines: lines})
	if r.onCalls != nil {
		r.onCalls()
	}
}

func (r *recordingActivity) ChildAgentEnded(end events.ChildAgentEnd) {
	r.ended = append(r.ended, end)
}

// A wired sink sees the child's own tool rounds as they are about to run, each attributed to
// the invocation id the caller minted, so a surface can show the child working rather than
// waiting for its result.
func TestRun_ReportsChildToolRoundsToTheActivitySink(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(contentChunk("looking"), toolCallChunk("call_1", "read")),
		streamRound(contentChunk("checking"), twoToolCallChunk("call_2", "grep", "call_3", "list")),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	sink := &recordingActivity{}
	req := baseRequest(client, &stubDispatcher{})
	req.Activity = sink
	req.InvocationID = "01920000-0000-7000-8000-0000000000ff"

	res, err := Run(t.Context(), req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("Reason = %q, want %q", res.Reason, ReasonCompleted)
	}

	want := []activityRound{
		{invocation: req.InvocationID, lines: []string{"read"}},
		{invocation: req.InvocationID, lines: []string{"grep", "list"}},
	}
	if len(sink.rounds) != len(want) {
		t.Fatalf("reported rounds = %v, want one per tool-call round: %v", sink.rounds, want)
	}
	for i, round := range sink.rounds {
		if round.invocation != want[i].invocation {
			t.Errorf("round %d invocation = %q, want the issuing child's %q", i, round.invocation, want[i].invocation)
		}
		if strings.Join(round.lines, ",") != strings.Join(want[i].lines, ",") {
			t.Errorf("round %d lines = %v, want %v", i, round.lines, want[i].lines)
		}
	}
	// The lifecycle halves belong to the caller that minted the id, not to this package.
	if len(sink.started) != 0 || len(sink.ended) != 0 {
		t.Errorf("Run reported %d start / %d end notifications, want none", len(sink.started), len(sink.ended))
	}
}

// A child that only edits is the case the user most needs to see while it runs, and it is
// exactly the round the parent's display hook drops in favour of a rendered patch the child
// has no surface for. The sink still gets it, and still gets it before the edit runs.
func TestRun_ReportsEditOnlyChildRoundBeforeDispatch(t *testing.T) {
	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(contentChunk("editing"), toolCallChunkArgs("call_1", "edit", `{"path":"internal/x.go"}`)),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	var order []string
	sink := &recordingActivity{onCalls: func() { order = append(order, "reported") }}
	disp := &stubDispatcher{onCall: func(string) { order = append(order, "dispatched") }}
	req := baseRequest(client, disp)
	req.Activity = sink
	req.InvocationID = "01920000-0000-7000-8000-0000000000ff"

	res, err := Run(t.Context(), req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("Reason = %q, want %q", res.Reason, ReasonCompleted)
	}

	if len(sink.rounds) != 1 {
		t.Fatalf("reported rounds = %v, want the edit-only round reported once", sink.rounds)
	}
	got := sink.rounds[0]
	if got.invocation != req.InvocationID {
		t.Errorf("round invocation = %q, want the issuing child's %q", got.invocation, req.InvocationID)
	}
	if strings.Join(got.lines, ",") != "Edit internal/x.go" {
		t.Errorf("round lines = %v, want the rendered edit entry", got.lines)
	}
	if strings.Join(order, ",") != "reported,dispatched" {
		t.Errorf("order = %v, want the round reported before the edit runs", order)
	}
}

// The sink is optional at the request boundary: validate does not require it, and a run
// without one still completes its rounds.
func TestRun_NilActivitySinkIsAccepted(t *testing.T) {
	req := baseRequest(&scriptedClient{}, &stubDispatcher{})
	if err := req.validate(); err != nil {
		t.Fatalf("validate rejected a request carrying no activity sink: %v", err)
	}

	client := &scriptedClient{rounds: []func(context.Context) (provider.Response, error){
		streamRound(contentChunk("looking"), toolCallChunk("call_1", "read")),
		streamRound(contentChunk("done"), finishChunk()),
	}}
	res, err := Run(t.Context(), baseRequest(client, &stubDispatcher{}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != ReasonCompleted {
		t.Fatalf("Reason = %q, want %q", res.Reason, ReasonCompleted)
	}
}
