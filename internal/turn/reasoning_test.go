package turn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

const (
	beamModel     = "reflection/beam-1.0-501b-a23b"
	beamToolCall  = `{"index":0,"id":"call_r","type":"function","function":{"name":"read","arguments":"{\"path\":\"README.md\"}"}}`
	beamMergedRaw = `[{"type":"reasoning.text","text":"Need to read it.","format":"unknown","index":0,"signature":"sig-1"},` +
		`{"type":"reasoning.encrypted","data":"ENC","id":"r1","format":"unknown","index":1}]`
)

func deltaChunk(delta string) string {
	return fmt.Sprintf(`{"id":"c","object":"chat.completion.chunk","created":1,"model":"m","provider":"Together","choices":[{"index":0,"delta":%s,"finish_reason":""}]}`, delta)
}

func sseBody(chunks ...string) string {
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString("data: " + c + "\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

type wireMessage struct {
	Role             string          `json:"role"`
	Content          json.RawMessage `json:"content"`
	ToolCalls        json.RawMessage `json:"tool_calls"`
	ToolCallID       string          `json:"tool_call_id"`
	Reasoning        *string         `json:"reasoning"`
	ReasoningDetails json.RawMessage `json:"reasoning_details"`
}

// beamServer imitates Beam behind OpenRouter: it rejects any request whose earlier
// assistant turn lacks its reasoning, and requires the tool-call turn to carry the
// exact merged reasoning_details sequence it streamed.
type beamServer struct {
	mu       sync.Mutex
	requests [][]wireMessage
}

func (s *beamServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Messages []wireMessage `json:"messages"`
	}
	_ = json.Unmarshal(body, &req)
	s.mu.Lock()
	s.requests = append(s.requests, req.Messages)
	s.mu.Unlock()

	var lastAssistantHasTools bool
	for i, m := range req.Messages {
		if m.Role != "assistant" {
			continue
		}
		lastAssistantHasTools = len(m.ToolCalls) > 0
		if lastAssistantHasTools && !sameJSON(m.ReasoningDetails, beamMergedRaw) {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"The assistant turn at messages[%d] is missing its reasoning."}}`, i), http.StatusBadRequest)
			return
		}
		if len(m.ReasoningDetails) == 0 && (m.Reasoning == nil || *m.Reasoning == "") {
			http.Error(w, fmt.Sprintf(`{"error":{"message":"The assistant turn at messages[%d] is missing its reasoning."}}`, i), http.StatusBadRequest)
			return
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	last := req.Messages[len(req.Messages)-1]
	if last.Role == "user" {
		_, _ = io.WriteString(w, sseBody(
			deltaChunk(`{"reasoning":"Need to ","reasoning_details":[{"type":"reasoning.text","text":"Need to ","format":"unknown","index":0}]}`),
			deltaChunk(`{"reasoning":"read it.","reasoning_details":[{"type":"reasoning.text","text":"read it.","index":0,"signature":"sig-1"}]}`),
			deltaChunk(`{"reasoning_details":[{"type":"reasoning.encrypted","data":"ENC","id":"r1","format":"unknown","index":1}]}`),
			string(toolCallsChunk(beamToolCall)),
			string(usageChunk(10, 5)),
		))
		return
	}
	_, _ = io.WriteString(w, sseBody(
		deltaChunk(`{"reasoning":"Got the file."}`),
		string(contentChunk("# Title")),
		string(finishChunk("stop")),
		string(usageChunk(20, 5)),
	))
}

func (s *beamServer) request(i int) []wireMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[i]
}

func sameJSON(got json.RawMessage, want string) bool {
	var g, w any
	if json.Unmarshal(got, &g) != nil || json.Unmarshal([]byte(want), &w) != nil {
		return false
	}
	return reflect.DeepEqual(g, w)
}

func openRouterClient(srv *httptest.Server) provider.Client {
	return provider.NewClient(provider.ClientConfig{
		Name:       "openrouter",
		BaseURL:    srv.URL,
		AuthHeader: "Authorization",
		AuthValue:  "Bearer sk-test",
		HTTPClient: srv.Client(),
	})
}

func runBeamTurn(t *testing.T, store *sessions.Store, client provider.Client, prompt string) string {
	t.Helper()
	store.Append(textMsg("user", prompt))
	var sink strings.Builder
	loop := NewToolLoop(Deps{
		Active: selectedState("openrouter", beamModel, "medium"),
		Store:  store,
		Client: client,
		Sink:   func(d string) { sink.WriteString(d) },
	}, &fakeDispatcher{}, 1)
	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("store.Flush() error = %v", err)
	}
	return sink.String()
}

func TestBeamReasoningSurvivesToolContinuationAndResume(t *testing.T) {
	srv := &beamServer{}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	path := filepath.Join(t.TempDir(), "session.json")

	shown := runBeamTurn(t, storeAt(path), openRouterClient(hs), "read README.md")
	if shown != "# Title" {
		t.Fatalf("sink = %q, want only the visible answer, no reasoning", shown)
	}
	cont := srv.request(1)
	if n := len(cont); n != 3 || cont[1].Role != "assistant" || cont[2].Role != "tool" || cont[2].ToolCallID != "call_r" {
		t.Fatalf("continuation messages = %+v, want user, assistant tool call, tool result", cont)
	}

	sess, _, err := sessions.OpenSession(path)
	if err != nil {
		t.Fatalf("reopen session: %v", err)
	}
	var final sessions.Message
	for _, r := range sess.Records {
		if m, ok := r.(sessions.Message); ok && m.Role == "assistant" && len(m.ToolCalls) == 0 {
			final = m
		}
	}
	if final.Content.Text() != "# Title" {
		t.Fatalf("final assistant content = %q, want %q", final.Content.Text(), "# Title")
	}

	runBeamTurn(t, sessions.New(path, sess), openRouterClient(hs), "read it again")
	resumed := srv.request(3)
	if got := resumed[3]; got.Role != "assistant" || got.Reasoning == nil || *got.Reasoning != "Got the file." || len(got.ReasoningDetails) != 0 {
		t.Fatalf("resumed final-answer turn = %+v, want reasoning %q and no details", got, "Got the file.")
	}
}

func beamRecord() sessions.Message {
	m := textMsg("assistant", "answer")
	m.Reasoning = &sessions.Reasoning{Provider: "openrouter", ModelID: beamModel, Text: "thought", Details: json.RawMessage(beamMergedRaw)}
	return m
}

func TestStoredReasoningReplaysOnlyForItsOwnModel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sel      model.Selection
		wantKept bool
	}{
		{"same model", model.Selection{Provider: "openrouter", ID: beamModel}, true},
		{"other model", model.Selection{Provider: "openrouter", ID: "other/model"}, false},
		{"other provider", model.Selection{Provider: "venice", ID: beamModel}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msgs := messagesFromRecords([]sessions.Record{textMsg("user", "q"), beamRecord()}, tc.sel)
			got := msgs[1]
			if kept := got.Reasoning != "" || len(got.ReasoningDetails) > 0; kept != tc.wantKept {
				t.Fatalf("reasoning kept = %v, want %v (msg %+v)", kept, tc.wantKept, got)
			}
		})
	}
}

func captureWire(t *testing.T, name string, msgs []provider.Message) string {
	t.Helper()
	var body []byte
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer hs.Close()
	client := provider.NewClient(provider.ClientConfig{Name: name, BaseURL: hs.URL, AuthHeader: "Authorization", AuthValue: "Bearer sk-test", HTTPClient: hs.Client()})
	resp, err := client.ChatCompletion(context.Background(), provider.Request{Model: beamModel, Messages: msgs, Stream: true})
	if err != nil {
		t.Fatalf("ChatCompletion() error = %v", err)
	}
	for resp.Stream.Next() {
	}
	return string(body)
}

func TestReasoningWireEncoding(t *testing.T) {
	plain := []provider.Message{{Role: "user", Content: "q"}, {Role: "assistant", Content: "a"}}
	withReasoning := []provider.Message{{Role: "user", Content: "q"}, {Role: "assistant", Content: "a", Reasoning: "thought", ReasoningDetails: json.RawMessage(beamMergedRaw)}}

	if got := captureWire(t, "openrouter", plain); strings.Contains(got, "reasoning") {
		t.Fatalf("request without reasoning carries a reasoning field: %s", got)
	}
	if got := captureWire(t, "venice", withReasoning); strings.Contains(got, "reasoning") {
		t.Fatalf("non-OpenRouter request carries reasoning: %s", got)
	}
	got := captureWire(t, "openrouter", withReasoning)
	var req struct {
		Messages []wireMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(got), &req); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	asst := req.Messages[1]
	if !sameJSON(asst.ReasoningDetails, beamMergedRaw) || asst.Reasoning != nil {
		t.Fatalf("assistant wire = %+v, want reasoning_details only", asst)
	}
}
