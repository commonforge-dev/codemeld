package turn

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessions"
)

// fenced wraps body in one Markdown code fence with the given info string (e.g. "json"
// or "" for a bare fence), matching the shape a small model emits a tool call in.
func fenced(lang, body string) string {
	return "```" + lang + "\n" + body + "\n```"
}

// --- parser: positive shapes ------------------------------------------------

func TestParseTextToolCall_PositiveShapes(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		wantName string
		wantArgs string
	}{
		{
			name:     "bare object",
			content:  `{"name":"grep","arguments":{"pattern":"yellow","path":"."}}`,
			wantName: "grep",
			wantArgs: `{"pattern":"yellow","path":"."}`,
		},
		{
			name:     "surrounding whitespace trimmed",
			content:  "  \n\t" + `{"name":"grep","arguments":{"pattern":"yellow"}}` + "\n  ",
			wantName: "grep",
			wantArgs: `{"pattern":"yellow"}`,
		},
		{
			name:     "object arguments are compacted",
			content:  `{"name":"grep","arguments":{"pattern": "yellow",  "path": "."}}`,
			wantName: "grep",
			wantArgs: `{"pattern":"yellow","path":"."}`,
		},
		{
			name:     "fenced with json language",
			content:  fenced("json", `{"name":"grep","arguments":{"pattern":"yellow"}}`),
			wantName: "grep",
			wantArgs: `{"pattern":"yellow"}`,
		},
		{
			name:     "fenced with no language",
			content:  fenced("", `{"name":"grep","arguments":{"pattern":"yellow"}}`),
			wantName: "grep",
			wantArgs: `{"pattern":"yellow"}`,
		},
		{
			name:     "arguments as a JSON-encoded string",
			content:  `{"name":"grep","arguments":"{\"pattern\":\"yellow\"}"}`,
			wantName: "grep",
			wantArgs: `{"pattern":"yellow"}`,
		},
		{
			name:     "empty object arguments",
			content:  `{"name":"list","arguments":{}}`,
			wantName: "list",
			wantArgs: `{}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deltas, ok := parseTextToolCall(tc.content, "stop")
			if !ok {
				t.Fatalf("parseTextToolCall(%q) ok = false, want true", tc.content)
			}
			if len(deltas) != 1 || len(deltas[0]) != 1 {
				t.Fatalf("deltas shape = %d chunks, want one chunk of one fragment", len(deltas))
			}
			frag := deltas[0][0]
			if frag.Function.Name != tc.wantName {
				t.Fatalf("name = %q, want %q", frag.Function.Name, tc.wantName)
			}
			if frag.Function.Arguments != tc.wantArgs {
				t.Fatalf("arguments = %q, want %q", frag.Function.Arguments, tc.wantArgs)
			}
			if frag.Index != 0 || frag.Type != "function" {
				t.Fatalf("frag index/type = %d/%q, want 0/function", frag.Index, frag.Type)
			}
			if !strings.HasPrefix(frag.ID, "call_") || len(frag.ID) <= len("call_") {
				t.Fatalf("synthesized id = %q, want a non-empty call_-prefixed id", frag.ID)
			}
			// The synthetic delta must round-trip through the same assembler a native call
			// uses, yielding the same name/arguments and a non-empty id.
			calls, err := assembleToolCalls(deltas)
			if err != nil {
				t.Fatalf("assembleToolCalls(synthetic) error = %v, want nil", err)
			}
			if len(calls) != 1 || calls[0].Name != tc.wantName || calls[0].Arguments != tc.wantArgs {
				t.Fatalf("assembled = %+v, want one %s/%s call", calls, tc.wantName, tc.wantArgs)
			}
		})
	}
}

// --- parser: negative table -------------------------------------------------

func TestParseTextToolCall_NegativeTable(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"plain prose", "Sure, I can help you find that color."},
		{"empty content", ""},
		{"whitespace only", "   \n\t  "},
		{"prose then fenced block", "Here is the call I would make:\n" + fenced("json", `{"name":"grep","arguments":{}}`)},
		{"prose alongside inline json", `I will run {"name":"grep","arguments":{}} to search.`},
		{"quoted example among prose", `For example, {"name":"grep","arguments":{"pattern":"x"}} searches files.`},
		{"trailing prose after object", `{"name":"grep","arguments":{}} then I will report back`},
		{"malformed partial json", `{"name":"grep","arguments":`},
		{"missing name", `{"arguments":{"pattern":"x"}}`},
		{"missing arguments", `{"name":"grep"}`},
		{"null arguments", `{"name":"grep","arguments":null}`},
		{"array arguments", `{"name":"grep","arguments":[1,2,3]}`},
		{"scalar arguments", `{"name":"grep","arguments":5}`},
		{"string arguments that are not an object", `{"name":"grep","arguments":"yellow"}`},
		{"empty name", `{"name":"","arguments":{}}`},
		{"top-level array of calls", `[{"name":"grep","arguments":{}}]`},
		{"unterminated fence", "```json\n" + `{"name":"grep","arguments":{}}`},
		{"fence wrapping prose", fenced("json", "this is not a tool call")},
		// A non-JSON fence language (here "javascript") must not be stripped and executed
		// as a tool call even when its body is a valid {"name":...,"arguments":{}} object:
		// only an empty or "json" info string carries a fenced text tool call.
		{"non-json fence with valid object", fenced("javascript", `{"name":"grep","arguments":{}}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deltas, ok := parseTextToolCall(tc.content, "stop")
			if ok {
				t.Fatalf("parseTextToolCall(%q) ok = true, want false (not a whole-message tool call)", tc.content)
			}
			if deltas != nil {
				t.Fatalf("deltas = %+v, want nil on a non-tool-call", deltas)
			}
		})
	}
}

// A genuine structured turn (finishReason "tool_calls") is owned by the structured
// branch: the parser must refuse it even when the content reads as a tool-call object, so
// the structured deltas are never re-derived from text.
func TestParseTextToolCall_StructuredFinishReasonRefused(t *testing.T) {
	content := `{"name":"grep","arguments":{"pattern":"yellow"}}`
	if _, ok := parseTextToolCall(content, "tool_calls"); ok {
		t.Fatalf("parseTextToolCall(_, \"tool_calls\") ok = true, want false (structured path owns it)")
	}
}

// stillTextToolCallCandidate must return true for every prefix of a content shape
// parseTextToolCall accepts — so a real call's raw bytes are never streamed before the parse
// decision — and false the moment the reply is proven ordinary prose or an unaccepted fence,
// so live streaming resumes. These cases pin both directions.
func TestStillTextToolCallCandidate(t *testing.T) {
	candidate := []string{
		"",               // nothing streamed yet
		"   \n",          // only whitespace
		"{",              // bare object opening
		`{"name":"grep"`, // partial bare object
		"`", "``", "```", // partial / complete opening fence
		"```\n",            // empty-fence line complete
		"```js", "```json", // json info string still streaming (prefix of "json")
		"```json\n",          // complete json fence line
		"```json\n{\"name\"", // body inside an accepted fence
		"  {",                // leading whitespace then an object
	}
	for _, s := range candidate {
		if !stillTextToolCallCandidate(s) {
			t.Errorf("stillTextToolCallCandidate(%q) = false, want true (prefix of an accepted call)", s)
		}
	}
	prose := []string{
		"Hello",          // ordinary prose
		"# heading",      // markdown heading
		"- bullet",       // list item
		"```python\n",    // unaccepted fence language (line complete)
		"```js\nconsole", // streamed past a non-json info string
		"```javascript",  // non-json info string, not a prefix of "json"
	}
	for _, s := range prose {
		if stillTextToolCallCandidate(s) {
			t.Errorf("stillTextToolCallCandidate(%q) = true, want false (proven ordinary content)", s)
		}
	}
}

// --- loop behavior: parse + dispatch ----------------------------------------

// captureDispatcher records the single call it is handed so a test can assert the parsed
// name/arguments reached the dispatcher seam, then returns a fixed output.
func captureDispatcher(out string, got *AssembledToolCall) *fakeDispatcher {
	return &fakeDispatcher{resultFn: func(c AssembledToolCall) (ToolResult, error) {
		*got = c
		return ToolResult{Content: out}, nil
	}}
}

// noJSONBlobRecorded asserts no assistant message in the store carries the raw tool-call
// JSON as its text (the text form must be dispatched, never committed as an answer).
func noJSONBlobRecorded(t *testing.T, recs []sessions.Record) {
	t.Helper()
	for _, r := range recs {
		m, ok := r.(sessions.Message)
		if !ok || m.Role != "assistant" {
			continue
		}
		if text := m.Content.Text(); strings.Contains(text, `"name"`) || strings.Contains(text, `"arguments"`) {
			t.Fatalf("assistant message committed a raw tool-call JSON blob: %q", text)
		}
	}
}

// Done-when 1 (bare): a streamed turn whose only content is a bare tool-call JSON object,
// finishing as "stop" (not "tool_calls"), is parsed and dispatched through the real
// OnToolCalls/ToolDispatcher path — the tool runs, the loop reaches a final answer, and no
// raw JSON is committed as assistant text.
func TestToolLoop_TextToolCallBareParsedAndDispatched(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "where is yellow set?"))

	content := `{"name":"grep","arguments":{"pattern":"yellow","path":"."}}`
	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk(content), finishChunk("stop")}, // text-format tool call, non-tool_calls finish
		finalAnswer("found it in colors.go"),
	}}
	var got AssembledToolCall
	disp := captureDispatcher("colors.go:12: yellow", &got)
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
	if got.Name != "grep" || got.Arguments != `{"pattern":"yellow","path":"."}` {
		t.Fatalf("dispatched call = %+v, want grep with {\"pattern\":\"yellow\",\"path\":\".\"}", got)
	}

	recs := store.Records()
	asst := assistantToolCallMessages(recs)
	if len(asst) != 1 || asst[0].Content.Text() != "" {
		t.Fatalf("assistant tool-call message = %+v, want one with empty text", asst)
	}
	if len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].Type != "function" {
		t.Fatalf("assistant ToolCalls = %+v, want one function call", asst[0].ToolCalls)
	}
	noJSONBlobRecorded(t, recs)
	tools := toolMessages(recs)
	if len(tools) != 1 || tools[0].Content.Text() != "colors.go:12: yellow" {
		t.Fatalf("tool messages = %+v, want one carrying the grep output", tools)
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response after final answer; kinds = %v", eventKinds(recs))
	}
	if final := lastAssistantText(recs); final != "found it in colors.go" {
		t.Fatalf("final assistant text = %q, want the final answer", final)
	}
}

// Done-when 1 (fenced): the same parse-and-dispatch behavior when the model wraps the
// tool-call object in a ```json code fence.
func TestToolLoop_TextToolCallFencedParsedAndDispatched(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))

	content := fenced("json", `{"name":"grep","arguments":{"pattern":"yellow"}}`)
	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk(content), finishChunk("stop")},
		finalAnswer("done"),
	}}
	var got AssembledToolCall
	disp := captureDispatcher("match", &got)
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if got.Name != "grep" || got.Arguments != `{"pattern":"yellow"}` {
		t.Fatalf("dispatched call = %+v, want grep with {\"pattern\":\"yellow\"}", got)
	}
	noJSONBlobRecorded(t, store.Records())
	if len(toolMessages(store.Records())) != 1 {
		t.Fatalf("tool messages = %d, want 1 (the fenced call dispatched)", len(toolMessages(store.Records())))
	}
}

// Done-when 2: arguments supplied as a JSON-encoded string are parsed identically to the
// object form — the dispatcher receives the decoded object, not the quoted string.
func TestToolLoop_TextToolCallArgumentsAsStringParsedAsObject(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))

	content := `{"name":"grep","arguments":"{\"pattern\":\"yellow\"}"}`
	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk(content), finishChunk("stop")},
		finalAnswer("done"),
	}}
	var got AssembledToolCall
	disp := captureDispatcher("match", &got)
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if got.Arguments != `{"pattern":"yellow"}` {
		t.Fatalf("dispatched arguments = %q, want the decoded object {\"pattern\":\"yellow\"}", got.Arguments)
	}
}

// streamSurface models the production transcript surface (internal/tui) the way the
// turn wiring drives it: Sink appends each streamed delta to the open buffer, Finalize
// commits that buffer as a line, and Interrupt seals it. It lets a turn-package test assert
// exactly what reaches the visible transcript without importing internal/tui. Like the real
// transcript, the open buffer is NOT reset between provider rounds — only finalize/interrupt
// commit and clear it — so a tool-call round that shows nothing leaves the final-answer round
// to fill and finalize the buffer. loop.Run is synchronous on the test goroutine, so the
// callbacks need no lock.
type streamSurface struct {
	open      strings.Builder
	committed []string
}

func (s *streamSurface) sink(delta string) { s.open.WriteString(delta) }

func (s *streamSurface) finalize() {
	s.committed = append(s.committed, s.open.String())
	s.open.Reset()
}

func (s *streamSurface) interrupt() {
	s.committed = append(s.committed, s.open.String()+" [interrupted]")
	s.open.Reset()
}

// shown is everything the transcript would display: the committed lines plus any buffer
// still open (an un-finalized in-progress reply).
func (s *streamSurface) shown() string {
	return strings.Join(s.committed, "\n") + s.open.String()
}

// Fix 1 (critical): a text-form tool call followed by a final answer must keep the raw
// tool-call JSON out of the visible transcript. Driven through a surface that models the
// production sink/finalize wiring, the shown text must carry the final answer and never the
// raw {"name":...,"arguments":...} JSON, while the store still records the assistant
// tool-call with empty text. On the pre-fix code round 1's JSON was streamed to the sink and
// finalized together with round 2's answer, so this test fails there.
func TestToolLoop_TextToolCallJSONNeverReachesSurface(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "where is yellow set?"))

	content := `{"name":"grep","arguments":{"pattern":"yellow","path":"."}}`
	const finalText = "found it in colors.go"
	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk(content), finishChunk("stop")}, // round 1: text-format tool call
		finalAnswer(finalText),                       // round 2: the final answer
	}}
	surface := &streamSurface{}
	var got AssembledToolCall
	disp := captureDispatcher("colors.go:12: yellow", &got)
	loop := NewToolLoop(Deps{
		Active:    selectedState("openai", "gpt-x", model.EffortDefault),
		Store:     store,
		Client:    client,
		Sink:      surface.sink,
		Finalize:  surface.finalize,
		Interrupt: surface.interrupt,
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	shown := surface.shown()
	if strings.Contains(shown, `"name"`) || strings.Contains(shown, `"arguments"`) {
		t.Fatalf("raw tool-call JSON reached the transcript surface: %q", shown)
	}
	if !strings.Contains(shown, finalText) {
		t.Fatalf("final answer missing from the transcript surface: %q", shown)
	}
	// The store still records the assistant tool-call with empty text (dispatched, not shown).
	asst := assistantToolCallMessages(store.Records())
	if len(asst) != 1 || asst[0].Content.Text() != "" {
		t.Fatalf("assistant tool-call message = %+v, want one with empty text", asst)
	}
	noJSONBlobRecorded(t, store.Records())
}

// Negative (Runner level): assistant content that is not a whole-message tool call —
// prose that quotes a tool-call block — is committed as an ordinary assistant message,
// records a model_response, and is never dispatched.
func TestRun_NonToolCallTextCommitsNormally(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	prose := `For example, {"name":"grep","arguments":{"pattern":"x"}} would search the tree.`
	var dispatched bool
	runner := New(Deps{
		Active:      selectedState("openai", "gpt-x", model.EffortDefault),
		Store:       store,
		Client:      streamClient(contentChunk(prose), finishChunk("stop")),
		OnToolCalls: func(context.Context, ToolCallHandoff) error { dispatched = true; return nil },
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if dispatched {
		t.Fatal("OnToolCalls was invoked for prose that merely quotes a tool-call block")
	}
	msgs := assistantMessages(store.Records())
	if len(msgs) != 1 || msgs[0].Content.Text() != prose {
		t.Fatalf("assistant messages = %+v, want one committing the prose verbatim", msgs)
	}
	if !hasKind(store.Records(), "model_response") {
		t.Fatalf("missing model_response for an ordinary text turn; kinds = %v", eventKinds(store.Records()))
	}
}

// The text-call branch must sit after the structured branch and not steal the
// empty_response path: a stream with zero content and no tool calls still records
// empty_response and no model_response (the parser rejects empty content).
func TestRun_EmptyStreamStillEmptyResponseAfterTextBranch(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	runner := New(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: streamClient(finishChunk("stop")),
	})

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, want nil for a recorded empty_response", err)
	}
	recs := store.Records()
	if !hasKind(recs, "provider_request_failed") {
		t.Fatalf("missing provider_request_failed for an empty stream; kinds = %v", eventKinds(recs))
	}
	if hasKind(recs, "model_response") {
		t.Fatalf("model_response emitted for an empty stream; the text branch stole the empty_response path")
	}
	if len(assistantMessages(recs)) != 0 {
		t.Fatal("assistant message recorded for an empty stream")
	}
}
