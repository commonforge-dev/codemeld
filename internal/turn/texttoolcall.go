// Recognizes a tool call a small/open model emits as assistant text (a JSON object,
// optionally inside one code fence) instead of as a structured tool call, and turns it
// into the synthetic streamed tool-call delta the agentic loop already assembles and
// dispatches (docs/ibm-model-issues.md).
package turn

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/openai/openai-go/v3"

	"codemeld.dev/codemeld/internal/ids"
)

// parseTextToolCall recognizes an assistant turn whose entire content is a single
// tool-call JSON object — bare or wrapped in one code fence — and returns it as a
// synthetic streamed tool-call delta that assembleToolCalls reconstructs exactly like a
// native call. It returns (nil, false) when the content is not a whole-message tool
// call, so the caller commits it as ordinary assistant text instead.
//
// Parsing is deliberately conservative (Step 2) to avoid hijacking prose: after trimming
// whitespace and at most one outer code fence, the entire message must be a single JSON
// object carrying a non-empty string "name" and an object-compatible "arguments" (a JSON
// object, or a JSON-encoded string that itself decodes to an object). Prose that merely
// mentions or quotes a tool-call block, text alongside a JSON block, malformed/partial
// JSON, a missing name or arguments, and a genuine structured turn (finishReason
// "tool_calls", which the structured path owns) are all rejected. The text form carries
// no tool_call_id, so a fresh one is synthesized because assembleToolCalls rejects empty
// ids.
func parseTextToolCall(content, finishReason string) ([][]openai.ChatCompletionChunkChoiceDeltaToolCall, bool) {
	// A structured tool-call turn is owned by the structured branch; never re-derive it
	// from the assistant text even if the content happens to look like a call.
	if finishReason == "tool_calls" {
		return nil, false
	}

	body := stripOneCodeFence(strings.TrimSpace(content))

	// json.Unmarshal rejects any non-whitespace before or after the single JSON value, so
	// this enforces "the whole message is one JSON object": leading or trailing prose, a
	// quoted example among text, and partial JSON all fail to decode here.
	var parsed struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return nil, false
	}
	if parsed.Name == "" || len(parsed.Arguments) == 0 {
		return nil, false
	}
	arguments, ok := normalizeToolArguments(parsed.Arguments)
	if !ok {
		return nil, false
	}

	frag := openai.ChatCompletionChunkChoiceDeltaToolCall{
		Index: 0,
		// The text form carries no id; assembleToolCalls rejects empty ids, so synthesize a
		// non-empty one that still reads as a tool_call_id.
		ID:   "call_" + ids.NewV7(),
		Type: "function",
		Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{
			Name:      parsed.Name,
			Arguments: arguments,
		},
	}
	return [][]openai.ChatCompletionChunkChoiceDeltaToolCall{{frag}}, true
}

// normalizeToolArguments renders a text tool call's "arguments" as the compact
// object-JSON string assembleToolCalls and decodeToolArgs expect — the same raw shape a
// structured call carries. It accepts arguments given directly as a JSON object or as a
// JSON-encoded string that itself decodes to an object; any other shape (array, scalar,
// null, or a string that is not an object) is rejected so a non-tool-call is not coerced
// into one.
func normalizeToolArguments(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}
	switch trimmed[0] {
	case '{':
		return compactJSONObject(trimmed)
	case '"':
		var encoded string
		if err := json.Unmarshal(trimmed, &encoded); err != nil {
			return "", false
		}
		return compactJSONObject([]byte(encoded))
	default:
		return "", false
	}
}

// compactJSONObject validates that b is a single JSON object and returns it with
// insignificant whitespace removed. json.Compact preserves key order (unlike a
// map round-trip) and rejects trailing non-whitespace after the value, so a string such
// as `{"a":1} extra` does not slip through.
func compactJSONObject(b []byte) (string, bool) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return "", false
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return "", false
	}
	return buf.String(), true
}

// stripOneCodeFence removes a single outer Markdown code fence (``` optionally followed
// by a language tag such as json) when the message is exactly one fenced block, returning
// the inner text trimmed. Anything that is not cleanly one outer fence is returned
// unchanged, so a fence wrapping prose (or text outside the fence) still fails the
// whole-message JSON check upstream. The input is assumed already whitespace-trimmed.
func stripOneCodeFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	rest := s[len("```"):]
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return s
	}
	if !fenceInfoString(rest[:nl]) {
		return s
	}
	inner := strings.TrimRight(rest[nl+1:], " \t\r\n")
	if !strings.HasSuffix(inner, "```") {
		return s
	}
	return strings.TrimSpace(inner[:len(inner)-len("```")])
}

// fenceInfoString reports whether the opening fence's info string marks a fenced text
// tool call: it must be empty or exactly "json" (case-insensitive). The task accepts only
// these two carriers (Step 2), so any other language tag — e.g. "javascript" — leaves the
// fence in place and the upstream whole-message JSON check rejects the block, keeping a
// fenced code example that merely looks like a call from being executed as one.
func fenceInfoString(s string) bool {
	s = strings.TrimRight(s, " \t\r")
	return s == "" || strings.EqualFold(s, "json")
}

// stillTextToolCallCandidate reports whether the assistant content streamed so far could
// still become a whole-message text tool call — a bare JSON object, or one outer code
// fence whose info string is empty or "json". Runner.Run holds streamed deltas back from
// the live sink while this is true so a completed text tool call's raw JSON is never shown;
// the first delta that makes it false proves the reply is ordinary prose, and the held
// deltas are then flushed and the rest streams live.
//
// It must return true for every prefix of any content parseTextToolCall accepts, so a real
// call's bytes are never streamed before the parse decision. It is intentionally permissive
// past that bar — a bare object or an accepted fence is buffered to stream end even when it
// ultimately fails to parse — trading a one-message rendering delay in those rare shapes for
// the guarantee that tool-call JSON stays hidden.
func stillTextToolCallCandidate(content string) bool {
	s := strings.TrimLeft(content, " \t\r\n")
	switch {
	case s == "":
		return true // only whitespace so far — anything could follow
	case s[0] == '{':
		return true // bare JSON object candidate; resolved when the stream completes
	case strings.HasPrefix("```", s):
		return true // "`", "``", or "```" — still a possible opening fence
	case !strings.HasPrefix(s, "```"):
		return false // first non-space rune is neither '{' nor a fence: ordinary prose
	}
	// Past a complete "```": decide on the fence info string. Until its terminating newline
	// arrives the info string is still streaming, so stay a candidate only while it remains a
	// possible prefix of "" or "json"; once the line is complete accept only an info string
	// fenceInfoString allows.
	rest := s[len("```"):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		return fenceInfoString(rest[:nl])
	}
	return strings.HasPrefix("json", strings.ToLower(strings.TrimRight(rest, " \t\r")))
}
