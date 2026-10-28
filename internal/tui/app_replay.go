// Session replay/decode and completion-footer methods for the App shell: projecting a resumed session's records into transcript blocks and reconstructing each turn's completion footer.

package tui

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/toolactivity"
)

// maxReplayBlocks bounds how many rendered conversation blocks /resume replays into
// the transcript: a long resumed session keeps only its most recent
// maxReplayBlocks user/assistant blocks, with a single omission marker standing in for
// the older ones, so the pane cannot blow up on a huge history.
const maxReplayBlocks = 200

// ReplaySessionRecords re-renders a resumed session's prior conversation into the transcript
// so /resume does not land on an empty-looking pane. Both entry points call it on the tview
// event-loop goroutine (cold-start before Run, or the in-TUI /resume continuation), so it
// mutates the pane directly rather than marshaling through the event queue; the projection
// and bounding rules live on replaySessionBlocks.
func (a *App) ReplaySessionRecords(records []sessions.Record) {
	a.transcript.replayBlocks(replaySessionBlocks(records), maxReplayBlocks)
}

// replaySessionBlocks projects a session record stream onto the ordered list of
// rendered transcript blocks ReplaySessionRecords appends. It mirrors the live
// transcript's visible content: a non-list user message becomes the escaped "> text"
// echo (input.go's submitted-prompt form), and a non-list assistant message with
// non-empty text is rendered through renderMarkdown, carrying that reply's fenced-block
// bodies so a replayed block's copy control has the same payload the live one had.
//
// It also reconstructs each completed turn's "provider - model - duration - HH:MM" footer
// by pairing the turn's start-of-turn model_turn event with its final turn_latency event:
// a visible assistant reply seen between the two gets a footer block appended right after
// it. A turn missing either event, or with no visible assistant reply (interrupted,
// failed, or tool-call-only), gets no footer — turn_latency exists only for a completed
// final answer, so its absence is the negative filter. Footer blocks are transcript-only
// UI derived from durable events, never message records, so they add nothing to the model
// input projection.
func replaySessionBlocks(records []sessions.Record) []replayBlock {
	var blocks []replayBlock
	var pendingModelTurn *events.ModelTurn // the open turn's model_turn, nil until one is seen
	var hasVisibleReply bool               // the open turn produced a visible assistant reply
	children := map[string]*replayChildAgent{}
	for i, rec := range records {
		switch r := rec.(type) {
		case sessions.Event:
			switch r.Kind {
			case events.KindChildAgentStart:
				// Routing is by invocation id alone, never by which records fall between a
				// start and an end, so two children whose lifetimes overlap in the stream
				// still replay as two separate blocks.
				start, ok := decodeChildAgentStart(r.Payload)
				if !ok {
					break
				}
				if _, seen := children[start.InvocationID]; seen {
					break
				}
				blocks = append(blocks, replayBlock{text: childAgentBlockText(start, nil, nil, false)})
				children[start.InvocationID] = &replayChildAgent{at: len(blocks) - 1, start: start}
			case events.KindChildAgentEnd:
				end, ok := decodeChildAgentEnd(r.Payload)
				if !ok {
					break
				}
				child, seen := children[end.InvocationID]
				if !seen || child.closed {
					break
				}
				blocks[child.at].text = childAgentBlockText(child.start, nil, &end, false)
				child.closed = true
			case events.KindModelTurn:
				// A model_turn marks a new turn boundary, so it always closes the previous
				// turn's window before opening this one. Clearing first means a malformed
				// marker cannot leave the prior turn's provider/model to be paired with this
				// turn's reply — the boundary is honored even when its payload is unusable.
				pendingModelTurn = nil
				hasVisibleReply = false
				if mt, ok := decodeModelTurn(r.Payload); ok {
					pendingModelTurn = &mt
				}
			case events.KindTurnLatency:
				// The final turn_latency closes the window: append the footer only when the
				// turn carried both a model_turn and a visible assistant reply.
				if tl, ok := decodeTurnLatency(r.Payload); ok && pendingModelTurn != nil && hasVisibleReply {
					blocks = append(blocks, replayBlock{text: completionFooter(*pendingModelTurn, tl, r.Timestamp)})
				}
				pendingModelTurn = nil
				hasVisibleReply = false
			}
		case sessions.Message:
			switch r.Role {
			case "user":
				if r.Content.IsList() {
					// A content-part user message renders its text part as the "> text" echo
					// and each image_url part as an "[image: name (size)]" placeholder, the
					// same projection the live submit echo uses. A list with no such
					// parts projects to "" and is skipped.
					if block := contentPartBlock(r.Content.Parts()); block != "" {
						blocks = append(blocks, replayBlock{text: block})
					}
					continue
				}
				// Route the plain-text user record through the same renderer as the live echo
				// and the content-part path so all three carry the teal rail identically;
				// previously this branch built the "> " prefix inline and so missed the rail.
				blocks = append(blocks, replayBlock{text: userBlockLines(r.Content.Text(), nil)})
			case "assistant":
				if !r.Content.IsList() {
					if text := r.Content.Text(); strings.TrimSpace(text) != "" {
						rendered, controls, payload := renderMarkdown(text)
						rendered, controls = appendResponseControl(rendered, controls, payload)
						blocks = append(blocks, replayBlock{text: rendered, controls: controls})
						hasVisibleReply = true
					}
				}
				if block := webActivityBlock(r.ToolCalls); block != "" {
					blocks = append(blocks, replayBlock{text: block})
				}
				for _, block := range askUserBlocks(r.ToolCalls, toolResultsAfter(records, i)) {
					blocks = append(blocks, replayBlock{text: block})
				}
			}
			// system messages and role:tool results are model-continuation data the live
			// transcript never shows, so they contribute no replay block.
		}
	}
	return blocks
}

// replayChildAgent tracks one child's block while the record stream is walked: at is where
// its block sits so the end record can rewrite it in place, and closed keeps a second end
// record from reopening a block already closed.
type replayChildAgent struct {
	at     int
	start  events.ChildAgentStart
	closed bool
}

func decodeChildAgentStart(payload json.RawMessage) (events.ChildAgentStart, bool) {
	var p events.ChildAgentStart
	if err := json.Unmarshal(payload, &p); err != nil || p.InvocationID == "" {
		return events.ChildAgentStart{}, false
	}
	return p, true
}

func decodeChildAgentEnd(payload json.RawMessage) (events.ChildAgentEnd, bool) {
	var p events.ChildAgentEnd
	if err := json.Unmarshal(payload, &p); err != nil || p.InvocationID == "" {
		return events.ChildAgentEnd{}, false
	}
	return p, true
}

func webActivityBlock(calls []sessions.ToolCall) string {
	var lines []string
	for _, call := range calls {
		name, arguments, ok := decodeToolCallFunction(call.Raw)
		if !ok {
			continue
		}
		line, ok := toolactivity.WebLine(name, arguments)
		if !ok {
			continue
		}
		lines = append(lines, line)
	}
	return toolActivityBlockText(lines)
}

// results holds only this call's own response group, so an id a later round reuses can never
// be paired here. The id also has to be unambiguous on both sides: session validation accepts
// two calls sharing one id as long as one result answers it, which would render one record
// twice or hand an ask_user call a result that belongs to another tool.
func askUserBlocks(calls []sessions.ToolCall, results map[string][]string) []string {
	owners := make(map[string]int, len(calls))
	for _, call := range calls {
		owners[call.ID]++
	}
	var blocks []string
	for _, call := range calls {
		name, arguments, ok := decodeToolCallFunction(call.Raw)
		if !ok || name != provider.AskUserToolName {
			continue
		}
		if owners[call.ID] != 1 || len(results[call.ID]) != 1 {
			continue
		}
		if block := askUserReplayBlock(arguments, results[call.ID][0]); block != "" {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

// A saved session is arbitrary content by the time /resume reads it, so a matching call id is
// not enough: the call has to be one the live form would have mounted — the same provider
// checker production dispatch runs — and the result has to be bytes the form could have
// written. Every prompt the record shows comes from the saved call rather than from the result.
func askUserReplayBlock(arguments, result string) string {
	call, err := provider.DecodeAskUserRequest(arguments)
	if err != nil {
		return ""
	}
	saved, ok := replayResult(result)
	if !ok || saved.Cancelled {
		return ""
	}
	if saved.Clarification != "" {
		if !replayFormText(saved.Clarification) || utf8.RuneCountInString(saved.Clarification) > maxClarificationRunes {
			return ""
		}
		return questionRecordBlock(QuestionResult{Clarification: saved.Clarification})
	}
	if len(saved.Answers) != len(call.Questions) {
		return ""
	}
	for i, q := range call.Questions {
		if !replayAnswer(q, saved.Answers[i]) {
			return ""
		}
	}
	return questionRecordBlock(QuestionResult{Answers: saved.Answers})
}

// Whether the live form could have written these exact bytes is one comparison, not a list of
// byte patterns to refuse: re-encoding what the result decodes to, through the same
// QuestionResult.Encode the dispatch path used, has to reproduce the saved text. Anything
// encoding/json accepts but never writes — an unknown or repeated member, a repaired lone
// surrogate or invalid UTF-8 byte, a \uXXXX escape for a character written literally,
// whitespace between tokens, a reordered or omitted member, a null where the form writes an
// empty array — comes back different and is refused. What is left for the value checks is only
// what the encoder cannot know: the question the answer belongs to, and what the user typed.
func replayResult(result string) (QuestionResult, bool) {
	var saved QuestionResult
	if err := json.Unmarshal([]byte(result), &saved); err != nil {
		return QuestionResult{}, false
	}
	encoded, err := saved.Encode()
	return saved, err == nil && encoded == result
}

// The form trims what the user typed and drops it when nothing is left, so untrimmed or empty
// text is text no form produced.
func replayFormText(text string) bool {
	return text != "" && strings.TrimSpace(text) == text
}

func replayAnswer(q provider.AskUserQuestion, answer QuestionAnswer) bool {
	if answer.ID != q.ID || answer.Prompt != q.Prompt {
		return false
	}
	if answer.Selected == nil || (len(answer.Selected) > 1 && !q.MultiSelect) {
		return false
	}
	// questionBlock.answer walks the offered options in order and keeps each at most once, so a
	// reordered or repeated selection is one no form wrote; advancing the search past each match
	// is both checks at once.
	offered := q.Options
	for _, option := range answer.Selected {
		at := slices.Index(offered, option)
		if at < 0 {
			return false
		}
		offered = offered[at+1:]
	}
	if answer.Custom == "" {
		return true
	}
	if !q.AllowCustom || !replayFormText(answer.Custom) {
		return false
	}
	// Choosing an option and opening the custom field each clear the other unless the question
	// is multi-select, where the field stays open alongside the checked options.
	return q.MultiSelect || len(answer.Selected) == 0
}

// A response group is the contiguous run of role-tool messages after an assistant tool-call
// record, so anything else ends it — the same boundary sessions validation enforces.
func toolResultsAfter(records []sessions.Record, i int) map[string][]string {
	results := make(map[string][]string)
	for j := i + 1; j < len(records); j++ {
		msg, ok := records[j].(sessions.Message)
		if !ok || msg.Role != "tool" {
			break
		}
		results[msg.ToolCallID] = append(results[msg.ToolCallID], msg.Content.Text())
	}
	return results
}

func decodeToolCallFunction(raw json.RawMessage) (string, string, bool) {
	var wrapper struct {
		Function struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil || wrapper.Function.Name == "" {
		return "", "", false
	}
	var arguments string
	_ = json.Unmarshal(wrapper.Function.Arguments, &arguments)
	return wrapper.Function.Name, arguments, true
}

// decodeModelTurn decodes a model_turn event payload, reporting ok=false when the
// payload is malformed or missing the provider/model the footer needs, so a bad record
// is treated as absent rather than rendering a half-empty footer.
func decodeModelTurn(payload json.RawMessage) (events.ModelTurn, bool) {
	var p events.ModelTurn
	if err := json.Unmarshal(payload, &p); err != nil || p.Provider == "" || p.ModelID == "" {
		return events.ModelTurn{}, false
	}
	return p, true
}

// decodeTurnLatency decodes a turn_latency event payload, reporting ok=false when it is
// malformed or incomplete so a bad record is treated as absent. It enforces the same
// invariants the event's own validate() does — non-empty provider/model and a present,
// non-negative duration_ms — so an incomplete payload like {"provider":..,"model_id":..}
// (missing duration_ms, which would otherwise decode to a bogus 0s footer) is rejected. A
// pointer detects presence, keeping a genuine duration_ms:0 (the zero-delta turn) valid.
func decodeTurnLatency(payload json.RawMessage) (events.TurnLatency, bool) {
	var p struct {
		Provider   string `json:"provider"`
		ModelID    string `json:"model_id"`
		DurationMs *int64 `json:"duration_ms"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return events.TurnLatency{}, false
	}
	if p.Provider == "" || p.ModelID == "" || p.DurationMs == nil || *p.DurationMs < 0 {
		return events.TurnLatency{}, false
	}
	return events.TurnLatency{Provider: p.Provider, ModelID: p.ModelID, DurationMs: *p.DurationMs}, true
}

// completionFooter renders the completion footer block for a completed turn, taking the
// provider/model from its model_turn and the duration and completion time from its final
// turn_latency, the duration formatted like the in-flight indicator's elapsed time so the
// same submit-start timing basis reads identically live and on replay.
func completionFooter(mt events.ModelTurn, tl events.TurnLatency, completedAt time.Time) string {
	return completionFooterBlock(mt.Provider, mt.ModelID, formatElapsed(time.Duration(tl.DurationMs)*time.Millisecond), completedAt)
}

// latestCompletionFooter returns the completion footer block for the latest turn in
// records, pairing that turn's start-of-turn model_turn with its final turn_latency the
// same way replaySessionBlocks does. It reflects only the latest turn window: a new
// model_turn opens a fresh window and clears any footer computed for an earlier turn, so a
// footer-free latest turn never reuses a prior success's footer. It reports ok=false when
// the latest turn has no turn_latency, no model_turn, or no visible reply — the
// interrupted, failed, empty-response, and tool-call-only cases that must show no footer.
// (Every turn that reaches this path emits a start-of-turn model_turn via EmitTurnStart,
// including the nil-error zero-delta empty-response turn that carries no turn_latency.)
func latestCompletionFooter(records []sessions.Record) (string, bool) {
	var pendingModelTurn *events.ModelTurn
	var hasVisibleReply bool
	var footer string
	var ok bool
	for _, rec := range records {
		switch r := rec.(type) {
		case sessions.Event:
			switch r.Kind {
			case events.KindModelTurn:
				// A model_turn marks a new turn boundary and supersedes any earlier turn's
				// footer, even when malformed — a bad marker still starts a fresh (footerless)
				// window rather than letting the prior turn's footer leak forward.
				pendingModelTurn = nil
				hasVisibleReply = false
				footer = ""
				ok = false
				if mt, dok := decodeModelTurn(r.Payload); dok {
					pendingModelTurn = &mt
				}
			case events.KindTurnLatency:
				if tl, dok := decodeTurnLatency(r.Payload); dok && pendingModelTurn != nil && hasVisibleReply {
					footer = completionFooter(*pendingModelTurn, tl, r.Timestamp)
					ok = true
				}
				pendingModelTurn = nil
				hasVisibleReply = false
			}
		case sessions.Message:
			if r.Role == "assistant" && !r.Content.IsList() && strings.TrimSpace(r.Content.Text()) != "" {
				hasVisibleReply = true
			}
		}
	}
	return footer, ok
}

// replayOmissionMarker is the single line replayBlocks inserts above the kept blocks
// when a resumed session's history exceeds maxReplayBlocks, naming how many older
// blocks were dropped so the bound is visible rather than silent.
func replayOmissionMarker(dropped int) string {
	return fmt.Sprintf("[%d earlier message(s) not shown]", dropped)
}

// AppendCompletionFooter appends the "provider - model - duration" footer for the most
// recently completed successful turn in records, taking provider/model from the turn's
// model_turn event and the duration from its final turn_latency event. It is a
// no-op when the latest turn produced no visible assistant reply or is missing either
// durable record — interrupted, failed, and tool-call-only turns show no footer. The
// turn controller calls it off the tview event-loop goroutine after a natural
// completion, so it marshals through the tview queue like the other stream-surface
// methods; the FinalizeStream that committed the reply is queued first, so the footer
// lands directly after it. The footer is a transcript-only metadata block: it is never
// recorded, so it cannot become model input or a durable user/assistant message.
func (a *App) AppendCompletionFooter(records []sessions.Record) {
	block, ok := latestCompletionFooter(records)
	if !ok {
		return
	}
	a.streamUpdate(func() { a.transcript.append(block) })
}
