// Tests for the suggest_followup interception in the agentic tool-call loop:
// the call is parsed and routed to the Deps.SuggestFollowup callback, never dispatched
// and never persisted, while suggest-only rounds preserve/finalize assistant prose and
// mixed rounds dispatch only the real calls.
package turn

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/sessions"
)

// suggestArgs is a well-formed suggest_followup arguments JSON string.
const suggestArgs = `{"label":"Add LOC deltas","prompt":"Add before/after LOC deltas to each task"}`

// assertNoSuggestFollowupOnDisk flushes the store and fails if the persisted session file
// contains the suggest_followup name anywhere — the Done-when readback that proves the
// intercepted call reached no durable record.
func assertNoSuggestFollowupOnDisk(t *testing.T, store *sessions.Store) {
	t.Helper()
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	if strings.Contains(string(data), "suggest_followup") {
		t.Fatalf("session file contains \"suggest_followup\"; the intercepted call must never be persisted:\n%s", data)
	}
}

// A round whose only tool call is suggest_followup fires the callback, dispatches
// nothing, and ends the turn (no continuation) while preserving the assistant prose as
// the ordinary final reply — with the call absent from every persisted record. Its usage
// chunk fires the Usage indicator callback exactly once (owned by ToolLoop.Run after
// the intercepted round returns), not twice — finalizeInterceptedRound no longer emits it.
func TestToolLoop_SuggestOnlyRoundFinalizesProseAndOmitsCall(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "summarize the tasks"))

	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk("Here is the summary."), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)), usageChunk(150, 25)},
	}}
	disp := &fakeDispatcher{}
	var gotLabel, gotPrompt string
	var suggestCalls int
	var usageCalls [][2]int64
	loop := NewToolLoop(Deps{
		Active: selectedState("openai", "gpt-x", model.EffortDefault),
		Store:  store,
		Client: client,
		SuggestFollowup: func(label, prompt string) {
			suggestCalls++
			gotLabel, gotPrompt = label, prompt
		},
		Usage: func(in, out int64) { usageCalls = append(usageCalls, [2]int64{in, out}) },
	}, disp, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	// One provider round: a suggest-only round is terminal and does not re-issue.
	if client.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 (suggest-only round does not re-issue)", client.callCount())
	}
	// The callback fired once with the parsed label/prompt.
	if suggestCalls != 1 || gotLabel != "Add LOC deltas" || gotPrompt != "Add before/after LOC deltas to each task" {
		t.Fatalf("SuggestFollowup fired %d times with (%q,%q), want 1 with the parsed label/prompt", suggestCalls, gotLabel, gotPrompt)
	}
	// The intercepted terminal round fires Usage exactly once (not twice), with the
	// round's exact totals.
	if len(usageCalls) != 1 || usageCalls[0] != [2]int64{150, 25} {
		t.Fatalf("Usage callback = %v, want exactly one call of (150, 25)", usageCalls)
	}
	// Nothing was dispatched.
	if got := disp.dispatchedOrder(); len(got) != 0 {
		t.Fatalf("dispatched = %v, want none (suggest_followup is intercepted, not dispatched)", got)
	}

	recs := store.Records()
	if asst := assistantToolCallMessages(recs); len(asst) != 0 {
		t.Fatalf("assistant tool-call messages = %d, want 0 (suggest_followup must not persist a tool_calls record)", len(asst))
	}
	if tools := toolMessages(recs); len(tools) != 0 {
		t.Fatalf("tool result messages = %d, want 0 (no result for an intercepted call)", len(tools))
	}
	// The assistant prose survives as the ordinary final reply, with a model_response.
	if final := lastAssistantText(recs); final != "Here is the summary." {
		t.Fatalf("final assistant text = %q, want the streamed prose", final)
	}
	if !hasKind(recs, "model_response") {
		t.Fatalf("missing model_response after suggest-only final answer; kinds = %v", eventKinds(recs))
	}
	assertNoSuggestFollowupOnDisk(t, store)
}

// A suggest_followup-only round with no visible assistant prose (empty, or whitespace the
// model streamed but that reads as nothing) produced no answer. It must surface an
// empty-response failure with visible feedback, route no ghost-text suggestion, dispatch
// nothing, and record none of the successful-answer artifacts — no assistant message, no
// model_response, no turn_latency, and no Usage callback. finalizeInterceptedRound's plain
// `assistantText != ""` check would instead persist the whitespace as an invisible reply,
// so this pins the trimmed guard and the non-nil error that suppresses ToolLoop.Run's
// success-path Usage callback.
func TestToolLoop_SuggestOnlyRoundRejectsInvisibleProse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte // nil = no content chunk streamed at all
	}{
		{name: "empty", content: nil},
		{name: "whitespace", content: contentChunk("  \n\t ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "summarize the tasks"))

			round := [][]byte{}
			if tc.content != nil {
				round = append(round, tc.content)
			}
			round = append(round,
				toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs)),
				usageChunk(150, 25),
			)
			client := &scriptedClient{rounds: [][][]byte{round}}

			disp := &fakeDispatcher{}
			var suggestCalls, usageCalls, finalizes int
			var notices []string
			loop := NewToolLoop(Deps{
				Active:          selectedState("openai", "gpt-x", model.EffortDefault),
				Store:           store,
				Client:          client,
				SuggestFollowup: func(string, string) { suggestCalls++ },
				Usage:           func(int64, int64) { usageCalls++ },
				Notice:          func(text string) { notices = append(notices, text) },
				RenderNotice:    func(verbatim, _, _ string, _ int) string { return verbatim },
				Finalize:        func() { finalizes++ },
			}, disp, 3)

			// A blank suggest-only round is a failure: Run returns the error, which is what
			// makes ToolLoop.Run skip its success-path Usage callback.
			if err := loop.Run(context.Background()); err == nil {
				t.Fatal("loop.Run() = nil, want a non-nil invalid-response error")
			}

			if suggestCalls != 0 {
				t.Fatalf("SuggestFollowup fired %d times, want 0 (no ghost text for an answer never made)", suggestCalls)
			}
			if usageCalls != 0 {
				t.Fatalf("Usage callback fired %d times, want 0 (an invalid round is not a successful round)", usageCalls)
			}
			if finalizes != 0 {
				t.Fatalf("Finalize fired %d times, want 0 (a blank suggest-only round must not finalize a successful reply)", finalizes)
			}
			if got := disp.dispatchedOrder(); len(got) != 0 {
				t.Fatalf("dispatched = %v, want none", got)
			}
			if len(notices) == 0 {
				t.Fatal("no failure notice surfaced; a blank suggest-only round must give visible feedback")
			}

			recs := store.Records()
			if !hasKind(recs, "provider_request_failed") {
				t.Fatalf("missing provider_request_failed; kinds = %v", eventKinds(recs))
			}
			if mr := decodeModelResponse(t, recs); mr.InputTokens != 150 || mr.OutputTokens != 25 {
				t.Fatalf("model_response tokens = (%d, %d), want the failed round's billed (150, 25)", mr.InputTokens, mr.OutputTokens)
			}
			if hasKind(recs, "turn_latency") {
				t.Fatalf("turn_latency recorded for an invisible suggest-only round; kinds = %v", eventKinds(recs))
			}
			if final := lastAssistantText(recs); final != "" {
				t.Fatalf("assistant text = %q, want none persisted for a blank suggest-only round", final)
			}
			assertNoSuggestFollowupOnDisk(t, store)
		})
	}
}

// A round carrying a real tool call plus a suggest_followup dispatches and persists only
// the real call, fires the callback for the suggestion, and continues to a final answer —
// with the suggestion absent from every record.
func TestToolLoop_MixedRoundDispatchesRealCallAndInterceptsSuggest(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "do it"))

	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk("Working on it."), toolCallsChunk(
			toolFrag(0, "call_real", "do", "{}"),
			toolFrag(1, "call_s", "suggest_followup", suggestArgs),
		)},
		finalAnswer("all done"),
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

	if client.callCount() != 2 {
		t.Fatalf("provider calls = %d, want 2 (a mixed round continues to a final answer)", client.callCount())
	}
	if suggestCalls != 1 {
		t.Fatalf("SuggestFollowup fired %d times, want 1", suggestCalls)
	}
	// Only the real call dispatched; the suggestion was intercepted.
	if got := disp.dispatchedOrder(); len(got) != 1 || got[0] != "call_real" {
		t.Fatalf("dispatched = %v, want [call_real] (suggest_followup intercepted)", got)
	}

	recs := store.Records()
	asst := assistantToolCallMessages(recs)
	if len(asst) != 1 {
		t.Fatalf("assistant tool-call messages = %d, want 1", len(asst))
	}
	if len(asst[0].ToolCalls) != 1 || asst[0].ToolCalls[0].ID != "call_real" {
		t.Fatalf("assistant ToolCalls = %+v, want only call_real (suggest_followup omitted)", asst[0].ToolCalls)
	}
	if asst[0].Content.Text() != "Working on it." {
		t.Fatalf("assistant tool-call content = %q, want the streamed prose preserved", asst[0].Content.Text())
	}
	if tools := toolMessages(recs); len(tools) != 1 || tools[0].ToolCallID != "call_real" {
		t.Fatalf("tool messages = %+v, want one answering call_real only", tools)
	}
	assertNoSuggestFollowupOnDisk(t, store)
}

// parseSuggestFollowup tolerates malformed/partial arguments without erroring: a weak
// model that mis-emits the call must not fail the turn (the call is intercepted either
// way), so a bad payload yields empty strings rather than a parse failure.
func TestParseSuggestFollowup_MalformedArgsYieldEmpty(t *testing.T) {
	for _, args := range []string{``, `{not json`, `{"label":"only label"}`, `[]`} {
		label, prompt := parseSuggestFollowup(args)
		if args == `{"label":"only label"}` {
			if label != "only label" || prompt != "" {
				t.Fatalf("parseSuggestFollowup(%q) = (%q,%q), want (only label, empty)", args, label, prompt)
			}
			continue
		}
		if label != "" || prompt != "" {
			t.Fatalf("parseSuggestFollowup(%q) = (%q,%q), want both empty", args, label, prompt)
		}
	}
}
