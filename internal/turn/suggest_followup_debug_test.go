// Tests for the turn-side suggest_followup development trace: when the dev-debug
// gate is on the loop records an ordered suggest_followup_debug sequence (advertised /
// no-call / seen / intercepted) carrying only stages, context, and lengths — never the
// suggestion text — and when the gate is off it records nothing.
package turn

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

// followupDebugEvents decodes every suggest_followup_debug record in order, so a test can
// assert the exact stage sequence and the per-stage context the trace recorded.
func followupDebugEvents(t *testing.T, recs []sessions.Record) []events.SuggestFollowupDebug {
	t.Helper()
	var out []events.SuggestFollowupDebug
	for _, r := range recs {
		ev, ok := r.(sessions.Event)
		if !ok || ev.Kind != events.KindSuggestFollowupDebug {
			continue
		}
		var p events.SuggestFollowupDebug
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode suggest_followup_debug payload: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func followupDebugStages(evs []events.SuggestFollowupDebug) []string {
	stages := make([]string, len(evs))
	for i, e := range evs {
		stages[i] = e.Stage
	}
	return stages
}

// A forced suggest-only round with the gate on records request_built (advertised),
// tool_call_seen, and intercepted — in that order, each stamped with the turn's
// provider/model/mode — and the intercepted stage carries the label/prompt rune lengths
// while the persisted session never contains the suggestion text itself.
func TestToolLoop_DevDebugRecordsForcedSuggestSequence(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "summarize the tasks"))

	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk("Here is the summary."), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs))},
	}}
	loop := NewToolLoop(Deps{
		Active:               selectedState("openai", "gpt-x", model.EffortDefault),
		Store:                store,
		Client:               client,
		Tools:                []provider.ToolDefinition{provider.SuggestFollowupToolDefinition()},
		SuggestFollowupDebug: true,
		Mode:                 "build",
		SuggestFollowup:      func(string, string) {},
	}, &fakeDispatcher{}, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}

	evs := followupDebugEvents(t, store.Records())
	gotStages := followupDebugStages(evs)
	wantStages := []string{
		events.SuggestFollowupStageRequestBuilt,
		events.SuggestFollowupStageToolCallSeen,
		events.SuggestFollowupStageIntercepted,
	}
	if strings.Join(gotStages, ",") != strings.Join(wantStages, ",") {
		t.Fatalf("debug stages = %v, want %v", gotStages, wantStages)
	}

	// Every stage carries the turn's provider/model/mode for correlation.
	for _, e := range evs {
		if e.Provider != "openai" || e.ModelID != "gpt-x" || e.Mode != "build" {
			t.Fatalf("stage %q context = (%q,%q,%q), want (openai,gpt-x,build)", e.Stage, e.Provider, e.ModelID, e.Mode)
		}
	}
	// request_built records that suggest_followup was advertised; no-call never fired.
	if rb := evs[0]; rb.Advertised == nil || !*rb.Advertised {
		t.Fatalf("request_built advertised = %v, want true", rb.Advertised)
	}
	// intercepted carries the label/prompt rune lengths, not the text.
	ic := evs[2]
	if ic.LabelLen != 14 || ic.PromptLen != 40 {
		t.Fatalf("intercepted lengths = (label %d, prompt %d), want (14, 40)", ic.LabelLen, ic.PromptLen)
	}

	// Privacy readback: the persisted session must never carry the suggestion label or
	// prompt text, even though the debug events (suggest_followup_debug kind) are present.
	if _, _, err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flush store: %v", err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	for _, secret := range []string{"Add LOC deltas", "Add before/after LOC deltas to each task"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("session file contains suggestion text %q; the trace must persist only lengths:\n%s", secret, data)
		}
	}
}

// With the gate off (the default), the same forced suggest-only round records no
// suggest_followup_debug events at all — a normal session stays byte-free of the trace.
func TestToolLoop_DevDebugOffRecordsNoTrace(t *testing.T) {
	store := storeAt(filepath.Join(t.TempDir(), "session.json"))
	store.Append(textMsg("user", "summarize the tasks"))

	client := &scriptedClient{rounds: [][][]byte{
		{contentChunk("Here is the summary."), toolCallsChunk(toolFrag(0, "call_s", "suggest_followup", suggestArgs))},
	}}
	loop := NewToolLoop(Deps{
		Active:          selectedState("openai", "gpt-x", model.EffortDefault),
		Store:           store,
		Client:          client,
		Tools:           []provider.ToolDefinition{provider.SuggestFollowupToolDefinition()},
		SuggestFollowup: func(string, string) {},
	}, &fakeDispatcher{}, 3)

	if err := loop.Run(context.Background()); err != nil {
		t.Fatalf("loop.Run() error = %v, want nil", err)
	}
	if evs := followupDebugEvents(t, store.Records()); len(evs) != 0 {
		t.Fatalf("recorded %d suggest_followup_debug events with the gate off, want 0: %v", len(evs), followupDebugStages(evs))
	}
}

// A plain final-answer round (the model never calls suggest_followup) with the gate on
// records request_built then provider_round_no_call — the trace that distinguishes "model
// produced prose instead of calling the tool" from an interception. advertised reflects
// whether the tool was offered.
func TestToolLoop_DevDebugRecordsNoCallWhenModelDoesNotCall(t *testing.T) {
	cases := []struct {
		name           string
		tools          []provider.ToolDefinition
		wantAdvertised bool
	}{
		{"advertised", []provider.ToolDefinition{provider.SuggestFollowupToolDefinition()}, true},
		{"not advertised", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := storeAt(filepath.Join(t.TempDir(), "session.json"))
			store.Append(textMsg("user", "hi"))

			client := &scriptedClient{rounds: [][][]byte{finalAnswer("just prose, no tool call")}}
			loop := NewToolLoop(Deps{
				Active:               selectedState("openai", "gpt-x", model.EffortDefault),
				Store:                store,
				Client:               client,
				Tools:                tc.tools,
				SuggestFollowupDebug: true,
				Mode:                 "plan",
			}, &fakeDispatcher{}, 3)

			if err := loop.Run(context.Background()); err != nil {
				t.Fatalf("loop.Run() error = %v, want nil", err)
			}

			evs := followupDebugEvents(t, store.Records())
			gotStages := followupDebugStages(evs)
			wantStages := []string{events.SuggestFollowupStageRequestBuilt, events.SuggestFollowupStageNoCall}
			if strings.Join(gotStages, ",") != strings.Join(wantStages, ",") {
				t.Fatalf("debug stages = %v, want %v", gotStages, wantStages)
			}
			if rb := evs[0]; rb.Advertised == nil || *rb.Advertised != tc.wantAdvertised {
				t.Fatalf("request_built advertised = %v, want %v", rb.Advertised, tc.wantAdvertised)
			}
		})
	}
}
