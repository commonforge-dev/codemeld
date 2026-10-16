// Tests for the TUI-side suggest_followup development trace: when the dev-debug gate
// is armed (SetFollowupDebugContext), the surface/ghost/accept/clear seams append ordered
// suggest_followup_debug events carrying only stages, context, lengths, and a discard
// reason — never the suggestion text — and when it is not armed they append nothing.
package tui

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

func followupDebugStore(t *testing.T) *sessions.Store {
	t.Helper()
	return sessions.New(filepath.Join(t.TempDir(), "session.json"), &sessions.Session{})
}

// followupDebugEvents decodes the suggest_followup_debug records in order so a test can
// assert the exact TUI stage sequence and the recorded context/reason.
func followupDebugEvents(t *testing.T, store *sessions.Store) []events.SuggestFollowupDebug {
	t.Helper()
	var out []events.SuggestFollowupDebug
	for _, r := range store.Records() {
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

func followupStages(evs []events.SuggestFollowupDebug) []string {
	stages := make([]string, len(evs))
	for i, e := range evs {
		stages[i] = e.Stage
	}
	return stages
}

// armedFollowupDebugApp builds an App with an active store and the dev-debug context armed,
// so the suggest_followup seams record their trace.
func armedFollowupDebugApp(t *testing.T) (*App, *sessions.Store) {
	t.Helper()
	a := New(nil)
	store := followupDebugStore(t)
	a.SetActiveStore(store)
	a.SetFollowupDebugContext("openai", "gpt-x", "build")
	return a, store
}

// A valid suggestion offered into an empty input records surface_called then ghost_set,
// each stamped with the armed provider/model/mode, and ghost_set carries the label/prompt
// rune lengths — not the text.
func TestApp_DevDebug_SurfaceThenGhostSet(t *testing.T) {
	a, store := armedFollowupDebugApp(t)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	evs := followupDebugEvents(t, store)
	if got := followupStages(evs); strings.Join(got, ",") != "surface_called,ghost_set" {
		t.Fatalf("stages = %v, want [surface_called ghost_set]", got)
	}
	for _, e := range evs {
		if e.Provider != "openai" || e.ModelID != "gpt-x" || e.Mode != "build" {
			t.Fatalf("stage %q context = (%q,%q,%q), want (openai,gpt-x,build)", e.Stage, e.Provider, e.ModelID, e.Mode)
		}
	}
	if gs := evs[1]; gs.LabelLen != 15 || gs.PromptLen != 31 {
		t.Fatalf("ghost_set lengths = (label %d, prompt %d), want (15, 31)", gs.LabelLen, gs.PromptLen)
	}
	assertNoFollowupTextPersisted(t, store, "write the tests", "Write unit tests for the parser")
}

// Tab acceptance records ghost_accepted after the surface/set pair.
func TestApp_DevDebug_TabRecordsAccepted(t *testing.T) {
	a, store := armedFollowupDebugApp(t)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")

	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := followupStages(followupDebugEvents(t, store)); strings.Join(got, ",") != "surface_called,ghost_set,ghost_accepted" {
		t.Fatalf("stages = %v, want [surface_called ghost_set ghost_accepted]", got)
	}
}

// A suggestion that the surface rejects records surface_called then ghost_cleared with the
// reason for the drop, and never arms a ghost.
func TestApp_DevDebug_SurfaceRejectionRecordsClearedReason(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(a *App)
		label      string
		prompt     string
		wantReason string
	}{
		{"blank label", func(*App) {}, "  ", "Write unit tests", "blank_fields"},
		{"occupied input", func(a *App) { a.input.SetText("draft") }, "write the tests", "Write unit tests", "input_occupied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, store := armedFollowupDebugApp(t)
			tc.setup(a)
			a.SuggestFollowup(tc.label, tc.prompt)

			evs := followupDebugEvents(t, store)
			if got := followupStages(evs); strings.Join(got, ",") != "surface_called,ghost_cleared" {
				t.Fatalf("stages = %v, want [surface_called ghost_cleared]", got)
			}
			if r := evs[1].Reason; r != tc.wantReason {
				t.Fatalf("ghost_cleared reason = %q, want %q", r, tc.wantReason)
			}
		})
	}
}

// A discarding key (empty-buffer Escape through the global capture) records ghost_cleared
// with the discard reason once a suggestion is pending.
func TestApp_DevDebug_DiscardKeyRecordsCleared(t *testing.T) {
	a, store := armedFollowupDebugApp(t)
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")
	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)); ev != nil {
		t.Fatalf("Escape not consumed by handleGlobalKey: %v", ev)
	}

	evs := followupDebugEvents(t, store)
	if got := followupStages(evs); strings.Join(got, ",") != "surface_called,ghost_set,ghost_cleared" {
		t.Fatalf("stages = %v, want [surface_called ghost_set ghost_cleared]", got)
	}
	if r := evs[2].Reason; r != "global_key" {
		t.Fatalf("ghost_cleared reason = %q, want global_key", r)
	}
}

// With the gate unarmed (the default), the same surface call and acceptance record nothing,
// so a normal session is byte-free of the trace.
func TestApp_DevDebug_OffRecordsNothing(t *testing.T) {
	a := New(nil)
	store := followupDebugStore(t)
	a.SetActiveStore(store)
	// Deliberately not armed via SetFollowupDebugContext.
	a.SuggestFollowup("write the tests", "Write unit tests for the parser")
	handler := a.input.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if evs := followupDebugEvents(t, store); len(evs) != 0 {
		t.Fatalf("recorded %d events with the gate off, want 0: %v", len(evs), followupStages(evs))
	}
}

// assertNoFollowupTextPersisted fails if any recorded event payload carries the suggestion
// label or prompt text, proving the trace persists only lengths.
func assertNoFollowupTextPersisted(t *testing.T, store *sessions.Store, label, prompt string) {
	t.Helper()
	for _, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok {
			continue
		}
		raw := string(ev.Payload)
		if strings.Contains(raw, label) || strings.Contains(raw, prompt) {
			t.Fatalf("event %s payload carries suggestion text: %s", ev.Kind, raw)
		}
	}
}
