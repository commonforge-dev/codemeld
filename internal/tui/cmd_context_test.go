// Tests for /context: the renderer shows a context-window usage summary — active
// provider/model, session token totals, the window size and percentage when known, an
// explicit unknown fallback when not, and an incomplete-counts notice on anomalous
// usage — never the system prompt, environment block, or advertised tools; the handler
// records the slash_command event, flushes, and opens the panel; the production
// registry wires /context to NewContextHandler; and /help describes the new behavior.
package tui

import (
	"encoding/json"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// fakeContextState is a recording ContextState returning canned in-memory state, so
// the renderer and handler are exercised without bootstrap wiring.
type fakeContextState struct {
	provider string
	modelID  string
	records  []sessions.Record
	window   int64
}

func (s fakeContextState) Selection() (string, string) { return s.provider, s.modelID }
func (s fakeContextState) Records() []sessions.Record  { return s.records }
func (s fakeContextState) ContextWindow() int64        { return s.window }

// modelRespRecord builds a model_response session record carrying the given token
// counts and optional anomaly, the same shape /status aggregates.
func modelRespRecord(t *testing.T, in, out int64, anomaly ...string) sessions.Record {
	t.Helper()
	b, err := json.Marshal(events.ModelResponse{InputTokens: in, OutputTokens: out, Anomaly: anomaly})
	if err != nil {
		t.Fatalf("marshal model_response: %v", err)
	}
	return sessions.Event{Kind: events.KindModelResponse, Payload: b}
}

// TestRenderContext_ShowsUsageSummary covers the known-window path: provider/model,
// input/output totals, the total, the window size, and the percentage used.
func TestRenderContext_ShowsUsageSummary(t *testing.T) {
	out := RenderContext(BuildContextSnapshot(fakeContextState{
		provider: "anthropic",
		modelID:  "claude-opus-4-8",
		window:   200000,
		records: []sessions.Record{
			modelRespRecord(t, 30000, 20000),
		},
	}))
	for _, want := range []string{
		"Provider: anthropic",
		"Model: claude-opus-4-8",
		"Token usage: 30000 input, 20000 output (50000 total)",
		"Context window: 200000 tokens",
		"Context used: 25% of window",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderContext output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestRenderContext_UnknownWindow pins the honest fallback: with no window source the
// panel says unknown and shows no percentage.
func TestRenderContext_UnknownWindow(t *testing.T) {
	out := RenderContext(BuildContextSnapshot(fakeContextState{
		provider: "anthropic",
		modelID:  "claude-opus-4-8",
		window:   0,
		records:  []sessions.Record{modelRespRecord(t, 100, 50)},
	}))
	if !strings.Contains(out, "Context window: unknown") {
		t.Errorf("unknown window did not render the unknown fallback\n--- output ---\n%s", out)
	}
	if strings.Contains(out, "%") {
		t.Errorf("unknown window rendered a percentage\n--- output ---\n%s", out)
	}
}

// TestRenderContext_IncompleteCounts pins that an anomaly-bearing model_response
// surfaces the incomplete-counts notice while still showing the available totals.
func TestRenderContext_IncompleteCounts(t *testing.T) {
	out := RenderContext(BuildContextSnapshot(fakeContextState{
		provider: "anthropic",
		modelID:  "claude-opus-4-8",
		records: []sessions.Record{
			modelRespRecord(t, 100, 50),
			modelRespRecord(t, 40, 10, "usage_missing"),
		},
	}))
	if !strings.Contains(out, "Token counts: incomplete (some turns did not report usage)") {
		t.Errorf("anomaly did not surface the incomplete-counts notice\n--- output ---\n%s", out)
	}
	// Available totals are still shown (100+40 input, 50+10 output).
	if !strings.Contains(out, "Token usage: 140 input, 60 output (200 total)") {
		t.Errorf("incomplete counts did not still show available totals\n--- output ---\n%s", out)
	}
}

func cachedRespRecord(t *testing.T, in, out, cached int64, partial bool) sessions.Record {
	t.Helper()
	b, err := json.Marshal(events.ModelResponse{
		InputTokens:              in,
		OutputTokens:             out,
		CachedInputTokens:        &cached,
		CachedInputTokensPartial: partial,
	})
	if err != nil {
		t.Fatalf("marshal model_response: %v", err)
	}
	return sessions.Event{Kind: events.KindModelResponse, Payload: b}
}

func TestRenderContext_ExactCachedUsage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []sessions.Record
		want    string
	}{
		{
			name: "summed",
			records: []sessions.Record{
				cachedRespRecord(t, 100, 50, 80, false),
				cachedRespRecord(t, 40, 10, 16, false),
			},
			want: "Token usage: 140 input (96 cached), 60 output (200 total)",
		},
		{
			name:    "reported-zero",
			records: []sessions.Record{cachedRespRecord(t, 100, 50, 0, false)},
			want:    "Token usage: 100 input (0 cached), 50 output (150 total)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderContext(BuildContextSnapshot(fakeContextState{provider: "openai", modelID: "gpt-5", records: tc.records}))
			if !strings.Contains(out, tc.want) {
				t.Errorf("RenderContext output missing %q\n--- output ---\n%s", tc.want, out)
			}
			if strings.Contains(out, "at least") || strings.Contains(out, "Cached-token usage is incomplete") {
				t.Errorf("a fully reported total rendered as a lower bound\n--- output ---\n%s", out)
			}
		})
	}
}

func TestRenderContext_PartialCachedUsage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []sessions.Record
	}{
		{
			name: "record-marked-partial",
			records: []sessions.Record{
				cachedRespRecord(t, 100, 50, 80, true),
				cachedRespRecord(t, 40, 10, 16, false),
			},
		},
		{
			name: "another-record-omits-the-count",
			records: []sessions.Record{
				cachedRespRecord(t, 100, 50, 96, false),
				modelRespRecord(t, 40, 10),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderContext(BuildContextSnapshot(fakeContextState{provider: "openai", modelID: "gpt-5", records: tc.records}))
			if want := "Token usage: 140 input (at least 96 cached), 60 output (200 total)"; !strings.Contains(out, want) {
				t.Errorf("RenderContext output missing %q\n--- output ---\n%s", want, out)
			}
			if want := "Cached-token usage is incomplete because some responses did not report it."; !strings.Contains(out, want) {
				t.Errorf("lower-bound cached usage carried no explanation\n--- output ---\n%s", out)
			}
		})
	}
}

func TestRenderContext_NeverReportedCachedUsage(t *testing.T) {
	out := RenderContext(BuildContextSnapshot(fakeContextState{
		provider: "openai",
		modelID:  "gpt-5",
		records: []sessions.Record{
			modelRespRecord(t, 100, 50),
			modelRespRecord(t, 40, 10, "usage_missing"),
		},
	}))
	if want := "Token usage: 140 input, 60 output (200 total)"; !strings.Contains(out, want) {
		t.Errorf("RenderContext output missing %q\n--- output ---\n%s", want, out)
	}
	if strings.Contains(out, "cached") || strings.Contains(out, "Cached") {
		t.Errorf("/context mentioned cached usage with nothing reported\n--- output ---\n%s", out)
	}
	if !strings.Contains(out, "Token counts: incomplete (some turns did not report usage)") {
		t.Errorf("the usage_missing notice was lost\n--- output ---\n%s", out)
	}
}

// TestRenderContext_DoesNotDumpSystemPrompt pins the /context privacy contract: the
// summary never carries the old system message, environment block, or advertised-tool
// sections.
func TestRenderContext_DoesNotDumpSystemPrompt(t *testing.T) {
	out := RenderContext(BuildContextSnapshot(fakeContextState{provider: "anthropic", modelID: "m", window: 1000}))
	for _, forbidden := range []string{"System message", "Environment block", "Advertised tools", "Mode:"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("/context leaked the old inspection section %q\n--- output ---\n%s", forbidden, out)
		}
	}
}

// TestBuildRegistry_ContextDispatchesToHandler pins the production wiring:
// /context goes through NewContextHandler — not recordHandler — so a single
// slash_command success event is appended, the record is flushed, and
// the panel opens via ShowPanel carrying the rendered snapshot.
func TestBuildRegistry_ContextDispatchesToHandler(t *testing.T) {
	host := newFakeHost()
	state := fakeContextState{
		provider: "anthropic",
		modelID:  "claude-opus-4-8",
		window:   200000,
		records:  []sessions.Record{modelRespRecord(t, 30000, 20000)},
	}
	// Only /context is bound to its real handler; every other command keeps the
	// recordHandler placeholder, so a passing dispatch proves /context is wired.
	reg := BuildRegistry(map[string]HandlerFunc{"context": NewContextHandler(state)})

	res := reg.DispatchSlashInput("/context", host)
	if res.Status != StatusHandled || res.Canonical != "context" || res.Err != nil {
		t.Fatalf("dispatch /context = %+v, want Handled/context/nil-err", res)
	}

	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "context" || p.Outcome != "success" || len(p.Args) != 0 {
		t.Errorf("event = %+v, want name=context args=[] outcome=success", p)
	}

	if host.flushes != 1 {
		t.Errorf("FlushActive called %d times, want 1 (req 400(e) command-event flush)", host.flushes)
	}
	if len(host.panels) != 1 {
		t.Fatalf("ShowPanel called %d times via the production registry, want 1 (recordHandler would call 0)", len(host.panels))
	}
	if len(host.statuses) != 0 {
		t.Errorf("ShowStatus called %d times, want 0 (/context uses the modal panel)", len(host.statuses))
	}
	want := RenderContext(BuildContextSnapshot(state))
	if host.panels[0] != want {
		t.Errorf("panel text = %q, want the rendered snapshot %q", host.panels[0], want)
	}
}

// TestContextHelpCopy pins that /help describes /context as context-window usage, not
// the old exact-provider-request inspection.
func TestContextHelpCopy(t *testing.T) {
	out := RenderHelp(BuildRegistry(nil))
	if !strings.Contains(out, "/context — Show context-window usage: session tokens used vs. the model's window") {
		t.Errorf("/help does not describe /context as context-window usage\n--- output ---\n%s", out)
	}
	if strings.Contains(out, "exact context sent to the model") {
		t.Errorf("/help still carries the old /context inspection wording\n--- output ---\n%s", out)
	}
}
