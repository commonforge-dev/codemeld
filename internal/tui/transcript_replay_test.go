package tui

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
)

func TestReplaySessionRecords_RendersVisibleAndSkipsHidden(t *testing.T) {
	records := []sessions.Record{
		userMsg("first question"),
		assistantMsg("first answer"),
		sessions.Message{Role: "system", Content: sessions.TextContent("you are a system prompt")},
		sessions.Message{Role: "tool", Content: sessions.TextContent("tool output"), ToolCallID: "0190tool"},
		sessions.Event{Kind: "launch_began"},
		sessions.Message{Role: "assistant", Content: sessions.TextContent("  "), ToolCalls: []sessions.ToolCall{{ID: "c1", Type: "function"}}},
		// Content-part-list user message with no plain-text projection: skipped.
		sessions.Message{Role: "user", Content: sessions.PartsContent([]sessions.ContentPart{{Type: "image"}})},
		userMsg("second question"),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "▌ first question\n\nfirst answer" + visibleResponseLine + "\n\n▌ second question"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

// TestReplaySessionRecords_PreservesOrder proves the replayed blocks keep the records'
// arrival order even when user and assistant turns interleave.
func TestReplaySessionRecords_PreservesOrder(t *testing.T) {
	records := []sessions.Record{
		userMsg("u1"),
		assistantMsg("a1"),
		userMsg("u2"),
		assistantMsg("a2"),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "▌ u1\n\na1" + visibleResponseLine + "\n\n▌ u2\n\na2" + visibleResponseLine
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

// TestReplaySessionRecords_BoundsLargeSession proves a session with more displayable
// blocks than maxReplayBlocks keeps only the most recent maxReplayBlocks blocks and
// inserts a single omission marker naming how many older blocks were dropped, so a huge
// history neither blows up the pane nor silently hides the truncation.
func TestReplaySessionRecords_BoundsLargeSession(t *testing.T) {
	const extra = 3
	records := make([]sessions.Record, 0, maxReplayBlocks+extra)
	for i := 0; i < maxReplayBlocks+extra; i++ {
		records = append(records, userMsg(fmt.Sprintf("msg%d", i)))
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	blocks := strings.Split(a.TranscriptText(), "\n\n")
	if len(blocks) != maxReplayBlocks+1 {
		t.Fatalf("rendered %d blocks, want %d (marker + %d kept)", len(blocks), maxReplayBlocks+1, maxReplayBlocks)
	}
	if want := replayOmissionMarker(extra); blocks[0] != want {
		t.Errorf("first block = %q, want omission marker %q", blocks[0], want)
	}
	// The oldest `extra` blocks are dropped, so the first kept block is msg<extra>.
	if want := "▌ " + fmt.Sprintf("msg%d", extra); blocks[1] != want {
		t.Errorf("first kept block = %q, want %q", blocks[1], want)
	}
	// The newest block is always retained.
	if want := "▌ " + fmt.Sprintf("msg%d", maxReplayBlocks+extra-1); blocks[len(blocks)-1] != want {
		t.Errorf("last block = %q, want newest %q", blocks[len(blocks)-1], want)
	}
}

// TestReplaySessionRecords_EmptyHistoryLeavesPaneEmpty proves replaying a session with
// no displayable records (only events) appends nothing, so a fresh-but-resumed session
// does not gain a stray block or omission marker.
func TestReplaySessionRecords_EmptyHistoryLeavesPaneEmpty(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{sessions.Event{Kind: "launch_began"}})

	if got := a.TranscriptText(); got != "" {
		t.Fatalf("replayed transcript = %q, want empty", got)
	}
}

// TestReplaySessionRecords_RendersImagePlaceholder proves a resumed content-part user
// message replays the same block the live submit echo shows: the text part as "> text"
// and each image_url part as an "[image: name (size)]" placeholder (name from the
// persisted part, size derived from the data URI), including the image-only case.
func TestReplaySessionRecords_RendersImagePlaceholder(t *testing.T) {
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, 1024))
	records := []sessions.Record{
		userMsg("before"),
		sessions.Message{Role: "user", Content: sessions.PartsContent([]sessions.ContentPart{
			{Type: "text", Raw: []byte(`{"type":"text","text":"explain this"}`)},
			imageURLContentPart(uri, "diagram.png"),
		})},
		sessions.Message{Role: "user", Content: sessions.PartsContent([]sessions.ContentPart{
			imageURLContentPart(uri, "solo.png"),
		})},
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "▌ before\n\n▌ explain this\n▌ [image: diagram.png (1 KB)]\n\n▌ [image: solo.png (1 KB)]"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

// TestReplaySessionRecords_ClipboardImageNameIsImageN proves a persisted clipboard image —
// whose codemeld-private "name" is the "Image N" the input field assigned — replays as
// "[image: Image N (size)]", not "clipboard.png", with no transcript-renderer change.
func TestReplaySessionRecords_ClipboardImageNameIsImageN(t *testing.T) {
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, 1024))
	records := []sessions.Record{
		sessions.Message{Role: "user", Content: sessions.PartsContent([]sessions.ContentPart{
			imageURLContentPart(uri, "Image 1"),
		})},
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	if got, want := a.TranscriptText(), "▌ [image: Image 1 (1 KB)]"; got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

// TestUserBlock_MultiLineRailLiveAndReplay pins the user rail on a multi-line user
// message: every line of the block carries the teal "▌ " rail (a continuous rail), and the
// live submit echo and the /resume plain-text replay render it identically through the
// shared userBlockLines renderer. The raw form keeps the live rail color tags; the visible
// (tag-stripped) form shows "▌ " on each line.
func TestUserBlock_MultiLineRailLiveAndReplay(t *testing.T) {
	const msg = "line one\nline two\nline three"
	const wantVisible = "▌ line one\n▌ line two\n▌ line three"
	const wantRaw = "[#1f9e8f]▌[-] line one\n[#1f9e8f]▌[-] line two\n[#1f9e8f]▌[-] line three"

	// Live echo path.
	live := New(func(string, ...sessions.ContentPart) bool { return true })
	live.input.SetText(msg)
	if !live.submitCurrent() {
		t.Fatal("submitCurrent rejected a multi-line submission")
	}
	if got := live.transcript.view.GetText(false); got != wantRaw {
		t.Fatalf("live multi-line echo raw = %q, want %q", got, wantRaw)
	}
	if got := live.TranscriptText(); got != wantVisible {
		t.Fatalf("live multi-line echo visible = %q, want %q", got, wantVisible)
	}

	// /resume plain-text replay path must match the live echo exactly.
	replay := New(nil)
	replay.ReplaySessionRecords([]sessions.Record{userMsg(msg)})
	if got := replay.TranscriptText(); got != wantVisible {
		t.Fatalf("replayed multi-line user block visible = %q, want %q (must match the live echo)", got, wantVisible)
	}
}

// TestReplaySessionRecords_RendersAssistantCompletionFooter proves a resumed successful
// turn replays the "provider - model - duration" footer directly after its assistant
// reply, reconstructed by pairing the turn's model_turn and final turn_latency.
func TestReplaySessionRecords_RendersAssistantCompletionFooter(t *testing.T) {
	records := []sessions.Record{
		userMsg("q"),
		modelTurnEvent("openai", "gpt-x"),
		assistantMsg("the answer"),
		turnLatencyEvent("openai", "gpt-x", 1000),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "▌ q\n\nthe answer" + visibleResponseLine + "\n\nopenai - gpt-x - 1s - " + footerClock()
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

// TestReplaySessionRecords_PairsCompletionFootersPerTurn proves two successful turns with
// different provider/model/duration payloads each attach their own footer to their own
// reply, so the pairing state resets per turn.
func TestReplaySessionRecords_PairsCompletionFootersPerTurn(t *testing.T) {
	records := []sessions.Record{
		userMsg("q1"), modelTurnEvent("openai", "gpt-x"), assistantMsg("a1"), turnLatencyEvent("openai", "gpt-x", 1000),
		userMsg("q2"), modelTurnEvent("anthropic", "claude"), assistantMsg("a2"), turnLatencyEvent("anthropic", "claude", 65000),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "▌ q1\n\na1" + visibleResponseLine + "\n\nopenai - gpt-x - 1s - " + footerClock() + "\n\n▌ q2\n\na2" + visibleResponseLine + "\n\nanthropic - claude - 1m 5s - " + footerClock()
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

func TestCompletionFooter_CompletionTimeUsesLocalZoneAtRender(t *testing.T) {
	records := []sessions.Record{
		modelTurnEvent("openai", "gpt-x"),
		assistantMsg("the answer"),
		turnLatencyEvent("openai", "gpt-x", 1000),
	}

	orig := time.Local
	time.Local = time.FixedZone("UTC+05:30", 5*3600+30*60)
	defer func() { time.Local = orig }()

	live := New(nil)
	live.AppendStreamDelta("the answer")
	live.FinalizeStream()
	live.AppendCompletionFooter(records)
	want := "the answer" + visibleResponseLine + "\n\nopenai - gpt-x - 1s - 19:37"
	if got := live.TranscriptText(); got != want {
		t.Fatalf("live transcript = %q, want %q", got, want)
	}

	replay := New(nil)
	replay.ReplaySessionRecords(records)
	if got := replay.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want the live transcript %q", got, want)
	}

	time.Local = time.FixedZone("UTC-03:00", -3*3600)
	later := New(nil)
	later.ReplaySessionRecords(records)
	if got, want := later.TranscriptText(), "the answer"+visibleResponseLine+"\n\nopenai - gpt-x - 1s - 11:07"; got != want {
		t.Fatalf("replayed transcript after zone change = %q, want %q", got, want)
	}
}

// TestReplaySessionRecords_SkipsCompletionFooterWithoutSuccessfulVisibleReply proves a
// footer is reconstructed only for a completed turn that carried both durable timing
// records and a visible assistant reply: a missing model_turn, a missing turn_latency, or
// a blank/tool-call-only assistant turn renders the reply (when any) but no footer.
func TestReplaySessionRecords_SkipsCompletionFooterWithoutSuccessfulVisibleReply(t *testing.T) {
	cases := []struct {
		name    string
		records []sessions.Record
		want    string
	}{
		{
			name:    "missing model_turn",
			records: []sessions.Record{userMsg("q"), assistantMsg("answer"), turnLatencyEvent("openai", "gpt-x", 1000)},
			want:    "▌ q\n\nanswer" + visibleResponseLine,
		},
		{
			name:    "missing turn_latency",
			records: []sessions.Record{userMsg("q"), modelTurnEvent("openai", "gpt-x"), assistantMsg("answer")},
			want:    "▌ q\n\nanswer" + visibleResponseLine,
		},
		{
			name: "blank assistant reply",
			records: []sessions.Record{
				modelTurnEvent("openai", "gpt-x"),
				sessions.Message{Role: "assistant", Content: sessions.TextContent("  ")},
				turnLatencyEvent("openai", "gpt-x", 1000),
			},
			want: "",
		},
		{
			name: "tool-call-only assistant reply",
			records: []sessions.Record{
				modelTurnEvent("openai", "gpt-x"),
				sessions.Message{Role: "assistant", Content: sessions.TextContent("  "), ToolCalls: []sessions.ToolCall{{ID: "c1", Type: "function"}}},
				turnLatencyEvent("openai", "gpt-x", 1000),
			},
			want: "",
		},
		{
			name: "malformed timing payload",
			records: []sessions.Record{
				userMsg("q"),
				modelTurnEvent("openai", "gpt-x"),
				assistantMsg("answer"),
				sessions.Event{Kind: events.KindTurnLatency, Payload: json.RawMessage("{")},
			},
			want: "▌ q\n\nanswer" + visibleResponseLine,
		},
		{
			// A structurally valid turn_latency object missing duration_ms decodes to a
			// zero duration; it must be treated as absent, not render a bogus "0s" footer.
			name: "turn_latency missing duration_ms",
			records: []sessions.Record{
				userMsg("q"),
				modelTurnEvent("openai", "gpt-x"),
				assistantMsg("answer"),
				rawEvent(events.KindTurnLatency, `{"provider":"openai","model_id":"gpt-x"}`),
			},
			want: "▌ q\n\nanswer" + visibleResponseLine,
		},
		{
			// A malformed new-turn model_turn must close the previous turn's window, so the
			// following reply cannot inherit turn 1's provider/model when a later valid
			// turn_latency arrives — the second reply gets no footer.
			name: "malformed model_turn does not inherit prior turn metadata",
			records: []sessions.Record{
				userMsg("q1"), modelTurnEvent("openai", "gpt-x"), assistantMsg("a1"), turnLatencyEvent("openai", "gpt-x", 1000),
				userMsg("q2"), rawEvent(events.KindModelTurn, `{"provider":""}`), assistantMsg("a2"), turnLatencyEvent("openai", "gpt-x", 1000),
			},
			want: "▌ q1\n\na1" + visibleResponseLine + "\n\nopenai - gpt-x - 1s - " + footerClock() + "\n\n▌ q2\n\na2" + visibleResponseLine,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords(tc.records)
			if got := a.TranscriptText(); got != tc.want {
				t.Fatalf("replayed transcript = %q, want %q (no footer)", got, tc.want)
			}
		})
	}
}

const longUserPrompt = "summarize the top 500. findings for the period as a numbered list with a short note per item"

func copyTranscriptAtWidth(t *testing.T, a *App, width int) string {
	t.Helper()
	text := a.TranscriptText()
	rows := transcriptRows(a.transcript.view.GetText(false), text, width)
	drawPrimitive(t, a.transcript.view, width, len(rows))
	a.transcript.beginSelect(0, 0)
	a.transcript.updateSelect(width, len(rows)-1)
	return a.transcript.endSelect()
}

func TestUserBlock_ReflowPreservesTranscriptAndCopy(t *testing.T) {
	for _, text := range []string{
		longUserPrompt,
		strings.Repeat("a", 100),
		"alpha\n" + longUserPrompt + "\nomega",
		"aaaaaaaa[red]bbbbbbbbbbbbbbbbbbbb",
	} {
		t.Run(text, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords([]sessions.Record{userMsg(text)})
			want := a.TranscriptText()
			if got := copyTranscriptAtWidth(t, a, 80); got != want {
				t.Fatalf("copied text before reflow = %q, want %q", got, want)
			}
			for _, width := range []int{24, 40, 24} {
				a.transcript.wrappedLineCount(width)
				if got := a.TranscriptText(); got != want {
					t.Fatalf("transcript after width %d = %q, want unchanged %q", width, got, want)
				}
				if got := copyTranscriptAtWidth(t, a, width); got != want {
					t.Fatalf("copied text after width %d = %q, want unchanged %q", width, got, want)
				}
			}
		})
	}
}

func TestUserBlock_ReflowPreservesImagePlaceholder(t *testing.T) {
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, 1024))
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{sessions.Message{Role: "user", Content: sessions.PartsContent([]sessions.ContentPart{
		{Type: "text", Raw: []byte(`{"type":"text","text":"explain this"}`)},
		imageURLContentPart(uri, "a-rather-long-diagram-name.png"),
	})}})
	want := a.TranscriptText()
	for _, width := range []int{24, 40, 24} {
		a.transcript.wrappedLineCount(width)
		if got := a.TranscriptText(); got != want {
			t.Fatalf("transcript after width %d = %q, want unchanged %q", width, got, want)
		}
		if got := copyTranscriptAtWidth(t, a, width); got != want {
			t.Fatalf("copied text after width %d = %q, want unchanged %q", width, got, want)
		}
	}
}

func TestUserBlock_ReflowSharedByLiveQueuedAndReplay(t *testing.T) {
	accept := func(string, ...sessions.ContentPart) bool { return true }
	live := New(accept)
	live.input.SetText(longUserPrompt)
	if !live.submitCurrent() {
		t.Fatal("submitCurrent rejected the long submission")
	}
	queued := New(accept)
	queued.EnqueuePrompt(longUserPrompt)
	queued.turnEnded(turnOutcomeCompleted)
	replay := New(nil)
	replay.ReplaySessionRecords([]sessions.Record{userMsg(longUserPrompt)})

	for _, tc := range []struct {
		name string
		a    *App
	}{{"live", live}, {"queued", queued}, {"replay", replay}} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.a.TranscriptText()
			for _, width := range []int{30, 18, 46} {
				tc.a.transcript.wrappedLineCount(width)
				if got := tc.a.TranscriptText(); got != want {
					t.Fatalf("transcript after width %d = %q, want %q", width, got, want)
				}
			}
		})
	}
}

func TestReplaySessionRecords_RendersFencedBlockBoundary(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		userMsg("how do I build it?"),
		assistantMsg("run this:\n\n```sh\ncd /tmp\nmake build\n```\n\nthen check it"),
		assistantMsg("```\n```"),
	})

	raw := a.transcript.view.GetText(false)
	for _, line := range []string{"cd /tmp", "make build"} {
		if !strings.Contains(raw, codeBlockTag+line+defaultTag) {
			t.Fatalf("replayed transcript raw = %q, want the block line %q painted with %s", raw, line, codeBlockTag)
		}
	}
	if !strings.Contains(raw, codeBlockTag+codeBlockBlankLine+defaultTag) {
		t.Fatalf("replayed transcript raw = %q, want the empty block replayed as a bounded blank line", raw)
	}
	if strings.Contains(raw, "```") {
		t.Fatalf("replayed transcript raw = %q, want the fences rendered, not replayed literally", raw)
	}

	want := "▌ how do I build it?\n\nrun this:\n\ncd /tmp\nmake build" + visibleCopyLine + "\n\nthen check it" + visibleResponseLine + "\n\n" + codeBlockBlankLine + visibleCopyLine + visibleResponseLine
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

// TestReplaySessionRecords_FencedBlockControlCopiesOriginalBody proves a replayed reply
// carries the same click payload the live one did: the body comes from the durable
// message, not from the display cells the pane redrew it into.
func TestReplaySessionRecords_FencedBlockControlCopiesOriginalBody(t *testing.T) {
	const body = "make build\nmake test"
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		userMsg("how do I build it?"),
		assistantMsg("run this:\n\n```sh\n" + body + "\n```"),
	})

	const response = "run this:\n\nmake build\nmake test"
	hits := transcriptCopyHits(t, a, 40, 10, map[string]string{
		body + "\n": codeCopyNotice,
		response:    responseCopyNotice,
	})
	if got := hits[body+"\n"]; got != statusCopyControl {
		t.Errorf("the cells that copy the replayed block spell %q, want exactly %q", got, statusCopyControl)
	}
	if got := hits[response]; got != responseCopyControl {
		t.Errorf("the cells that copy the replayed response spell %q, want exactly %q", got, responseCopyControl)
	}
}

func TestReplaySessionRecords_CodeOnlyReplyShowsOnlyBlockControl(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		userMsg("how do I build it?"),
		assistantMsg("```sh\nmake build\n```"),
	})

	if got, want := a.TranscriptText(), "▌ how do I build it?\n\nmake build"+visibleCopyLine; got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
	hits := transcriptCopyHits(t, a, 40, 10, map[string]string{
		"make build\n": codeCopyNotice,
	})
	if got := hits["make build\n"]; got != statusCopyControl {
		t.Errorf("the cells that copy the replayed block spell %q, want exactly %q", got, statusCopyControl)
	}
}

func TestReplaySessionRecords_WhitespaceBlockKeepsResponseControl(t *testing.T) {
	for _, src := range []string{"```\n   \n```", "```\nline\n  \n```"} {
		a := New(nil)
		a.ReplaySessionRecords([]sessions.Record{userMsg("q"), assistantMsg(src)})

		_, _, payload := renderMarkdown(src)
		controls := a.transcript.codeControls[len(a.transcript.codeControls)-1]
		if len(controls) != 2 || !controls[1].response || controls[1].body != payload {
			t.Fatalf("%q: controls = %+v, want the block control and a response control carrying %q", src, controls, payload)
		}
	}
}

// TestReplaySessionRecords_NonFencedBlocksArmNothing proves replay adds a payload only
// where a fenced block was: echoes, tool activity, and plain prose stay inert.
func TestReplaySessionRecords_NonFencedBlocksArmNothing(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		userMsg("what is this?"),
		assistantMsg("plain prose with an `inline` span and an indented block:\n\n    indented\n"),
	})

	if regions := codeRegions(a.transcript.controls.all); len(regions) != 0 {
		t.Fatalf("click regions = %+v, want none for a reply with no fenced block", regions)
	}
	if regions := responseRegions(a.transcript.controls.all); len(regions) != 1 {
		t.Fatalf("response regions = %+v, want exactly one for the single assistant reply", regions)
	}
}

// TestReplaySessionRecords_ResponseControlsOnlyOnAssistantReplies pins which replayed
// blocks arm a response control: only the visible assistant replies, never the user echo,
// the tool activity, the completion footer, or the omission marker.
func TestReplaySessionRecords_ResponseControlsOnlyOnAssistantReplies(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		userMsg("q"),
		modelTurnEvent("openai", "gpt-x"),
		assistantToolCallMsg("reading the docs", webToolCall("c1", "web_fetch", `{"url":"https://a.test"}`)),
		sessions.Message{Role: "tool", Content: sessions.TextContent("PAGE BODY"), ToolCallID: "c1"},
		assistantMsg("run this:\n\n```sh\nmake build\n```"),
		turnLatencyEvent("openai", "gpt-x", 1000),
	})

	var payloads []string
	for _, r := range responseRegions(a.transcript.controls.all) {
		payloads = append(payloads, r.payload)
	}
	want := []string{"reading the docs", "run this:\n\nmake build"}
	if !slices.Equal(payloads, want) {
		t.Fatalf("response payloads = %q, want one per assistant reply %q", payloads, want)
	}

	t.Run("the omission marker arms nothing", func(t *testing.T) {
		records := make([]sessions.Record, 0, maxReplayBlocks+2)
		for i := 0; i < maxReplayBlocks+2; i++ {
			records = append(records, userMsg("q"))
		}
		a := New(nil)
		a.ReplaySessionRecords(records)
		if got := a.transcript.controls.all; len(got) != 0 {
			t.Fatalf("click regions = %+v, want none across a bounded user-only history", got)
		}
	})
}

func TestReplaySessionRecords_ProjectsWebActivityAtRecordPosition(t *testing.T) {
	records := []sessions.Record{
		userMsg("research tview escaping"),
		assistantToolCallMsg("", webToolCall("c1", "web_search", `{"query":"tview escape tags"}`)),
		sessions.Message{Role: "tool", Content: sessions.TextContent("SEARCH RESULT BODY"), ToolCallID: "c1"},
		assistantToolCallMsg("now reading the docs", webToolCall("c2", "web_fetch", `{"url":"https://go.dev/doc/effective_go"}`)),
		sessions.Message{Role: "tool", Content: sessions.TextContent("FETCHED PAGE BODY"), ToolCallID: "c2"},
		assistantMsg("escape tags with tview.Escape"),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "▌ research tview escaping\n\nWebSearch tview escape tags\n\nnow reading the docs" + visibleResponseLine + "\n\n" +
		"WebFetch https://go.dev/doc/effective_go\n\nescape tags with tview.Escape" + visibleResponseLine
	got := a.TranscriptText()
	if got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
	for _, body := range []string{"SEARCH RESULT BODY", "FETCHED PAGE BODY"} {
		if strings.Contains(got, body) {
			t.Fatalf("replayed transcript = %q, leaked tool-result body %q", got, body)
		}
	}
}

func TestReplaySessionRecords_RetainsOnlyWebCallsFromMixedRound(t *testing.T) {
	records := []sessions.Record{
		assistantToolCallMsg("",
			webToolCall("c1", "bash", `{"command":"go build ./..."}`),
			webToolCall("c2", "web_search", `{"query":"alpha"}`),
			webToolCall("c3", "read", `{"path":"server.go"}`),
			webToolCall("c4", "web_fetch", `{"url":"https://a.test"}`),
			webToolCall("c5", "vcs_commit", `{"message":"x"}`),
		),
		assistantToolCallMsg("", webToolCall("c6", "web_search", `{"query":"beta"}`)),
		assistantToolCallMsg("", webToolCall("c7", "edit", `{"path":"pkg/utils.go"}`)),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "WebSearch alpha\nWebFetch https://a.test\n\nWebSearch beta"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

func TestReplaySessionRecords_HandlesMalformedWebToolCallWrappers(t *testing.T) {
	cases := []struct {
		name string
		call sessions.ToolCall
		want string
	}{
		{"absent raw wrapper", sessions.ToolCall{ID: "c1", Type: "function"}, ""},
		{"malformed raw wrapper", rawToolCall("c1", `{`), ""},
		{"wrapper is not an object", rawToolCall("c1", `"web_search"`), ""},
		{"missing function object", rawToolCall("c1", `{"id":"c1","type":"function"}`), ""},
		{"empty function name", rawToolCall("c1", `{"function":{"name":"","arguments":"{}"}}`), ""},
		{"non-web function name", rawToolCall("c1", `{"function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}`), ""},
		{"web search missing arguments", rawToolCall("c1", `{"function":{"name":"web_search"}}`), "web_search"},
		{"web search malformed arguments", rawToolCall("c1", `{"function":{"name":"web_search","arguments":"{not json"}}`), "web_search"},
		{"web fetch object arguments", rawToolCall("c1", `{"function":{"name":"web_fetch","arguments":{"url":"https://a.test"}}}`), "web_fetch"},
		{"web fetch numeric arguments", rawToolCall("c1", `{"function":{"name":"web_fetch","arguments":7}}`), "web_fetch"},
		{"web fetch empty url", rawToolCall("c1", `{"function":{"name":"web_fetch","arguments":"{\"url\":\"\"}"}}`), "web_fetch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords([]sessions.Record{
				userMsg("q"),
				assistantToolCallMsg("", tc.call),
				assistantMsg("answer"),
			})

			want := "▌ q\n\nanswer" + visibleResponseLine
			if tc.want != "" {
				want = "▌ q\n\n" + tc.want + "\n\nanswer" + visibleResponseLine
			}
			if got := a.TranscriptText(); got != want {
				t.Fatalf("replayed transcript = %q, want %q", got, want)
			}
		})
	}
}

func TestReplaySessionRecords_MalformedCallDoesNotDropTheRound(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		assistantToolCallMsg("",
			rawToolCall("c1", `{`),
			webToolCall("c2", "web_search", `{"query":"still shown"}`),
			rawToolCall("c3", `{"function":{"name":"web_fetch","arguments":9}}`),
		),
		assistantMsg("answer"),
	})

	want := "WebSearch still shown\nweb_fetch\n\nanswer" + visibleResponseLine
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q", got, want)
	}
}

func TestReplaySessionRecords_WebActivityRendersLiterally(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		assistantToolCallMsg("",
			webToolCall("c1", "web_search", `{"query":"[red]tview tag[-] syntax"}`),
			webToolCall("c2", "web_fetch", `{"url":"https://a.test/p?q=[b]#[c]"}`),
		),
	})

	want := "WebSearch [red]tview tag[-] syntax\nWebFetch https://a.test/p?q=[b]#[c]"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want %q (tag syntax must stay literal)", got, want)
	}
	if raw := a.transcript.view.GetText(false); !strings.Contains(raw, "[red[]") {
		t.Fatalf("replayed transcript raw = %q, want the escaped bracket guard", raw)
	}
}

func TestReplaySessionRecords_WebActivityLeavesFooterPairingUnchanged(t *testing.T) {
	cases := []struct {
		name    string
		records []sessions.Record
		want    string
	}{
		{
			name: "tool-call-only turn with web activity gets no footer",
			records: []sessions.Record{
				modelTurnEvent("openai", "gpt-x"),
				assistantToolCallMsg("", webToolCall("c1", "web_search", `{"query":"gopher"}`)),
				turnLatencyEvent("openai", "gpt-x", 1000),
			},
			want: "WebSearch gopher",
		},
		{
			name: "completed research turn footers only its visible reply",
			records: []sessions.Record{
				userMsg("q"),
				modelTurnEvent("openai", "gpt-x"),
				assistantToolCallMsg("", webToolCall("c1", "web_fetch", `{"url":"https://a.test"}`)),
				sessions.Message{Role: "tool", Content: sessions.TextContent("PAGE BODY"), ToolCallID: "c1"},
				assistantMsg("the answer"),
				turnLatencyEvent("openai", "gpt-x", 1000),
			},
			want: "▌ q\n\nWebFetch https://a.test\n\nthe answer" + visibleResponseLine + "\n\nopenai - gpt-x - 1s - " + footerClock(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords(tc.records)
			if got := a.TranscriptText(); got != tc.want {
				t.Fatalf("replayed transcript = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReplaySessionRecords_BoundsWebActivityBlocks(t *testing.T) {
	const extra = 4
	rounds := (maxReplayBlocks + extra) / 2
	records := make([]sessions.Record, 0, rounds*2)
	for i := 0; i < rounds; i++ {
		records = append(records,
			userMsg(fmt.Sprintf("msg%d", i)),
			assistantToolCallMsg("", webToolCall("c", "web_search", fmt.Sprintf(`{"query":"q%d"}`, i))),
		)
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	blocks := strings.Split(a.TranscriptText(), "\n\n")
	if len(blocks) != maxReplayBlocks+1 {
		t.Fatalf("rendered %d blocks, want %d (marker + %d kept)", len(blocks), maxReplayBlocks+1, maxReplayBlocks)
	}
	if want := replayOmissionMarker(extra); blocks[0] != want {
		t.Errorf("first block = %q, want omission marker %q", blocks[0], want)
	}
	if want := fmt.Sprintf("▌ msg%d", extra/2); blocks[1] != want {
		t.Errorf("first kept block = %q, want %q", blocks[1], want)
	}
	if want := fmt.Sprintf("WebSearch q%d", rounds-1); blocks[len(blocks)-1] != want {
		t.Errorf("last block = %q, want the newest activity %q", blocks[len(blocks)-1], want)
	}
}

func userMsg(text string) sessions.Message {
	return sessions.Message{Role: "user", Content: sessions.TextContent(text)}
}

func assistantMsg(text string) sessions.Message {
	return sessions.Message{Role: "assistant", Content: sessions.TextContent(text)}
}

func assistantToolCallMsg(text string, calls ...sessions.ToolCall) sessions.Message {
	return sessions.Message{Role: "assistant", Content: sessions.TextContent(text), ToolCalls: calls}
}

func webToolCall(id, name, arguments string) sessions.ToolCall {
	raw, err := json.Marshal(struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}{ID: id, Type: "function", Function: struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}{Name: name, Arguments: arguments}})
	if err != nil {
		panic(err)
	}
	return sessions.ToolCall{ID: id, Type: "function", Raw: raw}
}

func rawToolCall(id, raw string) sessions.ToolCall {
	return sessions.ToolCall{ID: id, Type: "function", Raw: json.RawMessage(raw)}
}

// modelTurnEvent builds a model_turn event record carrying provider/model, the start-of-turn
// half of the completion-footer pairing.
func modelTurnEvent(provider, model string) sessions.Event {
	payload, _ := json.Marshal(events.ModelTurn{Provider: provider, ModelID: model, Effort: "default", Source: "picker"})
	return sessions.Event{Kind: events.KindModelTurn, Payload: payload}
}

var turnLatencyAt = time.Date(2026, 9, 25, 14, 7, 0, 0, time.UTC)

func footerClock() string {
	return turnLatencyAt.Local().Format("15:04")
}

// turnLatencyEvent builds a final turn_latency event record carrying the turn's
// duration_ms, the completing half of the footer pairing.
func turnLatencyEvent(provider, model string, ms int64) sessions.Event {
	payload, _ := json.Marshal(events.TurnLatency{Provider: provider, ModelID: model, DurationMs: ms})
	return sessions.Event{Kind: events.KindTurnLatency, Timestamp: turnLatencyAt, Payload: payload}
}

// rawEvent builds an event record with a hand-written payload, for exercising malformed
// or incomplete footer events the marshaling helpers above cannot produce.
func rawEvent(kind, payload string) sessions.Event {
	return sessions.Event{Kind: kind, Payload: json.RawMessage(payload)}
}

func askUserToolCall(id, arguments string) sessions.ToolCall {
	return webToolCall(id, provider.AskUserToolName, arguments)
}

func toolResultMsg(toolCallID, content string) sessions.Message {
	return sessions.Message{Role: "tool", Content: sessions.TextContent(content), ToolCallID: toolCallID}
}

const storagePrompt = "Where should sessions be stored?"

const askUserStorageArgs = `{"questions":[{"id":"storage","prompt":"` + storagePrompt + `","options":["Local disk","Object store"]}]}`

const askUserCustomArgs = `{"questions":[{"id":"name","prompt":"What should it be called?","options":["ask"],"allow_custom":true}]}`

const storageAnswer = `{"id":"storage","prompt":"` + storagePrompt + `","selected":["Object store"]}`

const askUserMultiArgs = `{"questions":[{"id":"pick","prompt":"Which stores?","options":["Local disk","Object store","Both"],"multi_select":true,"allow_custom":true}]}`

const askUserReplayArgs = `{"context":"Sessions are replayed on /resume.","questions":[` +
	`{"id":"storage","prompt":"Where should sessions be stored?","options":["Local disk","Object store"]},` +
	`{"id":"name","prompt":"What should it be called?","options":["ask"],"allow_custom":true}]}`

const askUserReplayResult = `{"answers":[` +
	`{"id":"storage","prompt":"Where should sessions be stored?","selected":["Object store"]},` +
	`{"id":"name","prompt":"What should it be called?","selected":[],"custom":"codemeld ask"}]}`

func TestReplaySessionRecords_RebuildsTheAnsweredQuestionRecord(t *testing.T) {
	records := []sessions.Record{
		userMsg("where should sessions live?"),
		assistantToolCallMsg("I need to know where sessions go.", askUserToolCall("c1", askUserReplayArgs)),
		toolResultMsg("c1", askUserReplayResult),
		assistantMsg("stored on the object store"),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "▌ where should sessions live?\n\n" +
		"I need to know where sessions go." + visibleResponseLine + "\n\n" +
		"Answered:\n" +
		"  Where should sessions be stored? — Object store\n" +
		"  What should it be called? — codemeld ask\n\n" +
		"stored on the object store" + visibleResponseLine
	got := a.TranscriptText()
	if got != want {
		t.Fatalf("replayed transcript =\n%q\nwant\n%q", got, want)
	}
	for _, leaked := range []string{provider.AskUserToolName, `{"answers"`, "c1", "storage"} {
		if strings.Contains(got, leaked) {
			t.Errorf("replayed transcript = %q, leaked the tool plumbing %q", got, leaked)
		}
	}
}

func TestReplaySessionRecords_RebuildsTheClarificationRecord(t *testing.T) {
	records := []sessions.Record{
		assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
		toolResultMsg("c1", `{"clarification":"what is an object store?"}`),
		assistantMsg("It is a remote blob service."),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "Asked for clarification:\n  what is an object store?\n\nIt is a remote blob service." + visibleResponseLine
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript =\n%q\nwant\n%q", got, want)
	}
}

func TestReplaySessionRecords_RendersNothingForAnUnpairableAskUserCall(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []sessions.Record
	}{
		{"no result at all", []sessions.Record{
			assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
		}},
		{"result names another call", []sessions.Record{
			assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
			toolResultMsg("c2", askUserReplayResult),
		}},
		{"two results claim the same id", []sessions.Record{
			assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
			toolResultMsg("c1", askUserReplayResult),
			toolResultMsg("c1", askUserReplayResult),
		}},
		{"the result sits in a later response group", []sessions.Record{
			assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
			assistantToolCallMsg("", webToolCall("c1", "bash", `{"command":"true"}`)),
			toolResultMsg("c1", askUserReplayResult),
		}},
		{"malformed result content", []sessions.Record{
			assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
			toolResultMsg("c1", "not json"),
		}},
		{"in-band argument refusal", []sessions.Record{
			assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
			toolResultMsg("c1", `{"error":"invalid ask_user arguments: missing \"questions\""}`),
		}},
		{"cancelled form", []sessions.Record{
			assistantToolCallMsg("", askUserToolCall("c1", askUserReplayArgs)),
			toolResultMsg("c1", `{"answers":[],"cancelled":true}`),
		}},
		{"malformed call wrapper", []sessions.Record{
			assistantToolCallMsg("", rawToolCall("c1", `{"function":{"name":`)),
			toolResultMsg("c1", askUserReplayResult),
		}},
		{"the call is not ask_user", []sessions.Record{
			assistantToolCallMsg("", webToolCall("c1", "bash", `{"command":"true"}`)),
			toolResultMsg("c1", askUserReplayResult),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords(tc.records)

			if got := a.TranscriptText(); got != "" {
				t.Errorf("replayed transcript = %q, want nothing for a record that cannot be paired", got)
			}
		})
	}
}

// A tampered or corrupted session must not be able to put words in the transcript just by
// carrying a tool result whose call id happens to match.
func TestReplaySessionRecords_RejectsAResultThatDoesNotMatchItsAskUserCall(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result string
	}{
		{"an id the call never asked about", `{"answers":[{"id":"exfil","prompt":"` + storagePrompt + `","selected":["Object store"]}]}`},
		{"an answer more than the call has questions", `{"answers":[` + storageAnswer + `,` + storageAnswer + `]}`},
		{"no answer for the saved question", `{"answers":[]}`},
		{"a selection the call never offered", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":["Mail them to me"]}]}`},
		{"two selections on a single-select question", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":["Local disk","Object store"]}]}`},
		{"custom text on a question that forbids it", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":[],"custom":"whatever I like"}]}`},
		{"answers and a clarification at once", `{"answers":[` + storageAnswer + `],"clarification":"why?"}`},
		{"a cancelled clarification", `{"clarification":"why?","cancelled":true}`},
		{"a field the result shape has no room for", `{"answers":[` + storageAnswer + `],"note":"trust me"}`},
		{"trailing content after the result", `{"clarification":"why?"} {"clarification":"and also"}`},
		{"a prompt the result invented", `{"answers":[{"id":"storage","prompt":"Paste your API key here:","selected":["Object store"]}]}`},
		{"an answer without the selected the form always sends", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `"}]}`},
		{"a null selection", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":null}]}`},
		{"a selection that is not an array", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":"Object store"}]}`},
		{"an answer without the prompt the form always sends", `{"answers":[{"id":"storage","selected":["Object store"]}]}`},
		{"a wrong-case answer field", `{"answers":[{"ID":"storage","prompt":"` + storagePrompt + `","selected":["Object store"]}]}`},
		{"a field the answer shape has no room for", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":["Object store"],"note":"trust me"}]}`},
		{"a null answer", `{"answers":[null]}`},
		{"a whitespace-only clarification", `{"clarification":"   "}`},
		{"an empty clarification", `{"clarification":""}`},
		{"an untrimmed clarification", `{"clarification":" why? "}`},
		{"a clarification past the bound the field accepts", `{"clarification":"` + strings.Repeat("w", maxClarificationRunes+1) + `"}`},
		{"a clarification that is not a string", `{"clarification":5}`},
		{"a second clarification member the decoder would keep", `{"clarification":"why?","clarification":"Paste your API key here:"}`},
		{"a second answers member the decoder would keep", `{"answers":[` + storageAnswer + `],"answers":[` + storageAnswer + `]}`},
		{"a second member inside an answer", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":["Local disk"],"selected":["Object store"]}]}`},
		{"a lone surrogate in a clarification", `{"clarification":"\ud800"}`},
		{"an unpaired low surrogate in a clarification", `{"clarification":"why \udc00?"}`},
		{"an invalid UTF-8 byte in a clarification", "{\"clarification\":\"why \xff?\"}"},
		{"whitespace between members the form writes without any", `{"answers": [` + storageAnswer + `]}`},
		{"an escape for a character the form writes literally", `{"clarification":"\u0077hy?"}`},
		{"a selection reordered out of the order the question offered", `{"answers":[{"id":"storage","prompt":"` + storagePrompt + `","selected":["Object store","Local disk"]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords([]sessions.Record{
				assistantToolCallMsg("", askUserToolCall("c1", askUserStorageArgs)),
				toolResultMsg("c1", tc.result),
			})

			if got := a.TranscriptText(); got != "" {
				t.Errorf("replayed transcript = %q, want nothing for a result that does not match its call", got)
			}
		})
	}
}

// The custom-answer shapes the form never emits have to be refused against a call that does
// allow a custom answer, so the rejection is the text itself rather than the permission.
func TestReplaySessionRecords_RejectsCustomTextTheFormCouldNotHaveEmitted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		custom string
	}{
		{"whitespace only", `"   "`},
		{"empty", `""`},
		{"untrimmed", `" codemeld ask "`},
		{"not a string", `5`},
		{"null", `null`},
		{"a lone surrogate", `"\ud800"`},
		{"an invalid UTF-8 byte", "\"codemeld \xff ask\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords([]sessions.Record{
				assistantToolCallMsg("", askUserToolCall("c1", askUserCustomArgs)),
				toolResultMsg("c1", `{"answers":[{"id":"name","prompt":"What should it be called?","selected":[],"custom":`+tc.custom+`}]}`),
			})

			if got := a.TranscriptText(); got != "" {
				t.Errorf("replayed transcript = %q, want nothing for custom text no form produced", got)
			}
		})
	}
}

// questionBlock.answer walks the offered options in order, and choosing an option or opening
// the custom field clears the other unless the question is multi-select. A persisted answer
// that breaks either rule is one no form wrote, however well it matches the saved question.
func TestReplaySessionRecords_RejectsAnswerStatesTheFormCannotReach(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   string
		answer string
	}{
		{
			"multi-select values out of the offered order",
			askUserMultiArgs,
			`{"id":"pick","prompt":"Which stores?","selected":["Object store","Local disk"]}`,
		},
		{
			"a multi-select value chosen twice",
			askUserMultiArgs,
			`{"id":"pick","prompt":"Which stores?","selected":["Both","Both"]}`,
		},
		{
			"a single-select option alongside custom text",
			askUserCustomArgs,
			`{"id":"name","prompt":"What should it be called?","selected":["ask"],"custom":"codemeld"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords([]sessions.Record{
				assistantToolCallMsg("", askUserToolCall("c1", tc.args)),
				toolResultMsg("c1", `{"answers":[`+tc.answer+`]}`),
			})

			if got := a.TranscriptText(); got != "" {
				t.Errorf("replayed transcript = %q, want nothing for an answer state the form cannot reach", got)
			}
		})
	}
}

// The mutual exclusion is the single-select rule only: a multi-select question keeps its custom
// field open beside the checked options, so refusing that pair would hide a real answer.
func TestReplaySessionRecords_RendersAMultiSelectAnswerWithCustomText(t *testing.T) {
	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		assistantToolCallMsg("", askUserToolCall("c1", askUserMultiArgs)),
		toolResultMsg("c1", `{"answers":[{"id":"pick","prompt":"Which stores?","selected":["Local disk","Both"],"custom":"and a cache"}]}`),
	})

	got := a.TranscriptText()
	for _, want := range []string{"Which stores?", "Local disk", "Both", "and a cache"} {
		if !strings.Contains(got, want) {
			t.Errorf("replayed transcript = %q, want it to contain %q", got, want)
		}
	}
}

// Session validation accepts two calls sharing one id as long as a single result answers it,
// so replay cannot treat a matching id as proof it knows which call the result belongs to.
func TestReplaySessionRecords_RejectsAnAmbiguousToolCallID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		calls []sessions.ToolCall
	}{
		{
			"two ask_user calls sharing one id",
			[]sessions.ToolCall{askUserToolCall("c1", askUserStorageArgs), askUserToolCall("c1", askUserStorageArgs)},
		},
		{
			"an ask_user call colliding with another tool",
			[]sessions.ToolCall{askUserToolCall("c1", askUserStorageArgs), webToolCall("c1", "web_search", `{"query":"anything"}`)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.ReplaySessionRecords([]sessions.Record{
				assistantToolCallMsg("", tc.calls...),
				toolResultMsg("c1", `{"answers":[`+storageAnswer+`]}`),
			})

			if got := a.TranscriptText(); strings.Contains(got, storagePrompt) {
				t.Errorf("replayed transcript = %q, want no question record for a result whose call id is ambiguous", got)
			}
		})
	}
}

// encoding/json repairs a lone surrogate into U+FFFD without reporting an error, so against a
// saved call whose own text carries U+FFFD the repaired id, prompt and selection all compare
// equal and a result no form emitted would otherwise render.
func TestReplaySessionRecords_RejectsMalformedUnicodeThatWouldBeRepairedIntoAMatch(t *testing.T) {
	args := `{"questions":[{"id":"store�","prompt":"Where�?","options":["Local� disk"]}]}`
	if _, err := provider.DecodeAskUserRequest(args); err != nil {
		t.Fatalf("DecodeAskUserRequest(%q) error = %v, want dispatch to accept text that carries U+FFFD as itself", args, err)
	}

	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		assistantToolCallMsg("", askUserToolCall("c1", args)),
		toolResultMsg("c1", `{"answers":[{"id":"store\ud800","prompt":"Where\ud800?","selected":["Local\ud800 disk"]}]}`),
	})

	if got := a.TranscriptText(); got != "" {
		t.Errorf("replayed transcript = %q, want nothing for a result whose text only matches once repaired", got)
	}
}

// Replay runs the saved call through the same provider checker production dispatch uses, so a
// call the live form would have refused renders nothing rather than drifting into acceptance.
func TestReplaySessionRecords_RejectsASavedCallDispatchWouldRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
	}{
		{"unknown question field", `{"questions":[{"id":"storage","prompt":"Where?","options":["Local disk"],"style":"grid"}]}`},
		{"unknown root field", `{"extra":true,"questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`},
		{"wrong-case questions", `{"Questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`},
		{"blank context", `{"context":"  ","questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`},
		{"context with a newline", `{"context":"why\nit matters","questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`},
		{"over-long context", `{"context":"` + strings.Repeat("x", provider.MaxAskUserContextRunes+1) + `","questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`},
		{"duplicate question id", `{"questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]},{"id":"storage","prompt":"Again?","options":["Object store"]}]}`},
		{"duplicate option", `{"questions":[{"id":"storage","prompt":"Where?","options":["Local disk","Local disk"]}]}`},
		{"blank prompt", `{"questions":[{"id":"storage","prompt":"","options":["Local disk"]}]}`},
		{"over-long prompt", `{"questions":[{"id":"storage","prompt":"` + strings.Repeat("x", provider.MaxAskUserTextRunes+1) + `","options":["Local disk"]}]}`},
		{"no options", `{"questions":[{"id":"storage","prompt":"Where?","options":[]}]}`},
		{"non-boolean flag", `{"questions":[{"id":"storage","prompt":"Where?","options":["Local disk"],"multi_select":"yes"}]}`},
		{"malformed Unicode prompt", `{"questions":[{"id":"storage","prompt":"\ud800","options":["Local disk"]}]}`},
		{"trailing content", askUserStorageArgs + ` {"extra":true}`},
		{"a repeated questions member", `{"questions":[],"questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`},
		{"a repeated context member", `{"context":"first","context":"second","questions":[{"id":"storage","prompt":"Where?","options":["Local disk"]}]}`},
		{"a repeated question member", `{"questions":[{"id":"storage","id":"exfil","prompt":"Where?","options":["Local disk"]}]}`},
		{"a repeated flag member", `{"questions":[{"id":"storage","prompt":"Where?","options":["Local disk"],"multi_select":false,"multi_select":true}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := provider.DecodeAskUserRequest(tc.args); err == nil {
				t.Fatalf("DecodeAskUserRequest(%q) error = nil, want dispatch to refuse this call", tc.args)
			}

			a := New(nil)
			a.ReplaySessionRecords([]sessions.Record{
				assistantToolCallMsg("", askUserToolCall("c1", tc.args)),
				toolResultMsg("c1", `{"answers":[{"id":"storage","prompt":"Where?","selected":["Local disk"]}]}`),
			})

			if got := a.TranscriptText(); got != "" {
				t.Errorf("replayed transcript = %q, want nothing for a call the live form would refuse", got)
			}
		})
	}
}

func TestReplaySessionRecords_PairsEachAskUserCallInsideItsOwnResponseGroup(t *testing.T) {
	records := []sessions.Record{
		assistantToolCallMsg("",
			webToolCall("c0", "web_search", `{"query":"object stores"}`),
			askUserToolCall("c1", askUserStorageArgs),
		),
		toolResultMsg("c0", "SEARCH RESULT BODY"),
		toolResultMsg("c1", `{"answers":[{"id":"storage","prompt":"`+storagePrompt+`","selected":["Local disk"]}]}`),
		assistantToolCallMsg("asking again", askUserToolCall("c1", askUserStorageArgs)),
		toolResultMsg("c1", `{"answers":[{"id":"storage","prompt":"`+storagePrompt+`","selected":["Object store"]}]}`),
	}

	a := New(nil)
	a.ReplaySessionRecords(records)

	want := "WebSearch object stores\n\n" +
		"Answered:\n  Where should sessions be stored? — Local disk\n\n" +
		"asking again" + visibleResponseLine + "\n\n" +
		"Answered:\n  Where should sessions be stored? — Object store"
	got := a.TranscriptText()
	if got != want {
		t.Fatalf("replayed transcript =\n%q\nwant\n%q", got, want)
	}
	if strings.Contains(got, "SEARCH RESULT BODY") {
		t.Errorf("replayed transcript = %q, leaked an unrelated tool result", got)
	}
}

func childStartEvent(start events.ChildAgentStart) sessions.Event {
	payload, _ := json.Marshal(start)
	return sessions.Event{Kind: events.KindChildAgentStart, Payload: payload}
}

func childEndEvent(end events.ChildAgentEnd) sessions.Event {
	payload, _ := json.Marshal(end)
	return sessions.Event{Kind: events.KindChildAgentEnd, Payload: payload}
}

// renderedBlocks puts raw block text through the transcript's own rendering path so an
// expected value built from childAgentBlockText compares against TranscriptText with the
// heading's style tags resolved the same way.
func renderedBlocks(blocks ...string) string {
	tr := newTranscript()
	for _, block := range blocks {
		tr.append(block)
	}
	return tr.text(true)
}

// A reloaded child block is byte-identical to the one the live path renders from the same
// lifecycle records, which is what makes the two paths one surface rather than two.
func TestReplaySessionRecords_ChildAgentBlockMatchesTheLivePath(t *testing.T) {
	start := childStart(childA, "/project/a.go", "/project/b.go")
	end := childEnd(childA, events.ChildAgentReasonCancelled, events.ChildRollbackRolledBack, "/project/a.go")

	live := New(nil)
	live.ChildAgentStarted(start)
	live.ChildAgentEnded(end)

	replayed := New(nil)
	replayed.ReplaySessionRecords([]sessions.Record{childStartEvent(start), childEndEvent(end)})

	if got, want := replayed.TranscriptText(), live.TranscriptText(); got != want {
		t.Fatalf("replayed block = %q, want the live block %q", got, want)
	}
	if len(replayed.transcript.lines) != 1 {
		t.Fatalf("replayed lines = %v, want one block for one lifecycle", replayed.transcript.lines)
	}
}

// Overlapping lifetimes in one record stream replay as two separate blocks, each closed by
// the end record naming its own invocation id.
func TestReplaySessionRecords_ChildAgentOverlappingLifetimes(t *testing.T) {
	startA := childStart(childA, "/project/a.go")
	startB := childStart(childB, "/project/b.go")
	endA := childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, "/project/a.go")
	endB := childEnd(childB, events.ChildAgentReasonFailed, events.ChildRollbackRolledBack, "/project/b.go")

	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		childStartEvent(startA),
		childStartEvent(startB),
		childEndEvent(endA),
		childEndEvent(endB),
	})

	want := renderedBlocks(
		childAgentBlockText(startA, nil, &endA, false),
		childAgentBlockText(startB, nil, &endB, false),
	)
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed overlapping children = %q, want %q", got, want)
	}
	if len(a.transcript.lines) != 2 {
		t.Fatalf("replayed lines = %v, want one block per child", a.transcript.lines)
	}
}

// A start whose end record never landed replays as a block that says no outcome was
// recorded — neither dropped nor left showing a child that is still running.
func TestReplaySessionRecords_ChildAgentUnclosedLifecycle(t *testing.T) {
	start := childStart(childA, "/project/a.go")

	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{childStartEvent(start), userMsg("next question")})

	want := childAgentUnclosedHeading + "\n  may write:\n    /project/a.go\n\n▌ next question"
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed unclosed lifecycle = %q, want %q", got, want)
	}
	if strings.Contains(a.TranscriptText(), childAgentRunningHeading) {
		t.Error("an unclosed lifecycle replayed as a running child")
	}
}

// A malformed payload, an end with no start, and a second end for a child already closed are
// each dropped: none may open a block or rewrite one that is already final.
func TestReplaySessionRecords_ChildAgentIgnoresUnusableRecords(t *testing.T) {
	start := childStart(childA, "/project/a.go")
	end := childEnd(childA, events.ChildAgentReasonCompleted, events.ChildRollbackNotNeeded, "/project/a.go")
	stray := childEnd(childB, events.ChildAgentReasonFailed, events.ChildRollbackRolledBack, "/project/b.go")
	reclose := childEnd(childA, events.ChildAgentReasonFailed, events.ChildRollbackUnrecovered, "/project/late.go")

	a := New(nil)
	a.ReplaySessionRecords([]sessions.Record{
		rawEvent(events.KindChildAgentStart, "{"),
		rawEvent(events.KindChildAgentStart, `{"invocation_id":""}`),
		childEndEvent(stray),
		childStartEvent(start),
		childStartEvent(start),
		childEndEvent(end),
		childEndEvent(reclose),
	})

	want := childAgentBlockText(start, nil, &end, false)
	if got := a.TranscriptText(); got != want {
		t.Fatalf("replayed transcript = %q, want only the one usable lifecycle %q", got, want)
	}
}
