package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

type queueFixture struct {
	t         *testing.T
	a         *App
	store     *sessions.Store
	sent      []sentPrompt
	busy      bool
	turnTakes bool
	accept    bool
	flushes   int
	flushErr  error
}

type sentPrompt struct {
	text  string
	parts []sessions.ContentPart
}

func newQueueFixture(t *testing.T) *queueFixture {
	t.Helper()
	f := &queueFixture{t: t, a: New(nil), accept: true}
	f.store = queueTestStore(filepath.Join(t.TempDir(), "session.json"))
	f.a.SetActiveStore(f.store)
	f.a.SetCommandFlush(func() error {
		f.flushes++
		if f.flushErr != nil {
			return f.flushErr
		}
		_, _, err := f.store.Flush(context.Background())
		return err
	})
	f.a.SetSubmit(func(input string, parts ...sessions.ContentPart) bool {
		if f.busy {
			if f.turnTakes && !f.a.HasQueuedPrompt() {
				f.a.SendingPrompt(input, parts...)
				return true
			}
			f.a.EnqueuePrompt(input, parts...)
			return true
		}
		if !f.accept {
			return false
		}
		f.sent = append(f.sent, sentPrompt{text: input, parts: parts})
		return true
	})
	return f
}

func queueTestStore(path string) *sessions.Store {
	started := time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)
	return sessions.New(path, &sessions.Session{
		Metadata: sessions.Metadata{
			ID:            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
			SchemaVersion: 1,
			Folder:        "/work",
			StartedAt:     started,
			UpdatedAt:     started,
		},
	})
}

func (f *queueFixture) pressKey(key tcell.Key) {
	f.t.Helper()
	handler := f.a.input.InputHandler()
	handler(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
}

func (f *queueFixture) enterText(text string) {
	f.t.Helper()
	f.a.input.SetText(text)
	f.pressKey(tcell.KeyEnter)
}

func (f *queueFixture) enterWithImage(text, label string) {
	f.t.Helper()
	f.a.input.SetText(text)
	f.a.input.addAttachment(testImageAttachment(label, 12), label)
	f.pressKey(tcell.KeyEnter)
}

func (f *queueFixture) queueRowLines() []string {
	f.t.Helper()
	text := f.a.queueRows.GetText(true)
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func (f *queueFixture) discardedEvents() []events.QueuedPromptDiscarded {
	f.t.Helper()
	data, err := os.ReadFile(f.store.Path())
	if err != nil {
		f.t.Fatalf("read flushed session: %v", err)
	}
	persisted, err := sessions.Unmarshal(data)
	if err != nil {
		f.t.Fatalf("decode flushed session: %v", err)
	}
	var out []events.QueuedPromptDiscarded
	for _, rec := range persisted.Records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindQueuedPromptDiscarded {
			continue
		}
		var payload events.QueuedPromptDiscarded
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			f.t.Fatalf("decode queued_prompt_discarded: %v", err)
		}
		out = append(out, payload)
	}
	return out
}

func TestEnqueuePrompt_HoldsPromptsWithoutSubmitting(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true

	f.enterText("summarize the diff")
	f.a.input.SetText("")
	f.a.input.addAttachment(testImageAttachment("diagram.png", 12), "diagram.png")
	f.pressKey(tcell.KeyEnter)
	f.enterText("then run the tests")

	if len(f.sent) != 0 {
		t.Fatalf("submitted %d prompts at enqueue time, want 0", len(f.sent))
	}
	if len(f.a.queued) != 3 {
		t.Fatalf("queued = %d prompts, want 3", len(f.a.queued))
	}
	if got := f.a.queued[0].text; got != "summarize the diff" {
		t.Errorf("front queued prompt = %q, want the oldest entry (FIFO)", got)
	}
	if got := f.a.queued[1]; got.text != "" || len(got.parts) != 1 {
		t.Errorf("image-only queued prompt = %+v, want empty text with one image part", got)
	}
	want := []string{
		queuedRowPrefix + "summarize the diff",
		queuedRowPrefix + "[1 image]",
		queuedRowPrefix + "then run the tests",
	}
	if got := f.queueRowLines(); !equalStrings(got, want) {
		t.Errorf("queue rows = %q, want one row per prompt in entry order %q", got, want)
	}
	if got := f.a.TranscriptText(); strings.Contains(got, "summarize the diff") {
		t.Errorf("transcript = %q, want no echo of a prompt that was only queued", got)
	}
	if got := f.a.input.GetText(); got != "" {
		t.Errorf("input = %q after an accepted enqueue, want it cleared for the next prompt", got)
	}

	for i := 0; i < 40; i++ {
		f.enterText("more work")
	}
	if len(f.a.queued) != 43 {
		t.Errorf("queued = %d prompts, want 43 (the queue is unbounded)", len(f.a.queued))
	}
	if got := len(f.queueRowLines()); got != 43 {
		t.Errorf("queue rows = %d, want one per queued prompt (43)", got)
	}
}

func TestQueuedPrompt_UpRecallsNewestFirstBeforeHistory(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true
	f.enterText("summarize the diff")
	f.enterWithImage("look at ", "diagram.png")

	f.pressKey(tcell.KeyUp)
	if got := f.a.input.GetText(); got != "look at [diagram.png]" {
		t.Fatalf("recalled draft = %q, want the newest queued prompt with its image token", got)
	}
	if atts := f.a.input.imageAttachments(); len(atts) != 1 || atts[0].displayName() != "diagram.png" {
		t.Fatalf("recalled attachments = %+v, want the queued prompt's one image", atts)
	}
	if len(f.sent) != 0 {
		t.Fatalf("recall submitted %d prompts, want 0 until Enter", len(f.sent))
	}
	if len(f.a.queued) != 1 || f.a.queued[0].text != "summarize the diff" {
		t.Fatalf("queue after recall = %+v, want only the older prompt left", f.a.queued)
	}

	f.busy = false
	f.pressKey(tcell.KeyEnter)
	if len(f.sent) != 1 || f.sent[0].text != "look at" || len(f.sent[0].parts) != 1 {
		t.Fatalf("submitted after Enter = %+v, want the recalled text plus its image part", f.sent)
	}

	f.a.input.SetText("")
	f.pressKey(tcell.KeyUp)
	if got := f.a.input.GetText(); got != "summarize the diff" {
		t.Fatalf("second recall = %q, want the remaining queued prompt", got)
	}
	if len(f.a.queued) != 0 {
		t.Fatalf("queued = %d prompts, want the queue drained by recall", len(f.a.queued))
	}

	f.a.input.SetText("")
	f.pressKey(tcell.KeyUp)
	if got := f.a.input.GetText(); got != "look at" {
		t.Errorf("↑ on an empty queue = %q, want the newest history entry", got)
	}
}

func TestQueuedPrompt_RecallRestoresCollapsedPasteToken(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true
	pasted := "one\ntwo\nthree\nfour\nfive\nsix\n"
	pasteInto(f.a.input, pasted)
	f.pressKey(tcell.KeyEnter)

	if got := f.a.queued[0].text; got != strings.TrimSpace(pasted) {
		t.Fatalf("queued text = %q, want the expanded paste %q", got, strings.TrimSpace(pasted))
	}

	f.pressKey(tcell.KeyUp)
	if got := f.a.input.GetText(); got != pastePlaceholder(6) {
		t.Fatalf("recalled draft = %q, want the collapsed paste placeholder %q", got, pastePlaceholder(6))
	}

	f.busy = false
	f.pressKey(tcell.KeyEnter)
	if len(f.sent) != 1 || f.sent[0].text != strings.TrimSpace(pasted) {
		t.Fatalf("submitted after recall = %+v, want the full pasted text expanded again", f.sent)
	}
}

func TestQueuedPromptRows_RenderDim(t *testing.T) {
	a := New(nil)
	a.EnqueuePrompt("summarize the diff")

	cells, width, _ := drawPrimitive(t, a.queueRows, 40, 1).GetContents()
	var row strings.Builder
	var style tcell.Style
	styled := false
	for col := 0; col < width; col++ {
		c := cells[col]
		if len(c.Runes) == 0 {
			continue
		}
		if !styled && string(c.Runes) != " " {
			style, styled = c.Style, true
		}
		row.WriteString(string(c.Runes))
	}
	if want := queuedRowPrefix + "summarize the diff"; !strings.Contains(row.String(), want) {
		t.Fatalf("queued row = %q, want it to render %q", row.String(), want)
	}
	fg, _, attr := style.Decompose()
	if fg != ghostTextColor {
		t.Errorf("queued row foreground = %v, want the dim grey %v", fg, ghostTextColor)
	}
	if attr&tcell.AttrDim == 0 {
		t.Error("queued row is not drawn with the dim attribute")
	}
}

func TestQueuedPromptRows_ReserveAndReleaseTranscriptSpace(t *testing.T) {
	h := newAppHarness(t, 60, 24)
	defer h.stop()
	h.a.SetActiveStore(queueTestStore(filepath.Join(t.TempDir(), "session.json")))

	h.runDraw(func() {
		for i := 0; i < 60; i++ {
			h.a.Append("conversation line")
		}
	})
	baseline, _ := queueBandRects(h)

	h.runDraw(func() {
		h.a.EnqueuePrompt("summarize the diff")
		h.a.EnqueuePrompt("then run the tests")
	})
	withRows, rows := queueBandRects(h)
	if rows.height != 2 {
		t.Fatalf("queued row band = %d rows, want one per queued prompt (2)", rows.height)
	}
	if want := baseline.height - 2; withRows.height != want {
		t.Errorf("transcript = %d rows with 2 queued prompts, want %d (the rows come out of the transcript)", withRows.height, want)
	}
	if inputY := queueInputTop(h); rows.y+rows.height != inputY {
		t.Errorf("queued rows end at row %d, want the input top %d (rows sit directly above the input)", rows.y+rows.height, inputY)
	}

	h.runDraw(func() { h.a.turnEnded(turnOutcomeInterrupted) })
	released, emptyRows := queueBandRects(h)
	if emptyRows.height != 0 {
		t.Errorf("queued row band = %d rows on an empty queue, want it collapsed", emptyRows.height)
	}
	if released.height != baseline.height {
		t.Errorf("transcript = %d rows after the queue drained, want the original %d", released.height, baseline.height)
	}
}

type queueRect struct{ y, height int }

func queueBandRects(h *appHarness) (transcript, rows queueRect) {
	h.t.Helper()
	h.a.app.QueueUpdate(func() {
		_, transcript.y, _, transcript.height = h.a.transcript.view.GetRect()
		_, rows.y, _, rows.height = h.a.queueRows.GetRect()
	})
	return transcript, rows
}

func queueInputTop(h *appHarness) int {
	h.t.Helper()
	var y int
	h.a.app.QueueUpdate(func() { _, y, _, _ = h.a.input.GetRect() })
	return y
}

func TestQueuedPromptHint_NeverReplacesFollowupGhostText(t *testing.T) {
	a := New(nil)
	a.EnqueuePrompt("summarize the diff")
	if got := screenText(drawPrimitive(t, a.input, 60, 3)); !strings.Contains(got, queuedPromptHint) {
		t.Fatalf("input row = %q, want the queue-edit hint while a prompt is queued", got)
	}

	a.SuggestFollowup("write the tests", "write the tests now")
	drawn := screenText(drawPrimitive(t, a.input, 60, 3))
	if !strings.Contains(drawn, "write the tests") {
		t.Errorf("input row = %q, want the pending follow-up ghost text", drawn)
	}
	if strings.Contains(drawn, queuedPromptHint) {
		t.Errorf("input row = %q, want the queue hint to yield to the ghost text", drawn)
	}

	a.EnqueuePrompt("then run the tests")
	drawn = screenText(drawPrimitive(t, a.input, 60, 3))
	if !strings.Contains(drawn, "write the tests") || strings.Contains(drawn, queuedPromptHint) {
		t.Errorf("input row = %q, want the ghost text kept while more prompts queue", drawn)
	}

	a.resetPendingFollowup()
	if got := screenText(drawPrimitive(t, a.input, 60, 3)); !strings.Contains(got, queuedPromptHint) {
		t.Errorf("input row = %q, want the queue hint back once no suggestion is pending", got)
	}
}

func TestTurnEnded_CompletedDispatchesFrontOnlyAfterPersistence(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true
	f.enterWithImage("look at ", "diagram.png")
	f.enterText("then run the tests")
	f.busy = false

	f.accept = false
	f.a.TurnEnded(turnOutcomeCompleted)
	if len(f.sent) != 0 {
		t.Fatalf("sent %d prompts after a rejected save, want 0", len(f.sent))
	}
	if len(f.a.queued) != 2 {
		t.Fatalf("queued = %d prompts after a rejected save, want both retained", len(f.a.queued))
	}
	front := f.a.queued[0]
	if front.text != "look at" || len(front.parts) != 1 {
		t.Errorf("front prompt after a rejected save = %+v, want its text and attachment intact", front)
	}
	if got := f.a.TranscriptText(); strings.Contains(got, "look at") {
		t.Errorf("transcript = %q, want no echo of a prompt whose save was rejected", got)
	}

	f.accept = true
	f.a.TurnEnded(turnOutcomeCompleted)
	if len(f.sent) != 1 || f.sent[0].text != "look at" || len(f.sent[0].parts) != 1 {
		t.Fatalf("dispatched = %+v, want only the front prompt with its image part", f.sent)
	}
	if len(f.a.queued) != 1 || f.a.queued[0].text != "then run the tests" {
		t.Fatalf("queue after dispatch = %+v, want only the newer prompt left", f.a.queued)
	}
	transcript := f.a.TranscriptText()
	if !strings.Contains(transcript, "look at") {
		t.Errorf("transcript = %q, want the dispatched prompt echoed once it was accepted", transcript)
	}
	if strings.Contains(transcript, "then run the tests") {
		t.Errorf("transcript = %q, want the still-queued prompt not echoed", transcript)
	}
}

func TestTurnEnded_DropOutcomesDiscardEveryQueuedPrompt(t *testing.T) {
	for _, outcome := range []string{turnOutcomeInterrupted, turnOutcomeTurnFailed} {
		t.Run(outcome, func(t *testing.T) {
			f := newQueueFixture(t)
			f.busy = true
			f.enterText("summarize the diff")
			f.a.input.SetText("")
			f.a.input.addAttachment(testImageAttachment("diagram.png", 12), "diagram.png")
			f.pressKey(tcell.KeyEnter)
			f.busy = false

			f.a.TurnEnded(outcome)

			if len(f.sent) != 0 {
				t.Fatalf("sent %d prompts on a %s turn, want 0", len(f.sent), outcome)
			}
			if len(f.a.queued) != 0 {
				t.Fatalf("queued = %d prompts after the discard, want the queue drained", len(f.a.queued))
			}
			discarded := f.discardedEvents()
			want := []events.QueuedPromptDiscarded{
				{Text: "summarize the diff", ImageCount: 0, Reason: outcome},
				{Text: "", ImageCount: 1, Reason: outcome},
			}
			if len(discarded) != len(want) {
				t.Fatalf("recorded %d discard events, want one per dropped prompt (%d)", len(discarded), len(want))
			}
			for i, w := range want {
				if discarded[i] != w {
					t.Errorf("discard event %d = %+v, want %+v", i, discarded[i], w)
				}
			}
			if f.flushes != len(want) {
				t.Errorf("flushed %d times, want each discard flushed (%d)", f.flushes, len(want))
			}
			transcript := f.a.TranscriptText()
			if got := strings.Count(transcript, neverSentPrefix); got != len(want) {
				t.Errorf("transcript has %d never-sent lines, want one per dropped prompt (%d):\n%s", got, len(want), transcript)
			}
			if !strings.Contains(transcript, neverSentPrefix+"summarize the diff") ||
				!strings.Contains(transcript, neverSentPrefix+"[1 image]") {
				t.Errorf("transcript = %q, want a never-sent line naming each dropped prompt", transcript)
			}
			if rows := f.queueRowLines(); rows != nil {
				t.Errorf("queue rows = %q, want them released once the queue drained", rows)
			}
		})
	}
}

func TestTurnEnded_DiscardWriteFailureKeepsPromptQueued(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true
	f.enterText("summarize the diff")
	f.enterText("then run the tests")
	f.busy = false
	f.flushErr = errors.New("flush hook failed")

	f.a.TurnEnded(turnOutcomeInterrupted)

	if len(f.a.queued) != 2 {
		t.Fatalf("queued = %d prompts after the flush hook returned an error, want both retained", len(f.a.queued))
	}
	if f.a.queued[0].text != "summarize the diff" {
		t.Errorf("front prompt = %q, want it kept at the front of the FIFO", f.a.queued[0].text)
	}
	if f.flushes != 1 {
		t.Errorf("flushed %d times, want the discard loop to stop at the first failure", f.flushes)
	}
	if got := f.a.TranscriptText(); strings.Contains(got, neverSentPrefix) {
		t.Errorf("transcript = %q, want no never-sent line for a prompt still queued", got)
	}
	if got := f.a.NoticeText(); !strings.Contains(got, "flush hook failed") {
		t.Errorf("notice = %q, want the returned flush hook error surfaced", got)
	}
	if got := len(f.queueRowLines()); got != 2 {
		t.Errorf("queue rows = %d, want both retained prompts still shown", got)
	}
}

func TestTurnEnded_DiscardFlushRetryPersistsOneEventPerPrompt(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true
	f.enterText("summarize the diff")
	f.enterText("then run the tests")
	f.busy = false

	f.flushErr = errors.New("flush hook failed")
	f.a.TurnEnded(turnOutcomeInterrupted)
	if len(f.a.queued) != 2 {
		t.Fatalf("queued = %d prompts after the flush hook returned an error, want both retained", len(f.a.queued))
	}

	f.flushErr = nil
	f.a.TurnEnded(turnOutcomeInterrupted)
	if len(f.a.queued) != 0 {
		t.Fatalf("queued = %d prompts after the retry, want the queue drained", len(f.a.queued))
	}

	discarded := f.discardedEvents()
	want := []events.QueuedPromptDiscarded{
		{Text: "summarize the diff", Reason: turnOutcomeInterrupted},
		{Text: "then run the tests", Reason: turnOutcomeInterrupted},
	}
	if len(discarded) != len(want) {
		t.Fatalf("persisted %d discard events after one failed flush and a retry, want one per dropped prompt (%d): %+v", len(discarded), len(want), discarded)
	}
	for i, w := range want {
		if discarded[i] != w {
			t.Errorf("persisted discard event %d = %+v, want %+v", i, discarded[i], w)
		}
	}
	transcript := f.a.TranscriptText()
	if got := strings.Count(transcript, neverSentPrefix); got != len(want) {
		t.Errorf("transcript has %d never-sent lines, want one per dropped prompt (%d):\n%s", got, len(want), transcript)
	}
}

func (f *queueFixture) inMemoryDiscardCount() int {
	f.t.Helper()
	n := 0
	for _, rec := range f.store.Records() {
		if ev, ok := rec.(sessions.Event); ok && ev.Kind == "queued_prompt_discarded" {
			n++
		}
	}
	return n
}

func TestTurnEnded_CompletedNeverSendsPromptDiscardedBeforeFlushError(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true
	f.enterText("summarize the diff")
	f.busy = false

	f.flushErr = context.Canceled
	f.a.TurnEnded(turnOutcomeInterrupted)
	if got := f.inMemoryDiscardCount(); got != 1 {
		t.Fatalf("in-memory discard events after the flush hook returned an error = %d, want 1", got)
	}
	if len(f.a.queued) != 1 {
		t.Fatalf("queued = %d prompts after the flush hook returned an error, want the row retained", len(f.a.queued))
	}

	for turn := 1; turn <= 2; turn++ {
		f.a.TurnEnded(turnOutcomeCompleted)
		if len(f.sent) != 0 {
			t.Fatalf("turn %d: sent %+v, want the discarded prompt never sent", turn, f.sent)
		}
		if len(f.a.queued) != 0 || f.queueRowLines() != nil {
			t.Fatalf("turn %d: queued = %+v rows = %q, want the discarded row removed", turn, f.a.queued, f.queueRowLines())
		}
		if got := strings.Count(f.a.TranscriptText(), "not sent: summarize the diff"); got != 1 {
			t.Fatalf("turn %d: transcript has %d not-sent lines, want 1:\n%s", turn, got, f.a.TranscriptText())
		}
	}
	if got := f.inMemoryDiscardCount(); got != 1 {
		t.Fatalf("in-memory discard events after the completed turns = %d, want 1", got)
	}

	f.flushErr = nil
	if err := f.a.FlushActive(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	want := []events.QueuedPromptDiscarded{{Text: "summarize the diff", Reason: turnOutcomeInterrupted}}
	if got := f.discardedEvents(); !slices.Equal(got, want) {
		t.Fatalf("persisted discard events = %+v, want %+v", got, want)
	}
}

func TestTurnEnded_CompletedDrainsDiscardedFrontBeforeLiveRow(t *testing.T) {
	setup := func(t *testing.T) *queueFixture {
		f := newQueueFixture(t)
		f.busy = true
		f.enterText("summarize the diff")
		f.enterText("then run the tests")
		f.busy = false
		f.flushErr = errors.New("flush hook failed")
		f.a.TurnEnded(turnOutcomeInterrupted)
		f.flushErr = nil
		return f
	}

	t.Run("submits the live row in the same turn", func(t *testing.T) {
		f := setup(t)
		f.a.TurnEnded(turnOutcomeCompleted)
		if len(f.sent) != 1 || f.sent[0].text != "then run the tests" {
			t.Fatalf("sent = %+v, want only the live row", f.sent)
		}
		if len(f.a.queued) != 0 {
			t.Fatalf("queued = %+v, want both rows gone", f.a.queued)
		}
		transcript := f.a.TranscriptText()
		notSent := strings.Index(transcript, "not sent: summarize the diff")
		echo := strings.Index(transcript, "then run the tests")
		if notSent < 0 || echo < notSent || strings.Count(transcript, "not sent: ") != 1 {
			t.Fatalf("transcript = %q, want one not-sent line for the discarded row before the live echo", transcript)
		}
		if got := f.inMemoryDiscardCount(); got != 1 {
			t.Fatalf("in-memory discard events = %d, want 1", got)
		}
	})

	t.Run("keeps the drained row removed when the live submit is rejected", func(t *testing.T) {
		f := setup(t)
		f.accept = false
		f.a.TurnEnded(turnOutcomeCompleted)
		if want := []string{"queued: then run the tests"}; !equalStrings(f.queueRowLines(), want) {
			t.Fatalf("queue rows = %q, want %q", f.queueRowLines(), want)
		}
		f.accept = true
		f.a.TurnEnded(turnOutcomeCompleted)
		if len(f.sent) != 1 || f.sent[0].text != "then run the tests" {
			t.Fatalf("sent = %+v, want only the live row", f.sent)
		}
		if got := strings.Count(f.a.TranscriptText(), "not sent: "); got != 1 {
			t.Fatalf("transcript has %d not-sent lines, want 1:\n%s", got, f.a.TranscriptText())
		}
	})

	t.Run("drains without a submit callback", func(t *testing.T) {
		f := setup(t)
		f.a.SetSubmit(nil)
		f.a.TurnEnded(turnOutcomeCompleted)
		if want := []string{"queued: then run the tests"}; !equalStrings(f.queueRowLines(), want) {
			t.Fatalf("queue rows = %q, want %q", f.queueRowLines(), want)
		}
		if got := strings.Count(f.a.TranscriptText(), "not sent: summarize the diff"); got != 1 {
			t.Fatalf("transcript has %d not-sent lines, want 1:\n%s", got, f.a.TranscriptText())
		}
	})
}

func TestUserMessagesUnsent_CompletedDrainsRecordedDiscard(t *testing.T) {
	f := newQueueFixture(t)
	f.busy, f.turnTakes = true, true
	f.enterText("first extra")
	f.enterText("second extra")
	f.busy = false
	if _, err := events.Append(f.store, events.QueuedPromptDiscarded{Text: "first extra", Reason: turnOutcomeInterrupted}); err != nil {
		t.Fatalf("append discard: %v", err)
	}

	f.a.UserMessagesUnsent(f.store, 2, 1, turnOutcomeCompleted)()

	if len(f.sent) != 1 || f.sent[0].text != "second extra" {
		t.Fatalf("sent = %+v, want only the live row", f.sent)
	}
	if len(f.a.queued) != 0 {
		t.Fatalf("queued = %+v, want both rows gone", f.a.queued)
	}
	if got := strings.Count(f.a.TranscriptText(), "not sent: first extra"); got != 1 {
		t.Fatalf("transcript has %d not-sent lines for the recorded row, want 1:\n%s", got, f.a.TranscriptText())
	}
	if got := f.inMemoryDiscardCount(); got != 1 {
		t.Fatalf("in-memory discard events = %d, want the recorded one only", got)
	}
}

func TestSendingPrompt_EchoesOnlyOnceAddedAfterPriorActivity(t *testing.T) {
	f := newQueueFixture(t)
	f.busy, f.turnTakes = true, true
	f.enterWithImage("look at ", "diagram.png")

	if want := []string{sendingRowPrefix + "look at [1 image]"}; !equalStrings(f.queueRowLines(), want) {
		t.Fatalf("queue rows = %q, want %q", f.queueRowLines(), want)
	}
	if got := f.a.TranscriptText(); strings.Contains(got, "look at") {
		t.Fatalf("transcript = %q, want no echo while the message waits for the turn", got)
	}
	if got := f.a.input.GetText(); got != "" {
		t.Fatalf("input = %q, want it cleared by the accepted submit", got)
	}
	if got := screenText(drawPrimitive(t, f.a.input, 60, 3)); strings.Contains(got, queuedPromptHint) {
		t.Errorf("input row = %q, want no queue-edit hint for a sending row", got)
	}

	f.a.AppendStreamDelta("checking the diff")
	f.a.AppendToolActivity([]string{"Run: go test ./..."})
	f.a.AppendStreamDelta("tests pass")
	f.a.UserMessageAdded(nil, f.store, "look at", []sessions.ContentPart{testImageAttachment("diagram.png", 12).imagePart()})
	f.a.AppendStreamDelta("the diagram shows")
	f.a.FinalizeStream()

	if rows := f.queueRowLines(); rows != nil {
		t.Fatalf("queue rows = %q, want the sending row removed once the turn added the message", rows)
	}
	transcript := f.a.TranscriptText()
	if got := strings.Count(transcript, "look at"); got != 1 {
		t.Fatalf("transcript has %d echoes of the added message, want 1:\n%s", got, transcript)
	}
	order := []string{"checking the diff", "Run: go test ./...", "tests pass", "look at", "[image: diagram.png", "the diagram shows"}
	last := -1
	for _, s := range order {
		i := strings.Index(transcript, s)
		if i <= last {
			t.Fatalf("transcript = %q, want %q after the text before it in %q", transcript, s, order)
		}
		last = i
	}
}

func TestUserMessagesUnsent_TransitionsSendingRowInPlace(t *testing.T) {
	setup := func(t *testing.T, outcome string) (*queueFixture, func()) {
		f := newQueueFixture(t)
		f.busy, f.turnTakes = true, true
		f.enterText("first extra")
		f.turnTakes = false
		f.enterText("second extra")
		want := []string{sendingRowPrefix + "first extra", queuedRowPrefix + "second extra"}
		if got := f.queueRowLines(); !equalStrings(got, want) {
			t.Fatalf("queue rows = %q, want %q", got, want)
		}
		end := f.a.UserMessagesUnsent(f.store, 1, 0, outcome)
		if !f.a.HasQueuedPrompt() {
			t.Fatal("HasQueuedPrompt = false with an unsent message not yet applied, want later submits to fall back")
		}
		f.busy = false
		return f, end
	}

	t.Run("completed dispatches the earlier message first", func(t *testing.T) {
		f, end := setup(t, turnOutcomeCompleted)
		f.accept = false
		end()
		want := []string{queuedRowPrefix + "first extra", queuedRowPrefix + "second extra"}
		if got := f.queueRowLines(); !equalStrings(got, want) {
			t.Fatalf("queue rows after the unsent hand-off = %q, want %q", got, want)
		}
		f.accept = true
		f.a.TurnEnded(turnOutcomeCompleted)
		if len(f.sent) != 1 || f.sent[0].text != "first extra" {
			t.Fatalf("dispatched = %+v, want only the earlier accepted message", f.sent)
		}
		if want := []string{queuedRowPrefix + "second extra"}; !equalStrings(f.queueRowLines(), want) {
			t.Fatalf("queue rows = %q, want %q", f.queueRowLines(), want)
		}
		f.a.TurnEnded(turnOutcomeCompleted)
		if len(f.sent) != 2 || f.sent[1].text != "second extra" {
			t.Fatalf("dispatched = %+v, want the later message sent next", f.sent)
		}
	})

	for _, outcome := range []string{turnOutcomeInterrupted, turnOutcomeTurnFailed} {
		t.Run(outcome+" marks each message not sent once", func(t *testing.T) {
			f, end := setup(t, outcome)
			end()
			transcript := f.a.TranscriptText()
			first := strings.Index(transcript, neverSentPrefix+"first extra")
			second := strings.Index(transcript, neverSentPrefix+"second extra")
			if first < 0 || second < first || strings.Count(transcript, neverSentPrefix) != 2 {
				t.Fatalf("transcript = %q, want one not-sent line per message in submit order", transcript)
			}
			if rows := f.queueRowLines(); rows != nil {
				t.Fatalf("queue rows = %q, want none left", rows)
			}
		})
	}
}

func TestUserMessagesUnsent_HonorsRecordedDiscards(t *testing.T) {
	setup := func(t *testing.T) *queueFixture {
		f := newQueueFixture(t)
		f.busy, f.turnTakes = true, true
		f.enterText("first extra")
		f.enterText("second extra")
		f.busy = false
		if _, err := events.Append(f.store, events.QueuedPromptDiscarded{Text: "first extra", Reason: turnOutcomeInterrupted}); err != nil {
			t.Fatalf("append discard: %v", err)
		}
		return f
	}

	t.Run("recorded discard is not appended again", func(t *testing.T) {
		f := setup(t)
		f.a.UserMessagesUnsent(f.store, 2, 1, turnOutcomeInterrupted)()
		want := []events.QueuedPromptDiscarded{
			{Text: "first extra", Reason: turnOutcomeInterrupted},
			{Text: "second extra", Reason: turnOutcomeInterrupted},
		}
		if got := f.discardedEvents(); !slices.Equal(got, want) {
			t.Fatalf("discard events = %+v, want %+v", got, want)
		}
		if got := strings.Count(f.a.TranscriptText(), neverSentPrefix); got != 2 {
			t.Fatalf("transcript has %d not-sent lines, want 2:\n%s", got, f.a.TranscriptText())
		}
	})
}

func TestDiscardHeldPrompts_RecordsHeldRowsInTheSessionLeft(t *testing.T) {
	f := newQueueFixture(t)
	f.busy, f.turnTakes = true, true
	f.enterText("added extra")
	f.enterText("unsent extra")
	f.turnTakes = false
	f.enterText("fallback extra")
	if _, err := events.Append(f.store, events.QueuedPromptDiscarded{Text: "unsent extra", Reason: turnOutcomeInterrupted}); err != nil {
		t.Fatalf("append discard: %v", err)
	}
	end := f.a.UserMessagesUnsent(f.store, 1, 1, turnOutcomeCompleted)

	f.a.DiscardHeldPrompts()
	fresh := queueTestStore(filepath.Join(t.TempDir(), "fresh.json"))
	f.a.SetActiveStore(fresh)
	f.turnTakes = true
	f.enterText("next session sending")
	f.turnTakes = false
	f.enterText("next session queued")
	f.busy = false
	end()
	f.a.UserMessageAdded(nil, f.store, "added extra", nil)

	if _, _, err := f.store.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	want := []events.QueuedPromptDiscarded{
		{Text: "unsent extra", Reason: turnOutcomeInterrupted},
		{Text: "fallback extra", Reason: turnOutcomeInterrupted},
	}
	if got := f.discardedEvents(); !slices.Equal(got, want) {
		t.Fatalf("discard events = %+v, want %+v", got, want)
	}
	if want := []string{sendingRowPrefix + "next session sending", queuedRowPrefix + "next session queued"}; !equalStrings(f.queueRowLines(), want) {
		t.Fatalf("queue rows = %q, want %q (late updates for the left session touch only its rows)", f.queueRowLines(), want)
	}
	if len(f.sent) != 0 {
		t.Fatalf("dispatched = %+v, want no queue policy from the left session's late TurnEnded", f.sent)
	}
	transcript := f.a.TranscriptText()
	for _, s := range []string{neverSentPrefix, "added extra", "unsent extra", "fallback extra"} {
		if strings.Contains(transcript, s) {
			t.Fatalf("transcript = %q, want no %q", transcript, s)
		}
	}
	if len(fresh.Records()) != 0 {
		t.Fatalf("fresh store records = %+v, want none", fresh.Records())
	}
}

func TestUserMessagesUnsent_EachTurnEndAppliesItsOwnBatch(t *testing.T) {
	t.Run("across a session switch", func(t *testing.T) {
		f := newQueueFixture(t)
		f.busy, f.turnTakes = true, true
		f.enterText("prior extra")
		if _, err := events.Append(f.store, events.QueuedPromptDiscarded{Text: "prior extra", Reason: turnOutcomeInterrupted}); err != nil {
			t.Fatalf("append discard: %v", err)
		}
		endPrior := f.a.UserMessagesUnsent(f.store, 1, 1, turnOutcomeInterrupted)
		f.a.DiscardHeldPrompts()
		fresh := queueTestStore(filepath.Join(t.TempDir(), "fresh.json"))
		f.a.SetActiveStore(fresh)
		f.enterText("fresh extra")
		endFresh := f.a.UserMessagesUnsent(fresh, 1, 0, turnOutcomeCompleted)
		f.busy = false

		endFresh()
		endPrior()

		if len(f.sent) != 1 || f.sent[0].text != "fresh extra" {
			t.Fatalf("dispatched = %+v, want the new session's unsent message sent once", f.sent)
		}
		if rows := f.queueRowLines(); rows != nil {
			t.Fatalf("queue rows = %q, want none left", rows)
		}
		if _, _, err := f.store.Flush(context.Background()); err != nil {
			t.Fatalf("flush: %v", err)
		}
		want := []events.QueuedPromptDiscarded{{Text: "prior extra", Reason: turnOutcomeInterrupted}}
		if got := f.discardedEvents(); !slices.Equal(got, want) {
			t.Fatalf("prior session discard events = %+v, want %+v", got, want)
		}
		if len(fresh.Records()) != 0 {
			t.Fatalf("fresh store records = %+v, want none", fresh.Records())
		}
		if transcript := f.a.TranscriptText(); strings.Contains(transcript, neverSentPrefix) {
			t.Fatalf("transcript = %q, want no not-sent line", transcript)
		}
	})

	t.Run("within one session", func(t *testing.T) {
		f := newQueueFixture(t)
		endFirst := f.a.UserMessagesUnsent(f.store, 0, 0, turnOutcomeCompleted)
		f.busy, f.turnTakes = true, true
		f.enterText("second extra")
		if _, err := events.Append(f.store, events.QueuedPromptDiscarded{Text: "second extra", Reason: turnOutcomeInterrupted}); err != nil {
			t.Fatalf("append discard: %v", err)
		}
		endSecond := f.a.UserMessagesUnsent(f.store, 1, 1, turnOutcomeInterrupted)
		f.busy = false

		endSecond()
		endFirst()

		want := []events.QueuedPromptDiscarded{{Text: "second extra", Reason: turnOutcomeInterrupted}}
		if got := f.discardedEvents(); !slices.Equal(got, want) {
			t.Fatalf("discard events = %+v, want %+v", got, want)
		}
		if got := strings.Count(f.a.TranscriptText(), neverSentPrefix+"second extra"); got != 1 {
			t.Fatalf("transcript has %d not-sent lines, want 1:\n%s", got, f.a.TranscriptText())
		}
		if len(f.sent) != 0 {
			t.Fatalf("dispatched = %+v, want nothing sent", f.sent)
		}
		if rows := f.queueRowLines(); rows != nil {
			t.Fatalf("queue rows = %q, want none left", rows)
		}
	})
}

func TestUserMessagesUnsent_DoesNotWaitOnBusyEventLoop(t *testing.T) {
	a := New(nil)
	a.SetActiveStore(queueTestStore(filepath.Join(t.TempDir(), "session.json")))
	a.newScreen = func() (tcell.Screen, error) { return tcell.NewSimulationScreen("UTF-8"), nil }
	errc := make(chan error, 1)
	go func() { errc <- a.Run() }()
	waitLoopRunning(t, a)
	defer func() {
		a.app.Stop()
		<-errc
	}()

	var end func()
	a.app.QueueUpdate(func() {
		a.SendingPrompt("held message")
		returned := make(chan struct{})
		go func() {
			end = a.UserMessagesUnsent(a.ActiveStore(), 1, 0, turnOutcomeCompleted)
			close(returned)
		}()
		select {
		case <-returned:
		case <-time.After(2 * time.Second):
			t.Error("UserMessagesUnsent waited on the event loop; a draining /clear would deadlock")
		}
	})
	if end == nil {
		t.Fatal("UserMessagesUnsent did not return")
	}

	end()
	var rows string
	a.app.QueueUpdate(func() { rows = a.queueRows.GetText(true) })
	if want := queuedRowPrefix + "held message"; rows != want {
		t.Fatalf("queue rows = %q, want %q (the sending row transitioned in place)", rows, want)
	}
}

func TestQueuedPrompt_RecallSkipsSendingRows(t *testing.T) {
	f := newQueueFixture(t)
	f.busy, f.turnTakes = true, true
	f.enterText("first extra")
	f.turnTakes = false
	f.enterText("second extra")
	if got := screenText(drawPrimitive(t, f.a.input, 60, 3)); !strings.Contains(got, queuedPromptHint) {
		t.Fatalf("input row = %q, want the queue-edit hint while a queued row exists", got)
	}

	f.pressKey(tcell.KeyUp)
	if got := f.a.input.GetText(); got != "second extra" {
		t.Fatalf("recalled draft = %q, want the newest queued row", got)
	}
	if want := []string{sendingRowPrefix + "first extra"}; !equalStrings(f.queueRowLines(), want) {
		t.Fatalf("queue rows = %q, want %q", f.queueRowLines(), want)
	}

	f.a.input.SetText("")
	if f.a.recallQueuedPrompt() {
		t.Fatal("recall took a sending row")
	}
	if got := screenText(drawPrimitive(t, f.a.input, 60, 3)); strings.Contains(got, queuedPromptHint) {
		t.Errorf("input row = %q, want no queue-edit hint with only a sending row", got)
	}
}

func TestDispatchQueuedFront_SkipsEchoWhenRunningTurnTakesIt(t *testing.T) {
	f := newQueueFixture(t)
	f.busy = true
	f.enterText("queued work")
	f.a.SetSubmit(func(input string, parts ...sessions.ContentPart) bool {
		f.a.SendingPrompt(input, parts...)
		return true
	})

	f.a.TurnEnded(turnOutcomeCompleted)

	if want := []string{sendingRowPrefix + "queued work"}; !equalStrings(f.queueRowLines(), want) {
		t.Fatalf("queue rows = %q, want %q", f.queueRowLines(), want)
	}
	if got := f.a.TranscriptText(); strings.Contains(got, "queued work") {
		t.Fatalf("transcript = %q, want no echo for a message the running turn took", got)
	}
}

func (f *queueFixture) literalPrompt(sent *[]string) {
	f.a.SetLiteralPrompt(func(text string, parts ...sessions.ContentPart) bool {
		if f.busy {
			if f.turnTakes && !f.a.HasQueuedPrompt() {
				f.a.SendingPrompt(text, parts...)
				return true
			}
			f.a.EnqueuePrompt(text, parts...)
			return true
		}
		if !f.accept {
			return false
		}
		*sent = append(*sent, text)
		return true
	})
}

func TestDispatchQueuedFront_LiteralEntryDrainsToPromptWithoutDispatch(t *testing.T) {
	f := newQueueFixture(t)
	var literal []string
	f.literalPrompt(&literal)
	f.busy = true
	if !f.a.SubmitLiteral("/help me with this") {
		t.Fatal("held literal prompt rejected")
	}
	f.enterText("ordinary follow-up")
	f.busy = false

	f.a.TurnEnded(turnOutcomeCompleted)
	if !slices.Equal(literal, []string{"/help me with this"}) || len(f.sent) != 0 {
		t.Fatalf("literal drain = %q, submit path = %+v; want the held body sent as model input only", literal, f.sent)
	}
	if got := f.a.TranscriptText(); !strings.Contains(got, "/help me with this") {
		t.Fatalf("transcript = %q, want the drained literal echoed", got)
	}

	f.a.TurnEnded(turnOutcomeCompleted)
	if len(f.sent) != 1 || f.sent[0].text != "ordinary follow-up" || len(literal) != 1 {
		t.Fatalf("submit path = %+v, literal = %q; want ordinary input drained through submit", f.sent, literal)
	}
}

func TestDispatchQueuedFront_RolledBackLiteralStaysLiteral(t *testing.T) {
	f := newQueueFixture(t)
	var literal []string
	f.literalPrompt(&literal)
	f.busy, f.turnTakes = true, true
	if !f.a.SubmitLiteral("/help joined") {
		t.Fatal("sending literal prompt rejected")
	}
	if want := []string{sendingRowPrefix + "/help joined"}; !equalStrings(f.queueRowLines(), want) {
		t.Fatalf("queue rows = %q, want %q", f.queueRowLines(), want)
	}
	end := f.a.UserMessagesUnsent(f.store, 1, 0, turnOutcomeCompleted)
	f.busy = false
	end()

	if !slices.Equal(literal, []string{"/help joined"}) || len(f.sent) != 0 {
		t.Fatalf("literal drain = %q, submit path = %+v; want the rolled-back body sent literally", literal, f.sent)
	}
}

func TestSubmitLiteral_ClearsOneShotMarkerOnEveryOutcome(t *testing.T) {
	for _, accept := range []bool{true, false} {
		t.Run(fmt.Sprintf("accept=%v", accept), func(t *testing.T) {
			f := newQueueFixture(t)
			f.a.SetLiteralPrompt(func(string, ...sessions.ContentPart) bool { return accept })
			if got := f.a.SubmitLiteral("body"); got != accept {
				t.Fatalf("SubmitLiteral = %v, want %v", got, accept)
			}
			f.busy = true
			f.enterText("ordinary")
			if len(f.a.queued) != 1 || f.a.queued[0].literal {
				t.Fatalf("queued = %+v, want one ordinary entry without the literal marker", f.a.queued)
			}
		})
	}
}
