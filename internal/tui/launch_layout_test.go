// Tests for the launch layout (transcript follows content via the
// before-draw height recompute, capping at the available screen height and
// shrinking back after a reset) and the tag-injection escaping that the
// transcript's dynamic colors require.
package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/sessions"
)

// layoutHarness runs the real App event loop against a simulation screen and
// exposes the reads the layout tests need — the drawn transcript-row height and the
// mouse-injection steps — on top of the shared appHarness draw-synchronization base.
type layoutHarness struct {
	*appHarness
}

func newLayoutHarness(t *testing.T, width, height int) *layoutHarness {
	return &layoutHarness{newAppHarness(t, width, height)}
}

// update runs f on the event-loop goroutine and waits for the draw it triggers,
// so a following transcriptHeight read sees the reflowed layout.
func (h *layoutHarness) update(f func()) { h.runDraw(f) }

// transcriptHeight returns the transcript view's drawn row height, read on the
// event-loop goroutine so it is serialized with the layout pass.
func (h *layoutHarness) transcriptHeight() int {
	h.t.Helper()
	var height int
	h.a.app.QueueUpdate(func() { _, _, _, height = h.a.transcript.view.GetRect() })
	return height
}

// inputHeightRows returns the input area's drawn row height (the flex item's
// allocated rect, which the before-draw hook sizes to App.inputRows), read on the
// event-loop goroutine so it is serialized with the layout pass.
func (h *layoutHarness) inputHeightRows() int {
	h.t.Helper()
	var height int
	h.a.app.QueueUpdate(func() { _, _, _, height = h.a.input.GetRect() })
	return height
}

type bandRects struct {
	transcriptY, transcriptH int
	gapY, gapH               int
	indicatorY, indicatorH   int
	inputY, inputH           int
}

func (r bandRects) transcriptEnd() int { return r.transcriptY + r.transcriptH }
func (r bandRects) inputEnd() int      { return r.inputY + r.inputH }

func (r bandRects) assertAnchored(t *testing.T, wantGap int) {
	t.Helper()
	if r.gapY != r.transcriptEnd() {
		t.Errorf("spacer starts at row %d, want %d (immediately after the transcript)", r.gapY, r.transcriptEnd())
	}
	if r.gapH != wantGap {
		t.Errorf("transcript-to-tracker spacing = %d rows, want %d", r.gapH, wantGap)
	}
	if want := r.gapY + r.gapH; r.indicatorY != want {
		t.Errorf("tracker starts at row %d, want %d (immediately after the spacer)", r.indicatorY, want)
	}
	if r.indicatorH != indicatorHeight {
		t.Errorf("tracker height = %d, want %d while active", r.indicatorH, indicatorHeight)
	}
	if want := r.indicatorY + r.indicatorH; r.inputY != want {
		t.Errorf("input starts at row %d, want %d (tracker directly adjacent above the input)", r.inputY, want)
	}
	if r.inputH < inputHeight {
		t.Errorf("input height = %d, want at least %d (its allocated rows were clipped)", r.inputH, inputHeight)
	}
}

func (h *layoutHarness) bands() bandRects {
	h.t.Helper()
	var r bandRects
	done := make(chan struct{})
	h.a.app.QueueUpdate(func() {
		_, r.transcriptY, _, r.transcriptH = h.a.transcript.view.GetRect()
		_, r.gapY, _, r.gapH = h.a.bannerGap.GetRect()
		_, r.indicatorY, _, r.indicatorH = h.a.indicator.GetRect()
		_, r.inputY, _, r.inputH = h.a.input.GetRect()
		close(done)
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		h.t.Fatal("band rectangle read did not complete within 2s")
	}
	return r
}

func (h *layoutHarness) rowText(y int) string {
	h.t.Helper()
	var row string
	done := make(chan struct{})
	h.a.app.QueueUpdate(func() {
		width, _ := h.screen.Size()
		var b strings.Builder
		for col := 0; col < width; col++ {
			s, _, _ := h.screen.Get(col, y)
			b.WriteString(s)
		}
		row = b.String()
		close(done)
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		h.t.Fatal("screen row read did not complete within 2s")
	}
	return row
}

func (h *layoutHarness) cellStyle(x, y int) tcell.Style {
	h.t.Helper()
	var style tcell.Style
	done := make(chan struct{})
	h.a.app.QueueUpdate(func() {
		cells, width, _ := h.screen.GetContents()
		style = cells[y*width+x].Style
		close(done)
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.a.app.Stop()
		h.t.Fatal("screen cell read did not complete within 2s")
	}
	return style
}

func (h *layoutHarness) startTurn(lines int) func() {
	h.t.Helper()
	h.update(func() {
		for i := 0; i < lines; i++ {
			h.a.Append(fmt.Sprintf("streamed line %d", i))
		}
		h.a.ShowIndicator(0, 0)
	})
	return func() { h.update(h.a.clearIndicatorDirect) }
}

// injectMouse posts a real mouse event into the running event loop so it routes
// through fireMouseActions, the installed app-level mouse capture, and the Flex
// layout exactly as a terminal event would, then waits for the draw the consumed
// event triggers. Dropping any stale draw token first makes the wait observe this
// event's draw, not a previous one.
func (h *layoutHarness) injectMouse(x, y int, button tcell.ButtonMask) {
	h.t.Helper()
	h.injectMouseMod(x, y, button, tcell.ModNone)
}

// injectMouseMod is injectMouse with an explicit modifier mask, so a test can drive a
// Shift-modified drag (Shift+drag still works in the input) through the same
// production event-loop route as a plain drag.
func (h *layoutHarness) injectMouseMod(x, y int, button tcell.ButtonMask, mod tcell.ModMask) {
	h.t.Helper()
	h.dropStaleDraw()
	h.a.app.QueueEvent(tcell.NewEventMouse(x, y, button, mod))
	h.waitDraw()
}

// injectMouseQuiet posts a mouse event that may not be consumed — and so would not on
// its own trigger the redraw injectMouse waits for — then forces a draw with a no-op
// resize so the event is fully processed before a following state read. Events share
// one FIFO channel, so the mouse event lands before the resize. Used to assert that an
// event has NO effect (e.g. a hover after a drag ended), where waiting on the event's
// own draw would hang.
func (h *layoutHarness) injectMouseQuiet(x, y int, button tcell.ButtonMask) {
	h.t.Helper()
	h.dropStaleDraw()
	w, ht := h.screen.Size()
	h.a.app.QueueEvent(tcell.NewEventMouse(x, y, button, tcell.ModNone))
	h.a.app.QueueEvent(tcell.NewEventResize(w, ht))
	h.waitDraw()
}

// TestLaunchLayout_TranscriptFollowsContentThenCaps pins content-following and capping:
// the transcript pane is sized to its content (so the input area follows it — one
// blank banner-gap row below, not pinned to the bottom), grows as lines append, and
// caps at the available screen height (screen minus the banner gap, input area,
// status-line, and mode-hint chrome) once the conversation overflows.
func TestLaunchLayout_TranscriptFollowsContentThenCaps(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()

	// The launch banner is one three-line block (its lines stay adjacent, no
	// blank separator rows inside it), so the pane is exactly three rows tall (the
	// banner gap is a separate chrome row below it, so it does not change the
	// transcript-pane height).
	h.update(func() {
		h.a.AppendBanner("banner line one", "banner line two", "banner line three")
	})
	if got := h.transcriptHeight(); got != 3 {
		t.Fatalf("transcript height at launch = %d, want 3 (pane sized to the banner, gap + input below)", got)
	}

	// Grow the conversation past the screen: the pane caps at screenH minus the
	// fixed chrome (banner gap 1 + input area 3 + two-row bottom footer 2 = 6)
	// rather than overflowing.
	h.update(func() {
		for i := 0; i < 60; i++ {
			h.a.Append(fmt.Sprintf("conversation line %d", i))
		}
	})
	wantCap := screenH - (bannerGapHeight + inputHeight + statusBarHeight)
	if got := h.transcriptHeight(); got != wantCap {
		t.Fatalf("transcript height after overflow = %d, want cap %d (available screen height)", got, wantCap)
	}

	// Reset to a short transcript (the /clear shrink, re-rendered banner): the
	// before-draw recompute shrinks the pane back without any reset-specific code.
	h.update(func() {
		h.a.ResetTranscript()
		h.a.Append("re-rendered banner")
	})
	if got := h.transcriptHeight(); got != 1 {
		t.Fatalf("transcript height after reset = %d, want 1 (pane shrank back to the re-rendered content)", got)
	}
}

// TestLaunchLayout_StatusOverlayAndResizeReflow pins overlay and resize reflow: opening the
// /status overlay reduces the transcript's available height by the overlay rows
// and closing it restores them, and a terminal resize reflows the cap — no stale
// heights, no overlap.
func TestLaunchLayout_StatusOverlayAndResizeReflow(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()

	// Overflow the pane so it sits at the cap and the overlay's effect on the cap
	// is observable.
	h.update(func() {
		for i := 0; i < 60; i++ {
			h.a.Append(fmt.Sprintf("line %d", i))
		}
	})
	baseCap := screenH - (bannerGapHeight + inputHeight + statusBarHeight)
	if got := h.transcriptHeight(); got != baseCap {
		t.Fatalf("precondition: transcript height = %d, want cap %d", got, baseCap)
	}

	// Opening /status adds its overlay rows to the chrome, so the transcript cap
	// shrinks by exactly that much.
	const statusBody = "line A\nline B"
	h.update(func() { h.a.ShowStatus(statusBody) })
	wantWithOverlay := baseCap - statusPanelHeight(statusBody)
	if got := h.transcriptHeight(); got != wantWithOverlay {
		t.Fatalf("transcript height with /status open = %d, want %d (overlay rows subtracted)", got, wantWithOverlay)
	}

	// Closing it restores the original cap (no stale height left behind).
	h.update(func() { h.a.dismissStatus() })
	if got := h.transcriptHeight(); got != baseCap {
		t.Fatalf("transcript height after /status close = %d, want cap %d restored", got, baseCap)
	}

	// A terminal resize reflows the cap to the new screen height on the next draw.
	const taller = 40
	h.update(func() { h.screen.SetSize(80, taller) })
	wantTaller := taller - (bannerGapHeight + inputHeight + statusBarHeight)
	if got := h.transcriptHeight(); got != wantTaller {
		t.Fatalf("transcript height after resize = %d, want %d (reflowed to the new screen height)", got, wantTaller)
	}
}

// TestLaunchLayout_InputGrowsWithMultiLineDraft pins multi-line input growth:
// the input area keeps its prior fixed footprint for a single-line buffer (so the
// launch-layout cap math is unchanged for the one-line case), and grows one row per
// extra logical line of a multi-line draft — shrinking the transcript cap by exactly
// the rows the input claims.
func TestLaunchLayout_InputGrowsWithMultiLineDraft(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()

	// A single-line (here empty) buffer keeps the prior fixed footprint.
	if got := h.inputHeightRows(); got != inputHeight {
		t.Fatalf("input height at launch = %d, want %d (single-line footprint unchanged)", got, inputHeight)
	}

	// Overflow the transcript so its height sits at the cap and the input's effect on
	// the cap is observable.
	h.update(func() {
		for i := 0; i < 60; i++ {
			h.a.Append(fmt.Sprintf("line %d", i))
		}
	})
	singleCap := screenH - (bannerGapHeight + inputHeight + statusBarHeight)
	if got := h.transcriptHeight(); got != singleCap {
		t.Fatalf("transcript cap with single-line input = %d, want %d (unchanged one-line case)", got, singleCap)
	}

	// A three-line draft grows the input to three text rows plus the two chrome
	// rules, and the transcript cap shrinks by exactly the two extra rows.
	h.update(func() { h.a.input.SetText("one\ntwo\nthree") })
	wantInput := 3 + inputChromeRows
	if got := h.inputHeightRows(); got != wantInput {
		t.Fatalf("input height with a 3-line draft = %d, want %d (grew with the line count)", got, wantInput)
	}
	grownCap := screenH - (bannerGapHeight + wantInput + statusBarHeight)
	if got := h.transcriptHeight(); got != grownCap {
		t.Fatalf("transcript cap with a 3-line input = %d, want %d (input grew by 2)", got, grownCap)
	}
}

// TestLaunchLayout_LargePasteRespectsInputHeightCap pins large-paste capping under the
// adaptive cap: a paste with more logical lines than the height-aware input cap caps
// the input area at that many text rows plus the two chrome rules (App.inputRows), so
// the TextArea scrolls internally rather than the oversized draft pushing the
// transcript off screen — and the transcript still keeps exactly minTranscriptRows. A
// large paste is set directly on the input here; the bracketed-paste delivery path is
// covered by TestRun_BracketedPasteInsertsWithoutSubmitting.
func TestLaunchLayout_LargePasteRespectsInputHeightCap(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()

	// Overflow the transcript so its height sits at the cap and the input's effect on
	// the cap is observable.
	h.update(func() {
		for i := 0; i < 60; i++ {
			h.a.Append(fmt.Sprintf("line %d", i))
		}
	})

	// The adaptive cap at this height: the full screen minus the non-input chrome, the
	// input's own chrome rules, and the reserved transcript floor.
	capTextRows := screenH - (bannerGapHeight + statusBarHeight) - inputChromeRows - minTranscriptRows

	// A paste of many logical lines (well past the cap) caps the input at capTextRows
	// text rows plus the two chrome rules.
	lines := make([]string, capTextRows*2)
	for i := range lines {
		lines[i] = fmt.Sprintf("pasted line %d", i)
	}
	h.update(func() { h.a.input.SetText(strings.Join(lines, "\n")) })

	wantInput := capTextRows + inputChromeRows
	if got := h.inputHeightRows(); got != wantInput {
		t.Fatalf("input height for a large paste = %d, want cap %d (capTextRows + chrome)", got, wantInput)
	}

	// The transcript cap follows the capped input height, so the transcript holds at
	// the reserved floor rather than the oversized draft pushing it off screen.
	wantCap := screenH - (bannerGapHeight + wantInput + statusBarHeight)
	if got := h.transcriptHeight(); got != wantCap {
		t.Fatalf("transcript height with a large paste = %d, want %d (cap follows the capped input)", got, wantCap)
	}
	if wantCap != minTranscriptRows {
		t.Fatalf("transcript reservation at the cap = %d, want minTranscriptRows %d", wantCap, minTranscriptRows)
	}
}

// TestLaunchLayout_InputWrapsAndReflowsLongLine pins wrapped-row input height: a single
// logical line longer than the input width grows the input area to the wrapped-row
// count (so the whole line is visible wrapped, not scrolled within one row), the
// input reflows when the terminal width changes (narrower → more rows, wider →
// fewer), and beyond the height-aware cap (App.inputTextRowCap) it stops growing. The line is one unbroken
// token, so its wrapped rows are ceil(len / textWidth) where textWidth is the screen
// width minus the two-cell "> " label — driven by the live before-draw width.
func TestLaunchLayout_InputWrapsAndReflowsLongLine(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()

	// 100 unbroken chars at width 80 → text width 78 → ceil(100/78) = 2 wrapped rows
	// plus the two chrome rules.
	h.update(func() { h.a.input.SetText(strings.Repeat("a", 100)) })
	if got := h.inputHeightRows(); got != 2+inputChromeRows {
		t.Fatalf("input height for a long line at width 80 = %d, want %d (wrapped to 2 rows)", got, 2+inputChromeRows)
	}

	// Narrower terminal → text width 48 → ceil(100/48) = 3 rows: the input reflows
	// taller without re-setting the buffer.
	h.update(func() { h.screen.SetSize(50, screenH) })
	if got := h.inputHeightRows(); got != 3+inputChromeRows {
		t.Fatalf("input height after shrink to width 50 = %d, want %d (reflowed to 3 rows)", got, 3+inputChromeRows)
	}

	// Wider terminal → the line fits on one row → the input shrinks back to the
	// single-line footprint.
	h.update(func() { h.screen.SetSize(200, screenH) })
	if got := h.inputHeightRows(); got != inputHeight {
		t.Fatalf("input height after grow to width 200 = %d, want %d (single-line footprint)", got, inputHeight)
	}

	// Very narrow terminal with a long unbroken token → far more wrapped rows than the
	// height-aware cap, so the input caps at inputTextRowCap text rows plus the chrome
	// rules and the wrapped line scrolls internally rather than pushing the transcript
	// off screen. 300 chars at text width 10 → 30 wrapped rows, well past the cap.
	capTextRows := screenH - (bannerGapHeight + statusBarHeight) - inputChromeRows - minTranscriptRows
	h.update(func() {
		h.a.input.SetText(strings.Repeat("a", 300))
		h.screen.SetSize(12, screenH)
	})
	if got := h.inputHeightRows(); got != capTextRows+inputChromeRows {
		t.Fatalf("input height at width 12 = %d, want cap %d (inputTextRowCap + chrome)", got, capTextRows+inputChromeRows)
	}
}

// TestLaunchLayout_LongLineWrapKeepsFirstRowVisible pins first-row visibility on wrap: when a line
// wraps because the user types the wrap-triggering character (the replace path, not
// SetText), the first wrapped row must stay visible. tview scrolls the TextArea's
// rowOffset to 1 against the stale one-row height when the wrap happens; the
// before-draw hook grows the box but must also pull rowOffset back to 0, or the
// now-2-row box hides row 0. The line is typed character by character through the
// real input handler (rune EventKeys) so the rowOffset scroll actually fires — an
// existing SetText-based reflow test would miss it because SetText resets rowOffset.
// The assertions on the row offset and the first screen text row both fail before the
// fix and pass after.
func TestLaunchLayout_LongLineWrapKeepsFirstRowVisible(t *testing.T) {
	const screenW, screenH = 80, 25
	h := newLayoutHarness(t, screenW, screenH)
	defer h.stop()

	// "START" leads the buffer so the first wrapped row carries a detectable marker; if
	// row 0 were hidden, the visible first row would be the all-'a' wrapped remainder.
	// 105 chars at text width 78 (width 80 minus the "> " label) wrap to exactly 2 rows,
	// well under the height-aware cap, so the fits-the-cap offset reset applies.
	typed := "START" + strings.Repeat("a", 100)
	h.update(func() {
		handler := h.a.input.InputHandler()
		for _, r := range typed {
			handler(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone), func(tview.Primitive) {})
		}
	})

	var (
		offRow, inputH int
		firstRow       string
	)
	h.a.app.QueueUpdate(func() {
		offRow, _ = h.a.input.GetOffset()
		x, y, w, hh := h.a.input.GetRect()
		inputH = hh
		// The top rule sits on row y; the first text row is the next row down.
		var b strings.Builder
		for col := x; col < x+w; col++ {
			s, _, _ := h.screen.Get(col, y+1)
			b.WriteString(s)
		}
		firstRow = b.String()
	})

	if offRow != 0 {
		t.Errorf("input row offset after a char-by-char wrap = %d, want 0 (row 0 must stay visible)", offRow)
	}
	if want := 2 + inputChromeRows; inputH != want {
		t.Errorf("input height after wrap = %d, want %d (2 wrapped rows + chrome)", inputH, want)
	}
	if !strings.Contains(firstRow, "START") {
		t.Errorf("first input text row = %q, want it to show the start of the typed line (the \"START\" marker), not the wrapped remainder", firstRow)
	}
}

func TestLaunchLayout_ActiveTrackerAnchoredAboveInput(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()
	defer h.startTurn(60)()

	r := h.bands()
	r.assertAnchored(t, activeGapHeight)

	wantCap := screenH - (activeGapHeight + indicatorHeight + inputHeight + statusBarHeight)
	if r.transcriptH != wantCap {
		t.Errorf("transcript height with the tracker active = %d, want %d (the wider spacer and tracker row subtracted)", r.transcriptH, wantCap)
	}
	for row := r.gapY; row < r.gapY+r.gapH; row++ {
		if got := strings.TrimSpace(h.rowText(row)); got != "" {
			t.Errorf("separation row %d = %q, want a blank row between the transcript and the tracker", row, got)
		}
	}
	if got := h.rowText(r.indicatorY); !strings.Contains(got, indicatorWorkingActivity) {
		t.Errorf("tracker row = %q, want it to show %q", got, indicatorWorkingActivity)
	}
	if !strings.Contains(h.rowText(r.indicatorY), "tokens)") {
		t.Errorf("tracker row = %q, want the elapsed/token figures rendered with it", h.rowText(r.indicatorY))
	}
}

func TestLaunchLayout_ActiveTrackerSpacingByRowBudget(t *testing.T) {
	cases := []struct {
		name    string
		screenH int
		wantGap int
	}{
		{"roomy", 25, activeGapHeight},
		{"exactly fits the transcript floor", 14, activeGapHeight},
		{"one row short of the floor", 13, bannerGapHeight},
		{"constrained", 10, bannerGapHeight},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newLayoutHarness(t, 80, tc.screenH)
			defer h.stop()
			h.update(func() { h.screen.SetSize(80, tc.screenH) })
			defer h.startTurn(60)()

			r := h.bands()
			r.assertAnchored(t, tc.wantGap)
			if r.transcriptH < 1 {
				t.Errorf("transcript height = %d, want at least one visible row", r.transcriptH)
			}
			if r.inputEnd() > tc.screenH-statusBarHeight {
				t.Errorf("input occupies rows through %d, want it to end by %d (above the footer, not clipped off screen)", r.inputEnd()-1, tc.screenH-statusBarHeight-1)
			}
		})
	}
}

func TestLaunchLayout_ActiveMultiLineDraftKeepsTranscriptFloor(t *testing.T) {
	const screenH = 14
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()
	h.update(func() { h.screen.SetSize(80, screenH) })
	defer h.startTurn(60)()

	h.update(func() { h.a.input.SetText("one\ntwo\nthree") })
	r := h.bands()
	r.assertAnchored(t, activeGapHeight)
	if r.transcriptH < minTranscriptRows {
		t.Errorf("transcript height with a three-row draft = %d, want at least the floor %d", r.transcriptH, minTranscriptRows)
	}
	if want := minInputTextRows + inputChromeRows; r.inputH != want {
		t.Errorf("input height with a three-row draft = %d, want %d (inputTextRowCap holds the transcript floor)", r.inputH, want)
	}
	if r.inputEnd() > screenH-statusBarHeight {
		t.Errorf("input occupies rows through %d, want it to end by %d (above the footer)", r.inputEnd()-1, screenH-statusBarHeight-1)
	}
}

func TestLaunchLayout_ActiveTrackerReflowsWithGrowthResizeAndDraft(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()
	defer h.startTurn(60)()

	h.bands().assertAnchored(t, activeGapHeight)

	h.update(func() {
		for i := 0; i < 40; i++ {
			h.a.Append(fmt.Sprintf("more streamed line %d", i))
		}
	})
	grown := h.bands()
	grown.assertAnchored(t, activeGapHeight)
	wantCap := screenH - (activeGapHeight + indicatorHeight + inputHeight + statusBarHeight)
	if grown.transcriptH != wantCap {
		t.Errorf("transcript height after streamed growth = %d, want the cap %d", grown.transcriptH, wantCap)
	}

	const taller = 40
	h.update(func() { h.screen.SetSize(80, taller) })
	resized := h.bands()
	resized.assertAnchored(t, activeGapHeight)
	if want := taller - (activeGapHeight + indicatorHeight + inputHeight + statusBarHeight); resized.transcriptH != want {
		t.Errorf("transcript height after resize = %d, want %d", resized.transcriptH, want)
	}

	h.update(func() { h.a.input.SetText("one\ntwo\nthree") })
	drafted := h.bands()
	drafted.assertAnchored(t, activeGapHeight)
	if want := 3 + inputChromeRows; drafted.inputH != want {
		t.Errorf("input height with a 3-line draft = %d, want %d", drafted.inputH, want)
	}
	if want := taller - (activeGapHeight + indicatorHeight + drafted.inputH + statusBarHeight); drafted.transcriptH != want {
		t.Errorf("transcript height with a 3-line draft = %d, want %d", drafted.transcriptH, want)
	}

	h.update(func() { h.screen.SetSize(80, 13) })
	h.bands().assertAnchored(t, bannerGapHeight)
}

func TestLaunchLayout_ActiveTrackerStatesStayReadable(t *testing.T) {
	h := newLayoutHarness(t, 80, 25)
	defer h.stop()
	defer h.startTurn(60)()

	states := []struct {
		name string
		show func()
		want string
	}{
		{"provider waiting", func() { h.a.SetProviderIdle("OpenAI", 3*time.Second) }, idleIndicatorActivity("OpenAI")},
		{"reconnecting", func() { h.a.ShowRetryBackoff(2, 4) }, "Reconnecting…"},
		{"resumed working", h.a.ResumeRetry, indicatorWorkingActivity},
	}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			h.update(st.show)
			r := h.bands()
			r.assertAnchored(t, activeGapHeight)
			if got := h.rowText(r.indicatorY); !strings.Contains(got, st.want) {
				t.Errorf("tracker row = %q, want it to show %q", got, st.want)
			}
		})
	}
}

func TestLaunchLayout_ClearedTrackerRestoresSingleRowGap(t *testing.T) {
	const screenH = 25
	h := newLayoutHarness(t, 80, screenH)
	defer h.stop()

	clear := h.startTurn(60)
	clear()

	r := h.bands()
	if r.indicatorH != 0 {
		t.Errorf("tracker height after clear = %d, want 0 (collapsed)", r.indicatorH)
	}
	if r.gapH != bannerGapHeight {
		t.Errorf("spacer after clear = %d rows, want %d", r.gapH, bannerGapHeight)
	}
	if want := r.gapY + r.gapH; r.inputY != want {
		t.Errorf("input starts at row %d, want %d (blank row directly above the input)", r.inputY, want)
	}
	if want := screenH - (bannerGapHeight + inputHeight + statusBarHeight); r.transcriptH != want {
		t.Errorf("transcript height after clear = %d, want the un-tracked cap %d", r.transcriptH, want)
	}
}

// tagInjectionCases are style-tag sequences an adversarial user or model could
// emit; under the transcript's dynamic colors they must render literally rather
// than restyling (or vanishing from) the pane.
var tagInjectionCases = []struct {
	name string
	raw  string
}{
	{"color", "[red]danger"},
	{"hex", "[#00ff00]ok"},
	{"bold reset", "[::b]bold[::-]"},
	{"fg bg flags", "[yellow:blue:b]warn"},
}

// TestTranscript_EscapesTagInjectionAcrossPaths pins tag-injection escaping: tag-like
// text routed through the echo, streamed-delta, and notice paths renders literally
// in the visible transcript. The visible text is read with stripAll=true, which
// resolves escapes back to the literal brackets — so an unescaped tag (which would
// be consumed and stripped) is distinguishable from the escaped literal we want.
func TestTranscript_EscapesTagInjectionAcrossPaths(t *testing.T) {
	for _, tc := range tagInjectionCases {
		t.Run("echo/"+tc.name, func(t *testing.T) {
			a := New(func(string, ...sessions.ContentPart) bool { return true })
			if !a.SubmitInput(tc.raw) {
				t.Fatal("submit should be accepted")
			}
			if got, want := a.TranscriptText(), "▌ "+tc.raw; got != want {
				t.Fatalf("echoed text = %q, want literal %q", got, want)
			}
		})
		t.Run("delta/"+tc.name, func(t *testing.T) {
			a := New(nil)
			a.AppendStreamDelta(tc.raw)
			a.FinalizeStream()
			if got, want := a.TranscriptText(), tc.raw+visibleResponseLine; got != want {
				t.Fatalf("streamed text = %q, want literal %q", got, want)
			}
		})
		t.Run("notice/"+tc.name, func(t *testing.T) {
			a := New(nil)
			a.Notice(tc.raw)
			if got := a.TranscriptText(); got != tc.raw {
				t.Fatalf("notice text = %q, want literal %q", got, tc.raw)
			}
		})
	}
}

// TestTranscript_EscapesTagSplitAcrossDeltas proves the streamed-delta escaping
// happens over the accumulated reply, not per delta: a tag split across two
// deltas ("[re" then "d]hi") reassembles into "[red]hi" and must still render
// literally. Escaping each delta in isolation would miss the split tag and let it
// restyle the line — this is the case that rules that approach out.
func TestTranscript_EscapesTagSplitAcrossDeltas(t *testing.T) {
	a := New(nil)
	a.AppendStreamDelta("[re")
	a.AppendStreamDelta("d]hi")
	// While still streaming, the in-progress line already renders literally.
	if got := a.TranscriptText(); got != "[red]hi" {
		t.Fatalf("in-progress split-tag delta = %q, want literal %q", got, "[red]hi")
	}
	a.FinalizeStream()
	if got, want := a.TranscriptText(), "[red]hi"+visibleResponseLine; got != want {
		t.Fatalf("finalized split-tag delta = %q, want literal %q", got, want)
	}
}

func (h *layoutHarness) transcriptRows() (railed, plain []string) {
	h.t.Helper()
	b := h.bands()
	for y := b.transcriptY; y < b.transcriptEnd(); y++ {
		row := strings.TrimRight(h.rowText(y), " ")
		switch {
		case row == "":
		case strings.HasPrefix(row, "▌ "):
			railed = append(railed, strings.TrimPrefix(row, "▌ "))
		default:
			plain = append(plain, row)
		}
	}
	return railed, plain
}

func TestLaunchLayout_UserRailOnEveryWrappedScreenRow(t *testing.T) {
	const screenH = 25
	const assistantReply = "assistant reply remains unrailed across every wrapped display row"
	h := newLayoutHarness(t, 34, screenH)
	defer h.stop()

	h.update(func() {
		h.a.ReplaySessionRecords([]sessions.Record{userMsg(longUserPrompt), assistantMsg(assistantReply)})
	})

	for _, width := range []int{34, 22, 46, 22} {
		h.update(func() { h.screen.SetSize(width, screenH) })
		railed, plain := h.transcriptRows()
		if len(railed) < 2 {
			t.Fatalf("at width %d the user block drew %d railed row(s), want it wrapped across several", width, len(railed))
		}
		if got := strings.Join(railed, " "); got != longUserPrompt {
			t.Errorf("at width %d the railed rows read as %q, want the submitted prompt %q", width, got, longUserPrompt)
		}
		want := assistantReply + " " + codeControlIndent + responseCopyControl
		if got := strings.Join(plain, " "); got != want {
			t.Errorf("at width %d the unrailed rows = %q, want only the assistant reply and its response control %q (a rail-less row means a user continuation lost its rail)", width, plain, want)
		}
	}
}

func TestLaunchLayout_UserRailUsesActualVisualRows(t *testing.T) {
	const screenH = 40
	cases := []struct {
		name   string
		text   string
		widths []int
	}{
		{"space-wrapped sentence", longUserPrompt, []int{34, 22, 46, 22}},
		{"unbroken token", strings.Repeat("a", 100), []int{34, 22, 46, 22}},
		{"explicit newlines", "alpha\n" + longUserPrompt + "\nomega", []int{34, 22, 46, 22}},
		{"tab at the rail offset", "ab\tXYZ", []int{10}},
		{"tab after word wrap", "abcd \tABCDEFGH", []int{11}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newLayoutHarness(t, tc.widths[0], screenH)
			defer h.stop()
			h.update(func() { h.a.ReplaySessionRecords([]sessions.Record{userMsg(tc.text)}) })
			for _, width := range tc.widths {
				h.update(func() { h.screen.SetSize(width, screenH) })
				b := h.bands()
				var transcriptX int
				h.a.app.QueueUpdate(func() { transcriptX, _, _, _ = h.a.transcript.view.GetRect() })
				rows := 0
				for y := b.transcriptY; y < b.transcriptEnd(); y++ {
					row := strings.TrimRight(h.rowText(y), " ")
					if row == "" {
						continue
					}
					rows++
					if !strings.HasPrefix(row, "▌ ") {
						t.Fatalf("width %d row %d = %q, want a user rail", width, y, row)
					}
					style := h.cellStyle(transcriptX, y)
					fg, _, _ := style.Decompose()
					if fg != tcell.GetColor(accentTealHex) {
						t.Errorf("width %d row %d rail color = %v, want %v", width, y, fg, tcell.GetColor(accentTealHex))
					}
				}
				if rows < 2 {
					t.Fatalf("width %d drew %d user row(s), want wrapping", width, rows)
				}
			}
		})
	}
}
