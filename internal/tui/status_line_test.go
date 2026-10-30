// Tests for the persistent status-line footer and the input restyle
// (phase-1 chrome): the footer renderer and its no-model fallback, the App
// readback/refresh seam, the model/effort apply paths' post-success footer refresh
// (and the no-refresh-on-failure contract), the killed input-box blue
// (ContrastBackgroundColor default), and the input's top/bottom rules + teal prompt.
package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// errBoom is a sentinel apply error used to prove the footer does not refresh on a
// failed model/effort apply.
var errBoom = errors.New("apply: boom")

// visibleStatusLine renders RenderStatusLine's filled-segment markup through a
// dynamic-color TextView (matching the production bottom bar) and returns the visible
// text, so tests assert what the user sees (the segment values) rather than the fixed
// fill tags.
func visibleStatusLine(state StatusState) string {
	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetText(RenderStatusLine(state))
	return tv.GetText(true)
}

// TestLaunchBannerBar_FilledWidthAndContent pins the banner bar renderer at a fixed
// width: it carries "◆ codemeld v<version>" together at the left (the version directly after
// the wordmark, in the dim banner-version color), paints the teal fill (white-on-teal bold
// wordmark), and pads the remainder of the row so the fill spans exactly the given width. The
// version is never hardcoded — it is whatever the caller passes.
func TestLaunchBannerBar_FilledWidthAndContent(t *testing.T) {
	const width = 40
	raw := LaunchBannerBar("9.9.9", width)
	if !strings.HasPrefix(raw, "[#ffffff:#1f9e8f:b]") || !strings.HasSuffix(raw, "[-:-:-]") {
		t.Fatalf("banner bar %q, want it wrapped in the teal fill tag", raw)
	}
	// The version is drawn in the dim banner-version color, non-bold, right after the wordmark.
	if !strings.Contains(raw, "[#bfe6df:#1f9e8f:-]9.9.9") {
		t.Errorf("banner bar %q, want the dim non-bold version tag immediately after the wordmark", raw)
	}

	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetText(raw)
	visible := tv.GetText(true)
	if !strings.HasPrefix(visible, "◆ codemeld 9.9.9") {
		t.Errorf("banner bar visible %q, want it to start with ◆ codemeld 9.9.9 (version after the wordmark)", visible)
	}
	if got := tview.TaggedStringWidth(visible); got != width {
		t.Errorf("banner bar visible width = %d, want %d (padded to fill the row)", got, width)
	}
}

// TestLaunchBannerBar_EscapesTagLikeVersion pins the escaping contract for the banner
// version: a runtime version carrying a "[tag]"-like sequence must render literally rather
// than being parsed as dynamic-color markup. This regression-guards tview.Escape(version) in
// LaunchBannerBar — removing it makes the rendered text drop the bracketed run.
func TestLaunchBannerBar_EscapesTagLikeVersion(t *testing.T) {
	const width = 40
	raw := LaunchBannerBar("9[red]9", width)

	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetText(raw)
	visible := tv.GetText(true)
	if !strings.Contains(visible, "9[red]9") {
		t.Errorf("banner bar visible %q, want it to contain the literal version 9[red]9 (escaped, not parsed as markup)", visible)
	}
}

// TestLaunchBannerMeta_RampOrderAndEscaping pins the banner subtitle: the segments render
// in provider · model · effort · dir order, each wrapped in the cool-grey ramp tag that
// lightens left→right (provider darkest → dir lightest), and every runtime value is escaped
// so a "[tag]"-like path renders literally rather than as markup.
func TestLaunchBannerMeta_RampOrderAndEscaping(t *testing.T) {
	raw := LaunchBannerMeta("openai", "gpt-5", "medium", "/tmp/[red]work")

	// Each segment carries its ramp color, in left→light order.
	for _, want := range []string{
		"[" + bannerMetaProvider + "]openai[-]",
		"[" + bannerMetaModel + "]gpt-5[-]",
		"[" + bannerMetaEffort + "]medium effort[-]",
		"[" + bannerMetaDir + "]/tmp/[red[]work[-]", // tview.Escape turns "[red]" into "[red[]"
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("banner meta %q missing segment %q", raw, want)
		}
	}

	// The visible (tag-stripped) line is the single ordered subtitle, dir included, with the
	// bracketed path rendered literally.
	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetText(raw)
	if got := tv.GetText(true); got != "openai · gpt-5 · medium effort · /tmp/[red]work" {
		t.Errorf("banner meta visible = %q, want the ordered subtitle with the literal bracketed path", got)
	}
}

// TestLaunchBannerMeta_NoModelFallback pins the empty-selection case: with no model the line
// collapses to the "no model selected" fallback plus the launch dir, never blank fields.
func TestLaunchBannerMeta_NoModelFallback(t *testing.T) {
	raw := LaunchBannerMeta("", "", "", "/work/proj")
	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetText(raw)
	if got := tv.GetText(true); got != "no model selected · /work/proj" {
		t.Errorf("banner meta no-model = %q, want the fallback segment then the launch dir", got)
	}
}

func TestRenderStatusLine_SelectedAndFallback(t *testing.T) {
	selected := &statusStateFake{provider: "openai", modelID: "gpt-5", effort: "medium", launchDir: "/work/proj"}
	got := visibleStatusLine(selected)
	for _, want := range []string{"openai", "gpt-5", "medium", "/work/proj"} {
		if !strings.Contains(got, want) {
			t.Errorf("status bar segments %q missing %q", got, want)
		}
	}

	// No model selected: Selection returns empty strings, so the bar shows the explicit
	// fallback segment instead of blank provider/model/effort fields, still naming the
	// launch dir.
	none := visibleStatusLine(&statusStateFake{launchDir: "/work/proj"})
	if !strings.Contains(none, "no model selected") || !strings.Contains(none, "/work/proj") {
		t.Errorf("no-model status bar = %q, want the fallback segment and the launch dir", none)
	}
}

// TestRenderStatusLine_TwoToneSlateSegments pins two-tone segments: each segment renders a
// darker leading cap immediately before a lighter body in the cooler slate ramp, the dir
// segment is retained, and the cap/body colors lighten left→right across provider → dir.
func TestRenderStatusLine_TwoToneSlateSegments(t *testing.T) {
	state := &statusStateFake{provider: "openai", modelID: "gpt-5", effort: "medium", launchDir: "/work/proj"}
	raw := RenderStatusLine(state)
	// Each segment is a "[-:cap] [white:body] value [-:-]" two-tone block; the dir keeps its
	// own cap+body so the pill is retained, not dropped.
	wantFills := []struct{ cap, body string }{
		{statusSegmentCap1, statusSegmentBody1}, // provider
		{statusSegmentCap2, statusSegmentBody2}, // model
		{statusSegmentCap3, statusSegmentBody3}, // effort
		{statusSegmentCap4, statusSegmentBody4}, // dir (retained)
		{statusSegmentCap5, statusSegmentBody5}, // sandbox
	}
	for _, w := range wantFills {
		if !strings.Contains(raw, "[-:"+w.cap+"] [") {
			t.Errorf("status line %q missing the darker leading cap fill %q", raw, w.cap)
		}
		if !strings.Contains(raw, "["+chromeOnFillText+":"+w.body+"] ") {
			t.Errorf("status line %q missing the white-on-slate body fill %q", raw, w.body)
		}
	}
	last := -1
	for i, w := range wantFills {
		idx := strings.Index(raw, "[-:"+w.cap+"] ["+chromeOnFillText+":"+w.body+"] ")
		if idx <= last {
			t.Errorf("status line %q, want pill %d at %d after the previous pill at %d", raw, i+1, idx, last)
		}
		last = idx
	}
	// Segments butt directly together: one segment's reset is immediately followed by the
	// next segment's cap tag, with no single-space joiner (which would paint a
	// default-background gap between the pills).
	if !strings.Contains(raw, "[-:-][-:") {
		t.Errorf("status line %q, want segments concatenated with no gap (reset directly into the next cap)", raw)
	}
	if strings.Contains(raw, "[-:-] [-:") {
		t.Errorf("status line %q, want no single-space joiner painting a default-bg gap between pills", raw)
	}
}

// TestFooter_TwoRowsSegmentsThenModeRow pins the two-row footer: the footer is two stacked
// rows — row 1 the segments (no mode pill), row 2 the filled mode pill followed by the
// shift+tab hint — and statusBarHeight reflects two rows.
func TestFooter_TwoRowsSegmentsThenModeRow(t *testing.T) {
	if statusBarHeight != 2 {
		t.Fatalf("statusBarHeight = %d, want 2 (the two-row footer)", statusBarHeight)
	}
	a := New(nil)
	a.SetStatusLineState(&statusStateFake{provider: "openai", modelID: "gpt-5", effort: "medium", launchDir: "/work"})

	// The footer flex stacks statusBar (row 1) over statusModeRow (row 2).
	if got := a.statusBarRow.GetItemCount(); got != 2 {
		t.Fatalf("footer flex item count = %d, want 2 (segments row + mode row)", got)
	}
	if a.statusBarRow.GetItem(0) != a.statusBar || a.statusBarRow.GetItem(1) != a.statusModeRow {
		t.Errorf("footer rows in wrong order, want statusBar then statusModeRow")
	}

	// Row 1 carries the segments and not the mode pill bullet.
	seg := a.StatusLineText()
	if !strings.Contains(seg, "gpt-5") {
		t.Errorf("segment row = %q, want it to carry the selection", seg)
	}
	if strings.Contains(seg, "•") {
		t.Errorf("segment row = %q, want the mode pill on the second row, not here", seg)
	}
	// Row 2 carries the mode pill grouped immediately with the hint.
	mode := a.ModeHintText()
	if !strings.Contains(mode, "• plan") || !strings.Contains(mode, "shift+tab to cycle") {
		t.Errorf("mode row = %q, want the • plan pill followed by the shift+tab hint", mode)
	}
}

// TestRenderStatusLine_KeepsChatGPTProviderId pins the bar's provider id: the status bar renders the
// active selection's stable provider id (openai-chatgpt), never the "OpenAI ChatGPT"
// display name — display names belong only to picker group headers, while every
// persisted/status surface keeps the id.
func TestRenderStatusLine_KeepsChatGPTProviderId(t *testing.T) {
	state := &statusStateFake{provider: "openai-chatgpt", modelID: "gpt-5.5", effort: "medium", launchDir: "/work/proj"}
	got := visibleStatusLine(state)
	for _, want := range []string{"openai-chatgpt", "gpt-5.5", "medium", "/work/proj"} {
		if !strings.Contains(got, want) {
			t.Errorf("status bar = %q, missing %q (stable provider id segment)", got, want)
		}
	}
	if strings.Contains(got, "OpenAI ChatGPT") {
		t.Errorf("status bar = %q, want it to not substitute the display name", got)
	}
}

// TestRenderStatusLine_EscapesBracketDirInDynamicColorView pins the path-escaping
// contract: a launch dir containing a "[tag]"-like sequence must render literally through
// the dynamic-color bar instead of being swallowed as color markup.
func TestRenderStatusLine_EscapesBracketDirInDynamicColorView(t *testing.T) {
	state := &statusStateFake{provider: "open[blue]ai", modelID: "gpt-[yellow]", effort: "med[green]ium", launchDir: "/tmp/[red]work"}
	got := visibleStatusLine(state)
	for _, literal := range []string{"open[blue]ai", "gpt-[yellow]", "med[green]ium", "/tmp/[red]work"} {
		if !strings.Contains(got, literal) {
			t.Errorf("status bar dropped literal bracket data %q (parsed as markup): %q", literal, got)
		}
	}
}

func TestRenderStatusLine_EscapesControlCharactersInLaunchDir(t *testing.T) {
	state := &statusStateFake{provider: "openai", modelID: "gpt-5", effort: "medium", launchDir: "/w/x\x1b\x1b[2Jy\rz\nq\u009b"}
	escaped := `/w/x\x1B\x1B[2Jy\x0Dz\x0Aq\u009B`

	raw := RenderStatusLine(state)
	if !strings.Contains(raw, escaped) {
		t.Errorf("status bar = %q, want the launch dir escaped as %q", raw, escaped)
	}
	if strings.ContainsAny(raw, "\x1b\r\n\u009b") {
		t.Errorf("status bar carries a raw control from the launch dir: %q", raw)
	}
	if got := visibleStatusLine(state); !strings.Contains(got, escaped) {
		t.Errorf("visible status bar = %q, want it to contain %q", got, escaped)
	}
}

func TestStatusLine_RefreshReflectsInstalledState(t *testing.T) {
	a := New(nil)
	state := &statusStateFake{provider: "openai", modelID: "gpt-5", effort: "medium", launchDir: "/work"}

	// SetStatusLineState seeds the segment row immediately from the installed source. The
	// mode pill now lives on the second footer row (ModeHintText), not the segment row.
	a.SetStatusLineState(state)
	for _, want := range []string{"openai", "gpt-5", "medium", "/work"} {
		if got := a.StatusLineText(); !strings.Contains(got, want) {
			t.Fatalf("seeded segment row = %q, want it to contain %q", got, want)
		}
	}
	if got := a.ModeHintText(); !strings.Contains(got, "• plan") {
		t.Fatalf("seeded mode row = %q, want it to contain the default • plan pill", got)
	}

	// A later selection change is reflected after RefreshStatusLine re-reads the
	// (live) source — the bar is not a one-time snapshot.
	state.modelID = "gpt-5-pro"
	state.effort = "high"
	a.RefreshStatusLine()
	got := a.StatusLineText()
	for _, want := range []string{"gpt-5-pro", "high"} {
		if !strings.Contains(got, want) {
			t.Fatalf("refreshed bar = %q, want it to contain %q", got, want)
		}
	}
	if strings.Contains(got, "gpt-5 ") {
		t.Fatalf("refreshed bar = %q, still shows the stale model", got)
	}
}

func TestStatusLine_RefreshShowsPillOnlyWithoutState(t *testing.T) {
	a := New(nil) // no StatusState installed (unit-test construction)
	a.RefreshStatusLine()
	// Without a StatusState the segment row renders empty, but the mode row still shows the
	// pill (it is driven by the active mode, not the StatusState), defaulting to plan, plus
	// the shift+tab hint (the pill sits on its own row).
	if got := a.StatusLineText(); strings.TrimSpace(got) != "" {
		t.Fatalf("segment row = %q, want empty when no StatusState is installed", got)
	}
	got := a.ModeHintText()
	if !strings.Contains(got, "• plan") || !strings.Contains(got, "shift+tab to cycle") {
		t.Fatalf("mode row = %q, want the default • plan pill and the shift+tab hint", got)
	}
}

func TestEffort_RefreshFiresOnSuccessOnly(t *testing.T) {
	var refreshes int
	refresh := func() { refreshes++ }

	// Valid level applies → exactly one refresh.
	deps := EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}, Refresh: refresh}
	if _, res := dispatchEffort(t, deps, "/effort high"); res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if refreshes != 1 {
		t.Fatalf("refreshes after a successful /effort = %d, want 1", refreshes)
	}

	// Unsupported value rejected before apply → no refresh.
	refreshes = 0
	model := selectedModel()
	model.supported = []string{"low", "medium", "high"}
	dispatchEffort(t, EffortDeps{Model: model, Applier: &effortApplierFake{}, Refresh: refresh}, "/effort minimal")
	if refreshes != 0 {
		t.Fatalf("refreshes after a rejected /effort = %d, want 0", refreshes)
	}

	// No model selected → refused before apply → no refresh.
	refreshes = 0
	dispatchEffort(t, EffortDeps{Model: &effortModelFake{selected: false}, Applier: &effortApplierFake{}, Refresh: refresh}, "/effort high")
	if refreshes != 0 {
		t.Fatalf("refreshes on the no-selection path = %d, want 0", refreshes)
	}
}

func TestEffortPicker_RefreshFiresOnConfirmNotInert(t *testing.T) {
	var refreshes int
	a := New(nil)
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}, Refresh: func() { refreshes++ }})

	// A real apply (multi-effort confirm) refreshes the footer.
	a.confirmEffortSelection("high", "medium", false)
	if refreshes != 1 {
		t.Fatalf("refreshes after a CTRL-E confirm = %d, want 1", refreshes)
	}

	// The inert {default}-only re-selection writes nothing, so it must not refresh.
	refreshes = 0
	a.confirmEffortSelection("default", "default", true)
	if refreshes != 0 {
		t.Fatalf("refreshes after the inert default-only confirm = %d, want 0", refreshes)
	}
}

func TestEffortPicker_RefreshNotFiredOnApplyError(t *testing.T) {
	var refreshes int
	a := New(nil)
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{err: errBoom}, Refresh: func() { refreshes++ }})

	a.confirmEffortSelection("high", "medium", false)
	if refreshes != 0 {
		t.Fatalf("refreshes after a failed apply = %d, want 0 (footer must not update on error)", refreshes)
	}
}

func TestModel_RefreshFiresOnSuccessOnly(t *testing.T) {
	var refreshes int
	refresh := func() { refreshes++ }

	deps := ModelDeps{Model: selectedCatalog(), Applier: &modelApplierFake{}, Refresh: refresh}
	if _, res := dispatchModel(t, deps, "/model gpt-5-mini"); res.Err != nil {
		t.Fatalf("dispatch err = %v, want nil", res.Err)
	}
	if refreshes != 1 {
		t.Fatalf("refreshes after a successful /model = %d, want 1", refreshes)
	}

	// Unsupported id rejected before apply → no refresh.
	refreshes = 0
	dispatchModel(t, ModelDeps{Model: selectedCatalog(), Applier: &modelApplierFake{}, Refresh: refresh}, "/model not-a-model")
	if refreshes != 0 {
		t.Fatalf("refreshes after a rejected /model = %d, want 0", refreshes)
	}
}

func TestModelPicker_RefreshFiresOnConfirmNotError(t *testing.T) {
	var refreshes int

	a := New(nil)
	a.SetModelPickerDeps(ModelPickerDeps{Applier: &providerModelApplierFake{}, Refresh: func() { refreshes++ }})
	a.confirmModelSelection(ProviderModel{Provider: "openai", ModelID: "gpt-5"}, "medium")
	if refreshes != 1 {
		t.Fatalf("refreshes after a CTRL-M confirm = %d, want 1", refreshes)
	}

	refreshes = 0
	a.SetModelPickerDeps(ModelPickerDeps{Applier: &providerModelApplierFake{err: errBoom}, Refresh: func() { refreshes++ }})
	a.confirmModelSelection(ProviderModel{Provider: "openai", ModelID: "gpt-5"}, "medium")
	if refreshes != 0 {
		t.Fatalf("refreshes after a failed CTRL-M apply = %d, want 0", refreshes)
	}
}

func TestApplyTheme_DefaultsContrastBackground(t *testing.T) {
	// Reset to tview's hardcoded blue, then prove applyTheme defaults it so the input
	// box no longer snapshots blue as its field background at construction.
	tview.Styles.ContrastBackgroundColor = tcell.ColorBlue
	applyTheme()
	if tview.Styles.ContrastBackgroundColor != tcell.ColorDefault {
		t.Fatalf("ContrastBackgroundColor = %v, want tcell.ColorDefault (the input-box blue must be killed)", tview.Styles.ContrastBackgroundColor)
	}
}

// TestInput_RendersTopBottomRulesTealPrompt launches the shell on a simulation
// screen and asserts the input chrome: a full-width horizontal
// rule above and below the prompt with no left/right vertical sides, the "›" prompt glyph
// on the row between the two rules, and the prompt drawn in the teal brand accent
// (accentTeal) rather than the old black. The input is the only chrome drawing box runes at
// launch (the /status overlay and transcript are zero-height and the panel page is hidden),
// so any vertical/corner border rune on screen would be a regression to the old four-sided
// box.
func TestInput_RendersTopBottomRulesTealPrompt(t *testing.T) {
	a := New(nil)
	ready := make(chan struct{}, 1)
	a.app.SetAfterDrawFunc(func(tcell.Screen) {
		select {
		case ready <- struct{}{}:
		default:
		}
	})
	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(40, 10)
	a.app.SetScreen(screen)

	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("app did not draw within 2s")
	}

	// Inspect the cell grid on the event-loop goroutine so the read is serialized
	// with the draw (same discipline as screenTextSync).
	var (
		ruleRows  []int // rows containing at least one horizontal-rule rune
		promptRow = -1  // row carrying the '›' prompt glyph
		promptFg  tcell.Color
		vertical  bool // any vertical/corner border rune anywhere (a regression)
	)
	a.app.QueueUpdate(func() {
		cells, width, height := screen.GetContents()
		for row := 0; row < height; row++ {
			rowHasRule := false
			for col := 0; col < width; col++ {
				c := cells[row*width+col]
				if len(c.Runes) == 0 {
					continue
				}
				switch c.Runes[0] {
				case tcell.RuneHLine:
					rowHasRule = true
				case tcell.RuneVLine,
					tcell.RuneULCorner, tcell.RuneURCorner,
					tcell.RuneLLCorner, tcell.RuneLRCorner,
					'║', '╔', '╗', '╚', '╝': // single-line set is the tcell.Rune* constants above; these are the double-line (focused) set
					vertical = true
				case '›':
					promptRow = row
					promptFg, _, _ = c.Style.Decompose()
				}
			}
			if rowHasRule {
				ruleRows = append(ruleRows, row)
			}
		}
	})
	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}

	if vertical {
		t.Fatalf("input drew a vertical/corner border rune; expected top/bottom rules only")
	}
	if len(ruleRows) < 2 {
		t.Fatalf("expected at least two rows with horizontal rules (input top + bottom), got rows %v", ruleRows)
	}
	if promptRow < 0 {
		t.Fatal("'›' prompt glyph not found on screen")
	}
	topRule, bottomRule := ruleRows[0], ruleRows[len(ruleRows)-1]
	if promptRow <= topRule || promptRow >= bottomRule {
		t.Fatalf("'›' prompt on row %d, want strictly between the top rule (%d) and bottom rule (%d)", promptRow, topRule, bottomRule)
	}
	if promptFg.Hex() != accentTeal.Hex() {
		t.Fatalf("'›' prompt foreground = %v, want the teal accent %v", promptFg, accentTeal)
	}
}

func TestRenderStatusLine_EndsWithSandboxPill(t *testing.T) {
	for _, sandbox := range []string{"on", "off", "unavailable"} {
		for name, state := range map[string]*statusStateFake{
			"model selected":    {provider: "openai", modelID: "gpt-5", effort: "medium", launchDir: "/work/proj", sandbox: sandbox, reason: "linux: not yet supported"},
			"no model selected": {launchDir: "/work/proj", sandbox: sandbox, reason: "linux: not yet supported"},
		} {
			raw := RenderStatusLine(state)
			wantTail := statusSegment(statusSegmentCap4, statusSegmentBody4, "/work/proj") +
				statusSegment(statusSegmentCap5, statusSegmentBody5, "sandbox: "+sandbox)
			if !strings.HasSuffix(raw, wantTail) {
				t.Errorf("%s/%s: status line %q, want it to end with the dir pill then %q", name, sandbox, raw, "sandbox: "+sandbox)
			}
			if strings.Contains(visibleStatusLine(state), "not yet supported") {
				t.Errorf("%s/%s: status line shows the reason; the pill carries only the sandbox state", name, sandbox)
			}
		}
	}
}
