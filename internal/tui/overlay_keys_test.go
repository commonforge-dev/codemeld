// Regression coverage for overlay key-handling priorities. While any overlay registered in
// overlays() holds the screen, the input area's own key handlers (history ↑/↓, Tab
// completion, Enter submit) must be bypassed, app-level shortcuts must not mutate
// input-level state or stack a second overlay, and CTRL-L must repaint without
// dismissing the overlay. These lock in the as-built routing —
// per-overlay focus plus App.handleGlobalKey — rather than a separate dispatcher.
package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/sessions"
)

// req600Overlay opens one overlays() entry on a fresh app, fully wiring whatever deps that
// overlay needs so it actually mounts and takes focus.
type req600Overlay struct {
	name string
	open func(*testing.T, *App)
	// settle blocks until a dismissal that completes on the tview event loop has finished.
	// Only the permission prompt needs one: it is the single overlay that cannot be mounted
	// without a running application.
	settle func(*testing.T, *App)
}

func req600Overlays() []req600Overlay {
	return []req600Overlay{
		{name: "status", open: func(_ *testing.T, a *App) { a.ShowStatus("snapshot") }},
		{name: "panel", open: func(_ *testing.T, a *App) { a.ShowPanel("help") }},
		{name: "effortPicker", open: func(_ *testing.T, a *App) {
			a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}})
			a.openEffortPicker()
		}},
		{name: "modelPicker", open: func(_ *testing.T, a *App) {
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: &providerModelApplierFake{}})
			a.openModelPicker()
		}},
		{name: "resumePicker", open: func(_ *testing.T, a *App) {
			a.openResumePicker(resumePickerEntries(), func(PickerResult) {}, ResumeActions{})
		}},
		{name: "reverseSearch", open: func(_ *testing.T, a *App) {
			a.history.Append("git status")
			a.history.Append("make build")
			a.openReverseSearch()
		}},
		{name: "secretPrompt", open: func(_ *testing.T, a *App) {
			a.OpenSecretPrompt(SecretPromptRequest{Label: "API key:", OnSubmit: func(string) {}})
		}},
		{name: "questionForm", open: func(t *testing.T, a *App) { openQuestions(t, a, questionFixture()) }},
		{name: "settingsPicker", open: func(_ *testing.T, a *App) {
			openEntryPicker(a, permissionsFixture(), nil, nil)
		}},
		{name: "blockedPicker", open: func(_ *testing.T, a *App) {
			a.openBlockedPicker([]BlockedRow{{Kind: BlockedRowFloor, Path: "/home/u/.codemeld"}})
		}},
		{name: "blockedDestination", open: func(_ *testing.T, a *App) {
			a.openBlockedDestination("/etc/secrets", func(string, BlockedDestination) string { return "" })
		}},
		{name: "filePicker", open: func(t *testing.T, a *App) {
			withFileRefSources(t, a, "main.go")
			collectFileRefTimers(a)
			a.input.SetText("draft ")
			a.input.SetText("draft @")
		}},
		{name: "slashPicker", open: func(_ *testing.T, a *App) {
			a.SetRegistry(BuildRegistry(nil))
			a.input.SetText("")
			a.input.SetText("/")
		}},
		{name: "connectPicker", open: func(_ *testing.T, a *App) {
			a.OpenConnectPicker([]ConnectProviderOption{{ID: "openai", Label: "OpenAI"}}, func(string) {})
		}},
		{
			name: "prompt",
			open: func(t *testing.T, a *App) {
				h := startPrompt(t, a, fullPromptRequest())
				t.Cleanup(func() {
					a.dismissPrompt()
					h.await()
				})
			},
			settle: func(t *testing.T, a *App) {
				waitOnLoop(t, a, "prompt teardown", func() bool { return !a.promptOpen })
			},
		},
	}
}

func snapshotOverlays(a *App) string {
	var open []string
	for _, o := range a.overlays() {
		if o.isOpen() {
			open = append(open, o.name)
		}
	}
	return strings.Join(open, ",")
}

func centrallyDismissed(a *App, name string) bool {
	for _, o := range a.overlays() {
		if o.name == name {
			return o.dismiss != nil
		}
	}
	return false
}

// A roster entry with no fixture would silently join none of the focus, shortcut, or ESC
// loops below, which is the drift that left six overlays untested.
func TestReq600Overlays_MatchesRoster(t *testing.T) {
	fixtures := map[string]int{}
	for _, tc := range req600Overlays() {
		fixtures[tc.name]++
	}
	for _, o := range New(nil).overlays() {
		switch fixtures[o.name] {
		case 1:
		case 0:
			t.Errorf("overlays() entry %q has no req600Overlays fixture; add one so the shared key loops cover it", o.name)
		default:
			t.Errorf("req600Overlays holds %d entries named %q, want exactly one", fixtures[o.name], o.name)
		}
		delete(fixtures, o.name)
	}
	for name := range fixtures {
		t.Errorf("req600Overlays entry %q names no overlays() entry", name)
	}
}

// TestOverlayOpen_InputDoesNotHoldFocus is the core invariant: every
// overlay moves focus off the input area while it is open. Because the input's
// history ↑/↓, Tab completion, and Enter-submit handlers live in App.handleInputKey
// / the input field's done func — both keyed on the input holding focus — an
// overlay that holds focus is exactly what makes those input-level behaviors
// no-ops for ↑/↓/Tab/Enter without any per-key suppression.
func TestOverlayOpen_InputDoesNotHoldFocus(t *testing.T) {
	var inputPrim tview.Primitive
	for _, tc := range req600Overlays() {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			inputPrim = a.input
			tc.open(t, a)
			if !a.anyOverlayOpen() {
				t.Fatalf("setup: %s overlay did not open", tc.name)
			}
			if a.app.GetFocus() == inputPrim {
				t.Errorf("input area holds focus while %s overlay is open; ↑/↓/Tab/Enter would reach the input handlers", tc.name)
			}
		})
	}
}

// TestOverlayOpen_GlobalShortcutsAreNoOps proves app-level shortcuts are consumed
// while an overlay is open and neither open a second overlay, dismiss the current
// one, nor disturb the input buffer. The resume picker owns CTRL-R/CTRL-D itself,
// so those two are covered by TestResumePicker_CtrlRAndCtrlDDelegatedToOverlayBinding.
func TestOverlayOpen_GlobalShortcutsAreNoOps(t *testing.T) {
	shortcuts := []struct {
		name string
		key  tcell.Key
	}{
		{"CTRL-E", tcell.KeyCtrlE},
		{"CTRL-M", tcell.KeyCtrlM},
		{"CTRL-R", tcell.KeyCtrlR},
		{"CTRL-D", tcell.KeyCtrlD},
		{"CTRL-V", tcell.KeyCtrlV},
	}
	for _, oc := range req600Overlays() {
		for _, sc := range shortcuts {
			t.Run(oc.name+"/"+sc.name, func(t *testing.T) {
				if oc.name == "resumePicker" && (sc.key == tcell.KeyCtrlR || sc.key == tcell.KeyCtrlD) {
					t.Skip("resume picker owns these shortcuts")
				}
				a := New(nil)
				a.input.SetText("draft")
				oc.open(t, a)
				before := snapshotOverlays(a)
				draft := a.input.GetText()

				if ev := a.handleGlobalKey(tcell.NewEventKey(sc.key, 0, tcell.ModNone)); ev != nil {
					t.Errorf("%s returned %v while %s open, want nil (consumed)", sc.name, ev, oc.name)
				}
				if got := snapshotOverlays(a); got != before {
					t.Errorf("%s changed overlay state while %s open: before %q after %q", sc.name, oc.name, before, got)
				}
				if got := a.input.GetText(); got != draft {
					t.Errorf("%s mutated the input buffer while %s open: got %q, want %q", sc.name, oc.name, got, draft)
				}
			})
		}
	}
}

// TestModelPicker_CtrlRLocalToPicker proves that an open model picker consumes
// Ctrl-R for forced refresh before the global reverse-search handler would see it,
// while the same key still opens reverse search when no model picker is open.
// The resume picker's own Ctrl-R pass-through (TestResumePicker_CtrlRAndCtrlDDelegatedToOverlayBinding)
// is unchanged.
func TestModelPicker_CtrlRLocalToPicker(t *testing.T) {
	t.Run("model picker open consumes Ctrl-R", func(t *testing.T) {
		a := New(nil)
		cat := refreshTriggerCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		if !a.modelPickerOpen {
			t.Fatal("setup: model picker did not open")
		}
		before := len(fake.calls)
		a.input.SetText("draft")

		if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone)); ev != nil {
			t.Errorf("Ctrl-R returned %v while model picker open, want nil (consumed by picker)", ev)
		}
		if !a.modelPickerOpen {
			t.Error("model picker dismissed by Ctrl-R; it must stay open")
		}
		if len(fake.calls) != before+1 {
			t.Errorf("Ctrl-R produced %d new requests, want exactly one forced refresh", len(fake.calls)-before)
		}
		if a.reverseSearchOpen {
			t.Error("reverse search opened by Ctrl-R while model picker is open; picker must own it")
		}
		if got := a.input.GetText(); got != "draft" {
			t.Errorf("input buffer = %q after Ctrl-R under model picker, want unchanged %q", got, "draft")
		}
	})

	t.Run("no model picker opens reverse search", func(t *testing.T) {
		a := New(nil)
		a.history.Append("git status")
		a.history.Append("make build")
		a.input.SetText("draft")

		if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModNone)); ev != nil {
			t.Errorf("Ctrl-R returned %v with no model picker, want nil (consumed by reverse search)", ev)
		}
		if !a.reverseSearchOpen {
			t.Error("reverse search did not open; Ctrl-R must open it when no model picker is open")
		}
	})

	t.Run("lowercase r reaches filter field", func(t *testing.T) {
		a := New(nil)
		cat := refreshTriggerCatalog()
		fake := &refreshCatalogFake{}
		a.SetModelPickerDeps(ModelPickerDeps{Catalog: cat, Applier: &providerModelApplierFake{}, RefreshCatalog: fake.refresh})
		a.openModelPicker()
		before := len(fake.calls)

		ev := tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone)
		if got := a.handleGlobalKey(ev); got != ev {
			t.Errorf("global capture consumed lowercase r while model picker open; it must pass through to the filter field")
		}
		if len(fake.calls) != before {
			t.Errorf("lowercase r triggered %d refresh requests, want 0 (only Ctrl-R should refresh)", len(fake.calls)-before)
		}
	})
}

// TestOverlayOpen_GlobalKeyDoesNotHijackOverlayOwnedKeys proves the app-level
// capture passes ↑/↓/Tab/Enter through unchanged while an overlay is open, so they
// reach the focused overlay's own bindings rather than being routed to input
// history nav, Tab completion, or submit. CTRL-M (77) is distinct from Enter
// (KeyCR, 13), so a passed-through Enter is never caught by the model-picker case.
func TestOverlayOpen_GlobalKeyDoesNotHijackOverlayOwnedKeys(t *testing.T) {
	keys := []struct {
		name string
		key  tcell.Key
	}{
		{"Up", tcell.KeyUp},
		{"Down", tcell.KeyDown},
		{"Tab", tcell.KeyTab},
		{"Enter", tcell.KeyEnter},
	}
	for _, oc := range req600Overlays() {
		for _, kc := range keys {
			t.Run(oc.name+"/"+kc.name, func(t *testing.T) {
				a := New(nil)
				oc.open(t, a)
				in := tcell.NewEventKey(kc.key, 0, tcell.ModNone)
				if ev := a.handleGlobalKey(in); ev != in {
					t.Errorf("global capture consumed/altered %s while %s open (got %v); it must pass through to the focused overlay", kc.name, oc.name, ev)
				}
			})
		}
	}
}

// TestStatusOverlay_ArrowsConsumedWithoutHistoryNav covers the "unbound ↑/↓" case
// the /status snapshot has no arrow navigation of its own, so it
// consumes ↑/↓ as no-ops at the overlay level and they must not fall through to the
// input's history navigation. The buffer and the history cursor stay put.
func TestStatusOverlay_ArrowsConsumedWithoutHistoryNav(t *testing.T) {
	a := New(nil)
	a.history.Append("first")
	a.history.Append("second")
	a.input.SetText("draft")
	a.ShowStatus("snapshot")

	for _, k := range []tcell.Key{tcell.KeyUp, tcell.KeyDown} {
		if ev := a.handleStatusKey(tcell.NewEventKey(k, 0, tcell.ModNone)); ev != nil {
			t.Errorf("status overlay returned %v for %v, want nil (consumed, no fall-through)", ev, k)
		}
	}
	if a.history.navigating() {
		t.Error("history began navigating while the status overlay consumed ↑/↓; req 600 forbids input-history nav under an overlay")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Errorf("input buffer = %q after ↑/↓ under the status overlay, want unchanged %q", got, "draft")
	}
}

// TestReverseSearchOverlay_ArrowsRoutedToOverlayNotHistory covers the "bound ↑/↓"
// case: the reverse-search overlay owns ↑/↓ (phase 1 keeps the single
// most-recent match selected), consuming them at the overlay level so they never
// reach the input's history navigation. The input buffer and history cursor stay
// put; the match is unchanged.
func TestReverseSearchOverlay_ArrowsRoutedToOverlayNotHistory(t *testing.T) {
	a := New(nil)
	a.history.Append("git status")
	a.history.Append("make build")
	a.input.SetText("draft")
	a.openReverseSearch()

	for _, k := range []tcell.Key{tcell.KeyUp, tcell.KeyDown} {
		if ev := a.reverseSearchFieldKeys(tcell.NewEventKey(k, 0, tcell.ModNone)); ev != nil {
			t.Errorf("reverse-search overlay returned %v for %v, want nil (consumed by overlay)", ev, k)
		}
	}
	if !a.reverseSearchOpen {
		t.Fatal("reverse-search closed by ↑/↓; the overlay owns them in phase 1")
	}
	if a.history.navigating() {
		t.Error("history began navigating while reverse-search consumed ↑/↓; the overlay must own them")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Errorf("input buffer = %q after ↑/↓ under reverse-search, want unchanged %q", got, "draft")
	}
	if a.reverseSearch.match != "make build" {
		t.Errorf("match after ↑/↓ = %q, want unchanged most-recent", a.reverseSearch.match)
	}
}

// TestOverlayOpen_CtrlLRepaintsWithoutReplacingOverlay covers the open-overlay key
// rules' CTRL-L clause for a really-mounted overlay (not just the statusOpen flag): the repaint
// fires exactly once and leaves the overlay open, its page mounted, and focus
// unchanged. The effort picker stands in for the pageful overlays.
func TestOverlayOpen_CtrlLRepaintsWithoutReplacingOverlay(t *testing.T) {
	a := New(nil)
	draws := 0
	a.draw = func() { draws++ }
	a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}})
	a.openEffortPicker()
	if !a.effortPickerOpen || !a.pages.HasPage(effortPickerPage) {
		t.Fatal("setup: effort picker did not open")
	}
	focusBefore := a.app.GetFocus()

	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlL, 0, tcell.ModNone)); ev != nil {
		t.Errorf("CTRL-L returned %v with the effort picker open, want nil (consumed)", ev)
	}
	if draws != 1 {
		t.Errorf("draw seam called %d times, want exactly 1", draws)
	}
	if !a.effortPickerOpen || !a.pages.HasPage(effortPickerPage) {
		t.Error("CTRL-L dismissed or replaced the effort picker; it must only repaint")
	}
	if a.app.GetFocus() != focusBefore {
		t.Error("CTRL-L changed focus while the effort picker was open")
	}
}

// TestOverlayOpen_EscDelegatesToCentralDismissal covers the open-overlay key rules'
// ESC clause for the overlays the central ESC priority path owns: with no stream active, ESC
// dismisses the open overlay via that overlay's own dismissal and returns focus to
// the input without touching the buffer — not through normal input handling.
func TestOverlayOpen_EscDelegatesToCentralDismissal(t *testing.T) {
	var inputPrim tview.Primitive
	roster := New(nil)
	for _, tc := range req600Overlays() {
		if !centrallyDismissed(roster, tc.name) {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			inputPrim = a.input
			a.input.SetText("draft")
			tc.open(t, a)
			if !a.anyOverlayOpen() {
				t.Fatalf("setup: %s overlay did not open", tc.name)
			}
			// The '@' and '/' pickers own their trigger literal, so the draft under test is
			// whatever the opener left behind rather than a fixed string.
			draft := a.input.GetText()

			a.HandleEsc()
			if tc.settle != nil {
				tc.settle(t, a)
			}

			if a.anyOverlayOpen() {
				t.Errorf("%s overlay still open after ESC; ESC must delegate to its dismissal binding", tc.name)
			}
			if a.app.GetFocus() != inputPrim {
				t.Errorf("focus not restored to the input after dismissing %s via ESC", tc.name)
			}
			if got := a.input.GetText(); got != draft {
				t.Errorf("input buffer = %q after ESC dismissing %s, want preserved %q", got, tc.name, draft)
			}
		})
	}
}

// TestOverlayOpen_EscOverActiveStreamDismissesBeforeInterrupting covers the priority the idle
// loop above cannot see: with a turn in flight the first ESC must still close the overlay and
// record nothing. /status is the one entry that then disarms the following press, spending it
// on the interrupt hint instead.
func TestOverlayOpen_EscOverActiveStreamDismissesBeforeInterrupting(t *testing.T) {
	roster := New(nil)
	for _, tc := range req600Overlays() {
		if !centrallyDismissed(roster, tc.name) {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			a, store, canceller := escGuardApp(t, true)
			a.dismissStatus()
			a.input.SetText("draft")
			tc.open(t, a)
			if !a.anyOverlayOpen() {
				t.Fatalf("setup: %s overlay did not open", tc.name)
			}
			draft := a.input.GetText()

			a.HandleEsc()
			if tc.settle != nil {
				tc.settle(t, a)
			}

			if a.anyOverlayOpen() {
				t.Fatalf("%s overlay still open after ESC; it owns ESC ahead of the stream", tc.name)
			}
			if canceller.calls != 0 {
				t.Fatalf("canceller called %d times dismissing %s, want 0", canceller.calls, tc.name)
			}
			if len(store.Records()) != 0 {
				t.Fatalf("records = %d after dismissing %s, want 0 (no stream_interrupted)", len(store.Records()), tc.name)
			}
			// The question form is the one overlay whose dismissal still delivers a tool
			// result, so the turn goes on and its pre-form prose has to be sealed instead of
			// absorbing whatever the model says next. Sealing is not interrupting: the
			// assertions above already pin that no interrupt was recorded.
			if wantStreaming := tc.name != "questionForm"; a.transcript.streaming != wantStreaming {
				t.Fatalf("transcript.streaming = %v after the %s ESC, want %v", a.transcript.streaming, tc.name, wantStreaming)
			}
			if got := a.input.GetText(); got != draft {
				t.Fatalf("input buffer = %q after ESC dismissing %s, want preserved %q", got, tc.name, draft)
			}

			if tc.name == "status" {
				a.HandleEsc()

				if got := a.NoticeText(); got != escInterruptHintText {
					t.Fatalf("notice after the second ESC = %q, want %q", got, escInterruptHintText)
				}
				if canceller.calls != 0 {
					t.Fatalf("canceller called %d times on the disarmed ESC, want 0", canceller.calls)
				}
			}

			a.HandleEsc()

			if canceller.calls != 1 {
				t.Fatalf("canceller called %d times, want 1 (the press after the dismissal interrupts)", canceller.calls)
			}
			if interrupt := onlyStreamInterrupted(t, store); interrupt.Source != "esc" {
				t.Fatalf("stream_interrupted source = %q, want esc", interrupt.Source)
			}
		})
	}
}

// TestResumePicker_EscDelegatedToOverlayBinding covers the /resume exception: with
// no stream active, the app-level capture does not consume ESC (it returns the
// event) so it reaches the resume list's own ESC binding (continuation
// model). The central ESC priority path neither dismisses the picker nor falls through to
// normal input handling — delegation is what makes the overlay's binding run.
func TestResumePicker_EscDelegatedToOverlayBinding(t *testing.T) {
	a := New(nil)
	a.input.SetText("draft")
	a.openResumePicker(resumePickerEntries(), func(PickerResult) {}, ResumeActions{})
	if !a.resumePickerOpen {
		t.Fatal("setup: resume picker did not open")
	}

	esc := tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)
	if ev := a.handleGlobalKey(esc); ev != esc {
		t.Errorf("global capture returned %v for ESC while the resume picker is open, want pass-through to the overlay's own ESC binding", ev)
	}
	if !a.resumePickerOpen {
		t.Error("central ESC path dismissed the resume picker; req 590 routes its ESC through the list's own binding")
	}
	if got := a.input.GetText(); got != "draft" {
		t.Errorf("input buffer = %q after ESC under the resume picker, want unchanged %q", got, "draft")
	}
}

// TestResumePicker_CtrlRAndCtrlDDelegatedToOverlayBinding covers the /resume
// shortcut exception: CTRL-R and CTRL-D must pass through the app-level capture
// so the focused resume table can open rename/delete through resumePickerKeys.
func TestResumePicker_CtrlRAndCtrlDDelegatedToOverlayBinding(t *testing.T) {
	a := New(nil)
	a.input.SetText("draft")
	a.openResumePicker(resumePickerEntries(), func(PickerResult) {}, ResumeActions{})
	if !a.resumePickerOpen {
		t.Fatal("setup: resume picker did not open")
	}

	for _, tc := range []struct {
		name string
		key  tcell.Key
	}{
		{"CTRL-R", tcell.KeyCtrlR},
		{"CTRL-D", tcell.KeyCtrlD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := tcell.NewEventKey(tc.key, 0, tcell.ModNone)
			if got := a.handleGlobalKey(ev); got != ev {
				t.Errorf("global capture returned %v for %s while the resume picker is open, want pass-through to the overlay's own binding", got, tc.name)
			}
			if !a.resumePickerOpen {
				t.Errorf("global %s path dismissed the resume picker", tc.name)
			}
			if got := a.input.GetText(); got != "draft" {
				t.Errorf("input buffer = %q after %s under the resume picker, want unchanged %q", got, tc.name, "draft")
			}
		})
	}
}

// TestOverlayOpen_EnterDelegatesToOverlayBinding covers the open-overlay key
// rules' Enter clause behaviorally: with an overlay open and a submit hook installed, the overlay owns
// Enter (the focused overlay's binding fires), so submit must not run. The
// reverse-search overlay's Enter accepts the current match into the buffer rather
// than submitting it; the input's Enter-submit path stays dormant.
func TestOverlayOpen_EnterDelegatesToOverlayBinding(t *testing.T) {
	submitted := 0
	a := New(func(string, ...sessions.ContentPart) bool { submitted++; return true })
	a.history.Append("git status")
	a.input.SetText("draft")
	a.openReverseSearch()

	// Enter through the overlay's own key handler accepts the match; it must not
	// reach submitCurrent.
	if ev := a.reverseSearchFieldKeys(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)); ev != nil {
		t.Errorf("reverse-search Enter returned %v, want nil (consumed by the overlay)", ev)
	}
	if submitted != 0 {
		t.Errorf("submit hook fired %d times on Enter under reverse-search; Enter must follow the overlay binding, not submit", submitted)
	}
	if a.reverseSearchOpen {
		t.Error("reverse-search still open after Enter accepted a match")
	}
	if got := a.input.GetText(); got != "git status" {
		t.Errorf("buffer after overlay Enter = %q, want the accepted match", got)
	}
}
