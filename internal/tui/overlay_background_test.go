// Tests that every page-mounted overlay paints an opaque background so the
// transcript underneath never bleeds through the full overlay page area
// (including the blank space around/inside the bordered content). The overlays are
// driven over the real event loop against a simulation screen, then the flattened
// screen is read on the loop goroutine and scanned for a transcript canary.
package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// overlayBleedCanary is the distinctive transcript marker appended to fill the
// transcript; overlayBleedCore is the interior substring scanned for. The marker
// carries a sacrificial "XX" prefix because a bled-through transcript line starts
// at column 0, where an overlay's left border overwrites the first cell (the
// reported one-column shift) — scanning for the core, not the full marker, stays
// robust to that clip while still being absent from every overlay's chrome.
const (
	overlayBleedCanary = "XXBLEEDCANARY"
	overlayBleedCore   = "BLEEDCANARY"
)

// overlayBleedHarness runs the real App event loop against a simulation screen and
// exposes a loop-serialized overlay-open read on top of the shared appHarness
// draw-synchronization base, so reads never race screen.Show().
type overlayBleedHarness struct {
	*appHarness
}

func newOverlayBleedHarness(t *testing.T, width, height int) *overlayBleedHarness {
	return &overlayBleedHarness{newAppHarness(t, width, height)}
}

// do runs f on the event-loop goroutine and waits for the draw it triggers, so a
// following screenText read sees the screen f produced.
func (h *overlayBleedHarness) do(f func()) { h.runDraw(f) }

// overlayOpen reports whether any overlay is mounted, read on the loop goroutine so
// the overlay-open flags are not touched concurrently with the draw loop.
func (h *overlayBleedHarness) overlayOpen() bool {
	open := false
	h.a.app.QueueUpdate(func() { open = h.a.anyOverlayOpen() })
	return open
}

// TestOverlayBackground_NoTranscriptBleed proves each page-mounted overlay, opened
// over a transcript full of the canary, leaves no canary anywhere in the full
// overlay page area. The effort picker and
// reverse-search have fixed-height roots whose Flex leaves unused cells, so this
// fails against the pre-fix bleed-through; the others (which already clear, or fill
// their slack) lock in the uniform wrapper across both root shapes.
func TestOverlayBackground_NoTranscriptBleed(t *testing.T) {
	cases := []struct {
		name string
		open func(*App)
	}{
		{"effort-picker", func(a *App) {
			a.SetEffortDeps(EffortDeps{Model: selectedModel(), Applier: &effortApplierFake{}})
			a.openEffortPicker()
		}},
		{"model-picker", func(a *App) {
			a.SetModelPickerDeps(ModelPickerDeps{Catalog: selectedModelCatalog(), Applier: &providerModelApplierFake{}})
			a.openModelPicker()
		}},
		{"reverse-search", func(a *App) {
			a.history.Append("git status")
			a.history.Append("make build")
			a.openReverseSearch()
		}},
		{"resume-picker", func(a *App) {
			a.openResumePicker(resumePickerEntries(), func(PickerResult) {}, ResumeActions{})
		}},
		{"resume-empty", func(a *App) {
			a.presentResumeEmpty("no resumable sessions in this folder", func() {})
		}},
		{"panel", func(a *App) { a.ShowPanel("help panel body") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newOverlayBleedHarness(t, 100, 40)
			defer h.stop()

			// Fill the transcript so the canary lands across many rows, well beyond the
			// few rows a small overlay root paints — the unused Flex area is exactly
			// where bleed-through showed.
			h.do(func() {
				for i := 0; i < 60; i++ {
					h.a.Append(overlayBleedCanary)
				}
			})
			// Precondition: the canary is on screen before the overlay opens, so a clean
			// post-open screen means the overlay covered it — not that it was never drawn.
			if !strings.Contains(screenTextSync(h.a, h.screen), overlayBleedCore) {
				t.Fatalf("setup: transcript canary not drawn before opening %s", tc.name)
			}

			h.do(func() { tc.open(h.a) })
			if !h.overlayOpen() {
				t.Fatalf("setup: %s overlay did not open", tc.name)
			}
			if strings.Contains(screenTextSync(h.a, h.screen), overlayBleedCore) {
				t.Errorf("transcript bled through the %s overlay: canary %q visible in the overlay page area", tc.name, overlayBleedCore)
			}
		})
	}
}

// flatScreen forces a draw, then reads the flattened simulation screen on the loop
// goroutine, so the read reflects the latest overlay state without racing the draw.
func (h *promptHarness) flatScreen() string {
	h.a.app.QueueUpdateDraw(func() {})
	return screenTextSync(h.a, h.screen)
}

// TestOverlayBackground_PermissionPromptNoBleed extends the no-bleed contract to the
// permission-prompt family: the base prompt and its stacked sub-pages (the
// scope chooser and Program-scope confirmation) are each opened over a canary-filled
// transcript and must show no bleed-through. Reaching the sub-pages by key navigation
// also proves the wrapper still routes focus/input to each overlay's own child.
func TestOverlayBackground_PermissionPromptNoBleed(t *testing.T) {
	a := New(nil)
	for i := 0; i < 40; i++ {
		a.Append(overlayBleedCanary)
	}
	h := startPrompt(t, a, fullPromptRequest())

	if strings.Contains(h.flatScreen(), overlayBleedCore) {
		h.a.app.Stop()
		t.Fatalf("transcript bled through the base permission prompt")
	}

	h.down(2) // allow for this session → routes a direct command through the scope chooser
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopePage)
	if strings.Contains(h.flatScreen(), overlayBleedCore) {
		h.a.app.Stop()
		t.Fatalf("transcript bled through the scope chooser")
	}

	h.down(1) // Subcommand (default) → Program, which opens the inline confirm step
	h.key(tcell.KeyEnter)
	h.waitPage(promptScopeConfirmPage)
	if strings.Contains(h.flatScreen(), overlayBleedCore) {
		h.a.app.Stop()
		t.Fatalf("transcript bled through the program-confirm step")
	}

	// Finalize so the app shuts down cleanly: confirm the inline program-scope choice
	// in one keypress (the cursor opens on "Confirm program-wide grant").
	h.key(tcell.KeyEnter)
	h.await()
}

// routeRecorder is a minimal focusable child that records the events routed to it,
// so a test can prove overlayBackground forwards focus, key, mouse, and paste to
// inner instead of swallowing them at the wrapper.
type routeRecorder struct {
	*tview.Box
	focused  bool
	gotKey   *tcell.EventKey
	gotMouse bool
	mouse    tview.MouseAction
	gotPaste bool
	paste    string
}

func (r *routeRecorder) Focus(delegate func(tview.Primitive)) {
	r.focused = true
	r.Box.Focus(delegate)
}
func (r *routeRecorder) HasFocus() bool { return r.focused }
func (r *routeRecorder) Blur()          { r.focused = false; r.Box.Blur() }

func (r *routeRecorder) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) {
	return func(ev *tcell.EventKey, _ func(tview.Primitive)) { r.gotKey = ev }
}

func (r *routeRecorder) MouseHandler() func(tview.MouseAction, *tcell.EventMouse, func(tview.Primitive)) (bool, tview.Primitive) {
	return func(action tview.MouseAction, _ *tcell.EventMouse, _ func(tview.Primitive)) (bool, tview.Primitive) {
		r.gotMouse = true
		r.mouse = action
		return true, r
	}
}

func (r *routeRecorder) PasteHandler() func(string, func(tview.Primitive)) {
	return func(text string, _ func(tview.Primitive)) { r.gotPaste = true; r.paste = text }
}

// TestOverlayBackground_RoutesToChildThroughPages proves the overlay routing
// contract: mounted the way every overlay is (wrapOverlayPage -> Pages.AddPage), the
// wrapper must let the
// real tview.Pages routing tree reach its child for focus, key, mouse, and paste —
// not just when its own handlers are called directly. Pages routes key/paste to the
// page whose item HasFocus and cascades mouse into the page under the pointer, so
// exercising the Pages handlers (rather than the wrapper handlers) proves the
// delegation survives the container that production actually puts it behind.
func TestOverlayBackground_RoutesToChildThroughPages(t *testing.T) {
	rec := &routeRecorder{Box: tview.NewBox()}
	wrapped := wrapOverlayPage(rec)

	pages := tview.NewPages()
	pages.AddPage("overlay", wrapped, true, true)
	pages.SetRect(0, 0, 40, 20)

	// Focus like the Application does: a recursive delegate that focuses each
	// primitive it is handed, so Pages -> wrapper -> child all run their Focus.
	var setFocus func(tview.Primitive)
	setFocus = func(p tview.Primitive) { p.Focus(setFocus) }
	pages.Focus(setFocus)
	if !rec.HasFocus() {
		t.Fatal("focus did not reach the overlay child through Pages -> wrapper")
	}

	// Key: Pages routes to the focused page's InputHandler, which the wrapper must
	// forward to the child.
	keyEv := tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	pages.InputHandler()(keyEv, setFocus)
	if rec.gotKey != keyEv {
		t.Error("key input did not reach the overlay child through Pages -> wrapper")
	}

	// Mouse: Pages cascades an event inside its rect into the page under it; the
	// wrapper must hand it to the child's MouseHandler.
	mouseEv := tcell.NewEventMouse(5, 5, tcell.Button1, tcell.ModNone)
	consumed, _ := pages.MouseHandler()(tview.MouseLeftDown, mouseEv, setFocus)
	if !consumed || !rec.gotMouse || rec.mouse != tview.MouseLeftDown {
		t.Errorf("mouse did not reach the overlay child through Pages -> wrapper: consumed=%v gotMouse=%v action=%v", consumed, rec.gotMouse, rec.mouse)
	}

	// Paste: Pages routes bracketed paste to the focused page's PasteHandler, which
	// the wrapper must forward to the child.
	pages.PasteHandler()("pasted text", setFocus)
	if !rec.gotPaste || rec.paste != "pasted text" {
		t.Errorf("paste did not reach the overlay child through Pages -> wrapper: gotPaste=%v text=%q", rec.gotPaste, rec.paste)
	}
}
