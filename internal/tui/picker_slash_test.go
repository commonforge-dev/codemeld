// Tests for the live '/' slash-command picker: single-'/'-at-line-start trigger
// detection and its negatives, prefix+alias filtering by canonical name, "/<name>
// <description>" row rendering, immediate submit of the canonical command on select through
// submitCurrent, literal-'/'+query preservation on ESC, the one-overlay-at-a-time guard, and
// inertness without a registry. The pure detector directly, the overlay behavior through App
// methods and the live query field's wiring, plus one running-loop SimulationScreen test that
// types real keys.
package tui

import (
	"slices"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/sessions"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestDetectSlashTrigger(t *testing.T) {
	cases := []struct {
		name   string
		prev   string
		cur    string
		wantAt int
		wantOK bool
	}{
		{"into empty buffer", "", "/", 0, true},
		{"after leading spaces", "  ", "  /", 2, true},
		{"after a leading tab", "\t", "\t/", 1, true},
		{"after a word is not line start", "x", "x/", 0, false},
		{"mid-word insertion", "ab", "a/b", 0, false},
		{"after a newline", "a\n", "a\n/", 0, false},
		{"lone newline before slash", "\n", "\n/", 0, false},
		{"second slash adjacent", "/", "//", 0, false},
		// A bracketed paste arrives as a multi-rune change, so it never triggers.
		{"paste of /text", "", "/foo", 0, false},
		{"paste containing /", "  ", "  /foo", 0, false},
		{"deletion", "/", "", 0, false},
		{"insert non-slash rune", "", "a", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at, ok := detectSlashTrigger(tc.prev, tc.cur)
			if ok != tc.wantOK || (ok && at != tc.wantAt) {
				t.Errorf("detectSlashTrigger(%q, %q) = (%d, %v), want (%d, %v)", tc.prev, tc.cur, at, ok, tc.wantAt, tc.wantOK)
			}
		})
	}
}

// recordSlashSubmit installs a submit hook that records every submitted text and returns accept,
// so a confirm test can assert the picker submitted the canonical command exactly once. The
// returned pointer holds the submitted texts in call order.
func recordSlashSubmit(a *App, accept bool) *[]string {
	got := &[]string{}
	a.SetSubmit(func(text string, _ ...sessions.ContentPart) bool {
		*got = append(*got, text)
		return accept
	})
	return got
}

// slashNames extracts the canonical names of a candidate slice for order-sensitive assertions.
func slashNames(cs []slashCandidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.name)
	}
	return out
}

// focusedSlashField opens the picker via a typed '/' and returns the live query field that holds
// focus, proving the widget buildSlashPicker focuses is the one whose SetChangedFunc/
// SetInputCapture the wiring tests then drive.
func focusedSlashField(t *testing.T, a *App) *tview.InputField {
	t.Helper()
	a.input.SetText("/")
	if !a.slashPickerOpen {
		t.Fatal("picker did not open on a typed '/'")
	}
	field, ok := a.app.GetFocus().(*tview.InputField)
	if !ok {
		t.Fatalf("focused widget = %T, want *tview.InputField (the query field must hold focus)", a.app.GetFocus())
	}
	return field
}

func TestSlashPicker_TriggerOpens(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))

	a.input.SetText("/") // fires the change hook: single '/' at the buffer start

	if !a.slashPickerOpen {
		t.Fatal("SlashPickerOpen false; typing '/' at line start must open the picker")
	}
	if !a.pages.HasPage(slashPickerPage) {
		t.Error("slash picker page not mounted")
	}
	if a.slashPicker == nil || len(a.slashPicker.candidates) == 0 {
		t.Error("picker opened with no registry candidates")
	}
	if got := a.input.GetText(); got != "/" {
		t.Errorf("input = %q, want %q (the trigger never consumes the '/')", got, "/")
	}
}

func TestSlashPicker_InertWithoutRegistry(t *testing.T) {
	a := New(nil) // no registry installed (unit-test construction)

	a.input.SetText("/")

	if a.slashPickerOpen {
		t.Error("picker opened with no registry installed; the trigger must be inert")
	}
	if got := a.input.GetText(); got != "/" {
		t.Errorf("input = %q, want %q (typed '/' left untouched)", got, "/")
	}
}

// TestSlashPicker_BracketedPasteOfSlashDoesNotOpen drives a paste of exactly '/' through the
// production PasteHandler path. A lone pasted '/' produces the same prev=""→cur="/" change as a
// typed '/', so only the input.pasting guard in onInputChanged tells them apart: the picker must
// stay closed and the '/' must land literally. Removing "|| a.input.pasting" from onInputChanged
// makes this fail.
func TestSlashPicker_BracketedPasteOfSlashDoesNotOpen(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil)) // registry installed: a *typed* '/' would open the picker

	pasteInto(a.input, "/")

	if got := a.input.GetText(); got != "/" {
		t.Errorf("input = %q, want %q (pasted '/' left literal)", got, "/")
	}
	if a.slashPickerOpen {
		t.Error("slash picker opened on a bracketed paste of '/'; a paste must never open it")
	}
	if a.pages.HasPage(slashPickerPage) {
		t.Error("slash picker page mounted on a bracketed paste of '/'")
	}
}

func TestSlashPicker_SuppressedWhileOverlayOpen(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	a.statusOpen = true // another overlay holds the screen

	a.input.SetText("/")

	if a.slashPickerOpen {
		t.Error("slashPickerOpen true; the '/' trigger must be a no-op while another overlay is open")
	}
	if a.pages.HasPage(slashPickerPage) {
		t.Error("slash picker page mounted while another overlay is open")
	}
}

// TestSlashPicker_PrefixFilterThroughWiring drives the focused production query field to prove
// buildSlashPicker wired field.SetChangedFunc to the filter: typing narrows by prefix over
// canonical names and aliases, in registry order, rendered as "/<name>  <description>".
func TestSlashPicker_PrefixFilterThroughWiring(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	field := focusedSlashField(t, a)

	field.SetText("mo") // production SetChangedFunc → onSlashQueryChanged
	sess := a.slashPicker
	if sess == nil {
		t.Fatal("picker closed on a matching query typed into the field")
	}
	if got := slashNames(sess.shown); !slices.Equal(got, []string{"model", "mode"}) {
		t.Errorf("shown for %q = %v, want [model mode]", "mo", got)
	}

	field.SetText("sett")
	if got := slashNames(a.slashPicker.shown); !slices.Equal(got, []string{"settings"}) {
		t.Errorf("shown for %q = %v, want [settings]", "sett", got)
	}
	if got := slashRowText(a.slashPicker.shown[0]); got != "/settings  Show and change settings and stored permission grants" {
		t.Errorf("row text = %q, want %q", got, "/settings  Show and change settings and stored permission grants")
	}

	field.SetText("perm")
	if a.slashPickerOpen || a.pages.HasPage(slashPickerPage) {
		t.Errorf("picker open for %q, want no match: /permissions is not a command", "perm")
	}
}

// TestSlashPicker_NoMatchClosesLeavingLiteral proves a non-empty query that matches nothing
// empties and closes the picker through the field's change hook, leaving the '/'+query literal.
func TestSlashPicker_NoMatchClosesLeavingLiteral(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	field := focusedSlashField(t, a)

	field.SetText("zzzqqq") // production SetChangedFunc → no-match close

	if a.slashPickerOpen || a.pages.HasPage(slashPickerPage) {
		t.Error("picker stayed open on a no-match query; it must empty and close")
	}
	if got := a.input.GetText(); got != "/zzzqqq" {
		t.Errorf("input = %q, want %q (no-match query left literal)", got, "/zzzqqq")
	}
}

// TestSlashPicker_FieldEnterConfirms delivers Enter through the focused production field's own
// input handler (which applies the SetInputCapture registration) to prove Enter submits the
// canonical "/settings" once through submitCurrent and clears the input on accept, after
// narrowing to a single command.
func TestSlashPicker_FieldEnterConfirms(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	got := recordSlashSubmit(a, true)
	field := focusedSlashField(t, a)
	field.SetText("se") // narrows to settings through the production change hook

	field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if !slices.Equal(*got, []string{"/settings"}) {
		t.Errorf("submitted = %v, want [/settings] (Enter must submit the canonical command once)", *got)
	}
	if txt := a.input.GetText(); txt != "" {
		t.Errorf("input = %q, want empty (accepted submit clears the input)", txt)
	}
	if a.slashPickerOpen || a.pages.HasPage(slashPickerPage) {
		t.Error("picker still open after Enter confirmed a command")
	}
}

// TestSlashPicker_EscLeavesLiteral proves ESC through the focused field leaves the literally
// typed '/'+query in the prompt. "que" still matches (the /exit 'quit' alias), so the picker is
// open when ESC arrives — exercising the ESC dismiss path, not the no-match auto-close.
func TestSlashPicker_EscLeavesLiteral(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	field := focusedSlashField(t, a)
	field.SetText("que") // matches /exit via its 'quit' alias, so the picker stays open

	field.InputHandler()(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := a.input.GetText(); got != "/que" {
		t.Errorf("input = %q, want %q (ESC leaves the typed '/'+query literal)", got, "/que")
	}
	if a.slashPickerOpen {
		t.Error("picker still open after ESC")
	}
}

// TestSlashPicker_EscThroughHandleEsc pins the production ESC path: a real ESC routes through
// App.HandleEsc to the slashPicker roster entry's dismissal, not the focused field handler
// directly. Removing that entry (overlays.go) makes ESC fall through to the input-clear branch
// and erase the draft, failing this test.
func TestSlashPicker_EscThroughHandleEsc(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	field := focusedSlashField(t, a)
	field.SetText("sett") // still matches /settings, so the picker is open when ESC arrives

	a.HandleEsc()

	if got := a.input.GetText(); got != "/sett" {
		t.Errorf("input = %q, want %q (ESC via HandleEsc leaves the '/'+query literal)", got, "/sett")
	}
	if a.slashPickerOpen || a.pages.HasPage(slashPickerPage) {
		t.Error("picker still open after ESC through HandleEsc")
	}
}

func TestSlashPicker_DismissRestoresFocusBeforeLeavingLiteral(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	field := focusedSlashField(t, a)
	field.SetText("sett")

	a.dismissSlashPicker(true)

	if a.app.GetFocus() != a.input {
		t.Errorf("focus = %T, want the input area restored on dismissal", a.app.GetFocus())
	}
	if a.slashPickerPrev != nil {
		t.Error("prior focus not cleared after dismissal")
	}
	if got := a.input.GetText(); got != "/sett" {
		t.Errorf("input = %q, want %q (the literal is spliced after focus is restored)", got, "/sett")
	}
}

func TestSlashPicker_RepeatedDismissDoesNotDuplicateQuery(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	field := focusedSlashField(t, a)
	field.SetText("sett")

	a.dismissSlashPicker(true)
	text := a.input.GetText()
	if text != "/sett" {
		t.Fatalf("input after the first dismissal = %q, want %q", text, "/sett")
	}
	elsewhere := tview.NewBox()
	a.app.SetFocus(elsewhere)

	a.dismissSlashPicker(true)

	if got := a.input.GetText(); got != text {
		t.Errorf("input after a second dismissal = %q, want the first close's %q", got, text)
	}
	if a.app.GetFocus() != elsewhere {
		t.Errorf("focus after a second dismissal = %T, want it left where it was", a.app.GetFocus())
	}
	if a.slashPicker != nil || a.pages.HasPage(slashPickerPage) {
		t.Error("a second dismissal revived the picker")
	}
}

// TestSlashPicker_FieldTabConfirms delivers Tab through the focused field's input handler (the
// SetInputCapture registration) to prove Tab, like Enter, submits the canonical command
// immediately. Removing tcell.KeyTab from slashPickerFieldKeys fails this test.
func TestSlashPicker_FieldTabConfirms(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	got := recordSlashSubmit(a, true)
	field := focusedSlashField(t, a)
	field.SetText("sett") // narrows to settings through the production change hook

	field.InputHandler()(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), func(tview.Primitive) {})

	if !slices.Equal(*got, []string{"/settings"}) {
		t.Errorf("submitted = %v, want [/settings] (Tab must submit the canonical command once)", *got)
	}
	if txt := a.input.GetText(); txt != "" {
		t.Errorf("input = %q, want empty (accepted submit clears the input)", txt)
	}
	if a.slashPickerOpen || a.pages.HasPage(slashPickerPage) {
		t.Error("picker still open after Tab confirmed a command")
	}
}

// TestSlashPicker_ListSelectConfirms drives the list's SetSelectedFunc callback — the path a mouse
// click on a row fires — by sending Enter through the list's own input handler. It proves the
// mouse/list seam submits the canonical command like Enter. Dropping the list.SetSelectedFunc
// callback in buildSlashPicker fails this test.
func TestSlashPicker_ListSelectConfirms(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	got := recordSlashSubmit(a, true)
	field := focusedSlashField(t, a)
	field.SetText("sett") // narrows the list to the single settings row

	sess := a.slashPicker
	sess.list.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if !slices.Equal(*got, []string{"/settings"}) {
		t.Errorf("submitted = %v, want [/settings] (list selection must submit the canonical command once)", *got)
	}
	if txt := a.input.GetText(); txt != "" {
		t.Errorf("input = %q, want empty (accepted submit clears the input)", txt)
	}
	if a.slashPickerOpen || a.pages.HasPage(slashPickerPage) {
		t.Error("picker still open after list selection confirmed a command")
	}
}

// TestSlashPicker_RejectRetainsCanonical proves the submitCurrent retention contract survives the
// picker path: when the submit hook rejects, the canonical command the picker wrote is left in the
// input (not cleared), and the overlay is still closed. The picker must not special-case retention.
func TestSlashPicker_RejectRetainsCanonical(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	got := recordSlashSubmit(a, false) // hook rejects the submission
	field := focusedSlashField(t, a)
	field.SetText("sett")

	field.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if !slices.Equal(*got, []string{"/settings"}) {
		t.Errorf("submitted = %v, want [/settings] (the canonical command is still submitted once)", *got)
	}
	if txt := a.input.GetText(); txt != "/settings" {
		t.Errorf("input = %q, want %q (a rejected submit retains the canonical command)", txt, "/settings")
	}
	if a.slashPickerOpen || a.pages.HasPage(slashPickerPage) {
		t.Error("picker still open after a rejected confirm")
	}
}

// TestSlashPicker_CountsAsOverlay pins that an open slash picker registers in anyOverlayOpen, so
// other global overlay triggers treat it as an overlay. Removing a.slashPickerOpen from
// App.anyOverlayOpen fails this test.
func TestSlashPicker_CountsAsOverlay(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	focusedSlashField(t, a) // opens the picker (fatals if it did not)

	if !a.anyOverlayOpen() {
		t.Error("anyOverlayOpen() = false while the slash picker is open; it must count as an overlay")
	}
}

// TestSlashPicker_ConfirmThroughLoop is the wiring-contract SimulationScreen test: it runs the
// real event loop, types '/' then 'se' as real keys through the wired change hook (the '/' opens
// the picker and hands focus to the query field, 'se' narrows it), asserts the popup opened with
// the expected filtered rows, then Enter selects the entry and the production event loop submits
// "/settings" through submitCurrent — the recording hook receives it and the accepted input
// clears — no injected fake picker.
func TestSlashPicker_ConfirmThroughLoop(t *testing.T) {
	a := New(nil)
	a.SetRegistry(BuildRegistry(nil))
	submitted := make(chan string, 1)
	a.SetSubmit(func(text string, _ ...sessions.ContentPart) bool {
		select {
		case submitted <- text:
		default:
		}
		return true
	})

	drawn := make(chan struct{}, 16)
	a.app.SetAfterDrawFunc(func(tcell.Screen) {
		select {
		case drawn <- struct{}{}:
		default:
		}
	})
	a.app.SetScreen(tcell.NewSimulationScreen("UTF-8"))

	errc := make(chan error, 1)
	go func() { errc <- a.app.Run() }()

	select {
	case <-drawn:
	case <-time.After(2 * time.Second):
		a.app.Stop()
		t.Fatal("app did not draw within 2s")
	}

	a.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, '/', tcell.ModNone))
	a.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, 's', tcell.ModNone))
	a.app.QueueEvent(tcell.NewEventKey(tcell.KeyRune, 'e', tcell.ModNone))

	// Poll until the picker is open and narrowed to the single /settings row.
	deadline := time.After(2 * time.Second)
	for !slices.Equal(slashShownNamesSync(a), []string{"settings"}) {
		select {
		case <-drawn:
		case <-deadline:
			got := slashShownNamesSync(a)
			a.app.Stop()
			t.Fatalf("picker not narrowed to [settings] within 2s; shown = %v", got)
		}
	}

	a.app.QueueEvent(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	select {
	case got := <-submitted:
		if got != "/settings" {
			a.app.Stop()
			t.Fatalf("submit hook received %q, want %q", got, "/settings")
		}
	case <-deadline:
		a.app.Stop()
		t.Fatal("submit hook not called within 2s after Enter selected the command")
	}
	for inputTextSync(a) != "" {
		select {
		case <-drawn:
		case <-deadline:
			got := inputTextSync(a)
			a.app.Stop()
			t.Fatalf("main input not cleared within 2s after accepted submit; buffer = %q, want empty", got)
		}
	}

	a.app.Stop()
	if err := <-errc; err != nil {
		t.Fatalf("app.Run returned error: %v", err)
	}
}

// slashShownNamesSync reads the picker's shown candidate names on the event-loop goroutine so a
// running-app test can check them without racing the loop, mirroring inputTextSync.
func slashShownNamesSync(a *App) []string {
	var names []string
	a.app.QueueUpdate(func() {
		if a.slashPicker != nil {
			names = slashNames(a.slashPicker.shown)
		}
	})
	return names
}
