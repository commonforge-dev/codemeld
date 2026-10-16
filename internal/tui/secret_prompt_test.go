// Tests for the reusable masked secret prompt: submit hands the entered
// string to the callback without it reaching any visible or durable sink, ESC/Ctrl-C
// cancel without submitting, the prompt counts as an overlay, and focus returns to
// the main input on close.
package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/sessions"
)

// assertNoSecretLeak fails if the sentinel appears in any readable app sink: the
// rendered screen, the notice line, the main input buffer, command history, or —
// when an active session store is installed — any record in the session event
// stream. Tests that want session-event coverage must call SetActiveStore before
// opening the prompt (see newSecretLeakStore).
func assertNoSecretLeak(t *testing.T, a *App, sentinel string) {
	t.Helper()
	if got := a.input.GetText(); strings.Contains(got, sentinel) {
		t.Errorf("main input buffer leaked the secret: %q", got)
	}
	if strings.Contains(a.transcript.notice, sentinel) {
		t.Errorf("notice leaked the secret: %q", a.transcript.notice)
	}
	for _, h := range a.history.Snapshot() {
		if strings.Contains(h, sentinel) {
			t.Errorf("command history leaked the secret: %q", h)
		}
	}
	if rendered := screenText(drawPrimitive(t, a.pages, 60, 12)); strings.Contains(rendered, sentinel) {
		t.Errorf("rendered screen leaked the secret: %q", rendered)
	}
	if store := a.ActiveStore(); store != nil {
		for _, r := range store.Records() {
			switch v := r.(type) {
			case sessions.Event:
				if strings.Contains(string(v.Payload), sentinel) {
					t.Errorf("session event %q leaked the secret: %s", v.Kind, v.Payload)
				}
			case sessions.Message:
				if strings.Contains(v.Content.Text(), sentinel) {
					t.Errorf("session message leaked the secret: %q", v.Content.Text())
				}
				for _, p := range v.Content.Parts() {
					if strings.Contains(string(p.Raw), sentinel) {
						t.Errorf("session message part leaked the secret: %s", p.Raw)
					}
				}
			}
		}
	}
}

// newSecretLeakStore installs an active on-disk session store on the app so the
// no-leak assertions cover the session event stream, not just the visible sinks.
// It reuses escTestStoreAtPath's seeded metadata.
func newSecretLeakStore(t *testing.T, a *App) *sessions.Store {
	t.Helper()
	store := escTestStoreAtPath(filepath.Join(t.TempDir(), "session.json"))
	a.SetActiveStore(store)
	return store
}

func TestSecretPrompt_SubmitReturnsSecretWithoutRenderingIt(t *testing.T) {
	const sentinel = "sk-SECRET-sentinel-9137"
	a := New(nil)
	newSecretLeakStore(t, a)
	a.input.SetText("draft")

	var got string
	calls := 0
	a.OpenSecretPrompt(SecretPromptRequest{
		Label:    "API key:",
		Help:     "Paste the provider API key; it is hidden as you type.",
		OnSubmit: func(s string) { calls++; got = s },
	})
	if !a.secretPromptOpen {
		t.Fatal("secret prompt did not open")
	}
	a.secretPrompt.field.SetText(sentinel)

	// While open, the masked field must render the mask character, not the secret.
	if rendered := screenText(drawPrimitive(t, a.pages, 60, 12)); strings.Contains(rendered, sentinel) {
		t.Fatalf("secret rendered on screen while open: %q", rendered)
	}

	a.submitSecretPrompt()

	if calls != 1 || got != sentinel {
		t.Fatalf("OnSubmit calls=%d got=%q, want 1 call with %q", calls, got, sentinel)
	}
	if a.secretPromptOpen || a.pages.HasPage(secretPromptPage) {
		t.Error("prompt still open after submit")
	}
	assertNoSecretLeak(t, a, sentinel)
}

func TestSecretPrompt_CancelDoesNotSubmit(t *testing.T) {
	const sentinel = "sk-should-not-submit"
	for _, tc := range []struct {
		name   string
		cancel func(*App)
	}{
		{"ESC", func(a *App) { a.HandleEsc() }},
		{"Ctrl-C", func(a *App) { a.handleGlobalKey(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			newSecretLeakStore(t, a)
			a.input.SetText("draft")

			submitted, cancelled := 0, 0
			a.OpenSecretPrompt(SecretPromptRequest{
				Label:    "API key:",
				OnSubmit: func(string) { submitted++ },
				OnCancel: func() { cancelled++ },
			})
			a.secretPrompt.field.SetText(sentinel)

			tc.cancel(a)

			if submitted != 0 {
				t.Errorf("OnSubmit fired on %s cancel", tc.name)
			}
			if cancelled != 1 {
				t.Errorf("OnCancel calls=%d on %s, want 1", cancelled, tc.name)
			}
			if a.secretPromptOpen || a.pages.HasPage(secretPromptPage) {
				t.Errorf("prompt still open after %s", tc.name)
			}
			if got := a.input.GetText(); got != "draft" {
				t.Errorf("input buffer = %q after %s, want preserved %q", got, tc.name, "draft")
			}
			assertNoSecretLeak(t, a, sentinel)
		})
	}
}

// TestSecretPrompt_EscCancelsWhileStreamInFlight pins the ESC priority fix: with an
// in-flight stream installed, ESC must cancel the open prompt without interrupting the
// stream. Before the fix, HandleEsc ran interruptStream first and returned, leaving the
// prompt mounted and OnCancel unrun. Remove the secretPromptOpen branch in HandleEsc and
// this fails (canceller.calls == 1, prompt still open, OnCancel not run).
func TestSecretPrompt_EscCancelsWhileStreamInFlight(t *testing.T) {
	a := New(nil)
	canceller := &fakeStreamCanceller{retained: 7, inFlight: true}
	a.SetStreamCanceller(canceller)
	a.input.SetText("draft")

	submitted, cancelled := 0, 0
	a.OpenSecretPrompt(SecretPromptRequest{
		Label:    "API key:",
		OnSubmit: func(string) { submitted++ },
		OnCancel: func() { cancelled++ },
	})

	a.HandleEsc()

	if canceller.calls != 0 {
		t.Errorf("stream canceller called %d times; ESC must cancel the prompt without touching the stream", canceller.calls)
	}
	if cancelled != 1 {
		t.Errorf("OnCancel calls=%d, want 1", cancelled)
	}
	if submitted != 0 {
		t.Errorf("OnSubmit fired on ESC cancel")
	}
	if a.secretPromptOpen || a.pages.HasPage(secretPromptPage) {
		t.Error("prompt still open after ESC")
	}
	if a.app.GetFocus() != a.input {
		t.Error("focus not restored to the main input after ESC")
	}
}

func TestSecretPrompt_CountsAsOverlay(t *testing.T) {
	a := New(nil)
	if a.anyOverlayOpen() {
		t.Fatal("an overlay was open before the test")
	}
	a.OpenSecretPrompt(SecretPromptRequest{Label: "API key:", OnSubmit: func(string) {}})
	if !a.anyOverlayOpen() {
		t.Error("secret prompt does not count as an overlay while open")
	}
	if a.app.GetFocus() == a.input {
		t.Error("main input holds focus while the secret prompt is open; input is not blocked")
	}
	a.submitSecretPrompt()
	if a.anyOverlayOpen() {
		t.Error("secret prompt still counts as an overlay after close")
	}
}

func rowText(cells []tcell.SimCell, width, row int) string {
	var b strings.Builder
	for c := 0; c < width; c++ {
		runes := cells[row*width+c].Runes
		if len(runes) == 0 {
			b.WriteRune(' ')
			continue
		}
		b.WriteString(string(runes))
	}
	return b.String()
}

func findCell(t *testing.T, s tcell.SimulationScreen, sub string) (row, col int) {
	t.Helper()
	cells, width, height := s.GetContents()
	for r := 0; r < height; r++ {
		if idx := strings.Index(rowText(cells, width, r), sub); idx >= 0 {
			return r, idx
		}
	}
	t.Fatalf("substring %q not found in rendered overlay", sub)
	return 0, 0
}

func TestSecretPrompt_TopAlignedHelpAndField(t *testing.T) {
	a := New(nil)
	a.OpenSecretPrompt(SecretPromptRequest{
		Label:    "API key",
		Help:     "Paste the provider key; it is hidden as you type.",
		OnSubmit: func(string) {},
	})
	s := drawPrimitive(t, a.pages, 60, 12)
	cells, width, height := s.GetContents()

	helpRow, _ := findCell(t, s, "Paste the provider key")
	labelRow, _ := findCell(t, s, "API key")

	if labelRow <= helpRow {
		t.Errorf("label row %d is not below help row %d", labelRow, helpRow)
	}
	if labelRow-helpRow > 2 {
		t.Errorf("field is %d rows below help; want it adjacent, not separated", labelRow-helpRow)
	}
	if labelRow > 3 {
		t.Errorf("label row %d is not near the top of the overlay", labelRow)
	}
	bottom := height - 2
	for c := 1; c < width-1; c++ {
		if runes := cells[bottom*width+c].Runes; len(runes) > 0 && runes[0] != ' ' {
			t.Errorf("bottom content row = %q, want blank space below the field", rowText(cells, width, bottom))
			break
		}
	}
}

func TestSecretPrompt_LabelStyleBlackAndNoYellow(t *testing.T) {
	a := New(nil)
	a.OpenSecretPrompt(SecretPromptRequest{
		Label:    "API key",
		Help:     "Paste the provider key; it is hidden as you type.",
		OnSubmit: func(string) {},
	})
	s := drawPrimitive(t, a.pages, 60, 12)
	cells, width, height := s.GetContents()

	row, col := findCell(t, s, "API key")
	if fg, _, _ := cells[row*width+col].Style.Decompose(); fg.Hex() != 0x000000 {
		t.Errorf("label foreground = %06X, want black (000000)", fg.Hex())
	}

	for r := 0; r < height; r++ {
		for c := 0; c < width; c++ {
			cell := cells[r*width+c]
			if len(cell.Runes) == 0 || cell.Runes[0] == ' ' {
				continue
			}
			if fg, _, _ := cell.Style.Decompose(); isYellow(fg) {
				t.Errorf("cell (%d,%d) %q uses fixed yellow", r, c, string(cell.Runes))
			}
		}
	}
}

func TestSecretPrompt_RestoresInputFocus(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(*App)
	}{
		{"submit", func(a *App) { a.submitSecretPrompt() }},
		{"cancel", func(a *App) { a.cancelSecretPrompt() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil)
			a.OpenSecretPrompt(SecretPromptRequest{Label: "API key:", OnSubmit: func(string) {}})
			if a.app.GetFocus() != a.secretPrompt.field {
				t.Fatal("field did not take focus on open")
			}
			tc.close(a)
			if a.app.GetFocus() != a.input {
				t.Errorf("focus not restored to the main input after %s", tc.name)
			}
		})
	}
}
