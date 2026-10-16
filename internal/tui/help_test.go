// Tests for /help: TR-TUI-4 phase filtering and shortcut/command rendering,
// the /help dispatch event + panel open, and the app panel open/dismiss surface.
package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"codemeld.dev/codemeld/internal/sessions"
)

// TestRenderHelp_ListsPhaseOneCommandsAndShortcuts is the positive half of
// TR-TUI-4: every phase-1 registry entry (canonical name, aliases, description)
// and every shortcut appears in the rendered panel.
func TestRenderHelp_ListsPhaseOneCommandsAndShortcuts(t *testing.T) {
	reg := BuildRegistry(nil)
	out := RenderHelp(reg)

	for _, c := range reg.Commands() {
		if !strings.Contains(out, "/"+c.Name) {
			t.Errorf("help output missing canonical name /%s", c.Name)
		}
		if !strings.Contains(out, c.Description) {
			t.Errorf("help output missing description for /%s: %q", c.Name, c.Description)
		}
		for _, a := range c.Aliases {
			if !strings.Contains(out, "/"+a) {
				t.Errorf("help output missing alias /%s of /%s", a, c.Name)
			}
		}
	}
	// Aliases are presented in the slash-prefixed "(aliases:...)" form.
	for _, want := range []string{"/clear (aliases: /new)", "/exit (aliases: /quit)"} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing alias listing %q", want)
		}
	}

	// Shortcut labels (plus the newline chord), hard-coded here so
	// the test fails if a required row is removed from the production shortcuts table
	// (not derived from it).
	if !strings.Contains(out, "Keyboard shortcuts") {
		t.Error("help output missing the Keyboard shortcuts section")
	}
	for _, keys := range []string{"ESC", "CTRL-C", "CTRL-D", "↑ / ↓", "Tab", "Ctrl+Enter / Ctrl+J", "Ctrl-Q", "@", "shift+tab", "CTRL-L", "CTRL-E", "CTRL-M", "CTRL-R", "CTRL-V", "Mouse wheel", "PageUp / PageDown", "Shift+↑ / Shift+↓", "Mouse drag", "Shift+drag"} {
		if !strings.Contains(out, keys) {
			t.Errorf("help output missing keyboard shortcut %q", keys)
		}
	}
	// A "Mouse drag" row covers app-owned transcript selection; a later change broadened
	// it to cover the input area too (plain drag now selects in both) and retired the
	// input-only Shift+drag row, since plain drag covers it. The Ctrl-Q copy row and
	// the transcript Shift+drag native-selection escape hatch stay.
	for _, want := range []string{
		"Ctrl-Q — Copy selected input text",
		"Mouse drag — Select transcript or input text and copy it to the clipboard (no Shift needed)",
		"Shift+drag — Select and copy transcript text natively where your terminal still offers it",
		// Tab accepts a pending follow-up suggestion before falling through to
		// slash-name completion.
		"Tab — Accept the suggested follow-up, or complete a slash-command name",
		// Clipboard image paste moved from CTRL-Y to CTRL-V.
		"CTRL-V — Paste an image from the system clipboard (needs wl-paste, xclip, xsel, or pngpaste)",
		// The user-facing "@" file-reference trigger (onInputChanged) is advertised.
		"@ — Type @ at a word boundary to pick a project file or image to reference",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing shortcut row %q", want)
		}
	}
	// CTRL-Y no longer pastes images, so it must not appear in the shortcuts.
	if strings.Contains(out, "CTRL-Y") {
		t.Error("help output still lists CTRL-Y; f430 moved clipboard image paste to CTRL-V")
	}
	// The input-only Shift+drag row is gone now that plain drag selects in the input;
	// the bare "Shift+drag" key string still appears via the transcript row above.
	if strings.Contains(out, "Shift+drag (input)") {
		t.Error("help output still lists the retired input-only Shift+drag row (f370: plain drag now selects in the input)")
	}
	// Environment variables section: the help panel
	// advertises only the env vars a TUI user may deliberately set to change codemeld's
	// behavior — OPENAI_API_KEY, CODEMELD_MOUSE_DEBUG, CODEMELD_DEV_DEBUG, and CODEMELD_SHELL_TOOL_HINT — and
	// intentionally omits foundational/session-detection vars (HOME, CI, DISPLAY,
	// WAYLAND_DISPLAY), asserted below.
	if !strings.Contains(out, "Environment variables") {
		t.Error("help output missing the Environment variables section")
	}
	for _, want := range []string{
		"OPENAI_API_KEY — API key for the OpenAI Platform provider; used in preference to the key saved in settings",
		"CODEMELD_MOUSE_DEBUG — Set to a file path to log mouse, drag, and auto-scroll events there for diagnosing selection issues",
		"CODEMELD_DEV_DEBUG — Set to 1 to record a development-only suggest_followup trace in the session (suggest_followup_debug events) for diagnosing a missing follow-up suggestion",
		"CODEMELD_SHELL_TOOL_HINT — Set to 1 to refuse bash calls that run grep, cat, head, tail, find, ls and similar programs, with a hint naming the structured tool to use; experiment only, a model that will not call those tools gets stuck",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing environment-variable row %q", want)
		}
	}
	// HOME, CI, DISPLAY, and WAYLAND_DISPLAY are read by production but intentionally
	// omitted from /help (foundational path resolution / auth-login gate / display-server
	// detection — not a TUI behavior toggle a user sets). Pin the omission as a row ("<NAME> — ")
	// so a future addition is a deliberate decision rather than silent drift.
	for _, omitted := range []string{"HOME — ", "CI — ", "DISPLAY — ", "WAYLAND_DISPLAY — "} {
		if strings.Contains(out, omitted) {
			t.Errorf("help output advertises env var %q; f455 classified it as intentionally omitted", strings.TrimSuffix(omitted, " — "))
		}
	}
	// The effort shortcut moved off CTRL-T; the help must no longer advertise it.
	if strings.Contains(out, "CTRL-T") {
		t.Error("help output still lists CTRL-T; the effort picker shortcut is now CTRL-E")
	}
}

func TestRenderHelp_SandboxSection(t *testing.T) {
	out := RenderHelp(BuildRegistry(nil))
	shortcutsAt := strings.Index(out, "Keyboard shortcuts")
	sandboxAt := strings.Index(out, "\nSandbox (bottom-bar sandbox: on | off | unavailable)\n")
	envAt := strings.Index(out, "Environment variables")
	if shortcutsAt < 0 || sandboxAt < shortcutsAt || envAt < sandboxAt {
		t.Fatalf("want the Sandbox section between the shortcuts and the environment variables:\n%s", out)
	}
	for _, want := range []string{
		"shift+tab — Cycle the interaction mode (plan/build/auto-edits); plan and auto-edits run shell commands in the sandbox when the startup check passed",
		"  on — Plan or auto-edits mode after the startup sandbox check passed (Linux amd64/arm64): shell commands run with OS-enforced filesystem and process-access restrictions; auto-edits asks fewer permission prompts",
		"  off — Build mode: shell commands run outside the sandbox, with build mode's usual prompts",
		"  unavailable — The startup check failed, the OS or architecture is not supported, or a settings file broke during the session; /status shows the reason.",
		"After a passed startup check, a broken settings file keeps plan and auto-edits commands sandboxed but makes every command ask first",
		"after a failed or unsupported check they run outside the sandbox with ordinary prompts, and stay outside it if a settings file later breaks",
		"Build mode runs outside it either way",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing sandbox text %q", want)
		}
	}
	for _, banned := range []string{"never prompt", "isolat"} {
		if strings.Contains(out, banned) {
			t.Errorf("help output overclaims the sandbox with %q", banned)
		}
	}
}

// TestRenderHelp_ConnectDescribesKeySetup pins the /connect help copy to the
// key-entry setup framing: the command sets a provider up by entering its
// API key, not by writing a scaffold the user hand-edits.
func TestRenderHelp_ConnectDescribesKeySetup(t *testing.T) {
	out := RenderHelp(BuildRegistry(nil))
	if !strings.Contains(out, "Set up a provider by entering its API key") {
		t.Error("help output missing the /connect key-entry setup description")
	}
	if strings.Contains(out, "scaffold") {
		t.Error("help output still describes /connect as writing a scaffold")
	}
}

func TestRenderHelp_ListsSettingsNotPermissions(t *testing.T) {
	out := RenderHelp(BuildRegistry(nil))
	if !strings.Contains(out, "/settings") || !strings.Contains(out, "Show and change settings and stored permission grants") {
		t.Errorf("help output = %q, want /settings with its description", out)
	}
	if strings.Contains(out, "/permissions") {
		t.Errorf("help output = %q, still lists /permissions", out)
	}
}

// TestRenderHelp_AlphabeticalByName verifies commands list in canonical-name
// order (step 2).
func TestRenderHelp_AlphabeticalByName(t *testing.T) {
	out := RenderHelp(BuildRegistry(nil))
	order := []string{"clear", "connect", "context", "effort", "exit", "help", "mode", "model", "rename", "resume", "settings", "status"}
	last := -1
	for _, name := range order {
		idx := strings.Index(out, "/"+name)
		if idx < 0 {
			t.Fatalf("command /%s not found in help output", name)
		}
		if idx < last {
			t.Errorf("command /%s appears out of alphabetical order", name)
		}
		last = idx
	}
}

// TestRenderHelp_ExcludesHigherPhaseCommands is the negative half of TR-TUI-4 /
// TR-TUI-14: commands gated to a phase beyond this build are omitted. With
// buildPhase == PhaseTwo (codemeld entered phase 2 with /rename), a phase-2
// command now ships and only phase-3 entries stay hidden; the hidden fixture is
// therefore PhaseThree.
func TestRenderHelp_ExcludesHigherPhaseCommands(t *testing.T) {
	reg, err := NewRegistry([]Command{
		{Name: "shipping", Description: "phase-1 cmd", ArgSig: ArgNone, Phase: PhaseOne, Handler: nopHandler},
		{Name: "shiptwo", Description: "phase-2 cmd", ArgSig: ArgNone, Phase: PhaseTwo, Handler: nopHandler},
		{Name: "futurethree", Description: "phase-3 cmd", ArgSig: ArgNone, Phase: PhaseThree, Handler: nopHandler},
	})
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	out := RenderHelp(reg)

	for _, shown := range []string{"/shipping", "/shiptwo"} {
		if !strings.Contains(out, shown) {
			t.Errorf("command %s at or below the build phase should appear in this build's help", shown)
		}
	}
	if strings.Contains(out, "/futurethree") {
		t.Error("phase-3 command /futurethree must not appear in the phase-2 build help")
	}
}

// TestHelpHandler_OpensPanelAndRecordsSuccess covers the /help dispatch: it
// records slash_command{name:"help", args:[], outcome:"success"} and opens the
// help panel with the rendered text.
func TestHelpHandler_OpensPanelAndRecordsSuccess(t *testing.T) {
	host := newFakeHost()
	res := BuildRegistry(nil).DispatchSlashInput("/help", host)

	if res.Status != StatusHandled || res.Canonical != "help" || res.Err != nil {
		t.Fatalf("dispatch /help = %+v, want Handled/help/nil-err", res)
	}
	if len(host.panels) != 1 {
		t.Fatalf("ShowPanel called %d times, want 1", len(host.panels))
	}
	if !strings.Contains(host.panels[0], "Keyboard shortcuts") {
		t.Errorf("panel text is not the rendered help: %q", host.panels[0])
	}

	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events, want 1", len(evs))
	}
	p := decodeSlash(t, evs[0])
	if p.Name != "help" || p.Outcome != "success" || len(p.Args) != 0 {
		t.Errorf("event = %+v, want name=help args=[] outcome=success", p)
	}
}

// flushErrHost is a CommandHost whose FlushActive always fails, so the /help
// durability boundary can be exercised without a real filesystem. Its
// store backs AppendSlashCommand in memory; only the flush returns the error.
type flushErrHost struct {
	store    *sessions.Store
	notices  []string
	panels   []string
	flushErr error
}

func newFlushErrHost(err error) *flushErrHost {
	return &flushErrHost{store: sessions.New("", &sessions.Session{}), flushErr: err}
}

func (h *flushErrHost) Notice(text string)     { h.notices = append(h.notices, text) }
func (h *flushErrHost) ShowPanel(text string)  { h.panels = append(h.panels, text) }
func (h *flushErrHost) ShowStatus(text string) {}
func (h *flushErrHost) Store() *sessions.Store { return h.store }
func (h *flushErrHost) FlushActive() error     { return h.flushErr }

// TestHelpHandler_FlushFailureRejectsAndOpensNoPanel covers the
// durability boundary on /help: when FlushActive fails, the submit must be
// rejected (input retained) and the panel must not open, because a command may
// not produce visible UI side effects past a failed flush. The assertion fails
// if ShowPanel is moved back before FlushActive.
func TestHelpHandler_FlushFailureRejectsAndOpensNoPanel(t *testing.T) {
	flushErr := errors.New("session write failed flushing /help slash_command")
	host := newFlushErrHost(flushErr)
	submit := NewSubmitFunc(BuildRegistry(nil), host, nil)

	if accepted := submit("/help"); accepted {
		t.Error("submit accepted /help on a flush failure; want reject so the input is retained")
	}
	if len(host.panels) != 0 {
		t.Errorf("ShowPanel called %d times on a flush failure; the panel must not open past a failed durability boundary", len(host.panels))
	}
	// The slash_command record was appended in memory before the failed flush;
	// it stays for a later retry rather than being lost.
	if got := len(slashEvents(host.store)); got != 1 {
		t.Errorf("appended %d slash_command events, want 1 retained in memory", got)
	}
}

// TestApp_ShowPanelBlocksInput confirms ShowPanel opens the panel and moves
// focus off the input area, so the input is blocked while the panel is open.
func TestApp_ShowPanelBlocksInput(t *testing.T) {
	a := New(nil)
	assertOverlayOpensAndFocuses(t, a,
		func() { a.ShowPanel("panel body") },
		func() bool { return a.panelOpen },
		a.panel, "panel body", "panel")
}

// TestApp_PanelEscDismissesAndRetainsInput confirms ESC dismisses the panel,
// returns focus to the input area, and leaves the input buffer untouched.
func TestApp_PanelEscDismissesAndRetainsInput(t *testing.T) {
	a := New(nil)
	a.input.SetText("draft text")
	a.ShowPanel("panel body")

	got := a.handlePanelKey(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))

	if got != nil {
		t.Error("ESC was not consumed by the panel")
	}
	if a.panelOpen {
		t.Error("panelOpen = true after ESC")
	}
	if a.app.GetFocus() != a.input {
		t.Error("focus did not return to the input area after dismiss")
	}
	if txt := a.input.GetText(); txt != "draft text" {
		t.Errorf("input buffer = %q after ESC, want it retained as %q", txt, "draft text")
	}
}

// TestApp_PanelNonEscKeyPassesThrough confirms non-ESC keys are left to the panel
// and do not dismiss it.
func TestApp_PanelNonEscKeyPassesThrough(t *testing.T) {
	a := New(nil)
	a.ShowPanel("panel body")

	ev := tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
	if got := a.handlePanelKey(ev); got != ev {
		t.Error("non-ESC key was not passed through to the panel")
	}
	if !a.panelOpen {
		t.Error("panel dismissed by a non-ESC key")
	}
}
