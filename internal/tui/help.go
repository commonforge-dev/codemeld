// /help command: renders the help panel listing the build's available
// commands and the keyboard shortcuts (TR-TUI-4).
package tui

import (
	"sort"
	"strings"
)

// buildPhase is the release phase this binary ships as. /help lists only the
// commands available in this build, i.e. those introduced in this phase or
// earlier. codemeld enters phase 2 with the /rename command, so this
// build ships PhaseOne and PhaseTwo commands; PhaseThree entries stay hidden until
// their phase flips.
const buildPhase = PhaseTwo

// shortcut is one keyboard-shortcut row in the help panel.
type shortcut struct {
	keys string
	desc string
}

// envVar is one environment-variable row in the help panel. The authoritative list with
// fuller descriptions lives in docs/environment-variables.md; this surfaces only the
// inclusion criterion below: a var a user running the TUI may set to change codemeld's
// behavior.
type envVar struct {
	name string
	desc string
}

// envVars are the environment variables the help panel advertises (see
// docs/environment-variables.md). Inclusion criterion: a var a user running the TUI
// may deliberately set to change codemeld's behavior. CODEMELD_MOUSE_DEBUG is the
// mouse/drag diagnostic (docs/tui-mouse-debugging.md): off by default, set it to a file path
// to capture events.
//
// Production also reads HOME, CI, DISPLAY, and WAYLAND_DISPLAY, but they are intentionally
// omitted here because they fail the criterion: HOME is foundational path resolution
// (internal/paths/home.go), CI only gates the auth browser-login flow (internal/cli/auth.go),
// and DISPLAY/WAYLAND_DISPLAY are display-server detection inputs that pick the clipboard
// helper (internal/tui/clipboard_image.go) — none is a codemeld feature toggle a TUI user
// sets. The RenderHelp test pins this omission so a future addition is a deliberate
// decision, not an accident.
var envVars = []envVar{
	{"OPENAI_API_KEY", "API key for the OpenAI Platform provider; used in preference to the key saved in settings"},
	{"CODEMELD_MOUSE_DEBUG", "Set to a file path to log mouse, drag, and auto-scroll events there for diagnosing selection issues"},
	{"CODEMELD_DEV_DEBUG", "Set to 1 to record a development-only suggest_followup trace in the session (suggest_followup_debug events) for diagnosing a missing follow-up suggestion"},
	{"CODEMELD_SHELL_TOOL_HINT", "Set to 1 to refuse bash calls that run grep, cat, head, tail, find, ls and similar programs, with a hint naming the structured tool to use; experiment only, a model that will not call those tools gets stuck"},
}

// shortcuts lists every phase-1 keyboard shortcut, in the order
// the shortcut requirement presents them, plus the shift+tab mode-cycle key, the
// newline chord, the transcript-scrollback keys / mouse note, the
// input-area Ctrl-Q copy row, and the plain-drag row that now selects in
// the transcript and the input alike (which retired the input-only Shift+drag row,
// since plain drag covers it). The transcript Shift+drag row stays as the native
// terminal-selection escape hatch. A later audit added the "@" file-reference trigger
// (the one user-facing entrypoint outside handleGlobalKey/handleInputKey, in
// onInputChanged); overlay-internal confirm/cancel/navigation keys (effort/model/resume/
// reverse-search/file-picker pickers and the permission prompt) are deliberately left out —
// they are overlay affordances, not global shortcuts a user invokes from the prompt.
var shortcuts = []shortcut{
	{"ESC", "Stop a streaming response, dismiss the open overlay, or clear the input buffer"},
	{"CTRL-C", "Clear the input buffer, or press twice on empty input to exit"},
	{"CTRL-D", "Exit codemeld"},
	{"↑ / ↓", "Navigate input history"},
	{"Tab", "Accept the suggested follow-up, or complete a slash-command name"},
	{"Ctrl+Enter / Ctrl+J", "Insert a newline in the prompt without submitting"},
	{"Ctrl-Q", "Copy selected input text"},
	{"@", "Type @ at a word boundary to pick a project file or image to reference"},
	{"shift+tab", "Cycle the interaction mode (plan/build/auto-edits); plan and auto-edits run shell commands in the sandbox when the startup check passed"},
	{"CTRL-L", "Repaint the screen"},
	{"CTRL-E", "Open the effort picker"},
	{"CTRL-M", "Open the model picker"},
	{"CTRL-R", "Reverse-search input history"},
	{"CTRL-V", "Paste an image from the system clipboard (needs wl-paste, xclip, xsel, or pngpaste)"},
	{"Mouse wheel", "Scroll the transcript to read earlier output"},
	{"PageUp / PageDown", "Scroll the transcript (keyboard fallback for the wheel)"},
	{"Shift+↑ / Shift+↓", "Scroll the transcript one line (where the terminal reports Shift)"},
	{"Mouse drag", "Select transcript or input text and copy it to the clipboard (no Shift needed)"},
	{"Shift+drag", "Select and copy transcript text natively where your terminal still offers it"},
}

var sandboxStates = []shortcut{
	{"on", "Plan or auto-edits mode after the startup sandbox check passed (Linux amd64/arm64): shell commands run with OS-enforced filesystem and process-access restrictions; auto-edits asks fewer permission prompts"},
	{"off", "Build mode: shell commands run outside the sandbox, with build mode's usual prompts"},
	{"unavailable", "The startup check failed, the OS or architecture is not supported, or a settings file broke during the session; /status shows the reason. After a passed startup check, a broken settings file keeps plan and auto-edits commands sandboxed but makes every command ask first; after a failed or unsupported check they run outside the sandbox with ordinary prompts, and stay outside it if a settings file later breaks. Build mode runs outside it either way"},
}

// RenderHelp returns the deterministic help-panel text for reg: every command
// available in this build listed alphabetically by canonical name
// followed by the keyboard shortcuts and the environment variables a TUI user may
// set to change behavior (see the envVars criterion; not every var codemeld reads).
// Phase-gated commands not yet shipping in this build are omitted (TR-TUI-4).
// Each command line shows the canonical name, slash-prefixed aliases (if any), and the
// description.
func RenderHelp(reg *Registry) string {
	cmds := reg.Commands()
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name < cmds[j].Name })

	var b strings.Builder
	b.WriteString("Commands\n")
	for _, c := range cmds {
		if c.Phase > buildPhase {
			continue
		}
		b.WriteString("  /")
		b.WriteString(c.Name)
		if len(c.Aliases) > 0 {
			prefixed := make([]string, len(c.Aliases))
			for i, a := range c.Aliases {
				prefixed[i] = "/" + a
			}
			b.WriteString(" (aliases: ")
			b.WriteString(strings.Join(prefixed, ", "))
			b.WriteString(")")
		}
		b.WriteString(" — ")
		b.WriteString(c.Description)
		b.WriteString("\n")
	}

	b.WriteString("\nKeyboard shortcuts\n")
	for _, s := range shortcuts {
		b.WriteString("  ")
		b.WriteString(s.keys)
		b.WriteString(" — ")
		b.WriteString(s.desc)
		b.WriteString("\n")
	}

	b.WriteString("\nSandbox (bottom-bar sandbox: on | off | unavailable)\n")
	for _, s := range sandboxStates {
		b.WriteString("  ")
		b.WriteString(s.keys)
		b.WriteString(" — ")
		b.WriteString(s.desc)
		b.WriteString("\n")
	}

	b.WriteString("\nEnvironment variables\n")
	for _, e := range envVars {
		b.WriteString("  ")
		b.WriteString(e.name)
		b.WriteString(" — ")
		b.WriteString(e.desc)
		b.WriteString("\n")
	}

	return b.String()
}

// helpHandler is the /help command handler: it opens the help panel and records
// the slash_command success event. It renders the registry that
// dispatched it, the live command set, rather than a package global (which would
// form an initialization cycle with the registry's command list).
func helpHandler(ctx CommandContext, _ []string) error {
	if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
		return err
	}
	// help has no later flush boundary of its own, so the
	// slash_command record is made durable here rather than waiting for an
	// unrelated later flush (slash_command writes are tied to the session's durability points).
	// Open the panel only after the append+flush succeed: a flush failure
	// rejects the submit, and the command must not produce visible UI side
	// effects past a failed durability boundary (symmetric with /status).
	if err := ctx.FlushActive(); err != nil {
		return err
	}
	ctx.ShowPanel(RenderHelp(ctx.Registry()))
	return nil
}
