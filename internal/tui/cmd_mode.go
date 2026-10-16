// /mode <plan|build|auto-edits> command and the shift+tab mode-cycle key share one
// injected mode-switch seam (ModeDeps): both validate-then-switch the run-scoped
// interaction mode and update the same persistent "<mode> mode on (shift+tab to
// cycle)" hint row below the status line. The command additionally records a slash_command; the
// key path does not, mirroring the CTRL-E effort picker.
package tui

import "fmt"

// The three interaction-mode keys, mirrored here as plain strings so internal/tui
// need not import internal/mode (the same decoupling cmd_effort.go uses for the
// effort enum). They are the canonical mode keys written to interaction_mode.
const (
	modeKeyPlan      = "plan"
	modeKeyBuild     = "build"
	modeKeyAutoEdits = "auto_edits"
)

// modeUsageNotice is the one-line TUI error shown for a bare or invalid /mode. It
// doubles as the slash_command.error_detail for that path.
const modeUsageNotice = "usage: /mode <plan|build|auto-edits>"

// ModeSwitcher is the run-scoped interaction-mode surface the /mode command and the
// shift+tab key drive. The production implementation (wired in internal/bootstrap)
// wraps mode.ActiveState and emits the interaction_mode{trigger:"user_command"}
// event; keeping it behind this string-keyed interface keeps internal/tui off an
// import of internal/mode and internal/events. The dependency-surface audit keeps this
// seam deliberately rather than as removable indirection: collapsing it into the
// concrete bootstrap switcher would pull internal/mode, internal/events, and the
// session-failure write path they reach into internal/tui, breaching the package
// boundary the interface exists to hold.
type ModeSwitcher interface {
	// Current returns the active mode key ("plan" | "build" | "auto_edits").
	Current() string
	// Apply records a runtime switch to modeKey and durably emits the
	// interaction_mode event; the switch takes effect on the next turn. A non-nil
	// error is an internal append/flush failure the caller must surface.
	Apply(modeKey string) error
}

// ModeDeps gathers the injectable capabilities the /mode command and the shift+tab
// key close over, so both entry points share one mode-switch + confirmation seam and
// can be driven end-to-end with fakes (mirroring EffortDeps). The audit keeps it as the
// single shared bundle rather than giving each surface its own switch path, so /mode and
// shift+tab cannot drift apart. Production wiring supplies the implementations bound to
// the running app + bootstrap result.
type ModeDeps struct {
	Switcher ModeSwitcher
	// Notify, when non-nil, renders the current mode into the persistent mode-hint row
	// for the given mode key — shown by both /mode and the shift+tab cycle so a switch
	// through either surface updates the same row identically. nil in unit tests
	// and before the production wiring installs it, leaving the switch silent rather
	// than panicking.
	Notify func(modeKey string)
}

// NewModeHandler returns the /mode handler. A bare or unrecognized argument prints
// the usage notice, retains the typed input, and records slash_command{outcome:error}
// with the same text; a valid value records
// slash_command{outcome:success}, switches the active mode, and updates the shared
// footer mode-hint row through Notify (the same row shift+tab updates), appending no
// transcript confirmation line. The success record is made durable by the switch's own
// interaction_mode flush (Apply), mirroring how /effort relies on its apply flush.
func NewModeHandler(deps ModeDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		// Dispatch enforces ArgOneOptional, so there are zero or one arguments. A bare
		// /mode has no picker (unlike /effort), so it falls through to the usage notice.
		if len(args) == 0 {
			return rejectMode(ctx, modeUsageNotice)
		}
		key, ok := normalizeModeArg(args[0])
		if !ok {
			return rejectMode(ctx, modeUsageNotice)
		}
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		if err := deps.Switcher.Apply(key); err != nil {
			return err
		}
		if deps.Notify != nil {
			deps.Notify(key)
		}
		return nil
	}
}

// rejectMode renders the usage notice, retains the typed input so the user can edit
// and retry, records the recognized command with outcome:error carrying the same text
// as error_detail, and flushes that record so the error
// event is durable before the handler returns — the switch's later flush does not run
// on the rejection path. It mirrors rejectEffort.
func rejectMode(ctx CommandContext, notice string) error {
	ctx.Notice(notice)
	ctx.RetainInput()
	if err := ctx.AppendSlashCommand(OutcomeError, notice); err != nil {
		return err
	}
	return ctx.FlushActive()
}

// normalizeModeArg maps a user-facing /mode argument to its canonical mode key,
// reporting whether it is one of the three accepted values. The auto-edits mode is
// spelled with a hyphen on the command line but keyed auto_edits internally.
func normalizeModeArg(arg string) (string, bool) {
	switch arg {
	case "plan":
		return modeKeyPlan, true
	case "build":
		return modeKeyBuild, true
	case "auto-edits":
		return modeKeyAutoEdits, true
	default:
		return "", false
	}
}

// modeCycleNext returns the mode shift+tab advances to from key, cycling
// plan → build → auto-edits → plan. An unrecognized key restarts the cycle at plan
// so the keybinding always lands on a valid mode.
func modeCycleNext(key string) string {
	switch key {
	case modeKeyPlan:
		return modeKeyBuild
	case modeKeyBuild:
		return modeKeyAutoEdits
	default:
		return modeKeyPlan
	}
}

// modeLabel renders a mode key as the user-facing word shown in the confirmation
// line: auto_edits displays as "auto-edits"; plan and build are unchanged.
func modeLabel(key string) string {
	if key == modeKeyAutoEdits {
		return "auto-edits"
	}
	return key
}

// modeColorTag returns the tview color the mode pill is FILLED with (plan=dark blue,
// build=softer green, auto-edits=muted amber/golden #b8860b), so each mode reads as a
// distinct filled rectangle behind white text. plan is a dark blue rather than cyan —
// cyan renders near-black on some terminals, making plan indistinguishable from black —
// while build/auto stay legible. Auto edits keeps the muted amber/golden hex.
func modeColorTag(key string) string {
	switch key {
	case modeKeyPlan:
		return colorModePlan
	case modeKeyBuild:
		return colorModeBuild
	case modeKeyAutoEdits:
		return colorModeAuto
	default:
		return "-"
	}
}

// modePill builds the active interaction mode's filled status-bar pill, e.g.
// "[#ffffff:#2456b8] • plan [-:-]" (a filled pill — white text on the mode
// fill background — rather than bare colored text, the design sample's biggest gap).
// The fill background is modeColorTag (plan=dark blue, build=softer green, auto-edits=muted
// amber) so the rectangle tracks the active mode; the "•" bullet and modeLabel wording are
// kept. The string carries intentional tview color tags from a closed literal set, so
// App.RefreshModeHint renders it straight into the dynamic-color mode row, never the escaped
// Notice path — that bypass is injection-safe because the input is controlled.
func modePill(key string) string {
	return fmt.Sprintf("[%s:%s] • %s [-:-]", chromeOnFillText, modeColorTag(key), modeLabel(key))
}

// cycleMode advances the interaction mode one step (plan → build → auto-edits → plan)
// on shift+tab and updates the persistent mode-hint row. Like the CTRL-E effort picker
// it records no slash_command — keyboard mode switches drive the same mode-switch seam
// the /mode command does, minus the command audit record. It is a no-op
// while an overlay holds the screen and before SetModeDeps installs the
// production switcher (unit tests, pre-wiring), so it never panics on a nil switcher.
func (a *App) cycleMode() {
	if a.anyOverlayOpen() || a.modeDeps.Switcher == nil {
		return
	}
	next := modeCycleNext(a.modeDeps.Switcher.Current())
	if err := a.modeDeps.Switcher.Apply(next); err != nil {
		a.Notice(err.Error())
		return
	}
	if a.modeDeps.Notify != nil {
		a.modeDeps.Notify(next)
	}
}

// SetModeDeps installs the mode-switch surface the shift+tab cycle key reads and
// applies through. The production wiring supplies the implementation bound to
// the run-scoped mode state + running app — the same ModeDeps BuildRegistry
// binds to the /mode command — so both surfaces switch through one seam. With none set
// the key stays inert. It is set once before Run, alongside the other injected hooks.
func (a *App) SetModeDeps(d ModeDeps) { a.modeDeps = d }
