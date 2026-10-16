// /color <name> command: recolor the input area's two rules and prompt glyph to
// one of the six fixed palette colors for the current run only, validating the name
// against the closed palette and rejecting anything else with the typed input retained.
package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
)

// colorPaletteNames lists the six accepted /color values in a stable order for the
// usage/error message and the tests. It is the command's presentation of the closed
// palette; the name→color truth is inputAccentPalette (colors.go), and
// TestColorPaletteNames_MatchPalette pins the two together so they cannot drift.
var colorPaletteNames = []string{"red", "green", "yellow", "blue", "magenta", "cyan"}

// ColorDeps is the injectable seam NewColorHandler closes over: the run-scoped
// input-accent apply path (production binds App.ApplyInputAccent). Apply may be nil
// in unit tests and before the production wiring installs it, leaving a successful
// /color inert past its recorded event, mirroring the other command deps.
type ColorDeps struct {
	Apply func(color tcell.Color)
}

// NewColorHandler returns the /color handler. Dispatch enforces ArgOneRequired, so
// there is exactly one argument. An unknown color name prints a one-line notice
// naming the value and the six valid choices, retains the typed input, and records
// slash_command{outcome:error} (flushed, since the rejection has no later flush
// boundary). A known name records slash_command{outcome:success} and flushes it
// before the visible accent change — /color has no later persistence boundary of its
// own, so success and error are made durable here, mirroring /help and /status.
func NewColorHandler(deps ColorDeps) HandlerFunc {
	return func(ctx CommandContext, args []string) error {
		color, ok := inputAccentPalette[args[0]]
		if !ok {
			return rejectColor(ctx, args[0])
		}
		if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
			return err
		}
		if err := ctx.FlushActive(); err != nil {
			return err
		}
		if deps.Apply != nil {
			deps.Apply(color)
		}
		return nil
	}
}

// rejectColor renders the unknown-color notice, retains the typed input so the user
// can edit and retry, records slash_command{outcome:error} with the same text, and
// flushes it so the error event is durable before the handler returns. It mirrors
// rejectMode/rejectEffort.
func rejectColor(ctx CommandContext, name string) error {
	notice := unknownColorNotice(name)
	ctx.Notice(notice)
	ctx.RetainInput()
	if err := ctx.AppendSlashCommand(OutcomeError, notice); err != nil {
		return err
	}
	return ctx.FlushActive()
}

// unknownColorNotice is the one-line error for a value outside the palette, naming
// the supplied value and all six valid choices. It doubles as the
// slash_command.error_detail for that path.
func unknownColorNotice(name string) string {
	return fmt.Sprintf("unknown color %s; valid colors: %s", name, strings.Join(colorPaletteNames, ", "))
}
