// Tests for the production /mode + shift+tab mode-switch seam (modedeps.go): the
// modeSwitcher reads the active mode key and, on a switch, mutates the run-scoped
// state to source user_command and durably emits interaction_mode with that source
// and the user_command trigger.
package bootstrap

import (
	"context"
	"testing"

	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/tui"
)

// TestModeSwitcher_ApplyMutatesStateAndEmitsUserCommandEvent pins Done-when #2: a
// production /mode (or shift+tab) switch records the runtime mode on the shared
// run-scoped state with source user_command — so the per-turn prompt/tool/posture
// consumers read the new mode on the next turn — and durably writes
// interaction_mode{mode, source:"user_command", trigger:"user_command"} onto the
// active session.
func TestModeSwitcher_ApplyMutatesStateAndEmitsUserCommandEvent(t *testing.T) {
	app := tui.New(nil)
	store := mkStore(t)
	app.SetActiveStore(store)
	active := mode.NewActiveState(mode.Build, mode.SourceDefault)
	sw := modeSwitcher{active: active, app: app, ctx: context.Background(), ui: &recordingHost{}}

	if got := sw.Current(); got != "build" {
		t.Fatalf("Current() before switch = %q, want %q", got, "build")
	}
	if err := sw.Apply("plan"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The shared run-scoped state now reads plan with source user_command, the value
	// the next turn's consumers see and the next event records.
	if m, src := active.Current(); m != mode.Plan || src != mode.SourceUserCommand {
		t.Fatalf("after Apply Current() = (%q, %q), want (plan, user_command)", m, src)
	}
	if got := sw.Current(); got != "plan" {
		t.Fatalf("modeSwitcher.Current() after switch = %q, want %q", got, "plan")
	}

	// The interaction_mode record is durable on disk with the user_command source/trigger.
	im := diskInteractionMode(t, readSessionFile(t, store.Path()))
	if len(im) != 1 || im[0].Mode != "plan" || im[0].Source != "user_command" || im[0].Trigger != "user_command" {
		t.Fatalf("durable interaction_mode = %+v, want one {plan, user_command, user_command}", im)
	}
}
