// Production implementation of the /mode + shift+tab mode-switch seam, bound to
// the run-scoped interaction-mode state and the running app. It lives in
// internal/bootstrap (not internal/tui) so the durable interaction_mode emit can
// route an atomic-write failure through sessionfailures without re-introducing the
// sessionfailures -> tui import cycle, exactly like clearModeState.
package bootstrap

import (
	"context"

	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/tui"
)

// modeSwitcher is the production tui.ModeSwitcher over the run-scoped interaction
// mode state. Current reports the active mode key; Apply records the runtime
// switch (ApplyUserCommand) and durably emits interaction_mode{trigger:"user_command"}
// onto whichever session is active when the switch runs — the same durable emitter
// /clear's carry-forward uses, so the three emission sites share one persistence
// policy. The switch takes effect on the next turn because the per-turn prompt/tool/
// posture consumers read the shared state then.
type modeSwitcher struct {
	active *mode.ActiveState
	app    *tui.App
	ctx    context.Context
	ui     tui.NoticeRenderer
}

func (s modeSwitcher) Current() string {
	m, _ := s.active.Current()
	return string(m)
}

func (s modeSwitcher) Apply(modeKey string) error {
	s.active.ApplyUserCommand(mode.Mode(modeKey))
	return emitInteractionMode(s.ctx, s.app.ActiveStore(), s.active, mode.TriggerUserCommand, s.ui)
}

// newModeDeps builds the production tui.ModeDeps bound to the run-scoped
// interaction-mode state and the running app. The same deps drive both the
// /mode command (via BuildRegistry) and the shift+tab cycle key (via
// App.SetModeDeps), so a switch through either surface records the identical
// interaction_mode event and updates the identical persistent mode-hint row. Notify
// (App.RefreshModeHint) re-renders that row as the filled mode pill followed by the
// "shift+tab to cycle" hint instead of appending a confirmation line to the session
// transcript, so a switch no longer scrolls a line through the conversation.
func newModeDeps(ctx context.Context, app *tui.App, active *mode.ActiveState) tui.ModeDeps {
	return tui.ModeDeps{
		Switcher: modeSwitcher{active: active, app: app, ctx: ctx, ui: app},
		Notify:   app.RefreshModeHint,
	}
}
