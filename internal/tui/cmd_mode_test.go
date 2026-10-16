// Tests for /mode and the shift+tab mode-cycle key: per-value switch + event,
// invalid/bare usage rejection, the colored confirmation message, the key path's
// cycle order and overlay/no-deps guards, and the production registry wiring.
package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// fakeModeSwitcher records the switches the /mode command and shift+tab drive,
// standing in for the production mode.ActiveState + interaction_mode emitter.
type fakeModeSwitcher struct {
	current  string
	applied  []string
	applyErr error
}

func (f *fakeModeSwitcher) Current() string { return f.current }

func (f *fakeModeSwitcher) Apply(key string) error {
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applied = append(f.applied, key)
	f.current = key
	return nil
}

// modeRegistry builds a registry with only /mode bound to NewModeHandler(deps), so
// the handler is exercised through the real dispatch path (parse, arity, run).
func modeRegistry(deps ModeDeps) *Registry {
	return MustNewRegistry([]Command{
		{Name: "mode", Description: "Set the interaction mode (plan/build/auto-edits)", ArgSig: ArgOneOptional, Phase: PhaseOne, Handler: NewModeHandler(deps)},
	})
}

// TestModeHandler_ValidSwitchPerValue covers each accepted argument: it switches to
// the canonical key (auto-edits → auto_edits), records slash_command{success}, shows
// the confirmation via Notify, and retains no input.
func TestModeHandler_ValidSwitchPerValue(t *testing.T) {
	cases := []struct{ arg, key string }{
		{"plan", "plan"},
		{"build", "build"},
		{"auto-edits", "auto_edits"},
	}
	for _, tc := range cases {
		t.Run(tc.arg, func(t *testing.T) {
			sw := &fakeModeSwitcher{current: "build"}
			var notified []string
			reg := modeRegistry(ModeDeps{Switcher: sw, Notify: func(k string) { notified = append(notified, k) }})
			host := newFakeHost()

			res := reg.DispatchSlashInput("/mode "+tc.arg, host)

			if res.Status != StatusHandled || res.Canonical != "mode" || res.Err != nil {
				t.Fatalf("dispatch = %+v, want Handled/mode/nil-err", res)
			}
			if res.RetainInput {
				t.Error("RetainInput = true on a valid switch, want false")
			}
			if len(sw.applied) != 1 || sw.applied[0] != tc.key {
				t.Errorf("applied = %v, want [%q]", sw.applied, tc.key)
			}
			if len(notified) != 1 || notified[0] != tc.key {
				t.Errorf("notified = %v, want [%q]", notified, tc.key)
			}
			if len(host.notices) != 0 {
				t.Errorf("notices = %v, want none on a valid switch", host.notices)
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("appended %d slash_command events, want 1", len(evs))
			}
			if p := decodeSlash(t, evs[0]); p.Name != "mode" || p.Outcome != "success" || p.ErrorDetail != "" {
				t.Errorf("event = %+v, want name=mode outcome=success", p)
			}
		})
	}
}

// TestModeHandler_InvalidOrBareRejects covers a bad value and a bare /mode: both
// print the usage notice, retain the input, record slash_command{error} with the same
// text, change no state, and show no confirmation.
func TestModeHandler_InvalidOrBareRejects(t *testing.T) {
	for _, input := range []string{"/mode bogus", "/mode"} {
		t.Run(input, func(t *testing.T) {
			sw := &fakeModeSwitcher{current: "build"}
			notified := 0
			reg := modeRegistry(ModeDeps{Switcher: sw, Notify: func(string) { notified++ }})
			host := newFakeHost()

			res := reg.DispatchSlashInput(input, host)

			if res.Status != StatusHandled || res.Err != nil {
				t.Fatalf("dispatch = %+v, want Handled/nil-err", res)
			}
			if !res.RetainInput {
				t.Error("RetainInput = false, want true so the user can edit and retry")
			}
			if len(host.notices) != 1 || host.notices[0] != modeUsageNotice {
				t.Errorf("notices = %v, want exactly [%q]", host.notices, modeUsageNotice)
			}
			if len(sw.applied) != 0 {
				t.Errorf("applied = %v, want none on a rejected switch", sw.applied)
			}
			if notified != 0 {
				t.Errorf("Notify called %d times on a rejected switch, want 0", notified)
			}
			evs := host.events()
			if len(evs) != 1 {
				t.Fatalf("appended %d slash_command events, want 1", len(evs))
			}
			if p := decodeSlash(t, evs[0]); p.Name != "mode" || p.Outcome != "error" || p.ErrorDetail != modeUsageNotice {
				t.Errorf("event = %+v, want name=mode outcome=error detail=%q", p, modeUsageNotice)
			}
		})
	}
}

// TestModeHandler_ApplyErrorSurfaces covers an internal switch failure: the handler
// returns the error (so the submit is rejected) and shows no confirmation. It also pins
// the durable-write ordering the audit retains — the slash_command{success} record is
// appended before ModeSwitcher.Apply, so an Apply failure cannot prevent the append:
// exactly one success event remains in the recorder, and Notify never runs.
func TestModeHandler_ApplyErrorSurfaces(t *testing.T) {
	sw := &fakeModeSwitcher{current: "build", applyErr: errors.New("emit interaction_mode failed")}
	notified := 0
	reg := modeRegistry(ModeDeps{Switcher: sw, Notify: func(string) { notified++ }})
	host := newFakeHost()

	res := reg.DispatchSlashInput("/mode plan", host)

	if res.Err == nil {
		t.Fatal("dispatch Err = nil on an Apply failure, want the surfaced error")
	}
	if notified != 0 {
		t.Errorf("Notify called %d times after an Apply failure, want 0", notified)
	}
	// The success event is appended before Apply runs, so an Apply failure cannot unrecord
	// it: exactly one success slash_command remains, pinning the append-before-apply order
	// (its on-disk durability rides on Apply's own flush, out of scope for this recorder).
	evs := host.events()
	if len(evs) != 1 {
		t.Fatalf("appended %d slash_command events on an Apply failure, want 1 (success recorded before Apply)", len(evs))
	}
	if p := decodeSlash(t, evs[0]); p.Name != "mode" || p.Outcome != "success" {
		t.Errorf("event = %+v, want name=mode outcome=success recorded before the Apply failure", p)
	}
}

// TestModePill_ColorsAndLabels pins the filled status-bar mode pill: each mode renders
// as " • <mode> " filled white-on-mode-color (plan=dark blue #2456b8, build=softer green
// #4a9d6b, auto-edits=muted amber/golden #b8860b), with the auto_edits key shown as the
// hyphenated "auto-edits". Plan is dark blue, not cyan, so it no longer renders near-black.
func TestModePill_ColorsAndLabels(t *testing.T) {
	cases := map[string]string{
		modeKeyPlan:      "[#ffffff:#2456b8] • plan [-:-]",
		modeKeyBuild:     "[#ffffff:#4a9d6b] • build [-:-]",
		modeKeyAutoEdits: "[#ffffff:#b8860b] • auto-edits [-:-]",
	}
	for key, want := range cases {
		if got := modePill(key); got != want {
			t.Errorf("modePill(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestCycleMode_UpdatesModeHintRowNotTranscript pins the shift+tab mode cycle: with Notify
// wired to the production RefreshModeHint, each shift+tab switch renders the new mode into
// the footer's second-row "• <mode>" pill (read back, tags stripped, via ModeHintText) and
// appends nothing to the session transcript. The row carries the pill followed by the
// shift+tab hint, so the read-back contains the active mode pill and the hint wording.
func TestCycleMode_UpdatesModeHintRowNotTranscript(t *testing.T) {
	sw := &fakeModeSwitcher{current: modeKeyPlan}
	a := New(nil)
	a.SetModeDeps(ModeDeps{Switcher: sw, Notify: a.RefreshModeHint})

	want := []string{"build", "auto-edits", "plan"}
	for i, label := range want {
		a.handleGlobalKey(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone))
		got := a.ModeHintText()
		if !strings.Contains(got, "• "+label) {
			t.Errorf("after shift+tab #%d mode row = %q, want it to contain the %q pill", i, got, "• "+label)
		}
		if !strings.Contains(got, "shift+tab to cycle") {
			t.Errorf("after shift+tab #%d mode row = %q, want it to contain the shift+tab hint", i, got)
		}
	}
	if got := a.TranscriptText(); got != "" {
		t.Errorf("transcript = %q, want empty (a mode switch updates the footer, not the transcript)", got)
	}
}

// TestCycleMode_ShiftTabCyclesAndNotifies covers the key path: shift+tab (KeyBacktab)
// advances plan → build → auto-edits → plan, is consumed each press, and shows the
// confirmation for each new mode. It appends no slash_command (the key path has no
// session store) — the keyboard switch mirrors the CTRL-E picker's no-record behavior.
func TestCycleMode_ShiftTabCyclesAndNotifies(t *testing.T) {
	sw := &fakeModeSwitcher{current: modeKeyPlan}
	var notified []string
	a := New(nil)
	a.SetModeDeps(ModeDeps{Switcher: sw, Notify: func(k string) { notified = append(notified, k) }})

	want := []string{modeKeyBuild, modeKeyAutoEdits, modeKeyPlan}
	for i, w := range want {
		if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone)); ev != nil {
			t.Errorf("shift+tab #%d returned %v, want nil (consumed)", i, ev)
		}
		if sw.current != w {
			t.Errorf("after shift+tab #%d current = %q, want %q", i, sw.current, w)
		}
	}
	if len(notified) != 3 || notified[0] != modeKeyBuild || notified[1] != modeKeyAutoEdits || notified[2] != modeKeyPlan {
		t.Errorf("notified = %v, want [build auto_edits plan]", notified)
	}
}

// TestCycleMode_NoOpWhileOverlayOpen covers parity: shift+tab is consumed but
// changes no mode while an overlay holds the screen.
func TestCycleMode_NoOpWhileOverlayOpen(t *testing.T) {
	sw := &fakeModeSwitcher{current: modeKeyPlan}
	a := New(nil)
	a.SetModeDeps(ModeDeps{Switcher: sw, Notify: func(string) {}})
	a.ShowStatus("snapshot")

	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone)); ev != nil {
		t.Errorf("shift+tab returned %v while an overlay is open, want nil (consumed)", ev)
	}
	if len(sw.applied) != 0 {
		t.Errorf("applied = %v while an overlay is open, want none", sw.applied)
	}
}

// TestCycleMode_InertWithoutDeps confirms shift+tab is consumed without panicking
// before the production wiring installs a switcher (the App pre-wiring state).
func TestCycleMode_InertWithoutDeps(t *testing.T) {
	a := New(nil)
	if ev := a.handleGlobalKey(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone)); ev != nil {
		t.Errorf("shift+tab returned %v with no mode deps, want nil (consumed)", ev)
	}
}

// TestBuildRegistry_ModeDispatchesToHandler pins the production wiring: the
// "mode" case binds NewModeHandler, so /mode reaches the real switch (a recordHandler
// placeholder would leave the switcher untouched).
func TestBuildRegistry_ModeDispatchesToHandler(t *testing.T) {
	sw := &fakeModeSwitcher{current: modeKeyBuild}
	reg := BuildRegistry(map[string]HandlerFunc{"mode": NewModeHandler(ModeDeps{Switcher: sw, Notify: func(string) {}})})
	host := newFakeHost()

	res := reg.DispatchSlashInput("/mode plan", host)

	if res.Status != StatusHandled || res.Canonical != "mode" || res.Err != nil {
		t.Fatalf("dispatch /mode = %+v, want Handled/mode/nil-err", res)
	}
	if len(sw.applied) != 1 || sw.applied[0] != modeKeyPlan {
		t.Errorf("applied = %v, want [plan]; a recordHandler wiring would leave it empty", sw.applied)
	}
}
