// Tests for the run-scoped interaction-mode state: key values and source round-trip.
package mode

import (
	"sync"
	"testing"
)

// TestModeKeysAreExactlyThree pins the contract that the only mode keys are
// plan, build, and auto_edits — the values written to interaction_mode and accepted
// for mode.default. A renamed or added constant fails here.
func TestModeKeysAreExactlyThree(t *testing.T) {
	if Plan != "plan" {
		t.Errorf("Plan = %q, want plan", Plan)
	}
	if Build != "build" {
		t.Errorf("Build = %q, want build", Build)
	}
	if AutoEdits != "auto_edits" {
		t.Errorf("AutoEdits = %q, want auto_edits", AutoEdits)
	}
}

// TestSourceAndTriggerValues pins the source and trigger vocabularies the
// interaction_mode event records.
func TestSourceAndTriggerValues(t *testing.T) {
	if SourceDefault != "default" || SourceConfig != "config" || SourceUserCommand != "user_command" {
		t.Errorf("sources = (%q, %q, %q), want (default, config, user_command)", SourceDefault, SourceConfig, SourceUserCommand)
	}
	if TriggerLaunch != "launch" || TriggerResume != "resume" || TriggerClear != "clear" || TriggerUserCommand != "user_command" {
		t.Errorf("triggers = (%q, %q, %q, %q), want (launch, resume, clear, user_command)",
			TriggerLaunch, TriggerResume, TriggerClear, TriggerUserCommand)
	}
}

// TestNewActiveState_CurrentRoundTrips covers the default/config/user_command source
// transitions: the constructor stores whatever mode+source it is given and Current
// returns them unchanged, so launch (default/config) and a carried-forward /mode
// switch (user_command) all read back the source the next event must record.
func TestNewActiveState_CurrentRoundTrips(t *testing.T) {
	cases := []struct {
		name   string
		mode   Mode
		source Source
	}{
		{"build default", Build, SourceDefault},
		{"plan config", Plan, SourceConfig},
		{"auto_edits user_command", AutoEdits, SourceUserCommand},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, src := NewActiveState(tc.mode, tc.source).Current()
			if m != tc.mode || src != tc.source {
				t.Errorf("Current() = (%q, %q), want (%q, %q)", m, src, tc.mode, tc.source)
			}
		})
	}
}

// TestApplyUserCommand_SetsModeAndUserCommandSource pins that a runtime /mode switch
// updates the shared active state in place: starting from Build/default the
// method moves it to Plan/user_command so the consumers reading this state see the
// new mode and the next interaction_mode event records source=user_command. A no-op
// body would leave it on Build/default and fail here.
func TestApplyUserCommand_SetsModeAndUserCommandSource(t *testing.T) {
	s := NewActiveState(Build, SourceDefault)
	s.ApplyUserCommand(Plan)
	m, src := s.Current()
	if m != Plan || src != SourceUserCommand {
		t.Fatalf("after ApplyUserCommand Current() = (%q, %q), want (plan, user_command)", m, src)
	}
}

func TestActiveState_ConcurrentCurrentAndApplyUserCommand(t *testing.T) {
	s := NewActiveState(Build, SourceDefault)
	const iterations = 10000

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := range iterations {
			if i%2 == 0 {
				s.ApplyUserCommand(Plan)
			} else {
				s.ApplyUserCommand(AutoEdits)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for range iterations {
			m, src := s.Current()
			valid := (m == Build && src == SourceDefault) ||
				((m == Plan || m == AutoEdits) && src == SourceUserCommand)
			if !valid {
				t.Errorf("Current() returned torn pair (%q, %q)", m, src)
				return
			}
		}
	}()

	wg.Wait()
}
