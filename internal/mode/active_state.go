// Run-scoped holder for the active interaction mode and the Source the next
// interaction_mode event must record, mirroring model.ActiveState.
package mode

import "sync"

// Mode is one of the three interaction modes. The string values are the
// canonical mode keys written to the interaction_mode record and the mode.default
// config value; no other modes exist (Non-Goals: no custom/user-defined modes).
type Mode string

const (
	// Plan is read-only: the agent investigates and produces plans but makes no
	// changes.
	Plan Mode = "plan"
	// Build may edit and run, pausing for permission per the existing grant system
	// — today's authorization behavior.
	Build Mode = "build"
	// AutoEdits may edit and run, with in-scope file edits auto-approved while
	// shell and out-of-scope operations still pause.
	AutoEdits Mode = "auto_edits"
)

// Source records where the active mode value came from, for the interaction_mode
// event. It is a distinct vocabulary from model.Source because mode
// sources differ: a mode is never recovered from a prior session, so it has no
// resume/picker source.
type Source string

const (
	// SourceDefault: the launch default mode (mode.default absent → hard-coded
	// build, or any launch/resume that starts from the configured default).
	SourceDefault Source = "default"
	// SourceConfig: the mode.default key was present in settings.
	SourceConfig Source = "config"
	// SourceUserCommand: the mode was selected at runtime via the /mode command.
	// Launch-time resolution never sets this source; it carries forward across /clear when a
	// prior /mode switch established it.
	SourceUserCommand Source = "user_command"
)

// Trigger records why an interaction_mode event was emitted. It is the
// closed set the interaction_mode payload validates against.
type Trigger string

const (
	// TriggerLaunch: emitted on a fresh launch.
	TriggerLaunch Trigger = "launch"
	// TriggerResume: emitted on a cold-start resume, which starts from mode.default
	// rather than the prior session's mode.
	TriggerResume Trigger = "resume"
	// TriggerClear: emitted into the fresh session of a /clear switch, carrying the
	// active mode forward.
	TriggerClear Trigger = "clear"
	// TriggerUserCommand: emitted on a /mode switch. Launch-time resolution does not emit it.
	TriggerUserCommand Trigger = "user_command"
)

// ActiveState holds the run-scoped active interaction mode and the Source value
// the next interaction_mode event must record, mirroring model.ActiveState. It is
// the single in-memory owner that launch/resume initialization, /clear
// carry-forward, the future /mode switch, and the mode-driven prompt/tool/
// authorization consumers all read.
//
// Mode is never persisted across sessions (Non-Goals): launch and resume both seed
// it from mode.default, so this state never restores a prior session's last-used
// mode. It is deliberately side-effect free — it performs no event append, flush,
// validation, or TUI rendering; callers own those. Unlike model.ActiveState there
// is no "no mode selected" state: a run always has exactly one active mode (Build by
// default), so the zero value is an empty, unusable holder that NewActiveState
// replaces — production never constructs the zero value.
type ActiveState struct {
	mu     sync.RWMutex
	mode   Mode
	source Source
}

// NewActiveState builds the run's active-mode state from a resolved mode and the
// Source to record on the next interaction_mode event. Launch and resume pass the
// mode.default value with SourceDefault (key absent) or SourceConfig (key present);
// a /clear carry-forward reuses the existing mode and its original source. The mode
// and source are stored as given; value validity is enforced where the event is
// appended (events.InteractionMode), mirroring how model.ActiveState defers
// selection validation to its callers.
func NewActiveState(m Mode, source Source) *ActiveState {
	return &ActiveState{mode: m, source: source}
}

// Current returns the active mode and the Source to record on the next
// interaction_mode event. Both are always present: a run always has one active mode.
func (s *ActiveState) Current() (Mode, Source) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode, s.source
}

// ApplyUserCommand records a runtime mode switch made via the /mode command:
// it replaces the active mode and sets the next interaction_mode source to
// SourceUserCommand, so the consumers reading this shared state see the new mode
// on the next turn and the emitted event records that the mode came from a user
// command. Mirroring model.ActiveState.ApplyUserSelection it is side-effect free —
// the caller appends the interaction_mode{trigger: "user_command"} record. Mode
// validity is enforced where the event is appended (events.InteractionMode),
// matching NewActiveState.
func (s *ActiveState) ApplyUserCommand(m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
	s.source = SourceUserCommand
}
