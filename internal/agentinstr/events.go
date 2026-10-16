// Event replay: maps each in-memory LoadEntry to an agent_instructions_loaded
// payload and appends it via the events package, so a launch or in-process
// session switch re-emits identical events without re-walking the disk.
package agentinstr

import (
	"fmt"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// Replay appends an agent_instructions_loaded event for every LoadEntry to store,
// in load order, preserving each entry's path, layer, load_order, skip state, skip
// reason, error category, and error detail. Bootstrap and TUI callers decide when
// to invoke it relative to their launch_began event; this package owns only the
// mapping and append. It stops and returns on the first append error.
func Replay(store *sessions.Store, entries []LoadEntry) error {
	for _, e := range entries {
		if _, err := events.Append(store, e.payload()); err != nil {
			return fmt.Errorf("agentinstr: replay %s (load_order %d): %w", e.Path, e.LoadOrder, err)
		}
	}
	return nil
}

// payload maps a LoadEntry to its agent_instructions_loaded payload. A loaded
// entry sets no skip/error fields; a size_limit skip sets only skip_reason; an
// unreadable skip carries the error category and detail through verbatim. This
// matches the events validator's loaded/size_limit/unreadable field rules.
func (e LoadEntry) payload() events.AgentInstructionsLoaded {
	p := events.AgentInstructionsLoaded{
		Path:      e.Path,
		Layer:     e.Layer,
		LoadOrder: int64(e.LoadOrder),
	}
	if e.Skipped {
		p.SkipReason = e.SkipReason
		if e.SkipReason == SkipUnreadable {
			p.ErrorCategory = string(e.ErrorCategory)
			p.ErrorDetail = e.ErrorDetail
		}
	}
	return p
}
