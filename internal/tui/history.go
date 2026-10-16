// In-memory, session-scoped input history with ↑/↓ navigation.
package tui

// defaultHistoryCap is the phase-1 per-session history size cap
// (Technical Considerations): the store keeps at most this many most-recent
// entries, evicting the oldest first.
const defaultHistoryCap = 200

// History is the per-session record of submitted input lines, in submission
// order, with a cursor for ↑/↓ navigation and a saved live draft. It is memory
// only and never persisted: a fresh launch or `--resume` starts empty.
// Duplicates — including consecutive equal entries — are preserved.
type History struct {
	entries []string // oldest first, newest last; len capped at max
	max     int      // size cap; oldest entries are evicted past it
	cursor  int      // index into entries while navigating (valid only when nav)
	draft   string   // live-line text saved on the first ↑ of a navigation run
	nav     bool     // true while the cursor points into entries
}

// NewHistory returns an empty history capped at the phase-1 200-entry limit.
func NewHistory() *History {
	return &History{max: defaultHistoryCap}
}

// Append records entry as the newest submission, preserving duplicates and
// evicting the oldest entry once the cap is exceeded (FIFO). It resets any
// in-progress navigation back to the live line, so the next ↑ starts from the
// newest entry and re-saves the current draft.
func (h *History) Append(entry string) {
	h.entries = append(h.entries, entry)
	if len(h.entries) > h.max {
		// Drop the oldest; submission order of the survivors is preserved.
		h.entries = h.entries[len(h.entries)-h.max:]
	}
	h.nav = false
	h.draft = ""
}

// Up walks one step toward older entries and returns the text the input field
// should show. The first ↑ of a run saves draft (the current live line) and
// returns the newest entry; further ↑ walk farther back and stay put at the
// oldest entry. With no history it is a no-op that returns draft unchanged.
func (h *History) Up(draft string) string {
	if len(h.entries) == 0 {
		return draft
	}
	if !h.nav {
		h.draft = draft
		h.nav = true
		h.cursor = len(h.entries) - 1
		return h.entries[h.cursor]
	}
	if h.cursor > 0 {
		h.cursor--
	}
	return h.entries[h.cursor]
}

// Down walks one step toward newer entries and returns the text the input field
// should show. From the newest entry it restores the saved draft and leaves
// navigation; once back on the draft it stays there. When not navigating it
// returns the saved draft and changes nothing.
func (h *History) Down() string {
	if !h.nav {
		return h.draft
	}
	if h.cursor < len(h.entries)-1 {
		h.cursor++
		return h.entries[h.cursor]
	}
	h.nav = false
	return h.draft
}

// navigating reports whether the cursor is currently inside the history (i.e. a
// ↑ run is in progress). The input binding uses it to leave a live, unsaved
// line untouched when ↓ is pressed with no navigation underway.
func (h *History) navigating() bool {
	return h.nav
}

// Snapshot returns a copy of the recorded entries in submission order, oldest
// first. It is the read-only seam reverse-search reads through: the copy
// means a caller cannot mutate stored history or the navigation state.
func (h *History) Snapshot() []string {
	out := make([]string, len(h.entries))
	copy(out, h.entries)
	return out
}
