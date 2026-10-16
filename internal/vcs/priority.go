// VCS detection tie-breaking by configured vcs.priority and the ambiguity warning helper.
package vcs

import (
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/fserrors"
)

// Rank returns the primary order bucket for name under priority. Lower ranks win. A name listed in
// priority ranks at its first position in that list. A name not listed ranks after every listed entry:
// unlisted built-ins (builtinNames[name] true) sort ahead of unlisted user-defined names. Rank only
// establishes the bucket; names sharing an unlisted bucket are equal here and broken alphabetically by
// TieBreak.
func Rank(name string, priority []string, builtinNames map[string]bool) (rank int) {
	for i, p := range priority {
		if p == name {
			return i // listed: first priority-list position.
		}
	}
	if builtinNames[name] {
		return len(priority) // unlisted built-in: after all listed entries.
	}
	return len(priority) + 1 // unlisted user-defined: after unlisted built-ins.
}

// TieBreak returns the winning name among same-depth detector matches under priority. It picks
// the lowest Rank; among names sharing an unlisted bucket it picks the alphabetically smallest. It returns
// an empty string when matches is empty.
func TieBreak(matches []string, priority []string, builtinNames map[string]bool) string {
	winner := ""
	winnerRank := 0
	for _, name := range matches {
		r := Rank(name, priority, builtinNames)
		if winner == "" || r < winnerRank || (r == winnerRank && name < winner) {
			winner, winnerRank = name, r
		}
	}
	return winner
}

// AmbiguityWarning returns a single-line warning when more than one detector matched at the same depth and
// no vcs.preferred override was applied; otherwise it returns an empty string. The warning names
// the chosen winner and points the user at vcs.priority and vcs.preferred. It is side-effect-free: the
// caller prints it. (The vcs.preferred override path bypasses tie-breaking and sets preferredApplied.)
func AmbiguityWarning(matches []string, winner string, preferredApplied bool) string {
	if preferredApplied || len(matches) <= 1 {
		return ""
	}
	return fserrors.CollapseControls(fmt.Sprintf(
		"codemeld: multiple VCS detected (%s); using %q via vcs.priority. Set vcs.preferred to force a choice or reorder vcs.priority.",
		strings.Join(matches, ", "), winner))
}
