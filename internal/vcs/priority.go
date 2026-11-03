// VCS detection tie-breaking by configured vcs.priority and the ambiguity warning helper.
package vcs

import (
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/fserrors"
	"github.com/goccy/go-yaml"
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

func AmbiguityWarning(matches []string, winner string, forceApplied bool) string {
	if forceApplied || len(matches) <= 1 {
		return ""
	}
	names := make([]string, len(matches))
	example := ""
	for i, m := range matches {
		names[i] = fserrors.CollapseControls(m)
		if example == "" && m != winner {
			example = names[i]
		}
	}
	if b, err := yaml.Marshal(example); err == nil {
		example = strings.TrimSuffix(string(b), "\n")
	}
	return fmt.Sprintf(
		"codemeld: multiple VCS detected (%s); using %q. Set vcs.force in the .codemeld/settings.yaml file to force a choice.\nExample:\n  vcs:\n    force: %s",
		strings.Join(names, ", "), fserrors.CollapseControls(winner), example)
}
