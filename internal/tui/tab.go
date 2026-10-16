// Tab completion for slash-command names: a pure helper that, given
// the input buffer text, the cursor position, and the command registry, decides
// whether Tab extends the typed name to a canonical command, extends it to the
// longest shared prefix of several candidates, lists those candidates, or does
// nothing. Argument-value completion is out of scope in phase 1.
package tui

import (
	"strings"
	"unicode"
)

// tabAction is what a Tab press should do to the input buffer.
type tabAction int

const (
	// tabNoop leaves the buffer unchanged: the cursor is not on a slash-name token,
	// or no command name shares the typed prefix ("No match → no-op").
	tabNoop tabAction = iota
	// tabReplace rewrites the buffer to Text — either a single canonical completion
	// or an extension to the longest common prefix of several candidates.
	tabReplace
	// tabList carries Matches, the candidate canonical slash names to show on one
	// line below the input because no further prefix extension is possible.
	tabList
)

// tabResult is the outcome of completeSlashName: the action to take plus the
// payload it needs — the rewritten buffer for tabReplace, the candidate slash
// names for tabList. The zero value is a no-op.
type tabResult struct {
	Action  tabAction
	Text    string   // rewritten buffer (tabReplace)
	Matches []string // candidate canonical slash names, registry order (tabList)
}

// candidate pairs a canonical command name with its argument signature, the data
// the completion decision needs after prefix matching and per-canonical dedupe.
type candidate struct {
	name   string
	argSig ArgSignature
}

// completeSlashName computes the Tab-completion outcome for buffer text with the
// cursor at rune offset cursor, against reg's commands. It completes a
// command NAME only: the buffer's first non-whitespace rune must be '/' and the
// cursor must sit on the first whitespace-bounded token. Candidates are the
// canonical commands whose canonical name or any alias begins with the typed name
// (alias routing), deduped to one entry per canonical command. Exactly one
// match extends to the full canonical slash name — with a single trailing space
// unless the command takes no arguments. Several matches extend to the longest
// common prefix of their canonical slash names; when that adds nothing, the names
// are returned for a one-line list. No candidate is a no-op, as is a cursor in the
// argument region (no argument-value completion in phase 1).
func completeSlashName(text string, cursor int, reg *Registry) tabResult {
	if reg == nil {
		return tabResult{}
	}
	runes := []rune(text)
	if cursor < 0 || cursor > len(runes) {
		return tabResult{}
	}

	// The first non-whitespace rune must be '/' (leading whitespace is tolerated,
	// mirroring the slash-command parser's TrimSpace).
	start := 0
	for start < len(runes) && unicode.IsSpace(runes[start]) {
		start++
	}
	if start >= len(runes) || runes[start] != '/' {
		return tabResult{}
	}

	// The name token runs from just after '/' to the first whitespace (or buffer
	// end). The cursor counts as "on the name token" anywhere after the '/' up to
	// and including the token's end (the position just before any separating
	// space); a cursor in the argument region is not a name completion.
	nameStart := start + 1
	nameEnd := nameStart
	for nameEnd < len(runes) && !unicode.IsSpace(runes[nameEnd]) {
		nameEnd++
	}
	if cursor < nameStart || cursor > nameEnd {
		return tabResult{}
	}
	typed := string(runes[nameStart:nameEnd])

	matches := candidateCanonicals(typed, reg)
	if len(matches) == 0 {
		return tabResult{}
	}

	// atEnd is true when the name is the last thing in the buffer, so a single-match
	// trailing space is only added when there are no arguments already following it.
	atEnd := nameEnd == len(runes)
	if len(matches) == 1 {
		newText := replaceName(runes, nameStart, nameEnd, matches[0].name, atEnd && matches[0].argSig != ArgNone)
		return tabResult{Action: tabReplace, Text: newText}
	}

	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.name
	}
	// Multiple candidates: extend to the longest common prefix of their canonical
	// names; a completion that adds nothing falls through to the candidate list.
	if lcp := longestCommonPrefix(names); len(lcp) > len(typed) {
		return tabResult{Action: tabReplace, Text: replaceName(runes, nameStart, nameEnd, lcp, false)}
	}
	slashNames := make([]string, len(names))
	for i, n := range names {
		slashNames[i] = "/" + n
	}
	return tabResult{Action: tabList, Matches: slashNames}
}

// candidateCanonicals returns, in registry source order, one entry per canonical
// command whose canonical name or any alias begins with typed (an alias
// prefix completes to its canonical command, and an alias plus its own canonical
// name count as a single canonical match). Iterating Commands() yields each
// command once, so the per-canonical dedupe is structural rather than a separate
// pass.
func candidateCanonicals(typed string, reg *Registry) []candidate {
	var out []candidate
	for _, c := range reg.Commands() {
		if strings.HasPrefix(c.Name, typed) || aliasHasPrefix(c.Aliases, typed) {
			out = append(out, candidate{name: c.Name, argSig: c.ArgSig})
		}
	}
	return out
}

// aliasHasPrefix reports whether any alias begins with typed.
func aliasHasPrefix(aliases []string, typed string) bool {
	for _, a := range aliases {
		if strings.HasPrefix(a, typed) {
			return true
		}
	}
	return false
}

// replaceName rewrites runes[nameStart:nameEnd] — the typed name, not including
// the leading '/' — with name, optionally followed by a single trailing space, and
// returns the full buffer. Any text after nameEnd (a separating space and existing
// arguments) is preserved.
func replaceName(runes []rune, nameStart, nameEnd int, name string, space bool) string {
	var b strings.Builder
	b.WriteString(string(runes[:nameStart]))
	b.WriteString(name)
	if space {
		b.WriteByte(' ')
	}
	b.WriteString(string(runes[nameEnd:]))
	return b.String()
}

// longestCommonPrefix returns the longest rune prefix shared by every string in
// names (empty when names is empty or the strings share nothing).
func longestCommonPrefix(names []string) string {
	if len(names) == 0 {
		return ""
	}
	prefix := []rune(names[0])
	for _, n := range names[1:] {
		r := []rune(n)
		if len(r) < len(prefix) {
			prefix = prefix[:len(r)]
		}
		for i := 0; i < len(prefix); i++ {
			if r[i] != prefix[i] {
				prefix = prefix[:i]
				break
			}
		}
	}
	return string(prefix)
}
