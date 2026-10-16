// Slash-command parser: classifies prompt input as a slash invocation, a bare
// exit/quit synonym, or ordinary (non-slash) text. Phase-1 syntax only — no
// quoting, escaping, flags, multi-line, or piping.
package tui

import (
	"regexp"
	"strings"
	"unicode"
)

// namePattern is the slash-command name grammar from: a lowercase
// letter followed by lowercase letters, digits, or hyphens. Shared by the
// parser and its tests so both agree on what a valid name is.
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// SlashParseKind is the outcome of parsing one line of prompt input.
type SlashParseKind int

const (
	// KindNotASlashCommand is ordinary prompt text: it neither begins with a
	// valid slash invocation nor is a bare exit/quit synonym. A line whose first
	// non-whitespace character is "/" but is not followed by a valid name (e.g.
	// "/", "/ ", "/Foo") also lands here per TR-TUI-12 — there is no separate
	// "invalid slash" outcome in phase 1.
	KindNotASlashCommand SlashParseKind = iota
	// KindSlashInvocation is a well-formed "/<name> [args...]" invocation. Whether
	// the name names a real command is the registry's concern, not the
	// parser's; an unknown-but-valid name still parses as this kind.
	KindSlashInvocation
	// KindBareExit is a bare "exit" or "quit" (case-insensitive, trimmed),
	// treated as equivalent to "/exit". The parser reports it as a
	// distinct kind and leaves the mapping to /exit to the dispatch layer.
	KindBareExit
)

// SlashInvocation is the parsed form of a "/<name> [args...]" line. Args are the
// whitespace-tokenized tokens after the name, with no quoting or escaping; it is
// nil when no arguments were supplied.
type SlashInvocation struct {
	Name string
	Args []string
}

// ParseResult is the tagged result of ParseSlashInput. Invocation is meaningful
// only when Kind is KindSlashInvocation; it is the zero value otherwise.
type ParseResult struct {
	Kind       SlashParseKind
	Invocation SlashInvocation
}

// ParseSlashInput classifies one line of prompt input. It trims surrounding
// whitespace first, so leading spaces before "/" or around "exit"/"quit" do not
// change the outcome. Tokenization of slash arguments collapses
// runs of whitespace; there is no quoting, escaping, flag, or multi-line
// handling in phase 1.
func ParseSlashInput(input string) ParseResult {
	trimmed := strings.TrimSpace(input)

	if strings.HasPrefix(trimmed, "/") {
		// The name is the run of characters immediately after "/" up to the first
		// whitespace; the slash-command grammar is "/<name>" with no whitespace between
		// the slash and the name. A "/" followed by whitespace or nothing (e.g.
		// "/", "/ ", "/ help") yields an empty name that fails the pattern and so
		// falls through to KindNotASlashCommand (TR-TUI-12).
		rest := trimmed[1:]
		name := rest
		var args []string
		if i := strings.IndexFunc(rest, unicode.IsSpace); i >= 0 {
			name = rest[:i]
			args = strings.Fields(rest[i+1:]) // collapses runs of whitespace; nil when none
		}
		if !namePattern.MatchString(name) {
			return ParseResult{Kind: KindNotASlashCommand}
		}
		return ParseResult{
			Kind:       KindSlashInvocation,
			Invocation: SlashInvocation{Name: name, Args: args},
		}
	}

	switch strings.ToLower(trimmed) {
	case "exit", "quit":
		return ParseResult{Kind: KindBareExit}
	}
	return ParseResult{Kind: KindNotASlashCommand}
}
