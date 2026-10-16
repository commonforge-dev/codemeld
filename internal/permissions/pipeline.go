// Whole-command splitting: cd-prefix path-scope hint capture, quote-aware pipeline splitting, and direct-vs-literal-vs-rejected routing for the permission system.
package permissions

import (
	"errors"
	"strings"
)

// Rejected-construct names reported in SplitResult.RejectedConstruct.
// These are the shell constructs outside the simple-compound allowlist; the value is the
// human-facing construct name handed to the agent in the unsupported_shell_construct
// error so the message can say which construct was refused.
const (
	constructCommandSub = "$()"
	constructBacktick   = "`"
	// constructNewline names a bare newline or carriage-return command separator.
	// tokenizeShell treats both as whitespace, so without this rejection a
	// multi-line input like "git status\nrm -rf x" would collapse into one
	// direct-command subject; the shell-construct allowlist excludes line separators, so
	// they are refused before permission matching. A readable name is used in
	// place of the literal control byte for the agent-facing error message.
	constructNewline = "newline"
)

// SplitResult is the outcome of normalizing a whole shell command per the
// strip-then-split-then-normalize order. Exactly one of three routes applies and
// the caller selects on the boolean fields:
//
// AllowedShell == false: a rejected construct was found.
//
//	  RejectedConstruct names it; the permission system is skipped entirely (no
//	  prompt, no grant authorizes). Stages is nil and LiteralRoute is false.
//	- AllowedShell == true && LiteralRoute == true: the command is syntactically
//	  accepted but outside the direct-command boundary (I/O redirection, a
//	  wrapper/literal-route stage, a bare simple compound, or a double-quoted
//	  command substitution). The whole
//	  prefix-stripped command is matched as a single literal subject — LiteralInput
//	  carries it (feed to CanonicalLiteralForm).
//	  Stages is nil.
//	- AllowedShell == true && LiteralRoute == false: every pipeline stage is a
//	  direct command. Stages holds one RouteDirect StageNormalization per stage,
//
// each authorized independently.
//
// CdHint carries the raw `<path>` from a leading `cd <path> && ` prefix,
// unquoted exactly as the shell would pass it to cd, or "" when no
// such prefix is present. It is preserved on the direct and literal routes so
// DerivePathScope can anchor the path scope; ~ expansion, absolute
// conversion, and symlink resolution are DerivePathScope's job, not this function's.
type SplitResult struct {
	CdHint            string
	Stages            []StageNormalization
	LiteralRoute      bool
	LiteralInput      string
	AllowedShell      bool
	RejectedConstruct string
}

// SplitCommand normalizes a whole shell command into a SplitResult per the
// step order: (1) strip a leading `cd <path> && ` prefix once, capturing <path>
// as CdHint; (2) on the remainder, refuse rejected constructs, then route
// I/O redirection, wrapper/literal forms, and bare simple compounds (`&&`,
// `;`, `||`) to a single literal subject, or (3) split on unquoted `|` and
// normalize each stage through NormalizeDirectStage.
//
// The returned error is reserved for malformed input that cannot be classified
// at all — an unterminated quote, a dangling backslash, an empty command, or an
// empty pipeline stage. A command that is well-formed but uses a construct
// outside the allowlist is NOT an error: it returns AllowedShell == false with
// RejectedConstruct set, because routes that case to the agent rather
// than to Go error handling. Operator detection is quote-aware: `|`, `;`, `&&`,
// `||`, newline/carriage-return separators, redirection, `$(`, and backticks
// inside single/double quotes or escaped are literal text, never shell syntax,
// except that a `$(` or backtick inside double quotes routes the command literal.
func SplitCommand(input string) (SplitResult, error) {
	if strings.TrimSpace(input) == "" {
		return SplitResult{}, errors.New("split command: empty command")
	}

	cdHint, rest, err := stripCdPrefix(input)
	if err != nil {
		return SplitResult{}, err
	}

	work := strings.TrimSpace(rest)
	if work == "" {
		return SplitResult{}, errors.New("split command: empty command after cd prefix")
	}

	mask, err := bareMask(work)
	if err != nil {
		return SplitResult{}, err
	}

	// a rejected construct poisons the whole command regardless of where it sits, so this scan runs
	// before redirection and pipeline handling. Simple-compound operators are not rejected here; they
	// route to literal matching below.
	if construct, ok := firstRejectedConstruct(work, mask); ok {
		return SplitResult{CdHint: cdHint, AllowedShell: false, RejectedConstruct: construct}, nil
	}

	// The direct executors run argv without a shell, so they would pass a double-quoted substitution
	// through as text instead of performing it.
	if hasDoubleQuotedSubstitution(work) {
		return SplitResult{CdHint: cdHint, LiteralRoute: true, LiteralInput: work, AllowedShell: true}, nil
	}

	// I/O redirection is syntactically accepted but outside the
	// direct-command boundary. Any bare `<` or `>` (which also covers `>>`, `2>`,
	// `&>`, heredocs, and process substitution `<(`/`>(`) routes the whole
	// prefix-stripped command to literal matching as one subject.
	if containsBareByte(work, mask, '<') || containsBareByte(work, mask, '>') {
		return SplitResult{CdHint: cdHint, LiteralRoute: true, LiteralInput: work, AllowedShell: true}, nil
	}

	// A bare simple compound operator is accepted and routed to the literal/compound path rather than
	// refused: the whole prefix-stripped command becomes one literal subject. The permission matcher
	// then decomposes a *simple* compound — every stage an otherwise direct command — for generalized
	// matching, and keeps every non-simple shape byte-exact. This is checked after the rejected-construct
	// scan, so command substitution/backticks/newlines are still refused, and after the redirection check,
	// so a redirection compound stays on the existing literal route.
	if containsBareSimpleCompoundOperator(work, mask) {
		return SplitResult{CdHint: cdHint, LiteralRoute: true, LiteralInput: work, AllowedShell: true}, nil
	}

	// step 2: split the remainder on unquoted `|`. Any `||` routed to the simple-compound path above, so
	// every bare `|` here is a single-pipe stage boundary.
	stages := splitBarePipes(work, mask)
	for _, stage := range stages {
		if strings.TrimSpace(stage) == "" {
			return SplitResult{}, errors.New("split command: empty pipeline stage")
		}
	}

	// step 3: normalize each stage. If any stage is a literal route
	// (wrapper form such as `sh -c`/`env`, backgrounding, subshell, or process
	// substitution), the whole prefix-stripped command becomes one literal
	// subject rather than a set of authorized direct stages (boundary).
	stageCtx := StageInCompound
	if len(stages) == 1 {
		stageCtx = StageSolo
	}
	normalized := make([]StageNormalization, 0, len(stages))
	for _, stage := range stages {
		norm, err := NormalizeDirectStage(stage, stageCtx)
		if err != nil {
			return SplitResult{}, err
		}
		if norm.Route == RouteLiteral {
			return SplitResult{CdHint: cdHint, LiteralRoute: true, LiteralInput: work, AllowedShell: true}, nil
		}
		normalized = append(normalized, norm)
	}

	return SplitResult{CdHint: cdHint, Stages: normalized, AllowedShell: true}, nil
}

// stripCdPrefix removes a single leading `cd <path> && ` prefix from input,
// returning the unquoted <path> as the hint and the remaining command. The
// prefix is recognized only when the text before the first bare `&&` tokenizes
// to exactly two words `cd` and one path: that keeps `cd a && b && c`'s later
// `&&` (and any non-cd leading `&&`) unstripped so it is refused downstream as a
// rejected construct. When no leading cd prefix applies, hint is "" and rest is
// the original input unchanged.
func stripCdPrefix(input string) (hint, rest string, err error) {
	mask, err := bareMask(input)
	if err != nil {
		return "", "", err
	}
	p, ok := firstBareAndAnd(input, mask)
	if !ok {
		return "", input, nil
	}
	prefixTokens, err := tokenizeShell(input[:p])
	if err != nil {
		return "", "", err
	}
	// Accept only a clean `cd <path>` prefix: exactly the word cd and one path
	// word with no bare shell operator hidden in it. tokenizeShell splits on
	// whitespace alone, so without the operator check a path token like `foo;bar`,
	// `$(pwd)`, or `a|b` would tokenize to two words, get stripped, and carry its
	// construct off where the rejected-construct scan never looks. A bare
	// operator means the leading text is not a simple cd, so the `&&` is left in
	// place to be refused downstream. A double-quoted substitution in the path is not stripped either,
	// because the hint would carry its text unexpanded.
	if len(prefixTokens) == 2 && prefixTokens[0].Value == "cd" && !prefixHasBareOperator(input, mask, p) &&
		!hasDoubleQuotedSubstitution(input[:p]) {
		return prefixTokens[1].Value, input[p+2:], nil
	}
	// Not the allowed `cd <path> &&` form; leave the `&&` in place so the rejected
	// -construct scan reports it.
	return "", input, nil
}

// prefixHasBareOperator reports whether input[:end] contains any bare (unquoted,
// unescaped) shell operator byte: `;`, `|`, `&`, `<`, `>`, a backtick, a
// newline/carriage-return separator, or a `$(` command substitution. A genuine
// `cd <path>` prefix has none — a path needing such a byte literally must quote
// it, which bareMask already marks non-bare. Finding one means the leading text
// before `&&` is not a simple cd and must not be stripped as a path hint.
func prefixHasBareOperator(input string, mask []bool, end int) bool {
	for i := 0; i < end; i++ {
		if !mask[i] {
			continue
		}
		switch input[i] {
		case ';', '|', '&', '<', '>', '`', '\n', '\r':
			return true
		case '$':
			if i+1 < end && mask[i+1] && input[i+1] == '(' {
				return true
			}
		}
	}
	return false
}

// firstBareAndAnd returns the index of the first bare (unquoted, unescaped) `&&`
// in s, or false when none is present.
func firstBareAndAnd(s string, mask []bool) (int, bool) {
	for i := 0; i+1 < len(s); i++ {
		if mask[i] && mask[i+1] && s[i] == '&' && s[i+1] == '&' {
			return i, true
		}
	}
	return 0, false
}

// firstRejectedConstruct scans s left to right and returns the name of the
// leftmost bare construct outside the allowlist: `$(`, a backtick, or a bare
// newline/carriage-return separator. Bare `&&`, `;`, and `||` are simple-compound
// operators routed to the literal/compound path, a single bare `|` is a pipeline,
// and a single bare `&` is backgrounding handled by the literal route.
func firstRejectedConstruct(s string, mask []bool) (string, bool) {
	for i := 0; i < len(s); i++ {
		if !mask[i] {
			continue
		}
		switch s[i] {
		case '\n', '\r':
			return constructNewline, true
		case '`':
			return constructBacktick, true
		case '$':
			if i+1 < len(s) && mask[i+1] && s[i+1] == '(' {
				return constructCommandSub, true
			}
		}
	}
	return "", false
}

func hasDoubleQuotedSubstitution(s string) bool {
	n := len(s)
	i := 0
	for i < n {
		switch s[i] {
		case '\\':
			i += 2
		case '\'':
			i++
			for i < n && s[i] != '\'' {
				i++
			}
			i++
		case '"':
			i++
			for i < n && s[i] != '"' {
				if s[i] == '\\' && i+1 < n && isDoubleQuoteEscape(s[i+1]) {
					i += 2
					continue
				}
				if s[i] == '`' || (s[i] == '$' && i+1 < n && s[i+1] == '(') {
					return true
				}
				i++
			}
			i++
		default:
			i++
		}
	}
	return false
}

// containsBareSimpleCompoundOperator reports whether s carries one of the bare operators the
// literal/simple-compound route understands. A single `|` is intentionally excluded: it remains the
// direct pipeline route unless combined with one of these compound operators.
func containsBareSimpleCompoundOperator(s string, mask []bool) bool {
	for i := 0; i < len(s); i++ {
		if !mask[i] {
			continue
		}
		switch s[i] {
		case ';':
			return true
		case '&':
			if i+1 < len(s) && mask[i+1] && s[i+1] == '&' {
				return true
			}
		case '|':
			if i+1 < len(s) && mask[i+1] && s[i+1] == '|' {
				return true
			}
		}
	}
	return false
}

// splitBarePipes splits s on every bare single `|`, returning the raw substrings
// between pipe boundaries (callers trim and normalize each). `||` has already
// routed to the simple-compound path, so a bare `|` here is never part of logical OR.
func splitBarePipes(s string, mask []bool) []string {
	var stages []string
	start := 0
	for i := 0; i < len(s); i++ {
		if mask[i] && s[i] == '|' {
			stages = append(stages, s[start:i])
			start = i + 1
		}
	}
	return append(stages, s[start:])
}

// containsBareByte reports whether b occurs as a bare (unquoted, unescaped) byte
// in s.
func containsBareByte(s string, mask []bool, b byte) bool {
	for i := 0; i < len(s); i++ {
		if mask[i] && s[i] == b {
			return true
		}
	}
	return false
}

// bareMask returns a slice the length of s where element i is true iff byte i is
// shell syntax — outside single/double quotes and not part of a backslash
// escape. It mirrors tokenizeShell's quoting rules (single quotes are literal
// throughout, double quotes honor only the `\" \\ \$ `+"`"+“ escapes) so this
// package's operator detection treats `|`, `;`, `&&`, `||`, redirection, `$(`,
// and backticks as syntax exactly where the tokenizer would, and never inside a
// quoted or escaped span. It returns an error for an unterminated quote or a
// dangling trailing backslash, matching the tokenizer, so malformed input is
// rejected rather than silently broadening a match.
func bareMask(s string) ([]bool, error) {
	mask := make([]bool, len(s))
	n := len(s)
	i := 0
	for i < n {
		switch s[i] {
		case '\\':
			if i+1 >= n {
				return nil, errors.New("shell split: dangling backslash at end of input")
			}
			// The backslash and the byte it escapes are literal, not syntax.
			i += 2
		case '\'':
			i++
			for i < n && s[i] != '\'' {
				i++
			}
			if i >= n {
				return nil, errors.New("shell split: unterminated single quote")
			}
			i++
		case '"':
			i++
			for i < n && s[i] != '"' {
				if s[i] == '\\' && i+1 < n && isDoubleQuoteEscape(s[i+1]) {
					i += 2
					continue
				}
				i++
			}
			if i >= n {
				return nil, errors.New("shell split: unterminated double quote")
			}
			i++
		default:
			mask[i] = true
			i++
		}
	}
	return mask, nil
}
