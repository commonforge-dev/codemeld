// Literal-command canonicalization and byte-equal literal-subject matching for the permission system.
package permissions

import "strings"

// CanonicalLiteralForm returns the canonical literal-command subject for input.
// Leading and trailing whitespace is stripped, the command is
// tokenized with the shared shell parser (the same tokenizer direct-command
// normalization uses), and the tokens are re-emitted separated
// by a single ASCII space (U+0020).
//
// Each token is normalized conservatively so that commands which execute
// identically collapse to one subject. A token whose unescaped value is free of
// any character the tokenizer cannot prove inert is re-emitted from that value
// in one canonical spelling — bare when the value needs no quoting, single-quoted
// otherwise — so quoting-style-equivalent spellings (`'x'`, `"x"`, bare `x`,
// `a\ b`) collapse to one form. A token whose value carries expansion (`$`, “ ` “),
// globbing (`* ? [ ] { }`), or shell-operator/structure characters (`< > & | ; ( )`
// and friends) is preserved as its verbatim original span (ShellToken.Raw),
// because single-quoting it could change what the command executes; this keeps
// `'$x'`, `"$x"`, and `$x` distinct and leaves redirection/operator forms intact.
// A token shaped like a shell assignment word (a valid name followed by `=`) is
// likewise preserved verbatim, so an environment assignment (`FOO=bar`) never
// collapses onto a quoted command word (`"FOO=bar"`) the shell would instead try
// to execute as a program. A token whose value is a shell reserved word (`for`,
// `if`, `in`, …) is likewise preserved verbatim, so the unquoted grammar form
// (`for`, which the shell parses as a loop keyword) never collapses onto the
// quoted command-word spelling (`"for"`, an ordinary word naming a program) the
// shell parses differently. A token whose raw span carries a backslash-newline
// line continuation is also preserved, because the shell removes that sequence
// (so `echo\<newline>hi` runs as `echohi`) while the tokenizer models it as a
// literal newline — re-quoting would collapse it onto a different command.
// Re-emitting each token in a single fixed spelling separated by one delimiter is
// idempotent — CanonicalLiteralForm(CanonicalLiteralForm(x)) equals CanonicalLiteralForm(x).
//
// Normalization never widens what a grant authorizes: the program, flags,
// operators, and token values are unchanged — only the textual quoting
// representation of provably-equivalent tokens is normalized. The canonical form
// is what callers store as the subject, hash for the audit-trail argument_hash,
// and match against. A malformed command (unterminated quote
// or dangling backslash) returns the tokenizer's error so callers never silently
// broaden a permission match.
func CanonicalLiteralForm(input string) (string, error) {
	tokens, err := tokenizeShell(strings.TrimSpace(input))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, t := range tokens {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(canonicalToken(t))
	}
	return b.String(), nil
}

// canonicalToken returns the single normalized spelling of one parsed token.
// Tokens whose value contains a character the tokenizer cannot prove inert, are
// shaped like a shell assignment word, are a shell reserved word whose quoting
// changes grammar, or whose raw span carries a backslash-newline line
// continuation the tokenizer does not model, keep their raw span (fail closed);
// all others are re-emitted from their value.
func canonicalToken(t ShellToken) string {
	if containsShellMeta(t.Value) || looksLikeAssignment(t.Value) || isReservedWord(t.Value) || containsLineContinuation(t.Raw) {
		return t.Raw
	}
	return ShellQuote(t.Value)
}

// containsLineContinuation reports whether raw holds a backslash immediately
// followed by a newline or carriage return. The shell removes such a
// backslash-newline as line continuation (in unquoted and double-quoted
// context: `echo\<newline>hi` executes as `echohi`), but tokenizeShell models
// it as a literal newline in the token value. Re-quoting from that mismatched
// value would let a line-continuation command collapse onto a quoted
// literal-newline command of different shell text, so a token whose raw span
// carries the sequence keeps its verbatim spelling. Over-matching here (e.g. an
// escaped backslash before a real newline) only preserves more distinctions —
// it can never broaden a grant.
func containsLineContinuation(raw string) bool {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] == '\\' && (raw[i+1] == '\n' || raw[i+1] == '\r') {
			return true
		}
	}
	return false
}

// looksLikeAssignment reports whether value has the shape of a shell assignment
// word: a valid shell name followed by `=`. The quoting of such a token is
// grammatically significant in command position — bare NAME=val sets NAME in the
// command's environment, while a quoted "NAME=val" is a command word naming a
// program — so the token is preserved verbatim instead of re-quoted from its
// value. Re-quoting would drop the unquoted NAME= grammar (`FOO="a b"` becomes
// the command-word shape `'FOO=a b'`) and collapse an assignment word onto a
// quoted command word of the same value, letting one grant authorize the other
// despite different shell behavior. The check is by value (not position), so it
// also preserves assignment-shaped argument tokens — conservative, never a
// broadening: it can only keep two spellings distinct, never merge them.
func looksLikeAssignment(value string) bool {
	eq := strings.IndexByte(value, '=')
	if eq <= 0 {
		return false
	}
	return isValidShellName(value[:eq])
}

// isReservedWord reports whether value is a POSIX shell reserved word whose
// unquoted spelling is parsed as grammar rather than as a command word. Quoting
// such a word removes its grammar role (unquoted `for` opens a loop; `"for"` is
// an ordinary command word naming a program `for`), so a token whose value is a
// reserved word is preserved verbatim instead of re-quoted from its value —
// otherwise `for > out` and `"for" > out`, which the shell parses as different
// command forms, would collapse to one subject. The single-character reserved
// words (`{`, `}`, `!`) are already preserved via containsShellMeta, so only the
// word-shaped ones are listed here. The check is by value (not position), so it
// also preserves a reserved word used as an ordinary argument — conservative,
// never a broadening: it can only keep two spellings distinct, never merge them.
func isReservedWord(value string) bool {
	switch value {
	case "for", "if", "then", "do", "done", "case", "esac",
		"while", "until", "else", "elif", "fi", "in":
		return true
	}
	return false
}

// containsShellMeta reports whether s holds any character the shell may interpret
// as expansion, globbing, or an operator/structure — characters whose meaning
// depends on quoting context the tokenizer does not evaluate. A token's value
// carrying any of these cannot be safely re-quoted, so it keeps its raw spelling.
// Checking the value (not the raw span) is what keeps `'$x'`, `"$x"`, and `$x`
// distinct: the tokenizer yields value `$x` for all three, so all three fail
// closed to their differing raw forms.
func containsShellMeta(s string) bool {
	return strings.ContainsAny(s, "$`*?[](){}<>&|;~!#")
}

// ShellQuote renders value as one shell word in canonical form: returned bare
// when every character is safe unquoted, otherwise single-quoted with any
// embedded single quote spliced as the standard '\” sequence. value is assumed
// free of expansion/glob/operator characters (see containsShellMeta), so
// single-quoting reproduces it verbatim with no shell interpretation.
func ShellQuote(value string) string {
	if value != "" && !strings.ContainsFunc(value, runeNeedsQuote) {
		return value
	}
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range value {
		if r == '\'' {
			b.WriteString(`'\''`)
			continue
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// runeNeedsQuote reports whether r forces value to be quoted. Letters, digits,
// and a small set of always-inert punctuation are safe bare; anything else
// (whitespace, quotes, backslash, …) is quoted.
func runeNeedsQuote(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	case strings.ContainsRune("_-./=:,@+%", r):
		return false
	default:
		return true
	}
}

// MatchesLiteralSubject reports whether a canonical literal command subject
// matches a stored literal grant subject: a literal subject
// matches only itself, and two literal subjects are equal only when their
// canonical forms are byte-equal. Both arguments must already be canonical —
// callers pass the output of CanonicalLiteralForm — because matching performs no
// normalization itself. Whitespace- and quoting-style-equivalent commands match
// because CanonicalLiteralForm already collapsed them to one form upstream, not
// because this function re-normalizes; two forms that are not byte-equal after
// canonicalization never match here.
func MatchesLiteralSubject(canonicalInput string, storedSubject string) bool {
	return canonicalInput == storedSubject
}
