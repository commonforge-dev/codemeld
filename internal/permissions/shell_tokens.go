// Shared shell-word tokenizer for permission-subject normalization: splits a command stage into tokens while preserving quote/escape and original-span metadata.
package permissions

import (
	"errors"
	"strings"
)

// ShellToken is one whitespace-delimited word parsed from a command stage by
// tokenizeShell. It carries the parsed value plus enough original-span metadata
// for both direct-command and literal-command normalization to decide how to
// re-emit the token.
type ShellToken struct {
	// Value is the unescaped, unquoted content — the string a shell would pass
	// to the program as a single argv entry. Literal canonicalization normalizes
	// most tokens from this value (see CanonicalLiteralForm).
	Value string
	// Raw is the verbatim input span that produced this token, including the
	// original quote characters and backslashes. Literal canonicalization falls
	// back to Raw for tokens whose value carries expansion/glob/operator syntax
	// it cannot prove equivalent.
	Raw string
	// Quoted is true when any character of the token appeared inside single or
	// double quotes. Direct-command normalization uses it to keep a quoted `:*`
	// from being read as the wildcard token.
	Quoted bool
	// unquoted holds the token's characters that appeared outside any quote and
	// were not backslash-escaped, in original order. Direct-command
	// normalization uses it to detect unquoted shell operators and leading
	// KEY=VALUE assignments without misfiring on the same characters when they
	// are quoted or escaped.
	unquoted string
}

// tokenizeShell splits stage into shell-style words, honoring single quotes,
// double quotes, and backslash escapes. Leading and trailing whitespace is
// ignored. It returns an error for an unterminated quote or a dangling trailing
// backslash so callers never silently broaden a permission match on malformed
// input. The same parser backs both direct-command normalization and
// literal-command canonicalization.
func tokenizeShell(stage string) ([]ShellToken, error) {
	var tokens []ShellToken
	n := len(stage)
	i := 0
	for {
		for i < n && isShellSpace(stage[i]) {
			i++
		}
		if i >= n {
			break
		}
		start := i
		var value, unquoted strings.Builder
		quoted := false
	token:
		for i < n {
			c := stage[i]
			switch {
			case isShellSpace(c):
				break token
			case c == '\\':
				if i+1 >= n {
					return nil, errors.New("shell tokenize: dangling backslash at end of input")
				}
				value.WriteByte(stage[i+1])
				i += 2
			case c == '\'':
				quoted = true
				i++
				j := i
				for j < n && stage[j] != '\'' {
					j++
				}
				if j >= n {
					return nil, errors.New("shell tokenize: unterminated single quote")
				}
				value.WriteString(stage[i:j])
				i = j + 1
			case c == '"':
				quoted = true
				i++
				for i < n && stage[i] != '"' {
					if stage[i] == '\\' && i+1 < n && isDoubleQuoteEscape(stage[i+1]) {
						value.WriteByte(stage[i+1])
						i += 2
						continue
					}
					value.WriteByte(stage[i])
					i++
				}
				if i >= n {
					return nil, errors.New("shell tokenize: unterminated double quote")
				}
				i++
			default:
				value.WriteByte(c)
				unquoted.WriteByte(c)
				i++
			}
		}
		tokens = append(tokens, ShellToken{
			Value:    value.String(),
			Raw:      stage[start:i],
			Quoted:   quoted,
			unquoted: unquoted.String(),
		})
	}
	return tokens, nil
}

func isShellSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isDoubleQuoteEscape reports whether a backslash inside double quotes escapes
// the following byte. Per POSIX, inside double quotes a backslash is literal
// unless it precedes one of these characters.
func isDoubleQuoteEscape(c byte) bool {
	return c == '"' || c == '\\' || c == '$' || c == '`'
}
