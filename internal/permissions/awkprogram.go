package permissions

import "strings"

type awkPrev int

const (
	awkOperand awkPrev = iota
	awkValue
	awkRegexEnd
	awkControlClose
	awkNoSlash
)

var awkBannedWords = map[string]bool{
	"system": true, "getline": true, "close": true, "fflush": true, "ENVIRON": true,
	"PROCINFO": true, "ARGV": true, "ARGC": true, "SYMTAB": true, "FUNCTAB": true,
}

var awkControlWords = map[string]bool{"if": true, "while": true, "for": true, "switch": true}

var awkNoSlashWords = map[string]bool{
	"if": true, "while": true, "for": true, "do": true, "else": true, "delete": true, "next": true,
	"nextfile": true, "function": true, "func": true, "BEGIN": true, "END": true, "BEGINFILE": true,
	"ENDFILE": true, "switch": true, "case": true, "default": true, "break": true, "continue": true,
	"length": true,
}

var awkOperators = []string{
	"&&", "||", "==", "!=", "!~", "<=", ">=", "+=", "-=", "*=", "%=", "^=", "++", "--",
	"[", ",", "{", "!", "~", "<", ">", "=", "+", "-", "*", "%", "^", "?", ":",
}

func awkReadOnlyProgram(prog string) bool {
	prev := awkOperand
	var parens []bool
	lastWord := ""
	inOutput, outputDepth := false, 0
	seen := false
	for i := 0; i < len(prog); {
		c := prog[i]
		switch c {
		case ' ', '\t':
			i++
			continue
		case '#':
			for i < len(prog) && prog[i] != '\n' {
				i++
			}
			continue
		case '\n':
			if inOutput && len(parens) == outputDepth && (prev == awkValue || prev == awkRegexEnd || prev == awkControlClose) {
				inOutput = false
			}
			prev = awkOperand
			i++
			continue
		case '\\':
			if i+1 < len(prog) && prog[i+1] == '\n' {
				i += 2
				continue
			}
			return false
		}
		seen = true
		word := ""
		switch {
		case c == '"':
			n, ok := awkStringLen(prog[i:])
			if !ok {
				return false
			}
			i += n
			prev = awkValue
		case c == '/' && prev == awkOperand:
			n, ok := awkRegexLen(prog[i:])
			if !ok {
				return false
			}
			i += n
			prev = awkRegexEnd
		case c == '/':
			if prev != awkValue {
				return false
			}
			i++
			if i < len(prog) && prog[i] == '=' {
				i++
			}
			prev = awkOperand
		case awkDigit(c) || c == '.' && i+1 < len(prog) && awkDigit(prog[i+1]):
			i += awkNumberLen(prog[i:])
			if i < len(prog) && awkIdentByte(prog[i]) {
				return false
			}
			prev = awkValue
		case awkIdentByte(c) && !awkDigit(c):
			n := 1
			for i+n < len(prog) && awkIdentByte(prog[i+n]) {
				n++
			}
			word = prog[i : i+n]
			i += n
			switch {
			case awkBannedWords[word]:
				return false
			case word == "print" || word == "printf":
				if !inOutput {
					inOutput, outputDepth = true, len(parens)
				}
				prev = awkOperand
			case word == "return" || word == "exit" || word == "in":
				prev = awkOperand
			case awkNoSlashWords[word]:
				prev = awkNoSlash
			default:
				prev = awkValue
			}
		case c == '(':
			parens = append(parens, awkControlWords[lastWord])
			i++
			prev = awkOperand
		case c == ')':
			if len(parens) == 0 {
				return false
			}
			prev = awkValue
			if parens[len(parens)-1] {
				prev = awkControlClose
			}
			parens = parens[:len(parens)-1]
			i++
		case c == ']':
			i++
			prev = awkValue
		case c == ';' || c == '}':
			if inOutput && len(parens) == outputDepth {
				inOutput = false
			}
			i++
			prev = awkOperand
		case c == '$':
			i++
			prev = awkNoSlash
		case strings.HasPrefix(prog[i:], ">>"):
			return false
		default:
			op := ""
			for _, o := range awkOperators {
				if strings.HasPrefix(prog[i:], o) {
					op = o
					break
				}
			}
			switch op {
			case "":
				return false
			case ">", ">=":
				if inOutput {
					return false
				}
			}
			i += len(op)
			prev = awkOperand
			if op == "++" || op == "--" {
				prev = awkNoSlash
			}
		}
		lastWord = word
	}
	return seen
}

func awkStringLen(s string) (int, bool) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
			if i >= len(s) || s[i] == '\n' {
				return 0, false
			}
		case '\n':
			return 0, false
		case '"':
			return i + 1, true
		}
	}
	return 0, false
}

func awkRegexLen(s string) (int, bool) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
			if i >= len(s) || s[i] == '\n' {
				return 0, false
			}
		case '\n':
			return 0, false
		case '/':
			return i + 1, true
		case '[':
			n, ok := awkBracketLen(s[i:])
			if !ok {
				return 0, false
			}
			i += n - 1
		}
	}
	return 0, false
}

// A `/` anywhere before the bracket's end rejects because awk implementations disagree on whether it
// ends the regex.
func awkBracketLen(s string) (int, bool) {
	i := 1
	if i < len(s) && s[i] == '^' {
		i++
	}
	if i < len(s) && s[i] == ']' {
		i++
	}
	for ; i < len(s); i++ {
		switch s[i] {
		case '/', '\n':
			return 0, false
		case ']':
			return i + 1, true
		case '\\':
			i++
			if i >= len(s) || s[i] == '/' || s[i] == '\n' {
				return 0, false
			}
		case '[':
			if i+1 < len(s) && strings.IndexByte(":.=", s[i+1]) >= 0 {
				end := strings.Index(s[i+2:], string(s[i+1])+"]")
				if end < 0 || strings.ContainsAny(s[i+2:i+2+end], "/\n") {
					return 0, false
				}
				i += end + 3
			}
		}
	}
	return 0, false
}

func awkNumberLen(s string) int {
	n := awkDigitsLen(s)
	if n < len(s) && s[n] == '.' {
		n++
		n += awkDigitsLen(s[n:])
	}
	if n < len(s) && (s[n] == 'e' || s[n] == 'E') {
		m := n + 1
		if m < len(s) && (s[m] == '+' || s[m] == '-') {
			m++
		}
		if d := awkDigitsLen(s[m:]); d > 0 {
			n = m + d
		}
	}
	return n
}

func awkDigitsLen(s string) int {
	n := 0
	for n < len(s) && awkDigit(s[n]) {
		n++
	}
	return n
}

func awkDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func awkIdentByte(c byte) bool {
	return awkDigit(c) || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_'
}
