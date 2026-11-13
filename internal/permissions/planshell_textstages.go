package permissions

import "strings"

// findNoValuePredicates are the only no-value read-only find predicates, actions, and boolean
// operators the safe subset accepts. Every other primary/action (`-delete`, `-exec`, `-prune`,
// `-printf`, `-fls`, …) is unlisted and so classifies mutating.
var findNoValuePredicates = map[string]struct{}{
	"-empty":  {}, // matches empty files/dirs; reads only
	"-print":  {}, // prints matched paths to stdout; reads only
	"-print0": {}, // prints matched paths NUL-separated; reads only
	"-o":      {}, // boolean or
	"-a":      {}, // boolean and
	"-not":    {},
	"!":       {},
}

// findBooleanOperators maps each operator admitted by findNoValuePredicates to whether it requires a
// complete expression on its left. All four require one on their right.
var findBooleanOperators = map[string]bool{
	"-o":   true,
	"-a":   true,
	"-not": false,
	"!":    false,
}

// findValuePredicates are the only value-taking read-only find predicates the safe subset accepts,
// each mapped to the validator its single following value token must pass. A predicate with a missing
// or invalid value classifies mutating.
var findValuePredicates = map[string]func(string) bool{
	"-type":     findValidType,      // one standard single-letter file-type code
	"-name":     findValidPattern,   // one glob pattern token
	"-iname":    findValidPattern,   // case-insensitive glob
	"-path":     findValidPattern,   // glob against the whole path
	"-ipath":    findValidPattern,   // case-insensitive path glob
	"-maxdepth": findValidNonNegInt, // non-negative depth limit
	"-mindepth": findValidNonNegInt, // non-negative depth floor
	"-mtime":    findValidTimeInt,   // find-style signed integer (days)
	"-ctime":    findValidTimeInt,
	"-atime":    findValidTimeInt,
	"-mmin":     findValidTimeInt, // find-style signed integer (minutes)
	"-cmin":     findValidTimeInt,
	"-amin":     findValidTimeInt,
	"-size":     findValidSize, // find-style size expression, e.g. 0, +1M, -100k
	"-newer":    findValidStartPath,
}

func findStageReadOnly(tokens []string) bool {
	i := 1
	paths := 0
	for i < len(tokens) && findValidStartPath(tokens[i]) {
		paths++
		i++
	}
	if paths == 0 { // a safe subset always names at least one relative start path
		return false
	}
	exprStart := i
	complete := false // whether a complete expression ends at the current position
	for i < len(tokens) {
		tok := tokens[i]
		if valid, ok := findValuePredicates[tok]; ok {
			if i+1 >= len(tokens) || !valid(tokens[i+1]) {
				return false // missing or invalid value
			}
			if _, isOperator := findBooleanOperators[tokens[i+1]]; isOperator {
				return false
			}
			complete = true
			i += 2
			continue
		}
		if _, ok := findNoValuePredicates[tok]; ok {
			if needsLeft, isOperator := findBooleanOperators[tok]; isOperator {
				if needsLeft && !complete {
					return false
				}
				complete = false
			} else {
				complete = true
			}
			i++
			continue
		}
		return false // unknown option/action/operator, or a late plain path token
	}
	return complete || i == exprStart
}

// Narrowing the start-path posture below the broader raw-shell path scope is deliberate;
// broadening it needs explicit review.
func findValidStartPath(tok string) bool {
	switch tok {
	case "", "!", "(", ")", ",":
		return false
	}
	if tok[0] == '-' || tok[0] == '/' { // option/operator/`--`/dash-leading, or absolute
		return false
	}
	if tok[0] == '~' || tok[0] == '$' { // expanded to a home path at exec, after classification
		return false
	}
	for _, seg := range strings.Split(tok, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// findValidType reports whether v is one standard single-letter find file-type code. The set is the
// portable intersection across GNU, BSD/macOS, and BusyBox find; platform-specific codes fail closed.
func findValidType(v string) bool {
	return len(v) == 1 && strings.IndexByte("bcdpfls", v[0]) >= 0
}

// findValidPattern reports whether v is a usable glob pattern token — any non-empty token, since find
// consumes the token after `-name`/`-path` literally as the pattern and never executes it.
func findValidPattern(v string) bool {
	return v != ""
}

// findValidNonNegInt reports whether v is a non-negative decimal integer (for -maxdepth/-mindepth).
func findValidNonNegInt(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// findValidTimeInt reports whether v is a find-style signed integer (`0`, `1`, `-1`, `+7`) for the
// -mtime/-ctime/-atime/-mmin/-cmin/-amin predicates.
func findValidTimeInt(v string) bool {
	if v != "" && (v[0] == '+' || v[0] == '-') {
		v = v[1:]
	}
	return findValidNonNegInt(v)
}

// findValidSize reports whether v is a find-style size expression: an optional `+`/`-` prefix, a
// decimal magnitude, and an optional single unit suffix from the portable set (`b`,`c`,`w`,`k`,`M`,`G`),
// e.g. `0`, `+1M`, `-100k`.
func findValidSize(v string) bool {
	if v != "" && (v[0] == '+' || v[0] == '-') {
		v = v[1:]
	}
	if v != "" && strings.IndexByte("bcwkMG", v[len(v)-1]) >= 0 {
		v = v[:len(v)-1]
	}
	return findValidNonNegInt(v)
}

func sedStageReadOnly(tokens []string) bool {
	args := tokens[1:]
	i := 0
	for i < len(args) && sedReadOnlyOption(args[i]) {
		i++
	}
	if i >= len(args) || !sedPrintOnlyScript(args[i]) {
		return false
	}
	files := args[i+1:]
	for _, f := range files {
		if f == "" || strings.HasPrefix(f, "-") {
			return false
		}
	}
	return true
}

func sedReadOnlyOption(tok string) bool {
	switch tok {
	case "-n", "--quiet", "--silent":
		return true
	}
	return false
}

func sedPrintOnlyScript(s string) bool {
	for _, command := range strings.Split(s, ";") {
		if !sedReadOnlyCommand(command) {
			return false
		}
	}
	return true
}

func sedReadOnlyCommand(s string) bool {
	body, addresses, ok := sedTrimAddress(s)
	if !ok || body == "" {
		return false
	}
	if body[0] == 'q' {
		return body == "q" && addresses < 2
	}
	if body[0] != 'p' && body[0] != '=' {
		return false
	}
	rest := body[1:]
	return rest == "" || rest == "q"
}

func sedTrimAddress(s string) (string, int, bool) {
	if rest, ok := strings.CutPrefix(s, "$"); ok {
		if strings.HasPrefix(rest, ",") {
			return "", 0, false
		}
		return rest, 1, true
	}
	rest, n := sedTrimAddressPart(s)
	if n == 0 {
		return rest, 0, true
	}
	if !strings.HasPrefix(rest, ",") {
		return rest, 1, true
	}
	rest, n = sedTrimAddressPart(rest[1:])
	if n == 0 {
		return "", 0, false
	}
	return rest, 2, true
}

func sedTrimAddressPart(s string) (string, int) {
	if strings.HasPrefix(s, "$") {
		return s[1:], 1
	}
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return s[n:], n
}

func awkStageReadOnly(tokens []string) bool {
	args := tokens[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch {
		case args[0] == "-F" && len(args) > 1 && args[1] != "":
			args = args[2:]
		case len(args[0]) > 2 && strings.HasPrefix(args[0], "-F"):
			args = args[1:]
		default:
			return false
		}
	}
	if len(args) == 0 || !awkRangePrintProgram(args[0]) && !awkReadOnlyProgram(args[0]) {
		return false
	}
	// AWK reads a `name=value` operand as an assignment, and GNU AWK opens `/dev/tcp`, `/dev/udp`,
	// and `/inet` paths as network connections.
	for _, f := range args[1:] {
		if f == "" || strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
			return false
		}
		if strings.HasPrefix(f, "/dev/") || strings.HasPrefix(f, "/inet") {
			return false
		}
	}
	return true
}

func awkRangePrintProgram(s string) bool {
	rest, counter, ok := awkCounter(awkSpace(s))
	if !ok {
		return false
	}
	if rest, ok = awkBound(rest, ">="); !ok {
		return false
	}
	if rest, ok = strings.CutPrefix(awkSpace(rest), "&&"); !ok {
		return false
	}
	rest, upper, ok := awkCounter(awkSpace(rest))
	if !ok || upper != counter {
		return false
	}
	if rest, ok = awkBound(rest, "<="); !ok {
		return false
	}
	if rest, ok = strings.CutPrefix(awkSpace(rest), "{"); !ok {
		return false
	}
	if rest, ok = awkWord(awkSpace(rest), "print"); !ok {
		return false
	}
	for {
		rest = awkSpace(rest)
		if after, closed := strings.CutPrefix(rest, "}"); closed {
			return awkSpace(after) == ""
		}
		if rest, ok = awkTerm(rest); !ok {
			return false
		}
	}
}

func awkBound(s, op string) (string, bool) {
	rest, ok := strings.CutPrefix(awkSpace(s), op)
	if !ok {
		return "", false
	}
	return awkDigits(awkSpace(rest))
}

func awkTerm(s string) (string, bool) {
	switch {
	case s == "":
		return "", false
	case s[0] == '"':
		return awkString(s)
	case s[0] == '$':
		return awkWord(s[1:], "0")
	case s[0] >= '0' && s[0] <= '9':
		return awkDigits(s)
	}
	rest, _, ok := awkCounter(s)
	return rest, ok
}

func awkCounter(s string) (string, string, bool) {
	for _, name := range []string{"FNR", "NR"} {
		if rest, ok := awkWord(s, name); ok {
			return rest, name, true
		}
	}
	return "", "", false
}

func awkString(s string) (string, bool) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[i+1:], true
		case '\\', '\n':
			return "", false
		}
	}
	return "", false
}

func awkDigits(s string) (string, bool) {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n == 0 {
		return "", false
	}
	return awkWord(s, s[:n])
}

func awkWord(s, lit string) (string, bool) {
	rest, ok := strings.CutPrefix(s, lit)
	if !ok || !awkBoundary(rest) {
		return "", false
	}
	return rest, true
}

// A trailing `.` or word character means the token continues into something the grammar never
// admits: `printf`, a `NR`-prefixed variable, or a float/exponent bound.
func awkBoundary(s string) bool {
	if s == "" {
		return true
	}
	switch c := s[0]; {
	case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_', c == '.':
		return false
	}
	return true
}

func awkSpace(s string) string {
	return strings.TrimLeft(s, " \t")
}

func uniqStageReadOnly(tokens []string) bool {
	args := tokens[1:]
	if len(args) == 1 && (args[0] == "--help" || args[0] == "--version") {
		return true
	}
	bareOptionalMethod := false
	for len(args) > 0 {
		if uniqReadOnlyOption(args[0]) {
			bareOptionalMethod = args[0] == "--all-repeated" || args[0] == "--group"
			args = args[1:]
			continue
		}
		n := uniqValueOptionTokens(args)
		if n < 0 {
			return false
		}
		if n == 0 {
			break
		}
		bareOptionalMethod = false
		args = args[n:]
	}
	if len(args) == 0 {
		return true
	}
	if bareOptionalMethod {
		return false
	}
	return len(args) == 1 && !strings.HasPrefix(args[0], "-")
}

func uniqReadOnlyOption(tok string) bool {
	switch tok {
	case "-c", "--count", "-d", "--repeated", "-D", "--all-repeated":
		return true
	case "-i", "--ignore-case", "-u", "--unique", "-z", "--zero-terminated":
		return true
	case "--all-repeated=none", "--all-repeated=prepend", "--all-repeated=separate":
		return true
	case "--group", "--group=separate", "--group=prepend", "--group=append", "--group=both":
		return true
	}
	return false
}

func uniqValueOptionTokens(args []string) int {
	tok := args[0]
	for _, opt := range []struct{ short, long string }{
		{"-f", "--skip-fields"},
		{"-s", "--skip-chars"},
		{"-w", "--check-chars"},
	} {
		switch {
		case tok == opt.short, tok == opt.long:
			if len(args) > 1 && findValidNonNegInt(args[1]) {
				return 2
			}
			return -1
		case strings.HasPrefix(tok, opt.short):
			if findValidNonNegInt(tok[len(opt.short):]) {
				return 1
			}
			return -1
		case strings.HasPrefix(tok, opt.long+"="):
			if findValidNonNegInt(tok[len(opt.long)+1:]) {
				return 1
			}
			return -1
		}
	}
	return 0
}
