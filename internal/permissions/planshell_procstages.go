package permissions

import "strings"

const (
	maxDiagInterval = 3600
	maxDiagCount    = 1000
)

func validBoundedInt(v string, max int) bool {
	if !findValidNonNegInt(v) {
		return false
	}
	n := 0
	for i := 0; i < len(v); i++ {
		digit := int(v[i] - '0')
		if n > max/10 || (n == max/10 && digit > max%10) {
			return false
		}
		n = n*10 + digit
	}
	return true
}

func validPositiveBoundedInt(v string, max int) bool {
	if !validBoundedInt(v, max) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] != '0' {
			return true
		}
	}
	return false
}

func validPidList(v string) bool {
	if v == "" {
		return false
	}
	for _, p := range strings.Split(v, ",") {
		if !findValidNonNegInt(p) {
			return false
		}
	}
	return true
}

// No documented Linux or FreeBSD ps(1) option writes a file, executes another program, opens a
// network connection, or escapes scope, and its operands are PIDs, so the option set is not
// restricted. Command-substitution syntax — "$(" or a backtick — is refused because it names
// another program to run; SplitCommand already keeps every substitution the shell would perform off
// direct execution, so this refusal only costs a prompt for inert quoted text. Every other argument
// spelling, including a quoted variable or glob, only changes argument text and is inert under
// direct execution, which runs the literal argv.
func psStageReadOnly(tokens []string) bool {
	for _, tok := range tokens[1:] {
		if strings.Contains(tok, "$(") || strings.Contains(tok, "`") {
			return false
		}
	}
	return true
}

// Any argv is inert only when test(1) runs directly: `sh -c` selects the shell builtin, whose bash
// `-v` primary runs a command substitution inside an array subscript, so the policy stays argSensitive.
func testStageReadOnly([]string) bool {
	return true
}

const pgrepFlags = "flaicvwxno"

func pgrepStageReadOnly(tokens []string) bool {
	operands := 0
	selectors := 0
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		switch tok {
		case "-u", "-U", "-P":
			if i+1 >= len(tokens) {
				return false
			}
			val := tokens[i+1]
			if tok == "-P" {
				if !validPidList(val) {
					return false
				}
			} else if val == "" {
				return false
			}
			selectors++
			i += 2
			continue
		}
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(pgrepFlags, tok[k]) < 0 {
					return false
				}
			}
			i++
			continue
		}
		operands++
		if operands > 1 {
			return false
		}
		i++
	}
	return operands+selectors >= 1
}

const pidofFlags = "sxqcz"

func pidofStageReadOnly(tokens []string) bool {
	names := 0
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(pidofFlags, tok[k]) < 0 {
					return false
				}
			}
			continue
		}
		if tok == "" {
			return false
		}
		names++
	}
	return names >= 1
}

const pstreeFlags = "panhugscl"

func pstreeStageReadOnly(tokens []string) bool {
	operands := 0
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(pstreeFlags, tok[k]) < 0 {
					return false
				}
			}
			continue
		}
		if tok == "" {
			return false
		}
		operands++
		if operands > 1 {
			return false
		}
	}
	return true
}

func lsofStageReadOnly(tokens []string) bool {
	return len(tokens) == 3 && tokens[1] == "-p" && findValidNonNegInt(tokens[2])
}

const ssReadFlags = "tulnpaemis46xwH"

func ssStageReadOnly(tokens []string) bool {
	for _, tok := range tokens[1:] {
		if len(tok) < 2 || tok[0] != '-' {
			return false
		}
		for k := 1; k < len(tok); k++ {
			if strings.IndexByte(ssReadFlags, tok[k]) < 0 {
				return false
			}
		}
	}
	return true
}

const freeFlags = "bkmghtwlo"

func freeStageReadOnly(tokens []string) bool {
	hasS, hasC := false, false
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		if len(tok) < 2 || tok[0] != '-' {
			return false
		}
		if tok == "-s" || tok == "-c" {
			if i+1 >= len(tokens) {
				return false
			}
			if tok == "-s" {
				if !validBoundedInt(tokens[i+1], maxDiagInterval) {
					return false
				}
				hasS = true
			} else {
				if !validBoundedInt(tokens[i+1], maxDiagCount) {
					return false
				}
				hasC = true
			}
			i += 2
			continue
		}
		if strings.HasPrefix(tok, "-s") {
			if !validBoundedInt(tok[2:], maxDiagInterval) {
				return false
			}
			hasS = true
			i++
			continue
		}
		if strings.HasPrefix(tok, "-c") {
			if !validBoundedInt(tok[2:], maxDiagCount) {
				return false
			}
			hasC = true
			i++
			continue
		}
		for k := 1; k < len(tok); k++ {
			if strings.IndexByte(freeFlags, tok[k]) < 0 {
				return false
			}
		}
		i++
	}
	return hasS == hasC
}

const vmstatFlags = "asdDwtnfm"

func vmstatStageReadOnly(tokens []string) bool {
	operands := make([]string, 0, 2)
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for k := 1; k < len(tok); k++ {
				if strings.IndexByte(vmstatFlags, tok[k]) < 0 {
					return false
				}
			}
			continue
		}
		operands = append(operands, tok)
	}
	switch len(operands) {
	case 0:
		return true
	case 2:
		return validBoundedInt(operands[0], maxDiagInterval) && validBoundedInt(operands[1], maxDiagCount)
	default:
		return false
	}
}

func uptimeStageReadOnly(tokens []string) bool {
	for _, tok := range tokens[1:] {
		if tok != "-p" && tok != "-s" {
			return false
		}
	}
	return true
}

func freebsdPgrepStageReadOnly(tokens []string) bool {
	patterns := 0
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "" {
			return false
		}
		if tok[0] != '-' {
			patterns++
			continue
		}
		if len(tok) < 2 || strings.HasPrefix(tok, "--") || patterns > 0 {
			return false
		}
		for j := 1; j < len(tok); j++ {
			if strings.IndexByte("Safilnoqvx", tok[j]) >= 0 {
				continue
			}
			if strings.IndexByte("GPUgsu", tok[j]) < 0 {
				return false
			}
			value := tok[j+1:]
			if value == "" {
				if i+1 >= len(tokens) {
					return false
				}
				value = tokens[i+1]
				i++
			}
			if !validPidList(value) {
				return false
			}
			j = len(tok)
		}
	}
	return patterns > 0
}

func freebsdPidofStageReadOnly(tokens []string) bool {
	names := 0
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			if len(tok) < 2 {
				return false
			}
			for i := 1; i < len(tok); i++ {
				if strings.IndexByte("sxqz", tok[i]) < 0 {
					return false
				}
			}
			continue
		}
		if tok == "" {
			return false
		}
		names++
	}
	return names > 0
}

func freebsdPstreeStageReadOnly(tokens []string) bool {
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-U" || tok == "-w" {
			continue
		}
		if tok == "-g" || tok == "-l" || tok == "-p" {
			if i+1 >= len(tokens) {
				return false
			}
			value := tokens[i+1]
			if tok == "-g" {
				if value != "1" && value != "2" && value != "3" {
					return false
				}
			} else if tok == "-l" && !validPositiveBoundedInt(value, maxDiagCount) {
				return false
			} else if tok == "-p" && !findValidNonNegInt(value) {
				return false
			}
			i++
			continue
		}
		if !findValidNonNegInt(tok) {
			return false
		}
	}
	return true
}

func freebsdFstatStageReadOnly(tokens []string) bool {
	return len(tokens) == 3 && tokens[1] == "-p" && findValidNonNegInt(tokens[2])
}

func freebsdProcstatStageReadOnly(tokens []string) bool {
	return len(tokens) == 3 && (tokens[1] == "-f" || tokens[1] == "-k" || tokens[1] == "-r") && findValidNonNegInt(tokens[2])
}

const freebsdSockstatFlags = "46AbCcfIiLlnqSsUuv"

func freebsdSockstatStageReadOnly(tokens []string) bool {
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-j" || tok == "-p" {
			if i+1 >= len(tokens) {
				return false
			}
			value := tokens[i+1]
			if tok == "-j" {
				if !findValidNonNegInt(value) {
					return false
				}
			} else if !freebsdValidPortList(value) {
				return false
			}
			i++
			continue
		}
		if len(tok) < 2 || tok[0] != '-' || strings.HasPrefix(tok, "--") {
			return false
		}
		for j := 1; j < len(tok); j++ {
			if strings.IndexByte(freebsdSockstatFlags, tok[j]) < 0 {
				return false
			}
		}
	}
	return true
}

func freebsdValidPortList(value string) bool {
	if value == "" {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		parts := strings.Split(item, "-")
		if len(parts) > 2 {
			return false
		}
		for _, part := range parts {
			if !validPositiveBoundedInt(part, 65535) {
				return false
			}
		}
	}
	return true
}

const freebsdVMStatFlags = "afHhimoPsz"

func freebsdVMStatStageReadOnly(tokens []string) bool {
	hasWait := false
	hasCount := false
	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-c" || tok == "-n" || tok == "-w" {
			if i+1 >= len(tokens) {
				return false
			}
			max := maxDiagCount
			switch tok {
			case "-w":
				max = maxDiagInterval
				hasWait = true
			case "-c":
				hasCount = true
			}
			if !validPositiveBoundedInt(tokens[i+1], max) {
				return false
			}
			i++
			continue
		}
		if len(tok) < 2 || tok[0] != '-' || strings.HasPrefix(tok, "--") {
			return false
		}
		for j := 1; j < len(tok); j++ {
			if strings.IndexByte(freebsdVMStatFlags, tok[j]) < 0 {
				return false
			}
		}
	}
	return !hasWait || hasCount
}

func freebsdUptimeStageReadOnly(tokens []string) bool {
	return len(tokens) == 1
}
