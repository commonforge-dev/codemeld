package permissions

import "strings"

const devNullTarget = "/dev/null"

func stripNullRedirects(canonical string) (string, bool) {
	mask, err := bareMask(canonical)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	kept := 0
	for i := 0; i < len(canonical); i++ {
		if !mask[i] || (canonical[i] != '>' && canonical[i] != '<') {
			continue
		}
		start, end, ok := nullRedirectSpan(canonical, mask, i)
		if !ok || start < kept {
			return "", false
		}
		b.WriteString(canonical[kept:start])
		kept = end
		i = end - 1
	}
	b.WriteString(canonical[kept:])
	return b.String(), true
}

// A here-string only feeds an inert word to stdin, so removing it leaves the programs that run
// unchanged; any span whose word or boundaries could mean more is rejected, never guessed at.
func stripClassifierHereStrings(subject string) (string, bool) {
	mask, err := bareMask(subject)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	kept := 0
	for i := 0; i < len(subject); i++ {
		if !mask[i] || subject[i] != '<' {
			continue
		}
		opEnd := i
		for opEnd < len(subject) && mask[opEnd] && subject[opEnd] == '<' {
			opEnd++
		}
		if opEnd-i < 3 {
			i = opEnd - 1
			continue
		}
		start, end, ok := hereStringSpan(subject, mask, i, opEnd)
		if !ok {
			return "", false
		}
		b.WriteString(subject[kept:start])
		kept = end
		i = end - 1
	}
	b.WriteString(subject[kept:])
	return b.String(), true
}

func hereStringSpan(s string, mask []bool, op, opEnd int) (start, end int, ok bool) {
	if opEnd-op != 3 || strings.ContainsAny(s, "\n\r") || op == 0 || !mask[op-1] || !isShellSpace(s[op-1]) {
		return 0, 0, false
	}
	prev := op - 1
	for prev >= 0 && mask[prev] && isShellSpace(s[prev]) {
		prev--
	}
	if prev < 0 || (mask[prev] && strings.IndexByte(";|&(){}<>!", s[prev]) >= 0) {
		return 0, 0, false
	}
	word := opEnd
	for word < len(s) && mask[word] && isShellSpace(s[word]) {
		word++
	}
	if word == len(s) {
		return 0, 0, false
	}
	end = word
	if s[word] == '\'' {
		end = word + 1 + strings.IndexByte(s[word+1:], '\'') + 1
	} else {
		for end < len(s) && mask[end] && !runeNeedsQuote(rune(s[end])) {
			end++
		}
		if end == word {
			return 0, 0, false
		}
	}
	if end < len(s) && (!mask[end] || (!isShellSpace(s[end]) && strings.IndexByte(";|&", s[end]) < 0)) {
		return 0, 0, false
	}
	return op - 1, end, true
}

func stripLiteralForClassification(canonical string) (string, bool) {
	remainder, ok := stripClassifierHereStrings(canonical)
	if !ok {
		return "", false
	}
	return stripNullRedirects(remainder)
}

func nullRedirectSpan(s string, mask []bool, i int) (start, end int, ok bool) {
	if s[i] != '>' {
		return 0, 0, false
	}
	start = i
	for start > 0 && mask[start-1] && s[start-1] >= '0' && s[start-1] <= '9' {
		start--
	}
	descriptor := s[start:i]
	switch descriptor {
	case "", "1", "2":
	default:
		return 0, 0, false
	}
	if start > 0 {
		switch {
		case !mask[start-1]:
			return 0, 0, false
		case isShellSpace(s[start-1]):
			start--
		case descriptor == "" && strings.IndexByte("&|;<>", s[start-1]) < 0:
		default:
			return 0, 0, false
		}
	}
	j := i + 1
	if j < len(s) && mask[j] && s[j] == '&' {
		return dupRedirectSpan(s, mask, start, j, descriptor)
	}
	if j < len(s) && mask[j] && s[j] == '>' {
		return 0, 0, false
	}
	for j < len(s) && mask[j] && isShellSpace(s[j]) {
		j++
	}
	end = j + len(devNullTarget)
	if end > len(s) || s[j:end] != devNullTarget {
		return 0, 0, false
	}
	for k := j; k < end; k++ {
		if !mask[k] {
			return 0, 0, false
		}
	}
	if !redirectSpanTerminated(s, mask, end) {
		return 0, 0, false
	}
	return start, end, true
}

// A descriptor duplication creates no file and truncates none, which is why these two spellings are
// admitted into a read-only classification.
func dupRedirectSpan(s string, mask []bool, start, amp int, descriptor string) (int, int, bool) {
	var target byte
	switch descriptor {
	case "1":
		target = '2'
	case "2":
		target = '1'
	default:
		return 0, 0, false
	}
	end := amp + 2
	if end > len(s) || !mask[amp+1] || s[amp+1] != target {
		return 0, 0, false
	}
	if !redirectSpanTerminated(s, mask, end) {
		return 0, 0, false
	}
	return start, end, true
}

func redirectSpanTerminated(s string, mask []bool, end int) bool {
	if end >= len(s) {
		return true
	}
	return isShellSpace(s[end]) || (mask[end] && strings.IndexByte(";|&", s[end]) >= 0)
}

func tokenExpansionFree(raw string) bool {
	if containsLineContinuation(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; c {
		case '\\':
			if i+1 >= len(raw) {
				return false
			}
			i++
		case '\'':
			j := strings.IndexByte(raw[i+1:], '\'')
			if j < 0 {
				return false
			}
			i += j + 1
		case '"':
			i++
			for i < len(raw) && raw[i] != '"' {
				if raw[i] == '\\' && i+1 < len(raw) && isDoubleQuoteEscape(raw[i+1]) {
					i += 2
					continue
				}
				if raw[i] == '$' || raw[i] == '`' {
					return false
				}
				i++
			}
			if i >= len(raw) {
				return false
			}
		default:
			if runeNeedsQuote(rune(c)) {
				return false
			}
		}
	}
	return true
}

func stagesExpansionFree(stages []StageNormalization) bool {
	for _, stage := range stages {
		tokens, err := tokenizeShell(stage.Source)
		if err != nil {
			return false
		}
		for _, t := range tokens {
			if !tokenExpansionFree(t.Raw) {
				return false
			}
		}
	}
	return true
}

// LiteralRunsHg and LiteralRunsPS report whether a literal-route command runs a named program in any
// stage, after the `/dev/null` redirects classification strips. They fail closed on text they cannot
// decompose, which only costs a route that never reached the program.
func LiteralRunsHg(canonical string) bool {
	return literalRunsProgram(canonical, "hg")
}

func LiteralRunsPS(canonical string) bool {
	return literalRunsProgram(canonical, "ps")
}

func literalRunsProgram(canonical, program string) bool {
	stripped, ok := stripLiteralForClassification(canonical)
	if !ok {
		return false
	}
	if _, stages, _, ok := SimpleCompoundStages(stripped); ok {
		return stagesRunProgram(stages, program)
	}
	split, err := SplitCommand(stripped)
	if err != nil {
		return false
	}
	return stagesRunProgram(split.Stages, program)
}

func stagesRunProgram(stages []StageNormalization, program string) bool {
	for _, stage := range stages {
		if len(stage.Tokens) > 0 && stage.Tokens[0] == program {
			return true
		}
	}
	return false
}

func classifyStrippedSingleStage(stages []StageNormalization) OperationClass {
	stage := stages[0]
	if stage.Route != RouteDirect || len(stage.Assignments) > 0 {
		return ClassMutating
	}
	if stageIsShellProgram(stage.Tokens) || stageNeedsOwnedArgv(stage.Tokens) || !stageTokensReadOnly(stage.Tokens) {
		return ClassMutating
	}
	if stageArgDependent(stage.Tokens) && !stagesExpansionFree(stages) {
		return ClassMutating
	}
	return ClassReadOnly
}

type literalBreakdown struct {
	stripped  string
	wrapped   bool
	compound  bool
	stages    []StageNormalization
	operators []string
}

func breakDownLiteral(canonical string) (literalBreakdown, bool) {
	stripped, ok := stripLiteralForClassification(canonical)
	if !ok {
		return literalBreakdown{}, false
	}
	literal := literalBreakdown{stripped: stripped}
	literal.wrapped, literal.stages, literal.operators, literal.compound = SimpleCompoundStages(stripped)
	if literal.compound {
		return literal, true
	}
	split, err := SplitCommand(stripped)
	if err != nil || !split.AllowedShell || split.LiteralRoute || split.CdHint != "" || len(split.Stages) != 1 {
		return literalBreakdown{}, false
	}
	literal.stages = split.Stages
	return literal, true
}

func classifyLiteralCompound(canonical string) OperationClass {
	// Even quoted substitutions execute under `sh -c`.
	if strings.Contains(canonical, "$(") || strings.Contains(canonical, "`") {
		return ClassMutating
	}
	literal, ok := breakDownLiteral(canonical)
	if !ok {
		return ClassMutating
	}
	stripped, wrapped, stages, operators := literal.stripped, literal.wrapped, literal.stages, literal.operators
	reparsedByShell := stripped != canonical
	if !literal.compound {
		if !reparsedByShell && !bareEnvTokens(stages[0].Tokens) {
			return ClassMutating
		}
		return classifyStrippedSingleStage(stages)
	}
	// A redirect-free all-`|` compound never reaches here — SplitCommand keeps it on the direct
	// route for per-stage authorization — so an unstripped one arrived by a cause still in force.
	if !wrapped && !reparsedByShell {
		hasNonPipeOperator := false
		for _, op := range operators {
			if op != "|" {
				hasNonPipeOperator = true
			}
		}
		if !hasNonPipeOperator {
			return ClassMutating
		}
	}
	argSensitive := false
	argDependent := false
	for _, stage := range stages {
		if stageIsShellProgram(stage.Tokens) || stageNeedsOwnedArgv(stage.Tokens) || !stageTokensReadOnly(stage.Tokens) {
			return ClassMutating
		}
		argSensitive = argSensitive || (stageArgSensitive(stage.Tokens) && !bareEnvTokens(stage.Tokens))
		argDependent = argDependent || stageArgDependent(stage.Tokens)
	}
	if wrapped {
		toks, err := tokenizeShell(stripped)
		if err != nil || len(toks) != 3 || !tokenExpansionFree(toks[2].Raw) {
			return ClassMutating
		}
		if !argSensitive || !stagesExpansionFree(stages) {
			return ClassMutating
		}
		return ClassReadOnly
	}
	if argDependent && !stagesExpansionFree(stages) {
		return ClassMutating
	}
	if argSensitive && !reparsedByShell {
		return ClassMutating
	}
	return ClassReadOnly
}
