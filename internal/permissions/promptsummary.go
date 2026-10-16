// Presentation-only authorization-prompt summary: a plain-language explanation of one
// prompted request, the requested targets it can establish from a closed shell grammar or
// a prepared tool's lexical arguments, and the request-shape counts both prompt surfaces
// render above the decision choices. Nothing here reaches matching, grants, events, or
// execution.
package permissions

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// These must stay equal to the dispatch.Action* constants; internal/permissions cannot
// import internal/dispatch.
const (
	promptActionCreateFile      = "Create file"
	promptActionEditFile        = "Edit file"
	promptActionDeleteFile      = "Delete file"
	promptActionCreateDirectory = "Create directory"
	promptActionMove            = "Move"
)

const (
	promptEffectRead    = "reads"
	promptEffectWrite   = "writes"
	promptEffectRun     = "runs a command"
	promptEffectNetwork = "contacts a host"
	promptEffectUnknown = "unknown"
)

const (
	promptKindShell    = "shell command"
	promptKindPipeline = "shell pipeline"
	promptKindHost     = "host request"
	promptKindTool     = "tool call"
)

const (
	promptFactRuneCap  = 120
	promptTargetRowCap = 6
	promptDevNull      = "/dev/null"
)

const PromptFactsOverflowNotice = "… additional authorization facts; inspect the complete request"

const promptUnknownSentence = "Codemeld cannot determine the full effect or target of this request — inspect the complete request before deciding."

// PromptSummaryInput is the display-only payload one prompt renders, carried beside the
// MatchRequest so the summary never renders matching data.
type PromptSummaryInput struct {
	Action          string
	Command         string
	RequestedTarget string
	Body            string
	HostRequest     string
	Stages          []string
}

// PromptSummaryResult is display data only: no matching subject, grant input, or path a
// caller could act on.
type PromptSummaryResult struct {
	Kind       string
	Sentence   string
	Effect     string
	Targets    []string
	Unknown    bool
	StageCount int
	Lines      int
	Chars      int
}

// PromptSummary explains one authorization request for the prompt. It fails closed: any
// request whose effect and target it cannot establish from the closed shell grammar below
// or from a prepared tool's lexical arguments reports the unknown-effect fallback rather
// than a guess.
func PromptSummary(req MatchRequest, in PromptSummaryInput) PromptSummaryResult {
	if len(in.Stages) > 1 {
		return batchPromptSummary(in.Stages)
	}
	switch req.Kind {
	case subjectKindHost:
		return hostPromptSummary(req, in)
	case subjectKindDirect, subjectKindLiteral:
		return shellPromptSummary(req, in)
	case subjectKindTool:
		return toolPromptSummary(req, in)
	default:
		return promptUnknownEffect(PromptSummaryResult{Kind: promptKindTool})
	}
}

// DisplayRows is the ordered fixed block both prompt surfaces render above the decision
// choices. The first two rows are the summary sentence and the request-shape line; a
// renderer with a row budget keeps those two and may drop the target rows that follow.
func (s PromptSummaryResult) DisplayRows() []string {
	rows := []string{"Summary: " + s.Sentence, s.shapeLine()}
	for i, target := range s.Targets {
		if i >= promptTargetRowCap {
			rows = append(rows, fmt.Sprintf("… plus %d more requested targets; inspect the complete request", len(s.Targets)-promptTargetRowCap))
			break
		}
		rows = append(rows, "Requested target: "+BoundPromptFact(target))
	}
	return rows
}

func (s PromptSummaryResult) shapeLine() string {
	kind := s.Kind
	if s.StageCount > 1 {
		kind = fmt.Sprintf("%s (%d stages)", kind, s.StageCount)
	}
	return fmt.Sprintf("Request: %s, %d lines, %d characters, effect: %s", kind, s.Lines, s.Chars, s.Effect)
}

// BoundPromptFact renders one variable authorization fact for a fixed prompt block: every
// ASCII control byte becomes a visible \xHH escape kept whole, and the result is cut on a
// rune and escape boundary at 120 code points with an ellipsis.
func BoundPromptFact(value string) string {
	var b strings.Builder
	count := 0
	for _, r := range value {
		unit := string(r)
		if r < 0x20 || r == 0x7f {
			unit = fmt.Sprintf("\\x%02X", r)
		}
		n := utf8.RuneCountInString(unit)
		if count+n > promptFactRuneCap {
			b.WriteString("…")
			break
		}
		b.WriteString(unit)
		count += n
	}
	return b.String()
}

// VisibleControlEscape renders untrusted request text for a terminal that has no scrollback
// discipline of its own: every ASCII control byte other than a line feed or tab becomes a
// visible \xHH escape, so a request cannot conceal, clear, or reposition what the prompt
// prints after it. Nothing is dropped or shortened, so the complete request stays inspectable.
func VisibleControlEscape(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			fmt.Fprintf(&b, "\\x%02X", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func promptUnknownEffect(s PromptSummaryResult) PromptSummaryResult {
	s.Unknown = true
	s.Effect = promptEffectUnknown
	s.Targets = nil
	s.Sentence = promptUnknownSentence
	if s.StageCount > 1 {
		s.Sentence = fmt.Sprintf("One choice authorizes all %d pipeline stages. %s", s.StageCount, promptUnknownSentence)
	}
	return s
}

func promptShape(payload string) (lines, chars int) {
	if payload == "" {
		return 0, 0
	}
	return strings.Count(strings.TrimSuffix(payload, "\n"), "\n") + 1, utf8.RuneCountInString(payload)
}

func hostPromptSummary(req MatchRequest, in PromptSummaryInput) PromptSummaryResult {
	lines, chars := promptShape(in.HostRequest)
	s := PromptSummaryResult{
		Kind:     promptKindHost,
		Effect:   promptEffectNetwork,
		Sentence: "Sends this request over the network to the requested host.",
		Lines:    lines,
		Chars:    chars,
	}
	if req.Host != "" {
		s.Targets = []string{req.Host}
	}
	return s
}

func toolPromptSummary(req MatchRequest, in PromptSummaryInput) PromptSummaryResult {
	lines, chars := promptShape(in.Body)
	s := PromptSummaryResult{Lines: lines, Chars: chars, Effect: promptEffectWrite}
	switch in.Action {
	case promptActionCreateFile:
		s.Kind, s.Sentence = "file create", "Creates a file."
	case promptActionEditFile:
		s.Kind, s.Sentence = "file edit", "Edits an existing file."
	case promptActionDeleteFile:
		s.Kind, s.Sentence = "file delete", "Deletes a file."
	case promptActionCreateDirectory:
		s.Kind, s.Sentence = "directory create", "Creates a directory."
	case promptActionMove:
		s.Kind, s.Sentence = "file move", "Moves a file or directory to another path."
	default:
		kind, ok := promptReadToolKind(req.Subject)
		if !ok {
			s.Kind = promptKindTool
			return promptUnknownEffect(s)
		}
		s.Kind, s.Effect, s.Sentence = kind, promptEffectRead, "Reads only — this call changes nothing."
	}
	if in.RequestedTarget != "" {
		s.Targets = []string{in.RequestedTarget}
	}
	return s
}

func promptReadToolKind(tool string) (string, bool) {
	switch tool {
	case "read":
		return "file read", true
	case "grep", "glob":
		return "file search", true
	case "list", "tree":
		return "directory listing", true
	case "file_count":
		return "file count", true
	default:
		return "", false
	}
}

func shellPromptSummary(req MatchRequest, in PromptSummaryInput) PromptSummaryResult {
	lines, chars := promptShape(in.Command)
	s := PromptSummaryResult{Kind: promptKindShell, Lines: lines, Chars: chars}
	targets, ok := shellWriteTargets(in.Command, req.Kind == subjectKindLiteral)
	if !ok {
		return promptUnknownEffect(s)
	}
	if len(targets) == 0 {
		s.Effect = promptEffectRun
		s.Sentence = "Runs a shell command with no requested write target."
		return s
	}
	s.Effect = promptEffectRun + ", " + promptEffectWrite
	s.Sentence = "Runs a shell command that writes the requested targets."
	s.Targets = targets
	return s
}

func batchPromptSummary(stages []string) PromptSummaryResult {
	lines, chars := promptShape(strings.Join(stages, "\n"))
	s := PromptSummaryResult{Kind: promptKindPipeline, StageCount: len(stages), Lines: lines, Chars: chars}
	var targets []string
	for _, stage := range stages {
		stageTargets, ok := shellWriteTargets(stage, false)
		if !ok {
			return promptUnknownEffect(s)
		}
		targets = append(targets, stageTargets...)
	}
	if len(targets) == 0 {
		s.Effect = promptEffectRun
		s.Sentence = fmt.Sprintf("One choice authorizes all %d pipeline stages; together they run commands with no requested write target.", len(stages))
		return s
	}
	s.Effect = promptEffectRun + ", " + promptEffectWrite
	s.Sentence = fmt.Sprintf("One choice authorizes all %d pipeline stages; together they run commands that write the requested targets.", len(stages))
	s.Targets = targets
	return s
}

// promptShellWord is either a shell word or a bare `>`/`>>` redirection operator.
type promptShellWord struct {
	raw      string
	value    string
	redirect string
	pos      int
}

// promptTarget is one requested target spelling. reported is what the prompt shows and
// span is the original word span the expansion check runs over, which differ for `dd`,
// whose target rides inside an `of=` assignment. pos is the target's word position in the
// raw command, which orders command operands and redirect targets as the user wrote them.
type promptTarget struct {
	reported string
	span     string
	pos      int
}

// shellWriteTargets reports the written targets of a displayed command, or false for any form
// outside the closed grammar below. Widening it means adding another named command form, never
// inferring an effect from code the grammar does not model.
func shellWriteTargets(command string, literalRoute bool) ([]string, bool) {
	words, ok := promptShellWords(command)
	if !ok || len(words) == 0 {
		return nil, false
	}
	programWords, redirects, ok := promptSplitRedirections(words)
	if !ok {
		return nil, false
	}

	var targets []promptTarget
	if len(programWords) > 0 {
		commandTargets, ok := promptCommandTargets(programWords)
		if !ok {
			return nil, false
		}
		targets = commandTargets
	} else if len(redirects) == 0 {
		return nil, false
	}
	for _, r := range redirects {
		// A /dev/null redirect discards what it is given, so it is not a written target.
		if r.value == promptDevNull {
			continue
		}
		targets = append(targets, promptTarget{reported: r.value, span: r.raw, pos: r.pos})
	}
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].pos < targets[j].pos })

	// A literal request is handed to `sh -c` verbatim, so every word of the accepted form —
	// not only the reported targets — must be proven expansion-free before any effect is named.
	if literalRoute {
		for _, w := range words {
			if w.redirect != "" {
				continue
			}
			if w.value == "" || !tokenExpansionFree(w.raw) {
				return nil, false
			}
		}
	}

	reported := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.reported == "" || !tokenExpansionFree(t.span) {
			return nil, false
		}
		reported = append(reported, t.reported)
	}
	return reported, true
}

// promptShellWords splits a displayed command into words and bare `>`/`>>` operators using the
// same quote-aware mask the matcher parses with, and refuses every construct outside one stage.
func promptShellWords(command string) ([]promptShellWord, bool) {
	mask, err := bareMask(command)
	if err != nil {
		return nil, false
	}
	for i := 0; i < len(command); i++ {
		if !mask[i] {
			continue
		}
		switch command[i] {
		case '|', '&', ';', '<', '`', '\n', '\r':
			return nil, false
		case '$':
			if i+1 < len(command) && mask[i+1] && command[i+1] == '(' {
				return nil, false
			}
		}
	}

	var words []promptShellWord
	start := -1
	flush := func(end int) {
		if start >= 0 {
			words = append(words, promptShellWord{raw: command[start:end]})
			start = -1
		}
	}
	for i := 0; i < len(command); {
		switch {
		case mask[i] && isShellSpace(command[i]):
			flush(i)
			i++
		case mask[i] && command[i] == '>':
			op := ">"
			end := i + 1
			if end < len(command) && mask[end] && command[end] == '>' {
				op = ">>"
				end++
			}
			// A bare `1` or `2` touching the operator is a file descriptor. Any other
			// all-digit span touching it is a descriptor the shell honours but this grammar
			// does not model, so the whole form is unrecognized rather than reported as an
			// operand plus a redirect.
			switch {
			case start >= 0 && command[start:i] == "1", start >= 0 && command[start:i] == "2":
				start = -1
			case start >= 0 && promptAllDigits(command[start:i]):
				return nil, false
			default:
				flush(i)
			}
			words = append(words, promptShellWord{redirect: op})
			i = end
		default:
			if start < 0 {
				start = i
			}
			i++
		}
	}
	flush(len(command))

	for i := range words {
		words[i].pos = i
		if words[i].redirect != "" {
			continue
		}
		tokens, err := tokenizeShell(words[i].raw)
		if err != nil || len(tokens) != 1 {
			return nil, false
		}
		words[i].value = tokens[0].Value
	}
	return words, true
}

func promptAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func promptSplitRedirections(words []promptShellWord) (command, redirects []promptShellWord, ok bool) {
	pendingCommandWord := false
	for i := 0; i < len(words); i++ {
		if words[i].redirect == "" {
			command = append(command, words[i])
			pendingCommandWord = true
			continue
		}
		// A whitespace-separated bare `1` or `2` before a redirect reads as a descriptor to
		// a human and as an operand to the shell; the grammar models neither, so the form is
		// unrecognized.
		if pendingCommandWord {
			if raw := command[len(command)-1].raw; raw == "1" || raw == "2" {
				return nil, nil, false
			}
		}
		if i+1 >= len(words) || words[i+1].redirect != "" {
			return nil, nil, false
		}
		redirects = append(redirects, words[i+1])
		i++
		pendingCommandWord = false
	}
	return command, redirects, true
}

func promptCommandTargets(words []promptShellWord) ([]promptTarget, bool) {
	switch words[0].value {
	case "tee":
		return promptTeeTargets(words[1:])
	case "cp", "mv", "install", "ln":
		return promptTwoOperandTarget(words[1:])
	case "mkdir", "rm", "touch":
		return promptOperandTargets(words[1:])
	case "truncate":
		return promptTruncateTargets(words[1:])
	case "dd":
		return promptDDTarget(words[1:])
	default:
		return nil, false
	}
}

func promptIsOptionWord(value string) bool { return strings.HasPrefix(value, "-") }

func promptTargetsOf(words []promptShellWord) []promptTarget {
	targets := make([]promptTarget, 0, len(words))
	for _, w := range words {
		targets = append(targets, promptTarget{reported: w.value, span: w.raw, pos: w.pos})
	}
	return targets
}

// promptOperands returns the operand words after an optional leading `--`. Without that
// separator any word starting with `-` is an option the closed grammar does not model.
func promptOperands(args []promptShellWord) ([]promptShellWord, bool) {
	if len(args) > 0 && args[0].value == "--" {
		return args[1:], true
	}
	for _, a := range args {
		if promptIsOptionWord(a.value) {
			return nil, false
		}
	}
	return args, true
}

func promptTeeTargets(args []promptShellWord) ([]promptTarget, bool) {
	i := 0
	afterSeparator := false
	for i < len(args) {
		value := args[i].value
		if value == "--" {
			afterSeparator = true
			i++
			break
		}
		if !promptIsOptionWord(value) {
			break
		}
		switch value {
		case "-a", "--append", "-i", "--ignore-interrupts":
			i++
		default:
			return nil, false
		}
	}
	operands := args[i:]
	if len(operands) == 0 {
		return nil, false
	}
	if !afterSeparator {
		for _, o := range operands {
			if promptIsOptionWord(o.value) {
				return nil, false
			}
		}
	}
	return promptTargetsOf(operands), true
}

func promptTwoOperandTarget(args []promptShellWord) ([]promptTarget, bool) {
	operands, ok := promptOperands(args)
	if !ok || len(operands) != 2 {
		return nil, false
	}
	return promptTargetsOf(operands[1:]), true
}

func promptOperandTargets(args []promptShellWord) ([]promptTarget, bool) {
	operands, ok := promptOperands(args)
	if !ok || len(operands) == 0 {
		return nil, false
	}
	return promptTargetsOf(operands), true
}

func promptTruncateTargets(args []promptShellWord) ([]promptTarget, bool) {
	if len(args) < 2 {
		return nil, false
	}
	if args[0].value != "-s" && args[0].value != "--size" {
		return nil, false
	}
	if args[1].value == "" {
		return nil, false
	}
	return promptOperandTargets(args[2:])
}

func promptDDTarget(args []promptShellWord) ([]promptTarget, bool) {
	if len(args) == 0 {
		return nil, false
	}
	var target *promptTarget
	for _, a := range args {
		key, value, found := strings.Cut(a.value, "=")
		if !found || value == "" {
			return nil, false
		}
		switch key {
		case "if", "bs", "count", "skip", "seek", "status", "conv":
		case "of":
			if target != nil {
				return nil, false
			}
			target = &promptTarget{reported: value, span: a.raw, pos: a.pos}
		default:
			return nil, false
		}
	}
	if target == nil {
		return nil, false
	}
	return []promptTarget{*target}, true
}
