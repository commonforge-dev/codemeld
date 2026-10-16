// Simple-compound recognition, the versioned generalized literal-subject form, and generalized
// matching for the permission system.
package permissions

import "strings"

// compoundSubjectPrefix is the sentinel + version that marks a literal grant subject as the
// generalized compound form rather than a byte-exact literal command. It is the first whitespace
// token of every encoded compound subject. CanonicalLiteralForm never emits this exact token
// sequence for an ordinary command unless a user deliberately runs a program literally named
// "compound/v1" followed by a "W"/"B" word and a valid stage grammar — and even then the grant
// would have to be hand-authored into the settings file, because the recognizer only ever decodes
// stored grant subjects, never the agent's request command (which is decomposed structurally via
// RecognizeSimpleCompound). A stored subject carrying the prefix that does not fully decode is
// rejected at load (entry.go) and never matches (fail closed), so a near-collision degrades to
// friction, never to a silent widening.
const compoundSubjectPrefix = "compound/v1"

// SimpleCompound is the ordered decomposition of a recognized simple compound command: its inner
// direct-command stages with their pinned operator structure. Wrapped reports the single accepted
// wrapper flavour, `sh -c '<compound>'`, as opposed to a bare simple compound; the two never
// cross-match. Stages holds each stage's canonical direct-command token sequence (program name
// followed by its arguments), and Operators holds the len(Stages)-1 operators between them, each
// `&&`, `;`, `||`, or `|`. It is the shape the per-stage scope chooser reads to build options, and
// the shape the generalized matcher compares a request against.
type SimpleCompound struct {
	Wrapped   bool
	Stages    [][]string
	Operators []string
}

// decodedCompound is the parsed form of a stored generalized compound subject: the same pinned
// structure as SimpleCompound but with each stage held as its stored direct-subject string (the
// Exact / Subcommand / Program scope form, e.g. `go build :*`) rather than request tokens, because
// a grant stage matches a request stage through MatchesDirectSubject.
type decodedCompound struct {
	wrapped       bool
	stageSubjects []string
	operators     []string
}

// isCompoundSubject reports whether a stored literal subject is the generalized compound form. The
// discriminator is the sentinel prefix as a whole first token; full structural validity is decided
// by decodeCompoundSubject, which fails closed.
func isCompoundSubject(subject string) bool {
	return subject == compoundSubjectPrefix || strings.HasPrefix(subject, compoundSubjectPrefix+" ")
}

// RecognizeSimpleCompound decomposes a canonical literal command into its ordered direct-command
// stages, or reports notSimple=false when the command is anything but a simple compound. The
// accepted shapes are the single wrapper form `sh -c '<stage> [&& <stage>]…'` and bare simple
// compounds/pipelines whose every stage is otherwise a direct command. Every other
// construct — a subshell, process substitution, backgrounding, a redirection, `$(...)`, a backtick,
// a nested wrapper, an env-assignment-bearing stage, an `sh -c` form with extra positional
// arguments, or any unparseable stage — returns false so the caller keeps today's byte-exact literal
// behaviour. It is conservative by construction: when in doubt it returns false, because a false
// "not simple" is only friction while a false "simple" would widen a grant.
//
// canonical must already be the CanonicalLiteralForm output. The matcher decomposes the request
// command with this function and compares it against a decoded grant; the prompt uses it to drive the
// per-stage scope chooser.
func RecognizeSimpleCompound(canonical string) (SimpleCompound, bool) {
	wrapped, norms, operators, ok := SimpleCompoundStages(canonical)
	if !ok {
		return SimpleCompound{}, false
	}
	stages := make([][]string, len(norms))
	for i, n := range norms {
		stages[i] = n.Tokens
	}
	return SimpleCompound{Wrapped: wrapped, Stages: stages, Operators: operators}, true
}

// RecognizeSimpleCompoundForGrant decides grant identity only: it ignores bare `/dev/null` redirects,
// so a caller deciding which executor runs the command must keep using SimpleCompoundStages, which
// still refuses every redirect.
func RecognizeSimpleCompoundForGrant(canonical string) (SimpleCompound, bool) {
	stripped, removed, ok := stripNullRedirectsForGrant(canonical)
	if !ok {
		return SimpleCompound{}, false
	}
	if !removed {
		return RecognizeSimpleCompound(canonical)
	}
	wrapped, norms, operators, ok := SimpleCompoundStages(stripped)
	if !ok {
		return SimpleCompound{}, false
	}
	// The stripped text is not what runs: `sh -c` re-parses the original, so a token that can expand
	// would authorize stages the chooser never saw.
	if !stagesExpansionFree(norms) {
		return SimpleCompound{}, false
	}
	stages := make([][]string, len(norms))
	for i, n := range norms {
		stages[i] = n.Tokens
	}
	return SimpleCompound{Wrapped: wrapped, Stages: stages, Operators: operators}, true
}

// An ineligible redirect is left in place rather than rejected here, so the caller's decomposition
// refuses the command exactly as it does today.
func stripNullRedirectsForGrant(canonical string) (stripped string, removed bool, ok bool) {
	wrapped := false
	body := canonical
	// Masking the outer wrapper marks the whole compound quoted, hiding every redirect from bareMask,
	// so the accepted `sh -c '<compound>'` shape must be unwrapped before the mask is built.
	if toks, err := tokenizeShell(canonical); err == nil && len(toks) == 3 &&
		toks[0].Value == "sh" && !toks[0].Quoted && toks[1].Value == "-c" {
		wrapped = true
		body = toks[2].Value
	}

	mask, err := bareMask(body)
	if err != nil {
		return "", false, false
	}
	stages, operators := splitCompound(body, mask)

	var b strings.Builder
	offset := 0
	for i, stage := range stages {
		feedsPipe := i < len(operators) && operators[i] == "|"
		text, hit := stripStageNullRedirects(stage, mask[offset:offset+len(stage)], feedsPipe)
		removed = removed || hit
		b.WriteString(text)
		offset += len(stage)
		if i < len(operators) {
			b.WriteString(operators[i])
			offset += len(operators[i])
		}
	}
	if !removed {
		return canonical, false, true
	}
	if wrapped {
		return "sh -c " + ShellQuote(b.String()), true, true
	}
	return b.String(), true, true
}

func stripStageNullRedirects(stage string, mask []bool, feedsPipe bool) (string, bool) {
	var b strings.Builder
	kept := 0
	removed := false
	for i := 0; i < len(stage); i++ {
		if !mask[i] || stage[i] != '>' {
			continue
		}
		start, end, spanOK := nullRedirectSpan(stage, mask, i)
		// nullRedirectSpan also accepts the duplications `2>&1` and `1>&2`; they change the bytes a
		// downstream stage receives, so grant identity keeps them.
		if !spanOK || start < kept || !strings.HasSuffix(stage[start:end], devNullTarget) {
			continue
		}
		// Discarding stdout changes what a piped stage reads, so only stderr is neutral there.
		if feedsPipe && nullRedirectDescriptor(stage, mask, i) != "2" {
			continue
		}
		b.WriteString(stage[kept:start])
		kept = end
		i = end - 1
		removed = true
	}
	if !removed {
		return stage, false
	}
	b.WriteString(stage[kept:])
	return b.String(), true
}

// nullRedirectSpan has already proved that the digits before i are a standalone descriptor, so this
// repeat of its backward scan needs no boundary check of its own.
func nullRedirectDescriptor(s string, mask []bool, i int) string {
	start := i
	for start > 0 && mask[start-1] && s[start-1] >= '0' && s[start-1] <= '9' {
		start--
	}
	return s[start:i]
}

// SimpleCompoundStages accepts canonical input for matching and source input for prompt display.
func SimpleCompoundStages(command string) (wrapped bool, stages []StageNormalization, operators []string, ok bool) {
	body := command

	// The single accepted wrapper flavour is exactly `sh -c '<compound>'`: three tokens, the bare
	// program sh, the -c flag, and one compound-string argument. Any extra positional argument, a
	// path-form sh (`/bin/sh`), or a different wrapper keeps the whole command byte-exact.
	if toks, err := tokenizeShell(command); err == nil && len(toks) == 3 &&
		toks[0].Value == "sh" && !toks[0].Quoted && toks[1].Value == "-c" {
		wrapped = true
		body = toks[2].Value
	}

	mask, err := bareMask(body)
	if err != nil {
		return false, nil, nil, false
	}
	if compoundBodyHasDisallowed(body, mask) {
		return false, nil, nil, false
	}
	rawStages, operators := splitCompound(body, mask)

	// A bare command with no compound operator is a single direct command, not a compound, and is
	// authorized stage-by-stage on the direct route — never generalized here. Only the wrapper form
	// may carry a single stage (`sh -c 'ls'`).
	if !wrapped && len(operators) == 0 {
		return false, nil, nil, false
	}

	stages = make([]StageNormalization, 0, len(rawStages))
	for _, raw := range rawStages {
		norm, err := NormalizeDirectStage(raw, StageInCompound)
		// A stage must normalize to a clean direct command. A wrapper/subshell/process-substitution
		// /backgrounding stage (RouteLiteral), an unparseable or empty stage (err), or a stage that
		// carries leading KEY=VALUE environment assignments or clears the environment is ineligible —
		// any of them forces the whole compound back to byte-exact.
		if err != nil || norm.Route != RouteDirect || len(norm.Assignments) > 0 || norm.ClearEnvironment {
			return false, nil, nil, false
		}
		stages = append(stages, norm)
	}
	return wrapped, stages, operators, true
}

// EncodeCompoundSubject assembles the deterministic, versioned generalized stored subject from a
// wrapper flag, the per-stage scope subjects the chooser produced (each an Exact / Subcommand /
// Program direct-subject string such as `gofmt -w a.go` or `go build :*`), and the operators between
// them. Every stage subject is re-rendered to one canonical spelling so equal generalizations encode
// byte-identically (and therefore hash and dedup identically). It fails closed — returning an error
// and no subject — on a malformed shape, an operator that is not simple-compound syntax, a stage that does not
// parse to a program, or a stage whose program IsDestructiveProgram flags: a destructive program is
// ineligible for widening, so the whole compound must stay byte-exact and no
// generalized grant is produced for it.
func EncodeCompoundSubject(wrapped bool, stageSubjects, operators []string) (string, error) {
	if len(stageSubjects) == 0 {
		return "", errCompound("no stages")
	}
	if len(operators) != len(stageSubjects)-1 {
		return "", errCompound("operator count does not match stage count")
	}

	var b strings.Builder
	b.WriteString(compoundSubjectPrefix)
	b.WriteByte(' ')
	if wrapped {
		b.WriteByte('W')
	} else {
		b.WriteByte('B')
		if len(stageSubjects) < 2 {
			return "", errCompound("a bare compound needs at least two stages")
		}
	}
	for i, ss := range stageSubjects {
		canon, ok := canonicalStageSubject(ss)
		if !ok {
			return "", errCompound("stage is not a valid direct subject")
		}
		if i > 0 {
			op := operators[i-1]
			if !isSimpleCompoundOperator(op) {
				return "", errCompound("operator must be &&, ;, ||, or |")
			}
			b.WriteByte(' ')
			b.WriteString(op)
		}
		b.WriteByte(' ')
		b.WriteString(canon)
	}

	encoded := b.String()
	// Self-check: the encoded subject must decode back to a well-formed compound (this also re-runs
	// the destructive gate and the operator/program checks), so a subject that would not round-trip
	// is never stored.
	if _, err := decodeCompoundSubject(encoded); err != nil {
		return "", err
	}
	return encoded, nil
}

// decodeCompoundSubject parses a stored generalized compound subject back into its pinned structure,
// failing closed on any malformation. It is the single decoder every caller (the matcher and the
// entry-load validator) shares, so a malformed generalized subject can never parse one way at load
// and another at match. It rejects a missing/garbled sentinel, a missing wrapper flag, a bare
// compound with fewer than two stages, an empty or unparseable stage, a disallowed construct, and —
// enforcing the destructive-program widening ban a second time at the load/match boundary — any
// stage whose program IsDestructiveProgram flags.
func decodeCompoundSubject(encoded string) (decodedCompound, error) {
	rest, ok := strings.CutPrefix(encoded, compoundSubjectPrefix+" ")
	if !ok {
		return decodedCompound{}, errCompound("missing compound subject prefix")
	}

	var wrapped bool
	switch {
	case strings.HasPrefix(rest, "W "):
		wrapped = true
	case strings.HasPrefix(rest, "B "):
		wrapped = false
	default:
		return decodedCompound{}, errCompound("missing or invalid wrapper flag")
	}
	rest = rest[2:]

	mask, err := bareMask(rest)
	if err != nil {
		return decodedCompound{}, err
	}
	if compoundBodyHasDisallowed(rest, mask) {
		return decodedCompound{}, errCompound("disallowed construct in compound body")
	}
	rawStages, operators := splitCompound(rest, mask)
	if !wrapped && len(operators) == 0 {
		return decodedCompound{}, errCompound("a bare compound needs at least two stages")
	}

	stageSubjects := make([]string, 0, len(rawStages))
	for _, raw := range rawStages {
		ss := strings.TrimSpace(raw)
		// A stored stage subject must already be in its one canonical spelling — the same form the
		// encoder emits — so a hand-authored non-canonical or ambiguous stage is rejected rather than
		// silently re-spelled. This is also the load/match check that keeps the decoder and encoder
		// agreeing on the stored form.
		canon, ok := canonicalStageSubject(ss)
		if !ok || canon != ss {
			return decodedCompound{}, errCompound("stage is not a canonical direct subject")
		}
		prog, ok := compoundStageProgram(ss)
		if !ok {
			return decodedCompound{}, errCompound("stage is not a valid direct subject")
		}
		if IsDestructiveProgram(prog) {
			return decodedCompound{}, errCompound("destructive program is ineligible for widening")
		}
		stageSubjects = append(stageSubjects, ss)
	}
	return decodedCompound{wrapped: wrapped, stageSubjects: stageSubjects, operators: operators}, nil
}

// matchesCompoundSubject reports whether a request command matches a stored generalized compound
// grant. It decodes the grant (fail closed: a grant that does not decode never matches), decomposes
// the request, and authorizes only when the two share the same wrapper flavour, the same operator
// structure and stage count, and every request stage satisfies the stored
// stage's scope rule through the existing direct-subject matcher. No request stage is ever matched
// against a different program or a different operator position: the comparison is positional, so a
// program swap, an operator change or injection, an added/removed stage, or a reordered stage all
// fail to match and re-prompt.
func matchesCompoundSubject(requestCanonical, grantSubject string) bool {
	grant, err := decodeCompoundSubject(grantSubject)
	if err != nil {
		return false
	}
	req, ok := RecognizeSimpleCompoundForGrant(requestCanonical)
	if !ok {
		return false
	}
	if req.Wrapped != grant.wrapped {
		return false
	}
	if len(req.Stages) != len(grant.stageSubjects) {
		return false
	}
	if len(req.Operators) != len(grant.operators) {
		return false
	}
	for i := range req.Operators {
		if req.Operators[i] != grant.operators[i] {
			return false
		}
	}
	for i := range req.Stages {
		// RecognizeSimpleCompound refuses an assignment-bearing or environment-clearing
		// stage, so a compound request never carries either to match.
		if !MatchesDirectSubject(req.Stages[i], nil, false, grant.stageSubjects[i]) {
			return false
		}
	}
	return true
}

// compoundStageProgram returns the canonical program token (the first word) of a stored stage
// subject, or ok=false when the subject is empty or does not tokenize. A bare `:*` is not a valid
// stage subject (it has no program), so it is rejected here too.
func compoundStageProgram(stageSubject string) (string, bool) {
	toks, err := tokenizeShell(stageSubject)
	if err != nil || len(toks) == 0 {
		return "", false
	}
	if isBareWildcardToken(toks[0]) {
		return "", false
	}
	return toks[0].Value, true
}

// canonicalStageSubject re-renders a stored stage subject to its single canonical spelling: each
// pinned token is re-emitted with the shared shell-quoting rule and an explicit trailing `:*`
// wildcard (Subcommand / Program scope) is preserved as one bare token. It returns ok=false for an
// empty, unparseable, or program-less subject (including a bare `:*`). A literal `:*` argument that
// was quoted or escaped in the source stays a quoted token, so it is never confused with the
// wildcard suffix.
func canonicalStageSubject(stageSubject string) (string, bool) {
	toks, err := tokenizeShell(stageSubject)
	if err != nil || len(toks) == 0 {
		return "", false
	}
	wildcard := false
	if isBareWildcardToken(toks[len(toks)-1]) {
		wildcard = true
		toks = toks[:len(toks)-1]
		if len(toks) == 0 {
			// A bare ":*" has no program to pin.
			return "", false
		}
	}
	parts := make([]string, len(toks))
	for i, t := range toks {
		parts[i] = ShellQuote(t.Value)
	}
	out := strings.Join(parts, " ")
	if wildcard {
		out += " :*"
	}
	return out, true
}

// compoundBodyHasDisallowed reports whether the compound body holds any bare construct other than the
// operators a simple compound may carry: `&&`, `;`, `||`, and a single `|`. A `$(`, backtick,
// newline/carriage-return, redirection (`<`/`>`), or single backgrounding `&` forces the command back
// to byte-exact. Quoted or escaped bytes are skipped via the mask, so an operator inside quotes is
// literal text, never structure; a `$(` or backtick inside double quotes still disallows, because the
// shell performs it.
func compoundBodyHasDisallowed(s string, mask []bool) bool {
	if hasDoubleQuotedSubstitution(s) {
		return true
	}
	for i := 0; i < len(s); i++ {
		if !mask[i] {
			continue
		}
		switch s[i] {
		case '\n', '\r', '`', '<', '>':
			return true
		case '|':
			if i+1 < len(s) && mask[i+1] && s[i+1] == '|' {
				i++ // || is allowed; consume the second | so it is not seen as a pipe
				continue
			}
			// a single | is an allowed pipeline boundary
		case '&':
			if i+1 < len(s) && mask[i+1] && s[i+1] == '&' {
				i++ // && is allowed; consume the second & so a following byte is judged on its own
				continue
			}
			return true // a single & is backgrounding
		case '$':
			if i+1 < len(s) && mask[i+1] && s[i+1] == '(' {
				return true // $(
			}
		}
	}
	return false
}

// splitCompound splits a compound body on every bare simple-compound operator, returning the raw stage
// substrings and the len(stages)-1 operators between them in order. It assumes compoundBodyHasDisallowed
// already passed, so a bare `|` is always a single pipe and `||` is always logical OR. Stages are
// returned untrimmed; the caller normalizes each.
func splitCompound(s string, mask []bool) (stages []string, operators []string) {
	start := 0
	for i := 0; i < len(s); i++ {
		if !mask[i] {
			continue
		}
		switch {
		case s[i] == '&' && i+1 < len(s) && mask[i+1] && s[i+1] == '&':
			stages = append(stages, s[start:i])
			operators = append(operators, "&&")
			i++
			start = i + 1
		case s[i] == '|':
			stages = append(stages, s[start:i])
			if i+1 < len(s) && mask[i+1] && s[i+1] == '|' {
				operators = append(operators, "||")
				i++
				start = i + 1
				continue
			}
			operators = append(operators, "|")
			start = i + 1
		case s[i] == ';':
			stages = append(stages, s[start:i])
			operators = append(operators, ";")
			start = i + 1
		}
	}
	stages = append(stages, s[start:])
	return stages, operators
}

func isSimpleCompoundOperator(op string) bool {
	switch op {
	case "&&", ";", "||", "|":
		return true
	default:
		return false
	}
}

// errCompound builds a package-local compound-subject error with a stable prefix.
func errCompound(detail string) error {
	return &compoundError{detail: detail}
}

type compoundError struct{ detail string }

func (e *compoundError) Error() string { return "compound subject: " + e.detail }
