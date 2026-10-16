// Package tui provides the terminal user interface.
package tui

import (
	"codemeld.dev/codemeld/internal/permissions"
)

type ScopeKind int

const (
	ScopeExact ScopeKind = iota
	ScopeSubcommand
	ScopeProgram
	ScopePrefix
	ScopePath
)

// scopeRecommendedSuffix marks the recommended/default scope option in the
// chooser list. The cursor also opens on it, but the label keeps the
// recommendation visible after the user navigates away.
const scopeRecommendedSuffix = " [recommended]"

// scopeProgramWarning is the advisory shown for the Program scope: a
// program grant authorizes any invocation of the program with any arguments
// within the chosen path scope, which is why it is marked advanced and gated
// behind an explicit inline confirm.
const scopeProgramWarning = "⚠ Program scope authorizes ANY invocation of this program with ANY arguments within the chosen path scope."

// scopeDestructiveProgramWarning is the stronger advisory shown above the standard
// breadth warning when the program being granted program-wide is classified
// destructive. A `<program> :*` grant authorizes every subcommand of the
// program, so for a destructive program it also authorizes the ones that delete data
// or rewrite history. It is advisory only: it never blocks the grant or changes the
// stored subject — it only sharpens the caution.
const scopeDestructiveProgramWarning = "⚠ DESTRUCTIVE program: this grant authorizes EVERY subcommand, including ones that permanently delete data or rewrite history."

const scopePrefixNotice = "A prefix choice stores every token shown before :* verbatim; only the tokens after it may vary. Changing a fixed token re-prompts."

const scopePathNotice = "The path choice stores a directory boundary. Use ← and → to widen or narrow it; / and your home directory are never offered. When the command runs, its path argument is resolved and checked against that boundary at the moment permission is decided — the boundary is not an execution-time sandbox and does not confine what the program opens afterwards."

func scopeChooserHelp(opts []scopeOption) string {
	help := "Choose the subject scope this grant stores:"
	for _, so := range opts {
		if so.Kind == ScopePrefix {
			help += "\n\n" + scopePrefixNotice
			break
		}
	}
	for _, so := range opts {
		if so.Kind == ScopePath {
			help += "\n\n" + scopePathNotice
			break
		}
	}
	return help + "\n\n" + scopeProgramWarning
}

// programConfirmWarning returns the advisory text for the Program-scope confirm step.
// It is always the standard breadth warning; for a destructive program the stronger
// destructive advisory is prepended. The destructive line never replaces the breadth
// warning — both are shown — so a destructive confirm carries strictly more caution.
func programConfirmWarning(destructive bool) string {
	if destructive {
		return scopeDestructiveProgramWarning + "\n\n" + scopeProgramWarning
	}
	return scopeProgramWarning
}

// scopeOption is one selectable subject-scope row in the chooser: its
// kind, the label shown in the list (the stored subject string plus a plain-words
// breadth phrase, so the user sees exactly what each choice authorizes and how wide
// it reaches), and the stored subject string the grant carries if chosen. The
// breadth phrase is display-only; it never changes Subject.
type scopeOption struct {
	Kind    ScopeKind
	Label   string
	Subject string
}

func exactScopeRow(program string, args []string) scopeOption {
	exact := permissions.ExactSubject(program, args)
	return scopeOption{
		Kind:    ScopeExact,
		Label:   "exact: " + exact + " — only this exact command",
		Subject: exact,
	}
}

func programScopeRow(program string) scopeOption {
	prog := permissions.ProgramSubject(program)
	return scopeOption{
		Kind:    ScopeProgram,
		Label:   "program (advanced): " + prog + " — ANY invocation of " + program + " (widest)",
		Subject: prog,
	}
}

func scopeOptionRows(program string, args []string) []scopeOption {
	rows := []scopeOption{exactScopeRow(program, args)}

	if offered, anchor := permissions.ClassifyDirectTokens(args); offered {
		prefix := args[:anchor+1]
		sub := permissions.PrefixSubject(program, prefix)
		rows = append(rows, scopeOption{
			Kind:    ScopeSubcommand,
			Label:   "subcommand: " + sub + " — any command starting with " + permissions.ExactSubject(program, prefix),
			Subject: sub,
		})
	}

	return append(rows, programScopeRow(program))
}

func scopeRow(program string, c permissions.DirectScopeChoice) scopeOption {
	switch c.Kind {
	case permissions.DirectScopePrefix:
		return scopeOption{
			Kind:    ScopePrefix,
			Label:   "prefix: " + c.Subject + " — fixed: " + permissions.ExactSubject(program, c.Pinned) + "; any later arguments may vary",
			Subject: c.Subject,
		}
	case permissions.DirectScopeProgram:
		return programScopeRow(program)
	case permissions.DirectScopePath:
		return pathScopeRow(program, c)
	default:
		return exactScopeRow(program, c.Pinned)
	}
}

// c.Subject is the opaque stored envelope and must never reach the screen.
func pathScopeRow(program string, c permissions.DirectScopeChoice) scopeOption {
	label := "path: " + c.Readable + " — " + permissions.ExactSubject(program, c.Pinned) +
		" against any path resolving under " + c.Boundaries[c.Boundary] + ", checked when permission is decided"
	if c.TailWildcard {
		label += "; any later arguments may vary"
	}
	if len(c.Boundaries) > 1 {
		label += " (← → adjust)"
	}
	return scopeOption{Kind: ScopePath, Label: label, Subject: c.Subject}
}

type scopeChooser struct {
	options    []scopeOption
	defaultIdx int
	model      permissions.DirectScopeModel
	pathRow    int
	boundary   int
}

func buildScopeChooserRows(program string, args []string, home string) (scopeChooser, bool) {
	model, ok := permissions.NewDirectScopeModel(append([]string{program}, args...), home)
	if !ok {
		return scopeChooser{pathRow: -1}, false
	}
	opts := make([]scopeOption, 0, len(model.Choices))
	for _, c := range model.Choices {
		opts = append(opts, scopeRow(model.Program, c))
	}
	opts[model.Recommended].Label += scopeRecommendedSuffix
	return scopeChooser{options: opts, defaultIdx: model.Recommended, model: model, pathRow: model.PathRow()}, true
}

func (sc *scopeChooser) adjust(step int) (string, bool) {
	if sc.pathRow < 0 {
		return "", false
	}
	choice, ok := sc.model.PathChoiceAt(sc.boundary + step)
	if !ok {
		return "", false
	}
	sc.boundary += step
	row := pathScopeRow(sc.model.Program, choice)
	if sc.pathRow == sc.defaultIdx {
		row.Label += scopeRecommendedSuffix
	}
	sc.options[sc.pathRow] = row
	return row.Label, true
}

// compoundStageScope holds the per-stage subject-scope choices for one stage of a
// recognized simple compound (e.g. `go build && npm test`). It is TUI-local
// display/selection data only: the chosen row per stage becomes a stored subject
// via the backend encoder, so this shape never assembles or persists a
// generalized subject. Command is the stage's canonical command text for display;
// Options are the selectable rows (reusing scopeOption so Label stays display-only
// and Subject stays the canonical stored-subject string); DefaultIdx is the row a
// stage opens on; NoWiden records that the stage program is destructive.
type compoundStageScope struct {
	Command    string
	Options    []scopeOption
	DefaultIdx int
	NoWiden    bool
}

// buildCompoundStageScopeOptions builds the per-stage scope choices for a
// recognized simple compound. Each stage's first token is its canonical program
// and the rest are argument tokens; rows are derived through the shared
// scopeOptionRows path so no second subject-encoding exists. Every stage defaults
// to the narrowest (Exact) scope rather than Subcommand, because widening any one
// stage of a compound is the riskier choice. A destructive stage (its program
// classified by permissions.IsDestructiveProgram) is exact-only with NoWiden set:
// its Subcommand and Program rows are suppressed, because the backend refuses a
// generalized compound subject containing a destructive program, so the chooser must
// never offer to widen it. A nil/empty (non-simple) Stages list yields no stage
// options, leaving the caller on the byte-exact literal path.
func buildCompoundStageScopeOptions(sc permissions.SimpleCompound) []compoundStageScope {
	if len(sc.Stages) == 0 {
		return nil
	}

	stages := make([]compoundStageScope, 0, len(sc.Stages))
	for _, stage := range sc.Stages {
		if len(stage) == 0 {
			// A recognized simple compound never has an empty stage; treat a
			// malformed one as non-simple and offer no stage options.
			return nil
		}
		program := stage[0]
		args := stage[1:]

		cs := compoundStageScope{
			Command:    permissions.ExactSubject(program, args),
			Options:    scopeOptionRows(program, args),
			DefaultIdx: 0, // every compound stage opens on the narrowest (Exact) scope
		}
		if permissions.IsDestructiveProgram(program) {
			// Keep only the Exact row; the Subcommand/Program widening rows must
			// not be offered for a destructive stage.
			cs.Options = cs.Options[:1]
			cs.NoWiden = true
		}
		cs.Options[cs.DefaultIdx].Label += scopeRecommendedSuffix
		stages = append(stages, cs)
	}
	return stages
}
