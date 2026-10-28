// Package tui provides terminal user-interface components.
package tui

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"codemeld.dev/codemeld/internal/permissions"
)

// actionEditFile must stay equal to dispatch.ActionEditFile; internal/tui cannot import dispatch.
const actionEditFile = "Edit file"

// promptInfoScrollStep is the number of rows the info block scrolls per
// PgUp/PgDn while the option list holds focus, so an overflowing canonical
// literal command can be read without losing the option-list flow.
const promptInfoScrollStep = 5

const (
	promptBasePage         = "prompt"
	promptScopePage        = "prompt-scope"
	promptScopeConfirmPage = "prompt-scope-confirm"
	// promptCompoundPage is the per-stage subject-scope chooser for a recognized
	// simple compound. One stage is shown at a time on this single page (the page is
	// torn down and re-added as the flow advances); a stage's Program choice layers
	// the shared promptScopeConfirmPage above it.
	promptCompoundPage = "prompt-compound"
)

// SubjectKind is the matching subject's classification shown on the prompt and
// branched on for the direct-command sub-choice. The string
// values are the human labels the prompt displays.
type SubjectKind string

const (
	// SubjectDirectCommand is a normalized exec-style command eligible for the
	// subject-scope sub-choice.
	SubjectDirectCommand SubjectKind = "direct-command"
	// SubjectLiteralCommand is a literal command subject matched byte-for-byte
	// against its canonical form; no scope sub-choice is offered.
	SubjectLiteralCommand SubjectKind = "literal-command"
	// SubjectStructuredTool is a structured tool call eligible for grants; no
	// scope sub-choice is offered.
	SubjectStructuredTool SubjectKind = "structured-tool"
	SubjectHost           SubjectKind = "host"
)

// PromptOption identifies one grant option. The iota order is the fixed
// top-to-bottom order of promptOptionsInOrder, so the cursor's initial position and
// the rendered list order both derive from it; OptionAllowProject is host-only and
// is listed in hostOptionsInOrder instead.
type PromptOption int

const (
	// OptionAllowOnce authorizes the single in-flight invocation and creates no
	// grant; it is the default-highlighted option (option 1).
	OptionAllowOnce PromptOption = iota
	// OptionDeny refuses the call (option 2). It is a single action:
	// selecting it finalizes the deny immediately with the default-reason envelope,
	// with no second overlay to collect an optional reason.
	OptionDeny
	// OptionAllowSession creates a session grant (option 3).
	OptionAllowSession
	// OptionAllowFolder creates a folder grant (option 4).
	OptionAllowFolder
	// OptionAllowGlobal creates a global grant (option 5).
	OptionAllowGlobal
	OptionAllowProject
)

var promptOptionsInOrder = []promptOptionRow{
	{OptionAllowOnce, "allow this once"},
	{OptionDeny, "deny"},
	{OptionAllowSession, "allow for this session"},
	{OptionAllowFolder, "allow in this folder permanently"},
	{OptionAllowGlobal, "allow globally permanently"},
}

var hostOptionsInOrder = []promptOptionRow{
	{OptionAllowOnce, "allow this once"},
	{OptionDeny, "deny"},
	{OptionAllowSession, "allow for this session"},
	{OptionAllowProject, "allow in this project"},
}

var hostFreshOptionsInOrder = []promptOptionRow{
	{OptionAllowOnce, "allow this once"},
	{OptionDeny, "deny"},
}

var promptMnemonics = map[PromptOption]rune{
	OptionAllowOnce:    'o',
	OptionDeny:         'd',
	OptionAllowSession: 's',
	OptionAllowFolder:  'f',
	OptionAllowGlobal:  'g',
	OptionAllowProject: 'p',
}

type PromptRequest struct {
	// Action is the human-readable action header: "Create file" /
	// "Edit file" for the file tools, "Run command" for shell subjects, "Run tool"
	// for any other structured tool. The raw subject kind is not displayed; it
	// lives only in the event log.
	Action string
	// For shell subjects, Subject is effective source text, not the matching subject.
	Subject string
	// Body is the payload shown verbatim with no truncation and nothing added — no
	// injected line numbers, no reformatting. Empty for a shell subject, whose command
	// is the Subject.
	Body string
	// Kind is the subject classification used to decide whether the
	// direct-command sub-choice applies. It is no longer displayed.
	Kind SubjectKind
	// CanonicalProgram is the canonical program token of a direct-command subject.
	// The scope subjects derive from it (including the Program-scope `<program> :*`
	// subject confirmed via the inline confirm step). Empty for non-direct-command
	// subjects.
	CanonicalProgram string
	// CanonicalArgs are the canonical argument tokens that follow the program
	// token, already normalized by the matching backend. They drive the
	// flag/positional classification and the Exact/Subcommand subject strings.
	CanonicalArgs []string
	// Pipeline is the full pipeline source text (all stages joined by " | ")
	// shown as display-only context on a direct pipeline-stage prompt, so the user
	// sees the isolated stage in Subject is one stage of a larger pipeline rather
	// than an unexplained standalone request (a safe-looking `sort`/`wc -l`). Empty
	// for a single direct command, a literal whole-command route, and every
	// structured tool. Display-only: it never affects matching or the stored grant.
	Pipeline string
	// WholeCommand marks a literal-route prompt as a whole-command approval — the
	// Subject is the entire command run verbatim, not one stage of a direct pipeline —
	// so the prompt frames a literal approval distinctly from a per-stage direct one.
	// False for direct commands (single or pipeline stage) and every structured tool.
	WholeCommand bool
	// BatchedStages, when it holds two or more entries, makes this one command-level
	// approval for a direct pipeline whose remaining (non-read-only) stages each still need
	// a decision. It is the ordered list of those stages'
	// canonical commands, shown verbatim under the full Pipeline so the user sees exactly what
	// is being approved — never a merged/summarized command. One option choice then applies to
	// every stage and a deny denies the whole pipeline. Empty (or a single entry, which the
	// batched producer renders as an ordinary single-stage prompt) leaves the prompt exactly as
	// before. Display-only: it never participates in matching or a stored grant.
	BatchedStages []string
	// BatchedEscalations is the per-stage scope-escalation warning for a batched approval,
	// index-aligned with BatchedStages. A non-empty entry holds the narrower already-approved
	// scope that the same stage's request now broadens (an ancestor of that folder), so the
	// batched prompt shows the same broaden-warning a per-stage prompt would; batching
	// must not hide trust-scope information. An empty entry means that stage does not broaden any
	// approved scope. Empty/nil for a non-escalating batch. Display-only, like BatchedStages.
	BatchedEscalations []string
	BatchedNotes       []string
	// ApprovalIndex and ApprovalTotal are this prompt's 1-based position in a walk of separate
	// approval questions and the number of questions in that walk. The overlay shows the position
	// only when ApprovalTotal exceeds 1, and discloses nothing about the questions that follow.
	// Both are zero for a prompt that is not part of such a walk. Display-only.
	ApprovalIndex int
	ApprovalTotal int
	// RunFolder is the resolved path_scope the command will execute in
	// (the cd-shifted path when a `cd <path> && ` prefix is present, not the
	// process cwd).
	RunFolder string
	// ProjectRoot is the resolved project root. When it differs from
	// RunFolder the prompt shows both and marks them different.
	ProjectRoot string
	// FolderSettingsPath is the absolute path the folder grant would be written
	// to (<project_root>/.codemeld/settings.yaml), shown for the folder option.
	// Empty when the caller has no folder option to describe.
	FolderSettingsPath string
	// FolderCoverage is the one-line statement of what the folder grant covers
	// (the resolved path_scope and its descendants), shown for the folder option.
	FolderCoverage     string
	OutOfRootFileWrite bool
	OutOfRootReadScope bool
	// CapabilityStoredSubject is the capability subject a grant should store when this
	// structured-tool prompt is approved with a grant-creating option. Dispatch supplies
	// permissions.CapabilityWriteTree for a file-tool member and CapabilityRead for an
	// out-of-project read, so those are the two values production sends. When set, a
	// session/folder/global selection returns it as PromptDecision.StoredSubject so the
	// stored grant folds the capability's sibling member tools at the scope, and
	// renderPromptFacts states that coverage. Empty for shell,
	// literal, direct commands (which use the scope chooser instead), tools that map to no
	// capability, and in-project reads — leaving the stored subject the concrete request
	// subject. It does not affect matching, the cache, or which options are shown.
	CapabilityStoredSubject string
	// LaunchDir is the resolved absolute directory codemeld was launched in. With
	// Boundary and WouldCreateSettingsFile it gates the launch-dir-only cross-mode
	// marker notice via CrossModeMarkerNotice; the prompt renders
	// no caller-supplied notice string, so the gate is always enforced here.
	LaunchDir string
	// Boundary is the resolved discovery.boundary mode ("launch-dir-only" or
	// "project-root"). Only "launch-dir-only" can plant a new cross-mode marker, so
	// it gates the notice.
	Boundary string
	// WouldCreateSettingsFile reports whether persisting a folder grant would newly
	// create <project_root>/.codemeld/settings.yaml (it did not exist before). An
	// existing file is already a marker, so no new cross-mode surprise and no notice.
	WouldCreateSettingsFile bool
	// ScopeEscalationNarrower, when non-empty, marks that this request's path scope is
	// strictly broader than (an ancestor of) a folder the user already approved for the
	// same subject; it holds that narrower already-approved scope. renderPromptFacts
	// then shows a salience warning naming it, so the broadening is not silent.
	// It changes nothing about matching or persistence — display only. Empty for every
	// non-escalating prompt.
	ScopeEscalationNarrower string
	Note                    string
	// Compound, when non-nil, carries the recognized simple-compound decomposition
	// (its ordered direct-command stages and pinned operators) for a literal-command
	// subject the backend recognized as a simple compound. It gates the
	// per-stage subject-scope chooser: a grant-creating selection opens one chooser per
	// stage, each defaulting to the narrowest (Exact) scope, and the chosen per-stage
	// canonical subjects are encoded into the backend generalized compound subject via
	// permissions.EncodeCompoundSubject. Nil for every non-compound subject — including
	// ordinary literal commands, which keep the byte-exact no-chooser path. In production
	// promptgate populates it from permissions.RecognizeSimpleCompound for literal-command
	// requests the backend recognizes as a simple compound.
	Compound *permissions.SimpleCompound
	// Summary is the display-only approval summary the bootstrap seam computes: internal/tui
	// cannot import internal/dispatch, so the classification cannot happen here. Its rows take
	// priority over the remaining fixed facts when the terminal cannot show all of them.
	Summary permissions.PromptSummaryResult

	// ProjectUntrusted withholds every durable project grant for a run the trust gate
	// refused. Its false zero value means trusted, which is a default for direct construction
	// inside internal/tui only: a project with no settings file is trusted by vacuity, so
	// there is no shape here to infer the decision from. Every production bootstrap path must
	// set it explicitly from the run's fixed decision, which is where that decision exists.
	ProjectUntrusted bool

	HostTool           string
	HostRequest        string
	Host               string
	FreshConfirmation  bool
	DirectHTTPFallback bool

	ExceptionalAuthority string
}

func (r PromptRequest) isHost() bool { return r.Kind == SubjectHost }

// IsDirectCommand reports whether the subject is a direct command. The
// subject-scope sub-choice attaches to a grant-creating selection when this is
// true (literal-command and structured-tool subjects are fixed and offer no
// sub-choice).
func (r PromptRequest) IsDirectCommand() bool { return r.Kind == SubjectDirectCommand }

func (r PromptRequest) isShellSubject() bool {
	return r.Kind == SubjectDirectCommand || r.Kind == SubjectLiteralCommand
}

// isBatched reports whether this is a command-level batched approval — two or more pipeline
// stages approved by one choice. It gates the batched preview (pipeline + each
// stage listed verbatim) and short-circuits the direct-command scope sub-choice, since a
// batched grant stores each stage's own concrete subject rather than one shared scope choice.
func (r PromptRequest) isBatched() bool { return len(r.BatchedStages) > 1 }

// IsSimpleCompound reports whether the subject is a recognized simple compound
// eligible for the per-stage subject-scope chooser. It is a separate gate
// from IsDirectCommand: simple compounds arrive as literal-command subjects, so an
// ordinary literal (Compound nil) keeps the byte-exact no-chooser path and only a
// request carrying the recognized decomposition opens the compound chooser.
func (r PromptRequest) IsSimpleCompound() bool { return r.Compound != nil }

func (r PromptRequest) folderGrantEligibleOutOfRoot() bool {
	return r.OutOfRootFileWrite || r.OutOfRootReadScope || r.isShellSubject()
}

func (r PromptRequest) folderOmission() FolderOmission {
	return OmitFolderOption(r.RunFolder, r.ProjectRoot, r.folderGrantEligibleOutOfRoot(), r.ProjectUntrusted)
}

// CapabilityCoveragePhrase renders what a capability grant covers —
// a plain-words verb followed by the capability's members, e.g.
// "writing (create + edit)" for write. It returns "" for a non-capability stored
// subject (an ordinary tool grant covers only its one tool), so the caller omits the
// coverage line. The member list is read from the matcher's exported source-of-truth
// table, so the wording cannot drift from what the grant actually folds.
func CapabilityCoveragePhrase(storedSubject string) string {
	members, ok := permissions.CapabilityMembers(storedSubject)
	if !ok {
		return ""
	}
	// The switch below covers every capability the table holds, so this raw-subject
	// fallback is unreachable today; it survives as the wording a capability added to
	// the table without a verb here would get, instead of an empty phrase.
	verb := storedSubject
	switch storedSubject {
	case permissions.CapabilityWrite:
		verb = "writing"
	case permissions.CapabilityWriteTree:
		verb = "creating and editing files and folders"
	case permissions.CapabilityRead:
		verb = "reading/searching"
	}
	return verb + " (" + strings.Join(members, " + ") + ")"
}

// CapabilityCoverageSentence is the wording every prompt surface prints above its grant options
// when the grant folds a capability, so no two surfaces describe the same grant differently.
func CapabilityCoverageSentence(storedSubject string) string {
	phrase := CapabilityCoveragePhrase(storedSubject)
	if phrase == "" {
		return ""
	}
	return "Approving a grant below allows " + phrase + " in this scope — not just this one tool."
}

// PromptDecision is the outcome the prompt returns to permission orchestration.
// The subject-scope choice extends this struct along the same return path without
// changing the shell's option selection.
type PromptDecision struct {
	// Option is the grant option the user selected.
	Option PromptOption
	// StoredSubject is the final stored subject string for a grant-creating decision
	// (session/folder/global): the direct-command scope sub-choice (Exact/Subcommand/
	// Program) for a direct command, the backend generalized compound subject built by
	// permissions.EncodeCompoundSubject from the per-stage choices for a recognized
	// simple compound, or the capability subject (write/read*) carried
	// in PromptRequest.CapabilityStoredSubject for a structured-tool capability grant. It
	// is empty for allow-once, deny, and any subject whose grant stores the concrete
	// request subject (a non-capability tool, an ordinary literal command, or a compound
	// the backend refuses to generalize, e.g. one with a destructive stage), so no folded
	// subject is stored there.
	StoredSubject string
	// DenyEnvelope is the synthetic deny tool-error envelope, built by
	// permissions.BuildDenyEnvelope with the default deny reason. Deny is
	// a single action, so no user-supplied reason is collected and this is
	// always the default-reason envelope. It is set only for OptionDeny decisions and
	// is empty for every other option. The shell neither delivers nor persists it;
	// the backend routes it back to the model as the denied tool result and persists it as a
	// normal tool-result entry.
	DenyEnvelope string
}

// createsGrant reports whether the option persists or anchors a permission grant
// (session/folder/global). "allow this once" and "deny" create no grant, so the
// subject-scope sub-choice does not apply to them.
func (o PromptOption) createsGrant() bool {
	switch o {
	case OptionAllowSession, OptionAllowFolder, OptionAllowGlobal, OptionAllowProject:
		return true
	default:
		return false
	}
}

const hostFreshConfirmationNotice = "⚠ Non-default scheme or port: this needs a one-time confirmation. Any approval you already gave this host does not apply here, and no approval is stored."

const hostDirectHTTPDisclosure = "This is a plain http:// request. https:// is tried first and plain http:// is used only if that attempt fails."

func promptOptionsFor(req PromptRequest) []promptOptionRow {
	if !req.isHost() {
		if req.ExceptionalAuthority != "" {
			return hostFreshOptionsInOrder
		}
		return displayedPromptOptions(req)
	}
	if req.FreshConfirmation {
		return hostFreshOptionsInOrder
	}
	if !req.ProjectUntrusted {
		return hostOptionsInOrder
	}
	// A copy: the returned rows drive both the rendered list and the index/mnemonic mapping,
	// so the withheld option is absent from the decision path rather than merely unrendered.
	out := make([]promptOptionRow, 0, len(hostOptionsInOrder))
	for _, o := range hostOptionsInOrder {
		if o.Option == OptionAllowProject {
			continue
		}
		out = append(out, o)
	}
	return out
}

func promptRowLabel(row promptOptionRow) string {
	mnemonic, ok := promptMnemonics[row.Option]
	if !ok {
		return row.Label
	}
	for i := 0; i < len(row.Label); i++ {
		if row.Label[i] != byte(mnemonic) || (i > 0 && row.Label[i-1] != ' ') {
			continue
		}
		accented := "[" + accentTealHex + "]" + tview.Escape("["+string(mnemonic)+"]") + defaultTag
		return row.Label[:i] + accented + row.Label[i+1:]
	}
	return row.Label
}

func promptMnemonicIndex(opts []promptOptionRow, r rune) (int, bool) {
	lower := unicode.ToLower(r)
	for i, o := range opts {
		if m, ok := promptMnemonics[o.Option]; ok && m == lower {
			return i, true
		}
	}
	return -1, false
}

func renderHostPreview(req PromptRequest) string {
	var b strings.Builder
	b.WriteString("Tool: ")
	b.WriteString(tview.Escape(req.HostTool))
	b.WriteString("\n")
	if req.HostRequest != "" {
		b.WriteString("Request: ")
		b.WriteString(tview.Escape(req.HostRequest))
		b.WriteString("\n")
	}
	return b.String()
}

func hostFactLines(req PromptRequest) []string {
	lines := []string{"", "Host: " + permissions.BoundPromptFact(req.Host)}
	if req.DirectHTTPFallback {
		lines = append(lines, hostDirectHTTPDisclosure)
	}
	if req.FreshConfirmation {
		return append(lines, hostFreshConfirmationNotice)
	}
	// A host prompt renders no folder explanation (buildPromptOverlay gates that note on
	// !isHost), so substituting this fact line is the only place it can state the cause.
	if req.ProjectUntrusted {
		return append(lines,
			"",
			"allow for this session — applies to this exact host until codemeld exits.",
			untrustedProjectGrantExplanation,
		)
	}
	return append(lines,
		"",
		"allow for this session — applies to this exact host until codemeld exits.",
		"allow in this project — saved in this project so it survives restart; applies to this exact host only.",
	)
}

const (
	patchRemovedColor = "[red]"
	patchAddedColor   = "[green]"
)

// renderPatchBody emits markup only around prefixes it classified itself and escapes every line's
// content, so patch text that looks like a tview tag cannot inject markup into the approval prompt.
func renderPatchBody(patch string) string {
	var b strings.Builder
	for i, line := range strings.Split(patch, "\n") {
		if i > 0 {
			b.WriteString("\n")
		}
		escaped := tview.Escape(line)
		switch {
		case i == 0 && strings.HasPrefix(line, "--- "), i == 1 && strings.HasPrefix(line, "+++ "):
			b.WriteString(escaped)
		case strings.HasPrefix(line, "-"):
			b.WriteString(patchRemovedColor + escaped + defaultTag)
		case strings.HasPrefix(line, "+"):
			b.WriteString(patchAddedColor + escaped + defaultTag)
		default:
			b.WriteString(escaped)
		}
	}
	return b.String()
}

func renderPromptPreview(req PromptRequest) string {
	if req.isHost() {
		return renderHostPreview(req)
	}
	var b strings.Builder
	leadWithCommand := req.isShellSubject() && !req.isBatched() && req.Subject != ""
	if leadWithCommand && req.ExceptionalAuthority != "" {
		b.WriteString(tview.Escape(req.Action))
		b.WriteString("\n")
	}
	if leadWithCommand {
		b.WriteString("Command: ")
		b.WriteString(tview.Escape(req.Subject))
		b.WriteString("\n")
	} else {
		b.WriteString(tview.Escape(req.Action))
		b.WriteString("\n")
	}
	if req.isBatched() {
		fmt.Fprintf(&b, "This pipeline has %d stages that need your approval; one choice below applies to all of them.\n", len(req.BatchedStages))
		if req.Pipeline != "" {
			b.WriteString("Pipeline: ")
			b.WriteString(tview.Escape(req.Pipeline))
			b.WriteString("\n")
		}
		b.WriteString("Stages needing approval:\n")
		for _, stage := range req.BatchedStages {
			b.WriteString("  ")
			b.WriteString(tview.Escape(stage))
			b.WriteString("\n")
		}
	} else if req.Pipeline != "" {
		b.WriteString("Part of pipeline: ")
		b.WriteString(tview.Escape(req.Pipeline))
		b.WriteString("\n")
	} else if req.WholeCommand {
		b.WriteString("Whole command approval — the entire command runs verbatim, not one stage of a pipeline.\n")
	}
	if req.Subject != "" && !leadWithCommand {
		b.WriteString(tview.Escape(req.Subject))
		b.WriteString("\n")
	}
	if req.Body != "" {
		b.WriteString("\n")
		if req.Action == actionEditFile {
			b.WriteString(renderPatchBody(req.Body))
		} else {
			b.WriteString(tview.Escape(req.Body))
		}
		b.WriteString("\n")
	}
	return b.String()
}

const scopeEscalationNotice = "⚠ Broader than a folder you already allowed: this asks for the PARENT of "

const ShellBlockedPathsNotice = "⚠ Blocked paths are not enforced for a command you approve: it runs unchecked."

const ExceptionalSandboxNotice = "⚠ This command still runs inside the sandbox: the fixed floor, blocked paths and every ordinary restriction stay in force; approval adds only %s."

const exceptionalAllowOnceExplanation = "allow this once — approves this invocation only; nothing is saved and an identical repeat asks again."

// promptFactLines bounds every variable value it renders. Rows stay logical so the overlay can fit them to a physical-row budget.
func promptFactLines(req PromptRequest) []string {
	if req.isHost() {
		return hostFactLines(req)
	}
	// Run folder, and project root with an explicit mismatch marker so the user
	// is not surprised by the grant anchor.
	lines := []string{"", "Run folder: " + permissions.BoundPromptFact(req.RunFolder)}
	if req.ProjectRoot != "" {
		root := permissions.BoundPromptFact(req.ProjectRoot)
		if req.ProjectRoot != req.RunFolder {
			lines = append(lines, "Project root: "+root, "⚠ run folder differs from project root")
		} else {
			lines = append(lines, "Project root: "+root+" (same as run folder)")
		}
	}
	if req.ExceptionalAuthority != "" {
		lines = append(lines, fmt.Sprintf(ExceptionalSandboxNotice, req.ExceptionalAuthority))
	} else if req.isShellSubject() {
		lines = append(lines, ShellBlockedPathsNotice)
	}
	if req.Note != "" {
		lines = append(lines, permissions.BoundPromptFact(req.Note))
	}

	// Scope-escalation warning: the request's path scope is broader than — an ancestor
	// of — a folder the user already approved for this same subject. Surface the
	// broadening before any grant option is weighed. It does not block; the user
	// can still approve.
	if req.ScopeEscalationNarrower != "" {
		lines = append(lines, scopeEscalationNotice+permissions.BoundPromptFact(req.ScopeEscalationNarrower))
	}
	// A batched stage's escalation belongs here rather than beside its stage in the preview:
	// the preview retains raw request text only, and every authorization fact is bounded.
	for i, narrower := range req.BatchedEscalations {
		if narrower == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("Stage %d: %s%s", i+1, scopeEscalationNotice, permissions.BoundPromptFact(narrower)))
	}
	for i, note := range req.BatchedNotes {
		if note != "" {
			lines = append(lines, fmt.Sprintf("Stage %d: %s", i+1, permissions.BoundPromptFact(note)))
		}
	}
	if req.ExceptionalAuthority != "" {
		return append(lines, "", exceptionalAllowOnceExplanation)
	}

	// When this tool's grant folds a capability, state what the stored
	// grant covers so the user sees that approving any grant option here also authorizes the
	// sibling member tools at this scope — not just this one tool. Rendered before the per-option
	// lines so it frames every grant choice. Empty (and so absent) for a non-capability subject.
	if sentence := CapabilityCoverageSentence(req.CapabilityStoredSubject); sentence != "" {
		lines = append(lines, "", sentence)
	}

	lines = append(lines, "")
	omission := req.folderOmission()
	if !omission.Hidden() && req.FolderSettingsPath != "" {
		folder := "allow in this folder permanently — saved to " + permissions.BoundPromptFact(req.FolderSettingsPath) + " so it survives restart."
		if req.FolderCoverage != "" {
			folder += " Applies when run from: " + permissions.BoundPromptFact(req.FolderCoverage) + "."
		}
		lines = append(lines, folder)
	}
	lines = append(lines, "allow globally permanently — saved permanently; applies from any folder.")

	if notice, show := CrossModeMarkerNotice(req.LaunchDir, req.ProjectRoot, req.RunFolder, req.Boundary, req.WouldCreateSettingsFile, omission); show {
		lines = append(lines, "", notice)
	}

	return lines
}

func promptFixedLines(req PromptRequest) []string {
	return append(req.Summary.DisplayRows(), promptFactLines(req)...)
}

// promptSummaryKeepRows covers the two rows DisplayRows emits first — the summary sentence and
// the request-shape line — which survive any row budget.
const promptSummaryKeepRows = 2

func fitPromptFixedLines(lines []string, keep, width, budget int) (string, int) {
	total := 0
	for _, line := range lines {
		total += len(wrapRows(line, width))
	}
	if total <= budget {
		return strings.Join(lines, "\n"), total
	}
	markerRows := len(wrapRows(permissions.PromptFactsOverflowNotice, width))
	used := 0
	kept := make([]string, 0, len(lines)+1)
	for i, line := range lines {
		rows := len(wrapRows(line, width))
		if i >= keep && used+rows+markerRows > budget {
			break
		}
		kept = append(kept, line)
		used += rows
	}
	if used+markerRows <= budget {
		return strings.Join(append(kept, permissions.PromptFactsOverflowNotice), "\n"), used + markerRows
	}
	// Omitted facts must stay marked, so the required rows are squeezed into what is left after
	// the notice. Below keep+markerRows even one row each leaves no room for it, and the required
	// rows win.
	if budget-markerRows >= keep {
		text, rows := squeezePromptKeepLines(lines, keep, width, budget-markerRows)
		return text + "\n" + permissions.PromptFactsOverflowNotice, rows + markerRows
	}
	return squeezePromptKeepLines(lines, keep, width, budget)
}

// squeezePromptKeepLines lays out the rows the prompt may never drop — the summary sentence and
// the request-shape line — when the budget is smaller than their wrapped height. Each is cut to
// its share of the budget rather than clipped away, so a short terminal still shows both.
func squeezePromptKeepLines(lines []string, keep, width, budget int) (string, int) {
	if keep > len(lines) {
		keep = len(lines)
	}
	if budget <= 0 || keep <= 0 {
		return "", 0
	}
	if budget < keep {
		keep = budget
	}
	per, extra := budget/keep, budget%keep
	kept := make([]string, 0, keep)
	for i := 0; i < keep; i++ {
		rows := per
		if i < extra {
			rows++
		}
		kept = append(kept, truncateToRows(lines[i], width, rows))
	}
	return strings.Join(kept, "\n"), budget
}

// truncateToRows cuts text to at most n wrapped rows at the given width, marking the cut so the
// row reads as shortened rather than complete.
func truncateToRows(text string, width, n int) string {
	rows := wrapRows(text, width)
	if n <= 0 || len(rows) <= n {
		return text
	}
	cut := text[:rows[n-1].end]
	if _, size := utf8.DecodeLastRuneInString(cut); size > 0 {
		cut = cut[:len(cut)-size]
	}
	return cut + "…"
}

func newPromptDivider() *tview.Box {
	d := tview.NewBox()
	d.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		for i := 0; i < width; i++ {
			screen.SetContent(x+i, y, tcell.RuneHLine, nil, tcell.StyleDefault)
		}
		return x, y, width, height
	})
	return d
}

func (a *App) buildPromptOverlay(req PromptRequest, decisionCh chan<- PromptDecision) (tview.Primitive, *tview.List) {
	// The tool-call preview (Action + Subject + Body) is the only block that may
	// overflow, so it gets the flexible, scrollable region. The facts below
	// stay non-scrolling and always visible, sized to their wrapped row count.
	preview := tview.NewTextView()
	preview.SetDynamicColors(true)
	preview.SetText(renderPromptPreview(req))

	// The facts slot wraps but never scrolls, so its fixed height is fitted to the live
	// width and height by the draw hook below; otherwise a wrapped grant anchor is clipped
	// with no way to reach it.
	fixedLines := promptFixedLines(req)
	facts := tview.NewTextView()
	facts.SetDynamicColors(false)
	facts.SetWrap(true)
	facts.SetWordWrap(true)
	facts.SetText(strings.Join(fixedLines, "\n"))
	factsHeight := len(fixedLines)

	opts := promptOptionsFor(req)

	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	list.SetMainTextStyle(tcell.StyleDefault.Bold(true))
	list.SetSelectedStyle(tcell.StyleDefault.Reverse(true).Bold(true))
	for _, o := range opts {
		list.AddItem(promptRowLabel(o), "", 0, nil)
	}
	list.SetCurrentItem(0)
	selectOption := func(index int) {
		// For a direct-command subject a grant-creating selection
		// (session/folder/global) must route through the subject-scope sub-choice
		// before the decision is finalized; allow-once and deny create no grant and
		// finalize immediately. The callback runs on the tview event loop, so the
		// chooser mutates pages/focus directly (no QueueUpdateDraw).
		opt := opts[index].Option
		if opt == OptionDeny {
			// Deny creates no grant, so the subject-scope sub-choice
			// never applies. Deny is a single action: it finalizes immediately
			// with the default-reason envelope rather than opening a second overlay to
			// collect an optional reason. The model still receives the default deny
			// reason via permissions.BuildDenyEnvelope("").
			a.completePrompt(decisionCh, defaultDenyPromptDecision())
			return
		}
		if req.isBatched() {
			// One command-level choice applies to every batched stage. The per-stage subject-scope
			// sub-choice does not apply: a batched grant stores each stage's own concrete subject
			// (the backend clears the shared scope choice per stage), so finalize immediately with
			// the bare option rather than opening a scope chooser for a single representative stage.
			a.completePrompt(decisionCh, PromptDecision{Option: opt})
			return
		}
		if req.IsDirectCommand() && opt.createsGrant() {
			a.showScopeChooser(req, opt, decisionCh)
			return
		}
		if req.IsSimpleCompound() && opt.createsGrant() {
			// A recognized simple compound routes a grant-creating selection
			// through one subject-scope chooser per stage before finalizing; an ordinary
			// literal (Compound nil) keeps the immediate byte-exact path below.
			a.showCompoundChooser(req, opt, decisionCh)
			return
		}
		decision := PromptDecision{Option: opt}
		if opt.createsGrant() {
			// A structured-tool grant stores the capability subject dispatch
			// precomputed, so the grant folds the sibling member tools. Empty for a
			// non-capability tool and for a literal command, leaving the stored subject the
			// concrete request subject; allow-once/deny do not reach here with createsGrant.
			decision.StoredSubject = req.CapabilityStoredSubject
		}
		a.completePrompt(decisionCh, decision)
	}
	list.SetSelectedFunc(func(index int, _ string, _ string, _ rune) { selectOption(index) })
	// The option list keeps focus, but the preview must stay reachable so a
	// canonical literal command (or long file body) too long for the visible area
	// can be read in full. PgUp/PgDn scroll the (unfocused) preview —
	// now the only region that can overflow; the facts block is fixed-height and
	// always visible, so it is never scrolled. Arrow keys still move the option cursor.
	// A page shorter than the scroll step would skip rows outright, so a preview squeezed by a
	// short terminal scrolls by what it can actually show.
	scrollStep := func() int {
		if _, _, _, height := preview.GetInnerRect(); height > 0 && height < promptInfoScrollStep {
			return height
		}
		return promptInfoScrollStep
	}
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			a.dismissPrompt()
			return nil
		case tcell.KeyPgDn:
			row, col := preview.GetScrollOffset()
			preview.ScrollTo(row+scrollStep(), col)
			return nil
		case tcell.KeyPgUp:
			row, col := preview.GetScrollOffset()
			if row -= scrollStep(); row < 0 {
				row = 0
			}
			preview.ScrollTo(row, col)
			return nil
		case tcell.KeyRune:
			if index, ok := promptMnemonicIndex(opts, ev.Rune()); ok {
				list.SetCurrentItem(index)
				selectOption(index)
				return nil
			}
		}
		return ev
	})

	// Layout: the preview takes the bulk of the space (a flexible row, not a
	// newline-count-fixed one), so wrapped multi-row command/body text uses the
	// overlay height instead of being clipped to one row per logical line; PgUp/PgDn
	// reach any remainder when the terminal is too short. The single divider sits
	// *above* the facts, so the screen reads as the question (preview) above its
	// answer (facts + choices). The facts block is sized to its wrapped row count (the
	// draw hook below keeps it in step with the live width) and the option list to
	// len(opts), so both stay fully visible below the divider without scrolling.
	divider := newPromptDivider()
	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(preview, 0, 4, false).
		AddItem(divider, 1, 0, false).
		AddItem(facts, factsHeight, 0, false).
		AddItem(list, len(opts), 0, true)
	// Recompute the fixed block in the parent Flex draw hook because terminal width and height
	// are unknown until drawing, and the parent resizes it before child layout in the same
	// frame. Its full-width inner width is width-2; count literal text because bracketed path
	// text is visible. The budget reserves the decision rows, the divider, and one preview row
	// first, so a long fact list can never push the choices or the whole preview off screen.
	currentFactsRows := factsHeight
	currentFactsText := ""
	currentNoteRows := -1
	currentDividerRows := 1
	var note *tview.TextView
	noteText := ""
	if omission := req.folderOmission(); !req.isHost() && req.ExceptionalAuthority == "" && omission.Hidden() {
		noteText = folderUnavailableText(omission)
		note = tview.NewTextView()
		note.SetDynamicColors(false)
		note.SetWrap(true)
		note.SetWordWrap(true)
		note.SetText(noteText)
	}
	body.SetDrawFunc(func(_ tcell.Screen, x, y, width, height int) (int, int, int, int) {
		innerWidth, innerHeight := width-2, height-2
		if innerWidth > 0 {
			// The choices and one preview row are reserved before anything else. The
			// below-list explanation and then the divider give their rows back, in that
			// order, when the summary and request-shape rows would not otherwise both fit.
			avail := max(0, innerHeight-len(opts)-1)
			noteRows, dividerRows := 0, 1
			if note != nil {
				noteRows = 1
			}
			if avail-noteRows-dividerRows < promptSummaryKeepRows {
				noteRows = 0
			}
			if avail-dividerRows < promptSummaryKeepRows {
				dividerRows = 0
			}
			budget := max(0, avail-noteRows-dividerRows)
			if dividerRows != currentDividerRows {
				currentDividerRows = dividerRows
				body.ResizeItem(divider, dividerRows, 0)
			}
			text, rows := fitPromptFixedLines(fixedLines, promptSummaryKeepRows, innerWidth, budget)
			if text != currentFactsText {
				currentFactsText = text
				facts.SetText(text)
			}
			if rows != currentFactsRows {
				currentFactsRows = rows
				body.ResizeItem(facts, rows, 0)
			}
			if note != nil {
				// Beyond its reserved row the note may use whatever the facts left over,
				// so a roomy terminal still shows the whole explanation.
				noteRows = min(len(wrapRows(noteText, innerWidth)),
					max(noteRows, innerHeight-len(opts)-dividerRows-rows-1))
				if noteRows != currentNoteRows {
					currentNoteRows = noteRows
					body.ResizeItem(note, noteRows, 0)
				}
			}
		}
		return x + 1, y + 1, max(0, width-2), max(0, height-2)
	})
	body.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if event == nil || !body.InRect(event.Position()) {
			return action, event
		}
		if event.Modifiers()&tcell.ModShift != 0 {
			return action, nil
		}
		scrollPreview := func(delta int) {
			row, col := preview.GetScrollOffset()
			if row += delta; row < 0 {
				row = 0
			}
			preview.ScrollTo(row, col)
			a.app.SetFocus(list)
		}
		switch action {
		case tview.MouseScrollDown:
			scrollPreview(scrollStep())
			return tview.MouseConsumed, nil
		case tview.MouseScrollUp:
			scrollPreview(-scrollStep())
			return tview.MouseConsumed, nil
		case tview.MouseLeftDown:
			a.app.SetFocus(list)
			return tview.MouseConsumed, nil
		case tview.MouseLeftClick:
			if !list.InRect(event.Position()) {
				a.app.SetFocus(list)
				return tview.MouseConsumed, nil
			}
		}
		return action, event
	})
	if note != nil {
		body.AddItem(note, 1, 0, false)
	}
	body.SetBorder(true)
	title := " permission required "
	if req.ApprovalTotal > 1 {
		title = fmt.Sprintf(" permission required — Approval %d of %d ", req.ApprovalIndex, req.ApprovalTotal)
	}
	body.SetTitle(title)
	return body, list
}

// PromptUser presents the permission prompt as a modal overlay on the running
// app shell and blocks until the user picks an option, then dismisses the
// overlay and restores the prior focus, leaving the transcript and input buffer
// untouched. It is invoked from permission orchestration off the
// tview event-loop goroutine, so it drives the UI through QueueUpdateDraw and
// must not be called from a tview callback.
func (a *App) PromptUser(req PromptRequest) (PromptDecision, error) {
	// One notifier covers the whole blocked window: the scope chooser, the compound
	// chooser, and the Program confirm all resolve into this one channel.
	notifier := StartPromptNotifier(context.Background(), a.promptNotifyAfter, a.notifyPromptWaiting)
	decision := a.awaitPromptDecision(req)
	notifier.Stop()
	a.closePromptOverlay()
	return decision, nil
}

// PromptIndependent walks one authorization group's approval questions and returns one decision per
// request, index-aligned with reqs. The window opens once and closes once — each question replaces
// the previous one in place — so the group has one visible prompt owner while every question still
// gets its own attributable choice. Each screen shows only the question it is deciding. A group of
// one question is the ordinary single prompt.
func (a *App) PromptIndependent(reqs []PromptRequest) ([]PromptDecision, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	notifier := StartPromptNotifier(context.Background(), a.promptNotifyAfter, a.notifyPromptWaiting)
	decisions := make([]PromptDecision, len(reqs))
	for i, req := range reqs {
		decisions[i] = a.awaitPromptDecision(req)
	}
	notifier.Stop()
	a.closePromptOverlay()
	return decisions, nil
}

// awaitPromptDecision puts one prompt on screen and blocks off the tview event loop until the user
// chooses. It replaces any prompt already showing rather than layering a second one, so a group
// walking its questions keeps one window and one focus save. It leaves the overlay up; the caller
// closes it once the last decision is in.
func (a *App) awaitPromptDecision(req PromptRequest) PromptDecision {
	decisionCh := make(chan PromptDecision, 1)
	overlay, list := a.buildPromptOverlay(req, decisionCh)

	a.app.QueueUpdateDraw(func() {
		if !a.promptOpen {
			a.promptPrev = a.app.GetFocus()
		}
		a.promptOpen = true
		a.promptDecisionCh = decisionCh
		a.removePromptChoosers()
		if a.pages.HasPage(promptBasePage) {
			a.pages.RemovePage(promptBasePage)
		}
		a.pages.AddPage(promptBasePage, wrapOverlayPage(overlay), true, true)
		a.app.SetFocus(list)
	})

	return <-decisionCh
}

func (a *App) closePromptOverlay() {
	a.app.QueueUpdateDraw(func() {
		a.promptOpen = false
		a.promptDecisionCh = nil
		a.removePromptChoosers()
		a.pages.RemovePage(promptBasePage)
		if a.promptPrev != nil {
			a.app.SetFocus(a.promptPrev)
		} else {
			a.app.SetFocus(a.input)
		}
		a.promptPrev = nil
	})
}

// The scope/compound choosers and the Program confirm step are normally torn down before the
// decision is sent; remove any remainder so no overlay outlives the prompt it belongs to.
func (a *App) removePromptChoosers() {
	for _, page := range []string{promptScopeConfirmPage, promptScopePage, promptCompoundPage} {
		if a.pages.HasPage(page) {
			a.pages.RemovePage(page)
		}
	}
}

// showScopeChooser layers the subject-scope sub-choice over the option
// prompt for a grant-creating direct-command selection. It runs on the tview
// event loop (invoked from the option list's selected-callback), so it mutates
// pages and focus directly. The chosen scope's stored subject string is attached
// to the decision sent on decisionCh; Program scope first routes through an
// inline confirm step.
func (a *App) showScopeChooser(req PromptRequest, opt PromptOption, decisionCh chan<- PromptDecision) {
	overlay, list := a.buildScopeChooser(req, opt, decisionCh)
	a.pages.AddPage(promptScopePage, wrapOverlayPage(overlay), true, true)
	a.app.SetFocus(list)
}

func (a *App) buildScopeChooser(req PromptRequest, opt PromptOption, decisionCh chan<- PromptDecision) (tview.Primitive, *tview.List) {
	sc, _ := buildScopeChooserRows(req.CanonicalProgram, req.CanonicalArgs, a.home)
	opts := sc.options

	info := tview.NewTextView()
	info.SetDynamicColors(false)
	info.SetWrap(true)
	info.SetWordWrap(true)
	info.SetText(scopeChooserHelp(opts))

	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	for _, so := range opts {
		list.AddItem(so.Label, "", 0, nil)
	}
	list.SetCurrentItem(sc.defaultIdx)
	list.SetSelectedFunc(func(index int, _ string, _ string, _ rune) {
		so := sc.options[index]
		if so.Kind == ScopeProgram {
			a.showProgramConfirm(req, opt, so.Subject, decisionCh, list)
			return
		}
		a.finalizeScope(opt, so.Subject, decisionCh)
	})
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		// tview's List moves the cursor on left/right, so an unconsumed arrow would
		// leave the row being adjusted.
		if step, ok := scopeBoundaryStep(ev); ok && list.GetCurrentItem() == sc.pathRow {
			if label, adjusted := sc.adjust(step); adjusted {
				list.SetItemText(sc.pathRow, label, "")
			}
			return nil
		}
		return a.capturePromptEscape(ev)
	})

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(info, 0, 1, false).
		AddItem(list, len(opts), 0, true)
	body.SetBorder(true)
	body.SetTitle(" subject scope ")
	return body, list
}

func scopeBoundaryStep(ev *tcell.EventKey) (int, bool) {
	switch ev.Key() {
	case tcell.KeyRight:
		return 1, true
	case tcell.KeyLeft:
		return -1, true
	}
	return 0, false
}

func (a *App) showProgramConfirm(req PromptRequest, opt PromptOption, subject string, decisionCh chan<- PromptDecision, scopeList *tview.List) {
	body, list := a.buildProgramConfirm(req, opt, subject, decisionCh, scopeList)
	a.pages.AddPage(promptScopeConfirmPage, wrapOverlayPage(centeredModal(body)), true, true)
	a.app.SetFocus(list)
}

// buildProgramConfirm constructs the Program-scope confirm overlay and its
// confirm/cancel list. The warning copy is the standard breadth warning, sharpened
// with the destructive advisory when permissions.IsDestructiveProgram classifies the
// canonical program token as destructive; the classification changes copy
// only — confirm still finalizes the same `<program> :*` stored subject and cancel
// still creates no grant. It returns the body primitive and the list to focus so the
// rendered copy can be exercised directly through the real classifier path.
func (a *App) buildProgramConfirm(req PromptRequest, opt PromptOption, subject string, decisionCh chan<- PromptDecision, scopeList *tview.List) (tview.Primitive, *tview.List) {
	return a.buildProgramConfirmList(
		req.CanonicalProgram,
		programGrantEffect(req, opt, subject),
		func() { a.finalizeScope(opt, subject, decisionCh) },
		func() { a.cancelProgramConfirm(scopeList) },
	)
}

func programGrantEffect(req PromptRequest, opt PromptOption, subject string) string {
	var lifetime, coverage string
	switch opt {
	case OptionAllowSession:
		lifetime = "this session only, until codemeld exits"
		coverage = runFolderCoverage(req)
	case OptionAllowFolder:
		target := req.FolderSettingsPath
		if target == "" {
			target = "this project's settings"
		}
		lifetime = "permanent — saved to " + target
		coverage = runFolderCoverage(req)
	case OptionAllowGlobal:
		lifetime = "permanent — saved globally"
		coverage = "any folder (all paths)"
	default:
		return ""
	}
	return "Effective grant: " + subject + " (direct command)\nLifetime: " + lifetime + "\nApplies when run from: " + coverage
}

func runFolderCoverage(req PromptRequest) string {
	if req.FolderCoverage != "" {
		return req.FolderCoverage
	}
	return req.RunFolder + " and its descendants"
}

// buildProgramConfirmList builds the shared Program-scope confirm widget: the
// breadth warning (sharpened to the destructive advisory when
// permissions.IsDestructiveProgram classifies the canonical program token as
// destructive) above a two-item confirm/cancel list whose cursor opens on
// confirm. The confirm and cancel actions are supplied by the caller so the one
// widget serves both the direct-command finalize-or-cancel flow and the
// simple-compound per-stage advance-or-return flow; the classification only sets the
// copy and never decides what confirm or cancel do.
func (a *App) buildProgramConfirmList(program, effect string, onConfirm, onCancel func()) (tview.Primitive, *tview.List) {
	info := tview.NewTextView()
	info.SetDynamicColors(false)
	text := programConfirmWarning(permissions.IsDestructiveProgram(program))
	if effect != "" {
		text += "\n\n" + effect
	}
	info.SetText(text)

	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	list.AddItem("Confirm program-wide grant", "", 0, nil)
	list.AddItem("Cancel", "", 0, nil)
	list.SetCurrentItem(0)
	list.SetSelectedFunc(func(index int, _ string, _ string, _ rune) {
		if index == 0 {
			onConfirm()
			return
		}
		onCancel()
	})
	list.SetInputCapture(a.capturePromptEscape)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(info, 0, 1, false).
		AddItem(list, 2, 0, true)
	body.SetBorder(true)
	body.SetTitle(" confirm program scope ")
	return body, list
}

// cancelProgramConfirm abandons the Program-scope confirm step: it removes
// only promptScopeConfirmPage and restores focus to the scope-chooser list without
// sending any decision, so PromptUser stays blocked and the user can pick a
// different scope or back out (no program-wide grant is created).
func (a *App) cancelProgramConfirm(scopeList *tview.List) {
	a.pages.RemovePage(promptScopeConfirmPage)
	a.app.SetFocus(scopeList)
}

// finalizeScope tears down the scope chooser (and any confirmation step) and
// sends the final decision carrying the chosen stored subject string. It runs on
// the event loop, so the page removal is serialized with the draw loop before
// PromptUser unblocks and restores the prior focus.
func (a *App) finalizeScope(opt PromptOption, subject string, decisionCh chan<- PromptDecision) {
	if a.pages.HasPage(promptScopeConfirmPage) {
		a.pages.RemovePage(promptScopeConfirmPage)
	}
	a.pages.RemovePage(promptScopePage)
	a.completePrompt(decisionCh, PromptDecision{Option: opt, StoredSubject: subject})
}

// showCompoundChooser begins the per-stage subject-scope sub-choice for a recognized
// simple compound, invoked from the option list's selected-callback for a
// grant-creating selection. It builds the per-stage rows through the shared helper
// and opens the first stage. If the request gated as a simple compound nonetheless
// yields no stages it finalizes byte-exact (empty stored subject) rather than
// synthesizing a generalized subject. It runs on the tview event loop, so it mutates
// pages and focus directly.
func (a *App) showCompoundChooser(req PromptRequest, opt PromptOption, decisionCh chan<- PromptDecision) {
	stages := buildCompoundStageScopeOptions(*req.Compound)
	if len(stages) == 0 {
		a.completePrompt(decisionCh, PromptDecision{Option: opt})
		return
	}
	a.showCompoundStage(req, opt, stages, 0, nil, decisionCh)
}

// showCompoundStage layers the chooser for stage idx of the compound over the base
// prompt. chosen holds the canonical stored subjects already selected for the earlier
// stages, in order. The single promptCompoundPage is reused across stages; the caller
// removes it before advancing.
func (a *App) showCompoundStage(req PromptRequest, opt PromptOption, stages []compoundStageScope, idx int, chosen []string, decisionCh chan<- PromptDecision) {
	overlay, list := a.buildCompoundStage(req, opt, stages, idx, chosen, decisionCh)
	a.pages.AddPage(promptCompoundPage, wrapOverlayPage(overlay), true, true)
	a.app.SetFocus(list)
}

// buildCompoundStage builds the modal overlay and focusable list for one stage's
// subject-scope choice. The rows and their default come from
// buildCompoundStageScopeOptions, so every stage opens on the narrowest (Exact)
// scope and a destructive stage offers only Exact (no widening rows). Selecting Exact
// or Subcommand advances immediately; selecting Program routes through the shared
// confirm step, which on confirm advances and on cancel returns to this
// stage with no decision. Each row carries the canonical stored subject from the
// shared subject helpers; the display labels never become stored subjects.
func (a *App) buildCompoundStage(req PromptRequest, opt PromptOption, stages []compoundStageScope, idx int, chosen []string, decisionCh chan<- PromptDecision) (tview.Primitive, *tview.List) {
	stage := stages[idx]
	// The bare program token (not the full stage command) classifies the confirm
	// copy; req.Compound.Stages is parallel to stages, so index idx lines up.
	program := req.Compound.Stages[idx][0]

	info := tview.NewTextView()
	info.SetDynamicColors(false)
	info.SetText(compoundStageHeader(idx, len(stages), stage.Command) + "\n\n" + compoundStageScopeHelp(stage))

	list := tview.NewList()
	list.ShowSecondaryText(false)
	applyPickerListColors(list)
	for _, so := range stage.Options {
		list.AddItem(so.Label, "", 0, nil)
	}
	list.SetCurrentItem(stage.DefaultIdx)
	list.SetSelectedFunc(func(index int, _ string, _ string, _ rune) {
		so := stage.Options[index]
		// Copy rather than append onto chosen so a sibling selection (e.g. after a
		// Program-confirm cancel and a re-pick) cannot alias an earlier stage's slice.
		next := make([]string, len(chosen), len(chosen)+1)
		copy(next, chosen)
		next = append(next, so.Subject)
		if so.Kind == ScopeProgram {
			a.showCompoundProgramConfirm(program, func() {
				a.advanceCompoundStage(req, opt, stages, idx, next, decisionCh)
			}, list)
			return
		}
		a.advanceCompoundStage(req, opt, stages, idx, next, decisionCh)
	})
	list.SetInputCapture(a.capturePromptEscape)

	body := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(info, 0, 1, false).
		AddItem(list, len(stage.Options), 0, true)
	body.SetBorder(true)
	body.SetTitle(" compound subject scope ")
	return body, list
}

// showCompoundProgramConfirm layers the Program-scope confirm step over the current
// compound stage, reusing the shared confirm widget. confirm removes the step and
// runs onConfirm (which advances the compound flow); cancel removes only the step and
// restores focus to the stage's list without sending any decision, so no grant is
// created and the user can pick a different scope.
func (a *App) showCompoundProgramConfirm(program string, onConfirm func(), stageList *tview.List) {
	body, list := a.buildProgramConfirmList(
		program,
		"",
		func() {
			a.pages.RemovePage(promptScopeConfirmPage)
			onConfirm()
		},
		func() {
			a.pages.RemovePage(promptScopeConfirmPage)
			a.app.SetFocus(stageList)
		},
	)
	a.pages.AddPage(promptScopeConfirmPage, wrapOverlayPage(centeredModal(body)), true, true)
	a.app.SetFocus(list)
}

// advanceCompoundStage tears down the just-completed stage's chooser and either opens
// the next stage or, once every stage has a chosen subject, finalizes the compound
// grant. chosen already includes the current stage's selection.
func (a *App) advanceCompoundStage(req PromptRequest, opt PromptOption, stages []compoundStageScope, idx int, chosen []string, decisionCh chan<- PromptDecision) {
	a.pages.RemovePage(promptCompoundPage)
	if idx+1 < len(stages) {
		a.showCompoundStage(req, opt, stages, idx+1, chosen, decisionCh)
		return
	}
	a.finalizeCompound(opt, *req.Compound, chosen, decisionCh)
}

// finalizeCompound encodes the chosen per-stage canonical subjects into the backend
// generalized compound subject and sends the grant decision. The stored subject comes
// only from permissions.EncodeCompoundSubject over the canonical stage subjects and
// the compound's pinned operators — never assembled from display labels. If the
// backend refuses the shape (most notably a compound containing a destructive-program
// stage, which is ineligible for widening), no alternative generalized subject is
// synthesized: the grant falls back to the byte-exact concrete subject by leaving
// StoredSubject empty.
func (a *App) finalizeCompound(opt PromptOption, sc permissions.SimpleCompound, stageSubjects []string, decisionCh chan<- PromptDecision) {
	subject, err := permissions.EncodeCompoundSubject(sc.Wrapped, stageSubjects, sc.Operators)
	if err != nil {
		subject = ""
	}
	a.completePrompt(decisionCh, PromptDecision{Option: opt, StoredSubject: subject})
}

// compoundStageHeader is the per-stage instruction shown above a compound stage's
// scope rows, naming which stage of how many is being scoped and its command.
func compoundStageHeader(idx, total int, command string) string {
	return fmt.Sprintf("Choose the subject scope for compound stage %d of %d:\n%s", idx+1, total, command)
}

// compoundExactOnlyNotice is the advisory shown for a compound stage that offers
// only the Exact scope: a destructive stage suppresses its widening rows, so the
// generic Program-scope warning would read as contradictory ("choose Program" when
// Program is not on offer). This explains instead why broader scopes are withheld.
const compoundExactOnlyNotice = "Exact scope only: broader (subcommand/program) scopes are withheld here for safety because this stage is destructive."

// compoundStageScopeHelp picks the advisory shown below a compound stage's header
// from the rows the stage actually offers, so the copy can never claim a scope the
// chooser does not present. When a Program row is offered the standard breadth
// warning applies; when it is not (a destructive, exact-only stage) the exact-only
// notice explains why broader scopes are unavailable.
func compoundStageScopeHelp(stage compoundStageScope) string {
	for _, so := range stage.Options {
		if so.Kind == ScopeProgram {
			return scopeProgramWarning
		}
	}
	return compoundExactOnlyNotice
}

// completePrompt sends the resolved prompt decision once. Normal option picks and
// ESC dismissal share this path so a second keypress before PromptUser's cleanup
// queue runs cannot block the event loop by sending into an already-filled channel.
func (a *App) completePrompt(decisionCh chan<- PromptDecision, decision PromptDecision) {
	if a.promptOpen {
		if a.promptDecisionCh == nil {
			return
		}
		a.promptDecisionCh = nil
	}
	decisionCh <- decision
}

// dismissPrompt resolves the base permission prompt as a safe deny. A permission
// request cannot be hidden without a decision because PromptUser is blocking the
// tool call; denying keeps the command/tool from running and lets the normal
// permission-decision flow complete.
func (a *App) dismissPrompt() {
	if !a.promptOpen || a.promptDecisionCh == nil {
		return
	}
	decisionCh := a.promptDecisionCh
	a.promptDecisionCh = nil
	decisionCh <- defaultDenyPromptDecision()
}

func (a *App) capturePromptEscape(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyEscape {
		a.dismissPrompt()
		return nil
	}
	return ev
}

// defaultDenyPromptDecision builds the deny decision carried by a plain "deny"
// selection and by an ESC dismissal (dismissPrompt): OptionDeny with the
// default-reason envelope. Deny takes no user-supplied reason, so this is the only
// deny envelope the prompt produces — permissions.BuildDenyEnvelope normalizes the
// empty reason to the default deny text.
func defaultDenyPromptDecision() PromptDecision {
	return PromptDecision{
		Option:       OptionDeny,
		DenyEnvelope: permissions.BuildDenyEnvelope(""),
	}
}
