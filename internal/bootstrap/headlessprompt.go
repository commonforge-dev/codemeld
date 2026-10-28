// Package bootstrap assembles codemeld's runtime dependencies.
package bootstrap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tui"
)

// terminalDisclosure must stay presentation-only: permissions.MatchRequest carries request
// identity, tokens, and path scope, and none of these fields may reach it or matching.
type terminalDisclosure struct {
	projectRoot             string
	launchDir               string
	boundary                string
	folderSettingsPath      string
	wouldCreateSettingsFile bool
}

// terminalPrompter is the stdin/stderr permission prompt the headless authorizer binds when
// --prompt-for-approval is set. in is read one line per prompt (a bufio.Reader so a final
// line without a trailing newline still parses); out receives all prompt text so stdout stays
// model-only; gate guarantees only one prompt is ever rendered/read at a time even when the
// agent dispatches tool calls concurrently.
type terminalPrompter struct {
	in *bufio.Reader
	// outMu serializes every write to out, which is an arbitrary io.Writer with no
	// synchronization of its own: the notifier writes from its timer goroutine while the
	// prompt goroutine is rendering. render, renderScopeChoices, renderProgramConfirm and
	// notify take it; the helpers they call write to out assuming it is already held.
	outMu     sync.Mutex
	out       io.Writer
	notifyTTY bool
	after     func(d time.Duration) <-chan time.Time

	gate       *promptGate
	disclosure terminalDisclosure
	// Set by HeadlessDriver.Run from BootstrapResult.Home. The empty zero value suppresses
	// the path-containment choice, so this surface never resolves home itself.
	home string
	// projectUntrusted is !BootstrapResult.TrustDecision.Trusted, set by HeadlessDriver.Run.
	// Its false zero value means trusted, so only that production assembly can withhold the
	// project choice; nothing here may infer trust from the disclosure or the cache.
	projectUntrusted bool
}

// newTerminalPrompter builds the terminal prompt over the injected stdin and the run's stderr.
// The single-slot gate is created here, once per run, so every per-request closure Build returns
// serializes on the same permit.
func newTerminalPrompter(stdin io.Reader, stderr io.Writer) *terminalPrompter {
	return &terminalPrompter{
		in:        bufio.NewReader(stdin),
		out:       stderr,
		notifyTTY: tui.PromptNotifyTTY(stderr),
		after:     time.After,
		gate:      newPromptGate(),
	}
}

func (p *terminalPrompter) notify() {
	if !p.notifyTTY {
		return
	}
	p.outMu.Lock()
	defer p.outMu.Unlock()
	_, _ = io.WriteString(p.out, "\a"+tui.PromptNotifySequence())
}

// build returns the permissions.AuthorizeDeps.Prompt closure for one authorization, capturing
// the matching request (for its resolved path scope) and the dispatch display payload (the
// human-readable action/subject/body). The closure acquires the shared gate (context-aware, so
// a cancelled work unit drops its pending prompt instead of showing it), renders the request and
// the orchestrator's display-only scope-escalation signal to stderr, reads one choice, and
// releases the gate with defer so a read error never strands the permit. A direct command whose
// choice creates a grant reads its stored subject scope through the same held permit, so the
// lifetime, scope, and Program-confirm reads cannot interleave with another request's prompt.
func (p *terminalPrompter) build(req permissions.MatchRequest, disp dispatch.PromptDisplay) func(context.Context, permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
	return func(ctx context.Context, esc permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
		if err := p.gate.acquire(ctx); err != nil {
			return permissions.PromptOutcome{}, err
		}
		defer p.gate.release()
		// One notifier for the whole closure: a direct-command grant is still blocked at
		// readDirectScope and the Program confirmation long after the first choice.
		notifier := tui.StartPromptNotifier(ctx, p.after, p.notify)
		defer notifier.Stop()
		p.render(req, disp, esc)
		host := req.Kind == matchKindHost
		outcome, err := p.readChoice(host, (host && req.FreshConfirmation) || disp.ExceptionalAuthority != "")
		if err != nil {
			return outcome, err
		}
		if err := ctx.Err(); err != nil {
			return permissions.PromptOutcome{}, err
		}
		outcome = applyCapabilitySubject(req, disp, outcome)
		outcome = p.readDirectScope(req, outcome)
		if err := ctx.Err(); err != nil {
			return permissions.PromptOutcome{}, err
		}
		return outcome, nil
	}
}

func applyCapabilitySubject(req permissions.MatchRequest, disp dispatch.PromptDisplay, outcome permissions.PromptOutcome) permissions.PromptOutcome {
	// A host display can carry a capability value, and a host grant must keep its own subject.
	if disp.GrantStoredSubject == "" || req.Kind != matchKindTool {
		return outcome
	}
	if outcome.Choice != permissions.PromptAllowSession && outcome.Choice != permissions.PromptAllowFolder {
		return outcome
	}
	outcome.StoredSubject = disp.GrantStoredSubject
	return outcome
}

func capabilityCoverageLine(req permissions.MatchRequest, disp dispatch.PromptDisplay) string {
	if req.Kind != matchKindTool {
		return ""
	}
	return tui.CapabilityCoverageSentence(disp.GrantStoredSubject)
}

const hostDirectHTTPDisclosure = "This is a plain http:// request. https:// is tried first and plain http:// is used only if that attempt fails."

const hostFreshConfirmationNotice = "⚠ Non-default scheme or port: this needs a one-time confirmation. Any approval you already gave this host does not apply here, and no approval is stored."

const scopeProgramWarning = "⚠ Program scope authorizes ANY invocation of this program with ANY arguments within the chosen path scope."

const scopeDestructiveProgramWarning = "⚠ DESTRUCTIVE program: this grant authorizes EVERY subcommand, including ones that permanently delete data or rewrite history."

// promptSummaryRows routes through the same permissions owner the interactive prompt uses, so
// both surfaces report identical shape counts for a request.
func promptSummaryRows(req permissions.MatchRequest, disp dispatch.PromptDisplay) []string {
	return promptSummaryFor(req, PromptDisplay{
		Action:          disp.Action,
		Subject:         disp.Subject,
		Body:            disp.Body,
		RequestedTarget: disp.RequestedTarget,
		HostRequest:     disp.HostRequest,
	}, nil).DisplayRows()
}

// visible neutralizes terminal control bytes in untrusted request text so a prompted request
// cannot conceal or reposition the summary and decision choices printed after it. The escape is
// lossless, so the complete request stays inspectable.
func visible(value string) string { return permissions.VisibleControlEscape(value) }

// fact renders one variable authorization fact under the same bounded contract as the
// interactive prompt: control bytes escaped whole and 120 code points at most, so no fact can
// add physical rows ahead of the choices. visible stays for the complete request payload only.
func fact(value string) string { return permissions.BoundPromptFact(value) }

func (p *terminalPrompter) renderSummary(rows []string) {
	for _, row := range rows {
		_, _ = fmt.Fprintf(p.out, "  %s\n", row)
	}
}

func (p *terminalPrompter) render(req permissions.MatchRequest, disp dispatch.PromptDisplay, esc permissions.ScopeEscalation) {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	_, _ = fmt.Fprintln(p.out)
	_, _ = fmt.Fprintln(p.out, "codemeld: approval required for a tool call (nothing pre-authorized it)")
	if req.Kind == matchKindHost {
		p.renderHost(req, disp)
		return
	}
	if disp.Action != "" {
		_, _ = fmt.Fprintf(p.out, "  %s: %s\n", disp.Action, visible(disp.Subject))
	} else if disp.Subject != "" {
		_, _ = fmt.Fprintf(p.out, "  %s\n", visible(disp.Subject))
	}
	if disp.Body != "" {
		_, _ = fmt.Fprintln(p.out, visible(disp.Body))
	}
	if req.PathScope != "" {
		_, _ = fmt.Fprintf(p.out, "  path: %s\n", fact(req.PathScope))
	}
	p.renderProjectRoot(req)
	if disp.ExceptionalAuthority != "" {
		_, _ = fmt.Fprintf(p.out, "  "+tui.ExceptionalSandboxNotice+"\n", disp.ExceptionalAuthority)
	} else if req.Kind == matchKindDirect || req.Kind == matchKindLiteral {
		_, _ = fmt.Fprintf(p.out, "  %s\n", tui.ShellBlockedPathsNotice)
	}
	if esc.Note != "" {
		_, _ = fmt.Fprintf(p.out, "  %s\n", fact(esc.Note))
	}
	if esc.NarrowerScope != "" {
		_, _ = fmt.Fprintf(p.out, "  ⚠ broader than a folder you already allowed: this asks for the PARENT of %s\n", fact(esc.NarrowerScope))
	}
	p.renderSummary(promptSummaryRows(req, disp))
	if line := capabilityCoverageLine(req, disp); line != "" {
		_, _ = fmt.Fprintf(p.out, "  %s\n", line)
	}
	if disp.ExceptionalAuthority != "" {
		_, _ = fmt.Fprintln(p.out, "  [1] allow this once     — run this call only; nothing is remembered and a repeat asks again")
		_, _ = fmt.Fprintln(p.out, "  [2] deny                — refuse this call")
		_, _ = fmt.Fprint(p.out, "codemeld: choose 1-2: ")
		return
	}
	_, _ = fmt.Fprintln(p.out, "  [1] allow once          — run this call; an identical repeat in this run is not re-asked")
	_, _ = fmt.Fprintln(p.out, "  [2] deny                — refuse this call")
	_, _ = fmt.Fprintln(p.out, "  [3] allow this session  — allow this and matching calls for the rest of the run")
	if p.projectUntrusted {
		_, _ = fmt.Fprint(p.out, "codemeld: choose 1-3 (a machine-wide/global grant is not offered here): ")
		return
	}
	_, _ = fmt.Fprintf(p.out, "  [4] allow in this project — remember this permanently in %s\n", fact(p.folderTarget()))
	if coverage := folderCoverage(req.PathScope); coverage != "" {
		_, _ = fmt.Fprintf(p.out, "      applies when run from: %s\n", coverage)
	}
	p.renderCrossModeNotice(req)
	_, _ = fmt.Fprint(p.out, "codemeld: choose 1-4 (a machine-wide/global grant is not offered here): ")
}

func (p *terminalPrompter) folderTarget() string {
	if p.disclosure.folderSettingsPath != "" {
		return p.disclosure.folderSettingsPath
	}
	return "this project's .codemeld/settings.yaml"
}

func folderCoverage(pathScope string) string {
	if pathScope == "" {
		return ""
	}
	return fact(pathScope) + " and its descendants"
}

func (p *terminalPrompter) renderProjectRoot(req permissions.MatchRequest) {
	root := p.disclosure.projectRoot
	if root == "" {
		return
	}
	if root == req.PathScope {
		_, _ = fmt.Fprintf(p.out, "  project root: %s (same as run folder)\n", fact(root))
		return
	}
	_, _ = fmt.Fprintf(p.out, "  project root: %s\n", fact(root))
	_, _ = fmt.Fprintln(p.out, "  ⚠ run folder differs from project root")
}

func (p *terminalPrompter) renderCrossModeNotice(req permissions.MatchRequest) {
	d := p.disclosure
	notice, show := tui.CrossModeMarkerNotice(d.launchDir, d.projectRoot, req.PathScope, d.boundary, d.wouldCreateSettingsFile,
		tui.OmitFolderOption(req.PathScope, d.projectRoot, false, p.projectUntrusted))
	if !show {
		return
	}
	_, _ = fmt.Fprintf(p.out, "  %s\n", notice)
}

func (p *terminalPrompter) renderHost(req permissions.MatchRequest, disp dispatch.PromptDisplay) {
	_, _ = fmt.Fprintf(p.out, "  tool: %s\n", fact(req.Subject))
	if disp.HostRequest != "" {
		_, _ = fmt.Fprintf(p.out, "  request: %s\n", visible(disp.HostRequest))
	}
	_, _ = fmt.Fprintf(p.out, "  host: %s\n", fact(req.Host))
	if disp.DirectHTTPFallback {
		_, _ = fmt.Fprintf(p.out, "  %s\n", hostDirectHTTPDisclosure)
	}
	p.renderSummary(promptSummaryRows(req, disp))
	if req.FreshConfirmation {
		_, _ = fmt.Fprintf(p.out, "  %s\n", hostFreshConfirmationNotice)
		_, _ = fmt.Fprintln(p.out, "  [1] allow this once     — run this call only; nothing is remembered and a repeat asks again")
		_, _ = fmt.Fprintln(p.out, "  [2] deny                — refuse this call")
		_, _ = fmt.Fprint(p.out, "codemeld: choose 1-2: ")
		return
	}
	_, _ = fmt.Fprintln(p.out, "  [1] allow this once     — run this call; an identical repeat in this run is not re-asked")
	_, _ = fmt.Fprintln(p.out, "  [2] deny                — refuse this call")
	_, _ = fmt.Fprintln(p.out, "  [3] allow for this session — applies to this exact host until codemeld exits")
	if p.projectUntrusted {
		_, _ = fmt.Fprint(p.out, "codemeld: choose 1-3: ")
		return
	}
	_, _ = fmt.Fprintln(p.out, "  [4] allow in this project — saved in this project so it survives restart; applies to this exact host only")
	_, _ = fmt.Fprint(p.out, "codemeld: choose 1-4: ")
}

func (p *terminalPrompter) readChoice(host, fresh bool) (permissions.PromptOutcome, error) {
	line, err := p.in.ReadString('\n')
	choice := strings.ToLower(strings.TrimSpace(line))
	if err != nil && choice == "" {
		return denyOutcome(), nil
	}
	switch choice {
	case "1", "allow", "allow-once", "once", "o":
		return permissions.PromptOutcome{Choice: permissions.PromptAllowOnce}, nil
	case "3", "session", "allow-session", "s":
		if fresh {
			return denyOutcome(), nil
		}
		return permissions.PromptOutcome{Choice: permissions.PromptAllowSession}, nil
	case "4", "project", "allow-project", "p":
		if fresh || p.projectUntrusted {
			return denyOutcome(), nil
		}
		if host {
			return permissions.PromptOutcome{Choice: permissions.PromptAllowProject}, nil
		}
		return permissions.PromptOutcome{Choice: permissions.PromptAllowFolder}, nil
	default:
		return denyOutcome(), nil
	}
}

func (p *terminalPrompter) readDirectScope(req permissions.MatchRequest, outcome permissions.PromptOutcome) permissions.PromptOutcome {
	if req.Kind != matchKindDirect {
		return outcome
	}
	if outcome.Choice != permissions.PromptAllowSession && outcome.Choice != permissions.PromptAllowFolder {
		return outcome
	}
	model, ok := permissions.NewDirectScopeModel(req.SubjectTokens, p.home)
	if !ok {
		return outcome
	}
	choices := headlessScopeChoices(model)

	persisted := outcome.Choice == permissions.PromptAllowFolder
	p.renderScopeChoices(req, model, choices, persisted)
	index, ok := p.readIndex(len(choices))
	if !ok {
		return denyOutcome()
	}

	selected := choices[index]
	if selected.RequiresConfirmation() {
		p.renderProgramConfirm(req, model.Program, selected.Subject, persisted)
		if !p.readConfirm() {
			return denyOutcome()
		}
	}
	outcome.StoredSubject = selected.Subject
	return outcome
}

const scopePrefixNotice = "A prefix choice stores every token shown before :* verbatim; only the tokens after it may vary. Changing a fixed token re-prompts."

// headlessScopeChoices fixes the path choice at its widest selectable ancestor: this surface
// reads one number and cannot walk the boundary, and the immediate parent of a path that
// changes every run would be a grant good for one run.
func headlessScopeChoices(model permissions.DirectScopeModel) []permissions.DirectScopeChoice {
	row := model.PathRow()
	if row < 0 {
		return model.Choices
	}
	widest, ok := model.PathChoiceAt(len(model.Choices[row].Boundaries) - 1)
	if !ok {
		return model.Choices
	}
	choices := slices.Clone(model.Choices)
	choices[row] = widest
	return choices
}

func scopePathNotice(boundary string) string {
	return "The path choice is fixed at " + boundary +
		", the widest boundary below / and your home directory; the interactive prompt can walk that boundary with ← and →, this one reads a single number and cannot." +
		" The command's path argument is resolved and checked against that boundary at the moment permission is decided — the boundary is not an execution-time sandbox and does not confine what the program opens afterwards."
}

func (p *terminalPrompter) renderScopeChoices(req permissions.MatchRequest, model permissions.DirectScopeModel, choices []permissions.DirectScopeChoice, persisted bool) {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	_, _ = fmt.Fprintln(p.out)
	_, _ = fmt.Fprintln(p.out, "codemeld: this grant stores a command subject — choose its scope")
	_, _ = fmt.Fprintln(p.out, "  subject kind: direct-command")
	_, _ = fmt.Fprintf(p.out, "  canonical command: %s\n", permissions.ExactSubject(model.Program, model.Args))
	if req.PathScope != "" {
		_, _ = fmt.Fprintf(p.out, "  run folder: %s\n", req.PathScope)
	}
	p.renderProjectRoot(req)
	if persisted {
		p.renderPersistTarget(req)
	}
	for i, c := range choices {
		_, _ = fmt.Fprintf(p.out, "  [%d] %s%s\n", i+1, p.scopeLabel(model, c), recommendedMark(i == model.Recommended))
	}
	_, _ = fmt.Fprintf(p.out, "  %s\n", scopePrefixNotice)
	if row := model.PathRow(); row >= 0 {
		_, _ = fmt.Fprintf(p.out, "  %s\n", scopePathNotice(choices[row].Boundaries[choices[row].Boundary]))
	}
	_, _ = fmt.Fprintf(p.out, "  %s\n", scopeProgramWarning)
	_, _ = fmt.Fprintf(p.out, "codemeld: choose 1-%d: ", len(choices))
}

// renderPersistTarget assumes renderProjectRoot has already run for this decision; it adds
// only the remaining persisted-folder facts.
func (p *terminalPrompter) renderPersistTarget(req permissions.MatchRequest) {
	_, _ = fmt.Fprintf(p.out, "  saved to: %s\n", p.folderTarget())
	if coverage := folderCoverage(req.PathScope); coverage != "" {
		_, _ = fmt.Fprintf(p.out, "  applies to: %s\n", coverage)
	}
	p.renderCrossModeNotice(req)
}

func (p *terminalPrompter) scopeLabel(model permissions.DirectScopeModel, c permissions.DirectScopeChoice) string {
	switch c.Kind {
	case permissions.DirectScopePrefix:
		return "prefix: " + c.Subject + " — fixed: " + permissions.ExactSubject(model.Program, c.Pinned) + "; any later arguments may vary"
	case permissions.DirectScopeProgram:
		return "program (advanced): " + c.Subject + " — ANY invocation of " + model.Program + " (widest)"
	case permissions.DirectScopePath:
		label := "path: " + c.Readable + " — " + permissions.ExactSubject(model.Program, c.Pinned) +
			" against any path resolving under " + c.Boundaries[c.Boundary] + ", checked when permission is decided"
		if c.TailWildcard {
			label += "; any later arguments may vary"
		}
		return label
	default:
		return "exact: " + c.Subject + " — only this exact command"
	}
}

func recommendedMark(recommended bool) string {
	if recommended {
		return " [recommended]"
	}
	return ""
}

// renderProgramConfirm is a distinct acknowledgement against the visible warning: one further
// choice, never a retype of the program name.
func (p *terminalPrompter) renderProgramConfirm(req permissions.MatchRequest, program, subject string, persisted bool) {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	_, _ = fmt.Fprintln(p.out)
	if permissions.IsDestructiveProgram(program) {
		_, _ = fmt.Fprintf(p.out, "  %s\n", scopeDestructiveProgramWarning)
	}
	_, _ = fmt.Fprintf(p.out, "  %s\n", scopeProgramWarning)
	_, _ = fmt.Fprintf(p.out, "  effective grant: %s (direct command)\n", subject)
	if persisted {
		_, _ = fmt.Fprintln(p.out, "  lifetime: permanent")
		p.renderPersistTarget(req)
	} else {
		_, _ = fmt.Fprintln(p.out, "  lifetime: this session only, until codemeld exits")
		if coverage := folderCoverage(req.PathScope); coverage != "" {
			_, _ = fmt.Fprintf(p.out, "  applies to: %s\n", coverage)
		}
	}
	_, _ = fmt.Fprintln(p.out, "  [1] confirm program-wide grant")
	_, _ = fmt.Fprintln(p.out, "  [2] cancel — create no grant")
	_, _ = fmt.Fprint(p.out, "codemeld: choose 1-2: ")
}

// readIndex fails closed: anything that is not a number in 1..count, including a blank line
// and EOF, reports false rather than falling back to a scope the user did not pick.
func (p *terminalPrompter) readIndex(count int) (int, bool) {
	line, err := p.in.ReadString('\n')
	answer := strings.TrimSpace(line)
	if err != nil && answer == "" {
		return 0, false
	}
	n, convErr := strconv.Atoi(answer)
	if convErr != nil || n < 1 || n > count {
		return 0, false
	}
	return n - 1, true
}

func (p *terminalPrompter) readConfirm() bool {
	index, ok := p.readIndex(2)
	return ok && index == 0
}

// denyOutcome is the deny result the terminal prompt returns for an explicit deny, EOF, or
// malformed input: a PromptDeny carrying the default-reason user deny envelope so the orchestrator
// delivers a well-formed tool error to the agent.
func denyOutcome() permissions.PromptOutcome {
	return permissions.PromptOutcome{Choice: permissions.PromptDeny, DenyEnvelope: permissions.BuildDenyEnvelope("")}
}
