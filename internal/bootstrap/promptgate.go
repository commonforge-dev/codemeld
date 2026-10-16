// Gated permission-prompt adapter: maps a permissions.MatchRequest plus
// caller/run-scoped display data to the tui prompt, drives the real prompt UI
// behind a single-slot gate so only one permission prompt is ever on screen, and
// maps the user's tui.PromptDecision back to a permissions.PromptOutcome. It lives
// in internal/bootstrap because it must import both internal/tui (App.PromptUser)
// and internal/permissions (PromptOutcome) — a binding neither internal/agent nor
// internal/dispatch can make without an import cycle.
package bootstrap

import (
	"context"
	"fmt"

	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tui"
)

// Permission subject-kind discriminators as they appear on
// permissions.MatchRequest.Kind. The permissions package keeps these as
// unexported constants and internal/dispatch builds requests with the same string
// literals; the bootstrap adapter restates them only to translate a request's
// matching kind into the tui.SubjectKind the prompt shell displays.
const (
	matchKindDirect  = "direct"
	matchKindLiteral = "literal"
	matchKindTool    = "tool"
	matchKindHost    = "host"
)

// promptShower shows one permission prompt and blocks until the user decides. The
// production binding is (*tui.App).PromptUser; tests substitute a fake so the gate
// serialization and the request/decision mapping are exercised without a terminal
// driver.
type promptShower func(tui.PromptRequest) (tui.PromptDecision, error)

// independentShower shows one authorization group as a single prompt window and returns one
// decision per listed call, index-aligned with the requests. The production binding is
// (*tui.App).PromptIndependent; a builder bound only to a promptShower falls back to asking each
// call in turn through it.
type independentShower func([]tui.PromptRequest) ([]tui.PromptDecision, error)

// PromptDisplay carries the caller/run-scoped display data a permission prompt
// shows that permissions.MatchRequest deliberately does not hold. Matching keys on
// MatchRequest.Subject (the registered tool name for a structured tool, the
// canonical command otherwise); Action/Subject/Body are the human-readable prompt
// payload supplied per call by the dispatch producer (dispatch.PromptDisplay),
// not the bare matching subject. The remaining fields are resolved once per run from
// bootstrap/config state. Keeping them out of internal/permissions preserves the
// split between matching data and prompt display.
type PromptDisplay struct {
	// Action is the prompt's action header ("Create file" / "Edit file" /
	// "Run command" / "Run tool"), produced by dispatch from the subject kind and tool.
	Action string
	// For shell subjects, Subject is effective source text, not MatchRequest.Subject.
	Subject string
	// Body is the payload shown verbatim with no truncation and nothing added: the file
	// content for a create, an old→new snippet for an edit, the full structured-tool
	// call for any other tool. It is empty for a shell subject (the whole command is the
	// Subject).
	Body string
	// OutOfRootFileWrite marks a structured edit/create prompt whose resolved target lies
	// outside the project root. It is copied verbatim from
	// dispatch.PromptDisplay and mapped onto tui.PromptRequest so the prompt offers the
	// folder option for that out-of-root write only; false for every other prompt.
	OutOfRootFileWrite bool
	// OutOfRootReadScope marks a read-only navigation tool prompt whose resolved scope lies
	// outside the project root. It is copied verbatim from dispatch.PromptDisplay and
	// mapped onto tui.PromptRequest so the prompt offers the folder option for that out-of-root
	// read-only scope too; false for every other prompt.
	OutOfRootReadScope bool
	// GrantStoredSubject is the capability subject (write/read*) a grant should store when this
	// structured-tool prompt is approved with a grant-creating option. It is copied verbatim
	// from dispatch.PromptDisplay and mapped onto tui.PromptRequest, where the grant-creating choice
	// returns it as the stored subject so the grant folds the sibling member tools. Empty for every
	// prompt whose grant should store the concrete request subject.
	GrantStoredSubject string
	// Pipeline mirrors dispatch.PromptDisplay.Pipeline: the full pipeline source text carried through
	// for a direct pipeline-stage prompt so the prompt can show the approved stage is one stage of a
	// larger pipeline. Empty for a single direct command, a literal route, and every structured tool. It
	// is display-only, never consulted for matching, and mapped straight onto tui.PromptRequest.Pipeline
	// by buildPromptRequest.
	Pipeline string
	// WholeCommand mirrors dispatch.PromptDisplay.WholeCommand: true on a literal-route prompt to mark a
	// whole-command approval (the Subject is the entire command, not one stage of a direct pipeline).
	// Display-only and mapped straight onto tui.PromptRequest.WholeCommand by buildPromptRequest.
	WholeCommand bool
	// RequestedTarget mirrors dispatch.PromptDisplay.RequestedTarget and feeds only the prompt
	// summary; it is never a matching or grant input.
	RequestedTarget string
	// ProjectRoot is the resolved project root shown alongside the run folder.
	ProjectRoot string
	// LaunchDir is the resolved directory codemeld was launched in; with Boundary
	// and WouldCreateSettingsFile it gates the launch-dir-only cross-mode notice.
	LaunchDir string
	// Boundary is the resolved discovery boundary mode ("launch-dir-only" or
	// "project-root").
	Boundary string
	// FolderSettingsPath is the absolute path a folder grant would be written to,
	// shown for the folder option.
	FolderSettingsPath string
	// FolderCoverage is the one-line statement of what the folder grant covers.
	FolderCoverage string
	// WouldCreateSettingsFile reports whether persisting a folder grant would newly
	// create the project settings file.
	WouldCreateSettingsFile bool
	// ProjectUntrusted is !BootstrapResult.TrustDecision.Trusted, fixed for the run. It must
	// come from that decision and never be inferred from the config layers: a project with no
	// settings file has the same layer shape as an untrusted one and is trusted.
	ProjectUntrusted     bool
	HostRequest          string
	DirectHTTPFallback   bool
	ExceptionalAuthority string
}

func exceptionalAuthority(req permissions.MatchRequest, mc permissions.ModeContext) string {
	if !mc.ExecutionConstrained || mc.Mode != string(mode.AutoEdits) || (req.Kind != matchKindDirect && req.Kind != matchKindLiteral) {
		return ""
	}
	authority, _ := permissions.ClassifyExceptional(req, mc)
	return authority
}

func markExceptional(disp dispatch.PromptDisplay, req permissions.MatchRequest, mc permissions.ModeContext) dispatch.PromptDisplay {
	if authority := exceptionalAuthority(req, mc); authority != "" {
		disp.Action = exceptionalAction(authority)
		disp.ExceptionalAuthority = authority
	}
	return disp
}

func exceptionalAction(authority string) string { return "Allow " + authority }

func checkExceptionalChoice(pr tui.PromptRequest, d tui.PromptDecision) error {
	if pr.ExceptionalAuthority != "" && d.Option != tui.OptionAllowOnce && d.Option != tui.OptionDeny {
		return fmt.Errorf("bootstrap: a prompt adding %s accepts only allow once or deny, not option %d", pr.ExceptionalAuthority, d.Option)
	}
	return nil
}

// applyShellContext carries dispatch's display-only shell scope/pipeline context (the full pipeline
// text for a direct pipeline stage and the literal whole-command marker) from a dispatch prompt
// display onto the bootstrap prompt display, keeping the field names aligned so the dispatch->bootstrap
// bridge is one-to-one. These fields are display-only — never consulted for matching — and stay empty
// for structured-tool prompts, whose dispatch display leaves them unset. buildPromptRequest maps them
// onto tui.PromptRequest; this seam only carries them across the dispatch->bootstrap bridge. Every
// other field of d is preserved.
func applyShellContext(d PromptDisplay, disp dispatch.PromptDisplay) PromptDisplay {
	d.Pipeline = disp.Pipeline
	d.WholeCommand = disp.WholeCommand
	return d
}

// promptSummaryFor is the single bootstrap seam onto permissions' summary owner, so the
// interactive and terminal prompts cannot disagree about a request's shape counts.
func promptSummaryFor(req permissions.MatchRequest, display PromptDisplay, stages []string) permissions.PromptSummaryResult {
	return permissions.PromptSummary(req, permissions.PromptSummaryInput{
		Action:          display.Action,
		Command:         display.Subject,
		RequestedTarget: display.RequestedTarget,
		Body:            display.Body,
		HostRequest:     display.HostRequest,
		Stages:          stages,
	})
}

// promptGate serializes permission prompts so the TUI never shows more than one at
// a time, app-wide: with agent.max_concurrency > 1 several work
// units can reach an unauthorized action at once, and their prompts must queue and
// resolve one at a time rather than overlap. It is a cap-1 buffered channel used as
// a one-permit semaphore — a caller acquires the permit before showing a prompt and
// releases it after.
type promptGate struct {
	slot chan struct{}
}

func newPromptGate() *promptGate {
	return &promptGate{slot: make(chan struct{}, 1)}
}

// acquire blocks until the single prompt permit is free, then holds it and returns
// nil; the caller must release it. If ctx is cancelled while waiting (or is already
// cancelled), it returns ctx.Err() without taking the permit, so a cancelled or
// interrupted work unit drops its pending prompt cleanly and never shows it. The
// upfront ctx check makes an already-cancelled caller deterministic — a bare select
// could otherwise still take a free permit when both cases are ready.
func (g *promptGate) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case g.slot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release frees the prompt permit for the next waiter. It is called via defer after
// a successful acquire so a prompt error never strands the permit.
func (g *promptGate) release() {
	<-g.slot
}

// PromptGateBuilder produces per-request permissions.AuthorizeDeps.Prompt closures
// that all serialize through one shared single-slot gate, so the non-overlap
// guarantee is app-wide and not per-caller. The production authorizer builds one per run
// and calls Build for each authorization.
type PromptGateBuilder struct {
	gate            *promptGate
	show            promptShower
	showIndependent independentShower
}

// NewPromptGateBuilder returns a builder whose closures drive the real prompt UI
// (app.PromptUser) behind a fresh shared gate. Exactly one builder — one gate — is
// created per run and shared across every prompt source so only one permission
// prompt is ever on screen.
func NewPromptGateBuilder(app *tui.App) *PromptGateBuilder {
	b := newPromptGateBuilder(app.PromptUser)
	b.showIndependent = app.PromptIndependent
	return b
}

// newPromptGateBuilder is the shared core and the test seam: it binds the gate to
// an arbitrary prompt shower so the mapping, serialization, and cancel-while-
// waiting behavior can be exercised with a fake instead of a terminal-driven App.
func newPromptGateBuilder(show promptShower) *PromptGateBuilder {
	b := &PromptGateBuilder{gate: newPromptGate(), show: show}
	// A builder bound to a bare single-prompt shower still owes one decision per call, so it
	// asks for each in turn instead of reusing one answer for the whole group.
	b.showIndependent = func(reqs []tui.PromptRequest) ([]tui.PromptDecision, error) {
		decisions := make([]tui.PromptDecision, len(reqs))
		for i, req := range reqs {
			d, err := b.show(req)
			if err != nil {
				return nil, err
			}
			decisions[i] = d
		}
		return decisions, nil
	}
	return b
}

// Build returns the AuthorizeDeps.Prompt closure for one authorization. The closure
// maps req + display + the orchestrator's display-only ScopeEscalation to a
// tui.PromptRequest, acquires the shared gate (context-aware), shows the prompt,
// releases the gate, and maps the returned tui.PromptDecision to a
// permissions.PromptOutcome. The request is built before the gate is acquired so a
// malformed request fails without occupying the single prompt slot, and the gate is
// released with defer so a prompt error never strands it. ctx gates only the wait for
// the slot; once the prompt is on screen (*tui.App).PromptUser blocks until the user
// decides (it takes no ctx), matching the permissions.Authorize contract that the permission prompt resolves
// regardless of later cancellation.
func (b *PromptGateBuilder) Build(req permissions.MatchRequest, display PromptDisplay) func(context.Context, permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
	return func(ctx context.Context, esc permissions.ScopeEscalation) (permissions.PromptOutcome, error) {
		promptReq, err := buildPromptRequest(req, display, esc)
		if err != nil {
			return permissions.PromptOutcome{}, err
		}
		if err := b.gate.acquire(ctx); err != nil {
			return permissions.PromptOutcome{}, err
		}
		defer b.gate.release()
		decision, err := b.show(promptReq)
		if err != nil {
			return permissions.PromptOutcome{}, err
		}
		if err := checkExceptionalChoice(promptReq, decision); err != nil {
			return permissions.PromptOutcome{}, err
		}
		return mapOutcome(decision)
	}
}

// buildPromptRequest maps a matching request plus run-scoped display data to the tui
// prompt's display contract. The human-readable Action/Subject/Body come from display
// (the dispatch producer), not from the matching subject; Kind stays the matching kind
// so the prompt can gate the direct-command sub-choice; a direct command's
// CanonicalProgram/CanonicalArgs come from the canonical token sequence (program then
// args); the escalation's narrower scope is copied through as the display-only
// broaden-warning signal; the rest is run-scoped display data. The matching subject string
// itself is no longer shown on the prompt — it stays on MatchRequest for
// grants and the event log. An unrecognized kind is a wiring bug surfaced as an error
// rather than a silently mistyped prompt.
func buildPromptRequest(req permissions.MatchRequest, display PromptDisplay, esc permissions.ScopeEscalation) (tui.PromptRequest, error) {
	kind, ok := subjectKindForRequest(req.Kind)
	if !ok {
		return tui.PromptRequest{}, fmt.Errorf("bootstrap: unknown permission subject kind %q", req.Kind)
	}
	if kind == tui.SubjectHost {
		return buildHostPromptRequest(req, display), nil
	}
	pr := tui.PromptRequest{
		Action:                  display.Action,
		Subject:                 display.Subject,
		Body:                    display.Body,
		Kind:                    kind,
		RunFolder:               req.PathScope,
		ProjectRoot:             display.ProjectRoot,
		FolderSettingsPath:      display.FolderSettingsPath,
		FolderCoverage:          display.FolderCoverage,
		OutOfRootFileWrite:      display.OutOfRootFileWrite,
		OutOfRootReadScope:      display.OutOfRootReadScope,
		CapabilityStoredSubject: display.GrantStoredSubject,
		Pipeline:                display.Pipeline,
		WholeCommand:            display.WholeCommand,
		LaunchDir:               display.LaunchDir,
		Boundary:                display.Boundary,
		WouldCreateSettingsFile: display.WouldCreateSettingsFile,
		ScopeEscalationNarrower: esc.NarrowerScope,
		ProjectUntrusted:        display.ProjectUntrusted,
		Summary:                 promptSummaryFor(req, display, nil),
		ExceptionalAuthority:    display.ExceptionalAuthority,
	}
	// CanonicalProgram/CanonicalArgs drive the direct-command scope
	// sub-choice; only a direct command carries SubjectTokens, and the prompt leaves
	// them empty for every other kind.
	if kind == tui.SubjectDirectCommand && len(req.SubjectTokens) > 0 {
		pr.CanonicalProgram = req.SubjectTokens[0]
		pr.CanonicalArgs = req.SubjectTokens[1:]
	}
	// A literal command the backend recognizes as a simple compound carries its ordered
	// stage/operator decomposition so the prompt can open the per-stage scope
	// chooser; an ordinary literal leaves Compound nil and keeps the byte-exact no-chooser
	// path. Only the backend recognizer builds the decomposition — bootstrap never parses
	// the command itself. Recognition does not widen: a compound with a destructive stage
	// is still recognized here (its stages are shown, locked to exact), and the downstream
	// EncodeCompoundSubject refuses to generalize it, so its grant stays byte-exact.
	if kind == tui.SubjectLiteralCommand {
		if sc, ok := permissions.RecognizeSimpleCompoundForGrant(req.Subject); ok {
			pr.Compound = &sc
		}
	}
	return pr, nil
}

func buildHostPromptRequest(req permissions.MatchRequest, display PromptDisplay) tui.PromptRequest {
	return tui.PromptRequest{
		Kind:               tui.SubjectHost,
		HostTool:           req.Subject,
		HostRequest:        display.HostRequest,
		Host:               req.Host,
		FreshConfirmation:  req.FreshConfirmation,
		DirectHTTPFallback: display.DirectHTTPFallback,
		ProjectUntrusted:   display.ProjectUntrusted,
		Summary:            promptSummaryFor(req, display, nil),
	}
}

// subjectKindForRequest translates a MatchRequest.Kind discriminator into the
// tui.SubjectKind the prompt shell branches on, reporting false for an unrecognized
// kind.
func subjectKindForRequest(kind string) (tui.SubjectKind, bool) {
	switch kind {
	case matchKindDirect:
		return tui.SubjectDirectCommand, true
	case matchKindLiteral:
		return tui.SubjectLiteralCommand, true
	case matchKindTool:
		return tui.SubjectStructuredTool, true
	case matchKindHost:
		return tui.SubjectHost, true
	default:
		return "", false
	}
}

// mapOutcome maps the user's tui.PromptDecision to the permissions.PromptOutcome the
// orchestrator consumes. The deny envelope is copied only for a deny, and the stored
// subject only for a grant-creating option (session/folder/global) — the direct-command
// scope choice, the generalized simple-compound subject, or the tool
// capability subject (write/read*). It is empty on the decision for allow-once, deny, and
// subjects whose grant stores the concrete request subject (an ordinary literal, or a
// compound the backend refused to generalize, e.g. a destructive stage). An unrecognized
// option is a wiring bug surfaced as an error.
func mapOutcome(d tui.PromptDecision) (permissions.PromptOutcome, error) {
	choice, ok := optionToChoice(d.Option)
	if !ok {
		return permissions.PromptOutcome{}, fmt.Errorf("bootstrap: unknown prompt option %d", d.Option)
	}
	out := permissions.PromptOutcome{Choice: choice}
	switch d.Option {
	case tui.OptionDeny:
		out.DenyEnvelope = d.DenyEnvelope
	case tui.OptionAllowSession, tui.OptionAllowFolder, tui.OptionAllowGlobal:
		out.StoredSubject = d.StoredSubject
	}
	return out, nil
}

// mapOutcomeFor maps one authorization-group decision onto one call of that group. The group
// prompt carries no representative capability subject, so a grant-creating choice stores the
// capability of the call it is being applied to rather than a sibling's.
func mapOutcomeFor(d tui.PromptDecision, display PromptDisplay) (permissions.PromptOutcome, error) {
	out, err := mapOutcome(d)
	if err != nil {
		return permissions.PromptOutcome{}, err
	}
	switch d.Option {
	case tui.OptionAllowSession, tui.OptionAllowFolder, tui.OptionAllowGlobal:
		out.StoredSubject = display.GrantStoredSubject
	}
	return out, nil
}

// optionToChoice maps a tui.PromptOption to its permissions.PromptChoice mirror,
// reporting false for an unrecognized option.
func optionToChoice(o tui.PromptOption) (permissions.PromptChoice, bool) {
	switch o {
	case tui.OptionAllowOnce:
		return permissions.PromptAllowOnce, true
	case tui.OptionDeny:
		return permissions.PromptDeny, true
	case tui.OptionAllowSession:
		return permissions.PromptAllowSession, true
	case tui.OptionAllowFolder:
		return permissions.PromptAllowFolder, true
	case tui.OptionAllowGlobal:
		return permissions.PromptAllowGlobal, true
	case tui.OptionAllowProject:
		return permissions.PromptAllowProject, true
	default:
		return 0, false
	}
}
