// Built-in command registry: canonical/alias command metadata, startup
// validation (TR-TUI-3), and slash-input dispatch that routes aliases to the
// canonical handler and rejects unknown or wrong-arity input without side
// effects.
package tui

import (
	"fmt"
	"strings"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/sessions"
)

// Phase is the release phase a command becomes available in. It is a typed
// integer so the registry's {1, 2, 3} phase domain is enforced at registry construction
// rather than left as a bare int.
type Phase int

const (
	PhaseOne   Phase = 1
	PhaseTwo   Phase = 2
	PhaseThree Phase = 3
)

// valid reports whether p is one of the three defined phases.
func (p Phase) valid() bool { return p == PhaseOne || p == PhaseTwo || p == PhaseThree }

// ArgSignature is a command's argument-arity contract: ArgNone accepts
// zero arguments, ArgOneRequired exactly one, ArgOneOptional zero or one,
// ArgRestRequired at least one (all words after the command name are joined
// into a single argument by dispatch).
type ArgSignature int

const (
	ArgNone ArgSignature = iota
	ArgOneRequired
	ArgOneOptional
	ArgRestRequired
	ArgRestOptional
)

// accepts reports whether n supplied arguments satisfy the signature.
func (s ArgSignature) accepts(n int) bool {
	switch s {
	case ArgNone:
		return n == 0
	case ArgOneRequired:
		return n == 1
	case ArgOneOptional:
		return n == 0 || n == 1
	case ArgRestRequired:
		return n >= 1
	case ArgRestOptional:
		return true
	default:
		return false
	}
}

// expectation renders the signature as the human phrase used in the wrong-arity
// error so the message states what was expected.
func (s ArgSignature) expectation() string {
	switch s {
	case ArgNone:
		return "no arguments"
	case ArgOneRequired:
		return "exactly one argument"
	case ArgOneOptional:
		return "at most one argument"
	case ArgRestRequired:
		return "at least one word"
	case ArgRestOptional:
		return "any number of words"
	default:
		return "an unspecified number of arguments"
	}
}

// Outcome is the slash_command event outcome.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeError   Outcome = "error"
)

// HandlerFunc runs a recognized command. args are the parsed arguments, already
// arity-checked by dispatch. The handler owns its command-specific side effects
// and the sequencing of its slash_command event via ctx; placeholder entries in the
// static list bind a shared default that records the event, and BuildRegistry replaces
// selected handlers with their real behavior.
type HandlerFunc func(ctx CommandContext, args []string) error

// Command is one registry entry: the canonical name, optional aliases
// that route to the same handler, the one-line description shown by /help, the
// argument signature, the phase it is available in, and the handler.
type Command struct {
	Name        string
	Aliases     []string
	Description string
	ArgSig      ArgSignature
	Phase       Phase
	Handler     HandlerFunc
}

// CommandContext is the per-invocation surface a handler uses to render a
// one-line notice, retain the user's typed input, and append the command's
// slash_command event. DispatchSlashInput binds the canonical name and parsed
// args before the handler runs, so AppendSlashCommand records the canonical name
// (never the alias the user typed).
type CommandContext interface {
	// Notice renders a one-line user-facing notice.
	Notice(text string)
	// RetainInput requests that the input buffer keep the user's typed text, e.g.
	// after a command-level validation error.
	RetainInput()
	// ShowPanel opens a modal text panel (e.g. the /help listing) that blocks
	// input until the user dismisses it with ESC, leaving the input buffer intact.
	ShowPanel(text string)
	// ShowStatus opens the /status overlay: a
	// borderless panel drawn directly under the input area with a single top rule,
	// rendering the snapshot text. It blocks input until ESC, identically to
	// ShowPanel but kept as a distinct surface so /status's visual treatment can
	// diverge from /help's panel.
	ShowStatus(text string)
	// Registry returns the registry that dispatched this invocation, so a handler
	// (e.g. /help) can render the live command set without a package global.
	Registry() *Registry
	// Store returns the active session store for this invocation. Handlers that
	// must append events on the prior session before yielding to an in-process
	// session swap (clear) use it to call events.Append directly
	// because AppendSlashCommand only covers the slash_command record.
	Store() *sessions.Store
	// AppendSlashCommand appends this invocation's slash_command event with the
	// canonical name and parsed args. errorDetail must be empty when
	// outcome is OutcomeSuccess and non-empty when it is OutcomeError; the
	// payload validator enforces this and AppendSlashCommand surfaces its error.
	AppendSlashCommand(outcome Outcome, errorDetail string) error
	// FlushActive makes the active session durable after a handler appended an
	// event that has no other flush boundary — the /status, /help, and
	// placeholder commands, whose slash_command record is otherwise left in memory
	// until some unrelated later flush (it ties slash_command writes to their durability point).
	// Handlers call it immediately after AppendSlashCommand and before their
	// next non-append step (opening an overlay/panel, or returning). The production
	// host flushes and, on an atomic-write failure, runs the per-turn
	// protocol (session_write_failed + notice) and returns nil so the run carries
	// the records forward; a nil error means the records are durable (or the
	// failure was handled). Commands that own a later flush of the same stream
	// (/clear, /effort, /model, /exit) do not call it.
	FlushActive() error
}

// CommandHost is the capability surface the embedding app provides to dispatch:
// a one-line notice sink and the active session store for event appends. The app
// supplies the production implementation; tests supply a fake.
type CommandHost interface {
	Notice(text string)
	Store() *sessions.Store
	// ShowPanel opens a modal text panel that blocks input until dismissed;
	// the embedding app provides the panel surface.
	ShowPanel(text string)
	// ShowStatus opens the /status overlay; the
	// embedding app provides a panel surface distinct from ShowPanel's so the status
	// overlay's borderless top-rule treatment and below-input placement stay separate
	// from /help's box.
	ShowStatus(text string)
	// FlushActive flushes the active session for the command-event
	// flush (see CommandContext.FlushActive). The production app (internal/tui)
	// delegates to an injected hook that routes a write failure through
	// sessionfailures.HandleWriteFailure, keeping that delegation off the
	// sessionfailures→tui import cycle; a host with no flush wiring returns nil.
	FlushActive() error
}

// commandContext is the dispatch-built CommandContext bound to one invocation;
// it carries the resolved canonical name so a typed alias never leaks into the
// recorded event, and records whether the handler asked to retain input.
type commandContext struct {
	host      CommandHost
	reg       *Registry
	canonical string
	args      []string
	retain    bool
}

func (c *commandContext) Notice(text string)     { c.host.Notice(text) }
func (c *commandContext) RetainInput()           { c.retain = true }
func (c *commandContext) ShowPanel(text string)  { c.host.ShowPanel(text) }
func (c *commandContext) ShowStatus(text string) { c.host.ShowStatus(text) }
func (c *commandContext) Registry() *Registry    { return c.reg }
func (c *commandContext) Store() *sessions.Store { return c.host.Store() }
func (c *commandContext) FlushActive() error     { return c.host.FlushActive() }

func (c *commandContext) AppendSlashCommand(outcome Outcome, errorDetail string) error {
	_, err := events.Append(c.host.Store(), events.SlashCommand{
		Name:        c.canonical,
		Args:        c.args,
		Outcome:     string(outcome),
		ErrorDetail: errorDetail,
	})
	return err
}

// Registry is the validated set of built-in commands plus canonical-name and
// alias-to-canonical lookup maps.
type Registry struct {
	commands []Command          // source order, for /help listing
	byName   map[string]Command // canonical name -> command
	alias    map[string]string  // alias -> canonical name
}

// NewRegistry validates commands against the registry rules / TR-TUI-3 and builds the
// lookup maps. It returns an error (rather than panicking) so tests can assert
// each violation class individually; MustNewRegistry is the startup wrapper that
// turns a violation into the build-stopping panic.
func NewRegistry(commands []Command) (*Registry, error) {
	byName := make(map[string]Command, len(commands))
	for _, c := range commands {
		if !c.Phase.valid() {
			return nil, fmt.Errorf("registry: command %q has invalid phase %d (want 1, 2, or 3)", c.Name, int(c.Phase))
		}
		if !namePattern.MatchString(c.Name) {
			return nil, fmt.Errorf("registry: canonical name %q does not match %s", c.Name, namePattern)
		}
		if c.Handler == nil {
			return nil, fmt.Errorf("registry: command %q has a nil handler", c.Name)
		}
		if _, dup := byName[c.Name]; dup {
			return nil, fmt.Errorf("registry: duplicate canonical name %q", c.Name)
		}
		byName[c.Name] = c
	}
	alias := make(map[string]string)
	for _, c := range commands {
		for _, a := range c.Aliases {
			if !namePattern.MatchString(a) {
				return nil, fmt.Errorf("registry: alias %q (of %q) does not match %s", a, c.Name, namePattern)
			}
			if _, isCanonical := byName[a]; isCanonical {
				return nil, fmt.Errorf("registry: alias %q (of %q) collides with a canonical name", a, c.Name)
			}
			if prior, dup := alias[a]; dup {
				return nil, fmt.Errorf("registry: alias %q is declared by both %q and %q", a, prior, c.Name)
			}
			alias[a] = c.Name
		}
	}
	cp := make([]Command, len(commands))
	copy(cp, commands)
	return &Registry{commands: cp, byName: byName, alias: alias}, nil
}

// MustNewRegistry builds a Registry and panics on any validation violation.
// Registry-shape violations are a build-stopping error; for the in-binary
// source-of-truth list a startup panic is the runtime equivalent.
func MustNewRegistry(commands []Command) *Registry {
	r, err := NewRegistry(commands)
	if err != nil {
		panic(err)
	}
	return r
}

// resolve maps a typed name (canonical or alias) to its canonical command.
func (r *Registry) resolve(name string) (Command, bool) {
	if c, ok := r.byName[name]; ok {
		return c, true
	}
	if canonical, ok := r.alias[name]; ok {
		return r.byName[canonical], true
	}
	return Command{}, false
}

// Commands returns the registry entries in source order, for /help listing.
func (r *Registry) Commands() []Command {
	out := make([]Command, len(r.commands))
	copy(out, r.commands)
	return out
}

// DispatchStatus classifies what DispatchSlashInput did with one line of input.
type DispatchStatus int

const (
	// StatusNotASlashCommand is ordinary prompt text; the caller routes it to the
	// model. No notice, no event.
	StatusNotASlashCommand DispatchStatus = iota
	// StatusUnknownCommand is a syntactically valid /<name> with no registry entry
	// a notice was rendered, input is retained, and no event was
	// appended.
	StatusUnknownCommand
	// StatusWrongArity is a recognized command invoked with the wrong argument
	// count: a notice was rendered, input is retained, no handler was
	// reached, and no event was appended.
	StatusWrongArity
	// StatusHandled means a command handler ran; Err carries its result.
	StatusHandled
)

// DispatchResult reports the outcome of one DispatchSlashInput call so the caller
// can decide whether to clear or retain the input buffer and whether to forward
// the line to the model.
type DispatchResult struct {
	Status      DispatchStatus
	Canonical   string // resolved canonical name (StatusWrongArity, StatusHandled)
	Notice      string // one-line text dispatch rendered (StatusUnknownCommand, StatusWrongArity)
	RetainInput bool   // caller should keep the typed text in the input buffer
	Err         error  // handler error, if any (StatusHandled)
}

// DispatchSlashInput parses one line via ParseSlashInput and dispatches it. A bare
// exit/quit is treated as /exit. Unknown commands and
// wrong-arity invocations render a one-line notice, retain the typed
// input, and append no event; valid invocations run the canonical handler, which
// appends the slash_command event at its own sequencing point.
func (r *Registry) DispatchSlashInput(input string, host CommandHost) DispatchResult {
	parsed := ParseSlashInput(input)
	switch parsed.Kind {
	case KindBareExit:
		// bare exit/quit is equivalent to /exit. It is the canonical name
		// so no alias step and no arity check (it takes no arguments) is needed.
		return r.invokeName("exit", nil, host)
	case KindSlashInvocation:
		return r.dispatch(parsed.Invocation.Name, parsed.Invocation.Args, host)
	default:
		return DispatchResult{Status: StatusNotASlashCommand}
	}
}

// dispatch resolves a typed slash name, enforces arity, and runs the handler.
func (r *Registry) dispatch(name string, args []string, host CommandHost) DispatchResult {
	cmd, ok := r.resolve(name)
	if !ok {
		return r.reject(host, StatusUnknownCommand, "",
			fmt.Sprintf("unknown command: /%s — type /help to see available commands", name))
	}
	if !cmd.ArgSig.accepts(len(args)) {
		return r.reject(host, StatusWrongArity, cmd.Name,
			fmt.Sprintf("/%s takes %s, got %d", cmd.Name, cmd.ArgSig.expectation(), len(args)))
	}
	if (cmd.ArgSig == ArgRestRequired || cmd.ArgSig == ArgRestOptional) && len(args) > 1 {
		args = []string{strings.Join(args, " ")}
	}
	return r.run(cmd, args, host)
}

// invokeName dispatches by canonical name with no alias step, used for the bare
// exit/quit synonym. An absent entry is reported as unknown.
func (r *Registry) invokeName(name string, args []string, host CommandHost) DispatchResult {
	cmd, ok := r.byName[name]
	if !ok {
		return r.reject(host, StatusUnknownCommand, "",
			fmt.Sprintf("unknown command: /%s — type /help to see available commands", name))
	}
	return r.run(cmd, args, host)
}

// reject renders the one-line notice, retains the input, and returns the
// rejection result without reaching a handler or appending an event.
func (r *Registry) reject(host CommandHost, status DispatchStatus, canonical, notice string) DispatchResult {
	host.Notice(notice)
	return DispatchResult{Status: status, Canonical: canonical, Notice: notice, RetainInput: true}
}

// run builds the per-invocation context bound to the canonical name and runs the
// handler, then reports the handler's input-retention request and error.
func (r *Registry) run(cmd Command, args []string, host CommandHost) DispatchResult {
	ctx := &commandContext{host: host, reg: r, canonical: cmd.Name, args: args}
	err := cmd.Handler(ctx, args)
	return DispatchResult{Status: StatusHandled, Canonical: cmd.Name, RetainInput: ctx.retain, Err: err}
}

// recordHandler is the shared phase-1 handler: it appends the command's
// slash_command success event, flushes it since the
// placeholder has no later flush boundary of its own, and performs no
// command-specific side effect. BuildRegistry's replacement handlers supply the
// real behavior with their own event sequencing and error paths.
func recordHandler(ctx CommandContext, _ []string) error {
	if err := ctx.AppendSlashCommand(OutcomeSuccess, ""); err != nil {
		return err
	}
	return ctx.FlushActive()
}

// connectPlaceholderHandler stands in for /connect until production wiring rebinds the entry
// to NewConnectHandler with production deps. Unlike recordHandler it records no
// success and clears no input: it renders a one-line unavailable notice and
// retains the typed input, so an unbound /connect never pretends a provider was
// connected.
func connectPlaceholderHandler(ctx CommandContext, _ []string) error {
	ctx.Notice("connect is not available yet")
	ctx.RetainInput()
	return nil
}

// builtinCommands is the in-binary source-of-truth registry list.
// Phase-1 commands plus the first phase-2 command, /rename: codemeld enters
// phase 2 with that command, so its PhaseTwo entry shipping here is what the
// buildPhase == PhaseTwo flip in help.go makes valid. Phase-2 commands
// /connect ships as a PhaseTwo placeholder (connectPlaceholderHandler: notice +
// retain, no success event, no write) that production wiring rebinds to the real
// NewConnectHandler via BuildRegistry. /color ships its metadata here (bound to the
// real NewColorHandler in production).
var builtinCommands = []Command{
	{Name: "help", Description: "Show available commands and keyboard shortcuts", ArgSig: ArgNone, Phase: PhaseOne, Handler: helpHandler},
	{Name: "clear", Aliases: []string{"new"}, Description: "End the current session and start a fresh one", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
	{Name: "connect", Description: "Set up a provider by entering its API key", ArgSig: ArgOneOptional, Phase: PhaseTwo, Handler: connectPlaceholderHandler},
	{Name: "status", Description: "Open the session status overlay", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
	{Name: "context", Description: "Show context-window usage: session tokens used vs. the model's window", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
	{Name: "effort", Description: "Set the active reasoning effort", ArgSig: ArgOneOptional, Phase: PhaseOne, Handler: recordHandler},
	{Name: "model", Description: "Set the active model", ArgSig: ArgOneOptional, Phase: PhaseOne, Handler: recordHandler},
	{Name: "mode", Description: "Set the interaction mode (plan/build/auto-edits)", ArgSig: ArgOneOptional, Phase: PhaseOne, Handler: recordHandler},
	{Name: "resume", Description: "Open the session picker to resume a session", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
	{Name: "settings", Description: "Show and change settings and stored permission grants", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
	{Name: "openrouter", Description: "Open the OpenRouter routing settings", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
	{Name: "blocked", Description: "Show blocked paths and where each comes from; /blocked add <path> blocks another", ArgSig: ArgRestOptional, Phase: PhaseOne, Handler: recordHandler},
	{Name: "exit", Aliases: []string{"quit"}, Description: "Exit codemeld", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
	{Name: "rename", Description: "Rename the current session", ArgSig: ArgRestRequired, Phase: PhaseTwo, Handler: recordHandler},
	{Name: "color", Description: "Recolor the input area for this run (red|green|yellow|blue|magenta|cyan)", ArgSig: ArgOneRequired, Phase: PhaseTwo, Handler: NewColorHandler(ColorDeps{})},
	{Name: "fork", Description: "Fork the current session into a new one that continues from here", ArgSig: ArgNone, Phase: PhaseTwo, Handler: recordHandler},
	{Name: "compact", Description: "Replace the conversation with a summary in a fresh child session", ArgSig: ArgNone, Phase: PhaseTwo, Handler: recordHandler},
	{Name: "systemone", Description: "Show or set the System One read-only check (a validated model, or off)", ArgSig: ArgOneOptional, Phase: PhaseTwo, Handler: recordHandler},
	{Name: "skills", Description: "List loaded skills and the ones not loaded, with the reason", ArgSig: ArgNone, Phase: PhaseOne, Handler: recordHandler},
}

// BuildRegistry assembles a built-in command registry from the source-of-truth
// builtinCommands metadata, replacing the default handler of any command whose
// name appears in replacements with the supplied handler. A nil or empty map
// yields the unbound, metadata-only registry — every command keeps the handler
// builtinCommands declares (recordHandler for the phase-1 placeholders), which is
// what the slash-command, help, and dispatch unit tests build; a populated map
// binds real handlers for production assembly. This is the single place the
// command list is copied, so the unbound and production registries cannot drift
// from builtinCommands.
func BuildRegistry(replacements map[string]HandlerFunc) *Registry {
	cmds := make([]Command, len(builtinCommands))
	copy(cmds, builtinCommands)
	for i := range cmds {
		if h, ok := replacements[cmds[i].Name]; ok {
			cmds[i].Handler = h
		}
	}
	return MustNewRegistry(cmds)
}
