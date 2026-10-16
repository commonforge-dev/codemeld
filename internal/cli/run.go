// Command-line entry points for codemeld.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/turn"
	ucli "github.com/urfave/cli/v3"
	"golang.org/x/term"
)

// runHeadlessBootstrap is a package-local seam over bootstrap.RunHeadless so the run
// tests can exercise the CLI's flag parsing, exit-code mapping, and denial-summary
// rendering without running the real one-shot bootstrap or touching the network.
var runHeadlessBootstrap = bootstrap.RunHeadless

// runStdin is the terminal-prompt input for `codemeld run --prompt-for-approval`, and
// stdinIsTerminal reports whether that stdin is a real terminal. Both are package-local
// seams so the run tests can drive the non-tty refusal and the prompt path without owning
// a real tty: production reads/checks os.Stdin, tests swap in a pipe and force the verdict.
var (
	runStdin        io.Reader = os.Stdin
	stdinIsTerminal           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
)

// newRunCommand builds the `codemeld run` command: a headless, one-shot agent turn
// that streams the assistant reply to stdout and exits. stdout/stderr are explicit so
// callers (and tests) can capture the model text and diagnostics separately.
func newRunCommand(stdout, stderr io.Writer) *ucli.Command {
	return &ucli.Command{
		Name: "run",
		// A declared path may legitimately contain a comma, and these are the command's only
		// slice flags, so the whole command opts out of urfave's default value splitting.
		DisableSliceFlagSeparator: true,
		Usage:                     "run the agent once headlessly: final answer to stdout, tool-round text to stderr (fail-closed; optional --prompt-for-approval)",
		UsageText:                 "codemeld run [--model <provider/id>] [--effort <advertised-effort|no-reasoning>] [--mode plan|build|auto-edits] [--title <name>] [--prompt-for-approval] [--files-authorized <path>]... [--files-authorized-delete <path>]... [--dev-debug] [--time-limit <duration>] \"<prompt>\"",
		Description: "Run the agent loop once for a single prompt and exit. Only the final answer, or\n" +
			"the partial answer of an interrupted stream, goes to stdout. The assistant text of\n" +
			"tool-call rounds goes to stderr alongside tool activity, as do denials, provider\n" +
			"errors, and other notices.\n\n" +
			"The permission posture is fail-closed: any tool or shell command not authorized by\n" +
			"an existing grant or the active mode's auto-allow is denied in-band — the agent is\n" +
			"told it was refused and continues, and nothing mutating runs. Refusals of different\n" +
			"calls do not end the run, but when the same call has been refused 5 times the agent\n" +
			"gets one final round with no tools to write its answer, and the run ends there. There\n" +
			"is no skip-approvals flag; this is the safe default for non-interactive use, where\n" +
			"input is often untrusted. On exit, any denied calls are summarized on stderr.\n\n" +
			"With --model the run uses that provider/model (split on the first '/'; the id may\n" +
			"contain further slashes) at --effort. There is no fixed list of efforts: --effort\n" +
			"accepts any reasoning effort the selected provider/model advertises in its cached\n" +
			"catalog, plus 'no-reasoning', which sends no reasoning-effort parameter at all.\n" +
			"'default', where a model advertises it, is one such provider value, not the\n" +
			"no-parameter choice. An omitted --effort means 'no-reasoning'; an empty --effort, an\n" +
			"--effort without --model, or one the selected model does not advertise, is a usage error.\n" +
			"Without --model the run uses the active model from settings (model.active). --mode\n" +
			"pins the interaction mode for the run, overriding mode.default; under 'plan' every\n" +
			"mutating call is denied by the mode. On Linux (amd64/arm64), when codemeld's startup\n" +
			"sandbox check passes, 'plan' and 'auto-edits' run shell commands inside an OS sandbox\n" +
			"with filesystem and process-access restrictions, and 'build' runs them outside it; if\n" +
			"the check fails or the platform is not supported, commands run outside the sandbox.\n\n" +
			"The run creates a normal session, so it is resumable with 'codemeld --resume <id>'\n" +
			"and listed by 'codemeld sessions'. Ctrl-C cancels the turn and still persists the\n" +
			"session durably.\n\n" +
			"With --title <name> that session is named, so the '/resume' picker lists the name\n" +
			"instead of the start of the prompt. The name is kept as you typed it apart from runs\n" +
			"of whitespace (including newlines) being collapsed to single spaces and a cut at 80\n" +
			"characters; a --title that is empty or only whitespace is a usage error and starts no\n" +
			"run. The name is written before the first turn, so an interrupted run keeps it, and\n" +
			"nothing later in the run overwrites it. Without --title the session is titled\n" +
			"automatically: the start of a plain-text prompt (its first 12 words, at most 80\n" +
			"characters) is stored as the title before the turn, and after a successful first turn\n" +
			"the run makes one more small model request and replaces it with the model's title.\n" +
			"Either step is best-effort, so a session can still end up without a title.\n\n" +
			"A headless run honors the list of approved project roots but never prompts for\n" +
			"approval, under any flag, and never adds a root to that list. An approved project\n" +
			"contributes both its .codemeld/settings.yaml and .codemeld/settings.local.yaml\n" +
			"layers exactly as it does interactively; a project that is not approved contributes\n" +
			"neither. The gate covers those two settings layers and the project's VCS command\n" +
			"templates. AGENTS.md files load on their ordinary discovery rules whether or not the\n" +
			"project is approved: the global one, any above the project root, and the project's own.\n\n" +
			"With --prompt-for-approval a tool or command that would otherwise be denied instead\n" +
			"pauses and asks on the terminal (the request prints to stderr, your choice is read\n" +
			"from stdin); the run then continues headless. Every run offers allow once (run this\n" +
			"call; an identical repeat in the same run is not re-asked), deny (refuse it), and\n" +
			"allow for this session (allow this and matching calls for the rest of the run). In an\n" +
			"approved project one more choice is offered: allow in this project (record it\n" +
			"permanently in this project's .codemeld/settings.local.yaml, exactly as the same choice\n" +
			"in the interactive UI does; it is listed and revoked the same way). In an unapproved\n" +
			"project that choice is withheld: the prompt does not list it, and answering with it\n" +
			"denies the call.\n" +
			"For a direct command, allow for this session asks a second question:\n" +
			"which command scope the grant stores. In an approved project allow in this project\n" +
			"asks it too. The choices are the same ones the interactive UI offers — the exact\n" +
			"command, one choice per argument boundary (the tokens shown before :* are\n" +
			"stored verbatim and only later arguments may vary), or the whole program, which is\n" +
			"the widest and needs a further confirmation against a breadth\n" +
			"warning. A scope answer that names none of the offered choices denies the call and\n" +
			"stores nothing. A permanent choice is offered only in an approved project; before it the\n" +
			"prompt names the resolved project root, the absolute settings file the grant is written to,\n" +
			"and the folders it will cover.\n" +
			"Every other subject — a literal command, a structured tool, a host — keeps its fixed\n" +
			"subject and is not asked.\n" +
			"The 'allow globally' option is never offered here, so a headless run cannot write a\n" +
			"machine-wide permission.\n" +
			"The flag requires an interactive terminal on stdin, which is what licenses recording\n" +
			"a permanent choice at all in an approved project; with piped or redirected stdin it\n" +
			"refuses to start (exit 2). Without the flag the run stays fail-closed and writes no grant\n" +
			"of any kind.\n\n" +
			"With --files-authorized <path> the run may create and edit exactly that path, and with\n" +
			"--files-authorized-delete <path> it may delete exactly that path. Repeat either flag\n" +
			"once per path — the value is never split on a separator, so --files-authorized\n" +
			"'a,b.txt' authorizes the single file named a,b.txt. The two lists are independent: a\n" +
			"path you may write is not a path you may delete, and a path you may delete is not a\n" +
			"path you may write; name it in both lists to do both.\n\n" +
			"With either flag present the lists become the sole authorization for the write tools\n" +
			"(create, edit, delete, mkdir, move) for the whole run: an undeclared write is denied\n" +
			"even if a permission grant, a repeat within the turn, the active mode, or\n" +
			"--prompt-for-approval would otherwise allow it, and nothing inside the run can widen\n" +
			"the lists. mkdir and move are never authorized by either list. Declaring a path whose\n" +
			"parent directories do not exist also authorizes creating those parent directories,\n" +
			"because create builds them inside its own single authorization.\n" +
			"--files-authorized-delete authorizes the exact path whether it is a file, a symlink,\n" +
			"or an empty directory; a non-empty directory is refused regardless of the\n" +
			"declaration. Plan mode is unaffected: a declared write is still denied there.\n\n" +
			"A run ceiling also bounds delegation. A delegate call may declare only write paths\n" +
			"the --files-authorized list already covers; an uncovered declaration is refused ahead\n" +
			"of any grant, the turn cache, the mode, and --prompt-for-approval, and no child agent\n" +
			"starts. Coverage is not permission to delegate — a covered call is authorized like any\n" +
			"other. A child's own writes are bounded by the paths its delegate call declared, and a\n" +
			"nested delegate call may declare only paths its own parent already declared.\n" +
			"--files-authorized-delete on its own leaves the run's write list empty, so every\n" +
			"delegate declaration is uncovered.\n\n" +
			"Outside the file tools and delegation the lists bound nothing — the lists are not a\n" +
			"sandbox and do not authorize or confine shell writes. A shell command follows the\n" +
			"mode's OS sandbox when one is active; where none confines it (build mode, or a failed\n" +
			"or unsupported startup check), a shell command authorized by a grant can still write\n" +
			"anywhere the process can write.\n" +
			"Reads, shell, and network keep their ordinary authorization. An unresolvable\n" +
			"declaration ends the run before its first turn, naming the path.\n\n" +
			"With --dev-debug (or CODEMELD_DEV_DEBUG=1) the run records an ordered, development-\n" +
			"only suggest_followup trace as suggest_followup_debug session events — whether the\n" +
			"tool was advertised, whether the model called it, and where it was intercepted — to\n" +
			"diagnose a missing follow-up suggestion. It persists only stages, lengths, and\n" +
			"reasons, never suggestion text, and is off in a normal run. Inspect it afterward with\n" +
			"'codemeld sessions show <id>'.\n\n" +
			"With --time-limit <duration> (a Go duration such as 28m or 1680s) the run's work is\n" +
			"bounded, counted from the start of the command. When time is up, codemeld cancels the\n" +
			"provider request or tool calls in flight and gives the agent one final round with no\n" +
			"tools to write its answer from the work already done; the answer goes to stdout and\n" +
			"stderr then reports that the time limit was reached. Tool calls cut off by the limit are\n" +
			"recorded as cancelled. That final round is not bounded by --time-limit, so a caller that\n" +
			"also wraps the run in its own timeout should set it a few minutes higher. A terminal\n" +
			"approval prompt already waiting for your answer is not interrupted, but an answer given\n" +
			"after the limit authorizes nothing. Without --time-limit the run has no time limit.\n\n" +
			"Exit codes: 0 on a completed run, including one ended by --time-limit with a final\n" +
			"answer; 2 for a usage error (empty prompt, a malformed,\n" +
			"missing, or uncatalogued model, an effort without a model or one the model does not\n" +
			"advertise, an invalid mode, a blank --title, an empty, malformed, zero, or negative\n" +
			"--time-limit, or --prompt-for-approval without a terminal on stdin);\n" +
			"1 for a bootstrap or provider failure.",
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:  "model",
				Usage: "provider/model to use (e.g. openai/gpt-5.5); split on the first '/'. Omit to use model.active",
			},
			&ucli.StringFlag{
				Name:  "effort",
				Usage: "reasoning effort for --model: any value that model advertises, or no-reasoning to send none (default: no-reasoning); requires --model",
			},
			&ucli.StringFlag{
				Name:  "mode",
				Usage: "interaction mode for the run: plan, build, or auto-edits (overrides mode.default)",
			},
			&ucli.StringFlag{
				Name:  "title",
				Usage: "name this run's session, so the /resume picker lists the name instead of the start of the prompt; whitespace is collapsed to single spaces and the name is cut at 80 characters; a blank value is a usage error. Omit to title the session automatically from the prompt, then from the model after a successful first turn",
			},
			&ucli.BoolFlag{
				Name:  "prompt-for-approval",
				Usage: "ask on the terminal (allow-once / deny / allow-for-this-session, plus allow-in-this-project in an approved project) instead of denying; requires a tty on stdin; never grants globally",
			},
			&ucli.StringSliceFlag{
				Name:  "files-authorized",
				Usage: "path this run may create and edit; repeat once per path (never split on a separator). With either files-authorized flag the lists are the sole authorization for create/edit/delete/mkdir/move, ahead of grants, the turn cache, the mode, and --prompt-for-approval; mkdir and move are never covered; declaring a path also authorizes creating its missing parent directories; a delegate call may declare only paths this list covers, and an uncovered one starts no child; outside the file tools and delegation nothing is bound — the lists are not a sandbox, and where the mode's OS sandbox does not confine it (build mode, or a failed or unsupported startup check) a granted shell command can still write elsewhere",
			},
			&ucli.StringSliceFlag{
				Name:  "files-authorized-delete",
				Usage: "path this run may delete — the exact path, whether a file, a symlink, or an empty directory (a non-empty directory is refused regardless); repeat once per path (never split on a separator). Independent of --files-authorized, and subject to the same sole-authorization rule and the same limits; on its own it leaves the run's write list empty, so every delegate declaration is uncovered",
			},
			&ucli.BoolFlag{
				Name:  "dev-debug",
				Usage: "record a development-only suggest_followup trace in the session (also enabled by CODEMELD_DEV_DEBUG=1); inspect it with 'codemeld sessions show'",
			},
			&ucli.StringFlag{
				Name:  "time-limit",
				Usage: "positive duration (e.g. 28m, 1680s) after which the run stops its work and ends with one tool-less final answer; counted from the start of the command. Omit for no limit",
			},
		},
		Action: func(ctx context.Context, c *ucli.Command) error {
			return runHeadless(ctx, c, stdout, stderr)
		},
	}
}

// runHeadless validates the run flags, wires the headless bootstrap, and maps its
// outcome to an exit code. It owns the run command's stderr line shapes and exit codes
// the same way runFresh owns the launch path's.
func runHeadless(ctx context.Context, c *ucli.Command, stdout, stderr io.Writer) error {
	start := time.Now()
	prompt := strings.TrimSpace(strings.Join(c.Args().Slice(), " "))
	if prompt == "" {
		return ucli.Exit("codemeld: run requires a prompt; usage: codemeld run [options] \"<prompt>\"", 2)
	}

	modelOverride, err := parseModelSelection(c.String("model"), c.String("effort"), c.IsSet("effort"))
	if err != nil {
		return err
	}
	modeKey, err := parseRunMode(c.String("mode"))
	if err != nil {
		return err
	}
	sessionTitle, err := parseRunTitle(c.String("title"), c.IsSet("title"))
	if err != nil {
		return err
	}
	timeLimit, err := parseTimeLimit(c.String("time-limit"), c.IsSet("time-limit"))
	if err != nil {
		return err
	}

	// --prompt-for-approval requires an interactive terminal on stdin: there is no one to
	// answer a prompt on a piped/redirected stream, and silently falling back to default-deny
	// would hide that the requested escalation never happened. Refuse before bootstrap (exit 2).
	promptForApproval := c.Bool("prompt-for-approval")
	if promptForApproval && !stdinIsTerminal() {
		return ucli.Exit("codemeld: --prompt-for-approval requires an interactive terminal on stdin (it is not a tty)", 2)
	}

	cwd, err := osGetwd()
	if err != nil {
		return ucli.Exit(fmt.Sprintf("codemeld: cannot determine working directory: %s", err), 1)
	}

	// Ctrl-C cancels the headless turn (Step 7). signal.NotifyContext lives here, in the
	// run Action, so the interactive launch/resume paths are untouched; the bootstrap's
	// final flush uses context.WithoutCancel so a cancel still persists the session.
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	steps := bootstrap.HeadlessFreshSteps(stderr, modelOverride, modeKey)
	driver := bootstrap.NewHeadlessDriver(prompt, stdout, stderr)
	if promptForApproval {
		driver.EnablePromptForApproval(runStdin)
	}
	// --dev-debug turns on the suggest_followup development trace; the driver ORs it
	// with CODEMELD_DEV_DEBUG, so env-only runs still get it.
	if c.Bool("dev-debug") {
		driver.EnableDevDebug()
	}
	driver.SetSessionTitle(sessionTitle)
	if timeLimit > 0 {
		driver.SetTimeLimit(start.Add(timeLimit), timeLimit)
	}
	driver.SetDeclaredFileScopes(c.StringSlice("files-authorized"), c.StringSlice("files-authorized-delete"))
	denied, runErr := runHeadlessBootstrap(runCtx, cwd, steps, driver)
	if len(denied) > 0 {
		printDenialSummary(stderr, denied)
	}
	if runErr != nil {
		return mapHeadlessError(runErr)
	}
	return nil
}

// parseModelSelection builds the explicit model selection for --model/--effort, or nil
// when --model is unset (the run then falls back to the production model.active step).
// --model splits on the first '/' only, since a model id may contain further slashes.
func parseModelSelection(modelFlag, effortFlag string, effortSet bool) (*model.Selection, error) {
	if effortSet && effortFlag == "" {
		return nil, ucli.Exit("codemeld: --effort needs a value: an effort the selected model advertises, or no-reasoning; omit --effort to send no reasoning effort", 2)
	}
	if modelFlag == "" {
		if effortFlag != "" {
			return nil, ucli.Exit(fmt.Sprintf("codemeld: --effort %q requires --model <provider>/<id>; the advertised efforts depend on the selected model", effortFlag), 2)
		}
		return nil, nil
	}
	providerID, modelID, ok := splitProviderModel(modelFlag)
	if !ok {
		return nil, ucli.Exit(fmt.Sprintf("codemeld: --model must be in <provider>/<id> form; got %q", modelFlag), 2)
	}
	effort := effortFlag
	if effort == "" {
		effort = model.EffortNoReasoning
	}
	return &model.Selection{Provider: providerID, ID: modelID, Effort: effort}, nil
}

// splitProviderModel splits a --model value on its first slash into provider and id.
// The id may contain further slashes (e.g. an OpenRouter id); both halves must be
// non-empty.
func splitProviderModel(arg string) (provider, id string, ok bool) {
	idx := strings.Index(arg, "/")
	if idx <= 0 || idx == len(arg)-1 {
		return "", "", false
	}
	return arg[:idx], arg[idx+1:], true
}

// parseRunMode normalizes a --mode flag to its canonical interaction-mode key
// (auto-edits → auto_edits), or "" when --mode is unset (the run honors mode.default).
// An unrecognized value is a usage error (exit 2). It mirrors normalizeModeArg in
// internal/tui/cmd_mode.go, restated here so the CLI validates --mode and maps it to
// exit 2 without importing internal/tui.
func parseRunMode(modeFlag string) (string, error) {
	switch modeFlag {
	case "":
		return "", nil
	case "plan":
		return "plan", nil
	case "build":
		return "build", nil
	case "auto-edits":
		return "auto_edits", nil
	default:
		return "", ucli.Exit(fmt.Sprintf("codemeld: --mode must be plan, build, or auto-edits; got %q", modeFlag), 2)
	}
}

// maxRunTitleLen caps a --title in runes. It restates internal/turn's own cap, which is
// private to that package along with the generated-title sanitizer.
const maxRunTitleLen = 80

// parseRunTitle normalizes a --title value for the session metadata. Unlike the generated-title
// sanitizer in internal/turn it keeps wrapping quotes: this is a name the user typed, not a model
// reply that may have ignored a no-quotes instruction.
func parseRunTitle(titleFlag string, titleSet bool) (string, error) {
	if !titleSet {
		return "", nil
	}
	title := strings.Join(strings.Fields(titleFlag), " ")
	if title == "" {
		return "", ucli.Exit("codemeld: --title needs a name; omit --title to title the session automatically", 2)
	}
	if runes := []rune(title); len(runes) > maxRunTitleLen {
		title = strings.TrimSpace(string(runes[:maxRunTitleLen]))
	}
	return title, nil
}

func parseTimeLimit(value string, set bool) (time.Duration, error) {
	if !set {
		return 0, nil
	}
	limit, err := time.ParseDuration(value)
	if err != nil || limit <= 0 {
		return 0, ucli.Exit(fmt.Sprintf("codemeld: --time-limit must be a positive duration such as 28m or 1680s; got %q", value), 2)
	}
	return limit, nil
}

// mapHeadlessError maps a headless-run error to its exit code and stderr line. A model
// problem the run cannot resolve non-interactively (an uncatalogued --model, or a
// picker-required model with no --model) is a usage error (exit 2); every other failure
// (bootstrap, provider, turn) is exit 1, a post-plan tool-dispatch failure through its own
// case and everything else through the shared launch error mapping.
func mapHeadlessError(err error) error {
	var dispatchFailure *turn.DispatchFailure
	switch {
	// Ahead of the default branch, which prints the whole wrapped chain: only the typed
	// error's own message is safe to show.
	case errors.As(err, &dispatchFailure):
		return ucli.Exit("codemeld: "+dispatchFailure.Error(), 1)
	case errors.Is(err, bootstrap.ErrModelNotInCatalog):
		return ucli.Exit("codemeld: "+err.Error(), 2)
	case errors.Is(err, bootstrap.ErrModelPickerRequired):
		return ucli.Exit("codemeld: no model resolved for this run; pass --model <provider/id>", 2)
	default:
		return mapBootstrapError(err)
	}
}

// printDenialSummary writes the denial summary to stderr after a run that refused at least
// one call: the denied subjects, why each was refused, and how to authorize it, so a silent
// no-op never hides a refusal (Done-when 6). The advice is per denial because a declared
// scope cannot be widened by the grant or interactive route the other denials point at. It
// never writes to stdout.
func printDenialSummary(stderr io.Writer, denied []bootstrap.DeniedCall) {
	_, _ = fmt.Fprintf(stderr, "codemeld: %d call(s) denied:\n", len(denied))
	for _, call := range denied {
		line := "  - " + call.Subject
		if call.Reason != "" {
			line += ": " + call.Reason
		}
		_, _ = fmt.Fprintln(stderr, line)
		_, _ = fmt.Fprintf(stderr, "    %s\n", denialAdvice(call))
	}
}

func denialAdvice(call bootstrap.DeniedCall) string {
	if call.DeclaredScope() {
		return "to authorize, name the path in --files-authorized or --files-authorized-delete when starting the run; a permission grant and --prompt-for-approval cannot widen a declared scope."
	}
	return "to authorize, grant the command/tool (a permission grant in .codemeld/settings.local.yaml) or run codemeld interactively."
}
