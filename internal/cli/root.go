// Package cli wires the codemeld root command and dispatches --resume.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codemeld.dev/codemeld/internal/agentinstr"
	"codemeld.dev/codemeld/internal/authstatus"
	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/paths"
	ucli "github.com/urfave/cli/v3"
)

// runFreshBootstrap, runResumeWithIDBootstrap, runResumePickerBootstrap, and
// osGetwd are package-local seams so tests can exercise the launch dispatch paths
// without running the real orchestrator or touching the filesystem.
var (
	runFreshBootstrap        = bootstrap.RunFresh
	runResumeWithIDBootstrap = bootstrap.RunResumeWithID
	runResumePickerBootstrap = bootstrap.RunResumePicker
	osGetwd                  = os.Getwd
	osLstat                  = os.Lstat
)

// resolveHome and statusNow are package-local seams so the auth-status tests can
// force home resolution and the clock without touching the real environment.
var (
	resolveHome = paths.ResolveHome
	statusNow   = time.Now
)

// Run constructs the root command, executes it against args, and returns the
// process exit code. stdout and stderr are explicit so callers can capture output.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := newRootCommand(stdout, stderr)
	if rewritten := nestedHelpArgs(cmd, args); rewritten != nil {
		args = rewritten
	}
	err := cmd.Run(ctx, args)
	if err == nil {
		return 0
	}
	var ec ucli.ExitCoder
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	fmt.Fprintf(stderr, "codemeld: %s\n", err)
	return 1
}

// nestedHelpArgs rewrites `codemeld help <command> <subcommand>...` into the
// already-correct `codemeld <command> <subcommand>... --help` path, because
// urfave/cli v3's help command resolves only its first topic and would otherwise
// print the parent's help as if the trailing topics were absent. It returns nil
// unless every topic after `help` names a command, so unknown topics and the
// one-topic form keep the library's behavior.
func nestedHelpArgs(root *ucli.Command, args []string) []string {
	if len(args) < 4 || args[1] != "help" {
		return nil
	}
	path := args[2:]
	cur := root
	for _, name := range path {
		cur = cur.Command(name)
		if cur == nil {
			return nil
		}
	}
	rewritten := append([]string{args[0]}, path...)
	return append(rewritten, "--help")
}

func newRootCommand(stdout, stderr io.Writer) *ucli.Command {
	cmd := &ucli.Command{
		Name:      "codemeld",
		Usage:     "agentic editor",
		UsageText: "codemeld [--resume [session-id]] [--no-agents | --no-dir-agent | --agents-file <absolute-path>]\n   codemeld <command> [command options]",
		Description: "codemeld is an agentic editor: it opens an interactive, AI-backed editing\n" +
			"session for the project in the current working directory.\n\n" +
			"Run codemeld with no arguments to start a fresh session. Use --resume to\n" +
			"continue earlier work: with no id it opens a picker of recent sessions, and\n" +
			"with an id it reopens that specific session.\n\n" +
			agentsFlagsHelp +
			"EXAMPLES:\n" +
			"   codemeld                            start a new session in the current directory\n" +
			"   codemeld --resume                   choose a recent session to continue\n" +
			"   codemeld --resume <session-id>      resume a specific session by id\n" +
			"   codemeld --no-agents                start a new session without any AGENTS.md file\n" +
			"   codemeld run \"summarize main.go\"     run the agent once headlessly and print the reply\n" +
			"   codemeld auth status                show OpenAI authentication state\n" +
			"   codemeld auth login openai-chatgpt  sign in with a ChatGPT subscription\n" +
			"   codemeld config check               validate the global, shared project, and local project settings files\n" +
			"   codemeld config check <path>        validate one named settings file, without project discovery\n" +
			"   codemeld sessions list [--all] [--json]  list recorded sessions for this folder, or every folder\n" +
			"   codemeld sessions doctor <session-id|path>  report a session's errors and anomalies\n" +
			"   codemeld sessions show <session-id|path> [options]  read a session's records in order, whole or filtered\n" +
			"   codemeld sessions permissions <session-id|path>  list a session's permission prompts, decisions, and explicit revocation requests\n" +
			"   codemeld sessions research <session-id|path>     report a session's web searches, fetches, and cited sources\n" +
			"   codemeld sessions summary <session-id|path>      report a session's execution records, permission path scopes, turns, and tokens",
		Writer:    stdout,
		ErrWriter: stderr,
		Flags: append([]ucli.Flag{
			&ucli.BoolFlag{
				Name:  "resume",
				Usage: "resume a prior session; optionally accepts a session id as a positional argument",
			},
		}, agentsFlags()...),
		Before: rejectRootAgentsFlagsBeforeCommand,
		Commands: []*ucli.Command{
			newRunCommand(stdout, stderr),
			newAuthCommand(stdout),
			newConfigCommand(stdout),
			newSessionsCommand(stdout, stderr),
			{
				Name:            enforce.HelperCommand,
				Hidden:          true,
				SkipFlagParsing: true,
				Action: func(_ context.Context, c *ucli.Command) error {
					if code := enforce.RunHelper(c.Args().Slice()); code != 0 {
						return ucli.Exit("", code)
					}
					return nil
				},
			},
		},
		Action: func(ctx context.Context, c *ucli.Command) error {
			return dispatch(ctx, c, stdout, stderr)
		},
		// Print only; Run converts the error to an exit code so process exit lives in one place.
		ExitErrHandler: func(_ context.Context, c *ucli.Command, err error) {
			if err == nil {
				return
			}
			if msg := err.Error(); msg != "" {
				fmt.Fprintln(c.ErrWriter, msg)
			}
		},
		OnUsageError: func(_ context.Context, _ *ucli.Command, err error, _ bool) error {
			return ucli.Exit(fmt.Sprintf("codemeld: %s", err), 2)
		},
	}
	return cmd
}

// newAuthCommand builds the `codemeld auth` command tree. It carries the offline
// `auth status` subcommand, the `auth login` and `auth logout` subcommands, and an
// Action that reports a usage error when no known subcommand is selected, so
// `codemeld auth` and `codemeld auth <unknown>` fail clearly without touching the
// launch/resume root paths.
func newAuthCommand(stdout io.Writer) *ucli.Command {
	return &ucli.Command{
		Name:      "auth",
		Usage:     "manage OpenAI authentication state: status, login, logout",
		UsageText: "codemeld auth <status|login|logout> [arguments]",
		Description: "Inspect and manage how codemeld authenticates to OpenAI. There are two\n" +
			"providers: openai (the OpenAI Platform, which uses an API key) and\n" +
			"openai-chatgpt (a ChatGPT subscription signed in through the browser).\n\n" +
			"Use 'auth status' to see the current state, 'auth login' to sign in to a\n" +
			"browser-login provider, and 'auth logout' to remove a stored session.\n" +
			"Running 'codemeld auth' without a subcommand is an error.",
		Commands: []*ucli.Command{
			{
				Name:      "status",
				Usage:     "report OpenAI Platform and OpenAI ChatGPT auth state (offline)",
				UsageText: "codemeld auth status [--json]",
				Description: "Report whether codemeld can authenticate to each OpenAI provider. It reads\n" +
					"only local configuration (OPENAI_API_KEY and the global settings file) and\n" +
					"never contacts the network, and it never prints secret values.\n\n" +
					"By default it writes a short human-readable summary. Pass --json to emit a\n" +
					"script-friendly JSON report (still without any secrets).",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: "json", Usage: "emit script-friendly JSON without secrets"},
				},
				Action: func(_ context.Context, c *ucli.Command) error {
					return runAuthStatus(c.Bool("json"), stdout)
				},
			},
			newAuthLoginCommand(stdout),
			newAuthLogoutCommand(stdout),
		},
		Action: func(_ context.Context, c *ucli.Command) error {
			if c.Args().Present() {
				return ucli.Exit(
					fmt.Sprintf("codemeld: unknown auth subcommand %q; use 'codemeld auth status', 'codemeld auth login', or 'codemeld auth logout'", c.Args().First()),
					2,
				)
			}
			return ucli.Exit("codemeld: auth requires a subcommand; use 'codemeld auth status', 'codemeld auth login', or 'codemeld auth logout'", 2)
		},
	}
}

// runAuthStatus resolves the global settings path from home and writes the offline
// auth-status report to stdout, in JSON when asJSON is set. It is offline-only: it
// reads OPENAI_API_KEY and the global settings file and never dials the network. A
// home-resolution failure renders the same line shape as the launch paths; any
// settings read/parse failure renders a single codemeld-prefixed error.
func runAuthStatus(asJSON bool, stdout io.Writer) error {
	home, err := resolveHome()
	if err != nil {
		return ucli.Exit("codemeld: cannot resolve home directory: "+paths.FormatHomeError(err), 1)
	}
	report, err := authstatus.Collect(bootstrap.SettingsPath(home), statusNow())
	if err != nil {
		return ucli.Exit("codemeld: "+err.Error(), 1)
	}
	if err := authstatus.Render(stdout, report, asJSON); err != nil {
		return ucli.Exit("codemeld: "+err.Error(), 1)
	}
	return nil
}

const (
	noAgentsFlag   = "no-agents"
	noDirAgentFlag = "no-dir-agent"
	agentsFileFlag = "agents-file"
)

func agentsFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.BoolFlag{
			Name:  noAgentsFlag,
			Local: true,
			Usage: "load no AGENTS.md file at all, not even the global one; wins over --no-dir-agent; cannot be combined with --agents-file",
		},
		&ucli.BoolFlag{
			Name:  noDirAgentFlag,
			Local: true,
			Usage: "skip only the AGENTS.md in the launch directory; the global file and every file above the launch directory still load; cannot be combined with --agents-file",
		},
		&ucli.StringFlag{
			Name:  agentsFileFlag,
			Local: true,
			Usage: "load only this AGENTS.md file instead of discovering any; must be a non-empty absolute path and may lie outside the project; cannot be combined with --no-agents or --no-dir-agent",
		},
	}
}

const agentsFlagsHelp = "AGENTS.md files are discovered by default: the global one, any above the launch\n" +
	"directory, and the one in the launch directory. --no-agents loads none of them, not\n" +
	"even the global one. --no-dir-agent skips only the launch directory's own file. With\n" +
	"both, --no-agents wins. --agents-file <absolute-path> loads only that file instead of\n" +
	"discovering any; it must be a non-empty absolute path, may lie outside the project,\n" +
	"and combining it with --no-agents or --no-dir-agent is a usage error (exit 2), as is\n" +
	"an empty or relative path. These controls work the same whether or not the project\n" +
	"is approved. For a headless run they go after 'run', as in\n" +
	"'codemeld run --no-agents \"<prompt>\"'; placed before any command name they are a\n" +
	"usage error (exit 2).\n\n"

func rejectRootAgentsFlagsBeforeCommand(ctx context.Context, c *ucli.Command) (context.Context, error) {
	if !c.Args().Present() || c.Command(c.Args().First()) == nil {
		return ctx, nil
	}
	for _, name := range []string{noAgentsFlag, noDirAgentFlag, agentsFileFlag} {
		if c.IsSet(name) {
			return ctx, ucli.Exit(fmt.Sprintf("codemeld: --%s must not come before a command name; for a headless run put it after 'run'", name), 2)
		}
	}
	return ctx, nil
}

func agentsSelection(c *ucli.Command) (agentinstr.Selection, error) {
	noAgents, noDirAgent := c.Bool(noAgentsFlag), c.Bool(noDirAgentFlag)
	if !c.IsSet(agentsFileFlag) {
		switch {
		case noAgents:
			return agentinstr.Selection{Mode: agentinstr.DiscoverNone}, nil
		case noDirAgent:
			return agentinstr.Selection{Mode: agentinstr.DiscoverAllButLaunchDir}, nil
		}
		return agentinstr.Selection{}, nil
	}
	if noAgents || noDirAgent {
		return agentinstr.Selection{}, ucli.Exit("codemeld: --agents-file cannot be combined with --no-agents or --no-dir-agent", 2)
	}
	path := c.String(agentsFileFlag)
	if !filepath.IsAbs(path) {
		return agentinstr.Selection{}, ucli.Exit(fmt.Sprintf("codemeld: --agents-file needs a non-empty absolute path; got %q", path), 2)
	}
	return agentinstr.Selection{Mode: agentinstr.ExplicitFile, Path: filepath.Clean(path)}, nil
}

func dispatch(ctx context.Context, c *ucli.Command, stdout, stderr io.Writer) error {
	selection, err := agentsSelection(c)
	if err != nil {
		return err
	}
	nargs := c.NArg()
	if c.IsSet("resume") {
		switch nargs {
		case 0:
			return runResume(ctx, "", false, selection, stdout, stderr)
		case 1:
			return runResume(ctx, c.Args().First(), true, selection, stdout, stderr)
		default:
			return ucli.Exit(
				fmt.Sprintf("codemeld: --resume accepts at most one session id; got %d positional arguments", nargs),
				2,
			)
		}
	}
	if nargs > 0 {
		return ucli.Exit(
			"codemeld: positional arguments require --resume; use 'codemeld --resume <id>' or run without arguments",
			2,
		)
	}
	return runFresh(ctx, selection, stdout, stderr)
}

// runFresh drives the fresh-launch bootstrap orchestrator and renders its errors
// as exit codes. The orchestrator does not print; this layer owns the stderr
// line shape and exit code for each terminal outcome.
func runFresh(ctx context.Context, selection agentinstr.Selection, stdout, stderr io.Writer) error {
	cwd, err := osGetwd()
	if err != nil {
		return ucli.Exit(fmt.Sprintf("codemeld: cannot determine working directory: %s", err), 1)
	}

	steps := bootstrap.DefaultFreshSteps(stdout, stderr)
	steps.AgentInstructionsSelection = selection
	if _, err := runFreshBootstrap(ctx, cwd, steps); err != nil {
		return mapBootstrapError(err)
	}
	return nil
}

// runResume drives the resume-launch bootstrap orchestrator and renders its errors
// as exit codes, mirroring runFresh. hasID selects the `--resume <id>` entrypoint
// over the no-id picker. The orchestrator does not print; this layer owns the
// stderr line shape and exit code for each terminal outcome.
func runResume(ctx context.Context, id string, hasID bool, selection agentinstr.Selection, stdout, stderr io.Writer) error {
	cwd, err := osGetwd()
	if err != nil {
		return ucli.Exit(fmt.Sprintf("codemeld: cannot determine working directory: %s", err), 1)
	}

	steps := bootstrap.DefaultResumeSteps(os.Stdin, stdout, stderr)
	steps.AgentInstructionsSelection = selection
	var runErr error
	if hasID {
		_, runErr = runResumeWithIDBootstrap(ctx, cwd, id, steps)
	} else {
		_, runErr = runResumePickerBootstrap(ctx, cwd, steps)
	}
	if runErr != nil {
		return mapBootstrapError(runErr)
	}
	return nil
}

// mapBootstrapError maps a launch-orchestrator error to the ucli.Exit code and
// stderr line shape both launch paths share.
func mapBootstrapError(err error) error {
	var hre *bootstrap.HomeResolveError
	switch {
	case errors.As(err, &hre):
		// step 0a: "codemeld: cannot resolve home directory: <reason>".
		return ucli.Exit("codemeld: "+hre.Error(), 1)
	case errors.Is(err, bootstrap.ErrFirstRunFailed):
		// The first-run runner already wrote its OP_FAIL line; exit quietly.
		return ucli.Exit("", 1)
	case errors.Is(err, bootstrap.ErrResumeListPreflight):
		// sessions.RunResumeListPreflight already wrote the exact terminal-
		// failure line; exit status 1 quietly so the user does not see a second wrapped
		// line (the no-id --resume preflight quiet-exit contract).
		return ucli.Exit("", 1)
	case errors.Is(err, bootstrap.ErrSessionWriteOnExit):
		// The clean-shutdown write-failure helper already wrote the OP_FAIL
		// line; exit status 1 quietly so the user does not see a second wrapped line.
		return ucli.Exit("", 1)
	default:
		return ucli.Exit(bootstrapErrorMessage(err), 1)
	}
}

func bootstrapErrorMessage(err error) string {
	var noSelectable *model.NoSelectableModelError
	if errors.As(err, &noSelectable) {
		return noSelectable.Error()
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "codemeld:") {
		return msg
	}
	return "codemeld: " + msg
}
