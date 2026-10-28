// `codemeld sessions` read-only diagnostics: `doctor` reports a session's
// recorded errors/failures/anomalies grouped by a derived severity, `show`
// renders its records in order with tool-call arguments unescaped for display,
// `permissions` lists the prompts a human was shown with their decisions and
// the explicit revocation requests, `research` reports the objective
// web-research funnel the records support, and `summary` aggregates the durable
// execution records, permission path scopes, turns, and tokens.
// No subcommand writes, locks, or mutates the session in any way.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/webresearch"
	ucli "github.com/urfave/cli/v3"
)

// tsDisplayLayout is the canonical session timestamp form (UTC, millisecond
// precision, trailing Z), reused so diagnostics print timestamps in the same
// shape the session file stores them in.
const tsDisplayLayout = "2006-01-02T15:04:05.000Z"

// Derived severity labels for doctor findings. Severity is not stored in the
// session; it is derived from the event kind and its fields (see classifyFinding).
const (
	sevError   = "error"
	sevWarning = "warning"
	sevInfo    = "info"
)

const reasonIncompleteRound = "incomplete_round"

// newSessionsCommand builds the read-only `codemeld sessions` command tree with
// the `doctor`, `show`, `permissions`, `research`, and `summary` subcommands,
// modeled on newAuthCommand. Running `codemeld sessions` with no subcommand is a
// usage error.
func newSessionsCommand(stdout, stderr io.Writer) *ucli.Command {
	return &ucli.Command{
		Name:  "sessions",
		Usage: "list and inspect recorded sessions: list, doctor, show, permissions, research, summary (read-only diagnostics)",
		UsageText: "codemeld sessions list [--all] [--json]\n" +
			"codemeld sessions <doctor|show|permissions|research|summary> <session-id|path> [options]",
		Description: "Inspect a recorded session file without changing it. These commands are\n" +
			"strictly read-only: they never write, lock, prune, fork, or refresh a\n" +
			"session, so running them is always safe.\n\n" +
			"A session is named either by its id or by an explicit path to a session JSON\n" +
			"file. A value that is a valid session id is treated as an id; anything else is\n" +
			"treated as a file path. An id is found no matter which directory you run from:\n" +
			"unlike 'codemeld --resume <id>', which refuses a session recorded in another\n" +
			"folder because resuming would run its next tool call against the wrong tree,\n" +
			"these commands only read, so they report the session and name the folder it was\n" +
			"recorded in.\n\n" +
			"Use 'sessions list' to find a session: it lists the sessions recorded for the\n" +
			"current folder, or for every recorded folder with --all, newest first. Use\n" +
			"'sessions doctor' to surface recorded errors, failures, and anomalies,\n" +
			"'sessions show' to read the message, event, and compaction records in order with\n" +
			"tool-call arguments unescaped — narrowed with --kind, --turn, and --last, or\n" +
			"emitted machine-readably with --json — 'sessions permissions' to list the permission\n" +
			"prompts a human was shown with their decisions and the explicit revocation\n" +
			"requests, 'sessions research' to report the web searches, the sources fetched,\n" +
			"and which of them a later answer cited, and 'sessions summary' to aggregate the\n" +
			"durable execution records, the permission path scopes they ran under, and the\n" +
			"turn, round, and token totals.\n\n" +
			"EXAMPLES:\n" +
			"   codemeld sessions list [--all] [--json]          list recorded sessions, newest first\n" +
			"   codemeld sessions doctor <session-id|path>       report recorded errors, failures, and anomalies\n" +
			"   codemeld sessions show <session-id|path> [options]  read the message, event, and compaction records in order\n" +
			"   codemeld sessions permissions <session-id|path>  list the permission prompts shown, their decisions, and explicit revocation requests\n" +
			"   codemeld sessions research <session-id|path>     report the web searches, fetches, and cited sources\n" +
			"   codemeld sessions summary <session-id|path>      report the execution records, permission path scopes, turns, and tokens",
		Commands: []*ucli.Command{
			{
				Name:      "list",
				Usage:     "list recorded sessions for the current folder, or every recorded folder with --all",
				UsageText: "codemeld sessions list [--all] [--json]",
				Description: "List the sessions recorded for the current folder, newest first: the same\n" +
					"sessions 'codemeld --resume' offers. Pass --all to list the sessions of every\n" +
					"folder recorded under ~/.codemeld/sessions instead. It takes no arguments.\n\n" +
					"Each row shows the session's stored title, whether you set it or it was generated,\n" +
					"or its first message when it has no title (an empty name when it has neither),\n" +
					"then the full session id, the folder it was recorded in, and its\n" +
					"started and last-updated times (UTC). The title and folder are quoted, so text\n" +
					"containing newlines or control characters stays on one row. Rows are ordered by\n" +
					"last-updated time, newest first, then by id.\n\n" +
					"A session file whose first line cannot be read, or that belongs to another\n" +
					"folder, is skipped with a warning on stderr; run 'codemeld sessions doctor <id>'\n" +
					"against it to see why. With --all, a folder that\n" +
					"cannot be read is skipped with a warning, and when the same session id appears in\n" +
					"more than one folder only the most recently updated copy is listed and the\n" +
					"others are reported on stderr. Failing to read the current folder's session\n" +
					"directory, or with --all the sessions directory itself, is an error.\n\n" +
					"Pass --json to print a JSON array of objects with the keys name, id, folder,\n" +
					"started_at, and updated_at; it prints [] when there are no sessions, and\n" +
					"warnings still go to stderr. This command only reads: it never writes, locks,\n" +
					"prunes, or refreshes a session.",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: "all", Usage: "list the sessions of every recorded folder, not only the current one"},
					&ucli.BoolFlag{Name: "json", Usage: "emit a JSON array of session rows"},
				},
				Action: func(_ context.Context, c *ucli.Command) error {
					return runSessionsList(c.Args().Slice(), c.Bool("all"), c.Bool("json"), stdout, stderr)
				},
			},
			{
				Name:      "doctor",
				Usage:     "report a session's recorded errors, failures, and anomalies",
				UsageText: "codemeld sessions doctor <session-id|path> [--json]",
				ArgsUsage: "<session-id|path>",
				Description: "Scan a session and report every recorded error, failure, and anomaly event,\n" +
					"grouped by a derived severity (error, warning, info) and ending with a count\n" +
					"per severity. Each finding shows its kind, timestamp, and the event's typed\n" +
					"fields (phase, reason, error_category, error_detail, http_status, a non-zero\n" +
					"tool exit_code, model_response anomaly tokens, a slash-command error, and the\n" +
					"turn_id/round_id/outcome/failure_phase of a turn lifecycle record).\n\n" +
					"A failed tool call also names its subject_kind, invocation_id, and duration_ms,\n" +
					"and identifies the tool as failed_tool by program name only: the executable for\n" +
					"a direct run, the tool name for a structured or vcs_* run, and nothing at all\n" +
					"for an 'sh -c' literal, whose script cannot be reduced to a safe name. The\n" +
					"recorded command's arguments and its captured stdout and stderr are never\n" +
					"printed; use 'sessions show' for those.\n\n" +
					"Severity is derived, not stored: the *_failed events, provider_request_failed,\n" +
					"security_state_halted, and a non-zero tool exit code are errors; an unsupported\n" +
					"effort, a model_response anomaly, and a failed slash command are warnings; a\n" +
					"stream interruption is info.\n\n" +
					"A security_state_halted finding names the protected settings file and the point\n" +
					"the check ran (before_mutating_call, before_final_success, or startup). A startup\n" +
					"halt has no turn or round to close, so it is reported on its own; an in-turn halt\n" +
					"is reported with the security_halted turn_terminal that closed its round.\n\n" +
					"Two findings describe an incomplete agent turn. A turn_terminal recording any\n" +
					"outcome other than completed or cancelled is an error, named by its turn and\n" +
					"round. A provider round that carries a turn/round pair but that no turn_terminal\n" +
					"ever closed is an error too, reported as reason=incomplete_round: the round left a\n" +
					"durable timing record and then stopped. Neither is replayed or repaired — the\n" +
					"report only tells you which turn to look at. A round with no turn/round pair was\n" +
					"written before those fields existed and is never reported, and a request still in\n" +
					"flight has no round record yet, so an active session is clean.\n\n" +
					"It exits non-zero only when the session cannot be loaded or validated, never\n" +
					"because findings exist. Pass --json for a machine-readable report.",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: "json", Usage: "emit a machine-readable JSON report"},
				},
				Action: func(_ context.Context, c *ucli.Command) error {
					return runSessionsDoctor(c.Args().Slice(), c.Bool("json"), stdout)
				},
			},
			{
				Name:      "show",
				Usage:     "render a session's message, event, and compaction records in order",
				UsageText: "codemeld sessions show <session-id|path> [options]",
				ArgsUsage: "<session-id|path>",
				Description: "Print a session's message, event, and compaction records in order. Tool-call\n" +
					"arguments are stored as a verbatim escaped JSON string so they round-trip to the\n" +
					"provider unchanged; this command unescapes and indents them for display only, and\n" +
					"does not change how they are stored. Arguments that are not valid JSON are shown\n" +
					"raw and flagged rather than failing the command.\n\n" +
					"A compacted child session starts with a compaction record: its full summary is\n" +
					"printed with the generation provider/model and the stamped parent record id, and\n" +
					"the header shows the metadata fork origin so the stored source link can be\n" +
					"compared with record zero. The parent session is never opened or traversed.\n\n" +
					"A whole session is usually far more than you want to read, so four options narrow\n" +
					"it. --kind <event-kind> keeps only event records of that kind and can be repeated\n" +
					"to keep several; it never matches messages or compactions, which carry no kind.\n" +
					"--turn <turn-id> selects one agent turn: every record from the user message that\n" +
					"opened it through the turn_terminal that closed it, so the turn's messages and\n" +
					"tool activity come along even though only its lifecycle records carry the id.\n" +
					"--last <n> keeps the final n records after the other filters. --json emits the\n" +
					"selected records machine-readably, with tool-call arguments unescaped into JSON\n" +
					"values and an argument that is not valid JSON carried raw with the same invalid\n" +
					"flag the printed form uses.\n\n" +
					"Each skill load is a skill_loaded event: the skill name, its layer (global or\n" +
					"project), how it was loaded (tool or slash), the file read (empty for SKILL.md),\n" +
					"and the byte count and SHA-256 digest of the loaded content, never the text\n" +
					"itself. --kind skill_loaded lists only the skill loads.\n\n" +
					"The filters compose in one invocation, and a record keeps the number of its\n" +
					"position in the whole session. Whenever a filter is active the header reads\n" +
					"'records: <selected> of <total>', so a filter that matched nothing is visibly a\n" +
					"filter result rather than an empty session, and exits 0. An unknown kind, a\n" +
					"--turn that is not a well-formed turn id, and a --last below 1 are usage errors;\n" +
					"a valid turn id the session never recorded simply selects nothing.",
				Flags: []ucli.Flag{
					&ucli.StringSliceFlag{Name: "kind", Usage: "keep only event records of this kind; repeatable"},
					&ucli.StringFlag{Name: "turn", Usage: "keep the complete record range of the turn with this id"},
					&ucli.IntFlag{Name: "last", Usage: "keep only the last n records after the other filters"},
					&ucli.BoolFlag{Name: "json", Usage: "emit a machine-readable JSON report"},
				},
				Action: func(_ context.Context, c *ucli.Command) error {
					return runSessionsShow(c.Args().Slice(), showOptions{
						kinds:   c.StringSlice("kind"),
						turn:    c.String("turn"),
						turnSet: c.IsSet("turn"),
						last:    c.Int("last"),
						lastSet: c.IsSet("last"),
						asJSON:  c.Bool("json"),
					}, stdout)
				},
			},
			{
				Name:      "permissions",
				Usage:     "list the permission prompts a human was shown, their decisions, and the explicit revocation requests",
				UsageText: "codemeld sessions permissions <session-id|path> [--json]",
				ArgsUsage: "<session-id|path>",
				Description: "List every permission prompt the session actually showed a human, in record\n" +
					"order, with its decision — granted, denied, or pending when no decision was\n" +
					"recorded. Each prompt takes the next decision recorded for the same subject\n" +
					"kind, subject, and request scope, so repeated identical prompts are answered in\n" +
					"the order they were shown and an earlier decision never satisfies a later prompt.\n\n" +
					"A granted prompt also says what the approval stored. 'grant=allow_once' means the\n" +
					"user approved that one call and nothing was written; otherwise the row names the\n" +
					"stored grant kind (session, folder, or global for a path subject; session or\n" +
					"project for a host subject), the folder or host it was stored at, and the subject\n" +
					"actually stored, which can be wider than the one requested. A global grant is\n" +
					"named by its kind alone, because it is stored against all paths rather than a\n" +
					"folder.\n\n" +
					"A prompt is flagged as a scope escalation when it asks for a folder that strictly\n" +
					"contains a folder an earlier decision in the same session already granted, and\n" +
					"that earlier stored subject covers this request under the same rule live matching\n" +
					"uses; the narrowest such earlier grant is named. An older record that is missing\n" +
					"the stored grant subject, or a direct command's tokens, is left unflagged rather\n" +
					"than guessed at.\n\n" +
					"Authorizations that never reached a human — an existing grant, an in-turn cache\n" +
					"hit, a mode posture, a run's declared file scope, a project's declared\n" +
					"command-list hit, or a read of an explicitly named path allowed without asking —\n" +
					"are never listed as prompts. They are counted at the end by their source (grant,\n" +
					"cache, mode_auto, declared_scope, declared_command, open_read, confined,\n" +
					"system_one_check) so the prompt count has a denominator.\n\n" +
					"Refusals made before any approval, by a blocked path (blocked_path) or a protected\n" +
					"settings file (protected_state), are counted at the end by source, apart from the\n" +
					"non-prompted authorizations.\n\n" +
					"System One checks, where a configured model judged a prompted shell command,\n" +
					"are counted by outcome (allowed, declined, failed, skipped). Failed checks are\n" +
					"broken down by reason, and skipped checks by reason too: paused, when an earlier\n" +
					"credits or authentication failure paused the check for the session, or a\n" +
					"structural reason (text, blocked_paths_unavailable, substitution, blocked_path,\n" +
					"wrapper, program_location, shell_shape) when the command could not qualify and\n" +
					"no model was asked. Each allowed command is listed with its model, p_read_only,\n" +
					"and the t_read_only threshold applied, so its margin can be reviewed. An allowed\n" +
					"check is counted once among the non-prompted authorizations, under\n" +
					"system_one_check.\n\n" +
					"The report ends with the explicit revocation requests: the grants a human removed\n" +
					"through the /settings revoke control, each naming the stored grant's own kind,\n" +
					"subject, scope, and grant kind. These are read only from recorded revocation\n" +
					"events, never inferred from a settings file that no longer holds a grant, so a\n" +
					"session that recorded none reports zero. A recorded request means /settings saw\n" +
					"the grant and asked for it to be deleted; it is not proof that this run is what\n" +
					"removed it from disk, and a revoke whose recording failed leaves no event at all.\n\n" +
					"This is a historical read of one session file, never a live authorization\n" +
					"decision. Pass --json for the same facts machine-readably. The report prints\n" +
					"session content verbatim, so its output is as sensitive as the session file\n" +
					"itself.",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: "json", Usage: "emit a machine-readable JSON report"},
				},
				Action: func(_ context.Context, c *ucli.Command) error {
					return runSessionsPermissions(c.Args().Slice(), c.Bool("json"), stdout)
				},
			},
			{
				Name:      "research",
				Usage:     "report the web searches, the sources fetched, and which of them a later answer cited",
				UsageText: "codemeld sessions research <session-id|path> [--json]",
				ArgsUsage: "<session-id|path>",
				Description: "Report what the session recorded about web research, in record order: every\n" +
					"web_search and web_fetch tool call, the query or address it carried, the\n" +
					"candidate addresses a search returned, the outcome of each fetch, and the\n" +
					"addresses a later visible answer quoted exactly. It ends with totals: searches,\n" +
					"total and unique queries, total and unique candidate addresses, candidates a\n" +
					"later fetch actually read, fetch outcomes, cited addresses, and how many web\n" +
					"permission prompts were shown across how many distinct hosts.\n\n" +
					"Each address is labelled with the stages the file supports: 'candidate' (a\n" +
					"search returned it), 'selected' (a later web_fetch asked for that exact\n" +
					"address), 'retrieved' or 'failed' (what the fetch recorded), and 'cited' (that\n" +
					"exact address appears in a later visible assistant answer). Uncited does not\n" +
					"mean unused: an address with no 'cited' label is NOT evidence that the model\n" +
					"ignored it — the session records what was called and what was answered, never\n" +
					"why. Nothing here is a judgement about the model's reasoning.\n\n" +
					"Older sessions searched and fetched in one step, returning a bundle of already\n" +
					"read sources. Those are reported as legacy auto-fetches with their recorded\n" +
					"outcomes, so an existing session stays readable without being converted.\n\n" +
					"Tool arguments and results are opaque stored text. One that is not readable\n" +
					"JSON is reported as unclassified evidence rather than guessed at, and never\n" +
					"fails the command. This is a historical read of one file: it writes no rating,\n" +
					"annotation, or event back. It prints the queries and addresses stored in the\n" +
					"session verbatim, so its output is as sensitive as the session file itself.\n\n" +
					"Pass --json for the same facts as one machine-readable document.",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: "json", Usage: "emit a machine-readable JSON report"},
				},
				Action: func(_ context.Context, c *ucli.Command) error {
					return runSessionsResearch(c.Args().Slice(), c.Bool("json"), stdout)
				},
			},
			{
				Name:      "summary",
				Usage:     "report a session's execution records, permission path scopes, turns, and tokens, and its current execution capability",
				UsageText: "codemeld sessions summary <session-id|path> [--json]",
				ArgsUsage: "<session-id|path>",
				Description: "Aggregate what a finished run recorded: which calls executed, which permission\n" +
					"scopes they ran under, and how many turns, rounds, and tokens the providers\n" +
					"took. Every number is derived from records the session already stores.\n\n" +
					"The report opens with the session's current execution capability, taken from\n" +
					"the last execution_capability record: constrained, refused with its refusal\n" +
					"reason, or not recorded when the session stored none.\n" +
					"constrained means the startup sandbox check passed, so plan and auto-edits shell\n" +
					"commands could run sandboxed with fewer prompts; refused carries the reason they\n" +
					"could not. A refusal for a broken settings file after a passed check still kept plan\n" +
					"and auto-edits commands sandboxed but made every command ask; a failed or unsupported\n" +
					"check ran them outside the sandbox with ordinary prompts. Neither value describes\n" +
					"build mode, which always runs commands outside the sandbox.\n\n" +
					"Execution is reported as two separately labelled classes, because the file keeps\n" +
					"two distinct durable lifecycles. tool_exec_end covers shell and vcs execution and\n" +
					"ends in an exit code, so its rows count invocations, non-zero-exit failures, and\n" +
					"total duration per subject_kind/subject. structured_read_end covers the six\n" +
					"allowlisted read tools (read, glob, grep, list, tree, file_count) and ends in a\n" +
					"closed outcome instead, so its rows count invocations, non-success outcomes, the\n" +
					"outcome breakdown, and total duration per tool. Every OTHER structured tool call\n" +
					"records no durable start/end pair at all: it is absent from both tables rather\n" +
					"than counted as zero, so this is an execution-record summary, not a complete\n" +
					"table of every tool the model called.\n\n" +
					"The path-scope table is built from tool_exec_start and structured_read_start and\n" +
					"lists the permission scopes those calls were authorized against — for a tool\n" +
					"subject that is a directory, never a file. A session does NOT record which files\n" +
					"were edited: the exact path lives only inside a tool call's stored arguments, and\n" +
					"this command does not decode those. Read the table as 'these scopes were\n" +
					"authorized', never as 'these files changed'. A scope's start count can also\n" +
					"exceed the matching execution table's invocation count, because the start is\n" +
					"recorded before the call runs and a process that stopped mid-call leaves a start\n" +
					"with no end.\n\n" +
					"Totals count distinct turns as the union of the turn ids on provider_round_trip\n" +
					"and turn_terminal, and count a round only from a provider_round_trip carrying\n" +
					"both a turn id and a round id. A counted round a turn_terminal closed is\n" +
					"terminated whatever that outcome was — a cancelled or provider-failed round is\n" +
					"terminated too, so terminated is not a success count; one with no matching\n" +
					"terminal is incomplete, the same rounds 'sessions doctor' reports as\n" +
					"reason=incomplete_round. A legacy round trip carrying neither id is counted in\n" +
					"neither and contributes only its duration and provider/model pair. Provider/model\n" +
					"pairs are the de-duplicated union of provider_round_trip and model_response, so a\n" +
					"session recorded before round trips existed still shows what it ran on.\n\n" +
					"Input and output tokens are summed from model_response. Cached input tokens are\n" +
					"reported as availability, not as a bare number: an absent cached_input_tokens\n" +
					"means the provider did not report it, so the total is exact only when every\n" +
					"contributing response reported a non-partial value, a lower bound when any\n" +
					"response omitted it or marked it partial, and unavailable when none reported it.\n" +
					"Provider-reported cost (cost_usd) is summed and reported the same way, scoped to\n" +
					"the recorded responses: exact only when every recorded response reported a\n" +
					"non-partial cost. Cost is assumed to be USD, following OpenRouter's convention;\n" +
					"every provider's reported cost is summed and its currency is neither verified\n" +
					"nor converted.\n\n" +
					"The approval_* totals measure time spent waiting on permission prompts, from\n" +
					"permission_prompt_wait records. approval_wait_ms is the length of the union of the\n" +
					"recorded wait intervals, so overlapping waits are counted once, not summed.\n" +
					"approval_requests sums the requests submitted to each prompt call; it is not a\n" +
					"count of questions shown, since one question can cover several requests.\n" +
					"approval_waits_cancelled counts cancelled waits. Failed waits count toward both\n" +
					"totals and have no separate failure count, so a wait that was not cancelled was\n" +
					"not necessarily answered. With no wait records all three are 0 and the text\n" +
					"report omits the permission-prompt wait line; that means no wait was recorded,\n" +
					"not that none happened.\n\n" +
					"A session with no execution records, no rounds, or no model responses reports\n" +
					"zeroes and exits 0. This is a read-only historical read of one file: it writes,\n" +
					"locks, and repairs nothing. It prints stored subjects and path scopes verbatim,\n" +
					"so its output is as sensitive as the session file itself.\n\n" +
					"Pass --json for the same facts as one machine-readable document.",
				Flags: []ucli.Flag{
					&ucli.BoolFlag{Name: "json", Usage: "emit a machine-readable JSON report"},
				},
				Action: func(_ context.Context, c *ucli.Command) error {
					return runSessionsSummary(c.Args().Slice(), c.Bool("json"), stdout)
				},
			},
		},
		Action: func(_ context.Context, c *ucli.Command) error {
			if c.Args().Present() {
				return ucli.Exit(
					fmt.Sprintf("codemeld: unknown sessions subcommand %q; use 'codemeld sessions list', 'codemeld sessions doctor', 'codemeld sessions show', 'codemeld sessions permissions', 'codemeld sessions research', or 'codemeld sessions summary'", c.Args().First()),
					2,
				)
			}
			return ucli.Exit("codemeld: sessions requires a subcommand; use 'codemeld sessions list', 'codemeld sessions doctor', 'codemeld sessions show', 'codemeld sessions permissions', 'codemeld sessions research', or 'codemeld sessions summary'", 2)
		},
	}
}

// runSessionsDoctor resolves the target, builds the diagnostics report, and
// renders it (JSON when asJSON). A load/validation failure exits non-zero with
// the typed loader message; findings never change the exit code.
func runSessionsDoctor(args []string, asJSON bool, stdout io.Writer) error {
	target, err := singleTarget(args, "doctor")
	if err != nil {
		return err
	}
	path, sess, err := resolveSession(target)
	if err != nil {
		return err
	}
	report := buildDoctorReport(path, sess)
	if asJSON {
		return renderJSON(stdout, report)
	}
	renderDoctorHuman(stdout, report)
	return nil
}

func runSessionsShow(args []string, opts showOptions, stdout io.Writer) error {
	target, err := singleTarget(args, "show")
	if err != nil {
		return err
	}
	if err := opts.validate(); err != nil {
		return err
	}
	path, sess, err := resolveSession(target)
	if err != nil {
		return err
	}
	selected := selectShowRecords(sess.Records, opts)
	if opts.asJSON {
		return renderJSON(stdout, buildShowReport(path, sess, selected, opts.filtering()))
	}
	renderShow(stdout, path, sess, selected, opts.filtering())
	return nil
}

func runSessionsResearch(args []string, asJSON bool, stdout io.Writer) error {
	target, err := singleTarget(args, "research")
	if err != nil {
		return err
	}
	path, sess, err := resolveSession(target)
	if err != nil {
		return err
	}
	report := buildResearchReport(path, sess)
	if asJSON {
		return renderJSON(stdout, report)
	}
	renderResearchHuman(stdout, report)
	return nil
}

func runSessionsPermissions(args []string, asJSON bool, stdout io.Writer) error {
	target, err := singleTarget(args, "permissions")
	if err != nil {
		return err
	}
	path, sess, err := resolveSession(target)
	if err != nil {
		return err
	}
	report := buildPermissionsReport(path, sess)
	if asJSON {
		return renderJSON(stdout, report)
	}
	renderPermissions(stdout, report)
	return nil
}

type listRow struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Folder    string `json:"folder"`
	StartedAt string `json:"started_at"`
	UpdatedAt string `json:"updated_at"`
}

func runSessionsList(args []string, all, asJSON bool, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		return ucli.Exit(fmt.Sprintf("codemeld: sessions list accepts no arguments; got %d", len(args)), 2)
	}
	home, err := resolveHome()
	if err != nil {
		return ucli.Exit("codemeld: cannot resolve home directory: "+paths.FormatHomeError(err), 1)
	}

	var entries []sessions.ListEntry
	var warnings []string
	empty := "no sessions found"
	if all {
		list, skips, lerr := sessions.ListResumableAll(home)
		if lerr != nil {
			return ucli.Exit(lerr.Error(), 1)
		}
		entries = list
		for _, s := range skips {
			switch {
			case s.Duplicate:
				warnings = append(warnings, fmt.Sprintf("discarded duplicate session %q from folder %q", s.ID, s.Folder))
			case s.Folder == "":
				warnings = append(warnings, fmt.Sprintf("skipped folder %q (unreadable)", s.Dir))
			default:
				warnings = append(warnings, fmt.Sprintf("skipped session %q in folder %q (unreadable or unparseable)", s.ID, s.Folder))
			}
		}
	} else {
		empty = "no sessions found for this folder"
		cwd, gerr := osGetwd()
		if gerr != nil {
			return ucli.Exit(fmt.Sprintf("codemeld: cannot determine working directory: %s", gerr), 1)
		}
		canonical, cerr := sessions.CanonicalizeFolder(cwd)
		if cerr != nil {
			return ucli.Exit(fmt.Sprintf("codemeld: sessions list: cannot resolve working directory %s: %s", cwd, cerr), 1)
		}
		list, skipped, lerr := sessions.ListResumable(home, canonical)
		if lerr != nil {
			return ucli.Exit(lerr.Error(), 1)
		}
		entries = list
		for _, s := range skipped {
			warnings = append(warnings, fmt.Sprintf("skipped session %q in folder %q (unreadable or unparseable)", s.ID, canonical))
		}
	}

	for _, w := range warnings {
		_, _ = fmt.Fprintln(stderr, "codemeld: sessions list: "+w)
	}

	rows := make([]listRow, 0, len(entries))
	for _, e := range entries {
		name := e.Title
		if name == "" {
			name = e.Preview
		}
		rows = append(rows, listRow{
			Name:      name,
			ID:        e.ID,
			Folder:    e.Folder,
			StartedAt: formatTimestamp(e.StartedAt),
			UpdatedAt: formatTimestamp(e.UpdatedAt),
		})
	}
	if asJSON {
		return renderJSON(stdout, rows)
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(stdout, empty)
		return err
	}
	for _, r := range rows {
		id := r.ID
		if q := strconv.Quote(id); q != `"`+id+`"` {
			id = q
		}
		if _, err := fmt.Fprintf(stdout, "%q  %s  folder=%q  started=%s  updated=%s\n", r.Name, id, r.Folder, r.StartedAt, r.UpdatedAt); err != nil {
			return err
		}
	}
	return nil
}

// singleTarget requires exactly one positional <session-id|path> argument,
// returning a usage error (exit 2) otherwise.
func singleTarget(args []string, sub string) (string, error) {
	switch len(args) {
	case 1:
		return args[0], nil
	case 0:
		return "", ucli.Exit(fmt.Sprintf("codemeld: sessions %s requires a session id or file path", sub), 2)
	default:
		return "", ucli.Exit(
			fmt.Sprintf("codemeld: sessions %s accepts exactly one session id or file path; got %d", sub, len(args)),
			2,
		)
	}
}

// resolveSession loads the session named by target and returns its file path and
// parsed records. A value that is a valid session id goes through the --resume
// resolver, but a folder mismatch is not a refusal here: these readers take no
// lock and append nothing, so the located session is read wherever it was
// recorded. Anything else is loaded directly as a file path. Every failure is
// returned already wrapped as a ucli.Exit (status 1) carrying the existing typed
// loader message.
func resolveSession(target string) (string, *sessions.Session, error) {
	if ids.IsValidV7(target) {
		home, err := resolveHome()
		if err != nil {
			return "", nil, ucli.Exit("codemeld: cannot resolve home directory: "+paths.FormatHomeError(err), 1)
		}
		cwd, err := osGetwd()
		if err != nil {
			return "", nil, ucli.Exit(fmt.Sprintf("codemeld: cannot determine working directory: %s", err), 1)
		}
		path, sess, rerr := sessions.ResolveResumeID(target, cwd, home, events.ValidatePayload)
		if rerr != nil {
			located, mismatch := mismatchedFolderPath(rerr)
			if !mismatch {
				return "", nil, ucli.Exit(rerr.Error(), 1)
			}
			sess, lerr := loadByPath(located)
			if lerr != nil {
				return "", nil, ucli.Exit(lerr.Error(), 1)
			}
			return located, sess, nil
		}
		return path, sess, nil
	}
	sess, err := loadByPath(target)
	if err != nil {
		return "", nil, ucli.Exit(err.Error(), 1)
	}
	return target, sess, nil
}

// mismatchedFolderPath returns the session file a resume resolution located when
// it failed only because the session belongs to another folder.
func mismatchedFolderPath(err error) (string, bool) {
	var wrong *sessions.ResumeWrongFolderError
	if errors.As(err, &wrong) {
		return wrong.Path, true
	}
	var cwd *sessions.ResumeCWDMismatchError
	if errors.As(err, &cwd) {
		return cwd.Path, true
	}
	return "", false
}

// loadByPath loads an explicit session file through the standard loader and the
// same validators the resume path runs, never the resume folder/CWD checks. It
// surfaces the loader's typed version refusal verbatim and renders not-found /
// parse / validation failures as codemeld-prefixed messages.
func loadByPath(path string) (*sessions.Session, error) {
	sess, _, err := sessions.OpenSession(path)
	if err != nil {
		var ve *sessions.VersionError
		if errors.As(err, &ve) {
			return nil, ve // already codemeld-prefixed; names the file and the version mismatch
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("codemeld: session file %s not found", path)
		}
		return nil, fmt.Errorf("codemeld: session %s cannot be parsed: %s", path, err)
	}
	if verr := sessions.ValidateRecordStream(sess.Records); verr != nil {
		return nil, fmt.Errorf("codemeld: session %s cannot be loaded: %s", path, verr)
	}
	if perr := sessions.ValidateEventPayloads(sess.Records, events.ValidatePayload); perr != nil {
		return nil, fmt.Errorf("codemeld: session %s cannot be loaded: %s", path, perr)
	}
	return sess, nil
}

// --- doctor report ----------------------------------------------------------

// summaryCounts is the per-severity finding count rendered at the end of a doctor
// report. The field order is the severity order (most to least serious).
type summaryCounts struct {
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
}

// finding is one reported error/failure/anomaly event: its kind, derived
// severity, timestamp, and the typed fields meaningful for that kind. All detail
// fields are omitempty so a finding only carries the fields its kind populates.
type finding struct {
	Kind             string   `json:"kind"`
	Severity         string   `json:"severity"`
	Timestamp        string   `json:"timestamp"`
	Phase            string   `json:"phase,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	Path             string   `json:"path,omitempty"`
	DetectionPoint   string   `json:"detection_point,omitempty"`
	Outcome          string   `json:"outcome,omitempty"`
	FailurePhase     string   `json:"failure_phase,omitempty"`
	FailureReason    string   `json:"failure_reason,omitempty"`
	FailedTool       string   `json:"failed_tool,omitempty"`
	SubjectKind      string   `json:"subject_kind,omitempty"`
	InvocationID     string   `json:"invocation_id,omitempty"`
	TurnID           string   `json:"turn_id,omitempty"`
	RoundID          string   `json:"round_id,omitempty"`
	ConfiguredEffort string   `json:"configured_effort,omitempty"`
	Source           string   `json:"source,omitempty"`
	Name             string   `json:"name,omitempty"`
	ErrorCategory    string   `json:"error_category,omitempty"`
	HTTPStatus       *int64   `json:"http_status,omitempty"`
	DurationMs       *int64   `json:"duration_ms,omitempty"`
	ExitCode         *int64   `json:"exit_code,omitempty"`
	Anomalies        []string `json:"anomalies,omitempty"`
	ErrorDetail      string   `json:"error_detail,omitempty"`
}

// doctorReport is the full read-only diagnostics report for one session.
type doctorReport struct {
	Session  string        `json:"session"`
	Folder   string        `json:"folder"`
	Findings []finding     `json:"findings"`
	Summary  summaryCounts `json:"summary"`
}

func classifyFinding(ev sessions.Event) (sev string, isFinding bool) {
	switch ev.Kind {
	case events.KindSessionWriteFailed,
		events.KindPermissionPersistFailed,
		events.KindModelRecoveryFailed,
		events.KindModelPersistFailed,
		events.KindModelGlobalMirrorFailed,
		events.KindProviderRequestFailed,
		events.KindSecurityStateHalted:
		return sevError, true
	case events.KindTurnTerminal:
		if terminalFailed(ev.Payload) {
			return sevError, true
		}
		return "", false
	case events.KindModelEffortUnsupported:
		return sevWarning, true
	case events.KindSlashCommand:
		if slashFailed(ev.Payload) {
			return sevWarning, true
		}
		return "", false
	case events.KindModelResponse:
		if len(modelAnomalies(ev.Payload)) > 0 {
			return sevWarning, true
		}
		return "", false
	case events.KindStreamInterrupted:
		return sevInfo, true
	default:
		return "", false
	}
}

// toolExecFinding reports a failed tool invocation. Stdout and Stderr are
// arbitrary captured output — keys, tokens, file contents — so they are
// deliberately left out of the finding.
func toolExecFinding(ev sessions.Event) (finding, bool) {
	var p events.ToolExecEnd
	if err := json.Unmarshal(ev.Payload, &p); err != nil || p.ExitCode == 0 {
		return finding{}, false
	}
	code, duration := p.ExitCode, p.DurationMs
	return finding{
		Kind:         ev.Kind,
		Severity:     sevError,
		Timestamp:    formatTimestamp(ev.Timestamp),
		FailedTool:   boundedToolName(p.SubjectKind, p.Subject),
		SubjectKind:  p.SubjectKind,
		InvocationID: p.InvocationID,
		DurationMs:   &duration,
		ExitCode:     &code,
	}, true
}

// boundedToolName reduces a recorded tool_exec_end subject to a name that cannot
// carry arguments. A direct subject is the joined argv, whose first token is the
// program; a tool subject is already a bare tool name. A literal subject is an
// arbitrary `sh -c` script whose first word may be an assignment, a builtin, or
// punctuation, so no name is derived from it at all.
func boundedToolName(subjectKind, subject string) string {
	switch subjectKind {
	case subjectKindTool:
		return subject
	case subjectKindDirect:
		if fields := strings.Fields(subject); len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

var terminalFailureOutcomes = map[string]bool{
	events.TurnOutcomeProviderFailed:     true,
	events.TurnOutcomeInvalidResponse:    true,
	events.TurnOutcomeToolAssemblyFailed: true,
	events.TurnOutcomeToolPlanInvalid:    true,
	events.TurnOutcomeDispatchFailed:     true,
	events.TurnOutcomeContinuationFailed: true,
	events.TurnOutcomeSecurityHalted:     true,
}

func terminalFailed(payload json.RawMessage) bool {
	var p events.TurnTerminal
	if err := json.Unmarshal(payload, &p); err != nil {
		return false
	}
	return terminalFailureOutcomes[p.Outcome]
}

// slashFailed reports whether a slash_command event recorded an error outcome.
func slashFailed(payload json.RawMessage) bool {
	var p events.SlashCommand
	if err := json.Unmarshal(payload, &p); err != nil {
		return false
	}
	return p.Outcome == "error"
}

// modelAnomalies returns a model_response event's anomaly tokens.
func modelAnomalies(payload json.RawMessage) []string {
	var p events.ModelResponse
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil
	}
	return p.Anomaly
}

type roundKey struct {
	turnID  string
	roundID string
}

func buildDoctorReport(path string, sess *sessions.Session) doctorReport {
	r := doctorReport{Session: path, Folder: sess.Metadata.Folder, Findings: []finding{}}
	terminated := terminatedRounds(sess)
	for _, rec := range sess.Records {
		ev, ok := rec.(sessions.Event)
		if !ok {
			continue
		}
		f, isFinding := findingFor(ev, terminated)
		if !isFinding {
			continue
		}
		r.Findings = append(r.Findings, f)
		switch f.Severity {
		case sevError:
			r.Summary.Error++
		case sevWarning:
			r.Summary.Warning++
		case sevInfo:
			r.Summary.Info++
		}
	}
	return r
}

func findingFor(ev sessions.Event, terminated map[roundKey]bool) (finding, bool) {
	switch ev.Kind {
	case events.KindProviderRoundTrip:
		return incompleteRoundFinding(ev, terminated)
	case events.KindToolExecEnd:
		return toolExecFinding(ev)
	}
	sev, isFinding := classifyFinding(ev)
	if !isFinding {
		return finding{}, false
	}
	return toFinding(ev, sev), true
}

func terminatedRounds(sess *sessions.Session) map[roundKey]bool {
	rounds := map[roundKey]bool{}
	for _, rec := range sess.Records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindTurnTerminal {
			continue
		}
		var p events.TurnTerminal
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		rounds[roundKey{p.TurnID, p.RoundID}] = true
	}
	return rounds
}

func incompleteRoundFinding(ev sessions.Event, terminated map[roundKey]bool) (finding, bool) {
	var p events.ProviderRoundTrip
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return finding{}, false
	}
	if p.TurnID == "" || p.RoundID == "" || terminated[roundKey{p.TurnID, p.RoundID}] {
		return finding{}, false
	}
	return finding{
		Kind:      ev.Kind,
		Severity:  sevError,
		Timestamp: formatTimestamp(ev.Timestamp),
		Reason:    reasonIncompleteRound,
		TurnID:    p.TurnID,
		RoundID:   p.RoundID,
	}, true
}

// toFinding decodes the typed fields a given finding kind carries. The session
// has already passed payload validation, so the decodes do not fail in practice;
// a decode miss simply leaves the optional fields empty.
func toFinding(ev sessions.Event, sev string) finding {
	f := finding{Kind: ev.Kind, Severity: sev, Timestamp: formatTimestamp(ev.Timestamp)}
	switch ev.Kind {
	case events.KindProviderRequestFailed:
		var p events.ProviderRequestFailed
		_ = json.Unmarshal(ev.Payload, &p)
		f.Phase, f.Reason, f.ErrorDetail, f.HTTPStatus = p.Phase, p.Reason, p.ErrorDetail, p.HTTPStatus
	case events.KindSessionWriteFailed:
		var p events.SessionWriteFailed
		_ = json.Unmarshal(ev.Payload, &p)
		f.Reason, f.ErrorCategory, f.ErrorDetail = p.Reason, p.ErrorCategory, p.ErrorDetail
	case events.KindPermissionPersistFailed:
		var p events.PermissionPersistFailed
		_ = json.Unmarshal(ev.Payload, &p)
		f.Reason, f.ErrorCategory, f.ErrorDetail = p.Reason, p.ErrorCategory, p.ErrorDetail
	case events.KindModelRecoveryFailed:
		var p events.ModelRecoveryFailed
		_ = json.Unmarshal(ev.Payload, &p)
		f.Reason, f.ErrorDetail = p.Reason, p.ErrorDetail
	case events.KindModelPersistFailed:
		var p events.ModelPersistFailed
		_ = json.Unmarshal(ev.Payload, &p)
		f.Reason, f.ErrorCategory, f.ErrorDetail = p.Reason, p.ErrorCategory, p.ErrorDetail
	case events.KindModelGlobalMirrorFailed:
		var p events.ModelGlobalMirrorFailed
		_ = json.Unmarshal(ev.Payload, &p)
		f.Reason, f.ErrorCategory, f.ErrorDetail = p.Reason, p.ErrorCategory, p.ErrorDetail
	case events.KindModelEffortUnsupported:
		var p events.ModelEffortUnsupported
		_ = json.Unmarshal(ev.Payload, &p)
		f.ConfiguredEffort = p.ConfiguredEffort
	case events.KindModelResponse:
		var p events.ModelResponse
		_ = json.Unmarshal(ev.Payload, &p)
		f.Anomalies = p.Anomaly
	case events.KindSlashCommand:
		var p events.SlashCommand
		_ = json.Unmarshal(ev.Payload, &p)
		f.Name, f.ErrorDetail = p.Name, p.ErrorDetail
	case events.KindStreamInterrupted:
		var p events.StreamInterrupted
		_ = json.Unmarshal(ev.Payload, &p)
		f.Source = p.Source
	case events.KindSecurityStateHalted:
		var p events.SecurityStateHalted
		_ = json.Unmarshal(ev.Payload, &p)
		// The settings path is the only free-form value a halt record carries, and the
		// human report is line-oriented, so it cannot forge lines of its own.
		f.Path, f.DetectionPoint = fserrors.CollapseControls(p.Path), p.DetectionPoint
	case events.KindTurnTerminal:
		var p events.TurnTerminal
		_ = json.Unmarshal(ev.Payload, &p)
		f.Outcome, f.FailurePhase, f.TurnID, f.RoundID = p.Outcome, p.FailurePhase, p.TurnID, p.RoundID
		f.FailureReason, f.FailedTool = p.FailureReason, p.FailedTool
	}
	return f
}

// renderDoctorHuman writes the human-readable doctor report: a header, one line
// per finding, and the per-severity summary. A clean session says so.
func renderDoctorHuman(w io.Writer, r doctorReport) {
	fmt.Fprintf(w, "session: %s\n", r.Session)
	fmt.Fprintf(w, "folder: %s\n", r.Folder)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "no errors, failures, or anomalies found")
		return
	}
	fmt.Fprintf(w, "findings: %d (error: %d, warning: %d, info: %d)\n\n",
		len(r.Findings), r.Summary.Error, r.Summary.Warning, r.Summary.Info)
	for _, f := range r.Findings {
		line := fmt.Sprintf("  [%s] %s  %s", f.Severity, f.Kind, f.Timestamp)
		if detail := findingDetail(f); detail != "" {
			line += "  " + detail
		}
		fmt.Fprintln(w, line)
	}
}

// findingDetail renders a finding's populated typed fields as a space-separated
// key=value string, in a stable order, with error_detail quoted last.
func findingDetail(f finding) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("phase", f.Phase)
	add("reason", f.Reason)
	add("path", f.Path)
	add("detection_point", f.DetectionPoint)
	add("outcome", f.Outcome)
	add("failure_phase", f.FailurePhase)
	add("failure_reason", f.FailureReason)
	add("failed_tool", f.FailedTool)
	add("subject_kind", f.SubjectKind)
	add("invocation_id", f.InvocationID)
	add("turn_id", f.TurnID)
	add("round_id", f.RoundID)
	add("configured_effort", f.ConfiguredEffort)
	add("source", f.Source)
	add("name", f.Name)
	add("error_category", f.ErrorCategory)
	if f.HTTPStatus != nil {
		parts = append(parts, fmt.Sprintf("http_status=%d", *f.HTTPStatus))
	}
	if f.DurationMs != nil {
		parts = append(parts, fmt.Sprintf("duration_ms=%d", *f.DurationMs))
	}
	if f.ExitCode != nil {
		parts = append(parts, fmt.Sprintf("exit_code=%d", *f.ExitCode))
	}
	if len(f.Anomalies) > 0 {
		parts = append(parts, "anomaly="+strings.Join(f.Anomalies, ","))
	}
	if f.ErrorDetail != "" {
		parts = append(parts, fmt.Sprintf("error_detail=%q", f.ErrorDetail))
	}
	return strings.Join(parts, " ")
}

func renderJSON(w io.Writer, report any) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// --- permissions report ------------------------------------------------------

const (
	outcomeGranted = "granted"
	outcomeDenied  = "denied"
	outcomePending = "pending"
)

const (
	subjectKindDirect = "direct"
	subjectKindHost   = "host"
	subjectKindTool   = "tool"
	grantKindGlobal   = "global"
)

type grantRecord struct {
	Stored    bool   `json:"stored"`
	Kind      string `json:"kind,omitempty"`
	PathScope string `json:"path_scope,omitempty"`
	HostScope string `json:"host_scope,omitempty"`
	Subject   string `json:"subject,omitempty"`
}

type scopeEscalation struct {
	GrantPathScope string `json:"grant_path_scope"`
	GrantSubject   string `json:"grant_subject"`
}

type promptRow struct {
	SubjectKind string           `json:"subject_kind"`
	Subject     string           `json:"subject"`
	Scope       string           `json:"scope"`
	Outcome     string           `json:"outcome"`
	Grant       *grantRecord     `json:"grant,omitempty"`
	Escalation  *scopeEscalation `json:"scope_escalation,omitempty"`
}

type nonPromptedCounts struct {
	Grant           int `json:"grant"`
	Cache           int `json:"cache"`
	ModeAuto        int `json:"mode_auto"`
	DeclaredScope   int `json:"declared_scope"`
	DeclaredCommand int `json:"declared_command"`
	OpenRead        int `json:"open_read"`
	Confined        int `json:"confined"`
	SystemOneCheck  int `json:"system_one_check"`
}

func (c nonPromptedCounts) total() int {
	return c.Grant + c.Cache + c.ModeAuto + c.DeclaredScope + c.DeclaredCommand + c.OpenRead + c.Confined + c.SystemOneCheck
}

type systemOneOutcomeCounts struct {
	Allowed  int `json:"allowed"`
	Declined int `json:"declined"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
}

type systemOneFailureCounts struct {
	Credits     int `json:"credits"`
	Auth        int `json:"auth"`
	RateLimited int `json:"rate_limited"`
	Timeout     int `json:"timeout"`
	Server      int `json:"server"`
	Network     int `json:"network"`
	Malformed   int `json:"malformed"`
	NoKey       int `json:"no_key"`
}

type systemOneSkippedCounts struct {
	Paused                  int `json:"paused"`
	Text                    int `json:"text"`
	BlockedPathsUnavailable int `json:"blocked_paths_unavailable"`
	Substitution            int `json:"substitution"`
	BlockedPath             int `json:"blocked_path"`
	Wrapper                 int `json:"wrapper"`
	ProgramLocation         int `json:"program_location"`
	ShellShape              int `json:"shell_shape"`
}

type systemOneAllowedRow struct {
	Subject   string  `json:"subject"`
	ModelID   string  `json:"model_id"`
	PReadOnly float64 `json:"p_read_only"`
	TReadOnly float64 `json:"t_read_only"`
}

type systemOneReport struct {
	Outcomes       systemOneOutcomeCounts `json:"outcomes"`
	FailureReasons systemOneFailureCounts `json:"failure_reasons"`
	SkippedReasons systemOneSkippedCounts `json:"skipped_reasons"`
	Allowed        []systemOneAllowedRow  `json:"allowed"`
}

func (r *systemOneReport) add(p events.PermissionSystemOneCheck) {
	switch p.Outcome {
	case "allowed":
		r.Outcomes.Allowed++
		r.Allowed = append(r.Allowed, systemOneAllowedRow{Subject: p.Subject, ModelID: p.ModelID, PReadOnly: *p.PReadOnly, TReadOnly: *p.TReadOnly})
	case "declined":
		r.Outcomes.Declined++
	case "skipped":
		r.Outcomes.Skipped++
		switch p.Reason {
		case "paused":
			r.SkippedReasons.Paused++
		case "text":
			r.SkippedReasons.Text++
		case "blocked_paths_unavailable":
			r.SkippedReasons.BlockedPathsUnavailable++
		case "substitution":
			r.SkippedReasons.Substitution++
		case "blocked_path":
			r.SkippedReasons.BlockedPath++
		case "wrapper":
			r.SkippedReasons.Wrapper++
		case "program_location":
			r.SkippedReasons.ProgramLocation++
		case "shell_shape":
			r.SkippedReasons.ShellShape++
		}
	case "failed":
		r.Outcomes.Failed++
		switch p.Reason {
		case "credits":
			r.FailureReasons.Credits++
		case "auth":
			r.FailureReasons.Auth++
		case "rate_limited":
			r.FailureReasons.RateLimited++
		case "timeout":
			r.FailureReasons.Timeout++
		case "server":
			r.FailureReasons.Server++
		case "network":
			r.FailureReasons.Network++
		case "malformed":
			r.FailureReasons.Malformed++
		case "no_key":
			r.FailureReasons.NoKey++
		}
	}
}

type refusedCounts struct {
	BlockedPath    int `json:"blocked_path"`
	ProtectedState int `json:"protected_state"`
}

// revocationRow is one recorded permission_revoke_requested: the identity of the grant the
// /permissions revoke control removed, copied from the event. Nothing here is derived from a
// settings file — a grant missing from YAML with no such event produces no row at all.
type revocationRow struct {
	Kind         string `json:"kind"`
	Subject      string `json:"subject"`
	Scope        string `json:"scope"`
	GrantKind    string `json:"grant_kind"`
	Source       string `json:"source"`
	ArgumentHash string `json:"argument_hash,omitempty"`
}

type permissionsReport struct {
	Session     string            `json:"session"`
	Folder      string            `json:"folder"`
	Rows        []promptRow       `json:"prompts"`
	Granted     int               `json:"granted"`
	Denied      int               `json:"denied"`
	Pending     int               `json:"pending"`
	NonPrompted nonPromptedCounts `json:"non_prompted"`
	Refused     refusedCounts     `json:"refused"`
	SystemOne   systemOneReport   `json:"system_one"`
	Revocations []revocationRow   `json:"revocation_requests"`
}

// requestScope returns the request scope a permission event was evaluated
// against: host subjects carry host_scope, every other subject kind path_scope.
func requestScope(subjectKind, pathScope, hostScope string) string {
	if subjectKind == subjectKindHost {
		return hostScope
	}
	return pathScope
}

type storedGrant struct {
	subjectKind string
	subject     string
	pathScope   string
}

func escalationCandidate(p events.PermissionDecision) (storedGrant, bool) {
	if p.Outcome != outcomeGranted || p.SubjectKind == subjectKindHost {
		return storedGrant{}, false
	}
	if p.GrantKind == "" || p.GrantKind == grantKindGlobal || p.GrantSubject == "" {
		return storedGrant{}, false
	}
	// A direct decision whose identity is absent or does not validate proves nothing about the
	// request's assignments, so it can never be the narrower grant a later prompt escalates.
	if _, _, ok := promptRequestAssignments(p.SubjectKind, p.DirectCommandSubject, p.DirectRequestSubject); !ok {
		return storedGrant{}, false
	}
	return storedGrant{subjectKind: p.SubjectKind, subject: p.GrantSubject, pathScope: p.GrantPathScope}, true
}

func classifyGrant(p events.PermissionDecision) *grantRecord {
	if p.Outcome != outcomeGranted {
		return nil
	}
	if p.GrantKind == "" {
		return &grantRecord{}
	}
	g := &grantRecord{Stored: true, Kind: p.GrantKind, Subject: p.GrantSubject}
	switch {
	case p.SubjectKind == subjectKindHost:
		g.HostScope = p.GrantHostScope
	case p.GrantKind != grantKindGlobal:
		g.PathScope = p.GrantPathScope
	}
	return g
}

// Subject must never be re-split into tokens; flattening it lost the quoted-token boundaries.
func promptRequestTokens(p events.PermissionPromptShown) (tokens []string, ok bool) {
	if p.SubjectKind != subjectKindDirect {
		return nil, true
	}
	if p.DirectTokens == nil {
		return nil, false
	}
	return *p.DirectTokens, true
}

// promptRequestAssignments reports the direct request's ordered environment
// assignments and whether it cleared the environment, decoded by the permission checker
// from the record's own identity fields. A legacy record without a valid identity reports
// ok=false: an empty list and a false flag would assert the request carried no assignment
// and inherited the environment, which the record does not prove.
func promptRequestAssignments(subjectKind, commandSubject, requestSubject string) (assignments []string, clearEnvironment, ok bool) {
	if subjectKind != subjectKindDirect {
		return nil, false, true
	}
	return permissions.DecodeDirectRequestSubject(requestSubject, commandSubject)
}

func findEscalation(p events.PermissionPromptShown, prior []storedGrant) *scopeEscalation {
	if p.SubjectKind == subjectKindHost {
		return nil
	}
	tokens, ok := promptRequestTokens(p)
	if !ok {
		return nil
	}
	assignments, clearEnvironment, ok := promptRequestAssignments(p.SubjectKind, p.DirectCommandSubject, p.DirectRequestSubject)
	if !ok {
		return nil
	}
	var narrowest *storedGrant
	for i := range prior {
		g := prior[i]
		if g.subjectKind != p.SubjectKind {
			continue
		}
		if g.pathScope == p.PathScope || !permissions.IsDescendantOrEqual(g.pathScope, p.PathScope) {
			continue
		}
		if !permissions.AuditSubjectMatches(p.SubjectKind, p.Subject, tokens, assignments, clearEnvironment, g.subject) {
			continue
		}
		if narrowest == nil || permissions.IsDeeperScope(g.pathScope, narrowest.pathScope) {
			narrowest = &prior[i]
		}
	}
	if narrowest == nil {
		return nil
	}
	return &scopeEscalation{GrantPathScope: narrowest.pathScope, GrantSubject: narrowest.subject}
}

// tupleKey is the correlation key pairing a decision with the prompt it answers.
// It is a struct rather than a joined string because every separator byte is a
// legal payload byte, so any serialized form can alias distinct tuples. identity
// separates the two direct keyings: an assignment-free identity is byte-equal to
// the legacy joined subject for a command whose tokens need no quoting, so without
// it an identity-less record and an identity-bearing one would share a key.
type tupleKey struct {
	subjectKind string
	subject     string
	scope       string
	identity    bool
}

// correlationKey pairs a direct record with its own request by the validated
// request identity, so two concurrent prompts for the same command with different
// assignments never take each other's decision. A direct record carrying neither
// identity field is legacy and keys off the joined subject, which pairs only with
// another legacy record. A direct record whose identity is present but does not
// validate proves nothing about the request it names, so ok is false and it
// neither queues nor consumes a pending prompt.
func correlationKey(subjectKind, subject, scope, commandSubject, requestSubject string) (tupleKey, bool) {
	if subjectKind != subjectKindDirect || (commandSubject == "" && requestSubject == "") {
		return tupleKey{subjectKind: subjectKind, subject: subject, scope: scope}, true
	}
	if _, _, ok := permissions.DecodeDirectRequestSubject(requestSubject, commandSubject); !ok {
		return tupleKey{}, false
	}
	return tupleKey{subjectKind: subjectKind, subject: requestSubject, scope: scope, identity: true}, true
}

// buildPermissionsReport walks the record stream in order, emitting one row per
// permission_prompt_shown and pairing each with the next permission_decision
// carrying the same correlation key (correlationKey). Repeated identical
// keys are paired FIFO, and because only prompts already seen are queued, a
// decision can never satisfy a prompt shown after it. permission_matched records
// an authorization no human saw, so it only ever feeds the tally, and
// permission_revoke_requested is not an authorization at all, so it feeds its own
// list. A session written before that event existed simply reports none.
func buildPermissionsReport(path string, sess *sessions.Session) permissionsReport {
	r := permissionsReport{
		Session: path, Folder: sess.Metadata.Folder, Rows: []promptRow{}, Revocations: []revocationRow{},
		SystemOne: systemOneReport{Allowed: []systemOneAllowedRow{}},
	}
	unanswered := map[tupleKey][]int{}
	var prior []storedGrant
	for _, rec := range sess.Records {
		ev, ok := rec.(sessions.Event)
		if !ok {
			continue
		}
		switch ev.Kind {
		case events.KindPermissionPromptShown:
			var p events.PermissionPromptShown
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				continue
			}
			scope := requestScope(p.SubjectKind, p.PathScope, p.HostScope)
			r.Rows = append(r.Rows, promptRow{
				SubjectKind: p.SubjectKind, Subject: p.Subject, Scope: scope, Outcome: outcomePending,
				Escalation: findEscalation(p, prior),
			})
			key, correlatable := correlationKey(p.SubjectKind, p.Subject, scope, p.DirectCommandSubject, p.DirectRequestSubject)
			if !correlatable {
				continue
			}
			unanswered[key] = append(unanswered[key], len(r.Rows)-1)
		case events.KindPermissionDecision:
			var p events.PermissionDecision
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				continue
			}
			if g, isCandidate := escalationCandidate(p); isCandidate {
				prior = append(prior, g)
			}
			key, correlatable := correlationKey(p.SubjectKind, p.Subject, requestScope(p.SubjectKind, p.PathScope, p.HostScope),
				p.DirectCommandSubject, p.DirectRequestSubject)
			if !correlatable {
				continue
			}
			queued := unanswered[key]
			if len(queued) == 0 {
				continue
			}
			r.Rows[queued[0]].Outcome = p.Outcome
			r.Rows[queued[0]].Grant = classifyGrant(p)
			unanswered[key] = queued[1:]
		case events.KindPermissionMatched:
			var p events.PermissionMatched
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				continue
			}
			switch p.OutcomeSource {
			case "grant":
				r.NonPrompted.Grant++
			case "cache":
				r.NonPrompted.Cache++
			case "mode_auto":
				r.NonPrompted.ModeAuto++
			case "declared_scope":
				r.NonPrompted.DeclaredScope++
			case "declared_command":
				r.NonPrompted.DeclaredCommand++
			case "open_read":
				r.NonPrompted.OpenRead++
			case "confined":
				r.NonPrompted.Confined++
			case "system_one_check":
				r.NonPrompted.SystemOneCheck++
			case "blocked_path":
				r.Refused.BlockedPath++
			case "protected_state":
				r.Refused.ProtectedState++
			}
		case events.KindPermissionSystemOneCheck:
			var p events.PermissionSystemOneCheck
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				continue
			}
			r.SystemOne.add(p)
		case events.KindPermissionRevokeRequested:
			var p events.PermissionRevokeRequested
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				continue
			}
			scope := p.PathScope
			if p.HostScope != "" {
				scope = p.HostScope
			}
			r.Revocations = append(r.Revocations, revocationRow{
				Kind: p.EntryKind, Subject: p.Subject, Scope: scope,
				GrantKind: p.GrantKind, Source: p.Source, ArgumentHash: p.ArgumentHash,
			})
		}
	}
	for _, row := range r.Rows {
		switch row.Outcome {
		case outcomeGranted:
			r.Granted++
		case outcomeDenied:
			r.Denied++
		default:
			r.Pending++
		}
	}
	return r
}

// renderPermissions writes the human-readable permissions report: a header, one
// line per prompt in record order, the non-prompted tally, the System One checks, and
// the explicit revocation requests. The tally and the revocation count are printed even when
// they are zero, because zero prompts against a large non-prompted count — and a
// session with no revocations at all — are the interesting cases.
func renderPermissions(w io.Writer, r permissionsReport) {
	fmt.Fprintf(w, "session: %s\n", r.Session)
	fmt.Fprintf(w, "folder: %s\n", r.Folder)
	if len(r.Rows) == 0 {
		fmt.Fprintln(w, "prompts shown: 0")
	} else {
		fmt.Fprintf(w, "prompts shown: %d (granted: %d, denied: %d, pending: %d)\n\n",
			len(r.Rows), r.Granted, r.Denied, r.Pending)
		for i, row := range r.Rows {
			line := fmt.Sprintf("  %d. [%s] %s  %s  scope=%s", i+1, row.Outcome, row.SubjectKind, row.Subject, row.Scope)
			if detail := rowDetail(row); detail != "" {
				line += "  " + detail
			}
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintf(w, "\nnon-prompted authorizations: %d (grant: %d, cache: %d, mode_auto: %d, declared_scope: %d, declared_command: %d, open_read: %d, confined: %d, system_one_check: %d)\n",
		r.NonPrompted.total(), r.NonPrompted.Grant, r.NonPrompted.Cache, r.NonPrompted.ModeAuto, r.NonPrompted.DeclaredScope, r.NonPrompted.DeclaredCommand, r.NonPrompted.OpenRead, r.NonPrompted.Confined, r.NonPrompted.SystemOneCheck)
	fmt.Fprintf(w, "refused before approval: %d (blocked_path: %d, protected_state: %d)\n",
		r.Refused.BlockedPath+r.Refused.ProtectedState, r.Refused.BlockedPath, r.Refused.ProtectedState)

	so := r.SystemOne
	fmt.Fprintf(w, "\nSystem One checks: %d (allowed: %d, declined: %d, failed: %d, skipped: %d)\n",
		so.Outcomes.Allowed+so.Outcomes.Declined+so.Outcomes.Failed+so.Outcomes.Skipped,
		so.Outcomes.Allowed, so.Outcomes.Declined, so.Outcomes.Failed, so.Outcomes.Skipped)
	f := so.FailureReasons
	fmt.Fprintf(w, "failed by reason: credits: %d, auth: %d, rate_limited: %d, timeout: %d, server: %d, network: %d, malformed: %d, no_key: %d\n",
		f.Credits, f.Auth, f.RateLimited, f.Timeout, f.Server, f.Network, f.Malformed, f.NoKey)
	sk := so.SkippedReasons
	fmt.Fprintf(w, "skipped by reason: paused: %d, text: %d, blocked_paths_unavailable: %d, substitution: %d, blocked_path: %d, wrapper: %d, program_location: %d, shell_shape: %d\n",
		sk.Paused, sk.Text, sk.BlockedPathsUnavailable, sk.Substitution, sk.BlockedPath, sk.Wrapper, sk.ProgramLocation, sk.ShellShape)
	for i, row := range so.Allowed {
		fmt.Fprintf(w, "  %d. [allowed] %q  model=%q  p_read_only=%g  t_read_only=%g\n", i+1, row.Subject, row.ModelID, row.PReadOnly, row.TReadOnly)
	}

	fmt.Fprintf(w, "\nexplicit revocation requests: %d\n", len(r.Revocations))
	for i, row := range r.Revocations {
		line := fmt.Sprintf("  %d. [%s] %s  %s  scope=%s  grant=%s", i+1, row.Source, row.Kind, row.Subject, row.Scope, row.GrantKind)
		if row.ArgumentHash != "" {
			line += "  argument_hash=" + row.ArgumentHash
		}
		fmt.Fprintln(w, line)
	}
}

func rowDetail(row promptRow) string {
	var parts []string
	if g := row.Grant; g != nil {
		if !g.Stored {
			parts = append(parts, "grant=allow_once")
		} else {
			parts = append(parts, "grant="+g.Kind)
			if g.PathScope != "" {
				parts = append(parts, "grant_scope="+g.PathScope)
			}
			if g.HostScope != "" {
				parts = append(parts, "grant_host="+g.HostScope)
			}
			if g.Subject != "" {
				parts = append(parts, fmt.Sprintf("grant_subject=%q", g.Subject))
			}
		}
	}
	if e := row.Escalation; e != nil {
		parts = append(parts,
			"escalates_grant_scope="+e.GrantPathScope,
			fmt.Sprintf("escalates_grant_subject=%q", e.GrantSubject))
	}
	return strings.Join(parts, " ")
}

// The dispatcher's own tool-name constants (internal/bootstrap/tooldispatch.go)
// are unexported, so the report matches the same literal strings the persisted
// tool calls were written with.
const (
	webSearchTool = "web_search"
	webFetchTool  = "web_fetch"
)

// There is deliberately no stage for "the model ignored this address" — no
// record can establish that.
const (
	stageCandidate = "candidate"
	stageSelected  = "selected"
	stageRetrieved = "retrieved"
	stageFailed    = "failed"
	stageCited     = "cited"
)

var stageRank = map[string]int{
	stageCandidate: 0,
	stageSelected:  1,
	stageRetrieved: 2,
	stageFailed:    3,
	stageCited:     4,
}

const (
	shapeCandidateSearch = "candidate_search"
	shapeLegacyAutoFetch = "legacy_auto_fetch"
	shapeFetch           = "fetch"
	shapeUnclassified    = "unclassified"
)

const (
	evidenceArguments = "arguments"
	evidenceResult    = "result"
)

// The complete persisted outcome set of webresearch.FetchResult. An outcome
// outside it is evidence this build cannot classify, not a failed fetch.
var fetchOutcomeStages = map[string]string{
	webresearch.OutcomeOK:                 stageRetrieved,
	webresearch.OutcomeRequestFailed:      stageFailed,
	webresearch.OutcomeResponseTooLarge:   stageFailed,
	webresearch.OutcomeUnsupportedContent: stageFailed,
	webresearch.OutcomeExtractionFailed:   stageFailed,
}

// The producers' own limits, restated because both sets are unexported:
// encodeSearchCandidates keeps at most five candidates and drops or bounds each
// field (internal/bootstrap/tooldispatch.go), and FetchText caps the final URL
// (internal/webresearch/fetch.go). A stored value past one of them is outside
// the persisted contract rather than merely unusual.
const (
	maxPersistedCandidates        = 5
	maxPersistedCandidateURLBytes = 2048
	maxPersistedTitleBytes        = 512
	maxPersistedSnippetBytes      = 4096
	maxPersistedPublishedBytes    = 512
	maxPersistedFinalURLBytes     = 2048
)

var candidateFieldBytes = map[string]int{
	"title":          maxPersistedTitleBytes,
	"snippet":        maxPersistedSnippetBytes,
	"published_date": maxPersistedPublishedBytes,
}

type researchSource struct {
	URL      string   `json:"url"`
	FinalURL string   `json:"final_url,omitempty"`
	Outcome  string   `json:"outcome,omitempty"`
	Cited    []string `json:"cited,omitempty"`
	Stages   []string `json:"stages"`
}

type researchCall struct {
	Record       int              `json:"record"`
	CallID       string           `json:"call_id"`
	Tool         string           `json:"tool"`
	Shape        string           `json:"shape"`
	Query        string           `json:"query,omitempty"`
	Omitted      int              `json:"omitted,omitempty"`
	Sources      []researchSource `json:"sources"`
	Unclassified []string         `json:"unclassified,omitempty"`
}

type researchSummary struct {
	Searches            int `json:"searches"`
	LegacySearches      int `json:"legacy_searches"`
	Fetches             int `json:"fetches"`
	Queries             int `json:"queries"`
	UniqueQueries       int `json:"unique_queries"`
	CandidateURLs       int `json:"candidate_urls"`
	UniqueCandidateURLs int `json:"unique_candidate_urls"`
	SelectedCandidates  int `json:"selected_candidates"`
	FetchRetrieved      int `json:"fetch_retrieved"`
	FetchFailed         int `json:"fetch_failed"`
	LegacyAutoFetches   int `json:"legacy_auto_fetches"`
	LegacyRetrieved     int `json:"legacy_retrieved"`
	LegacyFailed        int `json:"legacy_failed"`
	CitedURLs           int `json:"cited_urls"`
	HostPrompts         int `json:"host_prompts"`
	UniquePromptedHosts int `json:"unique_prompted_hosts"`
	UnclassifiedCalls   int `json:"unclassified_calls"`
}

type researchReport struct {
	Session string          `json:"session"`
	Folder  string          `json:"folder"`
	Calls   []researchCall  `json:"calls"`
	Summary researchSummary `json:"summary"`
}

type researchAnswer struct {
	record int
	text   string
}

func buildResearchReport(path string, sess *sessions.Session) researchReport {
	r := researchReport{Session: path, Folder: sess.Metadata.Folder, Calls: researchCalls(sess.Records)}
	markSelections(r.Calls)
	markCitations(r.Calls, visibleAnswers(sess.Records))
	r.Summary = summarizeResearch(r.Calls)
	r.Summary.HostPrompts, r.Summary.UniquePromptedHosts = webHostPrompts(sess.Records)
	return r
}

func researchCalls(records []sessions.Record) []researchCall {
	calls := []researchCall{}
	for i, rec := range records {
		m, ok := rec.(sessions.Message)
		if !ok {
			continue
		}
		ambiguous := duplicateCallIDs(m.ToolCalls)
		for _, tc := range m.ToolCalls {
			name, arguments := toolCallFunction(tc.Raw)
			if name != webSearchTool && name != webFetchTool {
				continue
			}
			result, hasResult := "", false
			if !ambiguous[tc.ID] {
				result, hasResult = toolResultFor(i, tc.ID, records)
			}
			calls = append(calls, buildResearchCall(i+1, tc.ID, name, arguments, result, hasResult))
		}
	}
	return calls
}

// The call ID is the report's only correlation boundary, so two calls sharing
// one ID have no result of their own: one response cannot be evidence for both.
func duplicateCallIDs(toolCalls []sessions.ToolCall) map[string]bool {
	seen, duplicates := map[string]bool{}, map[string]bool{}
	for _, tc := range toolCalls {
		if seen[tc.ID] {
			duplicates[tc.ID] = true
		}
		seen[tc.ID] = true
	}
	return duplicates
}

func toolResultFor(i int, callID string, records []sessions.Record) (string, bool) {
	for j := i + 1; j < len(records); j++ {
		msg, ok := records[j].(sessions.Message)
		if !ok || msg.Role != "tool" {
			return "", false
		}
		if msg.ToolCallID != callID {
			continue
		}
		if msg.Content.IsList() {
			return "", false
		}
		return msg.Content.Text(), true
	}
	return "", false
}

func buildResearchCall(record int, callID, tool, arguments, result string, hasResult bool) researchCall {
	c := researchCall{Record: record, CallID: callID, Tool: tool, Sources: []researchSource{}}
	if tool == webSearchTool {
		buildSearchCall(&c, arguments, result, hasResult)
	} else {
		buildFetchCall(&c, arguments, result, hasResult)
	}
	return c
}

func buildSearchCall(c *researchCall, arguments, result string, hasResult bool) {
	query, ok := stringArg(arguments, "query")
	if !ok || strings.TrimSpace(query) == "" {
		c.Unclassified = append(c.Unclassified, evidenceArguments)
		query = ""
	}
	c.Query = query
	if !hasResult {
		c.Shape = shapeUnclassified
		c.Unclassified = append(c.Unclassified, evidenceResult)
		return
	}
	shape, sources, omitted, partial := classifySearchResult(result)
	c.Shape, c.Sources, c.Omitted = shape, sources, omitted
	if shape == shapeUnclassified || partial {
		c.Unclassified = append(c.Unclassified, evidenceResult)
	}
}

func buildFetchCall(c *researchCall, arguments, result string, hasResult bool) {
	c.Shape = shapeFetch
	url, ok := stringArg(arguments, "url")
	if !ok || strings.TrimSpace(url) == "" {
		c.Unclassified = append(c.Unclassified, evidenceArguments)
		url = ""
	}
	finalURL, outcome, parsed, finalReadable := classifyFetchResult(result)
	stage, known := "", false
	if parsed {
		stage, known = outcomeStage(outcome)
	}
	if !hasResult || !parsed || !known || !finalReadable {
		c.Unclassified = append(c.Unclassified, evidenceResult)
	}
	if url == "" {
		return
	}
	src := researchSource{URL: url, FinalURL: finalURL, Outcome: outcome, Stages: []string{}}
	if known {
		src.Stages = addStage(src.Stages, stage)
	}
	c.Sources = append(c.Sources, src)
}

func classifySearchResult(result string) (shape string, sources []researchSource, omitted int, partial bool) {
	sources = []researchSource{}
	fields, ok := jsonObjectFields(result)
	if !ok {
		return shapeUnclassified, sources, 0, false
	}
	candidatesRaw, hasCandidates := fields["candidates"]
	sourcesRaw, hasSources := fields["sources"]
	if hasCandidates && hasSources {
		return shapeUnclassified, sources, 0, false
	}
	if raw := candidatesRaw; hasCandidates {
		var entries []map[string]json.RawMessage
		if !isJSONArray(raw) || json.Unmarshal(raw, &entries) != nil {
			return shapeCandidateSearch, sources, 0, true
		}
		for i, entry := range entries {
			url, readable := stringField(entry, "url")
			if i >= maxPersistedCandidates || !readable || !persistedCandidateURL(url) {
				partial = true
				continue
			}
			if !optionalStringFields(entry, "title", "snippet", "published_date") ||
				!withinFieldBounds(entry, candidateFieldBytes) {
				partial = true
			}
			sources = append(sources, researchSource{URL: url, Stages: []string{stageCandidate}})
		}
		if omittedRaw, hasOmitted := fields["omitted"]; hasOmitted {
			if isJSONNull(omittedRaw) || json.Unmarshal(omittedRaw, &omitted) != nil || omitted < 0 {
				omitted, partial = 0, true
			}
		}
		return shapeCandidateSearch, sources, omitted, partial
	}
	if raw := sourcesRaw; hasSources {
		var entries []map[string]json.RawMessage
		if !isJSONArray(raw) || json.Unmarshal(raw, &entries) != nil {
			return shapeLegacyAutoFetch, sources, 0, true
		}
		for _, entry := range entries {
			src, entryPartial, ok := legacySource(entry)
			partial = partial || entryPartial
			if ok {
				sources = append(sources, src)
			}
		}
		return shapeLegacyAutoFetch, sources, 0, partial
	}
	return shapeUnclassified, sources, 0, false
}

// The producer stores the exact string webresearch.AdmissibleHTTPS returned
// (encodeSearchCandidates in internal/bootstrap/tooldispatch.go), so an address that is merely
// admissible but spelled differently is still outside the persisted contract.
func persistedCandidateURL(address string) bool {
	if len(address) > maxPersistedCandidateURLBytes {
		return false
	}
	canonical, ok := webresearch.AdmissibleHTTPS(address)
	return ok && canonical == address
}

// A final URL is written only on a successful fetch, from the redacted address
// the response came back on, bounded to its own byte cap. It is not held to the
// candidate contract's canonical HTTPS form: a plaintext target stays admissible
// through its redirects, and the cap truncates rather than drops.
func persistedFinalURL(address, outcome string) bool {
	if outcome != webresearch.OutcomeOK || len(address) > maxPersistedFinalURLBytes {
		return false
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || parsed.Scheme == "http"
}

func legacySource(entry map[string]json.RawMessage) (src researchSource, partial, ok bool) {
	address, _ := stringField(entry, "url")
	if address == "" {
		return researchSource{}, true, false
	}
	partial = !optionalStringFields(entry, "title", "content")
	src = researchSource{URL: address, Stages: []string{stageCandidate}}
	src.Outcome, _ = stringField(entry, "outcome")
	if _, hasFinal := entry["final_url"]; hasFinal {
		finalURL, readable := stringField(entry, "final_url")
		if !readable || !persistedFinalURL(finalURL, src.Outcome) {
			partial = true
		} else {
			src.FinalURL = finalURL
		}
	}
	if src.Outcome == "" {
		return src, true, true
	}
	stage, known := outcomeStage(src.Outcome)
	if !known {
		return src, true, true
	}
	src.Stages = addStage(src.Stages, stage)
	return src, partial, true
}

func classifyFetchResult(result string) (finalURL, outcome string, ok, resultReadable bool) {
	fields, valid := jsonObjectFields(result)
	if !valid {
		return "", "", false, false
	}
	outcome, valid = stringField(fields, "outcome")
	if !valid || outcome == "" {
		return "", "", false, false
	}
	resultReadable = optionalStringFields(fields, "content")
	if _, hasFinal := fields["final_url"]; hasFinal {
		final, readable := stringField(fields, "final_url")
		if !readable || !persistedFinalURL(final, outcome) {
			resultReadable = false
		} else {
			finalURL = final
		}
	}
	return finalURL, outcome, true, resultReadable
}

func outcomeStage(outcome string) (stage string, known bool) {
	stage, known = fetchOutcomeStages[outcome]
	return stage, known
}

// The name is decoded independently of the arguments so that a recognized web
// call whose arguments are not the contract's JSON string stays in the report
// as unclassified argument evidence instead of disappearing from it.
func toolCallFunction(raw json.RawMessage) (name, arguments string) {
	call, ok := jsonObjectFields(string(raw))
	if !ok {
		return "", ""
	}
	fn, ok := jsonObjectFields(string(call["function"]))
	if !ok {
		return "", ""
	}
	name, _ = stringField(fn, "name")
	arguments, _ = stringField(fn, "arguments")
	return name, arguments
}

func jsonObjectFields(raw string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// A JSON null decodes into a slice without error, so an explicit null
// collection must be rejected here rather than reported as an empty one.
func isJSONArray(raw json.RawMessage) bool {
	var elements []json.RawMessage
	return json.Unmarshal(raw, &elements) == nil && elements != nil
}

func stringArg(arguments, key string) (string, bool) {
	fields, ok := jsonObjectFields(arguments)
	if !ok {
		return "", false
	}
	return stringField(fields, key)
}

// Every persisted string field here carries an address, an outcome, a tool
// name, or an arguments payload, none of which has a blank in range, so a
// present empty or whitespace-only value is malformed evidence and never an
// absent field.
func stringField(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, has := fields[key]
	if !has || isJSONNull(raw) {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	if strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

// The producer bounds each field before writing it, so a longer stored value
// was never produced by it and the byte length is checked on the decoded string
// the producer measured, not on its JSON escaping.
func withinFieldBounds(fields map[string]json.RawMessage, bounds map[string]int) bool {
	for key, limit := range bounds {
		raw, has := fields[key]
		if !has {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil && len(value) > limit {
			return false
		}
	}
	return true
}

func optionalStringFields(fields map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		raw, has := fields[key]
		if !has {
			continue
		}
		var value string
		if isJSONNull(raw) || json.Unmarshal(raw, &value) != nil || value == "" {
			return false
		}
	}
	return true
}

// A JSON null decodes into a string or a number without error, so a present
// null must be rejected wherever an absent field is legitimate: otherwise a
// malformed record is reported as a confirmed empty or zero value.
func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

func addStage(stages []string, stage string) []string {
	for _, s := range stages {
		if s == stage {
			return stages
		}
	}
	stages = append(stages, stage)
	sort.SliceStable(stages, func(i, j int) bool { return stageRank[stages[i]] < stageRank[stages[j]] })
	return stages
}

func hasStage(src researchSource, stage string) bool {
	for _, s := range src.Stages {
		if s == stage {
			return true
		}
	}
	return false
}

// A legacy bundle already fetched its sources when the search ran, so a later
// explicit fetch of the same address is a second retrieval of a historical
// record, never evidence that the model selected that source from candidates.
func markSelections(calls []researchCall) {
	for i := range calls {
		for j := range calls[i].Sources {
			src := &calls[i].Sources[j]
			if calls[i].Tool == webSearchTool {
				if calls[i].Shape == shapeCandidateSearch && fetchedLater(calls, calls[i].Record, src.URL) {
					src.Stages = addStage(src.Stages, stageSelected)
				}
				continue
			}
			if offeredEarlier(calls, calls[i].Record, src.URL) {
				src.Stages = addStage(src.Stages, stageSelected)
			}
		}
	}
}

func fetchedLater(calls []researchCall, record int, url string) bool {
	if url == "" {
		return false
	}
	for _, c := range calls {
		if c.Tool != webFetchTool || c.Record <= record {
			continue
		}
		for _, src := range c.Sources {
			if src.URL == url {
				return true
			}
		}
	}
	return false
}

func offeredEarlier(calls []researchCall, record int, url string) bool {
	if url == "" {
		return false
	}
	for _, c := range calls {
		if c.Tool != webSearchTool || c.Record >= record {
			continue
		}
		for _, src := range c.Sources {
			if src.URL == url {
				return true
			}
		}
	}
	return false
}

// A redirect makes the requested and final addresses two distinct persisted
// strings, so the exact one an answer repeated is kept as the citation; the
// other was never in the answer and must not be reported or counted as cited.
func markCitations(calls []researchCall, answers []researchAnswer) {
	for i := range calls {
		for j := range calls[i].Sources {
			src := &calls[i].Sources[j]
			addresses := []string{src.URL}
			if src.FinalURL != "" && src.FinalURL != src.URL {
				addresses = append(addresses, src.FinalURL)
			}
			for _, address := range addresses {
				if citedLater(answers, calls[i].Record, address) {
					src.Cited = append(src.Cited, address)
				}
			}
			if len(src.Cited) > 0 {
				src.Stages = addStage(src.Stages, stageCited)
			}
		}
	}
}

func citedLater(answers []researchAnswer, record int, url string) bool {
	if url == "" {
		return false
	}
	for _, a := range answers {
		if a.record > record && containsWholeURL(a.text, url) {
			return true
		}
	}
	return false
}

func containsWholeURL(text, url string) bool {
	for offset := 0; offset <= len(text)-len(url); {
		i := strings.Index(text[offset:], url)
		if i < 0 {
			return false
		}
		start := offset + i
		if !urlPrecedes(text[:start]) && !urlContinues(text[start+len(url):]) {
			return true
		}
		offset = start + 1
	}
	return false
}

// The mirror boundary: an occurrence inside a longer address — a proxy,
// archive, or redirect link that carries the persisted address in its own path
// or query — is not a citation of it. Only a character that could continue an
// address counts, because prose routinely attaches a bracket, quote, or
// emphasis marker to the front of one.
func urlPrecedes(before string) bool {
	const urlContinuation = `-._~/?#@%&=+$;`
	r, size := utf8.DecodeLastRuneInString(before)
	if size == 0 {
		return false
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(urlContinuation, r)
}

// A longer address that merely starts with the persisted one is a different
// address, so the occurrence only counts when nothing that could extend the
// path, query, or fragment follows it. Punctuation that normally ends a
// sentence is skipped, since prose routinely places it right after an address.
func urlContinues(rest string) bool {
	const sentencePunctuation = `.,;:!?'")]}`
	const urlPunctuation = `-._~:/?#[]@!$&'()*+,;=%`
	for _, r := range rest {
		if strings.ContainsRune(sentencePunctuation, r) {
			continue
		}
		return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(urlPunctuation, r)
	}
	return false
}

// A message carrying tool calls is the model asking for work rather than
// answering, and a tool result is fetched content rather than the model's own
// words, so neither is citation evidence.
func visibleAnswers(records []sessions.Record) []researchAnswer {
	var answers []researchAnswer
	for i, rec := range records {
		m, ok := rec.(sessions.Message)
		if !ok || m.Role != "assistant" || len(m.ToolCalls) > 0 || m.Content.IsList() {
			continue
		}
		if text := m.Content.Text(); text != "" {
			answers = append(answers, researchAnswer{record: i + 1, text: text})
		}
	}
	return answers
}

func webHostPrompts(records []sessions.Record) (total, uniqueHosts int) {
	seen := map[string]bool{}
	for _, rec := range records {
		ev, ok := rec.(sessions.Event)
		if !ok || ev.Kind != events.KindPermissionPromptShown {
			continue
		}
		var p events.PermissionPromptShown
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		if p.SubjectKind != subjectKindHost || (p.Subject != webSearchTool && p.Subject != webFetchTool) {
			continue
		}
		total++
		if p.HostScope != "" {
			seen[p.HostScope] = true
		}
	}
	return total, len(seen)
}

func summarizeResearch(calls []researchCall) researchSummary {
	s := researchSummary{}
	queries, candidates, selected, cited := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range calls {
		if len(c.Unclassified) > 0 {
			s.UnclassifiedCalls++
		}
		if c.Tool == webSearchTool {
			summarizeSearchCall(&s, c, queries, candidates, selected)
		} else {
			summarizeFetchCall(&s, c)
		}
		for _, src := range c.Sources {
			for _, address := range src.Cited {
				cited[address] = true
			}
		}
	}
	s.UniqueQueries, s.UniqueCandidateURLs = len(queries), len(candidates)
	s.SelectedCandidates, s.CitedURLs = len(selected), len(cited)
	return s
}

func summarizeSearchCall(s *researchSummary, c researchCall, queries, candidates, selected map[string]bool) {
	s.Searches++
	if c.Shape == shapeLegacyAutoFetch {
		s.LegacySearches++
	}
	if c.Query != "" {
		s.Queries++
		queries[c.Query] = true
	}
	for _, src := range c.Sources {
		s.CandidateURLs++
		candidates[src.URL] = true
		if hasStage(src, stageSelected) {
			selected[src.URL] = true
		}
		if c.Shape != shapeLegacyAutoFetch || src.Outcome == "" {
			continue
		}
		s.LegacyAutoFetches++
		switch {
		case hasStage(src, stageRetrieved):
			s.LegacyRetrieved++
		case hasStage(src, stageFailed):
			s.LegacyFailed++
		}
	}
}

func summarizeFetchCall(s *researchSummary, c researchCall) {
	s.Fetches++
	for _, src := range c.Sources {
		switch {
		case hasStage(src, stageRetrieved):
			s.FetchRetrieved++
		case hasStage(src, stageFailed):
			s.FetchFailed++
		}
	}
}

func renderResearchHuman(w io.Writer, r researchReport) {
	s := r.Summary
	fmt.Fprintf(w, "session: %s\n", r.Session)
	fmt.Fprintf(w, "folder: %s\n", r.Folder)
	fmt.Fprintf(w, "web research calls: %d (searches: %d, fetches: %d)\n", len(r.Calls), s.Searches, s.Fetches)
	if len(r.Calls) > 0 {
		fmt.Fprintln(w)
		for i, c := range r.Calls {
			renderResearchCall(w, i+1, c)
		}
	}
	fmt.Fprintln(w, "\nfunnel:")
	fmt.Fprintf(w, "  searches: %d (legacy auto-fetch: %d)\n", s.Searches, s.LegacySearches)
	fmt.Fprintf(w, "  queries: %d total, %d unique (%d repeated)\n", s.Queries, s.UniqueQueries, s.Queries-s.UniqueQueries)
	fmt.Fprintf(w, "  candidate urls: %d total, %d unique (%d repeated)\n",
		s.CandidateURLs, s.UniqueCandidateURLs, s.CandidateURLs-s.UniqueCandidateURLs)
	fmt.Fprintf(w, "  candidates a later fetch selected: %d\n", s.SelectedCandidates)
	fmt.Fprintf(w, "  explicit fetches: %d (retrieved: %d, failed: %d)\n", s.Fetches, s.FetchRetrieved, s.FetchFailed)
	fmt.Fprintf(w, "  legacy auto-fetches: %d (retrieved: %d, failed: %d)\n",
		s.LegacyAutoFetches, s.LegacyRetrieved, s.LegacyFailed)
	fmt.Fprintf(w, "  urls cited in a later answer: %d\n", s.CitedURLs)
	fmt.Fprintf(w, "  web host prompts: %d shown, %d unique hosts\n", s.HostPrompts, s.UniquePromptedHosts)
	fmt.Fprintf(w, "  calls with unclassified evidence: %d\n", s.UnclassifiedCalls)
	fmt.Fprintln(w, "\nuncited does not mean unused: this reports what the session file records, never why the model answered as it did.")
}

func renderResearchCall(w io.Writer, n int, c researchCall) {
	line := fmt.Sprintf("  %d. record %d  %s  %s  shape=%s", n, c.Record, c.Tool, c.CallID, c.Shape)
	if c.Query != "" {
		line += fmt.Sprintf("  query=%q", c.Query)
	}
	if len(c.Unclassified) > 0 {
		line += "  unclassified=" + strings.Join(c.Unclassified, ",")
	}
	fmt.Fprintln(w, line)
	for _, src := range c.Sources {
		fmt.Fprintln(w, "       "+researchSourceDetail(src))
	}
	if c.Omitted > 0 {
		fmt.Fprintf(w, "       omitted candidates: %d\n", c.Omitted)
	}
}

func researchSourceDetail(src researchSource) string {
	detail := src.URL
	if src.FinalURL != "" {
		detail += "  final_url=" + src.FinalURL
	}
	if src.Outcome != "" {
		detail += "  outcome=" + src.Outcome
	}
	if len(src.Cited) > 0 {
		detail += "  cited=" + strings.Join(src.Cited, ",")
	}
	if len(src.Stages) == 0 {
		return detail + "  stages=none"
	}
	return detail + "  stages=" + strings.Join(src.Stages, ",")
}

// --- show -------------------------------------------------------------------

// internal/events publishes no enumeration of its Kind… constants, so the set
// --kind accepts is written out here and pinned to that source by
// TestSessionsShow_KindListMatchesEventsPackage.
var showKinds = []string{
	events.KindAgentInstructionsLoaded,
	events.KindChildAgentEnd,
	events.KindChildAgentStart,
	events.KindExecutionCapability,
	events.KindInteractionMode,
	events.KindLaunchBegan,
	events.KindModelCatalogRefreshed,
	events.KindModelChanged,
	events.KindModelEffortUnsupported,
	events.KindModelGlobalMirrorFailed,
	events.KindModelPersistFailed,
	events.KindModelRecoveryFailed,
	events.KindModelResponse,
	events.KindModelTurn,
	events.KindPermissionDecision,
	events.KindPermissionMatched,
	events.KindPermissionPersistFailed,
	events.KindPermissionPromptShown,
	events.KindPermissionPromptWait,
	events.KindPermissionRevokeRequested,
	events.KindPermissionSystemOneCheck,
	events.KindProviderRequestFailed,
	events.KindProviderRequestRetry,
	events.KindProviderRequestRetrySkipped,
	events.KindProviderRoundTrip,
	events.KindProviderStreamIdle,
	events.KindQueuedPromptDiscarded,
	events.KindSecurityStateHalted,
	events.KindSessionForked,
	events.KindSessionPruneSummary,
	events.KindSessionWriteFailed,
	events.KindSkillLoaded,
	events.KindSlashCommand,
	events.KindStreamInterrupted,
	events.KindStructuredReadEnd,
	events.KindStructuredReadRefused,
	events.KindStructuredReadStart,
	events.KindSuggestFollowupDebug,
	events.KindToolExecEnd,
	events.KindToolExecStart,
	events.KindTurnLatency,
	events.KindTurnTerminal,
}

// The …Set fields keep `--last 0` and `--turn ""` rejectable instead of
// indistinguishable from an unsupplied flag.
type showOptions struct {
	kinds   []string
	turn    string
	turnSet bool
	last    int
	lastSet bool
	asJSON  bool
}

func (o showOptions) filtering() bool {
	return len(o.kinds) > 0 || o.turn != "" || o.last > 0
}

func (o showOptions) validate() error {
	for _, k := range o.kinds {
		if !knownEventKind(k) {
			return ucli.Exit(
				fmt.Sprintf("codemeld: sessions show --kind %q is not a recorded event kind; valid kinds: %s", k, strings.Join(showKinds, ", ")),
				2,
			)
		}
	}
	if o.turnSet && !ids.IsValidV7(o.turn) {
		return ucli.Exit(fmt.Sprintf("codemeld: sessions show --turn %q is not a valid turn id", o.turn), 2)
	}
	if o.lastSet && o.last < 1 {
		return ucli.Exit(fmt.Sprintf("codemeld: sessions show --last must be greater than zero; got %d", o.last), 2)
	}
	return nil
}

func knownEventKind(kind string) bool {
	for _, k := range showKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// number is the record's position in the whole session, not in the selection.
type numberedRecord struct {
	number int
	record sessions.Record
}

func selectShowRecords(records []sessions.Record, opts showOptions) []numberedRecord {
	first, last := 0, len(records)-1
	if opts.turn != "" {
		var found bool
		first, last, found = turnRange(records, opts.turn)
		if !found {
			return nil
		}
	}
	var selected []numberedRecord
	for i := first; i <= last; i++ {
		if len(opts.kinds) > 0 && !matchesKinds(records[i], opts.kinds) {
			continue
		}
		selected = append(selected, numberedRecord{number: i + 1, record: records[i]})
	}
	if opts.last > 0 && len(selected) > opts.last {
		selected = selected[len(selected)-opts.last:]
	}
	return selected
}

func matchesKinds(rec sessions.Record, kinds []string) bool {
	ev, ok := rec.(sessions.Event)
	if !ok {
		return false
	}
	for _, k := range kinds {
		if ev.Kind == k {
			return true
		}
	}
	return false
}

// Only turn_terminal and provider_round_trip carry a turn id, so the range has to
// be reconstructed around them: it spans the turn's first through last lifecycle
// record, widened at both ends over the records that carry no id of their own.
//
// The end is the last lifecycle record rather than the last turn_terminal because
// a terminal closes one *round*, not the turn -- an agentic turn writes one per
// round, and doctor's incomplete_round finding (see incompleteRoundFinding) names
// exactly a later round that recorded its provider_round_trip and then died before
// its terminal. Stopping at the last terminal would hide that round from the reader
// doctor just sent to look at it.
func turnRange(records []sessions.Record, turnID string) (first, last int, found bool) {
	firstLifecycle, lastLifecycle := -1, -1
	for i, rec := range records {
		ev, ok := rec.(sessions.Event)
		if !ok || (ev.Kind != events.KindTurnTerminal && ev.Kind != events.KindProviderRoundTrip) {
			continue
		}
		if payloadTurnID(ev.Payload) != turnID {
			continue
		}
		if firstLifecycle < 0 {
			firstLifecycle = i
		}
		lastLifecycle = i
	}
	if firstLifecycle < 0 {
		return 0, 0, false
	}
	return turnStart(records, firstLifecycle), turnEnd(records, lastLifecycle), true
}

// turnTailKinds are the records the turn loop writes *after* the turn_terminal that
// closed a round: recordTerminal runs first and the provider_request_failed saying
// why the round failed is committed only afterwards (turn.go's deferOrCommit), with
// the retry bookkeeping around it. None of them carry a turn id, so a range ending at
// the last lifecycle record would drop the reason the turn ended -- the very thing
// doctor sends the reader to --turn to see.
//
// The set is closed on purpose. Widening the tail to every record that carries no
// turn id would sweep in whatever the user did between turns -- the slash_command and
// model_changed of a `/model` run after the turn, say -- and report it as part of a
// turn it has nothing to do with.
var turnTailKinds = map[string]bool{
	events.KindProviderRequestFailed:       true,
	events.KindProviderRequestRetry:        true,
	events.KindProviderRequestRetrySkipped: true,
}

// turnEnd extends the range past the turn's last lifecycle record over the
// contiguous run of turnTailKinds records that follows it.
func turnEnd(records []sessions.Record, lifecycle int) int {
	end := lifecycle
	for i := lifecycle + 1; i < len(records); i++ {
		ev, ok := records[i].(sessions.Event)
		if !ok || !turnTailKinds[ev.Kind] {
			return end
		}
		end = i
	}
	return end
}

func turnStart(records []sessions.Record, lifecycle int) int {
	for i := lifecycle - 1; i >= 0; i-- {
		if m, ok := records[i].(sessions.Message); ok && m.Role == "user" {
			return i
		}
	}
	return lifecycle
}

func payloadTurnID(payload json.RawMessage) string {
	var p struct {
		TurnID string `json:"turn_id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return ""
	}
	return p.TurnID
}

func renderShow(w io.Writer, path string, sess *sessions.Session, selected []numberedRecord, filtered bool) {
	fmt.Fprintf(w, "session: %s\n", path)
	fmt.Fprintf(w, "folder: %s\n", sess.Metadata.Folder)
	if ff := sess.Metadata.ForkedFrom; ff != nil {
		fmt.Fprintf(w, "forked_from: session=%s record=%s\n", ff.SessionID, ff.RecordID)
	}
	if filtered {
		fmt.Fprintf(w, "records: %d of %d\n\n", len(selected), len(sess.Records))
	} else {
		fmt.Fprintf(w, "records: %d\n\n", len(sess.Records))
	}
	for _, sel := range selected {
		switch r := sel.record.(type) {
		case sessions.Message:
			renderMessage(w, sel.number, r)
		case sessions.Event:
			renderEvent(w, sel.number, r)
		case sessions.Compaction:
			renderCompaction(w, sel.number, r)
		}
		fmt.Fprintln(w)
	}
}

type showReport struct {
	Session    string          `json:"session"`
	Folder     string          `json:"folder"`
	ForkedFrom *showForkOrigin `json:"forked_from,omitempty"`
	Records    int             `json:"records"`
	Selected   int             `json:"selected"`
	Filtered   bool            `json:"filtered"`
	Entries    []showEntry     `json:"entries"`
}

type showForkOrigin struct {
	SessionID string `json:"session_id"`
	RecordID  string `json:"record_id"`
}

type showEntry struct {
	Number       int                `json:"number"`
	Type         string             `json:"type"`
	ID           string             `json:"id"`
	Timestamp    string             `json:"timestamp"`
	ParentID     string             `json:"parent_id,omitempty"`
	Role         string             `json:"role,omitempty"`
	Content      *string            `json:"content,omitempty"`
	ContentParts *[]json.RawMessage `json:"content_parts,omitempty"`
	ToolCallID   string             `json:"tool_call_id,omitempty"`
	ToolCalls    []showToolCall     `json:"tool_calls,omitempty"`
	Kind         string             `json:"kind,omitempty"`
	Payload      json.RawMessage    `json:"payload,omitempty"`
	Summary      string             `json:"summary,omitempty"`
	Provider     string             `json:"provider,omitempty"`
	ModelID      string             `json:"model_id,omitempty"`
}

// sessions.Message's own marshaler preserves the provider-facing escaped
// arguments string, so a consumer gets the unescaped value only because the
// entry is rebuilt here.
type showToolCall struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Arguments    json.RawMessage `json:"arguments,omitempty"`
	RawArguments *string         `json:"raw_arguments,omitempty"`
	InvalidJSON  bool            `json:"invalid_json_arguments"`
}

func buildShowReport(path string, sess *sessions.Session, selected []numberedRecord, filtered bool) showReport {
	report := showReport{
		Session:  path,
		Folder:   sess.Metadata.Folder,
		Records:  len(sess.Records),
		Selected: len(selected),
		Filtered: filtered,
		Entries:  make([]showEntry, 0, len(selected)),
	}
	if ff := sess.Metadata.ForkedFrom; ff != nil {
		report.ForkedFrom = &showForkOrigin{SessionID: ff.SessionID, RecordID: ff.RecordID}
	}
	for _, sel := range selected {
		report.Entries = append(report.Entries, showRecordEntry(sel))
	}
	return report
}

func showRecordEntry(sel numberedRecord) showEntry {
	switch r := sel.record.(type) {
	case sessions.Message:
		e := showEntry{
			Number: sel.number, Type: "message", ID: r.ID, Timestamp: formatTimestamp(r.Timestamp),
			ParentID: r.ParentID, Role: r.Role, ToolCallID: r.ToolCallID,
		}
		if r.Content.IsList() {
			parts := make([]json.RawMessage, 0, len(r.Content.Parts()))
			for _, p := range r.Content.Parts() {
				parts = append(parts, p.Raw)
			}
			e.ContentParts = &parts
		} else {
			text := r.Content.Text()
			e.Content = &text
		}
		for _, tc := range r.ToolCalls {
			e.ToolCalls = append(e.ToolCalls, showToolCallEntry(tc))
		}
		return e
	case sessions.Event:
		return showEntry{
			Number: sel.number, Type: "event", ID: r.ID, Timestamp: formatTimestamp(r.Timestamp),
			ParentID: r.ParentID, Kind: r.Kind, Payload: r.Payload,
		}
	case sessions.Compaction:
		return showEntry{
			Number: sel.number, Type: "compaction", ID: r.ID, Timestamp: formatTimestamp(r.Timestamp),
			ParentID: r.ParentID, Summary: r.Summary, Provider: r.Provider, ModelID: r.ModelID,
		}
	}
	return showEntry{Number: sel.number}
}

func showToolCallEntry(tc sessions.ToolCall) showToolCall {
	name, display, invalid := toolCallArguments(tc.Raw)
	if invalid {
		return showToolCall{ID: tc.ID, Name: name, RawArguments: &display, InvalidJSON: true}
	}
	return showToolCall{ID: tc.ID, Name: name, Arguments: json.RawMessage(display)}
}

func renderCompaction(w io.Writer, n int, c sessions.Compaction) {
	fmt.Fprintf(w, "%d. compaction  %s\n", n, formatTimestamp(c.Timestamp))
	fmt.Fprintf(w, "    generated by: provider=%s model=%s\n", c.Provider, c.ModelID)
	fmt.Fprintf(w, "    source record: parent_id=%s\n", c.ParentID)
	fmt.Fprintln(w, "    summary:")
	writeIndented(w, "      ", c.Summary)
}

// renderMessage prints one message record: a header (role, timestamp, and the
// answered tool_call id for tool messages), its content, and any tool calls with
// arguments unescaped and indented for display.
func renderMessage(w io.Writer, n int, m sessions.Message) {
	header := fmt.Sprintf("%d. message  role=%s  %s", n, m.Role, formatTimestamp(m.Timestamp))
	if m.ToolCallID != "" {
		header += "  answers tool_call " + m.ToolCallID
	}
	fmt.Fprintln(w, header)

	if m.Content.IsList() {
		for _, p := range m.Content.Parts() {
			fmt.Fprintf(w, "    [content part type=%s] %s\n", p.Type, compactJSON(p.Raw))
		}
	} else if text := m.Content.Text(); text != "" {
		writeIndented(w, "    ", text)
	}

	for _, tc := range m.ToolCalls {
		name, display, invalid := toolCallArguments(tc.Raw)
		flag := ""
		if invalid {
			flag = "  [invalid JSON arguments]"
		}
		fmt.Fprintf(w, "    tool_call %s  %s%s\n", tc.ID, name, flag)
		writeIndented(w, "      ", display)
	}
}

// renderEvent prints one event record: a header (kind, timestamp) and its
// payload, indented and pretty-printed when it is valid JSON.
func renderEvent(w io.Writer, n int, e sessions.Event) {
	fmt.Fprintf(w, "%d. event  kind=%s  %s\n", n, e.Kind, formatTimestamp(e.Timestamp))
	if pretty, ok := prettyJSON(e.Payload); ok {
		writeIndented(w, "    ", pretty)
	} else {
		writeIndented(w, "    ", strings.TrimSpace(string(e.Payload)))
	}
}

// toolCallArguments extracts a tool call's function name and a display form of
// its arguments from the stored raw entry. Stored arguments is a verbatim escaped
// JSON string; this unescapes and indents it for display only. invalid
// is true when the entry or its arguments string is not valid JSON, in which case
// display is the raw value so a malformed call is shown rather than dropped.
func toolCallArguments(raw json.RawMessage) (name, display string, invalid bool) {
	var tc struct {
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &tc); err != nil {
		return "", strings.TrimSpace(string(raw)), true
	}
	pretty, ok := prettyJSON([]byte(tc.Function.Arguments))
	if !ok {
		return tc.Function.Name, tc.Function.Arguments, true
	}
	return tc.Function.Name, pretty, false
}

// prettyJSON indents raw JSON with two-space indentation. ok is false when raw is
// not valid JSON.
func prettyJSON(raw []byte) (string, bool) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return "", false
	}
	return buf.String(), true
}

// compactJSON renders raw JSON on a single line, or the trimmed raw bytes when it
// is not valid JSON.
func compactJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return strings.TrimSpace(string(raw))
	}
	return buf.String()
}

// writeIndented writes s to w with prefix prepended to every line.
func writeIndented(w io.Writer, prefix, s string) {
	for _, line := range strings.Split(s, "\n") {
		fmt.Fprintf(w, "%s%s\n", prefix, line)
	}
}

// formatTimestamp renders a record timestamp in the canonical UTC millisecond Z form.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(tsDisplayLayout)
}
