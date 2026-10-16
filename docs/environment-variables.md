# Environment variables

The environment variables a user can set to change codemeld's behavior. This is not a list of every
variable codemeld reads: it also reads system variables such as `HOME`, `PATH`, `CI`, `DISPLAY` and
`WAYLAND_DISPLAY` to find files and helper programs and to detect the session, and tests read
variables of their own; none of those is listed here. The runtime ones below are also surfaced in the
TUI `/help` panel (`internal/tui/help.go`); keep the two in sync when changing either.

## Runtime

| Variable | Effect |
|----------|--------|
| `OPENAI_API_KEY` | API key for the OpenAI Platform provider. When set it is used in preference to the key saved in settings (`internal/authstatus`, `internal/provider`). |
| `CODEMELD_MOUSE_DEBUG` | Set to a writable **file path** to append a log of mouse / drag / auto-scroll events there. Off (and zero-cost) when unset. Use it to diagnose TUI selection or scroll problems that the test harness cannot reproduce — see `docs/tui-mouse-debugging.md`. Implemented in `internal/tui/mousedebug.go`. |
| `CODEMELD_DEV_DEBUG` | Set to `1` to record an ordered, development-only `suggest_followup` trace as `suggest_followup_debug` session events: whether the tool was advertised, whether the model called it, where it was intercepted, and what the TUI surface did (surface called, ghost set, accepted, cleared). It persists only stages, lengths, booleans, and a discard reason — never the suggestion label/prompt text — and is off (and event-free) in a normal session. The headless `codemeld run --dev-debug` flag enables the same trace. Inspect the events afterward with `codemeld sessions show <id>`. To judge the producer guidance: a `tool_call_seen` / `intercepted` stage after `request_built` with `advertised: true` means the model actually called `suggest_followup`, whereas `provider_round_no_call` on that turn means it ended without calling the tool. |
| `CODEMELD_SHELL_TOOL_HINT` | Set to `1` to refuse a `bash` call when the permission scanner splits its command into stages and one of those stages runs `grep`, `egrep`, `fgrep`, `rg`, `cat`, `head`, `tail`, `find` or `ls`. A command the scanner does not split into stages — for example one with a redirection to a file, a subshell, `$(...)`, or a wrapper such as `xargs`, `bash -c` or `sudo` — is not refused and goes through normal shell dispatch. For a refused call nothing runs, no permission prompt appears and no `tool_exec_*` record is written; the model instead gets a tool result starting `shell-tool hint:` that names the structured tool for each such program (`grep`, `read`, `glob`, `list`). Read on every call, so it can be flipped between runs without restarting the session. It exists only for an experiment that counts the hint results in the stored messages (they are absent from `codemeld sessions summary`). Not for normal use: while it is on, a model that will not or cannot call the structured tools gets stuck. Any other value, or unset, leaves shell dispatch unchanged. |

## Development / test only

| Variable | Effect |
|----------|--------|
| `CODEMELD_UPDATE_SNAPSHOTS` | Set to `1` to regenerate the golden snapshot fixtures during `go test` instead of asserting against them (`internal/agentinstr/snapshot_test.go`; see `docs/gated-changes.md`). Not read by the shipped binary. |
