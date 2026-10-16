# Security Policy

## Reporting a vulnerability

Please report security issues **privately by email** — do not open a public issue
for a suspected vulnerability.

- **Email:** francisco@natserv.com
- Use a clear subject line (for example, `codemeld security: <short summary>`).
- Include the version shown by `/status`, your OS and terminal emulator, the
  provider and model in use, and the smallest steps that reproduce the issue.
- **Redact secrets** before sending: remove API keys, session tokens, and any
  `~/.codemeld` settings or session contents from logs and attachments.

You will receive an acknowledgement of your report. Once an issue is confirmed
and fixed, a patched release is published and the reporter is credited unless
they prefer to remain anonymous.

## Supported versions

codemeld is pre-1.0 and ships from a single active line of development. Security
fixes land on the latest release; there is no long-term-support branch yet.
Please upgrade to the most recent version before reporting an issue.

## Security model you should know about

codemeld is an agentic editor, so two parts of its design carry real risk if
misused. Understanding them helps you report meaningful issues and operate it
safely.

- **It can run shell commands.** An LLM-driven agent proposes commands and edits
  that codemeld can execute on your machine. There is deliberately no "approve
  everything" or opt-out mode. The permission system is the front door for
  codemeld's own tools and for every shell command that runs outside the
  confinement boundary. How a shell command is authorized depends on the mode
  and on a self-test codemeld runs at startup. A command keeps the mode it was
  authorized under for all its stages, even if you switch modes while it runs.
  - **Self-test passed (Linux amd64/arm64 only).** Plan and Auto edits commands —
    including the version-control tools' commands and child agents' commands —
    run inside a mandatory boundary (Landlock ABI 3 or newer, seccomp,
    `no_new_privs`, resource limits, a fixed environment) with no ordinary
    command prompt. No setting turns it off. Plan may write nothing except
    `/dev/null` and open no sockets. Auto edits may write the project's top-level
    files and folders, except `.codemeld` and any entry that is a symlink to the
    project root, to protected state, or to somewhere outside the project, plus a
    private temp folder for the session. Blocked paths are carved out of both. No
    confined command can read `~/.codemeld` or write `~/.codemeld` or
    `<project>/.codemeld`. In Auto edits, a recognized network, deletion or
    history-rewrite command asks (allow once or deny); deletion or history
    rewrite by an unrecognized program runs confined without asking, and a literal
    command codemeld cannot split into stages gets an ordinary prompt. Approving
    network access adds internet sockets for that one command. The status bar
    shows `sandbox: on`.
  - **Self-test passed, then a settings file's blocked-path list breaks.** Plan and
    Auto edits commands stay confined, and every shell command asks until the
    file is fixed, except one you already denied this turn; version-control tool
    calls do not ask. The status bar shows `sandbox: unavailable`; `/status` and
    headless output add the reason.
  - **Self-test failed, or an unsupported OS, architecture, or kernel.** Commands
    run unconfined with ordinary permission prompts (Plan still refuses mutating
    commands), and the status bar shows `sandbox: unavailable`; `/status` and
    headless output add the reason as `sandbox: unavailable (reason)`. The
    reason names the failure — for example, a Landlock ABI below 3, which Linux
    kernels before 6.2 have.
  - **Build mode** always runs commands unconfined with ordinary prompts
    (`sandbox: off` on a confined host).

  `sandbox: unavailable` alone does not mean commands run unconfined: its reason
  tells a broken settings file apart from a failed or unsupported self-test. The
  session record keeps the underlying value — `constrained`, or `refused` with
  its reason — which `codemeld sessions summary` reports. If the boundary cannot be set up for a command, that command
  fails with the error, and codemeld never re-runs it outside the boundary.
  Treat a flaw that lets an action run without the expected permission prompt,
  or run unconfined where it should be confined, as a security issue.

- **It stores provider credentials locally.** Provider API keys and login
  session state are kept as plaintext in your per-user settings file
  (`~/.codemeld/global/settings.yaml`, created with `0600` permissions) when not
  supplied through the environment. You can keep the OpenAI Platform key out of
  that file by setting `OPENAI_API_KEY` instead — see
  [`docs/environment-variables.md`](docs/environment-variables.md). Because this
  file can hold plaintext keys and session tokens, never commit it to a
  repository, paste it into a bug report, or sync it to untrusted locations.

### What the confinement boundary does not cover

These gaps are known and accepted. Reports that show one of them reaching
further than described here are still welcome.

- **Same-user signals.** A confined command can signal any process of your
  account, codemeld and your editor included.
- **File metadata in Auto edits.** A command can change permissions, ownership,
  extended attributes, and timestamps on any file your account owns, including
  blocked paths and codemeld's own security state. For example, it can make a
  blocked credential file readable to another account, or make codemeld's
  settings unreadable. The last of these puts the session into the
  broken-settings state, where every command asks.
- **Other metadata routes in Plan.** Plan denies the ordinary metadata calls;
  a kernel route to file metadata outside that deny list stays open.
- **`/proc` visibility.** A command can list processes and read their command
  lines, but not their environment or memory.
- **Kernel vulnerabilities and resource exhaustion.** A kernel bug can break
  any boundary. Resource limits bound ordinary cases only, not total disk use,
  memory, or descendants that leave the command's process group.
- **No per-command intent review.** Any program may run inside the boundary,
  including one that a hostile file in the repository suggests.
- **Output reaches the model.** What a command reads appears in the transcript
  and is sent to your model provider. Blocked paths and the web tools' approval
  prompts bound this, not the socket block.
- **Host processes watching writable folders.** A process outside the boundary
  that watches a write root or the session temp folder can upload or run what a
  command writes there, or read from a FIFO or socket file the command creates
  there.
- **An approved network command is an upload channel** to any address,
  loopback and the local network included, and every process it starts
  inherits that reach.
- **Authorized writes can still corrupt.** A command can empty or garble any
  file it may write.

Outside the boundary — Build mode, or any host where the self-test did not pass
— a shell command has your account's full authority once it is allowed to run.

### Network destinations

codemeld itself connects only to:

- the LLM providers you configure, at the base URL you set, for model
  requests and model discovery;
- `https://auth.openai.com` (login, token refresh, logout) and
  `https://chatgpt.com/backend-api/codex` (model requests), only if you use the
  ChatGPT subscription login;
- Exa at `mcp.exa.ai` for `web_search`, and the page and redirect hops of a
  `web_fetch`.

Model requests to a configured provider, and ChatGPT login, token refresh, and
logout, refuse redirects. Only `web_fetch` follows redirects, and it authorizes
each hop on its own host.

Model requests and model discovery, ChatGPT login, token refresh, and logout,
and `web_search` honor the standard proxy variables: an `https://` request goes
through the proxy named by `HTTPS_PROXY` and an `http://` request through
`HTTP_PROXY`, and a host matching `NO_PROXY` is reached directly. With no
matching variable set, the request connects directly. `web_fetch` always
connects directly.

The web tools are advertised by default and can be removed with
`web_research.enabled: false` in the global settings file. Every web call
needs a human approval or a matching grant for that exact host and tool, in
every mode; enabling the tools or supplying a key is not authorization. An
allow-once answer covers that host and tool for the rest of the turn. A
redirect changing scheme or port requires a fresh one-time confirmation even
when the hostname has a project grant. A search never fetches the pages it
lists. Shell commands you allow are separate: outside the boundary they have
your account's ordinary network access. Any other network call codemeld makes
itself is a bug — please report it.
