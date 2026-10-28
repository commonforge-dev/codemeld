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
    `no_new_privs`, resource limits, and codemeld's own environment minus
    withheld and secret-looking variables, under a fixed table for `PATH`,
    `HOME` and the temp folder) with no ordinary command prompt. No setting
    turns it off. Plan may write nothing except
    `/dev/null` and open no sockets that reach another process; the only socket
    either mode may create is a Unix stream or seqpacket socketpair, whose two
    ends stay connected only to each other; datagram socketpairs are denied, and
    the same socketpair rule holds in the approved network variant. Auto edits may write the project's top-level
    files and folders, except `.codemeld` and any entry that is a symlink to the
    project root, to protected state, or to somewhere outside the project, plus a
    private temp folder for the session, plus each folder declared in
    `writable_folders`. While no settings file is broken, codemeld's own edit,
    create and make-folder tools may also write inside a declared folder in Auto
    edits without a prompt, and its delete tool may remove an entry inside the
    project or a declared folder, though never the project folder or a declared
    folder itself; move gains no authority from a declared folder. Commands see the session's private temp folder as `TMPDIR`, and
    codemeld adds no other temporary write grant: `/tmp` and the `$TMPDIR`
    codemeld was launched with are writable only through an effective declared
    `writable_folders` entry covering their resolved location, or when that
    location is within a granted top-level project entry (the project grant
    never covers the project root itself, `.codemeld`, or an entry resolving
    outside the project). Blocked paths and the protected
    `.codemeld` folders are carved out of every one of these, and `/dev/shm`
    itself is never writable. A write folder that the grant of another write
    folder already covers (for example, a private temp folder inside a declared
    writable folder) is never granted on its own, so replacing it with a symlink
    gives commands no access to the symlink's target. A declared folder under
    `/dev/shm` is not covered by `/dev` or `/dev/shm`, since `/dev/shm` is carved
    out of them, so it keeps its own grant; its parent stays unwritable. No
    confined command can write `~/.codemeld` or `<project>/.codemeld`, or read
    `~/.codemeld`, with one exception: confined commands may read and run files
    in `~/.codemeld/skills` when the conditions in
    [`docs/skills.md`](docs/skills.md#global-skills-and-the-sandbox) hold. The
    rest of `~/.codemeld` stays unreadable, skills stay unwritable, and
    codemeld's file tools still refuse skill paths. In Auto edits, a command
    with a recognized network or history-rewrite stage asks (allow once or
    deny), wherever a deletion sits in the chain. Every other command runs
    confined without asking: file deletion such as `rm`, a command codemeld
    cannot split into stages, and deletion or history rewrite by an
    unrecognized program. Version control brings back committed content only,
    so a deleted file loses its uncommitted edits and an untracked or ignored
    file is gone, the same loss an overwrite causes. A recognized command is
    also found inside a visible `bash -c` or `sh -c` body and behind `command`,
    `nice`, `nohup`, `time` or `xargs`. Approving network access adds internet
    sockets for that one command. The status bar shows `sandbox: on`.
  - <a id="broken-settings"></a>**Self-test passed, then a settings file's blocked-path list breaks.** Plan and
    Auto edits commands stay confined, and every shell command asks until the
    file is fixed, except one you already denied this turn; a recognized file
    deletion asks again with allow once or deny only; version-control tool
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

### Project approval state

`~/.codemeld/global/approved-projects.yaml` holds the project roots you approved,
and nothing else. It lives outside every repository, and the structured file
tools refuse to write it. Deleting it discards those approvals: the next launch
on a terminal asks again for a project that has its own codemeld settings or
version-control templates, while a project with none of those is not asked
about. A non-interactive run never prompts and never recreates the approvals,
though it still honours approvals already in the file. An older
`~/.codemeld/global/trust.yaml` may still be present; it is no longer read and
can be deleted. See
[`docs/approvals.md`](docs/approvals.md#project-approval-for-cloned-repositories).

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
  including one that a hostile file in the repository suggests. In Auto edits,
  text piped into a shell (`echo 'rm -rf x' | bash`), a script's contents, and
  arguments `xargs` reads while it runs are not inspected, so a recognized
  command hidden there runs confined without asking; visible `-c` bodies and
  wrapped commands are checked.
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
- **Subfolder swaps around a carved-out path.** When a write folder holds a
  blocked or no-write path, codemeld grants that folder's subfolders one by
  one, by name. A program left running from an earlier command could, with
  exact timing, replace one of those subfolders with a symlink between the
  check and the grant, and the command being started would then get write
  access to the symlink's target.

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
