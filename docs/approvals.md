# Permissions

This page explains what codemeld does without asking, what it asks about, and what it refuses.
For the security model, including what the shell sandbox does not cover, see
[SECURITY.md](../SECURITY.md). For how the sandbox works and when it is unavailable, see
[Execution capability](architecture.md#execution-capability).

There is no "approve everything" mode, no `--yolo` flag, and no setting that turns the permission
checks off.

## Modes

A mode sets how much the agent may do before it stops to ask. It never replaces the permission
checks. Switch with `/mode <plan|build|auto-edits>` or shift+tab.

| Mode | Reads | Changes through codemeld's own tools | Shell commands |
|---|---|---|---|
| **Plan** | Allowed | Refused without a prompt. Write tools are not offered to the model. | Sandboxed where available (writes and network fail); elsewhere only read-only commands run: proven read-only by codemeld's rules, or, with the opt-in [System One check](system-one.md), judged read-only by a model for one run |
| **Build** (default) | Allowed | Asked, unless a saved approval covers the request | Never sandboxed; asked unless read-only or already approved |
| **Auto edits** | Allowed | Create, edit, make-folder and move inside the project run without asking; with the sandbox on, no settings file broken and the project's settings admitted by [project approval](#project-approval-for-cloned-repositories) at launch, so do create, edit and make-folder in a declared writable folder, the folder itself included; with the sandbox on and no settings file broken, so does a delete inside the project or a declared writable folder; everything else is asked | Sandboxed where available, and then run without asking unless recognized as network access or a history rewrite, or while a settings file is broken; elsewhere as in Build, plus the project's `declared_commands` |

- Auto edits approves only a target that is inside the project after symlinks are resolved, apart
  from the declared folders in [Writing outside the project](#writing-outside-the-project). A move
  needs both ends inside the project. A delete of the project folder or a declared folder itself is
  asked.
- Auto edits' approvals are made per call and are not saved, so switching back to Build takes
  effect from the next tool call.
- A tool call keeps the mode it started with until it finishes, including every stage of a shell
  command. A mode switch applies to later calls.

## Approving a request

When codemeld asks, you choose one of:

- **Allow once**: this call. For the rest of the turn codemeld does not ask again for the same
  tool in the same folder, or the same command in the same folder. A delete or a move that reaches
  this prompt, and a command Auto edits flags as exceptional (below), are asked every time.
- **Allow for this session**: kept in memory until codemeld exits; no settings file is written.
- **Allow in this folder permanently** (*allow in this project* for web access): saved to the
  project's `.codemeld/settings.local.yaml`. Not offered in an unapproved project.
- **Allow globally**: saved to `~/.codemeld/global/settings.yaml` and used in every folder. Not
  offered for web access or in a headless run.
- **Deny**: nothing runs and no approval is saved. The denial is recorded in the session and shown
  to you, and the turn stops after that round, so the model gets no further round to try another
  way. Within that round the same request is denied without asking, except the requests that Allow
  once asks every time and a web request on a non-default scheme or port, which are asked again.
  A refusal by a mode, by the protection of codemeld's settings files and blocked paths, or because
  nobody can approve is different: the model sees it in the next round and may continue another
  way. A file change outside a declared file scope starts as a refusal like yours. The scope comes
  from a headless run's `--files-authorized` and `--files-authorized-delete` flags, or, for a child
  agent, from the `files`, `files_delete`, `files_move` and `files_mkdir` its parent declared; it
  covers codemeld's file tools, not what a shell command writes. When someone can approve, which in
  a headless run means `--prompt-for-approval`, the turn stops as after your Deny, and codemeld does
  not ask you to widen the scope. When nobody can approve, as for every child agent even under the
  terminal UI, it becomes a refusal with no approver and the model may continue another way; after
  repeated refusals of the same call, tool use ends and the model writes its final answer.
  Continuing never carries out the refused change. In Plan the declared scope is not checked: Plan
  refuses the file change as a mode refusal, declared or not.

An approval for a file tool covers a folder and its subfolders, not one file. When you approve a
plain shell command for the session or permanently, you choose what is stored: the exact command,
a prefix such as `go test :*` that covers later `go test` commands, or the whole program (after an
extra confirmation). A command codemeld judges as one piece (below) is stored exactly, except a
simple compound: plain commands joined by `&&`, `||`, `;` or `|`, written bare (`go build ./... &&
gofmt -w a.go`) or as a plain `sh -c '<body>'` with nothing in the body that expands. There you
choose what is stored for each of its stages (`RecognizeSimpleCompoundForGrant`,
`internal/permissions/compound.go`). If a stage runs a
program codemeld treats as destructive, the whole command is stored exactly. Apart from a
global approval, an approval applies in its folder and below.

codemeld writes the shared `.codemeld/settings.yaml` only when you share an approval into it or
remove one through `/settings`, add a shared entry with `/blocked add`, or remove a shared entry
in `/blocked` after you confirm it.

## Reviewing and revoking approvals

`/settings` lists this session's approvals and those saved for this project (yours and shared)
and globally. From there you can revoke an
approval, share a project approval into the shared `.codemeld/settings.yaml`, or remove one from
it. codemeld's own file and version-control tools never change its settings files or the project
approval list; when the model needs a settings change, it asks you to use `/settings`.

## Project approval for cloned repositories

A cloned repository is written by someone else, and its settings could otherwise grant permissions,
set the mode, or choose the commands codemeld runs for version control. So until you approve a
project folder, codemeld ignores its project settings: both settings files in its `.codemeld`
folder, its version-control templates, and its blocked paths. Project skills and AGENTS.md are read
independently of project-settings approval; see [Skills](skills.md).

codemeld asks at startup, on a terminal, when the folder has its own codemeld settings or
version-control templates. The approval names the folder, not the files' contents, so later
changes to those files take effect without another question. If you decline, it asks again next
launch. Approved folders are listed in
`~/.codemeld/global/approved-projects.yaml`. A headless run uses that list but never asks and never
adds to it.

## Reading files

codemeld's read, search and list tools read a path the model names, inside or outside the project,
without asking, unless the path is blocked. A path that escapes the project without being named, for
example through `..` or a symlink inside the project, is refused before anything is read. If a
settings file is broken, so that the blocked-path list is unknown, a read outside the project asks.

Several project reads may run at the same time, up to `agent.max_concurrency`, and each is
recorded in the session. Every other tool call runs on its own, in the order the model asked for
it, except that child-agent calls that cannot reach the same files may also run at the same time.

## Blocked paths

`blocked_paths`, in the global settings file or either project settings file, lists files and
folders codemeld's tools and sandboxed commands may neither read nor write. Entries from every file
are combined, so one file cannot remove another file's entries. `~/.codemeld` is always blocked,
with one exception for sandboxed commands: they may read and run files in `~/.codemeld/skills`, under
the conditions in [Skills](skills.md#global-skills-and-the-sandbox). Those files stay unwritable, and
codemeld's file tools still refuse them. A read-only shell command that names a blocked path, or runs inside one, is refused; one that names a
folder containing a blocked path asks instead of running automatically. Outside the sandbox, a
command you approve is not checked against blocked paths.

## Writing outside the project

A create or edit outside the project is never silent: it asks, unless a saved approval already
covers that folder, and the approval covers the real folder after symlinks are resolved. The one
exception is a folder you declare in the project's `writable_folders`: in Auto edits, while shell
commands are sandboxed, no settings file is broken and the project's settings were admitted by
[project approval](#project-approval-for-cloned-repositories) at launch, create, edit and make-folder inside a
declared folder run without asking, and so does a delete inside it, though not of the declared
folder itself (`sandboxedDelete`, `internal/permissions/orchestrate.go`). A declared folder never
approves a move.

A file tool creates, writes or deletes through the folder it checked and never follows a symlink
in the last step, so a folder or symlink swapped in after the check cannot redirect it.

## Deleting files

`delete` is never covered by an approval for creating or editing. In Auto edits, while shell
commands are sandboxed and no settings file is broken, a delete inside the project or a declared
writable folder runs without asking (`sandboxedDelete`, `internal/permissions/orchestrate.go`).
A delete of the project folder or a declared folder itself, of a target outside both, in Build,
without the sandbox, or while a settings file is broken is asked; Plan refuses it. A run limited by
`--files-authorized-delete`, or a child agent's declared deletes, keeps that limit
(`declaredScopePosture`). It
removes one file, one symlink (not what it points at) or one empty folder; it refuses a folder that
still holds anything, so it can never remove a whole tree.

## Shell commands

**Read-only commands run without asking, in every mode**, except that in Plan and Auto edits, while
shell commands are sandboxed, a broken settings file makes every shell command ask. A command counts as read-only only when
codemeld can tell from its exact text that it cannot write a file, start another program, reach the
network, or leave its scope: for example `ls`, `cat`, `grep`, `git log`, `hg status`, or a
`find . -name '*.go'` listing. When codemeld cannot tell, the command is treated as a change.
Read-only is not the only way to run without a prompt: the sandbox in Auto edits, a saved approval,
a declared command and the System One check can also let a command run, as this page explains.
Options from configuration codemeld did not check are kept out: when a read-only command runs
automatically outside the sandbox, a Mercurial command ignores your hgrc files and `jj` its
configuration, and approving the same command at a prompt runs it with your configuration. `rg`
never receives `RIPGREP_CONFIG_PATH`.

These commands are proven read-only by codemeld's own rules. In Plan and Auto edits only, never
Build, the opt-in [System One check](system-one.md) can also allow a `direct` or `literal` shell
command those rules could not prove and that would otherwise ask (or be refused in Plan). It first
runs codemeld's structural checks, then asks a model, so such a command is judged read-only, not
proven. It allows that one run only: no approval is saved and nothing is kept for the rest of the
turn (`prePromptCheck`, `internal/permissions/orchestrate.go`).

**Here-strings and bare `env`.** A command that feeds one word to standard input with a
here-string (`jq -n 'input' <<< '1'`, `grep x <<< 'a b'`) is judged by the programs it runs, as
`printf '%s\n' word | jq …` would be. The word must be one single-quoted word or a bare word with
no `$`, `\`, backtick, `~`, wildcard, brace or shell operator. Any other word, a descriptor before
the operator (`0<<<`), a heredoc (`<<`), a here-string with no command before it, or a remaining
redirection to a file keeps the command a change (`stripClassifierHereStrings`,
`internal/permissions/planshell.go`). This check removes only here-strings, redirections to
`/dev/null` and `2>&1`/`1>&2` (`stripNullRedirects`); the wider redirection removal described below
applies only to sandboxed commands in Auto edits. The command still runs exactly as written through
`sh -c`, and an exact approval saved for it still matches only that text, here-string word
included. Running it needs a system `sh` that accepts `<<<`: where it does not (dash, FreeBSD `sh`)
the shell reports a syntax error and runs nothing, and codemeld neither picks another shell nor
rewrites the command. `env` with no arguments only prints the environment, as `printenv` does, so
it is read-only alone or in a chain (`env | grep -i shell`; `bareEnvTokens`). `env` with any
option, assignment or program, and a path spelling such as `/usr/bin/env`, are judged as before.

**Declared commands.** In an approved project, `declared_commands` in `.codemeld/settings.yaml`
lists command prefixes that Auto edits runs without asking when commands are not sandboxed. It
covers only a plain command with no leading `VAR=value` and no cleared environment.

**Chains are checked stage by stage.** In a chain joined by `|`, `&&`, `||` or `;`, each stage is
judged on its own: read-only stages run without asking and the others ask (or, without the
sandbox, are refused in Plan). Stages that need approval share one prompt, and one denied stage
stops the whole chain before anything runs. A command codemeld cannot split safely, for example
one with `sh -c`, a redirection to a file, or a `$(...)` inside double quotes, is judged as one
piece and needs an approval of the whole command (a simple compound, bare or in a plain `sh -c`,
can be approved stage by stage, see [Approving a request](#approving-a-request)), except with the
sandbox in Auto edits and
valid settings. There,
every command codemeld accepts runs in the sandbox without asking unless one of its stages is
recognized as network access or a history rewrite (`SandboxedAutoEditsAuthority`,
`internal/permissions/exceptional.go`). To find those stages codemeld splits the command itself,
after removing redirections to a fixed file name (one with no `$`, backtick, `~` or wildcard), and
judges each stage that is a plain command, a plain command after leading `VAR=value` assignments
whose values have no `$`, backtick, `~` or wildcard (judged by the program after them), or one of
these shell and wrapper forms:

- `bash` or `sh` without `-c` (`bash --version`, `sh -x script.sh`, `bash -o pipefail script.sh`,
  or a bare `bash` reading standard input) runs like a script; a script name, when given, must have
  no `$`, `~` or wildcard.
- `bash -c '<body>'` or `sh -c '<body>'`, also with other options (`bash -ec`, `sh -lc`), anywhere
  in a chain: the body goes through the same redirection removal and checks, is split, and each of
  its stages is judged by these rules, so `bash -c 'git push'` asks for network access. The body
  and the words after it must not expand when the outer command is read (`bash -c "$X"` is not
  split).
- `command`, `nice`, `nohup`, `time` and `xargs` are judged by the command they run, so
  `nice git push`, `time curl x` and `xargs git push` ask as `git push` and `curl x` would. Each
  accepts only its own option list (`wrapperOptionArgs`, `xargsOptionArgs`) and `--`. `xargs` with
  no command runs `echo`. Up to three wrappers may be nested; a fourth is not split.
- `command -v`, `command -V` and `type` (optionally with `-a`, `-f`, `-p`, `-P` or `-t`) followed
  by one or more names only print where each name resolves.

Every stage is checked, so a deletion anywhere in the chain does not hide the others:
`rm x && git rebase main` and `rm x | hg strip .` ask for a history rewrite, and `rm x; curl y`
asks for network access. File deletion itself (`rm`, `git clean`, `find . -delete`) runs without
asking. A command codemeld cannot split also runs in the sandbox without asking, as an unrecognized
script does. That covers a program name holding a `$` (`$X -rf .`), `env` with assignments or
`-i`, assignments before `env`, `bash`, `sh` or a wrapper, a `-c` body holding another `bash -c` or
`sh -c` stage, `bash`, `sh` or `env` run by a wrapper, a shell or wrapper named by a path
(`/bin/bash`), a shell option bundle holding `o` or `O` (`bash -co pipefail`) or `+c`, an option
word or option value that expands (`bash -$FLAGS`, `xargs -n $N`), a wrapper option outside its
list (`xargs --unknown`), `exec`, `eval`, `source`, `.`, `builtin`, control words such as `if`,
and a `$(...)`, backtick or newline inside a quoted `-c` body. In the command itself, an unquoted
`$(...)`, a backtick or a newline is refused outright before anything is asked (`SplitCommand`,
`internal/permissions/pipeline.go`).

Text a shell reads from standard input or a script file, and arguments `xargs` reads while it runs,
are not inspected: `echo 'rm -rf x' | bash` runs in the sandbox without asking, as `bash x.sh`
does.

A here-string that passes the read-only check's word rules above, and a bare `env`, are split like
any other stage: `jq -n 'input' <<< '1'` and `env | grep -i shell` run without asking, while
`curl x <<< y` still asks for network access (`classifierStages`,
`internal/permissions/exceptional.go`). A command that has such a here-string and also any `bash`
or `sh` stage without `-c` is not split, wherever that stage sits: after a pipe
(`cat <<< 'rm x' | sh`), in a visible `-c` body (`bash -c 'sh' <<< 'rm x'`), or in an unrelated
part of the chain (`jq . <<< x; bash script.sh`). Like `printf 'rm x' | sh`, it runs in the sandbox
without asking. This classification is no guard against what a shell runs from standard input; the
sandbox is the boundary.

A leading `cd <folder> &&` is not part of that check: `SplitCommand`
(`internal/permissions/pipeline.go`) removes it, and `DispatchShell` (`internal/dispatch/shell.go`)
judges and runs the rest of the command with that folder as its scope.

**The Linux sandbox.** On a Linux amd64 or arm64 host that passes codemeld's startup self-test,
Plan and Auto edits commands run inside a sandbox, and the sandbox, not a prompt, is what allows
them. Plan commands cannot write files or reach the network. Auto edits commands may write the
project (except its `.codemeld` folder), a private temp folder for the session, and the folders
listed in `writable_folders`. Each command reads that list when it starts, so a folder added or
removed mid-session applies from the next command without a restart; a command already running
keeps the folders it started with. While the project settings file cannot be read or is invalid,
or any settings file is broken, commands get none of the declared folders, and the next command
after the settings are fixed gets them back. git stops on a global config file it cannot read, so
while `blocked_paths` covers `~/.gitconfig` or `~/.config/git/config`, sandboxed commands get
`GIT_CONFIG_GLOBAL=/dev/null` and git ignores both of those files (`confinement.prepare` in
`internal/bootstrap/confinedrunner.go`). Unblocking only one of them is not enough: git reads them
again only when neither path is covered.

Sandboxed commands get the environment codemeld was started with, so a tool that finds its files
through a variable, such as mise with `MISE_DATA_DIR`, keeps working. codemeld reads it once, at
startup (`StartTUI`, `HeadlessDriver.Run`), and withholds three kinds of entries (`runner.InheritedEnvironment` in
`internal/runner/childenv.go`): names that change how programs load or what they connect to
(`LD_*`, `GIT_*`, `HG*`, `SSH_*`, `DBUS_*`, `XDG_*`, `*_PROXY`, `BASH_ENV`, `DOCKER_HOST`, and
others), secret-looking names (containing `TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, `COOKIE` and
similar, ending in `_KEY`, `_PASS` or `_PW`, or starting with `AWS_`, `GITHUB_`, `CODEMELD_` and
similar), and values holding a URL with a username and password (`scheme://user:password@`).
`PATH`, `HOME`, `PWD`, `TMPDIR`, `GOCACHE`, `SHELL`, `TERM`, `LANG` and `LC_ALL` always come from
codemeld's fixed table, and a command's own `VAR=value` assignment replaces an inherited value
(`confinement.prepare`). Name matching cannot catch every secret: one stored under an unusual name,
such as `MYAPP_PW2`, reaches sandboxed commands. A sandboxed command cannot open a network
connection itself, but such a secret can still leave through the command's output (which reaches
the transcript and the model provider), through a network command you approve, or through a
program outside the sandbox that watches a folder the command can write. Build mode runs approved
commands with codemeld's full environment (`commandEnv` in `internal/runner/descendants_linux.go`).

In Auto edits with valid settings, a sandboxed command that codemeld recognizes as network access
or a version-control history rewrite (such as `curl`, `git push`, `git reset --hard`, `hg strip`)
still asks, with allow once or deny only, and runs inside the sandbox when approved; only an
approved network command runs with network access (`confinement.policy`,
`internal/bootstrap/confinedrunner.go`). A saved approval never answers it (`resolveWithoutPrompt`,
`internal/permissions/orchestrate.go`). Every other command runs in the sandbox without asking
(`autoEditsPosture`): file deletion such as `rm`, a command codemeld cannot split, and a script or
program it does not recognize, so any of them can delete or rewrite files inside the writable
folders. Version control brings back committed content only: a deleted file loses its uncommitted
edits, and an untracked or ignored file is gone, the same loss an overwrite causes. If a settings
file breaks after the self-test passed, every sandboxed command asks until it is fixed, and a
recognized file deletion is again asked with allow once or deny only (`exceptionalAuthority`,
`internal/bootstrap/promptgate.go`).

**Without the sandbox** (Build mode, or a host where the self-test did not pass) a command runs with
your account's full authority once it is allowed. Plan refuses every command that is not proven
read-only, unless the opt-in [System One check](system-one.md) allows that one run (`planPosture`,
`internal/permissions/orchestrate.go`).

**Version-control tools.** codemeld's structured version-control actions run without asking only
when they are read-only and come from a source codemeld trusts: its built-in templates, an
unchanged copy of them, or a global template that runs exactly the built-in read-only command. A
repository's own `.codemeld/vcs` templates can never mark an action read-only.

## Web access

`web_search` and `web_fetch` never run without your approval, in any mode: each call needs an answer
at the prompt or an approval for that exact host and tool, for this session or saved in the
project. A request on a non-default scheme or port asks every time, allow once or deny only.
Enabling the tools or adding an Exa key is not an approval. A search reaches only `mcp.exa.ai`
and never opens the pages it lists; reading one is a separate `web_fetch` the model must ask for.
`web_fetch` checks every redirect hop on its own host, and refuses loopback, private-network and
cloud-metadata addresses even for an approved host.

## Headless runs: `codemeld run`

A headless run has nobody to ask, so it is fail-closed: a call that no saved approval, mode rule,
or sandbox allows is denied, the model is told, and the run continues. Plan's refusals apply as in
the terminal UI. At the end, the run prints which requests were denied and how to approve them.
The one exception is the opt-in [System One check](system-one.md): in Plan and Auto edits, after
codemeld's structural checks, it can allow one run of a shell command a model judged read-only,
with no approval saved and nothing kept for the turn. When it does not allow the command, the
denial stays, and any failure or pause note is added to its reason
(`internal/bootstrap/headless.go`).

- `--prompt-for-approval` asks on the terminal instead of denying. It needs a terminal on stdin and
  exits before starting without one. Its choices are allow once, deny, allow for this session, and
  allow in this project (offered only for an approved project). It never offers a global approval.
- `--files-authorized <path>` and `--files-authorized-delete <path>` (repeat each once per path)
  name the only files the run may create or edit, and delete. With either flag set, nothing else
  can approve a file change, not a saved approval, a mode, or a prompt; making a folder or moving a
  file is not allowed at all. Plan still refuses the change. These flags cover codemeld's file tools
  only, not what a shell command writes.

## What the model is told

Every turn starts with one system message: codemeld's instructions for the active mode (plus notes
for some models), a description of the environment, and every `AGENTS.md` codemeld found (the
global one and those from the filesystem root down to the launch folder). A `/compact` summary is
sent as a user message marked as reference material, never as part of the system message, so text
copied into a summary gains no authority.
