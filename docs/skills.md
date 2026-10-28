# Skills

A skill is a folder of instructions, and optionally scripts or other files, that you or the model
can call on by name. This page covers where skills live, how to write one, how each side starts one,
and what the sandbox lets skill scripts do.

## Where skills live

codemeld reads skills from two folders, one skill per subfolder:

- `~/.codemeld/skills/<name>/`, for every project;
- `<project>/.codemeld/skills/<name>/`, for one project.

Each skill folder holds a `SKILL.md`. Other folders, such as `.claude/skills` or `.agents/skills`,
are not read.

When both folders have a valid skill with the same name, the project's skill is loaded instead of
yours, and codemeld warns at startup. If the project's skill is invalid, it is skipped and your
global skill stays loaded.

Project skills are read whether or not you approved the project's settings; see
[Project approval for cloned repositories](approvals.md#project-approval-for-cloned-repositories).

## Writing SKILL.md

`SKILL.md` starts with YAML front matter between two `---` lines, followed by the instructions:

```markdown
---
name: release-notes
description: Draft release notes from the commits since the last tag.
---
Read the log since the last tag and group the changes by area. $ARGUMENTS
```

- **`name`** must equal the folder name. When it is missing, empty or `null`, the folder name is
  used. A name is 1 to 64 characters of lowercase letters, digits and single hyphens between them,
  such as `release-notes` or `7zip` (the pattern `^[a-z0-9]+(-[a-z0-9]+)*$`).
- **`description`** is required. After surrounding spaces are trimmed it must not be empty, and it
  may be at most 1024 characters (Unicode code points). `null` counts as missing.
- **`disable-model-invocation`**, optional, is `true` or `false`. See
  [How the model uses skills](#how-the-model-uses-skills).

codemeld reads only those three keys. Others, such as `allowed-tools`, `context` or `model`, are
ignored. A key it reads that has the wrong type, such as a `name` that is a number or a
`disable-model-invocation` that is `null` or a string, makes codemeld skip the whole skill.

`SKILL.md` may be at most `agent_instructions.max_file_bytes` bytes, 65536 (64 KiB) by default. This
is the same setting that limits `AGENTS.md`.

A skill that breaks one of these rules is not loaded, and codemeld says why at startup.

## Starting a skill yourself

In the interactive app, type `/<name>`, optionally followed by text: `/release-notes since v0.4`.
codemeld sends the skill's instructions to the model as your message. `codemeld run` has no slash
commands.

The text after the name replaces each `$ARGUMENTS` in the instructions, except one followed by `[`.
A backslash before the dollar sign, `\$ARGUMENTS`, stops the replacement, and both the backslash and
the rest stay in the message. When nothing was replaced and you typed text, codemeld adds it at the
end, after a blank line, as `ARGUMENTS: <your text>`.

codemeld does nothing else to the instructions. Lines starting with `!` are not run, and `$0` or
`$ARGUMENTS[0]` are not replaced: they reach the model as written.

A slash command needs a name that starts with a letter. A skill such as `7zip` loads, but it gets no
slash command, and codemeld warns at startup.

## How the model uses skills

The system prompt lists each loaded skill's name and description and tells the model to call the
`skill` tool when a request matches one.

- With just a name, the tool returns the skill's folder, its instructions, and a list of the other
  files in the folder. The model's argument text is not put into the instructions.
- With a `file` path relative to the skill folder, it returns that one file. The tool only reads;
  it never runs a skill's scripts. Running one is an ordinary shell command.

`disable-model-invocation: true` takes the skill out of the system-prompt list, and the tool refuses
to return its instructions. You can still start it with its slash command. This is not an access
control: the tool's `file` argument still returns the skill's other files, and `SKILL.md` itself as
it is on disk. A skill with this setting and no slash command, such as `7zip`, cannot be started by
either route.

## Names that clash with built-in commands

A skill whose name matches a built-in command or its alias, such as `skills`, `clear` or `new`, is
not loaded, with a startup warning.

`/skills` shows the skills loaded at startup, with each one's description and `SKILL.md` path, and
the ones not loaded, with the reason. It does not show the instructions.

## When changes take effect

Skills are read once, when codemeld starts. Until the next start, edits to `SKILL.md`, its front
matter, and added or removed skills change nothing: not the instructions sent, not the model's list,
and not `/skills`. Reading `SKILL.md` as a file does not refresh them.

The skill tool reads a skill's other files and their list again on every call, and a script run by
the shell is read from disk when it runs.

## Global skills and the sandbox

`~/.codemeld` is protected: codemeld's tools and commands may neither read nor write it. Skills in
`~/.codemeld/skills` are a narrow exception, so their scripts can run.

The exception applies only to Plan and Auto edits shell commands that run confined: on a supported
Linux host whose startup self-test passed (see
[Confined shell commands](../README.md#confined-shell-commands-linux)). It does not apply to Build or
to any command running outside the sandbox. A command you approve outside the sandbox is not checked
against blocked paths at all.

Confined commands may read and run files in the skills folder, at its real location after symlinks,
unless any of these holds:

- the folder is missing or is not a folder;
- its real location is, or holds, a blocked path, as when `skills` is a symlink to `~/.codemeld` or
  to `~`;
- its real location is elsewhere in `~/.codemeld`;
- an entry in your `blocked_paths` covers `~/.codemeld/skills` or lies inside it;
- a settings file's blocked-path list is broken.

The rest stays protected:

- The rest of `~/.codemeld` (settings, keys, sessions, the approved-projects list) stays unreadable.
  A symlink in a skill folder that leads there is still unreadable, but a hard link in a skill
  folder to a file there is readable. Only you can create one.
- Confined commands cannot write any file in `~/.codemeld`, skills included. The separate Auto edits
  gap for file metadata, described in
  [SECURITY.md](../SECURITY.md#what-the-confinement-boundary-does-not-cover), is unchanged.
- codemeld's read, search, list and other file tools still refuse paths in `~/.codemeld/skills`. The
  `skill` tool reads skills itself, and `/skills` shows only the list.
- A read-only shell command that names a path in `~/.codemeld/skills` is refused, as for any path in
  `~/.codemeld`.

Keep no secrets in a skill folder.
