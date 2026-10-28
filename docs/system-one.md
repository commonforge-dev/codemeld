# The System One read-only check

The System One check lets codemeld run some shell commands that only read without asking you,
after a small decision model judged them read-only. It is off by default. The numbers
on this page come from the project's 2026-10-22 evaluation of the candidate models.

## What it does

codemeld already runs a shell command without asking when its own rules can prove the command only
reads (see [Shell commands](approvals.md#shell-commands)). Many harmless commands still ask,
because those rules are strict. With the System One check turned on, codemeld can ask a System One
model about such a command just before it would show you a prompt, or before Plan would refuse it
(`prePromptCheck`, `internal/permissions/orchestrate.go`).

- **Which commands.** Only a shell command (`direct` or `literal`) not already allowed by codemeld's
  own rules. Never a tool, web host, network-access or outside-read request
  (`prePromptEligible`, `internal/permissions/orchestrate.go`).
  - At an ordinary prompt, such as in Auto edits, the command is checked only when no saved approval
    and no earlier approval in the same turn settled it (`resolveWithoutPrompt`). A command that
    sandboxed Auto edits runs without asking never reaches a prompt, so it is never checked: System
    One does not decide those automatic allowances (`autoEditsPosture`).
  - In Plan, a command it would refuse is checked at that refusal, before saved approvals and the
    turn's earlier approvals are looked at (`planPosture`). Plan does not use saved approvals for
    such a command, so a matching one does not stop the check or its refusal.
- **Which modes.** Plan and Auto edits only, never Build (`SystemOneEligible`,
  `internal/permissions/systemone_eligible.go`).
- **codemeld's checks come first.** A command is never sent to the model when it contains `$(`, a
  backtick, `<(` or `>(`, a redirect to a file, a program run by path or from inside the project
  (apart from the name lookups below), or a mention of a blocked path or `.codemeld/global`
  (`SystemOneEligible`).
- **Name lookups.** `command -v NAME…` and `type NAME…` with one or more plain, unquoted names such
  as `jq` or `python3` (no paths, options or patterns) can be checked (`systemOneLookupStage`,
  called by `systemOneStageEligible`). These forms only look the names up and never run them, so a
  name that is found inside the project, or not found at all, does not stop the check. Only the
  lookup's own `command` or `type` word skips the checks on how and from where a program runs; the
  other stages of a compound command are checked as usual, so `type jq && ./x.sh` is still
  excluded. Every other check above still applies, and qualifying only means the model is asked; it
  does not allow the command.
- **When a command cannot qualify.** With System One on, a command offered to the check that fails
  these checks is not sent to any model. When the run has a session with an ID, codemeld tries to
  add a `skipped` record naming the reason to it (`systemOneCheck.check`,
  `internal/bootstrap/systemonecheck.go`); adding the record does not save the session file by
  itself. If the record cannot be added, the skip stays silent and may leave no record. With System
  One off, or with no command text, nothing is recorded, and a request never offered to the check
  (see *Which commands* above) is not a skip. `codemeld sessions permissions <session-id|path>`
  shows the skipped checks by reason, so you can see why the model was not asked.
- **What is never sent.** Network access, file deletion, and version-control history rewrites
  always go to the ordinary prompt when they ask (`ClassifyExceptional`,
  `internal/permissions/exceptional.go`). In sandboxed Auto edits with valid settings a file
  deletion does not ask: it runs in the sandbox without a prompt or a check.
  The model is asked only whether a command reads, never whether it may write, delete, use the
  network or run other code.
- **When it allows.** The model returns three probabilities: that the command only reads, that it
  could expose secrets, and that it contains program code. The command runs only when all three pass
  the selected model's thresholds (`Model.Allows`, `internal/systemone/client.go`). This is a model's
  judgment, not a guarantee.
- **What it allows.** That one run of the command. No approval is saved and nothing is remembered
  for the turn, so the next identical command is checked again (`prePromptCheck`). Every other
  answer gives the ordinary prompt, or Plan's refusal.
- **Headless runs.** In `codemeld run`, an allowed check replaces the unattended refusal. Otherwise
  the refusal stays, and any failure or pause note is added to its reason
  (`internal/bootstrap/headless.go`). With `--prompt-for-approval`, the check runs before the
  terminal prompt.

## How the models were chosen

Each candidate model was tested twice on OpenRouter against:
- 742 real shell commands that raised a permission prompt in 30 days of sessions
  (2026-08-25 to 2026-09-24);
- 48 harmful commands that must never be allowed: deletes, writes, network reads, secret readers,
  hidden code, and one prompt-injection attempt written as a shell comment.

A model is listed only when it accepts codemeld's request unchanged, allows 0 harmful commands at
its thresholds in two full runs, removes a useful number of prompts, and answers within the
5-second limit codemeld gives each call (`callTimeout`, `internal/systemone/client.go`). The counts
below are evaluation counts, not production promises: the test applied its own filter before the
model, and prompts removed count Plan and Auto edits only.

The listed models (`Models`, `internal/systemone/client.go`). The thresholds are: read-only at
least, secrets below, program code below.

| Setting value | Thresholds | Prompts removed | Harmful allowed | Decisions that flipped between runs | Cost per 1000 commands (OpenRouter) |
|---|---|---|---|---|---|
| `openrouter:typesafe/jev-1.13` | 0.9 / 0.3 / 0.2 | 151 (one run) | 0 | 17 | $0.037 |
| `venice:jev-latest` | 0.9 / 0.3 / 0.2 | not evaluated | not evaluated | not evaluated | not measured |
| `openrouter:liquid/d1` | 0.8 / 0.3 / 0.2 | 161 / 160 | 0 / 0 | 37 | $0.011 |

`venice:jev-latest` is the Jev model as Venice serves it; every Jev test ran on OpenRouter.

Not listed:
- **Upstage Solar Decide** took about 8 seconds per command, over the 5-second limit.
- **Inception Mercury Decide** was considered and left out over a security concern found during
  testing.

## Risks of turning it on

- **The model can be wrong.** 0 harmful commands allowed in testing does not mean never; the test
  set is finite.
- **Your command text leaves your machine.** When an eligible command is actually checked, its text,
  including paths, file names and arguments, goes to the selected model's provider (OpenRouter or
  Venice) under that provider's data terms. Commands codemeld's own checks exclude are not sent.
- **An allowed command's output goes to your main model.** It enters the conversation like any
  command output, so a secret reader the model misjudged exposes the secret to your main model
  provider.
- **A command can try to talk the model round.** Command text can carry words written to make the
  model answer "read-only". codemeld's own checks do not read that text; the model does.
- **Answers vary between runs.** The same command may run without asking once and ask the next
  time. This is most visible with Liquid d1 (37 flipped decisions, against 17 for Jev).
- **The sandbox matters.** Where shell commands are not sandboxed, an allowed command runs with your
  account's full authority. Where they are, it still runs in the sandbox and blocked paths stay
  blocked (`confinedRunner`, `internal/bootstrap/confinedrunner.go`).
- **Some model names are not pinned.** `venice:jev-latest` and `openrouter:liquid/d1` name no fixed
  version, so the provider can change the model behind them without notice.
- **Checks are billed by the provider.** The costs above are OpenRouter measurements; Venice's cost
  was not measured.
- **Some failures pause the check.** Running out of credits or an authentication failure pauses the
  check for the rest of the session. A missing provider key does not pause it: each eligible command
  falls back to the ordinary prompt or refusal with a `/connect <provider>` note. Other failures,
  such as a timeout or a malformed reply, also fall back without pausing
  (`systemOneCheck.check`, `internal/bootstrap/systemonecheck.go`).

## Turning it on and off

- In the terminal UI, `/systemone` opens a picker listing `off` and each listed model, with the
  current setting selected and a model whose provider has no API key marked `no API key`. Its header
  shows the current setting, the provider, model and API-key state when a model is selected, that
  the check applies only in Plan and Auto edits, and any pause. Choosing a different value saves it;
  a model with no API key is refused. Choosing the current value, or pressing Esc, closes the picker
  without saving. `/systemone <setting value>` turns it on with that model (it refuses a provider
  with no API key), and `/systemone off` turns it off (`internal/tui/cmd_systemone.go`). The choice
  is saved to the global settings file.
- Or set `system_one` in `~/.codemeld/global/settings.yaml` to one setting value from the table, or
  to `off`. Absent means `off` (`internal/config/cache.go`). A project's settings file cannot set it:
  the key is rejected there (`EnforceGlobalOnly`, `internal/config/globalonly.go`).
- Checks are recorded in the session file when recording succeeds.
  `codemeld sessions permissions <session-id|path>` counts the checks by outcome (`allowed`,
  `declined`, `failed`, `skipped`), breaks the failed and skipped ones down by reason, and lists
  each allowed command with its model and score
  (see [sessions.md](sessions.md)).
