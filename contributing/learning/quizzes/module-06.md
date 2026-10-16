# Quiz — Module 6: Dispatch & runner

Closed-book. Write your answers before opening `module-06-key.md`.

---

**1.** In a 3-stage pipeline, what runs if stage 2 is denied?

**2.** Does the runner interpret shell metacharacters like `$HOME` or `|`?

**3.** How is a structured tool looked up in the registry?

**4.** What does dispatch return for an unknown tool name, and does it prompt the user first?

**5.** What happens to a `;`-joined command like `git status ; rm x` — is it refused, authorized as
one subject, or something else? What about `git status || rm x`, and what does the difference mean
for a direct grant you already hold for `git status`?

**6.** Where do leading `FOO=bar` assignments go — into the authorization subject, or the runner's
environment?

**7.** How is a non-zero exit code (e.g. running `false`) reported — as a Go error or as a result?

**8.** For a `vcs.<action>` tool, which directory is authorized — codemeld's process cwd or the
action's own cwd?

**9.** Does `Exec` cap stdout/stderr at `sessions.max_tool_output_bytes`? Does running a pipeline?

**10.** What does the runner return for a missing binary, and how is the error category derived?

**11.** How does dispatch treat `git status` differently from `sh -c "git status"`?

**12.** Do the stages of a pipe group run one at a time or concurrently? What does that mean for
`yes | head -n 1`, and why does `yes | command -v head` still hang?

**13.** Running a pipeline is an optional capability found by type assertion instead of a method on
`Runner`. Why, and what is the one outcome that sends a pipe group to the sequential loop?

**14.** `PrepareTool` takes a trailing `guard ...securitystate.Policy`. (a) What happens when a
caller passes none? (b) The structured-read preparation path passes none — is that a bug? (c) Where
is the typed refusal it can return recognized, and why must that happen *before* the generic error
adapter?

**15.** A guard refusal reaches the production dispatcher but the session store cannot accept the
`permission_matched` record. What does `Dispatch` return, and does the file tool run? What about raw
`bash` — is a settings-file write through a granted shell command refused the same way?
