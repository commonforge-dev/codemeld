# Quiz — Module 12: Agent Modes, System Prompt & Tool Advertising

_Last updated: 2026-08-22_

Closed-book. Write your answers before opening `module-12-key.md`. The goal is to find your
gaps, not to score — anything you can't answer from memory is what to re-read.

> Questions 3–6b cover the assembled system message, environment block, and shared file-scope
> guidance. Module 12 now keeps only the mode-specific view of those; their full lifecycle lives
> in [`system-prompts.md`](../system-prompts.md) (this quiz is the shared self-test for that
> page), so answer them from there.

---

**1. The three modes.** Name the three interaction modes, their canonical string keys, and in
one phrase what each does to mutating actions (deny / prompt / auto-approve).

**2. Plan enforcement.** Plan is read-only by *enforcement*, not just instruction. Name the
three independent mechanisms that enforce it, and the file/symbol behind each.

**3. Assembly order.** In what fixed order are the sections of the synthetic `system` message
assembled, and which function builds it? One section is optional and model-specific — name it, say
what an unflagged model (no special instructions) ends up assembling, and what happens to an empty
optional section.
> *From the code, not `system-prompts.md`:* which models include the special-instructions section,
> where the active model id comes from, and the exact helper (with its separator) that joins the
> sections.

**4. Empty AGENTS.md.** With **zero** `AGENTS.md` files loaded, is the system message empty?
Why, and which phase-1 behavior does this supersede?

**5. Environment block — included.** List the five facts the environment block states. Which
function formats it?

**6. Environment block — excluded.** Name three things deliberately **excluded** from the
environment block, and the one-sentence reason (give the cache rationale).

**6b. File scope in the shared prompt.** `shared.md` tells the model to stop and ask before
changing a file the request does not clearly require, and not to remove or roll back unrelated
configuration, generated state, user changes, or authorization state. Which code path enforces
that rule, and what happens when a model ignores it? Say why the rule does **not** mean an
accepted "fix X" request now needs a second approval before its own files are edited, and name
the test that fails if the wording is dropped or reworded.

**7. Tool advertising in Plan.** In Plan mode, which tools are advertised? What single piece of
metadata drives the filter, and which function applies it?

**8. The `bash` definition.** Why is `bash`'s advertised definition product-authored *outside*
the tool registry, and in which modes is it advertised?

**9. Posture ordering.** Where in `Authorize` is mode posture evaluated relative to the
real-grant match and the turn cache? Why does the order matter for Plan? One check runs
*before* mode posture — name it, say what turns it on, and say why it must return "handled"
for its denials as well as its approvals.

**9b. Declared write scopes.** `codemeld run` was started with `--files-authorized notes.md`
and nothing else. For that run, say what happens to: an `edit` of `notes.md`; an `edit` of
`other.md` when a folder grant for `edit` covers the project; a `delete` of `notes.md`; a
`mkdir`; and an `edit` of `notes.md` in Plan mode. Which two of those change if
`--files-authorized-delete notes.md` is added? What does a declared delete cover exactly, and
what does a write declaration for `a/b/c.txt` also authorize when `a/` does not exist?

**10. mode_auto records.** When a mode makes a decision (Plan deny, read-only auto-allow, Auto
edits in-scope edit), how is it recorded, and what is *not* created or stored as a side effect?
A declared write scope records the same *shape* under a different `outcome_source` — name it,
say why reusing `mode_auto` would have been wrong, and give the `denied_by` value a declared
miss carries and the one consequence of that choice a headless caller actually sees.

**11. Auto edits in-scope class.** Precisely which requests does Auto edits auto-approve without
a prompt? Name the function and the containment rule it uses. `move` is in the class — what does
it need that the other tools do not, where does that come from, and why is one path not enough?
Name two mutating things Auto edits still sends to a prompt. Does a declared write scope change
any of this answer?

**11b. Legacy `write` vs successor `write_tree`.** A user's `settings.yaml` already contains a
folder grant with `subject: write`. The agent calls `mkdir` in that folder, in Build mode. Does
the grant cover it? Today the same approval would store a different subject — which, why, and
which function decides? Name the table that settles all of this, and say whether either
capability covers `move` or `delete`.

**12. Read-only auto-allow across modes.** A bare read-only command (`rg`/`cat`/`vcs_status`)
does not prompt in Build even though an ungranted mutating request does. Which modes does the
read-only auto-allow cover, and where in the code does that decision live?

**13. `mode.default` persistence.** What is the default launch mode? Is the active mode ever
restored from a prior or resumed session? What happens to the mode on `/clear`?
