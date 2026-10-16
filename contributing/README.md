# Contributing to codemeld

_Last updated: 2026-10-10_

## The most useful thing you can send: unneeded permission prompts

Use codemeld on a real project. Every time it asks permission for a command you believe it should
not have needed to ask about, report it. Report any other issue or error you hit too.

Include:

- the command text it asked about;
- the mode shown in the UI: `plan`, `build`, or `auto-edits`;
- whether you ran it headless (`codemeld run`) or in the TUI;
- the prompt text codemeld showed.

Redact secrets and private paths first.

Send it as a GitHub issue using the bug template
([`.github/ISSUE_TEMPLATE/bug.yml`](../.github/ISSUE_TEMPLATE/bug.yml)). The template has no
separate fields for the mode, headless or TUI, or the command, so put them in "What happened?" and
"Steps to reproduce".

## Start here

1. **[setup.md](setup.md)**: get a dev environment running, then build, test, and lint.
2. **[invariants-list.md](invariants-list.md)**: the rules any change must keep, one line each.
3. **[learning/00-START-HERE.md](learning/00-START-HERE.md)**: a module-by-module tour of the
   code. The modules are frozen snapshots; refresh one from the code before you study it.

When you make a change, [workflow.md](workflow.md) and [invariants.md](invariants.md) are the
detailed references.
