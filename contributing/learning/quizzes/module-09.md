# Quiz — Module 9: VCS templates

_Last updated: 2026-07-03_

Closed-book. Write your answers before opening `module-09-key.md`.

---

**1.** When a directory contains both `.git` and `.hg` and `vcs.preferred` is not set, which VCS is
chosen, and by what rule?

**2.** Same directory, but `vcs.preferred: hg` is set. What happens?

**3.** `vcs.preferred: hg` but only `.git` exists anywhere up the tree. Result?

**4.** How do you add support for a new VCS such as Fossil?

**5.** What runs a VCS action, and in what directory? Does it go through a shell?

**6.** A VCS action's binary isn't installed. What does the agent see?

**7.** An action's `cwd` resolves outside the repo root (e.g. via a symlink). What happens?

**8.** Is `detect` exposed as a `vcs_detect` tool?

**9.** A user writes `git.yaml` with a *different* `detect` marker. Is that marker used for detection?

**10.** Where do the built-in templates live, and are they re-copied if a user edits them?

**11.** A project's `.codemeld/vcs/git.yaml` marks the `commit` action `class: read_only`. Does
`vcs_commit` then auto-allow without a prompt? Would your answer change if the same declaration were
in the global `~/.codemeld/global/vcs/git.yaml`? What is the general rule for which sources may
advertise a VCS action as read-only?
