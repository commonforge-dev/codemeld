# Module 9 — VCS templates

_Snapshot as of 2026-07-03; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-07-03_

> codemeld supports git, Mercurial, and Jujutsu — and any other VCS — without hard-coding any of
> them. Version control is just YAML templates. This module covers how that works end to end.

## Goal

After this module you can:

- Describe what a VCS template is and the 15 required actions.
- Explain auto-detection (innermost match) and how ties are broken (`vcs.priority`, `vcs.preferred`).
- Explain how a template's actions become `vcs.<action>` tools and how an action runs.

## Why it matters

This is the "any VCS" differentiator made concrete, and a clean example of data-driven design
(YAML defines behavior; Go just executes it). It also reuses path-scoping from Module 5.

## Read (in order)

1. `internal/vcs/builtin/embed.go` and `internal/vcs/builtin/git.yaml` — the embedded built-ins.
2. `internal/vcs/template.go` — `Template`, `LoadTemplates`, `checkCompleteness`, `requiredActions`.
3. `internal/vcs/detect.go` — `DetectInDir`, marker validation.
4. `internal/vcs/autodetect.go` — `AutoDetect` (the upward walk).
5. `internal/vcs/priority.go` and `preferred.go` — tie-breaking and the hard override.
6. `internal/vcs/tool.go` and `invoke.go` — actions as tools, and how one runs.

## Mental model

### The template

A VCS template is **one YAML file whose top-level keys *are* the action names** (no `name:`/
`actions:` wrapper — those are forbidden). It must define **15 actions**: `detect`, `status`,
`diff`, `add`, `commit`, `log`, `branch-current`, `branch-create`, `branch-switch`, `restore-file`,
`is-clean`, `stash`, `stash-pop`, `merge-status`, `rebase-status`. `detect` is a single `marker`
(e.g. `.git`); every other action is an `argv` list (run **directly, no shell**) plus an optional
`cwd`. Placeholders are a closed set — `{path}`, `{message}`, `{branch}` — each allowed only in
specific actions.

### Built-ins and adding your own

git/hg/jj are **embedded in the binary** (`//go:embed`). On first run they're materialized to
`~/.codemeld/global/vcs/<name>.yaml` (only if absent — a user-edited copy is never overwritten), but
the running process always loads built-ins from the embedded copy, so deleting the disk files
doesn't disable them. To add a VCS, drop `<name>.yaml` in `~/.codemeld/global/vcs/` or a project's
`.codemeld/vcs/` (project overrides global). A *new* name must declare all 15 actions including
`detect`; a template named after a built-in is an **override** (may omit `detect`).

> Note: the README says `~/.codemeld/vcs/` for short; the actual paths are
> `~/.codemeld/global/vcs/` (global) and `<project>/.codemeld/vcs/` (per-project).

### Auto-detection

`AutoDetect` walks upward from the cwd and returns the **innermost** level where any marker matches
(ancestors are ignored once an inner level matches). Detection is a pure marker probe — the VCS's
binary need not be installed, and a marker is matched with `lstat` (a symlink named `.git` counts).
The boundary is `launch-dir-only` (no walk) or `project-root` (walk up through the project root). If
several markers match at the same depth, all are returned so the caller can break the tie.

### Tie-breaking and the hard override

- **`vcs.priority`** (default `[git, hg, jj]`) is a *soft* tie-break via `Rank`/`TieBreak`: listed
  names win by list order; it only re-orders VCSes that already matched (it never forces one that
  isn't present). An ambiguity warning prints when more than one matched.
- **`vcs.preferred`** is a *hard* override: it probes **only** the named VCS's marker, skips
  `vcs.priority` entirely, and **never falls back** — if that VCS isn't found anywhere, codemeld
  errors out. A built-in-name override still uses the authoritative built-in marker.

### Actions as tools

`RegisterActions` registers one `vcs.<action>` tool per **non-detect** action (`detect` is never a
tool). When invoked, `Invoke` substitutes placeholders, resolves the cwd (must be **within the repo
root** — symlink escapes are rejected via `IsDescendantOrEqual` from Module 5), runs the `argv`
directly through the runner, and emits paired `tool_exec_start`/`tool_exec_end` events. A launch
failure (missing binary, cwd escape, or repo root removed) surfaces as a **result** with
`exit_code = -1`, not a Go error.

### Read-only classification and who is trusted to declare it

Every `vcs.<action>` tool carries a read-only-vs-mutating flag (`tools.Metadata.ReadOnly`). A
read-only action **auto-allows in every mode with no prompt**, so who is allowed to say "this action
is read-only" is a trust decision, not a convenience — a repository that could mark its own actions
read-only would auto-approve them and widen its own permission boundary.

- **`class` is a per-action YAML key**, not a template-wide setting. Its closed vocabulary is
  `read_only` and `mutating` (`ActionClass` in `template.go`: `ClassReadOnly`, `ClassMutating`, and
  `ClassUnset` for the absent key). An unknown or non-string `class` is a load-time `ValidationError`
  that aborts startup; an **absent** class stays mutating. The default fails closed to mutating.
- **`builtinReadOnlyActions`** (`tool.go`) is the *only* product-authored read-only set:
  `status`, `diff`, `log`, `branch-current`, `is-clean`, `merge-status`, `rebase-status`. Everything
  else (`add`, `commit`, `branch-create`, `branch-switch`, `restore-file`, `stash`, `stash-pop`) is
  mutating unless a *trusted* template explicitly declares otherwise.
- **`actionReadOnly`** (`tool.go`) makes the call. An action is read-only iff **(a)** the template is
  an embedded built-in *or* an unchanged built-in reference copy **and** the action name is in
  `builtinReadOnlyActions`, **or (b)** the caller passed trust (`RegisterActionsWithTrustedClasses`
  rather than `RegisterActions`) **and** the action declares `class: read_only`.
- **Unchanged reference copies** are recognized by `BuiltinReferenceCopy` — raw-byte equality against
  the embedded `git`/`hg`/`jj` (not YAML-equivalence). A materialized-but-untouched first-run copy
  keeps the built-in read-only set; edit one byte and it loses that provenance and only gets read-only
  for actions it *explicitly* declares (and only if it lives in the trusted global layer).
- **Global is trusted, project is not.** `loadVCSTemplates` (`internal/bootstrap/vcs_bootstrap.go`)
  overlays the global `~/.codemeld/global/vcs/` layer with `overlayTemplates(..., true, ...)` and the
  per-project `<project>/.codemeld/vcs/` layer with `false`. The trust flag is keyed per template
  pointer, so a project override — a *different* pointer — never inherits the global layer's trust.
  A project-local `class: read_only` is silently ignored; the action stays promptable.

This is the invariant in `contributing/invariants.md`: a repository-controlled template fails closed.

## Watch for (Go idioms)

- **`embed.FS` for ship-in-binary defaults.** The same embedded bytes are both materialized to disk
  and parsed in memory, with a byte-snapshot test (`TestBuiltinTemplates_ByteSnapshot`) pinning them.
- **Defensive copies on accessors.** `BuiltinNames()`/`BuiltinTemplate()` return fresh clones so
  callers can't mutate package state.
- **Package-var `readDir` seam** lets tests force an unreadable directory deterministically.
- **Typed sentinel errors** (`CWDEscapeError`, `RepoRootResolveError`, `AnchorReadError`) drive the
  launch-failure branches via `errors.As`.

## Quiz

Closed-book: [`quizzes/module-09.md`](quizzes/module-09.md). Grade against
[`quizzes/module-09-key.md`](quizzes/module-09-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** A directory contains both `.git` and `.hg`, and `vcs.preferred` is not
set. Which VCS wins? Predict, then read `TieBreak` (`priority.go`) and confirm against `TestTieBreak`
("default priority picks git over hg") and `TestAutoDetect_TiedMarkersSameLevel`.

**B. Read a real template.** Open `internal/vcs/builtin/git.yaml`. Identify the `detect` marker and
three actions, and note why `merge-status`/`rebase-status` are *probe-only* (read-only `rev-parse`).

**C. Locate the cwd constraint.** Find where a vcs action's cwd is forced to stay within the repo
root (`ResolveActionCWD` in `invoke.go`) and the test for a symlink escape
(`TestInvoke_CwdEscapeLaunchFailure`). Record the `file:function` in [`progress.md`](progress.md).

## Done when

- You can explain the template model and the difference between `vcs.priority` and `vcs.preferred`.
- You can explain how an action becomes a tool and what a launch failure looks like.
- You read a real built-in template and understood its shape.
