# Module 3 — Bootstrap / the launch spine

_Snapshot as of 2026-10-03; it may be out of date — refresh it from the code before studying._

> This is the **spine**: what happens, in order, when you run `codemeld`. Understand this and you
> understand how every other subsystem gets wired together at startup.

## Goal

After this module you can:

- Trace the call chain from `main()` to the TUI starting.
- Recite the ordered fresh-launch steps and say what each does.
- Explain the first-run short-circuit and how `--resume` is dispatched differently.
- Explain the "struct of step functions" seam that makes the orchestrator testable.

## Why it matters

`RunFresh` is the one function that calls config, VCS, model, sessions, and the TUI in the right
order. Every later module is "one of the steps." Knowing the order tells you what exists when.

## Read (in order)

1. `cmd/codemeld/main.go` — the one-line entry point.
2. `internal/cli/root.go` — `Run`, `dispatch`, `runFresh`, and `--resume` handling.
3. `internal/bootstrap/orchestrate.go` — `RunFresh`, `FreshSteps`, `DefaultFreshSteps`,
   `BootstrapResult`. **This is the central file.**
4. `internal/bootstrap/orchestrate_test.go` — see how the step order is pinned.
5. Skim `internal/bootstrap/firstrun_*.go` — what first-run generation does.
6. `internal/bootstrap/resume.go` — the resume sub-sequence.

## Mental model

### Entry → launch

```
cmd/codemeld/main.go : main()                 os.Exit(cli.Run(...))
  → internal/cli/root.go : Run                 builds the urfave/cli command; turns error → exit code
    → dispatch                                  routes on --resume / positional args
      → runFresh → runFreshBootstrap (= bootstrap.RunFresh)
        → internal/bootstrap/orchestrate.go : RunFresh   runs the ordered steps
          → step 8 : StartTUI                   the tview event loop starts
```

### The fresh-launch steps (in order)

`RunFresh` runs these in order; each runs only if every prior step returned nil:

| Step | Name | What it does |
|------|------|--------------|
| 0a | `ResolveHome` | Resolve `$HOME` before any `~`-path is used. |
| 0 | `RunFirstRun` | If global `settings.yaml` is absent → generate and **short-circuit**; else continue. |
| 1 | `LoadGlobalSettings` | Load `~/.codemeld/global/settings.yaml`. |
| 2 | `ResolveProjectRoot` | Find the project root; collect config layer paths. |
| 2b | `GateTrust` | Decide whether this project is approved to contribute its settings and VCS templates (see "The approval gate" below). |
| 2.5 | `ScaffoldProjectIgnore` | Scaffold the `<project-root>/.codemeld/codemeldignore` template (only when absent), after project-root resolution and before any later step reads the project tree. |
| 3 | `ComposeConfig` | Compose global, then project, then local (Module 4). |
| 4 | `LoadVCSTemplates` | Load built-in + project VCS templates (Module 9). |
| 5 | `ValidatePreferredVCS` | Validate `vcs.preferred`. |
| 6 | `DetectVCS` | Auto-detect the active VCS. |
| 6c | `BuildToolRegistry` | Build the tool registry. |
| 7 | `DetermineModel` | Resolve the active model (or signal "picker required" / "no model"). |
| 7b | `EnsureFreshSession` | Create the session dir, mint the id, write the folder file. |
| 7b0 | `AcquireLock` | Take ownership of the new session's `.lock` sidecar — **before** the first durable append. |
| 7b1 | `AppendLaunchBegan` | Append exactly one `launch_began` event (source: fresh) — the session anchor. |
| 7b2 | `InitMode` | Seed the active interaction mode from `mode.default` and append the session-start `interaction_mode` event, after `launch_began` and before AGENTS.md load. |
| 7c | `LoadAgentInstructions` | Load `AGENTS.md` into the session stream. |
| 8 | `StartTUI` | Start the terminal UI. |

(The lettered/fractional steps — `0a`, `2b`, `2.5`, `6c`, `7b0`, `7b1`, `7b2` — are real ordered sub-steps, not typos.)

**Ownership starts here, not at resume.** Step 7b0 is the fresh half of session ownership: a process owns
exactly its current active session, so a *fresh* launch takes the same `<session>.json.lock`
sidecar a resume takes (`sessions.AcquireResumeLock` — the `ResumeLock` names are historical). It
runs after the file exists and before `launch_began`, because a fresh session that another process
can resume or prune while this one is appending is exactly the hole UUID uniqueness does not close.
The release closure is stored on `BootstrapResult.ResumeLockRelease`; a later step failing releases
it on the way out, so a failed launch never leaves a lock behind.

**Compose order is not precedence.** Step 3 reads three settings layers in a fixed order — the global
`~/.codemeld/global/settings.yaml`, then the shared project `.codemeld/settings.yaml`, then the local
`.codemeld/settings.local.yaml` — and when two layers set the same overrideable setting the nearer one
wins, so precedence runs the other way: local over project over global. `permissions` and
`blocked_paths` are the exception: they combine across layers, so a nearer list — even an empty
one — only adds and never clears or replaces a farther layer's entries (Module 4). The two
project-scope layers are composed only for an approved project (step 2b).

### The approval gate (step 2b)

`GateTrust` runs right after the project root is known and before any project settings file is
published as a source or read. It looks the root up in the approved-projects list,
`~/.codemeld/global/approved-projects.yaml`.

- **Approved root:** both project-scope settings files are composed and the project's VCS templates are
  loaded. This holds in every launch mode — fresh, resume and headless — because each reads the same
  stored list.
- **Nothing to gate:** a root with no shared settings file, no local settings file and no project VCS
  template folder is never asked about; there is nothing to approve.
- **Unapproved root, interactive launch:** when the gated inputs can be inspected and stdin is a
  terminal, codemeld asks one y/n question naming them. Only an explicit `y`/`yes` whose approval is
  then saved to the list admits the project. A "no", an empty answer, a failed save, a launch whose
  stdin is not a terminal, or gated inputs that cannot be inspected all lead to the same result: the
  launch **degrades** rather than refusing to start — it ignores the project's settings files and
  VCS templates, says so on stderr, and runs on the global layer alone.
- **Headless run:** it honors the list but never prompts and never appends to it, whatever flags it
  is given. An unapproved root degrades as above.

Both resume forms run the same gate at the same step (`runResumeSubsequence` in `resume.go`).
Loading `AGENTS.md` stays in its later step (7c) and does not depend on approval.

### First-run, normal, resume

- **First run:** if global settings are absent, step 0 generates them — **directories → built-in VCS
  templates → global `~/.codemeld/global/codemeldignore` scaffold → settings** (settings must be
  written *after* its parent dirs exist; the ignore scaffold lands before settings via
  `RunScaffoldGlobalCodemeldignore`, see `internal/bootstrap/codemeldignore_scaffold.go`) — then
  `RunFresh` returns `(nil, nil)` and the process exits 0. No other steps run.
- **Normal launch:** all steps run; `RunFresh` returns a populated `*BootstrapResult`.
- **Resume:** `dispatch` branches on `--resume`: no id → `RunResumePicker`, one id →
  `RunResumeWithID`, bad arg counts → exit 2. Both resume forms enter the real resume bootstrap
  path in `bootstrap/resume.go`; the no-id path lists/selects a session before running the same
  resume sub-sequence as `--resume <id>`.

### What `BootstrapResult` carries

Filled in step order: `Home`, `LaunchDir`, `ProjectRoot`, `ConfigLayerPaths` (global-first,
project-last: the global path plus the admitted shared project path, or the global path alone; it
never includes the local path), `Config`, `VCSTemplate` (nil if none), `ToolRegistry`, `Model` (`*model.ActiveState`)
+ `ModelPickerRequired`, `Session` (`*sessions.Store`), `ResumeLockRelease` (step 7b0 — the release
token for the session's ownership, on **both** the fresh and resume paths), `BackgroundPrune`,
`Mode` (`*mode.ActiveState`, step 7b2), `AgentInstructions`.

`ConfigLayerPaths` is not where `/status` gets its settings list. That comes from `SettingsLayers`,
filled at step 3: one snapshot per layer — global, project and local — each labelled by its kind, so
`/status` shows `[global]`, `[project]` and `[local]` rather than a position. Project-scope layers the
gate refused are carried as ignored and not listed.

`ResumeLockRelease` is the handoff point between bootstrap and runtime ownership: `StartTUI` moves
it into a run-scoped `resumeLockHolder`, and every later session switch — `/clear`, `/resume`,
`/fork`, `/compact` — transfers ownership through that one holder rather than releasing and
re-acquiring on its own. Module 7 covers the transfer order.

### The seam pattern

`FreshSteps` is a **struct whose fields are functions** — one per step. `RunFresh` owns ordering and
short-circuiting; the steps own the work. Two wirings of the same struct:

- **Production:** `DefaultFreshSteps(stdout, stderr)` returns the real implementations.
- **Tests:** `recordingSteps` returns steps that just record their name (and let a test override one
  to inject a failure), so the *order* and *short-circuit* behavior can be asserted without touching
  the filesystem or real subsystems. This is why `orchestrate_test.go` can pin the whole sequence.

## Watch for (Go idioms)

- **Struct-of-funcs dependency injection.** `FreshSteps`/`ResumeSteps` are plain structs of `func`
  fields, not interfaces — the orchestrator stays interface-free and every step is independently
  swappable.
- **Typed error + `Unwrap` + sentinel.** `HomeResolveError` renders the user-facing line *and*
  `Unwrap()`s its cause, so the CLI uses `errors.As(err, &hre)`; first-run failure uses the sentinel
  `ErrFirstRunFailed` (`errors.Is`) to choose a *silent* exit (the runner already printed).
- **`any`-typed placeholders.** `BootstrapResult.VCSTemplate/ToolRegistry/Model/Mode` are `any` so the
  spine stays decoupled from the leaf packages' concrete types — the orchestrator can compile and be
  ordered/tested without importing them.

## Quiz

Closed-book: [`quizzes/module-03.md`](quizzes/module-03.md). Grade against
[`quizzes/module-03-key.md`](quizzes/module-03-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** If the global `settings.yaml` is absent, how many of the launch steps
run? Predict, then read the first-run branch of `RunFresh` and confirm against
`TestRunFresh_FirstRunShortCircuits` in `orchestrate_test.go`.

**B. Recover the step order.** From `RunFresh`, write the ordered list of fresh-launch steps. Check
it against the `want` slice in `TestRunFresh_StepOrder`. Did you get the lettered sub-steps right?

**C. Trace the session sub-steps.** In `DefaultFreshSteps`, find the three steps that run against the
fresh session in order — `AppendLaunchBegan` (7b1), `InitMode` (7b2), `LoadAgentInstructions` (7c) —
and the adapters they call (`appendLaunchBegan`, `initLaunchMode`, `loadAgentInstructions`). Record in
[`progress.md`](progress.md) why `launch_began` must stay the anchor (hint: what does `InitMode` append
*after* it, and why does order matter for the session record stream?).

## Done when

- You can sketch the entry → `RunFresh` → `StartTUI` chain and the step order from memory.
- You can explain what the first-run branch returns and why the process exits 0.
- You can explain how `recordingSteps` lets the order be tested without a filesystem.
