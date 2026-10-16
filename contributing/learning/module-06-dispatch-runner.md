# Module 6 — Dispatch & runner

_Snapshot as of 2026-09-11; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-09-11_

> This module connects two earlier ones: a permission check (Module 5) authorizes, and then
> *something runs*. Dispatch is the router; the runner is the executor.

## Goal

After this module you can:

- Describe the two dispatch paths (structured tool vs raw shell) and how they differ.
- Explain how authorization wraps execution — especially the "authorize **all** stages before
  running **any**" rule for pipelines.
- Explain what the runner does (and deliberately does *not* do): direct `os/exec`, no shell, no cap.

## Why it matters

This is where a model's tool call actually touches the machine. The safety properties (no stage
runs unless all are authorized; the runner never interprets a shell) live here.

## Read (in order)

1. `internal/dispatch/shell.go` — `DispatchShell`, `dispatchDirect`, `dispatchLiteral`, and the
   `Authorizer`/`Runner` seams.
2. `internal/dispatch/tool.go` — `DispatchTool`, `PrepareTool`, `DispatchPreparedTool`,
   `resolveToolPathScope`.
3. `internal/runner/runner.go` — `Runner`, `DirectExecRunner`, `RunSpec`, `RunResult`.
4. `internal/tools/registry.go` — `Registry.Lookup` (exact-name).
5. `internal/dispatch/shell_test.go` and `internal/runner/runner_test.go` for the behavior.

## Mental model

### Two dispatch paths

| | `DispatchShell` (raw shell) | `DispatchTool` (structured) |
|---|---|---|
| Lookup | normalize + split via `SplitCommand` | exact-name `Registry.Lookup` |
| Subject kind | `direct` (with tokens) or `literal` | `tool` |
| Multi-stage | yes — pipelines | single call |
| Runs commands | itself, via injected `Runner` | delegates to the tool (no `Runner` arg) |
| Unknown/rejected | `*UnsupportedConstructError` | `*NoSuchToolError` |

**`DispatchShell`** flow: `SplitCommand` → if an unsupported construct (an unquoted `$()` or
backtick, bare newlines) → `*UnsupportedConstructError` **before any prompt** → `DerivePathScope`
(one scope, reused for *both* authorize and run, so it can never authorize dir A and run in dir B) →
route to `dispatchStaged`, `dispatchLiteral`, or `dispatchDirect`. A `$()` or backtick **inside
double quotes** is not an unsupported construct: the shell performs it, so the whole command goes to
`dispatchLiteral` and runs verbatim via `sh -c` — never `dispatchDirect` or `dispatchStaged`, which
run argv without a shell and would pass the substitution through as text. It always prompts until an
exact-text grant covers it (Plan denies it), and no generalized grant can. A single-quoted or escaped
`$(x)` is inert text and keeps its direct route
(`TestDispatchShell_DoubleQuotedSubstitutionRunsThroughTheShell`,
`TestDispatchShell_DoubleQuotedSubstitutionNeverRunsDirect`,
`TestDispatchShell_InertQuotedSubstitutionTextKeepsItsRoute`). Compound operators are **not**
rejected constructs: a bare compound whose operators are **only `&&`, `||`, `;`, and/or `|`** (and
which `SimpleCompoundStages` decomposes cleanly) goes to `dispatchStaged`, where each stage is its own
`direct` subject — so an existing direct grant covers each matching stage of `a && b`, `a || b`,
`a ; b`, or `a ; b | c`. A compound carrying redirection, a wrapper, a subshell, backgrounding, an
env-assignment-bearing stage, or a malformed stage goes to `dispatchLiteral` instead: the whole
prefix-stripped command becomes one literal/compound subject and runs verbatim via `sh -c`, so no
direct grant is ever borrowed for it. The price of staying off `sh -c` is that a staged chain gets no
shell expansion: `echo '*' || true` prints a literal `*`, just as a direct pipeline always has. That
price is what changed for mixed forms: `grep x *.go | head; ls` used to reach
`sh -c` and have its glob expanded, and now the program receives the literal `*.go` — a real change
in results, and the same rule pure pipelines have always followed.

**`dispatchStaged` is two passes too:** Pass 1 authorizes *every* candidate stage (both sides of an
`&&` or `||`, and every member of every pipe group, so the conditional-execution decision never
changes what was authorized); Pass 2 runs them directly — no `sh -c`. Stages joined by `|` form one
**pipe group**: its members run **concurrently, joined by OS pipes**, and the group's visible stdout
and exit status are its **final member's**. Both routes execute a pipe group through the same shared
helper, so `dispatchDirect` and `dispatchStaged` cannot drift apart. Concurrency is what makes
`yes | head -n 1` return at all: `head` exits after one line, the parent closes the upstream read
end, and `yes` takes SIGPIPE. A group that cannot stream — one stage only, or a `command -v` builtin
among the stages — falls back to running its members one at a time with each stdout buffered into the
next one's stdin. `&&`, `||`, and `;` then sequence *completed groups*, not individual stages: `&&` runs the
next group only after a zero exit status, `||` only after a non-zero one, `;` regardless, and a new
group always starts from nil stdin. So `a; b | c` runs `a`, then pipes `b` into `c`, and `a | b && c`
tests `b`'s status. A skipped group runs nothing, contributes no output, and does not set the exit
code, and each group looks only at the operator immediately before it — which is exactly `sh`'s
equal-precedence, left-associative grouping, so `a && b || c` with a failing `a` runs `a` then `c`.

**`dispatchDirect` is two passes:** Pass 1 authorizes *every* stage; Pass 2 runs them only if all
passed. So a denied **later** stage means **no** stage runs — even an earlier granted one. Leading
`KEY=VALUE` assignments are stripped from the authorization subject but **layered onto the runner
env** at exec (so `FOO=bar ls` authorizes `ls` but runs with `FOO=bar`).

**`DispatchTool`** flow: `Registry.Lookup(name)` → miss → `*NoSuchToolError` **without prompting** →
resolve path scope (a `vcs.<action>` tool anchors on its `EffectiveCWD()`, not the process cwd) →
authorize (`Kind: tool`) → the **tool** owns its invocation (that's why there's no `Runner` arg).

### Preparation is the first half, split out

`DispatchTool` is literally `PrepareTool` then `DispatchPreparedTool`. The split exists because a
caller sometimes needs to know *what a call would do* before deciding whether to run any of a batch of
calls:

- **`PrepareTool`** does the lookup and the resolution and stops there. It returns a `PreparedTool`
  holding the resolved target/scope and mode-auth context. It **prompts nobody and invokes nothing**,
  so preparing a call the caller then discards costs no permission and no side effect. Its refusals are
  the same ones `DispatchTool` makes before prompting: an unknown name and a structurally invalid
  target.
- **`DispatchPreparedTool`** authorizes that resolved scope and, only if granted, invokes with the
  **same** resolved target. Nothing is re-resolved, so the authorized path and the accessed path cannot
  drift if the filesystem changes in between. A zero `PreparedTool` (preparation failed, or never ran)
  is refused before authorization rather than dispatched.

Reuse is not the same as trust: the tool still revalidates the resolved target at invocation
(`ReadTool.read` re-checks it against the project root), so a file swapped for a symlink out of the
project between preparation and invocation is refused rather than read.

`PreparedTool` exposes only `Name()`, `Scope()`, and `ExternalRead()` — enough to classify a call,
not enough to rewrite what will be authorized.

### The refusal that happens before authorization

`PrepareTool` takes a trailing `guard ...securitystate.Policy`. When a call site supplies one, the
policy classifies the call against codemeld's own settings files before anything else: the endpoint
the model *named* is checked ahead of the tool's own resolver (otherwise a protected target would
come back as an ordinary bad-target error), and the resolved endpoint is checked after it. It covers
`edit`, `create`, `delete`, `mkdir`, and `move` only.

The handoff is typed, not textual. `PrepareTool` returns a `*securitystate.Refusal`;
`DispatchTool` returns it verbatim; and the production dispatcher
(`productionToolDispatcher.Dispatch` in `internal/bootstrap/tooldispatch.go`) is the one place that
recognizes it, with `errors.As` **before** the generic error adapter — which would otherwise treat
an unfamiliar error as an internal dispatch failure. On recognizing it the dispatcher records the
`permission_matched` evidence through the active session store and returns the guard deny envelope;
the tool is never invoked. If that record cannot be appended the whole turn fails rather than
proceeding with an unrecorded refusal.

Three things deliberately stay outside it:

- **A zero policy protects nothing.** `guardPolicy` returns an empty `securitystate.Policy` when the
  variadic is empty, so a call site that passes no guard is unguarded on purpose — which also means
  wiring the policy into `DispatchTool` is what makes the guard real, not merely constructing it.
- **The structured-read preparation path passes no guard.** `classifyStructuredRead` calls
  `PrepareTool` without one, because reads are not in scope: reading a settings file keeps whatever
  result it has today.
- **Raw shell is not covered.** `DispatchShell` has no equivalent, so a granted `bash` command can
  still write these files. That is a known gap, not a covered case.

### The runner

`Runner` is a tiny interface (`NewInvocationID`, `Exec`). `DirectExecRunner` is the phase-1
implementation: it runs `spec.Argv` **directly via `os/exec`** — **no shell, no metacharacter
interpretation** (`["echo","$HOME"]` prints the literal `$HOME`). Key facts:

- `Exec` output is **never capped** by the runner; the `sessions.max_tool_output_bytes` cap is applied
  later at event/model-input time.
- A **non-zero exit** and a **launch failure** are *results*, not Go errors. A launch failure returns
  `ExitCode = -1` and a `LaunchErrCategory` (e.g. `NotFound` for a missing binary). A non-nil error is
  reserved for invalid input (bad invocation id, empty argv).
- The `Runner` **interface is the future-sandbox seam**: phase 1 is `DirectExecRunner`; a sandbox
  slots in behind the same interface without changing callers.
- **Running a pipeline is an optional capability, not a `Runner` method.** `PipelineRunner`
  (`PreflightPipeline` + `Pipeline`) is discovered by **type assertion**, so the single-command fakes
  elsewhere need no stub and a future sandboxed backend is not forced to hand two live processes a
  shared descriptor. `PreflightPipeline` validates every stage and decides support before anything
  starts; it is the only place `ErrPipelineUnsupported` can come from, and that sentinel is the only
  outcome that falls back to the sequential loop — so no stage can ever execute twice.
- Unlike `Exec`, `Pipeline` **does** bound what it keeps: it retains the first `maxCapture` bytes of
  each stream and reports the true byte total beside it, so a stage that produced more than was kept
  is recorded as truncated instead of as a short, complete stream.

## Watch for (Go idioms)

- **Interface-mirroring seams.** `dispatch.Authorizer` and `dispatch.Runner` re-declare narrow
  interfaces over `permissions` and `runner`, so `internal/dispatch` needn't import `config`/`tui`/
  `events` and tests can inject a `fakeAuthorizer`/`fakeRunner`.
- **Optional capability interfaces.** `PipelineRunner` sits *beside* `Runner` and is found with a type
  assertion, the same shape `BatchAuthorizer` uses beside `Authorizer`: the core interface stays small
  and every implementation that does not need the extra behavior is left alone.
- **Errors as control-flow values.** `*UnsupportedConstructError`, `*DeniedError`, `*NoSuchToolError`
  are typed errors callers discriminate with `errors.As`.
- **Outcome vs failure.** A non-zero exit / launch failure is a `RunResult`, not an `error` — a
  deliberate split so dispatch can record real tool output for a failed command.

## Quiz

Closed-book: [`quizzes/module-06.md`](quizzes/module-06.md). Grade against
[`quizzes/module-06-key.md`](quizzes/module-06-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** In the pipeline `cat file | grep secret`, where `cat file` is granted but
`grep secret` is denied — does `cat file` run? Predict, then read `dispatchDirect` (`shell.go`) and
confirm against `TestDispatchShell_PipelineOneStageDeniedShortCircuits`.

**B. Predict, then verify.** What does the runner do with `["echo", "$HOME"]` — expand or print
literally? Predict, then confirm against `TestDirectExecRunner_NoShellInterpretation`
(`runner_test.go`). Why is "no shell" a safety property?

**C. Locate the two-pass structure.** Find the two passes inside `dispatchDirect` and record the
`file:function` chain in [`progress.md`](progress.md). Write one sentence on why authorizing all
stages before running any is the whole point.

**D. Predict, then verify.** Does `yes | head -n 1` return? Does `yes | command -v head`? Predict
both, then read the shared pipe-group helper in `shell.go` and confirm against
`TestDispatchShell_PipeGroupsStreamOnBothRoutes` (`shell_test.go`).

## Done when

- You can explain both dispatch paths and when each is used.
- You can explain why no stage of a pipeline runs if any stage is denied.
- You can explain that the runner never interprets a shell and never caps `Exec` output.
- You can explain why running a pipeline is an optional capability rather than a `Runner` method.
- You can explain why the protected-state refusal is recognized by type before the generic error
  adapter, and why raw shell is not covered by it.
