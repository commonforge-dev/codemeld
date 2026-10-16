# Answer key — Module 6: Dispatch & runner

_Last updated: 2026-09-11_

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** **Nothing** — no stage runs. `dispatchDirect` (`dispatch/shell.go`) authorizes *all* stages in
pass 1 and returns `*DeniedError` before pass 2 starts, so even an earlier granted stage never runs.
*Proof:* pinned by `TestDispatchShell_PipelineOneStageDeniedShortCircuits` in `shell_test.go`
(`run.calls == 0` though stage 1 was granted).

**2.** No. `DirectExecRunner.Exec` (`runner/runner.go`) runs `spec.Argv` directly via
`exec.CommandContext` — no shell. *Proof:* `TestDirectExecRunner_NoShellInterpretation` in
`runner_test.go` (`["echo","$HOME"]` prints the literal `$HOME`). A pipeline's stages are assembled by
*dispatch* and joined by the runner over OS pipes — never by a shell.

**3.** By **exact name only** — `Registry.Lookup` (`tools/registry.go`), a flat `map`, no regex/prefix/
shell-equivalence. *Proof:* `TestLookupExactNameOnly` in `tools/registry_test.go`.

**4.** `*NoSuchToolError`, with **no** authorization prompt — `DispatchTool` (`dispatch/tool.go`)
returns on the lookup miss before authorizing. *Proof:*
`TestDispatchTool_UnknownReturnsNoSuchToolWithoutPrompting` in `tool_test.go`
(`len(auth.requests) == 0`).

**5.** Neither refused nor authorized as one subject: a bare compound whose operators are **only `&&`,
`||`, `;`, and/or `|`** is decomposed by `DispatchShell` into `dispatchStaged`, which authorizes **each
stage as its own `direct` subject** before any stage runs. So your `git status` grant covers that
stage, while `rm x` gets its own decision, and a deny there means **nothing** runs. `git status || rm x`
takes that same staged route (`internal/dispatch/shell.go`) — `rm x` is still authorized up front even though a successful `git status` will skip it,
and a deny on it still stops everything. The only difference `||` makes is *when* the successor runs:
after a non-zero status instead of a zero one. A mixed form such as `git status ; git log | head`
takes that route too: `git log | head` runs as one pipe group (its two members run concurrently over
an OS pipe, and the group's status is taken from `head`), and every one of its three stages is a
`direct` subject. *Proof:*
`TestDispatchShell_PipeGroupsChainWithinGroupAndSequenceBetween`,
`TestDispatchShell_MixedPipeFormRoutesToStagedPerStage`,
`TestDispatchShell_SemicolonAuthorizesAllThenRunsInOrder`,
`TestDispatchShell_AndCompoundAuthorizesPerStageAndRuns`,
`TestDispatchShell_LogicalOrRoutesToStagedPerStage`,
`TestDispatchShell_StagedAuthorizesSkippedStageBeforeRunning`, and
`TestDispatchShell_CompoundDenialPreventsAnyExecution` in `shell_test.go`. Truly unsupported
constructs (an unquoted `$()` or backtick, bare newlines) *are* refused with
`*UnsupportedConstructError` before any prompt or path resolution — `DispatchShell` checks
`!split.AllowedShell` first (`TestDispatchShell_RejectedConstructNoPromptNoRun`). A `$()` or
backtick inside double quotes is not refused: `DispatchShell` sends the whole command to
`dispatchLiteral`, where it runs through `sh -c` with the substitution performed, always prompts
until an exact-text grant covers it, and can hold no other grant
(`TestDispatchShell_DoubleQuotedSubstitutionNeverRunsDirect`).

**6.** Into the **runner's environment**, not the subject. `dispatchDirect` authorizes subject `ls`
but sets `spec.Env = append(os.Environ(), stage.Assignments...)`. *Proof:*
`TestDispatchShell_DirectStageAppliesEnvAssignments` in `shell_test.go`.

**7.** As a **result** (nil error); `RunResult.ExitCode` carries it (via `exec.ExitError`). *Proof:*
`DirectExecRunner.Exec` (`runner/runner.go`); `TestDirectExecRunner_NonZeroExit` in `runner_test.go`,
and dispatch-side `TestDispatchShell_RunnerOutcomesAreResultsNotErrors`.

**8.** The action's own **effective execution directory** via `EffectiveCWD()` (not the process cwd) —
`resolveToolPathScope` (`dispatch/tool.go`). *Proof:*
`TestDispatchTool_VCSActionRoutesThroughRegisteredTool` in `tool_test.go`.

**9.** `Exec` does not — it returns the full captured bytes and the cap is applied later at
event/model-input time. Running a pipeline does: `Pipeline` retains only the first `maxCapture` bytes
of each stream and reports the true byte total beside it, so a stage that outran the cap is recorded
as truncated with a real `original_bytes` rather than as a short complete stream. *Proof:* `RunResult`
and `PipelineResult` docs in `runner/runner.go`; `TestDirectExecRunner_OutputNotCapped` (200 KB
returned intact past the 64 KB default) and
`TestDirectExecRunner_PipelineBoundsCaptureAndCountsEveryByte` in `runner_test.go`.

**10.** A launch-failure **result**: `ExitCode = -1`, nil streams, `LaunchErrCategory = NotFound`, nil
error. `classifyLaunchErr` maps the `exec.ErrNotFound` sentinel explicitly before the errno fallback.
*Proof:* `runner/runner.go` `classifyLaunchErr`; `TestDirectExecRunner_BinaryNotFound` (and
`_PermissionDenied`) in `runner_test.go`.

**11.** `git status` is a **direct** subject (`Kind: direct`, tokens `[git status]`); `sh -c "git
status"` is a **wrapper** → the **literal** route (`Kind: literal`, a distinct canonical subject, run
verbatim via `sh -c`). *Proof:* `TestDispatchShell_WrapperFormRoutesToLiteralDistinctSubject` in
`shell_test.go`.

**12.** **Concurrently**, joined by OS pipes — one shared helper serves both the direct and the staged
route. So `yes | head -n 1` returns: `head` exits after one line, the parent closes the upstream read
end, and `yes` takes SIGPIPE. `yes | command -v head` still hangs, because `command -v` is a shell
builtin answered by `builtinLookupResult` with no process — there is no stdin for `yes` to lose, so
that group falls back to the sequential loop and waits for `yes` to finish, which it never does. That
is unchanged, known, and out of scope. *Proof:*
`TestDispatchShell_PipeGroupsStreamOnBothRoutes` and
`TestDispatchDirect_SingleStageAndBuiltinGroupsStaySequential` in `shell_test.go`.

**13.** Because a `Runner` method would force **every** implementation — including the single-command
fakes in `internal/vcs` and `internal/dispatch` tests, and any later sandboxed or remote backend — to
own multi-process pipe orchestration, which is exactly what such a backend is least able to provide.
`PipelineRunner` sits beside `Runner` and is found with a type assertion (the shape `BatchAuthorizer`
uses beside `Authorizer`). The **only** outcome that sends a group to the sequential loop is
`ErrPipelineUnsupported` from `PreflightPipeline`; any other preflight error returns with nothing
started, and a post-launch error returns without a retry — so a stage can never execute twice.
*Proof:* `PipelineRunner` in `runner/runner.go` and its dispatch mirror in `dispatch/shell.go`;
`TestDispatchDirect_UnsupportedPreflightRunsTheSequentialLoop` and
`TestDispatchDirect_PreflightAndPipelineErrorsNeverRunAStageTwice` in `shell_test.go`.

**14.** (a) `guardPolicy` returns the zero `securitystate.Policy`, which protects nothing — a call
site that supplies no guard is unguarded, deliberately. That is also why merely constructing the
policy is not enough: it only takes effect once it is forwarded as `DispatchTool`'s trailing
argument. (b) **Not a bug** — reads are outside the guard's scope, so `classifyStructuredRead`
prepares without one and reading a settings file keeps whatever result it has today. (c) In
`productionToolDispatcher.Dispatch` (`bootstrap/tooldispatch.go`), with `errors.As` on
`*securitystate.Refusal` **before** `adapt`. `adapt` classifies a handful of known error types and
returns everything else as an internal dispatch failure that aborts the turn, so a refusal reaching
it would be turned into a crash instead of a recoverable denial. *Proof:* `guardPolicy` and
`PrepareTool` in `dispatch/tool.go`, `denyProtectedState` in `bootstrap/tooldispatch.go`; pinned by
`TestProductionDispatcher_GuardLeavesStructuredReadRouteUnchanged` and
`TestProductionDispatcher_OrdinaryPreparationErrorIsNotAGuardRefusal` in `tooldispatch_test.go`.

**15.** It returns a **non-nil error** — an internal dispatch failure that aborts the turn — and the
file tool is **not** invoked either way, because the refusal already happened in `PrepareTool`. The
rule is fail-closed: an unrecordable refusal must not be returned as an unrecorded denial. Raw
`bash` is **not** covered: `DispatchShell` has no guard, so a granted shell command can still write
those files. That residual is accepted and documented in the ADR, not closed. *Proof:*
`denyProtectedState` in `bootstrap/tooldispatch.go`; pinned by
`TestProductionDispatcher_GuardEventAppendFailureFailsClosed` in `tooldispatch_test.go`.
