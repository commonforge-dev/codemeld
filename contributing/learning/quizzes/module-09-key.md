# Answer key — Module 9: VCS templates

_Last updated: 2026-07-03_

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** **git** — `AutoDetect` returns both at the same depth, then `TieBreak` applies `vcs.priority`
(default `[git, hg, jj]`), and an ambiguity warning prints. *Proof:* `vcs/priority.go` `TieBreak`;
`TestTieBreak` ("default priority picks git over hg") and `TestAutoDetect_TiedMarkersSameLevel`.

**2.** `RunPreferred` probes **only** `.hg`, skips `vcs.priority`, and selects the directory — git is
never considered. *Proof:* `vcs/preferred.go` `RunPreferred`; `TestRunPreferred_BothMarkersNamedWins`.

**3.** **No fallback** — detection fails and codemeld exits with an error naming the settings file.
*Proof:* `vcs/preferred.go` `RunPreferred`/`noPreferredMatchError`; `TestRunPreferred_SkipsPriorityNoFallback`,
`TestRunPreferred_DetectFailsEverywhere`.

**4.** Create `fossil.yaml` (filename `^[a-z][a-z0-9-]*\.yaml$`) in `~/.codemeld/global/vcs/` or a
project's `.codemeld/vcs/`, declaring all 15 actions including a `detect: { marker: ... }` block (a
new, non-built-in name requires `detect`). *Proof:* `vcs/template.go` `LoadTemplates`/`checkCompleteness`;
`TestAutoDetect_CustomTemplateParticipates`, `TestLoadTemplates_ValidNewName`.

**5.** `Invoke` (`vcs/invoke.go`) runs the action's `argv` **directly via the runner — no shell** — in
the cwd from `ResolveActionCWD` (the repo root when `cwd` is omitted). *Proof:* `Invoke`/`ResolveActionCWD`;
`TestInvoke_CleanInvocationEmitsPairedEvents`.

**6.** A synthesized **result**: `exit_code = -1`, empty stdout, stderr
`codemeld: vcs_<action>: launch failed: <argv[0]>: <category>`, plus paired `tool_exec_start`/
`tool_exec_end` sharing one invocation id. *Proof:* `vcs/invoke.go` launch-failure branch;
`TestInvoke_BinaryNotFoundLaunchFailure`.

**7.** `exit_code = -1`, stderr `codemeld: vcs_<action>: cwd escapes repo root: <resolved-cwd>`, and the
process **never starts** (`ResolveActionCWD` returns a `*CWDEscapeError` after symlink resolution).
*Proof:* `vcs/invoke.go` `ResolveActionCWD`/`Invoke`; `TestInvoke_CwdEscapeLaunchFailure`,
`TestResolveActionCWD`.

**8.** **No** — `RegisterActions` skips `detect`; only the 14 non-detect actions become `vcs_<action>`
tools. *Proof:* `vcs/tool.go` `RegisterActions`; `TestRegisterActions_RegistersNonDetectByName`
(asserts `vcs_detect` misses).

**9.** **No** — a built-in-name template is an *override*: the built-in `.git` marker stays
authoritative for detection; the override's `detect` block is ignored (and may be omitted). Its other
actions do take effect. *Proof:* `vcs/autodetect.go` `eligibleDetectors`, `vcs/preferred.go`
`preferredMarker`; `TestAutoDetect_BuiltinNameOverrideUsesBuiltinDetect`,
`TestLoadTemplates_BuiltinOverrideMayOmitDetect`.

**10.** Embedded in the binary via `//go:embed`; materialized to `~/.codemeld/global/vcs/` only on
first run and only if **absent** (an edited file is never overwritten). *Proof:* `vcs/builtin/embed.go`;
`bootstrap/firstrun_vcs.go` `MaterializeBuiltinTemplates`; `TestBuiltinTemplates_ByteSnapshot`.

**11.** **No** — a project-local template is **untrusted**, so its `class: read_only` is ignored and
`vcs_commit` stays mutating (promptable). This is deliberate: a read-only action auto-allows with no
prompt, so a repository must not be able to declare its own actions read-only and bypass the
permission front door. **Yes, it would change** for the global copy *only if* `commit` were declared
read-only there — the global layer is trusted, so an explicit `class: read_only` is honored. (Here
`commit` also is not in the built-in read-only set, so a *pristine* global copy would still leave it
mutating; only an explicit trusted-global declaration flips it.) **General rule:** exactly three
sources may advertise a VCS action read-only — embedded built-ins, unchanged built-in reference copies
(byte-identical first-run copies), and explicit `class: read_only` in trusted global templates.
*Proof:* `vcs/tool.go` `actionReadOnly` / `builtinReadOnlyActions` / `RegisterActions` vs
`RegisterActionsWithTrustedClasses`; `bootstrap/vcs_bootstrap.go` `loadVCSTemplates`/`overlayTemplates`
(global `true`, project `false`). Tests: `TestLoadVCSTemplates_ProjectOverrideDoesNotInheritGlobalTrust`
and `TestActionTool_UntrustedClassIgnored` (project distrust); `TestLoadVCSTemplates_GlobalExplicitClassAdvertisesReadOnly`
and `TestActionTool_TrustedClassCanMarkReadOnly` (trusted global honored); `TestActionTool_UnchangedReferenceCopyUsesBuiltinClassification`
and `TestLoadVCSTemplates_MaterializedReferencesAdvertiseReadOnly` (unchanged reference copies).
