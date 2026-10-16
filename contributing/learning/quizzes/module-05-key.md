# Answer key — Module 5: Permissions

_Last updated: 2026-10-06_

Citations are **file + function/symbol name**, not line numbers — lines drift as the code
changes, but a function name stays findable. Search (or your editor's "go to symbol") lands you
on the exact code.

---

**1. Path scope.**
- (a) `/home/me/foo/sub` → **yes** (descendant).
- (b) `/home/me/bar` → **no** (sibling).
- (c) `/home/me` → **no** (ancestor).
- (d) `/home/me/foobar` → **no** (sibling — *not* a substring/prefix match).

Rule: a grant authorizes its scope and **every descendant**, never an ancestor or a sibling.
Source: `IsDescendantOrEqual` in `internal/permissions/scope.go`, which uses `filepath.Rel` to
stay boundary-safe. The test `TestIsDescendantOrEqual` (`scope_test.go`) includes the exact
"sibling prefix trap" case `{"/a/foobar", "/a/foo", false}`.

**2. Lifetimes.**
- **session** — not stored; in memory only (the `grantKindSession` constant in `matcher.go`;
  matches with the same descendant rule as folder).
- **folder** — `<project_root>/.codemeld/settings.local.yaml`; `path_scope` is the cleaned absolute
  folder. A project host grant (`grant_kind: project`) is written to the same local file.
- **global** — `~/.codemeld/global/settings.yaml`; `path_scope` is `"*"`. Never the prompt default.

The local file stays on this machine. A grant reaches the shared `.codemeld/settings.yaml` only
through the `/settings` picker's share action.

Source: README "Permissions that respect your time"; the `PermissionEntry.PathScope` doc comment
in `entry.go`; `productionAuthorizer.persistGrant` in `bootstrap/authdeps.go` for the target file.

**3. Path canonicalization.**
`canonicalProgram` in `normalize_direct.go`. It will **not** reduce the path when the bare name on
the current `$PATH` does not resolve (via `os.SameFile`, in helper `sameExecutable`) to that same
executable — e.g. an out-of-`PATH` binary. Then the original path token is kept so it can't
impersonate a bare-name grant.

**4. Environment assignments.**
- (a) **Matching:** stripped from the subject. `NormalizeDirectStage` peels leading `KEY=VALUE`
  tokens (predicate `isEnvAssignment`), so the canonical tokens are just `git log` and they match
  the existing grant.
- (b) **Execution:** preserved on `StageNormalization.Assignments`, so the authorized command
  still runs with `GIT_PAGER=cat` in its environment — out of the matched identity, not discarded.

Both in `normalize_direct.go`.

**5. Pipelines. — False.**
A bare `a | b` pipeline is split on `|` by the splitter in `pipeline.go`, and each stage is
authorized **separately by exact program name** (`Match` in `matcher.go`; `docs/architecture.md` →
"Pipelines are authorized stage-by-stage by exact program name"). So `git log | head` checks
`git log` and `head` independently. A recognized bare `&&`/`||`/`;`/`|` compound is authorized the
same stage-by-stage way (`DispatchShell` → `dispatchStaged`), including a mixed form like
`git log | head ; hg status`. A compound carrying a
wrapper, redirection, or another unsupported construct is the exception: it routes to the
literal/compound path as one unit — byte-exact, or a generalized compound grant that still pins the
exact program set and operator structure — see `compound.go`, `compound_test.go`.

**6. Wrappers.**
`sh` is in `wrapperPrograms` (`normalize_direct.go`). A wrapper/indirect leading program is taken
out of the direct boundary and tagged `RouteLiteral` by `NormalizeDirectStage`, so it
routes to **literal** matching — byte-equal on the canonical subject (`MatchesLiteralSubject`,
`normalize_literal.go`). It therefore cannot reuse a `direct` grant for `git log`; you'd need a
literal grant for the exact wrapped form.

**7. Cross-field rule.**
For a `global` grant, `path_scope` must be `"*"`. The rule, enforced in `ParseEntry` (`entry.go`):
`path_scope == "*"` **iff** `grant_kind == global` — a global grant requires `"*"`, and `"*"`
requires global. Either mismatch is rejected at parse time.

**8. Turn cache.**
`TurnCache` (`turncache.go`) memoizes each prompt's resolved outcome — **including denies** — for
the duration of a single model turn, keyed by `(kind, subject, pathScope)`, so an agent retrying a
transient failure within the same turn isn't re-prompted (`Record`). It is consulted **only after**
the real-grant `Match` (`matcher.go`) returns no match — real grants always win — via `Lookup`. It
is emptied by `Reset` at the start of every new user submission. It holds no grants.

**9. No "approve everything".**
Design stance: the permission system is the front door, and codemeld refuses to ship an
approval-free mode that "pretends approval-free is safe" (README "No 'approve everything' mode";
`docs/architecture.md` → "Permission system is the front door"). If you want
unattended runs, build a sandbox *around* codemeld.

**10. Deny.**
A structured **deny envelope**: a UTF-8 byte-capped JSON object built in `denyenvelope.go` and
delivered back to the agent as the tool result, so the model sees an explicit refusal it can react
to rather than a silent hang.

**11. Multiple choice. — (a) Kind, Subject, PathScope, GrantKind.**
`ArgumentHash` is excluded because a literal entry's hash is **derived from its Subject**, so it
adds no distinguishing identity (the `DedupKey` type and the `PermissionEntry.DedupKey` method in
`entry.go`).

**12. Compounds.**
- (a) **Stage-by-stage.** `SplitCommand` (`pipeline.go`) does route the whole prefix-stripped
  command to the literal route, but `DispatchShell` (`internal/dispatch/shell.go`) re-admits the
  safe set: a **bare** compound that `SimpleCompoundStages` decomposes cleanly and whose operators
  are **only `&&`, `||`, `;`, and/or `|`** goes to `dispatchStaged`, which builds one `direct` subject
  per stage. So your existing direct grant for `go build` authorizes that stage inside the chain with no
  new prompt. Authorize-all-before-run still holds: if `git add .` is not authorized, **no** stage
  runs.
- (b) **They now split: `a > b && c` stays one literal subject, `a || b` does not.** Redirection
  keeps a command on the literal route in `SplitCommand`, so it is matched as a single `literal`
  subject and run verbatim via `sh -c`; a `direct` grant can never satisfy a `literal` request
  (`Match` requires the kinds to agree), so that boundary fails closed. A bare `a || b`, by contrast,
  is inside dispatch's operator allowlist (`internal/dispatch/shell.go`): it decomposes to
  `dispatchStaged` and each stage is its own `direct` subject, so the
  grant *is* borrowed per stage — and because the chain never reaches `sh -c`, its stages no longer
  get glob or variable expansion. A pipe mixed into a chain (`a; b | c`) goes the same staged way,
  with `b | c` run as one pipe group. The literal route still claims redirection, a wrapper, a
  subshell, backgrounding, an env-assignment-bearing stage, and a malformed stage.
- (c) A generalized grant authorizes a literal-route command only when the request is a **simple
  compound** (`RecognizeSimpleCompound`, `compound.go`): `sh -c '<stage> [&& <stage>]…'` or a bare
  compound whose every stage is a clean direct command. The stored subject
  (`EncodeCompoundSubject`, `compound/v1`) **pins** the wrapper flavour (wrapped vs bare), the
  program set, the stage count, and the exact operator sequence; it widens **only** each stage's own
  leaf arguments to that stage's chosen scope. `matchesCompoundSubject` rejects any program swap,
  operator change, or added/removed/reordered stage.
- (d) **Fail closed.** A redirection, subshell, nested wrapper, or env-assignment-bearing stage is
  *not* a simple compound, and a destructive program is explicitly ineligible for widening (the
  `IsDestructiveProgram` gate in `EncodeCompoundSubject`); all fall back to **byte-exact** literal
  matching. One narrow exception: a bare `/dev/null` redirect
  is ignored when deciding *grant identity*, so a compound disqualified by that alone can still take a
  generalized grant — execution, and every other redirect, are unchanged. (An unquoted command substitution or backtick is a different bucket — it never reaches literal
  matching at all; see (e). A double-quoted one does reach it: it runs through `sh -c`, always
  prompts until an exact-text grant covers it, and is never a generalized subject.) The principle: a false "not simple" is only friction, but a false
  "simple" would silently widen a grant — so when in doubt, narrow.
- (e) `echo $(whoami)` uses an **unsupported construct**: `SplitCommand` rejects it
  (`AllowedShell == false`) and dispatch surfaces it in-band **without prompting and without
  running** (an unquoted `$(…)` or backtick and a bare newline are all rejected before any prompt
  and can never be authorized by a grant — compound operators are not in that bucket). Quoting
  changes the answer: `echo "$(whoami)"` routes literal and runs through `sh -c` with the
  substitution performed, always prompts until an exact-text grant covers it (Plan denies it), and
  can hold no other grant. Source: `pipeline.go`, `compound.go`, `internal/dispatch/shell.go`;
  `TestSplitCommand_DoubleQuotedSubstitutionRoutesLiteral` and
  `TestDoubleQuotedSubstitutionIsNeverAutoAllowed`.

**13. The no-exec shell exception.**
- **Auto-allow:** (a) and (c). **Mutating:** (b), (d), (e), (f), (g), (h).
- The accepted grammar is exactly four spellings — `bash -n`, `bash -o noexec`,
  `bash -O extglob -n` (either option order), and `sh -n` — followed only by plain non-option script
  operands (`noExecShellTokens`, `planshell.go`). So (b) is out because `--noexec` is not a Bash
  option at all; (d) is out because `-O extglob` is admitted **only** alongside `-n` — a parser
  setting is never the whole option list; (e) is out because `-c` is a dash-leading token, not a
  script operand, and it executes.
- **The unlisted-option rule: fail closed.** Any option the validator does not name — an unknown
  flag, another `-O` value, an interactive/login/startup option, a missing value, a dash-leading,
  plus-leading, or empty operand, bare `bash`/`sh` — classifies the stage **mutating**, keeping
  today's posture (prompt in Build/Auto edits, deny in Plan, nothing executed). One unrecognized
  option could restore execution, so silence means "no". A plus-leading operand is excluded for
  exactly that reason: `+n` and `+o noexec` (and grouped forms such as `+xn`) cancel no-exec mode, so
  `bash -n +n f.sh` would run the script; `bash -n ./+f.sh` still checks a `+`-named script.
- **The route rule: only where dispatch runs the exact validated argv.** `noExecShellStage`
  (`normalize_direct.go`) lifts a stage out of `wrapperPrograms` only for the bare, unquoted,
  unescaped `bash`/`sh` program word with no leading env assignment — so (g) keeps the literal route,
  as would `/bin/bash -n f.sh` or `"bash" -n f.sh`. On the literal route `stageIsShellProgram`
  (`planshell.go`) forces any shell stage mutating, which is why (f) and (h) do not auto-allow even
  though the inner text is an accepted form: `sh -c` re-parses text no validator saw. A bare
  `bash -n f.sh && ls` chain *does* auto-allow, because dispatch decomposes it to `dispatchStaged`
  and each stage runs as its own validated argv. Source: `normalize_direct.go`, `planshell.go`,
  `planshell_test.go`.

**14. The builtin lookup.**
- **Auto-allow:** (a) and (b). **Prompt:** (c), (d), (e), (f), (g), (h).
- The accepted grammar is exactly `command -v <name>`: three tokens, each the bare, unquoted,
  unescaped spelling, no leading env assignment, and `<name>` a plain program name of letters,
  digits, `_`, `-`, `.`, `+` not starting with `-` (`commandLookupTokens`/`plainProgramName`,
  `planshell.go`; `commandLookupStage`, `normalize_direct.go`). So (e) is an ordinary wrapper
  invocation, (f) carries an assignment, (h) is a path rather than a plain name, and (g) is the
  literal route, where `stageIsShellProgram` forces any wrapper stage mutating.
- (i) **Nothing runs.** The lookup is resolved by `exec.LookPath` during normalization and kept on
  `StageNormalization.LookupPath`; `builtinLookupResult` (`internal/dispatch/shell.go`) returns that
  path plus a newline with exit 0 from `dispatchDirect` and `dispatchStaged`, so no shell and no
  program is launched and the path is never resolved a second time — what dispatch does is exactly
  what was authorized. (b) auto-allows for the same reason `bash -n f.sh && ls` does: dispatch
  decomposes the bare compound to `dispatchStaged` and judges each stage on its own.
- (ii) The carve-out is qualified on the lookup **succeeding**, and the admitted namespace is Go's
  `exec.LookPath` — PATH executables only. An alias, a function, and a builtin such as `cd` are all
  misses, so `command -v cd` never qualifies, keeps `command`'s literal route, and prompts, exactly
  like (c). Distinguishing "absent" from "builtin" would require running a shell.
- (iii) `-V` is simply not in the grammar, and deliberately so: its answer is a sentence whose
  wording differs across dash, bash, and zsh, so codemeld would have to invent one and then assert
  its own invention. `command -V` and every `type` form are out of scope and keep today's prompting
  behaviour; `type` gains no `commandPolicies` entry at all. Source: `normalize_direct.go`,
  `planshell.go`, `internal/dispatch/shell.go`, `planshell_test.go`.

**15. The refusal before the check.**
- (a) **Refused earlier**, by the protected-state policy inside `PrepareTool`, before authorization
  runs at all. `move` widens to ancestor containment because a move relocates whole subtrees, so a
  source that *holds* `<project_root>/.codemeld/settings.yaml` carries it away; the single-target
  tools (`edit`, `create`, `delete`, `mkdir`) only match the named entry itself.
- (b) All of them: the read-only auto-allow, a declared write scope, the mode posture, the grant
  match, the turn cache, and the prompt. The policy is consulted first, so none of those routes is
  ever reached for one of the five guarded tools on a protected path.
- (c) **No.** There is no grant, mode, or approval that authorizes it — the supported route for
  changing those files is a dedicated typed writer such as `/settings`. Supported, not
  exclusive: the guard leaves the VCS mutation tools and a granted raw `bash` command uncovered.
- (d) **No.** The refusal is `denied_by: "guard"`, which is recoverable: the loop re-issues so the
  model can report the refusal and name `/settings`.
Source: `securitystate/protect.go` (`Policy.protects`, `guardedTools`), `dispatch/tool.go`
(`PrepareTool`), `bootstrap/tooldispatch.go` (`denyProtectedState`).

**16. Reading the three `denied_by` values.**
- `user` — a human at the prompt, or a fail-closed non-interactive run with no approval available.
  **Terminal**: the turn halts.
- `mode` — the active mode's posture, e.g. Plan refusing a mutation. **Recoverable**: the loop
  re-issues.
- `guard` — the protected-state policy, before any authorization ran. **Recoverable**: the loop
  re-issues.
An unrecognized value is treated as **terminal**. That is the fail-closed direction: continuing on a
refusal the loop cannot classify would let an unknown policy be worked around by simply trying
again, whereas halting on a value a newer build understands only costs a turn.
Source: `permissions/denyenvelope.go`, `turn/tools.go` (`decodeDenyEnvelope`).

**17. Why `awk` is not name-only.**
- **Auto-allow:** (a), (b), (c), (d), (e), (h), (i), (j), (p). **Prompt:** (f), (g), (k), (l),
  (m), (n), (o).
- `awkStageReadOnly` (`planshell.go`) accepts only `-F` field-separator options, then one inline
  program, then zero or more operands, and admits the program through either of two paths: the
  retained range-print grammar (`awkRangePrintProgram`), which still takes (a)–(d) and (h) as before,
  or the lexer `awkReadOnlyProgram` (`awkprogram.go`), which admits any program with no write,
  command, or environment reach — so (e)'s `$1`, which the old grammar refused, now passes, and
  (j)'s `/` follows the value `s`, where it can only be division. (f) is a
  `name=value` operand AWK treats as a variable assignment rather than an input file; (g) and (o)
  reprogram the script with `-v`, which no program text can make safe; (k) writes to a file with
  `print >`; (m) calls the banned `system`.
- (1) Any three of: run a program (`system("…")`, `print | "cmd"`), read an unvalidated source
  (`getline < "/etc/passwd"`), write or truncate a file (`>`, `>>`), read the environment
  (`ENVIRON["HOME"]`), redirect which files are read (`ARGV[1] = "/etc/shadow"`), or be reprogrammed
  by an option (`-f prog.awk`, `-v x=1`). A name-only entry is judged by the executable alone, so
  none of these would ever be seen — which is why `awk` is `argSensitive` with a validator and is
  pinned out of the name-only set by `TestReadOnlyExecutableSetUnchanged`.
- (2) Whitespace around the punctuation is optional on both paths, so (a) and (b) are the same one
  range and one print action.
- (3) Neither path evaluates the program: the range grammar compares the bounds as token text, and
  the lexer only checks which tokens appear. A reversed range matches no record and prints nothing,
  which is as read-only as any other range.
- (4) AWK allows an output redirection in a `print`/`printf` statement, and the lexer does not try
  to tell a redirect from a comparison, so it rejects every `>` or `>=` there. (l)'s parenthesized
  `a > b` is a comparison that writes nothing, but it prompts anyway: a safe program lost to that
  conservative rule. In (i) the `>` is in the pattern, before the `{ print }` statement
  begins, so it can only be a comparison.
- (5) AWK implementations disagree on whether a `/` inside a bracket expression ends the regex, and
  a misread regex boundary could hide code inside what looked like regex text, so codemeld fails
  closed on that ambiguity — a deliberate choice, not a claim that (n) is invalid AWK. (p) escapes
  the slash outside a bracket (`/\//`), which every AWK reads the same way, and auto-allows.
- (6) With no operand AWK reads stdin, which holds only what the user piped or typed in, so it
  reaches nothing the operand checks would have refused.
Source: `permissions/awkprogram.go` (`awkReadOnlyProgram`), `permissions/planshell.go`
(`awkStageReadOnly`, `awkRangePrintProgram`, `commandPolicies`), `permissions/planshell_test.go`
(`TestClassifyReadOnlyShellAwk`, `TestAwkStageTokensFailClosed`, `TestReadOnlyExecutableSetUnchanged`),
`permissions/awkprogram_test.go` (`TestAwkStageRejectsAdversarialPrograms`,
`TestAwkStageRejectsUnsafeOptions`, `TestAwkReadOnlyProgramAccepts`).
