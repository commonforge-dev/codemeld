# Module 5 — Permissions (the differentiator)

_Snapshot as of 2026-10-06; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-10-06_

> Prerequisite: none strictly, but Module 2 (core types) and Module 4 (config) make this easier.
> This is the headline module — the permission system is what most distinguishes codemeld.

## Goal

After this module you can:

- Explain why `git log`, `/usr/bin/git log`, `GIT_PAGER=cat git log`, and `cd sub && git log`
  are treated as the **same** approval — and name the mechanism behind each.
- Name the three grant **lifetimes** and exactly where each is stored.
- State the **path-scope rule** precisely, including why a grant in `/a/foo` does not leak to the
  sibling `/a/foobar`.
- Explain what the **turn-scoped cache** does and how it differs from a grant.
- Say what the agent receives when a request is **denied**.

## Why it matters

Phase 1 ships **no sandbox**. The permission system *is* the authorization mechanism — the
"front door" (`docs/architecture.md` → "Permission system is the front door"). It is also the
feature the README leads with. If you understand this module, you understand codemeld's stance:
approve once, never re-prompt for the same operation spelled differently, never an
"approve-everything" escape hatch.

## Read (in order)

1. `docs/architecture.md` → "Permission system is the front door" and "Tool dispatch is exact-name".
2. The code, in this order — each file's top doc comment states, in words, the rule it enforces:
   - `internal/permissions/entry.go` — `PermissionEntry`, `ParseEntry`, `ComputeArgumentHash`,
     `DedupKey`, `MarshalEntry`. The on-disk grant shape.
   - `internal/permissions/scope.go` — `CleanAbsResolve`, `IsDescendantOrEqual`, `DerivePathScope`,
     `FindScopeEscalation`. Path-scope rules, plus the display-only broader-than-existing signal.
   - `internal/permissions/shell_tokens.go` — the tokenizer that preserves quote/escape metadata
     (skim; you'll lean on it in the next two files).
   - `internal/permissions/normalize_direct.go` — `NormalizeDirectStage`, `MatchesDirectSubject`,
     `canonicalProgram`, `isEnvAssignment`. How a raw command becomes a canonical subject — and,
     on `StageNormalization.Source`, the display-only spelling that canonicalization throws away.
   - `internal/permissions/normalize_literal.go` — the wrapper/indirect route (byte-equal match).
   - `internal/permissions/pipeline.go` — splitting a whole command into stages.
   - `internal/permissions/matcher.go` — `Match`, `subjectMatches`, `pathScopeMatches`. The check.
   - `internal/permissions/planshell.go` — `classifyReadOnlyShell`, `stageTokensReadOnly`,
     `commandPolicies`. The one shared all-mode read-only shell classifier and its admitted
     diagnostics.
   - `internal/permissions/turncache.go` — `TurnCache`. The per-turn memoization.
   - `internal/permissions/denyenvelope.go` — what the agent gets on a deny.
3. Cross-references: the package's own `_test.go` files — the normalization, scope, and matcher
   tables are the exhaustive specification of behavior (pipeline split, path-scope resolve, turn
   cache, direct matching are each pinned by a test table).

> Citations in this module and its answer key use **file + function/symbol name**, never line
> numbers — lines move as the code changes, but a symbol name stays findable with your editor's
> "go to symbol" or a quick search.

## Mental model

### The shape of a grant

A stored grant is a `PermissionEntry` (`entry.go`): a 4-tuple identity
`(Kind, Subject, PathScope, GrantKind)` plus an optional `ArgumentHash`.

- **Kind** ∈ `direct` | `literal` | `tool` — how the subject is matched.
- **Subject** — the canonical command/tool string.
- **PathScope** — `"*"` for a global grant, or a cleaned absolute directory for a folder grant.
- **GrantKind** ∈ on-disk `folder` | `global`, plus `project` for a web host grant (below); plus in-memory-only `session` (the
  `grantKindSession` constant in `matcher.go`).

The cross-field rule is strict, enforced in `ParseEntry` (`entry.go`): `path_scope == "*"`
**iff** `grant_kind == global`.

### The three lifetimes (and where each lives)

| Lifetime | Stored where | PathScope |
|----------|--------------|-----------|
| **session** | nowhere — in memory only, gone when the process exits | a concrete folder (descendant rule, like folder) |
| **folder** | `<project_root>/.codemeld/settings.local.yaml` | the cleaned absolute folder |
| **global** | `~/.codemeld/global/settings.yaml` | `"*"` (all paths) |

A web tool's "allow in this project" approval is the folder grant's network counterpart: a
**project host grant** (`grant_kind: project`) for one exact host and one tool. It carries a
`host_scope` instead of a `path_scope` and is written to the same
`<project_root>/.codemeld/settings.local.yaml`.

Folder and project grants are permanent, but they stay on this machine: the local file is not
shared with the team. A permanent approval reaches the shared `.codemeld/settings.yaml` only when you
share it — the `/settings` picker's share action publishes that one entry after a confirmation,
and a second action removes one shared entry. codemeld writes the shared file in no other way (Module
4 → "Persist").

Global is **never the default** in the prompt, and there is **no "approve everything" mode**.

### Why differently-spelled commands collapse to one subject

A raw command is normalized before it's matched, so equivalent spellings produce one canonical
subject. Four distinct mechanisms, four files:

1. **Absolute path → bare name.** `canonicalProgram` (`normalize_direct.go`) reduces
   `/usr/bin/git` to `git` — but only if `git` on the current `$PATH` resolves (via
   `os.SameFile`) to that exact executable. An out-of-PATH binary keeps its full path so it
   can't impersonate a bare-name grant.
2. **Leading env assignments stripped.** `NormalizeDirectStage` (`normalize_direct.go`)
   peels leading `KEY=VALUE` tokens off the *subject* (predicate `isEnvAssignment`) so
   `GIT_PAGER=cat git log` matches the grant `git log`. The assignments are **kept** in
   `StageNormalization.Assignments` so the authorized command still runs with the requested
   environment — they're out of the matched identity, not discarded.
3. **`cd <path> && cmd` becomes path scope, not subject.** `DerivePathScope` (`scope.go`)
   gives a `cd` prefix precedence as the request's path scope. So `cd sub && git log` authorizes
   the subject `git log` *in `sub`* — the `cd` never becomes part of the command identity.
4. **Pure pipelines split into stages.** The splitter in `pipeline.go` splits a bare `a | b`
   pipeline on `|`; each stage is authorized **separately, by exact program name** (`Match` in
   `matcher.go`, and `architecture.md` → "stage-by-stage by exact program name"). So in
   `git log | head`, the `git log` stage reuses your existing grant; `head` is its own
   authorization decision. (The README's "`git log | head` doesn't re-prompt" is about the
   `git log` stage, not a claim that the pipeline is one unit.)
5. **Safe `&&`/`||`/`;`/`|` compounds split into direct stages; everything else is one literal subject.**
   `SplitCommand` sends every bare compound to the **literal** route (`pipeline.go`), but
   `DispatchShell` then re-admits the narrow safe set: if the compound is bare (not
   `sh -c`-wrapped), decomposes cleanly via `SimpleCompoundStages`, and its operators are **only**
   `&&`, `||`, `;`, and/or `|`, each stage is authorized as its own **direct** subject exactly like a
   pipeline stage — so a mixed form such as `hg log ; hg diff | head` is three direct subjects, not
   one literal one. That is why a direct grant such as `go test :*` authorizes every matching
   stage of `go test ./internal/permissions && go test ./internal/dispatch` without another prompt: the
   grant is matched per stage, not against the whole command. Authorize-all-before-run still applies,
   so one stage outside the grant denies the chain and nothing runs. Two consequences follow from a
   chain leaving `sh -c`: its stages run as literal argv, so globs and variables
   are no longer expanded for them, and their read-only verdict comes from the per-stage classifier,
   which trusts each program's own validator against the exact tokens instead of vetoing every
   argument-sensitive program.

   Everything else stays **one literal subject**: redirection, a wrapper, a subshell,
   backgrounding, an env-assignment-bearing stage, and any malformed or empty stage. By default that matches byte-exact like any literal; a **simple compound**
   (`sh -c '<stage> [&& <stage>]…'`, or a bare compound whose every stage is otherwise a direct
   command) can also be authorized by a *generalized* grant that pins the program set and operator
   structure while widening each stage's arguments to its chosen scope (`compound.go`:
   `RecognizeSimpleCompound`, `EncodeCompoundSubject`, and the generalized branch of
   `subjectMatches`). Anything non-simple that still *reaches* literal matching (a subshell,
   redirection, a nested wrapper, an env-assignment-bearing stage, or a stage whose program
   `IsDestructiveProgram` flags) stays byte-exact — fail closed, because a false widen is a security regression
   while a false byte-exact is only friction. Redirection has one narrow exception, and it is a
   **grant-identity** rule only: `RecognizeSimpleCompoundForGrant` ignores bare `/dev/null` redirects
   when deciding which stored grant covers a request, so a compound disqualified by nothing else can
   still open the chooser and store a generalized subject. It is a *different, narrower* strip than the
   classification one described later in this module — no `2>&1`, and stdout only off a pipe — and it
   is detailed there. An **unquoted** command substitution (`$(…)`) or backtick never gets
   that far: `SplitCommand` rejects it before any prompt (`firstRejectedConstruct` in
   `pipeline.go`), so no grant — direct, literal, or generalized — can ever authorize it. A `$(…)`
   or backtick **inside double quotes** is different, because the shell performs it:
   `SplitCommand` routes the whole command literal (`hasDoubleQuotedSubstitution`), so it runs
   through `sh -c` with the substitution performed, it always prompts until an exact-text grant
   covers it (Plan denies it), and it is never a simple compound, so only a byte-exact literal grant
   can cover it. Single-quoted or escaped substitution text (`echo '$(x)'`,
   `awk '{print $(NF)}' f`) is inert and keeps its direct route
   (`TestSplitCommand_DoubleQuotedSubstitutionRoutesLiteral`,
   `TestSplitCommand_InertQuotedSubstitutionTextStaysDirect`,
   `TestDoubleQuotedSubstitutionIsNeverAutoAllowed`).

Wrapper/indirect forms (`sh -c …`, `env FOO=bar …`, `bash`, `command`, `nice`, `nohup`, `time`,
`xargs`) deliberately leave the direct boundary and route to **literal** matching
(`wrapperPrograms` in `normalize_direct.go`), which is byte-equal on the canonical subject (or, for
a simple `sh -c` compound, generalized per point 5) — you can't smuggle an arbitrary command past a
direct grant by wrapping it. Three narrow grammars are the exception, and they share one reason: the
tokens codemeld inspected *are* the invocation that executes. They are the `bash -n` / `sh -n` no-exec
syntax checks (`noExecShellStage`), `command -v <name>` (`commandLookupStage`), and a **standalone**
flagless `bash`/`sh` script invocation such as `bash process-dir.sh u.txt` (`scriptInvocationStage`). All three are detailed later in this module.

### What the prompt shows is not what the grant matches

Everything above describes the **matching** subject. The **prompt** deliberately shows something
else: the *effective source* — the command exactly as the agent spelled it, minus only the `cd
<path> &&` prefix (point 3 above; that's path scope, not command text).

The two must differ, because the collapsing that makes matching work is lossy. `git commit -m "a
b"` has the canonical tokens `git commit -m` + `a b`; rendering those back gives `git commit -m a
b`, which looks like *two* arguments. A user approving a command has to see the quotes that decide
what actually runs, so the prompt shows the source spelling instead.

The plumbing: `StageNormalization.Source` carries each accepted direct stage's verbatim text
beside its canonical `Tokens`, the way `Assignments` and `ExecForms` already carry execution-only
detail (points 2 and the `~` expansion). `dispatch/shell.go` copies it to `PromptDisplay.Subject`;
the literal route displays `SplitCommand.LiteralInput`, which is byte-identical to the string handed
to `sh -c`.

The rule that keeps this safe is **one-directional**: source text is display-only. It never reaches
`MatchRequest.Subject`/`SubjectTokens`, a grant, a turn-cache key, an event, the read-only
classification, or runner argv — those all stay on `Tokens`. If a display string could reach a grant
key, a cosmetic re-spelling could widen what an approval covers. When you touch this code, that is
the invariant to check first.

### The request that never reaches the check

One class of request is refused before any of this runs. codemeld's own settings files carry the
grants that this whole module is about, so a model-facing structured file tool that could rewrite
them could rewrite its own authorization. A recorded session did exactly that: two ordinary `edit`
calls removed seven approved folder grants.

`PrepareTool` (`internal/dispatch/tool.go`) therefore consults a protected-state policy
(`internal/securitystate`) before it hands anything to authorization. The policy holds the run's three
configured settings paths — the shared `.codemeld/settings.yaml`, the local
`.codemeld/settings.local.yaml`, and the global `~/.codemeld/global/settings.yaml` — plus the
project approval store `~/.codemeld/global/approved-projects.yaml`, and each one's `.lock` sidecar,
and refuses exactly five tools on them:
`edit`, `create`, `delete`, `mkdir`, and `move`. It checks the endpoint the model *named* before the
tool's own resolver runs, and the resolved endpoint after it, so neither an alias nor a
`move` of the directory that holds a protected file slips past.

Because it runs first, it pre-empts every route in this module — the read-only auto-allow, a
declared write scope, the mode posture, the grant match, the turn cache, and the prompt. There is
no grant, no mode, and no approval that authorizes one of these five tools against those files.
Read-only tools are outside the policy entirely; so is raw shell, which is a real remaining gap
rather than a covered case.

The `vcs_<action>` tools are a second way to rewrite a file, and they are covered by the same
policy. A VCS action runs its template's argv as a real subprocess with no sandbox, so the check has
to happen *before* it launches — once `git switch` or `git stash pop` has replaced the settings
file, refusing afterwards changes nothing. Right after `PrepareTool` resolves the directory the
action will run in, it asks the action for a verdict:

- A **built-in** action (or a byte-identical first-run reference copy) that can replace working-file
  bytes — Git and Mercurial `branch-switch`, `restore-file`, `stash`, `stash-pop`, plus Jujutsu
  `branch-switch` and `restore-file` — runs one small read-only backend query, such as
  `git ls-files --error-unmatch -- .codemeld/settings.yaml`, asking whether a protected file is in
  what the action would change. Yes, or an answer the query cannot establish, refuses.
- For `restore-file` that would-change set is bounded by the path the model asked to restore, so
  restoring an unrelated file stays available. The protected file itself, a directory holding it, a
  hardlink alias, a path reaching it through a symlinked directory, and any argument the check
  cannot bound — a whole-tree `.`, a flag, a wildcard, a Git pathspec, a Mercurial pattern, or a
  Jujutsu fileset expression — all refuse.
- Jujutsu's `stash`/`stash-pop` only print status, and `add`/`commit` record history without
  touching the working copy, so committing settings bytes the user already approved still works.
- A **custom** template can put any command behind a familiar action name, so a custom action is
  refused while the policy is active — unless it comes from the trusted global template directory,
  declares `class: read_only`, *and* runs the built-in's own read-only argv exactly. A project
  template never gets that exception.

A protected file is recognized inside the repository by its path, through a symlink, and through a
**hardlink** to it. What this does *not* cover: repository hooks, filters, and extensions, and a
change made by something else between the query and the action.

The refusal is its own `denied_by` value — see `### Deny` below — and it is **recoverable**: the
turn loop re-issues the model with the refusal in context so it can point the user at
`/settings`, which is one of the dedicated writers that *may* change these files.

### The check itself

`Match(req, grants)` (`matcher.go`) walks grants **in stored order** and returns the first
whose kind, subject, and path-scope all satisfy the request:

```
MatchRequest{Kind, Subject, SubjectTokens, PathScope}
   │
   ├─ subjectMatches      direct → MatchesDirectSubject(tokens)   (normalize_direct.go)
   │                      literal → byte-exact MatchesLiteralSubject (normalize_literal.go), or
   │                                generalized compound match for a compound grant (compound.go)
   │                      tool    → exact Subject == grant.Subject
   │
   └─ pathScopeMatches    global  → grant.PathScope == "*"
                          session/folder → IsDescendantOrEqual(reqPath, grant.PathScope)
```

`IsDescendantOrEqual` (`scope.go`) is the heart of path-scoping: a grant authorizes its
scope and **every descendant**, never an ancestor, never a sibling. It's computed with
`filepath.Rel` so it's **boundary-safe** — scope `/a/foo` does **not** match `/a/foobar`
(a naïve string-prefix check would wrongly match it).

### The broader-than-existing signal (display only)

Because a grant never authorizes its *ancestor*, asking for a folder broader than one you
already approved correctly **re-prompts** — a grant in `/work/notes` does not match a
request at the parent `/work`. But that re-prompt, on its own, looks identical to a fresh
request for a brand-new narrow folder, hiding that you're about to *widen* an earlier approval.
`FindScopeEscalation(req, grants)` (`scope.go`) closes that gap **without changing
authorization**: it reuses the same `subjectMatches` rules and `IsDescendantOrEqual` to find an
already-approved **same-subject** grant whose scope is a *strict descendant* of the request
(i.e. the request is a broader ancestor), and returns the narrowest such scope in a
`ScopeEscalation`. It **ignores global grants** (a global grant would have matched before
prompting, and `*` is not a narrower folder). It is computed only on the prompt path, after the
grant and turn-cache misses, and it creates/changes/reads **no** grant, cache key, or event —
the returned scope only feeds a warning line in the prompt (see Module 10).

### Turn cache ≠ grant

`TurnCache` (`turncache.go`) memoizes the *outcome* of each prompt for the duration of one model
turn, keyed by `(kind, subject, pathScope)` — so an agent that retries a transient failure inside
the same turn isn't re-prompted. It is consulted **only after** `Match` finds no real grant
(real grants always win), it stores **no** grants (even a hit creates nothing durable), it caches
**denies** too, and it's `Reset` at the start of every new user submission so each turn
re-confirms intent. SubjectTokens is excluded from its key on purpose.

### Deny

On a deny, `denyenvelope.go` builds a structured, UTF-8-capped JSON envelope delivered back to
the agent as the tool result, so the model learns the request was refused rather than silently
hanging.

`denied_by` says who refused, and the value decides whether the turn survives:

| `denied_by` | Who refused | Turn outcome |
|-------------|-------------|--------------|
| `user` | a human at the prompt, or a fail-closed run with no approval available | terminal — the turn halts |
| `mode` | the active mode's posture (Plan refusing a mutation) | recoverable — the loop re-issues |
| `guard` | the protected-state policy, before authorization ran at all | recoverable — the loop re-issues |

Anything the classifier cannot place stays terminal, so an unrecognized value fails closed rather
than continuing.

### The shared read-only shell classifier

One classifier decides whether a raw-shell stage is side-effect-free, and it is the **same** in
every mode:
`classifyReadOnlyShell` → `stageTokensReadOnly` over the product-authored `commandPolicies` table
in `planshell.go`. A read-only verdict auto-allows the stage in Build and Auto edits and is the
only shell form Plan permits; no mode keeps a duplicate list. The table admits three shapes:
name-only readers (`cat`, `ls`, `grep`, `col`, …, safe by the program alone — `col` only reformats
stdin and has no write-capable option), read-only VCS subcommands
(hg `status`/`st`, `diff`, `log`/`history`, `cat`, `summary`/`sum`, `files`, `help`, `grep`, `root`,
`id`/`identify`, `manifest`, `parents`, `heads`, `annotate`/`blame`, `tags`, `branches`, `tip`,
`paths`, `version`, `locate`, `export`, `verify`, `admin::verify`, `resolve`, `bookmarks`/`bookmark`, `branch`, and `phase`; git `status`, `diff`, `log`, `show`, `ls-files`, `help`, `grep`, `blame`,
`ls-tree`, `describe`, `shortlog`, `show-ref`, `for-each-ref`, `merge-base`, `name-rev`, `rev-list`,
`cat-file`;
with mutating flags
deny-listed — hg `--config`, `-R`/`--repository`, `--pager`, `-o`/`--output`, `--ssh`,
`--remotecmd`, `--insecure`, `--debugger`, `-T`/`--template`, `--style`, and git `-c`,
`--config-env`, `--git-dir`, `--work-tree`, `--exec-path`, `--output`, plus flags denied only under
the subcommand that makes them dangerous: hg `id`/`identify` → `-e`, `admin::verify` → `--option`,
git `grep` →
`-O`/`--open-files-in-pager`/`--textconv`/`--ext-grep`, `diff`/`log`/`show` → `--textconv`,
`cat-file` → `--filters`/`--textconv`, `help` → `-w`/`--web`. `git grep -O[<pager>]` opens its
matches in an arbitrary program while the same `-O` is `git diff`/`log`/`show`'s read-only
`--order-file`, and `git help -w` opens a browser while `git diff/blame/log/shortlog -w` only
ignores whitespace or wraps output. Git resolves any unambiguous abbreviation of a subcommand long
option — `git grep --textcon` and `git cat-file --fil` both run a config-defined program — and
which prefixes are unambiguous depends on the installed version's flag set, so a scoped long flag
denies **every prefix of itself** and exempts only an audited list of exact safe spellings carried on
the entry (`scopedDenyFlag.safeSpellings`, today only `--text` inside `--textconv`). That exemption
is per subcommand: `git grep --text` is a real read-only flag, while `git cat-file --text` resolves
to `--textconv`. Over-denial only costs a prompt, so the rule fails closed on a git it has never
seen), and
the **argument-sensitive** commands, each with its own validator. Those are the file/text readers
`find`, `uniq`, `sed`, and `awk` (`awk`'s program rule is spelled out below) — `sed` admits only `-n`/`--quiet`/`--silent` plus a print-only script
followed by plain file operands or none at all (`sed -n 1,28p` reads stdin in a pipeline). That
script is one or more `;`-separated commands and **every** one of them must be either an optional
`N`, `$`, `N,M`, or `N,$` address then `p` or `=` then an optional `q`, or a quit — bare `q` or a
single-address `Nq`/`$q` — so `sed -n '150,245p;1020,1170p;1460,1575p'` and `sed -n '1,5p;5q'` are
read-only while one unaccepted command rejects the whole script: an empty command (`1,5p;`, `;;3p`),
a command with leading whitespace (`1,5p; 3p`), a two-address quit (`1,5q`), `-i`, `-e`, `-f`,
`w`/`W`, `s///`, `r`, `e`, a `{…}` block, a dash-leading operand, and regex addresses all stay
mutating —
the no-exec shell syntax checks `bash` and `sh` (below), and the platform-specific diagnostics. Linux admits `ps`, `pgrep`, `pidof`, `pstree`, `lsof`, `ss`,
`free`, `vmstat`, `uptime`, `journalctl`, `dmesg`, and `top`; FreeBSD admits `ps`, `pgrep`, `pidof`, `pstree`,
`fstat`, `procstat`, `sockstat`, `vmstat`, and `uptime`. The same command name can have a different
validator or admitted form on each platform, and FreeBSD `dmesg` is not admitted. `ps` is the
broadest of them and the one exception to the per-option shape: one shared validator classifies
**any** direct `ps` argument list read-only on both platforms, so `ps --help`, `ps --version`,
`ps -eF`, `ps --forest`, `ps -eo pid,cmd --sort=-pcpu`, `ps -L`, and `ps ax` on Linux, and `ps -ww`,
`ps -tt`, `ps -Dboth`, `ps 1234`, `ps -o etime,nlwp`, and `ps --libxo=json` on FreeBSD, all
auto-allow. What the classifier asks is whether a command can **write a file, execute another
program, create network egress, or escape scope**, and no documented `ps` option on either platform
does any of those: Linux `ps` reports a `/proc` snapshot, and FreeBSD `ps(1)` documents no
output-to-file, signal-delivery, write, execution, or scope-escape option, with PIDs as its
positional operands. That axis is **not** a confidentiality filter — how much of the system a
read-only command may see is settled once for every process/socket/log reader admitted here, not
per `ps` flag. The route guards are untouched, because `ps` stays argument-sensitive on both
platforms: `LD_PRELOAD=/tmp/x.so ps -ef`, `ps -ef > out`, `ps -ef && ls`, `sh -c "ps -ef && ls ~/x"`,
and `ps "$(id)"` all stay mutating. `ps "$(id)"` never reaches the `ps` validator as a direct
stage: an unquoted substitution is refused before any prompt, and a double-quoted one sends the
command down the literal `sh -c` route, where the substitution runs and the command always prompts
until an exact-text grant covers it. The validator still refuses substitution syntax left in inert
quoted text such as `ps '$(id)'`, which costs only a prompt, while a quoted variable or glob only
changes argument text and the direct route runs the literal argv. The recognized inert `sh -c`
wrapper and bare `/dev/null` routes were already open to `ps` on Linux before this change
(`sh -c "ps aux"` was read-only) and keep their guards, so `sh -c "ps --help"` and
`ps --help 2>/dev/null` auto-allow with them exactly as the direct forms do. `top` is the
narrowest of them: only the Linux procps-ng **bounded batch** form is admitted — `-b` **and** a
bounded positive `-n`, plus the display-only flags `-e`/`-E`, `-o`, `-p`, `-H`, `-h`, `-V`, `-O`
(so `top -b -n 1 -e m -o +RES` is read-only) — while bare `top`, any form missing `-b` or a bounded
`-n`, any other flag, and **every** `top` form on FreeBSD and macOS stay mutating. The shared base
prompt states that same limit to the model in every mode, and a Plan-mode denial of a direct Linux
`top` stage answers with corrective wording naming `-b`, a bounded positive `-n`, and `top -b -n 1`
instead of the generic shape guidance; both are advisory. The validator is the authority — no
prompt wording and no recovery text can widen what auto-allows. Every validator other than `ps`
accepts only an exact bounded form and fails closed: an unknown option, a missing or invalid value, or
an unsupported operator classifies the stage mutating. Which routes an argument-sensitive command can
auto-allow on is the **execution-fidelity** rule: a direct stage and a bare `&&`/`||`/`;` stage both
execute as the exact argv the validator inspected, so `sed -n '1,5p' a; sed -n '9,20p' b` auto-allows
stage by stage. The literal route hands the text back to a shell that expands and re-splits it after
validation, so an argument-sensitive command auto-allows there only when **every raw token is
inert** — no `$`, backtick, glob, brace list, or leading `~` — which makes the argv the shell runs
the argv that was validated: `sh -c "ps aux"` and `sh -c 'sed -n 1,5p f && ls'` auto-allow, while
`sh -c 'sed -n 1,5p $F'` and the mixed form `sed -n '1,5p' a | head; ls` stay mutating. Two kinds of redirection are read-only-neutral:
`stripNullRedirects` removes the bare forms `>/dev/null`, `1>/dev/null`, and `2>/dev/null`
(whitespace before the target allowed, and a descriptor-less `>` may sit directly against the
preceding word as in `grep x f>/dev/null`, while a `1`/`2` descriptor must be its own token) and the
two descriptor duplications `2>&1` and `1>&2` (both descriptors explicit and adjacent — a duplication
creates no file and truncates none) from a
**copy** of the canonical text before classifying it, so `grep -n x f 2>/dev/null` and
`grep -n x f 2>&1` auto-allow. That copy is also the only thing that admits an **all-`|`** compound
here: `grep a f 2>/dev/null | head` and `hg log 2>/dev/null | grep x | head -20` auto-allow because
what the strip leaves is the same stage list the direct route would have judged one stage at a time,
while a redirect-free `grep a f | head` never reaches this classifier at all — it stays a direct
pipeline. An all-`|` compound held whole by anything the strip does not remove — a wrapper, a
subshell, an env-assignment-bearing stage, a surviving redirect — stays mutating. Every
other redirect — a different target, `>>`, `<`, `&>`, another descriptor pairing such as `3>&1`,
`2>&3`, or a descriptor-less `>&1`, or a quoted target such as
`2>'/dev/null'` — stays mutating. Quoted or escaped redirect-looking text is never structure and is
never stripped, so `echo "2>/dev/null" f` keeps its ordinary direct-route classification: an `echo`
argument that happens to contain `>`.

**Two strips, not one.** The strip above is classification-only. Grant identity has its own, narrower
strip (`stripNullRedirectsForGrant` / `RecognizeSimpleCompoundForGrant` in `compound.go`), and the two differ in what they remove. The grant strip removes only bare
`>/dev/null`, `1>/dev/null`, and `2>/dev/null`; it never removes `2>&1` or `1>&2`, and it removes the
two **stdout** forms only on a stage that does not feed a pipe (the last stage, or one followed by
`&&`, `;`, or `||`) — `a >/dev/null | b` and `a | b` do not hand the same bytes to `b`, the same
downstream-data reason the duplications are excluded. A compound grant's identity is therefore "the
compound modulo bare `/dev/null` redirects": one grant covers `./p.sh u.txt 2>/dev/null | sed -n 1,18p`
and `./p.sh u.txt 2> /dev/null | sed -n 1,18p`. When that strip actually removed a redirect, the
command must additionally be expansion-free in every stage (`stagesExpansionFree`), because `sh -c`
re-parses the text the chooser generalized; a redirect-free compound keeps the recognition it always
had, with no new gate. Every other redirect keeps a **byte-exact** grant — a different target, `>>`,
`<`, `&>`, `3>&1`, a quoted target, or a glued word suffix such as `f1>/dev/null`, which is an
argument followed by a stdout redirect rather than an explicit descriptor. Neither strip changes what
runs: the command still routes to `dispatchLiteral` and still executes verbatim through `sh -c`, and
the prompt still shows the redirect.

For hg and git the subcommand is **not** simply the second token. `commandPolicy.stageSubcommand`
scans the leading tokens for the first one that does not start with `-`, so `hg --cwd main cat -r REV
f` classifies as the `cat` read it is, instead of failing at the flag before it reaches `cat`. Only two exact spellings may come
first — hg `--cwd` and git `-C`, the flags that choose a working directory — and the **value** that
follows one is skipped, which is the whole security argument: without that skip, `hg --cwd status
commit` and `git -C log commit` would read a directory named `status`/`log` as the subcommand and
auto-allow a commit. A `--cwd=main` spelling consumes nothing, a `--cwd` with no following token
yields no subcommand, and any other leading flag — including hg's own valid abbreviation `--cw` —
yields no subcommand and stays mutating; the exact match lives on the admit side, while hg's
deliberately over-broad `abbrevLong` prefix matching stays on the deny side, where over-matching only
costs a prompt. Choosing a directory is admitted rather than denied because this classifier never
consults path scope at all: `cd P && hg log` already auto-allows, and `hg --cwd P log` reads the same
repository the same way. Retargeting a *repository* is a different thing and stays denied
(`-R`/`--repository`, `--git-dir`/`--work-tree`), and because the deny scan still covers every token
in the stage, a permitted `--cwd` never rescues a denied flag later in the command:
`hg --cwd main --config alias.x=!sh log` and `git -C /dir --exec-path=/tmp log` are both mutating.

Mercurial needed three rules the subcommand token alone cannot express, and they are worth reading
together because each one exists for a bypass that survived the previous one.

The set lists hg's documented **aliases** — `st`, `sum`, `history`, and the canonical `identify`, of
which `id` is the alias — but not its command **prefixes**. hg happily runs `hg sta`, yet which
prefixes are unambiguous depends on which extensions are installed, so a prefix rule on the admit
side would fail open on a machine whose extension set differs. `hg sta` therefore prompts.

Several subcommands are admitted only in an exact argument form, and the check for them hangs off the
**resolved subcommand** (`commandPolicy.subcommandArgs`), not the policy-level `validator` field —
`stageReadOnly` returns a validator's verdict before it ever reaches the subcommand set or the deny
scan, so a validator on `hg` would silently discard every one of them. `resolve` reads only as exactly
`hg resolve -l` or `hg resolve --list`; anything else fails closed, because `hg resolve --tool CMD`
runs an arbitrary merge program. `id`/`identify` reads only with **no positional token at all**. That
last rule looks over-strict until you follow the bypass: identify carries a hidden `-e`/`--ssh CMD`
that hg runs as the transport program, so `hg id --ssh '<any command>' ssh://host/repo` executed
before any network contact. Denying the flag is not enough — hg accepts a cluster whose last letter
takes the value, so `hg id -ne CMD` still works — and testing the argument for `://` is not enough
either, because hg resolves a `[paths]` alias, so `hg id default` reaches a remote with no URL text
anywhere in the stage. Rejecting every positional is the control that closes both; the transport
flags are denied as well, but only as defense in depth.

The remaining three are the commands whose verdict flips on their arguments alone. `bookmarks` (and
its `bookmark` alias) reads bare or as exactly `-l`/`--list`; a positional NAME creates a bookmark and
`-d`/`-m`/`-r`/`-i`/`-f` delete, rename, or move one. `branch` reads only bare, because every argument
it takes sets a branch — including the EXPERIMENTAL `-r`/`--rev VALUE`, which is why `branch` and
`phase` must never share a validator even though the spelling is identical. `phase` reads bare or with
the repeatable `-r`/`--rev` selector, separate or `=`-joined, while `-p`/`-d`/`-s` move a phase
boundary that cannot be walked back locally once a changeset is published. The validator judges only
the flag names; a flag's **value** is left to the deny scans that run over every token afterwards, so
`hg phase -r --template` is rejected even though the validator consumed `--template` as a value.
`bisect` is not in the set at all — a bare `hg bisect` resumes the search and updates the working
directory, so there is no read-only form to validate.

Templates are denied program-wide (`-T`, `--template`, `--style`, their long prefixes, and `-T`
hidden in a cluster) because the template language's `config()` function reads configured values, and
`hg paths` hides an embedded password only when the formatter is plain — so `hg paths -Tjson` prints
`https://user:pass@host` verbatim. `--debugger` is denied for the same class of reason: it enters
pdb, which reads Python from stdin. Its prefix rule also rejects the harmless `--debug`, and the
cluster scan rejects a revision glued to `-r` and spelled with an `R`, `o`, or `T`; both are accepted,
because over-denial costs a prompt and under-denial costs an auto-allowed execution.

Finally, argv is not hg's only input, so classification alone could not close the boundary. A user or
repository hgrc supplies aliases (`[alias] x = !<shell>`), hooks, defaults, and extensions that the
approved argv never names, and `HGPLAIN` does not disable them. `permissions.Decision.ReadOnlyAuto`
marks the one allow the active mode granted **because the command classified read-only** — never a
prompt, grant, cache, or declared-scope allow — and dispatch carries it per stage so an hg process
holding it runs with exactly `PATH`, `HGRCPATH=/dev/null`, `HGRCSKIPREPO=1`, and
`HGPLAIN=+strictflags` and nothing else, on the direct, pipeline, staged, and auto-allowed
stripped-literal routes. That is also why extension-provided `glog` and `shelve` are not in the set:
the automatic environment loads no extension, so the command may not exist — `hg shelve --list` is
read-only at the Mercurial command level and is still prompt-gated for that reason alone. A command the user approved at a prompt
keeps its ordinary environment, because stripping the configuration the user asked for would be a
different decision than refusing to trust configuration the user never saw.

For what a stripped redirect leaves on the `sh -c` route, one further rule narrows the refusal: an
argument-sensitive command is read-only when its own validator passes **and every raw token of every
stage in the command is expansion-free**, because then the argument list the shell builds is provably
the list that was validated. `tokenExpansionFree` reads the raw spelling the canonical form preserved,
so `'$F'` and `\$F` are literal text while `$F` and `"$F"` expand; it fails closed on an unquoted `$`,
`*`, `?`, `[`, `{`, or `~`, an unterminated quote, and any byte outside the always-inert set. The rule
is expansion-freedom, not variable-freedom — with a file named `-i` in the directory,
`sed -n '1,5p' *.md` reaches `sed` as an in-place edit — and its scope is the whole command, because a
variable in any stage can be assigned a value that changes what a later stage sees. So
`sed -n 1,5p f 2>/dev/null` auto-allows, while `sed -n 1,5p $F 2>/dev/null` and
`sed -n 1,5p f 2>/dev/null && grep x *.go` stay mutating. The one recognized wrapper shape,
`sh -c '<simple compound>'`, shares that condition: `sh -c 'sed -n 1,5p f'` and `sh -c "ps aux"`
auto-allow, while `sh -c 'sed -n 1,5p $F'` and `sh -c 'sed -n 1,5p f && ls $F'` stay mutating — the
inner shell re-parses the whole body, so every stage in it must be inert, not only the
argument-checked one. Every other wrapper spelling — an extra positional argument (`sh -c 'x' extra`),
a nested wrapper, `bash -c`, a path-form `/bin/sh`, anything `SimpleCompoundStages` declines — stays
mutating. What triggers the condition is **argument-dependence, not a validator**. A policy whose
verdict reads argument text qualifies three ways: a validator (`find`, `sed`, `awk`, `top`), a
`readOnlySubcommands` set (`hg`, `git`), or a `denyFlags` list (`hg`, `git`, `sort`, `date`, `rg`,
`file`, `df`, `tail`). Those last two kinds
are the easy ones to miss — the scan sees the literal `$X` and passes it, then the shell expands
it into `--config=alias.log=!<cmd>` or `-o out`, which is the whole point of the deny list. So
`hg log $X 2>/dev/null`, `hg log $X 2>/dev/null | head`, `hg log $X && hg status`, and
`sort $X 2>/dev/null` are all mutating, single stage and compound alike (`commandPolicy.argDependent`).
Name-only allowlisted commands are untouched by the rule — an empty policy is never
argument-dependent — so `grep x $F 2>/dev/null`, `grep x *.md 2>/dev/null | head`, and
`grep a f 2>/dev/null | head -$N` classify exactly as before. That exemption is only as good as the
list it trusts, so every entry was audited against the three hazard classes — a flag
that writes a file, one that runs a program, one that retargets scope. Four failed and now carry deny
lists: `rg` (`--pre` and `--hostname-bin` run a named executable; `-z`/`--search-zip` spawns a
decompressor), `file` (`-C`/`--compile` writes the compiled magic database, `-z`/`-Z` shells out to
gzip/bzip2/lzip/lrzip/zstd), `df` (`--sync` flushes dirty buffers), and `tail` (`-f`/`-F`/`--follow`,
the excluded follow forms). The cost of that fix is paid by the ordinary forms too: those four are
argument-dependent now, so `rg needle *.md 2>/dev/null` and `file -b *.md 2>/dev/null` prompt, while
the redirect-free `rg needle *.md` still auto-allows on the direct route.

Two smaller lessons live in the same fix. A **bundled short flag** is part of the spelling:
`stageMatchesDenyFlag` matches short flags by prefix, so `rg -zn` was always denied but `rg -nz`,
`file -bC`, and `sort -uo out.txt f` were not. `commandPolicy.clusterShortFlags` opts a policy into
scanning the whole cluster, and it is opt-in rather than blanket because a cluster letter is not
always a flag — `date -Iseconds` carries date's denied `-s`. And **argv is not always the whole
input**: `rg` reads options from the file named by `RIPGREP_CONFIG_PATH`, where a `--pre=<helper>`
line runs a program for a command whose argv is spotless. No amount of argument inspection sees that,
so the control sits at execution — `internal/dispatch/shell.go` removes that one variable from the
environment of every process it launches, keeping every other inherited variable and every approved
stage assignment.

A wrapper carrying
no argument-checked stage (`sh -c "ls"`,
`sh -c 'hg log && hg status'`) keeps its prior mutating classification. `commandPolicies`
(`planshell.go`) is the whole admission policy, so the standing exclusions are the table's silence
rather than a separate list: a command that is not in it, or whose validator declines the exact
tokens it was given, is mutating. `planshell_test.go` is the executable record of both halves.

`bash` and `sh` are the one argument-sensitive entry that is also a **wrapper program**, and the only
reason they are admitted at all is Bash's no-exec mode: `-n` parses a script and runs none of it. The
accepted grammar is closed and exactly four spellings — `bash -n`, `bash -o noexec`,
`bash -O extglob -n` (either option order, since `-O extglob` only lets the parser read extended glob
patterns and is admitted **only** next to `-n`), and `sh -n` — each followed by nothing but plain
non-option script operands (`noExecShellTokens` in `planshell.go`). Anything else fails closed and
keeps today's posture: `bash --noexec` (which Bash does not accept as a no-exec option at all), `-c`,
interactive/login/startup options, another `-O` value, any unknown flag, a dash-leading, plus-leading,
or empty operand, and bare `bash`/`sh`. The plus-leading rule closes a real bypass: `+n` and
`+o noexec` — and grouped spellings such as `+xn` — cancel no-exec mode, so `bash -n +n f.sh` would
parse the script and then run it; a script actually named with a leading `+` is still checkable as
`bash -n ./+f.sh`. Because a wrapper is normally never a direct command, the exception is
also spelled out in normalization: `noExecShellStage` (`normalize_direct.go`) lifts a stage out of
`wrapperPrograms` only when the program word is the bare, unquoted, unescaped `bash` or `sh` and the
stage carries no leading env assignment, so `/bin/bash -n f.sh`, `"bash" -n f.sh`, and
`FOO=bar bash -n f.sh` all stay on the literal route. The same execution-fidelity rule as every other
argument-sensitive command then applies, and here it is the whole point: `stageIsShellProgram` forces a
shell stage mutating on the literal route, so `bash -n f.sh` and `sh -n f.sh; bash -n g.sh` auto-allow
in Build, Auto edits, and Plan, while `sh -c "bash -n f.sh"`, `bash -n f.sh > out`, and
`bash -n f.sh > /dev/null` do not — handing a shell invocation back to `sh -c` would let the outer
shell re-parse text no validator saw.

`bash` and `sh` have a **second** carve-out, and it is about routing, not classification. A *standalone* flagless
script invocation may take the direct route: `scriptInvocationStage`
(`normalize_direct.go`) accepts a bare, unquoted, unescaped `bash`/`sh` program word with no leading
env assignment and a first operand that is non-empty and begins with neither `-` nor `+`. That operand
is the script, so everything after it is the script's own argv and is not inspected — `bash foo.sh -n`
is accepted, and its `-n` is an argument to `foo.sh`. The point is the grant the user can then store:
`bash process-dir.sh u.txt` becomes the direct subject `["bash", "process-dir.sh", "u.txt"]` and can be
approved once as `bash process-dir.sh :*`, the way `./process-dir.sh :*` already could. The tokens are
kept verbatim — `bash foo.sh` is never rewritten to `foo.sh` — so a grant for one spelling never
matches the other.

Three things about that carve-out are worth holding on to. **It grants no read-only status:** the
`commandPolicies` validator is still `noExecShellTokens`, so `bash foo.sh` classifies mutating and
still prompts in Build and Auto edits and denies in Plan. **The plus-leading rejection is load-bearing:**
both shells parse `+`-leading invocation options and keep parsing afterwards, so `bash +O extglob -c
'<code>'` still reaches `-c`; it stays on the literal route, and because `grantMatches` requires equal
subject kinds, neither a direct `bash :*` nor a direct `bash +O :*` grant can ever authorize it. **It is
single-stage only:** `NormalizeDirectStage` takes a `StageContext` and admits the grammar only under
`StageSolo`; `SplitCommand` supplies `StageSolo` only for a one-stage command and `StageInCompound` for
every pipeline stage, and `SimpleCompoundStages` supplies `StageInCompound` to every stage it rechecks,
so `bash process-dir.sh u.txt | tail -n 25` stays one byte-exact literal subject and still runs as
`sh -c '<original pipeline>'` with the outer shell's expansion and streaming. Because a direct-routed
stage runs from verbatim argv instead of through `sh -c`, `bash script.sh *.txt` reaches the runner
unexpanded while a bare leading `~` still expands through `ExecForms` — the same behavior
`./script.sh *.txt` has always had on the direct route.

`command` is the second wrapper with a carve-out, and the only one codemeld answers **itself**.
`command -v magick` asks a pure question — where does `magick` resolve — but `command` is a shell
builtin: there is no executable to launch, so an ordinary direct stage would authorize a lookup and
then have nothing to run. Instead the lookup happens during normalization, next to the `exec.LookPath`
call `canonicalProgram` already makes: `commandLookupStage` (`normalize_direct.go`) accepts exactly
`command -v <name>` — three tokens, every one of them the bare, unquoted, unescaped spelling, no
leading env assignment — where `<name>` is a plain program name of letters, digits, `_`, `-`, `.`, and
`+` that does not start with `-` (`commandLookupTokens`, `planshell.go`), **and** `exec.LookPath`
resolves it. The resolved path rides along on `StageNormalization.LookupPath`, and
`builtinLookupResult` (`internal/dispatch/shell.go`) returns it plus a newline with exit 0 from both
`dispatchDirect` and `dispatchStaged` — no shell, no program, and no second lookup, so what dispatch
does is exactly what was authorized. The admitted namespace is therefore Go's, not the shell's: PATH
executables resolve, while an alias, a function, and a builtin such as `cd` are all **misses**. A miss
is not a denial — it simply fails to qualify for the carve-out, so the stage keeps `command`'s literal
route and prompts as it does today; separating "no such program" from "that's a builtin" would mean
running a shell, which is the one thing this design refuses to do. Everything else keeps today's
posture too: `command -V` and every `type` form are deliberately out of scope (their output is a
sentence whose wording differs across dash, bash, and zsh, and `type` gains no policy entry at all),
as are `command ls -la`, `command sh -c '…'`, a bare or multi-operand `-v`, a path or quoted operand,
and `PATH=/opt/bin command -v foo`. And the execution-fidelity rule applies here exactly as it does to
`bash -n`: `command -v magick` and `command -v magick && ls` auto-allow in Build, Auto edits, and
Plan, while `sh -c "command -v magick"` and `command -v magick > out` stay mutating.

`awk` needs the most careful validator in the table, because AWK is a programming language rather
than a filter: `system("…")`, `print | "cmd"`, and a gawk coprocess run programs, `getline` reads a
source nobody validated, `>` and `>>` write files, `ENVIRON` and `PROCINFO` expose the environment,
`ARGV` and `ARGC` change which files get read, and `-f`/`-v` replace or reprogram the script
outright. None of that can be judged from the program name, so `awk` is `argSensitive` with its own
validator (`awkStageReadOnly`, `planshell.go`) and is deliberately absent from the name-only set —
the exact-set tests (`TestReadOnlyExecutableSetUnchanged`, `TestVCSReadOnlySubcommandSetsAreCurated`)
fail if anyone adds it. The validator accepts only a field separator as an option (`-F sep` with a
non-empty separator, or `-F:` attached; `-f`, `-v`, `--`, and every other option reject), then one
inline program, then zero or more input operands — with no operand the program reads stdin, so
`ls -l | awk '{print $5}'` qualifies. The program passes through either of two paths. The original
range-print grammar (`awkRangePrintProgram`) still admits its one shape, so
`awk 'NR>=55 && NR<=70 {print NR ":" $0}' f` auto-allows as before. Everything else goes through a
small lexer (`awkReadOnlyProgram`, `awkprogram.go`) that walks the program token by token, skips
whitespace and `#` comments, and admits it unless it finds something that could write, run, or
reach past the operands. It rejects a `>` or `>=` anywhere inside a `print`/`printf` statement, even
a parenthesized comparison like `print (a > b)` that writes nothing: AWK allows an output
redirection in those statements, and the lexer does not try to tell a redirection from a
comparison, so it refuses both; `>>`; a `|` that is not part of `||`; `@` (gawk's `@load`/`@include` and
indirect calls by name); a backtick, a single `&`, a stray `\`, or any other byte that is not a
known AWK operator; and the words `getline`, `system`, `close`, `fflush`, `ENVIRON`, `PROCINFO`,
`ARGV`, `ARGC`, `SYMTAB`, and `FUNCTAB`. A `/` is the subtle one: AWK reads it as either the start
of a regex or a division, and a misread would let code hide inside what the lexer took for regex
text, so `/` starts a regex only where an operand is expected and divides only right after a value
(a variable, number, string, `]`, or a non-control `)`); anywhere else — after `$`, `++`, a regex,
an `if (…)` condition, or a word like `length` — it fails closed. Literals must be well formed: an
unterminated or newline-containing string or regex rejects, and so does a regex bracket expression
that holds a `/` or is left unclosed, because AWK implementations disagree on whether that `/` ends
the regex — `awk '/[/]/ { print }' f` prompts while `awk '/\// { print }' f` is the admitted way to
match a slash. An empty or comment-only program rejects. So `awk '{print $1}' f`,
`awk -F: '{print $1, $3}' f`, `awk '$3 > 100 { print $1 }' f`, and
`awk '{ s += $2 } END { print s/NR }' f` all auto-allow, while `awk '{ print > "out" }' f`,
`awk '{ print (a > b) }' f`, and `awk 'BEGIN { system("id") }' f` prompt. The operand checks did not
change: an operand containing `=` is rejected, because AWK reads `name=value` as a variable
assignment rather than an input file; so is a dash-leading or empty operand; and so is any operand
starting `/dev/` or `/inet`, because GNU AWK resolves `/dev/tcp/host/port`, `/dev/udp/host/port`,
and `/inet/tcp/0/host/port` to an outbound network connection rather than to a file on disk —
reading one is not a local read at all. The execution-fidelity rule applies as it does to `sed`:
`awk '{print $1}' f`, `awk '{print $1}' f | head`, and `awk '{print $1}' a; ls` auto-allow in Build,
Auto edits, and Plan because each stage executes as the exact argv the validator inspected, while a
form that really reaches `sh -c` needs the whole-command expansion-free proof above — so
`sh -c 'awk "{print NF}" f'` and `sh -c 'awk "NR>=1 && NR<=10 {print}" f'` auto-allow, while
`sh -c 'awk "{print $1}" f'` (a double-quoted program carrying an unescaped `$`), a leading
assignment, `bash -c`, a nested or trailing-operand wrapper, command substitution, and an unsafe
redirect all stay mutating.

## Watch for (Go idioms)

- **The tests are the spec.** Normalization and scope are pure functions, exhaustively
  table-tested. `scope_test.go`'s `TestIsDescendantOrEqual` table *is* the definition of "what
  counts as contained." When unsure how an edge case behaves, the test table answers it faster
  than re-reading prose.
- **Raw-bytes vs parsed value.** `isEnvAssignment` (`normalize_direct.go`) scans the token's
  **raw** bytes, not the unquoted value, so `F"OO"=bar` and `"FOO=bar"` can't masquerade as the
  valid name `FOO`. Same idea for the `:*` wildcard in `MatchesDirectSubject` — it's a wildcard
  only when its raw source bytes are exactly `:*`, never when quoted/escaped.
- **Identity excludes derived data.** `DedupKey` drops `ArgumentHash` (it's derived from the
  subject) and the turn-cache key drops `SubjectTokens` (derived from the subject). Both avoid
  fragmenting an identity on data that adds nothing.

## Quiz

Take it closed-book: [`quizzes/module-05.md`](quizzes/module-05.md). Grade against
[`quizzes/module-05-key.md`](quizzes/module-05-key.md) — the key cites file and function/symbol.

## Hands-on (open-book)

**A. Predict, then verify.** Will `GIT_PAGER=cat git log` re-prompt if `git log` was already
approved as a folder grant in this directory? Write your prediction first. Then find the code
that decides it — the env-strip loop in `NormalizeDirectStage` and `isEnvAssignment`
(`normalize_direct.go`) — and the test `TestNormalizeDirectStage_Assignments`
(`normalize_direct_test.go`), which shows the tokens reduce to `git log` while the assignment
is preserved on `Assignments`. Did your prediction match? (Bonus: find the test proving
`env FOO=bar git log` instead routes to *literal* matching — why is that the safe choice?)

**B. Write a test.** Add a test asserting a **folder** grant in `/a/foo` does **not** match a
request in the sibling `/a/bar`. A clean shape that exercises the matcher directly:

```go
func TestMatch_FolderGrantDoesNotMatchSibling(t *testing.T) {
    grant := PermissionEntry{Kind: "tool", Subject: "vcs_status", PathScope: "/a/foo", GrantKind: "folder"}
    req := MatchRequest{Kind: "tool", Subject: "vcs_status", PathScope: "/a/bar"}
    if Match(req, []PermissionEntry{grant}).Matched {
        t.Fatal("folder grant in /a/foo must not match request in sibling /a/bar")
    }
}
```

Put it in `internal/permissions/matcher_test.go`, run `go test ./internal/permissions`, and find
your test's result in the output. It should pass against current code — you're proving the invariant and
learning the matcher API, not chasing a bug. Cross-check: `scope_test.go`'s `TestIsDescendantOrEqual`
already encodes the same rule (the "sibling prefix trap" case). *(Revert your addition afterward,
or keep it if you think it adds value and want to propose it.)*

**C. Trace canonical-subject normalization.** Find where a raw command is reduced to its canonical
permission subject — start at `NormalizeDirectStage`, then follow `canonicalProgram`, `isEnvAssignment`,
and `DerivePathScope`, and see how the normalized subject reaches `Match`. Record the
`file:function` for each in [`progress.md`](progress.md).

## Done when

- You answered every quiz question correctly **without** the key.
- Your hands-on A prediction matched what the code actually does.
- Your hands-on B test passed, and you can explain *why* it passes by pointing at
  `IsDescendantOrEqual`.
- You can say which requests never reach `Match` at all, and which of the three `denied_by` values
  let the turn continue.
