# Answer key — Module 13: Read-only navigation & inspection tools

Citations are **file + function/symbol name**, not line numbers — lines drift as the code
changes, but a function name stays findable. Search (or your editor's "go to symbol") lands you
on the exact code.

---

**1. The six tools.**
- `read` ≈ `cat` (`ReadTool`, `read.go`), `grep` ≈ `grep`/`rg` (`GrepTool`, `grep.go`),
  `glob` ≈ filename glob (`GlobTool`, `glob.go`), `list` ≈ `ls` (`ListTool`, `list.go`),
  `tree` ≈ `tree` (`TreeTool`, `tree.go`), `file_count` ≈ `ls | wc -l` / `find … | wc -l`
  (`FileCountTool`, `filecount.go`).
- `read` requires `path`; `grep` and `glob` require `pattern` (not `path`). `list`, `tree`, and
  `file_count` take no required argument — an omitted `path` defaults to the project root (the
  optional-path mode of `ResolveReadTarget`, `ReadTargetOptions.RequirePath == false` in their
  `ResolveTarget`).

**2. Why no prompt (and the one exception).**
`Advertise()` returns `tools.Metadata{ReadOnly: true}` (each tool's `Advertise`, e.g.
`ReadTool.Advertise` in `read.go`; the field is on `tools.Metadata` in `registry.go`). For an
**in-project** target that read-only classification auto-allows the request in **all
three modes** — Plan, Build, Auto edits — evaluated before grant match and the
turn cache, recorded as `permission_matched{outcome_source: "mode_auto", outcome: "once"}` with
**no grant created**. `ReadOnly: true` also makes the tool advertised in Plan.

**The external-read exception:** an **explicit out-of-project** read target (an absolute or `~` path outside
the root) does **not** auto-allow, and is **no longer rejected** before authorization either — it
**prompts**. Dispatch sets `ModeContext.ExternalRead` and `modePosture` (`orchestrate.go`) falls
straight through for it, skipping both the read-only auto-allow and Plan's mutating-deny, so it
reaches a normal permission prompt (once/session/folder/global) in Build, Auto edits, *and* Plan.
Only an *implicit* escape (`..`/symlink out, directory-symlink root, `~user`, malformed path)
still fails closed before any read.

**3. `find` / `tree` allowlist.**
The *executable-name* read-only shell allowlist (`planReadOnlyExecutables`) deliberately keeps
`find` and `tree` off it because their mutating flags (`find -delete`/`-exec`/`-fprintf`,
`tree -o`) cannot be ruled out by an executable-name-only classification. The structured,
project-root-scoped `tree` and `glob`/`list` tools cover that navigation instead and need no
allowlist entry (the tools register in `toolRegistryFactory.realize`, `tooldispatch.go`).
`find` additionally has an **argument-sensitive** carve-out `tree` does not: `stageTokensReadOnly`
routes a direct `find` stage to `findStageReadOnly` (`planshell.go`), a fail-closed left-to-right
parser that admits it read-only only when every token is a safe read-only listing form — one or
more relative start paths (no absolute, `..`, dash-leading, or `--`) then only supported read-only
predicates (`-type`, `-name`, `-maxdepth`, `-mtime`, `-size`, `-empty`, `-print`, …). Any mutating
action, unsupported operator, missing/invalid value, or path escape falls closed to mutating, so
`find` stays out of `planReadOnlyExecutables` — it is admitted by parsing its arguments, never by
name.

**4. Confinement.**
`ResolveReadTarget` (`readresolve.go`) is the shared boundary; it runs before any read for all
six tools. A relative `path` resolves against the **project root**, not the process cwd, so the
tools behave identically however `codemeld` was launched. Containment is checked with
`permissions.IsDescendantOrEqual` against the normalized root. An **implicit** escape — outside
the root *through* `..` normalization or *through* a symlink — fails closed with a `*TargetError`
before a byte is read. An **explicit** absolute or `~` target naming a path outside the root is
the exception: it is resolved to an external scope and marked promptable
(`ExternalReadScope`) rather than rejected, so it reaches the permission prompt instead of a
silent failure.

**5. Symlink policy** (`ResolveReadTarget`/`ResolveReadFile` in `readresolve.go`):
- (a) Recursive tool + directory-symlink `path` → **rejected fail-closed** (the
  `RejectDirectorySymlink` branch refuses it before collapsing to the real directory; the tool
  also re-`Lstat`s the root before walking).
- (b) `list` reports the symlink entry as type **`symlink`** and never follows it
  (`classifyDirEntry`/`ClassifyEntry` classify by the entry's own type).
- (c) `read` follows the link **only** when its resolved target is a regular file still inside
  the root (`ResolveReadFile`); a directory, special file, or escaping symlink is an in-band
  rejection.

**6. The walker** (`Walk`/`WalkOptions`, `walk.go`):
Any three of: skips dot-prefixed entries unless `IncludeHidden`; never descends a
directory symlink — reports it as `EntrySymlink` (`classifyDirEntry`); emits in
deterministic pre-order (directories before descendants, siblings ascending by name); consults
the ordered `Ignore` matchers before emit/descent unless `IncludeIgnored`. `MaxDepth: 1` =
immediate children only (the `list` tool); `MaxDepth: 0` = unlimited depth.

**7. Bound the result, not the walk.**
`grep` must search **every** eligible file to bound *matches*, and `glob` must consider every
entry to find matches anywhere in the tree; capping the *walk* (`Walk` with a non-zero `Limit`)
would stop emitting entries after the cap and **silently drop matches in files/paths deeper than
the cap**. So they walk unbounded (`Limit: 0`) and bound matches/paths afterward — see the
comments in `GrepTool.grep` and `GlobTool.glob`.

**8. Ignore story.**
codemeld chose a single codemeld-owned `codemeldignore` format instead of parsing the two native
formats — `.gitignore` and `.hgignore` — because that meant carrying two divergent external
ignore dialects: gitignore's nested/negation glob semantics **and** Mercurial's regex-default
`.hgignore` with `syntax:` directives, whose Python/Perl regexp dialect does not map onto Go's
RE2 (no backreferences/lookaround). Neither native file is parsed in phase 1. (The matcher lives
in `codemeldignore.go`.)

**9. codemeldignore semantics.**
`<project-root>/.codemeld/codemeldignore` and `~/.codemeld/global/codemeldignore`
(`ProjectCodemeldignorePath` / `GlobalCodemeldignorePath`). Their patterns are a **union**
(`LoadCodemeldignoreMatcher`), order-independent because there is no negation. A slash-less
pattern like `vendor` is **root-only**; to match a name at any depth you write an explicit
leading `**/` (`**/vendor`). Matching is literal `doublestar.Match` against the
project-root-relative slash-path (`CodemeldignoreMatcher.ShouldSkip`).

**10. The two flags.**
`include_hidden` disables the dot-entry (hidden) filter; `include_ignored` disables the
`codemeldignore` matcher (the VCS-ignore filter). They are **independent** switches, not the same
one — set/read separately in each tool's `*Tool.<tool>` via `optionalBoolArg`, and passed as
`WalkOptions.IncludeHidden` / `IncludeIgnored`.

**11. Truncation indicator.**
It lives in **stderr**, as the single first line, prefixed with `MetadataPrefix`
(`codemeld-tool-meta: `) carrying `OutputMeta` as compact JSON (`BoundedResult`, `limits.go`).
Being in stderr keeps `read`'s verbatim stdout uncorrupted; and because the global byte
cap (`events.TruncateToolOutput`) preserves a **prefix** of each stream, the first-line indicator
survives even when stdout is trimmed. `byte_cap` takes precedence over a `limit` reason.

**12. Dispatch invariant.**
The registry is a **flat `map[string]entry`** keyed by `Name()` (`Registry` in `registry.go`),
and `Lookup` is **exact-name only** — no regex or shell-equivalence fallback. Each of the six
tools satisfies it by returning a fixed built-in `Name()`
(`read`/`grep`/`glob`/`list`/`tree`/`file_count`) with no template namespace, registered under
`tools.BuiltinSource` in `toolRegistryFactory.realize`. `ValidatePhase1ReadArgs`
(`phase1readargs.go`) is keyed by those same six exact names.

**13. Concurrency boundary.**
Each call must (1) carry one of the six **exact** registered names, (2) decode its JSON arguments,
(3) pass `ValidatePhase1ReadArgs`, and (4) resolve through `dispatch.PrepareTool` to a non-empty
scope that is **not** an external read — i.e. positively inside the project. A call that fails any
of those keeps the synthetic `production-tool-dispatch` conflict target and becomes a **model-order
barrier**: it waits for the contiguous run of eligible reads before it, and the next run waits for
it. It splits the response rather than serializing it, so `read A, grep B, edit C, read D, glob E`
runs `{A, B}`, then `C`, then `{D, E}`. `agent.max_concurrency` is the only cap — 1 is sequential —
and there is no second limit or worker pool. Each overlapped read writes the
pair `structured_read_start` (UUIDv7 invocation id, exact tool name, resolved scope, configured cap)
before the invocation and one `structured_read_end` (terminal outcome + monotonic duration) after.
A start that cannot be appended means the read never runs; an end append failure is returned as an
internal dispatch error after the start already exists.
An excluded call leaves neither half of that pair; it leaves one best-effort
`structured_read_refused` planning record with the exact tool name and the refusal reason.

**14. Multiple choice. — (b) rejected in-band with a numeric-validation error.**
`ValidateNumericArgs` (`limits.go`) enforces `offset >= 1` and returns a `*TargetError`
("offset must be >= 1, got 0") with **no silent clamp**; dispatch surfaces it in-band
so the model can correct itself, without aborting the turn.
