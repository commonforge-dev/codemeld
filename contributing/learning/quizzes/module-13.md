# Quiz — Module 13: Read-only navigation & inspection tools

Closed-book. Write your answers before opening `module-13-key.md`. The goal is to find your
gaps, not to score — anything you can't answer from memory is what to re-read.

---

**1. The six tools.** Name the six read-only tools and the shell command each is the
structured equivalent of. Which two require an argument other than `path`, and which ones default
their `path` to the project root?

**2. Why no prompt (and the one exception).** What single piece of advertising metadata makes an
**in-project** read auto-allow without prompting? In which modes does that auto-allow apply, what
permission event is recorded (with its `outcome_source`), and is a grant created? Then: for an
**explicit out-of-project** read target — does it auto-allow, prompt, or fail
closed, and which dispatch/mode signal carries it?

**3. `find` / `tree` allowlist.** Why do `find` and `tree` (the shell binaries) deliberately get
**no** entry on the *executable-name* read-only shell allowlist (`planReadOnlyExecutables`), and
what covers that navigation instead? `find` still gets a narrower read-only path that `tree` does
not — what is it, where does it live, and how does it stay safe without an allowlist entry?

**4. Confinement.** Which shared function resolves and contains every tool's `path` before any
read, and what does a relative `path` resolve against — the process cwd or the project root? Why
that choice? Which kind of out-of-root target is *rejected* fail-closed, and which kind
is instead *resolved and made promptable*?

**5. Symlink policy.** For each of (a) a recursive tool given a directory-symlink `path`, (b) a
symlink *entry* encountered by `list`, and (c) `read` pointed at a symlink — state what happens.

**6. The walker.** Name three things the shared `Walk` does for the recursive tools by default.
What does `MaxDepth` of `1` mean, and what does `0` mean?

**7. Bound the result, not the walk.** `grep` and `glob` call the walker with `Limit: 0`
(unbounded) and bound their output afterward. Why is bounding the *walk* instead a correctness
bug?

**8. Ignore story.** Why does codemeld use its own `codemeldignore` file instead of parsing
`.gitignore` and `.hgignore`? Name the two native ignore formats that decision sets aside, and the
specific dialect feature of each that made parsing it costly.

**9. codemeldignore semantics.** Where do the two `codemeldignore` files live, how are their
patterns combined, and what does a slash-less pattern like `vendor` match — root-only, or at any
depth? How do you express "match this name at any depth"?

**10. The two flags.** What do `include_hidden` and `include_ignored` each disable? Are they the
same switch or independent?

**11. Truncation indicator.** Where in the result does the truncation indicator live (stdout or
stderr, and where in that stream), and why does that placement let it survive the
`max_tool_output_bytes` byte cap without corrupting `read`'s output?

**12. Dispatch invariant.** The tool registry is what kind of data structure, and is `Lookup`
exact-name or pattern-based? How do these six tools satisfy that invariant?

**13. Concurrency boundary.** These six names are also the only calls production runs concurrently.
State the four conditions a call must meet to qualify, what a call that fails any of them does to
the calls before and after it, and which single setting caps the overlap. Then: which two records
does each overlapped read leave in the session, what happens if either of them cannot be appended,
and what does an excluded call leave instead?

**14. Multiple choice.** A `read` call with `offset: 0` is:
- (a) silently treated as `offset: 1`
- (b) rejected in-band with a numeric-validation error
- (c) returns the whole file
- (d) an internal error that aborts the turn
