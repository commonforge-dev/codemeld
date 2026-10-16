# Gated changes

A few changes in this repo are **blocked by a check** until you take one specific extra step.
The check fails on purpose, so the change can't slip in unnoticed and someone has to look at
it on the way through. "Gated" just means there's a gate you have to open on purpose.

If `mise run check` fails with one of the messages below, you've hit one of these gates. Don't
work around it by deleting the test or blindly accepting the new output — find the matching
gate below and do the step it asks for.

Each gate lists the files involved, what makes it fail, the step to fix it, and why it's there.
§5 covers one more set: the open-source shipping-set scans plus the Go vulnerability scan, all
run by `mise run release-check`. Of those, the reference check also runs in `check` /
`check-race`; the secret scan and `govulncheck` run **only at release time**.

## 1. System-prompt snapshots (rewritten for you with an env var)

These tests save a copy of the system message codemeld assembles for a **normal chat turn**, and
fail if the real message stops matching that saved copy. (A "snapshot" is a saved copy of expected
output; a "fixture" is the file that copy lives in.)

**Files**: `internal/agentinstr/snapshot_test.go`, plus the saved copies committed in
`internal/agentinstr/testdata/snapshots/` (`plan.txt`, `build.txt`, `auto_edits.txt`,
`base_env_only.txt`, `with_agents.txt`, `special_latex.txt`) — that directory is the
authoritative set.

**What makes it fail**: any wording change to a base prompt (`internal/agentinstr/baseprompts/shared.md`,
`plan.md`, `build.md`, `auto_edits.md`), to the extra instructions some models get
(`internal/agentinstr/baseprompts/special-instructions.md`), or to the environment block. Each
saved copy is the full message sent in one mode, and `shared.md` is copied word-for-word into
every one — so editing `shared.md` changes all of them. Only `special_latex.txt` covers the extra
instructions, so an edit there shows up in the saved copies only for the one model that copy pins.
`TestAssembledSystemMessage_GoldenSnapshots` then fails because the real output no longer matches
the saved copy.

Two of the saved copies, `base_env_only.txt` and `with_agents.txt`, also pin how an empty and a
populated loaded `AGENTS.md` are assembled into the message — so a change to that assembly fires the
gate too, even though the `AGENTS.md` wording itself belongs to the project, not the product.

**What it does not cover**: this gate watches exactly two product-authored sources — the five
embedded Markdown files and the generated environment block — because those are the normal-turn
assembly text. The title and compaction instructions are product-authored, editable instruction text
as well; they are simply inline Go in separate requests. Their focused tests, and the actual
advertised-tool coverage, are separate from this gate:

| Source | Where it lives | Its own check |
|---|---|---|
| Title instruction | `titleSystemPrompt` in `internal/turn/titlegen.go` | `TestGenerateTitle_RequestShape` (`internal/turn/titlegen_test.go`) |
| Compaction instruction | `compactionSummaryInstruction` in `internal/turn/request.go` | `TestBuildCompactionSummaryRequest_ExactShape` (`internal/turn/request_test.go`) |
| Compaction-summary wrapper | `compactionContextMessage` in `internal/turn/request.go` | `TestBuildRequest_ProjectsCompactionSummaryAfterInstructions` (same file) |
| Advertised tool descriptions | each tool's `Advertise()` metadata in its own package (`internal/filetools`, `internal/vcs/tool.go`, `internal/bootstrap/tooldispatch_web.go`), plus `BashToolDefinition` and `SuggestFollowupToolDefinition` in `internal/provider/tooldefs.go` | `internal/provider/tooldefs_test.go` pins the product definitions; registry metadata coverage varies by tool, with no shared exact-description test |

For the title, compaction, or product tool definitions, run the named package tests. For registry
metadata, review the description with its package tests; `mise run snapshot-update` has nothing to
say about any of them.

**What to do**:

```sh
mise run snapshot-update   # rewrites the saved copies, then fails on purpose
mise run check             # assert against the new copies (no variable set): now it passes
```

Then look at what changed (`hg diff internal/agentinstr/testdata/snapshots/`) and confirm the
only difference is the one you meant to make. Commit the updated copies together with the
prompt change.

This is the only gate that rewrites its files for you, and it does so in two steps on purpose:
with the variable set, the test writes the new copies **and then fails anyway**. That
deliberate failure is the whole point — it stops the files from quietly updating themselves in
CI, so a change to the always-running system prompt is always something a person chose and
reviewed. (The saved copies use a `<goos>` placeholder in place of the operating-system name,
so they read the same on every machine.)

**Why it's gated**: these instructions go to the model on every normal chat turn. A wording change
here that nobody reviewed is a silent change to how the whole product behaves.

## 2. First-run setup snapshots (edited by hand)

Same idea as gate 1 — saved copies of expected output — except you update these yourself;
there's no variable that rewrites them.

**Files**: `internal/bootstrap/firstrun_snapshot_test.go` and
`internal/bootstrap/firstrun_settings_test.go`, which check the saved files
`internal/bootstrap/testdata/snapshots/first_run_message.txt` and `first_run_settings.yaml`,
plus the expected-text constants in the tests (for example `expectedProviderBlock`).

**What makes it fail**: a change to the message printed on first run, or to the `settings.yaml`
file codemeld writes for a brand-new user. The test compares the real output to the saved copy
and fails with a printed "expected vs. got" difference.

**What to do**: edit the saved file (`first_run_message.txt` / `first_run_settings.yaml`) or the
expected-text constant in the test so it matches the new output — but only after confirming the
change is intended. The test comments are clear: update these only when the first-run message or
starter `settings.yaml` is deliberately changed, never just to make a surprise change pass.

**Why it's gated**: this is exactly what a brand-new user sees on first run, plus the starter
`settings.yaml`. Changing it by accident changes the new-user experience with nobody deciding to.

## 3. Unused-code allowlist (deadcode)

**Files**: `.deadcode-allow` and `scripts/deadcode-check.sh` (run by `mise run deadcode-check`,
part of `mise run check` and `check-race`). Full guide: `docs/deadcode-process.md`.

**What makes it fail**: the `deadcode` tool finds a function that nothing reachable from
`main()` ever calls (dead code), and that function isn't listed in `.deadcode-allow`. The check
prints `deadcode-check: unreachable, non-allowlisted function(s):` followed by the `file Name`.

**What to do** — pick one, on purpose:
- **hook it up** so real code calls it (best), or
- **delete** it, or
- if it's a helper only the tests use, add a `file Name` line to `.deadcode-allow` **and** put a
  `// intentional: test-only seam (no production caller by design).` comment on it. Keep the list
  short — a growing list is a warning sign, not a convenience.

See `docs/deadcode-process.md` for how to sort findings and turn the real ones into
tracked cleanup work.

**Why it's gated**: it keeps dead code from piling up, while still letting through the rare
function only tests need — as long as it's on a list you can review.

## 4. Leftover-placeholder markers (wiring-stub)

**Files**: `// WIRING-STUB(owner: <owner-id>)` comments in `.go` files, checked by
`mise run wiring-stub-check` as part of `mise run check` and `check-race`. The checker
recognizes a set of open follow-up owner IDs and fails any marker whose owner is not among them.
This real check runs only in the development tree, where a development-only mise overlay that
does not ship defines it. In the public tree `wiring-stub-check` is an intentionally inactive step
that does nothing, so this gate never fires there.

A `WIRING-STUB` comment marks a placeholder that doesn't do its real job yet, and names the
follow-up owner meant to finish it.

**What makes it fail**: a marker names an owner the checker no longer recognizes as open —
usually because the follow-up finished but the placeholder got left behind. The check fails with
a `wiring-stub-check:` message naming the leftover marker's spot and the owner id it points at.

**What to do**: point the marker at an owner that's still open and will finish the work, or remove
the marker if the placeholder is now done and no longer a placeholder. (Don't close out a
follow-up owner while it still has an unresolved marker.)

**Why it's gated**: a placeholder that does nothing yet shouldn't outlive the follow-up that
promised to finish it and quietly get forgotten.

## 5. Shipping-set scans, vet, and the Go vulnerability scan

`mise run release-check` runs four checks in order and stops at the first failure:

1. `mise run oss-reference-check` — banned internal references inside a shipping file.
2. `mise run oss-secret-scan` — secrets or private-machine paths inside a shipping file.
3. `go vet ./...` — the standard vet analyzers, run standalone so the release gate does not
   depend on the lint task.
4. `govulncheck ./...` — the Go vulnerability scanner over the module's reachable code.

The reference check does not wait for release: `mise run check` and `mise run check-race` run it
too, as their last step. The secret scan and `govulncheck` run only in `release-check`.

The first two scan the exact set of files that ship to the public repository. They guard the
public surface against two things a path-based ignore list cannot catch: a banned reference, or
a secret, sitting *inside* a shipping file (an ignore list excludes whole paths, never file
contents). That file list is built by `find` over the shipping roots, not from the VCS
manifest, so an **untracked** scratch file under one of them is scanned like a committed one —
and now fails `check` and `check-race`, not just the release gate.

**Files**: `scripts/oss-shipping-files.sh` (the single shared list of shipping files, so both
scans share one boundary), `scripts/oss-reference-check.sh` with its `.oss-reference-allow`
allowlist, and `scripts/oss-secret-scan.sh`. They are wired as `mise run oss-reference-check`
(also run by `mise run check` and `mise run check-race`), `mise run oss-secret-scan`, and the
combined `mise run release-check`; `mise run oss-gate-selftest` exercises both scanners against
fixtures. `govulncheck` is pinned at `v1.6.0` through mise's Go backend, so `mise install`
provides it.

**What makes the reference check fail**: a shipping file (code or public doc) contains one of
the token patterns it matches, in three categories:

1. An internal requirement-number tag: `req`, `req-`, or `requirement` followed by a number, or
   the bare word for the internal product requirements document.
2. The name of an internal-only directory or file that does not ship.
3. A task or ADR id: a whole token made of `adr-` and three digits, or of one of the letters
   `g f i m t` and three or four digits, in any letter case (an uppercase `ADR-` or task letter
   counts too).

Public code and docs must stand on their own for a reader who does not have the internal
documents. The check prints `oss-reference-check:` followed by each offending file, line, and
matched text.

Category 3 replaces the earlier rule that a bare `adr-NNN` citation in prose passes this gate.
An ADR id points at a decision record that does not ship, so it dangles for a public reader in
the same way an internal directory name does. In `.go` files the check reads only comment text
(`//` and `/* ... */` comments, including block comments that span lines); ids inside Go
strings, rune literals, raw strings, and identifiers are not checked. The comment text is
found by a small lexer in the script that tracks strings and comments, so a `//` inside a string
is not taken for a comment, and a string before a trailing comment is skipped while the comment
itself is still checked. Every other shipping file is checked in full.

**What to do**: remove the reference and state the underlying reason in plain words instead. Two
kinds of match can instead be allowed by a `path<TAB>match` line in `.oss-reference-allow`:

- Category 1: one of the requirement-named Go identifiers or test diagnostics that were
  deliberately kept (renaming them would change runtime behavior).
- Category 3: an audited false positive, an id-shaped token that is not a task or ADR id — a
  CPU architecture name such as the 32-bit x86 one in a doc, or a fragment of a hash. Add one
  entry per file where it legitimately occurs; do not loosen the pattern.

The path is matched exactly and case-sensitively; the token is matched case-insensitively, so
one entry covers every capitalization of that token in that file. An entry for a public doc
works like any other: an exact doc path permits its token in that doc. Test files
(`*_test.go`) are not allowed by filename; intentional test diagnostics need entries too. The
allowance stays file- and token-scoped — it never permits the same text in another file or in
a file whose path differs only in letter case. Category 2 cannot be allowed at all: an entry
for a withheld-path match is ignored.

**What makes the secret scan fail**: a shipping file contains a credential-shaped value (a
provider key/token prefix, or a private-key block), a real session-dump path under
`~/.codemeld/sessions/`, or a private developer-machine absolute path (your home directory, or
the project-storage root outside a test fixture). Documented names such as `OPENAI_API_KEY` and
user-facing config paths such as `~/.codemeld/global/settings.yaml` are intentionally **not**
flagged. The check prints `oss-secret-scan:` with each finding's category and location.

**What to do**: remove the secret or private value. Machine-local configuration belongs in the
hgignored `mise.local.toml` (mise merges it automatically) or the withheld apparatus, never in a
shipping file.

**What makes `go vet` fail**: one of the standard vet analyzers reports a problem — a bad
`Printf` format, an unused result, a suspicious struct tag. Fix the reported line; `mise run
lint` runs the same analyzers, so this rarely fires on its own.

**What makes `govulncheck` fail**: it reports a known vulnerability that your code can actually
reach, or it cannot consult the vulnerability database. It queries `https://vuln.go.dev` by
default, so this step needs outbound network access; run the release gate from a machine that
has it.

**What to do about a vulnerability**: upgrade the affected dependency to the fixed version
`govulncheck` names (`go get <module>@<version> && go mod tidy`) and re-run the gate. If the
finding is in the Go standard library, move to the patched Go release. Do not skip the scan to
get a release out — the report lists the call path that reaches the vulnerable code, so a
finding here means the shipped binary is affected.

**Why it's gated, and what runs where**: internal tasks cite requirement numbers by convention,
so without a mechanical backstop the public surface drifts dirty again within days of any
one-time cleanup. The reference check was once grouped with the other three, on the same
reasoning — wiring a dirty scan into `check` would have made ordinary development fail until
unrelated cleanup was done. That reason expired once the shipping set was clean: the check is a
local grep with no network access, it costs a second, and a banned reference is cheapest to fix
in the edit that introduced it. So it runs in `check` and `check-race`. The one real cost of that
move is the `find`-built file list above: an untracked scratch file left under a shipping root
now fails the everyday gates. The secret scan stays release-only — a private path or credential
only has to be absent when the project ships — and `govulncheck` stays release-only because it
needs a network round-trip, which an everyday gate must not depend on.

## A related habit: helpers only tests use

A few functions listed in `.deadcode-allow` — for example `SetSyncFileForTest` and
`SetSyncDirForTest` in `internal/fsutil/atomic.go` — exist only for tests to call; no real
code path reaches them, by design. Each one has an
inline `// intentional: test-only seam` comment next to its allowlist line. This isn't a
separate gate; it's how gate 3 records a deliberate exception. If you move or rename one, keep
its comment and its `.deadcode-allow` line in step.
