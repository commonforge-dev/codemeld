# Module 4 — Config: load & compose

_Snapshot as of 2026-10-09; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-10-09_

> Configuration determines behavior. This module covers how the three settings layers — global,
> project, and local — are loaded, how they merge, the session-lifetime read view, and how codemeld
> writes settings back safely.

## Goal

After this module you can:

- Explain the three settings layers — global, project, local — and how each is loaded and
  validated, including what the project approval gate withholds.
- State the compose precedence rules — including the `permissions` and `blocked_paths`
  concatenation, the `permissions` dedup, and the empty-list rule.
- Say what the config `Cache` is, why its snapshot reads never touch disk, and why the favorite
  toggle is the one path that reconciles from the writer's disk state.
- List the global-only keys and explain the sidecar-lock write chokepoint.

## Why it matters

Almost every other subsystem reads its settings through the composed config and the `Cache`. The
merge and persist rules are subtle, and several "why is it built this way?" answers live here.

## Read (in order)

1. `internal/config/load.go` — `LoadYAMLBytes`, `ValidateGlobalSettingsBytes`,
   `ValidateProjectSettingsBytes`, `ValidateLocalSettingsBytes`, `FormatLoadError`,
   `WarnIfBroaderThan0600`. A launch calls them from `internal/bootstrap/orchestrate.go`
   (`defaultLoadGlobalSettings`, `readAdmittedProjectSettingsLayer`,
   `readAdmittedLocalSettingsLayer`).
   `internal/config/local.go` — `LocalSettingsPath`, `PersistLocal`, and the local layer's key
   allow-list.
   `internal/bootstrap/trust.go` + `internal/trust/trust.go` — `gateTrust`, `Lookup`, `Record`,
   `StorePath`: the project approval gate.
2. `internal/config/schema.go` — `Validate` (embedded JSON Schema).
3. `internal/config/discovery.go` — `LocateProjectRoot`.
4. `internal/config/compose.go` — `Compose`.
5. `internal/config/cache.go` — `Cache`, `NewCache`.
6. `internal/config/globalonly.go` — `EnforceGlobalOnly`.
7. `internal/config/persist.go` + `internal/config/rewrite.go` — `Persist`, `RewriteKey`. The
   persist path's doc comments explain why the lock is on a sidecar.

## Mental model

### Three layers

- **Global:** `~/.codemeld/global/settings.yaml`. At launch `defaultLoadGlobalSettings` first calls
  `WarnIfBroaderThan0600` (advisory warning if the file holding plaintext credentials — provider API
  keys and ChatGPT session tokens — is more permissive than `0600`), then reads the file and passes
  the bytes to `ValidateGlobalSettingsBytes`.
- **Project (shared):** `.codemeld/settings.yaml` (also the discovery marker), validated by
  `ValidateProjectSettingsBytes`, which ends with `EnforceGlobalOnly`. This is the file a team
  authors, reviews, and commits. codemeld writes it only through two picker actions — see
  "Persist" below.
- **Local:** `.codemeld/settings.local.yaml`, in the same folder. Its path is derived from the
  project root discovery already settled (`LocalSettingsPath`); it is never a discovery marker of
  its own. It receives what codemeld writes for one user on one machine, and
  `ValidateLocalSettingsBytes` accepts only three top-level keys: `model` with the single subkey
  `active`, `permissions` whose entries have `grant_kind` `folder` or `project`, and
  `blocked_paths`. Every other top-level key is rejected with a message pointing at the shared
  `.codemeld/settings.yaml` (a global-only key keeps its own pointer at the global file), so is any
  `model` subkey other than `active`, and so is an entry with `grant_kind: global`, which belongs in
  the global file.

Both project-scope files are read only when the project root is approved — see "An unapproved
project contributes nothing" below.

`settings.local.yaml` and its `settings.local.yaml.lock` sidecar are this machine's own state, not
team configuration: add both to the repository's root ignore file (`.gitignore`, `.hgignore`, …).
codemeld never reads or edits a version-control ignore file itself. When a run's write creates the
local file, it
prints one notice naming both paths and asking you to add them (`RenderLocalSettingsIgnoreNotice` in
`internal/tui/notice.go`); that notice is the whole mechanism.

`blocked_paths` can come from all three files. The global file is where `/blocked` adds a
recommended entry; the shared file carries entries the team wrote; local entries are written by
hand. `/blocked` can remove an entry from the global or the local file, but adding stays
global-only (`removeBlockedEntry` and `addRecommendedEntry` in `internal/bootstrap/blockeddeps.go`).

All three validators start with `LoadYAMLBytes`, which runs `Validate` (`schema.go`): it compiles an
embedded JSON Schema once and reports the dotted offending key on failure. `LoadYAMLBytes`
deliberately decodes into `any` (not `map[string]any`) so a non-map root reaches *schema
validation* instead of being misreported as a parse error.

### When a layer fails to load

The loaders return a `LoadFailure` category next to the error: `UnreadableFile`, `YAMLParseError`,
or `SchemaValidationError` (`LoadOK` on success). These constants are an internal classification —
code branches on them, but their string values (`unreadable_file`, …) never appear in the load
failure message.

What a user sees is built by `FormatLoadError(path, category, err, consequence)`: a first line
naming the file, the kind of failure, and its consequence, then a `what happened:` line and a
`to fix:` line. A duplicate key in a project settings file at launch looks like this:

```
codemeld: <project>/.codemeld/settings.yaml: is not valid YAML; codemeld did not start.
  what happened: the key "default" is set twice in the same block, at line 2 and again at line 3
  to fix: delete one of the two "default" lines, either line 2 or line 3
```

- The kind of failure is one of three phrases: `could not be read`, `is not valid YAML`, or
  `does not match the settings schema`. For a schema failure, `what happened:` carries the dotted
  key the validator named.
- A duplicate key is the one failure with a tailored fix: it names both lines and, inside a list
  entry, the entry's `subject` or `name`. Every other failure gets a general fix for its kind.
- The consequence is passed in rather than derived from the category, because the same failure
  means different things to different callers: a launch passes `LaunchAborted` ("codemeld did not
  start"), while `codemeld config check` says "codemeld would not start with this file in place".

To predict the output, look for the phrase and the `what happened:` line — never for a category
token.

### An unapproved project contributes nothing

A launch asks the approval gate about the project root before composing (`runFreshCore` in
`internal/bootstrap/orchestrate.go`, `gateTrust` in `internal/bootstrap/trust.go`). The gate covers
the shared `.codemeld/settings.yaml`, the local `.codemeld/settings.local.yaml`, and the
`.codemeld/vcs` template folder. If the root is not listed in the approval store
`~/.codemeld/global/approved-projects.yaml`, **both** project-scope settings files are dropped before
anything reads them: not parsed, not validated, not composed. They contribute no permissions and no
`blocked_paths` entries at all, the project's VCS templates are not loaded, and the launch composes
the global layer alone. So a broken `.codemeld/settings.yaml` produces **no** load failure while its
project is unapproved, and the error first appears once you approve it, which makes approving look
like the thing that broke it. `AGENTS.md` is not covered by the gate and loads either way.

An interactive launch (stdin is a terminal) asks once, naming the covered paths that exist; a yes
appends the canonical root to the store (`trust.Record`). Approval is per project root and
permanent: it records the root, not the files' contents, so editing, replacing, or deleting the
files later never brings the question back, and codemeld has no command that withdraws it. A no
records nothing, so the next interactive launch asks again. A non-interactive launch —
`codemeld run`, or piped stdin — honors the list but never prompts and never appends to it. A root
with none of the covered paths present is not asked about at all.

**What an approval does not buy.** Approving a root is not a review of what its files say, now or
later. After approval, every later commit to the project's settings takes effect at the next launch
with no further question — including a `permissions` entry whose `path_scope` is any absolute path,
`mode.default`, `declared_commands` (commands that run with no prompt), and the argv in
`.codemeld/vcs` templates. Approving a repository means trusting whoever can commit to it.

To validate a project settings file without launching and without approving its project, run
`codemeld config check <path>` — naming the file parses it under the project layer's rules. With no
argument the command reports an unapproved project's shared file as `present, not approved` and
leaves it unparsed, just as a launch does; it does not yet check `settings.local.yaml` on its own.
[`../setup.md`](../setup.md) lists its output states and exit codes.

### Discovery (two modes — note the real names)

`LocateProjectRoot(cwd, mode)` supports exactly two boundary modes:

- **`launch-dir-only`** (the **default**) — no walk; only the launch dir's own marker is checked.
- **`project-root`** — walk upward to the **innermost** ancestor containing `.codemeld/settings.yaml`.
  The home dir `~/.codemeld` is carved out (never matched as a project root). An unreadable *anchor*
  errors (`*AnchorReadError`); an unreadable dir higher up just warns and the walk continues.

Project-root selection is by marker file, **independent of any VCS marker** — that's deliberate, to
avoid a circular dependency with VCS auto-detection.

### Compose (`Compose`)

The layers compose in a fixed order — global, then project, then local — and the **local** layer
is nearest, so it wins. The rules:

- **Nearest-wins, one level deep** for the known map keys (`discovery`, `agent`, `agent_instructions`,
  `sessions`, `vcs`, `model`, `mode`, `provider`): global subkeys are kept, project subkeys override per
  key (e.g. `mode.default`), and local subkeys override both (e.g. a local `model.active` over the
  shared file's).
  A `provider.<name>` entry or `model.active` value is replaced **wholesale**, not field-merged.
- **Lists replace** (e.g. `vcs.priority`); scalars override; unknown keys pass through (the nearest
  layer that has the key wins).
- **`permissions` concatenate** across all three layers — global, then project, then local — and
  dedup by the 4-tuple `(kind, subject, scope, grant_kind)`, keeping the **first** occurrence, so
  when two layers carry the same grant the farther copy is the one kept. `scope` is the entry's
  `path_scope`, or — for a network grant — its canonical `host_scope`, so a host grant and a path
  grant can never collapse into each other.
- **`blocked_paths` concatenate** the same way, global then project then local.
- For both lists, **no layer can remove another layer's entry**: a nearer list only adds.
- **Empty `permissions: []` in the project or local file is treated as absent** — it does *not*
  revoke grants from a farther layer. (An empty *global* list, by contrast, is preserved.)
- **`declared_commands` comes from the project layer alone**; the global and local validators
  reject the key.
- Inputs are never mutated; the result shares no mutable structure.

### Provider entries are connection-only, except OpenRouter routing

A `provider.<name>` entry carries **connection configuration**: `base_url`, `api_key`, and an
optional `auth_header`. The one exception is `provider.openrouter`, which also accepts an optional
`routing` block of OpenRouter provider-routing preferences — `sort` (`throughput`, `latency`, or
`best_value`), `data_collection` (`allow` or `deny`), `require_parameters` (boolean), and
`max_price`, a map from an exact model id to a `prompt` and/or `completion` cap in US dollars per
million tokens (`openrouterProviderEntry` in the schema; Module 8 covers what is sent). Every other
entry rejects `routing`. No entry has a `models` key, `openrouter` included — the retired
`provider.<name>.models` list is **rejected** by the settings schema (`schemas/settings.schema.json`
sets `models: false` under `providerEntry` and `openrouterProviderEntry`), and `Validate` names the
precise dotted key `provider.<name>.models` in the error.
Selectable model ids come solely from the local discovered catalog (`models.yaml`), refreshed by
`/connect`. This is a deliberate breaking change: no migration, ignored-field, or
compatibility parser is provided, so an existing dev settings file with the key must be hand-edited.

### The Cache (`Cache` / `NewCache`)

The single, session-lifetime read source. Built **once**; parses providers, permissions, and the
`model.favorites` list up front. Its snapshot reads **never re-read files** (external on-disk edits are
invisible for the run). It exposes defaulted accessors (defaults: `Discovery()`→`launch-dir-only`,
`AgentMaxConcurrency()`→`3`, `RetentionDays()`→`30`, `MaxToolOutputBytes()`→`65536`,
`VCSPriority()`→`[git, hg, jj]`, `Attribution()`→`true`, …), a defensive `Favorites()` snapshot of the ordered favorited
provider/model pairs, and in-memory write-backs (`AppendPermission`, `SetModelActiveRaw`) that are
visible immediately but **not** persisted — persistence is a separate path.

There is no *general* reload API. The exceptions are deliberate confirmed-write updates, each writing
the **global** layer and publishing to the session only after the write is confirmed; among them are
`Cache.SetAttribution`, the OpenRouter routing setters, and `Cache.ToggleFavorite`. Ordinary
snapshot reads still never re-read files.

`Cache.SetAttribution(on)` is the smallest: it persists `attribution` through the
same locked writer and only then updates the value `Attribution()` reports, so the next provider client
picks the new setting up without a restart. A failure returns the writer's exact reason/category/error
and leaves both the file and the session value alone — which is what lets the `/settings` settings
tab promise it never shows an optimistic value.

The OpenRouter routing setters — `Cache.SetOpenRouterDataCollection`, `Cache.SetOpenRouterSort`,
and `Cache.SetOpenRouterMaxPrice` — all go through `Cache.setOpenRouterRouting`. It fails closed
before any write when there is no configured `provider.openrouter` entry or no global layer path,
persists the one `provider.openrouter.routing.<key>` value with `Persist`, and only after a confirmed
write updates the routing of the cached `openrouter` entry, so the next OpenRouter client built from
`Cache.Provider` sends the new value without a restart. A failure returns the writer's exact
reason/category/error and leaves the session value alone.

`Cache.ToggleFavorite(target, want)` is the most involved:
it favorites/unfavorites exactly one pair in the **global** settings file (`layerPaths[0]`; an unset or
empty first layer fails closed before any write) through the locked `persistFavorite` writer. Only on a
confirmed successful (or no-op) write does it replace the cached favorites from the writer's own
lock-held disk state — so a pair another codemeld instance persisted is reconciled into the session
view, and the cache never predicts the next list from its possibly-stale copy. On any writer failure it
returns nil favorites plus the writer's exact reason/category/error and leaves the cache untouched. Note
the post-rename nuance: a `ReasonParentDirError` can follow a successful rename, so the file may already
hold the transition even though no confirmed result is returned — the method makes **no** disk-rollback
claim.

### Global-only keys (`EnforceGlobalOnly`)

Rejected in a **per-project** file (legitimate only in the global file):

1. `discovery.boundary` — it governs the upward walk, so it must be settled before per-project layers
   are even discovered.
2. `sessions.retention_days` — governs pruning across *all* folders.
3. `sessions.max_tool_output_bytes` — a process-wide cap.
4. the **whole `provider:` map** (and any nested `provider.<name>.<field>`) — the credentials/destination
   trust boundary; a checked-in repo config must not redirect `base_url` or supply keys.
5. the **whole `auth:` map** (and any nested `auth.<name>`, e.g. `auth.openai-chatgpt`) — codemeld-owned
   credential/session state; a per-project file must not carry it.
6. `model.favorites` — favorited provider/model pairs belong to the user, not a repo, so they live only
   in the global file. Only this child is rejected: `model.active` stays per-project (codemeld writes
   it to the local file) and `model.last_used` stays the global fallback.
7. `attribution` — whether outbound OpenRouter requests name codemeld. It is a top-level boolean that
   defaults to **true** when absent, so an existing `settings.yaml` needs no edit. It is global-only
   because the `/settings` settings tab reads it, writes it, and shows it back: with one owning file
   there is no layering question, so the value on screen is always the value in effect.

A key that is *not* on that list can be set per project; when `Compose` merges scalars, it lets a
project file win. Note what making a key global-only costs: a project file that already carried
`attribution` now **fails to load** with the standard `does not match the settings schema` message,
whose `what happened:` line names the key and the global file, rather than being silently
downgraded. That trade is only worth it for a key a UI displays and writes.

The mirror image is a **project-only** shape: a network permission entry (`host_scope`).
`ValidateGlobalSettingsBytes` (`load.go`) rejects it in the global file with the same
`does not match the settings schema` message, because `Compose` concatenates the raw layers before
anything parses them — after composition an entry's origin layer is gone, so a global host grant
would silently become an effective egress grant.

### Persist (`Persist` + `RewriteKey`)

The single chokepoint for every settings write. Which file a write lands in depends on the key:

- **Local file** `.codemeld/settings.local.yaml`, through `PersistLocal` (`local.go`): folder
  grants, project host grants (`grant_kind: project`), `model.active`, and the removal of a local
  `blocked_paths` entry.
- **Global file** `~/.codemeld/global/settings.yaml`: global grants, `model.last_used`,
  `model.favorites` toggles, the `attribution` opt-out, the OpenRouter routing settings, the
  `auth.openai-chatgpt` ChatGPT session state set/delete, and `/blocked`'s recommended
  `blocked_paths` additions and removals.
- **Shared file** `.codemeld/settings.yaml`: only two deliberate `/settings` picker actions, each
  after a confirmation. **Share** publishes one entry from the local file into the shared file and
  then removes it from the local file; it is offered only for a local grant in an approved project.
  **Remove** deletes one shared entry. codemeld writes the shared file in no other way, so a
  permanent approval stays on this machine unless you share it.

```
EnsureDir(parent)
  → acquire lock on  target + ".lock"      ← a SIDECAR, never the settings file
    → re-read the file under the lock        (absent file = empty doc, not a failure)
      → RewriteKey: merge + WriteAtomic(0600)   (byte-preserving AST splice)
    → release lock (defer)
```

Each settings file has its own sidecar — `settings.yaml.lock` beside the shared and the global
file, `settings.local.yaml.lock` beside the local one. The lock is on a sidecar because
`WriteAtomic` replaces the settings file's inode by rename — a lock on that inode would orphan and
break mutual exclusion for 3+ concurrent writers. `RewriteKey` may
only write the codemeld-owned keys (`permissions`, `model.active`, `model.last_used`,
`model.favorites`, `attribution`, `auth.openai-chatgpt`, `blocked_paths`, and `provider.<name>`); every other key,
comment, anchor, and whitespace round-trips **byte-for-byte** because it splices bytes rather than
re-marshalling. `attribution` is the smallest case to read first: it replaces the boolean scalar's
own bytes, so an inline `# comment` on that same line survives too.

`model.favorites` is the one key whose *new value* is computed inside the lock rather than supplied
by the caller. `persistFavorite` passes only the one pair to toggle; `Persist` fills in the ordered
transition from its own re-read (`favorites.go` `favoriteToggleValue.prepare` + `applyFavorite`).
A caller that handed in a whole list could hand in a snapshot taken before the lock and silently
erase another codemeld instance's toggle. A duplicate add or a remove of an absent pair writes no
bytes at all.

### The settings files a model-facing tool may not touch

`Persist` is the *only* way these files are supposed to change, but nothing used to stop the model
from reaching them the ordinary way: an `edit` call on `.codemeld/settings.yaml` is just a file
write, and a recorded session removed seven approved permission grants that way.

So the three settings paths the run was configured with — the shared
`<project_root>/.codemeld/settings.yaml`, the local `<project_root>/.codemeld/settings.local.yaml`,
and the global `<home>/.codemeld/global/settings.yaml` — and the approval store
`<home>/.codemeld/global/approved-projects.yaml`, plus each one's `.lock` sidecar, are refused for
the five mutating structured file tools (`edit`, `create`, `delete`, `mkdir`, `move`). The
classification lives in `internal/securitystate` (`Policy.RefuseNominal` / `Policy.RefuseResolved`),
and bootstrap builds the policy in `protectedStatePolicy` (`internal/bootstrap/trust.go`) from the
same names this module's loaders use — `projectSettingsPath(cache.ProjectRoot())`,
`config.LocalSettingsPath(cache.ProjectRoot())`, `SettingsPath(home)`, and `trust.StorePath(home)` —
never from the launch directory. The approval store is in the set so a model cannot approve the
repository it is running in through the file tools.

Two details are worth holding on to:

- **The sidecar is protected for the same reason the lock exists.** A tool that could create or
  replace `settings.yaml.lock` could break the mutual exclusion `Persist` depends on without ever
  touching the settings file.
- **It is the configured names, not a shape.** An unrelated nested `settings.yaml` somewhere in the
  project is an ordinary file. The guard also has no idea what is *inside* the file — it reads no
  YAML, so there is no before/after state for it to get wrong.

The dedicated writers this module describes are unaffected: they are typed Go calls, not tool
dispatch.

## Watch for (Go idioms)

- **Package-local function-pointer seams.** `readDir`/`userHomeDir` (`discovery.go`),
  `acquireLock`/`rereadSettings`/`mergeWrite` (`persist.go`) are swapped in tests to force failure modes
  the real filesystem can't produce on demand.
- **`sync.Once` compile-and-cache.** `settingsSchema()` compiles the embedded JSON Schema exactly once.
- **Decode into `any` to route errors.** A non-map root reaches schema validation, not a parse error.
- **Copy-on-the-boundary immutability.** `deepCopyValue`/`slices.Clone`/`copyProviderEntry` give value
  semantics over decoded YAML so neither `Compose` nor `Cache` ever aliases caller data.

## Quiz

Closed-book: [`quizzes/module-04.md`](quizzes/module-04.md). Grade against
[`quizzes/module-04-key.md`](quizzes/module-04-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** A project `.codemeld/settings.yaml` has `permissions: []`; the global
file has two grants. How many grants are in the composed result? Predict, then read
`composePermissions` in `compose.go` and confirm against the `TestCompose` case for empty project
permissions not revoking inherited global grants.

**B. Locate the rule.** Predict what happens if you put a `provider:` block in a *project* settings
file. Then find `EnforceGlobalOnly` (`globalonly.go`) and the `TestEnforceGlobalOnly_Rejects` case
that proves it. Why is `provider:` global-only?

**C. Trace the write.** Trace a permission write through `config.Persist`: list the steps from lock to
unlock and note exactly which file the lock is taken on. Record it in [`progress.md`](progress.md),
and write one sentence on why it's a sidecar (the atomic rename replaces the settings file's inode,
so a lock taken on that file would orphan).

## Done when

- You can state the compose precedence and the empty-`permissions` rule from memory.
- You can list the global-only keys.
- You can explain the sidecar lock and what `RewriteKey` is and isn't allowed to touch.
- You can name the three settings paths and the approval store a structured file tool may not
  mutate, and say why each one's `.lock` sidecar is in that set.
