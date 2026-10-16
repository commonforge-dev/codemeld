# Answer key — Module 4: Config: load & compose

_Last updated: 2026-10-06_

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** `defaultLoadGlobalSettings` (`bootstrap/orchestrate.go`). It calls `WarnIfBroaderThan0600`
first (advisory plaintext-credential warning naming API keys and ChatGPT session tokens), then reads
the file and passes the bytes to `ValidateGlobalSettingsBytes`. The two project-scope loaders,
`readAdmittedProjectSettingsLayer` and `readAdmittedLocalSettingsLayer`, never warn: they run only
for an approved project, read the file, and pass the bytes to `ValidateProjectSettingsBytes` and
`ValidateLocalSettingsBytes` respectively. *Proof:* `bootstrap/orchestrate.go`
`defaultLoadGlobalSettings`/`defaultComposeConfig`/`readAdmittedProjectSettingsLayer`/`readAdmittedLocalSettingsLayer`,
`load.go` `WarnIfBroaderThan0600`/`ValidateGlobalSettingsBytes`/`ValidateLocalSettingsBytes`; pinned by
`TestDefaultLoadGlobalSettings_PreservesBroaderThan0600Warning` and
`TestRunFresh_UntrustedAtTheGateNeverReadsProjectSettings` in `bootstrap/orchestrate_test.go` and
`TestWarnIfBroaderThan0600_BroaderWarnsAndBytesValidate` and `TestWarnIfBroaderThan0600_Exactly0600`
in `load_test.go`.

**2.** A one-level merge: `{preferred: git, priority: [hg]}` — global subkeys kept, project subkeys
override per key, and the list subkey is replaced wholesale. The local file cannot take part here:
it rejects every top-level key except `model`, `permissions`, and `blocked_paths`, so a local `vcs`
mapping fails validation before compose runs. Where the local file does set a value — `model.active`
— it overrides the project and global values, because the local layer is nearest. *Proof:*
`compose.go` `Compose`/`mergeMapOneLevel`; `local.go` `localAllowedKeys`/`enforceLocalAllowList`;
`TestCompose` case "map subkeys merge, inherited subkey kept" in `compose_test.go`,
`TestValidateLocalSettingsBytes_RejectsKeysOutsideTheAllowList` in `local_test.go`, and
`TestDefaultFreshSteps_ComposeConfig_LocalLayerWinsOverTheSharedFile` in
`bootstrap/orchestrate_test.go`.

**3.** It **concatenates** across the three layers — global, then project, then local — instead of
replacing, then dedups by the 4-tuple `(kind, subject, scope, grant_kind)` — where `scope` is
`path_scope`, or the canonical `host_scope` for a network grant — keeping the first occurrence, so the
farthest copy of a repeated grant is kept and no layer can remove another layer's entry. *Proof:*
`compose.go` `composePermissions`/`dedupPermissions`/`dedupKeyOf`; `permissions.DedupKey`;
`TestCompose` case "permissions concat-merge with dedup, first occurrence kept",
`TestCompose_PermissionsConcatenateGlobalProjectLocal`, and
`TestCompose_PermissionsDedupKeepsTheFarthestCopy` in `compose_test.go`.

**4.** No — an explicit empty list in the project file (or the local file) is treated as **absent**;
grants from the farther layers survive. *Proof:* `compose.go` `composePermissions` (a project-scope
layer contributes only when `has && len(list) > 0`); pinned by the `TestCompose` case for empty
project permissions not revoking inherited global grants and `TestCompose_EmptyLocalPermissionsListIsAbsent`
in `compose_test.go`.

**5.** `launch-dir-only`, defined as `defaultDiscoveryBoundary` in `cache.go` and returned by
`Cache.Discovery()`. *Proof:* pinned by `TestCacheDefaults` in `cache_test.go`. (The schema enum is
only `launch-dir-only` / `project-root`.)

**6.** It falls back to the launch anchor (with no project layer). The home directory is **never**
matched even if it has a marker. *Proof:* `discovery.go` `LocateProjectRoot` (`home == "" || dir != home`);
pinned by `TestLocateProjectRoot_NoMarkerFallsBackToCWD` and `_HomeCodemeldExcluded` in
`discovery_test.go`.

**7.** It is the single session-lifetime read source: it parses provider/permission/favorite views once
and its snapshot reads (`Favorites`, the other accessors) do **no file reads** afterward, so external
on-disk edits are invisible. It does **not** persist (that's the `Persist` path) and has **no general
reload API**. Its exceptions are confirmed-write updates that write the global layer and publish to
the session only after the write is confirmed — among them `Cache.SetAttribution`, the OpenRouter
routing setters `Cache.SetOpenRouterDataCollection`, `Cache.SetOpenRouterSort`, and
`Cache.SetOpenRouterMaxPrice` (all through `Cache.setOpenRouterRouting`), and
`Cache.ToggleFavorite(target, want)`. The favorite toggle is the one that reconciles from disk: it
toggles exactly one pair in the global settings file (`layerPaths[0]`; an unset/empty first layer fails closed with
`reread_parse_error` before any write) through the locked `persistFavorite`, and **only on a confirmed
success** replaces the cached favorites from the writer's own lock-held disk state — so a pair another
codemeld instance persisted is reconciled in, and the cache never derives the next list from its stale
copy. On any writer failure it returns nil favorites plus the writer's exact reason/category/error and
leaves the cache unchanged; a `ReasonParentDirError` can follow a successful rename, so the file may
already hold the transition with **no** disk-rollback claim. *Proof:* `cache.go` `Cache` doc +
`NewCache` + `Favorites` + `Cache.setOpenRouterRouting`, `favorites.go` `Cache.ToggleFavorite`; pinned
by `TestCacheExternalEditsInvisible`, `TestNewCache_Favorites`, `TestCacheFavorites_DefensiveCopies`,
`TestCacheOpenRouterRouting_SettersPersistThenPreserveSiblings`, and
`TestCacheOpenRouterRouting_WriteFailureLeavesCacheUnchanged` in `cache_test.go` and
`TestCacheToggleFavorite_GlobalPathAndReconciliation`, `_NoLayerFailsClosed`, `_NoOpPreservesBytes`,
`_PrePublishFailure`, `_ParentSyncFailure` in `favorites_test.go`.

**8.** `discovery.boundary`, `sessions.retention_days`, `sessions.max_tool_output_bytes`, the entire
`provider:` map (including any nested `provider.<name>.<field>`), and the entire `auth:` map
(including any nested `auth.<name>`, e.g. `auth.openai-chatgpt`), `model.favorites` (only that
child — `model.active` and `model.last_used` stay allowed), and `attribution`. *Proof:* `globalonly.go`
`firstGlobalOnlyViolation`; pinned by `TestEnforceGlobalOnly_Rejects` in `globalonly_test.go`.

**9.** The sidecar `target + ".lock"`. The settings file's inode is replaced by atomic rename
(`WriteAtomic`), so a lock on it would orphan and break mutual exclusion for 3+ writers.
*Proof:* `persist.go` `Persist`/`lockSuffix`; pinned by `TestPersist_LocksSidecarNotSettingsFile` and
`TestPersist_ConcurrentWriters_ThreePlus_NoLostUpdate` in `persist_test.go`.

**10.** `parent_dir_error`, `lock_timeout`, `lock_acquire_error`, `reread_io_error`,
`reread_parse_error`. An **absent file is NOT** a failure — it's treated as an empty document and the
merge proceeds. *Proof:* `persist.go` `Persist` skip branches; pinned by
`TestPersist_MalformedFile_SkipsWriteUnmodified`, `_LockTimeout_SkipsWrite`, `_RereadIOError_SkipsWrite`,
and `_RereadAbsent_TreatedAsEmpty` in `persist_test.go`.

**11.** Only `permissions`, `model.active`, `model.last_used`, `model.favorites` (package-private
`keyModelFavorites`), `attribution`, `auth.openai-chatgpt` (set or delete), a `provider.<name>`
connection entry (`KeyProviderPrefix`), and the OpenRouter routing keys
`provider.openrouter.routing.data_collection`, `.sort`, and `.max_price`
(`KeyOpenRouterRouting*`). Everything else — keys, comments, anchors, ordering, whitespace — round-trips
byte-for-byte (it splices bytes, doesn't re-marshal), then writes via `fsutil.WriteAtomic` at mode
`0600`. *Proof:* `rewrite.go` `RewriteKey` + the `Key*` constants. `model.favorites` differs from the
rest: its value is derived inside the lock by `favorites.go` `favoriteToggleValue.prepare`, not passed
in, so a stale whole-list snapshot cannot erase a concurrent toggle; pinned by
`TestPersistFavorite_UsesLockedLatestState` and
`TestPersistFavorite_ConcurrentDifferentAddsBothSurvive` in `persist_test.go`.

**12.** Load fails validation — provider entries carry connection fields only, so `models` is a
rejected field. The error names the precise dotted key `provider.openai.models`. It is enforced in
`schemas/settings.schema.json`, where `providerEntry` declares `"models": false` (a subschema that
always fails when the key is present, yielding the leaf instance location rather than the parent that
`additionalProperties: false` would report). The breaking change is deliberate: there is no migration.
Under `provider.openrouter` the result is the same — `openrouterProviderEntry` also declares
`"models": false`. The one thing that entry accepts beyond connection fields is an optional `routing`
block (`sort`, `data_collection`, `require_parameters`, per-model `max_price`); every other entry
rejects `routing`. *Proof:* `schema.go` `Validate`/`offendingKeys`; pinned by the
`TestValidate_Rejects` cases "global provider legacy models list rejected at its dotted leaf", "project
provider legacy models list rejected at its dotted leaf", and "routing on a non-openrouter entry" in
`schema_test.go`.

**13.** Rejected — the whole project file fails to load. `attribution` is global-only, so
`EnforceGlobalOnly` reports `schema validation failed at attribution: global-only key must be moved to
~/.codemeld/global/settings.yaml`, and it runs *before* `Compose`, so scalar precedence never gets a
chance to apply. Where the key is absent everywhere, `Cache.Attribution()` reports `true` from
`defaultAttribution` — an existing `settings.yaml` needs no edit. A non-boolean in the global file fails
schema validation at the dotted key `attribution` before a cache is ever built, so it cannot silently
fall back. *Proof:* `cache.go` `NewCache`/`Cache.Attribution`, `globalonly.go`
`firstGlobalOnlyViolation`, `schemas/settings.schema.json`; pinned by `TestCacheDefaults` and
`TestCacheAccessors` in `cache_test.go`, the `TestEnforceGlobalOnly_Rejects` cases "attribution opt-out"
and "attribution opt-in" in `globalonly_test.go`, and the `TestValidate_Rejects` case "non-boolean
attribution" in `schema_test.go`.

**14.** Because the session value is the contract for what is *already durable*: `buildTurnClient`
snapshots `Cache.Attribution()` when it builds the next provider client, so publishing before a
confirmed write would send un-persisted headers (or drop persisted ones) for the rest of the run.
`SetAttribution` returns the writer's exact reason/category/error and leaves both the file and the
cached value untouched on failure, so the settings tab re-renders from the unchanged accessor — the row
keeps its on-disk value and a one-line notice reports the failure. *Proof:* `cache.go`
`Cache.SetAttribution`, `picker_settings.go` `App.actOnSettingsRow`, `turndeps.go`
`buildTurnClient`; pinned by `TestCacheSetAttribution_WritesGlobalLayerAndPublishesToSession`,
`_NoGlobalLayerFailsClosed`, `_WriteFailureLeavesDiskAndSessionUnchanged` in `cache_test.go` and
`TestSettingsPicker_FailedSettingWriteKeepsRowsAndNotifies` in `picker_settings_test.go`.

**15.** The protected set is the run's three **configured** settings paths — the shared
`<project_root>/.codemeld/settings.yaml`, the local `<project_root>/.codemeld/settings.local.yaml`,
and the global `<home>/.codemeld/global/settings.yaml` — plus the approval store
`<home>/.codemeld/global/approved-projects.yaml`, each with its `.lock` sidecar, and the five
mutating structured file tools (`edit`, `create`, `delete`, `mkdir`, `move`) are refused on all
eight. Bootstrap supplies the names from the same sources the loaders and the approval gate use —
`projectSettingsPath(cache.ProjectRoot())`, `config.LocalSettingsPath(cache.ProjectRoot())`,
`SettingsPath(home)`, and `trust.StorePath(home)` — never from the launch directory. The store is in
the set so a model cannot approve the repository it runs in through the file tools. Each sidecar is in
the set because the writers take their lock there: a tool that could create or replace a sidecar
could break the mutual exclusion every write to that file depends on without touching the file at
all. An unrelated nested `settings.yaml` is **not** protected — the rule is those configured names,
not a filename shape. *Proof:* `bootstrap/trust.go` `protectedStatePolicy`, called from
`bootstrap/starttui.go` and `bootstrap/headless.go`; `securitystate/protect.go`
`Policy.protectedIdentities` and `guardedTools`; `trust/trust.go` `StorePath`; pinned by
`TestProtectedStatePolicy_RefusesTheLocalSettingsFile` in `bootstrap/trust_test.go` and
`TestProductionDispatcher_GuardRefusesProtectedMutationBeforeInvocation` in
`bootstrap/tooldispatch_test.go`.
