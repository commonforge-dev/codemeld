# Answer key — Module 3: Bootstrap / the launch spine

Citations are **file + function/symbol name**. Behavioral/ordering claims name the test that pins them.

---

**1.** Step **0a**, `ResolveHome` — resolve the home directory before any `~`-bearing path is
dereferenced. *Proof:* `bootstrap/orchestrate.go` `RunFresh`; order pinned by
`TestRunFresh_StepOrder` in `orchestrate_test.go`.

**2.** `RunFirstRun`: **absent** → generate first-run state and return `ran=true`, short-circuiting
before step 1; **present** → `ran=false`, continue. *Proof:* `bootstrap/orchestrate.go`
`defaultRunFirstRun`; pinned by `TestRunFresh_FirstRunShortCircuits`.

**3.** **Directories → built-in VCS templates → global `codemeldignore` scaffold → settings.** The
settings writer needs its parent directories to already exist, and the global ignore file lands
before settings. *Proof:* `defaultRunFirstRun` calling `RunEnsureFirstRunDirs`
→ `RunMaterializeBuiltinTemplates` → `RunScaffoldGlobalCodemeldignore` → `RunWriteSettings`
(`bootstrap/orchestrate.go`; scaffold in `bootstrap/codemeldignore_scaffold.go`); dir order noted in
`firstrun_dirs.go` `FirstRunDirs` ("Order is load-bearing").

**4.** Step **7**, `DetermineModel` (resolve the active model). Its "no selectable model" exit aborts
before any session work. *Proof:* `RunFresh`; pinned by `TestRunFresh_DetermineModelPathFourExit`.

**5.** Step **7b1**, `AppendLaunchBegan`, source **fresh** — exactly one event, **after** session
creation (7b). It is the session anchor, so it is *not* immediately followed by the AGENTS.md load:
step **7b2** `InitMode` runs next (seeding the mode and appending `interaction_mode`), then step **7c**
`LoadAgentInstructions`. *Proof:* `FreshSteps.AppendLaunchBegan` / `InitMode` + `RunFresh`; placement
pinned by `TestRunFresh_LaunchBeganBetweenSessionAndAgents` and the `want` slice in
`TestRunFresh_StepOrder`.

**6.** No — each step runs only if every preceding step returned nil; `RunFresh` returns `(nil, err)`
and stops. *Proof:* `RunFresh`; pinned by `TestRunFresh_ShortCircuitsOnStepError`.

**7.** First-run branch → `(nil, nil)` (the caller exits 0). Full launch → a populated
`*BootstrapResult, nil`. *Proof:* `RunFresh`; `TestRunFresh_FirstRunShortCircuits` (nil result) and
`TestRunFresh_StepOrder` (non-nil result).

**8.** `runFresh` does `errors.As(err, &hre)` for a `*HomeResolveError` and exits with the rendered
message and code 1. *Proof:* `cli/root.go` `runFresh`; the wrapping is pinned by
`TestRunFresh_HomeResolveFailureWrapped` in `orchestrate_test.go`.

**9.** In `cli.Run`: nil error → 0; an `ExitCoder` error → its code; otherwise print `codemeld: <err>`
and return 1. *Proof:* `cli/root.go` `Run`.

**10.** `ScaffoldProjectIgnore` (**2.5**) runs **after** `ResolveProjectRoot` (2) and the approval
gate `GateTrust` (2b) that immediately follows it, and **before**
`ComposeConfig` (3), so the project `.codemeld` dir and starter ignore file exist before any later step
reads the project tree. `InitMode` (**7b2**) runs **after** `AppendLaunchBegan` (7b1) and **before**
`LoadAgentInstructions` (7c), so `launch_began` stays the session anchor. *Proof:* `RunFresh` and the
`want` slice in `TestRunFresh_StepOrder`.

**11.** **Global-first, then project-last:** `[globalSettingsPath, projectLayers...]`; with no project
layer, only the global path. *Proof:* `RunFresh` (the `ConfigLayerPaths` assignment); pinned by
`TestRunFresh_ConfigLayerPaths`.

**12.** **Composed global, then project, then local**; for an overrideable setting the nearer layer
wins, so precedence is **local over project over global**. `permissions` and `blocked_paths` instead
**combine** across the layers: a nearer list only adds, so a global `blocked_paths` entry survives a
local `blocked_paths: []`. The two project-scope layers are composed only when the approval
gate (2b) admitted the project. `/status` lists them from **`SettingsLayers`** — one snapshot per layer,
labelled by kind (`global`, `project`, `local`) — not from `ConfigLayerPaths`, which stays
global-first/project-last and never includes the local file. *Proof:* `defaultComposeConfig`
(`bootstrap/orchestrate.go`) calling `config.Compose`; `settingsLayerSnapshots`
(`bootstrap/orchestrate.go`); `statusLayers` (`bootstrap/starttui.go`); precedence pinned by
`TestDefaultFreshSteps_ComposeConfig_LocalLayerWinsOverTheSharedFile`, the combining by
`composeBlockedPaths` (`config/compose.go`), the gate by
`TestRunFresh_UntrustedLaunchWithholdsTheLocalSettingsLayer`.
