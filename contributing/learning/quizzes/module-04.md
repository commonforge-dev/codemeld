# Quiz — Module 4: Config: load & compose

_Last updated: 2026-10-06_

Closed-book. Write your answers before opening `module-04-key.md`.

---

**1.** At launch, which function loads the *global* layer, and what extra step does it take before
validating the bytes that the per-project loader doesn't?

**2.** Global and project both set `vcs` with different subkeys (global `preferred: git`, project
`priority: [hg]`). What's in the composed `vcs`?

**3.** What is special about `permissions` during compose, and what is the dedup identity?

**4.** Does `permissions: []` in a project file wipe inherited global grants?

**5.** What is the default `discovery.boundary`, and where is that default defined?

**6.** In `project-root` mode with no marker anywhere up the tree, what is the project root? And what
about a stray `~/.codemeld/settings.yaml`?

**7.** What does the config `Cache` do, and what does it deliberately *not* do, after construction?
Its snapshot reads never re-read files — so how does `Cache.ToggleFavorite` make a favorite another
codemeld instance persisted visible, and what does it do to the cache on a writer failure (including a
`ReasonParentDirError` after a rename may have published the new bytes)?

**8.** List the keys that `EnforceGlobalOnly` rejects in a per-project file.

**9.** What file is the `Persist` lock taken on, and why not the settings file itself?

**10.** Which `Persist` failure reasons skip the write and leave the file untouched? (Is an absent
file one of them?)

**11.** Which keys can `RewriteKey` write, and what does it guarantee about everything else in the file?

**12.** A user pastes `models: [gpt-5.5]` under a `provider.openai` entry in `settings.yaml`. What
happens at load, and what exact key does the validation error name? Where in the schema is that
enforced? Would the same key pass under `provider.openrouter`, and what does that one entry accept
beyond connection fields?

**13.** A repo checks in `.codemeld/settings.yaml` containing `attribution: false`, while the global
file says nothing about the key. Is the project file accepted, what does `Cache.Attribution()` report
where the key is absent, and what would a non-boolean value in the *global* file do?

**14.** `Cache.SetAttribution` writes the global settings file and then updates the value
`Attribution()` reports. Why must the update come second, and what does the `/settings` settings tab
show if the write fails?

**15.** The model asks to `edit` `<project_root>/.codemeld/settings.local.yaml`. Which paths does
the run treat as protected — settings files and anything else — where do those names come from, and
why is each one's `.lock` sidecar protected as well? Would a `settings.yaml` in some unrelated
subdirectory of the project be protected?
