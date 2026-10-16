# Quiz — Module 3: Bootstrap / the launch spine

Closed-book. Write your answers before opening `module-03-key.md`.

---

**1.** What is the very first step `codemeld` runs on a fresh launch, and why must it be first?

**2.** What does step 0 (`RunFirstRun`) do when the global settings file is absent versus present?

**3.** In first-run generation, in what order are the operations done, and why that order?

**4.** What runs immediately *before* the session is created (step 7b)?

**5.** How is the `launch_began` event placed in the fresh sequence (which step, what source, between
what)? Which step runs immediately *after* it, before AGENTS.md load?

**6.** If step N fails, do the later steps run?

**7.** What does `RunFresh` return on the first-run branch versus a full launch?

**8.** How does the CLI turn a home-resolution failure into the right process exit?

**9.** Where is the per-process exit code decided, and what are the cases?

**10.** Where do `ScaffoldProjectIgnore` (step 2.5) and `InitMode` (step 7b2) sit in the fresh
sequence — what runs immediately before and after each?

**11.** In what order are the config layer source paths recorded on `BootstrapResult`?

**12.** Step 3 composes three settings layers. In what order are they composed, which one wins when
two set the same overrideable setting, what happens instead to `permissions` and `blocked_paths`, and
which `BootstrapResult` field does `/status` read to list them?
