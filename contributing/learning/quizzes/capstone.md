# Quiz — Capstone (synthesis)

Closed-book. These span modules. Write your answers before opening `capstone-key.md`.

---

**1.** Trace the zero-phone-home guarantee from code to test: name the sanctioned functions that
open outbound connections and the origin each one may reach (OpenAI-compatible provider traffic,
ChatGPT/Codex model traffic, and OpenAI OAuth traffic), and name the tests that enforce nothing else
dials out and that credentials are redacted on failure.

**2.** Name three different places the codebase writes durable files **atomically** (temp + rename),
and explain why advisory locks are taken on a **sidecar** rather than the data file.

**3.** The three permission grant lifetimes: where does each persist (file path or "nowhere"), and
which packages are involved when a folder grant is created *and* saved?

**4.** Why is the project root marked by `.codemeld/settings.yaml` instead of being inferred from the
VCS root? (Give the dependency-cycle reason.)

**5.** In a pipeline `cat x | grep secret` where `grep secret` is denied, what runs, and what is the
structural reason no stage runs?

**6.** How does a line typed in the TUI become a model turn, and where is the `AGENTS.md` system prompt
assembled and inserted?

**7.** What is the difference between a real permission grant and a turn-cache hit, and which one wins
when both could apply?

**8.** Contrast the recovery paths for a session write failure **mid-turn** versus on **clean shutdown**.

**9.** In the fresh-launch sequence, what must happen before the session is created (step 7b)?

**10.** "The tests are the spec." Give two concrete examples where a table-driven test *is* the
definition of a behavior, naming the test.
