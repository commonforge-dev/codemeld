# Quiz — Module 11: Infra & periphery

_Last updated: 2026-07-12_

Closed-book. Write your answers before opening `module-11-key.md`.

---

**1.** What are the exact steps of an atomic write, in order?

**2.** If the rename step fails, which step token comes back, and is anything left on disk?

**3.** What is locked (which file), and what auto-releases it?

**4.** How does `TryAcquire` differ from calling `Acquire(path, 0)`?

**5.** What happens when persisting a folder or global permission grant fails?

**6.** Which errnos map to which categories, and what is the fallback category?

**7.** What is the canonical OP_FAIL line format, and does it end with a newline?

**8.** How does `ResolveHome` decide the home directory, and what does `Expand("~root")` do?

**9.** Why does `EnsureDirAt` create a missing suffix one component at a time under a held descriptor
instead of calling `os.MkdirAll`, and which two open flags make an escape impossible? Why does the `create`
tool **not** use its `createdDirs` return value to roll back the parent directories it created when a nested
create later fails, and what residue does that leave behind?
