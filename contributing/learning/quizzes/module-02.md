# Quiz — Module 2: Core types & vocabulary

Closed-book. Write your answers before opening `module-02-key.md`.

---

**1.** What record kinds can appear in a `Session`, and how is that set kept closed to the package?
Which one may appear only as `Records[0]` of a linked child, and what carries its source provenance?

**2.** Where is the rule "a `tool_call`'s `type` must be `function`" enforced — at parse time or later?

**3.** What does `IsValidV7` reject that the underlying `uuid.Parse` would accept?

**4.** After `NewCache`, can mutating the input `composed` map change what the cache returns? Why?

**5.** Does the config `Cache` re-read on-disk YAML when the file is edited mid-session?

**6.** How does `events.Append` treat invalid UTF-8 in a payload string, and does it mutate the
caller's payload?

**7.** When a tool is registered twice, when is it a hard error versus a warning?

**8.** Name the structured built-in tools in the registry. In what order does `Registry.List()`
return them, and why is `bash` not in that list?

**9.** On disk, what is the field name for a model's identifier (it is deliberately *not* `model`)?

**10.** Is the `EventPayload` set open or closed, and what enforces that?
