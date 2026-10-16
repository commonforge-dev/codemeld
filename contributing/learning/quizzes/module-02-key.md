# Answer key — Module 2: Core types & vocabulary

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** `Message`, `Event`, and `Compaction`. The `Record` interface has an unexported `isRecord()`
method that only those three types implement, so outside code can't add a variant. `Compaction` is
valid **only as `Records[0]` of a linked child** (the metadata header is not a `Record`); its source
provenance is the child's `Metadata.ForkedFrom` plus the `Compaction.ParentID` stamped on record
zero, which must equal `ForkedFrom.RecordID` — `Provider`/`ModelID` are audit metadata, not
provenance. *Proof:* `sessions/schema.go` — `Record`, `Message.isRecord`, `Event.isRecord`,
`Compaction.isRecord`, `validateProvenance`. Pinned by `TestCompaction_RoundTrip` and
`TestCompaction_Rejects` in `sessions/schema_test.go`.

**2.** **Later**, not at parse time. `Unmarshal`/`parseToolCalls` only preserve `id`/`type`/`Raw`;
the "must be `function`" rule is enforced by `ValidateRecordStream`. *Proof:*
`sessions/schema.go` `parseToolCalls`; `sessions/validate.go` `ValidateRecordStream`. Pinned by
`TestUnmarshalThenValidate_NonFunctionToolCallType` in `sessions/schema_test.go`.

**3.** Uppercase hex (and anything not in strict lowercase canonical form). *Proof:* `ids/uuidv7.go`
`uuidV7Pattern`, `IsValidV7`. Pinned by `TestIsValidV7_Rejections` (case `uppercase_hex`) in
`ids/uuidv7_test.go`.

**4.** No — `NewCache` copies/resolves everything it keeps (`slices.Clone`, `deepCopyValue`,
`parsePermissions`) at construction, so later mutation of the input leaks nothing. *Proof:*
`config/cache.go` `NewCache`; pinned by `TestCacheExternalEditsInvisible` in `config/cache_test.go`.

**5.** No — it is built once and never re-reads files; there is no reload API in phase 1.
*Proof:* `config/cache.go` `Cache` doc comment. Behavior pinned by `TestCacheExternalEditsInvisible`.

**6.** It coerces invalid UTF-8 byte runs to a single U+FFFD (via `strings.ToValidUTF8`) on a deep
copy, leaving the caller's payload untouched. *Proof:* `events/append.go` `canonicalize`, `Append`.
Pinned by `TestAppend_UTF8Coercion` in `events/append_test.go`.

**7.** Same name from the **same source** → hard error (`*DuplicateNameError`, registry unchanged).
Same name from a **different source** → the later registration wins with a single stderr warning.
*Proof:* `tools/registry.go` `Register`. Pinned by `TestSameSourceDuplicateErrorsWithExactLine` and
`TestCrossSourceReplacementWarns` in `tools/registry_test.go`.

**8.** The structured built-ins are `edit`, `create`, `delete`, `read`, `glob`, `grep`, `list`, `tree` (plus
`vcs.*` action tools when a VCS is active). `Registry.List()` returns them in deterministic
ascending-name order — it sorts by name rather than preserving registration order. `bash` is **not**
in the registry: it has no `Tool`, is advertised separately by a product-authored provider
definition, and dispatch special-cases its pinned name to run through the shell path. *Proof:*
`internal/bootstrap/tooldispatch.go` `realize`, the `*ToolName` constants in `internal/filetools/`,
`internal/tools/registry.go` `List`, and `internal/provider/tooldefs.go` `BashToolDefinition`.

**9.** `id` (it maps to `Selection.ID`; `model` is never an alias). *Proof:* `model/selection.go`
`Selection`, `ParseSelection`. Pinned by `TestParseSelection_ModelNotAliasForID` in
`model/selection_test.go`.

**10.** **Closed.** `EventPayload` has an unexported `validate()` method, so only types in the
`events` package can implement it. *Proof:* `events/payloads.go` `EventPayload`.
