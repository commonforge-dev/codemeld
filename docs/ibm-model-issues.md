<!-- Observed failure modes of small/weak models (notably IBM Granite) and how codemeld currently handles them. -->
# IBM / small-model issues

_Last updated: 2026-06-22_

A running record of how weak models (small open models routed via OpenRouter — IBM
Granite seen first) misbehave in codemeld, what the agent does about it today, and where
the gap is. Read this before answering "is X related to the model-not-responding work?".

## Quick map: not-responding-properly is two different problems

| Symptom | What the provider returned | Handled? | Where |
|---|---|---|---|
| Empty / silent turn | **No usable content** (`no_choices`, `null_content`, `zero_delta_stream`) or missing/truncated HTTP body | **Yes** — `provider_request_failed` + one-line notice | `internal/provider/transport_errors.go`, `internal/turn/turn.go` |
| Tool call printed as prose | **Normal content** that *is* a ```json `{"name":…,"arguments":…}` block (whole message), but no structured tool call | **Yes** — parsed and dispatched like a native call | `internal/turn/texttoolcall.go`, §"Textual tool call" |
| LaTeX math in plain-text answers | **Normal content** that explains math with LaTeX delimiters/commands (`\(5 \times 2\)`, `\[\sqrt{2}\]`) that render as literal backslashes in a terminal | **Yes** — a per-model special-instruction block tells the flagged model to use plain text / Unicode | `internal/agentinstr/special.go`, §"LaTeX math notation" |

The two look similar to the user ("it said it would do something, then nothing happened")
but are opposite at the wire level: one has no content, the other has content that just
never got dispatched.

## Textual tool call emitted as assistant text (HANDLED)

> **Handled.** An earlier version of this doc called this "model misbehavior"
> and said "do not auto-execute — security risk." That framing is **superseded**. Text-format
> tool calls are a normal, expected variant from small/open models; the correct, user-friendly
> handling (what OpenCode/Aider do) is to **parse the text call and dispatch it like a native
> call**. It is not a security downgrade: a parsed call runs through the *same* permission
> gate (the same authorizer / deny path) as a structured call — model-fabricated arguments are
> equally untrusted either way, and safety comes from that gate, not from the call's encoding.
> Parse-and-dispatch is implemented in `internal/turn/texttoolcall.go`.

### What it is
A small model "calls a tool" by writing the invocation as text in its content stream
instead of emitting a structured tool call. Example seen with `ibm-granite/granite-4.1-8b`:
the model wrote a plan and then a fenced block —

```json
{ "name": "grep", "arguments": { "pattern": "yellow", "path": ".", ... } }
```

— and the turn ended. No grep ran. To the user it looks like a hang.

### Reproduction
- Model `ibm-granite/granite-4.1-8b` via OpenRouter, plan mode.
- User asked where the yellow `@` color is set; model emitted the grep tool call as a
  fenced JSON block in its content and stopped.
- The `model_response` event recorded valid output tokens and `"anomaly": []` — i.e. it was
  logged as a clean, successful turn, and no structured tool call was ever dispatched.

### Why nothing fired before the fix (code trace)
`internal/turn/turn.go`, after the stream closes:
- The structured-tool-call branch `if finishReason == "tool_calls" || len(toolCallDeltas) > 0`
  is the only branch into tool execution. It fires solely on *structured* tool-call deltas
  (`choice.Delta.ToolCalls`) or a `tool_calls` finish reason. A ```json``` block in
  `choice.Delta.Content` accumulates into `reply` and never reached here.
- The `if reply.Len() == 0` `empty_response` path was skipped, because there
  *was* content.
- So it fell through: the text (fake tool call included) was committed as a normal
  assistant message and `model_response` was emitted.

**Closed by the fix.** A text-tool-call parse branch now sits *between* the two (after the
structured branch, before the empty-response check): when `len(toolCallDeltas)==0` and
`finishReason != "tool_calls"`, `parseTextToolCall` (`internal/turn/texttoolcall.go`) tries
to read the whole reply as a tool-call object and, on success, hands it through the same
`OnToolCalls` path a native call uses. Plain text and empty streams are untouched.

### Why `anomaly: []` did not catch it
The `anomaly` field on `model_response` is **not** a general "model misbehaved" channel.
The only value it ever carries is `usage_missing` (token-accounting gap) — see
`internal/model/turn_events.go` (`UsageAccumulator.Totals` / `normalizeUsage`) and the
field definition (`ModelResponse.Anomaly` in `internal/events/payloads.go`). This turn had valid
usage, so the array was empty. It was never going to flag a textual tool call.

### Relation to the empty-response work
Adjacent but **not covered**. Those classifiers
(`ClassifyEmptyCompletion`, `EmptyStreamClassification` in
`internal/provider/transport_errors.go`) require *no usable content*. A model emitting a
tool call as prose produces plenty of content, so none of them fire. This is a distinct
failure mode, not an extension of empty-response.

### Handling (as built)
- **Injection point:** in `turn.go`, between the structured-tool-call branch and the
  `reply.Len()==0` empty-response branch. When `len(toolCallDeltas)==0` and
  `finishReason != "tool_calls"`, `parseTextToolCall` parses `reply` as a tool call.
- **On success:** the parsed call is routed through the *same* `OnToolCalls` handoff the
  structured path uses (→ `assembleToolCalls` → scheduler → `ToolDispatcher`), so it inherits
  the identical **auto/ask permission rules for the current mode** with no extra gate — a
  denied parsed call persists the deny envelope exactly as a denied native call does. The
  handoff passes `AssistantText: ""`, so the raw JSON is never committed as assistant text.
  The parser synthesizes a `call_`-prefixed `tool_call_id` because the text form carries none
  and `assembleToolCalls` rejects empty ids.
- **On failure:** the turn falls through unchanged — the content really is plain text.
- **Conservative parse** to avoid hijacking prose: content is treated as a tool call only when
  the *whole* message (after trimming whitespace and at most one code fence) is a single JSON
  object with a non-empty `name` and object-compatible `arguments` (a JSON object, or a
  JSON-encoded string that decodes to an object). A message that merely quotes/mentions tool
  JSON, or carries prose alongside it, is not a tool call.
- Out of scope for now: XML-style or other bespoke tool-call encodings (the same parser seam
  can grow them later); a top-level JSON array of multiple calls is an optional extension.

## LaTeX math notation in plain-text answers (HANDLED)

### What it is
Some models default to LaTeX when they explain mathematics — inline `\(5 \times 2 = 10\)`,
display `\[5 + 10 = 15\]`, and commands like `\frac`, `\sqrt`, `\cdot`. codemeld renders in
a terminal, where those delimiters and commands show up as literal backslash sequences
rather than typeset math: visual noise. Not every model does this, so putting the
instruction in the shared base prompt for every model would pay the prompt-cache/prefix
cost on every request, including models that never emit LaTeX.

### Handling (as built): per-model special instructions
The codebase carries a small library of **per-model special-instruction blocks** — the same
model-keyed approach this doc already uses for other weak-model quirks — applied only to
the models known to need each one:

- **Block library:** `internal/agentinstr/baseprompts/special-instructions.md` holds named
  blocks delimited by an H2 heading (`## latex-math` starts a block; its body runs until the
  next `## ` or EOF). The first block, `latex-math`, tells the model to write math as plain
  text with Unicode symbols (`×`, `÷`, `√`, `≈`, `≠`, …) and to avoid LaTeX delimiters and
  commands.
- **Flag list:** `modelSpecialInstructions` in `internal/agentinstr/special.go` maps a flagged
  model — keyed by provider id + model id — to its ordered block names. The initial entry is
  `openrouter` + `ibm-granite/granite-4.1-8b` → `["latex-math"]`.
- **Assembly:** `AssembleSystemMessage` inserts `SpecialInstructions(provider, modelID)` as a
  top-level section **after** the base prompt and **before** the environment block. An unflagged
  model gets `""` there, so its assembled system message is byte-identical to before — only the
  flagged model's prompt-cache prefix is invalidated, not every model's. The active model is read
  per turn, so a `/model` switch changes the special instructions on the next turn.

To flag another model (or add a different quirk), add a new block to the markdown file and a new
`modelSpecialInstructions` entry; a test (`TestModelSpecialInstructions_BlocksExist`) fails loudly
if a mapped block name does not exist. Keeping the granularity per-block-per-model means a future
quirk affecting a *different* model does not leak onto Granite.

## Reference: where the relevant code lives
- Turn flow / structured tool-call handoff / text-tool-call parse branch / empty-response
  branch / normal commit — `internal/turn/turn.go`.
- Text-format tool-call parser — `internal/turn/texttoolcall.go` (`parseTextToolCall`).
- Empty / truncated classifiers — `internal/provider/transport_errors.go`.
- `model_response` payload + the `anomaly` field — `ModelResponse.Anomaly` in `internal/events/payloads.go`.
- Anomaly population (usage-only) — `internal/model/turn_events.go`.
- Per-model special instructions (LaTeX-math block + flag list) — `internal/agentinstr/special.go`,
  `internal/agentinstr/baseprompts/special-instructions.md`.
