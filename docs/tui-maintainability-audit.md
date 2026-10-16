# TUI Maintainability Audit

**Historical audit — not maintained.** This is a maintainability assessment of `internal/tui`. The
A/B/C findings were first assessed in three slices on 2026-07-27, a refresh labelled 2026-08-05
rechecked them, and the A5 row of the refresh's status table records a later update from
2026-08-11. Everything after the next section is that historical record: its statuses, sizes, line
numbers, and "current" wording describe the tree at those dates, not the code today, and none of it
is authoritative for the present state. The only later corrections are in the next section.

The three slices are labelled by their finding prefixes: **A** — application shell, **B** — picker
and resume surfaces, **C** — permission prompts, dead-code evidence, and verification.

## Status at 2026-10-15 — not part of the historical snapshot

These corrections were checked against the code on 2026-10-15. They update only the findings named
here; every other status below is still the historical one.

| Finding | Status at 2026-10-15 | Evidence in the current code |
|---------|----------------------|------------------------------|
| A4 image-path extraction | **Done** | The image-path attachment functions (`extractImagePathAttachments`, `scanPastedImagePaths`, `attachPastedImagePaths`) live in `internal/tui/app_imagepaths.go`, not `app.go`. |
| B13 shared overlay teardown | **Done** | `closeOverlayPage` in `internal/tui/app.go` removes the page and restores focus; every picker's dismiss function (`picker_file.go`, `picker_model.go`, `picker_effort.go`, `picker_slash.go`, `picker_connect.go`, `picker_settings.go`, `picker_resume.go`, `picker_blocked.go`) calls it. |
| C23 overlay/ESC comment cleanup | **Done, by a different route** | Modal overlays are now registered once, in ESC priority order, by `overlays()` in `internal/tui/overlays.go`. `HandleEsc` in `internal/tui/key_esc.go` and `anyOverlayOpen` in `app.go` both iterate that list, and `dismissOpenOverlay` no longer exists, so the stale flag list and ownership comments the finding named are gone with the code they described. The fix that landed is the overlay registry that the original C23 and B14 findings advised against building. |
| C17 comment cleanup | **Done for production comments only** | `internal/tui/prompt.go`, `prompt_scope.go`, and `prompt_folder.go` no longer contain task or ADR identifiers. Identifiers still appear in comments, test messages, and fixtures in `prompt_test.go`, `prompt_folder_test.go`, and `prompt_scope_test.go`; the test files have not been scrubbed. |

**`ProgramSubject` form.** The refresh found the prompt comments describing `ProgramSubject` as
`<program>:*`, and the original assessment located it in `prompt_scope.go`. Both are out of date.
`ProgramSubject` is defined in `internal/permissions/direct_scope.go` and returns the program, a
space, then `:*` — the stored form is `<program> :*` — and the production prompt comments in
`prompt.go` and `prompt_scope.go` already use that form, so no comment edit is needed. The bare `:*`
wildcard token is recognized in `internal/permissions/normalize_direct.go` by `isBareWildcardToken`
and `matchesDirectScope`; the historical sections now cite these symbols by name rather than by
line number.

**The permissions picker was renamed, not removed.** It is now the settings picker:
`internal/tui/picker_settings.go`, `picker_settings_test.go`, and `cmd_settings.go`, and its symbols
use `settings` where the historical text says `permissions` (for example `dismissSettingsPicker`).
The historical sections cite these files by their current names, but every line number and line
count attached to them is a coordinate in the file as it was then, not a position in the current
file.

## Status

Historical, as of the 2026-08-05 refresh (the A5 row records the 2026-08-11 update).

| Slice | Area | Baseline | Status at the 2026-08-05 refresh |
|-------|------|----------|----------------------------------|
| A | Application shell — `app.go`, `app_test.go`, and direct input/selection/mouse/streaming/indicator/attachment collaborators | Assessed 2026-07-27 | Findings rechecked 2026-08-05; recommended structural cleanups remained pending |
| B | Picker and resume surfaces — `cmd_resume.go`, `picker_file.go`, `picker_model.go` and their tests | Assessed 2026-07-27 | Findings rechecked 2026-08-05; recommended structural cleanups remained pending |
| C | Permission prompts, dead-code evidence, consolidated verification | Assessed 2026-07-27 | Comment/name findings remained present; verification claims below are historical |

**Conclusion at the refresh:** the audit remained valid as a baseline, but it was not a record of
completed refactoring. The tree then still contained most of the actionable findings, including
duplicated picker teardown and model-navigation logic and stale process references in TUI comments.
A5 was the exception: the global key router moved out of `picker_effort.go` on 2026-08-11 into
`internal/tui/key_global.go`. No implementation changes were made by the refresh.

## Snapshot at the 2026-08-05 refresh (historical)

### Production and test sizes at the refresh

| File | Lines | Recheck |
|------|------:|---------|
| `internal/tui/app.go` | 1990 | The shell remains large; `New` and `submitCurrent` are still retained as cohesive sequences. |
| `internal/tui/prompt.go` | 1103 | The prompt overlay and policy/rendering code remain in one file; the chooser construction duplication remains. |
| `internal/tui/picker_model.go` | 979 | The model picker remains the largest picker implementation; no shared navigation helper was found. |
| `internal/tui/app_test.go` | 1139 | No meaningful size reduction from the baseline. |
| `internal/tui/prompt_test.go` | 2452 | The prompt harness exists, but the file remains larger than the baseline. |
| `internal/tui/picker_model_test.go` | 2323 | The previously noted test-route duplication remains in the current file. |
| `internal/tui/cmd_status_test.go` | 1132 | Still outside the original slices and now larger than the old 798-line snapshot. |
| `internal/tui/cmd_clear_test.go` | 771 | Still outside the original slices. |
| `internal/tui/cmd_compact_test.go` | 701 | Still outside the original slices. |
| `internal/tui/launch_layout_test.go` | 792 | Still outside the original slices. |
| `internal/tui/cmd_fork_test.go` | 594 | Still outside the original slices. |
| `internal/tui/cmd_connect_test.go` | 554 | Still outside the original slices. |

### Recommendation status

| Finding group | Status at the refresh | Evidence from the tree at the refresh |
|---------------|----------------|-----------------------------|
| A4 image-path extraction | **Pending** | Image-path attachment functions are still in `internal/tui/app.go`. |
| A5 global-key file move | **Done 2026-08-11** | `handleGlobalKey` now lives in `internal/tui/key_global.go`. |
| A7 mouse-guard simplification | **Pending** | `handleAppMouse` remains in `internal/tui/app_selection.go`; no guard helper was found. |
| A10 transcript helper extraction | **Pending** | The receiverless transcript content helpers remain part of the transcript implementation. |
| A13/A14/B15/B16/C18 test consolidation | **Pending or not demonstrated** | The large test files remain; existing `newAppHarness`/`startPrompt` helpers do not prove that the identified duplicate setup was removed. |
| B1 resume flush helper | **Pending** | No `flushOrSink` helper was found in the current TUI package. |
| B8/B9/B12 model-picker simplification | **Pending** | No shared model-picker key-case or `nextSelectableRow` helper was found. |
| B13 shared overlay teardown | **Pending** | No shared overlay-focus/teardown helper was found; dismissal tails remain in picker files. |
| C10/C11 prompt naming cleanup | **Pending or not demonstrated** | The prompt page literal and the `OmitFolderOption` naming require a current code review before being called fixed. |
| C17 comment cleanup | **Pending** | Prompt comments still contained task and ADR references. |
| C23 overlay/ESC comment cleanup | **Pending** | `anyOverlayOpen` still omits several flags in its prose, and `key_esc.go` still contains the stale permissions ownership wording. |
| C24 deadcode allowlist cleanup | **Not re-run** | The July deadcode result is historical; this refresh did not run the gate. |

### Comment findings at the refresh

The comment rule remains the same: retain comments that explain a non-obvious invariant, safety
boundary, concurrency rule, or workaround; remove comments that restate an obvious function body.
The tree at the refresh still had these high-confidence cleanup classes:

- Trivial `Name` and `SubjectKind` methods in the structured file tools have repetitive comments
  whose content is already clear from the method name and one-line body.
- `internal/tui/prompt_scope.go`, `prompt_folder.go`, `cmd_effort.go`, `cmd_model.go`, and related
  TUI files still contain internal task/ADR identifiers that should be replaced by the invariant,
  if the invariant is still needed.
- The prompt comments then described `ProgramSubject` as `<program>:*`, while the implementation
  returned `<program> :*`. Since corrected: see the 2026-10-15 status section.
- `internal/tui/app.go`'s `anyOverlayOpen` prose still does not enumerate all of its modal flags, even
  though the implementation includes the secret, slash, connect, permissions, and question-form
  overlays.

### Refresh method

This refresh checked current line counts, symbol locations, helper names, overlay flags, prompt
comments, and the existence of the proposed extraction/consolidation helpers. It did not modify
production code, did not run the dead-code gate, and did not rerun the historical 2026-07-27 test
verification. The detailed slice sections remain useful for rationale and behavior constraints, but
their line-number citations should be treated as baseline evidence rather than current coordinates.

**Report status at the refresh: refreshed baseline, actionable findings still open.**

## Scope

In scope for slice A:

- `internal/tui/app.go` (1976 lines) and `internal/tui/app_test.go` (1139 lines).
- The collaborators the application shell exercises directly: `internal/tui/app_selection.go`,
  `internal/tui/app_indicator.go`, `internal/tui/app_replay.go`, `internal/tui/input.go`,
  `internal/tui/transcript.go`, `internal/tui/transcript_selection.go`, and the global key router,
  hosted in `internal/tui/picker_effort.go` when this slice was assessed and moved to
  `internal/tui/key_global.go` on 2026-08-11.
- Their behaviour-pinning tests, chiefly `internal/tui/app_test.go`,
  `internal/tui/stream_surface_test.go`, `internal/tui/input_test.go`,
  `internal/tui/transcript_selection_test.go`, and the shared helpers in
  `internal/tui/harness_test.go`.
- Production construction and consumption context: `internal/bootstrap/starttui.go` builds the
  `App`; `internal/bootstrap/turndeps.go` and `internal/bootstrap/connectdeps.go` consume the
  background turn surface.

Out of scope for this slice: the picker overlays other than the key router that happens to live in
`picker_effort.go` (slice B), the permission prompt surface (slice C), and any code change at all — this
audit classifies, it does not refactor.

## Method

1. **Read before judging.** Every finding below was derived by reading the named file and, where
   the claim is about reachability, by grepping for callers across `internal/`.
2. **Cite a caller, an invariant, or a test.** A candidate with no concrete caller, no stated
   invariant, and no test seam is recorded as *rejected*, not as a refactor idea. Length alone is
   never evidence: `app.go` is long because the application shell owns the widget graph, the
   event-loop entry points, and ~20 injected seams — none of which shrink by moving lines to
   another file.
3. **Classify, then state what must survive.** Every recommendation names the ownership or
   invariant a future implementer must preserve, so the recommendation can be triaged without
   re-deriving the analysis.
4. **Prefer rejection under uncertainty.** Where the safety argument is unresolved (timer
   invalidation ordering, lock discipline, token ranges), the candidate is retained or deferred.

### Classification vocabulary

| Class | Meaning |
|-------|---------|
| **retain** | The complexity is load-bearing. No change recommended; the entry records *why*, so the candidate is not re-raised. |
| **simplify locally** | A change confined to one function or file, with no ownership move. |
| **extract** | Move a cohesive cluster (fields + methods used only together) to its own file/type, behaviour unchanged. |
| **consolidate test setup** | Share arrange/teardown between tests without touching a single assertion. |
| **defer** | Real candidate, but the evidence needed to size it belongs to a later slice or a separate investigation. |

## Application shell (slice A)

*Historical — from the 2026-07-27 assessment and its 2026-08-05 review notes; statuses and line
numbers are from those dates, not current.*

### Inventory

| Unit | Location | Size | Shape |
|------|----------|------|-------|
| `App` struct | `internal/tui/app.go:169-484` | 96 fields | 12 widget handles, 33 overlay open/prev/session fields, ~16 injected seams, 3 sync primitives, 12 indicator fields, 13 selection/mouse fields, 7 misc flags |
| `New` | `internal/tui/app.go:489-676` | 188 lines | Theme, struct literal, panel/status overlays, indicator, footer rows, root flex, before-draw closure (`:582-606`), five capture/hook installs |
| `submitCurrent` | `internal/tui/app.go:1009-1081` | 73 lines | One acceptance sequence: expand → extract typed image paths → reject → history → notice → dispatch → echo → clear |
| `streamUpdate` | `internal/tui/app.go:1800-1806` | 6 lines | The single off-loop/on-loop decision point |
| `handleAppMouse` | `internal/tui/app_selection.go:47-218` | 172 lines | One four-case switch, ~15 return points |
| `renderLocked` | `internal/tui/transcript.go:448-490` | 43 lines | Sole lock-held renderer; 12 lock-taking callers inside `transcript.go` |
| `reconcileSegments` | `internal/tui/input.go:266-296` | 31 lines | Single-pass repin of paste + image ranges |
| `handleGlobalKey` | `internal/tui/picker_effort.go:27-184` | 158 lines | Top-level key router, 12 bindings |

Test scale for context: `internal/tui` holds 56 `*_test.go` files and 752 top-level `Test*`
functions. `app_test.go` (35) and `stream_surface_test.go` (29) contribute 64 of them.

### Ownership boundaries

These are the boundaries any recommendation in this slice must not disturb. Each is stated with the
symbol that owns it.

**Event loop and queue.** `streamUpdate` (`app.go:1800-1806`) is the only place that decides between
`QueueUpdateDraw` and a direct call, keyed on the `running atomic.Bool` (`app.go:416`, set/cleared in
`Run` at `app.go:997-998`). The direct-call branch is not an optimisation: before `Run`, the tview
queue is never drained, so a queued mutation would block forever — unit tests and pre-`Run` wiring
depend on the direct path. Ten exported background entry points route through it
(`NoticeFromBackground` `:1554`, `RunBackgroundAfterDraw` `:1557`, `CommitProviderError` `:1588`,
`AppendStreamDelta` `:1661`, `MarkStreamInterrupted` `:1673`, `FinalizeStream` `:1709`,
`AppendToolActivity` `:1726`, `RollbackPartial` `:1738`, `CommitRetryRecovered` `:1745`,
`SuggestFollowup` `:1761`), as do `app_replay.go:217`, six sites in `app_indicator.go`, and the two
drag-scroll ticks in `app_selection.go:259,303`. The only raw `QueueUpdateDraw` calls in `app.go`
are `:950` (`queueModalFocusRestore`), `:1574` (`RunOnEventLoopForTest`), and `:1802` inside
`streamUpdate` itself. Pinned by `TestAppStreamSurface_OffLoopMarshalsThroughQueue`
(`stream_surface_test.go:484-509`) and its three siblings at `:511`, `:602`, `:715`, which are
`-race` detectors: they observe ordering and race-freedom, not the queue directly.

**Timers.** There is no `time.Timer` handle anywhere in the shell to stop. The single seam is
`afterFunc` (`app.go:433`, defaulted at `app.go:503` to a `time.AfterFunc` whose return value is
discarded). Every cancellation is therefore a **generation counter compared inside the callback**:
`inputScrollGen` (`app.go:462`), `transcriptScrollGen` (`app.go:482`), `indicatorGen`
(`app.go:203`), `ctrlCHintGen` (`app.go:427`). The drag-scroll ticks reschedule *unconditionally*
(`app_selection.go:272`, `:313`), so the guard at `:260-262` / `:304-306` is the only thing that
ends the chain. The bump ordering is load-bearing: `handleAppMouse` bumps `transcriptScrollGen`
*after* `beginSelect` (`:131` then `:133`) and *after* `updateTranscriptSelection` on release
(`:145` then `:147`, with `endSelect` at `:149`). Reversing either pair either kills a live
auto-scroll or lets a re-armed tick outlive the drag. Only `app_indicator.go:203` uses a real
ticker, with `defer t.Stop()` at `:204`, a `stop` channel, *and* the `indicatorGen` check at `:222`.

**Locks.** Three mutexes plus one atomic guard the shell: `indicatorMu` (`app.go:187`) covering the
12 indicator fields, `activeMu` (`app.go:392`) covering `activeStore`, and `transcript.mu`
(`transcript.go:27`). The transcript's convention is that all 18 methods take `mu` except
`renderLocked` (`transcript.go:448`), which requires it held, and `scrollPage`
(`transcript.go:531`), which delegates. The `*Locked` suffix marks exactly one of the three
lock-contract methods: `offsetAt` (`transcript_selection.go:138`, lock required) and
`scrollDragScroll` (`transcript_selection.go:259`, lock *forbidden* — it calls `scrollBy`, which
locks) carry their contract only in prose.

**Widget graph.** `New` installs `SetBeforeDrawFunc`, `SetRoot`, `SetInputCapture`,
`SetMouseCapture`, `SetChangedFunc`, and `SetPasteFunc` against a single shared `root`/`pages`
graph. `App` is the composition root for that graph; nothing else may own it.

**Token ranges.** `reconcileSegments` (`input.go:266-296`) repins collapsed-paste and image-token
ranges against `prevText` (`input.go:72`) in **one pass** so the two segment kinds can never
desynchronise under an edit. Ranges are byte offsets; exactly one accessor converts to runes
(`Cursor`, `input.go:648-655`). `submitText` (`input.go:599-622`) applies its splices in descending
start order (`input.go:617-620`) so earlier ranges stay valid.

### Findings

Each finding is `ID — classification`. Recommendations are consolidated in the table below.

**A1 — retain. Splitting `App` by size.** `App` is 96 fields and `app.go` is 1976 lines, but the
fields already cluster by concern and the three largest clusters already live in their own files:
the 12 indicator fields are referenced only from `app_indicator.go` (plus `IndicatorVisible()` reads
at `app.go:780,799`), and the 13 selection fields only from `app_selection.go` (plus one read in the
before-draw closure at `app.go:601`). Moving the *struct* would not move the coupling: `New`
(`app.go:489-676`) must still install every capture against one `root`/`pages` graph, and every
extracted type would need a back-reference to `a.app` for `QueueUpdateDraw` and `SetFocus`.
Rejected — line count is not evidence of a cohesion problem here.

**A2 — retain. `streamUpdate` and its ten one-line wrappers.** The wrappers at `app.go:1554`,
`:1588`, `:1661`, `:1673`, `:1709`, `:1738`, `:1745` (plus `app_replay.go:217`) share an identical
shape, which reads as duplication. They are not: each is a distinct exported entry point in the
background turn surface consumed by `internal/bootstrap/turndeps.go`, and the body is already one
line. A generic wrapper would remove nothing and would obscure the one thing a reader needs to
check — that a background caller went through the queue. Rejected.

**A3 — retain. `submitCurrent`'s 73 lines.** The length is one acceptance sequence with four
inline responsibilities (image extraction, history append, notice/echo suppression, dispatch), not
mixed concerns. Every step is load-bearing and separately pinned: rejection before dispatch
(`app.go:1027-1031`, `TestSubmitCurrent_BlocksConcreteImagePathRejections`, `app_test.go:326-403`,
five cases), image-only acceptance with empty text (`app.go:1042`,
`TestSubmitCurrent_ImageOnlyAccepted`, `:71-90`), buffer retention on rejection (`app.go:1065`,
`TestSubmitCurrent_RejectRetainsAttachments`, `:153-170`), and the notice-clear-*before*-dispatch
ordering (`app.go:1058` before `:1062`, `TestSubmitCurrent_ClearBeforeDispatchLetsHandlerSetFreshNotice`,
`:745-762`). Extracting any step changes the ordering that these tests exist to pin. Rejected.

**A4 — extract. The image-path attachment cluster in `app.go`.** `handleClipboardImage`
(`:1097-1133`), `extractImagePathAttachments` (`:1150-1182`), `scanPastedImagePaths`
(`:1201-1227`), `attachPastedImagePaths` (`:1243-1271`), `isConcreteImageRejection` (`:1235`),
`isInputSpace` (`:1276`), `refProjectRoot` (`:1287`), and the types `imagePathRejection` (`:1138`)
and `pastedImagePath` (`:1189`) form a closed cluster: the only `App` state they touch is `home`
(`:328`), `clipboard` (`:373`), `statusLineState` (`:224`, read-only) and `Notice`. They own no
widget, no lock, no timer, and no queue decision. Two of them also carry the one genuine duplicate
in this area — the whitespace tokenizer at `:1158-1180` is the same scan as `:1208-1225`, differing
only in whether positions are retained. Moving the cluster to `app_imagepaths.go` is a pure file
move and would make the shared tokenizer visible enough to be worth unifying afterwards. Behaviour
that must survive: `submitCurrent` calls `extractImagePathAttachments` *after* the leading-`/` check
(`app.go:1021` then `:1027`), so slash commands stay text-only
(`TestSubmitCurrent_SlashCommandKeepsImagePathArg`, `app_test.go:431-450`); token attachments are
ordered before typed ones (`app.go:1032-1038`,
`TestSubmitCurrent_TokenPartsInBufferOrder`, `:95-121`); and unresolved paths stay prose
(`TestSubmitCurrent_LeavesUnresolvedImagePathAsText`, `:408-426`).

**A5 — extract (file move only). `handleGlobalKey` lives in `picker_effort.go`.** The app's entire
top-level key router is `picker_effort.go:27-184` — 47% of that file — yet exactly **one** of its 12
bindings concerns the effort picker (CTRL-E, `:109-111`). The other eleven route page/line scroll
(`:66-94`), Escape (`:95-108`), CTRL-M (`:112-116`), CTRL-R (`:117-129`), CTRL-V (`:130-142`),
CTRL-Y (`:143-149`), Backtab (`:150-156`), CTRL-C (`:157-169`), CTRL-D (`:170-181`), and the CTRL-L
early return (`:32-35`). The per-key handlers it dispatches to already follow a `key_*.go`
convention (`key_ctrll.go:11`, `key_esc.go:23`, `key_ctrlc.go:36`, `key_ctrld.go:18`), and
`key_esc.go:32` has to back-reference "handleGlobalKey (picker_effort.go)" in prose precisely
because the location is unguessable. It has exactly one production registration
(`app.go:621`, `SetInputCapture`) and is re-entered by three documented test seams
(`app.go:1857`, `:1868`, `:1887`) plus 14 test files. Renaming the file to `key_global.go` (or
moving the function into it) is a discoverability fix with no behaviour surface at all.

**A6 — retain. The twin drag-scroll timers.** `scheduleInputDragScroll`/`inputDragScrollTick`
(`app_selection.go:248-274`) and `scheduleTranscriptDragScroll`/`transcriptDragScrollTick`
(`:292-315`) are near-verbatim twins, and the transcript comment at `:311-312` says so. They are
retained anyway. The two panes keep their state in different structs — the input's anchor, position,
and `selecting` flag are all `App` fields (`app.go:459-463`), while the transcript's anchor and range
live behind `transcript.mu` (`transcript.go:69-72`) with only the position mirror and generation
counter on `App` (`app.go:481-483`). Unifying them needs an interface over that asymmetry, and the
generation-bump ordering described under *Timers* above is load-bearing on the transcript side
because the bumps are inlined in `handleAppMouse` (`:133-134`, `:147-148`) rather than encapsulated
the way `beginInputSelection` (`:225-226`) and `finishInputSelection` (`:243-245`) encapsulate the
input side. The behaviour at risk is pinned by
`TestInputSelection_RunningAppDragScrollTimerContinuesWithoutMouseMove`
(`transcript_selection_test.go:536`), `TestInputSelection_HoldAtBoxBottomScrollsDown` (`:740`), and
`TestTranscriptSelection_DragScrollsPastVisibleRows` (`:382`). Per `docs/tui-mouse-debugging.md`,
the `SimulationScreen` tests inject jitter-free events and can stay green while a real terminal
fails, so they are not sufficient cover for a rewrite of this pair. Rejected as a refactor;
recorded as a genuine duplicate that stays.

**A7 — simplify locally. The repeated guard prelude in `handleAppMouse`.** The three-line sequence
`if a.statusOpen { SetFocus(a.status); return nil, action }` followed by
`if a.anyOverlayOpen() { return event, action }` appears three times (`app_selection.go:94-103`,
`:167-174`, `:202-209`), as does `x, y := event.Position(); if a.inInputRect(x, y)` (`:104-105`,
`:175-176`, `:210-211`). This is confined to one function and involves no ownership move. The risk
is that the guards are *not* uniform — `MouseMove` (`:63-89`) deliberately has no such prelude, and
the Shift-outside-input branch at `:123-125` deliberately passes through without calling
`beginSelect`. A helper must therefore be opt-in per case, not hoisted above the switch. Coverage:
`TestHandleAppMouse_FocusGuards` (`transcript_scroll_test.go:217`),
`TestHandleAppMouse_AboveInputClickKeepsFocus` (`:192`),
`TestAppMouse_SpacerRowClickKeepsFocus_ThroughRealLayout` (`:256`),
`TestPromptOverlay_MouseKeepsOptionListFocused` (`prompt_test.go:872`). Note the gap: no test names
the `statusOpen` swallow specifically.

**A8 — retain. `renderLocked`'s selection invalidation, and the `wrappedLineCount` re-wrap.**
`renderLocked` (`transcript.go:448-490`) clears `selecting`/`selAnchor`/`selStart`/`selEnd` at
`:453-454` because those are byte offsets into the previous displayed text. A candidate concern is
that `wrappedLineCount` (`transcript.go:548-560`) also calls `t.view.SetText` at `:556` without
going through `renderLocked`, apparently skipping that invalidation. Examined and **rejected**: the
`:556` call passes `t.view.GetText(false)` — the same text — purely to force a re-wrap at a new
width, so the byte offsets the selection holds remain valid and `drawSelectionHighlight`
(`transcript_selection.go:292-353`) recomputes screen cells from them on each draw. The two
`SetText` calls have different contracts and correctly behave differently. Recorded here so the
apparent inconsistency is not re-raised.

**A9 — retain. `reconcileSegments`' twin loops; add a focused test instead.** The paste loop
(`input.go:279-286`) and image loop (`:288-295`) are byte-for-byte identical apart from the slice.
Merging them is the wrong move: the doc comment at `:258-265` states the invariant that both kinds
are repinned "in one pass so the two segment kinds' ranges can never desynchronize under an edit",
and both already delegate the actual arithmetic to the shared `shiftPinnedRange` (`:307-340`). The
residual duplication is six lines of slice bookkeeping. What is genuinely missing is direct
coverage: no test names `reconcileSegments` (its only caller is the `SetChangedFunc` wrapper at
`input.go:428`), and the ambiguous-duplicate-placeholder `default:` drop branch at `input.go:322` is
reached only transitively through `pasteInto`. That is a test-coverage finding, not a refactor.

**A10 — extract. Receiverless content-part helpers in `transcript.go`.** `userBlockLines`,
`userRailLines`, `contentPartBlock`, `textPartContent`, `imagePlaceholder`, `dataURIByteLen`,
`base64ByteLen`, and `humanBytes` occupy `transcript.go:92-210` — roughly 119 of the file's 560
lines — and none has a `transcript` receiver or touches transcript state. They decode content parts
and format byte sizes. Their tests already live apart, in
`transcript_replay_test.go`. Moving them to their own file leaves `transcript.go` as the
lock-and-render type it claims to be. Behaviour to preserve: `userBlockLines` is called from
`submitCurrent` (`app.go:1077`) and its exact rail markup is asserted verbatim
(`TestSubmitCurrent_AcceptEchoesPromptToTranscript`, `app_test.go:506-523`, which pins
`[#1f9e8f]▌[-]`), and the `[image: diagram.png (2 KB)]` placeholder form is pinned by
`TestSubmitCurrent_AttachmentReachesHookEchoedAndCleared` (`app_test.go:41-69`).

**A11 — defer to slice B. The overlay open/prev triads.** Ten near-identical
`xOpen bool` / `xPrev tview.Primitive` / `xSession *T` triads occupy `app.go:236-348`, and each new
overlay requires three coordinated edits: the struct, the 12-term OR in `anyOverlayOpen`
(`app.go:939`), and the dispatch chain in `dismissOpenOverlay` (`key_esc.go:91-130`). This is the
largest single field group in `App` and a real consolidation candidate. It is deferred rather than
recommended here because every one of the ten overlays is a picker or prompt owned by slices B and C;
sizing the change without that slice's evidence would be guessing. Coverage that constrains it:
`TestOverlayOpen_GlobalShortcutsAreNoOps` (`overlay_keys_test.go:106`),
`TestOverlayOpen_EscDelegatesToCentralDismissal` (`:326`), and the delegation tests at `:361`,
`:384`, `:419`.

**A12 — defer to slice C. Test-only exported surface.** Eighteen exported `App` methods have zero
production callers and exist as cross-package seams for `internal/bootstrap/*_test.go` — including
`SubmitInput` (`app.go:1829`), `SeedInput` (`:1840`), `PressCtrlE` (`:1856`), `PressCtrlV`
(`:1886`), `SubmitCurrent` (`:1896`), `TranscriptText` (`:1960`), `NoticeText` (`:1967`),
`RunOnEventLoopForTest` (`:1573`). Each documents itself as never called at runtime. Similarly
`indicatorStopped` (`app.go:210`) is production-write-only, read only by `indicator_test.go:252`,
and its declaration comment says exactly that. These are documented deliberate seams, not dead
code — but the dead-code sweep is slice C's, so the pointer is recorded rather than judged here. One
boundary leak worth flagging to that slice: `NoticeText` reaches through the transcript's
encapsulation and takes `a.transcript.mu` directly at `app.go:1968-1970` instead of calling a
transcript method.

**A13 — consolidate test setup. `app_test.go` has no construction fixture.** All 35 tests in
`app_test.go` hand-roll `New(...)` (call sites at `:44, 74, 98, 128, 156, 178, 205, 245, 295, 381,
411, 434, 455, 476, 492, 508, 527, 544, 557, 572, 589, 615, 638, 663, 681, 694, 717, 746, 770, 849,
916, 948, 979, 1009, 1028`), in three recurring shapes: a bare recording-parts app (13 sites), the
same plus project root and home (7 sites, e.g. `:176-182`, `:203-209`, `:243-249`, `:293-298`), and
a recording app plus `SetText` (12 sites). That is roughly 115 lines of repeated arrange. A shared
harness already exists — `newAppHarness` (`harness_test.go:31-51`) — but only three test files use
it, and `app_test.go` reimplements its exact afterDraw + `SimulationScreen` + `go Run()` +
`Stop`/`<-errc` sequence at `:768-826` and `:839-905` in a different idiom. Consolidation must not
touch a single assertion: the accept/reject pairs
(`TestSubmitCurrent_AcceptClearsField` `:474` / `_RejectRetainsField` `:490`,
`_AcceptEchoesPromptToTranscript` `:506` / `_RejectDoesNotEchoPrompt` `:525`) are meaningful only as
pairs, and the setup differences between them are part of what each pins.

**A14 — consolidate test setup. The four off-loop tests in `stream_surface_test.go`.**
`TestAppStreamSurface_OffLoopMarshalsThroughQueue` (`:484-509`) and its siblings at `:511-532`,
`:602-622`, and `:715-736` repeat the same six-line arrange (`New` + `SimulationScreen` + the
`newScreen` seam at `app.go:445` + `errc` + `go a.Run()` + `waitLoopRunning`) and the same four-line
teardown — about 40 duplicated lines. A local running-app helper would remove it. Three elements
must survive verbatim: the `newScreen` injection (without it the test opens a real terminal), the
`waitLoopRunning` barrier (`:741-754`, which is what proves the subsequent calls are genuinely
off-loop *while the loop is live*), and the `transcriptText` read through `QueueUpdate` (`:760-765`,
which serialises the assertion onto the loop goroutine). These tests assert marshaling *indirectly*
— through ordered content plus race-freedom under `-race` — so a helper that changes when the loop
starts would silently void them.

**A15 — retain. "Weak" tests that look like removal candidates.**
`TestStreamCanceller_DefaultInert` (`stream_surface_test.go:226-231`) is three statements asserting
a nil field, and `TestSubmitCurrent_NilHookIsNoOp` (`app_test.go:571-581`) is a nil-guard smoke
test. Both are retained: the nil-seam contract is real production behaviour (`app.go:1042` returns
false on `a.submit == nil`, and the same "injected seam may be nil" idiom recurs at `:854`, `:889`,
`:1098`, `:1633`), and `internal/bootstrap` constructs the `App` before installing several of those
seams. Likewise `TestAppStreamSurface_DelegatesToTranscript` (`:255-281`) duplicates transcript-level
assertions but pins the *delegation*, which is the layer the background surface depends on.
Rejected as removal candidates.

### Recommendations (slice A)

| ID | Class | Affected files and symbols | Evidence | Expected benefit | Risk | Preserved behaviour | Non-goals | Follow-up task justified? |
|----|-------|----------------------------|----------|------------------|------|---------------------|-----------|---------------------------|
| A5 | extract (file move) | `internal/tui/picker_effort.go:27-184` `handleGlobalKey`; registration `internal/tui/app.go:621`; prose back-reference `internal/tui/key_esc.go:32` | 1 of 12 bindings is effort-related; sibling handlers already use `key_*.go` (`key_ctrll.go:11`, `key_esc.go:23`, `key_ctrlc.go:36`, `key_ctrld.go:18`) | The top-level key router becomes findable by name; removes the prose cross-reference | Very low — file move, no call graph change | Binding order inside the switch, the pre-switch side effects at `:28-64`, and the deliberate resume-picker pass-throughs at `:117-129`, `:170-181` | Do not re-order bindings, merge per-key handlers, or change which keys are consumed vs passed through | **Yes** — small, isolated, purely a discoverability win |
| A4 | extract | `internal/tui/app.go` `handleClipboardImage:1097`, `extractImagePathAttachments:1150`, `scanPastedImagePaths:1201`, `attachPastedImagePaths:1243`, `isConcreteImageRejection:1235`, `isInputSpace:1276`, `refProjectRoot:1287`, types `imagePathRejection:1138`, `pastedImagePath:1189` | Closed cluster: touches only `home:328`, `clipboard:373`, `statusLineState:224`, `Notice`. Duplicate tokenizer at `:1158-1180` vs `:1208-1225` | ~180 lines out of `app.go`; makes the duplicated tokenizer unifiable | Low — no widget, lock, timer, or queue ownership moves | Slash-command text-only path (`app.go:1021` before `:1027`); token-then-typed part order (`:1032-1038`); rejection before dispatch leaves the buffer intact | Do not change what counts as a concrete rejection, do not tokenize typed paths, do not merge the two attachment pipelines | **Yes** — cohesive and independently testable via `app_test.go:175-450` |
| A10 | extract | `internal/tui/transcript.go:92-210` `userBlockLines`, `userRailLines`, `contentPartBlock`, `textPartContent`, `imagePlaceholder`, `dataURIByteLen`, `base64ByteLen`, `humanBytes` | Receiverless, no transcript state, ~119 of 560 lines; tests already separate in `transcript_replay_test.go` | `transcript.go` reduces to the locked render/scroll type | Low — pure functions | Exact rail markup `[#1f9e8f]▌[-]` (`app_test.go:506-523`) and the `[image: name (size)]` placeholder form (`app_test.go:41-69`) | Do not alter any rendered string; do not fold these into the `transcript` type | **Yes** — mechanical, high clarity gain |
| A13 | consolidate test setup | `internal/tui/app_test.go` (35 inline `New(...)` sites); existing `newAppHarness` `internal/tui/harness_test.go:31-51` | Three repeated arrange shapes totalling ~115 lines; `app_test.go:768-826` and `:839-905` reimplement the harness sequence | Removes ~115 duplicated lines and one duplicated event-loop idiom | Medium — a shared fixture can mask a setup difference a test depends on | Every `TestSubmitCurrent_*` assertion, especially the accept/reject pairs at `:474/:490` and `:506/:525` and the five-case rejection matrix at `:326-403` | Do not merge, delete, or weaken any assertion; do not collapse accept/reject pairs into table cases that lose the pairing | **Yes**, if scoped to arrange-only with a diff that touches no assertion line |
| A14 | consolidate test setup | `internal/tui/stream_surface_test.go:484-509`, `:511-532`, `:602-622`, `:715-736`; helpers `waitLoopRunning:741`, `transcriptText:760`; seam `internal/tui/app.go:445` `newScreen` | Same 6-line arrange and 4-line teardown repeated four times (~40 lines) | Removes ~40 lines; one place to keep the off-loop idiom correct | Medium — these are `-race` detectors asserting indirectly | The `newScreen` injection, the `waitLoopRunning` barrier before the off-loop calls, the `QueueUpdate`-wrapped assertion read, and clean `Stop`/`<-errc` shutdown | Do not replace `waitLoopRunning` with a sleep; do not read the transcript off-loop; do not drop the shutdown assertion | **Yes**, bundled with A13 |
| A7 | simplify locally | `internal/tui/app_selection.go` `handleAppMouse:47-218` — preludes at `:94-103`, `:167-174`, `:202-209`; rect tests at `:104-105`, `:175-176`, `:210-211` | Three verbatim repetitions inside one 172-line function | Shortens the largest selection function; one place for the focus-shield rule | Medium — the guards are deliberately non-uniform (`MouseMove` `:63-89` has none; Shift-outside-input `:123-125` passes through) | Which mouse actions consume vs pass through the event, and the synthetic drag-end event at `:190-195` that ends TextArea's native drag | Do not hoist guards above the switch; do not unify `MouseMove` with the click cases; do not touch generation-counter bumps at `:133-134`, `:147-148` | Optional — only alongside a real-terminal check per `docs/tui-mouse-debugging.md`; the `SimulationScreen` tests alone are not sufficient cover |
| A9 | test coverage | `internal/tui/input.go` `reconcileSegments:266-296`, `shiftPinnedRange:307-340` (drop branch at `:322`); sole caller `input.go:428` | No test names `reconcileSegments`; the ambiguous-duplicate `default:` drop is reached only transitively | Directly pins the token-range invariant instead of inferring it from paste behaviour | Low — additive test only | The one-pass repin of pastes and images together; byte-offset semantics; the `prevText` diff basis | Do not merge the two loops; do not change drop semantics to make a test easier | **Yes** — small additive test task |
| A1 | retain | `internal/tui/app.go:169-484` `App`; `New:489-676` | Indicator and selection clusters already isolated in `app_indicator.go` / `app_selection.go`; every extraction still needs `a.app` for queue and focus | None — the field count reflects real owned concerns, so a split relocates lines without reducing coupling | A split would add back-references to `a.app` in every new type and re-open the capture-install ordering in `New` | Composition-root ownership of `root`/`pages` and all captures installed in `New` | Do not split `App` on line count | No |
| A2 | retain | `internal/tui/app.go` `streamUpdate:1800-1806` and wrappers `:1554, :1588, :1661, :1673, :1709, :1738, :1745`, `app_replay.go:217` | Bodies are already one line; each is a distinct background entry point used by `internal/bootstrap/turndeps.go` | None — bodies are already minimal and the repetition is the readable proof that each background caller queues | A generic wrapper would hide the queue hop that reviewers check for, and could reintroduce a direct off-loop mutation | `running.Load()` branch: queue while live, direct call pre-`Run` (the queue is undrained before `Run`) | Do not introduce a generic wrapper or a background-surface interface | No |
| A3 | retain | `internal/tui/app.go` `submitCurrent:1009-1081` | Each step separately pinned in `app_test.go:41-762`; notice-clear precedes dispatch by design (`:1058` before `:1062`) | None — the length is one ordered sequence, not mixed concerns | Helper extraction invites step re-ordering, which silently breaks rejection-before-dispatch and clear-before-dispatch | Rejection-before-dispatch, image-only acceptance, buffer retention on reject, clear-before-dispatch ordering | Do not extract steps into helpers that could re-order them | No |
| A6 | retain | `internal/tui/app_selection.go:248-274` vs `:292-315`; counters `app.go:462`, `:482`; seam `afterFunc app.go:433,503` | Pane state is split across `App` and `transcript`; gen bumps for the transcript are inlined at `:133-134`, `:147-148`; ticks reschedule unconditionally at `:272`, `:313` | Roughly 40 lines, which does not pay for the risk below | An interface over two panes whose state lives in different structs would move the gen bumps; `SimulationScreen` tests inject jitter-free events and can stay green while a real terminal fails | Generation-counter invalidation and its bump ordering relative to `beginSelect`/`endSelect`; no timer handle exists to stop | Do not unify the two timers behind an interface; do not move the gen bumps | No — revisit only with real-terminal evidence |
| A8 | retain | `internal/tui/transcript.go` `renderLocked:448-490` (invalidation `:453-454`), `wrappedLineCount:548-560` (`SetText` at `:556`) | The `:556` call re-sets identical text for re-wrap, so selection byte offsets stay valid; highlights recompute in `transcript_selection.go:292-353` | None — the two `SetText` calls have different contracts and correctly differ | Routing `wrappedLineCount` through `renderLocked` would drop a live selection on every terminal resize | Selection invalidation on content change; survival of a completed selection across wheel/keyboard scroll (`scrollBy`/`scrollPage` do not render) | Do not route `wrappedLineCount` through `renderLocked` | No |
| A15 | retain | `internal/tui/stream_surface_test.go:226-231`, `:255-281`; `internal/tui/app_test.go:571-581` | Nil-seam behaviour is real (`app.go:1042`, and the same idiom at `:854`, `:889`, `:1098`, `:1633`); `internal/bootstrap` builds the `App` before installing seams | None — the line saving is trivial | Deleting them removes the only coverage of the nil-seam contract that `internal/bootstrap` construction depends on | Nil-seam no-op contracts and the transcript delegation layer | Do not delete tests for being short | No |
| A11 | defer to slice B | `internal/tui/app.go:236-348` overlay triads; `anyOverlayOpen:939`; `internal/tui/key_esc.go:91-130` `dismissOpenOverlay` | Ten triads; adding an overlay needs three coordinated edits | Would shrink the largest field group in `App` | Not yet sized — every overlay is picker/prompt owned | Overlay dismissal priority order and per-overlay key delegation (`overlay_keys_test.go:106, 326, 361, 384, 419`) | Do not size or attempt this before the picker slice | Decide in slice B |
| A12 | defer to slice C | 18 test-only exported `App` methods (`app.go:1573, 1829, 1840, 1856, 1867, 1886, 1896, 1908, 1960, 1967`, …); `indicatorStopped app.go:210`; `NoticeText app.go:1968-1970` | Zero production callers, each self-documented as a test seam; `NoticeText` takes `transcript.mu` directly | Would clarify the public surface | Removing a seam breaks `internal/bootstrap/*_test.go` | Cross-package test reachability for `internal/bootstrap` | Do not judge these as dead code in this slice | Decide in slice C |

## Picker and resume surfaces (slice B)

*Historical — from the 2026-07-27 assessment and its 2026-08-05 review notes; statuses and line
numbers are from those dates, not current.*

### Scope

In scope for this slice:

- `internal/tui/cmd_resume.go` (548 lines) with `internal/tui/cmd_resume_test.go` (1280 lines).
- `internal/tui/picker_file.go` (436 lines) with `internal/tui/picker_file_test.go` (1474 lines).
- `internal/tui/picker_model.go` (974 lines) with `internal/tui/picker_model_test.go` (2153 lines).
- The direct production collaborators those three exercise: `internal/tui/picker_resume.go` (the
  `ResumePicker` implementation the resume handler drives), the global key router in
  `internal/tui/picker_effort.go`, and the ESC dismissal chain in `internal/tui/key_esc.go`.
- Production construction and registration context, cited as caller evidence and not modified:
  `internal/bootstrap/resumedeps.go` builds `ResumeDeps`; `internal/bootstrap/starttui.go:181,264`
  registers `NewResumeHandler`; `internal/bootstrap/provider_refresh.go` owns the goroutine behind
  the model picker's catalog refresh.

Out of scope: the permission prompt surface and the dead-code sweep (slice C), the other picker
overlays except where they are evidence for a cross-picker claim (`picker_slash.go`,
`picker_connect.go`, `picker_settings.go`, `picker_effort.go`'s effort half), and any code change
at all.

### Inventory

| Unit | Location | Size | Shape |
|------|----------|------|-------|
| `ResumeDeps` | `cmd_resume.go:182-212` | 15 fields | 14 injected capabilities + `FlushCtx`; 12 wired by the test fixture |
| `NewResumeHandler` | `cmd_resume.go:239-316` | 78 lines | Pre-picker steps (list → skipped notices → success record → flush) then a continuation |
| `runResumeSwitch` | `cmd_resume.go:335-485` | 151 lines | One ordered transaction, 5 early-return branches, 4 flush-and-sink blocks |
| `filePickerSession` | `picker_file.go:36-46` | 9 fields | Owns a goroutine, a `context.CancelFunc`, and a `uint64` generation |
| `modelPickerSession` | `picker_model.go:46-60` | 13 fields | Owns row mapping, a filter query, and a two-field refresh-ownership token |
| `resumePickerSession` | `picker_resume.go:57-64` | 6 fields | No async work; one-shot `fired` guard |
| `populateModelTable` | `picker_model.go:273-323` | 51 lines | Pure; 3 callers (`:180`, `:401`, `:447`) |
| `handleGlobalKey` resume/model escapes | `picker_effort.go:95-107`, `:117-119`, `:170-172` | 3 blocks | Picker-specific branches inside the global router |

Test scale for context: the picker surface is 2,992 production lines against 5,769 test lines across
seven `picker_*_test.go` files. `picker_model_test.go` holds 59 top-level tests,
`picker_file_test.go` 28, `cmd_resume_test.go` 21.

### Ownership boundaries

These are the boundaries any recommendation in this slice must not disturb.

**Resume durable ordering.** `runResumeSwitch` (`cmd_resume.go:335-485`) is one transaction whose
*ordering* is the contract, not an implementation detail. Classification comes first
(`Loader.Load`, `:343`) so the two branches that do not switch away — load failure (`:344-360`) and
older schema (`:362-381`) — leave the originally-active session and its in-flight stream untouched.
Only after those does the stream cancel and drain run (`:387-388`), then the pre-switch flush
(`:406-411`) whose failure *refuses* the switch, then `Switch.Switch` (`:413`), then the
`launch_began` anchor (`:433`), then `Activate` (`:449`), then transcript replay (`:451-454`),
refresh (`:457`), model recovery (`:463`), agent replay (`:469`), and the final target flush
(`:477-482`). Three of the five branches flush the *prior* store as a checkpoint; the last flushes
the *target*. The picker-open `slash_command{success}` is flushed before the overlay opens
(`:273-278`), not inside the continuation, so a crash while the picker is open cannot lose it.
This is pinned end-to-end: strictly-increasing call ticks and the `switch < activate < refresh`
window with `launch_began` already present at `Activate`
(`TestResumeHandler_SelectionSwitchesAndOrdersEvents`, `cmd_resume_test.go:396-490`, assertions at
`:464-467` and `:484-489`); flush-before-open via a deferred picker callback
(`TestResumeHandler_FlushesSuccessBeforeOpeningPicker`, `:308-334`); refusal on a failed pre-switch
flush (`TestResumeHandler_PreSwitchFlushFailureRefuses`, `:1086`); the drain preceding the flush,
proven by the prior file *not existing* mid-drain
(`TestResumeHandler_EqualSchemaSwitchWaitsForCancelledTurn`, `:492`, assertions at `:511-515` and
`:527-528`). Durability is verified by reading the session files back from disk (`:434-440`,
`:530-536`, `:687-695`, `:1017-1023`), not from in-memory records.

**File-search generation and cancellation.** `filePickerSession` owns the only cancellable
background work in the picker surface. `invalidateFileRefSearch` (`picker_file.go:392-402`) bumps
`searchGeneration` **before** it calls `cancel`, and nils `searchCancel` in between, so a worker that
observes cancellation can never win a race against a newer generation.
`ownsFileRefSearch` (`:404-406`) requires **both** `a.filePicker == sess` *and*
`sess.searchGeneration == gen`; every off-loop effect is gated on it (`applyFileRefSearchRow` `:220`,
`applyFileRefSearchFinal` `:234`, and the debounce timer's own start closure `:420`). There are four
revocation entry points — query cleared (`:190`), reschedule (`:416`), dismiss (`:319`), and the
zero-result self-dismiss (`:247`). The last of these means a *background completion can tear this
picker down*, which no other overlay does. Pinned by
`TestFileRefSearchInvalidate_RevokesBeforeCancel` (`picker_file_test.go:865`, the bump-before-cancel
ordering), `TestFileRefSearchSchedule_ObsoleteTimerCannotStart` (`:809`),
`TestFileRefSearchSchedule_RejectsReplacedSession` (`:842`, the session-identity half), and the five
subtests of `TestFilePicker_RevocationRejectsStaleEffects` (`:1294`, `:1373`, `:1400`, `:1423`,
`:1447`).

**File-search trigger and debounce.** The picker opens only from the typing seam — `onInputChanged`
(`picker_file.go:63-89`) calls `detectAtTrigger` (`input.go:783`) and then `openFilePicker`
(`:91-112`), which is inert without a project root and home (`:99-101`) and while any overlay is open
(`:92-94`). No walk happens at open: the list shows guidance only (`:125`) and no timer is scheduled
(`TestFilePicker_OpensGuidanceWithoutWalk`, `picker_file_test.go:984`, assertion `:1004-1006`). Each
query change goes through `scheduleFileRefSearch` (`:408-429`), which computes the delay from
`fileRefDebounceDelay` (`:381-390`, 400 ms for the first rune and 250 ms after — `:377-378`),
*invalidates first* (`:416`), captures the new generation, and defers through `a.afterFunc`; the
timer's own closure re-checks ownership before starting anything (`:420`). Emptying the query
revokes without scheduling (`:189-192`). Pinned by `TestFileRefDebounceDelay_CountsRunes`
(`picker_file_test.go:779`, rune not byte counting), `TestFilePicker_FieldChangeSchedulesThroughWiring`
(`:756`, the `SetChangedFunc` wiring at `picker_file.go:135` reaches the scheduler),
`TestFilePicker_QueryClearsToGuidanceAndRevokes` (`:708`), and
`TestFilePicker_LiveScheduleAndRunningLoop` (`:1009`), which asserts both delays under a live loop
and that only the owning timer starts a worker.

**Model selection confirmation.** `confirmModelSelection` (`picker_model.go:859-880`) dismisses the
overlay *first* (`:860`) and only then applies through the injected `ProviderModelApplier`. On
failure it surfaces a notice and returns without clearing the existing notice, refreshing the status
line, or writing any transcript line (`:862-865`). On success the order is fixed: `ClearNotice`
(`:870`), then the status-line `Refresh` (`:873-875`), then the permanent confirmation line
(`:876`), then the cross-mode marker line when the write created one (`:877-879`). Every selection
persists — there is no session-only path. Pinned by
`TestModelPicker_ConfirmAppliesProviderModelEffort` (`picker_model_test.go:417`),
`TestModelPicker_ConfirmEffortMatchesPickerSelection` (`:442`, the effort comes from `sess.effort`),
`TestModelPicker_ConfirmClearsStaleNotice` (`:646`),
`TestModelPicker_ConfirmApplyErrorSurfaced` (`:665`),
`TestModelPicker_ConfirmShowsCrossModeMarkerNotice` (`:682`),
`TestModelPicker_ConfirmEscapesTagLikeText` (`:707`), and
`TestModelPicker_DismissEmitsNothing` (`:770`, an ESC dismissal applies nothing and emits nothing).

**Model dependency seams.** `ModelPickerDeps` (`cmd_model.go:304-316`) supplies `Catalog`,
`Applier`, `Refresh`, `RefreshCatalog`, `Favorites`, and `ToggleFavorite`; the picker is inert until
they are installed
(`openModelPicker` returns on `cat == nil`, `:72-74`), which is what makes CTRL-M a no-op before
bootstrap wires it. There are three production entrypoints, not one: the CTRL-M key case
(`picker_effort.go:112-116`), and the exported `OpenModelPicker` (`picker_model.go:106`) called both
from `internal/bootstrap/starttui.go` on a picker-required launch outcome and from
`resumeModelRecoverer.Recover` (`internal/bootstrap/resumedeps.go:363`) when resume's model recovery
fails — a direct coupling from the resume surface into the model picker.

**Off-loop UI boundary.** Every mutation the file-search worker makes reaches the widget through
`a.streamUpdate` (`picker_file.go:213`, `:215`, `:419`) — the shell's single queue decision point
documented under *Event loop and queue* above. The worker goroutine (`:210`) touches only its own
`ctx`/`cancel` locals; `searchCancel` is written and read on the loop alone (`:208`, `:237`, `:398`).
The model picker's refresh callback does the same (`picker_model.go:356`), and its goroutine lives
outside the TUI entirely, in `internal/bootstrap/provider_refresh.go:133-135`.

**Model row mapping.** `dataByRow` (`picker_model.go:49`) maps each *visible* table row to an index
into the full `rows` slice, or `-1` for a header or spacer, and `dataIndex` (`:722-727`) is the only
accessor. Every selection, confirmation, effort refresh, and favourite toggle resolves through it
(`:194`, `:199`, `:414`, `:569`, `:640`, `:654`, `:682`, `:713`), so a filtered or favourites-reordered
table can never confirm a display position instead of the original `ProviderModel`. Pinned by
`TestModelPicker_FilteredConfirmResolvesOriginalModel` (`picker_model_test.go:871`),
`TestModelPicker_SortsModelIDsWithinProviderGroup` (`:1098`, `dataIndex` returns the catalog source
index despite sorting), `TestModelPicker_FilterHidesEmptyProviderGroups` (`:840`), and
`TestModelPicker_FavoriteAliasResolvesExactPair` (`:1905`, resolution on the (provider, modelID)
pair, not the model ID alone).

**Model refresh ownership.** Three *separate* guards, deliberately not one mechanism.
(1) Per-provider dedupe: `requested map[string]bool` (`picker_model.go:57`, checked at `:346-349`)
with the built-in ChatGPT provider skipped (`:343-345`). (2) Notice ownership:
`refreshToken`/`refreshOwner` (`:58-59`, set at `:350-352`, compared at `:365`) so an older
completion cannot overwrite a newer provider's progress line. (3) Session identity: the completion
closure captures `target := sess` (`:354`) and `applyModelRefreshResult` drops anything whose target
is no longer `a.modelPicker` (`:361-364`), which is what `dismissModelPicker` nilling the session
(`:901`) relies on. Crucially the table is **still rebuilt** on `ModelRefreshUpdated` even when the
completion does not own the notice (`:368` sits outside the `ownsNotice` check) — the catalog is
shared, so a stale completion's *data* is welcome while its *notice* is not. Pinned by
`TestModelPicker_StaleProviderRefreshesOnce` (`picker_model_test.go:1453`),
`TestModelPicker_IgnoresStaleRefreshCompletion` (`:1697`),
`TestModelPicker_OutOfOrderCompletionPreservesNewerNotice` (`:1801`), and
`TestModelPicker_DismissClearsInProgressRefreshNotice` (`:2132`).

**Selection preservation across a rebuild.** `rebuildModelPickerFromCatalog`
(`picker_model.go:386-415`) snapshots the highlighted `(provider, modelID)` *before* re-reading the
catalog (`:391-396`), re-resolves it through `modelRowIndex` into `wantFull` (`:400`), and falls back
to `firstModelRow` only when the row vanished (`:403-405`). `onModelFilterChanged` (`:439-464`)
deliberately does **not** preserve the selection — it resets to the first row and then recomputes the
effort explicitly, because tview may not fire the changed func when the new first row reuses the old
coordinates (the reason is stated at `:451-453`). Pinned by the three subtests of
`TestModelPicker_RefreshSuccessRebuildsFilteredRows` (`picker_model_test.go:1541`, `:1572`, `:1602`),
`TestModelPicker_RefreshRebuildsFilteredFavorites` (`:1984`), and
`TestModelPicker_EffortStepsAfterFilter` (`:932`).

### Findings

Each finding is `ID — classification`. Recommendations are consolidated in the table below.

**B1 — simplify locally. The four flush-and-sink blocks in `runResumeSwitch`.** The six-line body
`if cat, reason, ferr := X.Flush(ctx); ferr != nil { if reason != sessions.ReasonNone { return
deps.WriteFailure.Handle(reason, cat, X.Path(), ferr, X) }; return ferr }` appears verbatim four
times: `cmd_resume.go:353-358` (load-failure checkpoint, `prior`), `:374-379` (older-schema
checkpoint, `prior`), `:406-411` (pre-switch refusal, `prior`), and `:477-482` (post-commit per-turn,
`target`). The *meaning* of each site is carried entirely by its position in the sequence, not by its
body, so a `flushOrSink(ctx, deps, st)` helper taking the store explicitly removes ~20 lines without
touching a single ordering decision. Each site is separately pinned:
`TestResumeHandler_LoadFailureKeepsCurrent` (`cmd_resume_test.go:1039`),
`TestResumeHandler_OlderSchemaFlushesCommandEvent` (`:999`),
`TestResumeHandler_PreSwitchFlushFailureRefuses` (`:1086`), and
`TestResumeHandler_LoadedSessionRecordsAreFlushed` (`:673`, which reads the target file back from
disk). The one real hazard is passing the wrong store; `:673` and `:999` are the tests that catch it.

**B2 — retain. `runResumeSwitch`'s 151 lines.** Same reasoning as A3, with stronger evidence. Every
adjacent pair of steps is separately pinned — classification before stream cancellation
(`TestResumeHandler_OlderSchemaPreservesInFlightStream`, `cmd_resume_test.go:951`;
`TestResumeHandler_NonSwitchingBranchesDoNotCancelOrWait`, `:545`), drain before pre-switch flush
(`:492`), pre-switch flush before switch (`:1086`), switch before launch anchor before `Activate`
before refresh (`:396`, assertions `:484-489`), reset/replay bracketed by switch and refresh
(`TestResumeHandler_SwitchResetsAndReplaysTranscript`, `:595`, assertion `:611-615`), and the
abort-on-sink-failure stop (`TestResumeHandler_LaunchWriteFailureSinkErrorAborts`, `:1122`).
Extracting sub-steps into helpers invites re-ordering, which is the one class of change these
ordering assertions exist to prevent. Rejected as a refactor.

**B3 — simplify locally (declaration only). The undeclared `Abort()` capability.** `ResumeSwitch`
(`cmd_resume.go:132-135`) declares `Switch` and `Activate`. The rollback capability is introduced by
an anonymous type assertion at `:421` — `aborter, canAbort := deps.Switch.(interface{ Abort() })` —
and armed by a deferred `if !activated { aborter.Abort() }` (`:423-429`). The production
implementation does supply it (`resumeSwitch` in `internal/bootstrap/resumedeps.go:259-300`, which
carries `pending`/`pendingPrior` across `Switch`/`Activate`/`Abort`), so this is a real third method
of a two-method interface, discoverable only by reading the assertion. Naming the optional interface
(`type resumeSwitchAborter interface{ Abort() }`) makes it greppable at no behaviour cost. The
discoverability cost is already visible in the tests: `fakeSwitch` (`cmd_resume_test.go:93-138`)
implements only `Switch` and `Activate`, so `canAbort` is **false in all twenty-one tests of
`cmd_resume_test.go`** — including `TestResumeHandler_LaunchWriteFailureSinkErrorAborts` (`:1122`),
which despite its name pins the *stop*, not the rollback. The rollback is covered from another
package entirely, by `TestResumeHandler_LaunchFailureCallsAbort`
(`internal/bootstrap/resumedeps_test.go:269`), which had to declare its own `resumeAbortSwitch`
(`:252-261`) carrying a method no interface in `internal/tui` names. What must survive: the
capability stays *optional* — a `ResumeSwitch` without `Abort` must still work — and the abort must
remain gated on `activated == false`.

**B4 — retain. `ResumeDeps`' fifteen fields.** The struct reads like a god-object parameter bag, but
every field is a distinct capability with a distinct production implementation
(`internal/bootstrap/resumedeps.go:35-55` binds each one) and a distinct fake. The branch tests
depend on substituting exactly one at a time: `fx.deps.Stream` alone becomes a `drainingStream`
(`cmd_resume_test.go:497-500`), `fx.deps.Lister` alone becomes a `folderScopedLister` (`:1202-1212`),
`newFlushFailingHost` replaces only the host (`:1087`). Bundling or collapsing capabilities would
remove the per-capability substitution that makes the transaction testable without a terminal.
Note `Fork` (`cmd_resume.go:199`) is currently unreachable — `resumeForker` at
`internal/bootstrap/resumedeps.go:381-383` returns nil and is documented as dead while
`sessions.ReaderSupportedVersion == 1`; that is a dead-seam observation for slice C's sweep, not a
reason to drop the field, which the older-schema tests still drive.

**B5 — retain. The file picker's generation-plus-identity ownership.** See *File-search generation
and cancellation* above. The four revocation call sites and the two-part ownership gate (session
identity *and* generation) are load-bearing and cheaply pinned; nothing here is duplication.
Rejected as a simplification candidate, and explicitly rejected as a candidate for sharing with the
model picker (see B10).

**B6 — retain. The two search-limit checks.** `fileRefSearchLimit` (`picker_file.go:338`) is
enforced on the producer side inside `searchFileRefs` (`:367`, which returns `nil` rather than
aborting so the walk still completes) *and* again on the UI side in `applyFileRefSearchRow`
(`:223-225`). This is not redundant: `sess.search` is an injected seam (`:45`, bound at `:103-105`,
and replaced by eight different stubs across `picker_file_test.go`), so the UI-side cap is the only
one that holds for an arbitrary search func. Both are covered —
`TestFileRefSearch_CompleteCorpusAndBound` (`picker_file_test.go:87`) for the producer bound, and
`TestFilePicker_StreamsRowsBeforeFinal` sub-2 (`:1143-1164`) for the UI bound. Recorded so the
apparent double-check is not re-raised.

**B7 — extract (file move only). `onInputChanged` lives in `picker_file.go`.** The prompt
TextArea's only change hook is `picker_file.go:63-89`, registered once in production at
`app.go:673`. Exactly one of its three responsibilities belongs to the file picker: it discards a
pending follow-up suggestion (`:70-73`), detects the `@` trigger (`:80-83`), and
detects the `/` slash-picker trigger (`:86-88`). This is the same misplacement shape as **A5**
(`handleGlobalKey` hosted in `picker_effort.go`), with the same symptom: four other files have to
name `App.onInputChanged` in prose to explain their own behaviour (`input.go:35`, `:73`, `:782`,
`:814`; `help.go:59`; `picker_effort.go:40`; `app.go:354`, `:1327`, `:1369`, `:1758`). Moving the
function to `key_input_changed.go` — or beside the input it hooks — is a pure file move. Behaviour that must survive: the follow-up discard runs *before* the overlay and
paste early returns (`:70-77`), and `fileRefPrevText` is advanced *before* those returns (`:74-76`)
so the next typed change compares against the post-paste buffer — pinned by
`TestFilePicker_BracketedPasteOfAtDoesNotOpen` (`picker_file_test.go:362`) and
`TestFilePicker_LongPasteCollapsesWithoutOpening` (`:341`).

**B8 — simplify locally. The two model-picker key switches.** `modelPickerFieldKeys`
(`picker_model.go:587-627`, 13 cases) and `modelPickerKeys` (`:744-777`, 9 cases) share nine
byte-identical cases: Escape, Home, End, PgUp, PgDn, Left, Right, Ctrl-R, Ctrl-F. The field router
adds Up/Down/Enter; the table router deliberately omits them so tview's built-in table navigation and
`SetSelectedFunc` (`:198-204`) handle them. A shared helper for the common nine must preserve that
omission exactly. Coverage of both routes already exists:
`TestModelPicker_CtrlFTogglesFavoriteFromBothRoutes` (`picker_model_test.go:2030`),
`TestModelPicker_CtrlRForcesProviderRefresh` (`:1492`, four subtests),
`TestModelPicker_HomeEndSelectFirstLastVisibleModel` (`:1130`), and
`TestModelPicker_PageKeysMoveByViewportOfSelectableRows` (`:1192`). Two of those four
(`:1144-1147`, `:1210-1213`) iterate a Go `map` to pick the route, so the two routes run in
nondeterministic order against one shared mutable `*tview.Table`; the other two (`:1527-1538`,
`:2032-2038`) already use a deterministic slice. Any work here should convert the map form to the
slice form rather than preserve it.

**B9 — simplify locally. The three selectable-row scans.** `moveModelPickerSelection`
(`picker_model.go:633-645`), `selectModelBoundary` (`:647-667`), and `pageModelPickerSelection`
(`:669-690`) each hand-roll the same walk over `dataByRow` looking for `dataIndex(i) >= 0`. One
`nextSelectableRow(sess, from, dir)` helper collapses all three. What must survive: clamping with no
wraparound at both ends, the empty-filtered-set no-op (every row maps to `-1`), and that paging counts
*selectable* rows against the drawn viewport height rather than table rows (`:674-686`). Pinned by
`TestModelPicker_NavigationSafeOnEmptyAndSingleResult` (`picker_model_test.go:1290`),
`TestModelPicker_NavigationStaysWithinFilterAndKeepsQuery` (`:1259`), `:1130`, and `:1192` — the last
of which needs a *drawn* `GetInnerRect()` and carries its own fixture-height guard at `:1201-1203`.

**B10 — retain. The three picker staleness mechanisms are not one mechanism.** The file picker drops a
stale worker's row entirely (`picker_file.go:219-231`) and cancels the producer; the model picker
keeps a stale completion's *rows* and drops only its *notice* (`picker_model.go:360-384`), and cannot
cancel at all because the goroutine belongs to `internal/bootstrap/provider_refresh.go:133-135`. The
resume picker has neither — its only concurrency guard is the one-shot `fired` flag
(`picker_resume.go:404-415`). Any shared "picker staleness" abstraction would have to pick one of
these three answers and would silently change the other two. Directly contrasted by
`TestFilePicker_RevocationRejectsStaleEffects` (`picker_file_test.go:1294`) against
`TestModelPicker_IgnoresStaleRefreshCompletion` (`picker_model_test.go:1697`) and
`TestModelPicker_OutOfOrderCompletionPreservesNewerNotice` (`:1801`). Rejected — this is the
architecture review's predicted trap, and the evidence confirms it.

**B11 — retain. `populateModelTable` and the `dataByRow` indirection.** See *Model row mapping*
above. The function is pure, has three callers, and the header/spacer offsets it produces are what
makes filtering and favourites safe. `picker_model.go` is the largest file in the picker surface at
974 lines, but the row-mapping half is already the smallest, best-isolated part of it. Rejected.

**B12 — simplify locally (narrow). The rebuild/filter tail.** `rebuildModelPickerFromCatalog`
(`picker_model.go:386-415`) and `onModelFilterChanged` (`:439-464`) share a ten-line tail:
`favoriteAliasOrder` → `filterModelRows` → `populateModelTable` → assign `dataByRow` → select →
`refreshHighlightedModel`. Only the populate-and-assign pair (`:401-402` / `:447-448`) is safe to
share. The selection policy must stay in each caller: the rebuild restores the prior
`(provider, modelID)` and falls back only when it vanished, while the filter resets to the first row
*and* recomputes the effort explicitly for the tview reason stated at `:451-453`. A helper that also
owned the selection would collapse the exact difference that
`TestModelPicker_RefreshSuccessRebuildsFilteredRows` (`picker_model_test.go:1541`, three subtests
with three different catalog deltas) and `TestModelPicker_EmptyFilterResultSafe` (`:889`) exist to
separate.

**B13 — extract. The seven verbatim overlay teardown tails.** The same six lines —
`pages.RemovePage(page)`; `if xPrev != nil { SetFocus(xPrev) } else { SetFocus(a.input) }`;
`xPrev = nil` — appear in every picker: `picker_file.go:321-327`, `picker_model.go:894-900`,
`picker_effort.go:305-311`, `picker_slash.go:230-236`, `picker_connect.go:84-90`,
`picker_settings.go:183-190`, `picker_resume.go:450-458`. A single
`a.restoreOverlayFocus(prev tview.Primitive)` (or a `closeOverlayPage` that also removes the page)
takes ~40 lines out with no ownership move. What must survive per picker: `picker_settings.go`
removes its `permissions-delete` child page first (`:184`), `picker_resume.go` removes *two* child
pages first (`:450-451`), `picker_model.go` clears an in-progress refresh notice *before* the
teardown (`:890-892`), and `picker_file.go`/`picker_slash.go` perform their literal splice *after*
focus restore (`picker_file.go:329-335`). Every one of those four exceptions is separately pinned —
e.g. `TestFilePicker_EscLeavesAtQueryLiteral` (`picker_file_test.go:651`) and
`TestModelPicker_DismissClearsInProgressRefreshNotice` (`picker_model_test.go:2132`).

**B14 — defer to slice C (with sizing evidence). A11's overlay triads.** This slice was asked to size
A11. The answer: **take B13, not the triad consolidation.** Adding an overlay today is not a
three-site edit, it is at least five, and nothing enforces any of them:
(1) the field triad in `app.go:236-348`; (2) the 12-term OR in `anyOverlayOpen` (`app.go:939`), whose
own doc comment at `:934-937` is already stale — it names eight of the twelve; (3) the ESC chain in
`key_esc.go:91-130`, which has only ten branches; (4) a guarded `open*` plus an idempotent `dismiss*`;
and (5) `handleGlobalKey` in `picker_effort.go`, which carries three picker-specific branches by name
— `if a.resumePickerOpen` on Escape (`:95-107`), on Ctrl-R (`:117-119`), and on Ctrl-D (`:170-172`),
plus `if a.modelPickerOpen { forceRefreshHighlightedProvider() }` (`:119-122`). The ten triads in
that range are also not uniform enough to register generically, and the two overlays outside it —
`panelOpen` (`app.go:176`) and `statusOpen` (`:178`) — have no `*Prev` at all:
`effortPickerOpen` has no session struct; `presentResumeEmpty`
(`picker_resume.go:417-439`) sets `resumePickerOpen = true` while leaving `a.resumePicker` nil, so
"flag set implies session present" is false; and `filePicker`/`slashPicker` dismissals take a
`leaveLiteral` argument the others do not. The gap worth acting on is that `resumePickerOpen` is in
`anyOverlayOpen` but *absent* from `dismissOpenOverlay`, which is correct only because
`picker_effort.go:95-107` returns ESC to the resume table's own capture
(`picker_resume.go:119`, `:177-190`) — and unlike the `secretPromptOpen` omission, which
`key_esc.go:124-125` documents (its branch is at `:33-36`), this one is unexplained where a reader
would look. Deferred to slice C as a
consistency/documentation item, not a refactor.

**B15 — consolidate test setup. `cmd_resume_test.go`'s duplicated recorders and act step.** Three
separate items, in descending value. (a) `fakeRefresher` (`cmd_resume_test.go:140-155`) and
`fakeRecoverer` (`:157-172`) are field-for-field and body-for-body identical apart from the method
name and an ignored `context.Context`; the same `if x.order != nil { x.at = x.order.tick() }`
recorder prologue is copied seven times (`:87-89`, `:116-118`, `:133-135`, `:151-153`, `:168-170`,
`:202-204`, `:210-212`), and `fakeReplayer` in `cmd_clear_test.go:154` is an eighth copy. (b)
`newResumeRegistry(t, fx.deps)` is built 21 times and `DispatchSlashInput("/resume", host)` is
checked 22 times (the 21 plus `TestBuildRegistry_ResumeDispatchesToHandler` at `:1251`, which builds
its registry through `BuildRegistry` instead), in two competing idioms — 13 sites check only
`res.Err` (`:575`, `:602`, `:633`, `:653`, `:683`, `:822`, `:853`, `:885`, `:922`, `:962`, `:1007`,
`:1051`, `:1216`) and 9 also check `res.Status` (`:315`, `:352`, `:408`, `:519`, `:712`, `:790`,
`:1093`, `:1136`, `:1260`); a helper must **return** the result rather than fold the assertion in,
because four of those nine carry branch-specific explanations of why `Handled` is right there
(`:714`, `:792`, `:1095`, `:1138`). (c) `fx.target` aliases `fx.loader.target`
(`:245` and `:253`), a two-place invariant only `TestResumeHandler_LaunchWriteFailureSinkErrorAborts`
(`:1128-1129`) currently maintains; a fixture option would remove the trap. What must survive: the
four branch-specific dispatch messages, the shared `callOrder` tick that three ordering tests read
(`:464`, `:527`, `:611`), and the on-disk read-backs (`:434`, `:530`, `:687`, `:1017`).

**B16 — consolidate test setup. The two hand-rolled live-app scaffolds in `picker_model_test.go`.**
`TestModelPicker_FilterLiveKeyboardPath` (`:955`, scaffold at `:961-981`) and
`TestModelPicker_CtrlMOpenArrowEnterApplyEscDismiss` (`:1012`, scaffold at `:1018-1039`) each
reimplement the same ~21 lines: `SimulationScreen` → `SetScreen` → `errc` → `go a.app.Run()` → an
identical `hasPicker` closure → an identical `waitPicker(want bool)` with a 2s deadline and 5ms poll.
The shared `newAppHarness` (`harness_test.go:31-51`) already solves this, and the file references
`harness_test.go` only for `findReverseVideoRows` (`:628`). This is the same finding as **A14**,
in a second file. What must survive: the `newScreen` injection (without it the test opens a real
terminal), the loop-running barrier before any key injection, and the reads that are serialised onto
the loop goroutine.

**B17 — retain. Picker fixture setup is already consolidated; further sharing is rejected.**
`picker_file_test.go` already has `withFileRefSources` (`:276-285`, 20 uses),
`startRunningFilePicker` (`:966-982`, 10 uses), `collectFileRefTimers` (`:803`, 8 uses),
`startFileRefSearchThroughField` (`:947`, 10 uses), and `fileRefListText` (`:897`, 13 uses).
`picker_model_test.go` has `providerModelCatalogFake` (`:39`), six catalog constructors
(`selectedModelCatalog` `:107` and five others), and `modelTableRow` (`:134`); its per-test arrange
is two to three lines where the varying `buildModelPicker` arguments *are* what each test pins.
`cmd_resume_test.go` uses `newResumeFixture` in 20 of its 21 tests and shares `newWritableHost`,
`callOrder`, `fakeStream`, `drainingStream`, `fakeReplayer`, `fakeWriteFailure`,
`newFlushFailingHost`, and `eventKinds` with `cmd_clear_test.go`. Beyond B15 and B16 the residual
repetition is arrange whose literal values are the oracle, and it must not be hidden: the `wantText`
row literal at `picker_model_test.go:152`, the deliberately malformed favourites list at
`:1866-1871` (a duplicate and a ghost entry, which are the whole point of the dedupe assertions), the
three different catalog deltas at `:1553`, `:1583`, `:1613`, the completion interleaving at
`:1812-1831`, and the cumulative refresh-count snapshots at `:1461-1487`. Rejected.

**B18 — test coverage. The file picker's keyboard selection and dismissal guards.** Nothing in
`picker_file_test.go` names `moveFilePickerSelection` (`picker_file.go:172-185`) or reaches the
`KeyUp`/`KeyDown` arms of `filePickerFieldKeys` (`:159-164`), the mouse `SetSelectedFunc` path
(`:128`), `dismissFilePicker`'s idempotence guard (`:315`) or its `insertAt <= len(text)` bound
(`:332`), or `confirmFileRef`'s `atByte` range guard (`:276-278`). Separately, four tests assert an
*absolute* generation value rather than a relation — `!= 8` (`picker_file_test.go:880-882`), `!= 4`
(`:1415-1417`), `!= 6` (`:1439-1441`), `!= 10` (`:1462-1464`) — so adding one more
`invalidateFileRefSearch` call anywhere breaks all four with off-by-one messages, while the
relational forms at `:594-596`, `:698-700`, and `:731-733` would survive. This is a test-coverage and
test-robustness finding, not a refactor.

**B19 — retain. `confirmModelSelection`'s dismiss-first ordering.** See *Model selection
confirmation* above. The overlay is torn down before the apply runs (`picker_model.go:860`) so the
confirmation and marker lines land on a transcript no overlay is covering, and so the status-line
`Refresh` (`:873-875`) runs against restored focus. The two `Append` calls (`:876`, `:878`) are
committed history, deliberately not notices, which is why `ClearNotice` at `:870` does not disturb
them. Rejected as a simplification. Recorded coverage nuance: the six unit-level confirm tests call
`confirmModelSelection` with no overlay mounted, where `dismissModelPicker`'s `!a.modelPickerOpen`
guard (`:887`) makes the first statement a no-op — the dismiss-before-apply ordering is exercised
only end-to-end, by `TestModelPicker_CtrlMOpenArrowEnterApplyEscDismiss`
(`picker_model_test.go:1012`, call-count deltas at `:1046`, `:1059`, `:1079`).

**B20 — test coverage. Two interchangeable model-picker construction seams.** 21 sites in
`picker_model_test.go` call `a.buildModelPicker(...)` directly, bypassing `openModelPicker`'s overlay
guard (`picker_model.go:69-71`), deps guard (`:72-74`), page mount (`:94`) and focus move (`:97`);
14 sites go through `SetModelPickerDeps` + `openModelPicker`; four do both in sequence
(`picker_model_test.go:872-876`, `:890-894`, `:1131-1135`, `:1377-1381`), building the picker twice.
The direct seam is legitimately cheaper for the pure row-mapping tests and should stay. The gap is
narrower than the split suggests: `openModelPicker`'s own active-selection conversion —
`modelRowIndex` into `initialRow` at `picker_model.go:77-87` — is never exercised, because
`TestModelPicker_InitialHighlightLandsOnActiveSelection` (`picker_model_test.go:264`) computes that
index in the test and feeds it to `buildModelPicker`, as its comment at `:268-270` states. The
`openModelPicker` path is otherwise covered for the no-selection (`:372`), overlay-open (`:388`), and
unwired (`:407`) cases. Note also that a related structural split makes this easy to misread:
`openModelPicker` sets `modelPickerOpen` (`:89`) while `buildModelPicker` assigns `a.modelPicker`
(`:174`), so the flag and the session are established in different functions.

### Recommendations (slice B)

| ID | Class | Affected files and symbols | Evidence | Expected benefit | Risk | Preserved behaviour | Non-goals | Follow-up task justified? |
|----|-------|----------------------------|----------|------------------|------|---------------------|-----------|---------------------------|
| B13 | extract | `internal/tui/picker_file.go:321-327`, `picker_model.go:894-900`, `picker_effort.go:305-311`, `picker_slash.go:230-236`, `picker_connect.go:84-90`, `picker_settings.go:183-190`, `picker_resume.go:450-458` | Six identical lines in all seven pickers; four documented per-picker exceptions sit *around* the tail, not inside it | ~40 lines removed; one place for the focus-restore rule | Low — no ownership, timer, or queue change | Permissions removes its child page first (`:184`); resume removes two (`:450-451`); model clears the refresh notice first (`:890-892`); file/slash splice the literal after focus restore (`picker_file.go:329-335`) | Do not fold the child-page removals, the notice clear, or the literal splice into the helper; do not unify the `dismiss*` functions themselves | **Yes** — mechanical, seven files, no behaviour surface |
| B7 | extract (file move) | `internal/tui/picker_file.go:63-89` `onInputChanged`; registration `internal/tui/app.go:673` | Three responsibilities, one is the file picker; same shape as A5's `handleGlobalKey` misplacement | The prompt's only change hook becomes findable by name | Very low — file move, no call-graph change | Follow-up discard and `fileRefPrevText` advance both run *before* the overlay/paste early returns (`:70-77`) | Do not split the hook into per-detector functions; do not change trigger precedence (`@` before `/`) | **Yes** — bundle with A5 |
| B1 | simplify locally | `internal/tui/cmd_resume.go:353-358`, `:374-379`, `:406-411`, `:477-482`; sink `WriteFailureSink` | Four verbatim six-line bodies; the position, not the body, carries each site's meaning | ~20 lines out of the longest function in the surface | Medium — passing the wrong store is a silent durability bug | Which store each site flushes (three `prior`, one `target`) and every step's position relative to load/cancel/switch/anchor/activate | Do not merge call sites, move a flush, or change which failures route through the sink vs surface | **Yes** — small, well pinned by `cmd_resume_test.go:673, 999, 1086, 1039` |
| B9 | simplify locally | `internal/tui/picker_model.go` `moveModelPickerSelection:633`, `selectModelBoundary:647`, `pageModelPickerSelection:669`; accessor `dataIndex:722` | Three hand-rolled scans of `dataByRow` for the same predicate | One selectable-row walk instead of three | Low–medium — paging counts selectable rows against a drawn viewport | No wraparound at either end; empty-filtered-set no-op; paging counts selectable rows, not table rows | Do not change clamping to wraparound; do not make paging count header/spacer rows | **Yes** — bundle with B8 |
| B8 | simplify locally | `internal/tui/picker_model.go` `modelPickerFieldKeys:587-627` and `modelPickerKeys:744-777` | Nine byte-identical cases across two switches | One place for the nine shared bindings | Medium — the table router's *omissions* are deliberate | The table router must keep passing Up/Down/Enter through to tview and `SetSelectedFunc` (`:198-204`) | Do not give the table router Up/Down/Enter; do not reorder cases; do not merge the two routers into one | **Yes** — bundle with B9, and convert the map-iterated route tables at `picker_model_test.go:1144-1147, 1210-1213` to the deterministic slice form used at `:1527, :2032` |
| B3 | simplify locally (declaration) | `internal/tui/cmd_resume.go:132-135` `ResumeSwitch`, assertion `:421`, deferred abort `:423-429`; impl `internal/bootstrap/resumedeps.go:259-300`, `:293` | A third method reachable only through an anonymous interface assertion; `fakeSwitch` (`cmd_resume_test.go:93-138`) omits it, so `canAbort` is false in every test of that file, and the rollback is covered only cross-package by `TestResumeHandler_LaunchFailureCallsAbort` (`internal/bootstrap/resumedeps_test.go:269`) via a locally declared `resumeAbortSwitch` (`:252-261`) | The optional rollback capability becomes greppable from the package that branches on it | Very low — a named type for an existing assertion | `Abort` stays optional (a `ResumeSwitch` without it must still work) and fires only when `activated == false` | Do not add `Abort` to `ResumeSwitch` itself; do not make the abort unconditional | **Yes** — bundle with B1 |
| B12 | simplify locally (narrow) | `internal/tui/picker_model.go` `rebuildModelPickerFromCatalog:386-415`, `onModelFilterChanged:439-464`; shared pair `:401-402` / `:447-448` | Ten-line shared tail; only the populate-and-assign pair is genuinely common | Removes the smaller half of the duplication safely | Medium — the selection policies are deliberately different | Rebuild restores `(provider, modelID)` and falls back only when it vanished; filter resets to the first row and recomputes the effort explicitly (`:451-453`) | Do not put selection or effort recomputation inside the shared helper | Optional — only alongside B8/B9 |
| B15 | consolidate test setup | `internal/tui/cmd_resume_test.go` `fakeRefresher:140` / `fakeRecoverer:157`; recorder prologue `:87, :116, :133, :151, :168, :202, :210`; act step ×21; alias `:245`/`:253` | Two literal duplicate types, eight copies of one recorder idiom, two competing dispatch idioms | Removes ~60 lines and one two-place fixture invariant | Medium — a shared fixture can mask a branch-specific setup | The four branch-specific dispatch messages (`:714, :792, :1095, :1138`); the `callOrder` ticks read at `:464, :527, :611`; the on-disk read-backs at `:434, :530, :687, :1017` | Do not fold the status assertion into the act helper; do not merge the older-schema tests into a table that loses their distinct branch claims | **Yes**, scoped to arrange-only with a diff touching no assertion |
| B16 | consolidate test setup | `internal/tui/picker_model_test.go:961-981` and `:1018-1039`; existing `newAppHarness` `internal/tui/harness_test.go:31-51` | ~21 duplicated lines twice, including two independent 2s/5ms polling loops | Removes ~40 lines; second instance of the A14 pattern | Medium — these drive a real event loop | The `newScreen` injection, the loop-running barrier before key injection, and loop-serialised reads | Do not replace the barrier with a sleep; do not read picker state off-loop | **Yes**, bundled with A14 |
| B18 | test coverage | `internal/tui/picker_file.go` `moveFilePickerSelection:172`, `filePickerFieldKeys:159-164`, `list.SetSelectedFunc:128`, `dismissFilePicker:315,332`, `confirmFileRef:276-278`; absolute-generation asserts `picker_file_test.go:880, 1415, 1439, 1462` | No test names these five paths; four tests assert absolute generation values | Pins ↑/↓ selection and the dismissal bounds; makes generation asserts survive an added invalidation | Low — additive tests plus four assertion rewrites | Clamped no-wraparound list movement; idempotent dismissal; the literal splice bound | Do not change production guards to make a test easier; do not drop the generation assertions, only make them relational | **Yes** — small additive test task |
| B20 | test coverage | `internal/tui/picker_model.go` `openModelPicker:68-98` (active-selection conversion `:77-87`, flag at `:89`) vs `buildModelPicker:153` (session assigned at `:174`); test sites `picker_model_test.go:264` and the four double-build sites `:872, :890, :1131, :1377` | 21 direct-build sites vs 14 open-path sites; `:264`'s own comment (`:268-270`) says it replicates the conversion rather than exercising it | Pins the one `openModelPicker` step no test reaches | Low — additive test | Direct `buildModelPicker` stays available for the pure row-mapping tests; the guards and page mount stay in `openModelPicker` | Do not force every test through `openModelPicker`; do not move the session assignment as part of a test change | **Yes** — one small test, bundle with B18 |
| B2 | retain | `internal/tui/cmd_resume.go` `runResumeSwitch:335-485` | Nineteen assertions across `cmd_resume_test.go` pin adjacent step pairs; four order mechanisms in use | None — the length is one ordered transaction | Helper extraction invites re-ordering, which is exactly what the ordering tests exist to catch | Classification before cancellation; drain before flush; flush-refusal before switch; anchor before `Activate` before refresh | Do not extract sub-steps of the switch sequence | No |
| B4 | retain | `internal/tui/cmd_resume.go:182-212` `ResumeDeps`; production binding `internal/bootstrap/resumedeps.go:35-55` | Each field has one production impl and one fake; branch tests substitute exactly one at a time | None — the field count reflects real injected capabilities | Bundling removes the single-capability substitution the branch tests depend on | Every capability stays independently injectable; `FlushCtx` nil still means `context.Background()` (`:214-219`) | Do not group fields into sub-structs or collapse `/clear`-shared capabilities | No — but flag `Fork` (`:199`) to slice C's dead-seam sweep |
| B5 | retain | `internal/tui/picker_file.go` `invalidateFileRefSearch:392-402`, `ownsFileRefSearch:404-406`, revocation sites `:190, :247, :319, :416` | Generation bump precedes cancel; ownership needs session identity *and* generation | None — this is the safety mechanism, not duplication | Any reordering or weakening re-opens the stale-worker race | Bump-before-cancel ordering; the two-part ownership gate; every off-loop effect gated on it | Do not reorder the bump and the cancel; do not drop the session-identity half | No |
| B6 | retain | `internal/tui/picker_file.go` `searchFileRefs:367`, `applyFileRefSearchRow:223-225`, seam `:45, :103-105` | The search func is injected and replaced by eight test stubs; only the UI cap holds for all of them | None — the two checks have different guarantees | Removing the UI cap lets an injected or future search func flood the list | Producer completes the walk past the cap (`return nil`, not abort); UI cap holds regardless of the search func | Do not remove either check; do not make the producer abort the walk | No |
| B10 | retain | `internal/tui/picker_file.go:219-231, 392-406` vs `picker_model.go:338-384` vs `picker_resume.go:404-415` | Three different answers to staleness: drop-and-cancel, keep-rows-drop-notice, one-shot flag | None — the differences are the contracts | A shared abstraction must pick one answer and would silently change the other two; the model picker cannot cancel at all (goroutine in `internal/bootstrap/provider_refresh.go:133-135`) | File-picker cancellation and generation; model-picker rebuild-on-stale with notice ownership; resume's single-fire continuation | Do not build a generic picker-session or picker-staleness abstraction | No — this is the architecture review's predicted trap, confirmed |
| B11 | retain | `internal/tui/picker_model.go` `populateModelTable:273-323`, `dataIndex:722-727`, callers `:180, :401, :447` | Pure function, one accessor, every selection path routes through it | None — already the best-isolated part of the file | Indexing `rows` by table position would break under filtering and favourites | Header/spacer rows map to `-1`; confirm resolves the original `ProviderModel`, never a display label or filtered position | Do not index `rows` by table row; do not inline the mapping into callers | No |
| B19 | retain | `internal/tui/picker_model.go` `confirmModelSelection:859-880`; guard `dismissModelPicker:887` | Dismiss precedes apply (`:860`); success order `ClearNotice:870` → `Refresh:873` → `Append:876` → marker `:878`; error branch returns before all of them (`:862-865`) | None — the ordering is the contract | Reordering would put the confirmation behind a live overlay or clear a notice the error path must keep | Dismiss-before-apply; error path leaves its notice and writes nothing; both confirmation lines are transcript history, not notices | Do not move the dismissal after the apply; do not convert the `Append` lines back into notices | No — but the end-to-end ordering rests on a single test (`picker_model_test.go:1012`); a focused confirm-while-open test would be cheap insurance |
| B17 | retain | `internal/tui/picker_file_test.go:276, 803, 897, 947, 966`; `picker_model_test.go:39, 107, 134`; `cmd_resume_test.go:236` | Helpers already exist and are used 8–20 times each; remaining arrange literals are the oracle | None — the shared arrange is already extracted | A further helper would hide the row literal at `picker_model_test.go:152`, the malformed favourites at `:1866-1871`, the three catalog deltas at `:1553/:1583/:1613`, and the interleaving at `:1812-1831` | Every literal that doubles as an expected value stays inline with its assertion | Do not consolidate picker fixtures further beyond B15 and B16 | No |
| B14 | defer to slice C | `internal/tui/app.go:236-348` triads and `anyOverlayOpen:939` (doc comment stale at `:934-937`); `internal/tui/key_esc.go:91-130`; `internal/tui/picker_effort.go:95-107, 117-119, 170-172`; `internal/tui/picker_resume.go:417-439` | Five edit sites, not three; ten branches for twelve flags; `resumePickerOpen`'s omission is undocumented where a reader would look; `presentResumeEmpty` sets the flag with a nil session | Would remove a silent-omission class of bug | The triads are not uniform: no `*Prev` for panel/status, no session for the effort picker, a `leaveLiteral` argument for file/slash, a flag-without-session state for empty resume | ESC priority order; the resume picker's own ESC capture (`picker_resume.go:119, 177-190`); the secret prompt's earlier interception (`key_esc.go:33-36`) | Do not build an overlay registry in this slice; do not move the resume ESC handling into `dismissOpenOverlay` | Decide in slice C — the actionable part is documenting the `resumePickerOpen` omission and refreshing the `anyOverlayOpen` comment; **A11 as a triad refactor is rejected**, take B13 instead |

### Hand-off to slice C

- **A11 is answered** (see **B14**): the triad consolidation is rejected on non-uniformity evidence;
  the extractable part is the teardown tail (**B13**). What remains for slice C is the documentation
  gap — `resumePickerOpen` is in `anyOverlayOpen` but not in `dismissOpenOverlay`, with no note where
  a reader would look, and the `anyOverlayOpen` doc comment (`app.go:934-937`) names eight of twelve
  flags.
- **A12's dead-code sweep gains one candidate** from this slice: `ResumeDeps.Fork`
  (`cmd_resume.go:199`) is wired in production to `resumeForker`
  (`internal/bootstrap/resumedeps.go:381-383`), which is documented as unreachable while
  `sessions.ReaderSupportedVersion == 1`. It is still driven by five tests, so it is a live seam for a
  dormant feature, not dead code — but it belongs in that sweep's evidence.
- The `permissionsPicker` teardown (`picker_settings.go:183-190`) and its nested
  `permissions-delete` child page are inside **B13**'s file set but belong to slice C's surface; that
  slice should confirm the extraction does not disturb the child-page ESC ownership at
  `key_esc.go:103-111`.

## Permission prompts and dead-code evidence (slice C)

*Historical — from the 2026-07-27 assessment and its 2026-08-05 review notes; statuses and line
numbers are from those dates, not current.*

### Scope

In scope for this slice:

- `internal/tui/prompt.go` (1033 lines) with `internal/tui/prompt_test.go` (2222 lines).
- The focused prompt collaborators: `internal/tui/prompt_scope.go` (240 lines) and
  `internal/tui/prompt_folder.go` (119 lines), with `prompt_scope_test.go` (382) and
  `prompt_folder_test.go` (169).
- The permission-display consumer `internal/tui/picker_settings.go` (385 lines) with
  `picker_settings_test.go` (685), reached here through **B13**'s teardown finding and the
  `capabilityCoveragePhrase` sharing.
- The central ESC path `internal/tui/key_esc.go` and the overlay flag set in
  `internal/tui/app.go:236-348`, as the two hand-off items **A12** and **B14** left open.
- Production construction and consumption context, cited as evidence and not modified:
  `internal/bootstrap/promptgate.go` (the serialized backend→TUI boundary),
  `internal/bootstrap/authdeps.go` and `internal/dispatch/tool.go` (the request producers),
  `internal/permissions/*` (the matcher, encoder, and orchestration the stored subject feeds).

Out of scope: any code change (this slice classifies, like the two before it), `.deadcode-allow`
edits, and `internal/tui/secret_prompt.go`, which is a masked-input overlay unrelated to the
permission prompt.

### Inventory

| Unit | Location | Size | Shape |
|------|----------|------|-------|
| `PromptRequest` | `prompt.go:92-218` | 23 fields | 4 display strings, 6 shell/batch context fields, 5 path/anchor fields, 3 out-of-root/capability policy inputs, 3 cross-mode gate inputs, 1 compound decomposition, 1 unused (`SessionScope`) |
| `buildPromptOverlay` | `prompt.go:455-647` | 193 lines | One overlay assembly: preview, facts, options list, key capture, draw hook, mouse capture, conditional note |
| `PromptUser` | `prompt.go:655-694` | 40 lines | Two `QueueUpdateDraw` closures around one blocking channel receive |
| `renderPromptFacts` | `prompt.go:367-442` | 76 lines | Pure; 6 conditional blocks over already-resolved data |
| Scope-chooser flow | `prompt.go:702-835` | 7 funcs | `showScopeChooser:702` → `buildScopeChooser:715` → `finalizeScope:829`, plus the Program-confirm sub-flow `showProgramConfirm:756` → `buildProgramConfirm:771` → `buildProgramConfirmList:787`, and `cancelProgramConfirm:820` |
| Compound flow | `prompt.go:844-961` | 6 funcs | `showCompoundChooser` → per-stage `buildCompoundStage` → `advanceCompoundStage` → `finalizeCompound` |
| `completePrompt` / `dismissPrompt` | `prompt.go:992-1013` | 9 + 8 lines | The whole one-shot/default-deny surface |
| `scopeOptionRows` | `prompt_scope.go:139-163` | 25 lines | Pure row builder; 2 callers (`:171`, `:227`) |
| `buildCompoundStageScopeOptions` | `prompt_scope.go:210-240` | 31 lines | Pure; 1 production caller (`prompt.go:845`), 5 test callers |
| `OmitFolderOption` | `prompt_folder.go:51-56` | 6 lines (15 doc lines) | The containment verdict; 4 production call sites |
| `promptGate` | `promptgate.go:118-148` | 3 funcs | Capacity-one permit, `acquire`/`release` |

Test scale for context: the permission-prompt surface is 1,777 production lines against 3,458 test
lines. `prompt_test.go` holds 56 top-level tests, `prompt_scope_test.go` 11,
`prompt_folder_test.go` 6, `picker_settings_test.go` 15.

### Ownership boundaries

These are the boundaries any recommendation in this slice must not disturb.

**One decision, then default deny.** `completePrompt` (`prompt.go:992-1000`) and `dismissPrompt`
(`:1006-1013`) are the only two senders on the per-call `decisionCh` (`:656`, buffered 1). Both nil
`a.promptDecisionCh` *before* sending, so a second keypress arriving between the receive at `:667`
and the cleanup closure at `:669` returns early instead of blocking the event loop on a full
buffer. Every abandonment resolves to a deny, never to silence: ESC on the base list
(`:554-556`), ESC on any child chooser through `capturePromptEscape` (`:1015-1021`, installed at
`:737`, `:805`, `:903`), and the central fallback `key_esc.go:122-123` all reach `dismissPrompt`,
which sends `defaultDenyPromptDecision()` (`:1028-1033`) — `OptionDeny` plus the default-reason
envelope from `permissions.BuildDenyEnvelope("")`. The two Program-confirm cancels
(`cancelProgramConfirm` `:820-823` and the compound cancel closure `:926-929`) deliberately send
*nothing*: they remove only the confirm page and restore focus, so `PromptUser` stays blocked and
no grant is created.

**The one-shot guard's unenforced precondition.** `completePrompt`'s nil-check is nested inside
`if a.promptOpen` (`:993`). When `promptOpen` is false the guard is skipped and `:999` sends
unconditionally. That is unreachable today for one specific reason worth stating: the page mount
(`:663`) and `promptOpen = true` (`:661`) happen in the *same* queued closure, so no selection
callback can exist before the flag is set, and the flag is cleared (`:670`) only in the cleanup
closure after the receive. The safety of the guard therefore depends on that closure staying
atomic — a fact no test pins (see **C19**).

**Capacity-one serialization.** `promptGate.slot` is `make(chan struct{}, 1)`
(`promptgate.go:123`); `Build` acquires at `:190` and `defer`s release at `:193`, and the batched
twin reaches the same gate at `authdeps.go:273-277`. Capacity one is not throughput tuning: the
TUI-side prompt state is app-global singletons (`a.promptDecisionCh` `prompt.go:662`, `a.promptPrev`
`:660`, the `"prompt"` page `:663`). With capacity above one, two `PromptUser` calls would overwrite
each other's channel, and one keypress would resolve the *wrong* request while the other blocked
forever at `:667`. Pinned by `TestPromptGate_SerializesConcurrentPrompts`
(`promptgate_test.go:695`, assertions at `:736-738` and `:743-745`) and
`TestPromptGate_CancelWhileWaiting` (`:752`, assertions at `:783-788`).

**Fail-closed rests on the error return, not on a deny default.** Every failure path in
`promptgate.go` returns `permissions.PromptOutcome{}` *with a non-nil error*: unknown subject kind
(`:187-189`), cancelled context (`:190-192` via `:133-141`), `show` error (`:195-197`), unknown
option (`:285-288`). The zero value of that struct is **not** a deny — `PromptAllowOnce` is the
`iota` zero at `orchestrate.go:14`. The behaviour is safe only because both callers check the error
first and return before touching the outcome (`orchestrate.go:233-235`, `dispatch/tool.go:277-279`).
Any future refactor that drops an error check turns a gate failure into an allow.

**Event-loop ownership.** `PromptUser` is the only prompt entry point invoked off the loop. It does
touch tview primitives before its first queue call: `buildPromptOverlay` (called at `:657`, defined
`:455-647`) constructs and configures the preview, facts block, options list and flex on the caller's
goroutine. That is safe because none of it is *shared* yet — nothing is attached to `a.pages` and no
existing primitive is mutated, so the draw loop cannot observe it. What `PromptUser` marshals onto the
loop is every mutation of shared app, page and focus state, through two `QueueUpdateDraw` closures:
the mount and focus hand-off (`:659-665`, including `a.pages.AddPage` `:663` and `SetFocus(list)`
`:664`) and the teardown (`:669-691`). The handlers `buildPromptOverlay` registers (`:502`, `:552`,
`:590`, `:599`) do touch shared state, but only when they fire later, from the loop. Its doc contract
(`:649-654`) is that it must not be called from a tview callback. Everything downstream —
the selected-callbacks, the choosers, `finalizeScope`, `advanceCompoundStage` — already runs *on*
the loop and therefore mutates `pages` and focus directly, which is why none of them queue.
Terminal-focus restoration is the one other prompt-aware loop hop
(`app.go:942-965`, guarded by `running.Load()`).

**Stored-subject derivation.** `PromptDecision.StoredSubject` (`prompt.go:293`) is written from
exactly three sources and never from a display label: the direct-command subject helpers
(`ExactSubject` `prompt_scope.go:101`, `SubcommandSubject` `:110`, and `ProgramSubject` — now
`ProgramSubject` in `internal/permissions/direct_scope.go`, which returns `<program> :*` — attached
to rows at `:144`, `:152`, `:160`); `permissions.EncodeCompoundSubject` for a recognized compound
(`prompt.go:956`, falling back to `""` — the byte-exact concrete subject — when the backend refuses
the shape, `:957-959`); and the passthrough of `req.CapabilityStoredSubject` (`:543`). The byte form
is load-bearing downstream: `isBareWildcardToken` and `matchesDirectScope` in
`permissions/normalize_direct.go` recognize a widened grant only when the last raw token is exactly
`:*`, so the single space in `ProgramSubject`'s `<program> :*` is contractual, and
`permissions/matcher.go:110` keys capability subjects by exact string. An approval shared by two or
more unresolved stages deliberately carries no stored subject, because one choice cannot select a
scope for every stage: the batched prompt offers no chooser (`prompt.go:518-525`) and
`AuthorizeBatch` clears the subject before building each stage's grant
(`orchestrate.go:207-217`). A batch with exactly one unresolved stage is not that case — it renders
the ordinary single-stage prompt with its scope chooser (`bootstrap/authdeps.go:292-295`), so its
selected subject is kept and becomes the grant's subject, while cache keys and events stay on the
stage's own concrete subject.

**Option reachability.** `displayedPromptOptions` (`prompt_folder.go:66-78`) returns *one* slice
that drives both the rendered list (`prompt.go:498-500`) and the index→option mapping
(`:508`), so a hidden folder option is absent from the decision path rather than merely invisible.
`OmitFolderOption` (`prompt_folder.go:51-56`) fails closed: containment must be established
(`permissions.IsDescendantOrEqual`) or the option is dropped unless the caller explicitly opts an
out-of-root write or read scope in. A destructive compound stage is truncated to Exact only
(`prompt_scope.go:233`) with `DefaultIdx` fixed at `0` (`:228`). Pinned by the unreachable-by-index
assertions at `prompt_test.go:2216` and `:2219`, and the containment table at
`prompt_folder_test.go:34`.

**Display wording is never policy.** `capabilityCoveragePhrase` (`prompt.go:260-275`) reads the
matcher's exported member table and returns a sentence; its two consumers write strings only
(`prompt.go:409-413`, `picker_settings.go:370`). Authorization branches on the table and the
subject strings (`matcher.go:110`, `entry.go:85`, `orchestrate.go:301`), never on the phrase. The one
classifier that legitimately spans both is `permissions.IsDestructiveProgram`: copy at
`prompt.go:790`, row suppression at `prompt_scope.go:230`.

**The TUI does not re-validate the request.** `prompt.go:1-5` states it renders caller-supplied,
already-normalized data; the only derivations are eligibility and display
(`OmitFolderOption` at `:416`/`:636`, `CrossModeMarkerNotice` at `:435`). Display strings originate
from model-supplied tool arguments through `dispatch/tool.go:370-393`, which is explicitly
best-effort (`:403-405`). The reverse direction is equally trusting, though it is not the direct
bootstrap-to-disk path it looks like — it runs through the permissions layer in three steps.
`mapOutcome` (`promptgate.go:284-297`) maps the decision into a `permissions.PromptOutcome`, copying
`StoredSubject` only for the three grant-creating options (`:294`) and leaving it empty for allow-once
and deny. `permissions.grant` (`orchestrate.go:281-298`) then calls `buildGrant` (`:307-322`), which
builds the entry: the stored subject becomes the entry's subject, falling back to the request's own
subject when it is empty (`:308-311`), and the argument hash is computed over that resolved subject
(`:319`). Only then does bootstrap persist the resulting entry, unchanged apart from choosing the
folder or global settings file (`authdeps.go:371-379`). No step re-validates the subject string; the
permissions layer selects it, it does not check it. That asymmetry is the design, and no
recommendation below moves validation across it.

### Findings

Each finding is `ID — classification`. Recommendations are consolidated in the table below.

**C1 — retain. `buildPromptOverlay`'s 193 lines.** The function is the largest in the surface. Most
of it is assembly — build preview, build facts, take the *already-filtered* option slice (`:491`),
install the key capture, the draw hook that re-sizes the facts block to its wrapped row count
(`:590-598`), the mouse capture, and the conditional folder-unavailable note (`:636-643`) — with one
load-bearing exception: the selected-callback it wires (`:502-546`) is decision-routing policy, not
assembly. Four guards plus the fall-through send a selection down five distinct routes: deny
finalizes with the default-deny envelope (`:509-516`); a batched request finalizes with the bare
option and opens no scope chooser (`:518-524`); a direct-command grant opens the subject-scope
chooser (`:526-528`); a simple-compound grant opens the per-stage chooser (`:530-535`); and any
other grant is completed inline with the capability stored subject attached (`:537-545`). That
routing is a permission decision boundary, which is why **C19** wants its abandonment paths pinned.
Extraction is still rejected: every candidate sub-unit needs the same three locals (`preview`,
`facts`, `opts`), and `opts` in particular is the one filtered slice that drives the render
(`:498`), the index→option mapping the callback reads (`:508`), and the list height (`:585`), so a
split would replace lexical sharing with parameter threading and let the slice and its index mapping
drift apart. The one genuinely cohesive cluster inside it is the list construction, which recurs
three times and is covered separately by **C12**.

**C2 — retain. The one-shot completion guard.** See *One decision, then default deny*. The guard is
nine lines that prevent a second keypress from blocking the tview event loop on a full buffer, and
`dismissPrompt` repeats the shape rather than calling `completePrompt` because it must also refuse to
fire when no prompt is open (`:1007`). Merging them would either lose that check or make
`completePrompt` responsible for building the deny envelope, which is currently the single
`defaultDenyPromptDecision` source used by both the deny option (`:515`) and every ESC path.
Retained; the missing test is **C19**, not a code change.

**C3 — retain. The capacity-one gate and its two acquire sites.** See *Capacity-one serialization*.
The gate is 31 lines total (`promptgate.go:118-148`) and both its concurrency tests assert observed
behaviour rather than internals. The duplication of the acquire/show/map sequence between
`Build` and the batched path is real and is recorded separately as **C16**.

**C4 — retain, with the hazard recorded. `PromptOutcome{}` is an allow.** See *Fail-closed rests on
the error return*. No change is recommended: making the zero value a deny would require a new
sentinel choice value in `internal/permissions` and would touch the orchestration contract, which is
outside an audit's authority and outside this slice's file budget. What this report can do is name
it, so a future reader does not "simplify" `orchestrate.go:233-235` or `dispatch/tool.go:277-279`
into an outcome-first branch.

**C5 — retain. `renderPromptFacts`' six conditional blocks.** The 76 lines (`prompt.go:367-442`) are
six independent disclosures over already-resolved data, and each one has its own assertion:

- requested target (`prompt.go:372-376`) — `prompt_test.go:125`, in
  `TestRenderPrompt_ExplainsAuthorizationScopeForCreateFile` (`:109-135`);
- run folder vs project root, both the mismatch and the same-folder wording (`:383-393`) —
  `prompt_test.go:567`, `:575`, `:578`, in `TestRenderPrompt_ProjectRootMismatchMarked` (`:565-581`);
- scope-escalation warning (`:399-403`) — `prompt_test.go:591` with the negative case at `:597`, in
  `TestRenderPrompt_ScopeEscalationWarned` (`:586-600`);
- capability coverage (`:409-413`) — `prompt_test.go:1524`, `:1527`, negative at `:1532-1537`, in
  `TestRenderPrompt_CapabilityCoverageWording` (`:1503-1538`);
- folder-grant destination and its coverage sub-line (`:416-426`) — `prompt_test.go:154-155` in
  `TestRenderPrompt_FactsOnlyDurableGrants` (`:137-165`), and again at `:428-432` in
  `TestRenderPromptSplit_PreviewAndFacts` (`:416-445`);
- cross-mode marker notice (`:435-439`) — `prompt_test.go:631` with both suppression cases at `:638`
  and `:645`, in `TestRenderPrompt_CrossModeNoticeOnlyWhenSupplied` (`:625-648`).

The function is pure, which is what lets those tests exist without a running screen. Splitting it by
disclosure would gain nothing and would put the `OmitFolderOption` gate at `:416` further from the
option list it explains.

**C6 — retain. The stored-subject derivation path.** See *Stored-subject derivation*. Three
producers converge on one field, and the compound producer deliberately delegates to the backend
encoder with an empty-string fallback rather than synthesizing an alternative subject
(`prompt.go:955-961`). This is the strongest safety property in the surface and the label/subject
separation is asserted directly (`prompt_scope_test.go:149`, `:363-379`). No consolidation of the
three producers is recommended: they differ in what they are allowed to widen.

**C7 — retain. `compoundStageScopeHelp` re-derives from the offered rows on purpose.**
`compoundStageScopeHelp` (`prompt.go:980-987`) scans `stage.Options` for a `ScopeProgram` row instead
of reading the `NoWiden` flag that `buildCompoundStageScopeOptions` already set (`prompt_scope.go:234`).
That looks like redundant work and is not: deriving the advisory from the rows actually present makes
it impossible for the copy to claim a scope the chooser does not offer, which is exactly the failure
the exact-only notice (`prompt.go:973`) exists to prevent. Rejected as a simplification candidate.

**C8 — simplify locally (declaration). `PromptRequest.SessionScope` is written and never read.**
Declared at `prompt.go:186` — the only field in the 23-field struct with no doc comment — and set at
`promptgate.go:224` from `req.PathScope`, the same value that populates `RunFolder` (`:223`). A
repo-wide grep finds no production reader; the only other occurrences are the field-mapping
expectations in `promptgate_test.go` (11 sites) and fixture literals in `prompt_test.go` (9 sites).
This is dead transport state, not a behaviour: `RunFolder` is the field every renderer consumes
(`prompt.go:416`, `:435`, `:636`). Removing it is a declaration change plus mapping-test edits.

**C9 — retain. `compoundStageScope.NoWiden` is a test handle, not dead state.** The field
(`prompt_scope.go:196`) is set at `:234` and, per **C7**, read by no production code — but it is the
only direct handle the destructive-suppression tests have on the *reason* a stage is exact-only
(`prompt_scope_test.go:221`, `:271`, `:290`, `:312`). Deleting it would force those assertions to
infer intent from row count. Retained as an intentional seam; **C7** forbids the other direction
(routing the help text through it).

**C10 — simplify locally. The `"prompt"` page name is a bare literal.** Its three sibling pages are
constants (`promptScopePage`, `promptScopeConfirmPage`, `promptCompoundPage`, `prompt.go:27-33`), but
the base page is spelled as a literal at `prompt.go:663`, `:684`, and — across files —
`app.go:960`, where the focus-restore switch lists all four page names side by side, three as
constants and one as a string. Eight test sites repeat it (`prompt_test.go:377, 709, 752, 801, 985,
1086, 1179`; `key_esc_test.go:196`). A `promptPage` constant removes a cross-file string coupling
with no behaviour surface.

**C11 — simplify locally (naming). `OmitFolderOption`'s third parameter lies about its meaning.**
The parameter is named `outOfRootFileWrite` (`prompt_folder.go:51`), but no production call site ever
passes the bare write field. Three call it directly with the *combined* verdict
`folderGrantEligibleOutOfRoot()` = `OutOfRootFileWrite || OutOfRootReadScope` (`prompt.go:250-252`,
used at `prompt.go:416`, `:636`, `prompt_folder.go:67`). The fourth, inside `CrossModeMarkerNotice`
(`prompt_folder.go:105`), forwards that function's own `outOfRootFileWrite` parameter — and its sole
production caller, `renderPromptFacts` (`prompt.go:435`), supplies the same combined verdict, so all
four sites see it. No test change follows from this: the two bootstrap sites that pass
`OutOfRootFileWrite` directly (`bootstrap/authdeps_test.go:882`, `:1543`) each assert that field is
true first (`:879-883`, `:1537-1544`), so they cover the write signal only and their expectations
match production for the case they exercise; the read-scope half is pinned separately at
`prompt_folder_test.go:69-85`. The recommendation is the rename of the parameter and its doc
sentence alone — no signature, behaviour, or expectation change.

**C12 — extract. The three chooser construction blocks.** `buildScopeChooser` (`prompt.go:722-745`),
`buildProgramConfirmList` (`:792-813`), and `buildCompoundStage` (`:881-911`) each build the same
widget: a non-dynamic `TextView` above a `List` with `ShowSecondaryText(false)`,
`applyPickerListColors`, per-row `AddItem`, `SetCurrentItem`, `SetInputCapture(a.capturePromptEscape)`,
wrapped in a `FlexRow` with a border and a title. That is roughly 14 duplicated lines per site across
three sites. The rows, the default index, the selected-callback, and the title differ; everything
else does not. Note the shared ESC capture is part of the repetition, which is the safety-relevant
half: a fourth chooser added by copy-paste that forgets `SetInputCapture` would silently lose the
default-deny path.

*Review note, 2026-08-05 — C12 not adopted.* The follow-up task raised from this finding
was cancelled on review. The recommendation trades a Medium risk — a helper that owns
`SetCurrentItem` can change which row a chooser opens on — for roughly 30 lines across three call
sites that are correct today, and its stated benefit is protection for a fourth chooser that does
not exist and is not planned. The copy-paste hazard it describes is real but hypothetical, and the
extraction is cheap to revisit if a fourth chooser is ever added. **C19 is unaffected and remains
worth doing on its own merits**: it pins the one-decision/always-deny guarantee regardless of
whether any chooser construction is ever shared.

**C13 — retain. The asymmetric confirm-page teardown.** The direct-command flow removes the confirm
page inside `finalizeScope` (`prompt.go:830-833`), while the compound flow removes it in the confirm
closure *before* advancing (`:923`). Two different owners for one page name. Unifying them would mean
either giving `finalizeScope` a compound-aware branch or making every caller remove the page first —
both of which move page ownership out of the function that knows whether a decision is being sent.
The current split is safe because `PromptUser`'s cleanup removes any remainder unconditionally
(`:675-683`). Retained; the belt-and-braces cleanup is the reason it is safe, and **C19** notes that
none of those three cleanup branches carries an assertion that would fail if the branch were deleted.

**C14 — rejected (no change). The "unreachable" absolute-path guard.**
`CrossModeMarkerNotice`'s `if !filepath.IsAbs(settingsPath)` (`prompt_folder.go:112-114`) reads as
dead — `settingsPath` comes from `filepath.Join(projectRoot, ...)` and the doc promises an absolute
`projectRoot`. It is not dead, but an empty `ProjectRoot` alone is not enough to reach it. Two earlier
returns stand in the way: the containment/eligibility check `OmitFolderOption(runFolder, projectRoot,
outOfRootFileWrite)` (`prompt_folder.go:105-107`), and the `launch-dir-only` boundary with
`WouldCreateSettingsFile` set (`:108-110`). With an empty root, `OmitFolderOption`
(`prompt_folder.go:51-56`) is false in exactly two shapes: the run folder is *contained* in the
cleaned empty root — `""`, `"."`, or a relative path such as `"sub"`, all of which
`permissions.IsDescendantOrEqual` accepts against `"."` (`permissions/scope.go:55-71`) — or the run
folder is absolute and therefore out of root, with the eligibility flag true (`OutOfRootFileWrite ||
OutOfRootReadScope`, `prompt.go:250-252`). Either shape, under a `launch-dir-only` boundary with a
settings file to create, reaches `filepath.Join("", ".codemeld", "settings.yaml")` — a relative path.
Those inputs are producible: `renderPromptFacts` explicitly tolerates an empty `ProjectRoot`
(`prompt.go:383` skips the project-root block when it is empty) and still calls
`CrossModeMarkerNotice` at `:435`. The guard is the thing that stops a relative settings path from
being announced as a grant destination. Rejected as a removal candidate.

**C15 — defer (investigation, not refactor). `PromptUser` has no running-loop guard.** Every other
*production* off-loop entry point checks `a.running.Load()` before queueing — `streamUpdate`
(`app.go:1801`), `queueModalFocusRestore` (`:943`, re-checked at `:947`), the background notice path
(`:1558`). The one other unguarded caller is the test-only helper `RunOnEventLoopForTest`
(`app.go:1573-1575`), which queues unconditionally and is driven only from `internal/bootstrap`
tests. `PromptUser` calls
`a.app.QueueUpdateDraw` unconditionally (`prompt.go:659`, and again in its teardown at `:669`), and tview's `QueueUpdate` blocks until the
function runs. If the loop has stopped while a tool call is in flight, the calling goroutine parks
forever *while holding the gate permit*, so `promptgate.go:193`'s release never runs and every later
prompt waits in `acquire` until its own context cancels. There is no test for a not-running TUI
(`promptgate_test.go` covers cancel-while-waiting, not loop shutdown). This is flagged, not
recommended: deciding what a prompt should do during shutdown is a behaviour question, not a
maintainability one, and it is outside this audit's authority.

**C16 — defer. The authorization boundary exists twice.** `PromptGateBuilder.Build`
(`promptgate.go:184-200`) and the batched pipeline path (`authdeps.go:267-283`) run the same five
steps — build request, `gate.acquire(ctx)`, `defer release()`, `show(req)`, `mapOutcome` — and the
second reaches across files into the builder's unexported fields (`a.prompts.gate` `:273`, `:276`;
`a.prompts.show` `:277`). Any hardening applied to one (a timeout, a running-loop guard per **C15**,
a fail-closed default per **C4**) silently misses the other. Deferred rather than recommended
because the fix is a `internal/bootstrap` API change, not a `internal/tui` one, and this slice's
authority stops at recording it.

**C17 — simplify locally (comments only). The prompt comment cluster has decayed.** Concrete,
non-speculative instances, all in the prompt files:
*Broken sentences left by stripped subjects* — `prompt.go:194` ("`('s project-root carve-out)`"),
`:433` ("or when has hidden"), `:487` ("when 's containment rule hides it"), `:632` (" places the
folder-unavailable explanation"), `prompt_folder.go:90` (same possessive, inside a bullet list whose
`-` marker is also missing, `:85-91`), `prompt_scope.go:169` (sentence ends on the dangling word
"matching."). The same artifact appears in the tests at `prompt_test.go:635`, `:1932-1934`, `:2050`.
*Statements that no longer match the code* — `prompt.go:255-257` names the read capability's members
as "read + grep + glob + list + tree", but the table at `permissions/capability.go:20` also contains
`file_count`, and the doc omits `CapabilityWriteTree` entirely although the switch handles it
(`:269-270`); `prompt_scope.go:114-115` documented `ProgramSubject` as returning `` `<program>:*` ``
while the code returned `<program> :*` (now produced by `ProgramSubject` in
`internal/permissions/direct_scope.go`, and since corrected in the prompt comments), and the space
is what lets `:*` arrive as a standalone token for the bare-wildcard check in
`permissions/normalize_direct.go` (`isBareWildcardToken`, `matchesDirectScope`); `prompt.go:74`
calls them "the five options" where four are routinely rendered (`prompt_folder.go:66-78`); `picker_settings_test.go:5-6` says there is "no
production registration" although `bootstrap/starttui.go:269` and
`internal/tui/registry.go:412` now register it.
*Process references in production comments* — 17 references in the two focused prompt files, of two
kinds: nine internal task ids (`prompt_scope.go:186, 207, 209`; `prompt_folder.go:6` and `:100`,
which carry two each, plus `:23`, `:45`) and eight ADR identifiers (`prompt_scope.go:26, 38, 43`;
`prompt_folder.go:17, 37, 41, 59, 81`). Add the task-history line at `prompt.go:466` ("the bug this
task fixes"). The project's comment rule forbids internal process references of either kind.
*A dead default the doc does not mention* — `capabilityCoveragePhrase`'s `verb := storedSubject`
fallback (`prompt.go:265`) cannot fire: `CapabilityMembers` returns `ok` for exactly the three keys
the switch below covers (`capability.go:17-21`).

**C18 — consolidate test setup. `prompt_test.go` runs six copies of one event-loop scaffold.**
Four verbatim blocks recur: the 13-line attach barrier (`:374-386`, `:706-718`, `:798-810`,
`:982-994`, `:1083-1095` — five byte-identical copies), the loop-start plus `PromptUser` goroutine
(`:362-372`, `:692-703`, `:780-790`, `:967-977`, `:1069-1079`, `:1166-1177` — six copies), the
await/stop/`errc` teardown (`:393-404`, `:722-734`, `:858-869`, `:1037-1048`, `:1114-1125`,
`:1210-1221` — six copies, two of which differ only in message strings), and the 21-line
"cancel produces no decision" block (`:1339-1359` vs `:1843-1863`, differing in four message
lines). The file already contains the extraction that would absorb them — `promptHarness`/`startPrompt`
(`:1156`, declared at `:1164`, 18 call sites in this file; 20 across `internal/tui/*_test.go`, the
other two being `key_esc_test.go:185` and `overlay_background_test.go:129`) — alongside a superseded first attempt, `runPromptApp` (`:689`,
one call site), and a dead helper `typeText` (`:1206`, zero call sites). Three tests (`:769`,
`:951`, `:1056`) plus `:360` use neither harness. The consolidation is arrange-only and must not
touch an assertion; two things must stay inline because they double as the oracle: the
`permissions.SimpleCompound` stage literals (`:1641-1644` and five siblings), whose stage strings are
deliberately re-typed into the expectations at `:1665-1668`, `:1722`, `:1784`, `:1873`, and the
option-label lists.

**C19 — test coverage. The one-shot guard and all three cleanup branches are unpinned.** No test in
`internal/tui` names `completePrompt`, `dismissPrompt`, or `promptDecisionCh`; nothing injects a
second Enter or ESC after a decision, so the guard at `prompt.go:993-999` — and the closure-atomicity
argument that makes it sufficient — is unprotected. None of the three leftover-page cleanup branches in
`PromptUser` (`prompt.go:675-683`) is pinned by an assertion that would fail if the branch were
deleted. Two kinds of near-miss are worth separating. One child-page check *is* post-decision: the
batched-grant test asserts `promptScopePage` is absent after the decision arrives and the loop has
stopped (`prompt_test.go:411-413`) — existing coverage, but of a chooser that this flow never opens,
so it is vacuous with respect to the cleanup branch at `:678-680` and deleting that branch would not
fail it. Every other child-page check is mid-flow: the compound-page-present assertion (`:1695`) and
the two cancel polls that wait for the confirm page to disappear (`:1349`, `:1853`), which run before
any decision is sent. The two compound ESC-dismissal tests (`:1733`, `:1795`) do execute the compound
and confirm cleanup branches, but assert only on the returned decision, so a deleted `RemovePage`
would strand the overlay and still pass. The only page whose absence is asserted after `PromptUser`
has returned is `"prompt"` itself (`prompt_test.go:752`, `key_esc_test.go:196`).
ESC on the non-compound scope chooser (`prompt.go:737`) has no deny test,
although the compound equivalents do (`prompt_test.go:1747`, `:1812`). The event-loop contract is
also unpinned: every `QueueUpdate` in the prompt tests that observes prompt state is a read barrier
(`:377`, `:709`, `:801`, `:985`, `:1086`, plus the `hasPage`, `focusedPrimitive` and
`focusedListItem` helpers at `:1200`, `:1236`, `:1243-1250`). The one exception is not an
observation and not a barrier: `:1694-1699` queues a mutation, setting focus to the input to stage
the stale-focus case. No test *deterministically* pins that
`PromptUser` queues its two setup mutations — `pages.AddPage("prompt", …)`
(`prompt.go:663`) and `SetFocus(list)` (`:664`), both inside the `QueueUpdateDraw` at `:659-665`.
The gap is the missing assertion, not a total absence of detection: `startPrompt` runs `PromptUser`
on its own goroutine (`prompt_test.go:1173-1176`) while `a.app.Run()` is live on another (`:1170`),
so replacing those queued mutations with direct off-loop writes is an unsynchronized access the race
detector can flag. That signal is incidental — it depends on the detector observing the interleaving,
and the everyday gate is `test-fast`, which runs without `-race` (`mise.toml:69-71`); only `mise run
test` and `check-race` carry it (`:65-67`, `:32`).
The mirror contract is pinned for `HandleEsc` (`key_esc_test.go:79-98`) and for nothing else, even
though `PromptUser`'s own doc states the rule (`prompt.go:649-654`). Finally, the base-prompt ESC default-deny test lives outside the
prompt files, in `key_esc_test.go:182-199` — correct, since that is the central ESC path, but it
means `prompt_test.go` alone does not cover the surface's most important guarantee.

**C20 — simplify locally (tests). Four determinism and pairing problems.** A map-iterated table
(`prompt_test.go:448-455`) makes failure order vary between runs — the same problem **B8** recorded
for `picker_model_test.go`. One parallel expectation pair is only half length-checked:
`wantLabels`/`wantOptions` (`:54-63`) are read under the same loop index (`:67`) at `:69` and `:72`,
so they are correctly paired, but only `wantLabels` has a length assertion (`:64-66`, against
`promptOptionsInOrder`). An unexpectedly short `wantOptions` therefore panics with an
index-out-of-range at `:71` instead of failing on the value it was meant to check.
The adjacent `wantCommands`/`wantKinds` declaration
(`prompt_scope_test.go:215-216`) is *not* a second such pair — `wantCommands` is indexed by the stage
index (`:218`) and `wantKinds` by the inner row index (`:230`), so they describe different dimensions
and must stay separate. The same option-label list is
re-declared three times (`prompt_test.go:54-63`, `:2006-2011`, `:2137-2143`).
Eleven `time.Sleep(5ms)` spin-polls stand in for the `waitDraw` afterDraw barrier
that already exists (`harness_test.go:55`) and two 200 ms fixed waits serve as negative assertions
(`:1344`, `:1848`). Separately, `prompt_scope_test.go` asserts against the real copy constants while
`prompt_test.go` re-types the same strings as literals (`"authorizes ANY invocation"` at `:1399`,
`:1411`, `:1654`, `:1913`; `"Exact scope only"` at `:1916`, whose constant `compoundExactOnlyNotice`
is referenced by no test).

**C21 — simplify locally. `picker_settings.go`'s unread session field and duplicated guards.**
`permissionsPickerSession.body` (`picker_settings.go:60`) is assigned at `:116` and read nowhere —
the local `body` variable is what gets mounted at `:119`. The same file repeats the
`pp := a.permissionsPicker; if pp == nil { return }` guard four times (`:145-148`, `:156-159`,
`:285-288`, `:299-302`) and the active-tab row selection twice (`:162-165`, `:214-217`). These are
small, but they sit inside **B13**'s file set, so they are cheap to fold into that change.

**C22 — A12 answered. Seventeen test-only exported `App` methods in `app.go`, and the gate cannot
see them.** The sweep of A12's file finds **17**, not the eighteen A12 estimated: `StatusLineText:867`, `ModeHintText:901`,
`SetScreenFactoryForTest:1569`, `RunOnEventLoopForTest:1573`, `SubmitInput:1829`, `SeedInput:1840`,
`InputText:1847`, `PressCtrlE:1856`, `PressCtrlM:1867`, `SetClipboardReader:1878`, `PressCtrlV:1886`,
`SubmitCurrent:1896`, `PressTab:1908`, `StatusText:1922`, `PermissionsOverlayText:1937`,
`TranscriptText:1960`, `NoticeText:1967`. **Fifteen** of the 17 carry a doc comment ending "this is
never called at runtime"; the two exceptions are `SetScreenFactoryForTest:1569` and
`RunOnEventLoopForTest:1573`, which sit back-to-back with **no doc comment at all** and so document
neither their test-only status nor the lifecycle constraint they carry. That is a documentation gap
in its own right, folded into **C17**'s comment pass. Every one of the 17 is driven by
`internal/bootstrap/*_test.go` — several *only* from
there (`PressCtrlE` by `starttui_test.go:356` alone, `PermissionsOverlayText` by
`tui_commands_test.go` alone, `NoticeText` by a single call site). They are therefore
cross-package seams, not dead code, and **A12's deferral resolves to: leave them, they are the
`internal/bootstrap` integration surface** — with the two undocumented ones given the doc sentence
the other fifteen already have. (A12 scoped itself to `app.go`; eleven further test-only exported
`App` methods live in the picker, secret-prompt, and indicator files under their own doc wording,
outside this hand-off.) Two facts belong on the record. First, none of them is in
`.deadcode-allow` — which has *no* `internal/tui/app.go` entries at all — and
`scripts/deadcode-check.sh` does not report them, so the allowlist policy ("each entry is an
intentional test-only seam") is not what is keeping them quiet; `*tui.App` is converted to interfaces
in bootstrap (`turndeps.go:164-189`), and the analyser treats such a type's method set as
potentially reachable. The reachability gate structurally cannot audit this class of seam, which is
why it needed a manual sweep. Second, the lock contract inside the class is inconsistent:
`NoticeText` takes `a.transcript.mu` directly (`app.go:1967-1971`) — A12's flagged encapsulation
leak, confirmed — while `PressTab` returns the same `a.transcript.notice` field with no lock at all
(`app.go:1912`). `indicatorStopped` (`app.go:210`) is a struct *field*, not a method, so no
reachability tool would ever report it; it is written at `app_indicator.go:44` and read only by
`indicator_test.go:252`.

**C23 — B14 answered. The overlay documentation gap is real and slightly worse than described.**
`anyOverlayOpen` checks twelve flags (`app.go:939`); its doc comment (`:933-937`) names eight,
omitting `secretPromptOpen`, `slashPickerOpen`, `connectPickerOpen`, and `permissionsPickerOpen` —
confirming B14. `dismissOpenOverlay` (`key_esc.go:91-130`) dispatches ten of the twelve;
`secretPromptOpen`'s absence *is* explained inline (`:124-125`, pointing at the earlier branch at
`:31-36`), and `resumePickerOpen`'s absence is explained nowhere — not at the switch, not in
`HandleEsc`'s doc (`:11-21`), not in the file header. Its ESC really is owned locally
(`picker_resume.go:119`, handler `:177-190`), which makes the resume picker the one overlay on a
different model. One more inversion belongs to this slice: the permissions branch comment
(`key_esc.go:104-106`) says "the revoke-confirmation child owns ESC locally", but the child
explicitly disclaims it — `permissionsDeleteKeys`' own doc says "ESC never reaches here — the
app-level capture routes it to the central dismiss path first"
(`picker_settings.go:266-269`), and the routing decision is the page-presence probe at
`key_esc.go:107-111`. The comment describes the *resume* model while the code implements the central
one. All three are comment-only corrections; the ESC priority order itself is load-bearing and must
not move.

**C24 — dead-code evidence. The gate passes, and 111 of 129 allowlist entries are stale.**
`scripts/deadcode-check.sh` exits 0: `deadcode` reports 18 unreachable functions and all 18 are
allowlisted, so there is **no removable, non-allowlisted dead code**. The 18 split into three
documented classes exactly as the script's policy intends, matching the consolidated verification
table below: six intentional test-only seams (`internal/fsutil` `SetSyncFileForTest`,
`SetSyncDirForTest`, `SetRenameNoReplaceAtForTest`, `SetBeforeMoveRenameForTest`; the two
`HeadlessDriver` flag accessors); four of deliberately deferred behaviour
(`internal/sessionfork`'s fork functions, dead while `sessions.ReaderSupportedVersion == 1`); and
eight of not-yet-integrated foundation (`internal/tui/cmd_compact.go`'s four unregistered handler
helpers plus `turn/request.go BuildCompactionSummaryRequest`, `provider_refresh.go
RefreshOutcome.String`, and `filetools/readresolve.go IsDirectorySymlink` and `ClassifyEntry`).
The finding the gate cannot produce is the inverse one: **111 of the 129 allowlist entries are no
longer reported**, i.e. their "remove this line once X lands" condition has been met (or the function
is gone). Three of those are this slice's own surface and are now demonstrably reachable from
production: `internal/tui/prompt_scope.go buildCompoundStageScopeOptions` (called at
`prompt.go:845`), `internal/permissions/compound.go EncodeCompoundSubject` (`prompt.go:956`), and
`internal/permissions/capability.go CapabilityMembers` (`prompt.go:261`); the twelve
`picker_settings.go` / `cmd_settings.go` entries are in the same state now that
`starttui.go:269` and `registry.go:412` register the overlay. The script only fails on findings
*missing* from the allowlist, so a stale entry is invisible to it forever, and the file's own header
("keep this list tiny — a growing allowlist is a smell") is the policy that this drift defeats.
Recorded only: this slice is forbidden from editing `.deadcode-allow`, and an allowlist entry is
never deletion authority for the function it names.

**C25 — retain. `B4`'s flagged `ResumeDeps.Fork` is a live seam for dormant behaviour.** Confirmed
as slice B predicted: the field (`cmd_resume.go:199`) has one call site (`:380`), is wired in production
to a documented no-op (`bootstrap/resumedeps.go:48`, `:383`), and is unreachable only because
`sessions.ReaderSupportedVersion == 1` (rationale at `resumedeps.go:373-382`, matching the
`internal/sessionfork` allowlist block). Four tests drive the branch by forcing the fake loader's
`older` flag *and* asserting the fork call: the `"older schema"` subtest of
`TestResumeHandler_NoReplayWhenSwitchDoesNotCommit` (`cmd_resume_test.go:625-642`, flag at `:630`),
`TestResumeHandler_OlderSchemaOffersFork` (`:913-941`), `…PreservesInFlightStream` (`:951-988`), and
`…FlushesCommandEvent` (`:999-1033`). A fifth site forces the flag without asserting fork behaviour —
the `"older schema"` row of `TestResumeHandler_NonSwitchingBranchesDoNotCancelOrWait` (`:550-553`),
which pins the no-cancel/no-wait invariant. Two further citations are neither: `:180` is the
`fakeForker.OfferFork` double, and `bootstrap/resumedeps_test.go:633-641` pins the *production*
seam's no-op contract with no loader and no `older` flag at all. It is not dead code and not a
removable seam.

### Recommendations (slice C)

| ID | Class | Affected files and symbols | Evidence | Expected benefit | Risk | Preserved behaviour | Non-goals | Follow-up task justified? |
|----|-------|----------------------------|----------|------------------|------|---------------------|-----------|---------------------------|
| C17 | simplify locally (comments) | `internal/tui/prompt.go:194, 255-257, 265, 433, 466, 487, 632`; `prompt_scope.go:26, 38, 43, 114-115, 169, 186, 207, 209`; `prompt_folder.go:6, 17, 23, 37, 41, 45, 59, 81, 85-91, 100`; `app.go:1569, 1573` (missing seam docs per **C22**); tests `prompt_test.go:635, 1932-1934, 2050`; `picker_settings_test.go:5-6` | Six broken sentences from stripped subjects, four statements contradicted by the code at the time (`capability.go:20`, the `ProgramSubject` form produced by `permissions/direct_scope.go`, `prompt_folder.go:66-78`, `starttui.go:269`), 17 internal process references (nine task ids and eight ADR identifiers), one task-history line, two undocumented test seams | The authorization surface's comments stop misdescribing what the code does; the repo's no-process-references rule holds here too | Very low — comment text only; no `//go:` directives involved | Every statement that is still true, especially the fail-closed and label-never-becomes-subject explanations | Do not delete a comment that records a non-obvious invariant; do not "fix" `prompt.go:265` by deleting the fallback branch without checking `capability.go:17-21` | **Yes** — comment-only, mechanical, no test impact |
| C10 | simplify locally | `internal/tui/prompt.go:663, 684`; `app.go:960`; tests `prompt_test.go:377, 709, 752, 801, 985, 1086, 1179`, `key_esc_test.go:196` | Three sibling page names are constants (`prompt.go:27-33`); the base page is a literal at 3 production and 8 test sites, including a switch that mixes both forms | One name for the page the focus-restore switch and both teardown paths share | Very low — a constant introduction | The page name string itself (`"prompt"`) must not change: `restoreModalFocusOnTerminalFocus` matches on it | Do not rename the page; do not fold the four page constants into a slice | **Yes** — bundle with C11 |
| C11 | simplify locally (naming) | `internal/tui/prompt_folder.go:51` `OmitFolderOption` param and doc `:36-50`; callers `prompt.go:416, 636`, `prompt_folder.go:67, 105` | Three callers pass `folderGrantEligibleOutOfRoot()` (`prompt.go:250-252`) directly (`prompt.go:416, 636`, `prompt_folder.go:67`); the fourth (`prompt_folder.go:105`, inside `CrossModeMarkerNotice`) forwards its own parameter, which its only production caller `renderPromptFacts` (`prompt.go:435`) supplies as the same combined verdict. No production site passes the bare write field | The parameter name stops contradicting every caller | Very low — parameter name and doc text only; no signature, behaviour, or test change | The fail-closed containment rule and the out-of-root re-enable for writes *and* reads | Do not change the signature shape or the containment logic; do not merge the two out-of-root request fields; do not change `authdeps_test.go:882, 1543`, which correctly cover the write signal only | **Yes** — bundle with C10 |
| C8 | simplify locally (declaration) | `internal/tui/prompt.go:186` `PromptRequest.SessionScope`; writer `internal/bootstrap/promptgate.go:224` and its comment `:207`; expectations `promptgate_test.go` (11 sites), fixtures `prompt_test.go` (9 sites) | No production reader anywhere; duplicates `RunFolder` (`promptgate.go:223`), the field every renderer actually consumes | Removes a field that a reader must otherwise assume is meaningful in an authorization struct | Low–medium — touches a cross-package struct and a field-mapping test table | The mapping of `req.PathScope` onto `RunFolder`, which is what `OmitFolderOption` and `CrossModeMarkerNotice` read | Do not remove `RunFolder`; do not repurpose the field instead of deleting it | **Yes** — small, but it crosses `internal/tui` and `internal/bootstrap`, so it needs its own task |
| C12 | extract | `internal/tui/prompt.go` `buildScopeChooser:722-745`, `buildProgramConfirmList:792-813`, `buildCompoundStage:881-911` | Same list+flex construction three times (~14 lines each), including the shared `SetInputCapture(a.capturePromptEscape)` that carries the ESC-to-deny path | ~30 lines removed and one place where a new chooser inherits the ESC capture by construction | Medium — the three differ in rows, default index, callback, and title; a helper that hides `SetCurrentItem` could change which row opens | Each chooser's default row (Subcommand-when-offered `prompt_scope.go:176`, confirm-index-0 `prompt.go:797`, compound Exact `prompt_scope.go:228`) and the ESC capture on every list | Do not unify the selected-callbacks; do not give the helper a default-index policy; do not merge the three `SetTitle` strings | **Not adopted** (2026-08-05) — the follow-up task was cancelled on review; see the review note under the C12 finding. C19 stands on its own |
| C21 | simplify locally | `internal/tui/picker_settings.go:60, 116` (`body`), guards `:145-148, 156-159, 285-288, 299-302`, tab selection `:162-165, 214-217` | `body` assigned once, read never; the nil guard is four verbatim copies; the tab-row selection is two | Removes a field that suggests state the session does not keep | Low — local to one file | The read-only mode (`revoke == nil`) and the highlighted-row → entry mapping used by the revoke confirm | Do not merge the guards that also test `pp.list`/`pp.revoke` (`:210-213`, `:231-234`) into the plain one | **Yes**, bundled with **B13** — same file, same change window |
| C19 | test coverage | `internal/tui/prompt.go` `completePrompt:992-1000`, `dismissPrompt:1006-1013`, cleanup branches `:675-683`, scope-chooser ESC seam `:737`, queued setup mutations `:659-665` (`AddPage` `:663`, `SetFocus` `:664`); test home `prompt_test.go` | Zero tests name the guard symbols; the one post-decision child-page assertion (`prompt_test.go:411-413`) is vacuous because that flow never opens the chooser, and every other child-page check is mid-flow (`:1695`, `:1349`, `:1853`), so no cleanup branch would fail on deletion; ESC-deny is covered for compound (`:1747`, `:1812`) but not for the scope chooser; no deterministic assertion pins `PromptUser`'s queueing of both setup mutations — the live-loop harness (`prompt_test.go:1170`, `:1173-1176`) leaves direct off-loop writes to incidental `-race` detection, which the everyday `test-fast` gate does not run (`mise.toml:69-71`) — and the mirror contract is pinned for `HandleEsc` alone (`key_esc_test.go:79-98`) | Pins the surface's most important guarantee — one decision, every abandonment is a deny, and the overlay is mounted and torn down on the event loop | Low — additive tests | The default-deny envelope, the single-send guard, the page-cleanup set, and `PromptUser`'s off-loop queueing of *both* setup mutations | Do not weaken the guard to make a test easier; do not move the existing `key_esc_test.go:182` test out of the central ESC file; do not satisfy the cleanup half with an assertion that passes when the branch is deleted | **Yes** — small additive test task, and a prerequisite for C12. **Acceptance**: not complete until it covers all four — the one-shot guard, the scope-chooser ESC deny, each of the three cleanup branches by an assertion that fails when that branch is removed, and a test proving both `PromptUser` UI mutations (`prompt.go:663`, `:664`) are still queued when `PromptUser` is invoked off the event loop |
| C18 | consolidate test setup | `internal/tui/prompt_test.go`: attach barrier (5 copies), loop+goroutine (6), teardown (6), cancel block (2); existing `promptHarness:1156`/`startPrompt:1164`; superseded `runPromptApp:689`; dead `typeText:1206` | ~150 duplicated arrange/teardown lines against a harness that already exists and is used 18 times in this file (20 across `internal/tui/*_test.go`) | Removes the duplication and the second, superseded harness | Medium — these drive a real tview loop; a shared fixture can mask a per-test setup difference | Every assertion; the `SimpleCompound` stage literals (`:1641-1644` and siblings) that double as expectations at `:1665-1668, 1722, 1784, 1873`; the option-label lists | Do not fold assertions into the harness; do not replace the attach barrier with a sleep; do not touch the literals that are oracles | **Yes**, scoped to arrange-only with a diff that touches no assertion — bundle with **A13**/**B15** |
| C20 | simplify locally (tests) | `internal/tui/prompt_test.go:54-63, 69, 72, 448-455, 1344, 1848, 2006-2011, 2137-2143`, 11 `time.Sleep` sites; `prompt_scope_test.go:215-216`; barrier `harness_test.go:55` | One map-iterated table, one parallel-array pair correctly indexed but only half length-checked (`prompt_test.go:54-63`, read at `:69` and `:72` under the same index, with a length assertion for `wantLabels` at `:64-66` and none for `wantOptions`, so a short `wantOptions` panics at `:71`; the adjacent `prompt_scope_test.go:215-216` arrays are indexed at different loop depths and are not a pair), two 200 ms negative waits, and copy asserted as literals where constants exist | Deterministic failure order and expectations that cannot pass by construction | Low–medium — rewriting a wait can change what a test actually observes | The negative assertions' meaning (no decision was sent) and the exact expected copy | Do not convert the paired accept/reject cases into a table that loses the pairing; do not assert copy through the constant where the test's point is the rendered string | **Yes**, bundle with C18 |
| C16 | defer | `internal/bootstrap/promptgate.go:184-200` `Build`; `internal/bootstrap/authdeps.go:267-283` batched path reaching `a.prompts.gate/show` at `:273, 276, 277` | Same five-step boundary twice; the second bypasses the builder's API | One place to harden the authorization boundary | Medium–high — it is the authorization path; both callers are behaviour-pinned by `promptgate_test.go:695, 752` and the batch tests at `:415-470` | Capacity-one serialization, the ctx-gated acquire, and the outcome mapping | Do not change the gate's capacity; do not merge the single and batched *request builders*, which legitimately differ | Deferred — an `internal/bootstrap` change, outside this slice's authority |
| C15 | defer (investigation) | `internal/tui/prompt.go:659` (unguarded `QueueUpdateDraw`) vs `app.go:943, 1558, 1801`; permit release `internal/bootstrap/promptgate.go:193` | Every sibling *production* off-loop entry point guards on `running.Load()` — the only other unguarded caller is the test-only `RunOnEventLoopForTest` (`app.go:1573-1575`); a stopped loop parks the caller and permanently loses the permit; no test covers a not-running TUI | Would close a shutdown-time hang path | High to decide, low to describe — what a pending prompt *should* do at shutdown is a product question | The blocking contract (`PromptUser` must not return before a decision) and the default-deny envelope | Do not add a running-guard that returns a zero `PromptDecision` — the zero option is `OptionAllowOnce` (`prompt.go:61`) | Deferred — behaviour question, not maintainability; record only |
| C1 | retain | `internal/tui/prompt.go` `buildPromptOverlay:455-647`, selected-callback `:502-546` | Assembly sharing three locals, plus a five-route selected-callback that is decision-routing policy (`:509`, `:518`, `:526`, `:530`, `:537-545`); the only cohesive repeat inside it is C12's list construction | None — extraction trades lexical sharing for parameter threading | A split invites the option slice and the index mapping drifting apart, which is the reachability guarantee | The single `opts` slice driving both render and mapping (`:491`, `:498-500`, `:508`) | Do not split by widget; do not compute options twice | No |
| C2 | retain | `internal/tui/prompt.go` `completePrompt:992-1000`, `dismissPrompt:1006-1013`, `defaultDenyPromptDecision:1028-1033` | Two senders, one buffered channel, both nil the handle before sending; `dismissPrompt` additionally refuses when no prompt is open | None — merging loses either the open-check or the single deny-envelope source | A merged sender could block the event loop on a second send | Single-send-per-prompt and the identical deny envelope for the deny option and every ESC | Do not merge the two senders; do not build the envelope at the call sites | No — but see C19 |
| C4 | retain (hazard recorded) | `internal/bootstrap/promptgate.go:187-197, 285-288`; `internal/permissions/orchestrate.go:14, 233-235`; `internal/dispatch/tool.go:277-279` | `PromptOutcome{}.Choice == PromptAllowOnce`; every gate failure returns that struct with a non-nil error | None here — a deny sentinel is a permissions-package contract change | Any refactor that reads the outcome before the error converts a gate failure into an allow | The error-first check at both call sites | Do not restructure either caller to branch on the outcome first; do not introduce a sentinel in this audit | No — record only |
| C5 | retain | `internal/tui/prompt.go` `renderPromptFacts:367-442`; tests `prompt_test.go:109-135, 137-165, 416-445, 565-581, 586-600, 625-648, 1503-1538` | Six independent disclosures, each with its own assertion — requested target `prompt_test.go:125`, root mismatch `:567, 575, 578`, escalation `:591` (negative `:597`), capability coverage `:1524, 1527` (negative `:1532-1537`), folder-grant destination `:154-155` and `:428-432`, cross-mode notice `:631` (suppressed `:638`, `:645`); purity is what lets them be asserted without a screen | None — a split separates the folder gate at `:416` from the option list it explains | Losing purity would force the disclosure tests onto a live loop | Disclosure order, the mismatch marker, and the `CrossModeMarkerNotice` gate staying inside the renderer | Do not move the notice decision to the caller; do not make the function take the App | No |
| C6 | retain | `internal/tui/prompt.go:543, 834, 955-961`; `prompt_scope.go:101-118, 139-163` | Three producers, one field, no label ever becomes a subject; the compound path defers to the backend encoder and falls back to byte-exact | None — the three differ in what they may widen | A shared "subject builder" would have to pick one widening policy | The `:*` byte form (`ProgramSubject` in `permissions/direct_scope.go`; recognized by `isBareWildcardToken` and `matchesDirectScope` in `permissions/normalize_direct.go`), the empty-string fallback, and the batched no-subject rule | Do not unify the three producers; do not synthesize a compound subject when the encoder refuses | No |
| C7 | retain | `internal/tui/prompt.go` `compoundStageScopeHelp:980-987`; flag `prompt_scope.go:196, 234` | The advisory is derived from the rows actually offered, so it cannot claim a scope the chooser withholds | None — reading `NoWiden` instead would be shorter and less safe | A destructive stage could show the Program breadth warning with no Program row | Copy derived from offered rows | Do not route the help text through `NoWiden` | No |
| C9 | retain | `internal/tui/prompt_scope.go:196` `NoWiden`; assertions `prompt_scope_test.go:221, 271, 290, 312` | Production never reads it, but it is the only direct handle the destructive-suppression tests have | None — deleting it forces those assertions to infer intent from row count | The tests would silently weaken to a row-count check | The destructive stage's exact-only truncation (`:233`) and fixed `DefaultIdx` (`:228`) | Do not delete it as "unused"; do not make production read it (C7) | No |
| C13 | retain | `internal/tui/prompt.go` `finalizeScope:829-835` vs `showCompoundProgramConfirm:919-933`; cleanup `PromptUser:675-683` | Two owners for one confirm page, made safe by the unconditional cleanup in `PromptUser` | None — unifying moves page ownership away from the function that knows whether a decision is sent | A compound-aware branch inside `finalizeScope` would couple the two flows | The unconditional removal of all three child pages before focus restore | Do not unify the two teardown owners; do not drop the cleanup in `PromptUser` | No — but C19 should cover the untested cleanup branches |
| C14 | retain (rejected candidate) | `internal/tui/prompt_folder.go:104-118`, early returns `:105-107, 108-110`, guard `:112-114`, `OmitFolderOption:51-56`; caller `prompt.go:383, 435` | An empty `ProjectRoot` is necessary but not sufficient: the guard is reached only past the `OmitFolderOption` early return (`:105-107`) and the `launch-dir-only` + create gate (`:108-110`) — so a contained/relative run folder, or an out-of-root one with the eligibility flag set, plus that boundary. `renderPromptFacts` explicitly tolerates the empty root, so those inputs are producible | None — the "dead branch" reading is wrong | Removing it lets a relative settings path be announced as a grant destination | The empty-`ProjectRoot` path through `renderPromptFacts` | Do not remove the `IsAbs` check | No |
| C22 | retain (A12 resolved) | `internal/tui/app.go:867, 901, 1569, 1573, 1829, 1840, 1847, 1856, 1867, 1878, 1886, 1896, 1908, 1922, 1937, 1960, 1967`; field `:210`; `.deadcode-allow` | 17 `app.go` methods with zero production callers, each driven from `internal/bootstrap/*_test.go`; 15 self-documented, `:1569` and `:1573` carrying no doc comment (handed to C17); none allowlisted, none reported by the gate | None — they are the cross-package integration surface | Removing any of them breaks `internal/bootstrap` tests that assert on the assembled app | Cross-package test reachability | Do not delete them; do not add them to `.deadcode-allow` (the gate does not report them, so an entry would be inert) | No — the sweep is the deliverable. The lock inconsistency between `NoticeText:1967` and `PressTab:1912` is worth a one-line note in a future touch, not a task |
| C23 | simplify locally (comments, B14 resolved) | `internal/tui/app.go:933-937` doc; `internal/tui/key_esc.go:91-130` (missing `resumePickerOpen` note) and `:104-106` (inverted ownership claim); cross-refs `picker_resume.go:119, 177-190`, `picker_settings.go:266-269` | The comment names 8 of 12 flags; `secretPromptOpen`'s omission is explained and `resumePickerOpen`'s is not; the permissions comment states the opposite of the code | A reader stops concluding that a missing branch is a bug, or that the delete modal owns ESC | Very low — comment text only | ESC priority order, the resume picker's local capture, and the page-presence probe for `permissions-delete` | Do not add `resumePickerOpen` to `dismissOpenOverlay`; do not move the resume ESC handling; do not build an overlay registry | **Yes** — comment-only, and it closes B14's actionable half |
| C24 | retain (evidence only) | `scripts/deadcode-check.sh`; `.deadcode-allow` (129 entries); `docs/deadcode-process.md` | Gate exits 0; 18 findings, all allowlisted; 111 allowlist entries no longer reported, including this slice's `buildCompoundStageScopeOptions`, `EncodeCompoundSubject`, and `CapabilityMembers` | Pruning the stale entries would restore the file's stated "keep this list tiny" property | Low per entry, but each removal must be re-verified against a live `deadcode` run, not against this snapshot | The allowlist's role as documentation of *why* a function is unreachable; allowlisting is never deletion authority | Do not edit `.deadcode-allow` in this audit; do not delete a function because its allowlist entry is stale — stale means *reachable* | **Yes** — an allowlist-pruning task, separate from this audit |
| C25 | retain (B4 resolved) | `internal/tui/cmd_resume.go:199` `Fork`, call site `:380`; `internal/bootstrap/resumedeps.go:48, 373-383`; tests `cmd_resume_test.go:630, 913, 951, 999`, `resumedeps_test.go:633` | Production no-op documented against `sessions.ReaderSupportedVersion == 1`; four tests force the loader's `older` flag and assert the fork call, a fifth forced-flag case (`cmd_resume_test.go:550-553`) pins the non-switching invariant, and the production seam has its own no-op test | None — it is dormant behaviour with a live seam | Removing it deletes the older-schema branch the reader will need at the next schema version | The older-schema branch's checkpoint flush before the fork offer (`cmd_resume.go:374-379`) | Do not delete the field or the branch; do not make the fork unconditional | No |

### Hand-off items closed

- **A12** → **C22**. Resolved as *retain*: 17 (not 18) test-only exported `App` methods in `app.go`,
  all `internal/bootstrap` seams, 15 of them carrying the seam doc comment and two
  (`SetScreenFactoryForTest:1569`, `RunOnEventLoopForTest:1573`) carrying none — that gap is handed
  to **C17**'s comment pass, not left as a claim of full documentation. The dead-code gate cannot
  see any of them, so this manual sweep is
  the record. The `NoticeText` lock reach-through is confirmed and, alongside `PressTab`'s unlocked
  read of the same field, noted for a future touch rather than a task.
- **B14** → **C23**. Resolved as *comment-only*: the `anyOverlayOpen` doc names 8 of 12 flags and the
  `resumePickerOpen` omission from `dismissOpenOverlay` is undocumented. The triad refactor stays
  rejected; **B13** remains the extractable part.
- **B13**'s permissions half → **C21**. Confirmed safe to include: the `permissions-delete` child
  page is removed *first* in `dismissPermissionsPicker` (`picker_settings.go:183`), and ESC
  ownership lives centrally at `key_esc.go:103-111`, not in the modal — so extracting the shared
  focus-restore tail does not touch the child-page ESC path.
- **B4**'s `ResumeDeps.Fork` → **C25**. Confirmed a live seam for dormant behaviour, not dead code.

## Consolidated verification

*Historical — run 2026-07-27; not re-run since.*

**Reachability — `scripts/deadcode-check.sh`: pass (exit 0), 2026-07-27.** `deadcode` reports 18
unreachable functions; all 18 are present in `.deadcode-allow`, so the script prints nothing and
exits 0. Classification of the 18 per the script's own policy (`scripts/deadcode-check.sh:33-34`:
wire a caller, delete, or document as an intentional seam):

| Class | Entries |
|-------|---------|
| Intentional test-only seam (allowlist bucket 3) | `internal/fsutil/atomic.go SetSyncFileForTest`, `SetSyncDirForTest`; `internal/fsutil/move.go SetRenameNoReplaceAtForTest`, `SetBeforeMoveRenameForTest`; `internal/bootstrap/headless.go HeadlessDriver.PromptForApprovalEnabled`, `DevDebugRequested` |
| Intentional deferred behaviour (bucket 3) | `internal/sessionfork/fork.go ForkSession`, `CreateChild`, `filterTextRecords`, `filterTextContent` — dead while `sessions.ReaderSupportedVersion == 1` |
| Not-yet-integrated foundation (bucket 2) | `internal/tui/cmd_compact.go NewCompactHandler`, `rejectCompact`, `failCompactAfterAcceptance`, `deriveCompactTitle`; `internal/turn/request.go BuildCompactionSummaryRequest`; `internal/bootstrap/provider_refresh.go RefreshOutcome.String`; `internal/filetools/readresolve.go IsDirectorySymlink`, `ClassifyEntry` |
| Removable dead code | **None.** |

No finding in this audit is dead code by that measure. The inverse problem the gate cannot report is
recorded as **C24**: 111 of the 129 allowlist entries are no longer reported, meaning their
documented unblocking condition has been met. Three of them are this slice's own surface
(`buildCompoundStageScopeOptions`, `EncodeCompoundSubject`, `CapabilityMembers`), all now called from
`prompt.go`. Per this task's constraints, `.deadcode-allow` was not modified, and no function was
judged deletable because it appears in it.

**Fast test gate — `mise run test-fast`: pass (exit 0), 2026-07-27.** The documented fast gate
(`docs/tech-stack.md:52`, `go test ./...`, no race detector) reports `ok` for all 32 test-bearing
packages, including `internal/tui`, `internal/bootstrap`, `internal/permissions`, and
`internal/dispatch`; the three `[no test files]` entries are `cmd/codemeld`,
`internal/testsupport`, and `schemas`. The working tree carried no source modification when it ran —
this audit changes only this document — so most package results were served from the build cache;
the run is a verification that the tree this audit describes is green, not that the audit changed
anything. No test was skipped, and no working-tree condition prevented the command.

## Full-report reconciliation

*Historical — from the 2026-07-27 assessment and its 2026-08-05 review notes; statuses and line
numbers are from those dates, not current.*

The three slices were split from one eight-question audit; the questions are not enumerated in a
single source, so they are restated here from the union of the three slice contracts, with the
finding IDs that answer each.

| # | Question | Answered by |
|---|----------|-------------|
| 1 | Is anything here speculative or unnecessary — code that could simply not exist? | **A2**, **A15**, **B4**, **B10** (rejected), **C8**, **C9**, **C21**, **C24**, **C25** |
| 2 | Which large files or functions hold a cohesive cluster worth extracting? | **A4**, **A5**, **A10** (yes); **B7**, **B13** (yes); **C12** (yes); **A1**, **A3**, **B2**, **C1**, **C5** (no) |
| 3 | Which complexity is load-bearing — what ownership or safety boundary makes it necessary? | Ownership-boundary sections of all three slices; **A2**, **A6**, **A8**, **B5**, **B6**, **B10**, **B19**, **C2**, **C3**, **C4**, **C6**, **C7**, **C13**, **C14** |
| 4 | Is production code duplicated in a way a shared helper would fix? | **A7**, **B1**, **B8**, **B9**, **B12**, **B13**, **C12**, **C16**, **C21** |
| 5 | Is test setup duplicated, and would a fixture preserve the behaviour being tested? | **A13**, **A14**, **B15**, **B16**, **B17** (rejected), **C18** |
| 6 | Are the tests organised by behaviour, with honest seams and no coverage gap? | **A9**, **A15**, **B18**, **B20**, **C19**, **C20** |
| 7 | Are comments and names still accurate? | **B14**, **C11**, **C17**, **C23** |
| 8 | Is there dead code, and is an unreachable function removable or an intentional seam? | **A12** → **C22**, **B4** → **C25**, **C24**, plus the reachability table above |

**Coverage of the named large files.** Every file named in the three slices' scope has an explicit
conclusion; the "no change" column is not an absence of findings but a stated one.

| File | Lines | Slice | Conclusion |
|------|-------|-------|-----------|
| `prompt_test.go` | 2222 | slice C | Change: **C18**, **C19**, **C20** (arrange-only consolidation, three added tests, determinism fixes) |
| `picker_model_test.go` | 2153 | slice B | Change: **B16**, **B20**, and the route-table determinism half of **B8** |
| `app.go` | 1976 | slice A | **No structural change** (**A1**, **A2**, **A3** retained); changes limited to **A4**'s extraction, **C10**'s constant, **C22**'s recorded seam list, **C23**'s doc comment |
| `picker_file_test.go` | 1474 | slice B | Change: **B18** |
| `cmd_resume_test.go` | 1280 | slice B | Change: **B15** |
| `app_test.go` | 1139 | slice A | Change: **A13** |
| `transcript_selection_test.go` | 1080 | slice A | **No change** — the selection assertions are the mouse surface's only real-behaviour cover (**A7**'s risk column) |
| `prompt.go` | 1033 | slice C | Change: **C12**, **C10**, **C17**; structure retained (**C1**, **C2**, **C5**, **C6**, **C13**) |
| `input.go` | 976 | slice A | **No change** except **A9**'s added test; `reconcileSegments`' one-pass repin retained |
| `picker_model.go` | 974 | slice B | Change: **B8**, **B9**, **B12**; **B11**, **B19** retained |
| `stream_surface_test.go` | 765 | slice A | Change: **A14**; **A15** rejects the removal candidates |
| `picker_settings_test.go` | 685 | slice C | **No change** beyond **C17**'s stale header comment |
| `input_test.go` | 665 | slice A | **No change** |
| `picker_resume.go` / `picker_resume_test.go` | 623 (test) | slice B | **No change**; the local ESC ownership is retained and documented via **C23** |
| `transcript.go` | 560 | slice A | Change: **A10**; `renderLocked` retained (**A8**) |
| `picker_settings.go` | 385 | slice C | Change: **C21**, bundled with **B13** |
| `prompt_scope.go` | 240 | slice C | **No change** except **C17**'s comments; **C6**, **C7**, **C9** retain the logic |
| `prompt_folder.go` | 119 | slice C | Change: **C11** (parameter name) and **C17**; **C14** rejects the guard removal |

**Scope statement.** Six `internal/tui` files above 550 lines were in no slice's scope and are
therefore *unassessed*, not cleared: `cmd_status_test.go` (798), `cmd_clear_test.go` (771),
`cmd_compact_test.go` (701), `launch_layout_test.go` (686), `cmd_fork_test.go` (594), and
`cmd_connect_test.go` (554). Five are slash-command surfaces; `launch_layout_test.go` is not — it
covers the launch layout and the transcript's tag-injection escaping
(`launch_layout_test.go:1-4`), and its only slash-command contact is `/status` used as a layout
perturbation (`:223`). No slice claimed any of the six. Read the absence of a finding about them as
an absence of evidence.

**Report status at the original assessment: complete.** All three slices had landed, the eight
questions were answered, and the verification above is the terminal record of that assessment.
