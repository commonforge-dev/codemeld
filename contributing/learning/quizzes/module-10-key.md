# Answer key — Module 10: TUI

Citations are **file + function/symbol name**. Behavioral claims name the test that pins them.

---

**1.** After trimming, a leading `/` followed by a name matching `^[a-z][a-z0-9-]*$` is a slash
invocation; a bare `exit`/`quit` is an exit; everything else is plain text. A lone `/` (or `/Foo`,
`/foo_bar`) falls through to **plain text**. *Proof:* `tui/slashparse.go` `ParseSlashInput`;
`TestParseSlashInput` in `slashparse_test.go`.

**2.** It goes to the `SubmitFunc` (`NewSubmitFunc`, `dispatchadapter.go`); on `StatusNotASlashCommand`
it's forwarded to the injected `PromptEntrypoint` (the turn path), and `submitCurrent` clears the field
only if that returns true. *Proof:* `tui/dispatchadapter.go` `NewSubmitFunc`, `tui/app.go`
`submitCurrent`; `TestNewSubmitFunc_PlainPrompt_AcceptedWhenEntrypointAccepts`.

**3.** The **canonical** name (e.g. `clear` for `/new`) — dispatch binds the canonical name into the
command context before the handler runs. *Proof:* `tui/registry.go` `Registry.run`/`commandContext`;
`TestDispatch_AliasRecordsCanonicalName`.

**4.** A one-line notice is rendered, the input is **retained**, and **no** `slash_command` event is
appended — no handler runs. *Proof:* `tui/registry.go` `Registry.reject`; `TestDispatch_UnknownCommand`,
`TestDispatch_WrongArity`.

**5.** Top-to-bottom: **allow this once** (default-highlighted) / **deny** / **allow for this session**
/ **allow in this folder permanently** / **allow globally permanently**. *Proof:* `tui/prompt.go`
`promptOptionsInOrder`/`PromptOption`; `TestPromptOptions_FixedOrderAndDefaultHighlight`,
`TestPromptUser_EnterPicksDefaultAllowOnce`.

**6.** `PromptUser` (called off the loop) blocks on a buffered `chan PromptDecision`; the option
callbacks send the decision; `PromptUser` tears down the overlay and returns it. *Proof:* `tui/prompt.go`
`PromptUser`/`completePrompt`; `TestPromptUser_DenyIsSingleAction`,
`TestPromptUser_SecondDecisionCannotBlockOrDoubleSend`.

**7.** A subject-scope sub-choice — **Exact / one Prefix row per visible token boundary / Program** —
and choosing **Program** opens an inline confirm step: a two-item `Confirm program-wide grant` /
`Cancel` list with the cursor on confirm, so one Enter accepts the broad grant (no byte-for-byte
retype). The middle rows are called **Prefix** (not "subcommand": codemeld does not know a program's
flag arity), run longest-pinned-prefix → shortest, and stop before the zero-length prefix because
`<program> :*` is the confirm-gated Program row. So
`prep-open-tasks.sh --only c175 --force` can store `prep-open-tasks.sh --only :*` without a
program-wide grant. The recommended row is unchanged by the extra choices: the prefix
`permissions.ClassifyDirectTokens` infers, else Exact — never a broader row. A chosen row pins **every token shown
before `:*` verbatim**; only later whole tokens may vary. Compound stages use the separate
`scopeOptionRows`/`buildCompoundStageScopeOptions` path and keep Exact / Subcommand / Program, the
narrowest default, and the destructive-stage exact-only rule — widening one stage of a compound is
the riskier choice. *Proof:* `tui/prompt_scope.go` `buildScopeChooserRows`/`scopeRow`,
`permissions/direct_scope.go` `NewDirectScopeModel`/`PrefixSubject`, `tui/prompt.go` `showProgramConfirm`; `TestPromptUser_DirectCommandProgramConfirm`,
`TestPromptUser_DirectCommandPrefixScopeStoresSelectedBoundary`,
`permissions` `TestNewDirectScopeModel_PrefixSubjectsMatchOnlyAtTokenBoundaries`,
`TestBuildCompoundStageScopeOptions_NoDirectPrefixRows`.

**8.** The provider sink calls `App.AppendStreamDelta` off the event loop. While `running`, it uses
`QueueUpdate` to append each delta to the buffer without requesting a draw, then arms one 50 ms timer
when none is pending. The timer returns through `QueueUpdateDraw` to render the accumulated buffer
once and does not re-arm until another delta arrives. This keeps mutation serialized with the UI loop
while avoiding a full transcript redraw for every delta; before `Run`, updates render directly for
deterministic tests. *Proof:* `tui/app.go` `AppendStreamDelta`/`armStreamRender`;
`TestAppStreamSurface_CoalescesRunningDeltas`.

**9.** `markInterrupted` commits the in-progress buffer with a `[interrupted]` suffix; `finalize`
commits it with no marker. *Proof:* `tui/transcript.go` `markInterrupted`/`finalize`;
`TestTranscript_MarkInterruptedAppendsMarker`, `TestTranscript_FinalizeCommitsWithoutMarker`.

**9a.** Each line of a fenced block is wrapped in `codeBlockTag`, which names a foreground *and* a
background (`codeBlockText`/`codeBlockFill`), so the block paints as a filled rectangle with a
visible edge against the prose; an inline `` `code` `` span keeps the foreground-only `codeColor` and
gains no fill, so the two never look alike. An empty block's body is one empty line, and a
zero-width styled run paints no cell, so a block that is blank throughout renders each of its lines
as a single space (`codeBlockBlankLine`) and still occupies a bounded line; a blank line inside a
block that has content stays empty, so the copied text matches the source. Every block line closes back to
`defaultTag`, so the fill ends with the block and the following paragraph renders unstyled. The body
comes from the raw source line segments and is `tview.Escape`'d rather than re-parsed, so `[red]`,
`**`, and backticks inside it display literally. All four display paths share the renderer — live
streaming (`renderStreamMarkdown`, which styles a still-open fence from its first body line and adds the copy control only once its closing fence has arrived),
`finalize`, `markInterrupted`, and `/resume` replay through `replaySessionBlocks` — so the block
looks the same in each. The boundary is drawn with color only, never border glyphs, so the
tags-stripped text a mouse selection copies is exactly the original block content. The producing half
is in the base prompt: it tells the model to fence anything the user is
meant to copy and keep the explanation outside the fence. *Proof:* `tui/markdown.go`
`renderMarkdown`'s `*ast.FencedCodeBlock` case and `codeBlockTag`/`codeBlockBlankLine`;
`tui/colors.go` `codeBlockText`/`codeBlockFill`; `agentinstr/baseprompts/shared.md`;
`TestRenderMarkdown_FencedCodeBlockStyled`,
`TestRenderMarkdown_FencedCodeBlockTagIsForegroundAndBackground`,
`TestRenderMarkdown_EmptyFencedCodeBlockStaysVisible`,
`TestTranscript_FinalizeSeparatesBlockFromSurroundingProse`,
`TestTranscript_FinalizeRendersTviewLikeBlockContentLiterally`,
`TestTranscript_MarkInterruptedRendersFencedBlockWithLiteralMarker`,
`TestRenderStreamMarkdown_OpenFenceStyledFromFirstBodyLine`,
`TestReplaySessionRecords_RendersFencedBlockBoundary`,
`TestBasePrompt_CopyableContentUsesFencedBlocks`.

**9b.** **Below**, because a block taller than the pane has already scrolled its top out of view by
the time you want to copy it, and a streaming reply auto-follows the bottom — so the end of the block
is what is on screen. It sits **two columns past the block's own container prefix** — measured from
`curPrefix()`, never from a fixed screen column, since the prefix widens with nesting (`"│ "` per
blockquote, `"  "` per *nested* list; a top-level list adds nothing). It is not aligned to the block's
first line because a fence inside a list item shares that row with the `"• "`/`"10. "` marker, which is
written straight to the buffer and never enters the prefix — aligning to it would move the control with
the marker's width and push it right of most of the block it labels. The two cues are the **brand teal
foreground** (`accentTealHex`) and an **underline**: the hyperlink idiom, the one pairing that reads as
clickable without explanation. The label names the *action* because it is the accessibility fallback —
a cue may not rest on color or dim styling alone, so `[click to copy]` still says what it
does on a terminal that drops the accent, the underline, or both. The text copied is the **source**
body, carried out of `renderMarkdown`
alongside the rendered string, byte for byte — **including the newline before the closing fence**,
which the drawn lines drop because it has no cell of its own. `renderMarkdown` returns one
`codeControl` per rendered block: the line of its own rendered text the control was written to, plus
that body. The transcript stores each committed block's controls beside that block and
`renderLocked` shifts those lines by the blocks joined above them, so `codeControlRegions` builds a
region from **what the renderer emitted**, never from a text match. That matters because once tags
are stripped a model-written `[click to copy]` line — in a fenced body or in prose — reads exactly like a
generated one, so scanning for the text would let model content arm a bogus control or cancel a real
one. No control is emitted for an **indented (4-space) code block**, an **inline `` `code` `` span**,
or a **fence that has not closed yet** — and an interrupted reply exposes none either, because
although goldmark closes a dangling fence at end of source, `endsInsideFence` sees there was no
closing fence and the snippet is truncated. That check reads fences through their container, so an
interrupted fence written inside a blockquote or a list item is caught the same way, and a closed one
is still copyable. A delta arriving between press and release copies **nothing**: `renderLocked`
calls `t.controls.set(...)`, and `set` drops the in-flight press along with the now-stale offsets.
*Proof:* `tui/markdown.go` `renderMarkdown`'s `*ast.FencedCodeBlock` case and `endsInsideFence`/`scanBlocks`;
`tui/transcript.go` `codeControlRegions`/`commitLocked`/`renderLocked`; `tui/app_selection.go`
`clickRegions`; `TestRenderMarkdown_FencedBlockCarriesSourceBody`,
`TestTranscript_TerminalStreamPathsArmClosedFenceControl`,
`TestTranscript_MarkInterruptedOpenFenceExposesNoControl`,
`TestTranscript_LiveStreamArmsControlOnlyForClosedFence`,
`TestTranscript_ContainerFenceControls`,
`TestTranscriptCodeCopy_ControlClickCopiesSourceBody`,
`TestTranscriptCodeCopy_ControlsComeFromTheRenderer`,
`TestTranscriptCodeCopy_ReRenderDropsArmedControl`,
`TestReplaySessionRecords_FencedBlockControlCopiesOriginalBody`,
`TestRenderMarkdown_CopyControlSitsTwoColumnsPastContainerPrefix`.

**10.** Priority: (1) dismiss the first open overlay in the `overlays()` roster (`tui/overlays.go`) —
an open overlay owns ESC, ahead of the stream, because it is the modal the user is looking at and it
blocks the very turn ESC would otherwise cancel; (2) else stop an in-flight stream (and emit
`stream_interrupted`); (3) else clear a non-empty input buffer (resetting any armed CTRL-C exit hint),
mirroring CTRL-C step 2; (4) else no-op. The roster is the single registration point — one ordered
entry per overlay-open flag, each with its `isOpen` predicate and its dismissal — so `HandleEsc` and
`anyOverlayOpen` both read it and a new overlay cannot half-register. Two entries carry a quirk:
`/status` disarms the next ESC when it dismisses over a live stream (it is modal but does not look
modal, so a reflexive second press would otherwise cancel the turn), and the `/resume` picker has a
**nil** dismissal — `handleGlobalKey` hands its ESC to the focused list instead of calling `HandleEsc`,
because the picker owes its caller a continuation result, so the walk registers it for open state only
and skips it. The clear sits below the higher-priority actions, so an in-flight response or an open
overlay keeps the draft (the file-picker `@`+query literal survives). *Proof:* `tui/key_esc.go`
`HandleEsc`, `tui/overlays.go` `overlays`; `TestOverlays_RosterCoversEveryOpenFlag`,
`TestHandleEsc_OverlayDismissBeatsStreamAndDoesNotDisarm`, `TestHandleEsc_NilDismissEntryIsSkipped`,
`TestApp_StatusEscDismissesBeforeInFlightCancel`,
`TestHandleEsc_ClearsNonEmptyInput` / `TestHandleEsc_OverlayDismissPreservesInput`.

**11.** The drag is owned by the **app-level** mouse capture, not the transcript view's: `handleAppMouse`
starts it on `MouseLeftDown` inside the transcript (`beginSelect`, focus stays on the input), extends it
on `MouseMove` (`updateSelect`), and finalizes on `MouseLeftUp` (`endSelect`) — the app capture is the
only seam that sees the `MouseMove` events a drag emits because it runs before tview routes events to a
primitive. The selection is tracked as **byte offsets into the stripped displayed text** and the
highlight is painted by `transcriptView.Draw`, which overlays reverse video *after* the text is drawn and
**never mutates the committed lines** (so dynamic-color rendering is untouched and offsets re-project
through the live scroll offset). Copy reuses the input area's OSC 52 path: `copyTranscriptSelection`
delegates to `inputField.copyToClipboard`, so transcript and input copy share one clipboard mechanism and
no separate copy command is needed. Wheel scrolling is untouched because it stays in the transcript
view's own `handleTranscriptMouse` capture, and **Shift+drag** is left as the terminal's native
select/copy escape hatch (the app capture only claims plain, non-Shift left-drags). *Proof:*
`tui/app.go` `handleAppMouse`/`copyTranscriptSelection`, `tui/transcript_selection.go` `transcriptView.Draw`,
`tui/input.go` `copyToClipboard`; `TestTranscriptSelection_DragSelectsAndCopies`,
`TestTranscriptSelection_WheelStillScrolls`, `TestTranscriptSelection_PlainClickDoesNotCopy`,
`TestTranscriptSelection_HighlightClearsOnReleaseAfterScroll`.

**12.** The retry loop calls TUI surface hooks through bootstrap. `ShowRetryBackoff` changes the in-flight
indicator to `Reconnecting… (attempt N of M)` while the retry waits; `ResumeRetry` restores `Working…`
before re-issue. A partial stream drop calls `RollbackPartial`, which clears the unsealed live buffer
without touching committed history. A recovered retry calls `CommitRetryRecovered`, appending the visible
`· recovered after N retry/retries` breadcrumb; exhaustion renders the normal provider failure through
`RenderProviderRequestFailedAfterAttemptsNotice`, prefixing line 1 with `failed after N attempts:` while
keeping hint behavior. *Proof:* `tui/app.go` `ShowRetryBackoff`/`ResumeRetry`/`RollbackPartial`/
`CommitRetryRecovered`; `tui/transcript.go` `rollbackPartial`/`commitRetryRecovered`; `tui/notice.go`
`RenderProviderRequestFailedAfterAttemptsNotice`; `TestIndicator_RetryBackoffAndResume`,
`TestAppStreamSurface_RetryRollbackAndBreadcrumb`, `TestRenderProviderRequestFailedAfterAttemptsNotice`.

**13.** The model picker uses **contiguous multi-term matching**: each whitespace-separated query term
must appear contiguously (case-insensitive) in at least one searchable field (model ID, provider ID,
provider display label). Different terms may match different fields. A row whose first term is a
case-insensitive model-ID prefix ranks ahead of other matching rows in the same provider group.
**Ctrl-R** triggers a forced provider refresh while the picker is open; lowercase `r` is a plain
printable character inserted into the filter field. Ctrl-R is consumed locally by the open model picker
and never reaches the global reverse-search handler. The file-reference picker also matches a contiguous,
case-insensitive substring of the whole path, but through a tree walk that ranks its matches before
emitting them (`searchFileRefs`/`matchesFileRefQuery`/`rankFileRefMatches`) rather than a pre-built
candidate corpus — see Q15.
*Proof:* `tui/picker_model.go` `filterModelRows`/`modelRowMatchesTerms`,
`tui/picker_effort.go` `handleGlobalKey`; `TestFilterModelRows`,
`TestModelPicker_CtrlRForcesProviderRefresh`, `TestModelPicker_CtrlRLocalToPicker`
(`tui/picker_model_test.go`, `tui/overlay_keys_test.go`).

**14.** A favorite is identified only by its exact `{provider, modelID}` pair (never a label, model
ID alone, or table position), so two favorites sharing a model ID under different providers stay
distinct; the injected snapshot renders in stored order under a non-selectable **Favorites** heading
above the provider groups, following the same filter matcher, collapsing duplicate pairs, and omitting
pairs with no current catalog row without writing anything. **Ctrl-F** adds/removes the highlighted
exact pair through the injected capability from either the filter field or the table; the picker stays
open and rebuilds its aliases only from the snapshot a confirmed toggle returns. On a failed toggle it
leaves the rows, query, highlight, and snapshot unchanged and shows a notice. The picker owns no
persistence. *Proof:* `tui/picker_model.go` `favoriteAliasOrder`/`toggleHighlightedFavorite`/
`populateModelTable`, `tui/cmd_model.go` `ModelPickerDeps`;
`TestModelPicker_FavoritesRenderAsAliasesBeforeGroups`, `TestModelPicker_FavoriteAliasResolvesExactPair`,
`TestModelPicker_CtrlFTogglesFavoriteFromBothRoutes`, `TestModelPicker_FavoriteToggleErrorPreservesState`
(`tui/picker_model_test.go`).

**15.** `@` opens the overlay on the guidance row `type to search project files` and walks nothing — an
empty query never starts a search (and clearing the query back to empty returns to that row and revokes
the search in flight). A non-empty query shows `searching...` and schedules the search after a
rune-count debounce: 400 ms at one rune, 250 ms above that. The 50 (`fileRefSearchLimit`) bounds
*emitted/displayed* rows, not traversal: the producer walks the complete codemeldignore-filtered tree,
collects every match, and only after the walk ends ranks them — exact path, then starts with the query,
then last element starts with it, then any other match; shallower first within a rank; walk order for
ties — and emits the 50 best. A walk error (such as an unreadable directory) still emits the ranked
matches found so far before returning; cancellation emits nothing. `emit` is synchronous, so every row
is applied before the final outcome, which is signalled only by the producer returning: nil with rows
keeps them; nil with zero rows keeps the picker open with a non-selectable `no matches` row (Enter or
Esc then closes it, leaving the typed `@query` literal); a non-nil error shows a notice and the
`search failed` row only when no row arrived; `context.Canceled` is silent. Stale results are excluded by a **generation counter**, not cancellation —
`afterFunc` returns no handle, so `invalidateFileRefSearch` bumps `sess.searchGeneration` (cancelling any
running worker context) and every queued row/final re-checks `ownsFileRefSearch(sess, gen)`. Workers
never touch tview directly; they marshal through `streamUpdate` onto the event loop.
*Proof:* `tui/picker_file.go` `(App).openFilePicker`/`(App).onFileRefQueryChanged`/`fileRefDebounceDelay`/
`(App).scheduleFileRefSearch`/`(App).startFileRefSearch`/`(App).applyFileRefSearchRow`/
`(App).applyFileRefSearchFinal`/`(App).invalidateFileRefSearch`/`(App).ownsFileRefSearch`/
`searchFileRefs`/`rankFileRefMatches`, `tui/app.go` `streamUpdate`; `TestFilePicker_OpensGuidanceWithoutWalk`,
`TestFileRefDebounceDelay_CountsRunes`, `TestFileRefSearch_CompleteCorpusAndBound`,
`TestRankFileRefMatches`, `TestFileRefSearch_Ranking`,
`TestFileRefSearch_Cancellation`, `TestFilePicker_LiveScheduleAndRunningLoop` (running-loop
`SimulationScreen` proof, race-checked with `go test -race ./internal/tui`),
`TestFilePicker_StreamsRowsBeforeFinal`, `TestFilePicker_SuccessFinal`, `TestFilePicker_ErrorFinal`,
`TestFileRefSearchSchedule_ObsoleteTimerCannotStart`, `TestFilePicker_RevocationRejectsStaleEffects`, and
the adapted selection regressions `TestFilePicker_SelectInsertsStreamedToken`,
`TestFilePicker_EnterWithNoSelectableRow`, `TestFilePicker_EscLeavesAtQueryLiteral`,
`TestFilePicker_QueryClearsToGuidanceAndRevokes` (`tui/picker_file_test.go`).

**15a.** From the **already-persisted assistant `tool_calls` entries** — the query and URL are in the
call arguments the session has always stored, so replay adds no session record and no schema field.
`replaySessionBlocks` reads each assistant record's entries, keeps only `web_search` / `web_fetch`,
and appends their formatted lines as **one escaped block in that record's own position** (after its
text, before later records); non-web calls stay hidden and role:tool **result** bodies are never
read, so a mixed round replays **only** its web lines — the `Read`/`Grep`/`Run:` activity the live
pane showed is not reconstructed. A tool-call entry whose wrapper or function
name cannot be decoded is **skipped** (it cannot be identified as web activity); a readable web name
with missing, malformed, or wrong-typed arguments falls back to the **bare tool name**, so a legacy
record degrades rather than failing the replay. Activity is not a reply, so `hasVisibleReply` stays
false and a tool-call-only turn still gets **no** completion footer; the blocks count against
`maxReplayBlocks` like any other. Nothing is sent to the model — these are transcript blocks only.
The formatter lives in the stdlib-only leaf package **`internal/toolactivity`** because
`internal/turn` already reaches `internal/tui` (`internal/model/persist.go`,
`internal/sessionfailures/failures.go`), so `internal/tui` importing `internal/turn` would be a
compile-time cycle; one shared `Format(name, arguments)` is what keeps the resumed line
byte-identical to the live one (the live emitter is `turn.ToolActivityLines` →
`App.AppendToolActivity`, and the same formatter also builds the `Denied <activity>: <reason>`
notice). *Proof:* `toolactivity/activity.go` `Format`/`WebLine`, `tui/app_replay.go`
`replaySessionBlocks`/`webActivityBlock`/`decodeToolCallFunction`, `turn/activity.go`
`ToolActivityLines`, `turn/tools.go` `assistantToolCallRecord`;
`TestReplaySessionRecords_ProjectsWebActivityAtRecordPosition`,
`TestReplaySessionRecords_RetainsOnlyWebCallsFromMixedRound`,
`TestReplaySessionRecords_HandlesMalformedWebToolCallWrappers`,
`TestReplaySessionRecords_WebActivityRendersLiterally`,
`TestReplaySessionRecords_WebActivityLeavesFooterPairingUnchanged`,
`TestReplaySessionRecords_BoundsWebActivityBlocks`,
`TestToolActivityLinesDelegatesToSharedFormatter`, `TestPackageImportsOnlyStdlib`.

**15b.** **↑↓** move the option cursor, **Enter** or a **left click** chooses the row under it (one
shared `choose` handler backs both), **Tab** steps forward through the focus ring and
**←/→** step that same ring — the shared context section when the call sent one, every question
region, each **open** custom-answer field, `Ask clarification` and its **open** entry, then Submit
and Cancel, wrapping at both ends, so **←** on the ring's first stop (the context section, or the
first question without one) lands on Cancel and
**→** on a question with its custom field open lands on that field rather than another question. Which
arrows navigate depends on what else they could mean for the focused control: on a question region ↑↓
belong to the option cursor, so only ←/→ step the ring; in an open custom field ←/→ edit the text, so
**↑** steps back to that question's options and **↓** forward; on a button no arrow has another
meaning, so all four step the ring (→/↓ forward, ←/↑ back). **PgUp/PgDn** scroll the question region,
**Ctrl-S** submits from any control including both buttons, **ESC** cancels. Backtab is unbound on
purpose — the app-level capture takes it for mode cycling first. Only the question region holding
keyboard focus draws a highlight, so it is never mistaken for a preselected answer.

`‹ Prev` and `Next ›` are the mouse's half of that navigation: a pointer can only act on what is
drawn, one question is drawn at a time, and the focus ring is a keyboard route. Without them a
mouse-only user could answer the first question and reach nothing else. They wrap and they keep every
answer and scroll position. They are drawn on the row directly under the question they move, and they
are **outside the focus ring** — the keyboard reaches every question on its own, so ring stops there
would only sit between the last question and Submit. Submit and Cancel hold their own row at the
bottom: two per row, because four on one row would push Submit and Cancel off the right edge of the
smallest supported terminal.

The mounted page is modal to the mouse: a button-down no control takes is consumed by the form, so it
never falls through to the input area underneath and steals the click, and a second quick click —
which tview reports as a double click, by time alone rather than by position — is treated the same as
a plain one, except when the click *immediately* before it chose that same row, where acting twice
would undo that choice (`actOnClick`). A click anywhere else in the form — `Next ›`, a button, blank
space — clears the remembered row, or coming back to a question and clicking an option a second time
could no longer toggle it off. A drag already in progress
when the form mounts is discarded there (`discardActiveDrags`), because `handleAppMouse` answers its
move and release ahead of the overlay guard and both release paths focus the input. A terminal blur/return
that left focus on that input is repaired by `restoreModalFocusOnTerminalFocus`, on the focus-gained
event and again on the first key after it, onto whichever control last held focus — a control the
mouse focused included, since every form control records that through its own focus callback rather
than only through Tab.

A **single-select** question replaces any previously listed choice and marks the current one `(*)`
against `( )` — an untouched question, or one answered only with custom text, validly has none; a
**multi-select** question toggles any subset and checks each `[x]` against `[ ]`. Plain ASCII, three
cells wide, escaped before the dynamic-colors view parses the line: `●`/`○` are one ambiguous-width
cell whose measured width terminals and tview can disagree about, and one quiet glyph lost against
the cursor row, which is why the cursor is now an accent color rather than a reverse-video bar. `Type your own answer` appears only on a question
that declared `allow_custom`: choosing it reveals and focuses **that question's own** text field and,
on a single-select question, replaces its option choice; the typed text is recorded under that
question's id and **no other answer changes**. It is a per-question *answer* mode, which is what
separates it from `Ask clarification` — that button asks the model a question instead of answering
any of them, and returns no answers at all (15f). A question you never touched comes back as an
**explicit empty** `"selected":[]` — the form never fills in a default or a recommended option, and
the encoded JSON keeps the request's question order and each question's declared option order.

A maximum-size request is tens of screenfuls on a 24-row terminal, so `questionStage` shows **one
question at a time** under a `Question k of n` counter and places only that question — an earlier
multi-column layout rendered them all and was an unreadable wall at the advertised maximum.
Navigation is what reaches the rest: `Tab` and ←/→ step the whole ring for the keyboard, `‹ Prev` and
`Next ›` do it for the mouse, and the question owning the focused control is the one shown, so the
last question is reachable and answerable and the buttons are always placed.

A label longer than one screen row is **not** shortened. `questionOptions` renders the prompt and
every option into one scrollable region and **wraps** each label across as many lines as it needs, so
there is no ellipsis, no fitted row, and no separate surface showing the full text — the row *is* the
full text. That region scrolls: ↑↓ move the cursor and pull the view along, **PgUp/PgDn** page it,
and the wheel scrolls it from anywhere over the question. Scrolling survives a relayout —
`questionBlock.layout` deliberately does not call `ensureVisible`, because layout runs on every focus
change and resize and pulling the view back to the current option there would silently discard a
scroll the user just made; only moving the cursor calls it. An option taller than the region is
pinned to its first line so its mark stays visible, which is what PgUp/PgDn are for. The property the
form guarantees is **reachability, not simultaneous visibility**: at the advertised maximum nothing
could show it all at once, so what holds is that every accepted rune can be brought on screen.

Widening and narrowing again is the harder half, and it is why the position is stored as a place in
the text — which prompt or option, and how far into it (`questionAnchor`) — rather than as a line
number. A new width rewraps every line, so the same numbered line is different text at the new width;
and once the whole question fits, `TextView.Draw` clamps its own offset to zero, so a plain number
carried across the round trip comes back as the beginning of the question. Every deliberate move
records the anchor (`scrollToLine`) and `render` maps it onto the new wrapping without recording,
which is exactly what lets the wide layout clamp tview's live offset while the narrow one puts the
reader back where they were.

ESC — or the **Cancel** button, which runs the same `cancelQuestionForm` teardown — closes the form,
delivers `{"answers":[],"cancelled":true}`, restores the focus captured at open through the shared
`closeOverlayPage` teardown, and leaves your typed draft untouched — and it does **not** cancel the
stream. That ordering is deliberate: `HandleEsc` gives the form ESC *before* stream interruption
because the agent turn is blocked on the form's result, so an ESC meant to dismiss the form would
otherwise kill the work behind it. *Proof:*
`tui/question_prompt.go` `AskQuestions`/`questionBlock.choose`/`questionBlock.layout`/
`questionStage.place`/`questionOptions.render`/`questionOptions.ensureVisible`/
`questionOverlay.MouseHandler`/`QuestionResult.Encode`/`cancelQuestionForm`/`finishQuestionForm`,
`tui/key_esc.go` `HandleEsc`,
`bootstrap/starttui.go` `newInteractiveToolAdvertiser`,
`bootstrap/tooldispatch_askuser.go` `setAskUser`/`dispatchAskUser`/`decodeAskUserRequest`,
`provider/tooldefs.go` `AskUserToolDefinition`;
`TestQuestionPrompt_SingleSelectKeepsOneOptionPerQuestion`,
`TestQuestionPrompt_MultiSelectTogglesOnlyItsOwnOptions`,
`TestQuestionPrompt_CustomTextStaysScopedToItsQuestion`,
`TestQuestionPrompt_SubmitEncodesDeterministicJSON`,
`TestQuestionPrompt_UnansweredQuestionsEncodeEmptyNotInferred`,
`TestQuestionPrompt_EscapeCancelsWithoutInterruptingTheWaitingTurn`,
`TestQuestionPrompt_CancelControlDismissesWithoutInterruptingTheWaitingTurn`,
`TestQuestionPrompt_ShrinkingTheTerminalKeepsTheFocusedQuestionVisible`,
`TestQuestionPrompt_OversizedQuestionScrollsWithinItsBlock`,
`TestQuestionPrompt_LongOptionsAreShownInFull`,
`TestQuestionPrompt_NarrowLayoutWrapsPromptsAndOptions`,
`TestQuestionPrompt_TagShapedTextRendersLiterally`,
`TestQuestionPrompt_CtrlSSubmitsFromEitherButton`,
`TestQuestionPrompt_SubmitButtonDeliversFromEnterAndMouse`,
`TestQuestionPrompt_TerminalFocusReturnRepairsTheForm`,
`TestQuestionPrompt_MouseFocusSurvivesTheTerminalFocusRepair`,
`TestQuestionPrompt_LiveMouseClicksReachTheMountedForm`,
`TestQuestionPrompt_RapidClicksActWithoutUndoingEachOther`,
`TestQuestionPrompt_CustomFieldLabelUsesNoFixedAccent`,
`TestQuestionPrompt_QuestionNavigationSitsUnderTheQuestion`,
`TestQuestionPrompt_WheelReachesTheHiddenOptionsOfAnOverTallQuestion`,
`TestQuestionPrompt_ShowsOneQuestionAtATimeWithItsPosition`,
`TestQuestionPrompt_NavigationShowsEachQuestionAndItsPosition`,
`TestQuestionPrompt_TheShownQuestionShowsACursorOnlyWhileItHasFocus`,
`TestQuestionPrompt_MaximumTextIsReadableAtTheSmallestTerminal`,
`TestQuestionPrompt_ScrolledMaximumStillSubmits`,
`TestQuestionPrompt_ManualScrollSurvivesNavigationAndResize`,
`TestQuestionPrompt_ArrowsWalkTheWholeFocusRing`,
`TestQuestionPrompt_MouseOnlyNavigationAnswersEveryQuestion`,
`TestQuestionPrompt_MultiSelectKeepsItsOptionsAlongsideCustomText`,
`TestAskQuestions_AbandonedRequestCannotDismissAnotherRequestsForm`,
`TestAskQuestions_StaleCleanupCannotDismissAReplacementForm`,
`TestAskUserTextPattern_StaysLooserThanTheRenderableRule`,
`TestAskUserTextPattern_DivergesOnlyWhereAPatternCannotFollow`,
`TestAskUserTextRenderable_AcceptsTheAdvertisedMaximum`,
`TestProductionDispatcher_AskUserRefusesMalformedUnicodeRatherThanRepairingIt`,
`TestProductionDispatcher_AskUserKeepsExplicitlyFalseResponseModes`,
`TestQuestionPrompt_AControlClickBetweenTwoRowClicksLeavesTheRowClickable`,
`TestQuestionPrompt_PrevAndNextWrapAtBothBoundaries`,
`TestProductionDispatcher_AskUserAppliesTheRenderableTextRule`,
`TestProductionDispatcher_AskUserRefusesTextThatWouldMountBlank`,
`TestAskQuestions_LiveCancelledContextTearsDownTheQueuedForm`,
`TestQuestionPrompt_MountingTheFormEndsAnActiveDrag`,
`TestQuestionPrompt_CtrlSSubmitsFromAnOpenCustomField`,
`TestProductionDispatcher_AskUserInvalidPayloadsNeverMountTheForm`,
`TestProductionDispatcher_AskUserKeepsAcceptedTextExactlyAsSent`,
`TestRunHeadless_NeverAdvertisesOrOpensTheQuestionForm`,
`TestStartTUI_AskUserToolCallMountsTheFormAndPersistsTheSubmittedAnswers`,
`TestStartTUI_AskUserDismissalContinuesTheSameTurn`,
`TestQuestionPrompt_WidthChangesKeepTheReadersPlace`,
`TestQuestionPrompt_OnlyTheFocusedButtonIsReversed`,
`TestQuestionPrompt_OptionCursorAndPagingMoveBothWays`,
`TestQuestionPrompt_TabFromAnOpenCustomFieldReachesSubmit`,
`TestQuestionPrompt_LiveEscapeCancelsThroughTheGlobalKeyRoute`,
`TestQuestionPrompt_SingleSelectHoldsEitherAnOptionOrCustomText`,
`TestQuestionPrompt_ClickingAWrappedLineChoosesItsOption`,
`TestQuestionPrompt_WheelUpMovesBackTheWayWheelDownCame`,
`TestQuestionPrompt_ClickingBlankFormSpaceStaysInsideTheForm`.

**15c.** `unicode.IsPrint` answers "is this a graphic character", not "does this draw anything".
`U+2800 BRAILLE PATTERN BLANK` and the Hangul fillers `U+115F`, `U+1160`, `U+3164`, `U+FFA0` are
symbols and letters by category, so `IsPrint` admits them and `IsSpace` does not exclude them — a
request whose two options are `U+2800` and `U+3164` is two *distinct* values (the schema's
`uniqueItems` is satisfied) that mount as two rows the reader cannot tell apart, or from an empty
one. `askUserBlank` names them, `AskUserTextRenderable` refuses them wherever they sit, and they are
in `askUserTextBlocked` too so the advertised pattern refuses them as well.

The three things a `pattern` cannot say: that some grapheme must occupy a cell (so combining-mark-only
text still matches it), which code points Unicode has not assigned (a fixed class enumerating them
goes stale at the next revision), and anything outside the BMP (ECMA-262 without the `u` flag reads
an astral character as two surrogate code units, so a range between two of them is a range in the
wrong order and the *whole* pattern stops compiling). The decoder refuses all three in band. The
disagreement is allowed in **one direction only** — the schema may advertise text the decoder then
refuses, never the reverse, which would tell the model to send something that can never be accepted —
and `TestAskUserTextPattern_DivergesOnlyWhereAPatternCannotFollow` sweeps every code point Go can put
in a string and fails on any other difference.

The paste lands in the **custom field**. tview collects a bracketed paste itself and hands the
finished block to the *root* primitive, never calling the application's key capture — which is where
the first-key repair lives, so that repair cannot see a paste at all. `rootPages.PasteHandler` runs
`restoreModalFocusOnTerminalFocus` before delegating to the pages, so focus is back on the form's own
control before the text is routed. With a non-text control focused (a question region, Submit,
Cancel) the paste is simply discarded — what must never happen is that it reaches the draft under an
open modal. *Proof:* `provider/tooldefs.go` `askUserBlank`/`AskUserTextRenderable`/
`askUserTextBlocked`/`AskUserTextPattern`, `tui/app.go` `rootPages.PasteHandler`/
`restoreModalFocusOnTerminalFocus`, `testsupport/askusertext.go` `AskUserTextCases`;
`TestAskUserTextPattern_StaysLooserThanTheRenderableRule`,
`TestAskUserTextPattern_DivergesOnlyWhereAPatternCannotFollow`,
`TestProductionDispatcher_AskUserRefusesTextThatWouldMountBlank`,
`TestProductionDispatcher_AskUserAcceptsEveryValidStringEscape`,
`TestProductionDispatcher_AskUserWaitsOnTheTurnsOwnContext`,
`TestStartTUI_AskUserFormClosesWhenTheTurnIsCancelled`,
`TestQuestionPrompt_PasteAfterLostTerminalFocusNeverReachesTheDraft`.

**15d.** **The order.** `productionAuthorizer.RevokeGrant` deletes the entry from the writable
settings file, then drops the live grant from the in-memory table, and only then appends a
`permission_revoke_requested` event and flushes it. The two files have no cross-file transaction, so
one of two bad outcomes has to be accepted: a revoked grant that keeps authorizing, or a real revoke
with no record. Dropping the live grant first accepts the second — a crash between the delete and
the append leaves that revoke unrecorded, which is the lesser harm.
**The session arm.** A memory-only (session) grant has no settings file to delete, so removing it
from the table *is* the whole revoke — `DeleteGrant` is never called and no settings file is created
or touched. It records only when the synchronized removal reports it actually removed the
`DedupKey`; a stale or duplicate request removes nothing, so it emits nothing and says nothing.
**The notice.** By the time recording is attempted the grant is already gone from disk and memory,
so the failure notice must not read as a failed revoke — it says the grant was removed but the
session record failed. The picker shows **exactly one** notice either way: an append rejection or a
flush error the write-failure protocol does not own raises that recording-failure notice, while a
flush failure the protocol *does* handle raises only its own `session_write_failed` notice, because
`newCommandFlush` returns nil after handling it and the revoke adds nothing on top.
**The appended record.** It is never rolled back and never re-appended. On a rejected append nothing
was queued at all; on either flush failure the one record stays queued in memory, so an
independently successful later flush carries that same single event rather than a duplicate.
*Proof:* `RevokeGrant`/`recordRevokeRequest`/`renderRevokeNotRecordedNotice`
(`internal/bootstrap/authdeps.go`), `Cache.RemovePermission` (`internal/config/cache.go`),
`newCommandFlush` (`internal/bootstrap/starttui.go`), `HandleWriteFailure`
(`internal/sessionfailures/failures.go`);
`TestProductionAuthorizer_RevokeSessionGrantMemoryOnly`,
`TestProductionAuthorizer_RevokeSessionGrantDuplicateRequestRecordsOnce`,
`TestProductionAuthorizer_RevokeRecordingFailureKeepsTheGrantRemoved`,
`TestProductionAuthorizer_RevokeNonWriteFlushFailureKeepsOneQueuedEvent`
(`internal/bootstrap/authdeps_test.go`), and
`TestPermissionsRevoke_SessionGrantIsDurableWithoutTouchingSettings` /
`TestPermissionsRevoke_HandledSessionWriteFailureKeepsOneQueuedEvent`
(`internal/bootstrap/tui_commands_test.go`).

**15e.** A request-level `context` is one plain-text paragraph of background **shared by every
question in the call**, up to 2,000 runes, drawn in its own section at the **top of the form, above
the questions**. The advertised schema tells the model to send it whenever a reasonable person could
need to know why the decision is being asked for, what it affects, or what a technical term in it
means, and to leave it out only for a choice that explains itself — without it the user is deciding
blind. It is **displayed literally**: dynamic colors are off and nothing is parsed as markdown, so
`**bold**` shows its asterisks. It word-wraps and is **independently scrollable** — it is the first
stop on the focus ring, and ↑↓ / PgUp/PgDn scroll it while it holds focus, moving nothing in the
question's own region. `sizeContext` caps its height at **a third of the form**, so a long paragraph
scrolls rather than crowding out the question and its options at 20x24. A call with no `context`
mounts **no section at all**, and nothing else about the form changes — same interactive-only
surface, same ordinary tool result. *Proof:* `tui/question_prompt.go`
`QuestionRequest`/`buildContext`/`sizeContext`/`focusRing`, `questionOverlay.Draw`;
`provider/tooldefs.go` `AskUserToolDefinition`/`MaxAskUserContextRunes`;
`TestQuestionPrompt_ContextIsDrawnAboveTheQuestion`,
`TestQuestionPrompt_ContextRendersLiterally`,
`TestQuestionPrompt_ContextScrollsWithoutMovingTheOptions`,
`TestQuestionPrompt_ContextNeverCrowdsOutTheQuestion`,
`TestQuestionPrompt_NoContextMountsNoContextSurface`,
`TestDecodeAskUserRequest_AcceptsACallWithoutContext`,
`TestProductionDispatcher_AskUserContextIsOptionalAndCarriesItsOwnBound`.

**15f.** `Ask clarification` is a **form-level action**, not an answer: its button sits on the ring
between the questions and Submit, and choosing it opens **one text entry** under it (bounded at 1,000
runes) and focuses it. **Enter** or **Ctrl-S** submits. What the model gets back is exactly
`{"clarification":"..."}` — **no `answers` key at all**, since `QuestionResult.Encode` marshals a
clarification through its own shape rather than pairing it with an empty answer list the model would
read as questions answered with nothing. The model is then expected to **reply and call `ask_user`
again with the same questions, its reply restated as the new call's `context`**: the reopened form
covers the screen, so an explanation left only in the prose behind it is not what the person choosing
is reading. Open-but-empty entry: Submit **falls through to the ordinary answers**, so Submit is
never a dead button and the model is never asked nothing. Closing the entry again **discards the text
typed into it**. Cancelling while it is open is still a **cancellation** (`cancelled:true`), not a
clarification. Against `Type your own answer`: that is a per-question answer mode, offered only where
the call set `allow_custom`, recorded under that one question's id and returned *with* the other
answers; clarification is offered on every form, replaces the answers entirely, and hands the model a
question rather than a decision. *Proof:* `tui/question_prompt.go`
`clarifyLabel`/`toggleClarify`/`buildClarifyField`/`clarification`/`questionForm.result`/
`QuestionResult.Encode`/`focusRing`, `provider/tooldefs.go` `AskUserToolDefinition`;
`TestQuestionResult_ClarificationEncodesWithoutAnAnswersKey`,
`TestQuestionPrompt_ClarificationSubmitsInPlaceOfTheAnswers`,
`TestQuestionPrompt_ClarificationAndCustomAnswerCannotBecomeEachOther`,
`TestQuestionPrompt_AnEmptyClarificationSubmitsTheAnswersInstead`,
`TestQuestionPrompt_ClosingTheClarificationEntryDiscardsItsText`,
`TestQuestionPrompt_ClarificationEntryStopsAtItsBound`,
`TestQuestionPrompt_CancellingWhileClarifyingStaysCancelled`,
`TestProductionDispatcher_AskUserClarificationReplacesTheAnswersEntirely`,
`TestQuestionPrompt_NarrowLayoutKeepsEveryControlReachable`.

**15g.** A **compact record**, not the tool traffic. An answered form appends an `Answered:` heading
and one `prompt — answer` line per question, a question you left alone reading `(no answer)`; a
clarification appends `Asked for clarification:` and the text you typed; a **dismissed form appends
nothing**. What is deliberately absent: the raw result JSON, the tool name, and the call id — the
role-`tool` result stays the model's copy and is persisted as it always was, and no new session event
or message role exists for this. The append is preceded by finalizing the in-progress assistant
stream (`commitQuestionRecord`), so the model's pre-call prose is committed as its own block instead
of absorbing whatever it says after the form; that seal runs for a **dismissal** too, because a
dismissed form still continues the same turn and its later text must not join the earlier prose.

On `/resume` the record is **rebuilt from the saved call/result pair**, never from anything new on
disk: `askUserBlocks` reads each assistant record's persisted `ask_user` calls and pairs each with
the **one** matching role-`tool` result **in that record's own response group**, so an id a later
round reuses cannot be paired here. The pair must be one the live form could have produced — the call
is re-checked with the same provider-owned request checker production dispatch runs, and the saved
result is re-encoded through the same `QuestionResult.Encode` and compared **byte for byte** with the
stored text, which refuses anything `encoding/json` accepts but the form never writes (a repaired
lone surrogate, an unknown or repeated member, whitespace between tokens, a `null` where the form
writes an empty array). Prompts come from the saved call, and an answered result must line up with
that call's questions one for one. Rebuilds nothing: an undecodable call, a call with no result or
with two, an id shared by another call in the group, a saved cancellation, a clarification that is
untrimmed/empty or past its bound, and an answer set that does not match its call. A resumed
transcript can therefore show less of a turn than the live pane did, never more; unrelated tool
results are model-continuation data and are skipped as always. *Proof:* `tui/transcript_content.go`
`questionRecordBlock`/`questionAnswerText`, `tui/question_prompt.go`
`finishQuestionForm`/`commitQuestionRecord`, `tui/app_replay.go`
`askUserBlocks`/`askUserReplayBlock`/`replayResult`/`toolResultsAfter`;
`TestQuestionPrompt_SubmittedFormSealsThePreambleThenRecordsTheAnswer`,
`TestQuestionPrompt_ClarificationRecordIsDistinctAndKeepsTheLaterAnswerSeparate`,
`TestQuestionPrompt_DismissedFormSealsThePreambleWithoutRecordingAnAnswer`,
`TestQuestionPrompt_RecordsNoAnswerForAnUntouchedQuestionAndNothingForACancelledForm`,
`TestQuestionPrompt_RecordKeepsTagShapedTextLiteralAndHidesTheToolPlumbing`,
`TestReplaySessionRecords_RebuildsTheAnsweredQuestionRecord`,
`TestReplaySessionRecords_RendersNothingForAnUnpairableAskUserCall`,
`TestReplaySessionRecords_RejectsAResultThatDoesNotMatchItsAskUserCall`,
`TestReplaySessionRecords_PairsEachAskUserCallInsideItsOwnResponseGroup`,
`TestStartTUI_AskUserContextClarificationAndRecordSurviveTheWholeTurn`.

**16.** Every rendered option carries one: **allow this [o]nce**, **[d]eny**, **allow for this
[s]ession**, **allow in this [f]older permanently**, **allow [g]lobally permanently**, and the
host-only **allow in this [p]roject**. The letter is shown inside the row's own label, wrapped in
literal brackets and drawn in the shared teal accent — the brackets are the non-color cue, so the
mapping is readable where the accent is not. Case does **not** matter (`o` and `O` both work) and
**no Enter** is needed — the option list's input capture moves the cursor to that row, calls the same
`selectOption` closure a click or arrow-plus-Enter calls, and consumes the key so it reaches no other
handler. Since the lookup runs over the rows this prompt actually renders, a letter for a withheld
option is inert: `f` when the out-of-root rule hides the folder row, `g`/`f` on a host prompt, `p` on
any non-host prompt, `s`/`f`/`g`/`p` on a fresh host confirmation. Routing through the shared closure
means `s`/`f`/`g` on a direct command still open the scope sub-choice, and `f` stores the same folder
grant — its scope is the resolved run folder and its descendants, not the project root its settings
file lives in. The shortcuts are **primary-screen only** — the scope chooser, the Program-scope
confirmation, and the compound stage chooser keep mouse/arrow/Enter-only interaction — and with no
prompt open the letters are ordinary typed input.
*Proof:* `tui/prompt.go` `promptMnemonics`/`promptRowLabel`/`promptMnemonicIndex`/`buildPromptOverlay`;
`TestPromptOverlay_MnemonicLabelsAccented`, `TestPromptUser_MnemonicAllowOnce`,
`TestPromptUser_MnemonicDeny`, `TestPromptUser_MnemonicSessionEntersScopeChooser`,
`TestPromptUser_MnemonicFolderEntersScopeChooser`,
`TestPromptUser_MnemonicFolderStructuredToolSelectsImmediately`,
`TestPromptUser_MnemonicFolderInertWhenOptionWithheld`,
`TestPromptUser_MnemonicProjectInertOffHostPrompt`,
`TestPromptUser_MnemonicGlobalEntersScopeChooser`, `TestPromptUser_MnemonicStructuredToolDecisions`,
`TestPromptUser_MnemonicHostPrompt`, `TestPromptUser_MnemonicHostHasNoGlobalShortcut`,
`TestPromptUser_MnemonicHostFreshConfirmationHasNoDurableShortcut`,
`TestPromptUser_MnemonicsInertOnScopeChooser`, `TestPromptUser_MnemonicsInertOnProgramConfirm`,
`TestPromptUser_MnemonicsInertOnCompoundStage`,
`TestApp_ApprovalMnemonicsAreOrdinaryInputWithoutPrompt` (`tui/prompt_test.go`).

**17.** The panel has **dynamic colors on**, so a bare `[click to copy]` is parsed as a color tag and
drawn as nothing at all — `RenderStatus` emits it through `tview.Escape` as `[click to copy[]`, the same
treatment the `[global]`/`[project]`/`[local]` layer labels already need. The teal-underline tag around it splits
the opposite way and is written **raw**, because an escaped tag would draw literally instead of styling
anything; the whole thing closes with the absolute reset *and* an explicit `[::U]`, because that reset
restores colors and ordinary attributes but leaves the underline flag set, so without the second tag the
underline leaks into the lines after it. A
test asserting on the returned string alone
cannot tell the two apart: the raw markup contains `[click to copy]` either way, so the assertion has to
go through the panel's `GetText(true)`, which is what the view actually shows, and pin both halves of the
split in the raw markup. The copied value is
`StatusState.SessionID()` read off `App.statusLineState` — the same object production hands to
`NewStatusHandler` — captured **when the overlay opens** (`armStatusCopy`), not when the click lands,
so the copy stays tied to the frozen snapshot; text is never scraped back out of the panel.
Activation is a **click**: press and release must both resolve to the control. A press on the control
released elsewhere finishes as an ordinary selection, and a press outside the panel released on the
control copies nothing — that press takes no `beginSelect`, so it clears the candidate explicitly
rather than leaving a stale one from an earlier open. The range is **byte offsets into the visible
text** because a narrow terminal wraps the session line onto a continuation row (and, narrower still,
splits `[click to copy]` itself across two): `statusView.offsetAt` is byte-offset based, so every part of a
wrapped control still maps into the range, while a cell rectangle would address the wrong screen row.
`offsetRowAt` additionally reports whether the column landed on the row's own text, which is what
keeps the blank padding at the end of the preceding row — one byte offset away from the control's
first character — from firing it. The transcript's code-block controls answer all of this the same
way because both run on the shared `clickRegion`/`clickRegions` pair: the list of `{byte range,
payload}` entries and the press/release gate are the mechanism's, while each view supplies its own
`offsetRowAt` mapping and its own lifecycle for installing and clearing the list (`ShowStatus`/
`dismissStatus` for the panel, `renderLocked` for the pane). A success copies over the **same OSC 52
path** as every selection,
leaves `/status` open and focused, and shows `Session ID copied`; **no session record is appended**
and the snapshot is not mutated. Over SSH the sequence reaches the local clipboard **only when the
client terminal and the SSH path both allow OSC 52** — codemeld emits it and cannot confirm delivery,
so drag-select stays the fallback.
*Proof:* `tui/cmd_status.go` `RenderStatus`/`statusCopyControl`/`statusSessionPrefix`,
`tui/app.go` `armStatusCopy`/`statusCopyRange`, `tui/app_selection.go`
`clickRegions`/`statusRegionAt`/`offsetRowAt`/`handleAppMouse`;
`TestRenderStatus_SessionLineCarriesEscapedCopyControl`,
`TestApp_StatusCopyControlHitTestFollowsWrappedText`,
`TestApp_StatusCopyControlNeedsPressAndReleaseOnIt`,
`TestApp_StatusCopyControlClickCopiesSessionIDThroughDispatch` (`tui/cmd_status_test.go`).

**18.** **No options and no keystroke** — the prompt never opens. The protected-state policy refuses
the call inside `PrepareTool`, before the prompt gate is reached, so there is nothing on screen to
approve: not "allow this once", not "allow globally permanently". What you see is the ordinary
denial notice followed by the model continuing, because the refusal is a `denied_by: "guard"`
envelope and the loop treats it like a mode denial: a further provider round runs and the agent
typically tells you to use `/settings`. The turn does **not** end (a `denied_by: "user"` refusal
would end it). `/settings` — and the other dedicated typed writers behind `/model`, `/effort`,
`auth`, and `/connect` — is the supported route, because those are typed Go calls rather than tool
dispatch. Supported, not exclusive: the guard covers only the five structured file operations, so
the VCS mutation tools and a granted raw `bash` command can still rewrite that file. *Proof:* `PrepareTool` (`dispatch/tool.go`), `denyProtectedState`
(`bootstrap/tooldispatch.go`), `IsRecoverableDeniedBy` (`permissions/denyenvelope.go`),
`decodeDenyEnvelope` (`turn/tools.go`); pinned by
`TestStartTUI_ProtectedSettingsMutationIsRefusedAndTheTurnReIssues`
(`bootstrap/starttui_test.go`).

**19.** **Three states, rendered by `RenderContext` off `BuildContextSnapshot`
(`internal/tui/cmd_context.go`):**

1. **Every record reports a count** — `Token usage: N input (C cached), N output (N total)`. A
   reported `0` is a measurement and renders as `(0 cached)`.
2. **The total is a known lower bound** — `Token usage: N input (at least C cached), N output (N
   total)`, followed by `Cached-token usage is incomplete because some responses did not report it.`
3. **No record reports a count** — `Token usage: N input, N output (N total)`, exactly as before the
   counter existed, with no cached clause at all.

**The two conditions behind state 2.** A contributing record carries
`cached_input_tokens_partial: true` (that turn itself had a round reporting nothing), **or** some
record omits `cached_input_tokens` entirely while another reports one. Either way the sum is real but
incomplete, so it is labelled `at least` rather than dropped or presented as exact.

**Why not `0 cached`.** No provider measured zero — printing it would report a measurement that was
never made. That violates the rule to keep unknown data honest rather than invent precision.
The `Context window: unknown` line two rows down follows the same rule: it prints an explicit
unknown and **no** percentage rather than a plausible-looking one.

**No — the notices are independent.** `Token counts: incomplete (some turns did not report usage)`
means a `usage_missing` anomaly on some turn and concerns the input/output totals; it was
deliberately not widened to cover cached tokens, and either notice can appear without the other.
*Proof:* `BuildContextSnapshot` and `RenderContext` (`internal/tui/cmd_context.go`), pinned by
`TestRenderContext_ExactCachedUsage`, `TestRenderContext_PartialCachedUsage`, and
`TestRenderContext_NeverReportedCachedUsage` (`internal/tui/cmd_context_test.go`), with the
end-to-end path pinned by `TestRun_CachedPromptTokensReachRecordAndContext` and
`TestRun_UnreportedCachedTokensLeaveContextUnchanged` (`internal/turn/turn_test.go`).
