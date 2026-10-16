# Module 10 — TUI

_Snapshot as of 2026-10-06; it may be out of date — refresh it from the code before studying._

_Last updated: 2026-10-06_

> The terminal UI is the front of the whole app: it parses what you type, shows the transcript,
> renders the permission prompt, and streams the model's reply. It's the largest package (~57 files)
> — this module covers the conceptual spine, not every file.

## Goal

After this module you can:

- Describe the tview app shell and its main panes.
- Explain how input becomes either a slash command or a prompt, and how commands dispatch.
- Recite the permission-prompt option order and explain how the decision flows back.
- Explain how streamed deltas reach the screen safely while a turn is running.

## Why it matters

This is where permissions (Module 5) and turns (Module 8) become visible. The thread-safety model
(mutate UI state only on the loop, marshal everything else through a queue) is the package's core
discipline.

## Read (in order)

1. `internal/tui/app.go` — the `App` shell, `Run`, `submitCurrent`, `streamUpdate`.
2. `internal/tui/slashparse.go` — `ParseSlashInput`.
3. `internal/tui/registry.go` — `Registry.DispatchSlashInput`, the command set.
4. `internal/tui/prompt.go` (+ `prompt_scope.go`) — `PromptUser`, the option order.
5. `internal/tui/transcript.go` — the streaming/transcript surface.
6. `internal/tui/input.go` and one `cmd_*.go` handler (e.g. `cmd_status.go`).

## Mental model

### The model picker overlay

The model picker (CTRL-M) opens a provider-grouped model table with a live filter field that
narrows the list as the user types. The filter uses **contiguous multi-term matching**:
each whitespace-separated query term must appear contiguously (case-insensitively) in at least
one of the row's searchable fields — model ID, stable provider ID, or provider display label.
Different terms may match different fields. A row whose first query term is a case-insensitive
prefix of its model ID ranks ahead of other matching rows within the same provider group.

When a favorites capability is wired, the picker renders a **Favorites** section above the provider
groups: a non-selectable `Favorites` heading followed by the saved pairs in their stored order, each
shown as a provider-qualified alias (e.g. `OpenAI ChatGPT · gpt-5.5`). A favorite is identified only
by its exact `{provider, modelID}` pair — two favorites sharing a model id under different providers
stay distinct — and every alias maps back to the same canonical provider-group row, so Enter, the
effort control, and filtering behave identically whether you act on the alias or the group row.
Aliases follow the same filter matcher as the groups, duplicate pairs collapse, and a favorite whose
pair has no current catalog row is silently omitted (never written away). **Ctrl-F** adds or removes
the highlighted exact pair through the injected capability; the picker stays open and rebuilds its
aliases only from the snapshot a confirmed toggle returns. If the toggle fails it leaves the rows,
query, highlight, and snapshot untouched and shows a notice. The picker owns none of the persistence:
the saved list and its durable write live in the config/cache layer (Module 4).

The filter field accepts all printable characters, including `r`. The **Ctrl-R** key (not lowercase `r`)
triggers a forced refresh of the highlighted provider's catalog. Ctrl-R is consumed locally by the
picker while it is open; when no model picker is open, Ctrl-R still opens history reverse-search.

### The file-reference picker (`@`)

Typing `@` mounts the overlay immediately showing the guidance row `type to search project files`, and
**walks nothing** — an empty query never starts a search. A non-empty query replaces the list with
`searching...` and schedules a background search after a **rune-count** debounce: 400 ms while the
query is one rune, 250 ms for anything longer (`fileRefDebounceDelay`). Clearing the query back to
empty returns to the guidance row and revokes the search in flight.

`searchFileRefs` traverses the **complete** codemeldignore-filtered tree; 50 (`fileRefSearchLimit`) is
an *emission* bound, not a traversal cap. It collects every match — whole project-relative path
containing the query as one contiguous, case-insensitive substring — and only after the walk ends ranks
them (`rankFileRefMatches`): the exact path first, then paths starting with the query, then paths whose
last element starts with it, then any other match; within a rank, shallower paths (fewer `/`) come
first, and ties keep walk order (a stable sort). It then emits the 50 best-ranked matches. A walk error
(say, an unreadable directory) still emits the ranked matches found so far before returning the error;
cancellation emits nothing. Completion is signalled only by **returning**. Every `emit` is synchronous,
so all displayed rows are applied before the final outcome is — rows first, then one of: a nil error
with rows (keep them), a nil error with zero rows (keep the picker open showing a non-selectable
`no matches` row, so the query can still be edited), a non-nil error (a notice, plus the
`search failed` row *only* when no row had arrived), or `context.Canceled` (silent — nothing is shown
for a search the user already replaced). No search closes the picker: only Enter, Esc, or a confirmed
selection does, and Enter or Esc with no selectable row leaves the typed `@query` literal.

On submit (`dropFileRefAt`), the leading `@` is removed from each whitespace-separated word that starts
with `@` and has at least one character after it, unless `os.Lstat` finds an entry at `filepath.Join(projectRoot, word)`, the whole word, `@`
included. The join cleans `..` components with no check that the result stays under the project root,
so `@/../../marker` keeps its `@` when a `marker` entry exists beside the project root folder. A prompt
starting with `/` is left untouched.

Ownership is a **generation counter**, not a cancel handle: `afterFunc` hands back nothing to cancel,
so `invalidateFileRefSearch` bumps `sess.searchGeneration` (and cancels the worker context when one is
running), and every queued effect re-checks `ownsFileRefSearch(sess, gen)` before touching the list. A
timer that fires for a superseded query, a row from a replaced search, or a final for a dismissed
session is dropped. The worker goroutine never touches tview directly: rows and finals are marshalled
onto the event loop through `streamUpdate`, the same queue the stream deltas use.

### The `/settings` picker

The overlay has four fixed tabs. The first three show the stored grants — commands/tool grants,
folders, project hosts — each sorted by its rendered row text. Tab navigation is **directional**: Tab
and → move to the next tab, ← moves to the previous one, and both wrap (← from the first tab lands on
settings). ← is the only backward key because the app-level capture consumes Backtab for mode cycling
before the picker ever sees it.

The fourth tab of the `/settings` overlay, **settings**, is not a grant tab: it renders its own rows
rather than routing through `activeRows`, which returns no grants there so every grant-shaped action
stays inert — `r` opens nothing. Its four rows — OpenRouter attribution, data collection, sort, and
max price — are all served by one injected read/write seam, `OpenRouterSettings`: a struct of getter
and setter functions bound to the config cache by `newSettingsDeps` in `internal/bootstrap/starttui.go`.
Every value is re-read from that seam on every repaint, so a failed write leaves the row at its
on-disk value and reports the failure as a one-line notice — there is no optimistic update.

The **sort** row cycles on Enter through three modes: default → throughput → best value → default.
While the sort row is highlighted, a one-line help under the list explains the current mode. Default
sends no `provider.sort`, leaving OpenRouter's normal routing (healthy providers, cheaper ones picked
more often). Throughput sends `provider.sort: "throughput"`: fastest providers first, whatever the
price. Best value sends `provider.sort: "price"` and, when the model's endpoint metadata gives a
usable speed bar, adds `provider.preferred_min_throughput` set to the lower-middle median of the
providers' p50 throughput, so slower providers go last; with no usable speed data it sends the price
sort alone (`internal/provider/client.go`). Successful metadata is reused for 12 hours, and a failed
fetch is retried after a 15-minute backoff (`internal/provider/openrouter_endpoints.go`). A value set
by hand in the settings file that is none of the three, such as `latency` (which still works), is
shown as written, its help line says it was set in the settings file, and Enter moves it to default.

When the active model is an OpenRouter model, the sort row also shows an estimated price for the
current mode, `about $<input> / $<output> per M`, plus the discount when the chosen provider offers
one. It picks from the model's endpoint list: the cheapest provider for default, the fastest for
throughput, and the cheapest one at or above the speed bar for best value. The estimate is a guide,
not a quote: it ignores data collection, ignored providers, max-price caps and tool support, all of
which can change which provider OpenRouter actually uses. The metadata is fetched in the background
and the row repaints when it arrives.

The **max price** row covers only the active model, whose id appears in its label:
`openrouter max price (<model id>)`. For a model that is not an OpenRouter model it reads
`active model is not an OpenRouter model` and Enter does nothing. Otherwise Enter opens an editor with
two separate, optional caps in US dollars per million tokens, labelled `input  $ ` and `output $ `
to match the words on the OpenRouter website; Tab, ↑ and ↓ move between them and Enter saves. The
row then reads `input $<p> / output $<c> per M tokens`, with `none` for an empty cap, or just `none`
when the model has no entry. The settings file stores the two caps under the YAML keys `prompt` and
`completion`, the names OpenRouter's API uses, and saving with both fields empty removes the model's
entry. A value that is not a number of at least 0 is refused with a notice naming the field, and
nothing is written.

`r` opens the revoke confirmation for the highlighted grant on the three grant tabs. The picker owns no persistence: the
injected seam removes the grant and surfaces its own skip/failure notice, then the picker re-reads
the **live** grant list and rebuilds the rows, so a skipped revoke simply leaves its row in place.

That seam is `productionAuthorizer.RevokeGrant` (`internal/bootstrap/authdeps.go`), and its ordering
is the part worth learning. A revoke touches two files that cannot be committed together: the
settings file and the session. So the order is fixed — delete from settings, **drop the live grant**,
then record a `permission_revoke_requested` event and flush it. The live grant goes first because a
revoked grant that keeps authorizing is a worse outcome than a revoke with no record; the cost is
that a crash between the two leaves a real revoke unrecorded, which is accepted rather than papered
over. A memory-only session grant has no file to delete, so its removal from the table *is* the
revoke — and it records only when that synchronized removal reports it actually removed something,
so a stale or duplicate `r` stays silent.

Because the grant is already gone by then, a recording failure can never be reported as a failed
revoke. The command flush hook (`newCommandFlush`) owns the `session_write_failed` notice/retry
protocol and returns nil once it has handled such a failure, so the revoke adds no second notice and
no second event — the appended record just waits for the next flush boundary. Only an append
rejection, or a flush error that protocol does not own, produces the revoke's own "revoke not
recorded" notice, which says plainly that the grant *was* removed.
Rebuilding the list would reset the cursor to the top, so the picker restores it afterwards: when
the revoked grant is gone from the refreshed tab the cursor lands on the row **above** the deleted
one (clamped, so revoking the first row selects the new first row and revoking the last row selects
the new last row); when the grant is still there — a skip or failure — the original row stays
selected. Revoking the only row leaves the `(no grants)` placeholder, which backs no grant and so
can never itself be revoked. The overlay stays open and focused on its list after every attempt.

### The multi-question form (`ask_user`)

When the agent needs a decision from you it calls the product-authored `ask_user` tool instead of
writing an interview in prose. That tool is **interactive-only**: `StartTUI` wraps the shared tool
advertiser (`newInteractiveToolAdvertiser`) to add it for the live TUI, and binds `App.AskQuestions`
as its dispatch target, so a headless run advertises neither the form nor a substitute and a model
that calls the name anyway gets the ordinary unknown-tool refusal.

The call is **dispatched, not intercepted** — unlike `suggest_followup`, which the turn loop drops
before persistence. The advertised schema states what JSON Schema can: at most 5 questions, 8
options each, 1–200 characters per id, prompt, and option label, distinct option labels, the three
required keys, and no other properties. A provider is free to send something else anyway, so
dispatch re-checks every one of those bounds itself, through the one strict checker the **provider**
package owns (`DecodeAskUserRequest`) so that dispatch and `/resume` replay cannot drift apart, and
adds the rules the schema cannot express — an id repeated within the call, a
`multi_select`/`allow_custom` sent as `null` or a non-boolean rather than omitted, and any trailing
JSON after the one object. It decodes
each object as raw key/value entries and accepts only the exact advertised property names, because
`encoding/json` matches a struct field **case-insensitively even with `DisallowUnknownFields` set**:
decoded into a struct, `"Questions"` and `"ID"` — which the closed schema rejects — would mount a
form. Displayed text is the interesting one. `AskUserTextRenderable` is the authoritative rule and it
asks whether the *terminal* can show the value: every rune must be printable, no rune may be a
graphic character that draws nothing, and at least one grapheme must occupy a cell. `unicode.IsPrint`
admits the ASCII space and no other whitespace, so that refuses a prompt of only a BOM, a NEL or a
combining mark — each of which passes every length, id and option check and then mounts as an empty
question — and refuses a tab or newline sitting beside visible text, which the region would measure
at one width and `TextView` would then draw at another. Printability is not enough on its own:
`U+2800 BRAILLE PATTERN BLANK` and the Hangul fillers are *graphic* characters that Unicode files as
symbols and letters, so `IsPrint` admits them and `IsSpace` does not exclude them, and a request
whose two options are `U+2800` and `U+3164` would mount two distinct values that both look blank.
`askUserBlank` names them and both layers refuse them wherever they sit.
The advertised `AskUserTextPattern` is the same rule as far as a JSON Schema `pattern` reaches: it is
anchored, so the blocked class is refused at every position rather than only in a value with nothing
else to show, and it is written as a class of literal characters rather than `\s`, because ECMA-262
`\s` and Go's `\s` cover different sets and each layer would otherwise enforce a rule the other does
not. That class is not a hand-picked list of the whitespace someone thought of: it names every
separator and every *assigned* control, format and private-use code point in the BMP (Unicode `Z`,
`Cc`, `Cf`, `Co`), plus the blank graphic characters above, so a bidi override, an invisible operator
or a braille blank beside visible text is refused by the schema as well as by the decoder. Three things a `pattern` cannot say are left over: that a grapheme
must occupy a cell, so combining-mark-only text still matches; which code points Unicode has not
assigned, since a fixed class enumerating them goes stale at the next revision; and anything outside
the BMP, because a JSON Schema pattern is ECMA-262 and an engine compiling it without the `u` flag
reads an astral character as two surrogate code units — a range between two of them is a range in the
wrong order, and the *whole pattern* stops compiling, which would cost the schema far more than the
tag character it excluded. All three differences are deliberate and one-directional — the schema may
advertise text the decoder then refuses in band, never the reverse — and they are the *only* three:
`TestAskUserTextPattern_DivergesOnlyWhereAPatternCannotFollow` sweeps every code point Go can put in
a string and fails on any other disagreement, while a shared table in `internal/testsupport` carries
both verdicts for the named cases.

One more thing has to be checked before the text is even a string. `encoding/json` **repairs**
malformed input rather than rejecting it: a lone surrogate escape such as `"\ud800"`, or an invalid
UTF-8 byte, silently becomes U+FFFD and no error is returned. U+FFFD is printable, so every rule
above would pass on a value the model never sent — and two different malformed ids would collapse
onto the same answer key. The decoder therefore inspects the raw JSON token first
(`provider.AskUserDecodesUnchanged`) and refuses anything `encoding/json` would rewrite; U+FFFD sent as itself
is ordinary text and stays accepted. Anything invalid is refused **in band, before any form is
mounted**, so the model can correct itself and the user is never shown a malformed question set.
Whatever *is* accepted is used **exactly as sent**: the id an answer comes back under is the id the
model sent, surrounding spaces included, because rewriting it would hand the model back a key it
never chose.

`AskQuestions` mounts the form and **blocks the turn goroutine** until you answer it, marshalling the
mount and the teardown through `streamUpdate` like the other off-loop surface methods. One form holds
every unanswered question but shows **one at a time**: `questionStage` places a `Question k of n`
counter above the block that currently owns focus. Only that question is placed in the flex — tview
draws a child past its parent's rect rather than clipping it, so a question that is not being shown
has to be out of the layout entirely, not merely sized to zero.

One question at a time is a deliberate reversal. The form first rendered every question at once
across width-derived columns, which at the advertised maximum — 5 questions of 8 options with
200-character text, roughly 18,000 terminal cells against a 20x24 screen's ~360 — is an unreadable
wall: truncated labels, one question's prompt wrapping between another's options, and nothing saying
which question has focus. It also made "the narrow layout exposes every question" unsatisfiable, and
the review finding chasing it was re-raised in four consecutive rounds against four different
elements of that layout. Showing one question removes cross-question packing and scrolling entirely;
what is left to overflow is a single question, which scrolls inside its own region.

A call may also carry a request-level **`context`**: one plain-text paragraph of background shared by
every question in it, up to 2,000 runes, drawn in its own section at the top of the form above them.
The advertised schema asks the model to send it whenever a reasonable person could need to know why
the decision is being asked for, what it affects, or what a technical term in it means, and to leave
it out only for a choice that explains itself — without it the user is deciding blind. It is
displayed literally: dynamic colors are off and nothing is parsed as markdown, so text written as
`**bold**` is shown with its asterisks. The section word-wraps and scrolls on its own — it is a stop
on the focus ring, and **↑↓**/**PgUp/PgDn** scroll it while it holds focus — and `sizeContext` caps
its height at a third of the form's, so a long paragraph scrolls instead of pushing the question and
its options off a 24-row terminal. A call that sends no `context` mounts no section at all. Nothing
else about the form moves: it is still the interactive-only surface, and what you submit is still
returned as an ordinary tool result.

Navigation is the whole focus ring, so every question is reachable and the buttons are always
placed: `Tab` and **←/→** step the shared context section when the call sent one, then the question
regions, each *open* custom-answer field, then `Ask clarification` and its *open* entry, then Submit
and Cancel, wrapping at both ends, and whichever question owns the focused control becomes the one
shown.

`‹ Prev` and `Next ›` exist because that ring is not a route a *mouse* has. A pointer can only act on
what is drawn, and one question is drawn at a time, so without a clickable control a mouse-only user
could answer the first question and nothing else. Clicking one moves the shown question (wrapping, so
neither is ever a dead button) and leaves every answer and scroll position as it was. They are drawn
in the stage, on the row **directly under the question they move**, and they are deliberately **not in
the focus ring**: the keyboard already steps the questions themselves, so ring stops there would only
stand between the last question and Submit. Submit and Cancel keep their own row at the bottom of the
box — two buttons per row, because at 20 columns four on one row would push Submit and Cancel off the
right edge.

A question's prompt and every one of its option rows are rendered into **one scrollable region**,
`questionOptions`, and each label **wraps in place** across as many lines as it needs. This replaces
`tview.List`, which prints an item with a single one-line write and so forced a label to be *fitted*
to the width with an ellipsis — and a fitted label then needed a second surface to show its full
text. Nothing is shortened here, so there is nothing to reveal: no ellipsis, no detail line, and no
prompt-clipping case. `questionOptions` keeps `owner` (which option each rendered line belongs to,
`-1` for the prompt's own lines) and `starts` (each option's first line) so a mouse click, the
keyboard cursor and the scroll offset all agree with the wrapping actually drawn.

The region scrolls rather than growing: **↑↓** move the option cursor and pull the view along,
**PgUp/PgDn** page it, and the **wheel** scrolls it from anywhere over the question. Scrolling is
*not* undone by a relayout — `questionBlock.layout` deliberately does not call `ensureVisible`,
because layout runs on every focus change and resize, and pulling the view back to the current option
there would silently discard a scroll the user just made with the wheel. Only moving the cursor calls
it.

Where the reader is, is kept as a place in the *text* rather than as a line number
(`questionAnchor`: which prompt or option, and how far into it). A display line number would not
survive either half of a resize. A new width rewraps every line, so the same numbered line is
different text afterwards; and a width wide enough to fit the whole question makes `TextView.Draw`
clamp its own offset to zero, so a number carried across a widen-and-narrow round trip comes back as
the beginning of the question. Every deliberate move — wheel, page, cursor — records the anchor
through `scrollToLine`, and `render` maps it onto the new wrapping *without* recording, which is what
lets a temporarily wide layout clamp tview's live offset without costing the reader their place. An option taller than the region is pinned to its first line so its chosen/unchosen mark stays on
screen, which is why PgUp/PgDn exist: they are the way to read such an option's tail.

Reachability, not simultaneous visibility, is the property that holds. At the advertised maximum the
request is tens of screenfuls on a 20x24 terminal, so no layout can show it all at once; what the
form guarantees is that every accepted rune can be brought on screen.

Prompts and labels are wrapped at the width they are actually drawn at — the region width for a
prompt, that minus `questionRowMarkWidth` for a row, since every row carries a mark and a space.
Measuring either at some other width desynchronizes what the layout budgets from what the terminal
renders, which is enough to collapse a question's option list to a single row.

Option and prompt text is provider data, not markup: `questionOptions.render` passes every label and
prompt through `tview.Escape`, and the only style tags in the rendered text are the ones it adds
itself to highlight the current row, so a label like `[red]Keep local[-]` is shown and submitted
exactly as written. The widget mirrors its focus state in a `focused` field rather than asking
`HasFocus()`: `TextView.Focus` holds the widget lock while it calls the focus callback, and both
`HasFocus` and `SetText` take that same lock, so rendering from inside that callback deadlocks.

Controls: **↑↓** move the option cursor, **Enter** or a **mouse click** chooses a row, **Tab** steps
forward through the focus ring enumerated just below, **PgUp/PgDn** scroll the question region,
**Ctrl-S** submits from any control including both buttons, **ESC** cancels.

**←/→** step the same ring `Tab` does rather than hopping question-to-question: that ring is the
context section when there is one, every question region, each *open* custom-answer field,
`Ask clarification` and its *open* entry, then Submit and Cancel, and it wraps at both ends
(`‹ Prev` and `Next ›` are outside it, being the mouse's route).
So **←** on the ring's first stop — the context section, or the first question when no context was
sent — lands on **Cancel**, and **→** on a question whose custom field is
open lands on that field, not on the next question. Which arrows navigate depends on what else they
could mean for the focused control: on a question region ↑↓ belong to the option cursor, so only ←/→
step the ring; in an open custom field ←/→ edit the text, so **↑** steps back to that question's
options and **↓** forward; on a button no arrow has another meaning, so all four step the ring
(→/↓ forward, ←/↑ back). Backtab is deliberately unbound — the app-level capture consumes it for mode
cycling before the form sees it.

Only the question region that owns keyboard focus draws a highlight, so it always says where the next
**↑↓**/`Enter` lands and never reads as a preselected answer. The mounted page is **modal to the
mouse**: a click's button-down that no control takes is consumed by the form rather than falling
through to the input area underneath, which would otherwise take focus and swallow the rest of the
gesture before the click reached the option row. Clicking fast is safe too. There is no double-click
gesture in the form — one click selects the row and its option — but tview classifies a click as a
double by **time alone**, so two quick clicks arrive that way whether or not they landed on the same
row. The form therefore treats a double click as the click it is (controls acting only on a plain
click would otherwise drop it), except when it repeats the row the click before it just chose
(`actOnClick`): acting twice there would uncheck a checkbox the user just checked, or close an open
custom answer and discard the text typed into it. "The click before it" means the click before it
*anywhere in the form*: clicking `Next ›`, a button or blank space clears the remembered row, so a
later click on that row is an ordinary click again. Without that, a multi-select user who came back
to a question could no longer turn an option off, since tview keeps classifying by time no matter
what was clicked in between. A drag that was already in progress when the form went up is **discarded at
the mount** (`discardActiveDrags`): `handleAppMouse` answers a move or a release from an active input
or transcript selection *before* its overlay guard, and both release paths focus the input, so a drag
that outlived the mount would hand the keyboard back to the input area under a form that is still
open. Nothing is copied, because the button was never released. It stays modal to the
**keyboard** too: a terminal blur/return that
leaves focus on the input underneath is repaired by `restoreModalFocusOnTerminalFocus`, from the
terminal's focus-gained event and again from the first key after it, and it restores whichever
control last held focus — every control records that from its own focus callback, so a question the
*mouse* focused is the one the keys come back to. A **bracketed paste** is the third route into that
repair and needs its own: tview collects a paste itself, without ever calling the app's key capture,
and hands the finished block to the **root** primitive. `rootPages.PasteHandler` therefore repairs
modal focus before delegating to the pages, so a paste that arrives while focus is stale lands in the
open custom field — or, with a non-text control focused, is discarded — instead of being typed into
the draft under an open form.

**Selecting the question text.** The prompt and every option label can be dragged over and copied,
with the same press-drag-release the conversation pane and `/status` use and through the same OSC 52
path. The *highlight* is shared code — the anchor/range state, the reverse-video pass and the
column-to-byte mapping live in `textSelection`, which `statusView` and `questionOptions` both hold.
The *copy* cannot be. `questionOptions` draws its own hard-wrapped rows, each option row behind a
mark and a space, so slicing what is displayed would copy a wrapped path as its first half, a
newline and four spaces. Instead every rendered row records the byte offset it begins at **in the
original prompt or label**, and a selection is projected back onto those strings: rows of one option
come back as one contiguous slice of it, and only a move from one prompt or option to the next puts
a newline in. No mark, no padding and no wrap-inserted break reaches the clipboard. Those offsets
have to come from the source rather than be measured off the rendered lines, because `render` wraps
`tview.Escape`d text — a third coordinate space, since `Escape` inserts a `[` into anything
tag-shaped and `WordWrap` drops the newline at a hard break — so a label written as
`[red]Keep local[-]` would otherwise copy back with an escape artifact in it. Nor can a row's offset
be recovered by *searching* the source for the row's un-escaped text: a wrap can leave the inserted
`[` at the end of one row and its `]` at the start of the next, and that fragment un-escapes to
something the source does not contain anywhere, so the search fails and the row silently keeps a
stale offset. The offsets are therefore carried straight through the escaping — `Escape` only ever
inserts a `[` ahead of a `]`, so every escaped byte maps back onto exactly one source byte, and a
row's start is read off that map rather than looked up.

The gesture is owned at the app level (`handleAppMouse`), ahead of the overlay pass-through, because
the form acts on the *click* and not on the button-down. Only the press is hit-tested against the
question's rect; after that every move and the release belong to the drag wherever the pointer is,
including the release tview delivers with a **nil event** when the same-event move already consumed
it. That is why the release branches on whether the pointer moved rather than on comparing the
release position to the press — a nil release has no position to compare. A press and release that
never moved is left alone, so `actOnClick` keeps deciding it exactly as before; a drag arms a
one-shot suppression so the click-class action that can still follow it does not choose a row, and
the next button-down disarms that, so a later genuine click is never swallowed. A re-render during a
drag — a choice, a resize, a question change — drops the highlight and the row map at once but keeps
ownership of the physical gesture, so the drag copies nothing and chooses nothing rather than
turning back into a click. **Closing** the form mid-drag is the same two stages taken further: the
gesture is held on the app, not on the form, so it survives the form being torn out from under it,
and it goes on consuming its release and the click-class action after it rather than letting either
land on whatever the closed overlay uncovered.

Two limits worth knowing. Dragging past the top or bottom of an over-tall question does not
auto-scroll the way the panes do: scroll with the wheel or PgUp/PgDn first, then drag. And
Shift+drag is still the terminal's own selection, which kitty clears on its next redraw — that is
the defect the app-owned drag routes around, not one it fixes. The simulation tests here prove the
routing and the byte mapping only; whether a real emulator delivers drag motion between the press
and the release at all is not something they can see, which is why the kitty gesture check in
`docs/tui-mouse-debugging.md` is part of this behavior rather than an optional extra.

A single-select question marks its one choice `(*)` against `( )`; a multi-select question checks any
subset `[x]` against `[ ]`. The marks are plain ASCII on purpose: `●`/`○` are one ambiguous-width cell
that terminals and tview can measure differently, and a single glyph is too quiet beside the row the
cursor is on — in a real terminal a chosen row read as unchosen until the cursor moved off it. For the
same reason the cursor is the shared teal accent on the row's text rather than reverse video, which
paints a bar loud enough to swallow the mark beside it. Because the marks are bracket-shaped they are
escaped like any other text before the dynamic-colors view parses the line, or `[x]` would be read as
markup and vanish. The buttons take the opposite choice — a focused button *is* reverse video — for
the reason the rest of the TUI does: `applyTheme` makes both of tview's theme backgrounds the
terminal's own, while `NewButton` keeps a fixed blue foreground for its focused state, so on a
terminal whose own foreground is blue the focused button would look exactly like the others.
A question that declared `allow_custom` also offers a **`Type your own answer`** row: choosing it
reveals that question's own text field, focuses it, and (for a single-select question) replaces its
option choice. The typed text is recorded only under that question's id — nothing you do to one
question touches another's answer.

**Asking a question back.** `Ask clarification` is a form-level action rather than an answer mode,
with its own button on the ring between the questions and Submit. Choosing it opens a single text
entry under it (up to 1,000 runes) and focuses it; **Enter** or **Ctrl-S** submits, and choosing the
action again closes the entry and discards what was typed. Submitting with the entry open but empty
falls through to the ordinary answers, so Submit is never a dead button and the model is never asked
nothing. A clarification is returned **instead of** the answers, as exactly `{"clarification":"..."}`
with no `answers` key: `QuestionResult.Encode` marshals it through its own shape, because the
ordinary shape would pair it with an empty answer list the model reads as questions answered with
nothing. Cancelling while the entry is open is still a cancellation.

What the model does with one is the other half of the contract, and the advertised description says
it: reply to the clarification, then call `ask_user` again with **the same questions** and that reply
restated as the new call's `context`. The reopened form covers the screen, so an explanation left
only in the prose behind it is not what the person choosing is reading. That is what keeps the action
distinct from `Type your own answer`, which answers one question in your own words, changes no other
answer, and comes back as that question's answer rather than as a question for the model.

Submission encodes one entry per requested question **in request order**, each question's selections
in its declared option order, and a question you left alone as an explicit empty answer. The form
never fills in a default or a recommended option. That JSON is returned as an ordinary tool result, so
`ToolLoop.onToolCalls` persists it against the original tool-call id and the next provider round reads
back exactly what you chose.

**The cancellation boundary.** The form carries a **Cancel** button beside Submit — in the Tab ring
and clickable — and `HandleEsc` gives the form ESC **ahead of stream interruption** (like the masked
secret prompt). Both run the same `cancelQuestionForm` teardown. That ordering is the point: the agent
turn is blocked on the form's result, so an ESC or Cancel meant to dismiss the form must not cancel
the work behind it (Ctrl-C still interrupts the turn, which is a different thing). Cancelling delivers an
explicit `{"answers":[],"cancelled":true}` result, closes the page through the shared
`closeOverlayPage` teardown (restoring the focus captured at open, falling back to the input), and
leaves your typed draft untouched. Only a cancelled turn context tears the form down without
delivering a result.

**What the conversation keeps.** A delivered form leaves a compact record in the transcript rather
than its tool traffic (`questionRecordBlock`). An answered form appends an `Answered:` heading and
one `prompt — answer` line per question, a question you left alone reading `(no answer)`; a
clarification appends `Asked for clarification:` and the text you typed; a cancelled form appends
nothing at all. The record carries no JSON, no tool name and no call id — the role-`tool` result
stays the model's own copy and is persisted exactly as before, and no new session event or message
role was added for any of this. Closing the form first finalizes whatever the assistant had streamed
ahead of the call (`commitQuestionRecord`), so that pre-call prose is committed as its own block
instead of absorbing what the model says after the form; the seal happens for a dismissal too,
because a dismissed form still continues the turn.

**On `/resume`** those records are rebuilt, not reread. `askUserBlocks` walks each assistant record's
persisted `ask_user` calls and pairs each one with the single matching role-`tool` result in that
record's own response group, so an id a later round reuses can never be paired here. The pair then
has to be one the live form could have produced: the call is re-checked with the same
provider-owned request checker production dispatch runs, and the saved result is re-encoded through
the same `QuestionResult.Encode` the form wrote it with and compared byte for byte against what is
stored, which refuses anything `encoding/json` accepts but the form never writes — a repaired
surrogate, a reordered or unknown member, whitespace between tokens. Every prompt in the rebuilt
record comes from the saved call, and an answered result has to line up with that call's questions
one for one. A call with no result, with two, or with an id another call in the group also used; a
saved cancellation; and anything failing those checks render **nothing**, so a resumed transcript
can show less of a turn than the live pane did, never more. Unrelated tool results are model
continuation data and are skipped here as they always were.

### The app shell

`App` (`app.go`) wraps a `tview.Application` over `tcell`. Its root is a vertical flex of the
**transcript** (flex 1), a **single-line input** field (the focused primitive), and a **persistent
two-row footer**: row 1 carries the status segments (provider · model · effort · launch dir), and
row 2 carries the filled mode pill plus the `shift+tab to cycle` hint — nothing else. A session you
named with `/rename` shows up instead as an accent-colored tab sitting in the input area's **top
rule**, right-aligned two columns short of the edge; it truncates with an ellipsis and then
disappears entirely on a narrow terminal rather than eating the rule. Page-mounted overlays (the
permission prompt, pickers) are added as extra `pages`, but `/status` is **not** one of them: it
stays directly below the input in the root flex as a read-only, modal-equivalent surface that owns
keyboard and mouse focus until dismissed (`HandleEsc` dismisses it before stream cancellation, and
`handleAppMouse` keeps focus on it and swallows background clicks above the panel). `App.Run()`
starts the tview event loop and blocks until `Stop()`.

Every overlay registers once in `overlays()` (`overlays.go`): an ordered list of entries, each naming
one `App` open flag, the predicate that reads it, and how it dismisses. `HandleEsc` walks that order
and `anyOverlayOpen` (the guard that stops CTRL-E/CTRL-M/CTRL-R and `@` opening a second overlay) loops
over the same list, so an overlay cannot own ESC without also blocking the others. A test walks the
`App` struct and fails if an open flag has no entry — adding a boolean and a switch case is exactly the
drift that made ESC over a streaming turn cancel the turn instead of closing the picker.

### Slash commands vs prompts

`ParseSlashInput` decides: after trimming, a leading `/` followed by a name matching
`^[a-z][a-z0-9-]*$` is a **slash invocation**; a bare `exit`/`quit` is an exit; everything else
(including a lone `/`) is **plain text**. `Registry.DispatchSlashInput` resolves the name (canonical
or alias), checks the argument count, and runs the handler. An **unknown command or wrong arity**
renders a one-line notice, **retains the input**, and appends **no** event. A bare prompt is forwarded
to the turn/submit path (Module 8). When you type an alias, the **canonical** name is what gets
recorded in the session event.

`builtinCommands` in `registry.go` is the one source of truth for the shipped set, and each entry
declares the phase it becomes available in — `/help` lists only entries at or below `buildPhase`.
Phase 1: `help`, `clear` (alias `new`), `status`, `context`, `effort`, `model`, `mode`, `resume`,
`permissions`, `exit` (alias `quit`). Phase 2: `rename`, `color`, `connect`, `fork`, `compact`.
`BuildRegistry(replacements)` is the single copy point: unit tests build it with no replacements and
get the metadata-only registry, while `StartTUI` passes the real handlers in. Add a command by adding
one `builtinCommands` entry and one `BuildRegistry` replacement — never a second list.

**The `/compact` submit lease.** `StartTUI` wraps the *whole* `tui.NewSubmitFunc` adapter, not just
the prompt entrypoint, in a compact-in-flight gate. That placement is the point: `NewSubmitFunc`
dispatches slash commands *before* it reaches the prompt path, so gating prompts alone would still
let `/clear`, `/resume`, `/fork`, `/exit`, or a second `/compact` mutate, replace, or close the
parent session compaction captured. While the gate is held every submission is rejected and its text
retained; the gate is released exactly once, on the event loop, on every terminal path.

### `/context`: three states, one of them silence

`cmd_context.go` builds an immutable `ContextSnapshot` when the panel opens and renders it; the
panel shows that frozen snapshot until ESC. `BuildContextSnapshot` sums the session's
`model_response` records the same way `/status` does, and the interesting part is the cached-input
figure, which has **three** rendered states rather than two:

| Session records | Rendered token line |
|-----------------|---------------------|
| Every record reports a cached count | `Token usage: N input (C cached), N output (N total)` |
| Some record is marked partial, or reports no count | `Token usage: N input (at least C cached), …` plus `Cached-token usage is incomplete because some responses did not report it.` |
| No record reports a count | `Token usage: N input, N output (N total)` — unchanged, no cached clause |

The third row is the one to internalize. Rendering `0 cached` there would be inventing precision:
codemeld would be reporting a measurement no provider made. The rule is to keep unknown data
honest rather than fill it in, so the clause is simply absent — the same instinct as the
`Context window: unknown` fallback two lines below, which prints no percentage rather than a
plausible one.

The middle row exists because a mixed session would otherwise read as exact. A record contributes to
the lower bound in two ways: it carries `cached_input_tokens_partial` (its own turn had a round that
reported nothing), or it omits `cached_input_tokens` entirely while some other record reports one.
Either way the sum is real but incomplete, so it is labelled `at least`.

Keep this separate from the older `Token counts: incomplete (some turns did not report usage)`
notice. That one means a `usage_missing` anomaly on some turn and concerns the input/output totals;
it was not widened to cover cached tokens, and the two can appear independently.

### The permission prompt UI

The five options appear in a fixed order, with the first highlighted by default, and every option
label renders **bold** (a list style set on the prompt's list):

1. **allow this [o]nce** (default; creates no grant)
2. **[d]eny**
3. **allow for this [s]ession**
4. **allow in this [f]older permanently**
5. **allow [g]lobally permanently**

**Keyboard mnemonics.** Every rendered row carries a one-letter shortcut, shown in the label itself:
the bracketed letter is drawn in the shared teal accent, and the brackets are the cue that survives a
terminal that ignores the color. `promptMnemonics` (`prompt.go`) holds the mapping and
`promptRowLabel` decorates the row. The host-only "allow in this [p]roject" row has `p`; the other
five letters are `o`, `d`, `s`, `f`, and `g`.

Pressing the letter, in **either case**, acts immediately: no Enter afterwards, and the key is
consumed so it reaches no other handler. It is not a second decision path — the option list's input
capture moves the cursor to that row and calls the same `selectOption` closure a mouse click or
arrow-plus-Enter calls, so `s`/`f`/`g` on a direct command still open the scope sub-choice below, and
`f` still stores the ordinary folder grant (it is written to the local
`<project_root>/.codemeld/settings.local.yaml`, but that file's location is not what it authorizes). Because the lookup runs over the rows this prompt actually renders,
a letter for an option the prompt withholds is **inert**: `f` does nothing when the out-of-root rule
below hides the folder row, `g`/`f` do nothing on a host prompt, `p` does nothing on any non-host
prompt, and `s`/`f`/`g`/`p` do nothing on a fresh host confirmation.

The shortcuts belong to the **primary** approval screen only. The scope chooser, the Program-scope
confirmation, and the compound per-stage chooser keep mouse / arrow / Enter-only interaction (plus
ESC), so the letters do nothing once one of those overlays is up. And since the capture lives on the
prompt's own list, the letters are ordinary typed input whenever no prompt is open.

**What the screen shows.** A single-command shell prompt opens with `Command: ` and the exact
effective source text dispatch supplied — quotes and all, never rebuilt from the canonical matching
tokens — so the command being approved is the first line. A batched approval is the exception: one
choice authorizes several stages, so no single command may stand for them and it keeps its action
header over the full pipeline and every stage. Structured tools keep their action header, target,
and verbatim payload.

Below the divider, `renderPromptFacts` states only what the user needs to decide: the run folder,
the project root (marked when it differs), and the **durable** grants — where a folder grant is
written and which folders it then covers, and that a global grant is permanent and applies
anywhere. Allow-once and session get no fact line; neither outlives the session, and the session
grant is anchored to the run folder already shown.

`PromptUser` is called **off** the event loop (it's blocking a tool call). It queues the overlay onto
the screen, blocks on a `chan PromptDecision`, and the option callbacks send the decision back. For a
**direct-command** grant, a session/folder/global choice opens a scope sub-choice (Exact / one
**Prefix** row per visible token boundary / Program); choosing **Program** opens an inline confirm step (`showProgramConfirm`) — a small overlay
showing the breadth warning and a two-item `Confirm program-wide grant` / `Cancel` list, with the cursor
on confirm, so one Enter accepts the broad grant. Because that one Enter is the last gate, the confirm
also states the **effective grant** it would create (`programGrantEffect`): the canonical stored
subject, that it is a direct command, the lifetime or persistence of the option already picked on the
base prompt, and the path coverage that option really stores — the run folder and its descendants for
session and folder, all paths for global. It reads only already-resolved request values, so the copy
cannot claim a wider scope than the grant carries. **ESC dismisses
the prompt as a deny** (it must send *something*, since a tool call is blocked).

**Choosing the wildcard boundary (Prefix rows).** The middle of the direct-command ladder is not one
inferred rung. `buildScopeChooserRows` (`prompt_scope.go`) emits a **Prefix** row for every visible
canonical token boundary, ordered from the longest pinned prefix to the shortest — so
`prep-open-tasks.sh --only c175 --force` offers `… --only c175 --force :*`, `… --only c175 :*`, and
`… --only :*`. The zero-length prefix is deliberately absent: `<program> :*` *is* the Program row,
and it must stay behind the confirm. The row is called **Prefix**, not "subcommand", because codemeld
does not know an arbitrary program's flag arity and must not imply it does.

Every row's `Subject` comes from `PrefixSubject`, which serializes each pinned token verbatim and
appends only the `:*` wildcard token — so the invariant a reviewer should check any change against is
**every token shown before `:*` is stored as-is; only later tokens may vary** (`MatchesDirectSubject`,
Module 5, compares whole tokens, so a partial token never matches). The recommended default is
unchanged by the extra rows: it is the prefix `permissions.ClassifyDirectTokens` infers when one exists, else Exact —
never a broader row.

Simple-compound stages go through a different builder (`scopeOptionRows` via
`buildCompoundStageScopeOptions`) and keep the Exact / Subcommand / Program ladder, the narrowest
default, and the destructive-stage exact-only rule. Prefix rows are direct-command only; widening one
stage of a compound is the riskier choice, so the stage chooser does not offer a boundary picker.

**Broader-than-existing warning.** When the request's path scope is a *strict ancestor* of a folder
the user already approved for the **same subject**, `renderPromptFacts` prepends a warning line —
`⚠ Broader than a folder you already allowed: this asks for the PARENT of <narrower-scope>` — so
widening an earlier grant is visible before any option is chosen. The signal is computed display-only
by `FindScopeEscalation` (Module 5) and carried across the seam on `PromptRequest.ScopeEscalationNarrower`;
it changes no option, default, or grant — it is pure salience.

**Out-of-root folder-option carve-out.** Option 4 ("allow in this folder permanently") is
hidden whenever the resolved path scope falls **outside** the project root — `OmitFolderOption`
(`prompt_folder.go`) drops it and a one-line note explains why. Three kinds of prompt are exempt, and
`PromptRequest.folderGrantEligibleOutOfRoot` (`prompt.go`) is the single verdict all of them go
through:

- a structured `edit`/`create` whose resolved **real** target is out-of-root (`OutOfRootFileWrite`);
- an explicit out-of-project read-only navigation tool (`OutOfRootReadScope`);
- a **shell** request — a direct command or a literal command — whichever folder it runs in.

The shell case exists because the alternative was worse: hiding the folder option left an
out-of-project command offering "allow globally permanently" — a machine-wide grant — as its only
durable choice, so the prompt withheld the *narrower* grant while still offering the broader one.
The grant is still written to this project's local `<project_root>/.codemeld/settings.local.yaml`; only
its recorded `path_scope` points outside the root, and `renderPromptFacts` names both. Every **other** out-of-root prompt (a structured tool
with neither signal) still loses the folder option.

**The prompt you will never see.** Some requests are refused before the prompt exists. If the model
calls `edit`, `create`, `delete`, `mkdir`, or `move` on protected state — the shared
`.codemeld/settings.yaml`, the local `.codemeld/settings.local.yaml`, the global
`~/.codemeld/global/settings.yaml`, the project approval store `~/.codemeld/global/approved-projects.yaml`,
or any of their `.lock` sidecars — the protected-state policy refuses it inside `PrepareTool`, so nothing reaches the
prompt gate and no option — not "allow this once", not "allow globally permanently" — is offered.
There is no keystroke that approves it.

What you see instead is recovery, not a halt: the refusal is a `denied_by: "guard"` envelope, which
the turn loop treats like a mode denial, so the model gets another provider round and normally
answers by telling you to run `/settings` (the picker in this module) — which *is* allowed to
change those files, because it is a dedicated typed writer rather than a tool call. A user denial,
by contrast, ends the turn.

### Transcript scrollback and follow-mode

By default the transcript **follows** the newest output: `renderLocked` calls `ScrollToEnd` on every
append/delta/notice so the latest line stays visible. The mouse wheel (tview's `EnableMouse(true)` plus
a `SetMouseCapture` on the non-focusable transcript view) and the keyboard fallback — **PageUp/PageDown**,
and **Shift+↑/Shift+↓** where the terminal reports the modifier — scroll up to read earlier output. The
first upward scroll sets `transcript.following = false`, so `renderLocked` then re-pins the saved offset
(`SetText` rebuilds the wrap index, so the row is captured before it and restored with `ScrollTo`) and a
streamed delta no longer yanks the view down. Scrolling back to the last row flips `following` true again
and auto-follow resumes. Bare ↑/↓ stay with input history (`handleInputKey`); the transcript scroll keys
live in `handleGlobalKey` and no-op while an overlay owns the screen.

Mouse mode takes plain click-drag away from the terminal's native selection, so the **transcript owns
it**: a plain left-drag (no Shift) selects transcript text in-app and copies it on mouse-up. The
drag is driven from `handleAppMouse` — the app-level capture, not the transcript view's wheel capture,
because the app capture consumes the left-button events before the view sees them and is the only seam
that observes the `MouseMove` events a drag emits. The selection is tracked as byte offsets into the
*stripped* displayed text (`GetText(true)`): `wrapRows` re-derives the wrapped display rows from that
plain text (style tags are zero-width, so visible wrapping matches what the `TextView` draws) to map a
screen coordinate to a position, and `transcriptView.Draw` overlays the highlight with reverse video
*after* the text is drawn — never mutating the committed lines, so dynamic-color rendering is untouched
and the offsets re-project through the live scroll offset (the highlight tracks the text while you drag
across a scroll). On mouse-up the copy fires and `endSelect` then **zeroes the offsets**, so the
highlight clears on release instead of lingering (`renderLocked` already drops a stale selection on
any text change; the release path adds the missing reset). The copy reuses the
input area's OSC 52 path (`copyToClipboard`), so transcript and input copy share one clipboard
mechanism. A **plain drag in the input area** selects too: the app owns the plain input drag in
`handleAppMouse` just like the transcript. The app maps input screen
coordinates to byte offsets, drives `TextArea.Select` directly while dragging, copies through the same
OSC 52 path on release, and collapses the selection so that highlight clears. While the drag is held on
the top or bottom visible input row — on a repeating timer, so it keeps scrolling even with no further
mouse motion — the app advances the TextArea row offset (`scrollDrag`) so selection can continue past the
initially visible prompt text. The drag owns that offset for its duration: the before-draw realign
(`adjustRowOffset`, below) is skipped while an app-owned input drag is selecting, so it cannot snap the
viewport back to the caret each frame and fight the drag. The **conversation pane has the same
edge-hold auto-scroll** (`transcript.scrollDragScroll` driven by `App.updateTranscriptSelection` and the
twin timer): a plain drag held on the top or bottom visible row scrolls the transcript (`scrollBy`,
re-enabling follow at the last row) so the selection can reach conversation beyond the initial viewport.
Both timers **reschedule for the whole drag, not only on a tick that scrolled** — a real mouse held at an
edge jitters by a fraction of a cell, and a tick that lands one row inside the edge must not kill the
auto-scroll; the gen/selecting guard ends the chain on release. And on both panes, a drag held
**below the last visible row** (the pointer is past the content, over the rule/chrome beneath it) takes the
**whole bottom line** rather than stopping at the pointer's column — to keep only part of that line the
user drags back up onto it (`offsetAt` clamps to the row end there). **Shift+drag** stays on the native pass-through path for the
input, and remains the terminal's native select/copy escape hatch on the transcript where the terminal
still offers it.

The **open `/status` snapshot selects the same way**: a plain left-drag over the panel highlights the range
and copies it through the same OSC 52 path on release, no Shift needed. Its press is the one the modal's
background shield would otherwise swallow, so `handleAppMouse` starts the drag when the press lands
inside the panel's rectangle and keeps shielding everything outside it — focus never leaves `a.status`, so
ESC still dismisses the modal ahead of any in-flight stream. `statusView` mirrors `transcriptView`: it paints
the highlight over the cells the `TextView` already drew, so the frozen snapshot's escaped bracket data and
bold section titles are never re-rendered, and the offsets are into `GetText(true)` so the copy is exactly
the visible text rather than the markup behind it. The range lives outside the transcript's state, so a
streamed repaint under the drag cannot reset it; it is dropped on release, on dismissal, and whenever a new
snapshot opens.

The session id on that snapshot also carries a **`[click to copy]` control** immediately to its right, so the
id can be taken without dragging it out by hand. The label is plain ASCII and `tview.Escape`'d exactly like the
`[global]`/`[project]`/`[local]` layer labels, which name each settings file's kind rather than its
position — the panel has dynamic colors on, so an unescaped `[click to copy]` would
be parsed as a color tag and never drawn at all. The style around it splits the opposite way: the brand-teal
underline tag (`accentTealHex` plus `::u`, the hyperlink idiom that reads as clickable without explanation) is
written **raw** and closed with the absolute reset followed by an explicit `[::U]`, because an *escaped*
tag would draw literally and because the pinned tview version's reset restores colors and ordinary
attributes without clearing the underline flag. The label
names the action rather than the noun, so it still reads as a control on a terminal that drops the accent or
the underline — the rule that a cue may not rest on color alone. What it copies is the session id `App`
captured from the installed `StatusState` **when the overlay opened**, never text scraped back out of the panel.
It stays an inline suffix on the session line, not a line of its own.

Both this control and the transcript's code-block controls run on **one click-region mechanism**
(`clickRegion`/`clickRegions` in `app_selection.go`): a list of `{byte range, payload}` entries over a
view's *stripped* text, plus a press/release pair. `handleAppMouse` records at `MouseLeftDown` which
region the press resolved to (a press elsewhere, which takes no `beginSelect`, clears that candidate
too) and copies only when the release resolves to the **same** region — so a drag that starts on a
control and ends elsewhere stays an ordinary selection, and a selection that runs across a control
copies its visible text like any other. Positions are **byte ranges** rather than cell rectangles, so
a narrow terminal that wraps the line, or splits `[click to copy]` across two rows, leaves every part of it
clickable. Each view maps a coordinate through its own `offsetRowAt` (`statusView`'s and the
`transcript`'s), which also reports whether the column landed on the row's own drawn text — that is
what keeps the blank padding beside a control, and the empty pane below the conversation, from firing
it. The transcript's regions are rebuilt in `renderLocked`, at the same point it invalidates the drag
selection and for the same reason: `SetText` rebuilds the text, so byte offsets from the previous
render are stale, and a press in flight is dropped with them.

The copy goes out over the
same OSC 52 path as every other selection. A `/status` success leaves the overlay open and focused with the notice
`Session ID copied`; a code block's shows `Code block copied`. No record is appended and the frozen snapshot is untouched. OSC 52 reaches the local
clipboard **over SSH only when the client terminal and the SSH path both permit it** — codemeld emits the
sequence and cannot confirm delivery, so the drag-select alternative above remains the fallback where a
terminal refuses it.

> **Debugging this path?** A harness test can stay green while a real terminal fails (no event jitter; the
> test picks the coordinates), and this path once cost several rounds because the report said "input area"
> but the user was dragging the conversation pane. The process — confirm in a real terminal, and capture real
> events to find which pane owns the drag — is in `docs/tui-mouse-debugging.md`.

The **input area** additionally wires a real system
clipboard so tview's built-in keyboard copy works: `newInput` calls `TextArea.SetClipboard` with a
copy callback that emits the selection over **OSC 52** (`ESC ] 52 ; c ; <base64> BEL`, base64-encoded
so clipboard content can't inject control bytes; works over SSH, no new dependency) through an
injectable `osc52` sink (a TTY-gated `os.Stdout` writer in production, a fake in tests). **Ctrl-Q**
copies the current selection. The contract is intentionally asymmetric — OSC 52 read-back is
unreliable, so the in-app paste source is the **last copy** held in `lastCopied`, not the live system
clipboard. The app binds **Ctrl-V** to *image* paste from the OS clipboard
(`handleGlobalKey` → `handleClipboardImage`), which deliberately supersedes tview's old in-app
last-copy text paste on Ctrl-V; ordinary terminal text paste stays on **Ctrl-Shift-V** / right-click
(the terminal consumes it and the app receives it as a bracketed paste through `PasteHandler`).

A **bracketed paste** of `pasteCollapseLineThreshold` or more logical lines collapses to a one-line
`[Pasted N lines — paste again to expand]` placeholder in the visible buffer while the full text is
retained off-screen as a `pasteSegment` on `inputField`, so a long paste no longer scrolls the draft
off-screen (the input box sizes off the short placeholder); the trailing affordance hints that re-pasting
the same block expands it. `submitCurrent` submits `inputField.submitText()` — each tracked placeholder
still present in the buffer is substituted back to its full text — so the hook, history, and echo carry
the real content, not the placeholder. Editing or deleting a placeholder makes its segment fail to match
at expansion (dropping the hidden text rather than submitting it stale), a re-paste of the same block
expands its placeholder in place instead of adding a second one, and a whole-buffer `SetText` (history
recall, clear, accepted-submit) drops the segments. Shorter pastes insert inline as before, and because
the placeholder carries no `@` the paste still never opens the file-reference picker.

When a placeholder is expanded back to full text, the input box no longer caps at a fixed row count: it
grows toward the live terminal height (`App.inputTextRowCap` reserves `minTranscriptRows` plus the chrome
for the conversation above), and when the expanded text still overflows the box the viewport scrolls so
the caret's wrapped row — the tail of the paste — sits on the last visible row rather than the head
(`inputField.adjustRowOffset`).

### Async stream rendering

The `transcript` holds committed lines plus an in-progress streaming buffer; `finalize` commits it
through `renderMarkdown` (inline **bold**/*italic*/`code` become absolute tview tags, and block
elements — fenced code blocks, bold headings, `•`/`N.` lists, `│ `-prefixed blockquotes —
render structurally on top of that; literal text is escaped internally so model output can't inject a
style tag), `markInterrupted` does the same
and appends an escaped `[interrupted]` marker.

A **fenced code block** gets a stronger treatment than the rest, because it is the one thing on
screen the user is meant to *copy*: the base prompt tells the model to put commands, snippets, and
replacement text inside a fence and keep the explanation outside it, and the renderer then draws
each of that block's lines with `codeBlockTag` — a foreground **and** a background
(`codeBlockText`/`codeBlockFill` in `colors.go`), so the block reads as a filled rectangle with a
visible edge against the prose above and below it. Inline `` `code` `` spans are deliberately *not*
changed: they keep the foreground-only `codeColor`, so a one-word span never looks like a copyable
block. Three details make the boundary hold. Every block line closes back to `defaultTag`, so the
fill stops at the block instead of running into the next paragraph. A block whose body is blank
throughout — an empty block, whose whole body is one empty line — renders each line as a single
space (`codeBlockBlankLine`), because a zero-width styled run paints no cell and the block would
otherwise be invisible; a blank line inside a block that *has* content is left empty instead, so
copied text keeps the snippet's own blank lines rather than gaining a stray space. And the body is
read from the raw source segments and escaped, never re-parsed, so
`[red]`, `**`, and backticks inside a block display literally and the text a terminal selection
copies is exactly what the model wrote — the boundary is drawn with color, not with border glyphs
that would end up in the user's clipboard.

Each closed fenced block also carries its own **`[click to copy]` control** on the line directly *below* it —
below, not above, because a block taller than the pane has already scrolled its top out of view and a
streaming reply auto-follows the bottom, so the end of the block is what is actually on screen. It is drawn
teal and underlined, and indented **two columns past the block's own container prefix** so it reads as the
block's caption rather than a new top-level paragraph. That offset is measured from `curPrefix()`, never from
a fixed screen column: the prefix widens with nesting (`"│ "` per blockquote, `"  "` per *nested* list), so the
absolute column differs per container by design. It is deliberately not aligned to the block's first line
either — a fence inside a list item shares its opening row with the `"• "`/`"10. "` marker, which is written
straight to the buffer and never enters the prefix, so aligning to it would push the control right of most of
the block it labels and would move with the marker's width.
Clicking it copies that block's body through the same OSC 52 path as any selection. What it copies is
the **source** body the model wrote, carried out of `renderMarkdown` alongside the rendered text, not
the display cells — byte for byte, including the newline that sits before the closing fence, which
the drawn lines drop because it has no cell of its own. `renderMarkdown` returns one `codeControl`
per block: the line of its own rendered text the control was written to, plus that source body. The
transcript keeps each committed block's controls beside it and `renderLocked` shifts those lines by
the blocks joined above them, so a region is built from what the renderer emitted rather than from a
text match. That is the point: once tags are stripped, a model-written line reading `[click to copy]` — in a
fenced body or in prose — is indistinguishable from a generated one, and scanning for it would let
model content add or cancel controls. A fence that never closed gets nothing: an interrupted reply
still parses as a fenced block, but the snippet is truncated. Indented (4-space) blocks and inline
spans get no control either. The control is the same escaped ASCII literal — and the same teal underline —
as `/status`'s, and it activates the same way, through the shared click-region mechanism described with
`/status` below. Both locators suffix-match the *stripped* line against that one shared constant, so the style
tags are invisible to them and the indent is only a prefix; what they do require is that the control stays the
end of the line it owns.

A sealed reply carries a second control of its own, **`[Copy response]`**, on the line below the
whole response. It is the same escaped teal-underlined literal riding the same click-region
mechanism as `[click to copy]`, and the two differ only in label and in scope: a block control
copies one closed fenced body, the response control copies that one assistant reply.
`appendResponseControl` is reachable only from the three paths that *seal* a reply — `finalize`,
`markInterrupted`, and `/resume` replay through `replaySessionBlocks` — because a live reply is
still growing and arming a control over it would expose a payload the next delta rewrites. All
three call it only when the reply text is non-whitespace, so a blank reply, and an assistant record
that carried nothing but tool calls, never get a response control. A non-blank reply usually gets
one, but not always: see the code-only case below. An interrupted reply can get one too: it is
sealed, and whatever text it managed to produce before the cut is copyable.

The one exception is a reply that is nothing but a single fenced code block. When the reply's only
control is that block's `[click to copy]`, and the block's body with its final newline dropped is
exactly the text the response control would copy, `appendResponseControl` leaves `[Copy response]`
off and the block control stays as the only one — two controls that copy the same text would just
be clutter. Any prose around the block, a second block, or a list or blockquote prefix makes the two
copies differ, so the reply keeps both. So do an empty block and a block whose last body line is
blank, and so does a reply whose single fence never closed, since that block has no control of its
own. Because the check lives inside `appendResponseControl`, `finalize`, `markInterrupted`, and
`/resume` replay all follow it the same way.

What it copies is neither the source nor the drawn cells but the **display projection**
`renderMarkdown` builds alongside the rendered text — the visible text with the style tags, the
internal escaping, and the generated control lines left out. So a response copy keeps the prose as
displayed and each code block's body, and omits what was never displayed (the fence delimiters and
their language tags) along with the chrome the renderer itself wrote: the per-block
`[click to copy]` lines, the response control, and the `[interrupted]` marker — which
`markInterrupted` appends to the rendered string *after* `renderMarkdown` has already returned the
projection. The projection is assembled as the renderer writes rather than recovered from the
finished string, for the same reason the block controls are: once tags are stripped, a line the
model wrote reading `[click to copy]` is indistinguishable from a generated one, and stripping by
text match would delete the model's own words.

Clicking either control goes out over the same OSC 52 path, and `copyControlPayload` reports the
outcome as a notice — `Response copied`, or `Code block copied` for a block. A failure it can
actually see while emitting becomes `Could not copy: <error>` in the chat. That is the whole of the
promise: the terminal never acknowledges an OSC 52 write, so a terminal that quietly refuses the
update cannot be detected and is never reported.

The live streaming buffer is not held plain until finalize. `renderStreamMarkdown` splits the
still-growing buffer at the last hard block boundary — a blank line *outside* an open fence, or a
closing fence: everything before it is complete and goes through `renderMarkdown`, so a finished code
block shows its boundary while the reply is still arriving, and the trailing in-progress block is
appended escaped. A closing fence counts on its own because CommonMark ends the block there, so a
block becomes copyable the moment it closes rather than waiting for the next blank-line delta. That
split is why a half-open ` ```go ` fence stays raw instead of flashing as a styled block and then
reflowing. The one scanner behind both that split and the "did this fence close?" question tracks
fences through their **container**, so a fence written inside a blockquote or a list item is seen
opening and closing: a close has to sit at the blockquote depth its opener did, which keeps a
` ``` ` written *inside* a quoted block's body from ending it. The
same four surfaces — live streaming, `finalize`, `markInterrupted`, and `/resume` replay via
`replaySessionBlocks` — all reach `renderMarkdown`, so the block looks identical in every one.
The provider sink calls
`App.AppendStreamDelta`/`FinalizeStream`/`MarkStreamInterrupted` **off the loop**. While the loop runs,
`AppendStreamDelta` uses `QueueUpdate` to append to the live buffer without a draw, then arms one
50 ms timer if none is pending. That timer re-enters through `QueueUpdateDraw`, renders the complete
buffer once, and does not re-arm until another delta arrives. Finalize, interruption, rollback, reset,
notice changes, and tool or patch boundaries invalidate the pending timer before their synchronous
render. Before `Run`, delta updates render directly so tests need no clock wait. Shutdown is an
exit-only boundary: `Stop` rejects new render work and stops tview immediately; callbacks that run
later drop, and process exit cleans up any callback that was already waiting for the loop. Because one
runtime goroutine feeds deltas synchronously, they stay in arrival order.

**Tool activity** is the other thing in the pane, and it has two producers that must agree. Just
before a tool-call round is dispatched, the turn formats each assembled call into one line and hands
the round to `AppendToolActivity`, which commits it as a single escaped block. The lines are
display-only — they are never recorded and never sent back to the model. The two web research tools
name what they are researching (`WebSearch <query>`, `WebFetch <url>`, each bounded to 120 runes), so
a long research turn reads as work in progress instead of a column of repeated `web_search`.

`ask_user` is left out of that formatting too (`nonEditCalls`), because the form commits its own
compact record and a line for it would say the same thing twice; only this display path filters it,
while scheduling and persistence still see the whole round.

Edit calls are the exception: they get no line before dispatch. An edit that is denied, malformed, or
fails to write would leave an `Edit <path>` line claiming a change that never happened, so the turn
sends the edit's unified patch to `AppendEditPatch` **after** the file was written and the round's
tool results were assembled, in assembled call order. A patch in the pane therefore always means a
successful edit — nothing is shown for one that was refused or failed. The block renders through
`renderPatchBody`, the same renderer the edit approval prompt uses, so removed lines are red, added
lines green, headers and context neutral, and every line's own text escaped. Like activity lines the
patch is display-only: it rides `ToolResult.DisplayPatch`, which is never persisted and never sent
back to the model, and it is not rebuilt on `/resume`. Only the interactive surface implements the
sink, so a headless run leaves the callback unset and prints no patch.

On `/resume` those lines have to be rebuilt, because the assistant records that carried the calls
have no visible text and are otherwise skipped. `replaySessionBlocks` reads each assistant record's
persisted `tool_calls` entries, keeps only the two web tools, and appends their lines as one block in
that record's own position — after its text, before later records. Nothing new is written to the
session for this: the query and URL already live in the persisted call arguments, and the *results*
of those calls are never read. Replay is therefore a web-only subset of what the live pane showed —
a mixed round's `Read`, `Grep`, or `Run:` lines do not come back, and neither do tool-result
bodies — so a resumed transcript can show less activity than the live turn did, never more. An
entry whose wrapper or function name cannot be decoded is skipped; a readable web name with
unusable arguments falls back to the bare tool name, so a legacy record degrades instead of failing
the replay. Activity is not a reply, so a tool-call-only turn still gets no completion footer, and
the blocks count against `maxReplayBlocks` like any other.

The label logic itself lives in **`internal/toolactivity`**, a stdlib-only leaf package both sides
import. It cannot live in `internal/turn`: `internal/turn` already reaches `internal/tui` (through
`internal/model/persist.go` and `internal/sessionfailures/failures.go`), so `internal/tui` importing
`internal/turn` is a compile-time cycle. One `Format(name, arguments)` for both callers is what keeps
a resumed line byte-identical to the live one — the alternative, a copy of the switch in each
package, drifts the first time a label changes.

`RunBackgroundAfterDraw` is the same discipline packaged for a *command* that must do slow work.
Give it a `work` and a `complete`: it paints once through `streamUpdate`, runs `work` on a fresh
goroutine, then marshals `complete` back onto the loop. The paint-first step is what keeps a
progress line or spinner visible instead of appearing only after the work finishes, and the
marshalled `complete` is why only that callback may touch terminal session state. `/compact` is the
production user — provider call and child preparation in `work`, activation and gate release in
`complete`. Before `Run`, the not-running branch just calls `complete(work())` inline, so the same
wiring is exercised synchronously in tests.

A provider that stops sending uses the same surface. When a stream goes quiet the turn calls
`SetProviderIdle(name, idle)`, which swaps the generic `Working…` for `Waiting for <provider>…`
and re-bases the elapsed clock on the *idle* duration, so the number counts silence rather than
turn length. That callback fires once per round, so the line ages through redraws of the stored
idle start, not through repeated calls. Past `indicatorLongWaitThreshold` (90 seconds) the copy
grows a hint: `Waiting for <provider>… still no response — press ESC to cancel`, alongside the
same elapsed idle time.

The hint is **advisory, and only copy**. Crossing 90 seconds cancels nothing, retries nothing, and
tears nothing down — the request stays in flight and stays cancellable, and ESC is still the only
thing that stops it. The reset works the same way in reverse: the first chunk to arrive fires
`OnProviderStreamActivity`, wired to `ResumeRetry`, which clears the idle state so the line falls
back to `Working…`; a later quiet stretch starts counting from its own duration rather than
resurrecting the old hint. Retry keeps priority over both, so a backoff in progress shows
`Reconnecting…` even while idle state is stored underneath it.

Auto-retry uses the same queued surface. `ShowRetryBackoff` changes the in-flight indicator to
`Reconnecting… (attempt N of M)` during backoff; `ResumeRetry` returns it to `Working…` before the
retry is issued. A partial stream drop calls `RollbackPartial`, which clears only the unsealed live
buffer so regenerated text starts cleanly. A successful retry calls `CommitRetryRecovered`, appending
a dim but text-visible `· recovered after N retry/retries` breadcrumb after the final answer; an
exhausted retry renders the normal provider failure line with a `failed after N attempts:` prefix.

## Watch for (Go idioms)

- **Capability interfaces, nil = inert.** Heavy dependencies are injected as small interfaces
  (`StreamCanceller`, `ExitController`, `StatusState`); a nil handle is a deliberate no-op, keeping
  `internal/tui` free of import cycles.
- **The `running atomic.Bool` seam.** The *same* method (`streamUpdate`) is safe before and during the
  loop — direct mutation before `Run` (the queue isn't drained yet), queued mutation during.
- **Thread-safety via the queue, not locks.** UI state is mutated only on the loop goroutine; the one
  explicit lock guards the swappable active store.
- **Generation-token invalidation** stops a stale CTRL-C-hint timer from wiping a freshly re-armed hint.

## Quiz

Closed-book: [`quizzes/module-10.md`](quizzes/module-10.md). Grade against
[`quizzes/module-10-key.md`](quizzes/module-10-key.md).

## Hands-on (open-book)

**A. Predict, then verify.** Does pressing ESC clear your typed input? Predict, then read `HandleEsc`
(`key_esc.go`) with `overlays()` (`overlays.go`) beside it and confirm the ESC priority order (dismiss
the first open overlay in the roster → stop stream → clear a non-empty buffer → no-op). An open
overlay beats stopping the stream: it is the modal the user is looking at, and it blocks the very turn
ESC would otherwise cancel. Find the two entries that are not ordinary — the one that disarms the next
ESC, and the one with no dismissal at all — and say what would break if either were treated like the
rest. Why does the clear sit *below* stream-stop and overlay-dismissal?

**B. Predict, then verify.** How is `/foo` distinguished from a prompt, and what about a lone `/`?
Predict, then confirm against `ParseSlashInput` and `TestParseSlashInput` (`slashparse_test.go`).

**C. Locate the option order.** Find `promptOptionsInOrder` (`prompt.go`) and the test that pins the
order and default (`TestPromptOptions_FixedOrderAndDefaultHighlight`). Record it in
[`progress.md`](progress.md).

## Done when

- You can sketch the three panes and explain where a typed line goes.
- You can recite the permission-prompt option order and explain the scope sub-choice.
- You can name the tool calls that never reach the prompt at all, and say how the turn continues
  after one is refused.
- You can name the four options with a letter mnemonic and say where those letters stop working.
- You can explain why off-loop UI updates go through `QueueUpdateDraw`.
- You can explain how retry backoff, partial rollback, recovery breadcrumb, and exhausted failure text
  move through the TUI surface.
- You can say what the indicator does after 90 seconds of provider silence, what clears it, and why
  it never cancels or retries the request itself.
- You can explain where a resumed session's web research lines come from, and why the label logic
  lives in its own package rather than in `internal/turn`.
- You can list the `ask_user` form's controls and its two per-question answer modes, say where a
  custom answer is recorded, distinguish both from the form-level `Ask clarification` path and say
  what the model is expected to do after one, and explain why ESC closes the form without cancelling
  the turn waiting on it.
- You can say what the shared `context` section is for, how it is bounded, and what an answered,
  clarified, or dismissed form leaves in the transcript — live and after `/resume`.
- You can name `/context`'s three cached-usage states and explain why the unreported one prints no
  cached figure instead of `0 cached`.
