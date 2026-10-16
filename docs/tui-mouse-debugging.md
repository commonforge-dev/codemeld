# Debugging TUI mouse / drag / selection bugs

Process notes for the `internal/tui` mouse path (selection, drag, auto-scroll), written after a
"drag doesn't auto-scroll" report that cost about five prior attempts plus several more before it was
fixed, almost entirely because the test harness gave false confidence and the report named the wrong
pane. Read this before investigating a similar report.

## A green SimulationScreen test does NOT prove a terminal-interaction fix works

The `internal/tui` tests drive the real tview event loop, the before-draw hook, and even a real
`time.AfterFunc` timer (see `layoutHarness` in `launch_layout_test.go`). They are still **necessary but
not sufficient** for mouse, drag, focus, and terminal-routing behavior, because they miss several bug
classes structurally:

1. **No sub-cell jitter.** Injected `tcell.EventMouse`s are pixel-perfect. A real mouse held at an edge
   jitters by a fraction of a cell, repeatedly crossing cell boundaries. A hold-at-edge auto-scroll timer
   that only reschedules on a tick that *actually scrolled* passes every harness test yet **dies on the
   first jitter** in a real terminal. Fix pattern: reschedule the timer for the whole drag (guarded by a
   generation/selecting token that ends it on release), and scroll only when the held position is on an
   edge — a momentary off-edge tick must not kill the chain.
2. **You pick the coordinates.** The test author chooses where the drag presses, so the harness can never
   reveal that the user was dragging over a *different primitive* than assumed.
3. **No real terminal focus/blur.** A SimulationScreen test can force stale focus and prove the app
   re-focuses the right primitive, but it cannot prove the emulator/window manager sends focus-gained
   events after the user switches away and returns. For that path, tcell must have focus reporting enabled
   (`Screen.EnableFocus()`), and the app must observe `*tcell.EventFocus` at the screen boundary before
   tview's event loop drops it. Fix pattern: handle focus-gained in the screen decorator/wrapper, marshal
   back onto the tview loop with `QueueUpdateDraw`, and re-focus only the active modal/page that owns
   keyboard input. Also add a global-key fallback for the next key while that modal is open: some
   terminal/window-manager combinations still do not deliver a usable focus-gained event, but the first
   post-return arrow/Enter/Escape can repair stale focus before routing that same key. Do not try to repair
   this with prompt-local key handling; prompt code never sees the terminal refocus event or the first key
   when focus is stuck on the wrong primitive.

So: **confirm any drag/scroll/focus fix in a real terminal, not just `mise run test`.**

## Find which pane the drag is actually on — capture real events

The biggest time-sink in that case: the report said "input area," so work focused on the **input box**, but the
user was drag-selecting the **conversation/transcript pane** above it. They are separate code paths
(`inputField` selection vs `transcript` selection in `transcript_selection.go`), and the conversation pane
simply had no drag auto-scroll. No amount of reasoning from the wording found this; one real capture did.

When a mouse bug will not reproduce in the harness, capture what the real terminal delivers. The logging
is **already built in** and gated by an env var (`internal/tui/mousedebug.go`) — run codemeld with:

```
CODEMELD_MOUSE_DEBUG=/tmp/cm-mouse.log codemeld
```

reproduce the gesture once, and read the file. It is off and zero-cost when the var is unset (also listed
in `docs/environment-variables.md` and the `/help` panel). It logs:

- In `(*App).handleAppMouse` (the app-level mouse capture in `internal/tui/app_selection.go`), **every** action: the
  `tview.MouseAction` (`0`=Move `1`=LeftDown `2`=LeftUp `3`=LeftClick `13`=WheelUp), `event.Position()`,
  `event.Buttons()`, the `inputSelecting` / `transcript.isSelecting()` states, and the input/transcript
  rects.
- In `scrollDrag` / `scrollDragScroll`, the scroll decision: `y`, inner `iy`/`ih`, `bottom`, current offset
  → next offset, `maxOffset`, and whether it scrolled.
- In the drag-scroll timer ticks, each fire (generation, selecting state, held `y`).

Reading the capture: **compare the press coordinates to each pane's rect.** In that report the press was at
`y=21` while `inputRect=(0,35,...)` — 14 rows above the input box, i.e. in the transcript. That one line
ended the investigation. Also watch for the *absence* of `Move` (action `0`) events between LeftDown and
LeftUp: that would mean the terminal is not delivering drag-motion events at all (a different problem —
mouse-mode enablement — not auto-scroll).

## Real-terminal smoke check for a mouse-driven overlay

Run this before calling a mouse-driven overlay done — a modal form, a picker, a popup menu, anything
that takes clicks on top of the normal layout. The worked example throughout is the `ask_user`
question form (`internal/tui/question_prompt.go`), but the gesture classes are the reusable part;
substitute your overlay's instances for the ones in parentheses.

### What a green suite still cannot establish

On top of the three structural gaps above (jitter, chosen coordinates, no real focus/blur), a passing
`internal/tui` run says nothing about these gesture classes:

- **Appearance.** The SimulationScreen records cells, not what a person sees on their theme. Both
  defects the question form's real-terminal sessions found were of this kind and the suite was green
  on both: a `›` label that inherited tview's yellow and was unreadable on a light background, and a
  chosen row that read as unchosen because an ambiguous-width `●` sat beside a full-width
  reverse-video cursor bar. Ambiguous-width and full-width glyphs, contrast, and the interaction of a
  cursor bar with a nearby mark are all in this class.
- **Event delivery.** Whether the emulator sends wheel events, drag-motion between LeftDown and
  LeftUp, focus-gained after a window switch, or bracketed paste **at all**. The harness injects them
  unconditionally, so it proves routing, never arrival.
- **Which primitive is under the pointer.** The harness author picks the coordinates; a real pointer
  lands where the layout actually put the row, one cell off, or on the frame around it.
- **Layout at the real minimum.** The harness picks its own screen size, so a control that the
  supported minimum size clips or pushes off-screen still passes.

### Driving the check

```
mise run build
CODEMELD_MOUSE_DEBUG=/tmp/cm-overlay.log ./codemeld
```

Reach the overlay the way a user does — from a live turn, through its production entrypoint (for the
question form, a turn that actually calls `ask_user`), not through a test hook. Then run the gesture
list twice: once at a normal window size, once at 20x24, the smallest supported layout.
Judge each gesture by eye against what the overlay is meant to do; the suite's opinion is not
evidence here.

### The gesture list

- **Plain click on an actionable row** (click an option row).
- **Rapid repeated clicks** (click a second row twice in quick succession — the second click must not
  undo the first).
- **Click on a continuation line of a wrapped row** (click the second rendered line of an option long
  enough to wrap).
- **State round-trip across a view change** (step away from a multi-select with `Next ›` and back with
  `‹ Prev`, then click a checked option to turn it off).
- **Wheel over the content and over the surrounding frame** (wheel an over-tall question down and back
  up, with the pointer over the question and again over the stage around it).
- **Boundary controls at both ends** (`‹ Prev` on the first question, `Next ›` on the last).
- **A drag already in progress when the overlay mounts** (start a drag in the input area, and again in
  the transcript, while a turn is about to mount the form). A full-window overlay covers the panes this
  gesture needs, so it may be unstartable by hand — see *Recording the result*.
- **Focus loss and return, then paste** (open a custom-answer field, switch to another window and
  back, then paste).
- **Dismissal** (click `Cancel`).

### When a gesture misbehaves

Read the capture with the questions from the section above: where were the press coordinates relative
to each pane's rect, and did the event class arrive at all. A gesture that produces no log line for
its own action is an arrival problem (mouse mode, focus reporting, bracketed paste), not a routing
one, and the fix is at the screen boundary rather than in the overlay.

Fix it in the primitive the capture implicates, confirm the same gesture in the same terminal, and
then add the part of it the SimulationScreen can hold — a click map, a scroll offset, a focus target,
a drawn style. Say in that test which half of the failure the harness structurally cannot see, so a
later reader does not mistake it for full coverage.

### Recording the result

Record in the task file, under **Notes**: the terminal emulator and version, both window sizes, and
one line per gesture per size. `not run` and `unclear` are not outcomes — a gesture that will not
reproduce closes with a `CODEMELD_MOUSE_DEBUG` capture that states what the terminal actually
delivered.

There is one honest third outcome: **unstartable**, where the overlay's own layout removes the
surface the gesture needs — a full-window modal covers the input and transcript, so a drag that must
already be in progress when it mounts cannot be begun by hand. That is a layout constraint, not
evidence the path works. Record it as unstartable with the reason, and leave the simulation test as
the only cover that path has.

## The shape of the current fix (so you do not re-derive it)

Both panes share an edge-hold drag auto-scroll, kept deliberately parallel:

- Input box: `inputField.scrollDrag` driven by `App.updateInputSelection` + `inputDragScrollTick`. The
  before-draw realign (`inputField.adjustRowOffset`) is **skipped while a drag is selecting** — it
  otherwise snaps the viewport to the caret every frame and fights the drag (the original bug here).
- Conversation pane: `transcript.scrollDragScroll` (delegates the offset move + follow flag to `scrollBy`)
  driven by `App.updateTranscriptSelection` + `transcriptDragScrollTick`.
- Both timers reschedule for the whole drag (jitter-proof, above).
- Both `offsetAt` mappers clamp the column to the row end when the pointer is held **below the last
  visible row** (`y > iy+ih-1`): dragging past the bottom rule means "take the whole line"; to keep only
  part of the bottom line the user drags back up onto it.

The behavior (not the debugging process) is also described in the human onboarding curriculum at
`contributing/learning/module-10-tui.md`.
