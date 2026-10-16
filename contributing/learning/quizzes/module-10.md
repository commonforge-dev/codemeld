# Quiz — Module 10: TUI

Closed-book. Write your answers before opening `module-10-key.md`.

---

**1.** How is a slash command distinguished from an ordinary prompt? What about a lone `/`?

**2.** Where does a bare (non-slash) prompt go, and what controls whether the input field clears?

**3.** When a user types an alias like `/new`, what command name is recorded in the session event?

**4.** What happens on an unknown command or wrong argument count?

**5.** What is the permission-prompt option order, and which option is the default?

**6.** How does a permission decision get back to the code that requested it?

**7.** For a direct-command grant, what extra choice is shown, and how is the most dangerous scope
guarded? What is the middle of that ladder called, how many rows does it have, which one is
recommended, what exactly does a chosen row pin — and why does a simple-compound stage not get the
same rows?

**8.** How do streamed model deltas reach the screen safely while the event loop is running, and why
are repeated deltas coalesced into one render?

**9.** How is a cancelled stream rendered differently from a completed one?

**9a.** What makes a fenced code block look different from the assistant's ordinary prose, and how
does that differ from an inline `` `code` `` span? Why does an *empty* fenced block still show
something, why doesn't the block's styling bleed into the paragraph after it, and what stops
bracket- or asterisk-heavy content inside a block from being interpreted as styling? Which display
paths get this treatment — and does any of it change what the user's mouse selection copies?

**9b.** Every closed fenced block gets a `[click to copy]` control. Why is it placed *below* the block
rather than above it, and how far in from the block's container prefix — measured against what, and
why not against the block's own first line? Which two style cues does it carry, and why does the
label name the action instead of the noun? Clicking it copies the block body — where does that text
come from, and how exactly does it end? What stops a model that writes a line reading
`[click to copy]`, inside a fenced block or in the
prose around it, from adding a control or taking one away? Name three code forms that get no control
at all, and say what a reply interrupted mid-fence exposes — including one written inside a
blockquote or a list item. Finally: a streamed delta arrives between your press on a control and
your release — what is copied, and which single line of code decides that?

**10.** What is the ESC priority order, and where is the list of overlays it walks written down? Does
ESC ever clear typed input? Which overlay is not dismissed by that walk, and why?

**11.** A plain (no-Shift) left-drag over the transcript selects and copies text in-app. Where is the
drag handled, how is the highlight drawn without corrupting the committed lines, how is the copy
performed, and how do wheel scrolling and the terminal's native Shift+drag stay out of its way?

**12.** During provider auto-retry, what TUI state changes happen for backoff, partial rollback,
successful recovery, and exhausted failure?

**13.** The model picker's filter uses what kind of matching, and how does `Ctrl-R` differ from
lowercase `r` while the picker is open?

**14.** How does the model picker's Favorites section identify a favorite, what does `Ctrl-F` do, and
what does the picker do on a failed toggle?

**15.** In the file-reference picker (`@`): what is on screen before you type, when does a search
actually start, what exactly does the 50 limit, in what order do rows and the search's outcome reach
the screen, and how are results from a query you already replaced kept off the list?

**15a.** A resumed session shows `WebSearch <query>` and `WebFetch <url>` lines from a research turn
that ran before the restart. Where does that text come from, given that the assistant records
carrying those calls have no visible text? What is kept and what is left out, what happens to a
record whose tool-call entry cannot be decoded, and does any of it change the completion footer, the
replay bound, or what the model is sent? Why does the label formatter live in its own package
instead of in `internal/turn` next to the live caller?

**15b.** The agent needs a decision from you and opens the `ask_user` question form. How do you move
around it and choose with a keyboard and with a mouse — name every stop on the focus ring — and what
is different about a single-select question and a multi-select one? What does `Type your own answer`
do, which answers does the text you type change, and why is that per-question mode not the same thing
as the form-level `Ask clarification` action beside Submit? What does a question you never touched come back as? Suppose the request uses the
advertised maximum — 5 questions of 8 options with 200-character labels — on a 24-row terminal: how
do you reach the last question, how do you read an option label far longer than one screen row, and
what property does the form actually guarantee about that text, given that no layout could show all
of it at once? If you scroll a long question with the wheel and then move focus away and back, what
happens to where you had scrolled to, and why is that the deliberate choice? What if instead you
widen the terminal until the whole question fits and then narrow it again — what has to be stored for
that to work, and what would a plain scroll-offset number come back as? Finally: you press ESC, or pick Cancel, while the
form is up — what happens to the form, to your typed draft, and to the agent turn that is waiting on
it, and why is that ordering deliberate?

**15c.** Every id, prompt and option label has to be text a terminal can show, and the rule is
enforced twice — once as the advertised JSON Schema `pattern`, once in the decoder. Why does
`unicode.IsPrint` not settle it on its own: which characters pass it and still draw nothing, and what
would a request whose two options are `U+2800` and `U+3164` put on screen? Name the three things the
`pattern` cannot say that the decoder still refuses, and say which direction the two layers are
allowed to disagree in. Separately: you have a custom-answer field open, the terminal loses and
regains focus without the app hearing about it, and you paste. Where does the text go, and why does
the first-key focus repair not cover this case?

**15d.** You press `r` on a grant in the `/settings` overlay and confirm. A revoke touches two
files that cannot be committed together — the settings file and the session — so what order does the
seam use, and which of the two possible bad outcomes is that order chosen to accept? What is
different about a session (memory-only) grant, and what has to be true before it records anything at
all? Now the recording fails: why can the notice never say the revoke failed, when does the picker
show a *second* notice and when exactly one, and what happens to the record that was already
appended?

**15e.** A call arrives carrying a `context` string as well as its questions. Where is that text
drawn, what is it for, and when is the model expected to send one at all? How is it rendered, how do
you scroll it, and what keeps a long paragraph from pushing the question and its options off a 24-row
terminal? What does a call that sends no context mount?

**15f.** You do not understand what you are being asked, so you use `Ask clarification` rather than
answering. What does that control open and how do you submit it? What exactly does the model get
back, and what is missing from it? What is the model then expected to do — and why does its
explanation have to arrive that way instead of as ordinary prose? What happens if you open the entry,
type nothing and Submit; if you close the entry again; if you cancel while it is open? Which parts of
this differ from `Type your own answer`?

**15g.** What does a delivered `ask_user` form leave in the conversation pane — for an answered form,
for a clarification, and for one you dismissed — and what of the tool call is deliberately not in it?
Why is the assistant's in-progress text finalized before that record is appended, and why does that
happen even for a dismissal? After `/resume` the record is on screen again: where does it come from,
what has to be true of the saved call and its result before it is rebuilt, and name the cases that
rebuild nothing at all.

**16.** Which permission-prompt options have a keyboard mnemonic and how is it displayed? Name the
letters for the folder row and for the host-only project row, and say which prompts offer each. Does
case matter, is an Enter needed after the letter, and what happens to a letter whose option this
particular prompt does not offer? Do the same letters work on the scope chooser or the
Program-scope confirmation?

**17.** `/status` shows the session id with a `[click to copy]` control beside it. Why is that literal
escaped before it reaches the panel while the style tag around it is written raw, and what would a test
that asserted only on `RenderStatus`'s returned
string fail to notice? Where does the id that gets copied come from, and at what moment is it read?
Say exactly which mouse sequence activates the control and which two nearby sequences must not — one
that starts on it, one that ends on it. The control's position is stored as a byte range rather than
a cell rectangle: what does a 20-column terminal do that makes the difference, and what stops the
empty cells at the end of the row above the control from triggering it? The transcript's code-block
controls answer all of that identically — which type do the two share, and what does each view still
have to supply itself? Finally, what does the user
see after a successful copy, what is deliberately *not* written, and what can codemeld honestly
promise about that clipboard over SSH?

**18.** The agent asks to `edit` your project's `.codemeld/settings.yaml`. Which prompt options do
you get, and which keystroke approves it? What do you actually see happen in the transcript, does
the turn end, what is the supported route for changing that file, and what does the guard still
leave uncovered?

**19.** `/context` reports how much cached prompt input the session's providers said they served.
Name the **three** states its token line can be in and the exact shape each renders. Two different
record conditions produce the middle state — name both. For the state where nothing was reported,
say what `/context` prints and why printing `0 cached` instead would be the wrong call, naming the
rule it would violate and one other line in the same panel that follows it. Finally: the panel
already has a `Token counts: incomplete` notice — does it cover cached tokens too?
