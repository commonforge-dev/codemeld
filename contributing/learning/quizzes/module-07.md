# Quiz — Module 7: Sessions & events

_Last updated: 2026-10-04_

Closed-book. Write your answers before opening `module-07-key.md`.

---

**1.** What are the two session write paths, and how is each made crash-safe?

**2.** Where do session files live, and how is the per-folder directory name formed?

**3.** Does `EnsureSession` write the file to disk? If not, who performs the first durable write?

**4.** Which sessions take an ownership lock, what exactly is locked, and with what timeout?

**5.** What prevents two processes from entering the same session at once?

**6.** What happens to a session on a write failure mid-turn?

**7.** How does a write failure on *clean shutdown* differ from a mid-turn one?

**8.** What does a fork copy, and what does it drop?

**9.** How does the reader handle a session whose `schema_version` is newer than it supports?

**10.** When does the pruner delete a session, and can it ever delete one another process is using?

**11.** The `codemeld sessions doctor` / `show` diagnostics are described as **read-only**. What does that mean they never do, and does `doctor` exit non-zero just because it found errors in the session?

**12.** `doctor` reports a severity per finding even though no severity is stored in the session. Which events map to **error**, which to **warning**, and which to **info** — and name something that is *not* a finding?

**13.** How do `doctor` and `show` accept their target (id, path, or both), and from which directories does each target form work? Which loader do they use so that a too-new `schema_version` or a missing file surfaces as a typed error, and how does their handling of a bare id differ from `codemeld --resume <id>` — and why?

**14.** The timing events `turn_latency` and `provider_round_trip`, plus `turn_terminal`, were added without bumping `schema_version`. Why is adding an event kind safe without a bump, how are provider-round records correlated, and how does `doctor` treat these events?

**15.** You need the current list of event kinds and the fields of a given payload. Which source file is authoritative, and how would you confirm it against a real session file — without relying on a copied-out schema list?

**16.** You run `sessions show` and `sessions doctor` on a valid **compacted child** session. What does `show` render for the compaction record and the session header — and which of those fields is the *source link* versus mere *generation metadata*? How does `doctor` treat the compaction, what happens on a malformed one (e.g. a `parent_id` that doesn't match the fork origin), and what would an **older reader** do with such a file?

**17.** `CreateChild`'s write-failure callback receives a file **path** — but only for one of the two flushes a child creation performs. Which failure reports the path, why is the path needed exactly there, and why does the other failure not use the path-aware callback? Does `ForkSession`'s callback also carry the path?

**18.** During a live child switch the process briefly holds **two** session locks. Which two, in what order are they acquired and released, and why is the alternative — releasing the source first — rejected? What does the shared bootstrap lifecycle do if acquiring or initializing the target fails? Which two registered commands drive this lifecycle in production today?

**19.** Child creation fails inside the shared lifecycle — once on the initial child write, once on the parent marker. In both cases, what happens to the active store, the parent's ownership, and the transcript? How does the initial-write failure surface (does it go through the retained-store `session_write_failed` protocol?), and what does the lifecycle do about the complete child file a parent-marker failure can leave behind?

**20.** The shipped phase-2 `/fork` command is a full-continuation live child switch wired through `StartTUI`. Trace one successful `/fork`: what does the parent's durable record stream end with (and in what order), what provenance does the child file carry, which records does the child copy versus drop, and what does the running app point at afterward? Why does `StartTUI` bind the fork's parent flush to the store's own `Store.Flush` rather than the handled `newCommandFlush`? How does this direct `/fork` differ from the legacy `ForkSession`?

**21.** `/compact` is also a live child switch, but asynchronous. Which goroutine does each stage run on (admission, provider call plus child preparation, activation)? How many times is the active model selection read, and what does that one read fix? What happens to a prompt or a `/clear` typed while compaction is in flight, and why does gating only the plain-prompt entrypoint not work?

**22.** `/compact` deliberately does **not** record its `slash_command` success when the command is accepted. Where does that success record actually land, what is it committed together with, and what does a durable success therefore imply? What does the parent look like after a failed compaction, and what can be left on disk?

**23.** Compare the two children on disk. Which records does a `/compact` child carry versus a `/fork` child, what title does each get, and why is a `/compact` child's `forked_from.record_id` **not** the compact success record while a `/fork` child's `forked_from.record_id` **is** the fork success record?

**24.** `sessions permissions` is an audit report, not just a list of prompts. For a **granted** row,
how does it tell "the user approved this one call" from "a grant was stored", and what does it name
in each case — including a grant stored against all paths and one stored for a host? When does it
flag a prompt as a **scope escalation**, which grant does it name when several qualify, and how does
it decide that an earlier stored subject covers this request without re-implementing the matcher?
Which two recorded values, when absent, leave a row deliberately unflagged — and why is guessing
worse than saying nothing? Does the marker change what is allowed?

**24a.** A grant is gone from a settings file. Which single event tells you a human revoked it
deliberately, and what stops any other actor from writing that same event? Which identity does the
event carry — the grant's or the request's — and why must that value never be hashed or shortened?
Then name the three things the record deliberately does **not** prove: what a *persisted* revocation
actually claims given when the settings file is inspected, why a successful revoke can end up with
no event at all (and which failure that ordering is chosen to avoid), and what state the record is
in after a flush failure the session-write protocol handles. Finally: what does `sessions permissions`
print for a session that recorded none, and what must it never do with a grant that is simply absent
from YAML?

**25.** `sessions research` reports a web-research funnel. Which records does it read, and how does
it accept its target? Name the closed set of labels an address can carry and the persisted evidence
behind each — in particular, what exactly has to be true for `selected` and for `cited`, and which
three pieces of text are deliberately *not* citation evidence. What does an address with no `cited`
label mean, and what does it **not** mean? How are the two search result shapes told apart and why
is the older one not converted? Which permission records count toward the host-prompt totals? And
what happens to a tool result that is stored but unreadable, versus a record that is invalid?

**26.** A structured file tool is refused before it is ever authorized. Which event kind records
that, why was no new kind minted for it, and which fields does the append-time validator pin closed?
Who writes the record — and why is that component, rather than the code that produced the refusal,
the right writer? If the append fails, what happens to the turn and to the tool? Finally: a test
asserts the refusal is recorded by reading the in-memory store. Why is that not sufficient evidence?

**27.** `model_response` gained a `cached_input_tokens` field after sessions had already been written
without it. Two decisions in its declaration are load-bearing rather than stylistic: name both, and
say precisely what breaks if each is dropped. Which value distinguishes "the provider reported
nothing" from "the provider reported zero", and how does each appear on the wire? What does the
companion `cached_input_tokens_partial` claim, when is it allowed to be written, and what does its
absence mean? Finally: does a missing cached count contribute an anomaly token, and why is that the
right answer?

**28.** A colleague reports that a run "seems to have died half way through" and hands you a session
id. Which five targeted `codemeld sessions` diagnostics (the ones that inspect a single session)
would you reach for, in what order, and what does each one answer? What target does each accept,
and from where can you run it? Two properties of these commands decide how you can use them and
what you may do with the output — name both.

**29.** `doctor` reports a finding and you want the context around it with `sessions show`. Which
finding shapes hand you a `turn_id` you can pass to `show --turn <turn-id>`, and which one identifies
a failed **tool** but no turn at all? For that second shape, what does the finding actually name, and
which `show` options would you narrow with instead?

**30.** You want to inspect a recent run but do not know its session id. Which `codemeld sessions`
subcommand do you run, which sessions does it list by default, and what does each row show? What do
`--all` and `--json` change, and what does `--all` do when one session id turns up in more than one
folder? One session file in the folder has a corrupt first line: what happens to it, where is that
reported, and does it break a script parsing the `--json` output? When does the command fail
outright instead?
