# Quiz — Module 5: Permissions

_Last updated: 2026-10-05_

Closed-book. Write your answers before opening `module-05-key.md`. The goal is to find your
gaps, not to score — anything you can't answer from memory is what to re-read.

---

**1. Path scope.** A grant is approved with scope `/home/me/foo`. For each request path, does the
grant apply? Then state the rule in one sentence.
- (a) `/home/me/foo/sub`
- (b) `/home/me/bar`
- (c) `/home/me`
- (d) `/home/me/foobar`

**2. Lifetimes.** Name the three grant lifetimes and where each is stored (give the file path, or
say "not stored").

**3. Path canonicalization.** Which function makes `/usr/bin/git log` and `git log` match the same
grant? Name the one condition under which it will **not** reduce the path to the bare name.

**4. Environment assignments.** `GIT_PAGER=cat git log` is checked against an existing grant for
`git log`. What happens to `GIT_PAGER=cat` (a) for matching, and (b) for execution?

**5. Pipelines.** True or false: a pipeline `a | b` is authorized as a single unit. Justify in one
sentence.

**6. Wrappers.** Why does `sh -c 'git log'` **not** reuse a `direct` grant for `git log`? What kind
of matching does it route to instead?

**7. Cross-field rule.** For a `global` grant, what must `path_scope` be? State the rule linking
`path_scope` and `grant_kind`.

**8. Turn cache.** In one or two sentences: what does the turn-scoped cache do, when is it consulted
relative to real grants, and when is it cleared?

**9. No "approve everything".** Why does codemeld deliberately ship no YOLO / approve-all mode?

**10. Deny.** When a request is denied, what exactly does the agent receive back (be specific about
the form, not just "an error")?

**11. Multiple choice.** A grant's dedup identity (`DedupKey`) is which 4-tuple, and why is the
field you left out excluded?
- (a) Kind, Subject, PathScope, GrantKind
- (b) Subject, PathScope, GrantKind, ArgumentHash
- (c) Kind, Subject, ArgumentHash, PathScope

**12. Compounds.** A bare `git add . && go build` reaches dispatch. (a) Which route does it take —
stage-by-stage like a pipeline, or one literal/compound subject, and what does that mean for a
direct grant you already approved for `go build`? (b) `a > b && c` and `a || b` reach dispatch with
that same grant in place. Which route do *they* take, and can either borrow the grant? (c) Under
what condition can a *generalized* compound grant authorize a command on the literal route with
widened leaf arguments, and what does that grant pin? (d) Why does a stage whose program is
destructive **not** get the generalized treatment — name the principle. (e) What happens to
`echo $(whoami)` before any prompt?

**13. The no-exec shell exception.** `bash` and `sh` are wrapper programs, yet a few of their
invocations auto-allow as read-only in Build, Auto edits, **and** Plan. Sort these into auto-allow vs
mutating, then state in one sentence the rule that decides an unlisted option, and the rule that
decides which route the exception is allowed on.
- (a) `bash -n deploy.sh`
- (b) `bash --noexec deploy.sh`
- (c) `bash -O extglob -n deploy.sh`
- (d) `bash -O extglob deploy.sh`
- (e) `sh -n -c 'rm -rf x'`
- (f) `sh -c "bash -n deploy.sh"`
- (g) `FOO=bar bash -n deploy.sh`
- (h) `bash -n deploy.sh > /dev/null`

**14. The builtin lookup.** `command` is a wrapper program too, yet `command -v magick` auto-allows
as read-only in every mode. Sort these into auto-allow vs prompt, then answer: (i) what does dispatch
actually run for an auto-allowed one, and what does the agent get back? (ii) `cd` is a real shell
builtin, so why does `command -v cd` land where it does? (iii) why is `command -V magick` treated
differently from `command -v magick`?
- (a) `command -v magick`
- (b) `command -v magick && ls`
- (c) `command -v nosuchprog`
- (d) `command -V magick`
- (e) `command ls -la`
- (f) `PATH=/opt/bin command -v magick`
- (g) `sh -c "command -v magick"`
- (h) `command -v /usr/bin/magick`

**15. The refusal before the check.** The model calls `move` with source `.codemeld` and destination
`stash`. Neither endpoint *is* a settings file. (a) Is the call authorized, denied at the prompt, or
refused earlier — and by what? (b) Name the routes in this module that the refusal takes precedence
over. (c) The user then approves nothing and grants nothing; can any grant, mode, or approval make
this call succeed? (d) Does the turn end?

**16. Reading the three `denied_by` values.** For each of `user`, `mode`, and `guard`: who refused,
and does the turn halt or continue? What happens to a `denied_by` value the loop does not recognize,
and why is that the right default?

**17. Why `awk` is not name-only.** `cat`, `grep`, and `nl` are trusted by program name alone, yet
`awk` is not, even though most requests only print a range or a column. Sort these into
auto-allow vs prompt, then answer: (1) name three things an AWK program can do that rule out
trusting `awk` by its executable name alone; (2) two of the accepted forms differ only in whitespace — why does that not matter?
(3) one accepted form has its bounds backwards — why is it still read-only? (4) (i) and (l) both
contain `>` — why does only one prompt? (5) (n) is a valid AWK program in most implementations —
why does it still prompt, and which listed form is the admitted way to match a literal `/`? (6) (h) names no input
file — why is that allowed?
- (a) `awk 'NR>=55 && NR<=70 {print NR ":" $0}' docs/session-format.md`
- (b) `awk 'NR >= 55 && NR <= 70 { print NR ":" $0 }' docs/session-format.md`
- (c) `awk 'FNR>=1 && FNR<=10 {print $0}' a b`
- (d) `awk 'NR>=70 && NR<=55 {print $0}' f`
- (e) `awk 'NR>=1 && NR<=10 {print $1}' f`
- (f) `awk 'NR>=1 && NR<=10 {print}' f g=1`
- (g) `awk -v n=10 'NR>=1 && NR<=10 {print}' f`
- (h) `awk 'NR>=1 && NR<=10 {print NR ":" $0}'`
- (i) `awk '$3 > 100 { print }' f`
- (j) `awk '{ s += $2 } END { print s/NR }' f`
- (k) `awk '{ print > f }' f`
- (l) `awk '{ print (a > b) }' f`
- (m) `awk 'BEGIN { system("id") }' f`
- (n) `awk '/[/]/ { print }' f`
- (o) `awk -v n=10 '{ print }' f`
- (p) `awk '/\// { print }' f`
