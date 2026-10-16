# Quiz — Module 15: OpenAI ChatGPT authentication

_Last updated: 2026-09-23_

Closed-book. Write your answers before opening `module-15-key.md`. The goal is to find your
gaps, not to score — anything you can't answer from memory is what to re-read.

---

**1. Separate provider, not a second credential.** ChatGPT subscription access ships as its own
provider id rather than a second credential on `openai`. What are the two provider ids, and what is
the design payoff of modelling the subscription as a separate provider (what reasoning does it
remove)? What happens if a user puts a `provider.openai-chatgpt` entry in their config?

**2. The command surface.** Name the four `auth` commands (including the `--json` variant) and one
line on what each touches. Why are `auth login openai` and `auth logout openai` **rejected**?

**3. Login ordering.** In `runAuthLogin` → `runChatGPTLogin` (`internal/cli/auth.go`), name the
conditions that exit non-zero **before** any storage write, and state the invariant about when the
session is persisted relative to the upstream login succeeding.

**4. Storage.** Where exactly does the ChatGPT session live (settings key + file path + the helper
that resolves it), at what file mode, and through what locking? Is it encrypted?

**5. Status is offline.** What does `authstatus.Collect` read, what does it deliberately **not** do,
and how does it classify the two providers with respect to each other?

**6. Pinned egress.** Name the two outbound origins ChatGPT credentials may reach and which traffic
goes to each. Where is each origin pinned in code, and can a setting, environment variable, or custom
provider redirect it? What is `http://localhost:1455` and why is it **not** outbound egress?

**7. Redaction.** List the credential-shaped values that must never be printed or logged on any path.
Name the test that proves redaction across layers and the three surfaces it checks.

**8. The package-local seams.** `auth.go` swaps several functions for fakes in tests so the command
runs without a TTY, real network, or a real settings write. Name three of them and say what the
production default is.

**9. Typed errors stay credential-free.** How does `loginErrorMessage` produce an actionable message
without risking a secret leak in the detail string? What does it match on?

**10. The unresolved permission risk.** codemeld does not claim official OpenAI approval for this
flow. State the risk in one sentence and the explicit policy for what happens if upstream later
disallows the flow. Why does this matter when you touch this area?

**11. Refreshing ChatGPT models from the picker.** What makes the model picker fetch a fresh
ChatGPT model list, and what never does? Before discovery, what happens to the stored session, and
which origins can the refresh reach? What does the picker show when no usable session exists, and
does it ever start a login? On success and on failure, what happens to the cached list, the picker
rows, and the selected model? Which local reads stay offline throughout?
