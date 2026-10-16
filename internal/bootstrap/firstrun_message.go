// First-run stdout messages: the created-settings message and the settings-to-review section.
package bootstrap

import (
	"fmt"
	"io"
)

// PrintFirstRunMessage emits the created-settings stdout message directing
// ChatGPT subscribers to `codemeld auth login openai-chatgpt` and Platform users
// to configure an OpenAI Platform API key (supersedes
// the single-line "configure a provider and API key" wording).
// The exact wording is pinned by a snapshot test; do not edit without updating
// the snapshots.
func PrintFirstRunMessage(w io.Writer, settingsPath string) {
	fmt.Fprintf(w, "codemeld: created default settings at %s\n", settingsPath)
	fmt.Fprintln(w, "codemeld works once an OpenAI provider is set up. The two OpenAI providers are billed differently:")
	fmt.Fprintln(w, "  - OpenAI ChatGPT subscription: run `codemeld auth login openai-chatgpt` to sign in - no API key required.")
	fmt.Fprintf(w, "  - OpenAI Platform (pay-as-you-go API key): edit %s and configure an OpenAI Platform API key under `provider:` (see the comments there).\n", settingsPath)
	fmt.Fprintf(w, "To use a different provider, configure it under `provider:` in %s, then re-run codemeld.\n", settingsPath)
}

// PrintSettingsToReview emits the "settings to review" section. The wording may
// evolve; only the set of listed keys is pinned.
func PrintSettingsToReview(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "settings to review (defaults are sensible for most users; raise these if you")
	fmt.Fprintln(w, "hit a limit, or change them when the default does not match your workflow):")
	fmt.Fprintln(w, "  - discovery.boundary       - how per-project settings files are located")
	fmt.Fprintln(w, "                                (default 'launch-dir-only', i.e. no upward walk).")
	fmt.Fprintln(w, "  - vcs.priority             - tie-breaker order when more than one VCS is")
	fmt.Fprintln(w, "                                detected; reorder to prefer one (e.g. [hg, git, jj]).")
	fmt.Fprintln(w, "  - sessions.retention_days  - days session JSON files are kept before pruning.")
	fmt.Fprintln(w, "  - sessions.max_tool_output_bytes")
	fmt.Fprintln(w, "                              - per-stream cap on tool stdout/stderr.")
	fmt.Fprintln(w, "  - agent_instructions.max_file_bytes")
	fmt.Fprintln(w, "                              - upper bound on AGENTS.md / instruction file size.")
	fmt.Fprintln(w, "  - agent.max_concurrency    - max independent agent work units per assistant turn.")
	fmt.Fprintln(w, "  - blocked_paths            - files and folders the agent can never read or change;")
	fmt.Fprintln(w, "                                recommended entries are already added.")
	fmt.Fprintln(w, "  - model.active             - written automatically by the in-TUI model picker;")
	fmt.Fprintln(w, "                                blocks the first turn until you select a model.")
}
