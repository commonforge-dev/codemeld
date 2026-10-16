// First-run generation and atomic write of ~/.codemeld/global/settings.yaml.
package bootstrap

import (
	"fmt"
	"io"
	"path/filepath"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/fsutil"
)

// canonicalProviderBlock is the verbatim provider: block. The whole block is
// commented out so that uncommenting it (deleting the leading "# " from each
// line) yields valid YAML — leaving an uncommented "provider: {}" key here would
// be a footgun, since a key cannot carry both an inline empty map and block
// children. The bytes must round-trip byte-for-byte with the canonical literal.
const canonicalProviderBlock = `# Add a provider entry to enable codemeld: uncomment the provider: block
# below (delete the leading "# " on each line) and paste your API key.
# Examples for the providers codemeld ships adapters for at launch:
#
# provider:
#   openai:
#     base_url: https://api.openai.com/v1
#     api_key: ""                          # paste your key here
#     # run /connect openai to validate the key and refresh the selectable model
#     # list into codemeld's own store; no models list is needed here.
#
#   openrouter:
#     base_url: https://openrouter.ai/api/v1
#     api_key: ""                          # paste your key here
#     # run /connect openrouter to validate the key and refresh the selectable
#     # model list into codemeld's own store; no models list is needed here.
#
#   venice:
#     base_url: https://api.venice.ai/api/v1
#     api_key: ""                          # paste your key here
#     # run /connect venice to validate the key and refresh the selectable model
#     # list into codemeld's own store; no models list is needed here.
`

// canonicalOpenAIAuthBlock explains the two independent OpenAI providers and how
// each is paid for and authenticated, plus the
// plaintext-credential warning for this file. It is comment-only
// sits just above the provider block, and deliberately ships no
// auth.openai-chatgpt example so users never paste a token-shaped value here.
const canonicalOpenAIAuthBlock = `# OpenAI sign-in: codemeld ships two separate OpenAI providers. Pick the one that
# matches how you pay for access; neither overrides the other.
#
#   openai-chatgpt (OpenAI ChatGPT subscription): built in, so it needs no entry
#     below and no API key. From an interactive shell, sign in with
#       codemeld auth login openai-chatgpt
#     This uses your own ChatGPT subscription where OpenAI's entitlement and
#     access policy allow it. codemeld is an independent client and is not
#     endorsed by or affiliated with OpenAI.
#
#   openai (OpenAI Platform API key): pay-as-you-go usage billing. Uncomment the
#     provider.openai example below and paste a Platform API key. CI, servers, and
#     other non-interactive setups should use this provider, not ChatGPT login.
#
# Security: this file (~/.codemeld/global/settings.yaml) may hold plaintext
# provider API keys and ChatGPT session tokens. It is readable by your local user
# account. Do not check it into a project, paste it into a bug report, or sync it
# to untrusted locations.
`

const canonicalWebResearchBlock = `# Web research (search and direct fetch) is ON by default. Nothing in this file
# authorizes a host or starts a request on its own.
#
# It adds outbound network egress: search requests go to Exa (mcp.exa.ai) and
# fetches go to the source hosts you follow. Nothing is contacted until it is
# approved by you per request in the permission prompt.
#
# The prompt offers allow once, this session, or this project; the grants you
# choose to keep are recorded under permissions: above.
#
# Direct fetch and search both work with no Exa key.
# web_research.api_key is optional - supply your own Exa key to run search
# against your own Exa account.
#
# On an install that must never make these requests, uncomment the block below:
# that switch is the only way to turn web research off.
#
# web_research:
#   enabled: false
#   api_key: ""            # optional; your own Exa key, for your own Exa quota
#   max_results: 6         # search candidates requested (5-25)
#   timeout_seconds: 20    # per search or fetch request, in seconds (1-120)
`

// canonicalModelBlock is the verbatim model: block. The leading comment block
// above model: {} is part of the canonical bytes.
const canonicalModelBlock = `# model.last_used is managed automatically by codemeld.
# It records the most recent model and effort you picked in any project,
# and is used as the default for folders you have not yet used with codemeld.
# Manual edits to this key will be overwritten the next time you pick a model.
model: {}
`

const generatedSettingsHead = `# codemeld: default global settings.
#
# This file is generated on first run at ~/.codemeld/global/settings.yaml.
# Every documented key with a hard-coded default is materialized below so you
# can see and edit it; keys you omit fall back to the same default at load
# time. Per-project overrides live in .codemeld/settings.yaml inside a
# project; see ` + "`discovery.boundary`" + ` below for how they are located.

discovery:
  # boundary mode: how codemeld locates per-project settings files.
  #   launch-dir-only - only the current directory's .codemeld/settings.yaml
  #                     is consulted (in addition to this global file).
  #   project-root    - walk upward and stop at the innermost ancestor
  #                     containing a .codemeld/settings.yaml file.
  boundary: launch-dir-only

vcs:
  # tie-breaker order when a folder contains markers for more than one VCS.
  # Reorder this list to prefer one when both are present (e.g. [hg, git, jj]
  # to prefer Mercurial). It does not force a VCS that is not detected; for
  # that, set 'preferred' below.
  priority: [git, hg, jj]
  # preferred (optional): a VCS template name used unconditionally, bypassing
  # detection. Allowed values are any built-in name (git, hg, jj) or a
  # user-defined template name under ~/.codemeld/global/vcs/ or
  # <project_root>/.codemeld/vcs/. Empty string means auto-detect (default).
  preferred: ""

sessions:
  # number of days session JSON files in ~/.codemeld/sessions/ are kept before
  # automatic pruning. Set higher to retain longer.
  retention_days: 30
  # per-stream cap (in bytes) on each tool invocation's stdout and stderr in
  # the session record stream and when fed back to the model. Applies to each
  # stream independently. Default is 64 KiB; minimum is 256 bytes.
  max_tool_output_bytes: 65536

agent_instructions:
  # instruction files (AGENTS.md and any configured additions) larger than
  # this many bytes are skipped at load time. Default is 64 KiB.
  max_file_bytes: 65536

agent:
  # maximum number of independent agent work units codemeld may run in
  # parallel within a single assistant turn. Use 1 to force fully sequential
  # execution.
  max_concurrency: 3

# permission grants persisted by the permission prompt (folder-scoped and
# global-scoped). The TUI appends entries here when you choose
# "allow in this folder permanently" or "allow globally permanently".
permissions: []

`

const generatedSettingsTail = canonicalWebResearchBlock + `
` + canonicalOpenAIAuthBlock + `
` + canonicalProviderBlock + `
` + canonicalModelBlock

// SettingsPath returns the absolute path to the generated global settings file.
func SettingsPath(home string) string {
	return filepath.Join(home, ".codemeld", "global", "settings.yaml")
}

// GeneratedSettingsBytes returns the canonical first-run settings.yaml bytes.
func GeneratedSettingsBytes() []byte {
	return []byte(generatedSettingsHead + renderBlockedPathsBlock() + "\n" + generatedSettingsTail)
}

// WriteFirstRunSettings atomically writes settings.yaml at mode 0600 so the
// plaintext API key is not group/world-readable. The parent
// directories must already exist. On failure it returns the failing step and
// error category.
func WriteFirstRunSettings(home string) (path string, step fsutil.AtomicWriteStep, cat fserrors.Category, err error) {
	path = SettingsPath(home)
	step, cat, err = fsutil.WriteAtomic(path, GeneratedSettingsBytes(), 0o600)
	return path, step, cat, err
}

// RunWriteSettings writes settings.yaml, then on success prints the first-run
// message and the settings-to-review section. On failure it prints the OP_FAIL
// stderr line with operation "write-settings" and returns exit code 1.
func RunWriteSettings(home string, stdout, stderr io.Writer) int {
	path, _, cat, err := WriteFirstRunSettings(home)
	if err != nil {
		fmt.Fprintln(stderr, fserrors.FormatOpFail("write-settings", path, cat))
		return 1
	}
	PrintFirstRunMessage(stdout, path)
	PrintSettingsToReview(stdout)
	return 0
}
