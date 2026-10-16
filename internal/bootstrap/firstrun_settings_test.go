// Snapshot tests for the first-run settings.yaml content, write semantics, and stdout message.
package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/securitystate"
	"github.com/goccy/go-yaml"
)

// expectedProviderBlock pins the provider block's literal bytes; review
// before changing.
const expectedProviderBlock = `# Add a provider entry to enable codemeld: uncomment the provider: block
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

// expectedOpenAIAuthBlock pins the OpenAI auth-guidance comment block.
// Review wording changes intentionally.
const expectedOpenAIAuthBlock = `# OpenAI sign-in: codemeld ships two separate OpenAI providers. Pick the one that
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

const expectedWebResearchBlock = `# Web research (search and direct fetch) is ON by default. Nothing in this file
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

// expectedModelBlock pins the model block's literal bytes exactly as written.
const expectedModelBlock = `# model.last_used is managed automatically by codemeld.
# It records the most recent model and effort you picked in any project,
# and is used as the default for folders you have not yet used with codemeld.
# Manual edits to this key will be overwritten the next time you pick a model.
model: {}
`

// expectedFirstRunMessage pins the first-run stdout wording.
// The `<path>` token is replaced by the test with the actual settings path.
const expectedFirstRunMessage = "codemeld: created default settings at <path>\n" +
	"codemeld works once an OpenAI provider is set up. The two OpenAI providers are billed differently:\n" +
	"  - OpenAI ChatGPT subscription: run `codemeld auth login openai-chatgpt` to sign in - no API key required.\n" +
	"  - OpenAI Platform (pay-as-you-go API key): edit <path> and configure an OpenAI Platform API key under `provider:` (see the comments there).\n" +
	"To use a different provider, configure it under `provider:` in <path>, then re-run codemeld.\n"

// expectedGeneratedSettings is an independent byte-for-byte snapshot of the
// full settings.yaml content produced by GeneratedSettingsBytes().
const expectedGeneratedSettings = `# codemeld: default global settings.
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

# blocked_paths: the agent's tools and read-only commands can never read or
# change these paths. codemeld wrote these recommended entries once, on first
# start, and never adds more. They are not a complete list of your secrets.
# Remove an entry to let the agent use it, or add your own absolute or ~/ paths.
blocked_paths:
  # Keys and passwords
  - "~/.ssh"
  - "~/.gnupg"
  - "~/.password-store"
  - "~/.local/share/keyrings"
  - "~/.local/share/kwalletd"
  - "~/Library/Keychains"
  # Cloud and cluster logins
  - "~/.aws"
  - "~/.azure"
  - "~/.config/gcloud"
  - "~/AppData/Roaming/gcloud"
  - "~/.kube"
  - "~/.docker/config.json"
  # Infrastructure tokens
  - "~/.terraform.d/credentials.tfrc.json"
  - "~/AppData/Roaming/terraform.d/credentials.tfrc.json"
  - "~/.vault-token"
  # Version-control config and tokens
  - "~/.hgrc"
  - "~/.config/hg/hgrc"
  - "~/Mercurial.ini"
  - "~/.gitconfig"
  - "~/.config/git/config"
  - "~/.git-credentials"
  - "~/.config/git/credentials"
  - "~/.config/gh"
  - "~/AppData/Roaming/GitHub CLI"
  - "~/.netrc"
  - "~/_netrc"
  # Package tokens
  - "~/.npmrc"
  - "~/.pypirc"
  - "~/.config/pip/pip.conf"
  - "~/.pip/pip.conf"
  - "~/Library/Application Support/pip/pip.conf"
  - "~/AppData/Roaming/pip/pip.ini"
  - "~/.cargo/credentials.toml"
  - "~/.cargo/credentials"
  - "~/.gem/credentials"
  - "~/.local/share/gem/credentials"
  # Java build settings
  - "~/.m2/settings.xml"
  - "~/.m2/settings-security.xml"
  - "~/.gradle/gradle.properties"
  # Other AI coding tools' logins
  - "~/.claude/.credentials.json"
  - "~/.codex/auth.json"
  - "~/.local/share/opencode/auth.json"
  # Shell history
  - "~/.bash_history"
  - "~/.zsh_history"
  - "~/.local/share/fish/fish_history"
  - "~/.sh_history"
  - "~/.history"
  # Browser profiles
  - "~/.mozilla/firefox"
  - "~/.config/mozilla/firefox"
  - "~/.config/google-chrome"
  - "~/.config/chromium"
  - "~/snap/firefox/common/.mozilla/firefox"
  - "~/snap/chromium/common/chromium"
  - "~/.var/app/org.mozilla.firefox/.mozilla/firefox"
  - "~/.var/app/com.google.Chrome/config/google-chrome"
  - "~/.var/app/org.chromium.Chromium/config/chromium"
  - "~/Library/Application Support/Firefox/Profiles"
  - "~/Library/Application Support/Google/Chrome"
  - "~/Library/Application Support/Chromium"
  - "~/AppData/Roaming/Mozilla/Firefox/Profiles"
  - "~/AppData/Local/Google/Chrome/User Data"
  - "~/AppData/Local/Chromium/User Data"

` + expectedWebResearchBlock + `
` + expectedOpenAIAuthBlock + `
` + expectedProviderBlock + `
` + expectedModelBlock

func TestProviderBlock_MatchesReq135Literal(t *testing.T) {
	if canonicalProviderBlock != expectedProviderBlock {
		t.Fatalf("canonicalProviderBlock drifted from PRD req 135 literal\n--- got ---\n%s\n--- want ---\n%s",
			canonicalProviderBlock, expectedProviderBlock)
	}
}

func TestModelBlock_MatchesReq515Literal(t *testing.T) {
	if canonicalModelBlock != expectedModelBlock {
		t.Fatalf("canonicalModelBlock drifted from PRD req 515 literal\n--- got ---\n%s\n--- want ---\n%s",
			canonicalModelBlock, expectedModelBlock)
	}
}

func TestOpenAIAuthBlock_MatchesCanonical(t *testing.T) {
	if canonicalOpenAIAuthBlock != expectedOpenAIAuthBlock {
		t.Fatalf("canonicalOpenAIAuthBlock drifted from the expected literal\n--- got ---\n%s\n--- want ---\n%s",
			canonicalOpenAIAuthBlock, expectedOpenAIAuthBlock)
	}
}

// TestGeneratedSettings_OpenAIAuthGuidance asserts the generated settings carry
// the first-run guidance: ChatGPT login command, Platform API-key path
// the non-interactive recommendation, the no-affiliation phrasing, and the
// plaintext-credential warning naming the global settings file. It also confirms
// no auth.openai-chatgpt token-shaped example is shipped.
func TestGeneratedSettings_OpenAIAuthGuidance(t *testing.T) {
	got := string(GeneratedSettingsBytes())
	for _, want := range []string{
		"codemeld auth login openai-chatgpt",              // ChatGPT subscribers
		"no API key",                                      // ChatGPT needs no key
		"OpenAI Platform API key",                         // Platform billing path
		"non-interactive setups should use this provider", // CI/servers use Platform
		"endorsed by or affiliated with OpenAI",           // no official-approval claim
		"~/.codemeld/global/settings.yaml",                // warning names the file
		"plaintext",                                       // plaintext credential warning
		"paste it into a bug report",                      // leakage warning
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated settings missing PRD-02 auth guidance text %q", want)
		}
	}
	// req: do not ship a sample auth.openai-chatgpt token block (leakage risk).
	if strings.Contains(got, "auth:") || strings.Contains(got, "auth.openai-chatgpt:") {
		t.Errorf("generated settings must not embed an auth/auth.openai-chatgpt block")
	}
}

// TestFirstRunMessage_DirectsBothOpenAIProviders confirms the stdout message
// points ChatGPT users at the login command and Platform users at API-key config
// and no longer claims an API key is mandatory.
func TestFirstRunMessage_DirectsBothOpenAIProviders(t *testing.T) {
	var b bytes.Buffer
	PrintFirstRunMessage(&b, "/home/u/.codemeld/global/settings.yaml")
	got := b.String()
	for _, want := range []string{
		"codemeld auth login openai-chatgpt",
		"no API key required",
		"OpenAI Platform API key",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("first-run message missing %q\n--- got ---\n%s", want, got)
		}
	}
	if strings.Contains(got, "cannot perform work until a provider and API key are configured") {
		t.Errorf("first-run message still carries the superseded PRD-01 req-45 wording")
	}
}

// TestProviderBlock_UncommentsToValidProviderConfig models the user action the
// change exists to make safe: starting at the "# provider:" line
// uncomment the example block (strip the leading "# " from each line), paste an
// api_key, and confirm the result parses as valid YAML and loads as a provider
// config. The old "provider: {}" form would have produced invalid YAML here.
func TestProviderBlock_UncommentsToValidProviderConfig(t *testing.T) {
	var b strings.Builder
	started := false
	for _, ln := range strings.Split(canonicalProviderBlock, "\n") {
		if !started {
			if strings.HasPrefix(ln, "# provider:") {
				started = true
			} else {
				continue
			}
		}
		switch {
		case ln == "#": // blank comment separator -> blank line
		case strings.HasPrefix(ln, "# "):
			b.WriteString(strings.TrimPrefix(ln, "# "))
		default:
			b.WriteString(ln)
		}
		b.WriteByte('\n')
	}
	uncommented := strings.ReplaceAll(b.String(), `api_key: ""`, `api_key: "sk-test"`)

	if err := config.Validate([]byte(uncommented), "settings.yaml"); err != nil {
		t.Fatalf("uncommented provider block fails settings schema validation: %v\n%s", err, uncommented)
	}

	var composed map[string]any
	if err := yaml.Unmarshal([]byte(uncommented), &composed); err != nil {
		t.Fatalf("uncommented provider block is not valid YAML: %v\n%s", err, uncommented)
	}
	providers, err := provider.ParseProviders(composed)
	if err != nil {
		t.Fatalf("ParseProviders: %v", err)
	}
	openai, ok := providers["openai"]
	if !ok {
		t.Fatalf("openai provider missing after uncommenting; got %v", providers)
	}
	if openai.APIKey != "sk-test" {
		t.Errorf("openai api_key = %q, want sk-test", openai.APIKey)
	}
	if openai.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("openai base_url = %q, want https://api.openai.com/v1", openai.BaseURL)
	}

	venice, ok := providers["venice"]
	if !ok {
		t.Fatalf("venice provider missing after uncommenting; got %v", providers)
	}
	if venice.BaseURL != "https://api.venice.ai/api/v1" {
		t.Errorf("venice base_url = %q, want https://api.venice.ai/api/v1", venice.BaseURL)
	}
	if venice.APIKey != "sk-test" {
		t.Errorf("venice api_key = %q, want sk-test", venice.APIKey)
	}
	if name, value := venice.ResolveAuthHeader(); name != "Authorization" || value != "Bearer sk-test" {
		t.Errorf("venice auth = (%q, %q), want (Authorization, Bearer sk-test)", name, value)
	}
}

func TestGeneratedSettings_FullByteSnapshot(t *testing.T) {
	got := string(GeneratedSettingsBytes())
	if got != expectedGeneratedSettings {
		t.Fatalf("GeneratedSettingsBytes() does not match snapshot\n--- got ---\n%s\n--- want ---\n%s",
			got, expectedGeneratedSettings)
	}
}

func TestGeneratedSettings_ContainsCanonicalBlocks(t *testing.T) {
	got := string(GeneratedSettingsBytes())
	if !strings.Contains(got, expectedProviderBlock) {
		t.Fatalf("generated settings missing canonical req-135 provider block")
	}
	if !strings.Contains(got, expectedModelBlock) {
		t.Fatalf("generated settings missing canonical req-515 model block")
	}
	if !strings.Contains(got, expectedWebResearchBlock) {
		t.Fatalf("generated settings missing canonical req-220 web_research block")
	}
}

func TestWebResearchBlock_MatchesCanonical(t *testing.T) {
	if canonicalWebResearchBlock != expectedWebResearchBlock {
		t.Fatalf("canonicalWebResearchBlock drifted from the expected literal\n--- got ---\n%s\n--- want ---\n%s",
			canonicalWebResearchBlock, expectedWebResearchBlock)
	}
}

func TestGeneratedSettings_WebResearchGuidance(t *testing.T) {
	got := string(GeneratedSettingsBytes())
	for _, want := range []string{
		"Web research (search and direct fetch) is ON by default",
		"adds outbound network egress",
		"mcp.exa.ai",
		"the source hosts you follow",
		"approved by you per request in the permission prompt",
		"allow once, this session, or this project",
		"Direct fetch and search both work with no Exa key",
		"web_research.api_key is optional",
		"supply your own Exa key to run search",
		"against your own Exa account",
		"that switch is the only way to turn web research off",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated settings missing req-220 web-research guidance %q", want)
		}
	}
	for _, unwanted := range []string{"is OFF by default", "needed only for search", "search stays unavailable"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("generated settings still carry the stale web-research claim %q", unwanted)
		}
	}

	var composed map[string]any
	if err := yaml.Unmarshal([]byte(got), &composed); err != nil {
		t.Fatalf("generated settings are not valid YAML: %v", err)
	}
	if _, ok := composed["web_research"]; ok {
		t.Errorf("generated settings materialize a live web_research key; the block must stay commented")
	}
}

func TestWebResearchBlock_UncommentsToValidSettings(t *testing.T) {
	var b strings.Builder
	started := false
	for _, ln := range strings.Split(canonicalWebResearchBlock, "\n") {
		if !started {
			if strings.HasPrefix(ln, "# web_research:") {
				started = true
			} else {
				continue
			}
		}
		switch {
		case ln == "#":
		case strings.HasPrefix(ln, "# "):
			b.WriteString(strings.TrimPrefix(ln, "# "))
		default:
			b.WriteString(ln)
		}
		b.WriteByte('\n')
	}
	uncommented := b.String()
	if !strings.Contains(uncommented, "enabled: false") {
		t.Fatalf("uncommented web_research block does not start disabled:\n%s", uncommented)
	}
	if err := config.Validate([]byte(uncommented), "settings.yaml"); err != nil {
		t.Fatalf("uncommented web_research block fails settings schema validation: %v\n%s", err, uncommented)
	}

	var noKey strings.Builder
	for _, ln := range strings.Split(uncommented, "\n") {
		if strings.Contains(ln, "api_key:") {
			continue
		}
		noKey.WriteString(ln + "\n")
	}
	if err := config.Validate([]byte(noKey.String()), "settings.yaml"); err != nil {
		t.Fatalf("web_research block without api_key fails schema validation: %v\n%s", err, noKey.String())
	}
}

// TestGeneratedSettings_ContainsAllDocumentedDefaults guards against drift in
// the surrounding default keys. It uses a string-presence check rather than a
// YAML loader to avoid pulling in a dep this package does not own.
func TestGeneratedSettings_ContainsAllDocumentedDefaults(t *testing.T) {
	got := string(GeneratedSettingsBytes())
	for _, materialized := range []string{
		"boundary: launch-dir-only",
		"priority: [git, hg, jj]",
		`preferred: ""`,
		"retention_days: 30",
		"max_tool_output_bytes: 65536",
		"max_file_bytes: 65536",
		"max_concurrency: 3",
		"permissions: []",
	} {
		if !strings.Contains(got, materialized) {
			t.Errorf("generated settings missing documented default %q (req 105)", materialized)
		}
	}
}

func TestWriteFirstRunSettings_CleanWrite(t *testing.T) {
	home := t.TempDir()
	parent := filepath.Join(home, ".codemeld", "global")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("seed parent dir: %v", err)
	}

	path, step, cat, err := WriteFirstRunSettings(home)
	if err != nil {
		t.Fatalf("WriteFirstRunSettings: %v (step=%q cat=%q)", err, step, cat)
	}
	if step != "" || cat != "" {
		t.Fatalf("step=%q cat=%q on success, want both empty", step, cat)
	}
	if path != filepath.Join(home, ".codemeld", "global", "settings.yaml") {
		t.Fatalf("path = %q, want $HOME/.codemeld/global/settings.yaml", path)
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read written file: %v", readErr)
	}
	if !bytes.Equal(got, GeneratedSettingsBytes()) {
		t.Fatalf("written bytes differ from GeneratedSettingsBytes()")
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("stat: %v", statErr)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %v, want 0600 (req 150)", mode)
	}
}

func TestRunWriteSettings_CleanRun_PrintsCanonicalMessage(t *testing.T) {
	home := t.TempDir()
	parent := filepath.Join(home, ".codemeld", "global")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("seed parent dir: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := RunWriteSettings(home, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on success", stderr.String())
	}

	path := filepath.Join(home, ".codemeld", "global", "settings.yaml")
	want := strings.ReplaceAll(expectedFirstRunMessage, "<path>", path)
	got := stdout.String()
	if !strings.HasPrefix(got, want) {
		t.Fatalf("stdout does not start with canonical req-45 message\n--- got prefix ---\n%s\n--- want ---\n%s",
			truncate(got, len(want)+32), want)
	}

	tail := got[len(want):]
	if !strings.Contains(tail, "settings to review") {
		t.Errorf("missing req-50 'settings to review' header in stdout tail: %q", tail)
	}
	for _, key := range []string{
		"discovery.boundary",
		"vcs.priority",
		"sessions.retention_days",
		"sessions.max_tool_output_bytes",
		"agent_instructions.max_file_bytes",
		"agent.max_concurrency",
		"blocked_paths",
		"model.active",
	} {
		if !strings.Contains(tail, key) {
			t.Errorf("req-50 settings-to-review section missing key %q in stdout tail", key)
		}
	}
	if strings.Contains(strings.ToLower(tail), "warning") {
		t.Errorf("settings-to-review tail = %q, want no warning wording", tail)
	}
}

func TestGeneratedSettings_BlockedPathsLoadAsTheRecommendedEntries(t *testing.T) {
	got := string(GeneratedSettingsBytes())
	if !strings.Contains(got, "permissions: []\n\n"+renderBlockedPathsBlock()+"\n"+expectedWebResearchBlock) {
		t.Fatalf("blocked_paths block is not directly after permissions: []\n%s", got)
	}

	home := t.TempDir()
	global := SettingsPath(home)
	raw, _, err := config.ValidateGlobalSettingsBytes(GeneratedSettingsBytes(), global)
	if err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes: %v", err)
	}
	layers := []securitystate.LayerSnapshot{{Kind: securitystate.LayerGlobal, Path: global, Present: true, Raw: raw}}

	var want []permissions.BlockedEntry
	for _, group := range recommendedBlockedPaths {
		for _, entry := range group.paths {
			path, err := permissions.ExpandBlockedEntry(home, entry)
			if err != nil {
				t.Fatalf("ExpandBlockedEntry(%q): %v", entry, err)
			}
			want = append(want, permissions.BlockedEntry{Path: path, Source: global})
		}
	}
	entries, err := blockedEntriesFromLayers(home, layers)
	if err != nil || !slices.Equal(entries, want) {
		t.Fatalf("blockedEntriesFromLayers = %+v, %v; want %+v", entries, err, want)
	}

	blocked, err := blockedPathsFromLayers(home, "", layers)
	if err != nil {
		t.Fatalf("blockedPathsFromLayers: %v", err)
	}
	if entry, ok := blocked.Blocking(filepath.Join(home, ".ssh", "id_rsa")); !ok || entry.Source != global {
		t.Fatalf("Blocking(~/.ssh/id_rsa) = %+v, %v; want an entry from %q", entry, ok, global)
	}
}

func TestRunWriteSettings_WriteFailure_EmitsOpFailAndExit1(t *testing.T) {
	home := t.TempDir()
	parent := filepath.Join(home, ".codemeld", "global")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("seed parent dir: %v", err)
	}
	// Force a rename failure by making the target an existing directory.
	target := filepath.Join(parent, "settings.yaml")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("seed directory at target path: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := RunWriteSettings(home, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on failure", stdout.String())
	}

	wantOpFailPrefix := "codemeld: write-settings failed: " + target + ":"
	if !strings.HasPrefix(stderr.String(), wantOpFailPrefix) {
		t.Fatalf("stderr missing OP_FAIL prefix\n--- got ---\n%s\n--- want prefix ---\n%s",
			stderr.String(), wantOpFailPrefix)
	}
	if strings.Count(stderr.String(), "\n") != 1 {
		t.Errorf("stderr must contain exactly one line (OP_FAIL only), got: %q", stderr.String())
	}
}

func TestSettingsPath_IsUnderHomeDotCodemeldGlobal(t *testing.T) {
	got := SettingsPath("/some/home")
	want := "/some/home/.codemeld/global/settings.yaml"
	if got != want {
		t.Fatalf("SettingsPath = %q, want %q", got, want)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
