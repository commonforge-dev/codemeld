// Tests for settings.yaml schema validation.
package config_test

import (
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/config"
)

func TestValidate_Accepts(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"empty document", `{}`},
		{"generated first-run file", string(bootstrap.GeneratedSettingsBytes())},
		{
			"agent.max_concurrency minimum boundary",
			`agent:
  max_concurrency: 1
`,
		},
		{
			"sessions.max_tool_output_bytes minimum boundary",
			`sessions:
  max_tool_output_bytes: 256
`,
		},
		{
			"connection-only provider with default auth_header omitted",
			`provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: ""
`,
		},
		{
			"connection-only provider with explicit auth_header",
			`provider:
  custom:
    base_url: https://example.test/v1
    api_key: secret
    auth_header:
      name: X-Api-Key
      value: "{api_key}"
`,
		},
		{
			"openrouter entry with full routing block and auth_header",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    auth_header:
      name: Authorization
      value: "Bearer {api_key}"
    routing:
      sort: throughput
      data_collection: deny
      require_parameters: true
`,
		},
		{
			"openrouter entry with partial routing block",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      sort: latency
      data_collection: allow
      require_parameters: false
`,
		},
		{
			"openrouter routing sort best_value",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      sort: best_value
`,
		},
		{
			"openrouter entry with empty routing block",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing: {}
`,
		},
		{
			"openrouter routing with per-model max_price and explicit zero",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      sort: throughput
      max_price:
        anthropic/claude-sonnet-4.5: { prompt: 3.5, completion: 16 }
        moonshotai/kimi-k2: { prompt: 1 }
        moonshotai/kimi-k2:free: { completion: 0 }
`,
		},
		{
			"openrouter routing with empty max_price",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      max_price: {}
`,
		},
		{
			"folder permission with directory path_scope",
			`permissions:
  - kind: direct
    subject: "ls"
    path_scope: /home/u/proj
    grant_kind: folder
`,
		},
		{
			"global permission with star path_scope",
			`permissions:
  - kind: tool
    subject: vcs_commit
    path_scope: "*"
    grant_kind: global
`,
		},
		{
			"literal permission carries argument_hash",
			`permissions:
  - kind: literal
    subject: "rm -rf build"
    path_scope: /home/u/proj
    grant_kind: folder
    argument_hash: ` + strings.Repeat("a", 64) + `
`,
		},
		{
			"project host permission for web_search",
			`permissions:
  - kind: tool
    subject: web_search
    host_scope: mcp.exa.ai
    grant_kind: project
`,
		},
		{
			"project host permission for web_fetch alongside a path entry",
			`permissions:
  - kind: direct
    subject: "ls"
    path_scope: /home/u/proj
    grant_kind: folder
  - kind: tool
    subject: web_fetch
    host_scope: docs.example.com
    grant_kind: project
`,
		},
		{
			"model.active and model.last_used accept arbitrary values",
			`model:
  active: anything-goes
  last_used:
    provider: openai
    id: gpt-5.5
    effort: high
`,
		},
		{
			"model.favorites absent alongside other model keys",
			`model:
  active: gpt-5.5
`,
		},
		{
			"model.favorites empty list",
			`model:
  favorites: []
`,
		},
		{
			"model.favorites ordered provider/id pairs",
			`model:
  active: gpt-5.5
  favorites:
    - provider: openai
      id: gpt-5.5
    - provider: openrouter
      id: anthropic/claude
`,
		},
		{
			"blocked_paths empty list",
			`blocked_paths: []
`,
		},
		{
			"blocked_paths home, absolute, and Windows drive entries",
			`blocked_paths:
  - "~"
  - "~/.ssh"
  - /data/secrets
  - 'C:\secrets'
  - C:/secrets
`,
		},
		{
			"writable_folders shape only, no path rules",
			`writable_folders:
  - /data/x
  - rel/path
  - "~user/x"
  - /
  - "~/.codemeld"
`,
		},
		{
			"mode.default valid enum value",
			`mode:
  default: auto_edits
`,
		},
		{
			"provider.retry full block alongside a provider",
			`provider:
  retry:
    enabled: true
    max_attempts: 4
    base_delay_ms: 500
    max_delay_ms: 8000
  openai:
    base_url: https://api.openai.com/v1
    api_key: x
`,
		},
		{
			"provider.retry empty block",
			`provider:
  retry: {}
`,
		},
		{
			"global auth.openai-chatgpt with all required fields",
			`auth:
  openai-chatgpt:
    access_token: at-value
    refresh_token: rt-value
    expires_at: "2026-01-01T00:00:00Z"
    account_id: acct-value
`,
		},
		{
			"auth.openai-chatgpt accepts empty strings (runtime integrity owned by g620)",
			`auth:
  openai-chatgpt:
    access_token: ""
    refresh_token: ""
    expires_at: ""
    account_id: ""
`,
		},
		{
			"confinement with both keys",
			`confinement:
  program_lookup: strict
  shared_temp_folders: deny
`,
		},
		{"confinement friendly and allow", `confinement: {program_lookup: friendly, shared_temp_folders: allow}`},
		{"empty confinement map", `confinement: {}`},
		{"attribution enabled", `attribution: true`},
		{"attribution disabled", `attribution: false`},
		{"empty web_research map", `web_research: {}`},
		{
			"web_research enabled only",
			`web_research:
  enabled: true
`,
		},
		{
			"fully configured web_research",
			`web_research:
  enabled: true
  api_key: exa-secret
  max_results: 12
  timeout_seconds: 45
`,
		},
		{
			"web_research empty api_key",
			`web_research:
  api_key: ""
`,
		},
		{
			"web_research range lower boundaries",
			`web_research:
  max_results: 5
  timeout_seconds: 1
`,
		},
		{
			"web_research range upper boundaries",
			`web_research:
  max_results: 25
  timeout_seconds: 120
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := config.Validate([]byte(tt.yaml), "settings.yaml"); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestValidate_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantKey string
	}{
		{
			"non-boolean attribution",
			`attribution: "yes"
`,
			"attribution",
		},
		{
			"wrong-type agent.max_concurrency",
			`agent:
  max_concurrency: "three"
`,
			"agent.max_concurrency",
		},
		{
			"agent.max_concurrency below minimum",
			`agent:
  max_concurrency: 0
`,
			"agent.max_concurrency",
		},
		{
			"unknown subkey under agent",
			`agent:
  unexpected: true
`,
			"agent",
		},
		{
			"unknown subkey under sessions",
			`sessions:
  retention_days: 30
  unexpected: 1
`,
			"sessions",
		},
		{
			"sessions.max_tool_output_bytes below minimum",
			`sessions:
  max_tool_output_bytes: 255
`,
			"sessions.max_tool_output_bytes",
		},
		{
			"unknown subkey under auth_header",
			`provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: ""
    auth_header:
      name: Authorization
      value: "Bearer {api_key}"
      prefix: Bearer
`,
			"provider.openai.auth_header",
		},
		{
			"unknown key under permission entry",
			`permissions:
  - kind: direct
    subject: "ls"
    path_scope: /home/u/proj
    grant_kind: folder
    expires_at: never
`,
			"permissions.0",
		},
		{
			"missing provider base_url",
			`provider:
  openai:
    api_key: ""
`,
			"provider.openai",
		},
		{
			"unknown key under provider entry",
			`provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: ""
    region: us-east
`,
			"provider.openai",
		},
		{
			"auth_header null",
			`provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: ""
    auth_header: null
`,
			"provider.openai.auth_header",
		},
		{
			"auth_header scalar",
			`provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: ""
    auth_header: "Bearer x"
`,
			"provider.openai.auth_header",
		},
		{
			"auth_header missing value subfield",
			`provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: ""
    auth_header:
      name: Authorization
`,
			"provider.openai.auth_header",
		},
		{
			"literal entry missing argument_hash",
			`permissions:
  - kind: literal
    subject: "rm -rf build"
    path_scope: /home/u/proj
    grant_kind: folder
`,
			"permissions.0",
		},
		{
			"direct entry carries forbidden argument_hash",
			`permissions:
  - kind: direct
    subject: "ls"
    path_scope: /home/u/proj
    grant_kind: folder
    argument_hash: ` + strings.Repeat("a", 64) + `
`,
			"permissions.0",
		},
		{
			"global grant with directory path_scope",
			`permissions:
  - kind: tool
    subject: vcs_commit
    path_scope: /home/u/proj
    grant_kind: global
`,
			"permissions.0",
		},
		{
			"folder grant with star path_scope",
			`permissions:
  - kind: direct
    subject: "ls"
    path_scope: "*"
    grant_kind: folder
`,
			"permissions.0",
		},
		{
			"permission entry with neither path_scope nor host_scope",
			`permissions:
  - kind: tool
    subject: web_fetch
    grant_kind: project
`,
			"permissions.0",
		},
		{
			"host entry also carrying path_scope",
			`permissions:
  - kind: tool
    subject: web_fetch
    host_scope: docs.example.com
    path_scope: /home/u/proj
    grant_kind: project
`,
			"permissions.0",
		},
		{
			"path entry carrying host_scope",
			`permissions:
  - kind: direct
    subject: "ls"
    path_scope: /home/u/proj
    host_scope: docs.example.com
    grant_kind: folder
`,
			"permissions.0",
		},
		{
			"host entry with unapproved tool subject",
			`permissions:
  - kind: tool
    subject: vcs_commit
    host_scope: docs.example.com
    grant_kind: project
`,
			"permissions.0.subject",
		},
		{
			"host entry with a non-tool kind",
			`permissions:
  - kind: direct
    subject: web_fetch
    host_scope: docs.example.com
    grant_kind: project
`,
			"permissions.0.kind",
		},
		{
			"host entry with a folder grant_kind",
			`permissions:
  - kind: tool
    subject: web_fetch
    host_scope: docs.example.com
    grant_kind: folder
`,
			"permissions.0.grant_kind",
		},
		{
			"host entry with a wildcard host_scope",
			`permissions:
  - kind: tool
    subject: web_fetch
    host_scope: "*"
    grant_kind: project
`,
			"permissions.0.host_scope",
		},
		{
			"host entry with an empty host_scope",
			`permissions:
  - kind: tool
    subject: web_fetch
    host_scope: ""
    grant_kind: project
`,
			"permissions.0.host_scope",
		},
		{
			"host entry carrying argument_hash",
			`permissions:
  - kind: tool
    subject: web_fetch
    host_scope: docs.example.com
    grant_kind: project
    argument_hash: ` + strings.Repeat("a", 64) + `
`,
			"permissions.0.argument_hash",
		},
		{
			"network subject scoped by path instead of host",
			`permissions:
  - kind: tool
    subject: web_search
    path_scope: /home/u/proj
    grant_kind: folder
`,
			"permissions.0.subject",
		},
		{
			"path entry with a project grant_kind",
			`permissions:
  - kind: direct
    subject: "ls"
    path_scope: /home/u/proj
    grant_kind: project
`,
			"permissions.0.grant_kind",
		},
		{
			"invalid discovery.boundary enum",
			`discovery:
  boundary: everywhere
`,
			"discovery.boundary",
		},
		{
			"model.favorites entry missing provider",
			`model:
  favorites:
    - id: gpt-5.5
`,
			"model.favorites.0",
		},
		{
			"model.favorites entry missing id",
			`model:
  favorites:
    - provider: openai
`,
			"model.favorites.0",
		},
		{
			"model.favorites entry with empty provider",
			`model:
  favorites:
    - provider: ""
      id: gpt-5.5
`,
			"model.favorites.0.provider",
		},
		{
			"model.favorites entry with empty id",
			`model:
  favorites:
    - provider: openai
      id: ""
`,
			"model.favorites.0.id",
		},
		{
			"model.favorites entry with wrong-type provider",
			`model:
  favorites:
    - provider: 5
      id: gpt-5.5
`,
			"model.favorites.0.provider",
		},
		{
			"model.favorites entry with wrong-type id",
			`model:
  favorites:
    - provider: openai
      id: 5
`,
			"model.favorites.0.id",
		},
		{
			"model.favorites entry with unknown field",
			`model:
  favorites:
    - provider: openai
      id: gpt-5.5
      effort: high
`,
			"model.favorites.0",
		},
		{
			"model.favorites null entry",
			`model:
  favorites:
    - null
`,
			"model.favorites.0",
		},
		{
			"model.favorites scalar entry",
			`model:
  favorites:
    - gpt-5.5
`,
			"model.favorites.0",
		},
		{
			"model.favorites array entry",
			`model:
  favorites:
    - [openai, gpt-5.5]
`,
			"model.favorites.0",
		},
		{
			"model.favorites null",
			`model:
  favorites: null
`,
			"model.favorites",
		},
		{
			"model.favorites entry with null provider",
			`model:
  favorites:
    - provider: null
      id: gpt-5.5
`,
			"model.favorites.0.provider",
		},
		{
			"model.favorites entry with null id",
			`model:
  favorites:
    - provider: openai
      id: null
`,
			"model.favorites.0.id",
		},
		{
			"model.favorites is not an array",
			`model:
  favorites:
    openai: gpt-5.5
`,
			"model.favorites",
		},
		{
			"model.favorites scalar",
			`model:
  favorites: gpt-5.5
`,
			"model.favorites",
		},
		{
			"blocked_paths relative entry",
			`blocked_paths:
  - secrets
`,
			"blocked_paths.0",
		},
		{
			"blocked_paths dot-relative entry",
			`blocked_paths:
  - ./x
`,
			"blocked_paths.0",
		},
		{
			"blocked_paths another user's home",
			`blocked_paths:
  - ~user/x
`,
			"blocked_paths.0",
		},
		{
			"blocked_paths drive-relative Windows entry",
			`blocked_paths:
  - C:x
`,
			"blocked_paths.0",
		},
		{
			"blocked_paths UNC entry",
			`blocked_paths:
  - '\\server\share'
`,
			"blocked_paths.0",
		},
		{
			"blocked_paths empty entry",
			`blocked_paths:
  - ""
`,
			"blocked_paths.0",
		},
		{
			"blocked_paths non-string entry",
			`blocked_paths:
  - 3
`,
			"blocked_paths.0",
		},
		{
			"blocked_paths scalar",
			`blocked_paths: /data/secrets
`,
			"blocked_paths",
		},
		{
			"writable_folders scalar",
			`writable_folders: /data/x
`,
			"writable_folders",
		},
		{
			"writable_folders non-string entry",
			`writable_folders:
  - 3
`,
			"writable_folders.0",
		},
		{
			"invalid mode.default enum",
			`mode:
  default: turbo
`,
			"mode.default",
		},
		{
			"unknown subkey under mode",
			`mode:
  preferred: plan
`,
			"mode",
		},
		{
			"provider.retry unknown subkey",
			`provider:
  retry:
    enabled: true
    jitter: full
`,
			"provider.retry",
		},
		{
			"provider.retry max_attempts below minimum",
			`provider:
  retry:
    max_attempts: 0
`,
			"provider.retry.max_attempts",
		},
		{
			"reserved provider.openai-chatgpt rejected by name",
			`provider:
  openai-chatgpt:
    base_url: https://api.openai.com/v1
    api_key: x
`,
			"provider.openai-chatgpt",
		},
		{
			"global provider legacy models list rejected at its dotted leaf",
			`provider:
  openai:
    base_url: https://api.openai.com/v1
    api_key: ""
    models:
      - gpt-5.5
`,
			"provider.openai.models",
		},
		{
			"project provider legacy models list rejected at its dotted leaf",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: ""
    models: []
`,
			"provider.openrouter.models",
		},
		{
			"openrouter entry missing base_url",
			`provider:
  openrouter:
    api_key: or-key
`,
			"provider.openrouter",
		},
		{
			"openrouter entry missing api_key",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
`,
			"provider.openrouter",
		},
		{
			"openrouter auth_header missing value subfield",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    auth_header:
      name: Authorization
`,
			"provider.openrouter.auth_header",
		},
		{
			"unknown key under openrouter entry",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    region: us-east
`,
			"provider.openrouter",
		},
		{
			"unknown key under openrouter routing",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      order: [together]
`,
			"provider.openrouter.routing",
		},
		{
			"openrouter routing sort price not offered",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      sort: price
`,
			"provider.openrouter.routing.sort",
		},
		{
			"openrouter routing data_collection out of enum",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      data_collection: maybe
`,
			"provider.openrouter.routing.data_collection",
		},
		{
			"openrouter routing require_parameters not boolean",
			`provider:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    api_key: or-key
    routing:
      require_parameters: "yes"
`,
			"provider.openrouter.routing.require_parameters",
		},
		{
			"routing on a non-openrouter entry",
			`provider:
  venice:
    base_url: https://api.venice.ai/api/v1
    api_key: v-key
    routing:
      sort: throughput
`,
			"provider.venice",
		},
		{
			"auth.openai-chatgpt missing required access_token",
			`auth:
  openai-chatgpt:
    refresh_token: rt
    expires_at: "2026-01-01T00:00:00Z"
    account_id: acct
`,
			"auth.openai-chatgpt",
		},
		{
			"auth.openai-chatgpt missing required refresh_token",
			`auth:
  openai-chatgpt:
    access_token: at
    expires_at: "2026-01-01T00:00:00Z"
    account_id: acct
`,
			"auth.openai-chatgpt",
		},
		{
			"auth.openai-chatgpt missing required expires_at",
			`auth:
  openai-chatgpt:
    access_token: at
    refresh_token: rt
    account_id: acct
`,
			"auth.openai-chatgpt",
		},
		{
			"auth.openai-chatgpt missing required account_id",
			`auth:
  openai-chatgpt:
    access_token: at
    refresh_token: rt
    expires_at: "2026-01-01T00:00:00Z"
`,
			"auth.openai-chatgpt",
		},
		{
			"auth.openai-chatgpt wrong-type access_token",
			`auth:
  openai-chatgpt:
    access_token: 123
    refresh_token: rt
    expires_at: "2026-01-01T00:00:00Z"
    account_id: acct
`,
			"auth.openai-chatgpt.access_token",
		},
		{
			"auth.openai-chatgpt wrong-type refresh_token",
			`auth:
  openai-chatgpt:
    access_token: at
    refresh_token: 456
    expires_at: "2026-01-01T00:00:00Z"
    account_id: acct
`,
			"auth.openai-chatgpt.refresh_token",
		},
		{
			"auth.openai-chatgpt wrong-type expires_at",
			`auth:
  openai-chatgpt:
    access_token: at
    refresh_token: rt
    expires_at: true
    account_id: acct
`,
			"auth.openai-chatgpt.expires_at",
		},
		{
			"auth.openai-chatgpt wrong-type account_id",
			`auth:
  openai-chatgpt:
    access_token: at
    refresh_token: rt
    expires_at: "2026-01-01T00:00:00Z"
    account_id: false
`,
			"auth.openai-chatgpt.account_id",
		},
		{
			"auth.openai-chatgpt unknown field",
			`auth:
  openai-chatgpt:
    access_token: at
    refresh_token: rt
    expires_at: "2026-01-01T00:00:00Z"
    account_id: acct
    id_token: leftover
`,
			"auth.openai-chatgpt",
		},
		{
			"unknown auth provider key",
			`auth:
  openai:
    access_token: at
`,
			"auth",
		},
		{
			"unknown key under web_research",
			`web_research:
  enabled: true
  backend: exa
`,
			"web_research",
		},
		{
			"non-boolean web_research.enabled",
			`web_research:
  enabled: "yes"
`,
			"web_research.enabled",
		},
		{
			"non-string web_research.api_key",
			`web_research:
  api_key: 12345
`,
			"web_research.api_key",
		},
		{
			"web_research.max_results below minimum",
			`web_research:
  max_results: 4
`,
			"web_research.max_results",
		},
		{
			"web_research.max_results above maximum",
			`web_research:
  max_results: 26
`,
			"web_research.max_results",
		},
		{
			"non-integer web_research.max_results",
			`web_research:
  max_results: 6.5
`,
			"web_research.max_results",
		},
		{
			"web_research.timeout_seconds below minimum",
			`web_research:
  timeout_seconds: 0
`,
			"web_research.timeout_seconds",
		},
		{
			"web_research.timeout_seconds above maximum",
			`web_research:
  timeout_seconds: 121
`,
			"web_research.timeout_seconds",
		},
		{
			"non-integer web_research.timeout_seconds",
			`web_research:
  timeout_seconds: "20"
`,
			"web_research.timeout_seconds",
		},
		{
			"fractional web_research.timeout_seconds",
			`web_research:
  timeout_seconds: 20.5
`,
			"web_research.timeout_seconds",
		},
		{
			"web_research as a scalar",
			`web_research: true`,
			"web_research",
		},
		{
			"confinement.program_lookup outside its enum",
			`confinement:
  program_lookup: open
`,
			"confinement.program_lookup",
		},
		{
			"confinement.shared_temp_folders outside its enum",
			`confinement:
  shared_temp_folders: ask
`,
			"confinement.shared_temp_folders",
		},
		{
			"unknown key under confinement",
			`confinement:
  program_lookup: strict
  extra_paths: /opt/bin
`,
			"confinement",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.Validate([]byte(tt.yaml), "settings.yaml")
			if err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantKey) {
				t.Fatalf("error %q does not mention offending key %q", err.Error(), tt.wantKey)
			}
		})
	}
}

func TestValidate_RejectsInvalidMaxPriceAtExactKeys(t *testing.T) {
	const model = "provider.openrouter.routing.max_price.anthropic/claude-sonnet-4.5"
	tests := []struct {
		name    string
		entry   string
		wantKey string
	}{
		{"negative prompt", "{ prompt: -1, completion: 2 }", model + ".prompt"},
		{"empty per-model object", "{}", model},
		{"unknown price key", "{ prompt: 1, request: 0.01 }", model},
		{"image price key", "{ prompt: 1, image: 0.01 }", model},
		{"non-object entry", "3", model},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := "provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: or-key\n    routing:\n      max_price:\n        anthropic/claude-sonnet-4.5: " + tt.entry + "\n"
			err := config.Validate([]byte(src), "settings.yaml")
			if err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			_, rest, ok := strings.Cut(err.Error(), "schema validation failed at ")
			if !ok {
				t.Fatalf("error %q lacks the schema validation key list", err.Error())
			}
			if keys, _, _ := strings.Cut(rest, ": "); keys != tt.wantKey {
				t.Fatalf("offending keys = %q, want exactly %q\nerror = %s", keys, tt.wantKey, err.Error())
			}
		})
	}
}

func TestEnforceGlobalOnly_RejectsProjectOpenRouterRouting(t *testing.T) {
	project := map[string]any{"provider": map[string]any{
		"openrouter": map[string]any{"routing": map[string]any{"data_collection": "allow"}},
	}}
	err := config.EnforceGlobalOnly("project/settings.yaml", project)
	if err == nil {
		t.Fatalf("EnforceGlobalOnly() = nil, want a global-only error")
	}
	if !strings.Contains(err.Error(), "provider.openrouter.routing") || !strings.Contains(err.Error(), "global-only") {
		t.Fatalf("error %q, want a global-only rejection at provider.openrouter.routing", err.Error())
	}
}

func TestValidateGlobalSettingsBytes_AcceptsOpenRouterBestValueSort(t *testing.T) {
	src := []byte("provider:\n  openrouter:\n    base_url: https://openrouter.ai/api/v1\n    api_key: or-key\n    routing:\n      sort: best_value\n")
	if _, _, err := config.ValidateGlobalSettingsBytes(src, "settings.yaml"); err != nil {
		t.Fatalf("ValidateGlobalSettingsBytes() error = %v, want nil", err)
	}
}
