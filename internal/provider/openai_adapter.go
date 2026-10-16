// Built-in OpenAI launch-provider connection defaults and Platform discovery
// projection.
package provider

import "os"

// PlatformProviderID is the stable provider id of the built-in OpenAI Platform
// (API-key) provider, persisted in model.active / model.last_used and matched at
// resume recovery. It is distinct from the OpenAI ChatGPT provider id
// ([ChatGPTProviderID]); there is no cross-provider precedence.
const PlatformProviderID = "openai"

// platformDisplayName is the OpenAI Platform provider's human-facing name in the
// selectable catalog.
const platformDisplayName = "OpenAI Platform"

// openAIAPIKeyEnv is the environment variable that, when set and non-empty,
// supplies the OpenAI Platform provider's API key ahead of the configured key.
const openAIAPIKeyEnv = "OPENAI_API_KEY"

// ResolvePlatformAPIKey returns the OpenAI Platform provider's effective API key,
// preferring a non-empty OPENAI_API_KEY environment variable over configuredKey
// (the key read from provider.openai.api_key in the global settings file). This
// precedence applies only to the Platform provider (auth kind [AuthKindPlatform]):
// the OpenAI ChatGPT provider uses its stored session and ignores OPENAI_API_KEY,
// and custom OpenAI-compatible providers resolve their key through
// provider.<name>.api_key unchanged.
func ResolvePlatformAPIKey(configuredKey string) string {
	if env := os.Getenv(openAIAPIKeyEnv); env != "" {
		return env
	}
	return configuredKey
}

func openAIAdapter() *Adapter {
	return &Adapter{
		Name:              PlatformProviderID,
		DefaultBaseURL:    "https://api.openai.com/v1",
		DefaultAuthHeader: AuthHeader{Name: defaultAuthHeaderName, Value: defaultAuthHeaderValue},
	}
}

func FilterPlatformDiscoveredModels(models []DiscoveredConfiguredModel) []DiscoveredConfiguredModel {
	return models
}

func init() {
	register(openAIAdapter())
}
