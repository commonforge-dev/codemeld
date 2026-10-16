// Built-in OpenRouter launch-provider connection defaults.
package provider

const openRouterProviderID = "openrouter"

func openRouterAdapter() *Adapter {
	return &Adapter{
		Name:              openRouterProviderID,
		DefaultBaseURL:    "https://openrouter.ai/api/v1",
		DefaultAuthHeader: AuthHeader{Name: defaultAuthHeaderName, Value: defaultAuthHeaderValue},
	}
}

func init() {
	register(openRouterAdapter())
}
