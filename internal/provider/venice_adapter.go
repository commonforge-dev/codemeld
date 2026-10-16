// Built-in Venice.ai OpenAI-compatible provider connection defaults.
package provider

func veniceAdapter() *Adapter {
	return &Adapter{
		Name:              "venice",
		DefaultBaseURL:    "https://api.venice.ai/api/v1",
		DefaultAuthHeader: AuthHeader{Name: defaultAuthHeaderName, Value: defaultAuthHeaderValue},
	}
}

func init() {
	register(veniceAdapter())
}
