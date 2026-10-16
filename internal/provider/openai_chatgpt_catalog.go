// Built-in OpenAI ChatGPT selectable-provider catalog metadata: provider id,
// display name, ChatGPT/Codex model origin, and model list.
// This file owns catalog metadata only; the ChatGPT/Codex Responses API
// request/response adapter and client live in openai_chatgpt_client.go.
package provider

// ChatGPTProviderID is the stable, reserved provider id of the built-in OpenAI
// ChatGPT (subscription) provider, persisted in model.active / model.last_used and
// matched at resume recovery. It is distinct from the OpenAI Platform provider id
// ([PlatformProviderID]); a user-defined provider.openai-chatgpt entry is rejected
// at load, so this provider is never read from the configured provider: map.
const ChatGPTProviderID = "openai-chatgpt"

// chatGPTDisplayName is the OpenAI ChatGPT provider's human-facing name in the
// selectable catalog.
const chatGPTDisplayName = "OpenAI ChatGPT"

func openAIChatGPTBuiltin() *builtinProvider {
	return &builtinProvider{
		id:          ChatGPTProviderID,
		displayName: chatGPTDisplayName,
		models:      []string{"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex-spark"},
		authKind:    AuthKindChatGPTSession,
		origin:      OriginChatGPTCodex,
	}
}

func init() {
	registerBuiltinSelectable(openAIChatGPTBuiltin())
}
