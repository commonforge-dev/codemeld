// Tests for the sanitized ChatGPT/Codex model adapt path: proof that prompt-bearing
// fields never reach the neutral shared-store records the connect writer persists.
package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A discovery response carrying prompt-bearing base_instructions and model_messages
// (plus an unmodeled future field) must adapt to store records holding only whitelisted
// selection/capability metadata: the prompt-bearing payloads and unknown fields are
// dropped end-to-end, from the parsed struct through to the neutral records the connect
// writer persists.
func TestChatGPTModelDiscoveryCacheSanitizesPromptFields(t *testing.T) {
	const secret = "SYSTEM PROMPT THAT MUST NOT PERSIST"
	body := `{"models":[{` +
		`"slug":"gpt-5.5","display_name":"GPT-5.5","context_window":400000,` +
		`"supported_reasoning_levels":[{"level":"xhigh","description":"max"}],` +
		`"default_reasoning_level":"high","supported_in_api":true,` +
		`"base_instructions":"` + secret + `",` +
		`"model_messages":[{"role":"system","content":"` + secret + `"}],` +
		`"unknown_future_field":123}]}`
	srv := modelsServer(t, nil, 200, body)
	c := testClient(srv, "tok", "acct")

	cache, err := c.discoverModels(context.Background())
	if err != nil {
		t.Fatalf("discoverModels() error = %v", err)
	}

	// The parsed struct already omits the prompt-bearing payloads by construction; the
	// adapter carries only the whitelisted fields into the neutral store records.
	models := chatGPTStoreModels(cache)
	if len(models) != 1 {
		t.Fatalf("adapted models = %d, want 1", len(models))
	}
	m := models[0]
	if m.ID != "gpt-5.5" || m.DisplayName != "GPT-5.5" || m.ContextWindow != 400000 {
		t.Fatalf("adapted core fields = %+v, want gpt-5.5/GPT-5.5/400000", m)
	}

	// Marshaling the full record must never surface a prompt-bearing or unknown field.
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal adapted record: %v", err)
	}
	adapted := string(raw)
	for _, forbidden := range []string{"base_instructions", "model_messages", secret, "unknown_future_field"} {
		if strings.Contains(adapted, forbidden) {
			t.Fatalf("adapted record leaked %q: %s", forbidden, adapted)
		}
	}
	// The whitelisted reasoning levels survive under capabilities for the later catalog task.
	if !strings.Contains(adapted, "xhigh") {
		t.Fatalf("adapted record dropped whitelisted reasoning levels: %s", adapted)
	}
	if _, ok := m.Capabilities["supported_reasoning_levels"]; !ok {
		t.Fatalf("capabilities dropped supported_reasoning_levels: %+v", m.Capabilities)
	}
}
