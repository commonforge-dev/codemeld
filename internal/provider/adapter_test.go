// Tests for built-in adapter catalogs, registry wiring, cache-only supported-effort
// resolution, and the shared client's auth-header/HTTPS request path.
package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestBuiltinRegistrationsCarryNoEffortData(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Adapter{}), reflect.TypeOf(builtinProvider{})} {
		for i := range typ.NumField() {
			name := typ.Field(i).Name
			if strings.Contains(strings.ToLower(name), "effort") {
				t.Errorf("%s has field %s; built-in registrations must declare no reasoning efforts", typ.Name(), name)
			}
		}
	}
}

func TestBuiltinAdaptersRetainConnectionDefaults(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
	}{
		{PlatformProviderID, "https://api.openai.com/v1"},
		{openRouterProviderID, "https://openrouter.ai/api/v1"},
		{"venice", "https://api.venice.ai/api/v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := builtinAdapters[tt.name]
			if !ok {
				t.Fatalf("%q absent from builtinAdapters", tt.name)
			}
			if a.Name != tt.name {
				t.Errorf("Name = %q, want %q", a.Name, tt.name)
			}
			if a.DefaultBaseURL != tt.baseURL {
				t.Errorf("DefaultBaseURL = %q, want %q", a.DefaultBaseURL, tt.baseURL)
			}
			want := AuthHeader{Name: defaultAuthHeaderName, Value: defaultAuthHeaderValue}
			if a.DefaultAuthHeader != want {
				t.Errorf("DefaultAuthHeader = %+v, want %+v", a.DefaultAuthHeader, want)
			}
		})
	}
}

func TestFilterPlatformDiscoveredModels_RetainsEverySanitizedModel(t *testing.T) {
	in := []DiscoveredConfiguredModel{
		{ID: "text-embedding-3-large"},
		{ID: "gpt-5.5-pro", Capabilities: map[string]any{"x": 1}},
		{ID: "gpt-4.1-mini"},
		{ID: "gpt-5.5"},
		{ID: "dall-e-3"},
		{ID: "gpt-5.5-turbo"},
		{ID: "GPT-5.5"},
	}
	got := FilterPlatformDiscoveredModels(in)
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("FilterPlatformDiscoveredModels() = %v, want every sanitized record in discovery order %v", got, in)
	}
	if got := FilterPlatformDiscoveredModels(nil); len(got) != 0 {
		t.Fatalf("FilterPlatformDiscoveredModels(nil) = %v, want empty", got)
	}
}

func TestSupportedEffort_CachelessFallbackIsNoReasoning(t *testing.T) {
	cases := []struct{ providerID, modelID string }{
		{PlatformProviderID, "gpt-5.5"},
		{PlatformProviderID, "gpt-5.5-pro"},
		{openRouterProviderID, "openai/gpt-5.5"},
		{openRouterProviderID, "anthropic/claude-opus-4.7"},
		{"venice", "zai-org-glm-5"},
		{ChatGPTProviderID, "gpt-5.5"},
		{ChatGPTProviderID, "gpt-5.3-codex-spark"},
		{PlatformProviderID, "no-such-model"},
		{"no-such-provider", "gpt-5.5"},
	}
	for _, c := range cases {
		t.Run(c.providerID+"/"+c.modelID, func(t *testing.T) {
			want := []string{EffortNoReasoning}
			if got := SupportedEffort(c.providerID, c.modelID); !reflect.DeepEqual(got, want) {
				t.Fatalf("SupportedEffort(%q, %q) = %v, want %v", c.providerID, c.modelID, got, want)
			}
		})
	}
}

// Venice is registered as a chat-completions adapter (so buildTurnClient's
// NewClient path resolves its base URL and Bearer default) but is NOT a built-in
// selectable provider: Venice models come from a provider.venice settings entry.
// /connect venice can populate the selectable ids by GET /models discovery into
// the system-owned models.yaml store, but the adapter itself stays out of
// builtinSelectable — which is what this test pins.
func TestVeniceAdapter_IsChatCompletionsNotSelectable(t *testing.T) {
	if _, ok := builtinAdapters["venice"]; !ok {
		t.Errorf("venice absent from builtinAdapters; it must be a chat-completions adapter")
	}
	if _, ok := builtinSelectable["venice"]; ok {
		t.Errorf("venice present in builtinSelectable; it is a configured-only provider")
	}
}

// The OpenAI ChatGPT provider is a built-in *selectable* provider, not an
// OpenAI-compatible chat-completions adapter: it must not appear in builtinAdapters
// (whose entries carry the chat-completions base URL and Bearer default that the
// NewClient path would use), only in builtinSelectable. The ChatGPT provider speaks
// the Responses API through a dedicated adapter, so it must never be
// resolved as a chat-completions provider.
func TestOpenAIChatGPT_IsSelectableNotChatCompletionsAdapter(t *testing.T) {
	if _, ok := builtinAdapters[ChatGPTProviderID]; ok {
		t.Errorf("%q present in builtinAdapters; it must not be a chat-completions adapter", ChatGPTProviderID)
	}
	if _, ok := builtinSelectable[ChatGPTProviderID]; !ok {
		t.Errorf("%q absent from builtinSelectable; it must be a built-in selectable provider", ChatGPTProviderID)
	}
	// The OpenAI Platform provider stays a chat-completions adapter and is not a
	// built-in selectable (its models come from the configured provider: map).
	if _, ok := builtinAdapters[PlatformProviderID]; !ok {
		t.Errorf("%q absent from builtinAdapters; the Platform provider must stay a chat-completions adapter", PlatformProviderID)
	}
	if _, ok := builtinSelectable[PlatformProviderID]; ok {
		t.Errorf("%q present in builtinSelectable; the Platform provider's models come from settings, not a built-in list", PlatformProviderID)
	}
}

// minimalCompletionBody is a syntactically valid non-streaming chat-completion
// response the openai-go decoder accepts.
const minimalCompletionBody = `{"id":"c1","object":"chat.completion","created":0,"model":"gpt-5.5","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`

// A custom non-Authorization auth header must be sent verbatim and must not be
// accompanied by any SDK- or environment-injected Authorization bearer header.
func TestChatCompletion_CustomHeaderNoBearerLeak(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "env-leak-key")

	var gotCustom, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustom = r.Header.Get("X-API-Key")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, minimalCompletionBody)
	}))
	defer srv.Close()

	entry := ProviderEntry{
		BaseURL:    srv.URL,
		APIKey:     "secret",
		AuthHeader: &AuthHeader{Name: "X-API-Key", Value: "{api_key}"},
	}
	name, value := entry.ResolveAuthHeader()
	c := NewClient(ClientConfig{BaseURL: srv.URL, AuthHeader: name, AuthValue: value, HTTPClient: srv.Client()})

	if _, err := c.ChatCompletion(context.Background(), Request{
		Model:    "anthropic/claude-opus-4.7",
		Messages: []Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("ChatCompletion() error = %v", err)
	}
	if gotCustom != "secret" {
		t.Fatalf("X-API-Key = %q, want %q", gotCustom, "secret")
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty (no SDK/env bearer leak)", gotAuth)
	}
}

// The streaming form dispatches to NewStreaming, reaches the stub with the
// resolved auth header, and sends stream:true in the request body.
func TestChatCompletion_StreamingDispatch(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL:    srv.URL,
		AuthHeader: "Authorization",
		AuthValue:  "Bearer sk-test",
		HTTPClient: srv.Client(),
	})
	resp, err := c.ChatCompletion(context.Background(), Request{
		Model:    "gpt-5.5",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Stream:   true,
	})
	if err != nil {
		t.Fatalf("ChatCompletion(stream) error = %v", err)
	}
	if resp.Stream == nil {
		t.Fatalf("ChatCompletion(stream) Stream = nil, want non-nil")
	}
	for resp.Stream.Next() {
	}
	if err := resp.Stream.Err(); err != nil {
		t.Fatalf("stream error = %v", err)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer sk-test")
	}
	if !strings.Contains(gotBody, `"stream":true`) {
		t.Fatalf("request body = %q, want it to contain \"stream\":true", gotBody)
	}
}

// A streaming request asks for the final usage chunk via
// stream_options.include_usage, so the runner can record exact model_response
// token usage; a non-streaming request sends no stream_options.
func TestChatCompletion_StreamingRequestsUsage(t *testing.T) {
	capture := func(req Request, eventStream bool) string {
		var gotBody string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			gotBody = string(body)
			if eventStream {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, minimalCompletionBody)
		}))
		defer srv.Close()

		c := NewClient(ClientConfig{
			BaseURL:    srv.URL,
			AuthHeader: "Authorization",
			AuthValue:  "Bearer sk-test",
			HTTPClient: srv.Client(),
		})
		resp, err := c.ChatCompletion(context.Background(), req)
		if err != nil {
			t.Fatalf("ChatCompletion() error = %v", err)
		}
		if resp.Stream != nil {
			for resp.Stream.Next() {
			}
			if err := resp.Stream.Err(); err != nil {
				t.Fatalf("stream error = %v", err)
			}
		}
		return gotBody
	}

	streamBody := capture(Request{Model: "gpt-5.5", Messages: []Message{{Role: "user", Content: "hi"}}, Stream: true}, true)
	if !strings.Contains(streamBody, `"include_usage":true`) {
		t.Fatalf("streaming request body = %q, want it to contain \"include_usage\":true", streamBody)
	}

	nonStreamBody := capture(Request{Model: "gpt-5.5", Messages: []Message{{Role: "user", Content: "hi"}}}, false)
	if strings.Contains(nonStreamBody, "stream_options") {
		t.Fatalf("non-streaming request body = %q, want no stream_options", nonStreamBody)
	}
}

func TestChatCompletion_ReasoningEffortWire(t *testing.T) {
	tests := []struct {
		name          string
		effort        string
		wantInBody    bool
		wantSubstring string
	}{
		{"literal default sent", EffortDefault, true, `"reasoning_effort":"default"`},
		{"empty omits effort", "", false, ""},
		{"explicit level sent", EffortHigh, true, `"reasoning_effort":"high"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				gotBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, minimalCompletionBody)
			}))
			defer srv.Close()

			c := NewClient(ClientConfig{
				BaseURL:    srv.URL,
				AuthHeader: "Authorization",
				AuthValue:  "Bearer sk-test",
				HTTPClient: srv.Client(),
			})
			if _, err := c.ChatCompletion(context.Background(), Request{
				Model:    "gpt-5.5",
				Messages: []Message{{Role: "user", Content: "hi"}},
				Effort:   tt.effort,
			}); err != nil {
				t.Fatalf("ChatCompletion() error = %v", err)
			}
			hasEffort := strings.Contains(gotBody, `"reasoning_effort"`)
			if hasEffort != tt.wantInBody {
				t.Fatalf("body %q reasoning_effort present = %v, want %v", gotBody, hasEffort, tt.wantInBody)
			}
			if tt.wantSubstring != "" && !strings.Contains(gotBody, tt.wantSubstring) {
				t.Fatalf("body %q, want substring %q", gotBody, tt.wantSubstring)
			}
		})
	}
}
