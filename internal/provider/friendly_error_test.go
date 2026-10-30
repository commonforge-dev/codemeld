// Table tests for FriendlyHTTPMessage body->message extraction.
package provider

import (
	"strings"
	"testing"
)

func TestFriendlyHTTPMessage(t *testing.T) {
	const name = "openrouter"
	const status = 429
	const prefix = "provider openrouter returned HTTP 429"

	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "openrouter metadata.raw preferred over generic message",
			body: `{"error":{"message":"Provider returned error","code":429,"metadata":{"raw":"google/gemma-4-26b-a4b-it:free is temporarily rate-limited upstream. Please retry shortly, or add your own key","provider_name":"Google AI Studio"}},"user_id":"user_2mzA"}`,
			want: prefix + ": google/gemma-4-26b-a4b-it:free is temporarily rate-limited upstream. Please retry shortly, or add your own key",
		},
		{
			name: "openai error.message when no metadata.raw",
			body: `{"error":{"message":"You exceeded your current quota, please check your plan and billing details.","type":"insufficient_quota","code":"insufficient_quota"}}`,
			want: prefix + ": You exceeded your current quota, please check your plan and billing details.",
		},
		{
			name: "non-JSON body falls back to bare prefix",
			body: "Bad Gateway",
			want: prefix,
		},
		{
			name: "empty body falls back to bare prefix",
			body: "",
			want: prefix,
		},
		{
			name: "JSON without error object falls back to bare prefix",
			body: `{"detail":"nope"}`,
			want: prefix,
		},
		{
			name: "error object without usable fields falls back to bare prefix",
			body: `{"error":{"code":429}}`,
			want: prefix,
		},
		{
			name: "empty metadata.raw falls through to error.message",
			body: `{"error":{"message":"real sentence","metadata":{"raw":""}}}`,
			want: prefix + ": real sentence",
		},
		{
			name: "control chars in extracted text collapse to single spaces",
			body: `{"error":{"metadata":{"raw":"line one\nline two\tcol\r\nend"}}}`,
			want: prefix + ": line one line two col end",
		},
		{
			name: "non-string metadata.raw is ignored, message used",
			body: `{"error":{"message":"fallback sentence","metadata":{"raw":42}}}`,
			want: prefix + ": fallback sentence",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FriendlyHTTPMessage(name, status, tc.body); got != tc.want {
				t.Fatalf("FriendlyHTTPMessage = %q, want %q", got, tc.want)
			}
		})
	}
}

// The internal user_id and JSON struct keys never reach the rendered line: only
// the extracted human sentence does.
func TestFriendlyHTTPMessage_NoInternalFieldsLeak(t *testing.T) {
	body := `{"error":{"message":"Provider returned error","metadata":{"raw":"retry shortly","provider_name":"Google AI Studio","is_byok":false}},"user_id":"user_2mzA"}`
	got := FriendlyHTTPMessage("openrouter", 429, body)
	for _, leaked := range []string{"user_id", "user_2mzA", "metadata", "is_byok", "provider_name", "{"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("rendered line %q leaks internal token %q", got, leaked)
		}
	}
}

func TestFriendlyRoutingExhaustionMessage(t *testing.T) {
	const friendly = "provider openrouter returned HTTP 404: No endpoints found that satisfy the max price for this request"
	const routingRemedy = "Change provider.openrouter.routing to let a provider through."
	const ignoreRemedy = "The ignore list is session-only; start a new session to clear it."
	httpErr := &HTTPError{Status: 404, Body: capturedMaxPriceBody}
	for _, tc := range []struct {
		name string
		err  RoutingExhaustionError
		want string
	}{
		{
			name: "captured max_price",
			err:  RoutingExhaustionError{Model: "inception/mercury-2.5", MaxPrice: MaxPrice{Prompt: 0.02, Completion: 0.075, HasPrompt: true, HasCompletion: true}},
			want: friendly + " (model inception/mercury-2.5; filters sent: max_price prompt 0.02 completion 0.075). " + routingRemedy,
		},
		{
			name: "partial max_price",
			err:  RoutingExhaustionError{Model: "inception/mercury-2.5", MaxPrice: MaxPrice{Completion: 0.075, HasCompletion: true}},
			want: friendly + " (model inception/mercury-2.5; filters sent: max_price completion 0.075). " + routingRemedy,
		},
		{
			name: "all four filters",
			err: RoutingExhaustionError{
				Model:              "inception/mercury-2.5",
				MaxPrice:           MaxPrice{Prompt: 0.02, Completion: 0.075, HasPrompt: true, HasCompletion: true},
				DataCollectionDeny: true,
				RequireParameters:  true,
				Ignore:             []string{"together", "deepinfra"},
			},
			want: friendly + " (model inception/mercury-2.5; filters sent: max_price prompt 0.02 completion 0.075, data_collection deny, require_parameters true, ignore [together deepinfra]). " + routingRemedy + " " + ignoreRemedy,
		},
		{
			name: "ignore alone",
			err:  RoutingExhaustionError{Model: "inception/mercury-2.5", Ignore: []string{"inception"}},
			want: friendly + " (model inception/mercury-2.5; filters sent: ignore [inception]). " + ignoreRemedy,
		},
		{
			name: "no filters sent",
			err:  RoutingExhaustionError{Model: "inception/mercury-2.5", MaxPrice: MaxPrice{Prompt: 1}},
			want: friendly + " (model inception/mercury-2.5; codemeld sent no routing filters). Check the provider settings in your OpenRouter account.",
		},
		{
			name: "control characters collapsed",
			err:  RoutingExhaustionError{Model: "inception/\nmercury", Ignore: []string{"to\ngether"}},
			want: friendly + " (model inception/ mercury; filters sent: ignore [to gether]). " + ignoreRemedy,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.err.HTTP = httpErr
			if got := FriendlyRoutingExhaustionMessage("openrouter", &tc.err); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestFriendlyRoutingExhaustionMessage_Quantizations(t *testing.T) {
	const friendly = "provider openrouter returned HTTP 404: No endpoints found that satisfy the max price for this request"
	const routingRemedy = "Change provider.openrouter.routing to let a provider through."
	const ignoreRemedy = "The ignore list is session-only; start a new session to clear it."
	for _, tc := range []struct {
		name string
		err  RoutingExhaustionError
		want string
	}{
		{
			name: "beside the other filters",
			err: RoutingExhaustionError{
				Model:              "z-ai/glm-5.3",
				MaxPrice:           MaxPrice{Prompt: 1, HasPrompt: true},
				DataCollectionDeny: true,
				RequireParameters:  true,
				Ignore:             []string{"together"},
				Quantization:       Quantization{Levels: []string{"fp8", "fp4"}, Mode: "required"},
			},
			want: friendly + " (model z-ai/glm-5.3; filters sent: max_price prompt 1, data_collection deny, require_parameters true, quantizations required [fp8 fp4] (each tried in order), ignore [together]). " + routingRemedy + " " + ignoreRemedy,
		},
		{
			name: "alone",
			err:  RoutingExhaustionError{Model: "z-ai/glm-5.3", Quantization: Quantization{Levels: []string{"int8"}, Mode: "required"}},
			want: friendly + " (model z-ai/glm-5.3; filters sent: quantizations required [int8] (each tried in order)). " + routingRemedy,
		},
		{
			name: "control characters collapsed",
			err:  RoutingExhaustionError{Model: "z-ai/glm-5.3", Quantization: Quantization{Levels: []string{"fp\n8", "fp4"}, Mode: "re\nquired"}},
			want: friendly + " (model z-ai/glm-5.3; filters sent: quantizations re quired [fp 8 fp4] (each tried in order)). " + routingRemedy,
		},
		{
			name: "mode without levels",
			err:  RoutingExhaustionError{Model: "z-ai/glm-5.3", Quantization: Quantization{Mode: "preferred"}},
			want: friendly + " (model z-ai/glm-5.3; codemeld sent no routing filters). Check the provider settings in your OpenRouter account.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.err.HTTP = &HTTPError{Status: 404, Body: capturedMaxPriceBody}
			if got := FriendlyRoutingExhaustionMessage("openrouter", &tc.err); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}
