// Internal provider contract over the OpenAI chat-completions shape: the shared
// openai-go-backed Client plus the built-in adapter registry.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/packages/param"
	"github.com/openai/openai-go/v3/packages/ssestream"
	"github.com/openai/openai-go/v3/shared"
)

// toolNamePattern is the provider-safe function-tool name alphabet OpenAI-compatible
// providers (OpenRouter, OpenAI) accept: it must start with a letter or underscore and
// contain only letters, digits, and underscores. A name outside it is rejected by the
// provider with HTTP 400, so codemeld validates locally first.
var toolNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateToolNames rejects any advertised tool definition or replayed assistant
// tool-call name that is not provider-safe, before the request reaches the network.
// This fails fast and locally instead of surfacing a provider 400, and also catches a
// stale persisted tool-call name (e.g. an old "vcs.status") replayed from a session.
func validateToolNames(req Request) error {
	for _, d := range req.Tools {
		if !toolNamePattern.MatchString(d.Name) {
			return fmt.Errorf("provider: invalid tool name %q: must match %s", d.Name, toolNamePattern.String())
		}
	}
	for _, m := range req.Messages {
		for _, tc := range m.ToolCalls {
			if !toolNamePattern.MatchString(tc.Name) {
				return fmt.Errorf("provider: invalid tool-call name %q: must match %s", tc.Name, toolNamePattern.String())
			}
		}
	}
	return nil
}

// Only an empty Request.Effort omits the reasoning parameter; non-empty values are
// sent unchanged.
const (
	EffortNone    = "none"
	EffortMinimal = "minimal"
	EffortLow     = "low"
	EffortMedium  = "medium"
	EffortHigh    = "high"
	EffortXHigh   = "xhigh"
	EffortDefault = "default"
)

// Message is one chat-completion message in codemeld's internal provider
// contract. Role is "system", "user", "assistant", or "tool". An assistant
// message that invoked tools carries them in ToolCalls; a tool-result message
// (Role "tool") carries the id of the assistant tool-call entry it answers in
// ToolCallID, so the OpenAI-compatible tool-call continuation round-trips back to
// the provider.
type Message struct {
	Role    string
	Content string
	// Parts carries a user message's content as an ordered list of content parts
	// (text and image_url) instead of a plain string. When non-empty on a
	// Role=="user" message it takes precedence over Content, and the message is
	// sent as a `content` array rather than a string. It is
	// ignored for every other role. The provider package stays free of a sessions
	// import: the turn package translates sessions.ContentPart into this shape.
	Parts []ContentPart
	// ToolCalls is the assistant message's tool calls. It is set only on
	// Role=="assistant" messages that requested tools; an empty list sends a plain
	// assistant message.
	ToolCalls []ToolCall
	// ToolCallID correlates a Role=="tool" result message to the assistant
	// tool-call entry it answers. It is empty for every other role.
	ToolCallID       string
	Reasoning        string
	ReasoningDetails json.RawMessage
}

// ContentPart is one part of a multi-part user message in the provider contract.
// Type is "text" or "image_url": a text part carries its text in Text, and an
// image_url part carries its image reference (a data: URI or a URL) in ImageURL.
// codemeld only synthesizes these two shapes.
type ContentPart struct {
	Type     string
	Text     string
	ImageURL string
}

// ToolCall is one OpenAI-compatible function tool call carried on an assistant
// provider message. Arguments is the raw JSON-encoded arguments string as the
// model produced it (phase 1 supports only the "function" tool-call type).
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// Request is one chat-completion call. Effort is sent unchanged when non-empty; an
// empty value omits the reasoning parameter. Stream
// selects the streaming response form. Tools is the turn's mode-filtered advertised
// tool set: when non-empty ChatCompletion sends it as `tools` with
// automatic tool choice; when empty it sends neither field. The request builder owns
// assembling and mode-filtering this set — ChatCompletion never inspects the registry
// or mode state.
type Request struct {
	Model            string
	Messages         []Message
	Effort           string
	Stream           bool
	Tools            []ToolDefinition
	PromptCacheKey   string
	IgnoredProviders []string
}

// Response carries the result of a ChatCompletion call in exactly one form: for
// a non-streaming request Completion is set and Stream is nil; for a streaming
// request Stream is set and Completion is nil. The OpenAI chat-completions shape
// is codemeld's internal provider contract, so the openai-go result
// types are surfaced directly.
type Response struct {
	Completion *openai.ChatCompletion
	Stream     *ssestream.Stream[openai.ChatCompletionChunk]
}

// Client is codemeld's internal provider interface over chat completions,
// covering both the non-streaming and streaming response forms.
type Client interface {
	ChatCompletion(ctx context.Context, req Request) (Response, error)
}

// ClientConfig holds the resolved per-provider values a Client needs. AuthHeader
// and AuthValue are the name/value returned by ProviderEntry.ResolveAuthHeader.
// Name is the provider's display name, woven into the HTTP-error surface prefix.
// HTTPClient is optional and lets tests point the client at a stub
// server.
type ClientConfig struct {
	Name         string
	BaseURL      string
	AuthHeader   string
	AuthValue    string
	Attribution  bool
	Routing      Routing
	HTTPClient   *http.Client
	BestValueTag func(ctx context.Context, model string, ignored []string) string
}

type openAIClient struct {
	name         string
	routing      Routing
	bestValueTag func(ctx context.Context, model string, ignored []string) string
	svc          openai.ChatCompletionService
}

// OpenRouter groups dashboard activity by HTTP-Referer and fetches that URL for the
// app's icon and description, so the value must be codemeld's real site.
const (
	attributionRefererHeader    = "HTTP-Referer"
	attributionRefererValue     = "https://codemeld.dev"
	attributionTitleHeader      = "X-Title"
	attributionTitleValue       = "Codemeld"
	attributionCategoriesHeader = "X-OpenRouter-Categories"
	attributionCategoriesValue  = "cli-agent,programming-app"
)

// NewClient builds the shared openai-go-backed Client for any OpenAI-compatible
// provider, whether a built-in adapter or a custom configured one. It constructs
// the chat-completions service directly rather than openai.NewClient so no
// OPENAI_* environment variable can inject a base URL, API key, or header; the
// only auth sent is the resolved AuthHeader/AuthValue.
func NewClient(cfg ClientConfig) Client {
	opts := []option.RequestOption{
		option.WithBaseURL(cfg.BaseURL),
		option.WithHeader(cfg.AuthHeader, cfg.AuthValue),
		// Phase 1 never auto-retries; openai-go otherwise retries 429/503 and
		// other non-2xx responses, which the verbatim HTTP-error surface must
		// see exactly once.
		option.WithMaxRetries(0),
	}
	if cfg.Attribution && cfg.Name == openRouterProviderID {
		opts = append(opts,
			option.WithHeader(attributionRefererHeader, attributionRefererValue),
			option.WithHeader(attributionTitleHeader, attributionTitleValue),
			option.WithHeader(attributionCategoriesHeader, attributionCategoriesValue),
		)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	opts = append(opts, option.WithHTTPClient(pinRedirects(hc)), option.WithMiddleware(refuseRedirect(cfg.Name)))
	return &openAIClient{name: cfg.Name, routing: cfg.Routing, bestValueTag: cfg.BestValueTag, svc: openai.NewChatCompletionService(opts...)}
}

func (c *openAIClient) ChatCompletion(ctx context.Context, req Request) (Response, error) {
	if err := validateToolNames(req); err != nil {
		return Response{}, err
	}
	params := openai.ChatCompletionNewParams{
		Model:    req.Model,
		Messages: toSDKMessages(req.Messages, c.name == openRouterProviderID),
	}
	if req.PromptCacheKey != "" {
		params.PromptCacheKey = openai.String(req.PromptCacheKey)
	}
	var extraOpts []option.RequestOption
	if req.Effort != "" {
		if c.name == openRouterProviderID {
			extraOpts = append(extraOpts, option.WithJSONSet("reasoning.effort", req.Effort))
		} else {
			params.ReasoningEffort = shared.ReasoningEffort(req.Effort)
		}
	}
	if c.name == openRouterProviderID {
		if len(req.IgnoredProviders) > 0 {
			extraOpts = append(extraOpts, option.WithJSONSet("provider.ignore", req.IgnoredProviders))
		}
		switch {
		case c.routing.Sort == openRouterSortBestValue:
			tag := ""
			if c.bestValueTag != nil {
				tag = c.bestValueTag(ctx, req.Model, req.IgnoredProviders)
			}
			if tag != "" {
				extraOpts = append(extraOpts, option.WithJSONSet("provider.order", []string{tag}))
			} else {
				extraOpts = append(extraOpts, option.WithJSONSet("provider.sort", "price"))
			}
		case c.routing.Sort != "":
			extraOpts = append(extraOpts, option.WithJSONSet("provider.sort", c.routing.Sort))
		}
		if c.routing.DataCollection != "" {
			extraOpts = append(extraOpts, option.WithJSONSet("provider.data_collection", c.routing.DataCollection))
		}
		if c.routing.RequireParameters {
			extraOpts = append(extraOpts, option.WithJSONSet("provider.require_parameters", true))
		}
		if p, ok := c.routing.MaxPrice[req.Model]; ok {
			price := map[string]float64{}
			if p.HasPrompt {
				price["prompt"] = p.Prompt
			}
			if p.HasCompletion {
				price["completion"] = p.Completion
			}
			extraOpts = append(extraOpts, option.WithJSONSet("provider.max_price", price))
		}
	}
	if len(req.Tools) > 0 {
		// advertise the turn's mode-filtered tool set with automatic tool
		// choice. An empty set leaves both fields omitted (omitzero), so a zero-tool
		// turn sends no `tools` and no `tool_choice` — the SDK's "none is the default
		// when no tools are present" applies.
		params.Tools = toSDKTools(req.Tools)
		params.ToolChoice = openai.ChatCompletionToolChoiceOptionUnionParam{OfAuto: param.NewOpt("auto")}
	}
	if req.Stream {
		// Ask for the final usage chunk (include_usage): an extra chunk with an
		// empty choices array and a populated usage object is streamed before
		// [DONE], carrying the turn's exact token totals so the runner can record
		// real model_response usage instead of usage_missing and feed the in-flight
		// indicator. The chunk may be absent if the stream is
		// interrupted, which the runner tolerates.
		params.StreamOptions = openai.ChatCompletionStreamOptionsParam{IncludeUsage: openai.Bool(true)}
		// The streaming call uses a body-failure detector that does not buffer the
		// SSE body: it wraps the response body so a missing/truncated 2xx body
		// surfaces from the incremental read as a status-carrying *HTTPBodyError
		// (the non-streaming detectHTTPBodyFailure buffers and cannot be reused
		// here)..
		stream := c.svc.NewStreaming(ctx, params, append(extraOpts, option.WithMiddleware(detectStreamingBodyFailure))...)
		if err := stream.Err(); err != nil {
			return Response{}, c.routingExhaustion(c.surfaceHTTPError(err), req)
		}
		return Response{Stream: stream}, nil
	}
	// The non-streaming detector buffers the response body to tell a
	// missing/truncated 2xx body apart, which is safe only off the streaming path
	completion, err := c.svc.New(ctx, params, append(extraOpts, option.WithMiddleware(detectHTTPBodyFailure))...)
	if err != nil {
		return Response{}, c.routingExhaustion(c.surfaceHTTPError(err), req)
	}
	return Response{Completion: completion}, nil
}

func (c *openAIClient) routingExhaustion(err error, req Request) error {
	var httpErr *HTTPError
	if c.name != openRouterProviderID || !errors.As(err, &httpErr) || !isRoutingFilterExhaustion(httpErr) {
		return err
	}
	return &RoutingExhaustionError{
		Model:              req.Model,
		MaxPrice:           c.routing.MaxPrice[req.Model],
		DataCollectionDeny: c.routing.DataCollection == "deny",
		RequireParameters:  c.routing.RequireParameters,
		Ignore:             slices.Clone(req.IgnoredProviders),
		HTTP:               httpErr,
	}
}

// refuseRedirect is needed because openai-go builds API errors only for status >= 400
// and would otherwise decode a refused redirect's body as a success.
func refuseRedirect(name string) option.Middleware {
	return func(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		res, err := next(req)
		if err != nil || res == nil || res.StatusCode < 300 || res.StatusCode >= 400 {
			return res, err
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return nil, newHTTPError(name, res.StatusCode, string(body), res.Header.Get("Retry-After"))
	}
}

// detectHTTPBodyFailure is provider-client middleware that turns a 2xx response
// with a missing or truncated body into a typed *HTTPBodyError carrying the HTTP
// status, so the turn layer can emit provider_request_failed{http_no_body|
// http_truncated}. The status survives only here: once the SDK
// reads a 2xx body it surfaces a bare decode/read error with no status. A non-2xx
// response is left untouched on the *HTTPError path, and a body that reads
// in full is re-populated so the SDK decodes it as usual.
func detectHTTPBodyFailure(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
	res, err := next(req)
	if err != nil || res == nil {
		return res, err
	}
	// Only a 2xx body is read-and-decoded by the SDK; a non-2xx status flows
	// through the verbatim *HTTPError path with its body intact.
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res, err
	}
	body, readErr := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if readErr != nil {
		// The body was cut off mid-transfer; the status line was received, so it is
		// preserved for http_truncated.
		return nil, &HTTPBodyError{Status: res.StatusCode, Truncated: true}
	}
	if len(body) == 0 {
		// A status line but no body at all.
		return nil, &HTTPBodyError{Status: res.StatusCode}
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	return res, nil
}

// detectStreamingBodyFailure is the streaming-path counterpart to
// detectHTTPBodyFailure. It must not buffer the SSE body, so it leaves a 2xx
// response intact but wraps its body in a bodyFailureReader: a body that yields
// no bytes at all surfaces as *HTTPBodyError{Status} (http_no_body) and a body
// cut off mid-transfer surfaces as *HTTPBodyError{Status, Truncated: true}
// (http_truncated), carrying the status the SSE decoder would otherwise drop. A
// non-2xx response is left on the verbatim *HTTPError path.
func detectStreamingBodyFailure(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
	res, err := next(req)
	if err != nil || res == nil {
		return res, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res, err
	}
	res.Body = &bodyFailureReader{rc: res.Body, status: res.StatusCode}
	return res, nil
}

// bodyFailureReader wraps a streaming 2xx response body so a missing or truncated
// body becomes a status-carrying *HTTPBodyError as the SSE decoder reads it — the
// only place the status survives, since the decoder would otherwise report a bare
// read error. It adds no buffering: normal bytes pass straight through and a clean
// end-of-body (io.EOF after at least one byte) is forwarded unchanged.
type bodyFailureReader struct {
	rc      io.ReadCloser
	status  int
	readAny bool
}

func (b *bodyFailureReader) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.readAny = true
	}
	if err == nil {
		return n, nil
	}
	if errors.Is(err, io.EOF) {
		if !b.readAny {
			// A 2xx status line arrived but not a single body byte: an absent body.
			return n, &HTTPBodyError{Status: b.status}
		}
		return n, err
	}
	// A non-EOF read error after the status line arrived: the body was cut off
	// mid-transfer. Wrap the original so the turn layer can still recover its
	// io.EOF/ErrUnexpectedEOF fidelity if partial content had already streamed.
	return n, &HTTPBodyError{Status: b.status, Truncated: true, Err: err}
}

func (b *bodyFailureReader) Close() error { return b.rc.Close() }

// surfaceHTTPError converts an openai-go API error (a non-2xx HTTP response)
// into a typed *HTTPError carrying the verbatim response body, leaving every
// other error (transport, decode, context) untouched for the separate
// transport-level failure path. The body is re-read from the response openai-go re-populated,
// so arbitrary bytes are preserved without going through the SDK's JSON parse.
func (c *openAIClient) surfaceHTTPError(err error) error {
	var apiErr *openai.Error
	if !errors.As(err, &apiErr) {
		return err
	}
	var body, retryAfter string
	if apiErr.Response != nil {
		// Preserve Retry-After so the auto-retry engine can honor a 429/503's
		// requested backoff; the rest of the response headers are dropped.
		retryAfter = apiErr.Response.Header.Get("Retry-After")
		if apiErr.Response.Body != nil {
			if raw, readErr := io.ReadAll(apiErr.Response.Body); readErr == nil {
				body = string(raw)
			}
		}
	}
	return newHTTPError(c.name, apiErr.StatusCode, body, retryAfter)
}

// toSDKTools maps codemeld's provider-agnostic tool definitions onto the openai-go
// function-tool params. Each definition becomes a function tool whose name,
// description, and JSON-Schema parameters are sent verbatim; a definition with no
// parameters omits the schema (an empty parameter list). The description is sent only
// when non-empty so a definition without one omits the field rather than sending "".
func toSDKTools(defs []ToolDefinition) []openai.ChatCompletionToolUnionParam {
	out := make([]openai.ChatCompletionToolUnionParam, 0, len(defs))
	for _, d := range defs {
		fn := shared.FunctionDefinitionParam{Name: d.Name}
		if d.Description != "" {
			fn.Description = param.NewOpt(d.Description)
		}
		if d.Parameters != nil {
			fn.Parameters = shared.FunctionParameters(d.Parameters)
		}
		out = append(out, openai.ChatCompletionToolUnionParam{
			OfFunction: &openai.ChatCompletionFunctionToolParam{Function: fn},
		})
	}
	return out
}

func toSDKMessages(msgs []Message, replayReasoning bool) []openai.ChatCompletionMessageParamUnion {
	out := make([]openai.ChatCompletionMessageParamUnion, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case "system":
			out = append(out, openai.SystemMessage(m.Content))
		case "assistant":
			msg := openai.AssistantMessage(m.Content)
			if len(m.ToolCalls) > 0 {
				msg = assistantToolCallMessage(m)
			}
			if replayReasoning {
				switch {
				case len(m.ReasoningDetails) > 0:
					msg.OfAssistant.SetExtraFields(map[string]any{"reasoning_details": m.ReasoningDetails})
				case m.Reasoning != "":
					msg.OfAssistant.SetExtraFields(map[string]any{"reasoning": m.Reasoning})
				}
			}
			out = append(out, msg)
		case "tool":
			out = append(out, openai.ToolMessage(m.Content, m.ToolCallID))
		default:
			if len(m.Parts) > 0 {
				out = append(out, userPartsMessage(m.Parts))
			} else {
				out = append(out, openai.UserMessage(m.Content))
			}
		}
	}
	return out
}

// userPartsMessage builds the SDK user message for a multi-part user turn, so the
// wire `content` is an array of content-part objects rather than a plain string.
// Each provider ContentPart maps to a text or image_url part
// image parts are sent with detail "auto". The turn package only emits text and
// image_url parts, so an image_url type builds the image part and every other type
// is treated as text (carrying ContentPart.Text).
func userPartsMessage(parts []ContentPart) openai.ChatCompletionMessageParamUnion {
	sdkParts := make([]openai.ChatCompletionContentPartUnionParam, 0, len(parts))
	for _, p := range parts {
		switch p.Type {
		case "image_url":
			sdkParts = append(sdkParts, openai.ImageContentPart(openai.ChatCompletionContentPartImageImageURLParam{
				URL:    p.ImageURL,
				Detail: "auto",
			}))
		default:
			sdkParts = append(sdkParts, openai.TextContentPart(p.Text))
		}
	}
	return openai.UserMessage(sdkParts)
}

// assistantToolCallMessage builds the SDK assistant message param for an
// assistant turn that requested tools. Content is sent only when non-empty —
// OpenAI requires assistant content only when tool_calls is absent — and each
// tool call is rendered as the function tool-call variant (the only phase-1
// type). The Type field is left at its "function" default.
func assistantToolCallMessage(m Message) openai.ChatCompletionMessageParamUnion {
	var asst openai.ChatCompletionAssistantMessageParam
	if m.Content != "" {
		asst.Content.OfString = param.NewOpt(m.Content)
	}
	asst.ToolCalls = make([]openai.ChatCompletionMessageToolCallUnionParam, len(m.ToolCalls))
	for i, tc := range m.ToolCalls {
		asst.ToolCalls[i] = openai.ChatCompletionMessageToolCallUnionParam{
			OfFunction: &openai.ChatCompletionMessageFunctionToolCallParam{
				ID: tc.ID,
				Function: openai.ChatCompletionMessageFunctionToolCallFunctionParam{
					Name:      tc.Name,
					Arguments: tc.Arguments,
				},
			},
		}
	}
	return openai.ChatCompletionMessageParamUnion{OfAssistant: &asst}
}

type Adapter struct {
	Name              string
	DefaultBaseURL    string
	DefaultAuthHeader AuthHeader
}

var builtinAdapters = map[string]*Adapter{}

func register(a *Adapter) {
	builtinAdapters[a.Name] = a
}

func SupportedEffort(provider, modelID string) []string {
	return Catalog{}.SupportedEffort(provider, modelID)
}
