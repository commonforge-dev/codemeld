// OpenAI ChatGPT (Codex) Responses API adapter: maps codemeld's provider.Request/
// Response turn contract onto the ChatGPT/Codex Responses API at the pinned,
// non-overridable origin, bridging Responses SSE events into the
// openai.ChatCompletionChunk stream the turn loop already consumes, with two-header
// auth and credential-safe HTTP errors. This adapter exception is scoped to the
// built-in openai-chatgpt provider only; Platform/OpenRouter/custom providers keep
// the chat-completions NewClient path unchanged.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/ssestream"
)

const (
	// chatGPTCodexBaseURL is the approved origin for ChatGPT/Codex model (Responses
	// API) requests. It is adapter-owned and non-overridable: no
	// setting, environment variable, custom provider, or user base URL may redirect
	// ChatGPT credentials elsewhere. Only in-package tests substitute the unexported
	// baseURL field with a stub server.
	chatGPTCodexBaseURL = "https://chatgpt.com/backend-api/codex"
	// chatGPTResponsesPath is the Responses endpoint appended to the base URL.
	chatGPTResponsesPath = "/responses"
	// chatGPTModelsPath is the model-discovery endpoint appended to the base URL.
	chatGPTModelsPath = "/models"
	// chatGPTAccountHeader carries the stored account id alongside the bearer token.
	// Its value is a credential-derived secret for redaction.
	chatGPTAccountHeader      = "ChatGPT-Account-ID"
	chatGPTCodexClientVersion = "0.160.0"
	// chatGPTCodexOriginator is the Codex client originator/User-Agent identity the
	// discovery endpoint expects alongside the ChatGPT credentials.
	chatGPTCodexOriginator = "codex_cli_rs"
)

// chatGPTProviderName is the display name woven into the HTTP-error surface prefix;
// it reuses the catalog's display-name constant.
const chatGPTProviderName = chatGPTDisplayName

// ChatGPTClientConfig carries the per-turn ChatGPT credentials the adapter needs.
// The production wiring loads and, where needed, refreshes the stored
// auth.openai-chatgpt session and supplies the already-resolved access token and
// account id here; the adapter never reads global settings, chooses providers, or
// refreshes tokens itself.
type ChatGPTClientConfig struct {
	AccessToken string
	AccountID   string
	// HTTPClient is optional and lets tests point the adapter at a stub server. It
	// changes only the transport, never the pinned origin: the request
	// URL stays chatgpt.com so a test redirects with a RoundTripper, not a base-URL
	// override. Production leaves it nil; either way the adapter wraps it in a
	// redirect-pinned copy (see pinRedirects) so credentials never follow a 3xx off
	// the approved origin.
	HTTPClient *http.Client
}

// chatGPTClient is the Responses API adapter satisfying the provider.Client turn
// contract. accessToken and accountID are the only credentials it holds; both are
// secrets scrubbed from any surfaced error text.
type chatGPTClient struct {
	accessToken string
	accountID   string
	// baseURL is the adapter-owned origin; NewChatGPTClient pins it to
	// chatGPTCodexBaseURL and only in-package tests override it.
	baseURL string
	// httpClient is redirect-pinned by pinRedirects so a 3xx from the origin cannot
	// carry the credential headers to another host.
	httpClient *http.Client
}

// NewChatGPTClient builds the ChatGPT/Codex Responses API adapter as a
// provider.Client. It pins the non-overridable approved origin and the caller
// supplies an already-loaded/refreshed access token and account id. The
// returned client speaks the Responses API and is used only for the built-in
// openai-chatgpt provider.
func NewChatGPTClient(cfg ChatGPTClientConfig) Client {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	return &chatGPTClient{
		accessToken: cfg.AccessToken,
		accountID:   cfg.AccountID,
		baseURL:     chatGPTCodexBaseURL,
		httpClient:  pinRedirects(hc),
	}
}

// pinRedirects returns a shallow copy of hc whose redirect policy refuses to follow
// any 3xx response, so the ChatGPT credentials ChatCompletion attaches can never ride
// a redirect off the approved origin. The redirect response is handed
// back unfollowed (http.ErrUseLastResponse) and surfaces as a non-2xx *HTTPError; the
// Responses API answers a direct 200 SSE, so a legitimate request never redirects. The
// passed-in client (http.DefaultClient in production, a test transport otherwise) is
// copied, never mutated, so pinning is side-effect free.
func pinRedirects(hc *http.Client) *http.Client {
	pinned := *hc
	pinned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &pinned
}

// ChatCompletion issues the streaming Responses API request and returns its events
// bridged into the openai.ChatCompletionChunk stream form turn.Run consumes. The
// turn contract always streams (BuildRequest sets Stream=true), so the ChatGPT
// adapter implements only the streaming form; a non-streaming request — never issued
// in production — is refused rather than silently mapped. A non-2xx response is
// surfaced as a credential-redacted *HTTPError (path); a transport failure is
// returned verbatim for the turn layer's transport-failure classifier.
func (c *chatGPTClient) ChatCompletion(ctx context.Context, req Request) (Response, error) {
	if !req.Stream {
		return Response{}, errors.New("openai-chatgpt: non-streaming requests are not supported")
	}
	if err := validateToolNames(req); err != nil {
		return Response{}, err
	}

	responsesReq := buildResponsesRequest(req)
	body, err := json.Marshal(responsesReq)
	if err != nil {
		return Response{}, fmt.Errorf("openai-chatgpt: encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+chatGPTResponsesPath, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("openai-chatgpt: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	// The only credentials sent, and only to the pinned origin.
	httpReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	httpReq.Header.Set(chatGPTAccountHeader, c.accountID)

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Transport/TLS failure: returned untouched so turn.Run's ClassifyRequestError
		// emits provider_request_failed{dial|tls|...}. The URL names only the pinned
		// origin and path, no credentials.
		return Response{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return Response{}, c.surfaceHTTPError(res)
	}
	bridge := newResponsesBridge(ssestream.NewDecoder(res), c.redact)
	return Response{Stream: ssestream.NewStream[openai.ChatCompletionChunk](bridge, nil)}, nil
}

// redact scrubs the locally held ChatGPT credentials and credential-derived values
// from text bound for an error body, surface, or notice, so a provider
// response that echoes the bearer token or account id can never leak them.
func (c *chatGPTClient) redact(s string) string {
	return redactCredentials(s, c.accessToken, c.accountID)
}

// surfaceHTTPError reads a non-2xx Responses response body, redacts locally held
// credentials, and wraps it as the same *HTTPError the chat-completions path
// produces, so turn.Run renders the friendly one-line notice and persists
// provider_request_failed identically — minus any token/account-derived value.
// A body read failure yields an empty body rather than leaking the read error.
func (c *chatGPTClient) surfaceHTTPError(res *http.Response) error {
	var body string
	if res.Body != nil {
		if raw, readErr := io.ReadAll(res.Body); readErr == nil {
			body = string(raw)
		}
		_ = res.Body.Close()
	}
	// Preserve Retry-After so the auto-retry engine can honor a 429/503's
	// requested backoff. It carries no credential-derived value, so it is not
	// redacted; the body still is.
	return newHTTPError(chatGPTProviderName, res.StatusCode, c.redact(body), res.Header.Get("Retry-After"))
}

// --- model discovery: GET /models -> sanitized cache shape ------------------

// discoverModels fetches the account's ChatGPT/Codex model list from the pinned origin
// and parses it into the sanitized cache shape — selection/capability metadata only.
// The response's prompt-bearing base_instructions and model_messages are dropped by
// construction (chatGPTModel has no field for them, so they are never unmarshaled),
// and the raw body is never retained or surfaced: a non-2xx response becomes a
// body-free *HTTPError (status and Retry-After only) and a malformed body becomes a
// redacted decode error with no body echo. The client is redirect-pinned, so the credential-bearing request
// never follows a 3xx off the origin. It performs no caching; the connect-path caller
// persists the adapted result through the injected store writer.
func (c *chatGPTClient) discoverModels(ctx context.Context) (chatGPTModelCache, error) {
	reqURL := c.baseURL + chatGPTModelsPath + "?client_version=" + chatGPTCodexClientVersion
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return chatGPTModelCache{}, fmt.Errorf("openai-chatgpt: build discovery request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	// The ChatGPT credentials, sent only to the pinned origin.
	httpReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	httpReq.Header.Set(chatGPTAccountHeader, c.accountID)
	// Codex client identity the discovery endpoint requires alongside the credentials.
	httpReq.Header.Set("version", chatGPTCodexClientVersion)
	httpReq.Header.Set("originator", chatGPTCodexOriginator)
	httpReq.Header.Set("User-Agent", chatGPTCodexOriginator+"/"+chatGPTCodexClientVersion)

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Transport/TLS failure or a refused redirect surfaced by the transport: the
		// error names only the pinned origin and path, no credentials.
		return chatGPTModelCache{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// A discovery non-2xx body can carry prompt-bearing base_instructions /
		// model_messages, so drop it entirely rather than redact-and-retain like the
		// Responses path — preserve only status and Retry-After, never the
		// response bytes.
		if res.Body != nil {
			_ = res.Body.Close()
		}
		return chatGPTModelCache{}, newHTTPError(chatGPTProviderName, res.StatusCode, "", res.Header.Get("Retry-After"))
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return chatGPTModelCache{}, fmt.Errorf("openai-chatgpt: read discovery response: %v", c.redact(err.Error()))
	}
	var cache chatGPTModelCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		// Redact and drop the raw body: a malformed models response can carry large
		// prompt-bearing payloads that must never reach a log or error surface.
		return chatGPTModelCache{}, fmt.Errorf("openai-chatgpt: decode discovery response: %v", c.redact(err.Error()))
	}
	return cache, nil
}

// RefreshChatGPTModelCache runs ChatGPT model discovery with the given session
// credentials, adapts the sanitized result into the shared discovered-model store's
// neutral records, and hands them to write for persistence. It runs only on explicit
// login and on a forced picker refresh — never automatically on picker open, highlight,
// or `codemeld auth status`. The store writer is injected so this package need not
// import internal/config. The returned error carries only a status/path, never a
// credential or a raw or prompt-bearing response body (discoverModels drops those by
// construction).
func RefreshChatGPTModelCache(ctx context.Context, cfg ChatGPTClientConfig, write func([]ChatGPTStoreModel) error) error {
	client, ok := NewChatGPTClient(cfg).(*chatGPTClient)
	if !ok {
		return errors.New("openai-chatgpt: discovery client construction failed")
	}
	cache, err := client.discoverModels(ctx)
	if err != nil {
		return err
	}
	return write(chatGPTStoreModels(cache))
}

// --- request mapping: provider.Request -> Responses API body ----------------

// responsesRequest is the ChatGPT/Codex Responses API request body. Only the
// fields codemeld populates are modeled; the model id is sent verbatim, system
// text is sent as instructions, and store is explicitly disabled.
type responsesRequest struct {
	Model          string              `json:"model"`
	Instructions   string              `json:"instructions"`
	Input          []responsesInput    `json:"input"`
	Tools          []responsesTool     `json:"tools,omitempty"`
	ToolChoice     string              `json:"tool_choice,omitempty"`
	Stream         bool                `json:"stream"`
	Store          bool                `json:"store"`
	Reasoning      *responsesReasoning `json:"reasoning,omitempty"`
	PromptCacheKey string              `json:"prompt_cache_key,omitempty"`
}

type responsesReasoning struct {
	Effort string `json:"effort"`
}

// responsesTool is one function tool advertised to the Responses API. The
// Responses function-tool shape is flat (name/description/parameters at the top
// level), unlike chat-completions' nested function object.
type responsesTool struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

// responsesInput is one Responses input item. It models the three shapes codemeld
// produces: a role message with content parts, an assistant function_call, and a
// function_call_output (tool result). Unused fields are omitted so each item
// serializes as exactly one shape.
type responsesInput struct {
	Type    string             `json:"type"`
	Role    string             `json:"role,omitempty"`
	Content []responsesContent `json:"content,omitempty"`
	// function_call item:
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	// function_call_output item:
	Output string `json:"output,omitempty"`
}

type responsesContent struct {
	Type     string  `json:"type"`
	Text     *string `json:"text,omitempty"`
	ImageURL string  `json:"image_url,omitempty"`
}

// buildResponsesRequest maps a streaming provider.Request onto the Responses API
// body, mirroring openAIClient.ChatCompletion's tool and effort handling: tools are
// advertised with automatic tool choice only when non-empty, and tool names are sent
// verbatim (they are already provider-safe and validated before this point).
func buildResponsesRequest(req Request) responsesRequest {
	tools := responsesToolsFromDefs(req.Tools)
	instructions, input := responsesInstructionsAndInput(req.Messages)
	out := responsesRequest{
		Model:          req.Model,
		Instructions:   instructions,
		Input:          input,
		Stream:         true,
		Store:          false,
		PromptCacheKey: req.PromptCacheKey,
	}
	if len(tools) > 0 {
		out.Tools = tools
		out.ToolChoice = "auto"
	}
	if req.Effort != "" {
		out.Reasoning = &responsesReasoning{Effort: req.Effort}
	}
	return out
}

// responsesToolsFromDefs maps codemeld's provider-agnostic tool definitions onto
// Responses function tools, sending name, description (only when non-empty), and
// JSON-Schema parameters (only when present) verbatim.
func responsesToolsFromDefs(defs []ToolDefinition) []responsesTool {
	out := make([]responsesTool, 0, len(defs))
	for _, d := range defs {
		out = append(out, responsesTool{
			Type:        "function",
			Name:        d.Name,
			Description: d.Description,
			Parameters:  d.Parameters,
		})
	}
	return out
}

// responsesInstructionsAndInput projects codemeld's provider messages onto the
// ChatGPT/Codex Responses request shape. System messages become top-level
// instructions because the ChatGPT backend rejects request bodies that omit that
// required field; non-system messages preserve order in input. A user message
// becomes input_text, a plain assistant message becomes output_text, assistant
// tool calls become function_call items, and tool results become
// function_call_output items keyed by call id, preserving the tool-call round-trip.
func responsesInstructionsAndInput(msgs []Message) (string, []responsesInput) {
	instructions := make([]string, 0, 1)
	out := make([]responsesInput, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case "assistant":
			if m.Content != "" {
				out = append(out, roleMessage("assistant", "output_text", m.Content))
			}
			for _, tc := range m.ToolCalls {
				out = append(out, responsesInput{
					Type:      "function_call",
					CallID:    tc.ID,
					Name:      tc.Name,
					Arguments: tc.Arguments,
				})
			}
		case "tool":
			out = append(out, responsesInput{
				Type:   "function_call_output",
				CallID: m.ToolCallID,
				Output: m.Content,
			})
		case "system":
			if m.Content != "" {
				instructions = append(instructions, m.Content)
			}
		default:
			if len(m.Parts) > 0 {
				out = append(out, responsesInput{
					Type:    "message",
					Role:    "user",
					Content: userResponsesContent(m.Parts),
				})
				continue
			}
			out = append(out, roleMessage("user", "input_text", m.Content))
		}
	}
	return strings.Join(instructions, "\n\n"), out
}

func userResponsesContent(parts []ContentPart) []responsesContent {
	out := make([]responsesContent, 0, len(parts))
	for _, p := range parts {
		if p.Type == "image_url" {
			out = append(out, responsesContent{Type: "input_image", ImageURL: p.ImageURL})
			continue
		}
		text := p.Text
		out = append(out, responsesContent{Type: "input_text", Text: &text})
	}
	return out
}

// roleMessage builds a Responses role message carrying a single text content part
// of the given part type (input_text for user/system, output_text for assistant).
func roleMessage(role, partType, text string) responsesInput {
	return responsesInput{
		Type:    "message",
		Role:    role,
		Content: []responsesContent{{Type: partType, Text: &text}},
	}
}

// --- streaming bridge: Responses SSE events -> chat-completion chunks --------

// responsesEvent is the discriminated Responses streaming event. type selects the
// variant; the remaining fields are the union of the shapes the bridge consumes.
type responsesEvent struct {
	Type   string `json:"type"`
	Delta  string `json:"delta"`
	ItemID string `json:"item_id"`
	// Arguments is the complete function-call argument string on a
	// function_call_arguments.done event (its delta-stream counterpart uses Delta).
	Arguments string           `json:"arguments"`
	Item      *responsesItem   `json:"item"`
	Response  *responsesResult `json:"response"`
}

// responsesItem is an output item carried by output_item.added/done events. For a
// function_call item, id is the streaming correlation key (matched by later
// arguments events' item_id) and call_id is the tool-call id codemeld must echo back
// as the function_call_output's call_id.
type responsesItem struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// responsesResult is the completed response object carried by response.completed
// (and the terminal failure events), holding the final usage and any error sentence.
type responsesResult struct {
	Usage *responsesUsage `json:"usage"`
	Error *responsesError `json:"error"`
}

type responsesUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
	// Pointer so an omitted detail stays distinct from a reported zero.
	InputTokensDetails struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

type responsesError struct {
	Message string `json:"message"`
}

// callState tracks one in-flight function call so streamed argument fragments
// correlate to a stable tool-call index and the id/name are emitted exactly once.
type callState struct {
	index        int64
	streamedArgs bool
}

// responsesBridge is an adapter-owned ssestream.Decoder that consumes the Responses
// SSE event stream (decoded by the wrapped raw decoder) and emits synthetic
// openai.ChatCompletionChunk JSON, so turn.Run and ToolLoop consume ChatGPT turns
// through the unchanged chat-completion stream contract: output_text deltas become
// content chunks, function-call items become tool_call deltas keyed by a stable
// index, response.completed becomes a finish chunk plus an include_usage-style usage
// chunk, and a malformed or out-of-order function-call sequence becomes a safe
// stream error rather than a partial, id-less tool call.
type responsesBridge struct {
	src    ssestream.Decoder
	redact func(string) string

	queue [][]byte // synthetic chunk payloads not yet handed to the Stream
	cur   ssestream.Event
	err   error

	calls           map[string]*callState // keyed by Responses output-item id
	nextIndex       int64
	sawFunctionCall bool
}

func newResponsesBridge(src ssestream.Decoder, redact func(string) string) *responsesBridge {
	return &responsesBridge{src: src, redact: redact, calls: map[string]*callState{}}
}

// Next advances to the next synthetic chunk, pulling and translating raw Responses
// events until at least one chunk is queued or the source ends. A translation error
// stops the stream and is surfaced through Err (turn.Run seals any partial reply and
// classifies it as a stream drop).
func (b *responsesBridge) Next() bool {
	for len(b.queue) == 0 {
		if !b.src.Next() {
			b.err = b.src.Err()
			return false
		}
		if err := b.translate(b.src.Event()); err != nil {
			b.err = err
			return false
		}
	}
	b.cur = ssestream.Event{Data: b.queue[0]}
	b.queue = b.queue[1:]
	return true
}

func (b *responsesBridge) Event() ssestream.Event { return b.cur }
func (b *responsesBridge) Close() error           { return b.src.Close() }
func (b *responsesBridge) Err() error             { return b.err }

// translate maps one raw Responses event to zero or more queued chunk payloads.
// Unhandled event types (response.created, in_progress, content_part.*,
// reasoning.*, …) and the terminal [DONE] marker produce nothing.
func (b *responsesBridge) translate(evt ssestream.Event) error {
	data := bytes.TrimSpace(evt.Data)
	if len(data) == 0 || bytes.HasPrefix(data, []byte("[DONE]")) {
		return nil
	}
	var e responsesEvent
	if err := json.Unmarshal(data, &e); err != nil {
		return fmt.Errorf("openai-chatgpt: decode Responses event: %v", b.redact(err.Error()))
	}
	switch e.Type {
	case "response.output_text.delta":
		b.enqueueContent(e.Delta)
	case "response.output_item.added":
		if e.Item != nil && e.Item.Type == "function_call" {
			return b.seedFunctionCall(e.Item)
		}
	case "response.function_call_arguments.delta":
		return b.enqueueFunctionArgs(e.ItemID, e.Delta)
	case "response.function_call_arguments.done":
		return b.completeFunctionArgs(e.ItemID, e.Arguments)
	case "response.output_item.done":
		if e.Item != nil && e.Item.Type == "function_call" {
			if err := b.seedFunctionCall(e.Item); err != nil {
				return err
			}
			return b.completeFunctionArgs(e.Item.ID, e.Item.Arguments)
		}
	case "response.completed":
		b.enqueueCompletion(e.Response)
	case "response.failed", "response.incomplete", "error":
		return b.responseError(e)
	}
	return nil
}

// enqueueContent queues an assistant content delta; an empty delta is dropped so it
// never reaches the turn loop as a no-op content choice.
func (b *responsesBridge) enqueueContent(delta string) {
	if delta == "" {
		return
	}
	b.queue = append(b.queue, marshalChunk(chunkPayload{
		Choices: []chunkChoice{{Delta: chunkDelta{Content: delta}}},
	}))
}

// seedFunctionCall registers a function-call item and emits its id+name once. The
// id and name must be present (they identify the call for tool_call_id correlation);
// a function-call announcement missing either is a protocol violation
// surfaced as a safe error rather than a partial tool call.
func (b *responsesBridge) seedFunctionCall(item *responsesItem) error {
	if _, ok := b.calls[item.ID]; ok {
		return nil
	}
	if item.CallID == "" || item.Name == "" {
		return fmt.Errorf("openai-chatgpt: function call missing call id or name for item %q", b.redact(item.ID))
	}
	st := &callState{index: b.nextIndex}
	b.nextIndex++
	b.calls[item.ID] = st
	b.sawFunctionCall = true
	b.queue = append(b.queue, marshalChunk(toolCallChunk(st.index, item.CallID, item.Name, "")))
	return nil
}

// enqueueFunctionArgs queues a streamed argument fragment for a known function call.
// Arguments for an item whose name/id were never announced cannot be assembled into
// a correlatable call, so they surface a safe protocol error.
func (b *responsesBridge) enqueueFunctionArgs(itemID, delta string) error {
	st, ok := b.calls[itemID]
	if !ok {
		return fmt.Errorf("openai-chatgpt: function-call arguments before name/id for item %q", b.redact(itemID))
	}
	if delta == "" {
		return nil
	}
	st.streamedArgs = true
	b.queue = append(b.queue, marshalChunk(toolCallChunk(st.index, "", "", delta)))
	return nil
}

// completeFunctionArgs emits the complete argument string for a function call when
// it was not already streamed incrementally (a backend that sends only the
// arguments.done / output_item.done full value and no deltas). When deltas already
// streamed, it is a no-op so arguments are never duplicated.
func (b *responsesBridge) completeFunctionArgs(itemID, arguments string) error {
	st, ok := b.calls[itemID]
	if !ok {
		return fmt.Errorf("openai-chatgpt: function-call completion before name/id for item %q", b.redact(itemID))
	}
	if st.streamedArgs || arguments == "" {
		return nil
	}
	st.streamedArgs = true
	b.queue = append(b.queue, marshalChunk(toolCallChunk(st.index, "", "", arguments)))
	return nil
}

// enqueueCompletion emits the terminal finish chunk (tool_calls when any function
// call streamed, otherwise stop) and, when the response carried usage, an
// include_usage-style usage chunk so model_response records the exact token totals
// instead of usage_missing.
func (b *responsesBridge) enqueueCompletion(resp *responsesResult) {
	finish := "stop"
	if b.sawFunctionCall {
		finish = "tool_calls"
	}
	b.queue = append(b.queue, marshalChunk(chunkPayload{
		Choices: []chunkChoice{{FinishReason: finish}},
	}))
	if resp != nil && resp.Usage != nil {
		u := &chunkUsage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
		if cached := resp.Usage.InputTokensDetails.CachedTokens; cached != nil {
			u.PromptTokensDetails = &chunkPromptTokensDetails{CachedTokens: *cached}
		}
		b.queue = append(b.queue, marshalChunk(chunkPayload{
			Choices: []chunkChoice{},
			Usage:   u,
		}))
	}
}

// responseError surfaces a terminal Responses failure event as a safe, redacted
// stream error: it prefers the response's error sentence and falls back to the event
// type, never echoing token/account-derived values.
func (b *responsesBridge) responseError(e responsesEvent) error {
	msg := e.Type
	if e.Response != nil && e.Response.Error != nil && e.Response.Error.Message != "" {
		msg = e.Response.Error.Message
	}
	return fmt.Errorf("openai-chatgpt: %s", b.redact(msg))
}

// --- synthetic chat-completion chunk JSON -----------------------------------

type chunkPayload struct {
	Choices []chunkChoice `json:"choices"`
	Usage   *chunkUsage   `json:"usage,omitempty"`
}

type chunkChoice struct {
	Index        int64      `json:"index"`
	Delta        chunkDelta `json:"delta"`
	FinishReason string     `json:"finish_reason,omitempty"`
}

type chunkDelta struct {
	Content   string          `json:"content,omitempty"`
	ToolCalls []chunkToolCall `json:"tool_calls,omitempty"`
}

type chunkToolCall struct {
	Index    int64             `json:"index"`
	ID       string            `json:"id,omitempty"`
	Type     string            `json:"type,omitempty"`
	Function chunkToolCallFunc `json:"function"`
}

type chunkToolCallFunc struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// chunkUsage mirrors openai.CompletionUsage's stream fields; the three counts are
// always emitted (no omitempty) so model.normalizeUsage sees them as present-and-valid
// rather than usage_missing. PromptTokensDetails takes the opposite default: emitting
// it for a response that carried no cached count would synthesize a false reported zero.
type chunkUsage struct {
	PromptTokens        int64                     `json:"prompt_tokens"`
	CompletionTokens    int64                     `json:"completion_tokens"`
	TotalTokens         int64                     `json:"total_tokens"`
	PromptTokensDetails *chunkPromptTokensDetails `json:"prompt_tokens_details,omitempty"`
}

type chunkPromptTokensDetails struct {
	CachedTokens int64 `json:"cached_tokens"`
}

// toolCallChunk builds a single-tool-call delta chunk at the given stable index. The
// id and name are sent only on the seed fragment (empty on argument fragments); the
// turn loop's assembleToolCalls keeps the first non-empty id and concatenates name
// and arguments across fragments, mirroring OpenAI's streamed tool-call shape.
func toolCallChunk(index int64, id, name, args string) chunkPayload {
	return chunkPayload{Choices: []chunkChoice{{Delta: chunkDelta{ToolCalls: []chunkToolCall{{
		Index:    index,
		ID:       id,
		Type:     "function",
		Function: chunkToolCallFunc{Name: name, Arguments: args},
	}}}}}}
}

// marshalChunk renders a synthetic chunk to JSON. The payload is only strings and
// ints, so marshaling cannot fail and the error is discarded.
func marshalChunk(p chunkPayload) []byte {
	b, _ := json.Marshal(p)
	return b
}
