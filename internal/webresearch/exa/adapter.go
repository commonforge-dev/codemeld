package exa

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"codemeld.dev/codemeld/internal/webresearch"
)

const (
	endpoint     = "https://mcp.exa.ai/mcp"
	searchTool   = "web_search_exa"
	apiKeyHeader = "x-api-key"
)

// None of these carry provider text, a header, a URL, or the key: they are
// returned verbatim to the capability layer and reach model-visible output.
var (
	errRateLimited      = errors.New("exa: your Exa account has reached its limit")
	errResponseTooLarge = errors.New("exa: the search response was too large")
	errSearchFailed     = errors.New("exa: the search request failed")
	errEmptyQuery       = errors.New("exa: the search query is empty")
)

// errTransient identifies transport and 5xx failures eligible for one retry.
var errTransient = errors.New("exa: the search request failed")

// The MCP cleanup logger must not write to stderr because stderr may be owned by the TUI.
var mcpLogger = slog.New(slog.DiscardHandler)

type Config struct {
	APIKey         string
	MaxResults     int
	Timeout        time.Duration
	MaxOutputBytes int
	HTTPClient     *http.Client
}

var _ webresearch.SearchBackend = (*Backend)(nil)

type Backend struct {
	maxResults int
	timeout    time.Duration
	httpClient *http.Client
	apiKey     string
}

func New(cfg Config) (*Backend, error) {
	if cfg.HTTPClient == nil {
		return nil, errors.New("exa: no HTTP client")
	}
	if cfg.MaxResults <= 0 {
		return nil, errors.New("exa: no result count")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("exa: no timeout")
	}
	if cfg.MaxOutputBytes <= 0 {
		return nil, errors.New("exa: no output cap")
	}
	// The transport limit is 2 * the output cap, so a larger cap would wrap to a
	// negative limit and fail every response, including an empty successful one.
	if cfg.MaxOutputBytes > math.MaxInt/2 {
		return nil, errors.New("exa: output cap too large")
	}
	return &Backend{
		maxResults: cfg.MaxResults,
		timeout:    cfg.Timeout,
		httpClient: boundedClient(cfg.HTTPClient, 2*cfg.MaxOutputBytes, cfg.APIKey),
		apiKey:     cfg.APIKey,
	}, nil
}

// Search retries transient failures once using a fresh lifecycle.
func (b *Backend) Search(ctx context.Context, query string) ([]webresearch.Candidate, error) {
	if strings.TrimSpace(query) == "" {
		return nil, errEmptyQuery
	}
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	candidates, err := b.searchOnce(ctx, query)
	if errors.Is(err, errTransient) {
		candidates, err = b.searchOnce(ctx, query)
	}
	if errors.Is(err, errTransient) {
		return nil, errSearchFailed
	}
	return candidates, err
}

func (b *Backend) searchOnce(ctx context.Context, query string) ([]webresearch.Candidate, error) {
	c, err := client.NewStreamableHttpClient(endpoint,
		transport.WithHTTPBasicClient(b.httpClient),
		transport.WithHTTPLogger(mcpLogger))
	if err != nil {
		return nil, errSearchFailed
	}
	defer func() { _ = c.Close() }()

	if err := c.Start(ctx); err != nil {
		return nil, classify(err)
	}
	var init mcp.InitializeRequest
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcp.Implementation{Name: "codemeld", Version: "1"}
	if _, err := c.Initialize(ctx, init); err != nil {
		return nil, classify(err)
	}
	var call mcp.CallToolRequest
	call.Params.Name = searchTool
	call.Params.Arguments = map[string]any{"query": query, "numResults": b.maxResults}
	result, err := c.CallTool(ctx, call)
	if err != nil {
		return nil, classify(err)
	}
	if result.IsError {
		return nil, errSearchFailed
	}
	return parseResults(redactKey(textOf(result.Content), b.apiKey))
}

// redactKey strips the configured key from provider-controlled text: the
// provider can echo it back inside a successful result, and a candidate reaches
// model-visible output. The placeholder carries no colon or newline so it
// cannot turn content into a parsed label.
func redactKey(text, apiKey string) string {
	if apiKey == "" {
		return text
	}
	return strings.ReplaceAll(text, apiKey, "[redacted]")
}

// classify keeps the provider failure out of the returned message: the MCP
// client formats status text, response bodies, and the request URL into its
// error strings, and those must not reach tool output.
func classify(err error) error {
	switch {
	case errors.Is(err, errRateLimited):
		return errRateLimited
	case errors.Is(err, errResponseTooLarge):
		return errResponseTooLarge
	case errors.Is(err, errTransient):
		return errTransient
	}
	return errSearchFailed
}

func textOf(content []mcp.Content) string {
	var b strings.Builder
	for _, item := range content {
		text, ok := item.(mcp.TextContent)
		if !ok {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(text.Text)
	}
	return b.String()
}

// boundedClient copies the caller's client so the MCP library only ever sees a
// buffered 2xx body within limit. The library reads every response body without
// a caller-configurable cap and formats non-2xx bodies into its errors, so both
// the bound and the status classification have to happen here, above it.
// Failing a 3xx here also keeps the adapter on its one approved origin: Go
// strips only Authorization-style headers across hosts, so a followed redirect
// would carry the Exa key to whatever host the response named.
// The key is set here rather than through the MCP client's static-header option
// because the library's session-cleanup DELETE bypasses that option and would
// otherwise go out uncredentialed.
func boundedClient(base *http.Client, limit int, apiKey string) *http.Client {
	bounded := *base
	inner := bounded.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	bounded.Transport = &boundedTransport{inner: inner, limit: limit, apiKey: apiKey}
	return &bounded
}

type boundedTransport struct {
	inner  http.RoundTripper
	limit  int
	apiKey string
}

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.apiKey != "" {
		req = req.Clone(req.Context())
		req.Header.Set(apiKeyHeader, t.apiKey)
	}
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, errTransient
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		_ = resp.Body.Close()
		return nil, errRateLimited
	}
	if resp.StatusCode >= 500 {
		_ = resp.Body.Close()
		return nil, errTransient
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = resp.Body.Close()
		return nil, errSearchFailed
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(t.limit)+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, errTransient
	}
	if len(body) > t.limit {
		return nil, errResponseTooLarge
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}
