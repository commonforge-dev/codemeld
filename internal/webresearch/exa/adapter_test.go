package exa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const (
	testOutputCap = 256
	testBodyCap   = 2 * testOutputCap
	testKey       = "exa-secret-key-value"
	sessionHeader = "Mcp-Session-Id"
	testSessionID = "exa-session-1"
)

type recorded struct {
	httpMethod string
	rpcMethod  string
	params     json.RawMessage
	header     http.Header
	url        string
}

// fixture answers the MCP Streamable-HTTP flow in process. toolReply overrides
// the tools/call answer so a test can inject a status, an oversized body, or a
// transport failure without reaching a network.
type fixture struct {
	seen        []recorded
	searchOut   string
	initStatus  int
	toolReply   func(id json.RawMessage) (*http.Response, error)
	deleteFails bool
}

func (f *fixture) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := recorded{httpMethod: req.Method, header: req.Header.Clone(), url: req.URL.String()}
	var rpc struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Params json.RawMessage `json:"params"`
	}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &rpc)
	}
	rec.rpcMethod, rec.params = rpc.Method, rpc.Params
	f.seen = append(f.seen, rec)

	if f.deleteFails && req.Method == http.MethodDelete {
		return nil, errors.New("cleanup reset by mcp.exa.ai for key " + testKey)
	}
	switch rpc.Method {
	case "initialize":
		if f.initStatus != 0 {
			return jsonReply(f.initStatus, `{"error":"`+testKey+` over quota"}`), nil
		}
		resp := jsonReply(http.StatusOK, initializeBody(rpc.ID))
		resp.Header.Set(sessionHeader, testSessionID)
		return resp, nil
	case "notifications/initialized":
		return reply(http.StatusAccepted, "", ""), nil
	case "tools/call":
		if f.toolReply != nil {
			return f.toolReply(rpc.ID)
		}
		return jsonReply(http.StatusOK, toolBody(rpc.ID, f.searchOut)), nil
	}
	return jsonReply(http.StatusOK, "{}"), nil
}

func (f *fixture) rpcMethods() []string {
	var out []string
	for _, rec := range f.seen {
		if rec.rpcMethod != "" {
			out = append(out, rec.rpcMethod)
		}
	}
	return out
}

func (f *fixture) lifecycles() int {
	n := 0
	for _, rec := range f.seen {
		if rec.rpcMethod == "initialize" {
			n++
		}
	}
	return n
}

func (f *fixture) httpMethods(method string) int {
	n := 0
	for _, rec := range f.seen {
		if rec.httpMethod == method {
			n++
		}
	}
	return n
}

func reply(status int, contentType, body string) *http.Response {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func jsonReply(status int, body string) *http.Response {
	return reply(status, "application/json", body)
}

func initializeBody(id json.RawMessage) string {
	return envelope(id, map[string]any{
		"protocolVersion": mcp.LATEST_PROTOCOL_VERSION,
		"capabilities":    map[string]any{},
		"serverInfo":      map[string]any{"name": "exa", "version": "1"},
	})
}

func toolBody(id json.RawMessage, text string) string {
	return envelope(id, map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
	})
}

func envelope(id json.RawMessage, result map[string]any) string {
	if len(id) == 0 {
		id = json.RawMessage("1")
	}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func resultText(pad string) string {
	return "Title: Example\nURL: https://example.com/a\nText: hello" + pad
}

// toolBodyOfSize returns a well-formed tool reply of exactly size bytes whose
// labelled text parses into one candidate, so a rejected oversized body proves
// the bound fired rather than the parser.
func toolBodyOfSize(t *testing.T, id json.RawMessage, size int) string {
	t.Helper()
	base := len(toolBody(id, resultText("")))
	if size < base {
		t.Fatalf("size %d is below the %d-byte minimum reply", size, base)
	}
	body := toolBody(id, resultText(strings.Repeat("x", size-base)))
	if len(body) != size {
		t.Fatalf("built a %d-byte reply, want %d", len(body), size)
	}
	return body
}

func newTestBackend(t *testing.T, apiKey string, f *fixture) *Backend {
	t.Helper()
	b, err := New(Config{
		APIKey:         apiKey,
		MaxResults:     5,
		Timeout:        5 * time.Second,
		MaxOutputBytes: testOutputCap,
		HTTPClient:     &http.Client{Transport: f},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestSearchEmptyKeySendsNoCredentialHeader(t *testing.T) {
	f := &fixture{searchOut: resultText("")}
	got, err := newTestBackend(t, "", f).Search(context.Background(), "example")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].URL != "https://example.com/a" {
		t.Fatalf("candidates = %+v", got)
	}
	if len(f.seen) == 0 {
		t.Fatal("no request reached the fixture")
	}
	for _, rec := range f.seen {
		if len(rec.header.Values(apiKeyHeader)) != 0 {
			t.Errorf("%s carried a credential header", rec.rpcMethod)
		}
		if rec.header.Get("Authorization") != "" {
			t.Errorf("%s carried an Authorization header", rec.rpcMethod)
		}
	}
}

func TestSearchConfiguredKeySendsOnlyAPIKeyHeader(t *testing.T) {
	f := &fixture{searchOut: resultText("")}
	got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, rec := range f.seen {
		values := rec.header.Values(apiKeyHeader)
		if len(values) != 1 || values[0] != testKey {
			t.Errorf("%s sent %v for %s", rec.rpcMethod, values, apiKeyHeader)
		}
		if rec.header.Get("Authorization") != "" {
			t.Errorf("%s carried an Authorization header", rec.rpcMethod)
		}
		if strings.Contains(rec.url, testKey) {
			t.Errorf("%s put the key in its URL", rec.rpcMethod)
		}
	}
	for _, candidate := range got {
		if strings.Contains(candidate.Title+candidate.URL+candidate.Snippet+candidate.PublishedDate, testKey) {
			t.Error("a candidate carried the key")
		}
	}
}

func TestSearchRedactsTheConfiguredKeyFromASuccessfulResult(t *testing.T) {
	f := &fixture{searchOut: "Title: " + testKey + " report\n" +
		"URL: https://example.com/?token=" + testKey + "\n" +
		"Published Date: 2026-01-02\n" +
		"Text: the key is " + testKey + " verbatim"}
	got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("candidates = %+v", got)
	}
	c := got[0]
	for field, value := range map[string]string{
		"Title": c.Title, "URL": c.URL, "Snippet": c.Snippet, "PublishedDate": c.PublishedDate,
	} {
		if strings.Contains(value, testKey) {
			t.Errorf("candidate %s carried the key: %q", field, value)
		}
	}
	if !strings.Contains(c.Title, "report") || !strings.Contains(c.Snippet, "verbatim") || c.PublishedDate != "2026-01-02" {
		t.Errorf("redaction dropped surrounding result text: %+v", c)
	}
}

// The MCP library sends its session-cleanup DELETE through the raw HTTP client
// rather than the request path its static-header option covers, so the keyed and
// keyless rules have to be asserted on that request too.
func TestSearchSessionCleanupFollowsTheCredentialRules(t *testing.T) {
	for name, key := range map[string]string{"configured key": testKey, "empty key": ""} {
		t.Run(name, func(t *testing.T) {
			f := &fixture{searchOut: resultText("")}
			if _, err := newTestBackend(t, key, f).Search(context.Background(), "example"); err != nil {
				t.Fatalf("Search: %v", err)
			}
			var cleanup []recorded
			for _, rec := range f.seen {
				if rec.httpMethod == http.MethodDelete {
					cleanup = append(cleanup, rec)
				}
			}
			if len(cleanup) != 1 {
				t.Fatalf("cleanup DELETE count = %d, want 1", len(cleanup))
			}
			rec := cleanup[0]
			if got := rec.header.Get(sessionHeader); got != testSessionID {
				t.Errorf("cleanup DELETE session = %q, want %q", got, testSessionID)
			}
			values := rec.header.Values(apiKeyHeader)
			switch {
			case key == "" && len(values) != 0:
				t.Errorf("cleanup DELETE carried %v for %s", values, apiKeyHeader)
			case key != "" && (len(values) != 1 || values[0] != key):
				t.Errorf("cleanup DELETE sent %v for %s", values, apiKeyHeader)
			}
			if rec.url != endpoint {
				t.Errorf("cleanup DELETE went to %s", rec.url)
			}
		})
	}
}

func TestSearchFailureWithConfiguredKeyOmitsTheKey(t *testing.T) {
	for name, reply := range map[string]func(json.RawMessage) (*http.Response, error){
		"rate limited": func(json.RawMessage) (*http.Response, error) {
			return jsonReply(http.StatusTooManyRequests, `{"error":"key `+testKey+` over quota"}`), nil
		},
		"server error": func(json.RawMessage) (*http.Response, error) {
			return jsonReply(http.StatusInternalServerError, `{"error":"key `+testKey+` rejected"}`), nil
		},
		"transport error": func(json.RawMessage) (*http.Response, error) {
			return nil, errors.New("dial tcp mcp.exa.ai:443: refused for key " + testKey)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fixture{toolReply: reply}
			got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
			if got != nil {
				t.Errorf("candidates = %+v", got)
			}
			if err == nil {
				t.Fatal("want an error")
			}
			assertBounded(t, err)
		})
	}
}

func assertBounded(t *testing.T, err error) {
	t.Helper()
	for _, leak := range []string{testKey, apiKeyHeader, "mcp.exa.ai", "https://", "dial tcp", "quota", "rejected"} {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(leak)) {
			t.Errorf("error %q leaked %q", err, leak)
		}
	}
}

func TestSearchPerformsOnlyTheRequiredLifecycleAndOneSearchCall(t *testing.T) {
	f := &fixture{searchOut: resultText("")}
	if _, err := newTestBackend(t, "", f).Search(context.Background(), "example"); err != nil {
		t.Fatalf("Search: %v", err)
	}
	want := []string{"initialize", "notifications/initialized", "tools/call"}
	got := f.rpcMethods()
	if len(got) != len(want) {
		t.Fatalf("rpc methods = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rpc methods = %v, want %v", got, want)
		}
	}
	for _, rec := range f.seen {
		if rec.url != endpoint {
			t.Errorf("%s went to %s", rec.rpcMethod, rec.url)
		}
	}
	var params struct {
		Name      string `json:"name"`
		Arguments struct {
			Query      string `json:"query"`
			NumResults int    `json:"numResults"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(f.seen[2].params, &params); err != nil {
		t.Fatalf("tools/call params: %v", err)
	}
	if params.Name != searchTool {
		t.Errorf("called tool %q, want %q", params.Name, searchTool)
	}
	if params.Arguments.Query != "example" || params.Arguments.NumResults != 5 {
		t.Errorf("arguments = %+v", params.Arguments)
	}
}

func TestSearchRejectsAnOversizedResponseBeforeParsing(t *testing.T) {
	// Each oversized body holds text that parses into a candidate, so a returned
	// size error can only mean the bound fired ahead of the parser.
	cases := map[string]struct {
		size        int
		contentType string
		wantErr     error
	}{
		"exactly at the cap":        {size: testBodyCap, contentType: "application/json"},
		"one byte over the cap":     {size: testBodyCap + 1, contentType: "application/json", wantErr: errResponseTooLarge},
		"one byte over as an event": {size: testBodyCap + 1, contentType: "text/event-stream", wantErr: errResponseTooLarge},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fixture{toolReply: func(id json.RawMessage) (*http.Response, error) {
				body := toolBodyOfSize(t, id, tc.size)
				if tc.contentType == "text/event-stream" {
					body = "event: message\ndata: " + body + "\n\n"
				}
				return reply(http.StatusOK, tc.contentType, body), nil
			}}
			got, err := newTestBackend(t, "", f).Search(context.Background(), "example")
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Search: %v", err)
				}
				if len(got) != 1 || got[0].URL != "https://example.com/a" {
					t.Fatalf("candidates = %+v", got)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("candidates = %+v", got)
			}
			assertBounded(t, err)
		})
	}
}

func TestSearchMapsRateLimitAndGenericFailures(t *testing.T) {
	cases := map[string]struct {
		reply   func(json.RawMessage) (*http.Response, error)
		wantErr error
	}{
		"rate limited": {
			reply:   func(json.RawMessage) (*http.Response, error) { return jsonReply(429, `{"error":"slow down"}`), nil },
			wantErr: errRateLimited,
		},
		"forbidden": {
			reply:   func(json.RawMessage) (*http.Response, error) { return jsonReply(403, `{"error":"forbidden"}`), nil },
			wantErr: errSearchFailed,
		},
		"server error": {
			reply:   func(json.RawMessage) (*http.Response, error) { return jsonReply(500, `{"error":"boom"}`), nil },
			wantErr: errSearchFailed,
		},
		"transport failure": {
			reply:   func(json.RawMessage) (*http.Response, error) { return nil, errors.New("connection reset") },
			wantErr: errSearchFailed,
		},
		"mcp error": {
			reply: func(id json.RawMessage) (*http.Response, error) {
				return jsonReply(200, `{"jsonrpc":"2.0","id":`+string(id)+`,"error":{"code":-32602,"message":"bad tool"}}`), nil
			},
			wantErr: errSearchFailed,
		},
		"tool error result": {
			reply: func(id json.RawMessage) (*http.Response, error) {
				return jsonReply(200, `{"jsonrpc":"2.0","id":`+string(id)+
					`,"result":{"isError":true,"content":[{"type":"text","text":"upstream refused"}]}}`), nil
			},
			wantErr: errSearchFailed,
		},
		"unusable text": {
			reply: func(id json.RawMessage) (*http.Response, error) {
				return jsonReply(200, toolBody(id, "Title: no url here")), nil
			},
			wantErr: errNoCandidates,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fixture{toolReply: tc.reply}
			got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("candidates = %+v", got)
			}
			assertBounded(t, err)
			for _, leak := range []string{"slow down", "forbidden", "boom", "connection reset", "bad tool", "upstream refused", "no url here"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error %q leaked provider text %q", err, leak)
				}
			}
		})
	}
}

// A 429 on initialize travels a different unwrap chain than one on tools/call,
// so the Exa-limit outcome has to survive both.
func TestSearchRateLimitOnInitializeIsBounded(t *testing.T) {
	f := &fixture{initStatus: http.StatusTooManyRequests}
	got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
	if !errors.Is(err, errRateLimited) {
		t.Fatalf("err = %v, want %v", err, errRateLimited)
	}
	if got != nil {
		t.Errorf("candidates = %+v", got)
	}
	assertBounded(t, err)
	if methods := f.rpcMethods(); len(methods) != 1 || methods[0] != "initialize" {
		t.Errorf("rpc methods = %v, want only initialize", methods)
	}
}

type countingBody struct {
	reader *strings.Reader
	read   int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.read += n
	return n, err
}

func (c *countingBody) Close() error { return nil }

func TestSearchDoesNotReadANonSuccessBody(t *testing.T) {
	for name, status := range map[string]int{
		"rate limited": http.StatusTooManyRequests,
		"server error": http.StatusInternalServerError,
	} {
		t.Run(name, func(t *testing.T) {
			body := &countingBody{reader: strings.NewReader(`{"error":"` + testKey + ` details"}`)}
			f := &fixture{toolReply: func(json.RawMessage) (*http.Response, error) {
				resp := jsonReply(status, "")
				resp.Body = body
				return resp, nil
			}}
			if _, err := newTestBackend(t, testKey, f).Search(context.Background(), "example"); err == nil {
				t.Fatal("want an error")
			}
			if body.read != 0 {
				t.Errorf("read %d bytes of the provider error body", body.read)
			}
		})
	}
}

func TestSearchDoesNotFollowARedirectOffTheApprovedOrigin(t *testing.T) {
	f := &fixture{toolReply: func(json.RawMessage) (*http.Response, error) {
		resp := reply(http.StatusFound, "", "")
		resp.Header.Set("Location", "https://attacker.example/collect")
		return resp, nil
	}}
	got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
	if !errors.Is(err, errSearchFailed) {
		t.Fatalf("err = %v, want %v", err, errSearchFailed)
	}
	if got != nil {
		t.Errorf("candidates = %+v", got)
	}
	for _, rec := range f.seen {
		if rec.url != endpoint {
			t.Errorf("request went to %s", rec.url)
		}
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }

func (failingBody) Close() error { return nil }

func TestSearchBoundsAFailedBodyRead(t *testing.T) {
	f := &fixture{toolReply: func(json.RawMessage) (*http.Response, error) {
		resp := jsonReply(http.StatusOK, "")
		resp.Body = failingBody{}
		return resp, nil
	}}
	got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
	if !errors.Is(err, errSearchFailed) {
		t.Fatalf("err = %v, want %v", err, errSearchFailed)
	}
	if got != nil {
		t.Errorf("candidates = %+v", got)
	}
	assertBounded(t, err)
}

func TestSearchReadsOnlyTextContent(t *testing.T) {
	f := &fixture{toolReply: func(id json.RawMessage) (*http.Response, error) {
		return jsonReply(http.StatusOK, envelope(id, map[string]any{"content": []any{
			map[string]any{"type": "text", "text": "Title: First\nURL: https://example.com/a\n"},
			map[string]any{"type": "image", "data": "aGk=", "mimeType": "image/png"},
			map[string]any{"type": "text", "text": "---\n\nTitle: Second\nURL: https://example.com/b"},
		}})), nil
	}}
	got, err := newTestBackend(t, "", f).Search(context.Background(), "example")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 2 || got[0].URL != "https://example.com/a" || got[1].URL != "https://example.com/b" {
		t.Fatalf("candidates = %+v", got)
	}
	if got[0].Title != "First" || got[1].Title != "Second" {
		t.Errorf("candidates = %+v", got)
	}
}

func TestSearchRejectsAnEmptyQuery(t *testing.T) {
	f := &fixture{searchOut: resultText("")}
	if _, err := newTestBackend(t, "", f).Search(context.Background(), "   "); !errors.Is(err, errEmptyQuery) {
		t.Fatalf("err = %v, want %v", err, errEmptyQuery)
	}
	if len(f.seen) != 0 {
		t.Errorf("an empty query reached the network: %v", f.rpcMethods())
	}
}

func captureTerminal(t *testing.T) func() string {
	t.Helper()
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))

	prevOut, prevErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout, os.Stderr = w, w
	written := make(chan string, 1)
	go func() {
		raw, _ := io.ReadAll(r)
		written <- string(raw)
	}()

	return func() string {
		slog.SetDefault(prev)
		os.Stdout, os.Stderr = prevOut, prevErr
		_ = w.Close()
		out := <-written
		_ = r.Close()
		return logged.String() + out
	}
}

func TestSearchCleanupFailureIsSilentAndKeepsTheResult(t *testing.T) {
	f := &fixture{searchOut: resultText(""), deleteFails: true}
	b := newTestBackend(t, testKey, f)

	drain := captureTerminal(t)
	got, err := b.Search(context.Background(), "example")
	output := drain()

	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].URL != "https://example.com/a" {
		t.Fatalf("candidates = %+v, want the successful result despite the failed cleanup", got)
	}
	if output != "" {
		t.Errorf("a failed cleanup wrote %q to the terminal", output)
	}
	if n := f.lifecycles(); n != 1 {
		t.Errorf("lifecycles = %d, want 1 (a cleanup failure is never retried)", n)
	}
	if n := f.httpMethods(http.MethodDelete); n != 1 {
		t.Errorf("cleanup DELETEs = %d, want 1", n)
	}
}

func TestSearchRetriesATransientFailureExactlyOnce(t *testing.T) {
	cases := map[string]func(json.RawMessage) (*http.Response, error){
		"transport failure": func(json.RawMessage) (*http.Response, error) {
			return nil, errors.New("dial tcp mcp.exa.ai:443: connection reset for key " + testKey)
		},
		"server error": func(json.RawMessage) (*http.Response, error) {
			return jsonReply(http.StatusInternalServerError, `{"error":"key `+testKey+` boom"}`), nil
		},
	}
	for name, failFirst := range cases {
		t.Run(name+" then success", func(t *testing.T) {
			attempt := 0
			f := &fixture{toolReply: func(id json.RawMessage) (*http.Response, error) {
				attempt++
				if attempt == 1 {
					return failFirst(id)
				}
				return jsonReply(http.StatusOK, toolBody(id, resultText(""))), nil
			}}
			got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			if len(got) != 1 || got[0].URL != "https://example.com/a" {
				t.Fatalf("candidates = %+v, want the second attempt's result", got)
			}
			// Each retry must create a fresh lifecycle.
			want := []string{
				"initialize", "notifications/initialized", "tools/call",
				"initialize", "notifications/initialized", "tools/call",
			}
			if got := f.rpcMethods(); !slices.Equal(got, want) {
				t.Fatalf("rpc methods = %v, want two complete lifecycles %v", got, want)
			}
			if n := f.httpMethods(http.MethodDelete); n != 2 {
				t.Errorf("cleanup DELETEs = %d, want one per lifecycle", n)
			}
		})

		t.Run(name+" twice", func(t *testing.T) {
			f := &fixture{toolReply: failFirst}
			got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
			if !errors.Is(err, errSearchFailed) {
				t.Fatalf("err = %v, want %v", err, errSearchFailed)
			}
			if got != nil {
				t.Errorf("candidates = %+v", got)
			}
			assertBounded(t, err)
			if n := f.lifecycles(); n != 2 {
				t.Fatalf("lifecycles = %d, want exactly 2 (one bounded retry, never a third attempt)", n)
			}
		})
	}
}

func TestSearchDoesNotRetryANonTransientFailure(t *testing.T) {
	oversized := func(t *testing.T) func(json.RawMessage) (*http.Response, error) {
		return func(id json.RawMessage) (*http.Response, error) {
			return jsonReply(http.StatusOK, toolBodyOfSize(t, id, testBodyCap+1)), nil
		}
	}
	cases := map[string]struct {
		reply   func(t *testing.T) func(json.RawMessage) (*http.Response, error)
		wantErr error
	}{
		"rate limited": {
			reply: func(*testing.T) func(json.RawMessage) (*http.Response, error) {
				return func(json.RawMessage) (*http.Response, error) {
					return jsonReply(http.StatusTooManyRequests, `{"error":"key `+testKey+` over quota"}`), nil
				}
			},
			wantErr: errRateLimited,
		},
		"unauthorized": {
			reply: func(*testing.T) func(json.RawMessage) (*http.Response, error) {
				return func(json.RawMessage) (*http.Response, error) {
					return jsonReply(http.StatusUnauthorized, `{"error":"key `+testKey+` rejected"}`), nil
				}
			},
			wantErr: errSearchFailed,
		},
		"forbidden": {
			reply: func(*testing.T) func(json.RawMessage) (*http.Response, error) {
				return func(json.RawMessage) (*http.Response, error) {
					return jsonReply(http.StatusForbidden, `{"error":"forbidden"}`), nil
				}
			},
			wantErr: errSearchFailed,
		},
		"malformed protocol response": {
			reply: func(*testing.T) func(json.RawMessage) (*http.Response, error) {
				return func(id json.RawMessage) (*http.Response, error) {
					return jsonReply(http.StatusOK, `{"jsonrpc":"2.0","id":`+string(id)+
						`,"error":{"code":-32602,"message":"bad tool"}}`), nil
				}
			},
			wantErr: errSearchFailed,
		},
		"unparseable result text": {
			reply: func(*testing.T) func(json.RawMessage) (*http.Response, error) {
				return func(id json.RawMessage) (*http.Response, error) {
					return jsonReply(http.StatusOK, toolBody(id, "Title: no url here")), nil
				}
			},
			wantErr: errNoCandidates,
		},
		"oversized response": {reply: oversized, wantErr: errResponseTooLarge},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fixture{toolReply: tc.reply(t)}
			got, err := newTestBackend(t, testKey, f).Search(context.Background(), "example")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("candidates = %+v", got)
			}
			assertBounded(t, err)
			if n := f.lifecycles(); n != 1 {
				t.Fatalf("lifecycles = %d, want 1 (%s is not retryable)", n, name)
			}
		})
	}
}

func TestNewRejectsAnIncompleteConfig(t *testing.T) {
	full := Config{MaxResults: 5, Timeout: time.Second, MaxOutputBytes: testOutputCap, HTTPClient: &http.Client{}}
	cases := map[string]func(*Config){
		"no client":     func(c *Config) { c.HTTPClient = nil },
		"no results":    func(c *Config) { c.MaxResults = 0 },
		"no timeout":    func(c *Config) { c.Timeout = 0 },
		"no output cap": func(c *Config) { c.MaxOutputBytes = 0 },
		"undoubleable output cap": func(c *Config) {
			c.MaxOutputBytes = math.MaxInt/2 + 1
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := full
			breakIt(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	t.Run("largest doubleable output cap", func(t *testing.T) {
		cfg := full
		cfg.MaxOutputBytes = math.MaxInt / 2
		if _, err := New(cfg); err != nil {
			t.Fatalf("New: %v", err)
		}
	})
}

func TestNewDoesNotMutateTheCallerClient(t *testing.T) {
	f := &fixture{}
	caller := &http.Client{Transport: f}
	if _, err := New(Config{MaxResults: 5, Timeout: time.Second, MaxOutputBytes: testOutputCap, HTTPClient: caller}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if caller.Transport != http.RoundTripper(f) {
		t.Error("New replaced the caller's transport")
	}
}
