// No-network regression test: a full headless session against a stubbed provider
// must make no HTTP dial to any host other than the configured provider
// (Testing Requirements). It guards the transport injected through the
// provider-client construction seam and fails on any non-allowlisted dial.
package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"codemeld.dev/codemeld/internal/model"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/webresearch"
	"codemeld.dev/codemeld/internal/webresearch/exa"
)

// sseStream renders the chunk payloads as a complete chat-completions SSE body
// (each chunk as one data: event, terminated by data: [DONE]), the shape
// openai-go's streaming decoder consumes over the wire.
func sseStream(chunks ...[]byte) string {
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString("data: ")
		b.Write(c)
		b.WriteString("\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

func TestNoNetwork_EnabledWebResearchIdleStartupDialsNoWebHost(t *testing.T) {
	guard := &recordingTransport{respond: func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("no-network test: rejected a web-research dial")
	}}
	var built atomic.Int64
	defer swapSearchBackend(func(cfg exa.Config) webresearch.SearchBackend {
		built.Add(1)
		if cfg.HTTPClient == nil {
			t.Error("the search adapter was built without an HTTP client")
			return nil
		}
		cfg.HTTPClient = &http.Client{Transport: guard}
		backend, err := exa.New(cfg)
		if err != nil {
			t.Errorf("exa.New with the production configuration: %v", err)
			return nil
		}
		return backend
	})()

	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	handoff, err := defaultBuildToolRegistry(nil)
	if err != nil {
		t.Fatalf("defaultBuildToolRegistry: %v", err)
	}
	result := &BootstrapResult{
		Home:         t.TempDir(),
		LaunchDir:    "/launch",
		Session:      mkStore(t),
		Model:        model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		ToolRegistry: handoff,
		Config: map[string]any{
			"web_research": map[string]any{"enabled": true, "timeout_seconds": 5},
		},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}
	if got := built.Load(); got != 1 {
		t.Fatalf("search adapters built = %d, want exactly 1 (enabled registration must wire the search backend)", got)
	}
	if got := guard.count(); got != 0 {
		t.Fatalf("web-research requests at idle startup = %d (%v), want 0", got, guard.sent())
	}
}

// TestNoNetwork_FullSessionDialsOnlyConfiguredProvider pins / the
// Testing Requirement: a complete headless session with a stubbed
// provider attempts no HTTP dial to any host other than the configured provider.
//
// It runs the production launch (StartTUI assembly + the wired submit/turn
// path) against an httptest TLS stub provider, injecting a guarded *http.Client
// through the provider-client construction seam (newTurnProviderClient → the
// real provider.NewClient) whose transport DialContext rejects and counts any
// dial outside the stub provider's host:port allowlist. A plain prompt submitted
// through the assembled app issues a real streaming provider.ChatCompletion over
// that guarded client; the test asserts the turn completes, the stub provider
// received the streaming request, the session holds the expected turn/response
// records, and zero non-allowlisted dials occurred.
//
// Known limitation: the guard observes only dials made through the
// injected HTTP client; raw net.Dial, DNS-only lookups, and libraries that bypass
// the configured transport are out of scope for phase 1.
func TestNoNetwork_FullSessionDialsOnlyConfiguredProvider(t *testing.T) {
	// Stub provider (no real network beyond loopback): record that the streaming
	// chat-completions endpoint was reached and serve a complete SSE turn.
	var reachedChatCompletions, sawStreamRequest atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/chat/completions") {
			reachedChatCompletions.Store(true)
		}
		if body, _ := io.ReadAll(r.Body); strings.Contains(string(body), `"stream":true`) {
			sawStreamRequest.Store(true)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sseStream(contentChunk("Hel"), contentChunk("lo"), finishChunk("stop")))
	}))
	defer srv.Close()

	// Guarded HTTP client: trusts the stub's self-signed cert (cloned from the
	// server's own client transport) but rejects and counts any dial whose addr is
	// not the stub provider's host:port. This is the transport DialContext
	// guard installed in test setup.
	allow := srv.Listener.Addr().String()
	transport := srv.Client().Transport.(*http.Transport).Clone()
	realDial := (&net.Dialer{}).DialContext
	var rejectedDials, allowedDials atomic.Int64
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != allow {
			rejectedDials.Add(1)
			return nil, fmt.Errorf("no-network test: rejected dial to %q (allowlist %q)", addr, allow)
		}
		allowedDials.Add(1)
		return realDial(ctx, network, addr)
	}
	guarded := &http.Client{Transport: transport}

	// Inject the guarded client through the provider-client construction seam:
	// the test still builds the real provider.Client (so the real openai-go
	// transport dials the stub), only routed through the guard.
	defer swapTurnProviderClient(func(cfg provider.ClientConfig) provider.Client {
		cfg.HTTPClient = guarded
		return provider.NewClient(cfg)
	})()

	// Join the background turn goroutine so the session store is read only after
	// the turn has finished writing to it.
	var turns sync.WaitGroup
	defer swapGoTurn(waitableGoTurn(&turns))()

	// Capture the assembled app without starting a real terminal event loop.
	var ran *tui.App
	defer swapRunApp(func(a *tui.App) error { ran = a; return nil })()

	store := mkStore(t)
	result := &BootstrapResult{
		Home:      t.TempDir(),
		LaunchDir: "/launch",
		Session:   store,
		Model:     model.NewActiveState(&model.Selection{Provider: "openai", ID: "gpt-5.5", Effort: model.EffortDefault}, model.SourceProject),
		Config: map[string]any{
			"provider": map[string]any{
				"openai": map[string]any{
					"base_url": srv.URL, // the only allowlisted destination
					"api_key":  "sk-test",
					"models":   []string{"gpt-5.5"},
				},
			},
		},
	}
	if err := StartTUI(context.Background(), result, io.Discard); err != nil {
		t.Fatalf("StartTUI error: %v", err)
	}
	if ran == nil {
		t.Fatal("StartTUI did not run the event loop (runApp not invoked)")
	}

	if !ran.SubmitInput("hello there") {
		t.Fatal("wired submit rejected a plain prompt; the full-session turn path is not wired")
	}
	turns.Wait()

	// The provider request must have traveled through the guarded transport, otherwise
	// rejectedDials == 0 is vacuous: a bypassed guard (default client reaching the stub)
	// would also leave it zero. Assert the guard observed the allowlisted dial first.
	if got := allowedDials.Load(); got == 0 {
		t.Fatal("guarded transport observed no allowlisted dial; the provider request bypassed the guard, making rejectedDials == 0 meaningless")
	}
	// Done-when 2 /: no dial reached any host other than the configured provider.
	if got := rejectedDials.Load(); got != 0 {
		t.Fatalf("rejected (non-allowlisted) dials = %d, want 0", got)
	}
	// Done-when 1: the full session ran against the stubbed provider — the streaming
	// chat-completions request reached the stub.
	if !reachedChatCompletions.Load() {
		t.Fatal("stub provider never received a /chat/completions request; the turn did not dial the configured provider")
	}
	if !sawStreamRequest.Load() {
		t.Fatal("stub provider did not receive a streaming request (no \"stream\":true in body)")
	}

	// The session holds the expected turn/response records: the durable user input,
	// the streamed assistant reply, and the model_turn / model_response events.
	if got := userMessageCount(store); got != 1 {
		t.Fatalf("persisted user messages = %d, want 1 (persist-before-dispatch)", got)
	}
	var assistant []sessions.Message
	for _, rec := range store.Records() {
		if m, ok := rec.(sessions.Message); ok && m.Role == "assistant" {
			assistant = append(assistant, m)
		}
	}
	if len(assistant) != 1 {
		t.Fatalf("assistant messages = %d, want 1 after a completed streamed turn", len(assistant))
	}
	if got := assistant[0].Content.Text(); got != "Hello" {
		t.Fatalf("assistant reply = %q, want %q (streamed deltas must assemble in order)", got, "Hello")
	}
	kinds := eventKinds(store.Records())
	for _, want := range []string{"model_turn", "model_response"} {
		if !slices.Contains(kinds, want) {
			t.Fatalf("missing %q event after a completed turn; kinds = %v", want, kinds)
		}
	}
}
