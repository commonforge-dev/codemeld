package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/webresearch"
	"codemeld.dev/codemeld/internal/webresearch/exa"
)

func TestProductionDispatcher_RegisteredWebToolFailsClosedBeforeAuthorization(t *testing.T) {
	reg := webResearchRegistry(t, map[string]any{"enabled": true})
	auth := &recordingAuthorizer{decision: allow()}
	run := &fakeDispatchRunner{}
	d := dispatcherFor(t, reg, run, auth)

	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{webSearchToolName, map[string]any{"query": "codemeld"}},
		{webFetchToolName, map[string]any{"url": "https://example.com"}},
	} {
		res, err := d.Dispatch(context.Background(), structuredCall("c1", tc.name, tc.args))
		if err != nil {
			t.Fatalf("Dispatch(%s) error = %v, want nil (the unavailable result is in-band)", tc.name, err)
		}
		if res.Denied {
			t.Fatalf("Dispatch(%s) returned a deny envelope, want a plain unavailable result", tc.name)
		}
		if res.Content != errWebResearchUnavailable.Error() {
			t.Fatalf("Dispatch(%s) content = %q, want %q", tc.name, res.Content, errWebResearchUnavailable.Error())
		}
	}
	if auth.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, want 0 (a schema-only web tool must not reach authorization)", auth.callCount())
	}
	if run.callCount() != 0 {
		t.Fatalf("runner calls = %d, want 0 (a schema-only web tool must not execute anything)", run.callCount())
	}
}

func TestProductionDispatcher_UnregisteredWebToolCallStaysUnknownTool(t *testing.T) {
	reg := webResearchRegistry(t, map[string]any{"enabled": false})
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, reg, &fakeDispatchRunner{}, auth)

	res, err := d.Dispatch(context.Background(), structuredCall("c1", webSearchToolName, map[string]any{"query": "codemeld"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if !strings.Contains(res.Content, "no_such_tool: "+webSearchToolName) {
		t.Fatalf("content = %q, want the ordinary no_such_tool result", res.Content)
	}
	if strings.Contains(res.Content, errWebResearchUnavailable.Error()) {
		t.Fatalf("content = %q, want no web-research unavailable result for an unregistered name", res.Content)
	}
	if auth.callCount() != 0 {
		t.Fatalf("authorizer calls = %d, want 0", auth.callCount())
	}
}

func TestProductionDispatcher_SameNameNonPlaceholderToolKeepsGenericDispatch(t *testing.T) {
	reg := tools.NewRegistry()
	tool := &stubStructuredTool{name: webSearchToolName, result: tools.Result{Stdout: []byte("out\n")}}
	if err := reg.Register("src", tool); err != nil {
		t.Fatalf("Register: %v", err)
	}
	auth := &recordingAuthorizer{decision: allow()}
	d := dispatcherFor(t, reg, &fakeDispatchRunner{}, auth)

	res, err := d.Dispatch(context.Background(), structuredCall("c1", webSearchToolName, map[string]any{"query": "codemeld"}))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Content != "out" {
		t.Fatalf("content = %q, want the registered tool's output", res.Content)
	}
	if auth.callCount() != 1 || tool.callCount() != 1 {
		t.Fatalf("authorizer calls = %d, tool calls = %d, want 1 and 1", auth.callCount(), tool.callCount())
	}
}

func textResponse(mediaType, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{mediaType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func redirectResponse(location string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{location}},
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

func webFetchDispatcher(t *testing.T, auth dispatch.Authorizer, tr http.RoundTripper, outputCap int) *productionToolDispatcher {
	t.Helper()
	store := mkStore(t)
	d := newProductionToolDispatcher(webResearchRegistry(t, map[string]any{"enabled": true}), &fakeDispatchRunner{}, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, outputCap, securitystate.Policy{})

	d.setWebFetch(config.WebResearchSettings{Enabled: true, TimeoutSeconds: 5})
	if d.fetchClient == nil {
		t.Fatal("setWebFetch left the fetch client nil for an enabled, positively configured timeout")
	}
	d.fetchClient.Transport = tr
	return d
}

func TestProductionDispatcher_SetWebFetchBindsConfiguredTimeoutOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings config.WebResearchSettings
		want     time.Duration
	}{
		{"configured timeout", config.WebResearchSettings{Enabled: true, TimeoutSeconds: 7}, 7 * time.Second},
		{"default timeout", config.WebResearchSettings{Enabled: true, TimeoutSeconds: 20}, 20 * time.Second},
		{"disabled", config.WebResearchSettings{TimeoutSeconds: 7}, 0},
		{"zero timeout", config.WebResearchSettings{Enabled: true}, 0},
		{"negative timeout", config.WebResearchSettings{Enabled: true, TimeoutSeconds: -3}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &recordingAuthorizer{decision: allow()}
			tr := scriptedTransport(map[string]*http.Response{})
			store := mkStore(t)
			d := newProductionToolDispatcher(webResearchRegistry(t, map[string]any{"enabled": true}), &fakeDispatchRunner{}, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})

			d.setWebFetch(tc.settings)

			if tc.want == 0 {
				if d.fetchClient != nil {
					t.Fatalf("fetch client = %+v, want none for %+v", d.fetchClient, tc.settings)
				}
				res, err := d.Dispatch(context.Background(), webFetchCall("https://docs.example.com/guide"))
				if err != nil {
					t.Fatalf("Dispatch error = %v, want nil", err)
				}
				if res.Content != errWebResearchUnavailable.Error() {
					t.Fatalf("content = %q, want the unavailable result while no fetch client is bound", res.Content)
				}
				if auth.callCount() != 0 || tr.count() != 0 {
					t.Fatalf("authorizer calls = %d, dials = %d, want 0 and 0", auth.callCount(), tr.count())
				}
				return
			}
			if d.fetchClient == nil {
				t.Fatalf("fetch client = nil, want one bound to %v", tc.want)
			}
			if d.fetchClient.Timeout != tc.want {
				t.Fatalf("fetch client timeout = %v, want the configured %v", d.fetchClient.Timeout, tc.want)
			}
		})
	}
}

func TestProductionDispatcher_SetWebFetchBuildsAGuardedDirectTransport(t *testing.T) {
	store := mkStore(t)
	d := newProductionToolDispatcher(webResearchRegistry(t, map[string]any{"enabled": true}), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})

	d.setWebFetch(config.WebResearchSettings{Enabled: true, TimeoutSeconds: 7})

	transport, ok := d.fetchClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("fetch transport = %T, want a cloned *http.Transport", d.fetchClient.Transport)
	}
	standard, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport = %T, want *http.Transport", http.DefaultTransport)
	}
	if standard.Proxy == nil {
		t.Fatal("the standard default transport has no proxy, so a nil Proxy no longer proves the fetch path is direct-only")
	}
	if transport.Proxy != nil {
		t.Fatal("fetch transport has a proxy, so a proxy could reach a destination the address guard never sees")
	}
	if got, want := reflect.ValueOf(transport.DialContext).Pointer(), reflect.ValueOf(webresearch.GuardedDialContext).Pointer(); got != want {
		t.Fatal("fetch transport does not dial through webresearch.GuardedDialContext")
	}
	for _, field := range []struct {
		name      string
		got, want any
	}{
		{"MaxIdleConns", transport.MaxIdleConns, standard.MaxIdleConns},
		{"MaxIdleConnsPerHost", transport.MaxIdleConnsPerHost, standard.MaxIdleConnsPerHost},
		{"IdleConnTimeout", transport.IdleConnTimeout, standard.IdleConnTimeout},
		{"TLSHandshakeTimeout", transport.TLSHandshakeTimeout, standard.TLSHandshakeTimeout},
		{"ExpectContinueTimeout", transport.ExpectContinueTimeout, standard.ExpectContinueTimeout},
		{"ForceAttemptHTTP2", transport.ForceAttemptHTTP2, standard.ForceAttemptHTTP2},
	} {
		if field.got != field.want {
			t.Fatalf("fetch transport %s = %v, want the cloned default %v", field.name, field.got, field.want)
		}
	}
	if d.fetchClient.Timeout != 7*time.Second {
		t.Fatalf("fetch client timeout = %v, want the configured 7s", d.fetchClient.Timeout)
	}
}

func TestGuardedFetchClient_FailsClosedWhenTheDefaultIsNotATransport(t *testing.T) {
	if client := guardedFetchClient(&recordingTransport{}, time.Second); client != nil {
		t.Fatalf("guardedFetchClient = %+v for a non-*http.Transport fallback, want no client rather than an unguarded one", client)
	}
}

func TestProductionDispatcher_FetchTransportDialRefusesALoopbackListener(t *testing.T) {
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := mkStore(t)
	d := newProductionToolDispatcher(webResearchRegistry(t, map[string]any{"enabled": true}), &fakeDispatchRunner{}, &recordingAuthorizer{decision: allow()}, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})
	d.setWebFetch(config.WebResearchSettings{Enabled: true, TimeoutSeconds: 7})

	transport, ok := d.fetchClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("fetch transport = %T, want a cloned *http.Transport", d.fetchClient.Transport)
	}
	conn, err := transport.DialContext(context.Background(), "tcp", strings.TrimPrefix(server.URL, "http://"))
	if err == nil {
		_ = conn.Close()
		t.Fatal("the production fetch transport connected to a loopback listener, want a refusal")
	}
	if got := served.Load(); got != 0 {
		t.Fatalf("loopback listener served %d requests, want 0", got)
	}
}

func TestProductionBindings_WireWebFetchFromConfiguredSettings(t *testing.T) {
	fset := token.NewFileSet()
	for _, tc := range []struct{ file, fn string }{
		{"starttui.go", "StartTUI"},
		{"headless.go", "Run"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			parsed, err := parser.ParseFile(fset, tc.file, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", tc.file, err)
			}
			wired := false
			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != tc.fn {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "setWebFetch" || len(call.Args) != 1 {
						return true
					}
					arg, ok := call.Args[0].(*ast.CallExpr)
					if !ok {
						return true
					}
					argSel, ok := arg.Fun.(*ast.SelectorExpr)
					if ok && argSel.Sel.Name == "WebResearch" {
						wired = true
					}
					return true
				})
			}
			if !wired {
				t.Fatalf("%s:%s does not call setWebFetch(cache.WebResearch()); the production binding would leave direct fetch unwired", tc.file, tc.fn)
			}
		})
	}
}

func TestProductionDispatcher_WebFetchAuthorizesEveryTargetBeforeDialing(t *testing.T) {
	tr := scriptedTransport(map[string]*http.Response{
		"https://docs.example.com/guide": redirectResponse("/v2"),
		"https://docs.example.com/v2":    redirectResponse("https://cdn.other.example/page"),
		"https://cdn.other.example/page": textResponse("text/plain; charset=utf-8", "the page body"),
	})
	auth := &hostAuthSpy{transport: tr}
	d := webFetchDispatcher(t, auth, tr, 65536)

	res, err := d.Dispatch(context.Background(), webFetchCall("https://docs.example.com/guide"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Denied {
		t.Fatalf("authorized fetch returned a deny envelope: %q", res.Content)
	}
	decoded := decodeFetchResult(t, res.Content, 65536)
	if decoded["outcome"] != "ok" || decoded["content"] != "the page body" {
		t.Fatalf("fetch result = %v, want the extracted page body with an ok outcome", decoded)
	}

	wantHosts := []string{"docs.example.com", "docs.example.com", "cdn.other.example"}
	if got := auth.hosts(); !reflect.DeepEqual(got, wantHosts) {
		t.Fatalf("authorized hosts = %v, want %v (every hop authorized on its own)", got, wantHosts)
	}
	for i, sent := range auth.dials {
		if sent != i {
			t.Fatalf("authorization %d ran after %d requests were sent, want %d — a target was dialed before it was authorized (sent: %v)", i, sent, i, tr.sent())
		}
	}
	wantURLs := []string{"https://docs.example.com/guide", "https://docs.example.com/v2", "https://cdn.other.example/page"}
	if got := tr.sent(); !reflect.DeepEqual(got, wantURLs) {
		t.Fatalf("requests = %v, want %v", got, wantURLs)
	}
	for i, req := range auth.reqs {
		if req.Kind != matchKindHost || req.Subject != webFetchToolName {
			t.Fatalf("authorization %d = kind %q subject %q, want an exact %q host request", i, req.Kind, req.Subject, webFetchToolName)
		}
		if req.FreshConfirmation {
			t.Fatalf("authorization %d asked for a fresh confirmation on a default-port https target", i)
		}
		if auth.displays[i].HostRequest != wantURLs[i] {
			t.Fatalf("authorization %d displayed request %q, want the display-safe target %q", i, auth.displays[i].HostRequest, wantURLs[i])
		}
		if auth.displays[i].DirectHTTPFallback {
			t.Fatalf("authorization %d disclosed an http fallback for an https target", i)
		}
		want := permissions.ModeContext{Class: permissions.ClassMutating, ToolName: webFetchToolName, NetworkEgress: true}
		if !reflect.DeepEqual(auth.modeCtxs[i], want) {
			t.Fatalf("authorization %d mode context = %+v, want %+v (network egress is never mode-auto-allowed)", i, auth.modeCtxs[i], want)
		}
	}
}

func TestProductionDispatcher_WebFetchTargetShapeDrivesConfirmationAndDisclosure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		url          string
		routes       map[string]*http.Response
		wantHostReq  string
		wantFresh    bool
		wantFallback bool
	}{
		{
			name:        "default https",
			url:         "https://docs.example.com/guide",
			routes:      map[string]*http.Response{"https://docs.example.com/guide": textResponse("text/plain", "ok body")},
			wantHostReq: "https://docs.example.com/guide",
		},
		{
			name:        "non-default port",
			url:         "https://docs.example.com:8443/guide",
			routes:      map[string]*http.Response{"https://docs.example.com:8443/guide": textResponse("text/plain", "ok body")},
			wantHostReq: "https://docs.example.com:8443/guide",
			wantFresh:   true,
		},
		{
			name:         "direct http falls back after the https attempt fails",
			url:          "http://docs.example.com/guide",
			routes:       map[string]*http.Response{"http://docs.example.com/guide": textResponse("text/plain", "ok body")},
			wantHostReq:  "http://docs.example.com/guide",
			wantFallback: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := scriptedTransport(tc.routes)
			auth := &hostAuthSpy{transport: tr}
			d := webFetchDispatcher(t, auth, tr, 65536)

			res, err := d.Dispatch(context.Background(), webFetchCall(tc.url))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if decoded := decodeFetchResult(t, res.Content, 65536); decoded["outcome"] != "ok" {
				t.Fatalf("fetch result = %v, want an ok outcome", decoded)
			}
			if len(auth.reqs) != 1 {
				t.Fatalf("authorizations = %d, want exactly one (the https-first attempt reuses the direct target's authorization)", len(auth.reqs))
			}
			if auth.reqs[0].FreshConfirmation != tc.wantFresh {
				t.Fatalf("fresh confirmation = %v, want %v", auth.reqs[0].FreshConfirmation, tc.wantFresh)
			}
			if auth.displays[0].HostRequest != tc.wantHostReq {
				t.Fatalf("displayed request = %q, want %q", auth.displays[0].HostRequest, tc.wantHostReq)
			}
			if auth.displays[0].DirectHTTPFallback != tc.wantFallback {
				t.Fatalf("http-fallback disclosure = %v, want %v", auth.displays[0].DirectHTTPFallback, tc.wantFallback)
			}
			if tc.wantFallback && tr.count() != 2 {
				t.Fatalf("requests = %v, want the failed https attempt then the plain http request", tr.sent())
			}
		})
	}
}

func TestProductionDispatcher_WebFetchDenialKeepsEnvelopeAndSendsNothing(t *testing.T) {
	envelope := permissions.BuildDenyEnvelope("")
	for _, tc := range []struct {
		name      string
		denied    map[string]string
		wantDials []string
	}{
		{
			name:      "initial target denied",
			denied:    map[string]string{"docs.example.com": envelope},
			wantDials: nil,
		},
		{
			name:      "redirect target denied",
			denied:    map[string]string{"cdn.other.example": envelope},
			wantDials: []string{"https://docs.example.com/guide"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := scriptedTransport(map[string]*http.Response{
				"https://docs.example.com/guide": redirectResponse("https://cdn.other.example/page"),
				"https://cdn.other.example/page": textResponse("text/plain", "secret page body"),
			})
			auth := &hostAuthSpy{transport: tr, denied: tc.denied}
			d := webFetchDispatcher(t, auth, tr, 65536)

			res, err := d.Dispatch(context.Background(), webFetchCall("https://docs.example.com/guide"))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil (a denial is in-band)", err)
			}
			if !res.Denied {
				t.Fatalf("result is not marked denied: %q", res.Content)
			}
			if res.Content != envelope {
				t.Fatalf("content = %q, want the unchanged deny envelope %q", res.Content, envelope)
			}
			if got := tr.sent(); !reflect.DeepEqual(got, tc.wantDials) {
				t.Fatalf("requests = %v, want %v (a denied target is never dialed)", got, tc.wantDials)
			}
			if strings.Contains(res.Content, "secret page body") {
				t.Fatalf("deny envelope leaked fetched content: %q", res.Content)
			}
		})
	}
}

func TestProductionDispatcher_WebFetchAuthorizationErrorAbortsTheTurn(t *testing.T) {
	tr := scriptedTransport(map[string]*http.Response{
		"https://docs.example.com/guide": textResponse("text/plain", "body"),
	})
	auth := &hostAuthSpy{transport: tr, err: context.Canceled}
	d := webFetchDispatcher(t, auth, tr, 65536)

	res, err := d.Dispatch(context.Background(), webFetchCall("https://docs.example.com/guide"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dispatch error = %v, want the authorization failure", err)
	}
	if res.Content != "" {
		t.Fatalf("content = %q, want none for an internal authorization failure", res.Content)
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %v, want none", tr.sent())
	}
}

func TestProductionDispatcher_WebFetchReturnsCompleteJSONAtEveryCap(t *testing.T) {
	for _, outputCap := range []int{256, 1024, 65536} {
		t.Run(fmt.Sprintf("cap %d", outputCap), func(t *testing.T) {
			body := strings.Repeat("readable page text ", 2*outputCap/19)
			tr := scriptedTransport(map[string]*http.Response{
				"https://docs.example.com/guide": textResponse("text/plain; charset=utf-8", body),
			})
			auth := &hostAuthSpy{transport: tr}
			d := webFetchDispatcher(t, auth, tr, outputCap)

			res, err := d.Dispatch(context.Background(), webFetchCall("https://docs.example.com/guide"))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			decoded := decodeFetchResult(t, res.Content, outputCap)
			if decoded["outcome"] != "ok" {
				t.Fatalf("outcome = %v, want ok", decoded["outcome"])
			}
			if content, _ := decoded["content"].(string); !strings.HasPrefix(content, "readable page text") {
				t.Fatalf("content = %q, want the extracted page text", content)
			}
		})
	}
}

func TestProductionDispatcher_WebFetchFailureOutcomesDiscloseNothing(t *testing.T) {
	const secret = "SUPER-SECRET"
	for _, tc := range []struct {
		name     string
		response *http.Response
		want     string
	}{
		{
			name: "error status",
			response: &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     http.Header{"Content-Type": []string{"text/plain"}, "Set-Cookie": []string{"session=" + secret}},
				Body:       io.NopCloser(strings.NewReader(secret + " body")),
			},
			want: webresearch.OutcomeRequestFailed,
		},
		{
			name:     "unsupported media type",
			response: textResponse("application/pdf", secret+" body"),
			want:     webresearch.OutcomeUnsupportedContent,
		},
		{
			name:     "oversized response",
			response: textResponse("text/plain", strings.Repeat(secret, 200)),
			want:     webresearch.OutcomeResponseTooLarge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const outputCap = 256
			target := "https://user:" + secret + "@docs.example.com/guide"
			tr := scriptedTransport(map[string]*http.Response{"https://docs.example.com/guide": tc.response})
			auth := &hostAuthSpy{transport: tr}
			d := webFetchDispatcher(t, auth, tr, outputCap)

			res, err := d.Dispatch(context.Background(), webFetchCall(target))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			decoded := decodeFetchResult(t, res.Content, outputCap)
			if decoded["outcome"] != tc.want {
				t.Fatalf("outcome = %v, want %q", decoded["outcome"], tc.want)
			}
			if _, ok := decoded["content"]; ok {
				t.Fatalf("a failed fetch returned content: %s", res.Content)
			}
			if strings.Contains(res.Content, secret) {
				t.Fatalf("result disclosed credentials, headers, or the raw body: %s", res.Content)
			}
			for _, display := range auth.displays {
				if strings.Contains(display.HostRequest, secret) {
					t.Fatalf("prompt display disclosed the URL credential: %q", display.HostRequest)
				}
			}
		})
	}
}

func TestProductionDispatcher_DirectFetchStaysWebFetchOnly(t *testing.T) {
	t.Run("web_search without a search backend stays unavailable", func(t *testing.T) {
		tr := scriptedTransport(map[string]*http.Response{})
		auth := &hostAuthSpy{transport: tr}
		d := webSearchDispatcher(t, auth, tr, 65536, nil)

		res, err := d.Dispatch(context.Background(), structuredCall("c1", webSearchToolName, map[string]any{"query": "codemeld"}))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if res.Content != errWebResearchUnavailable.Error() {
			t.Fatalf("content = %q, want the unavailable result", res.Content)
		}
		if len(auth.reqs) != 0 || tr.count() != 0 {
			t.Fatalf("authorizations = %d, requests = %d, want 0 and 0", len(auth.reqs), tr.count())
		}
	})

	t.Run("same-name non-placeholder tool", func(t *testing.T) {
		reg := tools.NewRegistry()
		tool := &stubStructuredTool{name: webFetchToolName, result: tools.Result{Stdout: []byte("out\n")}}
		if err := reg.Register("src", tool); err != nil {
			t.Fatalf("Register: %v", err)
		}
		tr := scriptedTransport(map[string]*http.Response{})
		auth := &recordingAuthorizer{decision: allow()}
		store := mkStore(t)
		d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, t.TempDir(), t.TempDir(), func() *sessions.Store { return store }, 65536, securitystate.Policy{})
		d.setWebFetch(config.WebResearchSettings{Enabled: true, TimeoutSeconds: 5})
		d.fetchClient.Transport = tr

		res, err := d.Dispatch(context.Background(), webFetchCall("https://docs.example.com/guide"))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if res.Content != "out" || tool.callCount() != 1 {
			t.Fatalf("content = %q, tool calls = %d, want the registered tool's own output", res.Content, tool.callCount())
		}
		if tr.count() != 0 {
			t.Fatalf("requests = %v, want none for a non-placeholder tool", tr.sent())
		}
	})

	for _, tc := range []struct {
		name string
		call turn.AssembledToolCall
		want string
	}{
		{"missing url", structuredCall("c1", webFetchToolName, map[string]any{}), `invalid tool arguments: missing "url"`},
		{"blank url", webFetchCall("   "), `invalid tool arguments: missing "url"`},
		{"non-string url", structuredCall("c1", webFetchToolName, map[string]any{"url": 42}), `invalid tool arguments: missing "url"`},
		{"malformed arguments", turn.AssembledToolCall{ID: "c1", Name: webFetchToolName, Arguments: "{not json"}, "invalid tool arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := scriptedTransport(map[string]*http.Response{})
			auth := &hostAuthSpy{transport: tr}
			d := webFetchDispatcher(t, auth, tr, 65536)

			res, err := d.Dispatch(context.Background(), tc.call)
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if !strings.Contains(res.Content, tc.want) {
				t.Fatalf("content = %q, want the in-band argument error %q", res.Content, tc.want)
			}
			if len(auth.reqs) != 0 || tr.count() != 0 {
				t.Fatalf("authorizations = %d, requests = %d, want 0 and 0", len(auth.reqs), tr.count())
			}
		})
	}
}

func TestProductionDispatcher_WebFetchRefusedSchemesNeverDial(t *testing.T) {
	for _, target := range []string{"file:///etc/passwd", "ftp://docs.example.com/guide", "https://*/guide"} {
		t.Run(target, func(t *testing.T) {
			tr := scriptedTransport(map[string]*http.Response{})
			auth := &hostAuthSpy{transport: tr}
			d := webFetchDispatcher(t, auth, tr, 65536)

			res, err := d.Dispatch(context.Background(), webFetchCall(target))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if decoded := decodeFetchResult(t, res.Content, 65536); decoded["outcome"] != webresearch.OutcomeRequestFailed {
				t.Fatalf("outcome = %v, want %q", decoded["outcome"], webresearch.OutcomeRequestFailed)
			}
			if len(auth.reqs) != 0 || tr.count() != 0 {
				t.Fatalf("authorizations = %d, requests = %d, want 0 and 0", len(auth.reqs), tr.count())
			}
		})
	}
}

func webSearchDispatcher(t *testing.T, auth dispatch.Authorizer, tr http.RoundTripper, outputCap int, backend webresearch.SearchBackend) *productionToolDispatcher {
	t.Helper()
	return webSearchDispatcherWith(t, auth, tr, outputCap, backend, map[string]any{"enabled": true})
}

func TestProductionDispatcher_WebSearchAuthorizesOnlyExaAndReturnsCandidateMetadata(t *testing.T) {
	tr := scriptedTransport(map[string]*http.Response{
		"https://a.example/1": textResponse("text/plain", "first body"),
		"https://b.example/2": textResponse("text/plain", "second body"),
	})
	auth := &hostAuthSpy{transport: tr}
	candidates := searchCandidates("https://a.example/1", "https://b.example/2")
	candidates[0].PublishedDate = "2026-01-02"
	backend := &stubSearchBackend{candidates: candidates, observe: auth.hosts}
	d := webSearchDispatcher(t, auth, tr, 65536, backend)

	res, err := d.Dispatch(context.Background(), webSearchCall("golang error wrapping"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	if res.Denied {
		t.Fatalf("authorized search returned a deny envelope: %q", res.Content)
	}
	if got := backend.calls(); !reflect.DeepEqual(got, []string{"golang error wrapping"}) {
		t.Fatalf("backend queries = %v, want the single dispatched query", got)
	}
	if got := backend.hostsAtSearch(); !reflect.DeepEqual(got, [][]string{{exaSearchHost}}) {
		t.Fatalf("hosts authorized when the query ran = %v, want only %q", got, exaSearchHost)
	}
	if got := auth.hosts(); !reflect.DeepEqual(got, []string{exaSearchHost}) {
		t.Fatalf("authorized hosts = %v, want only %q — a search authorizes no candidate host", got, exaSearchHost)
	}
	req := auth.reqs[0]
	if req.Kind != matchKindHost || req.Subject != webSearchToolName {
		t.Fatalf("authorization = kind %q subject %q, want an exact %q host request", req.Kind, req.Subject, webSearchToolName)
	}
	want := permissions.ModeContext{Class: permissions.ClassMutating, ToolName: webSearchToolName, NetworkEgress: true}
	if !reflect.DeepEqual(auth.modeCtxs[0], want) {
		t.Fatalf("authorization mode context = %+v, want %+v (network egress is never mode-auto-allowed)", auth.modeCtxs[0], want)
	}
	if auth.displays[0].HostRequest != "golang error wrapping" {
		t.Fatalf("search prompt displayed %q, want the query", auth.displays[0].HostRequest)
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %v, want none — a search dials no candidate", tr.sent())
	}
	decoded, omitted := decodeSearchResults(t, res.Content, 65536)
	if got := candidateURLs(decoded); !reflect.DeepEqual(got, []string{"https://a.example/1", "https://b.example/2"}) {
		t.Fatalf("candidate urls = %v, want the ranked candidates in relevance order", got)
	}
	if decoded[0]["title"] != "title of https://a.example/1" || decoded[0]["snippet"] != "snippet" {
		t.Fatalf("first candidate = %v, want the backend's own title and snippet", decoded[0])
	}
	if decoded[0]["published_date"] != "2026-01-02" {
		t.Fatalf("first candidate published date = %v, want the backend's date", decoded[0]["published_date"])
	}
	if _, ok := decoded[1]["published_date"]; ok {
		t.Fatalf("second candidate = %v, want no published date when the backend supplied none", decoded[1])
	}
	if omitted != 0 {
		t.Fatalf("omitted = %d, want 0", omitted)
	}
}

func TestProductionDispatcher_WebSearchCandidateIsReadOnlyThroughAnExplicitWebFetch(t *testing.T) {
	tr := scriptedTransport(map[string]*http.Response{
		"https://one.example/a": textResponse("text/plain", "first body"),
	})
	auth := &hostAuthSpy{transport: tr}
	backend := &stubSearchBackend{candidates: searchCandidates("https://one.example/a")}
	d := webSearchDispatcher(t, auth, tr, 65536, backend)

	searched, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch(web_search) error = %v, want nil", err)
	}
	decoded, _ := decodeSearchResults(t, searched.Content, 65536)
	selected := candidateURLs(decoded)[0]
	if strings.Contains(searched.Content, "first body") {
		t.Fatalf("search returned page content without a web_fetch call: %s", searched.Content)
	}
	if tr.count() != 0 {
		t.Fatalf("requests after the search = %v, want none", tr.sent())
	}

	fetched, err := d.Dispatch(context.Background(), webFetchCall(selected))
	if err != nil {
		t.Fatalf("Dispatch(web_fetch) error = %v, want nil", err)
	}
	wantHosts := []string{exaSearchHost, "one.example"}
	if got := auth.hosts(); !reflect.DeepEqual(got, wantHosts) {
		t.Fatalf("authorized hosts = %v, want %v (the Exa approval never covers the selected candidate)", got, wantHosts)
	}
	wantSubjects := []string{webSearchToolName, webFetchToolName}
	for i, req := range auth.reqs {
		if req.Kind != matchKindHost || req.Subject != wantSubjects[i] {
			t.Fatalf("authorization %d = kind %q subject %q, want an exact %q host request", i, req.Kind, req.Subject, wantSubjects[i])
		}
	}
	if !reflect.DeepEqual(auth.dials, []int{0, 0}) {
		t.Fatalf("requests sent at each authorization = %v, want [0 0] — the selected candidate was dialed before it was authorized (sent: %v)", auth.dials, tr.sent())
	}
	if got := tr.sent(); !reflect.DeepEqual(got, []string{selected}) {
		t.Fatalf("requests = %v, want exactly the explicitly fetched candidate", got)
	}
	if decodedFetch := decodeFetchResult(t, fetched.Content, 65536); decodedFetch["outcome"] != webresearch.OutcomeOK || decodedFetch["content"] != "first body" {
		t.Fatalf("fetch result = %v, want the selected candidate's readable body", decodedFetch)
	}
}

func TestProductionDispatcher_WebSearchCandidateHostDenialLeavesTheSearchIntact(t *testing.T) {
	envelope := permissions.BuildDenyEnvelope("")
	tr := scriptedTransport(map[string]*http.Response{
		"https://one.example/a": textResponse("text/plain", "first body"),
	})
	auth := &hostAuthSpy{transport: tr, denied: map[string]string{"one.example": envelope}}
	backend := &stubSearchBackend{candidates: searchCandidates("https://one.example/a")}
	d := webSearchDispatcher(t, auth, tr, 65536, backend)

	searched, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch(web_search) error = %v, want nil", err)
	}
	if searched.Denied {
		t.Fatalf("a search whose candidate host is denied was itself denied: %q", searched.Content)
	}
	decoded, _ := decodeSearchResults(t, searched.Content, 65536)
	if got := candidateURLs(decoded); !reflect.DeepEqual(got, []string{"https://one.example/a"}) {
		t.Fatalf("candidate urls = %v, want the ranked candidate — its host denial belongs to web_fetch", got)
	}

	fetched, err := d.Dispatch(context.Background(), webFetchCall("https://one.example/a"))
	if err != nil {
		t.Fatalf("Dispatch(web_fetch) error = %v, want nil (a denial is in-band)", err)
	}
	if !fetched.Denied || fetched.Content != envelope {
		t.Fatalf("fetch denied = %v content = %q, want the unchanged deny envelope", fetched.Denied, fetched.Content)
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %v, want none (a denied candidate host is never dialed)", tr.sent())
	}
	if strings.Contains(searched.Content, "first body") || strings.Contains(fetched.Content, "first body") {
		t.Fatalf("page content reached the model without an approved fetch: %s / %s", searched.Content, fetched.Content)
	}
}

func TestProductionDispatcher_WebSearchDenialQueriesNothing(t *testing.T) {
	envelope := permissions.BuildDenyEnvelope("")
	tr := scriptedTransport(map[string]*http.Response{
		"https://a.example/1": textResponse("text/plain", "first body"),
	})
	auth := &hostAuthSpy{transport: tr, denied: map[string]string{exaSearchHost: envelope}}
	backend := &stubSearchBackend{candidates: searchCandidates("https://a.example/1")}
	d := webSearchDispatcher(t, auth, tr, 65536, backend)

	res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil (a denial is in-band)", err)
	}
	if !res.Denied || res.Content != envelope {
		t.Fatalf("result denied = %v content = %q, want the unchanged deny envelope", res.Denied, res.Content)
	}
	if res.Terminal || res.Notice != "" {
		t.Fatalf("terminal = %v notice = %q, want a denial rather than a backend-failure notice", res.Terminal, res.Notice)
	}
	if got := backend.calls(); len(got) != 0 {
		t.Fatalf("backend queries = %v, want none after a denied search", got)
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %v, want none", tr.sent())
	}
}

func TestProductionDispatcher_WebSearchAuthorizationErrorAbortsTheTurn(t *testing.T) {
	tr := scriptedTransport(map[string]*http.Response{})
	auth := &hostAuthSpy{transport: tr, err: context.Canceled}
	backend := &stubSearchBackend{candidates: searchCandidates("https://a.example/1")}
	d := webSearchDispatcher(t, auth, tr, 65536, backend)

	res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dispatch error = %v, want the authorization failure", err)
	}
	if res.Content != "" {
		t.Fatalf("content = %q, want none for an internal authorization failure", res.Content)
	}
	if len(backend.calls()) != 0 || tr.count() != 0 {
		t.Fatalf("backend queries = %v, requests = %v, want none", backend.calls(), tr.sent())
	}
}

func TestProductionDispatcher_WebSearchKeepsRankedHTTPSCandidatesUpToFive(t *testing.T) {
	kept := []string{
		"https://one.example/a", "https://two.example/b", "https://three.example/c",
		"https://four.example/d", "https://five.example/e",
	}
	tr := scriptedTransport(map[string]*http.Response{})
	auth := &hostAuthSpy{transport: tr}
	backend := &stubSearchBackend{candidates: searchCandidates(
		"https://one.example/a",
		"http://plain.example/insecure",
		"https://two.example/b",
		"://malformed",
		"https://three.example/c",
		"ftp://files.example/x",
		"https://four.example/d",
		"https://five.example/e",
		"https://six.example/f",
	)}
	d := webSearchDispatcher(t, auth, tr, 65536, backend)

	res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	candidates, omitted := decodeSearchResults(t, res.Content, 65536)
	if got := candidateURLs(candidates); !reflect.DeepEqual(got, kept) {
		t.Fatalf("candidate urls = %v, want the first five usable https candidates in relevance order", got)
	}
	if omitted != 1 {
		t.Fatalf("omitted = %d, want only the sixth usable https candidate counted (a non-https or malformed candidate never is)", omitted)
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %v, want none", tr.sent())
	}
	if got := auth.hosts(); !reflect.DeepEqual(got, []string{exaSearchHost}) {
		t.Fatalf("authorized hosts = %v, want only %q (no candidate host is authorized)", got, exaSearchHost)
	}
}

func TestProductionDispatcher_WebSearchExcludesCandidatesWebFetchWouldRefuse(t *testing.T) {
	usable := []string{
		"https://one.example/a", "https://two.example/b", "https://three.example/c",
		"https://four.example/d", "https://five.example/e", "https://six.example/f",
	}
	for _, refused := range []string{
		"https://example.com:0/",
		"https://example.com:65536/",
		"https://*/",
		"https:///path",
		"https://ex ample.com/",
	} {
		t.Run(refused, func(t *testing.T) {
			tr := scriptedTransport(map[string]*http.Response{})
			auth := &hostAuthSpy{transport: tr}
			backend := &stubSearchBackend{candidates: searchCandidates(append([]string{refused}, usable...)...)}
			d := webSearchDispatcher(t, auth, tr, 65536, backend)

			res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			candidates, omitted := decodeSearchResults(t, res.Content, 65536)
			if got := candidateURLs(candidates); !reflect.DeepEqual(got, usable[:5]) {
				t.Fatalf("candidate urls = %v, want only the five usable candidates web_fetch would admit", got)
			}
			if omitted != 1 {
				t.Fatalf("omitted = %d, want 1 — only the sixth usable candidate counts, never one web_fetch refuses", omitted)
			}
			if tr.count() != 0 {
				t.Fatalf("requests = %v, want none", tr.sent())
			}
		})
	}
}

func TestProductionDispatcher_WebSearchKeepsCandidatesInTheirCanonicalFetchForm(t *testing.T) {
	tr := scriptedTransport(map[string]*http.Response{})
	auth := &hostAuthSpy{transport: tr}
	backend := &stubSearchBackend{candidates: searchCandidates("https://ONE.example.:8443/a", "https://two.example:65535/b")}
	d := webSearchDispatcher(t, auth, tr, 65536, backend)

	res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	candidates, omitted := decodeSearchResults(t, res.Content, 65536)
	want := []string{"https://one.example:8443/a", "https://two.example:65535/b"}
	if got := candidateURLs(candidates); !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate urls = %v, want %v — an in-range port is usable and the host is shown as web_fetch would dial it", got, want)
	}
	if omitted != 0 {
		t.Fatalf("omitted = %d, want 0", omitted)
	}
}

// A candidate URL is surfaced whole or not at all: cutting it at the field limit could land inside
// a percent escape, and the resulting string is a target web_fetch cannot reach.
func TestProductionDispatcher_WebSearchOmitsACandidateURLTooLongToSurfaceWhole(t *testing.T) {
	const outputCap = 1 << 20
	const prefix = "https://one.example/"
	fits := prefix + strings.Repeat("a", maxCandidateURLBytes-len(prefix)-len("%2F")) + "%2F"
	overLong := prefix + strings.Repeat("a", maxCandidateURLBytes-len(prefix)-1) + "%2F"
	tr := scriptedTransport(map[string]*http.Response{fits: textResponse("text/plain", "kept body")})
	auth := &hostAuthSpy{transport: tr}
	backend := &stubSearchBackend{candidates: searchCandidates(overLong, fits)}
	d := webSearchDispatcher(t, auth, tr, outputCap, backend)

	searched, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch(web_search) error = %v, want nil", err)
	}
	candidates, omitted := decodeSearchResults(t, searched.Content, outputCap)
	if got := candidateURLs(candidates); !reflect.DeepEqual(got, []string{fits}) {
		t.Fatalf("candidate urls = %v, want only the %d-byte candidate that fits the url field whole", got, len(fits))
	}
	if omitted != 1 {
		t.Fatalf("omitted = %d, want the usable candidate too long to surface counted as omitted", omitted)
	}

	selected := candidateURLs(candidates)[0]
	fetched, err := d.Dispatch(context.Background(), webFetchCall(selected))
	if err != nil {
		t.Fatalf("Dispatch(web_fetch) error = %v, want nil", err)
	}
	if got := tr.sent(); !reflect.DeepEqual(got, []string{fits}) {
		t.Fatalf("requests = %v, want the surfaced candidate to reach its unmodified original target", got)
	}
	if decoded := decodeFetchResult(t, fetched.Content, outputCap); decoded["outcome"] != webresearch.OutcomeOK || decoded["content"] != "kept body" {
		t.Fatalf("fetch result = %v, want the surfaced candidate read successfully", decoded)
	}
}

func TestProductionDispatcher_WebSearchCandidateMetadataStaysBoundedAndCredentialSafe(t *testing.T) {
	const secret = "SUPER-SECRET"
	const outputCap = 1 << 20
	tr := scriptedTransport(map[string]*http.Response{})
	auth := &hostAuthSpy{transport: tr}
	backend := &stubSearchBackend{candidates: []webresearch.Candidate{{
		Title:         strings.Repeat("t", 4096) + "\xff",
		URL:           "https://user:" + secret + "@one.example/" + strings.Repeat("a", 2000),
		Snippet:       strings.Repeat("s", 65536) + "\xff",
		PublishedDate: strings.Repeat("9", 4096),
	}}}
	d := webSearchDispatcher(t, auth, tr, outputCap, backend)

	res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
	if err != nil {
		t.Fatalf("Dispatch error = %v, want nil", err)
	}
	candidates, _ := decodeSearchResults(t, res.Content, outputCap)
	if len(candidates) != 1 {
		t.Fatalf("candidates = %v, want the single usable https candidate", candidates)
	}
	for _, tc := range []struct {
		field string
		limit int
	}{
		{"title", maxCandidateTitleBytes},
		{"url", maxCandidateURLBytes},
		{"snippet", maxCandidateSnippetBytes},
		{"published_date", maxCandidatePublishedBytes},
	} {
		value, _ := candidates[0][tc.field].(string)
		if len(value) > tc.limit {
			t.Fatalf("%s is %d bytes, want <= its %d-byte contract cap", tc.field, len(value), tc.limit)
		}
		if !utf8.ValidString(value) {
			t.Fatalf("%s is not valid UTF-8: %q", tc.field, value)
		}
	}
	if got, _ := candidates[0]["url"].(string); !strings.HasPrefix(got, "https://user:xxxxx@one.example/a") {
		t.Fatalf("candidate url = %q, want the credential redacted out of the display form", got)
	}
	if strings.Contains(res.Content, secret) {
		t.Fatalf("result disclosed a URL credential: %s", res.Content)
	}
	for _, display := range auth.displays {
		if strings.Contains(display.HostRequest, secret) {
			t.Fatalf("prompt display disclosed the URL credential: %q", display.HostRequest)
		}
	}
	if tr.count() != 0 {
		t.Fatalf("requests = %v, want none", tr.sent())
	}
}

func TestProductionDispatcher_WebSearchArgumentAndBackendFailuresStayInBand(t *testing.T) {
	for _, tc := range []struct {
		name string
		call turn.AssembledToolCall
		want string
	}{
		{"missing query", structuredCall("c1", webSearchToolName, map[string]any{}), `invalid tool arguments: missing "query"`},
		{"blank query", webSearchCall("   "), `invalid tool arguments: missing "query"`},
		{"non-string query", structuredCall("c1", webSearchToolName, map[string]any{"query": 42}), `invalid tool arguments: missing "query"`},
		{"malformed arguments", turn.AssembledToolCall{ID: "c1", Name: webSearchToolName, Arguments: "{not json"}, "invalid tool arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := scriptedTransport(map[string]*http.Response{})
			auth := &hostAuthSpy{transport: tr}
			backend := &stubSearchBackend{candidates: searchCandidates("https://one.example/a")}
			d := webSearchDispatcher(t, auth, tr, 65536, backend)

			res, err := d.Dispatch(context.Background(), tc.call)
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			if !strings.Contains(res.Content, tc.want) {
				t.Fatalf("content = %q, want the in-band argument error %q", res.Content, tc.want)
			}
			if res.Terminal || res.Denied || res.Notice != "" {
				t.Fatalf("terminal = %v denied = %v notice = %q, want a plain in-band argument error", res.Terminal, res.Denied, res.Notice)
			}
			if len(auth.reqs) != 0 || len(backend.calls()) != 0 || tr.count() != 0 {
				t.Fatalf("authorizations = %d, queries = %v, requests = %d, want none", len(auth.reqs), backend.calls(), tr.count())
			}
		})
	}

	t.Run("no usable candidate", func(t *testing.T) {
		tr := scriptedTransport(map[string]*http.Response{})
		auth := &hostAuthSpy{transport: tr}
		backend := &stubSearchBackend{candidates: searchCandidates("http://plain.example/insecure")}
		d := webSearchDispatcher(t, auth, tr, 65536, backend)

		res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if res.Content != `{"candidates":[]}` {
			t.Fatalf("content = %q, want an empty candidate list", res.Content)
		}
		if len(auth.reqs) != 1 || tr.count() != 0 {
			t.Fatalf("authorizations = %d, requests = %d, want only the search authorization", len(auth.reqs), tr.count())
		}
	})

	t.Run("backend failure", func(t *testing.T) {
		tr := scriptedTransport(map[string]*http.Response{})
		auth := &hostAuthSpy{transport: tr}
		backend := &stubSearchBackend{err: errors.New("exa: the search request failed")}
		d := webSearchDispatcher(t, auth, tr, 65536, backend)

		res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil (a backend failure is in-band)", err)
		}
		if res.Denied || res.Content != "exa: the search request failed" {
			t.Fatalf("content = %q denied = %v, want the bounded backend error", res.Content, res.Denied)
		}
		if res.Terminal {
			t.Fatalf("terminal = true for a failed search, want false so the model keeps the turn and decides what to do next")
		}
		if res.Notice != "exa: the search request failed" {
			t.Fatalf("notice = %q, want the bounded backend error on the non-terminal notice path", res.Notice)
		}
		if tr.count() != 0 {
			t.Fatalf("requests = %v, want none", tr.sent())
		}
	})

	t.Run("successful search is not terminal and carries no notice", func(t *testing.T) {
		tr := scriptedTransport(map[string]*http.Response{})
		auth := &hostAuthSpy{transport: tr}
		backend := &stubSearchBackend{candidates: searchCandidates("https://one.example/a")}
		d := webSearchDispatcher(t, auth, tr, 65536, backend)

		res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
		if err != nil {
			t.Fatalf("Dispatch error = %v, want nil", err)
		}
		if res.Terminal || res.Denied {
			t.Fatalf("terminal = %v denied = %v for a successful search, want both false", res.Terminal, res.Denied)
		}
		if res.Notice != "" {
			t.Fatalf("notice = %q for a successful search, want none", res.Notice)
		}
	})
}

func TestProductionDispatcher_WebSearchReturnsCompleteJSONAtEveryCap(t *testing.T) {
	for _, outputCap := range []int{64, 128, 256, 4096, 65536} {
		t.Run(fmt.Sprintf("cap %d", outputCap), func(t *testing.T) {
			urls := []string{"https://one.example/a", "https://two.example/b", "https://three.example/c"}
			candidates := searchCandidates(urls...)
			for i := range candidates {
				candidates[i].Snippet = strings.Repeat("readable snippet text ", 1000)
			}
			tr := scriptedTransport(map[string]*http.Response{})
			auth := &hostAuthSpy{transport: tr}
			backend := &stubSearchBackend{candidates: candidates}
			d := webSearchDispatcher(t, auth, tr, outputCap, backend)

			res, err := d.Dispatch(context.Background(), webSearchCall("codemeld"))
			if err != nil {
				t.Fatalf("Dispatch error = %v, want nil", err)
			}
			// decodeSearchResults fails the cap and the JSON-validity check for us; what is left to
			// pin is that overflow drops whole candidates into omitted rather than unbounding a field.
			decoded, omitted := decodeSearchResults(t, res.Content, outputCap)
			if len(decoded)+omitted != len(urls) {
				t.Fatalf("candidates = %d, omitted = %d, want the three usable candidates accounted for", len(decoded), omitted)
			}
			for _, candidate := range decoded {
				snippet, _ := candidate["snippet"].(string)
				if len(snippet) > maxCandidateSnippetBytes {
					t.Fatalf("snippet is %d bytes, want <= its %d-byte contract cap", len(snippet), maxCandidateSnippetBytes)
				}
			}
		})
	}
}

func TestNewSearchBackend_UnusableConfigurationStaysFailClosed(t *testing.T) {
	if backend := newSearchBackend(exa.Config{}); backend != nil {
		t.Fatalf("search backend = %v for an unusable configuration, want nil so web_search stays fail-closed", backend)
	}
	valid := exa.Config{HTTPClient: &http.Client{}, MaxResults: 3, Timeout: time.Second, MaxOutputBytes: 65536}
	if backend := newSearchBackend(valid); backend == nil {
		t.Fatal("search backend = nil for the production configuration shape")
	}
}

func TestRunHeadless_WebFetchRunsThroughTheProductionBinding(t *testing.T) {
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "the local body")
	}))
	defer server.Close()

	client := toolThenContentClient(nil, webFetchToolName, `{"url":`+mustJSONString(server.URL+"/page")+`}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	composed := headlessProviderConfig()
	composed["web_research"] = map[string]any{"enabled": true, "timeout_seconds": 1}

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("read the page", &stdout, &stderr)
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
	result.Config = composed

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := driver.Run(ctx, result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if strings.Contains(stderr.String(), "tool: "+webFetchToolName) {
		t.Fatalf("prompt output %q asked to authorize a loopback literal — it must be refused before the permission prompt", stderr.String())
	}
	if got := served.Load(); got != 0 {
		t.Fatalf("loopback server served %d requests, want 0", got)
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool messages = %+v, want exactly one fetch result", toolMsgs)
	}
	decoded := decodeFetchResult(t, toolMsgs[0].Content.Text(), 65536)
	if decoded["outcome"] != webresearch.OutcomeRequestFailed {
		t.Fatalf("outcome = %v, want %q for a refused loopback literal", decoded["outcome"], webresearch.OutcomeRequestFailed)
	}
	for _, leak := range []string{"127.0.0.1", "the local body"} {
		if strings.Contains(toolMsgs[0].Content.Text(), leak) {
			t.Fatalf("tool result %q repeats %q, want only the refusal outcome", toolMsgs[0].Content.Text(), leak)
		}
	}
}

func TestRunHeadless_WebSearchRunsThroughTheProductionBinding(t *testing.T) {
	var served atomic.Int64
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "the source body")
	}))
	defer source.Close()

	const public = "https://docs.example.com/page"
	backend := &stubSearchBackend{candidates: searchCandidates(public, source.URL+"/page")}
	defer swapSearchBackend(func(exa.Config) webresearch.SearchBackend { return backend })()

	client := toolThenContentClient(nil, webSearchToolName, `{"query":"golang error wrapping"}`, "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

	composed := headlessProviderConfig()
	composed["web_research"] = map[string]any{"enabled": true, "timeout_seconds": 1}

	var stdout, stderr bytes.Buffer
	driver := NewHeadlessDriver("research this", &stdout, &stderr)
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
	result.Config = composed

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := driver.Run(ctx, result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if got := backend.calls(); !reflect.DeepEqual(got, []string{"golang error wrapping"}) {
		t.Fatalf("backend queries = %v — the realized search backend did not reach the production dispatcher", got)
	}
	for _, want := range []string{"tool: " + webSearchToolName, "host: " + exaSearchHost} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("prompt output %q missing %q — the search was not authorized on the Exa host", stderr.String(), want)
		}
	}
	if strings.Contains(stderr.String(), "tool: "+webFetchToolName) {
		t.Fatalf("prompt output %q asked to authorize a candidate host — a search never fetches one", stderr.String())
	}
	if got := served.Load(); got != 0 {
		t.Fatalf("candidate origin served %d requests, want 0 (a search dials no candidate)", got)
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 1 {
		t.Fatalf("tool messages = %+v, want exactly one search result", toolMsgs)
	}
	candidates, _ := decodeSearchResults(t, toolMsgs[0].Content.Text(), 65536)
	if len(candidates) != 1 || candidates[0]["url"] != public {
		t.Fatalf("candidates = %v, want only the public https candidate — a loopback candidate web_fetch would refuse is dropped", candidates)
	}
}
