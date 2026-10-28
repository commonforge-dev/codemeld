package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/tui"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/webresearch"
	"codemeld.dev/codemeld/internal/webresearch/exa"
)

const (
	webSearchQuery        = "codemeld release notes"
	webSearchKeySentinel  = "EXA-KEY-SENTINEL-9c2e"
	webSearchBodySentinel = "EXA-BODY-SENTINEL-9c2e"
)

type webSearchHarness struct {
	dispatcher *productionToolDispatcher
	auth       *productionAuthorizer
	registry   *tools.Registry
	cache      *config.Cache
	prompts    *webFetchPrompts
}

// The registry binds whatever newSearchBackend returned at realize time, so the seam is
// restored immediately after realize rather than deferred to the end of the test.
func newWebSearchHarness(t *testing.T, project, home string, cache *config.Cache, origins *webFetchOrigins, backend func(exa.Config) webresearch.SearchBackend, decide func(tui.PromptRequest) tui.PromptDecision) *webSearchHarness {
	t.Helper()
	return newWebSearchHarnessInMode(t, project, home, cache, origins, backend, decide, mode.NewActiveState(mode.Build, mode.SourceDefault))
}

func newWebSearchHarnessInMode(t *testing.T, project, home string, cache *config.Cache, origins *webFetchOrigins, backend func(exa.Config) webresearch.SearchBackend, decide func(tui.PromptRequest) tui.PromptDecision, modeActive *mode.ActiveState) *webSearchHarness {
	t.Helper()
	store := mkStore(t)
	app := tui.New(nil)
	app.SetActiveStore(store)

	prompts := &webFetchPrompts{decide: decide}
	auth := newProductionAuthorizer(app, cache, permissions.NewTurnCache(), newPromptGateBuilder(prompts.show), home, project, modeActive)

	restore := swapSearchBackend(backend)
	reg, err := (&toolRegistryFactory{active: nil}).realize(cache, func() *sessions.Store { return store }, home, project, securitystate.Policy{})
	restore()
	if err != nil {
		t.Fatalf("realize production registry: %v", err)
	}

	d := newProductionToolDispatcher(reg, &fakeDispatchRunner{}, auth, home, project, func() *sessions.Store { return store }, webFetchOutputCap, securitystate.Policy{})
	d.setWebFetch(cache.WebResearch())
	if d.fetchClient != nil {
		d.fetchClient.Transport = origins.transport
	}
	return &webSearchHarness{dispatcher: d, auth: auth, registry: reg, cache: cache, prompts: prompts}
}

func (h *webSearchHarness) search(t *testing.T, query string) turn.ToolResult {
	t.Helper()
	res, err := h.dispatcher.Dispatch(context.Background(), webSearchCall(query))
	if err != nil {
		t.Fatalf("Dispatch(web_search %q) error = %v, want nil (an in-band result, never a turn abort)", query, err)
	}
	return res
}

// fetch runs the model's follow-up read of a candidate through the same production dispatcher, so
// the selected source's authorization and dial are observed on the real path rather than simulated.
func (h *webSearchHarness) fetch(t *testing.T, rawURL string) turn.ToolResult {
	t.Helper()
	res, err := h.dispatcher.Dispatch(context.Background(), webFetchCall(rawURL))
	if err != nil {
		t.Fatalf("Dispatch(web_fetch %s) error = %v, want nil (an in-band result, never a turn abort)", rawURL, err)
	}
	return res
}

func (h *webSearchHarness) promptTools() []string {
	var out []string
	for _, req := range h.prompts.requests() {
		out = append(out, req.HostTool)
	}
	return out
}

func fixedSearchBackend(backend webresearch.SearchBackend) func(exa.Config) webresearch.SearchBackend {
	return func(exa.Config) webresearch.SearchBackend { return backend }
}

func allowOnceEveryPrompt(tui.PromptRequest) tui.PromptDecision {
	return tui.PromptDecision{Option: tui.OptionAllowOnce}
}

func allowOnceForHosts(hosts ...string) func(tui.PromptRequest) tui.PromptDecision {
	return func(req tui.PromptRequest) tui.PromptDecision {
		if slices.Contains(hosts, req.Host) {
			return tui.PromptDecision{Option: tui.OptionAllowOnce}
		}
		return tui.PromptDecision{Option: tui.OptionDeny}
	}
}

func webSearchHostRequest(subject, host string) (permissions.MatchRequest, dispatch.PromptDisplay, permissions.ModeContext) {
	return permissions.MatchRequest{Kind: matchKindHost, Subject: subject, Host: host},
		dispatch.PromptDisplay{HostRequest: "https://" + host + "/page"},
		permissions.ModeContext{Class: permissions.ClassMutating, ToolName: subject, NetworkEgress: true}
}

func wantProjectSearchGrant(host string) permissions.PermissionEntry {
	return permissions.PermissionEntry{Kind: "tool", Subject: webSearchToolName, HostScope: host, GrantKind: projectGrantKind}
}

// --- controlled Exa MCP transport -------------------------------------------

type exaExchange struct {
	httpMethod string
	rpcMethod  string
	params     string
	url        string
	header     http.Header
}

// exaMCPFixture answers the MCP Streamable-HTTP flow in process so the real Exa adapter —
// its bounded transport, credential header, and failure classification — runs without a dial.
type exaMCPFixture struct {
	resultText string
	toolStatus int
	toolBody   string

	mu   sync.Mutex
	seen []exaExchange
}

func (f *exaMCPFixture) RoundTrip(req *http.Request) (*http.Response, error) {
	var rpc struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Params json.RawMessage `json:"params"`
	}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &rpc)
	}
	f.mu.Lock()
	f.seen = append(f.seen, exaExchange{
		httpMethod: req.Method,
		rpcMethod:  rpc.Method,
		params:     string(rpc.Params),
		url:        req.URL.String(),
		header:     req.Header.Clone(),
	})
	f.mu.Unlock()

	switch rpc.Method {
	case "initialize":
		resp := exaJSONReply(http.StatusOK, exaEnvelope(rpc.ID, map[string]any{
			"protocolVersion": exaProtocolVersion(rpc.Params),
			"capabilities":    map[string]any{},
			"serverInfo":      map[string]any{"name": "exa", "version": "1"},
		}))
		resp.Header.Set("Mcp-Session-Id", "exa-integration-session")
		return resp, nil
	case "notifications/initialized":
		return exaJSONReply(http.StatusAccepted, ""), nil
	case "tools/call":
		if f.toolStatus != 0 {
			return exaJSONReply(f.toolStatus, f.toolBody), nil
		}
		return exaJSONReply(http.StatusOK, exaEnvelope(rpc.ID, map[string]any{
			"content": []any{map[string]any{"type": "text", "text": f.resultText}},
		})), nil
	}
	return exaJSONReply(http.StatusOK, "{}"), nil
}

func (f *exaMCPFixture) exchanges() []exaExchange {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]exaExchange(nil), f.seen...)
}

func (f *exaMCPFixture) rpcExchanges() []exaExchange {
	var out []exaExchange
	for _, ex := range f.exchanges() {
		if ex.rpcMethod != "" {
			out = append(out, ex)
		}
	}
	return out
}

func (f *exaMCPFixture) toolCalls() int {
	n := 0
	for _, ex := range f.exchanges() {
		if ex.rpcMethod == "tools/call" {
			n++
		}
	}
	return n
}

func exaJSONReply(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func exaEnvelope(id json.RawMessage, result map[string]any) string {
	if len(id) == 0 {
		id = json.RawMessage("1")
	}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// The MCP client rejects a version it did not offer, so the fixture echoes the requested one
// instead of pinning a literal that would rot with the library.
func exaProtocolVersion(params json.RawMessage) string {
	var decoded struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &decoded)
	if decoded.ProtocolVersion == "" {
		return "2025-06-18"
	}
	return decoded.ProtocolVersion
}

func exaResultText(urls ...string) string {
	records := make([]string, len(urls))
	for i, u := range urls {
		records[i] = fmt.Sprintf("Title: result %d\nURL: %s\nText: an exa snippet", i, u)
	}
	return strings.Join(records, "\n\n---\n\n")
}

func realExaBackend(t *testing.T, f *exaMCPFixture, capture *exa.Config) func(exa.Config) webresearch.SearchBackend {
	return func(cfg exa.Config) webresearch.SearchBackend {
		if capture != nil {
			*capture = cfg
		}
		cfg.HTTPClient = &http.Client{Transport: f, Timeout: cfg.Timeout}
		backend, err := exa.New(cfg)
		if err != nil {
			t.Errorf("exa.New with the production configuration: %v", err)
			return nil
		}
		return backend
	}
}

// --- production turn wiring -------------------------------------------------

func webSearchProjectGrant() []any {
	return []any{map[string]any{
		"kind":       "tool",
		"subject":    webSearchToolName,
		"host_scope": exaSearchHost,
		"grant_kind": projectGrantKind,
	}}
}

func TestWebSearchIntegration_EnabledRegistrationDeliversASearchResultThroughTheProductionTurn(t *testing.T) {
	for _, tc := range []struct {
		name       string
		web        map[string]any
		wantBuilds int64
	}{
		{"enabled", map[string]any{"enabled": true, "timeout_seconds": 5}, 1},
		{"disabled", map[string]any{"enabled": false}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var builds atomic.Int64
			backend := &stubSearchBackend{candidates: searchCandidates("https://source.test/page")}
			defer swapSearchBackend(func(exa.Config) webresearch.SearchBackend {
				builds.Add(1)
				return backend
			})()

			client := toolThenContentClient(nil, webSearchToolName, `{"query":"`+webSearchQuery+`"}`, "ok")
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			composed := headlessProviderConfig()
			composed["web_research"] = tc.web
			composed["permissions"] = webSearchProjectGrant()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("research this", &stdout, &stderr)
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
			result.Config = composed

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := driver.Run(ctx, result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			if got := builds.Load(); got != tc.wantBuilds {
				t.Fatalf("search adapters built = %d, want %d", got, tc.wantBuilds)
			}
			toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
			if len(toolMsgs) != 1 {
				t.Fatalf("durable tool messages = %+v, want exactly one", toolMsgs)
			}
			content := toolMsgs[0].Content.Text()

			if tc.wantBuilds == 0 {
				if got := backend.calls(); len(got) != 0 {
					t.Fatalf("backend queries = %v, want none while web research is disabled", got)
				}
				if !strings.Contains(content, "no_such_tool: "+webSearchToolName) {
					t.Fatalf("tool result = %q, want the ordinary unknown-tool result", content)
				}
				return
			}

			if got := backend.calls(); !slices.Equal(got, []string{webSearchQuery}) {
				t.Fatalf("backend queries = %v — the registered search did not reach the production dispatcher", got)
			}
			candidates, omitted := decodeSearchResults(t, content, webFetchOutputCap)
			if !slices.Equal(candidateURLs(candidates), []string{"https://source.test/page"}) {
				t.Fatalf("durable candidates = %v, want the single ranked https candidate", candidates)
			}
			if omitted != 0 {
				t.Fatalf("omitted = %d, want 0", omitted)
			}
		})
	}
}

func TestWebSearchIntegration_DeniedSearchReachesNoBackendOrCandidateTransport(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()
	origins := newWebFetchOrigins(t)
	origins.secure(t, "first.test")
	origins.secure(t, "second.test")

	backend := &stubSearchBackend{candidates: searchCandidates("https://first.test/page", "https://second.test/page")}

	denied := newWebSearchHarness(t, project, home, webFetchCache(t, project, true), origins, fixedSearchBackend(backend), denyEveryPrompt)
	res := denied.search(t, webSearchQuery)
	if !res.Denied {
		t.Fatalf("ungranted web_search was not denied; content=%q", res.Content)
	}
	if res.Content == "" {
		t.Fatal("denied web_search carried an empty envelope")
	}
	if got := backend.calls(); len(got) != 0 {
		t.Fatalf("backend queries after a denial = %v, want none (Exa is authorized before the search)", got)
	}
	if got := origins.total(); got != 0 {
		t.Fatalf("denied web_search made %d controlled-origin requests, want 0", got)
	}
	if got := denied.prompts.hosts(); !slices.Equal(got, []string{exaSearchHost}) {
		t.Fatalf("prompted hosts = %v, want exactly one prompt for %s", got, exaSearchHost)
	}
	if got := len(denied.cache.Permissions()); got != 0 {
		t.Fatalf("grant table holds %d entries after a denial, want 0", got)
	}
	mustNotExist(t, webFetchSettingsPath(project), "a denied web_search must write no project grant")
	mustNotExist(t, SettingsPath(home), "a web_search approval never reaches the global settings file")

	granted := newWebSearchHarness(t, project, home, webFetchCache(t, project, true), origins,
		fixedSearchBackend(backend), allowOnceForHosts(exaSearchHost))
	ok := granted.search(t, webSearchQuery)
	if ok.Denied {
		t.Fatalf("granted web_search was denied; content=%q", ok.Content)
	}
	if got := backend.calls(); !slices.Equal(got, []string{webSearchQuery}) {
		t.Fatalf("backend queries = %v, want the one granted search", got)
	}
	candidates, _ := decodeSearchResults(t, ok.Content, webFetchOutputCap)
	if !slices.Equal(candidateURLs(candidates), []string{"https://first.test/page", "https://second.test/page"}) {
		t.Fatalf("candidates = %v, want both ranked https candidates", candidateURLs(candidates))
	}
	if got := origins.total(); got != 0 {
		t.Fatalf("granted web_search made %d candidate-origin requests, want 0", got)
	}
	if got := granted.prompts.hosts(); !slices.Equal(got, []string{exaSearchHost}) {
		t.Fatalf("prompted hosts = %v, want only %s (no candidate host is authorized)", got, exaSearchHost)
	}
	if got := origins.escapes(); len(got) != 0 {
		t.Fatalf("dials outside the controlled origins = %v, want none", got)
	}
}

func TestWebSearchIntegration_NoModePostureResolvesASearchOrItsCandidateFetch(t *testing.T) {
	for _, m := range []*mode.ActiveState{
		mode.NewActiveState(mode.Build, mode.SourceDefault),
		mode.NewActiveState(mode.AutoEdits, mode.SourceConfig),
		mode.NewActiveState(mode.Plan, mode.SourceConfig),
	} {
		key, _ := m.Current()
		t.Run(string(key), func(t *testing.T) {
			project := webFetchProject(t)
			home := t.TempDir()
			origins := newWebFetchOrigins(t)
			source := origins.secure(t, "first.test")
			candidates := searchCandidates("https://first.test/page")

			refused := newWebSearchHarnessInMode(t, project, home, webFetchCache(t, project, true), origins,
				fixedSearchBackend(&stubSearchBackend{candidates: candidates}), denyEveryPrompt, m)
			res := refused.search(t, webSearchQuery)
			if !res.Denied {
				t.Fatalf("an ungranted search resolved without a user decision; content=%q", res.Content)
			}
			if got := refused.prompts.hosts(); !slices.Equal(got, []string{exaSearchHost}) {
				t.Fatalf("prompted hosts = %v, want one prompt for %s (network egress is never mode-resolved)", got, exaSearchHost)
			}
			if got := origins.total(); got != 0 {
				t.Fatalf("refused search made %d candidate requests, want 0", got)
			}

			approved := newWebSearchHarnessInMode(t, project, home, webFetchCache(t, project, true), origins,
				fixedSearchBackend(&stubSearchBackend{candidates: candidates}), allowOnceEveryPrompt, m)
			ok := approved.search(t, webSearchQuery)
			if ok.Denied {
				t.Fatalf("an approved search was refused in %s; content=%q", key, ok.Content)
			}
			if got := origins.total(); got != 0 {
				t.Fatalf("approved search made %d candidate requests, want 0 in %s", got, key)
			}
			if got := approved.prompts.hosts(); !slices.Equal(got, []string{exaSearchHost}) {
				t.Fatalf("prompted hosts = %v, want only %s until the model fetches a candidate", got, exaSearchHost)
			}

			// The candidate host is resolved by its own web_fetch prompt in every mode, never by the
			// mode posture and never by the search approval that preceded it.
			approved.prompts.reset()
			if fetched := approved.fetch(t, "https://first.test/page"); fetched.Denied {
				t.Fatalf("an approved candidate fetch was refused in %s; content=%q", key, fetched.Content)
			}
			if got := approved.promptTools(); !slices.Equal(got, []string{webFetchToolName}) {
				t.Fatalf("prompted tools for the candidate read = %v, want a separate %s prompt", got, webFetchToolName)
			}
			if got := origins.served(source); got != 1 {
				t.Fatalf("selected candidate served %d requests, want 1", got)
			}
			if got := origins.escapes(); len(got) != 0 {
				t.Fatalf("dials outside the controlled origins = %v, want none", got)
			}
		})
	}
}

func TestWebSearchIntegration_AuthorizesOnlyExaThenTheSelectedCandidateSeparately(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()
	origins := newWebFetchOrigins(t)
	first := origins.secure(t, "first.test")
	second := origins.secure(t, "second.test")

	backend := &stubSearchBackend{candidates: searchCandidates("https://first.test/page", "https://second.test/page")}
	h := newWebSearchHarness(t, project, home, webFetchCache(t, project, true), origins, fixedSearchBackend(backend), allowOnceEveryPrompt)
	backend.observe = h.prompts.hosts

	res := h.search(t, webSearchQuery)
	if res.Denied {
		t.Fatalf("approved web_search was denied; content=%q", res.Content)
	}

	atSearch := backend.hostsAtSearch()
	if len(atSearch) != 1 || !slices.Equal(atSearch[0], []string{exaSearchHost}) {
		t.Fatalf("authorizations at backend time = %v, want exactly the %s search authorization", atSearch, exaSearchHost)
	}
	if got := h.prompts.hosts(); !slices.Equal(got, []string{exaSearchHost}) {
		t.Fatalf("prompted hosts = %v, want only %s (a search authorizes no candidate host)", got, exaSearchHost)
	}
	if got := h.promptTools(); !slices.Equal(got, []string{webSearchToolName}) {
		t.Fatalf("prompted tools = %v, want only %s", got, webSearchToolName)
	}
	for _, req := range h.prompts.requests() {
		if req.HostTool == webSearchToolName && req.HostRequest != webSearchQuery {
			t.Fatalf("search prompt displayed %q, want the query %q", req.HostRequest, webSearchQuery)
		}
	}
	candidates, _ := decodeSearchResults(t, res.Content, webFetchOutputCap)
	if !slices.Equal(candidateURLs(candidates), []string{"https://first.test/page", "https://second.test/page"}) {
		t.Fatalf("candidates = %v, want both ranked https candidates", candidateURLs(candidates))
	}
	if got := origins.total(); got != 0 {
		t.Fatalf("the search made %d candidate-origin requests, want 0", got)
	}

	h.prompts.reset()
	selected := candidateURLs(candidates)[0]
	fetched := h.fetch(t, selected)
	if fetched.Denied {
		t.Fatalf("the explicitly selected candidate was denied; content=%q", fetched.Content)
	}
	if got := h.prompts.hosts(); !slices.Equal(got, []string{"first.test"}) {
		t.Fatalf("prompted hosts for the selected candidate = %v, want its own exact host", got)
	}
	if got := h.promptTools(); !slices.Equal(got, []string{webFetchToolName}) {
		t.Fatalf("prompted tools for the selected candidate = %v, want a separate %s prompt", got, webFetchToolName)
	}
	if got := webFetchOutcome(t, fetched.Content); got != webresearch.OutcomeOK {
		t.Fatalf("selected candidate outcome = %q, want %q", got, webresearch.OutcomeOK)
	}
	if got := origins.served(first); got != 1 {
		t.Fatalf("selected candidate served %d requests, want 1", got)
	}
	if got := origins.served(second); got != 0 {
		t.Fatalf("the unselected candidate served %d requests, want 0", got)
	}
	if got := origins.escapes(); len(got) != 0 {
		t.Fatalf("dials outside the controlled origins = %v, want none", got)
	}
}

func TestWebSearchIntegration_ProjectSearchGrantReloadsForItsToolAndHostOnly(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()
	origins := newWebFetchOrigins(t)
	origins.secure(t, "first.test")

	backend := &stubSearchBackend{candidates: searchCandidates("https://first.test/page")}
	approved := newWebSearchHarness(t, project, home, webFetchCache(t, project, true), origins, fixedSearchBackend(backend), denyEveryPrompt)
	approved.prompts.decide = func(req tui.PromptRequest) tui.PromptDecision {
		if req.Host == exaSearchHost {
			return tui.PromptDecision{Option: tui.OptionAllowProject}
		}
		return tui.PromptDecision{Option: tui.OptionAllowOnce}
	}
	if res := approved.search(t, webSearchQuery); res.Denied {
		t.Fatalf("approved web_search was denied; content=%q", res.Content)
	}

	entries := readPersistedPermissions(t, webFetchSettingsPath(project), project)
	if len(entries) != 1 {
		t.Fatalf("persisted permission entries = %d (%+v), want exactly the search-host grant", len(entries), entries)
	}
	if want := wantProjectSearchGrant(exaSearchHost); entries[0] != want {
		t.Fatalf("persisted entry = %+v, want %+v", entries[0], want)
	}
	if entries[0].PathScope != "" {
		t.Fatalf("persisted host grant carries path scope %q, want none", entries[0].PathScope)
	}
	mustNotExist(t, SettingsPath(home), "an allow-in-this-project search approval must never reach the global settings file")

	fresh := newWebSearchHarness(t, project, home, reloadedWebFetchCache(t, project), origins,
		fixedSearchBackend(&stubSearchBackend{candidates: searchCandidates("https://first.test/page")}), denyEveryPrompt)
	reloaded := fresh.search(t, webSearchQuery)
	if reloaded.Denied {
		t.Fatalf("the reloaded project grant did not authorize the search; content=%q", reloaded.Content)
	}
	candidates, _ := decodeSearchResults(t, reloaded.Content, webFetchOutputCap)
	if !slices.Equal(candidateURLs(candidates), []string{"https://first.test/page"}) {
		t.Fatalf("candidates = %v, want the ranked https candidate", candidateURLs(candidates))
	}
	if got := fresh.prompts.hosts(); len(got) != 0 {
		t.Fatalf("prompted hosts after reload = %v, want none (the search grant covers Exa and no candidate is dialed)", got)
	}
	// The reloaded search grant covers Exa only, so reading the candidate it returned still needs
	// its own web_fetch decision — which the deny-all prompt refuses.
	if refused := fresh.fetch(t, "https://first.test/page"); !refused.Denied {
		t.Fatalf("the search grant authorized a candidate read; content=%q", refused.Content)
	}
	if got := fresh.prompts.hosts(); !slices.Equal(got, []string{"first.test"}) {
		t.Fatalf("prompted hosts for the candidate read = %v, want its own exact host", got)
	}
	if got := origins.total(); got != 0 {
		t.Fatalf("candidate origins served %d requests, want 0", got)
	}
	fresh.prompts.reset()

	for _, tc := range []struct{ subject, host, why string }{
		{webFetchToolName, exaSearchHost, "the search grant must not authorize web_fetch on the same host"},
		{webSearchToolName, "other.exa.test", "the search grant must not authorize a sibling host"},
	} {
		req, disp, modeCtx := webSearchHostRequest(tc.subject, tc.host)
		decision, err := fresh.auth.Authorize(context.Background(), req, disp, modeCtx)
		if err != nil {
			t.Fatalf("Authorize(%s %s) error = %v, want nil", tc.subject, tc.host, err)
		}
		if decision.DenyEnvelope == "" {
			t.Fatalf("%s: %s on %s resolved without a fresh decision", tc.why, tc.subject, tc.host)
		}
	}
	if got := len(fresh.prompts.requests()); got != 2 {
		t.Fatalf("cross-tool and sibling-host prompts = %d, want 2 fresh prompts", got)
	}
	if got := readPersistedPermissions(t, webFetchSettingsPath(project), project); len(got) != 1 {
		t.Fatalf("persisted entries after the reload probes = %+v, want only the original search grant", got)
	}
	if got := origins.escapes(); len(got) != 0 {
		t.Fatalf("dials outside the controlled origins = %v, want none", got)
	}
}

// Exa can rank a URL longer than the candidate url field. The real adapter must hand it to the
// capability layer whole, so the model sees it omitted and counted rather than shortened into a
// prefix that names a different fetch target.
func TestWebSearchIntegration_AnOverlongExaResultIsOmittedNotShortened(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()
	origins := newWebFetchOrigins(t)
	source := origins.secure(t, "source.test")

	const prefix = "https://source.test/"
	boundary := prefix + strings.Repeat("a", maxCandidateURLBytes-len(prefix))
	overLong := prefix + strings.Repeat("b", maxCandidateURLBytes-len(prefix)+1)
	fixture := &exaMCPFixture{resultText: exaResultText(overLong, boundary)}
	web := map[string]any{"enabled": true, "timeout_seconds": 5, "max_results": 3}
	h := newWebSearchHarness(t, project, home, webFetchCacheWith(t, project, web), origins,
		realExaBackend(t, fixture, nil), allowOnceEveryPrompt)

	res := h.search(t, webSearchQuery)
	if res.Denied {
		t.Fatalf("approved web_search was denied; content=%q", res.Content)
	}
	candidates, omitted := decodeSearchResults(t, res.Content, webFetchOutputCap)
	if got := candidateURLs(candidates); !slices.Equal(got, []string{boundary}) {
		t.Fatalf("candidate urls = %v, want only the %d-byte result that carries whole", got, len(boundary))
	}
	if omitted != 1 {
		t.Fatalf("omitted = %d, want the over-long Exa result counted as omitted", omitted)
	}
	if strings.Contains(res.Content, overLong[:maxCandidateURLBytes]) {
		t.Fatal("the search result carries a prefix of the over-long Exa result, a target Exa never ranked")
	}

	h.prompts.reset()
	fetched := h.fetch(t, candidateURLs(candidates)[0])
	if fetched.Denied {
		t.Fatalf("the surfaced boundary candidate was denied; content=%q", fetched.Content)
	}
	if got := webFetchOutcome(t, fetched.Content); got != webresearch.OutcomeOK {
		t.Fatalf("boundary candidate outcome = %q, want %q", got, webresearch.OutcomeOK)
	}
	if got := origins.served(source); got != 1 {
		t.Fatalf("the boundary candidate's origin served %d requests, want 1", got)
	}
	if got := origins.escapes(); len(got) != 0 {
		t.Fatalf("dials outside the controlled origins = %v, want none", got)
	}
}

func TestWebSearchIntegration_KeylessAndKeyedSearchesDifferOnlyAtTheOutboundHeader(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()
	origins := newWebFetchOrigins(t)
	source := origins.secure(t, "source.test")

	run := func(t *testing.T, key string) (*exaMCPFixture, *webSearchHarness, turn.ToolResult, exa.Config) {
		t.Helper()
		fixture := &exaMCPFixture{resultText: exaResultText("https://source.test/page")}
		web := map[string]any{"enabled": true, "timeout_seconds": 5, "max_results": 3}
		if key != "" {
			web["api_key"] = key
		}
		var captured exa.Config
		h := newWebSearchHarness(t, project, home, webFetchCacheWith(t, project, web), origins,
			realExaBackend(t, fixture, &captured), allowOnceEveryPrompt)
		res := h.search(t, webSearchQuery)
		if res.Denied {
			t.Fatalf("approved web_search was denied; content=%q", res.Content)
		}
		return fixture, h, res, captured
	}

	keylessFixture, keyless, keylessRes, keylessCfg := run(t, "")
	keyedFixture, keyed, keyedRes, keyedCfg := run(t, webSearchKeySentinel)

	if keylessCfg.APIKey != "" || keyedCfg.APIKey != webSearchKeySentinel {
		t.Fatalf("adapter keys = %q/%q, want empty and the configured key", keylessCfg.APIKey, keyedCfg.APIKey)
	}
	if keylessCfg.MaxResults != keyedCfg.MaxResults || keylessCfg.Timeout != keyedCfg.Timeout || keylessCfg.MaxOutputBytes != keyedCfg.MaxOutputBytes {
		t.Fatalf("adapter configuration %+v differs from %+v beyond the key", keyedCfg, keylessCfg)
	}

	for _, ex := range keylessFixture.exchanges() {
		if len(ex.header.Values("x-api-key")) != 0 {
			t.Fatalf("keyless %s carried a credential header", ex.rpcMethod)
		}
	}
	for _, ex := range keyedFixture.exchanges() {
		if got := ex.header.Get("x-api-key"); got != webSearchKeySentinel {
			t.Fatalf("keyed %s carried key header %q, want the configured key on every request", ex.rpcMethod, got)
		}
	}

	keylessRPC, keyedRPC := keylessFixture.rpcExchanges(), keyedFixture.rpcExchanges()
	if len(keylessRPC) != len(keyedRPC) {
		t.Fatalf("keyed exchanges = %d, want the keyless %d", len(keyedRPC), len(keylessRPC))
	}
	for i := range keylessRPC {
		a, b := keylessRPC[i], keyedRPC[i]
		if a.httpMethod != b.httpMethod || a.rpcMethod != b.rpcMethod || a.params != b.params || a.url != b.url {
			t.Fatalf("exchange %d = %+v, want the keyless exchange %+v", i, b, a)
		}
		stripped := b.header.Clone()
		stripped.Del("x-api-key")
		if !reflect.DeepEqual(stripped, a.header) {
			t.Fatalf("exchange %d headers = %v, want the keyless headers %v apart from x-api-key", i, stripped, a.header)
		}
	}

	if keylessRes.Content != keyedRes.Content {
		t.Fatalf("keyed result = %q, want the keyless result %q", keyedRes.Content, keylessRes.Content)
	}
	if strings.Contains(keyedRes.Content, webSearchKeySentinel) {
		t.Fatalf("search result disclosed the configured key: %s", keyedRes.Content)
	}
	candidates, _ := decodeSearchResults(t, keyedRes.Content, webFetchOutputCap)
	if !slices.Equal(candidateURLs(candidates), []string{"https://source.test/page"}) {
		t.Fatalf("candidates = %v, want the ranked https candidate", candidateURLs(candidates))
	}
	for _, req := range keyed.prompts.requests() {
		if strings.Contains(req.Host, webSearchKeySentinel) || strings.Contains(req.HostRequest, webSearchKeySentinel) {
			t.Fatalf("authorization disclosed the configured key: %+v", req)
		}
	}
	for _, entry := range keyed.cache.Permissions() {
		if strings.Contains(entry.Subject, webSearchKeySentinel) || strings.Contains(entry.HostScope, webSearchKeySentinel) {
			t.Fatalf("grant table disclosed the configured key: %+v", entry)
		}
	}
	for _, ex := range keyedFixture.exchanges() {
		if strings.Contains(ex.url, webSearchKeySentinel) || strings.Contains(ex.params, webSearchKeySentinel) {
			t.Fatalf("outbound URL or parameters disclosed the configured key: %+v", ex)
		}
	}
	if got := origins.served(source); got != 0 {
		t.Fatalf("controlled candidate origin served %d requests, want 0 (neither search reads a candidate)", got)
	}
	if got := origins.escapes(); len(got) != 0 {
		t.Fatalf("dials outside the controlled origins = %v, want none", got)
	}
	wantHosts := []string{exaSearchHost}
	if got := keyless.prompts.hosts(); !slices.Equal(got, wantHosts) {
		t.Fatalf("keyless prompted hosts = %v, want %v", got, wantHosts)
	}
	if got := keyed.prompts.hosts(); !slices.Equal(got, wantHosts) {
		t.Fatalf("keyed prompted hosts = %v, want the keyless %v", got, wantHosts)
	}
}

func TestWebSearchIntegration_SearchReturnsAtMostFiveCandidatesAndDialsNone(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()
	origins := newWebFetchOrigins(t)

	var urls []string
	var labels []string
	for i := 1; i <= 5; i++ {
		host := fmt.Sprintf("kept%d.test", i)
		labels = append(labels, origins.secure(t, host))
		urls = append(urls, "https://"+host+"/page")
	}
	// The plain-http and over-limit candidates are deliberately unmapped, so any fetch of one
	// registers as an escape from the controlled network rather than passing silently.
	urls = append(urls, "http://plain.test/page", "https://sixth.test/page", "https://seventh.test/page")

	backend := &stubSearchBackend{candidates: searchCandidates(urls...)}
	h := newWebSearchHarness(t, project, home, webFetchCache(t, project, true), origins, fixedSearchBackend(backend), allowOnceEveryPrompt)

	res := h.search(t, webSearchQuery)
	if res.Denied {
		t.Fatalf("approved web_search was denied; content=%q", res.Content)
	}
	// The bound is spelled out rather than read from maxSearchCandidates, so raising the production
	// constant fails this test instead of moving its expectation with it.
	candidates, omitted := decodeSearchResults(t, res.Content, webFetchOutputCap)
	if len(candidates) != 5 {
		t.Fatalf("candidates = %d (%v), want the five-candidate cap", len(candidates), candidateURLs(candidates))
	}
	if !slices.Equal(candidateURLs(candidates), urls[:5]) {
		t.Fatalf("candidates = %v, want the first five ranked https candidates", candidateURLs(candidates))
	}
	if omitted != 2 {
		t.Fatalf("omitted = %d, want 2 (the over-limit https candidates)", omitted)
	}
	if got := origins.total(); got != 0 {
		t.Fatalf("candidate requests = %d, want 0 (a search reads nothing)", got)
	}
	for _, label := range labels {
		if got := origins.served(label); got != 0 {
			t.Fatalf("%s served %d requests, want 0", label, got)
		}
	}
	if got := h.prompts.hosts(); !slices.Equal(got, []string{exaSearchHost}) {
		t.Fatalf("prompted hosts = %v, want only the Exa search authorization", got)
	}
	if got := origins.escapes(); len(got) != 0 {
		t.Fatalf("dials outside the controlled origins = %v, want none (no candidate is dialed at all)", got)
	}
}

// --- production plan serialization ------------------------------------------

type serializedSearchBackend struct {
	hold time.Duration

	mu      sync.Mutex
	live    int
	peak    int
	queries []string
}

func (b *serializedSearchBackend) Search(_ context.Context, query string) ([]webresearch.Candidate, error) {
	b.mu.Lock()
	b.live++
	if b.live > b.peak {
		b.peak = b.live
	}
	b.queries = append(b.queries, query)
	b.mu.Unlock()
	time.Sleep(b.hold)
	b.mu.Lock()
	b.live--
	b.mu.Unlock()
	return searchCandidates("https://" + query + ".test/page"), nil
}

func (b *serializedSearchBackend) counts() (calls, peak int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.queries), b.peak
}

func twoSearchClient(first, second string) *stubTurnClient {
	var round int32
	return &stubTurnClient{fn: func(context.Context, provider.Request) (provider.Response, error) {
		if atomic.AddInt32(&round, 1) == 1 {
			return provider.Response{Stream: newStream(toolCallsChunk(
				toolFrag(0, "call_1", webSearchToolName, `{"query":"`+first+`"}`),
				toolFrag(1, "call_2", webSearchToolName, `{"query":"`+second+`"}`),
			))}, nil
		}
		return provider.Response{Stream: newStream(contentChunk("ok"), finishChunk("stop"))}, nil
	}}
}

func TestWebSearchIntegration_WebSearchBatchStaysSerializedUnderConfiguredConcurrency(t *testing.T) {
	for _, concurrency := range []int{4, 1} {
		t.Run(fmt.Sprintf("max_concurrency %d", concurrency), func(t *testing.T) {
			backend := &serializedSearchBackend{hold: 30 * time.Millisecond}
			defer swapSearchBackend(fixedSearchBackend(backend))()

			client := twoSearchClient("alpha", "beta")
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			composed := headlessProviderConfig()
			composed["web_research"] = map[string]any{"enabled": true, "timeout_seconds": 5}
			composed["permissions"] = webSearchProjectGrant()
			composed["agent"] = map[string]any{"max_concurrency": concurrency}

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("research both", &stdout, &stderr)
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Build, mode.SourceDefault))
			result.Config = composed

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := driver.Run(ctx, result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			calls, peak := backend.counts()
			if calls != 2 {
				t.Fatalf("backend searches = %d, want 2", calls)
			}
			if peak != 1 {
				t.Fatalf("peak concurrent searches = %d, want 1 (the production plan serializes every web-tool batch)", peak)
			}
			toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
			if len(toolMsgs) != 2 {
				t.Fatalf("durable tool messages = %d, want 2", len(toolMsgs))
			}
			for i, want := range []string{"https://alpha.test/page", "https://beta.test/page"} {
				candidates, _ := decodeSearchResults(t, toolMsgs[i].Content.Text(), webFetchOutputCap)
				if !slices.Equal(candidateURLs(candidates), []string{want}) {
					t.Fatalf("tool result %d candidates = %v, want %q (results keep model-call order)", i, candidateURLs(candidates), want)
				}
			}
		})
	}
}

func TestWebSearchIntegration_ConcurrentWebResearchPromptsSerialize(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()

	authorizerFor := func(probe *promptProbe) *productionAuthorizer {
		store := mkStore(t)
		app := tui.New(nil)
		app.SetActiveStore(store)
		return newProductionAuthorizer(app, emptyCache(t, project), permissions.NewTurnCache(),
			newPromptGateBuilder(probe.show), home, project, mode.NewActiveState(mode.Build, mode.SourceDefault))
	}

	// The per-identity in-flight lock keys on subject, not host, so two web_fetch hosts would
	// serialize without ever reaching the gate; distinct subjects leave the shared gate as the
	// only thing that can keep the two prompts apart.
	probe := &promptProbe{}
	auth := authorizerFor(probe)
	requests := []struct{ subject, host string }{
		{webSearchToolName, exaSearchHost},
		{webFetchToolName, "source.test"},
	}
	var wg sync.WaitGroup
	for _, tc := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, disp, modeCtx := webSearchHostRequest(tc.subject, tc.host)
			if _, err := auth.Authorize(context.Background(), req, disp, modeCtx); err != nil {
				t.Errorf("Authorize(%s %s) error = %v, want nil", tc.subject, tc.host, err)
			}
		}()
	}
	wg.Wait()
	shown, peak := probe.counts()
	if shown != 2 {
		t.Fatalf("prompts shown = %d, want 2 (one per distinct web-research request)", shown)
	}
	if peak != 1 {
		t.Fatalf("peak prompts on screen = %d, want 1 (the shared gate serializes them)", peak)
	}

	release := make(chan struct{})
	held := &promptProbe{opened: make(chan struct{})}
	held.whileHeld = func(*sessions.Store) { <-release }
	gated := authorizerFor(held)

	var first sync.WaitGroup
	first.Add(1)
	go func() {
		defer first.Done()
		req, disp, modeCtx := webSearchHostRequest(webSearchToolName, exaSearchHost)
		if _, err := gated.Authorize(context.Background(), req, disp, modeCtx); err != nil {
			t.Errorf("held Authorize error = %v, want nil", err)
		}
	}()
	<-held.opened

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	req, disp, modeCtx := webSearchHostRequest(webFetchToolName, "queued.test")
	if _, err := gated.Authorize(cancelled, req, disp, modeCtx); err == nil {
		t.Fatal("a cancelled queued authorization resolved, want the cancellation error")
	}
	if shown, _ := held.counts(); shown != 1 {
		t.Fatalf("prompts shown while one was held = %d, want 1 (a cancelled queued request shows none)", shown)
	}
	close(release)
	first.Wait()
	shown, peak = held.counts()
	if shown != 1 || peak != 1 {
		t.Fatalf("prompts shown/peak = %d/%d, want 1/1", shown, peak)
	}
}

func requestText(req provider.Request) string {
	var b strings.Builder
	for _, m := range req.Messages {
		b.WriteString(m.Role + "\n" + m.Content + "\n")
		for _, part := range m.Parts {
			b.WriteString(part.Text + "\n" + part.ImageURL + "\n")
		}
		for _, tc := range m.ToolCalls {
			b.WriteString(tc.Name + "\n" + tc.Arguments + "\n")
		}
	}
	return b.String()
}

func TestWebSearchIntegration_FailedSearchContinuesToTheNextModelRound(t *testing.T) {
	for _, tc := range []struct {
		name          string
		fixture       *exaMCPFixture
		wantToolCalls int
		wantContent   string
		leaks         []string
	}{
		{
			name: "upstream failure",
			fixture: &exaMCPFixture{
				toolStatus: http.StatusInternalServerError,
				toolBody:   `{"error":"key ` + webSearchKeySentinel + ` rejected: ` + webSearchBodySentinel + `"}`,
			},
			wantToolCalls: 2,
			wantContent:   "exa: the search request failed",
			leaks:         []string{webSearchKeySentinel, webSearchBodySentinel, exaSearchHost, "request failed with status 500"},
		},
		{
			name:          "no usable result",
			fixture:       &exaMCPFixture{},
			wantToolCalls: 1,
			wantContent:   "exa: the search response held no usable result",
			leaks:         []string{webSearchKeySentinel, exaSearchHost},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer swapSearchBackend(realExaBackend(t, tc.fixture, nil))()

			const answer = "the search did not come back, so here is what I already know"
			var mu sync.Mutex
			var requests []provider.Request
			var round int32
			client := &stubTurnClient{title: streamedTitle("Model title"), fn: func(_ context.Context, req provider.Request) (provider.Response, error) {
				mu.Lock()
				requests = append(requests, req)
				mu.Unlock()
				if atomic.AddInt32(&round, 1) == 1 {
					return provider.Response{Stream: newStream(toolCallsChunk(
						toolFrag(0, "call_1", webSearchToolName, `{"query":"`+webSearchQuery+`"}`),
					))}, nil
				}
				return provider.Response{Stream: newStream(contentChunk(answer), finishChunk("stop"))}, nil
			}}
			defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()

			composed := headlessProviderConfig()
			composed["web_research"] = map[string]any{
				"enabled": true, "timeout_seconds": 5, "max_results": 3, "api_key": webSearchKeySentinel,
			}
			composed["permissions"] = webSearchProjectGrant()

			var stdout, stderr bytes.Buffer
			driver := NewHeadlessDriver("research this", &stdout, &stderr)
			dir := filepath.Join(t.TempDir(), "project-500")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			result := headlessResult(t, dir, mode.NewActiveState(mode.Build, mode.SourceDefault))
			result.Config = composed

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := driver.Run(ctx, result); err != nil {
				t.Fatalf("driver.Run: %v", err)
			}

			if got := tc.fixture.toolCalls(); got != tc.wantToolCalls {
				t.Fatalf("tools/call attempts = %d, want %d (only the adapter's own bounded retry, and no provider-round retry)", got, tc.wantToolCalls)
			}
			if got := client.callCount(); got != 2 {
				t.Fatalf("provider rounds = %d, want 2 (a failed search continues to the next model round)", got)
			}

			recs := reloadStore(t, result.Session)
			toolMsgs := messagesByRole(recs, "tool")
			if len(toolMsgs) != 1 {
				t.Fatalf("durable tool messages = %+v, want exactly one answering the single web_search call", toolMsgs)
			}
			content := toolMsgs[0].Content.Text()
			if content != tc.wantContent {
				t.Fatalf("durable tool result = %q, want the bounded search failure %q", content, tc.wantContent)
			}
			surfaced := stdout.String() + stderr.String()
			if !strings.Contains(surfaced, tc.wantContent) {
				t.Fatalf("user-visible output = %q, want the bounded failure surfaced", surfaced)
			}

			mu.Lock()
			continuation := requestText(requests[1])
			mu.Unlock()
			if !strings.Contains(continuation, content) {
				t.Fatalf("continuation request = %q, want the bounded failure in model context", continuation)
			}
			if wd := mustCanonical(t, dir); !strings.Contains(continuation, wd) {
				t.Fatalf("continuation request = %q, want the working directory %q", continuation, wd)
			}
			for _, leak := range tc.leaks {
				if strings.Contains(content, leak) || strings.Contains(surfaced, leak) || strings.Contains(continuation, leak) {
					t.Fatalf("failed search disclosed %q; result=%q output=%q continuation=%q", leak, content, surfaced, continuation)
				}
			}
			var final string
			for _, msg := range messagesByRole(recs, "assistant") {
				if len(msg.ToolCalls) == 0 {
					final = msg.Content.Text()
				}
			}
			if final != answer {
				t.Fatalf("final assistant text = %q, want the answer the model produced after the failed search", final)
			}
		})
	}
}

func TestWebSearchIntegration_RateLimitedSearchReturnsABoundedCredentialSafeOutcome(t *testing.T) {
	project := webFetchProject(t)
	home := t.TempDir()
	origins := newWebFetchOrigins(t)

	fixture := &exaMCPFixture{
		toolStatus: http.StatusTooManyRequests,
		toolBody:   `{"error":"key ` + webSearchKeySentinel + ` over quota: ` + webSearchBodySentinel + `"}`,
	}
	cache := webFetchCacheWith(t, project, map[string]any{
		"enabled": true, "timeout_seconds": 5, "max_results": 3, "api_key": webSearchKeySentinel,
	})
	h := newWebSearchHarness(t, project, home, cache, origins, realExaBackend(t, fixture, nil), allowOnceEveryPrompt)

	res := h.search(t, webSearchQuery)
	if res.Denied {
		t.Fatalf("a rate-limited search returned a deny envelope, want a bounded in-band failure; content=%q", res.Content)
	}
	if len(res.Content) > webFetchOutputCap {
		t.Fatalf("rate-limited result is %d bytes, want <= the %d-byte output cap", len(res.Content), webFetchOutputCap)
	}
	if !strings.Contains(res.Content, "reached its limit") {
		t.Fatalf("rate-limited result = %q, want the user-account-limit outcome", res.Content)
	}
	for _, leak := range []string{webSearchKeySentinel, webSearchBodySentinel, exaSearchHost, "429"} {
		if strings.Contains(res.Content, leak) {
			t.Fatalf("rate-limited result disclosed %q: %s", leak, res.Content)
		}
	}
	if got := fixture.toolCalls(); got != 1 {
		t.Fatalf("tools/call attempts = %d, want 1 (a rate limit is never retried)", got)
	}
	if got := origins.total(); got != 0 {
		t.Fatalf("source requests after a failed search = %d, want 0", got)
	}
	if got := h.prompts.hosts(); !slices.Equal(got, []string{exaSearchHost}) {
		t.Fatalf("prompted hosts = %v, want only the search authorization", got)
	}
	if got := origins.escapes(); len(got) != 0 {
		t.Fatalf("dials outside the controlled origins = %v, want none", got)
	}
}
