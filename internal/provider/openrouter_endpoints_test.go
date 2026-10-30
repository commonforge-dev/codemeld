package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const endpointsKey = "or-secret-key"

func endpointsEntry(baseURL string) ProviderEntry {
	return ProviderEntry{BaseURL: baseURL, APIKey: endpointsKey}
}

func fetchEndpoints(t *testing.T, srv *httptest.Server, model string) ([]openRouterEndpoint, error) {
	t.Helper()
	endpoints, _, err := fetchOpenRouterEndpoints(context.Background(), srv.Client(), endpointsEntry(srv.URL+"/api/v1/"), "Authorization", "Bearer "+endpointsKey, model)
	return endpoints, err
}

func endpointsBody(p50s ...any) string {
	var parts []string
	for i, p := range p50s {
		tp := "null"
		if p != nil {
			tp = fmt.Sprintf(`{"p50":%v,"p75":1,"p90":1,"p99":1}`, p)
		}
		parts = append(parts, fmt.Sprintf(`{"provider_name":"p%d","tag":"p%d/%v","pricing":{"prompt":"0.000001","completion":"0.000002"},"throughput_last_30m":%s}`, i, i, p, tp))
	}
	return `{"data":{"endpoints":[` + strings.Join(parts, ",") + `]}}`
}

func TestFetchOpenRouterEndpoints_ParsesPricesAndThroughput(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.EscapedPath()
		_, _ = io.WriteString(w, `{"data":{"endpoints":[
			{"provider_name":"Inception","tag":"inception/fp8/us","quantization":"fp8","pricing":{"prompt":"0.00000004","completion":"0.00000015","discount":0.8},"throughput_last_30m":{"p50":512.5,"p75":400,"p90":300,"p99":100}},
			{"provider_name":"Slow","pricing":{"prompt":"0.0000001","completion":"0.0000003"},"throughput_last_30m":null},
			{"provider_name":"Broken","pricing":{"prompt":"n/a","completion":"0.0000003"},"throughput_last_30m":{"p50":9}}
		]}}`)
	}))
	t.Cleanup(srv.Close)

	got, err := fetchEndpoints(t, srv, "inception/mercury-2.5")
	if err != nil {
		t.Fatalf("fetch error = %v", err)
	}
	want := []openRouterEndpoint{
		{ProviderName: "Inception", Tag: "inception/fp8/us", PromptPerM: 0.04, CompletionPerM: 0.15, P50Throughput: 512.5, HasThroughput: true, Quantization: "fp8"},
		{ProviderName: "Slow", PromptPerM: 0.1, CompletionPerM: 0.3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoints = %#v, want %#v", got, want)
	}
	if gotAuth != "Bearer "+endpointsKey {
		t.Fatalf("Authorization = %q, want the configured key", gotAuth)
	}
	if gotPath != "/api/v1/models/inception/mercury-2.5/endpoints" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestFetchOpenRouterEndpoints_EscapesModelSegments(t *testing.T) {
	cases := map[string]string{
		"meta-llama/llama-3.3-70b-instruct:free": "/api/v1/models/meta-llama/llama-3.3-70b-instruct:free/endpoints",
		"org/we?ird id":                          "/api/v1/models/org/we%3Fird%20id/endpoints",
	}
	for model, want := range cases {
		t.Run(model, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.EscapedPath()
				_, _ = io.WriteString(w, `{"data":{"endpoints":[]}}`)
			}))
			t.Cleanup(srv.Close)
			if _, err := fetchEndpoints(t, srv, model); err != nil {
				t.Fatalf("fetch error = %v", err)
			}
			if gotPath != want {
				t.Fatalf("path = %q, want %q", gotPath, want)
			}
		})
	}
}

func TestFetchOpenRouterEndpoints_RedirectNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			leaked.Store(true)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	_, err := fetchEndpoints(t, srv, "m")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusFound {
		t.Fatalf("error = %v, want HTTPError 302", err)
	}
	if leaked.Load() {
		t.Fatalf("redirect was followed and the key re-sent")
	}
}

func TestFetchOpenRouterEndpoints_ErrorCarriesNoBodyOrKey(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "bad key "+endpointsKey+" provider-prose")
	}))
	t.Cleanup(srv.Close)
	_, err := fetchEndpoints(t, srv, "m")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusUnauthorized || httpErr.Body != "" {
		t.Fatalf("error = %#v, want body-free HTTPError 401", err)
	}
	if strings.Contains(err.Error(), endpointsKey) || strings.Contains(err.Error(), "provider-prose") {
		t.Fatalf("error %q leaks the body or key", err)
	}
}

func TestFetchOpenRouterEndpoints_OversizedResponseFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"endpoints":[{"provider_name":"marker-provider","pricing":{"prompt":"0.000001","completion":"0.000001"},"throughput_last_30m":{"p50":5}}]},"pad":"`)
		_, _ = io.WriteString(w, strings.Repeat("x", maxOpenRouterEndpointsBytes))
		_, _ = io.WriteString(w, `"}`)
	}))
	t.Cleanup(srv.Close)
	got, err := fetchEndpoints(t, srv, "m")
	if err == nil || got != nil {
		t.Fatalf("fetch = %#v, %v; want an error and no endpoints", got, err)
	}
	if strings.Contains(err.Error(), "marker-provider") || strings.Contains(err.Error(), "xxxx") {
		t.Fatalf("error %q carries the body", err)
	}
}

func TestOpenRouterSpeedBar(t *testing.T) {
	ep := func(p50s ...float64) []openRouterEndpoint {
		var out []openRouterEndpoint
		for _, p := range p50s {
			out = append(out, openRouterEndpoint{P50Throughput: p, HasThroughput: true})
		}
		return append(out, openRouterEndpoint{})
	}
	cases := []struct {
		name      string
		endpoints []openRouterEndpoint
		want      float64
		wantOK    bool
	}{
		{"one provider", ep(70), 70, true},
		{"odd count", ep(90, 10, 50), 50, true},
		{"even count takes lower middle", ep(80, 20, 60, 40), 40, true},
		{"two providers", ep(100, 30), 30, true},
		{"no throughput", ep(), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := openRouterSpeedBar(tc.endpoints)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("speed bar = %v, %v; want %v, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

type endpointsServer struct {
	srv     *httptest.Server
	hits    atomic.Int32
	mu      sync.Mutex
	status  int
	body    string
	entered chan struct{}
	release chan struct{}
}

func newEndpointsServer(t *testing.T, body string) *endpointsServer {
	t.Helper()
	s := &endpointsServer{status: http.StatusOK, body: body}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		status, body, entered, release := s.status, s.body, s.entered, s.release
		s.mu.Unlock()
		if entered != nil {
			entered <- struct{}{}
			<-release
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *endpointsServer) set(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

func (s *endpointsServer) block() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered, s.release = make(chan struct{}, 1), make(chan struct{})
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestStore(s *endpointsServer) (*OpenRouterEndpointStore, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	return &OpenRouterEndpointStore{HTTPClient: s.srv.Client(), Now: clock.Now}, clock
}

func lookupTag(ctx context.Context, store *OpenRouterEndpointStore, baseURL, model string) string {
	return store.BestValueTag(ctx, endpointsEntry(baseURL), "Authorization", "Bearer "+endpointsKey, model, "", nil)
}

func expectLookup(t *testing.T, store *OpenRouterEndpointStore, s *endpointsServer, baseURL, wantTag string, wantHits int32) {
	t.Helper()
	if tag := lookupTag(context.Background(), store, baseURL, "m"); tag != wantTag {
		t.Fatalf("BestValueTag = %q, want %q", tag, wantTag)
	}
	if got := s.hits.Load(); got != wantHits {
		t.Fatalf("endpoint requests = %d, want %d", got, wantHits)
	}
}

func TestOpenRouterEndpointStore_SuccessCachedTwelveHours(t *testing.T) {
	s := newEndpointsServer(t, endpointsBody(10, 30, 20))
	store, clock := newTestStore(s)
	expectLookup(t, store, s, s.srv.URL, "p1/30", 1)
	clock.advance(12*time.Hour - time.Second)
	expectLookup(t, store, s, s.srv.URL, "p1/30", 1)
	s.set(http.StatusOK, endpointsBody(50))
	clock.advance(time.Second)
	expectLookup(t, store, s, s.srv.URL, "p0/50", 2)
}

func TestOpenRouterEndpointStore_FailureRetriedAfterFifteenMinutes(t *testing.T) {
	s := newEndpointsServer(t, "")
	s.set(http.StatusServiceUnavailable, "down")
	store, clock := newTestStore(s)
	expectLookup(t, store, s, s.srv.URL, "", 1)
	clock.advance(15*time.Minute - time.Second)
	expectLookup(t, store, s, s.srv.URL, "", 1)
	s.set(http.StatusOK, endpointsBody(40))
	clock.advance(time.Second)
	expectLookup(t, store, s, s.srv.URL, "p0/40", 2)
}

func TestOpenRouterEndpointStore_NoBarSuccessCachedTwelveHours(t *testing.T) {
	for name, body := range map[string]string{
		"empty list":       `{"data":{"endpoints":[]}}`,
		"all null p50 set": endpointsBody(nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			s := newEndpointsServer(t, body)
			store, clock := newTestStore(s)
			expectLookup(t, store, s, s.srv.URL, "", 1)
			clock.advance(12*time.Hour - time.Second)
			expectLookup(t, store, s, s.srv.URL, "", 1)
			clock.advance(time.Second)
			expectLookup(t, store, s, s.srv.URL, "", 2)
		})
	}
}

func TestOpenRouterEndpointStore_KeyedByBaseURL(t *testing.T) {
	first := newEndpointsServer(t, endpointsBody(10))
	second := newEndpointsServer(t, endpointsBody(99))
	store, _ := newTestStore(first)
	expectLookup(t, store, first, first.srv.URL, "p0/10", 1)
	expectLookup(t, store, first, first.srv.URL+"/", "p0/10", 1)
	store.HTTPClient = second.srv.Client()
	expectLookup(t, store, second, second.srv.URL, "p0/99", 1)
}

func TestOpenRouterEndpointStore_ConcurrentLookupsShareOneFetch(t *testing.T) {
	s := newEndpointsServer(t, endpointsBody(10, 30, 20))
	s.block()
	store, _ := newTestStore(s)

	const n = 8
	results := make(chan string, n)
	for range n {
		go func() {
			results <- lookupTag(context.Background(), store, s.srv.URL, "m")
		}()
	}
	<-s.entered
	time.Sleep(20 * time.Millisecond)
	close(s.release)
	for range n {
		if tag := <-results; tag != "p1/30" {
			t.Fatalf("BestValueTag = %q, want p1/30", tag)
		}
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("endpoint requests = %d, want 1", got)
	}
}

func TestOpenRouterEndpointStore_WaiterGivesUpWithoutCancellingOwner(t *testing.T) {
	for name, newCtx := range map[string]func() (context.Context, context.CancelFunc){
		"cancelled": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		},
		"timed out": func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 10*time.Millisecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			waiterCtx, cancel := newCtx()
			defer cancel()
			s := newEndpointsServer(t, endpointsBody(10, 30, 20))
			s.block()
			store, _ := newTestStore(s)

			ownerDone := make(chan string, 1)
			go func() {
				ownerDone <- lookupTag(context.Background(), store, s.srv.URL, "m")
			}()
			<-s.entered

			if tag := lookupTag(waiterCtx, store, s.srv.URL, "m"); tag != "" {
				t.Fatalf("waiter BestValueTag = %q, want none", tag)
			}
			close(s.release)
			if tag := <-ownerDone; tag != "p1/30" {
				t.Fatalf("owner BestValueTag = %q, want p1/30", tag)
			}
			expectLookup(t, store, s, s.srv.URL, "p1/30", 1)
		})
	}
}

func TestOpenRouterBestValue(t *testing.T) {
	ep := func(tag string, total, p50 float64) openRouterEndpoint {
		return openRouterEndpoint{Tag: tag, PromptPerM: total, P50Throughput: p50, HasThroughput: true}
	}
	noSpeed := func(tag string, total float64) openRouterEndpoint {
		return openRouterEndpoint{Tag: tag, PromptPerM: total}
	}
	cluster := []openRouterEndpoint{
		ep("slow/fp8", 0.40, 50),
		ep("relace", 0.57, 127),
		ep("wafer/nvfp4", 0.66, 154),
		ep("pricey/fp8", 2.0, 300),
	}
	cases := []struct {
		name      string
		endpoints []openRouterEndpoint
		ignored   []string
		want      string
	}{
		{"faster endpoint within 20% wins over the cheapest", cluster, nil, "wafer/nvfp4"},
		{"exactly 1.2x the cheapest is eligible", []openRouterEndpoint{ep("cheap", 1.0, 100), ep("edge", 1.2, 200)}, nil, "edge"},
		{"one price unit above 1.2x is not", []openRouterEndpoint{ep("cheap", 1.0, 100), ep("edge", 1.2001, 200)}, nil, "cheap"},
		{
			"below the bar or without speed data is never picked nor sets the cheapest price",
			[]openRouterEndpoint{ep("below", 0.1, 10), noSpeed("unknown", 0.05), ep("bar", 0.5, 50), ep("faster", 0.55, 60)}, nil, "faster",
		},
		{"ignored base slug skips its endpoints", cluster, []string{"wafer"}, "relace"},
		{"ignored full tag skips its endpoint", cluster, []string{"wafer/nvfp4"}, "relace"},
		{"ignored slug matches only a whole first segment", cluster, []string{"waf"}, "wafer/nvfp4"},
		{"equal speed picks the cheaper", []openRouterEndpoint{ep("dear", 1.1, 100), ep("thrifty", 1.0, 100)}, nil, "thrifty"},
		{"equal speed and price keep the first listed", []openRouterEndpoint{ep("first", 1.0, 100), ep("second", 1.0, 100)}, nil, "first"},
		{
			"equal speed and decimal-equal split prices keep the first listed",
			[]openRouterEndpoint{
				{Tag: "first", PromptPerM: 0.1, CompletionPerM: 0.2, P50Throughput: 100, HasThroughput: true},
				{Tag: "second", PromptPerM: 0.15, CompletionPerM: 0.15, P50Throughput: 100, HasThroughput: true},
			}, nil, "first",
		},
		{"no speed data picks nothing", []openRouterEndpoint{noSpeed("a", 1.0), noSpeed("b", 2.0)}, nil, ""},
		{"empty list picks nothing", []openRouterEndpoint{}, nil, ""},
		{"nil list picks nothing", nil, nil, ""},
		{
			"missing tags neither win nor lower the cheapest price",
			[]openRouterEndpoint{ep("", 0.1, 100), ep("tagged", 0.5, 100), ep("faster", 0.58, 120)}, nil, "faster",
		},
		{"all tags missing picks nothing", []openRouterEndpoint{ep("", 0.1, 100), ep("", 0.5, 120)}, nil, ""},
		{"multi-segment tag is returned intact", []openRouterEndpoint{ep("baseten/fp8/us", 1.0, 100), ep("other", 1.0, 50)}, nil, "baseten/fp8/us"},
		{"ignored base slug matches a multi-segment tag", []openRouterEndpoint{ep("baseten/fp8/us", 1.0, 100), ep("other", 1.0, 100)}, []string{"baseten"}, "other"},
		{"partial multi-segment prefix is not ignored", []openRouterEndpoint{ep("baseten/fp8/us", 1.0, 100), ep("other", 1.0, 100)}, []string{"baseten/fp8"}, "baseten/fp8/us"},
		{"bound holds for totals whose multiples overflow int64", []openRouterEndpoint{ep("cheap", 8e14, 100), ep("fast", 9e14, 200)}, nil, "fast"},
		{"bound excludes for totals whose multiples overflow int64", []openRouterEndpoint{ep("cheap", 7e14, 100), ep("fast", 9e14, 200)}, nil, "cheap"},
		{"negative cheapest total admits nothing", []openRouterEndpoint{ep("credit", -1.0, 100), ep("smaller", -0.5, 200)}, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := openRouterBestValue(tc.endpoints, tc.ignored)
			if got.Tag != tc.want || ok != (tc.want != "") {
				t.Fatalf("pick = %q, %v; want %q", got.Tag, ok, tc.want)
			}
		})
	}
}

var levelHosts = []openRouterEndpoint{
	{Tag: "x/fp8", Quantization: "fp8", PromptPerM: 1.5, P50Throughput: 50, HasThroughput: true},
	{Tag: "y/mxfp8", Quantization: "mxfp8", PromptPerM: 1.0, P50Throughput: 40, HasThroughput: true},
	{Tag: "z/fp4", Quantization: "fp4", PromptPerM: 0.1, P50Throughput: 200, HasThroughput: true},
	{Tag: "w/nvfp4", Quantization: "nvfp4", PromptPerM: 0.1, P50Throughput: 300, HasThroughput: true},
	{Tag: "v/bf16", Quantization: "bf16", PromptPerM: 0.1, P50Throughput: 250, HasThroughput: true},
	{Tag: "u", Quantization: "unknown", PromptPerM: 5.0, P50Throughput: 10, HasThroughput: true},
	{Tag: "n", PromptPerM: 0.1, P50Throughput: 20, HasThroughput: true},
}

func TestOpenRouterBestValueTag_RestrictedToLevel(t *testing.T) {
	cases := []struct {
		level string
		want  string
	}{
		{"", "w/nvfp4"},
		{"fp8", "y/mxfp8"},
		{"mxfp8", "y/mxfp8"},
		{"fp4", "w/nvfp4"},
		{"nvfp4", "w/nvfp4"},
		{"mxfp4", ""},
		{"bf16", "v/bf16"},
		{"unknown", "u"},
		{"int8", ""},
	}
	for _, tc := range cases {
		t.Run("level="+tc.level, func(t *testing.T) {
			if got := openRouterBestValueTag(levelHosts, tc.level, nil); got != tc.want {
				t.Fatalf("tag = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenRouterEndpointStore_LevelLookupsShareFetchAndKeepCache(t *testing.T) {
	var parts []string
	for _, e := range levelHosts {
		parts = append(parts, fmt.Sprintf(`{"provider_name":%q,"tag":%q,"quantization":%q,"pricing":{"prompt":"%.7f","completion":"0"},"throughput_last_30m":{"p50":%v}}`,
			e.Tag, e.Tag, e.Quantization, e.PromptPerM/1e6, e.P50Throughput))
	}
	s := newEndpointsServer(t, `{"data":{"endpoints":[`+strings.Join(parts, ",")+`]}}`)
	store, _ := newTestStore(s)
	entry := endpointsEntry(s.srv.URL)
	for _, tc := range []struct{ level, want string }{{"fp8", "y/mxfp8"}, {"fp4", "w/nvfp4"}, {"", "w/nvfp4"}} {
		if got := store.BestValueTag(context.Background(), entry, "Authorization", "Bearer "+endpointsKey, "m", tc.level, nil); got != tc.want {
			t.Fatalf("BestValueTag(level %q) = %q, want %q", tc.level, got, tc.want)
		}
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("endpoint requests = %d, want 1", got)
	}
	cached := store.entries[openRouterKey(entry, "m")].endpoints
	var tags []string
	for _, e := range cached {
		tags = append(tags, e.Tag+"="+e.Quantization)
	}
	want := []string{"x/fp8=fp8", "y/mxfp8=mxfp8", "z/fp4=fp4", "w/nvfp4=nvfp4", "v/bf16=bf16", "u=unknown", "n="}
	if !reflect.DeepEqual(tags, want) {
		t.Fatalf("cached endpoints = %q, want %q", tags, want)
	}
}

const quantizationBody = `{"data":{"endpoints":[
	{"provider_name":"a","tag":"a/fp8","quantization":"fp8","pricing":{"prompt":"0.0000003","completion":"0.0000004"},"throughput_last_30m":{"p50":10}},
	{"provider_name":"b","tag":"b/fp8","quantization":"fp8","pricing":{"prompt":"0.0000001","completion":"0.0000002","discount":0.5},"throughput_last_30m":{"p50":90}},
	{"provider_name":"broken","tag":"broken/fp8","quantization":"fp8","pricing":{"prompt":"n/a","completion":"0"},"throughput_last_30m":{"p50":900}},
	{"provider_name":"c","tag":"c/nvfp4","quantization":"nvfp4","pricing":{"prompt":"0.000001","completion":"0.000001"},"throughput_last_30m":{"p50":5}},
	{"provider_name":"d","tag":"d","quantization":"unknown","pricing":{"prompt":"0.000002","completion":"0.000002"},"throughput_last_30m":{"p50":5}},
	{"provider_name":"e","tag":"e","quantization":"","pricing":{"prompt":"0.000002","completion":"0.000002"},"throughput_last_30m":{"p50":5}},
	{"provider_name":"f","tag":"f","pricing":{"prompt":"bad","completion":"0.000002"},"throughput_last_30m":{"p50":5}}
]}}`

const quantizationBestTag = "b/fp8"

func awaitFetched(t *testing.T, fetched chan struct{}) {
	t.Helper()
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("background fetch did not report completion")
	}
}

func countsNow(store *OpenRouterEndpointStore, baseURL string) (map[string]int, OpenRouterHostsState, chan struct{}) {
	fetched := make(chan struct{})
	counts, state := store.QuantizationCounts(endpointsEntry(baseURL), "Authorization", "Bearer "+endpointsKey, "m", func() { close(fetched) })
	return counts, state, fetched
}

func expectCounts(t *testing.T, store *OpenRouterEndpointStore, s *endpointsServer, want map[string]int, wantState OpenRouterHostsState, wantHits int32) {
	t.Helper()
	counts, state, _ := countsNow(store, s.srv.URL)
	if state != wantState || !reflect.DeepEqual(counts, want) {
		t.Fatalf("QuantizationCounts = %v, %v; want %v, %v", counts, state, want, wantState)
	}
	if got := s.hits.Load(); got != wantHits {
		t.Fatalf("endpoint requests = %d, want %d", got, wantHits)
	}
}

func TestOpenRouterEndpointStore_QuantizationCountsTallyEveryHostButKeepPricedEligibility(t *testing.T) {
	s := newEndpointsServer(t, quantizationBody)
	store, _ := newTestStore(s)

	counts, state, fetched := countsNow(store, s.srv.URL)
	if state != OpenRouterHostsPending || counts != nil {
		t.Fatalf("QuantizationCounts before any fetch = %v, %v; want pending", counts, state)
	}
	awaitFetched(t, fetched)
	expectCounts(t, store, s, map[string]int{"fp8": 3, "nvfp4": 1, "unknown": 1, "": 2}, OpenRouterHostsReady, 1)

	var tags []string
	for _, e := range store.entries[openRouterKey(endpointsEntry(s.srv.URL), "m")].endpoints {
		tags = append(tags, e.Tag)
	}
	if want := []string{"a/fp8", "b/fp8", "c/nvfp4", "d", "e"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("price-eligible endpoints = %q, want %q", tags, want)
	}
	expectLookup(t, store, s, s.srv.URL, quantizationBestTag, 1)
}

func TestOpenRouterEndpointStore_BestValueTagFetchFeedsQuantizationCounts(t *testing.T) {
	s := newEndpointsServer(t, quantizationBody)
	store, _ := newTestStore(s)
	expectLookup(t, store, s, s.srv.URL, quantizationBestTag, 1)
	expectCounts(t, store, s, map[string]int{"fp8": 3, "nvfp4": 1, "unknown": 1, "": 2}, OpenRouterHostsReady, 1)
}

func TestOpenRouterEndpointStore_BestValueTagJoinsQuantizationCountsFetch(t *testing.T) {
	s := newEndpointsServer(t, quantizationBody)
	s.block()
	store, _ := newTestStore(s)

	_, _, fetched := countsNow(store, s.srv.URL)
	<-s.entered
	tag := make(chan string, 1)
	go func() {
		tag <- lookupTag(context.Background(), store, s.srv.URL, "m")
	}()
	time.Sleep(20 * time.Millisecond)
	close(s.release)
	awaitFetched(t, fetched)
	if got := <-tag; got != quantizationBestTag {
		t.Fatalf("BestValueTag = %q, want %q", got, quantizationBestTag)
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("endpoint requests = %d, want 1", got)
	}
}

func TestOpenRouterEndpointStore_QuantizationCountsKeepCacheWindows(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		want      map[string]int
		wantState OpenRouterHostsState
		window    time.Duration
	}{
		{"empty list is ready", http.StatusOK, `{"data":{"endpoints":[]}}`, map[string]int{}, OpenRouterHostsReady, 12 * time.Hour},
		{"failure", http.StatusServiceUnavailable, "down", nil, OpenRouterHostsFailed, 15 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEndpointsServer(t, "")
			s.set(tc.status, tc.body)
			store, clock := newTestStore(s)

			_, _, fetched := countsNow(store, s.srv.URL)
			awaitFetched(t, fetched)
			expectCounts(t, store, s, tc.want, tc.wantState, 1)
			clock.advance(tc.window - time.Second)
			expectCounts(t, store, s, tc.want, tc.wantState, 1)

			s.set(http.StatusOK, quantizationBody)
			clock.advance(time.Second)
			_, state, fetched := countsNow(store, s.srv.URL)
			if state != OpenRouterHostsPending {
				t.Fatalf("expired entry state = %v, want pending", state)
			}
			awaitFetched(t, fetched)
			expectCounts(t, store, s, map[string]int{"fp8": 3, "nvfp4": 1, "unknown": 1, "": 2}, OpenRouterHostsReady, 2)
		})
	}
}

func TestOpenRouterEndpointStore_QuantizationCountsRefetchAnUnretainedEntry(t *testing.T) {
	s := newEndpointsServer(t, quantizationBody)
	store, clock := newTestStore(s)
	store.entries = map[openRouterEndpointKey]*openRouterEndpointEntry{
		{baseURL: s.srv.URL, model: "m"}: {fetched: clock.Now()},
	}

	_, state, fetched := countsNow(store, s.srv.URL)
	if state != OpenRouterHostsPending {
		t.Fatalf("unretained entry state = %v, want pending", state)
	}
	awaitFetched(t, fetched)
	expectCounts(t, store, s, map[string]int{"fp8": 3, "nvfp4": 1, "unknown": 1, "": 2}, OpenRouterHostsReady, 1)
}

func TestOpenRouterEndpointStore_QuantizationCountsJoinTheirOwnFetch(t *testing.T) {
	s := newEndpointsServer(t, quantizationBody)
	s.block()
	store, _ := newTestStore(s)

	_, _, first := countsNow(store, s.srv.URL)
	<-s.entered
	_, state, joined := countsNow(store, s.srv.URL)
	if state != OpenRouterHostsPending {
		t.Fatalf("joined state = %v, want pending", state)
	}
	close(s.release)
	awaitFetched(t, first)
	awaitFetched(t, joined)
	expectCounts(t, store, s, map[string]int{"fp8": 3, "nvfp4": 1, "unknown": 1, "": 2}, OpenRouterHostsReady, 1)
}

func TestOpenRouterEndpointStore_QuantizationCountsJoinABestValueTagFetch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		wantTag   string
		want      map[string]int
		wantState OpenRouterHostsState
	}{
		{"success", http.StatusOK, quantizationBestTag, map[string]int{"fp8": 3, "nvfp4": 1, "unknown": 1, "": 2}, OpenRouterHostsReady},
		{"failure", http.StatusServiceUnavailable, "", nil, OpenRouterHostsFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEndpointsServer(t, "")
			s.set(tc.status, quantizationBody)
			s.block()
			store, _ := newTestStore(s)

			tag := make(chan string, 1)
			go func() {
				tag <- lookupTag(context.Background(), store, s.srv.URL, "m")
			}()
			<-s.entered
			_, state, fetched := countsNow(store, s.srv.URL)
			if state != OpenRouterHostsPending {
				t.Fatalf("state while BestValueTag fetches = %v, want pending", state)
			}
			close(s.release)
			awaitFetched(t, fetched)
			if got := <-tag; got != tc.wantTag {
				t.Fatalf("BestValueTag = %q, want %q", got, tc.wantTag)
			}
			expectCounts(t, store, s, tc.want, tc.wantState, 1)
		})
	}
}
