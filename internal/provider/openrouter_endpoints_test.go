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
	return fetchOpenRouterEndpoints(context.Background(), srv.Client(), endpointsEntry(srv.URL+"/api/v1/"), "Authorization", "Bearer "+endpointsKey, model)
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
			{"provider_name":"Inception","tag":"inception/fp8/us","pricing":{"prompt":"0.00000004","completion":"0.00000015","discount":0.8},"throughput_last_30m":{"p50":512.5,"p75":400,"p90":300,"p99":100}},
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
		{ProviderName: "Inception", Tag: "inception/fp8/us", PromptPerM: 0.04, CompletionPerM: 0.15, Discount: 0.8, P50Throughput: 512.5, HasThroughput: true},
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
	return store.BestValueTag(ctx, endpointsEntry(baseURL), "Authorization", "Bearer "+endpointsKey, model, nil)
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

func TestOpenRouterEstimate(t *testing.T) {
	mixed := []openRouterEndpoint{
		{ProviderName: "slow", Tag: "slow", PromptPerM: 0.1, CompletionPerM: 0.2, P50Throughput: 10, HasThroughput: true},
		{ProviderName: "unknown", Tag: "unknown", PromptPerM: 0.05, CompletionPerM: 0.05},
		{ProviderName: "fast", Tag: "fast", PromptPerM: 1, CompletionPerM: 2, P50Throughput: 200, HasThroughput: true},
		{ProviderName: "mid", Tag: "mid", PromptPerM: 0.3, CompletionPerM: 0.4, Discount: 0.25, P50Throughput: 50, HasThroughput: true},
	}
	noSpeed := []openRouterEndpoint{
		{ProviderName: "a", Tag: "a", PromptPerM: 0.5, CompletionPerM: 0.5},
		{ProviderName: "b", Tag: "b", PromptPerM: 0.2, CompletionPerM: 0.3},
	}
	ties := []openRouterEndpoint{
		{ProviderName: "first", Tag: "first", PromptPerM: 0.1, CompletionPerM: 0.3, P50Throughput: 40, HasThroughput: true},
		{ProviderName: "second", Tag: "second", PromptPerM: 0.3, CompletionPerM: 0.1, Discount: 0.5, P50Throughput: 40, HasThroughput: true},
	}
	parsed := func(name, prompt, completion string, discount float64) openRouterEndpoint {
		p, okP := pricePerMillion(prompt)
		c, okC := pricePerMillion(completion)
		if !okP || !okC {
			t.Fatalf("pricePerMillion(%q, %q) failed", prompt, completion)
		}
		return openRouterEndpoint{ProviderName: name, Tag: name, PromptPerM: p, CompletionPerM: c, Discount: discount, P50Throughput: 40, HasThroughput: true}
	}
	decimalTies := []openRouterEndpoint{
		parsed("first", "0.0000001", "0.0000002", 0.1),
		parsed("second", "0.00000015", "0.00000015", 0.2),
	}
	lowerSecond := []openRouterEndpoint{
		parsed("first", "0.0000001", "0.0000002", 0.1),
		parsed("lower", "0.00000015", "0.0000001499", 0.3),
	}
	higherFirst := []openRouterEndpoint{
		parsed("higher", "0.00000015", "0.0000001501", 0.4),
		parsed("second", "0.0000001", "0.0000002", 0.1),
	}
	cluster := []openRouterEndpoint{
		{Tag: "cheap", PromptPerM: 0.25, CompletionPerM: 0.32, P50Throughput: 127, HasThroughput: true},
		{Tag: "quick", PromptPerM: 0.3, CompletionPerM: 0.36, Discount: 0.1, P50Throughput: 154, HasThroughput: true},
		{Tag: "slow", PromptPerM: 0.1, CompletionPerM: 0.1, P50Throughput: 50, HasThroughput: true},
	}
	untagged := []openRouterEndpoint{
		{PromptPerM: 0.1, CompletionPerM: 0.1, P50Throughput: 40, HasThroughput: true},
		{PromptPerM: 0.2, CompletionPerM: 0.2, P50Throughput: 40, HasThroughput: true},
	}
	est := func(e openRouterEndpoint) OpenRouterEstimate {
		return OpenRouterEstimate{PromptPerM: e.PromptPerM, CompletionPerM: e.CompletionPerM, Discount: e.Discount}
	}
	cases := []struct {
		name      string
		endpoints []openRouterEndpoint
		mode      string
		want      OpenRouterEstimate
		wantOK    bool
	}{
		{"default decimal-equal totals keep the first listed", decimalTies, "default", est(decimalTies[0]), true},
		{"best value decimal-equal totals keep the first listed", decimalTies, "best_value", est(decimalTies[0]), true},
		{"default nearby lower total wins", lowerSecond, "default", est(lowerSecond[1]), true},
		{"best value nearby lower total wins", lowerSecond, "best_value", est(lowerSecond[1]), true},
		{"default nearby higher total loses", higherFirst, "default", est(higherFirst[1]), true},
		{"best value nearby higher total loses", higherFirst, "best_value", est(higherFirst[1]), true},
		{"default picks the cheapest", mixed, "default", OpenRouterEstimate{PromptPerM: 0.05, CompletionPerM: 0.05}, true},
		{"throughput picks the fastest known p50", mixed, "throughput", OpenRouterEstimate{PromptPerM: 1, CompletionPerM: 2}, true},
		{"best value picks the cheapest at or above the bar and reports its discount", mixed, "best_value", OpenRouterEstimate{PromptPerM: 0.3, CompletionPerM: 0.4, Discount: 0.25}, true},
		{"best value without a bar picks nothing", noSpeed, "best_value", OpenRouterEstimate{}, false},
		{"best value picks the fastest within 20% of the cheapest", cluster, "best_value", est(cluster[1]), true},
		{"best value without usable tags picks nothing", untagged, "best_value", OpenRouterEstimate{}, false},
		{"throughput without speed data", noSpeed, "throughput", OpenRouterEstimate{}, false},
		{"default tie picks the first listed", ties, "default", OpenRouterEstimate{PromptPerM: 0.1, CompletionPerM: 0.3}, true},
		{"throughput tie picks the first listed", ties, "throughput", OpenRouterEstimate{PromptPerM: 0.1, CompletionPerM: 0.3}, true},
		{"best value tie picks the first listed", ties, "best_value", OpenRouterEstimate{PromptPerM: 0.1, CompletionPerM: 0.3}, true},
		{"hand-set latency", mixed, "latency", OpenRouterEstimate{}, false},
		{"empty default", nil, "default", OpenRouterEstimate{}, false},
		{"empty throughput", nil, "throughput", OpenRouterEstimate{}, false},
		{"empty best value", []openRouterEndpoint{}, "best_value", OpenRouterEstimate{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := openRouterEstimate(tc.endpoints, tc.mode)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("estimate = %+v, %v; want %+v, %v", got, ok, tc.want, tc.wantOK)
			}
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

const estimateBody = `{"data":{"endpoints":[
	{"provider_name":"a","tag":"a/fp8","pricing":{"prompt":"0.0000003","completion":"0.0000004"},"throughput_last_30m":{"p50":10}},
	{"provider_name":"b","tag":"b/fp8","pricing":{"prompt":"0.0000001","completion":"0.0000002","discount":0.5},"throughput_last_30m":{"p50":90}}
]}}`

var estimateCheapest = OpenRouterEstimate{PromptPerM: 0.1, CompletionPerM: 0.2, Discount: 0.5}

const estimateCheapestTag = "b/fp8"

func estimateNow(store *OpenRouterEndpointStore, baseURL string) (OpenRouterEstimate, bool, chan struct{}) {
	fetched := make(chan struct{})
	est, ok := store.Estimate(endpointsEntry(baseURL), "Authorization", "Bearer "+endpointsKey, "m", "default", func() { close(fetched) })
	return est, ok, fetched
}

func awaitFetched(t *testing.T, fetched chan struct{}) {
	t.Helper()
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("background fetch did not report completion")
	}
}

func expectEstimate(t *testing.T, store *OpenRouterEndpointStore, s *endpointsServer, want OpenRouterEstimate, wantOK bool, wantHits int32) {
	t.Helper()
	est, ok, _ := estimateNow(store, s.srv.URL)
	if est != want || ok != wantOK {
		t.Fatalf("Estimate = %+v, %v; want %+v, %v", est, ok, want, wantOK)
	}
	if got := s.hits.Load(); got != wantHits {
		t.Fatalf("endpoint requests = %d, want %d", got, wantHits)
	}
}

func TestOpenRouterEndpointStore_BestValueTagFetchFeedsEstimate(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	store, _ := newTestStore(s)
	expectLookup(t, store, s, s.srv.URL, estimateCheapestTag, 1)
	expectEstimate(t, store, s, estimateCheapest, true, 1)
}

func TestOpenRouterEndpointStore_EstimateFetchesInBackgroundAndFeedsBestValueTag(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	s.block()
	store, _ := newTestStore(s)

	est, ok, fetched := estimateNow(store, s.srv.URL)
	if ok {
		t.Fatalf("Estimate before any fetch = %+v, want none", est)
	}
	<-s.entered
	expectEstimate(t, store, s, OpenRouterEstimate{}, false, 1)
	_, _, joined := estimateNow(store, s.srv.URL)
	close(s.release)
	awaitFetched(t, fetched)
	awaitFetched(t, joined)
	expectEstimate(t, store, s, estimateCheapest, true, 1)
	expectLookup(t, store, s, s.srv.URL, estimateCheapestTag, 1)
}

func TestOpenRouterEndpointStore_UnretainedEntryDoesNotSuppressEstimateFetch(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	store, clock := newTestStore(s)
	store.entries = map[openRouterEndpointKey]*openRouterEndpointEntry{
		{baseURL: s.srv.URL, model: "m"}: {fetched: clock.Now()},
	}

	_, ok, fetched := estimateNow(store, s.srv.URL)
	if ok {
		t.Fatal("unretained entry produced an estimate")
	}
	awaitFetched(t, fetched)
	expectEstimate(t, store, s, estimateCheapest, true, 1)
}

func TestOpenRouterEndpointStore_BestValueTagJoinsBackgroundFetch(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	s.block()
	store, _ := newTestStore(s)

	_, _, fetched := estimateNow(store, s.srv.URL)
	<-s.entered
	tag := make(chan string, 1)
	go func() {
		tag <- lookupTag(context.Background(), store, s.srv.URL, "m")
	}()
	time.Sleep(20 * time.Millisecond)
	close(s.release)
	awaitFetched(t, fetched)
	if got := <-tag; got != estimateCheapestTag {
		t.Fatalf("BestValueTag = %q, want %q", got, estimateCheapestTag)
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("endpoint requests = %d, want 1", got)
	}
}

func TestOpenRouterEndpointStore_EstimateDoesNotWaitOnBestValueTagFetch(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	s.block()
	store, _ := newTestStore(s)

	tag := make(chan string, 1)
	go func() {
		tag <- lookupTag(context.Background(), store, s.srv.URL, "m")
	}()
	<-s.entered
	expectEstimate(t, store, s, OpenRouterEstimate{}, false, 1)
	close(s.release)
	if got := <-tag; got != estimateCheapestTag {
		t.Fatalf("BestValueTag = %q, want %q", got, estimateCheapestTag)
	}
	expectEstimate(t, store, s, estimateCheapest, true, 1)
}

func TestOpenRouterEndpointStore_EstimateKeepsCacheWindows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		window time.Duration
	}{
		{"empty list", http.StatusOK, `{"data":{"endpoints":[]}}`, 12 * time.Hour},
		{"failure", http.StatusServiceUnavailable, "down", 15 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newEndpointsServer(t, "")
			s.set(tc.status, tc.body)
			store, clock := newTestStore(s)

			_, _, fetched := estimateNow(store, s.srv.URL)
			awaitFetched(t, fetched)
			expectEstimate(t, store, s, OpenRouterEstimate{}, false, 1)
			clock.advance(tc.window - time.Second)
			expectEstimate(t, store, s, OpenRouterEstimate{}, false, 1)

			s.set(http.StatusOK, estimateBody)
			clock.advance(time.Second)
			_, ok, fetched := estimateNow(store, s.srv.URL)
			if ok {
				t.Fatal("expired entry produced an estimate")
			}
			awaitFetched(t, fetched)
			expectEstimate(t, store, s, estimateCheapest, true, 2)
		})
	}
}
