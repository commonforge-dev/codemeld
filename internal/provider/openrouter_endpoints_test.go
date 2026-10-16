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
		parts = append(parts, fmt.Sprintf(`{"provider_name":"p%d","pricing":{"prompt":"0.000001","completion":"0.000002"},"throughput_last_30m":%s}`, i, tp))
	}
	return `{"data":{"endpoints":[` + strings.Join(parts, ",") + `]}}`
}

func TestFetchOpenRouterEndpoints_ParsesPricesAndThroughput(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.EscapedPath()
		_, _ = io.WriteString(w, `{"data":{"endpoints":[
			{"provider_name":"Inception","pricing":{"prompt":"0.00000004","completion":"0.00000015","discount":0.8},"throughput_last_30m":{"p50":512.5,"p75":400,"p90":300,"p99":100}},
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
		{ProviderName: "Inception", PromptPerM: 0.04, CompletionPerM: 0.15, Discount: 0.8, P50Throughput: 512.5, HasThroughput: true},
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

func lookupBar(ctx context.Context, store *OpenRouterEndpointStore, baseURL, model string) (float64, bool) {
	return store.SpeedBar(ctx, endpointsEntry(baseURL), "Authorization", "Bearer "+endpointsKey, model)
}

func expectLookup(t *testing.T, store *OpenRouterEndpointStore, s *endpointsServer, baseURL string, wantBar float64, wantOK bool, wantHits int32) {
	t.Helper()
	bar, ok := lookupBar(context.Background(), store, baseURL, "m")
	if bar != wantBar || ok != wantOK {
		t.Fatalf("SpeedBar = %v, %v; want %v, %v", bar, ok, wantBar, wantOK)
	}
	if got := s.hits.Load(); got != wantHits {
		t.Fatalf("endpoint requests = %d, want %d", got, wantHits)
	}
}

func TestOpenRouterEndpointStore_SuccessCachedTwelveHours(t *testing.T) {
	s := newEndpointsServer(t, endpointsBody(10, 30, 20))
	store, clock := newTestStore(s)
	expectLookup(t, store, s, s.srv.URL, 20, true, 1)
	clock.advance(12*time.Hour - time.Second)
	expectLookup(t, store, s, s.srv.URL, 20, true, 1)
	s.set(http.StatusOK, endpointsBody(50))
	clock.advance(time.Second)
	expectLookup(t, store, s, s.srv.URL, 50, true, 2)
}

func TestOpenRouterEndpointStore_FailureRetriedAfterFifteenMinutes(t *testing.T) {
	s := newEndpointsServer(t, "")
	s.set(http.StatusServiceUnavailable, "down")
	store, clock := newTestStore(s)
	expectLookup(t, store, s, s.srv.URL, 0, false, 1)
	clock.advance(15*time.Minute - time.Second)
	expectLookup(t, store, s, s.srv.URL, 0, false, 1)
	s.set(http.StatusOK, endpointsBody(40))
	clock.advance(time.Second)
	expectLookup(t, store, s, s.srv.URL, 40, true, 2)
}

func TestOpenRouterEndpointStore_NoBarSuccessCachedTwelveHours(t *testing.T) {
	for name, body := range map[string]string{
		"empty list":       `{"data":{"endpoints":[]}}`,
		"all null p50 set": endpointsBody(nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			s := newEndpointsServer(t, body)
			store, clock := newTestStore(s)
			expectLookup(t, store, s, s.srv.URL, 0, false, 1)
			clock.advance(12*time.Hour - time.Second)
			expectLookup(t, store, s, s.srv.URL, 0, false, 1)
			clock.advance(time.Second)
			expectLookup(t, store, s, s.srv.URL, 0, false, 2)
		})
	}
}

func TestOpenRouterEndpointStore_KeyedByBaseURL(t *testing.T) {
	first := newEndpointsServer(t, endpointsBody(10))
	second := newEndpointsServer(t, endpointsBody(99))
	store, _ := newTestStore(first)
	expectLookup(t, store, first, first.srv.URL, 10, true, 1)
	expectLookup(t, store, first, first.srv.URL+"/", 10, true, 1)
	store.HTTPClient = second.srv.Client()
	expectLookup(t, store, second, second.srv.URL, 99, true, 1)
}

func TestOpenRouterEndpointStore_ConcurrentLookupsShareOneFetch(t *testing.T) {
	s := newEndpointsServer(t, endpointsBody(10, 30, 20))
	s.block()
	store, _ := newTestStore(s)

	const n = 8
	type result struct {
		bar float64
		ok  bool
	}
	results := make(chan result, n)
	for range n {
		go func() {
			bar, ok := lookupBar(context.Background(), store, s.srv.URL, "m")
			results <- result{bar, ok}
		}()
	}
	<-s.entered
	time.Sleep(20 * time.Millisecond)
	close(s.release)
	for range n {
		if r := <-results; r.bar != 20 || !r.ok {
			t.Fatalf("SpeedBar = %v, %v; want 20, true", r.bar, r.ok)
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

			ownerDone := make(chan float64, 1)
			go func() {
				bar, _ := lookupBar(context.Background(), store, s.srv.URL, "m")
				ownerDone <- bar
			}()
			<-s.entered

			if bar, ok := lookupBar(waiterCtx, store, s.srv.URL, "m"); ok {
				t.Fatalf("waiter SpeedBar = %v, true; want no bar", bar)
			}
			close(s.release)
			if bar := <-ownerDone; bar != 20 {
				t.Fatalf("owner SpeedBar = %v, want 20", bar)
			}
			expectLookup(t, store, s, s.srv.URL, 20, true, 1)
		})
	}
}

func TestOpenRouterEstimate(t *testing.T) {
	mixed := []openRouterEndpoint{
		{ProviderName: "slow", PromptPerM: 0.1, CompletionPerM: 0.2, P50Throughput: 10, HasThroughput: true},
		{ProviderName: "unknown", PromptPerM: 0.05, CompletionPerM: 0.05},
		{ProviderName: "fast", PromptPerM: 1, CompletionPerM: 2, P50Throughput: 200, HasThroughput: true},
		{ProviderName: "mid", PromptPerM: 0.3, CompletionPerM: 0.4, Discount: 0.25, P50Throughput: 50, HasThroughput: true},
	}
	noSpeed := []openRouterEndpoint{
		{ProviderName: "a", PromptPerM: 0.5, CompletionPerM: 0.5},
		{ProviderName: "b", PromptPerM: 0.2, CompletionPerM: 0.3},
	}
	ties := []openRouterEndpoint{
		{ProviderName: "first", PromptPerM: 0.1, CompletionPerM: 0.3, P50Throughput: 40, HasThroughput: true},
		{ProviderName: "second", PromptPerM: 0.3, CompletionPerM: 0.1, Discount: 0.5, P50Throughput: 40, HasThroughput: true},
	}
	parsed := func(name, prompt, completion string, discount float64) openRouterEndpoint {
		p, okP := pricePerMillion(prompt)
		c, okC := pricePerMillion(completion)
		if !okP || !okC {
			t.Fatalf("pricePerMillion(%q, %q) failed", prompt, completion)
		}
		return openRouterEndpoint{ProviderName: name, PromptPerM: p, CompletionPerM: c, Discount: discount, P50Throughput: 40, HasThroughput: true}
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
		{"best value without a bar picks the cheapest", noSpeed, "best_value", OpenRouterEstimate{PromptPerM: 0.2, CompletionPerM: 0.3}, true},
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

const estimateBody = `{"data":{"endpoints":[
	{"provider_name":"a","pricing":{"prompt":"0.0000003","completion":"0.0000004"},"throughput_last_30m":{"p50":10}},
	{"provider_name":"b","pricing":{"prompt":"0.0000001","completion":"0.0000002","discount":0.5},"throughput_last_30m":{"p50":90}}
]}}`

var estimateCheapest = OpenRouterEstimate{PromptPerM: 0.1, CompletionPerM: 0.2, Discount: 0.5}

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

func TestOpenRouterEndpointStore_SpeedBarFetchFeedsEstimate(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	store, _ := newTestStore(s)
	expectLookup(t, store, s, s.srv.URL, 10, true, 1)
	expectEstimate(t, store, s, estimateCheapest, true, 1)
}

func TestOpenRouterEndpointStore_EstimateFetchesInBackgroundAndFeedsSpeedBar(t *testing.T) {
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
	expectLookup(t, store, s, s.srv.URL, 10, true, 1)
}

func TestOpenRouterEndpointStore_BarOnlyEntryDoesNotSuppressEstimateFetch(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	store, clock := newTestStore(s)
	store.entries = map[openRouterEndpointKey]*openRouterEndpointEntry{
		{baseURL: s.srv.URL, model: "m"}: {fetched: clock.Now(), bar: 10, hasBar: true},
	}

	_, ok, fetched := estimateNow(store, s.srv.URL)
	if ok {
		t.Fatal("bar-only entry produced an estimate")
	}
	awaitFetched(t, fetched)
	expectEstimate(t, store, s, estimateCheapest, true, 1)
}

func TestOpenRouterEndpointStore_SpeedBarJoinsBackgroundFetch(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	s.block()
	store, _ := newTestStore(s)

	_, _, fetched := estimateNow(store, s.srv.URL)
	<-s.entered
	bar := make(chan float64, 1)
	go func() {
		b, _ := lookupBar(context.Background(), store, s.srv.URL, "m")
		bar <- b
	}()
	time.Sleep(20 * time.Millisecond)
	close(s.release)
	awaitFetched(t, fetched)
	if got := <-bar; got != 10 {
		t.Fatalf("SpeedBar = %v, want 10", got)
	}
	if got := s.hits.Load(); got != 1 {
		t.Fatalf("endpoint requests = %d, want 1", got)
	}
}

func TestOpenRouterEndpointStore_EstimateDoesNotWaitOnSpeedBarFetch(t *testing.T) {
	s := newEndpointsServer(t, estimateBody)
	s.block()
	store, _ := newTestStore(s)

	bar := make(chan float64, 1)
	go func() {
		b, _ := lookupBar(context.Background(), store, s.srv.URL, "m")
		bar <- b
	}()
	<-s.entered
	expectEstimate(t, store, s, OpenRouterEstimate{}, false, 1)
	close(s.release)
	if got := <-bar; got != 10 {
		t.Fatalf("SpeedBar = %v, want 10", got)
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
