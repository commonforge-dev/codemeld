package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	openRouterSortBestValue      = "best_value"
	maxOpenRouterEndpointsBytes  = 4 << 20
	openRouterEndpointsFreshFor  = 12 * time.Hour
	openRouterEndpointsFailedFor = 15 * time.Minute
	openRouterSpeedBarTimeout    = 5 * time.Second
)

type openRouterEndpoint struct {
	ProviderName   string
	Tag            string
	PromptPerM     float64
	CompletionPerM float64
	Discount       float64
	P50Throughput  float64
	HasThroughput  bool
}

type openRouterEndpointsResponse struct {
	Data struct {
		Endpoints []struct {
			ProviderName string `json:"provider_name"`
			Tag          string `json:"tag"`
			Pricing      struct {
				Prompt     string  `json:"prompt"`
				Completion string  `json:"completion"`
				Discount   float64 `json:"discount"`
			} `json:"pricing"`
			Throughput *struct {
				P50 *float64 `json:"p50"`
			} `json:"throughput_last_30m"`
		} `json:"endpoints"`
	} `json:"data"`
}

func fetchOpenRouterEndpoints(ctx context.Context, hc *http.Client, entry ProviderEntry, authName, authValue, model string) ([]openRouterEndpoint, error) {
	redact := func(s string) string { return redactCredentials(s, entry.APIKey, authValue) }

	segments := strings.Split(model, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	reqURL := strings.TrimSuffix(entry.BaseURL, "/") + "/models/" + strings.Join(segments, "/") + "/endpoints"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("provider %s endpoints: build request: %s", openRouterProviderID, redact(err.Error()))
	}
	httpReq.Header.Set("Accept", "application/json")
	if authName != "" {
		httpReq.Header.Set(authName, authValue)
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := pinRedirects(hc).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("provider %s endpoints: %s", openRouterProviderID, redact(err.Error()))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, newHTTPError(openRouterProviderID, res.StatusCode, "", res.Header.Get("Retry-After"))
	}

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxOpenRouterEndpointsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("provider %s endpoints: read response: %s", openRouterProviderID, redact(err.Error()))
	}
	if len(raw) > maxOpenRouterEndpointsBytes {
		return nil, fmt.Errorf("provider %s endpoints: response exceeds %d bytes", openRouterProviderID, maxOpenRouterEndpointsBytes)
	}
	var body openRouterEndpointsResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("provider %s endpoints: decode response: %s", openRouterProviderID, redact(err.Error()))
	}

	out := make([]openRouterEndpoint, 0, len(body.Data.Endpoints))
	for _, e := range body.Data.Endpoints {
		prompt, okPrompt := pricePerMillion(e.Pricing.Prompt)
		completion, okCompletion := pricePerMillion(e.Pricing.Completion)
		if !okPrompt || !okCompletion {
			continue
		}
		ep := openRouterEndpoint{
			ProviderName:   e.ProviderName,
			Tag:            e.Tag,
			PromptPerM:     prompt,
			CompletionPerM: completion,
			Discount:       e.Pricing.Discount,
		}
		if e.Throughput != nil && e.Throughput.P50 != nil {
			ep.P50Throughput, ep.HasThroughput = *e.Throughput.P50, true
		}
		out = append(out, ep)
	}
	return out, nil
}

// Appending the exponent to the decimal string avoids the rounding error of multiplying the parsed per-token float.
func pricePerMillion(perToken string) (float64, bool) {
	v, err := strconv.ParseFloat(perToken+"e6", 64)
	if err != nil {
		v, err = strconv.ParseFloat(perToken, 64)
		v *= 1e6
	}
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

func openRouterSpeedBar(endpoints []openRouterEndpoint) (float64, bool) {
	var speeds []float64
	for _, e := range endpoints {
		if e.HasThroughput {
			speeds = append(speeds, e.P50Throughput)
		}
	}
	if len(speeds) == 0 {
		return 0, false
	}
	sort.Float64s(speeds)
	return speeds[(len(speeds)-1)/2], true
}

type OpenRouterEstimate struct {
	PromptPerM     float64
	CompletionPerM float64
	Discount       float64
}

func openRouterBestValue(endpoints []openRouterEndpoint, ignored []string) (openRouterEndpoint, bool) {
	bar, hasBar := openRouterSpeedBar(endpoints)
	if !hasBar {
		return openRouterEndpoint{}, false
	}
	var eligible []*openRouterEndpoint
	for i := range endpoints {
		e := &endpoints[i]
		if e.Tag != "" && e.HasThroughput && e.P50Throughput >= bar && !openRouterTagIgnored(e.Tag, ignored) {
			eligible = append(eligible, e)
		}
	}
	if len(eligible) == 0 {
		return openRouterEndpoint{}, false
	}
	cheapest := openRouterPriceTotal(eligible[0])
	for _, e := range eligible[1:] {
		cheapest = min(cheapest, openRouterPriceTotal(e))
	}
	limit := new(big.Int).Mul(big.NewInt(6), big.NewInt(cheapest))
	var pick *openRouterEndpoint
	for _, e := range eligible {
		total := openRouterPriceTotal(e)
		if new(big.Int).Mul(big.NewInt(5), big.NewInt(total)).Cmp(limit) > 0 {
			continue
		}
		if pick == nil || e.P50Throughput > pick.P50Throughput || e.P50Throughput == pick.P50Throughput && total < openRouterPriceTotal(pick) {
			pick = e
		}
	}
	if pick == nil {
		return openRouterEndpoint{}, false
	}
	return *pick, true
}

func openRouterTagIgnored(tag string, ignored []string) bool {
	base, _, _ := strings.Cut(tag, "/")
	for _, slug := range ignored {
		if slug == tag || slug == base {
			return true
		}
	}
	return false
}

func openRouterEstimate(endpoints []openRouterEndpoint, sortMode string) (OpenRouterEstimate, bool) {
	if sortMode == openRouterSortBestValue {
		pick, ok := openRouterBestValue(endpoints, nil)
		if !ok {
			return OpenRouterEstimate{}, false
		}
		return OpenRouterEstimate{PromptPerM: pick.PromptPerM, CompletionPerM: pick.CompletionPerM, Discount: pick.Discount}, true
	}
	var pick *openRouterEndpoint
	cheaper := func(e *openRouterEndpoint) bool {
		return pick == nil || openRouterPriceTotal(e) < openRouterPriceTotal(pick)
	}
	for i := range endpoints {
		e := &endpoints[i]
		var better bool
		switch sortMode {
		case "default":
			better = cheaper(e)
		case "throughput":
			better = e.HasThroughput && (pick == nil || e.P50Throughput > pick.P50Throughput)
		}
		if better {
			pick = e
		}
	}
	if pick == nil {
		return OpenRouterEstimate{}, false
	}
	return OpenRouterEstimate{PromptPerM: pick.PromptPerM, CompletionPerM: pick.CompletionPerM, Discount: pick.Discount}, true
}

// Prices compare in whole ten-thousandths of a dollar per million, the precision the settings tab shows, so float sum error cannot split a tie.
func openRouterPriceTotal(e *openRouterEndpoint) int64 {
	return int64(math.Round((e.PromptPerM + e.CompletionPerM) * 1e4))
}

type OpenRouterEndpointStore struct {
	HTTPClient *http.Client
	Now        func() time.Time

	mu      sync.Mutex
	entries map[openRouterEndpointKey]*openRouterEndpointEntry
}

type openRouterEndpointKey struct {
	baseURL string
	model   string
}

type openRouterEndpointEntry struct {
	fetched   time.Time
	failed    bool
	retained  bool
	endpoints []openRouterEndpoint
	pending   chan struct{}
	notify    []func()
}

func (s *OpenRouterEndpointStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *OpenRouterEndpointStore) fresh(e *openRouterEndpointEntry) bool {
	ttl := openRouterEndpointsFreshFor
	if e.failed {
		ttl = openRouterEndpointsFailedFor
	}
	return s.now().Sub(e.fetched) < ttl
}

func (s *OpenRouterEndpointStore) claim(key openRouterEndpointKey) *openRouterEndpointEntry {
	if s.entries == nil {
		s.entries = map[openRouterEndpointKey]*openRouterEndpointEntry{}
	}
	owned := &openRouterEndpointEntry{pending: make(chan struct{})}
	s.entries[key] = owned
	return owned
}

func (s *OpenRouterEndpointStore) fill(ctx context.Context, owned *openRouterEndpointEntry, entry ProviderEntry, authName, authValue, model string) (openRouterEndpointEntry, []func()) {
	endpoints, err := fetchOpenRouterEndpoints(ctx, s.HTTPClient, entry, authName, authValue, model)
	filled := openRouterEndpointEntry{fetched: s.now(), failed: err != nil, retained: err == nil, endpoints: endpoints}
	s.mu.Lock()
	pending, notify := owned.pending, owned.notify
	*owned = filled
	s.mu.Unlock()
	close(pending)
	return filled, notify
}

func openRouterKey(entry ProviderEntry, model string) openRouterEndpointKey {
	return openRouterEndpointKey{baseURL: strings.TrimSuffix(entry.BaseURL, "/"), model: model}
}

func (s *OpenRouterEndpointStore) BestValueTag(ctx context.Context, entry ProviderEntry, authName, authValue, model string, ignored []string) string {
	ctx, cancel := context.WithTimeout(ctx, openRouterSpeedBarTimeout)
	defer cancel()
	key := openRouterKey(entry, model)
	for {
		s.mu.Lock()
		e := s.entries[key]
		if e != nil && e.pending != nil {
			pending := e.pending
			s.mu.Unlock()
			select {
			case <-pending:
				continue
			case <-ctx.Done():
				return ""
			}
		}
		if e != nil && s.fresh(e) {
			endpoints := e.endpoints
			s.mu.Unlock()
			return openRouterBestValueTag(endpoints, ignored)
		}
		owned := s.claim(key)
		s.mu.Unlock()

		filled, _ := s.fill(ctx, owned, entry, authName, authValue, model)
		return openRouterBestValueTag(filled.endpoints, ignored)
	}
}

func openRouterBestValueTag(endpoints []openRouterEndpoint, ignored []string) string {
	pick, _ := openRouterBestValue(endpoints, ignored)
	return pick.Tag
}

func (s *OpenRouterEndpointStore) Estimate(entry ProviderEntry, authName, authValue, model, sortMode string, fetched func()) (OpenRouterEstimate, bool) {
	key := openRouterKey(entry, model)
	s.mu.Lock()
	e := s.entries[key]
	if e != nil && e.pending != nil {
		if e.notify != nil {
			e.notify = append(e.notify, fetched)
		}
		s.mu.Unlock()
		return OpenRouterEstimate{}, false
	}
	if e != nil && (e.retained || e.failed) && s.fresh(e) {
		endpoints := e.endpoints
		s.mu.Unlock()
		return openRouterEstimate(endpoints, sortMode)
	}
	owned := s.claim(key)
	owned.notify = []func(){fetched}
	s.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), openRouterSpeedBarTimeout)
		defer cancel()
		_, notify := s.fill(ctx, owned, entry, authName, authValue, model)
		for _, f := range notify {
			f()
		}
	}()
	return OpenRouterEstimate{}, false
}
