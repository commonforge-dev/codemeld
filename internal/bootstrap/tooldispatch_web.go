package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/dispatch"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/turn"
	"codemeld.dev/codemeld/internal/webresearch"
	"codemeld.dev/codemeld/internal/webresearch/exa"
)

const (
	webSearchToolName = "web_search"
	webFetchToolName  = "web_fetch"
)

const exaSearchHost = "mcp.exa.ai"

const maxSearchCandidates = 5

var errWebResearchUnavailable = errors.New("web research is not available yet")

type webResearchTool struct {
	name        string
	param       string
	description string
	paramDesc   string
	search      webresearch.SearchBackend
}

func (t *webResearchTool) Name() string        { return t.name }
func (t *webResearchTool) SubjectKind() string { return "tool" }

func (t *webResearchTool) Advertise() tools.Metadata {
	return tools.Metadata{
		Description: t.description,
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				t.param: map[string]any{
					"type":        "string",
					"description": t.paramDesc,
				},
			},
			"required":             []string{t.param},
			"additionalProperties": false,
		},
		ReadOnly: false,
	}
}

func (t *webResearchTool) Invoke(context.Context, map[string]any) (tools.Result, error) {
	return tools.Result{}, errWebResearchUnavailable
}

var newSearchBackend = func(cfg exa.Config) webresearch.SearchBackend {
	backend, err := exa.New(cfg)
	if err != nil {
		return nil
	}
	return backend
}

func webResearchTools() []*webResearchTool {
	return []*webResearchTool{
		{
			name:  webSearchToolName,
			param: "query",
			description: "Search the web and return up to five candidate results: title, address, snippet, and published date only. " +
				"It does not read any of them, so nothing here is page content. " +
				"Run one targeted search at a time and read the candidates it returns before running another. " +
				"Then call web_fetch on only the one or two candidate addresses that look most likely to answer the question — " +
				"reading a candidate is a separate call the user approves separately. " +
				"Stop searching and fetching as soon as you have enough evidence to answer.",
			paramDesc: "One targeted thing to search for, in plain words.",
		},
		{
			name:  webFetchToolName,
			param: "url",
			description: "Fetch one web page and return its readable text. " +
				"Use when you already have the address of the page you want to read, including a promising address from web_search results.",
			paramDesc: "Full http or https address of the page to fetch.",
		},
	}
}

func (d *productionToolDispatcher) setWebFetch(settings config.WebResearchSettings) {
	if !settings.Enabled || settings.TimeoutSeconds <= 0 {
		d.fetchClient = nil
		return
	}
	d.fetchClient = guardedFetchClient(http.DefaultTransport, time.Duration(settings.TimeoutSeconds)*time.Second)
}

// A proxy would resolve and contact a destination the guarded dialer never sees, so the fetch
// path is direct-only; a fallback that is not an *http.Transport leaves no fetch client at all.
func guardedFetchClient(fallback http.RoundTripper, timeout time.Duration) *http.Client {
	base, ok := fallback.(*http.Transport)
	if !ok {
		return nil
	}
	transport := base.Clone()
	transport.Proxy = nil
	transport.DialContext = webresearch.GuardedDialContext
	return &http.Client{Timeout: timeout, Transport: transport}
}

// errWebFetchDenied stops the transport at a denied target without carrying the deny envelope
// through webresearch, which reports every authorization failure as request_failed.
var errWebFetchDenied = errors.New("web fetch not authorized")

type fetchAuthorization struct {
	d        *productionToolDispatcher
	envelope string
	wrapUp   bool
	err      error
}

func (a *fetchAuthorization) authorize(ctx context.Context, target webresearch.Target) error {
	decision, err := a.d.authorizer.Authorize(ctx,
		permissions.MatchRequest{
			Kind:              matchKindHost,
			Subject:           webFetchToolName,
			Host:              target.Host,
			FreshConfirmation: target.FreshConfirmation,
		},
		dispatch.PromptDisplay{
			HostRequest:        target.URL,
			DirectHTTPFallback: target.Scheme == "http",
		},
		permissions.ModeContext{
			Class:         permissions.ClassMutating,
			ToolName:      webFetchToolName,
			NetworkEgress: true,
		})
	if err != nil {
		a.err = err
		return err
	}
	if decision.DenyEnvelope != "" {
		a.envelope = decision.DenyEnvelope
		a.wrapUp = decision.WrapUp
		return errWebFetchDenied
	}
	return nil
}

func (d *productionToolDispatcher) dispatchWebFetch(ctx context.Context, args map[string]any) (turn.ToolResult, error) {
	rawURL, _ := args["url"].(string)
	if strings.TrimSpace(rawURL) == "" {
		return inbandToolError(fmt.Errorf("invalid tool arguments: missing %q", "url")), nil
	}
	auth := &fetchAuthorization{d: d}
	res := webresearch.FetchText(ctx, d.fetchClient, rawURL, auth.authorize, d.outputCap)
	if auth.err != nil {
		return turn.ToolResult{}, auth.err
	}
	// A refusal wins over any result the transport still produced: a denied https redirect is
	// followed by the plain-http attempt for a direct http target, and that fallback content must
	// not stand in for the refused hop.
	if auth.envelope != "" {
		return turn.ToolResult{Content: auth.envelope, Denied: true, WrapUp: auth.wrapUp}, nil
	}
	encoded, err := encodeFetchResult(res, d.outputCap)
	if err != nil {
		return turn.ToolResult{}, err
	}
	return turn.ToolResult{Content: encoded}, nil
}

type searchCandidate struct {
	Title         string `json:"title,omitempty"`
	URL           string `json:"url"`
	Snippet       string `json:"snippet,omitempty"`
	PublishedDate string `json:"published_date,omitempty"`
}

type searchResults struct {
	Candidates []searchCandidate `json:"candidates"`
	Omitted    int               `json:"omitted,omitempty"`
}

func (d *productionToolDispatcher) dispatchWebSearch(ctx context.Context, backend webresearch.SearchBackend, args map[string]any) (turn.ToolResult, error) {
	query, _ := args["query"].(string)
	if strings.TrimSpace(query) == "" {
		return inbandToolError(fmt.Errorf("invalid tool arguments: missing %q", "query")), nil
	}
	decision, err := d.authorizer.Authorize(ctx,
		permissions.MatchRequest{Kind: matchKindHost, Subject: webSearchToolName, Host: exaSearchHost},
		dispatch.PromptDisplay{HostRequest: query},
		permissions.ModeContext{
			Class:         permissions.ClassMutating,
			ToolName:      webSearchToolName,
			NetworkEgress: true,
		})
	if err != nil {
		return turn.ToolResult{}, err
	}
	if decision.DenyEnvelope != "" {
		return turn.ToolResult{Content: decision.DenyEnvelope, Denied: true, WrapUp: decision.WrapUp}, nil
	}
	candidates, err := backend.Search(ctx, query)
	if err != nil {
		// The backend's error text is fixed and provider-free, so the same string is safe as
		// both the model's tool result and the user's notice.
		result := inbandToolError(err)
		result.Notice = result.Content
		return result, nil
	}
	return d.encodeSearchCandidates(candidates)
}

// encodeSearchCandidates returns ranked metadata only. A candidate host is neither authorized nor
// dialed here: reading one is a separate model-issued web_fetch call with its own exact-host prompt.
func (d *productionToolDispatcher) encodeSearchCandidates(candidates []webresearch.Candidate) (turn.ToolResult, error) {
	results := searchResults{Candidates: []searchCandidate{}}
	for _, candidate := range candidates {
		// A candidate web_fetch would refuse is not a usable result and is dropped uncounted; a
		// usable one is surfaced with its whole URL or counted as omitted, never cut down to a
		// shorter string naming some other target.
		display, ok := webresearch.AdmissibleHTTPS(candidate.URL)
		if !ok {
			continue
		}
		if len(display) > maxCandidateURLBytes || len(results.Candidates) == maxSearchCandidates {
			results.Omitted++
			continue
		}
		results.Candidates = append(results.Candidates, searchCandidate{
			Title:         boundedField(candidate.Title, maxCandidateTitleBytes),
			URL:           display,
			Snippet:       boundedField(candidate.Snippet, maxCandidateSnippetBytes),
			PublishedDate: boundedField(candidate.PublishedDate, maxCandidatePublishedBytes),
		})
	}
	encoded, err := encodeSearchResults(results, d.outputCap)
	if err != nil {
		return turn.ToolResult{}, err
	}
	return turn.ToolResult{Content: encoded}, nil
}

// The per-field caps a candidate record is held to, independent of any one backend's own bounds.
const (
	maxCandidateTitleBytes     = 512
	maxCandidatePublishedBytes = 512
	maxCandidateURLBytes       = 2048
	maxCandidateSnippetBytes   = 4096
)

// Invalid bytes are coerced before the cap so a candidate field is valid UTF-8 at its declared
// length, rather than growing past it when the JSON encoder substitutes replacement runes.
func boundedField(value string, cap int) string {
	return truncateUTF8(strings.ToValidUTF8(value, "�"), cap)
}

// encodeSearchResults keeps the result one complete JSON object inside cap by shrinking candidate
// metadata — and, past that, dropping whole candidates into the omitted count — rather than
// truncating the serialized object.
func encodeSearchResults(results searchResults, cap int) (string, error) {
	for {
		encoded, err := json.Marshal(results)
		if err != nil {
			return "", err
		}
		over := len(encoded) - cap
		if over <= 0 || !shrinkSearchResults(&results, over) {
			return string(encoded), nil
		}
	}
}

func shrinkSearchResults(results *searchResults, over int) bool {
	longest := -1
	for i, candidate := range results.Candidates {
		if longest < 0 || len(candidate.Snippet) > len(results.Candidates[longest].Snippet) {
			longest = i
		}
	}
	if longest < 0 {
		return false
	}
	if snippet := results.Candidates[longest].Snippet; snippet != "" {
		results.Candidates[longest].Snippet = truncateUTF8(snippet, len(snippet)-over)
		return true
	}
	last := len(results.Candidates) - 1
	if results.Candidates[last].PublishedDate != "" || results.Candidates[last].Title != "" {
		results.Candidates[last].PublishedDate = ""
		results.Candidates[last].Title = ""
		return true
	}
	results.Candidates = results.Candidates[:last]
	results.Omitted++
	return true
}

// encodeFetchResult keeps the result one complete JSON object inside cap: overflow shrinks the
// optional fields rather than truncating the serialized object.
func encodeFetchResult(res webresearch.FetchResult, cap int) (string, error) {
	for {
		encoded, err := json.Marshal(res)
		if err != nil {
			return "", err
		}
		over := len(encoded) - cap
		switch {
		case over <= 0:
			return string(encoded), nil
		case res.Content != "":
			res.Content = truncateUTF8(res.Content, len(res.Content)-over)
		case res.FinalURL != "":
			res.FinalURL = ""
		default:
			return string(encoded), nil
		}
	}
}

func truncateUTF8(value string, cap int) string {
	if cap <= 0 {
		return ""
	}
	if len(value) <= cap {
		return value
	}
	end := cap
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}
