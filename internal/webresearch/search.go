package webresearch

import "context"

type Candidate struct {
	Title         string
	URL           string
	Snippet       string
	PublishedDate string
}

// SearchBackend runs one query against a search provider. The returned
// candidates keep the provider's relevance order, and no provider or transport
// type crosses this boundary.
type SearchBackend interface {
	Search(ctx context.Context, query string) ([]Candidate, error)
}
