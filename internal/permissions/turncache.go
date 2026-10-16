// Turn-scoped approval cache: per-turn memoization of permission outcomes.
package permissions

type turnCacheKey struct {
	kind      string
	subject   string
	pathScope string
	host      string
}

// TurnCache is the process-local, in-memory turn-scoped approval cache.
// It memoizes the resolved outcome of every permission prompt for the
// duration of a single model turn so an agent's retry-on-transient-failure
// pattern does not re-prompt the user within that turn, while every distinct
// user-driven turn still re-confirms intent. It holds no grants: a hit
// short-circuits with the cached outcome only and never creates or modifies a
// session/folder/global PermissionEntry. Real grants live in the matcher's table
// and always win over the cache, so callers consult it only when Match returns
// no match. The zero value is ready to use. Not safe for concurrent use; the
// turn loop drives it from a single goroutine.
type TurnCache struct {
	entries map[turnCacheKey]string
}

// NewTurnCache returns an empty TurnCache ready for the first turn.
func NewTurnCache() *TurnCache {
	return &TurnCache{entries: map[turnCacheKey]string{}}
}

// Lookup returns the cached outcome for req and whether one was recorded this
// turn (read rule). A hit reads no grant — the caller short-circuits
// with outcome and shows no prompt. Consult Lookup only after the real-grant
// Match returns no match, since a real grant always wins over the cache.
func (c *TurnCache) Lookup(req MatchRequest) (outcome string, hit bool) {
	outcome, hit = c.entries[turnCacheKeyOf(req)]
	return outcome, hit
}

// Record stores req's resolved outcome for the rest of the turn (write
// rule). Every prompt resolution is recorded, including deny, so a denied retry
// of the same subject within the turn short-circuits instead of re-prompting.
// outcome is opaque here — one of once/deny/session_grant/folder_grant/
// global_grant per §Reserved Values — and is not validated. Recording creates or
// modifies no grant.
func (c *TurnCache) Record(req MatchRequest, outcome string) {
	if c.entries == nil {
		c.entries = map[turnCacheKey]string{}
	}
	c.entries[turnCacheKeyOf(req)] = outcome
}

// Reset empties the cache so the next turn starts with no cached decisions
// (clear rule). The caller invokes it at the start of every new user
// submission, before any of the new turn's permission checks run; the boundary
// itself is owned by prompt/runtime orchestration, while TurnCache only provides
// the hook.
func (c *TurnCache) Reset() {
	c.entries = map[turnCacheKey]string{}
}

// turnCacheKeyOf projects a MatchRequest onto the cache key, dropping
// SubjectTokens so it can neither broaden nor fragment the key.
func turnCacheKeyOf(req MatchRequest) turnCacheKey {
	if req.Kind == subjectKindHost {
		return turnCacheKey{kind: req.Kind, subject: req.Subject, host: req.Host}
	}
	return turnCacheKey{kind: req.Kind, subject: req.Subject, pathScope: req.PathScope}
}
