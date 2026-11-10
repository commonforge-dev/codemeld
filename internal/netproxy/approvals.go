package netproxy

import (
	"context"
	"errors"
	"net"
	"sync"
)

var errSessionEnded = errors.New("netproxy: the session proxy stopped")

type approvals struct {
	mu      sync.Mutex
	session map[string]bool
}

func (a *approvals) covers(host, port string) bool {
	key, ok := targetKey(host, port)
	a.mu.Lock()
	defer a.mu.Unlock()
	return ok && a.session[key]
}

// commit and end share the approvals mutex so that accepting an answer and cancelling its request
// have one winner: a grant is never stored for a request whose cancellation already returned.
func (a *approvals) commit(ctx context.Context, host, port string, session bool) bool {
	key, ok := targetKey(host, port)
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	if session && ok {
		a.session[key] = true
	}
	return true
}

func (a *approvals) end(cancel func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cancel()
}

func (s *Server) approve(ctx context.Context, o *Owner, host, port string) string {
	if s.allow[net.JoinHostPort(host, port)] || s.approvals.covers(host, port) {
		return ""
	}
	if o.ask == nil {
		return "not approved (no one to ask)"
	}
	var mu sync.Mutex
	accepted, returned := DecisionDeny, false
	accept := func(d Decision) bool {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case returned || (d != DecisionOnce && d != DecisionSession):
			return false
		case accepted != DecisionDeny:
			return d == accepted
		case !s.approvals.commit(ctx, host, port, d == DecisionSession):
			return false
		}
		accepted = d
		return true
	}
	d, err := o.ask(ctx, host, port, func() bool { return s.approvals.covers(host, port) }, accept)
	mu.Lock()
	returned = true
	mu.Unlock()
	switch {
	case ctx.Err() != nil:
		return ended(ctx)
	case accepted != DecisionDeny:
		return ""
	case err != nil:
		return "not approved (prompt failed)"
	case d == DecisionDeny:
		return "not approved (denied)"
	case d == DecisionOnce || d == DecisionSession:
		if !s.approvals.commit(ctx, host, port, d == DecisionSession) {
			return ended(ctx)
		}
		return ""
	}
	return "not approved (prompt failed)"
}

func ended(ctx context.Context) string {
	if errors.Is(context.Cause(ctx), errSessionEnded) {
		return "not approved (session ended)"
	}
	return "not approved (command ended)"
}
