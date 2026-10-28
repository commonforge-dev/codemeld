package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/systemone"
)

const (
	systemOneUnrecordedNote = "System One check could not be recorded — asking you"
	systemOnePausedPrefix   = "System One check paused for this session: "
)

type systemOneCheck struct {
	cache   *config.Cache
	blocked *permissions.BlockedPaths

	mu sync.Mutex
	// Keyed by store instance so a reloaded store with the same session id starts unpaused.
	pauses map[*sessions.Store]map[string]string
}

func newSystemOneCheck(cache *config.Cache, blocked *permissions.BlockedPaths) *systemOneCheck {
	return &systemOneCheck{cache: cache, blocked: blocked, pauses: map[*sessions.Store]map[string]string{}}
}

func (c *systemOneCheck) pauseReason(store *sessions.Store, child string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pauses[store][child]
}

func (c *systemOneCheck) pause(store *sessions.Store, child, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	children := c.pauses[store]
	if children == nil {
		children = map[string]string{}
		c.pauses[store] = children
	}
	if _, paused := children[child]; !paused {
		children[child] = reason
	}
}

func (c *systemOneCheck) status(store *sessions.Store) string {
	if reason := c.pauseReason(store, ""); reason != "" {
		return systemOnePausedPrefix + reason
	}
	return ""
}

// systemOneLiteralTexts maps a literal request's identity to its display text; an identity seen
// with two different texts maps to "", which no check accepts.
type systemOneLiteralTexts map[inflightKey]string

func (t systemOneLiteralTexts) add(req permissions.MatchRequest, text string) {
	if req.Kind != matchKindLiteral {
		return
	}
	k := inflightKeyOf(req)
	if prev, seen := t[k]; !seen {
		t[k] = text
	} else if prev != text {
		t[k] = ""
	}
}

func (t systemOneLiteralTexts) commandText(req permissions.MatchRequest, mc permissions.ModeContext) string {
	switch req.Kind {
	case matchKindDirect:
		if len(mc.Stages) == 1 {
			return mc.Stages[0].Source
		}
	case matchKindLiteral:
		return t[inflightKeyOf(req)]
	}
	return ""
}

func (c *systemOneCheck) bind(store *sessions.Store, texts systemOneLiteralTexts) func(context.Context, permissions.MatchRequest, permissions.ModeContext) permissions.PrePromptResult {
	if c == nil {
		return nil
	}
	return func(ctx context.Context, req permissions.MatchRequest, mc permissions.ModeContext) permissions.PrePromptResult {
		return c.check(ctx, store, texts.commandText(req, mc), req, mc)
	}
}

func (c *systemOneCheck) check(ctx context.Context, store *sessions.Store, text string, req permissions.MatchRequest, mc permissions.ModeContext) permissions.PrePromptResult {
	m, ok := systemone.Lookup(c.cache.SystemOne())
	if !ok || text == "" {
		return permissions.PrePromptResult{}
	}
	skip := permissions.SystemOneEligible(req, mc, c.blocked, text)
	if store == nil || store.SessionID() == "" {
		if skip != "" {
			return permissions.PrePromptResult{}
		}
		return permissions.PrePromptResult{Note: systemOneUnrecordedNote}
	}
	subject := req.Subject
	if req.Kind == matchKindDirect && len(req.SubjectTokens) > 0 {
		subject = strings.Join(req.SubjectTokens, " ")
	}
	rec := events.PermissionSystemOneCheck{
		SubjectKind: req.Kind, Subject: subject, PathScope: req.PathScope,
		Provider: m.Provider, ModelID: m.ModelID,
	}
	child := mc.ChildInvocationID
	if skip != "" {
		rec.Outcome, rec.Reason = "skipped", skip
		_ = events.EmitSystemOneCheckAttributed(store, rec, child)
		return permissions.PrePromptResult{}
	}
	record := func(allow bool, note string) permissions.PrePromptResult {
		if err := events.EmitSystemOneCheckAttributed(store, rec, child); err != nil {
			return permissions.PrePromptResult{Note: systemOneUnrecordedNote}
		}
		return permissions.PrePromptResult{Allow: allow, Note: note}
	}

	if reason := c.pauseReason(store, child); reason != "" {
		rec.Outcome, rec.Reason = "skipped", "paused"
		return record(false, systemOnePausedPrefix+reason)
	}
	entry, ok := c.cache.Provider(m.Provider)
	if !ok || entry.APIKey == "" {
		rec.Outcome, rec.Reason = "failed", "no_key"
		return record(false, fmt.Sprintf("System One check: no %s API key — run /connect %s", m.Provider, m.Provider))
	}

	start := time.Now()
	ans, err := systemone.Classify(ctx, nil, m, entry, text)
	rec.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		failure := &systemone.Error{Kind: systemone.KindNetwork}
		errors.As(err, &failure)
		rec.Outcome, rec.Reason = "failed", string(failure.Kind)
		var reason string
		switch failure.Kind {
		case systemone.KindCredits:
			reason = "out of credits on " + m.Provider
		case systemone.KindAuth:
			reason = "authentication failed on " + m.Provider
		default:
			return record(false, fmt.Sprintf("System One check failed (%s) — asking you", failure.Kind))
		}
		c.pause(store, child, reason)
		return record(false, "System One check failed: "+reason+" — asking you; paused for this session")
	}

	rec.ModelID, rec.Effect = ans.Model, ans.Effect
	rec.PReadOnly, rec.PSecrets, rec.PCode = &ans.ReadOnly, &ans.Secrets, &ans.Code
	rec.TReadOnly, rec.TSecrets, rec.TCode = &m.ReadOnly, &m.Secrets, &m.Code
	if m.Allows(ans) {
		rec.Outcome = "allowed"
		return record(true, "")
	}
	rec.Outcome = "declined"
	return record(false, "")
}
