package permissions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/sessions"
)

type orchEmitted struct {
	kind, subjectKind, subject, pathScope                      string
	grantKind, grantPathScope, outcome, outcomeSource, argHash string
	grantSubject                                               string
	directTokens                                               []string
	directCommandSubject, directRequestSubject                 string
}

type orchRecord struct {
	req     MatchRequest
	outcome string
}

type orchCaptures struct {
	events   []orchEmitted
	prompts  int
	records  []orchRecord
	appends  []PermissionEntry
	persists []PermissionEntry
}

func (c *orchCaptures) kinds() []string {
	ks := make([]string, len(c.events))
	for i, e := range c.events {
		ks[i] = e.kind
	}
	return ks
}

type orchGrants struct {
	entries []PermissionEntry
	cap     *orchCaptures
}

func (g *orchGrants) Permissions() []PermissionEntry { return g.entries }
func (g *orchGrants) AppendPermission(e PermissionEntry) {
	g.entries = append(g.entries, e)
	g.cap.appends = append(g.cap.appends, e)
}

type orchCache struct {
	hits map[turnCacheKey]string
	cap  *orchCaptures
}

func (c *orchCache) Lookup(req MatchRequest) (string, bool) {
	o, ok := c.hits[turnCacheKeyOf(req)]
	return o, ok
}
func (c *orchCache) Record(req MatchRequest, outcome string) {
	c.cap.records = append(c.cap.records, orchRecord{req: req, outcome: outcome})
}

type orchFixture struct {
	cap    *orchCaptures
	grants *orchGrants
	cache  *orchCache
	deps   AuthorizeDeps
}

func newFixture(prompt func(context.Context, ScopeEscalation) (PromptOutcome, error), persistErr error) *orchFixture {
	cap := &orchCaptures{}
	grants := &orchGrants{cap: cap}
	cache := &orchCache{hits: map[turnCacheKey]string{}, cap: cap}
	deps := AuthorizeDeps{
		Grants: grants,
		Cache:  cache,
		Prompt: func(ctx context.Context, esc ScopeEscalation) (PromptOutcome, error) {
			cap.prompts++
			return prompt(ctx, esc)
		},
		PersistGrant: func(e PermissionEntry) (PermissionEntry, error) {
			cap.persists = append(cap.persists, e)
			return e, persistErr
		},
		EmitPromptShown: func(sk, s, ps string, dt []string, id DirectIdentity) error {
			cap.events = append(cap.events, orchEmitted{kind: "permission_prompt_shown", subjectKind: sk, subject: s, pathScope: ps, directTokens: dt, directCommandSubject: id.CommandSubject, directRequestSubject: id.RequestSubject})
			return nil
		},
		EmitDecision: func(sk, s, ps, outcome, gk, gps string, id DirectIdentity) error {
			cap.events = append(cap.events, orchEmitted{kind: "permission_decision", subjectKind: sk, subject: s, pathScope: ps, outcome: outcome, grantKind: gk, grantPathScope: gps, directCommandSubject: id.CommandSubject, directRequestSubject: id.RequestSubject})
			return nil
		},
		EmitDecisionGrant: func(sk, s, ps, gk, gps, gs string, id DirectIdentity) error {
			cap.events = append(cap.events, orchEmitted{kind: "permission_decision", subjectKind: sk, subject: s, pathScope: ps, outcome: decisionGranted, grantKind: gk, grantPathScope: gps, grantSubject: gs, directCommandSubject: id.CommandSubject, directRequestSubject: id.RequestSubject})
			return nil
		},
		EmitMatched: func(sk, s, ps, gk, gps, outcome, src, ah, drs string) error {
			cap.events = append(cap.events, orchEmitted{kind: "permission_matched", subjectKind: sk, subject: s, pathScope: ps, grantKind: gk, grantPathScope: gps, outcome: outcome, outcomeSource: src, argHash: ah, directRequestSubject: drs})
			return nil
		},
	}
	return &orchFixture{cap: cap, grants: grants, cache: cache, deps: deps}
}

func choose(c PromptChoice) func(context.Context, ScopeEscalation) (PromptOutcome, error) {
	return func(context.Context, ScopeEscalation) (PromptOutcome, error) { return PromptOutcome{Choice: c}, nil }
}

func neverPrompt(context.Context, ScopeEscalation) (PromptOutcome, error) {
	return PromptOutcome{}, errors.New("prompt must not be called")
}

func toolReq() MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj}
}

func deleteReq() MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: toolNameDelete, PathScope: scopeProj}
}

func moveReq() MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: toolNameMove, PathScope: scopeProj}
}

func mustAuthorize(t *testing.T, req MatchRequest, deps AuthorizeDeps) Decision {
	t.Helper()
	return mustAuthorizeMode(t, req, ModeContext{}, deps)
}

func mustAuthorizeMode(t *testing.T, req MatchRequest, modeCtx ModeContext, deps AuthorizeDeps) Decision {
	t.Helper()
	d, err := Authorize(context.Background(), req, modeCtx, deps)
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	return d
}

func wantKinds(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("event kinds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event kinds = %v, want %v", got, want)
		}
	}
}

func TestAuthorizeMatchedGrantShortCircuits(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{toolGrant("vcs_commit", scopeProj, grantKindFolder)}

	d := mustAuthorize(t, toolReq(), f.deps)

	if f.cap.prompts != 0 {
		t.Fatalf("prompt called %d times, want 0", f.cap.prompts)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceGrant {
		t.Fatalf("outcome_source = %q, want %q", ev.outcomeSource, outcomeSourceGrant)
	}
	if ev.outcome != outcomeFolderGrant || ev.grantKind != grantKindFolder || ev.grantPathScope != scopeProj {
		t.Fatalf("matched event = %+v, want folder grant at %s", ev, scopeProj)
	}
	if d.Outcome != outcomeFolderGrant || d.Grant == nil {
		t.Fatalf("decision = %+v, want folder_grant with grant", d)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a real-grant match must not record to cache or append: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizeCacheHit(t *testing.T) {
	tests := []struct {
		name           string
		cached         string
		wantOutcome    string
		wantGrantKind  string
		wantGrantScope string
		wantDeny       bool
	}{
		{name: "once", cached: outcomeOnce, wantOutcome: outcomeOnce},
		{name: "deny", cached: outcomeDeny, wantOutcome: outcomeDeny, wantDeny: true},
		{name: "folder grant shadow-case", cached: outcomeFolderGrant, wantOutcome: outcomeFolderGrant, wantGrantKind: grantKindFolder, wantGrantScope: scopeProj},
		{name: "global grant shadow-case", cached: outcomeGlobalGrant, wantOutcome: outcomeGlobalGrant, wantGrantKind: grantKindGlobal, wantGrantScope: allPathsScope},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req := toolReq()
			f.cache.hits[turnCacheKeyOf(req)] = tc.cached

			d := mustAuthorize(t, req, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("prompt called %d times, want 0", f.cap.prompts)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			ev := f.cap.events[0]
			if ev.outcomeSource != outcomeSourceCache {
				t.Fatalf("outcome_source = %q, want %q", ev.outcomeSource, outcomeSourceCache)
			}
			if ev.outcome != tc.wantOutcome || ev.grantKind != tc.wantGrantKind || ev.grantPathScope != tc.wantGrantScope {
				t.Fatalf("matched event = %+v, want outcome=%q grant_kind=%q grant_scope=%q", ev, tc.wantOutcome, tc.wantGrantKind, tc.wantGrantScope)
			}
			if d.Outcome != tc.wantOutcome {
				t.Fatalf("decision outcome = %q, want %q", d.Outcome, tc.wantOutcome)
			}
			if d.Grant != nil {
				t.Fatalf("cache hit must carry no grant, got %+v", d.Grant)
			}
			if tc.wantDeny && d.DenyEnvelope == "" {
				t.Fatalf("cached deny must return a deny envelope")
			}
			if !tc.wantDeny && d.DenyEnvelope != "" {
				t.Fatalf("non-deny cache hit must not return an envelope, got %q", d.DenyEnvelope)
			}
		})
	}
}

func TestAuthorizeAllowOnce(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	req := toolReq()

	d := mustAuthorize(t, req, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if len(f.cap.records) != 1 || f.cap.records[0].outcome != outcomeOnce {
		t.Fatalf("cache records = %+v, want one once record", f.cap.records)
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("allow-once must not append a grant, got %+v", f.cap.appends)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil || d.DenyEnvelope != "" {
		t.Fatalf("decision = %+v, want once with no grant/envelope", d)
	}
}

func TestAuthorizeAllowOnceEmitsGrantedDecisionWithNoGrantFields(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	store := newStore()
	withRealEmitters(f, store)
	req := toolReq()

	mustAuthorize(t, req, f.deps)

	wantKinds(t, storeEventKinds(t, store), []string{"permission_prompt_shown", "permission_decision"})
	var dec events.PermissionDecision
	if err := json.Unmarshal(store.Records()[1].(sessions.Event).Payload, &dec); err != nil {
		t.Fatalf("unmarshal permission_decision: %v", err)
	}
	want := events.PermissionDecision{SubjectKind: req.Kind, Subject: req.Subject, PathScope: req.PathScope, Outcome: decisionGranted}
	if dec != want {
		t.Fatalf("permission_decision = %+v, want %+v (an allow-once approval stores no grant)", dec, want)
	}

	f.cache.hits[turnCacheKeyOf(req)] = f.cap.records[0].outcome
	f.deps.Prompt = neverPrompt

	mustAuthorize(t, req, f.deps)

	wantKinds(t, storeEventKinds(t, store), []string{"permission_prompt_shown", "permission_decision", "permission_matched"})
	last := f.cap.events[len(f.cap.events)-1]
	if last.outcome != outcomeOnce || last.outcomeSource != outcomeSourceCache {
		t.Fatalf("cache resolution event = %+v, want once from the cache (not a second human decision)", last)
	}
}

func TestAuthorizeAllowOnceDecisionEmitErrorPropagates(t *testing.T) {
	boom := errors.New("emit failure")
	f := newFixture(choose(PromptAllowOnce), nil)
	f.deps.EmitDecision = func(string, string, string, string, string, string, DirectIdentity) error { return boom }

	d, err := Authorize(context.Background(), toolReq(), ModeContext{}, f.deps)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if d.Outcome != "" {
		t.Fatalf("decision = %+v, want the zero decision when the decision event fails", d)
	}
}

func TestAuthorizeDecisionRecordsStoredGrantSubject(t *testing.T) {
	tests := []struct {
		name   string
		prompt func(context.Context, ScopeEscalation) (PromptOutcome, error)
		req    MatchRequest
		want   events.PermissionDecision
	}{
		{
			name: "folder grant stores a wider subject than the request",
			prompt: func(context.Context, ScopeEscalation) (PromptOutcome, error) {
				return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "git"}, nil
			},
			req: MatchRequest{Kind: subjectKindDirect, Subject: "git commit -m wip", SubjectTokens: []string{"git", "commit", "-m", "wip"}, PathScope: scopeProj},
			want: events.PermissionDecision{
				SubjectKind: subjectKindDirect, Subject: "git commit -m wip", PathScope: scopeProj,
				Outcome: decisionGranted, GrantKind: grantKindFolder, GrantPathScope: scopeProj, GrantSubject: "git",
				DirectCommandSubject: "git commit -m wip", DirectRequestSubject: "git commit -m wip",
			},
		},
		{
			name: "tool capability grant stores the folded capability",
			prompt: func(context.Context, ScopeEscalation) (PromptOutcome, error) {
				return PromptOutcome{Choice: PromptAllowGlobal, StoredSubject: CapabilityWrite}, nil
			},
			req: MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeProj},
			want: events.PermissionDecision{
				SubjectKind: subjectKindTool, Subject: "edit", PathScope: scopeProj,
				Outcome: decisionGranted, GrantKind: grantKindGlobal, GrantPathScope: allPathsScope, GrantSubject: CapabilityWrite,
			},
		},
		{
			name:   "session grant stores the requested subject",
			prompt: choose(PromptAllowSession),
			req:    toolReq(),
			want: events.PermissionDecision{
				SubjectKind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj,
				Outcome: decisionGranted, GrantKind: grantKindSession, GrantPathScope: scopeProj, GrantSubject: "vcs_commit",
			},
		},
		{
			name:   "host project grant keeps host-form scopes",
			prompt: choose(PromptAllowProject),
			req:    hostReq("web_fetch", "docs.example.com"),
			want: events.PermissionDecision{
				SubjectKind: subjectKindHost, Subject: "web_fetch", Outcome: decisionGranted,
				GrantKind: grantKindProject, HostScope: "docs.example.com", GrantHostScope: "docs.example.com",
				GrantSubject: "web_fetch",
			},
		},
		{
			name:   "allow once stores nothing",
			prompt: choose(PromptAllowOnce),
			req:    toolReq(),
			want: events.PermissionDecision{
				SubjectKind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj, Outcome: decisionGranted,
			},
		},
		{
			name:   "deny stores nothing",
			prompt: choose(PromptDeny),
			req:    toolReq(),
			want: events.PermissionDecision{
				SubjectKind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj, Outcome: decisionDenied,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(tc.prompt, nil)
			store := newStore()
			withRealEmitters(f, store)

			mustAuthorize(t, tc.req, f.deps)

			wantKinds(t, storeEventKinds(t, store), []string{"permission_prompt_shown", "permission_decision"})
			var dec events.PermissionDecision
			if err := json.Unmarshal(store.Records()[1].(sessions.Event).Payload, &dec); err != nil {
				t.Fatalf("unmarshal permission_decision: %v", err)
			}
			if dec != tc.want {
				t.Fatalf("permission_decision = %+v, want %+v", dec, tc.want)
			}
		})
	}
}

func TestAuthorizeGrantDecisionEmitErrorStopsBeforePersist(t *testing.T) {
	boom := errors.New("emit failure")
	f := newFixture(choose(PromptAllowFolder), nil)
	f.deps.EmitDecisionGrant = func(string, string, string, string, string, string, DirectIdentity) error { return boom }

	d, err := Authorize(context.Background(), toolReq(), ModeContext{}, f.deps)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if d.Outcome != "" {
		t.Fatalf("decision = %+v, want the zero decision when the decision event fails", d)
	}
	if len(f.cap.persists) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a failed decision event must not persist or append: persists=%+v appends=%+v", f.cap.persists, f.cap.appends)
	}
}

func TestAuthorizeDeleteAllowOnceNotCached(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)

	d := mustAuthorize(t, deleteReq(), f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if len(f.cap.records) != 0 {
		t.Fatalf("cache records = %+v, want none (a delete allow-once must not be cached)", f.cap.records)
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("allow-once must not append a grant, got %+v", f.cap.appends)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil {
		t.Fatalf("decision = %+v, want once with no grant", d)
	}
}

func TestAuthorizeDeleteDenyNotCached(t *testing.T) {
	f := newFixture(choose(PromptDeny), nil)

	d := mustAuthorize(t, deleteReq(), f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if len(f.cap.records) != 0 {
		t.Fatalf("cache records = %+v, want none (a delete deny must not be cached)", f.cap.records)
	}
	if d.Outcome != outcomeDeny {
		t.Fatalf("decision outcome = %q, want deny", d.Outcome)
	}
}

func TestAuthorizeMoveAllowOnceNotCached(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)

	d := mustAuthorize(t, moveReq(), f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if len(f.cap.records) != 0 {
		t.Fatalf("cache records = %+v, want none (a move allow-once must not be cached)", f.cap.records)
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("allow-once must not append a grant, got %+v", f.cap.appends)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil {
		t.Fatalf("decision = %+v, want once with no grant", d)
	}
}

func TestAuthorizeMoveDenyNotCached(t *testing.T) {
	f := newFixture(choose(PromptDeny), nil)

	d := mustAuthorize(t, moveReq(), f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if len(f.cap.records) != 0 {
		t.Fatalf("cache records = %+v, want none (a move deny must not be cached)", f.cap.records)
	}
	if d.Outcome != outcomeDeny {
		t.Fatalf("decision outcome = %q, want deny", d.Outcome)
	}
}

func TestAuthorizeDenyRoutesEnvelope(t *testing.T) {
	const userEnvelope = `{"denied_by":"user","reason":"not now"}`
	prompt := func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptDeny, DenyEnvelope: userEnvelope}, nil
	}
	f := newFixture(prompt, nil)
	req := toolReq()

	d := mustAuthorize(t, req, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	dec := f.cap.events[1]
	if dec.outcome != decisionDenied || dec.grantKind != "" || dec.grantPathScope != "" {
		t.Fatalf("decision event = %+v, want denied with no grant fields", dec)
	}
	if len(f.cap.records) != 1 || f.cap.records[0].outcome != outcomeDeny {
		t.Fatalf("cache records = %+v, want one deny record", f.cap.records)
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("deny must not append a grant, got %+v", f.cap.appends)
	}
	if d.Outcome != outcomeDeny || d.DenyEnvelope != userEnvelope {
		t.Fatalf("decision = %+v, want deny routing the UI envelope %q", d, userEnvelope)
	}
}

const observedPlanLoop = `for f in a110 a115 a120 a130 a135 a145 a165 a166 b690 a125 a160; do echo "=== $f ==="; head -5 notes/202607/$f.md | grep -i '^#'; grep -iE 'Created|Updated' notes/202607/$f.md | head -3; echo "--- run log rounds/verdict ---"; grep -icE 'round|check|converg|PASS|FAIL|SKIPPED|RETRIED' logs/run-$f.log; done`

func TestPlanModeDenyReasonGivesRecoveryGuidance(t *testing.T) {
	shellCase := func(input string) (MatchRequest, ModeContext) {
		req, mc := shellReqCtxFor(t, "plan", input)
		req.PathScope = scopeProj
		return req, mc
	}
	tests := []struct {
		name      string
		input     string
		wantShape string
	}{
		{
			name:      "observed session shell loop",
			input:     observedPlanLoop,
			wantShape: "shell loops",
		},
		{
			name:      "compact shell loop",
			input:     `for f in a;do echo "$f";done`,
			wantShape: "shell loops",
		},
		{
			name:      "sh -c wrapper",
			input:     `sh -c "rm keep.txt"`,
			wantShape: "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs",
		},
		{
			name:      "bash -lc wrapper",
			input:     `bash -lc "rg TODO"`,
			wantShape: "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs",
		},
		{
			name:      "env wrapper",
			input:     `env -u LC_ALL rg TODO`,
			wantShape: "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs",
		},
		{
			name:      "command wrapper",
			input:     `command rg TODO`,
			wantShape: "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs",
		},
		{
			name:      "wrapper in later pipeline stage",
			input:     `rg TODO | env -u LC_ALL head`,
			wantShape: "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs",
		},
		{
			name:      "wrapper after && control-flow separator",
			input:     `rg TODO && env LC_ALL=C head`,
			wantShape: "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs",
		},
		{
			name:      "wrapper after ; control-flow separator",
			input:     `ls; command rg TODO`,
			wantShape: "shell wrappers such as sh -c, bash -lc, env, command, nice, nohup, time, or xargs",
		},
		{
			name:      "redirection",
			input:     `ls > out.txt`,
			wantShape: "shell redirection",
		},
		{
			name:      "mixed pipe held on the literal route by an env-assignment stage",
			input:     `FOO=bar cat a | grep x ; echo done`,
			wantShape: "a pipe combined with ;, &&, or ||",
		},
		{
			name:      "separator-only echo block",
			input:     `echo "=== files ==="; find . -type f`,
			wantShape: "echo separator blocks",
		},
		{
			name:      "plain mutating direct command",
			input:     `rm -rf x`,
			wantShape: "mutating shell commands",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellCase(tc.input)
			d := mustAuthorizeMode(t, req, mc, f.deps)

			if d.Outcome != outcomeDeny {
				t.Fatalf("outcome = %q, want deny (Plan must still deny the shape)", d.Outcome)
			}
			deniedBy, reason := decodeDenyFields(t, d.DenyEnvelope)
			if deniedBy != "mode" {
				t.Fatalf("denied_by = %q, want mode (a policy denial, not a user denial)", deniedBy)
			}
			if !strings.Contains(reason, tc.wantShape) {
				t.Fatalf("reason %q missing shape guidance %q", reason, tc.wantShape)
			}
			if !strings.Contains(reason, "read/glob") || !strings.Contains(reason, "read-only") {
				t.Fatalf("reason %q missing read/glob + read-only recovery guidance", reason)
			}
			if f.cap.prompts != 0 {
				t.Fatalf("prompted %d times, want 0 (Plan denies without prompting)", f.cap.prompts)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			ev := f.cap.events[len(f.cap.events)-1]
			if ev.outcome != outcomeDeny || ev.outcomeSource != outcomeSourceModeAuto {
				t.Fatalf("event = %+v, want mode_auto deny", ev)
			}
		})
	}
}

func TestPlanModeInvalidLinuxTopGetsBatchRecoveryGuidance(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{"top", "top -n 1", "top -d 1", "top -b", "top -b -n 99999", "top -b -n 1 -u root"} {
		t.Run(input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, input)

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if d.Outcome != outcomeDeny {
				t.Fatalf("outcome = %q, want deny (only the bounded batch form is admitted)", d.Outcome)
			}
			if !IsModeDenyEnvelope(d.DenyEnvelope) {
				t.Fatalf("envelope %q is not a recoverable mode denial", d.DenyEnvelope)
			}
			deniedBy, reason := decodeDenyFields(t, d.DenyEnvelope)
			if deniedBy != "mode" {
				t.Fatalf("denied_by = %q, want mode", deniedBy)
			}
			for _, want := range []string{
				"batch mode (-b)",
				"bounded positive iteration count (-n)",
				"top -b -n 1 — an interactive or unbounded form is never allowed",
			} {
				if !strings.Contains(reason, want) {
					t.Fatalf("reason %q missing top recovery guidance %q", reason, want)
				}
			}
			if len(reason) > maxDenyReasonBytes {
				t.Fatalf("reason is %d bytes, want at most %d so the envelope cap cannot truncate it", len(reason), maxDenyReasonBytes)
			}
			if f.cap.prompts != 0 {
				t.Fatalf("prompted %d times, want 0 (Plan denies without prompting)", f.cap.prompts)
			}
		})
	}
}

func TestPlanModeTopRecoveryStaysLinuxDirectRouteOnly(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		input    string
	}{
		{"freebsd rejects the linux batch form", "freebsd", "top -b -n 1"},
		{"darwin rejects the linux batch form", "darwin", "top -b -n 1"},
		{"redirected top is refused for its shape", "linux", "top -b -n 1 > out"},
		{"wrapped top is refused for its shape", "linux", `sh -c "top"`},
		{"unrelated mutating command", "linux", "rm -rf build"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withShellPlatform(t, tc.platform)
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, tc.input)

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if d.Outcome != outcomeDeny {
				t.Fatalf("outcome = %q, want deny", d.Outcome)
			}
			_, reason := decodeDenyFields(t, d.DenyEnvelope)
			if !strings.Contains(reason, "read/glob") || !strings.Contains(reason, "read-only") {
				t.Fatalf("reason %q lost the generic recovery guidance", reason)
			}
			if strings.Contains(reason, "top -b -n 1") {
				t.Fatalf("reason %q offered the Linux batch form outside the approved case", reason)
			}
		})
	}
}

func TestPlanModeCommandSubstitutionUsesUnsupportedConstructPath(t *testing.T) {
	split, err := SplitCommand(`echo $(rm keep.txt)`)
	if err != nil {
		t.Fatalf("SplitCommand returned error: %v", err)
	}
	if split.AllowedShell {
		t.Fatalf("AllowedShell = true, want false for production command-substitution rejection")
	}
	if split.RejectedConstruct != constructCommandSub {
		t.Fatalf("RejectedConstruct = %q, want %q", split.RejectedConstruct, constructCommandSub)
	}
}

func decodeDenyFields(t *testing.T, envelope string) (deniedBy, reason string) {
	t.Helper()
	var wire struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(envelope), &wire); err != nil {
		t.Fatalf("deny envelope %q is not valid JSON: %v", envelope, err)
	}
	return wire.DeniedBy, wire.Reason
}

func TestAuthorizeDenyDefaultsEmptyEnvelope(t *testing.T) {
	prompt := func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptDeny}, nil
	}
	f := newFixture(prompt, nil)

	d := mustAuthorize(t, toolReq(), f.deps)

	if want := BuildDenyEnvelope(""); d.DenyEnvelope != want {
		t.Fatalf("deny envelope = %q, want default %q", d.DenyEnvelope, want)
	}
}

func TestAuthorizeSessionGrant(t *testing.T) {
	f := newFixture(choose(PromptAllowSession), nil)
	req := toolReq()

	d := mustAuthorize(t, req, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	dec := f.cap.events[1]
	if dec.outcome != decisionGranted || dec.grantKind != grantKindSession || dec.grantPathScope != scopeProj {
		t.Fatalf("decision event = %+v, want granted session at %s", dec, scopeProj)
	}
	if len(f.cap.records) != 1 || f.cap.records[0].outcome != outcomeSessionGrant {
		t.Fatalf("cache records = %+v, want one session_grant record", f.cap.records)
	}
	if len(f.cap.appends) != 1 {
		t.Fatalf("session grant must append exactly one entry, got %+v", f.cap.appends)
	}
	got := f.cap.appends[0]
	want := PermissionEntry{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj, GrantKind: grantKindSession}
	if got != want {
		t.Fatalf("appended entry = %+v, want %+v", got, want)
	}
	if len(f.cap.persists) != 0 {
		t.Fatalf("session grant must not persist, got %+v", f.cap.persists)
	}
	if d.Outcome != outcomeSessionGrant || d.Grant == nil || *d.Grant != want {
		t.Fatalf("decision = %+v, want session_grant carrying the entry", d)
	}
}

func TestAuthorizeFolderGrantPersists(t *testing.T) {
	f := newFixture(choose(PromptAllowFolder), nil)
	req := toolReq()

	d := mustAuthorize(t, req, f.deps)

	dec := f.cap.events[1]
	if dec.outcome != decisionGranted || dec.grantKind != grantKindFolder || dec.grantPathScope != scopeProj {
		t.Fatalf("decision event = %+v, want granted folder at %s", dec, scopeProj)
	}
	want := PermissionEntry{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj, GrantKind: grantKindFolder}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended = %+v, want one %+v", f.cap.appends, want)
	}
	if len(f.cap.persists) != 1 || f.cap.persists[0] != want {
		t.Fatalf("folder grant must persist the entry once, got %+v", f.cap.persists)
	}
	if d.Outcome != outcomeFolderGrant || d.PersistErr != nil {
		t.Fatalf("decision = %+v, want folder_grant with no persist error", d)
	}
}

func TestAuthorizeGlobalGrantUsesAllPathsScope(t *testing.T) {
	f := newFixture(choose(PromptAllowGlobal), nil)
	req := toolReq()

	d := mustAuthorize(t, req, f.deps)

	dec := f.cap.events[1]
	if dec.outcome != decisionGranted || dec.grantKind != grantKindGlobal || dec.grantPathScope != allPathsScope {
		t.Fatalf("decision event = %+v, want granted global at %q", dec, allPathsScope)
	}
	want := PermissionEntry{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: allPathsScope, GrantKind: grantKindGlobal}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended = %+v, want one %+v", f.cap.appends, want)
	}
	if len(f.cap.persists) != 1 || f.cap.persists[0] != want {
		t.Fatalf("global grant must persist the entry once, got %+v", f.cap.persists)
	}
	if d.Outcome != outcomeGlobalGrant {
		t.Fatalf("decision outcome = %q, want %q", d.Outcome, outcomeGlobalGrant)
	}
}

func TestAuthorizeGrantUsesStoredSubjectForDirectCommand(t *testing.T) {
	prompt := func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "git"}, nil
	}
	f := newFixture(prompt, nil)
	req := MatchRequest{Kind: subjectKindDirect, Subject: "git commit -m wip", SubjectTokens: []string{"git", "commit", "-m", "wip"}, PathScope: scopeProj}

	mustAuthorize(t, req, f.deps)

	if len(f.cap.appends) != 1 || f.cap.appends[0].Subject != "git" {
		t.Fatalf("appended subject = %+v, want stored subject \"git\"", f.cap.appends)
	}
	if dec := f.cap.events[1]; dec.subject != "git commit -m wip" {
		t.Fatalf("decision subject = %q, want the request subject", dec.subject)
	}
}

func TestAuthorizeToolGrantStoresCapabilitySubject(t *testing.T) {
	prompt := func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: CapabilityWrite}, nil
	}
	f := newFixture(prompt, nil)
	req := MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeProj}

	d := mustAuthorize(t, req, f.deps)

	want := PermissionEntry{Kind: subjectKindTool, Subject: CapabilityWrite, PathScope: scopeProj, GrantKind: grantKindFolder}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended = %+v, want one capability entry %+v", f.cap.appends, want)
	}
	if len(f.cap.persists) != 1 || f.cap.persists[0] != want {
		t.Fatalf("persisted = %+v, want the capability entry %+v", f.cap.persists, want)
	}
	if d.Grant == nil || *d.Grant != want {
		t.Fatalf("decision grant = %+v, want the capability entry %+v", d.Grant, want)
	}
	if shown := f.cap.events[0]; shown.kind != "permission_prompt_shown" || shown.subject != "edit" {
		t.Fatalf("prompt_shown event = %+v, want the concrete subject \"edit\"", shown)
	}
	if dec := f.cap.events[1]; dec.kind != "permission_decision" || dec.subject != "edit" || dec.grantKind != grantKindFolder || dec.grantPathScope != scopeProj {
		t.Fatalf("decision event = %+v, want concrete request subject %q at folder %s", dec, "edit", scopeProj)
	}
	if len(f.cap.records) != 1 || f.cap.records[0].req.Subject != "edit" {
		t.Fatalf("cache records = %+v, want one record keyed by the concrete subject \"edit\"", f.cap.records)
	}
}

func TestAuthorizeToolGrantWriteTreeEmitsConcreteMkdirSubject(t *testing.T) {
	prompt := func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: CapabilityWriteTree}, nil
	}
	f := newFixture(prompt, nil)
	req := MatchRequest{Kind: subjectKindTool, Subject: "mkdir", PathScope: scopeProj}

	d := mustAuthorize(t, req, f.deps)

	want := PermissionEntry{Kind: subjectKindTool, Subject: CapabilityWriteTree, PathScope: scopeProj, GrantKind: grantKindFolder}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended = %+v, want one write_tree entry %+v", f.cap.appends, want)
	}
	if len(f.cap.persists) != 1 || f.cap.persists[0] != want {
		t.Fatalf("persisted = %+v, want the write_tree entry %+v", f.cap.persists, want)
	}
	if d.Grant == nil || *d.Grant != want {
		t.Fatalf("decision grant = %+v, want the write_tree entry %+v", d.Grant, want)
	}
	if dec := f.cap.events[1]; dec.kind != "permission_decision" || dec.subject != "mkdir" || dec.grantKind != grantKindFolder || dec.grantPathScope != scopeProj {
		t.Fatalf("decision event = %+v, want concrete request subject %q with stored write_tree at folder %s", dec, "mkdir", scopeProj)
	}
}

func TestAuthorizeCapabilityGrantMatchUsesCapabilitySubject(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{toolGrant(CapabilityRead, scopeProj, grantKindFolder)}
	req := MatchRequest{Kind: subjectKindTool, Subject: "list", PathScope: scopeProj}

	d := mustAuthorize(t, req, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceGrant || ev.subject != CapabilityRead {
		t.Fatalf("matched event = %+v, want grant-sourced capability subject %q", ev, CapabilityRead)
	}
	if ev.grantKind != grantKindFolder || ev.grantPathScope != scopeProj {
		t.Fatalf("matched event grant fields = %+v, want folder at %s", ev, scopeProj)
	}
	if d.Outcome != outcomeFolderGrant || d.Grant == nil || d.Grant.Subject != CapabilityRead {
		t.Fatalf("decision = %+v, want a folder grant carrying the capability subject", d)
	}
}

func TestAuthorizeGrantSetsLiteralArgumentHash(t *testing.T) {
	canonical, err := CanonicalLiteralForm(`sh -c "echo hi"`)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm error = %v", err)
	}
	f := newFixture(choose(PromptAllowSession), nil)
	req := MatchRequest{Kind: subjectKindLiteral, Subject: canonical, PathScope: scopeProj}

	mustAuthorize(t, req, f.deps)

	if len(f.cap.appends) != 1 {
		t.Fatalf("want one appended entry, got %+v", f.cap.appends)
	}
	if got, want := f.cap.appends[0].ArgumentHash, ComputeArgumentHash(canonical); got != want {
		t.Fatalf("argument hash = %q, want %q", got, want)
	}
}

func TestAuthorizePersistErrorSurfacedNotFatal(t *testing.T) {
	persistErr := errors.New("lock timeout")
	f := newFixture(choose(PromptAllowFolder), persistErr)

	d, err := Authorize(context.Background(), toolReq(), ModeContext{}, f.deps)
	if err != nil {
		t.Fatalf("persistence failure must not fail authorization: %v", err)
	}
	if !errors.Is(d.PersistErr, persistErr) {
		t.Fatalf("PersistErr = %v, want %v", d.PersistErr, persistErr)
	}
	if d.Outcome != outcomeFolderGrant || d.Grant == nil || len(f.cap.appends) != 1 {
		t.Fatalf("decision = %+v / appends = %+v, want an active folder grant", d, f.cap.appends)
	}
}

func TestAuthorizeDegradesPersistFailureBeforeLaterMatches(t *testing.T) {
	persistErr := errors.New("disk full")
	f := newFixture(choose(PromptAllowGlobal), nil)
	req := toolReq()
	degraded := PermissionEntry{Kind: req.Kind, Subject: req.Subject, PathScope: req.PathScope, GrantKind: grantKindSession}
	f.deps.PersistGrant = func(e PermissionEntry) (PermissionEntry, error) {
		f.cap.persists = append(f.cap.persists, e)
		return degraded, persistErr
	}

	d := mustAuthorize(t, req, f.deps)

	if !errors.Is(d.PersistErr, persistErr) {
		t.Fatalf("PersistErr = %v, want %v", d.PersistErr, persistErr)
	}
	chosen := PermissionEntry{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: allPathsScope, GrantKind: grantKindGlobal}
	if len(f.cap.persists) != 1 || f.cap.persists[0] != chosen {
		t.Fatalf("persist attempt = %+v, want the chosen global entry %+v", f.cap.persists, chosen)
	}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != degraded {
		t.Fatalf("appended = %+v, want only the degraded entry %+v", f.cap.appends, degraded)
	}
	if d.Grant == nil || *d.Grant != degraded {
		t.Fatalf("decision grant = %+v, want the degraded entry %+v", d.Grant, degraded)
	}

	f.deps.Prompt = neverPrompt
	d2 := mustAuthorize(t, req, f.deps)
	if d2.Outcome != outcomeSessionGrant || d2.Grant == nil || d2.Grant.GrantKind != grantKindSession {
		t.Fatalf("same-path re-check = %+v, want a session grant, not a global grant", d2)
	}
	if ev := f.cap.events[len(f.cap.events)-1]; ev.kind != "permission_matched" || ev.grantKind != grantKindSession || ev.grantPathScope != scopeProj {
		t.Fatalf("matched event = %+v, want session grant at %s", ev, scopeProj)
	}

	f.deps.Prompt = choose(PromptDeny)
	other := MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeOther}
	d3 := mustAuthorize(t, other, f.deps)
	if d3.Outcome != outcomeDeny {
		t.Fatalf("out-of-path re-check = %q, want a fresh prompt (deny), not a global-grant match", d3.Outcome)
	}
}

func TestAuthorizeContextCancelled(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Authorize(ctx, toolReq(), ModeContext{}, f.deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(f.cap.events) != 0 || f.cap.prompts != 0 {
		t.Fatalf("a cancelled context must do no work: events=%v prompts=%d", f.cap.events, f.cap.prompts)
	}
}

func TestAuthorizePromptErrorPropagates(t *testing.T) {
	boom := errors.New("ui failure")
	prompt := func(context.Context, ScopeEscalation) (PromptOutcome, error) { return PromptOutcome{}, boom }
	f := newFixture(prompt, nil)

	_, err := Authorize(context.Background(), toolReq(), ModeContext{}, f.deps)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown"})
	if len(f.cap.records) != 0 {
		t.Fatalf("a failed prompt must not record an outcome, got %+v", f.cap.records)
	}
}

func TestAuthorizePassesScopeEscalationToPrompt(t *testing.T) {
	var got ScopeEscalation
	prompt := func(_ context.Context, esc ScopeEscalation) (PromptOutcome, error) {
		got = esc
		return PromptOutcome{Choice: PromptAllowOnce}, nil
	}
	f := newFixture(prompt, nil)
	f.grants.entries = append(f.grants.entries, PermissionEntry{
		Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj + "/sub", GrantKind: grantKindFolder,
	})
	req := MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj}

	mustAuthorize(t, req, f.deps)

	if got.NarrowerScope != scopeProj+"/sub" {
		t.Fatalf("prompt escalation = %+v, want NarrowerScope %q", got, scopeProj+"/sub")
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("escalation prompt must not append a grant, got %+v", f.cap.appends)
	}
}

func TestAuthorizeNoEscalationWhenNoNarrowerGrant(t *testing.T) {
	got := ScopeEscalation{NarrowerScope: "sentinel"}
	prompt := func(_ context.Context, esc ScopeEscalation) (PromptOutcome, error) {
		got = esc
		return PromptOutcome{Choice: PromptAllowOnce}, nil
	}
	f := newFixture(prompt, nil)

	mustAuthorize(t, toolReq(), f.deps)

	if got.NarrowerScope != "" {
		t.Fatalf("fresh prompt escalation = %+v, want empty", got)
	}
}

func TestAuthorizeEmitsValidG300Events(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(f *orchFixture, store *sessions.Store)
		req       MatchRequest
		modeCtx   ModeContext
		wantKinds []string
	}{
		{
			name:      "plan deny mutating",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = neverPrompt },
			req:       toolReq(),
			modeCtx:   ModeContext{Mode: "plan", Class: ClassMutating},
			wantKinds: []string{"permission_matched"},
		},
		{
			name:      "plan allow read-only",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = neverPrompt },
			req:       toolReq(),
			modeCtx:   ModeContext{Mode: "plan", Class: ClassReadOnly},
			wantKinds: []string{"permission_matched"},
		},
		{
			name:      "plan literal deny carries argument_hash",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = neverPrompt },
			req:       MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj},
			modeCtx:   ModeContext{Mode: "plan", Class: ClassMutating},
			wantKinds: []string{"permission_matched"},
		},
		{
			name:      "plan read-only shell allow",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = neverPrompt },
			req:       MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeProj},
			modeCtx:   ModeContext{Mode: "plan", Class: ClassMutating, Stages: []StageNormalization{{Route: RouteDirect, Tokens: []string{"ls"}}}},
			wantKinds: []string{"permission_matched"},
		},
		{
			name:      "plan mutating shell deny",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = neverPrompt },
			req:       MatchRequest{Kind: subjectKindDirect, Subject: "rm -rf x", SubjectTokens: []string{"rm", "-rf", "x"}, PathScope: scopeProj},
			modeCtx:   ModeContext{Mode: "plan", Class: ClassMutating, Stages: []StageNormalization{{Route: RouteDirect, Tokens: []string{"rm", "-rf", "x"}}}},
			wantKinds: []string{"permission_matched"},
		},
		{
			name:      "auto edits in-scope create allow",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = neverPrompt },
			req:       createReq(scopeProj + "/sub"),
			modeCtx:   autoCreateMode(scopeProj + "/sub/new.txt"),
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "grant match",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.grants.entries = []PermissionEntry{toolGrant("vcs_commit", scopeProj, grantKindFolder)}
				f.deps.Prompt = neverPrompt
			},
			req:       toolReq(),
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "cache deny",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.cache.hits[turnCacheKeyOf(toolReq())] = outcomeDeny
				f.deps.Prompt = neverPrompt
			},
			req:       toolReq(),
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "cache literal grant shadow-case",
			setup: func(f *orchFixture, _ *sessions.Store) {
				req := MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj}
				f.cache.hits[turnCacheKeyOf(req)] = outcomeFolderGrant
				f.deps.Prompt = neverPrompt
			},
			req:       MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj},
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "cache literal once",
			setup: func(f *orchFixture, _ *sessions.Store) {
				req := MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj}
				f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce
				f.deps.Prompt = neverPrompt
			},
			req:       MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj},
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "cache literal deny",
			setup: func(f *orchFixture, _ *sessions.Store) {
				req := MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj}
				f.cache.hits[turnCacheKeyOf(req)] = outcomeDeny
				f.deps.Prompt = neverPrompt
			},
			req:       MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj},
			wantKinds: []string{"permission_matched"},
		},
		{
			name:      "allow once",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptAllowOnce) },
			req:       toolReq(),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name:      "deny prompt",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptDeny) },
			req:       toolReq(),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name:      "session grant",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptAllowSession) },
			req:       toolReq(),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name: "tool capability folder grant",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.deps.Prompt = func(context.Context, ScopeEscalation) (PromptOutcome, error) {
					return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: CapabilityWrite}, nil
				}
			},
			req:       MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeProj},
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name: "tool capability grant match",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.grants.entries = []PermissionEntry{toolGrant(CapabilityRead, scopeProj, grantKindFolder)}
				f.deps.Prompt = neverPrompt
			},
			req:       MatchRequest{Kind: subjectKindTool, Subject: "list", PathScope: scopeProj},
			wantKinds: []string{"permission_matched"},
		},
		{
			name:      "global grant",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptAllowGlobal) },
			req:       toolReq(),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name:      "host session grant",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptAllowSession) },
			req:       hostReq("web_search", "docs.example.com"),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name:      "host project grant",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptAllowProject) },
			req:       hostReq("web_fetch", "docs.example.com"),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name:      "host allow once",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptAllowOnce) },
			req:       hostReq("web_fetch", "docs.example.com"),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name:      "host deny prompt",
			setup:     func(f *orchFixture, _ *sessions.Store) { f.deps.Prompt = choose(PromptDeny) },
			req:       hostReq("web_fetch", "docs.example.com"),
			wantKinds: []string{"permission_prompt_shown", "permission_decision"},
		},
		{
			name: "host project grant match",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.grants.entries = []PermissionEntry{hostGrant("web_fetch", "docs.example.com")}
			},
			req:       hostReq("web_fetch", "docs.example.com"),
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "host session grant match",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.grants.entries = []PermissionEntry{{Kind: subjectKindTool, Subject: "web_search", HostScope: "mcp.exa.ai", GrantKind: grantKindSession}}
			},
			req:       hostReq("web_search", "mcp.exa.ai"),
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "host cache once",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.cache.hits[turnCacheKeyOf(hostReq("web_fetch", "docs.example.com"))] = outcomeOnce
			},
			req:       hostReq("web_fetch", "docs.example.com"),
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "host cache deny",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.cache.hits[turnCacheKeyOf(hostReq("web_fetch", "docs.example.com"))] = outcomeDeny
			},
			req:       hostReq("web_fetch", "docs.example.com"),
			wantKinds: []string{"permission_matched"},
		},
		{
			name: "host cache project grant",
			setup: func(f *orchFixture, _ *sessions.Store) {
				f.cache.hits[turnCacheKeyOf(hostReq("web_fetch", "docs.example.com"))] = grantOutcome(grantKindProject)
			},
			req:       hostReq("web_fetch", "docs.example.com"),
			wantKinds: []string{"permission_matched"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			store := newStore()
			f.deps.EmitPromptShown = func(sk, s, ps string, dt []string, id DirectIdentity) error {
				return events.EmitPromptShown(store, sk, s, ps, dt, id.CommandSubject, id.RequestSubject)
			}
			f.deps.EmitDecision = func(sk, s, ps, o, gk, gps string, id DirectIdentity) error {
				return events.EmitDecision(store, sk, s, ps, o, gk, gps, id.CommandSubject, id.RequestSubject)
			}
			f.deps.EmitDecisionGrant = func(sk, s, ps, gk, gps, gs string, id DirectIdentity) error {
				return events.EmitDecisionGrant(store, sk, s, ps, gk, gps, gs, id.CommandSubject, id.RequestSubject)
			}
			f.deps.EmitMatched = func(sk, s, ps, gk, gps, o, src, ah, drs string) error {
				return events.EmitMatchedIdentity(store, sk, s, ps, gk, gps, o, src, ah, drs)
			}
			tc.setup(f, store)

			if _, err := Authorize(context.Background(), tc.req, tc.modeCtx, f.deps); err != nil {
				t.Fatalf("Authorize emitted an invalid g300 payload: %v", err)
			}
			wantKinds(t, storeEventKinds(t, store), tc.wantKinds)
		})
	}
}

func withRealEmitters(f *orchFixture, store *sessions.Store) {
	cap := f.cap
	f.deps.EmitPromptShown = func(sk, s, ps string, dt []string, id DirectIdentity) error {
		cap.events = append(cap.events, orchEmitted{kind: "permission_prompt_shown", subjectKind: sk, subject: s, pathScope: ps, directTokens: dt, directCommandSubject: id.CommandSubject, directRequestSubject: id.RequestSubject})
		return events.EmitPromptShown(store, sk, s, ps, dt, id.CommandSubject, id.RequestSubject)
	}
	f.deps.EmitDecision = func(sk, s, ps, o, gk, gps string, id DirectIdentity) error {
		cap.events = append(cap.events, orchEmitted{kind: "permission_decision", subjectKind: sk, subject: s, pathScope: ps, outcome: o, grantKind: gk, grantPathScope: gps, directCommandSubject: id.CommandSubject, directRequestSubject: id.RequestSubject})
		return events.EmitDecision(store, sk, s, ps, o, gk, gps, id.CommandSubject, id.RequestSubject)
	}
	f.deps.EmitDecisionGrant = func(sk, s, ps, gk, gps, gs string, id DirectIdentity) error {
		cap.events = append(cap.events, orchEmitted{kind: "permission_decision", subjectKind: sk, subject: s, pathScope: ps, outcome: decisionGranted, grantKind: gk, grantPathScope: gps, grantSubject: gs, directCommandSubject: id.CommandSubject, directRequestSubject: id.RequestSubject})
		return events.EmitDecisionGrant(store, sk, s, ps, gk, gps, gs, id.CommandSubject, id.RequestSubject)
	}
	f.deps.EmitMatched = func(sk, s, ps, gk, gps, o, src, ah, drs string) error {
		cap.events = append(cap.events, orchEmitted{kind: "permission_matched", subjectKind: sk, subject: s, pathScope: ps, grantKind: gk, grantPathScope: gps, outcome: o, outcomeSource: src, argHash: ah, directRequestSubject: drs})
		return events.EmitMatchedIdentity(store, sk, s, ps, gk, gps, o, src, ah, drs)
	}
}

func TestAuthorize_GeneralizedCompoundGrantMatch(t *testing.T) {
	encoded, err := EncodeCompoundSubject(true, []string{"gofmt :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	reqSubject, err := CanonicalLiteralForm(`sh -c 'gofmt -l -w pkg/ && go build -v ./cmd/...'`)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm error: %v", err)
	}

	f := newFixture(neverPrompt, nil)
	store := newStore()
	withRealEmitters(f, store)
	f.grants.entries = []PermissionEntry{{Kind: subjectKindLiteral, Subject: encoded, PathScope: scopeProj, GrantKind: grantKindFolder, ArgumentHash: ComputeArgumentHash(encoded)}}
	f.deps.Prompt = neverPrompt

	req := MatchRequest{Kind: subjectKindLiteral, Subject: reqSubject, PathScope: scopeProj}
	if _, err := Authorize(context.Background(), req, ModeContext{}, f.deps); err != nil {
		t.Fatalf("Authorize emitted an invalid g300 payload: %v", err)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.subject != encoded {
		t.Errorf("matched event subject = %q, want the compound encoding %q", ev.subject, encoded)
	}
	if ev.argHash != ComputeArgumentHash(encoded) {
		t.Errorf("matched event argument_hash = %q, want SHA-256 of the pinned encoding", ev.argHash)
	}
}

func TestAuthorize_GeneralizedCompoundGrantCreate(t *testing.T) {
	encoded, err := EncodeCompoundSubject(false, []string{"gofmt :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	reqSubject, err := CanonicalLiteralForm("gofmt -w a.go && go build ./...")
	if err != nil {
		t.Fatalf("CanonicalLiteralForm error: %v", err)
	}

	f := newFixture(neverPrompt, nil)
	store := newStore()
	withRealEmitters(f, store)
	f.deps.Prompt = func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: encoded}, nil
	}

	req := MatchRequest{Kind: subjectKindLiteral, Subject: reqSubject, PathScope: scopeProj}
	if _, err := Authorize(context.Background(), req, ModeContext{}, f.deps); err != nil {
		t.Fatalf("Authorize emitted an invalid g300 payload: %v", err)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if len(f.cap.appends) != 1 {
		t.Fatalf("expected one appended grant, got %d", len(f.cap.appends))
	}
	got := f.cap.appends[0]
	if got.Subject != encoded {
		t.Errorf("stored grant subject = %q, want the compound encoding %q", got.Subject, encoded)
	}
	if got.ArgumentHash != ComputeArgumentHash(encoded) {
		t.Errorf("stored grant argument_hash = %q, want SHA-256 of the pinned encoding", got.ArgumentHash)
	}
}

func TestAuthorize_GeneralizedCompoundGrantPersistAndReadBack(t *testing.T) {
	encoded, err := EncodeCompoundSubject(true, []string{"gofmt :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}

	f := newFixture(neverPrompt, nil)
	store := newStore()
	withRealEmitters(f, store)
	f.deps.Prompt = func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: encoded}, nil
	}

	createReq := MatchRequest{Kind: subjectKindLiteral, Subject: canon(t, `sh -c 'gofmt -w a.go && go build ./...'`), PathScope: scopeProj}
	if _, err := Authorize(context.Background(), createReq, ModeContext{}, f.deps); err != nil {
		t.Fatalf("Authorize (create) emitted an invalid g300 payload: %v", err)
	}
	if len(f.cap.persists) != 1 || f.cap.persists[0].Subject != encoded {
		t.Fatalf("persistence seam = %+v, want one entry with the compound encoding %q", f.cap.persists, encoded)
	}
	if len(f.cap.appends) != 1 {
		t.Fatalf("expected one appended grant, got %d", len(f.cap.appends))
	}
	if got := f.cap.appends[0]; got.Subject != encoded || got.ArgumentHash != ComputeArgumentHash(encoded) {
		t.Fatalf("appended grant = {Subject:%q Hash:%q}, want {%q, %q}", got.Subject, got.ArgumentHash, encoded, ComputeArgumentHash(encoded))
	}

	accept := Match(MatchRequest{Kind: subjectKindLiteral, Subject: canon(t, `sh -c 'gofmt -l -w pkg/ && go build -v ./cmd/...'`), PathScope: scopeProj}, f.grants.entries)
	if !accept.Matched {
		t.Fatalf("differently-argued matching compound was not authorized by the persisted grant")
	}
	if accept.Grant == nil || accept.Grant.Subject != encoded {
		t.Fatalf("read-back matched grant = %+v, want the persisted compound encoding %q", accept.Grant, encoded)
	}

	for _, tc := range []struct {
		name    string
		subject string
	}{
		{"swapped program", `sh -c 'gofmt -w a.go && go vet ./...'`},
		{"changed operator", `sh -c 'gofmt -w a.go | go build ./...'`},
	} {
		if res := Match(MatchRequest{Kind: subjectKindLiteral, Subject: canon(t, tc.subject), PathScope: scopeProj}, f.grants.entries); res.Matched {
			t.Errorf("%s: compound %q matched the persisted grant, want no match", tc.name, tc.subject)
		}
	}
}

func TestAuthorize_DestructiveCompoundGrantStaysByteExact(t *testing.T) {
	reqSubject := canon(t, "gofmt -w a.go && git add .")

	f := newFixture(neverPrompt, nil)
	store := newStore()
	withRealEmitters(f, store)
	f.deps.Prompt = func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: ""}, nil
	}

	req := MatchRequest{Kind: subjectKindLiteral, Subject: reqSubject, PathScope: scopeProj}
	if _, err := Authorize(context.Background(), req, ModeContext{}, f.deps); err != nil {
		t.Fatalf("Authorize emitted an invalid g300 payload: %v", err)
	}
	if len(f.cap.appends) != 1 {
		t.Fatalf("expected one appended grant, got %d", len(f.cap.appends))
	}
	got := f.cap.appends[0]
	if isCompoundSubject(got.Subject) {
		t.Errorf("destructive compound persisted a generalized subject %q, want byte-exact", got.Subject)
	}
	if got.Subject != reqSubject {
		t.Errorf("stored grant subject = %q, want the byte-exact request subject %q", got.Subject, reqSubject)
	}
	if got.ArgumentHash != ComputeArgumentHash(reqSubject) {
		t.Errorf("stored grant argument_hash = %q, want SHA-256 of the byte-exact subject", got.ArgumentHash)
	}
	if len(f.cap.persists) != 1 || f.cap.persists[0].Subject != reqSubject {
		t.Errorf("persistence seam = %+v, want the byte-exact request subject %q", f.cap.persists, reqSubject)
	}
}

func TestAuthorizePlanDeniesMutatingWithoutPrompt(t *testing.T) {
	f := newFixture(neverPrompt, nil)

	d := mustAuthorizeMode(t, toolReq(), ModeContext{Mode: "plan", Class: ClassMutating}, f.deps)

	if f.cap.prompts != 0 {
		t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeDeny {
		t.Fatalf("mode deny event = %+v, want mode_auto deny", ev)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("mode_auto deny carried grant fields: %+v", ev)
	}
	if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
		t.Fatalf("decision = %+v, want deny with an envelope", d)
	}
	var env struct {
		DeniedBy string `json:"denied_by"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(d.DenyEnvelope), &env); err != nil {
		t.Fatalf("deny envelope is not clean JSON: %v", err)
	}
	if env.DeniedBy != "mode" {
		t.Fatalf("denied_by = %q, want \"mode\" (a policy denial must not look like a user denial)", env.DeniedBy)
	}
	if !strings.Contains(env.Reason, "plan") || !strings.Contains(env.Reason, "mutating") {
		t.Fatalf("reason = %q, want it to name the plan mode and the mutating restriction", env.Reason)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a mode decision must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizePlanAllowsReadOnlyWithoutPrompt(t *testing.T) {
	f := newFixture(neverPrompt, nil)

	d := mustAuthorizeMode(t, toolReq(), ModeContext{Mode: "plan", Class: ClassReadOnly}, f.deps)

	if f.cap.prompts != 0 {
		t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
		t.Fatalf("mode allow event = %+v, want mode_auto once", ev)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("mode_auto allow carried grant fields: %+v", ev)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil || d.DenyEnvelope != "" {
		t.Fatalf("decision = %+v, want once with no grant/envelope", d)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a mode decision must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizeExternalReadPromptsInEveryMode(t *testing.T) {
	for _, m := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(m, func(t *testing.T) {
			f := newFixture(choose(PromptAllowOnce), nil)
			mc := ModeContext{Mode: m, Class: ClassReadOnly, ToolName: "read", ExternalRead: true}

			d := mustAuthorizeMode(t, toolReq(), mc, f.deps)

			if f.cap.prompts != 1 {
				t.Fatalf("prompt called %d times in %s, want 1 (an external read must prompt, not auto-resolve)", f.cap.prompts, m)
			}
			for _, ev := range f.cap.events {
				if ev.outcomeSource == outcomeSourceModeAuto {
					t.Fatalf("external read produced a mode_auto event in %s: %+v (mode posture must not resolve it)", m, ev)
				}
			}
			if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
				t.Fatalf("decision = %+v in %s, want a prompt-sourced once with no deny envelope", d, m)
			}
		})
	}
}

func TestAuthorizeOpenReadAllowsWithoutPromptInEveryMode(t *testing.T) {
	for _, m := range []string{"", "build", modeAutoEdits, modePlan} {
		t.Run("mode="+m, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			f.grants.entries = []PermissionEntry{toolGrant("read", scopeProj, grantKindFolder)}
			req := MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: scopeProj}
			mc := ModeContext{Mode: m, Class: ClassReadOnly, ToolName: "read", OpenRead: true}

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("prompt called %d times, want 0", f.cap.prompts)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			ev := f.cap.events[0]
			if ev.outcomeSource != outcomeSourceOpenRead || ev.outcome != outcomeOnce || ev.subject != "read" || ev.pathScope != scopeProj {
				t.Fatalf("event = %+v, want open_read once for read at %s", ev, scopeProj)
			}
			if ev.grantKind != "" || ev.grantPathScope != "" {
				t.Fatalf("open_read allow carried grant fields: %+v", ev)
			}
			if d.Outcome != outcomeOnce || d.Grant != nil || d.ReadOnlyAuto || d.DenyEnvelope != "" {
				t.Fatalf("decision = %+v, want once with no grant, no ReadOnlyAuto and no envelope", d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 || len(f.cap.persists) != 0 {
				t.Fatalf("open_read touched the cache or grants: records=%v appends=%v persists=%v", f.cap.records, f.cap.appends, f.cap.persists)
			}
		})
	}

	t.Run("fresh confirmation still prompts", func(t *testing.T) {
		f := newFixture(choose(PromptAllowOnce), nil)
		req := hostReq("web_fetch", "docs.example.com")
		req.FreshConfirmation = true
		mc := hostModeCtx("web_fetch")
		mc.OpenRead = true

		mustAuthorizeMode(t, req, mc, f.deps)

		if f.cap.prompts != 1 {
			t.Fatalf("prompt called %d times, want 1", f.cap.prompts)
		}
		for _, ev := range f.cap.events {
			if ev.outcomeSource == outcomeSourceOpenRead {
				t.Fatalf("fresh confirmation resolved through open_read: %+v", ev)
			}
		}
	})
}

func TestAuthorizeShellPathAskSkipsModePosture(t *testing.T) {
	type shellCase struct {
		name  string
		req   MatchRequest
		mc    ModeContext
		grant PermissionEntry
	}
	shellCases := func(m string) []shellCase {
		return []shellCase{
			{
				name:  "direct",
				req:   MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeProj},
				mc:    ModeContext{Mode: m, Class: ClassMutating, Stages: []StageNormalization{{Route: RouteDirect, Tokens: []string{"ls"}, ExecForms: []HomeExpansion{{}}}}},
				grant: directGrant("ls", scopeProj, grantKindFolder),
			},
			{
				name:  "literal",
				req:   MatchRequest{Kind: subjectKindLiteral, Subject: "ls 2>/dev/null", PathScope: scopeProj},
				mc:    ModeContext{Mode: m, Class: ClassMutating, LiteralRoute: true},
				grant: literalGrant("ls 2>/dev/null", scopeProj, grantKindFolder),
			},
		}
	}
	noModeAuto := func(t *testing.T, f *orchFixture) {
		t.Helper()
		for _, ev := range f.cap.events {
			if ev.outcomeSource == outcomeSourceModeAuto {
				t.Fatalf("event %+v is mode_auto, want mode posture skipped", ev)
			}
		}
	}
	for _, m := range []string{"build", modeAutoEdits, modePlan} {
		for _, tc := range shellCases(m) {
			t.Run(m+"/"+tc.name, func(t *testing.T) {
				f := newFixture(neverPrompt, nil)
				if _, handled, err := modePosture(tc.req, tc.mc, f.deps); err != nil || !handled {
					t.Fatalf("modePosture without the flag handled = %v, err = %v; want the read-only auto-allow", handled, err)
				}

				asking := tc.mc
				asking.ShellPathAsk = true
				f = newFixture(neverPrompt, nil)
				if _, handled, err := modePosture(tc.req, asking, f.deps); err != nil || handled {
					t.Fatalf("modePosture with the flag handled = %v, err = %v; want not handled", handled, err)
				}
				if len(f.cap.events) != 0 {
					t.Fatalf("events = %+v, want none from mode posture", f.cap.events)
				}

				f = newFixture(neverPrompt, nil)
				f.grants.entries = []PermissionEntry{tc.grant}
				if d := mustAuthorizeMode(t, tc.req, asking, f.deps); d.Grant == nil || d.DenyEnvelope != "" {
					t.Fatalf("decision = %+v, want the stored grant to allow", d)
				}
				noModeAuto(t, f)

				f = newFixture(neverPrompt, nil)
				f.cache.hits[turnCacheKeyOf(tc.req)] = outcomeOnce
				if d := mustAuthorizeMode(t, tc.req, asking, f.deps); d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
					t.Fatalf("decision = %+v, want the turn cache to allow", d)
				}
				noModeAuto(t, f)

				f = newFixture(choose(PromptAllowOnce), nil)
				if d := mustAuthorizeMode(t, tc.req, asking, f.deps); d.Outcome != outcomeOnce || d.ReadOnlyAuto {
					t.Fatalf("decision = %+v, want a prompt-sourced once", d)
				}
				if f.cap.prompts != 1 {
					t.Fatalf("prompts = %d, want 1", f.cap.prompts)
				}
				noModeAuto(t, f)
			})
		}
	}

	t.Run("auto declared command", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindDirect, Subject: "make test", SubjectTokens: []string{"make", "test"}, PathScope: scopeProj}
		mc := ModeContext{
			Mode:             modeAutoEdits,
			Class:            ClassMutating,
			Stages:           []StageNormalization{{Route: RouteDirect, Tokens: []string{"make", "test"}, ExecForms: []HomeExpansion{{}, {}}}},
			DeclaredCommands: []DeclaredCommand{{Subject: "make test"}},
		}
		f := newFixture(neverPrompt, nil)
		if d := mustAuthorizeMode(t, req, mc, f.deps); d.DenyEnvelope != "" {
			t.Fatalf("decision = %+v, want the declared command allowed without the flag", d)
		}

		mc.ShellPathAsk = true
		f = newFixture(choose(PromptAllowOnce), nil)
		mustAuthorizeMode(t, req, mc, f.deps)
		if f.cap.prompts != 1 {
			t.Fatalf("prompts = %d, want the declared command to prompt when the shell check asks", f.cap.prompts)
		}
		for _, ev := range f.cap.events {
			if ev.outcomeSource == OutcomeSourceDeclaredCommand {
				t.Fatalf("event %+v is a declared-command allow, want the prompt", ev)
			}
		}
	})
}

func webReq(subject string) MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: subject, PathScope: scopeProj}
}

func TestAuthorizeNetworkEgressPromptsInEveryMode(t *testing.T) {
	for _, subject := range []string{"web_search", "web_fetch"} {
		for _, m := range []string{"build", modeAutoEdits, modePlan} {
			for _, class := range []OperationClass{ClassReadOnly, ClassMutating} {
				t.Run(subject+"/"+m+"/"+string(class), func(t *testing.T) {
					f := newFixture(choose(PromptAllowOnce), nil)
					mc := ModeContext{Mode: m, Class: class, ToolName: subject, NetworkEgress: true}

					d := mustAuthorizeMode(t, webReq(subject), mc, f.deps)

					if f.cap.prompts != 1 {
						t.Fatalf("prompt called %d times in %s, want 1 (a web call must prompt, not auto-resolve)", f.cap.prompts, m)
					}
					for _, ev := range f.cap.events {
						if ev.outcomeSource == outcomeSourceModeAuto {
							t.Fatalf("web call produced a mode_auto event in %s: %+v (mode posture must not resolve it)", m, ev)
						}
					}
					if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
						t.Fatalf("decision = %+v in %s, want a prompt-sourced once with no deny envelope", d, m)
					}
				})
			}
		}
	}
}

func TestAuthorizeNetworkEgressDenialKeepsBoundedEnvelope(t *testing.T) {
	for _, m := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(m, func(t *testing.T) {
			f := newFixture(choose(PromptDeny), nil)
			mc := ModeContext{Mode: m, Class: ClassMutating, ToolName: "web_search", NetworkEgress: true}

			d := mustAuthorizeMode(t, webReq("web_search"), mc, f.deps)

			if d.Outcome != outcomeDeny {
				t.Fatalf("outcome = %q in %s, want %q", d.Outcome, m, outcomeDeny)
			}
			if d.DenyEnvelope != BuildDenyEnvelope("") {
				t.Fatalf("deny envelope = %q in %s, want the existing bounded user-deny envelope", d.DenyEnvelope, m)
			}
			if len(f.cap.appends) != 0 {
				t.Fatalf("a denied web call created grants in %s: %v", m, f.cap.appends)
			}
		})
	}
}

func TestAuthorizeNetworkEgressMatchingGrantStillShortCircuits(t *testing.T) {
	for _, m := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(m, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			f.grants.entries = []PermissionEntry{toolGrant("web_search", scopeProj, grantKindSession)}
			mc := ModeContext{Mode: m, Class: ClassMutating, ToolName: "web_search", NetworkEgress: true}

			d := mustAuthorizeMode(t, webReq("web_search"), mc, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("prompt called %d times in %s, want 0 (a matching grant authorizes the call)", f.cap.prompts, m)
			}
			if d.Outcome != outcomeSessionGrant || d.Grant == nil {
				t.Fatalf("decision = %+v in %s, want a session-grant match", d, m)
			}
			if ev := f.cap.events[0]; ev.outcomeSource != outcomeSourceGrant {
				t.Fatalf("outcome source = %q in %s, want %q", ev.outcomeSource, m, outcomeSourceGrant)
			}
		})
	}
}

func hostModeCtx(subject string) ModeContext {
	return ModeContext{Mode: "build", Class: ClassMutating, ToolName: subject, NetworkEgress: true}
}

func authorizeHost(t *testing.T, f *orchFixture, subject, host string) Decision {
	t.Helper()
	return mustAuthorizeMode(t, hostReq(subject, host), hostModeCtx(subject), f.deps)
}

func lastEvent(t *testing.T, f *orchFixture) orchEmitted {
	t.Helper()
	if len(f.cap.events) == 0 {
		t.Fatalf("no events emitted")
	}
	return f.cap.events[len(f.cap.events)-1]
}

func TestAuthorizeHostAllowOnceIsCachedPerHostAndTool(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	f.deps.Cache = NewTurnCache()

	if d := authorizeHost(t, f, "web_search", "docs.example.com"); d.Outcome != outcomeOnce {
		t.Fatalf("first host decision = %+v, want %q", d, outcomeOnce)
	}
	if f.cap.prompts != 1 {
		t.Fatalf("prompt called %d times for the first host call, want 1", f.cap.prompts)
	}

	d := authorizeHost(t, f, "web_search", "docs.example.com")
	if d.Outcome != outcomeOnce || d.Grant != nil {
		t.Fatalf("repeated host decision = %+v, want a grantless %q", d, outcomeOnce)
	}
	if f.cap.prompts != 1 {
		t.Fatalf("prompt called %d times after the repeat, want 1 (the repeat must hit the cache)", f.cap.prompts)
	}
	if ev := lastEvent(t, f); ev.kind != "permission_matched" || ev.outcomeSource != outcomeSourceCache {
		t.Fatalf("repeat event = %+v, want a cache-sourced permission_matched", ev)
	}

	probes := []struct {
		name    string
		subject string
		host    string
	}{
		{"sibling host", "web_search", "api.example.com"},
		{"registrable domain", "web_search", "example.com"},
		{"other web tool", "web_fetch", "docs.example.com"},
	}
	for i, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			authorizeHost(t, f, p.subject, p.host)
			if want := 2 + i; f.cap.prompts != want {
				t.Fatalf("prompt called %d times after the %s probe, want %d (it must not inherit the cached decision)",
					f.cap.prompts, p.name, want)
			}
		})
	}
}

func TestAuthorizeHostDenyIsCachedPerHostAndTool(t *testing.T) {
	f := newFixture(choose(PromptDeny), nil)
	f.deps.Cache = NewTurnCache()

	first := authorizeHost(t, f, "web_search", "docs.example.com")
	if first.Outcome != outcomeDeny || first.DenyEnvelope != BuildDenyEnvelope("") {
		t.Fatalf("first host denial = %+v, want %q with the existing synthetic envelope", first, outcomeDeny)
	}

	repeat := authorizeHost(t, f, "web_search", "docs.example.com")
	if repeat.Outcome != outcomeDeny || repeat.DenyEnvelope != BuildDenyEnvelope("") {
		t.Fatalf("repeated host denial = %+v, want %q with the existing synthetic envelope", repeat, outcomeDeny)
	}
	if f.cap.prompts != 1 {
		t.Fatalf("prompt called %d times after the repeat, want 1 (the repeat must hit the cache)", f.cap.prompts)
	}
	if ev := lastEvent(t, f); ev.kind != "permission_matched" || ev.outcomeSource != outcomeSourceCache || ev.outcome != outcomeDeny {
		t.Fatalf("repeat event = %+v, want a cache-sourced permission_matched deny", ev)
	}

	probes := []struct {
		name    string
		subject string
		host    string
	}{
		{"sibling host", "web_search", "api.example.com"},
		{"other web tool", "web_fetch", "docs.example.com"},
	}
	for i, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			authorizeHost(t, f, p.subject, p.host)
			if want := 2 + i; f.cap.prompts != want {
				t.Fatalf("prompt called %d times after the %s probe, want %d (a denial must not transfer)",
					f.cap.prompts, p.name, want)
			}
		})
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("a denied host call created grants: %v", f.cap.appends)
	}
}

func TestAuthorizeHostAuditRecordsCarryWebToolAndCanonicalHost(t *testing.T) {
	f := newFixture(choose(PromptAllowSession), nil)
	f.deps.Cache = NewTurnCache()

	if d := authorizeHost(t, f, "web_fetch", "docs.example.com"); d.Outcome != outcomeSessionGrant {
		t.Fatalf("host session decision = %+v, want %q", d, outcomeSessionGrant)
	}
	authorizeHost(t, f, "web_fetch", "docs.example.com")

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision", "permission_matched"})
	for _, ev := range f.cap.events {
		if ev.subjectKind != subjectKindHost || ev.subject != "web_fetch" || ev.pathScope != "docs.example.com" {
			t.Fatalf("event = %+v, want the web tool with the canonical host as its scope", ev)
		}
	}
	if ev := f.cap.events[1]; ev.grantKind != grantKindSession || ev.grantPathScope != "docs.example.com" {
		t.Fatalf("decision event = %+v, want a session grant scoped to the canonical host", ev)
	}
	ev := f.cap.events[2]
	if ev.grantKind != grantKindSession || ev.grantPathScope != "docs.example.com" || ev.outcomeSource != outcomeSourceGrant || ev.argHash != "" {
		t.Fatalf("match event = %+v, want a grant-sourced session match on the canonical host with no argument hash", ev)
	}
}

func TestAuthorizeHostCacheRecordCarriesCanonicalHost(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	f.deps.Cache = NewTurnCache()

	authorizeHost(t, f, "web_search", "mcp.exa.ai")
	authorizeHost(t, f, "web_search", "mcp.exa.ai")

	ev := lastEvent(t, f)
	if ev.kind != "permission_matched" || ev.outcomeSource != outcomeSourceCache {
		t.Fatalf("repeat event = %+v, want a cache-sourced permission_matched", ev)
	}
	if ev.subjectKind != subjectKindHost || ev.subject != "web_search" || ev.pathScope != "mcp.exa.ai" {
		t.Fatalf("cache event = %+v, want the web tool with the canonical host as its scope", ev)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("cache event = %+v, want no grant fields for a cached once", ev)
	}
}

func TestAuthorizeHostAllowSessionKeepsOneExactHostGrantInMemory(t *testing.T) {
	f := newFixture(choose(PromptAllowSession), nil)
	f.deps.Cache = NewTurnCache()

	d := authorizeHost(t, f, "web_search", "docs.example.com")

	want := PermissionEntry{Kind: subjectKindTool, Subject: "web_search", HostScope: "docs.example.com", GrantKind: grantKindSession}
	if d.Outcome != outcomeSessionGrant || d.Grant == nil || *d.Grant != want {
		t.Fatalf("decision = %+v, want an in-memory exact-host session grant %+v", d, want)
	}
	if len(f.cap.persists) != 0 {
		t.Fatalf("an allow-for-session host grant reached the persistence seam: %v", f.cap.persists)
	}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended grants = %v, want exactly %+v", f.cap.appends, want)
	}
	for _, other := range []MatchRequest{hostReq("web_search", "api.example.com"), hostReq("web_fetch", "docs.example.com")} {
		if Match(other, f.grants.entries).Matched {
			t.Fatalf("the session host grant matched %+v", other)
		}
	}
}

func TestAuthorizeHostAllowProjectHandsOffOneExactHostGrant(t *testing.T) {
	f := newFixture(choose(PromptAllowProject), nil)
	f.deps.Cache = NewTurnCache()

	d := authorizeHost(t, f, "web_fetch", "docs.example.com")

	want := PermissionEntry{Kind: subjectKindTool, Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: grantKindProject}
	if d.Outcome != grantOutcome(grantKindProject) || d.Grant == nil || *d.Grant != want {
		t.Fatalf("decision = %+v, want an exact-host project grant %+v", d, want)
	}
	if len(f.cap.persists) != 1 || f.cap.persists[0] != want {
		t.Fatalf("persisted grants = %v, want exactly %+v", f.cap.persists, want)
	}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended grants = %v, want exactly %+v", f.cap.appends, want)
	}
	if ev := lastEvent(t, f); ev.grantKind != grantKindProject || ev.grantPathScope != "docs.example.com" {
		t.Fatalf("decision event = %+v, want a project grant scoped to the canonical host", ev)
	}
}

func freshHostReq(subject, host string) MatchRequest {
	req := hostReq(subject, host)
	req.FreshConfirmation = true
	return req
}

func authorizeFreshHost(f *orchFixture, subject, host string) (Decision, error) {
	return Authorize(context.Background(), freshHostReq(subject, host), hostModeCtx(subject), f.deps)
}

func TestAuthorizeFreshHostPromptsPastGrantsAndCache(t *testing.T) {
	sessionHostGrant := PermissionEntry{Kind: subjectKindTool, Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: grantKindSession}
	cached := func(outcome string) func(*orchFixture) {
		return func(f *orchFixture) {
			f.cache.hits[turnCacheKeyOf(hostReq("web_fetch", "docs.example.com"))] = outcome
		}
	}
	resolvers := []struct {
		name  string
		setup func(*orchFixture)
	}{
		{"project grant", func(f *orchFixture) {
			f.grants.entries = []PermissionEntry{hostGrant("web_fetch", "docs.example.com")}
		}},
		{"session grant", func(f *orchFixture) {
			f.grants.entries = []PermissionEntry{sessionHostGrant}
		}},
		{"cached once", cached(outcomeOnce)},
		{"cached deny", cached(outcomeDeny)},
		{"cached project grant", cached(grantOutcome(grantKindProject))},
	}
	for _, tc := range resolvers {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(PromptAllowOnce), nil)
			tc.setup(f)

			d, err := authorizeFreshHost(f, "web_fetch", "docs.example.com")
			if err != nil {
				t.Fatalf("Authorize returned error: %v", err)
			}
			if d.Outcome != outcomeOnce || d.Grant != nil {
				t.Fatalf("fresh decision = %+v, want a grantless %q", d, outcomeOnce)
			}
			if f.cap.prompts != 1 {
				t.Fatalf("prompt called %d times, want 1: a %s must not suppress a fresh confirmation", f.cap.prompts, tc.name)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 || len(f.cap.persists) != 0 {
				t.Fatalf("a fresh confirmation stored something: records=%v appends=%v persists=%v",
					f.cap.records, f.cap.appends, f.cap.persists)
			}
		})
	}
}

func TestAuthorizeFreshHostOutcomeIsNeverCached(t *testing.T) {
	cases := []struct {
		name   string
		choice PromptChoice
		want   string
	}{
		{"once", PromptAllowOnce, outcomeOnce},
		{"deny", PromptDeny, outcomeDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(tc.choice), nil)
			f.deps.Cache = NewTurnCache()

			for i := 1; i <= 2; i++ {
				d, err := authorizeFreshHost(f, "web_fetch", "docs.example.com")
				if err != nil {
					t.Fatalf("Authorize returned error: %v", err)
				}
				if d.Outcome != tc.want {
					t.Fatalf("fresh decision %d = %+v, want %q", i, d, tc.want)
				}
				if f.cap.prompts != i {
					t.Fatalf("prompt called %d times over %d fresh confirmations, want %d", f.cap.prompts, i, i)
				}
			}

			if d := authorizeHost(t, f, "web_fetch", "docs.example.com"); d.Outcome != tc.want {
				t.Fatalf("ordinary decision = %+v, want %q", d, tc.want)
			}
			if f.cap.prompts != 3 {
				t.Fatalf("prompt called %d times, want 3: a fresh confirmation must leave no cache entry behind", f.cap.prompts)
			}
			if len(f.cap.appends) != 0 || len(f.cap.persists) != 0 {
				t.Fatalf("fresh confirmations created grants: appends=%v persists=%v", f.cap.appends, f.cap.persists)
			}
		})
	}
}

func TestAuthorizeFreshHostRejectsGrantCreatingChoices(t *testing.T) {
	cases := []struct {
		name   string
		choice PromptChoice
	}{
		{"session", PromptAllowSession},
		{"folder", PromptAllowFolder},
		{"global", PromptAllowGlobal},
		{"project", PromptAllowProject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(tc.choice), nil)

			if _, err := authorizeFreshHost(f, "web_fetch", "docs.example.com"); err == nil {
				t.Fatal("Authorize accepted a grant-creating choice for a fresh confirmation")
			}
			if len(f.cap.appends) != 0 || len(f.cap.persists) != 0 || len(f.cap.records) != 0 {
				t.Fatalf("a rejected fresh confirmation stored something: appends=%v persists=%v records=%v",
					f.cap.appends, f.cap.persists, f.cap.records)
			}
		})
	}
}

func TestAuthorizeRejectsFreshConfirmationOnNonHostRequests(t *testing.T) {
	toolFresh := toolReq()
	toolFresh.FreshConfirmation = true
	cases := []struct {
		name string
		req  MatchRequest
	}{
		{"tool", toolFresh},
		{"direct", MatchRequest{Kind: subjectKindDirect, Subject: "git status", SubjectTokens: []string{"git", "status"}, PathScope: scopeProj, FreshConfirmation: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			f.grants.entries = []PermissionEntry{toolGrant("vcs_commit", scopeProj, grantKindFolder)}

			if _, err := Authorize(context.Background(), tc.req, ModeContext{}, f.deps); err == nil {
				t.Fatal("Authorize accepted a fresh confirmation on a non-host request")
			}
			if f.cap.prompts != 0 || len(f.cap.events) != 0 || len(f.cap.records) != 0 {
				t.Fatalf("a rejected non-host marker still authorized: prompts=%d events=%v records=%v",
					f.cap.prompts, f.cap.events, f.cap.records)
			}
		})
	}
}

func TestAuthorizeRejectsCrossedGrantLifetimes(t *testing.T) {
	cases := []struct {
		name   string
		choice PromptChoice
		req    MatchRequest
		mc     ModeContext
	}{
		{"host/folder", PromptAllowFolder, hostReq("web_fetch", "docs.example.com"), hostModeCtx("web_fetch")},
		{"host/global", PromptAllowGlobal, hostReq("web_fetch", "docs.example.com"), hostModeCtx("web_fetch")},
		{"path/project", PromptAllowProject, toolReq(), ModeContext{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(tc.choice), nil)

			if _, err := Authorize(context.Background(), tc.req, tc.mc, f.deps); err == nil {
				t.Fatal("Authorize accepted a grant lifetime the request cannot carry")
			}
			if len(f.cap.appends) != 0 || len(f.cap.persists) != 0 {
				t.Fatalf("rejected outcome still created grants: appends=%v persists=%v", f.cap.appends, f.cap.persists)
			}
		})
	}
}

func TestAuthorizeHostBypassesModeAutoDecisions(t *testing.T) {
	for _, m := range []string{"build", modeAutoEdits, modePlan} {
		for _, class := range []OperationClass{ClassReadOnly, ClassMutating} {
			t.Run(m+"/"+string(class), func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				f.deps.Cache = NewTurnCache()
				mc := ModeContext{Mode: m, Class: class, ToolName: "web_fetch"}

				d := mustAuthorizeMode(t, hostReq("web_fetch", "docs.example.com"), mc, f.deps)

				if f.cap.prompts != 1 {
					t.Fatalf("prompt called %d times in %s, want 1 (a host request must reach the prompt)", f.cap.prompts, m)
				}
				for _, ev := range f.cap.events {
					if ev.outcomeSource == outcomeSourceModeAuto {
						t.Fatalf("host request produced a mode_auto event in %s: %+v", m, ev)
					}
				}
				if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
					t.Fatalf("decision = %+v in %s, want a prompt-sourced once with no deny envelope", d, m)
				}
			})
		}
	}
}

func TestAuthorizeHostGrantWinsOverModePosture(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{hostGrant("web_fetch", "docs.example.com")}
	mc := ModeContext{Mode: modePlan, Class: ClassMutating, ToolName: "web_fetch"}

	d := mustAuthorizeMode(t, hostReq("web_fetch", "docs.example.com"), mc, f.deps)

	if d.Outcome != grantOutcome(grantKindProject) || d.Grant == nil {
		t.Fatalf("decision = %+v, want the existing project host grant to authorize the call", d)
	}
	if ev := lastEvent(t, f); ev.outcomeSource != outcomeSourceGrant {
		t.Fatalf("event = %+v, want a grant-sourced match rather than a mode decision", ev)
	}
}

func TestAuthorizeInProjectReadKeepsModeAutoAllow(t *testing.T) {
	for _, m := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(m, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := ModeContext{Mode: m, Class: ClassReadOnly, ToolName: "read"}

			d := mustAuthorizeMode(t, toolReq(), mc, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("in-project read prompted %d times in %s, want 0 (mode auto-allow)", f.cap.prompts, m)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			if ev := f.cap.events[0]; ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
				t.Fatalf("in-project read event = %+v in %s, want mode_auto once", ev, m)
			}
			if d.Outcome != outcomeOnce {
				t.Fatalf("decision = %+v in %s, want once", d, m)
			}
		})
	}
}

func TestAuthorizePlanPostureShadowsMatchingGrant(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{toolGrant("vcs_commit", scopeProj, grantKindFolder)}

	d := mustAuthorizeMode(t, toolReq(), ModeContext{Mode: "plan", Class: ClassMutating}, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeDeny {
		t.Fatalf("shadowed grant must still deny via mode: event = %+v", ev)
	}
	if d.Outcome != outcomeDeny {
		t.Fatalf("decision outcome = %q, want deny (existing grant shadowed by Plan)", d.Outcome)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("shadowing must not record/append: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizePlanPostureShadowsCachedEntry(t *testing.T) {
	for _, cached := range []string{outcomeOnce, outcomeDeny} {
		t.Run(cached, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req := toolReq()
			f.cache.hits[turnCacheKeyOf(req)] = cached

			d := mustAuthorizeMode(t, req, ModeContext{Mode: "plan", Class: ClassMutating}, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			ev := f.cap.events[0]
			if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeDeny {
				t.Fatalf("shadowed cache must still deny via mode: event = %+v, want mode_auto deny", ev)
			}
			if d.Outcome != outcomeDeny {
				t.Fatalf("decision outcome = %q, want deny (cached %q shadowed by Plan)", d.Outcome, cached)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("shadowing must not record/append: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestAuthorizePlanLiteralDenialCarriesArgumentHash(t *testing.T) {
	const literal = `sh -c "echo hi"`
	f := newFixture(neverPrompt, nil)
	req := MatchRequest{Kind: subjectKindLiteral, Subject: literal, PathScope: scopeProj}

	mustAuthorizeMode(t, req, ModeContext{Mode: "plan", Class: ClassMutating}, f.deps)

	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeDeny {
		t.Fatalf("event = %+v, want mode_auto deny", ev)
	}
	if ev.argHash != ComputeArgumentHash(literal) {
		t.Fatalf("argument_hash = %q, want ComputeArgumentHash(%q) = %q", ev.argHash, literal, ComputeArgumentHash(literal))
	}
}

func TestAuthorizeBuildModeStillPrompts(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)

	d := mustAuthorizeMode(t, toolReq(), ModeContext{Mode: "build", Class: ClassMutating}, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if f.cap.prompts != 1 {
		t.Fatalf("Build must prompt, prompted %d times", f.cap.prompts)
	}
	if d.Outcome != outcomeOnce {
		t.Fatalf("decision = %+v, want once from the prompt", d)
	}
}

func TestAuthorizeAutoEditsNonEditToolStillPrompts(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)

	d := mustAuthorizeMode(t, toolReq(), ModeContext{Mode: modeAutoEdits, ToolName: "vcs_commit", Class: ClassMutating}, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if d.Outcome != outcomeOnce {
		t.Fatalf("a mutating non-edit tool in Auto edits must fall through to the prompt (Build-equivalent), got %+v", d)
	}
}

func TestAuthorizeAutoEditsDeleteAlwaysPrompts(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)

	req := MatchRequest{Kind: subjectKindTool, Subject: "delete", PathScope: scopeProj}
	mc := ModeContext{Mode: modeAutoEdits, ToolName: "delete", Class: ClassMutating, TargetPath: scopeProj + "/doomed.txt", ProjectRoot: scopeProj}
	d := mustAuthorizeMode(t, req, mc, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if d.Outcome != outcomeOnce {
		t.Fatalf("an in-project delete in Auto edits must fall through to the prompt (never auto-approved), got %+v", d)
	}
}

func autoEditMode(target string) ModeContext {
	return ModeContext{Mode: modeAutoEdits, ToolName: toolNameEdit, Class: ClassMutating, TargetPath: target, ProjectRoot: scopeProj}
}

func editReq(containingDir string) MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: toolNameEdit, PathScope: containingDir}
}

func autoMkdirMode(target string) ModeContext {
	return ModeContext{Mode: modeAutoEdits, ToolName: toolNameMkdir, Class: ClassMutating, TargetPath: target, ProjectRoot: scopeProj}
}

func mkdirReq(containingDir string) MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: toolNameMkdir, PathScope: containingDir}
}

type autoEditsToolCase struct {
	name    string
	subject string
	mode    func(target string) ModeContext
	req     func(containingDir string) MatchRequest
}

var autoEditsToolCases = []autoEditsToolCase{
	{name: "edit", subject: toolNameEdit, mode: autoEditMode, req: editReq},
	{name: "create", subject: toolNameCreate, mode: autoCreateMode, req: createReq},
	{name: "mkdir", subject: toolNameMkdir, mode: autoMkdirMode, req: mkdirReq},
}

func TestIsAutoEditsTool_CurrentEligibleSet(t *testing.T) {
	for _, name := range []string{toolNameEdit, toolNameCreate, toolNameMkdir, toolNameMove} {
		if !isAutoEditsTool(name) {
			t.Errorf("isAutoEditsTool(%q) = false, want true (current eligible set)", name)
		}
	}
	for _, name := range []string{toolNameDelete, "write_tree", "list", "read", "vcs_commit", "Edit", "CREATE", "Mkdir", "Move", ""} {
		if isAutoEditsTool(name) {
			t.Errorf("isAutoEditsTool(%q) = true, want false (only edit/create/mkdir/move are eligible)", name)
		}
	}
}

func TestIsInScopeFileTool_ResolvedTargetContainment(t *testing.T) {
	tests := []struct {
		name string
		req  MatchRequest
		mc   ModeContext
		want bool
	}{
		{
			name: "edit target inside project",
			req:  editReq(scopeProj),
			mc:   ModeContext{ToolName: toolNameEdit, TargetPath: scopeProj + "/sub/a.txt", ProjectRoot: scopeProj},
			want: true,
		},
		{
			name: "create target equal to root",
			req:  createReq(scopeProj),
			mc:   ModeContext{ToolName: toolNameCreate, TargetPath: scopeProj, ProjectRoot: scopeProj},
			want: true,
		},
		{
			name: "edit target outside project",
			req:  editReq(scopeOther),
			mc:   ModeContext{ToolName: toolNameEdit, TargetPath: scopeOther + "/x.txt", ProjectRoot: scopeProj},
			want: false,
		},
		{
			name: "ineligible tool never in scope",
			req:  MatchRequest{Kind: subjectKindTool, Subject: toolNameDelete, PathScope: scopeProj},
			mc:   ModeContext{ToolName: toolNameDelete, TargetPath: scopeProj + "/a.txt", ProjectRoot: scopeProj},
			want: false,
		},
		{
			name: "move with both endpoints inside project",
			req:  moveReq(),
			mc:   moveAutoMode(scopeProj+"/a.txt", scopeProj+"/sub/b.txt"),
			want: true,
		},
		{
			name: "move source outside project",
			req:  moveReq(),
			mc:   moveAutoMode(scopeOther+"/a.txt", scopeProj+"/b.txt"),
			want: false,
		},
		{
			name: "move destination outside project",
			req:  moveReq(),
			mc:   moveAutoMode(scopeProj+"/a.txt", scopeOther+"/b.txt"),
			want: false,
		},
		{
			name: "move with empty source endpoint",
			req:  moveReq(),
			mc:   moveAutoMode("", scopeProj+"/b.txt"),
			want: false,
		},
		{
			name: "move with empty destination endpoint",
			req:  moveReq(),
			mc:   moveAutoMode(scopeProj+"/a.txt", ""),
			want: false,
		},
		{
			name: "move never keys on the single-target field",
			req:  moveReq(),
			mc:   ModeContext{ToolName: toolNameMove, TargetPath: scopeProj + "/a.txt", ProjectRoot: scopeProj},
			want: false,
		},
		{
			name: "non-tool kind never in scope",
			req:  MatchRequest{Kind: subjectKindDirect, Subject: toolNameEdit, PathScope: scopeProj},
			mc:   ModeContext{ToolName: toolNameEdit, TargetPath: scopeProj + "/a.txt", ProjectRoot: scopeProj},
			want: false,
		},
		{
			name: "empty target path",
			req:  editReq(scopeProj),
			mc:   ModeContext{ToolName: toolNameEdit, TargetPath: "", ProjectRoot: scopeProj},
			want: false,
		},
		{
			name: "empty project root",
			req:  editReq(scopeProj),
			mc:   ModeContext{ToolName: toolNameEdit, TargetPath: scopeProj + "/a.txt", ProjectRoot: ""},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isInScopeFileTool(tc.req, tc.mc); got != tc.want {
				t.Fatalf("isInScopeFileTool(%+v, %+v) = %v, want %v", tc.req, tc.mc, got, tc.want)
			}
		})
	}
}

func TestAuthorizeAutoEditsInScopeAutoAllows(t *testing.T) {
	for _, tc := range autoEditsToolCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			containing := scopeProj + "/sub"
			req := tc.req(containing)
			mc := tc.mode(containing + "/a.txt")

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("an in-scope %s must not prompt, prompted %d times", tc.name, f.cap.prompts)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			ev := f.cap.events[0]
			if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
				t.Fatalf("%s approval event = %+v, want mode_auto once", tc.name, ev)
			}
			if ev.subjectKind != subjectKindTool || ev.subject != tc.subject || ev.pathScope != containing {
				t.Fatalf("%s approval event = %+v, want tool/%q at containing dir %s", tc.name, ev, tc.subject, containing)
			}
			if ev.grantKind != "" || ev.grantPathScope != "" || ev.argHash != "" {
				t.Fatalf("mode_auto %s approval carried grant/hash fields: %+v", tc.name, ev)
			}
			if d.Outcome != outcomeOnce || d.Grant != nil || d.DenyEnvelope != "" {
				t.Fatalf("decision = %+v, want once with no grant/envelope", d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("an in-scope %s must not record to cache or append a grant: records=%v appends=%v", tc.name, f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestAuthorizeAutoEditsShellStillPrompts(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	req := MatchRequest{Kind: subjectKindDirect, Subject: "rm -rf x", SubjectTokens: []string{"rm", "-rf", "x"}, PathScope: scopeProj}
	mc := ModeContext{Mode: modeAutoEdits, Class: ClassMutating, Stages: []StageNormalization{{Route: RouteDirect, Tokens: []string{"rm", "-rf", "x"}}}}

	d := mustAuthorizeMode(t, req, mc, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if f.cap.prompts != 1 {
		t.Fatalf("a raw shell command in Auto edits must prompt, prompted %d times", f.cap.prompts)
	}
	if d.Outcome != outcomeOnce {
		t.Fatalf("decision = %+v, want once from the prompt", d)
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("a prompted shell command must not auto-create a grant: %+v", f.cap.appends)
	}
}

func declaredDirectReq(tokens []string) MatchRequest {
	return MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(tokens, " "), SubjectTokens: tokens, PathScope: scopeProj}
}

func mustDeclaredCommands(t *testing.T, raw ...string) []DeclaredCommand {
	t.Helper()
	items := make([]any, len(raw))
	for i, r := range raw {
		items[i] = r
	}
	entries, notices, err := ParseDeclaredCommands(items)
	if err != nil {
		t.Fatalf("ParseDeclaredCommands(%v) error = %v", raw, err)
	}
	if len(notices) != 0 {
		t.Fatalf("ParseDeclaredCommands(%v) notices = %v, want none", raw, notices)
	}
	return entries
}

func TestAuthorizeAutoDeclaredCommandAllowsWithoutPrompt(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	declared := mustDeclaredCommands(t, "prep-open-tasks.sh --only")
	tokens := []string{"prep-open-tasks.sh", "--only", "i425"}
	req := declaredDirectReq(tokens)
	mc := ModeContext{
		Mode:             modeAutoEdits,
		Class:            ClassMutating,
		Stages:           []StageNormalization{{Route: RouteDirect, Tokens: tokens}},
		DeclaredCommands: declared,
	}

	d := mustAuthorizeMode(t, req, mc, f.deps)

	if f.cap.prompts != 0 {
		t.Fatalf("a declared-list hit must not prompt, prompted %d times", f.cap.prompts)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil || d.DenyEnvelope != "" {
		t.Fatalf("decision = %+v, want once with no grant/envelope", d)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != OutcomeSourceDeclaredCommand || ev.outcome != outcomeOnce {
		t.Fatalf("event = %+v, want declared_command once", ev)
	}
	if ev.subjectKind != subjectKindDirect || ev.subject != "prep-open-tasks.sh --only i425" || ev.pathScope != scopeProj {
		t.Fatalf("event = %+v, want the joined command tokens at the request scope", ev)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" || ev.argHash != "" {
		t.Fatalf("declared_command approval carried grant/hash fields: %+v", ev)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a declared-list hit must not record to cache or append a grant: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizeAutoDeclaredCommandRepeatedArgumentNotCached(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	declared := mustDeclaredCommands(t, "prep-open-tasks.sh --only")
	mc := func(tokens []string) ModeContext {
		return ModeContext{Mode: modeAutoEdits, Class: ClassMutating, Stages: []StageNormalization{{Route: RouteDirect, Tokens: tokens}}, DeclaredCommands: declared}
	}

	first := []string{"prep-open-tasks.sh", "--only", "i425"}
	dA := mustAuthorizeMode(t, declaredDirectReq(first), mc(first), f.deps)
	if dA.Outcome != outcomeOnce {
		t.Fatalf("first decision = %+v, want once", dA)
	}
	if _, hit := f.cache.Lookup(declaredDirectReq(first)); hit {
		t.Fatalf("a declared-list hit must not write a turn-cache entry")
	}

	second := []string{"prep-open-tasks.sh", "--only", "i425", "--force"}
	dB := mustAuthorizeMode(t, declaredDirectReq(second), mc(second), f.deps)
	if dB.Outcome != outcomeOnce {
		t.Fatalf("second decision (a different argument, 13 minutes later in the measured sample) = %+v, want once", dB)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched", "permission_matched"})
	for i, ev := range f.cap.events {
		if ev.outcomeSource != OutcomeSourceDeclaredCommand {
			t.Fatalf("event[%d] = %+v, want a fresh declared_command decision, not a cache hit", i, ev)
		}
	}
}

func TestAuthorizeAutoDeclaredCommandEnvironmentBearingRequestStillPrompts(t *testing.T) {
	cases := []struct {
		name             string
		declaration      string
		tokens           []string
		assignments      []string
		clearEnvironment bool
	}{
		{"leading assignment", "scripts/work.sh", []string{"scripts/work.sh"}, []string{"TERM=xterm"}, false},
		{"assigned PATH", "scripts/work.sh", []string{"scripts/work.sh"}, []string{"PATH=/tmp/probe/bin"}, false},
		{"env -i with its own PATH", "hg status", []string{"hg", "status"}, []string{"PATH=/tmp/probe/bin"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(PromptAllowOnce), nil)
			declared := mustDeclaredCommands(t, tc.declaration)
			subject, err := DirectRequestSubject(tc.tokens, tc.assignments, tc.clearEnvironment)
			if err != nil {
				t.Fatalf("DirectRequestSubject() error = %v", err)
			}
			req := MatchRequest{
				Kind: subjectKindDirect, Subject: subject, SubjectTokens: tc.tokens,
				Assignments: tc.assignments, ClearEnvironment: tc.clearEnvironment, PathScope: scopeProj,
			}
			mc := ModeContext{
				Mode:  modeAutoEdits,
				Class: ClassMutating,
				Stages: []StageNormalization{{
					Route: RouteDirect, Tokens: tc.tokens,
					Assignments: tc.assignments, ClearEnvironment: tc.clearEnvironment,
				}},
				DeclaredCommands: declared,
			}

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if f.cap.prompts != 1 {
				t.Fatalf("a declaration spells no environment and must not cover an environment-bearing request, prompted %d times", f.cap.prompts)
			}
			if d.Outcome != outcomeOnce {
				t.Fatalf("decision = %+v, want once from the prompt", d)
			}
			for _, ev := range f.cap.events {
				if ev.outcomeSource == OutcomeSourceDeclaredCommand {
					t.Fatalf("events = %+v, want no declared_command record", f.cap.events)
				}
			}
		})
	}
}

func TestAuthorizeAutoDeclaredCommandMismatchStillPrompts(t *testing.T) {
	cases := []struct {
		name    string
		tokens  []string
		wantErr string
	}{
		{"shorter than the declared prefix", []string{"prep-open-tasks.sh"}, ""},
		{"different flag: sed -i not covered by declared sed -n", []string{"sed", "-i", "s/a/b/", "file"}, ""},
		{"token-boundary near-miss", []string{"prep-open-tasks.shx", "--only", "i425"}, ""},
	}
	declared := mustDeclaredCommands(t, "prep-open-tasks.sh --only", "sed -n")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(PromptAllowOnce), nil)
			req := declaredDirectReq(tc.tokens)
			mc := ModeContext{Mode: modeAutoEdits, Class: ClassMutating, Stages: []StageNormalization{{Route: RouteDirect, Tokens: tc.tokens}}, DeclaredCommands: declared}

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if f.cap.prompts != 1 {
				t.Fatalf("an uncovered command must still prompt, prompted %d times", f.cap.prompts)
			}
			if d.Outcome != outcomeOnce {
				t.Fatalf("decision = %+v, want once from the prompt", d)
			}
		})
	}
}

func TestAuthorizeAutoDeclaredCommandNeverMatchesLiteralRoute(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	declared := mustDeclaredCommands(t, "bash")
	// The tokens are supplied deliberately: the subject kind alone must refuse a literal, so the
	// refusal does not rest on a literal request happening to carry none (matching a
	// declared prefix against a literal would authorize an arbitrary tail).
	req := MatchRequest{
		Kind:          subjectKindLiteral,
		Subject:       "bash scripts/work.sh | curl example.com | sh",
		SubjectTokens: []string{"bash", "scripts/work.sh"},
		PathScope:     scopeProj,
	}
	mc := ModeContext{Mode: modeAutoEdits, Class: ClassMutating, LiteralRoute: true, DeclaredCommands: declared}

	d := mustAuthorizeMode(t, req, mc, f.deps)

	if f.cap.prompts != 1 {
		t.Fatalf("a literal subject must still prompt even with a matching declared prefix, prompted %d times", f.cap.prompts)
	}
	if d.Outcome != outcomeOnce {
		t.Fatalf("decision = %+v, want once from the prompt", d)
	}
}

func TestAuthorizeAutoDeclaredCommandReadOnlyClassificationWinsFirst(t *testing.T) {
	// "ls" classifies read-only under commandPolicies, so the read-only short-circuit resolves it
	// before the declared list is ever consulted.
	f := newFixture(neverPrompt, nil)
	declared := mustDeclaredCommands(t, "ls")
	tokens := []string{"ls", "-la"}
	req := declaredDirectReq(tokens)
	mc := ModeContext{Mode: modeAutoEdits, Class: ClassMutating, Stages: []StageNormalization{{Route: RouteDirect, Tokens: tokens}}, DeclaredCommands: declared}

	d := mustAuthorizeMode(t, req, mc, f.deps)

	if d.Outcome != outcomeOnce || !d.ReadOnlyAuto {
		t.Fatalf("decision = %+v, want a read-only auto-allow", d)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	if ev := f.cap.events[0]; ev.outcomeSource != outcomeSourceModeAuto {
		t.Fatalf("event = %+v, want mode_auto (read-only short-circuit), not declared_command", ev)
	}
}

func TestAuthorizeBuildAndPlanNeverConsultDeclaredCommands(t *testing.T) {
	declared := mustDeclaredCommands(t, "prep-open-tasks.sh --only")
	tokens := []string{"prep-open-tasks.sh", "--only", "i425"}
	req := declaredDirectReq(tokens)
	stages := []StageNormalization{{Route: RouteDirect, Tokens: tokens}}

	t.Run("build", func(t *testing.T) {
		f := newFixture(choose(PromptAllowOnce), nil)
		mc := ModeContext{Mode: "build", Class: ClassMutating, Stages: stages, DeclaredCommands: declared}
		d := mustAuthorizeMode(t, req, mc, f.deps)
		if f.cap.prompts != 1 {
			t.Fatalf("build mode must not consult the declared list, prompted %d times", f.cap.prompts)
		}
		if d.Outcome != outcomeOnce {
			t.Fatalf("decision = %+v, want once from the prompt", d)
		}
	})

	t.Run("plan", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := ModeContext{Mode: modePlan, Class: ClassMutating, Stages: stages, DeclaredCommands: declared}
		d := mustAuthorizeMode(t, req, mc, f.deps)
		if d.Outcome != outcomeDeny {
			t.Fatalf("decision = %+v, want plan's mutating-command denial, not a declared-list allow", d)
		}
		wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
		if ev := f.cap.events[0]; ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeDeny {
			t.Fatalf("event = %+v, want mode_auto deny", ev)
		}
	})
}

func TestAuthorizeAutoEditsOutOfScopeTargetPrompts(t *testing.T) {
	for _, tc := range autoEditsToolCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(PromptAllowOnce), nil)
			req := tc.req(scopeOther)
			mc := tc.mode(scopeOther + "/x.txt")

			d := mustAuthorizeMode(t, req, mc, f.deps)

			wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
			if f.cap.prompts != 1 {
				t.Fatalf("an out-of-scope %s target in Auto edits must prompt, prompted %d times", tc.name, f.cap.prompts)
			}
			if d.Outcome != outcomeOnce {
				t.Fatalf("decision = %+v, want once from the prompt", d)
			}
			if len(f.cap.appends) != 0 {
				t.Fatalf("a prompted %s must not auto-create a grant: %+v", tc.name, f.cap.appends)
			}
		})
	}
}

func TestAuthorizeAutoEditsRepeatedTargetsNotCached(t *testing.T) {
	for _, tc := range autoEditsToolCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			containing := scopeProj + "/sub"
			req := tc.req(containing)

			dA := mustAuthorizeMode(t, req, tc.mode(containing+"/a.txt"), f.deps)
			if dA.Outcome != outcomeOnce {
				t.Fatalf("first %s decision = %+v, want once", tc.name, dA)
			}
			if len(f.cap.records) != 0 {
				t.Fatalf("mode-auto must not write the turn cache, records=%v", f.cap.records)
			}
			if _, hit := f.cache.Lookup(req); hit {
				t.Fatalf("mode-auto wrote a turn-cache entry for the shared key")
			}

			dB := mustAuthorizeMode(t, req, tc.mode(containing+"/b.txt"), f.deps)
			if dB.Outcome != outcomeOnce {
				t.Fatalf("second %s decision = %+v, want once (independently authorized, not via cache)", tc.name, dB)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched", "permission_matched"})
			for i, ev := range f.cap.events {
				if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
					t.Fatalf("event[%d] = %+v, want mode_auto once (not a cache-sourced match)", i, ev)
				}
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("mode-auto must neither cache nor append: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestAuthorizeAutoEditsShadowsGrantAndCache(t *testing.T) {
	for _, tc := range autoEditsToolCases {
		t.Run(tc.name, func(t *testing.T) {
			containing := scopeProj + "/sub"
			req := tc.req(containing)
			mc := tc.mode(containing + "/a.txt")

			t.Run("matching grant shadowed", func(t *testing.T) {
				f := newFixture(neverPrompt, nil)
				f.grants.entries = []PermissionEntry{toolGrant(tc.subject, containing, grantKindFolder)}

				d := mustAuthorizeMode(t, req, mc, f.deps)

				wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
				ev := f.cap.events[0]
				if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
					t.Fatalf("a matching grant must be shadowed by the mode-auto approval: event = %+v", ev)
				}
				if d.Outcome != outcomeOnce || d.Grant != nil {
					t.Fatalf("decision = %+v, want once with no grant (existing grant shadowed)", d)
				}
				if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
					t.Fatalf("shadowing must not record/append: records=%v appends=%v", f.cap.records, f.cap.appends)
				}
			})

			t.Run("cached entry shadowed", func(t *testing.T) {
				f := newFixture(neverPrompt, nil)
				f.cache.hits[turnCacheKeyOf(req)] = outcomeFolderGrant

				d := mustAuthorizeMode(t, req, mc, f.deps)

				wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
				ev := f.cap.events[0]
				if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
					t.Fatalf("a cached entry must be shadowed by the mode-auto approval: event = %+v", ev)
				}
				if d.Outcome != outcomeOnce {
					t.Fatalf("decision = %+v, want once (cached entry shadowed)", d)
				}
				if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
					t.Fatalf("shadowing must not record/append: records=%v appends=%v", f.cap.records, f.cap.appends)
				}
			})
		})
	}
}

func TestAuthorizeModeSwitchDoesNotAlterPriorGrantsOrRecords(t *testing.T) {
	f := newFixture(choose(PromptAllowSession), nil)
	req := toolReq()
	buildMode := ModeContext{Mode: "build", Class: ClassMutating, ToolName: "vcs_commit"}

	dGrant := mustAuthorizeMode(t, req, buildMode, f.deps)
	if dGrant.Outcome != outcomeSessionGrant {
		t.Fatalf("Build grant decision = %+v, want session_grant", dGrant)
	}
	grantsAfterBuild := append([]PermissionEntry(nil), f.grants.entries...)
	eventsAfterBuild := append([]orchEmitted(nil), f.cap.events...)
	if len(grantsAfterBuild) != 1 {
		t.Fatalf("permissions table after Build grant = %+v, want exactly one entry", grantsAfterBuild)
	}

	f.deps.Prompt = neverPrompt
	dPlan := mustAuthorizeMode(t, req, ModeContext{Mode: "plan", Class: ClassMutating, ToolName: "vcs_commit"}, f.deps)
	if dPlan.Outcome != outcomeDeny {
		t.Fatalf("Plan decision = %+v, want deny (the existing grant is shadowed by Plan, req 150)", dPlan)
	}
	if len(f.grants.entries) != len(grantsAfterBuild) {
		t.Fatalf("permissions table size changed across the mode switch: got %+v, want %+v", f.grants.entries, grantsAfterBuild)
	}
	for i := range grantsAfterBuild {
		if f.grants.entries[i] != grantsAfterBuild[i] {
			t.Fatalf("prior grant[%d] was altered by the mode switch: got %+v, want %+v", i, f.grants.entries[i], grantsAfterBuild[i])
		}
	}
	if len(f.cap.events) <= len(eventsAfterBuild) {
		t.Fatalf("Plan deny appended no event (events did not grow past %d)", len(eventsAfterBuild))
	}
	for i := range eventsAfterBuild {
		if !reflect.DeepEqual(f.cap.events[i], eventsAfterBuild[i]) {
			t.Fatalf("already-emitted event[%d] was rewritten by the mode switch: got %+v, want %+v", i, f.cap.events[i], eventsAfterBuild[i])
		}
	}

	dReturn := mustAuthorizeMode(t, req, buildMode, f.deps)
	if dReturn.Outcome != outcomeSessionGrant || dReturn.Grant == nil {
		t.Fatalf("post-switch Build decision = %+v, want the surviving session grant to authorize without a prompt", dReturn)
	}
	last := f.cap.events[len(f.cap.events)-1]
	if last.kind != "permission_matched" || last.outcomeSource != outcomeSourceGrant {
		t.Fatalf("post-switch match event = %+v, want a grant-sourced permission_matched", last)
	}
}

func TestAuthorizeBuildEditGrantAuthorizesDifferentTargetUnderScope(t *testing.T) {
	f := newFixture(choose(PromptAllowSession), nil)
	firstReq := editReq(scopeProj)
	firstMode := ModeContext{Mode: "build", ToolName: toolNameEdit, Class: ClassMutating, TargetPath: scopeProj + "/a.txt", ProjectRoot: scopeProj}

	dFirst := mustAuthorizeMode(t, firstReq, firstMode, f.deps)
	if dFirst.Outcome != outcomeSessionGrant || dFirst.Grant == nil {
		t.Fatalf("first edit decision = %+v, want a session grant on the edit tool", dFirst)
	}
	if f.cap.prompts != 1 {
		t.Fatalf("first edit prompted %d times, want 1 (no grant existed yet)", f.cap.prompts)
	}
	granted := *dFirst.Grant
	if granted.Kind != subjectKindTool || granted.Subject != toolNameEdit || granted.PathScope != scopeProj || granted.GrantKind != grantKindSession {
		t.Fatalf("appended grant = %+v, want a session tool grant on %q at %s", granted, toolNameEdit, scopeProj)
	}

	f.deps.Prompt = neverPrompt
	subDir := scopeProj + "/sub"
	secondReq := editReq(subDir)
	secondMode := ModeContext{Mode: "build", ToolName: toolNameEdit, Class: ClassMutating, TargetPath: subDir + "/b.txt", ProjectRoot: scopeProj}

	dSecond := mustAuthorizeMode(t, secondReq, secondMode, f.deps)
	if dSecond.Outcome != outcomeSessionGrant || dSecond.Grant == nil {
		t.Fatalf("second edit decision = %+v, want the existing session grant to authorize the different target", dSecond)
	}
	if f.cap.prompts != 1 {
		t.Fatalf("second edit prompted again (total prompts = %d, want 1); one edit grant must cover any target under its scope", f.cap.prompts)
	}
	last := f.cap.events[len(f.cap.events)-1]
	if last.kind != "permission_matched" || last.outcomeSource != outcomeSourceGrant || last.grantPathScope != scopeProj {
		t.Fatalf("second edit event = %+v, want a grant-sourced permission_matched at scope %s", last, scopeProj)
	}
	if got := len(f.cap.appends); got != 1 {
		t.Fatalf("grant appends = %d, want 1 (the second edit matches the existing grant, creating none)", got)
	}
}

func autoCreateMode(target string) ModeContext {
	return ModeContext{Mode: modeAutoEdits, ToolName: toolNameCreate, Class: ClassMutating, TargetPath: target, ProjectRoot: scopeProj}
}

func createReq(containingDir string) MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: toolNameCreate, PathScope: containingDir}
}

func moveAutoMode(source, destination string) ModeContext {
	return ModeContext{Mode: modeAutoEdits, ToolName: toolNameMove, Class: ClassMutating,
		MoveSource: source, MoveDestination: destination, ProjectRoot: scopeProj}
}

func assertNoModeAuto(t *testing.T, f *orchFixture) {
	t.Helper()
	for _, ev := range f.cap.events {
		if ev.outcomeSource == outcomeSourceModeAuto {
			t.Fatalf("move produced a mode_auto event: %+v (Auto edits must not auto-approve this move)", ev)
		}
	}
}

func TestAuthorizeAutoEditsMoveInProjectAutoAllows(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	containing := scopeProj + "/sub"
	req := MatchRequest{Kind: subjectKindTool, Subject: toolNameMove, PathScope: containing}

	mc := moveAutoMode(containing+"/src.txt", containing+"/dest.txt")
	d := mustAuthorizeMode(t, req, mc, f.deps)

	if f.cap.prompts != 0 {
		t.Fatalf("an all-in-project move must not prompt, prompted %d times", f.cap.prompts)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
		t.Fatalf("move approval event = %+v, want mode_auto once", ev)
	}
	if ev.subjectKind != subjectKindTool || ev.subject != toolNameMove || ev.pathScope != containing {
		t.Fatalf("move approval event = %+v, want tool/%q at %s", ev, toolNameMove, containing)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("mode_auto move event carried grant fields: %+v", ev)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil {
		t.Fatalf("decision = %+v, want once with no grant", d)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a mode-auto move must neither cache nor append: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
	if _, hit := f.cache.Lookup(req); hit {
		t.Fatalf("a mode-auto move wrote a turn-cache entry")
	}
}

func TestAuthorizeAutoEditsMoveOutOfRootStillPrompts(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		destination string
	}{
		{name: "source outside project", source: scopeOther + "/src.txt", destination: scopeProj + "/dest.txt"},
		{name: "destination outside project", source: scopeProj + "/src.txt", destination: scopeOther + "/dest.txt"},
		{name: "both endpoints outside project", source: scopeOther + "/src.txt", destination: scopeOther + "/dest.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(PromptAllowOnce), nil)

			d := mustAuthorizeMode(t, moveReq(), moveAutoMode(tc.source, tc.destination), f.deps)

			wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
			if f.cap.prompts != 1 {
				t.Fatalf("an out-of-root move in Auto edits must prompt, prompted %d times", f.cap.prompts)
			}
			assertNoModeAuto(t, f)
			if d.Outcome != outcomeOnce {
				t.Fatalf("decision = %+v, want once from the prompt", d)
			}
		})
	}
}

func TestAuthorizeAutoEditsMoveDeniedOutOfRootReturnsDenyEnvelope(t *testing.T) {
	f := newFixture(choose(PromptDeny), nil)

	d := mustAuthorizeMode(t, moveReq(), moveAutoMode(scopeProj+"/src.txt", scopeOther+"/dest.txt"), f.deps)

	assertNoModeAuto(t, f)
	if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
		t.Fatalf("decision = %+v, want a deny with an envelope so the move never executes", d)
	}
}

func TestAuthorizeAutoEditsMoveResolvesGrantAndCacheNotModeAuto(t *testing.T) {
	containing := scopeProj + "/sub"
	req := MatchRequest{Kind: subjectKindTool, Subject: toolNameMove, PathScope: containing}
	mc := moveAutoMode(containing+"/src.txt", scopeOther+"/dest.txt")

	t.Run("grant resolves via ordinary match", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		f.grants.entries = []PermissionEntry{toolGrant(toolNameMove, containing, grantKindFolder)}

		d := mustAuthorizeMode(t, req, mc, f.deps)

		wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
		ev := f.cap.events[0]
		if ev.outcomeSource != outcomeSourceGrant {
			t.Fatalf("move grant event = %+v, want a grant-sourced match (not mode_auto)", ev)
		}
		if d.Outcome != outcomeFolderGrant || d.Grant == nil {
			t.Fatalf("decision = %+v, want the existing folder grant to authorize move", d)
		}
		if len(f.cap.appends) != 0 {
			t.Fatalf("a real-grant match must not append: %+v", f.cap.appends)
		}
	})

	t.Run("cache resolves via ordinary hit", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		f.cache.hits[turnCacheKeyOf(req)] = outcomeFolderGrant

		d := mustAuthorizeMode(t, req, mc, f.deps)

		wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
		ev := f.cap.events[0]
		if ev.outcomeSource != outcomeSourceCache {
			t.Fatalf("move cache event = %+v, want a cache-sourced match (not mode_auto)", ev)
		}
		if d.Outcome != outcomeFolderGrant {
			t.Fatalf("decision = %+v, want the cached outcome to resolve move", d)
		}
	})
}

func TestAuthorizeAutoEditsMoveRepeatedTargetsEachPrompt(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	containing := scopeProj + "/sub"
	req := MatchRequest{Kind: subjectKindTool, Subject: toolNameMove, PathScope: containing}

	dA := mustAuthorizeMode(t, req, moveAutoMode(containing+"/a.txt", scopeOther+"/a.txt"), f.deps)
	if dA.Outcome != outcomeOnce {
		t.Fatalf("first move decision = %+v, want once from the prompt", dA)
	}
	if len(f.cap.records) != 0 {
		t.Fatalf("a move allow-once must not be cached, records=%v", f.cap.records)
	}
	if _, hit := f.cache.Lookup(req); hit {
		t.Fatalf("a move wrote a turn-cache entry for the shared key")
	}

	dB := mustAuthorizeMode(t, req, moveAutoMode(containing+"/b.txt", scopeOther+"/b.txt"), f.deps)
	if dB.Outcome != outcomeOnce {
		t.Fatalf("second move decision = %+v, want a fresh prompt (not a cached or auto-approved reuse)", dB)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision", "permission_prompt_shown", "permission_decision"})
	assertNoModeAuto(t, f)
	if f.cap.prompts != 2 {
		t.Fatalf("each distinct move must prompt, prompted %d times, want 2", f.cap.prompts)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("move must neither cache nor append: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func shellReqCtxFor(t *testing.T, mode, input string) (MatchRequest, ModeContext) {
	t.Helper()
	split, err := SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
	}
	mc := ModeContext{Mode: mode, Class: ClassMutating, Stages: split.Stages, LiteralRoute: split.LiteralRoute}
	if split.LiteralRoute {
		return MatchRequest{Kind: subjectKindLiteral, Subject: split.LiteralInput, PathScope: scopeProj}, mc
	}
	first := split.Stages[0]
	return MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(first.Tokens, " "), SubjectTokens: first.Tokens, PathScope: scopeProj}, mc
}

func TestAuthorizePlanAllowsReadOnlyShellWithoutPrompt(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	req, mc := shellReqCtxFor(t, "plan", "rg foo | head")

	d := mustAuthorizeMode(t, req, mc, f.deps)

	if f.cap.prompts != 0 {
		t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
		t.Fatalf("mode allow event = %+v, want mode_auto once", ev)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("mode_auto allow carried grant fields: %+v", ev)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil || d.DenyEnvelope != "" {
		t.Fatalf("decision = %+v, want once with no grant/envelope", d)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a mode decision must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizePlanDeniesMutatingShellWithoutPrompt(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"env assignment on allowlisted exec", `LD_PRELOAD=/x/evil.so ls`},
		{"wrapper route", `sh -c "ls"`},
		{"redirection", `ls > out`},
		{"backgrounding literal route", `ls &`},
		{"non-allowlisted mutating-capable", `find . -delete`},
		{"pipeline with one non-allowlisted stage", `cat a | tee out.txt`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, "plan", tc.input)

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
			}
			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			ev := f.cap.events[0]
			if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeDeny {
				t.Fatalf("mode deny event = %+v, want mode_auto deny", ev)
			}
			if ev.grantKind != "" || ev.grantPathScope != "" {
				t.Fatalf("mode_auto deny carried grant fields: %+v", ev)
			}
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision = %+v, want deny with an envelope", d)
			}
			var env struct {
				DeniedBy string `json:"denied_by"`
			}
			if err := json.Unmarshal([]byte(d.DenyEnvelope), &env); err != nil {
				t.Fatalf("deny envelope is not clean JSON: %v", err)
			}
			if env.DeniedBy != "mode" {
				t.Fatalf("denied_by = %q, want \"mode\" (a policy denial must not look like a user denial)", env.DeniedBy)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a mode decision must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestAuditedReaderHazardousFormsNeverAutoAllow(t *testing.T) {
	for _, input := range []string{
		`rg --pre=$X needle src 2>/dev/null`,
		`rg --pre=sh needle src`,
		`rg --pre sh needle src`,
		`rg --hostname-bin=$X needle src`,
		`rg -nz needle src`,
		`file -C 2>/dev/null`,
		`file -bC`,
		`file -z x.gz`,
		`df --sync`,
		`tail -f a.log`,
		`sort -uo out.txt f`,
	} {
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)

				d := mustAuthorizeMode(t, req, mc, f.deps)

				wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
				if f.cap.prompts != 1 {
					t.Fatalf("%s must prompt in %s, prompted %d times", input, mode, f.cap.prompts)
				}
				if d.Outcome != outcomeOnce {
					t.Fatalf("decision = %+v, want once from the prompt", d)
				}
				if len(f.cap.appends) != 0 {
					t.Fatalf("a prompted command must not auto-create a grant: %+v", f.cap.appends)
				}
			})
		}
		t.Run(modePlan+"/"+input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, input)

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
			}
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision = %+v, want deny with an envelope", d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a mode decision must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestAuditedReaderOrdinaryFormsAutoAllowInEveryMode(t *testing.T) {
	for _, input := range []string{
		`rg needle src`,
		`rg --pre-glob=*.pdf needle src`,
		`rg -n --hidden needle src 2>/dev/null`,
		`file x.md`,
		`file -b x.md`,
		`df -h`,
		`tail -n 20 a.log`,
	} {
		for _, mode := range []string{"build", modeAutoEdits, modePlan} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(neverPrompt, nil)
				req, mc := shellReqCtxFor(t, mode, input)

				d := mustAuthorizeMode(t, req, mc, f.deps)

				assertModeAutoAllow(t, f, d)
			})
		}
	}
}

func readOnlyToolReq() MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: "vcs_status", PathScope: scopeProj}
}

func assertModeAutoAllow(t *testing.T, f *orchFixture, d Decision) {
	t.Helper()
	if f.cap.prompts != 0 {
		t.Fatalf("a read-only request must not prompt, prompted %d times", f.cap.prompts)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeOnce {
		t.Fatalf("mode allow event = %+v, want mode_auto once", ev)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("mode_auto allow carried grant fields: %+v", ev)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil || d.DenyEnvelope != "" {
		t.Fatalf("decision = %+v, want once with no grant/envelope", d)
	}
	if !d.ReadOnlyAuto {
		t.Fatalf("decision = %+v, want the read-only mode-auto source set", d)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a mode decision must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizeReadOnlyAutoAllowsInEveryActiveMode(t *testing.T) {
	for _, mode := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(mode+"/read-only tool", func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := ModeContext{Mode: mode, ToolName: "vcs_status", Class: ClassReadOnly}

			d := mustAuthorizeMode(t, readOnlyToolReq(), mc, f.deps)

			assertModeAutoAllow(t, f, d)
		})
		t.Run(mode+"/read-only shell pipeline", func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, mode, "rg foo | head")

			d := mustAuthorizeMode(t, req, mc, f.deps)

			assertModeAutoAllow(t, f, d)
		})
		t.Run(mode+"/plain echo auto-allows", func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, mode, "echo HOME=$HOME")

			d := mustAuthorizeMode(t, req, mc, f.deps)

			assertModeAutoAllow(t, f, d)
		})
	}
}

func TestAuthorizeBuildMutatingShellPrompts(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	req, mc := shellReqCtxFor(t, "build", "rm -rf x")

	d := mustAuthorizeMode(t, req, mc, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if f.cap.prompts != 1 {
		t.Fatalf("a mutating shell command in Build must prompt, prompted %d times", f.cap.prompts)
	}
	if d.Outcome != outcomeOnce {
		t.Fatalf("decision = %+v, want once from the prompt", d)
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("a prompted shell command must not auto-create a grant: %+v", f.cap.appends)
	}
}

func TestAuthorizeBuildEmptyModeStillFallsThrough(t *testing.T) {
	f := newFixture(choose(PromptAllowOnce), nil)
	req, mc := shellReqCtxFor(t, "", "rg foo | head")

	d := mustAuthorizeMode(t, req, mc, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if f.cap.prompts != 1 {
		t.Fatalf("empty Mode must disable posture and prompt, prompted %d times", f.cap.prompts)
	}
	if d.Outcome != outcomeOnce {
		t.Fatalf("decision = %+v, want once from the prompt (no posture)", d)
	}
}

func TestAuthorizeReadOnlyAutoAllowShadowsGrantAndCacheInBuild(t *testing.T) {
	req := readOnlyToolReq()
	mc := ModeContext{Mode: "build", ToolName: "vcs_status", Class: ClassReadOnly}

	t.Run("matching grant shadowed", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		f.grants.entries = []PermissionEntry{toolGrant("vcs_status", scopeProj, grantKindFolder)}

		d := mustAuthorizeMode(t, req, mc, f.deps)

		assertModeAutoAllow(t, f, d)
	})

	t.Run("cached entry shadowed", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		f.cache.hits[turnCacheKeyOf(req)] = outcomeFolderGrant

		d := mustAuthorizeMode(t, req, mc, f.deps)

		assertModeAutoAllow(t, f, d)
	})
}

func TestAuthorizeFindReadOnlyAutoAllowsInEveryActiveMode(t *testing.T) {
	for _, mode := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, mode, "find . -type f -name '*.go' | grep foo | head")

			d := mustAuthorizeMode(t, req, mc, f.deps)

			assertModeAutoAllow(t, f, d)
		})
	}
}

func TestAuthorizeFindMutatingShellPromptsOrDenies(t *testing.T) {
	inputs := []string{
		"find . -delete",
		"find . -exec rm {} +",
		"find . -maxdepth x",
		"find /tmp -type f",
		"find .. -type f",
		"FOO=bar find . -type f",
		"find . -type f > out",
		"find . -type f && ls",
	}
	for _, input := range inputs {
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)

				d := mustAuthorizeMode(t, req, mc, f.deps)

				wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
				if f.cap.prompts != 1 {
					t.Fatalf("mutating find in %s must prompt, prompted %d times", mode, f.cap.prompts)
				}
				if d.Outcome != outcomeOnce {
					t.Fatalf("decision = %+v, want once from the prompt", d)
				}
				if len(f.cap.appends) != 0 {
					t.Fatalf("a prompted find command must not auto-create a grant: %+v", f.cap.appends)
				}
			})
		}
		t.Run("plan/"+input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, "plan", input)

			d := mustAuthorizeMode(t, req, mc, f.deps)

			if f.cap.prompts != 0 {
				t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
			}
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision = %+v, want deny with an envelope", d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a mode decision must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func newStore() *sessions.Store {
	return sessions.New("/unused/session.json", &sessions.Session{
		Metadata: sessions.Metadata{ID: ids.NewV7(), Folder: scopeProj, SchemaVersion: sessions.CurrentSchemaVersion},
	})
}

func storeEventKinds(t *testing.T, store *sessions.Store) []string {
	t.Helper()
	var ks []string
	for _, r := range store.Records() {
		ev, ok := r.(sessions.Event)
		if !ok {
			t.Fatalf("record %T is not a sessions.Event", r)
		}
		ks = append(ks, ev.Kind)
	}
	return ks
}

func batchReq(subject string) BatchRequest {
	return BatchRequest{Req: MatchRequest{Kind: subjectKindTool, Subject: subject, PathScope: scopeProj}}
}

func directBatchReq(tokens ...string) BatchRequest {
	return BatchRequest{Req: MatchRequest{
		Kind:          subjectKindDirect,
		Subject:       strings.Join(tokens, " "),
		SubjectTokens: tokens,
		PathScope:     scopeProj,
	}}
}

func chooseBatch(calls *int, c PromptChoice) func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
	return func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
		*calls++
		return PromptOutcome{Choice: c}, nil
	}
}

func neverBatchPrompt(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
	return PromptOutcome{}, errors.New("batch prompt must not be called")
}

func TestResolveWithoutPrompt_ParityWithAuthorize(t *testing.T) {
	tests := []struct {
		name    string
		modeCtx ModeContext
		setup   func(f *orchFixture)
	}{
		{
			name: "grant match",
			setup: func(f *orchFixture) {
				f.grants.entries = []PermissionEntry{toolGrant("vcs_commit", scopeProj, grantKindFolder)}
			},
		},
		{
			name:  "cache hit",
			setup: func(f *orchFixture) { f.cache.hits[turnCacheKeyOf(toolReq())] = outcomeOnce },
		},
		{
			name:    "mode auto-allow read-only",
			modeCtx: ModeContext{Mode: modePlan, Class: ClassReadOnly},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			single := newFixture(neverPrompt, nil)
			if tc.setup != nil {
				tc.setup(single)
			}
			wantDec := mustAuthorizeMode(t, toolReq(), tc.modeCtx, single.deps)

			factored := newFixture(neverPrompt, nil)
			if tc.setup != nil {
				tc.setup(factored)
			}
			gotDec, resolved, err := resolveWithoutPrompt(toolReq(), tc.modeCtx, factored.deps)
			if err != nil {
				t.Fatalf("resolveWithoutPrompt error: %v", err)
			}
			if !resolved {
				t.Fatalf("resolveWithoutPrompt reported needs-prompt for a request the single path settles without one")
			}
			if gotDec.Outcome != wantDec.Outcome || gotDec.DenyEnvelope != wantDec.DenyEnvelope {
				t.Fatalf("decision = %+v, want %+v", gotDec, wantDec)
			}
			if (gotDec.Grant == nil) != (wantDec.Grant == nil) {
				t.Fatalf("grant presence mismatch: got %+v, want %+v", gotDec.Grant, wantDec.Grant)
			}
			if gotDec.Grant != nil && *gotDec.Grant != *wantDec.Grant {
				t.Fatalf("grant = %+v, want %+v", *gotDec.Grant, *wantDec.Grant)
			}
			if !reflect.DeepEqual(factored.cap.events, single.cap.events) {
				t.Fatalf("events diverged:\n factored=%+v\n single  =%+v", factored.cap.events, single.cap.events)
			}
			if factored.cap.prompts != 0 {
				t.Fatalf("resolve-without-prompt must not prompt, prompted %d times", factored.cap.prompts)
			}
		})
	}
}

func TestAuthorizeBatch_NoPromptWhenAllResolved(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = neverBatchPrompt
	f.grants.entries = []PermissionEntry{toolGrant("granted", scopeProj, grantKindFolder)}
	f.cache.hits[turnCacheKeyOf(MatchRequest{Kind: subjectKindTool, Subject: "cached", PathScope: scopeProj})] = outcomeOnce

	decs, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("granted"), batchReq("cached")}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if len(decs) != 2 {
		t.Fatalf("decisions = %d, want 2", len(decs))
	}
	if decs[0].Outcome != outcomeFolderGrant || decs[1].Outcome != outcomeOnce {
		t.Fatalf("decisions = %+v, want folder_grant then once", decs)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched", "permission_matched"})
}

func TestAuthorizeBatch_OnePromptForUnresolved(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptBatch = chooseBatch(&calls, PromptAllowSession)
	f.grants.entries = []PermissionEntry{toolGrant("granted", scopeProj, grantKindFolder)}

	decs, err := AuthorizeBatch(context.Background(), []BatchRequest{
		batchReq("granted"), batchReq("needs_a"), batchReq("needs_b"),
	}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("batched prompt called %d times, want exactly 1", calls)
	}
	if decs[0].Outcome != outcomeFolderGrant {
		t.Fatalf("resolved stage decision = %+v, want the folder grant", decs[0])
	}
	if decs[1].Outcome != outcomeSessionGrant || decs[2].Outcome != outcomeSessionGrant {
		t.Fatalf("unresolved decisions = %+v, want the single batched session outcome applied to both", decs[1:])
	}
	wantKinds(t, f.cap.kinds(), []string{
		"permission_matched",
		"permission_prompt_shown", "permission_prompt_shown",
		"permission_decision", "permission_decision",
	})
}

func TestAuthorizeBatch_PromptCarriesOriginalStageIndex(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	var got []int
	f.deps.PromptBatch = func(_ context.Context, prompts []BatchPromptRequest) (PromptOutcome, error) {
		for _, p := range prompts {
			got = append(got, p.Index)
		}
		return PromptOutcome{Choice: PromptAllowSession}, nil
	}
	f.grants.entries = []PermissionEntry{toolGrant("granted", scopeProj, grantKindFolder)}

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{
		batchReq("needs_a"), batchReq("granted"), batchReq("needs_b"),
	}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if want := []int{0, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prompt indexes = %v, want %v (positions in the input batch, not the compacted prompt slice)", got, want)
	}
}

func TestAuthorizeBatch_PromptErrorPropagates(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	boom := errors.New("batch prompt failed")
	f.deps.PromptBatch = func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
		return PromptOutcome{}, boom
	}

	_, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("s1"), batchReq("s2")}, f.deps)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the batch prompt error propagated", err)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("records = %+v, appends = %+v, want none after a failed prompt", f.cap.records, f.cap.appends)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_prompt_shown"})
}

func TestAuthorizeBatch_NoPromptForEmptyUnresolvedSet(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptBatch = chooseBatch(&calls, PromptDeny)
	f.grants.entries = []PermissionEntry{toolGrant("a", scopeProj, grantKindFolder), toolGrant("b", scopeProj, grantKindSession)}

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("a"), batchReq("b")}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if calls != 0 {
		t.Fatalf("batched prompt called %d times, want 0 (no stage needed a prompt)", calls)
	}
}

func TestAuthorizeBatch_DenyDeniesAll(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptBatch = chooseBatch(&calls, PromptDeny)

	decs, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("s1"), batchReq("s2")}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("batched prompt called %d times, want 1", calls)
	}
	for i, d := range decs {
		if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
			t.Fatalf("decision[%d] = %+v, want deny with an envelope", i, d)
		}
	}
	wantKinds(t, f.cap.kinds(), []string{
		"permission_prompt_shown", "permission_prompt_shown",
		"permission_decision", "permission_decision",
	})
	if e := f.cap.events[2]; e.outcome != decisionDenied || e.subject != "s1" {
		t.Fatalf("decision event = %+v, want denied for s1", e)
	}
	if e := f.cap.events[3]; e.outcome != decisionDenied || e.subject != "s2" {
		t.Fatalf("decision event = %+v, want denied for s2", e)
	}
}

func TestAuthorizeBatch_ResolvedDenyStopsLaterStages(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = neverBatchPrompt
	f.cache.hits[turnCacheKeyOf(MatchRequest{Kind: subjectKindTool, Subject: "denied", PathScope: scopeProj})] = outcomeDeny

	decs, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("denied"), batchReq("needs_prompt")}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if decs[0].Outcome != outcomeDeny || decs[0].DenyEnvelope == "" {
		t.Fatalf("first decision = %+v, want a deny carrying an envelope", decs[0])
	}
	if len(f.cap.appends) != 0 {
		t.Fatalf("appends = %+v, want no grant created for a stage after the denial", f.cap.appends)
	}
	if decs[1].Outcome != "" {
		t.Fatalf("second decision = %+v, want the zero decision (not authorized past the denial)", decs[1])
	}
}

func TestAuthorizeBatch_GrantPerSubject(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptBatch = chooseBatch(&calls, PromptAllowFolder)

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("s1"), batchReq("s2")}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if len(f.cap.appends) != 2 {
		t.Fatalf("appends = %+v, want one grant per subject", f.cap.appends)
	}
	wantEntries := []PermissionEntry{
		{Kind: subjectKindTool, Subject: "s1", PathScope: scopeProj, GrantKind: grantKindFolder},
		{Kind: subjectKindTool, Subject: "s2", PathScope: scopeProj, GrantKind: grantKindFolder},
	}
	if f.cap.appends[0] != wantEntries[0] || f.cap.appends[1] != wantEntries[1] {
		t.Fatalf("appended = %+v, want per-subject grants %+v", f.cap.appends, wantEntries)
	}
	if len(f.cap.records) != 2 || f.cap.records[0].req.Subject != "s1" || f.cap.records[1].req.Subject != "s2" {
		t.Fatalf("cache records = %+v, want one per subject keyed by the concrete subject", f.cap.records)
	}
}

func TestAuthorizeBatch_GrantIgnoresStoredSubjectSharedByTwoStages(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "git"}, nil
	}

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("git status"), batchReq("rm x")}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	wantEntries := []PermissionEntry{
		{Kind: subjectKindTool, Subject: "git status", PathScope: scopeProj, GrantKind: grantKindFolder},
		{Kind: subjectKindTool, Subject: "rm x", PathScope: scopeProj, GrantKind: grantKindFolder},
	}
	if len(f.cap.appends) != 2 || f.cap.appends[0] != wantEntries[0] || f.cap.appends[1] != wantEntries[1] {
		t.Fatalf("appended = %+v, want per-stage concrete subjects %+v (not the shared stored subject)", f.cap.appends, wantEntries)
	}
	if len(f.cap.records) != 2 || f.cap.records[0].req.Subject != "git status" || f.cap.records[1].req.Subject != "rm x" {
		t.Fatalf("cache records = %+v, want one per stage keyed by the concrete subject", f.cap.records)
	}
	wantKinds(t, f.cap.kinds(), []string{
		"permission_prompt_shown", "permission_prompt_shown",
		"permission_decision", "permission_decision",
	})
	if f.cap.events[2].subject != "git status" || f.cap.events[3].subject != "rm x" {
		t.Fatalf("decision events = %+v, want each stage's concrete subject", f.cap.events[2:])
	}
}

func TestAuthorizeBatch_GrantKeepsStoredSubjectOfLoneUnresolvedStage(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "prdtasks create :*"}, nil
	}
	req := directBatchReq("prdtasks", "create", "g", "First task")

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{req}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	want := PermissionEntry{Kind: subjectKindDirect, Subject: "prdtasks create :*", PathScope: scopeProj, GrantKind: grantKindFolder}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended = %+v, want the prompt-selected subject %+v", f.cap.appends, want)
	}
	if len(f.cap.records) != 1 || f.cap.records[0].req.Subject != req.Req.Subject {
		t.Fatalf("cache records = %+v, want one keyed by the concrete subject %q", f.cap.records, req.Req.Subject)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	for _, e := range f.cap.events {
		if e.subject != req.Req.Subject {
			t.Fatalf("event %+v, want the concrete subject %q (the selected scope is only the grant subject)", e, req.Req.Subject)
		}
	}
}

func TestAuthorizeBatch_GrantKeepsStoredSubjectAfterGrantedStage(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{directGrant("hg status", scopeProj, grantKindFolder)}
	f.deps.PromptBatch = func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "prdtasks create :*"}, nil
	}
	granted := directBatchReq("hg", "status")
	prompted := directBatchReq("prdtasks", "create", "g", "First task")

	decs, err := AuthorizeBatch(context.Background(), []BatchRequest{granted, prompted}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if decs[0].Outcome != outcomeFolderGrant || decs[0].Grant == nil || decs[0].Grant.Subject != "hg status" {
		t.Fatalf("granted stage decision = %+v, want its existing folder grant", decs[0])
	}
	want := PermissionEntry{Kind: subjectKindDirect, Subject: "prdtasks create :*", PathScope: scopeProj, GrantKind: grantKindFolder}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended = %+v, want only the prompted stage's selected subject %+v", f.cap.appends, want)
	}
	if len(f.cap.records) != 1 || f.cap.records[0].req.Subject != prompted.Req.Subject {
		t.Fatalf("cache records = %+v, want only the prompted stage keyed by its concrete subject", f.cap.records)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched", "permission_prompt_shown", "permission_decision"})
	if e := f.cap.events[2]; e.subject != prompted.Req.Subject || e.grantKind != grantKindFolder {
		t.Fatalf("decision event = %+v, want the concrete subject %q with a folder grant", e, prompted.Req.Subject)
	}
}

func TestAuthorizeBatch_EmitsValidG300EventsPerSubject(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	store := newStore()
	withRealEmitters(f, store)
	calls := 0
	f.deps.PromptBatch = chooseBatch(&calls, PromptAllowSession)

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("s1"), batchReq("s2")}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch emitted an invalid g300 payload: %v", err)
	}
	wantKinds(t, storeEventKinds(t, store), []string{
		"permission_prompt_shown", "permission_prompt_shown",
		"permission_decision", "permission_decision",
	})
}

func TestAuthorizeBatch_ContextCancelled(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = neverBatchPrompt
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := AuthorizeBatch(ctx, []BatchRequest{batchReq("s1")}, f.deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(f.cap.events) != 0 {
		t.Fatalf("a cancelled context must emit nothing, got %+v", f.cap.events)
	}
}

func TestAuthorizeBatch_RejectsFreshConfirmation(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = neverBatchPrompt
	f.grants.entries = []PermissionEntry{toolGrant("granted", scopeProj, grantKindFolder)}
	fresh := BatchRequest{Req: freshHostReq("web_fetch", "docs.example.com"), ModeCtx: hostModeCtx("web_fetch")}

	decs, err := AuthorizeBatch(context.Background(), []BatchRequest{batchReq("granted"), fresh}, f.deps)
	if err == nil {
		t.Fatalf("AuthorizeBatch accepted a fresh confirmation, decisions = %+v", decs)
	}
	if len(f.cap.events) != 0 || len(f.cap.records) != 0 {
		t.Fatalf("a rejected batch still authorized: events=%v records=%v", f.cap.events, f.cap.records)
	}
}

func TestAuthorize_SingleRequestUnchanged(t *testing.T) {
	f := newFixture(choose(PromptAllowSession), nil)

	d := mustAuthorize(t, toolReq(), f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	if len(f.cap.records) != 1 || f.cap.records[0].outcome != outcomeSessionGrant {
		t.Fatalf("cache records = %+v, want one session_grant record", f.cap.records)
	}
	want := PermissionEntry{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj, GrantKind: grantKindSession}
	if len(f.cap.appends) != 1 || f.cap.appends[0] != want {
		t.Fatalf("appended = %+v, want one %+v", f.cap.appends, want)
	}
	if d.Outcome != outcomeSessionGrant || d.Grant == nil || *d.Grant != want {
		t.Fatalf("decision = %+v, want session_grant carrying the entry", d)
	}
}

func TestPromptFlow_CarriesSubjectTokensUnchanged(t *testing.T) {
	tokens := []string{"git", "commit", "-m", "First task"}
	f := newFixture(choose(PromptAllowOnce), nil)
	req := MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(tokens, " "), SubjectTokens: tokens, PathScope: scopeProj}

	mustAuthorize(t, req, f.deps)

	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
	got := f.cap.events[0]
	if !reflect.DeepEqual(got.directTokens, tokens) {
		t.Fatalf("emitted direct tokens = %q, want %q", got.directTokens, tokens)
	}
	if got.subject != "git commit -m First task" {
		t.Fatalf("emitted subject = %q, want the flattened form", got.subject)
	}
	if len(strings.Fields(got.subject)) == len(got.directTokens) {
		t.Fatal("test premise broken: the flattened subject is not lossy for this request")
	}
}

func TestPromptFlow_PassesNoTokensForOtherKinds(t *testing.T) {
	tests := []struct {
		name string
		req  MatchRequest
	}{
		{"literal", MatchRequest{Kind: subjectKindLiteral, Subject: "cat foo | wc -l", PathScope: scopeProj}},
		{"tool", toolReq()},
		{"host", hostReq("web_fetch", "docs.example.com")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(choose(PromptAllowOnce), nil)
			mustAuthorize(t, tc.req, f.deps)
			if got := f.cap.events[0]; got.directTokens != nil {
				t.Fatalf("%s request emitted direct tokens %q, want none", tc.name, got.directTokens)
			}
		})
	}
}

func TestPromptFlow_EmitterErrorStopsBeforePrompt(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	boom := errors.New("emit failed")
	f.deps.EmitPromptShown = func(string, string, string, []string, DirectIdentity) error { return boom }
	req := MatchRequest{Kind: subjectKindDirect, Subject: "git status", SubjectTokens: []string{"git", "status"}, PathScope: scopeProj}

	if _, err := Authorize(context.Background(), req, ModeContext{}, f.deps); !errors.Is(err, boom) {
		t.Fatalf("Authorize error = %v, want %v", err, boom)
	}
	if f.cap.prompts != 0 {
		t.Fatalf("prompt called %d times after an emitter error, want 0", f.cap.prompts)
	}
	if len(f.cap.events) != 0 || len(f.cap.appends) != 0 || len(f.cap.records) != 0 {
		t.Fatalf("emitter error still produced state: events=%v appends=%v records=%v", f.cap.events, f.cap.appends, f.cap.records)
	}
}

func TestAuthorizeBatch_CarriesEachStagesSubjectTokens(t *testing.T) {
	calls := 0
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = chooseBatch(&calls, PromptAllowOnce)
	stages := [][]string{
		{"git", "commit", "-m", "First task"},
		{"grep", "-r", "TODO note", "src"},
	}

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{
		directBatchReq(stages[0]...), directBatchReq(stages[1]...),
	}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}

	var prompts []orchEmitted
	for _, e := range f.cap.events {
		if e.kind == "permission_prompt_shown" {
			prompts = append(prompts, e)
		}
	}
	if len(prompts) != len(stages) {
		t.Fatalf("emitted %d prompt events, want %d", len(prompts), len(stages))
	}
	for i, want := range stages {
		if !reflect.DeepEqual(prompts[i].directTokens, want) {
			t.Errorf("prompt[%d] direct tokens = %q, want %q", i, prompts[i].directTokens, want)
		}
	}
}

func TestAuthorizeBatch_EmitterErrorStopsBeforeSharedPrompt(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptBatch = neverBatchPrompt
	boom := errors.New("emit failed")
	f.deps.EmitPromptShown = func(string, string, string, []string, DirectIdentity) error { return boom }

	_, err := AuthorizeBatch(context.Background(), []BatchRequest{
		directBatchReq("git", "status"), directBatchReq("ls", "-l"),
	}, f.deps)
	if !errors.Is(err, boom) {
		t.Fatalf("AuthorizeBatch error = %v, want %v", err, boom)
	}
	if len(f.cap.persists) != 0 || len(f.cap.appends) != 0 || len(f.cap.records) != 0 {
		t.Fatalf("emitter error still produced state: persists=%v appends=%v records=%v", f.cap.persists, f.cap.appends, f.cap.records)
	}
}

// --- declared write scopes ---

const (
	declTargetA = scopeProj + "/a.txt"
	declTargetB = scopeProj + "/b.txt"
)

func declSet(paths ...string) map[string]bool {
	m := make(map[string]bool, len(paths))
	for _, p := range paths {
		m[p] = true
	}
	return m
}

func declMode(tool, target string, write, remove map[string]bool) ModeContext {
	return ModeContext{
		Class:          ClassMutating,
		ToolName:       tool,
		TargetPath:     target,
		ProjectRoot:    scopeProj,
		DeclaredWrite:  write,
		DeclaredDelete: remove,
	}
}

func declReq(tool string) MatchRequest {
	return MatchRequest{Kind: subjectKindTool, Subject: tool, PathScope: scopeProj}
}

func assertDeclaredEvent(t *testing.T, f *orchFixture, outcome string) orchEmitted {
	t.Helper()
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != OutcomeSourceDeclaredScope || ev.outcome != outcome {
		t.Fatalf("declared-scope event = %+v, want %s/%s", ev, OutcomeSourceDeclaredScope, outcome)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("declared-scope event carried grant fields: %+v", ev)
	}
	if len(f.cap.records) != 0 {
		t.Fatalf("cache records = %+v, want none (a declared decision is per call)", f.cap.records)
	}
	if len(f.cap.appends) != 0 || len(f.cap.persists) != 0 {
		t.Fatalf("appends = %+v persists = %+v, want none (a declared decision creates no grant)", f.cap.appends, f.cap.persists)
	}
	if f.cap.prompts != 0 {
		t.Fatalf("prompts = %d, want 0 (a declared decision never reaches the prompt)", f.cap.prompts)
	}
	return ev
}

// TestAuthorizeDeclaredScope_MembershipDecidesWriteTools proves the write list authorizes exactly
// the paths it names for edit and create, and denies every other target terminally.
func TestAuthorizeDeclaredScope_MembershipDecidesWriteTools(t *testing.T) {
	for _, tool := range []string{toolNameEdit, toolNameCreate} {
		t.Run(tool+" covered", func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(tool), declMode(tool, declTargetA, declSet(declTargetA), nil), f.deps)
			if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
				t.Fatalf("decision = %+v, want a per-call allow", d)
			}
			assertDeclaredEvent(t, f, outcomeOnce)
		})
		t.Run(tool+" uncovered", func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(tool), declMode(tool, declTargetB, declSet(declTargetA), nil), f.deps)
			if d.Outcome != outcomeDeny {
				t.Fatalf("decision = %+v, want a denial", d)
			}
			if d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("DenialSource = %q, want %q", d.DenialSource, OutcomeSourceDeclaredScope)
			}
			if IsModeDenyEnvelope(d.DenyEnvelope) {
				t.Fatalf("deny envelope = %s, want denied_by user so the summary keeps it", d.DenyEnvelope)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}
}

// TestAuthorizeDeclaredScope_ListsAreIndependent proves membership in one list implies nothing
// about the other, in both directions.
func TestAuthorizeDeclaredScope_ListsAreIndependent(t *testing.T) {
	tests := []struct {
		name           string
		tool           string
		write, deletes map[string]bool
		wantOutcome    string
	}{
		{"delete denied by a write-only declaration", toolNameDelete, declSet(declTargetA), nil, outcomeDeny},
		{"delete allowed once the delete list names it", toolNameDelete, declSet(declTargetA), declSet(declTargetA), outcomeOnce},
		{"edit denied by a delete-only declaration", toolNameEdit, nil, declSet(declTargetA), outcomeDeny},
		{"create denied by a delete-only declaration", toolNameCreate, nil, declSet(declTargetA), outcomeDeny},
		{"delete allowed by a delete-only declaration", toolNameDelete, nil, declSet(declTargetA), outcomeOnce},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(tc.tool), declMode(tc.tool, declTargetA, tc.write, tc.deletes), f.deps)
			if d.Outcome != tc.wantOutcome {
				t.Fatalf("decision = %+v, want outcome %s", d, tc.wantOutcome)
			}
			assertDeclaredEvent(t, f, tc.wantOutcome)
		})
	}
}

// TestAuthorizeDeclaredScope_MkdirAndMoveAreNeverAuthorized proves neither list can authorize a
// mkdir or a move, even with every relevant path declared in both lists.
func TestAuthorizeDeclaredScope_MkdirAndMoveAreNeverAuthorized(t *testing.T) {
	both := declSet(declTargetA, declTargetB)

	t.Run("mkdir", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		d := mustAuthorizeMode(t, declReq(toolNameMkdir), declMode(toolNameMkdir, declTargetA, both, both), f.deps)
		if d.Outcome != outcomeDeny {
			t.Fatalf("decision = %+v, want a denial", d)
		}
		assertDeclaredEvent(t, f, outcomeDeny)
	})

	t.Run("move", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := declMode(toolNameMove, "", both, both)
		mc.MoveSource, mc.MoveDestination = declTargetA, declTargetB
		d := mustAuthorizeMode(t, declReq(toolNameMove), mc, f.deps)
		if d.Outcome != outcomeDeny {
			t.Fatalf("decision = %+v, want a denial", d)
		}
		assertDeclaredEvent(t, f, outcomeDeny)
	})
}

// TestAuthorizeDeclaredScope_NoRouteBypassesTheCeiling proves the ceiling resolves ahead of every
// other authorization route: a matching grant, a turn-cache entry, and Auto edits' project-root
// rule each fail to authorize an undeclared write.
func TestAuthorizeDeclaredScope_NoRouteBypassesTheCeiling(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		setup func(f *orchFixture, req MatchRequest)
	}{
		{
			name: "a matching folder grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameEdit, scopeProj, grantKindFolder)}
			},
		},
		{
			name: "a global grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameEdit, allPathsScope, grantKindGlobal)}
			},
		},
		{
			name: "a turn-cache allow",
			setup: func(f *orchFixture, req MatchRequest) {
				f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce
			},
		},
		{
			name: "a turn-cache session grant",
			setup: func(f *orchFixture, req MatchRequest) {
				f.cache.hits[turnCacheKeyOf(req)] = outcomeSessionGrant
			},
		},
		{
			name:  "Auto edits' project-root rule",
			mode:  modeAutoEdits,
			setup: func(*orchFixture, MatchRequest) {},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req := declReq(toolNameEdit)
			tc.setup(f, req)
			mc := declMode(toolNameEdit, declTargetB, declSet(declTargetA), nil)
			mc.Mode = tc.mode

			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial that %s cannot widen", d, tc.name)
			}
			assertDeclaredEvent(t, f, outcomeDeny)

			// The declared path still authorizes, so the ceiling narrows rather than blocks.
			f2 := newFixture(neverPrompt, nil)
			tc.setup(f2, req)
			mc.TargetPath = declTargetA
			if d := mustAuthorizeMode(t, req, mc, f2.deps); d.Outcome != outcomeOnce {
				t.Fatalf("declared target decision = %+v, want a per-call allow", d)
			}
			assertDeclaredEvent(t, f2, outcomeOnce)
		})
	}
}

// TestAuthorizeDeclaredScope_PostureIsModeIndependent proves the ceiling decides identically with
// no mode and in Build — the mode a production headless run actually reaches modePosture with.
func TestAuthorizeDeclaredScope_PostureIsModeIndependent(t *testing.T) {
	for _, m := range []string{"", "build"} {
		t.Run("mode="+m, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := declMode(toolNameEdit, declTargetB, declSet(declTargetA), nil)
			mc.Mode = m

			d := mustAuthorizeMode(t, declReq(toolNameEdit), mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision with mode %q = %+v, want a declared-scope denial", m, d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}
}

// TestAuthorizeDeclaredScope_PlanRemainsTheSoleAuthority proves the ceiling is skipped in Plan, so
// a write declared in both lists is still denied there with Plan's own envelope and record.
func TestAuthorizeDeclaredScope_PlanRemainsTheSoleAuthority(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	both := declSet(declTargetA)
	mc := declMode(toolNameEdit, declTargetA, both, both)
	mc.Mode = modePlan

	d := mustAuthorizeMode(t, declReq(toolNameEdit), mc, f.deps)
	if d.Outcome != outcomeDeny {
		t.Fatalf("decision = %+v, want Plan's denial", d)
	}
	if !IsModeDenyEnvelope(d.DenyEnvelope) {
		t.Fatalf("deny envelope = %s, want Plan's denied_by mode envelope", d.DenyEnvelope)
	}
	if d.DenialSource != outcomeSourceModeAuto {
		t.Fatalf("DenialSource = %q, want %q", d.DenialSource, outcomeSourceModeAuto)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	if ev := f.cap.events[0]; ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != outcomeDeny {
		t.Fatalf("Plan event = %+v, want mode_auto deny", ev)
	}
}

// TestAuthorizeDeclaredScope_LeavesOtherSubjectsAlone proves an active ceiling changes nothing for
// reads, shell, and network: a grant still authorizes a shell command in the same run.
func TestAuthorizeDeclaredScope_LeavesOtherSubjectsAlone(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{directGrant("git status", scopeProj, grantKindFolder)}
	req, mc := shellReqCtxFor(t, "", "git status")
	mc.DeclaredWrite = declSet(declTargetA)
	mc.DeclaredDelete = declSet(declTargetA)

	d := mustAuthorizeMode(t, req, mc, f.deps)
	if d.Outcome != outcomeFolderGrant {
		t.Fatalf("decision = %+v, want the shell grant to still authorize under an active ceiling", d)
	}
	if ev := lastEvent(t, f); ev.outcomeSource != outcomeSourceGrant {
		t.Fatalf("event = %+v, want a grant match", ev)
	}
}

// TestAuthorizeDeclaredScope_InactiveCeilingChangesNothing proves an empty pair of lists is not a
// ceiling: authorization falls through to the ordinary routes exactly as before.
func TestAuthorizeDeclaredScope_InactiveCeilingChangesNothing(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{toolGrant(toolNameEdit, scopeProj, grantKindFolder)}

	d := mustAuthorizeMode(t, declReq(toolNameEdit), declMode(toolNameEdit, declTargetA, nil, nil), f.deps)
	if d.Outcome != outcomeFolderGrant {
		t.Fatalf("decision = %+v, want the ordinary grant match with no ceiling active", d)
	}
	if ev := lastEvent(t, f); ev.outcomeSource != outcomeSourceGrant {
		t.Fatalf("event = %+v, want a grant match", ev)
	}
}

// TestDeclaredScopeDenyReason_FixedFactsPrecedeTheEscapedTarget proves the declared-scope deny reason ordering:
// every classification fact appears, in order, ahead of the escaped canonical target.
func TestDeclaredScopeDenyReason_FixedFactsPrecedeTheEscapedTarget(t *testing.T) {
	tests := []struct {
		name     string
		mc       ModeContext
		wantSeq  []string
		wantLast string
	}{
		{
			name: "write list absent",
			mc:   declMode(toolNameEdit, declTargetA, nil, declSet(declTargetA)),
			wantSeq: []string{
				"a declared-scope ceiling is active",
				declaredWriteFlag + " was not supplied",
				"the ceiling cannot widen during the run",
			},
			wantLast: "target=" + strconv.Quote(declTargetA),
		},
		{
			name: "write list present but missing the target",
			mc:   declMode(toolNameEdit, declTargetB, declSet(declTargetA), nil),
			wantSeq: []string{
				"a declared-scope ceiling is active",
				declaredWriteFlag + " was supplied but does not list this target",
				"the ceiling cannot widen during the run",
			},
			wantLast: "target=" + strconv.Quote(declTargetB),
		},
		{
			name: "delete list absent",
			mc:   declMode(toolNameDelete, declTargetA, declSet(declTargetA), nil),
			wantSeq: []string{
				declaredDeleteFlag + " was not supplied",
				"the ceiling cannot widen during the run",
			},
			wantLast: "target=" + strconv.Quote(declTargetA),
		},
		{
			name: "delete list present but missing the target",
			mc:   declMode(toolNameDelete, declTargetB, nil, declSet(declTargetA)),
			wantSeq: []string{
				declaredDeleteFlag + " was supplied but does not list this target",
				"the ceiling cannot widen during the run",
			},
			wantLast: "target=" + strconv.Quote(declTargetB),
		},
		{
			name: "mkdir names both flags as unable to authorize it",
			mc:   declMode(toolNameMkdir, declTargetA, declSet(declTargetA), nil),
			wantSeq: []string{
				"neither " + declaredWriteFlag + " nor " + declaredDeleteFlag + " can authorize " + toolNameMkdir,
				"the ceiling cannot widen during the run",
			},
			wantLast: "target=" + strconv.Quote(declTargetA),
		},
		{
			name: "both flags supplied are both named",
			mc:   declMode(toolNameEdit, declTargetB, declSet(declTargetA), declSet(declTargetA)),
			wantSeq: []string{
				declaredWriteFlag + " was supplied but does not list this target",
				"this run was started with " + declaredWriteFlag + " and " + declaredDeleteFlag,
				"the ceiling cannot widen during the run",
			},
			wantLast: "target=" + strconv.Quote(declTargetB),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := declaredScopeDenyReason(tc.mc)
			at := -1
			for _, want := range tc.wantSeq {
				idx := strings.Index(got, want)
				if idx <= at {
					t.Fatalf("reason %q is missing %q or has it out of order", got, want)
				}
				at = idx
			}
			if !strings.HasSuffix(got, tc.wantLast) {
				t.Fatalf("reason %q does not end with the escaped target %q", got, tc.wantLast)
			}
		})
	}
}

// TestDeclaredScopeDenyReason_MoveEndsWithSourceThenDestination proves a move denial ends with the
// exact source-then-destination form rather than an empty single target.
func TestDeclaredScopeDenyReason_MoveEndsWithSourceThenDestination(t *testing.T) {
	mc := declMode(toolNameMove, "", declSet(declTargetA), declSet(declTargetA))
	mc.MoveSource, mc.MoveDestination = declTargetA, declTargetB

	got := declaredScopeDenyReason(mc)
	want := "source=" + strconv.Quote(declTargetA) + "; destination=" + strconv.Quote(declTargetB)
	if !strings.HasSuffix(got, want) {
		t.Fatalf("move reason %q does not end with %q", got, want)
	}
	if strings.Contains(got, "target=") {
		t.Fatalf("move reason %q used the single-target form", got)
	}
}

// TestDeclaredScopeDenyReason_EscapesControlCharacters proves a legal filename carrying control
// characters cannot forge extra lines in the one-line stderr notice.
func TestDeclaredScopeDenyReason_EscapesControlCharacters(t *testing.T) {
	forged := scopeProj + "/a\nfake: authorized\t.txt"
	got := declaredScopeDenyReason(declMode(toolNameEdit, forged, declSet(declTargetA), nil))
	if strings.ContainsAny(got, "\n\t") {
		t.Fatalf("reason %q carries a raw control character", got)
	}
	if !strings.HasSuffix(got, "target="+strconv.Quote(forged)) {
		t.Fatalf("reason %q does not end with the escaped target", got)
	}
}

// TestDeclaredScopeDenyReason_TruncationCostsOnlyPathDetail proves an overlength target — and an
// overlength move endpoint pair — is cut by the envelope's 512-byte cap without losing any
// classification fact.
func TestDeclaredScopeDenyReason_TruncationCostsOnlyPathDetail(t *testing.T) {
	long := scopeProj + "/" + strings.Repeat("p", 900) + ".txt"

	t.Run("single target", func(t *testing.T) {
		mc := declMode(toolNameEdit, long, declSet(declTargetA), declSet(declTargetA))
		capped := envelopeReason(t, BuildDenyEnvelope(declaredScopeDenyReason(mc)))
		for _, want := range []string{
			"a declared-scope ceiling is active",
			declaredWriteFlag + " was supplied but does not list this target",
			"this run was started with " + declaredWriteFlag + " and " + declaredDeleteFlag,
			"the ceiling cannot widen during the run",
			"target=",
		} {
			if !strings.Contains(capped, want) {
				t.Fatalf("capped reason %q lost %q", capped, want)
			}
		}
		if len(capped) > maxDenyReasonBytes {
			t.Fatalf("capped reason is %d bytes, want at most %d", len(capped), maxDenyReasonBytes)
		}
	})

	t.Run("move endpoints", func(t *testing.T) {
		mc := declMode(toolNameMove, "", declSet(declTargetA), declSet(declTargetA))
		mc.MoveSource, mc.MoveDestination = long, long
		capped := envelopeReason(t, BuildDenyEnvelope(declaredScopeDenyReason(mc)))
		for _, want := range []string{
			"a declared-scope ceiling is active",
			"neither " + declaredWriteFlag + " nor " + declaredDeleteFlag + " can authorize " + toolNameMove,
			"the ceiling cannot widen during the run",
			"source=",
		} {
			if !strings.Contains(capped, want) {
				t.Fatalf("capped move reason %q lost %q", capped, want)
			}
		}
		if strings.Index(capped, "source=") > strings.Index(capped, "destination=") && strings.Contains(capped, "destination=") {
			t.Fatalf("capped move reason %q reversed the endpoint order", capped)
		}
	})

	t.Run("both endpoints fit", func(t *testing.T) {
		mc := declMode(toolNameMove, "", declSet(declTargetA), nil)
		mc.MoveSource, mc.MoveDestination = declTargetA, declTargetB
		capped := envelopeReason(t, BuildDenyEnvelope(declaredScopeDenyReason(mc)))
		want := "source=" + strconv.Quote(declTargetA) + "; destination=" + strconv.Quote(declTargetB)
		if !strings.HasSuffix(capped, want) {
			t.Fatalf("capped move reason %q does not end with %q", capped, want)
		}
	})
}

func envelopeReason(t *testing.T, envelope string) string {
	t.Helper()
	var e struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(envelope), &e); err != nil {
		t.Fatalf("unmarshal deny envelope %q: %v", envelope, err)
	}
	return e.Reason
}

func childMode(tool, target string, write map[string]bool) ModeContext {
	mc := declMode(tool, target, write, nil)
	mc.ChildAgent = true
	return mc
}

func nestedDelegateMode(parent, nested map[string]bool) ModeContext {
	mc := childMode(toolNameDelegate, "", parent)
	mc.DelegateWrite = nested
	return mc
}

func childDeleteMode(target string, write, remove map[string]bool) ModeContext {
	mc := childMode(toolNameDelete, target, write)
	mc.DeclaredDelete = remove
	return mc
}

func nestedScopesMode(parentWrite, parentDelete, nestedWrite, nestedDelete map[string]bool) ModeContext {
	mc := nestedDelegateMode(parentWrite, nestedWrite)
	mc.DeclaredDelete = parentDelete
	mc.DelegateDelete = nestedDelete
	return mc
}

func TestAuthorizeChildScope_WriteAndDeleteDeclarationsAreAsymmetric(t *testing.T) {
	tests := []struct {
		name          string
		tool          string
		write, remove map[string]bool
		wantAllow     bool
	}{
		{"a delete-declared target deletes", toolNameDelete, nil, declSet(declTargetA), true},
		{"a write-declared target is not deletable", toolNameDelete, declSet(declTargetA), nil, false},
		{"a delete-declared target is not editable", toolNameEdit, nil, declSet(declTargetA), false},
		{"a delete-declared target is not creatable", toolNameCreate, nil, declSet(declTargetA), false},
		{"a target in both lists edits", toolNameEdit, declSet(declTargetA), declSet(declTargetA), true},
		{"a target in both lists creates", toolNameCreate, declSet(declTargetA), declSet(declTargetA), true},
		{"a target in both lists deletes", toolNameDelete, declSet(declTargetA), declSet(declTargetA), true},
		{"a delete declaration authorizes no mkdir", toolNameMkdir, nil, declSet(declTargetA), false},
		{"a delete declaration authorizes no move", toolNameMove, nil, declSet(declTargetA), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := declMode(tc.tool, declTargetA, tc.write, tc.remove)
			mc.ChildAgent = true

			d := mustAuthorizeMode(t, declReq(tc.tool), mc, f.deps)
			if tc.wantAllow {
				if d.Outcome != outcomeOnce {
					t.Fatalf("decision = %+v, want the declaration's allow", d)
				}
				assertDeclaredEvent(t, f, outcomeOnce)
				return
			}
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}
}

func TestAuthorizeChildScope_NestedDelegateChecksEachFormAgainstItsImmediateParent(t *testing.T) {
	declTargetC := scopeProj + "/c.txt"
	tests := []struct {
		name                      string
		parentWrite, parentDelete map[string]bool
		nestedWrite, nestedDelete map[string]bool
		wantAllow                 bool
	}{
		{"a delete-only subset", declSet(declTargetA), declSet(declTargetB), nil, declSet(declTargetB), true},
		{"write and delete subsets together", declSet(declTargetA), declSet(declTargetB), declSet(declTargetA), declSet(declTargetB), true},
		{"a delete path outside the parent's delete list", declSet(declTargetA), declSet(declTargetB), declSet(declTargetA), declSet(declTargetC), false},
		{"a parent write path admits no nested delete of it", declSet(declTargetA), nil, nil, declSet(declTargetA), false},
		{"a parent delete path admits no nested write of it", nil, declSet(declTargetA), declSet(declTargetA), nil, false},
		{"an omitted nested delete list fits an absent parent list", declSet(declTargetA), nil, declSet(declTargetA), nil, true},
		{"a supplied empty nested delete list fits an absent parent list", declSet(declTargetA), nil, declSet(declTargetA), declSet(), true},
		{"a declaration that did not resolve", declSet(declTargetA), declSet(declTargetB), nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := nestedScopesMode(tc.parentWrite, tc.parentDelete, tc.nestedWrite, tc.nestedDelete)

			d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
			want := outcomeDeny
			if tc.wantAllow {
				want = outcomeOnce
			}
			if d.Outcome != want {
				t.Fatalf("decision = %+v, want %s", d, want)
			}
			assertDeclaredEvent(t, f, want)
		})
	}
}

func TestAuthorizeChildScope_NoRouteBypassesTheChildCeiling(t *testing.T) {
	baseline := newFixture(neverPrompt, nil)
	want := mustAuthorizeMode(t, declReq(toolNameEdit), childMode(toolNameEdit, declTargetB, declSet(declTargetA)), baseline.deps)
	if want.Outcome != outcomeDeny || want.DenyEnvelope == "" {
		t.Fatalf("baseline decision = %+v, want a child declared-scope denial", want)
	}

	tests := []struct {
		name  string
		mode  string
		setup func(f *orchFixture, req MatchRequest)
	}{
		{
			name: "a matching folder grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameEdit, scopeProj, grantKindFolder)}
			},
		},
		{
			name: "a global grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameEdit, allPathsScope, grantKindGlobal)}
			},
		},
		{
			name:  "Auto edits' project-root rule",
			mode:  modeAutoEdits,
			setup: func(*orchFixture, MatchRequest) {},
		},
		{
			name: "a repeat within the child's own turn",
			setup: func(f *orchFixture, req MatchRequest) {
				f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req := declReq(toolNameEdit)
			tc.setup(f, req)
			mc := childMode(toolNameEdit, declTargetB, declSet(declTargetA))
			mc.Mode = tc.mode

			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a child declared-scope denial that %s cannot widen", d, tc.name)
			}
			if d.DenyEnvelope != want.DenyEnvelope {
				t.Fatalf("deny envelope = %s, want the same refusal as with no covering route: %s", d.DenyEnvelope, want.DenyEnvelope)
			}
			assertDeclaredEvent(t, f, outcomeDeny)

			f2 := newFixture(neverPrompt, nil)
			tc.setup(f2, req)
			mc.TargetPath = declTargetA
			if d := mustAuthorizeMode(t, req, mc, f2.deps); d.Outcome != outcomeOnce {
				t.Fatalf("declared target decision = %+v, want a per-call allow", d)
			}
			assertDeclaredEvent(t, f2, outcomeOnce)
		})
	}
}

func TestAuthorizeChildScope_MkdirMoveAndDeleteNameTheMissingChildForm(t *testing.T) {
	tests := []struct {
		tool string
		form string
	}{
		{toolNameDelete, "this delegate call did not supply files_delete"},
		{toolNameMkdir, "this delegate call did not supply files_mkdir"},
		{toolNameMove, "this delegate call did not supply files_move"},
	}
	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := childMode(tc.tool, declTargetA, declSet(declTargetA))
			if tc.tool == toolNameMove {
				mc.TargetPath = ""
				mc.MoveSource, mc.MoveDestination = declTargetA, declTargetB
			}

			d := mustAuthorizeMode(t, declReq(tc.tool), mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a child declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)

			reason := envelopeReason(t, d.DenyEnvelope)
			if !strings.Contains(reason, tc.form) {
				t.Fatalf("reason %q does not name the missing child form %q", reason, tc.form)
			}
			for _, forbidden := range []string{declaredWriteFlag, "not available", "unavailable", "forbidden"} {
				if strings.Contains(reason, forbidden) {
					t.Fatalf("reason %q contains %q; a child refusal names only the missing declaration form", reason, forbidden)
				}
			}
		})
	}
}

func TestAuthorizeChildScope_AnEmptyDeclarationDeniesRatherThanFallingThrough(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.grants.entries = []PermissionEntry{toolGrant(toolNameEdit, allPathsScope, grantKindGlobal)}

	d := mustAuthorizeMode(t, declReq(toolNameEdit), childMode(toolNameEdit, declTargetA, nil), f.deps)
	if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
		t.Fatalf("decision = %+v, want a child declared-scope denial rather than the global grant", d)
	}
	assertDeclaredEvent(t, f, outcomeDeny)
}

func TestAuthorizeChildScope_NestedDelegateNeedsASubsetOfItsParent(t *testing.T) {
	parent := declSet(declTargetA, declTargetB)
	tests := []struct {
		name        string
		nested      map[string]bool
		wantOutcome string
	}{
		{"the parent's whole set", parent, outcomeOnce},
		{"a proper subset", declSet(declTargetA), outcomeOnce},
		{"one path outside the parent", declSet(declTargetA, scopeProj+"/c.txt"), outcomeDeny},
		{"a declaration the child could not resolve", nil, outcomeDeny},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(toolNameDelegate), nestedDelegateMode(parent, tc.nested), f.deps)
			if d.Outcome != tc.wantOutcome {
				t.Fatalf("decision = %+v, want outcome %s", d, tc.wantOutcome)
			}
			assertDeclaredEvent(t, f, tc.wantOutcome)
		})
	}
}

func TestAuthorizeChildScope_NoRouteAuthorizesAChildDelegateCall(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		setup func(f *orchFixture, req MatchRequest)
	}{
		{
			name: "a matching folder grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameDelegate, scopeProj, grantKindFolder)}
			},
		},
		{
			name: "a global grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameDelegate, allPathsScope, grantKindGlobal)}
			},
		},
		{
			name: "a turn-cache allow",
			setup: func(f *orchFixture, req MatchRequest) {
				f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce
			},
		},
		{
			name:  "Auto edits",
			mode:  modeAutoEdits,
			setup: func(*orchFixture, MatchRequest) {},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req := declReq(toolNameDelegate)
			tc.setup(f, req)
			mc := nestedDelegateMode(declSet(declTargetA), declSet(declTargetB))
			mc.Mode = tc.mode

			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial that %s cannot widen", d, tc.name)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}
}

func TestAuthorizeChildScope_RefusalKeepsTheDeclaredScopeAuditEncoding(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	d := mustAuthorizeMode(t, declReq(toolNameEdit), childMode(toolNameEdit, declTargetB, declSet(declTargetA)), f.deps)

	ev := assertDeclaredEvent(t, f, outcomeDeny)
	if ev.outcomeSource != OutcomeSourceDeclaredScope {
		t.Fatalf("outcome_source = %q, want %q", ev.outcomeSource, OutcomeSourceDeclaredScope)
	}
	deniedBy, reason := decodeDenyFields(t, d.DenyEnvelope)
	if deniedBy != "user" {
		t.Fatalf("denied_by = %q, want user", deniedBy)
	}
	if !strings.Contains(reason, "child agent") || !strings.Contains(reason, "declared write paths") {
		t.Fatalf("reason %q does not identify the child's own declaration", reason)
	}

	modeF := newFixture(neverPrompt, nil)
	modeMC := childMode(toolNameEdit, declTargetB, declSet(declTargetA))
	modeMC.Mode = modePlan
	modeD := mustAuthorizeMode(t, declReq(toolNameEdit), modeMC, modeF.deps)
	if !IsModeDenyEnvelope(modeD.DenyEnvelope) || lastEvent(t, modeF).outcomeSource != outcomeSourceModeAuto {
		t.Fatalf("Plan decision = %+v with event %+v, want a mode denial distinct from the child refusal", modeD, lastEvent(t, modeF))
	}

	promptF := newFixture(choose(PromptDeny), nil)
	promptMC := declMode(toolNameEdit, declTargetB, nil, nil)
	promptD := mustAuthorizeMode(t, declReq(toolNameEdit), promptMC, promptF.deps)
	if promptD.DenyEnvelope == d.DenyEnvelope {
		t.Fatalf("a prompt denial produced the child refusal's envelope %s", promptD.DenyEnvelope)
	}
	if lastEvent(t, promptF).outcomeSource == OutcomeSourceDeclaredScope {
		t.Fatalf("a prompt denial emitted the declared-scope source: %+v", lastEvent(t, promptF))
	}
}

func TestChildScopeDenyReason_FixedFactsPrecedeTheEscapedTarget(t *testing.T) {
	const classification = "a child agent may touch only the paths its delegate call declared"
	const unwidenable = "the child declaration cannot widen while the child runs"
	tests := []struct {
		name     string
		mc       ModeContext
		wantSeq  []string
		wantLast string
	}{
		{
			name:     "the write paths do not list the target",
			mc:       childMode(toolNameEdit, declTargetB, declSet(declTargetA)),
			wantSeq:  []string{classification, "the child's declared write paths do not list this target", unwidenable},
			wantLast: "target=" + strconv.Quote(declTargetB),
		},
		{
			name:     "delete with files_delete omitted",
			mc:       childMode(toolNameDelete, declTargetA, declSet(declTargetA)),
			wantSeq:  []string{classification, "this delegate call did not supply files_delete", unwidenable},
			wantLast: "target=" + strconv.Quote(declTargetA),
		},
		{
			name:     "delete with files_delete supplied empty",
			mc:       childDeleteMode(declTargetA, declSet(declTargetA), declSet()),
			wantSeq:  []string{classification, "this delegate call supplied an empty files_delete", unwidenable},
			wantLast: "target=" + strconv.Quote(declTargetA),
		},
		{
			name:     "delete whose files_delete misses the target",
			mc:       childDeleteMode(declTargetA, nil, declSet(declTargetB)),
			wantSeq:  []string{classification, "this delegate call's files_delete does not list this target", unwidenable},
			wantLast: "target=" + strconv.Quote(declTargetA),
		},
		{
			name:     "a nested delegate names delete paths outside its parent",
			mc:       nestedScopesMode(declSet(declTargetA), declSet(declTargetA), declSet(declTargetA), declSet(declTargetA, declTargetB)),
			wantSeq:  []string{classification, "a nested delegate call may declare in files_delete only delete paths its own parent already declared", unwidenable},
			wantLast: "undeclared_delete=" + strconv.Quote(declTargetB),
		},
		{
			name:     "a nested delegate names the paths outside its parent",
			mc:       nestedDelegateMode(declSet(declTargetA), declSet(declTargetA, declTargetB, scopeProj+"/c.txt")),
			wantSeq:  []string{classification, "a nested delegate call may declare only write paths its own parent already declared", unwidenable},
			wantLast: "undeclared=" + strconv.Quote(declTargetB+" "+scopeProj+"/c.txt"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := declaredScopeDenyReason(tc.mc)
			at := -1
			for _, want := range tc.wantSeq {
				idx := strings.Index(got, want)
				if idx <= at {
					t.Fatalf("reason %q is missing %q or has it out of order", got, want)
				}
				at = idx
			}
			if !strings.HasSuffix(got, tc.wantLast) {
				t.Fatalf("reason %q does not end with the escaped target %q", got, tc.wantLast)
			}
		})
	}
}

func TestChildScopeDenyReason_TruncationCostsOnlyPathDetail(t *testing.T) {
	long := scopeProj + "/" + strings.Repeat("p", 900) + ".txt"
	capped := envelopeReason(t, BuildDenyEnvelope(declaredScopeDenyReason(childMode(toolNameEdit, long, declSet(declTargetA)))))
	for _, want := range []string{
		"a child agent may touch only the paths its delegate call declared",
		"the child's declared write paths do not list this target",
		"the child declaration cannot widen while the child runs",
		"target=",
	} {
		if !strings.Contains(capped, want) {
			t.Fatalf("capped reason %q lost %q", capped, want)
		}
	}
	if len(capped) > maxDenyReasonBytes {
		t.Fatalf("capped reason is %d bytes, want at most %d", len(capped), maxDenyReasonBytes)
	}
}

// --- top-level delegate under a codemeld run ceiling ---

func topLevelDelegateMode(write, remove, candidate map[string]bool) ModeContext {
	mc := declMode(toolNameDelegate, "", write, remove)
	mc.DelegateWrite = candidate
	return mc
}

// Being bounded by the run's write declaration is not itself permission to start a child.
func TestAuthorizeDeclaredScope_TopLevelDelegateNeedsASubsetOfTheRunCeiling(t *testing.T) {
	ceiling := declSet(declTargetA, declTargetB)

	t.Run("an uncovered candidate is refused terminally", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := topLevelDelegateMode(ceiling, nil, declSet(declTargetA, scopeProj+"/c.txt"))

		d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
		if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
			t.Fatalf("decision = %+v, want a declared-scope denial", d)
		}
		assertDeclaredEvent(t, f, outcomeDeny)
	})

	t.Run("a covered candidate is left to its operations", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := topLevelDelegateMode(ceiling, nil, declSet(declTargetA))

		d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
		assertLeftToLaunchOperations(t, f, d)
	})
}

func assertLeftToLaunchOperations(t *testing.T, f *orchFixture, d Decision) {
	t.Helper()
	if d.DenyEnvelope != "" || d.Grant != nil {
		t.Fatalf("decision = %+v, want neither a refusal nor a grant", d)
	}
	if f.cap.prompts != 0 {
		t.Fatalf("prompts = %d, want none under the tool name delegate", f.cap.prompts)
	}
	if len(f.cap.events) != 0 {
		t.Fatalf("events = %+v, want no delegate decision recorded", f.cap.events)
	}
}

func TestAuthorizeTopLevelDelegate_NoDelegateApprovalIsConsulted(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		setup func(f *orchFixture, req MatchRequest)
	}{
		{name: "no approval at all", setup: func(*orchFixture, MatchRequest) {}},
		{
			name: "a global delegate grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameDelegate, allPathsScope, grantKindGlobal)}
			},
		},
		{
			name: "a turn-cache deny",
			setup: func(f *orchFixture, req MatchRequest) {
				f.cache.hits[turnCacheKeyOf(req)] = outcomeDeny
			},
		},
		{name: "Auto edits", mode: modeAutoEdits, setup: func(*orchFixture, MatchRequest) {}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req := declReq(toolNameDelegate)
			tc.setup(f, req)
			mc := topLevelDelegateMode(nil, nil, declSet(declTargetA))
			mc.Mode = tc.mode

			d := mustAuthorizeMode(t, req, mc, f.deps)
			assertLeftToLaunchOperations(t, f, d)
		})
	}
}

func TestAuthorizeDeclaredScope_PlanSkipsTheTopLevelDelegateGate(t *testing.T) {
	tests := []struct {
		name      string
		candidate map[string]bool
	}{
		{"covered", declSet(declTargetA)},
		{"uncovered", declSet(scopeProj + "/c.txt")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := topLevelDelegateMode(declSet(declTargetA), nil, tc.candidate)
			mc.Mode = modePlan

			d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
			if !IsModeDenyEnvelope(d.DenyEnvelope) {
				t.Fatalf("decision = %+v, want Plan's mode denial", d)
			}
			if ev := lastEvent(t, f); ev.outcomeSource != outcomeSourceModeAuto {
				t.Fatalf("event = %+v, want outcome_source %s", ev, outcomeSourceModeAuto)
			}
		})
	}
}

func TestAuthorizeDeclaredScope_TopLevelDelegateReadsAnAbsentWriteListAsEmpty(t *testing.T) {
	t.Run("a delete-only ceiling refuses every candidate", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := topLevelDelegateMode(nil, declSet(declTargetA), declSet(declTargetA))

		d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
		if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
			t.Fatalf("decision = %+v, want a declared-scope denial", d)
		}
		assertDeclaredEvent(t, f, outcomeDeny)
		if reason := envelopeReason(t, d.DenyEnvelope); !strings.Contains(reason, declaredWriteFlag+" was not supplied") {
			t.Fatalf("reason %q does not name the absent write list", reason)
		}
	})

	t.Run("neither flag skips the subset check", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := topLevelDelegateMode(nil, nil, declSet(scopeProj+"/c.txt"))

		d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
		assertLeftToLaunchOperations(t, f, d)
	})
}

func TestAuthorizeDeclaredScope_NoRouteAuthorizesAnUncoveredTopLevelDelegate(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		setup func(f *orchFixture, req MatchRequest)
	}{
		{
			name: "a matching folder grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameDelegate, scopeProj, grantKindFolder)}
			},
		},
		{
			name: "a global grant",
			setup: func(f *orchFixture, _ MatchRequest) {
				f.grants.entries = []PermissionEntry{toolGrant(toolNameDelegate, allPathsScope, grantKindGlobal)}
			},
		},
		{
			name: "a turn-cache allow",
			setup: func(f *orchFixture, req MatchRequest) {
				f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce
			},
		},
		{
			name:  "Auto edits",
			mode:  modeAutoEdits,
			setup: func(*orchFixture, MatchRequest) {},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req := declReq(toolNameDelegate)
			tc.setup(f, req)
			mc := topLevelDelegateMode(declSet(declTargetA), nil, declSet(declTargetB))
			mc.Mode = tc.mode

			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial that %s cannot widen", d, tc.name)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}
}

func TestTopLevelDelegateRefusal_KeepsTheDeclaredScopeAuditEncoding(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	mc := topLevelDelegateMode(declSet(declTargetA), nil, declSet(declTargetB))

	d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)

	if ev := assertDeclaredEvent(t, f, outcomeDeny); ev.outcomeSource != OutcomeSourceDeclaredScope {
		t.Fatalf("outcome_source = %q, want %q", ev.outcomeSource, OutcomeSourceDeclaredScope)
	}
	deniedBy, reason := decodeDenyFields(t, d.DenyEnvelope)
	if deniedBy != "user" {
		t.Fatalf("denied_by = %q, want user", deniedBy)
	}
	if !strings.Contains(reason, "undeclared="+strconv.Quote(declTargetB)) {
		t.Fatalf("reason %q does not name the missing child write declaration", reason)
	}
}

func TestTopLevelDelegateDenyReason_FixedFactsPrecedeTheEscapedPaths(t *testing.T) {
	mc := topLevelDelegateMode(declSet(declTargetA), nil, declSet(declTargetA, declTargetB, scopeProj+"/c.txt"))

	got := declaredScopeDenyReason(mc)
	at := -1
	for _, want := range []string{
		"a declared-scope ceiling is active for this run and a child agent may declare only write paths it already lists",
		declaredWriteFlag + " was supplied but does not list every child write path this call declared",
		"the ceiling cannot widen during the run",
	} {
		idx := strings.Index(got, want)
		if idx <= at {
			t.Fatalf("reason %q is missing %q or has it out of order", got, want)
		}
		at = idx
	}
	wantLast := "undeclared=" + strconv.Quote(declTargetB+" "+scopeProj+"/c.txt")
	if !strings.HasSuffix(got, wantLast) {
		t.Fatalf("reason %q does not end with the escaped undeclared paths %q", got, wantLast)
	}
}

func TestTopLevelDelegateDenyReason_TruncationCostsOnlyPathDetail(t *testing.T) {
	long := scopeProj + "/" + strings.Repeat("p", 900) + ".txt"
	mc := topLevelDelegateMode(declSet(declTargetA), nil, declSet(long))

	capped := envelopeReason(t, BuildDenyEnvelope(declaredScopeDenyReason(mc)))
	for _, want := range []string{
		"a declared-scope ceiling is active for this run and a child agent may declare only write paths it already lists",
		declaredWriteFlag + " was supplied but does not list every child write path this call declared",
		"the ceiling cannot widen during the run",
		"undeclared=",
	} {
		if !strings.Contains(capped, want) {
			t.Fatalf("capped reason %q lost %q", capped, want)
		}
	}
	if len(capped) > maxDenyReasonBytes {
		t.Fatalf("capped reason is %d bytes, want at most %d", len(capped), maxDenyReasonBytes)
	}
}

func topLevelScopesMode(write, remove, candidateWrite, candidateDelete map[string]bool) ModeContext {
	mc := topLevelDelegateMode(write, remove, candidateWrite)
	mc.DelegateDelete = candidateDelete
	return mc
}

func TestAuthorizeDeclaredScope_TopLevelDelegateDeleteNeedsASubsetOfTheRunDeleteCeiling(t *testing.T) {
	declTargetC := scopeProj + "/c.txt"
	tests := []struct {
		name                            string
		write, remove                   map[string]bool
		candidateWrite, candidateDelete map[string]bool
		wantDenied                      bool
		wantReason                      string
	}{
		{name: "a delete subset is left to its operations", write: declSet(declTargetA), remove: declSet(declTargetB),
			candidateWrite: declSet(declTargetA), candidateDelete: declSet(declTargetB)},
		{name: "a delete-only subset is left to its operations", write: declSet(declTargetA), remove: declSet(declTargetB),
			candidateDelete: declSet(declTargetB)},
		{name: "a delete outside the run's delete list is refused", write: declSet(declTargetA), remove: declSet(declTargetB),
			candidateWrite: declSet(declTargetA), candidateDelete: declSet(declTargetC), wantDenied: true,
			wantReason: declaredDeleteFlag + " was supplied but does not list every child delete path this call declared"},
		{name: "a delete-only candidate outside the ceiling is refused", write: declSet(declTargetA), remove: declSet(declTargetB),
			candidateDelete: declSet(declTargetC), wantDenied: true},
		{name: "a write-only run ceiling refuses any child delete", write: declSet(declTargetA),
			candidateWrite: declSet(declTargetA), candidateDelete: declSet(declTargetA), wantDenied: true,
			wantReason: declaredDeleteFlag + " was not supplied"},
		{name: "an omitted child delete list fits a write-only ceiling", write: declSet(declTargetA),
			candidateWrite: declSet(declTargetA)},
		{name: "a supplied empty child delete list fits a write-only ceiling", write: declSet(declTargetA),
			candidateWrite: declSet(declTargetA), candidateDelete: declSet()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mc := topLevelScopesMode(tc.write, tc.remove, tc.candidateWrite, tc.candidateDelete)
			if tc.wantDenied {
				f := newFixture(neverPrompt, nil)
				d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
				if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
					t.Fatalf("decision = %+v, want a declared-scope denial", d)
				}
				assertDeclaredEvent(t, f, outcomeDeny)
				if reason := envelopeReason(t, d.DenyEnvelope); !strings.Contains(reason, tc.wantReason) {
					t.Fatalf("reason %q does not contain %q", reason, tc.wantReason)
				}
				return
			}
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
			assertLeftToLaunchOperations(t, f, d)
		})
	}
}

func TestTopLevelDelegateDenyReason_NamesTheDeleteFormWhenOnlyDeletesWiden(t *testing.T) {
	declTargetC := scopeProj + "/c.txt"
	mc := topLevelScopesMode(declSet(declTargetA), declSet(declTargetB), declSet(declTargetA), declSet(declTargetB, declTargetC))

	got := declaredScopeDenyReason(mc)
	at := -1
	for _, want := range []string{
		"a declared-scope ceiling is active for this run and a child agent may declare only delete paths it already lists",
		declaredDeleteFlag + " was supplied but does not list every child delete path this call declared",
		"the ceiling cannot widen during the run",
	} {
		idx := strings.Index(got, want)
		if idx <= at {
			t.Fatalf("reason %q is missing %q or has it out of order", got, want)
		}
		at = idx
	}
	if wantLast := "undeclared_delete=" + strconv.Quote(declTargetC); !strings.HasSuffix(got, wantLast) {
		t.Fatalf("reason %q does not end with the escaped undeclared delete paths %q", got, wantLast)
	}
	if strings.Contains(got, "undeclared=") {
		t.Fatalf("reason %q names an undeclared write path the candidate does not have", got)
	}
}

func TestAwkReadOnlyModeIndependent(t *testing.T) {
	for _, input := range awkAcceptedForms {
		for _, mode := range []string{"build", modeAutoEdits, modePlan} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(neverPrompt, nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				assertModeAutoAllow(t, f, d)
			})
		}
	}
}

func TestAwkRejectedFormsKeepModePosture(t *testing.T) {
	for _, input := range awkRejectedForms {
		t.Run(modePlan+"/"+input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, input)
			d := mustAuthorizeMode(t, req, mc, f.deps)
			if f.cap.prompts != 0 {
				t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
			}
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q = %+v, want deny with an envelope", input, d)
			}
			if d.Grant != nil || len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a mode denial must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
				if f.cap.prompts != 1 {
					t.Fatalf("%q prompted %d times in %s, want 1", input, f.cap.prompts, mode)
				}
				if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
					t.Fatalf("decision for %q in %s = %+v, want a prompt-sourced once", input, mode, d)
				}
				if len(f.cap.appends) != 0 {
					t.Fatalf("a prompted command must not auto-create a grant: %+v", f.cap.appends)
				}
			})
		}
	}
}

func envDirectReq(t *testing.T, assignments []string, tokens ...string) MatchRequest {
	t.Helper()
	subject, err := DirectRequestSubject(tokens, assignments, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject(%v, %v): %v", tokens, assignments, err)
	}
	return MatchRequest{
		Kind: subjectKindDirect, Subject: subject, SubjectTokens: tokens,
		Assignments: assignments, PathScope: scopeProj,
	}
}

// The chooser only ever selects a command-only scope, so buildGrant is what keeps the request's
// assignments in the stored subject.
func TestAuthorize_AssignmentGrantStoresTheChosenScopeWithItsAssignments(t *testing.T) {
	for _, scope := range []string{"hg status", "hg status :*", "hg :*"} {
		t.Run(scope, func(t *testing.T) {
			f := newFixture(func(context.Context, ScopeEscalation) (PromptOutcome, error) {
				return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: scope}, nil
			}, nil)
			req := envDirectReq(t, []string{"FOO=bar"}, "hg", "status")

			mustAuthorize(t, req, f.deps)

			if len(f.cap.appends) != 1 {
				t.Fatalf("appended grants = %d, want 1", len(f.cap.appends))
			}
			entry := f.cap.appends[0]
			decoded, err := decodeDirectEnvSubject(entry.Subject)
			if err != nil {
				t.Fatalf("stored subject %q is not a versioned direct-env subject: %v", entry.Subject, err)
			}
			if decoded.Subject != scope || !slices.Equal(decoded.Assignments, []string{"FOO=bar"}) {
				t.Fatalf("stored payload = %+v, want scope %q with [FOO=bar]", decoded, scope)
			}
			if !Match(req, []PermissionEntry{entry}).Matched {
				t.Fatal("the stored grant does not authorize the request that created it")
			}
			bare := MatchRequest{Kind: subjectKindDirect, Subject: "hg status", SubjectTokens: []string{"hg", "status"}, PathScope: scopeProj}
			if Match(bare, []PermissionEntry{entry}).Matched {
				t.Fatal("the assignment-bearing grant authorized the bare command")
			}
		})
	}
}

// A shared approval across several unresolved stages clears StoredSubject, so buildGrant falls back
// to the request identity, which is already encoded and must not be wrapped a second time.
func TestAuthorizeBatch_ClearedStoredSubjectReusesTheEncodedRequestIdentity(t *testing.T) {
	f := newFixture(nil, nil)
	f.deps.PromptBatch = func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "hg :*"}, nil
	}
	first := envDirectReq(t, []string{"FOO=bar"}, "hg", "status")
	second := envDirectReq(t, []string{"FOO=bar"}, "hg", "log")

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{{Req: first}, {Req: second}}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch: %v", err)
	}

	if len(f.cap.appends) != 2 {
		t.Fatalf("appended grants = %d, want 2", len(f.cap.appends))
	}
	for i, req := range []MatchRequest{first, second} {
		entry := f.cap.appends[i]
		if entry.Subject != req.Subject {
			t.Fatalf("stage %d stored %q, want the request identity %q", i, entry.Subject, req.Subject)
		}
		if !Match(req, []PermissionEntry{entry}).Matched {
			t.Fatalf("stage %d grant does not authorize the request that created it", i)
		}
	}
}

func TestTurnCache_IsolatesAssignmentAndTokenBoundaryVariants(t *testing.T) {
	bare := MatchRequest{Kind: subjectKindDirect, Subject: "hg status", SubjectTokens: []string{"hg", "status"}, PathScope: scopeProj}
	env := envDirectReq(t, []string{"LD_PRELOAD=/x/evil.so"}, "hg", "status")
	quoted := envDirectReq(t, []string{"FOO=x"}, "cmd", "a b")
	split := envDirectReq(t, []string{"FOO=x"}, "cmd", "a", "b")

	pairs := [][2]MatchRequest{{bare, env}, {env, bare}, {quoted, split}, {split, quoted}}
	for _, outcome := range []string{outcomeOnce, outcomeDeny, outcomeSessionGrant, outcomeFolderGrant, outcomeGlobalGrant} {
		for _, pair := range pairs {
			t.Run(outcome, func(t *testing.T) {
				cache := NewTurnCache()
				cache.Record(pair[0], outcome)
				if _, hit := cache.Lookup(pair[0]); !hit {
					t.Fatal("the recorded request lost its own cache entry")
				}
				if got, hit := cache.Lookup(pair[1]); hit {
					t.Fatalf("a %q recorded for one request replayed onto the other as %q", outcome, got)
				}
			})
		}
	}
}

func TestAuthorize_DirectEventsKeepJoinedSubjectsAndCarryIdentities(t *testing.T) {
	req := envDirectReq(t, []string{"FOO=bar"}, "git", "commit", "-m", "a b")
	command := ExactSubject("git", []string{"commit", "-m", "a b"})

	t.Run("prompt and grant decision", func(t *testing.T) {
		f := newFixture(func(context.Context, ScopeEscalation) (PromptOutcome, error) {
			return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "git :*"}, nil
		}, nil)
		mustAuthorize(t, req, f.deps)
		if len(f.cap.events) != 2 {
			t.Fatalf("emitted events = %d, want a prompt and a decision", len(f.cap.events))
		}
		for _, e := range f.cap.events {
			if e.subject != "git commit -m a b" {
				t.Fatalf("%s subject = %q, want the joined command tokens", e.kind, e.subject)
			}
			if e.directCommandSubject != command || e.directRequestSubject != req.Subject {
				t.Fatalf("%s identities = %q/%q, want %q/%q", e.kind, e.directCommandSubject, e.directRequestSubject, command, req.Subject)
			}
		}
	})

	t.Run("grant match", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		stored, err := EncodeDirectEnvSubject([]string{"FOO=bar"}, false, "git :*")
		if err != nil {
			t.Fatalf("EncodeDirectEnvSubject: %v", err)
		}
		f.grants.entries = []PermissionEntry{{Kind: subjectKindDirect, Subject: stored, PathScope: scopeProj, GrantKind: grantKindFolder}}
		mustAuthorize(t, req, f.deps)
		matched := f.cap.events[0]
		if matched.kind != "permission_matched" || matched.subject != "git commit -m a b" {
			t.Fatalf("permission_matched = %+v, want the joined command subject", matched)
		}
		if matched.directRequestSubject != req.Subject {
			t.Fatalf("permission_matched identity = %q, want %q", matched.directRequestSubject, req.Subject)
		}
	})

	t.Run("mode auto", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		bare := MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeProj}
		modeCtx := ModeContext{Mode: modePlan, Stages: []StageNormalization{{Route: RouteDirect, Tokens: []string{"ls"}}}}
		mustAuthorizeMode(t, bare, modeCtx, f.deps)
		matched := f.cap.events[0]
		if matched.outcomeSource != outcomeSourceModeAuto || matched.subject != "ls" {
			t.Fatalf("mode_auto event = %+v, want the joined command subject", matched)
		}
		if matched.directRequestSubject != "ls" {
			t.Fatalf("mode_auto identity = %q, want %q", matched.directRequestSubject, "ls")
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce
		mustAuthorize(t, req, f.deps)
		matched := f.cap.events[0]
		if matched.outcomeSource != outcomeSourceCache || matched.subject != "git commit -m a b" {
			t.Fatalf("cache event = %+v, want the joined command subject", matched)
		}
		if matched.directRequestSubject != req.Subject {
			t.Fatalf("cache identity = %q, want %q", matched.directRequestSubject, req.Subject)
		}
	})
}

func TestReadOnlyAutoMarksOnlyTheModeReadOnlyAllow(t *testing.T) {
	t.Run("prompt allow once", func(t *testing.T) {
		f := newFixture(choose(PromptAllowOnce), nil)
		req, mc := shellReqCtxFor(t, "build", "hg commit -m x")

		d := mustAuthorizeMode(t, req, mc, f.deps)

		if d.Outcome != outcomeOnce || d.ReadOnlyAuto {
			t.Fatalf("decision = %+v, want a prompt-sourced once with no read-only mode-auto source", d)
		}
	})

	t.Run("stored grant", func(t *testing.T) {
		f := newFixture(choose(PromptAllowFolder), nil)
		req, mc := shellReqCtxFor(t, "build", "hg commit -m x")
		mustAuthorizeMode(t, req, mc, f.deps)
		if len(f.grants.entries) == 0 {
			t.Fatal("the folder approval stored no grant")
		}
		f.deps.Prompt = neverPrompt

		d := mustAuthorizeMode(t, req, mc, f.deps)

		if d.Grant == nil || d.ReadOnlyAuto {
			t.Fatalf("decision = %+v, want a grant match with no read-only mode-auto source", d)
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		req, mc := shellReqCtxFor(t, "build", "hg commit -m x")
		f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce

		d := mustAuthorizeMode(t, req, mc, f.deps)

		if d.Outcome != outcomeOnce || d.ReadOnlyAuto {
			t.Fatalf("decision = %+v, want a cache-sourced once with no read-only mode-auto source", d)
		}
	})

	t.Run("plan denial", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		req, mc := shellReqCtxFor(t, modePlan, "hg commit -m x")

		d := mustAuthorizeMode(t, req, mc, f.deps)

		if d.Outcome != outcomeDeny || d.ReadOnlyAuto {
			t.Fatalf("decision = %+v, want a denial with no read-only mode-auto source", d)
		}
	})
}

func clearEnvDirectReq(t *testing.T, assignments []string, tokens ...string) MatchRequest {
	t.Helper()
	subject, err := DirectRequestSubject(tokens, assignments, true)
	if err != nil {
		t.Fatalf("DirectRequestSubject(%v, %v, true): %v", tokens, assignments, err)
	}
	return MatchRequest{
		Kind: subjectKindDirect, Subject: subject, SubjectTokens: tokens,
		Assignments: assignments, ClearEnvironment: true, PathScope: scopeProj,
	}
}

func TestAuthorize_ClearEnvironmentGrantStoresTheChosenScopeAsV2(t *testing.T) {
	assignments := []string{"PATH=/usr/bin", "HGPLAIN=+strictflags"}
	for _, scope := range []string{"hg status", "hg status :*", "hg :*"} {
		t.Run(scope, func(t *testing.T) {
			f := newFixture(func(context.Context, ScopeEscalation) (PromptOutcome, error) {
				return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: scope}, nil
			}, nil)
			req := clearEnvDirectReq(t, assignments, "hg", "status")

			mustAuthorize(t, req, f.deps)

			if len(f.cap.appends) != 1 {
				t.Fatalf("appended grants = %d, want 1", len(f.cap.appends))
			}
			entry := f.cap.appends[0]
			if !strings.HasPrefix(entry.Subject, directEnvSubjectPrefixV2) {
				t.Fatalf("stored subject %q does not carry the v2 sentinel", entry.Subject)
			}
			decoded, err := decodeDirectEnvSubject(entry.Subject)
			if err != nil {
				t.Fatalf("stored subject %q does not decode: %v", entry.Subject, err)
			}
			if decoded.Subject != scope || !decoded.ClearEnvironment || !slices.Equal(decoded.Assignments, assignments) {
				t.Fatalf("stored payload = %+v, want scope %q clearing with %v", decoded, scope, assignments)
			}
			if !Match(req, []PermissionEntry{entry}).Matched {
				t.Fatal("the stored grant does not authorize the request that created it")
			}
			inherited := envDirectReq(t, assignments, "hg", "status")
			if Match(inherited, []PermissionEntry{entry}).Matched {
				t.Fatal("the clear-environment grant authorized the inherited-environment form")
			}
		})
	}
}

func TestAuthorizeBatch_ClearedStoredSubjectKeepsTheV2RequestIdentity(t *testing.T) {
	assignments := []string{"PATH=/usr/bin"}
	f := newFixture(nil, nil)
	f.deps.PromptBatch = func(context.Context, []BatchPromptRequest) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "hg :*"}, nil
	}
	first := clearEnvDirectReq(t, assignments, "hg", "status")
	second := clearEnvDirectReq(t, assignments, "hg", "log")

	if _, err := AuthorizeBatch(context.Background(), []BatchRequest{{Req: first}, {Req: second}}, f.deps); err != nil {
		t.Fatalf("AuthorizeBatch: %v", err)
	}

	if len(f.cap.appends) != 2 {
		t.Fatalf("appended grants = %d, want 2", len(f.cap.appends))
	}
	for i, req := range []MatchRequest{first, second} {
		entry := f.cap.appends[i]
		if entry.Subject != req.Subject {
			t.Fatalf("stage %d stored %q, want the request identity %q", i, entry.Subject, req.Subject)
		}
		if !Match(req, []PermissionEntry{entry}).Matched {
			t.Fatalf("stage %d grant does not authorize the request that created it", i)
		}
	}
}

func TestTurnCache_IsolatesClearEnvironmentFromItsInheritedForm(t *testing.T) {
	assignments := []string{"PATH=/usr/bin", "FOO=1"}
	clear := clearEnvDirectReq(t, assignments, "cmd")
	inherited := envDirectReq(t, assignments, "cmd")
	bare := MatchRequest{Kind: subjectKindDirect, Subject: "cmd", SubjectTokens: []string{"cmd"}, PathScope: scopeProj}
	spaced := clearEnvDirectReq(t, []string{"PATH=/usr/bin", "FOO=1 cmd"}, "cmd")

	pairs := [][2]MatchRequest{{clear, inherited}, {inherited, clear}, {clear, bare}, {bare, clear}, {clear, spaced}, {spaced, clear}}
	for _, outcome := range []string{outcomeOnce, outcomeDeny, outcomeSessionGrant, outcomeFolderGrant, outcomeGlobalGrant} {
		for _, pair := range pairs {
			t.Run(outcome, func(t *testing.T) {
				cache := NewTurnCache()
				cache.Record(pair[0], outcome)
				if _, hit := cache.Lookup(pair[0]); !hit {
					t.Fatal("the recorded request lost its own cache entry")
				}
				if got, hit := cache.Lookup(pair[1]); hit {
					t.Fatalf("a %q recorded for one request replayed onto the other as %q", outcome, got)
				}
			})
		}
	}
}

func TestAuthorize_ClearEnvironmentEventsKeepTheUnchangedDirectContract(t *testing.T) {
	assignments := []string{"PATH=/usr/bin", "HGPLAIN=+strictflags"}
	tokens := []string{"hg", "commit", "-m", "a b"}
	req := clearEnvDirectReq(t, assignments, tokens...)
	command := ExactSubject(tokens[0], tokens[1:])

	f := newFixture(func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		return PromptOutcome{Choice: PromptAllowFolder, StoredSubject: "hg :*"}, nil
	}, nil)
	mustAuthorize(t, req, f.deps)

	if len(f.cap.events) != 2 {
		t.Fatalf("emitted events = %d, want a prompt and a decision", len(f.cap.events))
	}
	for _, e := range f.cap.events {
		if e.subject != strings.Join(tokens, " ") {
			t.Fatalf("%s subject = %q, want the joined command tokens", e.kind, e.subject)
		}
		if e.directCommandSubject != command || e.directRequestSubject != req.Subject {
			t.Fatalf("%s identities = %q/%q, want %q/%q", e.kind, e.directCommandSubject, e.directRequestSubject, command, req.Subject)
		}
		if !strings.HasPrefix(e.directRequestSubject, directEnvSubjectPrefixV2) {
			t.Fatalf("%s request identity %q is not the opaque v2 form", e.kind, e.directRequestSubject)
		}
	}
	prompt := f.cap.events[0]
	if !reflect.DeepEqual(prompt.directTokens, tokens) {
		t.Fatalf("emitted direct tokens = %q, want the command tokens %q", prompt.directTokens, tokens)
	}
	gotAssignments, gotClear, ok := DecodeDirectRequestSubject(prompt.directRequestSubject, prompt.directCommandSubject)
	if !ok || !gotClear || !slices.Equal(gotAssignments, assignments) {
		t.Fatalf("the emitted identity decoded to %v/%v/%v, want the clear request's ordered assignments", gotAssignments, gotClear, ok)
	}
}

func independentReq(subject, scope string) BatchRequest {
	return BatchRequest{Req: MatchRequest{Kind: subjectKindTool, Subject: subject, PathScope: scope}}
}

func fixedIndependentPrompt(calls *int, choices ...PromptChoice) func(context.Context, []BatchPromptRequest) ([]PromptOutcome, error) {
	return func(_ context.Context, prompts []BatchPromptRequest) ([]PromptOutcome, error) {
		*calls++
		outcomes := make([]PromptOutcome, len(prompts))
		for i := range prompts {
			outcomes[i] = PromptOutcome{Choice: choices[i]}
		}
		return outcomes, nil
	}
}

func TestAuthorizeIndependent_OnePromptReturnsAnOutcomePerCall(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptIndependent = fixedIndependentPrompt(&calls, PromptAllowOnce, PromptAllowOnce)
	f.grants.entries = []PermissionEntry{toolGrant("granted", scopeProj, grantKindFolder)}

	decs, err := AuthorizeIndependent(context.Background(), []BatchRequest{
		independentReq("granted", scopeProj), independentReq("read", scopeProj), independentReq("read_image", scopeProj),
	}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeIndependent error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("independent prompt called %d times, want exactly 1 for the whole group", calls)
	}
	if decs[0].Outcome != outcomeFolderGrant {
		t.Fatalf("resolved call decision = %+v, want the folder grant", decs[0])
	}
	if decs[1].Outcome != outcomeOnce || decs[2].Outcome != outcomeOnce {
		t.Fatalf("prompted decisions = %+v, want each allowed once", decs[1:])
	}
	wantKinds(t, f.cap.kinds(), []string{
		"permission_matched",
		"permission_prompt_shown", "permission_prompt_shown",
		"permission_decision", "permission_decision",
	})
}

func TestAuthorizeIndependent_MixedOutcomesApplyOnlyToTheirOwnCall(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptIndependent = fixedIndependentPrompt(&calls, PromptAllowOnce, PromptDeny, PromptAllowOnce)

	decs, err := AuthorizeIndependent(context.Background(), []BatchRequest{
		independentReq("read", scopeProj), independentReq("grep", scopeProj), independentReq("list", scopeProj),
	}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeIndependent error: %v", err)
	}
	if decs[0].Outcome != outcomeOnce || decs[2].Outcome != outcomeOnce {
		t.Fatalf("approved siblings = %+v, want both allowed once despite the denial between them", []Decision{decs[0], decs[2]})
	}
	if decs[1].Outcome != outcomeDeny || decs[1].DenyEnvelope == "" {
		t.Fatalf("denied call = %+v, want a deny carrying its own envelope", decs[1])
	}
	if decs[0].DenyEnvelope != "" || decs[2].DenyEnvelope != "" {
		t.Fatalf("an approved sibling inherited the denied call's envelope: %+v", decs)
	}
}

func TestAuthorizeIndependent_ResolvedDenyDoesNotStopSiblings(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptIndependent = fixedIndependentPrompt(&calls, PromptAllowOnce)
	f.cache.hits[turnCacheKeyOf(MatchRequest{Kind: subjectKindTool, Subject: "denied", PathScope: scopeProj})] = outcomeDeny

	decs, err := AuthorizeIndependent(context.Background(), []BatchRequest{
		independentReq("denied", scopeProj), independentReq("read", scopeProj),
	}, f.deps)
	if err != nil {
		t.Fatalf("AuthorizeIndependent error: %v", err)
	}
	if decs[0].Outcome != outcomeDeny {
		t.Fatalf("first decision = %+v, want the cached deny", decs[0])
	}
	// AuthorizeBatch stops a pipeline here; independent calls are not stages of one command.
	if decs[1].Outcome != outcomeOnce {
		t.Fatalf("second decision = %+v, want it authorized on its own despite the sibling denial", decs[1])
	}
}

func TestAuthorizeIndependent_PromptErrorResolvesNothing(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	boom := errors.New("prompt transport failed")
	f.deps.PromptIndependent = func(context.Context, []BatchPromptRequest) ([]PromptOutcome, error) {
		return nil, boom
	}

	_, err := AuthorizeIndependent(context.Background(), []BatchRequest{
		independentReq("read", scopeProj), independentReq("grep", scopeProj),
	}, f.deps)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the prompt error propagated", err)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("records = %+v, appends = %+v, want none after a failed prompt", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizeIndependent_ContextCancelled(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptIndependent = func(context.Context, []BatchPromptRequest) ([]PromptOutcome, error) {
		return nil, errors.New("prompt must not be called")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := AuthorizeIndependent(ctx, []BatchRequest{independentReq("read", scopeProj)}, f.deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(f.cap.events) != 0 {
		t.Fatalf("events = %+v, want none for a cancelled group", f.cap.events)
	}
}

func TestAuthorizeIndependent_CancelledWhileTheGroupPromptIsOpen(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	ctx, cancel := context.WithCancel(context.Background())
	f.deps.PromptIndependent = func(_ context.Context, prompts []BatchPromptRequest) ([]PromptOutcome, error) {
		cancel()
		outcomes := make([]PromptOutcome, len(prompts))
		for i := range prompts {
			outcomes[i] = PromptOutcome{Choice: PromptAllowGlobal}
		}
		return outcomes, nil
	}
	defer cancel()

	decs, err := AuthorizeIndependent(ctx, []BatchRequest{
		independentReq("read", scopeProj), independentReq("grep", scopeProj),
	}, f.deps)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled for an allow returned after the group was cancelled", err)
	}
	if decs != nil {
		t.Fatalf("decisions = %+v, want none so no caller can run a group member", decs)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("records = %+v, appends = %+v, want no grant or persistence for a cancelled group", f.cap.records, f.cap.appends)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_prompt_shown"})
}

func TestAuthorizeIndependent_ShortOutcomeVectorIsRejected(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptIndependent = func(context.Context, []BatchPromptRequest) ([]PromptOutcome, error) {
		return []PromptOutcome{{Choice: PromptAllowOnce}}, nil
	}

	_, err := AuthorizeIndependent(context.Background(), []BatchRequest{
		independentReq("read", scopeProj), independentReq("grep", scopeProj),
	}, f.deps)
	if err == nil {
		t.Fatalf("AuthorizeIndependent accepted 1 outcome for 2 prompted calls, want an error")
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("records = %+v, appends = %+v, want none for an unusable outcome vector", f.cap.records, f.cap.appends)
	}
}

func TestAuthorizeIndependent_RejectsFreshConfirmation(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	f.deps.PromptIndependent = func(context.Context, []BatchPromptRequest) ([]PromptOutcome, error) {
		return nil, errors.New("prompt must not be called")
	}
	req := independentReq("web_fetch", scopeProj)
	req.Req.FreshConfirmation = true

	if _, err := AuthorizeIndependent(context.Background(), []BatchRequest{req}, f.deps); err == nil {
		t.Fatalf("AuthorizeIndependent accepted a fresh confirmation, want a refusal")
	}
}

func TestAuthorizeIndependent_PersistenceBindsToTheRequestingCall(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	calls := 0
	f.deps.PromptIndependent = fixedIndependentPrompt(&calls, PromptAllowGlobal, PromptAllowGlobal)
	reqs := []BatchRequest{independentReq("read", scopeProj), independentReq("read", "/other/tree")}
	var persistedFor []string
	f.deps.PersistGrantAt = func(index int) func(PermissionEntry) (PermissionEntry, error) {
		return func(e PermissionEntry) (PermissionEntry, error) {
			persistedFor = append(persistedFor, reqs[index].Req.PathScope)
			return e, nil
		}
	}

	if _, err := AuthorizeIndependent(context.Background(), reqs, f.deps); err != nil {
		t.Fatalf("AuthorizeIndependent error: %v", err)
	}
	want := []string{scopeProj, "/other/tree"}
	if !reflect.DeepEqual(persistedFor, want) {
		t.Fatalf("persist bound to scopes %v, want %v (each grant degrades to its own request's path)", persistedFor, want)
	}
}

const (
	declTargetC = scopeProj + "/c.txt"
	declTargetD = scopeProj + "/d.txt"
)

func movePairs(pairs ...MovePair) map[MovePair]bool {
	m := make(map[MovePair]bool, len(pairs))
	for _, p := range pairs {
		m[p] = true
	}
	return m
}

func childMoveMode(source, destination string, moves map[MovePair]bool) ModeContext {
	mc := childMode(toolNameMove, "", nil)
	mc.MoveSource, mc.MoveDestination = source, destination
	mc.DeclaredMoves = moves
	return mc
}

func TestAuthorizeChildScope_AMovePairIsTheUnitOfAuthority(t *testing.T) {
	pairs := movePairs(MovePair{Source: declTargetA, Destination: declTargetB}, MovePair{Source: declTargetC, Destination: declTargetD})
	tests := []struct {
		name      string
		mc        ModeContext
		wantAllow bool
	}{
		{"a declared pair moves", childMoveMode(declTargetA, declTargetB, pairs), true},
		{"the other declared pair moves", childMoveMode(declTargetC, declTargetD, pairs), true},
		{"endpoints from two declared pairs do not compose", childMoveMode(declTargetA, declTargetD, pairs), false},
		{"a declared pair does not run backwards", childMoveMode(declTargetB, declTargetA, pairs), false},
		{"a declared pair grants no write on its destination", childMode(toolNameCreate, declTargetB, nil), false},
		{"a declared pair grants no delete of its source", childDeleteMode(declTargetA, nil, nil), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := tc.mc
			mc.DeclaredMoves = pairs

			d := mustAuthorizeMode(t, declReq(mc.ToolName), mc, f.deps)
			if tc.wantAllow {
				if d.Outcome != outcomeOnce {
					t.Fatalf("decision = %+v, want the pair's allow", d)
				}
				assertDeclaredEvent(t, f, outcomeOnce)
				return
			}
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}

	t.Run("a run ceiling authorizes no move whatever pairs reach it", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := declMode(toolNameMove, "", declSet(declTargetA, declTargetB), declSet(declTargetA, declTargetB))
		mc.MoveSource, mc.MoveDestination, mc.DeclaredMoves = declTargetA, declTargetB, pairs

		d := mustAuthorizeMode(t, declReq(toolNameMove), mc, f.deps)
		if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
			t.Fatalf("decision = %+v, want a declared-scope denial", d)
		}
		assertDeclaredEvent(t, f, outcomeDeny)
	})
}

func TestAuthorizeChildScope_MoveRefusalNamesTheFilesMoveForm(t *testing.T) {
	tests := []struct {
		name  string
		moves map[MovePair]bool
		form  string
	}{
		{"files_move omitted", nil, "this delegate call did not supply files_move"},
		{"files_move supplied empty", movePairs(), "this delegate call supplied an empty files_move"},
		{"files_move without this pair", movePairs(MovePair{Source: declTargetB, Destination: declTargetA}),
			"this delegate call's files_move does not declare this source and destination as one pair"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(toolNameMove), childMoveMode(declTargetA, declTargetB, tc.moves), f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)

			reason := envelopeReason(t, d.DenyEnvelope)
			at := -1
			for _, want := range []string{"a child agent may touch only the paths its delegate call declared", tc.form, "cannot widen while the child runs", "source=" + strconv.Quote(declTargetA)} {
				idx := strings.Index(reason, want)
				if idx <= at {
					t.Fatalf("reason %q is missing %q or has it out of order", reason, want)
				}
				at = idx
			}
			if !strings.HasSuffix(reason, "destination="+strconv.Quote(declTargetB)) {
				t.Fatalf("reason %q does not end with the canonical destination", reason)
			}
			if strings.Contains(reason, declaredWriteFlag) {
				t.Fatalf("reason %q names a CLI flag; a child refusal names the delegate argument", reason)
			}
		})
	}
}

func TestAuthorizeChildScope_NestedMovePairsMatchOnlyAsWholePairs(t *testing.T) {
	ab := MovePair{Source: declTargetA, Destination: declTargetB}
	cd := MovePair{Source: declTargetC, Destination: declTargetD}
	ad := MovePair{Source: declTargetA, Destination: declTargetD}
	tests := []struct {
		name           string
		parent, nested map[MovePair]bool
		moveOnly       bool
		wantAllow      bool
	}{
		{name: "a declared pair", parent: movePairs(ab, cd), nested: movePairs(ab), wantAllow: true},
		{name: "every declared pair", parent: movePairs(ab, cd), nested: movePairs(ab, cd), wantAllow: true},
		{name: "a move-only nested declaration", parent: movePairs(ab), nested: movePairs(ab), moveOnly: true, wantAllow: true},
		{name: "endpoints recombined from two parent pairs", parent: movePairs(ab, cd), nested: movePairs(ad)},
		{name: "a pair the parent did not declare", parent: movePairs(ab), nested: movePairs(cd)},
		{name: "any pair under a parent with no move pairs", nested: movePairs(ab)},
		{name: "an omitted nested move form fits a parent with none", wantAllow: true},
		{name: "a supplied empty nested move form fits a parent with none", nested: movePairs(), wantAllow: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := nestedScopesMode(declSet(declTargetA), nil, declSet(declTargetA), nil)
			if tc.moveOnly {
				mc.DelegateWrite = nil
			}
			mc.DeclaredMoves, mc.DelegateMoves = tc.parent, tc.nested

			d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
			want := outcomeDeny
			if tc.wantAllow {
				want = outcomeOnce
			}
			if d.Outcome != want {
				t.Fatalf("decision = %+v, want %s", d, want)
			}
			assertDeclaredEvent(t, f, want)
			if tc.wantAllow {
				return
			}
			reason := envelopeReason(t, d.DenyEnvelope)
			if !strings.Contains(reason, "a nested delegate call may declare in files_move only whole move pairs its own parent already declared") {
				t.Fatalf("reason %q does not name the nested move-pair rule", reason)
			}
			if !strings.Contains(reason, "undeclared_move=") || strings.Contains(reason, "undeclared=") {
				t.Fatalf("reason %q should name only the undeclared move pairs", reason)
			}
		})
	}
}

func TestAuthorizeDeclaredScope_TopLevelDelegateMovePairsAreRefusedUnderARunCeiling(t *testing.T) {
	ab := MovePair{Source: declTargetA, Destination: declTargetB}
	tests := []struct {
		name           string
		candidateWrite map[string]bool
		moves          map[MovePair]bool
		wantDenied     bool
	}{
		{name: "a pair beside a covered write list", candidateWrite: declSet(declTargetA), moves: movePairs(ab), wantDenied: true},
		{name: "a move-only candidate", moves: movePairs(ab), wantDenied: true},
		{name: "a supplied empty move form", candidateWrite: declSet(declTargetA), moves: movePairs()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mc := topLevelScopesMode(declSet(declTargetA, declTargetB), declSet(declTargetA, declTargetB), tc.candidateWrite, nil)
			mc.DelegateMoves = tc.moves
			if !tc.wantDenied {
				f := newFixture(neverPrompt, nil)
				d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
				assertLeftToLaunchOperations(t, f, d)
				return
			}
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)

			reason := envelopeReason(t, d.DenyEnvelope)
			at := -1
			for _, want := range []string{
				"a declared-scope ceiling is active for this run and a child agent may declare no move pairs",
				"neither " + declaredWriteFlag + " nor " + declaredDeleteFlag + " can authorize files_move",
				"the ceiling cannot widen during the run",
			} {
				idx := strings.Index(reason, want)
				if idx <= at {
					t.Fatalf("reason %q is missing %q or has it out of order", reason, want)
				}
				at = idx
			}
			if wantLast := "undeclared_move=" + strconv.Quote(declTargetA+" -> "+declTargetB); !strings.HasSuffix(reason, wantLast) {
				t.Fatalf("reason %q does not end with the escaped undeclared pair %q", reason, wantLast)
			}
		})
	}
}

func TestAuthorizePromptAnsweredAfterCancellationGrantsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newFixture(func(context.Context, ScopeEscalation) (PromptOutcome, error) {
		cancel()
		return PromptOutcome{Choice: PromptAllowFolder}, nil
	}, nil)

	if _, err := Authorize(ctx, toolReq(), ModeContext{}, f.deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(f.cap.persists) != 0 || len(f.cap.appends) != 0 || len(f.cap.records) != 0 {
		t.Fatalf("an answer after cancellation took effect: persists=%v appends=%v records=%v", f.cap.persists, f.cap.appends, f.cap.records)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown"})
}

func assertConfinedOnce(t *testing.T, f *orchFixture, req MatchRequest, d Decision) {
	t.Helper()
	if f.cap.prompts != 0 {
		t.Fatalf("confined Plan must not prompt, prompted %d times", f.cap.prompts)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	ev := f.cap.events[0]
	if ev.outcomeSource != OutcomeSourceConfined || ev.outcome != outcomeOnce {
		t.Fatalf("event = %+v, want confined once", ev)
	}
	if ev.grantKind != "" || ev.grantPathScope != "" {
		t.Fatalf("confined allow carried grant fields: %+v", ev)
	}
	wantHash := ""
	if req.Kind == subjectKindLiteral {
		wantHash = ComputeArgumentHash(req.Subject)
	}
	if ev.argHash != wantHash {
		t.Fatalf("argument_hash = %q, want %q", ev.argHash, wantHash)
	}
	if d.Outcome != outcomeOnce || d.Grant != nil || d.DenyEnvelope != "" || d.ReadOnlyAuto {
		t.Fatalf("decision = %+v, want once with no grant, envelope or ReadOnlyAuto", d)
	}
	if len(f.cap.records) != 0 || len(f.cap.appends) != 0 || len(f.cap.persists) != 0 {
		t.Fatalf("confined allow touched cache or grants: records=%v appends=%v persists=%v", f.cap.records, f.cap.appends, f.cap.persists)
	}
}

func TestAuthorizeConstrainedPlanShellRecordsConfined(t *testing.T) {
	cases := []struct {
		name, input string
		kind        string
		readOnly    bool
	}{
		{"mutating direct", "touch out.txt", subjectKindDirect, false},
		{"mutating literal", `ls > out`, subjectKindLiteral, false},
		{"read-only direct", "rg foo | head", subjectKindDirect, true},
		{"read-only literal", "ls && pwd", subjectKindLiteral, true},
	}
	flags := []struct {
		name string
		set  func(*ModeContext)
	}{
		{"plain", func(*ModeContext) {}},
		{"shell path ask", func(mc *ModeContext) { mc.ShellPathAsk = true }},
		{"external read", func(mc *ModeContext) { mc.ExternalRead = true }},
		{"network egress", func(mc *ModeContext) { mc.NetworkEgress = true }},
	}
	for _, tc := range cases {
		for _, fl := range flags {
			t.Run(tc.name+"/"+fl.name, func(t *testing.T) {
				req, mc := shellReqCtxFor(t, modePlan, tc.input)
				if req.Kind != tc.kind {
					t.Fatalf("request kind = %q, want %q", req.Kind, tc.kind)
				}
				mc.ExecutionConstrained = true
				fl.set(&mc)

				f := newFixture(neverPrompt, nil)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				assertConfinedOnce(t, f, req, d)

				g := newFixture(neverPrompt, nil)
				d, handled, err := modePosture(req, mc, g.deps)
				if err != nil || !handled {
					t.Fatalf("modePosture handled=%v err=%v, want handled", handled, err)
				}
				assertConfinedOnce(t, g, req, d)
			})
		}
		t.Run(tc.name+"/unconstrained", func(t *testing.T) {
			req, mc := shellReqCtxFor(t, modePlan, tc.input)
			f := newFixture(neverPrompt, nil)

			d := mustAuthorizeMode(t, req, mc, f.deps)

			wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
			ev := f.cap.events[0]
			wantOutcome := outcomeDeny
			if tc.readOnly {
				wantOutcome = outcomeOnce
			}
			if ev.outcomeSource != outcomeSourceModeAuto || ev.outcome != wantOutcome || d.Outcome != wantOutcome {
				t.Fatalf("event = %+v decision = %+v, want mode_auto %s", ev, d, wantOutcome)
			}
			if d.ReadOnlyAuto != tc.readOnly {
				t.Fatalf("ReadOnlyAuto = %v, want %v", d.ReadOnlyAuto, tc.readOnly)
			}
			if !tc.readOnly && d.DenyEnvelope == "" {
				t.Fatalf("unconstrained mutating shell must keep the mode deny envelope")
			}
		})
	}
}

func TestAuthorizeConstrainedPlanLiteralRewriteAskRecordsConfined(t *testing.T) {
	const literal = `sh -c "echo hi"`
	f := newFixture(neverPrompt, nil)
	req := MatchRequest{Kind: subjectKindLiteral, Subject: literal, PathScope: scopeProj}
	mc := ModeContext{Mode: modePlan, Class: ClassMutating, LiteralRoute: true, ShellPathAsk: true, ExecutionConstrained: true}

	d := mustAuthorizeMode(t, req, mc, f.deps)

	assertConfinedOnce(t, f, req, d)
}

func TestAuthorizeConstrainedPlanStillDeniesStructuredEdit(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	req := MatchRequest{Kind: subjectKindTool, Subject: toolNameEdit, PathScope: scopeProj}
	mc := ModeContext{Mode: modePlan, Class: ClassMutating, ToolName: toolNameEdit, ExecutionConstrained: true}

	d := mustAuthorizeMode(t, req, mc, f.deps)

	if d.Outcome != outcomeDeny || d.DenyEnvelope != BuildModeDenyEnvelope(d.DenyReason) || d.DenialSource != outcomeSourceModeAuto {
		t.Fatalf("decision = %+v, want the mode deny envelope", d)
	}
}

func TestModePostureConstrainedPlanLeavesHostUnhandled(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	req := MatchRequest{Kind: subjectKindHost, Subject: "web_fetch", PathScope: "docs.example.com"}
	mc := ModeContext{Mode: modePlan, Class: ClassMutating, ExecutionConstrained: true}

	_, handled, err := modePosture(req, mc, f.deps)

	if handled || err != nil {
		t.Fatalf("host request handled=%v err=%v, want unhandled", handled, err)
	}
	if len(f.cap.events) != 0 {
		t.Fatalf("host request emitted %v, want none", f.cap.events)
	}
}

const scopeWritable = "/home/u/shared"

func constrainedAutoShell(t *testing.T, input string) (MatchRequest, ModeContext) {
	t.Helper()
	req, mc := shellReqCtxFor(t, modeAutoEdits, input)
	mc.ExecutionConstrained = true
	mc.ProjectRoot = scopeProj
	mc.WritableFolders = []string{scopeWritable}
	return req, mc
}

func constrainedAutoTool(tool, target string) (MatchRequest, ModeContext) {
	req := MatchRequest{Kind: subjectKindTool, Subject: tool, PathScope: filepath.Dir(target)}
	mc := ModeContext{Mode: modeAutoEdits, Class: ClassMutating, ToolName: tool, TargetPath: target,
		ProjectRoot: scopeProj, WritableFolders: []string{scopeWritable}, ExecutionConstrained: true}
	return req, mc
}

func wantUnhandled(t *testing.T, req MatchRequest, mc ModeContext) {
	t.Helper()
	f := newFixture(neverPrompt, nil)
	if d, handled, err := modePosture(req, mc, f.deps); handled || err != nil {
		t.Fatalf("modePosture(%q) = %+v handled=%v err=%v, want unhandled", req.Subject, d, handled, err)
	}
	if len(f.cap.events) != 0 {
		t.Fatalf("unhandled request emitted %v", f.cap.events)
	}
}

func wantModeAutoAllow(t *testing.T, req MatchRequest, mc ModeContext) {
	t.Helper()
	f := newFixture(neverPrompt, nil)
	d, handled, err := modePosture(req, mc, f.deps)
	if !handled || err != nil || d.Outcome != outcomeOnce {
		t.Fatalf("modePosture(%s %s) = %+v handled=%v err=%v, want a mode_auto allow", req.Subject, mc.TargetPath, d, handled, err)
	}
	wantKinds(t, f.cap.kinds(), []string{"permission_matched"})
	if src := f.cap.events[0].outcomeSource; src != outcomeSourceModeAuto {
		t.Fatalf("outcome_source = %q, want mode_auto", src)
	}
}

func TestModePostureConstrainedAutoShell(t *testing.T) {
	for _, input := range []string{"bash build.sh", "make", "touch a", "python -m pip install x", "sudo rm x", "rg foo | head", "ls && pwd", `sh -c 'go build ./...'`} {
		t.Run("confined "+input, func(t *testing.T) {
			req, mc := constrainedAutoShell(t, input)
			f := newFixture(neverPrompt, nil)
			d, handled, err := modePosture(req, mc, f.deps)
			if !handled || err != nil {
				t.Fatalf("handled=%v err=%v, want handled", handled, err)
			}
			assertConfinedOnce(t, f, req, d)
		})
	}
	for _, input := range []string{
		`sh -c 'curl x'`, "curl x", "rm x", "hg --cwd /repo strip", "hg --config extensions.strip= strip",
		"git -c x=y reset --hard", "git reset HEAD~1 --hard", `sh -c 'if true; then curl x; fi'`, `ls && curl x`,
	} {
		t.Run("unhandled "+input, func(t *testing.T) {
			req, mc := constrainedAutoShell(t, input)
			wantUnhandled(t, req, mc)
		})
	}
	t.Run("git reset --soft is ordinary", func(t *testing.T) {
		req, mc := constrainedAutoShell(t, "git reset --soft HEAD~1")
		f := newFixture(neverPrompt, nil)
		d, _, _ := modePosture(req, mc, f.deps)
		assertConfinedOnce(t, f, req, d)
	})
}

func TestModePostureConstrainedAutoFileTools(t *testing.T) {
	inRoot := scopeProj + "/a.txt"
	inWritable := scopeWritable + "/a.txt"
	sibling := "/home/u/shared-other/a.txt"
	for _, tool := range []string{toolNameEdit, toolNameCreate, toolNameMkdir} {
		t.Run(tool, func(t *testing.T) {
			req, mc := constrainedAutoTool(tool, inRoot)
			wantModeAutoAllow(t, req, mc)
			req, mc = constrainedAutoTool(tool, inWritable)
			wantModeAutoAllow(t, req, mc)
			req, mc = constrainedAutoTool(tool, sibling)
			wantUnhandled(t, req, mc)
		})
	}
	t.Run("unconstrained writable folder is unhandled", func(t *testing.T) {
		req, mc := constrainedAutoTool(toolNameEdit, inWritable)
		mc.ExecutionConstrained = false
		wantUnhandled(t, req, mc)
	})
	t.Run("delete gains no allowance", func(t *testing.T) {
		req, mc := constrainedAutoTool(toolNameDelete, inRoot)
		wantUnhandled(t, req, mc)
		req, mc = constrainedAutoTool(toolNameDelete, inWritable)
		wantUnhandled(t, req, mc)
	})
	t.Run("move is not widened", func(t *testing.T) {
		mc := moveAutoMode(inRoot, scopeProj+"/b.txt")
		mc.ExecutionConstrained = true
		mc.WritableFolders = []string{scopeWritable}
		wantModeAutoAllow(t, moveReq(), mc)
		mc.MoveDestination = inWritable
		wantUnhandled(t, moveReq(), mc)
	})
}

func TestAuthorizeConstrainedAutoOrdinaryShellRecordsConfined(t *testing.T) {
	flags := []func(*ModeContext){
		func(*ModeContext) {},
		func(mc *ModeContext) { mc.ShellPathAsk = true },
		func(mc *ModeContext) { mc.ExternalRead = true },
		func(mc *ModeContext) { mc.NetworkEgress = true },
	}
	for _, input := range []string{"touch a", "rg foo | head", "ls && pwd", `sh -c 'go build ./...'`} {
		for i, set := range flags {
			t.Run(fmt.Sprintf("%s/%d", input, i), func(t *testing.T) {
				req, mc := constrainedAutoShell(t, input)
				set(&mc)
				f := newFixture(neverPrompt, nil)
				assertConfinedOnce(t, f, req, mustAuthorizeMode(t, req, mc, f.deps))
			})
		}
	}
	for i, set := range flags {
		t.Run(fmt.Sprintf("exceptional/%d", i), func(t *testing.T) {
			req, mc := constrainedAutoShell(t, "curl x")
			set(&mc)
			f := newFixture(choose(PromptAllowOnce), nil)
			mustAuthorizeMode(t, req, mc, f.deps)
			if f.cap.prompts != 1 {
				t.Fatalf("prompts = %d, want 1", f.cap.prompts)
			}
		})
	}
	for _, input := range []string{
		"sh -c 'r\\\nm --version'", "ls && cu\\\nrl x", "sh -c 'git re\\\nset --hard'",
		"sh -c 'git reset --ha\\\nrd'", "sh -c 'hg st\\\nrip tip'",
	} {
		t.Run("line continuation "+input, func(t *testing.T) {
			req, mc := constrainedAutoShell(t, input)
			f := newFixture(choose(PromptAllowOnce), nil)
			mustAuthorizeMode(t, req, mc, f.deps)
			if f.cap.prompts != 1 {
				t.Fatalf("prompts = %d, want 1", f.cap.prompts)
			}
			for _, ev := range f.cap.events {
				if ev.outcomeSource == OutcomeSourceConfined {
					t.Fatalf("automatic confined allowance emitted: %+v", ev)
				}
			}
		})
	}
	t.Run("declared command hit", func(t *testing.T) {
		req, mc := constrainedAutoShell(t, "make test")
		mc.DeclaredCommands = []DeclaredCommand{{Subject: "make test"}}
		f := newFixture(neverPrompt, nil)
		assertConfinedOnce(t, f, req, mustAuthorizeMode(t, req, mc, f.deps))
	})
}

func TestAuthorizeConstrainedAutoExceptionalIgnoresGrantsAndCache(t *testing.T) {
	cases := []struct {
		input string
		grant PermissionEntry
	}{
		{"curl x", directGrant("curl x", allPathsScope, grantKindGlobal)},
		{`sh -c 'curl x'`, literalGrant(`sh -c 'curl x'`, allPathsScope, grantKindGlobal)},
		{`ls && curl x`, literalGrant(`ls && curl x`, allPathsScope, grantKindGlobal)},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			req, mc := constrainedAutoShell(t, tc.input)

			f := newFixture(choose(PromptAllowOnce), nil)
			f.grants.entries = []PermissionEntry{tc.grant}
			mustAuthorizeMode(t, req, mc, f.deps)
			if f.cap.prompts != 1 {
				t.Fatalf("saved grant suppressed the constrained prompt: prompts = %d", f.cap.prompts)
			}

			f = newFixture(choose(PromptAllowOnce), nil)
			f.cache.hits[turnCacheKeyOf(req)] = outcomeOnce
			mustAuthorizeMode(t, req, mc, f.deps)
			if f.cap.prompts != 1 {
				t.Fatalf("cache entry suppressed the constrained prompt: prompts = %d", f.cap.prompts)
			}

			mc.ExecutionConstrained = false
			f = newFixture(neverPrompt, nil)
			f.grants.entries = []PermissionEntry{tc.grant}
			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Grant == nil || f.cap.prompts != 0 {
				t.Fatalf("unconstrained decision = %+v prompts = %d, want the saved grant", d, f.cap.prompts)
			}
		})
	}
	t.Run("out-of-scope edit keeps its grant path", func(t *testing.T) {
		req, mc := constrainedAutoTool(toolNameEdit, "/home/u/elsewhere/a.txt")
		f := newFixture(neverPrompt, nil)
		f.grants.entries = []PermissionEntry{toolGrant(toolNameEdit, allPathsScope, grantKindGlobal)}
		d := mustAuthorizeMode(t, req, mc, f.deps)
		if d.Grant == nil || f.cap.prompts != 0 {
			t.Fatalf("decision = %+v prompts = %d, want the saved grant", d, f.cap.prompts)
		}
	})
}

func brokenSettingsShapes(t *testing.T, mode string) map[string][]BatchRequest {
	t.Helper()
	split := func(input string, literal bool) SplitResult {
		t.Helper()
		s, err := SplitCommand(input)
		if err != nil || s.LiteralRoute != literal {
			t.Fatalf("SplitCommand(%q) = %+v, %v; want literal route %v", input, s, err, literal)
		}
		return s
	}
	stageReqs := func(stages []StageNormalization) []BatchRequest {
		t.Helper()
		out := make([]BatchRequest, len(stages))
		for i, s := range stages {
			subject, err := DirectRequestSubject(s.Tokens, s.Assignments, s.ClearEnvironment)
			if err != nil {
				t.Fatalf("DirectRequestSubject: %v", err)
			}
			out[i] = BatchRequest{
				Req: MatchRequest{Kind: subjectKindDirect, Subject: subject, SubjectTokens: s.Tokens,
					Assignments: s.Assignments, ClearEnvironment: s.ClearEnvironment, PathScope: scopeProj},
				ModeCtx: ModeContext{Mode: mode, Class: ClassMutating, Stages: []StageNormalization{s}},
			}
		}
		return out
	}
	staged := split("touch a && ls", true)
	wrapped, stagedStages, _, ok := SimpleCompoundStages(staged.LiteralInput)
	if !ok || wrapped || len(stagedStages) != 2 {
		t.Fatalf("SimpleCompoundStages(%q) = %v %+v %v, want two unwrapped stages", staged.LiteralInput, wrapped, stagedStages, ok)
	}
	pipe := split("rg foo | head", false)
	if len(pipe.Stages) != 2 {
		t.Fatalf("pipe stages = %+v, want two", pipe.Stages)
	}
	literal := split(`sh -c 'touch a'`, true)
	return map[string][]BatchRequest{
		"direct":     stageReqs(split("make test", false).Stages),
		"staged":     stageReqs(stagedStages),
		"pipe group": stageReqs(pipe.Stages),
		"literal": {{
			Req:     MatchRequest{Kind: subjectKindLiteral, Subject: literal.LiteralInput, PathScope: scopeProj},
			ModeCtx: ModeContext{Mode: mode, Class: ClassMutating, Stages: literal.Stages, LiteralRoute: true},
		}},
	}
}

type brokenVariant struct {
	name  string
	apply func(t *testing.T, f *orchFixture, reqs []BatchRequest)
}

var brokenVariants = []brokenVariant{
	{"no grant", func(*testing.T, *orchFixture, []BatchRequest) {}},
	{"grant", func(t *testing.T, f *orchFixture, reqs []BatchRequest) {
		for _, r := range reqs {
			f.grants.entries = append(f.grants.entries, PermissionEntry{Kind: r.Req.Kind, Subject: r.Req.Subject, PathScope: allPathsScope, GrantKind: grantKindGlobal})
			if !Match(r.Req, f.grants.entries).Matched {
				t.Fatalf("grant does not match %+v", r.Req)
			}
		}
	}},
	{"turn cache allow", func(_ *testing.T, f *orchFixture, reqs []BatchRequest) {
		for _, r := range reqs {
			f.cache.hits[turnCacheKeyOf(r.Req)] = outcomeOnce
		}
	}},
	{"declared command", func(_ *testing.T, _ *orchFixture, reqs []BatchRequest) {
		for i, r := range reqs {
			if r.Req.Kind == subjectKindDirect {
				reqs[i].ModeCtx.DeclaredCommands = []DeclaredCommand{{Subject: r.Req.Subject}}
			}
		}
	}},
}

var authorizePaths = []string{"single", "batch", "independent"}

func runShellShape(t *testing.T, path string, reqs []BatchRequest, setFlags func(*ModeContext), variant func(*testing.T, *orchFixture, []BatchRequest)) ([]Decision, *orchCaptures) {
	t.Helper()
	reqs = slices.Clone(reqs)
	for i := range reqs {
		setFlags(&reqs[i].ModeCtx)
	}
	f := newFixture(choose(PromptAllowOnce), nil)
	f.deps.PromptBatch = func(_ context.Context, prompts []BatchPromptRequest) (PromptOutcome, error) {
		f.cap.prompts += len(prompts)
		return PromptOutcome{Choice: PromptAllowOnce}, nil
	}
	f.deps.PromptIndependent = func(_ context.Context, prompts []BatchPromptRequest) ([]PromptOutcome, error) {
		f.cap.prompts += len(prompts)
		out := make([]PromptOutcome, len(prompts))
		for i := range out {
			out[i] = PromptOutcome{Choice: PromptAllowOnce}
		}
		return out, nil
	}
	variant(t, f, reqs)
	var decs []Decision
	var err error
	switch path {
	case "single":
		for _, r := range reqs {
			d := mustAuthorizeMode(t, r.Req, r.ModeCtx, f.deps)
			decs = append(decs, d)
		}
	case "batch":
		decs, err = AuthorizeBatch(context.Background(), reqs, f.deps)
	case "independent":
		decs, err = AuthorizeIndependent(context.Background(), reqs, f.deps)
	}
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return decs, f.cap
}

func TestAuthorizeConstrainedBrokenSettingsAsksBeforeEveryShellCommand(t *testing.T) {
	for _, mode := range []string{modePlan, modeAutoEdits} {
		for shape, reqs := range brokenSettingsShapes(t, mode) {
			for _, v := range brokenVariants {
				for _, path := range authorizePaths {
					t.Run(strings.Join([]string{mode, shape, v.name, path}, "/"), func(t *testing.T) {
						decs, cap := runShellShape(t, path, reqs, func(mc *ModeContext) {
							mc.ExecutionConstrained, mc.SettingsBroken = true, false
						}, v.apply)
						if cap.prompts != 0 {
							t.Fatalf("valid settings prompted %d times, want the existing auto-allow", cap.prompts)
						}
						for i, d := range decs {
							if d.Outcome == outcomeDeny {
								t.Fatalf("valid settings decision %d = %+v, want an allow", i, d)
							}
						}

						decs, cap = runShellShape(t, path, reqs, func(mc *ModeContext) {
							mc.ExecutionConstrained, mc.SettingsBroken = true, true
						}, v.apply)
						if cap.prompts != len(reqs) {
							t.Fatalf("broken settings prompted %d times for %d requests, want every request asked", cap.prompts, len(reqs))
						}
						for _, ev := range cap.events {
							if ev.kind == "permission_matched" {
								t.Fatalf("broken settings auto-resolved %+v", ev)
							}
						}
						for i, d := range decs {
							if d.Outcome != outcomeOnce {
								t.Fatalf("broken settings decision %d = %+v, want the prompted allow", i, d)
							}
						}
					})
				}
			}
		}
	}
}

func TestAuthorizeConstrainedBrokenSettingsKeepsCachedDenials(t *testing.T) {
	cachedDeny := func(_ *testing.T, f *orchFixture, reqs []BatchRequest) {
		for _, r := range reqs {
			f.cache.hits[turnCacheKeyOf(r.Req)] = outcomeDeny
		}
	}
	for _, mode := range []string{modePlan, modeAutoEdits} {
		for shape, reqs := range brokenSettingsShapes(t, mode) {
			for _, path := range authorizePaths {
				t.Run(strings.Join([]string{mode, shape, path}, "/"), func(t *testing.T) {
					decs, cap := runShellShape(t, path, reqs, func(mc *ModeContext) {
						mc.ExecutionConstrained, mc.SettingsBroken = true, true
					}, cachedDeny)
					if cap.prompts != 0 {
						t.Fatalf("cached denial prompted %d times", cap.prompts)
					}
					if d := decs[0]; d.Outcome != outcomeDeny || d.DenialSource != outcomeSourceCache {
						t.Fatalf("decision = %+v, want the cached denial", d)
					}
				})
			}
		}
	}
}

func TestAuthorizeBrokenSettingsLeavesUnconstrainedAndBuildUnchanged(t *testing.T) {
	postures := []struct {
		name, mode  string
		constrained bool
	}{
		{"unconstrained plan", modePlan, false},
		{"unconstrained auto", modeAutoEdits, false},
		{"constrained build", "build", true},
		{"unconstrained build", "build", false},
	}
	for _, p := range postures {
		for shape, reqs := range brokenSettingsShapes(t, p.mode) {
			for _, v := range brokenVariants {
				for _, path := range authorizePaths {
					t.Run(strings.Join([]string{p.name, shape, v.name, path}, "/"), func(t *testing.T) {
						flags := func(broken bool) func(*ModeContext) {
							return func(mc *ModeContext) { mc.ExecutionConstrained, mc.SettingsBroken = p.constrained, broken }
						}
						wantDecs, wantCap := runShellShape(t, path, reqs, flags(false), v.apply)
						gotDecs, gotCap := runShellShape(t, path, reqs, flags(true), v.apply)
						if !reflect.DeepEqual(gotDecs, wantDecs) || !reflect.DeepEqual(gotCap, wantCap) {
							t.Fatalf("broken settings changed the outcome:\n got %+v %+v\nwant %+v %+v", gotDecs, gotCap, wantDecs, wantCap)
						}
					})
				}
			}
		}
	}
	t.Run("unconstrained plan keeps read-only allows and mutating denials", func(t *testing.T) {
		shapes := brokenSettingsShapes(t, modePlan)
		broken := func(mc *ModeContext) { mc.SettingsBroken = true }
		none := brokenVariants[0].apply
		decs, _ := runShellShape(t, "single", shapes["pipe group"], broken, none)
		for i, d := range decs {
			if d.Outcome != outcomeOnce || !d.ReadOnlyAuto {
				t.Fatalf("read-only stage %d = %+v, want the read-only allow", i, d)
			}
		}
		for _, shape := range []string{"direct", "literal"} {
			decs, _ = runShellShape(t, "single", shapes[shape], broken, none)
			if d := decs[0]; d.Outcome != outcomeDeny || d.DenialSource != outcomeSourceModeAuto {
				t.Fatalf("%s = %+v, want the Plan mutating denial", shape, d)
			}
		}
	})
}

const (
	declDirX  = scopeProj + "/x"
	declDirXY = scopeProj + "/x/y"
	declDirXZ = scopeProj + "/x/z"
)

func childDirMode(target string, dirs map[string]bool) ModeContext {
	mc := childMode(toolNameMkdir, target, nil)
	mc.DeclaredDirs = dirs
	return mc
}

func TestAuthorizeChildScope_MkdirNeedsTheExactDeclaredDirectory(t *testing.T) {
	dirs := declSet(declDirXY, declDirXZ)
	tests := []struct {
		name      string
		target    string
		wantAllow bool
	}{
		{"a declared directory", declDirXY, true},
		{"the other declared directory", declDirXZ, true},
		{"the missing parent a declared mkdir creates", declDirX, false},
		{"a directory below a declared one", declDirXY + "/deeper", false},
		{"an undeclared sibling", scopeProj + "/x/w", false},
		{"a case variant", scopeProj + "/x/Y", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(toolNameMkdir), childDirMode(tc.target, dirs), f.deps)
			if tc.wantAllow {
				if d.Outcome != outcomeOnce {
					t.Fatalf("decision = %+v, want the declaration's allow", d)
				}
				assertDeclaredEvent(t, f, outcomeOnce)
				return
			}
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope || IsModeDenyEnvelope(d.DenyEnvelope) {
				t.Fatalf("decision = %+v, want a terminal declared-scope denial", d)
			}
			if deniedBy, _ := decodeDenyFields(t, d.DenyEnvelope); deniedBy != "user" {
				t.Fatalf("denied_by = %q, want user", deniedBy)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}

	t.Run("a global grant does not widen it", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		f.grants.entries = []PermissionEntry{toolGrant(toolNameMkdir, allPathsScope, grantKindGlobal)}
		d := mustAuthorizeMode(t, declReq(toolNameMkdir), childDirMode(declDirX, dirs), f.deps)
		if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
			t.Fatalf("decision = %+v, want a declared-scope denial ahead of the grant", d)
		}
		assertDeclaredEvent(t, f, outcomeDeny)
	})

	t.Run("Plan stays a mode denial", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := childDirMode(declDirXY, dirs)
		mc.Mode = modePlan
		d := mustAuthorizeMode(t, declReq(toolNameMkdir), mc, f.deps)
		if !IsModeDenyEnvelope(d.DenyEnvelope) || lastEvent(t, f).outcomeSource != outcomeSourceModeAuto {
			t.Fatalf("Plan decision = %+v with event %+v, want a mode denial", d, lastEvent(t, f))
		}
	})

	t.Run("a run ceiling authorizes no mkdir whatever directories reach it", func(t *testing.T) {
		f := newFixture(neverPrompt, nil)
		mc := declMode(toolNameMkdir, declDirXY, declSet(declDirXY), declSet(declDirXY))
		mc.DeclaredDirs = dirs
		d := mustAuthorizeMode(t, declReq(toolNameMkdir), mc, f.deps)
		if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
			t.Fatalf("decision = %+v, want a declared-scope denial", d)
		}
		assertDeclaredEvent(t, f, outcomeDeny)
	})
}

func TestAuthorizeChildScope_ADeclaredDirectoryGrantsNothingInsideItOrOnIt(t *testing.T) {
	inside := declDirX + "/f.txt"
	tests := []struct {
		name string
		mc   ModeContext
	}{
		{"no create inside it", childMode(toolNameCreate, inside, nil)},
		{"no edit inside it", childMode(toolNameEdit, inside, nil)},
		{"no create of the directory path itself", childMode(toolNameCreate, declDirX, nil)},
		{"no delete inside it", childDeleteMode(inside, nil, nil)},
		{"no delete of the directory itself", childDeleteMode(declDirX, nil, nil)},
		{"no move out of it", childMoveMode(inside, declTargetA, nil)},
		{"no move into it", childMoveMode(declTargetA, inside, nil)},
		{"no move of the directory itself", childMoveMode(declDirX, declTargetB, nil)},
		{"no mkdir inside it", childMode(toolNameMkdir, declDirXY, nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			mc := tc.mc
			mc.DeclaredDirs = declSet(declDirX)

			d := mustAuthorizeMode(t, declReq(mc.ToolName), mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)
		})
	}
}

func TestAuthorizeChildScope_MkdirRefusalNamesTheFilesMkdirForm(t *testing.T) {
	tests := []struct {
		name string
		dirs map[string]bool
		form string
	}{
		{"files_mkdir omitted", nil, "this delegate call did not supply files_mkdir"},
		{"files_mkdir supplied empty", declSet(), "this delegate call supplied an empty files_mkdir"},
		{"files_mkdir without this directory", declSet(declDirXZ), "this delegate call's files_mkdir does not list this directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(toolNameMkdir), childDirMode(declDirXY, tc.dirs), f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)

			reason := envelopeReason(t, d.DenyEnvelope)
			at := -1
			for _, want := range []string{"a child agent may touch only the paths its delegate call declared", tc.form, "cannot widen while the child runs"} {
				idx := strings.Index(reason, want)
				if idx <= at {
					t.Fatalf("reason %q is missing %q or has it out of order", reason, want)
				}
				at = idx
			}
			if !strings.HasSuffix(reason, "target="+strconv.Quote(declDirXY)) {
				t.Fatalf("reason %q does not end with the canonical target", reason)
			}
		})
	}
}

func TestAuthorizeChildScope_NestedDirectoriesMustBeASubsetOfTheParentsDirectories(t *testing.T) {
	tests := []struct {
		name                   string
		parentWrite            map[string]bool
		parent, nested         map[string]bool
		nestedWrite            map[string]bool
		wantAllow, wantDirRule bool
	}{
		{name: "a proper subset", parent: declSet(declDirXY, declDirXZ), nested: declSet(declDirXY), nestedWrite: declSet(declTargetA), wantAllow: true},
		{name: "an equal set", parent: declSet(declDirXY, declDirXZ), nested: declSet(declDirXY, declDirXZ), nestedWrite: declSet(declTargetA), wantAllow: true},
		{name: "a directory-only nested candidate", parent: declSet(declDirXY), nested: declSet(declDirXY), wantAllow: true},
		{name: "an omitted nested directory form", parent: declSet(declDirXY), nestedWrite: declSet(declTargetA), wantAllow: true},
		{name: "a supplied empty nested directory form", nested: declSet(), nestedWrite: declSet(declTargetA), wantAllow: true},
		{name: "an extra directory", parent: declSet(declDirXY), nested: declSet(declDirXY, declDirXZ), nestedWrite: declSet(declTargetA), wantDirRule: true},
		{name: "any directory under a parent with none", nested: declSet(declDirXY), nestedWrite: declSet(declTargetA), wantDirRule: true},
		{name: "the missing parent of a declared directory", parent: declSet(declDirXY), nested: declSet(declDirX), nestedWrite: declSet(declTargetA), wantDirRule: true},
		{name: "a parent write path admits no nested directory", parentWrite: declSet(declTargetA, declDirX), nested: declSet(declDirX), nestedWrite: declSet(declTargetA), wantDirRule: true},
		{name: "a parent directory admits no nested write inside it", parent: declSet(declDirX), nestedWrite: declSet(declDirX + "/f.txt")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			parentWrite := tc.parentWrite
			if parentWrite == nil {
				parentWrite = declSet(declTargetA)
			}
			mc := nestedDelegateMode(parentWrite, tc.nestedWrite)
			mc.DeclaredDirs, mc.DelegateDirs = tc.parent, tc.nested

			d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
			want := outcomeDeny
			if tc.wantAllow {
				want = outcomeOnce
			}
			if d.Outcome != want {
				t.Fatalf("decision = %+v, want %s", d, want)
			}
			assertDeclaredEvent(t, f, want)
			if !tc.wantDirRule {
				return
			}
			reason := envelopeReason(t, d.DenyEnvelope)
			if !strings.Contains(reason, "a nested delegate call may declare in files_mkdir only directories its own parent already declared") {
				t.Fatalf("reason %q does not name the nested directory rule", reason)
			}
			if !strings.Contains(reason, "undeclared_mkdir=") || strings.Contains(reason, "undeclared=") {
				t.Fatalf("reason %q should name only the undeclared directories", reason)
			}
		})
	}
}

func TestAuthorizeDeclaredScope_TopLevelDelegateDirectoriesAreRefusedUnderARunCeiling(t *testing.T) {
	tests := []struct {
		name           string
		ceiling        bool
		candidateWrite map[string]bool
		dirs           map[string]bool
		wantDenied     bool
	}{
		{name: "a directory beside a covered write list", ceiling: true, candidateWrite: declSet(declTargetA), dirs: declSet(declDirXY), wantDenied: true},
		{name: "a directory-only candidate", ceiling: true, dirs: declSet(declDirXY), wantDenied: true},
		{name: "a supplied empty directory form", ceiling: true, candidateWrite: declSet(declTargetA), dirs: declSet()},
		{name: "no run ceiling", candidateWrite: declSet(declTargetA), dirs: declSet(declDirXY)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var write, remove map[string]bool
			if tc.ceiling {
				write, remove = declSet(declTargetA, declTargetB, declDirXY), declSet(declTargetA, declTargetB)
			}
			mc := topLevelScopesMode(write, remove, tc.candidateWrite, nil)
			mc.DelegateDirs = tc.dirs
			if !tc.wantDenied {
				f := newFixture(neverPrompt, nil)
				d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
				assertLeftToLaunchOperations(t, f, d)
				return
			}
			f := newFixture(neverPrompt, nil)
			d := mustAuthorizeMode(t, declReq(toolNameDelegate), mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenialSource != OutcomeSourceDeclaredScope {
				t.Fatalf("decision = %+v, want a declared-scope denial", d)
			}
			assertDeclaredEvent(t, f, outcomeDeny)

			reason := envelopeReason(t, d.DenyEnvelope)
			at := -1
			for _, want := range []string{
				"a declared-scope ceiling is active for this run and a child agent may declare no directories",
				"neither " + declaredWriteFlag + " nor " + declaredDeleteFlag + " can authorize files_mkdir",
				"the ceiling cannot widen during the run",
			} {
				idx := strings.Index(reason, want)
				if idx <= at {
					t.Fatalf("reason %q is missing %q or has it out of order", reason, want)
				}
				at = idx
			}
			if wantLast := "undeclared_mkdir=" + strconv.Quote(declDirXY); !strings.HasSuffix(reason, wantLast) {
				t.Fatalf("reason %q does not end with the escaped undeclared directory %q", reason, wantLast)
			}
		})
	}
}
