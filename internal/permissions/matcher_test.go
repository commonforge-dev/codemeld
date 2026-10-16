// Tests for real-grant permission matching across direct/literal/tool subjects, path-scope rules, ordering, and no-match behavior.
package permissions

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Synthetic absolute paths reused across cases. IsDescendantOrEqual cleans and
// compares them without touching the filesystem, so they need not exist.
const (
	scopeProj  = "/home/u/proj"
	scopeSub   = "/home/u/proj/sub"
	scopeUp    = "/home/u"
	scopeOther = "/home/u/other"
)

func directGrant(subject, scope, grantKind string) PermissionEntry {
	return PermissionEntry{Kind: subjectKindDirect, Subject: subject, PathScope: scope, GrantKind: grantKind}
}

func literalGrant(subject, scope, grantKind string) PermissionEntry {
	return PermissionEntry{Kind: subjectKindLiteral, Subject: subject, PathScope: scope, GrantKind: grantKind}
}

func toolGrant(subject, scope, grantKind string) PermissionEntry {
	return PermissionEntry{Kind: subjectKindTool, Subject: subject, PathScope: scope, GrantKind: grantKind}
}

func hostGrant(subject, host string) PermissionEntry {
	return PermissionEntry{Kind: subjectKindTool, Subject: subject, HostScope: host, GrantKind: grantKindProject}
}

func hostReq(subject, host string) MatchRequest {
	return MatchRequest{Kind: subjectKindHost, Subject: subject, Host: host}
}

// TestMatch is the comprehensive table: each kind's subject rule, the
// session/folder/global path-scope rules, kind isolation, the direct `:*`
// token-boundary cases, and the no-match / negative-smuggling cases. wantIdx is
// the index of the grant expected to win, or -1 for a no-match.
func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		req     MatchRequest
		grants  []PermissionEntry
		wantIdx int
	}{
		// direct subject rule ---
		{
			name:    "direct exact match (folder grant)",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "git status", SubjectTokens: []string{"git", "status"}, PathScope: scopeProj},
			grants:  []PermissionEntry{directGrant("git status", scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		{
			name:    "direct wildcard matches token-boundary prefix",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "git log --oneline", SubjectTokens: []string{"git", "log", "--oneline"}, PathScope: scopeProj},
			grants:  []PermissionEntry{directGrant("git log :*", scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		{
			name:    "direct exact rejects extra argument",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "git status -s", SubjectTokens: []string{"git", "status", "-s"}, PathScope: scopeProj},
			grants:  []PermissionEntry{directGrant("git status", scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		// literal subject rule ---
		{
			name:    "literal exact byte-equal match",
			req:     MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj},
			grants:  []PermissionEntry{literalGrant(`sh -c "echo hi"`, scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		// tool subject rule ---
		{
			name:    "tool exact name match (global grant)",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj},
			grants:  []PermissionEntry{toolGrant("vcs_commit", allPathsScope, grantKindGlobal)},
			wantIdx: 0,
		},
		{
			name:    "tool different name no match",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj},
			grants:  []PermissionEntry{toolGrant("vcs_push", allPathsScope, grantKindGlobal)},
			wantIdx: -1,
		},
		// capability subject expansion (read side of the fold) ---
		{
			name:    "capability write grant matches create at scope",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "create", PathScope: scopeProj},
			grants:  []PermissionEntry{toolGrant(CapabilityWrite, scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		{
			name:    "capability write grant matches edit at scope",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeProj},
			grants:  []PermissionEntry{toolGrant(CapabilityWrite, scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		{
			name:    "capability write grant matches edit at descendant",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeSub},
			grants:  []PermissionEntry{toolGrant(CapabilityWrite, scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		{
			name:    "capability write grant does not match a sibling scope",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "create", PathScope: scopeOther},
			grants:  []PermissionEntry{toolGrant(CapabilityWrite, scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		{
			name:    "capability write grant does not match a read member",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "grep", PathScope: scopeProj},
			grants:  []PermissionEntry{toolGrant(CapabilityWrite, scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		{
			name:    "capability write grant does not match an unrelated tool",
			req:     MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj},
			grants:  []PermissionEntry{toolGrant(CapabilityWrite, scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		// path-scope rules ---
		{
			name:    "global grant matches any request path",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeOther},
			grants:  []PermissionEntry{directGrant("ls", allPathsScope, grantKindGlobal)},
			wantIdx: 0,
		},
		{
			name:    "folder grant matches descendant path",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeSub},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		{
			name:    "folder grant matches the scope itself",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeProj},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindFolder)},
			wantIdx: 0,
		},
		{
			name:    "folder grant does not match ancestor",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeUp},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		{
			name:    "folder grant does not match sibling",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeOther},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		{
			name:    "session grant matches descendant like a folder grant",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeSub},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindSession)},
			wantIdx: 0,
		},
		{
			name:    "session grant does not match ancestor like a folder grant",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeUp},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindSession)},
			wantIdx: -1,
		},
		// --- kind isolation: a grant of another kind never matches ---
		{
			name:    "tool grant does not satisfy a direct request with the same subject string",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeProj},
			grants:  []PermissionEntry{toolGrant("ls", scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		// --- no match against an empty / non-matching table (cache untouched) ---
		{
			name:    "no grants returns a clean no-match",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "rm", SubjectTokens: []string{"rm"}, PathScope: scopeProj},
			grants:  nil,
			wantIdx: -1,
		},
		{
			name:    "no matching subject returns a clean no-match",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "rm", SubjectTokens: []string{"rm"}, PathScope: scopeProj},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindFolder)},
			wantIdx: -1,
		},
		// --- defensive: a malformed global grant whose scope is not "*" ---
		{
			name:    "global grant kind with non-star scope never matches",
			req:     MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: scopeProj},
			grants:  []PermissionEntry{directGrant("ls", scopeProj, grantKindGlobal)},
			wantIdx: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMatch(t, Match(tt.req, tt.grants), tt.grants, tt.wantIdx)
		})
	}
}

// TestMatch_GeneralizedCompound is the terminal wiring test: a real Match over a
// stored generalized compound grant, exercised through the production matcher, authorizes a
// differently-argued compound while a program/operator/stage change re-prompts, and the widening
// never bypasses path-scope containment (invariant 5: a request whose resolved scope is an ancestor
// or sibling of the grant scope never matches, however its arguments widen).
func TestMatch_GeneralizedCompound(t *testing.T) {
	encoded, err := EncodeCompoundSubject(true, []string{"gofmt :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	grant := literalGrant(encoded, scopeProj, grantKindFolder)
	// The byte-exact subject the user originally approved, kept as a separate literal grant to prove
	// the two coexist and that the generalized grant is what authorizes a re-argued command.
	exact := literalGrant(canon(t, `sh -c 'gofmt -w a.go && go build ./...'`), scopeProj, grantKindFolder)

	litReq := func(cmd, scope string) MatchRequest {
		return MatchRequest{Kind: subjectKindLiteral, Subject: canon(t, cmd), PathScope: scope}
	}

	cases := []struct {
		name   string
		req    MatchRequest
		grants []PermissionEntry
		want   bool
	}{
		{
			name:   "widened arguments match the generalized grant",
			req:    litReq(`sh -c 'gofmt -l -w pkg/ && go build -v ./cmd/...'`, scopeProj),
			grants: []PermissionEntry{grant},
			want:   true,
		},
		{
			name:   "the original byte-exact command still matches the generalized grant",
			req:    litReq(`sh -c 'gofmt -w a.go && go build ./...'`, scopeSub),
			grants: []PermissionEntry{grant},
			want:   true,
		},
		{
			name:   "program swap re-prompts (no match)",
			req:    litReq(`sh -c 'gofmt -w a.go && go test ./...'`, scopeProj),
			grants: []PermissionEntry{grant},
			want:   false,
		},
		{
			name:   "operator injection re-prompts (no match)",
			req:    litReq(`sh -c 'gofmt -w a.go && rm -rf y'`, scopeProj),
			grants: []PermissionEntry{grant},
			want:   false,
		},
		{
			name:   "added stage re-prompts (no match)",
			req:    litReq(`sh -c 'gofmt -w a.go && go build ./... && echo done'`, scopeProj),
			grants: []PermissionEntry{grant},
			want:   false,
		},
		{
			name:   "invariant 5: widened args cannot escape to an ancestor scope",
			req:    litReq(`sh -c 'gofmt -w a.go && go build ./...'`, scopeUp),
			grants: []PermissionEntry{grant},
			want:   false,
		},
		{
			name:   "invariant 5: widened args cannot ride into a sibling scope",
			req:    litReq(`sh -c 'gofmt -w a.go && go build ./...'`, scopeOther),
			grants: []PermissionEntry{grant},
			want:   false,
		},
		{
			name:   "regression: a byte-exact literal grant is unaffected and still matches its exact command",
			req:    litReq(`sh -c 'gofmt -w a.go && go build ./...'`, scopeProj),
			grants: []PermissionEntry{exact},
			want:   true,
		},
		{
			name:   "regression: a byte-exact literal grant does not widen",
			req:    litReq(`sh -c 'gofmt -l -w pkg/ && go build ./...'`, scopeProj),
			grants: []PermissionEntry{exact},
			want:   false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.req, tt.grants)
			if res.Matched != tt.want {
				t.Fatalf("Match(%q) matched = %v, want %v", tt.req.Subject, res.Matched, tt.want)
			}
		})
	}
}

// TestMatch_NegativeTable asserts the specific evasion attempts the spec calls
// out: direct wildcard token-boundary smuggling, a folder path-prefix escape,
// and subject normalization/encoding tricks — each must yield no match.
func TestMatch_NegativeTable(t *testing.T) {
	tests := []struct {
		name   string
		req    MatchRequest
		grants []PermissionEntry
	}{
		{
			name:   "direct wildcard does not smuggle past the token boundary (git :* vs gitfoo)",
			req:    MatchRequest{Kind: subjectKindDirect, Subject: "gitfoo", SubjectTokens: []string{"gitfoo"}, PathScope: scopeProj},
			grants: []PermissionEntry{directGrant("git :*", scopeProj, grantKindFolder)},
		},
		{
			name:   "direct wildcard does not match a suffixed token (git log :* vs git logfoo)",
			req:    MatchRequest{Kind: subjectKindDirect, Subject: "git logfoo", SubjectTokens: []string{"git", "logfoo"}, PathScope: scopeProj},
			grants: []PermissionEntry{directGrant("git log :*", scopeProj, grantKindFolder)},
		},
		{
			name:   "folder path-prefix escape (/a/bc is not a descendant of /a/b)",
			req:    MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: "/a/bc"},
			grants: []PermissionEntry{directGrant("ls", "/a/b", grantKindFolder)},
		},
		{
			name:   "literal subject differing only in whitespace does not match",
			req:    MatchRequest{Kind: subjectKindLiteral, Subject: "echo hi", PathScope: scopeProj},
			grants: []PermissionEntry{literalGrant("echo  hi", scopeProj, grantKindFolder)},
		},
		{
			// quote-style-equivalent commands now share a canonical form and DO
			// match (see TestMatch_LiteralQuoteEquivalence); what must still fail is
			// a near-miss whose canonical forms stay distinct — here a single-quoted
			// literal `$x` against a double-quoted expansion `$x`.
			name:   "literal expansion variants do not match",
			req:    MatchRequest{Kind: subjectKindLiteral, Subject: `echo '$x'`, PathScope: scopeProj},
			grants: []PermissionEntry{literalGrant(`echo "$x"`, scopeProj, grantKindFolder)},
		},
		{
			name:   "tool name is not a prefix or substring match",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj},
			grants: []PermissionEntry{toolGrant("vcs_commit_amend", allPathsScope, grantKindGlobal)},
		},
		{
			// A permission grant persisted under the old dotted VCS tool name is stale after
			// the provider-safe rename: it fails closed against the new underscore subject
			// (exact match only), so the user is prompted again rather than silently granted.
			name:   "stale dotted VCS grant does not match new underscore subject",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj},
			grants: []PermissionEntry{toolGrant("vcs.commit", allPathsScope, grantKindGlobal)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMatch(t, Match(tt.req, tt.grants), tt.grants, -1)
		})
	}
}

func TestMatch_ExactHost(t *testing.T) {
	const host = "api.example.com"
	if canonical, err := CanonicalHost(host); err != nil || canonical != host {
		t.Fatalf("CanonicalHost(%q) = (%q, %v), want (%q, nil): fixture is not canonical", host, canonical, err, host)
	}

	tests := []struct {
		name   string
		req    MatchRequest
		grants []PermissionEntry
		want   bool
	}{
		{
			name:   "exact host and tool match",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
			want:   true,
		},
		{
			name:   "exact host and tool match for web_search",
			req:    hostReq("web_search", host),
			grants: []PermissionEntry{hostGrant("web_search", host)},
			want:   true,
		},
		{
			name:   "parent host does not match a child grant",
			req:    hostReq("web_fetch", "example.com"),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
		},
		{
			name:   "child host does not match a parent grant",
			req:    hostReq("web_fetch", "inner.api.example.com"),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
		},
		{
			name:   "sibling host does not match",
			req:    hostReq("web_fetch", "cdn.example.com"),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
		},
		{
			name:   "wildcard grant does not match a concrete host",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{hostGrant("web_fetch", "*.example.com")},
		},
		{
			name:   "all-hosts sentinel grant does not match, even a sentinel request",
			req:    hostReq("web_fetch", allPathsScope),
			grants: []PermissionEntry{hostGrant("web_fetch", allPathsScope)},
		},
		{
			name:   "case variant does not match",
			req:    hostReq("web_fetch", "API.Example.com"),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
		},
		{
			name:   "trailing-dot variant does not match",
			req:    hostReq("web_fetch", host+"."),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
		},
		{
			name:   "a web_search grant never authorizes web_fetch",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{hostGrant("web_search", host)},
		},
		{
			name:   "a web_fetch grant never authorizes web_search",
			req:    hostReq("web_search", host),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
		},
		{
			name:   "a host request with no host fails closed",
			req:    hostReq("web_fetch", ""),
			grants: []PermissionEntry{hostGrant("web_fetch", host)},
		},
		{
			name:   "an empty host on both sides fails closed rather than matching itself",
			req:    hostReq("web_fetch", ""),
			grants: []PermissionEntry{hostGrant("web_fetch", "")},
		},
		{
			name:   "a host request naming a non-network subject fails closed",
			req:    hostReq("read", host),
			grants: []PermissionEntry{hostGrant("read", host)},
		},
		{
			name:   "a path-scoped tool grant cannot answer a host request",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{toolGrant("web_fetch", scopeProj, grantKindFolder)},
		},
		{
			name:   "a global tool grant cannot answer a host request",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{toolGrant("web_fetch", allPathsScope, grantKindGlobal)},
		},
		{
			name:   "a capability grant cannot answer a host request",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{toolGrant(CapabilityRead, scopeProj, grantKindFolder)},
		},
		{
			name:   "a host grant carrying a path scope is malformed and never matches",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{{Kind: subjectKindTool, Subject: "web_fetch", HostScope: host, PathScope: scopeProj, GrantKind: grantKindProject}},
		},
		{
			name:   "a host grant with a non-project grant kind never matches",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{{Kind: subjectKindTool, Subject: "web_fetch", HostScope: host, GrantKind: grantKindFolder}},
		},
		{
			name:   "a host grant with a non-tool kind never matches",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{{Kind: subjectKindLiteral, Subject: "web_fetch", HostScope: host, GrantKind: grantKindProject}},
		},
		{
			name:   "an empty-host grant never matches a host request",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{{Kind: subjectKindTool, Subject: "web_fetch", GrantKind: grantKindProject}},
		},
		{
			name:   "a non-matching earlier host grant does not stop the scan",
			req:    hostReq("web_fetch", host),
			grants: []PermissionEntry{hostGrant("web_fetch", "other.example.com"), hostGrant("web_fetch", host)},
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantIdx := -1
			if tt.want {
				wantIdx = len(tt.grants) - 1
			}
			assertMatch(t, Match(tt.req, tt.grants), tt.grants, wantIdx)
		})
	}
}

func TestMatch_HostGrantDoesNotWidenPathMatching(t *testing.T) {
	const host = "api.example.com"
	fetchGrant := hostGrant("web_fetch", host)

	t.Run("a host grant never answers a path-scoped tool request", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "web_fetch", PathScope: scopeProj}
		assertMatch(t, Match(req, []PermissionEntry{fetchGrant}), []PermissionEntry{fetchGrant}, -1)
	})
	t.Run("a host grant never answers a direct command request", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindDirect, Subject: "web_fetch", SubjectTokens: []string{"web_fetch"}, PathScope: scopeProj}
		assertMatch(t, Match(req, []PermissionEntry{fetchGrant}), []PermissionEntry{fetchGrant}, -1)
	})
	t.Run("a host grant never answers a literal command request", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindLiteral, Subject: "web_fetch", PathScope: scopeProj}
		assertMatch(t, Match(req, []PermissionEntry{fetchGrant}), []PermissionEntry{fetchGrant}, -1)
	})
	t.Run("a malformed grant carrying both scopes never answers a path request", func(t *testing.T) {
		both := []PermissionEntry{{Kind: subjectKindTool, Subject: "web_fetch", HostScope: host, PathScope: scopeProj, GrantKind: grantKindFolder}}
		req := MatchRequest{Kind: subjectKindTool, Subject: "web_fetch", PathScope: scopeProj}
		assertMatch(t, Match(req, both), both, -1)
	})

	grants := []PermissionEntry{
		fetchGrant,
		directGrant("git status", scopeProj, grantKindFolder),
		literalGrant(`sh -c "echo hi"`, scopeProj, grantKindFolder),
		toolGrant(CapabilityWrite, scopeProj, grantKindFolder),
		toolGrant("vcs_commit", allPathsScope, grantKindGlobal),
	}
	regressions := []struct {
		name    string
		req     MatchRequest
		wantIdx int
	}{
		{"direct still matches its folder grant", MatchRequest{Kind: subjectKindDirect, Subject: "git status", SubjectTokens: []string{"git", "status"}, PathScope: scopeProj}, 1},
		{"direct still fails outside its scope", MatchRequest{Kind: subjectKindDirect, Subject: "git status", SubjectTokens: []string{"git", "status"}, PathScope: scopeOther}, -1},
		{"literal still matches byte-exact", MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "echo hi"`, PathScope: scopeProj}, 2},
		{"capability still expands to a member at a descendant", MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeSub}, 3},
		{"capability still stops at a sibling scope", MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeOther}, -1},
		{"global tool grant still matches any path", MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeOther}, 4},
	}
	for _, tt := range regressions {
		t.Run(tt.name, func(t *testing.T) {
			assertMatch(t, Match(tt.req, grants), grants, tt.wantIdx)
		})
	}
}

// TestMatch_LiteralQuoteEquivalence proves the end-to-end merge: a grant stored
// for one quoting spelling matches a request made with any equivalent spelling,
// because both reach the matcher as the same canonical subject. The matcher itself
// stays byte-exact — the equivalence comes from CanonicalLiteralForm upstream.
func TestMatch_LiteralQuoteEquivalence(t *testing.T) {
	storedSubject, err := CanonicalLiteralForm(`gofmt -w 'x'`)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm error = %v", err)
	}
	grants := []PermissionEntry{literalGrant(storedSubject, scopeProj, grantKindFolder)}
	for _, spelling := range []string{`gofmt -w x`, `gofmt -w 'x'`, `gofmt -w "x"`} {
		reqSubject, err := CanonicalLiteralForm(spelling)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q) error = %v", spelling, err)
		}
		req := MatchRequest{Kind: subjectKindLiteral, Subject: reqSubject, PathScope: scopeProj}
		assertMatch(t, Match(req, grants), grants, 0)
	}
}

// TestMatch_FirstMatchWins confirms iteration order is the tie-break: the first
// stored grant that satisfies kind, subject, and path scope wins, even when a
// later grant would also match.
func TestMatch_FirstMatchWins(t *testing.T) {
	grants := []PermissionEntry{
		directGrant("git :*", scopeProj, grantKindFolder),  // matches first
		directGrant("git log", scopeProj, grantKindFolder), // also matches
	}
	req := MatchRequest{Kind: subjectKindDirect, Subject: "git log", SubjectTokens: []string{"git", "log"}, PathScope: scopeProj}
	assertMatch(t, Match(req, grants), grants, 0)
}

// TestMatch_NoMatchDoesNotCarryCacheOutcome pins the done-when item that a
// no-match result is a pure no-match: no Grant and no outcome source. The
// matcher has no cache parameter, so a cache hit can only be produced later by
// the turn cache and prompt orchestration, never here.
func TestMatch_NoMatchDoesNotCarryCacheOutcome(t *testing.T) {
	req := MatchRequest{Kind: subjectKindDirect, Subject: "rm -rf /", SubjectTokens: []string{"rm", "-rf", "/"}, PathScope: scopeProj}
	got := Match(req, []PermissionEntry{directGrant("ls", scopeProj, grantKindFolder)})
	if got.Matched {
		t.Fatalf("Match() Matched = true, want false")
	}
	if got.Grant != nil {
		t.Fatalf("Match() Grant = %+v, want nil", *got.Grant)
	}
	if got.OutcomeSource != "" {
		t.Fatalf("Match() OutcomeSource = %q, want empty (cache read is owned by g145/g155)", got.OutcomeSource)
	}
}

// TestMatch_LiteralAndToolIgnoreSubjectTokens guards the shared-type invariant
// from the architecture review: SubjectTokens is meaningful only for direct
// requests; literal and tool matching must ignore it and key off Subject.
func TestMatch_LiteralAndToolIgnoreSubjectTokens(t *testing.T) {
	t.Run("literal ignores bogus SubjectTokens", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindLiteral, Subject: "echo hi", SubjectTokens: []string{"totally", "different"}, PathScope: scopeProj}
		grants := []PermissionEntry{literalGrant("echo hi", scopeProj, grantKindFolder)}
		assertMatch(t, Match(req, grants), grants, 0)
	})
	t.Run("tool ignores bogus SubjectTokens", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", SubjectTokens: []string{"totally", "different"}, PathScope: scopeProj}
		grants := []PermissionEntry{toolGrant("vcs_commit", allPathsScope, grantKindGlobal)}
		assertMatch(t, Match(req, grants), grants, 0)
	})
}

// TestMatch_CapabilityReadAllMembers asserts a stored read capability grant
// matches every one of its concrete member subjects at the scope and a
// descendant. The expected member list is hand-written here, not read from the
// matcher's own source-of-truth table, so a regression that drops, adds, or
// changes a read member is caught rather than silently mirrored by the test.
func TestMatch_CapabilityReadAllMembers(t *testing.T) {
	want := []string{"read", "grep", "glob", "list", "tree", "file_count"}
	assertCapabilityMembers(t, CapabilityRead, want)
	grants := []PermissionEntry{toolGrant(CapabilityRead, scopeProj, grantKindFolder)}
	for _, member := range want {
		t.Run(member+" at scope", func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: member, PathScope: scopeProj}
			assertMatch(t, Match(req, grants), grants, 0)
		})
		t.Run(member+" at descendant", func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: member, PathScope: scopeSub}
			assertMatch(t, Match(req, grants), grants, 0)
		})
	}
	t.Run("read capability does not match a write member", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeProj}
		assertMatch(t, Match(req, grants), grants, -1)
	})
}

// TestMatch_CapabilityWriteAllMembers is the adversarial write-capability table:
// a stored write grant matches every concrete write member (create and edit) at
// the grant scope and at a descendant scope — including create at a descendant,
// the case TestMatch alone does not cover. The member set is pinned to an
// independent hand-written list so a dropped or added write member is caught,
// mirroring TestMatch_CapabilityReadAllMembers for the write side of the fold.
func TestMatch_CapabilityWriteAllMembers(t *testing.T) {
	want := []string{"create", "edit"}
	assertCapabilityMembers(t, CapabilityWrite, want)
	grants := []PermissionEntry{toolGrant(CapabilityWrite, scopeProj, grantKindFolder)}
	for _, member := range want {
		t.Run(member+" at scope", func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: member, PathScope: scopeProj}
			assertMatch(t, Match(req, grants), grants, 0)
		})
		t.Run(member+" at descendant", func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: member, PathScope: scopeSub}
			assertMatch(t, Match(req, grants), grants, 0)
		})
	}
	t.Run("write capability does not match a read member", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "grep", PathScope: scopeProj}
		assertMatch(t, Match(req, grants), grants, -1)
	})
	t.Run("legacy write capability does not fold mkdir", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "mkdir", PathScope: scopeProj}
		assertMatch(t, Match(req, grants), grants, -1)
	})
}

func TestMatch_CapabilityWriteTreeAllMembers(t *testing.T) {
	want := []string{"create", "edit", "mkdir"}
	assertCapabilityMembers(t, CapabilityWriteTree, want)
	grants := []PermissionEntry{toolGrant(CapabilityWriteTree, scopeProj, grantKindFolder)}
	for _, member := range want {
		t.Run(member+" at scope", func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: member, PathScope: scopeProj}
			assertMatch(t, Match(req, grants), grants, 0)
		})
		t.Run(member+" at descendant", func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: member, PathScope: scopeSub}
			assertMatch(t, Match(req, grants), grants, 0)
		})
	}
	for _, outside := range []string{"grep", "read", "move", "delete", "vcs_commit"} {
		t.Run("write_tree does not fold "+outside, func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: outside, PathScope: scopeProj}
			assertMatch(t, Match(req, grants), grants, -1)
		})
	}
	t.Run("write_tree does not authorize a direct shell mkdir", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindDirect, Subject: "mkdir sub", SubjectTokens: []string{"mkdir", "sub"}, PathScope: scopeProj}
		assertMatch(t, Match(req, grants), grants, -1)
	})
	t.Run("write_tree does not authorize a literal shell command", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c "mkdir sub"`, PathScope: scopeProj}
		assertMatch(t, Match(req, grants), grants, -1)
	})
	t.Run("write_tree does not match a sibling scope", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "mkdir", PathScope: scopeOther}
		assertMatch(t, Match(req, grants), grants, -1)
	})
}

// TestMatch_LegacyConcreteNoWidening pins the no-retroactive-widening guarantee:
// a legacy concrete tool grant keeps exact-match semantics, so a stored "create"
// matches request "create" but never "edit", even though both are members of the
// write capability.
func TestMatch_LegacyConcreteNoWidening(t *testing.T) {
	writeGrants := []PermissionEntry{toolGrant("create", scopeProj, grantKindFolder)}
	t.Run("create matches create", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "create", PathScope: scopeProj}
		assertMatch(t, Match(req, writeGrants), writeGrants, 0)
	})
	t.Run("create does not match edit", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: scopeProj}
		assertMatch(t, Match(req, writeGrants), writeGrants, -1)
	})

	readGrants := []PermissionEntry{toolGrant("read", scopeProj, grantKindFolder)}
	t.Run("read matches read", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: scopeProj}
		assertMatch(t, Match(req, readGrants), readGrants, 0)
	})
	t.Run("read does not match grep", func(t *testing.T) {
		req := MatchRequest{Kind: subjectKindTool, Subject: "grep", PathScope: scopeProj}
		assertMatch(t, Match(req, readGrants), readGrants, -1)
	})
}

func TestCapabilityForMember(t *testing.T) {
	members := map[string]string{
		"create":     CapabilityWriteTree,
		"edit":       CapabilityWriteTree,
		"mkdir":      CapabilityWriteTree,
		"read":       CapabilityRead,
		"grep":       CapabilityRead,
		"glob":       CapabilityRead,
		"list":       CapabilityRead,
		"tree":       CapabilityRead,
		"file_count": CapabilityRead,
	}
	for member, want := range members {
		t.Run(member, func(t *testing.T) {
			got, ok := CapabilityForMember(member)
			if !ok || got != want {
				t.Fatalf("CapabilityForMember(%q) = (%q, %v), want (%q, true)", member, got, ok, want)
			}
		})
	}
	for _, notMember := range []string{CapabilityWrite, CapabilityWriteTree, CapabilityRead, "move", "delete", "vcs_commit", "read_file", ""} {
		t.Run("non-member/"+notMember, func(t *testing.T) {
			if got, ok := CapabilityForMember(notMember); ok || got != "" {
				t.Fatalf("CapabilityForMember(%q) = (%q, %v), want (\"\", false)", notMember, got, ok)
			}
		})
	}
}

func TestCapabilityForMemberDeterministic(t *testing.T) {
	for _, member := range []string{"create", "edit", "mkdir"} {
		for i := 0; i < 1000; i++ {
			got, ok := CapabilityForMember(member)
			if !ok || got != CapabilityWriteTree {
				t.Fatalf("CapabilityForMember(%q) = (%q, %v) on call %d, want (%q, true) every call", member, got, ok, i, CapabilityWriteTree)
			}
		}
	}
}

// assertCapabilityMembers pins the exact reserved member contract for a
// capability independently of the matcher's source-of-truth table:
// CapabilityMembers(capability) must return exactly want, compared as a set.
// The expectation is hand-written by the caller — never derived from
// CapabilityMembers — so a dropped, added, or wrong member is observable rather
// than mirrored by the test.
func assertCapabilityMembers(t *testing.T, capability string, want []string) {
	t.Helper()
	got, ok := CapabilityMembers(capability)
	if !ok {
		t.Fatalf("CapabilityMembers(%q) ok = false, want true", capability)
	}
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	if len(gotSorted) != len(wantSorted) {
		t.Fatalf("CapabilityMembers(%q) = %v, want exactly %v", capability, got, want)
	}
	for i := range wantSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Fatalf("CapabilityMembers(%q) = %v, want exactly %v", capability, got, want)
		}
	}
}

func TestAuditSubjectMatches(t *testing.T) {
	tests := []struct {
		name          string
		kind          string
		reqSubject    string
		reqTokens     []string
		storedSubject string
		want          bool
	}{
		{
			name: "direct exact tokens", kind: subjectKindDirect,
			reqSubject: "git status", reqTokens: []string{"git", "status"},
			storedSubject: "git status", want: true,
		},
		{
			name: "direct wildcard covers a longer command", kind: subjectKindDirect,
			reqSubject: "git log --oneline", reqTokens: []string{"git", "log", "--oneline"},
			storedSubject: "git log :*", want: true,
		},
		{
			name: "direct quoted whitespace argument stays one token", kind: subjectKindDirect,
			reqSubject: `git commit -m "First task"`, reqTokens: []string{"git", "commit", "-m", "First task"},
			storedSubject: `git commit -m "First task"`, want: true,
		},
		{
			name: "direct subject re-split on whitespace does not match", kind: subjectKindDirect,
			reqSubject: `git commit -m "First task"`, reqTokens: []string{"git", "commit", "-m", "First", "task"},
			storedSubject: `git commit -m "First task"`, want: false,
		},
		{
			name: "direct pinned quoted argument differs", kind: subjectKindDirect,
			reqSubject: `git commit -m "Second task"`, reqTokens: []string{"git", "commit", "-m", "Second task"},
			storedSubject: `git commit -m "First task"`, want: false,
		},
		{
			name: "direct wildcard prefix crosses a token boundary", kind: subjectKindDirect,
			reqSubject: "git log --oneline", reqTokens: []string{"git", "log", "--oneline"},
			storedSubject: "git lo :*", want: false,
		},
		{
			name: "direct quoted :* is a literal argument", kind: subjectKindDirect,
			reqSubject: "git log", reqTokens: []string{"git", "log"},
			storedSubject: `git ":*"`, want: false,
		},
		{
			name: "direct with unknown tokens never matches", kind: subjectKindDirect,
			reqSubject: "git status", reqTokens: nil,
			storedSubject: "git :*", want: false,
		},
		{
			name: "literal byte-equal", kind: subjectKindLiteral,
			reqSubject: `sh -c "echo hi"`, storedSubject: `sh -c "echo hi"`, want: true,
		},
		{
			name: "literal different command", kind: subjectKindLiteral,
			reqSubject: `sh -c "echo hi"`, storedSubject: `sh -c "echo bye"`, want: false,
		},
		{
			name: "tool exact registered name", kind: subjectKindTool,
			reqSubject: "vcs_commit", storedSubject: "vcs_commit", want: true,
		},
		{
			name: "tool capability grant covers a narrower subject", kind: subjectKindTool,
			reqSubject: "edit", storedSubject: CapabilityWrite, want: true,
		},
		{
			name: "tool capability grant does not cover a read member", kind: subjectKindTool,
			reqSubject: "grep", storedSubject: CapabilityWrite, want: false,
		},
		{
			name: "unrecognized kind never matches", kind: "bogus",
			reqSubject: "anything", storedSubject: "anything", want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AuditSubjectMatches(tt.kind, tt.reqSubject, tt.reqTokens, nil, false, tt.storedSubject); got != tt.want {
				t.Fatalf("AuditSubjectMatches(%q, %q, %v, %q) = %v, want %v",
					tt.kind, tt.reqSubject, tt.reqTokens, tt.storedSubject, got, tt.want)
			}
			req := MatchRequest{Kind: tt.kind, Subject: tt.reqSubject, SubjectTokens: tt.reqTokens, PathScope: scopeProj}
			grants := []PermissionEntry{{
				Kind: tt.kind, Subject: tt.storedSubject, PathScope: scopeProj, GrantKind: grantKindFolder,
			}}
			if live := Match(req, grants).Matched; live != tt.want {
				t.Fatalf("live Match at an equal scope = %v, want %v — the audit helper no longer follows the live rule", live, tt.want)
			}
		})
	}
}

// assertMatch checks a MatchResult against the expected outcome. wantIdx >= 0
// requires a real-grant match equal to grants[wantIdx] with OutcomeSource
// "grant"; wantIdx < 0 requires the zero-value no-match.
func assertMatch(t *testing.T, got MatchResult, grants []PermissionEntry, wantIdx int) {
	t.Helper()
	if wantIdx < 0 {
		if got.Matched || got.Grant != nil || got.OutcomeSource != "" {
			t.Fatalf("Match() = %+v, want no-match (Matched=false, Grant=nil, OutcomeSource=\"\")", got)
		}
		return
	}
	if !got.Matched {
		t.Fatalf("Match() = no match, want match at grant %d", wantIdx)
	}
	if got.OutcomeSource != outcomeSourceGrant {
		t.Fatalf("Match() OutcomeSource = %q, want %q", got.OutcomeSource, outcomeSourceGrant)
	}
	if got.Grant == nil {
		t.Fatalf("Match() matched but Grant is nil")
	}
	if want := grants[wantIdx]; *got.Grant != want {
		t.Fatalf("Match() Grant = %+v, want %+v", *got.Grant, want)
	}
}

func TestMatch_HostilePlusOptionShellStaysLiteralAndUnmatchedByDirectGrants(t *testing.T) {
	const hostile = `bash +O extglob -c 'rm -rf /'`

	norm, err := NormalizeDirectStage(hostile, StageSolo)
	if err != nil {
		t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", hostile, err)
	}
	if norm.Route != RouteLiteral || norm.Reason != ReasonWrapperCommand {
		t.Fatalf("NormalizeDirectStage(%q) = route %v reason %q, want the wrapper literal route", hostile, norm.Route, norm.Reason)
	}

	split, err := SplitCommand(hostile)
	if err != nil {
		t.Fatalf("SplitCommand(%q) error = %v, want nil", hostile, err)
	}
	canonical, err := CanonicalLiteralForm(split.LiteralInput)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	req := MatchRequest{Kind: subjectKindLiteral, Subject: canonical, PathScope: scopeProj}
	for _, subject := range []string{"bash :*", "bash +O :*"} {
		t.Run(subject, func(t *testing.T) {
			grants := []PermissionEntry{directGrant(subject, scopeProj, grantKindFolder)}
			if got := Match(req, grants); got.Matched {
				t.Fatalf("direct grant %q matched the literal request %q; direct and literal subjects must stay kind-isolated", subject, canonical)
			}
		})
	}
}

func TestMatch_ScriptInvocationAndExecutableSubjectsStayDisjoint(t *testing.T) {
	tests := []struct {
		name    string
		command string
		grant   string
	}{
		{name: "bash grant does not cover the executable form", command: "./foo.sh x", grant: "bash foo.sh :*"},
		{name: "executable grant does not cover the bash form", command: "bash foo.sh x", grant: "./foo.sh :*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			split, err := SplitCommand(tt.command)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", tt.command, err)
			}
			if len(split.Stages) != 1 {
				t.Fatalf("SplitCommand(%q) = %d stages, want one direct stage", tt.command, len(split.Stages))
			}
			tokens := split.Stages[0].Tokens
			req := MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(tokens, " "), SubjectTokens: tokens, PathScope: scopeProj}
			grants := []PermissionEntry{directGrant(tt.grant, scopeProj, grantKindFolder)}
			if got := Match(req, grants); got.Matched {
				t.Fatalf("grant %q matched %v; `bash <script>` and `./<script>` are two different executions", tt.grant, tokens)
			}
		})
	}
}

func TestMatch_BareGrantDoesNotAuthorizeAnAssignmentBearingCommand(t *testing.T) {
	grants := []PermissionEntry{{
		Kind: subjectKindDirect, Subject: "hg status", PathScope: scopeProj, GrantKind: grantKindFolder,
	}}
	bare := MatchRequest{
		Kind: subjectKindDirect, Subject: "hg status",
		SubjectTokens: []string{"hg", "status"}, PathScope: scopeProj,
	}
	if !Match(bare, grants).Matched {
		t.Fatal("the bare command stopped matching its own grant")
	}
	for _, assignment := range adversarialAssignments {
		t.Run(assignment, func(t *testing.T) {
			req := bare
			req.Assignments = []string{assignment}
			subject, err := DirectRequestSubject(req.SubjectTokens, req.Assignments, false)
			if err != nil {
				t.Fatalf("DirectRequestSubject: %v", err)
			}
			req.Subject = subject
			if Match(req, grants).Matched {
				t.Fatalf("%q ran under the bare `hg status` grant", assignment)
			}
		})
	}
}

func TestMatch_AssignmentGrantAuthorizesOnlyItsOrderedSet(t *testing.T) {
	stored, err := EncodeDirectEnvSubject([]string{"A=1", "B=2"}, false, "hg status")
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	grants := []PermissionEntry{{
		Kind: subjectKindDirect, Subject: stored, PathScope: scopeProj, GrantKind: grantKindFolder,
	}}
	tests := []struct {
		name        string
		assignments []string
		want        bool
	}{
		{name: "same ordered set", assignments: []string{"A=1", "B=2"}, want: true},
		{name: "different value", assignments: []string{"A=1", "B=9"}},
		{name: "extra assignment", assignments: []string{"A=1", "B=2", "C=3"}},
		{name: "removed assignment", assignments: []string{"A=1"}},
		{name: "reordered set", assignments: []string{"B=2", "A=1"}},
		{name: "no assignments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, err := DirectRequestSubject([]string{"hg", "status"}, tt.assignments, false)
			if err != nil {
				t.Fatalf("DirectRequestSubject: %v", err)
			}
			req := MatchRequest{
				Kind: subjectKindDirect, Subject: subject, SubjectTokens: []string{"hg", "status"},
				Assignments: tt.assignments, PathScope: scopeProj,
			}
			if got := Match(req, grants).Matched; got != tt.want {
				t.Fatalf("Match with %v = %v, want %v", tt.assignments, got, tt.want)
			}
		})
	}
}

func TestMatch_ClearEnvironmentGrantAuthorizesOnlyItsOwnState(t *testing.T) {
	assignments := []string{"PATH=/usr/bin", "HGPLAIN=1"}
	clearGrant, err := EncodeDirectEnvSubject(assignments, true, "hg :*")
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	envGrant, err := EncodeDirectEnvSubject(assignments, false, "hg :*")
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	request := func(t *testing.T, tokens, assignments []string, clear bool) MatchRequest {
		t.Helper()
		subject, err := DirectRequestSubject(tokens, assignments, clear)
		if err != nil {
			t.Fatalf("DirectRequestSubject: %v", err)
		}
		return MatchRequest{
			Kind: subjectKindDirect, Subject: subject, SubjectTokens: tokens,
			Assignments: assignments, ClearEnvironment: clear, PathScope: scopeProj,
		}
	}
	tests := []struct {
		name    string
		stored  string
		tokens  []string
		assigns []string
		clear   bool
		want    bool
	}{
		{name: "clear grant covers its own request", stored: clearGrant, tokens: []string{"hg", "status"}, assigns: assignments, clear: true, want: true},
		{name: "clear grant widens the command only", stored: clearGrant, tokens: []string{"hg", "log", "-l", "1"}, assigns: assignments, clear: true, want: true},
		{name: "clear grant refuses an inherited environment", stored: clearGrant, tokens: []string{"hg", "status"}, assigns: assignments},
		{name: "clear grant refuses a changed assignment", stored: clearGrant, tokens: []string{"hg", "status"}, assigns: []string{"PATH=/usr/bin", "HGPLAIN=2"}, clear: true},
		{name: "clear grant refuses a reordered set", stored: clearGrant, tokens: []string{"hg", "status"}, assigns: []string{"HGPLAIN=1", "PATH=/usr/bin"}, clear: true},
		{name: "v1 grant covers its own request", stored: envGrant, tokens: []string{"hg", "status"}, assigns: assignments, want: true},
		{name: "v1 grant refuses a clear request", stored: envGrant, tokens: []string{"hg", "status"}, assigns: assignments, clear: true},
		{name: "legacy grant refuses a clear request", stored: "hg :*", tokens: []string{"hg", "status"}, assigns: assignments, clear: true},
		{name: "legacy grant still covers the bare command", stored: "hg :*", tokens: []string{"hg", "status"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grants := []PermissionEntry{{
				Kind: subjectKindDirect, Subject: tt.stored, PathScope: scopeProj, GrantKind: grantKindFolder,
			}}
			if got := Match(request(t, tt.tokens, tt.assigns, tt.clear), grants).Matched; got != tt.want {
				t.Fatalf("Match = %v, want %v", got, tt.want)
			}
		})
	}

	legacy := []PermissionEntry{{
		Kind: subjectKindDirect, Subject: "hg :*", PathScope: scopeProj, GrantKind: grantKindFolder,
	}}
	assignmentFreeClear := MatchRequest{
		Kind: subjectKindDirect, Subject: "hg status", SubjectTokens: []string{"hg", "status"},
		ClearEnvironment: true, PathScope: scopeProj,
	}
	if Match(assignmentFreeClear, legacy).Matched {
		t.Fatal("a legacy grant authorized an assignment-free clear request")
	}
}

func TestAuditSubjectMatches_ClearRequestNeverMatchesV1OrLegacy(t *testing.T) {
	assignments := []string{"PATH=/usr/bin"}
	clearGrant, err := EncodeDirectEnvSubject(assignments, true, "hg :*")
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	envGrant, err := EncodeDirectEnvSubject(assignments, false, "hg :*")
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject: %v", err)
	}
	tokens := []string{"hg", "status"}
	const command = "hg status"
	for _, stored := range []string{envGrant, "hg :*", "hg status"} {
		if AuditSubjectMatches(subjectKindDirect, command, tokens, assignments, true, stored) {
			t.Fatalf("a clear request audit-matched the prior grant %q", stored)
		}
	}
	if !AuditSubjectMatches(subjectKindDirect, command, tokens, assignments, true, clearGrant) {
		t.Fatal("a clear request stopped audit-matching its own grant")
	}
	if AuditSubjectMatches(subjectKindDirect, command, tokens, assignments, false, clearGrant) {
		t.Fatal("an inherited-environment request audit-matched a clear grant")
	}
}

// replayFixture reproduces the recorded prep-run window: a scratch directory whose name is
// minted per run, a repository below it, and the run folder every one of those commands was
// issued from.
type replayFixture struct {
	home      string
	tmp       string
	run       string
	repo      string
	runFolder string
}

func newReplayFixture(t *testing.T) replayFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	f := replayFixture{
		home:      filepath.Join(root, "home", "user"),
		tmp:       filepath.Join(root, "tmp"),
		runFolder: filepath.Join(root, "work", "codemeld"),
	}
	f.run = filepath.Join(f.tmp, "codemeld-g2430-audit.RtAY58")
	f.repo = filepath.Join(f.run, "subprobe", "sub")
	for _, dir := range []string{f.home, f.repo, filepath.Join(f.run, "bin"), f.runFolder} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for _, file := range []string{
		filepath.Join(f.run, "id-ssh"),
		filepath.Join(f.run, "bin", "git"),
		filepath.Join(f.run, "bin", "ssh"),
	} {
		if err := os.WriteFile(file, nil, 0o644); err != nil {
			t.Fatalf("write %s: %v", file, err)
		}
	}
	return f
}

// TestMatch_FourGrantsCoverTheRecordedTempDirectoryWindow replays the eight direct commands
// that prompted in the 2026-08-26 prep run. Every grant carries the same run-folder scope as
// the requests, so a miss is a command-subject miss rather than the independent path-scope
// check refusing first.
func TestMatch_FourGrantsCoverTheRecordedTempDirectoryWindow(t *testing.T) {
	f := newReplayFixture(t)

	mktemp := []string{"mktemp", "-d", filepath.Join(f.tmp, "codemeld-g2430-audit.XXXXXX")}
	gitInit := []string{"git", "init", f.repo}
	grants := []PermissionEntry{
		directGrant(ExactSubject(mktemp[0], mktemp[1:]), f.runFolder, grantKindSession),
		directGrant(mustEncodeUnder(t, gitInit, 2, f.tmp, false), f.runFolder, grantKindSession),
		directGrant(mustEncodeUnder(t, []string{"chmod", "+x", filepath.Join(f.run, "id-ssh")}, 2, f.tmp, false), f.runFolder, grantKindSession),
		directGrant(mustEncodeUnder(t, []string{"git", "-C", f.repo, "add", "a"}, 2, f.tmp, true), f.runFolder, grantKindSession),
	}

	recorded := [][]string{
		mktemp,
		gitInit,
		{"chmod", "+x", filepath.Join(f.run, "id-ssh")},
		{"chmod", "+x", filepath.Join(f.run, "bin", "git")},
		{"chmod", "+x", filepath.Join(f.run, "bin", "ssh")},
		{"git", "-C", f.repo, "add", "a"},
		{"git", "-C", f.repo, "commit", "-m", "init"},
		{"git", "-C", f.repo, "rev-parse", "HEAD"},
	}
	if len(recorded) != 8 {
		t.Fatalf("replay covers %d commands, want the 8 recorded ones", len(recorded))
	}
	for _, tokens := range recorded {
		req := MatchRequest{
			Kind:          subjectKindDirect,
			Subject:       ExactSubject(tokens[0], tokens[1:]),
			SubjectTokens: tokens,
			PathScope:     f.runFolder,
		}
		if !Match(req, grants).Matched {
			t.Errorf("recorded command %v still prompts under the four grants", tokens)
		}
	}

	outside := []struct {
		name   string
		tokens []string
	}{
		{"chmod inside home", []string{"chmod", "+x", filepath.Join(f.home, "authorized_keys")}},
		{"chmod in the run folder", []string{"chmod", "+x", f.runFolder}},
		{"git -C outside the boundary", []string{"git", "-C", f.runFolder, "add", "a"}},
		{"a different scratch name for mktemp", []string{"mktemp", "-d", filepath.Join(f.tmp, "other.XXXXXX")}},
	}
	if err := os.WriteFile(filepath.Join(f.home, "authorized_keys"), nil, 0o644); err != nil {
		t.Fatalf("write home key: %v", err)
	}
	for _, c := range outside {
		t.Run(c.name, func(t *testing.T) {
			req := MatchRequest{
				Kind:          subjectKindDirect,
				Subject:       ExactSubject(c.tokens[0], c.tokens[1:]),
				SubjectTokens: c.tokens,
				PathScope:     f.runFolder,
			}
			if Match(req, grants).Matched {
				t.Fatalf("%v matched the four grants", c.tokens)
			}
		})
	}

	elsewhere := MatchRequest{
		Kind:          subjectKindDirect,
		Subject:       ExactSubject("chmod", []string{"+x", filepath.Join(f.run, "id-ssh")}),
		SubjectTokens: []string{"chmod", "+x", filepath.Join(f.run, "id-ssh")},
		PathScope:     filepath.Dir(f.runFolder),
	}
	if Match(elsewhere, grants).Matched {
		t.Error("a containment grant matched outside its stored run-folder scope")
	}
}

// TestMatch_ContainmentIsDecidedWhenAuthorizationIsEvaluated documents an accepted gap.
// Containment is checked against the filesystem as it stands when the decision is made; the
// request tokens dispatch receives are the original lexical ones, and this task neither
// canonicalizes them nor rechecks identity before the program runs. A replacement after a
// successful match therefore fails only the next match — the earlier decision is not revoked,
// and nothing here confines execution.
func TestMatch_ContainmentIsDecidedWhenAuthorizationIsEvaluated(t *testing.T) {
	f := newReplayFixture(t)
	via := filepath.Join(f.run, "link")
	if err := os.Symlink(filepath.Join(f.run, "bin"), via); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	tokens := []string{"chmod", "+x", filepath.Join(via, "git")}
	req := MatchRequest{
		Kind:          subjectKindDirect,
		Subject:       ExactSubject(tokens[0], tokens[1:]),
		SubjectTokens: tokens,
		PathScope:     f.runFolder,
	}
	grants := []PermissionEntry{
		directGrant(mustEncodeUnder(t, tokens, 2, f.tmp, false), f.runFolder, grantKindSession),
	}
	if !Match(req, grants).Matched {
		t.Fatal("the resolved request path is not authorized before the swap")
	}

	outside := filepath.Join(filepath.Dir(f.tmp), "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "git"), nil, 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Remove(via); err != nil {
		t.Fatalf("remove link: %v", err)
	}
	if err := os.Symlink(outside, via); err != nil {
		t.Fatalf("re-point link: %v", err)
	}

	if Match(req, grants).Matched {
		t.Fatal("a later match still authorized the request after its ancestor was replaced")
	}
	if !slices.Equal(req.SubjectTokens, tokens) {
		t.Fatalf("SubjectTokens = %v, want the original lexical tokens %v", req.SubjectTokens, tokens)
	}
}
