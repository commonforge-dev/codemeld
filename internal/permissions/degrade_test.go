// Tests for DegradeGrant.
package permissions

import "testing"

func TestDegradeGrant_FolderPreservesPathScope(t *testing.T) {
	orig := toolGrant("vcs_commit", scopeProj, grantKindFolder)

	got := DegradeGrant(orig, scopeProj)

	want := PermissionEntry{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj, GrantKind: grantKindSession}
	if got != want {
		t.Fatalf("DegradeGrant(folder) = %+v, want %+v", got, want)
	}
	// requestPath is ignored for a folder grant: its PathScope already is the
	// request path, so a different requestPath must not change it.
	if other := DegradeGrant(orig, scopeOther); other.PathScope != scopeProj {
		t.Fatalf("folder PathScope = %q, want it preserved as %q regardless of requestPath", other.PathScope, scopeProj)
	}
}

func TestDegradeGrant_GlobalRewritesToRequestPath(t *testing.T) {
	orig := toolGrant("vcs_commit", allPathsScope, grantKindGlobal)

	got := DegradeGrant(orig, scopeProj)

	want := PermissionEntry{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: scopeProj, GrantKind: grantKindSession}
	if got != want {
		t.Fatalf("DegradeGrant(global) = %+v, want %+v", got, want)
	}
	// A degraded global grant must never keep the all-paths sentinel in memory.
	if got.PathScope == allPathsScope {
		t.Fatalf("degraded global PathScope still %q; it must be rewritten to the request path", allPathsScope)
	}
}

func TestDegradeGrant_ProjectHostKeepsCanonicalHostAndTool(t *testing.T) {
	orig := hostGrant("web_fetch", "docs.example.com")

	got := DegradeGrant(orig, scopeProj)

	want := PermissionEntry{Kind: subjectKindTool, Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: grantKindSession}
	if got != want {
		t.Fatalf("DegradeGrant(project host) = %+v, want %+v", got, want)
	}
	if got.PathScope != "" {
		t.Fatalf("degraded host grant gained PathScope %q; a host grant has no path scope", got.PathScope)
	}
	if got.HostScope == allPathsScope {
		t.Fatalf("degraded host grant HostScope is %q; it must stay one exact host", allPathsScope)
	}
	if other := DegradeGrant(orig, scopeOther); other.PathScope != "" || other.HostScope != "docs.example.com" {
		t.Fatalf("DegradeGrant(project host, other requestPath) = %+v, want the host preserved and no path scope", other)
	}
}

func TestDegradeGrant_DegradedProjectHostStillAuthorizesSameHostAndTool(t *testing.T) {
	degraded := DegradeGrant(hostGrant("web_fetch", "docs.example.com"), scopeProj)
	grants := []PermissionEntry{degraded}

	req := MatchRequest{Kind: subjectKindHost, Subject: "web_fetch", Host: "docs.example.com"}
	if res := Match(req, grants); !res.Matched {
		t.Fatalf("degraded host grant did not authorize its own host/tool, want match")
	}

	rejected := []struct {
		name    string
		subject string
		host    string
	}{
		{"sibling host", "web_fetch", "evil.example.com"},
		{"parent host", "web_fetch", "example.com"},
		{"other web tool", "web_search", "docs.example.com"},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindHost, Subject: tc.subject, Host: tc.host}
			if res := Match(req, grants); res.Matched {
				t.Fatalf("degraded host grant wrongly authorized %s (%s, %s)", tc.name, tc.subject, tc.host)
			}
		})
	}
}

func TestDegradeGrant_PreservesKindSubjectAndLiteralHash(t *testing.T) {
	hash := ComputeArgumentHash(`sh -c "echo hi"`)
	orig := PermissionEntry{
		Kind:         subjectKindLiteral,
		Subject:      `sh -c "echo hi"`,
		PathScope:    allPathsScope,
		GrantKind:    grantKindGlobal,
		ArgumentHash: hash,
	}

	got := DegradeGrant(orig, scopeProj)

	if got.Kind != subjectKindLiteral || got.Subject != orig.Subject || got.ArgumentHash != hash {
		t.Fatalf("Kind/Subject/ArgumentHash not preserved: %+v", got)
	}
	if got.GrantKind != grantKindSession || got.PathScope != scopeProj {
		t.Fatalf("rewrite fields wrong: %+v", got)
	}
}

// TestDegradeGrant_DegradedGlobalMatchBoundary asserts the descendant rule the
// rewrite relies on: a degraded global grant rescoped to scopeProj
// authorizes scopeProj and its descendants, but not a sibling, an ancestor, a
// cleaned traversal that escapes the scope, or a string-prefix-only path.
func TestDegradeGrant_DegradedGlobalMatchBoundary(t *testing.T) {
	degraded := DegradeGrant(toolGrant("vcs_commit", allPathsScope, grantKindGlobal), scopeProj)
	grants := []PermissionEntry{degraded}

	authorized := []struct {
		name string
		path string
	}{
		{"exact request path", scopeProj},
		{"descendant", scopeSub},
	}
	for _, tc := range authorized {
		t.Run("authorizes "+tc.name, func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: tc.path}
			if res := Match(req, grants); !res.Matched {
				t.Fatalf("degraded grant did not authorize %s %q, want match", tc.name, tc.path)
			}
		})
	}

	rejected := []struct {
		name string
		path string
	}{
		{"sibling directory", scopeOther},
		{"parent directory", scopeUp},
		{"cleaned traversal escaping scope", scopeProj + "/../secret"},
		{"string-prefix-only non-descendant", scopeProj + "app"},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			req := MatchRequest{Kind: subjectKindTool, Subject: "vcs_commit", PathScope: tc.path}
			if res := Match(req, grants); res.Matched {
				t.Fatalf("degraded grant wrongly authorized %s %q, want no match", tc.name, tc.path)
			}
		})
	}
}
