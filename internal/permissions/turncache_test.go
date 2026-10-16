// Tests for the turn-scoped approval cache: worked example, reset, deny caching, SubjectTokens key-exclusion, and zero-value usability.
package permissions

import "testing"

// TestTurnCache_WorkedExample follows §Reserved Values "Turn-scoped approval
// cache": read_file -> edit -> bash are each approved "once", then a transient
// retry of the same bash hits the cache and proceeds silently with no second
// prompt.
func TestTurnCache_WorkedExample(t *testing.T) {
	c := NewTurnCache()

	readReq := MatchRequest{Kind: subjectKindTool, Subject: "read_file", PathScope: "/work/pkg/foo"}
	editReq := MatchRequest{Kind: subjectKindTool, Subject: "edit", PathScope: "/work/pkg/foo"}
	bashReq := MatchRequest{Kind: subjectKindTool, Subject: "bash", PathScope: "/work"}

	// Each subject is a miss the first time it is seen this turn.
	for _, req := range []MatchRequest{readReq, editReq, bashReq} {
		if _, hit := c.Lookup(req); hit {
			t.Fatalf("Lookup(%+v) = hit before Record, want miss", req)
		}
	}

	c.Record(readReq, "once")
	c.Record(editReq, "once")
	c.Record(bashReq, "once")

	// The retried bash call (identical kind/subject/path scope) hits silently.
	got, hit := c.Lookup(bashReq)
	if !hit {
		t.Fatalf("Lookup(retry bash) = miss, want hit")
	}
	if got != "once" {
		t.Fatalf("Lookup(retry bash) outcome = %q, want %q", got, "once")
	}

	// A subject that was never approved still misses within the same turn.
	unseen := MatchRequest{Kind: subjectKindTool, Subject: "write_file", PathScope: "/work"}
	if _, hit := c.Lookup(unseen); hit {
		t.Fatalf("Lookup(unseen subject) = hit, want miss")
	}
}

// TestTurnCache_ResetClears confirms Reset empties the cache so the next turn
// starts fresh, and that the cache is reusable afterward.
func TestTurnCache_ResetClears(t *testing.T) {
	c := NewTurnCache()
	req := MatchRequest{Kind: subjectKindTool, Subject: "bash", PathScope: "/work"}
	c.Record(req, "once")

	if _, hit := c.Lookup(req); !hit {
		t.Fatalf("Lookup before Reset = miss, want hit")
	}

	c.Reset()

	if _, hit := c.Lookup(req); hit {
		t.Fatalf("Lookup after Reset = hit, want miss (new turn starts fresh)")
	}

	c.Record(req, "deny")
	if got, hit := c.Lookup(req); !hit || got != "deny" {
		t.Fatalf("Lookup after Reset+Record = (%q, %v), want (%q, true)", got, hit, "deny")
	}
}

// TestTurnCache_CachesDenyOutcomes confirms a deny is cached as readily as an
// allow, so a denied retry within the same turn short-circuits instead of
// re-prompting.
func TestTurnCache_CachesDenyOutcomes(t *testing.T) {
	c := NewTurnCache()
	req := MatchRequest{Kind: subjectKindDirect, Subject: "rm", SubjectTokens: []string{"rm", "-rf", "/"}, PathScope: "/work"}

	c.Record(req, "deny")

	got, hit := c.Lookup(req)
	if !hit {
		t.Fatalf("Lookup(denied subject) = miss, want hit")
	}
	if got != "deny" {
		t.Fatalf("Lookup(denied subject) outcome = %q, want %q", got, "deny")
	}
}

// TestTurnCache_KeyIgnoresSubjectTokens confirms SubjectTokens is excluded from
// the key: two direct checks sharing kind/subject/path scope but differing only
// in their token slice resolve to the same entry, while a differing kind,
// subject, or path scope misses.
func TestTurnCache_KeyIgnoresSubjectTokens(t *testing.T) {
	c := NewTurnCache()
	recorded := MatchRequest{Kind: subjectKindDirect, Subject: "go", SubjectTokens: []string{"go", "test", "./..."}, PathScope: "/work"}
	c.Record(recorded, "once")

	probe := MatchRequest{Kind: subjectKindDirect, Subject: "go", SubjectTokens: []string{"go", "build"}, PathScope: "/work"}
	got, hit := c.Lookup(probe)
	if !hit {
		t.Fatalf("Lookup with differing SubjectTokens = miss, want hit (tokens must not be in the key)")
	}
	if got != "once" {
		t.Fatalf("Lookup with differing SubjectTokens outcome = %q, want %q", got, "once")
	}

	// A differing key component, by contrast, must miss.
	misses := []struct {
		name string
		req  MatchRequest
	}{
		{"different kind", MatchRequest{Kind: subjectKindLiteral, Subject: "go", PathScope: "/work"}},
		{"different subject", MatchRequest{Kind: subjectKindDirect, Subject: "gofmt", PathScope: "/work"}},
		{"different path scope", MatchRequest{Kind: subjectKindDirect, Subject: "go", PathScope: "/work/sub"}},
	}
	for _, m := range misses {
		t.Run(m.name, func(t *testing.T) {
			if _, hit := c.Lookup(m.req); hit {
				t.Fatalf("Lookup(%+v) = hit, want miss (%s)", m.req, m.name)
			}
		})
	}
}

func TestTurnCache_HostRequestsKeyOnCanonicalHost(t *testing.T) {
	c := NewTurnCache()
	recorded := hostReq("web_search", "docs.example.com")

	if _, hit := c.Lookup(recorded); hit {
		t.Fatalf("Lookup(host) = hit before Record, want miss")
	}

	c.Record(recorded, "once")

	got, hit := c.Lookup(hostReq("web_search", "docs.example.com"))
	if !hit {
		t.Fatalf("Lookup(identical host request) = miss, want hit")
	}
	if got != "once" {
		t.Fatalf("Lookup(identical host request) outcome = %q, want %q", got, "once")
	}

	misses := []struct {
		name string
		req  MatchRequest
	}{
		{"sibling host under the same registrable domain", hostReq("web_search", "api.example.com")},
		{"registrable domain itself", hostReq("web_search", "example.com")},
		{"suffix-extended host", hostReq("web_search", "docs.example.com.evil.test")},
		{"other web tool, same host", hostReq("web_fetch", "docs.example.com")},
	}
	for _, m := range misses {
		t.Run(m.name, func(t *testing.T) {
			if _, hit := c.Lookup(m.req); hit {
				t.Fatalf("Lookup(%+v) = hit, want miss (%s)", m.req, m.name)
			}
		})
	}
}

func TestTurnCache_HostKeyIsolatedFromOtherKinds(t *testing.T) {
	c := NewTurnCache()

	c.Record(hostReq("web_fetch", "docs.example.com"), "once")
	if _, hit := c.Lookup(MatchRequest{Kind: subjectKindTool, Subject: "web_fetch"}); hit {
		t.Fatalf("a tool request reused a host decision, want miss")
	}

	c.Record(MatchRequest{Kind: subjectKindTool, Subject: "web_search", PathScope: "/work"}, "once")
	if _, hit := c.Lookup(hostReq("web_search", "docs.example.com")); hit {
		t.Fatalf("a host request reused a tool decision, want miss")
	}
}

func TestTurnCache_HostKeyIgnoresPathScope(t *testing.T) {
	c := NewTurnCache()
	recorded := hostReq("web_search", "docs.example.com")
	recorded.PathScope = "/work"
	c.Record(recorded, "once")

	probe := hostReq("web_search", "docs.example.com")
	probe.PathScope = "/work/sub"
	if got, hit := c.Lookup(probe); !hit || got != "once" {
		t.Fatalf("Lookup(host with differing path scope) = (%q, %v), want (%q, true)", got, hit, "once")
	}
}

// TestTurnCache_ZeroValueUsable confirms a zero-value TurnCache (e.g. embedded
// by value in an orchestrator struct) records and looks up without a constructor.
func TestTurnCache_ZeroValueUsable(t *testing.T) {
	var c TurnCache
	req := MatchRequest{Kind: subjectKindTool, Subject: "bash", PathScope: "/work"}

	if _, hit := c.Lookup(req); hit {
		t.Fatalf("Lookup on zero-value cache = hit, want miss")
	}

	c.Record(req, "once")
	if got, hit := c.Lookup(req); !hit || got != "once" {
		t.Fatalf("zero-value Record+Lookup = (%q, %v), want (%q, true)", got, hit, "once")
	}
}
