// Tests for permission entry parsing, validation, hashing, and YAML emission.
package permissions

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func literalHash(subject string) string { return ComputeArgumentHash(subject) }

func TestParseEntry_Valid(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want PermissionEntry
	}{
		{
			name: "direct folder",
			raw: map[string]any{
				"kind":       "direct",
				"subject":    "ls",
				"path_scope": "/home/u/proj",
				"grant_kind": "folder",
			},
			want: PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "/home/u/proj", GrantKind: "folder"},
		},
		{
			name: "tool global",
			raw: map[string]any{
				"kind":       "tool",
				"subject":    "vcs_commit",
				"path_scope": "*",
				"grant_kind": "global",
			},
			want: PermissionEntry{Kind: "tool", Subject: "vcs_commit", PathScope: "*", GrantKind: "global"},
		},
		{
			name: "literal folder with matching argument_hash",
			raw: map[string]any{
				"kind":          "literal",
				"subject":       "rm -rf build",
				"path_scope":    "/home/u/proj",
				"grant_kind":    "folder",
				"argument_hash": literalHash("rm -rf build"),
			},
			want: PermissionEntry{Kind: "literal", Subject: "rm -rf build", PathScope: "/home/u/proj", GrantKind: "folder", ArgumentHash: literalHash("rm -rf build")},
		},
		{
			name: "tool capability write folder",
			raw: map[string]any{
				"kind":       "tool",
				"subject":    CapabilityWrite,
				"path_scope": "/home/u/proj",
				"grant_kind": "folder",
			},
			want: PermissionEntry{Kind: "tool", Subject: CapabilityWrite, PathScope: "/home/u/proj", GrantKind: "folder"},
		},
		{
			name: "tool capability read-family global",
			raw: map[string]any{
				"kind":       "tool",
				"subject":    CapabilityRead,
				"path_scope": "*",
				"grant_kind": "global",
			},
			want: PermissionEntry{Kind: "tool", Subject: CapabilityRead, PathScope: "*", GrantKind: "global"},
		},
		{
			name: "tool web_search project host",
			raw: map[string]any{
				"kind":       "tool",
				"subject":    "web_search",
				"host_scope": "mcp.exa.ai",
				"grant_kind": "project",
			},
			want: PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "mcp.exa.ai", GrantKind: "project"},
		},
		{
			name: "tool web_fetch project host is an IP literal",
			raw: map[string]any{
				"kind":       "tool",
				"subject":    "web_fetch",
				"host_scope": "127.0.0.1",
				"grant_kind": "project",
			},
			want: PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "127.0.0.1", GrantKind: "project"},
		},
		{
			name: "host is lowercased and loses one trailing dot",
			raw: map[string]any{
				"kind":       "tool",
				"subject":    "web_fetch",
				"host_scope": "Docs.Example.COM.",
				"grant_kind": "project",
			},
			want: PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"},
		},
		{
			name: "unicode IDN host is stored as canonical ASCII",
			raw: map[string]any{
				"kind":       "tool",
				"subject":    "web_fetch",
				"host_scope": "bücher.example.com",
				"grant_kind": "project",
			},
			want: PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "xn--bcher-kva.example.com", GrantKind: "project"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEntry(tt.raw, "settings.yaml", 0)
			if err != nil {
				t.Fatalf("ParseEntry() = %v, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("ParseEntry() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseEntry_Rejects(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want string // substring the error must contain
	}{
		{
			name: "unknown key",
			raw: map[string]any{
				"kind": "direct", "subject": "ls", "path_scope": "/home/u/proj", "grant_kind": "folder",
				"expires_at": "never",
			},
			want: "unknown key",
		},
		{
			name: "missing required key",
			raw:  map[string]any{"kind": "direct", "subject": "ls", "grant_kind": "folder"},
			want: "missing required key",
		},
		{
			name: "non-string field value",
			raw:  map[string]any{"kind": "direct", "subject": 7, "path_scope": "/home/u/proj", "grant_kind": "folder"},
			want: "must be a string",
		},
		{
			name: "invalid kind enum",
			raw:  map[string]any{"kind": "wildcard", "subject": "ls", "path_scope": "/home/u/proj", "grant_kind": "folder"},
			want: "kind",
		},
		{
			name: "invalid grant_kind enum",
			raw:  map[string]any{"kind": "direct", "subject": "ls", "path_scope": "/home/u/proj", "grant_kind": "session"},
			want: "grant_kind",
		},
		{
			name: "literal without argument_hash",
			raw:  map[string]any{"kind": "literal", "subject": "rm -rf build", "path_scope": "/home/u/proj", "grant_kind": "folder"},
			want: "requires argument_hash",
		},
		{
			name: "literal with mismatched argument_hash",
			raw: map[string]any{
				"kind": "literal", "subject": "rm -rf build", "path_scope": "/home/u/proj", "grant_kind": "folder",
				"argument_hash": literalHash("rm -rf other"),
			},
			want: "does not match",
		},
		{
			name: "non-literal with forbidden argument_hash",
			raw: map[string]any{
				"kind": "direct", "subject": "ls", "path_scope": "/home/u/proj", "grant_kind": "folder",
				"argument_hash": literalHash("ls"),
			},
			want: "only allowed for literal",
		},
		{
			name: "relative path_scope",
			raw:  map[string]any{"kind": "direct", "subject": "ls", "path_scope": "proj", "grant_kind": "folder"},
			want: "path_scope",
		},
		{
			name: "unclean path_scope",
			raw:  map[string]any{"kind": "direct", "subject": "ls", "path_scope": "/home/u/proj/", "grant_kind": "folder"},
			want: "path_scope",
		},
		{
			name: "star path_scope with folder grant",
			raw:  map[string]any{"kind": "direct", "subject": "ls", "path_scope": "*", "grant_kind": "folder"},
			want: "requires grant_kind global",
		},
		{
			name: "path path_scope with global grant",
			raw:  map[string]any{"kind": "tool", "subject": "vcs_commit", "path_scope": "/home/u/proj", "grant_kind": "global"},
			want: "requires path_scope",
		},
		{
			name: "capability subject write on direct kind",
			raw:  map[string]any{"kind": "direct", "subject": CapabilityWrite, "path_scope": "/home/u/proj", "grant_kind": "folder"},
			want: "reserved capability",
		},
		{
			name: "capability subject read-family on literal kind",
			raw: map[string]any{
				"kind": "literal", "subject": CapabilityRead, "path_scope": "/home/u/proj", "grant_kind": "folder",
				"argument_hash": literalHash(CapabilityRead),
			},
			want: "reserved capability",
		},
		{
			name: "network entry carrying path_scope",
			raw: map[string]any{
				"kind": "tool", "subject": "web_fetch", "host_scope": "example.com",
				"path_scope": "/home/u/proj", "grant_kind": "project",
			},
			want: "must not set path_scope",
		},
		{
			name: "network subject scoped by path instead of host",
			raw:  map[string]any{"kind": "tool", "subject": "web_search", "path_scope": "/home/u/proj", "grant_kind": "folder"},
			want: "must not set path_scope",
		},
		{
			name: "network entry without host_scope",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "grant_kind": "project"},
			want: "requires host_scope",
		},
		{
			name: "wildcard host_scope",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "*", "grant_kind": "project"},
			want: "wildcard host",
		},
		{
			name: "empty host_scope",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "", "grant_kind": "project"},
			want: "host is empty",
		},
		{
			name: "invalid punycode host",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "xn--0.example.com", "grant_kind": "project"},
			want: "host_scope",
		},
		{
			name: "invalid unicode label host",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "exa mple.com", "grant_kind": "project"},
			want: "host_scope",
		},
		{
			name: "empty label host",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "docs..example.com", "grant_kind": "project"},
			want: "host_scope",
		},
		{
			name: "host grant with folder grant_kind",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "example.com", "grant_kind": "folder"},
			want: "requires grant_kind",
		},
		{
			name: "host grant with global grant_kind",
			raw:  map[string]any{"kind": "tool", "subject": "web_search", "host_scope": "mcp.exa.ai", "grant_kind": "global"},
			want: "requires grant_kind",
		},
		{
			name: "host grant with session grant_kind",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "example.com", "grant_kind": "session"},
			want: "requires grant_kind",
		},
		{
			name: "host grant missing grant_kind",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": "example.com"},
			want: "missing required key",
		},
		{
			name: "unsupported tool subject with host_scope",
			raw:  map[string]any{"kind": "tool", "subject": "vcs_commit", "host_scope": "example.com", "grant_kind": "project"},
			want: "valid only for subject web_search or web_fetch",
		},
		{
			name: "capability subject with host_scope",
			raw:  map[string]any{"kind": "tool", "subject": CapabilityRead, "host_scope": "example.com", "grant_kind": "project"},
			want: "valid only for subject web_search or web_fetch",
		},
		{
			name: "path entry carrying host_scope",
			raw: map[string]any{
				"kind": "direct", "subject": "ls", "path_scope": "/home/u/proj", "grant_kind": "folder",
				"host_scope": "example.com",
			},
			want: "valid only for subject web_search or web_fetch",
		},
		{
			name: "network subject on direct kind",
			raw:  map[string]any{"kind": "direct", "subject": "web_fetch", "host_scope": "example.com", "grant_kind": "project"},
			want: "network subject valid only for kind",
		},
		{
			name: "network subject on literal kind",
			raw: map[string]any{
				"kind": "literal", "subject": "web_fetch", "host_scope": "example.com", "grant_kind": "project",
				"argument_hash": literalHash("web_fetch"),
			},
			want: "network subject valid only for kind",
		},
		{
			name: "host grant carrying argument_hash",
			raw: map[string]any{
				"kind": "tool", "subject": "web_fetch", "host_scope": "example.com", "grant_kind": "project",
				"argument_hash": literalHash("web_fetch"),
			},
			want: "only allowed for literal",
		},
		{
			name: "path entry with project grant_kind",
			raw:  map[string]any{"kind": "direct", "subject": "ls", "path_scope": "/home/u/proj", "grant_kind": "project"},
			want: "not one of folder, global",
		},
		{
			name: "non-string host_scope",
			raw:  map[string]any{"kind": "tool", "subject": "web_fetch", "host_scope": 7, "grant_kind": "project"},
			want: "must be a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseEntry(tt.raw, "settings.yaml", 3)
			if err == nil {
				t.Fatalf("ParseEntry() = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.want)
			}
			// errors must carry file path and entry index for callers.
			if !strings.Contains(err.Error(), "settings.yaml") || !strings.Contains(err.Error(), "permissions.3") {
				t.Fatalf("error %q must name file path and permissions index", err.Error())
			}
		})
	}
}

func TestParseEntry_RecanonicalizesLegacyLiteral(t *testing.T) {
	// A grant persisted under the old quote-preserving canonical spelling.
	const oldSubject = `sh -c "echo hi"`
	want, err := CanonicalLiteralForm(oldSubject)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm(%q) = %v", oldSubject, err)
	}
	if want == oldSubject {
		t.Fatalf("test precondition: canonical form unchanged for %q", oldSubject)
	}

	got, err := ParseEntry(map[string]any{
		"kind":          "literal",
		"subject":       oldSubject,
		"path_scope":    "/home/u/proj",
		"grant_kind":    "folder",
		"argument_hash": literalHash(oldSubject),
	}, "settings.yaml", 0)
	if err != nil {
		t.Fatalf("ParseEntry() = %v, want nil", err)
	}
	if got.Subject != want {
		t.Fatalf("Subject = %q, want canonical %q", got.Subject, want)
	}
	if got.ArgumentHash != literalHash(want) {
		t.Fatalf("ArgumentHash = %q, want hash of canonical subject", got.ArgumentHash)
	}

	// A request for the same command, canonicalized as dispatch does, must match.
	req, err := CanonicalLiteralForm(oldSubject)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm(request) = %v", err)
	}
	if !MatchesLiteralSubject(req, got.Subject) {
		t.Fatalf("canonicalized request %q does not match loaded grant %q", req, got.Subject)
	}
}

func TestComputeArgumentHash(t *testing.T) {
	h := ComputeArgumentHash("rm -rf build")
	if len(h) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h))
	}
	if strings.ToLower(h) != h {
		t.Fatalf("hash %q is not lowercase", h)
	}
	for _, r := range h {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("hash %q contains non-hex rune %q", h, r)
		}
	}
	if ComputeArgumentHash("rm -rf build") != h {
		t.Fatalf("hash is not deterministic")
	}
}

func TestDedupKey_UsableAsMapKey(t *testing.T) {
	a := PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "/home/u/proj", GrantKind: "folder"}
	b := PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "/home/u/proj", GrantKind: "folder"}
	c := PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "/home/u/other", GrantKind: "folder"}

	seen := map[DedupKey]int{}
	seen[a.DedupKey()]++
	seen[b.DedupKey()]++ // same identity as a, must collapse
	seen[c.DedupKey()]++

	if len(seen) != 2 {
		t.Fatalf("dedup map has %d distinct keys, want 2", len(seen))
	}
	if seen[a.DedupKey()] != 2 {
		t.Fatalf("a/b did not collapse: count = %d, want 2", seen[a.DedupKey()])
	}
}

func TestDedupKey_HostScopeIsDistinctFromPathScope(t *testing.T) {
	host := PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"}
	sameHost := PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"}
	otherTool := PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "docs.example.com", GrantKind: "project"}
	otherHost := PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "api.example.com", GrantKind: "project"}
	pathTwin := PermissionEntry{Kind: "tool", Subject: "web_fetch", PathScope: "docs.example.com", GrantKind: "project"}

	if host.DedupKey() != sameHost.DedupKey() {
		t.Fatalf("equal host entries produced different keys")
	}
	if host.DedupKey().PathScope != "" {
		t.Fatalf("host identity leaked into PathScope: %+v", host.DedupKey())
	}
	seen := map[DedupKey]int{}
	for _, e := range []PermissionEntry{host, sameHost, otherTool, otherHost, pathTwin} {
		seen[e.DedupKey()]++
	}
	if len(seen) != 4 {
		t.Fatalf("dedup map has %d distinct keys, want 4: %+v", len(seen), seen)
	}
}

func TestMarshalEntry_HostEntryEmitsHostScope(t *testing.T) {
	e := PermissionEntry{Kind: "tool", Subject: "web_fetch", HostScope: "docs.example.com", GrantKind: "project"}
	out, err := MarshalEntry(e)
	if err != nil {
		t.Fatalf("MarshalEntry() = %v, want nil", err)
	}
	const want = "kind: tool\nsubject: web_fetch\nhost_scope: docs.example.com\ngrant_kind: project\n"
	if string(out) != want {
		t.Fatalf("MarshalEntry() =\n%q\nwant\n%q", out, want)
	}
}

func TestEntry_HostEntryRoundTrips(t *testing.T) {
	e := PermissionEntry{Kind: "tool", Subject: "web_search", HostScope: "mcp.exa.ai", GrantKind: "project"}
	out, err := MarshalEntry(e)
	if err != nil {
		t.Fatalf("MarshalEntry() = %v, want nil", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(out, &raw); err != nil {
		t.Fatalf("yaml.Unmarshal round trip error: %v\n%s", err, out)
	}
	got, err := ParseEntry(raw, "settings.yaml", 0)
	if err != nil {
		t.Fatalf("ParseEntry(round-tripped host entry) = %v, want nil", err)
	}
	if got != e {
		t.Fatalf("round trip changed the entry:\n got %+v\nwant %+v", got, e)
	}
}

func TestEntry_UnicodeHostPersistsAsASCII(t *testing.T) {
	got, err := ParseEntry(map[string]any{
		"kind":       "tool",
		"subject":    "web_fetch",
		"host_scope": "BÜCHER.example.com.",
		"grant_kind": "project",
	}, "settings.yaml", 0)
	if err != nil {
		t.Fatalf("ParseEntry() = %v, want nil", err)
	}
	const want = "xn--bcher-kva.example.com"
	if got.HostScope != want {
		t.Fatalf("HostScope = %q, want canonical ASCII %q", got.HostScope, want)
	}
	out, err := MarshalEntry(got)
	if err != nil {
		t.Fatalf("MarshalEntry() = %v, want nil", err)
	}
	if string(out) != "kind: tool\nsubject: web_fetch\nhost_scope: "+want+"\ngrant_kind: project\n" {
		t.Fatalf("MarshalEntry() did not persist the canonical ASCII host:\n%s", out)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(out, &raw); err != nil {
		t.Fatalf("yaml.Unmarshal round trip error: %v\n%s", err, out)
	}
	again, err := ParseEntry(raw, "settings.yaml", 0)
	if err != nil {
		t.Fatalf("ParseEntry(persisted ASCII host) = %v, want nil", err)
	}
	if again != got {
		t.Fatalf("round trip changed the entry:\n got %+v\nwant %+v", again, got)
	}
}

func TestMarshalEntry_PathEntryBytes(t *testing.T) {
	tests := []struct {
		name  string
		entry PermissionEntry
		want  string
	}{
		{
			name:  "direct folder",
			entry: PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "/home/u/proj", GrantKind: "folder"},
			want:  "kind: direct\nsubject: ls\npath_scope: /home/u/proj\ngrant_kind: folder\n",
		},
		{
			name:  "tool folder",
			entry: PermissionEntry{Kind: "tool", Subject: "vcs_commit", PathScope: "/home/u/proj", GrantKind: "folder"},
			want:  "kind: tool\nsubject: vcs_commit\npath_scope: /home/u/proj\ngrant_kind: folder\n",
		},
		{
			name: "literal folder",
			entry: PermissionEntry{
				Kind: "literal", Subject: "rm -rf build", PathScope: "/home/u/proj", GrantKind: "folder",
				ArgumentHash: literalHash("rm -rf build"),
			},
			want: "kind: literal\nsubject: rm -rf build\npath_scope: /home/u/proj\ngrant_kind: folder\nargument_hash: " + literalHash("rm -rf build") + "\n",
		},
		{
			name:  "tool global",
			entry: PermissionEntry{Kind: "tool", Subject: "vcs_commit", PathScope: "*", GrantKind: "global"},
			want:  "kind: tool\nsubject: vcs_commit\npath_scope: \"*\"\ngrant_kind: global\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := MarshalEntry(tt.entry)
			if err != nil {
				t.Fatalf("MarshalEntry() = %v, want nil", err)
			}
			if string(out) != tt.want {
				t.Fatalf("MarshalEntry() =\n%q\nwant\n%q", out, tt.want)
			}
			var raw map[string]any
			if err := yaml.Unmarshal(out, &raw); err != nil {
				t.Fatalf("yaml.Unmarshal round trip error: %v\n%s", err, out)
			}
			got, err := ParseEntry(raw, "settings.yaml", 0)
			if err != nil {
				t.Fatalf("ParseEntry(round-tripped path entry) = %v, want nil", err)
			}
			if got != tt.entry {
				t.Fatalf("round trip changed the entry:\n got %+v\nwant %+v", got, tt.entry)
			}
		})
	}
}

func TestMarshalEntry_StarPathScopeQuoted(t *testing.T) {
	e := PermissionEntry{Kind: "tool", Subject: "vcs_commit", PathScope: "*", GrantKind: "global"}
	out, err := MarshalEntry(e)
	if err != nil {
		t.Fatalf("MarshalEntry() = %v, want nil", err)
	}
	s := string(out)
	if strings.Contains(s, "path_scope: *\n") {
		t.Fatalf("path_scope emitted as bare alias-like scalar:\n%s", s)
	}
	if !strings.Contains(s, `path_scope: '*'`) && !strings.Contains(s, `path_scope: "*"`) {
		t.Fatalf("path_scope not emitted as a quoted scalar:\n%s", s)
	}
}

func TestMarshalEntry_LiteralIncludesHash(t *testing.T) {
	e := PermissionEntry{Kind: "literal", Subject: "rm -rf build", PathScope: "/home/u/proj", GrantKind: "folder", ArgumentHash: literalHash("rm -rf build")}
	out, err := MarshalEntry(e)
	if err != nil {
		t.Fatalf("MarshalEntry() = %v, want nil", err)
	}
	if !strings.Contains(string(out), "argument_hash:") {
		t.Fatalf("literal entry omitted argument_hash:\n%s", out)
	}
}

// TestEntry_CompoundSubjectRoundTrips proves a generalized compound subject
// survives MarshalEntry -> YAML -> ParseEntry unchanged: the `&&` operators and `:*` wildcards round
// trip, argument_hash pins the encoding, and the entry loads (the decoder accepts it).
func TestEntry_CompoundSubjectRoundTrips(t *testing.T) {
	encoded, err := EncodeCompoundSubject(true, []string{"gofmt :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	e := PermissionEntry{Kind: "literal", Subject: encoded, PathScope: "/home/u/proj", GrantKind: "folder", ArgumentHash: literalHash(encoded)}

	out, err := MarshalEntry(e)
	if err != nil {
		t.Fatalf("MarshalEntry() = %v, want nil", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(out, &raw); err != nil {
		t.Fatalf("yaml.Unmarshal round trip error: %v\n%s", err, out)
	}
	got, err := ParseEntry(raw, "settings.yaml", 0)
	if err != nil {
		t.Fatalf("ParseEntry(round-tripped compound) = %v, want nil", err)
	}
	if got != e {
		t.Fatalf("round trip changed the entry:\n got %+v\nwant %+v", got, e)
	}
}

// TestParseEntry_RejectsHostileCompound proves a generalized subject that is well-formed-looking and
// carries a correct argument_hash is still rejected at load when it fails the decoder — here a
// compound that widens a destructive program (invariant 4). A valid hash is not enough: the decoder
// is the fail-closed gate, so a hand-authored hostile widened grant never loads or matches.
func TestParseEntry_RejectsHostileCompound(t *testing.T) {
	hostile := "compound/v1 W gofmt :* && rm :*"
	raw := map[string]any{
		"kind":          "literal",
		"subject":       hostile,
		"path_scope":    "/home/u/proj",
		"grant_kind":    "folder",
		"argument_hash": literalHash(hostile), // a genuine SHA-256 of the subject
	}
	if _, err := ParseEntry(raw, "settings.yaml", 0); err == nil {
		t.Fatalf("ParseEntry accepted a compound subject widening a destructive program, want rejection")
	}
}

func TestLayerIsInMemoryOnly(t *testing.T) {
	if _, err := ParseEntry(map[string]any{
		"kind": "direct", "subject": "ls", "path_scope": "/proj", "grant_kind": "folder", "layer": "local",
	}, "/f.yaml", 0); err == nil || !strings.Contains(err.Error(), `unknown key "layer"`) {
		t.Fatalf("err = %v, want the existing unknown-key rejection", err)
	}

	entry := PermissionEntry{Kind: "direct", Subject: "ls", PathScope: "/proj", GrantKind: "folder", Layer: LayerLocal}
	data, err := MarshalEntry(entry)
	if err != nil {
		t.Fatalf("MarshalEntry: %v", err)
	}
	if strings.Contains(string(data), "layer") {
		t.Fatalf("marshalled entry %q must not emit a layer key", data)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reparsed, err := ParseEntry(raw, "/f.yaml", 0)
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if reparsed.Layer != "" {
		t.Fatalf("reparsed layer = %q, want empty", reparsed.Layer)
	}
	if reparsed.DedupKey() != entry.DedupKey() {
		t.Fatalf("DedupKey changed across layers: %+v vs %+v", reparsed.DedupKey(), entry.DedupKey())
	}

	other := entry
	other.Layer = LayerProject
	if other.DedupKey() != entry.DedupKey() {
		t.Fatalf("DedupKey = %+v, want two copies differing only in Layer to share it", other.DedupKey())
	}
}
