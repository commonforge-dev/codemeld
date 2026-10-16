// Tests for CleanAbsResolve, IsDescendantOrEqual, DerivePathScope, and FindScopeEscalation.
package permissions

import (
	"os"
	"path/filepath"
	"testing"
)

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return r
}

func mkdir(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", p, err)
	}
	return p
}

func TestCleanAbsResolve_HomeExpansion(t *testing.T) {
	home := t.TempDir()
	sub := mkdir(t, filepath.Join(home, "proj"))

	got, err := CleanAbsResolve(home, "/no/such/base", "~/proj")
	if err != nil {
		t.Fatalf("CleanAbsResolve: %v", err)
	}
	if want := mustEval(t, sub); got != want {
		t.Fatalf("CleanAbsResolve(~/proj) = %q, want %q", got, want)
	}
}

func TestCleanAbsResolve_SymlinkResolution(t *testing.T) {
	base := t.TempDir()
	target := mkdir(t, filepath.Join(base, "real"))
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	got, err := CleanAbsResolve("", "", link)
	if err != nil {
		t.Fatalf("CleanAbsResolve: %v", err)
	}
	if want := mustEval(t, target); got != want {
		t.Fatalf("CleanAbsResolve(link) = %q, want %q (symlink not resolved)", got, want)
	}
}

func TestCleanAbsResolve_RelativeJoinsBase(t *testing.T) {
	base := t.TempDir()
	sub := mkdir(t, filepath.Join(base, "child"))

	got, err := CleanAbsResolve("", base, "child")
	if err != nil {
		t.Fatalf("CleanAbsResolve: %v", err)
	}
	if want := mustEval(t, sub); got != want {
		t.Fatalf("CleanAbsResolve(child) = %q, want %q", got, want)
	}
}

func TestCleanAbsResolve_NotADirectory(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if got, err := CleanAbsResolve("", "", file); err == nil {
		t.Fatalf("CleanAbsResolve(file) = %q, want error (not a directory)", got)
	}
}

func TestCleanAbsResolve_MissingTarget(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if got, err := CleanAbsResolve("", "", missing); err == nil {
		t.Fatalf("CleanAbsResolve(missing) = %q, want error", got)
	}
}

func TestIsDescendantOrEqual(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		scope string
		want  bool
	}{
		{"equal", "/a/b", "/a/b", true},
		{"direct child", "/a/b/c", "/a/b", true},
		{"deep descendant", "/a/b/c/d/e", "/a/b", true},
		{"descendant of root", "/a/b", "/", true},
		{"ancestor", "/a", "/a/b", false},
		{"root vs deeper scope", "/", "/a", false},
		{"sibling prefix trap", "/a/foobar", "/a/foo", false},
		{"sibling", "/a/c", "/a/b", false},
		{"unrelated", "/x/y", "/a/b", false},
		{"unclean inputs normalize", "/a/b/c/../c", "/a/b", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsDescendantOrEqual(c.path, c.scope); got != c.want {
				t.Fatalf("IsDescendantOrEqual(%q, %q) = %v, want %v", c.path, c.scope, got, c.want)
			}
		})
	}
}

func TestFindScopeEscalation(t *testing.T) {
	childRead := PermissionEntry{Kind: subjectKindTool, Subject: "read", PathScope: "/media/imgdown", GrantKind: grantKindFolder}
	cases := []struct {
		name   string
		req    MatchRequest
		grants []PermissionEntry
		want   string
	}{
		{
			name:   "parent request over child grant escalates",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/media"},
			grants: []PermissionEntry{childRead},
			want:   "/media/imgdown",
		},
		{
			name:   "equal scope is not an escalation",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/media/imgdown"},
			grants: []PermissionEntry{childRead},
			want:   "",
		},
		{
			name:   "descendant request is not an escalation",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/media/imgdown/cache"},
			grants: []PermissionEntry{childRead},
			want:   "",
		},
		{
			name:   "sibling scope does not escalate",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/media/photos"},
			grants: []PermissionEntry{childRead},
			want:   "",
		},
		{
			name:   "unrelated scope does not escalate",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/var/log"},
			grants: []PermissionEntry{childRead},
			want:   "",
		},
		{
			name:   "different subject does not escalate",
			req:    MatchRequest{Kind: subjectKindTool, Subject: "write", PathScope: "/media"},
			grants: []PermissionEntry{childRead},
			want:   "",
		},
		{
			name:   "different kind does not escalate",
			req:    MatchRequest{Kind: subjectKindLiteral, Subject: "read", PathScope: "/media"},
			grants: []PermissionEntry{childRead},
			want:   "",
		},
		{
			name: "global grant is ignored",
			req:  MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/media"},
			grants: []PermissionEntry{
				{Kind: subjectKindTool, Subject: "read", PathScope: allPathsScope, GrantKind: grantKindGlobal},
			},
			want: "",
		},
		{
			name: "deepest narrower grant wins",
			req:  MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/media"},
			grants: []PermissionEntry{
				{Kind: subjectKindTool, Subject: "read", PathScope: "/media/imgdown", GrantKind: grantKindFolder},
				{Kind: subjectKindTool, Subject: "read", PathScope: "/media/imgdown/cache", GrantKind: grantKindSession},
			},
			want: "/media/imgdown/cache",
		},
		{
			// Reuses MatchesDirectSubject, not raw string equality: a stored "git :*"
			// program scope matches a "git log --oneline" request, so the broader parent
			// request still escalates. Raw equality would miss this.
			name: "direct subject with stored program scope matches via subject rules",
			req:  MatchRequest{Kind: subjectKindDirect, Subject: "git log --oneline", SubjectTokens: []string{"git", "log", "--oneline"}, PathScope: "/repo"},
			grants: []PermissionEntry{
				{Kind: subjectKindDirect, Subject: "git :*", PathScope: "/repo/sub", GrantKind: grantKindFolder},
			},
			want: "/repo/sub",
		},
		{
			name: "direct subject not matching stored subject does not escalate",
			req:  MatchRequest{Kind: subjectKindDirect, Subject: "ls", SubjectTokens: []string{"ls"}, PathScope: "/repo"},
			grants: []PermissionEntry{
				{Kind: subjectKindDirect, Subject: "git :*", PathScope: "/repo/sub", GrantKind: grantKindFolder},
			},
			want: "",
		},
		{
			name: "literal subject equal canonical escalates",
			req:  MatchRequest{Kind: subjectKindLiteral, Subject: "git status > out", PathScope: "/repo"},
			grants: []PermissionEntry{
				{Kind: subjectKindLiteral, Subject: "git status > out", PathScope: "/repo/sub", GrantKind: grantKindFolder},
			},
			want: "/repo/sub",
		},
		{
			// Reuses capability expansion: a stored "read*" capability grant matches a
			// concrete "read" request, so a broader parent request escalates against it.
			name: "tool capability grant escalates a member request",
			req:  MatchRequest{Kind: subjectKindTool, Subject: "read", PathScope: "/proj"},
			grants: []PermissionEntry{
				{Kind: subjectKindTool, Subject: CapabilityRead, PathScope: "/proj/sub", GrantKind: grantKindFolder},
			},
			want: "/proj/sub",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FindScopeEscalation(c.req, c.grants).NarrowerScope; got != c.want {
				t.Fatalf("FindScopeEscalation(scope=%q) = %q, want %q", c.req.PathScope, got, c.want)
			}
		})
	}
}

func TestDerivePathScope_AbsoluteCdHintWins(t *testing.T) {
	// Stands in for the spec example `cd /tmp && hg log` -> /tmp; a tempdir keeps
	// the test off platform-specific symlinked paths like macOS's /tmp.
	cdTarget := t.TempDir()
	processCWD := t.TempDir()

	got, err := DerivePathScope("", cdTarget, processCWD, "", "")
	if err != nil {
		t.Fatalf("DerivePathScope: %v", err)
	}
	if want := mustEval(t, cdTarget); got != want {
		t.Fatalf("DerivePathScope(cdHint) = %q, want %q", got, want)
	}
}

func TestDerivePathScope_RelativeCdHintResolvesUnderProcessCWD(t *testing.T) {
	processCWD := t.TempDir()
	sub := mkdir(t, filepath.Join(processCWD, "subdir"))

	got, err := DerivePathScope("", "subdir", processCWD, "", "")
	if err != nil {
		t.Fatalf("DerivePathScope: %v", err)
	}
	if want := mustEval(t, sub); got != want {
		t.Fatalf("DerivePathScope(relative cd) = %q, want %q", got, want)
	}
}

func TestDerivePathScope_StructuredToolUsesToolCwd(t *testing.T) {
	toolCwd := t.TempDir()
	processCWD := t.TempDir()

	got, err := DerivePathScope("", "", processCWD, toolCwd, subjectKindTool)
	if err != nil {
		t.Fatalf("DerivePathScope: %v", err)
	}
	if want := mustEval(t, toolCwd); got != want {
		t.Fatalf("DerivePathScope(tool) = %q, want %q", got, want)
	}
}

func TestDerivePathScope_BareCommandUsesProcessCWD(t *testing.T) {
	processCWD := t.TempDir()

	got, err := DerivePathScope("", "", processCWD, "", "direct")
	if err != nil {
		t.Fatalf("DerivePathScope: %v", err)
	}
	if want := mustEval(t, processCWD); got != want {
		t.Fatalf("DerivePathScope(bare) = %q, want %q", got, want)
	}
}

func TestDerivePathScope_RejectsAllPathsSentinel(t *testing.T) {
	processCWD := t.TempDir()

	if got, err := DerivePathScope("", "*", processCWD, "", ""); err == nil {
		t.Fatalf("DerivePathScope(cdHint=*) = %q, want error", got)
	}
	if got, err := DerivePathScope("", "", "*", "", "direct"); err == nil {
		t.Fatalf("DerivePathScope(processCWD=*) = %q, want error", got)
	}
}
