package permissions

import (
	"slices"
	"strings"
	"testing"
)

func TestExceptionalAuthority(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		{"curl x", authorityNetwork},
		{"wget x", authorityNetwork},
		{"ssh host", authorityNetwork},
		{"scp a host:b", authorityNetwork},
		{"hg pull", authorityNetwork},
		{"hg push", authorityNetwork},
		{"hg clone src dst", authorityNetwork},
		{"git fetch", authorityNetwork},
		{"git push origin main", authorityNetwork},
		{"git pull", authorityNetwork},
		{"git clone url", authorityNetwork},
		{"pip install x", authorityNetwork},
		{"pip3 install x", authorityNetwork},
		{"rm x", authorityFileDeletion},
		{"rmdir d", authorityFileDeletion},
		{"unlink x", authorityFileDeletion},
		{"shred x", authorityFileDeletion},
		{"hg strip tip", authorityHistoryRewrite},
		{"hg rollback", authorityHistoryRewrite},
		{"git reset --hard", authorityHistoryRewrite},
		{"hg --cwd /repo strip", authorityHistoryRewrite},
		{"hg --config extensions.strip= strip", authorityHistoryRewrite},
		{"git -c x=y reset --hard", authorityHistoryRewrite},
		{"git reset HEAD~1 --hard", authorityHistoryRewrite},
		{"hg strip -r pull", authorityNetwork},
		{"git reset --soft HEAD~1", ""},
		{"hg log", ""},
		{"git status", ""},
		{"pip list", ""},
		{"/tmp/rm x", ""},
		{"ls", ""},
		{"go build ./...", ""},
		{"gofmt -w x.go", ""},
		{"python -m pip install x", ""},
		{"sudo rm x", ""},
		{"git --hard reset", ""},
		{"find . -delete", authorityFileDeletion},
		{"find . -name *.o -delete", authorityFileDeletion},
		{"find . -exec rm {} ;", authorityFileDeletion},
		{"find . -execdir rmdir {} ;", authorityFileDeletion},
		{"find . -ok unlink {} ;", authorityFileDeletion},
		{"find . -okdir shred {} ;", authorityFileDeletion},
		{"find . -exec rm {} +", authorityFileDeletion},
		{"find . -name *.o -execdir rm {} +", authorityFileDeletion},
		{"git clean", authorityFileDeletion},
		{"git clean -f", authorityFileDeletion},
		{"git clean -n", authorityFileDeletion},
		{"git clean -d -n", authorityFileDeletion},
		{"git rebase main", authorityHistoryRewrite},
		{"git -C dir rebase", authorityHistoryRewrite},
		{"git commit --amend", authorityHistoryRewrite},
		{"git commit -m x --amend", authorityHistoryRewrite},
		{"git filter-branch", authorityHistoryRewrite},
		{"git filter-repo", authorityHistoryRewrite},
		{"hg histedit", authorityHistoryRewrite},
		{"hg rebase -d main", authorityHistoryRewrite},
		{"hg commit --amend", authorityHistoryRewrite},
		{"hg uncommit", authorityHistoryRewrite},
		{"hg amend", authorityHistoryRewrite},
		{"git -C dir reset HEAD~1 --hard", authorityHistoryRewrite},
		{"git commit -m x", ""},
		{"hg commit -m x", ""},
		{"find . -name x -print", ""},
		{"find . -exec git status ;", ""},
		{"find . -exec /tmp/rm {} ;", ""},
		{"find . -name -delete", authorityFileDeletion},
		{"git log rebase", authorityHistoryRewrite},
		{"git commit -m --amend", authorityHistoryRewrite},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			got, ok := ExceptionalAuthority(strings.Fields(tc.cmd))
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("ExceptionalAuthority(%q) = (%q, %v), want (%q, %v)", tc.cmd, got, ok, tc.want, tc.want != "")
			}
		})
	}
	if got, ok := ExceptionalAuthority(nil); ok || got != "" {
		t.Fatalf("ExceptionalAuthority(nil) = (%q, %v), want no authority", got, ok)
	}
	if want := []string{authorityNetwork, authorityFileDeletion, authorityHistoryRewrite}; !slices.Equal(authorityPrecedence, want) {
		t.Fatalf("authorityPrecedence = %v, want %v", authorityPrecedence, want)
	}
}

func TestClassifyExceptional(t *testing.T) {
	cases := []struct {
		name             string
		shell            string
		req              MatchRequest
		mc               ModeContext
		wantAuthority    string
		wantClassifiable bool
	}{
		{shell: "find . -delete", wantAuthority: authorityFileDeletion, wantClassifiable: true},
		{shell: `find . -exec rm {} \;`, wantAuthority: authorityFileDeletion, wantClassifiable: true},
		{shell: "find . -execdir rm {} +", wantAuthority: authorityFileDeletion, wantClassifiable: true},
		{shell: "git -C dir rebase", wantAuthority: authorityHistoryRewrite, wantClassifiable: true},
		{shell: "git commit --amend", wantAuthority: authorityHistoryRewrite, wantClassifiable: true},
		{shell: `sh -c 'ls && git commit -m x --amend'`, wantAuthority: authorityHistoryRewrite, wantClassifiable: true},
		{shell: `sh -c 'ls && find . -name "*.o" -delete'`, wantAuthority: authorityFileDeletion, wantClassifiable: true},
		{shell: "git commit -m x", wantClassifiable: true},
		{shell: "find . -name x -print", wantClassifiable: true},
		{shell: `find . -exec git status \;`, wantClassifiable: true},
		{
			name:             "control syntax literal",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c 'if true; then curl x; fi'`},
			wantClassifiable: false,
		},
		{
			name:             "brace group literal",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c '{ curl x; }'`},
			wantClassifiable: false,
		},
		{
			name:             "line continuation inside a program word",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "sh -c 'r\\\nm --version'"},
			wantClassifiable: false,
		},
		{
			name:             "line continuation inside a network program word",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "ls && cu\\\nrl x"},
			wantClassifiable: false,
		},
		{
			name:             "line continuation inside a subcommand",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "sh -c 'git re\\\nset --hard'"},
			wantClassifiable: false,
		},
		{
			name:             "line continuation inside an option",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "sh -c 'git reset --ha\\\nrd'"},
			wantClassifiable: false,
		},
		{
			name:             "line continuation inside an hg subcommand",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "sh -c 'hg st\\\nrip tip'"},
			wantClassifiable: false,
		},
		{
			name:             "line continuation inside a reserved word",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "sh -c 'i\\\nf true; then curl x; fi'"},
			wantClassifiable: false,
		},
		{
			name:             "reserved word in",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "sh -c 'in'"},
			wantClassifiable: false,
		},
		{
			name:             "line continuation between words",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: "sh -c 'go build \\\n./...'"},
			wantClassifiable: false,
		},
		{
			name:             "unsplittable literal",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: `ls > out`},
			wantClassifiable: false,
		},
		{
			name:             "non-leading stages pick the highest precedence",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: `ls && git reset --hard && rm x && curl y`},
			wantAuthority:    authorityNetwork,
			wantClassifiable: true,
		},
		{
			name:             "ordinary literal",
			req:              MatchRequest{Kind: subjectKindLiteral, Subject: `sh -c 'go build ./...'`},
			wantClassifiable: true,
		},
		{
			name:             "direct with an exceptional later stage",
			req:              MatchRequest{Kind: subjectKindDirect, Subject: "ls"},
			mc:               ModeContext{Stages: []StageNormalization{{Route: RouteDirect, Tokens: []string{"ls"}}, {Route: RouteDirect, Tokens: []string{"rm", "x"}}}},
			wantAuthority:    authorityFileDeletion,
			wantClassifiable: true,
		},
		{
			name:             "direct without stages",
			req:              MatchRequest{Kind: subjectKindDirect, Subject: "curl x"},
			wantClassifiable: false,
		},
		{
			name:             "structured edit",
			req:              MatchRequest{Kind: subjectKindTool, Subject: toolNameEdit},
			mc:               ModeContext{ToolName: toolNameEdit},
			wantClassifiable: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+tc.shell, func(t *testing.T) {
			req, mc := tc.req, tc.mc
			if tc.shell != "" {
				req, mc = shellCtx(t, tc.shell)
				if strings.HasPrefix(tc.shell, "sh -c ") != (req.Kind == subjectKindLiteral) {
					t.Fatalf("shellCtx(%q) routed to kind %q", tc.shell, req.Kind)
				}
			}
			authority, classifiable := ClassifyExceptional(req, mc)
			if authority != tc.wantAuthority || classifiable != tc.wantClassifiable {
				t.Fatalf("ClassifyExceptional = (%q, %v), want (%q, %v)", authority, classifiable, tc.wantAuthority, tc.wantClassifiable)
			}
		})
	}
}
