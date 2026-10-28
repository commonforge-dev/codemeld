package permissions

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
		{"hg ci --amend", authorityHistoryRewrite},
		{"hg commit --amen", authorityHistoryRewrite},
		{"hg ci --am", authorityHistoryRewrite},
		{"hg ci --ame", authorityHistoryRewrite},
		{"git commit --amen", authorityHistoryRewrite},
		{"git commit --ame", authorityHistoryRewrite},
		{"git commit --am", authorityHistoryRewrite},
		{"git commit -m --amen", authorityHistoryRewrite},
		{"hg ci -m x", ""},
		{"git ci --amend", ""},
		{"git commit --a", ""},
		{"git commit --amfoo", ""},
		{"git commit --amed", ""},
		{"git commit --amend-ish", ""},
		{"hg commit --amfoo", ""},
		{"hg ci --amed", ""},
		{"hg ci --amend-ish", ""},
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

var classifyExceptionalCases = []struct {
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
	{shell: `sh -c 'hg ci --am -m x'`, wantAuthority: authorityHistoryRewrite, wantClassifiable: true},
	{shell: `sh -c 'exec git clean -fd'`, wantClassifiable: false},
	{shell: `sh -c 'eval git clean -fd'`, wantClassifiable: false},
	{shell: `sh -c '. ./env.sh'`, wantClassifiable: false},
	{shell: `sh -c 'source ./env.sh'`, wantClassifiable: false},
	{shell: `sh -c 'builtin cd scratch'`, wantClassifiable: false},
	{
		name:             "builtin in a later literal stage",
		req:              MatchRequest{Kind: subjectKindLiteral, Subject: `ls && exec git clean -fd`},
		wantClassifiable: false,
	},
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
		name:             "static redirection literal",
		req:              MatchRequest{Kind: subjectKindLiteral, Subject: `ls > out`},
		wantClassifiable: true,
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

func TestClassifyExceptional(t *testing.T) {
	for _, tc := range classifyExceptionalCases {
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

var classifyRedirectionCases = []struct {
	subject          string
	wantAuthority    string
	wantClassifiable bool
}{
	{`ls lib 2>&1`, "", true},
	{`ls -la scripts test 2>&1 | head -40`, "", true},
	{`printf 'x\n' > test/a.bats; shellcheck test/a.bats`, "", true},
	{`shellcheck a.bats >/dev/null 2>&1; echo done`, "", true},
	{`printf a | tee b.sh >/dev/null`, "", true},
	{`sh -c 'grep x f > out'`, "", true},
	{`cat < in.txt`, "", true},
	{`echo x>>log.txt`, "", true},
	{`ls '>' rm`, "", true},
	{`ls \> rm`, "", true},
	{`echo x >| out`, "", true},
	{`cat 3<>in.txt`, "", true},
	{`echo x 3>&-`, "", true},
	{`ls 2> out`, "", true},
	{`ls 3>&1`, "", true},
	{`cat 3<&0`, "", true},
	{`echo x >&2`, "", true},
	{`echo x > 'a b'`, "", true},
	{`echo x>one>two`, "", true},
	{`echo a2>out`, "", true},

	{`rm test/a 2>&1`, authorityFileDeletion, true},
	{`> out rm test/a`, authorityFileDeletion, true},
	{`curl https://x > page.html`, authorityNetwork, true},
	{`find test -name x -delete 2>/dev/null`, authorityFileDeletion, true},
	{`hg push 2>&1 | tail -3`, authorityNetwork, true},
	{`ls >a&&rm x`, authorityFileDeletion, true},
	{`echo x>out;rm y`, authorityFileDeletion, true},
	{`sh -c 'rm x 2>/dev/null'`, authorityFileDeletion, true},
	{`bash script.sh > out`, "", true},
	{`bash script.sh > out; ls`, "", true},
	{`X=1 ls > out`, "", true},
	{`X=1 rm f > out`, authorityFileDeletion, true},
	{`env FOO=bar ls > out`, "", false},
	{`X=1 bash script.sh > out`, "", false},
	{`sh $OPTIONS > out`, "", false},

	{`cat <(rm x)`, "", false},
	{`ls >(curl u)`, "", false},
	{`diff <(ls a) <(ls b)`, "", false},
	{`echo "$(rm x)" > f`, "", false},
	{`ls > $(rm x)`, "", false},
	{`ls > "$(rm x)"`, "", false},
	{`cat < "$(hg strip x)"`, "", false},
	{"ls > `rm x`", "", false},
	{`cat < <(rm x)`, "", false},
	{`ls > >(curl u)`, "", false},
	{`cat <<EOF`, "", false},
	{`ls 2>&1 &`, "", false},
	{`ls &> f`, "", false},
	{`ls &>> f`, "", false},
	{`{ rm x; } > f`, "", false},
	{`exec 3>f`, "", false},
	{`eval ls > f`, "", false},
	{`ls {fd}>f`, "", false},
	{`D=x; printf a > "$D/f"`, "", false},
	{`x=1 > f`, "", false},
	{`ls >`, "", false},
	{`ls 2>`, "", false},
	{`> f`, "", false},
	{`&> f`, "", false},
	{`ls 12>f`, "", false},
	{`ls >&-`, "", false},
	{`cat <&0`, "", false},
	{`cat 3<&-`, "", false},
	{`ls 2>&12`, "", false},
	{`ls > *.log`, "", false},
	{`sh -c >f 'ls';ls`, "", true},
	{`sh -c "sh -c 'ls';ls >f"`, "", false},

	{"ls >\nout", "", false},
	{"ls 2>\nout", "", false},
	{"ls >\rout", "", false},
	{"ls > 'a\nb'", "", false},
	{"ls > \"a\nb\"", "", false},
	{"ls > a\\\nb", "", false},
	{"sh -c 'ls >\nout'", "", false},
	{"sh -c 'ls > \"a\nb\"'", "", false},
}

func TestClassifyExceptionalRedirections(t *testing.T) {
	for _, tc := range classifyRedirectionCases {
		t.Run(tc.subject, func(t *testing.T) {
			authority, classifiable := ClassifyExceptional(MatchRequest{Kind: subjectKindLiteral, Subject: tc.subject}, ModeContext{})
			if authority != tc.wantAuthority || classifiable != tc.wantClassifiable {
				t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (%q, %v)", tc.subject, authority, classifiable, tc.wantAuthority, tc.wantClassifiable)
			}
		})
	}
}

func TestClassifyExceptionalWrapperSubstitutionAfterCanonicalization(t *testing.T) {
	cases := []struct {
		source           string
		wantClassifiable bool
	}{
		{`sh -c "echo x > '$(rm victim)'"`, false},
		{"sh -c \"echo x > '`rm victim`'\"", false},
		{`sh -c "echo '$(rm victim)'"`, false},
		{"sh -c \"echo '`rm victim`'\"", false},
		{`sh -c "ls; echo '$(rm victim)' > out"`, false},
		{`sh -c 'echo x > '\''$(rm victim)'\'`, true},
		{"sh -c 'echo x > '\\''`rm victim`'\\'", true},
		{`sh -c "grep x f > out"`, true},
		{`sh -c 'grep x f > out'`, true},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			subject, err := CanonicalLiteralForm(tc.source)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q): %v", tc.source, err)
			}
			authority, classifiable := ClassifyExceptional(MatchRequest{Kind: subjectKindLiteral, Subject: subject}, ModeContext{})
			if authority != "" || classifiable != tc.wantClassifiable {
				t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (\"\", %v)", subject, authority, classifiable, tc.wantClassifiable)
			}
		})
	}
}

func TestLiteralClassifierStagesKeepCommandWords(t *testing.T) {
	cases := map[string][][]string{
		`echo a2>out`:        {{"echo", "a2"}},
		`echo x>one>two`:     {{"echo", "x"}},
		`ls '>' rm`:          {{"ls", ">", "rm"}},
		`ls >a&&rm x`:        {{"ls"}, {"rm", "x"}},
		`echo x>out;rm y`:    {{"echo", "x"}, {"rm", "y"}},
		`cat 3<&0 x`:         {{"cat", "x"}},
		`echo x >| out | wc`: {{"echo", "x"}, {"wc"}},
	}
	for subject, want := range cases {
		stages, ok := literalClassifierStages(subject)
		if !ok || len(stages) != len(want) {
			t.Fatalf("literalClassifierStages(%q) = %+v, %v; want %d stages", subject, stages, ok, len(want))
		}
		for i := range want {
			if !slices.Equal(stages[i].Tokens, want[i]) {
				t.Fatalf("literalClassifierStages(%q) stage %d = %q, want %q", subject, i, stages[i].Tokens, want[i])
			}
		}
	}
}

func TestExceptionalPathQualifiedFindDeleter(t *testing.T) {
	writeRm := func(dir string) string {
		path := filepath.Join(dir, "rm")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Setenv("PATH", filepath.Dir(writeRm(t.TempDir())))
	outside := writeRm(t.TempDir())
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Fatalf("LookPath(rm) under the test PATH: %v", err)
	}
	if !filepath.IsAbs(rm) {
		t.Fatalf("LookPath(rm) = %q, want an absolute path", rm)
	}
	cases := []struct {
		tokens []string
		want   string
	}{
		{[]string{"find", ".", "-exec", rm, "{}", ";"}, authorityFileDeletion},
		{[]string{"find", ".", "-execdir", rm, "{}", "+"}, authorityFileDeletion},
		{[]string{"find", ".", "-exec", outside, "{}", ";"}, ""},
		{[]string{"find", ".", "-execdir", outside, "{}", "+"}, ""},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.tokens, " "), func(t *testing.T) {
			got, ok := ExceptionalAuthority(tc.tokens)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("ExceptionalAuthority = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.want != "")
			}
			req := MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(tc.tokens, " ")}
			mc := ModeContext{Stages: []StageNormalization{{Route: RouteDirect, Tokens: tc.tokens}}}
			authority, classifiable := ClassifyExceptional(req, mc)
			if authority != tc.want || !classifiable {
				t.Fatalf("ClassifyExceptional = (%q, %v), want (%q, true)", authority, classifiable, tc.want)
			}
		})
	}
}

var literalChainCases = []struct {
	source           string
	wantAuthority    string
	wantClassifiable bool
}{
	{`bash scripts/x.sh; echo "EXIT=$?"`, "", true},
	{`bash scripts/x.sh 2>&1 | tail -20; echo "EXIT=${PIPESTATUS[0]}"`, "", true},
	{`SHELL=/usr/bin/bash mise run x 2>&1 | tail -5`, "", true},
	{`X=1 Y=2 ls; pwd`, "", true},
	{`FOO="a b" go test ./... | tail -3`, "", true},
	{`sh scripts/x.sh a "$B" $C; ls`, "", true},
	{`bash "scripts/x.sh"; ls`, "", true},
	{`bash 'a$b.sh'; ls`, "", true},
	{`bash a\$b.sh; ls`, "", true},
	{`bash ./+name; ls`, "", true},
	{`env ls; pwd`, "", true},
	{`ls && cd sub`, "", true},
	{`ls; cd sub; pwd`, "", true},

	{`X=1 rm f; ls`, authorityFileDeletion, true},
	{`ls &&   X=1   rm   f`, authorityFileDeletion, true},
	{`X='1' rm f | cat`, authorityFileDeletion, true},
	{`GIT_DIR=x git push && ls`, authorityNetwork, true},
	{`ls; A=1 B="2 3" curl u`, authorityNetwork, true},
	{`bash x.sh; rm y`, authorityFileDeletion, true},
	{`ls && cd sub && rm x`, authorityFileDeletion, true},

	{`X=1 bash script.sh; ls`, "", false},
	{`X=1 sh script.sh`, "", false},
	{`X=1 bash -c 'ls'; ls`, "", false},
	{`X=1 env FOO=bar ls; ls`, "", false},
	{`env FOO=bar ls; ls`, "", false},
	{`ls | env FOO=bar ls`, "", false},
	{`env -i PATH=/usr/bin ls; ls`, "", false},
	{`X=1 exec rm f; ls`, "", false},
	{`X=1 eval ls; ls`, "", false},
	{`X=1 source a; ls`, "", false},
	{`X=1 . a; ls`, "", false},
	{`X=1 builtin cd x; ls`, "", false},
	{`X=1 ! ls; pwd`, "", false},
	{`X=1 while ls; pwd`, "", false},
	{`X=$Y ls; pwd`, "", false},
	{`X=~ ls; pwd`, "", false},
	{`X=1; ls`, "", false},
	{`ls; X=1`, "", false},
	{`ls; bash -c 'rm x'`, authorityFileDeletion, true},
	{`ls; sh -c 'ls'`, "", true},
	{`bash -x script.sh; ls`, "", true},
	{`bash +x script.sh; ls`, "", true},
	{`bash +O extglob x.sh; ls`, "", true},
	{`X=1 nice ls; ls`, "", false},
	{`/bin/bash x.sh; ls`, "", false},
	{`bash x.sh (rm y); ls`, "", false},
	{`bash "$SCRIPT"; ls`, "", false},
	{`bash ${SCRIPT}; ls`, "", false},
	{`sh $OPTIONS; ls`, "", false},
	{`bash *.sh; ls`, "", false},
	{`bash x?.sh; ls`, "", false},
	{`bash ~/x.sh; ls`, "", false},

	{`ls; $X -rf .`, "", false},
	{`$X -rf . > out`, "", false},
	{`"$P" x; ls`, "", false},
	{`${P} x; ls`, "", false},
	{`X=1 $P x; ls`, "", false},
	{`ls | env $P x`, "", false},
	{`'$P' x; ls`, "", true},
	{`\$P x; ls`, "", true},
}

func TestClassifyExceptionalLiteralChainStages(t *testing.T) {
	for _, tc := range literalChainCases {
		t.Run(tc.source, func(t *testing.T) {
			subject, err := CanonicalLiteralForm(tc.source)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q): %v", tc.source, err)
			}
			authority, classifiable := ClassifyExceptional(MatchRequest{Kind: subjectKindLiteral, Subject: subject}, ModeContext{})
			if authority != tc.wantAuthority || classifiable != tc.wantClassifiable {
				t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (%q, %v)", subject, authority, classifiable, tc.wantAuthority, tc.wantClassifiable)
			}
		})
	}
}

func TestClassifyExceptionalDirectProgramWordExpansionUnchanged(t *testing.T) {
	for _, input := range []string{`$X -rf .`, `"$P" x`, `${P} x`} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if req.Kind != subjectKindDirect {
				t.Fatalf("shellCtx(%q) routed to kind %q, want direct", input, req.Kind)
			}
			if authority, classifiable := ClassifyExceptional(req, mc); authority != "" || !classifiable {
				t.Fatalf("ClassifyExceptional = (%q, %v), want (\"\", true)", authority, classifiable)
			}
		})
	}
}

func TestLiteralClassifierStagesMatchSimpleCompoundStages(t *testing.T) {
	for _, subject := range []string{
		`ls && pwd`,
		`go test ./... | tail -5; wc -l a`,
		`git status || hg st`,
		`rg foo | head -3 && wc -l a`,
		`env ls; git log -1`,
	} {
		t.Run(subject, func(t *testing.T) {
			got, ok := literalClassifierStages(subject)
			_, want, _, wantOK := SimpleCompoundStages(subject)
			if !ok || !wantOK || len(got) != len(want) {
				t.Fatalf("literalClassifierStages = %+v, %v; SimpleCompoundStages = %+v, %v", got, ok, want, wantOK)
			}
			for i := range want {
				if !slices.Equal(got[i].Tokens, want[i].Tokens) {
					t.Fatalf("stage %d tokens = %q, SimpleCompoundStages = %q", i, got[i].Tokens, want[i].Tokens)
				}
			}
		})
	}
}

const deletion, network = "file deletion", "network access"

var shellAndWrapperCases = []struct {
	source           string
	wantAuthority    string
	wantClassifiable bool
}{
	{`bash --version | head -1`, "", true},
	{`sh -x scripts/a.sh`, "", true},
	{`bash -o pipefail scripts/a.sh`, "", true},
	{`bash -c 'ls | head -1'`, "", true},
	{`bash -ec 'go test ./...'`, "", true},
	{`command -v jq bats shellcheck`, "", true},
	{`type jq bats`, "", true},
	{`nice -n 5 make`, "", true},
	{`time go test ./...`, "", true},
	{`find . -name '*.go' | xargs grep foo`, "", true},
	{`"bash" -c 'ls'`, "", true},
	{`ls; sh -c 'ls'`, "", true},
	{`echo 'rm -rf x' | bash`, "", true},
	{`nice nice nice ls`, "", true},
	{`bash -c -- '-x'`, "", true},

	{`bash -c 'rm -rf x'`, deletion, true},
	{`bash -ec 'rm x'`, deletion, true},
	{`sh -lc 'curl x'`, network, true},
	{`bash -o pipefail -c 'rm x'`, deletion, true},
	{`nice rm x`, deletion, true},
	{`nohup curl x`, network, true},
	{`time rm x`, deletion, true},
	{`xargs rm`, deletion, true},
	{`xargs -n1 rm`, deletion, true},
	{`xargs -i rm {}`, deletion, true},
	{`xargs -e rm`, deletion, true},
	{`xargs -l rm`, deletion, true},
	{`xargs -0 -- rm`, deletion, true},
	{`command rm x`, deletion, true},
	{`nice nohup rm x`, deletion, true},
	{`ls; sh -c 'rm x'`, deletion, true},
	{`sh -c 'rm x'`, deletion, true},

	{`bash -c "bash -c 'rm x'"`, "", false},
	{`bash -c "$X"`, "", false},
	{`bash -c 'eval x'`, "", false},
	{`bash -c 'source x'`, "", false},
	{`xargs --unknown rm`, "", false},
	{`nice nice nice nice ls`, "", false},
	{`nice`, "", false},
	{`bash -c'rm x'`, "", false},
	{`bash -c`, "", false},
	{`bash -c ''`, "", false},
	{`bash -c 'echo $(rm x)'`, "", false},
	{"bash -c 'echo `rm x`'", "", false},
	{`bash -c "echo $(rm x)"`, "", false},
	{`bash -co pipefail 'rm x'`, "", false},
	{`bash -cO extglob 'rm x'`, "", false},
	{`bash +xo pipefail scripts/a.sh`, "", false},
	{`bash -$FLAGS 'rm x'`, "", false},
	{`bash --$OPTION 'rm x'`, "", false},
	{`xargs -$FLAGS rm`, "", false},
	{`bash +c 'rm x'`, "", false},
	{`bash -c 'ls' $X`, "", false},
	{`bash -c "ls $X"`, "", false},
	{`xargs -n$N rm`, "", false},
	{`xargs -n $N rm`, "", false},
	{`nice bash x.sh`, "", false},
	{`nice bash -c 'rm x'`, "", false},
	{`xargs sh`, "", false},
	{`nice env ls`, "", false},
	{`nice X=1 ls`, "", false},
	{`/bin/bash -c 'ls'`, "", false},
	{`/usr/bin/nice ls`, "", false},
	{`nice eval ls`, "", false},
	{`type ls -x`, "", false},
	{`command -v`, "", false},
}

func TestClassifyExceptionalShellAndWrapperStages(t *testing.T) {
	for _, tc := range shellAndWrapperCases {
		t.Run(tc.source, func(t *testing.T) {
			req, mc := shellCtx(t, tc.source)
			authority, classifiable := ClassifyExceptional(req, mc)
			if authority != tc.wantAuthority || classifiable != tc.wantClassifiable {
				t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (%q, %v)", req.Subject, authority, classifiable, tc.wantAuthority, tc.wantClassifiable)
			}
		})
	}
}

func TestClassifyExceptionalWrappedPathProgram(t *testing.T) {
	dir := t.TempDir()
	rm := filepath.Join(dir, "rm")
	if err := os.WriteFile(rm, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	req, mc := shellCtx(t, "nice "+rm+" x")
	if authority, classifiable := ClassifyExceptional(req, mc); authority != "file deletion" || !classifiable {
		t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (\"file deletion\", true)", req.Subject, authority, classifiable)
	}
}

func classifyLiteralExceptional(subject string) (string, bool) {
	return ClassifyExceptional(MatchRequest{Kind: subjectKindLiteral, Subject: subject}, ModeContext{})
}

var hereStringsAndBareEnvSubjects = []string{
	`jq -n '9223372036854775807 + 1'; jq -n '9223372036854775808 > 9223372036854775807'; jq -n '(3600000000000 * 9223372036854775807 / 1) | floor'; jq -n '("1" + ("0" * 5)) | tonumber'; jq -n '[match("(\\d+(\\.\\d*)?|\\.\\d+)(ns|us|ms|s|m|h)"; "g")] | length' <<< 1h30m250ms`,
	`env | grep -i shell; printf 'x\n'`,
	`env | grep -i -E 'shell|opt' ; printf 'probe2\n'`,
	`jq -n 'input' <<< '1'`,
	`cat <<< word`,
	`bash -c 'jq . <<< x'`,
	`jq . <<< 'a'; jq . <<< 'b'`,
}

func TestClassifyExceptionalHereStringsAndBareEnv(t *testing.T) {
	for _, subject := range hereStringsAndBareEnvSubjects {
		t.Run(subject, func(t *testing.T) {
			if authority, classifiable := classifyLiteralExceptional(subject); authority != "" || !classifiable {
				t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (\"\", true)", subject, authority, classifiable)
			}
		})
	}
}

var hereStringRiskyCases = []struct{ subject, want string }{
	{`rm x <<< y`, "file deletion"},
	{`xargs rm <<< f`, "file deletion"},
	{`curl x <<< y`, "network access"},
	{`hg strip <<< y`, "VCS history rewrite"},
}

func TestClassifyExceptionalHereStringKeepsRiskyAuthority(t *testing.T) {
	for _, tc := range hereStringRiskyCases {
		t.Run(tc.subject, func(t *testing.T) {
			if authority, classifiable := classifyLiteralExceptional(tc.subject); authority != tc.want || !classifiable {
				t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (%q, true)", tc.subject, authority, classifiable, tc.want)
			}
		})
	}
}

var hereStringBypassSubjects = []string{
	`jq . <<< 'a'; jq . <<< $V`,
	`jq . <<< $VAR`,
	`jq . <<< "$VAR"`,
	`jq . <<< $(rm x)`,
	"jq . <<< `rm x`",
	`jq . 0<<< x`,
	`jq . 3<<< x`,
	`cat << EOF`,
	`jq . <<<< x`,
	`jq . <<< <(rm x)`,
	`jq . <<< >(rm x)`,
	`jq . <<< a>out`,
	`sh <<< 'rm x'`,
	`bash <<< 'rm x'`,
	`env sh <<< 'rm x'`,
	`command sh <<< 'rm x'`,
	`xargs sh <<< 'rm x'`,
	`bash -x <<< 'rm x'`,
	`bash -c 'sh' <<< 'rm x'`,
	`sh -c 'sh' <<< 'rm x'`,
	`cat <<< 'rm x' | sh`,
	`bash -c 'cat <<< x'; sh`,
	`jq . <<< x; bash script.sh`,
	`eval x <<< y`,
	`rm x <<< y; sh`,
}

func TestClassifyExceptionalHereStringBypassesStayUnclassifiable(t *testing.T) {
	for _, subject := range hereStringBypassSubjects {
		t.Run(subject, func(t *testing.T) {
			if authority, classifiable := classifyLiteralExceptional(subject); classifiable {
				t.Fatalf("ClassifyExceptional(%q) = (%q, true), want unclassifiable", subject, authority)
			}
		})
	}
}

func TestClassifyExceptionalHereStringFactsStayPerCall(t *testing.T) {
	want := map[string]bool{`cat <<< x`: true, `bash script.sh`: true, `cat <<< x | sh`: false}
	order := []string{`cat <<< x`, `bash script.sh`, `cat <<< x | sh`, `bash script.sh`, `cat <<< x`}
	for _, subject := range order {
		if _, classifiable := classifyLiteralExceptional(subject); classifiable != want[subject] {
			t.Fatalf("sequential ClassifyExceptional(%q) classifiable = %v, want %v", subject, classifiable, want[subject])
		}
	}
	var wg sync.WaitGroup
	errs := make(chan string, 300)
	for range 100 {
		for _, subject := range order[:3] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, classifiable := classifyLiteralExceptional(subject); classifiable != want[subject] {
					errs <- subject
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for subject := range errs {
		t.Fatalf("concurrent ClassifyExceptional(%q) classifiable != %v", subject, want[subject])
	}
}

type classifierResults struct {
	authority    string
	classifiable bool
	sandboxed    string
}

func classifyBoth(subject string) classifierResults {
	req := MatchRequest{Kind: subjectKindLiteral, Subject: subject}
	authority, classifiable := ClassifyExceptional(req, ModeContext{})
	return classifierResults{authority, classifiable, SandboxedAutoEditsAuthority(req, ModeContext{})}
}

func TestExceptionalClassificationsStayPerCallConcurrently(t *testing.T) {
	want := map[string]classifierResults{
		`ls -la`:                     {"", true, ""},
		`rm -rf build`:               {"file deletion", true, ""},
		`curl x`:                     {"network access", true, "network access"},
		`hg strip tip`:               {"VCS history rewrite", true, "VCS history rewrite"},
		`rm x && git rebase main`:    {"file deletion", true, "VCS history rewrite"},
		`rm x; curl y`:               {"network access", true, "network access"},
		`cat <<< x | sh`:             {"", false, ""},
		`ls && cu` + "\\\n" + `rl x`: {"", false, ""},
	}
	subjects := slices.Sorted(maps.Keys(want))
	var wg sync.WaitGroup
	errs := make(chan string, 100*len(subjects))
	for range 100 {
		for _, subject := range subjects {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if got := classifyBoth(subject); got != want[subject] {
					errs <- fmt.Sprintf("%q = %+v, want %+v", subject, got, want[subject])
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatalf("concurrent classification %s", msg)
	}
}

type classifierTableCase struct {
	name         string
	req          MatchRequest
	mc           ModeContext
	authority    string
	classifiable bool
}

func classifierCommandTable(t *testing.T) []classifierTableCase {
	t.Helper()
	literal := func(source string) MatchRequest {
		t.Helper()
		subject, err := CanonicalLiteralForm(source)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q): %v", source, err)
		}
		return MatchRequest{Kind: subjectKindLiteral, Subject: subject}
	}
	var table []classifierTableCase
	for _, tc := range classifyExceptionalCases {
		req, mc := tc.req, tc.mc
		if tc.shell != "" {
			req, mc = shellCtx(t, tc.shell)
		}
		table = append(table, classifierTableCase{tc.name + tc.shell, req, mc, tc.wantAuthority, tc.wantClassifiable})
	}
	for _, tc := range classifyRedirectionCases {
		table = append(table, classifierTableCase{tc.subject, MatchRequest{Kind: subjectKindLiteral, Subject: tc.subject}, ModeContext{}, tc.wantAuthority, tc.wantClassifiable})
	}
	for _, tc := range literalChainCases {
		table = append(table, classifierTableCase{tc.source, literal(tc.source), ModeContext{}, tc.wantAuthority, tc.wantClassifiable})
	}
	for _, tc := range shellAndWrapperCases {
		req, mc := shellCtx(t, tc.source)
		table = append(table, classifierTableCase{tc.source, req, mc, tc.wantAuthority, tc.wantClassifiable})
	}
	for _, subject := range hereStringsAndBareEnvSubjects {
		table = append(table, classifierTableCase{subject, MatchRequest{Kind: subjectKindLiteral, Subject: subject}, ModeContext{}, "", true})
	}
	for _, tc := range hereStringRiskyCases {
		table = append(table, classifierTableCase{tc.subject, MatchRequest{Kind: subjectKindLiteral, Subject: tc.subject}, ModeContext{}, tc.want, true})
	}
	for _, subject := range hereStringBypassSubjects {
		table = append(table, classifierTableCase{subject, MatchRequest{Kind: subjectKindLiteral, Subject: subject}, ModeContext{}, "", false})
	}
	return table
}

func TestSandboxedAutoEditsAuthorityParityWithClassifierTable(t *testing.T) {
	for _, tc := range classifierCommandTable(t) {
		t.Run(tc.name, func(t *testing.T) {
			authority, classifiable := ClassifyExceptional(tc.req, tc.mc)
			if authority != tc.authority || classifiable != tc.classifiable {
				t.Fatalf("ClassifyExceptional = (%q, %v), want (%q, %v)", authority, classifiable, tc.authority, tc.classifiable)
			}
			want := tc.authority
			if want == "file deletion" || !tc.classifiable {
				want = ""
			}
			if got := SandboxedAutoEditsAuthority(tc.req, tc.mc); got != want {
				t.Fatalf("SandboxedAutoEditsAuthority = %q, want %q", got, want)
			}
		})
	}
}

func TestSandboxedAutoEditsAuthorityChecksEveryStage(t *testing.T) {
	for _, tc := range []struct{ source, classified, sandboxed string }{
		{`rm -rf build`, "file deletion", ""},
		{`rm x && touch y`, "file deletion", ""},
		{`git clean -fdx`, "file deletion", ""},
		{`find . -delete`, "file deletion", ""},
		{`bash -c 'rm x'`, "file deletion", ""},
		{`nice rm x`, "file deletion", ""},
		{`rm x && git rebase main`, "file deletion", "VCS history rewrite"},
		{`git rebase main; rm x`, "file deletion", "VCS history rewrite"},
		{`rm x | hg strip .`, "file deletion", "VCS history rewrite"},
		{`rm x; curl y`, "network access", "network access"},
		{`git reset --hard && git push`, "network access", "network access"},
		{`rm x && command git push`, "network access", "network access"},
		{`rm x && nice git push`, "network access", "network access"},
		{`rm x | xargs git push`, "network access", "network access"},
		{`rm x; bash -c 'git push'`, "network access", "network access"},
		{`rm x && git commit --amend`, "file deletion", "VCS history rewrite"},
		{`git commit --amend -m clean`, "file deletion", "VCS history rewrite"},
		{`find . -delete && hg histedit`, "file deletion", "VCS history rewrite"},
		{`which -a x; file "$(which x)"`, "", ""},
		{`env PATH="/d:$PATH" /abs/check.sh`, "", ""},
	} {
		t.Run(tc.source, func(t *testing.T) {
			req, mc := shellCtx(t, tc.source)
			if authority, _ := ClassifyExceptional(req, mc); authority != tc.classified {
				t.Fatalf("ClassifyExceptional = %q, want %q", authority, tc.classified)
			}
			if got := SandboxedAutoEditsAuthority(req, mc); got != tc.sandboxed {
				t.Fatalf("SandboxedAutoEditsAuthority = %q, want %q", got, tc.sandboxed)
			}
		})
	}
}

func TestClassifyExceptionalShellStagesWithoutHereStringUnchanged(t *testing.T) {
	for _, subject := range []string{`bash --version`, `bash script.sh`, `echo 'rm -rf x' | bash`, `printf 'rm x' | sh`} {
		if authority, classifiable := classifyLiteralExceptional(subject); authority != "" || !classifiable {
			t.Fatalf("ClassifyExceptional(%q) = (%q, %v), want (\"\", true)", subject, authority, classifiable)
		}
	}
}
