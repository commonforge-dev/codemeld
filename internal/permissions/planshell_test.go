package permissions

import (
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

func shellCtx(t *testing.T, input string) (MatchRequest, ModeContext) {
	t.Helper()
	split, err := SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
	}
	mc := ModeContext{Stages: split.Stages, LiteralRoute: split.LiteralRoute}
	if split.LiteralRoute {
		canon, err := CanonicalLiteralForm(split.LiteralInput)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q) returned error: %v", split.LiteralInput, err)
		}
		return MatchRequest{Kind: subjectKindLiteral, Subject: canon}, mc
	}
	first := split.Stages[0]
	return MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(first.Tokens, " "), SubjectTokens: first.Tokens}, mc
}

func policyIsNameOnly(p commandPolicy) bool {
	return p.readOnlySubcommands == nil && p.validator == nil && len(p.denyFlags) == 0 &&
		len(p.subcommandDenyFlags) == 0 && !p.argSensitive
}

func TestReadOnlyExecutableSetUnchanged(t *testing.T) {
	want := []string{
		"basename", "cat", "cmp", "col", "column", "cut", "dirname", "du", "echo", "grep",
		"head", "id", "jq", "ls", "nl", "od", "printenv", "printf", "pwd", "readlink", "realpath",
		"stat", "tr", "true", "uname", "wc", "which", "whoami",
	}

	got := make([]string, 0, len(commandPolicies))
	for name, policy := range commandPolicies {
		if policyIsNameOnly(policy) {
			got = append(got, name)
		}
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("name-only allowlist = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("name-only allowlist = %v, want exactly %v", got, want)
		}
	}
	for _, excluded := range []string{"find", "tree", "hostname", "diff", "sort", "rg", "file", "df", "tail", "awk", "jj"} {
		if policy, ok := commandPolicies[excluded]; ok && policyIsNameOnly(policy) {
			t.Fatalf("%q must not be a name-only allowlist entry: an executable-only check cannot reject its mutating flags", excluded)
		}
	}
	for _, name := range []string{"test", "["} {
		policy, ok := commandPolicies[name]
		if !ok {
			t.Fatalf("%q is not configured, want an argument-sensitive pass-through policy", name)
		}
		if !policy.argSensitive || policy.validator == nil ||
			reflect.ValueOf(policy.validator).Pointer() != reflect.ValueOf(testStageReadOnly).Pointer() {
			t.Fatalf("%q policy = %+v, want argSensitive with the testStageReadOnly validator (sh -c selects a shell builtin with a broader expression surface)", name, policy)
		}
		if policy.readOnlySubcommands != nil || len(policy.denyFlags) != 0 || len(policy.subcommandDenyFlags) != 0 || len(policy.platforms) != 0 {
			t.Fatalf("%q policy = %+v, want a pass-through policy with no subcommands, deny flags, or platform restriction", name, policy)
		}
	}
}

func TestCmpOdTestDirectFormsReadOnly(t *testing.T) {
	for _, input := range []string{
		"cmp a b",
		"cmp -s a b",
		"od -An -tx1 -N20 f",
		"test -x pers.sh",
		"[ -f f ]",
		"od -c f | head",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) took the literal route, want direct", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
	const staged = "test -x f && cmp a b"
	for _, s := range stagedCtxs(t, "", staged) {
		if got := classifyReadOnlyShell(s.req, s.mc); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q stage %q) = %q, want read_only", staged, s.req.Subject, got)
		}
	}
}

func TestCmpOdTestDirectFormsAutoAllowInEveryMode(t *testing.T) {
	for _, mode := range []string{"build", modeAutoEdits, modePlan} {
		for _, input := range []string{
			"cmp a b",
			"cmp -s a b",
			"od -An -tx1 -N20 f",
			"test -x pers.sh",
			"[ -f f ]",
			"od -c f | head",
		} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(neverPrompt, nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				assertModeAutoAllow(t, f, d)
			})
		}
		t.Run(mode+"/test -x f && cmp a b", func(t *testing.T) {
			for _, s := range stagedCtxs(t, mode, "test -x f && cmp a b") {
				f := newFixture(neverPrompt, nil)
				d := mustAuthorizeMode(t, s.req, s.mc, f.deps)
				assertModeAutoAllow(t, f, d)
			}
		})
	}
}

func TestCmpOdTestRouteGuardsUnchanged(t *testing.T) {
	for _, input := range []string{
		"cmp a b > out",
		"od -c f >> log",
		"LD_PRELOAD=/tmp/x.so cmp a b",
		"FOO=1 test -x f",
		"test -x f && rm f",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
	t.Run("staged test -x f && rm f", func(t *testing.T) {
		for _, s := range stagedCtxs(t, "", "test -x f && rm f") {
			if classifyReadOnlyShell(s.req, s.mc) == ClassMutating {
				return
			}
		}
		t.Fatal("every stage of \"test -x f && rm f\" classified read_only, want the rm stage to deny the compound")
	})
}

func TestTestBuiltinExpressionsOnShellRouteNeverAutoAllow(t *testing.T) {
	inputs := []string{
		`test -v 'x[$(printf INJECTED >&2)]' && cmp a b`,
		`[ -v 'x[$(printf INJECTED >&2)]' ] && cmp a b`,
		`test -v "x[$y]" 2>/dev/null`,
		`[ -v "x[$y]" ] 2>/dev/null`,
		`test -v "x[$y]" 2>/dev/null && cmp a b`,
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (sh -c would evaluate a shell builtin expression)", input, got)
			}
		})
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				if f.cap.prompts != 1 {
					t.Fatalf("%q prompted %d times in %s, want 1", input, f.cap.prompts, mode)
				}
				if d.ReadOnlyAuto {
					t.Fatalf("%q in %s carried the read-only mode-auto source: %+v", input, mode, d)
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
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q = %+v, want deny with an envelope", input, d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a denied request must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestReadOnlyAllowlistIncludesPlainEchoOnly(t *testing.T) {
	for _, input := range []string{`echo hi`, `echo HOME=$HOME`, `echo a b c | grep a`} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (plain direct echo)", input, got)
		}
	}
	for _, input := range []string{`echo hi > out`, `sh -c "echo hi"`, `FOO=bar echo hi`} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (echo only auto-allows as a plain direct command)", input, got)
		}
	}
}

func TestClassifyReadOnlyShellEachAllowlistedExecutableIsReadOnly(t *testing.T) {
	for name, policy := range commandPolicies {
		if !policyIsNameOnly(policy) {
			continue
		}
		if got := classifyReadOnlyShell(shellCtx(t, name)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (allowlisted executable)", name, got)
		}
	}
}

func TestClassifyReadOnlyShellReadOnlyPipelines(t *testing.T) {
	for _, input := range []string{
		"ls",
		"ls -la /tmp",
		"rg foo | head",
		"cat a.txt | grep x | wc -l",
		"tail -n 20 a.log | grep err",
		"pwd",
		"du -sh .",
		"df -h",
		"which rg",
		"cat a.txt | nl",
		"printenv PATH | column -t",
		"jq . session.json",
		"printf done",
		"printf '%s\\n' a b",
		"jq . session.json | head",
		"cat session.json | jq .",
		"printf hello | grep h",
		"cut -f1",
		"tr -d ' '",
		"cat a.txt | cut -f1 | tr -d ' '",
		"sort -u",
		"env ls",
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
		}
	}
}

func TestClassifyReadOnlyShellMutating(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"env assignment on allowlisted exec", `LD_PRELOAD=/x/evil.so ls`},
		{"env assignment on listed command cat", `LD_PRELOAD=/x/evil.so cat`},
		{"plain env assignment", `FOO=bar ls`},
		{"env assignment on a later stage", `ls | FOO=bar grep x`},
		{"wrapper route", `sh -c "ls"`},
		{"redirection", `ls > out`},
		{"backgrounding literal route", `ls &`},
		{"subshell literal route", `(cat a)`},
		{"non-allowlisted executable", `rm -rf x`},
		{"unknown executable", `frobnicate --whatever x`},
		{"mutating-capable find", `find . -delete`},
		{"find with -exec", `find . -exec rm {} +`},
		{"tree writes a file with -o", `tree -o out.txt`},
		{"diff runs pr with -l", `diff -l a b`},
		{"hostname can set the system hostname", `hostname newname`},
		{"sed mutates in place with -i", `sed -i s/a/b/ f`},
		{"env clearing the environment carries assignments", `env -i PATH=/usr/bin ls`},
		{"env assigning the environment carries assignments", `env FOO=bar ls`},
		{"pipeline with one non-allowlisted stage", `cat a | tee out.txt`},
		{"sort writes a file with separated -o", `sort -o out.txt f`},
		{"sort writes a file with glued -o", `sort -oout.txt f`},
		{"sort writes a file with equals --output", `sort --output=out.txt f`},
		{"sort writes a file with separated --output", `sort --output out.txt f`},
		{"sort writes a file with abbreviated --output", `sort --out=out.txt f`},
		{"sort runs a program with --compress-program", `sort --compress-program gzip f`},
		{"sort runs a program with abbreviated --compress-program", `sort --comp gzip f`},
		{"jq redirection", `jq . session.json > out`},
		{"printf redirection", `printf done > out`},
		{"env assignment on jq", `LD_PRELOAD=/x/evil.so jq . session.json`},
		{"env assignment on printf", `LD_PRELOAD=/x/evil.so printf done`},
		{"wrapper on printf", `sh -c "printf done"`},
		{"pipeline with printf then non-allowlisted stage", `printf done | tee out.txt`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, tc.input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", tc.input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellEnvAssignmentDeniedDespiteAllowlistedExecutable(t *testing.T) {
	req, mc := shellCtx(t, `LD_PRELOAD=/x/evil.so ls`)

	if len(mc.Stages) != 1 {
		t.Fatalf("Stages = %+v, want one direct stage", mc.Stages)
	}
	stage := mc.Stages[0]
	if len(stage.Tokens) == 0 || stage.Tokens[0] != "ls" {
		t.Fatalf("canonical executable = %v, want first token \"ls\" (allowlisted)", stage.Tokens)
	}
	if policy, ok := commandPolicies[stage.Tokens[0]]; !ok || !policyIsNameOnly(policy) {
		t.Fatal("test premise broken: \"ls\" should be allowlisted")
	}
	if len(stage.Assignments) == 0 {
		t.Fatalf("Assignments = %v, want the stripped LD_PRELOAD assignment preserved", stage.Assignments)
	}
	if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
		t.Fatalf("classifyReadOnlyShell = %q, want mutating (env assignment, not the executable, must deny)", got)
	}
}

func TestClassifyReadOnlyShellRejectedConstructMutating(t *testing.T) {
	for _, input := range []string{`cat $(echo x)`, `jq . $(echo session.json)`, `printf $(echo done)`} {
		split, err := SplitCommand(input)
		if err != nil {
			t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
		}
		if split.AllowedShell {
			t.Fatalf("SplitCommand(%q).AllowedShell = true, want false (rejected construct)", input)
		}
		mc := ModeContext{Stages: split.Stages, LiteralRoute: split.LiteralRoute}
		if got := classifyReadOnlyShell(MatchRequest{}, mc); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q rejected) = %q, want mutating", input, got)
		}
	}
}

func TestClassifyReadOnlyShellAndCompoundLiteralMutating(t *testing.T) {
	for _, input := range []string{`ls && rm x`, `ls ; rm x`, `ls || rm x`} {
		split, err := SplitCommand(input)
		if err != nil {
			t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
		}
		if !split.AllowedShell || !split.LiteralRoute {
			t.Fatalf("SplitCommand(%q) = {allowed:%v literal:%v}, want literal route", input, split.AllowedShell, split.LiteralRoute)
		}
		req := MatchRequest{Kind: subjectKindLiteral, Subject: split.LiteralInput}
		mc := ModeContext{Stages: split.Stages, LiteralRoute: split.LiteralRoute}
		if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q literal) = %q, want mutating", input, got)
		}
	}
}

func TestVCSReadOnlySubcommandSetsAreCurated(t *testing.T) {
	want := map[string][]string{
		"hg": {
			"admin::verify", "annotate", "blame", "bookmark", "bookmarks", "branch", "branches", "cat",
			"diff", "export", "files", "grep", "heads", "help", "history", "id", "identify", "locate",
			"log", "manifest", "parents", "paths", "phase", "resolve", "root", "st", "status", "sum",
			"summary", "tags", "tip", "verify", "version",
		},
		"git": {"blame", "cat-file", "check-ignore", "describe", "diff", "for-each-ref", "grep", "help", "log", "ls-files", "ls-tree", "merge-base", "name-rev", "rev-list", "shortlog", "show", "show-ref", "status"},
		"jj":  {"diff", "evolog", "help", "interdiff", "log", "root", "show", "st", "status", "version"},
	}
	wantGlobalValueFlags := map[string][]string{"hg": {"--cwd"}, "git": {"-C"}, "jj": {"--color"}}
	for prog, wantSubs := range want {
		policy, ok := commandPolicies[prog]
		if !ok {
			t.Fatalf("commandPolicies missing %q", prog)
		}
		got := make([]string, 0, len(policy.readOnlySubcommands))
		for sub := range policy.readOnlySubcommands {
			got = append(got, sub)
		}
		sort.Strings(got)
		if len(got) != len(wantSubs) {
			t.Fatalf("%s subcommands = %v, want exactly %v", prog, got, wantSubs)
		}
		for i := range wantSubs {
			if got[i] != wantSubs[i] {
				t.Fatalf("%s subcommands = %v, want exactly %v", prog, got, wantSubs)
			}
		}
	}
	for prog, wantFlags := range wantGlobalValueFlags {
		got := make([]string, 0, len(commandPolicies[prog].globalValueFlags))
		for flag := range commandPolicies[prog].globalValueFlags {
			got = append(got, flag)
		}
		sort.Strings(got)
		if !equalStrings(got, wantFlags) {
			t.Fatalf("%s globalValueFlags = %v, want exactly %v", prog, got, wantFlags)
		}
	}
	wantDenyFlags := map[string][]string{
		"hg": {
			"--config", "-R", "--repository", "--pager", "-o", "--output",
			"--ssh", "--remotecmd", "--insecure", "--debugger", "-T", "--template", "--style",
		},
		"git": {"-c", "--config-env", "--git-dir", "--work-tree", "--exec-path", "--output"},
		"jj": {
			"--config", "--config-file", "-R", "--repository", "--at-operation", "--at-op",
			"--tool", "-T", "--template",
		},
	}
	for prog, wantFlags := range wantDenyFlags {
		if !equalStrings(commandPolicies[prog].denyFlags, wantFlags) {
			t.Fatalf("%s denyFlags = %v, want exactly %v", prog, commandPolicies[prog].denyFlags, wantFlags)
		}
	}
	textconv := scopedDenyFlag{flag: "--textconv", safeSpellings: []string{"--text"}}
	wantSubcommandDenyFlags := map[string]map[string][]scopedDenyFlag{
		"hg": {
			"id":            {{flag: "-e"}},
			"identify":      {{flag: "-e"}},
			"admin::verify": {{flag: "--option"}},
		},
		"git": {
			"grep":     {{flag: "-O"}, {flag: "--open-files-in-pager"}, textconv, {flag: "--ext-grep"}},
			"diff":     {textconv},
			"log":      {textconv},
			"show":     {textconv},
			"cat-file": {{flag: "--filters"}, {flag: "--textconv"}},
			"help":     {{flag: "-w"}, {flag: "--web"}},
		},
	}
	for name, policy := range commandPolicies {
		want := wantSubcommandDenyFlags[name]
		if len(policy.subcommandDenyFlags) != len(want) {
			t.Fatalf("%s subcommandDenyFlags = %v, want exactly %v", name, policy.subcommandDenyFlags, want)
		}
		for sub, wantFlags := range want {
			if !reflect.DeepEqual(policy.subcommandDenyFlags[sub], wantFlags) {
				t.Fatalf("%s %s subcommandDenyFlags = %v, want exactly %v", name, sub, policy.subcommandDenyFlags[sub], wantFlags)
			}
		}
		for sub, flags := range policy.subcommandDenyFlags {
			if _, ok := policy.readOnlySubcommands[sub]; !ok {
				t.Fatalf("%s carries subcommandDenyFlags %v for unadmitted subcommand %q", name, flags, sub)
			}
		}
		for sub := range policy.subcommandArgs {
			if _, ok := policy.readOnlySubcommands[sub]; !ok {
				t.Fatalf("%s carries a subcommandArgs check for unadmitted subcommand %q", name, sub)
			}
		}
	}
	wantSubcommandArgs := map[string][]string{
		"hg":  {"bookmark", "bookmarks", "branch", "id", "identify", "phase", "resolve"},
		"git": {"check-ignore"},
	}
	for name, policy := range commandPolicies {
		got := make([]string, 0, len(policy.subcommandArgs))
		for sub := range policy.subcommandArgs {
			got = append(got, sub)
		}
		sort.Strings(got)
		if !equalStrings(got, wantSubcommandArgs[name]) {
			t.Fatalf("%s subcommandArgs = %v, want exactly %v", name, got, wantSubcommandArgs[name])
		}
	}
	for prog := range wantGlobalValueFlags {
		for _, flag := range commandPolicies[prog].denyFlags {
			if _, ok := commandPolicies[prog].globalValueFlags[flag]; ok {
				t.Fatalf("%s lists %q as both a global value flag and a deny flag", prog, flag)
			}
		}
	}
	for name, policy := range commandPolicies {
		if _, ok := wantGlobalValueFlags[name]; !ok && len(policy.globalValueFlags) > 0 {
			t.Fatalf("%s carries globalValueFlags %v, want none", name, policy.globalValueFlags)
		}
	}
	configured := make([]string, 0)
	for name, policy := range commandPolicies {
		if !policyIsNameOnly(policy) {
			configured = append(configured, name)
		}
	}
	sort.Strings(configured)
	wantConfigured := []string{"[", "awk", "bash", "command", "date", "df", "diff", "dmesg", "env", "file", "find", "free", "git", "hg", "jj", "journalctl", "lsof", "pgrep", "pidof", "ps", "pstree", "rg", "sed", "sh", "sort", "ss", "tail", "test", "top", "type", "uniq", "uptime", "vmstat"}
	if len(configured) != len(wantConfigured) {
		t.Fatalf("configured (non-name-only) policies = %v, want exactly %v", configured, wantConfigured)
	}
	for i := range wantConfigured {
		if configured[i] != wantConfigured[i] {
			t.Fatalf("configured (non-name-only) policies = %v, want exactly %v", configured, wantConfigured)
		}
	}
	find, ok := commandPolicies["find"]
	if !ok {
		t.Fatal("commandPolicies missing \"find\"")
	}
	if find.readOnlySubcommands != nil {
		t.Fatalf("find policy must carry no readOnlySubcommands (it is validator-based), got %v", find.readOnlySubcommands)
	}
	if find.validator == nil {
		t.Fatal("find policy must carry a validator (argument-sensitive carve-out)")
	}
}

func TestClassifyReadOnlyShellVCSReadOnly(t *testing.T) {
	for _, input := range []string{
		"hg log",
		"hg log --limit 20",
		"hg status",
		"hg diff",
		"hg cat -r 3 path/to/file",
		"hg summary",
		"hg files",
		"hg files path/to/dir",
		"hg help",
		"hg help amend",
		"hg grep -n -i proposal set:**.md",
		"hg grep pattern",
		"hg root",
		"hg id -nibt",
		"hg id",
		"hg manifest proposals",
		"hg manifest",
		"git log",
		"git log --oneline -n 20",
		"git status",
		"git status --short",
		"git diff",
		"git show HEAD:path/to/file",
		"git ls-files",
		"git ls-files path/to/dir",
		"git help",
		"git help commit",
		"hg parents",
		"hg heads",
		"hg --cwd main status",
		"hg --cwd main cat -r 9c7465b91819 docs/index.md",
		"hg --cwd main parents",
		"hg --cwd main heads",
		"hg --cwd /abs/path log",
		"hg --cwd=main status",
		"git -C /dir log",
		"git -C /dir status",
		"git log -C",
		"git show -C",
		"git diff -O order",
		"git diff -Oorder",
		"git diff --order-file order",
		"git log -O order",
		"git show -O order HEAD",
		"git -C /dir diff -O order",
		"git grep --text x",
		"git diff --text",
		"git log --text",
		"git show --text",
		"git -C /dir grep --text x",
		"git grep --extended-regexp x",
		"git grep --exte x",
		"git grep -e a --or -e b",
		"git grep -w pattern",
		"git rev-list --filter=blob:none HEAD",
		"git rev-list --objects --filter=blob:none HEAD",
		"git cat-file -p HEAD:f",
		"git cat-file -t HEAD",
		"git cat-file --batch",
		"git cat-file --batch-check",
		"git -C /dir cat-file -p HEAD:f",
		"git diff -w",
		"git blame -w path/to/file",
		"git log -w",
		"git shortlog -w",
		"git -C /dir diff -w",
		"hg root --cwd /other",
		"hg grep --cwd /other pattern",
		"hg --cwd a --cwd b status",
		"git grep pattern",
		"git grep -n -i pattern -- path/to/dir",
		"git blame path/to/file",
		"git ls-tree HEAD",
		"git ls-tree -r --name-only HEAD path/to/dir",
		"git describe",
		"git describe --tags --always",
		"git shortlog -s -n",
		"git show-ref",
		"git show-ref --tags",
		"git for-each-ref refs/heads",
		"git for-each-ref --sort=refname refs/tags",
		"git merge-base HEAD main",
		"git merge-base --is-ancestor HEAD main",
		"git name-rev HEAD",
		"git rev-list --max-count=5 HEAD",
		"git rev-list --count HEAD",
		"git -C /dir grep pattern",
		"git -C /dir blame path/to/file",
		"git -C /dir ls-tree HEAD",
		"git -C /dir describe --tags",
		"git -C /dir shortlog -s -n",
		"git -C /dir show-ref --tags",
		"git -C /dir for-each-ref refs/heads",
		"git -C /dir merge-base HEAD main",
		"git -C /dir name-rev HEAD",
		"git -C /dir rev-list --count HEAD",
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
		}
	}
}

func TestClassifyReadOnlyShellVCSReadOnlyPipeline(t *testing.T) {
	for _, input := range []string{
		"hg log --limit 30 | head -30",
		"hg cat -r 3 file | tail -15",
		"git log | grep foo | head",
		"git log --oneline | head -30",
		"cd main && git log --oneline | head",
		"cd main && hg log | head -20",
		"cd main && hg parents",
		"hg --cwd main log | head -20",
		"git -C /dir log | head",
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
		}
	}
}

func TestClassifyReadOnlyShellJJReadOnly(t *testing.T) {
	for _, input := range []string{
		"jj status",
		"jj st",
		"jj log",
		"jj log -r @ -n 10",
		"jj log -p",
		"jj diff",
		"jj diff --types",
		"jj show",
		"jj evolog",
		"jj interdiff --from a --to b",
		"jj root",
		"jj version",
		"jj help",
		"jj help commit",
		"jj help util exec",
		"jj --color never log",
		"jj log | head -20",
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
		}
	}
}

func TestClassifyReadOnlyShellJJMutating(t *testing.T) {
	for _, input := range []string{
		// bare program: ui.default-command chooses what this runs
		"jj",
		// mutating and unknown top-level commands
		"jj commit -m x", "jj new", "jj describe -m x", "jj abandon", "jj squash",
		"jj git push", "jj undo", "jj edit @-", "jj fix", "jj run echo",
		// mixed namespaces whose nested commands mutate or execute
		"jj util exec -- id", "jj file list", "jj op log", "jj operation log",
		"jj bookmark list", "jj tag list", "jj workspace root", "jj config set --user ui.pager x",
		// configuration and repository retargeting, separate-value and attached forms
		"jj log --config ui.pager=x", "jj log --config=ui.pager=x",
		"jj log --config-file /tmp/evil.toml", "jj log --config-file=/tmp/evil.toml",
		"jj -R /other status", "jj -R/other status", "jj --repository /other status",
		"jj --repository=/other status", "jj --at-operation @- log", "jj --at-op=@- log",
		"jj log --at-operation @-",
		// external diff programs
		"jj diff --tool evil", "jj diff --tool=evil", "jj show --tool evil",
		"jj log -p --tool evil", "jj evolog --tool evil", "jj interdiff --tool evil",
		// templates, including the short form hidden inside a cluster
		"jj log -T '{description}'", "jj log --template '{description}'", "jj log -Tjson",
		"jj log -pT '{description}'",
		// leading global options the subcommand walk cannot resolve
		"jj --color log", "jj --no-pager log", "jj --quiet status", "jj --debug status",
		"jj --ignore-working-copy status",
		// near-miss spellings: jj 0.44 accepts no abbreviation, so neither does the policy
		"jj stat", "jj --colour never log", "jj --unknown-flag log", "jj --colo never log",
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
		}
	}
}

func TestClassifyReadOnlyShellJJLiteralNeverAutoAllows(t *testing.T) {
	for _, input := range []string{
		"jj status 2>/dev/null",
		`sh -c "jj status"`,
		`sh -c "jj status && ls"`,
		"jj status > /dev/null",
		`sh -c "jj status | wc -l"`,
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating: the literal route cannot carry jj's argv isolation", input, got)
		}
	}
}

func TestClassifyReadOnlyShellJJClearedEnvironmentNeverAutoAllows(t *testing.T) {
	for _, input := range []string{
		"env -i PATH=/usr/bin jj diff",
		"env -i PATH=/usr/bin jj status",
		"env -i PATH=/usr/bin jj log | head -20",
	} {
		req, mc := shellCtx(t, input)
		if len(mc.Stages) == 0 {
			t.Fatalf("%q produced no direct stages, so the cleared-environment case is untested", input)
		}
		stage := mc.Stages[0]
		if stage.Route != RouteDirect || !stage.ClearEnvironment || len(stage.Tokens) == 0 || stage.Tokens[0] != "jj" {
			t.Fatalf("%q normalized to %+v, want a direct cleared-environment jj stage", input, stage)
		}
		if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating: a cleared-environment stage selects its own jj and cannot carry the owned environment", input, got)
		}
	}
}

func TestClassifyReadOnlyShellVCSMutating(t *testing.T) {
	cases := []string{
		// hg mutating subcommands
		"hg commit -m x", "hg push", "hg pull", "hg rebase", "hg strip -r 3",
		"hg debugstrip -r 3", "hg update", "hg merge", "hg backout -r 3", "hg phase -p 3",
		"hg revert file", "hg add file", "hg branch feature", "hg resolve --mark file",
		// hg bare program / unknown subcommand
		"hg", "hg forget file",
		// hg flag bypass on an admitted subcommand
		"hg log --config=alias.log=!x", "hg -R /other log", "hg --repository /other log",
		"hg log --pager x", "hg cat -o out.txt PATH",
		"hg cat --output=out.txt PATH", "hg cat -oout.txt PATH",
		"hg files --output x", "hg files --out=x", "hg files -o x",
		// hg prefix-abbreviation bypass on an admitted subcommand (hg accepts unambiguous prefixes)
		"hg log --repo /other", "hg log --repo=/other", "hg log --pag cat", "hg log --pag=cat",
		"hg cat --out out.txt PATH", "hg cat --out=out.txt PATH", "hg log --conf=alias.log=!x",
		"hg --cw /other log", "hg --cw main status",
		"hg -R /other/repo log", "hg --repo /other/repo status",
		"hg grep --config=alias.x=x", "hg grep --conf=alias.x=x", "hg grep -R /other pattern",
		"hg grep --pager cat pattern",
		"hg manifest --output FILE", "hg manifest --out=FILE", "hg manifest -o FILE",
		"hg root -R /other", "hg id --config=x.y=z", "hg id -o out.txt",
		"hg --pager cat log", "hg --pag cat root",
		"hg bookmark name",
		// git mutating subcommands
		"git commit -m x", "git push", "git pull", "git fetch", "git checkout main",
		"git switch main", "git reset --hard", "git merge x", "git rebase main",
		"git restore file", "git add file", "git stash", "git branch feature",
		"git branch -d x", "git clean -fd",
		"git tag v1", "git stash list", "git worktree add d", "git reflog expire",
		"git config user.name x", "git ls-remote", "git archive -o out.tar HEAD",
		"git symbolic-ref HEAD refs/heads/x", "git notes add -m x", "git bisect start",
		"git remote add o u", "git rev-parse --git-dir",
		// git bare program / unknown subcommand
		"git", "git rev-parse HEAD",
		// git flag bypass on an admitted subcommand
		"git grep -O vim x", "git grep -Ovim x", "git grep --open-files-in-pager=vim x",
		"git grep --open-files-in-pager vim x", "git -C /dir grep -O vim x",
		"git grep -O", "git grep pattern -O vim", "git -C /dir grep --open-files-in-pager=vim x",
		"git grep --op=vim x", "git -C /dir grep --open-files-in-p=vim x",
		"git grep --ope=cat x", "git grep --open=cat x", "git grep --o x",
		"git -C /dir -c core.pager=sh grep x", "git blame --output=f x",
		"git ls-tree --git-dir=/other HEAD",
		// git --textconv and its abbreviations on each admitting subcommand
		"git grep --textconv x", "git grep --textcon x", "git grep --textco x", "git grep --textc x",
		"git -C /dir grep --textcon x", "git grep --textconv=x y",
		"git diff --textconv", "git log --textconv", "git show --textconv",
		"git diff --textcon", "git log --textc", "git show --tex",
		// git grep --ext-grep and its abbreviations
		"git grep --ext-grep x", "git grep --ext-gre x", "git grep --ext-g x", "git grep --ext- x",
		"git grep --ext x", "git -C /dir grep --ext-g x",
		// git cat-file --filters/--textconv abbreviations; cat-file has no `--text`, so that spelling is one too
		"git cat-file --filters HEAD:f", "git cat-file --filter HEAD:f", "git cat-file --filte HEAD:f",
		"git cat-file --filt HEAD:f", "git cat-file --fil HEAD:f", "git cat-file --fi HEAD:f",
		"git cat-file --f HEAD:f", "git -C /dir cat-file --fil HEAD:f",
		"git cat-file --textconv HEAD:f", "git cat-file --text HEAD:f", "git cat-file --tex HEAD:f",
		"git cat-file --t HEAD:f", "git cat-file --filters --path=f HEAD",
		"git rev-list --exec-path=/tmp HEAD",
		"git -c core.pager=x log", "git -c core.fsmonitor=x status",
		"git --git-dir=/other/.git log", "git --work-tree=/other status",
		"git --exec-path=/tmp log", "git diff --output=out.txt", "git show --output=out.txt HEAD",
		"git --config-env=x.y=Z log",
		"git ls-files --output=x", "git ls-files --output x",
		"git help -w", "git help --web", "git help -w commit", "git help --web commit",
		"git help --we", "git help --we status", "git help --w status", "git -C /dir help --we status",
		// a cwd value named like an admitted subcommand must not become the subcommand
		"hg --cwd status commit", "git -C log commit",
		"hg --cwd log push", "git -C status commit -m x",
		// mutating subcommands behind an accepted cwd flag
		"hg --cwd main commit -m x", "hg --cwd=main commit",
		"git -C /dir push", "git -C /dir checkout -b x",
		// glued and value-less cwd spellings
		"git -C/dir push", "git -C/dir log", "hg --cwd", "git -C",
		"hg --cwd main", "hg --cwd=main", "git -C /dir",
		// deny-listed flag behind an accepted cwd flag
		"hg --cwd main --config alias.x=!sh log", "hg --cwd main -R /other log",
		"hg --cwd main log --pager sh", "hg --cwd main cat -o out.txt f",
		"hg --cwd main --repo /other log", "hg --cwd main log --conf=alias.x=!sh",
		"git -C /dir -c core.pager=sh log", "git -C /dir --git-dir=/other log",
		"git -C /dir --exec-path=/tmp log", "git -C /dir diff --output=f",
		"git -C /dir --work-tree=/other status", "git -C /dir --config-env=x.y=Z log",
		// an unrecognized leading flag yields no subcommand
		"hg -v log", "hg --color never status", "git --no-pager log", "hg --cwd main -v log",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

// The rows are the verdict of a live git 2.43 probe of every prefix of each deny flag: what git
// resolves to the flag must classify mutating, what it refuses is recorded read-only, so "no
// accepted abbreviation" is evidence rather than an assumption. A new deny flag fails here until it
// is probed the same way.
func TestGitDenyFlagAbbreviationVerdicts(t *testing.T) {
	type flagKey struct{ sub, flag string }
	type verdict struct {
		mutating []string
		readOnly []string
	}
	audited := map[flagKey]verdict{
		{"", "-c"}:           {mutating: []string{"git -c core.pager=sh log"}},
		{"", "--config-env"}: {mutating: []string{"git --config-env=x.y=Z log"}, readOnly: []string{"git log --config-en=x.y=Z"}},
		{"", "--git-dir"}:    {mutating: []string{"git --git-dir=/other log"}, readOnly: []string{"git log --git-di=/other"}},
		{"", "--work-tree"}:  {mutating: []string{"git --work-tree=/other status"}, readOnly: []string{"git status --work-tre=/other"}},
		{"", "--exec-path"}:  {mutating: []string{"git --exec-path=/tmp log"}, readOnly: []string{"git log --exec-pat=/tmp"}},
		{"", "--output"}: {
			mutating: []string{"git diff --output=out.txt", "git log --output=out.txt"},
			readOnly: []string{"git diff --outp=out.txt", "git diff --outpu=out.txt", "git log --outp=out.txt"},
		},
		{"grep", "-O"}: {
			mutating: []string{"git grep -O vim x", "git grep -Ovim x"},
			readOnly: []string{"git diff -O order", "git log -O order"},
		},
		{"grep", "--open-files-in-pager"}: {
			mutating: []string{"git grep --open-files-in-pager=vim x", "git grep --op=vim x", "git grep --ope=vim x", "git grep --open=vim x"},
		},
		{"grep", "--textconv"}: {
			mutating: []string{"git grep --textconv x", "git grep --textcon x", "git grep --textc x"},
			readOnly: []string{"git grep --text x"},
		},
		{"grep", "--ext-grep"}: {
			mutating: []string{"git grep --ext-grep x", "git grep --ext-gre x", "git grep --ext- x"},
			readOnly: []string{"git grep --extended-regexp x", "git grep --exte x"},
		},
		{"diff", "--textconv"}: {mutating: []string{"git diff --textconv"}, readOnly: []string{"git diff --text"}},
		{"log", "--textconv"}:  {mutating: []string{"git log --textconv"}, readOnly: []string{"git log --text"}},
		{"show", "--textconv"}: {mutating: []string{"git show --textconv"}, readOnly: []string{"git show --text"}},
		{"cat-file", "--filters"}: {
			mutating: []string{"git cat-file --filters HEAD:f", "git cat-file --filter HEAD:f", "git cat-file --fi HEAD:f"},
			readOnly: []string{"git cat-file -p HEAD:f"},
		},
		{"cat-file", "--textconv"}: {
			mutating: []string{"git cat-file --textconv HEAD:f", "git cat-file --tex HEAD:f", "git cat-file --text HEAD:f"},
		},
		{"help", "-w"}: {
			mutating: []string{"git help -w status"},
			readOnly: []string{"git diff -w", "git blame -w f", "git log -w", "git shortlog -w"},
		},
		{"help", "--web"}: {
			mutating: []string{"git help --web status", "git help --we status", "git help --w status"},
		},
	}
	policy := commandPolicies["git"]
	inPolicy := map[flagKey]bool{}
	for _, f := range policy.denyFlags {
		inPolicy[flagKey{"", f}] = true
	}
	for sub, flags := range policy.subcommandDenyFlags {
		for _, f := range flags {
			inPolicy[flagKey{sub, f.flag}] = true
		}
	}
	for key := range inPolicy {
		if _, ok := audited[key]; !ok {
			t.Fatalf("git deny flag %q (subcommand %q) has no recorded abbreviation verdict", key.flag, key.sub)
		}
	}
	for key, v := range audited {
		if !inPolicy[key] {
			t.Fatalf("audit records git deny flag %q (subcommand %q) that the policy no longer carries", key.flag, key.sub)
		}
		if len(v.mutating) == 0 {
			t.Fatalf("git deny flag %q (subcommand %q) records no denied spelling", key.flag, key.sub)
		}
		for _, input := range v.mutating {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		}
		for _, input := range v.readOnly {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		}
	}
}

func TestGitScopedDenyFlagPrefixesAllClassifyMutating(t *testing.T) {
	for sub, flags := range commandPolicies["git"].subcommandDenyFlags {
		for _, f := range flags {
			if !strings.HasPrefix(f.flag, "--") {
				continue
			}
			for i := 3; i <= len(f.flag); i++ {
				spelling := f.flag[:i]
				want := ClassMutating
				if slices.Contains(f.safeSpellings, spelling) {
					want = ClassReadOnly
				}
				for _, input := range []string{
					"git " + sub + " " + spelling,
					"git -C /dir " + sub + " " + spelling,
				} {
					t.Run(input, func(t *testing.T) {
						if got := classifyReadOnlyShell(shellCtx(t, input)); got != want {
							t.Fatalf("classifyReadOnlyShell(%q) = %q, want %q", input, got, want)
						}
					})
				}
			}
			for _, safe := range f.safeSpellings {
				input := "git " + sub + " " + safe
				t.Run(input, func(t *testing.T) {
					if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
						t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
					}
				})
			}
		}
	}
}

func TestClassifyReadOnlyShellDate(t *testing.T) {
	for _, input := range []string{
		"date",
		"date +%F",
		"date -u",
		"date -d yesterday +%s",
		"date -Iseconds",
		"date +%F | head -1",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
	for _, input := range []string{
		"date -s now",
		"date -s 2026-07-28",
		"date --set=now",
		"date --set now",
		"date --se now",
		"date --se=now",
		"date --s now",
		"date -u -s now",
		"date +%F > out",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func assertShellClass(t *testing.T, inputs []string, want OperationClass) {
	t.Helper()
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != want {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestClassifyReadOnlyShellRipgrep(t *testing.T) {
	assertShellClass(t, []string{
		"rg needle src",
		"rg foo | head",
		"rg --pre-glob=*.pdf needle src",
		"rg -n --hidden needle src 2>/dev/null",
		"rg needle *.md",
		"rg --ignore-file .gitignore needle src",
	}, ClassReadOnly)

	assertShellClass(t, []string{
		"rg --pre=$X needle src 2>/dev/null",
		"rg --pre sh needle src",
		"rg --pre=sh needle src",
		"rg --pre=sh needle src | head",
		"rg --pre-glob=*.pdf --pre sh needle src",
		"rg --hostname-bin=id needle src",
		"rg --hostname-bin id needle src",
		"rg --hostname-bin=$X needle src",
		"rg --pre=$X needle src && ls",
		"rg -z needle src",
		"rg --search-zip needle src",
		"rg -nz needle src",
		"rg -zn needle src",
	}, ClassMutating)
}

func TestClassifyReadOnlyShellFile(t *testing.T) {
	assertShellClass(t, []string{
		"file x.md",
		"file -b x.md",
		"file -m custom.magic x.md",
		"file --mime-type x.md",
		"file --continue x.md",
		"file -bc x.md",
		"file -b x.md 2>/dev/null",
	}, ClassReadOnly)

	assertShellClass(t, []string{
		"file -C",
		"file --compile -m custom.magic",
		"file --comp -m custom.magic",
		"file -C 2>/dev/null",
		"file -C 2>/dev/null | head",
		"file -C && ls",
		"file -bC",
		"file -Cb",
		"file -z x.gz",
		"file --uncompress x.gz",
		"file -Z x.gz",
		"file --uncompress-noreport x.gz",
		"file -bz x.gz",
	}, ClassMutating)
}

func TestClassifyReadOnlyShellDf(t *testing.T) {
	assertShellClass(t, []string{
		"df",
		"df -h",
		"df --si",
		"df --output=source",
		"df -h 2>/dev/null",
	}, ClassReadOnly)

	assertShellClass(t, []string{
		"df --sync",
		"df --sy",
		"df --sync 2>/dev/null",
		"df --sync | head",
	}, ClassMutating)
}

func TestClassifyReadOnlyShellTailFollow(t *testing.T) {
	assertShellClass(t, []string{
		"tail -n 20 a.log",
		"tail -c 100 a.log",
		"tail -n 20 a.log | grep err",
		"tail -qn 5 a.log",
		"tail --retry -n 5 a.log",
	}, ClassReadOnly)

	assertShellClass(t, []string{
		"tail -f a.log",
		"tail -F a.log",
		"tail --follow a.log",
		"tail --follow=name a.log",
		"tail --fol a.log",
		"tail -qf a.log",
		"tail -f a.log | grep err",
	}, ClassMutating)
}

func TestShortFlagClusterScanIsOptInPerPolicy(t *testing.T) {
	want := []string{"diff", "file", "hg", "jj", "rg", "sort", "tail"}
	got := make([]string, 0, len(want))
	for name, policy := range commandPolicies {
		if policy.clusterShortFlags {
			got = append(got, name)
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clusterShortFlags policies = %v, want exactly %v (date must stay out: `date -Iseconds` carries its denied -s)", got, want)
	}
}

func TestShortFlagClusterCannotHideADenyFlag(t *testing.T) {
	assertShellClass(t, []string{
		"rg -nz needle src",
		"rg -zn needle src",
		"file -bC",
		"file -Cb",
		"sort -uo out.txt f",
		"sort -o out.txt f",
	}, ClassMutating)

	assertShellClass(t, []string{
		"date -Iseconds",
		"date -u",
		"date -d yesterday +%s",
		"sort -u",
		"sort -n f",
		// These two carry sort's denied `-o` and ripgrep's denied `-z` as ordinary letters of a long
		// option, which the cluster scan must not read as flags.
		"sort --zero-terminated f",
		"rg --max-filesize=1M needle src",
		"hg log",
		"git status",
		"hg id -nibt",
		"rg -n needle src",
		"file -b x.md",
	}, ClassReadOnly)
}

func TestArgDependentReadersLoseTheLiteralRouteExpansionExemption(t *testing.T) {
	assertShellClass(t, []string{
		"rg needle *.md 2>/dev/null",
		"rg x *.md 2>/dev/null | head",
		"file -b *.md 2>/dev/null",
		"df $D 2>/dev/null",
		"tail -n 5 $F 2>/dev/null",
		"rg needle ~/notes 2>/dev/null",
	}, ClassMutating)

	for _, input := range []string{"rg needle *.md", "file -b *.md"} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) took the literal route; this form must stay on the direct route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (direct route: the tokens are the final argv)", input, got)
			}
		})
	}
}

func TestVCSReadOnlyModeIndependent(t *testing.T) {
	for _, input := range []string{
		"git log --oneline | head",
		"hg grep -n -i proposal set:**.md",
		"hg root",
		"hg id -nibt",
		"hg manifest proposals",
		"hg log | sed -n 1,28p",
		"hg --cwd main cat -r 9c7465b91819 docs/index.md",
		"hg --cwd main status",
		"hg --cwd main parents",
		"hg --cwd main heads",
		"git -C /dir log",
		"git -C /dir status",
		"git grep pattern",
		"git blame path/to/file",
		"git ls-tree HEAD",
		"git describe --tags",
		"git shortlog -s -n",
		"git show-ref --tags",
		"git for-each-ref refs/heads",
		"git merge-base HEAD main",
		"git name-rev HEAD",
		"git rev-list --count HEAD",
		"git -C /dir grep pattern",
		"git -C /dir blame path/to/file",
		"git -C /dir ls-tree HEAD",
		"git -C /dir describe --tags",
		"git -C /dir shortlog -s -n",
		"git -C /dir show-ref --tags",
		"git -C /dir for-each-ref refs/heads",
		"git -C /dir merge-base HEAD main",
		"git -C /dir name-rev HEAD",
		"git -C /dir rev-list --count HEAD",
		"git cat-file -p HEAD:f",
		"git -C /dir cat-file -p HEAD:f",
		"git grep --text x",
		"git diff --text",
		"git rev-list --filter=blob:none HEAD",
		"git diff -O order",
		"git diff -w",
		"git blame -w path/to/file",
		"git log -w",
		"git shortlog -w",
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

func TestVCSCwdOptionAdversarialModePosture(t *testing.T) {
	for _, input := range []string{
		"hg --cwd status commit",
		"git -C log commit",
		"hg --cwd main commit -m x",
		"git -C /dir push",
		"hg --cwd=main commit",
		"git -C/dir push",
		"hg --cwd main --config alias.x=!sh log",
		"git -C /dir -c core.pager=sh log",
		"git -C /dir grep --open-files-in-p=vim x",
		"git grep --op=vim x",
		"git grep --textcon x",
		"git -C /dir grep --textcon x",
		"git grep --ext-g x",
		"git -C /dir grep --ext-g x",
		"git cat-file --fil HEAD:f",
		"git -C /dir cat-file --fil HEAD:f",
		"git cat-file --text HEAD:f",
		"git help --we status",
		"git -C /dir help --we status",
		"hg --cwd main resolve --li",
		"hg --cw main status",
	} {
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)

				d := mustAuthorizeMode(t, req, mc, f.deps)

				wantKinds(t, f.cap.kinds(), []string{"permission_prompt_shown", "permission_decision"})
				if f.cap.prompts != 1 {
					t.Fatalf("a mutating VCS command in %s must prompt, prompted %d times", mode, f.cap.prompts)
				}
				if d.Outcome != outcomeOnce {
					t.Fatalf("decision = %+v, want once from the prompt", d)
				}
				if len(f.cap.appends) != 0 {
					t.Fatalf("a prompted VCS command must not auto-create a grant: %+v", f.cap.appends)
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

func TestJqPrintfReadOnlyModeIndependent(t *testing.T) {
	for _, input := range []string{"jq . session.json", "printf done", "jq . session.json && printf done"} {
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

func TestClassifyReadOnlyShellReadOnlyLiteralCompound(t *testing.T) {
	for _, input := range []string{
		"hg log && hg status",
		"git diff && git log",
		"hg log && git status",
		"hg status && hg diff && hg log",
		"git log --oneline && ls -la",
		"hg log ; hg status",
		"git diff ; git log",
		"hg log || hg status",
		"git diff || git log",
		"hg log | head && git status", // mixed |/&& admitted: all stages read-only
		"hg log | head ; git status",
		"hg log | head || git status",
		"cd main && hg log && hg status",
		"cd main && hg log ; hg status",
		"cd main && hg log || hg status",
		"jq . session.json && printf done",
		"printf done ; jq . session.json",
		"jq . session.json || printf done",
		"cat session.json | jq . && printf done",
		"true && cut -f1 && tr -d ' '",
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (bare all-read-only compound)", input, got)
		}
	}
}

func TestClassifyReadOnlyShellLiteralCompoundMutating(t *testing.T) {
	for _, input := range []string{
		"hg log && hg commit -m x",
		"git log && git reset --hard",
		"hg status && hg push",
		"hg log && rm -rf x",
		"hg log ; hg commit -m x",
		"git log || git reset --hard",
		"hg log ; rm -rf x",
		"hg log || rm -rf x",
		"git log > out",
		`sh -c "hg log && hg status"`,
		"FOO=bar hg log && hg status",                // env-assignment-bearing stage
		`echo "$(touch marker)" | head ; hg status`,  // quoted command substitution would execute under sh -c
		`echo "$(touch marker)" | head || hg status`, // quoted command substitution would execute under sh -c
		"hg log $X && hg status",
		"git diff ; git log $X",
		"jq . session.json && rm x",
		"printf done ; rm x",
		"jq . session.json > out ; printf done",
		"FOO=bar jq . session.json && printf done",
		`printf "$(touch marker)" | head ; jq . x.json`,
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
		}
	}
}

func TestClassifyLiteralCompoundFailClosed(t *testing.T) {
	cases := []struct {
		subject string
		want    OperationClass
	}{
		{"hg log && hg status", ClassReadOnly},
		{"hg log ; hg status", ClassReadOnly},
		{"hg log || hg status", ClassReadOnly},
		{"hg log", ClassMutating},
		{"hg log | head", ClassMutating},
		{"hg log | head ; git status", ClassReadOnly},
		{"hg log | head || git status", ClassReadOnly},
		{`echo "$(touch marker)" | head ; hg status`, ClassMutating},
		{`echo "$(touch marker)" | head || hg status`, ClassMutating},
		{"sh -c 'hg log && hg status'", ClassMutating},
		{"sh -c 'sed -n 1,5p f'", ClassReadOnly},
		{"sh -c 'sed -n 1,5p f && hg status $F'", ClassMutating},
		{"bash -c 'sed -n 1,5p f'", ClassMutating},
		{"echo $(hg log) && hg status", ClassMutating}, // command substitution
		{"hg log && hg commit", ClassMutating},         // mutating stage
		{"hg log ; hg commit", ClassMutating},          // mutating stage
		{"hg log || hg commit", ClassMutating},         // mutating stage
		{"hg log $X && hg status", ClassMutating},      // expansion in a name-only stage
		{"hg log && hg status $F", ClassMutating},
		{"hg log ; git log $X", ClassMutating},
		{"git log || hg log $X", ClassMutating},
		{"hg log $X | head ; git status", ClassMutating},
	}
	for _, tc := range cases {
		if got := classifyLiteralCompound(tc.subject); got != tc.want {
			t.Fatalf("classifyLiteralCompound(%q) = %q, want %q", tc.subject, got, tc.want)
		}
	}
}

func TestNullRedirectClassifiesReadOnly(t *testing.T) {
	for _, input := range []string{
		"grep -n x f 2>/dev/null",
		"ls -la d >/dev/null",
		"hg status 2> /dev/null",
		"cat f 1>/dev/null",
		"grep x f>/dev/null",
		"hg log 2>/dev/null",
		"grep a f 2>/dev/null; grep b f",
		"grep a f 2>/dev/null && hg log 2>/dev/null",
		"grep a f 2>/dev/null&& hg log",
		"grep x f 2>&1",
		"grep x f 1>&2",
		"hg status 2>&1",
		"grep x f 2>&1 && ls",
		"grep a f 2>&1; grep b f",
		"grep a f >/dev/null 2>&1",
		"grep a f 2>&1&& hg log",
		"grep a f 2>/dev/null | head",
		"grep a f | head 2>/dev/null",
		"hg log 2>/dev/null | grep x | head -20",
		"grep a f 2>&1 | head",
		// Name-only stages stay outside the expansion-free condition.
		"grep x *.md 2>/dev/null | head",
		"grep a f 2>/dev/null | head -$N",
		"grep x $F 2>/dev/null",
		"grep x {a,b}.md 2>/dev/null | head",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (the redirect is read-only-neutral)", input, got)
			}
		})
	}
}

func TestNullRedirectVariantsStayMutating(t *testing.T) {
	for _, input := range []string{
		"grep x f > out.txt",
		"grep x f >> /dev/null",
		"grep x f < in.txt",
		"grep x f &>/dev/null",
		"grep x f&>/dev/null",
		"grep x f2>/dev/null",
		"grep x f >& /dev/null",
		"grep x f 3>/dev/null",
		"grep x f 2>$OUT",
		// A single stripped stage judged by subcommand or deny-flag scan needs the same
		// expansion-free proof a validator-checked one does: the shell expands $X after the scan.
		"hg log $X 2>/dev/null",
		"hg log ${X} 2>/dev/null",
		`hg log "$X" 2>/dev/null`,
		"git log $X 2>/dev/null",
		"hg log $X 2>&1",
		"sort $X 2>/dev/null",
		"date $X 2>/dev/null",
		"hg log *.md 2>/dev/null",
		"grep x f 2>/dev/nullx",
		"grep x f 2>/dev/null*",
		"grep x f 2>'/dev/null'",
		"find $D -type f 2>/dev/null",
		"rm -rf x 2>/dev/null",
		"sort -o out.txt 2>/dev/null",
		"FOO=bar grep x f 2>/dev/null",
		"sh -c 'hg log 2>/dev/null'",
		"grep a f 2>/dev/null && rm x",
		"grep x f 3>&1",
		"grep x f 2>&3",
		"grep x f 1>&3",
		"grep x f 3>&2",
		"grep x f >&1",
		"grep x f >&2",
		"grep x f2>&1",
		"grep x f 2>& 1",
		"grep x f 2>&$N",
		"grep x f 2>&1x",
		"grep x f 2>&1 > out.txt",
		"grep x f 2>&1 >> /dev/null",
		"grep x f 2>&1 < in.txt",
		"grep x f 2>'&1'",
		"rm -rf x 2>&1",
		"sort -o out.txt 2>&1",
		"FOO=bar grep x f 2>&1",
		"find $D -type f 2>&1",
		"sh -c 'hg log 2>&1'",
		"grep a f 2>&1 && rm x",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestAllPipeCompoundDeniedCauses(t *testing.T) {
	for _, input := range []string{
		"grep a f 2>/dev/null | rm -rf x",
		"sh -c 'grep a f | head' 2>/dev/null",
		"FOO=bar grep a f 2>/dev/null | head",
		"grep a f > out.txt | head",
		"sed -n 1,5p $F 2>/dev/null | head",
		"grep a f 2>/dev/null | head > out",
		"(grep a f) 2>/dev/null | head",
		"grep a f 2>/dev/null | bash -n x.sh",
		"hg log --config=alias.x=id 2>/dev/null | head",
		"hg log $X 2>/dev/null | head",
		"hg log ${X} 2>/dev/null | head",
		`hg log "$X" 2>/dev/null | head`,
		"git log $X 2>/dev/null | head",
		"hg log $X* 2>/dev/null | head",
		"hg log 2>/dev/null | grep $P | head",
		"sort f 2>/dev/null | head -$N",
		"sort $X 2>/dev/null | head",
		"date $X 2>/dev/null | head",
		"hg log 2>/dev/null | sort $X",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestDoubleQuotedSubstitutionIsNeverAutoAllowed(t *testing.T) {
	for _, input := range []string{
		`grep "$(x)" f`,
		`echo "$(printf hi)"`,
		`test "$(printf 1)" -eq 1 && echo ok`,
		`printf 'a\n' | grep "$(printf a)"`,
		`cd "$(pwd)" && ls`,
		"echo \"`printf hi`\"",
	} {
		req, mc := shellCtx(t, input)
		if !mc.LiteralRoute {
			t.Fatalf("SplitCommand(%q) took the direct route, want literal", input)
		}
		if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
		}
		if sc, ok := RecognizeSimpleCompoundForGrant(req.Subject); ok {
			t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = %+v, want no per-stage chooser", req.Subject, sc)
		}
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				if f.cap.prompts != 1 {
					t.Fatalf("%q prompted %d times in %s, want 1", input, f.cap.prompts, mode)
				}
				if d.ReadOnlyAuto {
					t.Fatalf("%q in %s carried the read-only mode-auto source: %+v", input, mode, d)
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
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q = %+v, want deny with an envelope", input, d)
			}
		})
	}

	req, mc := shellCtx(t, `grep "$v" f`)
	if mc.LiteralRoute || classifyReadOnlyShell(req, mc) != ClassReadOnly {
		t.Fatalf(`grep "$v" f = literal %v class %q, want a read-only direct stage`, mc.LiteralRoute, classifyReadOnlyShell(req, mc))
	}
}

func TestAllPipeCompoundSubstitutionRejectedBeforeClassification(t *testing.T) {
	for _, input := range []string{
		"grep a f 2>/dev/null | $(evil)",
		"grep a f 2>/dev/null | `evil`",
	} {
		t.Run(input, func(t *testing.T) {
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if split.AllowedShell {
				t.Fatalf("SplitCommand(%q).AllowedShell = true, want the substitution refused", input)
			}
		})
	}
}

func TestRedirectFreePipelineStaysOnDirectRoute(t *testing.T) {
	for _, input := range []string{"grep a f | head", "hg log | grep x | head -20"} {
		t.Run(input, func(t *testing.T) {
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if !split.AllowedShell || split.LiteralRoute || split.LiteralInput != "" {
				t.Fatalf("SplitCommand(%q) = %+v, want direct stages and no literal input", input, split)
			}
			for _, stage := range split.Stages {
				if stage.Route != RouteDirect {
					t.Fatalf("SplitCommand(%q) stage %v is not direct", input, stage.Tokens)
				}
			}
		})
	}
}

func TestNullRedirectQuotedTextIsNotStructure(t *testing.T) {
	for _, input := range []string{
		`echo "2>/dev/null" f`,
		`echo '2>/dev/null' f`,
		`echo 2\>/dev/null f`,
		`echo "2>&1" f`,
		`echo '2>&1' f`,
		`echo 2\>\&1 f`,
	} {
		t.Run(input, func(t *testing.T) {
			got, ok := stripNullRedirects(input)
			if !ok || got != input {
				t.Fatalf("stripNullRedirects(%q) = (%q, %v), want the input unchanged", input, got, ok)
			}
			req, mc := shellCtx(t, input)
			if mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) took the literal route; quoted redirect text is not structure", input)
			}
			if cls := classifyReadOnlyShell(req, mc); cls != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (an ordinary echo argument, unchanged by the /dev/null rule)", input, cls)
			}
		})
	}
}

func TestStripNullRedirects(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"grep -n x f 2>/dev/null", "grep -n x f", true},
		{"ls -la d >/dev/null", "ls -la d", true},
		{"hg status 2> /dev/null", "hg status", true},
		{"cat f 1>/dev/null", "cat f", true},
		{"grep x f>/dev/null", "grep x f", true},
		{"grep a f 2>/dev/null; grep b f", "grep a f; grep b f", true},
		{"grep a f 2>/dev/null && hg log 2>/dev/null", "grep a f && hg log", true},
		{"hg log && hg status", "hg log && hg status", true},
		{"grep x f 2>&1", "grep x f", true},
		{"grep x f 1>&2", "grep x f", true},
		{"grep a f 2>&1 && hg log", "grep a f && hg log", true},
		{"grep a f >/dev/null 2>&1", "grep a f", true},
		{"grep a f 2>&1 2>/dev/null", "grep a f", true},
		{"grep x f >> /dev/null", "", false},
		{"grep x f >&1", "", false},
		{"grep x f >&2", "", false},
		{"grep x f 3>&1", "", false},
		{"grep x f 2>&3", "", false},
		{"grep x f 1>&3", "", false},
		{"grep x f 3>&2", "", false},
		{"grep x f 2>&1x", "", false},
		{"grep x f 2>&$N", "", false},
		{"grep x f 2>& 1", "", false},
		{"grep x f 2>&", "", false},
		{"grep x f2>&1", "", false},
		{"grep x f 2>&'1'", "", false},
		{"grep x f 2>&1 > out.txt", "", false},
		{"grep x f &>/dev/null", "", false},
		{"grep x f&>/dev/null", "", false},
		{"grep x f2>/dev/null", "", false},
		{"grep x f < in.txt", "", false},
		{"grep x f 3>/dev/null", "", false},
		{"grep x f 2>/dev/nullx", "", false},
		{"grep x f 2>'/dev/null'", "", false},
		{"grep x'2'>/dev/null", "", false},
		{`grep 'unterminated 2>/dev/null`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := stripNullRedirects(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("stripNullRedirects(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNullRedirectLeavesGrantIdentityUnchanged(t *testing.T) {
	for _, input := range []string{
		"grep -n x f 2>/dev/null",
		"grep a f 2>/dev/null; grep b f",
		"grep a f 2>/dev/null | head",
		"sed -n 1,5p f 2>/dev/null",
		"grep -n x f 2>&1",
		"grep a f 2>&1; grep b f",
		"sed -n 1,5p f 1>&2",
	} {
		t.Run(input, func(t *testing.T) {
			canon, err := CanonicalLiteralForm(input)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q) returned error: %v", input, err)
			}
			if canon != input {
				t.Fatalf("CanonicalLiteralForm(%q) = %q, want the redirect text preserved verbatim", input, canon)
			}
			if _, ok := RecognizeSimpleCompound(canon); ok {
				t.Fatalf("RecognizeSimpleCompound(%q) recognized a redirect-bearing command; generalized compound grants must stay unavailable", canon)
			}

			classifyLiteralCompound(canon)

			after, err := CanonicalLiteralForm(input)
			if err != nil || after != canon {
				t.Fatalf("CanonicalLiteralForm(%q) after classification = (%q, %v), want %q", input, after, err, canon)
			}
			if _, ok := RecognizeSimpleCompound(canon); ok {
				t.Fatalf("RecognizeSimpleCompound(%q) after classification recognized a compound", canon)
			}
			if !MatchesLiteralSubject(canon, input) {
				t.Fatalf("MatchesLiteralSubject(%q, %q) = false, want the stored subject to still match itself", canon, input)
			}
			stripped, ok := stripNullRedirects(canon)
			if !ok || stripped == canon {
				t.Fatalf("stripNullRedirects(%q) = (%q, %v), want a stripped copy", canon, stripped, ok)
			}
			if MatchesLiteralSubject(stripped, canon) {
				t.Fatalf("the stripped copy %q must not match the stored subject %q", stripped, canon)
			}
		})
	}
}

func TestNullRedirectReadOnlyModeIndependent(t *testing.T) {
	for _, input := range []string{
		"grep -n x f 2>/dev/null",
		"grep x f>/dev/null",
		"hg status 2> /dev/null",
		"grep a f 2>/dev/null; grep b f",
		"grep a f 2>/dev/null | head",
		"hg log 2>/dev/null | grep x | head -20",
		"grep x f 2>&1",
		"grep x f 2>&1 && ls",
		"grep x f 1>&2",
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

func TestNullRedirectRejectedFormsStayPlanDenied(t *testing.T) {
	for _, input := range []string{"grep x f > out.txt", "grep x f 2>&3", "grep x f &>/dev/null", "find $D -type f 2>/dev/null"} {
		t.Run(input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, input)
			d := mustAuthorizeMode(t, req, mc, f.deps)
			if f.cap.prompts != 0 {
				t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
			}
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision = %+v, want deny with an envelope", d)
			}
			if d.Grant != nil || len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a mode denial must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestTokenExpansionFree(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"f", true},
		{"1,5p", true},
		{"-n", true},
		{"a/b.md", true},
		{"'$F'", true},
		{`\$F`, true},
		{"'*.md'", true},
		{`\~/f`, true},
		{`"plain text"`, true},
		{`"a\$F"`, true},
		{"$F", false},
		{`"$F"`, false},
		{"${F}", false},
		{"*.md", false},
		{"?.md", false},
		{"[ab].md", false},
		{"{a,b}", false},
		{"{a}", false},
		{"~/f", false},
		{"a~b", false},
		{"`id`", false},
		{"\"`id`\"", false},
		{"'unterminated", false},
		{`"unterminated`, false},
		{`trailing\`, false},
		{"\\\n-i", false},
		{"\\\r-i", false},
		{"\"a\\\nb\"", false},
		{"'a\\\nb'", false},
		{"a!b", false},
		{"a#b", false},
		{"café", false},
	}
	for _, tc := range cases {
		if got := tokenExpansionFree(tc.raw); got != tc.want {
			t.Fatalf("tokenExpansionFree(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestLiteralRouteArgSensitiveExpansionFree(t *testing.T) {
	for _, input := range []string{
		"sed -n 1,5p f 2>/dev/null",
		"sed -n '1,5p' f 2>/dev/null",
		`sed -n 1,5p '$F' 2>/dev/null`,
		`sed -n 1,5p \$F 2>/dev/null`,
		"sed -n 1,5p '*.md' 2>/dev/null",
		"find . -type f 2>/dev/null",
		"sed -n 1,5p f 2>/dev/null && grep x f",
		"grep x f 2>/dev/null || sed -n 1,5p f",
		"sed -n 1,5p f 2>/dev/null | head",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (every raw token is inert)", input, got)
			}
		})
	}
}

func TestLiteralRouteArgSensitiveExpandableStaysMutating(t *testing.T) {
	for _, input := range []string{
		"sed -n 1,5p $F 2>/dev/null",
		`sed -n 1,5p "$F" 2>/dev/null`,
		"sed -n 1,5p *.md 2>/dev/null",
		"sed -n 1,5p ?.md 2>/dev/null",
		"sed -n 1,5p [ab].md 2>/dev/null",
		"sed -n 1,5p {a,b} 2>/dev/null",
		"sed -n 1,5p {a} 2>/dev/null",
		"sed -n 1,5p ~/f 2>/dev/null",
		"sed -n 1,5p f 2>/dev/null && grep x $F",
		"sed -n 1,5p f 2>/dev/null && grep x *.go",
		"grep x $F 2>/dev/null && sed -n 1,5p f",
		"sed -n 1,5p f && grep x f",
		"sed -i 1,5p f 2>/dev/null",
		"sed -n 1,5p f \\\n-i 2>/dev/null",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestRecognizedShWrapperExpansionFreeReadOnly(t *testing.T) {
	for _, input := range []string{
		"sh -c 'sed -n 1,5p f'",
		"sh -c 'sed -n 1,5p f' 2>/dev/null",
		"sh -c 'sed -n 1,5p f && ls'",
		"sh -c 'find . -type f'",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (recognized wrapper, every raw token inert)", input, got)
			}
		})
	}
	for _, mode := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, mode, "sh -c 'sed -n 1,5p f'")
			d := mustAuthorizeMode(t, req, mc, f.deps)
			assertModeAutoAllow(t, f, d)
		})
	}
}

func TestShWrapperDeclinedShapesStayMutating(t *testing.T) {
	for _, input := range []string{
		"sh -c 'sed -n 1,5p $F'",
		`sh -c "sed -n 1,5p '$F'"`,
		"sh -c 'sed -n 1,5p f && ls $F'",
		"sh -c 'sed -n 1,5p f' extra",
		`sh -c 'sh -c "sed -n 1,5p f"'`,
		"bash -c 'sed -n 1,5p f'",
		"sh -c 'hg log && hg status'",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestLiteralRouteLineContinuationStaysPlanDenied(t *testing.T) {
	f := newFixture(neverPrompt, nil)
	input := "sed -n 1,5p f \\\n-i 2>/dev/null"
	req, mc := shellReqCtxFor(t, modePlan, input)
	d := mustAuthorizeMode(t, req, mc, f.deps)
	if f.cap.prompts != 0 {
		t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
	}
	if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
		t.Fatalf("decision = %+v, want deny with an envelope", d)
	}
	if d.Grant != nil || len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
		t.Fatalf("a mode denial must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
	}
}

func TestLiteralRouteNameOnlyUnchangedByExpansionRule(t *testing.T) {
	for _, input := range []string{"grep x $F 2>/dev/null", "grep x *.md 2>/dev/null", "grep x ~/f 2>/dev/null"} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (name-only command, unchanged)", input, got)
			}
		})
	}
}

func TestLiteralRouteArgSensitiveExpansionFreeModeIndependent(t *testing.T) {
	for _, input := range []string{"sed -n 1,5p f 2>/dev/null", "find . -type f 2>/dev/null"} {
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

// TestVCSReadOnlyLiteralCompoundModeIndependent is the mode-independence regression: one representative
// bare all-read-only compound auto-allows identically in Build, Auto edits, and Plan through the
// production Authorize path — one mode_auto "once" with no grant or cache write — proving the compound
// carve-out is a single mode-independent classification, not a per-mode branch. Mirrors
// TestVCSReadOnlyModeIndependent for the direct route.
func TestVCSReadOnlyLiteralCompoundModeIndependent(t *testing.T) {
	for _, input := range []string{"hg log && hg status", "hg log ; hg status", "hg log || hg status"} {
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

func TestClassifyReadOnlyShellEmptyAndLiteralContextsMutating(t *testing.T) {
	if got := classifyReadOnlyShell(MatchRequest{}, ModeContext{}); got != ClassMutating {
		t.Fatalf("classifyReadOnlyShell(empty) = %q, want mutating", got)
	}
	lit := MatchRequest{Kind: subjectKindLiteral, Subject: "hg log"}
	if got := classifyReadOnlyShell(lit, ModeContext{LiteralRoute: true}); got != ClassMutating {
		t.Fatalf("classifyReadOnlyShell(literal single command) = %q, want mutating", got)
	}
}

func TestClassifyReadOnlyShellFindReadOnly(t *testing.T) {
	for _, input := range []string{
		"find .",
		"find . -type f",
		"find src -type f",
		"find internal docs -name '*.md'",
		"find pkg/util -mtime -1 -name '*.go'",
		"find ./contributing -maxdepth 2 -type f",
		"find . -name '*.go'",
		"find . -type f -name '*_test.go'",
		"find . -maxdepth 2 -type f -name '*.md'",
		"find . -mtime -1 -name '*.go'",
		"find . -ctime +7 -type f",
		"find . -atime 0 -type f",
		"find . -mmin -30 -type f",
		"find . -cmin +60 -name '*.md'",
		"find . -amin 0",
		"find . -type f -iname '*.md'",
		"find . -type d -name internal",
		"find . -type f -size +1M",
		"find . -type f -empty",
		"find . -type f -print",
		"find . -type f -print0",
		"find . -name '*.go' -o -name '*.md'",
		"find . -not -path './vendor/*' -print",
		"find . -name x -a -name y",
		"find . ! -name '*.go'",
		"find . -not -name '*.go'",
		"find . -type f -a -name '*.go' -o -type d -not -name vendor",
		"find . -maxdepth 2 -name '*queue*' -not -path './build/*'",
	} {
		if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
			t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
		}
	}
}

func TestClassifyReadOnlyShellFindMutating(t *testing.T) {
	for _, input := range []string{
		"find . -delete",
		"find . -exec rm {} +",
		"find . -execdir rm {} +",
		"find . -ok rm {} +",
		"find . -okdir rm {} +",
		"find . -fprint out.txt",
		"find . -fprint0 out.txt",
		"find . -fprintf out.txt '%p'",
		"find . -fls out.txt",
		"find . -printf '%p'",
		"find . -prune",
		"find . -o -name '*.go'",
		"find . -a -name '*.go'",
		"find . '(' -name '*.go' ')'",
		"find . -type f , -print",
		"find . -unknown",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellFindOperatorAdversarialMutating(t *testing.T) {
	for _, input := range []string{
		"find . -exec rm {} +",
		"find . -execdir rm {} +",
		"find . -ok rm {} +",
		"find . -okdir rm {} +",
		"find . -delete",
		"find . -fls out.txt",
		"find . -fprint out.txt",
		"find . -fprint0 out.txt",
		"find . -fprintf out.txt '%p'",
		"find . -o",
		"find . -a",
		"find . -not",
		"find . !",
		"find . -name x -o",
		"find . -not -o -name y",
		"find . -name -o",
		"find . -name x -o -name -a",
		"find /etc -name x -o -name y",
		"find ../x -not -name y",
		"find . '(' -name a -o -name b ')'",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellFindSemicolonActionMutating(t *testing.T) {
	for _, input := range []string{
		"find . -exec rm {} ;",
		"find . -execdir rm {} ;",
		"find . -ok rm {} ;",
		"find . -okdir rm {} ;",
	} {
		t.Run(input, func(t *testing.T) {
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if !split.AllowedShell || !split.LiteralRoute {
				t.Fatalf("SplitCommand(%q) = {allowed:%v literal:%v}, want literal route", input, split.AllowedShell, split.LiteralRoute)
			}
			req := MatchRequest{Kind: subjectKindLiteral, Subject: split.LiteralInput}
			mc := ModeContext{Stages: split.Stages, LiteralRoute: split.LiteralRoute}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q literal) = %q, want mutating", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellFindMalformed(t *testing.T) {
	for _, input := range []string{
		"find . -name",
		"find . -type",
		"find . -maxdepth",
		"find . -maxdepth x",
		"find . -mtime",
		"find . -mtime soon",
		"find . -size",
		"find src -type f docs -name '*.go'",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellFindBoundaryBypasses(t *testing.T) {
	for _, input := range []string{
		"FOO=bar find . -type f",
		"find /tmp -type f",
		"find .. -type f",
		"find ../other -type f",
		"find ./../other -type f",
		"find -- -type f",
		"find -logs -type f",
		"sh -c 'find /tmp -type f'",
		"find . -type f > out",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellFindNewerInScopeReadOnly(t *testing.T) {
	for _, input := range []string{
		"find . -name '*.go' -newer x",
		"find src -newer go.mod -type f",
		"find . -newer ./a/b",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) took the literal route, want direct", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellFindNewerAndOptionRefusalsMutating(t *testing.T) {
	for _, input := range []string{
		"find . -newer /etc/passwd",
		"find . -newer ../x",
		"find . -newer a/../../x",
		"find . -newer -x",
		"find . -newer",
		"find . -newer ~/x",
		"find . -newer $HOME/x",
		"find ~ -type f",
		"find $HOME -name x",
		"find -D tree .",
		"find -L . -name x",
		"find -H .",
		"find -P .",
		"find -O3 .",
		"find . -anewer x",
		"find . -cnewer x",
		"find . -newermt 2026-01-01",
		"find . -files0-from list",
		"find . -fprint /dev/stdout",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellFindReadOnlyPipeline(t *testing.T) {
	if got := classifyReadOnlyShell(shellCtx(t, "find . -type f -name '*.go' | grep foo | head")); got != ClassReadOnly {
		t.Fatalf("safe find pipeline = %q, want read_only", got)
	}
	if got := classifyReadOnlyShell(shellCtx(t, "find . -delete | grep foo")); got != ClassMutating {
		t.Fatalf("mutating find pipeline = %q, want mutating", got)
	}
}

func TestClassifyReadOnlyShellFindLiteralCompoundMutating(t *testing.T) {
	for _, input := range []string{
		"find . -type f && ls",
		"find . -type f && grep foo bar",
		"ls && find . -type f",
		"find . -type f ; ls",
		"find . -type f || ls",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (the sh -c literal route re-parses an argument-sensitive stage)", input, got)
			}
		})
	}
}

func TestFindLiteralRouteMutatingViaArgSensitivity(t *testing.T) {
	find, ok := commandPolicies["find"]
	if !ok || !find.argSensitive {
		t.Fatalf("find policy argSensitive = %v (ok=%v), want true", find.argSensitive, ok)
	}
	for _, prog := range []string{"hg", "git"} {
		if commandPolicies[prog].argSensitive {
			t.Fatalf("%s policy must not be argSensitive; only argument-sensitive carve-outs are direct-route only", prog)
		}
	}

	const probe = "zzargsensitiveprobe"
	if _, exists := commandPolicies[probe]; exists {
		t.Fatalf("probe program %q unexpectedly already configured; pick an unused name", probe)
	}
	commandPolicies[probe] = commandPolicy{argSensitive: true, validator: func([]string) bool { return true }}
	defer delete(commandPolicies, probe)

	if got := classifyLiteralCompound(probe + " x && ls"); got != ClassMutating {
		t.Fatalf("classifyLiteralCompound(argSensitive probe compound) = %q, want mutating: the literal route must reject every argSensitive program via the flag, not a hardcoded find name", got)
	}

	if got := classifyLiteralCompound("find . -type f && ls"); got != ClassMutating {
		t.Fatalf("classifyLiteralCompound(find compound) = %q, want mutating (argSensitive stage)", got)
	}
	if got := classifyLiteralCompound("hg log && hg status"); got != ClassReadOnly {
		t.Fatalf("classifyLiteralCompound(all-VCS compound) = %q, want read_only (no argSensitive stage)", got)
	}
}

type stagedStage struct {
	req MatchRequest
	mc  ModeContext
}

func stagedCtxs(t *testing.T, mode, input string) []stagedStage {
	t.Helper()
	split, err := SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
	}
	if !split.AllowedShell || !split.LiteralRoute {
		t.Fatalf("SplitCommand(%q): allowedShell=%v literalRoute=%v, want a compound", input, split.AllowedShell, split.LiteralRoute)
	}
	wrapped, stages, operators, ok := SimpleCompoundStages(split.LiteralInput)
	if !ok || wrapped || len(operators) == 0 {
		t.Fatalf("SimpleCompoundStages(%q): ok=%v wrapped=%v operators=%v, want an unwrapped simple compound", input, ok, wrapped, operators)
	}
	for _, op := range operators {
		if op != "&&" && op != ";" {
			t.Fatalf("SimpleCompoundStages(%q) operator %q keeps the command on the sh -c literal route", input, op)
		}
	}
	out := make([]stagedStage, len(stages))
	for i, stage := range stages {
		out[i] = stagedStage{
			req: MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(stage.Tokens, " "), SubjectTokens: stage.Tokens, PathScope: scopeProj},
			mc:  ModeContext{Mode: mode, Class: ClassMutating, Stages: []StageNormalization{stage}},
		}
	}
	return out
}

func TestStagedCompoundArgSensitiveStagesReadOnly(t *testing.T) {
	for _, input := range []string{
		"find . -type f; ls",
		"find . -type f && ls",
		"sed -n 1,5p a; sed -n 1,5p b",
		"sed -n 1,5p; ls",
		"sed -n '1,5p' a; printf -- ---; sed -n '9,20p' b",
		"ls && find . -type f",
		"uniq -c a; ls",
	} {
		t.Run(input, func(t *testing.T) {
			for _, s := range stagedCtxs(t, "", input) {
				if got := classifyReadOnlyShell(s.req, s.mc); got != ClassReadOnly {
					t.Fatalf("classifyReadOnlyShell(%q stage %q) = %q, want read_only (the staged route runs the exact validated argv)", input, s.req.Subject, got)
				}
			}
		})
	}
}

func TestStagedCompoundFailingStageMutating(t *testing.T) {
	for _, input := range []string{
		"find . -delete; ls",
		"sed -i s/a/b/ f; ls",
		"sed -n; ls",
		"sed -n 1,5w out.txt; ls",
		"ls && tee out",
	} {
		t.Run(input, func(t *testing.T) {
			for _, s := range stagedCtxs(t, "", input) {
				if got := classifyReadOnlyShell(s.req, s.mc); got == ClassMutating {
					return
				}
			}
			t.Fatalf("classifyReadOnlyShell(%q): every stage classified read_only, want a mutating stage to deny the compound", input)
		})
	}

	t.Run("env assignment on a staged stage", func(t *testing.T) {
		req, mc := shellCtx(t, "FOO=bar ls")
		if len(mc.Stages) != 1 || len(mc.Stages[0].Assignments) == 0 {
			t.Fatalf("SplitCommand(FOO=bar ls) stages = %+v, want one stage carrying an assignment", mc.Stages)
		}
		if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
			t.Fatalf("classifyReadOnlyShell(FOO=bar ls staged) = %q, want mutating", got)
		}
	})
}

func TestStagedArgSensitiveCompoundAutoAllowsInEveryMode(t *testing.T) {
	for _, input := range []string{
		"find . -type f; ls",
		"sed -n '1,5p' a; printf -- ---; sed -n '9,20p' b",
	} {
		for _, mode := range []string{"build", modeAutoEdits, modePlan} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				for _, s := range stagedCtxs(t, mode, input) {
					f := newFixture(neverPrompt, nil)
					d := mustAuthorizeMode(t, s.req, s.mc, f.deps)
					assertModeAutoAllow(t, f, d)
				}
			})
		}
	}
}

func TestStagedFailingArgSensitiveStageDeniesInPlan(t *testing.T) {
	for _, input := range []string{"sed -i s/a/b/ f; ls", "find . -delete; ls"} {
		t.Run(input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			s := stagedCtxs(t, modePlan, input)[0]
			d := mustAuthorizeMode(t, s.req, s.mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q stage %q = %+v, want a mode deny with an envelope", input, s.req.Subject, d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a denied stage must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestShellReparsedRouteArgSensitiveStagesMutating(t *testing.T) {
	for _, input := range []string{
		"sed -n 1,5p a | head; ls",
		"find . -type f | head; ls",
		"sh -c \"find . -type f && ls ~/x\"",
		"find . -type f || ls",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (the shell re-parses text no validator saw)", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellUniq(t *testing.T) {
	for _, input := range []string{
		"uniq",
		"uniq input",
		"uniq --help",
		"uniq --version",
		"uniq -c",
		"uniq --count",
		"uniq -d",
		"uniq --repeated",
		"uniq -c input",
		"uniq -c -d input",
		"uniq -D",
		"uniq --all-repeated",
		"uniq --all-repeated=none",
		"uniq --all-repeated=prepend",
		"uniq --all-repeated=separate",
		"uniq -D input",
		"uniq --all-repeated=separate input",
		"uniq --group",
		"uniq --group=separate",
		"uniq --group=prepend",
		"uniq --group=append",
		"uniq --group=both",
		"uniq --group=both input",
		"uniq -i",
		"uniq --ignore-case",
		"uniq -u",
		"uniq --unique",
		"uniq -z",
		"uniq --zero-terminated",
		"uniq -i -u -z input",
		"uniq -f 1",
		"uniq -f1",
		"uniq --skip-fields=1",
		"uniq --skip-fields 1",
		"uniq -f 0",
		"uniq -f 10",
		"uniq -f 1 input",
		"uniq -c -f 2 input",
		"uniq --skip-fields=0 input",
		"uniq -s 1",
		"uniq -s1",
		"uniq --skip-chars=1",
		"uniq --skip-chars 1",
		"uniq -s 0",
		"uniq -s 10",
		"uniq -s 1 input",
		"uniq -c -s 2 input",
		"uniq -f 1 -s 2 input",
		"uniq --skip-chars=0 input",
		"uniq -w 1",
		"uniq -w1",
		"uniq --check-chars=1",
		"uniq --check-chars 1",
		"uniq -w 0",
		"uniq -w 10",
		"uniq -w 1 input",
		"uniq -c -w 2 input",
		"uniq -f 1 -s 2 -w 3 input",
		"uniq --check-chars=0 input",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
	for _, input := range []string{
		"uniq input output",
		"uniq --unknown",
		"uniq -c input output",
		"uniq --count input output",
		"uniq -cd",
		"uniq --count=1",
		"uniq --counts",
		"uniq --repeat",
		"uniq --all-repeated=invalid",
		"uniq --all-repeated=",
		"uniq --all-repeated separate",
		"uniq --all-repeated none",
		"uniq --all-repeated prepend",
		"uniq --all-repeated invalid",
		"uniq --all-repeated separate input",
		"uniq --all-repeateds",
		"uniq --group=invalid",
		"uniq --group=none",
		"uniq --group=",
		"uniq --group separate",
		"uniq --group invalid",
		"uniq --group input",
		"uniq --groups",
		"uniq --group=both input output",
		"uniq -Dc",
		"uniq -iu",
		"uniq -uz",
		"uniq --ignore-case=1",
		"uniq --ignore-cases",
		"uniq --unique=1",
		"uniq --uniques",
		"uniq --zero-terminated=1",
		"uniq --zero-terminateds",
		"uniq -I",
		"uniq -U",
		"uniq -Z",
		"uniq -i input output",
		"uniq input -c",
		"uniq input output extra",
		"uniq --help output",
		"uniq --version output",
		"uniq --help --version",
		"uniq --help=x",
		"uniq --versions",
		"uniq -h",
		"uniq -f",
		"uniq --skip-fields",
		"uniq -c -f",
		"uniq -f x",
		"uniq -fx",
		"uniq -f input",
		"uniq --skip-fields x",
		"uniq --skip-fields=x",
		"uniq --skip-fields=",
		"uniq -f -1",
		"uniq -f 1.5",
		"uniq -f+1",
		"uniq --skip-fieldss=1",
		"uniq --skip-field=1",
		"uniq -f 1 input output",
		"uniq -cf1",
		"uniq -s",
		"uniq --skip-chars",
		"uniq -c -s",
		"uniq -s x",
		"uniq -sx",
		"uniq -s input",
		"uniq --skip-chars x",
		"uniq --skip-chars=x",
		"uniq --skip-chars=",
		"uniq -s -1",
		"uniq -s 1.5",
		"uniq -s+1",
		"uniq --skip-charss=1",
		"uniq --skip-char=1",
		"uniq -s 1 input output",
		"uniq -cs1",
		"uniq -w",
		"uniq --check-chars",
		"uniq -c -w",
		"uniq -w x",
		"uniq -wx",
		"uniq -w input",
		"uniq --check-chars x",
		"uniq --check-chars=x",
		"uniq --check-chars=",
		"uniq -w -1",
		"uniq -w 1.5",
		"uniq -w+1",
		"uniq --check-charss=1",
		"uniq --check-char=1",
		"uniq -w 1 input output",
		"uniq -cw1",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestUniqLiteralCompoundMutating(t *testing.T) {
	if !commandPolicies["uniq"].argSensitive {
		t.Fatalf("uniq policy argSensitive = false, want true: an admitted direct form must not auto-allow on the sh -c literal route")
	}
	for _, input := range []string{
		"uniq input && ls",
		"ls && uniq",
		"uniq ; ls",
		"uniq || ls",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (the sh -c literal route re-parses an argument-sensitive stage)", input, got)
			}
		})
	}
}

var sedSessionInvocations = []string{
	"sed -n 1610,1745p /home/u/proj/build.sh",
	"sed -n 2130,2345p /home/u/proj/selftest.sh",
	"sed -n 180,380p /home/u/proj/selftest.sh",
	"sed -n 250,325p /home/u/proj/README.md",
	"sed -n 1,100p /home/u/proj/selftest.sh",
	"sed -n 500,620p /home/u/proj/selftest.sh",
	"sed -n 650,770p /home/u/proj/selftest.sh",
	"sed -n 2380,2515p /home/u/proj/build.sh",
	"sed -n 3100,3160p /home/u/proj/build.sh",
	"sed -n 70,145p internal/tui/transcript.go",
	"sed -n 460,490p internal/tui/transcript.go",
	"sed -n 555,580p internal/tui/transcript.go",
}

func TestProbeProgramSetsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  map[string]struct{}
		want []string
	}{
		{"probeFlagPrograms", probeFlagPrograms, []string{"awk", "codemeld", "find", "git", "go", "hg", "jq", "mise", "node", "python3", "rg", "sed", "systemctl"}},
		{"probeSubcommandPrograms", probeSubcommandPrograms, []string{"git", "go", "hg", "mise"}},
	} {
		got := slices.Sorted(maps.Keys(tc.set))
		if !slices.Equal(got, tc.want) {
			t.Fatalf("%s = %v, want exactly %v", tc.name, got, tc.want)
		}
	}
}

func TestClassifyReadOnlyShellProbesReadOnly(t *testing.T) {
	for _, input := range []string{
		"go version",
		"go help",
		"hg --version",
		"hg version",
		"git --version",
		"git help",
		"python3 -V",
		"python3 --help",
		"node --version",
		"mise --version",
		"mise version",
		"rg --version",
		"jq --help",
		"awk --version",
		"sed --help",
		"sed --version",
		"find --version",
		"go '--version'",
		"systemctl --version",
		"codemeld --help",
		"codemeld -h",
		"codemeld --version",
		"codemeld -V",
		"git check-ignore -v --no-index a/b",
		"git check-ignore --no-index --stdin",
		"git check-ignore --no-index -- --index",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) took the literal route, want direct", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellProbesMutating(t *testing.T) {
	for _, input := range []string{
		"unknown-prog --help",
		"go --version extra",
		"go version --json",
		"./script --version",
		"python3 help",
		"node version",
		"FOO=1 go version",
		"go --Version",
		"go -version",
		"go --version=1",
		"go -- --version",
		"go",
		"env -i go version",
		"uniq -h",
		"uptime -V",
		"lsof -V",
		"ansible --version",
		"ansible-playbook --version",
		"systemctl restart x",
		"systemctl version",
		"codemeld version",
		"codemeld help",
		"codemeld run x",
		"git -c core.pager=x check-ignore a",
		"git check-ignore --output=f a",
		"git check-ignore --stdin",
		"git check-ignore a",
		"git check-ignore --no-index --index a",
		"git check-ignore --no-index --ind a",
		"git check-ignore -- --no-index",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestClassifyReadOnlyShellSed(t *testing.T) {
	inputs := []string{
		"sed -n 1,220p f",
		"sed -n '1,220p' f",
		"sed -n $p f",
		"sed -n '$p' f",
		"sed -n 12= f",
		"sed -n 1,$p f",
		"sed -n 12p f",
		"sed -n 12pq f",
		"sed -n '1,5p' a b c",
		"sed -n p f",
		"sed -n = f",
		"sed --quiet 1,5p f",
		"sed --silent 1,5p f",
		"sed 1,5p f",
		"sed -n -n 1,5p f",
		"sed -n 1,5p f | head",
		"sed -n 1,28p",
		"sed -n '1,28p'",
		"sed -n 12p",
		"sed -n $p",
		"sed -n 12=",
		"sed -n 12pq",
		"sed --quiet 1,5p",
		"sed --silent 1,5p",
		"sed -n p",
		"sed -n 'p' ",
		"sed 1,5p",
		"hg log | sed -n 1,28p",
		"cat f | sed -n 1,5p | head",
		"sed -n '150,245p;1020,1170p;1460,1575p' f",
		"cat f | sed -n '150,245p;1020,1170p;1460,1575p'",
		"sed -n '1,5p;5q' f",
		"sed -n '1,5p;q' f",
		"sed -n '$p;1p' f",
		"sed -n '1,5p;$q' f",
		"sed -n '1,5=;3p' f",
		"sed -n '1,5p;3pq' f",
		"sed -n 'q' f",
		"sed -n '5q'",
	}
	inputs = append(inputs, sedSessionInvocations...)
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
	for _, input := range []string{
		"sed -i s/a/b/ f",
		"sed -i.bak s/a/b/ f",
		"sed --in-place s/a/b/ f",
		"sed --in-pl s/a/b/ f",
		"sed --in s/a/b/ f",
		"sed -n -i 1,5p f",
		"sed -n 1,5w out.txt f",
		"sed -n '1,5w out.txt' f",
		"sed -n '1,5W out.txt' f",
		"sed -n '1,5p;6,9w x' f",
		"sed -n '1,5p; 6,9p' f",
		"sed -f script.sed f",
		"sed --file=script.sed f",
		"sed -e 1p -e 2p f",
		"sed --expression=1p f",
		"sed s/a/b/ f",
		"sed -n s/a/b/p f",
		"sed -n",
		"sed",
		"sed -i s/a/b/",
		"sed --in-place s/a/b/",
		"sed -n 1,5w out.txt",
		"sed -n '1,5w out.txt'",
		"sed -n '1,5W out.txt'",
		"sed -n s/a/b/p",
		"sed -n 1,5d",
		"sed -n '/foo/p'",
		"sed -n '5{p;q}'",
		"sed -n '1,5r other'",
		"sed -n '1e ls'",
		"sed -E -n 1,5p",
		"sed -f script.sed",
		"sed -e 1p",
		"sed -n ''",
		"sed -n '' f",
		"sed -n '/foo/p' f",
		"sed -n '5{p;q}' f",
		"sed -n '1,5r other' f",
		"sed -n '1,5R other' f",
		"sed -n '1e ls' f",
		"sed -n -- 1,5p f",
		"sed -n 1,5p -- f",
		"sed -n 1,5p -i",
		"sed -n 1,5p f -i",
		"sed -n 1,5p f --in-place",
		"sed -s -n 1,5p f",
		"sed -E -n 1,5p f",
		"sed -r -n 1,5p f",
		"sed -z -n 1,5p f",
		"sed --debug -n 1,5p f",
		"sed -n 1,p f",
		"sed -n 1, f",
		"sed -n ,5p f",
		"sed -n '$,5p' f",
		"sed -n '$,$p' f",
		"sed -n 1,5q f",
		"sed -n 1,5d f",
		"sed -n 1,5pp f",
		"sed -n 1,5qp f",
		"sed -n '1,5p\n6,9w x' f",
		"sed -n '1,5p;w out.txt' f",
		"sed -n '1,5p;W out.txt' f",
		"sed -n '1,5p;s/a/b/w out' f",
		"sed -n '1,5p;r /etc/passwd' f",
		"sed -n '1,5p;;3p' f",
		"sed -n '1,5p;' f",
		"sed -n ';1,5p' f",
		"sed -n ';' f",
		"sed -n '1,5p;e ls' f",
		"sed -i '1,5p;3p' f",
		"sed -n -e '1,5p' -e '3p' f",
		"sed -n '/a;b/p' f",
		"sed -n '1,5p;{w out}' f",
		"sed -n '1,5p;1,5q' f",
		"sed -n '1,5p;5qp' f",
		"sed -n '1,5p;q5' f",
		"sed -n '1,5p; 5q' f",
		"sed -n '1,5p;5d' f",
		"sed -n '1,5p;$,5p' f",
		"sed -n '1,5p;/foo/p' f",
		"sed -n \"1,5p;$Rp\" f",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

func TestSedLiteralCompoundMutating(t *testing.T) {
	if !commandPolicies["sed"].argSensitive {
		t.Fatalf("sed policy argSensitive = false, want true: an admitted direct form must not auto-allow on the sh -c literal route")
	}
	for _, input := range []string{
		"sed -n 1,5p a; ls",
		"sed -n 1,5p a && ls",
		"sed -n 1,5p a || ls",
		"ls && sed -n 1,5p a",
		"sed -n 1,5p a && ls; pwd",
		"sh -c \"sed -n 1,5p $F\"",
		"sed -n 1,5p a > out",
		"sh -c 'sed -n \"1,5p;$Rp\" f'",
		"sh -c \"sed -n '1,5p;9,20p' $F\"",
		"sed -n '1,5p;9,20p' a; ls",
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (no expansion-free literal-route form covers it)", input, got)
			}
		})
	}
}

func TestSedReadOnlyModeIndependent(t *testing.T) {
	for _, input := range []string{
		"sed -n 1,220p f",
		"sed --quiet '$p' f",
		"sed -n 12= f",
		"sed -n '150,245p;1020,1170p;1460,1575p' f",
		"sed -n '150,245p;1020,1170p;1460,1575p'",
		"sed -n '1,5p;5q' f",
		"sed -n '1,5p;q' f",
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

func TestSedRejectedScriptStaysPlanDenied(t *testing.T) {
	for _, input := range []string{"sed -n '1,5p;w out.txt' f", "sed -n '1,5p;' f", "sed -n '1,5p;1,5q' f"} {
		t.Run(input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, input)
			d := mustAuthorizeMode(t, req, mc, f.deps)
			if f.cap.prompts != 0 {
				t.Fatalf("Plan must not prompt, prompted %d times", f.cap.prompts)
			}
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision = %+v, want deny with an envelope", d)
			}
			if d.Grant != nil || len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a mode denial must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestSedSessionInvocationsNoLongerPrompt(t *testing.T) {
	for _, input := range sedSessionInvocations {
		t.Run(input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, "build", input)
			d := mustAuthorizeMode(t, req, mc, f.deps)
			assertModeAutoAllow(t, f, d)
		})
	}
}

var awkAcceptedForms = []string{
	`awk 'NR>=55 && NR<=70 {print NR ":" $0}' docs/session-format.md`,
	`awk 'NR >= 55 && NR <= 70 { print NR ":" $0 }' docs/session-format.md`,
	`awk 'NR>=55&&NR<=70{print NR":"$0}' docs/session-format.md`,
	`awk '  NR>=55   &&   NR<=70   {   print   NR   ":"   $0   }  ' docs/session-format.md`,
	`awk 'FNR>=1 && FNR<=10 {print $0}' f`,
	`awk 'FNR>=1 && FNR<=10 {print $0}' a b`,
	`awk 'NR>=1 && NR<=10 {print}' f`,
	`awk 'NR>=1 && NR<=10 {print FNR " " $0}' a b c`,
	`awk 'NR>=70 && NR<=55 {print $0}' f`,
	`awk 'NR>=0 && NR<=000 {print 42}' f`,
	`awk 'NR>=1 && NR<=10 {print "only text"}' f`,
	`awk 'NR>=1 && NR<=10 {print $0}' ./weird-name`,
	`awk 'BEGIN{print "x"} NR>=1 && NR<=2 {print}' f`,
	`awk 'NR>=1 && NR<=2 {print} END{print}' f`,
	`awk 'NR>=1 && NR<=2 {print}{print}' f`,
	`awk 'NR>=1 && NR<=2 {print;}' f`,
	`awk 'NR>=1 && NR<=2 {print NR, $0}' f`,
	`awk 'NR>=1 && NR<=2 {print $1}' f`,
	`awk 'NR>=1 && NR<=2 {print $0 $2}' f`,
	`awk 'NR>=1 && NR<=2 {printf "%s" $0}' f`,
	`awk 'NR>=1 && NR<=2 {print x}' f`,
	`awk 'NR>=1 && NR<=2 {x=1 print}' f`,
	`awk 'NR>=1 && NR<=2 {print length($0)}' f`,
	`awk 'NR>=1 && NR<=2 {print "a\nb"}' f`,
	`awk 'NR>=1 && NR<=2' f`,
	`awk 'NR>=1 {print}' f`,
	`awk 'NR<=2 {print}' f`,
	`awk 'NR>=1 && FNR<=2 {print}' f`,
	`awk 'NR>1 && NR<2 {print}' f`,
	`awk 'NR>=1 || NR<=2 {print}' f`,
	`awk 'NR>=+1 && NR<=2 {print}' f`,
	`awk 'NR>=1.0 && NR<=2 {print}' f`,
	`awk 'NR>=1e2 && NR<=2 {print}' f`,
	`awk 'NR>= && NR<=2 {print}' f`,
	`awk 'NRX>=1 && NRX<=2 {print}' f`,
	`awk '/needle/ {print}' f`,
	`awk 'NR>=1 && NR<=2 {print NR ":" $0}'`,
	`awk -F'|' '{print NF}' f`,
	`awk -F: '{print $1, $3}' f`,
	`awk 'function flush() { if (section != "") printf "%5d  %s\n", words, section } /^## / { flush(); section = $0; words = 0; next } { words += NF } END { flush() }' f.md`,
	`awk '{print $1}'`,
	`awk 'NR==FNR{a[$1];next} ($1 in a)' f g`,
	`awk '$3 > 100 { print $1 }' f`,
	`awk '$1 >= 2 || $2 == "x"' f`,
	`awk '{ s += $2 } END { print s/NR }' f`,
	`awk '{ print ($1 + $2) / 2 }' f`,
}

var awkRejectedForms = []string{
	`awk 'NR>=1 && NR<=10 {print}' f g=1`,
	`awk -v n=10 'NR>=1 && NR<=10 {print}' f`,
	`awk '{print "unterminated}' f`,
	`awk 'NR>=1 && NR<=2 {system("id")}' f`,
	`awk 'NR>=1 && NR<=2 {getline line < "/etc/passwd"; print line}' f`,
	`awk 'NR>=1 && NR<=2 {print > "out"}' f`,
	`awk 'NR>=1 && NR<=2 {print >> "out"}' f`,
	`awk 'NR>=1 && NR<=2 {print | "sh"}' f`,
	`awk 'NR>=1 && NR<=2 {close("out"); print}' f`,
	`awk -f prog.awk f`,
	`awk 'NR>=1 && NR<=2 {print}' /dev/tcp/host/443`,
	`awk 'NR>=1 && NR<=2 {print}' /dev/udp/host/53`,
	`awk 'NR>=1 && NR<=2 {print}' /inet/tcp/0/host/443`,
	`awk 'NR>=1 && NR<=2 {print}' /inet/udp/0/host/53`,
	`awk 'NR>=1 && NR<=2 {print}' /inet4/tcp/0/host/443`,
	`awk 'NR>=1 && NR<=2 {print}' /inet6/tcp/0/host/443`,
	`awk 'NR>=1 && NR<=2 {print}' f /dev/tcp/host/443`,
	`awk 'NR>=1 && NR<=2 {print}' /dev/stdin`,
	`sh -c 'awk "NR>=1 && NR<=10 {print $0}" f'`,
	`awk 'NR>=1 && NR<=2 {print}' -`,
	`awk 'NR>=1 && NR<=2 {print}' --`,
	`awk`,
}

func TestClassifyReadOnlyShellAwk(t *testing.T) {
	assertShellClass(t, awkAcceptedForms, ClassReadOnly)
	assertShellClass(t, awkRejectedForms, ClassMutating)
}

func TestAwkAcceptedFormsTakeDirectRoute(t *testing.T) {
	const input = `awk 'NR>=55 && NR<=70 {print NR ":" $0}' docs/session-format.md`
	want := []string{"awk", `NR>=55 && NR<=70 {print NR ":" $0}`, "docs/session-format.md"}
	for _, form := range awkAcceptedForms {
		t.Run(form, func(t *testing.T) {
			split, err := SplitCommand(form)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", form, err)
			}
			if split.LiteralRoute || len(split.Stages) != 1 {
				t.Fatalf("SplitCommand(%q): literalRoute=%v stages=%d, want one direct stage", form, split.LiteralRoute, len(split.Stages))
			}
			if split.Stages[0].Route != RouteDirect || len(split.Stages[0].Assignments) != 0 {
				t.Fatalf("SplitCommand(%q) stage = %+v, want a direct stage with no assignments", form, split.Stages[0])
			}
		})
	}
	split, err := SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
	}
	assertDirectStageTokens(t, input, split.Stages[0], want)
	if !stageTokensReadOnly(want) {
		t.Fatalf("stageTokensReadOnly(%v) = false, want true (the validator judges the exact executed argv)", want)
	}
}

func TestAwkIsArgumentSensitiveNotNameOnly(t *testing.T) {
	policy, ok := commandPolicies["awk"]
	if !ok || !policy.argSensitive || policy.validator == nil {
		t.Fatalf("awk policy = %+v (ok=%v), want an argument-sensitive entry with a validator", policy, ok)
	}
	if policyIsNameOnly(policy) {
		t.Fatalf("awk must not be a name-only allowlist entry: awk can run programs and write files")
	}
}

func TestAwkStageTokensFailClosed(t *testing.T) {
	const prog = `NR>=1 && NR<=2 {print}`
	for _, tokens := range [][]string{
		{"awk", prog, "-"},
		{"awk", prog, "-n"},
		{"awk", prog, "--"},
		{"awk", prog, "x=1", "f"},
		{"awk", prog, "f", "x=1"},
		{"awk", prog, ""},
		{"awk", "-f", "prog.awk", "f"},
		{"awk", "-v", "x=1", prog, "f"},
		{"awk", "--", prog, "f"},
		{"awk", `NR>=1 && NR<=2 {system("id")}`, "f"},
		{"awk", `NR>=1 && NR<=2 {getline line < "/etc/passwd"; print line}`, "f"},
		{"awk", `NR>=1 && NR<=2 {print > "out"}`, "f"},
		{"awk", `NR>=1 && NR<=2 {print >> "out"}`, "f"},
		{"awk", `NR>=1 && NR<=2 {print | "sh"}`, "f"},
		{"awk", `NR>=1 && NR<=2 {close("out"); print}`, "f"},
		{"awk", `NR>=1 && NR<=2 {print}`, "f", "g", "-h"},
	} {
		t.Run(strings.Join(tokens, " "), func(t *testing.T) {
			if stageTokensReadOnly(tokens) {
				t.Fatalf("stageTokensReadOnly(%v) = true, want false (unsafe option, operand, or program)", tokens)
			}
		})
	}
}

func TestAwkDirectPipelineReadOnly(t *testing.T) {
	assertShellClass(t, []string{
		`awk 'NR>=55 && NR<=70 {print NR ":" $0}' f | head`,
		`awk 'NR>=1 && NR<=10 {print}' f | grep x | wc -l`,
		`cat f | awk 'NR>=1 && NR<=10 {print}' g`,
		`awk 'NR>=1 && NR<=10 {print $1}' f | head`,
	}, ClassReadOnly)
	assertShellClass(t, []string{
		`awk 'NR>=1 && NR<=10 {print}' f | tee out`,
	}, ClassMutating)
}

func TestAwkStagedCompoundAutoAllowsInEveryMode(t *testing.T) {
	for _, input := range []string{
		`awk 'NR>=1 && NR<=10 {print}' a; ls`,
		`awk 'NR>=1 && NR<=10 {print}' a && awk 'FNR>=2 && FNR<=3 {print $0}' b`,
	} {
		for _, mode := range []string{"build", modeAutoEdits, modePlan} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				for _, s := range stagedCtxs(t, mode, input) {
					if got := classifyReadOnlyShell(s.req, s.mc); got != ClassReadOnly {
						t.Fatalf("classifyReadOnlyShell(%q stage %q) = %q, want read_only (the staged route runs the exact validated argv)", input, s.req.Subject, got)
					}
					f := newFixture(neverPrompt, nil)
					d := mustAuthorizeMode(t, s.req, s.mc, f.deps)
					assertModeAutoAllow(t, f, d)
				}
			})
		}
	}
}

func TestAwkStagedCompoundRejectedStageDeniesInPlan(t *testing.T) {
	for _, input := range []string{
		`awk '{print > "x"}' a; ls`,
		`awk 'NR>=1 && NR<=10 {system("id")}' a && ls`,
	} {
		t.Run(input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			s := stagedCtxs(t, modePlan, input)[0]
			d := mustAuthorizeMode(t, s.req, s.mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q stage %q = %+v, want a mode deny with an envelope", input, s.req.Subject, d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a denied stage must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
	}
}

func TestAwkLiteralCompoundMutating(t *testing.T) {
	for _, input := range []string{
		`awk 'NR>=1 && NR<=10 {print}' a; ls`,
		`awk 'NR>=1 && NR<=10 {print}' a && ls`,
		`awk 'NR>=1 && NR<=10 {print}' a || ls`,
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (no expansion-free literal-route form covers it)", input, got)
			}
		})
	}
}

func TestAwkLiteralRouteFollowsExistingWrapperRule(t *testing.T) {
	for _, input := range []string{
		`sh -c 'awk "NR>=1 && NR<=10 {print}" f'`,
		`sh -c 'awk "NR>=1 && NR<=10 {print}" f' 2>/dev/null`,
		`awk 'NR>=1 && NR<=10 {print}' f 2>/dev/null`,
		`awk 'NR>=1 && NR<=10 {print}' '*.md' 2>/dev/null`,
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (recognized wrapper, every raw token inert)", input, got)
			}
		})
	}
	for _, input := range []string{
		`sh -c "awk 'NR>=1 && NR<=10 {print $0}' f"`,
		`sh -c 'awk "NR>=1 && NR<=10 {print}" $F'`,
		`sh -c 'awk "NR>=1 && NR<=10 {print}" f' extra`,
		`sh -c 'sh -c "awk \"NR>=1 && NR<=10 {print}\" f"'`,
		`bash -c 'awk "NR>=1 && NR<=10 {print}" f'`,
		`FOO=bar awk 'NR>=1 && NR<=10 {print}' f`,
		`awk 'NR>=1 && NR<=10 {print}' $F 2>/dev/null`,
		`awk 'NR>=1 && NR<=10 {print}' f > out`,
		`sh -c 'awk "NR>=1 && NR<=10 {print}" "$(ls)"'`,
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
	for _, input := range []string{
		`awk 'NR>=1 && NR<=10 {print}' $(ls)`,
		"awk 'NR>=1 && NR<=10 {print}' `ls`",
	} {
		t.Run(input, func(t *testing.T) {
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if split.AllowedShell {
				t.Fatalf("SplitCommand(%q).AllowedShell = true, want false (rejected construct)", input)
			}
			mc := ModeContext{Stages: split.Stages, LiteralRoute: split.LiteralRoute}
			if got := classifyReadOnlyShell(MatchRequest{}, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q rejected) = %q, want mutating", input, got)
			}
		})
	}
}

func withShellPlatform(t *testing.T, platform string) {
	t.Helper()
	prev := shellPlatform
	shellPlatform = platform
	t.Cleanup(func() { shellPlatform = prev })
}

func TestLinuxDiagnosticsReadOnly(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"ps aux",
		"ps -ef",
		"ps -e -f",
		"ps -o pid,cmd",
		"ps -p 1",
		"ps -p 1,2,3",
		"ps --help",
		"ps --version",
		"ps -eF",
		"ps --forest",
		"ps -eo pid,cmd --sort=-pcpu",
		"ps -L",
		"ps ax",
		"ps -ef | grep foo | head",
		"pgrep foo",
		"pgrep -f 'python.*server'",
		"pgrep -u root sshd",
		"pgrep -P 1",
		"pidof sshd",
		"pidof -s -x sshd bash",
		"pstree",
		"pstree -p",
		"pstree -pau 1",
		"pstree root",
		"lsof -p 1",
		"ss -tlnp",
		"ss -tuln",
		"ss -s",
		"free",
		"free -m",
		"free -h",
		"free -s 1 -c 5",
		"vmstat",
		"vmstat 1 5",
		"vmstat -a",
		"uptime",
		"uptime -p",
		"uptime -s",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (closed diagnostic form)", input, got)
			}
		})
	}
}

func TestLinuxDiagnosticsRejectUnknownFlags(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"pgrep -F pidfile",
		"pgrep -P abc",
		"pgrep foo bar",
		"pgrep -u",
		"pgrep",
		"pgrep -f",
		"pgrep -n",
		"pidof",
		"pidof -o 1 sshd",
		"pstree -H 1",
		"pstree a b",
		"lsof",
		"lsof -i",
		"lsof -p 1,2,3",
		"lsof -p1234",
		"lsof -p 1 /etc",
		"lsof -t -p 1",
		"ss -K",
		"ss --kill",
		"ss -D dump",
		"ss state",
		"ss -r",
		"free -x",
		"free -s 1",
		"free -s 999999 -c 5",
		"free -c 5",
		"free -s abc -c 5",
		"vmstat 1",
		"vmstat 1 99999",
		"vmstat -z",
		"vmstat -S",
		"vmstat 1 x",
		"uptime -V",
		"uptime now",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (unlisted flag or bad operand)", input, got)
			}
		})
	}
}

func TestLinuxDiagnosticsModeIndependent(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"ps aux", "ps --help", "ps --version", "ps -eF", "ps --forest", "ps -eo pid,cmd --sort=-pcpu",
		"ps -L", "ps ax",
		"pgrep foo", "pidof sshd", "pstree -p", "lsof -p 1", "ss -tlnp", "free -m", "vmstat", "uptime",
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

func TestPlatformGatingDenies(t *testing.T) {
	withShellPlatform(t, "freebsd")
	for _, input := range []string{
		"pgrep -c sshd", "pidof -c sshd", "pstree -a",
		"lsof -p 1", "ss -tlnp", "free -m", "vmstat 1 5", "uptime -p",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) with non-Linux platform = %q, want mutating", input, got)
			}
		})
	}
}

func TestDiffReadOnlyOnLinuxInEveryMode(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"diff a b",
		"diff -u a b",
		"diff -U 5 a b",
		"diff -r d1 d2",
		"diff -q a b",
		"diff --unified=3 a b",
		"diff --color=never -u a b",
	} {
		for _, mode := range []string{"build", modeAutoEdits, modePlan} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
					t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
				}
				f := newFixture(neverPrompt, nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				assertModeAutoAllow(t, f, d)
			})
		}
	}
}

func TestDiffStaysNonReadOnlyOffLinux(t *testing.T) {
	for _, platform := range []string{"freebsd", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			withShellPlatform(t, platform)
			if got := classifyReadOnlyShell(shellCtx(t, "diff a b")); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) on %s = %q, want mutating", "diff a b", platform, got)
			}
		})
	}
}

func TestDiffPaginateIsNeverReadOnly(t *testing.T) {
	withShellPlatform(t, "linux")
	assertShellClass(t, []string{
		"diff -l a b",
		"diff --paginate a b",
		"diff --pag a b",
		"diff --pagi a b",
		"diff --paginate=x a b",
		"diff -ul a b",
		"diff -rul d1 d2",
		"diff -u -l a b",
		"diff a b -l",
		"diff -u a b > out",
		"diff -u a b -l 2>/dev/null",
	}, ClassMutating)
}

func TestDiffLiteralRouteNeedsExpansionFreeArgs(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, tc := range []struct {
		input string
		want  OperationClass
	}{
		{"diff -u a b 2>/dev/null", ClassReadOnly},
		{"diff -u $FILES 2>/dev/null", ClassMutating},
		{"diff -u *.txt b 2>/dev/null", ClassMutating},
	} {
		t.Run(tc.input, func(t *testing.T) {
			req, mc := shellCtx(t, tc.input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", tc.input)
			}
			if got := classifyReadOnlyShell(req, mc); got != tc.want {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestFreeBSDDiagnosticsReadOnly(t *testing.T) {
	withShellPlatform(t, "freebsd")
	for _, input := range []string{
		"ps -ax",
		"ps -p 1,2 -o pid,command",
		"ps -ww",
		"ps -tt",
		"ps -L",
		"ps -Dboth",
		"ps 1234",
		"ps -o etime,nlwp",
		"ps --libxo=json",
		"ps --libxo json",
		"ps -e",
		"ps -M core",
		"ps -N /boot/kernel/kernel",
		"pgrep -S -P 1 sshd",
		"pidof -s sshd",
		"pstree -g 2 -p 1",
		"fstat -p 1",
		"procstat -f 1",
		"procstat -k 1",
		"procstat -r 1",
		"sockstat -46l -p 22,80-81",
		"vmstat -H -w 1 -c 5",
		"uptime",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (closed FreeBSD diagnostic form)", input, got)
			}
		})
	}
}

func TestFreeBSDDiagnosticsRejectUnknownFlags(t *testing.T) {
	withShellPlatform(t, "freebsd")
	for _, input := range []string{
		"pgrep -F /var/run/x.pid sshd",
		"pgrep -M core sshd",
		"pgrep -P abc sshd",
		"pgrep",
		"pidof -c sshd",
		"pidof",
		"pstree -f input",
		"pstree -g 4",
		"pstree -u root",
		"fstat",
		"fstat /etc/passwd",
		"fstat -N kernel -p 1",
		"fstat -p abc",
		"procstat -v 1",
		"procstat -f",
		"procstat -f abc",
		"procstat -a -f",
		"procstat -f core.1",
		"sockstat -j any",
		"sockstat -p 0",
		"sockstat -p 70000",
		"sockstat -P tcp",
		"vmstat -M core",
		"vmstat -w 1",
		"vmstat -w",
		"vmstat -c",
		"vmstat -wc",
		"vmstat -w 18446744073709551616 -c 1",
		"vmstat -w 1 -c 18446744073709551616",
		"vmstat 1 5",
		"uptime -p",
		"dmesg",
		"dmesg -a",
		"dmesg -c",
		"dmesg -M core",
		"service sshd status",
		"service sshd restart",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (unlisted FreeBSD form)", input, got)
			}
		})
	}
}

func TestFreeBSDOnlyFormsDeniedOnLinux(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"pgrep -S sshd",
		"pstree -g 2 -p 1",
		"fstat -p 1",
		"procstat -f 1",
		"sockstat -l",
		"vmstat -w 1 -c 5",
		"dmesg",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) on Linux = %q, want mutating", input, got)
			}
		})
	}
}

func TestFreeBSDDiagnosticsDirectRouteOnly(t *testing.T) {
	withShellPlatform(t, "freebsd")
	for _, input := range []string{
		"ps -ax && ls",
		"fstat -p 1 > out",
		"FOO=bar sockstat -l",
		`sh -c "procstat -f 1 && ls ~/x"`,
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (FreeBSD diagnostics are direct-route only)", input, got)
			}
		})
	}
	if got := classifyReadOnlyShell(shellCtx(t, `sh -c "procstat -f 1"`)); got != ClassReadOnly {
		t.Fatalf(`classifyReadOnlyShell(sh -c "procstat -f 1") = %q, want read_only (recognized wrapper, every raw token inert)`, got)
	}
}

func TestPSDirectArbitraryArgumentsReadOnly(t *testing.T) {
	for _, platform := range []string{"linux", "freebsd"} {
		for _, input := range []string{
			"ps -wwZlmjc --sort=start_time",
			"ps -Ao user,pid,ppid,pcpu,etimes,args",
			"ps --no-headers --cols 400",
			"ps 1 2 3",
			"ps -N /boot/kernel/kernel -M /var/crash/vmcore.0",
			"ps --libxo=xml,pretty -auxww",
			"ps -zzz --not-a-real-option",
			`ps "$HOME"`,
			"ps '*.go'",
		} {
			t.Run(platform+"/"+input, func(t *testing.T) {
				withShellPlatform(t, platform)
				if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
					t.Fatalf("classifyReadOnlyShell(%q) on %s = %q, want read_only (ps has no documented option that writes, executes, opens a network connection, or escapes scope, so its option set is not an allowlist)", input, platform, got)
				}
			})
		}
	}
}

func TestPSDirectExpansionSpelledArgumentsAutoAllow(t *testing.T) {
	for _, platform := range []string{"linux", "freebsd"} {
		for _, input := range []string{`ps "$HOME"`, "ps '*.go'"} {
			for _, mode := range []string{"build", modeAutoEdits, modePlan} {
				t.Run(platform+"/"+mode+"/"+input, func(t *testing.T) {
					withShellPlatform(t, platform)
					f := newFixture(neverPrompt, nil)
					req, mc := shellReqCtxFor(t, mode, input)
					d := mustAuthorizeMode(t, req, mc, f.deps)
					assertModeAutoAllow(t, f, d)
				})
			}
		}
	}
}

func TestPSRouteBoundariesUnchanged(t *testing.T) {
	for _, platform := range []string{"linux", "freebsd"} {
		for _, input := range []string{
			"LD_PRELOAD=/tmp/x.so ps -ef",
			"FOO=bar ps -ef",
			"ps -ef > out",
			"ps -ef && ls",
			`sh -c "ps -ef && ls ~/x"`,
			`ps "$(id)"`,
		} {
			t.Run(platform+"/"+input, func(t *testing.T) {
				withShellPlatform(t, platform)
				if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
					t.Fatalf("classifyReadOnlyShell(%q) on %s = %q, want mutating (assignment, redirection, compound, wrapper, and substitution routes keep their boundary)", input, platform, got)
				}
			})
		}
		for _, input := range []string{"ps $(id)", "ps -p `id -u`"} {
			t.Run(platform+"/"+input, func(t *testing.T) {
				withShellPlatform(t, platform)
				split, err := SplitCommand(input)
				if err != nil {
					t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
				}
				if split.AllowedShell {
					t.Fatalf("SplitCommand(%q).AllowedShell = true, want false (command substitution rejected)", input)
				}
				mc := ModeContext{Stages: split.Stages, LiteralRoute: split.LiteralRoute}
				if got := classifyReadOnlyShell(MatchRequest{}, mc); got != ClassMutating {
					t.Fatalf("classifyReadOnlyShell(%q substitution) on %s = %q, want mutating", input, platform, got)
				}
			})
		}
	}
}

func TestPSInertWrapperAndNullRedirectRoutesStayReadOnly(t *testing.T) {
	for _, platform := range []string{"linux", "freebsd"} {
		for _, input := range []string{
			`sh -c "ps --help"`,
			`sh -c "ps -ef"`,
			`sh -c "ps aux"`,
		} {
			t.Run(platform+"/"+input, func(t *testing.T) {
				withShellPlatform(t, platform)
				req, mc := shellCtx(t, input)
				if !mc.LiteralRoute {
					t.Fatalf("SplitCommand(%q) did not take the literal route", input)
				}
				if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
					t.Fatalf("classifyReadOnlyShell(%q) on %s = %q, want read_only (recognized wrapper, every raw token inert — this route was open to ps before this task)", input, platform, got)
				}
			})
		}
		for _, input := range []string{
			"ps --help 2>/dev/null",
			"ps -ef 2>/dev/null",
			"ps aux >/dev/null",
		} {
			t.Run(platform+"/"+input, func(t *testing.T) {
				withShellPlatform(t, platform)
				if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
					t.Fatalf("classifyReadOnlyShell(%q) on %s = %q, want read_only (bare /dev/null redirect stripped before classification — this route was open to ps on Linux before this task)", input, platform, got)
				}
			})
		}
		for _, input := range []string{`sh -c "ps --help"`, "ps --help 2>/dev/null"} {
			for _, mode := range []string{"build", modeAutoEdits, modePlan} {
				t.Run(platform+"/"+mode+"/"+input, func(t *testing.T) {
					withShellPlatform(t, platform)
					f := newFixture(neverPrompt, nil)
					req, mc := shellReqCtxFor(t, mode, input)
					d := mustAuthorizeMode(t, req, mc, f.deps)
					assertModeAutoAllow(t, f, d)
				})
			}
		}
	}
}

func TestPSLiteralDetectorMatchesReadOnlyRoutes(t *testing.T) {
	for _, platform := range []string{"linux", "freebsd"} {
		for _, tc := range []struct {
			input    string
			class    OperationClass
			detectPS bool
		}{
			{`sh -c "ps --libxo=html"`, ClassReadOnly, true},
			{"ps --libxo=HTML 2>/dev/null", ClassReadOnly, true},
			{"ps --libxo=x 2>&1", ClassReadOnly, true},
			{`sh -c "ps --libxo=x && ls"`, ClassReadOnly, true},
			{"ls 2>/dev/null", ClassReadOnly, false},
			{"ps --libxo=x > out", ClassMutating, false},
			{`sh -c "ps --libxo=$VALUE"`, ClassMutating, true},
		} {
			t.Run(platform+"/"+tc.input, func(t *testing.T) {
				withShellPlatform(t, platform)
				req, mc := shellCtx(t, tc.input)
				if got := classifyReadOnlyShell(req, mc); got != tc.class {
					t.Fatalf("classifyReadOnlyShell(%q) = %q, want %q", tc.input, got, tc.class)
				}
				if got := LiteralRunsPS(req.Subject); got != tc.detectPS {
					t.Fatalf("LiteralRunsPS(%q) = %v, want %v", req.Subject, got, tc.detectPS)
				}
			})
		}
	}
	if LiteralRunsPS(`ps --libxo=x "`) {
		t.Fatal("LiteralRunsPS accepted malformed literal text")
	}
}

func TestFreeBSDPSModeIndependent(t *testing.T) {
	withShellPlatform(t, "freebsd")
	for _, input := range []string{
		"ps -ww", "ps -tt", "ps -L", "ps -Dboth", "ps 1234", "ps -o etime,nlwp", "ps --libxo=json",
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

func TestProcessControlStillRejected(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"kill 1",
		"kill -9 1",
		"pkill foo",
		"fuser -k /var/run/x.pid",
		"ss -K",
		"lsof /etc/passwd",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (process/socket control)", input, got)
			}
		})
	}
}

func TestDiagnosticsRouteVerdicts(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"ps -ef", "pgrep foo", "pidof sshd", "pstree -p", "lsof -p 1", "ss -tlnp", "free -m", "vmstat", "uptime",
	} {
		t.Run(input, func(t *testing.T) {
			for _, s := range stagedCtxs(t, "", input+" && ls") {
				if got := classifyReadOnlyShell(s.req, s.mc); got != ClassReadOnly {
					t.Fatalf("classifyReadOnlyShell(%q stage %q) = %q, want read_only (each staged stage is classified on its own)", input+" && ls", s.req.Subject, got)
				}
			}
		})
	}
	for _, input := range []string{
		`sh -c "ps aux && ls ~/x"`,
		"ps aux > out",
		"free -m > out",
		"FOO=bar ps aux",
		"LD_PRELOAD=/x/evil.so ps -ef",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (wrapper chain, redirection or environment assignment)", input, got)
			}
		})
	}
	if got := classifyReadOnlyShell(shellCtx(t, `sh -c "ps aux"`)); got != ClassReadOnly {
		t.Fatalf(`classifyReadOnlyShell(sh -c "ps aux") = %q, want read_only (recognized wrapper, every raw token inert)`, got)
	}
}

func TestJournalctlBoundedReadOnly(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"journalctl --no-pager -n 200",
		"journalctl -n 200 --no-pager",
		"journalctl --no-pager -n200",
		"journalctl --no-pager --lines 50",
		"journalctl --no-pager --lines=50",
		"journalctl --no-pager -n 1000",
		"journalctl --no-pager -n 200 -u foo.service",
		"journalctl --no-pager -n 50 --unit foo.service",
		"journalctl --no-pager -n 50 --unit=foo.service",
		"journalctl --no-pager -n 50 -ufoo.service",
		"journalctl --no-pager -n 20 -p err",
		"journalctl --no-pager -n 20 --priority=3",
		"journalctl --no-pager -n 20 -perr",
		"journalctl --no-pager -n 20 --since yesterday --until now",
		"journalctl --no-pager -n 20 -u foo.service -p warning --since yesterday",
		"journalctl --no-pager -n 20 | grep err | head",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (bounded pager-free journal read)", input, got)
			}
		})
	}
}

func TestJournalctlRejectsUnboundedAndLifecycle(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"journalctl -n 20",
		"journalctl --no-pager",
		"journalctl --no-pager -n 99999",
		"journalctl --no-pager -n 0",
		"journalctl --no-pager -n0",
		"journalctl --no-pager --lines=0",
		"journalctl --no-pager -n abc",
		"journalctl --no-pager -n",
		"journalctl --no-pager -n -u foo.service",
		"journalctl --no-pager -n 20 -f",
		"journalctl --no-pager -n 20 --follow",
		"journalctl --no-pager -n 20 --vacuum-size=1G",
		"journalctl --no-pager -n 20 --vacuum-time=1d",
		"journalctl --no-pager -n 20 --vacuum-files=2",
		"journalctl --no-pager -n 20 --rotate",
		"journalctl --no-pager -n 20 --flush",
		"journalctl --no-pager -n 20 --sync",
		"journalctl --no-pager -n 20 --relinquish-var",
		"journalctl --no-pager -n 20 --setup-keys",
		"journalctl --no-pager -n 20 --verify",
		"journalctl --no-pager -n 20 --root /mnt",
		"journalctl --no-pager -n 20 --directory /var/log/journal",
		"journalctl --no-pager -n 20 -D /var/log/journal",
		"journalctl --no-pager -n 20 --file /var/log/journal/x.journal",
		"journalctl --no-pager -n 20 --machine container",
		"journalctl --no-pager -n 20 -M container",
		"journalctl --no-pager -n 20 --namespace ns",
		"journalctl --no-pager -n 20 --output-fields=MESSAGE",
		"journalctl --no-pager -n 20 -o json",
		"journalctl --no-pager -n 20 --pager-end",
		"journalctl --no-pager -n 20 -e",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (unbounded, missing --no-pager, or lifecycle/scope-escape flag)", input, got)
			}
		})
	}
}

func TestDmesgBoundedReadOnly(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"dmesg --nopager --buffer-size 4096",
		"dmesg -P -s 4096",
		"dmesg -P -s 4096 -T",
		"dmesg -PxT -s 4096",
		"dmesg --nopager --ctime --buffer-size=4096",
		"dmesg -P -k -s 4096",
		"dmesg -P -l err -s 4096",
		"dmesg --nopager --level err --buffer-size 4096",
		"dmesg -P --level=err,warn -s 4096",
		"dmesg -P -f kern -s 4096",
		"dmesg -Plerr -s 4096",
		"dmesg -Ps4096",
		"dmesg -P -s 1048576",
		"dmesg -P -s 4096 | grep -i error | head",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (bounded pager-free kernel-buffer read)", input, got)
			}
		})
	}
}

func TestDmesgRejectsClearAndFollow(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"dmesg",
		"dmesg -T",
		"dmesg -C",
		"dmesg --clear",
		"dmesg -c",
		"dmesg --read-clear",
		"dmesg -P -C",
		"dmesg -D",
		"dmesg -E",
		"dmesg -n 1",
		"dmesg --console-level 1",
		"dmesg -w",
		"dmesg --follow",
		"dmesg --follow-new",
		"dmesg -F /var/log/dmesg",
		"dmesg --file /var/log/dmesg",
		"dmesg -P",
		"dmesg --nopager",
		"dmesg -P -T",
		"dmesg -P -s 0",
		"dmesg -P -s0",
		"dmesg -P --buffer-size=0",
		"dmesg -P -s abc",
		"dmesg -P -s",
		"dmesg -P -s 2097152",
		"dmesg -P --buffer-size 2097152",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (bare dump, clear, console, follow, or file source)", input, got)
			}
		})
	}
}

func TestLogReadersPlatformGated(t *testing.T) {
	withShellPlatform(t, "freebsd")
	for _, input := range []string{
		"journalctl --no-pager -n 200",
		"journalctl --no-pager -n 20 -u foo.service",
		"dmesg -P -s 4096",
		"dmesg --nopager --ctime --buffer-size 4096",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) with non-Linux platform = %q, want mutating", input, got)
			}
		})
	}
}

func TestLogReadersDirectRouteOnly(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"journalctl --no-pager -n 20 && ls",
		"dmesg -P -s 4096 && ls",
		"dmesg -P -s 4096 && journalctl --no-pager -n 20",
		`sh -c "journalctl --no-pager -n 20 && ls ~/x"`,
		`sh -c "dmesg -P -s 4096 && ls ~/x"`,
		"journalctl --no-pager -n 20 > out",
		"dmesg -P -s 4096 > out",
		"FOO=bar journalctl --no-pager -n 20",
		"LD_PRELOAD=/x/evil.so dmesg -P -s 4096",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (log readers are direct-route only)", input, got)
			}
		})
	}
	for _, input := range []string{`sh -c "journalctl --no-pager -n 20"`, `sh -c "dmesg -P -s 4096"`} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (recognized wrapper, every raw token inert)", input, got)
			}
		})
	}
	for _, input := range []string{
		"journalctl --no-pager -n $(echo 20)",
		"dmesg -P $(echo -T)",
	} {
		t.Run(input, func(t *testing.T) {
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if split.AllowedShell {
				t.Fatalf("SplitCommand(%q).AllowedShell = true, want false (command substitution rejected)", input)
			}
			mc := ModeContext{Stages: split.Stages, LiteralRoute: split.LiteralRoute}
			if got := classifyReadOnlyShell(MatchRequest{}, mc); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q substitution) = %q, want mutating", input, got)
			}
		})
	}
}

func TestColFilterReadOnly(t *testing.T) {
	for _, input := range []string{"col", "col -b", "col -bx", "col -l 100", "cat notes.txt | col -b | head"} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (col only reformats stdin)", input, got)
			}
		})
	}
	for _, input := range []string{"col -b > out.txt", "col -b | tee out.txt"} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (the redirect or the sibling stage decides)", input, got)
			}
		})
	}
}

func TestTopBoundedBatchReadOnly(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"top -b -n 1",
		"top -b -n 1 -e m -o +RES",
		"top -b -n 1 -p 123",
		"top -b -n 1 -p123",
		"top -b -n 3 -p 123,456",
		"top -b -n1",
		"top -b -n 1 -E g -H",
		"top -b -n 1 -o %CPU",
		"top -b -n 1 -O",
		"top -b -n 1000 -h",
		"top -b -n 5 | head -20",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (bounded batch process snapshot)", input, got)
			}
		})
	}
}

func TestTopRejectsInteractiveAndUnboundedForms(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"top",
		"top -n 1",
		"top -d 1",
		"top -b",
		"top -b -n 99999",
		"top -b -n 0",
		"top -b -n",
		"top -b -n abc",
		"top -bn1",
		"top -b -n 1 -d 1",
		"top -b -n 1 -u root",
		"top -b -n 1 -s",
		"top -b -n 1 -p abc",
		"top -b -n 1 -p",
		"top -b -n 1 -p $$",
		"top -b -n 1 -e x",
		"top -b -n 1 -E x",
		"top -b -n 1 -o",
		"top -b -n 1 -o RES!",
		"top -b -n 1 -o +",
		"top -b -n 1 -H1",
		"top -b -n 1 sshd",
		"top --batch-mode --iterations 1",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (interactive, unbounded, or unlisted form)", input, got)
			}
		})
	}
}

func TestTopPlatformGated(t *testing.T) {
	for _, platform := range []string{"freebsd", "darwin"} {
		for _, input := range []string{"top -b -n 1", "top -b -n 1 -e m -o +RES", "top -b -n 1 -p 123"} {
			t.Run(platform+"/"+input, func(t *testing.T) {
				withShellPlatform(t, platform)
				if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
					t.Fatalf("classifyReadOnlyShell(%q) with %s platform = %q, want mutating", input, platform, got)
				}
			})
		}
	}
}

func TestTopDirectRouteOnly(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{
		"top -b -n 1 && ls",
		"top -b -n 1 > out",
		"FOO=bar top -b -n 1",
		`sh -c "top -b -n 1 && ls ~/x"`,
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (top is direct-route only)", input, got)
			}
		})
	}
	for _, input := range []string{`sh -c "top -b -n 1"`} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (recognized wrapper, every raw token inert)", input, got)
			}
		})
	}
}

func TestColAndTopModeIndependent(t *testing.T) {
	withShellPlatform(t, "linux")
	for _, input := range []string{"col -b", "top -b -n 1"} {
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

var noExecShellAccepted = []struct {
	input  string
	tokens []string
}{
	{"bash -n", []string{"bash", "-n"}},
	{"bash -n script.sh", []string{"bash", "-n", "script.sh"}},
	{"bash -n scripts/deploy.sh", []string{"bash", "-n", "scripts/deploy.sh"}},
	{"bash -o noexec", []string{"bash", "-o", "noexec"}},
	{"bash -o noexec script.sh", []string{"bash", "-o", "noexec", "script.sh"}},
	{"bash -O extglob -n", []string{"bash", "-O", "extglob", "-n"}},
	{"bash -O extglob -n script.sh", []string{"bash", "-O", "extglob", "-n", "script.sh"}},
	{"bash -n -O extglob script.sh", []string{"bash", "-n", "-O", "extglob", "script.sh"}},
	{"sh -n", []string{"sh", "-n"}},
	{"sh -n script.sh", []string{"sh", "-n", "script.sh"}},
	{"sh -n a.sh b.sh", []string{"sh", "-n", "a.sh", "b.sh"}},
}

func assertDirectStageTokens(t *testing.T, input string, stage StageNormalization, want []string) {
	t.Helper()
	if stage.Route != RouteDirect {
		t.Fatalf("%q stage route = %v, want RouteDirect so dispatch runs the exact validated argv", input, stage.Route)
	}
	if len(stage.Assignments) != 0 {
		t.Fatalf("%q stage assignments = %v, want none", input, stage.Assignments)
	}
	if strings.Join(stage.Tokens, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%q stage tokens = %v, want %v", input, stage.Tokens, want)
	}
}

func TestNoExecShellSyntaxChecksTakeDirectRoute(t *testing.T) {
	for _, tc := range noExecShellAccepted {
		t.Run(tc.input, func(t *testing.T) {
			split, err := SplitCommand(tc.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", tc.input, err)
			}
			if split.LiteralRoute || len(split.Stages) != 1 {
				t.Fatalf("SplitCommand(%q) = literalRoute %v with %d stages, want exactly one direct stage", tc.input, split.LiteralRoute, len(split.Stages))
			}
			assertDirectStageTokens(t, tc.input, split.Stages[0], tc.tokens)
			if got := classifyReadOnlyShell(shellCtx(t, tc.input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (accepted no-exec syntax check)", tc.input, got)
			}
		})
	}
}

func TestNoExecShellSyntaxChecksAutoAllowInEveryMode(t *testing.T) {
	for _, tc := range noExecShellAccepted {
		for _, mode := range []string{"build", modeAutoEdits, modePlan} {
			t.Run(mode+"/"+tc.input, func(t *testing.T) {
				f := newFixture(neverPrompt, nil)
				req, mc := shellReqCtxFor(t, mode, tc.input)
				assertModeAutoAllow(t, f, mustAuthorizeMode(t, req, mc, f.deps))
			})
		}
	}
}

func TestNoExecShellPipelineKeepsValidatedArgv(t *testing.T) {
	const input = "bash -n a.sh | head"
	split, err := SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
	}
	if split.LiteralRoute || len(split.Stages) != 2 {
		t.Fatalf("SplitCommand(%q) = literalRoute %v with %d stages, want two direct stages", input, split.LiteralRoute, len(split.Stages))
	}
	assertDirectStageTokens(t, input, split.Stages[0], []string{"bash", "-n", "a.sh"})
	if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
		t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
	}
}

func TestNoExecShellStagedChainKeepsValidatedArgvInEveryMode(t *testing.T) {
	for _, tc := range []struct {
		input  string
		tokens [][]string
	}{
		{"bash -n a.sh && ls", [][]string{{"bash", "-n", "a.sh"}, {"ls"}}},
		{"sh -n a.sh; bash -O extglob -n b.sh", [][]string{{"sh", "-n", "a.sh"}, {"bash", "-O", "extglob", "-n", "b.sh"}}},
	} {
		for _, mode := range []string{"build", modeAutoEdits, modePlan} {
			t.Run(mode+"/"+tc.input, func(t *testing.T) {
				stages := stagedCtxs(t, mode, tc.input)
				if len(stages) != len(tc.tokens) {
					t.Fatalf("stagedCtxs(%q) = %d stages, want %d", tc.input, len(stages), len(tc.tokens))
				}
				for i, s := range stages {
					assertDirectStageTokens(t, tc.input, s.mc.Stages[0], tc.tokens[i])
					if got := classifyReadOnlyShell(s.req, s.mc); got != ClassReadOnly {
						t.Fatalf("classifyReadOnlyShell(%q stage %q) = %q, want read_only (the staged route runs the exact validated argv)", tc.input, s.req.Subject, got)
					}
					f := newFixture(neverPrompt, nil)
					assertModeAutoAllow(t, f, mustAuthorizeMode(t, s.req, s.mc, f.deps))
				}
			})
		}
	}
}

// commandLookupPATH points $PATH at a directory holding a single `magick` executable, so every
// `command -v` case is judged against a known lookup namespace rather than the host's binaries.
func commandLookupPATH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "magick")
	writeExecutable(t, path)
	t.Setenv("PATH", dir)
	return path
}

func TestCommandLookupTakesDirectRouteAndClassifiesReadOnly(t *testing.T) {
	commandLookupPATH(t)
	const input = "command -v magick"
	split, err := SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
	}
	if split.LiteralRoute || len(split.Stages) != 1 {
		t.Fatalf("SplitCommand(%q) = literalRoute %v with %d stages, want exactly one direct stage", input, split.LiteralRoute, len(split.Stages))
	}
	assertDirectStageTokens(t, input, split.Stages[0], []string{"command", "-v", "magick"})
	if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
		t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (an accepted builtin lookup)", input, got)
	}
}

func TestCommandLookupAutoAllowsInEveryMode(t *testing.T) {
	for _, mode := range []string{"build", modeAutoEdits, modePlan} {
		t.Run(mode, func(t *testing.T) {
			commandLookupPATH(t)
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, mode, "command -v magick")
			assertModeAutoAllow(t, f, mustAuthorizeMode(t, req, mc, f.deps))
		})
	}
}

func TestCommandLookupStagedChainAutoAllowsInEveryMode(t *testing.T) {
	for _, mode := range []string{"build", modeAutoEdits, modePlan} {
		for _, input := range []string{"command -v magick && ls", "command -v magick; ls"} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				commandLookupPATH(t)
				stages := stagedCtxs(t, mode, input)
				if len(stages) != 2 {
					t.Fatalf("stagedCtxs(%q) = %d stages, want 2", input, len(stages))
				}
				assertDirectStageTokens(t, input, stages[0].mc.Stages[0], []string{"command", "-v", "magick"})
				for _, s := range stages {
					if got := classifyReadOnlyShell(s.req, s.mc); got != ClassReadOnly {
						t.Fatalf("classifyReadOnlyShell(%q stage %q) = %q, want read_only", input, s.req.Subject, got)
					}
					f := newFixture(neverPrompt, nil)
					assertModeAutoAllow(t, f, mustAuthorizeMode(t, s.req, s.mc, f.deps))
				}
			})
		}
	}
}

func typeLookupPATH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ls")
	writeExecutable(t, path)
	t.Setenv("PATH", dir)
	return path
}

var typeLookupRejected = []string{
	"type -a ls",
	"type -p ls",
	"type ls cat",
	"type nosuchprog",
	`type "ls"`,
	`type 'ls'`,
	`type l\s`,
	"type ./ls",
	"type ls=1",
	"FOO=1 type ls",
	"type",
	"/usr/bin/type ls",
	`"type" ls`,
	`t\ype ls`,
}

func TestTypeLookupTakesDirectRouteAndClassifiesReadOnly(t *testing.T) {
	typeLookupPATH(t)
	const input = "type ls"
	split, err := SplitCommand(input)
	if err != nil {
		t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
	}
	if split.LiteralRoute || len(split.Stages) != 1 {
		t.Fatalf("SplitCommand(%q) = literalRoute %v with %d stages, want exactly one direct stage", input, split.LiteralRoute, len(split.Stages))
	}
	assertDirectStageTokens(t, input, split.Stages[0], []string{"type", "ls"})
	if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
		t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
	}
}

func TestTypeLookupRejectedFormsTakeLiteralRouteAndClassifyMutating(t *testing.T) {
	for _, input := range typeLookupRejected {
		t.Run(input, func(t *testing.T) {
			typeLookupPATH(t)
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if !split.LiteralRoute {
				t.Fatalf("SplitCommand(%q) took the direct route, want literal", input)
			}
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating", input, got)
			}
		})
	}
}

// commandLookupRejected is the adversarial deny table: every form outside the accepted lookup
// grammar, plus a name that does not resolve, must stay mutating so it prompts.
var commandLookupRejected = []string{
	"command",
	"command -v",
	"command -v magick ls",
	"command -v missingprog",
	"command -v cd",
	"command -V magick",
	"command -c foo",
	"command --version magick",
	"command magick",
	"command ls -la",
	"command sh -c 'rm -rf /'",
	"command env FOO=bar ls",
	"PATH=/opt/bin command -v magick",
	"FOO=bar command -v magick",
	`"command" -v magick`,
	`command "-v" magick`,
	`command -v 'magick'`,
	`command -v mag\ick`,
	`command -v 'ma gick'`,
	`command -v 'magick;ls'`,
	`command -v 'magick` + "`ls`'",
	`command -v '$magick'`,
	"command -v ./magick",
	"command -v /usr/bin/magick",
	"command -v -magick",
	"command -v FOO=bar",
	"/usr/bin/command -v magick",
	`sh -c "command -v magick"`,
	"command -v magick > out",
	"command -v magick > /dev/null",
	"command -v magick &",
	"type -p magick",
	"type -a magick",
}

func TestCommandLookupRejectedFormsMutating(t *testing.T) {
	for _, input := range commandLookupRejected {
		t.Run(input, func(t *testing.T) {
			commandLookupPATH(t)
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (only the closed lookup grammar auto-allows)", input, got)
			}
		})
	}
	for _, input := range []string{"command -v $(echo magick)", "command -v `echo magick`"} {
		t.Run(input, func(t *testing.T) {
			commandLookupPATH(t)
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if split.AllowedShell {
				t.Fatalf("SplitCommand(%q).AllowedShell = true, want false (substitution is refused before matching)", input)
			}
		})
	}
}

func TestCommandLookupRejectedFormsKeepModePosture(t *testing.T) {
	for _, input := range []string{"command -v missingprog", "command -V magick", "command ls -la", "type -p magick"} {
		t.Run(modePlan+"/"+input, func(t *testing.T) {
			commandLookupPATH(t)
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, input)
			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q = %+v, want a Plan deny with an envelope and no execution", input, d)
			}
		})
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				commandLookupPATH(t)
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				if f.cap.prompts != 1 {
					t.Fatalf("%q prompted %d times in %s, want 1", input, f.cap.prompts, mode)
				}
				if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
					t.Fatalf("decision for %q in %s = %+v, want a prompt-sourced once", input, mode, d)
				}
			})
		}
	}
}

func TestCommandLookupPolicyFailsClosed(t *testing.T) {
	for _, name := range []string{"command", "type"} {
		if policy := commandPolicies[name]; policy.validator == nil || !policy.argSensitive {
			t.Fatalf("%s policy = %+v, want an argument-sensitive validator", name, policy)
		}
	}
	for _, tokens := range [][]string{
		{"command"},
		{"command", "-v"},
		{"command", "-v", ""},
		{"command", "-v", "magick", "ls"},
		{"command", "-V", "magick"},
		{"command", "-c", "foo"},
		{"command", "-vp", "magick"},
		{"command", "magick"},
		{"command", "ls", "-la"},
		{"command", "sh", "-c", "rm -rf /"},
		{"command", "-v", "-magick"},
		{"command", "-v", "./magick"},
		{"command", "-v", "/usr/bin/magick"},
		{"command", "-v", "FOO=bar"},
		{"command", "-v", "mag ick"},
		{"command", "-v", "magick;ls"},
		{"command", "-v", "magick$X"},
		{"command", "-v", "magick`ls`"},
		{"command", "-v", "magick*"},
		{"command", "-v", "~magick"},
		{"/usr/bin/command", "-v", "magick"},
		{"type"},
		{"type", "-p", "magick"},
		{"type", "-a", "magick"},
		{"type", "magick", "ls"},
		{"type", "./magick"},
		{"type", "ls=1"},
		{"/usr/bin/type", "magick"},
	} {
		t.Run(strings.Join(tokens, " "), func(t *testing.T) {
			if stageTokensReadOnly(tokens) {
				t.Fatalf("stageTokensReadOnly(%v) = true, want false (only `command -v <plain-name>` and `type <plain-name>` are admitted)", tokens)
			}
		})
	}
	for _, tokens := range [][]string{
		{"type", "magick"},
		{"command", "-v", "magick"},
		{"command", "-v", "docker-compose"},
		{"command", "-v", "python3.12"},
		{"command", "-v", "g++"},
		{"command", "-v", "x86_64-linux-gnu-gcc"},
	} {
		t.Run(strings.Join(tokens, " "), func(t *testing.T) {
			if !stageTokensReadOnly(tokens) {
				t.Fatalf("stageTokensReadOnly(%v) = false, want true (accepted builtin lookup grammar)", tokens)
			}
		})
	}
}

var noExecShellRejected = []string{
	"bash",
	"sh",
	"bash -c true",
	"sh -c ls",
	"bash -lc ls",
	"bash --noexec",
	"bash --noexec script.sh",
	"bash -n -c 'rm -rf x'",
	"sh -n -c ls",
	"bash -i -n",
	"bash -n -i",
	"bash -l -n",
	"bash --login -n",
	"bash --rcfile x -n",
	"bash --norc -n",
	"bash -O extglob",
	"bash -O globstar -n",
	"bash -n -O globstar",
	"bash -O -n",
	"bash -nO extglob",
	"bash -o",
	"bash -o errexit",
	"bash -o noexec -o xtrace",
	"bash -o noexec -O extglob",
	"bash -n -n",
	"bash -n --",
	"bash -n -",
	"sh -o noexec",
	"sh -N",
	"/bin/bash -n script.sh",
	`"bash" -n script.sh`,
	`ba\sh -n script.sh`,
	"FOO=bar bash -n script.sh",
	"LD_PRELOAD=/x/evil.so sh -n script.sh",
	`sh -c "bash -n script.sh"`,
	`sh -c "bash -n a.sh && ls"`,
	"bash -n script.sh > out",
	"bash -n script.sh > /dev/null",
	"bash -n script.sh 2> /dev/null",
	"bash -n a.sh && ls",
	"bash -n a.sh; ls",
	"bash -n a.sh | head; ls",
	"cat a.sh | bash",
	"bash -n a.sh &",
}

func TestNoExecShellRejectedFormsMutating(t *testing.T) {
	for _, input := range noExecShellRejected {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (only the closed no-exec grammar auto-allows)", input, got)
			}
		})
	}
	for _, input := range []string{"bash -n $(echo a.sh)", "sh -n `echo a.sh`"} {
		t.Run(input, func(t *testing.T) {
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if split.AllowedShell {
				t.Fatalf("SplitCommand(%q).AllowedShell = true, want false (substitution is refused before matching)", input)
			}
		})
	}
}

func TestNoExecShellRejectedFormsKeepLiteralRoute(t *testing.T) {
	for _, input := range []string{
		"bash",
		"bash -c true",
		"bash --noexec script.sh",
		"bash -O globstar -n",
		"/bin/bash -n script.sh",
		`"bash" -n script.sh`,
		"FOO=bar bash -n script.sh",
		"LD_PRELOAD=/x/evil.so sh -n script.sh",
	} {
		t.Run(input, func(t *testing.T) {
			split, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) returned error: %v", input, err)
			}
			if !split.LiteralRoute {
				t.Fatalf("SplitCommand(%q) produced direct stages %+v, want the wrapper literal route", input, split.Stages)
			}
		})
	}
}

func TestNoExecShellPolicyFailsClosed(t *testing.T) {
	for _, tokens := range [][]string{
		{"bash"},
		{"sh"},
		{"bash", "-c", "true"},
		{"bash", "--noexec"},
		{"bash", "--noexec", "a.sh"},
		{"bash", "-n", "-c", "ls"},
		{"bash", "-O", "globstar", "-n"},
		{"bash", "-n", "-O", "globstar"},
		{"bash", "-O", "extglob"},
		{"bash", "-O", "extglob", "-o", "noexec"},
		{"bash", "-o"},
		{"bash", "-o", "errexit"},
		{"bash", "-i", "-n"},
		{"bash", "-n", "-i"},
		{"bash", "-nO", "extglob"},
		{"bash", "-n", "--"},
		{"bash", "-n", "-"},
		{"bash", "-n", ""},
		{"bash", "-n", "a.sh", "-c", "ls"},
		{"sh", "-o", "noexec"},
		{"sh", "-c", "ls"},
		{"sh", "-n", "-c", "ls"},
		{"/bin/bash", "-n"},
		{"/bin/sh", "-n"},
	} {
		t.Run(strings.Join(tokens, " "), func(t *testing.T) {
			if stageTokensReadOnly(tokens) {
				t.Fatalf("stageTokensReadOnly(%v) = true, want false (an unlisted shell option must fail closed)", tokens)
			}
		})
	}
	for _, tokens := range [][]string{
		{"bash", "-n"},
		{"bash", "-n", "a.sh"},
		{"bash", "-o", "noexec"},
		{"bash", "-O", "extglob", "-n"},
		{"bash", "-n", "-O", "extglob"},
		{"sh", "-n"},
		{"sh", "-n", "a.sh", "b.sh"},
	} {
		t.Run(strings.Join(tokens, " "), func(t *testing.T) {
			if !stageTokensReadOnly(tokens) {
				t.Fatalf("stageTokensReadOnly(%v) = false, want true (accepted no-exec syntax check)", tokens)
			}
		})
	}
}

func TestNoExecShellRejectedFormsKeepModePosture(t *testing.T) {
	for _, input := range []string{"bash -c true", "bash --noexec script.sh", `sh -c "bash -n script.sh"`, "bash -n script.sh > out"} {
		t.Run(modePlan+"/"+input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, input)
			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q = %+v, want a Plan deny with an envelope and no execution", input, d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a denied command must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				if f.cap.prompts != 1 {
					t.Fatalf("%q prompted %d times in %s, want 1", input, f.cap.prompts, mode)
				}
				if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
					t.Fatalf("decision for %q in %s = %+v, want a prompt-sourced once", input, mode, d)
				}
			})
		}
	}
}

type noExecShellCase struct {
	input  string
	tokens []string
}

// Every row was confirmed to execute its script against `/dev/stdin` on 2026-08-17.
func noExecShellCancellationCases() []noExecShellCase {
	prefixes := [][]string{
		{"bash", "-n"},
		{"bash", "-o", "noexec"},
		{"bash", "-O", "extglob", "-n"},
		{"bash", "-n", "-O", "extglob"},
		{"sh", "-n"},
	}
	cancellations := [][]string{{"+n"}, {"+o", "noexec"}, {"+xn"}}
	cases := make([]noExecShellCase, 0, len(prefixes)*len(cancellations)+1)
	for _, prefix := range prefixes {
		for _, cancellation := range cancellations {
			tokens := append(append(append([]string{}, prefix...), cancellation...), "a.sh")
			cases = append(cases, noExecShellCase{input: strings.Join(tokens, " "), tokens: tokens})
		}
	}
	return append(cases, noExecShellCase{input: "bash -n +", tokens: []string{"bash", "-n", "+"}})
}

func TestNoExecShellCancellationTokensRejected(t *testing.T) {
	for _, tc := range noExecShellCancellationCases() {
		t.Run(tc.input, func(t *testing.T) {
			if noExecShellTokens(tc.tokens) {
				t.Fatalf("noExecShellTokens(%v) = true, want false (the plus-spelled token restores execution)", tc.tokens)
			}
		})
	}
	for _, tokens := range [][]string{
		{"bash", "-n", "./+name.sh"},
		{"sh", "-n", "./+name.sh"},
	} {
		t.Run(strings.Join(tokens, " "), func(t *testing.T) {
			if !noExecShellTokens(tokens) {
				t.Fatalf("noExecShellTokens(%v) = false, want true (a plus-named script stays checkable through a path operand)", tokens)
			}
		})
	}
}

func TestBashNoExecOptionsLeavesPlusSpellingToOperandCheck(t *testing.T) {
	for _, tc := range noExecShellCancellationCases() {
		if tc.tokens[0] != "bash" {
			continue
		}
		t.Run(tc.input, func(t *testing.T) {
			args := tc.tokens[1:]
			rest := args[bashNoExecOptions(args):]
			if len(rest) == 0 || !strings.HasPrefix(rest[0], "+") {
				t.Fatalf("bashNoExecOptions(%v) consumed the plus-spelled cancellation as an option; it must fall through to the operand check", args)
			}
		})
	}
}

func directShellCtx(tokens []string) (MatchRequest, ModeContext) {
	return MatchRequest{Kind: subjectKindDirect, Subject: strings.Join(tokens, " "), SubjectTokens: tokens},
		ModeContext{Stages: []StageNormalization{{Route: RouteDirect, Tokens: tokens}}}
}

func TestNoExecShellCancellationNeverReadOnlyOnDirectRoute(t *testing.T) {
	for _, tc := range noExecShellCancellationCases() {
		t.Run(tc.input, func(t *testing.T) {
			if got := classifyReadOnlyShell(directShellCtx(tc.tokens)); got != ClassMutating {
				t.Fatalf("classifyReadOnlyShell(%v as a direct stage) = %q, want mutating", tc.tokens, got)
			}
		})
	}
}

func TestNoExecShellCancellationKeepsModePosture(t *testing.T) {
	for _, tc := range noExecShellCancellationCases() {
		t.Run(modePlan+"/"+tc.input, func(t *testing.T) {
			f := newFixture(neverPrompt, nil)
			req, mc := shellReqCtxFor(t, modePlan, tc.input)
			d := mustAuthorizeMode(t, req, mc, f.deps)
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q = %+v, want a Plan deny with an envelope and no execution", tc.input, d)
			}
			if len(f.cap.records) != 0 || len(f.cap.appends) != 0 {
				t.Fatalf("a denied command must not touch the cache or grant table: records=%v appends=%v", f.cap.records, f.cap.appends)
			}
		})
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+tc.input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, tc.input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				if f.cap.prompts != 1 {
					t.Fatalf("%q prompted %d times in %s, want 1", tc.input, f.cap.prompts, mode)
				}
				if d.Outcome != outcomeOnce || d.DenyEnvelope != "" {
					t.Fatalf("decision for %q in %s = %+v, want a prompt-sourced once", tc.input, mode, d)
				}
			})
		}
	}
}

func TestClassifyReadOnlyShellMercurialAuditedAdmissions(t *testing.T) {
	assertShellClass(t, []string{
		"hg st",
		"hg sum",
		"hg history",
		"hg identify",
		"hg --cwd main st",
		"hg --cwd=main sum",
		"hg --cwd main history",
		"hg --cwd main identify",
		"hg annotate docs/index.md",
		"hg blame docs/index.md",
		"hg tags",
		"hg branches",
		"hg tip",
		"hg paths",
		"hg version",
		"hg locate docs/*.md",
		"hg export -r 3",
		"hg verify",
		"hg admin::verify",
		"hg --cwd main annotate docs/index.md",
		"hg --cwd main blame docs/index.md",
		"hg --cwd=main tags",
		"hg --cwd main branches",
		"hg --cwd=main tip",
		"hg --cwd main paths",
		"hg --cwd=main version",
		"hg --cwd main locate docs/*.md",
		"hg --cwd main export -r 3",
		"hg --cwd=main verify",
		"hg --cwd=main admin::verify",
		"hg id",
		"hg id -r 3",
		"hg id -rtip",
		"hg id --rev 3",
		"hg id --rev=3",
		"hg id -n",
		"hg identify -i",
		"hg id -nibt",
		"hg resolve -l",
		"hg resolve --list",
		"hg --cwd main resolve -l",
		"hg --cwd=main resolve --list",
		"hg bookmarks",
		"hg bookmark",
		"hg bookmarks -l",
		"hg bookmarks --list",
		"hg bookmark --list",
		"hg --cwd main bookmarks",
		"hg --cwd=main bookmarks -l",
		"hg --cwd main bookmark --list",
		"hg branch",
		"hg --cwd main branch",
		"hg --cwd=main branch",
		"hg phase",
		"hg phase -r REV",
		"hg phase --rev REV",
		"hg phase --rev=REV",
		"hg phase -r A -r B",
		"hg --cwd main phase",
		"hg --cwd=main phase --rev REV",
		"hg help -e",
		"hg help --extension",
	}, ClassReadOnly)
}

func TestClassifyReadOnlyShellMercurialFailsClosed(t *testing.T) {
	assertShellClass(t, []string{
		// identify's transport options run the value as a program before any network contact, and a
		// positional SOURCE resolves through [paths] to a remote with no URL text in the stage.
		"hg id --ssh /tmp/x ssh://host/repo",
		"hg id -e /tmp/x ssh://host/repo",
		"hg id -ne /tmp/x ssh://host/repo",
		"hg id --remotecmd /tmp/x ssh://host/repo",
		"hg id --insecure ssh://host/repo",
		"hg id ssh://host/repo",
		"hg id default",
		"hg id ../other-clone",
		"hg identify default",
		"hg identify -i default",
		"hg summary --remote",
		"hg sum --remote",
		// the debugger reads Python from stdin; --debug is the accepted over-denial of its prefix rule
		"hg --debugger log",
		"hg log --debugger",
		"hg log --debug",
		"hg log --deb",
		"hg --debu status",
		// hg resolves unambiguous command prefixes; the classifier admits documented aliases only
		"hg sta",
		"hg stat",
		"hg summ",
		"hg ident",
		"hg annot",
		"hg vers",
		"hg expor",
		// file-writing flags, including the --option spelling --output's prefix rule cannot reach
		"hg export -o out.patch",
		"hg export --output=out.patch",
		"hg export -oout.patch",
		"hg admin::verify -o k=v",
		"hg admin::verify --option k=v",
		"hg admin::verify --optio k=v",
		"hg admin::verify --o k=v",
		// a template or style renders a configured auth.*.password verbatim
		"hg paths -Tjson",
		`hg paths --template '{url}'`,
		"hg paths --templ x",
		"hg paths --te x",
		"hg identify --style default",
		"hg status --style=compact",
		"hg log --sty x",
		"hg log --st x",
		"hg log -T x",
		`hg log -nT'{rev}'`,
		"hg annotate -Tjson docs/index.md",
		"hg tags -T x",
		// the cluster scan cannot tell a glued value from a bundle, so a revision spelled with an R,
		// o, or T loses its auto-allow — over-denial inside a cluster costs a prompt, never an allow
		"hg id -rREV",
		"hg log -rTIP",
		// configuration disclosure and the debug* surface stay out entirely
		"hg config",
		"hg showconfig",
		"hg config -e",
		"hg debugconfig",
		"hg debugstate",
		"hg debugshell",
		"hg debugcommands",
		// graphlog supplies glog, and the automatic environment loads no extension
		"hg glog",
		"hg glog -l 5",
		"hg --cwd main glog",
		// every resolve form but the two exact list spellings
		"hg resolve",
		"hg resolve -m path",
		"hg resolve -u path",
		"hg resolve --all",
		"hg resolve -l -m path",
		"hg resolve --li",
		"hg resolve --tool /tmp/x",
		"hg resolve -l extra",
		"hg --cwd main resolve -l --pager cat",
		"hg -R other resolve -l",
		// bookmarks writes on a positional NAME and on every flag but the exact list spellings
		"hg bookmarks name",
		"hg bookmark name",
		"hg bookmarks -d name",
		"hg bookmarks --delete name",
		"hg bookmarks -m old new",
		"hg bookmarks -r REV name",
		"hg bookmarks -i",
		"hg bookmarks -f name",
		"hg bookmarks --li",
		"hg bookmarks -l extra",
		"hg bookmarks -l -d name",
		"hg bookmarks -T json",
		`hg bookmarks --template '{bookmark}'`,
		"hg bookmarks --style default",
		`hg bookmarks -lT'{bookmark}'`,
		// branch takes no read-only argument; its experimental -r is the phase spelling that reads
		"hg branch newname",
		"hg branch -f name",
		"hg branch --force name",
		"hg branch -C",
		"hg branch --clean",
		"hg branch -r REV",
		"hg branch --rev REV",
		"hg branch --rev=REV",
		"hg branch -T json",
		"hg branch --style default",
		// every phase form but the bare and revision-only reads moves the phase boundary
		"hg phase -p -r REV",
		"hg phase --public -r REV",
		"hg phase -d",
		"hg phase -s",
		"hg phase -f -r REV",
		"hg phase -r REV -p",
		"hg phase --re REV",
		"hg phase --rev",
		"hg phase -r",
		"hg phase -rREV",
		"hg phase REV",
		"hg phase -T json",
		"hg phase --style default",
		// shelve is extension-dependent, and the automatic environment loads no extension
		"hg shelve",
		"hg shelve -l",
		"hg shelve --list",
		"hg shelve -l --patch",
		"hg shelve --list --stat",
		"hg shelve -n name",
		"hg shelve --delete",
		"hg shelve -l --delete",
		"hg --cwd main shelve -l",
		// a bare bisect resumes the search and updates the working directory
		"hg bisect",
		"hg bisect -g",
		"hg bisect --good",
		"hg bisect -b",
		"hg bisect -r",
		"hg bisect -c cmd",
		"hg --cwd main bisect",
	}, ClassMutating)
}

func TestMercurialTemplateAndStylePrefixesAllFailClosed(t *testing.T) {
	var inputs []string
	for _, flag := range []string{"--template", "--style"} {
		for n := 3; n <= len(flag); n++ {
			inputs = append(inputs, "hg log "+flag[:n]+" x", "hg paths "+flag[:n]+"=x")
		}
	}
	assertShellClass(t, inputs, ClassMutating)
}

func TestClassifyReadOnlyShellMercurialRoutesUnchanged(t *testing.T) {
	assertShellClass(t, []string{
		"hg st | head -20",
		"hg history --limit 5 | head",
		"hg tags && hg branches",
		"hg st ; hg tip",
		"hg log 2>/dev/null",
		"hg id 2>/dev/null | head",
		"hg resolve -l 2>/dev/null",
		"cd main && hg st | head",
		"hg bookmarks | head",
		"hg bookmarks --list 2>/dev/null",
		"hg branch 2>/dev/null",
		"hg branch && hg bookmarks -l",
		"hg phase -r tip | head",
		"hg phase --rev tip 2>/dev/null",
		"hg branch ; hg phase",
	}, ClassReadOnly)

	assertShellClass(t, []string{
		`sh -c "hg st"`,
		`sh -c "hg resolve -l"`,
		"hg st > out.txt",
		"hg export -r 3 > out.patch",
		"hg resolve -l > out.txt",
		"hg export -r $R 2>/dev/null",
		"hg st $X && hg tip",
		"hg tags && hg commit -m x",
		`sh -c "hg bookmarks -l"`,
		`sh -c "hg branch"`,
		`sh -c "hg phase -r tip"`,
		"hg bookmarks > out.txt",
		"hg branch > out.txt",
		"hg phase -r tip > out.txt",
		"hg bookmarks $X 2>/dev/null",
		"hg branch $X 2>/dev/null",
		"hg phase -r $X 2>/dev/null",
		"hg bookmarks --config=alias.x=!sh",
		"hg branch --config=alias.x=!sh",
		"hg phase --config=alias.x=!sh -r tip",
		"hg -R other bookmarks -l",
		"hg -R other branch",
		"hg -R other phase -r tip",
		"hg --cwd main bookmarks --pager cat",
		"hg --cwd main branch --pager cat",
		"hg --cwd main phase --pager cat",
		"hg branch && hg commit -m x",
	}, ClassMutating)
}

func TestMercurialAdmissionsModePosture(t *testing.T) {
	for _, input := range []string{
		"hg st", "hg resolve -l", "hg --cwd main resolve --list", "hg admin::verify", "hg paths",
		"hg branch", "hg bookmarks --list", "hg phase -r REV",
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

func TestMercurialExcludedFormsNeverReceiveAModeAutoAllow(t *testing.T) {
	for _, input := range []string{
		"hg glog", "hg config", "hg id default", "hg paths -Tjson", "hg resolve --li", "hg sta",
		"hg shelve", "hg shelve -l", "hg shelve --list", "hg shelve -l --patch", "hg shelve --list --stat",
		"hg shelve -n name", "hg shelve --delete", "hg shelve -l --delete",
		"hg bisect", "hg bisect --good",
		"hg bookmarks name", "hg bookmarks -T json", "hg branch newname", "hg branch -r REV", "hg phase -p -r REV",
	} {
		for _, mode := range []string{"build", modeAutoEdits} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				f := newFixture(choose(PromptAllowOnce), nil)
				req, mc := shellReqCtxFor(t, mode, input)
				d := mustAuthorizeMode(t, req, mc, f.deps)
				if f.cap.prompts != 1 {
					t.Fatalf("%q prompted %d times in %s, want 1", input, f.cap.prompts, mode)
				}
				if d.ReadOnlyAuto {
					t.Fatalf("%q in %s carried the read-only mode-auto source: %+v", input, mode, d)
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
			if d.Outcome != outcomeDeny || d.DenyEnvelope == "" {
				t.Fatalf("decision for %q = %+v, want deny with an envelope", input, d)
			}
		})
	}
}

func TestClassifyReadOnlyShellEnvClearedEnvironmentIsNeverAutoAllowed(t *testing.T) {
	req, mc := shellCtx(t, `env -i PATH=/usr/bin ls`)

	if len(mc.Stages) != 1 {
		t.Fatalf("Stages = %+v, want one direct stage", mc.Stages)
	}
	stage := mc.Stages[0]
	if !slices.Equal(stage.Tokens, []string{"ls"}) {
		t.Fatalf("Tokens = %v, want the allowlisted inner command [ls]", stage.Tokens)
	}
	if !stage.ClearEnvironment {
		t.Fatal("ClearEnvironment = false, want the -i state preserved")
	}
	if !slices.Equal(stage.Assignments, []string{"PATH=/usr/bin"}) {
		t.Fatalf("Assignments = %v, want the mandatory PATH assignment preserved", stage.Assignments)
	}
	if got := classifyReadOnlyShell(req, mc); got != ClassMutating {
		t.Fatalf("classifyReadOnlyShell = %q, want mutating (an accepted -i stage always carries an assignment)", got)
	}

	bareReq, bareMC := shellCtx(t, "env ls")
	if got := classifyReadOnlyShell(bareReq, bareMC); got != ClassReadOnly {
		t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only (bare env stays execution-equivalent)", "env ls", got)
	}
}

func TestStripClassifierHereStrings(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"jq -n input <<< 1", "jq -n input", true},
		{"grep x <<< 'a b'", "grep x", true},
		{"cat a <<< x b", "cat a b", true},
		{"jq . <<< a; jq . <<< 'b'", "jq .; jq .", true},
		{"jq . <<< x | head", "jq . | head", true},
		{"jq . <<< 'a $b' 2>/dev/null", "jq . 2>/dev/null", true},
		{"jq . <<<x", "jq .", true},
		{"grep x f 2>/dev/null", "grep x f 2>/dev/null", true},
		{"cat << EOF", "cat << EOF", true},
		{"echo '<<<' x", "echo '<<<' x", true},
		{"jq . <<< $VAR", "", false},
		{`jq . <<< "$VAR"`, "", false},
		{"jq . <<< $(id)", "", false},
		{"jq . <<< `id`", "", false},
		{`jq . <<< a\\b`, "", false},
		{`jq . <<< a\b`, "", false},
		{`jq . <<< "a"`, "", false},
		{"jq . 0<<< x", "", false},
		{"jq . 3<<< x", "", false},
		{"jq .<<< x", "", false},
		{"jq . <<<< x", "", false},
		{"<<< x", "", false},
		{"ls; <<< x cat", "", false},
		{" <<< x", "", false},
		{"jq . <<< ;", "", false},
		{"jq . <<< | cat", "", false},
		{"jq . <<<", "", false},
		{"jq . <<< <(rm x)", "", false},
		{"jq . <<< >(rm x)", "", false},
		{"jq . <<< {a,b}", "", false},
		{"jq . <<< ~", "", false},
		{"jq . <<< *", "", false},
		{"jq . <<< a>out", "", false},
		{"jq . <<< a<b", "", false},
		{"jq . <<< 'a'b", "", false},
		{"jq . <<< 1 3<<< x", "", false},
		{"ls\n<<< x inproj", "", false},
		{"ls\r<<< x inproj", "", false},
		{"jq . <<< x\nrm y", "", false},
		{"jq . <<< 'unterminated", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := stripClassifierHereStrings(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("stripClassifierHereStrings(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestHereStringClassifiesReadOnly(t *testing.T) {
	for _, input := range []string{
		`jq -n 'input' <<< '1'`,
		`grep x <<< 'a b'`,
		`jq -n '9223372036854775807 + 1'; jq -n '[match("(\\d+)"; "g")] | length' <<< '1h30m250ms'`,
	} {
		t.Run(input, func(t *testing.T) {
			req, mc := shellCtx(t, input)
			if !mc.LiteralRoute {
				t.Fatalf("SplitCommand(%q) did not take the literal route", input)
			}
			if got := classifyReadOnlyShell(req, mc); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
}

func TestHereStringBypassesStayMutating(t *testing.T) {
	for _, subject := range []string{
		"jq . <<< $VAR",
		`jq . <<< "$VAR"`,
		"jq . <<< $(id)",
		"jq . <<< `id`",
		`jq . <<< a\\b`,
		"jq . 0<<< x",
		"jq . 3<<< x",
		"cat << EOF",
		"jq . <<<< x",
		"<<< x",
		"rm x <<< y",
		"sh <<< 'rm x'",
		"xargs rm <<< f",
		"jq . <<< <(rm x)",
		"jq . <<< >(rm x)",
		"jq . <<< {a,b}",
		"jq . <<< a>out",
		"jq . <<< a<b",
		"jq . <<< 1 > out",
		"jq . <<< 1 >> out",
		"jq . <<< 1 2> err",
		"jq . <<< 1 3<<< x",
		"ls\n<<< x inproj",
		"ls\r<<< x inproj",
		"ls\n<<< x ls",
	} {
		t.Run(subject, func(t *testing.T) {
			if got := classifyLiteralCompound(subject); got != ClassMutating {
				t.Fatalf("classifyLiteralCompound(%q) = %q, want mutating", subject, got)
			}
		})
	}
}

func TestHereStringLiteralsRunHgAndPS(t *testing.T) {
	if !LiteralRunsHg("hg status <<< x") {
		t.Fatal("LiteralRunsHg(hg status <<< x) = false, want true")
	}
	if !LiteralRunsPS("ps aux <<< x") {
		t.Fatal("LiteralRunsPS(ps aux <<< x) = false, want true")
	}
}

func TestHereStringLeavesGrantIdentityAndNullStripUnchanged(t *testing.T) {
	for _, input := range []string{"jq . <<< a", "jq . <<< a; jq . <<< b", "grep x <<< 'a b' | head"} {
		t.Run(input, func(t *testing.T) {
			canon, err := CanonicalLiteralForm(input)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm(%q): %v", input, err)
			}
			if canon != input {
				t.Fatalf("CanonicalLiteralForm(%q) = %q, want the here-string text preserved", input, canon)
			}
			if _, ok := RecognizeSimpleCompoundForGrant(canon); ok {
				t.Fatalf("RecognizeSimpleCompoundForGrant(%q) recognized a here-string command", canon)
			}
			if _, ok := stripNullRedirects(canon); ok {
				t.Fatalf("stripNullRedirects(%q) accepted a here-string", canon)
			}
			changed := strings.Replace(canon, "<<< a", "<<< z", 1)
			changed = strings.Replace(changed, "<<< 'a b'", "<<< 'z b'", 1)
			if MatchesLiteralSubject(changed, canon) {
				t.Fatalf("a changed stdin word %q matched the stored subject %q", changed, canon)
			}
		})
	}
}

func TestBareEnvClassifiesReadOnly(t *testing.T) {
	for _, input := range []string{
		"env",
		"env | grep -i shell",
		`env | grep -i shell; printf 'x\n'`,
		`"env" | grep -i shell; printf 'x\n'`,
		`"env" ; printf x`,
		"env 2>/dev/null; printf x",
		"env <<< x",
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = %q, want read_only", input, got)
			}
		})
	}
	for _, subject := range []string{"env", `env | grep -i shell; printf 'x\n'`, "env; printf x"} {
		if got := classifyLiteralCompound(subject); got != ClassReadOnly {
			t.Fatalf("classifyLiteralCompound(%q) = %q, want read_only", subject, got)
		}
	}
}

func TestEnvWithArgumentsStaysNotReadOnly(t *testing.T) {
	for _, input := range []string{
		"env rm x",
		"env -i",
		"env -u X",
		"env FOO=bar",
		"FOO=1 env",
		"/usr/bin/env",
		"env sh -c 'id'",
		`"env"; printf x`,
	} {
		t.Run(input, func(t *testing.T) {
			if got := classifyReadOnlyShell(shellCtx(t, input)); got == ClassReadOnly {
				t.Fatalf("classifyReadOnlyShell(%q) = read_only, want not read_only", input)
			}
		})
	}
	if !stageTokensReadOnly([]string{"env"}) {
		t.Fatal(`stageTokensReadOnly(["env"]) = false, want true`)
	}
	for _, tokens := range [][]string{
		{"env", "rm", "x"},
		{"env", "-i"},
		{"env", "-u", "X"},
		{"env", "FOO=bar"},
		{"env", "sh", "-c", "id"},
	} {
		if stageTokensReadOnly(tokens) {
			t.Fatalf("stageTokensReadOnly(%q) = true, want false", tokens)
		}
	}
}

func TestBareEnvDoesNotWaiveNeighbourStageChecks(t *testing.T) {
	for _, subject := range []string{
		"env; sed -n '1p' f",
		"env; ps aux",
		"env; sort $X 2>/dev/null",
		`sh -c "env; ps $X"`,
	} {
		t.Run(subject, func(t *testing.T) {
			if got := classifyLiteralCompound(subject); got != ClassMutating {
				t.Fatalf("classifyLiteralCompound(%q) = %q, want mutating", subject, got)
			}
		})
	}
}
