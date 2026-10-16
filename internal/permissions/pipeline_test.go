// Tests for whole-command splitting: cd-prefix hint capture, pipeline splitting, and direct/literal/rejected routing.
package permissions

import "testing"

// assertDirect checks that res took the direct-pipeline route with the expected
// cd hint and per-stage canonical tokens.
func assertDirect(t *testing.T, res SplitResult, wantCd string, wantStages [][]string) {
	t.Helper()
	if !res.AllowedShell {
		t.Fatalf("AllowedShell = false (RejectedConstruct=%q), want direct route", res.RejectedConstruct)
	}
	if res.LiteralRoute {
		t.Fatalf("LiteralRoute = true (LiteralInput=%q), want direct route", res.LiteralInput)
	}
	if res.CdHint != wantCd {
		t.Fatalf("CdHint = %q, want %q", res.CdHint, wantCd)
	}
	if len(res.Stages) != len(wantStages) {
		t.Fatalf("got %d stages, want %d (%v)", len(res.Stages), len(wantStages), res.Stages)
	}
	for i, st := range res.Stages {
		if st.Route != RouteDirect {
			t.Fatalf("stage %d route = %v, want RouteDirect", i, st.Route)
		}
		if !equalStrings(st.Tokens, wantStages[i]) {
			t.Fatalf("stage %d tokens = %v, want %v", i, st.Tokens, wantStages[i])
		}
	}
}

func TestSplitCommand_DirectStages(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		cd     string
		stages [][]string
	}{
		{name: "single command", input: "git log", cd: "", stages: [][]string{{"git", "log"}}},
		{name: "two-stage pipeline", input: "git log | wc -l", cd: "", stages: [][]string{{"git", "log"}, {"wc", "-l"}}},
		{name: "three-stage pipeline", input: "a | b | c", cd: "", stages: [][]string{{"a"}, {"b"}, {"c"}}},
		{name: "leading env assignment", input: "FOO=bar git status", cd: "", stages: [][]string{{"git", "status"}}},
		{name: "leading envs in a piped stage", input: "git log | A=1 wc -l", cd: "", stages: [][]string{{"git", "log"}, {"wc", "-l"}}},
		{name: "pipe with no surrounding spaces", input: "git log|wc -l", cd: "", stages: [][]string{{"git", "log"}, {"wc", "-l"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := SplitCommand(tt.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", tt.input, err)
			}
			assertDirect(t, res, tt.cd, tt.stages)
		})
	}
}

// TestSplitCommand_CdPrefixPropagatesToEveryStage covers the combined
// `cd <path> && a | b | c` form: the cd prefix is stripped before pipeline
// splitting, so CdHint applies to every direct stage (Done-when item 1
// step order).
func TestSplitCommand_CdPrefixPropagatesToEveryStage(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		cd     string
		stages [][]string
	}{
		{name: "cd then single command", input: "cd /tmp && git log", cd: "/tmp", stages: [][]string{{"git", "log"}}},
		{name: "cd then two-stage pipeline", input: "cd /srv && a | b", cd: "/srv", stages: [][]string{{"a"}, {"b"}}},
		{name: "cd then three-stage pipeline", input: "cd /var && a | b | c", cd: "/var", stages: [][]string{{"a"}, {"b"}, {"c"}}},
		{name: "relative cd path kept raw", input: "cd sub/dir && ls", cd: "sub/dir", stages: [][]string{{"ls"}}},
		{name: "quoted cd path unquoted in hint", input: `cd "my dir" && ls`, cd: "my dir", stages: [][]string{{"ls"}}},
		{name: "home shortcut cd path kept raw for g135", input: "cd ~/proj && git status", cd: "~/proj", stages: [][]string{{"git", "status"}}},
		{name: "cd combined with leading env in a stage", input: "cd /tmp && FOO=bar git log | wc -l", cd: "/tmp", stages: [][]string{{"git", "log"}, {"wc", "-l"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := SplitCommand(tt.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", tt.input, err)
			}
			assertDirect(t, res, tt.cd, tt.stages)
		})
	}
}

// TestSplitCommand_CdPrefixOperatorBypass guards against a construct smuggled into the `cd <path>`
// prefix. tokenizeShell splits only on whitespace, so a path token such as `foo;bar` or `$(pwd)`
// looks like a single word; the prefix must not be stripped (CdHint stays empty) and the construct
// must never be routed to a direct command. A still-rejected construct (`$(`) is refused; accepted
// literal-route operators (`;`, `||`, a bare `|`, `&`, `&&`, or a redirection) route the whole
// prefix-stripped-nothing command to one byte-exact literal subject — never a direct stage, so nothing
// is smuggled past authorization either way.
func TestSplitCommand_CdPrefixOperatorBypass(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		rejected bool // true: AllowedShell==false; false: routes to a single literal subject
	}{
		{"semicolon in cd path", "cd foo;bar && ls", false},
		{"logical-or in cd path", "cd foo||bar && ls", false},
		{"command-sub in cd path", "cd $(pwd) && ls", true},
		{"pipe in cd path", "cd foo|bar && ls", false},
		{"background in cd path", "cd foo& && ls", false},
		{"redirection in cd path", "cd foo>bar && ls", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SplitCommand(tc.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error: %v", tc.input, err)
			}
			// The defense that matters in every case: the unsafe prefix is never captured as a cd hint
			// and the construct is never routed to a direct stage.
			if got.CdHint != "" {
				t.Errorf("SplitCommand(%q) captured CdHint %q from an unsafe prefix, want empty",
					tc.input, got.CdHint)
			}
			if tc.rejected {
				if got.AllowedShell {
					t.Errorf("SplitCommand(%q) AllowedShell = true (stages %v), want refused",
						tc.input, got.Stages)
				}
				return
			}
			if !got.AllowedShell || !got.LiteralRoute || got.Stages != nil {
				t.Errorf("SplitCommand(%q) = {allowed:%v literal:%v stages:%v}, want one byte-exact literal subject",
					tc.input, got.AllowedShell, got.LiteralRoute, got.Stages)
			}
		})
	}
}

// TestSplitCommand_CdPrefixQuotedOperator confirms the operator guard is
// quote-aware: a path whose special byte is quoted is a legitimate directory
// name, so the prefix is still stripped and the byte survives in the hint.
func TestSplitCommand_CdPrefixQuotedOperator(t *testing.T) {
	got, err := SplitCommand(`cd "foo;bar" && ls`)
	if err != nil {
		t.Fatalf("SplitCommand error: %v", err)
	}
	if !got.AllowedShell {
		t.Fatalf("AllowedShell = false, want a stripped prefix with a quoted path")
	}
	if got.CdHint != "foo;bar" {
		t.Errorf("CdHint = %q, want %q", got.CdHint, "foo;bar")
	}
}

// TestSplitCommand_RejectedConstructs covers: constructs outside the
// allowlist are refused with AllowedShell=false and the offending construct
// named; the permission system is skipped (no direct stages, no literal route).
func TestSplitCommand_RejectedConstructs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "command substitution", input: "echo $(date)", want: constructCommandSub},
		{name: "backtick substitution", input: "echo `date`", want: constructBacktick},
		{name: "newline separator", input: "git status\nrm -rf x", want: constructNewline},
		{name: "carriage return separator", input: "git status\rrm -rf x", want: constructNewline},
		{name: "command substitution wins over accepted semicolon", input: "echo $(date) ; ls", want: constructCommandSub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := SplitCommand(tt.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil (rejection is not a Go error)", tt.input, err)
			}
			if res.AllowedShell {
				t.Fatalf("SplitCommand(%q) AllowedShell = true, want false (rejected)", tt.input)
			}
			if res.RejectedConstruct != tt.want {
				t.Fatalf("SplitCommand(%q) RejectedConstruct = %q, want %q", tt.input, res.RejectedConstruct, tt.want)
			}
			if res.LiteralRoute || res.Stages != nil {
				t.Fatalf("SplitCommand(%q) produced a route (literal=%v stages=%v) for a rejected command", tt.input, res.LiteralRoute, res.Stages)
			}
		})
	}
}

// TestSplitCommand_LiteralRoute covers Done-when item 4: I/O redirection and
// wrapper/literal-route forms route the prefix-stripped command to one
// literal subject while preserving CdHint.
func TestSplitCommand_LiteralRoute(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		cd      string
		literal string
	}{
		{name: "stdout redirection", input: "git log > out.txt", cd: "", literal: "git log > out.txt"},
		{name: "append redirection", input: "echo hi >> log", cd: "", literal: "echo hi >> log"},
		{name: "stdin redirection", input: "sort < data", cd: "", literal: "sort < data"},
		{name: "stderr redirection", input: "make 2> err", cd: "", literal: "make 2> err"},
		{name: "merge fds", input: "make 2>&1", cd: "", literal: "make 2>&1"},
		{name: "process substitution", input: "diff <(ls a) <(ls b)", cd: "", literal: "diff <(ls a) <(ls b)"},
		{name: "redirection in a piped stage", input: "a | b > c", cd: "", literal: "a | b > c"},
		{name: "cd preserved through redirection", input: "cd /tmp && git log > out.txt", cd: "/tmp", literal: "git log > out.txt"},
		{name: "sh -c wrapper", input: `sh -c "git status"`, cd: "", literal: `sh -c "git status"`},
		{name: "env wrapper", input: "env -u FOO git log", cd: "", literal: "env -u FOO git log"},
		{name: "wrapper in a piped stage", input: `a | sh -c "x"`, cd: "", literal: `a | sh -c "x"`},
		{name: "subshell", input: "(ls)", cd: "", literal: "(ls)"},
		{name: "backgrounding", input: "sleep 5 &", cd: "", literal: "sleep 5 &"},
		{name: "cd preserved through wrapper", input: `cd /tmp && sh -c "ls"`, cd: "/tmp", literal: `sh -c "ls"`},
		// A bare `&&` compound is accepted onto the literal/compound route
		// rather than refused. The whole prefix-stripped command is one literal subject.
		{name: "and compound", input: "make && test", cd: "", literal: "make && test"},
		{name: "semicolon compound", input: "git log ; echo done", cd: "", literal: "git log ; echo done"},
		{name: "logical-or compound", input: "git log || echo fail", cd: "", literal: "git log || echo fail"},
		{name: "no-space semicolon compound", input: "a;b", cd: "", literal: "a;b"},
		{name: "no-space logical-or compound", input: "a||b", cd: "", literal: "a||b"},
		{name: "second and after cd prefix", input: "cd a && b && c", cd: "a", literal: "b && c"},
		{name: "semicolon after cd prefix", input: "cd a && b ; c", cd: "a", literal: "b ; c"},
		{name: "logical-or after cd prefix", input: "cd a && b || c", cd: "a", literal: "b || c"},
		{name: "mixed pipe and and-compound", input: "a | b && c", cd: "", literal: "a | b && c"},
		{name: "mixed pipe and semicolon", input: "a | b ; c", cd: "", literal: "a | b ; c"},
		{name: "mixed pipe and logical-or", input: "a | b || c", cd: "", literal: "a | b || c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := SplitCommand(tt.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", tt.input, err)
			}
			if !res.AllowedShell {
				t.Fatalf("SplitCommand(%q) AllowedShell = false (%q), want literal route", tt.input, res.RejectedConstruct)
			}
			if !res.LiteralRoute {
				t.Fatalf("SplitCommand(%q) LiteralRoute = false (stages=%v), want literal route", tt.input, res.Stages)
			}
			if res.LiteralInput != tt.literal {
				t.Fatalf("SplitCommand(%q) LiteralInput = %q, want %q", tt.input, res.LiteralInput, tt.literal)
			}
			if res.CdHint != tt.cd {
				t.Fatalf("SplitCommand(%q) CdHint = %q, want %q", tt.input, res.CdHint, tt.cd)
			}
			if res.Stages != nil {
				t.Fatalf("SplitCommand(%q) returned direct stages %v on the literal route", tt.input, res.Stages)
			}
		})
	}
}

// TestSplitCommand_QuotedMetacharacters covers Done-when item 5: operators
// inside single/double quotes or backslash-escaped are literal text, never shell
// syntax — so they neither split, reject, nor route to literal.
func TestSplitCommand_QuotedMetacharacters(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		stages [][]string
	}{
		{name: "double-quoted pipe", input: `echo "a | b"`, stages: [][]string{{"echo", "a | b"}}},
		{name: "single-quoted pipe", input: `echo 'a|b'`, stages: [][]string{{"echo", "a|b"}}},
		{name: "escaped pipe", input: `echo a\|b`, stages: [][]string{{"echo", "a|b"}}},
		{name: "double-quoted semicolon", input: `echo "a ; b"`, stages: [][]string{{"echo", "a ; b"}}},
		{name: "single-quoted logical and", input: `echo 'a && b'`, stages: [][]string{{"echo", "a && b"}}},
		{name: "double-quoted redirection", input: `echo "a > b"`, stages: [][]string{{"echo", "a > b"}}},
		{name: "single-quoted command substitution", input: `echo '$(date)'`, stages: [][]string{{"echo", "$(date)"}}},
		{name: "single-quoted backtick", input: `echo '` + "`date`" + `'`, stages: [][]string{{"echo", "`date`"}}},
		{name: "escaped ampersands are not logical and", input: `echo a\&\&b`, stages: [][]string{{"echo", "a&&b"}}},
		{name: "quoted operators still split on a bare pipe", input: `echo "a;b" | wc -l`, stages: [][]string{{"echo", "a;b"}, {"wc", "-l"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := SplitCommand(tt.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", tt.input, err)
			}
			assertDirect(t, res, "", tt.stages)
		})
	}
}

func TestSplitCommand_DoubleQuotedSubstitutionRoutesLiteral(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		cd      string
		literal string
	}{
		{name: "whole word", input: `echo "$(printf hi)"`, literal: `echo "$(printf hi)"`},
		{name: "backtick", input: "echo \"`printf hi`\"", literal: "echo \"`printf hi`\""},
		{name: "embedded in text", input: `echo "pre$(x)post"`, literal: `echo "pre$(x)post"`},
		{name: "spaced", input: `echo "$( x )"`, literal: `echo "$( x )"`},
		{name: "inside a parameter default", input: `echo "${v:-$(x)}"`, literal: `echo "${v:-$(x)}"`},
		{name: "after an escaped backslash", input: `echo "\\$(x)"`, literal: `echo "\\$(x)"`},
		{name: "locale string", input: `echo $"$(x)"`, literal: `echo $"$(x)"`},
		{name: "single quote inside double quotes", input: `echo "it's $(x)"`, literal: `echo "it's $(x)"`},
		{name: "later pipe stage", input: `ls | grep "$(x)"`, literal: `ls | grep "$(x)"`},
		{name: "later and stage", input: `ls && grep "$(x)" f`, literal: `ls && grep "$(x)" f`},
		{name: "cd path is not stripped", input: `cd "$(pwd)" && ls`, literal: `cd "$(pwd)" && ls`},
		{name: "backtick in cd path is not stripped", input: "cd \"`pwd`\" && ls", literal: "cd \"`pwd`\" && ls"},
		{name: "after a clean cd prefix", input: `cd /tmp && grep "$(x)" f`, cd: "/tmp", literal: `grep "$(x)" f`},
		{name: "redirect-bearing command already literal", input: `grep "$(x)" f > out`, literal: `grep "$(x)" f > out`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := SplitCommand(tt.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", tt.input, err)
			}
			if !res.AllowedShell || !res.LiteralRoute || res.Stages != nil {
				t.Fatalf("SplitCommand(%q) = %+v, want the literal route with no direct stages", tt.input, res)
			}
			if res.LiteralInput != tt.literal || res.CdHint != tt.cd {
				t.Fatalf("SplitCommand(%q) LiteralInput = %q CdHint = %q, want %q and %q", tt.input, res.LiteralInput, res.CdHint, tt.literal, tt.cd)
			}
			if _, _, _, ok := SimpleCompoundStages(res.LiteralInput); ok {
				t.Fatalf("SimpleCompoundStages(%q) = simple, want not simple so the command runs through sh -c", res.LiteralInput)
			}
		})
	}
}

func TestSplitCommand_UnquotedSubstitutionStillRejectedBesideQuotedOne(t *testing.T) {
	for _, input := range []string{`echo "$(echo "$(x)")"`, `echo "$(a)" $(b)`, "echo \"$(a)\" `b`"} {
		res, err := SplitCommand(input)
		if err != nil {
			t.Fatalf("SplitCommand(%q) error = %v, want nil", input, err)
		}
		if res.AllowedShell || res.RejectedConstruct == "" {
			t.Fatalf("SplitCommand(%q) = %+v, want the unquoted construct refused", input, res)
		}
	}
}

func TestSplitCommand_InertQuotedSubstitutionTextStaysDirect(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		cd     string
		stages [][]string
	}{
		{name: "awk field reference", input: `awk '{print $(NF)}' f`, stages: [][]string{{"awk", "{print $(NF)}", "f"}}},
		{name: "single-quoted substitution", input: `echo '$(x)'`, stages: [][]string{{"echo", "$(x)"}}},
		{name: "escaped dollar in double quotes", input: `echo "\$(x)"`, stages: [][]string{{"echo", "$(x)"}}},
		{name: "escaped backticks in double quotes", input: "echo \"\\`x\\`\"", stages: [][]string{{"echo", "`x`"}}},
		{name: "double quotes inside single quotes", input: `echo '"$(x)"'`, stages: [][]string{{"echo", `"$(x)"`}}},
		{name: "double-quoted home variable", input: `grep "$HOME" f`, stages: [][]string{{"grep", "$HOME", "f"}}},
		{name: "double-quoted variable", input: `grep "$v" f`, stages: [][]string{{"grep", "$v", "f"}}},
		{name: "cd path with a double-quoted variable", input: `cd "$v" && ls`, cd: "$v", stages: [][]string{{"ls"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := SplitCommand(tt.input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", tt.input, err)
			}
			assertDirect(t, res, tt.cd, tt.stages)
		})
	}
}

// TestSplitCommand_Errors covers malformed input that cannot be classified:
// these return a Go error rather than a routed SplitResult (Notes:
// empty commands and empty pipeline stages are syntax errors, not grants).
func TestSplitCommand_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "whitespace only", input: "   "},
		{name: "empty after cd prefix", input: "cd /tmp && "},
		{name: "trailing empty pipeline stage", input: "git log |"},
		{name: "leading empty pipeline stage", input: "| wc -l"},
		{name: "empty middle pipeline stage", input: "a | | b"},
		{name: "env-only pipeline stage", input: "git log | FOO=bar"},
		{name: "unterminated double quote", input: `git "log`},
		{name: "unterminated single quote", input: `echo 'x`},
		{name: "dangling backslash", input: `echo x\`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SplitCommand(tt.input); err == nil {
				t.Fatalf("SplitCommand(%q) error = nil, want error", tt.input)
			}
		})
	}
}

func TestSplitCommand_ScriptInvocationStandaloneIsDirectButPipelineStaysLiteral(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		res, err := SplitCommand("bash process-dir.sh u.txt")
		if err != nil {
			t.Fatalf("SplitCommand error = %v, want nil", err)
		}
		assertDirect(t, res, "", [][]string{{"bash", "process-dir.sh", "u.txt"}})
	})
	for _, input := range []string{"bash process-dir.sh u.txt | tail -n 25", "sh producer.sh | head -n 1", "cat a | bash filter.sh"} {
		t.Run(input, func(t *testing.T) {
			res, err := SplitCommand(input)
			if err != nil {
				t.Fatalf("SplitCommand(%q) error = %v, want nil", input, err)
			}
			if !res.AllowedShell || !res.LiteralRoute {
				t.Fatalf("SplitCommand(%q) = allowed %v literal %v, want the literal route", input, res.AllowedShell, res.LiteralRoute)
			}
			if res.LiteralInput != input {
				t.Fatalf("SplitCommand(%q) LiteralInput = %q, want the original pipeline text", input, res.LiteralInput)
			}
			if res.Stages != nil {
				t.Fatalf("SplitCommand(%q) returned direct stages %v on the literal route", input, res.Stages)
			}
		})
	}
}
