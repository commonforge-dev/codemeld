// Tests for direct-command stage normalization, wrapper routing, $PATH canonicalization, and subject matching.
package permissions

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeDirectStage_Direct(t *testing.T) {
	tests := []struct {
		name       string
		stage      string
		want       []string
		wantSource string
	}{
		{name: "plain command", stage: "git log", want: []string{"git", "log"}, wantSource: "git log"},
		{name: "command with flags", stage: "git log --oneline -n 5", want: []string{"git", "log", "--oneline", "-n", "5"}, wantSource: "git log --oneline -n 5"},
		{name: "leading env stripped", stage: "FOO=bar git log", want: []string{"git", "log"}, wantSource: "FOO=bar git log"},
		{name: "multiple leading envs stripped", stage: "A=1 B=2 git status", want: []string{"git", "status"}, wantSource: "A=1 B=2 git status"},
		{name: "env with quoted value still stripped", stage: `FOO="a b" git log`, want: []string{"git", "log"}, wantSource: `FOO="a b" git log`},
		{name: "env with empty value stripped", stage: "FOO= git log", want: []string{"git", "log"}, wantSource: "FOO= git log"},
		{name: "quoted argument preserves spaces and value", stage: `git commit -m "a & b"`, want: []string{"git", "commit", "-m", "a & b"}, wantSource: `git commit -m "a & b"`},
		{name: "fully quoted first word is not an assignment", stage: `"FOO=bar"`, want: []string{"FOO=bar"}, wantSource: `"FOO=bar"`},
		{name: "escaped byte in name is a command word not an assignment", stage: `F\OO=bar git log`, want: []string{"FOO=bar", "git", "log"}, wantSource: `F\OO=bar git log`},
		{name: "quoted byte in name is a command word not an assignment", stage: `F"OO"=bar git log`, want: []string{"FOO=bar", "git", "log"}, wantSource: `F"OO"=bar git log`},
		{name: "flag containing equals is not an assignment", stage: "grep --color=auto x", want: []string{"grep", "--color=auto", "x"}, wantSource: "grep --color=auto x"},
		{name: "escaped ampersand stays direct literal arg", stage: `echo \&`, want: []string{"echo", "&"}, wantSource: `echo \&`},
		{name: "quoted ampersand stays direct literal arg", stage: `echo '&'`, want: []string{"echo", "&"}, wantSource: `echo '&'`},
		{
			name:       "quoted whitespace argument keeps its quotes for display",
			stage:      `notes add m "Research parallelization options later"`,
			want:       []string{"notes", "add", "m", "Research parallelization options later"},
			wantSource: `notes add m "Research parallelization options later"`,
		},
		{
			name:       "single-quoted and escaped spelling is preserved verbatim",
			stage:      `git commit -m 'it'\''s here' --author=a\ b`,
			want:       []string{"git", "commit", "-m", "it's here", "--author=a b"},
			wantSource: `git commit -m 'it'\''s here' --author=a\ b`,
		},
		{
			name:       "surrounding whitespace is trimmed but inner spelling is not",
			stage:      `   grep -n  "a  b"   `,
			want:       []string{"grep", "-n", "a  b"},
			wantSource: `grep -n  "a  b"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDirectStage(tt.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tt.stage, err)
			}
			if got.Route != RouteDirect {
				t.Fatalf("NormalizeDirectStage(%q) route = %v, want RouteDirect", tt.stage, got.Route)
			}
			if !equalStrings(got.Tokens, tt.want) {
				t.Fatalf("NormalizeDirectStage(%q) tokens = %v, want %v", tt.stage, got.Tokens, tt.want)
			}
			if got.Source != tt.wantSource {
				t.Fatalf("NormalizeDirectStage(%q) source = %q, want %q (display must keep the source spelling)", tt.stage, got.Source, tt.wantSource)
			}
		})
	}
}

func TestNormalizeDirectStage_SourceIsNotMatchingData(t *testing.T) {
	bare, err := NormalizeDirectStage(`git commit -m msg`, StageSolo)
	if err != nil {
		t.Fatalf("NormalizeDirectStage: %v", err)
	}
	quoted, err := NormalizeDirectStage(`git "commit" -m 'msg'`, StageSolo)
	if err != nil {
		t.Fatalf("NormalizeDirectStage: %v", err)
	}
	if !equalStrings(bare.Tokens, quoted.Tokens) {
		t.Fatalf("tokens diverged: %v vs %v — differing Source must not change the matching subject", bare.Tokens, quoted.Tokens)
	}
	if bare.Source == quoted.Source {
		t.Fatalf("Source = %q for both spellings, want each stage's own verbatim text", bare.Source)
	}
	if !MatchesDirectSubject(quoted.Tokens, nil, false, "git commit :*") {
		t.Fatalf("MatchesDirectSubject(%v, nil, %q) = false, want true (Source must not affect matching)", quoted.Tokens, "git commit :*")
	}
}

func TestNormalizeDirectStage_LiteralRouteCarriesNoSource(t *testing.T) {
	for _, stage := range []string{`sh -c "git status"`, `sleep 5 &`, `(ls)`, `diff <(ls a) b`} {
		got, err := NormalizeDirectStage(stage, StageSolo)
		if err != nil {
			t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", stage, err)
		}
		if got.Route != RouteLiteral {
			t.Fatalf("NormalizeDirectStage(%q) route = %v, want RouteLiteral", stage, got.Route)
		}
		if got.Source != "" {
			t.Fatalf("NormalizeDirectStage(%q) source = %q, want empty on a literal-routed stage", stage, got.Source)
		}
	}
}

// TestNormalizeDirectStage_HomeExpansionForms proves the execution-only HOME metadata (ExecForms) is
// carried parallel to Tokens without ever changing the canonical Tokens: a bare leading `~`/`$HOME`
// argument is marked Expand with the correct Suffix, while quoted, escaped, embedded, and `~user`
// forms are not — and in every case Tokens keep the literal, unexpanded value used for authorization.
func TestNormalizeDirectStage_HomeExpansionForms(t *testing.T) {
	tests := []struct {
		name       string
		stage      string
		wantTokens []string
		wantForms  []HomeExpansion
	}{
		{
			name:       "bare tilde path",
			stage:      "cat ~/srht/que",
			wantTokens: []string{"cat", "~/srht/que"},
			wantForms:  []HomeExpansion{{}, {Expand: true, Suffix: "/srht/que"}},
		},
		{
			name:       "bare lone tilde",
			stage:      "ls ~",
			wantTokens: []string{"ls", "~"},
			wantForms:  []HomeExpansion{{}, {Expand: true, Suffix: ""}},
		},
		{
			name:       "bare $HOME path",
			stage:      "cat $HOME/srht/que",
			wantTokens: []string{"cat", "$HOME/srht/que"},
			wantForms:  []HomeExpansion{{}, {Expand: true, Suffix: "/srht/que"}},
		},
		{
			name:       "quoted tilde stays literal",
			stage:      `cat '~/srht/que'`,
			wantTokens: []string{"cat", "~/srht/que"},
			wantForms:  []HomeExpansion{{}, {}},
		},
		{
			name:       "quoted $HOME stays literal",
			stage:      `cat '$HOME/srht/que'`,
			wantTokens: []string{"cat", "$HOME/srht/que"},
			wantForms:  []HomeExpansion{{}, {}},
		},
		{
			name:       "double-quoted $HOME stays literal",
			stage:      `cat "$HOME"/srht/que`,
			wantTokens: []string{"cat", "$HOME/srht/que"},
			wantForms:  []HomeExpansion{{}, {}},
		},
		{
			name:       "escaped tilde stays literal",
			stage:      `cat \~/srht/que`,
			wantTokens: []string{"cat", "~/srht/que"},
			wantForms:  []HomeExpansion{{}, {}},
		},
		{
			name:       "embedded $HOME not leading",
			stage:      "echo HOME=$HOME",
			wantTokens: []string{"echo", "HOME=$HOME"},
			wantForms:  []HomeExpansion{{}, {}},
		},
		{
			name:       "tilde user unsupported",
			stage:      "ls ~alice/x",
			wantTokens: []string{"ls", "~alice/x"},
			wantForms:  []HomeExpansion{{}, {}},
		},
		{
			name:       "$HOME prefix of longer name",
			stage:      "echo $HOMEDIR",
			wantTokens: []string{"echo", "$HOMEDIR"},
			wantForms:  []HomeExpansion{{}, {}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDirectStage(tt.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tt.stage, err)
			}
			if !equalStrings(got.Tokens, tt.wantTokens) {
				t.Fatalf("NormalizeDirectStage(%q) tokens = %v, want %v (canonical subject must stay unexpanded)", tt.stage, got.Tokens, tt.wantTokens)
			}
			if len(got.ExecForms) != len(tt.wantForms) {
				t.Fatalf("NormalizeDirectStage(%q) ExecForms = %+v, want %+v", tt.stage, got.ExecForms, tt.wantForms)
			}
			for i, w := range tt.wantForms {
				if got.ExecForms[i] != w {
					t.Fatalf("NormalizeDirectStage(%q) ExecForms[%d] = %+v, want %+v", tt.stage, i, got.ExecForms[i], w)
				}
			}
		})
	}
}

// TestNormalizeDirectStage_Assignments checks that leading KEY=VALUE assignments are stripped from
// the subject Tokens but preserved on Assignments as resolved KEY=VALUE strings (step 3), so
// an authorized direct stage can execute with the requested environment.
func TestNormalizeDirectStage_Assignments(t *testing.T) {
	tests := []struct {
		name        string
		stage       string
		wantTokens  []string
		wantAssigns []string
	}{
		{name: "no assignments", stage: "git log", wantTokens: []string{"git", "log"}, wantAssigns: nil},
		{name: "single assignment", stage: "FOO=bar git log", wantTokens: []string{"git", "log"}, wantAssigns: []string{"FOO=bar"}},
		{name: "multiple assignments preserve order", stage: "A=1 B=2 git status", wantTokens: []string{"git", "status"}, wantAssigns: []string{"A=1", "B=2"}},
		{name: "quoted value is unquoted", stage: `FOO="a b" git log`, wantTokens: []string{"git", "log"}, wantAssigns: []string{"FOO=a b"}},
		{name: "empty value preserved", stage: "FOO= git log", wantTokens: []string{"git", "log"}, wantAssigns: []string{"FOO="}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDirectStage(tt.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tt.stage, err)
			}
			if got.Route != RouteDirect {
				t.Fatalf("NormalizeDirectStage(%q) route = %v, want RouteDirect", tt.stage, got.Route)
			}
			if !equalStrings(got.Tokens, tt.wantTokens) {
				t.Fatalf("NormalizeDirectStage(%q) tokens = %v, want %v", tt.stage, got.Tokens, tt.wantTokens)
			}
			if !equalStrings(got.Assignments, tt.wantAssigns) {
				t.Fatalf("NormalizeDirectStage(%q) assignments = %v, want %v", tt.stage, got.Assignments, tt.wantAssigns)
			}
		})
	}
}

// TestNormalizeDirectStage_PathResolution exercises step 3 with a
// test-controlled $PATH so it never depends on the host's system binaries
// (architecture-review risk note).
func TestNormalizeDirectStage_PathResolution(t *testing.T) {
	dir := t.TempDir()
	gitPath := filepath.Join(dir, "git")
	writeExecutable(t, gitPath)
	t.Setenv("PATH", dir)

	t.Run("absolute path resolving to the same $PATH executable becomes bare name", func(t *testing.T) {
		got, err := NormalizeDirectStage(gitPath+" log", StageSolo)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if got.Route != RouteDirect || !equalStrings(got.Tokens, []string{"git", "log"}) {
			t.Fatalf("got %+v, want direct [git log]", got)
		}
	})

	t.Run("bare name normalizes to itself", func(t *testing.T) {
		got, err := NormalizeDirectStage("git log", StageSolo)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if !equalStrings(got.Tokens, []string{"git", "log"}) {
			t.Fatalf("got %v, want [git log]", got.Tokens)
		}
	})

	t.Run("absolute path to a different executable keeps the original token", func(t *testing.T) {
		other := t.TempDir()
		otherGit := filepath.Join(other, "git")
		writeExecutable(t, otherGit)
		got, err := NormalizeDirectStage(otherGit+" log", StageSolo)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if !equalStrings(got.Tokens, []string{otherGit, "log"}) {
			t.Fatalf("got %v, want [%s log]", got.Tokens, otherGit)
		}
	})
}

func TestNormalizeDirectStage_OnlyAnAbsoluteProgramPathBecomesItsBareName(t *testing.T) {
	proc := t.TempDir()
	writeExecutable(t, filepath.Join(proc, "tool"))
	binTool := filepath.Join(proc, "bin", "tool")
	if err := os.MkdirAll(filepath.Dir(binTool), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeExecutable(t, binTool)
	t.Chdir(proc)

	for _, tc := range []struct {
		stage string
		path  string
		want  string
	}{
		{"bin/tool", filepath.Join(proc, "bin"), "bin/tool"},
		{"./tool", proc, "./tool"},
		{binTool, filepath.Join(proc, "bin"), "tool"},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			got, err := NormalizeDirectStage(tc.stage, StageSolo)
			if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if !equalStrings(got.Tokens, []string{tc.want}) {
				t.Fatalf("got %v, want [%s]", got.Tokens, tc.want)
			}
		})
	}
}

func TestNormalizeDirectStage_CommandLookupTakesDirectRoute(t *testing.T) {
	dir := t.TempDir()
	magick := filepath.Join(dir, "magick")
	writeExecutable(t, magick)
	t.Setenv("PATH", dir)

	got, err := NormalizeDirectStage("command -v magick", StageSolo)
	if err != nil {
		t.Fatalf("NormalizeDirectStage error = %v, want nil", err)
	}
	if got.Route != RouteDirect {
		t.Fatalf("route = %v, want RouteDirect (a resolved lookup leaves the wrapper route)", got.Route)
	}
	if !equalStrings(got.Tokens, []string{"command", "-v", "magick"}) {
		t.Fatalf("tokens = %v, want [command -v magick]", got.Tokens)
	}
	if got.LookupPath != magick {
		t.Fatalf("LookupPath = %q, want %q (dispatch must not resolve it a second time)", got.LookupPath, magick)
	}
	if len(got.ExecForms) != len(got.Tokens) || len(got.Assignments) != 0 {
		t.Fatalf("ExecForms = %+v, assignments = %v, want one form per token and no assignments", got.ExecForms, got.Assignments)
	}
	if got.Source != "command -v magick" {
		t.Fatalf("source = %q, want the verbatim stage text", got.Source)
	}
}

func TestNormalizeDirectStage_CommandLookupRejectedSpellingsStayLiteral(t *testing.T) {
	dir := t.TempDir()
	magick := filepath.Join(dir, "magick")
	writeExecutable(t, magick)
	t.Setenv("PATH", dir)

	for _, stage := range []string{
		"command -v",
		"command -v magick ls",
		"command -v missingprog",
		"command -v cd",
		"command -V magick",
		"command -c magick",
		"command --version magick",
		"command magick",
		"command ls -la",
		"command sh -c 'rm -rf /'",
		"PATH=/opt/bin command -v magick",
		"FOO=bar command -v magick",
		`"command" -v magick`,
		`com"mand" -v magick`,
		`command "-v" magick`,
		`command -v 'magick'`,
		`command -v "magick"`,
		`command -v mag\ick`,
		"command -v " + magick,
		"command -v ./magick",
		"command -v -magick",
		"command -v FOO=bar",
		"/usr/bin/command -v magick",
	} {
		t.Run(stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", stage, err)
			}
			if got.Route != RouteLiteral || got.Reason != ReasonWrapperCommand {
				t.Fatalf("NormalizeDirectStage(%q) = route %v reason %q, want the wrapper literal route", stage, got.Route, got.Reason)
			}
			if got.Tokens != nil || got.LookupPath != "" {
				t.Fatalf("NormalizeDirectStage(%q) leaked tokens %v / lookup %q onto a literal stage", stage, got.Tokens, got.LookupPath)
			}
		})
	}
}

func TestNormalizeDirectStage_TypeLookupTakesDirectRoute(t *testing.T) {
	typeLookupPATH(t)
	want, err := exec.LookPath("ls")
	if err != nil {
		t.Fatalf("exec.LookPath(ls) error = %v", err)
	}

	got, err := NormalizeDirectStage("type ls", StageSolo)
	if err != nil {
		t.Fatalf("NormalizeDirectStage error = %v, want nil", err)
	}
	if got.Route != RouteDirect {
		t.Fatalf("route = %v, want RouteDirect", got.Route)
	}
	if !equalStrings(got.Tokens, []string{"type", "ls"}) {
		t.Fatalf("tokens = %v, want [type ls]", got.Tokens)
	}
	if got.LookupPath != want {
		t.Fatalf("LookupPath = %q, want %q", got.LookupPath, want)
	}
}

func TestNormalizeDirectStage_TypeLookupRejectedSpellingsStayLiteral(t *testing.T) {
	typeLookupPATH(t)
	for _, stage := range typeLookupRejected {
		t.Run(stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", stage, err)
			}
			if got.Route != RouteLiteral || got.Reason != ReasonWrapperCommand {
				t.Fatalf("NormalizeDirectStage(%q) = route %v reason %q, want the wrapper literal route", stage, got.Route, got.Reason)
			}
			if got.Tokens != nil || got.LookupPath != "" {
				t.Fatalf("NormalizeDirectStage(%q) leaked tokens %v / lookup %q onto a literal stage", stage, got.Tokens, got.LookupPath)
			}
		})
	}
}

func TestNormalizeDirectStage_ProgramUnescapedSeparator(t *testing.T) {
	for _, tc := range []struct {
		stage string
		token string
		want  bool
	}{
		{"bad/program", "bad/program", true},
		{`bad\/program`, "bad/program", false},
		{`bad\/sub/program`, "bad/sub/program", true},
		{`.\/myapp`, "./myapp", false},
		{`"./out dir/app"`, "./out dir/app", true},
		{`'/opt/x/bin/t'`, "/opt/x/bin/t", true},
		{`"bad\/program"`, `bad\/program`, true},
		{"FOO=bar ./myapp", "./myapp", true},
		{`FOO=bar .\/myapp`, "./myapp", false},
		{"myprog", "myprog", false},
		{`my\prog`, "myprog", false},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(tc.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tc.stage, err)
			}
			if got.Route != RouteDirect || len(got.Tokens) != 1 || got.Tokens[0] != tc.token {
				t.Fatalf("NormalizeDirectStage(%q) = route %v tokens %v, want direct [%s]", tc.stage, got.Route, got.Tokens, tc.token)
			}
			if len(got.ExecForms) != 1 || got.ExecForms[0] != (HomeExpansion{}) || got.Source != tc.stage {
				t.Fatalf("NormalizeDirectStage(%q) = forms %+v source %q, want one unexpanded form and the verbatim source", tc.stage, got.ExecForms, got.Source)
			}
			if got.ProgramUnescapedSeparator != tc.want {
				t.Fatalf("NormalizeDirectStage(%q).ProgramUnescapedSeparator = %v, want %v", tc.stage, got.ProgramUnescapedSeparator, tc.want)
			}
		})
	}
}

func TestNormalizeDirectStage_NoExecShellCancellationStaysLiteral(t *testing.T) {
	for _, tc := range noExecShellCancellationCases() {
		t.Run(tc.input, func(t *testing.T) {
			got, err := NormalizeDirectStage(tc.input, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tc.input, err)
			}
			if got.Route != RouteLiteral || got.Reason != ReasonWrapperCommand {
				t.Fatalf("NormalizeDirectStage(%q) = route %v reason %q, want the wrapper literal route", tc.input, got.Route, got.Reason)
			}
			if got.Tokens != nil {
				t.Fatalf("NormalizeDirectStage(%q) leaked tokens %v onto a literal stage", tc.input, got.Tokens)
			}
		})
	}
}

func TestNormalizeDirectStage_NoExecShellAcceptedFormsStayDirect(t *testing.T) {
	assertDirect := func(t *testing.T, input string, want []string) {
		t.Helper()
		got, err := NormalizeDirectStage(input, StageSolo)
		if err != nil {
			t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", input, err)
		}
		assertDirectStageTokens(t, input, got, want)
	}
	for _, tc := range noExecShellAccepted {
		t.Run(tc.input, func(t *testing.T) { assertDirect(t, tc.input, tc.tokens) })
	}
	t.Run("bash -n ./+name.sh", func(t *testing.T) {
		assertDirect(t, "bash -n ./+name.sh", []string{"bash", "-n", "./+name.sh"})
	})
}

func TestNormalizeDirectStage_LookupPathOnlyOnAcceptedLookup(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, filepath.Join(dir, "magick"))
	t.Setenv("PATH", dir)

	for _, stage := range []string{"ls -la", "bash -n a.sh", "which magick", "git log"} {
		t.Run(stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", stage, err)
			}
			if got.LookupPath != "" {
				t.Fatalf("NormalizeDirectStage(%q) LookupPath = %q, want empty (only `command -v` is answered without running)", stage, got.LookupPath)
			}
		})
	}
}

func TestNormalizeDirectStage_LiteralRouting(t *testing.T) {
	tests := []struct {
		name   string
		stage  string
		reason LiteralReason
	}{
		{name: "sh -c wrapper", stage: `sh -c "ls"`, reason: ReasonWrapperCommand},
		{name: "bash -lc wrapper", stage: `bash -lc "ls"`, reason: ReasonWrapperCommand},
		{name: "quoted sh wrapper still routes literal", stage: `"sh" -c "git status"`, reason: ReasonWrapperCommand},
		{name: "quoted env wrapper still routes literal", stage: `"env" FOO=bar git log`, reason: ReasonWrapperCommand},
		{name: "partially quoted wrapper still routes literal", stage: `s"h" -c "ls"`, reason: ReasonWrapperCommand},
		{name: "command builtin", stage: "command ls", reason: ReasonWrapperCommand},
		{name: "nice wrapper", stage: "nice git gc", reason: ReasonWrapperCommand},
		{name: "nohup wrapper", stage: "nohup server", reason: ReasonWrapperCommand},
		{name: "time wrapper", stage: "time make", reason: ReasonWrapperCommand},
		{name: "xargs wrapper", stage: "xargs rm", reason: ReasonWrapperCommand},
		{name: "absolute path wrapper recognized by base name", stage: "/usr/bin/env git log", reason: ReasonWrapperCommand},
		{name: "trailing backgrounding ampersand", stage: "git gc &", reason: ReasonBackgrounding},
		{name: "attached backgrounding ampersand", stage: "server&", reason: ReasonBackgrounding},
		{name: "subshell", stage: "(ls)", reason: ReasonSubshell},
		{name: "process substitution", stage: "cat <(ls)", reason: ReasonProcessSubstitution},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDirectStage(tt.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tt.stage, err)
			}
			if got.Route != RouteLiteral {
				t.Fatalf("NormalizeDirectStage(%q) route = %v, want RouteLiteral", tt.stage, got.Route)
			}
			if got.Tokens != nil {
				t.Fatalf("NormalizeDirectStage(%q) returned direct tokens %v for a literal-route stage", tt.stage, got.Tokens)
			}
			if got.Reason != tt.reason {
				t.Fatalf("NormalizeDirectStage(%q) reason = %q, want %q", tt.stage, got.Reason, tt.reason)
			}
		})
	}
}

func TestNormalizeDirectStage_Errors(t *testing.T) {
	assertErrorInputs(t, "NormalizeDirectStage", func(s string) error {
		_, err := NormalizeDirectStage(s, StageSolo)
		return err
	}, []errorCase{
		{name: "empty", input: ""},
		{name: "whitespace only", input: "   "},
		{name: "assignments only", input: "FOO=bar BAZ=1"},
		{name: "unterminated quote propagates", input: `git "log`},
	})
}

func TestMatchesDirectSubject(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		subject string
		want    bool
	}{
		{name: "wildcard matches longer command", tokens: []string{"git", "log", "--oneline"}, subject: "git log :*", want: true},
		{name: "wildcard matches multi-arg command", tokens: []string{"git", "log", "-n", "5"}, subject: "git log :*", want: true},
		{name: "wildcard matches exact prefix", tokens: []string{"git", "log"}, subject: "git log :*", want: true},
		{name: "wildcard rejects partial token match", tokens: []string{"git", "logfoo"}, subject: "git log :*", want: false},
		{name: "wildcard rejects suffixed token", tokens: []string{"git", "log-extra"}, subject: "git log :*", want: false},
		{name: "wildcard rejects shorter command", tokens: []string{"git"}, subject: "git log :*", want: false},
		{name: "single-token wildcard prefix", tokens: []string{"git", "status"}, subject: "git :*", want: true},
		{name: "exact match", tokens: []string{"git", "status"}, subject: "git status", want: true},
		{name: "exact rejects extra argument", tokens: []string{"git", "status", "-s"}, subject: "git status", want: false},
		{name: "exact rejects missing argument", tokens: []string{"git"}, subject: "git status", want: false},
		{name: "single token exact", tokens: []string{"ls"}, subject: "ls", want: true},
		{name: "single token rejects args", tokens: []string{"ls", "-la"}, subject: "ls", want: false},
		{name: "quoted wildcard is a literal argument", tokens: []string{"grep", ":*"}, subject: `grep ":*"`, want: true},
		{name: "quoted wildcard does not act as prefix", tokens: []string{"grep", "foo"}, subject: `grep ":*"`, want: false},
		{name: "escaped wildcard is a literal argument", tokens: []string{"grep", ":*"}, subject: `grep :\*`, want: true},
		{name: "escaped wildcard does not act as prefix", tokens: []string{"grep", "foo"}, subject: `grep :\*`, want: false},
		{name: "subject with quoted arg containing space", tokens: []string{"git", "commit", "-m", "a b"}, subject: `git commit -m "a b"`, want: true},
		{name: "bare wildcard never matches", tokens: []string{"git", "log"}, subject: ":*", want: false},
		{name: "malformed subject never matches", tokens: []string{"git", "log"}, subject: `git "log`, want: false},
		{name: "empty subject never matches", tokens: []string{"git"}, subject: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesDirectSubject(tt.tokens, nil, false, tt.subject); got != tt.want {
				t.Fatalf("MatchesDirectSubject(%v, nil, %q) = %v, want %v", tt.tokens, tt.subject, got, tt.want)
			}
		})
	}
}

// errorCase is one named malformed input for the shared error-assertion helper.
type errorCase struct {
	name  string
	input string
}

// assertErrorInputs runs produceErr over each malformed input as a named subtest and fails it if no
// error is returned. It is the shared form of the malformed-input loops in NormalizeDirectStage and
// tokenizeShell tests (dupl group 41); label names the function under test in failure messages.
func assertErrorInputs(t *testing.T, label string, produceErr func(string) error, cases []errorCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := produceErr(tc.input); err == nil {
				t.Fatalf("%s(%q) error = nil, want error", label, tc.input)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func TestNormalizeDirectStage_ScriptInvocationSoloTakesDirectRoute(t *testing.T) {
	tests := []struct {
		stage string
		want  []string
	}{
		{stage: "bash foo.sh", want: []string{"bash", "foo.sh"}},
		{stage: "bash foo.sh u.txt", want: []string{"bash", "foo.sh", "u.txt"}},
		{stage: "sh foo.sh a b", want: []string{"sh", "foo.sh", "a", "b"}},
		{stage: "bash ./process-dir.sh n.txt", want: []string{"bash", "./process-dir.sh", "n.txt"}},
		{stage: "bash ./+odd.sh", want: []string{"bash", "./+odd.sh"}},
		{stage: "bash foo.sh -n", want: []string{"bash", "foo.sh", "-n"}},
		{stage: "bash foo.sh +x", want: []string{"bash", "foo.sh", "+x"}},
	}
	for _, tt := range tests {
		t.Run(tt.stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(tt.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tt.stage, err)
			}
			assertDirectStageTokens(t, tt.stage, got, tt.want)
			if got.LookupPath != "" {
				t.Fatalf("NormalizeDirectStage(%q) LookupPath = %q, want empty (nothing is resolved for a script invocation)", tt.stage, got.LookupPath)
			}
			if got.Source != tt.stage {
				t.Fatalf("NormalizeDirectStage(%q) source = %q, want the source spelling", tt.stage, got.Source)
			}
		})
	}
}

func TestNormalizeDirectStage_ScriptInvocationInCompoundStaysLiteral(t *testing.T) {
	for _, stage := range []string{"bash foo.sh", "bash foo.sh u.txt", "sh foo.sh a b", "bash ./process-dir.sh n.txt"} {
		t.Run(stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(stage, StageInCompound)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", stage, err)
			}
			if got.Route != RouteLiteral || got.Reason != ReasonWrapperCommand {
				t.Fatalf("NormalizeDirectStage(%q, StageInCompound) = route %v reason %q, want the wrapper literal route", stage, got.Route, got.Reason)
			}
			if got.Tokens != nil {
				t.Fatalf("NormalizeDirectStage(%q, StageInCompound) leaked tokens %v onto a literal stage", stage, got.Tokens)
			}
		})
	}
}

func TestNormalizeDirectStage_ScriptInvocationRejectedSpellingsStayLiteral(t *testing.T) {
	rejected := []string{
		"bash -c 'rm -rf /'",
		"bash -s",
		"bash -i",
		"bash -lc cmd",
		"bash --",
		"bash --rcfile x foo.sh",
		"bash +O extglob",
		"bash +O extglob -c 'rm -rf /'",
		"bash +x -c cmd",
		"bash +o posix -c cmd",
		"sh +o nolog -c cmd",
		"bash +O foo.sh",
		"bash",
		"sh",
		"/bin/bash foo.sh",
		`"bash" foo.sh`,
		`'sh' foo.sh`,
		`b\ash foo.sh`,
		`s\h foo.sh`,
		"FOO=bar bash foo.sh",
		`bash ''`,
	}
	for _, stage := range rejected {
		t.Run(stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", stage, err)
			}
			if got.Route != RouteLiteral || got.Reason != ReasonWrapperCommand {
				t.Fatalf("NormalizeDirectStage(%q) = route %v reason %q, want the wrapper literal route", stage, got.Route, got.Reason)
			}
			if got.Tokens != nil {
				t.Fatalf("NormalizeDirectStage(%q) leaked tokens %v onto a literal stage", stage, got.Tokens)
			}
		})
	}
}

func TestNormalizeDirectStage_NoExecShellFormsUnaffectedByStageContext(t *testing.T) {
	tests := []struct {
		stage string
		want  []string
	}{
		{stage: "bash -n foo.sh", want: []string{"bash", "-n", "foo.sh"}},
		{stage: "bash -o noexec foo.sh", want: []string{"bash", "-o", "noexec", "foo.sh"}},
	}
	for _, tt := range tests {
		for _, ctx := range []StageContext{StageSolo, StageInCompound} {
			t.Run(tt.stage, func(t *testing.T) {
				got, err := NormalizeDirectStage(tt.stage, ctx)
				if err != nil {
					t.Fatalf("NormalizeDirectStage(%q) error = %v, want nil", tt.stage, err)
				}
				assertDirectStageTokens(t, tt.stage, got, tt.want)
				if got.LookupPath != "" {
					t.Fatalf("NormalizeDirectStage(%q) LookupPath = %q, want empty", tt.stage, got.LookupPath)
				}
			})
		}
	}
}

func TestScriptInvocationDirectRouteStaysMutating(t *testing.T) {
	const input = "bash foo.sh"
	if got := classifyReadOnlyShell(shellCtx(t, input)); got != ClassMutating {
		t.Fatalf("classifyReadOnlyShell(%q) = %q, want mutating (the direct route grants no read-only status)", input, got)
	}
	for _, mode := range []string{"build", modeAutoEdits} {
		t.Run(mode, func(t *testing.T) {
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

func mustEncodeDirectEnv(t *testing.T, assignments []string, subject string) string {
	t.Helper()
	encoded, err := EncodeDirectEnvSubject(assignments, false, subject)
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject(%v, %q): %v", assignments, subject, err)
	}
	return encoded
}

func TestEncodeDirectEnvSubject_RoundTrips(t *testing.T) {
	tests := []struct {
		name        string
		assignments []string
		subject     string
	}{
		{name: "exact scope", assignments: []string{"FOO=bar"}, subject: "hg status"},
		{name: "prefix scope keeps its bare wildcard", assignments: []string{"FOO=bar"}, subject: "hg status :*"},
		{name: "program scope keeps its bare wildcard", assignments: []string{"FOO=bar"}, subject: "hg :*"},
		{name: "ordered set", assignments: []string{"A=1", "B=2", "C=3"}, subject: "ls"},
		{name: "whitespace-bearing value", assignments: []string{"FOO=a b"}, subject: "ls"},
		{name: "empty value", assignments: []string{"FOO="}, subject: "ls"},
		{name: "quoted literal wildcard argument", assignments: []string{"FOO=bar"}, subject: `grep ':*'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := mustEncodeDirectEnv(t, tt.assignments, tt.subject)
			if !isDirectEnvSubject(encoded) {
				t.Fatalf("encoded %q is not recognized as a direct-env subject", encoded)
			}
			if _, err := tokenizeShell(encoded); err == nil {
				t.Fatalf("encoded %q parses as a shell subject; the sentinel must keep it unparseable", encoded)
			}
			got, err := decodeDirectEnvSubject(encoded)
			if err != nil {
				t.Fatalf("decodeDirectEnvSubject(%q): %v", encoded, err)
			}
			if !slices.Equal(got.Assignments, tt.assignments) || got.Subject != tt.subject {
				t.Fatalf("decoded = %+v, want assignments %v subject %q", got, tt.assignments, tt.subject)
			}
		})
	}
}

func TestEncodeDirectEnvSubject_Rejects(t *testing.T) {
	tests := []struct {
		name        string
		assignments []string
		subject     string
	}{
		{name: "no assignments", assignments: nil, subject: "ls"},
		{name: "assignment without a separator", assignments: []string{"FOO"}, subject: "ls"},
		{name: "assignment with an invalid name", assignments: []string{"1FOO=bar"}, subject: "ls"},
		{name: "assignment with an empty name", assignments: []string{"=bar"}, subject: "ls"},
		{name: "non-canonical subject", assignments: []string{"FOO=bar"}, subject: `hg "status"`},
		{name: "unparseable subject", assignments: []string{"FOO=bar"}, subject: `hg "status`},
		{name: "empty subject", assignments: []string{"FOO=bar"}, subject: ""},
		{name: "program-less subject", assignments: []string{"FOO=bar"}, subject: ":*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := EncodeDirectEnvSubject(tt.assignments, false, tt.subject); err == nil {
				t.Fatalf("EncodeDirectEnvSubject(%v, %q) accepted an invalid pair", tt.assignments, tt.subject)
			}
		})
	}
}

func TestDecodeDirectEnvSubject_FailsClosed(t *testing.T) {
	payload := func(body string) string {
		return directEnvSubjectPrefix + base64.RawURLEncoding.EncodeToString([]byte(body))
	}
	tests := []struct {
		name    string
		encoded string
	}{
		{name: "no sentinel", encoded: "hg status"},
		{name: "sentinel without a payload", encoded: "'direct-env/v1"},
		{name: "wrong version", encoded: "'direct-env/v2 " + base64.RawURLEncoding.EncodeToString([]byte(`{"assignments":["A=1"],"subject":"ls"}`))},
		{name: "not base64url", encoded: directEnvSubjectPrefix + "not base64"},
		{name: "padded base64", encoded: directEnvSubjectPrefix + base64.URLEncoding.EncodeToString([]byte(`{"assignments":["A=1"],"subject":"ls"}`))},
		{name: "not JSON", encoded: payload("nope")},
		{name: "unknown field", encoded: payload(`{"assignments":["A=1"],"subject":"ls","extra":1}`)},
		{name: "trailing data", encoded: payload(`{"assignments":["A=1"],"subject":"ls"}{}`)},
		{name: "trailing object delimiter", encoded: payload(`{"assignments":["A=1"],"subject":"ls"}}`)},
		{name: "trailing array delimiter", encoded: payload(`{"assignments":["A=1"],"subject":"ls"}]`)},
		{name: "empty assignments", encoded: payload(`{"assignments":[],"subject":"ls"}`)},
		{name: "assignment is not NAME=VALUE", encoded: payload(`{"assignments":["nope"],"subject":"ls"}`)},
		{name: "non-canonical subject", encoded: payload(`{"assignments":["A=1"],"subject":"'ls'"}`)},
		{name: "program-less subject", encoded: payload(`{"assignments":["A=1"],"subject":":*"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeDirectEnvSubject(tt.encoded); err == nil {
				t.Fatalf("decodeDirectEnvSubject(%q) accepted a malformed value", tt.encoded)
			}
			if MatchesDirectSubject([]string{"ls"}, []string{"A=1"}, false, tt.encoded) {
				t.Fatalf("malformed stored subject %q authorized a request", tt.encoded)
			}
		})
	}
}

func TestDirectRequestSubject_PreservesTokenBoundaries(t *testing.T) {
	if _, err := DirectRequestSubject(nil, nil, false); err == nil {
		t.Fatal("DirectRequestSubject accepted an empty command token sequence")
	}

	bare, err := DirectRequestSubject([]string{"hg", "status"}, nil, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	if bare != "hg status" {
		t.Fatalf("assignment-free identity = %q, want %q", bare, "hg status")
	}

	quoted, err := DirectRequestSubject([]string{"cmd", "a b"}, []string{"FOO=x"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	split, err := DirectRequestSubject([]string{"cmd", "a", "b"}, []string{"FOO=x"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	if quoted == split {
		t.Fatalf("FOO=x cmd 'a b' and FOO=x cmd a b share the identity %q", quoted)
	}

	spaced, err := DirectRequestSubject([]string{"cmd"}, []string{"FOO=x cmd"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	collide, err := DirectRequestSubject([]string{"cmd", "cmd"}, []string{"FOO=x"}, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	if spaced == collide {
		t.Fatalf("a whitespace-bearing assignment collided with an extra command token: %q", spaced)
	}
}

func TestDecodeDirectRequestSubject(t *testing.T) {
	envIdentity := mustEncodeDirectEnv(t, []string{"FOO=bar"}, "hg status")
	tests := []struct {
		name            string
		requestSubject  string
		commandSubject  string
		wantAssignments []string
		wantOK          bool
	}{
		{name: "exact identity proves no assignments", requestSubject: "hg status", commandSubject: "hg status", wantOK: true},
		{name: "versioned identity reports its assignments", requestSubject: envIdentity, commandSubject: "hg status",
			wantAssignments: []string{"FOO=bar"}, wantOK: true},
		{name: "versioned identity naming a different command", requestSubject: envIdentity, commandSubject: "hg log"},
		{name: "missing command identity", requestSubject: "hg status", commandSubject: ""},
		{name: "wildcard command identity is not exact", requestSubject: "hg :*", commandSubject: "hg :*"},
		{name: "non-canonical command identity", requestSubject: `hg "status"`, commandSubject: `hg "status"`},
		{name: "malformed versioned identity", requestSubject: directEnvSubjectPrefix + "!!", commandSubject: "hg status"},
		{name: "identity that is neither exact nor versioned", requestSubject: "hg log", commandSubject: "hg status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := DecodeDirectRequestSubject(tt.requestSubject, tt.commandSubject)
			if ok != tt.wantOK {
				t.Fatalf("DecodeDirectRequestSubject(%q, %q) ok = %v, want %v", tt.requestSubject, tt.commandSubject, ok, tt.wantOK)
			}
			if !slices.Equal(got, tt.wantAssignments) {
				t.Fatalf("assignments = %v, want %v", got, tt.wantAssignments)
			}
		})
	}
}

var adversarialAssignments = []string{
	"LD_PRELOAD=/x/evil.so",
	"LD_LIBRARY_PATH=/x",
	"PATH=/x",
	"BASH_ENV=/x/rc",
	"ENV=/x/rc",
	"IFS= ",
	"PYTHONPATH=/x",
	"PERL5LIB=/x",
	"GIT_CONFIG_GLOBAL=/x/config",
}

func TestMatchesDirectSubject_BareGrantNeverCoversAnAssignment(t *testing.T) {
	for _, storedSubject := range []string{"hg status", "hg status :*", "hg :*"} {
		for _, assignment := range adversarialAssignments {
			t.Run(storedSubject+" vs "+assignment, func(t *testing.T) {
				if !MatchesDirectSubject([]string{"hg", "status"}, nil, false, storedSubject) {
					t.Fatalf("the bare request stopped matching %q", storedSubject)
				}
				if MatchesDirectSubject([]string{"hg", "status"}, []string{assignment}, false, storedSubject) {
					t.Fatalf("stored %q authorized a request carrying %q", storedSubject, assignment)
				}
			})
		}
	}
}

func TestMatchesDirectSubject_VersionedGrantPinsItsAssignments(t *testing.T) {
	tests := []struct {
		name        string
		scope       string
		tokens      []string
		assignments []string
		want        bool
	}{
		{name: "exact scope matches its own request", scope: "hg status", tokens: []string{"hg", "status"},
			assignments: []string{"A=1", "B=2"}, want: true},
		{name: "exact scope rejects an extra argument", scope: "hg status", tokens: []string{"hg", "status", "-q"},
			assignments: []string{"A=1", "B=2"}},
		{name: "prefix scope widens the command only", scope: "hg status :*", tokens: []string{"hg", "status", "-q"},
			assignments: []string{"A=1", "B=2"}, want: true},
		{name: "program scope widens the command only", scope: "hg :*", tokens: []string{"hg", "log"},
			assignments: []string{"A=1", "B=2"}, want: true},
		{name: "changed value", scope: "hg status", tokens: []string{"hg", "status"},
			assignments: []string{"A=9", "B=2"}},
		{name: "extra assignment", scope: "hg status", tokens: []string{"hg", "status"},
			assignments: []string{"A=1", "B=2", "C=3"}},
		{name: "removed assignment", scope: "hg status", tokens: []string{"hg", "status"},
			assignments: []string{"A=1"}},
		{name: "reordered assignments", scope: "hg status", tokens: []string{"hg", "status"},
			assignments: []string{"B=2", "A=1"}},
		{name: "no assignments at all", scope: "hg status", tokens: []string{"hg", "status"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stored := mustEncodeDirectEnv(t, []string{"A=1", "B=2"}, tt.scope)
			if got := MatchesDirectSubject(tt.tokens, tt.assignments, false, stored); got != tt.want {
				t.Fatalf("MatchesDirectSubject(%v, %v, <%s>) = %v, want %v", tt.tokens, tt.assignments, tt.scope, got, tt.want)
			}
		})
	}
}

// A quoted command word spelled like an assignment names a program on $PATH, so a legacy grant for it
// must keep authorizing that program and nothing else.
func TestMatchesDirectSubject_LegacyAssignmentShapedCommandWord(t *testing.T) {
	const stored = `"FOO=x" hg status`
	if !MatchesDirectSubject([]string{"FOO=x", "hg", "status"}, nil, false, stored) {
		t.Fatalf("stored %q stopped covering the program literally named FOO=x", stored)
	}
	if MatchesDirectSubject([]string{"hg", "status"}, []string{"FOO=x"}, false, stored) {
		t.Fatalf("stored %q authorized the environment assignment form", stored)
	}
}

func TestEncodeDirectEnvSubject_RejectsInvalidUTF8(t *testing.T) {
	bad := "FOO=\xff\xfe"
	worse := "FOO=\xfe\xff"
	if _, err := EncodeDirectEnvSubject([]string{bad}, false, "ls"); err == nil {
		t.Fatal("EncodeDirectEnvSubject accepted an assignment that JSON would rewrite")
	}
	if _, err := DirectRequestSubject([]string{"ls"}, []string{worse}, false); err == nil {
		t.Fatal("DirectRequestSubject accepted an assignment that JSON would rewrite")
	}
}

func TestNormalizeDirectStage_EnvGrammarRoutesDirect(t *testing.T) {
	tests := []struct {
		name            string
		stage           string
		wantTokens      []string
		wantAssignments []string
		wantClear       bool
	}{
		{
			name:            "measured hg invocation",
			stage:           "env -i PATH=/usr/bin:/bin HGRCPATH=/dev/null HGRCSKIPREPO=1 HGPLAIN=+strictflags hg status",
			wantTokens:      []string{"hg", "status"},
			wantAssignments: []string{"PATH=/usr/bin:/bin", "HGRCPATH=/dev/null", "HGRCSKIPREPO=1", "HGPLAIN=+strictflags"},
			wantClear:       true,
		},
		{name: "bare env is the inner command", stage: "env ls", wantTokens: []string{"ls"}},
		{name: "bare env keeps inner arguments", stage: "env ls -la /tmp", wantTokens: []string{"ls", "-la", "/tmp"}},
		{
			name:            "assignments without -i inherit the environment",
			stage:           "env FOO=bar git log",
			wantTokens:      []string{"git", "log"},
			wantAssignments: []string{"FOO=bar"},
		},
		{
			name:            "quoted assignment value is unquoted once",
			stage:           `env FOO="a b" cmd`,
			wantTokens:      []string{"cmd"},
			wantAssignments: []string{"FOO=a b"},
		},
		{
			name:            "absolute PATH entries are accepted",
			stage:           "env -i PATH=/bin:/usr/bin:/usr/local/bin ls",
			wantTokens:      []string{"ls"},
			wantAssignments: []string{"PATH=/bin:/usr/bin:/usr/local/bin"},
			wantClear:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDirectStage(tt.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q): %v", tt.stage, err)
			}
			if got.Route != RouteDirect {
				t.Fatalf("NormalizeDirectStage(%q) route = %v, want RouteDirect", tt.stage, got.Route)
			}
			if !slices.Equal(got.Tokens, tt.wantTokens) {
				t.Fatalf("tokens = %v, want %v", got.Tokens, tt.wantTokens)
			}
			if !slices.Equal(got.Assignments, tt.wantAssignments) {
				t.Fatalf("assignments = %v, want %v", got.Assignments, tt.wantAssignments)
			}
			if got.ClearEnvironment != tt.wantClear {
				t.Fatalf("ClearEnvironment = %v, want %v", got.ClearEnvironment, tt.wantClear)
			}
			if len(got.ExecForms) != len(got.Tokens) {
				t.Fatalf("ExecForms = %v, want one entry per token %v", got.ExecForms, got.Tokens)
			}
			if got.Source != tt.stage {
				t.Fatalf("Source = %q, want the verbatim stage %q", got.Source, tt.stage)
			}
		})
	}
}

func TestNormalizeDirectStage_UnsupportedEnvGrammarStaysLiteral(t *testing.T) {
	stages := []string{
		"env -u FOO ls",
		"env -uFOO ls",
		`env -S "ls -l"`,
		`env --split-string "ls -l"`,
		"env -- ls",
		"env --debug ls",
		"env -0 ls",
		"env",
		"env -i PATH=/usr/bin",
		"env FOO=bar",
		`env sh -c "ls"`,
		"env bash -n f.sh",
		"env command -v rg",
		"env env ls",
		"env -i PATH=/usr/bin /usr/bin/hg status",
		"env -i PATH=/usr/bin ./tool",
		"env -i PATH=/usr/bin bin/tool",
		"env -i ls",
		"env -i HGPLAIN=1 ls",
		"env -i PATH=bin ls",
		"env -i PATH= ls",
		"env -i PATH=:/usr/bin ls",
		"env -i PATH=/usr/bin: ls",
		"env -i PATH=./bin:/usr/bin ls",
		"env PATH=bin ls",
		"env -i PATH=/usr/bin -u FOO ls",
		"FOO=1 env ls",
		`env "-i" PATH=/usr/bin ls`,
		"env A=1 -i PATH=/usr/bin hg status",
		"env PATH=/usr/bin -i hg status",
		`env "hg" status`,
		`env h\g status`,
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q): %v", stage, err)
			}
			if got.Route != RouteLiteral {
				t.Fatalf("NormalizeDirectStage(%q) route = %v, want RouteLiteral", stage, got.Route)
			}
			if got.Tokens != nil || got.Assignments != nil || got.ClearEnvironment {
				t.Fatalf("NormalizeDirectStage(%q) leaked direct state %+v", stage, got)
			}
			if got.Reason != ReasonWrapperCommand {
				t.Fatalf("NormalizeDirectStage(%q) reason = %q, want %q", stage, got.Reason, ReasonWrapperCommand)
			}
		})
	}
}

func TestNormalizeDirectStage_BareEnvIsExecutionEquivalent(t *testing.T) {
	for _, command := range []string{"ls", "ls -la /tmp", "hg status", `grep "a b" f`} {
		t.Run(command, func(t *testing.T) {
			bare, err := NormalizeDirectStage(command, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q): %v", command, err)
			}
			wrapped, err := NormalizeDirectStage("env "+command, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q): %v", "env "+command, err)
			}
			if !slices.Equal(wrapped.Tokens, bare.Tokens) {
				t.Fatalf("tokens = %v, want the bare command's %v", wrapped.Tokens, bare.Tokens)
			}
			if wrapped.Assignments != nil || wrapped.ClearEnvironment {
				t.Fatalf("bare env grew an environment identity: %+v", wrapped)
			}
			bareID, err := DirectRequestSubject(bare.Tokens, bare.Assignments, bare.ClearEnvironment)
			if err != nil {
				t.Fatalf("DirectRequestSubject: %v", err)
			}
			wrappedID, err := DirectRequestSubject(wrapped.Tokens, wrapped.Assignments, wrapped.ClearEnvironment)
			if err != nil {
				t.Fatalf("DirectRequestSubject: %v", err)
			}
			if bareID != wrappedID {
				t.Fatalf("identity %q != bare identity %q", wrappedID, bareID)
			}
		})
	}
}

func TestNormalizeDirectStage_EnvTokensAreNotReExpanded(t *testing.T) {
	tests := []struct {
		stage      string
		wantTokens []string
	}{
		{stage: "env FOO=$BAR cmd", wantTokens: []string{"cmd"}},
		{stage: "env cmd *.go", wantTokens: []string{"cmd", "*.go"}},
		{stage: "env -i PATH=/bin cmd $HOME/x", wantTokens: []string{"cmd", "$HOME/x"}},
	}
	for _, tt := range tests {
		t.Run(tt.stage, func(t *testing.T) {
			got, err := NormalizeDirectStage(tt.stage, StageSolo)
			if err != nil {
				t.Fatalf("NormalizeDirectStage(%q): %v", tt.stage, err)
			}
			if got.Route != RouteDirect || !slices.Equal(got.Tokens, tt.wantTokens) {
				t.Fatalf("NormalizeDirectStage(%q) = %+v, want direct tokens %v", tt.stage, got, tt.wantTokens)
			}
		})
	}
	for _, stage := range []string{"env cmd $(id)", "env cmd `id`"} {
		t.Run(stage, func(t *testing.T) {
			split, err := SplitCommand(stage)
			if err != nil {
				t.Fatalf("SplitCommand(%q): %v", stage, err)
			}
			if split.AllowedShell {
				t.Fatalf("SplitCommand(%q) = %+v, want a refused construct", stage, split)
			}
		})
	}
}

func mustEncodeDirectEnvClear(t *testing.T, assignments []string, subject string) string {
	t.Helper()
	encoded, err := EncodeDirectEnvSubject(assignments, true, subject)
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject(%v, true, %q): %v", assignments, subject, err)
	}
	return encoded
}

func TestEncodeDirectEnvSubject_V2PayloadShape(t *testing.T) {
	assignments := []string{"PATH=/usr/bin", "FOO=a b"}
	encoded := mustEncodeDirectEnvClear(t, assignments, "hg :*")
	body, ok := strings.CutPrefix(encoded, directEnvSubjectPrefixV2)
	if !ok {
		t.Fatalf("encoded %q does not carry the v2 sentinel", encoded)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("v2 payload is not base64url: %v", err)
	}
	const want = `{"assignments":["PATH=/usr/bin","FOO=a b"],"clear_environment":true,"subject":"hg :*"}`
	if string(raw) != want {
		t.Fatalf("v2 payload = %s, want %s", raw, want)
	}
	if !isDirectEnvSubject(encoded) {
		t.Fatalf("encoded %q is not recognized as a direct-env subject", encoded)
	}
	if _, err := tokenizeShell(encoded); err == nil {
		t.Fatalf("encoded %q parses as a shell subject; the sentinel must keep it unparseable", encoded)
	}
	got, err := decodeDirectEnvSubject(encoded)
	if err != nil {
		t.Fatalf("decodeDirectEnvSubject(%q): %v", encoded, err)
	}
	if !slices.Equal(got.Assignments, assignments) || got.Subject != "hg :*" || !got.ClearEnvironment {
		t.Fatalf("decoded = %+v, want the encoded clear identity", got)
	}
}

func TestDecodeDirectEnvSubject_V2FailsClosed(t *testing.T) {
	v2 := func(body string) string {
		return directEnvSubjectPrefixV2 + base64.RawURLEncoding.EncodeToString([]byte(body))
	}
	v1 := func(body string) string {
		return directEnvSubjectPrefix + base64.RawURLEncoding.EncodeToString([]byte(body))
	}
	tests := []struct {
		name    string
		encoded string
	}{
		{name: "v2 sentinel without a payload", encoded: "'direct-env/v2"},
		{name: "clear flag missing", encoded: v2(`{"assignments":["A=1"],"subject":"ls"}`)},
		{name: "clear flag false", encoded: v2(`{"assignments":["A=1"],"clear_environment":false,"subject":"ls"}`)},
		{name: "clear flag not a boolean", encoded: v2(`{"assignments":["A=1"],"clear_environment":"true","subject":"ls"}`)},
		{name: "v2 without assignments", encoded: v2(`{"assignments":[],"clear_environment":true,"subject":"ls"}`)},
		{name: "v2 assignment is not NAME=VALUE", encoded: v2(`{"assignments":["nope"],"clear_environment":true,"subject":"ls"}`)},
		{name: "v2 non-canonical subject", encoded: v2(`{"assignments":["A=1"],"clear_environment":true,"subject":"'ls'"}`)},
		{name: "v2 unknown field", encoded: v2(`{"assignments":["A=1"],"clear_environment":true,"subject":"ls","extra":1}`)},
		{name: "v2 trailing data", encoded: v2(`{"assignments":["A=1"],"clear_environment":true,"subject":"ls"}{}`)},
		{name: "v2 not base64url", encoded: directEnvSubjectPrefixV2 + "not base64"},
		{name: "v1 sentinel over a v2 payload", encoded: v1(`{"assignments":["A=1"],"clear_environment":true,"subject":"ls"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeDirectEnvSubject(tt.encoded); err == nil {
				t.Fatalf("decodeDirectEnvSubject(%q) accepted a malformed value", tt.encoded)
			}
			if MatchesDirectSubject([]string{"ls"}, []string{"A=1"}, true, tt.encoded) {
				t.Fatalf("malformed stored subject %q authorized a clear request", tt.encoded)
			}
			if MatchesDirectSubject([]string{"ls"}, []string{"A=1"}, false, tt.encoded) {
				t.Fatalf("malformed stored subject %q authorized an inherited-environment request", tt.encoded)
			}
		})
	}
}

func TestMatchesDirectSubject_ClearEnvironmentIsPartOfIdentity(t *testing.T) {
	assignments := []string{"PATH=/usr/bin", "HGPLAIN=1"}
	clearGrant := mustEncodeDirectEnvClear(t, assignments, "hg :*")
	envGrant := mustEncodeDirectEnv(t, assignments, "hg :*")
	tokens := []string{"hg", "status"}

	if !MatchesDirectSubject(tokens, assignments, true, clearGrant) {
		t.Fatal("the v2 grant stopped covering its own clear request")
	}
	if MatchesDirectSubject(tokens, assignments, false, clearGrant) {
		t.Fatal("a v2 grant authorized an inherited-environment request")
	}
	if MatchesDirectSubject(tokens, assignments, true, envGrant) {
		t.Fatal("a v1 grant authorized a clear request")
	}
	if !MatchesDirectSubject(tokens, assignments, false, envGrant) {
		t.Fatal("the v1 grant stopped covering its own inherited-environment request")
	}
	for _, legacy := range []string{"hg status", "hg status :*", "hg :*"} {
		if MatchesDirectSubject(tokens, nil, true, legacy) {
			t.Fatalf("legacy grant %q authorized a clear request", legacy)
		}
		if MatchesDirectSubject(tokens, assignments, true, legacy) {
			t.Fatalf("legacy grant %q authorized an assignment-bearing clear request", legacy)
		}
	}
	for _, changed := range [][]string{{"PATH=/usr/bin"}, {"HGPLAIN=1", "PATH=/usr/bin"}, {"PATH=/usr/bin", "HGPLAIN=2"}} {
		if MatchesDirectSubject(tokens, changed, true, clearGrant) {
			t.Fatalf("the v2 grant authorized the changed assignment set %v", changed)
		}
	}
}

func TestDirectRequestSubject_ClearAndAssignedFormsNeverShareAnIdentity(t *testing.T) {
	tokens := []string{"cmd"}
	assignments := []string{"FOO=1", "PATH=/usr/bin"}

	clear, err := DirectRequestSubject(tokens, assignments, true)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	inherited, err := DirectRequestSubject(tokens, assignments, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	bare, err := DirectRequestSubject(tokens, nil, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject: %v", err)
	}
	if clear == inherited || clear == bare || inherited == bare {
		t.Fatalf("identities collided: clear %q, inherited %q, bare %q", clear, inherited, bare)
	}
	if _, err := DirectRequestSubject(tokens, nil, true); err == nil {
		t.Fatal("DirectRequestSubject accepted a clear request with no assignments")
	}

	gotAssignments, gotClear, ok := DecodeDirectRequestSubject(clear, "cmd")
	if !ok || !gotClear || !slices.Equal(gotAssignments, assignments) {
		t.Fatalf("DecodeDirectRequestSubject(clear) = %v, %v, %v", gotAssignments, gotClear, ok)
	}
	if _, gotClear, ok := DecodeDirectRequestSubject(inherited, "cmd"); !ok || gotClear {
		t.Fatalf("a v1 identity reported clear = %v, ok = %v", gotClear, ok)
	}
	if _, gotClear, ok := DecodeDirectRequestSubject(bare, "cmd"); !ok || gotClear {
		t.Fatalf("a legacy identity reported clear = %v, ok = %v", gotClear, ok)
	}
}

// underFixture is a machine-shaped tree with a scratch directory whose per-run child name
// is the varying part a containment grant exists to cover.
type underFixture struct {
	root string
	home string
	tmp  string
	run  string
	file string
}

func newUnderFixture(t *testing.T) underFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp root: %v", err)
	}
	f := underFixture{root: root, home: filepath.Join(root, "home", "user"), tmp: filepath.Join(root, "tmp")}
	f.run = filepath.Join(f.tmp, "codemeld-g2430-audit.RtAY58")
	f.file = filepath.Join(f.run, "id-ssh")
	if err := os.MkdirAll(f.home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(f.run, 0o755); err != nil {
		t.Fatalf("mkdir run: %v", err)
	}
	if err := os.WriteFile(f.file, nil, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return f
}

func mustEncodeUnder(t *testing.T, tokens []string, pathIndex int, boundary string, tail bool) string {
	t.Helper()
	subject, err := EncodeDirectUnderSubject(tokens, pathIndex, boundary, tail)
	if err != nil {
		t.Fatalf("EncodeDirectUnderSubject(%v, %d, %q, %v): %v", tokens, pathIndex, boundary, tail, err)
	}
	return subject
}

func underSubjectFor(t *testing.T, p directUnderSubject) string {
	t.Helper()
	encoded, err := encodeDirectUnderPayload(p)
	if err != nil {
		t.Fatalf("encodeDirectUnderPayload(%+v): %v", p, err)
	}
	return encoded
}

func TestDirectUnderSubject_AuthorizesResolvedDescendantsOnly(t *testing.T) {
	f := newUnderFixture(t)
	other := filepath.Join(f.tmp, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatalf("mkdir other: %v", err)
	}
	for _, p := range []string{filepath.Join(other, "id-ssh"), filepath.Join(f.home, "authorized_keys")} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	sibling := filepath.Join(f.root, "tmpx")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "id-ssh"), nil, 0o644); err != nil {
		t.Fatalf("write sibling: %v", err)
	}

	subject := mustEncodeUnder(t, []string{"chmod", "+x", f.file}, 2, f.tmp, false)
	for _, path := range []string{f.file, filepath.Join(other, "id-ssh"), f.tmp} {
		if !MatchesDirectSubject([]string{"chmod", "+x", path}, nil, false, subject) {
			t.Errorf("containment grant at %q does not authorize %q", f.tmp, path)
		}
	}
	for _, path := range []string{
		filepath.Join(f.home, "authorized_keys"),
		filepath.Join(sibling, "id-ssh"),
		f.home,
		f.root,
	} {
		if MatchesDirectSubject([]string{"chmod", "+x", path}, nil, false, subject) {
			t.Errorf("containment grant at %q authorized %q", f.tmp, path)
		}
	}
	if MatchesDirectSubject([]string{"chown", "+x", f.file}, nil, false, subject) {
		t.Error("containment grant authorized a different program")
	}
	if MatchesDirectSubject([]string{"chmod", "-x", f.file}, nil, false, subject) {
		t.Error("containment grant authorized a different fixed token")
	}
	if MatchesDirectSubject([]string{"chmod", "+x", f.file, "extra"}, nil, false, subject) {
		t.Error("containment grant without a tail wildcard authorized a trailing token")
	}
	if MatchesDirectSubject([]string{"chmod", "+x"}, nil, false, subject) {
		t.Error("containment grant authorized a command with too few tokens")
	}
}

func TestDirectUnderSubject_TailWildcardConstrainsWhatPrecedesIt(t *testing.T) {
	f := newUnderFixture(t)
	repo := filepath.Join(f.run, "subprobe", "sub")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	etc := filepath.Join(f.root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}

	subject := mustEncodeUnder(t, []string{"git", "-C", repo, "add", "a"}, 2, f.tmp, true)
	for _, tokens := range [][]string{
		{"git", "-C", repo, "add", "a"},
		{"git", "-C", repo, "commit", "-m", "init"},
		{"git", "-C", repo, "rev-parse", "HEAD"},
		{"git", "-C", f.tmp},
	} {
		if !MatchesDirectSubject(tokens, nil, false, subject) {
			t.Errorf("tail-wildcard grant does not authorize %v", tokens)
		}
	}
	for _, tokens := range [][]string{
		{"git", "-C", etc, "add", "a"},
		{"git", "add", "a"},
		{"git", "-c", "foo", "-C", repo, "add", "a"},
		{"git", "-C"},
		{"git"},
	} {
		if MatchesDirectSubject(tokens, nil, false, subject) {
			t.Errorf("tail-wildcard grant authorized %v", tokens)
		}
	}
}

func TestDirectUnderSubject_MalformedPayloadsMatchNothing(t *testing.T) {
	f := newUnderFixture(t)
	valid := directUnderSubject{Tokens: []string{"chmod", "+x", ""}, PathIndex: 2, Boundary: f.tmp}

	shapes := []struct {
		name    string
		payload directUnderSubject
	}{
		{"duplicate path positions", directUnderSubject{Tokens: []string{"chmod", "", ""}, PathIndex: 2, Boundary: f.tmp}},
		{"no path position", directUnderSubject{Tokens: []string{"chmod", "+x", "x"}, PathIndex: 2, Boundary: f.tmp}},
		{"path index below the program", directUnderSubject{Tokens: []string{"", "+x"}, PathIndex: 0, Boundary: f.tmp}},
		{"path index off the end", directUnderSubject{Tokens: []string{"chmod", "+x", ""}, PathIndex: 3, Boundary: f.tmp}},
		{"path index not the last token", directUnderSubject{Tokens: []string{"chmod", "", "+x"}, PathIndex: 1, Boundary: f.tmp}},
		{"wildcard among the fixed tokens", directUnderSubject{Tokens: []string{"chmod", ":*", ""}, PathIndex: 2, Boundary: f.tmp}},
		{"root boundary", directUnderSubject{Tokens: []string{"chmod", "+x", ""}, PathIndex: 2, Boundary: "/"}},
		{"relative boundary", directUnderSubject{Tokens: []string{"chmod", "+x", ""}, PathIndex: 2, Boundary: "tmp"}},
		{"unclean boundary", directUnderSubject{Tokens: []string{"chmod", "+x", ""}, PathIndex: 2, Boundary: f.tmp + "/../tmp"}},
		{"empty boundary", directUnderSubject{Tokens: []string{"chmod", "+x", ""}, PathIndex: 2, Boundary: ""}},
		{"no tokens", directUnderSubject{Tokens: nil, PathIndex: 2, Boundary: f.tmp}},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			if err := checkDirectUnderPayload(s.payload); err == nil {
				t.Fatalf("checkDirectUnderPayload(%+v) = nil error", s.payload)
			}
			raw, err := json.Marshal(s.payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			subject := directUnderSubjectPrefix + base64.RawURLEncoding.EncodeToString(raw)
			if MatchesDirectSubject([]string{"chmod", "+x", f.file}, nil, false, subject) {
				t.Fatalf("malformed containment subject %+v authorized a command", s.payload)
			}
		})
	}

	canonical := underSubjectFor(t, valid)
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	paddedRaw := raw
	for _, boundary := range []string{f.tmp, f.run, f.root} {
		p := valid
		p.Boundary = boundary
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal padded payload: %v", err)
		}
		if len(encoded)%3 != 0 {
			paddedRaw = encoded
			break
		}
	}
	if len(paddedRaw)%3 == 0 {
		t.Fatal("no boundary produced a payload whose base64 encoding carries padding")
	}
	textual := []struct {
		name    string
		subject string
	}{
		{"unknown payload field", directUnderSubjectPrefix + base64.RawURLEncoding.EncodeToString(
			[]byte(`{"tokens":["chmod","+x",""],"path_index":2,"boundary":"`+f.tmp+`","tail_wildcard":false,"extra":1}`))},
		{"trailing payload data", directUnderSubjectPrefix + base64.RawURLEncoding.EncodeToString(append(slices.Clone(raw), '{', '}'))},
		{"reordered payload fields", directUnderSubjectPrefix + base64.RawURLEncoding.EncodeToString(
			[]byte(`{"boundary":"`+f.tmp+`","tail_wildcard":false,"path_index":2,"tokens":["chmod","+x",""]}`))},
		{"padded base64", directUnderSubjectPrefix + base64.URLEncoding.EncodeToString(paddedRaw)},
		{"undecodable payload", directUnderSubjectPrefix + "!!!not base64!!!"},
		{"empty payload", directUnderSubjectPrefix},
		{"prefix without the leading quote", strings.TrimPrefix(canonical, "'")},
	}
	for _, c := range textual {
		t.Run(c.name, func(t *testing.T) {
			if MatchesDirectSubject([]string{"chmod", "+x", f.file}, nil, false, c.subject) {
				t.Fatalf("subject %q authorized a command", c.subject)
			}
		})
	}
	if !MatchesDirectSubject([]string{"chmod", "+x", f.file}, nil, false, canonical) {
		t.Fatalf("canonical containment subject %q does not authorize its own command", canonical)
	}
}

func TestDirectUnderSubject_EncodeRefusesUnrepresentableRequests(t *testing.T) {
	f := newUnderFixture(t)
	cases := []struct {
		name      string
		tokens    []string
		pathIndex int
		boundary  string
		tail      bool
	}{
		{"path index at the program", []string{"chmod", f.file}, 0, f.tmp, false},
		{"path index off the end", []string{"chmod", f.file}, 2, f.tmp, false},
		{"dropped trailing tokens without a wildcard", []string{"git", "-C", f.run, "add"}, 2, f.tmp, false},
		{"root boundary", []string{"chmod", "+x", f.file}, 2, "/", false},
		{"relative boundary", []string{"chmod", "+x", f.file}, 2, "tmp", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := EncodeDirectUnderSubject(c.tokens, c.pathIndex, c.boundary, c.tail); err == nil {
				t.Fatal("EncodeDirectUnderSubject = nil error")
			}
		})
	}
}

func TestDirectUnderSubject_LegacySubjectsKeepTheirExactMeaning(t *testing.T) {
	f := newUnderFixture(t)
	legacy := ExactSubject("chmod", []string{"+x", ":under=" + f.tmp})
	if !MatchesDirectSubject([]string{"chmod", "+x", ":under=" + f.tmp}, nil, false, legacy) {
		t.Fatalf("legacy subject %q does not match its own literal argument", legacy)
	}
	if MatchesDirectSubject([]string{"chmod", "+x", f.file}, nil, false, legacy) {
		t.Fatalf("legacy subject %q gained containment behavior", legacy)
	}
	prefixed := PrefixSubject("chmod", []string{"+x", ":under=" + f.tmp})
	if MatchesDirectSubject([]string{"chmod", "+x", f.file}, nil, false, prefixed) {
		t.Fatalf("legacy prefix subject %q gained containment behavior", prefixed)
	}
	if !MatchesDirectSubject([]string{"chmod", "+x", ":under=" + f.tmp, "more"}, nil, false, prefixed) {
		t.Fatalf("legacy prefix subject %q lost its literal reading", prefixed)
	}
}

func TestDirectUnderSubject_WhitespaceBoundaryRoundTrips(t *testing.T) {
	f := newUnderFixture(t)
	spaced := filepath.Join(f.tmp, "scratch dir")
	inner := filepath.Join(spaced, "deep")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatalf("mkdir spaced: %v", err)
	}
	target := filepath.Join(inner, "id-ssh")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	subject := mustEncodeUnder(t, []string{"chmod", "+x", target}, 2, spaced, false)
	if strings.Contains(subject, spaced) {
		t.Fatalf("subject %q carries the boundary outside the encoded payload", subject)
	}
	p, err := decodeDirectUnderSubject(subject)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Boundary != spaced {
		t.Fatalf("decoded boundary = %q, want %q", p.Boundary, spaced)
	}
	if !MatchesDirectSubject([]string{"chmod", "+x", target}, nil, false, subject) {
		t.Fatal("whitespace-bearing boundary does not authorize its own command")
	}
	outside := filepath.Join(f.tmp, "scratch")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	sibling := filepath.Join(outside, "id-ssh")
	if err := os.WriteFile(sibling, nil, 0o644); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	if MatchesDirectSubject([]string{"chmod", "+x", sibling}, nil, false, subject) {
		t.Fatalf("boundary %q authorized the sibling prefix %q", spaced, outside)
	}
}

func TestDirectUnderSubject_AdversarialPathsAreRefused(t *testing.T) {
	f := newUnderFixture(t)
	outside := filepath.Join(f.root, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, nil, 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	escape := filepath.Join(f.run, "escape")
	if err := os.Symlink(secret, escape); err != nil {
		t.Fatalf("symlink escape: %v", err)
	}
	// The lexical parent is inside the boundary while the resolved parent is not.
	parentLink := filepath.Join(f.run, "out")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}

	subject := mustEncodeUnder(t, []string{"chmod", "+x", f.file}, 2, f.tmp, false)
	refused := []struct {
		name string
		arg  string
	}{
		{"symlink resolving outside the boundary", escape},
		{"lexical parent inside, resolved parent outside", filepath.Join(parentLink, "secret")},
		{"dot segments escaping the boundary", filepath.Join(f.tmp, "..", "outside", "secret")},
		{"relative argument", "id-ssh"},
		{"missing target", filepath.Join(f.run, "absent")},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			if MatchesDirectSubject([]string{"chmod", "+x", c.arg}, nil, false, subject) {
				t.Fatalf("containment grant authorized %q", c.arg)
			}
		})
	}

	t.Run("stored boundary replaced by a symlink", func(t *testing.T) {
		scratch := filepath.Join(f.tmp, "scratch")
		if err := os.MkdirAll(scratch, 0o755); err != nil {
			t.Fatalf("mkdir scratch: %v", err)
		}
		target := filepath.Join(scratch, "id-ssh")
		if err := os.WriteFile(target, nil, 0o644); err != nil {
			t.Fatalf("write target: %v", err)
		}
		stored := mustEncodeUnder(t, []string{"chmod", "+x", target}, 2, scratch, false)
		if !MatchesDirectSubject([]string{"chmod", "+x", target}, nil, false, stored) {
			t.Fatal("boundary does not authorize its own command before the swap")
		}
		if err := os.RemoveAll(scratch); err != nil {
			t.Fatalf("remove scratch: %v", err)
		}
		if err := os.Symlink(outside, scratch); err != nil {
			t.Fatalf("symlink over the boundary: %v", err)
		}
		if MatchesDirectSubject([]string{"chmod", "+x", secret}, nil, false, stored) {
			t.Fatal("a boundary replaced by a symlink still authorized a command through it")
		}
		if MatchesDirectSubject([]string{"chmod", "+x", filepath.Join(scratch, "secret")}, nil, false, stored) {
			t.Fatal("a boundary replaced by a symlink still authorized its own spelling")
		}
		p, err := decodeDirectUnderSubject(stored)
		if err != nil {
			t.Fatalf("decode stored subject: %v", err)
		}
		if resolved, err := resolveExistingEntry(p.Boundary); err == nil && resolved == p.Boundary {
			t.Fatalf("stored boundary %q still resolves to itself after the swap", p.Boundary)
		}
	})
}

func TestDirectUnderSubject_EnvironmentAssignmentsStayPartOfAuthorization(t *testing.T) {
	f := newUnderFixture(t)
	bare := mustEncodeUnder(t, []string{"chmod", "+x", f.file}, 2, f.tmp, false)
	for _, assignments := range [][]string{{"LD_PRELOAD=/x/evil.so"}, {"FOO=bar"}} {
		if MatchesDirectSubject([]string{"chmod", "+x", f.file}, assignments, false, bare) {
			t.Errorf("bare containment grant authorized a request carrying %v", assignments)
		}
	}
	if MatchesDirectSubject([]string{"chmod", "+x", f.file}, nil, true, bare) {
		t.Error("bare containment grant authorized a cleared-environment request")
	}

	wrapped, err := EncodeDirectEnvSubject([]string{"FOO=bar"}, false, bare)
	if err != nil {
		t.Fatalf("EncodeDirectEnvSubject over a containment subject: %v", err)
	}
	if !MatchesDirectSubject([]string{"chmod", "+x", f.file}, []string{"FOO=bar"}, false, wrapped) {
		t.Error("assignment-bearing containment grant does not authorize its own request")
	}
	if MatchesDirectSubject([]string{"chmod", "+x", f.file}, nil, false, wrapped) {
		t.Error("assignment-bearing containment grant authorized an assignment-free request")
	}
	if MatchesDirectSubject([]string{"chmod", "+x", filepath.Join(f.home, "keys")}, []string{"FOO=bar"}, false, wrapped) {
		t.Error("assignment-bearing containment grant authorized a path outside the boundary")
	}
	if _, err := EncodeDirectEnvSubject([]string{"FOO=bar"}, false, directUnderSubjectPrefix+"garbage"); err == nil {
		t.Error("EncodeDirectEnvSubject accepted a malformed containment subject")
	}
}
