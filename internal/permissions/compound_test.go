// Tests for simple-compound recognition, the generalized literal-subject encode/decode, and
// generalized matching: positive decomposition, the adversarial negative table,
// the destructive-program gate, malformed fail-closed handling, and per-stage widened matching.
package permissions

import (
	"reflect"
	"strings"
	"testing"
)

// canon is a test helper: the canonical literal form of input, failing the test on a tokenizer error.
func canon(t *testing.T, input string) string {
	t.Helper()
	c, err := CanonicalLiteralForm(input)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm(%q) error: %v", input, err)
	}
	return c
}

// TestRecognizeSimpleCompound_Positive proves a simple compound decomposes to its ordered direct
// stages with the operators pinned and the wrapper flavour recorded (Done-when item 1, accept side).
func TestRecognizeSimpleCompound_Positive(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wrapped bool
		stages  [][]string
		ops     []string
	}{
		{
			name:    "bare and-compound",
			input:   "gofmt -w a.go && go build ./...",
			wrapped: false,
			stages:  [][]string{{"gofmt", "-w", "a.go"}, {"go", "build", "./..."}},
			ops:     []string{"&&"},
		},
		{
			name:    "bare semicolon compound",
			input:   "hg log ; echo done",
			wrapped: false,
			stages:  [][]string{{"hg", "log"}, {"echo", "done"}},
			ops:     []string{";"},
		},
		{
			name:    "bare logical-or compound",
			input:   "hg log || echo fail",
			wrapped: false,
			stages:  [][]string{{"hg", "log"}, {"echo", "fail"}},
			ops:     []string{"||"},
		},
		{
			name:    "bare pipeline",
			input:   "cat a.txt | grep needle",
			wrapped: false,
			stages:  [][]string{{"cat", "a.txt"}, {"grep", "needle"}},
			ops:     []string{"|"},
		},
		{
			name:    "wrapper and-compound",
			input:   `sh -c 'gofmt -w a.go && go build ./...'`,
			wrapped: true,
			stages:  [][]string{{"gofmt", "-w", "a.go"}, {"go", "build", "./..."}},
			ops:     []string{"&&"},
		},
		{
			name:    "wrapper single stage",
			input:   `sh -c 'ls -la'`,
			wrapped: true,
			stages:  [][]string{{"ls", "-la"}},
			ops:     nil,
		},
		{
			name:    "three stages mixed operators",
			input:   "cat f | grep x && echo done",
			wrapped: false,
			stages:  [][]string{{"cat", "f"}, {"grep", "x"}, {"echo", "done"}},
			ops:     []string{"|", "&&"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, ok := RecognizeSimpleCompound(canon(t, tt.input))
			if !ok {
				t.Fatalf("RecognizeSimpleCompound(%q) = not simple, want simple", tt.input)
			}
			if sc.Wrapped != tt.wrapped {
				t.Errorf("Wrapped = %v, want %v", sc.Wrapped, tt.wrapped)
			}
			if !equalStageTokens(sc.Stages, tt.stages) {
				t.Errorf("Stages = %v, want %v", sc.Stages, tt.stages)
			}
			if strings.Join(sc.Operators, ",") != strings.Join(tt.ops, ",") {
				t.Errorf("Operators = %v, want %v", sc.Operators, tt.ops)
			}
		})
	}
}

// TestSimpleCompoundStages proves the execution-facing decomposition returns each stage's full
// StageNormalization — the same token/operator structure as RecognizeSimpleCompound, plus the
// per-token ~/$HOME ExecForms a direct executor needs so a stage like `cat ~/f` still expands home.
func TestSimpleCompoundStages(t *testing.T) {
	wrapped, stages, ops, ok := SimpleCompoundStages(canon(t, "cat ~/f ; echo done"))
	if !ok || wrapped {
		t.Fatalf("SimpleCompoundStages = (wrapped %v, ok %v), want (false, true)", wrapped, ok)
	}
	if strings.Join(ops, ",") != ";" {
		t.Fatalf("operators = %v, want [;]", ops)
	}
	want := [][]string{{"cat", "~/f"}, {"echo", "done"}}
	got := make([][]string, len(stages))
	for i, s := range stages {
		got[i] = s.Tokens
	}
	if !equalStageTokens(got, want) {
		t.Fatalf("stage tokens = %v, want %v", got, want)
	}
	// The `~/f` token carries an execution-only home expansion so a direct run does not exec a literal `~`.
	if len(stages[0].ExecForms) < 2 || !stages[0].ExecForms[1].Expand {
		t.Fatalf("stage 0 ExecForms = %+v, want the ~/f token marked for home expansion", stages[0].ExecForms)
	}
	// RecognizeSimpleCompound stays consistent with the execution-facing form (same tokens/operators).
	sc, ok := RecognizeSimpleCompound(canon(t, "cat ~/f ; echo done"))
	if !ok || !equalStageTokens(sc.Stages, want) || strings.Join(sc.Operators, ",") != ";" {
		t.Fatalf("RecognizeSimpleCompound inconsistent with SimpleCompoundStages: %+v", sc)
	}
}

func TestSimpleCompoundStages_SourceSpelling(t *testing.T) {
	const source = `git commit -m "a b" ; cat ~/f`

	wrapped, stages, ops, ok := SimpleCompoundStages(source)
	if !ok || wrapped {
		t.Fatalf("SimpleCompoundStages(source) = (wrapped %v, ok %v), want (false, true)", wrapped, ok)
	}
	if strings.Join(ops, ",") != ";" {
		t.Fatalf("operators = %v, want [;]", ops)
	}
	wantSources := []string{`git commit -m "a b"`, "cat ~/f"}
	for i, s := range stages {
		if s.Source != wantSources[i] {
			t.Fatalf("stage %d source = %q, want %q (quotes must survive for the prompt)", i, s.Source, wantSources[i])
		}
	}

	canWrapped, canStages, canOps, canOK := SimpleCompoundStages(canon(t, source))
	if canOK != ok || canWrapped != wrapped || !reflect.DeepEqual(canOps, ops) {
		t.Fatalf("canonical decomposition diverged: (wrapped %v, ops %v, ok %v)", canWrapped, canOps, canOK)
	}
	if len(canStages) != len(stages) {
		t.Fatalf("canonical stage count = %d, want %d", len(canStages), len(stages))
	}
	for i := range stages {
		if !equalStrings(stages[i].Tokens, canStages[i].Tokens) {
			t.Fatalf("stage %d tokens = %v (source) vs %v (canonical), want identical", i, stages[i].Tokens, canStages[i].Tokens)
		}
		if !reflect.DeepEqual(stages[i].ExecForms, canStages[i].ExecForms) {
			t.Fatalf("stage %d ExecForms = %+v (source) vs %+v (canonical), want identical", i, stages[i].ExecForms, canStages[i].ExecForms)
		}
		if !reflect.DeepEqual(stages[i].Assignments, canStages[i].Assignments) {
			t.Fatalf("stage %d Assignments = %v (source) vs %v (canonical), want identical", i, stages[i].Assignments, canStages[i].Assignments)
		}
	}
	if canStages[0].Source == stages[0].Source {
		t.Fatalf("canonical stage source = %q, expected it to have lost the source quoting", canStages[0].Source)
	}
	if len(stages[1].ExecForms) < 2 || !stages[1].ExecForms[1].Expand {
		t.Fatalf("stage 1 ExecForms = %+v, want the ~/f token marked for home expansion", stages[1].ExecForms)
	}
}

func TestRecognizeSimpleCompoundForGrant_DoubleQuotedSubstitution(t *testing.T) {
	for _, input := range []string{
		`test "$(printf 1)" -eq 1 && echo ok`,
		`grep "$(x)" f 2>/dev/null && ls`,
		"echo \"`x`\" 2>/dev/null | head",
	} {
		if sc, ok := RecognizeSimpleCompoundForGrant(canon(t, input)); ok {
			t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = %+v, want not simple so no per-stage chooser is offered", input, sc)
		}
	}

	sc, ok := RecognizeSimpleCompoundForGrant(canon(t, `echo "\$(date)" && echo hi`))
	if !ok || len(sc.Stages) != 2 || !equalStrings(sc.Stages[0], []string{"echo", "$(date)"}) {
		t.Fatalf("escaped-dollar compound = (%+v, %v), want a simple compound whose first stage is [echo $(date)]", sc, ok)
	}
}

// TestRecognizeSimpleCompound_Negative is the fail-closed table: every non-simple construct returns
// "not simple" so the caller keeps byte-exact literal behaviour (Done-when item 1, reject side).
func TestRecognizeSimpleCompound_Negative(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"subshell", "(ls) && echo hi"},
		{"process substitution", "diff <(ls a) && echo hi"},
		{"backgrounding", "sleep 5 & echo hi"},
		{"redirection", "git log > out && echo hi"},
		{"command substitution", `echo $(date) && echo hi`},
		{"backtick", "echo `date` && echo hi"},
		{"double-quoted command substitution", `echo "$(date)" && echo hi`},
		{"double-quoted backtick", "echo \"`date`\" && echo hi"},
		{"double-quoted substitution in a pipe stage", `ls | grep "$(date)"`},
		{"double-quoted substitution inside the wrapper", `sh -c 'echo "$(date)" && echo hi'`},
		{"nested wrapper stage", "sh -c 'x' && echo hi"},
		{"env-assignment-bearing stage", "FOO=bar make && echo hi"},
		{"env-assignment-only stage", "FOO=bar && echo hi"},
		{"env stage carrying assignments", "env FOO=bar make && echo hi"},
		{"env stage clearing the environment", "env -i PATH=/usr/bin make && echo hi"},
		{"sh -c extra positional arg", `sh -c 'a && b' extra`},
		{"bare single command (not a compound)", "ls -la"},
		{"empty middle stage", "a &&  && b"},
		{"empty semicolon stage", "a ; ; b"},
		{"empty logical-or stage", "a || || b"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c, err := CanonicalLiteralForm(tt.input)
			if err != nil {
				// An unparseable input is itself "not simple"; nothing more to assert.
				return
			}
			if _, ok := RecognizeSimpleCompound(c); ok {
				t.Fatalf("RecognizeSimpleCompound(%q) = simple, want not simple (must stay byte-exact)", tt.input)
			}
		})
	}
}

// TestEncodeDecodeRoundTrip proves the generalized subject is deterministic and round-trips through
// the shared encoder/decoder, and that the destructive-program gate refuses to encode a compound that
// contains a destructive program (Done-when items 1 and 3, plus invariant 8's deterministic form).
func TestEncodeDecodeRoundTrip(t *testing.T) {
	enc, err := EncodeCompoundSubject(true, []string{"gofmt :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	if !isCompoundSubject(enc) {
		t.Fatalf("encoded subject %q is not recognized as a compound subject", enc)
	}
	// Determinism: re-encoding equal inputs yields a byte-identical subject.
	enc2, err := EncodeCompoundSubject(true, []string{"gofmt   :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject (respacing) error: %v", err)
	}
	if enc != enc2 {
		t.Errorf("encoding is not deterministic: %q vs %q", enc, enc2)
	}
	dec, err := decodeCompoundSubject(enc)
	if err != nil {
		t.Fatalf("decodeCompoundSubject(%q) error: %v", enc, err)
	}
	if !dec.wrapped {
		t.Errorf("decoded wrapped = false, want true")
	}
	if strings.Join(dec.stageSubjects, "|") != "gofmt :*|go build :*" {
		t.Errorf("decoded stageSubjects = %v", dec.stageSubjects)
	}
	if strings.Join(dec.operators, ",") != "&&" {
		t.Errorf("decoded operators = %v", dec.operators)
	}
}

// TestEncodeCompoundSubject_DestructiveGate proves invariant 4: a compound containing any
// destructive program offers no widened grant — the encoder refuses it, forcing byte-exact.
func TestEncodeCompoundSubject_DestructiveGate(t *testing.T) {
	for _, prog := range []string{"rm", "rmdir", "git", "hg"} {
		t.Run(prog, func(t *testing.T) {
			if _, err := EncodeCompoundSubject(false, []string{"gofmt :*", prog + " :*"}, []string{"&&"}); err == nil {
				t.Fatalf("EncodeCompoundSubject with destructive %q succeeded, want refusal", prog)
			}
			// Even an exact-scoped destructive stage is ineligible: the whole compound must stay byte-exact.
			if _, err := EncodeCompoundSubject(false, []string{"gofmt :*", prog + " -rf x"}, []string{"&&"}); err == nil {
				t.Fatalf("EncodeCompoundSubject with exact destructive %q succeeded, want refusal", prog)
			}
		})
	}
}

// TestDecodeCompoundSubject_Malformed proves the decoder fails closed on every malformed generalized
// subject, so a corrupted or hostile stored subject never matches (Done-when item 1, malformed side).
func TestDecodeCompoundSubject_Malformed(t *testing.T) {
	cases := []struct {
		name    string
		subject string
	}{
		{"empty", ""},
		{"prefix only", "compound/v1"},
		{"missing flag", "compound/v1 gofmt :*"},
		{"bad flag", "compound/v1 X gofmt :*"},
		{"empty stage", "compound/v1 W "},
		{"empty middle stage", "compound/v1 W gofmt :* &&  && go build :*"},
		{"empty semicolon stage", "compound/v1 W gofmt :* ; ; go build :*"},
		{"disallowed redirection", "compound/v1 W gofmt :* > out"},
		{"disallowed command substitution", "compound/v1 W echo $(date)"},
		{"destructive program", "compound/v1 W gofmt :* && rm :*"},
		{"bare compound single stage", "compound/v1 B gofmt :*"},
		{"non-canonical stage spacing", "compound/v1 W gofmt  -w  a.go"},
		{"bare wildcard stage", "compound/v1 W :*"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeCompoundSubject(tt.subject); err == nil {
				t.Fatalf("decodeCompoundSubject(%q) succeeded, want fail-closed error", tt.subject)
			}
		})
	}
}

// TestMatchesCompoundSubject proves the generalized matching invariants: a request matches only when
// its program set and operator structure are identical and each stage satisfies its stored scope; a
// program swap, an operator injection, an added/removed stage, a reorder, or a wrapper-flavour change
// never matches (Done-when item 2).
func TestMatchesCompoundSubject(t *testing.T) {
	// Grant: wrapped `sh -c '<gofmt any-args> && <go build any-args>'` — both stages widened to Program scope.
	grant, err := EncodeCompoundSubject(true, []string{"gofmt :*", "go build :*"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}

	positives := []string{
		`sh -c 'gofmt -w x.go && go build ./...'`,
		`sh -c 'gofmt -l -w pkg/ && go build -v ./cmd/...'`,
		`sh -c 'gofmt && go build'`,
	}
	for _, cmd := range positives {
		t.Run("match/"+cmd, func(t *testing.T) {
			if !matchesCompoundSubject(canon(t, cmd), grant) {
				t.Fatalf("matchesCompoundSubject(%q) = false, want true (widened args must match)", cmd)
			}
		})
	}

	negatives := []struct {
		name string
		cmd  string
	}{
		{"program swap", `sh -c 'gofmt -w x && go test ./...'`},
		{"operator injection", `sh -c 'gofmt -w x && rm -rf y'`},
		{"operator change && to pipe", `sh -c 'gofmt -w x | go build ./...'`},
		{"added stage", `sh -c 'gofmt -w x && go build ./... && echo done'`},
		{"removed stage", `sh -c 'gofmt -w x'`},
		{"reordered stages", `sh -c 'go build ./... && gofmt -w x'`},
		{"wrapper flavour mismatch (bare)", "gofmt -w x && go build ./..."},
		{"first program differs", `sh -c 'echo hi && go build ./...'`},
	}
	for _, tt := range negatives {
		t.Run("nomatch/"+tt.name, func(t *testing.T) {
			if matchesCompoundSubject(canon(t, tt.cmd), grant) {
				t.Fatalf("matchesCompoundSubject(%q) = true, want false (%s must re-prompt)", tt.cmd, tt.name)
			}
		})
	}
}

// TestMatchesCompoundSubject_ExactStagePins proves an Exact-scope stage is byte-pinned: it matches
// only the identical argument vector, never a widened one, so widening is strictly opt-in per stage.
func TestMatchesCompoundSubject_ExactStagePins(t *testing.T) {
	// Stage 0 widened (Program), stage 1 pinned Exact.
	grant, err := EncodeCompoundSubject(false, []string{"gofmt :*", "go build ./..."}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	if !matchesCompoundSubject(canon(t, "gofmt -w x && go build ./..."), grant) {
		t.Fatalf("exact stage with identical args should match")
	}
	if matchesCompoundSubject(canon(t, "gofmt -w x && go build -v ./..."), grant) {
		t.Fatalf("exact stage must not match a different argument vector")
	}
}

// TestMatchesCompoundSubject_FailsClosedOnBadGrant proves a grant subject that does not decode never
// matches, regardless of the request.
func TestMatchesCompoundSubject_FailsClosedOnBadGrant(t *testing.T) {
	if matchesCompoundSubject(canon(t, "gofmt -w x && go build ./..."), "compound/v1 W rm :* && go build :*") {
		t.Fatalf("a grant widening a destructive program must never match")
	}
}

func equalStageTokens(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.Join(a[i], "\x00") != strings.Join(b[i], "\x00") {
			return false
		}
	}
	return true
}

func TestSimpleCompoundStages_ScriptPipelineNotRestaged(t *testing.T) {
	for _, input := range []string{
		"bash process-dir.sh u.txt | tail -n 25",
		"sh producer.sh | head -n 1",
		"bash foo.sh && ls",
		`sh -c "bash foo.sh | tail -n 5"`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, _, _, ok := SimpleCompoundStages(input); ok {
				t.Fatalf("SimpleCompoundStages(%q) = ok, want refusal (a flagless script stage is direct only standalone)", input)
			}
		})
	}
}

func TestRecognizeSimpleCompoundForGrant_EligibleNullRedirects(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wrapped bool
		stages  [][]string
		ops     []string
	}{
		{
			name:   "stderr redirect on a piped stage",
			input:  "./p.sh u.txt 2>/dev/null | sed -n 1,18p",
			stages: [][]string{{"./p.sh", "u.txt"}, {"sed", "-n", "1,18p"}},
			ops:    []string{"|"},
		},
		{
			name:   "stderr redirect with whitespace before the target",
			input:  "./p.sh u.txt 2> /dev/null | grep x",
			stages: [][]string{{"./p.sh", "u.txt"}, {"grep", "x"}},
			ops:    []string{"|"},
		},
		{
			name:   "stderr redirect in every stage",
			input:  "./p.sh u.txt 2>/dev/null | grep x 2>/dev/null",
			stages: [][]string{{"./p.sh", "u.txt"}, {"grep", "x"}},
			ops:    []string{"|"},
		},
		{
			name:   "stdout redirect on a stage followed by &&",
			input:  "a >/dev/null && b",
			stages: [][]string{{"a"}, {"b"}},
			ops:    []string{"&&"},
		},
		{
			name:   "stdout redirect on a stage followed by ;",
			input:  "a >/dev/null ; b",
			stages: [][]string{{"a"}, {"b"}},
			ops:    []string{";"},
		},
		{
			name:   "stdout redirect on a stage followed by ||",
			input:  "a >/dev/null || b",
			stages: [][]string{{"a"}, {"b"}},
			ops:    []string{"||"},
		},
		{
			name:   "stdout redirect on the last stage",
			input:  "a | b >/dev/null",
			stages: [][]string{{"a"}, {"b"}},
			ops:    []string{"|"},
		},
		{
			name:   "explicit stdout descriptor on the last stage",
			input:  "a | b 1>/dev/null",
			stages: [][]string{{"a"}, {"b"}},
			ops:    []string{"|"},
		},
		{
			name:   "descriptor-less redirect glued to the preceding word",
			input:  "grep x f>/dev/null && b",
			stages: [][]string{{"grep", "x", "f"}, {"b"}},
			ops:    []string{"&&"},
		},
		{
			name:    "accepted wrapper strips inside the quoted body",
			input:   `sh -c 'a 2>/dev/null | b'`,
			wrapped: true,
			stages:  [][]string{{"a"}, {"b"}},
			ops:     []string{"|"},
		},
		{
			name:    "accepted wrapper with a single stage",
			input:   `sh -c 'ls -la 2>/dev/null'`,
			wrapped: true,
			stages:  [][]string{{"ls", "-la"}},
			ops:     nil,
		},
		{
			name:    "accepted wrapper with a stdout redirect off the pipe",
			input:   `sh -c 'gofmt -w a.go >/dev/null && go build ./...'`,
			wrapped: true,
			stages:  [][]string{{"gofmt", "-w", "a.go"}, {"go", "build", "./..."}},
			ops:     []string{"&&"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, ok := RecognizeSimpleCompoundForGrant(canon(t, tt.input))
			if !ok {
				t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = not simple, want the stripped decomposition", tt.input)
			}
			if sc.Wrapped != tt.wrapped {
				t.Errorf("Wrapped = %v, want %v", sc.Wrapped, tt.wrapped)
			}
			if !equalStageTokens(sc.Stages, tt.stages) {
				t.Errorf("Stages = %v, want %v", sc.Stages, tt.stages)
			}
			if strings.Join(sc.Operators, ",") != strings.Join(tt.ops, ",") {
				t.Errorf("Operators = %v, want %v", sc.Operators, tt.ops)
			}
			// The executor decision reads the original text: it must still refuse it, so the command
			// keeps running verbatim through `sh -c` on dispatchLiteral.
			if _, ok := RecognizeSimpleCompound(canon(t, tt.input)); ok {
				t.Errorf("RecognizeSimpleCompound(%q) = simple, want refusal (executor routing must not change)", tt.input)
			}
			if _, _, _, ok := SimpleCompoundStages(canon(t, tt.input)); ok {
				t.Errorf("SimpleCompoundStages(%q) = ok, want refusal (executor routing must not change)", tt.input)
			}
		})
	}
}

func TestRecognizeSimpleCompoundForGrant_ByteExactNegatives(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"stdout to null feeding a pipe", "a >/dev/null | b"},
		{"explicit stdout descriptor feeding a pipe", "a 1>/dev/null | b"},
		{"stderr onto stdout", "a 2>&1 | b"},
		{"stdout onto stderr", "a 1>&2 | b"},
		{"different target", "a > out.txt | b"},
		{"append to null", "a >> /dev/null | b"},
		{"combined descriptors to null", "a &>/dev/null | b"},
		{"input redirect", "a < in.txt | b"},
		{"other descriptor duplication", "a 3>&1 | b"},
		{"quoted null target", `a 2>'/dev/null' | b`},
		{"variable in the redirect-bearing stage", "a $X 2>/dev/null | b"},
		{"glob in the redirect-bearing stage", "a *.go 2>/dev/null | b"},
		{"leading tilde in the redirect-bearing stage", "a ~/x 2>/dev/null | b"},
		{"brace list in the redirect-bearing stage", "a {x,y} 2>/dev/null | b"},
		{"variable in a later stage", "a 2>/dev/null | b $Y"},
		{"glued word suffix before a pipe", "a f1>/dev/null | b"},
		{"glued stderr-looking suffix before a pipe", "a f2>/dev/null | b"},
		{"glued word suffix on the last stage", "a | b f1>/dev/null"},
		{"glued stderr-looking suffix on the last stage", "a | b f2>/dev/null"},
		{"eligible strip leaves an input redirect behind", "a 2>/dev/null | b < in.txt"},
		{"eligible strip leaves an ineligible stdout redirect behind", "a >/dev/null | b 2>/dev/null"},
		{"wrapper with an extra positional argument", `sh -c 'a 2>/dev/null | b' extra`},
		{"path-form sh wrapper", `/bin/sh -c 'a 2>/dev/null | b'`},
		{"bash wrapper", `bash -c 'a 2>/dev/null | b'`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := RecognizeSimpleCompoundForGrant(canon(t, tt.input)); ok {
				t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = simple, want not simple (must stay byte-exact)", tt.input)
			}
		})
	}
}

func TestRecognizeSimpleCompoundForGrant_QuotedRedirectTextIsData(t *testing.T) {
	c := canon(t, `echo "2>/dev/null" f | b`)
	want := [][]string{{"echo", "2>/dev/null", "f"}, {"b"}}

	sc, ok := RecognizeSimpleCompoundForGrant(c)
	if !ok {
		t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = not simple, want the quoted token intact", c)
	}
	if !equalStageTokens(sc.Stages, want) || strings.Join(sc.Operators, ",") != "|" {
		t.Fatalf("stages = %v, operators = %v, want %v with a single pipe", sc.Stages, sc.Operators, want)
	}
	// Its route is unchanged: the execution recognizer already accepts this pipeline today.
	exec, ok := RecognizeSimpleCompound(c)
	if !ok || !equalStageTokens(exec.Stages, want) {
		t.Fatalf("RecognizeSimpleCompound(%q) = (%+v, %v), want the same stages", c, exec, ok)
	}

	wrappedForm := canon(t, `sh -c 'echo "2>/dev/null" f | b'`)
	sc, ok = RecognizeSimpleCompoundForGrant(wrappedForm)
	if !ok || !sc.Wrapped || !equalStageTokens(sc.Stages, want) {
		t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = (%+v, %v), want the wrapped form with the same stages", wrappedForm, sc, ok)
	}
}

func TestStripNullRedirectsForGrant(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		removed bool
		ok      bool
	}{
		{"stderr on a stage feeding a pipe", "a 2>/dev/null | b", "a | b", true, true},
		{"stderr with whitespace before the target", "a 2> /dev/null | b", "a | b", true, true},
		{"stdout on the last stage", "a | b >/dev/null", "a | b", true, true},
		{"stdout feeding a pipe is kept", "a >/dev/null | b", "a >/dev/null | b", false, true},
		{"explicit stdout descriptor feeding a pipe is kept", "a 1>/dev/null | b", "a 1>/dev/null | b", false, true},
		{"duplication is kept", "a 2>&1 | b", "a 2>&1 | b", false, true},
		{"glued word suffix is kept", "a f2>/dev/null | b", "a f2>/dev/null | b", false, true},
		{"other target is kept", "a > out.txt | b", "a > out.txt | b", false, true},
		{"accepted wrapper is rebuilt around the stripped body", `sh -c 'a 2>/dev/null | b'`, `sh -c 'a | b'`, true, true},
		{"redirect-free input is returned unchanged", "a | b", "a | b", false, true},
		{"unterminated quote fails closed", "a 2>/dev/null | b '", "", false, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, removed, ok := stripNullRedirectsForGrant(tt.input)
			if got != tt.want || removed != tt.removed || ok != tt.ok {
				t.Fatalf("stripNullRedirectsForGrant(%q) = (%q, %v, %v), want (%q, %v, %v)",
					tt.input, got, removed, ok, tt.want, tt.removed, tt.ok)
			}
		})
	}
}

func TestRecognizeSimpleCompoundForGrant_BareRedirectFreeUnchanged(t *testing.T) {
	for _, input := range []string{
		"a $X && b | c",
		"a *.go && b | c",
		"a ~/x && b | c",
		"gofmt -w a.go && go build ./...",
	} {
		t.Run(input, func(t *testing.T) {
			c := canon(t, input)
			want, wantOK := RecognizeSimpleCompound(c)
			if !wantOK {
				t.Fatalf("RecognizeSimpleCompound(%q) = not simple; the regression case needs a recognized command", input)
			}
			got, ok := RecognizeSimpleCompoundForGrant(c)
			if !ok {
				t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = not simple, want the existing recognition preserved", input)
			}
			if got.Wrapped != want.Wrapped || !equalStageTokens(got.Stages, want.Stages) ||
				strings.Join(got.Operators, ",") != strings.Join(want.Operators, ",") {
				t.Fatalf("grant recognition %+v differs from existing recognition %+v", got, want)
			}
		})
	}
}

func TestRecognizeSimpleCompoundForGrant_WrappedRedirectFreeExpansionRefused(t *testing.T) {
	for _, input := range []string{
		`sh -c 'a $X && b'`,
		`sh -c 'a *.go && b'`,
	} {
		t.Run(input, func(t *testing.T) {
			c := canon(t, input)
			if _, ok := RecognizeSimpleCompoundForGrant(c); ok {
				t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = simple, want refusal (sh -c expands the token)", input)
			}
			if _, ok := RecognizeSimpleCompound(c); !ok {
				t.Fatalf("RecognizeSimpleCompound(%q) = not simple, want execution recognition unchanged", input)
			}
		})
	}
}

func exactCompoundGrant(t *testing.T, sc SimpleCompound) string {
	t.Helper()
	stageSubjects := make([]string, len(sc.Stages))
	for i, stage := range sc.Stages {
		stageSubjects[i] = ExactSubject(stage[0], stage[1:])
	}
	grant, err := EncodeCompoundSubject(sc.Wrapped, stageSubjects, sc.Operators)
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	return grant
}

func TestMatchesCompoundSubject_WrappedQuotedGrantDoesNotCoverExpansion(t *testing.T) {
	source := canon(t, `sh -c "mv '*.txt' d && true"`)
	request := canon(t, `sh -c 'mv *.txt d && true'`)

	sc, ok := RecognizeSimpleCompoundForGrant(source)
	if !ok {
		t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = not simple, want the inert source recognized", source)
	}
	grant := exactCompoundGrant(t, sc)
	if want := "compound/v1 W mv '*.txt' d && true"; grant != want {
		t.Fatalf("grant = %q, want %q", grant, want)
	}
	if !matchesCompoundSubject(source, grant) {
		t.Fatalf("matchesCompoundSubject(%q, %q) = false, want the grant to cover its own source", source, grant)
	}
	if matchesCompoundSubject(request, grant) {
		t.Fatalf("matchesCompoundSubject(%q, %q) = true, want the expanding glob to re-prompt", request, grant)
	}
}

func TestMatchesCompoundSubject_StoredWrappedGrantDoesNotCoverExpansion(t *testing.T) {
	const stored = "compound/v1 W mv '*.txt' d && true"
	if !matchesCompoundSubject(canon(t, `sh -c "mv '*.txt' d && true"`), stored) {
		t.Fatalf("stored grant %q does not match its inert source, want a decodable grant", stored)
	}
	if matchesCompoundSubject(canon(t, `sh -c 'mv *.txt d && true'`), stored) {
		t.Fatalf("stored grant %q matched the expanding request, want re-prompt", stored)
	}
}

func TestRecognizeSimpleCompoundForGrant_WrappedExpansionTable(t *testing.T) {
	cases := []struct {
		name      string
		inert     string
		expanding string
		homePin   bool
	}{
		{"star", "ls '*.txt' && true", "ls *.txt && true", false},
		{"question mark", "ls 'a?.txt' && true", "ls a?.txt && true", false},
		{"bracket class", "ls '[ab].txt' && true", "ls [ab].txt && true", false},
		{"tilde", "cat '~/x' && true", "cat ~/x && true", true},
		{"home variable", "cat '$HOME' && true", "cat $HOME && true", true},
		{"double-quoted home variable", "cat '$HOME' && true", `cat "$HOME" && true`, true},
		{"brace list", "ls '{a,b}' && true", "ls {a,b} && true", false},
	}
	variants := []struct {
		name     string
		redirect string
	}{
		{"redirect-free", ""},
		{"stderr to null", " 2>/dev/null"},
	}
	for _, tt := range cases {
		for _, v := range variants {
			t.Run(tt.name+"/"+v.name, func(t *testing.T) {
				withRedirect := func(body string) string {
					stage, rest, _ := strings.Cut(body, " && ")
					return "sh -c " + ShellQuote(stage+v.redirect+" && "+rest)
				}
				source := canon(t, withRedirect(tt.inert))
				request := canon(t, withRedirect(tt.expanding))

				sc, ok := RecognizeSimpleCompoundForGrant(source)
				if !ok || !sc.Wrapped {
					t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = (%+v, %v), want the inert wrapped source", source, sc, ok)
				}
				grant := exactCompoundGrant(t, sc)
				if got := matchesCompoundSubject(source, grant); got == tt.homePin {
					t.Fatalf("matchesCompoundSubject(%q, %q) = %v, want %v (a pinned home form cannot prove its expansion)", source, grant, got, !tt.homePin)
				}
				if _, ok := RecognizeSimpleCompoundForGrant(request); ok {
					t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = simple, want refusal", request)
				}
				if matchesCompoundSubject(request, grant) {
					t.Fatalf("matchesCompoundSubject(%q, %q) = true, want the expanding spelling to re-prompt", request, grant)
				}
			})
		}
	}
}

func TestRecognizeSimpleCompoundForGrant_BashWrapperStaysByteExact(t *testing.T) {
	for _, input := range []string{
		`bash -c "mv '*.txt' d && true"`,
		`bash -c 'mv *.txt d && true'`,
		`bash -c "mv '*.txt' d 2>/dev/null && true"`,
		`bash -c 'mv *.txt d 2>/dev/null && true'`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, ok := RecognizeSimpleCompoundForGrant(canon(t, input)); ok {
				t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = simple, want bash -c to stay byte-exact", input)
			}
		})
	}
}

func TestRecognizeSimpleCompoundForGrant_StoredSubjectCarriesNoRedirect(t *testing.T) {
	req, ok := RecognizeSimpleCompoundForGrant(canon(t, "./p.sh u.txt 2>/dev/null | sed -n 1,18p"))
	if !ok {
		t.Fatalf("RecognizeSimpleCompoundForGrant = not simple, want the stripped decomposition")
	}
	// Built the way the chooser's default Exact row builds them: ExactSubject in
	// internal/tui/prompt_scope.go shell-quotes each token and joins them with one space.
	stageSubjects := make([]string, len(req.Stages))
	for i, stage := range req.Stages {
		parts := make([]string, len(stage))
		for j, tok := range stage {
			parts[j] = ShellQuote(tok)
		}
		stageSubjects[i] = strings.Join(parts, " ")
	}
	stored, err := EncodeCompoundSubject(req.Wrapped, stageSubjects, req.Operators)
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	if want := "compound/v1 B ./p.sh u.txt | sed -n 1,18p"; stored != want {
		t.Fatalf("stored subject = %q, want %q", stored, want)
	}
	if strings.Contains(stored, "/dev/null") {
		t.Fatalf("stored subject %q still carries the redirect", stored)
	}
}

func TestMatchesCompoundSubject_NullRedirectWidening(t *testing.T) {
	// The chooser defaults every stage to Exact, so the stage-one widening below is the user's
	// choice, not something the redirect strip produced.
	grant, err := EncodeCompoundSubject(false, []string{"./p.sh :*", "sed -n 1,18p"}, []string{"|"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	if want := "compound/v1 B ./p.sh :* | sed -n 1,18p"; grant != want {
		t.Fatalf("encoded grant = %q, want %q", grant, want)
	}

	positives := []string{
		"./p.sh other.txt 2>/dev/null | sed -n 1,18p",
		"./p.sh other.txt 2> /dev/null | sed -n 1,18p",
	}
	for _, cmd := range positives {
		t.Run("match/"+cmd, func(t *testing.T) {
			if !matchesCompoundSubject(canon(t, cmd), grant) {
				t.Fatalf("matchesCompoundSubject(%q) = false, want true", cmd)
			}
		})
	}

	negatives := []struct {
		name string
		cmd  string
	}{
		{"descriptor duplication", "./p.sh other.txt 2>&1 | sed -n 1,18p"},
		{"different target", "./p.sh other.txt > log | sed -n 1,18p"},
		{"stdout discarded into a pipe", "./p.sh other.txt >/dev/null | sed -n 1,18p"},
		{"glued word suffix", "./p.sh other.txt f1>/dev/null | sed -n 1,18p"},
		{"glued stderr-looking suffix", "./p.sh other.txt f2>/dev/null | sed -n 1,18p"},
		{"exact stage two differs", "./p.sh other.txt | sed -n 2,9p"},
		{"different program", "./q.sh other.txt 2>/dev/null | sed -n 1,18p"},
		{"different operator", "./p.sh other.txt 2>/dev/null && sed -n 1,18p"},
		{"extra stage", "./p.sh other.txt 2>/dev/null | sed -n 1,18p | head"},
	}
	for _, tt := range negatives {
		t.Run("nomatch/"+tt.name, func(t *testing.T) {
			if matchesCompoundSubject(canon(t, tt.cmd), grant) {
				t.Fatalf("matchesCompoundSubject(%q) = true, want false (%s must re-prompt)", tt.cmd, tt.name)
			}
		})
	}

	exact, err := EncodeCompoundSubject(false, []string{"./p.sh u.txt", "sed -n 1,18p"}, []string{"|"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject (all exact) error: %v", err)
	}
	if want := "compound/v1 B ./p.sh u.txt | sed -n 1,18p"; exact != want {
		t.Fatalf("encoded all-exact grant = %q, want %q", exact, want)
	}
	if !matchesCompoundSubject(canon(t, "./p.sh u.txt 2>/dev/null | sed -n 1,18p"), exact) {
		t.Fatalf("the all-exact grant must still cover its own redirect-bearing spelling")
	}
	if matchesCompoundSubject(canon(t, "./p.sh other.txt 2>/dev/null | sed -n 1,18p"), exact) {
		t.Fatalf("the all-exact grant must not cover a different argument; the strip does not widen a stage")
	}
}

// The redirect-free spelling of this command never reaches literal matching at all — dispatch
// authorizes it stage by stage as direct requests — so the two kinds must not cross-match.
func TestMatch_LiteralCompoundGrantDoesNotCoverDirectRequest(t *testing.T) {
	subject, err := EncodeCompoundSubject(false, []string{"./p.sh :*", "sed -n 1,18p"}, []string{"|"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject error: %v", err)
	}
	grants := []PermissionEntry{{
		Kind:      subjectKindLiteral,
		Subject:   subject,
		PathScope: "/work/proj",
		GrantKind: grantKindFolder,
	}}

	literal := MatchRequest{
		Kind:      subjectKindLiteral,
		Subject:   canon(t, "./p.sh other.txt 2>/dev/null | sed -n 1,18p"),
		PathScope: "/work/proj",
	}
	if !Match(literal, grants).Matched {
		t.Fatalf("the literal request must match its generalized compound grant")
	}

	direct := MatchRequest{
		Kind:          subjectKindDirect,
		Subject:       "./p.sh other.txt",
		SubjectTokens: []string{"./p.sh", "other.txt"},
		PathScope:     "/work/proj",
	}
	if Match(direct, grants).Matched {
		t.Fatalf("a direct request must not match a literal compound grant")
	}
}

// A compound grant never carries environment state, so its stages must keep matching the
// assignment-free, environment-inheriting reading even after clear-environment identity exists.
func TestMatchesCompoundSubject_StagesStayAssignmentFreeAndInheriting(t *testing.T) {
	grant, err := EncodeCompoundSubject(false, []string{"env :*", "echo hi"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject: %v", err)
	}
	request, err := CanonicalLiteralForm("env ls && echo hi")
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	if matchesCompoundSubject(request, grant) {
		t.Fatalf("a compound grant over the wrapper name authorized %q", request)
	}

	inner, err := EncodeCompoundSubject(false, []string{"ls :*", "echo hi"}, []string{"&&"})
	if err != nil {
		t.Fatalf("EncodeCompoundSubject: %v", err)
	}
	if !matchesCompoundSubject(request, inner) {
		t.Fatalf("a compound grant over the inner command stopped authorizing %q", request)
	}
	for _, held := range []string{"env FOO=bar ls && echo hi", "env -i PATH=/usr/bin ls && echo hi"} {
		c, err := CanonicalLiteralForm(held)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q): %v", held, err)
		}
		if matchesCompoundSubject(c, inner) {
			t.Fatalf("an environment-bearing stage matched the assignment-free compound grant: %q", held)
		}
	}
}

func TestMatchesCompoundSubject_PinnedHomeStageFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		stage    string
		requests []string
	}{
		{"exact tilde path", ExactSubject("cat", []string{"~/x"}), []string{"cat '~/x' && true", "cat \\~/x && true", "cat ~/x && true"}},
		{"exact home variable", ExactSubject("cat", []string{"$HOME"}), []string{"cat '$HOME' && true", `cat "$HOME" && true`, "cat $HOME && true"}},
		{"exact lone tilde", ExactSubject("cat", []string{"-n", "~"}), []string{"cat -n '~' && true", "cat -n ~ && true"}},
		{"prefix pinning a home form", PrefixSubject("cat", []string{"~/x"}), []string{"cat '~/x' -n && true", "cat ~/x -n && true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant, err := EncodeCompoundSubject(false, []string{tt.stage, "true"}, []string{"&&"})
			if err != nil {
				t.Fatalf("EncodeCompoundSubject(%q): %v", tt.stage, err)
			}
			source := canon(t, tt.requests[0])
			if _, ok := RecognizeSimpleCompoundForGrant(source); !ok {
				t.Fatalf("RecognizeSimpleCompoundForGrant(%q) = not simple, want the grant's own source recognized", source)
			}
			for _, request := range tt.requests {
				if matchesCompoundSubject(canon(t, request), grant) {
					t.Fatalf("matchesCompoundSubject(%q, %q) = true, want a pinned home form refused", request, grant)
				}
			}
		})
	}
}

func TestMatchesCompoundSubject_UnpinnedHomeFormsKeepMatching(t *testing.T) {
	tests := []struct {
		name    string
		stage   string
		request string
	}{
		{"program scope over a tilde path", ProgramSubject("cat"), "cat '~/x' && true"},
		{"prefix scope over a home variable tail", PrefixSubject("cat", []string{"-n"}), "cat -n '$HOME' && true"},
		{"prefix scope over a lone tilde tail", PrefixSubject("cat", []string{"-n"}), "cat -n '~' && true"},
		{"exact tilde-user pin", ExactSubject("cat", []string{"~alice/x"}), "cat '~alice/x' && true"},
		{"exact longer variable pin", ExactSubject("cat", []string{"$HOMEDIR"}), "cat '$HOMEDIR' && true"},
		{"exact embedded home variable pin", ExactSubject("cat", []string{"a/$HOME"}), "cat 'a/$HOME' && true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant, err := EncodeCompoundSubject(false, []string{tt.stage, "true"}, []string{"&&"})
			if err != nil {
				t.Fatalf("EncodeCompoundSubject(%q): %v", tt.stage, err)
			}
			if !matchesCompoundSubject(canon(t, tt.request), grant) {
				t.Fatalf("matchesCompoundSubject(%q, %q) = false, want the unpinned argument covered", tt.request, grant)
			}
		})
	}
}
