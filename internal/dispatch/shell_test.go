// Unit tests for DispatchShell: route selection, per-stage authorization, literal/wrapper routing,
// rejected constructs, pipeline chaining, and runner-result adaptation, using fake authorizer/runner.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/tools"
)

// authBehavior is the canned response the fake authorizer returns for one subject. prompts records
// whether the modeled permission check would have shown a prompt (a real-grant or cache hit does not).
type authBehavior struct {
	decision permissions.Decision
	prompts  bool
}

// fakeAuthorizer is a dispatch-local stand-in for the Authorize seam. It returns canned
// decisions per canonical subject, records every request and its prompt-display payload in order,
// and tracks which subjects triggered a modeled prompt so tests can assert "only that stage prompts".
type fakeAuthorizer struct {
	bySubject   map[string]authBehavior
	fallback    *authBehavior
	onAuthorize func(permissions.MatchRequest)
	requests    []permissions.MatchRequest
	displays    []PromptDisplay
	modeCtxs    []permissions.ModeContext
	prompted    []string
	batchCalls  int
	batches     [][]BatchAuthRequest
}

func (f *fakeAuthorizer) Authorize(_ context.Context, req permissions.MatchRequest, display PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	f.requests = append(f.requests, req)
	f.displays = append(f.displays, display)
	f.modeCtxs = append(f.modeCtxs, modeCtx)
	if f.onAuthorize != nil {
		f.onAuthorize(req)
	}
	b, ok := f.bySubject[req.Subject]
	if !ok {
		if f.fallback == nil {
			return permissions.Decision{}, errors.New("fakeAuthorizer: no behavior for subject " + req.Subject)
		}
		b = *f.fallback
	}
	if b.prompts {
		f.prompted = append(f.prompted, req.Subject)
	}
	return b.decision, nil
}

// AuthorizeBatch lets the fake stand in for the BatchAuthorizer seam dispatchDirect now drives.
// It records the batch it was handed, then authorizes every stage through the same per-subject
// Authorize path (so requests/displays/modeCtxs/prompted stay populated for the existing per-stage
// assertions) and returns index-aligned decisions. Modeling the seam as a per-stage loop keeps these
// dispatch-level tests focused on what dispatch builds and how it reads decisions; the real
// resolve-without-prompt-then-one-prompt behavior is covered in internal/permissions.
func (f *fakeAuthorizer) AuthorizeBatch(ctx context.Context, reqs []BatchAuthRequest) ([]permissions.Decision, error) {
	f.batchCalls++
	f.batches = append(f.batches, reqs)
	decs := make([]permissions.Decision, len(reqs))
	for i, r := range reqs {
		d, err := f.Authorize(ctx, r.Req, r.Display, r.ModeCtx)
		if err != nil {
			return nil, err
		}
		decs[i] = d
	}
	return decs, nil
}

func envRequestSubject(t *testing.T, assignments []string, tokens ...string) string {
	t.Helper()
	subject, err := permissions.DirectRequestSubject(tokens, assignments, false)
	if err != nil {
		t.Fatalf("DirectRequestSubject(%v, %v): %v", tokens, assignments, err)
	}
	return subject
}

// compile-time check that the fake satisfies both seams DispatchShell needs (Authorize for the
// literal route, AuthorizeBatch for the direct pipeline route).
var (
	_ Authorizer      = (*fakeAuthorizer)(nil)
	_ BatchAuthorizer = (*fakeAuthorizer)(nil)
)

// fakeRunner is a dispatch-local stand-in for the shared command runner. It hands out deterministic
// distinct invocation ids, records every RunSpec it is asked to execute, and returns canned results
// in call order.
type fakeRunner struct {
	results []runner.RunResult
	execErr error
	calls   []runner.RunSpec
	nextID  int
}

func (f *fakeRunner) NewInvocationID() string {
	id := "inv-" + string(rune('a'+f.nextID))
	f.nextID++
	return id
}

func (f *fakeRunner) Exec(_ context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	idx := len(f.calls)
	f.calls = append(f.calls, spec)
	if f.execErr != nil {
		return runner.RunResult{}, f.execErr
	}
	if idx < len(f.results) {
		return f.results[idx], nil
	}
	return runner.RunResult{}, nil
}

type planAuthorizer struct{ root string }

func (p planAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, _ PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	modeCtx.Mode = "plan"
	modeCtx.ProjectRoot = p.root
	deps := permissions.AuthorizeDeps{
		EmitMatched: func(_, _, _, _, _, _, _, _, _ string) error { return nil },
	}
	return permissions.Authorize(ctx, req, modeCtx, deps)
}

func grantDecision() permissions.Decision { return permissions.Decision{Outcome: "folder_grant"} }

func denyDecision(envelope string) permissions.Decision {
	return permissions.Decision{Outcome: "deny", DenyEnvelope: envelope}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return r
}

func envContains(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

func mkdir(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", p, err)
	}
	return p
}

func TestDispatchShell_SingleStageAuthorizedRuns(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	wantScope := mustEval(t, cwd)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"git status": {decision: grantDecision()},
	}}
	run := &fakeRunner{results: []runner.RunResult{
		{Stdout: []byte("clean\n"), Stderr: []byte("warn\n"), ExitCode: 0, Duration: 5 * time.Millisecond},
	}}

	res, err := DispatchShell(context.Background(), "git status", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	got := auth.requests[0]
	if got.Kind != "direct" || got.Subject != "git status" {
		t.Fatalf("MatchRequest kind/subject = %q/%q, want direct/\"git status\"", got.Kind, got.Subject)
	}
	if !reflect.DeepEqual(got.SubjectTokens, []string{"git", "status"}) {
		t.Fatalf("SubjectTokens = %v, want [git status]", got.SubjectTokens)
	}
	if got.PathScope != wantScope {
		t.Fatalf("PathScope = %q, want %q", got.PathScope, wantScope)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	call := run.calls[0]
	if !reflect.DeepEqual(call.Argv, []string{"git", "status"}) {
		t.Fatalf("Argv = %v, want [git status]", call.Argv)
	}
	if call.Cwd != wantScope {
		t.Fatalf("RunSpec.Cwd = %q, want %q", call.Cwd, wantScope)
	}
	if call.InvocationID == "" {
		t.Fatalf("RunSpec.InvocationID is empty; runner requires a minted id")
	}
	if string(res.Stdout) != "clean\n" || string(res.Stderr) != "warn\n" || res.ExitCode != 0 {
		t.Fatalf("result = %+v, want stdout/stderr/exit clean/warn/0", res)
	}
}

func TestDispatchShell_PromptDisplayIsRunCommand(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()

	t.Run("direct pipeline carries each stage's source command and the full pipeline context", func(t *testing.T) {
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
			"cat file": {decision: grantDecision()},
			"grep x":   {decision: grantDecision()},
		}}
		run := &fakeRunner{results: []runner.RunResult{{}, {}}}
		if _, err := DispatchShell(context.Background(), "cat file | grep x", home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		want := []PromptDisplay{
			{Action: ActionRunCommand, Subject: "cat file", Pipeline: "cat file | grep x"},
			{Action: ActionRunCommand, Subject: "grep x", Pipeline: "cat file | grep x"},
		}
		if !reflect.DeepEqual(auth.displays, want) {
			t.Fatalf("prompt displays = %+v, want %+v", auth.displays, want)
		}
		// the pipeline context is display-only: each stage's matching subject and tokens stay the
		// isolated stage, unchanged by the added full-pipeline text.
		wantTokens := [][]string{{"cat", "file"}, {"grep", "x"}}
		for i, req := range auth.requests {
			if !reflect.DeepEqual(req.SubjectTokens, wantTokens[i]) {
				t.Fatalf("stage %d SubjectTokens = %v, want %v (pipeline context must not change matching tokens)", i, req.SubjectTokens, wantTokens[i])
			}
		}
	})

	t.Run("quoted direct stages display their source while matching stays canonical", func(t *testing.T) {
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
			"git commit -m 'a b'": {decision: grantDecision(), prompts: true},
			"tee out.txt":         {decision: grantDecision(), prompts: true},
		}}
		run := &fakeRunner{results: []runner.RunResult{{}, {}}}
		input := `git commit -m "a b" | tee out.txt`
		if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		wantDisplays := []PromptDisplay{
			{Action: ActionRunCommand, Subject: `git commit -m "a b"`, Pipeline: input},
			{Action: ActionRunCommand, Subject: "tee out.txt", Pipeline: input},
		}
		if !reflect.DeepEqual(auth.displays, wantDisplays) {
			t.Fatalf("prompt displays = %+v, want %+v (quotes must survive to the prompt)", auth.displays, wantDisplays)
		}
		if auth.requests[0].Subject != "git commit -m 'a b'" {
			t.Fatalf("matching subject = %q, want the canonical %q (display must not reach the request)", auth.requests[0].Subject, "git commit -m 'a b'")
		}
		wantTokens := []string{"git", "commit", "-m", "a b"}
		if !reflect.DeepEqual(auth.requests[0].SubjectTokens, wantTokens) {
			t.Fatalf("SubjectTokens = %v, want %v", auth.requests[0].SubjectTokens, wantTokens)
		}
		if got := auth.modeCtxs[0].Stages; len(got) != 1 || !reflect.DeepEqual(got[0].Tokens, wantTokens) {
			t.Fatalf("mode context stage tokens = %+v, want %v", got, wantTokens)
		}
		if !reflect.DeepEqual(run.calls[0].Argv, wantTokens) {
			t.Fatalf("Argv = %v, want %v (display text must never reach exec)", run.calls[0].Argv, wantTokens)
		}
	})

	t.Run("single direct command carries no pipeline context", func(t *testing.T) {
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"ls -l": {decision: grantDecision()}}}
		run := &fakeRunner{results: []runner.RunResult{{}}}
		if _, err := DispatchShell(context.Background(), "ls -l", home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		want := []PromptDisplay{{Action: ActionRunCommand, Subject: "ls -l"}}
		if !reflect.DeepEqual(auth.displays, want) {
			t.Fatalf("prompt displays = %+v, want %+v (single direct command has empty Pipeline and WholeCommand)", auth.displays, want)
		}
	})

	t.Run("cd prefix is absent from direct display text while it still sets the scope", func(t *testing.T) {
		dir := t.TempDir()
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{"ls -l": {decision: grantDecision()}}}
		run := &fakeRunner{results: []runner.RunResult{{}}}
		if _, err := DispatchShell(context.Background(), "cd "+dir+" && ls -l", home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		want := []PromptDisplay{{Action: ActionRunCommand, Subject: "ls -l"}}
		if !reflect.DeepEqual(auth.displays, want) {
			t.Fatalf("prompt displays = %+v, want %+v (the cd prefix is path scope, not displayed command text)", auth.displays, want)
		}
		if auth.requests[0].PathScope != mustEval(t, dir) || run.calls[0].Cwd != mustEval(t, dir) {
			t.Fatalf("scope = %q / cwd = %q, want %q (stripping the prefix from display must not move the scope)", auth.requests[0].PathScope, run.calls[0].Cwd, mustEval(t, dir))
		}
	})

	t.Run("literal route displays the exact text handed to sh -c and marks a whole-command approval", func(t *testing.T) {
		input := `git commit -m "a b" > out.txt`
		canonical, err := permissions.CanonicalLiteralForm(input)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm: %v", err)
		}
		if canonical == input {
			t.Fatalf("canonical form %q equals the source; this case must exercise a real display/matching divergence", canonical)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{canonical: {decision: grantDecision()}}}
		run := &fakeRunner{results: []runner.RunResult{{}}}
		if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		want := PromptDisplay{Action: ActionRunCommand, Subject: input, WholeCommand: true}
		if len(auth.displays) != 1 || auth.displays[0] != want {
			t.Fatalf("prompt displays = %+v, want [%+v]", auth.displays, want)
		}
		if auth.requests[0].Subject != canonical || auth.requests[0].Kind != "literal" {
			t.Fatalf("request = %+v, want the canonical literal subject %q", auth.requests[0], canonical)
		}
		if !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", input}) {
			t.Fatalf("Argv = %v, want [sh -c %q]", run.calls[0].Argv, input)
		}
		if auth.displays[0].Subject != run.calls[0].Argv[2] {
			t.Fatalf("display %q != sh -c argument %q", auth.displays[0].Subject, run.calls[0].Argv[2])
		}
	})

	t.Run("literal route display drops the cd prefix and keeps the rest verbatim", func(t *testing.T) {
		dir := t.TempDir()
		effective := `git status > "out file.txt"`
		canonical, err := permissions.CanonicalLiteralForm(effective)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm: %v", err)
		}
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{canonical: {decision: grantDecision()}}}
		run := &fakeRunner{results: []runner.RunResult{{}}}
		if _, err := DispatchShell(context.Background(), "cd "+dir+" && "+effective, home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		if auth.displays[0].Subject != effective {
			t.Fatalf("display = %q, want the prefix-stripped %q", auth.displays[0].Subject, effective)
		}
		if !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", effective}) {
			t.Fatalf("Argv = %v, want [sh -c %q]", run.calls[0].Argv, effective)
		}
	})
}

func TestDispatchShell_SingleStageDeniedDoesNotRun(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	env := permissions.BuildDenyEnvelope("not allowed")

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"rm secret": {decision: denyDecision(env), prompts: true},
	}}
	run := &fakeRunner{}

	_, err := DispatchShell(context.Background(), "rm secret", home, cwd, auth, run)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if de.Envelope != env {
		t.Fatalf("DeniedError.Envelope = %q, want %q", de.Envelope, env)
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0 (denied command must not run)", len(run.calls))
	}
}

func TestDispatchShell_PipelineOneStageDeniedShortCircuits(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	env := permissions.BuildDenyEnvelope("blocked")

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"cat file":    {decision: grantDecision()},                  // grant: no prompt
		"grep secret": {decision: denyDecision(env), prompts: true}, // prompt then deny
	}}
	run := &fakeRunner{}

	_, err := DispatchShell(context.Background(), "cat file | grep secret", home, cwd, auth, run)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0 (no stage runs when a later stage is denied)", len(run.calls))
	}
	// Both stages were authorized in order; only the unauthorized one prompted.
	wantSubjects := []string{"cat file", "grep secret"}
	gotSubjects := []string{auth.requests[0].Subject, auth.requests[1].Subject}
	if len(auth.requests) != 2 || !reflect.DeepEqual(gotSubjects, wantSubjects) {
		t.Fatalf("authorize subjects = %v, want %v", gotSubjects, wantSubjects)
	}
	if !reflect.DeepEqual(auth.prompted, []string{"grep secret"}) {
		t.Fatalf("prompted subjects = %v, want only [grep secret]", auth.prompted)
	}
}

func TestDispatchShell_RejectedConstructNoPromptNoRun(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()

	cases := map[string]string{
		"command substitution":   "echo $(whoami)",
		"backtick":               "echo `id`",
		"newline":                "git status\nrm -rf x",
		"unquoted beside quoted": `echo "$(a)" $(b)`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}} // any call errors out
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), input, home, cwd, auth, run)
			var ue *UnsupportedConstructError
			if !errors.As(err, &ue) {
				t.Fatalf("input %q: error = %v, want *UnsupportedConstructError", input, err)
			}
			if ue.Construct == "" {
				t.Fatalf("input %q: UnsupportedConstructError.Construct is empty", input)
			}
			if len(auth.requests) != 0 {
				t.Fatalf("input %q: authorize calls = %d, want 0 (no prompt for rejected construct)", input, len(auth.requests))
			}
			if len(run.calls) != 0 {
				t.Fatalf("input %q: runner calls = %d, want 0", input, len(run.calls))
			}
		})
	}
}

func TestDispatchShell_DoubleQuotedSubstitutionRunsThroughTheShell(t *testing.T) {
	cases := []struct {
		input  string
		stdout string
	}{
		{`echo "$(printf hi)"`, "hi\n"},
		{`test "$(printf 1)" -eq 1 && echo ok`, "ok\n"},
		{`printf 'a\n' | grep "$(printf a)"`, "a\n"},
		{`cd "$(pwd)" && ls`, "marker.txt\n"},
		{"echo \"`printf hi`\"", "hi\n"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(cwd, "marker.txt"), nil, 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			canonical, err := permissions.CanonicalLiteralForm(tc.input)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm: %v", err)
			}
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &recordingExecRunner{}

			res, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run)
			if err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if auth.batchCalls != 0 || len(auth.requests) != 1 {
				t.Fatalf("batch calls = %d, authorize calls = %d, want one literal authorization and no staged or direct batch", auth.batchCalls, len(auth.requests))
			}
			if got := auth.requests[0]; got.Kind != "literal" || got.Subject != canonical || got.SubjectTokens != nil {
				t.Fatalf("request = %+v, want literal subject %q", got, canonical)
			}
			if len(run.calls) != 1 || !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", tc.input}) {
				t.Fatalf("runner calls = %+v, want the verbatim command through sh -c", run.calls)
			}
			if string(res.Stdout) != tc.stdout {
				t.Fatalf("Stdout = %q (stderr %q), want %q", res.Stdout, res.Stderr, tc.stdout)
			}
		})
	}
}

func TestDispatchShell_DoubleQuotedSubstitutionNeverRunsDirect(t *testing.T) {
	cases := []struct {
		input    string
		rejected bool
	}{
		{input: `echo "pre$(x)post"`},
		{input: `echo "$( x )"`},
		{input: `echo "${v:-$(x)}"`},
		{input: `echo "\\$(x)"`},
		{input: `echo "$(echo "$(x)")"`, rejected: true},
		{input: `echo $"$(x)"`},
		{input: `ls | grep "$(x)"`},
		{input: "ls | grep \"`x`\""},
		{input: `ls && grep "$(x)" f`},
		{input: `ls ; grep "$(x)" f | head`},
		{input: `cd "$(pwd)" && ls`},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run)
			if tc.rejected {
				var ue *UnsupportedConstructError
				if !errors.As(err, &ue) || len(auth.requests) != 0 || len(run.calls) != 0 {
					t.Fatalf("error = %v, authorize calls = %d, runner calls = %d, want *UnsupportedConstructError before any prompt", err, len(auth.requests), len(run.calls))
				}
				return
			}
			if err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			canonical, err := permissions.CanonicalLiteralForm(tc.input)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm: %v", err)
			}
			if auth.batchCalls != 0 || len(auth.requests) != 1 || auth.requests[0].Kind != "literal" || auth.requests[0].Subject != canonical {
				t.Fatalf("batch calls = %d, requests = %+v, want one literal subject %q", auth.batchCalls, auth.requests, canonical)
			}
			if len(run.calls) != 1 || !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", tc.input}) {
				t.Fatalf("runner calls = %+v, want the verbatim command through sh -c", run.calls)
			}
		})
	}
}

func TestDispatchShell_InertQuotedSubstitutionTextKeepsItsRoute(t *testing.T) {
	cases := []struct {
		input string
		argv  []string
	}{
		{`awk '{print $(NF)}' f`, []string{"awk", "{print $(NF)}", "f"}},
		{`echo '$(x)'`, []string{"echo", "$(x)"}},
		{`echo "\$(x)"`, []string{"echo", "$(x)"}},
		{"echo \"\\`x\\`\"", []string{"echo", "`x`"}},
		{`grep "$HOME" f`, []string{"grep", "$HOME", "f"}},
		{`grep "$v" f`, []string{"grep", "$v", "f"}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			wantSubject := envRequestSubject(t, nil, tc.argv...)
			if len(auth.requests) != 1 || auth.requests[0].Kind != "direct" || auth.requests[0].Subject != wantSubject ||
				!reflect.DeepEqual(auth.requests[0].SubjectTokens, tc.argv) {
				t.Fatalf("requests = %+v, want one direct subject %q", auth.requests, wantSubject)
			}
			if len(run.calls) != 1 || !reflect.DeepEqual(run.calls[0].Argv, tc.argv) {
				t.Fatalf("runner calls = %+v, want argv %v with no shell", run.calls, tc.argv)
			}
		})
	}

	const redirected = `grep "$(x)" f > out`
	canonical, err := permissions.CanonicalLiteralForm(redirected)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{}
	if _, err := DispatchShell(context.Background(), redirected, t.TempDir(), t.TempDir(), auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 || auth.requests[0].Kind != "literal" || auth.requests[0].Subject != canonical {
		t.Fatalf("requests = %+v, want one literal subject %q", auth.requests, canonical)
	}
	if len(run.calls) != 1 || !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", redirected}) {
		t.Fatalf("runner calls = %+v, want the verbatim command through sh -c", run.calls)
	}
}

func TestDispatchShell_AndCompoundAuthorizesPerStageAndRuns(t *testing.T) {
	prependFixturePrograms(t, "gofmt", "go", "git")
	cases := []struct {
		input      string
		wantStages [][]string
	}{
		{"gofmt -w a.go && go build ./...", [][]string{{"gofmt", "-w", "a.go"}, {"go", "build", "./..."}}},
		{"git status && git log", [][]string{{"git", "status"}, {"git", "log"}}},
		{`git status && echo "all done" ; git log`, [][]string{{"git", "status"}, {"echo", "all done"}, {"git", "log"}}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			wantScope := mustEval(t, cwd)

			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(auth.requests) != len(tc.wantStages) {
				t.Fatalf("authorize calls = %d, want %d (per-stage direct, not one literal subject)", len(auth.requests), len(tc.wantStages))
			}
			for i, req := range auth.requests {
				wantSubject := permissions.ExactSubject(tc.wantStages[i][0], tc.wantStages[i][1:])
				if req.Kind != "direct" || req.Subject != wantSubject {
					t.Fatalf("request[%d] = %+v, want direct subject %q", i, req, wantSubject)
				}
				if !reflect.DeepEqual(req.SubjectTokens, tc.wantStages[i]) {
					t.Fatalf("request[%d].SubjectTokens = %v, want %v (direct grant matching keys on tokens)", i, req.SubjectTokens, tc.wantStages[i])
				}
				if req.PathScope != wantScope {
					t.Fatalf("request[%d].PathScope = %q, want %q", i, req.PathScope, wantScope)
				}
				wantOneStage(t, auth.modeCtxs[i], tc.wantStages[i])
				if auth.modeCtxs[i].LiteralRoute {
					t.Fatalf("request[%d] ModeContext.LiteralRoute = true, want false (a staged chain classifies per direct stage)", i)
				}
			}
			if len(run.calls) != len(tc.wantStages) {
				t.Fatalf("runner calls = %d, want %d (each stage run directly, no sh -c)", len(run.calls), len(tc.wantStages))
			}
			for i, call := range run.calls {
				if !reflect.DeepEqual(call.Argv, tc.wantStages[i]) {
					t.Fatalf("stage %d Argv = %v, want %v (no sh -c wrapper)", i, call.Argv, tc.wantStages[i])
				}
				if call.Cwd != wantScope {
					t.Fatalf("stage %d Cwd = %q, want the shared resolved scope %q", i, call.Cwd, wantScope)
				}
			}
		})
	}
}

type recordingPlanAuthorizer struct {
	planAuthorizer
	decisions []permissions.Decision
}

func (r *recordingPlanAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, display PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	d, err := r.planAuthorizer.Authorize(ctx, req, display, modeCtx)
	r.decisions = append(r.decisions, d)
	return d, err
}

func TestDispatchShell_CompoundArgSensitiveStagesRunAsArgvInPlan(t *testing.T) {
	cases := []struct {
		input    string
		wantArgv [][]string
	}{
		{"find . -type f && ls", [][]string{{"find", ".", "-type", "f"}, {"ls"}}},
		{
			"sed -n '1,5p' a; printf -- ---; sed -n '9,20p' b",
			[][]string{{"sed", "-n", "1,5p", "a"}, {"printf", "--", "---"}, {"sed", "-n", "9,20p", "b"}},
		},
		{"sed -n '1,5p' a | head; ls", [][]string{{"sed", "-n", "1,5p", "a"}, {"head"}, {"ls"}}},
		{"ps -ef && ls", [][]string{{"ps", "-ef"}, {"ls"}}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if strings.HasPrefix(tc.input, "ps ") && runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
				t.Skip("ps read-only rows exist only for Linux and FreeBSD")
			}
			cwd := t.TempDir()
			home := t.TempDir()
			run := &fakeRunner{}
			auth := &recordingPlanAuthorizer{planAuthorizer: planAuthorizer{root: mustEval(t, cwd)}}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell(%q) = %v, want nil (staged argument-sensitive stages auto-allow in Plan)", tc.input, err)
			}
			if len(auth.decisions) != len(tc.wantArgv) {
				t.Fatalf("authorize calls = %d, want %d (one per staged stage)", len(auth.decisions), len(tc.wantArgv))
			}
			for i, d := range auth.decisions {
				if d.Outcome != "once" || d.Grant != nil || d.DenyEnvelope != "" {
					t.Fatalf("decision[%d] = %+v, want a mode auto-allow with no stored grant", i, d)
				}
			}
			if len(run.calls) != len(tc.wantArgv) {
				t.Fatalf("runner calls = %d, want %d (each stage run directly)", len(run.calls), len(tc.wantArgv))
			}
			for i, call := range run.calls {
				if !reflect.DeepEqual(call.Argv, tc.wantArgv[i]) {
					t.Fatalf("stage %d Argv = %v, want %v (no sh -c wrapper)", i, call.Argv, tc.wantArgv[i])
				}
			}
		})
	}
}

func TestDispatchShell_CompoundArgSensitiveStageDeniedInPlan(t *testing.T) {
	for _, input := range []string{
		"sed -i s/a/b/ f; ls",
		"find . -delete && ls",
		"sed -i s/a/b/ f || ls",
		"sed -i s/a/b/ f | head || ls",
		"ls | head ; find . -delete",
	} {
		t.Run(input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			run := &fakeRunner{}
			auth := planAuthorizer{root: mustEval(t, cwd)}

			_, err := DispatchShell(context.Background(), input, home, cwd, auth, run)
			var denied *DeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("DispatchShell(%q) err = %v, want *DeniedError", input, err)
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %d, want 0 (a denied compound executes nothing)", len(run.calls))
			}
		})
	}
}

func TestDispatchShell_AwkStagedCompoundAuthorizesExactArgvBeforeRunning(t *testing.T) {
	awkArgv := []string{"awk", `NR>=55 && NR<=70 {print NR ":" $0}`, "docs/session-format.md"}
	cases := []struct {
		input    string
		wantAuth [][]string
		wantRun  [][]string
	}{
		{
			`awk 'NR>=55 && NR<=70 {print NR ":" $0}' docs/session-format.md; ls`,
			[][]string{awkArgv, {"ls"}},
			[][]string{awkArgv, {"ls"}},
		},
		{
			`awk 'NR>=1 && NR<=10 {print}' a && awk 'FNR>=2 && FNR<=3 {print $0}' b`,
			[][]string{{"awk", `NR>=1 && NR<=10 {print}`, "a"}, {"awk", `FNR>=2 && FNR<=3 {print $0}`, "b"}},
			[][]string{{"awk", `NR>=1 && NR<=10 {print}`, "a"}, {"awk", `FNR>=2 && FNR<=3 {print $0}`, "b"}},
		},
		{
			`awk 'NR>=1 && NR<=10 {print}' a || ls`,
			[][]string{{"awk", `NR>=1 && NR<=10 {print}`, "a"}, {"ls"}},
			[][]string{{"awk", `NR>=1 && NR<=10 {print}`, "a"}},
		},
		{
			`awk 'NR>=1 && NR<=10 {print}' a | head; ls`,
			[][]string{{"awk", `NR>=1 && NR<=10 {print}`, "a"}, {"head"}, {"ls"}},
			[][]string{{"awk", `NR>=1 && NR<=10 {print}`, "a"}, {"head"}, {"ls"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			wantScope := mustEval(t, cwd)

			run := &fakeRunner{}
			var runCallsAtAuth []int
			auth := &fakeAuthorizer{
				fallback:    &authBehavior{decision: grantDecision()},
				onAuthorize: func(permissions.MatchRequest) { runCallsAtAuth = append(runCallsAtAuth, len(run.calls)) },
			}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell(%q): %v", tc.input, err)
			}
			if len(auth.requests) != len(tc.wantAuth) {
				t.Fatalf("authorize calls = %d, want %d (per-stage direct, not one literal subject)", len(auth.requests), len(tc.wantAuth))
			}
			for i, req := range auth.requests {
				wantSubject := permissions.ExactSubject(tc.wantAuth[i][0], tc.wantAuth[i][1:])
				if req.Kind != "direct" || req.Subject != wantSubject {
					t.Fatalf("request[%d] = %+v, want direct subject %q", i, req, wantSubject)
				}
				if !reflect.DeepEqual(req.SubjectTokens, tc.wantAuth[i]) {
					t.Fatalf("request[%d].SubjectTokens = %v, want %v (the validator judges the argv dispatch runs)", i, req.SubjectTokens, tc.wantAuth[i])
				}
				if req.PathScope != wantScope {
					t.Fatalf("request[%d].PathScope = %q, want %q", i, req.PathScope, wantScope)
				}
				wantOneStage(t, auth.modeCtxs[i], tc.wantAuth[i])
				if auth.modeCtxs[i].LiteralRoute {
					t.Fatalf("request[%d] ModeContext.LiteralRoute = true, want false (a staged chain classifies per direct stage)", i)
				}
			}
			for _, n := range runCallsAtAuth {
				if n != 0 {
					t.Fatalf("runner calls observed during authorization = %v, want all zero (authorize-all-before-run)", runCallsAtAuth)
				}
			}
			gotRun := make([][]string, len(run.calls))
			for i, call := range run.calls {
				gotRun[i] = call.Argv
				if call.Cwd != wantScope {
					t.Fatalf("stage %d Cwd = %q, want the shared resolved scope %q", i, call.Cwd, wantScope)
				}
			}
			if !reflect.DeepEqual(gotRun, tc.wantRun) {
				t.Fatalf("executed stages = %v, want %v (direct argv, no sh -c)", gotRun, tc.wantRun)
			}
		})
	}
}

func TestDispatchShell_AwkStagesAutoAllowInPlan(t *testing.T) {
	for _, tc := range []struct {
		input  string
		stages int
	}{
		{`awk 'NR>=55 && NR<=70 {print NR ":" $0}' docs/session-format.md`, 1},
		{`awk 'NR>=55 && NR<=70 {print NR ":" $0}' docs/session-format.md | head`, 2},
		{`awk 'NR>=1 && NR<=10 {print}' a; ls`, 2},
		{`awk 'NR>=1 && NR<=10 {print}' a && ls`, 2},
		{`awk 'NR>=1 && NR<=10 {print}' a || ls`, 2},
	} {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			run := &fakeRunner{}
			auth := &recordingPlanAuthorizer{planAuthorizer: planAuthorizer{root: mustEval(t, cwd)}}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell(%q) = %v, want nil (a validated awk stage auto-allows in Plan)", tc.input, err)
			}
			if len(auth.decisions) != tc.stages {
				t.Fatalf("authorize calls = %d, want %d (one per stage)", len(auth.decisions), tc.stages)
			}
			for i, d := range auth.decisions {
				if d.Outcome != "once" || d.Grant != nil || d.DenyEnvelope != "" {
					t.Fatalf("decision[%d] = %+v, want a mode auto-allow with no stored grant", i, d)
				}
			}
		})
	}
}

func TestDispatchShell_AwkRejectedStageDeniedInPlan(t *testing.T) {
	for _, input := range []string{
		`awk '{print > "x"}' a; ls`,
		`awk 'NR>=1 && NR<=10 {system("id")}' a && ls`,
		`awk 'NR>=1 && NR<=10 {print > "out"}' a || ls`,
		`ls | head; awk -f prog.awk a`,
	} {
		t.Run(input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			run := &fakeRunner{}
			auth := planAuthorizer{root: mustEval(t, cwd)}

			_, err := DispatchShell(context.Background(), input, home, cwd, auth, run)
			var denied *DeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("DispatchShell(%q) err = %v, want *DeniedError", input, err)
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %d, want 0 (a denied compound executes nothing)", len(run.calls))
			}
		})
	}
}

func TestDispatchShell_CompoundAllReadOnlyAutoAllowedInPlan(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("a")}, {Stdout: []byte("b")}}}
	auth := planAuthorizer{root: mustEval(t, cwd)}

	if _, err := DispatchShell(context.Background(), "git status && git log", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell(git status && git log) = %v, want nil (an all-read-only VCS compound still auto-allows in Plan)", err)
	}
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (both read-only stages run)", len(run.calls))
	}
}

func TestDispatchShell_StagedConditionalExecution(t *testing.T) {
	prependFixturePrograms(t, "git")
	cases := []struct {
		name     string
		input    string
		results  []runner.RunResult
		wantArgv [][]string
		wantExit int
	}{
		{
			name:     "&& successor runs after a zero exit",
			input:    "git status && git log",
			results:  []runner.RunResult{{Stdout: []byte("a"), ExitCode: 0}, {Stdout: []byte("b"), ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "log"}},
		},
		{
			name:     "&& successor is skipped after a non-zero exit",
			input:    "git status && git log",
			results:  []runner.RunResult{{Stdout: []byte("a"), ExitCode: 3}},
			wantArgv: [][]string{{"git", "status"}},
			wantExit: 3,
		},
		{
			name:     "; successor runs after a non-zero exit",
			input:    "git status ; git log",
			results:  []runner.RunResult{{ExitCode: 3}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "log"}},
		},
		{
			name:     "a failure skips the rest of the && chain but not a later ; stage",
			input:    "git status && git log && git diff ; git show",
			results:  []runner.RunResult{{ExitCode: 3}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "show"}},
		},
		{
			name:     "|| successor runs after a non-zero exit",
			input:    "git status || git log",
			results:  []runner.RunResult{{ExitCode: 3}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "log"}},
		},
		{
			name:     "|| successor is skipped after a zero exit",
			input:    "git status || git log",
			results:  []runner.RunResult{{ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}},
		},
		{
			name:     "a && b || c with a and b succeeding skips c",
			input:    "git status && git log || git diff",
			results:  []runner.RunResult{{ExitCode: 0}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "log"}},
		},
		{
			name:     "a && b || c with b failing runs c",
			input:    "git status && git log || git diff",
			results:  []runner.RunResult{{ExitCode: 0}, {ExitCode: 2}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "log"}, {"git", "diff"}},
		},
		{
			name:     "a && b || c with a failing skips b and runs c",
			input:    "git status && git log || git diff",
			results:  []runner.RunResult{{ExitCode: 5}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "diff"}},
		},
		{
			name:     "a || b && c with a succeeding skips b and runs c",
			input:    "git status || git log && git diff",
			results:  []runner.RunResult{{ExitCode: 0}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "diff"}},
		},
		{
			name:     "a || b && c with a failing and b succeeding runs all three",
			input:    "git status || git log && git diff",
			results:  []runner.RunResult{{ExitCode: 1}, {ExitCode: 0}, {ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}, {"git", "log"}, {"git", "diff"}},
		},
		{
			name:     "a || b && c with a and b failing skips c",
			input:    "git status || git log && git diff",
			results:  []runner.RunResult{{ExitCode: 1}, {ExitCode: 4}},
			wantArgv: [][]string{{"git", "status"}, {"git", "log"}},
			wantExit: 4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{results: tc.results}

			res, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run)
			if err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			gotArgv := make([][]string, len(run.calls))
			for i, call := range run.calls {
				gotArgv[i] = call.Argv
			}
			if !reflect.DeepEqual(gotArgv, tc.wantArgv) {
				t.Fatalf("executed stages = %v, want %v", gotArgv, tc.wantArgv)
			}
			if res.ExitCode != tc.wantExit {
				t.Fatalf("exit code = %d, want %d (a skipped successor keeps the running status)", res.ExitCode, tc.wantExit)
			}
		})
	}
}

func TestDispatchShell_StagedAggregatesOnlyExecutedStages(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{results: []runner.RunResult{
		{Stdout: []byte("out-a"), Stderr: []byte("err-a"), ExitCode: 0, Duration: 2 * time.Millisecond},
		{Stdout: []byte("out-c"), Stderr: []byte("err-c"), ExitCode: 7, Duration: 3 * time.Millisecond},
	}}

	res, err := DispatchShell(context.Background(), "git status || git log ; git diff", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (the || successor is skipped after a zero exit)", len(run.calls))
	}
	if string(res.Stdout) != "out-aout-c" {
		t.Fatalf("stdout = %q, want %q (executed stages only, in execution order)", res.Stdout, "out-aout-c")
	}
	if string(res.Stderr) != "err-aerr-c" {
		t.Fatalf("stderr = %q, want %q (executed stages only, in execution order)", res.Stderr, "err-aerr-c")
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7 (the last stage actually run)", res.ExitCode)
	}
	if res.Duration != 5*time.Millisecond {
		t.Fatalf("duration = %v, want 5ms (sum of executed stages)", res.Duration)
	}
}

func TestDispatchShell_StagedAuthorizesSkippedStageBeforeRunning(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	run := &fakeRunner{results: []runner.RunResult{{ExitCode: 0}}}
	var runCallsAtAuth []int
	auth := &fakeAuthorizer{
		fallback:    &authBehavior{decision: grantDecision()},
		onAuthorize: func(permissions.MatchRequest) { runCallsAtAuth = append(runCallsAtAuth, len(run.calls)) },
	}

	if _, err := DispatchShell(context.Background(), "git status || rm -rf x", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	wantSubjects := []string{"git status", "rm -rf x"}
	gotSubjects := make([]string, len(auth.requests))
	for i, req := range auth.requests {
		gotSubjects[i] = req.Subject
	}
	if !reflect.DeepEqual(gotSubjects, wantSubjects) {
		t.Fatalf("authorized subjects = %v, want %v (a stage short-circuiting will skip is still authorized)", gotSubjects, wantSubjects)
	}
	if !reflect.DeepEqual(runCallsAtAuth, []int{0, 0}) {
		t.Fatalf("runner calls observed during authorization = %v, want [0 0] (authorize-all-before-run)", runCallsAtAuth)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1 (the || successor is skipped after a zero exit)", len(run.calls))
	}
}

func TestDispatchShell_PipeGroupsChainWithinGroupAndSequenceBetween(t *testing.T) {
	prependFixturePrograms(t, "git")
	cases := []struct {
		name       string
		input      string
		results    []runner.RunResult
		wantArgv   [][]string
		wantStdin  []string
		wantStdout string
		wantExit   int
	}{
		{
			name:       "a ; b | c runs a first, then pipes b into c",
			input:      "git status ; git log | head",
			results:    []runner.RunResult{{Stdout: []byte("a")}, {Stdout: []byte("b")}, {Stdout: []byte("c")}},
			wantArgv:   [][]string{{"git", "status"}, {"git", "log"}, {"head"}},
			wantStdin:  []string{"", "", "b"},
			wantStdout: "ac",
		},
		{
			name:       "a | b ; c | d runs two independent groups",
			input:      "git status | head ; git log | tail",
			results:    []runner.RunResult{{Stdout: []byte("a")}, {Stdout: []byte("b")}, {Stdout: []byte("c")}, {Stdout: []byte("d")}},
			wantArgv:   [][]string{{"git", "status"}, {"head"}, {"git", "log"}, {"tail"}},
			wantStdin:  []string{"", "a", "", "c"},
			wantStdout: "bd",
		},
		{
			name:       "a group's non-zero final member skips an && successor",
			input:      "git status | head && git log",
			results:    []runner.RunResult{{Stdout: []byte("a"), ExitCode: 0}, {Stdout: []byte("b"), ExitCode: 3}},
			wantArgv:   [][]string{{"git", "status"}, {"head"}},
			wantStdin:  []string{"", "a"},
			wantStdout: "b",
			wantExit:   3,
		},
		{
			name:       "a group's non-zero final member runs a || successor",
			input:      "git status | head || git log",
			results:    []runner.RunResult{{Stdout: []byte("a"), ExitCode: 0}, {Stdout: []byte("b"), ExitCode: 4}, {Stdout: []byte("c"), ExitCode: 0}},
			wantArgv:   [][]string{{"git", "status"}, {"head"}, {"git", "log"}},
			wantStdin:  []string{"", "a", ""},
			wantStdout: "bc",
		},
		{
			name:       "a skipped group runs no member and contributes no output",
			input:      "git status && git log | head",
			results:    []runner.RunResult{{Stdout: []byte("a"), ExitCode: 5}},
			wantArgv:   [][]string{{"git", "status"}},
			wantStdin:  []string{""},
			wantStdout: "a",
			wantExit:   5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{results: tc.results}

			res, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run)
			if err != nil {
				t.Fatalf("DispatchShell(%q): %v", tc.input, err)
			}
			gotArgv := make([][]string, len(run.calls))
			gotStdin := make([]string, len(run.calls))
			for i, call := range run.calls {
				gotArgv[i] = call.Argv
				gotStdin[i] = string(call.Stdin)
			}
			if !reflect.DeepEqual(gotArgv, tc.wantArgv) {
				t.Fatalf("executed stages = %v, want %v (direct argv, never sh -c)", gotArgv, tc.wantArgv)
			}
			if !reflect.DeepEqual(gotStdin, tc.wantStdin) {
				t.Fatalf("stage stdin = %q, want %q (chained inside a group, nil at a group start)", gotStdin, tc.wantStdin)
			}
			if string(res.Stdout) != tc.wantStdout {
				t.Fatalf("stdout = %q, want %q (each group's final member only)", res.Stdout, tc.wantStdout)
			}
			if res.ExitCode != tc.wantExit {
				t.Fatalf("exit code = %d, want %d (the last group's final member)", res.ExitCode, tc.wantExit)
			}
		})
	}
}

func TestDispatchShell_PipeGroupAggregatesStderrAndDuration(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{results: []runner.RunResult{
		{Stdout: []byte("a"), Stderr: []byte("err-a"), Duration: 2 * time.Millisecond},
		{Stdout: []byte("b"), Stderr: []byte("err-b"), Duration: 3 * time.Millisecond},
		{Stdout: []byte("c"), Stderr: []byte("err-c"), ExitCode: 7, Duration: 4 * time.Millisecond},
	}}

	res, err := DispatchShell(context.Background(), "git status | head ; git log", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if string(res.Stderr) != "err-aerr-berr-c" {
		t.Fatalf("stderr = %q, want %q (every executed member, in order)", res.Stderr, "err-aerr-berr-c")
	}
	if res.Duration != 9*time.Millisecond {
		t.Fatalf("duration = %v, want 9ms (sum of every executed member)", res.Duration)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", res.ExitCode)
	}
}

func TestDispatchShell_PipeGroupRunnerErrorReturns(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	boom := errors.New("runner exploded")
	run := &fakeRunner{execErr: boom}

	if _, err := DispatchShell(context.Background(), "git status ; git log | head", home, cwd, auth, run); !errors.Is(err, boom) {
		t.Fatalf("DispatchShell error = %v, want %v (a runner error is not swallowed)", err, boom)
	}
}

func TestDispatchShell_MixedPipeFormRoutesToStagedPerStage(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	wantScope := mustEval(t, cwd)
	const input = "git status ; git log | head"
	wantStages := [][]string{{"git", "status"}, {"git", "log"}, {"head"}}

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{results: []runner.RunResult{{}, {}, {}}}

	if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell(%q): %v", input, err)
	}
	if len(auth.requests) != len(wantStages) {
		t.Fatalf("authorize calls = %d, want %d (per-stage direct, not one literal subject)", len(auth.requests), len(wantStages))
	}
	for i, req := range auth.requests {
		wantSubject := strings.Join(wantStages[i], " ")
		if req.Kind != "direct" || req.Subject != wantSubject {
			t.Fatalf("request[%d] = %+v, want direct subject %q", i, req, wantSubject)
		}
		if req.PathScope != wantScope {
			t.Fatalf("request[%d].PathScope = %q, want %q", i, req.PathScope, wantScope)
		}
		wantOneStage(t, auth.modeCtxs[i], wantStages[i])
		if auth.modeCtxs[i].LiteralRoute {
			t.Fatalf("request[%d] ModeContext.LiteralRoute = true, want false (a mixed pipe form classifies per direct stage)", i)
		}
	}
	for i, call := range run.calls {
		if call.Argv[0] == "sh" {
			t.Fatalf("stage %d Argv = %v, want direct argv (a mixed form no longer reaches sh -c)", i, call.Argv)
		}
	}
}

func TestDispatchShell_MixedPipeAllReadOnlyAutoAllowedInPlan(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	run := &fakeRunner{results: []runner.RunResult{{}, {}, {}}}
	auth := &recordingPlanAuthorizer{planAuthorizer: planAuthorizer{root: mustEval(t, cwd)}}

	const input = "grep a f ; grep b f | head"
	if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell(%q) = %v, want nil (every stage is read-only, so nothing prompts)", input, err)
	}
	if len(auth.decisions) != 3 {
		t.Fatalf("authorize calls = %d, want 3 (one per staged stage)", len(auth.decisions))
	}
	for i, d := range auth.decisions {
		if d.Outcome != "once" || d.Grant != nil || d.DenyEnvelope != "" {
			t.Fatalf("decision[%d] = %+v, want a mode auto-allow with no prompt and no stored grant", i, d)
		}
	}
	if len(run.calls) != 3 {
		t.Fatalf("runner calls = %d, want 3 (every stage runs)", len(run.calls))
	}
}

func TestDispatchShell_MixedPipeUnsafeStagePromptsAlone(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{
		bySubject: map[string]authBehavior{
			"tee out": {decision: grantDecision(), prompts: true},
		},
		fallback: &authBehavior{decision: grantDecision()},
	}
	run := &fakeRunner{results: []runner.RunResult{{}, {}, {}}}

	if _, err := DispatchShell(context.Background(), "grep a f ; grep b f | tee out", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if !reflect.DeepEqual(auth.prompted, []string{"tee out"}) {
		t.Fatalf("prompted subjects = %v, want [tee out] (only the unsafe stage, not the whole command)", auth.prompted)
	}
}

func TestDispatchShell_LogicalOrReadOnlyClassifiedPerStageInPlan(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	root := mustEval(t, cwd)
	const input = "sed -n 1p a || sed -n 2p b"
	wantArgv := [][]string{{"sed", "-n", "1p", "a"}, {"sed", "-n", "2p", "b"}}

	run := &fakeRunner{results: []runner.RunResult{{ExitCode: 1}, {ExitCode: 0}}}
	auth := &recordingPlanAuthorizer{planAuthorizer: planAuthorizer{root: root}}

	if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell(%q) = %v, want nil (each read-only stage auto-allows on its own)", input, err)
	}
	if len(auth.decisions) != 2 {
		t.Fatalf("authorize calls = %d, want 2 (one per stage)", len(auth.decisions))
	}
	for i, d := range auth.decisions {
		if d.Outcome != "once" || d.Grant != nil || d.DenyEnvelope != "" {
			t.Fatalf("decision[%d] = %+v, want a mode auto-allow with no stored grant", i, d)
		}
	}
	gotArgv := make([][]string, len(run.calls))
	for i, call := range run.calls {
		gotArgv[i] = call.Argv
	}
	if !reflect.DeepEqual(gotArgv, wantArgv) {
		t.Fatalf("executed stages = %v, want %v (direct argv, no sh -c)", gotArgv, wantArgv)
	}

	canonical, err := permissions.CanonicalLiteralForm(input)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	literal, err := auth.planAuthorizer.Authorize(
		context.Background(),
		permissions.MatchRequest{Kind: "literal", Subject: canonical, PathScope: root},
		PromptDisplay{Action: ActionRunCommand, Subject: input, WholeCommand: true},
		permissions.ModeContext{Class: permissions.ClassMutating, LiteralRoute: true},
	)
	if err != nil {
		t.Fatalf("literal-route Authorize: %v", err)
	}
	if literal.DenyEnvelope == "" {
		t.Fatalf("literal-route decision = %+v, want a Plan denial (classifyLiteralCompound vetoes argument-sensitive programs)", literal)
	}
}

func TestDispatchShell_LogicalOrRoutesToStagedPerStage(t *testing.T) {
	prependFixturePrograms(t, "git")
	cases := []struct {
		input      string
		results    []runner.RunResult
		wantStages [][]string
		wantRun    [][]string
	}{
		{
			input:      "git status || echo failed",
			results:    []runner.RunResult{{ExitCode: 1}, {ExitCode: 0}},
			wantStages: [][]string{{"git", "status"}, {"echo", "failed"}},
			wantRun:    [][]string{{"git", "status"}, {"echo", "failed"}},
		},
		{
			input:      "git status || echo failed && git log",
			results:    []runner.RunResult{{ExitCode: 0}},
			wantStages: [][]string{{"git", "status"}, {"echo", "failed"}, {"git", "log"}},
			wantRun:    [][]string{{"git", "status"}, {"git", "log"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			wantScope := mustEval(t, cwd)

			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{results: tc.results}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(auth.requests) != len(tc.wantStages) {
				t.Fatalf("authorize calls = %d, want %d (per-stage direct, not one literal subject)", len(auth.requests), len(tc.wantStages))
			}
			for i, req := range auth.requests {
				wantSubject := permissions.ExactSubject(tc.wantStages[i][0], tc.wantStages[i][1:])
				if req.Kind != "direct" || req.Subject != wantSubject {
					t.Fatalf("request[%d] = %+v, want direct subject %q", i, req, wantSubject)
				}
				if !reflect.DeepEqual(req.SubjectTokens, tc.wantStages[i]) {
					t.Fatalf("request[%d].SubjectTokens = %v, want %v", i, req.SubjectTokens, tc.wantStages[i])
				}
				if req.PathScope != wantScope {
					t.Fatalf("request[%d].PathScope = %q, want %q", i, req.PathScope, wantScope)
				}
				wantOneStage(t, auth.modeCtxs[i], tc.wantStages[i])
				if auth.modeCtxs[i].LiteralRoute {
					t.Fatalf("request[%d] ModeContext.LiteralRoute = true, want false (a bare || chain classifies per direct stage)", i)
				}
			}
			gotRun := make([][]string, len(run.calls))
			for i, call := range run.calls {
				gotRun[i] = call.Argv
				if call.Cwd != wantScope {
					t.Fatalf("stage %d Cwd = %q, want the shared resolved scope %q", i, call.Cwd, wantScope)
				}
			}
			if !reflect.DeepEqual(gotRun, tc.wantRun) {
				t.Fatalf("executed stages = %v, want %v (each stage run directly, never through sh -c)", gotRun, tc.wantRun)
			}
		})
	}
}

func TestDispatchShell_ExcludedShapesCannotBorrowDirectGrant(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		literal bool
	}{
		{"wrapper", `sh -c "prdtasks create g x && prdtasks create f y"`, true},
		{"wrapper with logical or", `sh -c "prdtasks create g x || prdtasks create f y"`, true},
		{"redirection", "prdtasks create g x && prdtasks create f y > out.txt", true},
		{"redirection with logical or", "prdtasks create g x || prdtasks create f y > out.txt", true},
		{"backgrounding", "prdtasks create g x & prdtasks create f y", true},
		{"env assignment stage", "FOO=bar prdtasks create g x && prdtasks create f y", true},
		{"env assignment stage with logical or", "FOO=bar prdtasks create g x || prdtasks create f y", true},
		{"pipe mixed with a wrapper stage", "prdtasks create g x | sh -c tee && prdtasks create f y", true},
		{"pipe mixed with an env assignment stage", "FOO=bar prdtasks create g x | tee log || prdtasks create f y", true},
		{"substitution", "prdtasks create g x && prdtasks create f $(whoami)", false},
		{"trailing empty stage", "prdtasks create g x &&", true},
		{"trailing empty stage after logical or", "prdtasks create g x ||", true},
		{"leading empty stage", "; prdtasks create f y", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			wantScope := mustEval(t, cwd)

			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
				"prdtasks create g x": {decision: grantDecision()},
				"prdtasks create f y": {decision: grantDecision()},
			}}
			var canonical string
			if tc.literal {
				var err error
				canonical, err = permissions.CanonicalLiteralForm(tc.input)
				if err != nil {
					t.Fatalf("CanonicalLiteralForm(%q): %v", tc.input, err)
				}
				auth.bySubject[canonical] = authBehavior{decision: denyDecision(`{"error":"denied"}`)}
			}
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run)
			if tc.literal {
				var denied *DeniedError
				if !errors.As(err, &denied) {
					t.Fatalf("DispatchShell error = %v, want *DeniedError", err)
				}
				if len(auth.requests) != 1 {
					t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
				}
				req := auth.requests[0]
				if req.Kind != "literal" || req.Subject != canonical || req.SubjectTokens != nil || req.PathScope != wantScope {
					t.Fatalf("request = %+v, want literal subject %q with no tokens at %q", req, canonical, wantScope)
				}
			} else {
				var unsupported *UnsupportedConstructError
				if !errors.As(err, &unsupported) {
					t.Fatalf("DispatchShell error = %v, want *UnsupportedConstructError", err)
				}
				if len(auth.requests) != 0 {
					t.Fatalf("authorize calls = %d, want 0", len(auth.requests))
				}
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %d, want 0 (an excluded shape never borrows a direct grant)", len(run.calls))
			}
		})
	}
}

func TestDispatchShell_CompoundDenialPreventsAnyExecution(t *testing.T) {
	prependFixturePrograms(t, "git")
	for _, input := range []string{
		"git status ; rm -rf x",
		"git status && rm -rf x",
		"git status && git log ; rm -rf x",
		"git status || rm -rf x",
		"git status || git log || rm -rf x",
		"git status ; git log | rm -rf x",
		"git status | head ; rm -rf x",
		"git status && rm -rf x | tee log",
	} {
		t.Run(input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			env := `{"error":"denied"}`
			auth := &fakeAuthorizer{
				bySubject: map[string]authBehavior{
					"rm -rf x": {decision: denyDecision(env), prompts: true},
				},
				fallback: &authBehavior{decision: grantDecision()},
			}
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), input, home, cwd, auth, run)
			var denied *DeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("err = %v, want *DeniedError", err)
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %d, want 0 (nothing runs when a stage is denied)", len(run.calls))
			}
		})
	}
}

func TestDispatchShell_SemicolonAuthorizesAllThenRunsInOrder(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	wantScope := mustEval(t, cwd)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"git status":      {decision: grantDecision()},
		"echo 'all done'": {decision: grantDecision()},
	}}
	run := &fakeRunner{results: []runner.RunResult{
		{Stdout: []byte("a"), ExitCode: 0},
		{Stdout: []byte("b"), ExitCode: 0},
	}}

	res, err := DispatchShell(context.Background(), `git status ; echo "all done"`, home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}

	// Both stages authorized as their own direct subject, in order, before any execution.
	wantSubjects := []string{"git status", "echo 'all done'"}
	if len(auth.requests) != 2 {
		t.Fatalf("authorize calls = %d, want 2 (per-stage, not one literal subject)", len(auth.requests))
	}
	for i, req := range auth.requests {
		if req.Kind != "direct" || req.Subject != wantSubjects[i] {
			t.Fatalf("request[%d] = %+v, want direct subject %q", i, req, wantSubjects[i])
		}
		if req.PathScope != wantScope {
			t.Fatalf("request[%d].PathScope = %q, want %q", i, req.PathScope, wantScope)
		}
	}
	wantDisplays := []PromptDisplay{
		{Action: ActionRunCommand, Subject: "git status"},
		{Action: ActionRunCommand, Subject: `echo "all done"`},
	}
	if !reflect.DeepEqual(auth.displays, wantDisplays) {
		t.Fatalf("prompt displays = %+v, want %+v", auth.displays, wantDisplays)
	}
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (each stage direct)", len(run.calls))
	}
	if !reflect.DeepEqual(run.calls[0].Argv, []string{"git", "status"}) {
		t.Fatalf("stage 1 Argv = %v, want [git status]", run.calls[0].Argv)
	}
	if !reflect.DeepEqual(run.calls[1].Argv, []string{"echo", "all done"}) {
		t.Fatalf("stage 2 Argv = %v, want [echo all done] (display quotes must not reach argv)", run.calls[1].Argv)
	}
	// Visible stdout is every executed stage concatenated in order (both go to the terminal, unlike a pipe).
	if string(res.Stdout) != "ab" {
		t.Fatalf("stdout = %q, want %q", res.Stdout, "ab")
	}
}

// commandLookupPATH points $PATH at a directory holding a single `magick` executable so the
// dispatch tests exercise a known lookup namespace rather than the host's binaries.
func commandLookupPATH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "magick")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
	t.Setenv("PATH", dir)
	return path
}

func TestDispatchShell_CommandLookupAnswersWithoutRunning(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	magick := commandLookupPATH(t)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"command -v magick": {decision: grantDecision()},
	}}
	run := &fakeRunner{}

	res, err := DispatchShell(context.Background(), "command -v magick", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %+v, want none (the builtin lookup must never launch a program or a shell)", run.calls)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	got := auth.requests[0]
	if got.Kind != "direct" || !reflect.DeepEqual(got.SubjectTokens, []string{"command", "-v", "magick"}) {
		t.Fatalf("authorized subject = %q kind %q tokens %v, want the validated direct tokens", got.Subject, got.Kind, got.SubjectTokens)
	}
	if string(res.Stdout) != magick+"\n" {
		t.Fatalf("Stdout = %q, want %q", res.Stdout, magick+"\n")
	}
	if len(res.Stderr) != 0 || res.ExitCode != 0 {
		t.Fatalf("result = %+v, want empty stderr and exit 0", res)
	}
}

func TestDispatchShell_TypeLookupAnswersWithoutRunning(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ls"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	t.Setenv("PATH", dir)
	ls, err := exec.LookPath("ls")
	if err != nil {
		t.Fatalf("exec.LookPath(ls): %v", err)
	}

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"type ls": {decision: grantDecision()},
	}}
	run := &fakeRunner{}

	res, err := DispatchShell(context.Background(), "type ls", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %+v, want none", run.calls)
	}
	if string(res.Stdout) != ls+"\n" {
		t.Fatalf("Stdout = %q, want %q", res.Stdout, ls+"\n")
	}
	if len(res.Stderr) != 0 || res.ExitCode != 0 {
		t.Fatalf("result = %+v, want empty stderr and exit 0", res)
	}
}

func TestDispatchShell_CommandLookupInPipelineFeedsNextStage(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	magick := commandLookupPATH(t)
	writeFixtureProgram(t, filepath.Dir(magick), "wc", "exit 0")

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("counted"), ExitCode: 0}}}

	res, err := DispatchShell(context.Background(), "command -v magick | wc -c", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 1 || !reflect.DeepEqual(run.calls[0].Argv, []string{"wc", "-c"}) {
		t.Fatalf("runner calls = %+v, want only the wc stage", run.calls)
	}
	if string(run.calls[0].Stdin) != magick+"\n" {
		t.Fatalf("wc stdin = %q, want the captured lookup result %q", run.calls[0].Stdin, magick+"\n")
	}
	if string(res.Stdout) != "counted" {
		t.Fatalf("Stdout = %q, want the final stage's output", res.Stdout)
	}
}

func TestDispatchShell_StagedCommandLookupAnswersWithoutRunning(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		results  []runner.RunResult
		wantArgv [][]string
		wantTail string
	}{
		{
			name:     "&& successor runs after the lookup's zero exit",
			input:    "command -v magick && git status",
			results:  []runner.RunResult{{Stdout: []byte("clean"), ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}},
			wantTail: "clean",
		},
		{
			name:     "; successor runs after the lookup",
			input:    "command -v magick ; git status",
			results:  []runner.RunResult{{Stdout: []byte("clean"), ExitCode: 0}},
			wantArgv: [][]string{{"git", "status"}},
			wantTail: "clean",
		},
		{
			name:     "|| successor is skipped after the lookup's zero exit",
			input:    "command -v magick || git status",
			wantArgv: [][]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			magick := commandLookupPATH(t)
			writeFixtureProgram(t, filepath.Dir(magick), "git", "exit 0")
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{results: tc.results}

			res, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run)
			if err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			gotArgv := make([][]string, len(run.calls))
			for i, call := range run.calls {
				gotArgv[i] = call.Argv
			}
			if !reflect.DeepEqual(gotArgv, tc.wantArgv) {
				t.Fatalf("executed stages = %v, want %v (the lookup stage never reaches the runner)", gotArgv, tc.wantArgv)
			}
			if !reflect.DeepEqual(auth.requests[0].SubjectTokens, []string{"command", "-v", "magick"}) {
				t.Fatalf("authorized subject tokens = %v, want the validated lookup tokens", auth.requests[0].SubjectTokens)
			}
			if want := magick + "\n" + tc.wantTail; string(res.Stdout) != want {
				t.Fatalf("Stdout = %q, want %q", res.Stdout, want)
			}
			if res.ExitCode != 0 {
				t.Fatalf("exit code = %d, want 0", res.ExitCode)
			}
		})
	}
}

func TestDispatchShell_CommandLookupMissAndWrapperFormsRunThroughTheShell(t *testing.T) {
	for _, input := range []string{"command -v missingprog", "command -V magick", `sh -c "command -v magick"`} {
		t.Run(input, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			commandLookupPATH(t)
			canonical, err := permissions.CanonicalLiteralForm(input)
			if err != nil {
				t.Fatalf("CanonicalLiteralForm: %v", err)
			}
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
				canonical: {decision: permissions.Decision{Outcome: "once"}, prompts: true},
			}}
			run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("shell-output"), ExitCode: 0}}}

			res, err := DispatchShell(context.Background(), input, home, cwd, auth, run)
			if err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if auth.requests[0].Kind != "literal" || len(auth.prompted) != 1 {
				t.Fatalf("%q authorized as %+v with %d prompts, want one literal-subject prompt", input, auth.requests[0], len(auth.prompted))
			}
			if len(run.calls) != 1 || !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", input}) {
				t.Fatalf("runner calls = %+v, want the verbatim command through sh -c", run.calls)
			}
			if string(res.Stdout) != "shell-output" {
				t.Fatalf("Stdout = %q, want the shell's own output", res.Stdout)
			}
		})
	}
}

func TestDispatchShell_WrapperFormRoutesToLiteralDistinctSubject(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	wantScope := mustEval(t, cwd)

	input := `sh -c "git status"`
	canonical, err := permissions.CanonicalLiteralForm(input)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	if canonical == "git status" {
		t.Fatalf("literal subject %q must be distinct from the direct subject \"git status\"", canonical)
	}

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		canonical: {decision: permissions.Decision{Outcome: "once"}, prompts: true},
	}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("ok"), ExitCode: 0}}}

	if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	got := auth.requests[0]
	if got.Kind != "literal" {
		t.Fatalf("Kind = %q, want literal", got.Kind)
	}
	if got.Subject != canonical {
		t.Fatalf("Subject = %q, want %q", got.Subject, canonical)
	}
	if got.SubjectTokens != nil {
		t.Fatalf("SubjectTokens = %v, want nil for a literal subject", got.SubjectTokens)
	}
	if got.PathScope != wantScope {
		t.Fatalf("PathScope = %q, want %q", got.PathScope, wantScope)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	if !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", input}) {
		t.Fatalf("Argv = %v, want [sh -c %q]", run.calls[0].Argv, input)
	}
	if run.calls[0].Cwd != wantScope {
		t.Fatalf("RunSpec.Cwd = %q, want %q", run.calls[0].Cwd, wantScope)
	}
}

func TestDispatchShell_RedirectionRoutesToLiteralAndRunsVerbatim(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	wantScope := mustEval(t, cwd)

	input := "git status > out.txt"
	canonical, err := permissions.CanonicalLiteralForm(input)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		canonical: {decision: permissions.Decision{Outcome: "once"}, prompts: true},
	}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("done"), ExitCode: 0}}}

	res, err := DispatchShell(context.Background(), input, home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if auth.requests[0].Kind != "literal" || auth.requests[0].Subject != canonical {
		t.Fatalf("redirection must route to literal subject %q, got kind %q subject %q", canonical, auth.requests[0].Kind, auth.requests[0].Subject)
	}
	if !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", input}) {
		t.Fatalf("Argv = %v, want [sh -c %q] (exact prefix-stripped command)", run.calls[0].Argv, input)
	}
	if run.calls[0].Cwd != wantScope {
		t.Fatalf("RunSpec.Cwd = %q, want %q", run.calls[0].Cwd, wantScope)
	}
	if string(res.Stdout) != "done" {
		t.Fatalf("Stdout = %q, want done", res.Stdout)
	}
}

func TestDispatchShell_LiteralDeniedDoesNotRun(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	input := "git status > out"
	canonical, err := permissions.CanonicalLiteralForm(input)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	env := permissions.BuildDenyEnvelope("denied")
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		canonical: {decision: denyDecision(env), prompts: true},
	}}
	run := &fakeRunner{}

	_, err = DispatchShell(context.Background(), input, home, cwd, auth, run)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0 (denied literal must not run)", len(run.calls))
	}
}

func TestDispatchShell_DirectAndStagedSpecsCarryStageAuthority(t *testing.T) {
	prependFixturePrograms(t, "curl", "ls")
	cases := []struct {
		input string
		want  []string
	}{
		{input: "curl https://example.test", want: []string{"network access"}},
		{input: "ls", want: []string{""}},
		{input: "ls && curl https://example.test", want: []string{"", "network access"}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}
			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), t.TempDir(), auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			got := make([]string, len(run.calls))
			for i, call := range run.calls {
				got[i] = call.ExceptionalAuthority
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ExceptionalAuthority per spec = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDispatchShell_NetworkAuthorityMatchesEnforce(t *testing.T) {
	prependFixturePrograms(t, "curl")
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{}
	if _, err := DispatchShell(context.Background(), "curl https://example.test", t.TempDir(), t.TempDir(), auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 1 || run.calls[0].ExceptionalAuthority != enforce.NetworkAccessAuthority {
		t.Fatalf("specs = %+v, want one with ExceptionalAuthority %q", run.calls, enforce.NetworkAccessAuthority)
	}
}

func TestDispatchShell_LiteralSpecCarriesSharedClassifierAuthority(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{input: `sh -c 'curl https://example.test'`, want: "network access"},
		{input: `sh -c 'ls'`, want: ""},
		{input: `sh -c 'if true; then curl x; fi'`, want: ""},
		{input: `curl https://example.test > out`, want: ""},
		{input: `sh -c 'curl https://example.test > out'`, want: ""},
		{input: `sh -c 'rm x && curl https://example.test'`, want: "network access"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cwd := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: permissions.Decision{Outcome: "once"}}}
			run := &fakeRunner{}
			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(auth.requests) != 1 || auth.requests[0].Kind != "literal" {
				t.Fatalf("requests = %+v, want one literal request", auth.requests)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			spec := run.calls[0]
			classified, _ := permissions.ClassifyExceptional(auth.requests[0], auth.modeCtxs[0])
			if spec.ExceptionalAuthority != tc.want || spec.ExceptionalAuthority != classified {
				t.Fatalf("ExceptionalAuthority = %q, want %q (shared classifier %q)", spec.ExceptionalAuthority, tc.want, classified)
			}
			if !reflect.DeepEqual(spec.Argv, []string{"sh", "-c", tc.input}) || spec.Cwd != mustEval(t, cwd) || spec.Stdin != nil || spec.Assignments != nil {
				t.Fatalf("spec = %+v, want only ExceptionalAuthority added to the literal spec", spec)
			}
		})
	}
}

func TestDispatchShell_PipelineChainsAndAggregates(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	cwd := t.TempDir()
	home := t.TempDir()
	wantScope := mustEval(t, cwd)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"alpha": {decision: grantDecision()},
		"beta":  {decision: grantDecision()},
	}}
	run := &fakeRunner{results: []runner.RunResult{
		{Stdout: []byte("from-alpha"), Stderr: []byte("e1"), ExitCode: 0, Duration: 2 * time.Millisecond},
		{Stdout: []byte("from-beta"), Stderr: []byte("e2"), ExitCode: 3, Duration: 4 * time.Millisecond},
	}}

	res, err := DispatchShell(context.Background(), "alpha | beta", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(run.calls))
	}
	if run.calls[0].Stdin != nil {
		t.Fatalf("stage 1 Stdin = %q, want nil", run.calls[0].Stdin)
	}
	if string(run.calls[1].Stdin) != "from-alpha" {
		t.Fatalf("stage 2 Stdin = %q, want from-alpha (chained from stage 1 stdout)", run.calls[1].Stdin)
	}
	if !reflect.DeepEqual(run.calls[0].Argv, []string{"alpha"}) || !reflect.DeepEqual(run.calls[1].Argv, []string{"beta"}) {
		t.Fatalf("stage argvs = %v / %v, want [alpha] / [beta]", run.calls[0].Argv, run.calls[1].Argv)
	}
	if run.calls[0].Cwd != wantScope || run.calls[1].Cwd != wantScope {
		t.Fatalf("stage cwds = %q / %q, want both %q", run.calls[0].Cwd, run.calls[1].Cwd, wantScope)
	}
	if run.calls[0].InvocationID == run.calls[1].InvocationID || run.calls[0].InvocationID == "" {
		t.Fatalf("stages must carry distinct non-empty invocation ids, got %q / %q", run.calls[0].InvocationID, run.calls[1].InvocationID)
	}
	// Final stage stdout/exit, stderr concatenated in order, durations summed.
	if string(res.Stdout) != "from-beta" {
		t.Fatalf("Stdout = %q, want from-beta", res.Stdout)
	}
	if res.ExitCode != 3 {
		t.Fatalf("ExitCode = %d, want 3 (final stage)", res.ExitCode)
	}
	if string(res.Stderr) != "e1e2" {
		t.Fatalf("Stderr = %q, want e1e2 (every executed stage in order)", res.Stderr)
	}
	if res.Duration != 6*time.Millisecond {
		t.Fatalf("Duration = %v, want 6ms", res.Duration)
	}
}

// TestDispatchShell_DirectStageAppliesEnvAssignments proves that a direct stage's leading
// KEY=VALUE assignments stay out of the command tokens but are part of the request identity and are
// still applied to the runner's environment. The reviewer's `FOO=bar env` example actually routes to
// literal matching because `env` is a wrapper, so a non-wrapper program is used to exercise the
// direct path the bug lived on.
func TestDispatchShell_DirectStageAppliesEnvAssignments(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()

	envLs := envRequestSubject(t, []string{"FOO=bar"}, "ls")
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		envLs: {decision: grantDecision()},
	}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("out"), ExitCode: 0}}}

	if _, err := DispatchShell(context.Background(), "FOO=bar ls", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	got := auth.requests[0]
	if got.Kind != "direct" || got.Subject != envLs {
		t.Fatalf("authorization subject = %q/%q, want direct/%q (the assignment is part of the request identity)", got.Kind, got.Subject, envLs)
	}
	if !reflect.DeepEqual(got.Assignments, []string{"FOO=bar"}) {
		t.Fatalf("Assignments = %v, want [FOO=bar]", got.Assignments)
	}
	if !reflect.DeepEqual(got.SubjectTokens, []string{"ls"}) {
		t.Fatalf("SubjectTokens = %v, want [ls]", got.SubjectTokens)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	call := run.calls[0]
	if !reflect.DeepEqual(call.Argv, []string{"ls"}) {
		t.Fatalf("Argv = %v, want [ls]", call.Argv)
	}
	if !envContains(call.Env, "FOO=bar") {
		t.Fatalf("RunSpec.Env = %v, want it to contain FOO=bar", call.Env)
	}
	if len(call.Env) <= 1 {
		t.Fatalf("RunSpec.Env = %v, want the inherited environment plus FOO=bar, not the assignment alone", call.Env)
	}
	wantDisplay := PromptDisplay{Action: ActionRunCommand, Subject: "FOO=bar ls"}
	if !reflect.DeepEqual(auth.displays[0], wantDisplay) {
		t.Fatalf("prompt display = %+v, want %+v (the prompt shows the full original text)", auth.displays[0], wantDisplay)
	}
}

func TestDispatchShell_DirectStageRecordsAssignments(t *testing.T) {
	ls, err := exec.LookPath("ls")
	if err != nil {
		t.Skipf("ls not available: %v", err)
	}
	lsDir := filepath.Dir(ls)
	cases := []struct {
		input   string
		want    []string
		wantEnv []string
	}{
		{"FOO=bar ls", []string{"FOO=bar"}, execEnvWithout([]string{"FOO=bar"}, ripgrepConfigEnv)},
		{"env -i PATH=" + lsDir + " A=1 ls", []string{"PATH=" + lsDir, "A=1"}, []string{"PATH=" + lsDir, "A=1"}},
		{"ls", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}
			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), t.TempDir(), auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			call := run.calls[0]
			if !reflect.DeepEqual(call.Assignments, tc.want) {
				t.Fatalf("Assignments = %#v, want %#v", call.Assignments, tc.want)
			}
			if !reflect.DeepEqual(call.Env, tc.wantEnv) {
				t.Fatalf("Env = %v, want %v", call.Env, tc.wantEnv)
			}
		})
	}
}

// A whitespace-bearing assignment value and a quoted command argument must not let two different
// commands share one request identity, since that identity is the turn-cache and in-flight key.
func TestDispatchShell_AssignmentRequestIdentitiesStayDistinct(t *testing.T) {
	prependFixturePrograms(t, "myprog", "a")
	cwd := t.TempDir()
	home := t.TempDir()

	seen := map[string]string{}
	for _, input := range []string{
		`FOO=x myprog 'a b'`,
		`FOO=x myprog a b`,
		`FOO='x myprog' a b`,
		`myprog a b`,
	} {
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		run := &fakeRunner{results: []runner.RunResult{{}}}
		if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell(%q): %v", input, err)
		}
		subject := auth.requests[0].Subject
		if other, dup := seen[subject]; dup {
			t.Fatalf("%q and %q share the request identity %q", other, input, subject)
		}
		seen[subject] = input
	}
}

// TestDispatchShell_HomeArgsExpandOnlyForExecution proves a bare leading `~` / `$HOME` path argument
// expands against the resolved home directory in the runner argv, while the authorization subject and
// subject tokens stay canonical and unexpanded (the grant/prompt still shows the literal `~`/`$HOME`).
func TestDispatchShell_HomeArgsExpandOnlyForExecution(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()

	cases := []struct {
		input       string
		wantSubject string
		wantSubjTok []string
		wantArgv    []string
	}{
		{"cat ~/srht/que", "cat '~/srht/que'", []string{"cat", "~/srht/que"}, []string{"cat", home + "/srht/que"}},
		{"cat $HOME/srht/que", "cat '$HOME/srht/que'", []string{"cat", "$HOME/srht/que"}, []string{"cat", home + "/srht/que"}},
		{"ls ~", "ls '~'", []string{"ls", "~"}, []string{"ls", home}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{tc.wantSubject: {decision: grantDecision()}}}
			run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("out")}}}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			got := auth.requests[0]
			if got.Subject != tc.wantSubject {
				t.Fatalf("authorization subject = %q, want %q (must stay canonical/unexpanded)", got.Subject, tc.wantSubject)
			}
			if !reflect.DeepEqual(got.SubjectTokens, tc.wantSubjTok) {
				t.Fatalf("SubjectTokens = %v, want %v (must stay canonical/unexpanded)", got.SubjectTokens, tc.wantSubjTok)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			if !reflect.DeepEqual(run.calls[0].Argv, tc.wantArgv) {
				t.Fatalf("runner Argv = %v, want %v (bare leading ~ / $HOME expands for execution only)", run.calls[0].Argv, tc.wantArgv)
			}
		})
	}
}

// TestDispatchShell_HomeArgsQuotedRemainLiteral proves a quoted `~` / `$HOME` argument keeps its
// literal form in the runner argv — quoting suppresses the execution-only expansion — while the
// canonical subject is the quote-stripped value (matching the bare form's subject, as the shell would).
func TestDispatchShell_HomeArgsQuotedRemainLiteral(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()

	cases := []struct {
		input       string
		wantSubject string
		wantArgv    []string
	}{
		{`cat '~/srht/que'`, "cat '~/srht/que'", []string{"cat", "~/srht/que"}},
		{`cat '$HOME/srht/que'`, "cat '$HOME/srht/que'", []string{"cat", "$HOME/srht/que"}},
		{`cat "$HOME"/srht/que`, "cat '$HOME/srht/que'", []string{"cat", "$HOME/srht/que"}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{tc.wantSubject: {decision: grantDecision()}}}
			run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("out")}}}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			if !reflect.DeepEqual(run.calls[0].Argv, tc.wantArgv) {
				t.Fatalf("runner Argv = %v, want %v (quoted HOME forms stay literal in argv)", run.calls[0].Argv, tc.wantArgv)
			}
		})
	}
}

// TestDispatchShell_ModeContextCarriesStageData proves the mode-authorization context for a
// direct-pipeline shell request carries the pre-normalization stage data — including each stage's
// stripped KEY=VALUE env assignments — and supplies the conservative ClassMutating placeholder.
// Dispatch never classifies raw shell itself; permissions.Authorize reclassifies from this
// stage data via the read-only allowlist, which needs the assignments (so `LD_PRELOAD=/x/evil.so ls`
// cannot pass an `ls` allowlist).
func TestDispatchShell_ModeContextCarriesStageData(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		envRequestSubject(t, []string{"FOO=bar"}, "ls"): {decision: grantDecision()},
	}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("out")}}}

	if _, err := DispatchShell(context.Background(), "FOO=bar ls", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.modeCtxs) != 1 {
		t.Fatalf("mode contexts = %d, want 1", len(auth.modeCtxs))
	}
	mc := auth.modeCtxs[0]
	if mc.Class != permissions.ClassMutating {
		t.Fatalf("operation class = %q, want mutating (dispatch supplies a conservative placeholder; Authorize reclassifies)", mc.Class)
	}
	if mc.LiteralRoute {
		t.Fatalf("LiteralRoute = true, want false for a direct pipeline")
	}
	if len(mc.Stages) != 1 {
		t.Fatalf("Stages = %+v, want exactly one direct stage", mc.Stages)
	}
	if !reflect.DeepEqual(mc.Stages[0].Assignments, []string{"FOO=bar"}) {
		t.Fatalf("stage Assignments = %v, want [FOO=bar] (the env-assignment data the read-only classifier needs)", mc.Stages[0].Assignments)
	}
}

// TestDispatchShell_ModeContextLiteralRouteIsMutating proves a literal/wrapper/redirection shell
// request reports LiteralRoute on its mode context and is classified mutating (such routes
// are never read-only).
func TestDispatchShell_ModeContextLiteralRouteIsMutating(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()

	canonical, err := permissions.CanonicalLiteralForm(`sh -c "echo hi"`)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{canonical: {decision: grantDecision()}}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("hi")}}}

	if _, err := DispatchShell(context.Background(), `sh -c "echo hi"`, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	mc := auth.modeCtxs[0]
	if !mc.LiteralRoute || mc.Class != permissions.ClassMutating {
		t.Fatalf("mode context = %+v, want LiteralRoute set and mutating class", mc)
	}
	if mc.Stages != nil {
		t.Fatalf("Stages = %+v, want nil on the literal route", mc.Stages)
	}
}

// TestDispatchShell_PipelineStagesApplyPerStageEnv proves env assignments are tracked per stage: an
// assignment on one stage is applied to that stage and never leaks onto a stage without one.
func TestDispatchShell_PipelineStagesApplyPerStageEnv(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	cwd := t.TempDir()
	home := t.TempDir()

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		envRequestSubject(t, []string{"FOO=bar"}, "alpha"): {decision: grantDecision()},
		"beta": {decision: grantDecision()},
	}}
	run := &fakeRunner{results: []runner.RunResult{
		{Stdout: []byte("a"), ExitCode: 0},
		{Stdout: []byte("b"), ExitCode: 0},
	}}

	if _, err := DispatchShell(context.Background(), "FOO=bar alpha | beta", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(run.calls))
	}
	if !envContains(run.calls[0].Env, "FOO=bar") {
		t.Fatalf("stage 1 Env = %v, want it to contain FOO=bar", run.calls[0].Env)
	}
	if run.calls[1].Env != nil {
		t.Fatalf("stage 2 Env = %v, want nil (no assignment on this stage; inherit parent)", run.calls[1].Env)
	}
}

func TestDispatchShell_RunnerOutcomesAreResultsNotErrors(t *testing.T) {
	cases := map[string]runner.RunResult{
		"non-zero exit":  {ExitCode: 1, Stderr: []byte("boom")},
		"launch failure": {ExitCode: -1},
	}
	for name, rr := range cases {
		t.Run(name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
				"false": {decision: grantDecision()},
			}}
			run := &fakeRunner{results: []runner.RunResult{rr}}

			res, err := DispatchShell(context.Background(), "false", home, cwd, auth, run)
			if err != nil {
				t.Fatalf("%s must be a result-level outcome, not a dispatch error: %v", name, err)
			}
			if res.ExitCode != rr.ExitCode {
				t.Fatalf("ExitCode = %d, want %d", res.ExitCode, rr.ExitCode)
			}
		})
	}
}

// TestDispatchShell_NoLeadingStageAuthorization guards the failure mode where a tricky input is
// authorized/run on its leading word or stage. Each case must end in denial or
// unsupported_shell_construct, never a run. The cd-prefix and pipe cases also assert the subject and
// scope the authorizer actually saw, proving the remainder/trailing segment is what gets checked.
func TestDispatchShell_NoLeadingStageAuthorization(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	cdTarget := mkdir(t, filepath.Join(cwd, "work"))
	denyEnv := permissions.BuildDenyEnvelope("blocked")

	denyAll := func() *fakeAuthorizer {
		return &fakeAuthorizer{
			bySubject: map[string]authBehavior{},
			fallback:  &authBehavior{decision: denyDecision(denyEnv), prompts: true},
		}
	}

	t.Run("stripped cd-prefix authorizes the remainder against the cd target", func(t *testing.T) {
		auth := denyAll()
		run := &fakeRunner{}
		_, err := DispatchShell(context.Background(), "cd "+cdTarget+" && rm secret", home, cwd, auth, run)
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v, want *DeniedError", err)
		}
		if len(run.calls) != 0 {
			t.Fatalf("runner calls = %d, want 0", len(run.calls))
		}
		if auth.requests[0].Subject != "rm secret" {
			t.Fatalf("authorized subject = %q, want \"rm secret\" (cd prefix must not become the subject)", auth.requests[0].Subject)
		}
		if want := mustEval(t, cdTarget); auth.requests[0].PathScope != want {
			t.Fatalf("PathScope = %q, want %q (the cd target, not process cwd)", auth.requests[0].PathScope, want)
		}
	})

	t.Run("quoted command word still authorizes the canonical subject", func(t *testing.T) {
		auth := denyAll()
		run := &fakeRunner{}
		_, err := DispatchShell(context.Background(), `"rm" secret`, home, cwd, auth, run)
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v, want *DeniedError", err)
		}
		if len(run.calls) != 0 {
			t.Fatalf("runner calls = %d, want 0", len(run.calls))
		}
		if auth.requests[0].Subject != "rm secret" {
			t.Fatalf("subject = %q, want \"rm secret\"", auth.requests[0].Subject)
		}
	})

	t.Run("escaped command word still authorizes the canonical subject", func(t *testing.T) {
		auth := denyAll()
		run := &fakeRunner{}
		_, err := DispatchShell(context.Background(), `r\m secret`, home, cwd, auth, run)
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v, want *DeniedError", err)
		}
		if auth.requests[0].Subject != "rm secret" {
			t.Fatalf("subject = %q, want \"rm secret\"", auth.requests[0].Subject)
		}
	})

	t.Run("command substitution is an unsupported construct", func(t *testing.T) {
		auth := denyAll()
		run := &fakeRunner{}
		_, err := DispatchShell(context.Background(), "rm $(echo secret)", home, cwd, auth, run)
		var ue *UnsupportedConstructError
		if !errors.As(err, &ue) {
			t.Fatalf("error = %v, want *UnsupportedConstructError", err)
		}
		if len(auth.requests) != 0 || len(run.calls) != 0 {
			t.Fatalf("authorize=%d run=%d, want 0/0", len(auth.requests), len(run.calls))
		}
	})

	t.Run("embedded pipe scans the trailing segment", func(t *testing.T) {
		// Leading stage is granted; the trailing segment after the bare pipe is denied. A dispatcher
		// that authorized on the leading stage would run; this must deny on the trailing stage.
		auth := &fakeAuthorizer{
			bySubject: map[string]authBehavior{"echo hi": {decision: grantDecision()}},
			fallback:  &authBehavior{decision: denyDecision(denyEnv), prompts: true},
		}
		run := &fakeRunner{}
		_, err := DispatchShell(context.Background(), "echo hi | rm secret", home, cwd, auth, run)
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Fatalf("error = %v, want *DeniedError", err)
		}
		if len(run.calls) != 0 {
			t.Fatalf("runner calls = %d, want 0 (trailing-stage denial must block the whole pipeline)", len(run.calls))
		}
		if len(auth.requests) != 2 || auth.requests[1].Subject != "rm secret" {
			t.Fatalf("trailing stage not scanned: requests = %v", auth.requests)
		}
	})
}

// TestDispatchShell_CdPrefixDirectRunsInResolvedScope proves the single scope resolved from a
// `cd <path> && ...` prefix is reused for BOTH authorization and execution on the direct route: an
// authorized `cd <target> && git status` authorizes against the cd target and runs there too, not in
// the process cwd. The denied counterpart in TestDispatchShell_NoLeadingStageAuthorization never
// reaches the runner, so this is the only test that pins RunSpec.Cwd to the cd target for a direct
// command (scope alignment).
func TestDispatchShell_CdPrefixDirectRunsInResolvedScope(t *testing.T) {
	prependFixturePrograms(t, "git")
	cwd := t.TempDir()
	home := t.TempDir()
	cdTarget := mkdir(t, filepath.Join(cwd, "work"))
	wantScope := mustEval(t, cdTarget)

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"git status": {decision: grantDecision()},
	}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("clean\n"), ExitCode: 0}}}

	if _, err := DispatchShell(context.Background(), "cd "+cdTarget+" && git status", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	if got := auth.requests[0]; got.Subject != "git status" || got.PathScope != wantScope {
		t.Fatalf("authorize subject/scope = %q/%q, want \"git status\"/%q (cd target)", got.Subject, got.PathScope, wantScope)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	if run.calls[0].Cwd != wantScope {
		t.Fatalf("RunSpec.Cwd = %q, want %q (execution must run in the same resolved cd target it authorized)", run.calls[0].Cwd, wantScope)
	}
}

// TestDispatchShell_CdPrefixLiteralRunsInResolvedScope is the literal-route counterpart: a
// `cd <target> && git status > out.txt` (redirection routes to literal) resolves the cd target once
// and reuses it for the literal subject's authorization AND the `sh -c` execution. Without this, the
// literal route could regress to authorizing the cd target while running in the process cwd
// (scope alignment).
func TestDispatchShell_CdPrefixLiteralRunsInResolvedScope(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	cdTarget := mkdir(t, filepath.Join(cwd, "work"))
	wantScope := mustEval(t, cdTarget)

	literalInput := "git status > out.txt"
	canonical, err := permissions.CanonicalLiteralForm(literalInput)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		canonical: {decision: permissions.Decision{Outcome: "once"}, prompts: true},
	}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("done"), ExitCode: 0}}}

	if _, err := DispatchShell(context.Background(), "cd "+cdTarget+" && "+literalInput, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
	if got := auth.requests[0]; got.Kind != "literal" || got.Subject != canonical || got.PathScope != wantScope {
		t.Fatalf("authorize kind/subject/scope = %q/%q/%q, want literal/%q/%q (cd target)", got.Kind, got.Subject, got.PathScope, canonical, wantScope)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	if !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", literalInput}) {
		t.Fatalf("Argv = %v, want [sh -c %q] (exact prefix-stripped command)", run.calls[0].Argv, literalInput)
	}
	if run.calls[0].Cwd != wantScope {
		t.Fatalf("RunSpec.Cwd = %q, want %q (execution must run in the same resolved cd target it authorized)", run.calls[0].Cwd, wantScope)
	}
}

// autoAllow models a stage the read-only classifier auto-allows: a non-deny decision with no
// modeled prompt (mode_auto "once" in production). A mutating stage instead prompts (prompts: true)
// or is denied.
func autoAllow() authBehavior {
	return authBehavior{decision: permissions.Decision{Outcome: "once"}}
}

func wantOneStage(t *testing.T, mc permissions.ModeContext, wantTokens []string) {
	t.Helper()
	if len(mc.Stages) != 1 {
		t.Fatalf("per-stage ModeContext.Stages = %+v, want exactly one stage %v", mc.Stages, wantTokens)
	}
	if !reflect.DeepEqual(mc.Stages[0].Tokens, wantTokens) {
		t.Fatalf("per-stage ModeContext.Stages[0].Tokens = %v, want %v", mc.Stages[0].Tokens, wantTokens)
	}
}

// TestDispatchDirect_PerStageReadOnly proves the per-stage posture change: in a mixed direct pipeline,
// each Authorize call receives a ModeContext scoped to its own single stage, so an independently
// read-only stage (grep/head) auto-allows while a non-read-only stage (find, deliberately excluded
// from the allowlist) prompts. The observed `hg cat … | tail` shape is covered as a subtest where,
// with read-only VCS subcommands classified read-only, both stages auto-allow and nothing prompts.
func TestDispatchDirect_PerStageReadOnly(t *testing.T) {
	prependFixturePrograms(t, "hg")
	cwd := t.TempDir()
	home := t.TempDir()

	t.Run("find | grep | head — only find prompts, per-stage context each", func(t *testing.T) {
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
			"find tasks -name x": {decision: grantDecision(), prompts: true}, // not allowlisted -> mutating -> prompts
			"grep foo":           autoAllow(),                                // read-only -> auto-allow
			"head":               autoAllow(),                                // read-only -> auto-allow
		}}
		run := &fakeRunner{results: []runner.RunResult{{}, {}, {}}}

		if _, err := DispatchShell(context.Background(), "find tasks -name x | grep foo | head", home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		if !reflect.DeepEqual(auth.prompted, []string{"find tasks -name x"}) {
			t.Fatalf("prompted = %v, want only [find tasks -name x] (read-only siblings auto-allow)", auth.prompted)
		}
		if len(auth.modeCtxs) != 3 {
			t.Fatalf("authorize calls = %d, want 3", len(auth.modeCtxs))
		}
		wantOneStage(t, auth.modeCtxs[0], []string{"find", "tasks", "-name", "x"})
		wantOneStage(t, auth.modeCtxs[1], []string{"grep", "foo"})
		wantOneStage(t, auth.modeCtxs[2], []string{"head"})
		if len(run.calls) != 3 {
			t.Fatalf("runner calls = %d, want 3 (all authorized)", len(run.calls))
		}
	})

	t.Run("hg cat … | tail — both auto-allow, zero prompts (post-g1060)", func(t *testing.T) {
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
			"hg cat contributing/README.md": autoAllow(), // read-only VCS subcommand
			"tail -15":                      autoAllow(), // read-only
		}}
		run := &fakeRunner{results: []runner.RunResult{{}, {}}}

		if _, err := DispatchShell(context.Background(), "hg cat contributing/README.md | tail -15", home, cwd, auth, run); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		if len(auth.prompted) != 0 {
			t.Fatalf("prompted = %v, want none (both stages read-only after g1060)", auth.prompted)
		}
		wantOneStage(t, auth.modeCtxs[0], []string{"hg", "cat", "contributing/README.md"})
		wantOneStage(t, auth.modeCtxs[1], []string{"tail", "-15"})
	})
}

func TestDispatchDirect_EnvAssignmentStageStaysMutating(t *testing.T) {
	prependFixturePrograms(t, "hg")
	cwd := t.TempDir()
	home := t.TempDir()

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"hg log": autoAllow(), // read-only VCS subcommand
		envRequestSubject(t, []string{"FOO=bar"}, "tail"): {decision: grantDecision(), prompts: true},
	}}
	run := &fakeRunner{results: []runner.RunResult{{}, {}}}

	if _, err := DispatchShell(context.Background(), "hg log | FOO=bar tail", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.modeCtxs) != 2 {
		t.Fatalf("authorize calls = %d, want 2", len(auth.modeCtxs))
	}
	// stage 1's per-stage context carries no assignments; stage 2's carries the stripped FOO=bar the
	// classifier needs to keep the stage mutating.
	if len(auth.modeCtxs[0].Stages[0].Assignments) != 0 {
		t.Fatalf("stage 1 Assignments = %v, want none", auth.modeCtxs[0].Stages[0].Assignments)
	}
	wantOneStage(t, auth.modeCtxs[1], []string{"tail"})
	if !reflect.DeepEqual(auth.modeCtxs[1].Stages[0].Assignments, []string{"FOO=bar"}) {
		t.Fatalf("stage 2 Assignments = %v, want [FOO=bar] (per-stage classification must keep the env-assignment guard)", auth.modeCtxs[1].Stages[0].Assignments)
	}
	wantIdentity := envRequestSubject(t, []string{"FOO=bar"}, "tail")
	if auth.requests[1].Subject != wantIdentity {
		t.Fatalf("stage 2 matched subject = %q, want %q (the assignment is part of the request identity)", auth.requests[1].Subject, wantIdentity)
	}
	if !reflect.DeepEqual(auth.requests[1].SubjectTokens, []string{"tail"}) {
		t.Fatalf("stage 2 SubjectTokens = %v, want [tail] (the prompt program stays command-only)", auth.requests[1].SubjectTokens)
	}
}

// TestDispatchDirect_DenyStopsPipeline_NothingRuns proves authorize-all-before-run survives the
// per-stage change: an earlier stage being auto-allowed (no prompt) must not let the pipeline run
// when a later stage is denied. The denied stage returns DeniedError from Pass 1 and no stage
// executes. Dispatch handles a deny decision identically whether it came from a Build prompt-deny or
// a Plan-mode mutating deny (Plan posture itself is tested in internal/permissions), so this also
// covers "Plan denies the mutating stage and read-only siblings do not rescue the pipeline".
func TestDispatchDirect_DenyStopsPipeline_NothingRuns(t *testing.T) {
	prependFixturePrograms(t, "hg")
	cwd := t.TempDir()
	home := t.TempDir()
	env := permissions.BuildDenyEnvelope("blocked")

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"hg log": autoAllow(), // read-only earlier stage: auto-allows, no prompt
		"find x": {decision: denyDecision(env), prompts: true},
	}}
	run := &fakeRunner{}

	_, err := DispatchShell(context.Background(), "hg log | find x", home, cwd, auth, run)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0 (an auto-allowed earlier stage must not run when a later stage is denied)", len(run.calls))
	}
	if !reflect.DeepEqual(auth.prompted, []string{"find x"}) {
		t.Fatalf("prompted = %v, want only [find x] (the read-only stage auto-allowed silently)", auth.prompted)
	}
	// both stages were authorized in order before any ran, each with its own per-stage context.
	wantOneStage(t, auth.modeCtxs[0], []string{"hg", "log"})
	wantOneStage(t, auth.modeCtxs[1], []string{"find", "x"})
}

// TestDispatchDirect_AllReadOnlyUnchanged proves no regression for an all-read-only pipeline: every
// stage still auto-allows (now per-stage rather than whole-command) and the pipeline runs.
func TestDispatchDirect_AllReadOnlyUnchanged(t *testing.T) {
	prependFixturePrograms(t, "hg")
	cwd := t.TempDir()
	home := t.TempDir()

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"hg log": autoAllow(),
		"head":   autoAllow(),
	}}
	run := &fakeRunner{results: []runner.RunResult{{}, {}}}

	if _, err := DispatchShell(context.Background(), "hg log | head", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.prompted) != 0 {
		t.Fatalf("prompted = %v, want none (all stages read-only)", auth.prompted)
	}
	wantOneStage(t, auth.modeCtxs[0], []string{"hg", "log"})
	wantOneStage(t, auth.modeCtxs[1], []string{"head"})
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (all stages authorized and run)", len(run.calls))
	}
}

func TestDispatchShell_ScopeResolutionErrorReturnsBeforePrompting(t *testing.T) {
	home := t.TempDir()
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}
	run := &fakeRunner{}

	_, err := DispatchShell(context.Background(), "git status", home, missing, auth, run)
	if err == nil {
		t.Fatalf("want a scope-resolution error for a missing process cwd")
	}
	var de *DeniedError
	var ue *UnsupportedConstructError
	var mc *MalformedCommandError
	if errors.As(err, &de) || errors.As(err, &ue) || errors.As(err, &mc) {
		t.Fatalf("scope error must surface directly, got %v", err)
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0 (scope error returns before prompting)", len(auth.requests))
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0", len(run.calls))
	}
}

// fakeBatchAuthorizer is a dispatch-local stand-in for the BatchAuthorizer seam used by dispatchDirect.
// It records the batch it was handed and returns canned decisions, so a test
// can pin the seam's shape (index-aligned decisions; a deny envelope as the pipeline-deny signal)
// independently of the production authorizer.
type fakeBatchAuthorizer struct {
	decisions []permissions.Decision
	batches   [][]BatchAuthRequest
}

func (f *fakeBatchAuthorizer) AuthorizeBatch(_ context.Context, reqs []BatchAuthRequest) ([]permissions.Decision, error) {
	f.batches = append(f.batches, reqs)
	return f.decisions, nil
}

// compile-time check that the fake satisfies the seam dispatchDirect consumes.
var _ BatchAuthorizer = (*fakeBatchAuthorizer)(nil)

// TestBatchAuthorizerSeamContract documents the batched seam's contract: AuthorizeBatch takes one
// BatchAuthRequest per stage (each carrying its own MatchRequest/PromptDisplay/ModeContext) and returns
// decisions index-aligned with them, where any decision with a non-empty DenyEnvelope denies the whole
// pipeline. It pins the seam shape at the fake level; the production route (dispatchDirect calling
// AuthorizeBatch) is covered by TestDispatchDirect_UsesAuthorizeBatch.
func TestBatchAuthorizerSeamContract(t *testing.T) {
	batch := &fakeBatchAuthorizer{decisions: []permissions.Decision{
		grantDecision(),
		denyDecision(permissions.BuildDenyEnvelope("blocked")),
	}}
	reqs := []BatchAuthRequest{
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "ls -l"}, Display: PromptDisplay{Action: ActionRunCommand, Subject: "ls -l"}},
		{Req: permissions.MatchRequest{Kind: "direct", Subject: "rm x"}, Display: PromptDisplay{Action: ActionRunCommand, Subject: "rm x"}},
	}

	decs, err := batch.AuthorizeBatch(context.Background(), reqs)
	if err != nil {
		t.Fatalf("AuthorizeBatch error: %v", err)
	}
	if len(decs) != len(reqs) {
		t.Fatalf("decisions = %d, want %d (index-aligned with the stages)", len(decs), len(reqs))
	}
	if decs[0].DenyEnvelope != "" {
		t.Fatalf("stage 0 = %+v, want authorized (no deny envelope)", decs[0])
	}
	if decs[1].DenyEnvelope == "" {
		t.Fatalf("stage 1 = %+v, want a deny envelope that denies the pipeline", decs[1])
	}
	if len(batch.batches) != 1 || len(batch.batches[0]) != 2 {
		t.Fatalf("batches = %+v, want one batch of two stages", batch.batches)
	}
}

// TestDispatchDirect_UsesAuthorizeBatch proves the batched-prompt wiring: a multi-stage direct pipeline is
// authorized through AuthorizeBatch in exactly ONE batched call carrying one BatchAuthRequest per
// stage — each with its own canonical matching subject/tokens, the full pipeline text as display-only
// context, and a per-stage mode context scoped to that single stage. It replaces the removed
// per-stage Authorize loop.
func TestDispatchDirect_UsesAuthorizeBatch(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"find tasks -name 'x y'": {decision: grantDecision(), prompts: true},
		"grep foo":               autoAllow(),
	}}
	run := &fakeRunner{results: []runner.RunResult{{}, {}}}

	input := `find tasks -name "x y" | grep foo`
	if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if auth.batchCalls != 1 {
		t.Fatalf("AuthorizeBatch calls = %d, want 1 (the whole pipeline authorized in one batch)", auth.batchCalls)
	}
	got := auth.batches[0]
	if len(got) != 2 {
		t.Fatalf("batch size = %d, want 2 (one BatchAuthRequest per stage)", len(got))
	}
	wantSubjects := []string{"find tasks -name 'x y'", "grep foo"}
	wantSources := []string{`find tasks -name "x y"`, "grep foo"}
	wantTokens := [][]string{{"find", "tasks", "-name", "x y"}, {"grep", "foo"}}
	for i, r := range got {
		if r.Req.Kind != "direct" || r.Req.Subject != wantSubjects[i] {
			t.Fatalf("stage %d req = %+v, want direct/%q", i, r.Req, wantSubjects[i])
		}
		if !reflect.DeepEqual(r.Req.SubjectTokens, wantTokens[i]) {
			t.Fatalf("stage %d tokens = %v, want %v", i, r.Req.SubjectTokens, wantTokens[i])
		}
		if r.Display.Pipeline != input {
			t.Fatalf("stage %d display pipeline = %q, want the full pipeline text %q with source quoting", i, r.Display.Pipeline, input)
		}
		if r.Display.Action != ActionRunCommand || r.Display.Subject != wantSources[i] {
			t.Fatalf("stage %d display = %+v, want Run command over the source %q", i, r.Display, wantSources[i])
		}
		if len(r.ModeCtx.Stages) != 1 || !reflect.DeepEqual(r.ModeCtx.Stages[0].Tokens, wantTokens[i]) {
			t.Fatalf("stage %d ModeCtx.Stages = %+v, want exactly the one stage %v", i, r.ModeCtx.Stages, wantTokens[i])
		}
	}
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2 (all authorized, pipeline runs)", len(run.calls))
	}
	if !reflect.DeepEqual(run.calls[0].Argv, wantTokens[0]) {
		t.Fatalf("stage 0 Argv = %v, want the canonical %v (display quoting must not reach argv)", run.calls[0].Argv, wantTokens[0])
	}
}

// TestDispatchDirect_BatchedDenyStopsPipeline proves a batched deny denies the whole pipeline: any
// decision carrying a deny envelope yields *DeniedError and no stage runs, even though an earlier
// stage authorized.
func TestDispatchDirect_BatchedDenyStopsPipeline(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	env := permissions.BuildDenyEnvelope("blocked")

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		"grep foo": autoAllow(),
		"rm x":     {decision: denyDecision(env), prompts: true},
	}}
	run := &fakeRunner{}

	_, err := DispatchShell(context.Background(), "grep foo | rm x", home, cwd, auth, run)
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want *DeniedError", err)
	}
	if de.Envelope != env {
		t.Fatalf("DeniedError.Envelope = %q, want %q", de.Envelope, env)
	}
	if auth.batchCalls != 1 {
		t.Fatalf("AuthorizeBatch calls = %d, want 1", auth.batchCalls)
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0 (a batched deny runs no stage)", len(run.calls))
	}
}

func TestDispatchShell_ScriptInvocationArgvStaysLiteral(t *testing.T) {
	prependFixturePrograms(t, "bash")
	cwd := t.TempDir()
	home := t.TempDir()

	cases := []struct {
		input       string
		wantSubject string
		wantTokens  []string
		wantArgv    []string
	}{
		{
			input:       "bash script.sh *.txt",
			wantSubject: "bash script.sh '*.txt'",
			wantTokens:  []string{"bash", "script.sh", "*.txt"},
			wantArgv:    []string{"bash", "script.sh", "*.txt"},
		},
		{
			input:       "bash script.sh ~/data",
			wantSubject: "bash script.sh '~/data'",
			wantTokens:  []string{"bash", "script.sh", "~/data"},
			wantArgv:    []string{"bash", "script.sh", home + "/data"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{tc.wantSubject: {decision: grantDecision()}}}
			run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("out")}}}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			got := auth.requests[0]
			if got.Kind != "direct" || got.Subject != tc.wantSubject {
				t.Fatalf("request = kind %q subject %q, want direct %q", got.Kind, got.Subject, tc.wantSubject)
			}
			if !reflect.DeepEqual(got.SubjectTokens, tc.wantTokens) {
				t.Fatalf("SubjectTokens = %v, want %v", got.SubjectTokens, tc.wantTokens)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			if !reflect.DeepEqual(run.calls[0].Argv, tc.wantArgv) {
				t.Fatalf("runner Argv = %v, want %v (direct routing takes the stage off the outer sh -c)", run.calls[0].Argv, tc.wantArgv)
			}
		})
	}
}

func TestDispatchShell_ScriptPipelineAuthorizedAndRunAsOneLiteral(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	input := "bash process-dir.sh u.txt | tail -n 25"

	canonical, err := permissions.CanonicalLiteralForm(input)
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{
		canonical: {decision: permissions.Decision{Outcome: "once"}, prompts: true},
	}}
	run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("done")}}}

	if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorization requests = %d (%v), want one literal subject", len(auth.requests), auth.requests)
	}
	got := auth.requests[0]
	if got.Kind != "literal" || got.Subject != canonical || got.SubjectTokens != nil {
		t.Fatalf("request = kind %q subject %q tokens %v, want the single literal subject %q", got.Kind, got.Subject, got.SubjectTokens, canonical)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1 (a script pipeline executes once through sh -c)", len(run.calls))
	}
	if !reflect.DeepEqual(run.calls[0].Argv, []string{"sh", "-c", input}) {
		t.Fatalf("runner Argv = %v, want [sh -c %q]", run.calls[0].Argv, input)
	}
}

type fakePipelineRunner struct {
	fakeRunner
	preflightErr error
	preflights   [][]runner.RunSpec
	runs         [][]runner.RunSpec
	results      []runner.PipelineResult
	pipelineErr  error
}

var _ PipelineRunner = (*fakePipelineRunner)(nil)

func (f *fakePipelineRunner) PreflightPipeline(_ context.Context, specs []runner.RunSpec) error {
	f.preflights = append(f.preflights, specs)
	return f.preflightErr
}

func (f *fakePipelineRunner) Pipeline(_ context.Context, specs []runner.RunSpec) ([]runner.PipelineResult, error) {
	f.runs = append(f.runs, specs)
	return f.results, f.pipelineErr
}

func TestDispatchDirect_MultiStagePipelineStreamsThroughTheCapability(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakePipelineRunner{results: []runner.PipelineResult{
		{Stdout: []byte("from-alpha"), Stderr: []byte("err-a"), ExitCode: 0},
		{Stdout: []byte("from-beta"), Stderr: []byte("err-b"), ExitCode: 4},
	}}

	res, err := DispatchShell(context.Background(), "alpha | beta", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("Exec calls = %d, want 0 (a multi-stage pipe group runs through the pipeline capability)", len(run.calls))
	}
	if len(run.preflights) != 1 || len(run.runs) != 1 {
		t.Fatalf("preflights/runs = %d/%d, want 1/1", len(run.preflights), len(run.runs))
	}
	specs := run.runs[0]
	if len(specs) != 2 {
		t.Fatalf("pipeline specs = %d, want one per stage", len(specs))
	}
	if !reflect.DeepEqual(specs[0].Argv, []string{"alpha"}) || !reflect.DeepEqual(specs[1].Argv, []string{"beta"}) {
		t.Fatalf("specs argv = %v/%v, want [alpha]/[beta]", specs[0].Argv, specs[1].Argv)
	}
	if specs[0].InvocationID == specs[1].InvocationID {
		t.Fatalf("both stages carry invocation id %q, want one per stage", specs[0].InvocationID)
	}
	for i, spec := range specs {
		if spec.Cwd != mustEval(t, cwd) {
			t.Fatalf("stage %d Cwd = %q, want the resolved scope %q", i, spec.Cwd, mustEval(t, cwd))
		}
		if spec.Stdin != nil {
			t.Fatalf("stage %d Stdin = %q, want nil (the pipeline links stages over OS pipes, not buffered slices)", i, spec.Stdin)
		}
	}
	if string(res.Stdout) != "from-beta" {
		t.Fatalf("stdout = %q, want the final stage's stdout", res.Stdout)
	}
	if string(res.Stderr) != "err-aerr-b" {
		t.Fatalf("stderr = %q, want every stage's stderr in order", res.Stderr)
	}
	if res.ExitCode != 4 {
		t.Fatalf("exit code = %d, want the final stage's 4", res.ExitCode)
	}
	if len(run.preflights[0]) != 2 {
		t.Fatalf("preflight specs = %d, want every stage validated before anything runs", len(run.preflights[0]))
	}
}

func TestDispatchDirect_PipelineDurationIsWallClockNotStageSum(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakePipelineRunner{results: []runner.PipelineResult{
		{Duration: time.Second},
		{Duration: time.Second},
	}}

	res, err := DispatchShell(context.Background(), "alpha | beta", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if res.Duration >= 2*time.Second {
		t.Fatalf("duration = %v, want the pipeline's elapsed time, not the 2s sum of overlapping stage durations", res.Duration)
	}
}

func TestDispatchDirect_SingleStageAndBuiltinGroupsStaySequential(t *testing.T) {
	lookupPATH := filepath.Dir(commandLookupPATH(t))
	writeFixtureProgram(t, lookupPATH, "alpha", "exit 0")
	writeFixtureProgram(t, lookupPATH, "wc", "exit 0")
	cases := []struct {
		name         string
		input        string
		wantExecutes int
	}{
		{"single stage", "alpha", 1},
		{"builtin in the group", "command -v magick | wc -c", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakePipelineRunner{}
			t.Setenv("PATH", lookupPATH)

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.preflights) != 0 || len(run.runs) != 0 {
				t.Fatalf("preflights/runs = %d/%d, want 0/0 (only a multi-stage all-process group is handed to the runner)", len(run.preflights), len(run.runs))
			}
			if len(run.calls) != tc.wantExecutes {
				t.Fatalf("Exec calls = %d, want %d", len(run.calls), tc.wantExecutes)
			}
		})
	}
}

func TestDispatchDirect_UnsupportedPreflightRunsTheSequentialLoop(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakePipelineRunner{
		preflightErr: ErrPipelineUnsupported,
		fakeRunner:   fakeRunner{results: []runner.RunResult{{Stdout: []byte("from-alpha")}, {Stdout: []byte("from-beta")}}},
	}

	res, err := DispatchShell(context.Background(), "alpha | beta", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.runs) != 0 {
		t.Fatalf("pipeline runs = %d, want 0 after an unsupported preflight", len(run.runs))
	}
	if len(run.calls) != 2 {
		t.Fatalf("Exec calls = %d, want 2 (the sequential loop runs each stage exactly once)", len(run.calls))
	}
	if run.calls[0].Stdin != nil {
		t.Fatalf("stage 0 Stdin = %q, want nil", run.calls[0].Stdin)
	}
	if string(run.calls[1].Stdin) != "from-alpha" {
		t.Fatalf("stage 1 Stdin = %q, want the upstream stdout buffered into it", run.calls[1].Stdin)
	}
	if string(res.Stdout) != "from-beta" {
		t.Fatalf("stdout = %q, want the final stage's stdout", res.Stdout)
	}
}

func TestDispatchDirect_PreflightAndPipelineErrorsNeverRunAStageTwice(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta")
	boom := errors.New("boom")
	cases := []struct {
		name          string
		run           *fakePipelineRunner
		wantPipelines int
	}{
		{"preflight error", &fakePipelineRunner{preflightErr: boom}, 0},
		{"post-launch error", &fakePipelineRunner{pipelineErr: boom, results: []runner.PipelineResult{{}, {}}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}

			_, err := DispatchShell(context.Background(), "alpha | beta", home, cwd, auth, tc.run)
			if !errors.Is(err, boom) {
				t.Fatalf("DispatchShell error = %v, want %v", err, boom)
			}
			if len(tc.run.calls) != 0 {
				t.Fatalf("Exec calls = %d, want 0 (only an unsupported preflight falls back, so no stage can execute twice)", len(tc.run.calls))
			}
			if len(tc.run.runs) != tc.wantPipelines {
				t.Fatalf("pipeline runs = %d, want %d", len(tc.run.runs), tc.wantPipelines)
			}
		})
	}
}

func TestDispatchDirect_PipelineStageCarriesEnvAssignments(t *testing.T) {
	prependFixturePrograms(t, "hg")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakePipelineRunner{results: []runner.PipelineResult{{}, {}}}

	if _, err := DispatchShell(context.Background(), "hg log | FOO=bar tail", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	specs := run.runs[0]
	if specs[0].Env != nil {
		t.Fatalf("stage 0 Env = %v, want nil so the parent environment is inherited", specs[0].Env)
	}
	if !envContains(specs[1].Env, "FOO=bar") {
		t.Fatalf("stage 1 Env does not carry FOO=bar; a stripped assignment must still take effect at exec")
	}
}

func TestDispatchShell_StagedPipeGroupStreamsAndSequencingIsUnchanged(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta", "gamma")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakePipelineRunner{
		fakeRunner: fakeRunner{results: []runner.RunResult{{Stdout: []byte("out-a"), Stderr: []byte("err-a")}}},
		results: []runner.PipelineResult{
			{Stdout: []byte("out-b"), Stderr: []byte("err-b")},
			{Stdout: []byte("out-c"), Stderr: []byte("err-c"), ExitCode: 0},
		},
	}

	res, err := DispatchShell(context.Background(), "alpha && beta | gamma", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 1 || !reflect.DeepEqual(run.calls[0].Argv, []string{"alpha"}) {
		t.Fatalf("Exec calls = %+v, want only the single-stage group `alpha`", run.calls)
	}
	if len(run.runs) != 1 || len(run.runs[0]) != 2 {
		t.Fatalf("pipeline runs = %+v, want one call carrying the two-stage pipe group", run.runs)
	}
	if run.runs[0][0].Stdin != nil {
		t.Fatalf("pipe group stage 0 Stdin = %q, want nil (each group starts from nil stdin)", run.runs[0][0].Stdin)
	}
	if string(res.Stdout) != "out-aout-c" {
		t.Fatalf("stdout = %q, want each group's visible stdout in order", res.Stdout)
	}
	if string(res.Stderr) != "err-aerr-berr-c" {
		t.Fatalf("stderr = %q, want every executed stage's stderr in order", res.Stderr)
	}
}

func TestDispatchShell_StagedSkippedGroupNeverReachesThePipeline(t *testing.T) {
	prependFixturePrograms(t, "alpha", "beta", "gamma")
	cwd := t.TempDir()
	home := t.TempDir()
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakePipelineRunner{
		fakeRunner: fakeRunner{results: []runner.RunResult{{Stdout: []byte("out-a"), ExitCode: 0}}},
	}

	res, err := DispatchShell(context.Background(), "alpha || beta | gamma", home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.preflights) != 0 || len(run.runs) != 0 {
		t.Fatalf("preflights/runs = %d/%d, want 0/0 (a group skipped by || never launches)", len(run.preflights), len(run.runs))
	}
	if string(res.Stdout) != "out-a" {
		t.Fatalf("stdout = %q, want only the executed group's output", res.Stdout)
	}
}

// realPipelineRunner binds the capture bound the way the production event decorator does, which is
// what makes DirectExecRunner satisfy the dispatch-local pipeline seam.
type realPipelineRunner struct {
	runner.DirectExecRunner
	cap int
}

func (r realPipelineRunner) Pipeline(ctx context.Context, specs []runner.RunSpec) ([]runner.PipelineResult, error) {
	return r.DirectExecRunner.Pipeline(ctx, specs, r.cap)
}

func TestDispatchShell_PipeGroupsStreamOnBothRoutes(t *testing.T) {
	if _, err := exec.LookPath("yes"); err != nil {
		t.Skipf("yes not available: %v", err)
	}
	if _, err := exec.LookPath("head"); err != nil {
		t.Skipf("head not available: %v", err)
	}
	cases := []struct {
		name       string
		input      string
		wantStdout string
	}{
		{"direct route", "yes | head -n 1", "y\n"},
		{"staged route", "echo a && yes | head -n 1", "a\ny\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := realPipelineRunner{cap: 64}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			type outcome struct {
				res tools.Result
				err error
			}
			done := make(chan outcome, 1)
			go func() {
				res, err := DispatchShell(ctx, tc.input, home, cwd, auth, run)
				done <- outcome{res: res, err: err}
			}()
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatalf("DispatchShell: %v", got.err)
				}
				if string(got.res.Stdout) != tc.wantStdout {
					t.Fatalf("stdout = %q, want %q", got.res.Stdout, tc.wantStdout)
				}
				if got.res.ExitCode != 0 {
					t.Fatalf("exit code = %d, want the final stage's 0", got.res.ExitCode)
				}
			case <-time.After(20 * time.Second):
				cancel()
				t.Fatalf("%q did not return within 20s", tc.input)
			}
		})
	}
}

func writeRipgrepPreConfig(t *testing.T, dir string) (sentinel string) {
	t.Helper()
	sentinel = filepath.Join(dir, "pwned")
	helper := filepath.Join(dir, "helper.sh")
	script := "#!/bin/sh\ntouch " + sentinel + "\nexec cat \"$1\"\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	config := filepath.Join(dir, "rgconfig")
	if err := os.WriteFile(config, []byte("--pre="+helper+"\n"), 0o644); err != nil {
		t.Fatalf("write ripgrep config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "input.txt"), []byte("needle\n"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	t.Setenv("RIPGREP_CONFIG_PATH", config)
	return sentinel
}

// Each subtest first runs ripgrep directly with the same inherited environment: a sentinel that never
// appears would make the whole assertion vacuous, so the control run has to create it.
func TestDispatchShell_InheritedRipgrepConfigNeverRunsItsPreProcessor(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skipf("rg not available: %v", err)
	}
	if _, err := exec.LookPath("head"); err != nil {
		t.Skipf("head not available: %v", err)
	}
	for _, tc := range []struct{ name, input string }{
		{"direct route", "rg needle input.txt"},
		{"pipeline route", "rg needle input.txt | head -n 1"},
		{"staged route", "echo start && rg needle input.txt"},
		{"literal route", "rg needle input.txt 2>/dev/null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			sentinel := writeRipgrepPreConfig(t, cwd)

			control := exec.Command("rg", "needle", "input.txt")
			control.Dir = cwd
			if out, err := control.CombinedOutput(); err != nil {
				t.Fatalf("control rg run failed: %v (%s)", err, out)
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Fatalf("control rg run did not create %s: the fixture proves nothing (%v)", sentinel, err)
			}
			if err := os.Remove(sentinel); err != nil {
				t.Fatalf("remove sentinel: %v", err)
			}

			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			res, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, realPipelineRunner{cap: 64})
			if err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if !strings.Contains(string(res.Stdout), "needle") {
				t.Fatalf("stdout = %q, want the ordinary search result", res.Stdout)
			}
			if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
				t.Fatalf("%s exists after %q: an inherited ripgrep config ran its --pre helper", sentinel, tc.input)
			}
		})
	}
}

func TestDispatchShell_RipgrepStageDropsOnlyTheRipgrepConfigVariable(t *testing.T) {
	prependFixturePrograms(t, "rg")
	cwd := t.TempDir()
	home := t.TempDir()
	t.Setenv("RIPGREP_CONFIG_PATH", "/inherited/rgconfig")
	t.Setenv("CODEMELD_TEST_KEEP", "kept")

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{}

	if _, err := DispatchShell(context.Background(), "rg needle f | wc -l", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(run.calls))
	}
	if envContains(run.calls[0].Env, "RIPGREP_CONFIG_PATH=/inherited/rgconfig") {
		t.Fatalf("rg stage Env still carries the inherited ripgrep config: %v", run.calls[0].Env)
	}
	if !envContains(run.calls[0].Env, "CODEMELD_TEST_KEEP=kept") {
		t.Fatalf("rg stage Env dropped an unrelated inherited variable: %v", run.calls[0].Env)
	}
	if run.calls[1].Env != nil {
		t.Fatalf("wc stage Env = %v, want nil (only an rg stage needs a rebuilt environment)", run.calls[1].Env)
	}
}

func TestDispatchShell_ExplicitRipgrepConfigAssignmentSurvives(t *testing.T) {
	prependFixturePrograms(t, "rg")
	cwd := t.TempDir()
	home := t.TempDir()
	t.Setenv("RIPGREP_CONFIG_PATH", "/inherited/rgconfig")

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{}

	if _, err := DispatchShell(context.Background(), "RIPGREP_CONFIG_PATH=/explicit/rgconfig rg needle f", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	if !envContains(run.calls[0].Env, "RIPGREP_CONFIG_PATH=/explicit/rgconfig") {
		t.Fatalf("Env = %v, want the approved stage assignment to survive", run.calls[0].Env)
	}
	if envContains(run.calls[0].Env, "RIPGREP_CONFIG_PATH=/inherited/rgconfig") {
		t.Fatalf("Env = %v, want the inherited value gone", run.calls[0].Env)
	}
}

func TestDispatchShell_LiteralRouteDropsOnlyTheRipgrepConfigVariable(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	t.Setenv("RIPGREP_CONFIG_PATH", "/inherited/rgconfig")
	t.Setenv("CODEMELD_TEST_KEEP", "kept")

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{}

	if _, err := DispatchShell(context.Background(), "rg needle f > out.txt", home, cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	spec := run.calls[0]
	if len(spec.Argv) == 0 || spec.Argv[0] != "sh" {
		t.Fatalf("Argv = %v, want the literal sh -c route", spec.Argv)
	}
	if envContains(spec.Env, "RIPGREP_CONFIG_PATH=/inherited/rgconfig") {
		t.Fatalf("literal sh -c Env still carries the inherited ripgrep config: %v", spec.Env)
	}
	if !envContains(spec.Env, "CODEMELD_TEST_KEEP=kept") {
		t.Fatalf("literal sh -c Env dropped an unrelated inherited variable: %v", spec.Env)
	}
}

// modeAuthorizer drives the real permissions.Authorize under one active mode, so a test observes the
// authorization source production sets rather than a canned decision.
type modeAuthorizer struct {
	mode string
	root string
}

func (m modeAuthorizer) Authorize(ctx context.Context, req permissions.MatchRequest, _ PromptDisplay, modeCtx permissions.ModeContext) (permissions.Decision, error) {
	modeCtx.Mode = m.mode
	modeCtx.ProjectRoot = m.root
	deps := permissions.AuthorizeDeps{
		EmitMatched: func(_, _, _, _, _, _, _, _, _ string) error { return nil },
	}
	return permissions.Authorize(ctx, req, modeCtx, deps)
}

func assertAutoPSChildEnv(t *testing.T, env []string) {
	t.Helper()
	if envContains(env, "XO_ENCODER_PATH=/inherited/encoders") {
		t.Fatalf("RunSpec.Env still carries the inherited libxo encoder path: %v", env)
	}
	if !envContains(env, "CODEMELD_TEST_KEEP=kept") {
		t.Fatalf("RunSpec.Env dropped an unrelated inherited variable: %v", env)
	}
}

func TestDispatchShell_AutoAllowedPSDropsTheInheritedEncoderPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		wantEnvs []bool
	}{
		{"direct route", "ps --libxo=json", []bool{true}},
		{"pipeline route", "ps --libxo=json | wc -l", []bool{true, false}},
		{"staged route", "ps --libxo=json && ps --libxo=xml", []bool{true, true}},
		{"inert wrapper", `sh -c "ps --libxo=html"`, []bool{true}},
		{"null redirect", "ps --libxo=HTML 2>/dev/null", []bool{true}},
		{"descriptor duplication", "ps --libxo=x 2>&1", []bool{true}},
		{"wrapped compound", `sh -c "ps --libxo=x && ls"`, []bool{true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			t.Setenv("XO_ENCODER_PATH", "/inherited/encoders")
			t.Setenv("CODEMELD_TEST_KEEP", "kept")
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, modeAuthorizer{mode: "build", root: cwd}, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != len(tc.wantEnvs) {
				t.Fatalf("runner calls = %d, want %d", len(run.calls), len(tc.wantEnvs))
			}
			for i, sanitized := range tc.wantEnvs {
				if sanitized {
					assertAutoPSChildEnv(t, run.calls[i].Env)
					continue
				}
				if run.calls[i].Env != nil {
					t.Fatalf("call %d Env = %v, want nil for the non-ps stage", i, run.calls[i].Env)
				}
			}
		})
	}
}

func TestDispatchShell_NonAutoPSKeepsTheOrdinaryEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		decision permissions.Decision
		literal  bool
	}{
		{"prompt", "ps --libxo=json", grantDecision(), false},
		{"grant", "ps --libxo=json", grantDecision(), false},
		{"cache", "ps --libxo=json", permissions.Decision{Outcome: "once"}, false},
		{"literal grant", `sh -c "ps --libxo=html"`, grantDecision(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			t.Setenv("XO_ENCODER_PATH", "/inherited/encoders")
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: tc.decision, prompts: tc.name == "prompt"}}
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			if tc.literal {
				if !envContains(run.calls[0].Env, "XO_ENCODER_PATH=/inherited/encoders") {
					t.Fatalf("literal Env = %v, want the ordinary inherited encoder path", run.calls[0].Env)
				}
				return
			}
			if run.calls[0].Env != nil {
				t.Fatalf("RunSpec.Env = %v, want nil so a non-auto ps inherits the ordinary environment", run.calls[0].Env)
			}
		})
	}
}

func assertOwnedHgEnv(t *testing.T, env []string) {
	t.Helper()
	want := []string{
		"PATH=" + os.Getenv("PATH"),
		"HGRCPATH=" + os.DevNull,
		"HGRCSKIPREPO=1",
		"HGPLAIN=+strictflags",
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("RunSpec.Env = %v, want exactly %v", env, want)
	}
}

func TestDispatchShell_AutoAllowedHgRunsInTheOwnedEnvironment(t *testing.T) {
	prependFixturePrograms(t, "hg")
	for _, tc := range []struct {
		name     string
		input    string
		wantEnvs []bool // per runner call: true = the owned hg environment, false = unchanged behavior
	}{
		{"direct route", "hg status", []bool{true}},
		{"pipeline route", "hg status | wc -l", []bool{true, false}},
		{"staged route", "hg root && hg status", []bool{true, true}},
		{"staged route with a non-hg neighbour", "hg status && ls", []bool{true, false}},
		{"literal route", "hg status 2>/dev/null", []bool{true}},
		{"newly admitted direct route", "hg branch", []bool{true}},
		{"newly admitted pipeline route", "hg bookmarks --list | wc -l", []bool{true, false}},
		{"newly admitted staged route", "hg branch && hg phase -r tip", []bool{true, true}},
		{"newly admitted literal route", "hg phase -r tip 2>/dev/null", []bool{true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			t.Setenv("CODEMELD_TEST_AMBIENT", "leaked")
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, modeAuthorizer{mode: "build", root: cwd}, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != len(tc.wantEnvs) {
				t.Fatalf("runner calls = %d, want %d", len(run.calls), len(tc.wantEnvs))
			}
			for i, owned := range tc.wantEnvs {
				if owned {
					assertOwnedHgEnv(t, run.calls[i].Env)
					continue
				}
				if run.calls[i].Env != nil {
					t.Fatalf("call %d Env = %v, want nil (only an auto-allowed hg process is isolated)", i, run.calls[i].Env)
				}
			}
		})
	}
}

func TestDispatchShell_GoAndMiseProbesRunPinnedWhateverTheirAuthorization(t *testing.T) {
	fixtures := t.TempDir()
	writeFixtureProgram(t, fixtures, "go", `exit 0`)
	writeFixtureProgram(t, fixtures, "mise", `exit 0`)
	t.Setenv("PATH", fixtures+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("MISE_OFFLINE", "0")
	t.Setenv("CODEMELD_TEST_INHERITED", "kept")
	t.Setenv("RIPGREP_CONFIG_PATH", "/inherited/rgconfig")

	for _, tc := range []struct {
		input string
		auto  bool
		env   string
		want  string
	}{
		{"go version", true, "GOTOOLCHAIN", "local"},
		{"go version", false, "GOTOOLCHAIN", "local"},
		{"env -i PATH=" + fixtures + " go version", false, "GOTOOLCHAIN", "local"},
		{"GOTOOLCHAIN=go1.99 go version", false, "GOTOOLCHAIN", "go1.99"},
		{"FOO=bar go version", false, "GOTOOLCHAIN", "local"},
		{"mise version", true, "MISE_OFFLINE", "1"},
		{"mise version", false, "MISE_OFFLINE", "1"},
		{"env -i PATH=" + fixtures + " mise version", false, "MISE_OFFLINE", "1"},
		{"MISE_OFFLINE=false mise version", false, "MISE_OFFLINE", "false"},
		{"FOO=bar mise version", false, "MISE_OFFLINE", "1"},
		{"go build", false, "", ""},
		{"mise install", false, "", ""},
	} {
		t.Run(fmt.Sprintf("%s auto=%v", tc.input, tc.auto), func(t *testing.T) {
			cwd := t.TempDir()
			var auth Authorizer = &fakeAuthorizer{fallback: &authBehavior{decision: permissions.Decision{Outcome: "once"}, prompts: true}}
			if tc.auto {
				auth = modeAuthorizer{mode: "build", root: cwd}
			}
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			env := run.calls[0].Env
			if tc.env == "" {
				if env != nil {
					t.Fatalf("Env = %v, want nil: a non-probe stage gets no pin", env)
				}
				return
			}
			var entries []string
			for _, e := range env {
				if strings.HasPrefix(e, tc.env+"=") {
					entries = append(entries, e)
				}
			}
			if len(entries) == 0 || entries[len(entries)-1] != tc.env+"="+tc.want {
				t.Fatalf("Env = %v, want the child to see %s=%s", env, tc.env, tc.want)
			}
			if assignsItself := strings.HasPrefix(tc.input, tc.env+"="); !assignsItself && len(entries) != 1 {
				t.Fatalf("%s entries = %v, want only the pin", tc.env, entries)
			}
			if strings.HasPrefix(tc.input, "env -i ") {
				if want := []string{"PATH=" + fixtures, tc.env + "=" + tc.want}; !slices.Equal(env, want) {
					t.Fatalf("Env = %v, want exactly %v", env, want)
				}
				return
			}
			if !envContains(env, "CODEMELD_TEST_INHERITED=kept") {
				t.Fatalf("Env = %v, want the inherited CODEMELD_TEST_INHERITED kept", env)
			}
			if strings.HasPrefix(tc.input, "FOO=bar ") && !envContains(env, "FOO=bar") {
				t.Fatalf("Env = %v, want the explicit FOO=bar kept", env)
			}
			if bare := !strings.Contains(tc.input, "="); bare && !envContains(env, "RIPGREP_CONFIG_PATH=/inherited/rgconfig") {
				t.Fatalf("Env = %v, want a bare probe to keep the inherited RIPGREP_CONFIG_PATH", env)
			}
		})
	}
}

// wantStage is one expected runner call; a nil env means the stage inherits the ordinary environment.
type wantStage struct {
	argv []string
	env  []string
}

func ownedJJStage(tail ...string) wantStage {
	argv := []string{"jj", "--no-pager", "--config", "ui.paginate=never", "--config", `ui.diff-formatter=":color-words"`, "--ignore-working-copy"}
	return wantStage{
		argv: append(argv, tail...),
		env:  []string{"PATH=" + os.Getenv("PATH"), "JJ_CONFIG="},
	}
}

func plainStage(argv ...string) wantStage { return wantStage{argv: argv} }

func TestDispatchShell_AutoAllowedJJRunsInTheOwnedEnvironmentAndArgv(t *testing.T) {
	prependFixturePrograms(t, "jj")
	for _, tc := range []struct {
		name  string
		input string
		want  []wantStage
	}{
		{"direct route", "jj status", []wantStage{ownedJJStage("status")}},
		{"direct route keeps the admitted flags", "jj log -r @ -n 10", []wantStage{ownedJJStage("log", "-r", "@", "-n", "10")}},
		{"pipeline route", "jj status | wc -l", []wantStage{ownedJJStage("status"), plainStage("wc", "-l")}},
		{"staged route", "jj root && jj status", []wantStage{ownedJJStage("root"), ownedJJStage("status")}},
		{"staged route with a non-jj neighbour", "jj status && ls", []wantStage{ownedJJStage("status"), plainStage("ls")}},
		{"mixed operators", "jj log | head && jj st", []wantStage{ownedJJStage("log"), plainStage("head"), ownedJJStage("st")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			t.Setenv("CODEMELD_TEST_AMBIENT", "leaked")
			t.Setenv("JJ_PAGER", "evil")
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, modeAuthorizer{mode: "build", root: cwd}, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != len(tc.want) {
				t.Fatalf("runner calls = %d, want %d", len(run.calls), len(tc.want))
			}
			for i, want := range tc.want {
				if !reflect.DeepEqual(run.calls[i].Argv, want.argv) {
					t.Fatalf("call %d Argv = %v, want exactly %v", i, run.calls[i].Argv, want.argv)
				}
				if !reflect.DeepEqual(run.calls[i].Env, want.env) {
					t.Fatalf("call %d Env = %v, want exactly %v", i, run.calls[i].Env, want.env)
				}
			}
		})
	}
}

func TestDispatchShell_NonAutoJJKeepsTheOrdinaryEnvironmentAndArgv(t *testing.T) {
	prependFixturePrograms(t, "jj")
	for _, tc := range []struct {
		name     string
		input    string
		decision permissions.Decision
		wantArgv []string
	}{
		{"prompt", "jj status", permissions.Decision{Outcome: "once"}, []string{"jj", "status"}},
		{"grant", "jj status", grantDecision(), []string{"jj", "status"}},
		{"cache", "jj status", permissions.Decision{Outcome: "once"}, []string{"jj", "status"}},
		{"mutating command", "jj commit -m x", grantDecision(), []string{"jj", "commit", "-m", "x"}},
		{"literal route", "jj status 2>/dev/null", grantDecision(), []string{"sh", "-c", "jj status 2>/dev/null"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			t.Setenv("CODEMELD_TEST_KEEP", "kept")
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: tc.decision, prompts: tc.name == "prompt"}}
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) != 1 {
				t.Fatalf("runner calls = %d, want 1", len(run.calls))
			}
			if !reflect.DeepEqual(run.calls[0].Argv, tc.wantArgv) {
				t.Fatalf("Argv = %v, want exactly %v: an approved jj command is not rewritten", run.calls[0].Argv, tc.wantArgv)
			}
			if tc.name == "literal route" {
				if !envContains(run.calls[0].Env, "CODEMELD_TEST_KEEP=kept") {
					t.Fatalf("literal Env = %v, want the ordinary inherited environment", run.calls[0].Env)
				}
				return
			}
			if run.calls[0].Env != nil {
				t.Fatalf("Env = %v, want nil: only a mode auto-allowed jj command is isolated", run.calls[0].Env)
			}
		})
	}
}

func TestDispatchShell_JJFormsThatNeverReachTheRunner(t *testing.T) {
	prependFixturePrograms(t, "jj")
	for _, input := range []string{
		"jj",
		"jj commit -m x",
		"jj util exec -- id",
		"jj file list",
		"jj op log",
		"jj log --config ui.pager=evil",
		"jj log --config-file=/tmp/evil.toml",
		"jj -R /other status",
		"jj --at-op=@- log",
		"jj diff --tool evil",
		"jj log -pT '{description}'",
		"jj --no-pager log",
		// the literal route cannot carry the argv isolation, so every jj literal stays gated
		"jj status 2>/dev/null",
		`sh -c "jj status"`,
	} {
		t.Run(input, func(t *testing.T) {
			cwd := t.TempDir()
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), input, t.TempDir(), cwd, modeAuthorizer{mode: "plan", root: cwd}, run)

			var denied *DeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("DispatchShell(%q) error = %v, want a denial", input, err)
			}
			if len(run.calls) != 0 {
				t.Fatalf("%q reached the runner: %+v", input, run.calls)
			}
		})
	}
}

func TestDispatchShell_ClearedEnvironmentJJNeverReachesTheRunner(t *testing.T) {
	prependFixturePrograms(t, "jj")
	bin := t.TempDir()
	writeFixtureProgram(t, bin, "jj", "exit 0")
	for _, input := range []string{
		"env -i PATH=" + bin + " jj diff",
		"env -i PATH=" + bin + " jj status | wc -l",
		"env -i PATH=" + bin + " jj root && jj status",
	} {
		t.Run(input, func(t *testing.T) {
			cwd := t.TempDir()
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), input, t.TempDir(), cwd, modeAuthorizer{mode: "plan", root: cwd}, run)

			var denied *DeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("DispatchShell(%q) error = %v, want a denial", input, err)
			}
			if len(run.calls) != 0 {
				t.Fatalf("%q reached the runner with a caller-selected jj: %+v", input, run.calls)
			}
		})
	}
}

func TestDispatchShell_PromptApprovedHgKeepsTheOrdinaryEnvironment(t *testing.T) {
	prependFixturePrograms(t, "hg")
	for _, tc := range []struct{ name, input string }{
		{"direct route", "hg status"},
		{"staged route", "hg root && hg status"},
		{"mutating command", "hg commit -m x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision(), prompts: true}}
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, t.TempDir(), cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(run.calls) == 0 {
				t.Fatal("nothing ran")
			}
			for i, call := range run.calls {
				if call.Env != nil {
					t.Fatalf("call %d Env = %v, want nil: a prompt- or grant-approved hg command is not isolated", i, call.Env)
				}
			}
		})
	}
}

func TestDispatchShell_LiteralHgIsolationNeedsTheModeAutoSource(t *testing.T) {
	cwd := t.TempDir()
	t.Setenv("CODEMELD_TEST_KEEP", "kept")
	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision(), prompts: true}}
	run := &fakeRunner{}

	if _, err := DispatchShell(context.Background(), "hg status 2>/dev/null", t.TempDir(), cwd, auth, run); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	if !envContains(run.calls[0].Env, "CODEMELD_TEST_KEEP=kept") {
		t.Fatalf("literal Env = %v, want the ordinary inherited environment", run.calls[0].Env)
	}
}

func TestDispatchShell_TemplateAndStyleHgFormsNeverReachTheRunner(t *testing.T) {
	prependFixturePrograms(t, "hg")
	for _, input := range []string{
		"hg paths -Tjson",
		`hg paths --template '{url}'`,
		"hg paths --templ x",
		"hg identify --style default",
		`hg log -nT'{rev}'`,
		"hg paths -Tjson 2>/dev/null",
		"hg root && hg paths -Tjson",
	} {
		t.Run(input, func(t *testing.T) {
			cwd := t.TempDir()
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), input, t.TempDir(), cwd, modeAuthorizer{mode: "plan", root: cwd}, run)

			var denied *DeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("DispatchShell(%q) error = %v, want a denial", input, err)
			}
			if len(run.calls) != 0 {
				t.Fatalf("%q reached the runner: %+v", input, run.calls)
			}
		})
	}
}

// hgSentinels are the paths a Mercurial configuration fixture writes when hg reads it: one from a
// user-level shell alias, one from a repository hook, and one from an extension module's import.
type hgSentinels struct{ alias, hook, extension string }

func (s hgSentinels) paths() []string { return []string{s.alias, s.hook, s.extension} }

func writeHgConfigFixtures(t *testing.T, cwd, home string) hgSentinels {
	t.Helper()
	hgFixture(t, cwd, "init", ".")
	writeFile(t, filepath.Join(cwd, "tracked.txt"), "seed\n")
	hgFixture(t, cwd, "add", "tracked.txt")
	hgFixture(t, cwd, "commit", "-m", "seed")
	writeFile(t, filepath.Join(cwd, "untracked.txt"), "later\n")

	s := hgSentinels{
		alias:     filepath.Join(home, "alias.sentinel"),
		hook:      filepath.Join(home, "hook.sentinel"),
		extension: filepath.Join(home, "extension.sentinel"),
	}
	ext := filepath.Join(home, "sentinelext.py")
	writeFile(t, ext, "open(r\""+s.extension+"\", \"w\").close()\n")
	userrc := filepath.Join(home, "user.hgrc")
	writeFile(t, userrc, "[extensions]\nsentinelext = "+ext+"\n"+
		"[alias]\nroot = !touch "+s.alias+" && echo hijacked\n"+
		"[defaults]\nstatus = -A\nphase = --public\n"+
		"[auth]\nx.prefix = example.invalid\nx.password = SENTINELPASSWORD\n")
	writeFile(t, filepath.Join(cwd, ".hg", "hgrc"), "[hooks]\npre-status = touch "+s.hook+"\n")

	t.Setenv("HGRCPATH", userrc)
	return s
}

func hgFixture(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("hg", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HGRCPATH="+os.DevNull, "HGRCSKIPREPO=1", "HGUSER=codemeld test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hg %v: %v\n%s", args, err, out)
	}
}

func hgPhaseOf(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("hg", "phase", "-r", "tip")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HGRCPATH="+os.DevNull, "HGRCSKIPREPO=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hg phase -r tip: %v\n%s", err, out)
	}
	_, phase, _ := strings.Cut(strings.TrimSpace(string(out)), ": ")
	return phase
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func removeAll(t *testing.T, paths []string) {
	t.Helper()
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", p, err)
		}
	}
}

// Each subtest first runs hg with the same inherited environment: a fixture that never fires would
// make the whole assertion vacuous, so the control run has to create every sentinel.
func TestDispatchShell_AutoAllowedHgIgnoresAmbientAndRepositoryConfiguration(t *testing.T) {
	if _, err := exec.LookPath("hg"); err != nil {
		t.Skipf("hg not available: %v", err)
	}
	for _, tc := range []struct{ name, input string }{
		{"direct route", "hg status"},
		{"pipeline route", "hg status | wc -l"},
		{"staged route", "hg root && hg status"},
		{"literal route", "hg status 2>/dev/null"},
		{"newly admitted branch route", "hg branch"},
		{"newly admitted phase route", "hg phase -r tip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			s := writeHgConfigFixtures(t, cwd, home)

			control := exec.Command("hg", "root")
			control.Dir = cwd
			if out, err := control.CombinedOutput(); err != nil {
				t.Fatalf("control hg root: %v\n%s", err, out)
			} else if !strings.Contains(string(out), "hijacked") {
				t.Fatalf("control hg root = %q, want the configured alias to have replaced it", out)
			}
			control = exec.Command("hg", "status")
			control.Dir = cwd
			if out, err := control.CombinedOutput(); err != nil {
				t.Fatalf("control hg status: %v\n%s", err, out)
			} else if !strings.Contains(string(out), "C tracked.txt") {
				t.Fatalf("control hg status = %q, want the configured [defaults] to have added -A", out)
			}
			control = exec.Command("hg", "phase", "-r", "tip")
			control.Dir = cwd
			if out, err := control.CombinedOutput(); err != nil {
				t.Fatalf("control hg phase: %v\n%s", err, out)
			}
			if phase := hgPhaseOf(t, cwd); phase != "public" {
				t.Fatalf("control hg phase left the changeset %q, want the configured [defaults] to have published it", phase)
			}
			hgFixture(t, cwd, "phase", "-f", "-d", "-r", "tip")
			for _, p := range s.paths() {
				if _, err := os.Stat(p); err != nil {
					t.Fatalf("control run did not create %s: the fixture proves nothing", p)
				}
			}
			removeAll(t, s.paths())

			res, err := DispatchShell(context.Background(), tc.input, home, cwd, modeAuthorizer{mode: "build", root: cwd}, realPipelineRunner{cap: 64})
			if err != nil {
				t.Fatalf("DispatchShell(%q): %v", tc.input, err)
			}
			for _, p := range s.paths() {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatalf("%s exists after %q: hg read a configuration source the auto-allow excludes", p, tc.input)
				}
			}
			if phase := hgPhaseOf(t, cwd); phase != "draft" {
				t.Fatalf("changeset phase after %q = %q, want draft: hg applied the configured [defaults]", tc.input, phase)
			}
			out := string(res.Stdout) + string(res.Stderr)
			if strings.Contains(out, "hijacked") || strings.Contains(out, "SENTINELPASSWORD") || strings.Contains(out, "C tracked.txt") {
				t.Fatalf("output of %q = %q, want the unaltered operation with no configured value in it", tc.input, out)
			}
			if tc.name == "direct route" && !strings.Contains(out, "untracked.txt") {
				t.Fatalf("output of %q = %q, want the real working-copy status", tc.input, out)
			}
		})
	}
}

func jjFixture(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("jj", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "JJ_CONFIG=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jj %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func jjConfigPath(t *testing.T, dir, layer string) string {
	t.Helper()
	return strings.TrimSpace(jjFixture(t, dir, "config", "path", layer))
}

func jjOperationCount(t *testing.T, dir string) int {
	t.Helper()
	out := jjFixture(t, dir, "--no-pager", "--ignore-working-copy", "op", "log", "--no-graph", "-T", `id.short() ++ "\n"`)
	return strings.Count(out, "\n")
}

// writeJJDiffFormatter points ui.diff-formatter at a script that creates sentinel, so the file's
// existence records whether jj read that configuration layer and ran the program it names.
func writeJJDiffFormatter(t *testing.T, configPath, sentinel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(configPath), err)
	}
	writeFile(t, configPath, `ui.diff-formatter = ["sh", "-c", "touch `+sentinel+`"]`+"\n")
}

func runJJControlDiff(t *testing.T, cwd, sentinel string) {
	t.Helper()
	control := exec.Command("jj", "--no-pager", "diff")
	control.Dir = cwd
	if out, err := control.CombinedOutput(); err != nil {
		t.Fatalf("control jj diff: %v\n%s", err, out)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("control run did not create %s: the fixture proves nothing", sentinel)
	}
}

func TestDispatchShell_AutoAllowedJJIgnoresAmbientConfiguration(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skipf("jj not available: %v", err)
	}
	for _, tc := range []struct{ name, input string }{
		{"direct route", "jj diff"},
		{"pipeline route", "jj diff | wc -l"},
		{"staged route", "jj root && jj diff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
			jjFixture(t, cwd, "git", "init", ".")
			writeFile(t, filepath.Join(cwd, "tracked.txt"), "seed\n")

			// Only the user layer is planted here: materializing a per-repo config would make the
			// dispatched jj, which resolves its config directory without the test's XDG_CONFIG_HOME,
			// generate a replacement outside the temporary directories. The repository and workspace
			// layers are covered by TestJJAutoArgvOverridesRepositoryAndWorkspaceConfiguration.
			userSentinel := filepath.Join(home, "user.sentinel")
			writeJJDiffFormatter(t, filepath.Join(home, "config", "jj", "config.toml"), userSentinel)
			runJJControlDiff(t, cwd, userSentinel)
			sentinels := []string{userSentinel}
			removeAll(t, sentinels)

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, modeAuthorizer{mode: "build", root: cwd}, realPipelineRunner{cap: 64}); err != nil {
				t.Fatalf("DispatchShell(%q): %v", tc.input, err)
			}
			for _, p := range sentinels {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatalf("%s exists after %q: jj read a configuration source the auto-allow excludes", p, tc.input)
				}
			}
		})
	}
}

// jj resolves the repository and workspace configuration from the configuration directory, which no
// environment variable disables, so this keeps XDG_CONFIG_HOME in the child and varies only the argv
// prefix — the isolation jjAutoEnv cannot supply.
func TestJJAutoArgvOverridesRepositoryAndWorkspaceConfiguration(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skipf("jj not available: %v", err)
	}
	for _, layer := range []string{"--repo", "--workspace"} {
		t.Run(layer, func(t *testing.T) {
			cwd := t.TempDir()
			home := t.TempDir()
			xdg := filepath.Join(home, "config")
			t.Setenv("XDG_CONFIG_HOME", xdg)
			jjFixture(t, cwd, "git", "init", ".")
			writeFile(t, filepath.Join(cwd, "tracked.txt"), "seed\n")
			sentinel := filepath.Join(home, "formatter.sentinel")
			writeJJDiffFormatter(t, jjConfigPath(t, cwd, layer), sentinel)
			env := append(jjAutoEnv(), "XDG_CONFIG_HOME="+xdg)

			control := exec.Command("jj", "--no-pager", "diff")
			control.Dir = cwd
			control.Env = env
			if out, err := control.CombinedOutput(); err != nil {
				t.Fatalf("control jj diff: %v\n%s", err, out)
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Fatalf("control run did not create %s: the owned environment alone does not reach this config layer", sentinel)
			}
			removeAll(t, []string{sentinel})

			argv := jjAutoArgv([]string{"jj", "diff"})
			isolated := exec.Command(argv[0], argv[1:]...)
			isolated.Dir = cwd
			isolated.Env = env
			if out, err := isolated.CombinedOutput(); err != nil {
				t.Fatalf("isolated jj diff: %v\n%s", err, out)
			}
			if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
				t.Fatalf("%s exists: the argv prefix did not override the configured ui.diff-formatter", sentinel)
			}
		})
	}
}

func TestDispatchShell_AutoAllowedJJLeavesTheOperationLogUnchanged(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skipf("jj not available: %v", err)
	}
	cwd := t.TempDir()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	jjFixture(t, cwd, "git", "init", ".")
	writeFile(t, filepath.Join(cwd, "untracked.txt"), "later\n")

	before := jjOperationCount(t, cwd)
	if _, err := DispatchShell(context.Background(), "jj status", home, cwd, modeAuthorizer{mode: "build", root: cwd}, realPipelineRunner{cap: 64}); err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if got := jjOperationCount(t, cwd); got != before {
		t.Fatalf("operation log = %d entries after an auto-allowed jj status, want %d: the read snapshotted the working copy", got, before)
	}
	jjFixture(t, cwd, "--no-pager", "status")
	if got := jjOperationCount(t, cwd); got <= before {
		t.Fatalf("operation log = %d entries after a snapshotting jj status, want more than %d: the fixture proves nothing", got, before)
	}
}

// writeFixtureProgram creates an executable script so a test can tell which of several same-named
// programs on different PATH entries actually ran.
func writeFixtureProgram(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	return path
}

func prependFixturePrograms(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		writeFixtureProgram(t, dir, name, "exit 0")
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func clearEnvRequestSubject(t *testing.T, assignments []string, tokens ...string) string {
	t.Helper()
	subject, err := permissions.DirectRequestSubject(tokens, assignments, true)
	if err != nil {
		t.Fatalf("DirectRequestSubject(%v, %v, true): %v", tokens, assignments, err)
	}
	return subject
}

func TestDispatchShell_ClearEnvironmentStageRunsWithListedVariablesOnly(t *testing.T) {
	printenv, err := exec.LookPath("printenv")
	if err != nil {
		t.Skipf("printenv not available: %v", err)
	}
	binDir := filepath.Dir(printenv)
	cwd := t.TempDir()
	home := t.TempDir()
	t.Setenv("CODEMELD_TEST_PARENT_ONLY", "leaked")

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	input := "env -i PATH=" + binDir + " CODEMELD_TEST_CHILD=set printenv"

	res, err := DispatchShell(context.Background(), input, home, cwd, auth, runner.DirectExecRunner{})
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
	slices.Sort(got)
	want := []string{"CODEMELD_TEST_CHILD=set", "PATH=" + binDir}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("child environment = %v, want exactly %v", got, want)
	}

	if len(auth.requests) != 1 {
		t.Fatalf("authorization requests = %d, want 1", len(auth.requests))
	}
	req := auth.requests[0]
	if !req.ClearEnvironment {
		t.Fatal("MatchRequest.ClearEnvironment = false, want the -i state carried into authorization")
	}
	wantSubject := clearEnvRequestSubject(t, []string{"PATH=" + binDir, "CODEMELD_TEST_CHILD=set"}, "printenv")
	if req.Subject != wantSubject {
		t.Fatalf("request identity = %q, want the v2 identity %q", req.Subject, wantSubject)
	}
	if !reflect.DeepEqual(req.SubjectTokens, []string{"printenv"}) {
		t.Fatalf("SubjectTokens = %v, want the bare inner program only", req.SubjectTokens)
	}
}

func TestDispatchShell_BareProgramResolvesFromTheRequestedPathInOrder(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	parentDir := filepath.Join(cwd, "parent")
	firstDir := filepath.Join(cwd, "first")
	secondDir := filepath.Join(cwd, "second")
	writeFixtureProgram(t, parentDir, "fixtureprog", `echo parent`)
	writeFixtureProgram(t, firstDir, "fixtureprog", `echo first`)
	writeFixtureProgram(t, secondDir, "fixtureprog", `echo second`)
	t.Setenv("PATH", parentDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &recordingExecRunner{}
	input := "env -i PATH=" + firstDir + string(os.PathListSeparator) + secondDir + " fixtureprog"

	res, err := DispatchShell(context.Background(), input, home, cwd, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) != "first" {
		t.Fatalf("stdout = %q, want the earlier requested-PATH entry to win", res.Stdout)
	}
	if len(run.calls) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(run.calls))
	}
	wantArgv := []string{filepath.Join(firstDir, "fixtureprog")}
	if !reflect.DeepEqual(run.calls[0].Argv, wantArgv) {
		t.Fatalf("Argv = %v, want only Argv[0] replaced with %v", run.calls[0].Argv, wantArgv)
	}
	if !reflect.DeepEqual(auth.requests[0].SubjectTokens, []string{"fixtureprog"}) {
		t.Fatalf("SubjectTokens = %v, want the canonical bare program", auth.requests[0].SubjectTokens)
	}
}

func TestDispatchShell_RequestedPathResolvesIdenticallyAtADescendantScope(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	approvedDir := filepath.Join(root, "bin")
	writeFixtureProgram(t, approvedDir, "fixtureprog", `echo approved`)
	sub := filepath.Join(root, "sub")
	writeFixtureProgram(t, filepath.Join(sub, "bin"), "fixtureprog", `echo descendant`)

	input := "env -i PATH=" + approvedDir + " fixtureprog"
	var argvs [][]string
	for _, scope := range []string{root, sub} {
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		run := &recordingExecRunner{}
		res, err := DispatchShell(context.Background(), input, home, scope, auth, run)
		if err != nil {
			t.Fatalf("DispatchShell at %q: %v", scope, err)
		}
		if strings.TrimSpace(string(res.Stdout)) != "approved" {
			t.Fatalf("stdout at %q = %q, want the approved executable", scope, res.Stdout)
		}
		if run.calls[0].Cwd != scope {
			t.Fatalf("Cwd = %q, want the run scope %q", run.calls[0].Cwd, scope)
		}
		argvs = append(argvs, run.calls[0].Argv)
	}
	if !reflect.DeepEqual(argvs[0], argvs[1]) {
		t.Fatalf("argv at the descendant scope = %v, want the same executable as at the grant scope %v", argvs[1], argvs[0])
	}
}

func TestDispatchShell_UnresolvedStageProgramIsRefusedBeforeAuthorization(t *testing.T) {
	cwd := mustEval(t, t.TempDir())
	home := t.TempDir()
	parentDir := filepath.Join(cwd, "parent")
	writeFixtureProgram(t, parentDir, "fixtureprog", `exit 0`)
	writeFixtureProgram(t, parentDir, "git", `exit 0`)
	writeFixtureProgram(t, parentDir, "cat", `exit 0`)
	t.Setenv("PATH", parentDir)
	t.Chdir(t.TempDir())
	empty := filepath.Join(cwd, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	for _, tc := range []struct {
		input   string
		stage   int
		program string
	}{
		{"assessment,", 0, "assessment,"},
		{`"assessment,"`, 0, "assessment,"},
		{"FOO=bar nosuchprog", 0, "nosuchprog"},
		{"FOO=bar nosuchprog | cat", 0, "nosuchprog"},
		{"cat f | nosuchprog", 1, "nosuchprog"},
		{"git status && assessment,", 1, "assessment,"},
		{"git status ; nosuchprog", 1, "nosuchprog"},
		{"git status && cd sub", 1, "cd"},
		{`.\/nosuchprog`, 0, "./nosuchprog"},
		{`bin\/nosuchprog`, 0, "bin/nosuchprog"},
		{`\/nonexistent\/nosuchprog`, 0, "/nonexistent/nosuchprog"},
		{"env -i PATH=" + empty + " fixtureprog", 0, "fixtureprog"},
		{"PATH=" + empty + " fixtureprog", 0, "fixtureprog"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{
				bySubject: map[string]authBehavior{"git status": {decision: grantDecision()}},
				fallback:  &authBehavior{decision: permissions.Decision{Outcome: "once"}, prompts: true},
			}
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run)
			var mc *MalformedCommandError
			if !errors.As(err, &mc) {
				t.Fatalf("error = %v, want *MalformedCommandError", err)
			}
			if want := fmt.Sprintf("shell stage %d: program %q", tc.stage, tc.program); !strings.Contains(mc.Error(), want) {
				t.Fatalf("Error() = %q, want it to name %s", mc.Error(), want)
			}
			if len(auth.requests) != 0 || len(auth.prompted) != 0 {
				t.Fatalf("authorize calls = %d, prompts = %d, want none", len(auth.requests), len(auth.prompted))
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %+v, want none", run.calls)
			}
		})
	}
}

func TestDispatchShell_EscapedRelativePathOnPathIsRefusedWhenAbsentFromTheStageFolder(t *testing.T) {
	cwd := mustEval(t, t.TempDir())
	home := t.TempDir()
	procDir := t.TempDir()
	writeFixtureProgram(t, filepath.Join(procDir, "bin"), "shadowprog", `exit 0`)
	t.Setenv("PATH", filepath.Join(procDir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(procDir)

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{}
	_, err := DispatchShell(context.Background(), `bin\/shadowprog`, home, cwd, auth, run)
	var mc *MalformedCommandError
	if !errors.As(err, &mc) {
		t.Fatalf("error = %v, want *MalformedCommandError", err)
	}
	if want := `shell stage 0: program "bin/shadowprog"`; !strings.Contains(mc.Error(), want) {
		t.Fatalf("Error() = %q, want it to name %s", mc.Error(), want)
	}
	if len(auth.requests) != 0 || len(run.calls) != 0 {
		t.Fatalf("authorize calls = %d, runner calls = %d, want none", len(auth.requests), len(run.calls))
	}
}

func TestDispatchShell_RelativeProgramPathRunsFromTheStageFolderNotPath(t *testing.T) {
	proc := mustEval(t, t.TempDir())
	home := t.TempDir()
	writeFixtureProgram(t, filepath.Join(proc, "bin"), "tool", `echo path`)
	sub := filepath.Join(proc, "sub")
	writeFixtureProgram(t, filepath.Join(sub, "bin"), "tool", `echo stage`)
	t.Setenv("PATH", filepath.Join(proc, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(proc)

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &recordingExecRunner{}
	res, err := DispatchShell(context.Background(), "cd sub && bin/tool", home, proc, auth, run)
	if err != nil {
		t.Fatalf("DispatchShell: %v", err)
	}
	if len(auth.requests) != 1 || len(auth.requests[0].SubjectTokens) == 0 || auth.requests[0].SubjectTokens[0] != "bin/tool" {
		t.Fatalf("authorize requests = %+v, want one whose subject starts with bin/tool", auth.requests)
	}
	if strings.TrimSpace(string(res.Stdout)) != "stage" {
		t.Fatalf("stdout = %q, want the stage folder's bin/tool to run", res.Stdout)
	}
	if len(run.calls) != 1 || run.calls[0].Cwd != sub || !reflect.DeepEqual(run.calls[0].Argv, []string{"bin/tool"}) {
		t.Fatalf("runner calls = %+v, want one bin/tool run in %q", run.calls, sub)
	}
}

func TestDispatchShell_BareProgramGrantCoversNoRelativeSpelling(t *testing.T) {
	proc := mustEval(t, t.TempDir())
	home := t.TempDir()
	writeFixtureProgram(t, proc, "tool", `exit 0`)
	writeFixtureProgram(t, filepath.Join(proc, "bin"), "tool", `exit 0`)
	t.Setenv("PATH", proc+string(os.PathListSeparator)+filepath.Join(proc, "bin"))
	t.Chdir(proc)

	for _, input := range []string{"./tool", "bin/tool", "bin/../bin/tool", `"bin/tool"`, `bin\/tool`} {
		t.Run(input, func(t *testing.T) {
			auth := &fakeAuthorizer{
				bySubject: map[string]authBehavior{"tool": {decision: grantDecision()}},
				fallback:  &authBehavior{decision: denyDecision("prompt declined"), prompts: true},
			}
			run := &fakeRunner{}
			_, err := DispatchShell(context.Background(), input, home, proc, auth, run)
			var mc *MalformedCommandError
			if !errors.As(err, &mc) && len(auth.prompted) == 0 {
				t.Fatalf("error = %v, prompts = %d, want a refusal or a prompt", err, len(auth.prompted))
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %+v, want none: the bare tool grant allowed %s", run.calls, input)
			}
			for _, req := range auth.requests {
				if permissions.MatchesDirectSubject(req.SubjectTokens, req.Assignments, req.ClearEnvironment, "tool") {
					t.Fatalf("a bare tool grant matches the request tokens %q the dispatcher produced for %s", req.SubjectTokens, input)
				}
			}
		})
	}
}

func TestDispatchShell_ResolvedOrUnescapedPathStageProgramsReachAuthorization(t *testing.T) {
	cwd := mustEval(t, t.TempDir())
	home := t.TempDir()
	prependFixturePrograms(t, "go", "real-program")
	writeFixtureProgram(t, filepath.Join(cwd, "bin"), "tool", `exit 0`)

	for _, tc := range []struct {
		input string
		argv  [][]string
	}{
		{"go build -o myapp && ./myapp", [][]string{{"go", "build", "-o", "myapp"}, {"./myapp"}}},
		{"SomeVar=somevalue real-program", [][]string{{"real-program"}}},
		{"OUTPUT_PATH[tencent]=/dev/fd/$a", [][]string{{"OUTPUT_PATH[tencent]=/dev/fd/$a"}}},
		{`"./out dir/app"`, [][]string{{"./out dir/app"}}},
		{`bin\/tool`, [][]string{{"bin/tool"}}},
		{`.\/bin\/tool | real-program`, [][]string{{"./bin/tool"}, {"real-program"}}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}

			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(auth.requests) != len(tc.argv) {
				t.Fatalf("authorize calls = %d, want %d", len(auth.requests), len(tc.argv))
			}
			gotArgv := make([][]string, len(run.calls))
			for i, call := range run.calls {
				gotArgv[i] = call.Argv
			}
			if !reflect.DeepEqual(gotArgv, tc.argv) {
				t.Fatalf("executed argv = %v, want %v", gotArgv, tc.argv)
			}
		})
	}
}

func TestDispatchShell_UnescapedPathProgramIsNotSearchedOnTheChildPath(t *testing.T) {
	cwd := mustEval(t, t.TempDir())
	home := t.TempDir()
	parentDir := filepath.Join(cwd, "parent")
	program := writeFixtureProgram(t, parentDir, "fixtureprog", `exit 0`)
	t.Setenv("PATH", parentDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	empty := filepath.Join(cwd, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &fakeRunner{}
	_, err := DispatchShell(context.Background(), "PATH="+empty+" "+program, home, cwd, auth, run)
	var mc *MalformedCommandError
	if errors.As(err, &mc) {
		t.Fatalf("error = %v, want the unescaped path exempt from the program preflight", err)
	}
	if len(auth.requests) != 1 {
		t.Fatalf("authorize calls = %d, want 1", len(auth.requests))
	}
}

func TestDispatchShell_MissingRequestedPathProgramFailsBeforeLaunch(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	parentDir := filepath.Join(cwd, "parent")
	writeFixtureProgram(t, parentDir, "fixtureprog", `echo parent`)
	t.Setenv("PATH", parentDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	empty := filepath.Join(cwd, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	for _, input := range []string{
		"env -i PATH=" + empty + " fixtureprog",
		"env PATH=" + empty + " fixtureprog",
	} {
		t.Run(input, func(t *testing.T) {
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &recordingExecRunner{}
			if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run); err == nil {
				t.Fatal("DispatchShell ran the stage, want a lookup failure before launch")
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %v, want none (the parent-PATH program must not run)", run.calls)
			}
		})
	}
}

// recordingExecRunner runs specs for real while recording each one, so a test can assert both what
// ran and the exact argv dispatch handed the runner.
type recordingExecRunner struct {
	runner.DirectExecRunner
	calls []runner.RunSpec
}

func (r *recordingExecRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	r.calls = append(r.calls, spec)
	return r.DirectExecRunner.Exec(ctx, spec)
}

// A leading PATH assignment reaches dispatch without passing the env grammar, so a relative entry is
// only stopped here. Resolving one would bind the stage to a different file per run directory.
func TestDispatchShell_RelativeRequestedPathEntryNeverResolves(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	writeFixtureProgram(t, filepath.Join(cwd, "relbin"), "fixtureprog", `echo relative`)
	parentDir := filepath.Join(cwd, "parent")
	writeFixtureProgram(t, parentDir, "fixtureprog", `echo parent`)
	t.Setenv("PATH", parentDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Chdir(cwd)

	auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
	run := &recordingExecRunner{}
	if _, err := DispatchShell(context.Background(), "PATH=relbin fixtureprog", home, cwd, auth, run); err == nil {
		t.Fatal("DispatchShell resolved a relative PATH entry, want a lookup failure before launch")
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %v, want none", run.calls)
	}
}

func TestMalformedCommandError_ReportsAndUnwrapsItsCause(t *testing.T) {
	cause := errors.New("shell split: unterminated single quote")
	err := error(&MalformedCommandError{Err: cause})

	if err.Error() != cause.Error() {
		t.Fatalf("Error() = %q, want the underlying reason %q", err.Error(), cause.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false, want true (Unwrap must expose the cause)")
	}
}

func TestDispatchShell_UnparseableCommandsWrapTheCauseAndRefuseBeforeAuthorizing(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSub string
	}{
		{"unterminated single quote", "echo 'x", "unterminated single quote"},
		{"unterminated double quote", `git "log`, "unterminated double quote"},
		{"dangling trailing backslash", `echo x\`, "dangling backslash"},
		{"empty command", "   ", "empty command"},
		{"empty remainder after cd prefix", "cd /tmp && ", "empty command after cd prefix"},
		{"empty pipeline stage", "ls | | wc", "empty pipeline stage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, cause := permissions.SplitCommand(tc.input); cause == nil {
				t.Fatalf("SplitCommand(%q) = nil error, want the case to still be malformed", tc.input)
			} else if !strings.Contains(cause.Error(), tc.wantSub) {
				t.Fatalf("SplitCommand(%q) error = %q, want it to contain %q", tc.input, cause, tc.wantSub)
			}

			auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}
			run := &fakeRunner{}

			_, err := DispatchShell(context.Background(), tc.input, t.TempDir(), t.TempDir(), auth, run)
			var mc *MalformedCommandError
			if !errors.As(err, &mc) {
				t.Fatalf("error = %v, want *MalformedCommandError", err)
			}
			if !errors.Is(err, mc.Err) {
				t.Fatalf("errors.Is(err, cause) = false, want the cause reachable through Unwrap")
			}
			if !strings.Contains(mc.Error(), tc.wantSub) {
				t.Fatalf("Error() = %q, want it to carry the underlying reason %q", mc.Error(), tc.wantSub)
			}
			if len(auth.requests) != 0 {
				t.Fatalf("authorize calls = %d, want 0 (an unparseable command is refused before authorization)", len(auth.requests))
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %d, want 0", len(run.calls))
			}
		})
	}
}

func TestDispatchShell_UnresolvableCdHintIsMalformedCommand(t *testing.T) {
	cwd := t.TempDir()
	missing := filepath.Join(cwd, "does-not-exist")

	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}
	run := &fakeRunner{}

	_, err := DispatchShell(context.Background(), "cd "+missing+" && git status", t.TempDir(), cwd, auth, run)
	var mc *MalformedCommandError
	if !errors.As(err, &mc) {
		t.Fatalf("error = %v, want *MalformedCommandError for a model-supplied cd hint that will not resolve", err)
	}
	if !errors.Is(err, mc.Err) {
		t.Fatalf("errors.Is(err, cause) = false, want the cause reachable through Unwrap")
	}
	if !strings.Contains(mc.Error(), missing) {
		t.Fatalf("Error() = %q, want it to name the unresolvable hint %q", mc.Error(), missing)
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0", len(auth.requests))
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0", len(run.calls))
	}
}

// DispatchShell's own parser rejects the same malformed quoting first, so dispatchLiteral's
// canonicalization wrapper is only reachable by calling it directly.
func TestDispatchLiteral_CanonicalFormFailureIsMalformedCommand(t *testing.T) {
	scope := mustEval(t, t.TempDir())
	auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}
	run := &fakeRunner{}

	literal := "echo 'x > out.txt"
	if _, cause := permissions.CanonicalLiteralForm(literal); cause == nil {
		t.Fatalf("CanonicalLiteralForm(%q) = nil error, want the case to still be malformed", literal)
	}

	_, err := dispatchLiteral(context.Background(), literal, scope, auth, run, permissions.ModeContext{Class: permissions.ClassMutating, LiteralRoute: true})
	var mc *MalformedCommandError
	if !errors.As(err, &mc) {
		t.Fatalf("error = %v, want *MalformedCommandError", err)
	}
	if !errors.Is(err, mc.Err) {
		t.Fatalf("errors.Is(err, cause) = false, want the cause reachable through Unwrap")
	}
	if !strings.Contains(mc.Error(), "unterminated single quote") {
		t.Fatalf("Error() = %q, want it to carry the underlying reason", mc.Error())
	}
	if len(auth.requests) != 0 {
		t.Fatalf("authorize calls = %d, want 0", len(auth.requests))
	}
	if len(run.calls) != 0 {
		t.Fatalf("runner calls = %d, want 0", len(run.calls))
	}
}

func TestDispatchShell_InfrastructureFailuresAreNotMalformedCommands(t *testing.T) {
	prependFixturePrograms(t, "git")
	t.Run("authorizer failure", func(t *testing.T) {
		auth := &fakeAuthorizer{bySubject: map[string]authBehavior{}}
		run := &fakeRunner{}

		_, err := DispatchShell(context.Background(), "git status", t.TempDir(), t.TempDir(), auth, run)
		if err == nil {
			t.Fatal("want an authorizer error")
		}
		var mc *MalformedCommandError
		if errors.As(err, &mc) {
			t.Fatalf("error = %v, want an authorizer failure to stay terminal", err)
		}
	})

	t.Run("runner failure", func(t *testing.T) {
		boom := errors.New("runner exploded")
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		run := &fakeRunner{execErr: boom}

		_, err := DispatchShell(context.Background(), "git status", t.TempDir(), t.TempDir(), auth, run)
		if !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the runner error propagated unwrapped", err)
		}
		var mc *MalformedCommandError
		if errors.As(err, &mc) {
			t.Fatalf("error = %v, want a runner failure to stay terminal", err)
		}
	})
}

func blockedSSHGuard(t *testing.T) (home, cwd, ssh string, guard securitystate.Policy) {
	t.Helper()
	home = mustEval(t, t.TempDir())
	cwd = mustEval(t, t.TempDir())
	ssh = mkdir(t, filepath.Join(home, ".ssh"))
	return home, cwd, ssh, securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: ssh, Source: "/cfg/settings.yaml"}})}
}

func TestDispatchShell_GuardRefusesReadOnlyBlockedPathsBeforeAuthorization(t *testing.T) {
	home, cwd, ssh, guard := blockedSSHGuard(t)
	direct := func(tokens ...string) securitystate.Refusal {
		return securitystate.Refusal{SubjectKind: "direct", Subject: strings.Join(tokens, " "), DirectRequestSubject: envRequestSubject(t, nil, tokens...)}
	}
	literal := func(input string) securitystate.Refusal {
		canonical, err := permissions.CanonicalLiteralForm(input)
		if err != nil {
			t.Fatalf("CanonicalLiteralForm(%q): %v", input, err)
		}
		return securitystate.Refusal{SubjectKind: "literal", Subject: canonical, ArgumentHash: permissions.ComputeArgumentHash(canonical)}
	}
	for _, tc := range []struct {
		input string
		scope string
		want  securitystate.Refusal
	}{
		{"cat ~/.ssh/k", cwd, direct("cat", "~/.ssh/k")},
		{"cat -- ~/.ssh/k", cwd, direct("cat", "--", "~/.ssh/k")},
		{"cat ~/tmp/../.ssh/k", cwd, direct("cat", "~/tmp/../.ssh/k")},
		{"cat notes | cat ~/.ssh/k", cwd, direct("cat", "~/.ssh/k")},
		{"cd " + ssh + " && ls", ssh, direct("ls")},
		{"ls && cat ~/.ssh/k", cwd, direct("cat", "~/.ssh/k")},
		{"rm x && cat ~/.ssh/k", cwd, direct("cat", "~/.ssh/k")},
		{"cat ~/.ssh/k 2>/dev/null", cwd, literal("cat ~/.ssh/k 2>/dev/null")},
		{`cat ~/.ssh/k 2> "/dev/null"`, cwd, literal(`cat ~/.ssh/k 2> "/dev/null"`)},
		{"ls 2>/dev/null; cat $HOME/.ssh/k 2>/dev/null", cwd, literal("ls 2>/dev/null; cat $HOME/.ssh/k 2>/dev/null")},
	} {
		t.Run(tc.input, func(t *testing.T) {
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}
			_, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run, guard)
			var got *securitystate.Refusal
			if !errors.As(err, &got) {
				t.Fatalf("error = %v, want a blocked-path refusal", err)
			}
			want := tc.want
			want.PathScope, want.Source, want.Entry, want.EntrySource, want.Envelope = tc.scope, "blocked_path", ssh, "/cfg/settings.yaml", got.Envelope
			if *got != want {
				t.Fatalf("refusal = %+v, want %+v", *got, want)
			}
			if !permissions.IsModeDenyEnvelope(got.Envelope) {
				t.Fatalf("Envelope = %q, want a recoverable guard envelope", got.Envelope)
			}
			if len(auth.requests) != 0 || auth.batchCalls != 0 || len(run.calls) != 0 {
				t.Fatalf("authorize calls = %d, batches = %d, runner calls = %d; want nothing authorized, prompted or run", len(auth.requests), auth.batchCalls, len(run.calls))
			}
		})
	}
}

func TestDispatchShell_GuardLeavesOtherCommandsToAuthorization(t *testing.T) {
	home, cwd, _, guard := blockedSSHGuard(t)
	for _, tc := range []struct {
		name  string
		input string
		guard securitystate.Policy
	}{
		{"quoted tilde runs as a relative path", `cat '~/.ssh/k'`, guard},
		{"escaped tilde runs as a relative path", `cat \~/.ssh/k`, guard},
		{"mutating command naming the blocked path", "rm ~/.ssh/k", guard},
		{"mutating stage naming the blocked path", "rm ~/.ssh/k && cat notes", guard},
		{"read-only literal with no blocked candidate", "cat notes 2>/dev/null", guard},
		{"no blocked list", "cat ~/.ssh/k", securitystate.Policy{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
			run := &fakeRunner{}
			if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, run, tc.guard); err != nil {
				t.Fatalf("DispatchShell: %v", err)
			}
			if len(auth.requests) == 0 || len(run.calls) == 0 {
				t.Fatalf("authorize calls = %d, runner calls = %d; want the command authorized and run", len(auth.requests), len(run.calls))
			}
		})
	}
}

func TestDispatchShell_OneBlockedListPerCommand(t *testing.T) {
	home, cwd, ssh, _ := blockedSSHGuard(t)
	sshEntry := []permissions.BlockedEntry{{Path: ssh, Source: "/cfg/settings.yaml"}}
	first, second := mkdir(t, filepath.Join(cwd, "first")), mkdir(t, filepath.Join(cwd, "second"))

	t.Run("a two-stage read-only command reloads once", func(t *testing.T) {
		policy, calls := liveBlockedPolicy(home, sshEntry, 0, nil)
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		if _, err := DispatchShell(context.Background(), "cat notes | ls "+first, home, cwd, auth, &fakeRunner{}, policy); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		if calls() != 1 {
			t.Fatalf("reload calls = %d, want 1", calls())
		}
	})

	t.Run("an entry added from the second reload on does not make stage 2 ask", func(t *testing.T) {
		added := append(slices.Clone(sshEntry), permissions.BlockedEntry{Path: filepath.Join(second, "inner"), Source: "/cfg/settings.yaml"})
		policy, _ := liveBlockedPolicy(home, sshEntry, 2, added)
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		if _, err := DispatchShell(context.Background(), "ls "+first+" && ls "+second, home, cwd, auth, &fakeRunner{}, policy); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		if len(auth.modeCtxs) != 2 || auth.modeCtxs[0].ShellPathAsk || auth.modeCtxs[1].ShellPathAsk {
			t.Fatalf("authorized stages = %+v, want two stages with no ask", auth.modeCtxs)
		}
	})

	t.Run("a removal from the second reload on does not reach stage 2", func(t *testing.T) {
		policy, _ := liveBlockedPolicy(home, sshEntry, 2, nil)
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		run := &fakeRunner{}
		_, err := DispatchShell(context.Background(), "ls && cat ~/.ssh/k", home, cwd, auth, run, policy)
		var refusal *securitystate.Refusal
		if !errors.As(err, &refusal) || refusal.Entry != ssh {
			t.Fatalf("error = %v, want a blocked-path refusal for %q", err, ssh)
		}
		if len(auth.requests) != 0 || len(run.calls) != 0 {
			t.Fatalf("authorize calls = %d, runner calls = %d; want 0/0", len(auth.requests), len(run.calls))
		}
	})
}

func TestDispatchShell_GuardMarksReadOnlyStagesThatAsk(t *testing.T) {
	home, cwd, _, guard := blockedSSHGuard(t)
	for _, tc := range []struct {
		input string
		want  []bool
	}{
		{"ls ~", []bool{true}},
		{"ls " + home, []bool{true}},
		{"grep -f~/.ssh/k notes", []bool{true}},
		{"cd ~ && ls", []bool{true}},
		{"cat notes | ls ~", []bool{false, true}},
		{"ls src && ls ~", []bool{false, true}},
		{"rm notes && ls ~", []bool{false, true}},
		{"cat $F 2>/dev/null", []bool{true}},
		{"ls ~ 2>/dev/null", []bool{true}},
		{`cat "$HOME/.ssh/k" 2>/dev/null`, []bool{true}},
		{"ls", []bool{false}},
		{"rm ~/notes", []bool{false}},
		{"cat notes 2>/dev/null", []bool{false}},
	} {
		for _, guarded := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s guarded=%v", tc.input, guarded), func(t *testing.T) {
				policy, want := securitystate.Policy{}, make([]bool, len(tc.want))
				if guarded {
					policy, want = guard, tc.want
				}
				auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
				if _, err := DispatchShell(context.Background(), tc.input, home, cwd, auth, &fakeRunner{}, policy); err != nil {
					t.Fatalf("DispatchShell: %v", err)
				}
				got := make([]bool, len(auth.modeCtxs))
				for i, mc := range auth.modeCtxs {
					got[i] = mc.ShellPathAsk
				}
				if !slices.Equal(got, want) {
					t.Fatalf("ShellPathAsk per authorized stage = %v, want %v", got, want)
				}
			})
		}
	}

	t.Run("a refused stage refuses the whole command before any ask", func(t *testing.T) {
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		run := &fakeRunner{}
		_, err := DispatchShell(context.Background(), "cat ~/.ssh/k && ls ~", home, cwd, auth, run, guard)
		var refusal *securitystate.Refusal
		if !errors.As(err, &refusal) {
			t.Fatalf("error = %v, want a blocked-path refusal", err)
		}
		if len(auth.requests) != 0 || len(run.calls) != 0 {
			t.Fatalf("authorize calls = %d, runner calls = %d; want 0/0", len(auth.requests), len(run.calls))
		}
	})
}

func TestDispatchShell_PlanOptionGlobAutoApprovesOnlyWhenNothingMatches(t *testing.T) {
	home, cwd, _, guard := blockedSSHGuard(t)
	input := `grep -rln "b09\|b08" ` + cwd + ` --include=*.md --include=*.txt 2>/dev/null | head -30`

	t.Run("no matching entry", func(t *testing.T) {
		auth := &recordingPlanAuthorizer{planAuthorizer: planAuthorizer{root: cwd}}
		run := &fakeRunner{}
		if _, err := DispatchShell(context.Background(), input, home, cwd, auth, run, guard); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		if len(auth.decisions) != 1 || auth.decisions[0].Outcome != "once" || !auth.decisions[0].ReadOnlyAuto {
			t.Fatalf("decisions = %+v, want one read-only mode auto-allow", auth.decisions)
		}
		if len(run.calls) != 1 {
			t.Fatalf("runner calls = %d, want 1", len(run.calls))
		}
	})

	t.Run("an entry matches the option glob", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(cwd, "--include=x.md"), nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		auth := &fakeAuthorizer{fallback: &authBehavior{decision: grantDecision()}}
		if _, err := DispatchShell(context.Background(), input, home, cwd, auth, &fakeRunner{}, guard); err != nil {
			t.Fatalf("DispatchShell: %v", err)
		}
		if len(auth.modeCtxs) != 1 || !auth.modeCtxs[0].ShellPathAsk {
			t.Fatalf("authorized contexts = %+v, want one that asks", auth.modeCtxs)
		}
	})
}

func TestDispatchShell_CancelledDuringAuthorizationRunsNothing(t *testing.T) {
	prependFixturePrograms(t, "git")
	literal, err := permissions.CanonicalLiteralForm("git status > out.txt")
	if err != nil {
		t.Fatalf("CanonicalLiteralForm: %v", err)
	}
	for _, tc := range []struct{ name, input, subject string }{
		{"literal", "git status > out.txt", literal},
		{"direct", "git status", "git status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			auth := &fakeAuthorizer{
				bySubject:   map[string]authBehavior{tc.subject: {decision: grantDecision(), prompts: true}},
				onAuthorize: func(permissions.MatchRequest) { cancel() },
			}
			run := &fakeRunner{results: []runner.RunResult{{Stdout: []byte("ran")}}}

			if _, err := DispatchShell(ctx, tc.input, t.TempDir(), t.TempDir(), auth, run); !errors.Is(err, context.Canceled) {
				t.Fatalf("DispatchShell error = %v, want context.Canceled", err)
			}
			if len(auth.requests) == 0 {
				t.Fatal("the command was never authorized; the test must cancel after authorization")
			}
			if len(run.calls) != 0 {
				t.Fatalf("runner calls = %d, want none after cancellation", len(run.calls))
			}
		})
	}
}
