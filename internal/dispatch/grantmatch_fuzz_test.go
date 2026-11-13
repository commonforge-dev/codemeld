package dispatch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/runner"
)

type grantSeed struct{ name, a, b string }

func grantSeeds() []grantSeed {
	seeds := []grantSeed{
		{"E2", `mv x '~/target'`, `mv x ~/target`},
		{"E3", `sh -c "mv '*.txt' d && true"`, `sh -c 'mv *.txt d && true'`},
		{"g5300", `cat '~/f' ; echo done`, `cat ~/f ; echo done`},
	}
	crossForm := []string{
		`mv a ~`, `mv a '~'`, `mv a ~/x`, `mv a '~/x'`, `mv a $HOME`, `mv a '$HOME'`,
		`mv a $HOME/x`, `mv a "$HOME"/x`, `mv a \~/x`, `mv a \$HOME/x`, `mv a ~'/'x`, `mv a ~"/x"`,
	}
	for _, a := range crossForm {
		for _, b := range crossForm {
			seeds = append(seeds, grantSeed{"cross-form", a, b})
		}
	}
	wrapped := [][2]string{
		{"ls '*.txt' && true", "ls *.txt && true"},
		{"ls 'a?.txt' && true", "ls a?.txt && true"},
		{"ls '[ab].txt' && true", "ls [ab].txt && true"},
		{"cat '~/x' && true", "cat ~/x && true"},
		{"cat '$HOME' && true", "cat $HOME && true"},
		{"cat '$HOME' && true", `cat "$HOME" && true`},
		{"ls '{a,b}' && true", "ls {a,b} && true"},
	}
	for _, pair := range wrapped {
		for _, redirect := range []string{"", " 2>/dev/null"} {
			wrap := func(body string) string {
				stage, rest, _ := strings.Cut(body, " && ")
				return "sh -c " + singleQuote(stage+redirect+" && "+rest)
			}
			seeds = append(seeds,
				grantSeed{"wrapped-expansion", wrap(pair[0]), wrap(pair[1])},
				grantSeed{"wrapped-expansion", wrap(pair[1]), wrap(pair[0])})
		}
	}
	return seeds
}

var (
	fuzzPrograms = []string{"mv", "cat"}
	fuzzWords    = []string{"f", "~", "~/x", "$HOME", "$HOME/x", "$X", "*.txt", "?", "[ab]", "{a,b}"}
	fuzzOps      = []string{"&&", ";", "|"}
	fuzzRedirect = []string{"", " >/dev/null", " 2>/dev/null"}
)

type byteReader struct{ data []byte }

func (r *byteReader) next(n int) int {
	if len(r.data) == 0 {
		return 0
	}
	b := r.data[0]
	r.data = r.data[1:]
	return int(b) % n
}

func singleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func quoteWord(w string, form int) string {
	switch form {
	case 1:
		return singleQuote(w)
	case 2:
		return `"` + w + `"`
	case 3:
		var b strings.Builder
		for _, r := range w {
			b.WriteByte('\\')
			b.WriteRune(r)
		}
		return b.String()
	case 4:
		if len(w) == 1 {
			return `\` + w
		}
		return singleQuote(w[:1]) + `"` + w[1:] + `"`
	default:
		return w
	}
}

func wrapCommand(body string, form int) string {
	switch form {
	case 1:
		return "sh -c " + singleQuote(body)
	case 2:
		return `sh -c "` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`").Replace(body) + `"`
	default:
		return body
	}
}

func decodeGrantPair(data []byte) (string, string) {
	r := &byteReader{data: data}
	wrapA, wrapB := r.next(3), r.next(3)
	redirA, redirB := r.next(len(fuzzRedirect)), r.next(len(fuzzRedirect))
	stages := 1 + r.next(2)
	op := fuzzOps[r.next(len(fuzzOps))]
	var bodyA, bodyB []string
	for i := range stages {
		stageA := []string{fuzzPrograms[r.next(len(fuzzPrograms))]}
		stageB := slices.Clone(stageA)
		for range 1 + r.next(3) {
			w := fuzzWords[r.next(len(fuzzWords))]
			stageA = append(stageA, quoteWord(w, r.next(5)))
			stageB = append(stageB, quoteWord(w, r.next(5)))
		}
		a, b := strings.Join(stageA, " "), strings.Join(stageB, " ")
		if i == 0 {
			a += fuzzRedirect[redirA]
			b += fuzzRedirect[redirB]
		}
		bodyA, bodyB = append(bodyA, a), append(bodyB, b)
	}
	return wrapCommand(strings.Join(bodyA, " "+op+" "), wrapA), wrapCommand(strings.Join(bodyB, " "+op+" "), wrapB)
}

type grantFixture struct {
	home, cwd, bin, log string
}

const fuzzXValue = "x-value"

func newGrantFixture(f *testing.F) *grantFixture {
	sh, err := exec.LookPath("sh")
	if err != nil {
		f.Skipf("sh not available: %v", err)
	}
	root, err := filepath.EvalSymlinks(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	fx := &grantFixture{
		home: filepath.Join(root, "home"),
		cwd:  filepath.Join(root, "work"),
		bin:  filepath.Join(root, "bin"),
		log:  filepath.Join(root, "runs.log"),
	}
	for _, dir := range []string{fx.home, fx.cwd, filepath.Join(fx.cwd, "d"), fx.bin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			f.Fatal(err)
		}
	}
	for _, name := range []string{"a", "b", "f", "x", "a.txt", "b.txt", "ab.txt"} {
		if err := os.WriteFile(filepath.Join(fx.cwd, name), nil, 0o644); err != nil {
			f.Fatal(err)
		}
	}
	// Piped stubs run at once, so each record must reach the log in one append.
	body := "#!/bin/sh\nrecord=$(printf '%s\\037' \"${0##*/}\" \"$@\")\nprintf '%s\\n' \"$record\" >>\"$CODEMELD_FUZZ_LOG\"\n"
	for _, name := range []string{"mv", "cat", "ls"} {
		path := filepath.Join(fx.bin, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			f.Fatal(err)
		}
	}
	if err := os.Symlink(sh, filepath.Join(fx.bin, "sh")); err != nil {
		f.Fatal(err)
	}
	return fx
}

type recordingShellRunner struct {
	fx     *grantFixture
	runs   [][]string
	stderr []string
}

func (r *recordingShellRunner) NewInvocationID() string { return "fuzz" }

func (r *recordingShellRunner) Exec(ctx context.Context, spec runner.RunSpec) (runner.RunResult, error) {
	if len(spec.Argv) < 3 || filepath.Base(spec.Argv[0]) != "sh" || spec.Argv[1] != "-c" {
		r.runs = append(r.runs, slices.Clone(spec.Argv))
		return runner.RunResult{}, nil
	}
	if err := os.WriteFile(r.fx.log, nil, 0o644); err != nil {
		return runner.RunResult{}, err
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", spec.Argv[1:]...)
	cmd.Dir = spec.Cwd
	cmd.Env = []string{"PATH=" + r.fx.bin, "HOME=" + r.fx.home, "X=" + fuzzXValue, "CODEMELD_FUZZ_LOG=" + r.fx.log}
	cmd.Stdin = bytes.NewReader(spec.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return runner.RunResult{}, err
		}
		exitCode = exitErr.ExitCode()
	}
	if stderr.Len() > 0 {
		r.stderr = append(r.stderr, stderr.String())
	}
	logged, err := os.ReadFile(r.fx.log)
	if err != nil {
		return runner.RunResult{}, err
	}
	var shellRuns [][]string
	for line := range strings.Lines(string(logged)) {
		fields := strings.Split(strings.TrimSuffix(line, "\n"), "\x1f")
		shellRuns = append(shellRuns, fields[:len(fields)-1])
	}
	slices.SortFunc(shellRuns, func(x, y []string) int { return slices.Compare(x, y) })
	r.runs = append(r.runs, shellRuns...)
	return runner.RunResult{Stdout: stdout.Bytes(), ExitCode: exitCode}, nil
}

type grantCheckAuthorizer struct {
	grants    []permissions.PermissionEntry
	requests  []permissions.MatchRequest
	uncovered bool
}

func (a *grantCheckAuthorizer) Authorize(_ context.Context, req permissions.MatchRequest, _ PromptDisplay, _ permissions.ModeContext) (permissions.Decision, error) {
	a.requests = append(a.requests, req)
	if a.grants != nil && !permissions.Match(req, a.grants).Matched {
		a.uncovered = true
		return denyDecision("not covered by the stored grants"), nil
	}
	return permissions.Decision{Outcome: "once"}, nil
}

func exactGrantsFor(reqs []permissions.MatchRequest) []permissions.PermissionEntry {
	grants := make([]permissions.PermissionEntry, 0, len(reqs))
	for _, req := range reqs {
		entry := permissions.PermissionEntry{Kind: req.Kind, Subject: req.Subject, PathScope: req.PathScope, GrantKind: "session"}
		if req.Kind == "literal" {
			if subject, ok := exactCompoundSubject(req.Subject); ok {
				entry.Subject = subject
			}
			entry.ArgumentHash = permissions.ComputeArgumentHash(entry.Subject)
		}
		grants = append(grants, entry)
	}
	return grants
}

func exactCompoundSubject(canonical string) (string, bool) {
	sc, ok := permissions.RecognizeSimpleCompoundForGrant(canonical)
	if !ok {
		return "", false
	}
	subjects := make([]string, len(sc.Stages))
	for i, stage := range sc.Stages {
		subject, err := permissions.CompoundStageScopeSubject(sc, i, permissions.ExactSubject(stage[0], stage[1:]))
		if err != nil {
			return "", false
		}
		subjects[i] = subject
	}
	subject, err := permissions.EncodeCompoundSubject(sc.Wrapped, subjects, sc.Operators)
	return subject, err == nil
}

func dispatchRecorded(t *testing.T, fx *grantFixture, input string, auth *grantCheckAuthorizer) ([][]string, bool) {
	t.Helper()
	run := &recordingShellRunner{fx: fx}
	_, err := DispatchShell(context.Background(), input, fx.home, fx.cwd, auth, run)
	var unsupported *UnsupportedConstructError
	var malformed *MalformedCommandError
	var denied *DeniedError
	switch {
	case errors.As(err, &unsupported), errors.As(err, &malformed), errors.As(err, &denied):
		return nil, false
	case err != nil:
		t.Fatalf("DispatchShell(%q): %v", input, err)
	}
	if len(run.stderr) > 0 {
		t.Fatalf("shell run of %q wrote to stderr: %q", input, run.stderr)
	}
	return run.runs, true
}

func FuzzGrantMatchesExecution(f *testing.F) {
	fx := newGrantFixture(f)
	seeds := grantSeeds()
	for i := range seeds {
		f.Add([]byte{0, byte(i)})
	}
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		var a, b string
		if data[0] == 0 {
			seed := seeds[int(data[len(data)-1])%len(seeds)]
			a, b = seed.a, seed.b
		} else {
			a, b = decodeGrantPair(data[1:])
		}
		authA := &grantCheckAuthorizer{}
		runA, ok := dispatchRecorded(t, fx, a, authA)
		if !ok {
			return
		}
		grants := exactGrantsFor(authA.requests)
		authB := &grantCheckAuthorizer{grants: grants}
		runB, ok := dispatchRecorded(t, fx, b, authB)
		if !ok || authB.uncovered {
			return
		}
		// Direct-stage grants are per stage, so B may reorder or repeat A's stages.
		for _, run := range runB {
			if !slices.ContainsFunc(runA, func(r []string) bool { return slices.Equal(r, run) }) {
				t.Fatalf("grant stored for A covers B but B runs %q, which A never ran\nA: %s\nB: %s\nstored subjects: %s\nA runs: %q\nB runs: %q",
					run, a, b, storedSubjects(grants), runA, runB)
			}
		}
	})
}

func storedSubjects(grants []permissions.PermissionEntry) string {
	parts := make([]string, len(grants))
	for i, g := range grants {
		parts[i] = fmt.Sprintf("%s %q", g.Kind, g.Subject)
	}
	return strings.Join(parts, "; ")
}
