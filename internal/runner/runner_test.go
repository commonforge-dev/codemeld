// Unit tests for DirectExecRunner: clean exec, non-zero exit, launch failures (not-found,
// permission-denied), no-shell behavior, invocation-id contract, uncapped output, and the
// Cwd/Env/Stdin pass-through fields.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
)

// The subprocess-helper env keys re-exec this test binary as a controllable child, so stdout,
// stderr, and exit code are produced without depending on host shell behavior (mirrors the
// os.Executable pattern in internal/locks/flock_test.go).
const (
	helperEnv       = "CODEMELD_RUNNER_HELPER"
	helperStdout    = "CODEMELD_RUNNER_STDOUT"
	helperStderr    = "CODEMELD_RUNNER_STDERR"
	helperExit      = "CODEMELD_RUNNER_EXIT"
	helperRepeat    = "CODEMELD_RUNNER_REPEAT"     // number of 'a' bytes to write to stdout
	helperPrintCwd  = "CODEMELD_RUNNER_PRINT_CWD"  // when "1", write os.Getwd() to stdout
	helperPrintEnv  = "CODEMELD_RUNNER_PRINT_ENV"  // comma-separated var names; write "name=value\n" for each
	helperEchoStdin = "CODEMELD_RUNNER_ECHO_STDIN" // when "1", copy stdin to stdout verbatim
	helperErrRepeat = "CODEMELD_RUNNER_ERR_REPEAT" // number of 'e' bytes to write to stderr
	helperSpew      = "CODEMELD_RUNNER_SPEW"       // when "1", write "y\n" to stdout forever (like yes)
	helperReadLine  = "CODEMELD_RUNNER_READ_LINE"  // when "1", copy one stdin line to stdout, then exit (like head -n 1)
	helperBlock     = "CODEMELD_RUNNER_BLOCK"      // when "1", block forever without reading or writing
	helperTouch     = "CODEMELD_RUNNER_TOUCH"
)

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		runHelper()
	}
	os.Exit(m.Run())
}

// runHelper emits the configured stdout/stderr and exits with the configured code, then never
// returns. It is reached only in the re-exec'd child process.
func runHelper() {
	if s := os.Getenv(helperStdout); s != "" {
		_, _ = os.Stdout.WriteString(s)
	}
	if s := os.Getenv(helperStderr); s != "" {
		_, _ = os.Stderr.WriteString(s)
	}
	if n := os.Getenv(helperRepeat); n != "" {
		count, _ := strconv.Atoi(n)
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("a"), count))
	}
	if os.Getenv(helperPrintCwd) == "1" {
		wd, _ := os.Getwd()
		_, _ = os.Stdout.WriteString(wd)
	}
	if names := os.Getenv(helperPrintEnv); names != "" {
		for name := range strings.SplitSeq(names, ",") {
			_, _ = fmt.Fprintf(os.Stdout, "%s=%s\n", name, os.Getenv(name))
		}
	}
	if n := os.Getenv(helperErrRepeat); n != "" {
		count, _ := strconv.Atoi(n)
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("e"), count))
	}
	if os.Getenv(helperEchoStdin) == "1" {
		_, _ = io.Copy(os.Stdout, os.Stdin)
	}
	if os.Getenv(helperReadLine) == "1" {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		_, _ = os.Stdout.WriteString(line)
		os.Exit(0)
	}
	if os.Getenv(helperSpew) == "1" {
		// Writing to a closed fd 1 raises SIGPIPE, which the Go runtime lets kill the process, so
		// this ends exactly when a downstream stage closes the pipe — the behavior `yes` has.
		for {
			_, _ = os.Stdout.WriteString("y\n")
		}
	}
	if os.Getenv(helperBlock) == "1" {
		select {}
	}
	if p := os.Getenv(helperTouch); p != "" {
		_ = os.WriteFile(p, []byte("done"), 0o600)
	}
	code := 0
	if c := os.Getenv(helperExit); c != "" {
		code, _ = strconv.Atoi(c)
	}
	os.Exit(code)
}

// helperSpec builds a RunSpec that re-execs this test binary in helper mode with the given extra
// env vars. The -test.run filter matches no real test, a backstop in case the child ever falls
// through to m.Run instead of os.Exit-ing inside runHelper.
func helperSpec(t *testing.T, id string, extra map[string]string) RunSpec {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	env := append(os.Environ(), helperEnv+"=1")
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return RunSpec{
		InvocationID: id,
		Argv:         []string{exe, "-test.run=^$"},
		Env:          env,
	}
}

func TestDirectExecRunner_CleanExec(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	spec := helperSpec(t, id, map[string]string{
		helperStdout: "hello out",
		helperStderr: "hello err",
	})

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec returned error on clean exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", res.ExitCode)
	}
	if string(res.Stdout) != "hello out" {
		t.Fatalf("Stdout = %q, want %q", res.Stdout, "hello out")
	}
	if string(res.Stderr) != "hello err" {
		t.Fatalf("Stderr = %q, want %q", res.Stderr, "hello err")
	}
	if res.LaunchErrCategory != "" {
		t.Fatalf("LaunchErrCategory = %q, want empty on clean exec", res.LaunchErrCategory)
	}
	if res.InvocationID != id {
		t.Fatalf("InvocationID = %q, want %q", res.InvocationID, id)
	}
}

func TestDirectExecRunner_NonZeroExit(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	spec := helperSpec(t, id, map[string]string{
		helperStdout: "partial",
		helperStderr: "boom",
		helperExit:   "3",
	})

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec returned error on non-zero exit; want nil (result-level outcome): %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("ExitCode = %d, want 3", res.ExitCode)
	}
	if string(res.Stdout) != "partial" {
		t.Fatalf("Stdout = %q, want %q (captured streams preserved on non-zero exit)", res.Stdout, "partial")
	}
	if string(res.Stderr) != "boom" {
		t.Fatalf("Stderr = %q, want %q", res.Stderr, "boom")
	}
	if res.LaunchErrCategory != "" {
		t.Fatalf("LaunchErrCategory = %q, want empty on non-zero exit (not a launch failure)", res.LaunchErrCategory)
	}
	if res.InvocationID != id {
		t.Fatalf("InvocationID = %q, want %q", res.InvocationID, id)
	}
}

func TestDirectExecRunner_BinaryNotFound(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	// A bare, non-existent name forces exec.LookPath to fail with exec.ErrNotFound, exercising the
	// explicit sentinel mapping rather than an errno path.
	spec := RunSpec{InvocationID: id, Argv: []string{"codemeld-no-such-binary-7f3a9c"}}

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec returned error on missing binary; want launch-failure result: %v", err)
	}
	if res.ExitCode != -1 {
		t.Fatalf("ExitCode = %d, want -1 on launch failure", res.ExitCode)
	}
	if res.LaunchErrCategory != fserrors.NotFound {
		t.Fatalf("LaunchErrCategory = %q, want %q", res.LaunchErrCategory, fserrors.NotFound)
	}
	if len(res.Stdout) != 0 || len(res.Stderr) != 0 {
		t.Fatalf("Stdout=%q Stderr=%q, want both empty on launch failure", res.Stdout, res.Stderr)
	}
	if res.InvocationID != id {
		t.Fatalf("InvocationID = %q, want %q", res.InvocationID, id)
	}
}

func TestDirectExecRunner_PermissionDenied(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()

	// A regular file without any execute bit denies execve with EACCES — including for root, which
	// CAP_DAC_OVERRIDE does not bypass when no execute bit is set on a regular file.
	dir := t.TempDir()
	noExec := filepath.Join(dir, "not-executable")
	if writeErr := os.WriteFile(noExec, []byte("#!/bin/sh\n"), 0o644); writeErr != nil {
		t.Fatalf("write non-executable file: %v", writeErr)
	}

	spec := RunSpec{InvocationID: id, Argv: []string{noExec}}
	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec returned error on permission denied; want launch-failure result: %v", err)
	}
	if res.ExitCode != -1 {
		t.Fatalf("ExitCode = %d, want -1 on launch failure", res.ExitCode)
	}
	if res.LaunchErrCategory != fserrors.PermissionDenied {
		t.Fatalf("LaunchErrCategory = %q, want %q", res.LaunchErrCategory, fserrors.PermissionDenied)
	}
	if res.InvocationID != id {
		t.Fatalf("InvocationID = %q, want %q", res.InvocationID, id)
	}
}

func TestDirectExecRunner_NoShellInterpretation(t *testing.T) {
	if _, err := exec.LookPath("echo"); err != nil {
		t.Skip("echo not found on PATH; cannot assert no-shell argv passthrough")
	}
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	spec := RunSpec{InvocationID: id, Argv: []string{"echo", "$HOME"}}

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", res.ExitCode)
	}
	if got := strings.TrimRight(string(res.Stdout), "\n"); got != "$HOME" {
		t.Fatalf("Stdout = %q, want literal %q (no shell variable expansion)", got, "$HOME")
	}
	if home := os.Getenv("HOME"); home != "" && strings.Contains(string(res.Stdout), home) {
		t.Fatalf("Stdout %q contains expanded HOME %q; argv must be passed literally", res.Stdout, home)
	}
}

func TestDirectExecRunner_NewInvocationID(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	if !ids.IsValidV7(id) {
		t.Fatalf("NewInvocationID returned %q, not a valid UUIDv7", id)
	}
	if other := r.NewInvocationID(); other == id {
		t.Fatalf("NewInvocationID returned the same id twice: %q", id)
	}
}

// TestDirectExecRunner_InvocationIDEchoed asserts the caller-supplied id is echoed verbatim for
// successful, non-zero, and launch-failure invocations alike (single id source).
func TestDirectExecRunner_InvocationIDEchoed(t *testing.T) {
	r := DirectExecRunner{}

	cases := []struct {
		name string
		spec func(id string) RunSpec
	}{
		{"success", func(id string) RunSpec { return helperSpec(t, id, nil) }},
		{"nonzero", func(id string) RunSpec { return helperSpec(t, id, map[string]string{helperExit: "7"}) }},
		{"launch_failure", func(id string) RunSpec {
			return RunSpec{InvocationID: id, Argv: []string{"codemeld-no-such-binary-7f3a9c"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := r.NewInvocationID()
			res, err := r.Exec(context.Background(), tc.spec(id))
			if err != nil {
				t.Fatalf("Exec error: %v", err)
			}
			if res.InvocationID != id {
				t.Fatalf("InvocationID = %q, want supplied id %q", res.InvocationID, id)
			}
		})
	}
}

func TestDirectExecRunner_InvalidInvocationID(t *testing.T) {
	r := DirectExecRunner{}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	for _, id := range []string{"", "not-a-uuid", "00000000-0000-7000-8000-00000000000G"} {
		res, execErr := r.Exec(context.Background(), RunSpec{InvocationID: id, Argv: []string{exe}})
		if execErr == nil {
			t.Fatalf("Exec(id=%q) returned nil error; want error for invalid invocation id", id)
		}
		if !isZeroResult(res) {
			t.Fatalf("Exec(id=%q) returned non-zero RunResult %+v; want unusable zero result", id, res)
		}
	}
}

// isZeroResult reports whether res is the unusable zero value Exec returns alongside an input
// error (RunResult is not comparable with == because of its []byte fields).
func isZeroResult(res RunResult) bool {
	return res.InvocationID == "" &&
		res.Stdout == nil && res.Stderr == nil &&
		res.ExitCode == 0 && res.Duration == 0 &&
		res.LaunchErrCategory == ""
}

func TestDirectExecRunner_EmptyArgvErrors(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	res, err := r.Exec(context.Background(), RunSpec{InvocationID: id, Argv: nil})
	if err == nil {
		t.Fatalf("Exec with empty Argv returned nil error; want error")
	}
	if !isZeroResult(res) {
		t.Fatalf("Exec with empty Argv returned non-zero RunResult %+v; want unusable zero result", res)
	}
}

// TestDirectExecRunner_OutputNotCapped proves the runner returns full captured bytes and does not
// apply the sessions.max_tool_output_bytes cap (that is the tool_exec_* event layer's job).
func TestDirectExecRunner_OutputNotCapped(t *testing.T) {
	const size = 200_000 // larger than the 65536-byte default cap
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	spec := helperSpec(t, id, map[string]string{helperRepeat: strconv.Itoa(size)})

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}
	if len(res.Stdout) != size {
		t.Fatalf("len(Stdout) = %d, want %d (runner must not cap output)", len(res.Stdout), size)
	}
}

// TestDirectExecRunner_Cwd proves RunSpec.Cwd reaches the child as its working directory
// (exec.Cmd.Dir). Dropping cmd.Dir = spec.Cwd makes the child report the parent's cwd, failing
// this test — guarding the cwd-scoped execution staged consumers like direct shell dispatch depend on.
func TestDirectExecRunner_Cwd(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	dir := t.TempDir()
	// chdir resolves symlinks (e.g. a /tmp → /private/tmp link), so compare against the canonical
	// form the child's os.Getwd reports rather than the possibly-symlinked t.TempDir path.
	wantDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	spec := helperSpec(t, id, map[string]string{helperPrintCwd: "1"})
	spec.Cwd = dir

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := string(res.Stdout); got != wantDir {
		t.Fatalf("child cwd = %q, want %q (RunSpec.Cwd must set exec.Cmd.Dir)", got, wantDir)
	}
}

// TestDirectExecRunner_Env proves a non-nil RunSpec.Env becomes the child's complete environment,
// replacing the parent's: the sentinel set in Env is visible while a variable present only in the
// parent process is absent. Dropping cmd.Env = spec.Env makes the child inherit the parent env,
// where the parent-only variable is non-empty, failing this test.
func TestDirectExecRunner_Env(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()

	const (
		sentinelVar = "CODEMELD_RUNNER_SENTINEL"
		sentinelVal = "controlled-env-value"
		parentVar   = "CODEMELD_RUNNER_PARENT_ONLY"
	)
	// Set parentVar in this process only; it is deliberately omitted from the controlled block
	// below, so the child must see it empty when Env fully replaces the parent environment.
	t.Setenv(parentVar, "leaked-from-parent")

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// A minimal, complete env block: only the helper gate, the dump instruction, and the sentinel.
	// The child runs via the absolute test-binary path, so it needs no PATH lookup.
	spec := RunSpec{
		InvocationID: id,
		Argv:         []string{exe, "-test.run=^$"},
		Env: []string{
			helperEnv + "=1",
			helperPrintEnv + "=" + sentinelVar + "," + parentVar,
			sentinelVar + "=" + sentinelVal,
		},
	}

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	want := sentinelVar + "=" + sentinelVal + "\n" + parentVar + "=\n"
	if got := string(res.Stdout); got != want {
		t.Fatalf("child env dump = %q, want %q (RunSpec.Env must set exec.Cmd.Env as the complete block)", got, want)
	}
}

// TestDirectExecRunner_EnvNilInheritsParent proves a nil RunSpec.Env makes the child inherit the
// parent process environment (the else branch of `if spec.Env != nil`). A variable set only in this
// parent process must reach the child unchanged. Forcing the nil branch to use an empty block
// (cmd.Env = []string{}) makes the child report the sentinel empty, failing this test — the
// complement of TestDirectExecRunner_Env, which pins the non-nil replace branch.
func TestDirectExecRunner_EnvNilInheritsParent(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()

	const (
		sentinelVar = "CODEMELD_RUNNER_INHERIT_SENTINEL"
		sentinelVal = "inherited-from-parent"
	)
	// Set the helper gate, the dump instruction, and the sentinel in this process only. With Env
	// left nil, the child must reach helper mode and see the sentinel purely through inheritance.
	t.Setenv(helperEnv, "1")
	t.Setenv(helperPrintEnv, sentinelVar)
	t.Setenv(sentinelVar, sentinelVal)

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// Env deliberately unset (nil): the inherit branch must supply the child's environment.
	spec := RunSpec{
		InvocationID: id,
		Argv:         []string{exe, "-test.run=^$"},
	}

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	want := sentinelVar + "=" + sentinelVal + "\n"
	if got := string(res.Stdout); got != want {
		t.Fatalf("child env dump = %q, want %q (nil RunSpec.Env must inherit the parent environment)", got, want)
	}
}

// TestDirectExecRunner_Stdin proves RunSpec.Stdin is fed to the child's standard input. The helper
// echoes everything it reads from stdin to stdout, including embedded NUL and newline bytes to
// prove raw byte fidelity. Dropping cmd.Stdin = bytes.NewReader(spec.Stdin) leaves the child with
// no input, so the echoed output is empty and this test fails — guarding the stdin chaining
// direct shell dispatch depends on.
func TestDirectExecRunner_Stdin(t *testing.T) {
	r := DirectExecRunner{}
	id := r.NewInvocationID()
	payload := []byte("stdin payload\x00with NUL and a trailing newline\n")
	spec := helperSpec(t, id, map[string]string{helperEchoStdin: "1"})
	spec.Stdin = payload

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0; stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := res.Stdout; !bytes.Equal(got, payload) {
		t.Fatalf("child stdin echo = %q, want %q (RunSpec.Stdin must feed child stdin)", got, payload)
	}
}

// pipelineWithin bounds the run so a stage that buffers instead of streaming fails the test rather
// than hanging the suite.
func pipelineWithin(t *testing.T, timeout time.Duration, maxCapture int, specs []RunSpec) ([]PipelineResult, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		results []PipelineResult
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := DirectExecRunner{}.Pipeline(ctx, specs, maxCapture)
		done <- outcome{results: results, err: err}
	}()
	select {
	case got := <-done:
		return got.results, got.err
	case <-time.After(timeout):
		cancel()
		t.Fatalf("Pipeline did not return within %v", timeout)
		return nil, nil
	}
}

func pipelineSpec(t *testing.T, extra map[string]string) RunSpec {
	t.Helper()
	return helperSpec(t, DirectExecRunner{}.NewInvocationID(), extra)
}

func missingBinarySpec() RunSpec {
	return RunSpec{InvocationID: DirectExecRunner{}.NewInvocationID(), Argv: []string{"codemeld-no-such-binary-7f3a9c"}}
}

func TestDirectExecRunner_PipelineEndsProducerWhenConsumerExits(t *testing.T) {
	specs := []RunSpec{
		pipelineSpec(t, map[string]string{helperSpew: "1"}),
		pipelineSpec(t, map[string]string{helperReadLine: "1"}),
	}

	results, err := pipelineWithin(t, 20*time.Second, 1024, specs)
	if err != nil {
		t.Fatalf("Pipeline error = %v, want nil", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want one per spec", len(results))
	}
	if string(results[1].Stdout) != "y\n" {
		t.Fatalf("final stdout = %q, want %q (the consumer read one line and exited)", results[1].Stdout, "y\n")
	}
	if results[1].ExitCode != 0 {
		t.Fatalf("consumer exit = %d, want 0", results[1].ExitCode)
	}
	if results[0].Duration <= 0 {
		t.Fatalf("producer duration = %v, want a positive wall time (the producer must have been waited on)", results[0].Duration)
	}
	if results[0].PipelineErrCategory != "" || results[1].PipelineErrCategory != "" {
		t.Fatalf("PipelineErrCategory = %q/%q, want empty (a downstream exit is not a pipeline failure)", results[0].PipelineErrCategory, results[1].PipelineErrCategory)
	}
}

func TestDirectExecRunner_PipelineYesHeadReturns(t *testing.T) {
	yesPath, err := exec.LookPath("yes")
	if err != nil {
		t.Skipf("yes not available: %v", err)
	}
	headPath, err := exec.LookPath("head")
	if err != nil {
		t.Skipf("head not available: %v", err)
	}
	r := DirectExecRunner{}
	specs := []RunSpec{
		{InvocationID: r.NewInvocationID(), Argv: []string{yesPath}},
		{InvocationID: r.NewInvocationID(), Argv: []string{headPath, "-n", "1"}},
	}

	results, err := pipelineWithin(t, 20*time.Second, 1024, specs)
	if err != nil {
		t.Fatalf("Pipeline error = %v, want nil", err)
	}
	if string(results[1].Stdout) != "y\n" {
		t.Fatalf("final stdout = %q, want %q", results[1].Stdout, "y\n")
	}
	if results[0].StdoutTotal < 2 {
		t.Fatalf("producer StdoutTotal = %d, want at least the one line the consumer read", results[0].StdoutTotal)
	}
}

func TestDirectExecRunner_PipelineLaunchFailureIsShellLikeAtEveryPosition(t *testing.T) {
	cases := []struct {
		name       string
		specs      func(*testing.T) []RunSpec
		failed     int
		wantStdout string
	}{
		{
			name: "first stage",
			specs: func(t *testing.T) []RunSpec {
				return []RunSpec{
					missingBinarySpec(),
					pipelineSpec(t, map[string]string{helperEchoStdin: "1", helperStdout: "ran"}),
				}
			},
			failed:     0,
			wantStdout: "ran",
		},
		{
			name: "middle stage",
			specs: func(t *testing.T) []RunSpec {
				return []RunSpec{
					pipelineSpec(t, map[string]string{helperSpew: "1"}),
					missingBinarySpec(),
					pipelineSpec(t, map[string]string{helperEchoStdin: "1", helperStdout: "ran"}),
				}
			},
			failed:     1,
			wantStdout: "ran",
		},
		{
			name: "last stage",
			specs: func(t *testing.T) []RunSpec {
				return []RunSpec{
					pipelineSpec(t, map[string]string{helperStdout: "upstream"}),
					missingBinarySpec(),
				}
			},
			failed:     1,
			wantStdout: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specs := tc.specs(t)
			results, err := pipelineWithin(t, 20*time.Second, 1024, specs)
			if err != nil {
				t.Fatalf("Pipeline error = %v, want nil (a launch failure is a result-level outcome)", err)
			}
			if len(results) != len(specs) {
				t.Fatalf("results = %d, want one per input spec so every start can be paired", len(results))
			}
			failed := results[tc.failed]
			if failed.ExitCode != -1 || failed.LaunchErrCategory != fserrors.NotFound {
				t.Fatalf("missing-binary stage = %+v, want ExitCode -1 with a not_found launch category", failed)
			}
			if len(failed.Stdout) != 0 || len(failed.Stderr) != 0 || failed.StdoutTotal != 0 || failed.StderrTotal != 0 {
				t.Fatalf("missing-binary stage streams = %+v, want empty streams and zero totals", failed)
			}
			last := results[len(results)-1]
			if string(last.Stdout) != tc.wantStdout {
				t.Fatalf("final stdout = %q, want %q", last.Stdout, tc.wantStdout)
			}
			for i, res := range results {
				if i == tc.failed {
					continue
				}
				if res.Duration <= 0 {
					t.Fatalf("stage %d duration = %v, want a positive wall time (every started stage is waited on, never left running)", i, res.Duration)
				}
			}
		})
	}
}

func TestDirectExecRunner_PipelineBoundsCaptureAndCountsEveryByte(t *testing.T) {
	specs := []RunSpec{
		pipelineSpec(t, map[string]string{helperRepeat: "5000", helperErrRepeat: "300"}),
		pipelineSpec(t, map[string]string{helperEchoStdin: "1", helperErrRepeat: "400"}),
	}

	results, err := pipelineWithin(t, 20*time.Second, 10, specs)
	if err != nil {
		t.Fatalf("Pipeline error = %v, want nil", err)
	}
	for i, want := range []int64{5000, 5000} {
		if len(results[i].Stdout) != 10 {
			t.Fatalf("stage %d retained stdout = %d bytes, want the 10-byte bound", i, len(results[i].Stdout))
		}
		if results[i].StdoutTotal != want {
			t.Fatalf("stage %d StdoutTotal = %d, want %d (every byte read is counted, not just the retained prefix)", i, results[i].StdoutTotal, want)
		}
	}
	for i, want := range []int64{300, 400} {
		if len(results[i].Stderr) != 10 {
			t.Fatalf("stage %d retained stderr = %d bytes, want the 10-byte bound", i, len(results[i].Stderr))
		}
		if results[i].StderrTotal != want {
			t.Fatalf("stage %d StderrTotal = %d, want %d", i, results[i].StderrTotal, want)
		}
	}
	if results[1].ExitCode != 0 {
		t.Fatalf("consumer exit = %d, want 0 (an over-cap stage must still complete, not block on a full pipe)", results[1].ExitCode)
	}
}

func TestDirectExecRunner_PipelineNonPositiveCapKeepsNothingAndStillCounts(t *testing.T) {
	for _, maxCapture := range []int{0, -1} {
		t.Run(strconv.Itoa(maxCapture), func(t *testing.T) {
			specs := []RunSpec{
				pipelineSpec(t, map[string]string{helperStdout: "upstream"}),
				pipelineSpec(t, map[string]string{helperEchoStdin: "1"}),
			}

			results, err := pipelineWithin(t, 20*time.Second, maxCapture, specs)
			if err != nil {
				t.Fatalf("Pipeline error = %v, want nil", err)
			}
			if len(results[1].Stdout) != 0 {
				t.Fatalf("retained stdout = %q, want nothing kept at a non-positive cap", results[1].Stdout)
			}
			if results[1].StdoutTotal != int64(len("upstream")) {
				t.Fatalf("StdoutTotal = %d, want %d (the bytes still flowed through the link)", results[1].StdoutTotal, len("upstream"))
			}
		})
	}
}

func TestDirectExecRunner_PipelineNonFinalNonZeroExitStillRunsSuccessor(t *testing.T) {
	specs := []RunSpec{
		pipelineSpec(t, map[string]string{helperStdout: "kept going", helperExit: "3"}),
		pipelineSpec(t, map[string]string{helperEchoStdin: "1"}),
	}

	results, err := pipelineWithin(t, 20*time.Second, 1024, specs)
	if err != nil {
		t.Fatalf("Pipeline error = %v, want nil", err)
	}
	if results[0].ExitCode != 3 {
		t.Fatalf("stage 0 exit = %d, want 3", results[0].ExitCode)
	}
	if string(results[1].Stdout) != "kept going" || results[1].ExitCode != 0 {
		t.Fatalf("stage 1 = %q/%d, want the upstream bytes and exit 0 (a non-final failure does not stop the pipeline)", results[1].Stdout, results[1].ExitCode)
	}
}

func TestDirectExecRunner_PipelineHonorsOnlyFirstStageStdin(t *testing.T) {
	specs := []RunSpec{
		pipelineSpec(t, map[string]string{helperEchoStdin: "1"}),
		pipelineSpec(t, map[string]string{helperEchoStdin: "1"}),
	}
	specs[0].Stdin = []byte("from the caller")
	specs[1].Stdin = []byte("ignored")

	results, err := pipelineWithin(t, 20*time.Second, 1024, specs)
	if err != nil {
		t.Fatalf("Pipeline error = %v, want nil", err)
	}
	if string(results[1].Stdout) != "from the caller" {
		t.Fatalf("final stdout = %q, want the first stage's stdin carried through; a later stage's Stdin must be ignored", results[1].Stdout)
	}
}

func TestDirectExecRunner_PipelineCancellationJoinsEveryStage(t *testing.T) {
	specs := []RunSpec{
		pipelineSpec(t, map[string]string{helperSpew: "1"}),
		pipelineSpec(t, map[string]string{helperBlock: "1"}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		results []PipelineResult
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := DirectExecRunner{}.Pipeline(ctx, specs, 1024)
		done <- outcome{results: results, err: err}
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case got := <-done:
		if got.err == nil {
			t.Fatalf("Pipeline error = nil, want a cancellation error")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("Pipeline error = %v, want it to wrap context.Canceled", got.err)
		}
		if len(got.results) != 2 {
			t.Fatalf("results = %d, want one per input spec even on cancellation", len(got.results))
		}
		for i, res := range got.results {
			if res.PipelineErrCategory != PipelineFailureCanceled {
				t.Fatalf("stage %d PipelineErrCategory = %q, want %q", i, res.PipelineErrCategory, PipelineFailureCanceled)
			}
			if res.Duration <= 0 {
				t.Fatalf("stage %d duration = %v, want a positive wall time (every started stage is waited on before returning)", i, res.Duration)
			}
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("Pipeline did not return after cancellation")
	}
}

func TestDirectExecRunner_PreflightPipelineRejectsBadSpecsBeforeAnythingRuns(t *testing.T) {
	r := DirectExecRunner{}
	valid := RunSpec{InvocationID: r.NewInvocationID(), Argv: []string{"true"}}
	cases := []struct {
		name  string
		specs []RunSpec
	}{
		{"no stages", nil},
		{"malformed invocation id", []RunSpec{valid, {InvocationID: "not-a-uuid", Argv: []string{"true"}}}},
		{"empty argv", []RunSpec{valid, {InvocationID: r.NewInvocationID()}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.PreflightPipeline(context.Background(), tc.specs)
			if err == nil {
				t.Fatalf("PreflightPipeline error = nil, want a rejection before any process starts")
			}
			if errors.Is(err, ErrPipelineUnsupported) {
				t.Fatalf("PreflightPipeline error = %v, want a validation error, not the unsupported sentinel (which would fall back and run the stages)", err)
			}
		})
	}
}

func TestDirectExecRunner_PreflightPipelineAcceptsValidSpecs(t *testing.T) {
	r := DirectExecRunner{}
	specs := []RunSpec{
		{InvocationID: r.NewInvocationID(), Argv: []string{"true"}},
		{InvocationID: r.NewInvocationID(), Argv: []string{"true"}},
	}
	if err := r.PreflightPipeline(context.Background(), specs); err != nil {
		t.Fatalf("PreflightPipeline error = %v, want nil (DirectExecRunner always supports pipelines)", err)
	}
}

func execBoundedWithin(t *testing.T, timeout time.Duration, spec RunSpec, maxCapture int) (RunResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := DirectExecRunner{}.ExecBounded(ctx, spec, maxCapture)
	if ctx.Err() != nil {
		t.Fatalf("ExecBounded did not finish within %v", timeout)
	}
	return res, err
}

func TestDirectExecRunner_ExecBoundedOverCapRunsToCompletion(t *testing.T) {
	const size = 200_000
	marker := filepath.Join(t.TempDir(), "done")
	spec := helperSpec(t, DirectExecRunner{}.NewInvocationID(), map[string]string{
		helperRepeat:    strconv.Itoa(size),
		helperErrRepeat: strconv.Itoa(size + 1),
		helperTouch:     marker,
		helperExit:      "4",
	})

	res, err := execBoundedWithin(t, 20*time.Second, spec, 100)
	if err != nil {
		t.Fatalf("ExecBounded error: %v", err)
	}
	if res.ExitCode != 4 {
		t.Fatalf("ExitCode = %d, want 4", res.ExitCode)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("last side effect not observed: %v", err)
	}
	if !bytes.Equal(res.Stdout, bytes.Repeat([]byte("a"), 100)) || !bytes.Equal(res.Stderr, bytes.Repeat([]byte("e"), 100)) {
		t.Fatalf("retained stdout %d / stderr %d bytes, want the 100-byte prefix of each", len(res.Stdout), len(res.Stderr))
	}
	if res.StdoutTotal != size || res.StderrTotal != size+1 {
		t.Fatalf("totals = %d/%d, want %d/%d", res.StdoutTotal, res.StderrTotal, size, size+1)
	}
	if res.InvocationID != spec.InvocationID || res.LaunchErrCategory != "" {
		t.Fatalf("InvocationID=%q LaunchErrCategory=%q", res.InvocationID, res.LaunchErrCategory)
	}
}

func TestDirectExecRunner_ExecBoundedUnderCapKeepsEverything(t *testing.T) {
	spec := helperSpec(t, DirectExecRunner{}.NewInvocationID(), map[string]string{
		helperStdout: "hello",
		helperStderr: "warn",
	})

	res, err := execBoundedWithin(t, 20*time.Second, spec, 100)
	if err != nil {
		t.Fatalf("ExecBounded error: %v", err)
	}
	if string(res.Stdout) != "hello" || string(res.Stderr) != "warn" {
		t.Fatalf("Stdout=%q Stderr=%q, want full output", res.Stdout, res.Stderr)
	}
	if res.StdoutTotal != 5 || res.StderrTotal != 4 {
		t.Fatalf("totals = %d/%d, want 5/4", res.StdoutTotal, res.StderrTotal)
	}
}

func TestDirectExecRunner_ExecBoundedMatchesExecOutcomes(t *testing.T) {
	r := DirectExecRunner{}
	dir := t.TempDir()
	noExec := filepath.Join(dir, "noexec")
	if err := os.WriteFile(noExec, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() RunSpec{
		"not found":         func() RunSpec { return RunSpec{InvocationID: r.NewInvocationID(), Argv: []string{"codemeld-no-such-binary-7f3a9c"}} },
		"permission denied": func() RunSpec { return RunSpec{InvocationID: r.NewInvocationID(), Argv: []string{noExec}} },
		"non-zero exit": func() RunSpec {
			return helperSpec(t, r.NewInvocationID(), map[string]string{helperExit: "3"})
		},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			want, err := r.Exec(context.Background(), spec())
			if err != nil {
				t.Fatalf("Exec error: %v", err)
			}
			got, err := execBoundedWithin(t, 20*time.Second, spec(), 100)
			if err != nil {
				t.Fatalf("ExecBounded error: %v", err)
			}
			if got.ExitCode != want.ExitCode || got.LaunchErrCategory != want.LaunchErrCategory {
				t.Fatalf("ExecBounded = (%d, %q), Exec = (%d, %q)", got.ExitCode, got.LaunchErrCategory, want.ExitCode, want.LaunchErrCategory)
			}
		})
	}
}

func TestDirectExecRunner_ExecKeepsFullOutputWithZeroTotals(t *testing.T) {
	const size = 200_000
	r := DirectExecRunner{}
	spec := helperSpec(t, r.NewInvocationID(), map[string]string{
		helperRepeat:    strconv.Itoa(size),
		helperErrRepeat: strconv.Itoa(size),
	})

	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		t.Fatalf("Exec error: %v", err)
	}
	if len(res.Stdout) != size || len(res.Stderr) != size {
		t.Fatalf("Exec retained %d/%d bytes, want %d each", len(res.Stdout), len(res.Stderr), size)
	}
	if res.StdoutTotal != 0 || res.StderrTotal != 0 {
		t.Fatalf("Exec totals = %d/%d, want 0/0", res.StdoutTotal, res.StderrTotal)
	}
}

const groupWriterInterval = 20 * time.Millisecond

func shPath(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	return sh
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func groupWriterArgv(t *testing.T, holdStdout bool) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	grows := filepath.Join(dir, "grows")
	stop := filepath.Join(dir, "stop")
	t.Cleanup(func() {
		_ = os.WriteFile(stop, nil, 0o600)
		if t.Failed() {
			time.Sleep(10 * groupWriterInterval)
		}
	})
	redirect := " >/dev/null 2>&1"
	if holdStdout {
		redirect = ""
	}
	script := `while [ ! -e "$2" ]; do printf x >> "$1"; printf y; sleep 0.02; done` + redirect + ` & wait`
	return []string{shPath(t), "-c", script, "sh", grows, stop}, grows
}

func waitForGrowth(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last int64
	for increases := 0; increases < 3; {
		if time.Now().After(deadline) {
			t.Fatalf("background writer did not grow %s across 3 samples (size %d)", path, last)
		}
		if size := fileSize(path); size > last {
			last = size
			increases++
		}
		time.Sleep(groupWriterInterval / 2)
	}
}

func TestDirectExecRunner_CancelKillsProcessGroup(t *testing.T) {
	r := DirectExecRunner{}
	runs := map[string]func(ctx context.Context, argv []string) error{
		"Exec": func(ctx context.Context, argv []string) error {
			res, err := r.Exec(ctx, RunSpec{InvocationID: r.NewInvocationID(), Argv: argv})
			if err == nil && res.LaunchErrCategory != "" {
				err = fmt.Errorf("LaunchErrCategory = %q, want empty for a started command", res.LaunchErrCategory)
			}
			return err
		},
		"ExecBounded": func(ctx context.Context, argv []string) error {
			res, err := r.ExecBounded(ctx, RunSpec{InvocationID: r.NewInvocationID(), Argv: argv}, 1024)
			if err == nil && res.LaunchErrCategory != "" {
				err = fmt.Errorf("LaunchErrCategory = %q, want empty for a started command", res.LaunchErrCategory)
			}
			return err
		},
		"Pipeline": func(ctx context.Context, argv []string) error {
			specs := []RunSpec{
				pipelineSpec(t, map[string]string{helperBlock: "1"}),
				{InvocationID: r.NewInvocationID(), Argv: argv},
			}
			results, err := r.Pipeline(ctx, specs, 1024)
			if !errors.Is(err, context.Canceled) {
				return fmt.Errorf("Pipeline error = %v, want it to wrap context.Canceled", err)
			}
			for i, res := range results {
				if res.PipelineErrCategory != PipelineFailureCanceled {
					return fmt.Errorf("stage %d PipelineErrCategory = %q, want %q", i, res.PipelineErrCategory, PipelineFailureCanceled)
				}
			}
			return nil
		},
	}
	for name, run := range runs {
		for _, holdStdout := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/holdStdout=%v", name, holdStdout), func(t *testing.T) {
				argv, grows := groupWriterArgv(t, holdStdout)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- run(ctx, argv) }()

				waitForGrowth(t, grows)
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("%s did not return after cancellation", name)
				}

				time.Sleep(2 * groupWriterInterval)
				before := fileSize(grows)
				time.Sleep(15 * groupWriterInterval)
				if after := fileSize(grows); after != before {
					t.Fatalf("file grew from %d to %d bytes after cancellation; the background child outlived its process group", before, after)
				}
			})
		}
	}
}

func TestKillGroupOnCancel_GoneGroupIsProcessDone(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), shPath(t), "-c", ":")
	killGroupOnCancel(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("Cancel on an exited group = %v, want os.ErrProcessDone", err)
	}
}

func TestDirectExecRunner_NormalExitKeepsBackgroundChildDelayedOutput(t *testing.T) {
	r := DirectExecRunner{}
	argv := []string{shPath(t), "-c", "(sleep 0.2; printf late) & printf early"}
	check := func(t *testing.T, res RunResult, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if string(res.Stdout) != "earlylate" || res.ExitCode != 0 || res.LaunchErrCategory != "" {
			t.Fatalf("Stdout=%q ExitCode=%d LaunchErrCategory=%q, want %q/0/empty", res.Stdout, res.ExitCode, res.LaunchErrCategory, "earlylate")
		}
	}
	t.Run("Exec", func(t *testing.T) {
		res, err := r.Exec(context.Background(), RunSpec{InvocationID: r.NewInvocationID(), Argv: argv})
		check(t, res, err)
	})
	t.Run("ExecBounded", func(t *testing.T) {
		res, err := execBoundedWithin(t, 20*time.Second, RunSpec{InvocationID: r.NewInvocationID(), Argv: argv}, 1024)
		check(t, res, err)
	})
}
