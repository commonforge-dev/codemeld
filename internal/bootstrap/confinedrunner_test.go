package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/events"
	"codemeld.dev/codemeld/internal/fserrors"
	"codemeld.dev/codemeld/internal/ids"
	"codemeld.dev/codemeld/internal/locks"
	"codemeld.dev/codemeld/internal/mode"
	"codemeld.dev/codemeld/internal/permissions"
	"codemeld.dev/codemeld/internal/provider"
	cmdrunner "codemeld.dev/codemeld/internal/runner"
	"codemeld.dev/codemeld/internal/securitystate"
	"codemeld.dev/codemeld/internal/sessions"
	"codemeld.dev/codemeld/internal/testsupport"
	"codemeld.dev/codemeld/internal/tools"
	"codemeld.dev/codemeld/internal/vcs"
)

type confineInner struct {
	execs      []cmdrunner.RunSpec
	bounded    []cmdrunner.RunSpec
	boundedCap int
	preflights [][]cmdrunner.RunSpec
	pipelines  [][]cmdrunner.RunSpec
	pipeCap    int
	onBounded  func(cmdrunner.RunSpec)
	onExec     func(cmdrunner.RunSpec)
	exitCode   int
	stdout     []byte
	stderr     []byte
	stderrSize int64
	launchErr  fserrors.Category
	err        error
	results    []cmdrunner.RunResult
}

func (f *confineInner) NewInvocationID() string { return ids.NewV7() }

func (f *confineInner) Exec(_ context.Context, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	f.execs = append(f.execs, spec)
	if f.onExec != nil {
		f.onExec(spec)
	}
	return f.result(spec)
}

func (f *confineInner) ExecBounded(_ context.Context, spec cmdrunner.RunSpec, maxCapture int) (cmdrunner.RunResult, error) {
	f.bounded = append(f.bounded, spec)
	f.boundedCap = maxCapture
	if f.onBounded != nil {
		f.onBounded(spec)
	}
	return f.result(spec)
}

func (f *confineInner) result(spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	if len(f.results) > 0 {
		res := f.results[0]
		f.results = f.results[1:]
		res.InvocationID, res.Stderr = spec.InvocationID, slices.Clone(res.Stderr)
		res.StdoutTotal, res.StderrTotal = int64(len(res.Stdout)), int64(len(res.Stderr))
		return res, f.err
	}
	return cmdrunner.RunResult{
		InvocationID: spec.InvocationID, ExitCode: f.exitCode, LaunchErrCategory: f.launchErr,
		Stdout: f.stdout, Stderr: slices.Clone(f.stderr),
		StdoutTotal: int64(len(f.stdout)), StderrTotal: max(f.stderrSize, int64(len(f.stderr))),
	}, f.err
}

func (f *confineInner) PreflightPipeline(_ context.Context, specs []cmdrunner.RunSpec) error {
	f.preflights = append(f.preflights, specs)
	return nil
}

func (f *confineInner) Pipeline(_ context.Context, specs []cmdrunner.RunSpec, maxCapture int) ([]cmdrunner.PipelineResult, error) {
	f.pipelines = append(f.pipelines, specs)
	f.pipeCap = maxCapture
	return make([]cmdrunner.PipelineResult, len(specs)), nil
}

func (f *confineInner) calls() int {
	return len(f.execs) + len(f.bounded) + len(f.preflights) + len(f.pipelines)
}

func fixedMode(m string) func() string { return func() string { return m } }

func testBlocked(t *testing.T) *permissions.BlockedPaths {
	t.Helper()
	return permissions.NewBlockedPaths(t.TempDir(), nil)
}

func decodeFrame(t *testing.T, stdin []byte) (enforce.Policy, []byte) {
	t.Helper()
	r := bytes.NewReader(stdin)
	p, err := enforce.ReadPolicyFrame(r)
	if err != nil {
		t.Fatalf("decode policy frame: %v", err)
	}
	rest, _ := io.ReadAll(r)
	return p, rest
}

func wantHelperArgv(t *testing.T, got []string, target ...string) {
	t.Helper()
	want := append([]string{"/proc/self/exe", enforce.HelperCommand}, target...)
	if !slices.Equal(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

func programDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func confinedSpec(cwd string, argv ...string) cmdrunner.RunSpec {
	return cmdrunner.RunSpec{InvocationID: ids.NewV7(), Argv: argv, Cwd: cwd}
}

func shellAdapter(conf *confinement, inner *confineInner) *confinedShellRunner {
	return &confinedShellRunner{events: &shellEventRunner{inner: inner, cap: 77}, conf: conf}
}

func runPipe(t *testing.T, r *confinedShellRunner, specs []cmdrunner.RunSpec) {
	t.Helper()
	if err := r.PreflightPipeline(context.Background(), specs); err != nil {
		t.Fatalf("PreflightPipeline: %v", err)
	}
	if _, err := r.Pipeline(context.Background(), specs); err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
}

func TestConfinedRunner_PassThroughKeepsSpecsIdentical(t *testing.T) {
	cwd := t.TempDir()
	launch := launchSnapshot("MISE_DATA_DIR=/data/coding/mise")
	confs := map[string]func(string) *confinement{
		"nil":             func(string) *confinement { return nil },
		"not constrained": func(m string) *confinement { return &confinement{mode: fixedMode(m), tmpDir: cwd, inherited: launch} },
		"constrained build": func(string) *confinement {
			return &confinement{constrained: true, mode: fixedMode(string(mode.Build)), tmpDir: cwd, inherited: launch}
		},
	}
	for name, mk := range confs {
		for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits, mode.Build} {
			t.Run(name+"/"+string(m), func(t *testing.T) {
				conf := mk(string(m))
				spec := confinedSpec(cwd, "ls", "-la")
				spec.Assignments = []string{"FOO=bar"}

				inner := &confineInner{}
				if _, err := shellAdapter(conf, inner).Exec(context.Background(), spec); err != nil {
					t.Fatalf("bash Exec: %v", err)
				}
				vcsInner := &confineInner{}
				if _, err := (&confinedRunner{inner: vcsInner, conf: conf, cap: 9}).Exec(context.Background(), spec); err != nil {
					t.Fatalf("vcs Exec: %v", err)
				}
				for _, got := range [][]cmdrunner.RunSpec{inner.execs, vcsInner.execs} {
					if len(got) != 1 || !reflect.DeepEqual(got[0], spec) || got[0].Env != nil {
						t.Fatalf("inner Exec specs = %+v, want exactly %+v with nil Env", got, spec)
					}
				}
				if len(inner.bounded)+len(vcsInner.bounded) != 0 {
					t.Fatal("an unconfined Exec selected bounded capture")
				}

				pipe := []cmdrunner.RunSpec{confinedSpec(cwd, "ls"), confinedSpec(cwd, "head")}
				pipeInner := &confineInner{}
				runPipe(t, shellAdapter(conf, pipeInner), pipe)
				if len(pipeInner.preflights) != 1 || !reflect.DeepEqual(pipeInner.preflights[0], pipe) ||
					len(pipeInner.pipelines) != 1 || !reflect.DeepEqual(pipeInner.pipelines[0], pipe) || pipeInner.pipeCap != 77 {
					t.Fatalf("pipeline preflight/run = %+v/%+v at cap %d, want the caller's specs at cap 77", pipeInner.preflights, pipeInner.pipelines, pipeInner.pipeCap)
				}

				rInner := &confineInner{}
				r := &confinedRunner{inner: rInner, conf: conf}
				if err := r.PreflightPipeline(context.Background(), pipe); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Pipeline(context.Background(), pipe, 5); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(rInner.pipelines, [][]cmdrunner.RunSpec{pipe}) || rInner.pipeCap != 5 {
					t.Fatalf("runner-level pipeline = %+v at cap %d, want the caller's specs at cap 5", rInner.pipelines, rInner.pipeCap)
				}
			})
		}
	}
}

func TestConfinedRunner_UnrecognizedModeRefusesBeforeRunning(t *testing.T) {
	cwd := t.TempDir()
	for name, modeFn := range map[string]func() string{"nil": nil, "empty": fixedMode(""), "unknown": fixedMode("unknown")} {
		t.Run(name, func(t *testing.T) {
			conf := &confinement{constrained: true, mode: modeFn, tmpDir: cwd}
			inner := &confineInner{}
			if _, err := shellAdapter(conf, inner).Exec(context.Background(), confinedSpec(cwd, "ls")); err == nil {
				t.Fatal("bash Exec error = nil, want a refusal")
			}
			if err := shellAdapter(conf, inner).PreflightPipeline(context.Background(), []cmdrunner.RunSpec{confinedSpec(cwd, "ls")}); err == nil {
				t.Fatal("PreflightPipeline error = nil, want a refusal")
			}
			r := &confinedRunner{inner: inner, conf: conf}
			if _, err := r.Exec(context.Background(), confinedSpec(cwd, "ls")); err == nil {
				t.Fatal("vcs Exec error = nil, want a refusal")
			}
			if err := r.PreflightPipeline(context.Background(), []cmdrunner.RunSpec{confinedSpec(cwd, "ls")}); err == nil {
				t.Fatal("runner-level PreflightPipeline error = nil, want a refusal")
			}
			if inner.calls() != 0 {
				t.Fatalf("inner calls = %d, want none", inner.calls())
			}
		})
	}
}

func TestConfinedRunner_ConfinedPreflightIsUnsupported(t *testing.T) {
	cwd := t.TempDir()
	confs := map[string]*confinement{
		"plan":                     {constrained: true, mode: fixedMode(string(mode.Plan)), blocked: testBlocked(t)},
		"auto_edits without a tmp": {constrained: true, mode: fixedMode(string(mode.AutoEdits)), blocked: testBlocked(t)},
		"context override to plan": {constrained: true, mode: fixedMode(string(mode.Build)), blocked: testBlocked(t)},
	}
	for name, conf := range confs {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if name == "context override to plan" {
				ctx = vcs.WithConfinementMode(ctx, string(mode.Plan))
			}
			pipe := []cmdrunner.RunSpec{confinedSpec(cwd, "ls"), confinedSpec(cwd, "head")}
			inner := &confineInner{}
			if err := shellAdapter(conf, inner).PreflightPipeline(ctx, pipe); !errors.Is(err, cmdrunner.ErrPipelineUnsupported) {
				t.Fatalf("bash PreflightPipeline = %v, want ErrPipelineUnsupported", err)
			}
			if err := (&confinedRunner{inner: inner, conf: conf}).PreflightPipeline(ctx, pipe); !errors.Is(err, cmdrunner.ErrPipelineUnsupported) {
				t.Fatalf("vcs PreflightPipeline = %v, want ErrPipelineUnsupported", err)
			}
			if inner.calls() != 0 {
				t.Fatalf("inner calls = %d, want none", inner.calls())
			}
		})
	}
}

func TestConfinedRunner_ConfinedModesApplyTheFixedEnvironment(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	tmp := t.TempDir()
	lookup := programDir(t, "ls", "head")
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(m), func(t *testing.T) {
			secrets := filepath.Join(home, "secrets")
			conf := &confinement{constrained: true, mode: fixedMode(string(m)), home: home, lookupPath: lookup, tmpDir: tmp,
				projectRoot: cwd, blocked: permissions.NewBlockedPaths(home, []permissions.BlockedEntry{{Path: secrets, Source: "/settings.yaml"}})}
			wantDir := ""
			if m == mode.AutoEdits {
				wantDir = tmp
			}
			spec := confinedSpec(cwd, "ls", "-la")
			spec.Assignments = []string{"FOO=bar"}
			wantEnv, err := cmdrunner.FixedEnvironment(home, cwd, wantDir, lookup, spec.Assignments)
			if err != nil {
				t.Fatal(err)
			}

			for name, run := range map[string]func(*confineInner) error{
				"bash": func(in *confineInner) error {
					_, err := shellAdapter(conf, in).Exec(context.Background(), spec)
					return err
				},
				"vcs": func(in *confineInner) error {
					_, err := (&confinedRunner{inner: in, conf: conf, cap: 33}).Exec(context.Background(), spec)
					return err
				},
			} {
				inner := &confineInner{}
				if err := run(inner); err != nil {
					t.Fatalf("%s Exec: %v", name, err)
				}
				if len(inner.execs) != 0 || len(inner.bounded) != 1 {
					t.Fatalf("%s: exec/bounded = %d/%d, want only ExecBounded", name, len(inner.execs), len(inner.bounded))
				}
				got := inner.bounded[0]
				if !slices.Equal(got.Env, wantEnv) {
					t.Fatalf("%s: env = %v, want %v", name, got.Env, wantEnv)
				}
				wantHelperArgv(t, got.Argv, filepath.Join(lookup, "ls"), "-la")
				policy, rest := decodeFrame(t, got.Stdin)
				if len(rest) != 0 || policy.Mode != string(m) || !slices.Contains(policy.BlockedPaths, secrets) ||
					!slices.Contains(policy.BlockedPaths, filepath.Join(home, ".codemeld")) || len(policy.WriteRoots) != 0 {
					t.Fatalf("%s: policy = %+v (trailing %q)", name, policy, rest)
				}
				if m == mode.Plan && (policy.NoWritePaths != nil || policy.TmpDir != "") {
					t.Fatalf("%s: plan policy = %+v, want no write carve-out or temp folder", name, policy)
				}
				if m == mode.AutoEdits && (policy.TmpDir != tmp || len(policy.NoWritePaths) != 1) {
					t.Fatalf("%s: auto_edits policy = %+v, want tmp %s and the .codemeld carve-out", name, policy, tmp)
				}
				if hasTmp := slices.ContainsFunc(got.Env, func(e string) bool {
					return strings.HasPrefix(e, "TMPDIR=") || strings.HasPrefix(e, "GOCACHE=")
				}); hasTmp != (m == mode.AutoEdits) {
					t.Fatalf("%s: env %v, TMPDIR/GOCACHE present = %v in %s", name, got.Env, hasTmp, m)
				}
			}
			if spec.Env != nil || spec.Argv[0] != "ls" || spec.Stdin != nil {
				t.Fatalf("caller's spec mutated to %+v", spec)
			}
		})
	}
}

func TestConfinedRunner_EmptyLookupPathResolvesOnFixedPATH(t *testing.T) {
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), blocked: testBlocked(t)}
	inner := &confineInner{}
	if _, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), confinedSpec(t.TempDir(), "sh")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(inner.bounded[0].Argv[2])
	if !slices.Contains(filepath.SplitList(cmdrunner.FixedPATH), dir) {
		t.Fatalf("argv[0] = %q, want it inside a FixedPATH directory", inner.bounded[0].Argv[0])
	}
}

func TestConfinedRunner_AutoEditsTempFolderPersistsAcrossCalls(t *testing.T) {
	tmp := t.TempDir()
	lookup := programDir(t, "go")
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.AutoEdits)), lookupPath: lookup, tmpDir: tmp,
		projectRoot: t.TempDir(), blocked: testBlocked(t)}
	inner := &confineInner{}
	calls := 0
	inner.onBounded = func(spec cmdrunner.RunSpec) {
		calls++
		marker := filepath.Join(tmp, "marker")
		if calls == 1 {
			if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("second call: marker gone: %v", err)
		}
	}
	r := shellAdapter(conf, inner)
	for range 2 {
		if _, err := r.Exec(context.Background(), confinedSpec(t.TempDir(), "go", "build")); err != nil {
			t.Fatal(err)
		}
	}
	for _, spec := range inner.bounded {
		if !slices.Contains(spec.Env, "TMPDIR="+tmp) || !slices.Contains(spec.Env, "GOCACHE="+filepath.Join(tmp, "go-build")) {
			t.Fatalf("env = %v, want TMPDIR and GOCACHE in %s", spec.Env, tmp)
		}
	}

	conf.tmpDir = ""
	empty := &confineInner{}
	if _, err := shellAdapter(conf, empty).Exec(context.Background(), confinedSpec(t.TempDir(), "go")); err == nil || empty.calls() != 0 {
		t.Fatalf("err = %v, calls = %d, want a refusal with no inner call", err, empty.calls())
	}
}

func TestConfinedRunner_KeepsProbePinsDropsOtherEnv(t *testing.T) {
	lookup := programDir(t, "go", "mise")
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: lookup, blocked: testBlocked(t)}
	for argv0, pin := range map[string]string{"go": "GOTOOLCHAIN=local", "mise": "MISE_OFFLINE=1"} {
		spec := confinedSpec(t.TempDir(), argv0, "version")
		spec.Env = []string{"PATH=/elsewhere", "SECRET=1", pin}
		inner := &confineInner{}
		if _, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), spec); err != nil {
			t.Fatal(err)
		}
		env := inner.bounded[0].Env
		if !slices.Contains(env, pin) || slices.Contains(env, "SECRET=1") || slices.Contains(env, "PATH=/elsewhere") {
			t.Fatalf("%s env = %v, want %s kept and the incoming entries dropped", argv0, env, pin)
		}
	}
}

func launchSnapshot(environ ...string) []string {
	inherited, _ := cmdrunner.InheritedEnvironment(environ)
	return inherited
}

func envNamed(env []string, name string) []string {
	var got []string
	for _, e := range env {
		if n, _, _ := strings.Cut(e, "="); n == name {
			got = append(got, e)
		}
	}
	return got
}

func requireOneEntryPerName(t *testing.T, env []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		if seen[name] {
			t.Fatalf("env = %q, want one entry for %s", env, name)
		}
		seen[name] = true
	}
}

func TestConfinedRunner_SandboxInheritsTheLaunchEnvironment(t *testing.T) {
	home := t.TempDir()
	tmp := t.TempDir()
	cwd := t.TempDir()
	lookup := programDir(t, "mise")
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.AutoEdits)), home: home, lookupPath: lookup, tmpDir: tmp,
		projectRoot: cwd, blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, "~/.gitconfig")),
		inherited: launchSnapshot("MISE_DATA_DIR=/data/coding/mise", "GOPATH=/launch/go", "PATH=/launch/bin",
			"HOME=/launch/home", "TMPDIR=/launch/tmp", "GOCACHE=/launch/cache", "GITHUB_TOKEN=x")}

	env := confinedExecEnv(t, conf, confinedSpec(cwd, "mise", "run"))
	for name, want := range map[string]string{
		"MISE_DATA_DIR": "/data/coding/mise", "GOPATH": "/launch/go", "PATH": lookup, "HOME": home,
		"TMPDIR": tmp, "GOCACHE": filepath.Join(tmp, "go-build"),
	} {
		if got := envNamed(env, name); !slices.Equal(got, []string{name + "=" + want}) {
			t.Errorf("%s entries = %q, want exactly %s=%s", name, got, name, want)
		}
	}
	if envNamed(env, "GITHUB_TOKEN") != nil || env[len(env)-1] != wantGitNeutralizer {
		t.Fatalf("env = %q, want no GITHUB_TOKEN and the git override last", env)
	}
	requireOneEntryPerName(t, env)

	spec := confinedSpec(cwd, "mise", "run")
	spec.Assignments = []string{"MISE_DATA_DIR=other", "MYAPP_TOKEN=x", "DATABASE_URL=postgres://u:p@h/db"}
	env = confinedExecEnv(t, conf, spec)
	for _, want := range spec.Assignments {
		name, _, _ := strings.Cut(want, "=")
		if got := envNamed(env, name); !slices.Equal(got, []string{want}) {
			t.Errorf("%s entries = %q, want exactly the assignment %s", name, got, want)
		}
	}
	if env[len(env)-1] != wantGitNeutralizer {
		t.Fatalf("env = %q, want the git override last", env)
	}
	requireOneEntryPerName(t, env)

	spec.Assignments = []string{"LD_PRELOAD=x"}
	inner := &confineInner{}
	_, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), spec)
	var assignErr *cmdrunner.EnvAssignmentError
	if !errors.As(err, &assignErr) || assignErr.Name != "LD_PRELOAD" || inner.calls() != 0 {
		t.Fatalf("err = %v, calls = %d; want an LD_PRELOAD assignment refusal before any run", err, inner.calls())
	}
}

func TestConfinedRunner_RunSpecEnvAndPlanTempStayOutOfTheSandbox(t *testing.T) {
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: t.TempDir(), lookupPath: programDir(t, "go"),
		blocked: testBlocked(t), inherited: launchSnapshot("MISE_DATA_DIR=/data/coding/mise", "TMPDIR=/launch/tmp", "GOCACHE=/launch/cache")}
	spec := confinedSpec(t.TempDir(), "go", "env")
	spec.Env = []string{"MISE_DATA_DIR=/injected", "INJECTED=1", "TMPDIR=/injected"}
	env := confinedExecEnv(t, conf, spec)
	if !slices.Equal(envNamed(env, "MISE_DATA_DIR"), []string{"MISE_DATA_DIR=/data/coding/mise"}) || envNamed(env, "INJECTED") != nil ||
		envNamed(env, "TMPDIR") != nil || envNamed(env, "GOCACHE") != nil {
		t.Fatalf("env = %q, want the launch MISE_DATA_DIR only and no RunSpec.Env, TMPDIR or GOCACHE entries", env)
	}
}

func TestConfinedRunner_ParallelPreparationsKeepTheLaunchSnapshot(t *testing.T) {
	home := t.TempDir()
	snapshot := launchSnapshot("MISE_DATA_DIR=/data/coding/mise", "GOPATH=/launch/go")
	want := slices.Clone(snapshot)
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: programDir(t, "go"),
		blocked: testBlocked(t), inherited: slices.Grow(snapshot, 64)}
	const n = 8
	envs := make([][]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			spec := confinedSpec(home, "go", "env")
			spec.Assignments = []string{"JOB=" + strconv.Itoa(i)}
			prepared, err := conf.prepare(spec, "", conf.blocked.Current())
			if err != nil {
				t.Error(err)
				return
			}
			envs[i] = prepared.Env
		})
	}
	wg.Wait()
	if !slices.Equal(conf.inherited, want) {
		t.Fatalf("stored snapshot = %q, want %q", conf.inherited, want)
	}
	for i, env := range envs {
		if !slices.Equal(envNamed(env, "JOB"), []string{"JOB=" + strconv.Itoa(i)}) || !slices.Contains(env, "GOPATH=/launch/go") {
			t.Errorf("command %d env = %q, want its own JOB and the launch GOPATH", i, env)
		}
	}
}

const wantGitNeutralizer = "GIT_CONFIG_GLOBAL=/dev/null"

func blockedEntries(t *testing.T, home string, raws ...string) []permissions.BlockedEntry {
	t.Helper()
	var entries []permissions.BlockedEntry
	for _, raw := range raws {
		path, err := permissions.ExpandBlockedEntry(home, raw)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, permissions.BlockedEntry{Path: path, Source: filepath.Join(home, "settings.yaml")})
	}
	return entries
}

func gitGlobalEntries(env []string) []string {
	var got []string
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_GLOBAL=") {
			got = append(got, e)
		}
	}
	return got
}

func confinedExecEnv(t *testing.T, conf *confinement, spec cmdrunner.RunSpec) []string {
	t.Helper()
	inner := &confineInner{}
	if _, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if len(inner.bounded) != 1 {
		t.Fatalf("bounded runs = %d, want 1", len(inner.bounded))
	}
	return inner.bounded[0].Env
}

func TestConfinedRunner_BlockedGitConfigNeutralizesTheGlobalConfig(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	tmp := t.TempDir()
	lookup := programDir(t, "git")
	for _, tc := range []struct {
		name    string
		blocked []string
		want    bool
	}{
		{"both default entries", []string{"~/.gitconfig", "~/.config/git/config"}, true},
		{"only ~/.gitconfig", []string{"~/.gitconfig"}, true},
		{"only ~/.config/git/config", []string{"~/.config/git/config"}, true},
		{"covering parent folder", []string{"~/.config"}, true},
		{"neither path covered", []string{"~/.config/hg/hgrc", "~/.hgrc"}, false},
	} {
		for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
			t.Run(tc.name+"/"+string(m), func(t *testing.T) {
				conf := &confinement{constrained: true, mode: fixedMode(string(m)), home: home, lookupPath: lookup, tmpDir: tmp,
					projectRoot: cwd, blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, tc.blocked...))}
				wantDir := ""
				if m == mode.AutoEdits {
					wantDir = tmp
				}
				base, err := cmdrunner.FixedEnvironment(home, cwd, wantDir, lookup, []string{"FOO=bar"})
				if err != nil {
					t.Fatal(err)
				}
				want := base
				if tc.want {
					want = append(slices.Clone(base), wantGitNeutralizer)
				}
				spec := confinedSpec(cwd, "git", "status")
				spec.Assignments = []string{"FOO=bar"}
				spec.Env = []string{"GIT_CONFIG_GLOBAL=/elsewhere/gitconfig"}
				if env := confinedExecEnv(t, conf, spec); !slices.Equal(env, want) {
					t.Fatalf("env = %q, want %q", env, want)
				}
			})
		}
	}
}

func TestConfinedRunner_GitConfigCheckFollowsSymlinksAndTheEffectiveHome(t *testing.T) {
	outside := t.TempDir()
	realConfig := filepath.Join(outside, "real-gitconfig")
	if err := os.WriteFile(realConfig, []byte("[user]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lookup := programDir(t, "git")
	outsideEntry := []permissions.BlockedEntry{{Path: realConfig, Source: filepath.Join(outside, "settings.yaml")}}

	t.Run("symlinked config resolves into a blocked file", func(t *testing.T) {
		home := t.TempDir()
		if err := os.Symlink(realConfig, filepath.Join(home, ".gitconfig")); err != nil {
			t.Fatal(err)
		}
		conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: lookup,
			blocked: permissions.NewBlockedPaths(home, outsideEntry)}
		if got := gitGlobalEntries(confinedExecEnv(t, conf, confinedSpec(home, "git"))); !slices.Equal(got, []string{wantGitNeutralizer}) {
			t.Fatalf("GIT_CONFIG_GLOBAL entries = %q, want only %q", got, wantGitNeutralizer)
		}
	})

	t.Run("empty confinement home falls back to the snapshot home", func(t *testing.T) {
		snapshotHome := t.TempDir()
		conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: lookup,
			blocked: permissions.NewBlockedPaths(snapshotHome, blockedEntries(t, snapshotHome, "~/.config"))}
		env := confinedExecEnv(t, conf, confinedSpec(snapshotHome, "git"))
		if got := gitGlobalEntries(env); !slices.Equal(got, []string{wantGitNeutralizer}) {
			t.Fatalf("GIT_CONFIG_GLOBAL entries = %q, want only %q", got, wantGitNeutralizer)
		}
		if !slices.Contains(env, "HOME="+snapshotHome) {
			t.Fatalf("env = %q, want HOME=%s", env, snapshotHome)
		}
	})

	t.Run("no home never checks cwd-relative config paths", func(t *testing.T) {
		cwd := t.TempDir()
		if err := os.Symlink(realConfig, filepath.Join(cwd, ".gitconfig")); err != nil {
			t.Fatal(err)
		}
		t.Chdir(cwd)
		conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: lookup}
		prepared, err := conf.prepare(confinedSpec(cwd, "git"), "", permissions.NewBlockedPaths("", outsideEntry))
		if err != nil {
			t.Fatal(err)
		}
		env := prepared.Env
		if got := gitGlobalEntries(env); len(got) != 0 {
			t.Fatalf("GIT_CONFIG_GLOBAL entries = %q, want none without a home", got)
		}
		if !slices.Contains(env, "HOME=") {
			t.Fatalf("env = %q, want an empty HOME", env)
		}
	})
}

func TestConfinedRunner_OneBlockedSnapshotFeedsEnvironmentAndPolicy(t *testing.T) {
	home := canonicalTempDir(t)
	gitEntries := blockedEntries(t, home, "~/.gitconfig")
	reloads := 0
	blocked := permissions.NewLiveBlockedPaths(home, home, nil, func() permissions.BlockedReload {
		reloads++
		if reloads%2 == 1 {
			return permissions.BlockedReload{Changed: true, Entries: gitEntries}
		}
		return permissions.BlockedReload{Changed: true}
	})
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: programDir(t, "git"), blocked: blocked}
	inner := &confineInner{}
	r := &confinedRunner{inner: inner, conf: conf}
	for range 2 {
		if _, err := r.Exec(context.Background(), confinedSpec(home, "git", "status")); err != nil {
			t.Fatal(err)
		}
	}
	if reloads != 2 {
		t.Fatalf("blocked-list reloads = %d over two commands, want one each", reloads)
	}
	gitconfig := filepath.Join(home, ".gitconfig")
	for i, want := range []bool{true, false} {
		spec := inner.bounded[i]
		policy, _ := decodeFrame(t, spec.Stdin)
		neutralized := slices.Contains(spec.Env, wantGitNeutralizer)
		if inPolicy := slices.Contains(policy.BlockedPaths, gitconfig); neutralized != want || inPolicy != want {
			t.Fatalf("command %d: override %v, policy blocks %s %v; want both %v", i+1, neutralized, gitconfig, inPolicy, want)
		}
	}
}

func TestConfinedRunner_GitAssignmentStaysRefused(t *testing.T) {
	home := t.TempDir()
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: programDir(t, "git"),
		blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, "~/.gitconfig"))}
	spec := confinedSpec(home, "git", "status")
	spec.Assignments = []string{"GIT_CONFIG_GLOBAL=x"}
	inner := &confineInner{}
	_, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), spec)
	var assignErr *cmdrunner.EnvAssignmentError
	if !errors.As(err, &assignErr) || assignErr.Name != "GIT_CONFIG_GLOBAL" || inner.calls() != 0 {
		t.Fatalf("err = %v, calls = %d; want a GIT_CONFIG_GLOBAL assignment refusal before any run", err, inner.calls())
	}
}

func TestConfinedRunner_UnsandboxedRunsGetNoGitOverride(t *testing.T) {
	home := t.TempDir()
	blocked := permissions.NewBlockedPaths(home, blockedEntries(t, home, "~/.gitconfig", "~/.config/git/config"))
	for name, conf := range map[string]*confinement{
		"self-test failed": {mode: fixedMode(string(mode.AutoEdits)), home: home, blocked: blocked, tmpDir: t.TempDir()},
		"build mode":       {constrained: true, mode: fixedMode(string(mode.Build)), home: home, blocked: blocked},
	} {
		t.Run(name, func(t *testing.T) {
			spec := confinedSpec(home, "git", "status")
			inner := &confineInner{}
			if _, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
			if len(inner.execs) != 1 || !reflect.DeepEqual(inner.execs[0], spec) || inner.execs[0].Env != nil {
				t.Fatalf("inner runs = %+v, want the caller's spec unchanged with nil Env", inner.execs)
			}
		})
	}
}

func TestConfinedRunner_ContextModeOverridesTheModeFunction(t *testing.T) {
	lookup := programDir(t, "hg")
	for _, override := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(override), func(t *testing.T) {
			conf := &confinement{constrained: true, mode: fixedMode(string(mode.Build)), lookupPath: lookup,
				blocked: testBlocked(t), projectRoot: t.TempDir(), tmpDir: t.TempDir()}
			inner := &confineInner{}
			ctx := vcs.WithConfinementMode(context.Background(), string(override))
			if _, err := (&confinedRunner{inner: inner, conf: conf, cap: 12}).Exec(ctx, confinedSpec(t.TempDir(), "hg", "status")); err != nil {
				t.Fatal(err)
			}
			if len(inner.bounded) != 1 || inner.boundedCap != 12 || len(inner.execs) != 0 {
				t.Fatalf("bounded/exec = %d/%d at cap %d, want the override's confined run at cap 12", len(inner.bounded), len(inner.execs), inner.boundedCap)
			}
			if policy, _ := decodeFrame(t, inner.bounded[0].Stdin); policy.Mode != string(override) {
				t.Fatalf("policy mode = %q, want the override %q", policy.Mode, override)
			}
		})
	}
}

func TestConfinedRunner_BuildPinRunsUnconfinedUnderAConfinedLiveMode(t *testing.T) {
	lookup := programDir(t, "hg")
	for _, live := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(live), func(t *testing.T) {
			conf := &confinement{constrained: true, mode: fixedMode(string(live)), lookupPath: lookup,
				blocked: testBlocked(t), projectRoot: t.TempDir(), tmpDir: t.TempDir()}
			ctx := vcs.WithConfinementMode(context.Background(), string(mode.Build))
			inner := &confineInner{}
			if _, err := (&confinedRunner{inner: inner, conf: conf, cap: 12}).Exec(ctx, confinedSpec(t.TempDir(), "hg", "status")); err != nil {
				t.Fatal(err)
			}
			shell := &confineInner{}
			if _, err := shellAdapter(conf, shell).Exec(ctx, confinedSpec(t.TempDir(), "hg", "status")); err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string]*confineInner{"vcs": inner, "shell": shell} {
				if len(got.execs) != 1 || len(got.bounded) != 0 || !slices.Equal(got.execs[0].Argv, []string{"hg", "status"}) {
					t.Fatalf("%s bounded/exec = %d/%d, want the Build pin's one unconfined run", name, len(got.bounded), len(got.execs))
				}
			}
		})
	}
}

func TestConfinedRunner_UnpinnedRunFollowsTheLiveMode(t *testing.T) {
	live := string(mode.Plan)
	conf := &confinement{constrained: true, mode: func() string { return live }, lookupPath: programDir(t, "hg"), blocked: testBlocked(t)}
	inner := &confineInner{}
	r := &confinedRunner{inner: inner, conf: conf, cap: 12}
	if _, err := r.Exec(context.Background(), confinedSpec(t.TempDir(), "hg", "status")); err != nil {
		t.Fatal(err)
	}
	live = string(mode.Build)
	if _, err := r.Exec(context.Background(), confinedSpec(t.TempDir(), "hg", "status")); err != nil {
		t.Fatal(err)
	}
	if len(inner.bounded) != 1 || len(inner.execs) != 1 {
		t.Fatalf("bounded/exec = %d/%d, want one confined Plan run then one unconfined Build run", len(inner.bounded), len(inner.execs))
	}
	if policy, _ := decodeFrame(t, inner.bounded[0].Stdin); policy.Mode != string(mode.Plan) {
		t.Fatalf("policy mode = %q, want plan", policy.Mode)
	}
}

func TestConfinedRunner_ConfinedExecNeedsBoundedCapability(t *testing.T) {
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan))}
	inner := &fakeDispatchRunner{}
	if _, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), confinedSpec(t.TempDir(), "sh")); err == nil || inner.callCount() != 0 {
		t.Fatalf("err = %v, exec calls = %d, want a refusal and no fall-back to Exec", err, inner.callCount())
	}
}

func TestConfinedRunner_PipelineRunsThePreflightSnapshot(t *testing.T) {
	cwd := t.TempDir()
	confs := map[string]*confinement{
		"nil":               nil,
		"not constrained":   {mode: fixedMode(string(mode.Plan))},
		"constrained build": {constrained: true, mode: fixedMode(string(mode.Build))},
	}
	mutate := func(pipe []cmdrunner.RunSpec) {
		pipe[0].Argv[1] = "-R"
		pipe[1].Argv[0] = "rm"
		pipe[1].Assignments[0] = "FOO=changed"
	}
	for name, conf := range confs {
		t.Run(name, func(t *testing.T) {
			pipe := []cmdrunner.RunSpec{confinedSpec(cwd, "ls", "-la"), confinedSpec(cwd, "head")}
			pipe[1].Assignments = []string{"FOO=bar"}
			store := mkStore(t)
			inner := &confineInner{}
			r := &confinedShellRunner{events: &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64}, conf: conf}
			if err := r.PreflightPipeline(context.Background(), pipe); err != nil {
				t.Fatalf("PreflightPipeline: %v", err)
			}
			snapshot := cloneSpecs(inner.preflights[0])
			mutate(pipe)
			if _, err := r.Pipeline(context.Background(), pipe); err != nil {
				t.Fatalf("Pipeline: %v", err)
			}
			if !reflect.DeepEqual(inner.pipelines[0], snapshot) {
				t.Fatalf("bash pipeline ran %+v, want the preflight snapshot %+v", inner.pipelines[0], snapshot)
			}
			reloaded := reloadStore(t, store)
			starts := decodeStoreEvents[events.ToolExecStart](t, reloaded, events.KindToolExecStart)
			ends := decodeStoreEvents[events.ToolExecEnd](t, reloaded, events.KindToolExecEnd)
			want := []string{"ls -la", "head"}
			if len(starts) != 2 || len(ends) != 2 {
				t.Fatalf("tool_exec events = %d start/%d end, want two pairs", len(starts), len(ends))
			}
			for i := range want {
				if starts[i].Subject != want[i] || ends[i].Subject != want[i] {
					t.Fatalf("record %d subjects = %q/%q, want %q", i, starts[i].Subject, ends[i].Subject, want[i])
				}
			}

			pipe = []cmdrunner.RunSpec{confinedSpec(cwd, "ls", "-la"), confinedSpec(cwd, "head")}
			pipe[1].Assignments = []string{"FOO=bar"}
			vcsInner := &confineInner{}
			vr := &confinedRunner{inner: vcsInner, conf: conf}
			if err := vr.PreflightPipeline(context.Background(), pipe); err != nil {
				t.Fatalf("vcs PreflightPipeline: %v", err)
			}
			snapshot = cloneSpecs(vcsInner.preflights[0])
			mutate(pipe)
			if _, err := vr.Pipeline(context.Background(), pipe, 5); err != nil {
				t.Fatalf("vcs Pipeline: %v", err)
			}
			if !reflect.DeepEqual(vcsInner.pipelines[0], snapshot) {
				t.Fatalf("vcs pipeline ran %+v, want the preflight snapshot %+v", vcsInner.pipelines[0], snapshot)
			}
		})
	}
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestConfinedRunner_AutoEditsPolicyWriteRoots(t *testing.T) {
	project := canonicalTempDir(t)
	outside := canonicalTempDir(t)
	for _, dir := range []string{"a/x", ".codemeld"} {
		if err := os.MkdirAll(filepath.Join(project, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "b.go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"l1": filepath.Join(project, ".codemeld"), "l2": outside, "l3": filepath.Join(project, "a", "x")} {
		if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
			t.Fatal(err)
		}
	}
	lookup := programDir(t, "ls")
	tmp := t.TempDir()
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.AutoEdits)), lookupPath: lookup, tmpDir: tmp,
		projectRoot: project, blocked: testBlocked(t)}
	inner := &confineInner{}
	r := shellAdapter(conf, inner)
	if _, err := r.Exec(context.Background(), confinedSpec(project, "ls")); err != nil {
		t.Fatal(err)
	}
	policy, _ := decodeFrame(t, inner.bounded[0].Stdin)
	wantRoots := []string{filepath.Join(project, "a"), filepath.Join(project, "b.go"), filepath.Join(project, "a", "x")}
	if !slices.Equal(policy.WriteRoots, wantRoots) || !slices.Equal(policy.NoWritePaths, []string{filepath.Join(project, ".codemeld")}) {
		t.Fatalf("write roots/no-write = %q/%q, want %q/[%s/.codemeld]", policy.WriteRoots, policy.NoWritePaths, wantRoots, project)
	}
	if !slices.Contains(inner.bounded[0].Env, "TMPDIR="+policy.TmpDir) || policy.TmpDir != tmp {
		t.Fatalf("policy tmp %q, env %v, want TMPDIR=%s", policy.TmpDir, inner.bounded[0].Env, tmp)
	}

	switched := t.TempDir()
	conf.tmpDir = switched
	if _, err := r.Exec(context.Background(), confinedSpec(project, "ls")); err != nil {
		t.Fatal(err)
	}
	if policy, _ := decodeFrame(t, inner.bounded[1].Stdin); policy.TmpDir != switched {
		t.Fatalf("after a session switch tmp = %q, want %q", policy.TmpDir, switched)
	}
}

func liveWritableConfinement(t *testing.T, current string, yaml string) (rereadFixture, *confinement) {
	t.Helper()
	f := newRereadFixture(t)
	f.writeGlobal(t)
	writeProjectSettings(t, f.project, yaml)
	return f, &confinement{constrained: true, mode: fixedMode(current), lookupPath: programDir(t, "ls"), tmpDir: t.TempDir(),
		projectRoot: f.project, writable: liveFoldersReader(t, f, []string{f.global, f.projectFile}, f.home), blocked: testBlocked(t)}
}

func policyWriteRoots(t *testing.T, conf *confinement) []string {
	t.Helper()
	p, err := conf.policy(conf.mode(), conf.tmpDir, "", conf.blocked.Current())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p.WriteRoots
}

func TestConfinedRunner_PolicyAppendsWritableFoldersAfterProjectRoots(t *testing.T) {
	w, v := declaredScopeDir(t), declaredScopeDir(t)
	for _, tc := range []struct {
		name    string
		entries func(project string) []string
		want    func(project string) []string
	}{
		{"one folder", func(string) []string { return []string{w} }, func(project string) []string {
			return []string{filepath.Join(project, "a"), filepath.Join(project, "b.go"), w}
		}},
		{"deduplicated", func(project string) []string { return []string{w, filepath.Join(project, "a"), v, w, v} }, func(project string) []string {
			return []string{filepath.Join(project, "a"), filepath.Join(project, "b.go"), w, v}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRereadFixture(t)
			if err := os.Mkdir(filepath.Join(f.project, "a"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.project, "b.go"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			f.writeGlobal(t)
			writeProjectSettings(t, f.project, writableFoldersYAML(tc.entries(f.project)...))
			frame := func(current string) enforce.Policy {
				conf := &confinement{constrained: true, mode: fixedMode(current), lookupPath: programDir(t, "ls"), tmpDir: t.TempDir(),
					projectRoot: f.project, writable: liveFoldersReader(t, f, []string{f.global, f.projectFile}, f.home), blocked: testBlocked(t)}
				inner := &confineInner{}
				if _, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), confinedSpec(f.project, "ls")); err != nil {
					t.Fatal(err)
				}
				policy, _ := decodeFrame(t, inner.bounded[0].Stdin)
				return policy
			}
			if got, want := frame(string(mode.AutoEdits)).WriteRoots, tc.want(f.project); !slices.Equal(got, want) {
				t.Fatalf("auto_edits write roots = %q, want %q", got, want)
			}
			if got := frame(string(mode.Plan)).WriteRoots; len(got) != 0 {
				t.Fatalf("plan write roots = %q, want none", got)
			}
		})
	}
}

func requirePrivateTempOnly(t *testing.T, conf *confinement, project, launchTmp string) {
	t.Helper()
	if conf == nil || !conf.constrained || conf.tmpDir == "" {
		t.Fatalf("confinement = %+v, want a constrained confinement with a private temp folder", conf)
	}
	inner := &confineInner{}
	if _, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), confinedSpec(project, "ls")); err != nil {
		t.Fatal(err)
	}
	policy, _ := decodeFrame(t, inner.bounded[0].Stdin)
	if slices.Contains(policy.WriteRoots, "/tmp") || slices.Contains(policy.WriteRoots, launchTmp) {
		t.Fatalf("auto_edits write roots = %q, want neither /tmp nor the launch TMPDIR %s", policy.WriteRoots, launchTmp)
	}
	if policy.TmpDir != conf.tmpDir || filepath.Dir(policy.TmpDir) != launchTmp {
		t.Fatalf("policy tmp = %q, want the private session folder %q inside %s", policy.TmpDir, conf.tmpDir, launchTmp)
	}
	if !slices.Contains(inner.bounded[0].Env, "TMPDIR="+policy.TmpDir) {
		t.Fatalf("command env = %v, want TMPDIR=%s", inner.bounded[0].Env, policy.TmpDir)
	}
	plan, err := conf.policy(string(mode.Plan), "", "", conf.blocked.Current())
	if err != nil || len(plan.WriteRoots) != 0 || plan.TmpDir != "" {
		t.Fatalf("plan policy = %+v, %v; want no write roots and no temp folder", plan, err)
	}
}

func TestLaunchConfinement_PolicyReadsTheLiveWritableFolders(t *testing.T) {
	home, project, folder := canonicalTempDir(t), canonicalTempDir(t), canonicalTempDir(t)
	t.Setenv("HOME", canonicalTempDir(t))
	settings := projectSettingsPath(project)
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("writable_folders: [\""+folder+"\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	composition, err := defaultComposeConfig(nil, project)
	if err != nil {
		t.Fatalf("defaultComposeConfig: %v", err)
	}

	for _, tc := range []struct {
		name, home string
		want       []string
	}{
		{"resolved home", home, []string{folder}},
		{"empty home", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cache *config.Cache
			out := testsupport.CaptureStderr(t, func() {
				cache, err = config.NewCache(composition.Config, project, []string{SettingsPath(tc.home), settings}, tc.home)
			})
			if err != nil {
				t.Fatalf("config.NewCache: %v", err)
			}
			conf := launchConfinement(enforce.Resolution{SelfTestPassed: true}, t.TempDir(), mode.NewActiveState(mode.AutoEdits, mode.SourceDefault),
				cache, tc.home, securitystate.Policy{Blocked: testBlocked(t)}, nil)
			if got := policyWriteRoots(t, conf); !slices.Equal(got, tc.want) || strings.Contains(out, "writable_folders") {
				t.Fatalf("policy write roots = %q, stderr = %q; want %q and no writable-folder notice", got, out, tc.want)
			}
		})
	}
}

func TestConfinedRunner_NilReaderOrDegradedSettingsGrantNoDeclaredFolders(t *testing.T) {
	folder := declaredScopeDir(t)
	f, conf := liveWritableConfinement(t, string(mode.AutoEdits), writableFoldersYAML(folder))
	if err := os.Mkdir(filepath.Join(f.project, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(f.project, "src")
	requireBase := func(t *testing.T, label string, want ...string) {
		t.Helper()
		p, err := conf.policy(string(mode.AutoEdits), conf.tmpDir, "", conf.blocked.Current())
		if err != nil {
			t.Fatalf("%s: policy: %v", label, err)
		}
		if !slices.Equal(p.WriteRoots, append([]string{own}, want...)) || p.TmpDir != conf.tmpDir ||
			!slices.Equal(p.NoWritePaths, []string{filepath.Join(f.project, ".codemeld")}) {
			t.Fatalf("%s: policy = %+v, want write roots %q, the private temp folder and the .codemeld no-write path", label, p, append([]string{own}, want...))
		}
	}
	requireBase(t, "valid", folder)

	reader := conf.writable
	conf.writable = nil
	requireBase(t, "nil reader")
	conf.writable = reader

	var problems map[string]string
	conf.blocked = permissions.NewLiveBlockedPaths(f.home, f.project, nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Problems: problems}
	})
	for _, broken := range []string{f.projectFile, f.global} {
		problems = map[string]string{broken: "can't be parsed"}
		requireBase(t, "degraded by "+broken)
		problems = nil
		requireBase(t, "recovered from "+broken, folder)
	}
}

func TestConfinedRunner_PolicyFollowsAFailedReadUntilValidSettingsReturn(t *testing.T) {
	folder := declaredScopeDir(t)
	f, conf := liveWritableConfinement(t, string(mode.AutoEdits), writableFoldersYAML(folder))
	if got := policyWriteRoots(t, conf); !slices.Equal(got, []string{folder}) {
		t.Fatalf("valid write roots = %q, want [%s]", got, folder)
	}
	rewriteSettings(t, f.projectFile, "writable_folders: [\n")
	if got := policyWriteRoots(t, conf); len(got) != 0 {
		t.Fatalf("malformed write roots = %q, want none", got)
	}
	rewriteSettings(t, f.projectFile, writableFoldersYAML(folder))
	if got := policyWriteRoots(t, conf); !slices.Equal(got, []string{folder}) {
		t.Fatalf("restored write roots = %q, want [%s]", got, folder)
	}
}

func TestConfinedRunner_BothAdaptersFrameTheLiveWritableFolders(t *testing.T) {
	first, added := declaredScopeDir(t), declaredScopeDir(t)
	for name, exec := range map[string]func(*confinement, *confineInner) error{
		"bash": func(conf *confinement, in *confineInner) error {
			_, err := shellAdapter(conf, in).Exec(context.Background(), confinedSpec(conf.projectRoot, "ls"))
			return err
		},
		"vcs": func(conf *confinement, in *confineInner) error {
			_, err := (&confinedRunner{inner: in, conf: conf}).Exec(context.Background(), confinedSpec(conf.projectRoot, "ls"))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, conf := liveWritableConfinement(t, string(mode.AutoEdits), writableFoldersYAML(first))
			inner := &confineInner{}
			steps := []struct {
				yaml string
				want []string
			}{
				{"", []string{first}},
				{writableFoldersYAML(first, added), []string{first, added}},
				{writableFoldersYAML(added), []string{added}},
			}
			for i, step := range steps {
				if step.yaml != "" {
					rewriteSettings(t, f.projectFile, step.yaml)
				}
				if err := exec(conf, inner); err != nil {
					t.Fatal(err)
				}
				if policy, _ := decodeFrame(t, inner.bounded[i].Stdin); !slices.Equal(policy.WriteRoots, step.want) {
					t.Fatalf("command %d write roots = %q, want %q", i, policy.WriteRoots, step.want)
				}
			}
		})
	}
}

func TestConfinedRunner_AHeldSettingsWriterLockFailsClosedThenRecovers(t *testing.T) {
	first, next := declaredScopeDir(t), declaredScopeDir(t)
	f, conf := liveWritableConfinement(t, string(mode.AutoEdits), writableFoldersYAML(first))
	if got := policyWriteRoots(t, conf); !slices.Equal(got, []string{first}) {
		t.Fatalf("primed write roots = %q, want [%s]", got, first)
	}
	release, reason, err := locks.TryAcquire(f.projectFile + ".lock")
	if release == nil {
		t.Fatalf("TryAcquire = %q, %v; want the sidecar lock", reason, err)
	}
	rewriteSettings(t, f.projectFile, writableFoldersYAML(next))
	built := make(chan []string, 1)
	go func() {
		p, err := conf.policy(string(mode.AutoEdits), conf.tmpDir, "", conf.blocked.Current())
		if err != nil {
			t.Errorf("policy: %v", err)
		}
		built <- p.WriteRoots
	}()
	select {
	case got := <-built:
		if len(got) != 0 {
			t.Fatalf("write roots while the writer holds the lock = %q, want none", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("policy build waited on the held settings lock")
	}
	release()
	if got := policyWriteRoots(t, conf); !slices.Equal(got, []string{next}) {
		t.Fatalf("write roots after release = %q, want [%s]", got, next)
	}
}

func TestConfinedRunner_OverlappingPolicyBuildsSeeACompleteFolderList(t *testing.T) {
	old := []string{declaredScopeDir(t), declaredScopeDir(t)}
	updated := []string{declaredScopeDir(t), declaredScopeDir(t)}
	f, conf := liveWritableConfinement(t, string(mode.AutoEdits), writableFoldersYAML(old...))
	building := make(chan struct{}, 8)
	conf.blocked = permissions.NewLiveBlockedPaths(f.home, f.project, nil, func() permissions.BlockedReload {
		building <- struct{}{}
		return permissions.BlockedReload{}
	})
	if got := policyWriteRoots(t, conf); !slices.Equal(got, old) {
		t.Fatalf("primed write roots = %q, want %q", got, old)
	}
	<-building

	reading, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	real := readHeldSettings
	readHeldSettings = func(parent *os.File, name string) ([]byte, fs.FileInfo, error) {
		once.Do(func() {
			close(reading)
			<-proceed
		})
		return real(parent, name)
	}
	t.Cleanup(func() { readHeldSettings = real })
	rewriteSettings(t, f.projectFile, writableFoldersYAML(old...))

	results := make(chan []string, 2)
	build := func() {
		p, err := conf.policy(string(mode.AutoEdits), conf.tmpDir, "", conf.blocked.Current())
		if err != nil {
			t.Errorf("policy: %v", err)
		}
		results <- p.WriteRoots
	}
	go build()
	<-building
	<-reading
	go build()
	<-building
	rewriteSettings(t, f.projectFile, writableFoldersYAML(updated...))
	close(proceed)
	for range 2 {
		if got := <-results; len(got) != 0 && !slices.Equal(got, old) && !slices.Equal(got, updated) {
			t.Fatalf("overlapping build write roots = %q, want all of %q, all of %q, or none", got, old, updated)
		}
	}
	if got := policyWriteRoots(t, conf); !slices.Equal(got, updated) {
		t.Fatalf("write roots after the overlapping builds = %q, want %q", got, updated)
	}
}

func TestConfinedRunner_PolicyTakesAFreshBlockedSnapshot(t *testing.T) {
	home := canonicalTempDir(t)
	realDir := filepath.Join(home, "real")
	link := filepath.Join(home, "link")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	var entries []permissions.BlockedEntry
	blocked := permissions.NewLiveBlockedPaths(home, home, nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Changed: true, Entries: entries}
	})
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: blocked}
	inner := &confineInner{}
	r := &confinedRunner{inner: inner, conf: conf}
	for range 2 {
		if _, err := r.Exec(context.Background(), confinedSpec(home, "ls")); err != nil {
			t.Fatal(err)
		}
		entries = []permissions.BlockedEntry{{Path: link, Source: filepath.Join(home, "settings.yaml")}}
	}
	first, _ := decodeFrame(t, inner.bounded[0].Stdin)
	second, _ := decodeFrame(t, inner.bounded[1].Stdin)
	floor := filepath.Join(home, ".codemeld")
	if !slices.Equal(first.BlockedPaths, []string{floor}) || !slices.Equal(second.BlockedPaths, []string{link, realDir, floor}) {
		t.Fatalf("blocked paths = %q then %q, want the floor then the link's two forms added", first.BlockedPaths, second.BlockedPaths)
	}
}

func TestConfinedRunner_HelperSetupFailureIsTheResult(t *testing.T) {
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: testBlocked(t)}
	run := map[string]func(*confineInner) (cmdrunner.RunResult, error){
		"bash": func(in *confineInner) (cmdrunner.RunResult, error) {
			return shellAdapter(conf, in).Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
		},
		"vcs": func(in *confineInner) (cmdrunner.RunResult, error) {
			return (&confinedRunner{inner: in, conf: conf}).Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
		},
	}
	for name, exec := range run {
		inner := &confineInner{exitCode: enforce.SetupFailureExitCode}
		res, err := exec(inner)
		if err != nil || res.ExitCode != enforce.SetupFailureExitCode {
			t.Fatalf("%s: result %+v, err %v, want exit %d", name, res, err, enforce.SetupFailureExitCode)
		}
		if len(inner.execs) != 0 || len(inner.bounded) != 1 || inner.bounded[0].Argv[1] != enforce.HelperCommand {
			t.Fatalf("%s: inner execs/bounded = %+v/%+v, want only the helper run", name, inner.execs, inner.bounded)
		}
	}
}

func TestConfinedRunner_InvalidUTF8BlockedTargetStartsNothing(t *testing.T) {
	home := canonicalTempDir(t)
	realDir := filepath.Join(home, "real\xff")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Skipf("filesystem rejects a name with byte 0xff: %v", err)
	}
	link := filepath.Join(home, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	entries := []permissions.BlockedEntry{{Path: link, Source: filepath.Join(home, "settings.yaml")}}
	blocked := permissions.NewLiveBlockedPaths(home, home, nil, func() permissions.BlockedReload {
		return permissions.BlockedReload{Changed: true, Entries: entries}
	})
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: blocked}
	store := mkStore(t)
	inner := &confineInner{}
	shell := &confinedShellRunner{events: &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64}, conf: conf}
	_, shellErr := shell.Exec(context.Background(), confinedSpec(home, "ls"))
	_, vcsErr := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), confinedSpec(home, "ls"))
	for name, err := range map[string]error{"bash": shellErr, "vcs": vcsErr} {
		if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
			t.Fatalf("%s: err = %v, want the invalid UTF-8 policy error", name, err)
		}
	}
	if inner.calls() != 0 || len(store.Records()) != 0 {
		t.Fatalf("inner calls = %d, records = %d, want nothing run and nothing recorded", inner.calls(), len(store.Records()))
	}
}

func TestConfinedRunner_OversizedPolicyStartsNothing(t *testing.T) {
	home := t.TempDir()
	var entries []permissions.BlockedEntry
	for i := range 3000 {
		entries = append(entries, permissions.BlockedEntry{Path: filepath.Join(home, "blocked-entry", strconv.Itoa(i)), Source: "/settings.yaml"})
	}
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"),
		blocked: permissions.NewBlockedPaths(home, entries)}
	store := mkStore(t)
	inner := &confineInner{}
	shell := &confinedShellRunner{events: &shellEventRunner{inner: inner, active: func() *sessions.Store { return store }, cap: 64}, conf: conf}
	_, shellErr := shell.Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
	_, vcsErr := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
	for name, err := range map[string]error{"bash": shellErr, "vcs": vcsErr} {
		if err == nil || !strings.Contains(err.Error(), "codemeld confinement: policy frame: policy frame exceeds 65536 bytes") {
			t.Fatalf("%s: err = %v, want the policy frame size error", name, err)
		}
	}
	if inner.calls() != 0 || len(store.Records()) != 0 {
		t.Fatalf("inner calls = %d, records = %d, want nothing run and nothing recorded", inner.calls(), len(store.Records()))
	}
}

type confinedExec func(*confineInner, cmdrunner.RunSpec) (cmdrunner.RunResult, error)

func confinedAdapters(t *testing.T, conf *confinement, cap int) map[string]confinedExec {
	store := mkStore(t)
	return map[string]confinedExec{
		"bash": func(in *confineInner, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
			return (&confinedShellRunner{events: &shellEventRunner{inner: in, cap: cap}, conf: conf}).Exec(context.Background(), spec)
		},
		"bash with store": func(in *confineInner, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
			active := func() *sessions.Store { return store }
			return (&confinedShellRunner{events: &shellEventRunner{inner: in, active: active, cap: cap}, conf: conf}).Exec(context.Background(), spec)
		},
		"vcs": func(in *confineInner, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
			return (&confinedRunner{inner: in, conf: conf, cap: cap}).Exec(context.Background(), spec)
		},
	}
}

func TestConfinedRunner_NetworkAuthoritySelectsTheNetworkPolicyVariant(t *testing.T) {
	cwd := t.TempDir()
	lookup := programDir(t, "curl")
	classified, _ := permissions.ExceptionalAuthority([]string{"curl", "https://example.com"})
	deletion, _ := permissions.ExceptionalAuthority([]string{"rm", "x"})
	if classified != enforce.NetworkAccessAuthority || deletion == "" || deletion == enforce.NetworkAccessAuthority {
		t.Fatalf("classifier authorities = %q/%q, want the enforcement network value and a distinct deletion value", classified, deletion)
	}
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		conf := &confinement{constrained: true, mode: fixedMode(string(m)), lookupPath: lookup, tmpDir: t.TempDir(), projectRoot: cwd, blocked: testBlocked(t)}
		for name, exec := range confinedAdapters(t, conf, 256) {
			t.Run(string(m)+"/"+name, func(t *testing.T) {
				run := func(authority string) (cmdrunner.RunSpec, enforce.Policy) {
					t.Helper()
					spec := confinedSpec(cwd, "curl", "https://example.com")
					spec.ExceptionalAuthority = authority
					inner := &confineInner{}
					if _, err := exec(inner, spec); err != nil {
						t.Fatalf("Exec(%q): %v", authority, err)
					}
					if inner.calls() != 1 || len(inner.bounded) != 1 {
						t.Fatalf("Exec(%q): inner calls = %d, want one bounded run", authority, inner.calls())
					}
					got := inner.bounded[0]
					wantHelperArgv(t, got.Argv, filepath.Join(lookup, "curl"), "https://example.com")
					policy, rest := decodeFrame(t, got.Stdin)
					if len(rest) != 0 {
						t.Fatalf("Exec(%q): trailing stdin %q after the frame", authority, rest)
					}
					got.Stdin, got.InvocationID, got.ExceptionalAuthority = nil, "", ""
					return got, policy
				}
				ordinarySpec, ordinary := run("")
				if ordinary.ExceptionalAuthority != "" {
					t.Fatalf("ordinary policy = %+v, want no exceptional authority", ordinary)
				}
				for _, tc := range []struct {
					authority string
					network   bool
				}{
					{enforce.NetworkAccessAuthority, m == mode.AutoEdits},
					{classified, m == mode.AutoEdits},
					{deletion, false},
				} {
					spec, policy := run(tc.authority)
					want := ordinary
					if tc.network {
						want.ExceptionalAuthority = enforce.NetworkAccessAuthority
					}
					if !reflect.DeepEqual(policy, want) {
						t.Fatalf("authority %q: policy = %+v, want %+v", tc.authority, policy, want)
					}
					if !reflect.DeepEqual(spec, ordinarySpec) {
						t.Fatalf("authority %q: inner spec = %+v, want the ordinary rewritten spec %+v", tc.authority, spec, ordinarySpec)
					}
				}
			})
		}
	}
}

func TestConfinedRunner_FailedConfinedRunGetsThePartialStateNote(t *testing.T) {
	const setup = "codemeld confinement: landlock: restrict self: operation not permitted\n"
	for _, tc := range []struct {
		name       string
		inner      confineInner
		wantStderr string
		wantErr    bool
	}{
		{"exit 1", confineInner{exitCode: 1, stderr: []byte("boom")}, "boom\n" + confinedFailureNote, false},
		{"exit 0", confineInner{stderr: []byte("warn")}, "warn", false},
		{"helper setup exit 125", confineInner{exitCode: enforce.SetupFailureExitCode, stderr: []byte(setup)}, setup + confinedFailureNote, false},
		{"target exit 125", confineInner{exitCode: enforce.SetupFailureExitCode, stderr: []byte("target")}, "target\n" + confinedFailureNote, false},
		{"signal exit", confineInner{exitCode: -1}, confinedFailureNote, false},
		{"launch failure", confineInner{exitCode: -1, launchErr: fserrors.NotFound}, "", false},
		{"runner error", confineInner{exitCode: 1, stderr: []byte("boom"), err: errors.New("runner broke")}, "", true},
	} {
		conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: testBlocked(t)}
		for name, exec := range confinedAdapters(t, conf, 4096) {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				inner := tc.inner
				inner.stdout = []byte("out\n")
				res, err := exec(&inner, confinedSpec(t.TempDir(), "ls"))
				if inner.calls() != 1 || len(inner.bounded) != 1 {
					t.Fatalf("inner calls = %d, want exactly one helper run", inner.calls())
				}
				if tc.wantErr {
					if err == nil || strings.Contains(string(res.Stderr), confinedFailureNote) {
						t.Fatalf("result %+v, err %v; want the runner error and no note", res, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("Exec: %v", err)
				}
				if string(res.Stderr) != tc.wantStderr || string(res.Stdout) != "out\n" {
					t.Fatalf("stdout/stderr = %q/%q, want %q/%q", res.Stdout, res.Stderr, "out\n", tc.wantStderr)
				}
			})
		}
	}
}

func TestConfinedRunner_PartialStateNoteSurvivesTheOutputCap(t *testing.T) {
	sep := int64(len("\n" + confinedFailureNote))
	for _, cap := range []int{256, 4096} {
		for name, stream := range map[string]struct {
			stderr []byte
			total  int64
		}{
			"at the cap":            {bytes.Repeat([]byte("a"), cap), int64(cap)},
			"cut short by capture":  {bytes.Repeat([]byte("a"), cap), int64(10 * cap)},
			"multi-byte at the cap": {bytes.Repeat([]byte("é"), cap/2), int64(cap)},
		} {
			t.Run(strconv.Itoa(cap)+"/"+name, func(t *testing.T) {
				check := func(t *testing.T, stdout, stderr []byte) {
					t.Helper()
					kept, ok := bytes.CutSuffix(stderr, []byte("\n"+confinedFailureNote))
					if !ok || bytes.Count(stderr, []byte(confinedFailureNote)) != 1 || len(stderr) > cap ||
						!utf8.Valid(stderr) || len(kept) == 0 || !bytes.HasPrefix(stream.stderr, kept) {
						t.Fatalf("stderr = %q (%d bytes), want a non-empty command prefix plus one note within %d", stderr, len(stderr), cap)
					}
					if string(stdout) != "out\n" {
						t.Fatalf("stdout = %q, want it unchanged", stdout)
					}
					if _, model := events.BuildModelInputBytes(stdout, stderr, cap); !bytes.Equal(model, stderr) {
						t.Fatalf("model stderr = %q, want the result stderr unchanged", model)
					}
				}
				checkEnd := func(t *testing.T, store *sessions.Store, stderr []byte) {
					t.Helper()
					ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd)
					if len(ends) != 1 || ends[0].Stderr != string(stderr) || ends[0].Stdout != "out\n" || !ends[0].Truncated ||
						ends[0].OriginalBytes == nil || ends[0].OriginalBytes.Stderr != stream.total+sep {
						t.Fatalf("tool_exec_end = %+v, want the result stderr, truncated, original stderr %d", ends, stream.total+sep)
					}
				}
				conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls", "hg"), blocked: testBlocked(t)}
				newInner := func() *confineInner {
					return &confineInner{exitCode: 1, stdout: []byte("out\n"), stderr: stream.stderr, stderrSize: stream.total}
				}

				for _, withStore := range []bool{false, true} {
					store := mkStore(t)
					shell := &shellEventRunner{inner: newInner(), cap: cap}
					if withStore {
						shell.active = func() *sessions.Store { return store }
					}
					res, err := (&confinedShellRunner{events: shell, conf: conf}).Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
					if err != nil {
						t.Fatal(err)
					}
					check(t, res.Stdout, res.Stderr)
					if res.StderrTotal != stream.total+sep || res.StderrTotal <= int64(len(res.Stderr)) {
						t.Fatalf("StderrTotal = %d for %d kept bytes, want %d", res.StderrTotal, len(res.Stderr), stream.total+sep)
					}
					if withStore {
						checkEnd(t, store, res.Stderr)
					}
				}

				store := mkStore(t)
				emit := func(p events.EventPayload) error {
					_, err := events.Append(store, p)
					return err
				}
				vr := &confinedRunner{inner: newInner(), conf: conf, cap: cap}
				res, err := vcs.Invoke(context.Background(), "status", &vcs.ActionSpec{Argv: []string{"hg", "status"}}, nil, t.TempDir(), vr, emit, cap)
				if err != nil {
					t.Fatal(err)
				}
				check(t, res.Stdout, res.Stderr)
				checkEnd(t, store, res.Stderr)
			})
		}
	}
}

func TestConfinedRunner_PartialStateNoteKeepsTruncationThroughNormalization(t *testing.T) {
	const cap = 256
	sep := int64(len("\n" + confinedFailureNote))
	for name, tc := range map[string]struct {
		stderr    []byte
		truncated bool
	}{
		"expands past the reserved budget": {bytes.Repeat([]byte{0xff, 'a'}, 30), true},
		"fits the reserved budget":         {bytes.Repeat([]byte{0xff, 'a'}, 5), false},
	} {
		t.Run(name, func(t *testing.T) {
			total := int64(len(tc.stderr))
			modelStderr := func(t *testing.T, stdout, stderr []byte) []byte {
				t.Helper()
				if string(stdout) != "out\n" {
					t.Fatalf("stdout = %q, want it unchanged", stdout)
				}
				_, model := events.BuildModelInputBytes(stdout, stderr, cap)
				if !bytes.HasSuffix(model, []byte("\n"+confinedFailureNote)) || bytes.Count(model, []byte(confinedFailureNote)) != 1 || len(model) > cap {
					t.Fatalf("model stderr = %q (%d bytes), want one complete note at the end within %d", model, len(model), cap)
				}
				return model
			}
			checkEnd := func(t *testing.T, store *sessions.Store, model []byte) {
				t.Helper()
				ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd)
				if len(ends) != 1 || ends[0].Stderr != string(model) || ends[0].Stdout != "out\n" || ends[0].Truncated != tc.truncated {
					t.Fatalf("tool_exec_end = %+v, want the model stderr and truncated = %v", ends, tc.truncated)
				}
				if tc.truncated && (ends[0].OriginalBytes == nil || ends[0].OriginalBytes.Stderr != total+sep) {
					t.Fatalf("original_bytes = %+v, want stderr %d", ends[0].OriginalBytes, total+sep)
				}
				if !tc.truncated && ends[0].OriginalBytes != nil {
					t.Fatalf("original_bytes = %+v, want none for a complete stream", ends[0].OriginalBytes)
				}
			}
			conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls", "hg"), blocked: testBlocked(t)}
			newInner := func() *confineInner {
				return &confineInner{exitCode: 1, stdout: []byte("out\n"), stderr: tc.stderr}
			}

			for _, withStore := range []bool{false, true} {
				store := mkStore(t)
				shell := &shellEventRunner{inner: newInner(), cap: cap}
				if withStore {
					shell.active = func() *sessions.Store { return store }
				}
				res, err := (&confinedShellRunner{events: shell, conf: conf}).Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
				if err != nil {
					t.Fatal(err)
				}
				model := modelStderr(t, res.Stdout, res.Stderr)
				if res.StderrTotal != total+sep || (res.StderrTotal > int64(len(res.Stderr))) != tc.truncated {
					t.Fatalf("StderrTotal = %d for %d kept bytes, want %d and truncated = %v", res.StderrTotal, len(res.Stderr), total+sep, tc.truncated)
				}
				if withStore {
					checkEnd(t, store, model)
				}
			}

			store := mkStore(t)
			emit := func(p events.EventPayload) error {
				_, err := events.Append(store, p)
				return err
			}
			vr := &confinedRunner{inner: newInner(), conf: conf, cap: cap}
			res, err := vcs.Invoke(context.Background(), "status", &vcs.ActionSpec{Argv: []string{"hg", "status"}}, nil, t.TempDir(), vr, emit, cap)
			if err != nil {
				t.Fatal(err)
			}
			checkEnd(t, store, modelStderr(t, res.Stdout, res.Stderr))
		})
	}
}

func TestConfinedShellRunner_FailureNoteSurvivesShellAggregation(t *testing.T) {
	noisy := cmdrunner.RunResult{Stdout: []byte("one\n"), Stderr: bytes.Repeat([]byte("a"), 256)}
	failed := cmdrunner.RunResult{ExitCode: 1, Stdout: []byte("two\n"), Stderr: []byte("boom")}
	for _, tc := range []struct {
		command     string
		results     []cmdrunner.RunResult
		failedStage int
		stdout      string
	}{
		{"ls && false", []cmdrunner.RunResult{noisy, failed}, 1, "one\ntwo"},
		{"false; ls", []cmdrunner.RunResult{failed, noisy}, 0, "two\none"},
		{"ls | false", []cmdrunner.RunResult{noisy, failed}, 1, "two"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			inner := &confineInner{results: tc.results}
			d := dispatcherFor(t, tools.NewRegistry(), inner, &recordingAuthorizer{decision: allow()})
			d.outputCap = 256
			d.confinement = &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls", "false"), blocked: testBlocked(t)}

			got, err := d.Dispatch(context.Background(), bashCall("c1", tc.command))
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if inner.calls() != 2 || len(inner.bounded) != 2 {
				t.Fatalf("inner calls = %d, bounded = %d, want two confined stages run once each", inner.calls(), len(inner.bounded))
			}
			if !strings.HasPrefix(got.Content, tc.stdout+"\nstderr:\n") || strings.Count(got.Content, confinedFailureNote) != 1 {
				t.Fatalf("content = %q, want stdout %q and the complete note once", got.Content, tc.stdout)
			}
			ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, d.active()), events.KindToolExecEnd)
			if len(ends) != 2 || !strings.HasSuffix(ends[tc.failedStage].Stderr, "\n"+confinedFailureNote) {
				t.Fatalf("tool_exec_end = %+v, want the failed stage's event to end with the note", ends)
			}
		})
	}
}

func TestConfinedRunner_UnconfinedFailureGetsNoNote(t *testing.T) {
	cwd := t.TempDir()
	for name, conf := range map[string]*confinement{
		"nil":               nil,
		"not constrained":   {mode: fixedMode(string(mode.AutoEdits)), tmpDir: cwd},
		"constrained build": {constrained: true, mode: fixedMode(string(mode.Build))},
	} {
		for adapter, exec := range confinedAdapters(t, conf, 4096) {
			t.Run(name+"/"+adapter, func(t *testing.T) {
				spec := confinedSpec(cwd, "ls")
				inner := &confineInner{exitCode: 1, stderr: []byte("boom")}
				res, err := exec(inner, spec)
				if err != nil {
					t.Fatal(err)
				}
				if len(inner.execs) != 1 || !reflect.DeepEqual(inner.execs[0], spec) {
					t.Fatalf("inner execs = %+v, want the caller's spec unchanged", inner.execs)
				}
				if res.ExitCode != 1 || string(res.Stderr) != "boom" {
					t.Fatalf("exit/stderr = %d/%q, want the command's own result with no note", res.ExitCode, res.Stderr)
				}
			})
		}
	}
	shell := &shellEventRunner{inner: &confineInner{exitCode: 1, stderr: []byte("boom")}, active: func() *sessions.Store { return mkStore(t) }, cap: 4096}
	if res, err := shell.ExecBounded(context.Background(), confinedSpec(cwd, "ls"), 4096); err != nil || string(res.Stderr) != "boom" {
		t.Fatalf("ordinary ExecBounded = %q, %v; want the command stderr alone", res.Stderr, err)
	}
}

func TestRunHeadless_PartialStateNoteFollowsTheConfinementFlag(t *testing.T) {
	for _, tc := range selfTestCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			swapResolveExecutionCapability(t, tc.resolution)
			inner := &confineInner{exitCode: 1, stderr: []byte("boom")}
			result := headlessResult(t, t.TempDir(), mode.NewActiveState(mode.Plan, mode.SourceDefault))
			d := runHeadlessShell(t, result, inner, "touch x")
			if d.confinement == nil || d.confinement.constrained != tc.want {
				t.Fatalf("confinement = %+v, want constrained = %v", d.confinement, tc.want)
			}
			toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
			if len(toolMsgs) != 1 || strings.Contains(toolMsgs[0].Content.Text(), confinedFailureNote) != tc.want {
				t.Fatalf("tool messages = %+v, want the note present = %v", toolMsgs, tc.want)
			}
		})
	}
}

func TestRunHeadless_AutoEditsConfinedFailureThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	const probe = "/tmp/codemeld-confine-probe"
	if _, err := cmdrunner.ResolveOnPath("sh", cmdrunner.FixedPATH); err != nil {
		t.Skipf("sh absent from %s: %v", cmdrunner.FixedPATH, err)
	}
	if _, err := os.Lstat(probe); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fixture: %s must be absent before the run, stat = %v", probe, err)
	}
	run := &helperForwardingRunner{bin: bin}
	result := headlessResult(t, project, mode.NewActiveState(mode.AutoEdits, mode.SourceDefault))
	result.Home, result.ConfigLayerPaths = home, []string{SettingsPath(home)}
	result.Config["confinement"] = map[string]any{"program_lookup": "strict"}

	prev := newShellRunner
	newShellRunner = func() cmdrunner.Runner { return run }
	defer func() { newShellRunner = prev }()
	client := toolThenContentClient(nil, bashToolName, toolArgs(t, map[string]any{"command": "sh -c 'echo hi > " + probe + "'"}), "ok")
	defer swapTurnProviderClient(func(provider.ClientConfig) provider.Client { return client })()
	driver := NewHeadlessDriver("run it", &bytes.Buffer{}, &bytes.Buffer{})
	driver.EnablePromptForApproval(strings.NewReader("1\n"))
	if err := driver.Run(context.Background(), result); err != nil {
		t.Fatalf("driver.Run: %v", err)
	}

	if len(run.specs) != 1 || run.specs[0].Argv[0] != "/proc/self/exe" || run.specs[0].Argv[1] != enforce.HelperCommand {
		t.Fatalf("inner runs = %+v, want exactly one through the helper", run.specs)
	}
	toolMsgs := messagesByRole(reloadStore(t, result.Session), "tool")
	if len(toolMsgs) != 1 || strings.Count(toolMsgs[0].Content.Text(), confinedFailureNote) != 1 {
		t.Fatalf("tool messages = %+v, want one result carrying the note once", toolMsgs)
	}
	if _, err := os.Lstat(probe); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s stat = %v, want it still absent", probe, err)
	}
}

type skillsFixture struct{ home, project, ext, codemeld, skills string }

func newSkillsFixture(t *testing.T) skillsFixture {
	t.Helper()
	home := canonicalTempDir(t)
	f := skillsFixture{home: home, project: canonicalTempDir(t), ext: canonicalTempDir(t),
		codemeld: filepath.Join(home, ".codemeld"), skills: filepath.Join(home, ".codemeld", "skills")}
	if err := os.MkdirAll(f.skills, 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func mustSymlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func replaceWithSymlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.RemoveAll(name); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, target, name)
}

func skillsPolicy(t *testing.T, conf *confinement, f skillsFixture) enforce.Policy {
	t.Helper()
	inner := &confineInner{}
	if _, err := shellAdapter(conf, inner).Exec(context.Background(), confinedSpec(f.project, "ls")); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	policy, _ := decodeFrame(t, inner.bounded[0].Stdin)
	return policy
}

func TestConfinedRunner_SkillsFolderReadRoot(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, f skillsFixture)
		blocked  func(f skillsFixture) []string
		confHome func(f skillsFixture) string
		degraded bool
		want     func(f skillsFixture) []string
	}{
		{name: "real skills folder", want: func(f skillsFixture) []string { return []string{f.skills} }},
		{name: "empty home falls back to the blocked home", confHome: func(skillsFixture) string { return "" },
			want: func(f skillsFixture) []string { return []string{f.skills} }},
		{name: "relative home", setup: func(t *testing.T, f skillsFixture) { t.Chdir(f.home) },
			confHome: func(skillsFixture) string { return "." }},
		{name: "unrelated configured entry", blocked: func(f skillsFixture) []string { return []string{"~/.ssh"} },
			want: func(f skillsFixture) []string { return []string{f.skills} }},
		{name: "configured entry is skills", blocked: func(skillsFixture) []string { return []string{"~/.codemeld/skills"} }},
		{name: "configured missing entry inside skills", blocked: func(skillsFixture) []string { return []string{"~/.codemeld/skills/pdf/missing"} }},
		{name: "configured entry covers skills", blocked: func(f skillsFixture) []string { return []string{f.home} }},
		{name: "configured entry reaches skills through a symlink",
			setup:   func(t *testing.T, f skillsFixture) { mustSymlink(t, f.skills, filepath.Join(f.home, "alias")) },
			blocked: func(skillsFixture) []string { return []string{"~/alias"} }},
		{name: "configured missing entry below a symlink to skills",
			setup:   func(t *testing.T, f skillsFixture) { mustSymlink(t, f.skills, filepath.Join(f.home, "alias")) },
			blocked: func(skillsFixture) []string { return []string{"~/alias/pdf/missing"} }},
		{name: "configured entry at the resolved skills location",
			setup:   func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.ext, f.skills) },
			blocked: func(f skillsFixture) []string { return []string{f.ext} }},
		{name: "configured missing entry below the resolved skills location",
			setup:   func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.ext, f.skills) },
			blocked: func(f skillsFixture) []string { return []string{filepath.Join(f.ext, "pdf", "missing")} }},
		{name: "skills missing", setup: func(t *testing.T, f skillsFixture) {
			if err := os.Remove(f.skills); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "skills is a file", setup: func(t *testing.T, f skillsFixture) {
			if err := os.Remove(f.skills); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.skills, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "codemeld folder is a file", setup: func(t *testing.T, f skillsFixture) {
			if err := os.RemoveAll(f.codemeld); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.codemeld, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "skills redirected to sessions", setup: func(t *testing.T, f skillsFixture) {
			sessions := filepath.Join(f.codemeld, "sessions")
			if err := os.Mkdir(sessions, 0o700); err != nil {
				t.Fatal(err)
			}
			replaceWithSymlink(t, sessions, f.skills)
		}},
		{name: "skills redirected to the codemeld folder", setup: func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.codemeld, f.skills) }},
		{name: "skills redirected to home", setup: func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.home, f.skills) }},
		{name: "skills redirected to a safe external folder",
			setup: func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.ext, f.skills) },
			want:  func(f skillsFixture) []string { return []string{f.ext} }},
		{name: "degraded blocked list", degraded: true},
	}
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		for _, tc := range cases {
			t.Run(string(m)+"/"+tc.name, func(t *testing.T) {
				f := newSkillsFixture(t)
				if tc.setup != nil {
					tc.setup(t, f)
				}
				var raws []string
				if tc.blocked != nil {
					raws = tc.blocked(f)
				}
				entries := blockedEntries(t, f.home, raws...)
				blocked := permissions.NewBlockedPaths(f.home, entries)
				if tc.degraded {
					blocked = permissions.NewLiveBlockedPaths(f.home, f.project, entries, func() permissions.BlockedReload {
						return permissions.BlockedReload{Problems: map[string]string{filepath.Join(f.home, "settings.yaml"): "can't be parsed"}}
					})
				}
				home := f.home
				if tc.confHome != nil {
					home = tc.confHome(f)
				}
				conf := &confinement{constrained: true, mode: fixedMode(string(m)), home: home, lookupPath: programDir(t, "ls"),
					tmpDir: t.TempDir(), projectRoot: f.project, blocked: blocked}
				var want []string
				if tc.want != nil {
					want = tc.want(f)
				}
				policy := skillsPolicy(t, conf, f)
				if !slices.Equal(policy.ReadRoots, want) {
					t.Errorf("read roots = %q, want %q", policy.ReadRoots, want)
				}
				if m == mode.AutoEdits {
					wantNoWrite := append([]string{filepath.Join(f.project, ".codemeld")}, want...)
					if !slices.Equal(policy.NoWritePaths, wantNoWrite) {
						t.Errorf("no-write paths = %q, want %q", policy.NoWritePaths, wantNoWrite)
					}
				}
				if !slices.Contains(policy.BlockedPaths, f.codemeld) {
					t.Errorf("blocked paths %q lost the floor %s", policy.BlockedPaths, f.codemeld)
				}
			})
		}
	}
}

func TestConfinedRunner_UninspectableSkillsFolderStartsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores folder permissions")
	}
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(m), func(t *testing.T) {
			f := newSkillsFixture(t)
			if err := os.Chmod(f.codemeld, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(f.codemeld, 0o755) })
			conf := &confinement{constrained: true, mode: fixedMode(string(m)), home: f.home, lookupPath: programDir(t, "ls"),
				tmpDir: t.TempDir(), projectRoot: f.project, blocked: permissions.NewBlockedPaths(f.home, nil)}
			inner := &confineInner{}
			if _, err := shellAdapter(conf, inner).Exec(context.Background(), confinedSpec(f.project, "ls")); !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("Exec error = %v, want a permission error", err)
			}
			if inner.calls() != 0 {
				t.Fatalf("inner runner called %d times", inner.calls())
			}
		})
	}
}
