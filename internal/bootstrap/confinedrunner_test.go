package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	"codemeld.dev/codemeld/internal/netproxy"
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

func withSessionTemp(t *testing.T, c *confinement) *confinement {
	t.Helper()
	dir, err := newSessionTempDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.removeAndRelease() })
	c.tmpDir = dir.path
	c.own(dir)
	return c
}

func withSessionProxy(t *testing.T, c *confinement) *confinement {
	t.Helper()
	c.own(nil)
	t.Cleanup(c.proxy.stop)
	return c
}

func sessionWithGlobalGrant(t *testing.T, host string) *confinement {
	t.Helper()
	home, project := canonicalTempDir(t), canonicalTempDir(t)
	path := SettingsPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("domain_grants:\n  - host: "+host+"\n    port: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	global, err := defaultLoadGlobalSettings(home)
	if err != nil {
		t.Fatal(err)
	}
	composition, err := defaultComposeConfig(global, project)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := config.NewCache(composition.Config, project, []string{path}, home)
	if err != nil {
		t.Fatal(err)
	}
	return withSessionProxy(t, launchConfinement(enforce.Resolution{SelfTestPassed: true}, t.TempDir(),
		mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home, securitystate.Policy{Blocked: testBlocked(t)}, nil))
}

func sessionProxyRefusal(t *testing.T, c *confinement, ask netproxy.Asker, authority string) string {
	t.Helper()
	endpoint, err := c.proxy.start()
	if err != nil {
		t.Fatal(err)
	}
	owner := c.proxy.running().NewOwner(ask)
	t.Cleanup(owner.Close)
	conn, err := net.Dial("tcp", endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := owner.Register(conn.LocalAddr().(*net.TCPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+authority+" HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Header.Get("X-Proxy-Refused")
}

func failIfAsked(t *testing.T) netproxy.Asker {
	return func(_ context.Context, host, port string, _ func() bool, _ func(netproxy.Decision) bool) (netproxy.Decision, error) {
		t.Errorf("asked for %s:%s", host, port)
		return netproxy.DecisionDeny, nil
	}
}

func TestLaunchConfinement_GlobalDomainGrantSkipsTheAsker(t *testing.T) {
	granted := sessionWithGlobalGrant(t, "127.0.0.1")
	if got := sessionProxyRefusal(t, granted, failIfAsked(t), "127.0.0.1:9"); got != "not public" {
		t.Fatalf("granted session refusal = %q, want the address check to refuse after the grant skipped the asker", got)
	}
	other := sessionWithGlobalGrant(t, "127.0.0.2")
	if got := sessionProxyRefusal(t, other, nil, "127.0.0.1:9"); got != "not approved (no one to ask)" {
		t.Fatalf("ungranted session refusal = %q, want the request to need approval", got)
	}
}

func TestSessionProxy_SessionsKeepTheirOwnSavedGrants(t *testing.T) {
	a, b := sessionWithGlobalGrant(t, "127.0.0.1"), sessionWithGlobalGrant(t, "127.0.0.2")
	real := startSessionProxy
	var together sync.WaitGroup
	together.Add(2)
	startSessionProxy = func(allow []string) (*netproxy.Server, string, error) {
		together.Done()
		together.Wait()
		return real(allow)
	}
	t.Cleanup(func() { startSessionProxy = real })
	childA := *a
	endpoints := make(chan error, 2)
	for _, c := range []*confinement{&childA, b} {
		go func() {
			_, err := c.proxy.start()
			endpoints <- err
		}()
	}
	for range 2 {
		if err := <-endpoints; err != nil {
			t.Fatal(err)
		}
	}
	parent, err := a.proxy.start()
	if err != nil {
		t.Fatal(err)
	}
	child, _ := childA.proxy.start()
	other, _ := b.proxy.start()
	if parent != child || parent == other {
		t.Fatalf("endpoints parent %v child %v other session %v; want parent and child to share only their own proxy", parent, child, other)
	}
	for _, tc := range []struct {
		name       string
		c          *confinement
		own, alien string
	}{
		{"parent", a, "127.0.0.1:9", "127.0.0.2:9"},
		{"child", &childA, "127.0.0.1:9", "127.0.0.2:9"},
		{"other session", b, "127.0.0.2:9", "127.0.0.1:9"},
	} {
		if got := sessionProxyRefusal(t, tc.c, failIfAsked(t), tc.own); got != "not public" {
			t.Errorf("%s: own grant %s refusal = %q, want admitted past the asker", tc.name, tc.own, got)
		}
		if got := sessionProxyRefusal(t, tc.c, nil, tc.alien); got != "not approved (no one to ask)" {
			t.Errorf("%s: other session's grant %s refusal = %q, want it to need approval", tc.name, tc.alien, got)
		}
	}
}

func requireSessionTempEnv(t *testing.T, env []string, tmp string) {
	t.Helper()
	if !slices.Equal(envNamed(env, "TMPDIR"), []string{"TMPDIR=" + tmp}) ||
		!slices.Equal(envNamed(env, "GOCACHE"), []string{"GOCACHE=" + tmp + "/go-build"}) {
		t.Fatalf("env = %q, want TMPDIR=%s and GOCACHE=%s/go-build", env, tmp, tmp)
	}
}

func requirePlanTempPolicy(t *testing.T, policy enforce.Policy, tmp string) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(tmp, &st); err != nil {
		t.Fatal(err)
	}
	if policy.Mode != string(mode.Plan) || policy.TmpDir != tmp || policy.TmpDirDev != uint64(st.Dev) || policy.TmpDirIno != st.Ino ||
		len(policy.WriteRoots) != 0 || len(policy.NoWritePaths) != 0 || policy.ExceptionalAuthority != "" {
		t.Fatalf("plan policy = %+v, want only the session temp folder %s (dev %d, ino %d)", policy, tmp, st.Dev, st.Ino)
	}
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
			if m == mode.Plan {
				withSessionTemp(t, conf)
			}
			wantDir := conf.tmpDir
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
				if !slices.Equal(got.Env, helperLaunchEnv(t, wantEnv)) {
					t.Fatalf("%s: env = %v, want %v", name, got.Env, wantEnv)
				}
				wantHelperArgv(t, got.Argv, filepath.Join(lookup, "ls"), "-la")
				policy, rest := decodeFrame(t, got.Stdin)
				if len(rest) != 0 || policy.Mode != string(m) || !slices.Contains(policy.BlockedPaths, secrets) ||
					!slices.Contains(policy.BlockedPaths, filepath.Join(home, ".codemeld")) || len(policy.WriteRoots) != 0 {
					t.Fatalf("%s: policy = %+v (trailing %q)", name, policy, rest)
				}
				if m == mode.Plan {
					requirePlanTempPolicy(t, policy, conf.tmpDir)
				}
				if m == mode.AutoEdits && (policy.TmpDir != tmp || len(policy.NoWritePaths) != 1) {
					t.Fatalf("%s: auto_edits policy = %+v, want tmp %s and the .codemeld carve-out", name, policy, tmp)
				}
				requireSessionTempEnv(t, got.Env, conf.tmpDir)
			}
			if spec.Env != nil || spec.Argv[0] != "ls" || spec.Stdin != nil {
				t.Fatalf("caller's spec mutated to %+v", spec)
			}
		})
	}
}

func TestConfinedRunner_EmptyLookupPathResolvesOnFixedPATH(t *testing.T) {
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), blocked: testBlocked(t)})
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

func TestConfinedRunner_MissingTempFolderRefusesBeforeRunning(t *testing.T) {
	unowned := t.TempDir()
	for name, c := range map[string]struct {
		mode   mode.Mode
		tmpDir string
		want   string
	}{
		"plan without a folder":       {mode.Plan, "", "bootstrap: confined plan run has no private temporary folder"},
		"auto_edits without a folder": {mode.AutoEdits, "", "bootstrap: confined auto_edits run has no private temporary folder"},
		"plan folder without a handle": {mode.Plan, unowned,
			"bootstrap: confined plan run has no private temporary folder handle for " + unowned},
	} {
		t.Run(name, func(t *testing.T) {
			conf := &confinement{constrained: true, mode: fixedMode(string(c.mode)), lookupPath: programDir(t, "ls"), tmpDir: c.tmpDir,
				projectRoot: t.TempDir(), blocked: testBlocked(t)}
			inner := &confineInner{}
			_, shellErr := shellAdapter(conf, inner).Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
			_, vcsErr := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), confinedSpec(t.TempDir(), "ls"))
			for route, err := range map[string]error{"bash": shellErr, "vcs": vcsErr} {
				if err == nil || err.Error() != c.want {
					t.Errorf("%s: err = %v, want %q", route, err, c.want)
				}
			}
			if inner.calls() != 0 {
				t.Fatalf("inner calls = %d, want none", inner.calls())
			}
		})
	}
}

func TestConfinedRunner_KeepsProbePinsDropsOtherEnv(t *testing.T) {
	lookup := programDir(t, "go", "mise")
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: lookup, blocked: testBlocked(t)})
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

func TestConfinedRunner_RunSpecEnvStaysOutAndPlanGetsTheSessionTemp(t *testing.T) {
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: t.TempDir(), lookupPath: programDir(t, "go"),
		blocked: testBlocked(t), inherited: launchSnapshot("MISE_DATA_DIR=/data/coding/mise", "TMPDIR=/launch/tmp", "GOCACHE=/launch/cache")})
	spec := confinedSpec(t.TempDir(), "go", "env")
	spec.Env = []string{"MISE_DATA_DIR=/injected", "INJECTED=1", "TMPDIR=/injected", "GOCACHE=/injected"}
	env := confinedExecEnv(t, conf, spec)
	if !slices.Equal(envNamed(env, "MISE_DATA_DIR"), []string{"MISE_DATA_DIR=/data/coding/mise"}) || envNamed(env, "INJECTED") != nil {
		t.Fatalf("env = %q, want the launch MISE_DATA_DIR only and no RunSpec.Env entries", env)
	}
	requireSessionTempEnv(t, env, conf.tmpDir)
}

func TestConfinedRunner_ParallelPreparationsKeepTheLaunchSnapshot(t *testing.T) {
	home := t.TempDir()
	snapshot := launchSnapshot("MISE_DATA_DIR=/data/coding/mise", "GOPATH=/launch/go", "GIT_CONFIG_GLOBAL=/x")
	want := []string{"MISE_DATA_DIR=/data/coding/mise", "GOPATH=/launch/go", "GIT_CONFIG_GLOBAL=/x"}
	conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: programDir(t, "go"),
		blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, "~/.gitconfig")), inherited: slices.Grow(snapshot, 64)}
	const n = 8
	envs := make([][]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			spec := confinedSpec(home, "go", "env")
			spec.Assignments = []string{"JOB=" + strconv.Itoa(i)}
			prepared, err := conf.prepare(spec, "", conf.blocked.Current(), "")
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
		if !slices.Equal(envNamed(env, "JOB"), []string{"JOB=" + strconv.Itoa(i)}) || !slices.Contains(env, "GOPATH=/launch/go") ||
			!slices.Equal(gitGlobalEntries(env), []string{wantGitNeutralizer}) || env[len(env)-1] != wantGitNeutralizer {
			t.Errorf("command %d env = %q, want its own JOB, the launch GOPATH and the git override last", i, env)
		}
		requireOneEntryPerName(t, env)
	}
}

func TestConfinedRunner_InheritedLaunchTempFolderBecomesTheSessionTemp(t *testing.T) {
	type setup struct {
		value, cwd  string
		noSession   bool
		assignments []string
	}
	launchTemp := func(t *testing.T) string {
		dir := t.TempDir()
		t.Setenv("TMPDIR", dir)
		return dir
	}
	symlink := func(t *testing.T, target, link string) {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	linkUp := func(t *testing.T) (base, other string) {
		base, other = t.TempDir(), t.TempDir()
		child := filepath.Join(other, "child")
		if err := os.Mkdir(child, 0o755); err != nil {
			t.Fatal(err)
		}
		symlink(t, child, filepath.Join(base, "link"))
		return base, other
	}
	upThrough := func(t *testing.T, searchable bool) (temp, through string) {
		base := t.TempDir()
		temp = filepath.Join(base, "temp")
		dir := filepath.Join(base, "dir")
		for _, d := range []string{temp, dir} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		through = dir + "/../temp"
		if searchable {
			return temp, through
		}
		if os.Geteuid() == 0 {
			t.Skip("root bypasses search permission")
		}
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		if _, err := os.Stat(through); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("Stat(%s) error = %v, want permission denied", through, err)
		}
		return temp, through
	}
	for name, tc := range map[string]struct {
		setup   func(t *testing.T) setup
		rewrite bool
	}{
		"exact match":    {func(t *testing.T) setup { d := launchTemp(t); return setup{value: d} }, true},
		"trailing slash": {func(t *testing.T) setup { d := launchTemp(t); return setup{value: d + "/"} }, true},
		"symlink to the temp folder": {func(t *testing.T) setup {
			d := launchTemp(t)
			link := filepath.Join(t.TempDir(), "link")
			symlink(t, d, link)
			return setup{value: link}
		}, true},
		"TMPDIR unset matches /tmp": {func(t *testing.T) setup {
			t.Setenv("TMPDIR", "")
			return setup{value: "/tmp"}
		}, true},
		"subfolder": {func(t *testing.T) setup {
			d := launchTemp(t)
			sub := filepath.Join(d, "sub")
			if err := os.Mkdir(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			return setup{value: sub}
		}, false},
		"unrelated folder": {func(t *testing.T) setup { launchTemp(t); return setup{value: t.TempDir()} }, false},
		"non-path value":   {func(t *testing.T) setup { launchTemp(t); return setup{value: "local"} }, false},
		"path list containing the temp folder": {func(t *testing.T) setup {
			d := launchTemp(t)
			return setup{value: d + ":" + t.TempDir()}
		}, false},
		"no session temp folder": {func(t *testing.T) setup {
			d := launchTemp(t)
			return setup{value: d, noSession: true}
		}, false},
		"command assignment": {func(t *testing.T) setup {
			d := launchTemp(t)
			return setup{value: d, assignments: []string{"GOTMPDIR=" + d}}
		}, false},
		"relative value through spec.Cwd": {func(t *testing.T) setup {
			base := t.TempDir()
			d := filepath.Join(base, "launch")
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", d)
			t.Chdir(t.TempDir())
			return setup{value: "launch", cwd: base}
		}, true},
		"relative launch TMPDIR, absolute value": {func(t *testing.T) setup {
			base := t.TempDir()
			cwd := t.TempDir()
			d := filepath.Join(base, "launch-tmp")
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Chdir(base)
			t.Setenv("TMPDIR", "launch-tmp")
			return setup{value: d, cwd: cwd}
		}, true},
		"unresolvable value": {func(t *testing.T) setup {
			d := launchTemp(t)
			symlink(t, "loop", filepath.Join(d, "loop"))
			return setup{value: d + "/loop/.."}
		}, false},
		"absolute launch TMPDIR through link/.., resolved folder": {func(t *testing.T) setup {
			base, other := linkUp(t)
			t.Setenv("TMPDIR", base+"/link/..")
			return setup{value: other}
		}, true},
		"absolute launch TMPDIR through link/.., lexical folder": {func(t *testing.T) setup {
			base, _ := linkUp(t)
			t.Setenv("TMPDIR", base+"/link/..")
			return setup{value: base}
		}, false},
		"relative launch TMPDIR through link/.., resolved folder": {func(t *testing.T) setup {
			base, other := linkUp(t)
			t.Chdir(base)
			t.Setenv("TMPDIR", "link/..")
			return setup{value: other}
		}, true},
		"relative launch TMPDIR through link/.., lexical folder": {func(t *testing.T) setup {
			base, _ := linkUp(t)
			t.Chdir(base)
			t.Setenv("TMPDIR", "link/..")
			return setup{value: base}
		}, false},
		"launch TMPDIR through a missing folder and ..": {func(t *testing.T) setup {
			base := t.TempDir()
			t.Setenv("TMPDIR", base+"/missing/..")
			return setup{value: base}
		}, false},
		"launch TMPDIR through a symlink loop and ..": {func(t *testing.T) setup {
			base := t.TempDir()
			symlink(t, "loop", filepath.Join(base, "loop"))
			t.Setenv("TMPDIR", base+"/loop/..")
			return setup{value: base}
		}, false},
		"value through a non-searchable folder and ..": {func(t *testing.T) setup {
			temp, through := upThrough(t, false)
			t.Setenv("TMPDIR", temp)
			return setup{value: through}
		}, false},
		"value through a searchable folder and ..": {func(t *testing.T) setup {
			temp, through := upThrough(t, true)
			t.Setenv("TMPDIR", temp)
			return setup{value: through}
		}, true},
		"launch TMPDIR through a non-searchable folder and ..": {func(t *testing.T) setup {
			temp, through := upThrough(t, false)
			t.Setenv("TMPDIR", through)
			return setup{value: temp}
		}, false},
		"launch TMPDIR through a searchable folder and ..": {func(t *testing.T) setup {
			temp, through := upThrough(t, true)
			t.Setenv("TMPDIR", through)
			return setup{value: temp}
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			s := tc.setup(t)
			cwd := s.cwd
			if cwd == "" {
				cwd = t.TempDir()
			}
			session := t.TempDir()
			if s.noSession {
				session = ""
			}
			conf := &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: t.TempDir(), lookupPath: programDir(t, "go"),
				blocked: testBlocked(t), inherited: launchSnapshot("GOTMPDIR=" + s.value)}
			spec := confinedSpec(cwd, "go", "build")
			spec.Assignments = s.assignments
			prepared, err := conf.prepare(spec, session, conf.blocked.Current(), "")
			if err != nil {
				t.Fatal(err)
			}
			want := "GOTMPDIR=" + s.value
			if s.assignments != nil {
				want = s.assignments[0]
			}
			if tc.rewrite {
				want = "GOTMPDIR=" + session
			}
			if got := envNamed(prepared.Env, "GOTMPDIR"); !slices.Equal(got, []string{want}) {
				t.Fatalf("GOTMPDIR entries = %q, want exactly %s", got, want)
			}
		})
	}
}

const wantGitNeutralizer = "GIT_CONFIG_GLOBAL=/dev/null"

func helperLaunchEnv(t *testing.T, target []string) []string {
	t.Helper()
	if got := envNamed(target, "TERM"); !slices.Equal(got, []string{"TERM=dumb"}) {
		t.Fatalf("target env TERM entries = %q, want exactly TERM=dumb", got)
	}
	launch := slices.Clone(target)
	launch[slices.Index(launch, "TERM=dumb")] = "TERM="
	return launch
}

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
				conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(m)), home: home, lookupPath: lookup,
					projectRoot: cwd, blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, tc.blocked...))})
				base, err := cmdrunner.FixedEnvironment(home, cwd, conf.tmpDir, lookup, []string{"FOO=bar"})
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
				if env := confinedExecEnv(t, conf, spec); !slices.Equal(env, helperLaunchEnv(t, want)) {
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
		conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: lookup,
			blocked: permissions.NewBlockedPaths(home, outsideEntry)})
		if got := gitGlobalEntries(confinedExecEnv(t, conf, confinedSpec(home, "git"))); !slices.Equal(got, []string{wantGitNeutralizer}) {
			t.Fatalf("GIT_CONFIG_GLOBAL entries = %q, want only %q", got, wantGitNeutralizer)
		}
	})

	t.Run("empty confinement home falls back to the snapshot home", func(t *testing.T) {
		snapshotHome := t.TempDir()
		conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: lookup,
			blocked: permissions.NewBlockedPaths(snapshotHome, blockedEntries(t, snapshotHome, "~/.config"))})
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
		prepared, err := conf.prepare(confinedSpec(cwd, "git"), "", permissions.NewBlockedPaths("", outsideEntry), "")
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: programDir(t, "git"), blocked: blocked})
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: programDir(t, "git"),
		blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, "~/.gitconfig"))})
	spec := confinedSpec(home, "git", "status")
	spec.Assignments = []string{"GIT_CONFIG_GLOBAL=x"}
	inner := &confineInner{}
	_, err := (&confinedRunner{inner: inner, conf: conf}).Exec(context.Background(), spec)
	var assignErr *cmdrunner.EnvAssignmentError
	if !errors.As(err, &assignErr) || assignErr.Name != "GIT_CONFIG_GLOBAL" || inner.calls() != 0 {
		t.Fatalf("err = %v, calls = %d; want a GIT_CONFIG_GLOBAL assignment refusal before any run", err, inner.calls())
	}
}

func TestConfinedRunner_InheritedGitGlobalConfigYieldsToTheOverride(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct {
		name    string
		blocked []string
		want    string
	}{
		{"blocked", []string{"~/.gitconfig"}, "GIT_CONFIG_GLOBAL=/dev/null"},
		{"neither path blocked", []string{"~/.hgrc"}, "GIT_CONFIG_GLOBAL=/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := []string{"GIT_CONFIG_GLOBAL=/x", "GOPATH=/launch/go"}
			conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: home, lookupPath: programDir(t, "git"),
				blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, tc.blocked...)), inherited: snapshot})
			env := confinedExecEnv(t, conf, confinedSpec(home, "git", "status"))
			if got := gitGlobalEntries(env); !slices.Equal(got, []string{tc.want}) {
				t.Fatalf("GIT_CONFIG_GLOBAL entries = %q, want only %q", got, tc.want)
			}
			requireOneEntryPerName(t, env)
			if !slices.Equal(snapshot, []string{"GIT_CONFIG_GLOBAL=/x", "GOPATH=/launch/go"}) {
				t.Fatalf("snapshot = %q, want it unchanged", snapshot)
			}
		})
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
			conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Build)), lookupPath: lookup,
				blocked: testBlocked(t), projectRoot: t.TempDir()})
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: func() string { return live }, lookupPath: programDir(t, "hg"), blocked: testBlocked(t)})
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan))})
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
	return f, withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(current), lookupPath: programDir(t, "ls"),
		projectRoot: f.project, writable: liveFoldersReader(t, f, []string{f.global, f.projectFile}, f.home), blocked: testBlocked(t)})
}

func policyWriteRoots(t *testing.T, conf *confinement) []string {
	t.Helper()
	p, err := conf.policy(conf.mode(), conf.tmpDir, conf.blocked.Current(), false)
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
				conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(current), lookupPath: programDir(t, "ls"),
					projectRoot: f.project, writable: liveFoldersReader(t, f, []string{f.global, f.projectFile}, f.home), blocked: testBlocked(t)})
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
	plan, err := conf.policy(string(mode.Plan), conf.tmpDir, conf.blocked.Current(), false)
	if err != nil {
		t.Fatal(err)
	}
	requirePlanTempPolicy(t, plan, conf.tmpDir)
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
		p, err := conf.policy(string(mode.AutoEdits), conf.tmpDir, conf.blocked.Current(), false)
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
		p, err := conf.policy(string(mode.AutoEdits), conf.tmpDir, conf.blocked.Current(), false)
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
		p, err := conf.policy(string(mode.AutoEdits), conf.tmpDir, conf.blocked.Current(), false)
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: blocked})
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: testBlocked(t)})
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: blocked})
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
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"),
		blocked: permissions.NewBlockedPaths(home, entries)})
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

func execNoted(r *confinedShellRunner, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
	res, err := r.Exec(context.Background(), spec)
	if err != nil {
		return res, err
	}
	return noteConfinedFailure(res, r.events.cap, r.failure), nil
}

func confinedAdapters(t *testing.T, conf *confinement, cap int) map[string]confinedExec {
	store := mkStore(t)
	return map[string]confinedExec{
		"bash": func(in *confineInner, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
			return execNoted(&confinedShellRunner{events: &shellEventRunner{inner: in, cap: cap}, conf: conf}, spec)
		},
		"bash with store": func(in *confineInner, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
			active := func() *sessions.Store { return store }
			return execNoted(&confinedShellRunner{events: &shellEventRunner{inner: in, active: active, cap: cap}, conf: conf}, spec)
		},
		"vcs": func(in *confineInner, spec cmdrunner.RunSpec) (cmdrunner.RunResult, error) {
			return (&confinedRunner{inner: in, conf: conf, cap: cap}).Exec(context.Background(), spec)
		},
	}
}

func TestConfinedRunner_ExceptionalAuthorityKeepsTheOrdinaryPolicy(t *testing.T) {
	cwd := t.TempDir()
	lookup := programDir(t, "curl")
	classified, _ := permissions.ExceptionalAuthority([]string{"curl", "https://example.com"})
	deletion, _ := permissions.ExceptionalAuthority([]string{"rm", "x"})
	if classified != enforce.NetworkAccessAuthority || deletion == "" || deletion == enforce.NetworkAccessAuthority {
		t.Fatalf("classifier authorities = %q/%q, want the enforcement network value and a distinct deletion value", classified, deletion)
	}
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(m)), lookupPath: lookup, projectRoot: cwd, blocked: testBlocked(t)})
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
				for _, authority := range []string{enforce.NetworkAccessAuthority, classified, deletion} {
					spec, policy := run(authority)
					if !reflect.DeepEqual(policy, ordinary) {
						t.Fatalf("authority %q: policy = %+v, want the ordinary %+v", authority, policy, ordinary)
					}
					if !reflect.DeepEqual(spec, ordinarySpec) {
						t.Fatalf("authority %q: inner spec = %+v, want the ordinary rewritten spec %+v", authority, spec, ordinarySpec)
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
		conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls"), blocked: testBlocked(t)})
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
				conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls", "hg"), blocked: testBlocked(t)})
				newInner := func() *confineInner {
					return &confineInner{exitCode: 1, stdout: []byte("out\n"), stderr: stream.stderr, stderrSize: stream.total}
				}

				for _, withStore := range []bool{false, true} {
					store := mkStore(t)
					shell := &shellEventRunner{inner: newInner(), cap: cap}
					if withStore {
						shell.active = func() *sessions.Store { return store }
					}
					res, err := execNoted(&confinedShellRunner{events: shell, conf: conf}, confinedSpec(t.TempDir(), "ls"))
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
			conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls", "hg"), blocked: testBlocked(t)})
			newInner := func() *confineInner {
				return &confineInner{exitCode: 1, stdout: []byte("out\n"), stderr: tc.stderr}
			}

			for _, withStore := range []bool{false, true} {
				store := mkStore(t)
				shell := &shellEventRunner{inner: newInner(), cap: cap}
				if withStore {
					shell.active = func() *sessions.Store { return store }
				}
				res, err := execNoted(&confinedShellRunner{events: shell, conf: conf}, confinedSpec(t.TempDir(), "ls"))
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
			d.confinement = withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), lookupPath: programDir(t, "ls", "false"), blocked: testBlocked(t)})

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
	skillsDir := func(f skillsFixture) []string { return []string{f.skills} }
	extDir := func(f skillsFixture) []string { return []string{f.ext} }
	cases := []struct {
		name     string
		setup    func(t *testing.T, f skillsFixture)
		blocked  func(f skillsFixture) []string
		confHome func(f skillsFixture) string
		degraded bool
		want     func(f skillsFixture) []string
		noWrite  func(f skillsFixture) []string
	}{
		{name: "real skills folder", want: skillsDir, noWrite: skillsDir},
		{name: "empty home falls back to the blocked home", confHome: func(skillsFixture) string { return "" },
			want: skillsDir, noWrite: skillsDir},
		{name: "relative home", setup: func(t *testing.T, f skillsFixture) {
			if err := os.MkdirAll(filepath.Join(f.project, ".codemeld", "skills"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Chdir(f.project)
		}, confHome: func(skillsFixture) string { return "." }},
		{name: "unrelated configured entry", blocked: func(f skillsFixture) []string { return []string{"~/.ssh"} },
			want: skillsDir, noWrite: skillsDir},
		{name: "configured entry is skills", blocked: func(skillsFixture) []string { return []string{"~/.codemeld/skills"} }, noWrite: skillsDir},
		{name: "configured missing entry inside skills", blocked: func(skillsFixture) []string { return []string{"~/.codemeld/skills/pdf/missing"} }, noWrite: skillsDir},
		{name: "configured entry covers skills", blocked: func(f skillsFixture) []string { return []string{f.home} }, noWrite: skillsDir},
		{name: "configured entry reaches skills through a symlink",
			setup:   func(t *testing.T, f skillsFixture) { mustSymlink(t, f.skills, filepath.Join(f.home, "alias")) },
			blocked: func(skillsFixture) []string { return []string{"~/alias"} }, noWrite: skillsDir},
		{name: "configured missing entry below a symlink to skills",
			setup:   func(t *testing.T, f skillsFixture) { mustSymlink(t, f.skills, filepath.Join(f.home, "alias")) },
			blocked: func(skillsFixture) []string { return []string{"~/alias/pdf/missing"} }, noWrite: skillsDir},
		{name: "configured entry at the resolved skills location",
			setup:   func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.ext, f.skills) },
			blocked: func(f skillsFixture) []string { return []string{f.ext} }, noWrite: extDir},
		{name: "configured missing entry below the resolved skills location",
			setup:   func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.ext, f.skills) },
			blocked: func(f skillsFixture) []string { return []string{filepath.Join(f.ext, "pdf", "missing")} }, noWrite: extDir},
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
		}, noWrite: func(f skillsFixture) []string { return []string{filepath.Join(f.codemeld, "sessions")} }},
		{name: "skills redirected to the codemeld folder", setup: func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.codemeld, f.skills) },
			noWrite: func(f skillsFixture) []string { return []string{f.codemeld} }},
		{name: "skills redirected to home", setup: func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.home, f.skills) },
			noWrite: func(f skillsFixture) []string { return []string{f.home} }},
		{name: "skills redirected to a safe external folder",
			setup: func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.ext, f.skills) },
			want:  extDir, noWrite: extDir},
		{name: "degraded blocked list", degraded: true, noWrite: skillsDir},
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
				conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(m)), home: home, lookupPath: programDir(t, "ls"),
					projectRoot: f.project, blocked: blocked})
				var want []string
				if tc.want != nil {
					want = tc.want(f)
				}
				policy := skillsPolicy(t, conf, f)
				if !slices.Equal(policy.ReadRoots, want) {
					t.Errorf("read roots = %q, want %q", policy.ReadRoots, want)
				}
				var wantNoWrite []string
				if m == mode.AutoEdits {
					wantNoWrite = []string{filepath.Join(f.project, ".codemeld")}
					if tc.noWrite != nil {
						wantNoWrite = append(wantNoWrite, tc.noWrite(f)...)
					}
				}
				if !slices.Equal(policy.NoWritePaths, wantNoWrite) {
					t.Errorf("no-write paths = %q, want %q", policy.NoWritePaths, wantNoWrite)
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
			conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(m)), home: f.home, lookupPath: programDir(t, "ls"),
				projectRoot: f.project, blocked: permissions.NewBlockedPaths(f.home, nil)})
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

func TestConfinedRunner_UninspectableSkillsFolderStopsAutoOnReadRefusalPaths(t *testing.T) {
	breaks := []struct {
		name     string
		apply    func(t *testing.T, f skillsFixture)
		checkErr func(t *testing.T, err error)
	}{
		{name: "symlink loop", apply: func(t *testing.T, f skillsFixture) { replaceWithSymlink(t, f.skills, f.skills) },
			checkErr: func(t *testing.T, err error) {
				if err == nil || !strings.Contains(err.Error(), "too many links") {
					t.Fatalf("Exec error = %v, want a symlink-loop error", err)
				}
			}},
		{name: "unreadable codemeld folder", apply: func(t *testing.T, f skillsFixture) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores folder permissions")
			}
			if err := os.Chmod(f.codemeld, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(f.codemeld, 0o755) })
		}, checkErr: func(t *testing.T, err error) {
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("Exec error = %v, want a permission error", err)
			}
		}},
	}
	refusals := []struct {
		name     string
		blocked  []string
		degraded bool
	}{
		{name: "ordinary"},
		{name: "degraded", degraded: true},
		{name: "blocked entry refuses the read grant", blocked: []string{"~/.codemeld/skills"}},
	}
	blockedFor := func(t *testing.T, f skillsFixture, raws []string, degraded bool) *permissions.BlockedPaths {
		entries := blockedEntries(t, f.home, raws...)
		if !degraded {
			return permissions.NewBlockedPaths(f.home, entries)
		}
		return permissions.NewLiveBlockedPaths(f.home, f.project, entries, func() permissions.BlockedReload {
			return permissions.BlockedReload{Problems: map[string]string{filepath.Join(f.home, "settings.yaml"): "can't be parsed"}}
		})
	}
	for _, b := range breaks {
		for _, r := range refusals {
			t.Run(b.name+"/auto_edits/"+r.name, func(t *testing.T) {
				f := newSkillsFixture(t)
				blocked := blockedFor(t, f, r.blocked, r.degraded)
				b.apply(t, f)
				conf := &confinement{constrained: true, mode: fixedMode(string(mode.AutoEdits)), home: f.home, lookupPath: programDir(t, "ls"),
					tmpDir: t.TempDir(), projectRoot: f.project, blocked: blocked}
				inner := &confineInner{}
				_, err := shellAdapter(conf, inner).Exec(context.Background(), confinedSpec(f.project, "ls"))
				b.checkErr(t, err)
				if inner.calls() != 0 {
					t.Fatalf("inner runner called %d times", inner.calls())
				}
			})
		}
		t.Run(b.name+"/plan/degraded", func(t *testing.T) {
			f := newSkillsFixture(t)
			blocked := blockedFor(t, f, nil, true)
			b.apply(t, f)
			conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.Plan)), home: f.home, lookupPath: programDir(t, "ls"),
				projectRoot: f.project, blocked: blocked})
			policy := skillsPolicy(t, conf, f)
			if len(policy.ReadRoots) != 0 || len(policy.NoWritePaths) != 0 {
				t.Fatalf("degraded plan policy read roots %q, no-write %q; want neither", policy.ReadRoots, policy.NoWritePaths)
			}
		})
	}
}

func TestConfinedRunner_SkillsLinkedIntoTheProjectStayUnwritableThroughTheRealHelper(t *testing.T) {
	home, project, bin := realConfinementHost(t)
	if _, err := cmdrunner.ResolveOnPath("sh", cmdrunner.FixedPATH); err != nil {
		t.Skipf("sh absent from %s: %v", cmdrunner.FixedPATH, err)
	}
	project, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	x, other, tmpDir := filepath.Join(project, "x"), filepath.Join(project, "other"), filepath.Join(filepath.Dir(project), "tmp")
	for _, dir := range []string{filepath.Join(x, "sub"), other, tmpDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sibling := filepath.Join(x, "skill.md")
	if err := os.WriteFile(sibling, []byte("orig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	skills := filepath.Join(home, ".codemeld", "skills")
	replaceWithSymlink(t, x, skills)
	cache, err := config.NewCache(map[string]any{"confinement": map[string]any{"program_lookup": "strict"}}, project,
		[]string{SettingsPath(home)}, home)
	if err != nil {
		t.Fatal(err)
	}
	guard := securitystate.Policy{Blocked: permissions.NewBlockedPaths(home, blockedEntries(t, home, filepath.Join(x, "sub")))}
	conf := withSessionProxy(t, launchConfinement(resolveExecutionCapability(enforce.ResolveInput{Home: home}), tmpDir,
		mode.NewActiveState(mode.AutoEdits, mode.SourceDefault), cache, home, guard, nil))

	inner := &confineInner{}
	if _, err := shellAdapter(conf, inner).Exec(context.Background(), confinedSpec(project, "sh")); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	policy, _ := decodeFrame(t, inner.bounded[0].Stdin)
	if len(policy.ReadRoots) != 0 || !slices.Contains(policy.NoWritePaths, x) {
		t.Fatalf("policy read roots %q, no-write %q; want no read root and %s unwritable", policy.ReadRoots, policy.NoWritePaths, x)
	}

	confined := &confinedRunner{inner: &helperForwardingRunner{bin: bin}, conf: conf, cap: 4096}
	write := func(t *testing.T, target string) cmdrunner.RunResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := confined.Exec(ctx, cmdrunner.RunSpec{InvocationID: ids.NewV7(), Argv: []string{"sh", "-c", `echo hi > "$1"`, "sh", target}, Cwd: project})
		if err != nil || ctx.Err() != nil {
			t.Fatalf("confined write to %s: %v, %v; result %+v", target, err, ctx.Err(), res)
		}
		return res
	}
	for _, target := range []string{filepath.Join(skills, "skill.md"), sibling} {
		res := write(t, target)
		if b, err := os.ReadFile(sibling); res.ExitCode == 0 || err != nil || string(b) != "orig\n" {
			t.Fatalf("write to %s: exit %d stderr %q, %s = %q, %v; want a failure leaving it unchanged", target, res.ExitCode, res.Stderr, sibling, b, err)
		}
	}
	unrelated := filepath.Join(other, "f")
	if res := write(t, unrelated); res.ExitCode != 0 {
		t.Fatalf("write to %s: exit %d stderr %q, want 0", unrelated, res.ExitCode, res.Stderr)
	}
	if b, err := os.ReadFile(unrelated); err != nil || string(b) != "hi\n" {
		t.Fatalf("%s = %q, %v; want the written line", unrelated, b, err)
	}
}

func TestConfinedRunner_AutoEditsPolicyProtectsHistoryStores(t *testing.T) {
	hgFolder, worktree, stores := declaredScopeDir(t), declaredScopeDir(t), declaredScopeDir(t)
	f, conf := liveWritableConfinement(t, string(mode.AutoEdits), writableFoldersYAML(hgFolder, worktree, stores))
	conf.home = f.home
	skills, gitdir := filepath.Join(f.home, ".codemeld", "skills"), filepath.Join(stores, "wtgit")
	for _, dir := range []string{skills, filepath.Join(f.project, ".git"), filepath.Join(hgFolder, ".hg"), gitdir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitdir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kept := []string{filepath.Join(f.project, ".codemeld"), skills}
	protected := slices.Concat(kept, []string{filepath.Join(f.project, ".git"), filepath.Join(hgFolder, ".hg"), filepath.Join(worktree, ".git"), gitdir})
	frame := func(t *testing.T, current string, exec func(*confineInner) error) enforce.Policy {
		t.Helper()
		conf.mode = fixedMode(current)
		inner := &confineInner{}
		if err := exec(inner); err != nil {
			t.Fatal(err)
		}
		policy, _ := decodeFrame(t, inner.bounded[0].Stdin)
		return policy
	}
	for _, tc := range []struct {
		name string
		exec func(*confineInner) error
		want []string
	}{
		{"shell", func(in *confineInner) error {
			_, err := shellAdapter(conf, in).Exec(context.Background(), confinedSpec(f.project, "ls"))
			return err
		}, protected},
		{"default runner", func(in *confineInner) error {
			_, err := (&confinedRunner{inner: in, conf: conf}).Exec(context.Background(), confinedSpec(f.project, "ls"))
			return err
		}, protected},
		{"vcs runner", func(in *confineInner) error {
			_, err := (&confinedRunner{inner: in, conf: conf, storesWritable: true}).Exec(context.Background(), confinedSpec(f.project, "ls"))
			return err
		}, kept},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := frame(t, string(mode.AutoEdits), tc.exec).NoWritePaths; !slices.Equal(got, tc.want) {
				t.Fatalf("auto_edits no-write paths = %q, want %q", got, tc.want)
			}
			requirePlanTempPolicy(t, frame(t, string(mode.Plan), tc.exec), conf.tmpDir)
		})
	}
}

func TestConfinedRunner_BrokenGitPointerStopsOnlyAutoEdits(t *testing.T) {
	mkdir := func(t *testing.T, dir string) string {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	gitdir := func(t *testing.T, project string) string {
		t.Helper()
		dir := mkdir(t, filepath.Join(project, "gd"))
		if err := os.WriteFile(filepath.Join(project, ".git"), []byte("gitdir: "+dir+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	for _, broken := range []struct {
		name   string
		marker func(t *testing.T, project string) string
		fifo   bool
	}{
		{"missing gitdir", func(t *testing.T, project string) string { return filepath.Join(project, ".git") }, false},
		{"dangling commondir symlink", func(t *testing.T, project string) string { return filepath.Join(gitdir(t, project), "commondir") }, false},
		{"dangling sharedpath symlink", func(t *testing.T, project string) string { return filepath.Join(mkdir(t, filepath.Join(project, ".hg")), "sharedpath") }, false},
		{"commondir fifo", func(t *testing.T, project string) string { return filepath.Join(gitdir(t, project), "commondir") }, true},
		{"sharedpath fifo", func(t *testing.T, project string) string { return filepath.Join(mkdir(t, filepath.Join(project, ".hg")), "sharedpath") }, true},
		{"gitdir selector through a regular file then dot-dot", func(t *testing.T, project string) string {
			mkdir(t, filepath.Join(project, "store"))
			if err := os.WriteFile(filepath.Join(project, "plainfile"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, ".git"), []byte("gitdir: selector\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(project, "selector")
		}, false},
	} {
		for _, tc := range []struct {
			mode    mode.Mode
			wantErr bool
		}{{mode.AutoEdits, true}, {mode.Plan, false}, {mode.Build, false}} {
			t.Run(broken.name+"/"+string(tc.mode), func(t *testing.T) {
				project := canonicalTempDir(t)
				marker := broken.marker(t, project)
				var err error
				switch {
				case broken.fifo:
					err = syscall.Mkfifo(marker, 0o600)
				case filepath.Base(marker) == ".git":
					err = os.WriteFile(marker, []byte("gitdir: "+filepath.Join(project, "missing")+"\n"), 0o600)
				case filepath.Base(marker) == "selector":
					err = os.Symlink("plainfile/../store", marker)
				default:
					err = os.Symlink(filepath.Join(project, "missing"), marker)
				}
				if err != nil {
					t.Fatal(err)
				}
				conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(tc.mode)), lookupPath: programDir(t, "ls"),
					projectRoot: project, blocked: testBlocked(t)})
				inner := &confineInner{}
				done := make(chan error, 1)
				go func() {
					_, err := shellAdapter(conf, inner).Exec(context.Background(), confinedSpec(project, "ls"))
					done <- err
				}()
				select {
				case err = <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("Exec still blocked after 10s; want discovery to return promptly")
				}
				if tc.wantErr {
					if err == nil || inner.calls() != 0 {
						t.Fatalf("Exec error = %v, inner calls = %d; want a discovery error and nothing run", err, inner.calls())
					}
					return
				}
				if err != nil || inner.calls() != 1 {
					t.Fatalf("Exec error = %v, inner calls = %d; want one run", err, inner.calls())
				}
			})
		}
	}
}

func TestConfinedShell_RefusedAssignmentStopsTheReroutedCommand(t *testing.T) {
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		t.Run(string(m), func(t *testing.T) {
			inner := &confineInner{}
			auth := &recordingAuthorizer{decision: allow()}
			d := dispatcherFor(t, tools.NewRegistry(), inner, auth)
			d.confinement = withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(m)), lookupPath: programDir(t, "sh"), blocked: testBlocked(t), projectRoot: d.processCWD})

			got, err := d.Dispatch(context.Background(), bashCall("c1", "XDG_CACHE_HOME=x grep x dir/*.md"))
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if !strings.Contains(got.Content, `environment assignment to "XDG_CACHE_HOME" is not allowed`) {
				t.Fatalf("content = %q, want the XDG_CACHE_HOME assignment refused", got.Content)
			}
			if auth.callCount() != 0 || inner.calls() != 0 {
				t.Fatalf("authorize calls = %d, runner calls = %d; want 0/0", auth.callCount(), inner.calls())
			}
		})
	}
}

func TestConfinedShell_ReroutedNetworkCommandKeepsItsModeRules(t *testing.T) {
	for _, command := range []string{"curl x/*", "ls dir/*.md && curl x", "env FOO=bar curl x/*", "FOO=$BAR curl x/*", "env FOO=bar curl x/* | grep y dir/*.md", "FOO=$BAR curl x/* | grep y dir/*.md"} {
		for _, m := range []mode.Mode{mode.AutoEdits, mode.Plan} {
			t.Run(fmt.Sprintf("%s/%s", command, m), func(t *testing.T) {
				t.Setenv("TMPDIR", t.TempDir())
				swapResolveExecutionCapability(t, constrainedResolution)
				inner := &confineInner{}
				result := headlessResult(t, t.TempDir(), mode.NewActiveState(m, mode.SourceDefault))
				runHeadlessShellAnswering(t, result, inner, command, nil)
				requireConfinedShellRun(t, inner, command)
				spec := inner.bounded[0]
				if spec.ExceptionalAuthority != enforce.NetworkAccessAuthority {
					t.Fatalf("RunSpec authority = %q, want the classified network authority", spec.ExceptionalAuthority)
				}
				policy, _ := decodeFrame(t, spec.Stdin)
				if policy.ExceptionalAuthority != "" || policy.Mode != string(m) {
					t.Fatalf("policy = %+v, want mode %s without network authority", policy, m)
				}
			})
		}
	}
}

func TestConfinedShell_BlockedReadOnlyStageRefusesTheReroutedCommand(t *testing.T) {
	for _, m := range []mode.Mode{mode.Plan, mode.AutoEdits} {
		for _, command := range []string{"cat ~/.ssh/k*", "rm x && cat ~/.ssh/k*"} {
			t.Run(string(m)+"/"+command, func(t *testing.T) {
				inner := &confineInner{}
				auth := &recordingAuthorizer{decision: allow()}
				d := dispatcherFor(t, tools.NewRegistry(), inner, auth)
				ssh := filepath.Join(d.home, ".ssh")
				if err := os.Mkdir(ssh, 0o700); err != nil {
					t.Fatal(err)
				}
				d.guard = securitystate.Policy{Blocked: permissions.NewBlockedPaths(d.home, blockedEntries(t, d.home, "~/.ssh"))}
				d.confinement = withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(m)), lookupPath: programDir(t, "sh"), blocked: d.guard.Blocked, projectRoot: d.processCWD})

				got, err := d.Dispatch(context.Background(), bashCall("c1", command))
				if err != nil {
					t.Fatalf("Dispatch: %v", err)
				}
				if !got.Denied || !strings.Contains(got.Notice, "blocked_paths entry") {
					t.Fatalf("result = %+v, want a blocked-path refusal", got)
				}
				if auth.callCount() != 0 || inner.calls() != 0 {
					t.Fatalf("authorize calls = %d, runner calls = %d; want 0/0", auth.callCount(), inner.calls())
				}
			})
		}
	}
}

type refusalHelper struct {
	records []netproxy.Refusal
	closed  bool
}

func (h *refusalHelper) HelperChannel() *os.File { return nil }
func (h *refusalHelper) Started() error          { return nil }
func (h *refusalHelper) Close()                  { h.closed = true }

func (h *refusalHelper) refusals() []netproxy.Refusal {
	if !h.closed {
		return nil
	}
	return slices.Clone(h.records)
}

type refusalReads struct {
	mu      sync.Mutex
	pending [][]netproxy.Refusal
	reads   int
}

func (r *refusalReads) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads
}

func swapInvocationRefusals(t *testing.T, calls ...[]netproxy.Refusal) *refusalReads {
	t.Helper()
	r := &refusalReads{pending: calls}
	real := invocationRefusals
	invocationRefusals = func(helper cmdrunner.HelperLaunch) []netproxy.Refusal {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.reads++
		if helper == nil {
			t.Error("refusals read for an invocation without a helper launch")
			return nil
		}
		helper.Close()
		var records []netproxy.Refusal
		if len(r.pending) > 0 {
			records, r.pending = r.pending[0], r.pending[1:]
		}
		return real(&refusalHelper{records: records})
	}
	t.Cleanup(func() { invocationRefusals = real })
	return r
}

func proxyRouteUnitConfinement(t *testing.T, projectRoot string, programs ...string) *confinement {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the proxy route needs the linux connect broker")
	}
	conf := withSessionTemp(t, &confinement{constrained: true, mode: fixedMode(string(mode.AutoEdits)), lookupPath: programDir(t, programs...),
		projectRoot: projectRoot, blocked: testBlocked(t), broker: enforce.BrokerSlice})
	t.Cleanup(conf.proxy.stop)
	return conf
}

const wantProxyRouteNote = "codemeld: this command ran on the proxy route; tools that do not use HTTPS_PROXY/HTTP_PROXY, including ssh, scp and SSH URLs, get no network; use Build mode for those."

func refusedLine(hostPort, reason string) string {
	return "codemeld: network refused: " + hostPort + " (" + reason + ")"
}

func omittedLine(n int) string {
	return fmt.Sprintf("codemeld: %d more network refusals omitted.", n)
}

func dispatchedStderr(t *testing.T, content string) string {
	t.Helper()
	if _, after, ok := strings.Cut(content, "stderr:\n"); ok {
		content = after
	}
	stderr, _, _ := strings.Cut(content, "\nexit status ")
	return stderr
}

func TestConfinedRunner_ProxyRouteDiagnosticsGetTheRouteExplanation(t *testing.T) {
	malformed := netproxy.Refusal{Reason: "bad request"}
	notTCP := netproxy.Refusal{Reason: "not a TCP connect"}
	uninspectable := netproxy.Refusal{Reason: "connect not inspectable"}
	dest := netproxy.Refusal{Host: "a.test", Port: "80", Reason: "not approved (no one to ask)"}
	destLine := refusedLine("a.test:80", "not approved (no one to ask)")
	long := netproxy.Refusal{Host: strings.Repeat("h", 150) + ".test", Port: "443", Reason: "not approved (denied)"}
	tight := len("\n"+confinedFailureNote) + 1 + 120
	for _, tc := range []struct {
		name     string
		records  []netproxy.Refusal
		cap      int
		addition string
	}{
		{"malformed proxy request", []netproxy.Refusal{malformed}, 4096, wantProxyRouteNote},
		{"not a TCP connect", []netproxy.Refusal{notTCP}, 4096, wantProxyRouteNote},
		{"connect not inspectable", []netproxy.Refusal{uninspectable}, 4096, wantProxyRouteNote},
		{"mixed diagnostics", []netproxy.Refusal{malformed, notTCP, uninspectable}, 4096, wantProxyRouteNote},
		{"malformed proxy request and a destination", []netproxy.Refusal{malformed, dest}, 4096, destLine},
		{"not a TCP connect and a destination", []netproxy.Refusal{dest, notTCP}, 4096, destLine},
		{"connect not inspectable and a destination", []netproxy.Refusal{uninspectable, dest}, 4096, destLine},
		{"mixed diagnostics and a destination", []netproxy.Refusal{malformed, dest, notTCP, uninspectable}, 4096, destLine},
		{"a destination that does not fit", []netproxy.Refusal{malformed, long, notTCP}, tight, omittedLine(1)},
	} {
		want := "boom\n" + tc.addition + "\n" + confinedFailureNote
		conf := proxyRouteUnitConfinement(t, t.TempDir(), "ls")
		for name, exec := range confinedAdapters(t, conf, tc.cap) {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				swapInvocationRefusals(t, tc.records)
				res, err := exec(&confineInner{exitCode: 1, stderr: []byte("boom")}, confinedSpec(t.TempDir(), "ls"))
				if err != nil {
					t.Fatal(err)
				}
				if string(res.Stderr) != want {
					t.Fatalf("stderr = %q, want %q", res.Stderr, want)
				}
			})
		}
		t.Run(tc.name+"/dispatch", func(t *testing.T) {
			swapInvocationRefusals(t, tc.records)
			d := dispatcherFor(t, tools.NewRegistry(), &confineInner{exitCode: 1, stderr: []byte("boom")}, &recordingAuthorizer{decision: allow()})
			d.outputCap = tc.cap
			d.confinement = proxyRouteUnitConfinement(t, d.processCWD, "ls")
			got, err := d.Dispatch(context.Background(), bashCall("c1", "ls"))
			if err != nil {
				t.Fatal(err)
			}
			if stderr := dispatchedStderr(t, got.Content); stderr != want {
				t.Fatalf("model stderr = %q, want %q", stderr, want)
			}
		})
	}
}

func TestConfinedFailure_RefusalLinesStayWithinTheOutputCap(t *testing.T) {
	noteRoom := len("\n" + confinedFailureNote)
	failed := cmdrunner.RunResult{ExitCode: 1}
	long := strings.Repeat("x", 200) + ".test"
	records := []netproxy.Refusal{
		{Host: "a.test", Port: "443", Reason: "not approved (denied)"},
		{Reason: "bad request"},
		{Host: "a.test", Port: "443", Reason: "not approved (denied)"},
		{Host: "2001:db8::1", Port: "8080", Reason: "direct connection not allowed (use the proxy)"},
		{Host: "a.test", Port: "443", Reason: "not approved (no one to ask)"},
		{Host: "a.test", Port: "443", Reason: "not approved (denied)"},
		{Host: long, Port: "443", Reason: "not approved (denied)"},
		{Host: "2001:db8::1", Port: "8080", Reason: "direct connection not allowed (use the proxy)"},
	}
	lines := []string{
		refusedLine("a.test:443", "not approved (denied)"),
		refusedLine("[2001:db8::1]:8080", "direct connection not allowed (use the proxy)"),
		refusedLine("a.test:443", "not approved (no one to ask)"),
		refusedLine(long+":443", "not approved (denied)"),
	}
	f := confinedFailureOf(failed, true, &refusalHelper{records: records})
	if f == nil || confinedFailureOf(cmdrunner.RunResult{}, true, &refusalHelper{records: records}) != nil {
		t.Fatalf("failure state = %+v, want one for the failed run and none for a successful one", f)
	}

	t.Run("exact", func(t *testing.T) {
		two := noteRoom + 1 + len(lines[0]) + 1 + len(lines[1]) + 1 + len(omittedLine(2)) + 1
		for _, tc := range []struct {
			name string
			cap  int
			want string
		}{
			{"everything fits", 4096, "boom\n" + strings.Join(lines, "\n") + "\n" + confinedFailureNote},
			{"two lines and the marker", two, "b\n" + lines[0] + "\n" + lines[1] + "\n" + omittedLine(2) + "\n" + confinedFailureNote},
			{"lines before the marker", two - 1, "boom\n" + lines[0] + "\n" + lines[1] + "\n" + confinedFailureNote},
		} {
			res := noteConfinedFailure(cmdrunner.RunResult{ExitCode: 1, Stderr: []byte("boom"), StderrTotal: 1000}, tc.cap, f)
			if string(res.Stderr) != tc.want {
				t.Fatalf("%s: stderr = %q, want %q", tc.name, res.Stderr, tc.want)
			}
			kept := len(tc.want) - len(strings.TrimPrefix(strings.TrimPrefix(tc.want, "boom"), "b"))
			if res.StderrTotal != 1000+int64(len(tc.want)-kept) {
				t.Fatalf("%s: StderrTotal = %d, want the 1000 command bytes plus %d rendered bytes", tc.name, res.StderrTotal, len(tc.want)-kept)
			}
		}
	})

	for name, stderr := range map[string][]byte{
		"no stderr":        nil,
		"short":            []byte("boom"),
		"multi-byte":       bytes.Repeat([]byte("é"), 300),
		"long":             bytes.Repeat([]byte("a"), 5000),
		"invalid UTF-8":    bytes.Repeat([]byte{0xff, 'a'}, 100),
		"continuation 1st": append([]byte{0x80, 0x80}, bytes.Repeat([]byte("z"), 50)...),
	} {
		t.Run(name, func(t *testing.T) {
			for cap := 256; cap <= 1400; cap++ {
				out, kept := withConfinedFailure(stderr, cap, f)
				if _, model := events.BuildModelInputBytes(nil, out, 1<<20); len(model) > cap {
					t.Fatalf("cap %d: model stderr is %d bytes", cap, len(model))
				}
				body, ok := bytes.CutSuffix(out, []byte(confinedFailureNote))
				if !ok || bytes.Count(out, []byte(confinedFailureNote)) != 1 || !bytes.HasPrefix(body, stderr[:kept]) {
					t.Fatalf("cap %d: stderr = %q, want a command prefix and one trailing note", cap, out)
				}
				if len(stderr) > 0 && kept == 0 {
					t.Fatalf("cap %d: stderr = %q, want a non-empty command prefix", cap, out)
				}
				rest := strings.TrimPrefix(string(body[kept:]), "\n")
				var got []string
				if rest != "" {
					got = strings.Split(strings.TrimSuffix(rest, "\n"), "\n")
				}
				shown := 0
				for shown < len(got) && shown < len(lines) && got[shown] == lines[shown] {
					shown++
				}
				switch {
				case shown == len(got):
				case shown == len(got)-1 && got[shown] == omittedLine(len(lines)-shown):
				default:
					t.Fatalf("cap %d: additions %q, want a prefix of %q and at most the omission marker", cap, got, lines)
				}
			}
		})
	}
}

func TestConfinedRunner_ProxyRouteNoteOnlyForFailedRuns(t *testing.T) {
	record := []netproxy.Refusal{{Host: "a.test", Port: "80", Reason: "not approved (no one to ask)"}}
	for _, tc := range []struct {
		name    string
		inner   confineInner
		want    string
		wantErr bool
	}{
		{"success", confineInner{stderr: []byte("warn")}, "warn", false},
		{"launch failure", confineInner{exitCode: -1, launchErr: fserrors.NotFound}, "", false},
		{"runner error", confineInner{exitCode: 1, stderr: []byte("boom"), err: errors.New("runner broke")}, "", true},
	} {
		conf := proxyRouteUnitConfinement(t, t.TempDir(), "ls")
		for name, exec := range confinedAdapters(t, conf, 4096) {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				reads := swapInvocationRefusals(t, record)
				inner := tc.inner
				res, err := exec(&inner, confinedSpec(t.TempDir(), "ls"))
				if (err != nil) != tc.wantErr || strings.Contains(string(res.Stderr), "codemeld:") {
					t.Fatalf("result %+v, err %v; want error %v and no note", res, err, tc.wantErr)
				}
				if !tc.wantErr && string(res.Stderr) != tc.want {
					t.Fatalf("stderr = %q, want %q", res.Stderr, tc.want)
				}
				if reads.count() != 0 {
					t.Fatalf("refusals read %d times, want none", reads.count())
				}
			})
		}
	}
}

func TestConfinedRunner_ProxyRefusalTotalsCountOnlyRenderedBytes(t *testing.T) {
	var records []netproxy.Refusal
	var lines []string
	for _, host := range []string{"first", "second", "third"} {
		host = strings.Repeat(host, 8) + ".test"
		records = append(records, netproxy.Refusal{Host: host, Port: "443", Reason: "not approved (denied)"})
		lines = append(lines, refusedLine(host+":443", "not approved (denied)"))
	}
	cap := len("\n"+confinedFailureNote) + 1 + len(lines[0]) + 1 + len(lines[1]) + 1 + len(omittedLine(1)) + 1
	want := "b\n" + lines[0] + "\n" + lines[1] + "\n" + omittedLine(1) + "\n" + confinedFailureNote
	wantTotal := int64(1000 + len(want) - len("b"))
	conf := proxyRouteUnitConfinement(t, t.TempDir(), "ls", "hg")
	newInner := func() *confineInner { return &confineInner{exitCode: 1, stderr: []byte("boom"), stderrSize: 1000} }

	for _, withStore := range []bool{false, true} {
		t.Run(fmt.Sprintf("bash session %v", withStore), func(t *testing.T) {
			swapInvocationRefusals(t, records)
			store := mkStore(t)
			shell := &shellEventRunner{inner: newInner(), cap: cap}
			if withStore {
				shell.active = func() *sessions.Store { return store }
			}
			res, err := execNoted(&confinedShellRunner{events: shell, conf: conf}, confinedSpec(t.TempDir(), "ls"))
			if err != nil {
				t.Fatal(err)
			}
			if string(res.Stderr) != want || res.StderrTotal != wantTotal {
				t.Fatalf("shell stderr = %q, total %d; want %q, total %d", res.Stderr, res.StderrTotal, want, wantTotal)
			}
			if withStore {
				ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd)
				if len(ends) != 1 || ends[0].Stderr != want || ends[0].OriginalBytes == nil || ends[0].OriginalBytes.Stderr != wantTotal {
					t.Fatalf("tool_exec_end = %+v, want stderr %q and original stderr %d", ends, want, wantTotal)
				}
			}
		})
	}

	t.Run("vcs", func(t *testing.T) {
		swapInvocationRefusals(t, records)
		res, err := (&confinedRunner{inner: newInner(), conf: conf, cap: cap}).Exec(context.Background(), confinedSpec(t.TempDir(), "hg"))
		if err != nil {
			t.Fatal(err)
		}
		if string(res.Stderr) != want || res.StderrTotal != wantTotal {
			t.Fatalf("vcs stderr = %q, total %d; want %q, total %d", res.Stderr, res.StderrTotal, want, wantTotal)
		}
	})
}

func TestConfinedShell_ProxyRefusalsSurviveShellAggregation(t *testing.T) {
	ok := cmdrunner.RunResult{Stdout: []byte("one\n"), Stderr: []byte("fine")}
	failed := cmdrunner.RunResult{ExitCode: 1, Stdout: []byte("two\n"), Stderr: []byte("boom")}
	ref := func(host string) netproxy.Refusal {
		return netproxy.Refusal{Host: host, Port: "80", Reason: "not approved (no one to ask)"}
	}
	line := func(host string) string { return refusedLine(host+":80", "not approved (no one to ask)") }
	noted := func(stderr string, lines ...string) string {
		return stderr + "\n" + strings.Join(lines, "\n") + "\n" + confinedFailureNote
	}
	short := len("\n"+confinedFailureNote) + 1 + len(line("a.test")) + 1 + len(line("b.test")) + 1 + len(omittedLine(1)) + 1
	for _, tc := range []struct {
		name    string
		command string
		cap     int
		results []cmdrunner.RunResult
		records [][]netproxy.Refusal
		ends    []string
		model   string
	}{
		{"ls && false", "ls && false", 4096, []cmdrunner.RunResult{ok, failed}, [][]netproxy.Refusal{{ref("a.test")}},
			[]string{"fine", noted("boom", line("a.test"))}, noted("fineboom", line("a.test"))},
		{"false; ls", "false; ls", 4096, []cmdrunner.RunResult{failed, ok}, [][]netproxy.Refusal{{ref("a.test")}},
			[]string{noted("boom", line("a.test")), "fine"}, noted("boomfine", line("a.test"))},
		{"ls | false", "ls | false", 4096, []cmdrunner.RunResult{ok, failed}, [][]netproxy.Refusal{{ref("a.test")}},
			[]string{"fine", noted("boom", line("a.test"))}, noted("fineboom", line("a.test"))},
		{"two failing stages", "false; false", 4096, []cmdrunner.RunResult{failed, failed},
			[][]netproxy.Refusal{{ref("a.test"), ref("b.test")}, {ref("b.test"), ref("c.test")}},
			[]string{noted("boom", line("a.test"), line("b.test")), noted("boom", line("b.test"), line("c.test"))},
			noted("boomboom", line("a.test"), line("b.test"), line("c.test"))},
		{"two failing stages over budget", "false; false", short, []cmdrunner.RunResult{failed, failed},
			[][]netproxy.Refusal{{ref("a.test"), ref("b.test")}, {ref("b.test"), ref("c.test")}},
			nil, noted("b", line("a.test"), line("b.test"), omittedLine(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapInvocationRefusals(t, tc.records...)
			inner := &confineInner{results: tc.results}
			d := dispatcherFor(t, tools.NewRegistry(), inner, &recordingAuthorizer{decision: allow()})
			d.outputCap = tc.cap
			d.confinement = proxyRouteUnitConfinement(t, d.processCWD, "ls", "false")

			got, err := d.Dispatch(context.Background(), bashCall("c1", tc.command))
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if inner.calls() != 2 || len(inner.bounded) != 2 {
				t.Fatalf("inner calls = %d, bounded = %d, want two confined stages", inner.calls(), len(inner.bounded))
			}
			if stderr := dispatchedStderr(t, got.Content); stderr != tc.model || len(stderr) > tc.cap {
				t.Fatalf("model stderr = %q, want %q", stderr, tc.model)
			}
			ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, d.active()), events.KindToolExecEnd)
			if len(ends) != 2 {
				t.Fatalf("tool_exec_end = %+v, want one per stage", ends)
			}
			for i, want := range tc.ends {
				if ends[i].Stderr != want {
					t.Fatalf("stage %d tool_exec_end stderr = %q, want %q", i, ends[i].Stderr, want)
				}
			}
		})
	}
}

func TestConfinedShell_ProxyRefusalNoteIsTheRecordedEndAndKeepsTheTimeoutNote(t *testing.T) {
	record := []netproxy.Refusal{{Host: "a.test", Port: "80", Reason: "not approved (no one to ask)"}}
	line := refusedLine("a.test:80", "not approved (no one to ask)")
	want := "boom\n" + line + "\n" + confinedFailureNote
	for _, withSession := range []bool{true, false} {
		t.Run(fmt.Sprintf("session %v", withSession), func(t *testing.T) {
			swapInvocationRefusals(t, record)
			d := dispatcherFor(t, tools.NewRegistry(), &confineInner{exitCode: 1, stderr: []byte("boom")}, &recordingAuthorizer{decision: allow()})
			store := d.active()
			if !withSession {
				d.active = nil
			}
			d.confinement = proxyRouteUnitConfinement(t, d.processCWD, "ls")
			got, err := d.Dispatch(context.Background(), bashCall("c1", "ls"))
			if err != nil {
				t.Fatal(err)
			}
			if stderr := dispatchedStderr(t, got.Content); stderr != want {
				t.Fatalf("model stderr = %q, want %q", stderr, want)
			}
			ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, store), events.KindToolExecEnd)
			if withSession && (len(ends) != 1 || ends[0].Stderr != want) {
				t.Fatalf("tool_exec_end = %+v, want the model stderr %q", ends, want)
			}
			if !withSession && len(ends) != 0 {
				t.Fatalf("tool_exec_end = %+v, want none without a session", ends)
			}
		})
	}

	t.Run("timeout", func(t *testing.T) {
		const cap = 512
		limit := 100 * time.Millisecond
		swapInvocationRefusals(t, record)
		inner := &confineInner{exitCode: -1, stderr: bytes.Repeat([]byte("e"), 2*cap), onBounded: func(cmdrunner.RunSpec) { time.Sleep(limit + 100*time.Millisecond) }}
		d := dispatcherFor(t, tools.NewRegistry(), inner, &recordingAuthorizer{decision: allow()})
		d.outputCap = cap
		d.confinement = proxyRouteUnitConfinement(t, d.processCWD, "ls")
		got, err := d.Dispatch(context.Background(), bashCallWithTimeout("c1", "ls", int(limit.Milliseconds())))
		if err != nil {
			t.Fatal(err)
		}
		stderr := dispatchedStderr(t, got.Content)
		if len(stderr) > cap || !strings.HasPrefix(stderr, "e") || !strings.HasSuffix(stderr, "\n"+line+"\n"+confinedFailureNote+"\n"+bashTimeoutNote(limit)) ||
			strings.Count(stderr, confinedFailureNote) != 1 {
			t.Fatalf("model stderr = %q (%d bytes), want a command prefix, the refusal, the note and the timeout note within %d", stderr, len(stderr), cap)
		}
		ends := decodeStoreEvents[events.ToolExecEnd](t, reloadStore(t, d.active()), events.KindToolExecEnd)
		if len(ends) != 1 || len(ends[0].Stderr) > cap || !strings.HasSuffix(ends[0].Stderr, "\n"+line+"\n"+confinedFailureNote) {
			t.Fatalf("tool_exec_end = %+v, want the bounded execution stderr without the timeout note", ends)
		}
	})
}
